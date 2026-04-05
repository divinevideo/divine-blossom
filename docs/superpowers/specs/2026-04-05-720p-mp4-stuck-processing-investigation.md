# Investigation: Broken `/720p.mp4` variants on `media.divine.video`

**Date**: 2026-04-05
**Branches**: `fix/720p-mp4-stuck-processing` (PR #59, merged)
**Reporter**: iOS session 2026-04-05, 5 bad hashes
**Status**: Root cause found, fix shipped, deploy verified live, backlog cleanup pending

## TL;DR

iOS `media_kit` reported `Failed to recognize file format` on `/720p.mp4`. It wasn't a corrupt MP4 — it was an HTTP **202 JSON "still processing"** body the player tried to parse as MP4. Videos had been stuck in that state for days because two bugs shipped together on 2026-03-29 in PR #51 (Divine resumable upload control plane):

1. **`handle_resumable_complete` never triggered the transcoder.** The legacy `process_upload` path calls `trigger_transcoding` + `trigger_transcription` after the upload completes. The new resumable `complete_session` handler returned the finalized response without calling either. Every resumable upload bypassed the transcoder entirely.

2. **The Fastly Compute on-demand fallback trigger was misrouted.** A global rename of `CLOUD_RUN_BACKEND` → `UPLOAD_SERVICE_BACKEND` in the same PR collapsed two distinct backends onto one. Three call sites in `src/main.rs` (transcode trigger, fMP4 backfill trigger, transcription trigger) build URLs pointing at `divine-transcoder-*.run.app` but were calling `send_async(UPLOAD_SERVICE_BACKEND)`. In Fastly Compute the backend name — not the URL hostname — decides where a request lands, so all three were being delivered to `upload.divine.video` and getting nginx 404. Fire-and-forget `send_async` hid the failure behind a false-positive `[HLS] Triggered…` log line. The "on-demand fallback" safety net that should have caught bug 1 was itself dead.

The two bugs interacted catastrophically: new resumable uploads never reached the transcoder (bug 1), and the safety-net code path that re-triggers stale records also never reached the transcoder (bug 2). The edge one-way status machine in `src/main.rs:1928` then pinned every affected blob at `transcode_status = Processing` forever — once in Processing it refuses to re-trigger.

Two of the five reported hashes were a different bug (orphan KV metadata without a GCS blob) — tracked separately.

## Observed failure modes (five reported hashes)

| Hash (first 8) | `/720p.mp4` | `/hls/master.m3u8` | raw `/<hash>` | Classification |
|---|---|---|---|---|
| `9be8c499` | **202** `status=processing` | **202** | **200** video/mp4 | Resumable-path stuck (bug 1+2) |
| `146c722a` | **202** `status=processing` | **202** | **200** video/mp4 | Resumable-path stuck (bug 1+2) |
| `cd665d2d` | **202** `status=processing` | **202** | **200** video/mp4 | Resumable-path stuck (bug 1+2) |
| `ae1102b3` | **404** `Content not found` | **404** | **404** | Orphan KV (separate bug) |
| `ff63ea82` | **404** | **404** | **404** | Metadata stub (separate bug) |

All three `202` hashes were uploaded 2026-04-04 ~10:26-10:29 UTC and were still stuck 12+ hours later. Provenance for each showed `upload_auth_event.content = "Complete resumable Blossom upload"` — confirming the resumable path. Probing at 15 s intervals over 5 minutes showed no state change; they were not briefly processing, they were permanently stuck.

## Root cause walk-through

### Symptom → first theory → real root cause

First pass concluded "the transcoder crashed mid-job and the webhook callback was lost, leaving the blob pinned at Processing, and the edge never re-triggers." That's partially true (the edge doesn't re-trigger once Processing), but it doesn't explain why so many blobs are stuck at once across different uploaders. A crash-on-every-attempt bug would have shown log spam on the transcoder. User confirmed: "still transcoding happens for days, it NEVER finishes."

Second pass: "the transcoder isn't being called at all." Evidence:
- `cloud-run-transcoder/src/main.rs` has ~35 structured log sites (`info!/warn!/error!`) and a webhook callback path for both success and failure. If the transcoder were invoked and failing, there'd be logs for every attempt.
- The silence for these hashes in transcoder logs is consistent with "the transcoder never received the request," not "the transcoder failed silently."

Third pass: find every place something should trigger the transcoder.

**Path A — direct upload via `process_upload`** (`cloud-run-upload/src/main.rs:525`): calls `trigger_transcoding()` at line 598 after the upload completes. This path works.

**Path B — resumable upload via `handle_resumable_complete`** (`cloud-run-upload/src/main.rs:485`): calls `manager.complete_session()` and returns. `resumable.rs` has zero references to `transcod` or `trigger`. **This path never calls the transcoder.** Every resumable upload since 2026-03-29 has been going through this path.

**Path C — on-demand fallback from Fastly Compute** (`src/main.rs:2059 trigger_on_demand_transcoding`): builds the URL `https://divine-transcoder-*.run.app/transcode` then calls `send_async(UPLOAD_SERVICE_BACKEND)`. Git blame on the `send_async` line shows commit `e9d85b3` (the PR #51 resumable control plane) renamed `CLOUD_RUN_BACKEND` → `UPLOAD_SERVICE_BACKEND` globally. Most call sites were legitimately targeting the upload service; three transcoder-bound call sites were not.

Verification of path C: `curl -X POST https://upload.divine.video/transcode` → HTTP **404** from nginx. The upload service has no `/transcode` route. The `send_async` fire-and-forget `Ok(_)` return path hides this completely — Compute logs `[HLS] Triggered on-demand transcoding for {hash}` and believes it succeeded.

Both bugs were introduced by the same commit (`e9d85b3`) in the same PR (#51) and have been live for 6 days.

## The fix (PR #59)

Two commits on branch `fix/720p-mp4-stuck-processing`:

**`811219e fix(upload): trigger HLS transcoding on resumable upload completion`**
After `manager.complete_session()` succeeds in `handle_resumable_complete`, spawn fire-and-forget transcoder and transcriber triggers keyed off `response.content_type`, mirroring the legacy `process_upload` path. +45 lines, -1 line in `cloud-run-upload/src/main.rs`.

**`41faeb8 fix(compute): route on-demand transcoder triggers to the transcoder backend`**
New `TRANSCODER_BACKEND = "cloud_run_transcoder"` constant with a code comment documenting that the backend must exist in the Fastly dashboard. Three misrouted `send_async(UPLOAD_SERVICE_BACKEND)` calls (transcode, backfill-fmp4, transcribe) switched to `send_async(TRANSCODER_BACKEND)`. +13 lines, -4 lines in `src/main.rs`.

Both compile clean against their respective targets (`wasm32-wasip1` for Compute, native for cloud-run-upload). PR #59 merged to main on 2026-04-05.

## Deploy timeline

| Time (UTC) | Action | Result |
|---|---|---|
| 23:17 | `fastly service backend create cloud_run_transcoder` on version **251** | ✅ Backend created |
| 23:27 | `fastly compute publish` creates versions 252 → activates **253** | ⚠️ New WASM live but cloned from v250, missing `cloud_run_transcoder` backend — fix 2 code still broken in production |
| 23:40 → 23:48 | `gcloud builds submit` **from wrong cwd**, fails silently → `gcloud run services update --image :latest` → revision `00008-kvg` live | ❌ No new image built, revision serves stale March 10 image — fix 1 not live |
| ~23:50 | Investigation catches the stale-image issue via Artifact Registry timestamps | Build re-run from `cloud-run-upload/` directory |
| 23:40 → 23:48 (retry) | `gcloud builds submit` succeeds with digest `7025c19f…` | ✅ New image built |
| 23:48 | `gcloud run services update` → revision `00009-sd6` | ✅ Fix 1 live |
| 23:55 → 00:01 | Transcoder Cloud Logging shows `Starting transcode for {hash}` at ~1/min | ✅ Fix 1 verified — resumable uploads reaching transcoder |
| ~00:05 | Discover Fastly versions 252/253 missing `cloud_run_transcoder` backend | Need to re-add to active version |
| ~00:06 | `fastly service backend create --version latest --autoclone` creates version **254** with backend | ✅ Backend restored |
| ~00:06 | `fastly service version activate 254` + `fastly purge --all` | ✅ Fix 2 live |

Two non-obvious deploy traps surfaced during this rollout:

1. **`gcloud builds submit --tag` failed silently** because cwd had no Dockerfile; the follow-up `gcloud run services update --image :latest` then redeployed the stale March 10 image, reported "Done", and fooled everyone. Skill extracted: `gcloud-builds-tag-deploy-false-success`.

2. **`fastly compute publish` cloned the previously-active version (250)**, not the draft 251 where the backend had been added. The publish path of versions 251 → 252 → 253 meant 252 and 253 had the new WASM but **lost the backend**. Fix was to autoclone a fresh version (254) off the active 253 and re-add the backend before activating. Skill extractable: "fastly compute publish ignores dashboard drafts unless they're active first."

## What the fix does NOT cover

- **Existing stuck records.** Every video uploaded via the resumable API between 2026-03-29 and 2026-04-04 23:48 UTC is still pinned at `transcode_status = Processing`. The deployed one-way status machine in `src/main.rs:1928` never re-triggers from Processing, so these don't self-heal. Requires an admin sweep (see remaining work).
- **Orphan KV records** (`ae1102b3`, `ff63ea82`). Metadata exists in KV, GCS blob does not. Separate data-integrity bug being investigated in a parallel workstream.
- **The root cause of bounding/observability gaps** that let these bugs hide for 6 days. There is no Sentry on cloud-run services yet (wiring exists on `fix/hls-moderation-enforcement` branch but not merged). There are no retries or terminal-failure classification on the Fastly Compute serving path (also on `fix/hls-moderation-enforcement` via `990fa07`).
- **Regression tests** for `handle_resumable_complete` → transcoder trigger. A helper extraction + 5 tests would have caught this in CI.

## Remaining work (swarm dispatched 2026-04-05)

Five parallel workstreams, four dispatched to background agents, one inline:

| # | Task | Owner | Status |
|---|---|---|---|
| 1 | Admin sweep `POST /admin/api/reset-stuck-transcodes` to unstick backlog | Agent (background) | in progress |
| 2 | Rebase `fix/hls-moderation-enforcement` onto main, open PR (bounding + Sentry) | Agent (background) | in progress |
| 3 | Orphan-KV cleanup tool + diagnostic for the 404 class | Agent (background) | in progress |
| 4 | Regression tests for `handle_resumable_complete` derivative triggers | Agent (background) | in progress |
| 5 | This report (update with full two-bug story) | Inline | done |

## Skills extracted from this investigation

- `fastly-compute-async-request-reliability` (updated) — added Section 4 covering the URL-vs-backend routing gotcha and how backend-constant renames can silently misroute cross-service async triggers.
- `gcloud-builds-tag-deploy-false-success` (new) — documents the `gcloud builds submit --tag` cwd-sensitivity trap and the chained-command false-positive deploy.

## Artifacts

- PR: https://github.com/divinevideo/divine-blossom/pull/59 (merged)
- Fastly active version: 254
- Cloud Run revision: `divine-blossom-upload-00009-sd6`
- Image digest: `sha256:7025c19f42d4fd618b52236f67d37de…`
- Response bodies captured: `/tmp/720p-inv/*.json`
- Source references:
  - Stuck 202 handler: `src/main.rs:1928-1954`
  - On-demand trigger (fixed): `src/main.rs:2059` (now uses `TRANSCODER_BACKEND`)
  - Resumable completion (fixed): `cloud-run-upload/src/main.rs:485` (now spawns triggers)
  - Bounding fix (still unmerged): commit `990fa07` on `fix/hls-moderation-enforcement`
