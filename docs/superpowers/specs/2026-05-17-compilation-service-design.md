# Compilation Service: Design Spec

## Goal

A backend service that takes a Nostr list of video events and produces a single concatenated MP4 compilation, with the Divine logo watermark and per-clip nip05 credits burned in, ready for upload to TikTok / Reels / YouTube. No UI — HTTP API only.

## Solution

New Cloud Run service `cloud-run-compiler/`, parallel to `cloud-run-transcoder/`. Same stack: Rust + FFmpeg + NVIDIA NVENC. Reuses transcoder patterns for deploy, auth, GCS layout, webhook callbacks.

## API

### `POST /compile`

v1 schema. `deny_unknown_fields` is enforced — any field not listed here returns 400.

```json
{
  "source": {
    "naddr": "naddr1..."           // OR
    "event_ids": ["<hex>", ...]
  },
  "aspects": ["9:16", "1:1", "16:9"],   // one or more; default ["9:16"]
  "fit": "blur-pad",                     // blur-pad | center-crop | letterbox; default blur-pad
  "watermark": {
    "enabled": true,
    "position": "bottom-right",          // top-left | top-right | bottom-left | bottom-right
    "opacity": 0.30
  },
  "credit": {
    "duration_ms": 2500,
    "show_display_name": true,
    "show_nip05": true
  },
  "audio": {
    "target_lufs": -14
  },
  "max_duration_sec": 600,               // soft cap; tail clips dropped with warning
  "callback_url": "https://..."          // POST'd when job completes
}
```

V2+ field/value additions (currently rejected): `source.nevents`, `per_clip_overrides`, `credit.mode`, `audio.mode`, `audio.bgm_url`, `transition`, `transition_ms`, `intro_card`, `outro_card`, `dry_run`. See "What's deferred to v2+" below.

Response (immediate):
```json
{ "job_id": "cmp_01HXY...", "status": "queued" }
```

### `GET /compile/:job_id`

```json
{
  "job_id": "cmp_01HXY...",
  "status": "queued | running | done | failed",
  "progress": 0.42,
  "result": {
    "outputs": [
      { "aspect": "9:16", "url": "https://...", "sha256": "...", "size": 12345, "dim": "1080x1920" },
      { "aspect": "1:1",  "url": "https://...", "sha256": "...", "size": 11122, "dim": "1080x1080" },
      { "aspect": "16:9", "url": "https://...", "sha256": "...", "size": 13344, "dim": "1920x1080" }
    ],
    "duration_sec": 487,
    "clips_used": 23,
    "clips_dropped": [{ "event_id": "...", "reason": "exceeded max_duration_sec" }],
    "credits": [
      { "event_id": "...", "pubkey": "...", "nip05": "alice@example.com", "display_name": "Alice" }
    ]
  },
  "callback_delivery": {
    "attempts": 1,
    "last_attempt_at": "2026-05-17T18:42:11Z",
    "last_status_code": 200,
    "delivered": true
  },
  "error": null
}
```

`GET /compile/:job_id` on an unknown id returns `404 Not Found` with `{"error": "job_not_found", "job_id": "..."}`.

When `status` transitions to `done` or `failed`, the service POSTs the same body to `callback_url` (3 retries with exponential backoff: 1s, 5s, 25s). The POST carries `X-Compiler-Signature: sha256=<hex>` where the hex is `HMAC_SHA256(COMPILER_WEBHOOK_SECRET, raw_body)`. Caller verifies before trusting the payload.

Callback delivery is recorded on the job doc as `callback_delivery: { attempts: N, last_attempt_at, last_status_code, delivered: bool }`. If all 3 retries fail, the job stays in its terminal status (`done` / `failed`) with `callback_delivery.delivered: false`; operators inspect via `GET /admin/jobs/:job_id`. (A `callback_delivered=false` query filter on `GET /admin/jobs` is v2+.)

### Auth

Either of these is sufficient on `POST /compile` and `GET /compile/:job_id`:

- **NIP-98** — preferred. Caller's pubkey is extracted (via the `nostr` crate's NIP-98 helpers — service does not hand-roll schnorr or bech32) and logged on the job. Tenant id is `pubkey:<hex>`.
- **Webhook shared-secret** (`Authorization: Bearer <secret>`) — for trusted internal callers (funnelcake, etc.). Each secret is bound to a fixed tenant name in service config (env `COMPILER_WEBHOOK_SECRETS=funnelcake:abc...,janitor:xyz...`). The tenant name comes from the secret, **not** from a client-supplied header — that prevents tenants from spoofing each other's identity or rate-limit bucket. Secret values must be hex or base64 (URL-safe) — no `,` or `:` allowed, since those are the env-format separators. Tenant id is `secret:<name>`.

If both are present, NIP-98 wins. If neither is present, 401.

V1 request validation is done by serde with `deny_unknown_fields` on `CompileRequest` and all nested structs — any field outside the schema above returns 400. No separate validation matrix needed.

## Pipeline

```
1. Validate request, persist job to Firestore (`compilation_jobs/<job_id>`), return job_id.
2. Worker picks up job:
   a. Resolve source → list of event refs (e/a tags from naddr in their literal
      tag order, or `event_ids` in the order the caller supplied).
      No sort, no shuffle — render order is whatever the input gave us.
      **Assumption:** `api.divine.video` returns list-event tags in their original
      event order (not re-sorted). Verify during implementation; if it sorts, fetch
      the raw list event JSON and parse tags ourselves.
   b. Fetch each event (kind 34235/34236) + each author's kind 0 profile via
      `https://api.divine.video` REST API. No relay WebSocket — REST is simpler,
      no reconnects, no subscription management. **Caveat:** REST responses can
      flatten events and lose tag data (e.g. `sha256` from `imeta`); request raw
      tags / event JSON, do not rely on flattened helper fields. (See
      `nostr-rest-api-field-mapping-gap` skill.)
   c. For each video event: pull sha256 from `imeta` tag, download the MP4 original from
      `https://media.divine.video/<sha256>` (bounded concurrency). HLS
      renditions are not used as input — comp re-encodes anyway, so we go straight
      from the original. No pre-check; if a blob is Restricted/AgeRestricted/missing
      the download returns 403/404 and the worker records `clips_dropped` with the
      mapped reason.
   d. ffprobe each downloaded file: duration, dim, codec, rotation.
   e. Build clip list, drop anything past max_duration_sec (tail-drop).
   f. For each requested aspect ratio, generate one concat plan and run FFmpeg.
      - GPU NVENC encode (CPU fallback for rotated/oddball inputs, same as transcoder).
      - Overlay: divine logo (static PNG bundled), per-clip credit text via drawtext.
      - Audio: loudnorm filter targeting target_lufs.
   g. Upload each output MP4 to blossom (GCS bucket divine-blossom-media), get sha256.
   h. Mark job done, persist result, POST callback_url.
3. On any failure: persist error, mark failed, POST callback_url.

**Per-clip failure policy:** Drop-and-continue. Any failure to fetch, probe, or
process a single clip (404, corrupted, no `imeta`, unsupported codec, moderated,
post-trim duration 0) is recorded in `clips_dropped` with a reason; the comp is
rendered with the remaining clips. Job only enters `failed` state if **zero**
source clips end up usable, or if a system-level failure occurs (Firestore down,
GPU error, blossom upload fails).
```

## What's in v1

- Input shapes: `naddr` and `event_ids`.
- Multi-aspect render (any combo of 9:16 / 1:1 / 16:9 in one job).
- All three fit modes globally (`blur-pad` / `center-crop` / `letterbox`).
- Static-corner watermark + lower-third-fade credit (no other modes).
- Passthrough audio + single-pass loudnorm.
- Hard cut transitions only.
- Webhook callback with HMAC signature.
- NIP-98 auth **and** webhook shared-secret auth (either sufficient).
- Rate limiting (Firestore counters per tenant, hourly + daily, TTL'd).
- Observability via structured `tracing` log lines for `queued` / `started` / `done`.
- Admin endpoints: `GET /admin/jobs`, `GET /admin/jobs/:job_id` (bearer-token auth only).

## What's deferred to v2+

These are NOT in v1. Schema rejects them with 400 (unknown field) until implemented:

- Source: `nevents` variant (callers hex-decode).
- `per_clip_overrides` (in/out trim, per-clip fit).
- `credit.mode` field (`always-on` / `corner-pill` / `off`). v1 always uses lower-third-fade.
- `transition` field (`crossfade` / `dip-to-black`) + `transition_ms`. v1 is hard cut.
- `intro_card` / `outro_card`.
- `audio.mode` field (`mute` / `ducked-under-music`) + `audio.bgm_url`. v1 is passthrough.
- `dry_run` mode.
- Animated watermark intro.
- Admin endpoints: `POST /admin/jobs/:job_id/cancel`, `POST .../requeue`, `GET /admin/tenants`.
- Admin auth via `COMPILER_ADMIN_PUBKEYS` pubkey allowlist (v1 ships bearer-token-only admin).
- Caller-auth pass-through so age-restricted blobs can be included if the caller has access.
- 20 GB source-byte cap with HEAD pre-check (v1 only enforces 500-clip cap; max_duration_sec gives a soft budget).
- Per-job concurrency dynamic tuning based on GPU utilization.
- Per-tenant idempotency keys / request dedup.
- Detailed observability event taxonomy (`clip_fetched`, `aspect_rendered`, etc.) and Cloud Monitoring derived metrics.
- Public "recently rendered comps" feed.
- Atomic Firestore-transaction job claim (v1 ships best-effort optimistic claim; duplicate-render risk is tiny at low concurrency).
- naddr list `a`-tag (addressable refs) resolution — v1 surfaces them in `clips_dropped` with reason `addressable_ref_not_supported_v1`.

## Constraints

- **Max clips per job: 500.** Enforced in the worker — job transitions to `failed` with `error: "too_many_clips"` if the resolved list exceeds this. (V2 may add a sync 400 for `event_ids` input.)
- **Output duration:** whatever the caller requests via `max_duration_sec` (default 600 if unspecified). No hard ceiling. Clips past the cap are tail-dropped and recorded in `clips_dropped`.
- **Empty resolved clip list** (zero usable clips after fetch/probe/download) → job fails with `error: "no_usable_clips"`. Don't render an empty MP4.
- **No request dedup.** Two identical `POST /compile` payloads create two independent jobs. Caller is responsible for not double-submitting.
- **Job working dir** is `/tmp/job_<id>/`, removed when the worker finishes regardless of outcome.
- Service does **not** sign or publish anything to Nostr. Caller signs whatever kind 34235 they want with the returned blob descriptors.

## Text rendering

Credits and any future text overlays use the Noto Sans family bundled in the Docker image via Debian packages pinned in the Dockerfile: `fonts-noto-core`, `fonts-noto-cjk`, `fonts-noto-extra` (Arabic ships in the extras). Pin to a specific Debian apt snapshot date so rebuilds are reproducible. fontconfig routes per glyph run. ~30 MB image cost, covers everything we'll realistically see.

## Rate limiting

Per-tenant. Tenant id is derived from auth (see Auth section above): `pubkey:<hex>` for NIP-98, `secret:<name>` for webhook secrets where the name comes from the service's env config (not a client-supplied header).

Defaults: **20 jobs/hr, 100 jobs/day** per tenant. Overrides live in Firestore at `rate_limits/<tenant_id>`. Counters are Firestore atomic increments with field-level TTL. Exceeded → `429 Too Many Requests` with `Retry-After` header.

## Observability

V1 emits three structured `tracing` log lines per job, picked up by Cloud Logging:

- `event="queued"` — at `POST /compile` (carries `job_id`, `tenant_id`)
- `event="started"` — when worker claims the job
- `event="done"` — at terminal state (carries `status`, `error?`)

A richer event taxonomy (`clip_fetched`, `clip_dropped`, `aspect_rendered`, `uploaded`) plus Cloud Monitoring derived metrics (`compiler_jobs_total{status}`, `compiler_render_duration_seconds`, `compiler_gpu_seconds_total`, `compiler_clips_dropped_total{reason}`, `compiler_rate_limit_hits_total{tenant_kind}`) is **v2+** — the full `clips_dropped` array is already on the job doc, so operators can derive these post-hoc from `GET /admin/jobs/:job_id` until the metrics layer ships.

## Admin endpoints

Auth: `Authorization: Bearer $COMPILER_ADMIN_TOKEN`. (Pubkey-allowlist admin auth is v2+.)

- `GET /admin/jobs?limit=50&status=...` — paginated recent jobs (newest first). Returns the array of `Job` records.
- `GET /admin/jobs/:job_id` — full detail: caller, source event ids, all credits, all output URLs, all `clips_dropped` reasons.

Admin endpoints are for operator visibility ("see what people are making") and incident response. `cancel`, `requeue`, `GET /admin/tenants`, and a public "recently rendered comps" feed are all v2+ — see deferred list.

## Output encoding

- **Codec:** H.264 + AAC in MP4 with `+faststart`. yuv420p.
- **Single bitrate per aspect:** 9:16 ≈ 6 Mbps @ 1080×1920, 1:1 ≈ 5 Mbps @ 1080×1080, 16:9 ≈ 6 Mbps @ 1920×1080. AAC 128 kbps stereo.
- **NVENC params** are lifted from the transcoder's existing pipeline.
- **Audio loudness:** single-pass `loudnorm` filter targeting `target_lufs` (default -14). Single-pass is good enough for short comps and avoids the two-pass measure-then-encode dance; the transcoder also uses single-pass.

## Concurrency and lifecycle

- Each Cloud Run instance processes up to 4 jobs in parallel (FFmpeg/NVENC slots shared).
- `max_instances` on the Cloud Run service starts at 5; tune from real traffic.
- Each job uses its own temp working dir under `/tmp/job_<id>/` and cleans up on completion (or on instance shutdown via SIGTERM handler).
- Comp MP4s are regular blossom blobs with no special TTL. Caller can `DELETE` if they want them gone. No GC job in v1.

## What's reused from cloud-run-transcoder

- `Dockerfile` GPU base image, NVENC build flags.
- `deploy.sh` shape and Artifact Registry repo pattern.
- ffprobe / GPU-encode-with-CPU-fallback logic.
- Webhook callback retry shape.
- Single-pass loudnorm pattern.

## Decisions locked

- **Job state:** Firestore (collection `compilation_jobs`, doc id = job_id). No fallback. Rate-limit counters live in `rate_limits/<tenant_id>` and depend on Firestore atomic increments. Job docs are retained indefinitely in v1 (jobs are small JSON; a TTL/GC is a future operational tune, not v1 scope).
- **Logo:** fetched at worker startup from `https://media.divine.video/divine-logo.png` (CDN-served, single source of truth, no rebuild needed to refresh the logo). Cached on local disk for the worker's lifetime.
- **Event/profile fetch:** `https://api.divine.video` REST API. No relay WebSocket.
- **Moderation:** `Restricted` and `AgeRestricted` source blobs are silently skipped in v1 and surfaced in `clips_dropped`. Per-user age-gate (caller opts in, request carries their auth, service fetches with that auth) is **v2+** — too much complexity for v1.
