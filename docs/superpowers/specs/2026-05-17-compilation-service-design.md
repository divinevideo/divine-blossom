# Compilation Service: Design Spec

## Goal

A backend service that takes a Nostr list of video events and produces a single concatenated MP4 compilation, with the Divine logo watermark and per-clip nip05 credits burned in, ready for upload to TikTok / Reels / YouTube. No UI — HTTP API only.

## Solution

New Cloud Run service `cloud-run-compiler/`, parallel to `cloud-run-transcoder/`. Same stack: Rust + FFmpeg + NVIDIA NVENC. Reuses transcoder patterns for deploy, auth, GCS layout, webhook callbacks.

## API

### `POST /compile`

```json
{
  "source": {
    "naddr": "naddr1..."           // OR
    "event_ids": ["<hex>", ...]    // OR
    "nevents": ["nevent1...", ...]
  },
  "aspects": ["9:16", "1:1", "16:9"],   // one or more; default ["9:16"]
  "fit": "blur-pad",                     // blur-pad | center-crop | letterbox; default blur-pad
  "per_clip_overrides": [                // optional
    { "event_id": "<hex>", "fit": "center-crop", "in_sec": 0.5, "out_sec": 5.8 }
  ],
  "watermark": {
    "enabled": true,
    "position": "bottom-right",          // top-left | top-right | bottom-left | bottom-right
    "opacity": 0.30
  },
  "credit": {
    "mode": "lower-third-fade",          // lower-third-fade | always-on | corner-pill | off
    "duration_ms": 2500,
    "show_display_name": true,
    "show_nip05": true
  },
  "audio": {
    "mode": "passthrough",               // passthrough | mute | ducked-under-music
    "bgm_url": null,                     // optional
    "target_lufs": -14
  },
  "transition": "cut",                   // cut | crossfade | dip-to-black
  "transition_ms": 0,
  "intro_card": null,                    // optional { title, subtitle, duration_ms }
  "outro_card": null,                    // same shape
  "max_duration_sec": 600,               // soft cap; tail clips dropped with warning
  "callback_url": "https://..."          // POST'd when job completes
}
```

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
  "error": null
}
```

When `status` transitions to `done` or `failed`, the service POSTs the same body to `callback_url` (fire-and-forget, 3 retries with exponential backoff). The POST carries `X-Compiler-Signature: sha256=<hex>` where the hex is `HMAC_SHA256(COMPILER_WEBHOOK_SECRET, raw_body)`. Caller verifies before trusting the payload.

### Auth

Either of these is sufficient on `POST /compile` and `GET /compile/:job_id`:

- **NIP-98** — preferred. Caller's pubkey is extracted and logged on the job for audit/abuse.
- **Webhook shared-secret** (`Authorization: Bearer $COMPILER_WEBHOOK_SECRET`) — fallback for trusted internal callers (funnelcake, etc.). No pubkey logged; `requested_by` is set to the calling service's name from a header.

If both are present, NIP-98 wins. If neither is present, 401.

## Pipeline

```
1. Validate request, persist job to Firestore (`compilation_jobs/<job_id>`), return job_id.
2. Worker picks up job:
   a. Resolve source → list of event refs (e/a tags from naddr in their literal
      tag order, or `event_ids`/`nevents` in the order the caller supplied).
      No sort, no shuffle — render order is whatever the input gave us.
   b. Fetch each event (kind 34235/34236) + each author's kind 0 profile via
      `https://api.divine.video` REST API. No relay WebSocket — REST is simpler,
      no reconnects, no subscription management. **Caveat:** REST responses can
      flatten events and lose tag data (e.g. `sha256` from `imeta`); request raw
      tags / event JSON, do not rely on flattened helper fields. (See
      `nostr-rest-api-field-mapping-gap` skill.)
   c. For each video event: pull sha256 from `imeta` tag, download the MP4 original from
      `https://media.divine.video/<sha256>` (parallel, bounded concurrency = 4). HLS
      renditions are not used as input — comp re-encodes anyway, so we go straight
      from the original. Skip blobs whose Blossom metadata is `Restricted` or
      `AgeRestricted` and record them in `clips_dropped`.
   d. ffprobe each downloaded file: duration, dim, codec, rotation.
   e. Build clip list, apply per_clip_overrides, drop anything past max_duration_sec.
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

- Input shapes: `naddr` and `event_ids` (skip `nevents` parsing in v1 — caller can hex-decode).
- Multi-aspect render (any combo of 9:16 / 1:1 / 16:9 in one job).
- All three fit modes.
- Per-clip `in_sec` / `out_sec` trim and `fit` override.
- Static-corner watermark + lower-third-fade credit (just one mode each implemented; other credit/watermark modes in the API schema return 400 in v1).
- Passthrough audio + loudnorm.
- Hard cut transitions only (`crossfade` / `dip-to-black` return 400).
- Webhook callback with HMAC signature.
- NIP-98 auth **and** webhook shared-secret auth (either sufficient).
- Rate limiting (Firestore counters).
- Observability (structured logs + derived metrics).
- Admin endpoints.
- Dry-run mode.

## What's deferred to v2+

- `always-on` / `corner-pill` credit modes.
- Crossfade / dip-to-black transitions.
- Intro / outro cards.
- BGM mixing (`ducked-under-music`).
- Animated watermark intro.
- Per-clip caption override.
- Caller-auth pass-through so age-restricted blobs can be included if the caller has access.
- Public "recently rendered comps" feed (admin-only in v1).
- Per-tenant idempotency keys.
- Per-job concurrency dynamic tuning based on GPU utilization.

v2+ fields/values present in a v1 request → `400 Bad Request` with the unsupported field listed. Failing loudly is cheaper than silent surprises.

## Constraints

- Max clips per job: 500 (enforced via 400). Sanity cap, not a cost ceiling.
- Max total source bytes downloaded: 20 GB (enforced via 400 if estimate exceeds; estimate from blossom `Content-Length` HEAD).
- Output duration: whatever the caller requests via `max_duration_sec` (default 600 if unspecified). No hard ceiling.
- Empty resolved clip list (zero usable clips after fetch/probe/moderation) → job fails with `error: "no_usable_clips"`. Don't render an empty MP4.
- Service does **not** sign or publish anything to Nostr. Caller signs whatever kind 34235 they want with the returned blob descriptors.

## Text rendering

Credits and any future text overlays use the Noto Sans family bundled in the Docker image: Noto Sans (Latin), Noto Sans CJK (Chinese/Japanese/Korean), Noto Sans Arabic. fontconfig routes per glyph run. ~30 MB image cost, covers everything we'll realistically see.

## Rate limiting

Per-tenant. Tenant id is:

- `pubkey:<hex>` for NIP-98 callers
- `secret:<name>` for webhook-secret callers (name comes from a request header set by the caller, e.g. `X-Caller-Service: funnelcake`)

Defaults: **20 jobs/hr, 100 jobs/day** per tenant. Overrides live in Firestore at `rate_limits/<tenant_id>`. Counters are Firestore atomic increments with field-level TTL. Exceeded → `429 Too Many Requests` with `Retry-After` header.

## Observability

Every job event emits a structured JSON log line picked up by Cloud Logging:

```json
{
  "job_id": "cmp_01HXY...",
  "event": "queued | started | clip_fetched | clip_dropped | aspect_rendered | uploaded | done | failed",
  "caller": { "kind": "nip98", "pubkey": "..." } | { "kind": "webhook", "tenant": "funnelcake" },
  "source_kind": "naddr | event_ids | nevents",
  "clip_count": 23, "clips_dropped": 2,
  "aspects": ["9:16","1:1","16:9"],
  "duration_sec": 487, "render_time_sec": 142, "gpu_seconds": 89,
  "error": null
}
```

Cloud Monitoring metrics derived from logs:

- `compiler_jobs_total{status}`
- `compiler_render_duration_seconds` (histogram)
- `compiler_gpu_seconds_total`
- `compiler_clips_dropped_total{reason}`
- `compiler_rate_limit_hits_total{tenant_kind}`

## Admin endpoints

Auth: admin pubkey allowlist (`COMPILER_ADMIN_PUBKEYS` env, comma-separated hex) **or** `Authorization: Bearer $COMPILER_ADMIN_TOKEN`.

- `GET /admin/jobs?limit=50&cursor=...&status=...&since=...` — paginated recent jobs (newest first). Returns job summaries.
- `GET /admin/jobs/:job_id` — full detail: caller, source event ids, all credits, all output URLs, all `clips_dropped` reasons.
- `GET /admin/tenants` — tenants with job counts, GPU minutes used, rate-limit overrides.
- `POST /admin/jobs/:job_id/cancel` — kill an in-flight job.
- `POST /admin/jobs/:job_id/requeue` — re-run a failed job with the original input.

Admin endpoints are for operator visibility ("see what people are making") and incident response. A future public "recently rendered comps" feed is explicitly **not** in v1 — that's a product surface, not the service's job.

## Dry-run mode

If the request includes `"dry_run": true`, the job:

1. Resolves the source list.
2. Fetches each event + author profile via `api.divine.video`.
3. HEADs each blob URL to confirm it exists and is fetchable.
4. Skips download, probe, render, and upload entirely.
5. Returns `result.credits` and `result.clips_dropped` populated; `result.outputs` is `[]`.
6. Marks job `done` with `dry_run: true` in the result.

Lets a caller preview what a comp would contain before spending GPU time on it.

## What's reused from cloud-run-transcoder

- `Dockerfile` GPU base image, NVENC build flags.
- `deploy.sh` shape and Artifact Registry repo pattern.
- ffprobe / GPU-encode-with-CPU-fallback logic.
- Webhook callback retry shape.
- Loudnorm two-pass pattern (if transcoder already does this — otherwise lift from FFmpeg docs).

## Behavior

- **Render order:** literal input order (list-tag order or caller-supplied array order). No sort, no shuffle.
- **Per-clip failure:** drop-and-continue. Failures recorded in `clips_dropped`. Job only fails if zero clips usable.
- **Dedup:** none. Two identical requests = two jobs.
- **Output lifetime:** comp MP4s are regular blossom blobs with no special TTL. Caller can `DELETE` if they want them gone. No GC job in v1.
- **Concurrency:** each Cloud Run instance processes up to 4 jobs in parallel (FFmpeg/NVENC slots shared). `max_instances` on the Cloud Run service starts at 5; tune from real traffic. Each job uses its own temp working dir under `/tmp/job_<id>/` and cleans up on completion.
- **Output codec:** H.264 + AAC in MP4 with `+faststart`. yuv420p. Single bitrate per aspect (9:16 ≈ 6 Mbps @ 1080×1920, 1:1 ≈ 5 Mbps @ 1080×1080, 16:9 ≈ 6 Mbps @ 1920×1080). AAC 128 kbps stereo. Lifts the transcoder's existing NVENC params.

## Decisions locked

- **Job state:** Firestore (collection `compilation_jobs`, doc id = job_id). Falls back to GCS JSON file if Firestore setup is more work than expected during implementation.
- **Logo:** fetched at worker startup from `https://media.divine.video/divine-logo.png` (CDN-served, single source of truth, no rebuild needed to refresh the logo). Cached on local disk for the worker's lifetime.
- **Event/profile fetch:** `https://api.divine.video` REST API. No relay WebSocket.
- **Moderation:** `Restricted` and `AgeRestricted` source blobs are silently skipped in v1 and surfaced in `clips_dropped`. Per-user age-gate (caller opts in, request carries their auth, service fetches with that auth) is **v2+** — too much complexity for v1.
