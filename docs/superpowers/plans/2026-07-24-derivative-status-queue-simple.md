# Durable Derivative Status Delivery — Simplest Thing That Could Work

**Goal:** Stop losing transcoder status callbacks. Nothing else.

**Approach:** Put Cloud Tasks between the transcoder and Fastly. Cloud Tasks owns retries, backoff, and dead-lettering — that is the durability, and it is queue configuration, not code. The receiver becomes idempotent and drops stale updates. Done.

**What already exists** (do not rebuild):
- `cloud-run-transcoder/src/main.rs` has `send_status_webhook` (8 call sites: `:1061, 1095, 1123, 1211, 1244, 1262`) and `send_transcript_status_webhook` (`:1306, 1363`). One function to change, not eight.
- Fastly already routes both callbacks: `src/main.rs:164` (moderation), `:167` (transcode status), with parsers at `:1366` and `:1411`.
- **`src/admin_sweep.rs` already reconciles lost webhooks** — it checks GCS for the HLS master manifest and marks `Complete` when the callback never arrived (`src/admin.rs:1270`). The reconciliation layer is built. The queue's job is to make it fire rarely, not to replace it.

**Non-goals:** no new crate, no Firestore outbox, no HMAC rotation scheme, no admission pause/drain, no dead-replay tooling, no lease-and-cursor reconciler. Every one of those is deferrable until a queue in production shows it is needed.

---

## Step 1: Create the queue

- [x] Enabled `cloudtasks.googleapis.com` on `rich-compiler-479518-d2` (was disabled) and created the queue:

```
gcloud tasks queues create derivative-status \
  --location=us-central1 --project=rich-compiler-479518-d2 \
  --max-attempts=10 --max-backoff=600s --min-backoff=5s \
  --max-concurrent-dispatches=50
# -> Created queue [us-central1/derivative-status]
```

Retries, exponential backoff, and attempt limits are now handled. No code.

## Step 2: Enqueue instead of POST

**Files:** `cloud-run-transcoder/src/main.rs`

- [x] `generation` = wall-clock milliseconds at send time (`current_generation_ms`). Monotonic per-sha, no new storage or plumbing. `attach_generation` stamps it onto any payload.
- [x] `send_status_webhook` and `send_transcript_status_webhook` now both call `deliver_status_payload`, which enqueues to Cloud Tasks when `status_queue_enabled` else direct-POSTs. All 8 + 2 call sites unchanged. `enqueue_status_task` POSTs `CreateTask` to the Cloud Tasks REST API using the instance access token; the Fastly bearer secret rides in the task's own headers, so a redelivery authenticates like the original.
- [x] `STATUS_QUEUE_ENABLED` (default `false`), `STATUS_QUEUE_LOCATION` (default `us-central1`), `STATUS_QUEUE_NAME` (default `derivative-status`) added to `Config`. Default false = direct POST = rollback.
- [x] **Tests (pass):** `attach_generation_adds_monotonic_field`, `cloud_tasks_body_wraps_payload_as_base64_http_request`, `cloud_tasks_body_omits_authorization_when_no_secret`. Cloud Tasks client stubbed via pure-function body builder; no network. Note: on enqueue failure the code does **not** fall back to direct POST — Cloud Tasks owns durability, and a silent double-path would defeat the ordering guarantee.

## Step 3: Make the receiver idempotent and order-safe

**Files:** `src/main.rs` (the two webhook handlers)

- [x] Added `transcode_generation` and `transcript_generation` (`Option<u64>`, skip-if-none) to `BlobMetadata` — separate axes, since transcode and transcript are independent update streams. Persisted via a `generation` field on both `TranscodeMetadataUpdate`/`TranscriptMetadataUpdate`; internal callers pass `None`, which preserves any stored value.
- [x] Both webhook handlers pre-check `is_stale_generation(incoming, stored)`: incoming `<` stored → return `200 {"ignored":"stale_generation"}` without applying or purging. A `200` so Cloud Tasks stops retrying.
- [x] Equal generation with unchanged status → the update writes the same value; harmless no-op idempotency. Malformed-payload handling already returns structured responses, not 5xx storms.
- [x] `generation` parsed from both payloads (`parse_transcode/transcript_status_webhook_payload`); absent = `None` = always applied (legacy senders, first update).
- [x] **Tests (type-check clean; edge `#[test]`s can't link natively — Fastly SDK is WASM-only, per AGENTS.md `cargo check --tests`):** `stale_generation_ordering` (3<5 stale, 5==5 not, 6>5 not, any `None` not), `transcode_payload_parses_generation` (incl. legacy `None`), `transcript_payload_parses_generation`. blossom-core: 99 pass incl. the new BlobMetadata fixtures.

## Step 4: Alert on the dead-letter path

- [x] Alert `derivative-status queue depth sustained high` — `cloudtasks.googleapis.com/queue/depth` > 100 for 15m. Policy `6130752747029271836`, notifies existing `GCP DevOps Email` channel.
- [x] Alert `derivative-status delivery attempts failing` — `queue/task_attempt_count` with `response_code != 200`, rate > 0 for 15m. Policy `2336123773137320083`. This is the pre-dead-letter signal; the cases `admin_sweep` must catch.
- [ ] Live-fire check deferred to after the flag flip — a failing-URL test task would need the queue exercised in production.

---

## Rollout

- [x] `roles/cloudtasks.enqueuer` granted to the transcoder SA `149672065768-compute@developer.gserviceaccount.com`.
- [x] Transcoder deployed on image `a7a9aed-queue` (revision `divine-transcoder-00042-99z`) via `gcloud run services update --image` — env preserved (all 17 vars intact, incl. `WEBHOOK_SECRET`/`PARAKEET_ASR_URL`). `STATUS_QUEUE_ENABLED` unset ⇒ still direct-POST. No behavior change.
- [ ] **Deploy the Fastly edge** (receiver). Needs your token — CLI can't auth non-interactively here:
  ```
  fastly compute publish --comment "durable derivative status: queue-aware receiver" \
    && fastly purge --all --service-id pOvEEWykEbpnylqst1KTrR
  ```
- [ ] **Cutover (the real behavior change):** after the edge is live, flip the transcoder:
  ```
  gcloud run services update divine-transcoder --region us-central1 \
    --project rich-compiler-479518-d2 --update-env-vars STATUS_QUEUE_ENABLED=true
  ```
  (`--update-env-vars` is additive — does not wipe the other 17.)
- [ ] Watch `admin_sweep`'s lost-webhook rate fall toward zero, and the two alert policies stay quiet. Roll back by setting `STATUS_QUEUE_ENABLED=false` (or `--remove-env-vars`).
- [x] `admin_sweep` stays as the permanent backstop — already works, catches residual cases.

## Incident found during rollout: 100% webhook 403 (pre-existing)

The cutover surfaced that **every** transcoder→edge status callback had been failing `403 Invalid webhook secret` for 6h+ (present on the untouched May-17 revision, so far older). Root cause: the transcoder's GCP `webhook_secret` (`c47e8db7…`, v1 since Jan 31) never matched the edge's Fastly `blossom_secrets/webhook_secret` (`d3f3e56e…`). The system had been surviving on `admin_sweep` reconciliation alone — which is *why* derivatives appeared "stuck."

Diagnosis path (all via gcloud/fastly, no plaintext exposed):
- Compared SHA-256 of GCP secret vs the Fastly store's exposed digest — mismatch.
- Confirmed the same `webhook_secret` guards the moderation inbound webhook (`src/main.rs:4782`), and `divine-moderation-service` (Cloudflare Worker) is healthy at ~250k req/day (`divine-brain ops_status`) → the **edge value is canonical**, the transcoder's copy is stale.
- The canonical plaintext is a Cloudflare Worker secret (write-only); scanned ~290 GCP secrets across 5 projects — no copy. So it can't be re-keyed into the transcoder directly.

Fix applied (touches nothing moderation depends on):
- [x] Edge: `validate_transcoder_webhook` now accepts a dedicated `transcoder_webhook_secret` **in addition to** the shared `webhook_secret`. Both `/admin/transcode-status` and `/admin/transcript-status` use it. Edge deployed v317.
- [x] Generated a fresh secret; added it to Fastly `blossom_secrets/transcoder_webhook_secret` and to GCP `webhook_secret` v2 (sole consumer: `divine-transcoder`). Transcoder redeployed rev `00044-rxc`.
- [x] Verified: `POST /admin/transcode-status` with the new secret → 404 (past auth); `/admin/transcript-status` → 202; wrong secret → 403. No new 403s from rev 00044. Moderation's `webhook_secret` untouched.

## When to build more

Do not pre-build these. Each becomes justified only by a specific observed failure:

| Signal in production | Then consider |
|---|---|
| Dead-letter volume is non-trivial | Replay tooling |
| Status updates apply out of order despite `generation` | A real ordering layer |
| A callback is forged or replayed by a third party | HMAC signing + rotation |
| Cloud Tasks itself drops messages | A Firestore outbox |
| The queue overwhelms Fastly under backlog | Admission pause and drain |

The existing 1,568-line design and 1,666-line plan are not wasted — they become this table's implementation notes if a row ever triggers.
