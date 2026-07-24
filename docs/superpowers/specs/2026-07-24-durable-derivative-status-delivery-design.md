# Durable Derivative Status Delivery Design

**Date:** 2026-07-24
**Issue:** divine-funnelcake#686
**Status:** Design review, revision 3

## Problem and baseline

The Cloud Run transcoder sends transcript and transcode status updates to
Fastly as fire-and-forget HTTP requests. A non-2xx response is logged, but the
job continues and the update is permanently lost.

During the current incident, transcript and HLS artifacts continued to be
written to GCS while Fastly rejected callbacks with `403 Invalid webhook
secret`. In one 24-hour investigation window, 2,360 callbacks for 444 hashes
were rejected. At the same time, Parakeet returned 337 successful responses
and 242 distinct VTT artifacts were uploaded. Lost terminal invalid-media
updates also caused one corrupt source to be processed and reported
repeatedly.

The reliability boundary must be the status event itself, not the lifetime of
one Cloud Run request.

## People and use cases

### Creator

WHO finishes an upload, WANTS completed transcript and transcode derivatives
to become discoverable, SO THAT the video is playable and captioned without
uploading again, WHEN Fastly or callback authentication is temporarily
unavailable.

WHO uploads invalid media, WANTS one stable terminal result, SO THAT the same
source is not processed indefinitely, WHEN terminal-status delivery is
temporarily unavailable.

### Viewer

WHO opens processed media, WANTS playback and subtitle availability to reflect
the artifacts that exist, SO THAT completed derivatives do not appear missing,
WHEN status events are delayed, duplicated, or delivered out of order.

### On-call operator

WHO repairs an outage or credential mismatch, WANTS pending status events to
drain automatically, SO THAT affected users recover without retranscoding,
WHEN delivery resumes.

WHO receives a dead-letter alert, WANTS a dry-run and replay workflow, SO THAT
a permanently malformed or rejected event can be corrected without editing
production storage by hand.

## Goals

- Persist every transcript and transcode status event before acknowledging
  publication.
- Survive temporary network, Fastly, credential, Cloud Tasks, and task-create
  failures.
- Make duplicate and out-of-order delivery harmless across every durable side
  effect.
- Rotate a route-scoped delivery credential without deploying the delivery
  worker.
- Detect a stuck backlog within five minutes.
- Recover incident-window artifacts and explicitly identified terminal
  failures without retranscoding.
- Prevent public callers from using processor routes to amplify compute,
  outbox, or queue cost.
- Keep this specific to derivative status delivery.

## Non-goals

- Replacing Fastly KV as the public metadata store.
- Replacing transcription or HLS generation.
- Strict FIFO ordering from Cloud Tasks.
- Building a reusable company-wide event platform.
- Automatically inferring historical terminal failures from unstructured
  error text.

## MVP and deferred work

The MVP includes:

- route-authenticated processor entry points;
- a typed, durable GCS outbox;
- one Cloud Tasks queue with enforced routing and authentication;
- one private delivery service;
- one private scheduled reconciliation job;
- versioned Fastly status endpoints with generation-matched writes;
- incident recovery tooling;
- metrics, alerts, and a checked-in runbook.

There is no direct-webhook fallback after queue-first publishing is enabled.
An unordered direct path would bypass the delivery guarantees. A later project
may consolidate this pattern with other Divine outboxes after production
evidence exists.

## Architecture

Build three small Rust binaries from shared modules:

- `divine-transcoder`: the existing processor, with authenticated entry points
  and queue-first status publication.
- `divine-status-delivery`: a lightweight private Cloud Run service with no
  CUDA or FFmpeg runtime.
- `divine-status-reconciler`: a lightweight Cloud Run Job using the delivery
  library but without the delivery credential.

```text
Authenticated processor
  -> create typed event
  -> immutable create in private GCS outbox
  -> create deterministic Cloud Task
  -> finish processing request

Cloud Tasks, queue-level OIDC and route override
  -> private delivery service
  -> load and validate pending event
  -> read current HMAC secret from mounted volume
  -> sign and POST full event to versioned Fastly route
  -> Fastly applies each durable effect with KV generation-match
  -> worker deletes pending event only after Fastly reports durable acceptance

Cloud Scheduler
  -> private Cloud Run reconciliation job
  -> resume paginated outbox scan from durable cursor
  -> recreate missing deterministic tasks
```

## Repository boundaries

Shared status types and pure decisions live in a library module that does not
depend on Axum, GCS, Cloud Tasks, or Fastly:

- `StatusEvent` and derivative-specific update types;
- validation;
- total ordering;
- retry/dead-letter classification;
- Fastly apply decisions.

Runtime adapters implement narrow interfaces:

- `OutboxStore`
- `TaskQueue`
- `WebhookClient`
- `SecretProvider`
- `Clock`
- `IdGenerator`

Router construction accepts these interfaces so service tests do not start the
GPU processor or require live cloud services.

Deployment scripts and configuration for the queue, private service,
reconciliation job, IAM bindings, log-based metrics, and alert policies are
owned in this repository under `cloud-run-transcoder/`. They require project,
region, bucket, service-account, and notification-channel inputs; they do not
embed credentials.

## Authentication boundaries

### Processor routes

The public Cloud Run service remains reachable because Fastly invokes it, but
all non-health routes require a dedicated `processor_request_secret` HMAC:

- `/transcode`
- `/transcribe`
- `/backfill-fmp4`
- `/audio/extract`
- any future route that can start work or write an outbox event

Fastly and the upload service sign the raw request body using a timestamped
HMAC. The canonical preimage is:

```text
v1
<uppercase HTTP method>
<exact normalized path, with no query string>
<unix timestamp seconds>
<canonical UUIDv7 request ID>
<lowercase hex SHA-256 of the raw body>
```

Callers send exactly one value for each of:

- `X-Divine-Auth-Version: v1`
- `X-Divine-Timestamp`
- `X-Divine-Request-Id`
- `X-Divine-Signature: <lowercase hex HMAC-SHA256>`

Each route rejects query strings, duplicate auth headers, non-canonical
encodings, timestamps outside five minutes, and signatures that fail a
constant-time comparison. HMAC keys contain at least 256 random bits; missing,
empty, short, or invalid keys fail readiness.

Before buffering or parsing JSON, route-specific body limits apply:

- `/transcode` and `/transcribe`: 8 KiB;
- `/backfill-fmp4`: 8 KiB;
- `/audio/extract`: 4 KiB.

After authentication, the processor creates
`processor-requests/<request_id>` in the private outbox bucket with
`ifGenerationMatch=0` and a 24-hour lifecycle. The marker contains the method,
path, body digest, and operation ID but no request body or credential. A
pre-existing marker returns `409 replay_detected` without starting work.
Trusted callers regenerate the timestamp, request ID, and signature for an
intentional retry; they never retry a 409 with the same signed request.
Because the signed digest binds the body, a captured request ID cannot
authorize a different payload or route. The replay marker is created before
expensive work or outbox publication.

The processor checks the signature in constant time and rejects unsigned
requests before parsing the body or allocating expensive work. CORS is limited
to the required production origin and does not substitute for authentication.

Existing per-hash transcript locking remains. Transcode receives the same
idempotent in-progress lock to suppress trusted duplicate work.

### Fastly status routes

Add dedicated routes:

- `POST /internal/derivative-status/v1/verify`
- `POST /internal/derivative-status/v1/transcript`
- `POST /internal/derivative-status/v1/transcode`

They accept only a new `derivative_status_secret` HMAC. This credential is not
accepted by admin, moderation, delete, restore, dashboard, or legacy webhook
routes. The current `webhook_secret` is never mounted in the delivery service.

The verify route accepts a signed, bounded nonce body and performs no metadata
mutation. It exists only for credential-rotation and deployment smoke tests
and uses the same signature verifier and rate limit as the status routes.

The delivery worker signs:

```text
v1
POST
<exact normalized versioned path>
<unix timestamp seconds>
<lowercase hex SHA-256 of raw request body bytes>
```

It sends the timestamp and lowercase hex HMAC-SHA256 signature in dedicated
headers:

- `X-Divine-Auth-Version: v1`
- `X-Divine-Timestamp: <unix seconds>`
- `X-Divine-Signature: <lowercase hex HMAC-SHA256>`
- `Content-Type: application/json`

Fastly rejects query strings, duplicate auth headers, a derivative that does
not match the selected route, and invalid encodings. It verifies the signature
in constant time and allows at most five minutes of clock skew.

The worker pins the exact HTTPS origin and route in configuration, disables
redirects, uses a 3-second connect timeout and 10-second total timeout, and
reads at most 16 KiB of an upstream response.

### Secret rotation

Fastly accepts `derivative_status_secret_primary` and, during rotation only,
`derivative_status_secret_secondary`. GCP exposes the current secret to the
delivery service as a mounted `latest` secret file, which is read for each
attempt.

Rotation order:

1. Place the new value in Fastly's secondary slot.
2. Add a new GCP secret version and make it latest.
3. Call the non-mutating signed verify route and confirm the new credential is
   accepted.
4. Promote the new Fastly value to primary.
5. Remove the old secondary value within one hour.
6. Alert on any use of the retiring credential after promotion.

The processor HMAC credential uses the same overlap procedure but remains a
separate secret.

## IAM and identity matrix

All service accounts are keyless.

| Identity | Allowed operations |
| --- | --- |
| Processor runtime | Create/read pending objects; create replay markers; create tasks in the one status queue; no list/delete |
| Delivery runtime | Read/delete pending objects; create/read dead objects; access only `derivative_status_secret`; no list/task-create |
| Reconciler runtime | List/read pending objects; create tasks; read/write reconciliation cursor |
| Cloud Tasks OIDC identity | Invoke only `divine-status-delivery` |
| Scheduler identity | Execute only `divine-status-reconciler` |
| Cloud Tasks service agent | Mint tokens for the task OIDC identity as required by Google |
| Recovery CLI identity | Read media artifact metadata and Fastly derivative status; create/read outbox events and tasks; no media-body read or delete |
| Deployment identity | Manage declared resources and `actAs` only the identities needed during deployment |

The queue uses queue-level `ALWAYS` overrides for HTTPS scheme, delivery host,
delivery path, POST method, OIDC service account, and audience. Producers
cannot choose a target or authentication identity. Only the deployment
identity needs `iam.serviceAccounts.actAs` while configuring that override;
task creators receive no impersonation role.

These permissions are implemented as bucket/queue/service-scoped custom roles
where predefined roles are broader than the table. Bucket access is reviewed
quarterly. Structured operational logs are retained for 30 days; Sentry uses
the project's restricted operational retention policy and stores only the
sanitized fields defined here.

## Private outbox

Use a dedicated private bucket with public-access prevention and uniform
bucket-level access. It contains no media:

- `pending/<event_id>.json`
- `dead/<event_id>.json`
- `processor-requests/<request_id>`
- `control/reconcile-cursor.json`
- `control/reconcile-lease.json`

Pending objects have no expiration lifecycle. Dead objects expire after 30
days, and processor request markers expire after 24 hours. Unknown-schema and
credential-failure pending objects remain until code/configuration is repaired
or an operator explicitly classifies them. Access is granted according to the
IAM matrix rather than by relying on a textual prefix in the media bucket.

Pending creation uses `ifGenerationMatch=0`. If the same event already exists,
the producer uses its narrow read permission to verify that its canonical
bytes match; a mismatch is an integrity error that fails publication and
alerts.

Successful cleanup deletes the exact generation read by the worker. Dead
movement creates the dead object with `ifGenerationMatch=0` before deleting
the matching pending generation. A crash at any boundary leaves at least one
recoverable copy.

## Producer publication state machine

Every status transition uses the same steps:

1. Construct and fully validate the canonical typed event.
2. Create the immutable pending object.
3. Create its deterministic Cloud Task with bounded client retries.
4. Return publication success once the pending object is durable, even if task
   creation failed; the reconciler owns the producer-to-queue gap.

For the initial `processing` transition, failure to persist pending returns 503
and the processor does not start expensive work. For `complete` or `failed`,
failure to persist pending returns 503 even if compute or artifact upload
already occurred; it is never converted to job success.

An intentional caller retry uses a new signed request ID. Existing-artifact
checks then publish `complete` without recomputation. Existing transcript and
transcode locks prevent overlapping compute. A terminal failure that already
has a durable pending event is not recreated within that operation; its
deterministic event ID makes repeat publication idempotent.

Outcomes:

| Condition | Processor behavior |
| --- | --- |
| Event validation fails | Internal error; no pending/task; alert |
| Pending create succeeds | Attempt task creation |
| Matching pending object already exists | Treat pending as durable and attempt task creation |
| Existing pending bytes differ | Integrity error; no work/success; alert |
| Task creation succeeds or returns `AlreadyExists` | Continue/return normal processor result |
| Task creation fails after bounded retries | Continue/return normal result because pending is durable; alert and reconcile |
| Pending persistence fails before work | Return 503; do not start work |
| Pending persistence fails after artifact/terminal result | Return 503; caller retries with a new signed request |

The processor response distinguishes media result from delivery state with
`status_delivery: queued|pending_reconciliation`. It never claims a status
event was delivered to Fastly synchronously.

## Event contract

Fastly receives the full event envelope. Cloud Tasks receives only the event
ID.

```json
{
  "schema_version": 1,
  "event_id": "018f6e33-c5af-5d82-a7b2-30f02e8f7e10",
  "sha256": "64 lowercase hex characters",
  "operation_id": "018f6e33-c5af-7b11-a2f7-7cf63d8a68ac",
  "operation_started_at_ms": 1784847000000,
  "sequence": 2,
  "created_at_ms": 1784847001234,
  "attempt_number": 1,
  "derivative": "transcript",
  "update": {
    "status": "complete",
    "job_id": "optional",
    "language": "en",
    "duration_ms": 6100,
    "cue_count": 3,
    "transcript_confidence": {
      "average_token_confidence": 0.91,
      "average_logprob": -0.09,
      "low_confidence_token_ratio": 0.02,
      "token_count": 47
    },
    "last_attempt_at_ms": 1784847001200
  }
}
```

The Rust type is a tagged enum:

- `DerivativeUpdate::Transcript(TranscriptUpdate)`
- `DerivativeUpdate::Transcode(TranscodeUpdate)`

The JSON uses `derivative` as the enum tag and `update` as its content.
Unknown fields are rejected.

### Transcript update

`status` is exactly `pending`, `processing`, `complete`, or `failed`.

| Field | Type and bound | Pending | Processing | Complete | Failed |
| --- | --- | --- | --- | --- | --- |
| `status` | enum | required | required | required | required |
| `job_id` | string, 1–128 bytes | optional | optional | optional | optional |
| `language` | ASCII BCP-47-shaped string, 1–35 bytes | optional | optional | optional | optional |
| `duration_ms` | `u64`, max 86,400,000 | forbidden | forbidden | optional | forbidden |
| `cue_count` | `u32`, max 1,000,000 | forbidden | forbidden | optional | forbidden |
| `transcript_confidence` | object below | forbidden | forbidden | optional | forbidden |
| `error_code` | safe identifier, 1–64 bytes | forbidden | forbidden | forbidden | required |
| `error_message` | safe template text, max 2,048 bytes | forbidden | forbidden | forbidden | optional |
| `retry_at_ms` | absolute Unix milliseconds | forbidden | forbidden | forbidden | optional |
| `terminal` | boolean | forbidden | forbidden | forbidden | required |
| `last_attempt_at_ms` | absolute Unix milliseconds | required | required | required | required |

`transcript_confidence` contains exactly:

- `average_token_confidence`: finite `f64` in `0.0..=1.0`;
- `average_logprob`: finite `f64` in `-100.0..=0.0`;
- `low_confidence_token_ratio`: finite `f64` in `0.0..=1.0`;
- `token_count`: `u32` in `1..=10_000_000`.

Blob assignments are:

- pending/processing: assign status and event timestamps; do not change the
  attempt counter;
- complete: assign status, clear errors/retry/terminal, and reset the blob
  transcript attempt counter to zero;
- failed: assign status/error/retry/terminal and set the blob transcript
  attempt counter to `max(current, attempt_number)`.

When `job_id` is present, the subtitle-job effect is required. Complete assigns
`Ready`, the stable VTT URL, and supplied language/duration/cue values, clears
error/retry fields, and preserves the job's attempt count. Failed assigns
`Failed`, safe error/retry fields, and sets the job attempt count to
`max(current, attempt_number)`. Pending and processing assign only their
corresponding job status and update timestamp.

When `job_id` is absent, no subtitle-job or hash-to-job effect is attempted.
The handler never guesses a job through the hash mapping.

### Transcode update

`status` is exactly `pending`, `processing`, `complete`, or `failed`.

| Field | Type and bound | Pending | Processing | Complete | Failed |
| --- | --- | --- | --- | --- | --- |
| `status` | enum | required | required | required | required |
| `new_size` | `u64`, max 53,687,091,200 | forbidden | forbidden | optional | forbidden |
| `display_width` | `u32`, 1–16,384; paired with height | forbidden | forbidden | optional | forbidden |
| `display_height` | `u32`, 1–16,384; paired with width | forbidden | forbidden | optional | forbidden |
| `error_code` | safe identifier, 1–64 bytes | forbidden | forbidden | forbidden | required |
| `error_message` | safe template text, max 2,048 bytes | forbidden | forbidden | forbidden | optional |
| `retry_at_ms` | absolute Unix milliseconds | forbidden | forbidden | forbidden | optional |
| `terminal` | boolean | forbidden | forbidden | forbidden | required |
| `last_attempt_at_ms` | absolute Unix milliseconds | required | required | required | required |

Assignments mirror transcript blob assignments: pending/processing preserve
the counter, complete clears failure state and resets the transcode attempt
counter to zero, and failed sets the counter to
`max(current, attempt_number)`. Width and height are either both absent or
both present; when present Fastly stores the canonical `WIDTHxHEIGHT` value.

### Safe errors

`error_message` is produced only by an allowlisted `error_code` → user-safe
template mapping. Raw provider bodies, FFmpeg stderr, signed URLs, filesystem
paths, user-controlled text, and exception chains are never persisted in
events, public metadata, structured logs, Sentry, or dead records. Diagnostic
telemetry records bounded error class, provider status, and timeout flags
instead.

Shared validation:

- body and outbox object at most 32 KiB;
- schema version exactly 1;
- canonical deterministic UUIDv5 event ID and UUIDv7 operation ID;
- SHA-256 exactly 64 lowercase hex characters;
- operation timestamp agrees with the UUIDv7 timestamp within one second;
- created time is not before operation start or more than ten minutes in the
  future;
- sequence is `1..=32`;
- attempt number is `1..=100`;
- status is one of the derivative's declared enum values;
- error code is at most 64 ASCII identifier characters;
- error message is sanitized and at most 2,048 bytes;
- job ID is at most 128 bytes;
- language is at most 35 ASCII characters;
- cue count, duration, dimensions, size, and absolute retry time use bounded
  unsigned integers;
- `last_attempt_at_ms` falls between operation start and event creation;
- `retry_at_ms`, when present, falls between event creation and seven days
  after event creation;
- fields forbidden for a given derivative or status are rejected.

Status timestamps and retry times are absolute event values. Fastly does not
replace them with delivery receipt time. Events contain no transcript text,
media bytes, owner key, signed URL, filesystem path, authorization value, or
other credential.

The delivery task request is:

```json
{"event_id":"canonical UUIDv5"}
```

with `Content-Type: application/json` and a maximum body of 128 bytes.

Unknown schema versions are retained and alerted as deployment skew rather
than automatically dead-lettered.

## Total order

An operation is one processor invocation, including all status transitions it
emits. An explicit retry creates a new operation.

Events are totally ordered by:

1. `operation_started_at_ms`;
2. `operation_id` as a canonical byte sequence;
3. `sequence`.

The UUID tie-breaker handles operations started in the same millisecond. The
trusted producer timestamp, UUID agreement check, future-skew bound, and HMAC
prevent future-dated replay poisoning.

For identical operation ordering fields and sequence:

- the same event ID plus the same canonical event digest is a duplicate;
- a different event ID or different digest is `integrity_conflict`, causes no
  mutation, returns 409, and raises a high-severity alert.

The producer derives one deterministic event ID from operation ID and sequence,
so a correct producer cannot create this conflict. Replaying the same event
preserves its event ID and ordering coordinates. A human corrective action
creates a new recovery operation so it intentionally supersedes prior state.

## Fastly durable-apply protocol

### Exact response contract

The versioned endpoints return 200 only after every required durable effect
has succeeded:

```json
{
  "event_id": "uuid",
  "outcome": "applied|duplicate|stale",
  "blob_effect": "applied|already_applied",
  "job_effect": "not_required|applied|already_applied",
  "mapping_effect": "not_required|applied|already_applied"
}
```

Missing blob metadata returns `409 metadata_not_ready`, not 202. If a transcript
event names a subtitle job that does not yet exist, it returns
`409 job_not_ready`. Both are retryable.

Errors use one bounded response type:

```json
{"error":"metadata_not_ready|job_not_ready|validation_failed|integrity_conflict|conflict_exhausted|internal"}
```

Invalid bodies or signatures return minimal generic errors without parser,
storage, secret, or upstream details. A mixed result aggregates as `applied`
when any required record applied the event, `duplicate` when every required
record already applied it, and `stale` when every required record is stale.
Conflicting mixed ordering is an integrity error rather than success.

### Generation-matched writes

Add separate optional serde-defaulted transcript and transcode watermarks to
`BlobMetadata`, plus a transcript watermark to `SubtitleJob` and the typed
hash-to-job mapping record. Each watermark contains:

- operation ordering fields;
- last sequence;
- last event ID.

Webhook paths bypass the five-minute POP-local metadata cache. They read the KV
value and generation marker, run the pure transition decision, then write with
`if_generation_match`. A precondition failure reloads and retries up to five
times before returning `409 conflict_exhausted`.

Because BlobMetadata and SubtitleJob are full-record KV values, **every**
mutation of an existing record—not only derivative status—moves to a shared
generation-aware read/modify/write helper with bounded conflict retries. This
includes upload completion, moderation, delete/restore, backfill, repair,
manual transcript controls, subtitle dispatch, and admin paths. Unconditional
full-record writes remain available only for create-with-no-existing-record
using add semantics. Compile-visible APIs and an inventory test prevent a
caller from bypassing the helper.

Concurrency tests race delivery against moderation, deletion, upload repair,
backfill, forced subtitle jobs, and subtitle dispatch to prove unrelated fields
and watermarks are preserved.

### Multi-effect retries

Blob and subtitle-job effects have independent watermarks in their respective
records.

For every attempt, Fastly:

1. Applies or confirms the blob effect with CAS.
2. Applies or confirms the subtitle-job effect with CAS when required.
3. When `job_id` is present, applies or confirms a typed hash-to-job mapping
   record with its own transcript watermark and generation-matched write.
4. Issues the required cache purges.
5. Returns the structured 200 response.

A duplicate blob effect does not short-circuit later effects. Therefore a
retry after a partial failure can finish the subtitle job and purges without
incrementing attempt counters or regressing blob state.

The event's explicit `job_id` is authoritative. A stale event cannot repoint
the hash mapping because the mapping applies the same total-order decision.
Forced replacement with a newer operation wins; a late completion for the old
job is stale for the mapping while remaining independently classifiable for
that old job record.

Failure counters are changed inside the CAS transition only when that record's
watermark has not already accepted the event. Completion and failure updates
are absolute assignments derived from the typed event; retrying them is
idempotent.

Legacy status endpoints remain only until the new edge route and worker are
verified. They do not accept the new route-scoped credential. Queue-first
producers are enabled only after the versioned endpoints are active, and the
legacy routes are then disabled before full rollout.

## Cloud Tasks queue

Provision one `derivative-status-delivery` queue in the delivery region:

- minimum backoff: 5 seconds;
- maximum backoff: 15 minutes;
- exponential backoff;
- maximum retry duration: 30 days;
- dispatch deadline: 20 seconds;
- maximum concurrent dispatches: 10;
- maximum dispatch rate: 20 per second;
- queue-level routing and OIDC overrides enforced with mode `ALWAYS`.

The queue overrides scheme, host, path, empty query, POST method,
`Content-Type: application/json`, OIDC service account, and audience.
Task creators supply only the deterministic name and bounded body—no URL,
query, authentication, or caller-selected headers. The delivery service
rejects a non-empty query, unexpected content type, oversized body, duplicate
content-type, or unknown JSON field. Cloud Tasks informational headers are
logged only as bounded delivery metadata and are never treated as identity.

Task names derive from event IDs. Cloud Tasks may retain a deleted task name
for up to 24 hours; `AlreadyExists` means "currently queued or still
tombstoned", not proof of delivery. The GCS pending object remains the source
of truth and the reconciler retries after the tombstone window if necessary.

## Delivery state machine

The worker handles:

| Condition | Task response and outbox action |
| --- | --- |
| Pending missing, dead missing | 204; already delivered/cleaned |
| Dead exists, pending missing | Verify dead event ID/digest, then 204 |
| Matching dead and pending both exist | Delete exact pending generation, then 204 |
| Dead/pending event ID or digest mismatch | 503; mutate neither; integrity alert |
| Pending read or secret read failure | 503; retain and retry |
| Unknown schema version | 503; retain and alert deployment skew |
| Structurally corrupt known-version event | Create dead, delete pending generation, 204 |
| Valid Fastly applied/duplicate/stale response | Delete pending generation, 204 |
| Malformed, oversized, mismatched, or unexpected Fastly 2xx | 503; retain and alert |
| Fastly 401/403 | 503; retain, high-severity credential alert |
| Fastly 409/408/425/429/5xx or network error | 503; retain and retry |
| Other Fastly 4xx | Create dead, delete pending generation, 204 |
| Fastly success followed by cleanup failure | 503; retry safely |

Dead records contain the original sanitized event, classification, upstream
status code when present, first/last attempt timestamps, and no response body
or credential.

Before deletion, the worker parses the bounded Fastly response, verifies the
exact schema, echoed event ID, aggregate outcome, and every required effect.
It retains the pending record on any mismatch. A dead-object create conflict
also requires matching event ID and canonical digest before pending cleanup.

The service reuses one HTTP client. Liveness proves the process is running.
Readiness verifies outbox access, secret-file readability, fixed target
configuration, and service mode without calling Fastly.

## Reconciliation job

Cloud Scheduler requests a Cloud Run Job once per minute. The job first
acquires `control/reconcile-lease.json` with a generation-matched write. The
lease records execution ID and expiry; a live lease makes a duplicate
Scheduler invocation exit successfully without scanning. A crashed execution
can be reclaimed after ten minutes using generation match. Correctness does
not depend on Cloud Run preventing overlapping executions.

The job stores the next GCS page token and cycle start time in
`control/reconcile-cursor.json` using a generation-match update. It advances
the cursor after every scanned page even when records on that page already
have tasks or are temporarily failing. At end-of-list it records cycle
completion and resets the cursor.

An invalid or expired GCS page token is recorded, then the cursor is reset with
generation match and a new full cycle starts. A per-record task-create failure
does not pin the page: the job logs it, advances, and the next full cycle
retries that pending object.

Each execution stops after eight minutes or 5,000 records, whichever comes
first. The next execution resumes from the persisted cursor. Tests cover a
backlog larger than one page, a permanently failing first page, cursor CAS
conflicts, lease contention/expiry, invalid cursor recovery, a crash before
and after cursor advancement, and full-cycle reset.

For every pending object older than two minutes, it creates the deterministic
task. `AlreadyExists` is recorded and scanning continues.

## Incident recovery tool

Provide a checked-in admin CLI using the recovery identity from the IAM table.
It emits canonical JSON with `schema_version`, `recovery_run_id`, creation
time, source evidence, ordered entries, and a SHA-256 manifest digest.

Artifact recovery has `discover`, `plan`, `apply`, and `verify` phases.

`discover`:

- lists `*/vtt/main.vtt` and `*/hls/master.m3u8` in the media bucket;
- emits a local manifest of artifact-backed `complete` candidates;
- accepts an explicit operator-supplied manifest of terminal failures derived
  from structured logs/Sentry evidence;
- does not mutate cloud state.

`plan`:

- validates every hash and current Fastly metadata response;
- excludes absent, deleted, or otherwise ineligible blob metadata;
- shows counts by derivative and desired status;
- creates one UUIDv7 recovery operation and deterministic UUIDv5 event IDs;
- writes a plan containing the source-manifest digest.

`apply`:

- requires the reviewed manifest and an explicit confirmation flag;
- refuses a plan whose source digest or canonical bytes changed after review;
- creates new recovery operations using the normal typed outbox publisher;
- never calls the processor or retranscodes media;
- is idempotent when rerun with the same manifest.

`verify` reports artifact count, planned count, applied count, remaining
stale count, and terminal retry suppression. The current incident's known
invalid-media hash is supplied through the reviewed manifest, not hardcoded.

Dead-letter operations are separate:

- `dead list` shows bounded IDs, classifications, ages, and derivatives;
- `dead inspect <event_id>` validates and prints a redacted canonical record;
- `dead plan-replay <event_id>` requires an operator-supplied correction and
  creates a new recovery operation rather than changing the immutable event;
- `dead apply-replay <reviewed-plan> --confirm` binds to the plan digest,
  publishes the corrective event, and leaves the original dead record for its
  30-day audit retention;
- `dead verify-replay` confirms the corrective event reached Fastly.

CLI output is machine-readable JSON by default. Mutation commands require the
dedicated recovery identity, explicit project/bucket inputs, a reviewed plan
digest, and `--confirm`; discovery and planning never mutate cloud state.

## Deployment order

1. Add native CAS helpers, optional watermarks, versioned Fastly endpoints,
   HMAC verification, and tests.
2. Publish Fastly with `fastly compute publish`, purge the service, and verify
   legacy behavior plus the new routes.
3. Provision the private outbox bucket, queue with enforced overrides,
   identities/IAM, private worker, reconciliation job, metrics, and alerts.
4. Deploy the delivery worker and test unauthenticated rejection, task OIDC,
   HMAC overlap, retry, dead-letter, CAS conflict, and secret rotation.
5. Add processor HMAC verification in dual-accept mode. Inventory and update
   every caller before rejection becomes mandatory: Fastly on-demand
   transcript/transcode paths, `cloud-run-upload`, `backfill.sh`,
   `backfill-prioritized.sh`, incident recovery tooling, and any documented
   operator command. Verify each caller, then reject unsigned requests.
6. Deploy queue-first producer support disabled and run controlled synthetic
   transcript/transcode canaries through the complete production queue and
   Fastly path for 24 hours.
7. Enable queue-first publication atomically for all real transcript and
   transcode status events if canary criteria pass.
8. Disable legacy status endpoints and observe for seven days.
9. Run incident recovery in dry-run, review its manifest, apply it, and verify
   convergence.
10. Remove old shared status-sender code after fourteen stable days.

Rollback never disables immutable outbox persistence while processors accept
work. Depending on the faulty layer it either:

- pauses processor admissions and lets in-flight operations persist their
  final events; or
- keeps processor publication active while pausing only queue dispatch.

Pending/dead objects are never deleted by rollback. If the new Fastly route is
the fault, pause queue dispatch, keep outbox publication active, roll back
Fastly atomically, correct the route, and resume. Never switch queued
producers to unordered direct delivery.

## Observability and alerts

Cloud Monitoring and Cloud Tasks built-in metrics are authoritative. Use
structured logs to create the missing outbox/dead-letter metrics.

Low-cardinality metric labels:

- service;
- derivative;
- status/outcome;
- failure class.

Hashes, event IDs, operation IDs, and job IDs appear only in access-controlled
structured logs, not metric labels.

Measure:

- enqueue success/failure and latency;
- delivery outcome, attempt count, and latency;
- Fastly response class;
- queue depth and oldest task age;
- pending age and count;
- dead count;
- reconciliation scan/recreate/failure/cycle duration;
- CAS conflict and exhaustion counts;
- artifact-to-terminal-metadata convergence latency;
- duplicate processor suppression.

The rollout baseline is the previous seven complete days at the same
five-minute interval. For a new queue with no history, baseline means zero
pending events older than two minutes and queue depth returning to zero between
normal bursts. "Dependencies healthy" means worker readiness passes, the
non-mutating Fastly verify route succeeds, GCS/Cloud Tasks API error rate is
below 1%, and no platform incident is declared.

Alert policies:

- pending or oldest-task age reaches four minutes, evaluated every minute;
- any sustained 401/403 for two minutes;
- any dead event;
- enqueue or reconciliation failures;
- queue depth grows for fifteen minutes;
- CAS retries exhaust;
- unsigned processor-route attempts exceed 10 per minute for five minutes;
- processor request rate or cost exceeds 2× the same-interval seven-day
  baseline for fifteen minutes.

Sentry fingerprints include service, derivative, and failure class so provider,
FFmpeg, delivery, and user-invalid-media events cannot collapse into one
group.

## User-facing success and rollout gates

Normal operation:

- p95 artifact-to-terminal-metadata convergence is below 30 seconds;
- at least 99.9% converges within five minutes;
- permanent untracked event loss is zero;
- a duplicate event changes no counter or terminal state;
- a delivered terminal invalid-media result suppresses repeated processing.

Canary passes after 24 hours only if:

- no lost or dead events;
- no unauthorized delivery acceptance;
- no metadata regression;
- no duplicate failure increment;
- p95 and five-minute objectives are met;
- queue and pending depth return to baseline.

Full rollout remains under observation for seven days. Legacy sender code is
removed only after fourteen stable days.

Pause rollout or roll back the faulty layer if:

- any accepted event becomes untracked;
- more than 0.1% of artifact-backed derivatives remain stale after five
  minutes while dependencies are healthy;
- any queued event regresses terminal metadata;
- any duplicate increments an attempt counter;
- a dead event occurs;
- credential failures persist for five minutes;
- oldest pending age exceeds fifteen minutes while Fastly is healthy.

During a prolonged dependency outage, artifacts may be directly retrievable
while metadata remains pending. The pending event remains durable, the
operator is alerted, and recovery occurs automatically after service returns.

## Coverage gate

The scaffolded root coverage command does not include
`cloud-run-transcoder`, which is excluded from the root workspace. Before the
first implementation commit, replace it with a checked-in
`scripts/check-derivative-status-coverage.sh` and point
`.coverage-thresholds.json` plus CI at that script.

Put all new domain behavior in a native `derivative-status-core` crate shared
by Fastly and Cloud Run. Put publisher, worker, reconciler, router, and adapter
orchestration in a `cloud-run-transcoder/status-delivery` library crate; its
delivery and reconciliation binaries are thin entry points. The existing
processor calls the covered publisher API.

The script runs:

```bash
cargo llvm-cov \
  --manifest-path derivative-status-core/Cargo.toml \
  --all-targets --all-features \
  --fail-under-lines 100 --fail-under-functions 100 --fail-under-regions 100

cargo llvm-cov \
  --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml \
  --all-targets --all-features \
  --fail-under-lines 100 --fail-under-functions 100 --fail-under-regions 100
```

The first command covers event validation, ordering, transition, response, and
CAS-retry decisions. The second covers every publisher, delivery, outbox,
queue, reconciliation, HTTP, and binary branch through injected adapters.
Thin Fastly and processor wiring is additionally exercised by their existing
crate tests and deployment contract tests. CI installs the pinned
`cargo-llvm-cov` version and treats either command or any integration test
failure as blocking.

## Testing strategy

Every implementation slice begins with a failing native test.

### Pure domain tests

- typed transcript/transcode serialization and field allowlists;
- size, UUID, hash, timestamp, sequence, attempt, and error bounds;
- total-order same-millisecond UUID tie-break;
- retry/dead/unknown-version classification;
- transition decisions for applied, duplicate, stale, and newer operation.

### Fastly metadata tests

Introduce an injected KV adapter exposing value plus generation and
generation-matched writes.

- uncached webhook lookup;
- CAS success and conflict reload;
- conflict exhaustion;
- duplicate failure does not increment;
- partial blob success followed by job failure completes on retry;
- missing blob/job returns retryable 409;
- cache purge is retried after durable effects;
- transcript and transcode use independent blob watermarks;
- forced hash-to-job replacement rejects a late old-job event;
- moderation/delete/upload/backfill/subtitle-dispatch races preserve all
  unrelated fields and delivery watermarks;
- every existing full-record writer uses the generation-aware path.

### Processor and publisher tests

- unsigned, stale, malformed, and wrong-secret processor requests are rejected
  before work;
- captured signatures cannot replay across method/path/body/request ID;
- replay markers reject repeated expensive work and expire after 24 hours;
- pre-authentication body limits reject oversized requests;
- current and overlap secrets are accepted;
- pending persistence precedes task creation;
- pending create conflict requires byte equality;
- task-create failure leaves a recoverable pending event;
- existing artifact makes a retried processor request publish completion
  without recomputation;
- duplicate transcode request is suppressed by its GCS lock.

### Delivery service tests

Use injected in-memory outbox/secret providers and a local HTTP server.

- all state-machine rows above;
- redirects are rejected;
- response and timeout bounds;
- mismatched or malformed successful responses retain pending;
- HMAC current/secondary rotation;
- success plus cleanup failure retries safely;
- dead create-before-delete generation ordering;
- both-present dead/pending cleanup and mismatch protection;
- missing pending is acknowledged;
- unknown schema remains pending.

### Reconciler and recovery tests

- multi-page backlog cannot starve later pages;
- durable cursor recovery at every crash boundary;
- overlapping execution prevention;
- task-name tombstone and `AlreadyExists` behavior;
- dry-run recovery never mutates;
- same manifest applies idempotently;
- recovery excludes ineligible metadata and never invokes processors.

### Deployment smoke tests

- private worker rejects unauthenticated invocation;
- queue-level host/path/method/OIDC overrides cannot be bypassed by task input;
- runtime identities cannot invoke or read outside their matrix;
- delivery HMAC cannot authenticate any admin route;
- processor HMAC cannot authenticate a status or admin route;
- a deliberate Fastly 403 stays pending and drains after credential repair;
- secret rotation succeeds without a worker revision;
- one transcript and one transcode reach terminal metadata end to end.

## Runbook

Create `docs/runbooks/derivative-status-delivery.md` containing exact,
non-secret commands and expected output for:

- health/readiness;
- queue depth and pending age;
- identifying credential failures safely;
- pausing/resuming dispatch and consequences;
- dual-secret rotation;
- pending and dead inspection;
- dead revalidation and replay as a new corrective operation;
- reconciliation cursor inspection/reset with safety checks;
- incident recovery dry-run/apply/verification;
- transcript and transcode end-to-end validation;
- rollback and backlog drain.

## Design-review sources

- Fastly KV generation markers support conditional writes and prevent lost
  updates: <https://www.fastly.com/documentation/reference/api/services/resources/kv-store-item/>
- The Fastly Rust insert builder exposes `if_generation_match`:
  <https://docs.rs/fastly/latest/src/fastly/kv_store.rs.html>
- Cloud Tasks treats non-2xx handler responses as failed attempts:
  <https://docs.cloud.google.com/tasks/docs/reference/rest/v2/projects.locations.queues.tasks>
- Queue-level `ALWAYS` routing and OIDC overrides apply to all tasks:
  <https://docs.cloud.google.com/tasks/docs/configuring-queues>
- Cloud Run mounted secret volumes read the latest secret version:
  <https://docs.cloud.google.com/run/docs/configuring/services/secrets>

## Success criteria

- A five-minute Fastly or credential outage loses zero events.
- Repair drains the backlog without retranscoding.
- Duplicate, concurrent, partial, and out-of-order delivery cannot regress
  metadata or multiply counters.
- Credential compromise is scoped to derivative status, not administration.
- Secret rotation requires no worker deployment.
- Task-creation failure is recovered by the outbox reconciler.
- Operators receive a backlog signal within five minutes.
- Incident-window artifacts and reviewed terminal failures converge through
  the same normal event path.
