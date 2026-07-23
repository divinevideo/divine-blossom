# Durable Derivative Status Delivery Design

**Date:** 2026-07-24
**Issue:** divine-funnelcake#686
**Status:** Design review, revision 2

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
HMAC. The processor checks the signature in constant time, enforces a
five-minute timestamp window, and rejects unsigned requests before parsing the
body or allocating expensive work. CORS is limited to the required production
origin and does not substitute for authentication.

Existing per-hash transcript locking remains. Transcode receives the same
idempotent in-progress lock to suppress trusted duplicate work.

### Fastly status routes

Add dedicated routes:

- `POST /internal/derivative-status/v1/transcript`
- `POST /internal/derivative-status/v1/transcode`

They accept only a new `derivative_status_secret` HMAC. This credential is not
accepted by admin, moderation, delete, restore, dashboard, or legacy webhook
routes. The current `webhook_secret` is never mounted in the delivery service.

The delivery worker signs:

```text
v1
<unix timestamp seconds>
<raw request body bytes>
```

It sends the timestamp and lowercase hex HMAC-SHA256 signature in dedicated
headers. Fastly verifies the signature in constant time and allows at most five
minutes of clock skew.

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
3. Deliver a signed smoke event and confirm the new credential is accepted.
4. Promote the new Fastly value to primary.
5. Remove the old secondary value within one hour.
6. Alert on any use of the retiring credential after promotion.

The processor HMAC credential uses the same overlap procedure but remains a
separate secret.

## IAM and identity matrix

All service accounts are keyless.

| Identity | Allowed operations |
| --- | --- |
| Processor runtime | Create pending outbox objects; create tasks in the one status queue |
| Delivery runtime | Read/delete pending objects; create dead objects; access only `derivative_status_secret` |
| Reconciler runtime | List/read pending objects; create tasks; read/write reconciliation cursor |
| Cloud Tasks OIDC identity | Invoke only `divine-status-delivery` |
| Scheduler identity | Execute only `divine-status-reconciler` |
| Cloud Tasks service agent | Mint tokens for the task OIDC identity as required by Google |
| Deployment identity | Manage declared resources and `actAs` only the identities needed during deployment |

The queue uses queue-level `ALWAYS` overrides for HTTPS scheme, delivery host,
delivery path, POST method, OIDC service account, and audience. Producers
cannot choose a target or authentication identity. Only the deployment
identity needs `iam.serviceAccounts.actAs` while configuring that override;
task creators receive no impersonation role.

## Private outbox

Use a dedicated private bucket with public-access prevention and uniform
bucket-level access. It contains no media:

- `pending/<event_id>.json`
- `dead/<event_id>.json`
- `control/reconcile-cursor.json`

Pending objects have no expiration lifecycle. Dead objects expire after 30
days. Access is granted according to the IAM matrix rather than by relying on a
textual prefix in the media bucket.

Pending creation uses `ifGenerationMatch=0`. If the same event already exists,
the producer verifies that its bytes match; a mismatch is an integrity error.

Successful cleanup deletes the exact generation read by the worker. Dead
movement creates the dead object with `ifGenerationMatch=0` before deleting
the matching pending generation. A crash at any boundary leaves at least one
recoverable copy.

## Event contract

Fastly receives the full event envelope. Cloud Tasks receives only the event
ID.

```json
{
  "schema_version": 1,
  "event_id": "018f6e33-c5af-7d82-a7b2-30f02e8f7e10",
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
    "confidence": "high",
    "last_attempt_at_ms": 1784847001200
  }
}
```

The Rust type is a tagged enum:

- `DerivativeUpdate::Transcript(TranscriptUpdate)`
- `DerivativeUpdate::Transcode(TranscodeUpdate)`

Shared validation:

- body and outbox object at most 32 KiB;
- schema version exactly 1;
- canonical UUIDv7 event and operation IDs;
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
- fields forbidden for a given derivative or status are rejected.

Status timestamps and retry times are absolute event values. Fastly does not
replace them with delivery receipt time. Events contain no transcript text,
media bytes, owner key, signed URL, filesystem path, authorization value, or
other credential.

The delivery task request is:

```json
{"event_id":"canonical UUIDv7"}
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

Replaying the same event preserves its event ID and ordering coordinates. A
human corrective action creates a new recovery operation so it intentionally
supersedes prior state.

## Fastly durable-apply protocol

### Exact response contract

The versioned endpoints return 200 only after every required durable effect
has succeeded:

```json
{
  "event_id": "uuid",
  "outcome": "applied|duplicate|stale",
  "blob_effect": "applied|already_applied",
  "job_effect": "not_required|applied|already_applied"
}
```

Missing blob metadata returns `409 metadata_not_ready`, not 202. If a transcript
event names a subtitle job that does not yet exist, it returns
`409 job_not_ready`. Both are retryable.

Invalid bodies or signatures return minimal generic errors without parser,
storage, secret, or upstream details.

### Generation-matched writes

Add an optional serde-defaulted delivery watermark to both `BlobMetadata` and
`SubtitleJob`:

- operation ordering fields;
- last sequence;
- last event ID.

Webhook paths bypass the five-minute POP-local metadata cache. They read the KV
value and generation marker, run the pure transition decision, then write with
`if_generation_match`. A precondition failure reloads and retries up to five
times before returning a retryable conflict.

Every existing writer of transcript or transcode status is routed through the
same generation-aware helper or explicitly creates a newer operation. No
status writer may perform an unconditional full-record overwrite.

### Multi-effect retries

Blob and subtitle-job effects have independent watermarks in their respective
records.

For every attempt, Fastly:

1. Applies or confirms the blob effect with CAS.
2. Applies or confirms the subtitle-job effect with CAS when required.
3. Refreshes the hash-to-job mapping idempotently.
4. Issues the required cache purges.
5. Returns the structured 200 response.

A duplicate blob effect does not short-circuit later effects. Therefore a
retry after a partial failure can finish the subtitle job and purges without
incrementing attempt counters or regressing blob state.

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

Task names derive from event IDs. Cloud Tasks may retain a deleted task name
for up to 24 hours; `AlreadyExists` means "currently queued or still
tombstoned", not proof of delivery. The GCS pending object remains the source
of truth and the reconciler retries after the tombstone window if necessary.

## Delivery state machine

The worker handles:

| Condition | Task response and outbox action |
| --- | --- |
| Pending missing, dead missing | 204; already delivered/cleaned |
| Dead exists | 204; already classified |
| Pending read or secret read failure | 503; retain and retry |
| Unknown schema version | 503; retain and alert deployment skew |
| Structurally corrupt known-version event | Create dead, delete pending generation, 204 |
| Fastly applied/duplicate/stale response | Delete pending generation, 204 |
| Fastly 401/403 | 503; retain, high-severity credential alert |
| Fastly 409/408/425/429/5xx or network error | 503; retain and retry |
| Other Fastly 4xx | Create dead, delete pending generation, 204 |
| Fastly success followed by cleanup failure | 503; retry safely |

Dead records contain the original sanitized event, classification, upstream
status code when present, first/last attempt timestamps, and no response body
or credential.

The service reuses one HTTP client. Liveness proves the process is running.
Readiness verifies outbox access, secret-file readability, fixed target
configuration, and service mode without calling Fastly.

## Reconciliation job

Cloud Scheduler starts a Cloud Run Job once per minute. Cloud Run permits only
one concurrent execution.

The job stores the next GCS page token and cycle start time in
`control/reconcile-cursor.json` using a generation-match update. It advances
the cursor after every scanned page even when records on that page already
have tasks or are temporarily failing. At end-of-list it records cycle
completion and resets the cursor.

Each execution stops after eight minutes or 5,000 records, whichever comes
first. The next execution resumes from the persisted cursor. Tests cover a
backlog larger than one page, a permanently failing first page, cursor CAS
conflicts, a crash before and after cursor advancement, and full-cycle reset.

For every pending object older than two minutes, it creates the deterministic
task. `AlreadyExists` is recorded and scanning continues.

## Incident recovery tool

Provide a checked-in admin CLI with `discover`, `plan`, and `apply` phases.

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
- creates deterministic event IDs within one recovery run.

`apply`:

- requires the reviewed manifest and an explicit confirmation flag;
- creates new recovery operations using the normal typed outbox publisher;
- never calls the processor or retranscodes media;
- is idempotent when rerun with the same manifest.

Verification reports artifact count, planned count, applied count, remaining
stale count, and terminal retry suppression. The current incident's known
invalid-media hash is supplied through the reviewed manifest, not hardcoded.

## Deployment order

1. Add native CAS helpers, optional watermarks, versioned Fastly endpoints,
   HMAC verification, and tests.
2. Publish Fastly with `fastly compute publish`, purge the service, and verify
   legacy behavior plus the new routes.
3. Provision the private outbox bucket, queue with enforced overrides,
   identities/IAM, private worker, reconciliation job, metrics, and alerts.
4. Deploy the delivery worker and test unauthenticated rejection, task OIDC,
   HMAC overlap, retry, dead-letter, CAS conflict, and secret rotation.
5. Add processor HMAC verification and update both trusted callers before
   rejecting unsigned requests.
6. Deploy queue-first producer support disabled, then enable it for a 10%
   deterministic hash canary for 24 hours.
7. Enable all transcript and transcode status events if canary criteria pass.
8. Disable legacy status endpoints and observe for seven days.
9. Run incident recovery in dry-run, review its manifest, apply it, and verify
   convergence.
10. Remove old shared status-sender code after fourteen stable days.

Rollback pauses producer publication but does not delete pending/dead objects.
The worker and reconciler continue until pending is empty. If the new Fastly
route is the fault, pause queue dispatch, roll back Fastly atomically, correct
the route, and resume; never switch queued producers to unordered direct
delivery.

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

Alert policies:

- pending or oldest-task age reaches four minutes, evaluated every minute;
- any sustained 401/403 for two minutes;
- any dead event;
- enqueue or reconciliation failures;
- queue depth grows for fifteen minutes;
- CAS retries exhaust;
- unsigned processor-route attempts exceed a conservative threshold;
- processor cost or request rate deviates materially from baseline.

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
- every existing derivative-status writer uses the generation-aware path.

### Processor and publisher tests

- unsigned, stale, malformed, and wrong-secret processor requests are rejected
  before work;
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
- HMAC current/secondary rotation;
- success plus cleanup failure retries safely;
- dead create-before-delete generation ordering;
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
