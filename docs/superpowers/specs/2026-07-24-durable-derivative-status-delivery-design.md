# Durable Derivative Status Delivery Design

**Date:** 2026-07-24
**Issue:** divine-funnelcake#686
**Status:** Approved

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

After authentication, the processor creates `<request_id>` in the private
processor-replay bucket with `ifGenerationMatch=0` and a 24-hour lifecycle.
The marker contains the method, path, body digest, and operation ID but no
request body or credential. A
pre-existing marker returns `409 replay_detected` without starting work.
Trusted callers regenerate the timestamp, request ID, and signature for an
intentional retry; they never retry a 409 with the same signed request.
Because the signed digest binds the body, a captured request ID cannot
authorize a different payload or route. The replay marker is created before
expensive work or outbox publication.

The processor checks the signature in constant time and rejects unsigned
requests before parsing the body or allocating expensive work. CORS is limited
to the required production origin and does not substitute for authentication.

The processor also exposes
`POST /internal/processor-auth/v1/verify`. It applies the same route-bound HMAC
protocol and dual-secret verifier but performs no replay-marker, outbox,
attempt, lock, artifact, or compute mutation. The raw body is at most 256 bytes
and has exactly `{"nonce":"<16-64 lowercase base64url characters>"}`. A valid
request returns exactly:

```json
{
  "authenticated": true,
  "auth_version": "v1",
  "request_id": "<echoed canonical UUIDv7>"
}
```

Invalid auth remains a minimal 401/403. The route rejects unknown fields and
is rate-limited per caller. Rotation succeeds only when each signer sends a
fresh nonce/request ID and receives the exact 200 schema through its real
production call path; it never uses a compute route as a probe.

Existing per-hash transcript locking remains. Transcode receives the same
idempotent in-progress lock to suppress trusted duplicate work.

Before acquiring a compute lock, the processor reads the derivative/hash
record in the immutable terminal-suppression bucket. If that record exists,
the request repairs pending/task state if needed and returns the stable bounded
terminal result without starting compute or publishing a newer processing
event. If not suppressed, it acquires the per-hash lock, re-reads suppression
to close the preflight race, then creates the operation ID and allocates its
ordinal in Firestore before work. Suppression is set
when a durable terminal-failure event is published with an allowlisted
permanent-input classification:

- `invalid_media`;
- `unsupported_media`;
- `no_audio_track`;
- `corrupt_media`.

Provider unavailability, authentication/configuration failures, timeouts, and
retry exhaustion are never permanent-input classifications. The enum and its
safe client messages are checked in and exhaustively tested.

Only the dedicated operator identity can clear suppression, through a
dry-run/confirm command that records reason, actor, prior terminal event ID,
and reviewed plan digest, then starts a new attempt epoch. Normal signed
processor callers cannot set an override flag. Clearing suppression does not
delete the prior event or audit record.

### Admission pause and drain

Every processor image supports two startup modes. `normal` serves the signed
compute routes. `maintenance` serves health/readiness and both non-mutating
verification routes, but every compute-capable route returns:

```json
{"error":"processor_admissions_paused","retryable":true}
```

with HTTP 503 and `Retry-After: 30`. The maintenance router never initializes
GPU/FFmpeg work or status publishers. Deployment keeps a tested named
maintenance revision at zero traffic. Pausing is a Cloud Run traffic change to
100% maintenance, followed by a describe check that fails the runbook if any
traffic remains on a normal revision. Resuming is a traffic change to 100% of
the explicitly named, verified normal revision; it never uses `latest`.

The deployed Cloud Run request timeout is the maximum operation timeout:
900 seconds, matching `cloud-run-transcoder/deploy.sh`. After pause, the drain
gate waits 1,800 seconds and also requires all of the following continuously
for two minutes:

- the per-revision `active_derivative_operations` gauge is zero;
- no transcript/transcode processing or terminal log originates from the old
  revision;
- no in-progress per-hash lock has an unexpired 900-second lease;
- Cloud Run reports zero active requests on the old revision.

Any nonzero or unavailable signal keeps admissions paused and pages the
processor owner; it never guesses that drain completed. The runbook records
the old/new revision names, pause time, signal evidence, traffic describe
output, and resume verification.

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

### Canonical signature bytes

Both HMAC protocols use UTF-8/ASCII fields joined by one byte `0x0a` (LF),
with no leading or trailing LF. Decimal timestamps contain ASCII digits only,
have no sign or leading zero, and UUIDs are lowercase canonical hyphenated
text. The body digest is lowercase hex over the exact received body bytes;
JSON is never reparsed or reserialized before verification. Paths are the
literal allowlisted ASCII route constants above. Percent-encoding, duplicate
slashes, a trailing slash, dot segments, or a query string are rejected rather
than normalized into a signed route.

Check in byte-level fixtures containing protocol name, hex key, raw body hex,
preimage hex, and expected signature hex. The same fixtures run unchanged in
Fastly, processor, upload, operator CLI, and delivery tests. Fixtures include
an empty body, a body ending in LF, non-ASCII JSON bytes, a leading-zero
timestamp rejection, uppercase UUID rejection, and each exact route, so
language/library differences cannot silently fork the protocol.

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

The processor verifier mounts
`processor_request_secret_primary` and, during rotation only,
`processor_request_secret_secondary`. The GCP processor runtime identity can
access those two secrets and no other application secret. The same logical
credential is copied into distinct signer stores:

- Fastly Secret Store for Fastly processor callers;
- Secret Manager access for the `cloud-run-upload` runtime identity;
- Secret Manager access for a dedicated, impersonated
  `derivative-processor-operator` identity used by approved backfill and
  operator commands.

No human user receives a long-lived service-account key or prints a secret.
Operator commands obtain short-lived identity credentials, read the one
processor signing secret in memory, and redact auth headers from output.
Neither upload nor operator identities can access `derivative_status_secret`
or the legacy `webhook_secret`.

Processor-secret rotation is verifier-first:

1. Put the new value in the processor verifier's secondary slot and deploy or
   refresh the verifier mount.
2. Update the Fastly, upload-runtime, and operator signer stores one at a time.
3. Prove each caller with a signed, non-compute verification request and
   confirm that old and new signatures are accepted during the overlap.
4. Promote the new value to verifier primary.
5. Remove the old value from every signer store.
6. Remove verifier secondary within one hour and alert on use of the retired
   credential.

The delivery and processor rotations are separate procedures and credentials.

## IAM and identity matrix

All service accounts are keyless.

| Identity | Allowed operations |
| --- | --- |
| Processor runtime | Create/read pending objects; create replay markers; create/read immutable suppression objects; transactionally get/create/update Firestore attempt records; create tasks in the one status queue; access only processor verifier primary/secondary secrets; no list/delete |
| Upload runtime | Access only the active `processor_request_secret` signer value; no status-delivery secret or outbox access |
| Fastly processor caller | Read only the Fastly Secret Store entry for the active processor signer; no status-delivery or admin credential |
| Operator/backfill signer | Impersonated dedicated identity; access only the active `processor_request_secret`; no status-delivery secret or outbox access |
| Delivery runtime | Read/delete pending objects; create/read dead objects; access only `derivative_status_secret`; no list/task-create/dead-delete |
| Reconciler runtime | List/read pending objects; create tasks; read/create/update/delete reconciliation cursor and lease objects |
| Cloud Tasks OIDC identity | Invoke only `divine-status-delivery` |
| Scheduler identity | Execute only `divine-status-reconciler` |
| Cloud Tasks service agent | Mint tokens for the task OIDC identity as required by Google |
| Recovery CLI identity | List media-bucket object metadata without `storage.objects.get`; read Fastly derivative status; list/read/create pending records; list/read dead records; create/read immutable suppression objects; transactionally get/create/update Firestore attempt records; create tasks; no media-body read and no delete |
| Suppression operator identity | Read/delete exact suppression objects and get/update Firestore attempt records only through the reviewed clear command; no create/list or pending/dead/media access |
| Deployment identity | Manage declared resources and `actAs` only the identities needed during deployment |

The queue uses queue-level `ALWAYS` overrides for HTTPS scheme, delivery host,
delivery path, POST method, OIDC service account, and audience. Producers
cannot choose a target or authentication identity. Only the deployment
identity needs `iam.serviceAccounts.actAs` while configuring that override;
task creators receive no impersonation role.

These permissions are implemented as resource-scoped custom roles where
predefined roles are broader than the table. Deployment contract tests inspect
the effective policy and prove each allowed and denied operation, including
Cloud Run invocation, job execution, queue task creation, Secret Manager
access, service-agent token minting, and every object operation.

Object namespaces are isolated with separate buckets rather than relying on
prefix-scoped prose or conditional delete permissions:

- pending-event bucket: producer create/read, delivery read/delete,
  reconciler list/read, recovery list/read/create;
- dead-event bucket: delivery create/read, recovery list/read; only the
  lifecycle service deletes;
- processor-replay bucket: processor create only;
- terminal-suppression bucket: processor/recovery create/read; suppression
  operator read/delete; no runtime list/update;
- reconciliation-control bucket: reconciler read/create/update/delete only.

`storage.objects.list` is bucket-wide. It is granted only on the pending bucket
to reconciler/recovery, on the dead bucket to recovery, and on the media bucket
to recovery for artifact discovery. Media listing exposes object metadata but
the recovery identity is explicitly denied `storage.objects.get`, so it cannot
read media bodies. No runtime has list access to the replay, suppression, or
control bucket. Bucket access is reviewed quarterly. Structured operational
logs are retained for 30 days; Sentry uses the project's restricted
operational retention policy and stores only the sanitized fields defined
here.

Attempt state uses a dedicated Firestore database with database-scoped custom
IAM permissions for entity get/create/update and transactions. Runtime roles
omit entity list and delete. Deployment tests prove an identity that can
allocate or update an attempt cannot delete a document, enumerate the
database, or access any other Firestore database.

## Private outbox

Use five dedicated private buckets with public-access prevention and uniform
bucket-level access. They contain no media:

- pending-event bucket: `<event_id>.json`;
- dead-event bucket: `<event_id>.json`;
- processor-replay bucket: `<request_id>`;
- terminal-suppression bucket: `<derivative>/<sha256>.json`;
- reconciliation-control bucket: `cursor.json` and `lease.json`.

Pending objects have no expiration lifecycle. Dead objects expire after 30
days, and processor request markers expire after 24 hours. Unknown-schema and
credential-failure pending objects remain until code/configuration is repaired
or an operator explicitly classifies them.

Pending creation uses `ifGenerationMatch=0`. If the same event already exists,
the producer uses its narrow read permission to verify that its canonical
bytes match; a mismatch is an integrity error that fails publication and
alerts.

Successful cleanup deletes the exact generation read by the worker. Dead
movement creates the dead object with `ifGenerationMatch=0` before deleting
the matching pending generation. A crash at any boundary leaves at least one
recoverable copy.

## Attempt allocation and terminal suppression

One Firestore attempt-state document exists per derivative/hash at
`derivative_attempts/<derivative>:<sha256>`:

```json
{
  "schema_version": 1,
  "attempt_epoch": "uuid",
  "next_attempt_number": 4,
  "allocations": {
    "<operation_id>": 1,
    "<operation_id>": 2,
    "<operation_id>": 3
  }
}
```

The processor creates its UUIDv7 operation ID, then uses one Firestore
transaction on this document to allocate the next ordinal. Retrying allocation
for the same operation ID returns the stored ordinal; a new operation receives
and stores the next value. The map is bounded by the maximum 100 attempts per
epoch, so the document is bounded and requires no cross-record transaction. An
ordinal is an admitted processing attempt: a process crash after allocation
still counts as an attempt when a later failure reports a higher ordinal.

Every event in the operation carries the allocated `attempt_epoch` and
`attempt_number`. Fastly assigns failure counters with
`max(current, attempt_number)` for the matching epoch. Consequently failure 2
delivered before failure 1 still records two admitted attempts, while
redelivery changes nothing. A stale failure from the same epoch may advance
the counter to its ordinal only when the current derivative state is not a
newer `complete` or terminal failure. It never changes status fields. A stale
event from an older epoch changes nothing.

`complete` resets the public failure counter to zero but retains its epoch
watermark and terminal status, so late failures from that epoch are ignored.
Completed artifacts use the existing-artifact fast path rather than
recomputation; permanent-input failures use terminal suppression. The
operator-only clear command first transactionally replaces the attempt record
fields with a new UUID epoch, `next_attempt_number=1`, and an empty allocation
map. It then deletes the exact suppression-object generation named by the
reviewed plan.

The first event in that new epoch is ordered after the reviewed override;
Fastly resets its epoch-local counter before applying the new operation.

Terminal publication first creates, with `ifGenerationMatch=0`, an immutable
suppression object containing the bounded canonical failure event, digest,
safe client result, and operation ordering fields. If it already exists, only
byte-identical content is accepted. The publisher then creates the immutable
pending event from those exact bytes and creates the task. A crash after
suppression but before pending creation is safe: the next processor preflight
sees suppression, recreates or verifies the deterministic pending event and
task, then returns the stable terminal result without compute. If suppression
storage is unavailable, preflight and terminal publication fail closed with
503.

The processor and recovery identities cannot update or delete suppression
objects. The operator clear order is epoch-rotation first, exact-generation
suppression delete second. A crash before delete remains safely suppressed and
the reviewed command can resume; after delete the new epoch is already
durable. Thus a Fastly/task outage or partial override cannot reopen the
corrupt-input compute loop.

Allocation number 100 blocks further normal operations with
`409 attempt_epoch_exhausted` and pages the processor owner before any compute.
The operator inspects the failure history and either leaves terminal
suppression in place or uses the same reviewed epoch-rotation command. Epoch
rotation is never automatic.

## Producer publication state machine

Every non-suppressed status transition uses the same steps:

1. Construct and fully validate the canonical typed event.
2. Create the immutable pending object.
3. Create its deterministic Cloud Task with bounded client retries.
4. Return publication success once the pending object is durable, even if task
   creation failed; the reconciler owns the producer-to-queue gap.

A permanent-input terminal failure uses the suppression-first protocol above:
persist the canonical event in attempt state, then run steps 2–4 from those
stored bytes. Preflight repair runs the same steps without compute.

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
| Terminal suppression exists but pending/task is missing | Recreate/verify it from stored canonical bytes; return stable terminal result without compute |

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
  "attempt_epoch": "018f6e33-c5af-7d22-a7b2-30f02e8f7e11",
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
  attempt epoch/counter to the event epoch and
  `max(current_for_epoch, attempt_number)`.

When `job_id` is present, the subtitle-job effect is required. Complete assigns
`Ready`, the stable VTT URL, and supplied language/duration/cue values, clears
error/retry fields, and preserves the job's attempt count. Failed assigns
`Failed`, safe error/retry fields, and sets the job attempt epoch/counter to
the event epoch and `max(current_for_epoch, attempt_number)`. Pending and
processing assign only their corresponding job status and update timestamp.

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
counter to zero, and failed assigns the matching-epoch maximum attempt number.
Width and height are either both absent or both present; when present Fastly
stores the canonical `WIDTHxHEIGHT` value.

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
- attempt epoch is a canonical UUID and attempt number is `1..=100`;
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

The attempt epoch/number must match the allocation stored for the event's
operation ID. The processor and recovery publisher reject a mismatch before
pending persistence. Fastly enforces ordered epoch transitions and trusts only
the route-authenticated typed publisher contract; it does not read GCS attempt
state. Existing-artifact completion carries its allocated ordinal but resets
the relevant public failure counter and never increments it.

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
  "blob_effect": "applied|already_applied|stale",
  "job_effect": "not_required|applied|already_applied|stale",
  "mapping_effect": "not_required|applied|already_applied|stale"
}
```

Missing blob metadata returns `409 metadata_not_ready`, not 202. If a transcript
event names a subtitle job that does not yet exist, it returns
`409 job_not_ready`. Both are retryable.

Errors use one bounded response type:

```json
{
  "event_id": "uuid when the bounded envelope supplied one",
  "error": "metadata_not_ready|job_not_ready|validation_failed|integrity_conflict|conflict_exhausted|internal"
}
```

Invalid bodies or signatures return minimal generic errors without parser,
storage, secret, or upstream details and omit `event_id` when no validated
envelope identity exists. Aggregation is exhaustive:

- `not_required` is valid only for an effect excluded by the event contract;
- `applied` means at least one required effect is `applied`, while every other
  required effect is `applied`, `already_applied`, or `stale`;
- `duplicate` means every required effect is `already_applied`;
- `stale` means no required effect is `applied`, at least one is `stale`, and
  every other required effect is `stale` or `already_applied`.

There is always at least one required effect: the blob. A required effect
reported as `not_required`, an effect value outside this matrix, an event
identity/digest conflict, or an aggregate that does not match its effects is
an integrity error rather than success. This explicitly permits partial-retry
results such as blob `already_applied`, job `applied`, mapping `stale`, with
aggregate `applied`, and duplicate/stale mixtures with aggregate `stale`.

### Generation-matched writes

Add separate optional serde-defaulted transcript and transcode watermarks to
`BlobMetadata`, plus a transcript watermark to `SubtitleJob` and the typed
hash-to-job mapping record. Each watermark contains:

- operation ordering fields;
- last sequence;
- last event ID;
- lowercase SHA-256 digest of the canonical event bytes.

Equal ordering coordinates are a duplicate only when both event ID and digest
match the watermark. Equal coordinates with a different event ID or digest are
an integrity conflict even after the pending object has been deleted.

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

The event's explicit `job_id` is authoritative for its subtitle-job record. A
stale event cannot repoint the canonical hash mapping because that mapping
applies the same total-order decision. Forced replacement with a newer
operation wins; a late completion for the old job is stale for the mapping
while remaining independently classifiable for that old job record. Once a
job has been superseded in the canonical mapping, an event for that older job
can never reclaim it.

Failure counters are changed inside the CAS transition using the
matching-epoch maximum ordinal rule. Completion and failure fields are
otherwise absolute assignments derived from the typed event. Retrying either
transition is idempotent.

### Hash-to-job bridge and ordering

The existing hash-to-job key contains a raw job-ID string. The typed mapping is
introduced in a new `subtitle-job-map-v2:<sha256>` key; the legacy key is never
overwritten with JSON.

Every mapping-writing path is first moved behind one compile-visible
`mutate_hash_job_mapping` helper. The inventory includes forced-job creation,
manual transcript controls, admin repair, subtitle dispatch, recovery, and
every direct KV insert found by a repository test. The helper reads key
`mapping_writes_paused` from the dedicated Fastly Config Store
`operational_controls` without an application cache before mutation. Missing,
malformed, or unreadable control state fails closed. When paused, every
mapping-writing route returns:

```json
{"error":"mapping_writes_paused","retryable":true}
```

with HTTP 503 and `Retry-After: 30`, before changing a job or mapping. No
caller-supplied flag bypasses the helper.

The freeze-capable bridge package is globally active before the control is
used. Operators verify the active service version, wait ten minutes for POP
propagation, and probe every inventoried route through multi-region POPs. They
then set `mapping_writes_paused=true`, wait another ten minutes, and require
all probes to return the exact paused response, the
`active_mapping_writers` gauge to remain zero, and no successful mapping-write
log for two minutes. Any missing signal keeps the freeze in place and blocks
migration. Resume occurs only after v2 parity verification: set the control
false, probe one safe canary mutation, verify v2/legacy parity, then resume
processor admissions.

A bridge Fastly release, deployed to every POP before status delivery is
enabled:

- reads the v2 mapping first and falls back to the legacy raw string;
- includes and round-trips all optional watermark fields that later releases
  can populate;
- after global bridge verification, writes the legacy raw string for
  compatibility and generation-matches a typed v2 record for every new or
  forced job;
- gives each forced-job creation its own UUIDv7 operation ID, start time, and
  sequence, and installs that ordering watermark in v2 before dispatching the
  job;
- uses generation-aware writes for every existing full-record mutation.

After the bridge helper is globally verified, both the Fastly mapping gate and
Cloud Run admission pause remain active during drain and migration. A
reconciliation pass converts every legacy mapping to its v2 baseline and
verifies parity. Only then does v2 become authoritative and both controls
resume in the order above. There is therefore no accepted legacy write after
v2 initialization that can be lost. Status delivery writes v2 only. Legacy
writes continue from bridge-or-newer packages for one compatibility release
and are then removed. The pre-v2 key may be deleted only after the seven-day
stable window and a scan proves every active mapping has v2 state.

For a legacy-only mapping first encountered by bridge code, v2 is initialized
with the current job ID and a reserved baseline watermark:
`operation_started_at_ms=0`, nil UUID, sequence `0`, and the canonical digest
of the typed baseline record. Sequence zero is invalid for events and exists
only for this migration sentinel, which orders below every real operation. A
forced-job transition and baseline creation both use create/CAS; after a
conflict they reload, and every real forced-job operation supersedes the
baseline. Events for a job other than the v2 canonical job may update that
job's own record, but mapping effect is `stale`.

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
The adapter uses `CreateTask`, because deterministic task IDs are required,
and supplies the API-required fixed placeholder URL
`https://invalid.invalid/`. Task creators otherwise supply only the
deterministic name and bounded body—no query, authentication, or
caller-selected headers. The `ALWAYS` override replaces the placeholder
scheme, host, path, method, headers, OIDC service account, and audience before
dispatch. Deployment contract tests inspect the queue configuration and send
a task containing the placeholder to prove the delivery service, not the
placeholder, receives it. The delivery service rejects a non-empty query,
unexpected content type, oversized body, duplicate content-type, or unknown
JSON field. Cloud Tasks informational headers are logged only as bounded
delivery metadata and are never treated as identity.

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
| Exact authenticated `400 validation_failed` with matching event ID and schema | Create dead, delete pending generation, 204 |
| Fastly 404/405, unknown or mismatched 4xx, or malformed error | 503; retain and alert route/configuration failure |
| Fastly success followed by cleanup failure | 503; retry safely |

Dead records contain the original sanitized event, classification, upstream
status code when present, first/last attempt timestamps, and no response body
or credential.

Automatic dead-lettering is deliberately allowlisted. It occurs only for a
locally detected structurally corrupt known-version event, or an authenticated
Fastly response whose exact bounded body is
`{"event_id":"<same-id>","error":"validation_failed"}` with HTTP 400.
`integrity_conflict`, 404, 405, every unrecognized status/error pair, and every
malformed response retain pending and page an operator. Route propagation,
rollback skew, or target misconfiguration therefore cannot discard an event.

Before deletion, the worker parses the bounded Fastly response, verifies the
exact schema, echoed event ID, aggregate outcome, and every required effect.
It retains the pending record on any mismatch. A dead-object create conflict
also requires matching event ID and canonical digest before pending cleanup.

The service reuses one HTTP client. Liveness proves the process is running.
Readiness verifies outbox access, secret-file readability, fixed target
configuration, and service mode without calling Fastly.

## Reconciliation job

Cloud Scheduler requests a Cloud Run Job once per minute. The job first
acquires `lease.json` in the reconciliation-control bucket with a
generation-matched write. The lease records execution ID, acquisition time,
and expiry; a live lease makes a duplicate Scheduler invocation exit
successfully without scanning. A crashed execution can be reclaimed after ten
minutes using generation match. Correctness does not depend on Cloud Run
preventing overlapping executions.

The job stores the next GCS page token and cycle start time in
`cursor.json` in the control bucket using a generation-match update. It advances
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

After every normal exit, including a bounded per-record failure, a `finally`
path deletes the exact lease generation acquired by that execution. A release
precondition failure is logged and does not delete another execution's lease.
If the process crashes before `finally`, expiry-only reclamation applies.
The reconciler identity has exact get/create/update/delete permission for the
two control objects. Tests cover successful release, early-return release,
panic/error cleanup, release races, crash expiry, and inability to access any
other bucket.

For every pending object older than two minutes, it creates the deterministic
task. `AlreadyExists` is recorded and scanning continues.

## Incident recovery tool

Provide a checked-in admin CLI using the recovery identity from the IAM table.
It emits canonical JSON with `schema_version`, `recovery_run_id`, creation
time, source evidence, ordered entries, and a SHA-256 manifest digest.

Artifact recovery has `discover`, `plan-intent`, `prepare`, `apply`, and
`verify` phases.

`discover`:

- lists `*/vtt/main.vtt` and `*/hls/master.m3u8` in the media bucket;
- emits a local manifest of artifact-backed `complete` candidates;
- accepts an explicit operator-supplied manifest of terminal failures derived
  from structured logs/Sentry evidence;
- does not mutate cloud state.

`plan-intent`:

- validates every hash and current Fastly metadata response;
- excludes absent, deleted, or otherwise ineligible blob metadata;
- shows counts by derivative and desired status;
- creates one UUIDv7 `recovery_run_id` for the reviewed manifest;
- writes a non-mutating intent manifest and digest, without operation IDs,
  attempt ordinals, or publishable event bytes.

`prepare`:

- requires the reviewed intent digest and an explicit `--confirm-prepare`;
- creates and persists one UUIDv7 status `operation_id` per ordered
  hash/derivative entry, with at most 32 status events and deterministic
  UUIDv5 event IDs derived from that entry's operation ID and sequence;
- transactionally reserves the exact Firestore attempt epoch/ordinal for every
  operation, idempotently keyed by operation ID;
- in the same Firestore transaction, creates
  `recovery_preparations/<recovery_run_id>:<entry_index>` containing the stable
  operation ID, allocation, canonical bytes, and digest; an existing matching
  preparation is reused and a mismatch is an integrity error;
- writes a prepared artifact containing every exact canonical event byte,
  intent digest, allocation evidence, and a prepared-artifact digest;
- does not create pending objects, tasks, Fastly writes, or processor work.

An operator reviews the prepared artifact after reservation. Preparation is
the explicit mutation boundary; discover and plan-intent remain dry-run.
Abandoned or crashed preparations retain their admitted ordinal reservations
and durable preparation records. Retrying prepare reads the exact known entry
document, so a crash between transaction commit and local artifact write
reconstructs identical bytes rather than allocating a new operation. These
reservations do not change public failure counters unless a later reviewed
event uses a higher ordinal. Exhaustion follows the reviewed epoch-rotation
procedure above rather than silently reusing numbers.

`apply`:

- requires the reviewed prepared-artifact digest and an explicit
  `--confirm-apply`;
- refuses an artifact whose intent digest, allocation evidence, event IDs, or
  canonical bytes changed after review;
- publishes exactly the operation IDs and event IDs stored in the reviewed
  prepared artifact using the normal typed outbox publisher;
- never calls the processor or retranscodes media;
- is idempotent when rerun with the same manifest.

`recovery_run_id` groups audit output only; it is never used as a status
operation ID. Replanning creates a new run. Re-preparing the same intent
reuses its persisted operation/allocation records; reapplying the same
reviewed prepared artifact reuses its IDs and canonical bytes, so every entry
remains idempotent even when a manifest contains hundreds of hashes.

`verify` reports artifact count, planned count, applied count, remaining
stale count, and terminal retry suppression. The current incident's known
invalid-media hash is supplied through the reviewed manifest, not hardcoded.

Dead-letter operations are separate:

- `dead list` shows bounded IDs, classifications, ages, and derivatives;
- `dead inspect <event_id>` validates and prints a redacted canonical record;
- `dead plan-replay <event_id>` requires an operator-supplied correction and
  creates a replay intent rather than changing the immutable event;
- `dead prepare-replay <reviewed-intent> --confirm-prepare` follows the same
  ordinal-reservation and exact-event review boundary;
- `dead apply-replay <reviewed-prepared-artifact> --confirm-apply` binds to the
  prepared digest, publishes the corrective event, and leaves the original
  dead record for its 30-day audit retention;
- `dead verify-replay` confirms the corrective event reached Fastly.

CLI output is machine-readable JSON by default. Prepare/apply commands require
the dedicated recovery identity, explicit project/bucket/database inputs, the
appropriate reviewed digest, and distinct confirmation flags. Discovery and
intent planning never mutate cloud state.

## Deployment order

0. Restore the active P1 independently of the long rollout: align the current
   legacy callback secret, verify live transcript and transcode callbacks, and
   run an audited artifact-backed metadata repair for the incident window.
   This repair does not wait for the 24-hour canary and does not retranscode.
1. Publish the freeze-capable bridge Fastly release. It moves every
   full-record mutation to generation-aware CAS, includes and losslessly
   round-trips every optional blob/job/v2 watermark field, inventories and
   gates every mapping writer, and dual-reads legacy/v2 mappings while legacy
   remains authoritative. It does not yet create v2 baselines or accept
   delivery watermarks.
2. Purge and prove the bridge active through the declared propagation/probe
   gate. Set the Fastly mapping control to paused, switch Cloud Run traffic to
   the maintenance revision, and satisfy both mapping-writer and processor
   drain criteria.
3. With both controls still paused, migrate legacy mappings to v2 baselines,
   reconcile parity, and declare the bridge version the rollback floor. Make
   v2 authoritative, canary-unfreeze the mapping gate, then resume processor
   admissions. No v2 mapping becomes authoritative during mixed-POP
   propagation.
4. Add versioned status endpoints and HMAC verification on top of the bridge;
   publish with `fastly compute publish`, purge, and verify legacy behavior
   plus the new routes.
5. Provision the five private state buckets, dedicated Firestore attempt
   database, queue with enforced overrides, identities/IAM, private worker,
   reconciliation job, metrics, and alerts.
6. Deploy the delivery worker and test unauthenticated rejection, task OIDC,
   HMAC overlap, retry, dead-letter, CAS conflict, and secret rotation.
7. Add processor HMAC verification in dual-accept mode. Inventory and update
   every caller before rejection becomes mandatory: Fastly on-demand
   transcript/transcode paths, `cloud-run-upload`, `backfill.sh`,
   `backfill-prioritized.sh`, incident recovery tooling, and any documented
   operator command. Verify each caller, then reject unsigned requests.
8. Deploy queue-first producer support in a named, zero-traffic processor
   revision and run controlled synthetic
   transcript/transcode canaries through the complete production queue and
   Fastly path for 24 hours.
9. If canary criteria pass, pause new processor admissions, wait for the old
   revision's bounded in-flight operations to finish, verify zero legacy
   callbacks for twice the maximum operation timeout, switch Cloud Run traffic
   100% to the named queue-first revision, and resume admissions. This is the
   rollout control plane; no per-instance feature flag or mixed direct/queued
   status mode is permitted.
10. Disable legacy status endpoints and observe for seven days.
11. Run the new recovery tool for any residual artifact/status drift: review
    the dry-run intent, prepare exact allocated events, review the prepared
    digest, apply, and verify convergence.
12. Remove old shared status-sender code and legacy mapping writes after
    fourteen stable days.

Rollback never disables immutable outbox persistence while processors accept
work. Depending on the faulty layer it either:

- pauses processor admissions and lets in-flight operations persist their
  final events; or
- keeps processor publication active while pausing only queue dispatch.

Pending/dead objects are never deleted by rollback. Before step 3, Fastly may
roll back normally. After any watermark or v2 canonical mapping exists, the
pre-CAS package is permanently ineligible: rollback may activate only the
declared bridge floor or a later CAS-compatible version. Slow POP propagation
is treated as a mixed-version deployment, so queue-first enablement waits
until probes prove every sampled POP understands optional watermarks and v2
mappings. If the new Fastly route is the fault, pause queue dispatch, keep
outbox publication active, activate the bridge floor, correct the route, and
resume. Never switch queued producers to unordered direct delivery.

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
- active derivative operations by processor revision;
- active mapping writers and mapping-freeze rejections by Fastly version;
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

If derivative computation or artifact upload succeeds but terminal-event
persistence returns 503, the caller sees a retryable processing failure rather
than success. Support should describe this as a temporary processing state:
the artifact is safe, a retry with a new signed request reuses the existing
artifact, publishes completion without recomputation, and does not require a
new user upload.

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
- size, UUID, hash, timestamp, sequence, attempt epoch/ordinal, and error
  bounds;
- total-order same-millisecond UUID tie-break;
- retry/dead/unknown-version classification;
- transition decisions for applied, duplicate, stale, and newer operation;
- exhaustive aggregate/effect response combinations;
- equal-order event-ID and canonical-digest conflicts.

### Fastly metadata tests

Introduce an injected KV adapter exposing value plus generation and
generation-matched writes.

- uncached webhook lookup;
- CAS success and conflict reload;
- conflict exhaustion;
- duplicate failure does not increment;
- out-of-order failures converge via matching-epoch maximum ordinal;
- a stale failure cannot alter a newer complete, terminal, or attempt epoch;
- partial blob success followed by job failure completes on retry;
- missing blob/job returns retryable 409;
- cache purge is retried after durable effects;
- transcript and transcode use independent blob watermarks;
- forced hash-to-job replacement rejects a late old-job event;
- legacy raw mapping bridge, baseline sentinel, v2 preference, dual-write
  window, and a forced-job/migration race;
- post-watermark rollback accepts the CAS bridge floor and rejects a pre-CAS
  package;
- every mapping writer is inventory-enforced through the fail-closed dynamic
  gate; migration cannot start until propagation, route probes, zero-active,
  and quiet-log criteria all pass;
- moderation/delete/upload/backfill/subtitle-dispatch races preserve all
  unrelated fields and delivery watermarks;
- every existing full-record writer uses the generation-aware path.

### Processor and publisher tests

- unsigned, stale, malformed, and wrong-secret processor requests are rejected
  before work;
- captured signatures cannot replay across method/path/body/request ID;
- every runtime passes the shared byte-level HMAC fixtures;
- replay markers reject repeated expensive work and expire after 24 hours;
- pre-authentication body limits reject oversized requests;
- current and overlap secrets are accepted;
- processor auth verify returns the exact bounded response and performs no
  replay, lock, attempt, outbox, artifact, or compute mutation;
- maintenance mode returns retryable 503 on every compute route while health
  and verification remain available;
- traffic pause/drain fails closed for every nonzero or unavailable signal and
  resumes only to an explicit named revision;
- pending persistence precedes task creation;
- pending create conflict requires byte equality;
- task-create failure leaves a recoverable pending event;
- existing artifact makes a retried processor request publish completion
  without recomputation;
- duplicate transcode request is suppressed by its GCS lock;
- attempt allocation is atomic, monotonic, bounded, and idempotent per
  operation ID;
- every permanent-input terminal code suppresses later compute before lock
  acquisition, while transient/provider codes do not;
- suppression clear requires the dedicated operator identity, reviewed digest,
  and new epoch;
- suppression present with missing pending and/or task reconstructs exact
  canonical bytes before lock acquisition and returns without compute;
- processor/recovery can create/read but cannot update/delete suppression,
  while the operator rotates the Firestore epoch before exact-generation
  deletion.

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
- unknown schema remains pending;
- 404, 405, unknown 4xx, mismatched error code, and malformed Fastly errors
  retain pending;
- only exact matching `400 validation_failed` and local structural corruption
  create dead records.

### Reconciler and recovery tests

- multi-page backlog cannot starve later pages;
- durable cursor recovery at every crash boundary;
- overlapping execution prevention;
- generation-matched lease release on success, early error, and release race,
  plus expiry recovery after a simulated crash;
- task-name tombstone and `AlreadyExists` behavior;
- recovery discover and intent dry-run never mutate;
- intent planning never mutates, prepare reserves stable ordinals without
  publishing, and apply refuses unreviewed or changed canonical bytes;
- crashed/repeated prepare and apply reuse stable IDs/ordinals idempotently;
- recovery excludes ineligible metadata and never invokes processors.

### Deployment smoke tests

- private worker rejects unauthenticated invocation;
- processor signer rotation is proven through the non-compute verification
  route for Fastly, upload, and operator call paths;
- a maintenance revision receives 100% traffic, rejects admissions, and meets
  the 900/1,800-second drain contract before bridge or queue-first cutover;
- all mapping-writing routes reject through the Fastly freeze control before
  migration, and v2/legacy parity is verified before controlled resume;
- queue-level host/path/method/OIDC overrides cannot be bypassed by task input;
- runtime identities cannot invoke or read outside their matrix;
- effective IAM grants listing only on the pending/dead/media buckets declared
  above and prevents delivery from deleting dead/control/replay objects;
- recovery can read but cannot create or delete dead records;
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
- incident recovery discover/intent dry-run, ordinal preparation, exact-event
  review, apply, and verification;
- transcript and transcode end-to-end validation;
- rollback and backlog drain.

Each alert and privileged action names an operational owner role and escalation
target: processor owner, delivery owner, Fastly owner, incident commander, or
support lead. The runbook also covers terminal-suppression inspection and
operator-only reviewed clearing, the immediate legacy-secret P1 repair,
maintenance-window alert annotations during queue pauses/rotation, and the
admission pause required for bridge and queue-first cutovers.

Maintenance annotations may mute only expected backlog, rate, and age
notifications for a bounded auto-expiring window. Integrity, dead-letter,
authorization, credential, and untracked-event alerts remain active. Resume
requires an explicit post-maintenance queue/pending/lock check and removal of
any remaining mute.

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
