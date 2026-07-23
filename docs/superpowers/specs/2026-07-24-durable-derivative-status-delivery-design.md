# Durable Derivative Status Delivery Design

**Date:** 2026-07-24
**Issue:** divine-funnelcake#686
**Status:** Approved for implementation planning

## Problem

The Cloud Run transcoder currently sends transcript and HLS status updates to
Fastly as fire-and-forget HTTP requests. A non-2xx response is logged, but the
job continues and the update is permanently lost.

On 2026-07-22 and 2026-07-23, Fastly rejected these callbacks with
`403 Invalid webhook secret`. Transcript and HLS artifacts continued to be
written to GCS, but Fastly KV metadata remained stale. Terminal invalid-media
failures were also lost, causing the same corrupt source to be retried and
reported repeatedly.

The reliability boundary must therefore be the status event itself, not the
duration of one Cloud Run request.

## Goals

- Deliver every transcript and HLS status update eventually.
- Survive temporary network, Fastly, credential, and Cloud Tasks failures.
- Make duplicate and out-of-order deliveries harmless.
- Allow webhook-secret rotation without redeploying the delivery service.
- Make a stuck delivery backlog visible within five minutes.
- Recover existing or future orphaned events without retranscoding media.
- Keep the solution specific to derivative status delivery rather than
  introducing a general event platform.

## Non-goals

- Replacing Fastly KV as the public metadata store.
- Replacing the existing transcription or HLS processing pipelines.
- Building a reusable company-wide event bus.
- Providing strict FIFO ordering from Cloud Tasks.
- Deploying or rotating production secrets as part of the code change.

## Architecture

The transcoder image will support two service modes:

- `processor` (default): the existing public `divine-transcoder` service.
- `delivery`: a private `divine-status-delivery` Cloud Run service exposing
  only health, task delivery, and reconciliation routes.

The services use the same image and Rust event types. They are separate Cloud
Run services because the existing transcoder is publicly invokable. Keeping
the delivery service private lets Cloud Run IAM authenticate Cloud Tasks and
Cloud Scheduler OIDC tokens without bespoke JWT validation in application
code.

```text
Transcript or HLS processor
  -> write immutable pending event to GCS
  -> create deterministic Cloud Task
  -> finish the processing request

Cloud Tasks (OIDC)
  -> private divine-status-delivery service
  -> load pending event from GCS
  -> read the current webhook secret from a mounted secret volume
  -> POST the existing payload to Fastly
  -> on Fastly 2xx, delete the pending event and acknowledge the task
  -> otherwise retain the event and retry or dead-letter it

Cloud Scheduler (OIDC, once per minute)
  -> reconciliation route
  -> find old pending events
  -> recreate missing deterministic tasks
```

## Components

### Shared status-delivery module

Create a focused module under `cloud-run-transcoder/src/` that owns:

- the versioned `StatusEvent` wire type;
- event validation;
- deterministic GCS object and Cloud Task names;
- outbox persistence;
- Cloud Tasks creation;
- delivery response classification;
- reconciliation decisions.

Provider transcription retries and derivative status-delivery retries remain
separate concerns.

### GCS outbox

Use the existing media bucket with dedicated internal prefixes:

- `status-outbox/pending/<event_id>.json`
- `status-outbox/dead/<event_id>.json`

An event is written to `pending` before task creation. If Cloud Tasks creation
fails, the processing request does not lose the event; the reconciler can
create the task later.

Pending records remain until Fastly accepts them. Permanently malformed events
move to `dead` with the delivery classification and timestamp. Dead records
are retained for operator inspection and alerting and must not contain
secrets.

GCS is already a required dependency of the processor and is strongly
consistent for object reads and listings. The outbox adds no new datastore.

### Cloud Tasks queue

Provision one regional queue, `derivative-status-delivery`, in the same region
as the delivery service.

Initial queue policy:

- minimum retry backoff: 5 seconds;
- maximum retry backoff: 15 minutes;
- exponential backoff;
- no small maximum-attempt cutoff;
- dispatch deadline: 30 seconds;
- maximum concurrent dispatches: 10;
- maximum dispatch rate: 20 per second.

Cloud Tasks invokes the private delivery service using a dedicated service
account with only `roles/run.invoker` on that service. The processor service
account receives only the permission needed to create tasks in this queue.

A task body contains only `event_id`. Task names are derived from the event ID,
so a producer or reconciler may safely repeat task creation. `AlreadyExists`
is treated as success.

### Private delivery service

The delivery service exposes:

- `GET /health`
- `POST /internal/status-events/deliver`
- `POST /internal/status-events/reconcile`

The service is not granted `allUsers` invocation. Cloud Run IAM rejects
unauthenticated requests before application code runs.

The webhook secret is mounted from Secret Manager as a `latest` version file
and read for each delivery. Cloud Run secret volumes fetch the latest value
when read, so secret rotation does not require a new revision. The secret is
never copied into a Cloud Task or GCS event.

The delivery service sends the existing bearer-authenticated payload to one of
the two existing Fastly routes:

- `/admin/transcode-status`
- `/admin/transcript-status`

It returns 2xx to Cloud Tasks only after Fastly accepts the event or the event
has been safely dead-lettered.

### Reconciler

Cloud Scheduler invokes reconciliation once per minute using a second service
account with `roles/run.invoker` on the private delivery service.

The reconciler lists pending records older than two minutes and recreates
their deterministic tasks. It processes a bounded page per invocation and
logs the continuation state. Duplicate task creation and duplicate delivery
are safe.

This is recovery for the producer-to-queue gap and task expiry; it is not a
second primary delivery mechanism.

## Event contract

```json
{
  "schema_version": 1,
  "event_id": "uuid",
  "derivative": "transcript",
  "sha256": "64 lowercase hex characters",
  "operation_id": "uuid",
  "operation_started_at_ms": 1784847000000,
  "sequence": 2,
  "created_at_ms": 1784847001234,
  "status": "complete",
  "payload": {
    "sha256": "64 lowercase hex characters",
    "status": "complete"
  }
}
```

`derivative` is `transcript` or `transcode`. The payload retains all existing
fields, including transcript `job_id`, language, duration, cue count, error
details, retry timing, dimensions, and terminal status.

Each processor invocation creates a unique `operation_id` and increasing
sequence numbers for its status events. `job_id` remains a product-facing
subtitle-job identifier and is not reused as a delivery identifier.

Events contain no media bytes, transcript text, owner keys, credentials, or
other secrets.

## Idempotency and ordering

Cloud Tasks provides at-least-once delivery, not strict FIFO ordering. Fastly
therefore stores a delivery watermark independently for transcript and
transcode metadata:

- last operation start time;
- last operation ID;
- last accepted sequence;
- last event ID.

Fastly applies an event when:

- its operation start time is newer than the stored operation; or
- it belongs to the stored operation and has a higher sequence.

Fastly acknowledges without mutation when:

- the event ID is a duplicate;
- the operation is older; or
- the sequence has already been applied.

This check happens before changing status, incrementing attempt counts,
updating subtitle jobs, or purging caches. Consequently:

- duplicate failures increment attempt counters once;
- delayed `processing` events cannot regress a completed operation;
- a later explicit retry operation may advance a previous terminal state.

The handler returns 200 for duplicate and stale events so Cloud Tasks stops
retrying them.

## Failure classification

Delivery results are handled as follows:

| Result | Action |
| --- | --- |
| Fastly 2xx | Delete pending record and acknowledge task |
| Network error | Retain pending record and retry |
| 401, 403 | Retain, alert as credential failure, and retry |
| 404 | Retain and retry because metadata creation can race delivery |
| 408, 409, 425, 429 | Retain and retry |
| 5xx | Retain and retry |
| Structurally invalid event before dispatch | Move to `dead` and alert |
| Other permanent Fastly 4xx | Move to `dead` and alert with sanitized response metadata |

The delivery service maps retryable upstream results to a non-2xx task-handler
response. It records the actual upstream status in structured logs and
metrics.

If deleting the pending event fails after Fastly accepted it, the task is
retried. Fastly idempotency makes the duplicate harmless, and the next attempt
can finish cleanup.

## Producer behavior

Replace both direct webhook functions with a shared queue-first publisher.

For every status transition:

1. Build and validate the status event.
2. Persist the pending GCS record.
3. Attempt deterministic task creation with short bounded client retries.
4. Return success once either task creation succeeds or the durable pending
   record is confirmed.

The media operation does not wait for Fastly delivery.

If the pending record itself cannot be persisted, return an error and capture
a focused Sentry event. A retried media request remains cheap after successful
artifact creation because existing GCS artifact checks emit `complete`
without recomputing the derivative.

## Observability

Structured logs and metrics include:

- event ID, derivative, hash, operation ID, and sequence;
- enqueue outcome and latency;
- delivery attempt count and latency;
- sanitized Fastly response status;
- pending outbox age and count;
- dead-letter count;
- reconciliation scanned, recreated, skipped, and failed counts.

Never log authorization headers, secret values, transcript content, media
bytes, or full external response bodies.

Create alerts for:

- oldest pending event greater than five minutes;
- any sustained 401/403 delivery response;
- any dead-letter event;
- task creation failures;
- reconciler failures;
- queue depth growing for fifteen minutes.

Sentry fingerprints must identify the service and failure class rather than
grouping all provider and delivery errors together.

## Testing

### Native unit tests

- Event serialization and validation for both derivative types.
- Deterministic event object and task naming.
- Retryable versus permanent response classification.
- Operation/sequence watermark comparisons.
- Duplicate failures do not increment attempt counts.
- Newer operations may advance terminal state.
- Older and duplicate events return success without mutation.

### Service tests

Use a local HTTP test server and injected outbox/task/webhook clients to prove:

- pending persistence happens before task creation;
- task-creation failure leaves a recoverable pending event;
- Fastly 403 retains the event and returns a retryable task response;
- Fastly 200 deletes the pending event;
- cleanup failure causes a safe duplicate retry;
- malformed events move to the dead prefix;
- reconciliation recreates deterministic missing tasks;
- `AlreadyExists` is successful reconciliation.

### Integration and deployment validation

- Run the transcoder test suite and clippy.
- Deploy the private delivery service before enabling producers.
- Submit a synthetic non-media status event against a controlled test
  metadata record.
- Verify OIDC invocation succeeds and unauthenticated invocation is rejected.
- Verify a deliberately rejected callback remains pending and retries.
- Correct the test credential and verify the queued event drains without
  recreation.
- Enable queue-first publishing for a small canary, then for all status events.

## Rollout and recovery

1. Provision the queue, service accounts, IAM, secret volume, Scheduler job,
   dashboards, and alerts.
2. Deploy the same image in private `delivery` mode.
3. Run authentication, retry, and secret-rotation smoke tests.
4. Deploy processor support with queue publishing disabled.
5. Enable queue-first publishing for transcript and transcode events.
6. Confirm pending age remains below five minutes and Fastly metadata reaches
   terminal states.
7. Reconcile existing VTT artifacts and terminal invalid-media failures from
   the incident window.

The initial release may retain the direct sender behind an emergency
configuration switch, marked `TODO(#686)` and disabled by default. Remove the
switch after the queued path has completed a stable observation period.

Rollback disables new queue publishing but does not delete pending or dead
records. The delivery service and reconciler remain active until the backlog
is empty.

## Operational runbook requirements

Document:

- how to inspect queue depth and oldest pending-event age;
- how to identify 401/403 delivery failures without reading secrets;
- how to synchronize or rotate the GCP and Fastly webhook secret safely;
- how to replay pending and dead events;
- how to pause and resume queue dispatch;
- how to validate one transcript and one HLS transition end to end;
- how to reconcile artifacts after a prolonged outage.

## Security

- The delivery service is private and OIDC-authenticated by Cloud Run IAM.
- Producer, task-invoker, and scheduler service accounts have separate,
  least-privilege roles.
- The Fastly secret exists only in Secret Manager, its mounted volume, and the
  outbound authorization header.
- Outbox events are operational metadata only and use bucket IAM already
  restricted to service identities.
- Logs and alerts use IDs and status codes, never credentials or user media.

## Success criteria

- A five-minute Fastly or credential outage loses zero status events.
- Restoring Fastly or the credential drains the backlog without
  retranscoding.
- Duplicate or out-of-order task delivery cannot regress metadata or multiply
  attempt counters.
- Secret rotation is observed by the delivery service without a new revision.
- A task-creation outage is recovered by the GCS outbox reconciler.
- Operators receive an alert within five minutes of a stuck backlog.
- Direct `.vtt`/HLS artifact availability and Fastly metadata converge after
  recovery.
