# Bounded Derivative Failure Handling Design

## Problem

Derivative generation failures currently behave badly in two ways:

1. Invalid or otherwise non-processable media can remain stored as canonical blobs but keep re-triggering HLS and transcript jobs forever.
2. Operationally meaningful failures are visible in logs, but not normalized into durable metadata or Sentry events that operators can track.

This creates wasted transcoder work, misleading public `202 Accepted` responses, and poor visibility into systemic bad-object patterns.

## Goals

- Keep canonical blob uploads non-blocking, even when derivatives cannot be generated.
- Bound derivative retries and stop re-triggering after a small number of failed attempts.
- Return terminal public errors for exhausted or fatal derivative failures instead of endless `202` responses.
- Normalize failure reporting across upload, transcode, and transcript paths.
- Send derivative failures to Sentry with stable grouping and enough context to investigate patterns.

## Non-Goals

- Reject all bad `video/*` uploads at ingest.
- Delete or tombstone existing bad blobs automatically.
- Redesign the subtitle job system.

## Recommended Approach

Extend blob metadata so derivative state can distinguish:

- in progress
- cooling down for retry
- failed but still retryable
- terminal failure

Track this separately for HLS/transcode and transcript generation. The upload service may still accept and store bad blobs, but it should stop eagerly dispatching derivative work when upload-time validation already proves the media is invalid. The transcoder and transcript worker should report structured failure payloads to Blossom, and Blossom should decide when retries are exhausted.

## Metadata Model

Add transcode failure metadata parallel to the existing transcript failure metadata:

- `transcode_attempt_count`
- `transcode_error_code`
- `transcode_error_message`
- `transcode_last_attempt_at`
- `transcode_retry_after`
- `transcode_terminal`

Extend transcript metadata with:

- `transcript_attempt_count`
- `transcript_terminal`

The terminal bit is the authoritative signal that public fetch handlers must stop re-triggering work.

## Failure Semantics

Use a small retry cap, defaulting to `3`.

Terminal conditions:

- explicit worker-reported terminal failure
- failure count reaching the configured cap
- upload-time media validation proves the source bytes are invalid for derivatives

Retryable conditions:

- provider rate limiting
- short-lived downstream failures with `retry_after`
- transient webhook or processing failures that do not classify as terminal

Example stable `error_code` values:

- `invalid_media`
- `ffprobe_failed`
- `thumbnail_extract_failed`
- `provider_rate_limited`
- `upload_failed`
- `dispatch_failed`

## Public API Behavior

For HLS and VTT fetches:

- `202 Accepted` while work is actually in progress
- `202 Accepted` with `Retry-After` during explicit cooldown
- `422 Unprocessable Entity` once derivative failure is terminal

Terminal response shape:

```json
{
  "status": "failed",
  "error_code": "invalid_media",
  "message": "Derivative generation failed for this blob",
  "retryable": false
}
```

The canonical blob remains retrievable at its stable media URL.

## Service Responsibilities

### Fastly Blossom

- Persist transcode and transcript failure metadata.
- Apply retry-cap policy.
- Stop public re-trigger loops after terminal failure.
- Return stable `422` derivative failure responses.

### Cloud Run Upload

- Continue accepting and storing canonical blobs.
- Normalize upload-time derivative validation failures for claimed `video/*`.
- Avoid dispatching derivative jobs when validation already proves the media is invalid.
- Emit Sentry events for upload-time invalid-media signals.

### Cloud Run Transcoder

- Send structured failure payloads for HLS and transcript failures.
- Include `error_code`, `error_message`, `retry_after`, and `terminal` where appropriate.
- Emit Sentry events with stable grouping for derivative failure classes.

## Sentry Reporting

Sentry should be emitted from the services where failures originate, not from public fetch handlers.

Capture:

- upload-time invalid media detection
- terminal transcode failures
- terminal transcript failures
- retry exhaustion events
- webhook/state reconciliation failures

Each event should include tags or extras for:

- `sha256`
- `derivative`
- `error_code`
- `attempt_count`
- `terminal`
- `content_type`
- `owner`
- `service`

Use stable fingerprints such as:

- `["divine-upload", "derivative-validation", "invalid_media"]`
- `["divine-transcoder", "hls", "invalid_media"]`
- `["divine-transcoder", "transcript", "provider_rate_limited"]`

## Testing Strategy

- Add Fastly unit tests for retry exhaustion and terminal `422` decisions.
- Add webhook parsing tests for new transcode failure fields.
- Add transcoder tests for structured failure webhook payloads.
- Add upload-service tests for invalid-media classification and derivative dispatch suppression.

## Rollout Notes

- Existing bad blobs should start surfacing terminal derivative responses once they exceed the retry cap or are explicitly marked terminal.
- No migration is required beyond tolerating absent metadata fields on older blobs.
