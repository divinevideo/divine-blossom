# Derivative Status Queue

Transcoder HLS and transcript status callbacks can be delivered through Cloud
Tasks by setting these Cloud Run env vars:

- `STATUS_QUEUE_ENABLED=true`
- `STATUS_QUEUE_LOCATION=us-central1`
- `STATUS_QUEUE_NAME=derivative-status`

Run `cloud-run-transcoder/setup-status-queue.sh` before enabling the flag. The
script creates or updates the queue with `--max-concurrent-dispatches=1`.
Serialized dispatch is part of the ordering contract: the edge receiver stores
`transcode_generation` and `transcript_generation` on blob metadata and ignores
callbacks whose generation is older than the stored value.

Generation values use a monotonic derivative-attempt token plus a small
per-event sequence, so a terminal callback from an older overlapping attempt
remains older than a processing callback from a newer attempt. Duplicate failed
callbacks with the same generation are acknowledged and ignored so Cloud Tasks
redelivery cannot replay terminal failure side effects.

`cloud-run-transcoder/deploy.sh` owns the env var names and defaults the flag to
`false`, so direct POST remains the rollback path. A production deploy should
set `STATUS_QUEUE_ENABLED=true` only after the queue and IAM grant are present.

The transcoder retries `CreateTask` three times. If all attempts fail it logs
`status_callback_enqueue_failed=true` and falls back to the direct POST path;
alerting should match that log signal, because a task that was never created
will not emit Cloud Tasks queue metrics.

The queue serializes transcode and transcript status callbacks together, so
`--max-concurrent-dispatches=1` is also the project-wide dispatch ceiling for
derivative status delivery. The task header includes the existing bearer
webhook secret, which means Cloud Tasks stores that shared secret at rest until
the task is dispatched.
