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

Generation is required once a blob has versioned derivative state. During the
rollout window, callbacks that omit `generation` are accepted only while the
stored `*_generation` field is still absent. After that, missing generations are
acknowledged with `ignored: "missing_generation"` and do not update metadata.
Malformed generations, such as strings, floats, negative values, or values
outside `u64`, are acknowledged with `ignored: "malformed_generation"` and do
not update metadata.

`cloud-run-transcoder/deploy.sh` owns the env var names and defaults the flag to
`false`, so direct POST remains the rollback path. A production deploy should
set `STATUS_QUEUE_ENABLED=true` only after the queue and IAM grant are present.

The transcoder makes three total `CreateTask` attempts. If all attempts fail it logs
`status_callback_enqueue_failed=true` and falls back to the direct POST path;
alerting should match that log signal, because a task that was never created
will not emit Cloud Tasks queue metrics.

The direct fallback is a best-effort rollback path, not an ordering guarantee.
Fastly KV metadata updates are read-modify-write operations without compare and
swap. Queue serialization prevents concurrent callback writers in the normal
path, but fallback POSTs can run concurrently with queued dispatch if Cloud
Tasks accepts some callbacks and rejects later ones. Treat
`status_callback_enqueue_failed=true` as a rollback signal and disable
`STATUS_QUEUE_ENABLED` while investigating repeated enqueue failures.

Paused queues require separate monitoring. Cloud Tasks accepts `CreateTask` for
a paused queue, so enqueue-failure logs do not catch that state. Alert on queue
state, queue depth, and oldest task age before enabling the flag.

The queue serializes transcode and transcript status callbacks together, so
`--max-concurrent-dispatches=1` is also the project-wide dispatch ceiling for
derivative status delivery. The task header includes the existing bearer
webhook secret, which means Cloud Tasks stores that shared secret at rest until
the task is dispatched.

Measure dispatch throughput in the target region before enabling production
traffic. Each callback performs one Fastly Compute request with an uncached
metadata read and a metadata write, and each upload normally emits about four
callbacks: transcode processing, transcode terminal, transcript processing, and
transcript terminal. Do not enable `STATUS_QUEUE_ENABLED=true` until the
measured callback latency supports the expected upload rate with headroom, or
until the rollout is capped below that measured ceiling.
