# Repair legacy aspect-distorted renditions

This runbook supports issues #303 and #161. Shipping this tooling does not repair
stored media: regeneration and cache invalidation require a separately authorized
operator. The original content-addressed blob must never be changed or deleted.

## Read-only selection

Prepare a private file containing one lowercase SHA256 per line from the archive
inventory. Keep inventory and audit output outside Git. Export originals and
derivative objects through an authorized storage read, not through the public
media edge (missing derivatives there can trigger generation). Store originals
at `originals/{hash}` and derivatives at `derivatives/{hash}/hls/` beneath a local
directory. Include both stream MP4s, both stream playlists, and their referenced
TS segments. With `ffprobe` installed, audit that local export:

```sh
python3 cloud-run-transcoder/audit_aspect_renditions.py \
  --hash-file /path/to/hashes.txt --media-root /path/to/export \
  > /path/to/aspect-audit.jsonl
```

The audit probes the original, both progressive aliases, and both HLS streams.
It selects 1280x720 or 854x480 landscape renditions whose display aspect differs
from the original by more than 1%, accounting for rotation and sample aspect
ratio. This includes square originals, not just portrait sources. It emits a
`request` object only for candidates. It never submits requests, deletes objects,
changes access, or purges caches. FFprobe network protocols are disabled, including
for URLs embedded in playlists. Probe errors are recorded and produce exit 1;
they are not evidence that a video is correct. Resolve/retry them before claiming
inventory coverage. Non-right-angle rotations require manual investigation.

## Operator-only regeneration

Confirm that the deployed transcoder supports `force` before proceeding. Normal
`POST /transcode` requests retain the existing-master shortcut. A request with
`{"hash":"<sha256>","force":true}` bypasses it, re-encodes from the original,
and replaces generated HLS derivatives without deleting the prefix first.
Forced repairs abort on an original probe failure rather than guessing 16:9,
and abort before uploading if the progressive MP4 remux fails.
Forced requests require the dedicated `TRANSCODE_REPAIR_SECRET` binding and
`X-Divine-Repair-Secret` header. They fail closed when unconfigured. Secret
provisioning and service configuration are separate operator-authorized work,
not performed by this change. Do not reuse transcription credentials or put
credentials in audit files, shell arguments, or logs. Submit only reviewed
candidates serially and inspect the completed response before advancing. Repairs
require an existing HLS master. Confirm that initial generation has fully
completed at origin before submitting one; do not repair an in-progress upload.

Forced transcodes acquire a generation-conditional GCS lock at
`{hash}/transcode.lock` and release only their own generation. Overlapping repairs
fail rather than overwrite each other. Normal requests do not take this lock and
retain their existing-master shortcut, so a failed repair cannot lock the normal
upload pipeline. Forced jobs run in a separate task so cancellation of the HTTP
response waiter does not cancel their work or lock release. This is not durable
execution: instance termination or a task panic can still leave a repair lock.
A disconnected client, Ctrl-C, or a request timeout gives an unknown outcome;
the writer may still be active. Do not immediately retry or remove its lock.
Inspect service logs and outputs at origin, and an operator must
confirm no writer remains before removing that specific lock. Do not expire locks
by elapsed time alone. Avoid simultaneous fMP4 backfills during the repair.

A successful response may include `repair_lock_warning`: the derivatives were
uploaded, but lock cleanup failed. Investigate that specific lock before the
next repair. If repair and cleanup both fail, the error reports both failures.
Failure callbacks also update the existing video's transcode status and attempt
count even when the old derivatives remain available. A HEAD of the existing
master playlist through the edge reconciles status to complete and resets the
attempt count; verify origin outputs first, since existence does not prove that
a partial repair produced a consistent set.

The edge's progressive aliases read `hls/stream_720p.mp4` and
`hls/stream_480p.mp4`; both must be regenerated successfully along with HLS.
Uploads are not an atomic prefix replacement: a failed upload can leave mixed
versions. Preserve the audit, retry failures, and verify every output at origin
before invalidating caches or marking a hash repaired. Existing files are not
deleted; unreferenced stale objects may remain.

## Verify and invalidate

Probe both MP4s and both HLS streams at origin after each repair and compare their
display ratios with the unchanged original. Confirm that the forced request
completed successfully. Cache invalidation is a
separate operator effect: follow `docs/runbooks/rollback.md` and purge only the
known repaired hash's surrogate key, never the whole cache. Verify the public
paths after propagation; CDN reads before purge can still see old data.

No visual UI change is included; sample request behavior changes only for the
explicit `force` option. Manual validation: audit a synthetic square original
with 16:9 derivatives, regenerate in an authorized test environment, verify all
four ratios and unchanged original bytes, then repeat without `force` and confirm
`already_exists`.
