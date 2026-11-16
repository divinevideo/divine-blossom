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

## Serial runner

`scripts/repair-aspect-renditions.sh` performs the regeneration and origin
verification above for an audit file, one hash at a time. It reads only records
that carry a `request` object, so every repair it submits was selected by the
audit. Use the isolated Python environment from `scripts/requirements-b2-sync.txt`
and supply the repair credential through `TRANSCODE_REPAIR_SECRET_FILE`, never
as an argument. Verification reads the unchanged original from GCS (application
default credentials, `GCS_BUCKET`) and the regenerated outputs from B2
(`B2_MEDIA_BUCKET`, `B2_REGION`, `B2_APPLICATION_KEY_ID`, `B2_APPLICATION_KEY`);
`--original-storage` and `--storage` select other stores. `--storage` must name
the store the edge reads derivatives from (`derived_media_read_primary`, see
`b2-derived-media.md`; public responses report it as `x-divine-source`).
Otherwise a hash can verify in one store while viewers still get the stretched
copy from the other.

```sh
./scripts/repair-aspect-renditions.sh --audit-file /path/to/aspect-audit.jsonl --dry-run
./scripts/repair-aspect-renditions.sh --audit-file /path/to/aspect-audit.jsonl --limit 1
./scripts/repair-aspect-renditions.sh --audit-file /path/to/aspect-audit.jsonl
```

Start with `--limit 1` and inspect that hash at origin and on a client before
the full run. For each hash the runner submits one forced request and never
retries it. On `status:complete` it downloads the original and the four outputs
the edge serves (`hls/stream_{720,480}p.mp4` and `hls/stream_{720,480}p.ts`),
probes them with the audit's geometry rules, and records the hash as done only
when every display ratio is within 1% of the original's. It stops the run, without
recording the hash, when the request is rejected before any work starts (401,
another 4xx, a redirect, or the worker's own `repair not configured` 503) or the
worker answers `already_exists`: a revision without repair support ignores
`force` and leaves the stretched files in place. It stops and records the hash
for review when the outcome is unknown (no or a truncated response, a gateway
error or a 503 the worker did not write, an unrecognized body), when the worker's
error involves the repair lock or `repair_lock_warning` is present, or when
verification fails. Any other worker error (a JSON 500) is recorded as failed and
the run continues with the next hash.

Before each request the runner writes the hash to `aspect-repair-inflight.txt`
and removes it once the outcome is recorded. Ctrl-C records the hash for review.
If the process is killed instead, the next run moves the leftover hash to review
and exits without submitting anything, so a repair whose writer may still be
active is never resubmitted.

Progress lives next to the audit file, or under `--state-dir`, and stays out of
Git like the audit output. `aspect-repair-done.txt` lists verified hashes only and
is the input for cache invalidation below. `aspect-repair-failed.txt` and
`aspect-repair-review.txt` carry a short reason per hash. Done and review entries
are skipped on later runs; remove a review entry only after an operator has
inspected its lock and outputs. Failed entries are resubmitted with
`--retry-failed`. Dry-run lists pending hashes without reading the credential,
submitting requests, or writing state.

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
