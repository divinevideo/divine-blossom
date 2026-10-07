# Repair legacy aspect-distorted renditions

This runbook supports issues #303 and #161. Shipping this tooling does not repair
stored media: regeneration and cache invalidation require a separately authorized
operator. The original content-addressed blob must never be changed or deleted.

## Read-only selection

Prepare a private file containing one lowercase SHA256 per line from the archive
inventory. Keep inventory and audit output outside Git. With `ffprobe` installed,
run the read-only audit against the verified media host:

```sh
python3 cloud-run-transcoder/audit_aspect_renditions.py \
  --hash-file /path/to/hashes.txt --media-base https://media.divine.video \
  > /path/to/aspect-audit.jsonl
```

The audit probes the original, both progressive aliases, and both HLS streams.
It selects 1280x720 or 854x480 landscape renditions whose display aspect differs
from the original by more than 1%, accounting for rotation and sample aspect
ratio. This includes square originals, not just portrait sources. It emits a
`request` object only for candidates. It never submits requests, deletes objects,
changes access, or purges caches. Probe errors are recorded and produce exit 1;
they are not evidence that a video is correct. Resolve/retry them before claiming
inventory coverage. Non-right-angle rotations require manual investigation.

## Operator-only regeneration

Confirm that the deployed transcoder supports `force` before proceeding. Normal
`POST /transcode` requests retain the existing-master shortcut. A request with
`{"hash":"<sha256>","force":true}` bypasses it, re-encodes from the original,
and replaces generated HLS derivatives without deleting the prefix first.
Forced repairs abort on an original probe failure rather than guessing 16:9,
and abort before uploading if the progressive MP4 remux fails.
Use the service's existing authenticated access route; do not put credentials
in audit files or logs. Submit only reviewed candidates, serially, and inspect
the completed response before advancing. Avoid concurrent transcodes of a hash.

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
paths after propagation; a CDN-only re-audit before purge can still see old data.

No visual UI change is included; sample request behavior changes only for the
explicit `force` option. Manual validation: audit a synthetic square original
with 16:9 derivatives, regenerate in an authorized test environment, verify all
four ratios and unchanged original bytes, then repeat without `force` and confirm
`already_exists`.
