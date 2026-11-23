# Video delivery processing permission

HLS generation, forced HLS repair, and MP4 backfill resolve permission from
server metadata at execution time. Queue payloads and repair credentials cannot
grant permission to encode. Existing task bodies remain valid.

Set `MEDIA_PROCESSING_POLICY_URL` to the HTTPS policy endpoint base. The worker
appends the full SHA-256 hash and sends `Authorization: Bearer <WEBHOOK_SECRET>`.
A successful response must contain that exact hash and one known policy:

```json
{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy":"copy_only"}
```

`copy_only` permits HLS packaging and MP4 remux only through stream copy. The
worker attempts compatible source reuse even during forced repairs. A rejected
source returns the terminal `archive_remux_incompatible` error without modifying
the original. Ordinary queue deliveries acknowledge that result only after the
terminal status callback succeeds. Tool or probe failures remain errors; they
cannot trigger an encoder fallback under this policy.

`allow_encode` permits the existing video encoding and AAC fallback behavior.
Only authoritative server metadata may grant this value.

An unset endpoint defaults to `copy_only`. A configured endpoint that is invalid,
unreachable, slow, unauthorized, malformed, or returns another hash fails the
job for retry. Requests have a five-second deadline, do not follow redirects,
and accept at most 4 KiB of response data. Responses and credentials are not
included in errors.

MP4 aliases are optional for copy-only HLS. If audio-copy remux fails, the worker
keeps successful HLS and any existing alias, and reports unregenerated filenames
in `skipped_progressive_aliases`. This includes forced HLS repairs. MP4-only
backfill reports an error when it cannot produce the selected aliases; it never
falls back to audio encoding for copy-only media. Existing publication claims,
pinned input verification, output verification, and master-last ordering apply.

This policy covers video delivery derivatives and their audio streams. Standalone
audio extraction and transcription are separate workflows and are unchanged.

Run the worker tests with:

```sh
cargo test --manifest-path cloud-run-transcoder/Cargo.toml --locked
cargo test --manifest-path cloud-run-transcoder/Cargo.toml --locked -- --ignored
```

The ignored tests require local FFmpeg and FFprobe, including libx264. The policy
process-boundary test uses synthetic sources, preserves compressed audio packet
hashes and decoded frame hashes, counts encoder invocations, and injects an
audio-copy failure in an isolated child process.

## Upload metadata and rollout

The edge endpoint is `GET /internal/media-policy/{sha256}`. It accepts the existing
transcoder webhook bearer secret, returns only the hash and processing decision,
and never caches responses. Reads require the existing `kv_origin_read_token`
secret and `metadata_kv_store_id` configuration; local POP KV is not authoritative
for granting permission. Missing origin configuration or metadata returns 503
with Retry-After so a
queue job dispatched before upload publication retries.

New authenticated video uploads receive `video_encoding_allowed=true` unless the
request includes `X-Divine-Video-Processing: copy-only`. That header only removes
processing permission; it is not archive provenance. Existing metadata, recovered
records, and legacy records without the flag remain copy-only. Trusted archive
storage always overrides encoding permission. Generation-conditional metadata
writes preserve reductions and archive storage against stale duplicate/webhook
writes. Duplicate uploads never upgrade an existing record; a copy-only opt-out
may reduce an existing permission. This only limits processing and does not
change media ownership or playback access. The edge forwards copy-only to the
upload service, which suppresses eager HLS dispatch before metadata publication.
Copy-only HLS is packaged on demand after the restriction is committed.

The opt-out is supported on direct uploads, mirrors and resumable completion.
Resumable initiation rejects the opt-out with 400 because existing upload sessions
do not persist it; use direct PUT for copy-only ingestion. A malformed opt-out
value is rejected rather than silently treated as permission to encode.

Existing derivatives still serve normally. A missing progressive MP4 alias on
copy-only media returns 422 so clients use the original instead of repeatedly
requesting an impossible audio-remux fallback. Compatible HLS packaging remains
available, and original bytes are never replaced.

Deploy edge metadata/lookup support before configuring the policy-aware worker.
Deploy the archive publisher opt-out before resuming held archive ingestion.
Keep the archive publishing hold until the maintainer explicitly resumes it.
Worker staging and queue cutover must retain B2-only storage settings and the
current ownership-loss handling. Verify one ordinary user encode and one archive
stream-copy job through real storage and callbacks before changing worker traffic.
Standalone archive recovery conversion (including WebM/3GP), extracted audio,
subtitles, moderation, and thumbnails are outside this delivery change.
