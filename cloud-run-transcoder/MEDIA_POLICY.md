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
