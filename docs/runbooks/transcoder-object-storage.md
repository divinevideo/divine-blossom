# Transcoder media object storage

The transcoder's private byte adapter defaults to GCS. Explicit
`MEDIA_STORAGE_PROVIDER=b2` selects B2 for original downloads, new HLS files,
and extracted audio. This source change does not activate that setting or
change public media URLs. Derived-media readers have separate configuration.

B2 selection requires `B2_MEDIA_BUCKET`, `B2_REGION`, `B2_ACCESS_KEY_ID`, and
`B2_SECRET_ACCESS_KEY`. The private HTTPS endpoint is derived from the region;
production has no endpoint override. Redirects are disabled. Connection,
request-header/control, and body-stall timeouts are 10, 120, and 30 seconds.
Authentication, configuration, transport and verification failures do not fall
back to another provider. Only a metadata lookup returning 404 means absence.

## Byte API

`MediaStorage::configured` accepts parsed `StorageConfiguration`, an optional
GCS client, and the GCS bucket. Constructing the B2 adapter needs no GCS client.
The running service still initializes an authenticated GCS client for its
remaining coordination and compatibility operations.

- `stat(key)` resolves the current version once and returns optional metadata.
- `stat_reference(&ObjectRef)` looks up an already selected version. Consumers
  carrying an event's object identity must use this method rather than resolve
  its key again. Wrong provider/bucket and missing versions fail before I/O.
- `download_original(metadata, expected_sha256, path)` reads the selected version,
  checks its metadata, length and SHA-256, and replaces the destination only
  after verification. GCS reads refetch the selected generation's metadata and
  condition the byte GET on the observed metageneration to reject in-place
  metadata changes. The original key must equal the full lowercase SHA-256.
- `verify_sha256(metadata, expected_sha256)` verifies pinned bytes without saving
  a file.
- `put_verified(key, bytes, mime, custom_metadata, cache_control)` writes metadata
  atomically with bytes, requires an actual generation/version, then verifies
  pinned metadata and readback before returning a receipt. Content-addressed
  keys must match the bytes.

`ObjectMetadata` contains `reference: ObjectRef`, `size`, `content_type`, `custom`
and `cache_control`. `VerifiedObject` contains `object: ObjectMetadata` and the
computed lowercase `sha256`. `ObjectRef.version` is a GCS generation or B2
version ID; it is never an ETag. Version IDs must be nonempty, at most
1024 bytes, and printable ASCII so the returned version header can be
verified exactly. Spaces and punctuation are preserved and query encoded;
non-ASCII and control bytes fail closed. The unversioned `null` sentinel is
rejected. Keys can contain Unicode. A write may have reached the provider when a
later verification fails; no receipt is issued for an unconfirmed outcome.

The production HLS helper preserves `source_sha256`, `derivative=hls`,
`hls_filename`, source MIME, existing custom provenance and immutable cache
control, returning one receipt per file. Audio preserves its existing keys,
MIME and provenance; an already present shared audio object must pass pinned
SHA verification. There is no transcoder thumbnail producer; JPEG support is
covered only by generic adapter tests.

## Boundaries and validation

Receipts prove individual object bytes and metadata. They do not grant job
execution authority, establish family completeness or publish a producer
completion marker. The existing master-presence shortcut and status webhooks
retain their legacy meaning. Durable completion and family readiness require
coordinator integration before provider activation.

Mutable jobs, locks, translation state, transcription/VTT and sound analysis
remain on their existing GCS APIs. The legacy fMP4 backfill explicitly reads
and writes GCS. B2 adapter tests can run without GCS; this does not make the
whole transcoder pipeline GCS independent or complete GCS retirement.

Run the Rust service tests with
`cargo test --manifest-path cloud-run-transcoder/Cargo.toml --locked` and lint
with `cargo clippy --manifest-path cloud-run-transcoder/Cargo.toml --locked --all-targets`.
The `object_storage` loopback cases exercise B2 version pinning, exact metadata,
checksums, failures, encoded keys, production download/HLS helpers and the
default GCS multipart wire path without contacting either provider.
