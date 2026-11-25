# Derived media on B2

This source capability lets canonical thumbnail, optimized MP4/HLS, WebVTT and
sound-analysis reads select B2. It does not activate a provider, migrate objects,
change client source selection, or establish playback parity by itself.

## Configuration

| Config-store key | Default | Values |
|---|---|---|
| derived_media_read_primary | gcs | gcs, b2 |
| derived_media_gcs_fallback_enabled | true | true, false |

These settings are independent of `media_read_primary` and `gcs_fallback_enabled`,
which govern original reads and cached audio aliases. B2 uses the existing
`b2_storage` backend, `b2_media_bucket` and `b2_media_region` configuration, and
the `b2_media_access_key` and `b2_media_secret_key` secret bindings. No secret
values belong in reports.

When B2 is selected, fallback follows the existing origin adapter: object absence,
origin 5xx and transport failure may use GCS only when enabled. Configuration and
authentication failures do not fall back. Route handlers still enforce policy
before this storage boundary. Disabling fallback permits B2 reads without GCS
bucket configuration. Invalid policy values produce errors before storage I/O.

Public translated-subtitle source reads use the same selected origin but bypass
backend caching. Internal translation job records retain their current GCS writer
origin until the coordination migration; they are a documented GCS dependency.

## Provider labels

Derived storage responses overwrite any origin-supplied `X-Divine-Source` with
the selected `b2` or `gcs` transport. A B2 miss followed by GCS fallback therefore
remains labelled GCS. Optimized MP4/TS responses retain that label, and HLS and
subtitle body reconstruction preserves it on a cache miss. The existing
body-only Simple Cache does not retain provider provenance; its hits explicitly
use `unknown` rather than inferring a provider from current configuration.

These labels describe selected transport or cached fill provenance, not a new
origin read on every downstream HIT. They do not prove immutable family
readiness, current revision, B2-only coverage, byte-weighted offload or billing.
These are internal fill-provenance labels. The outer VCL strips
`X-Divine-Source` on client-facing delivery for every host, while preserving it
on shield hops for internal cache admission. This requires the separate outer
VCL validation and activation procedure in [Outer VCL](outer-vcl.md); publishing
Compute alone does not deploy the stripping rule. Follow the
[deployment order](rollback.md#choose-the-deployment-order): activate the reviewed
outer VCL first, before merging this change can publish Compute from `main`.
Rolling back the pair reverses that order, Compute first and outer VCL second.
Do not rely on a temporary public-label window: publishing Compute before the
stripping rule is active can expose a cached fill-time label on the main host,
not a fresh-read signal. No live activation is established by these source tests.

Missing labels on rebuilt responses remain unattributed, even when their body
bytes are unchanged. In particular, sound-analysis JSON is returned in a new
response without copying this label. Do not substitute a provider from hostname
or rollout flags. Body-only Simple Cache hits also lack the HLS C2PA/source
metadata; the label does not repair that separate metadata-retention limitation.

## Activation prerequisites

Verify all required artifact families, their metadata and current source versions
in the private B2 authority. Public optimized MP4 paths map to stored hash/hls
objects; copying only bare original hashes is insufficient. Confirm writers and
replication keep derived media current and erasure covers these objects and all
versions. Existing cached GCS bytes can hide an origin dependency: acceptance
requires fresh owned fixtures and verified origin reads with fallback disabled.

The canonical CDN and application cache behavior is retained. Validate cold and
warm native/web playback with normal rendition selection, range/HEAD, subtitles,
thumbnails, restart and denial. A storage helper test proves only its own boundary.
Use the complete media replacement plan for upload, processing, backfill, rollback
and final GCS retirement. Do not enable this setting based only on local tests.

## Mapped audio cutover and recovery

Cached audio aliases (`/{source_sha256}.audio.m4a`) follow the original-read
settings. Before setting `media_read_primary=b2` with
`gcs_fallback_enabled=false`, Platform must verify every audio hash referenced by
a live, permitted mapping in the private B2 serving bucket. Verify the pinned
object's SHA-256, size and MIME type, and make sure all active audio writers keep
that bucket current through cutover. The [original-video mirror](b2-original-sync.md)
skips audio. Changing the transcoder's writer also leaves historical objects where
they were. Keep fallback enabled while this coverage is incomplete.

When only B2 serves reads, a mapped object missing from B2 returns non-cacheable
HTTP 503 on GET and HEAD. Retrying only checks the serving origin again. Both
methods keep the mapping and reverse references, and neither starts extraction
for this miss. Platform handles the repair outside the edge. Use an approved
media migration to restore a verified copy from GCS or backup at the same audio
hash in the serving bucket. Recheck current source and audio policy and erasure
eligibility, preserve the original bytes and provenance, and verify the
destination version before checking the normal audio alias on a cold read.

If no verified copy remains, keep the mapping and reverse references while
Platform reviews regeneration and metadata reconciliation. A new extraction can
produce a different hash. It must never be written under the old hash or published
without reconciling its source mapping and erasure references. The general
[blob reconciliation tool](blob-reconciliation.md#classification-meanings)
excludes alias-only derived audio from missing-byte repair.

Before rolling back to GCS-primary reads, verify mapped audio in GCS as well. A
GCS-only miss still follows legacy stale-mapping cleanup. A B2-only writer can
leave GCS without a copy even when the B2 cutover was fully verified. Retain the
current serving policy until the rollback inventory is complete.

## Local verification

Run cargo check --tests --locked and cargo clippy --locked --all-targets --all-features.
Run python3 scripts/run-media-origin-tests.py with VICEROY set to an installed
executable whose path has no spaces (Cargo runner argument parsing requires it).
The runner uses loopback synthetic backends and fake credentials; it verifies
actual signed storage requests, selected bucket, preserved Range, absence of GCS
requests in B2-only mode, defaults, optional fallback and terminal errors.
