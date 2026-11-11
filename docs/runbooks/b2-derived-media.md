# Derived media on B2

This source capability lets canonical thumbnail, optimized MP4/HLS, WebVTT and
sound-analysis reads select B2. It does not activate a provider, migrate objects,
change client source selection, or establish playback parity by itself.

## Configuration

| Config-store key | Default | Values |
|---|---|---|
| derived_media_read_primary | gcs | gcs, b2 |
| derived_media_gcs_fallback_enabled | true | true, false |

These settings are independent of media_read_primary and gcs_fallback_enabled,
which previously selected only originals. B2 uses the existing b2_storage backend,
b2_media_bucket and b2_media_region configuration and secret bindings
b2_media_access_key and b2_media_secret_key. No secret values belong in reports.

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

## Local verification

Run cargo check --tests --locked and cargo clippy --locked --all-targets --all-features.
Run python3 scripts/run-media-origin-tests.py with VICEROY set to an installed
executable whose path has no spaces (Cargo runner argument parsing requires it).
The runner uses loopback synthetic backends and fake credentials; it verifies
actual signed storage requests, selected bucket, preserved Range, absence of GCS
requests in B2-only mode, defaults, optional fallback and terminal errors.
