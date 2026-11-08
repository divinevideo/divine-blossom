# Playback revision inventory validation v1

This source-only consumer contract validates a bounded private marker against the
existing upload-service completed receipt and inspected producer plan. It does
not write a marker, fetch an object, publish readiness, select the current source,
start a worker, grant dispatch, or authorize playback. The receipt wire shape is
unchanged. The producer journal and marker publisher remain separate integration
requirements; a planned artifact is not proof that its bytes exist.

`scripts/b2_playback_revision.py` exposes
`validate_revision_inventory(receipt, attempt, marker_bytes, marker_ref, playlists)`.
Inputs are the unwrapped completed receipt and inspected planned attempt from
[the upload service](https://github.com/divinevideo/divine-upload-server), exact
marker bytes, the pinned ObjectRef used to fetch them, and the three playlist
bodies keyed by logical filename. The caller must fetch the exact receipt marker
version and exact artifact versions. A pure function cannot prove fetch origin;
supplying a matching reference does not establish provider I/O or existence.

## Marker shape

The JSON body is at most 64 KiB, UTF-8, with no duplicate members at any level,
unknown fields, non-JSON numeric constants, or bool-as-integer values. Its exact
fields are:

- `schema_version`: integer 1.
- `producer_job_id`, `pipeline_version`, `lease_generation`, `input_revision`:
  exactly the completed receipt and inspected plan identity/fences.
- `parent_sha256`, `source`, `source_size`: the exact receipt and plan values.
- `source_content_type`: bounded descriptive hint only. It is deliberately not
  compared to receipt MIME or `content_type_hint`, used as a policy grant, or
  described as a verified source probe.
- `revision_id`: the exact durable 32-lowercase-hex attempt nonce.
- `artifacts`: exactly the seven ordered planned entries below.

The receipt must be completed with a nonnull pinned manifest at
`_private/artifact-families/v1/{parent}/complete.json`. The plan must be in its
current source-defined `planned` phase. Processing identity is checked against
the existing canonical job-ID encoding. Already committed completion does not
require an unexpired processing lease. Arrival order, job IDs, nonces and opaque
versions never establish globally current source or revision ordering.

## Artifact inventory and playlist closure

Each artifact has exactly `filename`, `object`, `sha256`, `size`, `content_type`
and `metadata`. The immutable ObjectRef binds to the planned provider/bucket and
`{parent}/revisions/v1/{revision_id}/{filename}`, with a structurally valid exact
version. Versions in JSON are claims, not proof they were returned by storage.
The ordered filenames are `stream_720p.ts`, `stream_720p.mp4`, `stream_480p.ts`,
`stream_480p.mp4`, `stream_720p.m3u8`, `stream_480p.m3u8`, `master.m3u8`.

Checksums, sizes and canonical MIME must match the inspected plan. Metadata is
exactly `source-sha256={parent}`, `derivative=hls`, `hls-filename={filename}`.
Bounds remain 32 MiB per artifact, 64 MiB per family and 64 KiB per playlist.

All three supplied playlist lengths and SHA-256 digests must match both marker
and plan. The existing strict family parser then validates their exact bytes,
relative references and byte-range closure over declared TS sizes. Logical
filenames are adapted internally to that parser's legacy key dictionary;
playlist bytes and URI rules are never rewritten. TS/MP4 digests and existence
remain claims until actual bytes or trusted pinned adapter receipts are checked.

The return value is a frozen `ValidatedRevisionInventory` containing immutable
artifact inventory claims. It has no readiness or provider-verification grant.
Changing the input dictionaries afterwards cannot change accepted claims.

## Before readiness or warming

A real consumer must additionally verify pinned payload bytes and metadata,
current-source authority, parent policy and all-writer copy/erase exclusion;
recheck the completed receipt before publication; and implement durable
uncertainty/settlement. Missing, superseded, inconsistent or unavailable evidence
stays pending. Public descriptors must not expose private refs or job identities.

Only then can selected optimized MP4/HLS renditions participate in bounded
warming and parity acceptance. Warming an original or a legacy latest-key path
does not establish revision-family readiness. GCS fallback must retain its
actual provider label and cannot be reported as a verified B2 family.

## Source validation

Run `python3 -m unittest scripts.tests.test_b2_playback_revision
scripts.tests.test_b2_playback_family` from the repository root. These synthetic
checks exercise the pure contract and HLS parser; they perform no storage I/O,
prove no live family coverage and do not migrate any GCS data.
