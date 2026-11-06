# Replace GCS media storage with B2

## Acceptance contract

The maintainer's goal is to drop GCS and use B2. Normal Auto playback must retain rendition selection, MP4/HLS paths, prefetch, local caching, range/HEAD behavior, startup, loops and seeks. An original-only B2 canary is a diagnostic tool, not migration acceptance. Existing published URLs and signed events remain valid. GCS media reads and writes must be unnecessary after cutover, including failure paths and background work.

This replaces the original-only completion criterion of the November demand-mirror work. It extends the October 21 cutover plan; existing verified upload, backfill, erasure and cache work should be integrated rather than rewritten. Dropping GCS media storage does not itself require moving Cloud Run, Pub/Sub or every unrelated Google service. Any remaining GCS coordination, audit or externally referenced object is an explicit retirement blocker or documented compatibility exception, never silently called complete.

## Approach

Keep public media URLs and ordinary player source selection stable. Move storage selection behind server interfaces and migrate both originals and their complete artifact families. Stage read and write selection independently while copies are verified. This preserves old clients and signed posts. A permanently separate original-only playback path cannot meet this goal. A global flip before writers, derivatives and erasure are ready would lose availability and is rejected.

## Verified source inventory (2026-11-07)

| Surface | Current dependency | Required work |
|---|---|---|
| Canonical originals | src/storage.rs download_media_object already selects GCS/B2 and optional fallback | Exercise canonical route with GCS unavailable; preserve policy/cache semantics |
| Optimized MP4/HLS | src/storage.rs download_hls_from_gcs hardcodes GCS; src/main.rs maps public paths | Add independent derived-media origin selection; verify complete rendition family before activation |
| Thumbnails, VTT, sound analysis | download_thumbnail, download_transcript_object_from_gcs, download_sound_analysis_from_gcs hardcode GCS | Migrate reads and writers, preserve mutable-source cache bypass |
| Small uploads and audit writes | src/storage.rs upload_blob, multipart and audit helpers | B2-authoritative writes and durable metadata; audit storage explicitly accounted for |
| Companion upload | cloud-run-upload/src/main.rs and resumable.rs use GCS SDK and sessions | Provider-pinned durable multipart/resume, whole-object checksum and completion dispatch |
| Transcode/audio/subtitles | cloud-run-transcoder/src/main.rs and sound_classification.rs use GCS for source/output, metadata and locks | Storage adapter for all artifacts, manifest-last publication, independent durable job/lease state |
| Moderation/finalization | cloud-functions/process-blob/main.py receives GCS finalize events and uses gs:// Vision image inputs | Authenticated durable idempotent finalization event; moderation accepts bytes or supported B2 read boundary |
| Historical/new mirror | scripts/sync_b2_originals.py and October 28 mirror design intentionally copy originals only | Artifact inventory, source-version binding, checksum verification and reconciliation for all retained objects |
| Deletion | src/main.rs delete_blob_gcs_artifacts and src/storage.rs version cleanup | Delete every original/derived/temp version and purge every delivery cache; durable retries and anti-resurrection |
| Mobile | infinite_video_feed playback_sources.dart prepends original and bypasses disk/prefetch for canary | Use ordinary playback for acceptance; never use canary results as proof of parity |
| External producers | divine-upload-server, archive crawler/publisher and moderation tools | Audit current branches/deployments and migrate producers; no assumed coverage from Blossom alone |

Brain search identified existing upload-server PR31 (document 0DE40D6BD110E2547930C97320) with verified dual-upload support. Acceptance agent reports PR31 merged at 2efac310e3b55dd5e667a0863bb7348231930c73; production upload mode and rollout remain unverified here. The local upload-server checkout still uses GCS directly; do not infer live state from it.

## Required invariants

- B2 authority stays private; viewer policy precedes delivery, fallback and copy admission.
- Denial, erasure and configuration/auth failures cannot become availability fallback.
- Original identity remains the full SHA-256; derivative readiness includes source identity/version, artifact key, size, checksum, content type and completion generation. ETag is not a checksum.
- Publish a rendition family only after all referenced files are verified; manifest publication cannot expose missing segments. Mutable subtitles/job state require explicit invalidation or uncached reads.
- Multipart progress and finalization survive crashes. Completed bytes and durable processing intent precede upload success. Retries cannot duplicate user-visible objects or jobs.
- Copying and erasure share authoritative exclusion; a stale copier or delayed cache fill cannot resurrect denied media.
- Defaults remain compatible during implementation. Provider activation, credential changes and irreversible GCS retirement remain operator operations with a concrete reviewed rollout.

## Completion gates

1. Source inventory is exhaustive across deployed producers/readers and every remaining GCS caller has an owner and disposition.
2. B2-only isolated integration environment can upload, resume, moderate, transcode, serve all artifact types, restart processing, delete and verify absence while GCS access fails.
3. Native mobile and web ordinary Auto playback use equivalent renditions in the same build. Measure first frame, stalls, replay and seek under cold/warm CDN and local-cache conditions on the same fixtures/network; record transfer sizes and trusted origin attribution. Agree numerical non-regression budgets from measured GCS baseline before ramp.
4. Backfill inventory accounts for all retained objects and mutable generations, then a final delta catches writes during copying. No GCS fallback is used in the acceptance window.
5. Erasure and delayed-fill races pass with real provider acknowledgements. Rollback still reads B2-only uploads; reverting to a GCS-only reader is not safe rollback.
6. After a reviewed observation window, disable routine GCS fallback and writes. Retire GCS data only after compatibility references, retention, backups and recovery are accounted for; bucket deletion is a separate irreversible operation.

## First implementation boundary

Add an independently configured derived-media read policy using the existing private signed-origin adapter. Default GCS, explicit B2 selection, separately disabled fallback, no production activation. This unblocks equivalent-rendition testing and later writer/backfill integration without silently switching derivatives when the original-only flag changes. Preserve existing caller policy checks and source cache choices. Mutable internal job-state reads remain GCS until their writer/coordination migration, and must not accidentally follow public derivative selection.
