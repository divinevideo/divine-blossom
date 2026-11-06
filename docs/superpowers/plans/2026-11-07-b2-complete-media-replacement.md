# B2 complete media replacement implementation plan

> **For agentic workers:** Use superpowers:executing-plans task by task. Checkboxes record verified completion, not intent.

**Goal:** Serve and produce all retained media on B2 with ordinary playback parity and no required GCS media access.

**Architecture:** Preserve canonical URLs and client rendition selection. Migrate storage interfaces, artifact families, durable processing and deletion before withdrawing GCS.

**Tech Stack:** Rust Fastly Compute and Cloud Run, Python processing/backfill, Flutter/native player, existing B2 adapters and CDN.

**Spec:** ../specs/2026-11-07-b2-complete-media-replacement-design.md

## Global constraints

Private authority, unchanged signed events, policy-first reads/copies, durable erasure, independent read/write rollout, no provider activation from this source branch. Reuse existing reviewed implementations. Full replacement is not complete when only the first task passes.

## Review focus

Missing segments in a published manifest; mutable VTT/job state accidentally cached or rerouted; late copies after erase; resumed uploads after writer switch; B2-only uploads lost by rollback. Each owning stage must test its failure before rollout.

## Task 1: Read equivalent derived media from the selected origin

Files: src/storage.rs; scripts/run-media-origin-tests.py; storage contract tests in src/storage.rs; docs/runbooks/b2-derived-media.md.

- [x] Extend local-backend tests: B2 derivative reads without any GCS bucket configuration, preserved range, default derivatives still GCS despite original B2 selection, explicit fallback only, auth/config fail closed, mutable job reads remain on writer origin.
- [x] Observe failures before implementing.
- [x] Add independent derived_media_read_primary and derived_media_gcs_fallback_enabled policy with default GCS and no implicit coupling to original read selection. Reuse signed fetch adapter with caller-specified MediaReadPolicy. Public thumbnail/HLS/VTT/audio-analysis reads use it; internal uncached transcript/job-state reads retain their current writer origin.
- [x] Run local synthetic origin contracts, cargo check --tests --locked and cargo clippy --locked --all-targets --all-features; review complete diff independently.
- [ ] Commit, push scoped source PR, inspect CI. Keep settings off until tasks 2/3 establish artifact availability.

## Task 2: Complete artifact replication and readiness

Files: scripts/sync_b2_originals.py, scripts/tests/test_sync_b2_originals.py and a dedicated artifact-family module/test file after mapping existing queue schema.

- [ ] Inventory canonical path mappings from src/main.rs and all transcoder outputs. Record actual source versions, metadata, bytes and references, including captions/audio/thumbnail variants.
- [ ] Add version-bound durable artifact jobs and family completion records; copy with bounded bytes, verify checksums, publish manifests last, and recheck policy/erase intent before admission.
- [ ] Test restart, partial family, changed source, corruption, deletion interleavings and fair discovery/transfer budgets. Demonstrate canonical derived routes with B2-only fixtures before production cohort selection.

## Task 3: B2-authoritative upload and processing

Files: cloud-run-upload/src/main.rs, resumable.rs, cleanup.rs; cloud-run-transcoder/src/main.rs, sound_classification.rs; cloud-functions/process-blob/main.py. Audit divine-upload-server PR31 before duplicating adapters.

- [ ] Reconcile existing provider-pinned upload implementation and tests with both deployed uploader entry points.
- [ ] Move artifact read/write/metadata interfaces behind provider selection; separate object storage from locks/job state. Preserve public upload and resume contracts.
- [ ] Persist completion intent with verified object identity before reporting success; authenticated idempotent dispatch replaces dependence on GCS finalize notifications. Adapt moderation inputs away from gs:// media.
- [ ] Test cancellation, restart, duplicate chunks/events, checksum mismatch, partial dual writes, lease expiry and processing retries. Run upload/transcoder service-local suites and processing Python tests with GCS unavailable.

## Task 4: External producers and complete erasure

Files: archive crawler/publisher and upload-server paths established by repository audit; src/storage.rs deletion helpers, src/main.rs delete_blob_gcs_artifacts, companion cleanup.rs and existing purge outbox.

- [ ] Inventory deployed producers, externally published Google URLs, audit stores and coordination objects. Migrate each or record a specific compatibility exception; do not declare those dependencies absent from an incomplete checkout scan.
- [ ] Extend bounded version enumeration/deletion to all authority/delivery/temp artifacts, retaining tombstones and legal holds; use existing durable purge outbox.
- [ ] Prove denied artifacts cannot return through fallback, caches, replayed jobs or late copies. Run real delayed-fill race and restart/retry erasure drills through the operator-owned harness.

## Task 5: Client parity, ramp and GCS withdrawal

Files: native/client QA harness and acceptance report; rollout/rollback runbooks and operator-reviewed IaC changes.

- [ ] Test ordinary mobile/web source selection with same encoded rendition on each origin; separately test real Auto selection, initial frame, loops, seeks, prefetch/cache and denial. Original-only canary is diagnostic only.
- [ ] Measure and set numeric baseline budgets before rollout; require repeated results with trusted origin correlation and zero hidden GCS fallback.
- [ ] Run all production-equivalent media workflows in a GCS-denied environment; reconcile full inventory plus final write delta.
- [ ] Operator ramps independent reads/writes after reviewed evidence, retains a B2-aware rollback, then disables GCS fallback/write access. Retire historical objects only after reviewed retention/reference/recovery evidence.

## Status

2026-11-07: Task 1 source implemented. Nine Viceroy origin contracts, two subtitle integration cases, cargo check and clippy passed (existing warnings). Independent private whole-diff review found a metadata alias regression; regression reproduced RED, fixed, then GREEN and re-reviewed clear. Source delivery/CI follows. Full migration, provider activation and client parity are not yet proven. Coordinator owns overall integration and provider changes; this branch owns Task 1 and supplies the dependency inventory.
