# B2 playback fallback and background migration

## Intent and selected approach

Serve media seamlessly while moving original videos from GCS to private B2. The maintainer selected immediate GCS playback with deduplicated background copying, keeping historical backfill and rollback. Copying inline was rejected because it delays playback and repeats work for popular clips; scheduled backfill alone does not prioritize requested videos.

## Read behavior

Keep published URLs and GCS upload authority. Add a disabled-by-default flag for canonical original-video read-through; do not change the reserved strict B2 canary endpoint. For a public, approved original, use independently verified readiness to read the immutable B2 version. If readiness is missing, serve GCS through the normal route and record one bounded, deduplicated migration hint. If B2 returns 404/410 for the pinned version despite existing readiness, serve GCS immediately and enqueue a repair hint identifying that observed version. The worker must verify that exact version is absent and readiness has not advanced before invalidating stale readiness/local completion and performing a new verified copy; its current ready shortcut is insufficient. A transient B2 outage may fall back to GCS without requesting another copy of an already verified version. Configuration/authentication failures remain distinguishable from an absent copy.

Moderation, independent quarantine, tombstones, account vanish and erasing gates remain authoritative before any delivery or enqueue and after origin I/O. Their denial is terminal; it never triggers fallback. Active copying may use GCS while deletion/erasing remains denied. Preserve GET, HEAD, Range, 206 and 416 semantics. No copy runs inside the playback request. Shared-cache behavior must be explicitly exercised before canonical activation; no cache may bypass revocation.

## Queue and worker

Use the existing Fastly metadata store for add-only per-hash demand hints, avoiding new playback-path cloud credentials. Hints are requests, never approval or readiness. The worker reads a bounded page, validates each full hash, checks current source generation and policy, commits work to its persistent SQLite queue before generation-conditional hint removal, then uses the existing bounded, checksum-verified copy/erasure mutex path. Duplicate reads coalesce. Queue/worker failures must not turn a successful GCS playback into an error; expose aggregate failure counters without identities. Demand, upload events and historical backfill share explicit copy/byte/spool budgets without starving one another.

## Rollout and limits

First implementation covers supported original videos under the existing 64 MiB ceiling. HLS, thumbnails, transcripts and larger originals remain on their existing GCS paths; do not call this a full storage cutover. Keep background history and upload synchronization. Activation requires exact bucket/key/erasure mapping, working runtime credentials, retained recoverable state, and synthetic production proof. Per-device canary testing precedes canonical flag activation. Disable read-through to roll reads back to GCS; retain all-version erasure while any B2 bytes remain. Never expire or blindly clear copying/erasing gates.

## Acceptance

Prove missing readiness returns GCS bytes and creates at most one hint; commit-before-removal survives restarts; approved work becomes a version-verified B2 hit; revoked/deleted content never falls back or recopies; B2 outage preserves GCS playback without upload storms; ranges/HEAD retain their contracts; copy/erase exclusion and all-version erasure hold; rollback and cache revocation work. Test locally, then with an owned approved fixture in production before broader activation.

## Builder decisions

Exact hint schema, pagination cursor, fair queue allocation, telemetry names and flag name are implementation choices. They must preserve the boundedness, policy and durable handoff contracts above. No global traffic switch is included in implementation approval.
