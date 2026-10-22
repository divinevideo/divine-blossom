# GCS to B2 media cutover

Approved scope: archive and Blossom media, Bunny delivery, staged cutover,
temporary GCS coordination for Blossom, and compatibility for published Google
URLs. This is an implementation sequence, not authorization to destroy buckets,
change credentials, merge PRs, or activate production configuration.

## Global constraints

- Authoritative media and approved-only CDN replicas use separate private buckets.
- Existing signed events, object keys, authentication and upload contracts survive.
- Default configuration preserves the currently deployed storage path.
- Read selection never weakens moderation; rollout flags never disable erasure.
- Backfill verifies bytes and rechecks deletion intent and mutable source versions.
- Keep account details, operational measurements and costs outside public commits.
- GCS state, backups, tracing and unrelated buckets are outside this migration.
- A production ramp requires account inventory, private signed-origin validation,
  erasure drills and a measured rollback. No unverified provider is activated.

## Task 1: Archive coordination and diagnostics

Add an explicitly selected Postgres backend for the existing archive budget CAS
interface, using the existing database and preserving all rate and lease limits.
Use generation-checked writes and fail closed on database failure. Add bounded,
jittered polling. Keep the legacy backend the default until all workers can be
drained together. Supply a read-only aggregate inventory and request diagnostic.

Test missing/stale state, competing writers, retries, database failure, backend
selection, and deadlines. Run the archive test suite with external integrations
excluded. Expected: existing limits and lease tests still pass; new backends do
not call GCS when selected. Document coordinated switch and rollback.

## Task 2: Private storage infrastructure and provider interfaces

Add importable B2 bucket infrastructure and separate media/coordination settings.
Define provider-neutral object references and GCS/B2 storage adapters. Require
explicit destination identity; preserve types, owner/provenance and checksums.
Keep default reads and writes on GCS. Do not grant CDN access to authority.

Validate provider configuration, request signing and unchanged GCS defaults.
Expected: existing operations pass and B2 requests use configured region/host.

## Task 3: Verified backfill and delivery

Implement bounded, resumable manifests and copy verification for archive and
Blossom assets. Use an explicit transfer-byte ceiling and strict public-delivery
allowlist. Preserve archive paths and map Blossom public rendition paths. Add
B2-first reads with policy-gated GCS fallback, independent of write selection.
Replicate only approved material and mark readiness only after verification.
Use owned hostnames; initially validate Standard globally, keeping existing
Volume resources intact. Update first-party archive URL resolution without
changing signed events or retiring referenced Google objects.

Test interruption, changed versions, bad checksums, policy changes, range and
HEAD, cache metadata, and deletion races. Expected: no unverified object is
selected and denied objects cannot be restored by fallback or replication.

## Task 4: Upload and processing migration

Implement provider-pinned resumable B2 sessions with negotiated 8 MiB parts,
durable progress and whole-object hash verification in both upload services.
Drain existing GCS sessions. Move derivatives and processing I/O behind adapters;
retain low-volume GCS locks. Dispatch finalization durably with authenticated,
idempotent jobs instead of depending on GCS events. Adapt Vision to image bytes.
Migrate archive writers, publisher tools and moderation fallback callers.

Test restart, duplicate chunks, cancellation, expiry, corrupt content, duplicate
jobs and stale status updates. Expected: public responses remain compatible and
newly stored B2 media is readable throughout rollback.

## Task 5: Erasure, rollout and retirement

Extend bounded cleanup to all authoritative/delivery versions and temporary
uploads. Preserve legal holds, references, tombstones, and deletion intent; purge
every configured CDN and verify absence before completion. Store cleanup on the
companion service when edge request bounds would be exceeded.

Run erasure and playback drills before rollout. Shadow for 48 hours, then ramp
independent read/delivery/write cohorts through 1/10/50/100 percent with 24 hours
at intermediate stages. Require seven stable days at full B2 traffic before
disabling routine GCS fallback. Keep removable GCS media for 30 days; referenced
Google URLs remain supported. Retain B2-capable readers during rollback.

Expected: tests and required CI pass, every remaining GCS caller is documented,
and actual combined delivery/storage/processing cost is measured privately.
