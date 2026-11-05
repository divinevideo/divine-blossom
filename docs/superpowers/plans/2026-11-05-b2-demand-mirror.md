# B2 demand mirror implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task by task.

**Goal:** Deliver approved originals from B2 or uncached GCS on the private test host, queuing bounded verified migration without delaying playback for a copy.

**Architecture:** Keep strict canary behavior by default. Typed origin outcomes select GCS fallback; add-only KV hints transfer to a durable SQLite demand queue before conditional removal. One worker shares bounded capacity across demand, uploads and history and repairs only independently confirmed missing versions under the existing erasure mutex.

**Tech stack:** Rust/Fastly, Python/SQLite, existing GCS and B2 SDK adapters.

**Spec:** ../specs/2026-11-05-b2-demand-mirror-design.md

## Global constraints

- Canonical anonymous access policy remains authoritative, including public pending originals as merged in PR #322; status is never overridden.
- Only exact configured direct host; `b2_demand_mirror_enabled` is absent/off by default. No canonical traffic activation.
- Copy ceiling 67,108,864 bytes; no copying in a playback request; all responses private/no-store.
- Actual HEAD and validated single ranges; policy and gate rechecked after each attempt. Denial is terminal.
- Hints `b2-demand:v1:{hash}` are add-only and contain no caller identity. Delete only the observed generation after durable commit.
- Retry at least 300 seconds; preserve durable queues, uncertain-PUT gates and permanent erasing gates.
- New feature implementation is authorized by the user's request to fix the audited blockers. Runtime operations remain owned by the existing deployment agent.

## Review focus

- Malformed readiness must not masquerade as missing data or trigger fallback/copy.
- A coalesced generic hint must still discover a missing remote version.
- New readiness during repair must survive an old observer's invalidation.
- Intake failures must not stop committed jobs; duplicate hints must preserve backoff.
- Shared spool pressure and byte consumption must not starve a lane.

### Task 1: Explicit origin outcomes and GCS-only fallback

**Files:** blossom-core/src/canary.rs, src/storage.rs, src/canary.rs, scripts/run-b2-canary-tests.py.

**Interfaces:** `CanaryOrigin` separates delivered response, missing and unavailable. `download_demand_gcs(hash, size, method, range)` bypasses every replica/cache. Handler emits one schema-validated add-only hint only after GCS success and final policy/gate checks.

- [ ] Add failing range/outcome and actual Viceroy delivery tests: missing readiness, missing version, outage, malformed/config denial, HEAD, 206/416, copying, oversized, revocation and deduplication.
- [ ] Implement typed outcomes, finite origin deadlines, validated ranges, flag-gated fallback and hint insertion; preserve strict mode.
- [ ] Run core and canary integration tests, check tests compile, then commit.

### Task 2: Durable demand intake and safe repair

**Files:** scripts/sync_b2_originals.py, scripts/tests/test_sync_b2_originals.py.

**Interfaces:** `FastlyKV.snapshot(key)` returns record and generation; `delete_if_generation(key,generation)` is narrowly allowlisted. `DemandHints.ingest(state,limit)` persists requests before removal. `Worker.process(key,budget,reconcile=False)` verifies remote readiness before any local completion shortcut for demand work.

- [ ] Add failing tests for SQLite restart/duplicate backoff/capacity, local HTTP pagination and conditional deletion, exact-version probes, adoption, repair under owned gate, source/policy/readiness races and uncertain PUT.
- [ ] Add restart-safe demand table and bounded prefix listing; condition every readiness invalidation; retain pending repair before invalidation; reuse verified copy path under one gate.
- [ ] Run all worker tests with real SDK dependencies and commit.

### Task 3: Fair scheduling, operator contract and delivery

**Files:** scripts/sync_b2_originals.py, scripts/tests/test_sync_b2_originals.py, docs/runbooks/b2-original-sync.md, docs/runbooks/b2-playback-canary.md, README.md.

**Interfaces:** `Worker.cycle(..., demand=None)` rotates demand/upload/history access to common budgets; `--demand-intake` enables bounded hint intake independently of edge flag.

- [ ] Add failing tests for three-lane progress, duplicate hashes, retry preservation, discovery/intake failure isolation, persisted rotation and partial-spool priority.
- [ ] Implement bounded scheduling, aggregate queue/byte/spool metrics and CLI validation. Document state recovery, cadence ownership, supported HTTP range policy and rollback.
- [ ] Run core tests, cargo check/clippy, Viceroy edge suite and script suite; inspect results.
- [ ] Obtain fresh whole-diff adversarial review, address material findings, push branch/open PR/request mapped team and inspect CI. Coordinate exact-head production acceptance with deployment owner; record any remaining live-test limits.
