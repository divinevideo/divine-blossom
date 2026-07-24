# Durable Derivative Status Delivery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace fire-and-forget transcript/transcode callbacks with an authenticated, durable, idempotent Cloud Tasks delivery path that recovers automatically from temporary failures without retranscoding.

**Architecture:** A pure `derivative-status-core` crate owns the event, HMAC, validation, ordering, transition, and response contracts. The Fastly service adds generation-matched metadata mutation and versioned status endpoints; a small Cloud Run delivery crate owns GCS outbox, Cloud Tasks REST, Firestore REST, delivery, reconciliation, and recovery adapters. The existing transcoder publishes queue-first events and enforces authenticated admission, attempt allocation, and immutable terminal suppression.

**Tech Stack:** Rust 1.83, Fastly Compute SDK 0.11.12, Axum 0.7, GCS, Cloud Tasks REST v2, Firestore REST v1, Cloud Run, Cloud Scheduler, HMAC-SHA256, serde, reqwest, cargo-llvm-cov.

**Approved design:** `docs/superpowers/specs/2026-07-24-durable-derivative-status-delivery-design.md`

**Production boundary:** Tasks 1–14 change and verify repository code only.
Task 15 contains production repair/rollout commands and must not execute
without an explicit production deployment instruction. Task 16 is a later
source-cleanup change and cannot begin until Task 15 records fourteen stable
production days and receives separate approval.

---

## File and dependency map

Create the following focused modules:

- `derivative-status-core/`
  - `src/event.rs`: versioned event/update types and canonical bytes.
  - `src/validation.rs`: exact field matrix and bounds.
  - `src/ordering.rs`: watermark comparisons and integrity conflicts.
  - `src/transition.rs`: blob/job/mapping mutations and effect aggregation.
  - `src/auth.rs`: canonical HMAC preimages and constant-time verification.
  - `src/response.rs`: exact success/error response contracts.
  - `tests/hmac_vectors.rs`: one fixture consumed by all Rust runtimes.
- `fixtures/derivative-status-hmac-v1.json`: byte-level cross-runtime vectors.
- `src/metadata_cas.rs`: injected generation-aware Fastly KV adapter and retry loop.
- `src/derivative_status.rs`: Fastly route auth, apply orchestration, and response serialization.
- `src/derivative_rate_limit.rs`: injected Fastly ERL adapter keyed by verified signer.
- `src/subtitle_mapping.rs`: legacy/v2 mapping bridge and fail-closed write gate.
- `cloud-run-transcoder/status-delivery/`
  - `src/ports.rs`: storage, queue, clock, token, secret, and webhook interfaces.
  - `src/publisher.rs`: pending-first publication.
  - `src/gcp_auth.rs`: metadata-server access-token cache.
  - `src/gcs.rs`: pending/dead/suppression/control bucket adapters.
  - `src/cloud_tasks.rs`: deterministic CreateTask REST adapter.
  - `src/firestore.rs`: transactional attempt/preparation REST adapter.
  - `src/fastly_client.rs`: signed, bounded delivery client.
  - `src/delivery.rs`: delivery state machine.
  - `src/reconciler.rs`: lease/cursor/paginated reconciliation.
  - `src/recovery.rs`: discover/intent/prepare/apply/verify domain workflow.
  - `src/bin/status-delivery.rs`, `status-reconciler.rs`, `derivative-status-admin.rs`: thin binaries.
- `cloud-run-transcoder/src/processor_auth.rs`: route-bound HMAC middleware and verification route.
- `cloud-run-transcoder/src/processor_rate_limit.rs`: bounded per-signer verification limiter.
- `cloud-run-transcoder/src/derivative_admission.rs`: lock/preflight/attempt/suppression behavior.
- `cloud-run-transcoder/src/status_publisher.rs`: typed producer facade.
- `cloud-run-upload/src/processor_request.rs`: shared-HMAC caller.
- `src/processor_request.rs`: pure Fastly processor-request signer and retry classifier.
- `cloud-run-transcoder/deploy-derivative-status.sh`: provision/deploy declarative resources.
- `scripts/provision-derivative-fastly-resources.sh`: render/confirm Fastly controls, secret names, and ERL entitlement.
- `cloud-run-transcoder/status-delivery/Dockerfile`: small non-GPU delivery/reconciler/admin image.
- `scripts/check-derivative-status-coverage.sh`: exact coverage gate.
- `docs/runbooks/derivative-status-delivery.md`: P1 repair, rollout, rotation, pause, replay, and rollback.

Modify integration points:

- `Cargo.toml`, `Cargo.lock`, `.github/workflows/ci.yml`, `.coverage-thresholds.json`.
- `blossom-core/src/types.rs`.
- `src/lib.rs`, `src/main.rs`, `src/metadata.rs`, `src/admin.rs`.
- `fastly.toml.example`, `fastly.toml.local`, `config-store-data.json`,
  `secret-store-data.json.example` (never the ignored real secret file).
- `cloud-run-transcoder/Cargo.toml`, `Cargo.lock`, `Dockerfile`, `deploy.sh`, `src/main.rs`.
- `cloud-run-upload/Cargo.toml`, `Cargo.lock`, `Dockerfile`, `deploy.sh`, `src/main.rs`.
- `cloud-run-transcoder/backfill.sh`, `backfill-prioritized.sh`, `scripts/backfill-fmp4.sh`.

Dependency order is strict:

```text
core contracts
  -> Fastly CAS bridge and v2 mapping
  -> Fastly status endpoints
  -> delivery/publisher adapters
  -> processor and caller integration
  -> infrastructure/recovery/observability
  -> production rollout
```

The pinned Rust 1.83 toolchain cannot parse current edition-2024 generated
Google clients. Cloud Tasks and Firestore therefore use small REST adapters
with the existing metadata-server OAuth token pattern; do not upgrade the
toolchain or add `google-cloud-tasks-v2`.

---

### Task 1: Scaffold the shared contract crate and coverage command

**Files:**
- Create: `derivative-status-core/Cargo.toml`
- Create: `derivative-status-core/src/lib.rs`
- Create: `derivative-status-core/src/event.rs`
- Create: `fixtures/derivative-status-hmac-v1.json`
- Create: `scripts/check-derivative-status-coverage.sh`
- Modify: `Cargo.toml`
- Modify: `.coverage-thresholds.json`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Create the crate shell and write the failing shared-contract smoke test**

Create `derivative-status-core/Cargo.toml`:

```toml
[package]
name = "derivative-status-core"
version = "0.1.0"
edition = "2021"

[dependencies]
base64 = "0.22"
hex = "0.4"
hmac = "0.12"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
subtle = "2"
thiserror = "1"
uuid = { version = "=1.12.1", features = ["serde", "v5", "v7"] }
```

Create `derivative-status-core/src/lib.rs` with this module declaration and
test before `event.rs` exists:

```rust
pub mod event;

#[cfg(test)]
mod tests {
    use crate::event::{Derivative, StatusEvent};

    #[test]
    fn event_contract_is_versioned_and_derivative_typed() {
        let value = serde_json::json!({
            "schema_version": 1,
            "derivative": "transcode"
        });
        let error = serde_json::from_value::<StatusEvent>(value).unwrap_err();
        assert!(error.to_string().contains("missing field"));
        assert_eq!(Derivative::Transcript.as_str(), "transcript");
    }
}
```

Add `derivative-status-core` to the root workspace and run
`cargo generate-lockfile` so the RED command tests the missing implementation,
not workspace or lockfile setup. Also add it as a direct path dependency of
the root `fastly-blossom` package; Task 11's Fastly signer imports the crate
directly and must not rely on the transitive `blossom-core` dependency.

- [ ] **Step 2: Run the test and verify RED**

Run:

```bash
cargo test --manifest-path derivative-status-core/Cargo.toml --locked
```

Expected: FAIL because `event.rs` and its types do not exist.

- [ ] **Step 3: Add the Rust-1.83-compatible event skeleton**

Create `event.rs` and define `Derivative`,
`DerivativeStatus`, and the initial `StatusEvent` in `event.rs`;
derive `Serialize`, `Deserialize`, `Clone`, `Debug`, `Eq` where valid. Keep the
smoke-test wire type minimal here; Task 2 replaces it with the custom exact-key
envelope parser and applies `#[serde(deny_unknown_fields)]` only to compatible
nested structs.

Initialize `fixtures/derivative-status-hmac-v1.json` as an empty JSON array;
Task 2 replaces it with the reviewed byte vectors.

- [ ] **Step 4: Make the smoke test GREEN**

Run:

```bash
cargo test --manifest-path derivative-status-core/Cargo.toml --locked
```

Expected: PASS.

- [ ] **Step 5: Add the real coverage entrypoint**

`scripts/check-derivative-status-coverage.sh` must run:

```bash
#!/usr/bin/env bash
set -euo pipefail
cargo llvm-cov --manifest-path derivative-status-core/Cargo.toml \
  --all-targets --all-features \
  --fail-under-lines 100 --fail-under-functions 100 --fail-under-regions 100
cargo llvm-cov --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml \
  --all-targets --all-features \
  --fail-under-lines 100 --fail-under-functions 100 --fail-under-regions 100
```

Point `.coverage-thresholds.json` at this script. Add CI installation of a
pinned `cargo-llvm-cov` with
`cargo install cargo-llvm-cov --version 0.8.7 --locked`, and run the script
after both crates exist; until Task 6 creates the delivery crate, keep the
second command behind an explicit file-exists guard that Task 6 removes.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock derivative-status-core fixtures/derivative-status-hmac-v1.json scripts/check-derivative-status-coverage.sh .coverage-thresholds.json .github/workflows/ci.yml
git commit -m "feat(status): scaffold derivative status contracts"
```

---

### Task 2: Implement event validation, HMAC, ordering, and transitions

**Files:**
- Modify: `derivative-status-core/src/event.rs`
- Create: `derivative-status-core/src/auth.rs`
- Create: `derivative-status-core/src/ordering.rs`
- Create: `derivative-status-core/src/response.rs`
- Create: `derivative-status-core/src/transition.rs`
- Create: `derivative-status-core/src/validation.rs`
- Create: `derivative-status-core/tests/hmac_vectors.rs`
- Modify: `fixtures/derivative-status-hmac-v1.json`

- [ ] **Step 1: Write failing serialization and validation tests**

Cover both tagged variants and every status field matrix. Representative tests:

```rust
#[test]
fn complete_transcript_rejects_failure_fields() {
    let event = transcript_event(json!({
        "status": "complete",
        "last_attempt_at_ms": 1_784_847_001_200_u64,
        "error_code": "invalid_media"
    }));
    assert_eq!(validate_event(&event), Err(ValidationError::ForbiddenField("error_code")));
}

#[test]
fn failed_transcode_requires_terminal_and_error_code() {
    let event = transcode_event(json!({
        "status": "failed",
        "last_attempt_at_ms": 1_784_847_001_200_u64
    }));
    assert_eq!(validate_event(&event), Err(ValidationError::MissingField("error_code")));
}
```

Include bounds for 32 KiB canonical bytes, hash, UUID versions, UUID timestamp
agreement, sequence `1..=32`, attempt `1..=100`, times, dimensions, cue count,
language, safe errors, and unknown fields.

- [ ] **Step 2: Verify RED**

```bash
cargo test --manifest-path derivative-status-core/Cargo.toml --locked validation
```

Expected: FAIL because complete types/validation are absent.

- [ ] **Step 3: Implement the exact event types**

Use these domain shapes:

```rust
#[derive(Clone, Debug)]
pub struct StatusEvent {
    pub schema_version: u16,
    pub event_id: Uuid,
    pub sha256: String,
    pub operation_id: Uuid,
    pub operation_started_at_ms: u64,
    pub sequence: u8,
    pub created_at_ms: u64,
    pub attempt_epoch: Uuid,
    pub attempt_number: u8,
    pub derivative: DerivativeUpdate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "derivative", content = "update", rename_all = "lowercase")]
pub enum DerivativeUpdate {
    Transcript(TranscriptUpdate),
    Transcode(TranscodeUpdate),
}
```

Do not combine `#[serde(flatten)]` with outer
`#[serde(deny_unknown_fields)]`; Serde does not support that contract. Instead,
implement `Serialize`/`Deserialize` for `StatusEvent` through a private wire
visitor that emits and accepts the approved flat envelope with exact keys:

```text
schema_version,event_id,sha256,operation_id,operation_started_at_ms,
sequence,created_at_ms,attempt_epoch,attempt_number,derivative,update
```

The visitor rejects unknown, duplicate, and missing top-level fields before
constructing the typed `DerivativeUpdate`; the update structs retain
`#[serde(deny_unknown_fields)]`. Round-trip and negative tests assert the
literal approved JSON shape.

Define typed update structs with the exact optional fields and bounds from the
approved spec:

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptUpdate {
    pub status: DerivativeStatus,
    pub job_id: Option<String>,
    pub language: Option<String>,
    pub duration_ms: Option<u64>,
    pub cue_count: Option<u32>,
    pub transcript_confidence: Option<TranscriptConfidence>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub retry_at_ms: Option<u64>,
    pub terminal: Option<bool>,
    pub last_attempt_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptConfidence {
    pub average_token_confidence: f64,
    pub average_logprob: f64,
    pub low_confidence_token_ratio: f64,
    pub token_count: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscodeUpdate {
    pub status: DerivativeStatus,
    pub new_size: Option<u64>,
    pub display_width: Option<u32>,
    pub display_height: Option<u32>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub retry_at_ms: Option<u64>,
    pub terminal: Option<bool>,
    pub last_attempt_at_ms: u64,
}
```

`canonical_bytes()` must call one deterministic serde path and
`canonical_digest()` must hash those bytes. Define one fixed UUID namespace
constant and derive event IDs as UUIDv5 over canonical
`"<operation_uuid>:<sequence>"` ASCII bytes; test the literal expected UUID so
all producers share the same identity rule.

- [ ] **Step 4: Write and verify failing ordering/transition tests**

```rust
#[test]
fn equal_coordinates_with_different_digest_conflict() {
    let current = watermark("event-a", "digest-a", 1000, op_uuid(), 2);
    let incoming = envelope("event-a", "digest-b", 1000, current.operation_id, 2);
    assert_eq!(compare(&current, &incoming), ApplyOrder::IntegrityConflict);
}

#[test]
fn out_of_order_failures_converge_to_max_attempt() {
    let mut state = transcript_state("epoch-a", 0);
    apply_failure(&mut state, failure("epoch-a", 2)).unwrap();
    apply_failure(&mut state, failure("epoch-a", 1)).unwrap();
    assert_eq!(state.attempt_count, 2);
}

#[test]
fn mixed_duplicate_and_stale_aggregates_stale() {
    assert_eq!(
        aggregate(Effect::AlreadyApplied, Effect::Stale, Effect::NotRequired),
        Ok(Outcome::Stale)
    );
}
```

Run and expect FAIL:

```bash
cargo test --manifest-path derivative-status-core/Cargo.toml --locked ordering
cargo test --manifest-path derivative-status-core/Cargo.toml --locked transition
```

- [ ] **Step 5: Implement total order, watermarks, transitions, and responses**

Define:

```rust
pub struct DeliveryWatermark {
    pub operation_started_at_ms: u64,
    pub operation_id: Uuid,
    pub sequence: u8,
    pub event_id: Uuid,
    pub canonical_digest: String,
}

pub enum Effect { NotRequired, Applied, AlreadyApplied, Stale }
pub enum Outcome { Applied, Duplicate, Stale }
pub enum ApplyOrder { Newer, Duplicate, Stale, IntegrityConflict }
```

Implement separate transcript/transcode blob transitions, subtitle-job
transition, mapping transition, matching-epoch `max(attempt_number)`, terminal
and complete stale guards, and the exhaustive aggregate matrix. No transition
may read wall-clock time.

- [ ] **Step 6: Write failing HMAC vector tests**

Fixture records must contain `protocol`, `key_hex`, `method`, `path`,
`timestamp`, optional `request_id`, `raw_body_hex`, `preimage_hex`, and
`signature_hex`.

```rust
#[test]
fn every_checked_in_vector_matches_bytes_and_signature() {
    for vector in vectors() {
        assert_eq!(hex::encode(vector.preimage()), vector.preimage_hex);
        assert_eq!(vector.sign().unwrap(), vector.signature_hex);
    }
}
```

Run and expect FAIL:

```bash
cargo test --manifest-path derivative-status-core/Cargo.toml --locked --test hmac_vectors
```

- [ ] **Step 7: Implement canonical HMAC bytes and constant-time verify**

Expose:

```rust
pub fn processor_preimage(input: &ProcessorSignatureInput<'_>) -> Result<Vec<u8>, AuthError>;
pub fn status_preimage(input: &StatusSignatureInput<'_>) -> Result<Vec<u8>, AuthError>;
pub fn sign_sha256(key: &[u8], preimage: &[u8]) -> Result<String, AuthError>;
pub fn verify_sha256(key: &[u8], preimage: &[u8], signature_hex: &str) -> Result<(), AuthError>;
```

Reject leading-zero timestamps, uppercase/noncanonical UUIDs, query strings,
percent-encoded paths, duplicate slashes, trailing slash, dot segments,
invalid hex, and keys shorter than 32 bytes.

- [ ] **Step 8: Verify and commit**

```bash
cargo test --manifest-path derivative-status-core/Cargo.toml --locked
cargo clippy --manifest-path derivative-status-core/Cargo.toml --locked --all-targets --all-features -- -D warnings
git add derivative-status-core fixtures/derivative-status-hmac-v1.json Cargo.lock
git commit -m "feat(status): define durable event contracts"
```

Expected: all core tests PASS and clippy emits no warnings.

---

### Task 3: Add the Fastly generation-aware bridge

**Files:**
- Create: `src/metadata_cas.rs`
- Modify: `src/lib.rs`
- Modify: `src/metadata.rs:54-136`
- Modify: `src/metadata.rs:253-485`
- Modify: `src/main.rs`
- Modify: `src/admin.rs`
- Modify: `blossom-core/Cargo.toml`
- Modify: `blossom-core/src/types.rs:36-103`
- Modify: `blossom-core/src/types.rs:342-367`

- [ ] **Step 1: Write failing adapter-level CAS tests**

The pure adapter test must model value plus `u64` generation:

```rust
#[test]
fn conflict_reloads_and_preserves_unrelated_fields() {
    let kv = FakeKv::with_conflict_once(blob_fixture());
    mutate_with_retry(&kv, "blob:abc", |mut blob| {
        blob.transcript_status = Some(TranscriptStatus::Processing);
        Ok(blob)
    }).unwrap();
    assert_eq!(kv.writes(), 2);
    assert_eq!(kv.current().status, BlobStatus::Restricted);
}
```

Also test create-only generation zero, missing values, five-conflict
exhaustion, and cache purge only after successful durable write.

- [ ] **Step 2: Verify RED**

```bash
cargo test -p fastly-blossom --locked --lib metadata_cas
```

Expected: FAIL because `metadata_cas` is absent.

- [ ] **Step 3: Implement the injected CAS helper**

Use `LookupResponse::current_generation()`; never use deprecated
`generation()`. The runtime write must be:

```rust
store
    .build_insert()
    .if_generation_match(generation)
    .execute(key, serialized)
```

Define and inject:

```rust
pub struct VersionedValue {
    pub bytes: Vec<u8>,
    pub generation: u64,
}

pub trait VersionedKv {
    fn read(&self, key: &str) -> Result<Option<VersionedValue>>;
    fn compare_and_swap(&self, key: &str, generation: u64, bytes: &[u8]) -> Result<()>;
    fn create(&self, key: &str, bytes: &[u8]) -> Result<()>;
}

pub fn mutate_with_retry<T, F>(
    store: &impl VersionedKv,
    key: &str,
    mutate: F,
) -> Result<T>
where
    T: Serialize + DeserializeOwned,
    F: FnMut(T) -> Result<T>;
```

Keep the raw unconditional insert private so inventory tests can reject new
full-record writers.

- [ ] **Step 4: Add serde-defaulted bridge fields**

Add optional transcript/transcode `DeliveryWatermark` plus attempt epoch fields
to `BlobMetadata`, transcript watermark/epoch to `SubtitleJob`, all with
`#[serde(default, skip_serializing_if = "Option::is_none")]`. Update every
literal fixture in `blossom-core`, `src/main.rs`, and `src/admin.rs`. Add the
path dependency on `derivative-status-core` to
`blossom-core/Cargo.toml`; keep the dependency one-way (the core contract crate
must not depend on `blossom-core`).

- [ ] **Step 5: Migrate every existing full-record mutation**

Replace `get_blob_metadata` + `put_blob_metadata` and job equivalents with
`mutate_existing`. Add an inventory test that scans `src/*.rs` and permits
`KVStore::insert` only in explicitly listed non-full-record helpers and
`metadata_cas.rs`.

- [ ] **Step 6: Verify bridge compatibility**

```bash
cargo test -p blossom-core --locked
cargo test -p fastly-blossom --locked --lib
cargo check --tests --locked
```

Expected: PASS, including deserialize/serialize round trips of legacy records
without watermark fields.

- [ ] **Step 7: Commit**

```bash
git add blossom-core/Cargo.toml blossom-core/src/types.rs src/lib.rs src/metadata.rs src/metadata_cas.rs src/main.rs src/admin.rs Cargo.lock
git commit -m "refactor(metadata): add generation-aware writes"
```

---

### Task 4: Implement the v2 subtitle mapping and fail-closed freeze

**Files:**
- Create: `src/subtitle_mapping.rs`
- Modify: `src/lib.rs`
- Modify: `src/metadata.rs:42-47`
- Modify: `src/main.rs:1780-2090`
- Modify: `fastly.toml.local`
- Modify: `fastly.toml.example`
- Create: `operational-controls-data.json`

- [ ] **Step 1: Write failing migration and gate tests**

Cover legacy fallback, baseline sentinel, v2 preference, forced replacement,
late old-job stale behavior, missing/malformed config, conditional legacy
dual-write, paginated baseline migration, and the inventory:

```rust
#[test]
fn real_operation_always_supersedes_legacy_baseline() {
    let baseline = MappingWatermark::legacy_baseline("job-old");
    let forced = forced_mapping("job-new", 1_784_847_000_000);
    assert_eq!(decide_mapping(&baseline, &forced), MappingDecision::Apply);
}

#[test]
fn unreadable_pause_control_fails_closed() {
    assert_eq!(
        mapping_write_permission(Err(ControlError::Unavailable)),
        Err(MappingWriteError::Paused)
    );
}
```

- [ ] **Step 2: Verify RED**

```bash
cargo test -p fastly-blossom --locked --lib subtitle_mapping
```

Expected: FAIL because v2 types/helpers are absent.

- [ ] **Step 3: Implement typed v2 reads and migration**

Use `subtitle_job_map_v2:<sha256>` and keep the legacy
`subtitle_hash:<sha256>` raw string. Implement:

```rust
pub fn get_mapping(hash: &str) -> Result<Option<ResolvedSubtitleMapping>>;
pub fn initialize_legacy_baseline(hash: &str, job_id: &str) -> Result<TypedSubtitleMapping>;
pub fn mutate_hash_job_mapping(input: MappingMutation) -> Result<MappingEffect>;
```

The baseline is timestamp 0, nil UUID, sequence 0, and its own canonical
digest. Real mutations use UUIDv7 ordering and generation match.

- [ ] **Step 4: Implement the operational control**

Open `ConfigStore::open("operational_controls")`, read
`mapping_writes_paused` on every mapping mutation, and return exact retryable
503 JSON from all route callers. Add local store binding/data with
`mapping_writes_paused=false`, `legacy_mapping_writes_enabled=true`, and
`legacy_status_endpoints_enabled=true`. Missing/malformed pause state fails
closed. The two retirement flags preserve legacy behavior until an explicit
rollout toggle.

- [ ] **Step 5: Add a bounded paginated migration endpoint**

Add an existing-admin-authenticated endpoint that lists only
`subtitle_hash:` keys, accepts `cursor` and `limit <= 100`, creates v2
baseline records with generation-match semantics, and returns the next cursor
plus migrated/already-present/conflict counts. It refuses to run unless
`mapping_writes_paused=true`. Tests cover multiple pages, retry after a
conflict, legacy/v2 parity, idempotent rerun, and no non-mapping key access.

- [ ] **Step 6: Verify and commit**

```bash
cargo test -p fastly-blossom --locked --lib subtitle_mapping
cargo check --tests --locked
git add src/subtitle_mapping.rs src/lib.rs src/metadata.rs src/main.rs fastly.toml.local fastly.toml.example operational-controls-data.json
git commit -m "feat(subtitles): add ordered v2 mapping bridge"
```

---

### Task 5: Add versioned Fastly durable-apply endpoints

**Files:**
- Create: `src/derivative_status.rs`
- Create: `src/derivative_rate_limit.rs`
- Modify: `src/lib.rs`
- Modify: `src/main.rs:150-180`
- Modify: `src/main.rs:4890-5190`
- Modify: `src/metadata.rs`
- Modify: `secret-store-data.json.example`

- [ ] **Step 1: Write failing route/auth/response tests**

Test exact paths, body limit, unknown fields, signature skew, primary/secondary
secrets, derivative/path mismatch, missing blob/job, partial effects, purges,
per-signer rate limiting, legacy endpoint controls, and exact response schema.

```rust
#[test]
fn duplicate_blob_does_not_skip_missing_job_effect() {
    let stores = fixtures::blob_duplicate_job_new();
    let response = apply_transcript(&stores, event()).unwrap();
    assert_eq!(response.blob_effect, Effect::AlreadyApplied);
    assert_eq!(response.job_effect, Effect::Applied);
    assert_eq!(response.outcome, Outcome::Applied);
}
```

- [ ] **Step 2: Verify RED**

```bash
cargo test -p fastly-blossom --locked --lib derivative_status
```

Expected: FAIL because the route module does not exist.

- [ ] **Step 3: Implement auth and verify route**

Add:

```text
POST /internal/derivative-status/v1/verify
POST /internal/derivative-status/v1/transcript
POST /internal/derivative-status/v1/transcode
```

Read only `derivative_status_secret_primary` and optional secondary from
`blossom_secrets`. The verify route must mutate nothing. Enforce exact HMAC
fixture bytes, five-minute skew, no query, duplicate-header rejection, and
32 KiB event/16 KiB response bounds.

- [ ] **Step 4: Implement the Fastly ERL boundary**

Wrap Fastly SDK 0.11.12 `RateCounter`/`Penaltybox` behind an injected
`StatusRateLimiter`. Key by the verified signer slot plus normalized route,
check it after constant-time signature verification and before JSON parsing or
KV work, and return bounded 429 with `Retry-After: 120`. Use
`ERL::check_rate` with
`RateWindow::TenSecs`, limit 40 requests/second, and a 120-second penalty
(Fastly's effective minimum);
the queue's 20 requests/second ceiling stays below that safety boundary. The
verify endpoint and both status endpoints use the same policy with distinct
route keys. Unit tests use a fake limiter; Task 12 links the Config Store and
verifies Fastly Edge Rate Limiting entitlement before any route deploy.
Limiter errors fail closed with bounded retryable 503, so Cloud Tasks retains
the event; only a confirmed limit returns 429.

- [ ] **Step 5: Implement independently watermarked durable effects**

Apply blob, optional job, optional mapping, and cache purge separately. Return
200 only when every required effect and purge succeeds. Return exact retryable
409 errors for metadata/job not ready and conflict exhaustion; return
event-bound 400 only for `validation_failed`.

- [ ] **Step 6: Add controlled legacy endpoint retirement**

Guard only `/admin/transcript-status` and `/admin/transcode-status` with
`legacy_status_endpoints_enabled`; default local/setup state remains true for
the compatibility window. False returns 410 without accepting either legacy
or new credentials. Missing/unreadable operational controls fail closed after
Task 12's deployment preflight has proven the store is linked.

- [ ] **Step 7: Verify legacy isolation and commit**

```bash
cargo test -p fastly-blossom --locked --lib
cargo check --tests --locked
git add src/derivative_status.rs src/derivative_rate_limit.rs src/lib.rs src/main.rs src/metadata.rs secret-store-data.json.example
git commit -m "feat(status): add durable Fastly apply endpoints"
```

Expected: legacy admin routes do not accept the derivative credential and all
tests PASS.

---

### Task 6: Scaffold the delivery runtime and pending-first publisher

**Files:**
- Create: `cloud-run-transcoder/status-delivery/Cargo.toml`
- Create: `cloud-run-transcoder/status-delivery/Cargo.lock`
- Create: `cloud-run-transcoder/status-delivery/src/lib.rs`
- Create: `cloud-run-transcoder/status-delivery/src/ports.rs`
- Create: `cloud-run-transcoder/status-delivery/src/publisher.rs`
- Create: `cloud-run-transcoder/status-delivery/src/bin/derivative-status-admin.rs`
- Modify: `cloud-run-transcoder/Cargo.toml`
- Modify: `cloud-run-transcoder/Cargo.lock`

- [ ] **Step 1: Write failing publisher tests with in-memory ports**

Create the standalone crate manifest with Rust 2021 and a direct
`derivative-status-core = { path = "../../derivative-status-core" }`
dependency. Add `async-trait`, pinned UUID `=1.12.1`, serde/serde_json,
thiserror, and Tokio test/runtime features. Add these direct dependencies to
the parent transcoder:

```toml
derivative-status-core = { path = "../derivative-status-core" }
status-delivery = { path = "status-delivery" }
```

Create `lib.rs` with `pub mod ports; pub mod publisher;`, then place the
failing tests in `publisher.rs` before defining the implementation types:

```rust
#[tokio::test]
async fn pending_is_durable_before_task_creation() {
    let calls = SharedCalls::default();
    let publisher = Publisher::new(fake_outbox(calls.clone()), fake_queue(calls.clone()));
    publisher.publish(event()).await.unwrap();
    assert_eq!(calls.values(), ["create_pending", "create_task"]);
}

#[tokio::test]
async fn task_failure_returns_pending_reconciliation() {
    let publisher = Publisher::new(memory_outbox(), failing_queue());
    assert_eq!(
        publisher.publish(event()).await.unwrap(),
        Publication::PendingReconciliation
    );
}

#[tokio::test]
async fn allocation_mismatch_fails_before_pending_creation() {
    let publisher = publisher_with_allocation(stored_allocation(7), event_with_attempt(6));
    assert_eq!(publisher.publish().await.unwrap_err(), PublishError::AllocationMismatch);
    assert_eq!(publisher.outbox_creates(), 0);
}
```

- [ ] **Step 2: Verify RED**

```bash
cargo generate-lockfile --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml
cargo generate-lockfile --manifest-path cloud-run-transcoder/Cargo.toml
cargo test --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml --locked publisher
```

Expected: FAIL because the publisher types/implementation are absent, not
because a manifest, path dependency, or lockfile is missing.

- [ ] **Step 3: Define narrow async ports**

Use `async-trait` and exact result types:

```rust
#[async_trait]
pub trait PendingStore {
    async fn create(&self, event: &CanonicalEvent) -> Result<CreateOutcome, StoreError>;
    async fn read(&self, event_id: Uuid) -> Result<Option<StoredEvent>, StoreError>;
    async fn delete_generation(&self, event_id: Uuid, generation: i64) -> Result<(), StoreError>;
}

#[async_trait]
pub trait TaskQueue {
    async fn create(&self, event_id: Uuid) -> Result<TaskCreate, QueueError>;
}
```

Also define `DeadStore`, `SuppressionStore`, `ControlStore`, `AttemptStore`,
`SecretProvider`, `WebhookClient`, `TokenProvider`, `Clock`, and `IdGenerator`.
Create the admin binary now as a thin command parser with no mutating
subcommands; later tasks add commands without forward-referencing a missing
target.

- [ ] **Step 4: Implement publication state machine**

Validate/canonicalize first, fetch the persisted allocation by operation ID,
and reject any attempt epoch/ordinal mismatch before touching the outbox.
Then create pending with create-only semantics, compare bytes on conflict, and
create the deterministic task with bounded retry. Pending success plus task
failure returns `PendingReconciliation`; pending failure is an error. Processor
and recovery publishers both use this same path. Only a confirmed new task
creation returns `Queued`; Cloud Tasks `AlreadyExists` returns
`PendingReconciliation` because the name may be an active task or a 24-hour
tombstone. Tests lock this truthful response distinction.

- [ ] **Step 5: Remove the initial coverage guard and commit**

```bash
cargo test --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml --locked
git add cloud-run-transcoder/status-delivery cloud-run-transcoder/Cargo.toml cloud-run-transcoder/Cargo.lock scripts/check-derivative-status-coverage.sh
git commit -m "feat(status): add pending-first publisher"
```

---

### Task 7: Implement GCS, Cloud Tasks, and Firestore REST adapters

**Files:**
- Create: `cloud-run-transcoder/status-delivery/src/gcp_auth.rs`
- Create: `cloud-run-transcoder/status-delivery/src/gcs.rs`
- Create: `cloud-run-transcoder/status-delivery/src/cloud_tasks.rs`
- Create: `cloud-run-transcoder/status-delivery/src/firestore.rs`
- Modify: `cloud-run-transcoder/status-delivery/src/lib.rs`
- Modify: `cloud-run-transcoder/status-delivery/Cargo.toml`
- Modify: `cloud-run-transcoder/src/main.rs:2494-2645`

- [ ] **Step 1: Write failing HTTP-contract tests**

Use a local Axum/wiremock server to assert:

```rust
#[tokio::test]
async fn create_task_uses_deterministic_name_and_inert_url() {
    let request = capture_create_task(event_id()).await;
    assert_eq!(request.task.name, expected_task_name(event_id()));
    assert_eq!(request.task.http_request.url, "https://invalid.invalid/");
    assert!(request.task.http_request.oidc_token.is_none());
    assert_eq!(request.task.dispatch_deadline, "20s");
}
```

Add Firestore tests for begin/get/commit, transaction retry, stable operation
allocation, atomic `recovery_preparations` write, max 100, and no delete/list
API. Add GCS tests for create-only pending/suppression/dead, exact-generation
delete, list pagination, and lease/cursor generations.

- [ ] **Step 2: Verify RED**

```bash
cargo test --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml --locked adapters
```

Expected: FAIL because adapters are absent.

- [ ] **Step 3: Extract a reusable metadata-server token provider**

Move the existing access-token cache behavior from
`cloud-run-transcoder/src/main.rs:2494-2645` into `gcp_auth.rs`: 50-minute
cache, three 5-second metadata attempts, 200/400/800 ms backoff, and local
`gcloud auth print-access-token` fallback only outside Cloud Run. Update the
parent transcoder to call the shared provider for its existing Vertex/GCP
paths, preserve its provider-error classification, and move the existing cache
tests rather than duplicating two token implementations.

- [ ] **Step 4: Implement Cloud Tasks REST CreateTask**

POST to:

```text
https://cloudtasks.googleapis.com/v2/projects/{project}/locations/{location}/queues/{queue}/tasks
```

Send deterministic task name, base64 JSON `{"event_id":"..."}`, fixed inert
URL, POST, content type, and a 20-second task dispatch deadline only. Treat
HTTP 409 as `AlreadyExists`; classify 429/5xx/network as retryable and every
bounded other response explicitly.

- [ ] **Step 5: Implement Firestore transactional REST**

Use `documents:beginTransaction`, transactional document reads, and
`documents:commit`. Serialize only typed integer/string/map/null fields.
Retry ABORTED conflicts with bounded jitter. One transaction updates
`derivative_attempts/<derivative>:<sha>` and, for recovery prepare,
`recovery_preparations/<run>:<index>`.

- [ ] **Step 6: Implement GCS stores**

Use existing `google-cloud-storage = 0.17.0`; keep each bucket in its own
adapter/config field. Pending/suppression/dead creation uses generation zero;
cleanup/release uses exact generation.

- [ ] **Step 7: Verify and commit**

```bash
cargo test --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml --locked adapters
cargo clippy --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml --locked --all-targets --all-features -- -D warnings
git add cloud-run-transcoder/status-delivery cloud-run-transcoder/src/main.rs cloud-run-transcoder/Cargo.lock
git commit -m "feat(status): add Google Cloud adapters"
```

---

### Task 8: Implement the private delivery service

**Files:**
- Create: `cloud-run-transcoder/status-delivery/src/fastly_client.rs`
- Create: `cloud-run-transcoder/status-delivery/src/delivery.rs`
- Create: `cloud-run-transcoder/status-delivery/src/config.rs`
- Create: `cloud-run-transcoder/status-delivery/src/bin/status-delivery.rs`
- Create: `cloud-run-transcoder/status-delivery/Dockerfile`

- [ ] **Step 1: Write failing delivery state-machine tests**

Create one test per table row in the spec, including:

```rust
#[tokio::test]
async fn fastly_404_retains_pending_and_retries() {
    let result = worker_with_fastly(404, r#"{"error":"not_found"}"#).deliver(id()).await;
    assert_eq!(result.http_status(), 503);
    assert!(pending_exists(id()).await);
    assert!(!dead_exists(id()).await);
}

#[tokio::test]
async fn only_matching_validation_failed_moves_dead() {
    let body = format!(r#"{{"event_id":"{}","error":"validation_failed"}}"#, id());
    assert_eq!(worker_with_fastly(400, &body).deliver(id()).await.http_status(), 204);
    assert!(!pending_exists(id()).await);
    assert!(dead_exists(id()).await);
}
```

Also cover both-present cleanup, digest mismatch, unknown schema, malformed
2xx, exact effect validation, 401/403, timeouts, cleanup failure, and redirect
rejection.

- [ ] **Step 2: Verify RED**

```bash
cargo test --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml --locked delivery
```

Expected: FAIL because delivery service is absent.

- [ ] **Step 3: Implement bounded signed Fastly client**

Use one reqwest client with redirects disabled, 3-second connect/10-second
total timeout, 16 KiB response cap, fixed origin/path, current secret file read
per attempt, and exact response parser.

- [ ] **Step 4: Implement delivery orchestration and router**

Expose only health/readiness and `POST /tasks/deliver`. The task body is at
most 128 bytes and unknown fields fail. Return 204 only after validated Fastly
acceptance plus exact pending cleanup, or an already-clean state.

- [ ] **Step 5: Verify and commit**

```bash
cargo test --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml --locked delivery
docker build -f cloud-run-transcoder/status-delivery/Dockerfile .
git add cloud-run-transcoder/status-delivery
git commit -m "feat(status): add private delivery worker"
```

---

### Task 9: Implement reconciliation with durable lease and cursor

**Files:**
- Create: `cloud-run-transcoder/status-delivery/src/reconciler.rs`
- Create: `cloud-run-transcoder/status-delivery/src/bin/status-reconciler.rs`

- [ ] **Step 1: Write failing crash-boundary and pagination tests**

Cover more than one page, permanently failing first page, invalid token reset,
task tombstones, eight-minute/5,000 cap, overlapping job, exact lease release,
release race, and crash expiry.

```rust
#[tokio::test]
async fn successful_run_releases_exact_lease_generation() {
    let control = recording_control_store();
    Reconciler::new(control.clone(), pending(), queue()).run().await.unwrap();
    assert_eq!(control.deleted_generation(), Some(control.acquired_generation()));
}
```

- [ ] **Step 2: Verify RED**

```bash
cargo test --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml --locked reconciler
```

Expected: FAIL because reconciler is absent.

- [ ] **Step 3: Implement lease/cursor reconciliation**

Acquire `lease.json`, exit successfully on live lease, reclaim expired lease
with generation match, persist cursor after each page, recreate tasks for
pending older than two minutes, and release in a finally-style guard on every
normal/error return. A process abort intentionally leaves expiry recovery.

- [ ] **Step 4: Verify and commit**

```bash
cargo test --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml --locked reconciler
git add cloud-run-transcoder/status-delivery/src/reconciler.rs cloud-run-transcoder/status-delivery/src/bin/status-reconciler.rs
git commit -m "feat(status): add outbox reconciliation"
```

---

### Task 10: Authenticate processor routes and add queue-first admission

**Files:**
- Create: `cloud-run-transcoder/src/processor_auth.rs`
- Create: `cloud-run-transcoder/src/processor_rate_limit.rs`
- Create: `cloud-run-transcoder/src/derivative_admission.rs`
- Create: `cloud-run-transcoder/src/status_publisher.rs`
- Modify: `cloud-run-transcoder/src/main.rs:1-180`
- Modify: `cloud-run-transcoder/src/main.rs:650-820`
- Modify: `cloud-run-transcoder/src/main.rs:1285-1760`
- Modify: `cloud-run-transcoder/src/main.rs:5128-5359`
- Modify: `cloud-run-transcoder/Cargo.toml`
- Modify: `cloud-run-transcoder/Dockerfile`
- Modify: `cloud-run-transcoder/deploy.sh`

- [ ] **Step 1: Write failing auth and maintenance router tests**

Test unsigned/wrong/stale/duplicate headers, route/body/request-ID binding,
pre-auth body limits, replay marker ordering, exact verify response with no
mutation, primary/secondary overlap, per-signer verification rate limiting,
`dual_accept` versus `enforce` rollout modes, production-only CORS, and
maintenance 503 on all compute routes. In dual-accept, unsigned legacy
requests are accepted and counted, valid signed requests use normal replay
protection, and malformed/invalid signed requests are always rejected.

- [ ] **Step 2: Verify RED**

```bash
cargo test --manifest-path cloud-run-transcoder/Cargo.toml --locked processor_auth
```

Expected: FAIL because middleware/routes do not exist.

- [ ] **Step 3: Implement route-bound raw-body HMAC middleware**

Buffer only the route-specific limit, verify exact raw bytes before JSON,
reconstruct the request body, then create replay marker before expensive work.
Exclude health and `/internal/processor-auth/v1/verify` from replay markers,
but not from HMAC. Read verifier primary plus optional secondary; callers read
primary only. Mount verifier secrets as files and reload them for each request
so rotation does not require a worker revision; readiness fails on a missing,
empty, short, or unreadable primary. Add a bounded in-process token bucket keyed by the verified
signer slot for the low-volume verify route: burst 5 and refill 5 per minute,
checked after authentication and before JSON. Cap the key map at the two
recognized signer slots, and test refill with an injected clock. Make the sole
allowed browser origin explicit configuration and reject wildcard CORS in
production. Read `PROCESSOR_AUTH_MODE=dual_accept|enforce`; emit a
low-cardinality unsigned-caller counter in dual-accept, and reject all unsigned
compute requests in enforce. The verify route always requires valid HMAC in
both modes.

- [ ] **Step 4: Write failing admission/suppression tests**

Cover lock then suppression recheck, Firestore allocation, ordinal exhaustion,
all four permanent-input codes, transient non-suppression, suppression-first
crash, preflight reconstruction, existing artifact completion, and reviewed
epoch clear ordering.

- [ ] **Step 5: Implement admission**

Order exactly:

```text
signed request:
  verify HMAC -> create replay marker -> read suppression -> acquire hash lock
  -> re-read suppression -> allocate operation/attempt -> publish processing
  -> start compute

unsigned request while dual_accept only:
  classify/count legacy caller -> read suppression -> acquire hash lock
  -> re-read suppression -> allocate operation/attempt -> publish processing
  -> start compute
```

Unsigned dual-accept requests have no replay marker because they have no
authenticated request ID; existing per-hash locks still suppress duplicate
compute. This branch is transitional and is removed from reach when
`PROCESSOR_AUTH_MODE=enforce`.

For permanent input failure:

```text
create immutable suppression -> create pending -> create task -> return
```

Fail closed on suppression/attempt/pending failures. Instrument
`active_derivative_operations` by revision.

- [ ] **Step 6: Map publication state into processor responses**

Every accepted compute/admission response includes exactly
`"status_delivery":"queued"` when task creation succeeded or
`"status_delivery":"pending_reconciliation"` when the durable pending object
exists but task creation exhausted its bounded retry. Add route-level tests
for both values and prove neither response is returned when pending creation
failed.

- [ ] **Step 7: Replace active fire-and-forget dispatch**

Route
pending, processing, complete, and failed transitions through one typed
`StatusPublisher`. Terminal persistence errors return 503 even after artifact
upload; existing artifacts publish complete without recompute. Retain the
legacy sender implementation behind `LEGACY_STATUS_SENDER_ENABLED=false` for
the bounded rollback window, and add an inventory test proving no normal-mode
call path invokes it when false. Task 16 removes the dormant code only after
the fourteen-day production gate.

- [ ] **Step 8: Add maintenance image mode and root-context build**

Read `PROCESSOR_MODE=normal|maintenance`. Maintenance initializes neither
GPU/FFmpeg nor publishers. Update Docker build context so path dependencies on
`../derivative-status-core` and `status-delivery` compile under Rust 1.83.
Deploy named revisions without automatic latest traffic.

- [ ] **Step 9: Verify and commit**

```bash
cargo test --manifest-path cloud-run-transcoder/Cargo.toml --locked
cargo clippy --manifest-path cloud-run-transcoder/Cargo.toml --locked --all-targets --all-features -- -D warnings
git add cloud-run-transcoder/src/processor_auth.rs \
  cloud-run-transcoder/src/processor_rate_limit.rs \
  cloud-run-transcoder/src/derivative_admission.rs \
  cloud-run-transcoder/src/status_publisher.rs \
  cloud-run-transcoder/src/main.rs \
  cloud-run-transcoder/Cargo.toml \
  cloud-run-transcoder/Cargo.lock \
  cloud-run-transcoder/Dockerfile \
  cloud-run-transcoder/deploy.sh
git commit -m "feat(transcoder): publish derivative status durably"
```

---

### Task 11: Sign every processor caller

**Files:**
- Create: `cloud-run-upload/src/processor_request.rs`
- Create: `src/processor_request.rs`
- Modify: `cloud-run-upload/src/main.rs:1791-1845`
- Modify: `cloud-run-upload/Cargo.toml`
- Modify: `cloud-run-upload/Dockerfile`
- Modify: `cloud-run-upload/deploy.sh`
- Modify: `src/main.rs:2700-3050`
- Modify: `src/storage.rs:1430-1505`
- Modify: `secret-store-data.json.example`
- Modify: `cloud-run-transcoder/status-delivery/src/bin/derivative-status-admin.rs`
- Modify: `cloud-run-transcoder/backfill.sh`
- Modify: `cloud-run-transcoder/backfill-prioritized.sh`
- Modify: `scripts/backfill-fmp4.sh`

- [ ] **Step 1: Write failing shared-vector caller tests**

Run the same `fixtures/derivative-status-hmac-v1.json` through upload, Fastly
pure caller helper, and admin CLI tests. Add wiremock assertions for all four
headers and exact raw JSON digest.

- [ ] **Step 2: Verify RED**

```bash
cargo test --manifest-path cloud-run-upload/Cargo.toml --locked processor_request
cargo test -p fastly-blossom --locked --lib processor_request
cargo test --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml --locked admin
```

Expected: FAIL because signing callers are absent.

- [ ] **Step 3: Implement upload and Fastly callers**

Use `derivative-status-core::auth` and canonical raw JSON bytes. Fetch only
`processor_request_secret_primary`; verifier secondary is never exposed to a
caller. Upload reads the mounted `latest` secret file for every request,
Fastly reads its Secret Store entry for every request, and the operator CLI
fetches the secret only in memory under its impersonated identity. Generate a
fresh UUIDv7/timestamp for every intentional retry. Treat
503 plus `Retry-After` as retryable and 409 replay as non-retryable for that
request ID.

- [ ] **Step 4: Implement safe operator submission**

`derivative-status-admin processor-request` reads the secret in memory,
constructs/signs/sends the request, and never prints auth headers. Backfill
scripts invoke this binary rather than handling the secret or raw curl auth.

- [ ] **Step 5: Update upload deployment/build**

Build from repo root so upload can depend on the shared crate. Mount only the
processor request signer secret, not derivative/admin credentials. Document
the primary and optional verifier-only secondary names in
`secret-store-data.json.example`; never add the ignored real secret file.

- [ ] **Step 6: Verify shell callers and commit**

```bash
cargo test --manifest-path cloud-run-upload/Cargo.toml --locked
cargo test -p fastly-blossom --locked --lib
cargo test --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml --locked
bash -n cloud-run-transcoder/backfill.sh
bash -n cloud-run-transcoder/backfill-prioritized.sh
bash -n scripts/backfill-fmp4.sh
rg -n 'derivative-status-admin processor-request' \
  cloud-run-transcoder/backfill.sh \
  cloud-run-transcoder/backfill-prioritized.sh \
  scripts/backfill-fmp4.sh
! rg -n 'processor_request_secret|X-Processor-(Timestamp|Request-Id|Signature)' \
  cloud-run-transcoder/backfill.sh \
  cloud-run-transcoder/backfill-prioritized.sh \
  scripts/backfill-fmp4.sh
git add cloud-run-upload/src/processor_request.rs \
  cloud-run-upload/src/main.rs \
  cloud-run-upload/Cargo.toml \
  cloud-run-upload/Cargo.lock \
  cloud-run-upload/Dockerfile \
  cloud-run-upload/deploy.sh \
  src/processor_request.rs \
  src/main.rs \
  src/storage.rs \
  secret-store-data.json.example \
  cloud-run-transcoder/status-delivery/src/bin/derivative-status-admin.rs \
  cloud-run-transcoder/backfill.sh \
  cloud-run-transcoder/backfill-prioritized.sh \
  scripts/backfill-fmp4.sh
git commit -m "feat(auth): sign every processor request"
```

---

### Task 12: Provision least-privilege infrastructure and deployment contracts

**Files:**
- Create: `cloud-run-transcoder/deploy-derivative-status.sh`
- Create: `cloud-run-transcoder/status-delivery/tests/deployment_contract.rs`
- Create: `scripts/provision-derivative-fastly-resources.sh`
- Modify: `cloud-run-transcoder/deploy.sh`
- Modify: `cloud-run-upload/deploy.sh`
- Modify: `README.md`

- [ ] **Step 1: Write failing rendered-config/IAM tests**

The deployment script must support `--render` with no cloud mutation. Parse
its JSON/YAML output and assert five buckets, one Firestore database, queue
ALWAYS overrides, exact retry/dispatch settings, private service/job,
scheduler, identities, and exact allow/deny matrix. The Fastly script must
also support a non-mutating `--render` whose output names the operational
Config Store, its initial entries and service link, fixed SDK rate-counter and
penalty-box names, Edge Rate Limiting entitlement preflight, and required
secret entry names without secret values.

- [ ] **Step 2: Verify RED**

```bash
cargo test --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml --locked deployment_contract
```

Expected: FAIL because render mode/resources are absent.

- [ ] **Step 3: Implement idempotent provisioning**

Create:

```text
pending-event bucket
dead-event bucket (30-day lifecycle)
processor-replay bucket (24-hour lifecycle)
terminal-suppression bucket
reconciliation-control bucket
dedicated Firestore attempt database
derivative-status-delivery queue
private delivery Cloud Run service
private reconciler Cloud Run Job
one-minute Scheduler trigger
all dedicated service identities, Secret Manager containers, and bindings
```

Queue overrides must be `ALWAYS` for HTTPS host/path, empty query, POST,
content type, OIDC identity, and audience. Task creators get no `actAs`.
Runtime IAM must omit forbidden list/delete/secret permissions.
Configure Scheduler to POST the Cloud Run v2 Job `:run` API once per minute
with an OAuth service-account token (not the task OIDC identity); its identity
gets only the target job execution permission.
Bootstrap derivative-delivery and processor-request primary/secondary
credentials only from operator-supplied files/stdin, write the matching halves
to Fastly Secret Store and Google Secret Manager, never accept secret bytes on
argv, and never print or render them. The delivery worker receives only the
derivative primary; processor callers receive only the processor primary;
verifiers receive primary plus optional secondary. Cloud Run consumes secret
versions through mounted `latest` files, not environment variables. Secret
material is exactly 64 lowercase hex characters encoding 32 random bytes with
no whitespace; every runtime decodes it before HMAC use and readiness rejects
any other form. Bootstrap uses the same validated input bytes for both writes
and never attempts to read back or print secret values.

- [ ] **Step 4: Set and verify the exact queue contract**

Render and provision:

```text
minBackoff=5s
maxBackoff=900s
maxRetryDuration=2592000s
maxAttempts=-1
maxDoublings=8
maxConcurrentDispatches=10
maxDispatchesPerSecond=20
```

The deployment-contract test parses rendered configuration and fails on any
different or omitted queue value. The adapter contract separately requires
every created task's `dispatchDeadline=20s`. `--smoke-queue-override` submits
the inert placeholder task and proves queue routing reaches the private worker
within the declared few-second path; it also inspects the live queue plus
synthetic task for all retry, deadline, concurrency, and rate values.

- [ ] **Step 5: Render/provision Fastly controls before route deployment**

`scripts/provision-derivative-fastly-resources.sh` must idempotently create or
resolve the `operational_controls` store, seed
`mapping_writes_paused=false`, `legacy_mapping_writes_enabled=true`, and
`legacy_status_endpoints_enabled=true`, and link the store to the staged
service version using the installed Fastly CLI's Config Store/resource-link
commands. Fastly Compute rate counters and penalty boxes are SDK primitives,
not CLI-created resource links: use fixed names
`derivative_status_rate_counter` and `derivative_status_penalty_box`, verify
Edge Rate Limiting entitlement/enablement before route deployment, and run a
bounded post-publish route smoke test that exercises the SDK primitive. It
prints exact service, version, store, and link IDs before requiring
`--confirm`; render and contract tests never mutate Fastly. Production rollout
must run its live preflight before publishing code that fails closed on these
bindings.

- [ ] **Step 6: Add deploy smoke subcommands without executing them**

Implement `--smoke-auth`, `--smoke-queue-override`, `--smoke-iam`,
`--pause-dispatch`, and `--resume-dispatch`. Commands print exact target
project/region/resources before requiring `--confirm`.

- [ ] **Step 7: Verify and commit**

```bash
bash -n cloud-run-transcoder/deploy-derivative-status.sh
bash -n scripts/provision-derivative-fastly-resources.sh
cargo test --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml --locked deployment_contract
git add cloud-run-transcoder/deploy-derivative-status.sh cloud-run-transcoder/status-delivery/tests/deployment_contract.rs scripts/provision-derivative-fastly-resources.sh cloud-run-transcoder/deploy.sh cloud-run-upload/deploy.sh README.md
git commit -m "ops(status): define durable delivery infrastructure"
```

---

### Task 13: Implement reviewed incident recovery and dead replay

**Files:**
- Create: `cloud-run-transcoder/status-delivery/src/recovery.rs`
- Create: `cloud-run-transcoder/status-delivery/src/suppression_clear.rs`
- Modify: `cloud-run-transcoder/status-delivery/src/bin/derivative-status-admin.rs`
- Create: `cloud-run-transcoder/status-delivery/tests/recovery_cli.rs`
- Create: `cloud-run-transcoder/status-delivery/tests/suppression_clear.rs`

- [ ] **Step 1: Write failing phase-boundary tests**

Cover non-mutating discover/intent, exact digest changes, Firestore prepare
transaction, crash after transaction, second review requirement, identical
re-prepare/apply, hundreds of hashes, eligibility exclusion, no processor
invocation, terminal suppression, dead corrective replay, paginated mapping
migration, and reviewed suppression clearing.

- [ ] **Step 2: Verify RED**

```bash
cargo test --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml --locked recovery
```

Expected: FAIL because recovery workflow is absent.

- [ ] **Step 3: Implement discover and plan-intent**

List only artifact metadata for `*/vtt/main.vtt` and `*/hls/master.m3u8`; never
read media bodies. Also accept an explicit operator-supplied canonical JSON
manifest of terminal failures derived from the sanitized structured-log/Sentry
fields; validate schema, hash, derivative, bounded safe error code/message,
evidence timestamp, duplicates, and digest, and never query raw Sentry payloads
or logs automatically. Fetch current Fastly derivative metadata, exclude
absent/deleted/ineligible entries, and emit canonical intent plus digest with
no mutation. Use the existing authenticated
`GET /admin/api/blob/<sha256>` response with an operator-supplied short-lived
admin bearer read from a file; never accept it on argv, persist it, or log it.
Tests prove 401/403/404 fail closed and that banned/deleted/ineligible metadata
is excluded. Tests also prove invalid/duplicate terminal entries are rejected
and valid entries flow through prepare/apply without artifact discovery.

- [ ] **Step 4: Implement prepare**

Require reviewed intent digest and `--confirm-prepare`. In one Firestore
transaction per entry, allocate/reuse operation/ordinal and write the known
`recovery_preparations/<run>:<index>` record. Emit exact canonical event bytes
and prepared digest; publish nothing.

- [ ] **Step 5: Implement apply/verify and dead replay**

Require reviewed prepared digest and `--confirm-apply`. Publish exact prepared
bytes through the normal outbox publisher. Dead replay creates a new corrective
operation and leaves original dead data untouched.

- [ ] **Step 6: Implement fleet mapping migration orchestration**

`derivative-status-admin mapping-migrate` requires both processor admissions
and Fastly mapping writes to be paused, walks the Task 4 admin endpoint cursor
until exhaustion, writes a canonical per-page audit record, reruns parity
inspection, and refuses authority cutover on any legacy/v2 mismatch. Tests
cover hundreds of entries, cursor resume, idempotent rerun, and a conflict
that is retried without skipping a key.

- [ ] **Step 7: Implement reviewed suppression clearing**

`suppression-clear plan` reads exactly one named suppression object plus
generation and current Firestore attempt epoch, then emits a canonical intent
and digest without mutation. `suppression-clear apply` requires the reviewed
digest and `--confirm`, transactionally rotates the attempt epoch first, then
deletes only the reviewed exact GCS generation. It emits bounded audit
evidence. A crash before delete remains suppressed; a generation mismatch or
changed Firestore state aborts. The suppression-operator identity has only
the permissions needed by this command.

- [ ] **Step 8: Verify and commit**

```bash
cargo test --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml --locked recovery
cargo test --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml --locked suppression_clear
git add cloud-run-transcoder/status-delivery/src/recovery.rs cloud-run-transcoder/status-delivery/src/suppression_clear.rs cloud-run-transcoder/status-delivery/src/bin/derivative-status-admin.rs cloud-run-transcoder/status-delivery/tests/recovery_cli.rs cloud-run-transcoder/status-delivery/tests/suppression_clear.rs
git commit -m "feat(status): add reviewed incident recovery"
```

---

### Task 14: Add observability, runbook, and full verification gates

**Files:**
- Create: `docs/runbooks/derivative-status-delivery.md`
- Modify: `cloud-run-transcoder/deploy-derivative-status.sh`
- Modify: `scripts/provision-derivative-fastly-resources.sh`
- Modify: `.github/workflows/ci.yml`
- Modify: `scripts/check-derivative-status-coverage.sh`
- Modify: `cloud-run-transcoder/src/main.rs`
- Modify: `cloud-run-transcoder/status-delivery/src/delivery.rs`
- Modify: `cloud-run-transcoder/status-delivery/src/reconciler.rs`

- [ ] **Step 1: Write failing metrics/log schema tests**

Assert low-cardinality labels only, bounded/redacted fields, distinct Sentry
fingerprints, and absence of hashes/event IDs in metric labels.

- [ ] **Step 2: Implement metrics and alert render output**

Emit enqueue/delivery/reconciliation/CAS/suppression/mapping-freeze metrics,
pending/dead age/count, convergence latency, and active-operation gauges.
Render alert policies with exact thresholds from the spec.

- [ ] **Step 3: Write the checked-in runbook**

Include exact non-secret commands, expected output, owner role, escalation,
pause impact, auto-expiring maintenance mutes, post-maintenance check, and
procedures for:

```text
current legacy-secret P1 repair
health/readiness
processor non-compute auth verification
queue and pending inspection
dispatch pause/resume
processor maintenance traffic/drain/resume
Fastly mapping freeze/probe/parity/resume
dual-secret rotation
suppression inspect/reviewed clear
dead inspect/prepare/apply replay
reconciler cursor/lease repair
recovery discover/intent/prepare/review/apply/verify
rollback floor and backlog drain
```

- [ ] **Step 4: Run the full local verification**

```bash
cargo test -p blossom-core --locked
cargo test --manifest-path derivative-status-core/Cargo.toml --locked
cargo test --manifest-path cloud-run-upload/Cargo.toml --locked
cargo test --manifest-path cloud-run-transcoder/Cargo.toml --locked
cargo test --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml --locked
cargo check --tests --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --manifest-path derivative-status-core/Cargo.toml --locked --all-targets --all-features -- -D warnings
cargo clippy --manifest-path cloud-run-upload/Cargo.toml --locked --all-targets --all-features -- -D warnings
cargo clippy --manifest-path cloud-run-transcoder/Cargo.toml --locked --all-targets --all-features -- -D warnings
cargo clippy --manifest-path cloud-run-transcoder/status-delivery/Cargo.toml --locked --all-targets --all-features -- -D warnings
bash scripts/check-derivative-status-coverage.sh
bash -n cloud-run-transcoder/deploy-derivative-status.sh
bash -n scripts/provision-derivative-fastly-resources.sh
bash -n cloud-run-transcoder/backfill.sh
bash -n cloud-run-transcoder/backfill-prioritized.sh
bash -n scripts/backfill-fmp4.sh
docker build -f cloud-run-transcoder/status-delivery/Dockerfile .
docker build -f cloud-run-transcoder/Dockerfile .
docker build -f cloud-run-upload/Dockerfile .
```

Expected: every command exits 0; coverage reports 100% lines/functions/regions
for both new crates.

- [ ] **Step 5: Commit**

```bash
git add docs/runbooks/derivative-status-delivery.md \
  cloud-run-transcoder/deploy-derivative-status.sh \
  cloud-run-transcoder/src/main.rs \
  cloud-run-transcoder/status-delivery/src/delivery.rs \
  cloud-run-transcoder/status-delivery/src/reconciler.rs \
  scripts/provision-derivative-fastly-resources.sh \
  .github/workflows/ci.yml \
  scripts/check-derivative-status-coverage.sh
git commit -m "ops(status): add monitoring and recovery runbook"
```

---

### Task 15: Production repair and staged rollout (explicit approval required)

**Files:**
- Read: `docs/runbooks/derivative-status-delivery.md`
- Read: `docs/superpowers/specs/2026-07-24-durable-derivative-status-delivery-design.md`
- No source edits during rollout.

- [ ] **Step 1: Obtain explicit production deployment approval**

Stop if the user has not explicitly authorized production secret changes,
resource provisioning, Cloud Run/Fastly deployments, traffic changes, and
incident recovery mutations.

- [ ] **Step 2: Repair the active P1 first**

Follow the runbook to align the current legacy callback secret, verify live
transcript/transcode callback success, and run audited artifact-backed
metadata repair without retranscoding.

Expected: fresh callback 2xx, rejected-callback rate reaches zero, repaired
artifact/status counts reconcile.

- [ ] **Step 3: Publish and verify the Fastly bridge floor**

Run the reviewed Fastly resource provisioner first and require live proof that
the operational control store, initial compatibility entries, service link,
required secret entries, and Edge Rate Limiting entitlement exist. From a
clean temporary worktree pinned
to the Task 4 bridge commit (before Task 5 status routes), use only:

```bash
fastly compute publish --comment "derivative status CAS bridge"
fastly purge --all --service-id pOvEEWykEbpnylqst1KTrR
```

Wait the declared propagation interval and run every mapping-route probe before
freeze/migration. Record the exact bridge commit and active Fastly version as
the rollback floor.

- [ ] **Step 4: Freeze, drain, migrate, and resume**

Deploy the fully verified processor image as a named
`PROCESSOR_MODE=maintenance` revision with zero traffic and smoke its 503
compute behavior before use. Set mapping writes paused, route Cloud Run 100%
to that named maintenance revision, wait 1,800 seconds, require every
zero/quiet signal for two minutes, run
`derivative-status-admin mapping-migrate` to cursor exhaustion, verify
legacy/v2 parity, canary unfreeze, and resume only the explicit pre-rollout
legacy normal revision. Record both revision names; never route to implicit
`latest`.

- [ ] **Step 5: Publish status routes and provision durable delivery**

From a separate clean worktree pinned to the fully verified Task 14 commit,
publish/purge the Fastly package containing the versioned status routes and
signed Fastly processor caller. Verify the status-auth non-mutating route,
legacy compatibility controls, bounded ERL behavior, and bridge behavior. Only then
provision the reviewed GCP render, deploy the private worker/reconciler, and
verify IAM, queue overrides, task deadline, retry contract, and secret
overlap.

- [ ] **Step 6: Deploy dual-accept processor auth and every signed caller**

Deploy a named queue-first processor revision with
`PROCESSOR_AUTH_MODE=dual_accept` and controlled traffic. Deploy the signed
`cloud-run-upload` revision and the full Fastly caller release, and install
the reviewed admin CLI/backfill entrypoint. Exercise
`/internal/processor-auth/v1/verify` through every real caller path with fresh
nonce/request IDs. Invalid signed requests must fail even in dual-accept.
Observe the unsigned-caller metric until every named caller is verified and
the metric remains zero for the runbook interval.

- [ ] **Step 7: Enforce processor auth and run the 24-hour canary**

Deploy a new named queue-first processor revision with
`PROCESSOR_AUTH_MODE=enforce`, canary traffic only after Step 6 is green, and
prove unsigned calls are rejected. Run one synthetic transcript and transcode
through the complete producer -> pending -> task -> worker -> Fastly path and
observe the canary for 24 hours. Do not proceed unless the report proves all
six blocking criteria:

```text
zero lost or dead events
zero unauthorized delivery acceptance
zero metadata regression
zero duplicate failure increments
p95 convergence < 30 seconds and >= 99.9% within five minutes
queue and pending depth returned to baseline
```

Any missing/unavailable criterion or threshold failure pauses rollout and
invokes the documented rollback for the faulty layer.

- [ ] **Step 8: Queue-first cutover and observation**

Repeat maintenance drain, switch 100% to the named queue-first revision, keep
the legacy sender disabled, keep legacy endpoints during the bounded
compatibility window, and observe the queue-first path.

- [ ] **Step 9: Retire legacy behavior with reversible controls**

Disable the legacy status endpoints after the required queue-first observation
gate and observe seven more days. After fourteen total stable days and a scan
proving every active mapping has v2 state, set
`legacy_mapping_writes_enabled=false`. Do not delete source in this rollout;
both changes are reversible Config Store controls and their before/after
values are recorded.

- [ ] **Step 10: Apply reviewed residual recovery**

Run discover/intent, review, prepare, review exact bytes, apply, and verify.
Never skip either digest review or use retranscoding for artifact-backed
completion.

- [ ] **Step 11: Final production evidence**

Record:

```text
zero untracked/lost events
zero unauthorized acceptance
zero duplicate counter increments
zero metadata regressions
p95 convergence < 30 seconds
>= 99.9% convergence within five minutes
queue/pending return to baseline
terminal corrupt media remains suppressed
```

Rollback only to the declared CAS-compatible bridge floor or newer.

---

### Task 16: Remove retired legacy code after the stability gate (future approval required)

**Files:**
- Modify: `cloud-run-transcoder/src/main.rs`
- Modify: `src/main.rs`
- Modify: `src/metadata.rs`
- Modify: `src/subtitle_mapping.rs`
- Modify: `docs/runbooks/derivative-status-delivery.md`

- [ ] **Step 1: Verify the irreversible cleanup gate**

Require Task 15 evidence for fourteen stable days, legacy endpoints disabled
for seven days, every active mapping represented in v2, no legacy sender
invocations, and explicit approval for a new cleanup PR. Stop on any missing
evidence.

- [ ] **Step 2: Write failing inventory tests**

Inventory tests must reject legacy webhook dispatch calls, legacy status route
registrations, and writes to `subtitle_hash:` while retaining the legacy read
fallback required for old inactive records.

- [ ] **Step 3: Remove dormant legacy implementations**

Delete the disabled sender code, legacy status handlers/routes, and legacy
mapping writes. Keep only the read fallback and documented rollback floor.

- [ ] **Step 4: Verify and commit**

```bash
cargo test --manifest-path cloud-run-transcoder/Cargo.toml --locked
cargo test -p fastly-blossom --locked --lib
cargo check --tests --locked
git add cloud-run-transcoder/src/main.rs src/main.rs src/metadata.rs src/subtitle_mapping.rs docs/runbooks/derivative-status-delivery.md
git commit -m "refactor(status): remove retired legacy delivery"
```
