# Bounded Derivative Failure Handling Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop infinite HLS/VTT retry loops for bad blobs while keeping canonical uploads non-blocking and reporting derivative failures to Sentry.

**Architecture:** Extend blob metadata with bounded derivative failure state, classify upload/transcoder failures into stable codes, and have public HLS/VTT fetch paths return terminal `422` errors after retry exhaustion. Upload and transcoder services emit Sentry events where failures originate; Fastly Blossom persists state and enforces public behavior.

**Tech Stack:** Fastly Compute Rust, Axum Rust services, Fastly KV metadata, GCS, reqwest, tracing, sentry

---

## File Map

- Modify: `src/blossom.rs`
- Modify: `src/metadata.rs`
- Modify: `src/main.rs`
- Modify: `cloud-run-upload/Cargo.toml`
- Modify: `cloud-run-upload/src/main.rs`
- Modify: `cloud-run-transcoder/Cargo.toml`
- Modify: `cloud-run-transcoder/src/main.rs`
- Modify: `README.md` only if needed after behavior changes

## Chunk 1: Fastly Retry Model

### Task 1: Add failing Fastly tests for bounded transcript retries

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Write failing tests for transcript terminal behavior**

Add unit tests around the transcript fetch decision helper for:
- failed transcript under retry cap remains retryable
- failed transcript at retry cap becomes terminal
- explicit terminal transcript failure becomes terminal immediately

- [ ] **Step 2: Run targeted tests to verify they fail**

Run: `cargo test transcript_fetch_action -- --nocapture`
Expected: compile or assertion failure because terminal retry state is not modeled yet.

- [ ] **Step 3: Add failing tests for transcode retry decisions**

Add unit tests for a new helper that will decide HLS retry behavior from transcode metadata.

- [ ] **Step 4: Run targeted tests to verify they fail**

Run: `cargo test derivative_retry -- --nocapture`
Expected: fail because helper and metadata fields do not exist yet.

## Chunk 2: Blob Metadata And Fastly Behavior

### Task 2: Extend blob metadata with bounded derivative failure state

**Files:**
- Modify: `src/blossom.rs`
- Modify: `src/metadata.rs`

- [ ] **Step 1: Add transcode and transcript attempt/terminal fields to `BlobMetadata`**

- [ ] **Step 2: Add metadata update helpers**

Implement helpers for:
- updating transcode status with failure details
- updating transcript status with failure details plus attempt counts
- classifying whether retries remain available

- [ ] **Step 3: Run Fastly tests**

Run: `cargo test metadata -- --nocapture`
Expected: pass for metadata-related tests.

### Task 3: Enforce bounded retry behavior in public HLS/VTT handlers

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Implement transcript retry decision helper**

Model:
- processing
- cooldown
- trigger
- terminal failure

- [ ] **Step 2: Implement transcode retry decision helper**

Model:
- processing
- cooldown
- trigger
- terminal failure

- [ ] **Step 3: Update public fetch handlers**

Change HLS and transcript fetches to return `422` JSON when terminal instead of re-triggering indefinitely.

- [ ] **Step 4: Run targeted tests**

Run: `cargo test transcript_fetch_action cargo test derivative_retry`
Expected: pass.

## Chunk 3: Worker Failure Reporting

### Task 4: Normalize transcode webhook failure payloads

**Files:**
- Modify: `cloud-run-transcoder/src/main.rs`

- [ ] **Step 1: Write failing tests for transcode webhook payload fields**

Cover `error_code`, `error_message`, `retry_after`, and `terminal`.

- [ ] **Step 2: Run targeted tests to verify they fail**

Run: `cargo test webhook --manifest-path cloud-run-transcoder/Cargo.toml -- --nocapture`
Expected: fail because transcode webhook payload is still too thin.

- [ ] **Step 3: Implement structured transcode failure payloads**

Mirror transcript webhook behavior and send terminal metadata for invalid media.

- [ ] **Step 4: Run targeted transcoder tests**

Run: `cargo test --manifest-path cloud-run-transcoder/Cargo.toml webhook -- --nocapture`
Expected: pass.

### Task 5: Suppress derivative dispatch for obviously invalid media without blocking upload

**Files:**
- Modify: `cloud-run-upload/src/main.rs`

- [ ] **Step 1: Write failing tests for upload-time invalid-media classification**

Cover cases where thumbnail/probe failures should mark derivatives invalid and skip dispatch.

- [ ] **Step 2: Run targeted tests to verify they fail**

Run: `cargo test --manifest-path cloud-run-upload/Cargo.toml invalid_media -- --nocapture`
Expected: fail because no such classification exists.

- [ ] **Step 3: Add upload-time invalid-media classification and response fields**

Return enough signal for Fastly to persist terminal derivative state without failing the upload itself.

- [ ] **Step 4: Run targeted upload tests**

Run: `cargo test --manifest-path cloud-run-upload/Cargo.toml invalid_media -- --nocapture`
Expected: pass.

## Chunk 4: Sentry Integration

### Task 6: Add Sentry to upload and transcoder services

**Files:**
- Modify: `cloud-run-upload/Cargo.toml`
- Modify: `cloud-run-upload/src/main.rs`
- Modify: `cloud-run-transcoder/Cargo.toml`
- Modify: `cloud-run-transcoder/src/main.rs`

- [ ] **Step 1: Add failing tests for Sentry classification helpers where practical**

Keep tests focused on event classification and fingerprint helpers rather than the Sentry SDK itself.

- [ ] **Step 2: Wire Sentry init from env**

Use `SENTRY_DSN`, `SENTRY_ENVIRONMENT`, and service-specific naming.

- [ ] **Step 3: Emit Sentry events for terminal derivative failures**

Upload:
- invalid media detected during derivative validation

Transcoder:
- terminal HLS failure
- terminal transcript failure
- retry exhaustion

- [ ] **Step 4: Run service test suites**

Run:
- `cargo test --manifest-path cloud-run-upload/Cargo.toml`
- `cargo test --manifest-path cloud-run-transcoder/Cargo.toml`

Expected: both pass.

## Chunk 5: Integration And Verification

### Task 7: Thread new upload response fields into Fastly upload metadata

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Parse upload-service derivative validity signals**

- [ ] **Step 2: Initialize metadata appropriately for invalid-but-stored blobs**

- [ ] **Step 3: Run targeted Fastly tests**

Run: `cargo test -- --nocapture`
Expected: new and existing relevant tests pass.

### Task 8: Final verification

**Files:**
- Modify: `README.md` only if behavior/API docs changed materially

- [ ] **Step 1: Run Fastly tests**

Run: `cargo test`
Expected: pass, or document any platform-specific Fastly linker limitation if only `cargo check --tests` is viable on this host.

- [ ] **Step 2: Run upload service tests**

Run: `cargo test --manifest-path cloud-run-upload/Cargo.toml`
Expected: pass.

- [ ] **Step 3: Run transcoder tests**

Run: `cargo test --manifest-path cloud-run-transcoder/Cargo.toml`
Expected: pass.

- [ ] **Step 4: Run formatting checks**

Run:
- `cargo fmt --check`
- `cargo fmt --manifest-path cloud-run-upload/Cargo.toml --check`
- `cargo fmt --manifest-path cloud-run-transcoder/Cargo.toml --check`

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/specs/2026-03-28-bounded-derivative-failure-handling-design.md \
        docs/superpowers/plans/2026-03-28-bounded-derivative-failure-handling.md \
        src/blossom.rs src/metadata.rs src/main.rs \
        cloud-run-upload/Cargo.toml cloud-run-upload/src/main.rs \
        cloud-run-transcoder/Cargo.toml cloud-run-transcoder/src/main.rs
git commit -m "feat: bound derivative retries for bad media"
```
