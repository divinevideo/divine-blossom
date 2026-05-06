# Divine Resumable Upload Sessions Server Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the `media.divine.video` control-plane and `upload.divine.video` data-plane server support required for Divine resumable upload sessions while keeping legacy `PUT /upload` intact.

**Architecture:** Keep Fastly Compute as the Blossom control plane and make it advertise resumable capability on `HEAD /upload`, validate `POST /upload/init` and `POST /upload/{uploadId}/complete`, and write canonical blob metadata only after completion. Put the chunk state machine in `cloud-run-upload`, where a new resumable module owns session state, chunk writes, offset queries, and aborts against durable storage without exposing provider-specific semantics to the client.

**Tech Stack:** Rust, Fastly Compute, Fastly KV, Google Cloud Storage, Axum, Cloud Run, serde, cargo test

---

**Source documents:**
- `docs/protocol/blossom/2026-03-26-divine-resumable-upload-sessions-bud.md`
- `/Users/rabble/code/divine/divine-mobile/.worktrees/blossom-resumable-upload/docs/superpowers/plans/2026-03-27-blossom-resumable-upload-execution-plan.md`

**Current server shape:**
- `src/main.rs` owns `PUT /upload`, `HEAD /upload`, provenance, delete, and the proxy flow into Cloud Run.
- `cloud-run-upload/src/main.rs` owns the heavy byte ingest and derivative generation.
- `src/storage.rs` already contains multipart helpers, but nothing currently exposes resumable session APIs or persisted upload offsets.

**Open contract decisions to lock before implementation:**
- Define what `POST /upload/init` returns when the final hash already exists. Recommended: return `409` with an existing-descriptor payload or a documented `X-Reason`, and keep the client using `HEAD /upload` preflight to avoid most duplicates.
- Define whether `DELETE /upload/{uploadId}` requires Blossom auth again or accepts the short-lived session token. Recommended: accept the same scoped session token as chunk uploads.
- Pick one durable session backend for Cloud Run. Recommended inference from the current architecture: store session manifests server-side and proxy chunks into a server-owned GCS resumable upload session URI, so clients never see storage-provider details.

## Chunk 1: Protocol Types And Control-Plane Contract

### Task 1: Add resumable protocol types and error mapping at the Fastly layer

**Files:**
- Modify: `src/error.rs`
- Modify: `src/blossom.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Write the failing protocol tests**

```rust
#[test]
fn upload_requirements_advertise_resumable_extension() {
    // HEAD /upload should include X-Divine-Upload-Extensions
}

#[test]
fn complete_rejects_unknown_upload_session_with_404() {
    // POST /upload/{uploadId}/complete should map server not found to 404
}
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `cargo test upload_requirements_advertise_resumable_extension complete_rejects_unknown_upload_session_with_404`

Expected: FAIL because the Fastly service only knows legacy upload requirements and legacy error variants.

- [ ] **Step 3: Add protocol request/response types and resumable-specific status handling**

```rust
#[derive(Serialize, Deserialize)]
pub struct ResumableUploadInitRequest {
    pub sha256: String,
    pub size: u64,
    pub content_type: String,
    pub file_name: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ResumableUploadInitResponse {
    pub upload_id: String,
    pub upload_url: String,
    pub expires_at: String,
    pub chunk_size: u64,
    pub next_offset: u64,
    pub required_headers: HashMap<String, String>,
}
```

- [ ] **Step 4: Extend Fastly error handling for resumable semantics**

```rust
pub enum BlossomError {
    Conflict(String),
    Gone(String),
    RangeNotSatisfiable(String),
    UnprocessableEntity(String),
    // existing variants...
}
```

- [ ] **Step 5: Add capability headers to `HEAD /upload` without changing legacy behavior**

Run: `cargo test upload_requirements_advertise_resumable_extension`

Expected: PASS

- [ ] **Step 6: Commit the protocol-surface changes**

```bash
git add src/error.rs src/blossom.rs src/main.rs
git commit -m "feat(upload): add Divine resumable control-plane types"
```

## Chunk 2: Fastly Control Plane Endpoints

### Task 2: Implement `init` and `complete` on `media.divine.video`

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Write the failing control-plane tests**

```rust
#[test]
fn init_validates_auth_tombstone_and_declared_hash() {
    // POST /upload/init should reject bad input before touching Cloud Run
}

#[test]
fn complete_writes_blob_metadata_only_after_session_success() {
    // POST /upload/{uploadId}/complete should mirror the existing Cloud Run proxy success path
}
```

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `cargo test init_validates_auth_tombstone_and_declared_hash complete_writes_blob_metadata_only_after_session_success`

Expected: FAIL because there are no resumable control-plane routes.

- [ ] **Step 3: Add Fastly routes for `POST /upload/init` and `POST /upload/{uploadId}/complete`**

```rust
match (req.get_method(), path) {
    (&Method::POST, "/upload/init") => handle_upload_init(req),
    (&Method::POST, p) if p.starts_with("/upload/") && p.ends_with("/complete") => {
        handle_upload_complete(req, p)
    }
    _ => { /* existing routes */ }
}
```

- [ ] **Step 4: Keep `init` narrow and keep `complete` responsible for canonical publication**

```rust
fn handle_upload_init(req: Request) -> Result<Response> {
    // validate auth, validate sha/size/type, reject tombstones, proxy to Cloud Run init
}

fn handle_upload_complete(req: Request, path: &str) -> Result<Response> {
    // validate auth, proxy to Cloud Run complete, then write BlobMetadata/user refs/audit/provenance
}
```

- [ ] **Step 5: Reuse the existing metadata/provenance pipeline from `handle_cloud_run_proxy`**

Run: `cargo test init_validates_auth_tombstone_and_declared_hash complete_writes_blob_metadata_only_after_session_success`

Expected: PASS

- [ ] **Step 6: Commit the control-plane routing work**

```bash
git add src/main.rs
git commit -m "feat(upload): add resumable init and complete routes"
```

## Chunk 3: Cloud Run Session State Machine

### Task 3: Build the `upload.divine.video` data plane

**Files:**
- Create: `cloud-run-upload/src/resumable.rs`
- Modify: `cloud-run-upload/src/main.rs`

- [ ] **Step 1: Write the failing Cloud Run tests**

```rust
#[tokio::test]
async fn init_creates_session_and_returns_upload_url() {
    // POST /upload/init
}

#[tokio::test]
async fn head_session_returns_committed_offset() {
    // HEAD /sessions/{uploadId}
}

#[tokio::test]
async fn put_session_chunk_rejects_non_contiguous_ranges() {
    // PUT /sessions/{uploadId}
}
```

- [ ] **Step 2: Run the targeted Cloud Run tests to verify they fail**

Run: `cargo test --manifest-path cloud-run-upload/Cargo.toml init_creates_session_and_returns_upload_url head_session_returns_committed_offset put_session_chunk_rejects_non_contiguous_ranges`

Expected: FAIL because the Cloud Run service only exposes legacy `PUT /upload`.

- [ ] **Step 3: Add a resumable session module with durable server-owned session state**

```rust
pub struct UploadSession {
    pub upload_id: String,
    pub owner: String,
    pub final_sha256: String,
    pub declared_size: u64,
    pub content_type: String,
    pub expires_at: u64,
    pub next_offset: u64,
    pub session_token: String,
    pub backend_state: BackendSessionState,
}
```

- [ ] **Step 4: Wire new routes and required CORS surface**

```rust
.route("/upload/init", post(handle_resumable_init))
.route("/upload/:upload_id/complete", post(handle_resumable_complete))
.route("/upload/:upload_id", delete(handle_resumable_abort))
.route("/sessions/:upload_id", put(handle_session_chunk))
.route("/sessions/:upload_id", head(handle_session_head))
```

- [ ] **Step 5: Make completion produce the same metadata the legacy proxy path expects**

```rust
pub struct CompleteUploadResponse {
    pub sha256: String,
    pub size: u64,
    pub content_type: String,
    pub thumbnail_url: Option<String>,
    pub dim: Option<String>,
}
```

- [ ] **Step 6: Add expiry cleanup and abort semantics**

Run: `cargo test --manifest-path cloud-run-upload/Cargo.toml`

Expected: PASS

- [ ] **Step 7: Commit the data-plane work**

```bash
git add cloud-run-upload/src/resumable.rs cloud-run-upload/src/main.rs
git commit -m "feat(upload): add resumable session data plane"
```

## Chunk 4: Config, Docs, And Integration Coverage

### Task 4: Document and wire the deploy/runtime requirements

**Files:**
- Modify: `README.md`
- Modify: `fastly.toml.example`
- Modify: `fastly.toml.local`
- Modify: `fastly.toml.docker`

- [ ] **Step 1: Write the failing config/docs checks**

```text
- README does not mention /upload/init, /upload/{id}/complete, or upload.divine.video
- Cloud Run config does not describe session secret, TTL, or public upload host
```

- [ ] **Step 2: Update docs and config placeholders**

```toml
[setup.backends.cloud_run_upload]
description = "Cloud Run upload and resumable session service"
```

- [ ] **Step 3: Add the required runtime knobs**

```text
UPLOAD_PUBLIC_BASE_URL=https://upload.divine.video
UPLOAD_SESSION_SECRET=...
UPLOAD_SESSION_TTL_SECS=3600
```

- [ ] **Step 4: Run the full verification suite**

Run: `cargo test`

Run: `cargo test --manifest-path cloud-run-upload/Cargo.toml`

Expected: PASS

- [ ] **Step 5: Commit the deployment/docs updates**

```bash
git add README.md fastly.toml.example fastly.toml.local fastly.toml.docker
git commit -m "docs(upload): document Divine resumable upload server flow"
```

Plan complete and saved to `docs/superpowers/plans/2026-03-27-divine-resumable-upload-sessions-server.md`. Ready to execute?
