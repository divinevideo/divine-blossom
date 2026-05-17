# Compilation Service Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a new Cloud Run GPU service (`cloud-run-compiler/`) that takes a Nostr list of video events (naddr or array of event ids), downloads the referenced MP4s from blossom, concatenates them with a Divine logo watermark and per-clip nip05 credits burned in, and uploads the resulting multi-aspect MP4 outputs (9:16, 1:1, 16:9) back to blossom. Async jobs with HMAC-signed webhook callbacks. NIP-98 or webhook-secret auth.

**Architecture:** New Rust crate parallel to `cloud-run-transcoder/`. Same stack: axum HTTP server on Cloud Run with NVIDIA L4 GPU, NVENC for encoding, ffprobe for probing, single Dockerfile build. Job state in Firestore (`compilation_jobs/<job_id>`). Each instance runs up to 4 jobs concurrently. Event/profile data fetched via `api.divine.video` REST API (no relay WebSocket). Source blobs downloaded from `media.divine.video`. Output MP4s uploaded to GCS bucket `divine-blossom-media`.

**Tech Stack:** Rust 1.83, axum 0.7, tokio, reqwest, google-cloud-storage, firestore (via `firestore` crate), secp256k1 + sha2 for NIP-98 verification, bech32 for naddr decoding, FFmpeg + NVENC, NVIDIA CUDA 12.2 runtime image.

**Spec:** `docs/superpowers/specs/2026-05-17-compilation-service-design.md`

---

## File Structure

**New crate:** `cloud-run-compiler/`

```
cloud-run-compiler/
├── Cargo.toml                     # crate manifest + dependency set
├── Cargo.lock                     # committed (matches transcoder pattern)
├── Dockerfile                     # multi-stage Rust → NVIDIA CUDA runtime
├── .dockerignore                  # exclude target/, .git, etc.
├── deploy.sh                      # Cloud Build + Cloud Run deploy script
├── src/
│   ├── main.rs                    # axum bootstrap, route wiring, worker spawn
│   ├── config.rs                  # Config struct + env loading + webhook-secret map parsing
│   ├── auth.rs                    # NIP-98 + webhook-secret middleware → Tenant
│   ├── rate_limit.rs              # Firestore counter check (20/hr, 100/day)
│   ├── observability.rs           # structured log macros + counter helpers
│   ├── logo.rs                    # fetch + cache divine-logo.png at startup
│   ├── webhook.rs                 # HMAC sign + deliver with retry; record on job doc
│   ├── api/
│   │   ├── mod.rs                 # axum router
│   │   ├── compile.rs             # POST /compile handler + V1 validation
│   │   ├── status.rs              # GET /compile/:id handler + 404 shape
│   │   └── admin.rs               # GET /admin/jobs, /admin/jobs/:id, /admin/tenants; POST cancel, requeue
│   ├── nostr/
│   │   ├── mod.rs                 # re-exports
│   │   ├── naddr.rs               # bech32 decode for naddr/nevent/npub
│   │   ├── api_client.rs          # api.divine.video REST: fetch event, profile, list
│   │   └── types.rs               # NostrEvent, Profile, Imeta, ListRef
│   ├── blossom/
│   │   ├── mod.rs                 # re-exports
│   │   ├── download.rs            # download blob from media.divine.video; HEAD for size
│   │   ├── moderation.rs          # check blob moderation status (call divine.video API)
│   │   └── upload.rs              # upload finished MP4 to GCS (via google-cloud-storage)
│   ├── render/
│   │   ├── mod.rs                 # render orchestrator
│   │   ├── probe.rs               # ffprobe wrapper
│   │   ├── fit.rs                 # blur-pad / center-crop / letterbox filtergraph builders
│   │   ├── overlay.rs             # logo overlay + drawtext credit chain
│   │   └── ffmpeg.rs              # NVENC command + GPU/CPU fallback execution
│   └── job/
│       ├── mod.rs                 # re-exports
│       ├── types.rs               # Job, JobStatus, JobResult, CallbackDelivery, CompileRequest schema
│       ├── store.rs               # Firestore CRUD
│       └── worker.rs              # worker loop: pick queued, run render, write result, fire webhook
├── tests/
│   ├── api_validation.rs          # V1 rejected-field matrix tests
│   ├── auth_nip98.rs              # NIP-98 verification tests with fixture events
│   ├── auth_webhook_secret.rs     # webhook secret env parsing + tenant binding
│   ├── nostr_naddr.rs             # bech32 round-trip tests
│   ├── nostr_imeta_parse.rs       # imeta tag extraction (incl. nostr-rest-api-field-mapping-gap)
│   ├── fit_filtergraph.rs         # filter string generation per fit mode
│   ├── overlay_filtergraph.rs     # logo + drawtext filter generation
│   ├── webhook_signature.rs       # HMAC sign + verify round-trip
│   └── render_smoke.rs            # tiny-fixture-clip end-to-end render (requires ffmpeg)
└── README.md                      # operator docs (only if user asks per CLAUDE.md)
```

**Responsibilities (one-line summary per file, for reviewers):**

> **Note:** The table below covers the full final layout (all chunks). Chunk 1 only creates the scaffold (`Cargo.toml`, `Cargo.lock`, `Dockerfile`, `.dockerignore`, `.gitignore`, `deploy.sh`, `src/main.rs`, `src/lib.rs`, `src/config.rs`, `tests/config.rs`). Subsequent chunks add the remaining files.

| File | Responsibility |
|------|---------------|
| `main.rs` | Wire config → axum router → worker pool. Bind port 8080. |
| `config.rs` | `Config { firestore_project, gcs_bucket, api_divine_video_url, media_divine_video_url, webhook_secrets: HashMap<String, String>, admin_pubkeys: HashSet<String>, admin_token: String, max_concurrent_jobs: usize, rate_limit_per_hour: u32, rate_limit_per_day: u32 }` |
| `auth.rs` | `Tenant { Pubkey(String) \| Secret(String) }`. axum extractor that runs NIP-98 first, falls back to webhook secret. |
| `rate_limit.rs` | Firestore atomic counter; returns `RateLimitOutcome { allowed, retry_after }`. |
| `webhook.rs` | `deliver_callback(url, payload, secret)` with 3-retry exponential backoff; updates job doc. |
| `logo.rs` | Fetch `https://media.divine.video/divine-logo.png` once at startup, cache to `/tmp/divine-logo.png`. |
| `api/compile.rs` | POST handler: validate v1 matrix, persist job to Firestore as `queued`, return `{job_id, status}`. |
| `api/status.rs` | GET handler: load job from Firestore, return JSON, 404 if missing. |
| `api/admin.rs` | Admin endpoints; auth via `COMPILER_ADMIN_PUBKEYS` or `COMPILER_ADMIN_TOKEN`. |
| `nostr/naddr.rs` | Decode `naddr1...` / `nevent1...` per NIP-19. |
| `nostr/api_client.rs` | `fetch_event(id)`, `fetch_profile(pubkey)`, `fetch_list(addr)` against `api.divine.video`. |
| `blossom/download.rs` | `download_blob(sha256) → bytes`; `head_blob(sha256) → size`. |
| `blossom/moderation.rs` | `check_blob_status(sha256) → BlobStatus { Active, Restricted, AgeRestricted }`. |
| `blossom/upload.rs` | `upload_blob(bytes) → BlobDescriptor { url, sha256, size }`. |
| `render/probe.rs` | `probe(file) → ProbeInfo { duration, dim, codec, rotation }`. |
| `render/fit.rs` | Filtergraph string builder for blur-pad / center-crop / letterbox at a target aspect. |
| `render/overlay.rs` | Build overlay chain: logo PNG → drawtext credit per clip. |
| `render/ffmpeg.rs` | Build + run NVENC command; fall back to CPU on NVENC failure. |
| `job/types.rs` | All request/response/job state types with serde derive. |
| `job/store.rs` | Firestore CRUD: `create_job`, `get_job`, `update_job`, `list_jobs_by_tenant`, etc. |
| `job/worker.rs` | Concurrent worker pool (size = `max_concurrent_jobs`). Polls Firestore. |

---

## Chunk 1: Crate scaffold and config

Goal: create the crate, get an empty axum service compiling and running locally with a /health endpoint. Establishes Cargo.toml, Dockerfile, deploy.sh, Config, and the test harness.

### Task 1.1: Create the crate skeleton

**Files:**
- Create: `cloud-run-compiler/Cargo.toml`
- Create: `cloud-run-compiler/src/main.rs`
- Create: `cloud-run-compiler/.dockerignore`
- Create: `cloud-run-compiler/.gitignore`

- [ ] **Step 1: Create `cloud-run-compiler/Cargo.toml`**

```toml
# ABOUTME: Cargo manifest for GPU video compilation Cloud Run service
# ABOUTME: Concatenates Nostr-listed videos with watermark + credits via NVENC

[package]
name = "divine-compiler"
version = "0.1.0"
edition = "2021"

[dependencies]
# Web framework
axum = { version = "0.7", features = ["http2"] }
tokio = { version = "1", features = ["full", "process"] }
tower-http = { version = "0.5", features = ["cors", "trace"] }
tower = "0.5"
hyper = { version = "1", features = ["http2", "server"] }
hyper-util = { version = "0.1", features = ["server", "http2", "tokio", "service"] }

# GCS - pinned to match transcoder (avoid edition2024 issues)
google-cloud-storage = "=0.17.0"
google-cloud-auth = "=0.12.0"
home = "=0.5.9"
base64ct = "=1.6.0"
time = "=0.3.36"

# Firestore (abdolence/firestore-rs). Verify the latest 0.4x on crates.io
# at the time of implementation and pin to whatever resolves; this version
# was the latest known stable when the plan was written.
firestore = "0.43"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Encoding / crypto
hex = "0.4"
base64 = "0.22"
sha2 = "0.10"
hmac = "0.12"
# NIP-98 uses BIP-340 schnorr over secp256k1 (XOnlyPublicKey + schnorr::Signature).
# `recovery` is ECDSA-only and unused for NIP-98.
secp256k1 = { version = "0.29", features = ["global-context", "rand", "std"] }
bech32 = "0.11"

# Async / IO
futures = "0.3"
bytes = "1"
tempfile = "3"

# HTTP client
reqwest = { version = "0.11", features = ["rustls-tls", "json"], default-features = false }

# Error handling
anyhow = "1"
thiserror = "1"

# Logging / telemetry
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
uuid = { version = "=1.12.1", features = ["v4"] }

[profile.release]
lto = true
opt-level = 3
strip = true
```

- [ ] **Step 2: Create `cloud-run-compiler/src/main.rs` with a minimal axum bootstrap**

```rust
// ABOUTME: Cloud Run service that compiles Nostr-listed videos into watermarked MP4 compilations
// ABOUTME: Async job queue, multi-aspect output, NVENC encoding, blossom upload

use axum::{routing::get, Router};
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .json()
        .init();

    let app = Router::new().route("/health", get(|| async { "ok" }));

    let port: u16 = std::env::var("PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!(?addr, "compiler service listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

- [ ] **Step 3: Create `cloud-run-compiler/.dockerignore`**

```
target/
.git/
.gitignore
*.md
tests/
```

- [ ] **Step 4: Create `cloud-run-compiler/.gitignore`**

```
/target/
*.rs.bk
```

- [ ] **Step 5: Verify it builds**

Run:
```bash
cd cloud-run-compiler && cargo check
```

Expected: compiles successfully (will download a lot of deps the first time). If a dep version conflict shows up, check the transcoder's `Cargo.lock` for the version it resolved to and pin to match.

- [ ] **Step 6: Run cargo fmt + clippy to lock style from chunk 1**

Run:
```bash
cd cloud-run-compiler && cargo fmt --check && cargo clippy --all-targets -- -D warnings
```

Expected: no formatting diffs, no clippy warnings. If formatting fails, run `cargo fmt` and re-commit.

- [ ] **Step 7: Run it and hit /health locally**

Run:
```bash
cd cloud-run-compiler && cargo run >/tmp/compiler.log 2>&1 &
SERVER_PID=$!
sleep 2 && curl -s http://localhost:8080/health
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
```

Expected: `ok`. Capturing `$!` avoids relying on `%1` job-control which is unreliable in non-interactive shells.

- [ ] **Step 8: Commit (including Cargo.lock)**

Note: the `.gitignore` only excludes `target/`, so `Cargo.lock` is intentionally committed (matches transcoder pattern for reproducible builds in Cloud Build).

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): scaffold cloud-run-compiler crate with health endpoint"
```

### Task 1.2: Dockerfile and `.dockerignore`

**Files:**
- Create: `cloud-run-compiler/Dockerfile`

- [ ] **Step 1: Create Dockerfile modeled on the transcoder's**

```dockerfile
# ABOUTME: Dockerfile for GPU video compilation Cloud Run service
# ABOUTME: NVIDIA CUDA runtime with FFmpeg NVENC + Noto fonts for credit overlays

# Build stage
FROM rust:1.83-slim-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

COPY src ./src
RUN touch src/main.rs && cargo build --release

# Runtime stage — Ubuntu 22.04 (Jammy) based CUDA runtime.
FROM nvidia/cuda:12.2.2-runtime-ubuntu22.04

WORKDIR /app

# Pin to a Ubuntu snapshot for reproducible font + ffmpeg versions.
# Base is Jammy, so we use snapshot.ubuntu.com/ubuntu (NOT snapshot.debian.org).
# To bump: change UBUNTU_SNAPSHOT and rebuild.
ARG UBUNTU_SNAPSHOT=20260501T000000Z
RUN if [ -n "${UBUNTU_SNAPSHOT}" ]; then \
      sed -i "s|http://archive.ubuntu.com/ubuntu|https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}|g; s|http://security.ubuntu.com/ubuntu|https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}|g" \
        /etc/apt/sources.list; \
    fi

RUN apt-get update && apt-get install -y \
    ca-certificates \
    ffmpeg \
    fonts-noto-core \
    fonts-noto-cjk \
    fonts-noto-extra \
    fontconfig \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/divine-compiler /app/divine-compiler

ENV PORT=8080
ENV NVIDIA_VISIBLE_DEVICES=all
ENV NVIDIA_DRIVER_CAPABILITIES=compute,video,utility

CMD ["/app/divine-compiler"]
```

- [ ] **Step 2: Verify build context is clean**

Run:
```bash
cd cloud-run-compiler && du -sh . --exclude=target
```

Expected: under 1 MB (no stray fixtures/binaries committed).

- [ ] **Step 3: Commit**

```bash
git add cloud-run-compiler/Dockerfile
git commit -m "feat(compiler): add Dockerfile with NVIDIA CUDA + ffmpeg + Noto fonts"
```

### Task 1.3: Config struct and env loading

**Files:**
- Create: `cloud-run-compiler/src/config.rs`
- Modify: `cloud-run-compiler/src/main.rs`
- Create: `cloud-run-compiler/tests/config.rs`

- [ ] **Step 1: Write the failing test**

Create `cloud-run-compiler/tests/config.rs`:

```rust
use divine_compiler::config::Config;
use std::collections::HashMap;

fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

#[test]
fn loads_defaults_when_only_required_vars_set() {
    let cfg = Config::from_env(&env(&[
        ("FIRESTORE_PROJECT", "rich-compiler-479518-d2"),
        ("GCS_BUCKET", "divine-blossom-media"),
    ]))
    .expect("config should load");

    assert_eq!(cfg.firestore_project, "rich-compiler-479518-d2");
    assert_eq!(cfg.gcs_bucket, "divine-blossom-media");
    assert_eq!(cfg.api_divine_video_url, "https://api.divine.video");
    assert_eq!(cfg.media_divine_video_url, "https://media.divine.video");
    assert_eq!(cfg.max_concurrent_jobs, 4);
    assert_eq!(cfg.rate_limit_per_hour, 20);
    assert_eq!(cfg.rate_limit_per_day, 100);
    assert!(cfg.webhook_secrets.is_empty());
    assert!(cfg.admin_pubkeys.is_empty());
}

#[test]
fn parses_webhook_secrets_env_format() {
    let cfg = Config::from_env(&env(&[
        ("FIRESTORE_PROJECT", "p"),
        ("GCS_BUCKET", "b"),
        ("COMPILER_WEBHOOK_SECRETS", "funnelcake:abc123,janitor:def456"),
    ]))
    .unwrap();

    assert_eq!(cfg.webhook_secrets.len(), 2);
    assert_eq!(cfg.webhook_secrets.get("abc123"), Some(&"funnelcake".to_string()));
    assert_eq!(cfg.webhook_secrets.get("def456"), Some(&"janitor".to_string()));
}

#[test]
fn rejects_webhook_secret_with_separator_chars() {
    // Comma inside secret would break parsing
    let res = Config::from_env(&env(&[
        ("FIRESTORE_PROJECT", "p"),
        ("GCS_BUCKET", "b"),
        ("COMPILER_WEBHOOK_SECRETS", "bad:abc,123,other:def"),
    ]));
    assert!(res.is_err(), "should reject ambiguous secret with comma");
}

#[test]
fn parses_admin_pubkeys_csv() {
    let cfg = Config::from_env(&env(&[
        ("FIRESTORE_PROJECT", "p"),
        ("GCS_BUCKET", "b"),
        ("COMPILER_ADMIN_PUBKEYS", "deadbeef,cafebabe"),
    ]))
    .unwrap();
    assert_eq!(cfg.admin_pubkeys.len(), 2);
    assert!(cfg.admin_pubkeys.contains("deadbeef"));
    assert!(cfg.admin_pubkeys.contains("cafebabe"));
}

#[test]
fn errors_on_missing_required_var() {
    let res = Config::from_env(&env(&[("GCS_BUCKET", "b")]));
    assert!(res.is_err());
    assert!(format!("{:?}", res.unwrap_err()).contains("FIRESTORE_PROJECT"));
}
```

- [ ] **Step 2: Run test — expect FAIL (`config` module doesn't exist)**

Run:
```bash
cd cloud-run-compiler && cargo test --test config
```

Expected: compile error, `divine_compiler::config` not found.

- [ ] **Step 3: Make the crate a library AND binary**

Note: this intentionally diverges from `cloud-run-transcoder`, which is binary-only. We expose a library so integration tests in `tests/` can import internals without going through HTTP.

Add to `cloud-run-compiler/Cargo.toml` (after `[package]`):

```toml
[lib]
name = "divine_compiler"
path = "src/lib.rs"

[[bin]]
name = "divine-compiler"
path = "src/main.rs"
```

- [ ] **Step 4: Create `cloud-run-compiler/src/lib.rs`**

```rust
// ABOUTME: Library crate exposing internals for integration tests
// ABOUTME: Binary entry point is in main.rs

pub mod config;
```

- [ ] **Step 5: Implement `cloud-run-compiler/src/config.rs`**

```rust
// ABOUTME: Config struct loaded from environment variables at startup
// ABOUTME: Validates required vars and parses CSV/colon-separated env formats

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct Config {
    pub firestore_project: String,
    pub gcs_bucket: String,
    pub api_divine_video_url: String,
    pub media_divine_video_url: String,
    /// Map secret value → tenant name. Reverse of env format so we can
    /// look up tenant by the bearer token presented.
    pub webhook_secrets: HashMap<String, String>,
    pub admin_pubkeys: HashSet<String>,
    pub admin_token: Option<String>,
    pub max_concurrent_jobs: usize,
    pub rate_limit_per_hour: u32,
    pub rate_limit_per_day: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("required env var missing: {0}")]
    Missing(&'static str),
    #[error("invalid env value for {var}: {detail}")]
    Invalid { var: &'static str, detail: String },
}

impl Config {
    pub fn from_env(env: &HashMap<String, String>) -> Result<Self, ConfigError> {
        let firestore_project = env
            .get("FIRESTORE_PROJECT")
            .ok_or(ConfigError::Missing("FIRESTORE_PROJECT"))?
            .clone();
        let gcs_bucket = env
            .get("GCS_BUCKET")
            .ok_or(ConfigError::Missing("GCS_BUCKET"))?
            .clone();

        let api_divine_video_url = env
            .get("API_DIVINE_VIDEO_URL")
            .cloned()
            .unwrap_or_else(|| "https://api.divine.video".to_string());
        let media_divine_video_url = env
            .get("MEDIA_DIVINE_VIDEO_URL")
            .cloned()
            .unwrap_or_else(|| "https://media.divine.video".to_string());

        let webhook_secrets = parse_webhook_secrets(env.get("COMPILER_WEBHOOK_SECRETS"))?;
        let admin_pubkeys = parse_csv_set(env.get("COMPILER_ADMIN_PUBKEYS"));
        let admin_token = env.get("COMPILER_ADMIN_TOKEN").cloned();

        let max_concurrent_jobs = env
            .get("MAX_CONCURRENT_JOBS")
            .and_then(|s| s.parse().ok())
            .unwrap_or(4);
        let rate_limit_per_hour = env
            .get("RATE_LIMIT_PER_HOUR")
            .and_then(|s| s.parse().ok())
            .unwrap_or(20);
        let rate_limit_per_day = env
            .get("RATE_LIMIT_PER_DAY")
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        Ok(Config {
            firestore_project,
            gcs_bucket,
            api_divine_video_url,
            media_divine_video_url,
            webhook_secrets,
            admin_pubkeys,
            admin_token,
            max_concurrent_jobs,
            rate_limit_per_hour,
            rate_limit_per_day,
        })
    }

    /// Convenience for the binary entry point. Reads from std::env.
    pub fn from_process_env() -> Result<Self, ConfigError> {
        let env: HashMap<String, String> = std::env::vars().collect();
        Self::from_env(&env)
    }
}

fn parse_webhook_secrets(
    raw: Option<&String>,
) -> Result<HashMap<String, String>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(HashMap::new());
    };
    let mut out = HashMap::new();
    for pair in raw.split(',') {
        if pair.is_empty() {
            continue;
        }
        // Exactly one ':' separator allowed. Secret values must not contain
        // ',' or ':' (documented in spec).
        let colon_count = pair.bytes().filter(|b| *b == b':').count();
        if colon_count != 1 {
            return Err(ConfigError::Invalid {
                var: "COMPILER_WEBHOOK_SECRETS",
                detail: format!(
                    "pair `{}` has {} colons, expected exactly 1",
                    pair, colon_count
                ),
            });
        }
        let (name, secret) = pair.split_once(':').unwrap();
        if name.is_empty() || secret.is_empty() {
            return Err(ConfigError::Invalid {
                var: "COMPILER_WEBHOOK_SECRETS",
                detail: format!("empty name or secret in pair `{}`", pair),
            });
        }
        out.insert(secret.to_string(), name.to_string());
    }
    Ok(out)
}

fn parse_csv_set(raw: Option<&String>) -> HashSet<String> {
    raw.map(|s| {
        s.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect()
    })
    .unwrap_or_default()
}
```

- [ ] **Step 6: Run test — expect PASS**

Run:
```bash
cd cloud-run-compiler && cargo test --test config
```

Expected: 5 tests pass.

- [ ] **Step 7: Wire `Config::from_process_env()` into `main.rs`**

Update `cloud-run-compiler/src/main.rs`:

```rust
// ABOUTME: Cloud Run service that compiles Nostr-listed videos into watermarked MP4 compilations
// ABOUTME: Async job queue, multi-aspect output, NVENC encoding, blossom upload

use axum::{routing::get, Router};
use divine_compiler::config::Config;
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .json()
        .init();

    let cfg = Config::from_process_env()?;
    tracing::info!(
        firestore_project = %cfg.firestore_project,
        gcs_bucket = %cfg.gcs_bucket,
        webhook_tenants = cfg.webhook_secrets.len(),
        admin_pubkeys = cfg.admin_pubkeys.len(),
        max_concurrent_jobs = cfg.max_concurrent_jobs,
        "compiler service starting"
    );

    let app = Router::new().route("/health", get(|| async { "ok" }));

    let port: u16 = std::env::var("PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

- [ ] **Step 8: Verify build and run**

Run:
```bash
cd cloud-run-compiler && cargo build
FIRESTORE_PROJECT=test GCS_BUCKET=test cargo run >/tmp/compiler.log 2>&1 &
SERVER_PID=$!
sleep 2 && curl -s http://localhost:8080/health
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
grep -q "compiler service starting" /tmp/compiler.log
```

Expected: `ok` from curl, and the grep succeeds (startup log line was emitted as JSON).

- [ ] **Step 9: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): add Config struct and env loading with webhook-secret map"
```

### Task 1.4: deploy.sh skeleton

**Files:**
- Create: `cloud-run-compiler/deploy.sh`

- [ ] **Step 1: Create the deploy script**

```bash
#!/bin/bash
# ABOUTME: Deploy divine-compiler to Cloud Run with GPU + Firestore + secrets wired
# ABOUTME: Builds in Cloud Build, then deploys with all required env and secret bindings

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-divine-compiler}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-149672065768-compute@developer.gserviceaccount.com}"
IMAGE_TAG="${IMAGE_TAG:-$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M%S)}"
IMAGE="gcr.io/${PROJECT_ID}/${SERVICE_NAME}:${IMAGE_TAG}"

GCS_BUCKET="${GCS_BUCKET:-divine-blossom-media}"
FIRESTORE_PROJECT="${FIRESTORE_PROJECT:-${PROJECT_ID}}"
API_DIVINE_VIDEO_URL="${API_DIVINE_VIDEO_URL:-https://api.divine.video}"
MEDIA_DIVINE_VIDEO_URL="${MEDIA_DIVINE_VIDEO_URL:-https://media.divine.video}"
MAX_CONCURRENT_JOBS="${MAX_CONCURRENT_JOBS:-4}"
RATE_LIMIT_PER_HOUR="${RATE_LIMIT_PER_HOUR:-20}"
RATE_LIMIT_PER_DAY="${RATE_LIMIT_PER_DAY:-100}"

echo "Building ${IMAGE} in Cloud Build..."
gcloud builds submit "${SCRIPT_DIR}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --tag "${IMAGE}"

echo "Deploying ${SERVICE_NAME} to Cloud Run..."
gcloud run deploy "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --image "${IMAGE}" \
  --allow-unauthenticated \
  --service-account "${SERVICE_ACCOUNT}" \
  --cpu 4 \
  --memory 16Gi \
  --gpu 1 \
  --gpu-type nvidia-l4 \
  --gpu-zonal-redundancy disabled \
  --concurrency 4 \
  --timeout 1800 \
  --max-instances 5 \
  --no-cpu-throttling \
  --set-env-vars "^@@^GCS_BUCKET=${GCS_BUCKET}@@FIRESTORE_PROJECT=${FIRESTORE_PROJECT}@@API_DIVINE_VIDEO_URL=${API_DIVINE_VIDEO_URL}@@MEDIA_DIVINE_VIDEO_URL=${MEDIA_DIVINE_VIDEO_URL}@@MAX_CONCURRENT_JOBS=${MAX_CONCURRENT_JOBS}@@RATE_LIMIT_PER_HOUR=${RATE_LIMIT_PER_HOUR}@@RATE_LIMIT_PER_DAY=${RATE_LIMIT_PER_DAY}" \
  --set-secrets "COMPILER_WEBHOOK_SECRETS=compiler_webhook_secrets:latest,COMPILER_ADMIN_TOKEN=compiler_admin_token:latest"

echo "Done! Service URL:"
gcloud run services describe "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --format='value(status.url)'
```

- [ ] **Step 2: Make it executable**

Run:
```bash
chmod +x cloud-run-compiler/deploy.sh
```

- [ ] **Step 3: Don't run it yet — the service is just a /health stub.** Commit only.

```bash
git add cloud-run-compiler/deploy.sh
git commit -m "feat(compiler): add deploy.sh for Cloud Run GPU + env/secret bindings"
```

**End of Chunk 1.** At this point: `cloud-run-compiler/` exists, builds, runs locally, has `/health`, has a deploy script ready for when the rest of the service is built.

---

## Chunk 2: Job types and V1 request validation

Goal: define the typed shape of every request, response, and job-state record. Implement the V1 validation matrix from the spec (reject deferred fields with 400). No persistence yet, no Firestore — pure types and validation logic with thorough unit tests.

### Task 2.1: Define request and response types

**Files:**
- Create: `cloud-run-compiler/src/job/mod.rs`
- Create: `cloud-run-compiler/src/job/types.rs`
- Modify: `cloud-run-compiler/src/lib.rs`

- [ ] **Step 1: Create `src/job/mod.rs`**

```rust
// ABOUTME: Job state machine, request/response types, Firestore CRUD, worker loop
// ABOUTME: types module is pure data; store and worker bring in side effects later

pub mod types;
```

- [ ] **Step 2: Implement `src/job/types.rs`**

```rust
// ABOUTME: All request, response, and job state types for the compiler service
// ABOUTME: Serde derive on everything; no IO or business logic in this file

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------- Request ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompileRequest {
    pub source: Source,
    #[serde(default = "default_aspects")]
    pub aspects: Vec<Aspect>,
    #[serde(default)]
    pub fit: Fit,
    #[serde(default)]
    pub per_clip_overrides: Vec<PerClipOverride>,
    #[serde(default)]
    pub watermark: Watermark,
    #[serde(default)]
    pub credit: Credit,
    #[serde(default)]
    pub audio: Audio,
    #[serde(default)]
    pub transition: Transition,
    #[serde(default)]
    pub transition_ms: u32,
    #[serde(default)]
    pub intro_card: Option<Card>,
    #[serde(default)]
    pub outro_card: Option<Card>,
    #[serde(default = "default_max_duration_sec")]
    pub max_duration_sec: u32,
    #[serde(default)]
    pub callback_url: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

fn default_aspects() -> Vec<Aspect> { vec![Aspect::Vertical] }
fn default_max_duration_sec() -> u32 { 600 }

// NOTE: `deny_unknown_fields` is not supported on enums (only on structs).
// The variants below are tuple-style, so unknown-field rejection is
// inherently in effect for them. Don't add the attribute here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Naddr(String),
    EventIds(Vec<String>),
    Nevents(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Aspect {
    #[serde(rename = "9:16")]
    Vertical,
    #[serde(rename = "1:1")]
    Square,
    #[serde(rename = "16:9")]
    Horizontal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fit {
    BlurPad,
    CenterCrop,
    Letterbox,
}
impl Default for Fit { fn default() -> Self { Fit::BlurPad } }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerClipOverride {
    pub event_id: String,
    #[serde(default)]
    pub fit: Option<Fit>,
    #[serde(default)]
    pub in_sec: Option<f32>,
    #[serde(default)]
    pub out_sec: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Watermark {
    #[serde(default = "_true")]
    pub enabled: bool,
    #[serde(default)]
    pub position: WatermarkPosition,
    #[serde(default = "default_opacity")]
    pub opacity: f32,
}
impl Default for Watermark {
    fn default() -> Self { Self { enabled: true, position: WatermarkPosition::BottomRight, opacity: 0.30 } }
}
fn default_opacity() -> f32 { 0.30 }
fn _true() -> bool { true }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WatermarkPosition { TopLeft, TopRight, BottomLeft, BottomRight }
impl Default for WatermarkPosition { fn default() -> Self { Self::BottomRight } }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credit {
    #[serde(default)]
    pub mode: CreditMode,
    #[serde(default = "default_credit_duration")]
    pub duration_ms: u32,
    #[serde(default = "_true")]
    pub show_display_name: bool,
    #[serde(default = "_true")]
    pub show_nip05: bool,
}
impl Default for Credit {
    fn default() -> Self { Self { mode: CreditMode::LowerThirdFade, duration_ms: 2500, show_display_name: true, show_nip05: true } }
}
fn default_credit_duration() -> u32 { 2500 }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CreditMode { LowerThirdFade, AlwaysOn, CornerPill, Off }
impl Default for CreditMode { fn default() -> Self { Self::LowerThirdFade } }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Audio {
    #[serde(default)]
    pub mode: AudioMode,
    #[serde(default)]
    pub bgm_url: Option<String>,
    #[serde(default = "default_target_lufs")]
    pub target_lufs: f32,
}
impl Default for Audio {
    fn default() -> Self { Self { mode: AudioMode::Passthrough, bgm_url: None, target_lufs: -14.0 } }
}
fn default_target_lufs() -> f32 { -14.0 }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AudioMode { Passthrough, Mute, DuckedUnderMusic }
impl Default for AudioMode { fn default() -> Self { Self::Passthrough } }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transition { Cut, Crossfade, DipToBlack }
impl Default for Transition { fn default() -> Self { Self::Cut } }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Card {
    pub title: String,
    #[serde(default)]
    pub subtitle: Option<String>,
    pub duration_ms: u32,
}

// ---------- Response / Job state ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus { Queued, Running, Done, Failed, Cancelled }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub job_id: String,
    pub status: JobStatus,
    #[serde(default)]
    pub progress: f32,
    pub request: CompileRequest,
    pub tenant_id: String, // "pubkey:<hex>" or "secret:<name>"
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub result: Option<JobResult>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub callback_delivery: Option<CallbackDelivery>,
    #[serde(default)]
    pub requeued_from: Option<String>,
    #[serde(default)]
    pub requeued_as: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    pub outputs: Vec<BlobDescriptor>,
    pub duration_sec: u32,
    pub clips_used: u32,
    pub clips_dropped: Vec<ClipDropped>,
    pub credits: Vec<RenderedCredit>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobDescriptor {
    pub aspect: Aspect,
    pub url: String,
    pub sha256: String,
    pub size: u64,
    pub dim: String, // "WxH"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipDropped {
    pub event_id: String,
    pub reason: String,
}

/// One entry per credited author in the rendered output. Distinct from the
/// request-side `Credit` struct (which describes the credit *style*).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedCredit {
    pub event_id: String,
    pub pubkey: String,
    #[serde(default)]
    pub nip05: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackDelivery {
    pub attempts: u32,
    pub last_attempt_at: chrono::DateTime<chrono::Utc>,
    pub last_status_code: u16,
    pub delivered: bool,
}
```

- [ ] **Step 3: Add `chrono` to Cargo.toml**

In `[dependencies]` add:

```toml
chrono = { version = "0.4", features = ["serde"] }
```

- [ ] **Step 4: Expose the module in `src/lib.rs`**

```rust
// ABOUTME: Library crate exposing internals for integration tests
// ABOUTME: Binary entry point is in main.rs

pub mod config;
pub mod job;
```

- [ ] **Step 5: Verify it compiles**

Run:
```bash
cd cloud-run-compiler && cargo build --tests
```

Expected: compiles.

- [ ] **Step 6: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): define CompileRequest, Job, and response types"
```

### Task 2.2: Serialization round-trip tests

**Files:**
- Create: `cloud-run-compiler/tests/job_types_serde.rs`

- [ ] **Step 1: Write tests covering every enum variant and optional field**

```rust
use divine_compiler::job::types::*;
use serde_json::json;

#[test]
fn parses_minimal_request_with_naddr() {
    let body = json!({ "source": { "naddr": "naddr1abc..." } });
    let req: CompileRequest = serde_json::from_value(body).unwrap();
    match req.source {
        Source::Naddr(s) => assert_eq!(s, "naddr1abc..."),
        _ => panic!("expected naddr"),
    }
    assert_eq!(req.aspects, vec![Aspect::Vertical]);
    assert_eq!(req.fit, Fit::BlurPad);
    assert_eq!(req.transition, Transition::Cut);
    assert_eq!(req.transition_ms, 0);
    assert_eq!(req.max_duration_sec, 600);
    assert!(!req.dry_run);
    assert!(req.callback_url.is_none());
}

#[test]
fn parses_full_request_with_event_ids() {
    let body = json!({
        "source": { "event_ids": ["deadbeef", "cafebabe"] },
        "aspects": ["9:16", "1:1", "16:9"],
        "fit": "center-crop",
        "per_clip_overrides": [
            { "event_id": "deadbeef", "fit": "letterbox", "in_sec": 0.5, "out_sec": 5.8 }
        ],
        "watermark": { "enabled": true, "position": "top-right", "opacity": 0.5 },
        "credit": { "mode": "lower-third-fade", "duration_ms": 3000, "show_display_name": true, "show_nip05": true },
        "audio": { "mode": "passthrough", "bgm_url": null, "target_lufs": -16.0 },
        "transition": "cut",
        "transition_ms": 0,
        "intro_card": null,
        "outro_card": null,
        "max_duration_sec": 300,
        "callback_url": "https://example.com/hook",
        "dry_run": false
    });
    let req: CompileRequest = serde_json::from_value(body).unwrap();
    assert_eq!(req.aspects.len(), 3);
    match req.source {
        Source::EventIds(ids) => assert_eq!(ids, vec!["deadbeef", "cafebabe"]),
        _ => panic!(),
    }
}

#[test]
fn rejects_unknown_fields() {
    let body = json!({ "source": { "naddr": "n" }, "bogus_field": true });
    let err = serde_json::from_value::<CompileRequest>(body).unwrap_err();
    assert!(err.to_string().contains("bogus_field"), "got: {}", err);
}

#[test]
fn rejects_unknown_aspect_value() {
    let body = json!({ "source": { "naddr": "n" }, "aspects": ["4:3"] });
    assert!(serde_json::from_value::<CompileRequest>(body).is_err());
}

#[test]
fn job_round_trips_through_json() {
    let job = Job {
        job_id: "cmp_test".into(),
        status: JobStatus::Done,
        progress: 1.0,
        request: serde_json::from_value(json!({ "source": { "naddr": "n" } })).unwrap(),
        tenant_id: "pubkey:dead".into(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        result: Some(JobResult {
            outputs: vec![BlobDescriptor {
                aspect: Aspect::Vertical, url: "https://x".into(),
                sha256: "abc".into(), size: 1000, dim: "1080x1920".into(),
            }],
            duration_sec: 60, clips_used: 5,
            clips_dropped: vec![],
            credits: vec![RenderedCredit {
                event_id: "e".into(), pubkey: "p".into(),
                nip05: Some("a@b".into()), display_name: Some("A".into()),
            }],
            dry_run: false,
        }),
        error: None,
        callback_delivery: Some(CallbackDelivery {
            attempts: 1,
            last_attempt_at: chrono::Utc::now(),
            last_status_code: 200,
            delivered: true,
        }),
        requeued_from: None,
        requeued_as: None,
    };
    let encoded = serde_json::to_string(&job).unwrap();
    let decoded: Job = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded.job_id, "cmp_test");
    assert_eq!(decoded.status, JobStatus::Done);
}
```

- [ ] **Step 2: Run tests**

Run:
```bash
cd cloud-run-compiler && cargo test --test job_types_serde
```

Expected: 5 tests pass.

- [ ] **Step 3: Commit**

```bash
git add cloud-run-compiler/
git commit -m "test(compiler): serde round-trip coverage for job types"
```

### Task 2.3: V1 validation matrix

**Files:**
- Create: `cloud-run-compiler/src/job/validation.rs`
- Modify: `cloud-run-compiler/src/job/mod.rs`
- Create: `cloud-run-compiler/tests/api_validation.rs`

- [ ] **Step 1: Write the failing test**

`cloud-run-compiler/tests/api_validation.rs`:

```rust
use divine_compiler::job::{types::*, validation::validate_v1};
use serde_json::{json, Value};

fn req(body: Value) -> CompileRequest { serde_json::from_value(body).unwrap() }

#[test]
fn accepts_minimal_naddr_request() {
    let r = req(json!({ "source": { "naddr": "naddr1abc" } }));
    assert!(validate_v1(&r).is_ok());
}

#[test]
fn rejects_nevents_source() {
    let r = req(json!({ "source": { "nevents": ["nevent1abc"] } }));
    let e = validate_v1(&r).unwrap_err();
    assert_eq!(e.field, "source");
    assert_eq!(e.value, "nevents");
}

#[test]
fn rejects_always_on_credit_mode() {
    let r = req(json!({
        "source": { "naddr": "n" },
        "credit": { "mode": "always-on", "duration_ms": 100, "show_display_name": true, "show_nip05": true }
    }));
    let e = validate_v1(&r).unwrap_err();
    assert_eq!(e.field, "credit.mode");
    assert_eq!(e.value, "always-on");
}

#[test]
fn rejects_corner_pill_credit_mode() {
    let r = req(json!({
        "source": { "naddr": "n" },
        "credit": { "mode": "corner-pill", "duration_ms": 100, "show_display_name": true, "show_nip05": true }
    }));
    assert!(validate_v1(&r).is_err());
}

#[test]
fn rejects_crossfade_transition() {
    let r = req(json!({ "source": { "naddr": "n" }, "transition": "crossfade" }));
    let e = validate_v1(&r).unwrap_err();
    assert_eq!(e.field, "transition");
    assert_eq!(e.value, "crossfade");
}

#[test]
fn rejects_dip_to_black_transition() {
    let r = req(json!({ "source": { "naddr": "n" }, "transition": "dip-to-black" }));
    assert!(validate_v1(&r).is_err());
}

#[test]
fn rejects_nonzero_transition_ms() {
    let r = req(json!({ "source": { "naddr": "n" }, "transition_ms": 500 }));
    let e = validate_v1(&r).unwrap_err();
    assert_eq!(e.field, "transition_ms");
}

#[test]
fn rejects_ducked_audio_mode() {
    let r = req(json!({
        "source": { "naddr": "n" },
        "audio": { "mode": "ducked-under-music", "bgm_url": null, "target_lufs": -14.0 }
    }));
    let e = validate_v1(&r).unwrap_err();
    assert_eq!(e.field, "audio.mode");
}

#[test]
fn rejects_bgm_url() {
    let r = req(json!({
        "source": { "naddr": "n" },
        "audio": { "mode": "passthrough", "bgm_url": "https://x.mp3", "target_lufs": -14.0 }
    }));
    let e = validate_v1(&r).unwrap_err();
    assert_eq!(e.field, "audio.bgm_url");
}

#[test]
fn rejects_intro_card() {
    let r = req(json!({
        "source": { "naddr": "n" },
        "intro_card": { "title": "Hi", "duration_ms": 2000 }
    }));
    let e = validate_v1(&r).unwrap_err();
    assert_eq!(e.field, "intro_card");
}

#[test]
fn rejects_outro_card() {
    let r = req(json!({
        "source": { "naddr": "n" },
        "outro_card": { "title": "Bye", "duration_ms": 2000 }
    }));
    let e = validate_v1(&r).unwrap_err();
    assert_eq!(e.field, "outro_card");
}

#[test]
fn rejects_too_many_event_ids_sync() {
    let ids: Vec<String> = (0..501).map(|i| format!("{:064x}", i)).collect();
    let r = req(json!({ "source": { "event_ids": ids } }));
    let e = validate_v1(&r).unwrap_err();
    assert_eq!(e.field, "source.event_ids");
    assert!(e.value.starts_with("501"));
}

#[test]
fn naddr_clip_count_not_checked_at_validation_time() {
    // naddr resolves to an unknown number of events at request time;
    // the 500-clip cap is enforced async in the worker, not here.
    let r = req(json!({ "source": { "naddr": "naddr1abc" } }));
    assert!(validate_v1(&r).is_ok());
}
```

- [ ] **Step 2: Run test — expect FAIL (`validate_v1` doesn't exist)**

Run:
```bash
cd cloud-run-compiler && cargo test --test api_validation
```

Expected: compile error.

- [ ] **Step 3: Implement `src/job/validation.rs`**

```rust
// ABOUTME: V1 request validation matrix
// ABOUTME: Rejects deferred-to-v2 fields with structured 400 errors

use crate::job::types::*;

#[derive(Debug, Clone, serde::Serialize)]
pub struct UnsupportedField {
    pub error: &'static str,
    pub field: String,
    pub value: String,
}

impl UnsupportedField {
    fn new(field: impl Into<String>, value: impl Into<String>) -> Self {
        Self { error: "unsupported_field", field: field.into(), value: value.into() }
    }
}

pub const MAX_CLIPS_PER_JOB: usize = 500;

pub fn validate_v1(req: &CompileRequest) -> Result<(), UnsupportedField> {
    // Source: nevents rejected in v1
    if let Source::Nevents(_) = &req.source {
        return Err(UnsupportedField::new("source", "nevents"));
    }

    // Source: sync clip-count cap for explicit lists
    if let Source::EventIds(ids) = &req.source {
        if ids.len() > MAX_CLIPS_PER_JOB {
            return Err(UnsupportedField::new(
                "source.event_ids",
                format!("{} > {}", ids.len(), MAX_CLIPS_PER_JOB),
            ));
        }
    }

    // Credit modes
    match req.credit.mode {
        CreditMode::AlwaysOn => return Err(UnsupportedField::new("credit.mode", "always-on")),
        CreditMode::CornerPill => return Err(UnsupportedField::new("credit.mode", "corner-pill")),
        _ => {}
    }

    // Transitions
    match req.transition {
        Transition::Crossfade => return Err(UnsupportedField::new("transition", "crossfade")),
        Transition::DipToBlack => return Err(UnsupportedField::new("transition", "dip-to-black")),
        _ => {}
    }
    if req.transition_ms != 0 {
        return Err(UnsupportedField::new("transition_ms", req.transition_ms.to_string()));
    }

    // Audio
    if let AudioMode::DuckedUnderMusic = req.audio.mode {
        return Err(UnsupportedField::new("audio.mode", "ducked-under-music"));
    }
    if req.audio.bgm_url.is_some() {
        return Err(UnsupportedField::new(
            "audio.bgm_url",
            req.audio.bgm_url.clone().unwrap_or_default(),
        ));
    }

    // Cards
    if req.intro_card.is_some() {
        return Err(UnsupportedField::new("intro_card", "non-null"));
    }
    if req.outro_card.is_some() {
        return Err(UnsupportedField::new("outro_card", "non-null"));
    }

    Ok(())
}
```

- [ ] **Step 4: Update `src/job/mod.rs`**

```rust
pub mod types;
pub mod validation;
```

- [ ] **Step 5: Run tests — expect PASS**

Run:
```bash
cd cloud-run-compiler && cargo test --test api_validation
```

Expected: 13 tests pass.

- [ ] **Step 6: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): V1 request validation matrix (rejects v2+ fields with 400)"
```

**End of Chunk 2.** Types and validation are in place with high test coverage. No external dependencies (no Firestore, no axum routing, no HTTP). Next chunk adds the Firestore store layer.

---

## Chunk 3: Firestore job store

Goal: persist and retrieve `Job` records in Firestore. CRUD operations + tenant-scoped queries. Uses the `firestore` crate (or hand-rolled REST if version unavailable). Tests use the Firestore emulator.

### Task 3.1: Add Firestore emulator scaffolding for tests

**Files:**
- Create: `cloud-run-compiler/scripts/firestore-emulator.sh`
- Create: `cloud-run-compiler/tests/common/mod.rs` (test helper)

- [ ] **Step 1: Add `uuid` to `[dev-dependencies]` in `Cargo.toml`**

The store tests build random collection suffixes. Add (or move from `[dependencies]` if already present):

```toml
[dev-dependencies]
uuid = { version = "=1.12.1", features = ["v4"] }
```

(Already in `[dependencies]` from Chunk 1; declaring it here is harmless and keeps test-only deps explicit.)

- [ ] **Step 2: Create the emulator startup script**

```bash
#!/bin/bash
# ABOUTME: Start a local Firestore emulator for integration tests
# ABOUTME: Requires gcloud SDK + java; emulator listens on 127.0.0.1:8085

set -euo pipefail

PORT="${FIRESTORE_EMULATOR_PORT:-8085}"
PROJECT="${FIRESTORE_PROJECT:-test-project}"

exec gcloud emulators firestore start \
  --host-port="127.0.0.1:${PORT}" \
  --project="${PROJECT}"
```

Make it executable:
```bash
chmod +x cloud-run-compiler/scripts/firestore-emulator.sh
```

- [ ] **Step 3: Create the test helper at the idiomatic `tests/common/` path**

Cargo treats `tests/*.rs` files as separate integration test binaries, but **directories** under `tests/` (containing a `mod.rs`) are NOT compiled as binaries — they're modules that other tests can `mod common;` into. That's the standard pattern for shared test helpers.

`cloud-run-compiler/tests/common/mod.rs`:

```rust
// ABOUTME: Shared test helpers for integration tests
// ABOUTME: Use `mod common;` in test files; Cargo won't try to compile this as its own test

use divine_compiler::job::store::JobStore;

/// Returns the emulator host if set, otherwise None. Tests that need the
/// emulator should be marked `#[ignore]` and started via `cargo test -- --ignored`.
pub fn emulator_host() -> Option<String> {
    std::env::var("FIRESTORE_EMULATOR_HOST").ok()
}

/// Builds a JobStore against the Firestore emulator. **Panics** if
/// FIRESTORE_EMULATOR_HOST is not set — callers must use the `#[ignore]`
/// attribute and rely on the runner to gate execution.
pub async fn store_for_tests(suffix: &str) -> JobStore {
    let _ = emulator_host()
        .expect("FIRESTORE_EMULATOR_HOST must be set; run via `cargo test -- --ignored` with the emulator running");
    let project = std::env::var("FIRESTORE_PROJECT").unwrap_or_else(|_| "test-project".into());
    let collection = format!("compilation_jobs_test_{}", suffix);
    JobStore::with_collection(&project, &collection)
        .await
        .expect("JobStore should connect to emulator")
}
```

- [ ] **Step 4: No test to run yet.** Commit:

```bash
git add cloud-run-compiler/Cargo.toml cloud-run-compiler/scripts/firestore-emulator.sh cloud-run-compiler/tests/common/mod.rs
git commit -m "test(compiler): add Firestore emulator helper under tests/common/"
```

### Task 3.2: Implement the JobStore

**Files:**
- Create: `cloud-run-compiler/src/job/store.rs`
- Modify: `cloud-run-compiler/src/job/mod.rs`
- Create: `cloud-run-compiler/tests/job_store.rs`

- [ ] **Step 1: Write the failing tests**

All Firestore-backed tests are marked `#[ignore]` so they only run via `cargo test -- --ignored`. CI runs the emulator and then `cargo test -- --ignored`. Local dev runs without the emulator just compiles them.

`cloud-run-compiler/tests/job_store.rs`:

```rust
mod common;

use divine_compiler::job::types::*;
use serde_json::json;
use uuid::Uuid;

fn fixture_job(id: &str) -> Job {
    Job {
        job_id: id.into(),
        status: JobStatus::Queued,
        progress: 0.0,
        request: serde_json::from_value(json!({ "source": { "naddr": "n" } })).unwrap(),
        tenant_id: "pubkey:dead".into(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        result: None,
        error: None,
        callback_delivery: None,
        requeued_from: None,
        requeued_as: None,
    }
}

#[tokio::test]
#[ignore]
async fn create_then_get_round_trip() {
    let suffix = Uuid::new_v4().simple().to_string();
    let store = common::store_for_tests(&suffix).await;

    let job = fixture_job("cmp_round_trip");
    store.create_job(&job).await.expect("create");
    let loaded = store.get_job("cmp_round_trip").await.expect("get").expect("present");
    assert_eq!(loaded.job_id, "cmp_round_trip");
    assert_eq!(loaded.tenant_id, "pubkey:dead");
}

#[tokio::test]
#[ignore]
async fn get_unknown_returns_none() {
    let suffix = Uuid::new_v4().simple().to_string();
    let store = common::store_for_tests(&suffix).await;
    let res = store.get_job("does_not_exist").await.expect("get");
    assert!(res.is_none());
}

#[tokio::test]
#[ignore]
async fn update_status_persists() {
    let suffix = Uuid::new_v4().simple().to_string();
    let store = common::store_for_tests(&suffix).await;

    let mut job = fixture_job("cmp_upd");
    store.create_job(&job).await.unwrap();
    job.status = JobStatus::Running;
    job.progress = 0.5;
    store.update_job(&job).await.unwrap();

    let loaded = store.get_job("cmp_upd").await.unwrap().unwrap();
    assert_eq!(loaded.status, JobStatus::Running);
    assert!((loaded.progress - 0.5).abs() < 1e-6);
}

#[tokio::test]
#[ignore]
async fn list_recent_orders_by_created_at_desc() {
    let suffix = Uuid::new_v4().simple().to_string();
    let store = common::store_for_tests(&suffix).await;

    for i in 0..5 {
        let mut j = fixture_job(&format!("cmp_list_{}", i));
        j.created_at = chrono::Utc::now() + chrono::Duration::seconds(i);
        store.create_job(&j).await.unwrap();
    }

    let recent = store.list_recent(10, None, None, None).await.unwrap();
    assert!(recent.len() >= 5);
    for w in recent.windows(2) {
        assert!(w[0].created_at >= w[1].created_at);
    }
}

#[tokio::test]
#[ignore]
async fn list_recent_filters_by_status() {
    let suffix = Uuid::new_v4().simple().to_string();
    let store = common::store_for_tests(&suffix).await;

    let mut queued = fixture_job("cmp_q");
    queued.status = JobStatus::Queued;
    store.create_job(&queued).await.unwrap();

    let mut done = fixture_job("cmp_d");
    done.status = JobStatus::Done;
    store.create_job(&done).await.unwrap();

    let only_done = store.list_recent(10, None, Some(JobStatus::Done), None).await.unwrap();
    assert!(only_done.iter().all(|j| j.status == JobStatus::Done));
    assert!(only_done.iter().any(|j| j.job_id == "cmp_d"));
}

#[tokio::test]
#[ignore]
async fn list_recent_paginates_via_cursor() {
    let suffix = Uuid::new_v4().simple().to_string();
    let store = common::store_for_tests(&suffix).await;

    let mut ids = vec![];
    for i in 0..6 {
        let id = format!("cmp_p_{}", i);
        let mut j = fixture_job(&id);
        j.created_at = chrono::Utc::now() + chrono::Duration::seconds(i);
        store.create_job(&j).await.unwrap();
        ids.push(id);
    }

    let page1 = store.list_recent(3, None, None, None).await.unwrap();
    assert_eq!(page1.len(), 3);
    let cursor = page1.last().unwrap().job_id.clone();
    let page2 = store.list_recent(3, Some(cursor), None, None).await.unwrap();
    assert!(page2.iter().all(|j| !page1.iter().any(|p| p.job_id == j.job_id)));
}

#[tokio::test]
#[ignore]
async fn list_recent_filters_callback_delivered() {
    let suffix = Uuid::new_v4().simple().to_string();
    let store = common::store_for_tests(&suffix).await;

    let mut delivered = fixture_job("cmp_cb_ok");
    delivered.callback_delivery = Some(CallbackDelivery {
        attempts: 1, last_attempt_at: chrono::Utc::now(),
        last_status_code: 200, delivered: true,
    });
    store.create_job(&delivered).await.unwrap();

    let mut undelivered = fixture_job("cmp_cb_bad");
    undelivered.callback_delivery = Some(CallbackDelivery {
        attempts: 3, last_attempt_at: chrono::Utc::now(),
        last_status_code: 500, delivered: false,
    });
    store.create_job(&undelivered).await.unwrap();

    let bad = store.list_recent(10, None, None, Some(false)).await.unwrap();
    assert!(bad.iter().any(|j| j.job_id == "cmp_cb_bad"));
    assert!(bad.iter().all(|j| j.callback_delivery.as_ref().map(|c| !c.delivered).unwrap_or(false)));
}

#[tokio::test]
#[ignore]
async fn list_by_tenant_scopes_results() {
    let suffix = Uuid::new_v4().simple().to_string();
    let store = common::store_for_tests(&suffix).await;

    let mut mine = fixture_job("cmp_mine");
    mine.tenant_id = "pubkey:alice".into();
    store.create_job(&mine).await.unwrap();

    let mut theirs = fixture_job("cmp_theirs");
    theirs.tenant_id = "pubkey:bob".into();
    store.create_job(&theirs).await.unwrap();

    let alice_jobs = store.list_by_tenant("pubkey:alice", 10).await.unwrap();
    assert!(alice_jobs.iter().all(|j| j.tenant_id == "pubkey:alice"));
    assert!(alice_jobs.iter().any(|j| j.job_id == "cmp_mine"));
    assert!(alice_jobs.iter().all(|j| j.job_id != "cmp_theirs"));
}
```

- [ ] **Step 2: Run test — expect FAIL**

Run:
```bash
cd cloud-run-compiler && cargo test --test job_store
```

Expected: compile error (`JobStore` doesn't exist).

- [ ] **Step 3: Implement `src/job/store.rs`**

> **Implementer note:** The `firestore` crate's fluent builder API drifts between minor versions (especially around cursors). The code below targets `firestore = "0.43"`. **Before writing this file, run `cargo doc --open -p firestore` (or browse crates.io) and confirm the exact builder method names: `paths!` vs `path!`, `start_after(...)` taking `FirestoreQueryCursor` vs a tuple, etc.** Adjust the code to match the resolved version; the CRUD *shape* is stable but call-site arguments aren't. Cursors in particular often take `FirestoreQueryCursor::AfterValue(vec![value.into()])` rather than `start_after([value])`.

```rust
// ABOUTME: Firestore CRUD for Job records
// ABOUTME: Uses the `firestore` crate; honors FIRESTORE_EMULATOR_HOST for tests

use crate::job::types::*;
use anyhow::{Context, Result};
use firestore::{FirestoreDb, FirestoreDbOptions, FirestoreQueryDirection, paths};

const DEFAULT_COLLECTION: &str = "compilation_jobs";

#[derive(Clone)]
pub struct JobStore {
    db: FirestoreDb,
    collection: String,
}

impl JobStore {
    pub async fn new(project_id: &str) -> Result<Self> {
        Self::with_collection(project_id, DEFAULT_COLLECTION).await
    }

    pub async fn with_collection(project_id: &str, collection: &str) -> Result<Self> {
        let opts = FirestoreDbOptions::new(project_id.to_string());
        let db = FirestoreDb::with_options(opts)
            .await
            .context("connect to firestore")?;
        Ok(Self { db, collection: collection.to_string() })
    }

    pub async fn create_job(&self, job: &Job) -> Result<()> {
        self.db
            .fluent()
            .insert()
            .into(&self.collection)
            .document_id(&job.job_id)
            .object(job)
            .execute::<()>()
            .await
            .context("firestore insert job")?;
        Ok(())
    }

    pub async fn get_job(&self, job_id: &str) -> Result<Option<Job>> {
        let res: Option<Job> = self
            .db
            .fluent()
            .select()
            .by_id_in(&self.collection)
            .obj()
            .one(job_id)
            .await
            .context("firestore get job")?;
        Ok(res)
    }

    pub async fn update_job(&self, job: &Job) -> Result<()> {
        let mut updated = job.clone();
        updated.updated_at = chrono::Utc::now();
        self.db
            .fluent()
            .update()
            .in_col(&self.collection)
            .document_id(&updated.job_id)
            .object(&updated)
            .execute::<()>()
            .await
            .context("firestore update job")?;
        Ok(())
    }

    pub async fn list_recent(
        &self,
        limit: u32,
        cursor: Option<String>,
        status_filter: Option<JobStatus>,
        callback_delivered_filter: Option<bool>,
    ) -> Result<Vec<Job>> {
        let mut q = self
            .db
            .fluent()
            .select()
            .from(self.collection.as_str())
            .order_by([(paths!(Job::created_at), FirestoreQueryDirection::Descending)])
            .limit(limit);

        if let Some(status) = status_filter {
            q = q.filter(|qb| qb.field(paths!(Job::status)).eq(status));
        }
        if let Some(delivered) = callback_delivered_filter {
            // Nested field path: callback_delivery.delivered
            q = q.filter(|qb| qb.field("callback_delivery.delivered").eq(delivered));
        }
        if let Some(cursor_id) = cursor {
            // Cursor is a job_id; fetch that doc's created_at and start_after.
            if let Some(start) = self.get_job(&cursor_id).await? {
                q = q.start_after([start.created_at]);
            }
        }

        let items: Vec<Job> = q.obj().query().await.context("firestore list query")?;
        Ok(items)
    }

    pub async fn list_by_tenant(&self, tenant_id: &str, limit: u32) -> Result<Vec<Job>> {
        let items: Vec<Job> = self
            .db
            .fluent()
            .select()
            .from(self.collection.as_str())
            .filter(|qb| qb.field(paths!(Job::tenant_id)).eq(tenant_id))
            .order_by([(paths!(Job::created_at), FirestoreQueryDirection::Descending)])
            .limit(limit)
            .obj()
            .query()
            .await
            .context("firestore list by tenant")?;
        Ok(items)
    }
}
```

Note on the `firestore` crate API: the `paths!` macro and fluent builder shape are based on version 0.43. If a different version is pinned in Chunk 1, the API may differ slightly (e.g. `paths!` may be `path!`, the start_after argument may take a `FirestoreValue` instead of a value tuple). Adjust call sites to match the actual crate; the *shape* of CRUD operations is stable across recent 0.4x versions.

- [ ] **Step 4: Update `src/job/mod.rs`**

```rust
pub mod types;
pub mod validation;
pub mod store;
```

- [ ] **Step 5: Run the tests against the emulator**

Open a second terminal:
```bash
cloud-run-compiler/scripts/firestore-emulator.sh
```

(or `gcloud beta emulators firestore start --host-port=127.0.0.1:8085`)

In the test terminal:
```bash
export FIRESTORE_EMULATOR_HOST=127.0.0.1:8085
export FIRESTORE_PROJECT=test-project
cd cloud-run-compiler && cargo test --test job_store -- --ignored
```

Expected: 7 tests pass (round trip, get-unknown, update, list-recent ordering, list-recent status filter, list-recent cursor pagination, list-recent callback_delivered filter, list-by-tenant). Without `--ignored` they're skipped (default), which is what we want for local `cargo test` runs when the emulator isn't running.

- [ ] **Step 6: Verify default `cargo test` does NOT run these (they should be ignored)**

Run:
```bash
unset FIRESTORE_EMULATOR_HOST
cd cloud-run-compiler && cargo test --test job_store 2>&1 | grep -c "ignored"
```

Expected: a count matching the number of `#[ignore]` tests (currently 7). No silent passes; the tests are explicitly skipped via `#[ignore]`.

- [ ] **Step 7: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): Firestore JobStore with create/get/update/list/filter ops"
```

**End of Chunk 3.** Job records can now be persisted and queried. Next chunk: auth.

---

## Chunk 4: Auth (NIP-98 + webhook secret) and Tenant extraction

Goal: implement both auth mechanisms from the spec, expose them as an axum extractor that yields a `Tenant`. NIP-98 wins when both are present. 401 if neither is valid.

### Task 4.1: Tenant type and auth error shape

**Files:**
- Create: `cloud-run-compiler/src/auth.rs`
- Modify: `cloud-run-compiler/src/lib.rs`

- [ ] **Step 1: Create `src/auth.rs` with type stubs**

```rust
// ABOUTME: Auth extraction: NIP-98 first, webhook shared-secret fallback
// ABOUTME: Yields a Tenant enum used everywhere downstream

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tenant {
    /// Caller authenticated via NIP-98. Inner string is hex pubkey.
    Pubkey(String),
    /// Caller authenticated via webhook shared secret. Inner string is the
    /// tenant name from `COMPILER_WEBHOOK_SECRETS` env config.
    Secret(String),
}

impl Tenant {
    pub fn id(&self) -> String {
        match self {
            Tenant::Pubkey(hex) => format!("pubkey:{}", hex),
            Tenant::Secret(name) => format!("secret:{}", name),
        }
    }
    pub fn kind(&self) -> &'static str {
        match self {
            Tenant::Pubkey(_) => "nip98",
            Tenant::Secret(_) => "webhook",
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum AuthError {
    #[error("missing authorization header")]
    Missing,
    #[error("invalid nip98 token: {0}")]
    InvalidNip98(String),
    #[error("invalid webhook secret")]
    InvalidSecret,
    #[error("internal error: {0}")]
    Internal(String),
}
```

- [ ] **Step 2: Expose in `src/lib.rs`**

```rust
pub mod config;
pub mod job;
pub mod auth;
```

- [ ] **Step 3: Verify it compiles**

Run: `cd cloud-run-compiler && cargo build --tests`. Expected: compiles.

- [ ] **Step 4: Commit**

```bash
git add cloud-run-compiler/src/auth.rs cloud-run-compiler/src/lib.rs
git commit -m "feat(compiler): add Tenant and AuthError types"
```

### Task 4.2: Webhook-secret lookup

**Files:**
- Modify: `cloud-run-compiler/src/auth.rs`
- Create: `cloud-run-compiler/tests/auth_webhook_secret.rs`

- [ ] **Step 1: Write the failing test**

```rust
use divine_compiler::auth::{Tenant, resolve_webhook_secret};
use std::collections::HashMap;

fn secrets() -> HashMap<String, String> {
    // env format: name -> ... wait no, the Config stores secret -> name (see Chunk 1).
    // So pass a map of secret_value -> tenant_name.
    let mut m = HashMap::new();
    m.insert("abc123".to_string(), "funnelcake".to_string());
    m.insert("def456".to_string(), "janitor".to_string());
    m
}

#[test]
fn known_secret_yields_tenant_by_name() {
    let t = resolve_webhook_secret("abc123", &secrets()).unwrap();
    assert_eq!(t, Tenant::Secret("funnelcake".into()));
}

#[test]
fn unknown_secret_returns_none() {
    assert!(resolve_webhook_secret("notreal", &secrets()).is_none());
}

#[test]
fn empty_map_returns_none() {
    assert!(resolve_webhook_secret("abc123", &HashMap::new()).is_none());
}
```

- [ ] **Step 2: Run — expect FAIL**

`cd cloud-run-compiler && cargo test --test auth_webhook_secret` → compile error (function missing).

- [ ] **Step 3: Implement in `src/auth.rs`** (append):

```rust
use std::collections::HashMap;

/// Look up a presented webhook secret in the configured `secret_value → tenant_name`
/// map. Returns `Some(Tenant::Secret(name))` on hit, `None` otherwise.
pub fn resolve_webhook_secret(
    presented: &str,
    config: &HashMap<String, String>,
) -> Option<Tenant> {
    config.get(presented).map(|name| Tenant::Secret(name.clone()))
}
```

- [ ] **Step 4: Run — expect PASS**

`cd cloud-run-compiler && cargo test --test auth_webhook_secret` → 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): webhook secret → tenant lookup"
```

### Task 4.3: NIP-98 token verification

NIP-98 (HTTP Auth): caller signs an event of kind 27235 with tags `["u", <url>]` and `["method", <HTTP_METHOD>]`, and presents it base64-encoded in the `Authorization: Nostr <base64>` header. `created_at` must be within a small window (±60s). The event id is the sha256 of the canonical JSON `[0, pubkey, created_at, kind, tags, content]`. The signature is BIP-340 schnorr over the event id, by the pubkey's XOnlyPublicKey.

**Files:**
- Modify: `cloud-run-compiler/src/auth.rs`
- Create: `cloud-run-compiler/src/nip98.rs`
- Modify: `cloud-run-compiler/src/lib.rs`
- Create: `cloud-run-compiler/tests/auth_nip98.rs`

- [ ] **Step 1a: Create `cloud-run-compiler/tests/common/nip98_fixtures.rs`**

The global `secp256k1::SECP256K1` is `Secp256k1<VerifyOnly>` in 0.29 — it can verify but **cannot sign or generate keys**. Tests need a full `Secp256k1<All>` context built locally.

```rust
// ABOUTME: Helpers for building signed NIP-98 events in tests
// ABOUTME: Uses secp256k1 schnorr; generates fresh keypair per call

use secp256k1::{Keypair, Secp256k1};
use sha2::{Digest, Sha256};

pub struct NostrKey {
    pub keypair: Keypair,
    pub pubkey_hex: String,
}

pub fn random_key() -> NostrKey {
    use secp256k1::rand::rngs::OsRng;
    let secp = Secp256k1::new(); // All caps; signs + verifies
    let kp = Keypair::new(&secp, &mut OsRng);
    let (xonly, _parity) = kp.x_only_public_key();
    let pubkey_hex = hex::encode(xonly.serialize());
    NostrKey { keypair: kp, pubkey_hex }
}

/// Build a NIP-98 event JSON, compute its id, schnorr-sign it, return
/// base64-encoded ready for `Authorization: Nostr <...>`.
pub fn build_token(key: &NostrKey, method: &str, url: &str, created_at: i64) -> String {
    use base64::Engine as _;
    let secp = Secp256k1::new();

    let tags = serde_json::json!([
        ["u", url],
        ["method", method],
    ]);
    let canonical = serde_json::json!([
        0, key.pubkey_hex, created_at, 27235, tags, ""
    ]);
    let serialized = serde_json::to_string(&canonical).unwrap();
    let id_bytes: [u8; 32] = Sha256::digest(serialized.as_bytes()).into();
    let msg = secp256k1::Message::from_digest(id_bytes);
    let sig = secp.sign_schnorr(&msg, &key.keypair);

    let event = serde_json::json!({
        "id": hex::encode(id_bytes),
        "pubkey": key.pubkey_hex,
        "created_at": created_at,
        "kind": 27235,
        "tags": tags,
        "content": "",
        "sig": hex::encode(sig.as_ref()),
    });
    let event_json = serde_json::to_string(&event).unwrap();
    base64::engine::general_purpose::STANDARD.encode(event_json)
}
```

- [ ] **Step 1b: Extend `cloud-run-compiler/tests/common/mod.rs`**

Append:

```rust
pub mod nip98_fixtures;
```

(Without this line the test files fail with `unresolved module`.)

- [ ] **Step 2: Write the failing test**

`cloud-run-compiler/tests/auth_nip98.rs`:

```rust
mod common;

use common::nip98_fixtures::{build_token, random_key};
use divine_compiler::auth::Tenant;
use divine_compiler::nip98::verify_nip98_token;

fn now() -> i64 { chrono::Utc::now().timestamp() }

#[test]
fn valid_token_returns_pubkey() {
    let key = random_key();
    let token = build_token(&key, "POST", "https://example.com/compile", now());
    let tenant = verify_nip98_token(&token, "POST", "https://example.com/compile").unwrap();
    assert_eq!(tenant, Tenant::Pubkey(key.pubkey_hex));
}

#[test]
fn rejects_wrong_method() {
    let key = random_key();
    let token = build_token(&key, "GET", "https://example.com/x", now());
    let err = verify_nip98_token(&token, "POST", "https://example.com/x").unwrap_err();
    assert!(format!("{:?}", err).to_lowercase().contains("method"));
}

#[test]
fn rejects_wrong_url() {
    let key = random_key();
    let token = build_token(&key, "POST", "https://example.com/a", now());
    let err = verify_nip98_token(&token, "POST", "https://example.com/b").unwrap_err();
    assert!(format!("{:?}", err).to_lowercase().contains("url"));
}

#[test]
fn rejects_stale_created_at() {
    let key = random_key();
    let token = build_token(&key, "POST", "https://x", now() - 600); // 10 min old
    let err = verify_nip98_token(&token, "POST", "https://x").unwrap_err();
    assert!(format!("{:?}", err).to_lowercase().contains("stale") || format!("{:?}", err).contains("created_at"));
}

#[test]
fn rejects_future_created_at() {
    let key = random_key();
    let token = build_token(&key, "POST", "https://x", now() + 600);
    assert!(verify_nip98_token(&token, "POST", "https://x").is_err());
}

#[test]
fn rejects_tampered_signature() {
    let key = random_key();
    let token = build_token(&key, "POST", "https://x", now());
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD.decode(&token).unwrap();
    let mut event: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    // Flip a byte in the signature.
    let sig_hex = event["sig"].as_str().unwrap();
    let mut bytes = hex::decode(sig_hex).unwrap();
    bytes[0] ^= 0x01;
    event["sig"] = serde_json::Value::String(hex::encode(&bytes));
    let bad = base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(&event).unwrap());
    assert!(verify_nip98_token(&bad, "POST", "https://x").is_err());
}

#[test]
fn rejects_wrong_kind() {
    let key = random_key();
    // Forge a kind-1 event using a local signing context.
    use sha2::{Digest, Sha256};
    use secp256k1::Secp256k1;
    use base64::Engine as _;
    let secp = Secp256k1::new();
    let tags = serde_json::json!([["u", "https://x"], ["method", "POST"]]);
    let created_at = now();
    let canonical = serde_json::json!([0, key.pubkey_hex, created_at, 1, tags, ""]);
    let id_bytes: [u8; 32] = Sha256::digest(serde_json::to_string(&canonical).unwrap().as_bytes()).into();
    let msg = secp256k1::Message::from_digest(id_bytes);
    let sig = secp.sign_schnorr(&msg, &key.keypair);
    let event = serde_json::json!({
        "id": hex::encode(id_bytes),
        "pubkey": key.pubkey_hex,
        "created_at": created_at,
        "kind": 1,
        "tags": tags, "content": "",
        "sig": hex::encode(sig.as_ref()),
    });
    let token = base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(&event).unwrap());
    let err = verify_nip98_token(&token, "POST", "https://x").unwrap_err();
    assert!(format!("{:?}", err).to_lowercase().contains("kind"));
}

#[test]
fn rejects_garbage_base64() {
    let err = verify_nip98_token("not-base64!@#", "POST", "https://x").unwrap_err();
    assert!(format!("{:?}", err).to_lowercase().contains("base64") || format!("{:?}", err).to_lowercase().contains("invalid"));
}
```

- [ ] **Step 3: Run — expect FAIL**

`cd cloud-run-compiler && cargo test --test auth_nip98` → compile error.

- [ ] **Step 4: Implement `src/nip98.rs`**

```rust
// ABOUTME: NIP-98 HTTP Auth event verification
// ABOUTME: kind 27235, tags include u + method, sig is BIP-340 schnorr over event id
//
// CAVEAT — NIP-01 canonicalization: the spec mandates a specific canonical
// JSON form (no whitespace, specific escape rules). We compute event IDs by
// calling `serde_json::to_string` on the same shape we serialize for
// signing. This is interoperable with any signer that uses serde_json (most
// Rust ones, including our fixtures), but is NOT guaranteed compatible with
// signers using stricter NIP-01 canonicalizers (e.g. JS clients hand-rolling
// the spec). If interop with arbitrary Nostr signers becomes a real
// requirement, switch to a NIP-01-compliant canonicalizer here.

use crate::auth::{AuthError, Tenant};
use base64::Engine as _;
use secp256k1::{schnorr::Signature, Message, XOnlyPublicKey, SECP256K1};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const KIND_HTTP_AUTH: i64 = 27235;
/// Accept events created within ±60 seconds of now.
const MAX_CLOCK_SKEW_SEC: i64 = 60;

#[derive(Debug, Deserialize)]
struct Nip98Event {
    id: String,
    pubkey: String,
    created_at: i64,
    kind: i64,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}

pub fn verify_nip98_token(
    token_b64: &str,
    expected_method: &str,
    expected_url: &str,
) -> Result<Tenant, AuthError> {
    // Trim leading "Nostr " if the caller passed the full header value.
    let token_b64 = token_b64.trim().trim_start_matches("Nostr ").trim();

    let raw = base64::engine::general_purpose::STANDARD
        .decode(token_b64)
        .map_err(|e| AuthError::InvalidNip98(format!("base64: {}", e)))?;
    let event: Nip98Event = serde_json::from_slice(&raw)
        .map_err(|e| AuthError::InvalidNip98(format!("json: {}", e)))?;

    if event.kind != KIND_HTTP_AUTH {
        return Err(AuthError::InvalidNip98(format!(
            "wrong kind: {} (want {})", event.kind, KIND_HTTP_AUTH
        )));
    }

    let now = chrono::Utc::now().timestamp();
    if (now - event.created_at).abs() > MAX_CLOCK_SKEW_SEC {
        return Err(AuthError::InvalidNip98(format!(
            "stale created_at: {} vs now {}", event.created_at, now
        )));
    }

    let u = find_tag(&event.tags, "u").ok_or_else(|| AuthError::InvalidNip98("missing u tag".into()))?;
    if u != expected_url {
        return Err(AuthError::InvalidNip98(format!("url mismatch: token={} req={}", u, expected_url)));
    }
    let m = find_tag(&event.tags, "method").ok_or_else(|| AuthError::InvalidNip98("missing method tag".into()))?;
    if !m.eq_ignore_ascii_case(expected_method) {
        return Err(AuthError::InvalidNip98(format!("method mismatch: token={} req={}", m, expected_method)));
    }

    // Recompute event id from canonical serialization
    let tags_json = serde_json::to_value(&event.tags).unwrap();
    let canonical = serde_json::json!([0, event.pubkey, event.created_at, event.kind, tags_json, event.content]);
    let canonical_str = serde_json::to_string(&canonical)
        .map_err(|e| AuthError::Internal(format!("serialize canonical: {}", e)))?;
    let computed_id: [u8; 32] = Sha256::digest(canonical_str.as_bytes()).into();
    let stated_id = hex::decode(&event.id)
        .map_err(|_| AuthError::InvalidNip98("id not hex".into()))?;
    if stated_id != computed_id {
        return Err(AuthError::InvalidNip98("id mismatch (event tampered)".into()));
    }

    // Verify schnorr sig over the event id
    let pubkey_bytes = hex::decode(&event.pubkey)
        .map_err(|_| AuthError::InvalidNip98("pubkey not hex".into()))?;
    if pubkey_bytes.len() != 32 {
        return Err(AuthError::InvalidNip98("pubkey not 32 bytes".into()));
    }
    let xonly = XOnlyPublicKey::from_slice(&pubkey_bytes)
        .map_err(|e| AuthError::InvalidNip98(format!("xonly pubkey: {}", e)))?;
    let sig_bytes = hex::decode(&event.sig)
        .map_err(|_| AuthError::InvalidNip98("sig not hex".into()))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::InvalidNip98(format!("sig must be 64 bytes, got {}", sig_bytes.len())))?;
    // 0.29: schnorr::Signature uses `from_byte_array`, not `from_slice`.
    let sig = Signature::from_byte_array(sig_arr);
    let msg = Message::from_digest(computed_id);
    SECP256K1
        .verify_schnorr(&sig, &msg, &xonly)
        .map_err(|e| AuthError::InvalidNip98(format!("schnorr verify: {}", e)))?;

    Ok(Tenant::Pubkey(event.pubkey))
}

fn find_tag<'a>(tags: &'a [Vec<String>], name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}
```

- [ ] **Step 5: Expose in `src/lib.rs`**

```rust
pub mod config;
pub mod job;
pub mod auth;
pub mod nip98;
```

- [ ] **Step 6: Run — expect PASS**

`cd cloud-run-compiler && cargo test --test auth_nip98` → 8 tests pass.

- [ ] **Step 7: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): NIP-98 token verification (kind 27235, schnorr, url+method check)"
```

### Task 4.4: axum Tenant extractor combining both auth paths

**Files:**
- Modify: `cloud-run-compiler/src/auth.rs`
- Create: `cloud-run-compiler/tests/auth_extractor.rs`

- [ ] **Step 1: Write the failing test**

```rust
mod common;

use common::nip98_fixtures::{build_token, random_key};
use divine_compiler::auth::{Tenant, extract_tenant};
use std::collections::HashMap;

fn make_secrets() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("supersecret".into(), "funnelcake".into());
    m
}

#[test]
fn nip98_header_yields_pubkey() {
    let key = random_key();
    let token = build_token(&key, "POST", "https://x/compile", chrono::Utc::now().timestamp());
    let header = format!("Nostr {}", token);
    let t = extract_tenant(Some(&header), "POST", "https://x/compile", &make_secrets()).unwrap();
    assert_eq!(t, Tenant::Pubkey(key.pubkey_hex));
}

#[test]
fn bearer_secret_yields_tenant_name() {
    let header = "Bearer supersecret";
    let t = extract_tenant(Some(header), "POST", "https://x/compile", &make_secrets()).unwrap();
    assert_eq!(t, Tenant::Secret("funnelcake".into()));
}

#[test]
fn nip98_prefix_is_recognized() {
    // HTTP only allows one Authorization header, so "both present" isn't
    // representable. We verify the `Nostr ` prefix dispatches to NIP-98.
    let key = random_key();
    let token = build_token(&key, "POST", "https://x/y", chrono::Utc::now().timestamp());
    let header = format!("Nostr {}", token);
    let t = extract_tenant(Some(&header), "POST", "https://x/y", &make_secrets()).unwrap();
    assert!(matches!(t, Tenant::Pubkey(_)));
}

#[test]
fn missing_header_returns_missing() {
    let err = extract_tenant(None, "POST", "https://x", &HashMap::new()).unwrap_err();
    assert!(matches!(err, divine_compiler::auth::AuthError::Missing));
}

#[test]
fn unknown_bearer_returns_invalid_secret() {
    let err = extract_tenant(Some("Bearer notreal"), "POST", "https://x", &make_secrets()).unwrap_err();
    assert!(matches!(err, divine_compiler::auth::AuthError::InvalidSecret));
}
```

- [ ] **Step 2: Implement the combined extractor in `src/auth.rs`** (append):

```rust
use crate::nip98::verify_nip98_token;

/// Combines NIP-98 and webhook-secret auth. Header is the `Authorization`
/// header value (or None). Method + url are the request's HTTP method and
/// fully-qualified URL. Secrets is the secret_value → tenant_name map from Config.
///
/// Resolution order:
/// - Header starts with "Nostr " → NIP-98
/// - Header starts with "Bearer " → webhook secret lookup
/// - Missing / unrecognized → AuthError
pub fn extract_tenant(
    auth_header: Option<&str>,
    method: &str,
    url: &str,
    secrets: &HashMap<String, String>,
) -> Result<Tenant, AuthError> {
    let header = auth_header.ok_or(AuthError::Missing)?;
    if let Some(rest) = header.strip_prefix("Nostr ") {
        return verify_nip98_token(rest, method, url);
    }
    if let Some(rest) = header.strip_prefix("Bearer ") {
        return resolve_webhook_secret(rest.trim(), secrets).ok_or(AuthError::InvalidSecret);
    }
    Err(AuthError::Missing)
}
```

- [ ] **Step 3: Run — expect PASS**

`cd cloud-run-compiler && cargo test --test auth_extractor` → 5 tests pass.

- [ ] **Step 4: Add an axum `FromRequestParts` impl so handlers can take `Tenant` as an extractor**

Append to `src/auth.rs`:

```rust
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;
use crate::config::Config;

#[derive(Debug, Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub job_store: Arc<crate::job::store::JobStore>,
}

#[async_trait]
impl<S> FromRequestParts<S> for Tenant
where
    S: Send + Sync,
    AppState: axum::extract::FromRef<S>,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = AppState::from_ref(state);
        let auth_value = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());

        // Reconstruct the full URL the caller hit. NIP-98's `u` tag is the
        // exact URL — we read it from `X-Forwarded-Host`/`X-Forwarded-Proto`
        // (set by Cloud Run/Fastly) when present, fall back to the Host header.
        let scheme = parts
            .headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("https");
        let host = parts
            .headers
            .get("x-forwarded-host")
            .or_else(|| parts.headers.get(axum::http::header::HOST))
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let path_and_query = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let full_url = format!("{}://{}{}", scheme, host, path_and_query);

        extract_tenant(auth_value, parts.method.as_str(), &full_url, &state.config.webhook_secrets)
            .map_err(AuthRejection)
    }
}

pub struct AuthRejection(pub AuthError);

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        let status = match &self.0 {
            AuthError::Missing => StatusCode::UNAUTHORIZED,
            AuthError::InvalidNip98(_) => StatusCode::UNAUTHORIZED,
            AuthError::InvalidSecret => StatusCode::UNAUTHORIZED,
            AuthError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(serde_json::json!({ "error": "unauthorized", "detail": self.0.to_string() }))).into_response()
    }
}
```

- [ ] **Step 5: Verify it compiles**

Run: `cd cloud-run-compiler && cargo build --tests`. Expected: compiles. (The extractor isn't exercised by unit tests yet — that comes in Chunk 9 when handlers are wired up.)

- [ ] **Step 6: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): axum FromRequestParts extractor for Tenant"
```

**End of Chunk 4.** Both auth mechanisms work, are tested, and the extractor is ready to be applied to handlers in Chunk 9.

---

## Chunk 5: Rate limiting

Goal: per-tenant rate limit (default 20/hr, 100/day) backed by Firestore atomic counters at `rate_limits/<tenant_id>`. Per-tenant overrides supported via the same Firestore doc. Exceeded → `RateLimitOutcome::TooMany { retry_after_seconds }`.

### Task 5.1: RateLimiter type + outcome

**Files:**
- Create: `cloud-run-compiler/src/rate_limit.rs`
- Modify: `cloud-run-compiler/src/lib.rs`

- [ ] **Step 1: Implement the type**

```rust
// ABOUTME: Per-tenant rate limiting via Firestore counter docs
// ABOUTME: Hourly + daily buckets keyed by tenant_id, with per-tenant override doc
//
// Spec deviations (intentional, documented):
//   - "Atomic increments" — we use read-modify-write inside a doc-existence-aware
//     branch instead. At-most-one over-count per window per tenant is acceptable
//     for v1.
//   - "Field-level TTL" — we write an `expires_at` field on each doc and rely
//     on a Firestore TTL policy (set up once in console / Terraform: collection
//     `rate_limits`, field `expires_at`). v1 ships the field; the operator
//     enables the TTL policy at deploy time.

use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, Duration, Timelike, Utc};
use firestore::FirestoreDb;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitOutcome {
    Allowed,
    TooMany { retry_after_seconds: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TenantLimits {
    #[serde(default)]
    pub per_hour: Option<u32>,
    #[serde(default)]
    pub per_day: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CounterDoc {
    #[serde(default)]
    hour_bucket: String,
    #[serde(default)]
    hour_count: u32,
    #[serde(default)]
    day_bucket: String,
    #[serde(default)]
    day_count: u32,
    #[serde(default)]
    overrides: Option<TenantLimits>,
    /// When Firestore's TTL policy should garbage-collect this doc.
    /// Set to `now + 36h` on every write so an idle tenant's row eventually
    /// disappears.
    expires_at: DateTime<Utc>,
}

const COLLECTION: &str = "rate_limits";
const TTL_HOURS: i64 = 36;

#[derive(Clone)]
pub struct RateLimiter {
    db: FirestoreDb,
    default_per_hour: u32,
    default_per_day: u32,
}

fn buckets(now: DateTime<Utc>) -> (String, String) {
    let h = format!("{:04}{:02}{:02}{:02}", now.year(), now.month(), now.day(), now.hour());
    let d = format!("{:04}{:02}{:02}", now.year(), now.month(), now.day());
    (h, d)
}

impl RateLimiter {
    pub fn new(db: FirestoreDb, default_per_hour: u32, default_per_day: u32) -> Self {
        Self { db, default_per_hour, default_per_day }
    }

    pub async fn check_and_increment(
        &self,
        tenant_id: &str,
        now: DateTime<Utc>,
    ) -> Result<RateLimitOutcome> {
        let (hour_bucket, day_bucket) = buckets(now);

        let existing: Option<CounterDoc> = self
            .db
            .fluent()
            .select()
            .by_id_in(COLLECTION)
            .obj()
            .one(tenant_id)
            .await
            .context("firestore get rate_limits doc")?;

        let doc_exists = existing.is_some();
        let mut doc = existing.unwrap_or_else(|| CounterDoc {
            hour_bucket: hour_bucket.clone(),
            hour_count: 0,
            day_bucket: day_bucket.clone(),
            day_count: 0,
            overrides: None,
            expires_at: now + Duration::hours(TTL_HOURS),
        });

        if doc.hour_bucket != hour_bucket {
            doc.hour_bucket = hour_bucket.clone();
            doc.hour_count = 0;
        }
        if doc.day_bucket != day_bucket {
            doc.day_bucket = day_bucket.clone();
            doc.day_count = 0;
        }

        let limits = doc.overrides.clone().unwrap_or_default();
        let per_hour = limits.per_hour.unwrap_or(self.default_per_hour);
        let per_day = limits.per_day.unwrap_or(self.default_per_day);

        if doc.hour_count >= per_hour {
            let secs = 3600 - (now.minute() as u64 * 60 + now.second() as u64);
            return Ok(RateLimitOutcome::TooMany { retry_after_seconds: secs });
        }
        if doc.day_count >= per_day {
            let secs = 86400 - (now.hour() as u64 * 3600 + now.minute() as u64 * 60 + now.second() as u64);
            return Ok(RateLimitOutcome::TooMany { retry_after_seconds: secs });
        }

        doc.hour_count += 1;
        doc.day_count += 1;
        doc.expires_at = now + Duration::hours(TTL_HOURS);

        // `update()` requires the doc to exist; `insert()` requires it not to.
        // We've already read existence above, so dispatch on that. Race window
        // between read and write may produce a stale `AlreadyExists` on `insert`
        // — on that specific error, retry the `update` path once.
        let write_res = if doc_exists {
            self.db
                .fluent()
                .update()
                .in_col(COLLECTION)
                .document_id(tenant_id)
                .object(&doc)
                .execute::<()>()
                .await
        } else {
            self.db
                .fluent()
                .insert()
                .into(COLLECTION)
                .document_id(tenant_id)
                .object(&doc)
                .execute::<()>()
                .await
        };
        if let Err(e) = write_res {
            // If the race lost (someone else inserted between our read and
            // insert), retry as update. Otherwise propagate.
            let msg = format!("{}", e);
            if !doc_exists && msg.to_lowercase().contains("exists") {
                self.db
                    .fluent()
                    .update()
                    .in_col(COLLECTION)
                    .document_id(tenant_id)
                    .object(&doc)
                    .execute::<()>()
                    .await
                    .context("firestore retry update after insert race")?;
            } else {
                return Err(anyhow::Error::from(e).context("firestore write rate_limits doc"));
            }
        }

        Ok(RateLimitOutcome::Allowed)
    }
}
```

- [ ] **Step 2: Expose in `src/lib.rs`**

```rust
pub mod config;
pub mod job;
pub mod auth;
pub mod nip98;
pub mod rate_limit;
```

- [ ] **Step 3: Verify compile**

Run: `cd cloud-run-compiler && cargo build --tests`. Expected: compiles.

- [ ] **Step 4: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): RateLimiter with per-tenant hourly/daily buckets and overrides"
```

### Task 5.2: Emulator-backed tests

**Files:**
- Create: `cloud-run-compiler/tests/rate_limit.rs`

- [ ] **Step 1: Write tests**

```rust
mod common;

use chrono::{Datelike, TimeZone, Timelike, Utc};
use divine_compiler::rate_limit::{RateLimitOutcome, RateLimiter, TenantLimits};
use firestore::{FirestoreDb, FirestoreDbOptions};
use uuid::Uuid;

fn skip_unless_emulator() -> Option<()> {
    common::emulator_host().map(|_| ())
}

async fn limiter(per_hour: u32, per_day: u32) -> RateLimiter {
    skip_unless_emulator().expect("emulator required for rate_limit tests; run with --ignored");
    let project = std::env::var("FIRESTORE_PROJECT").unwrap_or_else(|_| "test-project".into());
    let db = FirestoreDb::with_options(FirestoreDbOptions::new(project))
        .await
        .expect("connect emulator");
    RateLimiter::new(db, per_hour, per_day)
}

#[tokio::test]
#[ignore]
async fn allows_under_limit() {
    let rl = limiter(5, 100).await;
    let tenant = format!("pubkey:test-{}", Uuid::new_v4().simple());
    for _ in 0..5 {
        let o = rl.check_and_increment(&tenant, Utc::now()).await.unwrap();
        assert_eq!(o, RateLimitOutcome::Allowed);
    }
}

#[tokio::test]
#[ignore]
async fn rejects_over_hourly_limit() {
    let rl = limiter(2, 100).await;
    let tenant = format!("pubkey:test-{}", Uuid::new_v4().simple());
    assert_eq!(rl.check_and_increment(&tenant, Utc::now()).await.unwrap(), RateLimitOutcome::Allowed);
    assert_eq!(rl.check_and_increment(&tenant, Utc::now()).await.unwrap(), RateLimitOutcome::Allowed);
    let o = rl.check_and_increment(&tenant, Utc::now()).await.unwrap();
    assert!(matches!(o, RateLimitOutcome::TooMany { .. }));
}

#[tokio::test]
#[ignore]
async fn rejects_over_daily_limit() {
    let rl = limiter(100, 2).await;
    let tenant = format!("pubkey:test-{}", Uuid::new_v4().simple());
    rl.check_and_increment(&tenant, Utc::now()).await.unwrap();
    rl.check_and_increment(&tenant, Utc::now()).await.unwrap();
    let o = rl.check_and_increment(&tenant, Utc::now()).await.unwrap();
    assert!(matches!(o, RateLimitOutcome::TooMany { .. }));
}

#[tokio::test]
#[ignore]
async fn hour_bucket_rolls_over() {
    let rl = limiter(1, 100).await;
    let tenant = format!("pubkey:test-{}", Uuid::new_v4().simple());
    let t0 = Utc.with_ymd_and_hms(2026, 5, 17, 10, 0, 0).unwrap();
    assert_eq!(rl.check_and_increment(&tenant, t0).await.unwrap(), RateLimitOutcome::Allowed);
    assert!(matches!(
        rl.check_and_increment(&tenant, t0).await.unwrap(),
        RateLimitOutcome::TooMany { .. }
    ));
    let t1 = t0 + chrono::Duration::hours(1);
    assert_eq!(rl.check_and_increment(&tenant, t1).await.unwrap(), RateLimitOutcome::Allowed);
}

#[tokio::test]
#[ignore]
async fn per_tenant_override_raises_limit() {
    let rl = limiter(1, 100).await;
    let tenant = format!("pubkey:test-{}", Uuid::new_v4().simple());

    // Seed an override doc directly via Firestore so the limiter picks it up.
    let project = std::env::var("FIRESTORE_PROJECT").unwrap_or_else(|_| "test-project".into());
    let db = FirestoreDb::with_options(FirestoreDbOptions::new(project)).await.unwrap();
    #[derive(serde::Serialize)]
    struct Seed {
        hour_bucket: String,
        hour_count: u32,
        day_bucket: String,
        day_count: u32,
        overrides: TenantLimits,
        expires_at: chrono::DateTime<Utc>,
    }
    let now = Utc::now();
    let seed = Seed {
        hour_bucket: format!("{:04}{:02}{:02}{:02}", now.year(), now.month(), now.day(), now.hour()),
        hour_count: 0,
        day_bucket: format!("{:04}{:02}{:02}", now.year(), now.month(), now.day()),
        day_count: 0,
        overrides: TenantLimits { per_hour: Some(5), per_day: None },
        expires_at: now + chrono::Duration::hours(36),
    };
    db.fluent().insert().into("rate_limits").document_id(&tenant).object(&seed).execute::<()>().await.unwrap();

    for _ in 0..5 {
        assert_eq!(rl.check_and_increment(&tenant, Utc::now()).await.unwrap(), RateLimitOutcome::Allowed);
    }
    assert!(matches!(
        rl.check_and_increment(&tenant, Utc::now()).await.unwrap(),
        RateLimitOutcome::TooMany { .. }
    ));
}
```

Note: `chrono::Datelike` and `Timelike` are required for the `.year()/.month()/.hour()` calls in the seed doc and are imported at the top.

- [ ] **Step 2: Run against emulator**

```bash
export FIRESTORE_EMULATOR_HOST=127.0.0.1:8085
export FIRESTORE_PROJECT=test-project
cd cloud-run-compiler && cargo test --test rate_limit -- --ignored
```

Expected: 5 tests pass.

- [ ] **Step 3: Commit**

```bash
git add cloud-run-compiler/
git commit -m "test(compiler): rate limiter emulator-backed tests (limit, rollover, override)"
```

### Task 5.3: Operator note — enable Firestore TTL policy

**Files:**
- Modify: `cloud-run-compiler/deploy.sh` (comment block)

- [ ] **Step 1: Add a comment block to `deploy.sh`** before the `gcloud run deploy` command:

```bash
# RATE LIMIT TTL POLICY (one-time setup per project)
# The rate_limits collection writes an `expires_at` field on every doc.
# Enable Firestore TTL so old buckets are GC'd:
#   gcloud firestore fields ttls update expires_at \
#     --collection-group=rate_limits \
#     --enable-ttl --project="${PROJECT_ID}"
# (Idempotent. Run once per environment.)
```

- [ ] **Step 2: Commit**

```bash
git add cloud-run-compiler/deploy.sh
git commit -m "docs(compiler): operator note for enabling rate_limits TTL policy"
```

**Cross-chunk dependency note for Chunk 9:** the HTTP layer must translate `RateLimitOutcome::TooMany { retry_after_seconds }` into a `429 Too Many Requests` response with a `Retry-After: <seconds>` header. The error body should be `{"error": "rate_limited", "retry_after_seconds": N}`. Verify this is in Chunk 9's handler wiring.

**End of Chunk 5.** Rate limiting is in place. Next chunk: Nostr REST client.

---

## Chunk 6: Nostr REST client (naddr decode + api.divine.video)

Goal: take a `Source` (naddr or array of event ids) and resolve it to a vector of `VideoClipMetadata` records (event id, pubkey, sha256, mime, profile display_name + nip05). All event/profile fetches go through `https://api.divine.video` REST.

**Critical caveat from the spec:** REST responses can flatten events and lose tag data (per `nostr-rest-api-field-mapping-gap`). We request raw event JSON (full tags array) and parse `imeta` ourselves; we never rely on flattened helper fields like a top-level `sha256`.

> **Implementer note:** This chunk assumes a REST shape for `api.divine.video` (e.g. `GET /event/<hex_id>`, `GET /profile/<hex_pubkey>`, `GET /list/<naddr>`). **Verify the actual endpoint paths and response shapes at implementation time** (the funnelcake repo or the `api.divine.video` OpenAPI spec is the source of truth). Adjust the URL templates in `nostr/api_client.rs`; the *structure* of parsing (`imeta` extraction, raw-tags-not-flattened) is what matters.

### Task 6.1: naddr / nevent bech32 decoding (NIP-19)

**Files:**
- Create: `cloud-run-compiler/src/nostr/mod.rs`
- Create: `cloud-run-compiler/src/nostr/naddr.rs`
- Modify: `cloud-run-compiler/src/lib.rs`
- Create: `cloud-run-compiler/tests/nostr_naddr.rs`

NIP-19 TLV format:
- `naddr` = bech32-encoded TLV with: `0=identifier` (the d-tag value), `1=relay` (optional), `2=author` (32 bytes), `3=kind` (4 bytes big-endian u32).
- `nevent` = bech32-encoded TLV with: `0=event_id` (32 bytes), `1=relay` (optional), `2=author` (optional 32 bytes), `3=kind` (optional 4 bytes).

- [ ] **Step 1: Create the module file**

`cloud-run-compiler/src/nostr/mod.rs`:

```rust
// ABOUTME: Nostr-side glue: bech32 decoding + REST client for api.divine.video
pub mod naddr;
pub mod types;
pub mod api_client;
```

- [ ] **Step 2: Stub the types module**

`cloud-run-compiler/src/nostr/types.rs`:

```rust
// ABOUTME: Plain data types for Nostr events and profiles fetched via REST
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrEvent {
    pub id: String,
    pub pubkey: String,
    pub kind: i64,
    pub created_at: i64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    #[serde(default)]
    pub sig: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Profile {
    pub pubkey: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub nip05: Option<String>,
    /// Raw kind-0 content (JSON-encoded), for fields we don't model yet.
    #[serde(default)]
    pub raw_content: Option<String>,
}

/// Parsed `imeta` tag entry. `imeta` is `["imeta", "url <url>", "x <sha256>", "m <mime>", ...]`
#[derive(Debug, Clone, Default)]
pub struct Imeta {
    pub url: Option<String>,
    pub sha256: Option<String>,
    pub mime: Option<String>,
    pub dim: Option<String>,
}

impl Imeta {
    /// Parse a single `imeta` tag (the inner `Vec<String>`, with the leading
    /// "imeta" element). Each subsequent element is "<key> <value>".
    pub fn parse(tag: &[String]) -> Option<Self> {
        if tag.first().map(|s| s.as_str()) != Some("imeta") { return None; }
        let mut out = Imeta::default();
        for entry in tag.iter().skip(1) {
            if let Some((k, v)) = entry.split_once(' ') {
                match k {
                    "url" => out.url = Some(v.to_string()),
                    "x"   => out.sha256 = Some(v.to_string()),
                    "m"   => out.mime = Some(v.to_string()),
                    "dim" => out.dim = Some(v.to_string()),
                    _ => {}
                }
            }
        }
        Some(out)
    }

    /// Find the first `imeta` tag on an event and parse it.
    pub fn first_in(event: &NostrEvent) -> Option<Self> {
        event.tags.iter().find_map(|t| Self::parse(t))
    }
}

/// NIP-19 naddr (kind 3xxxx addressable event reference) decomposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaddrRef {
    pub identifier: String,
    pub author: String,    // 32-byte hex
    pub kind: u32,
    pub relays: Vec<String>,
}

/// NIP-19 nevent reference decomposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeventRef {
    pub event_id: String,  // 32-byte hex
    pub author: Option<String>,
    pub kind: Option<u32>,
    pub relays: Vec<String>,
}
```

- [ ] **Step 3: Write the decoder tests first**

`cloud-run-compiler/tests/nostr_naddr.rs`:

```rust
use divine_compiler::nostr::naddr::{decode_naddr, decode_nevent};

// Fixture naddr/nevent strings can be regenerated using `nak` or the
// `nostr-tools` JS lib. These are deterministic for a given input.
const SAMPLE_NADDR: &str = "naddr1qq8jqv3eyf3lkmf38yjry6r9dgekgepkdcerjwfsdcst2cesxv5xydjsyukxw"; // placeholder; replace at impl time

#[test]
fn imeta_parses_canonical_shape() {
    use divine_compiler::nostr::types::{Imeta, NostrEvent};
    let event = NostrEvent {
        id: "i".into(), pubkey: "p".into(), kind: 34235, created_at: 0,
        content: "".into(), sig: None,
        tags: vec![
            vec!["title".into(), "test".into()],
            vec![
                "imeta".into(),
                "url https://example.com/abc.mp4".into(),
                "x abc123".into(),
                "m video/mp4".into(),
                "dim 1920x1080".into(),
            ],
        ],
    };
    let im = Imeta::first_in(&event).unwrap();
    assert_eq!(im.url.as_deref(), Some("https://example.com/abc.mp4"));
    assert_eq!(im.sha256.as_deref(), Some("abc123"));
    assert_eq!(im.mime.as_deref(), Some("video/mp4"));
    assert_eq!(im.dim.as_deref(), Some("1920x1080"));
}

#[test]
fn imeta_returns_none_when_absent() {
    use divine_compiler::nostr::types::{Imeta, NostrEvent};
    let event = NostrEvent {
        id: "i".into(), pubkey: "p".into(), kind: 1, created_at: 0,
        content: "".into(), sig: None,
        tags: vec![vec!["e".into(), "abc".into()]],
    };
    assert!(Imeta::first_in(&event).is_none());
}

#[test]
#[ignore = "needs real naddr fixture from `nak encode naddr ...`; replace SAMPLE_NADDR and remove this attribute before merging the chunk"]
fn naddr_decode_round_trip() {
    use divine_compiler::nostr::naddr::decode_naddr;
    let n = decode_naddr(SAMPLE_NADDR).expect("decode naddr");
    assert_eq!(n.kind, 34235); // kind embedded in fixture
    assert_eq!(n.author.len(), 64);  // 32 bytes hex-encoded
    assert!(!n.identifier.is_empty());
}

#[test]
#[ignore = "needs real nevent fixture from `nak encode nevent ...`; supply and remove this attribute before merging"]
fn nevent_decode_extracts_event_id() {
    use divine_compiler::nostr::naddr::decode_nevent;
    let n = decode_nevent("nevent1...REPLACE_ME...").expect("decode nevent");
    assert_eq!(n.event_id.len(), 64);
}

#[test]
fn malformed_naddr_returns_err() {
    let r = decode_naddr("not-a-real-naddr");
    assert!(r.is_err());
}
```

- [ ] **Step 4: Run — expect FAIL**

`cd cloud-run-compiler && cargo test --test nostr_naddr` → compile error (decoder fns missing).

- [ ] **Step 5: Implement `src/nostr/naddr.rs`**

```rust
// ABOUTME: NIP-19 TLV bech32 decoding for naddr and nevent
// ABOUTME: Returns plain data structs; verification of decoded fields is the caller's job

use crate::nostr::types::{NaddrRef, NeventRef};
use anyhow::{anyhow, Context, Result};
use bech32::{Bech32, Hrp};

const HRP_NADDR: &str = "naddr";
const HRP_NEVENT: &str = "nevent";

const TLV_SPECIAL: u8 = 0;  // identifier (naddr) or event_id (nevent)
const TLV_RELAY: u8 = 1;
const TLV_AUTHOR: u8 = 2;
const TLV_KIND: u8 = 3;

pub fn decode_naddr(s: &str) -> Result<NaddrRef> {
    let (hrp, data) = decode_bech32(s)?;
    if hrp.as_str() != HRP_NADDR {
        return Err(anyhow!("expected naddr hrp, got {}", hrp.as_str()));
    }
    let tlvs = parse_tlvs(&data)?;
    let identifier = tlvs.iter().find(|(t, _)| *t == TLV_SPECIAL)
        .map(|(_, v)| std::str::from_utf8(v).map(|s| s.to_string()))
        .ok_or_else(|| anyhow!("naddr missing identifier TLV"))?
        .context("identifier not valid utf-8")?;
    let author_bytes = tlvs.iter().find(|(t, _)| *t == TLV_AUTHOR)
        .map(|(_, v)| v.to_vec())
        .ok_or_else(|| anyhow!("naddr missing author TLV"))?;
    if author_bytes.len() != 32 {
        return Err(anyhow!("naddr author must be 32 bytes, got {}", author_bytes.len()));
    }
    let kind_bytes = tlvs.iter().find(|(t, _)| *t == TLV_KIND)
        .map(|(_, v)| v.to_vec())
        .ok_or_else(|| anyhow!("naddr missing kind TLV"))?;
    if kind_bytes.len() != 4 {
        return Err(anyhow!("naddr kind must be 4 bytes, got {}", kind_bytes.len()));
    }
    let kind = u32::from_be_bytes([kind_bytes[0], kind_bytes[1], kind_bytes[2], kind_bytes[3]]);
    let relays = tlvs.iter()
        .filter(|(t, _)| *t == TLV_RELAY)
        .filter_map(|(_, v)| std::str::from_utf8(v).ok().map(str::to_string))
        .collect();
    Ok(NaddrRef { identifier, author: hex::encode(author_bytes), kind, relays })
}

pub fn decode_nevent(s: &str) -> Result<NeventRef> {
    let (hrp, data) = decode_bech32(s)?;
    if hrp.as_str() != HRP_NEVENT {
        return Err(anyhow!("expected nevent hrp, got {}", hrp.as_str()));
    }
    let tlvs = parse_tlvs(&data)?;
    let id_bytes = tlvs.iter().find(|(t, _)| *t == TLV_SPECIAL)
        .map(|(_, v)| v.to_vec())
        .ok_or_else(|| anyhow!("nevent missing event_id TLV"))?;
    if id_bytes.len() != 32 {
        return Err(anyhow!("nevent id must be 32 bytes"));
    }
    let author = tlvs.iter().find(|(t, _)| *t == TLV_AUTHOR)
        .filter(|(_, v)| v.len() == 32)
        .map(|(_, v)| hex::encode(v));
    let kind = tlvs.iter().find(|(t, _)| *t == TLV_KIND)
        .filter(|(_, v)| v.len() == 4)
        .map(|(_, v)| u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
    let relays = tlvs.iter()
        .filter(|(t, _)| *t == TLV_RELAY)
        .filter_map(|(_, v)| std::str::from_utf8(v).ok().map(str::to_string))
        .collect();
    Ok(NeventRef { event_id: hex::encode(id_bytes), author, kind, relays })
}

fn decode_bech32(s: &str) -> Result<(Hrp, Vec<u8>)> {
    let (hrp, data) = bech32::decode(s).context("bech32 decode")?;
    Ok((hrp, data))
}

/// Parse the TLV byte stream: 1 byte type, 1 byte length, N bytes value.
/// Errors on a trailing partial TLV (length byte missing or value truncated)
/// rather than silently dropping it.
fn parse_tlvs(data: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    let mut i = 0;
    let mut out = Vec::new();
    while i < data.len() {
        if i + 2 > data.len() {
            return Err(anyhow!("trailing partial TLV: {} byte(s) left without type+length header", data.len() - i));
        }
        let t = data[i];
        let l = data[i + 1] as usize;
        if i + 2 + l > data.len() {
            return Err(anyhow!("TLV length {} exceeds remaining {}", l, data.len() - i - 2));
        }
        out.push((t, &data[i + 2..i + 2 + l]));
        i += 2 + l;
    }
    Ok(out)
}
```

- [ ] **Step 6: Expose in `src/lib.rs`**

```rust
pub mod nostr;
```

(Append to the existing list of pub mods.)

- [ ] **Step 7: Run — expect PASS for the imeta tests; the naddr/nevent fixture tests remain placeholder until real fixtures are provided**

```bash
cd cloud-run-compiler && cargo test --test nostr_naddr
```

Expected: `imeta_parses_canonical_shape`, `imeta_returns_none_when_absent`, `malformed_naddr_returns_err` pass. The two placeholder tests (`naddr_decode_round_trip`, `nevent_decode_extracts_event_id`) pass trivially (they don't assert anything yet). **Before merging this chunk**, replace `SAMPLE_NADDR` with a real value produced by `nak encode naddr -k 34235 -d <d> -p <author_hex>` and turn the placeholder bodies into real round-trip assertions.

- [ ] **Step 8: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): NIP-19 naddr/nevent decode + imeta tag parser"
```

### Task 6.2: api.divine.video REST client

**Files:**
- Create: `cloud-run-compiler/src/nostr/api_client.rs`
- Create: `cloud-run-compiler/tests/nostr_api_client.rs`

The client is a thin wrapper over `reqwest`. It exposes three calls used by the worker:

- `fetch_event(event_id_hex) → NostrEvent` — single event lookup
- `fetch_profile(pubkey_hex) → Profile` — kind-0 profile lookup, returns Default if not found
- `fetch_list_event(naddr) → NostrEvent` — fetches the list event referenced by an naddr (kind 30000/30001/30005)

> **Endpoint path verification needed at impl time.** Likely shapes (verify against funnelcake / api.divine.video docs):
> - `GET /api/event/<hex_id>` or `GET /api/events/<hex_id>`
> - `GET /api/profile/<hex_pubkey>` or `GET /api/users/<hex_pubkey>`
> - `GET /api/event/<naddr>` (some APIs accept naddr directly; others require we decode it locally and look up by author+kind+identifier).

- [ ] **Step 1: Implement the client**

```rust
// ABOUTME: REST client for api.divine.video
// ABOUTME: Returns raw event JSON; never relies on flattened helper fields (per nostr-rest-api-field-mapping-gap)

use crate::nostr::naddr::decode_naddr;
use crate::nostr::types::{NaddrRef, NostrEvent, Profile};
use anyhow::{anyhow, Context, Result};
use reqwest::{Client, StatusCode};
use std::time::Duration;

/// Distinguished error so callers can apply the spec's drop-and-continue
/// policy (Pipeline step 2c) without string-matching the anyhow message.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Clone)]
pub struct ApiClient {
    base_url: String,
    http: Client,
}

impl ApiClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("divine-compiler/0.1")
            .build()
            .context("build http client")?;
        Ok(Self { base_url: base_url.into(), http })
    }

    pub async fn fetch_event(&self, event_id_hex: &str) -> Result<NostrEvent, FetchError> {
        let url = format!("{}/api/event/{}", self.base_url.trim_end_matches('/'), event_id_hex);
        let resp = self.http.get(&url).send().await
            .map_err(|e| FetchError::Other(anyhow!(e).context("GET event")))?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Err(FetchError::NotFound(event_id_hex.to_string()));
        }
        if !resp.status().is_success() {
            return Err(FetchError::Other(anyhow!("api error {} on {}", resp.status(), url)));
        }
        let val: serde_json::Value = resp.json().await
            .map_err(|e| FetchError::Other(anyhow!(e).context("parse event response")))?;
        let event_val = val.get("event").cloned().unwrap_or(val);
        serde_json::from_value(event_val)
            .map_err(|e| FetchError::Other(anyhow!(e).context("deserialize NostrEvent")))
    }

    pub async fn fetch_profile(&self, pubkey_hex: &str) -> Result<Profile> {
        let url = format!("{}/api/profile/{}", self.base_url.trim_end_matches('/'), pubkey_hex);
        let resp = self.http.get(&url).send().await.context("GET profile")?;
        if resp.status() == StatusCode::NOT_FOUND {
            // Empty profile is fine — caller falls back to display = npub
            return Ok(Profile { pubkey: pubkey_hex.to_string(), ..Profile::default() });
        }
        if !resp.status().is_success() {
            return Err(anyhow!("api error {} on profile {}", resp.status(), pubkey_hex));
        }
        let val: serde_json::Value = resp.json().await.context("parse profile response")?;
        // Common shape: { "pubkey": "...", "content": "<json-string>", "metadata": {...} }
        // We grab nip05 + display_name from `metadata` if present, falling
        // back to parsing `content` (the canonical kind-0 form).
        let metadata = val.get("metadata").cloned();
        let display_name = metadata.as_ref()
            .and_then(|m| m.get("display_name").or_else(|| m.get("name")))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let nip05 = metadata.as_ref()
            .and_then(|m| m.get("nip05"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let raw_content = val.get("content")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        Ok(Profile { pubkey: pubkey_hex.to_string(), display_name, nip05, raw_content })
    }

    pub async fn fetch_list_event(&self, naddr: &str) -> Result<NostrEvent, FetchError> {
        // Try the direct naddr endpoint first. ONLY fall back to addressable
        // lookup on 404 or deserialize-shape mismatch — never swallow 5xx
        // or network errors silently.
        let url = format!("{}/api/event/{}", self.base_url.trim_end_matches('/'), naddr);
        let resp = self.http.get(&url).send().await
            .map_err(|e| FetchError::Other(anyhow!(e).context("GET naddr event")))?;
        match resp.status() {
            StatusCode::OK => {
                let val: serde_json::Value = resp.json().await
                    .map_err(|e| FetchError::Other(anyhow!(e).context("parse naddr event resp")))?;
                let event_val = val.get("event").cloned().unwrap_or(val);
                match serde_json::from_value::<NostrEvent>(event_val) {
                    Ok(ev) => Ok(ev),
                    Err(de_err) => {
                        tracing::warn!(?de_err, %naddr, "naddr direct lookup returned unexpected shape; falling back to addressable");
                        let n: NaddrRef = decode_naddr(naddr).map_err(FetchError::Other)?;
                        self.fetch_addressable(&n.author, n.kind, &n.identifier).await
                    }
                }
            }
            StatusCode::NOT_FOUND => {
                let n: NaddrRef = decode_naddr(naddr).map_err(FetchError::Other)?;
                self.fetch_addressable(&n.author, n.kind, &n.identifier).await
            }
            other => Err(FetchError::Other(anyhow!("api error {} on naddr lookup {}", other, url))),
        }
    }

    async fn fetch_addressable(&self, author: &str, kind: u32, d_tag: &str) -> Result<NostrEvent, FetchError> {
        // TODO(impl): confirm `/api/addressable?author=&kind=&d=` against the
        // api.divine.video OpenAPI spec; this path is invented in the plan.
        let url = format!(
            "{}/api/addressable?author={}&kind={}&d={}",
            self.base_url.trim_end_matches('/'),
            author, kind, urlencoding::encode(d_tag),
        );
        let resp = self.http.get(&url).send().await
            .map_err(|e| FetchError::Other(anyhow!(e).context("GET addressable")))?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Err(FetchError::NotFound(format!("{}/{}/{}", author, kind, d_tag)));
        }
        if !resp.status().is_success() {
            return Err(FetchError::Other(anyhow!("api error {} on addressable {}/{}/{}", resp.status(), author, kind, d_tag)));
        }
        let val: serde_json::Value = resp.json().await
            .map_err(|e| FetchError::Other(anyhow!(e).context("parse addressable resp")))?;
        let event_val = val.get("event").cloned().unwrap_or(val);
        serde_json::from_value(event_val)
            .map_err(|e| FetchError::Other(anyhow!(e).context("deserialize addressable event")))
    }
}
```

- [ ] **Step 2: Add `urlencoding` to `Cargo.toml`**

```toml
urlencoding = "2"
```

- [ ] **Step 3: Write integration tests using a mock HTTP server**

```rust
// cloud-run-compiler/tests/nostr_api_client.rs
use divine_compiler::nostr::api_client::ApiClient;
use divine_compiler::nostr::types::{Imeta, NostrEvent};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn fetch_event_returns_full_tags_not_flattened() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/event/abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "event": {
                "id": "abc123",
                "pubkey": "deadbeef",
                "kind": 34235,
                "created_at": 1700000000,
                "tags": [
                    ["title", "Hello"],
                    ["imeta", "url https://media.divine.video/cafebabe", "x cafebabe", "m video/mp4"]
                ],
                "content": "",
                "sig": null
            }
        })))
        .mount(&server)
        .await;
    let client = ApiClient::new(server.uri()).unwrap();
    let event: NostrEvent = client.fetch_event("abc123").await.unwrap();
    let im = Imeta::first_in(&event).expect("imeta present");
    assert_eq!(im.sha256.as_deref(), Some("cafebabe"));
    assert_eq!(im.url.as_deref(), Some("https://media.divine.video/cafebabe"));
}

#[tokio::test]
async fn fetch_event_handles_unwrapped_top_level_event() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/event/abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "abc", "pubkey": "p", "kind": 34235,
            "created_at": 0, "tags": [], "content": "", "sig": null
        })))
        .mount(&server)
        .await;
    let client = ApiClient::new(server.uri()).unwrap();
    let event = client.fetch_event("abc").await.unwrap();
    assert_eq!(event.id, "abc");
}

#[tokio::test]
async fn fetch_event_404_is_distinguished_not_found() {
    use divine_compiler::nostr::api_client::FetchError;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/event/missing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let client = ApiClient::new(server.uri()).unwrap();
    let err = client.fetch_event("missing").await.unwrap_err();
    assert!(matches!(err, FetchError::NotFound(_)));
}

#[tokio::test]
async fn flattened_helper_sha256_is_ignored() {
    // The api may helpfully add a top-level `sha256` field. We MUST NOT use
    // it — the source of truth is the imeta tag in `tags`. Guards the
    // nostr-rest-api-field-mapping-gap trap.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/event/flat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "flat", "pubkey": "p", "kind": 34235,
            "created_at": 0, "tags": [], "content": "",
            "sig": null,
            "sha256": "TRAP_DO_NOT_USE"
        })))
        .mount(&server)
        .await;
    let client = ApiClient::new(server.uri()).unwrap();
    let event = client.fetch_event("flat").await.unwrap();
    assert!(Imeta::first_in(&event).is_none(),
        "must not consume flattened sha256; only imeta tag counts");
}

#[tokio::test]
async fn fetch_profile_missing_returns_empty_profile() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/profile/unknown"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let client = ApiClient::new(server.uri()).unwrap();
    let p = client.fetch_profile("unknown").await.unwrap();
    assert_eq!(p.pubkey, "unknown");
    assert!(p.nip05.is_none());
}

#[tokio::test]
async fn fetch_profile_extracts_nip05_and_display_name() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/profile/alice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "pubkey": "alice",
            "metadata": { "display_name": "Alice", "nip05": "alice@example.com" }
        })))
        .mount(&server)
        .await;
    let client = ApiClient::new(server.uri()).unwrap();
    let p = client.fetch_profile("alice").await.unwrap();
    assert_eq!(p.display_name.as_deref(), Some("Alice"));
    assert_eq!(p.nip05.as_deref(), Some("alice@example.com"));
}
```

- [ ] **Step 4: Add `wiremock` to `[dev-dependencies]`**

```toml
[dev-dependencies]
wiremock = "0.6"
# (uuid already there from Chunk 3)
```

- [ ] **Step 5: Run — expect PASS**

```bash
cd cloud-run-compiler && cargo test --test nostr_api_client
```

Expected: 6 tests pass (event-with-full-tags, top-level-event-shape, 404-distinguished, profile-missing-default, profile-nip05-extract, flattened-helper-trap).

- [ ] **Step 6: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): api.divine.video REST client with mock-tested event+profile fetch"
```

**End of Chunk 6.** Nostr lookups work. Next chunk: blossom IO (download source MP4s + upload comp outputs).

---

## Chunk 7: Blossom IO (download, moderation check, GCS upload)

Goal: download source MP4s from `https://media.divine.video/<sha256>` with bounded concurrency, check moderation status before download, upload finished comp outputs to the GCS bucket `divine-blossom-media`.

> **Endpoint verification at impl time:** the moderation status endpoint is likely served by the Fastly Compute service at `https://media.divine.video/<sha256>/info` or `https://blossom.dvines.org/<sha256>/info` and returns JSON including a `status` field. Verify against the existing `src/` Fastly Compute code (look for `/info` handler) before implementing.

### Task 7.1: `BlobStatus` type + moderation check

**Files:**
- Create: `cloud-run-compiler/src/blossom/mod.rs`
- Create: `cloud-run-compiler/src/blossom/moderation.rs`
- Modify: `cloud-run-compiler/src/lib.rs`
- Create: `cloud-run-compiler/tests/blossom_moderation.rs`

- [ ] **Step 1: Create the module and types**

`cloud-run-compiler/src/blossom/mod.rs`:

```rust
// ABOUTME: Blossom blob IO: download with concurrency cap, moderation gate, GCS upload
pub mod moderation;
pub mod download;
pub mod upload;

use serde::{Deserialize, Serialize};

/// Mirrors the spec's blob status enum (`Active | Restricted | AgeRestricted`),
/// plus a synthetic `Deleted` value the moderation client emits on HTTP 404 so
/// callers can drop the clip without a separate not-found code path. `Deleted`
/// is NEVER returned by the upstream `/info` JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum BlobStatus {
    Active,
    Restricted,
    AgeRestricted,
    Deleted,
}

impl BlobStatus {
    pub fn is_publicly_fetchable(self) -> bool { matches!(self, BlobStatus::Active) }
}
```

- [ ] **Step 2: Implement the moderation client**

`cloud-run-compiler/src/blossom/moderation.rs`:

```rust
// ABOUTME: Check a blob's moderation status before downloading it
// ABOUTME: Calls https://media.divine.video/<sha256>/info; 404 → Deleted; 5xx/network errors propagate as Err

use crate::blossom::BlobStatus;
use anyhow::{anyhow, Context, Result};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use std::time::Duration;

#[derive(Deserialize)]
struct InfoResponse {
    #[serde(default)]
    status: Option<BlobStatus>,
    #[serde(default, alias = "moderationStatus")]
    moderation_status: Option<BlobStatus>,
}

pub struct ModerationClient {
    base_url: String,
    http: Client,
}

impl ModerationClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent("divine-compiler/0.1")
            .build()
            .context("build moderation http client")?;
        Ok(Self { base_url: base_url.into(), http })
    }

    /// Returns the blob's status. `404` is reported as `Deleted` so callers
    /// can drop it without bothering to attempt download.
    pub async fn check(&self, sha256: &str) -> Result<BlobStatus> {
        // TODO(impl): verify /info endpoint shape against Fastly Compute src/.
        let url = format!("{}/{}/info", self.base_url.trim_end_matches('/'), sha256);
        let resp = self.http.get(&url).send().await.context("GET blob info")?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(BlobStatus::Deleted);
        }
        if !resp.status().is_success() {
            return Err(anyhow!("blob info {} → {}", url, resp.status()));
        }
        let body: InfoResponse = resp.json().await.context("parse blob info response")?;
        Ok(body.status.or(body.moderation_status).unwrap_or(BlobStatus::Active))
    }
}
```

- [ ] **Step 3: Tests with `wiremock`**

`cloud-run-compiler/tests/blossom_moderation.rs`:

```rust
use divine_compiler::blossom::moderation::ModerationClient;
use divine_compiler::blossom::BlobStatus;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn active_status_is_publicly_fetchable() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/abc/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "status": "Active" })))
        .mount(&server).await;
    let c = ModerationClient::new(server.uri()).unwrap();
    let s = c.check("abc").await.unwrap();
    assert_eq!(s, BlobStatus::Active);
    assert!(s.is_publicly_fetchable());
}

#[tokio::test]
async fn restricted_status_not_fetchable() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/abc/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "status": "Restricted" })))
        .mount(&server).await;
    let s = ModerationClient::new(server.uri()).unwrap().check("abc").await.unwrap();
    assert_eq!(s, BlobStatus::Restricted);
    assert!(!s.is_publicly_fetchable());
}

#[tokio::test]
async fn age_restricted_status_not_fetchable() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/abc/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "status": "AgeRestricted" })))
        .mount(&server).await;
    let s = ModerationClient::new(server.uri()).unwrap().check("abc").await.unwrap();
    assert_eq!(s, BlobStatus::AgeRestricted);
    assert!(!s.is_publicly_fetchable());
}

#[tokio::test]
async fn missing_blob_returns_deleted() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/abc/info"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server).await;
    let s = ModerationClient::new(server.uri()).unwrap().check("abc").await.unwrap();
    assert_eq!(s, BlobStatus::Deleted);
}

#[tokio::test]
async fn accepts_camelcase_moderation_status_alias() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/abc/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "moderationStatus": "Active" })))
        .mount(&server).await;
    let s = ModerationClient::new(server.uri()).unwrap().check("abc").await.unwrap();
    assert_eq!(s, BlobStatus::Active);
}

#[tokio::test]
async fn five_xx_propagates_as_err() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/abc/info"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server).await;
    let r = ModerationClient::new(server.uri()).unwrap().check("abc").await;
    assert!(r.is_err(), "5xx must propagate; do not silently treat as Active");
}

#[test]
fn deleted_status_is_not_publicly_fetchable() {
    assert!(!BlobStatus::Deleted.is_publicly_fetchable());
}
```

- [ ] **Step 4: Expose in `src/lib.rs`** — add `pub mod blossom;`.

- [ ] **Step 5: Run tests** — `cargo test --test blossom_moderation`. Expected: 7 pass (4 status mappings + camelCase alias + 5xx propagation + Deleted-not-fetchable unit test).

- [ ] **Step 6: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): blossom moderation check (Active/Restricted/AgeRestricted/Deleted)"
```

### Task 7.2: Bounded-concurrency download

**Files:**
- Create: `cloud-run-compiler/src/blossom/download.rs`
- Create: `cloud-run-compiler/tests/blossom_download.rs`

- [ ] **Step 1: Implement**

```rust
// ABOUTME: Download blobs from media.divine.video to a temp dir
// ABOUTME: Bounded by a semaphore; HEAD for total-size estimate before download

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::{Client, StatusCode};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct DownloadClient {
    base_url: String,
    http: Client,
}

#[derive(Debug)]
pub struct Downloaded {
    pub sha256: String,
    pub path: PathBuf,
    pub bytes: u64,
}

impl DownloadClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .user_agent("divine-compiler/0.1")
            .build()
            .context("build download http client")?;
        Ok(Self { base_url: base_url.into(), http })
    }

    pub async fn head_size(&self, sha256: &str) -> Result<u64> {
        let url = format!("{}/{}", self.base_url.trim_end_matches('/'), sha256);
        let resp = self.http.head(&url).send().await.context("HEAD blob")?;
        if !resp.status().is_success() {
            return Err(anyhow!("HEAD {} → {}", url, resp.status()));
        }
        let len = resp
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| anyhow!("missing Content-Length on HEAD {}", url))?;
        Ok(len)
    }

    pub async fn download_one(&self, sha256: &str, dest: &Path) -> Result<Downloaded> {
        let url = format!("{}/{}", self.base_url.trim_end_matches('/'), sha256);
        let resp = self.http.get(&url).send().await.context("GET blob")?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Err(anyhow!("blob {} not found", sha256));
        }
        if !resp.status().is_success() {
            return Err(anyhow!("GET {} → {}", url, resp.status()));
        }
        let mut file = fs::File::create(dest).await.context("create download file")?;
        let mut stream = resp.bytes_stream();
        let mut total: u64 = 0;
        while let Some(chunk) = stream.next().await {
            let chunk: Bytes = chunk.context("read download chunk")?;
            file.write_all(&chunk).await.context("write download chunk")?;
            total += chunk.len() as u64;
        }
        file.flush().await.ok();
        Ok(Downloaded { sha256: sha256.to_string(), path: dest.to_path_buf(), bytes: total })
    }

    /// Download many sha256s into `dir`, capped at `concurrency` in-flight.
    /// Returns one `Result` per input in the same order.
    pub async fn download_many(
        &self,
        sha256s: &[String],
        dir: &Path,
        concurrency: usize,
    ) -> Vec<Result<Downloaded>> {
        let sem = Arc::new(Semaphore::new(concurrency));
        let mut tasks = FuturesUnordered::new();
        for (idx, sha) in sha256s.iter().enumerate() {
            let sem = sem.clone();
            let me = self.clone();
            let sha = sha.clone();
            let dest = dir.join(&sha);
            tasks.push(async move {
                let _permit = sem.acquire_owned().await.unwrap();
                let r = me.download_one(&sha, &dest).await;
                (idx, r)
            });
        }
        let mut out: Vec<Option<Result<Downloaded>>> = (0..sha256s.len()).map(|_| None).collect();
        while let Some((idx, r)) = tasks.next().await {
            out[idx] = Some(r);
        }
        out.into_iter().map(|o| o.expect("all slots filled")).collect()
    }
}
```

- [ ] **Step 2: Tests**

```rust
// cloud-run-compiler/tests/blossom_download.rs
use divine_compiler::blossom::download::DownloadClient;
use std::fs;
use tempfile::tempdir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn head_size_returns_content_length() {
    let server = MockServer::start().await;
    Mock::given(method("HEAD")).and(path("/abc"))
        .respond_with(ResponseTemplate::new(200).insert_header("Content-Length", "12345"))
        .mount(&server).await;
    let c = DownloadClient::new(server.uri()).unwrap();
    assert_eq!(c.head_size("abc").await.unwrap(), 12345);
}

#[tokio::test]
async fn download_one_writes_bytes_to_dest() {
    let server = MockServer::start().await;
    let payload = b"hello world".to_vec();
    Mock::given(method("GET")).and(path("/abc"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(payload.clone()))
        .mount(&server).await;
    let dir = tempdir().unwrap();
    let dest = dir.path().join("abc");
    let c = DownloadClient::new(server.uri()).unwrap();
    let d = c.download_one("abc", &dest).await.unwrap();
    assert_eq!(d.bytes, payload.len() as u64);
    assert_eq!(fs::read(&dest).unwrap(), payload);
}

#[tokio::test]
async fn download_many_preserves_input_order() {
    let server = MockServer::start().await;
    for id in &["a", "b", "c"] {
        Mock::given(method("GET")).and(path(format!("/{}", id)))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(format!("body-{}", id).into_bytes()))
            .mount(&server).await;
    }
    let dir = tempdir().unwrap();
    let c = DownloadClient::new(server.uri()).unwrap();
    let results = c.download_many(
        &["a".into(), "b".into(), "c".into()],
        dir.path(),
        2,
    ).await;
    assert_eq!(results.len(), 3);
    for (i, expected) in ["a", "b", "c"].iter().enumerate() {
        let d = results[i].as_ref().expect("download ok");
        assert_eq!(d.sha256, *expected);
    }
}

#[tokio::test]
async fn download_many_one_failure_does_not_poison_others() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/a"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"a-body".to_vec()))
        .mount(&server).await;
    Mock::given(method("GET")).and(path("/b"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server).await;
    Mock::given(method("GET")).and(path("/c"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"c-body".to_vec()))
        .mount(&server).await;
    let dir = tempdir().unwrap();
    let c = DownloadClient::new(server.uri()).unwrap();
    let r = c.download_many(&["a".into(), "b".into(), "c".into()], dir.path(), 4).await;
    assert!(r[0].is_ok());
    assert!(r[1].is_err());
    assert!(r[2].is_ok());
}
```

- [ ] **Step 3: Run** — `cargo test --test blossom_download`. Expected: 4 pass.

- [ ] **Step 4: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): bounded-concurrency blob download with HEAD size check"
```

### Task 7.3: GCS upload for finished outputs

**Files:**
- Create: `cloud-run-compiler/src/blossom/upload.rs`

- [ ] **Step 1: Implement**

```rust
// ABOUTME: Upload finished comp MP4 to the divine-blossom-media GCS bucket
// ABOUTME: Computes sha256 of bytes, stores at gs://<bucket>/<sha256>, returns descriptor

use anyhow::{Context, Result};
use google_cloud_storage::client::{Client as GcsClient, ClientConfig};
use google_cloud_storage::http::objects::upload::{Media, UploadObjectRequest, UploadType};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::fs;

#[derive(Debug, Clone)]
pub struct UploadResult {
    pub sha256: String,
    pub size: u64,
    pub url: String,
}

pub struct GcsUploader {
    client: GcsClient,
    bucket: String,
    public_base_url: String,
}

impl GcsUploader {
    pub async fn new(bucket: impl Into<String>, public_base_url: impl Into<String>) -> Result<Self> {
        let config = ClientConfig::default()
            .with_auth()
            .await
            .context("gcs client config (ADC)")?;
        let client = GcsClient::new(config);
        Ok(Self { client, bucket: bucket.into(), public_base_url: public_base_url.into() })
    }

    pub async fn upload_file(&self, src: &Path, content_type: &str) -> Result<UploadResult> {
        let bytes = fs::read(src).await.context("read comp output for upload")?;
        let sha256 = hex::encode(Sha256::digest(&bytes));
        let size = bytes.len() as u64;

        let req = UploadObjectRequest { bucket: self.bucket.clone(), ..Default::default() };

        // TODO(impl): choose ONE of these two paths after verifying against
        // google-cloud-storage 0.17 docs at impl time. Both upload bytes and
        // set Content-Type; differ only in mechanism. Do NOT ship the
        // assign-after-upload pattern from earlier drafts of this plan — it
        // doesn't actually patch the GCS object.
        //
        //   Path A (Multipart, recommended): UploadType::Multipart carries
        //   metadata + bytes in one request. Construct an `Object` with
        //   `name = sha256` and `content_type = Some(...)`, then call
        //   `upload_object(&req, bytes, &UploadType::Multipart(Box::new(obj)))`.
        //
        //   Path B (Simple + patch): use the current Simple upload, then call
        //   `patch_object(...)` with a `PatchObjectRequest` setting
        //   `content_type`. Two round-trips but works with the older API.
        //
        // Pseudocode for Path A:
        //   let mut obj = Object::default();
        //   obj.name = sha256.clone();
        //   obj.content_type = Some(content_type.into());
        //   let upload_type = UploadType::Multipart(Box::new(obj));
        //   self.client.upload_object(&req, bytes, &upload_type).await?;
        let _ = (content_type,); // suppress unused-var warning until impl chooses
        let media = Media::new(sha256.clone());
        let upload_type = UploadType::Simple(media);
        self.client
            .upload_object(&req, bytes, &upload_type)
            .await
            .context("gcs upload_object")?;

        let url = format!("{}/{}", self.public_base_url.trim_end_matches('/'), sha256);
        Ok(UploadResult { sha256, size, url })
    }
}
```

> **Memory note (follow-up):** `fs::read` slurps the whole file. For comps up to ~200 MB × 3 aspects × 4 concurrent jobs = ~2.4 GB peak, well within the 16 GiB instance. Streaming upload via `tokio::fs::File` + chunked PUT is a future optimization; not v1 scope.

- [ ] **Step 2: No unit test for this** — GCS upload integration is exercised by the smoke test in Chunk 10. Cover with compile-only here.

Run: `cd cloud-run-compiler && cargo build --tests`. Expected: compiles.

- [ ] **Step 3: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): GCS uploader for finished comp MP4s"
```

**End of Chunk 7.** All blob IO works. Next chunk: render pipeline.

---

## Chunk 8a: Render pipeline — probe and filtergraph builders (pure functions)

Goal: implement `ffprobe` invocation + the **pure-function** filtergraph builders for fit modes and overlays. No FFmpeg execution yet; that's Chunk 8b. Pure functions are easy to test exhaustively.

### Task 8a.1: `render/mod.rs` + types + ffprobe

**Files:**
- Create: `cloud-run-compiler/src/render/mod.rs`
- Create: `cloud-run-compiler/src/render/probe.rs`
- Modify: `cloud-run-compiler/src/lib.rs`
- Create: `cloud-run-compiler/tests/render_probe.rs`

- [ ] **Step 1: Create the module**

`cloud-run-compiler/src/render/mod.rs`:

```rust
// ABOUTME: Render pipeline — probe, fit/overlay filtergraph construction, FFmpeg execution
pub mod probe;
pub mod fit;
pub mod overlay;
pub mod ffmpeg;

/// Resolved target dimensions for a given Aspect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetDim {
    pub width: u32,
    pub height: u32,
}

impl From<crate::job::types::Aspect> for TargetDim {
    fn from(a: crate::job::types::Aspect) -> Self {
        use crate::job::types::Aspect::*;
        match a {
            Vertical   => TargetDim { width: 1080, height: 1920 },
            Square     => TargetDim { width: 1080, height: 1080 },
            Horizontal => TargetDim { width: 1920, height: 1080 },
        }
    }
}
```

- [ ] **Step 2: Implement probe**

`cloud-run-compiler/src/render/probe.rs`:

```rust
// ABOUTME: ffprobe wrapper — extracts duration, dimensions, codec, rotation
use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::path::Path;
use tokio::process::Command;

#[derive(Debug, Clone, PartialEq)]
pub struct ProbeInfo {
    pub duration_sec: f64,
    pub width: u32,
    pub height: u32,
    pub codec: String,
    /// Degrees: 0, 90, 180, 270.
    pub rotation: i32,
}

#[derive(Deserialize)]
struct FfprobeOut {
    streams: Vec<Stream>,
    format: Format,
}

#[derive(Deserialize)]
struct Stream {
    codec_type: String,
    #[serde(default)] codec_name: String,
    #[serde(default)] width: u32,
    #[serde(default)] height: u32,
    #[serde(default)] tags: Option<StreamTags>,
    #[serde(default)] side_data_list: Option<Vec<SideData>>,
}

#[derive(Deserialize, Default)]
struct StreamTags { #[serde(default)] rotate: Option<String> }

#[derive(Deserialize)]
struct SideData { #[serde(default)] rotation: Option<i32>, #[serde(default, rename = "side_data_type")] _ty: String }

#[derive(Deserialize)]
struct Format { #[serde(default)] duration: String }

pub async fn probe(file: &Path) -> Result<ProbeInfo> {
    let out = Command::new("ffprobe")
        .args([
            "-v", "error",
            "-print_format", "json",
            "-show_format",
            "-show_streams",
            "-show_entries", "stream=codec_type,codec_name,width,height:stream_side_data=rotation:stream_tags=rotate:format=duration",
        ])
        .arg(file)
        .output()
        .await
        .context("spawn ffprobe")?;
    if !out.status.success() {
        return Err(anyhow!("ffprobe failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let parsed: FfprobeOut = serde_json::from_slice(&out.stdout).context("parse ffprobe json")?;
    let video = parsed
        .streams
        .iter()
        .find(|s| s.codec_type == "video")
        .ok_or_else(|| anyhow!("no video stream in {:?}", file))?;
    let duration_sec = parsed.format.duration.parse::<f64>().unwrap_or(0.0);
    // Rotation: prefer modern side_data_list (display matrix), fall back to legacy tags.rotate
    let rotation = video
        .side_data_list
        .as_ref()
        .and_then(|list| list.iter().find_map(|s| s.rotation))
        .or_else(|| video.tags.as_ref().and_then(|t| t.rotate.as_ref().and_then(|r| r.parse::<i32>().ok())))
        .unwrap_or(0)
        .rem_euclid(360);
    Ok(ProbeInfo {
        duration_sec,
        width: video.width,
        height: video.height,
        codec: video.codec_name.clone(),
        rotation,
    })
}
```

- [ ] **Step 3: Tests against tiny fixture clips**

Note: ffprobe tests need a real video file. Build one in-test with FFmpeg's `lavfi` source.

```rust
// cloud-run-compiler/tests/render_probe.rs
use divine_compiler::render::probe::probe;
use tempfile::tempdir;
use tokio::process::Command;

async fn make_clip(out_path: &std::path::Path, w: u32, h: u32, sec: f32) {
    let status = Command::new("ffmpeg")
        .args([
            "-y",
            "-f", "lavfi",
            "-i", &format!("color=c=red:s={}x{}:d={}", w, h, sec),
            "-c:v", "libx264",
            "-pix_fmt", "yuv420p",
        ])
        .arg(out_path)
        .status()
        .await
        .expect("spawn ffmpeg");
    assert!(status.success());
}

#[tokio::test]
#[ignore = "requires ffmpeg + ffprobe in PATH"]
async fn probe_reads_dimensions_and_duration() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("clip.mp4");
    make_clip(&p, 640, 480, 2.0).await;
    let info = probe(&p).await.unwrap();
    assert_eq!(info.width, 640);
    assert_eq!(info.height, 480);
    assert!((info.duration_sec - 2.0).abs() < 0.2);
    assert_eq!(info.codec, "h264");
    assert_eq!(info.rotation, 0);
}

#[tokio::test]
#[ignore = "requires ffmpeg + ffprobe in PATH"]
async fn probe_errors_on_non_video() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("nope.txt");
    tokio::fs::write(&p, b"not a video").await.unwrap();
    assert!(probe(&p).await.is_err());
}
```

- [ ] **Step 4: Run (tests gated by ffmpeg availability)**

```bash
cd cloud-run-compiler && cargo test --test render_probe -- --ignored
```

Expected: 2 tests pass when ffmpeg+ffprobe are on PATH.

- [ ] **Step 5: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): ffprobe wrapper with rotation + duration extraction"
```

### Task 8a.2: Fit filtergraph builders

Goal: produce the FFmpeg filter string that transforms an input stream (label `[v_in]`) into a target-aspect output (label `[v_fit]`) per the three fit modes. Pure functions, exhaustively testable.

**Files:**
- Create: `cloud-run-compiler/src/render/fit.rs`
- Create: `cloud-run-compiler/tests/render_fit.rs`

- [ ] **Step 1: Implement**

```rust
// ABOUTME: Build the FFmpeg filtergraph fragment for a single clip's fit-to-target transform
// ABOUTME: blur-pad, center-crop, letterbox; all produce a stream labeled [out_label]

use crate::job::types::Fit;
use crate::render::TargetDim;

pub fn fit_filter(input_label: &str, output_label: &str, fit: Fit, target: TargetDim) -> String {
    let (w, h) = (target.width, target.height);
    match fit {
        Fit::BlurPad => {
            // Two parallel chains: scaled foreground, blurred background; overlay center.
            // Foreground: scale to fit, preserving aspect.
            // Background: scale to fill, boxblur.
            format!(
                "[{input}]split=2[bg_in][fg_in];\
                 [bg_in]scale={w}:{h}:force_original_aspect_ratio=increase,crop={w}:{h},boxblur=20:5[bg];\
                 [fg_in]scale={w}:{h}:force_original_aspect_ratio=decrease[fg];\
                 [bg][fg]overlay=(W-w)/2:(H-h)/2[{out}]",
                input = input_label, out = output_label, w = w, h = h,
            )
        }
        Fit::CenterCrop => format!(
            "[{input}]scale={w}:{h}:force_original_aspect_ratio=increase,crop={w}:{h}[{out}]",
            input = input_label, out = output_label, w = w, h = h,
        ),
        Fit::Letterbox => format!(
            "[{input}]scale={w}:{h}:force_original_aspect_ratio=decrease,\
             pad={w}:{h}:(ow-iw)/2:(oh-ih)/2:color=black[{out}]",
            input = input_label, out = output_label, w = w, h = h,
        ),
    }
}
```

- [ ] **Step 2: Tests**

```rust
// cloud-run-compiler/tests/render_fit.rs
use divine_compiler::job::types::Fit;
use divine_compiler::render::{fit::fit_filter, TargetDim};

const T_VERT: TargetDim = TargetDim { width: 1080, height: 1920 };

#[test]
fn blur_pad_uses_split_overlay() {
    let f = fit_filter("v0", "vfit0", Fit::BlurPad, T_VERT);
    assert!(f.contains("split=2"), "{}", f);
    assert!(f.contains("boxblur"), "{}", f);
    assert!(f.contains("overlay=(W-w)/2:(H-h)/2"), "{}", f);
    assert!(f.starts_with("[v0]"));
    assert!(f.ends_with("[vfit0]"));
}

#[test]
fn center_crop_uses_increase_then_crop() {
    let f = fit_filter("v0", "vfit0", Fit::CenterCrop, T_VERT);
    assert!(f.contains("force_original_aspect_ratio=increase"));
    assert!(f.contains("crop=1080:1920"));
    assert!(!f.contains("boxblur"));
    assert!(!f.contains("pad="));
}

#[test]
fn letterbox_uses_decrease_then_pad_black() {
    let f = fit_filter("v0", "vfit0", Fit::Letterbox, T_VERT);
    assert!(f.contains("force_original_aspect_ratio=decrease"));
    assert!(f.contains("pad=1080:1920"));
    assert!(f.contains("color=black"));
}

#[test]
fn target_dim_from_aspect_matches_spec_resolutions() {
    use divine_compiler::job::types::Aspect;
    assert_eq!(TargetDim::from(Aspect::Vertical),   TargetDim { width: 1080, height: 1920 });
    assert_eq!(TargetDim::from(Aspect::Square),     TargetDim { width: 1080, height: 1080 });
    assert_eq!(TargetDim::from(Aspect::Horizontal), TargetDim { width: 1920, height: 1080 });
}

#[test]
fn fit_filter_works_for_all_aspect_ratios() {
    use divine_compiler::job::types::Aspect;
    for aspect in [Aspect::Vertical, Aspect::Square, Aspect::Horizontal] {
        let target = TargetDim::from(aspect);
        for fit in [Fit::BlurPad, Fit::CenterCrop, Fit::Letterbox] {
            let f = fit_filter("v", "out", fit, target);
            assert!(f.starts_with("[v]"), "aspect={:?} fit={:?}: {}", aspect, fit, f);
            assert!(f.ends_with("[out]"), "aspect={:?} fit={:?}: {}", aspect, fit, f);
            assert!(f.contains(&format!("{}", target.width)));
            assert!(f.contains(&format!("{}", target.height)));
        }
    }
}
```

- [ ] **Step 3: Run** — `cargo test --test render_fit`. Expected: 5 pass.

- [ ] **Step 4: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): pure-function fit-mode filtergraph builders (blur-pad, center-crop, letterbox)"
```

### Task 8a.3: Overlay filtergraph (logo + per-clip drawtext credits)

The overlay layer takes the fitted `[v_fit_N]` stream and stamps:
1. A semi-transparent logo PNG at a corner, throughout the clip.
2. A per-clip credit drawtext that fades in over 0.3s, holds, fades out over 0.3s — total duration `credit.duration_ms` from the request, starting at the clip's start.

**Files:**
- Create: `cloud-run-compiler/src/render/overlay.rs`
- Create: `cloud-run-compiler/tests/render_overlay.rs`

- [ ] **Step 1: Implement**

```rust
// ABOUTME: Filtergraph builders for the logo overlay and per-clip credit drawtext
// ABOUTME: Both operate on a fitted [v_in] stream; chain logo then credit

use crate::job::types::{Watermark, WatermarkPosition, Credit, CreditMode};

/// Logo overlay. Returns a filtergraph fragment that consumes `[input_label]`
/// and `[logo_label]` and produces `[output_label]`.
///
/// The caller is responsible for adding the logo PNG as an input and labeling
/// it; this just chains the overlay filter.
pub fn logo_overlay_filter(
    input_label: &str,
    logo_label: &str,
    output_label: &str,
    target_w: u32,
    wm: &Watermark,
) -> String {
    if !wm.enabled {
        // No-op: copy input to output via null filter so labels still line up.
        return format!("[{}]null[{}]", input_label, output_label);
    }
    // Logo width = 12% of frame width; height auto.
    let logo_w = (target_w as f32 * 0.12).round() as u32;
    // Position: 16 px margin from the chosen corner.
    let (x, y) = match wm.position {
        WatermarkPosition::TopLeft     => ("16".to_string(), "16".to_string()),
        WatermarkPosition::TopRight    => (format!("W-w-16"), "16".to_string()),
        WatermarkPosition::BottomLeft  => ("16".to_string(), format!("H-h-16")),
        WatermarkPosition::BottomRight => (format!("W-w-16"), format!("H-h-16")),
    };
    // Scale logo, apply per-channel opacity by multiplying alpha
    let alpha = wm.opacity.clamp(0.0, 1.0);
    format!(
        "[{logo}]scale={lw}:-1,format=rgba,colorchannelmixer=aa={a}[logo_s];\
         [{input}][logo_s]overlay={x}:{y}[{out}]",
        logo = logo_label, lw = logo_w, a = alpha,
        input = input_label, x = x, y = y, out = output_label,
    )
}

/// One credit overlay per clip. The drawtext is gated to `[start_sec, start_sec + duration_sec]`
/// via `enable=between(t,a,b)`.
pub fn credit_drawtext_filter(
    input_label: &str,
    output_label: &str,
    credit: &Credit,
    text: &str,        // already-formatted "Alice (@alice@example.com)" etc.
    start_sec: f64,
    target_h: u32,
) -> String {
    if matches!(credit.mode, CreditMode::Off) || text.is_empty() {
        return format!("[{}]null[{}]", input_label, output_label);
    }
    let duration_sec = (credit.duration_ms as f64) / 1000.0;
    let end = start_sec + duration_sec;
    let fade_in_end = start_sec + 0.3;
    let fade_out_start = end - 0.3;
    // Position lower-third: y = 78% of frame height
    let y = (target_h as f32 * 0.78).round() as u32;
    // drawtext escaping. The text is inside single-quoted `text='...'`. We must
    // escape: backslash, comma (filter arg separator), colon (option separator),
    // percent (drawtext %{...} macro trigger), and single-quote (string terminator).
    // Backslash MUST be replaced first so subsequent escapes' added backslashes
    // aren't doubled.
    let escaped = text
        .replace('\\', "\\\\")
        .replace(',', "\\,")
        .replace(':', "\\:")
        .replace('%', "\\%")
        .replace('\'', "\\'");
    // `enable` toggles the filter on/off (hard cut at window boundaries);
    // `alpha` shapes the fade envelope INSIDE the window. Both are needed —
    // `alpha` alone would still render outside the window (clamped), wasting
    // GPU; `enable` alone would pop the text on/off without a fade.
    format!(
        "[{input}]drawtext=fontfile=/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf:\
         text='{text}':\
         x=(w-text_w)/2:y={y}:\
         fontsize=42:\
         fontcolor=white:\
         box=1:boxcolor=black@0.55:boxborderw=12:\
         enable='between(t,{s},{e})':\
         alpha='if(lt(t,{fi}),(t-{s})/0.3, if(gt(t,{fo}), ({e}-t)/0.3, 1))'\
         [{out}]",
        input = input_label,
        text = escaped,
        y = y,
        s = format!("{:.3}", start_sec),
        e = format!("{:.3}", end),
        fi = format!("{:.3}", fade_in_end),
        fo = format!("{:.3}", fade_out_start),
        out = output_label,
    )
}

/// Format the human-readable credit string from profile fields.
pub fn format_credit_text(display_name: Option<&str>, nip05: Option<&str>, pubkey_hex: &str) -> String {
    match (display_name, nip05) {
        (Some(d), Some(n)) => format!("{} • {}", d, n),
        (Some(d), None)    => d.to_string(),
        (None, Some(n))    => n.to_string(),
        (None, None)       => format!("npub: {}…", &pubkey_hex[..8.min(pubkey_hex.len())]),
    }
}
```

- [ ] **Step 2: Tests**

```rust
// cloud-run-compiler/tests/render_overlay.rs
use divine_compiler::job::types::{Credit, CreditMode, Watermark, WatermarkPosition};
use divine_compiler::render::overlay::{credit_drawtext_filter, format_credit_text, logo_overlay_filter};

fn wm(pos: WatermarkPosition) -> Watermark {
    Watermark { enabled: true, position: pos, opacity: 0.30 }
}

#[test]
fn logo_disabled_emits_null_passthrough() {
    let w = Watermark { enabled: false, ..wm(WatermarkPosition::BottomRight) };
    let f = logo_overlay_filter("v0", "logo", "out", 1080, &w);
    assert_eq!(f, "[v0]null[out]");
}

#[test]
fn logo_bottom_right_overlay_string() {
    let f = logo_overlay_filter("v0", "logo", "out", 1080, &wm(WatermarkPosition::BottomRight));
    assert!(f.contains("overlay=W-w-16:H-h-16"));
    assert!(f.contains("colorchannelmixer=aa=0.3"));
    assert!(f.contains("scale=130:-1")); // 12% of 1080 = 129.6 → 130
}

#[test]
fn logo_top_left_overlay_uses_constant_corner() {
    let f = logo_overlay_filter("v0", "logo", "out", 1920, &wm(WatermarkPosition::TopLeft));
    assert!(f.contains("overlay=16:16"));
}

fn credit() -> Credit {
    Credit { mode: CreditMode::LowerThirdFade, duration_ms: 2500, show_display_name: true, show_nip05: true }
}

#[test]
fn credit_off_mode_passes_through() {
    let mut c = credit(); c.mode = CreditMode::Off;
    let f = credit_drawtext_filter("v", "out", &c, "Alice", 0.0, 1920);
    assert_eq!(f, "[v]null[out]");
}

#[test]
fn credit_empty_text_passes_through() {
    let f = credit_drawtext_filter("v", "out", &credit(), "", 0.0, 1920);
    assert_eq!(f, "[v]null[out]");
}

#[test]
fn credit_drawtext_has_fade_envelope() {
    let f = credit_drawtext_filter("v", "out", &credit(), "Alice", 10.0, 1920);
    // Window: 10.000 .. 12.500
    assert!(f.contains("between(t,10.000,12.500)"));
    // Fade in ends at 10.300, fade out starts at 12.200
    assert!(f.contains("10.300"));
    assert!(f.contains("12.200"));
}

#[test]
fn credit_drawtext_escapes_colon_in_text() {
    let f = credit_drawtext_filter("v", "out", &credit(), "Time: 12:30", 0.0, 1920);
    assert!(f.contains("Time\\:"));
}

#[test]
fn credit_drawtext_escapes_comma_percent_apostrophe() {
    // User-controlled display names can be anything. We must defend against
    // characters that break the filter syntax.
    let f = credit_drawtext_filter("v", "out", &credit(), "Bob, 100% O'Brien", 0.0, 1920);
    assert!(f.contains("Bob\\,"), "comma must be escaped: {}", f);
    assert!(f.contains("100\\%"), "percent must be escaped: {}", f);
    assert!(f.contains("O\\'Brien"), "apostrophe must be escaped to \\' (one backslash): {}", f);
    // And it must NOT be over-escaped to \\\' (literal backslash + apostrophe).
    assert!(!f.contains("O\\\\'Brien"), "apostrophe over-escaped: {}", f);
}

#[test]
fn format_credit_text_prefers_displayname_plus_nip05() {
    assert_eq!(format_credit_text(Some("Alice"), Some("alice@x"), "deadbeef"), "Alice • alice@x");
    assert_eq!(format_credit_text(Some("Alice"), None, "deadbeef"), "Alice");
    assert_eq!(format_credit_text(None, Some("alice@x"), "deadbeef"), "alice@x");
    assert_eq!(format_credit_text(None, None, "deadbeefcafe"), "npub: deadbeef…");
}
```

- [ ] **Step 3: Run** — `cargo test --test render_overlay`. Expected: 9 pass.

- [ ] **Step 4: Expose in `lib.rs`** — add `pub mod render;` if not already.

- [ ] **Step 5: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): pure-function logo overlay + drawtext credit filtergraph builders"
```

**End of Chunk 8a.** Pure functions for fit and overlay are tested. Next sub-chunk: ffmpeg execution + render orchestrator.

---

## Chunk 8b: FFmpeg execution and render orchestrator

Goal: assemble the per-aspect FFmpeg command (concat of N fitted+credited clips + persistent logo overlay + NVENC encode) and execute it. Per-aspect outputs are written to the job's temp dir, then handed to the GCS uploader from Chunk 7.

### Task 8b.1: Build the per-aspect ffmpeg command

**Files:**
- Create: `cloud-run-compiler/src/render/ffmpeg.rs`
- Create: `cloud-run-compiler/tests/render_ffmpeg_args.rs`

The command shape:
```
ffmpeg -y \
  -hwaccel cuda -hwaccel_output_format cuda \      # optional GPU decode
  -i /tmp/job/clip_0.mp4 -i /tmp/job/clip_1.mp4 ... \
  -i /tmp/logo.png \
  -filter_complex "<built filtergraph>" \
  -map "[v_final]" -map "[a_final]" \
  -c:v h264_nvenc -preset p5 -b:v 6M -maxrate 8M -bufsize 12M \
  -pix_fmt yuv420p -profile:v high -level 4.2 \
  -c:a aac -b:a 128k -ar 48000 \
  -movflags +faststart \
  /tmp/job/out_9_16.mp4
```

The filter_complex chains per-clip: `fit_filter` → `credit_drawtext_filter` → concat → `logo_overlay_filter`.

- [ ] **Step 1: Implement command builder (pure function — no execution yet)**

```rust
// ABOUTME: Build the FFmpeg command for one aspect ratio of a comp job
// ABOUTME: Pure function; execution lives in `run_ffmpeg`

use crate::job::types::{Credit, Watermark};
use crate::render::fit::fit_filter;
use crate::render::overlay::{credit_drawtext_filter, logo_overlay_filter};
use crate::render::TargetDim;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ClipInput {
    pub path: PathBuf,
    pub fit: crate::job::types::Fit,
    pub credit_text: String,
    pub duration_sec: f64,
}

#[derive(Debug, Clone)]
pub struct AspectJob {
    pub clips: Vec<ClipInput>,
    pub target: TargetDim,
    pub logo_path: PathBuf,
    pub watermark: Watermark,
    pub credit: Credit,
    pub output_path: PathBuf,
    pub bitrate_kbps: u32,
    pub use_gpu: bool,
}

pub fn build_command(job: &AspectJob) -> Vec<String> {
    // -y: overwrite output (safe for GPU→CPU retry — we always re-encode from scratch).
    // -loglevel warning + -nostats: keep stderr small enough to be useful in error
    //   messages. Without this, ffmpeg dumps frame-by-frame progress into stderr
    //   and a 10-minute render produces tens of MB of noise that swallows real errors.
    let mut args: Vec<String> = vec![
        "-y".into(),
        "-loglevel".into(), "warning".into(),
        "-nostats".into(),
    ];

    if job.use_gpu {
        // GPU decode for h264 inputs; falls through to CPU for unsupported codecs.
        args.push("-hwaccel".into());
        args.push("cuda".into());
    }

    for clip in &job.clips {
        args.push("-i".into());
        args.push(clip.path.to_string_lossy().into());
    }
    // Logo as the last input
    let logo_input_index = job.clips.len();
    args.push("-i".into());
    args.push(job.logo_path.to_string_lossy().into());

    args.push("-filter_complex".into());
    args.push(build_filter_complex(job, logo_input_index));

    args.push("-map".into());
    args.push("[v_final]".into());
    args.push("-map".into());
    args.push("[a_final]".into());

    if job.use_gpu {
        args.extend([
            "-c:v", "h264_nvenc",
            "-preset", "p5",
            "-rc:v", "vbr",
        ].iter().map(|s| s.to_string()));
    } else {
        args.extend([
            "-c:v", "libx264",
            "-preset", "medium",
        ].iter().map(|s| s.to_string()));
    }
    let bitrate = format!("{}k", job.bitrate_kbps);
    let maxrate = format!("{}k", job.bitrate_kbps * 4 / 3);
    let bufsize = format!("{}k", job.bitrate_kbps * 2);
    args.extend([
        "-b:v", &bitrate, "-maxrate", &maxrate, "-bufsize", &bufsize,
        "-pix_fmt", "yuv420p", "-profile:v", "high", "-level", "4.2",
        "-c:a", "aac", "-b:a", "128k", "-ar", "48000",
        "-movflags", "+faststart",
    ].iter().map(|s| s.to_string()));
    args.push(job.output_path.to_string_lossy().into());

    args
}

fn build_filter_complex(job: &AspectJob, logo_index: usize) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut start_sec = 0.0;
    let mut v_labels: Vec<String> = Vec::new();
    let mut a_labels: Vec<String> = Vec::new();

    for (i, clip) in job.clips.iter().enumerate() {
        // Video chain: input → fit → credit
        let fit_label = format!("vfit_{}", i);
        parts.push(fit_filter(&format!("{}:v:0", i), &fit_label, clip.fit, job.target));
        let credit_label = format!("vcr_{}", i);
        parts.push(credit_drawtext_filter(
            &fit_label,
            &credit_label,
            &job.credit,
            &clip.credit_text,
            start_sec,
            job.target.height,
        ));
        v_labels.push(format!("[{}]", credit_label));

        // Audio: just label the input audio for the concat.
        // V1 LIMITATION: assumes every clip has an [N:a:0] stream (true for
        // Vines, which always have audio even if silent). If a clip is audio-less,
        // ffmpeg fails with stream-not-found. TODO(v2): probe.audio_streams check
        // upstream → inject `anullsrc=channel_layout=stereo:sample_rate=48000`
        // as a synthetic input for muted clips.
        a_labels.push(format!("[{}:a:0]", i));

        start_sec += clip.duration_sec;
    }

    // Concat all clips
    let concat_inputs: String = v_labels.iter().zip(a_labels.iter())
        .map(|(v, a)| format!("{}{}", v, a)).collect();
    parts.push(format!(
        "{}concat=n={}:v=1:a=1[v_cat][a_final]",
        concat_inputs, job.clips.len()
    ));

    // Logo overlay on the concatenated video
    parts.push(logo_overlay_filter(
        "v_cat",
        &format!("{}:v:0", logo_index),
        "v_final",
        job.target.width,
        &job.watermark,
    ));

    parts.join(";")
}
```

- [ ] **Step 2: Tests on the pure builder**

```rust
// cloud-run-compiler/tests/render_ffmpeg_args.rs
use divine_compiler::job::types::{Credit, CreditMode, Fit, Watermark, WatermarkPosition};
use divine_compiler::render::ffmpeg::{build_command, AspectJob, ClipInput};
use divine_compiler::render::TargetDim;
use std::path::PathBuf;

fn fixture_job(use_gpu: bool, clip_count: usize) -> AspectJob {
    AspectJob {
        clips: (0..clip_count).map(|i| ClipInput {
            path: PathBuf::from(format!("/tmp/job/clip_{}.mp4", i)),
            fit: Fit::BlurPad,
            credit_text: format!("Author {}", i),
            duration_sec: 6.0,
        }).collect(),
        target: TargetDim { width: 1080, height: 1920 },
        logo_path: PathBuf::from("/tmp/logo.png"),
        watermark: Watermark { enabled: true, position: WatermarkPosition::BottomRight, opacity: 0.3 },
        credit: Credit { mode: CreditMode::LowerThirdFade, duration_ms: 2500, show_display_name: true, show_nip05: true },
        output_path: PathBuf::from("/tmp/job/out_9x16.mp4"),
        bitrate_kbps: 6000,
        use_gpu,
    }
}

#[test]
fn gpu_command_uses_nvenc_and_hwaccel() {
    let cmd = build_command(&fixture_job(true, 2));
    assert!(cmd.windows(2).any(|w| w == ["-hwaccel".to_string(), "cuda".to_string()]));
    assert!(cmd.windows(2).any(|w| w == ["-c:v".to_string(), "h264_nvenc".to_string()]));
    assert!(!cmd.iter().any(|s| s == "libx264"));
}

#[test]
fn cpu_command_uses_libx264_no_hwaccel() {
    let cmd = build_command(&fixture_job(false, 2));
    assert!(!cmd.iter().any(|s| s == "-hwaccel"));
    assert!(cmd.windows(2).any(|w| w == ["-c:v".to_string(), "libx264".to_string()]));
}

#[test]
fn filter_complex_concats_n_clips() {
    let cmd = build_command(&fixture_job(true, 3));
    let fc_pos = cmd.iter().position(|s| s == "-filter_complex").unwrap();
    let fc = &cmd[fc_pos + 1];
    assert!(fc.contains("concat=n=3:v=1:a=1"));
    assert!(fc.contains("[v_cat]"));
    assert!(fc.contains("[a_final]"));
    assert!(fc.contains("[v_final]"));
}

#[test]
fn filter_complex_advances_credit_start_per_clip() {
    let cmd = build_command(&fixture_job(true, 3));
    let fc = &cmd[cmd.iter().position(|s| s == "-filter_complex").unwrap() + 1];
    // Clip 0 credit window starts at 0.000; clip 1 at 6.000; clip 2 at 12.000.
    assert!(fc.contains("between(t,0.000,2.500)"));
    assert!(fc.contains("between(t,6.000,8.500)"));
    assert!(fc.contains("between(t,12.000,14.500)"));
}

#[test]
fn bitrate_flag_uses_kbps_suffix() {
    let cmd = build_command(&fixture_job(true, 1));
    assert!(cmd.iter().any(|s| s == "6000k"));
}

#[test]
fn output_path_is_final_arg() {
    let cmd = build_command(&fixture_job(true, 1));
    assert_eq!(cmd.last().map(|s| s.as_str()), Some("/tmp/job/out_9x16.mp4"));
}

#[test]
fn movflags_faststart_present() {
    let cmd = build_command(&fixture_job(true, 1));
    assert!(cmd.windows(2).any(|w| w == ["-movflags".to_string(), "+faststart".to_string()]));
}

#[test]
fn loglevel_warning_keeps_stderr_small() {
    let cmd = build_command(&fixture_job(true, 1));
    assert!(cmd.windows(2).any(|w| w == ["-loglevel".to_string(), "warning".to_string()]));
    assert!(cmd.iter().any(|s| s == "-nostats"));
}
```

- [ ] **Step 3: Run** — `cargo test --test render_ffmpeg_args`. Expected: 8 pass.

- [ ] **Step 4: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): pure-function FFmpeg command builder per aspect ratio"
```

### Task 8b.2: Execute ffmpeg with GPU-then-CPU fallback

**Files:**
- Modify: `cloud-run-compiler/src/render/ffmpeg.rs`

- [ ] **Step 1: Append the executor**

```rust
use anyhow::{anyhow, Context, Result};
use tokio::process::Command;

/// Run the FFmpeg command. If `use_gpu=true` and the GPU pass fails with a
/// non-zero exit, retry on CPU. Returns the path to the produced MP4 on success.
/// `-y` in the command makes a partially-written GPU output safe to overwrite
/// on the CPU retry. Tested manually in staging; mocking tokio::process::Command
/// for the fallback path isn't worth the test maintenance burden.
pub async fn run_render(job: &AspectJob) -> Result<PathBuf> {
    if job.use_gpu {
        match try_one_pass(job, true).await {
            Ok(_) => return Ok(job.output_path.clone()),
            Err(e) => {
                tracing::warn!(?e, output = ?job.output_path, "GPU encode failed; falling back to CPU");
            }
        }
    }
    try_one_pass(job, false).await?;
    Ok(job.output_path.clone())
}

async fn try_one_pass(job: &AspectJob, use_gpu: bool) -> Result<()> {
    let mut cfg = job.clone();
    cfg.use_gpu = use_gpu;
    let args = build_command(&cfg);
    let out = Command::new("ffmpeg").args(&args).output().await.context("spawn ffmpeg")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!("ffmpeg exited {} (gpu={}); stderr tail:\n{}", out.status, use_gpu, tail(&stderr, 2000)));
    }
    if !job.output_path.exists() {
        return Err(anyhow!("ffmpeg returned 0 but output {} missing", job.output_path.display()));
    }
    Ok(())
}

fn tail(s: &str, n: usize) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() <= n { return s; }
    // Find a char boundary near the tail
    let mut start = bytes.len() - n;
    while !s.is_char_boundary(start) { start += 1; }
    &s[start..]
}
```

- [ ] **Step 2: Smoke test (gated by ffmpeg availability)**

`cloud-run-compiler/tests/render_ffmpeg_run.rs`:

```rust
use divine_compiler::job::types::{Credit, CreditMode, Fit, Watermark, WatermarkPosition};
use divine_compiler::render::ffmpeg::{run_render, AspectJob, ClipInput};
use divine_compiler::render::TargetDim;
use std::path::PathBuf;
use tempfile::tempdir;
use tokio::process::Command;

async fn make_clip(out: &std::path::Path, color: &str, sec: f32) {
    let s = Command::new("ffmpeg")
        .args([
            "-y", "-f", "lavfi",
            "-i", &format!("color=c={}:s=640x480:d={}", color, sec),
            "-f", "lavfi",
            "-i", &format!("sine=frequency=440:duration={}", sec),
            "-c:v", "libx264", "-pix_fmt", "yuv420p",
            "-c:a", "aac",
            "-shortest",
        ])
        .arg(out).status().await.unwrap();
    assert!(s.success());
}

async fn make_logo(out: &std::path::Path) {
    // 64x64 magenta PNG with alpha
    let s = Command::new("ffmpeg")
        .args([
            "-y", "-f", "lavfi",
            "-i", "color=c=magenta:s=64x64:d=0.04",
            "-frames:v", "1",
        ])
        .arg(out).status().await.unwrap();
    assert!(s.success());
}

#[tokio::test]
#[ignore = "requires ffmpeg in PATH; ~10s wall time"]
async fn renders_two_clip_comp_cpu_only() {
    let dir = tempdir().unwrap();
    let c0 = dir.path().join("c0.mp4");
    let c1 = dir.path().join("c1.mp4");
    let logo = dir.path().join("logo.png");
    let out = dir.path().join("out.mp4");
    make_clip(&c0, "red", 1.0).await;
    make_clip(&c1, "blue", 1.0).await;
    make_logo(&logo).await;
    let job = AspectJob {
        clips: vec![
            ClipInput { path: c0, fit: Fit::BlurPad, credit_text: "Alice".into(), duration_sec: 1.0 },
            ClipInput { path: c1, fit: Fit::BlurPad, credit_text: "Bob".into(),   duration_sec: 1.0 },
        ],
        target: TargetDim { width: 360, height: 640 }, // small for speed
        logo_path: logo,
        watermark: Watermark { enabled: true, position: WatermarkPosition::BottomRight, opacity: 0.4 },
        credit: Credit { mode: CreditMode::LowerThirdFade, duration_ms: 800, show_display_name: true, show_nip05: false },
        output_path: out.clone(),
        bitrate_kbps: 1500,
        use_gpu: false,
    };
    let path = run_render(&job).await.expect("render");
    assert_eq!(path, out);
    let md = std::fs::metadata(&path).expect("output exists");
    assert!(md.len() > 1000, "output too small ({} bytes)", md.len());
}
```

- [ ] **Step 3: Run (gated)** — `cargo test --test render_ffmpeg_run -- --ignored`. Expected: 1 passes when ffmpeg is on PATH.

- [ ] **Step 4: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): ffmpeg executor with GPU-to-CPU fallback"
```

### Task 8b.3: Top-level render orchestrator

**Files:**
- Modify: `cloud-run-compiler/src/render/mod.rs`

- [ ] **Step 1: Add `render_aspect` orchestration helper**

Append to `src/render/mod.rs`:

```rust
use crate::job::types::{Aspect, BlobDescriptor, CompileRequest, Fit};
use crate::render::ffmpeg::{run_render, AspectJob, ClipInput};
use anyhow::Result;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ProbedClip {
    pub event_id: String,
    pub path: PathBuf,
    pub duration_sec: f64,
    pub fit: Fit,
    pub credit_text: String,
}

pub struct AspectResult {
    pub aspect: Aspect,
    pub output_path: PathBuf,
    pub dim: TargetDim,
}

pub async fn render_aspect(
    aspect: Aspect,
    clips: &[ProbedClip],
    logo_path: &Path,
    job_dir: &Path,
    req: &CompileRequest,
    use_gpu: bool,
) -> Result<AspectResult> {
    let target = TargetDim::from(aspect);
    let bitrate_kbps = match aspect {
        Aspect::Vertical | Aspect::Horizontal => 6000,
        Aspect::Square => 5000,
    };
    let output_path = job_dir.join(format!(
        "out_{}.mp4",
        match aspect { Aspect::Vertical => "9x16", Aspect::Square => "1x1", Aspect::Horizontal => "16x9" }
    ));
    let aspect_job = AspectJob {
        clips: clips.iter().map(|c| ClipInput {
            path: c.path.clone(),
            fit: c.fit,
            credit_text: c.credit_text.clone(),
            duration_sec: c.duration_sec,
        }).collect(),
        target,
        logo_path: logo_path.to_path_buf(),
        watermark: req.watermark.clone(),
        credit: req.credit.clone(),
        output_path: output_path.clone(),
        bitrate_kbps,
        use_gpu,
    };
    run_render(&aspect_job).await?;
    Ok(AspectResult { aspect, output_path, dim: target })
}
```

- [ ] **Step 2: Verify compile** — `cargo build --tests`. Expected: compiles.

- [ ] **Step 3: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): render_aspect orchestrator wiring clips → ffmpeg per aspect"
```

**End of Chunk 8b.** Render pipeline is complete: probe, build filters, run ffmpeg with GPU fallback, orchestrate per aspect. Next chunk: HTTP handlers + worker loop + observability.

---

## Chunk 9: HTTP handlers, worker loop, webhook delivery, observability

Goal: wire all the pieces. axum router with auth + rate limit middleware on `POST /compile` and `GET /compile/:job_id`. Admin endpoints. Background worker pool that processes queued jobs. HMAC-signed webhook delivery. Structured logging.

### Task 9.1: Webhook delivery (HMAC-signed) with retry

**Files:**
- Create: `cloud-run-compiler/src/webhook.rs`
- Modify: `cloud-run-compiler/src/lib.rs`
- Create: `cloud-run-compiler/tests/webhook_signature.rs`

- [ ] **Step 1: Implement signer + verifier helpers and delivery**

```rust
// ABOUTME: HMAC-SHA256 webhook signer; fire-and-forget delivery with exp backoff
// ABOUTME: Verifier exposed so callers / tests can authenticate inbound signatures

use crate::job::types::CallbackDelivery;
use anyhow::Result;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

/// Returns "sha256=<hex>" — the value of the `X-Compiler-Signature` header.
pub fn sign(secret: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(body);
    let bytes = mac.finalize().into_bytes();
    format!("sha256={}", hex::encode(bytes))
}

pub fn verify(secret: &str, body: &[u8], header_value: &str) -> bool {
    let expected = sign(secret, body);
    constant_time_eq(expected.as_bytes(), header_value.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) { diff |= x ^ y; }
    diff == 0
}

const BACKOFF_SECS: [u64; 3] = [1, 5, 25];

/// Fire-and-forget: 3 retries with exp backoff. Returns the final CallbackDelivery
/// record so the worker can persist it on the job doc.
pub async fn deliver(
    url: &str,
    body: &[u8],
    secret: Option<&str>,
) -> CallbackDelivery {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("reqwest client");
    let mut attempts: u32 = 0;
    let mut last_status: u16 = 0;
    for delay in BACKOFF_SECS.iter() {
        attempts += 1;
        if attempts > 1 {
            tokio::time::sleep(Duration::from_secs(*delay)).await;
        }
        let mut req = client.post(url).body(body.to_vec()).header("content-type", "application/json");
        if let Some(s) = secret {
            req = req.header("X-Compiler-Signature", sign(s, body));
        }
        let res = req.send().await;
        match res {
            Ok(r) => {
                last_status = r.status().as_u16();
                if r.status().is_success() {
                    return CallbackDelivery {
                        attempts,
                        last_attempt_at: chrono::Utc::now(),
                        last_status_code: last_status,
                        delivered: true,
                    };
                }
            }
            Err(e) => {
                tracing::warn!(attempt = attempts, ?e, "webhook delivery error");
                last_status = 0; // network error
            }
        }
    }
    CallbackDelivery {
        attempts,
        last_attempt_at: chrono::Utc::now(),
        last_status_code: last_status,
        delivered: false,
    }
}
```

- [ ] **Step 2: Tests**

```rust
// cloud-run-compiler/tests/webhook_signature.rs
use divine_compiler::webhook::{deliver, sign, verify};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, Respond, ResponseTemplate};

#[test]
fn sign_format_matches_spec() {
    let s = sign("shh", b"hello");
    assert!(s.starts_with("sha256="));
    assert_eq!(s.len(), 7 + 64);
}

#[test]
fn verify_accepts_valid_signature() {
    assert!(verify("shh", b"hello", &sign("shh", b"hello")));
}

#[test]
fn verify_rejects_modified_body() {
    let s = sign("shh", b"hello");
    assert!(!verify("shh", b"hella", &s));
}

#[test]
fn verify_rejects_wrong_key() {
    let s = sign("shh", b"hello");
    assert!(!verify("other", b"hello", &s));
}

#[tokio::test]
async fn deliver_succeeds_on_first_2xx() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server).await;
    let r = deliver(&server.uri(), b"{}", Some("shh")).await;
    assert!(r.delivered);
    assert_eq!(r.attempts, 1);
    assert_eq!(r.last_status_code, 200);
}

#[tokio::test]
async fn deliver_retries_on_5xx_up_to_three_times() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .expect(3)
        .mount(&server).await;
    let r = deliver(&server.uri(), b"{}", None).await;
    assert!(!r.delivered);
    assert_eq!(r.attempts, 3);
    assert_eq!(r.last_status_code, 503);
}

#[tokio::test]
async fn deliver_sends_signature_header_when_secret_present() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("X-Compiler-Signature", sign("shh", b"{}").as_str()))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server).await;
    let r = deliver(&server.uri(), b"{}", Some("shh")).await;
    assert!(r.delivered);
}
```

Notes:
- The 5xx retry test exercises the full 1s + 5s = 6s backoff. Acceptable for a tested-once test; mark `#[ignore]` if your CI is time-budget sensitive.

- [ ] **Step 3: Run** — `cargo test --test webhook_signature`. Expected: 7 pass (the 5xx retry test takes ~6s; rest are instant).

- [ ] **Step 4: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): HMAC-signed webhook delivery with 3-retry exponential backoff"
```

### Task 9.2: Logo fetcher (startup once, cached on disk)

**Files:**
- Create: `cloud-run-compiler/src/logo.rs`
- Modify: `cloud-run-compiler/src/lib.rs`

- [ ] **Step 1: Implement**

```rust
// ABOUTME: One-shot logo fetcher; downloads from media.divine.video at startup
// ABOUTME: Cached on local disk for the worker's lifetime

use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;

pub async fn fetch_logo_to(dest_dir: &std::path::Path, url: &str) -> Result<PathBuf> {
    fs::create_dir_all(dest_dir).await.context("mkdir logo cache dir")?;
    let dest = dest_dir.join("divine-logo.png");
    if dest.exists() {
        return Ok(dest);
    }
    let resp = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?
        .get(url)
        .send()
        .await
        .context("GET logo")?;
    if !resp.status().is_success() {
        return Err(anyhow!("logo GET {} → {}", url, resp.status()));
    }
    let bytes = resp.bytes().await.context("read logo bytes")?;
    let mut f = fs::File::create(&dest).await.context("create logo file")?;
    f.write_all(&bytes).await.context("write logo file")?;
    Ok(dest)
}
```

- [ ] **Step 2: Tests**

```rust
// cloud-run-compiler/tests/logo_fetch.rs
use divine_compiler::logo::fetch_logo_to;
use tempfile::tempdir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn fetch_logo_writes_file() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/divine-logo.png"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"PNGBYTES".to_vec()))
        .mount(&server).await;
    let dir = tempdir().unwrap();
    let p = fetch_logo_to(dir.path(), &format!("{}/divine-logo.png", server.uri())).await.unwrap();
    assert!(p.exists());
    let bytes = std::fs::read(&p).unwrap();
    assert_eq!(bytes, b"PNGBYTES");
}

#[tokio::test]
async fn fetch_logo_uses_cache_on_second_call() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/divine-logo.png"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"PNG".to_vec()))
        .expect(1) // only one HTTP call across the two fetches
        .mount(&server).await;
    let dir = tempdir().unwrap();
    let url = format!("{}/divine-logo.png", server.uri());
    let _ = fetch_logo_to(dir.path(), &url).await.unwrap();
    let _ = fetch_logo_to(dir.path(), &url).await.unwrap();
}
```

- [ ] **Step 3: Expose in `lib.rs`** — add `pub mod logo;` and `pub mod webhook;`.

- [ ] **Step 4: Run** — `cargo test --test logo_fetch`. Expected: 2 pass.

- [ ] **Step 5: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): startup logo fetcher with disk cache"
```

### Task 9.3: Observability helpers

**Files:**
- Create: `cloud-run-compiler/src/observability.rs`
- Modify: `cloud-run-compiler/src/lib.rs`

- [ ] **Step 1: Implement structured-log helpers**

```rust
// ABOUTME: Wraps tracing::info!() with the structured-log schema from the spec
// ABOUTME: Every job event goes through here so Cloud Logging derives metrics consistently

use crate::auth::Tenant;
use serde::Serialize;
use serde_json::Value;

#[derive(Serialize)]
pub struct JobEvent<'a> {
    pub job_id: &'a str,
    pub event: &'a str,
    pub caller: Value,
    pub source_kind: Option<&'a str>,
    pub clip_count: Option<u32>,
    pub clips_dropped: Option<u32>,
    pub aspects: Option<&'a [&'a str]>,
    pub duration_sec: Option<u32>,
    pub render_time_sec: Option<u32>,
    pub gpu_seconds: Option<u32>,
    pub error: Option<&'a str>,
}

pub fn emit(event: JobEvent<'_>) {
    // serialize to JSON once, log as a single message — Cloud Logging
    // parses the message body as a structured payload via tracing-subscriber's
    // json formatter.
    let json = serde_json::to_string(&event).unwrap_or_else(|_| "{}".into());
    tracing::info!("{}", json);
}

pub fn caller_json(tenant: &Tenant) -> Value {
    match tenant {
        Tenant::Pubkey(p) => serde_json::json!({ "kind": "nip98", "pubkey": p }),
        Tenant::Secret(n) => serde_json::json!({ "kind": "webhook", "tenant": n }),
    }
}
```

- [ ] **Step 2: Quick smoke test**

```rust
// cloud-run-compiler/tests/observability.rs
use divine_compiler::auth::Tenant;
use divine_compiler::observability::{caller_json, emit, JobEvent};

#[test]
fn caller_json_for_pubkey() {
    let v = caller_json(&Tenant::Pubkey("deadbeef".into()));
    assert_eq!(v["kind"], "nip98");
    assert_eq!(v["pubkey"], "deadbeef");
}

#[test]
fn caller_json_for_secret() {
    let v = caller_json(&Tenant::Secret("funnelcake".into()));
    assert_eq!(v["kind"], "webhook");
    assert_eq!(v["tenant"], "funnelcake");
}

#[test]
fn emit_does_not_panic() {
    emit(JobEvent {
        job_id: "cmp_x",
        event: "queued",
        caller: caller_json(&Tenant::Pubkey("p".into())),
        source_kind: Some("naddr"),
        clip_count: None, clips_dropped: None, aspects: None,
        duration_sec: None, render_time_sec: None, gpu_seconds: None,
        error: None,
    });
}
```

- [ ] **Step 3: Expose in lib.rs** — add `pub mod observability;`.

- [ ] **Step 4: Run** — `cargo test --test observability`. Expected: 3 pass.

- [ ] **Step 5: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): structured-log JobEvent helper for Cloud Logging"
```

### Task 9.4: API handlers — `POST /compile`, `GET /compile/:job_id`

**Files:**
- Create: `cloud-run-compiler/src/api/mod.rs`
- Create: `cloud-run-compiler/src/api/compile.rs`
- Create: `cloud-run-compiler/src/api/status.rs`
- Modify: `cloud-run-compiler/src/lib.rs`

- [ ] **Step 1: Implement the router**

`cloud-run-compiler/src/api/mod.rs`:

```rust
// ABOUTME: axum router wiring all public + admin endpoints
pub mod compile;
pub mod status;
pub mod admin;

use crate::auth::AppState;
use axum::routing::{get, post};
use axum::Router;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/compile", post(compile::post_compile))
        .route("/compile/:job_id", get(status::get_status))
        .route("/admin/jobs", get(admin::list_jobs))
        .route("/admin/jobs/:job_id", get(admin::get_job))
        .route("/admin/jobs/:job_id/cancel", post(admin::cancel_job))
        .route("/admin/jobs/:job_id/requeue", post(admin::requeue_job))
        .route("/admin/tenants", get(admin::list_tenants))
        .with_state(state)
}
```

- [ ] **Step 2: Implement `POST /compile`**

`cloud-run-compiler/src/api/compile.rs`:

```rust
// ABOUTME: POST /compile — validate, persist as queued, return job_id
use crate::auth::{AppState, Tenant};
use crate::job::types::{CompileRequest, Job, JobStatus};
use crate::job::validation::{validate_v1, UnsupportedField};
use crate::rate_limit::RateLimitOutcome;
use crate::observability::{caller_json, emit, JobEvent};
use axum::{extract::State, http::{HeaderMap, HeaderValue, StatusCode}, response::{IntoResponse, Response}, Json};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

#[derive(Serialize)]
pub struct CompileResponse {
    pub job_id: String,
    pub status: String,
}

/// Error responses include their own headers — wrapped in `Response` so we can
/// set `Retry-After` on 429 (spec line 207 mandates the header, not just the body).
fn err(status: StatusCode, body: Value, extra_headers: Vec<(&'static str, String)>) -> Response {
    let mut headers = HeaderMap::new();
    for (k, v) in extra_headers {
        if let Ok(h) = HeaderValue::from_str(&v) { headers.insert(k, h); }
    }
    (status, headers, Json(body)).into_response()
}

pub async fn post_compile(
    State(state): State<AppState>,
    tenant: Tenant,
    Json(req): Json<CompileRequest>,
) -> Result<Json<CompileResponse>, Response> {
    if let Err(e) = validate_v1(&req) {
        let body = serde_json::to_value(&e).unwrap_or_default();
        return Err(err(StatusCode::BAD_REQUEST, body, vec![]));
    }
    let tenant_id = tenant.id();
    match state.rate_limiter.check_and_increment(&tenant_id, chrono::Utc::now()).await {
        Ok(RateLimitOutcome::Allowed) => {}
        Ok(RateLimitOutcome::TooMany { retry_after_seconds }) => {
            return Err(err(
                StatusCode::TOO_MANY_REQUESTS,
                serde_json::json!({ "error": "rate_limited", "retry_after_seconds": retry_after_seconds }),
                vec![("Retry-After", retry_after_seconds.to_string())],
            ));
        }
        Err(e) => {
            tracing::error!(?e, "rate limit check failed");
            return Err(err(StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": "rate_limit_check_failed" }), vec![]));
        }
    }

    let job_id = format!("cmp_{}", Uuid::new_v4().simple());
    let now = chrono::Utc::now();
    let job = Job {
        job_id: job_id.clone(),
        status: JobStatus::Queued,
        progress: 0.0,
        request: req.clone(),
        tenant_id,
        created_at: now,
        updated_at: now,
        result: None,
        error: None,
        callback_delivery: None,
        requeued_from: None,
        requeued_as: None,
    };

    if let Err(e) = state.job_store.create_job(&job).await {
        tracing::error!(?e, "create_job failed");
        return Err(err(StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({ "error": "persist_failed" }), vec![]));
    }

    emit(JobEvent {
        job_id: &job_id,
        event: "queued",
        caller: caller_json(&tenant),
        source_kind: Some(source_kind(&req)),
        clip_count: None, clips_dropped: None, aspects: None,
        duration_sec: None, render_time_sec: None, gpu_seconds: None,
        error: None,
    });

    Ok(Json(CompileResponse { job_id, status: "queued".to_string() }))
}

fn source_kind(req: &CompileRequest) -> &'static str {
    use crate::job::types::Source;
    match req.source {
        Source::Naddr(_) => "naddr",
        Source::EventIds(_) => "event_ids",
        Source::Nevents(_) => "nevents", // rejected by validate_v1 but enum exhaustiveness
    }
}

// NOTE: do NOT add `impl Serialize for UnsupportedField` here. The struct
// already derives `Serialize` in `src/job/validation.rs` (Chunk 2). Adding
// a second impl would fail with conflicting implementations of trait.
```

- [ ] **Step 3: Implement `GET /compile/:job_id`**

`cloud-run-compiler/src/api/status.rs`:

```rust
// ABOUTME: GET /compile/:job_id — load job from Firestore, return JSON, 404 if missing
use crate::auth::{AppState, Tenant};
use axum::{extract::{Path, State}, http::StatusCode, Json};
use serde_json::{json, Value};

pub async fn get_status(
    State(state): State<AppState>,
    _tenant: Tenant,           // auth required, identity not used for v1 (admin sees everything)
    Path(job_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match state.job_store.get_job(&job_id).await {
        Ok(Some(job)) => Ok(Json(serde_json::to_value(&job).unwrap())),
        Ok(None) => Err((StatusCode::NOT_FOUND, Json(json!({ "error": "job_not_found", "job_id": job_id })))),
        Err(e) => {
            tracing::error!(?e, "get_job failed");
            Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "store_failed" }))))
        }
    }
}
```

- [ ] **Step 4: Extend `AppState`**

In `src/auth.rs`, extend the `AppState` struct from Chunk 4:

```rust
#[derive(Debug, Clone)]
pub struct AppState {
    pub config: Arc<crate::config::Config>,
    pub job_store: Arc<crate::job::store::JobStore>,
    pub rate_limiter: Arc<crate::rate_limit::RateLimiter>,
}
```

(Plus matching `FromRef` impls if the existing extractor needs them — `axum::extract::FromRef` derive will work since all three fields are `Clone`.)

- [ ] **Step 5: Verify compile** — `cargo build --tests`. Fix any import / type drift.

- [ ] **Step 6: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): POST /compile + GET /compile/:job_id handlers with auth + rate limit"
```

### Task 9.5: Admin endpoints

**Files:**
- Create: `cloud-run-compiler/src/api/admin.rs`

- [ ] **Step 1: Implement**

```rust
// ABOUTME: Admin endpoints — list/inspect/cancel/requeue jobs and inspect tenants
// ABOUTME: Auth via admin pubkey allowlist OR Bearer admin token

use crate::auth::AppState;
use crate::job::types::{Job, JobStatus};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize, Default)]
pub struct ListQuery {
    pub limit: Option<u32>,
    pub cursor: Option<String>,
    pub status: Option<JobStatus>,
    pub callback_delivered: Option<bool>,
}

fn require_admin(state: &AppState, headers: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
    let auth = headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    if let Some(token) = auth.and_then(|h| h.strip_prefix("Bearer ")) {
        if let Some(expected) = state.config.admin_token.as_deref() {
            if token == expected { return Ok(()); }
        }
        if state.config.admin_pubkeys.contains(token) { return Ok(()); } // legacy hex-direct
    }
    // Could also accept NIP-98 with pubkey in admin allowlist — defer to v2.
    Err((StatusCode::UNAUTHORIZED, Json(json!({ "error": "admin_required" }))))
}

pub async fn list_jobs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin(&state, &headers)?;
    let limit = q.limit.unwrap_or(50).min(500);
    let jobs = state.job_store
        .list_recent(limit, q.cursor, q.status, q.callback_delivered)
        .await
        .map_err(|e| { tracing::error!(?e, "list_jobs"); err_500() })?;
    Ok(Json(json!({ "jobs": jobs })))
}

pub async fn get_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin(&state, &headers)?;
    let job = state.job_store.get_job(&job_id).await
        .map_err(|e| { tracing::error!(?e); err_500() })?;
    match job {
        Some(j) => Ok(Json(serde_json::to_value(&j).unwrap())),
        None => Err((StatusCode::NOT_FOUND, Json(json!({ "error": "job_not_found", "job_id": job_id })))),
    }
}

pub async fn cancel_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin(&state, &headers)?;
    let Some(mut job) = state.job_store.get_job(&job_id).await
        .map_err(|e| { tracing::error!(?e); err_500() })? else {
        return Err((StatusCode::NOT_FOUND, Json(json!({ "error": "job_not_found", "job_id": job_id }))));
    };
    job.status = JobStatus::Cancelled;
    state.job_store.update_job(&job).await
        .map_err(|e| { tracing::error!(?e); err_500() })?;
    // The worker checks status before each stage; cancel propagates next time it polls.
    Ok(Json(json!({ "ok": true })))
}

pub async fn requeue_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin(&state, &headers)?;
    let Some(original) = state.job_store.get_job(&job_id).await
        .map_err(|e| { tracing::error!(?e); err_500() })? else {
        return Err((StatusCode::NOT_FOUND, Json(json!({ "error": "job_not_found", "job_id": job_id }))));
    };
    let now = chrono::Utc::now();
    let new_id = format!("cmp_{}", uuid::Uuid::new_v4().simple());
    let mut new_job = Job {
        job_id: new_id.clone(),
        status: JobStatus::Queued,
        progress: 0.0,
        request: original.request.clone(),
        tenant_id: original.tenant_id.clone(),
        created_at: now,
        updated_at: now,
        result: None, error: None, callback_delivery: None,
        requeued_from: Some(original.job_id.clone()),
        requeued_as: None,
    };
    state.job_store.create_job(&new_job).await.map_err(|e| { tracing::error!(?e); err_500() })?;
    let mut updated_orig = original;
    updated_orig.requeued_as = Some(new_id.clone());
    let _ = state.job_store.update_job(&updated_orig).await;
    Ok(Json(json!({ "ok": true, "job_id": new_id, "requeued_from": updated_orig.job_id })))
}

pub async fn list_tenants(
    State(_state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_admin(&_state, &headers)?;
    // V1: derive tenant summaries from job_store::list_by_tenant lazily as
    // operators ask. For v1, return an empty stub with a note — full
    // aggregation requires the Firestore aggregation API. This is OK because
    // the spec says admin "see what people are making" is for incident response,
    // and `GET /admin/jobs` already provides per-job tenant visibility.
    Ok(Json(json!({ "tenants": [], "note": "v1 stub; per-job tenant visible via /admin/jobs" })))
}

fn err_500() -> (StatusCode, Json<Value>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "internal" })))
}
```

- [ ] **Step 2: Verify compile** — `cargo build --tests`.

- [ ] **Step 3: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): admin endpoints — list/get/cancel/requeue jobs"
```

### Task 9.6: Worker loop

**Files:**
- Create: `cloud-run-compiler/src/job/worker.rs`
- Modify: `cloud-run-compiler/src/job/mod.rs`

The worker polls Firestore for `status = queued` jobs, picks them up, runs them concurrently up to `max_concurrent_jobs`, and writes the result back.

- [ ] **Step 1: Skeleton**

```rust
// ABOUTME: Background worker loop. Polls Firestore for queued jobs and runs them.
// ABOUTME: Concurrency cap = Config::max_concurrent_jobs; each job has its own /tmp/job_<id>/.

use crate::auth::AppState;
use crate::blossom::download::DownloadClient;
use crate::blossom::moderation::ModerationClient;
use crate::blossom::upload::GcsUploader;
use crate::blossom::BlobStatus;
use crate::job::types::*;
use crate::nostr::api_client::{ApiClient, FetchError};
use crate::nostr::types::{Imeta, Profile};
use crate::nostr::naddr::decode_naddr;
use crate::observability::{caller_json, emit, JobEvent};
use crate::render::{
    overlay::format_credit_text,
    render_aspect, ProbedClip,
};
use crate::render::probe::probe;
use crate::webhook;
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

pub struct Worker {
    state: AppState,
    api: Arc<ApiClient>,
    moderation: Arc<ModerationClient>,
    download: Arc<DownloadClient>,
    upload: Arc<GcsUploader>,
    logo_path: PathBuf,
    sem: Arc<Semaphore>,
}

impl Worker {
    pub fn new(
        state: AppState,
        api: ApiClient,
        moderation: ModerationClient,
        download: DownloadClient,
        upload: GcsUploader,
        logo_path: PathBuf,
    ) -> Self {
        let limit = state.config.max_concurrent_jobs;
        Self {
            state,
            api: Arc::new(api),
            moderation: Arc::new(moderation),
            download: Arc::new(download),
            upload: Arc::new(upload),
            logo_path,
            sem: Arc::new(Semaphore::new(limit)),
        }
    }

    pub async fn run_forever(self: Arc<Self>) {
        loop {
            match self.state.job_store.list_recent(10, None, Some(JobStatus::Queued), None).await {
                Ok(jobs) => {
                    for job in jobs {
                        let me = self.clone();
                        let permit = self.sem.clone().acquire_owned().await.unwrap();
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = me.process_job(job).await {
                                tracing::error!(?e, "job processing error");
                            }
                        });
                    }
                }
                Err(e) => tracing::error!(?e, "worker poll failed"),
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    async fn process_job(&self, mut job: Job) -> Result<()> {
        // Mark running (with optimistic update)
        job.status = JobStatus::Running;
        job.progress = 0.05;
        self.state.job_store.update_job(&job).await.context("mark running")?;
        emit(JobEvent { job_id: &job.job_id, event: "started",
            caller: caller_json_from_tenant_id(&job.tenant_id),
            source_kind: Some(source_kind(&job.request)),
            ..empty_event() });

        let work_dir = std::env::temp_dir().join(format!("job_{}", job.job_id));
        tokio::fs::create_dir_all(&work_dir).await.context("mkdir work_dir")?;

        let outcome = self.run_inner(&mut job, &work_dir).await;
        let _ = tokio::fs::remove_dir_all(&work_dir).await;

        match outcome {
            Ok(result) => {
                job.status = JobStatus::Done;
                job.progress = 1.0;
                job.result = Some(result);
            }
            Err(e) => {
                job.status = JobStatus::Failed;
                job.error = Some(format!("{:#}", e));
            }
        }
        self.state.job_store.update_job(&job).await.context("persist terminal state")?;
        emit(JobEvent { job_id: &job.job_id, event: if matches!(job.status, JobStatus::Done) { "done" } else { "failed" },
            caller: caller_json_from_tenant_id(&job.tenant_id),
            error: job.error.as_deref(), ..empty_event() });

        // Webhook delivery (fire-and-forget)
        if let Some(url) = job.request.callback_url.clone() {
            let body = serde_json::to_vec(&job).unwrap_or_default();
            // Pick the right secret to sign with: use the first configured
            // webhook secret matching the tenant if any; otherwise leave unsigned.
            let secret_owner = job.tenant_id.strip_prefix("secret:").unwrap_or("");
            let secret = self.state.config.webhook_secrets
                .iter()
                .find_map(|(sec, name)| if name == secret_owner { Some(sec.clone()) } else { None });
            let delivery = webhook::deliver(&url, &body, secret.as_deref()).await;
            job.callback_delivery = Some(delivery);
            let _ = self.state.job_store.update_job(&job).await;
        }
        Ok(())
    }

    async fn run_inner(&self, job: &mut Job, work_dir: &std::path::Path) -> Result<JobResult> {
        // 1) Resolve source → list of event ids (+ any a-tag refs we dropped)
        let (event_ids, mut clips_dropped) = self.resolve_source(&job.request.source).await?;

        // 2) Sanity cap (async, naddr branch)
        if event_ids.len() > crate::job::validation::MAX_CLIPS_PER_JOB {
            anyhow::bail!("too_many_clips: {} > {}", event_ids.len(), crate::job::validation::MAX_CLIPS_PER_JOB);
        }

        // 3) Fetch events + profiles (drop-and-continue per spec). `clips_dropped`
        //    already carries any a-tag refs we skipped during source resolution.
        let mut events: Vec<NostrEvent> = vec![];
        for id in &event_ids {
            match self.api.fetch_event(id).await {
                Ok(ev) => events.push(ev),
                Err(FetchError::NotFound(_)) => clips_dropped.push(ClipDropped { event_id: id.clone(), reason: "event_not_found".into() }),
                Err(FetchError::Other(e)) => clips_dropped.push(ClipDropped { event_id: id.clone(), reason: format!("event_fetch_err: {:#}", e) }),
            }
        }

        // 4) For each event, get imeta sha256 + check moderation + download
        let mut probed: Vec<ProbedClip> = vec![];
        let mut credits: Vec<RenderedCredit> = vec![];
        for ev in &events {
            let Some(imeta) = Imeta::first_in(ev).and_then(|i| i.sha256.clone().map(|s| (i, s))) else {
                clips_dropped.push(ClipDropped { event_id: ev.id.clone(), reason: "no_imeta_sha256".into() });
                continue;
            };
            let sha = imeta.1;
            // Moderation
            match self.moderation.check(&sha).await {
                Ok(BlobStatus::Active) => {}
                Ok(status) => {
                    clips_dropped.push(ClipDropped { event_id: ev.id.clone(), reason: format!("moderation:{:?}", status) });
                    continue;
                }
                Err(e) => {
                    clips_dropped.push(ClipDropped { event_id: ev.id.clone(), reason: format!("moderation_err: {:#}", e) });
                    continue;
                }
            }
            // Download
            let dest = work_dir.join(&sha);
            let dl = match self.download.download_one(&sha, &dest).await {
                Ok(d) => d,
                Err(e) => {
                    clips_dropped.push(ClipDropped { event_id: ev.id.clone(), reason: format!("download_err: {:#}", e) });
                    continue;
                }
            };
            // Probe
            let info = match probe(&dl.path).await {
                Ok(i) => i,
                Err(e) => {
                    clips_dropped.push(ClipDropped { event_id: ev.id.clone(), reason: format!("probe_err: {:#}", e) });
                    continue;
                }
            };
            // Profile
            let prof = self.api.fetch_profile(&ev.pubkey).await.unwrap_or_else(|_| Profile { pubkey: ev.pubkey.clone(), ..Profile::default() });
            let credit_text = format_credit_text(prof.display_name.as_deref(), prof.nip05.as_deref(), &ev.pubkey);

            // Per-clip override (fit only; in/out trim is v2+, see validation guard)
            let override_ = job.request.per_clip_overrides.iter().find(|o| o.event_id == ev.id);
            let fit = override_.and_then(|o| o.fit).unwrap_or(job.request.fit);
            // V1 LIMITATION: per_clip_overrides.in_sec / out_sec are validated-rejected
            // at request time (see Chunk 2 follow-up below). We never see them here.
            probed.push(ProbedClip {
                event_id: ev.id.clone(),
                path: dl.path.clone(),
                duration_sec: info.duration_sec,
                fit,
                credit_text: credit_text.clone(),
            });
            credits.push(RenderedCredit {
                event_id: ev.id.clone(),
                pubkey: ev.pubkey.clone(),
                nip05: prof.nip05.clone(),
                display_name: prof.display_name.clone(),
            });
        }

        // 5) Apply max_duration_sec cap
        let cap = job.request.max_duration_sec as f64;
        let mut total: f64 = 0.0;
        let mut kept: Vec<ProbedClip> = vec![];
        for c in probed {
            if total + c.duration_sec > cap {
                clips_dropped.push(ClipDropped { event_id: c.event_id.clone(), reason: "exceeded_max_duration_sec".into() });
                continue;
            }
            total += c.duration_sec;
            kept.push(c);
        }

        if kept.is_empty() {
            anyhow::bail!("no_usable_clips");
        }

        // 6) Dry-run early exit
        if job.request.dry_run {
            return Ok(JobResult {
                outputs: vec![], duration_sec: total as u32,
                clips_used: kept.len() as u32,
                clips_dropped, credits, dry_run: true,
            });
        }

        // 7) Render each requested aspect
        let mut outputs: Vec<BlobDescriptor> = vec![];
        for aspect in &job.request.aspects {
            let r = render_aspect(*aspect, &kept, &self.logo_path, work_dir, &job.request, true)
                .await
                .with_context(|| format!("render aspect {:?}", aspect))?;
            // Upload
            let up = self.upload.upload_file(&r.output_path, "video/mp4")
                .await
                .with_context(|| format!("upload aspect {:?}", aspect))?;
            outputs.push(BlobDescriptor {
                aspect: *aspect, url: up.url, sha256: up.sha256, size: up.size,
                dim: format!("{}x{}", r.dim.width, r.dim.height),
            });
        }

        Ok(JobResult {
            outputs, duration_sec: total as u32,
            clips_used: kept.len() as u32,
            clips_dropped, credits, dry_run: false,
        })
    }

    /// Returns `(event_ids_in_tag_order, dropped_a_tag_refs)`. `a` tags
    /// reference addressable events (kind 3xxxx); v1 doesn't resolve them
    /// (would require a second naddr decode + addressable fetch per item).
    /// We surface them in `clips_dropped` instead of silently swallowing.
    async fn resolve_source(&self, source: &Source) -> Result<(Vec<String>, Vec<ClipDropped>)> {
        match source {
            Source::EventIds(ids) => Ok((ids.clone(), vec![])),
            Source::Nevents(_) => anyhow::bail!("nevents not supported in v1"),
            Source::Naddr(naddr) => {
                let list = self.api.fetch_list_event(naddr).await
                    .map_err(|e| anyhow::anyhow!("fetch list: {:?}", e))?;
                let mut ids = vec![];
                let mut dropped = vec![];
                for t in &list.tags {
                    if t.len() < 2 { continue; }
                    match t[0].as_str() {
                        "e" => ids.push(t[1].clone()),
                        "a" => dropped.push(ClipDropped {
                            event_id: t[1].clone(),
                            reason: "addressable_ref_not_supported_v1".into(),
                        }),
                        _ => {}
                    }
                }
                Ok((ids, dropped))
            }
        }
    }
}

fn source_kind(req: &CompileRequest) -> &'static str {
    match req.source { Source::Naddr(_) => "naddr", Source::EventIds(_) => "event_ids", Source::Nevents(_) => "nevents" }
}

fn caller_json_from_tenant_id(id: &str) -> serde_json::Value {
    if let Some(p) = id.strip_prefix("pubkey:") {
        serde_json::json!({ "kind": "nip98", "pubkey": p })
    } else if let Some(n) = id.strip_prefix("secret:") {
        serde_json::json!({ "kind": "webhook", "tenant": n })
    } else {
        serde_json::json!({ "kind": "unknown", "id": id })
    }
}

fn empty_event() -> JobEvent<'static> {
    JobEvent {
        job_id: "", event: "", caller: serde_json::json!({}),
        source_kind: None, clip_count: None, clips_dropped: None,
        aspects: None, duration_sec: None, render_time_sec: None, gpu_seconds: None,
        error: None,
    }
}
```

- [ ] **Step 2: Update `src/job/mod.rs`** — `pub mod worker;`.

- [ ] **Step 3: Wire it in `main.rs`**

```rust
// In main.rs, after building the router and before axum::serve:
let api = ApiClient::new(&cfg.api_divine_video_url)?;
let mod_client = ModerationClient::new(&cfg.media_divine_video_url)?;
let dl = DownloadClient::new(&cfg.media_divine_video_url)?;
let up = GcsUploader::new(&cfg.gcs_bucket, &cfg.media_divine_video_url).await?;
let logo_path = divine_compiler::logo::fetch_logo_to(
    std::path::Path::new("/tmp/divine-compiler"),
    &format!("{}/divine-logo.png", cfg.media_divine_video_url.trim_end_matches('/')),
).await?;
let worker = Arc::new(Worker::new(state.clone(), api, mod_client, dl, up, logo_path));
tokio::spawn(worker.run_forever());
```

(Refactor `main.rs` to construct `AppState` with the rate_limiter + job_store from a Firestore client, build router, spawn worker, serve.)

- [ ] **Step 4: Verify compile** — `cargo build`. Expected: compiles.

- [ ] **Step 5: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): worker loop — resolve source, fetch, probe, render, upload, callback"
```

### Task 9.7: Tighten V1 validation matrix (in_sec/out_sec rejection)

The worker now relies on `per_clip_overrides.in_sec` / `out_sec` being absent. We need the validator to enforce that.

**Files:**
- Modify: `cloud-run-compiler/src/job/validation.rs`
- Modify: `cloud-run-compiler/tests/api_validation.rs`

- [ ] **Step 1: Extend `validate_v1`** — after the existing `intro_card` / `outro_card` rejections:

```rust
    // per_clip_overrides: v1 supports `fit` override only; in/out trim is v2+.
    for (i, o) in req.per_clip_overrides.iter().enumerate() {
        if o.in_sec.is_some() {
            return Err(UnsupportedField::new(
                format!("per_clip_overrides[{}].in_sec", i),
                "any (v2+)",
            ));
        }
        if o.out_sec.is_some() {
            return Err(UnsupportedField::new(
                format!("per_clip_overrides[{}].out_sec", i),
                "any (v2+)",
            ));
        }
    }
```

- [ ] **Step 2: Add two tests**

```rust
#[test]
fn rejects_per_clip_in_sec() {
    let r = req(json!({
        "source": { "naddr": "n" },
        "per_clip_overrides": [{ "event_id": "abc", "in_sec": 0.5 }]
    }));
    let e = validate_v1(&r).unwrap_err();
    assert!(e.field.ends_with(".in_sec"));
}

#[test]
fn rejects_per_clip_out_sec() {
    let r = req(json!({
        "source": { "naddr": "n" },
        "per_clip_overrides": [{ "event_id": "abc", "out_sec": 5.0 }]
    }));
    let e = validate_v1(&r).unwrap_err();
    assert!(e.field.ends_with(".out_sec"));
}
```

- [ ] **Step 3: Update Chunk 5's V1 validation matrix table in the spec doc** (one-line addition):

The plan needs to add `per_clip_overrides[i].in_sec` and `per_clip_overrides[i].out_sec` to the spec's matrix. That's a spec edit, not a code edit — leave a follow-up note in the chunk commit message.

- [ ] **Step 4: Run** — `cargo test --test api_validation`. Expected: 15 pass (13 from Chunk 2 + 2 new).

- [ ] **Step 5: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): reject per_clip in_sec/out_sec at validation (v1 ships without trim)"
```

### Task 9.8: Worker job-claim race — document and add lease scaffolding

**Files:**
- Modify: `cloud-run-compiler/src/job/types.rs`
- Modify: `cloud-run-compiler/src/job/worker.rs`

The current worker `list_recent(Queued) → update Running` is racy across instances. v1 ships a "good enough" claim (lease window) — multiple workers pick up the same job in the worst case, but the second one notices the status changed and bails.

- [ ] **Step 1: Add a `lease_until` field to `Job`**

In `types.rs`, add to the `Job` struct:

```rust
    #[serde(default)]
    pub lease_until: Option<chrono::DateTime<chrono::Utc>>,
```

- [ ] **Step 2: Wrap the worker's "mark running" step with a CAS check**

Replace the `mark running` block in `process_job`:

```rust
        // CAS-style claim: re-read, check status, set lease + Running. If
        // status changed under us (another worker claimed it), bail.
        let current = self.state.job_store.get_job(&job.job_id).await
            .context("re-read for claim")?
            .ok_or_else(|| anyhow::anyhow!("job vanished before claim"))?;
        if !matches!(current.status, JobStatus::Queued) {
            tracing::info!(job_id = %job.job_id, status = ?current.status, "skip — already claimed by another worker");
            return Ok(());
        }
        job = current;
        job.status = JobStatus::Running;
        job.progress = 0.05;
        job.lease_until = Some(chrono::Utc::now() + chrono::Duration::minutes(30));
        self.state.job_store.update_job(&job).await.context("mark running")?;
```

Caveat: Firestore doesn't do conditional updates by default (would need `run_transaction`); this is a TOCTOU-with-narrow-window. Two workers can still both claim. Acceptable for v1; flag for v2 hardening:

```rust
// V1 LIMITATION: this is a best-effort claim. True atomic claim requires
// `db.run_transaction` reading + writing in one transaction. With max_instances=5
// × 4 jobs each, the duplicate-claim window is small but real. v2+: switch to
// FirestoreDb::run_transaction with a status check inside the transaction body.
```

- [ ] **Step 3: Verify compile** — `cargo build`. Expected: compiles.

- [ ] **Step 4: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): add lease_until + best-effort job claim CAS in worker"
```

**End of Chunk 9.** The service handles requests end-to-end with auth, rate limiting, observability, admin endpoints, and a worker loop. Known v1 limitations recorded in source comments: no per-clip trim, naddr `a`-tag refs surfaced in clips_dropped, worker claim is best-effort not fully atomic, audio-less clips fail. Final chunk: deploy.sh wiring + smoke test.

---

## Chunk 10: Deploy + smoke test

Goal: wire all env vars and secrets into `deploy.sh`, run a real deploy to a staging Cloud Run service, execute an end-to-end smoke test against a known-good naddr, verify outputs.

### Task 10.1: Final `deploy.sh` (all env + secrets wired)

**Files:**
- Modify: `cloud-run-compiler/deploy.sh`

- [ ] **Step 1: Replace the deploy.sh from Chunk 1.4 with the final version**

```bash
#!/bin/bash
# ABOUTME: Deploy divine-compiler to Cloud Run GPU with Firestore + secrets wired
# ABOUTME: Builds in Cloud Build, then deploys; idempotent

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-divine-compiler}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-149672065768-compute@developer.gserviceaccount.com}"
IMAGE_TAG="${IMAGE_TAG:-$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M%S)}"
IMAGE="gcr.io/${PROJECT_ID}/${SERVICE_NAME}:${IMAGE_TAG}"

GCS_BUCKET="${GCS_BUCKET:-divine-blossom-media}"
FIRESTORE_PROJECT="${FIRESTORE_PROJECT:-${PROJECT_ID}}"
API_DIVINE_VIDEO_URL="${API_DIVINE_VIDEO_URL:-https://api.divine.video}"
MEDIA_DIVINE_VIDEO_URL="${MEDIA_DIVINE_VIDEO_URL:-https://media.divine.video}"
MAX_CONCURRENT_JOBS="${MAX_CONCURRENT_JOBS:-4}"
RATE_LIMIT_PER_HOUR="${RATE_LIMIT_PER_HOUR:-20}"
RATE_LIMIT_PER_DAY="${RATE_LIMIT_PER_DAY:-100}"
# Optional CSV of admin hex pubkeys. Leave empty for bearer-token-only admin auth.
COMPILER_ADMIN_PUBKEYS="${COMPILER_ADMIN_PUBKEYS:-}"

# RATE LIMIT TTL POLICY (one-time setup per project, idempotent):
#   gcloud firestore fields ttls update expires_at \
#     --collection-group=rate_limits --enable-ttl --project="${PROJECT_ID}"

# REQUIRED SECRETS (Secret Manager):
#   compiler_webhook_secrets — env format: "name1:secret1,name2:secret2"
#   compiler_admin_token     — single bearer string for admin endpoints

echo "Building ${IMAGE} in Cloud Build..."
gcloud builds submit "${SCRIPT_DIR}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --tag "${IMAGE}"

echo "Deploying ${SERVICE_NAME} to Cloud Run (GPU L4)..."
gcloud run deploy "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --image "${IMAGE}" \
  --allow-unauthenticated \
  --service-account "${SERVICE_ACCOUNT}" \
  --cpu 4 \
  --memory 16Gi \
  --gpu 1 \
  --gpu-type nvidia-l4 \
  --gpu-zonal-redundancy disabled \
  --concurrency 4 \
  --timeout 1800 \
  --max-instances 5 \
  --no-cpu-throttling \
  --set-env-vars "^@@^GCS_BUCKET=${GCS_BUCKET}@@FIRESTORE_PROJECT=${FIRESTORE_PROJECT}@@API_DIVINE_VIDEO_URL=${API_DIVINE_VIDEO_URL}@@MEDIA_DIVINE_VIDEO_URL=${MEDIA_DIVINE_VIDEO_URL}@@MAX_CONCURRENT_JOBS=${MAX_CONCURRENT_JOBS}@@RATE_LIMIT_PER_HOUR=${RATE_LIMIT_PER_HOUR}@@RATE_LIMIT_PER_DAY=${RATE_LIMIT_PER_DAY}@@COMPILER_ADMIN_PUBKEYS=${COMPILER_ADMIN_PUBKEYS}" \
  --set-secrets "COMPILER_WEBHOOK_SECRETS=compiler_webhook_secrets:latest,COMPILER_ADMIN_TOKEN=compiler_admin_token:latest"

echo "Service URL:"
gcloud run services describe "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --format='value(status.url)'

echo
echo "Smoke test: hit /health"
SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" --region "${REGION}" --format='value(status.url)')
curl -fsS "${SERVICE_URL}/health" && echo " — OK"
```

- [ ] **Step 2: One-time IAM setup (document, don't run from deploy.sh)**

Add this section to the top of `deploy.sh` as a comment:

```bash
# ONE-TIME SETUP (per project):
#   gcloud services enable firestore.googleapis.com cloudbuild.googleapis.com run.googleapis.com --project="${PROJECT_ID}"
#   gcloud firestore databases create --location="us-central" --project="${PROJECT_ID}"  # if not already
#   gcloud firestore fields ttls update expires_at \
#     --collection-group=rate_limits --enable-ttl --project="${PROJECT_ID}"
#   gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
#     --member="serviceAccount:${SERVICE_ACCOUNT}" --role="roles/datastore.user"
#   gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
#     --member="serviceAccount:${SERVICE_ACCOUNT}" --role="roles/storage.objectAdmin"
#   echo -n "your-webhook-secret-here" | gcloud secrets create compiler_webhook_secrets \
#     --data-file=- --project="${PROJECT_ID}"   # format: name1:secret1,name2:secret2
#   echo -n "your-admin-bearer-token" | gcloud secrets create compiler_admin_token \
#     --data-file=- --project="${PROJECT_ID}"
```

- [ ] **Step 3: Commit**

```bash
git add cloud-run-compiler/deploy.sh
git commit -m "feat(compiler): final deploy.sh with all env + secrets + GPU L4 wired"
```

### Task 10.2: Smoke test script

**Files:**
- Create: `cloud-run-compiler/scripts/smoke-test.sh`

- [ ] **Step 1: Implement**

```bash
#!/bin/bash
# ABOUTME: End-to-end smoke test for the deployed divine-compiler service
# ABOUTME: Submits a real compile, polls until done, verifies outputs are fetchable

set -euo pipefail

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-divine-compiler}"

# Auth: the smoke test acts as a webhook-secret caller (the same auth path
# funnelcake/janitor use). MUST be a value present in COMPILER_WEBHOOK_SECRETS
# at the value-side of one of the name:secret pairs. The matching tenant
# name is logged on the job but doesn't affect the smoke test itself.
# Do NOT use COMPILER_ADMIN_TOKEN here — that's for /admin endpoints only.
WEBHOOK_SECRET="${SMOKE_WEBHOOK_SECRET:?must export SMOKE_WEBHOOK_SECRET (one of the configured COMPILER_WEBHOOK_SECRETS values)}"

# A known-good list naddr. Replace with a real one before running.
SMOKE_NADDR="${SMOKE_NADDR:?must export SMOKE_NADDR (a naddr1... pointing at a small video list)}"

SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" --region "${REGION}" --format='value(status.url)')

echo "Submitting compile job to ${SERVICE_URL}..."
SUBMIT=$(curl -fsS -X POST "${SERVICE_URL}/compile" \
  -H "Authorization: Bearer ${WEBHOOK_SECRET}" \
  -H "Content-Type: application/json" \
  -d "$(cat <<EOF
{
  "source": { "naddr": "${SMOKE_NADDR}" },
  "aspects": ["9:16", "1:1", "16:9"],
  "fit": "blur-pad",
  "max_duration_sec": 120
}
EOF
)")
JOB_ID=$(echo "${SUBMIT}" | jq -r '.job_id')
echo "Job id: ${JOB_ID}"

echo "Polling for done..."
for _ in $(seq 1 60); do
  STATUS_JSON=$(curl -fsS "${SERVICE_URL}/compile/${JOB_ID}" \
    -H "Authorization: Bearer ${WEBHOOK_SECRET}")
  STATUS=$(echo "${STATUS_JSON}" | jq -r '.status')
  echo "  ...${STATUS}"
  if [[ "${STATUS}" == "done" || "${STATUS}" == "failed" ]]; then
    break
  fi
  sleep 10
done

echo "${STATUS_JSON}" | jq .

if [[ "${STATUS}" != "done" ]]; then
  echo "Job did not complete (status=${STATUS})"
  exit 1
fi

echo "Verifying outputs are fetchable..."
COUNT=$(echo "${STATUS_JSON}" | jq '.result.outputs | length')
[[ "${COUNT}" -ge 1 ]] || { echo "no outputs produced"; exit 1; }
echo "${STATUS_JSON}" | jq -r '.result.outputs[].url' | while read -r URL; do
  echo "  HEAD ${URL}"
  curl -fsSI "${URL}" > /dev/null
done

echo "Smoke test passed."
```

- [ ] **Step 2: Make executable + commit**

```bash
chmod +x cloud-run-compiler/scripts/smoke-test.sh
git add cloud-run-compiler/scripts/smoke-test.sh
git commit -m "test(compiler): end-to-end smoke test script (submit → poll → verify outputs)"
```

### Task 10.3: Run the deploy, then the smoke test

These are operator steps — running them produces no code changes but verifies the whole system.

- [ ] **Step 1: Deploy to a staging project**

```bash
PROJECT_ID=<staging-gcp-project> SERVICE_NAME=divine-compiler-staging \
  cloud-run-compiler/deploy.sh
```

Expected: build succeeds, service deploys, `/health` returns `ok`. **First-time deploy will fail** if the IAM/secrets/Firestore prerequisites in the deploy.sh comment block aren't done — run those first.

- [ ] **Step 2: Run the smoke test**

```bash
PROJECT_ID=<staging-gcp-project> SERVICE_NAME=divine-compiler-staging \
  SMOKE_WEBHOOK_SECRET=<one-of-the-configured-COMPILER_WEBHOOK_SECRETS-values> \
  SMOKE_NADDR=<real-list-naddr-with-2-or-3-tiny-videos> \
  cloud-run-compiler/scripts/smoke-test.sh
```

Expected: job runs in <10 min, status = `done`, 3 output URLs (one per aspect) are HEAD-fetchable.

- [ ] **Step 3: Manual verification**

- Open each output URL in a browser, confirm:
  - Video plays
  - Divine logo bug visible at the configured corner
  - Per-clip credit text appears at the start of each clip
  - Aspect ratios correct (vertical, square, horizontal)
  - Audio is present and not clipping

- [ ] **Step 4: Manual verification — Cloud Logging**

```bash
gcloud logging read 'resource.type=cloud_run_revision AND resource.labels.service_name="divine-compiler-staging" AND jsonPayload.event="done"' \
  --limit=5 --format=json --project="${PROJECT_ID}"
```

Expected: a JSON log line with `event="done"`, the job id matching the smoke test, populated `clip_count`, `aspects`, `duration_sec`, `render_time_sec`, `gpu_seconds`.

- [ ] **Step 5: Sign off**

If all four manual checks pass, the v1 service is ready. Tag the commit and roll into a release PR:

```bash
# Tag scoped to the directory since the repo holds several components.
git tag cloud-run-compiler/v1.0.0
git push origin cloud-run-compiler/v1.0.0
gh pr create --title "compiler: v1 launch" --body "Implementation of docs/superpowers/specs/2026-05-17-compilation-service-design.md, plan at docs/superpowers/plans/2026-05-17-compilation-service.md"
```

(If the repo's tag convention turns out to be flat `vX.Y.Z` instead, swap accordingly — check `git tag -l | head` first.)

**End of Chunk 10.** End of plan. The service is deployed, smoke-tested, and ready.

---

## Plan-level summary of v1 limitations (also recorded in source comments)

- No per-clip `in_sec`/`out_sec` trim (validated-rejected; v2+).
- `naddr` lists with `a` (addressable-ref) tags surface those refs in `clips_dropped` with `addressable_ref_not_supported_v1`; resolving them is v2+.
- Worker job-claim is best-effort, not fully atomic. With max 5 instances × 4 concurrent each, the duplicate-claim window is small but real. v2: switch to `FirestoreDb::run_transaction`.
- Audio-less clips will fail the render. v2: probe audio streams up front and inject silence with `anullsrc` for muted inputs.
- Content-type on GCS uploads — implementer chooses between `UploadType::Multipart` (recommended) or `patch_object` follow-up at impl time.
- `firestore` crate version may need a bump from the pinned 0.43 if that version isn't current at impl time; `paths!`/`start_after` API drift may require adjustment.
- `api.divine.video` endpoint paths are best-guesses; verify against the actual OpenAPI spec at impl time.
- NIP-01 canonicalization uses `serde_json::to_string` round-trip; not interop-safe with arbitrary external signers — see `nip98.rs` caveat.
- 720p HLS-as-input not supported (always download MP4 original per spec).
- Streaming GCS upload deferred — full file read into memory is fine for v1's expected file sizes.
- Smoke test depends on a real `SMOKE_NADDR` fixture; operator must supply one with 2–3 small videos for the first run.

