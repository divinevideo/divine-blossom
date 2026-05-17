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

**End of Chunk 3.** Job records can now be persisted and queried. Next chunk: auth and rate limiting.

