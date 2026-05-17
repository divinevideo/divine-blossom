# Compilation Service Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development (if available) or superpowers:executing-plans. Steps use `- [ ]` checkboxes.

**Goal:** New Cloud Run GPU service `cloud-run-compiler/` (parallel to `cloud-run-transcoder/`) that takes a Nostr list of video events, downloads source MP4s from blossom, and produces concatenated MP4s in three aspect ratios (9:16, 1:1, 16:9) with a Divine logo watermark and per-clip nip05 credits burned in. Async jobs, HMAC-signed webhook callback. NIP-98 or webhook-secret auth.

**Architecture:** Single Rust crate. axum HTTP server on Cloud Run GPU (NVIDIA L4), NVENC encoding via system FFmpeg. Firestore for job state at `compilation_jobs/<job_id>`. Source events via `https://api.divine.video` REST. Source blobs via `https://media.divine.video/<sha256>`. Outputs uploaded to GCS bucket `divine-blossom-media`. Concurrency cap of 4 jobs per Cloud Run instance.

**Tech Stack:** Rust 1.83, axum 0.7, tokio, reqwest, `firestore` crate, `nostr` crate (for NIP-19 decode + NIP-98 verification — do NOT hand-roll), `google-cloud-storage`, system FFmpeg + NVENC + Noto Sans fonts.

**Spec:** `docs/superpowers/specs/2026-05-17-compilation-service-design.md`

**KISS posture:** Every file ships only what v1 needs. We don't build forward-compatible schemas, don't pre-check moderation (let downloads fail and surface), don't split modules into trees, don't add dry-run / per-clip-override / cancel / requeue / lease-CAS until someone actually asks. v1-deferred items from the spec stay deferred — they get added when there's real demand, not on speculation.

---

## File Structure (final)

```
cloud-run-compiler/
├── Cargo.toml          # deps incl. `nostr` crate
├── Cargo.lock          # committed
├── Dockerfile          # nvidia/cuda + ffmpeg + Noto fonts
├── .dockerignore
├── .gitignore
├── deploy.sh           # Cloud Build + Cloud Run deploy
├── scripts/
│   ├── firestore-emulator.sh
│   └── smoke-test.sh
├── src/
│   ├── main.rs         # axum bootstrap, worker spawn
│   ├── lib.rs          # pub mod exports (library face for integration tests)
│   ├── config.rs       # Config struct + env loading
│   ├── job.rs          # Job, JobStatus, JobResult, CompileRequest, Firestore CRUD
│   ├── auth.rs         # Tenant extractor (NIP-98 via `nostr` crate + webhook secret)
│   ├── rate_limit.rs   # Firestore counter w/ hourly+daily buckets
│   ├── nostr_api.rs    # api.divine.video REST client + imeta parse
│   ├── blossom.rs      # download + GCS upload
│   ├── render.rs       # probe + filtergraph builders + ffmpeg exec
│   ├── webhook.rs      # HMAC sign + deliver with retry
│   ├── handlers.rs     # axum router + POST /compile + GET /compile/:id + admin
│   └── worker.rs       # background loop: poll queued → fetch → render → upload → callback
└── tests/
    ├── common/mod.rs           # Firestore emulator helper
    ├── config.rs               # env loading
    ├── job_types_serde.rs      # CompileRequest + Job round-trip
    ├── job_store.rs            # Firestore CRUD (gated by emulator)
    ├── auth.rs                 # NIP-98 via nostr crate + webhook secret extractor
    ├── rate_limit.rs           # Firestore counter (gated by emulator)
    ├── nostr_api.rs            # api.divine.video wiremock tests
    ├── blossom.rs              # download wiremock tests
    ├── render_filters.rs       # pure fit + overlay filtergraph string builders
    ├── render_ffmpeg_args.rs   # pure ffmpeg-command builder
    ├── render_smoke.rs         # end-to-end render with tiny fixture clips (gated by ffmpeg)
    └── webhook.rs              # HMAC sign + deliver + retry
```

**Why these files (one line each):**

| File | Responsibility |
|---|---|
| `main.rs` | wire config → state → axum router → spawn worker, bind PORT |
| `config.rs` | `Config { firestore_project, gcs_bucket, api_url, media_url, webhook_secrets, admin_token, ... }` |
| `job.rs` | `Job`, `JobStatus`, `JobResult`, `CompileRequest` types + `JobStore` (Firestore CRUD) — one cohesive module |
| `auth.rs` | `Tenant` enum + axum extractor that runs NIP-98 (via `nostr::nips::nip98`) then webhook secret |
| `rate_limit.rs` | `RateLimiter::check_and_increment(tenant_id, now)` |
| `nostr_api.rs` | `ApiClient::{fetch_event, fetch_profile, fetch_list_event}` + `Imeta::first_in(event)` |
| `blossom.rs` | `DownloadClient::download(sha256, dest)` + `GcsUploader::upload_file(path)` |
| `render.rs` | `probe(file)`, `build_command(AspectJob)`, `run_render(AspectJob)` (GPU→CPU fallback), `render_aspect(...)` |
| `webhook.rs` | `sign(secret, body)`, `verify(...)`, `deliver(url, body, secret) -> CallbackDelivery` |
| `handlers.rs` | axum `Router` building, all HTTP handlers (POST /compile, GET /compile/:id, GET /admin/jobs, GET /admin/jobs/:id, /health) |
| `worker.rs` | `Worker::run_forever()` poll loop, `process_job(job)` orchestration |

---

## Chunk 1: Scaffold

Goal: crate exists, builds, runs `/health` locally, deploy.sh ready.

### Task 1.1: Crate + Cargo.toml + axum bootstrap

**Files:** Create `cloud-run-compiler/{Cargo.toml, .dockerignore, .gitignore, src/main.rs, src/lib.rs}`.

- [ ] **Step 1: Cargo.toml**

```toml
# ABOUTME: Cargo manifest for GPU video compilation Cloud Run service
# ABOUTME: Concatenates Nostr-listed videos with watermark + credits via NVENC

[package]
name = "divine-compiler"
version = "0.1.0"
edition = "2021"

[lib]
name = "divine_compiler"
path = "src/lib.rs"

[[bin]]
name = "divine-compiler"
path = "src/main.rs"

[dependencies]
axum = { version = "0.7", features = ["http2"] }
tokio = { version = "1", features = ["full", "process"] }
tower-http = { version = "0.5", features = ["trace"] }
hyper = { version = "1", features = ["http2", "server"] }

# Pinned to match cloud-run-transcoder (edition2024 workarounds)
google-cloud-storage = "=0.17.0"
google-cloud-auth = "=0.12.0"
home = "=0.5.9"
base64ct = "=1.6.0"
time = "=0.3.36"

firestore = "0.43"  # verify latest 0.4x at impl time, pin to whatever resolves

serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = { version = "0.4", features = ["serde"] }

hex = "0.4"
base64 = "0.22"
sha2 = "0.10"
hmac = "0.12"

# NIP-98 verification + NIP-19 (naddr/nevent) decode — DO NOT hand-roll either.
nostr = { version = "0.34", default-features = false, features = ["std", "nip19", "nip98"] }

futures = "0.3"
bytes = "1"
tempfile = "3"
urlencoding = "2"
uuid = { version = "=1.12.1", features = ["v4"] }

reqwest = { version = "0.11", features = ["rustls-tls", "json"], default-features = false }

anyhow = "1"
thiserror = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

[dev-dependencies]
wiremock = "0.6"

[profile.release]
lto = true
opt-level = 3
strip = true
```

> **Implementer note on `nostr` crate version:** 0.34 is the latest known at plan-write time. If a newer is stable, bump and skim its CHANGELOG for breaking changes in `nip19` / `nip98`. The API we use is stable: `Nip19::from_bech32(...)`, `nip98::Event::verify(...)`-style or equivalent.

- [ ] **Step 2: `.dockerignore` and `.gitignore`**

`.dockerignore`:
```
target/
.git/
.gitignore
*.md
tests/
```

`.gitignore`:
```
/target/
*.rs.bk
```

- [ ] **Step 3: `src/lib.rs`**

```rust
// ABOUTME: Library face for the compiler service (binary is src/main.rs)
pub mod config;
pub mod job;
pub mod auth;
pub mod rate_limit;
pub mod nostr_api;
pub mod blossom;
pub mod render;
pub mod webhook;
pub mod handlers;
pub mod worker;
```

(Some of these don't exist yet — leave them commented out and uncomment as later chunks add them, OR declare empty `pub mod X { }` stubs now and fill in.)

- [ ] **Step 4: `src/main.rs`** (minimal)

```rust
// ABOUTME: Cloud Run service that compiles Nostr-listed videos into watermarked MP4 compilations

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

- [ ] **Step 5: Build + run + curl**

```bash
cd cloud-run-compiler && cargo build
cargo run >/tmp/compiler.log 2>&1 & SERVER_PID=$!
sleep 2 && curl -s http://localhost:8080/health
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
```

Expected: `ok`.

- [ ] **Step 6: cargo fmt + clippy clean baseline**

```bash
cd cloud-run-compiler && cargo fmt --check && cargo clippy --all-targets -- -D warnings
```

Expected: no diffs, no warnings.

- [ ] **Step 7: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): scaffold crate with axum + /health"
```

### Task 1.2: Dockerfile

**File:** Create `cloud-run-compiler/Dockerfile`.

- [ ] **Step 1: Multi-stage build**

```dockerfile
# ABOUTME: Dockerfile for GPU video compilation Cloud Run service
# ABOUTME: NVIDIA CUDA runtime + FFmpeg NVENC + Noto Sans fonts for credit overlays

FROM rust:1.83-slim-bookworm AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs
RUN cargo build --release
RUN rm -rf src
COPY src ./src
RUN touch src/main.rs && cargo build --release

# Runtime: Ubuntu 22.04 (Jammy) CUDA. Use Ubuntu snapshots (NOT debian.snapshot)
# since the base is Jammy.
FROM nvidia/cuda:12.2.2-runtime-ubuntu22.04
WORKDIR /app
ARG UBUNTU_SNAPSHOT=20260501T000000Z
RUN if [ -n "${UBUNTU_SNAPSHOT}" ]; then \
      sed -i "s|http://archive.ubuntu.com/ubuntu|https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}|g; s|http://security.ubuntu.com/ubuntu|https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}|g" \
        /etc/apt/sources.list; \
    fi
RUN apt-get update && apt-get install -y \
    ca-certificates ffmpeg \
    fonts-noto-core fonts-noto-cjk fonts-noto-extra fontconfig \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/divine-compiler /app/divine-compiler
ENV PORT=8080
ENV NVIDIA_VISIBLE_DEVICES=all
ENV NVIDIA_DRIVER_CAPABILITIES=compute,video,utility
CMD ["/app/divine-compiler"]
```

- [ ] **Step 2: Commit**

```bash
git add cloud-run-compiler/Dockerfile
git commit -m "feat(compiler): Dockerfile with NVIDIA CUDA + ffmpeg + Noto fonts"
```

### Task 1.3: Config

**Files:** Create `src/config.rs` + `tests/config.rs`.

- [ ] **Step 1: Tests first**

```rust
// tests/config.rs
use divine_compiler::config::Config;
use std::collections::HashMap;

fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

#[test]
fn loads_defaults_with_only_required_vars() {
    let cfg = Config::from_env(&env(&[
        ("FIRESTORE_PROJECT", "p"),
        ("GCS_BUCKET", "b"),
    ])).unwrap();
    assert_eq!(cfg.firestore_project, "p");
    assert_eq!(cfg.gcs_bucket, "b");
    assert_eq!(cfg.api_url, "https://api.divine.video");
    assert_eq!(cfg.media_url, "https://media.divine.video");
    assert_eq!(cfg.max_concurrent_jobs, 4);
    assert!(cfg.webhook_secrets.is_empty());
}

#[test]
fn parses_webhook_secrets_env() {
    let cfg = Config::from_env(&env(&[
        ("FIRESTORE_PROJECT", "p"), ("GCS_BUCKET", "b"),
        ("COMPILER_WEBHOOK_SECRETS", "funnelcake:abc,janitor:def"),
    ])).unwrap();
    assert_eq!(cfg.webhook_secrets.get("abc"), Some(&"funnelcake".into()));
    assert_eq!(cfg.webhook_secrets.get("def"), Some(&"janitor".into()));
}

#[test]
fn rejects_malformed_secrets() {
    let res = Config::from_env(&env(&[
        ("FIRESTORE_PROJECT", "p"), ("GCS_BUCKET", "b"),
        ("COMPILER_WEBHOOK_SECRETS", "bad:abc,123"),
    ]));
    assert!(res.is_err());
}

#[test]
fn errors_on_missing_required() {
    assert!(Config::from_env(&env(&[("GCS_BUCKET", "b")])).is_err());
}
```

- [ ] **Step 2: Implement**

```rust
// src/config.rs
// ABOUTME: Config loaded from env at startup. Required: FIRESTORE_PROJECT, GCS_BUCKET.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Config {
    pub firestore_project: String,
    pub gcs_bucket: String,
    pub api_url: String,
    pub media_url: String,
    pub webhook_secrets: HashMap<String, String>, // secret_value -> tenant_name
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
        let firestore_project = env.get("FIRESTORE_PROJECT").ok_or(ConfigError::Missing("FIRESTORE_PROJECT"))?.clone();
        let gcs_bucket = env.get("GCS_BUCKET").ok_or(ConfigError::Missing("GCS_BUCKET"))?.clone();
        let api_url = env.get("API_DIVINE_VIDEO_URL").cloned().unwrap_or_else(|| "https://api.divine.video".into());
        let media_url = env.get("MEDIA_DIVINE_VIDEO_URL").cloned().unwrap_or_else(|| "https://media.divine.video".into());
        let webhook_secrets = parse_webhook_secrets(env.get("COMPILER_WEBHOOK_SECRETS"))?;
        let admin_token = env.get("COMPILER_ADMIN_TOKEN").cloned();
        let max_concurrent_jobs = env.get("MAX_CONCURRENT_JOBS").and_then(|s| s.parse().ok()).unwrap_or(4);
        let rate_limit_per_hour = env.get("RATE_LIMIT_PER_HOUR").and_then(|s| s.parse().ok()).unwrap_or(20);
        let rate_limit_per_day = env.get("RATE_LIMIT_PER_DAY").and_then(|s| s.parse().ok()).unwrap_or(100);
        Ok(Config { firestore_project, gcs_bucket, api_url, media_url, webhook_secrets, admin_token, max_concurrent_jobs, rate_limit_per_hour, rate_limit_per_day })
    }
    pub fn from_process_env() -> Result<Self, ConfigError> {
        Self::from_env(&std::env::vars().collect())
    }
}

fn parse_webhook_secrets(raw: Option<&String>) -> Result<HashMap<String, String>, ConfigError> {
    let Some(raw) = raw else { return Ok(HashMap::new()); };
    let mut out = HashMap::new();
    for pair in raw.split(',').filter(|s| !s.is_empty()) {
        let colons = pair.bytes().filter(|b| *b == b':').count();
        if colons != 1 {
            return Err(ConfigError::Invalid {
                var: "COMPILER_WEBHOOK_SECRETS",
                detail: format!("pair `{}` has {} colons, expected 1", pair, colons),
            });
        }
        let (name, secret) = pair.split_once(':').unwrap();
        if name.is_empty() || secret.is_empty() {
            return Err(ConfigError::Invalid {
                var: "COMPILER_WEBHOOK_SECRETS",
                detail: format!("empty name or secret in `{}`", pair),
            });
        }
        out.insert(secret.to_string(), name.to_string());
    }
    Ok(out)
}
```

- [ ] **Step 3: Wire `from_process_env()` into `main.rs`** (replace the empty main body to read config and log it).

- [ ] **Step 4: Run** `cargo test --test config`. Expected: 4 pass.

- [ ] **Step 5: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): Config struct with env parsing + webhook secret map"
```

### Task 1.4: deploy.sh

**File:** Create `cloud-run-compiler/deploy.sh`.

- [ ] **Step 1: Write the deploy script**

```bash
#!/bin/bash
# ABOUTME: Deploy divine-compiler to Cloud Run GPU with Firestore + secrets wired
# ABOUTME: Builds in Cloud Build, then deploys

# ONE-TIME SETUP (per project):
#   gcloud services enable firestore.googleapis.com cloudbuild.googleapis.com run.googleapis.com --project="${PROJECT_ID}"
#   gcloud firestore databases create --location="us-central" --project="${PROJECT_ID}"  # if absent
#   gcloud firestore fields ttls update expires_at --collection-group=rate_limits \
#     --enable-ttl --project="${PROJECT_ID}"
#   gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
#     --member="serviceAccount:${SERVICE_ACCOUNT}" --role="roles/datastore.user"
#   gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
#     --member="serviceAccount:${SERVICE_ACCOUNT}" --role="roles/storage.objectAdmin"
#   echo -n "name1:secret1,name2:secret2" | gcloud secrets create compiler_webhook_secrets \
#     --data-file=- --project="${PROJECT_ID}"
#   echo -n "your-admin-bearer-token" | gcloud secrets create compiler_admin_token \
#     --data-file=- --project="${PROJECT_ID}"

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
gcloud builds submit "${SCRIPT_DIR}" --project "${PROJECT_ID}" --region "${REGION}" --tag "${IMAGE}"

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
  --set-env-vars "^@@^GCS_BUCKET=${GCS_BUCKET}@@FIRESTORE_PROJECT=${FIRESTORE_PROJECT}@@API_DIVINE_VIDEO_URL=${API_DIVINE_VIDEO_URL}@@MEDIA_DIVINE_VIDEO_URL=${MEDIA_DIVINE_VIDEO_URL}@@MAX_CONCURRENT_JOBS=${MAX_CONCURRENT_JOBS}@@RATE_LIMIT_PER_HOUR=${RATE_LIMIT_PER_HOUR}@@RATE_LIMIT_PER_DAY=${RATE_LIMIT_PER_DAY}" \
  --set-secrets "COMPILER_WEBHOOK_SECRETS=compiler_webhook_secrets:latest,COMPILER_ADMIN_TOKEN=compiler_admin_token:latest"

SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" --project "${PROJECT_ID}" --region "${REGION}" --format='value(status.url)')
echo "Service URL: ${SERVICE_URL}"
curl -fsS "${SERVICE_URL}/health" && echo " — OK"
```

- [ ] **Step 2: chmod + commit**

```bash
chmod +x cloud-run-compiler/deploy.sh
git add cloud-run-compiler/deploy.sh
git commit -m "feat(compiler): deploy.sh for Cloud Run GPU L4"
```

**End of Chunk 1.**

---

## Chunk 2: Job types + Firestore store

Goal: define `CompileRequest`, `Job`, `JobStatus`, `JobResult` (v1-only — no forward-compat fields), and Firestore CRUD. One file: `src/job.rs`.

### Task 2.1: Types

**Files:** Create `src/job.rs`, `tests/job_types_serde.rs`.

- [ ] **Step 1: Tests first**

```rust
// tests/job_types_serde.rs
use divine_compiler::job::*;
use serde_json::json;

#[test]
fn parses_minimal_request_with_naddr() {
    let r: CompileRequest = serde_json::from_value(json!({
        "source": { "naddr": "naddr1abc" }
    })).unwrap();
    match r.source {
        Source::Naddr(s) => assert_eq!(s, "naddr1abc"),
        _ => panic!(),
    }
    assert_eq!(r.aspects, vec![Aspect::Vertical]);
    assert_eq!(r.fit, Fit::BlurPad);
    assert_eq!(r.max_duration_sec, 600);
}

#[test]
fn parses_full_request() {
    let r: CompileRequest = serde_json::from_value(json!({
        "source": { "event_ids": ["a", "b"] },
        "aspects": ["9:16", "1:1", "16:9"],
        "fit": "center-crop",
        "watermark": { "enabled": true, "position": "top-right", "opacity": 0.5 },
        "credit": { "show_display_name": true, "show_nip05": true, "duration_ms": 3000 },
        "audio": { "target_lufs": -16.0 },
        "max_duration_sec": 300,
        "callback_url": "https://example.com/hook"
    })).unwrap();
    assert_eq!(r.aspects.len(), 3);
    assert_eq!(r.watermark.position, WatermarkPosition::TopRight);
}

#[test]
fn rejects_unknown_top_level_field() {
    let r = serde_json::from_value::<CompileRequest>(json!({
        "source": { "naddr": "n" }, "dry_run": true
    }));
    assert!(r.is_err(), "dry_run is v2+; must be rejected");
}

#[test]
fn rejects_unsupported_aspect() {
    let r = serde_json::from_value::<CompileRequest>(json!({
        "source": { "naddr": "n" }, "aspects": ["4:3"]
    }));
    assert!(r.is_err());
}

#[test]
fn job_round_trips_through_json() {
    let req: CompileRequest = serde_json::from_value(json!({ "source": { "naddr": "n" } })).unwrap();
    let job = Job {
        job_id: "cmp_x".into(), status: JobStatus::Queued, progress: 0.0,
        request: req, tenant_id: "pubkey:dead".into(),
        created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
        result: None, error: None, callback_delivery: None,
    };
    let s = serde_json::to_string(&job).unwrap();
    let d: Job = serde_json::from_str(&s).unwrap();
    assert_eq!(d.job_id, "cmp_x");
}
```

- [ ] **Step 2: Implement `src/job.rs`** — types only, store comes next

```rust
// ABOUTME: Compile job types + Firestore CRUD. One module, one job_id keyspace.

use serde::{Deserialize, Serialize};

// --- Request ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompileRequest {
    pub source: Source,
    #[serde(default = "default_aspects")]
    pub aspects: Vec<Aspect>,
    #[serde(default)]
    pub fit: Fit,
    #[serde(default)]
    pub watermark: Watermark,
    #[serde(default)]
    pub credit: Credit,
    #[serde(default)]
    pub audio: Audio,
    #[serde(default = "default_max_duration_sec")]
    pub max_duration_sec: u32,
    #[serde(default)]
    pub callback_url: Option<String>,
}

fn default_aspects() -> Vec<Aspect> { vec![Aspect::Vertical] }
fn default_max_duration_sec() -> u32 { 600 }

/// V1: only `naddr` or `event_ids`. `nevents` is not exposed — callers
/// hex-decode if they have nevent strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Naddr(String),
    EventIds(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Aspect {
    #[serde(rename = "9:16")] Vertical,
    #[serde(rename = "1:1")] Square,
    #[serde(rename = "16:9")] Horizontal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fit { BlurPad, CenterCrop, Letterbox }
impl Default for Fit { fn default() -> Self { Fit::BlurPad } }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Watermark {
    #[serde(default = "_true")] pub enabled: bool,
    #[serde(default)] pub position: WatermarkPosition,
    #[serde(default = "default_opacity")] pub opacity: f32,
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

/// V1 ships ONE credit style: `lower-third-fade`. No `mode` field on the
/// request — we removed the v2 modes (always-on, corner-pill, off) from the
/// schema entirely. If you need them, add a `mode` field later.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credit {
    #[serde(default = "default_credit_duration")] pub duration_ms: u32,
    #[serde(default = "_true")] pub show_display_name: bool,
    #[serde(default = "_true")] pub show_nip05: bool,
}
impl Default for Credit { fn default() -> Self { Self { duration_ms: 2500, show_display_name: true, show_nip05: true } } }
fn default_credit_duration() -> u32 { 2500 }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Audio {
    #[serde(default = "default_target_lufs")] pub target_lufs: f32,
}
impl Default for Audio { fn default() -> Self { Self { target_lufs: -14.0 } } }
fn default_target_lufs() -> f32 { -14.0 }

// --- Job state ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus { Queued, Running, Done, Failed }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub job_id: String,
    pub status: JobStatus,
    #[serde(default)] pub progress: f32,
    pub request: CompileRequest,
    pub tenant_id: String, // "pubkey:<hex>" or "secret:<name>"
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)] pub result: Option<JobResult>,
    #[serde(default)] pub error: Option<String>,
    #[serde(default)] pub callback_delivery: Option<CallbackDelivery>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    pub outputs: Vec<BlobDescriptor>,
    pub duration_sec: u32,
    pub clips_used: u32,
    pub clips_dropped: Vec<ClipDropped>,
    pub credits: Vec<RenderedCredit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobDescriptor {
    pub aspect: Aspect, pub url: String, pub sha256: String, pub size: u64, pub dim: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipDropped { pub event_id: String, pub reason: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedCredit {
    pub event_id: String, pub pubkey: String,
    #[serde(default)] pub nip05: Option<String>,
    #[serde(default)] pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackDelivery {
    pub attempts: u32,
    pub last_attempt_at: chrono::DateTime<chrono::Utc>,
    pub last_status_code: u16,
    pub delivered: bool,
}
```

- [ ] **Step 3: Run** `cargo test --test job_types_serde`. Expected: 5 pass.

- [ ] **Step 4: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): CompileRequest + Job state types (v1 only)"
```

### Task 2.2: Firestore store

**Files:** Append `JobStore` to `src/job.rs`; create `scripts/firestore-emulator.sh`, `tests/common/mod.rs`, `tests/job_store.rs`.

- [ ] **Step 1: Emulator launch script**

```bash
#!/bin/bash
# scripts/firestore-emulator.sh
set -euo pipefail
PORT="${FIRESTORE_EMULATOR_PORT:-8085}"
PROJECT="${FIRESTORE_PROJECT:-test-project}"
exec gcloud emulators firestore start --host-port="127.0.0.1:${PORT}" --project="${PROJECT}"
```

`chmod +x cloud-run-compiler/scripts/firestore-emulator.sh`

- [ ] **Step 2: `tests/common/mod.rs`** — emulator helper

```rust
// ABOUTME: Shared test helpers. NOT compiled as its own test binary (lives in tests/common/).

use divine_compiler::job::JobStore;

pub async fn store_for_tests(suffix: &str) -> JobStore {
    let _ = std::env::var("FIRESTORE_EMULATOR_HOST").expect(
        "FIRESTORE_EMULATOR_HOST must be set; run via `cargo test -- --ignored` with the emulator"
    );
    let project = std::env::var("FIRESTORE_PROJECT").unwrap_or_else(|_| "test-project".into());
    let collection = format!("compilation_jobs_test_{}", suffix);
    JobStore::with_collection(&project, &collection).await.expect("connect emulator")
}
```

- [ ] **Step 3: Append `JobStore` to `src/job.rs`**

```rust
// --- Firestore store ---

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
        let db = FirestoreDb::with_options(FirestoreDbOptions::new(project_id.to_string()))
            .await.context("connect firestore")?;
        Ok(Self { db, collection: collection.into() })
    }

    pub async fn create_job(&self, job: &Job) -> Result<()> {
        self.db.fluent().insert().into(&self.collection).document_id(&job.job_id)
            .object(job).execute::<()>().await.context("insert job")?;
        Ok(())
    }

    pub async fn get_job(&self, job_id: &str) -> Result<Option<Job>> {
        let r: Option<Job> = self.db.fluent().select().by_id_in(&self.collection)
            .obj().one(job_id).await.context("get job")?;
        Ok(r)
    }

    pub async fn update_job(&self, job: &Job) -> Result<()> {
        let mut updated = job.clone();
        updated.updated_at = chrono::Utc::now();
        self.db.fluent().update().in_col(&self.collection).document_id(&updated.job_id)
            .object(&updated).execute::<()>().await.context("update job")?;
        Ok(())
    }

    /// Newest first. `status` filter optional.
    pub async fn list_recent(&self, limit: u32, status_filter: Option<JobStatus>) -> Result<Vec<Job>> {
        let mut q = self.db.fluent().select()
            .from(self.collection.as_str())
            .order_by([(paths!(Job::created_at), FirestoreQueryDirection::Descending)])
            .limit(limit);
        if let Some(s) = status_filter {
            q = q.filter(|qb| qb.field(paths!(Job::status)).eq(s));
        }
        let items: Vec<Job> = q.obj().query().await.context("list jobs")?;
        Ok(items)
    }
}
```

> **Implementer note on the `firestore` crate fluent API:** the `paths!` macro and `start_after`/cursor semantics drift between minor versions. Before writing this, run `cargo doc -p firestore --open` and confirm: `paths!` vs `path!`, the exact signature of `update().in_col().document_id().object()`, and the cursor type. The CRUD shapes (insert, get, update, query with order+limit+filter) are stable across recent 0.4x; only the exact method names move.

- [ ] **Step 4: Store tests (`tests/job_store.rs`)**

All `#[ignore]`d so default `cargo test` skips them when the emulator isn't running.

```rust
mod common;
use divine_compiler::job::*;
use serde_json::json;
use uuid::Uuid;

fn fixture(id: &str) -> Job {
    Job {
        job_id: id.into(), status: JobStatus::Queued, progress: 0.0,
        request: serde_json::from_value(json!({ "source": { "naddr": "n" } })).unwrap(),
        tenant_id: "pubkey:dead".into(),
        created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
        result: None, error: None, callback_delivery: None,
    }
}

#[tokio::test]
#[ignore]
async fn round_trip_create_get() {
    let s = common::store_for_tests(&Uuid::new_v4().simple().to_string()).await;
    let j = fixture("cmp_a");
    s.create_job(&j).await.unwrap();
    assert_eq!(s.get_job("cmp_a").await.unwrap().unwrap().job_id, "cmp_a");
    assert!(s.get_job("nope").await.unwrap().is_none());
}

#[tokio::test]
#[ignore]
async fn update_persists() {
    let s = common::store_for_tests(&Uuid::new_v4().simple().to_string()).await;
    let mut j = fixture("cmp_u");
    s.create_job(&j).await.unwrap();
    j.status = JobStatus::Done;
    s.update_job(&j).await.unwrap();
    assert_eq!(s.get_job("cmp_u").await.unwrap().unwrap().status, JobStatus::Done);
}

#[tokio::test]
#[ignore]
async fn list_recent_orders_desc_and_filters_status() {
    let s = common::store_for_tests(&Uuid::new_v4().simple().to_string()).await;
    for i in 0..3 {
        let mut j = fixture(&format!("cmp_{}", i));
        j.created_at = chrono::Utc::now() + chrono::Duration::seconds(i);
        if i == 1 { j.status = JobStatus::Done; }
        s.create_job(&j).await.unwrap();
    }
    let all = s.list_recent(10, None).await.unwrap();
    assert!(all.windows(2).all(|w| w[0].created_at >= w[1].created_at));
    let done_only = s.list_recent(10, Some(JobStatus::Done)).await.unwrap();
    assert!(done_only.iter().all(|j| j.status == JobStatus::Done));
}
```

- [ ] **Step 5: Run** — with emulator running, `cargo test --test job_store -- --ignored`. Expected: 3 pass.

- [ ] **Step 6: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): Firestore JobStore CRUD with emulator-backed integration tests"
```

**End of Chunk 2.**

---

## Chunk 3: Auth + rate limiting

Goal: NIP-98 (via the `nostr` crate — do NOT hand-roll) + webhook secret extractor, plus per-tenant Firestore rate limiting.

### Task 3.1: Tenant + auth extractor

**Files:** Create `src/auth.rs`, `tests/auth.rs`.

The `nostr` crate provides `nostr::nips::nip98` — use it. The exact entry point varies (commonly `nip98::HttpData` / `Event::is_valid_nip98(method, url)`), so the implementer should check the crate docs and adapt.

- [ ] **Step 1: Tests** — fixtures use `nostr` for signing too, so we don't reimplement schnorr/Keypair plumbing.

```rust
// tests/auth.rs
use divine_compiler::auth::{extract_tenant, Tenant};
use std::collections::HashMap;

// Build a valid NIP-98 token using the nostr crate's helpers.
fn make_nip98_header(method: &str, url: &str) -> String {
    use nostr::prelude::*;
    let keys = Keys::generate();
    let event = EventBuilder::http_auth(
        url.parse().unwrap(),
        nostr::nips::nip98::HttpMethod::from(method).unwrap_or(nostr::nips::nip98::HttpMethod::Post),
    )
    .to_event(&keys).unwrap();
    let json = serde_json::to_string(&event).unwrap();
    use base64::Engine as _;
    format!("Nostr {}", base64::engine::general_purpose::STANDARD.encode(json))
}

fn secrets() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("abc123".into(), "funnelcake".into());
    m
}

#[test]
fn nip98_header_extracts_pubkey() {
    let header = make_nip98_header("POST", "https://example.com/compile");
    let t = extract_tenant(Some(&header), "POST", "https://example.com/compile", &secrets()).unwrap();
    assert!(matches!(t, Tenant::Pubkey(_)));
}

#[test]
fn bearer_known_secret_yields_tenant_name() {
    let t = extract_tenant(Some("Bearer abc123"), "POST", "https://x", &secrets()).unwrap();
    assert_eq!(t, Tenant::Secret("funnelcake".into()));
}

#[test]
fn missing_header_is_401() {
    let err = extract_tenant(None, "POST", "https://x", &HashMap::new()).unwrap_err();
    assert!(matches!(err, divine_compiler::auth::AuthError::Missing));
}

#[test]
fn unknown_bearer_is_401() {
    let err = extract_tenant(Some("Bearer nope"), "POST", "https://x", &secrets()).unwrap_err();
    assert!(matches!(err, divine_compiler::auth::AuthError::InvalidSecret));
}

#[test]
fn wrong_url_on_nip98_token_fails() {
    let header = make_nip98_header("POST", "https://example.com/a");
    let err = extract_tenant(Some(&header), "POST", "https://example.com/b", &secrets()).unwrap_err();
    assert!(matches!(err, divine_compiler::auth::AuthError::InvalidNip98(_)));
}
```

> The exact `nostr` API call sites above are illustrative — confirm against the pinned `nostr = "0.34"` (or newer) docs. The crate's `nip98` module is the canonical helper for both signing and verifying NIP-98 events; the test fixture and the verifier must use the same module so the canonicalization matches.

- [ ] **Step 2: Implement `src/auth.rs`**

```rust
// ABOUTME: Auth extraction: NIP-98 (via nostr crate) preferred, webhook secret as fallback
// ABOUTME: Yields a Tenant used for rate-limiting bucket id + audit logging

use crate::config::Config;
use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tenant {
    Pubkey(String),
    Secret(String),
}
impl Tenant {
    pub fn id(&self) -> String {
        match self { Tenant::Pubkey(h) => format!("pubkey:{}", h), Tenant::Secret(n) => format!("secret:{}", n) }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum AuthError {
    #[error("missing authorization header")] Missing,
    #[error("invalid nip98 token: {0}")] InvalidNip98(String),
    #[error("invalid webhook secret")] InvalidSecret,
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub job_store: Arc<crate::job::JobStore>,
    pub rate_limiter: Arc<crate::rate_limit::RateLimiter>,
}

pub fn extract_tenant(
    auth_header: Option<&str>,
    method: &str,
    url: &str,
    secrets: &HashMap<String, String>,
) -> Result<Tenant, AuthError> {
    let header = auth_header.ok_or(AuthError::Missing)?;

    if let Some(rest) = header.strip_prefix("Nostr ") {
        // Decode the base64 NIP-98 event and verify via the nostr crate.
        // The nostr crate exposes NIP-98 helpers; the exact entry point may
        // be `nostr::nips::nip98::HttpData` or an `Event` method depending
        // on version. Adapt at implementation time.
        return verify_nip98(rest.trim(), method, url).map(Tenant::Pubkey);
    }
    if let Some(rest) = header.strip_prefix("Bearer ") {
        return secrets.get(rest.trim())
            .cloned().map(Tenant::Secret).ok_or(AuthError::InvalidSecret);
    }
    Err(AuthError::Missing)
}

/// Verify a base64-encoded NIP-98 event matches the given method+url.
/// Returns the pubkey hex on success.
fn verify_nip98(b64: &str, method: &str, url: &str) -> Result<String, AuthError> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD.decode(b64)
        .map_err(|e| AuthError::InvalidNip98(format!("base64: {}", e)))?;
    let event: nostr::Event = serde_json::from_slice(&raw)
        .map_err(|e| AuthError::InvalidNip98(format!("json: {}", e)))?;
    // The nostr crate's NIP-98 module checks: kind 27235, signature valid,
    // u-tag == url, method-tag == method, created_at within ±60s.
    // The exact API: in nostr 0.34 this is likely a method on Event or a
    // helper in `nostr::nips::nip98`. Adjust call site to whichever the
    // pinned version exposes.
    event.verify().map_err(|e| AuthError::InvalidNip98(format!("sig: {}", e)))?;
    nostr::nips::nip98::HttpData::try_from(&event)
        .map_err(|e| AuthError::InvalidNip98(format!("nip98 shape: {}", e)))?
        .check(method, url)
        .map_err(|e| AuthError::InvalidNip98(format!("nip98 check: {}", e)))?;
    Ok(event.pubkey.to_hex())
}

// --- axum extractor ---

#[async_trait]
impl<S> FromRequestParts<S> for Tenant
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AuthRejection;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app = AppState::from_ref(state);
        let auth = parts.headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok());
        let scheme = parts.headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()).unwrap_or("https");
        let host = parts.headers.get("x-forwarded-host")
            .or_else(|| parts.headers.get(axum::http::header::HOST))
            .and_then(|v| v.to_str().ok()).unwrap_or("");
        let pq = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let url = format!("{}://{}{}", scheme, host, pq);
        extract_tenant(auth, parts.method.as_str(), &url, &app.config.webhook_secrets).map_err(AuthRejection)
    }
}

pub struct AuthRejection(pub AuthError);
impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "unauthorized", "detail": self.0.to_string()
        }))).into_response()
    }
}
```

> **Implementer note:** the precise `nostr` crate API for NIP-98 (`HttpData::try_from`, `check(method, url)`) is illustrative. Read the crate docs at impl time and use whichever entry points the pinned version exposes. The point is: don't hand-roll schnorr / event id / tag matching.

- [ ] **Step 3: Run** `cargo test --test auth`. Expected: 5 pass.

- [ ] **Step 4: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): Tenant extractor (NIP-98 via nostr crate + webhook secret)"
```

### Task 3.2: Rate limiter

**Files:** Create `src/rate_limit.rs`, `tests/rate_limit.rs`.

- [ ] **Step 1: Implement**

```rust
// ABOUTME: Per-tenant rate limit. Firestore doc per tenant with hourly + daily counters.
// ABOUTME: TTL via `expires_at` field (operator enables Firestore TTL policy in deploy.sh).

use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, Duration, Timelike, Utc};
use firestore::FirestoreDb;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitOutcome {
    Allowed,
    TooMany { retry_after_seconds: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CounterDoc {
    hour_bucket: String, hour_count: u32,
    day_bucket: String, day_count: u32,
    #[serde(default)] overrides: Option<TenantOverrides>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TenantOverrides {
    #[serde(default)] pub per_hour: Option<u32>,
    #[serde(default)] pub per_day: Option<u32>,
}

const COLLECTION: &str = "rate_limits";
const TTL_HOURS: i64 = 36;

#[derive(Clone)]
pub struct RateLimiter {
    db: FirestoreDb,
    default_per_hour: u32,
    default_per_day: u32,
}

impl RateLimiter {
    pub fn new(db: FirestoreDb, per_hour: u32, per_day: u32) -> Self {
        Self { db, default_per_hour: per_hour, default_per_day: per_day }
    }

    pub async fn check_and_increment(&self, tenant_id: &str, now: DateTime<Utc>) -> Result<RateLimitOutcome> {
        let hour_bucket = format!("{:04}{:02}{:02}{:02}", now.year(), now.month(), now.day(), now.hour());
        let day_bucket  = format!("{:04}{:02}{:02}",      now.year(), now.month(), now.day());

        let existing: Option<CounterDoc> = self.db.fluent().select().by_id_in(COLLECTION)
            .obj().one(tenant_id).await.context("read rate_limits doc")?;
        let doc_exists = existing.is_some();
        let mut doc = existing.unwrap_or_else(|| CounterDoc {
            hour_bucket: hour_bucket.clone(), hour_count: 0,
            day_bucket: day_bucket.clone(),  day_count: 0,
            overrides: None,
            expires_at: now + Duration::hours(TTL_HOURS),
        });

        if doc.hour_bucket != hour_bucket { doc.hour_bucket = hour_bucket; doc.hour_count = 0; }
        if doc.day_bucket  != day_bucket  { doc.day_bucket  = day_bucket;  doc.day_count  = 0; }

        let per_hour = doc.overrides.as_ref().and_then(|o| o.per_hour).unwrap_or(self.default_per_hour);
        let per_day  = doc.overrides.as_ref().and_then(|o| o.per_day).unwrap_or(self.default_per_day);

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

        let write = if doc_exists {
            self.db.fluent().update().in_col(COLLECTION).document_id(tenant_id).object(&doc).execute::<()>().await
        } else {
            self.db.fluent().insert().into(COLLECTION).document_id(tenant_id).object(&doc).execute::<()>().await
        };
        // Race-loss safety: if we lost a CREATE race, retry as update.
        if let Err(e) = write {
            let msg = format!("{}", e);
            if !doc_exists && msg.to_lowercase().contains("exists") {
                self.db.fluent().update().in_col(COLLECTION).document_id(tenant_id)
                    .object(&doc).execute::<()>().await.context("retry as update")?;
            } else {
                return Err(anyhow::Error::from(e).context("write rate_limits doc"));
            }
        }
        Ok(RateLimitOutcome::Allowed)
    }
}
```

- [ ] **Step 2: Tests** (`#[ignore]`d, emulator-backed)

```rust
mod common;
use chrono::{TimeZone, Utc};
use divine_compiler::rate_limit::{RateLimitOutcome, RateLimiter};
use firestore::{FirestoreDb, FirestoreDbOptions};
use uuid::Uuid;

async fn limiter(per_hour: u32, per_day: u32) -> RateLimiter {
    let _ = std::env::var("FIRESTORE_EMULATOR_HOST").expect("emulator required");
    let project = std::env::var("FIRESTORE_PROJECT").unwrap_or_else(|_| "test-project".into());
    let db = FirestoreDb::with_options(FirestoreDbOptions::new(project)).await.unwrap();
    RateLimiter::new(db, per_hour, per_day)
}

#[tokio::test] #[ignore]
async fn allows_under_then_rejects_over_hour() {
    let rl = limiter(2, 100).await;
    let t = format!("pubkey:{}", Uuid::new_v4().simple());
    assert_eq!(rl.check_and_increment(&t, Utc::now()).await.unwrap(), RateLimitOutcome::Allowed);
    assert_eq!(rl.check_and_increment(&t, Utc::now()).await.unwrap(), RateLimitOutcome::Allowed);
    assert!(matches!(rl.check_and_increment(&t, Utc::now()).await.unwrap(), RateLimitOutcome::TooMany { .. }));
}

#[tokio::test] #[ignore]
async fn hour_bucket_rolls_over() {
    let rl = limiter(1, 100).await;
    let t = format!("pubkey:{}", Uuid::new_v4().simple());
    let t0 = Utc.with_ymd_and_hms(2026, 5, 17, 10, 0, 0).unwrap();
    rl.check_and_increment(&t, t0).await.unwrap();
    assert!(matches!(rl.check_and_increment(&t, t0).await.unwrap(), RateLimitOutcome::TooMany { .. }));
    let t1 = t0 + chrono::Duration::hours(1);
    assert_eq!(rl.check_and_increment(&t, t1).await.unwrap(), RateLimitOutcome::Allowed);
}
```

- [ ] **Step 3: Run** with emulator: `cargo test --test rate_limit -- --ignored`. Expected: 2 pass.

- [ ] **Step 4: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): per-tenant Firestore rate limiter with hourly+daily buckets and TTL"
```

**End of Chunk 3.**

---

## Chunk 4: Nostr REST + Blossom IO

Goal: `src/nostr_api.rs` (api.divine.video client + imeta parser; naddr decode via `nostr::nips::nip19`) and `src/blossom.rs` (download from `media.divine.video`, upload to GCS).

### Task 4.1: Nostr REST client + imeta

**Files:** Create `src/nostr_api.rs`, `tests/nostr_api.rs`.

- [ ] **Step 1: Implement**

```rust
// ABOUTME: api.divine.video REST client + imeta tag parser.
// ABOUTME: naddr decode uses the `nostr` crate; we never hand-roll NIP-19.

use anyhow::{anyhow, Context, Result};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct NostrEvent {
    pub id: String,
    pub pubkey: String,
    pub kind: i64,
    pub created_at: i64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    #[serde(default)] pub sig: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Profile {
    pub pubkey: String,
    #[serde(default)] pub display_name: Option<String>,
    #[serde(default)] pub nip05: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Imeta {
    pub url: Option<String>,
    pub sha256: Option<String>,
    pub mime: Option<String>,
    pub dim: Option<String>,
}
impl Imeta {
    /// Parse a single `imeta` tag (inner Vec<String> with leading "imeta").
    pub fn parse(tag: &[String]) -> Option<Self> {
        if tag.first().map(|s| s.as_str()) != Some("imeta") { return None; }
        let mut out = Imeta::default();
        for e in tag.iter().skip(1) {
            if let Some((k, v)) = e.split_once(' ') {
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
    pub fn first_in(ev: &NostrEvent) -> Option<Self> {
        ev.tags.iter().find_map(|t| Self::parse(t))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("not found: {0}")] NotFound(String),
    #[error(transparent)] Other(#[from] anyhow::Error),
}

#[derive(Clone)]
pub struct ApiClient {
    base: String,
    http: Client,
}

impl ApiClient {
    pub fn new(base: impl Into<String>) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("divine-compiler/0.1")
            .build().context("http client")?;
        Ok(Self { base: base.into(), http })
    }

    pub async fn fetch_event(&self, event_id_hex: &str) -> Result<NostrEvent, FetchError> {
        // TODO(impl): confirm path against api.divine.video docs.
        let url = format!("{}/api/event/{}", self.base.trim_end_matches('/'), event_id_hex);
        self.get_event_at(&url, event_id_hex).await
    }

    pub async fn fetch_profile(&self, pubkey_hex: &str) -> Result<Profile, FetchError> {
        let url = format!("{}/api/profile/{}", self.base.trim_end_matches('/'), pubkey_hex);
        let resp = self.http.get(&url).send().await.map_err(other)?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(Profile { pubkey: pubkey_hex.into(), ..Profile::default() });
        }
        if !resp.status().is_success() {
            return Err(FetchError::Other(anyhow!("profile {} → {}", url, resp.status())));
        }
        let val: serde_json::Value = resp.json().await.map_err(other)?;
        let md = val.get("metadata");
        let display_name = md.and_then(|m| m.get("display_name").or_else(|| m.get("name")))
            .and_then(|v| v.as_str()).map(str::to_string);
        let nip05 = md.and_then(|m| m.get("nip05")).and_then(|v| v.as_str()).map(str::to_string);
        Ok(Profile { pubkey: pubkey_hex.into(), display_name, nip05 })
    }

    /// Resolve an naddr → its (kind 30000/30001/30005) list event. Uses the nostr
    /// crate to decode naddr, then queries by author+kind+d-tag.
    pub async fn fetch_list_event(&self, naddr: &str) -> Result<NostrEvent, FetchError> {
        use nostr::prelude::*;
        let coord = Coordinate::from_bech32(naddr)
            .map_err(|e| FetchError::Other(anyhow!("decode naddr: {}", e)))?;
        let author_hex = coord.public_key.to_hex();
        let kind = coord.kind.as_u16() as u32;
        let d_tag = coord.identifier.clone();
        // TODO(impl): confirm `/api/addressable` against api.divine.video.
        let url = format!(
            "{}/api/addressable?author={}&kind={}&d={}",
            self.base.trim_end_matches('/'), author_hex, kind, urlencoding::encode(&d_tag),
        );
        self.get_event_at(&url, naddr).await
    }

    async fn get_event_at(&self, url: &str, identity: &str) -> Result<NostrEvent, FetchError> {
        let resp = self.http.get(url).send().await.map_err(other)?;
        if resp.status() == StatusCode::NOT_FOUND { return Err(FetchError::NotFound(identity.into())); }
        if !resp.status().is_success() {
            return Err(FetchError::Other(anyhow!("api {} → {}", url, resp.status())));
        }
        let val: serde_json::Value = resp.json().await.map_err(other)?;
        let event_val = val.get("event").cloned().unwrap_or(val);
        serde_json::from_value(event_val).map_err(|e| FetchError::Other(anyhow!(e).context("deserialize event")))
    }
}

fn other<E: std::error::Error + Send + Sync + 'static>(e: E) -> FetchError {
    FetchError::Other(anyhow::Error::from(e))
}
```

- [ ] **Step 2: Tests** (`tests/nostr_api.rs`)

```rust
use divine_compiler::nostr_api::{ApiClient, FetchError, Imeta, NostrEvent};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn imeta_parses_canonical_shape() {
    let ev = NostrEvent {
        id: "i".into(), pubkey: "p".into(), kind: 34235, created_at: 0,
        content: "".into(), sig: None,
        tags: vec![
            vec!["title".into(), "t".into()],
            vec!["imeta".into(), "url https://x/abc".into(), "x abc".into(), "m video/mp4".into()],
        ],
    };
    let im = Imeta::first_in(&ev).unwrap();
    assert_eq!(im.sha256.as_deref(), Some("abc"));
    assert_eq!(im.mime.as_deref(), Some("video/mp4"));
}

#[tokio::test]
async fn fetch_event_returns_full_tags() {
    let s = MockServer::start().await;
    Mock::given(method("GET")).and(path("/api/event/abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "event": {
                "id": "abc", "pubkey": "p", "kind": 34235, "created_at": 0,
                "tags": [["imeta", "url https://x/c", "x cafebabe"]],
                "content": "", "sig": null
            }
        }))).mount(&s).await;
    let c = ApiClient::new(s.uri()).unwrap();
    let ev = c.fetch_event("abc").await.unwrap();
    let im = Imeta::first_in(&ev).unwrap();
    assert_eq!(im.sha256.as_deref(), Some("cafebabe"));
}

#[tokio::test]
async fn fetch_event_404_is_distinguished() {
    let s = MockServer::start().await;
    Mock::given(method("GET")).and(path("/api/event/missing"))
        .respond_with(ResponseTemplate::new(404)).mount(&s).await;
    let c = ApiClient::new(s.uri()).unwrap();
    assert!(matches!(c.fetch_event("missing").await.unwrap_err(), FetchError::NotFound(_)));
}

#[tokio::test]
async fn flattened_helper_sha256_is_ignored() {
    // Guards the nostr-rest-api-field-mapping-gap trap: if the API ever
    // adds a top-level `sha256`, we must NOT consume it.
    let s = MockServer::start().await;
    Mock::given(method("GET")).and(path("/api/event/flat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "flat", "pubkey": "p", "kind": 34235, "created_at": 0,
            "tags": [], "content": "", "sig": null, "sha256": "TRAP"
        }))).mount(&s).await;
    let c = ApiClient::new(s.uri()).unwrap();
    let ev = c.fetch_event("flat").await.unwrap();
    assert!(Imeta::first_in(&ev).is_none());
}

#[tokio::test]
async fn fetch_profile_missing_returns_empty() {
    let s = MockServer::start().await;
    Mock::given(method("GET")).and(path("/api/profile/u"))
        .respond_with(ResponseTemplate::new(404)).mount(&s).await;
    let c = ApiClient::new(s.uri()).unwrap();
    let p = c.fetch_profile("u").await.unwrap();
    assert!(p.nip05.is_none());
}
```

- [ ] **Step 3: Run** `cargo test --test nostr_api`. Expected: 5 pass.

- [ ] **Step 4: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): api.divine.video REST client + imeta parser (naddr decode via nostr crate)"
```

### Task 4.2: Blossom IO

**Files:** Create `src/blossom.rs`, `tests/blossom.rs`.

- [ ] **Step 1: Implement**

```rust
// ABOUTME: Blossom IO — download source MP4s, upload finished comp MP4s to GCS
// ABOUTME: No moderation pre-check; download errors (403/404) drop the clip via Worker

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use futures::stream::StreamExt;
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::fs;
use tokio::io::AsyncWriteExt;

#[derive(Clone)]
pub struct DownloadClient {
    base: String,
    http: Client,
}

#[derive(Debug)]
pub struct Downloaded { pub sha256: String, pub path: PathBuf, pub bytes: u64 }

impl DownloadClient {
    pub fn new(base: impl Into<String>) -> Result<Self> {
        let http = Client::builder().timeout(Duration::from_secs(120))
            .user_agent("divine-compiler/0.1").build().context("http client")?;
        Ok(Self { base: base.into(), http })
    }

    /// Download `sha256` → `dest`. Returns Err on any non-2xx (caller decides
    /// drop-and-continue policy). Restricted/AgeRestricted blobs surface as
    /// 403/404 here — we don't pre-check.
    pub async fn download(&self, sha256: &str, dest: &Path) -> Result<Downloaded> {
        let url = format!("{}/{}", self.base.trim_end_matches('/'), sha256);
        let resp = self.http.get(&url).send().await.context("GET blob")?;
        if !resp.status().is_success() {
            return Err(anyhow!("GET {} → {}", url, resp.status()));
        }
        let mut f = fs::File::create(dest).await.context("create dest")?;
        let mut stream = resp.bytes_stream();
        let mut total: u64 = 0;
        while let Some(chunk) = stream.next().await {
            let chunk: Bytes = chunk.context("read chunk")?;
            f.write_all(&chunk).await.context("write chunk")?;
            total += chunk.len() as u64;
        }
        f.flush().await.ok();
        Ok(Downloaded { sha256: sha256.into(), path: dest.into(), bytes: total })
    }
}

// --- Upload ---

use google_cloud_storage::client::{Client as GcsClient, ClientConfig};
use google_cloud_storage::http::objects::upload::{Media, UploadObjectRequest, UploadType};
use google_cloud_storage::http::objects::Object;

pub struct GcsUploader {
    client: GcsClient,
    bucket: String,
    public_base: String,
}

#[derive(Debug, Clone)]
pub struct UploadResult { pub sha256: String, pub size: u64, pub url: String }

impl GcsUploader {
    pub async fn new(bucket: impl Into<String>, public_base: impl Into<String>) -> Result<Self> {
        let cfg = ClientConfig::default().with_auth().await.context("gcs config (ADC)")?;
        Ok(Self { client: GcsClient::new(cfg), bucket: bucket.into(), public_base: public_base.into() })
    }

    pub async fn upload_file(&self, src: &Path, content_type: &str) -> Result<UploadResult> {
        let bytes = fs::read(src).await.context("read upload src")?;
        let sha256 = hex::encode(Sha256::digest(&bytes));
        let size = bytes.len() as u64;

        // Multipart upload carries the content type inline.
        let mut obj = Object::default();
        obj.name = sha256.clone();
        obj.content_type = Some(content_type.into());
        let upload = UploadType::Multipart(Box::new(obj));
        let req = UploadObjectRequest { bucket: self.bucket.clone(), ..Default::default() };

        self.client.upload_object(&req, bytes, &upload).await.context("gcs upload")?;
        let url = format!("{}/{}", self.public_base.trim_end_matches('/'), sha256);
        Ok(UploadResult { sha256, size, url })
    }
}
```

> **Implementer note:** verify the `google-cloud-storage = "=0.17.0"` Multipart API at impl time. If `Object::default()` + Multipart doesn't compile against the pinned version, fall back to Simple upload + a follow-up `patch_object` to set content type. Either way, `upload_file` returns `{sha256, size, url}`.

- [ ] **Step 2: Tests** (downloads only — GCS upload is exercised by Chunk 6 smoke test)

```rust
use divine_compiler::blossom::DownloadClient;
use std::fs;
use tempfile::tempdir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn download_writes_bytes() {
    let s = MockServer::start().await;
    Mock::given(method("GET")).and(path("/abc"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"hello".to_vec()))
        .mount(&s).await;
    let dir = tempdir().unwrap();
    let dest = dir.path().join("abc");
    let d = DownloadClient::new(s.uri()).unwrap().download("abc", &dest).await.unwrap();
    assert_eq!(d.bytes, 5);
    assert_eq!(fs::read(&dest).unwrap(), b"hello");
}

#[tokio::test]
async fn download_404_is_err() {
    let s = MockServer::start().await;
    Mock::given(method("GET")).and(path("/missing"))
        .respond_with(ResponseTemplate::new(404)).mount(&s).await;
    let dir = tempdir().unwrap();
    let r = DownloadClient::new(s.uri()).unwrap()
        .download("missing", &dir.path().join("x")).await;
    assert!(r.is_err());
}

#[tokio::test]
async fn download_403_restricted_is_err() {
    // Restricted/AgeRestricted blobs return 403 from the moderation layer.
    // We don't pre-check; the worker classifies via clips_dropped.
    let s = MockServer::start().await;
    Mock::given(method("GET")).and(path("/restricted"))
        .respond_with(ResponseTemplate::new(403)).mount(&s).await;
    let dir = tempdir().unwrap();
    let r = DownloadClient::new(s.uri()).unwrap()
        .download("restricted", &dir.path().join("x")).await;
    assert!(r.is_err());
}
```

- [ ] **Step 3: Run** `cargo test --test blossom`. Expected: 3 pass.

- [ ] **Step 4: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): blossom download (no pre-check) + GCS multipart upload"
```

**End of Chunk 4.**

---

## Chunk 5: Render pipeline

Goal: one file `src/render.rs` containing probe, fit/overlay filtergraph builders, ffmpeg command builder, and the GPU→CPU fallback executor. Pure functions are exhaustively tested; ffmpeg execution gated by binary availability.

### Task 5.1: `render.rs`

**Files:** Create `src/render.rs`, `tests/render_filters.rs`, `tests/render_ffmpeg_args.rs`, `tests/render_smoke.rs`.

- [ ] **Step 1: Implement**

```rust
// ABOUTME: Render pipeline — probe, fit/overlay filtergraph, ffmpeg command + exec
// ABOUTME: Pure builders are unit-tested; executor needs ffmpeg on PATH

use crate::job::{Aspect, Credit, Fit, Watermark, WatermarkPosition};
use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use tokio::process::Command;

// --- Target dimensions ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetDim { pub width: u32, pub height: u32 }

impl From<Aspect> for TargetDim {
    fn from(a: Aspect) -> Self {
        match a {
            Aspect::Vertical   => TargetDim { width: 1080, height: 1920 },
            Aspect::Square     => TargetDim { width: 1080, height: 1080 },
            Aspect::Horizontal => TargetDim { width: 1920, height: 1080 },
        }
    }
}

// --- Probe ---

#[derive(Debug, Clone, PartialEq)]
pub struct ProbeInfo { pub duration_sec: f64, pub width: u32, pub height: u32, pub codec: String, pub rotation: i32 }

#[derive(Deserialize)] struct FfprobeOut { streams: Vec<Stream>, format: Format }
#[derive(Deserialize)] struct Stream {
    codec_type: String,
    #[serde(default)] codec_name: String,
    #[serde(default)] width: u32,
    #[serde(default)] height: u32,
    #[serde(default)] tags: Option<StreamTags>,
    #[serde(default)] side_data_list: Option<Vec<SideData>>,
}
#[derive(Deserialize, Default)] struct StreamTags { #[serde(default)] rotate: Option<String> }
#[derive(Deserialize)] struct SideData { #[serde(default)] rotation: Option<i32> }
#[derive(Deserialize)] struct Format { #[serde(default)] duration: String }

pub async fn probe(file: &Path) -> Result<ProbeInfo> {
    let out = Command::new("ffprobe")
        .args(["-v", "error", "-print_format", "json",
               "-show_format", "-show_streams",
               "-show_entries", "stream=codec_type,codec_name,width,height:stream_side_data=rotation:stream_tags=rotate:format=duration"])
        .arg(file).output().await.context("spawn ffprobe")?;
    if !out.status.success() { return Err(anyhow!("ffprobe: {}", String::from_utf8_lossy(&out.stderr))); }
    let p: FfprobeOut = serde_json::from_slice(&out.stdout).context("parse ffprobe json")?;
    let v = p.streams.iter().find(|s| s.codec_type == "video")
        .ok_or_else(|| anyhow!("no video stream"))?;
    let rotation = v.side_data_list.as_ref()
        .and_then(|l| l.iter().find_map(|s| s.rotation))
        .or_else(|| v.tags.as_ref().and_then(|t| t.rotate.as_ref().and_then(|r| r.parse().ok())))
        .unwrap_or(0).rem_euclid(360);
    Ok(ProbeInfo {
        duration_sec: p.format.duration.parse().unwrap_or(0.0),
        width: v.width, height: v.height,
        codec: v.codec_name.clone(), rotation,
    })
}

// --- Fit filtergraph (pure) ---

pub fn fit_filter(input: &str, output: &str, fit: Fit, target: TargetDim) -> String {
    let (w, h) = (target.width, target.height);
    match fit {
        Fit::BlurPad => format!(
            "[{i}]split=2[bg_in][fg_in];\
             [bg_in]scale={w}:{h}:force_original_aspect_ratio=increase,crop={w}:{h},boxblur=20:5[bg];\
             [fg_in]scale={w}:{h}:force_original_aspect_ratio=decrease[fg];\
             [bg][fg]overlay=(W-w)/2:(H-h)/2[{o}]",
            i = input, o = output, w = w, h = h,
        ),
        Fit::CenterCrop => format!(
            "[{i}]scale={w}:{h}:force_original_aspect_ratio=increase,crop={w}:{h}[{o}]",
            i = input, o = output, w = w, h = h,
        ),
        Fit::Letterbox => format!(
            "[{i}]scale={w}:{h}:force_original_aspect_ratio=decrease,pad={w}:{h}:(ow-iw)/2:(oh-ih)/2:color=black[{o}]",
            i = input, o = output, w = w, h = h,
        ),
    }
}

// --- Overlay filtergraph (pure) ---

pub fn logo_overlay(input: &str, logo: &str, output: &str, target_w: u32, wm: &Watermark) -> String {
    if !wm.enabled { return format!("[{}]null[{}]", input, output); }
    let logo_w = (target_w as f32 * 0.12).round() as u32;
    let (x, y) = match wm.position {
        WatermarkPosition::TopLeft     => ("16".to_string(), "16".to_string()),
        WatermarkPosition::TopRight    => ("W-w-16".to_string(), "16".to_string()),
        WatermarkPosition::BottomLeft  => ("16".to_string(), "H-h-16".to_string()),
        WatermarkPosition::BottomRight => ("W-w-16".to_string(), "H-h-16".to_string()),
    };
    let alpha = wm.opacity.clamp(0.0, 1.0);
    format!(
        "[{logo}]scale={lw}:-1,format=rgba,colorchannelmixer=aa={a}[logo_s];\
         [{i}][logo_s]overlay={x}:{y}[{o}]",
        logo = logo, lw = logo_w, a = alpha, i = input, x = x, y = y, o = output,
    )
}

/// Per-clip credit drawtext. Lower-third with fade-in/fade-out.
/// `enable` toggles render on/off; `alpha` shapes the fade INSIDE the window.
pub fn credit_drawtext(input: &str, output: &str, credit: &Credit, text: &str, start_sec: f64, target_h: u32) -> String {
    if text.is_empty() { return format!("[{}]null[{}]", input, output); }
    let dur = (credit.duration_ms as f64) / 1000.0;
    let end = start_sec + dur;
    let fi = start_sec + 0.3;
    let fo = end - 0.3;
    let y = (target_h as f32 * 0.78).round() as u32;
    // Escape characters that have special meaning in drawtext: backslash first,
    // then comma (filter arg separator), colon (option separator), percent
    // (%{...} macro trigger), and apostrophe (text='...' terminator).
    let esc = text
        .replace('\\', "\\\\")
        .replace(',', "\\,")
        .replace(':', "\\:")
        .replace('%', "\\%")
        .replace('\'', "\\'");
    format!(
        "[{i}]drawtext=fontfile=/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf:\
         text='{t}':x=(w-text_w)/2:y={y}:fontsize=42:fontcolor=white:\
         box=1:boxcolor=black@0.55:boxborderw=12:\
         enable='between(t,{s:.3},{e:.3})':\
         alpha='if(lt(t,{fi:.3}),(t-{s:.3})/0.3, if(gt(t,{fo:.3}), ({e:.3}-t)/0.3, 1))'[{o}]",
        i = input, t = esc, y = y, s = start_sec, e = end, fi = fi, fo = fo, o = output,
    )
}

pub fn format_credit_text(display_name: Option<&str>, nip05: Option<&str>, pubkey: &str) -> String {
    match (display_name, nip05) {
        (Some(d), Some(n)) => format!("{} • {}", d, n),
        (Some(d), None)    => d.to_string(),
        (None, Some(n))    => n.to_string(),
        (None, None)       => format!("npub: {}…", &pubkey[..8.min(pubkey.len())]),
    }
}

// --- ffmpeg command builder (pure) ---

#[derive(Debug, Clone)]
pub struct ClipInput { pub path: PathBuf, pub credit_text: String, pub duration_sec: f64 }

#[derive(Debug, Clone)]
pub struct AspectJob {
    pub clips: Vec<ClipInput>,
    pub target: TargetDim,
    pub fit: Fit,
    pub logo_path: PathBuf,
    pub watermark: Watermark,
    pub credit: Credit,
    pub output_path: PathBuf,
    pub bitrate_kbps: u32,
    pub use_gpu: bool,
}

pub fn build_command(job: &AspectJob) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "-y".into(),
        "-loglevel".into(), "warning".into(), "-nostats".into(),
    ];
    if job.use_gpu { args.push("-hwaccel".into()); args.push("cuda".into()); }
    for c in &job.clips { args.push("-i".into()); args.push(c.path.to_string_lossy().into()); }
    let logo_idx = job.clips.len();
    args.push("-i".into()); args.push(job.logo_path.to_string_lossy().into());

    args.push("-filter_complex".into());
    args.push(build_filter_complex(job, logo_idx));

    args.push("-map".into()); args.push("[v_final]".into());
    args.push("-map".into()); args.push("[a_final]".into());

    if job.use_gpu {
        args.extend(["-c:v", "h264_nvenc", "-preset", "p5", "-rc:v", "vbr"].iter().map(|s| s.to_string()));
    } else {
        args.extend(["-c:v", "libx264", "-preset", "medium"].iter().map(|s| s.to_string()));
    }
    let br = format!("{}k", job.bitrate_kbps);
    let mx = format!("{}k", job.bitrate_kbps * 4 / 3);
    let bf = format!("{}k", job.bitrate_kbps * 2);
    args.extend([
        "-b:v", &br, "-maxrate", &mx, "-bufsize", &bf,
        "-pix_fmt", "yuv420p", "-profile:v", "high", "-level", "4.2",
        "-c:a", "aac", "-b:a", "128k", "-ar", "48000",
        "-movflags", "+faststart",
    ].iter().map(|s| s.to_string()));
    args.push(job.output_path.to_string_lossy().into());
    args
}

fn build_filter_complex(job: &AspectJob, logo_idx: usize) -> String {
    let mut parts: Vec<String> = vec![];
    let mut start = 0.0_f64;
    let mut v: Vec<String> = vec![];
    let mut a: Vec<String> = vec![];
    for (i, c) in job.clips.iter().enumerate() {
        let fit_l = format!("vfit_{}", i);
        parts.push(fit_filter(&format!("{}:v:0", i), &fit_l, job.fit, job.target));
        let cr_l = format!("vcr_{}", i);
        parts.push(credit_drawtext(&fit_l, &cr_l, &job.credit, &c.credit_text, start, job.target.height));
        v.push(format!("[{}]", cr_l));
        a.push(format!("[{}:a:0]", i));
        start += c.duration_sec;
    }
    // V1 LIMITATION: assumes every clip has [N:a:0]. Audio-less clips fail.
    let concat_inputs: String = v.iter().zip(a.iter()).map(|(vv, aa)| format!("{}{}", vv, aa)).collect();
    parts.push(format!("{}concat=n={}:v=1:a=1[v_cat][a_final]", concat_inputs, job.clips.len()));
    parts.push(logo_overlay("v_cat", &format!("{}:v:0", logo_idx), "v_final", job.target.width, &job.watermark));
    parts.join(";")
}

// --- ffmpeg exec with GPU→CPU fallback ---

pub async fn run_render(job: &AspectJob) -> Result<PathBuf> {
    if job.use_gpu {
        match try_one(job, true).await {
            Ok(_) => return Ok(job.output_path.clone()),
            Err(e) => tracing::warn!(?e, "GPU encode failed; falling back to CPU"),
        }
    }
    try_one(job, false).await?;
    Ok(job.output_path.clone())
}

async fn try_one(job: &AspectJob, use_gpu: bool) -> Result<()> {
    let mut cfg = job.clone(); cfg.use_gpu = use_gpu;
    let args = build_command(&cfg);
    let out = Command::new("ffmpeg").args(&args).output().await.context("spawn ffmpeg")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!("ffmpeg exit {} (gpu={}):\n{}", out.status, use_gpu, tail(&stderr, 2000)));
    }
    if !job.output_path.exists() { return Err(anyhow!("ffmpeg ok but output missing")); }
    Ok(())
}

fn tail(s: &str, n: usize) -> &str {
    if s.len() <= n { return s; }
    let mut start = s.len() - n;
    while !s.is_char_boundary(start) { start += 1; }
    &s[start..]
}

// --- top-level orchestration helper used by Worker ---

#[derive(Debug, Clone)]
pub struct ProbedClip { pub event_id: String, pub path: PathBuf, pub duration_sec: f64, pub credit_text: String }

pub struct AspectResult { pub aspect: Aspect, pub output_path: PathBuf, pub dim: TargetDim }

pub async fn render_aspect(
    aspect: Aspect,
    clips: &[ProbedClip],
    fit: Fit,
    watermark: Watermark,
    credit: Credit,
    logo_path: &Path,
    job_dir: &Path,
    use_gpu: bool,
) -> Result<AspectResult> {
    let target = TargetDim::from(aspect);
    let bitrate_kbps = match aspect { Aspect::Square => 5000, _ => 6000 };
    let output_path = job_dir.join(format!("out_{}.mp4", match aspect {
        Aspect::Vertical => "9x16", Aspect::Square => "1x1", Aspect::Horizontal => "16x9"
    }));
    let aj = AspectJob {
        clips: clips.iter().map(|c| ClipInput { path: c.path.clone(), credit_text: c.credit_text.clone(), duration_sec: c.duration_sec }).collect(),
        target, fit, logo_path: logo_path.into(),
        watermark, credit,
        output_path: output_path.clone(), bitrate_kbps, use_gpu,
    };
    run_render(&aj).await?;
    Ok(AspectResult { aspect, output_path, dim: target })
}
```

- [ ] **Step 2: Filter tests (pure functions)**

```rust
// tests/render_filters.rs
use divine_compiler::job::{Credit, Fit, Watermark, WatermarkPosition, Aspect};
use divine_compiler::render::{fit_filter, logo_overlay, credit_drawtext, format_credit_text, TargetDim};

const T: TargetDim = TargetDim { width: 1080, height: 1920 };

#[test]
fn blur_pad_uses_split_overlay() {
    let f = fit_filter("v0", "vfit", Fit::BlurPad, T);
    assert!(f.contains("split=2") && f.contains("boxblur") && f.contains("overlay=(W-w)/2:(H-h)/2"));
}

#[test]
fn center_crop_and_letterbox_shapes() {
    let cc = fit_filter("v0", "o", Fit::CenterCrop, T);
    assert!(cc.contains("force_original_aspect_ratio=increase") && cc.contains("crop=1080:1920"));
    let lb = fit_filter("v0", "o", Fit::Letterbox, T);
    assert!(lb.contains("pad=1080:1920") && lb.contains("color=black"));
}

#[test]
fn fit_works_for_all_aspects() {
    for a in [Aspect::Vertical, Aspect::Square, Aspect::Horizontal] {
        let t = TargetDim::from(a);
        for f in [Fit::BlurPad, Fit::CenterCrop, Fit::Letterbox] {
            let s = fit_filter("v", "o", f, t);
            assert!(s.contains(&t.width.to_string()) && s.contains(&t.height.to_string()));
        }
    }
}

fn wm(p: WatermarkPosition) -> Watermark { Watermark { enabled: true, position: p, opacity: 0.3 } }

#[test]
fn logo_disabled_emits_null() {
    let wm = Watermark { enabled: false, ..wm(WatermarkPosition::BottomRight) };
    assert_eq!(logo_overlay("v", "logo", "out", 1080, &wm), "[v]null[out]");
}

#[test]
fn logo_positions_have_correct_offsets() {
    assert!(logo_overlay("v", "l", "o", 1080, &wm(WatermarkPosition::BottomRight))
        .contains("overlay=W-w-16:H-h-16"));
    assert!(logo_overlay("v", "l", "o", 1080, &wm(WatermarkPosition::TopLeft))
        .contains("overlay=16:16"));
}

fn cr() -> Credit { Credit { duration_ms: 2500, show_display_name: true, show_nip05: true } }

#[test]
fn credit_empty_text_passes_through() {
    assert_eq!(credit_drawtext("v", "o", &cr(), "", 0.0, 1920), "[v]null[o]");
}

#[test]
fn credit_has_fade_envelope() {
    let f = credit_drawtext("v", "o", &cr(), "Alice", 10.0, 1920);
    assert!(f.contains("between(t,10.000,12.500)"));
    assert!(f.contains("10.300") && f.contains("12.200"));
}

#[test]
fn credit_escapes_user_input() {
    let f = credit_drawtext("v", "o", &cr(), "Bob, 100% O'Brien", 0.0, 1920);
    assert!(f.contains("Bob\\,") && f.contains("100\\%") && f.contains("O\\'Brien"));
    assert!(!f.contains("O\\\\'Brien"), "apostrophe over-escaped");
}

#[test]
fn format_credit_text_prefers_full() {
    assert_eq!(format_credit_text(Some("A"), Some("a@x"), "deadbeefcafe"), "A • a@x");
    assert_eq!(format_credit_text(None, None, "deadbeefcafe"), "npub: deadbeef…");
}
```

- [ ] **Step 3: ffmpeg-args tests (pure builder)**

```rust
// tests/render_ffmpeg_args.rs
use divine_compiler::job::{Credit, Fit, Watermark, WatermarkPosition};
use divine_compiler::render::{build_command, AspectJob, ClipInput, TargetDim};
use std::path::PathBuf;

fn fixture(use_gpu: bool, n: usize) -> AspectJob {
    AspectJob {
        clips: (0..n).map(|i| ClipInput {
            path: PathBuf::from(format!("/tmp/c{}.mp4", i)),
            credit_text: format!("Author {}", i),
            duration_sec: 6.0,
        }).collect(),
        target: TargetDim { width: 1080, height: 1920 },
        fit: Fit::BlurPad,
        logo_path: PathBuf::from("/tmp/logo.png"),
        watermark: Watermark { enabled: true, position: WatermarkPosition::BottomRight, opacity: 0.3 },
        credit: Credit { duration_ms: 2500, show_display_name: true, show_nip05: true },
        output_path: PathBuf::from("/tmp/out.mp4"),
        bitrate_kbps: 6000,
        use_gpu,
    }
}

#[test]
fn gpu_uses_nvenc() {
    let cmd = build_command(&fixture(true, 2));
    assert!(cmd.windows(2).any(|w| w == ["-c:v".to_string(), "h264_nvenc".to_string()]));
    assert!(!cmd.iter().any(|s| s == "libx264"));
}

#[test]
fn cpu_uses_libx264_no_hwaccel() {
    let cmd = build_command(&fixture(false, 2));
    assert!(!cmd.iter().any(|s| s == "-hwaccel"));
    assert!(cmd.windows(2).any(|w| w == ["-c:v".to_string(), "libx264".to_string()]));
}

#[test]
fn filter_complex_concats_n_clips_and_advances_credit_start() {
    let cmd = build_command(&fixture(true, 3));
    let fc = &cmd[cmd.iter().position(|s| s == "-filter_complex").unwrap() + 1];
    assert!(fc.contains("concat=n=3:v=1:a=1[v_cat][a_final]"));
    assert!(fc.contains("between(t,0.000,2.500)"));
    assert!(fc.contains("between(t,6.000,8.500)"));
    assert!(fc.contains("between(t,12.000,14.500)"));
}

#[test]
fn output_is_final_and_faststart_set() {
    let cmd = build_command(&fixture(true, 1));
    assert_eq!(cmd.last().map(|s| s.as_str()), Some("/tmp/out.mp4"));
    assert!(cmd.windows(2).any(|w| w == ["-movflags".to_string(), "+faststart".to_string()]));
    assert!(cmd.windows(2).any(|w| w == ["-loglevel".to_string(), "warning".to_string()]));
}
```

- [ ] **Step 4: End-to-end smoke (gated by ffmpeg)**

```rust
// tests/render_smoke.rs
use divine_compiler::job::{Credit, Fit, Watermark, WatermarkPosition};
use divine_compiler::render::{run_render, AspectJob, ClipInput, TargetDim};
use std::path::PathBuf;
use tempfile::tempdir;
use tokio::process::Command;

async fn make_clip(out: &std::path::Path, color: &str, sec: f32) {
    let s = Command::new("ffmpeg").args([
        "-y", "-f", "lavfi", "-i", &format!("color=c={}:s=640x480:d={}", color, sec),
        "-f", "lavfi", "-i", &format!("sine=frequency=440:duration={}", sec),
        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-c:a", "aac", "-shortest",
    ]).arg(out).status().await.unwrap();
    assert!(s.success());
}

async fn make_logo(out: &std::path::Path) {
    let s = Command::new("ffmpeg").args([
        "-y", "-f", "lavfi", "-i", "color=c=magenta:s=64x64:d=0.04", "-frames:v", "1",
    ]).arg(out).status().await.unwrap();
    assert!(s.success());
}

#[tokio::test]
#[ignore = "needs ffmpeg in PATH; ~10s wall time"]
async fn renders_two_clip_comp_cpu() {
    let dir = tempdir().unwrap();
    let c0 = dir.path().join("c0.mp4"); make_clip(&c0, "red", 1.0).await;
    let c1 = dir.path().join("c1.mp4"); make_clip(&c1, "blue", 1.0).await;
    let logo = dir.path().join("logo.png"); make_logo(&logo).await;
    let out = dir.path().join("out.mp4");

    let aj = AspectJob {
        clips: vec![
            ClipInput { path: c0, credit_text: "Alice".into(), duration_sec: 1.0 },
            ClipInput { path: c1, credit_text: "Bob".into(),   duration_sec: 1.0 },
        ],
        target: TargetDim { width: 360, height: 640 },
        fit: Fit::BlurPad,
        logo_path: logo,
        watermark: Watermark { enabled: true, position: WatermarkPosition::BottomRight, opacity: 0.4 },
        credit: Credit { duration_ms: 800, show_display_name: true, show_nip05: false },
        output_path: out.clone(),
        bitrate_kbps: 1500,
        use_gpu: false,
    };
    run_render(&aj).await.expect("render");
    assert!(std::fs::metadata(&out).unwrap().len() > 1000);
}
```

- [ ] **Step 5: Run** the unit tests: `cargo test --test render_filters --test render_ffmpeg_args`. Expected: 11 pass.

- [ ] **Step 6: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): render pipeline — probe, fit/overlay/ffmpeg builders + NVENC exec"
```

**End of Chunk 5.**

---

## Chunk 6: HTTP + worker + webhook + smoke

Goal: handlers, worker, webhook, logo fetch, deploy + smoke test. Final shipping chunk.

### Task 6.1: Webhook

**Files:** Create `src/webhook.rs`, `tests/webhook.rs`.

- [ ] **Step 1: Implement**

```rust
// ABOUTME: HMAC-signed webhook delivery with 3-retry exp backoff
use crate::job::CallbackDelivery;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

pub fn sign(secret: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

pub fn verify(secret: &str, body: &[u8], header_value: &str) -> bool {
    let expected = sign(secret, body);
    if expected.len() != header_value.len() { return false; }
    let mut diff: u8 = 0;
    for (a, b) in expected.bytes().zip(header_value.bytes()) { diff |= a ^ b; }
    diff == 0
}

const BACKOFF_SECS: [u64; 3] = [1, 5, 25];

pub async fn deliver(url: &str, body: &[u8], secret: Option<&str>) -> CallbackDelivery {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(10)).build().expect("client");
    let mut attempts = 0;
    let mut last = 0u16;
    for delay in BACKOFF_SECS.iter() {
        attempts += 1;
        if attempts > 1 { tokio::time::sleep(Duration::from_secs(*delay)).await; }
        let mut req = client.post(url).body(body.to_vec()).header("content-type", "application/json");
        if let Some(s) = secret { req = req.header("X-Compiler-Signature", sign(s, body)); }
        match req.send().await {
            Ok(r) => {
                last = r.status().as_u16();
                if r.status().is_success() {
                    return CallbackDelivery { attempts, last_attempt_at: chrono::Utc::now(), last_status_code: last, delivered: true };
                }
            }
            Err(e) => { tracing::warn!(?e, attempt = attempts, "webhook err"); last = 0; }
        }
    }
    CallbackDelivery { attempts, last_attempt_at: chrono::Utc::now(), last_status_code: last, delivered: false }
}
```

- [ ] **Step 2: Tests**

```rust
use divine_compiler::webhook::{deliver, sign, verify};
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn sign_and_verify_round_trip() {
    let s = sign("shh", b"hello");
    assert!(s.starts_with("sha256=") && s.len() == 7 + 64);
    assert!(verify("shh", b"hello", &s));
    assert!(!verify("shh", b"hello!", &s));
    assert!(!verify("other", b"hello", &s));
}

#[tokio::test]
async fn delivers_first_2xx() {
    let s = MockServer::start().await;
    Mock::given(method("POST")).respond_with(ResponseTemplate::new(200)).expect(1).mount(&s).await;
    let r = deliver(&s.uri(), b"{}", Some("shh")).await;
    assert!(r.delivered); assert_eq!(r.attempts, 1);
}

#[tokio::test]
async fn sends_signature_header() {
    let s = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("X-Compiler-Signature", sign("shh", b"{}").as_str()))
        .respond_with(ResponseTemplate::new(200)).expect(1).mount(&s).await;
    let r = deliver(&s.uri(), b"{}", Some("shh")).await;
    assert!(r.delivered);
}

#[tokio::test]
#[ignore = "exercises 1s+5s backoff, ~6s wall time"]
async fn retries_on_5xx() {
    let s = MockServer::start().await;
    Mock::given(method("POST")).respond_with(ResponseTemplate::new(503)).expect(3).mount(&s).await;
    let r = deliver(&s.uri(), b"{}", None).await;
    assert!(!r.delivered); assert_eq!(r.attempts, 3);
}
```

- [ ] **Step 3: Run** `cargo test --test webhook`. Expected: 3 pass (5xx retry test is `#[ignore]`'d).

- [ ] **Step 4: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): HMAC-signed webhook delivery with retry"
```

### Task 6.2: Logo fetch + Handlers + Worker

**Files:** Create `src/handlers.rs`, `src/worker.rs`, update `src/main.rs`. The logo fetch is small enough to inline in `worker.rs` or `main.rs` startup.

- [ ] **Step 1: `src/handlers.rs`**

```rust
// ABOUTME: axum router + POST /compile + GET /compile/:id + admin endpoints
use crate::auth::{AppState, Tenant};
use crate::job::*;
use crate::rate_limit::RateLimitOutcome;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/compile", post(post_compile))
        .route("/compile/:job_id", get(get_status))
        .route("/admin/jobs", get(admin_list))
        .route("/admin/jobs/:job_id", get(admin_get))
        .with_state(state)
}

#[derive(Serialize)]
struct CompileResponse { job_id: String, status: String }

fn err(status: StatusCode, body: Value, headers: Vec<(&'static str, String)>) -> Response {
    let mut hm = HeaderMap::new();
    for (k, v) in headers { if let Ok(h) = HeaderValue::from_str(&v) { hm.insert(k, h); } }
    (status, hm, Json(body)).into_response()
}

async fn post_compile(
    State(state): State<AppState>,
    tenant: Tenant,
    Json(req): Json<CompileRequest>,
) -> Result<Json<CompileResponse>, Response> {
    let tenant_id = tenant.id();
    match state.rate_limiter.check_and_increment(&tenant_id, chrono::Utc::now()).await {
        Ok(RateLimitOutcome::Allowed) => {}
        Ok(RateLimitOutcome::TooMany { retry_after_seconds }) => {
            return Err(err(
                StatusCode::TOO_MANY_REQUESTS,
                json!({ "error": "rate_limited", "retry_after_seconds": retry_after_seconds }),
                vec![("Retry-After", retry_after_seconds.to_string())],
            ));
        }
        Err(e) => {
            tracing::error!(?e, "rate limit error");
            return Err(err(StatusCode::INTERNAL_SERVER_ERROR, json!({"error":"rate_limit_failed"}), vec![]));
        }
    }

    let job_id = format!("cmp_{}", Uuid::new_v4().simple());
    let now = chrono::Utc::now();
    let job = Job {
        job_id: job_id.clone(), status: JobStatus::Queued, progress: 0.0,
        request: req, tenant_id,
        created_at: now, updated_at: now,
        result: None, error: None, callback_delivery: None,
    };
    if let Err(e) = state.job_store.create_job(&job).await {
        tracing::error!(?e, "create_job failed");
        return Err(err(StatusCode::INTERNAL_SERVER_ERROR, json!({"error":"persist_failed"}), vec![]));
    }
    tracing::info!(job_id = %job_id, event = "queued", tenant_id = %job.tenant_id, "job queued");
    Ok(Json(CompileResponse { job_id, status: "queued".into() }))
}

async fn get_status(
    State(state): State<AppState>,
    _tenant: Tenant,
    Path(job_id): Path<String>,
) -> Result<Json<Value>, Response> {
    match state.job_store.get_job(&job_id).await {
        Ok(Some(j)) => Ok(Json(serde_json::to_value(&j).unwrap())),
        Ok(None) => Err(err(StatusCode::NOT_FOUND, json!({"error":"job_not_found","job_id":job_id}), vec![])),
        Err(e) => {
            tracing::error!(?e, "get_job failed");
            Err(err(StatusCode::INTERNAL_SERVER_ERROR, json!({"error":"store_failed"}), vec![]))
        }
    }
}

// --- Admin ---

fn require_admin(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    let auth = headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    if let Some(token) = auth.and_then(|h| h.strip_prefix("Bearer ")) {
        if let Some(expected) = state.config.admin_token.as_deref() {
            if token == expected { return Ok(()); }
        }
    }
    Err(err(StatusCode::UNAUTHORIZED, json!({"error":"admin_required"}), vec![]))
}

#[derive(Deserialize, Default)]
struct ListQ { limit: Option<u32>, status: Option<JobStatus> }

async fn admin_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListQ>,
) -> Result<Json<Value>, Response> {
    require_admin(&state, &headers)?;
    let limit = q.limit.unwrap_or(50).min(500);
    let jobs = state.job_store.list_recent(limit, q.status).await
        .map_err(|e| { tracing::error!(?e, "admin_list"); err(StatusCode::INTERNAL_SERVER_ERROR, json!({"error":"internal"}), vec![]) })?;
    Ok(Json(json!({ "jobs": jobs })))
}

async fn admin_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Result<Json<Value>, Response> {
    require_admin(&state, &headers)?;
    match state.job_store.get_job(&job_id).await {
        Ok(Some(j)) => Ok(Json(serde_json::to_value(&j).unwrap())),
        Ok(None) => Err(err(StatusCode::NOT_FOUND, json!({"error":"job_not_found"}), vec![])),
        Err(e) => { tracing::error!(?e); Err(err(StatusCode::INTERNAL_SERVER_ERROR, json!({"error":"internal"}), vec![])) }
    }
}
```

- [ ] **Step 2: `src/worker.rs`**

```rust
// ABOUTME: Background worker — polls Firestore for queued jobs, runs them concurrently
use crate::auth::AppState;
use crate::blossom::{DownloadClient, GcsUploader};
use crate::job::*;
use crate::nostr_api::{ApiClient, FetchError, Imeta};
use crate::render::{format_credit_text, render_aspect, probe, ProbedClip};
use crate::webhook;
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

pub struct Worker {
    state: AppState,
    api: Arc<ApiClient>,
    download: Arc<DownloadClient>,
    upload: Arc<GcsUploader>,
    logo_path: PathBuf,
    sem: Arc<Semaphore>,
}

impl Worker {
    pub fn new(state: AppState, api: ApiClient, download: DownloadClient, upload: GcsUploader, logo_path: PathBuf) -> Self {
        let limit = state.config.max_concurrent_jobs;
        Self { state, api: Arc::new(api), download: Arc::new(download), upload: Arc::new(upload), logo_path, sem: Arc::new(Semaphore::new(limit)) }
    }

    pub async fn run_forever(self: Arc<Self>) {
        loop {
            match self.state.job_store.list_recent(10, Some(JobStatus::Queued)).await {
                Ok(jobs) => {
                    for job in jobs {
                        let me = self.clone();
                        let permit = self.sem.clone().acquire_owned().await.unwrap();
                        tokio::spawn(async move {
                            let _p = permit;
                            if let Err(e) = me.process(job).await {
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

    async fn process(&self, mut job: Job) -> Result<()> {
        // Optimistic claim. KISS: at low concurrency the duplicate-claim race
        // is tiny; a duplicate render at worst burns one GPU pass. v2: switch
        // to FirestoreDb::run_transaction.
        job.status = JobStatus::Running; job.progress = 0.05;
        self.state.job_store.update_job(&job).await.context("mark running")?;
        tracing::info!(job_id = %job.job_id, event = "started", "job started");

        let work_dir = std::env::temp_dir().join(format!("job_{}", job.job_id));
        tokio::fs::create_dir_all(&work_dir).await.context("mkdir work_dir")?;

        let outcome = self.run_inner(&mut job, &work_dir).await;
        let _ = tokio::fs::remove_dir_all(&work_dir).await;

        match outcome {
            Ok(result) => { job.status = JobStatus::Done; job.progress = 1.0; job.result = Some(result); }
            Err(e)     => { job.status = JobStatus::Failed; job.error = Some(format!("{:#}", e)); }
        }
        self.state.job_store.update_job(&job).await.context("persist terminal")?;
        tracing::info!(job_id = %job.job_id, event = "done", status = ?job.status, error = ?job.error, "job terminal");

        if let Some(url) = job.request.callback_url.clone() {
            let body = serde_json::to_vec(&job).unwrap_or_default();
            // Pick the matching webhook secret for signing (if caller is a webhook tenant).
            let secret = job.tenant_id.strip_prefix("secret:").and_then(|name| {
                self.state.config.webhook_secrets.iter()
                    .find_map(|(sec, n)| if n == name { Some(sec.clone()) } else { None })
            });
            let delivery = webhook::deliver(&url, &body, secret.as_deref()).await;
            job.callback_delivery = Some(delivery);
            let _ = self.state.job_store.update_job(&job).await;
        }
        Ok(())
    }

    async fn run_inner(&self, job: &mut Job, work_dir: &std::path::Path) -> Result<JobResult> {
        let (event_ids, mut clips_dropped) = self.resolve_source(&job.request.source).await?;
        if event_ids.len() > 500 { anyhow::bail!("too_many_clips: {} > 500", event_ids.len()); }

        let mut clips: Vec<ProbedClip> = vec![];
        let mut credits: Vec<RenderedCredit> = vec![];

        for id in &event_ids {
            let ev = match self.api.fetch_event(id).await {
                Ok(e) => e,
                Err(FetchError::NotFound(_)) => { clips_dropped.push(ClipDropped { event_id: id.clone(), reason: "event_not_found".into() }); continue; }
                Err(FetchError::Other(e))   => { clips_dropped.push(ClipDropped { event_id: id.clone(), reason: format!("fetch_err: {:#}", e) }); continue; }
            };
            let Some(sha) = Imeta::first_in(&ev).and_then(|i| i.sha256) else {
                clips_dropped.push(ClipDropped { event_id: ev.id.clone(), reason: "no_imeta_sha256".into() });
                continue;
            };
            let dest = work_dir.join(&sha);
            let dl = match self.download.download(&sha, &dest).await {
                Ok(d) => d,
                Err(e) => {
                    let s = format!("{:#}", e);
                    let reason = if s.contains("403") { "moderation_restricted" }
                                 else if s.contains("404") { "blob_not_found" }
                                 else { "download_err" };
                    clips_dropped.push(ClipDropped { event_id: ev.id.clone(), reason: format!("{}: {}", reason, s) });
                    continue;
                }
            };
            let info = match probe(&dl.path).await {
                Ok(i) => i,
                Err(e) => { clips_dropped.push(ClipDropped { event_id: ev.id.clone(), reason: format!("probe_err: {:#}", e) }); continue; }
            };
            let prof = self.api.fetch_profile(&ev.pubkey).await.unwrap_or_else(|_| crate::nostr_api::Profile { pubkey: ev.pubkey.clone(), ..Default::default() });
            let credit_text = format_credit_text(prof.display_name.as_deref(), prof.nip05.as_deref(), &ev.pubkey);
            clips.push(ProbedClip { event_id: ev.id.clone(), path: dl.path, duration_sec: info.duration_sec, credit_text });
            credits.push(RenderedCredit {
                event_id: ev.id.clone(), pubkey: ev.pubkey.clone(),
                nip05: prof.nip05.clone(), display_name: prof.display_name.clone(),
            });
        }

        // max_duration_sec cap (tail-drop)
        let cap = job.request.max_duration_sec as f64;
        let mut total: f64 = 0.0;
        let mut kept: Vec<ProbedClip> = vec![];
        for c in clips {
            if total + c.duration_sec > cap {
                clips_dropped.push(ClipDropped { event_id: c.event_id.clone(), reason: "exceeded_max_duration_sec".into() });
                continue;
            }
            total += c.duration_sec;
            kept.push(c);
        }
        if kept.is_empty() { anyhow::bail!("no_usable_clips"); }

        let mut outputs: Vec<BlobDescriptor> = vec![];
        for aspect in &job.request.aspects {
            let r = render_aspect(
                *aspect, &kept, job.request.fit,
                job.request.watermark.clone(), job.request.credit.clone(),
                &self.logo_path, work_dir, true,
            ).await.with_context(|| format!("render {:?}", aspect))?;
            let up = self.upload.upload_file(&r.output_path, "video/mp4").await
                .with_context(|| format!("upload {:?}", aspect))?;
            outputs.push(BlobDescriptor {
                aspect: *aspect, url: up.url, sha256: up.sha256, size: up.size,
                dim: format!("{}x{}", r.dim.width, r.dim.height),
            });
        }

        Ok(JobResult { outputs, duration_sec: total as u32, clips_used: kept.len() as u32, clips_dropped, credits })
    }

    async fn resolve_source(&self, src: &Source) -> Result<(Vec<String>, Vec<ClipDropped>)> {
        match src {
            Source::EventIds(ids) => Ok((ids.clone(), vec![])),
            Source::Naddr(naddr) => {
                let list = self.api.fetch_list_event(naddr).await
                    .map_err(|e| anyhow::anyhow!("fetch list: {:?}", e))?;
                let mut ids = vec![];
                let mut dropped = vec![];
                for t in &list.tags {
                    if t.len() < 2 { continue; }
                    match t[0].as_str() {
                        "e" => ids.push(t[1].clone()),
                        "a" => dropped.push(ClipDropped { event_id: t[1].clone(), reason: "addressable_ref_not_supported_v1".into() }),
                        _ => {}
                    }
                }
                Ok((ids, dropped))
            }
        }
    }
}
```

- [ ] **Step 3: `src/main.rs` (final wiring)**

```rust
// ABOUTME: Cloud Run service entry. Builds config → state → router → worker, binds PORT.

use anyhow::Context;
use divine_compiler::{
    auth::AppState,
    blossom::{DownloadClient, GcsUploader},
    config::Config,
    handlers::build_router,
    job::JobStore,
    nostr_api::ApiClient,
    rate_limit::RateLimiter,
    worker::Worker,
};
use firestore::{FirestoreDb, FirestoreDbOptions};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .json().init();

    let cfg = Arc::new(Config::from_process_env()?);
    tracing::info!(
        firestore_project = %cfg.firestore_project, gcs_bucket = %cfg.gcs_bucket,
        webhook_tenants = cfg.webhook_secrets.len(), max_concurrent_jobs = cfg.max_concurrent_jobs,
        "compiler starting"
    );

    // Wire dependencies
    let db = FirestoreDb::with_options(FirestoreDbOptions::new(cfg.firestore_project.clone()))
        .await.context("firestore connect")?;
    let job_store = Arc::new(JobStore::new(&cfg.firestore_project).await?);
    let rate_limiter = Arc::new(RateLimiter::new(db, cfg.rate_limit_per_hour, cfg.rate_limit_per_day));

    let api = ApiClient::new(&cfg.api_url)?;
    let download = DownloadClient::new(&cfg.media_url)?;
    let upload = GcsUploader::new(&cfg.gcs_bucket, &cfg.media_url).await?;

    // Fetch logo once at startup; cache on disk for the worker's lifetime.
    let logo_path = fetch_logo(&cfg.media_url).await?;

    let state = AppState { config: cfg.clone(), job_store: job_store.clone(), rate_limiter: rate_limiter.clone() };

    let worker = Arc::new(Worker::new(state.clone(), api, download, upload, logo_path));
    tokio::spawn(worker.run_forever());

    let app = build_router(state);
    let port: u16 = std::env::var("PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn fetch_logo(media_base: &str) -> anyhow::Result<PathBuf> {
    let dir = std::path::Path::new("/tmp/divine-compiler");
    tokio::fs::create_dir_all(dir).await.context("mkdir logo cache")?;
    let dest = dir.join("divine-logo.png");
    if dest.exists() { return Ok(dest); }
    let url = format!("{}/divine-logo.png", media_base.trim_end_matches('/'));
    let resp = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15)).build()?
        .get(&url).send().await.context("GET logo")?;
    if !resp.status().is_success() { anyhow::bail!("logo {} → {}", url, resp.status()); }
    let bytes = resp.bytes().await?;
    tokio::fs::write(&dest, &bytes).await?;
    Ok(dest)
}
```

- [ ] **Step 4: Verify compile** — `cargo build`. Expected: compiles cleanly.

- [ ] **Step 5: Commit**

```bash
git add cloud-run-compiler/
git commit -m "feat(compiler): handlers + worker + main.rs wiring (end-to-end service)"
```

### Task 6.3: Smoke test + deploy + sign off

**Files:** Create `cloud-run-compiler/scripts/smoke-test.sh`.

- [ ] **Step 1: Smoke test script**

```bash
#!/bin/bash
# ABOUTME: End-to-end smoke test for the deployed divine-compiler service
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-divine-compiler}"

# Auth: webhook-secret caller (NOT admin token). Must be a value present in
# COMPILER_WEBHOOK_SECRETS at the secret-side of one of the name:secret pairs.
WEBHOOK_SECRET="${SMOKE_WEBHOOK_SECRET:?export SMOKE_WEBHOOK_SECRET (a configured webhook secret)}"
SMOKE_NADDR="${SMOKE_NADDR:?export SMOKE_NADDR (a naddr1... pointing at a small video list)}"

SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" --region "${REGION}" --format='value(status.url)')

echo "Submitting compile job..."
SUBMIT=$(curl -fsS -X POST "${SERVICE_URL}/compile" \
  -H "Authorization: Bearer ${WEBHOOK_SECRET}" \
  -H "Content-Type: application/json" \
  -d "{\"source\":{\"naddr\":\"${SMOKE_NADDR}\"},\"aspects\":[\"9:16\",\"1:1\",\"16:9\"],\"max_duration_sec\":120}")
JOB_ID=$(echo "${SUBMIT}" | jq -r '.job_id')
echo "Job id: ${JOB_ID}"

echo "Polling for done..."
for _ in $(seq 1 60); do
  STATUS_JSON=$(curl -fsS "${SERVICE_URL}/compile/${JOB_ID}" -H "Authorization: Bearer ${WEBHOOK_SECRET}")
  STATUS=$(echo "${STATUS_JSON}" | jq -r '.status')
  echo "  ...${STATUS}"
  [[ "${STATUS}" == "done" || "${STATUS}" == "failed" ]] && break
  sleep 10
done

echo "${STATUS_JSON}" | jq .
[[ "${STATUS}" == "done" ]] || { echo "Job did not finish (${STATUS})"; exit 1; }

echo "Verifying outputs..."
echo "${STATUS_JSON}" | jq -r '.result.outputs[].url' | while read -r URL; do
  echo "  HEAD ${URL}"
  curl -fsSI "${URL}" > /dev/null
done

echo "Smoke test passed."
```

`chmod +x cloud-run-compiler/scripts/smoke-test.sh`.

- [ ] **Step 2: Deploy to staging**

```bash
PROJECT_ID=<staging-project> SERVICE_NAME=divine-compiler-staging cloud-run-compiler/deploy.sh
```

First-time deploy needs the prerequisites in deploy.sh's comment header (Firestore TTL, IAM, secrets).

- [ ] **Step 3: Run smoke**

```bash
PROJECT_ID=<staging-project> SERVICE_NAME=divine-compiler-staging \
  SMOKE_WEBHOOK_SECRET=<configured webhook secret> \
  SMOKE_NADDR=<real naddr with 2-3 small videos> \
  cloud-run-compiler/scripts/smoke-test.sh
```

- [ ] **Step 4: Manual verification**

Open each of the 3 output URLs. Confirm: video plays, divine logo bug at the configured corner, per-clip credit text fades in/out at the start of each clip, aspect ratio correct, audio present.

Tail Cloud Logging for `event="done"`:
```bash
gcloud logging read 'resource.type=cloud_run_revision AND resource.labels.service_name="divine-compiler-staging" AND jsonPayload.event="done"' \
  --limit=5 --project="${PROJECT_ID}"
```

- [ ] **Step 5: Sign off + PR**

```bash
git add cloud-run-compiler/
git commit -m "test(compiler): end-to-end smoke test script"
gh pr create --title "compiler: v1 launch" --body "Implementation of docs/superpowers/specs/2026-05-17-compilation-service-design.md per plan docs/superpowers/plans/2026-05-17-compilation-service.md"
```

**End of Chunk 6. End of plan.**

---

## V1 deferrals (intentional simplifications)

These are explicitly NOT in v1; ship them when there's real demand:

- **Per-clip overrides** (`in_sec`/`out_sec` trim, per-clip `fit`). Schema doesn't accept the field.
- **Dry-run mode** — schema rejects `dry_run: true`.
- **nevents source variant** — caller hex-decodes.
- **Admin cancel/requeue** — only list + get for v1.
- **Atomic job-claim** — best-effort update; duplicate-claim window is tiny at low concurrency.
- **Streaming GCS upload** — `fs::read` whole file is fine for v1 sizes.
- **Crossfade/dip-to-black transitions, intro/outro cards, always-on credit modes, BGM mixing, animated watermark** — schema doesn't accept these fields.
- **Public "recently rendered comps" feed** — admin-only in v1.
- **Per-tenant idempotency keys** — none.
- **naddr `a`-tag (addressable refs)** — surfaced in `clips_dropped` with `addressable_ref_not_supported_v1`.
- **Pre-checking moderation** — we let downloads fail (403 = restricted, 404 = deleted/missing) and surface in `clips_dropped`.

## Known v1 limitations (documented in source)

- **Audio-less clips fail.** Render assumes every input has `[N:a:0]`. v2: probe + inject silence via `anullsrc` for muted inputs.
- **NIP-01 canonicalization via `nostr` crate.** Should be interop-safe with other Rust signers; verify cross-client interop in staging.
- **`firestore` crate version drift.** API surface may shift between minor versions; verify against the pinned version at impl time.
- **`api.divine.video` endpoint paths.** `/api/event/<hex>`, `/api/profile/<hex>`, `/api/addressable?author&kind&d` are best-guesses; verify against actual OpenAPI before deploy.
- **`google-cloud-storage` Multipart vs Simple upload.** Verify Multipart works against the pinned 0.17 version; fall back to Simple + `patch_object` if not.
