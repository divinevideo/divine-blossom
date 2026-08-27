# Divine Blossom

Content-addressed media storage for the [Divine](https://divine.video) platform, implementing the [Blossom](https://github.com/hzrd149/blossom) protocol for Nostr on [Fastly Compute](https://www.fastly.com/products/edge-compute). Divine Blossom serves media at `media.divine.video`: blobs are addressed by their SHA-256 hash, uploads are authorized with signed Nostr events, and video is transcoded to adaptive HLS with generated transcripts. The Fastly edge service handles retrieval, auth, and admin; heavier work (large uploads, transcoding, speech-to-text, moderation) runs in companion Cloud Run services on GCP.

## Features

- **Content-addressed storage** — blobs stored and retrieved by SHA-256 hash, backed by Google Cloud Storage
- **Nostr auth** — Blossom auth events (kind 24242, Schnorr signatures) for uploads and deletes; NIP-98 HTTP auth (kind 27235) for viewer/list requests
- **HLS transcoding** — multi-quality adaptive streaming (1080p, 720p, 480p, 360p) generated on GPU-backed Cloud Run
- **WebVTT transcripts** — automatic speech-to-text with a stable transcript URL at `/<sha256>.vtt` and an on-demand subtitle jobs API
- **Range requests** — native video seeking with `206 Partial Content` on blobs, quality variants, and audio
- **Provenance & audit** — every upload and delete stores its signed auth event as cryptographic proof; actions are logged to Google Cloud Logging
- **Moderation** — SafeSearch (Vision API) screening plus shadow restriction, so restricted content is visible only to its owner or an admin
- **Age restriction** — `age_restricted` blobs serve to any authenticated viewer and return `401` to anonymous requests
- **Admin soft-delete & restore** — DMCA/legal removal with a full audit trail while preserving recoverable storage, plus re-index/restore
- **Tombstones & legal hold** — legally removed content is blocked from re-upload (returns 403)
- **GDPR vanish** — user- and admin-initiated erasure of a pubkey's content
- **C2PA trust checking** — validates Content Credentials manifests and signer trust chains on uploaded media
- **CDN fallback** — missing blobs are fetched from a fallback chain (`cdn.divine.video`, `blossom.divine.video`, `cdn.satellite.earth`, `image.nostr.build`)

### Supported Blossom endpoints (BUDs)

| BUD | Capability |
|-----|------------|
| BUD-01 | Blob retrieval (`GET`/`HEAD /<sha256>`) |
| BUD-02 | Upload, list, and delete management |
| BUD-04 | Mirroring — pull a blob from another server by URL |
| BUD-06 | Upload pre-validation (`HEAD /upload`) |
| BUD-09 | Reporting — accept NIP-56 report events (kind 1984) |

Maximum upload size is 50 GB. Files above the in-process limit are streamed through the Cloud Run upload service.

## Architecture

Divine Blossom is a Fastly Compute edge service plus a set of GCP Cloud Run companions. The edge service is the front door for all media traffic; it stores small blobs directly and delegates large uploads, transcoding, speech-to-text, and moderation.

```
Client → Fastly Compute (Rust WASM) → GCS (blobs) + Fastly KV (metadata)
           ├── Cloud Run Upload (Rust) → GCS + transcoder trigger
           ├── Cloud Run Transcoder (Rust, NVIDIA GPU) → HLS segments to GCS
           ├── Cloud Run ASR / Parakeet (Python) → speech-to-text for transcripts
           └── Cloud Run Process-Blob (Python) → C2PA validation + SafeSearch moderation
```

- **Fastly Compute edge** (`src/`) — Rust WASM service. Handles blob retrieval, uploads, metadata in Fastly KV, HLS proxying, transcripts, admin, provenance, and auth. Pure-logic types and delete/moderation policy live in the `blossom-core` library crate so they can be unit-tested natively (outside the WASM runtime).
- **Cloud Run Upload** (`cloud-run-upload/`) — Rust service on GCP. Receives large uploads over HTTP/2 (bypassing the Fastly body-size limit), sanitizes with `ffmpeg -c copy`, hashes, uploads to GCS, triggers the transcoder, and emits audit logs.
- **Cloud Run Transcoder** (`cloud-run-transcoder/`) — Rust service on GCP with an NVIDIA GPU. Downloads source from GCS, transcodes to HLS via FFmpeg NVENC, and uploads segments back.
- **Cloud Run ASR / Parakeet** (`cloud-run-asr-parakeet/`) — Python service. Runs speech-to-text (Parakeet TDT) as a sidecar to the transcoder for WebVTT transcript generation.
- **Cloud Run Process-Blob** (`cloud-functions/process-blob/`) — Python/Flask service triggered by GCS object finalization via Eventarc. Validates C2PA Content Credentials (`c2patool`) and runs SafeSearch moderation (Vision API), then updates Fastly KV metadata through a webhook.

**Platform details**

- GCS bucket: `divine-blossom-media`
- CDN / public host: `media.divine.video` (Fastly)
- Fastly stores: KV store `blossom_metadata`, config store `blossom_config`, secret store `blossom_secrets`

## Getting started

### Prerequisites

- [Fastly CLI](https://developer.fastly.com/learning/tools/cli/)
- [Rust](https://rustup.rs/) — the toolchain is pinned by `rust-toolchain.toml` (stable 1.83.0, target `wasm32-wasip1`)
- A GCP project with a GCS bucket and Cloud Run
- A Fastly account with Compute enabled

### Install the WASM target

```bash
rustup target add wasm32-wasip1
```

### Create the Fastly stores

```bash
# KV store for blob metadata
fastly kv-store create --name blossom_metadata

# Config store for non-secret settings
fastly config-store create --name blossom_config

# Secret store for GCS HMAC credentials and tokens
fastly secret-store create --name blossom_secrets
```

### Local development

```bash
# Copy the example manifest and fill in credentials (gitignored)
cp fastly.toml.example fastly.toml

# Run the local Compute test server
fastly compute serve
```

`fastly.toml` is gitignored so secrets are never committed. The `[local_server]` section (backends, KV, config, and secret stores) is used only for local testing; in production these bindings are managed in the Fastly dashboard.

### Tests

```bash
./scripts/run-edge-tests.sh                                  # edge crate tests under Viceroy
cargo check --tests --locked                                  # edge crate compile check
cargo test -p blossom-core --locked                           # pure-logic core
cargo test --manifest-path cloud-run-upload/Cargo.toml --locked
cargo clippy --locked --all-targets --all-features            # lint gate used in CI
```

## Configuration

Configuration is split across the Fastly config store (non-secret) and secret store (credentials). The `fastly.toml.example` manifest documents the full set of backends and store bindings.

### Config store (`blossom_config`)

| Key | Description |
|-----|-------------|
| `gcs_bucket` | GCS bucket name (`divine-blossom-media`) |
| `gcs_project_id` | GCP project ID |
| `funnelcake_api_url` | Funnelcake permission API base URL |
| `ENABLE_PHYSICAL_DELETE` | When `"true"`, creator-delete via `/admin/api/moderate` physically removes bytes from GCS and purges edge caches; when `"false"` (default), it flips status only. Admin DMCA via `/admin/api/delete` is always a soft-delete regardless of this flag. |
| `REQUIRE_DERIVATIVE_STATUS_GENERATION` | Set to `"false"` only during rollback to a transcoder image that does not send derivative status `generation` values. Defaults to required once a blob has versioned derivative state. |

### Secret store (`blossom_secrets`)

| Key | Description |
|-----|-------------|
| `gcs_access_key` | GCS HMAC access key |
| `gcs_secret_key` | GCS HMAC secret key |
| `moderation_api_token` | Bearer token for the Divine moderation API |

### Backends

Registered in Fastly and mirrored in `fastly.toml.example`: `gcs_storage` (GCS), the CDN fallback chain (`cdn_divine`, `blossom_divine`, `cdn_satellite`, `nostr_build`), `upload_service` (large-upload/resumable control plane), `moderation_api`, and `funnelcake_api`.

### Process-Blob (Cloud Run) environment

C2PA validation in `cloud-functions/process-blob` is controlled by environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `C2PA_MODE` | `off`, `log`, or `enforce` | `off` |
| `C2PA_TRUST_ANCHORS` | Path to trusted CA certificates (PEM) | `/app/trust_anchors.pem` |
| `C2PA_CHECK_IMAGES` | Also validate image uploads | `false` |
| `C2PA_MAX_FILE_SIZE` | Skip C2PA above this size (bytes) | `2147483648` |
| `C2PA_WARN_FILE_SIZE` | Warn above this size (bytes) | `268435456` |

In `enforce` mode, unsigned or untrusted content is rejected (status set to `restricted`). C2PA runs before SafeSearch to short-circuit untrusted content and save Vision API cost.

## API

### Retrieval (BUD-01)

| Method | Path | Description |
|--------|------|-------------|
| `GET` / `HEAD` | `/<sha256>[.ext]` | Retrieve blob / check existence |
| `GET` / `HEAD` | `/<sha256>.hls` | HLS master manifest |
| `GET` / `HEAD` | `/<sha256>/<quality>` | Quality variant (e.g. `720p`, `480p`) |
| `GET` / `HEAD` | `/<sha256>.vtt`, `/<sha256>/VTT` | WebVTT transcript (on-demand generation) |
| `GET` | `/<sha256>/provenance` | Provenance info (owner, uploaders, auth events) |

### Management (BUD-02)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `PUT` | `/upload` | Required | Upload blob |
| `HEAD` | `/upload` | None | Upload requirements (BUD-06) |
| `DELETE` | `/<sha256>` | Required | Permanently delete your own blob |
| `DELETE` | `/vanish` | Required | GDPR erasure of your content |
| `GET` | `/list/<pubkey>` | Optional | List a user's blobs |
| `PUT` | `/mirror` | Required | Mirror a blob from another server (BUD-04) |
| `PUT` | `/report` | None | Report content via a NIP-56 event (BUD-09) |

The resumable-upload control plane (`POST /upload/init`, `POST /upload/<id>/complete`) proxies large sessions to the upload service.

### Subtitle jobs

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/subtitles/jobs` | Create a subtitle job (`video_sha256`, optional `lang`, `force`) |
| `GET` | `/v1/subtitles/jobs/<job_id>` | Job status (`queued`, `processing`, `ready`, `failed`) |
| `GET` | `/v1/subtitles/by-hash/<sha256>` | Idempotent lookup of an existing job by hash |

### Admin

Admin routes require an admin session (Google or GitHub OAuth; see `OAUTH_SETUP.md`). Highlights:

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/admin/api/delete` | Soft-delete a blob, remove it from public serving/indexes, optionally set legal hold |
| `POST` | `/admin/api/restore` | Restore a soft-deleted blob to `active`, `pending`, or `restricted` |
| `POST` | `/admin/api/moderate` | Creator/moderation action (respects `ENABLE_PHYSICAL_DELETE`) |
| `GET` | `/admin/api/stats`, `/admin/api/recent`, `/admin/api/users` | Dashboard data |

Example soft-delete:

```bash
curl -X POST https://media.divine.video/admin/api/delete \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"sha256": "abc123...", "reason": "DMCA #1234", "legal_hold": true}'
```

When `legal_hold: true`, a tombstone is set that blocks re-upload of the same hash (returns 403).

### Authentication

Management operations (`PUT /upload`, `DELETE /<sha256>`, vanish) use Blossom auth events (kind 24242):

```json
{
  "kind": 24242,
  "content": "Upload blob",
  "tags": [
    ["t", "upload"],
    ["x", "<sha256>"],
    ["expiration", "<unix_timestamp>"]
  ]
}
```

Send as `Authorization: Nostr <base64_encoded_signed_event>`.

Viewer/list requests also accept NIP-98 HTTP auth (kind 27235) for the exact request URL and method. Protected media GET routes additionally accept Blossom GET auth (kind 24242 with `["t","get"]`). When multiple `Authorization` headers are present, viewer auth succeeds if any valid NIP-98 or Blossom GET header matches. `age_restricted` blobs serve to any authenticated viewer and return `401 {"error":"age_restricted"}` to anonymous requests; `restricted` blobs remain shadow-banned and serve only to the owner or an admin.

### Request correlation

Admin and moderation endpoints accept an `X-Request-Id` header and echo it into related log lines (`[req=<id>]`) so retries and partial failures can be traced. When the outer Fastly VCL service is chained in front of Compute it pins the selected ID in `X-Divine-Edge-Request-Id`, which takes precedence and is overwritten on every chained request, so it is trustworthy only once that outer service is activated; until then a direct caller can set the header itself. Otherwise `X-Request-Id` is used. If neither is present, the leading segment of the Cloudflare `cf-ray` header is used; failing that, a short hex ID is generated. IDs are sanitized and capped at 64 characters, so common caller IDs (UUIDs, trace IDs) are preserved verbatim and longer values keep a 64-character prefix. Upstream services (e.g. the moderation service driving creator-delete) should forward a stable `X-Request-Id` across retries. `[PURGE]` logs carry the blob `sha256` as the surrogate key for cross-referencing cache purges.

## Deployment

Deploys go to Fastly Compute with a single atomic command:

```bash
fastly compute publish --comment "description"
```

Always use `fastly compute publish` (build + deploy in one step), never separate `build` and `deploy`. Do not globally purge after a routine deploy. To invalidate one blob and its derivatives, purge its hash surrogate key with `fastly purge --key <hash> --service-id <service-id>`. When a response-semantics change truly requires invalidating the entire catalogue, manually run the CI workflow on `main` with its `purge_cache` input enabled. Package propagation to all POPs can take several minutes after a publish.

CI (`.github/workflows/ci.yml`) runs the edge, core, upload, transcoder, and Python test suites plus clippy on every push and PR. On a push to `main` it then, in parallel: publishes the edge service to Fastly without globally purging the CDN, builds and pushes the container image to GHCR, and deploys `process-blob` to Cloud Run (`us-central1`). The Compute publish fails closed unless the repository variable `FASTLY_OUTER_DIAGNOSTICS_ACTIVE` is `true`; set it only after activating the required outer `vcl/deliver.vcl`. If a push was blocked by that gate, manually run the `CI` workflow on `main` with `publish_compute` enabled after the outer VCL is active and the variable is set.

## License

MIT

---

Part of [Divine](https://divine.video) — your playground for human creativity · [Brand guidelines](https://github.com/divinevideo/brand-guidelines)
