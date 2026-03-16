# Fastly Blossom Server

A [Blossom](https://github.com/hzrd149/blossom) media server for Nostr running on Fastly Compute, optimized for video content.

## Architecture

```
Client → Fastly Compute (Rust WASM) → GCS (blobs) + Fastly KV (metadata)
           ├── Cloud Run Upload (Rust) → GCS + Transcoder trigger
           ├── Cloud Run Transcoder (Rust, NVIDIA GPU) → HLS segments to GCS
           ├── Cloud Run Process-Blob (Python) → C2PA validation + SafeSearch moderation
           └── Cloud Logging (audit trail)
```

- **Fastly Compute Edge** (`src/`) - Rust WASM service on Fastly. Handles uploads, metadata KV, HLS proxying, admin, provenance
- **Cloud Run Upload** (`cloud-run-upload/`) - Rust service on GCP. Receives video bytes, sanitizes (ffmpeg -c copy), hashes, uploads to GCS, triggers transcoder, receives audit logs
- **Cloud Run Transcoder** (`cloud-run-transcoder/`) - Rust service on GCP with NVIDIA GPU. Downloads from GCS, transcodes to HLS via FFmpeg NVENC, uploads segments back
- **Cloud Run Process-Blob** (`cloud-functions/process-blob/`) - Python/Flask service on GCP. Triggered by GCS object finalization via Eventarc. Validates C2PA Content Credentials (c2patool) and runs SafeSearch moderation (Vision API), then updates Fastly KV metadata via webhook
- **GCS bucket**: `divine-blossom-media`
- **CDN**: `media.divine.video` (Fastly)

## Features

- **BUD-01**: Blob retrieval (GET/HEAD)
- **BUD-02**: Upload/delete/list management
- **BUD-03**: User server list support
- **Nostr auth**: Kind 24242 signature validation (Schnorr signatures)
- **Shadow restriction**: Moderated content only visible to owner
- **Range requests**: Native video seeking support
- **HLS transcoding**: Multi-quality adaptive streaming (1080p, 720p, 480p, 360p)
- **WebVTT transcripts**: Stable transcript URL at `/<sha256>.vtt` with async generation
- **Provenance & audit**: Cryptographic proof of upload/delete authorship with Cloud Logging audit trail
- **Tombstones**: Legal hold prevents re-upload of removed content
- **Admin soft-delete**: DMCA/legal removal with full audit trail while preserving recoverable storage
- **Admin restore**: Re-index and restore previously soft-deleted blobs
- **C2PA trust checking**: Validates Content Credentials (C2PA) manifests and signer trust chains on uploaded media

## Setup

### Prerequisites

- [Fastly CLI](https://developer.fastly.com/learning/tools/cli/)
- [Rust](https://rustup.rs/) with wasm32-wasi target
- GCP project with GCS bucket and Cloud Run
- Fastly account with Compute enabled

### Install Rust target

```bash
rustup target add wasm32-wasi
```

### Configure secrets

1. Create a GCS bucket with HMAC credentials
2. Set up Fastly stores:

```bash
# Create KV store
fastly kv-store create --name blossom_metadata

# Create config store
fastly config-store create --name blossom_config

# Create secret store with GCS HMAC credentials
fastly secret-store create --name blossom_secrets
```

### Local development

```bash
# Copy the example config and fill in your credentials
cp fastly.toml.example fastly.toml

# Edit fastly.toml with your GCS credentials (this file is gitignored)
# Then run:
fastly compute serve
```

**Note**: `fastly.toml` is gitignored to prevent accidentally committing secrets. The `[local_server.secret_stores]` section is only used for local testing.

### Deploy

```bash
fastly compute publish
```

## API Endpoints

### BUD-01: Retrieval

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/<sha256>[.ext]` | Retrieve blob |
| `HEAD` | `/<sha256>[.ext]` | Check blob exists |
| `GET` | `/<sha256>.vtt` | Retrieve WebVTT transcript (on-demand generation) |
| `HEAD` | `/<sha256>.vtt` | Check transcript status/existence |
| `GET` | `/<sha256>/VTT` | Alias for transcript retrieval |

### Subtitle Jobs API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/subtitles/jobs` | Create subtitle job (`video_sha256`, optional `lang`, optional `force`) |
| `GET` | `/v1/subtitles/jobs/<job_id>` | Get subtitle job status (`queued`, `processing`, `ready`, `failed`) |
| `GET` | `/v1/subtitles/by-hash/<sha256>` | Idempotent hash lookup for existing subtitle job |

### BUD-02: Management

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `PUT` | `/upload` | Required | Upload blob |
| `HEAD` | `/upload` | None | Get upload requirements |
| `DELETE` | `/<sha256>` | Required | Permanently delete your own blob |
| `GET` | `/list/<pubkey>` | Optional | List user's blobs |

### Provenance & Admin

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/<sha256>/provenance` | None | Get provenance info (owner, uploaders, auth events) |
| `POST` | `/admin/api/delete` | Admin | Soft-delete blob, remove it from public serving/indexes, and optionally set legal hold |
| `POST` | `/admin/api/restore` | Admin | Restore a soft-deleted blob to `active`, `pending`, or `restricted` |

### Provenance

Every upload and delete stores the signed Nostr auth event (kind 24242) in KV as cryptographic proof of who authorized the action. The `/provenance` endpoint returns:

```json
{
  "sha256": "abc123...",
  "owner": "<nostr_pubkey>",
  "uploaders": ["<pubkey1>", "<pubkey2>"],
  "upload_auth_event": { ... },
  "delete_auth_event": null,
  "tombstone": null
}
```

### Audit Logging

All uploads and deletes are logged to Google Cloud Logging via the Cloud Run upload service. Each audit entry includes: action, SHA-256, actor pubkey, timestamp, the signed auth event, and a metadata snapshot. Logs are queryable via Cloud Logging with labels `service=divine-blossom, component=audit`.

### Delete Semantics

- `DELETE /<sha256>` is a direct user delete and permanently removes the canonical blob.
- `POST /admin/api/delete` is an admin soft-delete. It marks the blob as `deleted`, stops all public serving, removes it from user/recent indexes, and preserves the stored blob so it can be recovered later.
- `POST /admin/api/restore` restores a soft-deleted blob and re-indexes it.
- `legal_hold: true` sets a tombstone that prevents re-upload of the same hash even if the stored blob is preserved.

### Admin Soft-Delete

```bash
curl -X POST https://media.divine.video/admin/api/delete \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"sha256": "abc123...", "reason": "DMCA #1234", "legal_hold": true}'
```

### Admin Restore

```bash
curl -X POST https://media.divine.video/admin/api/restore \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"sha256": "abc123...", "status": "active"}'
```

When `legal_hold: true`, a tombstone is set preventing re-upload of the removed content (returns 403).

## C2PA Trust Checking

The `cloud-functions/process-blob` module validates [C2PA](https://c2pa.org/) Content Credentials on uploaded media using [c2patool](https://github.com/contentauth/c2patool).

### How it works

1. **Manifest extraction** — runs `c2patool --detailed <file>` to read the embedded C2PA manifest
2. **Trust chain validation** — runs `c2patool --detailed <file> trust --trust_anchors <trust_anchors.pem>` to verify the signer against trusted certificate authorities

Validation results (manifest presence, trust status, claim generator, issuer) are attached to the blob's metadata via the Fastly KV webhook.

### Modes

Controlled by the `C2PA_MODE` environment variable:

| Mode | Behavior |
|------|----------|
| `off` (default) | No C2PA validation |
| `log` | Validates and logs results but does not block content |
| `enforce` | Rejects unsigned or untrusted content (sets status to `restricted`) |

### Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `C2PA_MODE` | Validation mode (`off`, `log`, `enforce`) | `off` |
| `C2PA_TRUST_ANCHORS` | Path to trusted CA certificates (PEM) | `/app/trust_anchors.pem` |
| `C2PA_CHECK_IMAGES` | Also validate image uploads (`true`/`false`) | `false` |
| `C2PA_MAX_FILE_SIZE` | Skip C2PA validation for files above this size (bytes) | `2147483648` (2GB) |
| `C2PA_WARN_FILE_SIZE` | Log a warning for files above this size (bytes) | `524288000` (500MB) |

### Trust anchors

The bundled `trust_anchors.pem` contains ProofSign CA certificates (ECDSA P-256) for verifying C2PA manifests signed by [ProofMode](https://proofmode.org/) on Android and iOS. Replace or extend this file with additional CA certificates as needed.

### Container

The module runs on Cloud Run as a Flask/gunicorn service. The Dockerfile installs c2patool v0.26.33 from GitHub releases. C2PA validation runs before SafeSearch moderation to short-circuit untrusted content early and save Vision API costs.

## Authentication

Uses Nostr kind 24242 events:

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

Send as: `Authorization: Nostr <base64_encoded_signed_event>`

## License

MIT
