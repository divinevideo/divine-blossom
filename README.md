# Fastly Blossom Server

A [Blossom](https://github.com/hzrd149/blossom) media server for Nostr running on Fastly Compute, optimized for video content.

## Architecture

```
Client → Fastly Compute (Rust WASM) → GCS (blobs) + Fastly KV (metadata)
           ├── Cloud Run Upload (Rust) → GCS + Transcoder trigger
           ├── Cloud Run Transcoder (Rust, NVIDIA GPU) → HLS segments to GCS
           └── Cloud Logging (audit trail)
```

- **Fastly Compute Edge** (`src/`) - Rust WASM service on Fastly. Handles uploads, metadata KV, HLS proxying, admin, provenance
- **Cloud Run Upload** (`cloud-run-upload/`) - Rust service on GCP. Receives legacy `PUT /upload` bytes, owns resumable upload sessions, writes temp/final objects in GCS, triggers transcoder, receives audit logs
- **Cloud Run Transcoder** (`cloud-run-transcoder/`) - Rust service on GCP with NVIDIA GPU. Downloads from GCS, transcodes to HLS via FFmpeg NVENC, uploads segments back
- **GCS bucket**: `divine-blossom-media`
- **Control plane**: `media.divine.video` (Fastly)
- **Data plane**: `upload.divine.video` (GKE-hosted resumable `HEAD`/`PUT`/`DELETE` service)

## Features

- **BUD-01**: Blob retrieval (GET/HEAD)
- **BUD-02**: Upload/delete/list management
- **BUD-03**: User server list support
- **Nostr auth**: Kind 24242 signature validation (Schnorr signatures)
- **Shadow restriction**: Moderated content only visible to owner
- **Range requests**: Native video seeking support
- **HLS transcoding**: Multi-quality adaptive streaming (1080p, 720p, 480p, 360p)
- **WebVTT transcripts**: Stable transcript URL at `/<sha256>.vtt` with async generation
- **Audio extraction**: Stable audio-only URL at `/<sha256>.audio.m4a` with Funnelcake permission gating
- **Provenance & audit**: Cryptographic proof of upload/delete authorship with Cloud Logging audit trail
- **Tombstones**: Legal hold prevents re-upload of removed content
- **Admin soft-delete**: DMCA/legal removal with full audit trail while preserving recoverable storage
- **Admin restore**: Re-index and restore previously soft-deleted blobs

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

If you want audio extraction enabled in production, add `funnelcake_api_url` to `blossom_config`. The example `fastly.toml.example` points it at `https://relay.divine.video`, which serves the public audio-reuse lookup used by the edge service.

### Local development

```bash
# Copy the example config and fill in your credentials
cp fastly.toml.example fastly.toml

# Edit fastly.toml with your GCS credentials (this file is gitignored)
# Then run:
fastly compute serve
```

**Note**: `fastly.toml` is gitignored to prevent accidentally committing secrets. The `[local_server.secret_stores]` section is only used for local testing.

### Cloud Run upload service configuration

`cloud-run-upload` now expects these runtime values in addition to the existing bucket and transcoder settings:

- `UPLOAD_BASE_URL=https://upload.divine.video`
- `RESUMABLE_SESSION_TTL_SECS=86400`
- `RESUMABLE_CHUNK_SIZE=8388608`

For browser/web clients, the `upload.divine.video` service must allow:

- Methods: `HEAD`, `PUT`, `POST`, `DELETE`, `OPTIONS`
- Request headers: `Authorization`, `Content-Type`, `Content-Range`
- Exposed response headers: `Upload-Offset`, `Upload-Length`, `Upload-Expires`, `X-Divine-Chunk-Size`

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
| `GET` | `/<sha256>.audio.m4a` | Extract and serve audio-only M4A for eligible videos |
| `HEAD` | `/<sha256>.audio.m4a` | Check audio extraction availability |

`GET /<sha256>.vtt` returns `202 Accepted` with `Retry-After` while transcription is still running or cooling down after a retryable provider failure. Clients should poll again instead of treating that response as "no subtitles".

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
| `POST` | `/upload/init` | Required | Create a Divine resumable upload session |
| `POST` | `/upload/<uploadId>/complete` | Required | Publish a completed resumable upload into canonical metadata |
| `DELETE` | `/<sha256>` | Required | Permanently delete your own blob |
| `GET` | `/list/<pubkey>` | Optional | List user's blobs |

When resumable support is available, `HEAD /upload` includes these discovery headers:

- `X-Divine-Upload-Extensions: resumable-sessions`
- `X-Divine-Upload-Control-Host: <public Blossom host>`
- `X-Divine-Upload-Data-Host: upload.divine.video`

`POST /upload/init` returns camelCase fields for the mobile client contract:

- `uploadId`
- `uploadUrl`
- `expiresAt`
- `chunkSize`
- `nextOffset`
- `requiredHeaders`

The session byte stream itself is served from `upload.divine.video`:

| Method | Host | Path | Auth | Description |
|--------|------|------|------|-------------|
| `HEAD` | `upload.divine.video` | `/sessions/<uploadId>` | Session bearer token | Query the committed offset |
| `PUT` | `upload.divine.video` | `/sessions/<uploadId>` | Session bearer token | Upload a contiguous chunk with `Content-Range` |
| `DELETE` | `upload.divine.video` | `/upload/<uploadId>` | Session bearer token | Abort a resumable upload session |

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

## Transcript Recovery

Use the repo-level backfill wrapper to inspect or enqueue missing transcripts through the existing `/admin/api/backfill-vtt` endpoint.

Dry-run the recent upload window without triggering work:

```bash
ADMIN_BEARER_TOKEN=<webhook_or_admin_token> \
bash scripts/backfill_missing_transcripts.sh --dry-run --limit 20
```

Enqueue the recent backfill at a controlled pace after Cloud Run and Blossom fixes are deployed:

```bash
ADMIN_BEARER_TOKEN=<webhook_or_admin_token> \
bash scripts/backfill_missing_transcripts.sh --limit 200 --sleep 2
```

Notes:
- Set either `ADMIN_BEARER_TOKEN` or `ADMIN_COOKIE`.
- `--scope recent` is the default and scans the rolling recent-upload index first.
- Use `--scope users` for a full corpus sweep when the recent window is not enough.
- `--reset-processing` requeues blobs stuck in `processing`, and `--force-retranscribe` reruns blobs marked `complete`.

## Debug Upload Harness

Use the upload harness to replay the upload control plane with a full HTTP transcript. The first version stops at upload completion and does not create the publish event.

Resumable upload example:

```bash
python3 scripts/debug_upload_harness.py \
  --server https://media.divine.video \
  --file /absolute/path/to/video.mp4 \
  --mode resumable \
  --auth-header 'Nostr <signed-event>'
```

ProofMode completion example:

```bash
python3 scripts/debug_upload_harness.py \
  --server https://media.divine.video \
  --file /absolute/path/to/video.mp4 \
  --mode resumable \
  --auth-header 'Nostr <signed-event>' \
  --proof-json /absolute/path/to/proofmode.json \
  --dump-json /tmp/upload-transcript.json
```

Replay only the completion request for an existing session:

```bash
python3 scripts/debug_upload_harness.py \
  --server https://media.divine.video \
  --mode resumable \
  --auth-header 'Nostr <signed-event>' \
  --complete-only \
  --upload-id up_example123 \
  --file-hash 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --file-size 1234567
```

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
