# Fastly Blossom Server

A [Blossom](https://github.com/hzrd149/blossom) media server for Nostr running on Fastly Compute, optimized for video content.

## Architecture

```
Fastly Compute (Rust) → Backblaze B2 (blobs) + Fastly KV (metadata)
                     → GCP (async moderation)
```

## Features

- **BUD-01**: Blob retrieval (GET/HEAD)
- **BUD-02**: Upload/delete/list management
- **BUD-03**: User server list support
- **Nostr auth**: Kind 24242 signature validation
- **Shadow restriction**: Moderated content only visible to owner
- **Range requests**: Native video seeking support
- **WebVTT transcripts**: Stable transcript URL at `/<sha256>.vtt` with async generation
- **Free egress**: B2 → Fastly bandwidth is free

## Setup

### Prerequisites

- [Fastly CLI](https://developer.fastly.com/learning/tools/cli/)
- [Rust](https://rustup.rs/) with wasm32-wasi target
- Backblaze B2 account
- Fastly account with Compute enabled

### Install Rust target

```bash
rustup target add wasm32-wasi
```

### Configure secrets

1. Create a Backblaze B2 bucket
2. Create an application key with read/write access
3. Set up Fastly stores:

```bash
# Create KV store
fastly kv-store create --name blossom_metadata

# Create config store
fastly config-store create --name blossom_config
fastly config-store-entry create --store-id <id> --key b2_bucket --value your-bucket-name
fastly config-store-entry create --store-id <id> --key b2_region --value us-west-004

# Create secret store
fastly secret-store create --name blossom_secrets
fastly secret-store-entry create --store-id <id> --key b2_key_id --value your-key-id
fastly secret-store-entry create --store-id <id> --key b2_app_key --value your-app-key
```

### Local development

```bash
# Copy the example config and fill in your credentials
cp fastly.toml.example fastly.toml

# Edit fastly.toml with your B2 credentials (this file is gitignored)
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
| `DELETE` | `/<sha256>` | Required | Delete blob |
| `GET` | `/list/<pubkey>` | Optional | List user's blobs |

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
