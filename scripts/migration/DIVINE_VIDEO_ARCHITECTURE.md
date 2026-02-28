# Divine Video Media Architecture

Reference document for migration scripts and understanding the divine.video media system.

## Nostr Event Kinds

### Kind 34235 - Video Event
Standard video metadata event containing video information and media references.

### Kind 34236 - HLS Video Event
Video event with HLS (HTTP Live Streaming) variants. Contains multiple quality levels and segment information.

## Relays

| Relay | Purpose |
|-------|---------|
| `wss://relay.divine.video` | Primary relay for divine.video content |
| `wss://relay3.openvine.co` | Secondary/backup relay |

### Pagination
When fetching events from relays:
- Use `limit` parameter (max ~5000 per request)
- Paginate backwards using `until` parameter set to `oldest_timestamp - 1`
- Continue until fewer events than limit are returned

```python
filter_obj = {"kinds": [34235, 34236], "limit": 5000}
if until is not None:
    filter_obj["until"] = until
```

## imeta Tag Formats

Events use `imeta` tags to store media metadata. **Two formats exist:**

### Format 1: Space-Separated (Common)
Each entry is a single string with space-separated key-value:
```json
["imeta", "url https://cdn.divine.video/abc123", "m video/mp4", "x abc123...", "size 12345"]
```

### Format 2: Alternating Key-Value Pairs
Keys and values are separate array elements:
```json
["imeta", "url", "https://cdn.divine.video/abc123", "m", "video/mp4", "x", "abc123...", "size", "12345"]
```

### imeta Fields
| Field | Description |
|-------|-------------|
| `url` | Media URL (can have multiple per imeta) |
| `m` | MIME type |
| `x` | SHA-256 hash (hex, 64 chars) |
| `size` | File size in bytes |
| `dim` | Dimensions (e.g., "1920x1080") |
| `blurhash` | Blurhash placeholder |

### Parsing Example
```python
def parse_imeta_array(imeta_tag: list) -> dict:
    """Parse imeta tag array - handles BOTH formats."""
    result = {}
    urls = []
    entries = imeta_tag[1:]  # Skip "imeta" prefix

    if entries and " " in entries[0]:
        # Format 1: Space-separated
        for entry in entries:
            if isinstance(entry, str) and " " in entry:
                key, value = entry.split(" ", 1)
                if key == "url":
                    urls.append(value)
                else:
                    result[key] = value
    else:
        # Format 2: Alternating key-value pairs
        i = 0
        while i < len(entries) - 1:
            key = entries[i]
            value = entries[i + 1]
            if key == "url":
                urls.append(value)
            else:
                result[key] = value
            i += 2

    result["urls"] = urls
    if urls:
        result["url"] = urls[0]
    return result
```

## Old CDN Sources

Blobs may exist on multiple legacy servers:

| Server | Notes |
|--------|-------|
| `https://cdn.divine.video` | Primary old CDN |
| `https://stream.divine.video` | Streaming server |
| `https://blossom.divine.video` | Old blossom server |

### URL Patterns
- `/{sha256}` - Raw hash
- `/{sha256}.mp4` - With extension
- `/{sha256}.jpg` - Thumbnails

## Blossom Protocol Authentication

Many blobs are protected and require Nostr authentication.

### Auth Event (Kind 24242)
```python
from nostr_sdk import Keys, EventBuilder, Kind, Tag

def create_blossom_auth_header(sha256: str, server_url: str) -> str:
    keys = Keys.generate()  # Or use existing keys
    expiration = int(time.time()) + 300  # 5 minutes

    builder = EventBuilder(Kind(24242), "").tags([
        Tag.parse(["t", "get"]),      # Action: get, upload, delete, list
        Tag.parse(["x", sha256]),      # Blob hash
        Tag.parse(["expiration", str(expiration)]),
    ])

    event = builder.sign_with_keys(keys)
    event_json = event.as_json()
    return "Nostr " + base64.b64encode(event_json.encode()).decode()
```

### Auth Header Format
```
Authorization: Nostr <base64-encoded-event-json>
```

### Action Types
| Action | Tag Value | Use Case |
|--------|-----------|----------|
| Get/Download | `["t", "get"]` | Downloading protected blobs |
| Upload | `["t", "upload"]` | Uploading new blobs |
| Delete | `["t", "delete"]` | Deleting blobs |
| List | `["t", "list"]` | Listing user's blobs |

## New Storage: Google Cloud Storage

### Bucket
- **Production**: `divine-blossom-media`

### GCS Project
- Project ID: `rich-compiler-479518-d2`
- Display Name: `divine-video`

### HMAC Authentication
GCS uses S3-compatible HMAC authentication:

```python
GCS_ACCESS_KEY = "GOOG1..."  # HMAC access key
GCS_SECRET_KEY = "..."        # HMAC secret key
GCS_BUCKET = "divine-blossom-media-staging"
```

### GCS XML API Signing (HMAC v2 style)
```python
import hmac
import hashlib
import base64
from datetime import datetime, timezone

def gcs_sign_request(method: str, bucket: str, key: str,
                     content_type: str = "", content_md5: str = "") -> tuple[str, dict]:
    host = "storage.googleapis.com"
    date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

    string_to_sign = f"{method}\n{content_md5}\n{content_type}\n{date}\n/{bucket}/{key}"

    signature = base64.b64encode(
        hmac.new(GCS_SECRET_KEY.encode(), string_to_sign.encode(), hashlib.sha1).digest()
    ).decode()

    headers = {
        "Host": host,
        "Date": date,
        "Authorization": f"GOOG1 {GCS_ACCESS_KEY}:{signature}",
    }
    if content_type:
        headers["Content-Type"] = content_type

    url = f"https://{host}/{bucket}/{key}"
    return url, headers
```

### Direct GCS Access (Public)
```
https://storage.googleapis.com/{bucket}/{sha256}
```

## Blob Metadata Structure

### BlobMetadata (Rust/Fastly)
```rust
pub struct BlobMetadata {
    pub sha256: String,        // Hex-encoded SHA-256
    pub size: u64,             // Bytes
    pub mime_type: String,     // e.g., "video/mp4"
    pub uploaded: String,      // ISO 8601 timestamp
    pub owner: String,         // Nostr pubkey (hex)
    pub status: BlobStatus,    // active, restricted, pending
    pub thumbnail: Option<String>,  // Thumbnail hash
    pub moderation: Option<ModerationResult>,
}
```

### BlobStatus
- `active` - Public, accessible
- `restricted` - Shadow-banned, only owner can access
- `pending` - Awaiting moderation

### KV Store Key Prefixes

| Prefix | Format | Description |
|--------|--------|-------------|
| (none) | `<sha256>` | BlobMetadata JSON |
| `user:` | `user:<pubkey>` | JSON array of blob hashes owned by user |
| `auth:` | `auth:<sha256>:<action>` | Signed Nostr auth event (kind 24242) for provenance |
| `tombstone:` | `tombstone:<sha256>` | Legal hold marker preventing re-upload |
| `refs:` | `refs:<sha256>` | JSON array of all pubkeys who uploaded this content |

### Provenance Chain
- Every upload/delete stores the original signed Nostr auth event in KV under `auth:<hash>:<action>`
- First uploader becomes owner; re-uploaders added to refs list
- Audit logs sent to Cloud Logging via Cloud Run `/audit` endpoint
- Admin force-delete creates tombstones for legal holds and writes audit entries

## Video MIME Types
```
video/mp4
video/webm
video/ogg
video/quicktime
video/x-msvideo
video/x-matroska
```

## Migration Statistics (Dec 2024)

From `relay.divine.video`:
- **Total events**: 3,846
- **Unique blobs**: 4,181
- **Successfully migrated to GCS**: 4,136 (99%)
- **Not found on old servers**: 45

## New Blossom Server

- **URL**: `https://blossom.dvines.org`
- **Platform**: Fastly Compute@Edge
- **Backend**: GCS via S3-compatible API

### Fastly Service
- Service ID: `pOvEEWykEbpnylqst1KTrR`
- Config Store: `blossom_config`
- Secret Store: `blossom_secrets`

## Environment Variables

For migration scripts:
```bash
export GCS_ACCESS_KEY="GOOG1..."
export GCS_SECRET_KEY="..."
export GCS_BUCKET="divine-blossom-media-staging"
export NOSTR_NSEC=""  # Optional - auto-generates if not set
```

## Python Dependencies

```
aiohttp
websockets
nostr-sdk
requests
```

## Common Issues

### SignatureDoesNotMatch with boto3
boto3's S3 client doesn't work well with GCS HMAC. Use direct XML API signing instead.

### 401 Unauthorized on old CDN
Protected blobs require Blossom auth. Any valid Nostr keypair works - generate on the fly.

### Progress file with stale entries
Clear `migration_progress.json` before fresh runs to avoid skipping blobs that weren't actually migrated.

### Two imeta formats
Always check for both formats when parsing - some events use space-separated, others use alternating pairs.
