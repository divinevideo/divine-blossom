# GCS Migration Design: Fastly Blossom

## Overview

Migrate Fastly Blossom from Backblaze B2 to Google Cloud Storage with content moderation (CSAM filtering) and video thumbnail extraction.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         UPLOAD FLOW                                  │
│                                                                      │
│  Client ──► Fastly Compute ──► GCS (HMAC S3-compat)                 │
│                   │                    │                             │
│                   └─► Fastly KV        │ Object Finalize             │
│                      (metadata)        ▼                             │
│                                  Cloud Function                      │
│                                       │                              │
│                          ┌────────────┼────────────┐                │
│                          ▼            ▼            ▼                │
│                    Vision API   Video Intel   Update KV             │
│                    (SafeSearch) (thumbnails)  (metadata)            │
│                          │            │                              │
│                          ▼            ▼                              │
│                    If flagged:   Upload to                          │
│                    DELETE blob   thumbnails/{sha256}                │
└─────────────────────────────────────────────────────────────────────┘
```

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| GCS Authentication | HMAC keys (S3-compat) | Reuses existing AWS v4 signing code, proven WASM-compatible |
| Async Processing | GCS Object Notification → Cloud Function | Serverless, auto-scales, no infrastructure to manage |
| Content Moderation | Allow immediately, remove if flagged | Better UX, accepted risk of brief exposure window |
| Large Files | Resumable uploads | High-quality 6-sec videos can be 20-50MB+ |
| Thumbnail Storage | `thumbnails/{sha256}` prefix | Avoids name collision with blobs |

## Component 1: Fastly Compute Storage (src/storage.rs)

### Configuration Changes

| Current (B2) | New (GCS) |
|--------------|-----------|
| Backend: `s3.{region}.backblazeb2.com` | Backend: `storage.googleapis.com` |
| Config: `b2_bucket`, `b2_region` | Config: `gcs_bucket`, `gcs_project` |
| Secret: `b2_key_id`, `b2_app_key` | Secret: `gcs_access_key`, `gcs_secret_key` |

### GCS HMAC Endpoints (S3-compatible)

GCS supports S3-compatible XML API with HMAC authentication:

| Operation | Endpoint |
|-----------|----------|
| Upload (simple) | `PUT /{bucket}/{sha256}` |
| Upload (resumable) | `POST /{bucket}/{sha256}?uploads` then `PUT ...?uploadId=X` |
| Download | `GET /{bucket}/{sha256}` |
| Check exists | `HEAD /{bucket}/{sha256}` |
| Delete | `DELETE /{bucket}/{sha256}` |

### Resumable Upload Protocol

For files >5MB, implement GCS resumable uploads:

```
1. Initiate: POST /{bucket}/{sha256}?uploads
   Response: <UploadId>xyz</UploadId>

2. Upload parts: PUT /{bucket}/{sha256}?uploadId=xyz&partNumber=1
   (repeat for each 5MB chunk)

3. Complete: POST /{bucket}/{sha256}?uploadId=xyz
   Body: <CompleteMultipartUpload>...</CompleteMultipartUpload>
```

### Code Changes Required

```rust
// src/storage.rs changes:

// 1. Update constants
const GCS_BACKEND: &str = "gcs_storage";
const GCS_HOST: &str = "storage.googleapis.com";

// 2. Update GCSConfig struct
struct GCSConfig {
    access_key: String,    // HMAC access key
    secret_key: String,    // HMAC secret key
    bucket: String,
    project: String,
}

// 3. Keep AWS v4 signing (works with GCS HMAC)
// - Change host() to return GCS_HOST
// - Change region to "auto" or specific GCS region

// 4. Add resumable upload for large files
fn upload_blob_resumable(hash: &str, body: Body, content_type: &str, size: u64) -> Result<()>
```

## Component 2: Cloud Function (Python)

### Trigger

GCS Object Finalize notification on blob bucket.

### Processing Logic

```python
def process_blob(event, context):
    bucket = event['bucket']
    blob_name = event['name']
    content_type = event['contentType']

    # Skip thumbnails
    if blob_name.startswith('thumbnails/'):
        return

    if content_type.startswith('image/'):
        result = check_image_safety(bucket, blob_name)
        if result.is_flagged:
            delete_blob(bucket, blob_name)
            update_metadata(blob_name, status='deleted', reason=result.reason)
        else:
            update_metadata(blob_name, status='active')

    elif content_type.startswith('video/'):
        # Extract thumbnail
        thumbnail = extract_video_thumbnail(bucket, blob_name)
        upload_thumbnail(bucket, f'thumbnails/{blob_name}', thumbnail)

        # Check safety on thumbnail
        result = check_image_safety(bucket, f'thumbnails/{blob_name}')
        if result.is_flagged:
            delete_blob(bucket, blob_name)
            delete_blob(bucket, f'thumbnails/{blob_name}')
            update_metadata(blob_name, status='deleted', reason=result.reason)
        else:
            update_metadata(blob_name, status='active', thumbnail=f'thumbnails/{blob_name}')
```

### Vision API SafeSearch

```python
from google.cloud import vision

def check_image_safety(bucket, blob_name):
    client = vision.ImageAnnotatorClient()
    image = vision.Image(source=vision.ImageSource(
        gcs_image_uri=f'gs://{bucket}/{blob_name}'
    ))

    response = client.safe_search_detection(image=image)
    safe = response.safe_search_annotation

    # Flag if LIKELY or VERY_LIKELY for adult/violence
    is_flagged = (
        safe.adult >= vision.Likelihood.LIKELY or
        safe.violence >= vision.Likelihood.LIKELY
    )

    return SafetyResult(is_flagged=is_flagged, scores=safe)
```

### Video Intelligence API (Thumbnail)

```python
from google.cloud import videointelligence

def extract_video_thumbnail(bucket, blob_name):
    client = videointelligence.VideoIntelligenceServiceClient()

    # Request frame at 1 second
    operation = client.annotate_video(
        input_uri=f'gs://{bucket}/{blob_name}',
        features=[videointelligence.Feature.SHOT_CHANGE_DETECTION],
    )

    # Get first frame as thumbnail
    # (Implementation depends on specific extraction method)
```

## Component 3: Fastly Configuration

### fastly.toml Updates

```toml
[setup.backends.gcs_storage]
address = "storage.googleapis.com"
port = 443

[setup.config_stores.blossom_config]
items = [
  { key = "gcs_bucket", value = "blossom-media" },
  { key = "gcs_project", value = "divine-blossom" },
]

[setup.secret_stores.blossom_secrets]
entries = [
  { key = "gcs_access_key", path = "..." },
  { key = "gcs_secret_key", path = "..." },
]
```

## Component 4: Metadata Updates

### BlobMetadata Changes

```rust
pub struct BlobMetadata {
    pub sha256: String,
    pub size: u64,
    pub mime_type: String,
    pub uploaded: String,
    pub owner: String,
    pub status: BlobStatus,
    pub thumbnail: Option<String>,  // NEW: path to thumbnail if video
    pub moderation: Option<ModerationResult>,  // NEW: safety check results
}

pub struct ModerationResult {
    pub checked_at: String,
    pub is_safe: bool,
    pub scores: Option<SafetyScores>,
}
```

## GCS Setup Requirements

### 1. Create GCS Bucket

```bash
gsutil mb -p PROJECT_ID -l us-central1 gs://blossom-media
```

### 2. Create HMAC Keys

```bash
gsutil hmac create SERVICE_ACCOUNT_EMAIL
# Returns: access_id and secret
```

### 3. Configure Object Notifications

```bash
gcloud functions deploy process-blob \
  --runtime python311 \
  --trigger-resource blossom-media \
  --trigger-event google.storage.object.finalize
```

### 4. Enable APIs

- Cloud Storage API
- Cloud Vision API
- Video Intelligence API
- Cloud Functions API

## Migration Plan

### Phase 1: Dual-Write (Week 1)
- Deploy GCS storage alongside B2
- Write to both, read from B2
- Verify GCS uploads work

### Phase 2: Cloud Function (Week 2)
- Deploy moderation Cloud Function
- Test with sample uploads
- Monitor false positive rate

### Phase 3: Switch Read (Week 3)
- Switch reads to GCS
- Keep B2 as fallback
- Monitor performance

### Phase 4: Cleanup (Week 4)
- Remove B2 code
- Migrate existing blobs if needed
- Full GCS operation

## Cost Estimates

| Service | Estimate (1000 uploads/month) |
|---------|------------------------------|
| GCS Storage | ~$0.02/GB/month |
| GCS Operations | ~$0.05/10k writes |
| Vision API | ~$1.50/1000 images |
| Video Intelligence | ~$0.10/min video |
| Cloud Functions | ~$0.40/million invocations |

**Note**: GCS egress to Fastly may incur costs ($0.12/GB) unlike B2's free egress.

## Security Considerations

1. **HMAC Keys**: Store in Fastly Secret Store, rotate regularly
2. **Service Account**: Minimal permissions (storage.objects.*)
3. **Cloud Function**: Runs with dedicated service account
4. **Content Policy**: Flagged content deleted, logged for review

## Open Questions

1. Should we keep B2 as backup storage?
2. Manual review workflow for edge cases?
3. Appeal process for false positives?
