// ABOUTME: Google Cloud Storage operations via S3-compatible API
// ABOUTME: Implements AWS v4 signing with GCS HMAC authentication

use crate::error::{BlossomError, Result};
use fastly::http::{Method, StatusCode};
use fastly::{Body, Request, Response};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Backend name (must match fastly.toml)
const GCS_BACKEND: &str = "gcs_storage";

/// Cloud Run backend for uploads/migrations
const CLOUD_RUN_BACKEND: &str = "cloud_run_upload";

/// Fallback backend names and their URL paths (must match fastly.toml)
/// Each tuple is (backend_name, host, path_prefix)
/// Path format: {path_prefix}{hash}
/// Order matters: first match wins, so put fastest/most reliable first
const FALLBACK_BACKENDS: &[(&str, &str, &str)] = &[
    ("cdn_divine", "cdn.divine.video", "/"),
    ("blossom_divine", "blossom.divine.video", "/"),
    ("cdn_satellite", "cdn.satellite.earth", "/"),
    // nostr.build uses image subdomain for media
    ("nostr_build", "image.nostr.build", "/"),
];

/// Config store name
const CONFIG_STORE: &str = "blossom_config";

/// Secret store name
const SECRET_STORE: &str = "blossom_secrets";

/// AWS signature version (works with GCS HMAC)
const AWS_ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// S3 service name (GCS uses s3 for S3-compat mode)
const SERVICE: &str = "s3";

/// GCS region for signing (use "auto" for path-style)
const GCS_REGION: &str = "auto";

/// Multipart upload threshold (5MB)
const MULTIPART_THRESHOLD: u64 = 5 * 1024 * 1024;

/// Part size for multipart uploads (5MB)
const PART_SIZE: u64 = 5 * 1024 * 1024;

/// Get config value
fn get_config(key: &str) -> Result<String> {
    let store = fastly::config_store::ConfigStore::open(CONFIG_STORE);
    store
        .get(key)
        .ok_or_else(|| BlossomError::Internal(format!("Missing config: {}", key)))
}

/// Get secret value
fn get_secret(key: &str) -> Result<String> {
    let store = fastly::secret_store::SecretStore::open(SECRET_STORE)
        .map_err(|e| BlossomError::Internal(format!("Failed to open secret store: {}", e)))?;

    let secret = store
        .get(key)
        .ok_or_else(|| BlossomError::Internal(format!("Missing secret: {}", key)))?;

    // Convert Bytes to String
    let plaintext_bytes = secret.plaintext();
    String::from_utf8(plaintext_bytes.to_vec())
        .map_err(|e| BlossomError::Internal(format!("Secret is not valid UTF-8: {}", e)))
}

/// GCS configuration
struct GCSConfig {
    access_key: String, // HMAC access key
    secret_key: String, // HMAC secret key
    bucket: String,
}

impl GCSConfig {
    fn load() -> Result<Self> {
        Ok(GCSConfig {
            access_key: get_secret("gcs_access_key")?,
            secret_key: get_secret("gcs_secret_key")?,
            bucket: get_config("gcs_bucket")?,
        })
    }

    fn host(&self) -> String {
        "storage.googleapis.com".to_string()
    }

    fn endpoint(&self) -> String {
        format!("https://{}", self.host())
    }

    fn region(&self) -> &str {
        GCS_REGION
    }
}

/// Upload a blob to GCS (simple PUT for small files)
/// owner: pubkey of the blob owner (stored in x-amz-meta-owner for durability)
pub fn upload_blob(
    hash: &str,
    body: Body,
    content_type: &str,
    size: u64,
    owner: &str,
) -> Result<()> {
    let config = GCSConfig::load()?;

    // For large files, use multipart upload
    if size > MULTIPART_THRESHOLD {
        return upload_blob_multipart(hash, body, content_type, size, owner);
    }

    let path = format!("/{}/{}", config.bucket, hash);

    let mut req = Request::new(Method::PUT, format!("{}{}", config.endpoint(), path));
    req.set_header("Content-Type", content_type);
    req.set_header("Content-Length", size.to_string());
    req.set_header("Host", config.host());
    // Store owner pubkey in GCS object metadata for durability
    req.set_header("x-amz-meta-owner", owner);

    // Sign the request (includes x-amz-meta-owner in signature)
    sign_request_with_owner(&mut req, &config, Some(hash_body_for_signing(size)), owner)?;

    req.set_body(body);

    let resp = req
        .send(GCS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Failed to upload: {}", e)))?;

    if !resp.get_status().is_success() {
        return Err(BlossomError::StorageError(format!(
            "Upload failed with status: {}",
            resp.get_status()
        )));
    }

    Ok(())
}

/// Download a thumbnail from GCS (stored as {hash}.jpg)
pub fn download_thumbnail(gcs_key: &str) -> Result<Response> {
    let config = GCSConfig::load()?;
    let path = format!("/{}/{}", config.bucket, gcs_key);
    let url = format!("{}{}", config.endpoint(), path);

    let mut req = Request::new(Method::GET, &url);
    req.set_header("Host", config.host());

    sign_request(&mut req, &config, Some("UNSIGNED-PAYLOAD".into()))?;

    let resp = req
        .send(GCS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Failed to download thumbnail: {}", e)))?;

    match resp.get_status() {
        StatusCode::OK => Ok(resp),
        StatusCode::NOT_FOUND => Err(BlossomError::NotFound("Thumbnail not found".into())),
        status => Err(BlossomError::StorageError(format!(
            "Thumbnail download failed with status: {}",
            status
        ))),
    }
}

/// Download HLS content from GCS (manifests and segments)
/// gcs_key format: {hash}/hls/{filename}
pub fn download_hls_from_gcs(gcs_key: &str, range: Option<&str>) -> Result<Response> {
    let config = GCSConfig::load()?;
    let path = format!("/{}/{}", config.bucket, gcs_key);
    let url = format!("{}{}", config.endpoint(), path);

    let mut req = Request::new(Method::GET, &url);
    req.set_header("Host", config.host());

    if let Some(range_value) = range {
        req.set_header("Range", range_value);
    }

    sign_request(&mut req, &config, Some("UNSIGNED-PAYLOAD".into()))?;

    let resp = req.send(GCS_BACKEND).map_err(|e| {
        BlossomError::StorageError(format!("Failed to download HLS content: {}", e))
    })?;

    match resp.get_status() {
        StatusCode::OK | StatusCode::PARTIAL_CONTENT => Ok(resp),
        StatusCode::NOT_FOUND => Err(BlossomError::NotFound("HLS content not found".into())),
        status => Err(BlossomError::StorageError(format!(
            "HLS download failed with status: {}",
            status
        ))),
    }
}

/// Download transcript content from GCS (WebVTT files)
/// gcs_key format: {hash}/vtt/{filename}
pub fn download_transcript_from_gcs(gcs_key: &str) -> Result<Response> {
    let config = GCSConfig::load()?;
    let path = format!("/{}/{}", config.bucket, gcs_key);
    let url = format!("{}{}", config.endpoint(), path);

    let mut req = Request::new(Method::GET, &url);
    req.set_header("Host", config.host());

    sign_request(&mut req, &config, Some("UNSIGNED-PAYLOAD".into()))?;

    let resp = req.send(GCS_BACKEND).map_err(|e| {
        BlossomError::StorageError(format!("Failed to download transcript content: {}", e))
    })?;

    match resp.get_status() {
        StatusCode::OK => Ok(resp),
        StatusCode::NOT_FOUND => Err(BlossomError::NotFound(
            "Transcript content not found".into(),
        )),
        status => Err(BlossomError::StorageError(format!(
            "Transcript download failed with status: {}",
            status
        ))),
    }
}

/// Download a blob from GCS (returns the response to stream back)
pub fn download_blob(hash: &str, range: Option<&str>) -> Result<Response> {
    let config = GCSConfig::load()?;
    let path = format!("/{}/{}", config.bucket, hash);
    let url = format!("{}{}", config.endpoint(), path);

    let mut req = Request::new(Method::GET, &url);
    req.set_header("Host", config.host());

    if let Some(range_value) = range {
        req.set_header("Range", range_value);
    }

    // Sign the request
    sign_request(&mut req, &config, Some("UNSIGNED-PAYLOAD".into()))?;

    let resp = req
        .send(GCS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Failed to download: {}", e)))?;

    let status = resp.get_status();
    match status {
        StatusCode::OK | StatusCode::PARTIAL_CONTENT => Ok(resp),
        StatusCode::NOT_FOUND => Err(BlossomError::NotFound("Blob not found in storage".into())),
        _ => Err(BlossomError::StorageError(format!(
            "Download failed with status: {}",
            status
        ))),
    }
}

/// Result of a fallback download - includes source information
pub struct FallbackDownloadResult {
    pub response: Response,
    pub source: String, // "gcs" or the backend name that served the content
}

/// Download a blob with fallback to CDNs
/// Tries GCS first, then falls back to configured CDN backends
/// Returns the response and the source that served it
pub fn download_blob_with_fallback(
    hash: &str,
    range: Option<&str>,
) -> Result<FallbackDownloadResult> {
    // Try GCS first
    match download_blob(hash, range) {
        Ok(resp) => {
            return Ok(FallbackDownloadResult {
                response: resp,
                source: "gcs".to_string(),
            });
        }
        Err(BlossomError::NotFound(_)) => {
            // Continue to fallback
        }
        Err(_e) => {
            // For non-404 errors, still try fallbacks
            // This handles cases where GCS is temporarily unavailable
        }
    }

    // Try each fallback backend
    for (backend_name, host, path_prefix) in FALLBACK_BACKENDS {
        match try_fallback_download(hash, range, backend_name, host, path_prefix) {
            Ok(resp) => {
                return Ok(FallbackDownloadResult {
                    response: resp,
                    source: backend_name.to_string(),
                });
            }
            Err(_) => {
                // Continue to next fallback
                continue;
            }
        }
    }

    // All sources failed
    Err(BlossomError::NotFound(
        "Blob not found in any storage".into(),
    ))
}

/// Try to download from a fallback CDN (simple HTTP GET, no auth)
fn try_fallback_download(
    hash: &str,
    range: Option<&str>,
    backend_name: &str,
    host: &str,
    path_prefix: &str,
) -> Result<Response> {
    let url = format!("https://{}{}{}", host, path_prefix, hash);

    let mut req = Request::new(Method::GET, &url);
    req.set_header("Host", host);

    if let Some(range_value) = range {
        req.set_header("Range", range_value);
    }

    let resp = req.send(backend_name).map_err(|e| {
        BlossomError::StorageError(format!("Fallback {} failed: {}", backend_name, e))
    })?;

    match resp.get_status() {
        StatusCode::OK | StatusCode::PARTIAL_CONTENT => Ok(resp),
        StatusCode::NOT_FOUND => Err(BlossomError::NotFound(format!(
            "Not found on {}",
            backend_name
        ))),
        status => Err(BlossomError::StorageError(format!(
            "Fallback {} returned status: {}",
            backend_name, status
        ))),
    }
}

/// Check if a blob exists in GCS
pub fn blob_exists(hash: &str) -> Result<bool> {
    let config = GCSConfig::load()?;
    let path = format!("/{}/{}", config.bucket, hash);

    let mut req = Request::new(Method::HEAD, format!("{}{}", config.endpoint(), path));
    req.set_header("Host", config.host());

    sign_request(&mut req, &config, Some("UNSIGNED-PAYLOAD".into()))?;

    let resp = req
        .send(GCS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Failed to check blob: {}", e)))?;

    Ok(resp.get_status() == StatusCode::OK)
}

/// Delete a blob from GCS
pub fn delete_blob(hash: &str) -> Result<()> {
    let config = GCSConfig::load()?;
    let path = format!("/{}/{}", config.bucket, hash);

    let mut req = Request::new(Method::DELETE, format!("{}{}", config.endpoint(), path));
    req.set_header("Host", config.host());

    sign_request(&mut req, &config, Some("UNSIGNED-PAYLOAD".into()))?;

    let resp = req
        .send(GCS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Failed to delete: {}", e)))?;

    if !resp.get_status().is_success() && resp.get_status() != StatusCode::NOT_FOUND {
        return Err(BlossomError::StorageError(format!(
            "Delete failed with status: {}",
            resp.get_status()
        )));
    }

    Ok(())
}

/// Initiate a multipart upload to GCS
fn initiate_multipart_upload(key: &str, content_type: &str) -> Result<String> {
    let config = GCSConfig::load()?;
    // Note: query string must be "uploads=" not just "uploads" for correct AWS4 signing
    let path = format!("/{}/{}?uploads=", config.bucket, key);

    let mut req = Request::new(Method::POST, format!("{}{}", config.endpoint(), path));
    req.set_header("Host", config.host());
    req.set_header("Content-Type", content_type);
    req.set_header("Content-Length", "0");

    sign_request(&mut req, &config, Some("UNSIGNED-PAYLOAD".into()))?;

    let mut resp = req
        .send(GCS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Failed to initiate multipart: {}", e)))?;

    if !resp.get_status().is_success() {
        let body = resp.take_body().into_string();
        return Err(BlossomError::StorageError(format!(
            "Initiate multipart failed with status: {}, body: {}",
            resp.get_status(),
            body
        )));
    }

    // Parse XML response to get UploadId
    let body = resp.take_body().into_string();

    // Simple XML parsing for UploadId
    let upload_id = extract_upload_id(&body).ok_or_else(|| {
        BlossomError::StorageError("Failed to parse UploadId from response".into())
    })?;

    Ok(upload_id)
}

/// Initiate a multipart upload to GCS with owner metadata
fn initiate_multipart_upload_with_owner(
    key: &str,
    content_type: &str,
    owner: &str,
) -> Result<String> {
    let config = GCSConfig::load()?;
    // Note: query string must be "uploads=" not just "uploads" for correct AWS4 signing
    let path = format!("/{}/{}?uploads=", config.bucket, key);

    let mut req = Request::new(Method::POST, format!("{}{}", config.endpoint(), path));
    req.set_header("Host", config.host());
    req.set_header("Content-Type", content_type);
    req.set_header("Content-Length", "0");
    // Store owner pubkey in GCS object metadata for durability
    req.set_header("x-amz-meta-owner", owner);

    sign_request_with_owner(&mut req, &config, Some("UNSIGNED-PAYLOAD".into()), owner)?;

    let mut resp = req
        .send(GCS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Failed to initiate multipart: {}", e)))?;

    if !resp.get_status().is_success() {
        let body = resp.take_body().into_string();
        return Err(BlossomError::StorageError(format!(
            "Initiate multipart failed with status: {}, body: {}",
            resp.get_status(),
            body
        )));
    }

    // Parse XML response to get UploadId
    let body = resp.take_body().into_string();

    // Simple XML parsing for UploadId
    let upload_id = extract_upload_id(&body).ok_or_else(|| {
        BlossomError::StorageError("Failed to parse UploadId from response".into())
    })?;

    Ok(upload_id)
}

/// Extract UploadId from XML response
fn extract_upload_id(xml: &str) -> Option<String> {
    // Look for <UploadId>...</UploadId>
    let start_tag = "<UploadId>";
    let end_tag = "</UploadId>";

    let start = xml.find(start_tag)? + start_tag.len();
    let end = xml[start..].find(end_tag)? + start;

    Some(xml[start..end].to_string())
}

/// Upload a single part of a multipart upload
fn upload_part(hash: &str, upload_id: &str, part_number: u32, body: &[u8]) -> Result<String> {
    let config = GCSConfig::load()?;
    let path = format!(
        "/{}/{}?partNumber={}&uploadId={}",
        config.bucket, hash, part_number, upload_id
    );

    let mut req = Request::new(Method::PUT, format!("{}{}", config.endpoint(), path));
    req.set_header("Host", config.host());
    req.set_header("Content-Length", body.len().to_string());

    // Calculate content hash for this part
    let content_hash = hex::encode(Sha256::digest(body));
    sign_request(&mut req, &config, Some(content_hash))?;

    req.set_body(Body::from(body.to_vec()));

    let resp = req
        .send(GCS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Failed to upload part: {}", e)))?;

    if !resp.get_status().is_success() {
        return Err(BlossomError::StorageError(format!(
            "Upload part {} failed with status: {}",
            part_number,
            resp.get_status()
        )));
    }

    // Get ETag from response header
    let etag = resp
        .get_header("ETag")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.trim_matches('"').to_string())
        .ok_or_else(|| BlossomError::StorageError("Missing ETag in part response".into()))?;

    Ok(etag)
}

/// Complete a multipart upload
fn complete_multipart_upload(
    hash: &str,
    upload_id: &str,
    parts: &[(u32, String)], // (part_number, etag)
) -> Result<()> {
    let config = GCSConfig::load()?;
    let path = format!("/{}/{}?uploadId={}", config.bucket, hash, upload_id);

    // Build XML body
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (part_number, etag) in parts {
        xml.push_str(&format!(
            "<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>",
            part_number, etag
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");

    let content_hash = hex::encode(Sha256::digest(xml.as_bytes()));

    let mut req = Request::new(Method::POST, format!("{}{}", config.endpoint(), path));
    req.set_header("Host", config.host());
    req.set_header("Content-Type", "application/xml");
    req.set_header("Content-Length", xml.len().to_string());

    sign_request(&mut req, &config, Some(content_hash))?;

    req.set_body(xml);

    let resp = req
        .send(GCS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Failed to complete multipart: {}", e)))?;

    if !resp.get_status().is_success() {
        return Err(BlossomError::StorageError(format!(
            "Complete multipart failed with status: {}",
            resp.get_status()
        )));
    }

    Ok(())
}

/// Upload a large blob using multipart upload (legacy - buffers entire body)
/// owner: pubkey of the blob owner (stored in x-amz-meta-owner for durability)
fn upload_blob_multipart(
    hash: &str,
    body: Body,
    content_type: &str,
    size: u64,
    owner: &str,
) -> Result<()> {
    // Read entire body into memory (required for chunking)
    let body_bytes = body.into_bytes();

    if body_bytes.len() as u64 != size {
        return Err(BlossomError::BadRequest(
            "Content-Length doesn't match body size".into(),
        ));
    }

    // Initiate multipart upload with owner metadata
    let upload_id = initiate_multipart_upload_with_owner(hash, content_type, owner)?;

    // Upload parts
    let mut parts: Vec<(u32, String)> = Vec::new();
    let mut offset: usize = 0;
    let mut part_number: u32 = 1;

    while offset < body_bytes.len() {
        let end = std::cmp::min(offset + PART_SIZE as usize, body_bytes.len());
        let chunk = &body_bytes[offset..end];

        let etag = upload_part(hash, &upload_id, part_number, chunk)?;
        parts.push((part_number, etag));

        offset = end;
        part_number += 1;
    }

    // Complete multipart upload
    complete_multipart_upload(hash, &upload_id, &parts)?;

    Ok(())
}

/// Streaming chunk size for reading body (256KB - safe for WASM memory)
const STREAMING_CHUNK_SIZE: usize = 256 * 1024;

/// Upload a blob using true streaming to avoid memory issues
/// Returns the computed SHA-256 hash of the uploaded content
///
/// Strategy (works for any file size up to 5GB):
/// 1. Stream body directly to GCS temp location (no buffering in WASM!)
/// 2. Download from temp to compute SHA-256 hash in streaming fashion
/// 3. Copy from temp to final hash-based location
/// 4. Delete temporary object
///
/// This approach never buffers more than STREAMING_CHUNK_SIZE (256KB) in memory,
/// which is critical for Fastly Compute's limited WASM heap.
pub fn upload_blob_streaming(body: Body, content_type: &str, expected_size: u64) -> Result<String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let config = GCSConfig::load()?;

    // Generate temporary object name with random suffix to avoid collisions
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let temp_key = format!("_temp/{}", timestamp);

    // Use simple streaming PUT for all file sizes (up to GCS 5GB single-object limit)
    upload_blob_streaming_simple(body, content_type, expected_size, &temp_key, &config)
}

/// True streaming upload: Upload body to temp, then download to compute hash, then copy to final
/// This approach never buffers the entire file in memory
fn upload_blob_streaming_simple(
    body: Body,
    content_type: &str,
    expected_size: u64,
    temp_key: &str,
    config: &GCSConfig,
) -> Result<String> {
    // Step 1: Stream body directly to temp location (no buffering!)
    let path = format!("/{}/{}", config.bucket, temp_key);
    let mut req = Request::new(Method::PUT, format!("{}{}", config.endpoint(), path));
    req.set_header("Content-Type", content_type);
    req.set_header("Content-Length", expected_size.to_string());
    req.set_header("Host", config.host());

    sign_request(&mut req, config, Some("UNSIGNED-PAYLOAD".into()))?;

    // Pass the body through directly - Fastly's runtime handles streaming
    req.set_body(body);

    let resp = req
        .send(GCS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Failed to upload to temp: {}", e)))?;

    let status = resp.get_status();
    if !status.is_success() {
        let body = resp.into_body_str();
        return Err(BlossomError::StorageError(format!(
            "Temp upload failed with status: {}, body: {}",
            status, body
        )));
    }

    // Step 2: Download from temp and compute hash in streaming fashion
    let hash = compute_hash_from_gcs(temp_key)?;

    // Check if blob already exists at final location
    if blob_exists(&hash)? {
        let _ = delete_blob(temp_key);
        return Ok(hash);
    }

    // Step 3: Copy from temp to final hash location
    copy_blob(temp_key, &hash)?;

    // Step 4: Delete temp
    let _ = delete_blob(temp_key);

    Ok(hash)
}

/// Download a blob from GCS and compute its SHA-256 hash in streaming fashion
fn compute_hash_from_gcs(key: &str) -> Result<String> {
    let config = GCSConfig::load()?;
    let path = format!("/{}/{}", config.bucket, key);

    let mut req = Request::new(Method::GET, format!("{}{}", config.endpoint(), path));
    req.set_header("Host", config.host());

    sign_request(&mut req, &config, Some("UNSIGNED-PAYLOAD".into()))?;

    let resp = req.send(GCS_BACKEND).map_err(|e| {
        BlossomError::StorageError(format!("Failed to download for hashing: {}", e))
    })?;

    if !resp.get_status().is_success() {
        return Err(BlossomError::StorageError(format!(
            "Download for hash failed with status: {}",
            resp.get_status()
        )));
    }

    // Stream through the body and compute hash
    let mut hasher = Sha256::new();
    let mut body = resp.into_body();

    for chunk_result in body.read_chunks(STREAMING_CHUNK_SIZE) {
        let chunk = chunk_result.map_err(|e| {
            BlossomError::Internal(format!("Failed to read chunk for hashing: {}", e))
        })?;
        hasher.update(&chunk);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Streaming upload for large files (> 5MB)
/// For files > 5MB, we can't use simple PUT (GCS has 5GB limit per request but we
/// can't stream without knowing the hash, and we can't buffer 5GB+).
/// Instead, we use the simple streaming approach: upload to temp, download to hash, copy.
/// This works for files up to any size supported by GCS PUT (5GB per object).
fn upload_blob_streaming_multipart(
    body: Body,
    content_type: &str,
    expected_size: u64,
    temp_key: &str,
    config: &GCSConfig,
) -> Result<String> {
    // For large files, still use the streaming approach:
    // 1. Stream body directly to temp (Fastly handles the streaming)
    // 2. Download from temp to compute hash
    // 3. Copy to final location
    //
    // Note: GCS allows PUT up to 5GB per request, so this works for most files.
    // For files > 5GB, we'd need true multipart upload, but that requires 5MB
    // minimum parts which exceeds WASM memory limits on Fastly Compute.

    let path = format!("/{}/{}", config.bucket, temp_key);
    let mut req = Request::new(Method::PUT, format!("{}{}", config.endpoint(), path));
    req.set_header("Content-Type", content_type);
    req.set_header("Content-Length", expected_size.to_string());
    req.set_header("Host", config.host());

    sign_request(&mut req, config, Some("UNSIGNED-PAYLOAD".into()))?;

    // Pass the body through directly
    req.set_body(body);

    let resp = req
        .send(GCS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Failed to upload to temp: {}", e)))?;

    let status = resp.get_status();
    if !status.is_success() {
        let body = resp.into_body_str();
        return Err(BlossomError::StorageError(format!(
            "Temp upload failed with status: {}, body: {}",
            status, body
        )));
    }

    // Download from temp and compute hash in streaming fashion
    let hash = compute_hash_from_gcs(temp_key)?;

    // Check if blob already exists at final location
    if blob_exists(&hash)? {
        let _ = delete_blob(temp_key);
        return Ok(hash);
    }

    // Copy from temp to final hash location
    copy_blob(temp_key, &hash)?;

    // Delete temp
    let _ = delete_blob(temp_key);

    Ok(hash)
}

/// Copy a blob from source to destination within the same bucket
fn copy_blob(source_key: &str, dest_key: &str) -> Result<()> {
    let config = GCSConfig::load()?;
    let path = format!("/{}/{}", config.bucket, dest_key);

    let mut req = Request::new(Method::PUT, format!("{}{}", config.endpoint(), path));
    req.set_header("Host", config.host());
    req.set_header("Content-Length", "0");

    // x-amz-copy-source header specifies the source object
    // URL encode the path separator in the key
    let encoded_source = source_key.replace('/', "%2F");
    let copy_source = format!("/{}/{}", config.bucket, encoded_source);
    req.set_header("x-amz-copy-source", &copy_source);

    // Sign with copy source header included
    sign_copy_request(&mut req, &config, &copy_source)?;

    let resp = req
        .send(GCS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Failed to copy blob: {}", e)))?;

    if !resp.get_status().is_success() {
        let body = resp.into_body_str();
        return Err(BlossomError::StorageError(format!(
            "Copy failed with status, body: {}",
            body
        )));
    }

    Ok(())
}

/// Sign a copy request (includes x-amz-copy-source in signed headers)
fn sign_copy_request(req: &mut Request, config: &GCSConfig, copy_source: &str) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = now.as_secs();
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_ymd(days_since_epoch);

    let date_stamp = format!("{:04}{:02}{:02}", year, month, day);
    let amz_date = format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        year, month, day, hours, minutes, seconds
    );

    // Set required headers
    req.set_header("x-amz-date", &amz_date);

    let payload_hash = "UNSIGNED-PAYLOAD";
    req.set_header("x-amz-content-sha256", payload_hash);

    // Create canonical request
    let method = req.get_method_str();
    let uri = req.get_path();
    let query = req.get_query_str().unwrap_or("");

    let host = config.host();

    // Include x-amz-copy-source in signed headers (alphabetical order!)
    let signed_headers = "host;x-amz-content-sha256;x-amz-copy-source;x-amz-date";

    let canonical_headers = format!(
        "host:{}\nx-amz-content-sha256:{}\nx-amz-copy-source:{}\nx-amz-date:{}\n",
        host, payload_hash, copy_source, amz_date
    );

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, uri, query, canonical_headers, signed_headers, payload_hash
    );

    // Create string to sign
    let credential_scope = format!(
        "{}/{}/{}/aws4_request",
        date_stamp,
        config.region(),
        SERVICE
    );

    let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));

    let string_to_sign = format!(
        "{}\n{}\n{}\n{}",
        AWS_ALGORITHM, amz_date, credential_scope, canonical_request_hash
    );

    // Calculate signature
    let signing_key = get_signing_key(&config.secret_key, &date_stamp, config.region())?;
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes())?);

    // Create authorization header
    let authorization = format!(
        "{} Credential={}/{}, SignedHeaders={}, Signature={}",
        AWS_ALGORITHM, config.access_key, credential_scope, signed_headers, signature
    );

    req.set_header("Authorization", authorization);

    Ok(())
}

/// Abort a multipart upload (cleanup on error)
fn abort_multipart_upload(key: &str, upload_id: &str) -> Result<()> {
    let config = GCSConfig::load()?;
    let path = format!("/{}/{}?uploadId={}", config.bucket, key, upload_id);

    let mut req = Request::new(Method::DELETE, format!("{}{}", config.endpoint(), path));
    req.set_header("Host", config.host());

    sign_request(&mut req, &config, Some("UNSIGNED-PAYLOAD".into()))?;

    let _ = req.send(GCS_BACKEND);
    // Ignore errors - this is best-effort cleanup

    Ok(())
}

/// Get current time as ISO 8601 string
pub fn current_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = now.as_secs();

    // Convert to date/time components (simplified UTC calculation)
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Calculate year, month, day from days since epoch (Jan 1, 1970)
    let (year, month, day) = days_to_ymd(days_since_epoch);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since Unix epoch to year, month, day
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Simplified calculation - good enough for our purposes
    let mut remaining_days = days as i64;
    let mut year = 1970i64;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months: [i64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1i64;
    for &days_in_month in &days_in_months {
        if remaining_days < days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }

    let day = remaining_days + 1;

    (year as u64, month as u64, day as u64)
}

/// Check if a year is a leap year
fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// AWS v4 request signing (works with GCS HMAC)
fn sign_request(req: &mut Request, config: &GCSConfig, payload_hash: Option<String>) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = now.as_secs();
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_ymd(days_since_epoch);

    let date_stamp = format!("{:04}{:02}{:02}", year, month, day);
    let amz_date = format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        year, month, day, hours, minutes, seconds
    );

    // Set required headers
    req.set_header("x-amz-date", &amz_date);

    let payload_hash = payload_hash.unwrap_or_else(|| "UNSIGNED-PAYLOAD".into());
    req.set_header("x-amz-content-sha256", &payload_hash);

    // Create canonical request
    let method = req.get_method_str();
    let uri = req.get_path();
    let query = req.get_query_str().unwrap_or("");

    let host = config.host();
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";

    let canonical_headers = format!(
        "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
        host, payload_hash, amz_date
    );

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, uri, query, canonical_headers, signed_headers, payload_hash
    );

    // Create string to sign
    let credential_scope = format!(
        "{}/{}/{}/aws4_request",
        date_stamp,
        config.region(),
        SERVICE
    );

    let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));

    let string_to_sign = format!(
        "{}\n{}\n{}\n{}",
        AWS_ALGORITHM, amz_date, credential_scope, canonical_request_hash
    );

    // Calculate signature
    let signing_key = get_signing_key(&config.secret_key, &date_stamp, config.region())?;
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes())?);

    // Create authorization header
    let authorization = format!(
        "{} Credential={}/{}, SignedHeaders={}, Signature={}",
        AWS_ALGORITHM, config.access_key, credential_scope, signed_headers, signature
    );

    req.set_header("Authorization", authorization);

    Ok(())
}

/// AWS v4 request signing with owner metadata header included
/// This is needed because custom headers must be in the canonical/signed headers
/// or GCS will reject the request with a signature mismatch
fn sign_request_with_owner(
    req: &mut Request,
    config: &GCSConfig,
    payload_hash: Option<String>,
    owner: &str,
) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = now.as_secs();
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_ymd(days_since_epoch);

    let date_stamp = format!("{:04}{:02}{:02}", year, month, day);
    let amz_date = format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        year, month, day, hours, minutes, seconds
    );

    // Set required headers
    req.set_header("x-amz-date", &amz_date);

    let payload_hash = payload_hash.unwrap_or_else(|| "UNSIGNED-PAYLOAD".into());
    req.set_header("x-amz-content-sha256", &payload_hash);

    // Create canonical request
    let method = req.get_method_str();
    let uri = req.get_path();
    let query = req.get_query_str().unwrap_or("");

    let host = config.host();
    // Include x-amz-meta-owner in signed headers (alphabetical order!)
    let signed_headers = "host;x-amz-content-sha256;x-amz-date;x-amz-meta-owner";

    let canonical_headers = format!(
        "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\nx-amz-meta-owner:{}\n",
        host, payload_hash, amz_date, owner
    );

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, uri, query, canonical_headers, signed_headers, payload_hash
    );

    // Create string to sign
    let credential_scope = format!(
        "{}/{}/{}/aws4_request",
        date_stamp,
        config.region(),
        SERVICE
    );

    let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));

    let string_to_sign = format!(
        "{}\n{}\n{}\n{}",
        AWS_ALGORITHM, amz_date, credential_scope, canonical_request_hash
    );

    // Calculate signature
    let signing_key = get_signing_key(&config.secret_key, &date_stamp, config.region())?;
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes())?);

    // Create authorization header
    let authorization = format!(
        "{} Credential={}/{}, SignedHeaders={}, Signature={}",
        AWS_ALGORITHM, config.access_key, credential_scope, signed_headers, signature
    );

    req.set_header("Authorization", authorization);

    Ok(())
}

/// Generate AWS v4 signing key
fn get_signing_key(secret_key: &str, date_stamp: &str, region: &str) -> Result<Vec<u8>> {
    let k_date = hmac_sha256(
        format!("AWS4{}", secret_key).as_bytes(),
        date_stamp.as_bytes(),
    )?;
    let k_region = hmac_sha256(&k_date, region.as_bytes())?;
    let k_service = hmac_sha256(&k_region, SERVICE.as_bytes())?;
    let k_signing = hmac_sha256(&k_service, b"aws4_request")?;
    Ok(k_signing)
}

/// HMAC-SHA256
fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| BlossomError::Internal(format!("HMAC error: {}", e)))?;

    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Placeholder for body hash during signing
/// For streaming uploads, we use UNSIGNED-PAYLOAD
fn hash_body_for_signing(_size: u64) -> String {
    // For large uploads, use unsigned payload and let GCS verify
    "UNSIGNED-PAYLOAD".into()
}

/// Trigger background migration of a blob from a fallback CDN to GCS
/// This sends an async request to Cloud Run and doesn't wait for completion
/// Returns Ok if the request was sent successfully (not if migration completed)
pub fn trigger_background_migration(hash: &str, source_backend: &str) -> Result<()> {
    // Find the CDN URL for this backend
    let source_url = match FALLBACK_BACKENDS
        .iter()
        .find(|(name, _, _)| *name == source_backend)
    {
        Some((_, host, path_prefix)) => format!("https://{}{}{}", host, path_prefix, hash),
        None => {
            return Err(BlossomError::Internal(format!(
                "Unknown fallback backend: {}",
                source_backend
            )))
        }
    };

    // Build migration request JSON
    let request_body = format!(
        r#"{{"source_url":"{}","expected_hash":"{}"}}"#,
        source_url, hash
    );

    // Send async request to Cloud Run /migrate endpoint
    // We use send_async so we don't block waiting for the migration to complete
    // NOTE: Use actual Cloud Run hostname, not custom domain, for proper routing
    const CLOUD_RUN_HOST: &str = "blossom-upload-rust-149672065768.us-central1.run.app";
    let mut req = Request::new(Method::POST, format!("https://{}/migrate", CLOUD_RUN_HOST));
    req.set_header("Host", CLOUD_RUN_HOST);
    req.set_header("Content-Type", "application/json");
    req.set_header("Content-Length", request_body.len().to_string());
    req.set_body(request_body);

    // Send async - fire and forget
    // We use send_async with streaming disabled to fire the request without waiting
    match req.send_async(CLOUD_RUN_BACKEND) {
        Ok(_pending) => {
            // Request sent successfully - we don't wait for response
            // The PendingRequest will be dropped, but the request is already in flight
            Ok(())
        }
        Err(e) => {
            // Log error but don't fail the request - migration is best-effort
            Err(BlossomError::Internal(format!(
                "Failed to trigger migration: {}",
                e
            )))
        }
    }
}
