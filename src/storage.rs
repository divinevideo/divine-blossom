// ABOUTME: Object storage operations against S3-compatible origins (GCS and Fastly Object Storage)
// ABOUTME: Implements AWS v4 signing plus read-through delivery from the FOS mirror

use crate::error::{BlossomError, Result};
use blossom_core::cache_policy::{immutable_storage_cache_policy, ImmutableStorageCachePolicy};
use blossom_core::read_through::{
    check_mirror_response, object_path, parse_bool_flag, replica_delete_outcome,
    write_back_decision, ReplicaDeleteOutcome, MAX_WRITE_BACK_BYTES, SOURCE_FOS, SOURCE_GCS,
};
use fastly::http::{Method, StatusCode};
use fastly::{Body, Request, Response};
use hmac::{Hmac, Mac};
use md5::Md5;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Backend name (must match fastly.toml)
const GCS_BACKEND: &str = "gcs_storage";

/// Fastly Object Storage backend name (must exist on the service).
const FOS_BACKEND: &str = "fos_storage";

/// Cloud Run backend for uploads/migrations
const CLOUD_RUN_BACKEND: &str = "cloud_run_upload";
const CLOUD_RUN_HOST: &str = "blossom-upload-rust-149672065768.us-central1.run.app";

/// Legacy CDN runtime fallback is intentionally disabled.
///
/// If a migration miss is discovered, backfill the verified bytes into GCS
/// instead of reintroducing legacy hosts into the hot delivery path.
const FALLBACK_BACKENDS: &[(&str, &str, &str)] = &[];

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

/// GCS S3-compatible endpoint host
const GCS_HOST: &str = "storage.googleapis.com";

/// Fastly Object Storage endpoint host (override with config key `fos_host`)
const FOS_HOST: &str = "us-east.object.fastlystorage.app";

/// Fastly Object Storage region for signing (override with config key `fos_region`)
const FOS_REGION: &str = "us-east";

/// Fastly Object Storage delivery bucket (override with config key `fos_bucket`)
const FOS_BUCKET: &str = "divine-media-delivery";

/// Config keys for the two independent read-through feature flags.
const FOS_READ_FLAG: &str = "fos_read_enabled";
const FOS_WRITE_BACK_FLAG: &str = "fos_write_back_enabled";

/// Header copied from the storage subrequest before the outer VCL service
/// replaces `X-Cache` with its own cache result. This is intentionally only a
/// cache-state label (HIT/MISS), never a credential or storage identifier.
pub const STORAGE_CACHE_HEADER: &str = "X-Divine-Storage-Cache";

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

/// Check if running in local/e2e mode (stubs external services)
pub fn is_local_mode() -> bool {
    get_config("local_mode")
        .map(|v| v == "true")
        .unwrap_or(false)
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

/// Credentials and addressing for one S3-compatible origin.
///
/// Both GCS (via its S3-compat endpoint) and Fastly Object Storage speak
/// SigV4 path-style S3, so a single config type and a single signer serve
/// both; only the host, region, bucket, and credentials differ.
struct S3Config {
    access_key: String, // HMAC access key
    secret_key: String, // HMAC secret key
    bucket: String,
    host: String,
    region: String,
}

impl S3Config {
    fn load_gcs() -> Result<Self> {
        Ok(S3Config {
            access_key: get_secret("gcs_access_key")?,
            secret_key: get_secret("gcs_secret_key")?,
            bucket: get_config("gcs_bucket")?,
            host: GCS_HOST.to_string(),
            region: GCS_REGION.to_string(),
        })
    }

    /// Fastly Object Storage mirror. Host, region, and bucket may be
    /// overridden from the config store; the defaults match the provisioned
    /// delivery bucket.
    fn load_fos() -> Result<Self> {
        Ok(S3Config {
            access_key: get_secret("fos_access_key")?,
            secret_key: get_secret("fos_secret_key")?,
            bucket: get_config("fos_bucket").unwrap_or_else(|_| FOS_BUCKET.to_string()),
            host: get_config("fos_host").unwrap_or_else(|_| FOS_HOST.to_string()),
            region: get_config("fos_region").unwrap_or_else(|_| FOS_REGION.to_string()),
        })
    }

    fn host(&self) -> String {
        self.host.clone()
    }

    fn endpoint(&self) -> String {
        format!("https://{}", self.host())
    }

    fn region(&self) -> &str {
        &self.region
    }

    /// Path-style object path, shared byte for byte across origins.
    fn object_path(&self, key: &str) -> String {
        object_path(&self.bucket, key)
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
    let config = S3Config::load_gcs()?;

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
    let config = S3Config::load_gcs()?;
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
    let config = S3Config::load_gcs()?;
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
    let config = S3Config::load_gcs()?;
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
    let config = S3Config::load_gcs()?;
    let url = format!("{}{}", config.endpoint(), config.object_path(hash));

    let mut req = Request::new(Method::GET, &url);
    req.set_header("Host", config.host());

    if let Some(range_value) = range {
        req.set_header("Range", range_value);
    }

    // Sign the request
    sign_request(&mut req, &config, Some("UNSIGNED-PAYLOAD".into()))?;
    enable_immutable_storage_cache(&mut req, hash);

    let mut resp = req
        .send(GCS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Failed to download: {}", e)))?;
    preserve_storage_cache_state(&mut resp);

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
    pub diagnostics: Option<BlobFetchDiagnostics>,
}

/// Privacy-safe phase timings for one bare-blob origin fetch.
#[derive(Debug, Default)]
pub struct BlobFetchDiagnostics {
    pub fos_lookup_ms: Option<u128>,
    pub fos_outcome: Option<&'static str>,
    pub gcs_fetch_ms: Option<u128>,
    pub buffer_ms: Option<u128>,
    pub write_back_ms: Option<u128>,
    pub source: Option<&'static str>,
    pub storage_cache: Option<&'static str>,
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
                source: SOURCE_GCS.to_string(),
                diagnostics: None,
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
                    diagnostics: None,
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

// ---------------------------------------------------------------------------
// Fastly Object Storage read-through mirror
//
// FOS is a delivery cache in front of the authoritative GCS bucket. It is not
// allowed to break delivery, so reads and write-back remain infallible at
// their boundaries: `try_download_blob_from_fos` returns `Option` and
// `try_write_back_to_fos` returns nothing. Physical erasure is different:
// `delete_blob_from_fos` is deliberately fallible so a caller cannot report
// successful erasure while replica bytes may remain.
// ---------------------------------------------------------------------------

/// Read a feature flag from the config store. Absent or unparseable is off.
pub(crate) fn config_flag(key: &str) -> bool {
    let value = fastly::config_store::ConfigStore::try_open(CONFIG_STORE)
        .ok()
        .and_then(|store| store.try_get(key).ok().flatten());
    parse_bool_flag(value.as_deref())
}

/// Whether to look in the FOS mirror before falling back to GCS.
pub fn fos_read_enabled() -> bool {
    config_flag(FOS_READ_FLAG)
}

/// Whether to copy GCS-served objects into the FOS mirror.
pub fn fos_write_back_enabled() -> bool {
    config_flag(FOS_WRITE_BACK_FLAG)
}

/// Fallible FOS GET. Private: callers must go through `try_download_blob_from_fos`.
fn download_blob_from_fos(hash: &str, range: Option<&str>) -> Result<Response> {
    let config = S3Config::load_fos()?;
    let url = format!("{}{}", config.endpoint(), config.object_path(hash));

    let mut req = Request::new(Method::GET, &url);
    req.set_header("Host", config.host());

    if let Some(range_value) = range {
        req.set_header("Range", range_value);
    }

    sign_request(&mut req, &config, Some("UNSIGNED-PAYLOAD".into()))?;
    enable_immutable_storage_cache(&mut req, hash);

    let mut resp = req
        .send(FOS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("FOS request failed: {}", e)))?;
    preserve_storage_cache_state(&mut resp);

    let status = resp.get_status();
    match status {
        StatusCode::OK | StatusCode::PARTIAL_CONTENT => Ok(resp),
        _ => Err(BlossomError::NotFound(format!(
            "FOS returned status: {}",
            status
        ))),
    }
}

/// Configure Fastly's HTTP read-through cache for a storage GET.
///
/// The caller reaches this function only after the media route has evaluated
/// metadata access using a cryptographically validated NIP-98/BUD-01 event.
/// The cache key is the storage URL/host, not the viewer credential, so every
/// authorized request can reuse the same immutable bytes while authorization
/// is still rechecked on every outer request.
fn enable_immutable_storage_cache(req: &mut Request, hash: &str) {
    let surrogate_key = hash.to_ascii_lowercase();

    // Keep Range on the cache lookup so Fastly can synthesize a 206 from a
    // stored full object. On a miss, fetch the complete object so the response
    // is eligible for insertion instead of forwarding an uncacheable 206.
    req.set_before_send(|backend_req| {
        prepare_storage_cache_miss(backend_req);
        Ok(())
    });

    req.set_after_send(move |candidate| {
        match immutable_storage_cache_policy(candidate.get_status().as_u16()) {
            ImmutableStorageCachePolicy::Store {
                ttl_seconds,
                stale_while_revalidate_seconds,
            } => {
                candidate.set_cacheable();
                candidate.set_ttl(Duration::from_secs(ttl_seconds.into()));
                candidate.set_stale_while_revalidate(Duration::from_secs(
                    stale_while_revalidate_seconds.into(),
                ));
                candidate.set_surrogate_keys([surrogate_key.as_str()]);
            }
            ImmutableStorageCachePolicy::DoNotStore => {
                candidate.set_uncacheable(false);
            }
        }
        Ok(())
    });
}

fn prepare_storage_cache_miss(req: &mut Request) {
    req.remove_header("Range");
}

fn normalize_storage_cache_state(value: &str) -> Option<&'static str> {
    match value.rsplit(',').next().map(str::trim) {
        Some(value) if value.eq_ignore_ascii_case("HIT") => Some("HIT"),
        Some(value) if value.eq_ignore_ascii_case("MISS") => Some("MISS"),
        _ => None,
    }
}

fn preserve_storage_cache_state(resp: &mut Response) {
    // Read the last X-Cache value: the SDK comma-joins a single prior value but
    // appends a separate header line when two or more exist, and the Compute
    // cache result is always the final value.
    let cache_state = resp
        .get_header_all_str("X-Cache")
        .last()
        .copied()
        .and_then(normalize_storage_cache_state);
    if let Some(cache_state) = cache_state {
        resp.set_header(STORAGE_CACHE_HEADER, cache_state);
    } else {
        resp.remove_header(STORAGE_CACHE_HEADER);
    }
}

/// Try to serve a blob from the FOS mirror.
///
/// `None` means "not served from the mirror" for every possible reason:
/// missing credentials or backend, transport failure, timeout, 404, any other
/// non-success status, or a body whose declared length does not match the size
/// recorded for the hash. The caller falls back to GCS.
///
/// The length check exists because a `2xx` from the mirror is not by itself
/// evidence that the mirror holds the object: an S3-compatible origin can answer
/// a `Range` request for a missing key with an error document under `206`, and
/// the serving route stamps the stored MIME type over whatever body arrives.
fn try_download_blob_from_fos(
    hash: &str,
    range: Option<&str>,
    expected_size: Option<u64>,
) -> Option<Response> {
    let resp = match download_blob_from_fos(hash, range) {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("[FOS] miss hash={} reason={}", hash, e);
            return None;
        }
    };

    let status = resp.get_status().as_u16();
    let content_length = resp.get_content_length().map(|len| len as u64);
    let content_range = resp
        .get_header_str("Content-Range")
        .map(|value| value.to_string());

    let check = check_mirror_response(
        status,
        content_length,
        content_range.as_deref(),
        expected_size,
    );
    if !check.is_trusted() {
        eprintln!(
            "[FOS] miss hash={} reason=untrusted_response check={} status={}",
            hash,
            check.reason(),
            status
        );
        return None;
    }

    Some(resp)
}

/// A body read that stopped either at EOF or at the memory ceiling.
enum BufferedBody {
    /// The whole body fit under the ceiling.
    Complete(Vec<u8>),
    /// The ceiling was hit or the stream errored; these are the bytes read so
    /// far and the rest is still in `body`.
    Partial(Vec<u8>),
}

/// Read at most `limit` bytes of `body` into memory.
///
/// This is the hard memory bound. The `Content-Length` check in
/// `write_back_decision` is only an early filter; this loop is what guarantees
/// we never buffer more than the ceiling even if an origin declares a length
/// it does not honour.
fn buffer_body_up_to(body: &mut Body, limit: usize) -> BufferedBody {
    let mut buf: Vec<u8> = Vec::new();

    for chunk in body.read_chunks(STREAMING_CHUNK_SIZE) {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(_) => return BufferedBody::Partial(buf),
        };
        if buf.len() + chunk.len() > limit {
            buf.extend_from_slice(&chunk);
            return BufferedBody::Partial(buf);
        }
        buf.extend_from_slice(&chunk);
    }

    BufferedBody::Complete(buf)
}

/// Fallible FOS PUT. Private: callers must go through `try_write_back_to_fos`.
fn upload_blob_to_fos(
    hash: &str,
    bytes: &[u8],
    content_type: &str,
    payload_hash: &str,
) -> Result<()> {
    let config = S3Config::load_fos()?;
    let url = format!("{}{}", config.endpoint(), config.object_path(hash));

    let mut req = Request::new(Method::PUT, &url);
    req.set_header("Host", config.host());
    req.set_header("Content-Type", content_type);
    req.set_header("Content-Length", bytes.len().to_string());

    // The object key is the SHA-256 of the content, so the digest computed by
    // the caller is also the correct SigV4 payload hash.
    sign_request(&mut req, &config, Some(payload_hash.to_string()))?;
    req.set_body(Body::from(bytes.to_vec()));

    let resp = req
        .send(FOS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("FOS upload failed: {}", e)))?;

    let status = resp.get_status();
    if !status.is_success() {
        return Err(BlossomError::StorageError(format!(
            "FOS upload returned status: {}",
            status
        )));
    }

    Ok(())
}

/// Copy an object into the FOS mirror. Failures are logged and discarded.
fn try_write_back_to_fos(hash: &str, bytes: &[u8], content_type: &str) {
    // Never mirror bytes that do not match the content address they would be
    // stored under.
    let digest = hex::encode(Sha256::digest(bytes));
    if digest != hash.to_ascii_lowercase() {
        eprintln!(
            "[FOS] write-back skipped hash={} reason=digest_mismatch actual={}",
            hash, digest
        );
        return;
    }

    match upload_blob_to_fos(hash, bytes, content_type, &digest) {
        Ok(()) => eprintln!("[FOS] write-back ok hash={} bytes={}", hash, bytes.len()),
        Err(e) => eprintln!("[FOS] write-back failed hash={} reason={}", hash, e),
    }
}

/// Download a blob, preferring the FOS mirror, and lazily populate the mirror.
///
/// Behaviour is identical to `download_blob_with_fallback` when both flags are
/// off, and identical in every FOS failure mode.
pub fn download_blob_read_through(
    hash: &str,
    range: Option<&str>,
    expected_size: Option<u64>,
) -> Result<FallbackDownloadResult> {
    let mut diagnostics = BlobFetchDiagnostics::default();
    if fos_read_enabled() {
        let started = Instant::now();
        if let Some(response) = try_download_blob_from_fos(hash, range, expected_size) {
            diagnostics.fos_lookup_ms = Some(started.elapsed().as_millis());
            diagnostics.fos_outcome = Some("hit");
            diagnostics.source = Some(SOURCE_FOS);
            diagnostics.storage_cache = response
                .get_header_str(STORAGE_CACHE_HEADER)
                .and_then(normalize_storage_cache_state);
            return Ok(FallbackDownloadResult {
                response,
                source: SOURCE_FOS.to_string(),
                diagnostics: Some(diagnostics),
            });
        }
        diagnostics.fos_lookup_ms = Some(started.elapsed().as_millis());
        diagnostics.fos_outcome = Some("miss");
    } else {
        diagnostics.fos_outcome = Some("disabled");
    }

    let started = Instant::now();
    let result = download_blob_with_fallback(hash, range)?;
    if result.source == SOURCE_GCS {
        diagnostics.gcs_fetch_ms = Some(started.elapsed().as_millis());
        diagnostics.source = Some(SOURCE_GCS);
    } else {
        diagnostics.source = Some("fallback");
    }
    diagnostics.storage_cache = result
        .response
        .get_header_str(STORAGE_CACHE_HEADER)
        .and_then(normalize_storage_cache_state);
    Ok(write_back_if_eligible(hash, range, result, diagnostics))
}

/// Mirror a GCS-served body into FOS when it is safe to buffer it.
///
/// The returned result always carries the same bytes, status, and headers as
/// the input; only the body's provenance (streamed vs. replayed from memory)
/// can differ.
fn write_back_if_eligible(
    hash: &str,
    range: Option<&str>,
    mut result: FallbackDownloadResult,
    mut diagnostics: BlobFetchDiagnostics,
) -> FallbackDownloadResult {
    let decision = write_back_decision(
        fos_write_back_enabled(),
        &result.source,
        result.response.get_status().as_u16(),
        range.is_some(),
        result.response.get_content_length().map(|len| len as u64),
        MAX_WRITE_BACK_BYTES,
    );

    if !decision.is_eligible() {
        result.diagnostics = Some(diagnostics);
        return result;
    }

    let content_type = result
        .response
        .get_header_str("Content-Type")
        .unwrap_or("application/octet-stream")
        .to_string();

    let mut body = result.response.take_body();
    let buffer_started = Instant::now();
    match buffer_body_up_to(&mut body, MAX_WRITE_BACK_BYTES as usize) {
        BufferedBody::Complete(bytes) => {
            diagnostics.buffer_ms = Some(buffer_started.elapsed().as_millis());
            let write_back_started = Instant::now();
            try_write_back_to_fos(hash, &bytes, &content_type);
            diagnostics.write_back_ms = Some(write_back_started.elapsed().as_millis());
            result.response.set_body(Body::from(bytes));
        }
        BufferedBody::Partial(bytes) => {
            diagnostics.buffer_ms = Some(buffer_started.elapsed().as_millis());
            // Larger than declared, or the stream faulted. Stitch the buffered
            // prefix back in front of the untouched remainder and skip the
            // write-back.
            eprintln!(
                "[FOS] write-back skipped hash={} reason=exceeded_ceiling",
                hash
            );
            let mut stitched = Body::from(bytes);
            stitched.append(body);
            result.response.set_body(stitched);
        }
    }

    result.diagnostics = Some(diagnostics);
    result
}

/// Check if a blob exists in GCS
pub fn blob_exists(hash: &str) -> Result<bool> {
    let config = S3Config::load_gcs()?;
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
    let config = S3Config::load_gcs()?;
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

fn build_fos_delete_request(key: &str, config: &S3Config) -> Result<Request> {
    let url = format!("{}{}", config.endpoint(), config.object_path(key));
    let mut req = Request::new(Method::DELETE, &url);
    req.set_header("Host", config.host());
    sign_request(&mut req, config, Some("UNSIGNED-PAYLOAD".into()))?;
    Ok(req)
}

/// Delete an object from the Fastly Object Storage delivery replica.
///
/// This operation is intentionally not gated by the mirror feature flags: the
/// historical bulk mirror may contain the object even when both flags are off.
pub fn delete_blob_from_fos(key: &str) -> Result<()> {
    let config = S3Config::load_fos()?;
    let req = build_fos_delete_request(key, &config)?;
    let resp = req
        .send(FOS_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("FOS delete failed: {}", e)))?;

    match replica_delete_outcome(resp.get_status().as_u16()) {
        ReplicaDeleteOutcome::Deleted | ReplicaDeleteOutcome::NotPresent => Ok(()),
        ReplicaDeleteOutcome::Failed => Err(BlossomError::StorageError(format!(
            "FOS delete failed with status: {}",
            resp.get_status()
        ))),
    }
}

const PROVIDER_MULTI_DELETE_LIMIT: usize = 1_000;
pub(crate) const CLOUD_RUN_DELETE_BATCH_LIMIT: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VanishDeleteTarget {
    GcsMain,
    FosMain,
}

#[derive(Debug)]
struct VanishDeleteBatch {
    stage: String,
    keys: Vec<String>,
    target: VanishDeleteTarget,
}

#[derive(Debug, Default, serde::Serialize)]
pub(crate) struct VanishStorageTimings {
    pub gcs_main_ms: u64,
    pub cloud_run_cleanup_ms: u64,
    pub fos_main_ms: u64,
    pub purge_vcl_ms: u64,
    pub purge_compute_ms: u64,
}

#[derive(Debug, Default)]
pub(crate) struct VanishStorageResult {
    pub failed_hashes: HashSet<String>,
    pub timings: VanishStorageTimings,
}

impl VanishStorageResult {
    pub(crate) fn replace_failures_after_retry(&mut self, retry: Self) {
        self.failed_hashes = retry.failed_hashes;
        self.timings.gcs_main_ms = self
            .timings
            .gcs_main_ms
            .saturating_add(retry.timings.gcs_main_ms);
        self.timings.cloud_run_cleanup_ms = self
            .timings
            .cloud_run_cleanup_ms
            .saturating_add(retry.timings.cloud_run_cleanup_ms);
        self.timings.fos_main_ms = self
            .timings
            .fos_main_ms
            .saturating_add(retry.timings.fos_main_ms);
        self.timings.purge_vcl_ms = self
            .timings
            .purge_vcl_ms
            .saturating_add(retry.timings.purge_vcl_ms);
        self.timings.purge_compute_ms = self
            .timings
            .purge_compute_ms
            .saturating_add(retry.timings.purge_compute_ms);
    }
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn multi_delete_body(keys: &[String]) -> String {
    let mut xml = String::from("<Delete>");
    for key in keys {
        xml.push_str("<Object><Key>");
        xml.push_str(&xml_escape(key));
        xml.push_str("</Key></Object>");
    }
    xml.push_str("<Quiet>false</Quiet></Delete>");
    xml
}

fn plan_vanish_delete_batches(hashes: &[String]) -> Vec<VanishDeleteBatch> {
    let mut batches = Vec::new();
    let targets = [
        (VanishDeleteTarget::GcsMain, "gcs_main", hashes.to_vec()),
        (VanishDeleteTarget::FosMain, "fos_main", hashes.to_vec()),
    ];

    for (target, stage, keys) in targets {
        for (index, keys) in keys.chunks(PROVIDER_MULTI_DELETE_LIMIT).enumerate() {
            batches.push(VanishDeleteBatch {
                stage: format!("{}:{}", stage, index),
                keys: keys.to_vec(),
                target,
            });
        }
    }
    batches
}

fn build_multi_delete_request(keys: &[String], config: &S3Config, stage: &str) -> Result<Request> {
    let body = multi_delete_body(keys);
    let payload_hash = hex::encode(Sha256::digest(body.as_bytes()));
    let path = format!("/{}?delete", config.bucket);
    let mut req = Request::new(Method::POST, format!("{}{}", config.endpoint(), path));
    req.set_header("Host", config.host());
    req.set_header("Content-Type", "application/xml");
    req.set_header("Content-Length", body.len().to_string());
    req.set_header("X-Divine-Vanish-Stage", stage);
    use base64::Engine as _;
    let checksum = Md5::digest(body.as_bytes());
    req.set_header(
        "Content-MD5",
        base64::engine::general_purpose::STANDARD.encode(checksum),
    );
    sign_request(&mut req, config, Some(payload_hash))?;
    req.set_body(body);
    Ok(req)
}

fn xml_section_blocks<'a>(xml: &'a str, section: &str) -> Vec<&'a str> {
    let mut blocks = Vec::new();
    let open = format!("<{}>", section);
    let close = format!("</{}>", section);
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let after_open = &rest[start + open.len()..];
        let Some(end) = after_open.find(&close) else {
            break;
        };
        blocks.push(&after_open[..end]);
        rest = &after_open[end + close.len()..];
    }
    blocks
}

fn xml_block_value<'a>(block: &'a str, element: &str) -> Option<&'a str> {
    let open = format!("<{}>", element);
    let close = format!("</{}>", element);
    let value = block.split_once(&open)?.1;
    Some(value.split_once(&close)?.0)
}

fn keys_in_xml_section(xml: &str, section: &str) -> HashSet<String> {
    xml_section_blocks(xml, section)
        .into_iter()
        .filter_map(|block| xml_block_value(block, "Key").map(str::to_string))
        .collect()
}

fn failed_multi_delete_keys(
    mut response: Response,
    requested: &[String],
    stage: &str,
) -> HashSet<String> {
    if !response.get_status().is_success() {
        return requested.iter().cloned().collect();
    }

    let body = response.take_body().into_string();
    let body_len = body.len();
    let deleted = keys_in_xml_section(&body, "Deleted");
    let already_absent: HashSet<String> = xml_section_blocks(&body, "Error")
        .into_iter()
        .filter(|block| {
            matches!(
                xml_block_value(block, "Code"),
                Some("NoSuchKey" | "NotFound" | "NoSuchObject")
            )
        })
        .filter_map(|block| xml_block_value(block, "Key").map(str::to_string))
        .collect();
    let failed = requested
        .iter()
        .filter(|key| !deleted.contains(*key) && !already_absent.contains(*key))
        .cloned()
        .collect::<HashSet<_>>();
    eprintln!(
        "[VANISH] multi-delete stage={} requested={} body_len={} deleted={} absent={} failed={}",
        stage,
        requested.len(),
        body_len,
        deleted.len(),
        already_absent.len(),
        failed.len()
    );
    failed
}

fn hash_for_vanish_key(key: &str) -> Option<String> {
    let hash = key.get(..64)?;
    if hash.chars().all(|character| character.is_ascii_hexdigit()) {
        Some(hash.to_lowercase())
    } else {
        None
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

fn mark_failed_keys(result: &mut VanishStorageResult, keys: &HashSet<String>) {
    result
        .failed_hashes
        .extend(keys.iter().filter_map(|key| hash_for_vanish_key(key)));
}

fn mark_failed_stage(
    result: &mut VanishStorageResult,
    stage_hashes: &HashMap<String, Vec<String>>,
    stage: &str,
    all_hashes: &[String],
) {
    if let Some(failed) = stage_hashes.get(stage) {
        result.failed_hashes.extend(failed.iter().cloned());
    } else {
        result.failed_hashes.extend(all_hashes.iter().cloned());
    }
}

fn purge_vanish_hashes(hashes: &[String], result: &mut VanishStorageResult) {
    if hashes.is_empty() {
        return;
    }

    let api_token = match get_secret("fastly_api_token") {
        Ok(token) if !token.is_empty() => token,
        _ => {
            eprintln!(
                "[VANISH] purge stage=setup error=missing_or_empty_token key_count={}",
                hashes.len()
            );
            result.failed_hashes.extend(hashes.iter().cloned());
            return;
        }
    };
    let services = [
        ("ML7R82HKfmTaqTpHExIDVN", "purge_vcl"),
        ("pOvEEWykEbpnylqst1KTrR", "purge_compute"),
    ];
    let mut pending = Vec::new();
    let mut stage_hashes = HashMap::<String, Vec<String>>::new();
    let mut stage_started = HashMap::<String, Instant>::new();

    for chunk in hashes.chunks(256) {
        for (service_id, stage) in services {
            let stage_id = format!("{}:{}", stage, stage_hashes.len());
            let mut req = Request::new(
                Method::POST,
                format!("https://api.fastly.com/service/{}/purge", service_id),
            );
            req.set_header("Host", "api.fastly.com");
            req.set_header("Fastly-Key", &api_token);
            req.set_header("Accept", "application/json");
            req.set_header("Surrogate-Key", chunk.join(" "));
            req.set_header("X-Divine-Vanish-Stage", &stage_id);
            stage_started.insert(stage_id.clone(), Instant::now());
            stage_hashes.insert(stage_id.clone(), chunk.to_vec());
            match req.send_async("fastly_api") {
                Ok(request) => pending.push(request),
                Err(error) => {
                    eprintln!(
                        "[VANISH] purge stage={} error=request_start:{} key_count={}",
                        stage_id,
                        error,
                        chunk.len()
                    );
                    result.failed_hashes.extend(chunk.iter().cloned());
                }
            }
        }
    }

    while !pending.is_empty() {
        let (response, remaining) = fastly::http::request::select(pending);
        pending = remaining;
        match response {
            Ok(response) => {
                let stage = response
                    .get_backend_request()
                    .and_then(|request| request.get_header_str("X-Divine-Vanish-Stage"))
                    .unwrap_or_default()
                    .to_string();
                if let Some(started) = stage_started.get(&stage) {
                    let duration = elapsed_ms(*started);
                    if stage.starts_with("purge_vcl") {
                        result.timings.purge_vcl_ms = result.timings.purge_vcl_ms.max(duration);
                    } else if stage.starts_with("purge_compute") {
                        result.timings.purge_compute_ms =
                            result.timings.purge_compute_ms.max(duration);
                    }
                }
                if !response.get_status().is_success() {
                    eprintln!(
                        "[VANISH] purge stage={} status={} key_count={}",
                        stage,
                        response.get_status().as_u16(),
                        stage_hashes.get(&stage).map_or(hashes.len(), Vec::len)
                    );
                    mark_failed_stage(result, &stage_hashes, &stage, hashes);
                }
            }
            Err(error) => {
                let transport_error = error.to_string();
                let request = error.into_sent_req();
                let stage = request
                    .get_header_str("X-Divine-Vanish-Stage")
                    .unwrap_or_default()
                    .to_string();
                eprintln!(
                    "[VANISH] purge stage={} error={} key_count={}",
                    stage,
                    transport_error,
                    stage_hashes.get(&stage).map_or(hashes.len(), Vec::len)
                );
                mark_failed_stage(result, &stage_hashes, &stage, hashes);
            }
        }
    }
}

/// Erase one bounded vanish batch from both origins and both CDN services.
pub(crate) fn erase_vanish_batch(hashes: &[String]) -> VanishStorageResult {
    let mut result = VanishStorageResult::default();
    let mut main_origin_failures = HashSet::new();
    if hashes.is_empty() {
        return result;
    }

    let gcs = match S3Config::load_gcs() {
        Ok(config) => config,
        Err(_) => {
            result.failed_hashes.extend(hashes.iter().cloned());
            return result;
        }
    };
    let fos = match S3Config::load_fos() {
        Ok(config) => config,
        Err(_) => {
            result.failed_hashes.extend(hashes.iter().cloned());
            return result;
        }
    };
    let mut pending = Vec::new();
    let mut stage_started = HashMap::<String, Instant>::new();
    let mut requested_by_stage = HashMap::<String, Vec<String>>::new();

    for batch in plan_vanish_delete_batches(hashes) {
        let (config, backend) = match batch.target {
            VanishDeleteTarget::GcsMain => (&gcs, GCS_BACKEND),
            VanishDeleteTarget::FosMain => (&fos, FOS_BACKEND),
        };
        let stage = batch.stage;
        let keys = batch.keys;
        stage_started.insert(stage.clone(), Instant::now());
        requested_by_stage.insert(stage.clone(), keys.clone());
        match build_multi_delete_request(&keys, config, &stage).and_then(|request| {
            request.send_async(backend).map_err(|error| {
                BlossomError::StorageError(format!("{} batch delete failed: {}", stage, error))
            })
        }) {
            Ok(request) => pending.push(request),
            Err(_) => {
                let failed_keys: HashSet<String> = keys.into_iter().collect();
                mark_failed_keys(&mut result, &failed_keys);
                if stage.starts_with("gcs_main:") || stage.starts_with("fos_main:") {
                    main_origin_failures.extend(
                        failed_keys
                            .iter()
                            .filter_map(|key| hash_for_vanish_key(key)),
                    );
                }
            }
        }
    }

    while !pending.is_empty() {
        let (response, remaining) = fastly::http::request::select(pending);
        pending = remaining;
        match response {
            Ok(response) => {
                let stage = response
                    .get_backend_request()
                    .and_then(|request| request.get_header_str("X-Divine-Vanish-Stage"))
                    .unwrap_or_default()
                    .to_string();
                let status = response.get_status();
                if !status.is_success() {
                    let key_count = requested_by_stage
                        .get(&stage)
                        .map_or(hashes.len(), Vec::len);
                    eprintln!(
                        "[VANISH] multi-delete stage={} status={} key_count={}",
                        stage,
                        status.as_u16(),
                        key_count
                    );
                }
                if let Some(started) = stage_started.get(stage.as_str()) {
                    let duration = elapsed_ms(*started);
                    match stage.as_str() {
                        stage if stage.starts_with("gcs_main:") => {
                            result.timings.gcs_main_ms = result.timings.gcs_main_ms.max(duration);
                        }
                        stage if stage.starts_with("fos_main:") => {
                            result.timings.fos_main_ms = result.timings.fos_main_ms.max(duration);
                        }
                        _ => {}
                    }
                }
                if let Some(requested) = requested_by_stage.get(&stage) {
                    let failed = failed_multi_delete_keys(response, requested, &stage);
                    mark_failed_keys(&mut result, &failed);
                    if stage.starts_with("gcs_main:") || stage.starts_with("fos_main:") {
                        main_origin_failures
                            .extend(failed.iter().filter_map(|key| hash_for_vanish_key(key)));
                    }
                } else {
                    eprintln!(
                        "[VANISH] multi-delete unmatched_stage={} expected_stages={:?}",
                        stage,
                        requested_by_stage.keys().collect::<Vec<_>>()
                    );
                    result.failed_hashes.extend(hashes.iter().cloned());
                    main_origin_failures.extend(hashes.iter().cloned());
                }
            }
            Err(error) => {
                let transport_error = error.to_string();
                let request = error.into_sent_req();
                let stage = request
                    .get_header_str("X-Divine-Vanish-Stage")
                    .unwrap_or_default();
                let key_count = requested_by_stage.get(stage).map_or(hashes.len(), Vec::len);
                eprintln!(
                    "[VANISH] multi-delete stage={} error={} key_count={}",
                    stage, transport_error, key_count
                );
                if let Some(requested) = requested_by_stage.get(stage) {
                    let failed: HashSet<String> = requested.iter().cloned().collect();
                    mark_failed_keys(&mut result, &failed);
                    if stage.starts_with("gcs_main:") || stage.starts_with("fos_main:") {
                        main_origin_failures
                            .extend(failed.iter().filter_map(|key| hash_for_vanish_key(key)));
                    }
                } else {
                    result.failed_hashes.extend(hashes.iter().cloned());
                    main_origin_failures.extend(hashes.iter().cloned());
                }
            }
        }
    }

    let cloud_cleanup_started = Instant::now();
    match trigger_cloud_run_delete_blobs(hashes) {
        Ok(failed) => result.failed_hashes.extend(failed),
        Err(_) => result.failed_hashes.extend(hashes.iter().cloned()),
    }
    result.timings.cloud_run_cleanup_ms = elapsed_ms(cloud_cleanup_started);

    let purgeable: Vec<String> = hashes
        .iter()
        .filter(|hash| !main_origin_failures.contains(*hash))
        .cloned()
        .collect();
    purge_vanish_hashes(&purgeable, &mut result);
    result
}

/// Initiate a multipart upload to GCS
fn initiate_multipart_upload(key: &str, content_type: &str) -> Result<String> {
    let config = S3Config::load_gcs()?;
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
    let config = S3Config::load_gcs()?;
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
    let config = S3Config::load_gcs()?;
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
    let config = S3Config::load_gcs()?;
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

    let config = S3Config::load_gcs()?;

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
    config: &S3Config,
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
    let config = S3Config::load_gcs()?;
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
    config: &S3Config,
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
    let config = S3Config::load_gcs()?;
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
fn sign_copy_request(req: &mut Request, config: &S3Config, copy_source: &str) -> Result<()> {
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
    let config = S3Config::load_gcs()?;
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
fn sign_request(req: &mut Request, config: &S3Config, payload_hash: Option<String>) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    sign_request_at(req, config, payload_hash, now)
}

fn canonical_query_string(query: Option<&str>) -> String {
    query
        .unwrap_or_default()
        .split('&')
        .filter(|parameter| !parameter.is_empty())
        .map(|parameter| {
            if parameter.contains('=') {
                parameter.to_string()
            } else {
                format!("{parameter}=")
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn sign_request_at(
    req: &mut Request,
    config: &S3Config,
    payload_hash: Option<String>,
    now: Duration,
) -> Result<()> {
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
    let query = canonical_query_string(req.get_query_str());

    let host = req
        .get_header_str("Host")
        .ok_or_else(|| BlossomError::Internal("signed request is missing its Host header".into()))?
        .to_string();
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
    config: &S3Config,
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

fn audit_log_entry(
    sha256: &str,
    action: &str,
    actor_pubkey: &str,
    timestamp: String,
    auth_event_json: Option<&str>,
    metadata_snapshot: Option<&str>,
    reason: Option<&str>,
) -> String {
    let mut entry = serde_json::Map::from_iter([
        ("action".into(), serde_json::Value::String(action.into())),
        ("sha256".into(), serde_json::Value::String(sha256.into())),
        (
            "actor_pubkey".into(),
            serde_json::Value::String(actor_pubkey.into()),
        ),
        (
            "timestamp".into(),
            serde_json::Value::String(timestamp),
        ),
    ]);
    if let Some(auth_event) = auth_event_json.and_then(|value| serde_json::from_str(value).ok()) {
        entry.insert("auth_event".into(), auth_event);
    }
    if let Some(metadata) = metadata_snapshot.and_then(|value| serde_json::from_str(value).ok()) {
        entry.insert("metadata_snapshot".into(), metadata);
    }
    if let Some(reason) = reason {
        entry.insert("reason".into(), serde_json::Value::String(reason.into()));
    }
    serde_json::Value::Object(entry).to_string()
}

/// Write an audit log entry via Cloud Run (which writes structured logs to Cloud Logging).
/// Fire-and-forget: failures are logged to stderr but never block the caller.
///
/// Cloud Run auto-ingests JSON stdout/stderr as structured logs into Cloud Logging,
/// so the audit endpoint just needs to print the JSON and return 200.
/// Cloud Logging provides: querying, retention policies, export to BigQuery, alerting.
pub fn write_audit_log(
    sha256: &str,
    action: &str,
    actor_pubkey: &str,
    auth_event_json: Option<&str>,
    metadata_snapshot: Option<&str>,
    reason: Option<&str>,
) {
    let entry = audit_log_entry(
        sha256,
        action,
        actor_pubkey,
        current_timestamp(),
        auth_event_json,
        metadata_snapshot,
        reason,
    );

    // Fire-and-forget POST to Cloud Run /audit endpoint
    // Cloud Run prints structured JSON → auto-ingested by Cloud Logging
    let mut req = Request::new(Method::POST, format!("https://{}/audit", CLOUD_RUN_HOST));
    req.set_header("Host", CLOUD_RUN_HOST);
    req.set_header("Content-Type", "application/json");
    req.set_body(Body::from(entry));

    match req.send_async(CLOUD_RUN_BACKEND) {
        Ok(_) => {
            eprintln!(
                "[AUDIT] {} sha256={} actor={}",
                action, sha256, actor_pubkey
            );
        }
        Err(e) => {
            eprintln!("[AUDIT] Failed to send audit log: {}", e);
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum VanishAuditPhase {
    Authorized,
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VanishAuditInitiator {
    Account,
    Admin,
}

impl VanishAuditInitiator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Admin => "admin",
        }
    }

    pub fn other(self) -> Self {
        match self {
            Self::Account => Self::Admin,
            Self::Admin => Self::Account,
        }
    }
}

fn vanish_audit_entry(
    pubkey: &str,
    operation_id: &str,
    timestamp: &str,
    initiator: VanishAuditInitiator,
    phase: VanishAuditPhase,
) -> serde_json::Value {
    let action = match (initiator, phase) {
        (VanishAuditInitiator::Account, VanishAuditPhase::Authorized) => "vanish_authorized",
        (VanishAuditInitiator::Account, VanishAuditPhase::Completed) => "vanish_completed",
        (VanishAuditInitiator::Admin, VanishAuditPhase::Authorized) => "admin_vanish_authorized",
        (VanishAuditInitiator::Admin, VanishAuditPhase::Completed) => "admin_vanish_completed",
    };
    let insert_id = hex::encode(Sha256::digest(
        format!("vanish-audit:v1:{action}:{operation_id}").as_bytes(),
    ));
    let mut entry = serde_json::json!({
        "action": action,
        "account_pubkey": pubkey,
        "audit_version": 1,
        "initiator": initiator.as_str(),
        "operation_id": operation_id,
        "time": timestamp,
        "logging.googleapis.com/insertId": insert_id,
    });
    if initiator == VanishAuditInitiator::Account {
        entry["actor_pubkey"] = serde_json::json!(pubkey);
    }
    entry
}

/// Write one idempotent account-level vanish audit record.
pub fn write_vanish_audit_log(
    pubkey: &str,
    operation_id: &str,
    timestamp: &str,
    initiator: VanishAuditInitiator,
    phase: VanishAuditPhase,
) -> Result<()> {
    const CLOUD_RUN_HOST: &str = "blossom-upload-rust-149672065768.us-central1.run.app";
    let webhook_secret = get_secret("webhook_secret")?;
    let payload = vanish_audit_entry(pubkey, operation_id, timestamp, initiator, phase);
    let mut request = Request::new(
        Method::POST,
        format!("https://{}/audit/vanish", CLOUD_RUN_HOST),
    );
    request.set_header("Host", CLOUD_RUN_HOST);
    request.set_header("Content-Type", "application/json");
    request.set_header("Authorization", format!("Bearer {webhook_secret}"));
    request.set_body(payload.to_string());

    let response = request.send(CLOUD_RUN_BACKEND).map_err(|error| {
        BlossomError::Internal(format!("Failed to deliver vanish audit: {error}"))
    })?;
    if !response.get_status().is_success() {
        return Err(BlossomError::Internal(format!(
            "Vanish audit returned status {}",
            response.get_status()
        )));
    }
    Ok(())
}

/// Dispatch one aggregate vanish timing record to the Cloud Logging bridge.
pub fn dispatch_vanish_timing_log(entry: &serde_json::Value) -> Result<()> {
    const CLOUD_RUN_HOST: &str = "blossom-upload-rust-149672065768.us-central1.run.app";
    let mut payload = entry.clone();
    payload["action"] = serde_json::json!("vanish_timing");
    payload["timestamp"] = serde_json::json!(current_timestamp());

    let mut req = Request::new(Method::POST, format!("https://{}/audit", CLOUD_RUN_HOST));
    req.set_header("Host", CLOUD_RUN_HOST);
    req.set_header("Content-Type", "application/json");
    req.set_body(payload.to_string());
    req.send_async(CLOUD_RUN_BACKEND).map_err(|error| {
        BlossomError::Internal(format!("Failed to dispatch vanish timing: {}", error))
    })?;
    Ok(())
}

fn cloud_run_delete_blob_body(hash: &str, expected_bucket: &str) -> String {
    serde_json::json!({
        "hash": hash,
        "expected_bucket": expected_bucket,
    })
    .to_string()
}

fn cloud_run_delete_blobs_body(hashes: &[String], expected_bucket: &str) -> Result<String> {
    if hashes.len() > CLOUD_RUN_DELETE_BATCH_LIMIT {
        return Err(BlossomError::Internal(format!(
            "Cloud Run batch cleanup exceeds the {CLOUD_RUN_DELETE_BATCH_LIMIT}-hash contract"
        )));
    }
    Ok(serde_json::json!({
        "hashes": hashes,
        "expected_bucket": expected_bucket,
    })
    .to_string())
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CloudCleanupStatus {
    Completed,
    Retryable,
    Permanent,
}

#[derive(Deserialize)]
struct CloudCleanupResponse {
    status: CloudCleanupStatus,
}

#[derive(Deserialize)]
struct BatchHashCleanupResponse {
    hash: String,
    status: CloudCleanupStatus,
}

#[derive(Deserialize)]
struct BatchCleanupResponse {
    status: CloudCleanupStatus,
    results: Vec<BatchHashCleanupResponse>,
}

fn classify_cloud_cleanup_response(status: StatusCode, body: &str) -> Result<()> {
    let cleanup = serde_json::from_str::<CloudCleanupResponse>(body).map_err(|_| {
        BlossomError::StorageError(format!(
            "Cloud Run derivative cleanup returned an untyped response with status {}",
            status
        ))
    })?;

    match cleanup.status {
        CloudCleanupStatus::Completed if status.is_success() => Ok(()),
        CloudCleanupStatus::Permanent => Err(BlossomError::Internal(format!(
            "Cloud Run derivative cleanup reported a permanent contract or configuration failure with status {}",
            status
        ))),
        CloudCleanupStatus::Retryable | CloudCleanupStatus::Completed => {
            Err(BlossomError::StorageError(format!(
                "Cloud Run derivative cleanup reported a retryable failure with status {}",
                status
            )))
        }
    }
}

pub fn trigger_cloud_run_delete_blob(hash: &str) -> Result<()> {
    let webhook_secret = get_secret("webhook_secret")?;
    let expected_bucket = get_config("gcs_bucket")?;
    let body = cloud_run_delete_blob_body(hash, &expected_bucket);

    let mut req = Request::new(
        Method::POST,
        format!("https://{}/delete-blob", CLOUD_RUN_HOST),
    );
    req.set_header("Host", CLOUD_RUN_HOST);
    req.set_header("Content-Type", "application/json");
    req.set_header("Authorization", format!("Bearer {}", webhook_secret));
    req.set_body(Body::from(body));

    let mut response = req.send(CLOUD_RUN_BACKEND).map_err(|error| {
        BlossomError::StorageError(format!("Cloud Run derivative cleanup failed: {}", error))
    })?;
    let status = response.get_status();
    let body = response.take_body().into_string();
    classify_cloud_cleanup_response(status, &body)
}

fn failed_cloud_cleanup_hashes(
    status: StatusCode,
    body: &str,
    requested: &[String],
) -> HashSet<String> {
    let Ok(response) = serde_json::from_str::<BatchCleanupResponse>(body) else {
        return requested.iter().cloned().collect();
    };
    if response.status == CloudCleanupStatus::Permanent
        || (response.status == CloudCleanupStatus::Completed && !status.is_success())
    {
        return requested.iter().cloned().collect();
    }

    let outcomes = response
        .results
        .into_iter()
        .map(|result| (result.hash.to_lowercase(), result.status))
        .collect::<HashMap<_, _>>();
    requested
        .iter()
        .filter(|hash| {
            !matches!(
                outcomes.get(&hash.to_lowercase()),
                Some(CloudCleanupStatus::Completed)
            )
        })
        .cloned()
        .collect()
}

fn plan_cloud_run_delete_chunks(hashes: &[String]) -> Vec<&[String]> {
    hashes.chunks(CLOUD_RUN_DELETE_BATCH_LIMIT).collect()
}

fn trigger_cloud_run_delete_blobs(hashes: &[String]) -> Result<HashSet<String>> {
    if hashes.is_empty() {
        return Ok(HashSet::new());
    }
    let webhook_secret = get_secret("webhook_secret")?;
    let expected_bucket = get_config("gcs_bucket")?;
    let mut failed = HashSet::new();
    for chunk in plan_cloud_run_delete_chunks(hashes) {
        failed.extend(trigger_cloud_run_delete_blobs_chunk(
            chunk,
            &webhook_secret,
            &expected_bucket,
        )?);
    }
    Ok(failed)
}

fn trigger_cloud_run_delete_blobs_chunk(
    hashes: &[String],
    webhook_secret: &str,
    expected_bucket: &str,
) -> Result<HashSet<String>> {
    let body = cloud_run_delete_blobs_body(hashes, expected_bucket)?;

    const CLOUD_RUN_HOST: &str = "blossom-upload-rust-149672065768.us-central1.run.app";
    let mut request = Request::new(
        Method::POST,
        format!("https://{}/delete-blobs", CLOUD_RUN_HOST),
    );
    request.set_header("Host", CLOUD_RUN_HOST);
    request.set_header("Content-Type", "application/json");
    request.set_header("Authorization", format!("Bearer {}", webhook_secret));
    request.set_body(Body::from(body));

    let mut response = request.send(CLOUD_RUN_BACKEND).map_err(|error| {
        BlossomError::StorageError(format!("Cloud Run batch cleanup failed: {}", error))
    })?;
    let status = response.get_status();
    let body = response.take_body().into_string();
    if !status.is_success() {
        eprintln!("[VANISH] Cloud Run batch cleanup returned status={status}");
    }
    Ok(failed_cloud_cleanup_hashes(status, &body, hashes))
}

/// Trigger synchronous migration of a blob from a fallback CDN to GCS.
/// Sends the request to Cloud Run and waits for completion (up to timeout).
/// With VCL caching in front, this only runs once per blob on cache miss,
/// so the latency is acceptable to ensure migration actually succeeds.
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

    // Send synchronous request to Cloud Run /migrate endpoint.
    // Previously this was send_async (fire-and-forget), but the PendingRequest
    // was dropped immediately, causing the worker to terminate before Cloud Run
    // could process the migration. Using synchronous send ensures the migration
    // actually completes before the response goes back through VCL.
    let mut req = Request::new(Method::POST, format!("https://{}/migrate", CLOUD_RUN_HOST));
    req.set_header("Host", CLOUD_RUN_HOST);
    req.set_header("Content-Type", "application/json");
    req.set_header("Content-Length", request_body.len().to_string());
    req.set_body(request_body);

    match req.send(CLOUD_RUN_BACKEND) {
        Ok(resp) => {
            let status = resp.get_status();
            if status.is_success() {
                eprintln!(
                    "[MIGRATE] Successfully migrated {} from {}",
                    hash, source_backend
                );
            } else {
                eprintln!(
                    "[MIGRATE] Cloud Run returned {} for {} migration",
                    status, hash
                );
            }
            Ok(())
        }
        Err(e) => {
            eprintln!(
                "[MIGRATE] Failed to migrate {} from {}: {}",
                hash, source_backend, e
            );
            // Don't fail the request - migration is best-effort
            Ok(())
        }
    }
}

/// Backend name for Funnelcake API
const FUNNELCAKE_BACKEND: &str = "funnelcake_api";

/// Cloud Run transcoder host for audio extraction
const CLOUD_RUN_TRANSCODER_HOST: &str = "divine-transcoder-149672065768.us-central1.run.app";

/// Response from Cloud Run audio extraction endpoint
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AudioExtractionResponse {
    pub audio_sha256: Option<String>,
    pub duration: Option<f64>,
    pub size: Option<u64>,
    pub mime_type: Option<String>,
    pub error: Option<String>,
}

fn parse_funnelcake_audio_reuse_response(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|json| {
            json.get("allow_audio_reuse")
                .and_then(|value| value.as_bool())
        })
        .unwrap_or(false)
}

fn parse_audio_extraction_error_response(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|json| {
            json.get("error")
                .and_then(|value| value.as_str())
                .map(|value| value.to_string())
        })
}

/// Check Funnelcake permission for audio reuse.
/// Returns Ok(true) if allowed, Ok(false) if denied, Err for unavailability.
pub fn check_funnelcake_audio_reuse(hash: &str) -> Result<bool> {
    // In local mode, always allow audio reuse for testing
    if is_local_mode() {
        return Ok(true);
    }

    let funnelcake_url = get_config("funnelcake_api_url").map_err(|_| {
        BlossomError::Internal("Funnelcake API URL not configured".into())
    })?;

    let url = format!(
        "{}/api/videos/by-sha256/{}/audio-reuse",
        funnelcake_url, hash
    );

    let mut req = Request::new(Method::GET, &url);
    // Set Host header from the URL
    if let Some(host) = funnelcake_url
        .strip_prefix("https://")
        .or_else(|| funnelcake_url.strip_prefix("http://"))
        .and_then(|s| s.split('/').next())
    {
        req.set_header("Host", host);
    }

    let mut resp = req.send(FUNNELCAKE_BACKEND).map_err(|e| {
        BlossomError::Internal(format!("Funnelcake unavailable: {}", e))
    })?;

    match resp.get_status() {
        StatusCode::OK => {
            let body = resp.take_body().into_string();
            Ok(parse_funnelcake_audio_reuse_response(&body))
        }
        StatusCode::NOT_FOUND => Ok(false),
        status => Err(BlossomError::Internal(format!(
            "Funnelcake returned unexpected status: {}",
            status.as_u16()
        ))),
    }
}

/// Trigger Cloud Run audio extraction endpoint (synchronous - waits for result).
/// Returns the audio extraction response from Cloud Run.
pub fn trigger_audio_extraction(hash: &str, owner: &str) -> Result<AudioExtractionResponse> {
    let webhook_secret = get_secret("webhook_secret").map_err(|_| {
        BlossomError::Internal("webhook_secret not configured".into())
    })?;

    let body = serde_json::json!({
        "sha256": hash,
        "owner": owner
    });

    let url = format!("https://{}/audio/extract", CLOUD_RUN_TRANSCODER_HOST);
    let mut req = Request::new(Method::POST, &url);
    req.set_header("Host", CLOUD_RUN_TRANSCODER_HOST);
    req.set_header("Content-Type", "application/json");
    req.set_header("Authorization", format!("Bearer {}", webhook_secret));
    req.set_body(body.to_string());

    let mut resp = req.send(CLOUD_RUN_BACKEND).map_err(|e| {
        BlossomError::Internal(format!("Audio extraction service unavailable: {}", e))
    })?;

    let status = resp.get_status();
    let resp_body = resp.take_body().into_string();

    match status {
        StatusCode::OK => serde_json::from_str::<AudioExtractionResponse>(&resp_body)
            .map_err(|e| {
                BlossomError::Internal(format!(
                    "Failed to parse audio extraction response: {}",
                    e
                ))
            }),
        StatusCode::UNPROCESSABLE_ENTITY => {
            let error = parse_audio_extraction_error_response(&resp_body)
                .unwrap_or_else(|| "extraction_failed".to_string());
            Ok(AudioExtractionResponse {
                audio_sha256: None,
                duration: None,
                size: None,
                mime_type: None,
                error: Some(error),
            })
        }
        _ => Err(BlossomError::Internal(format!(
            "Audio extraction failed with status: {}",
            status.as_u16()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        audit_log_entry, build_fos_delete_request, build_multi_delete_request,
        canonical_query_string,
        classify_cloud_cleanup_response, cloud_run_delete_blob_body, cloud_run_delete_blobs_body,
        failed_cloud_cleanup_hashes, failed_multi_delete_keys, mark_failed_stage,
        multi_delete_body, normalize_storage_cache_state, parse_audio_extraction_error_response,
        parse_funnelcake_audio_reuse_response, plan_cloud_run_delete_chunks,
        plan_vanish_delete_batches,
        prepare_storage_cache_miss, preserve_storage_cache_state, sign_request_at,
        vanish_audit_entry, S3Config,
        VanishDeleteTarget, VanishStorageResult, CLOUD_RUN_DELETE_BATCH_LIMIT, FOS_BACKEND,
        PROVIDER_MULTI_DELETE_LIMIT, STORAGE_CACHE_HEADER, VanishAuditInitiator, VanishAuditPhase,
    };
    use fastly::http::header;
    use fastly::{Request, Response};
    use std::{collections::HashMap, time::Duration};

    #[test]
    fn audit_log_entry_serializes_optional_fields_without_manual_escaping() {
        let entry = audit_log_entry(
            &"a".repeat(64),
            "delete",
            &"b".repeat(64),
            "2026-08-31T00:00:00Z".into(),
            Some(r#"{"id":"event"}"#),
            None,
            Some("quoted \"reason\" with \\ and\nnewline"),
        );
        let value: serde_json::Value = serde_json::from_str(&entry).expect("valid audit JSON");

        assert_eq!(value["auth_event"]["id"], "event");
        assert_eq!(value["reason"], "quoted \"reason\" with \\ and\nnewline");
        assert!(value.get("metadata_snapshot").is_none());
    }

    #[test]
    fn cloud_cleanup_request_carries_the_edge_bucket() {
        let body = cloud_run_delete_blob_body(&"a".repeat(64), "configured-bucket");
        let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

        assert_eq!(value["hash"], "a".repeat(64));
        assert_eq!(value["expected_bucket"], "configured-bucket");
    }

    #[test]
    fn vanish_audit_is_minimal_and_idempotent_per_phase() {
        let pubkey = "1".repeat(64);
        let operation_id = "2".repeat(64);
        let timestamp = "2026-08-31T18:00:00Z";
        let authorized = vanish_audit_entry(
            &pubkey,
            &operation_id,
            timestamp,
            VanishAuditInitiator::Account,
            VanishAuditPhase::Authorized,
        );
        let authorized_retry = vanish_audit_entry(
            &pubkey,
            &operation_id,
            timestamp,
            VanishAuditInitiator::Account,
            VanishAuditPhase::Authorized,
        );
        let completed = vanish_audit_entry(
            &pubkey,
            &operation_id,
            timestamp,
            VanishAuditInitiator::Account,
            VanishAuditPhase::Completed,
        );

        assert_eq!(authorized, authorized_retry);
        assert_ne!(
            authorized["logging.googleapis.com/insertId"],
            completed["logging.googleapis.com/insertId"]
        );
        assert_eq!(authorized["account_pubkey"], pubkey);
        assert_eq!(authorized["actor_pubkey"], pubkey);
        assert_eq!(authorized["time"], timestamp);
        assert!(authorized.get("auth_event").is_none());
        assert!(authorized.get("sha256").is_none());

        let admin = vanish_audit_entry(
            &pubkey,
            &operation_id,
            timestamp,
            VanishAuditInitiator::Admin,
            VanishAuditPhase::Authorized,
        );
        assert_eq!(admin["action"], "admin_vanish_authorized");
        assert_eq!(admin["initiator"], "admin");
        assert!(admin.get("actor_pubkey").is_none());
        assert_eq!(
            VanishAuditInitiator::Account.other(),
            VanishAuditInitiator::Admin
        );
        assert_eq!(
            VanishAuditInitiator::Admin.other(),
            VanishAuditInitiator::Account
        );
    }

    #[test]
    fn cloud_cleanup_batch_body_enforces_the_cloud_run_limit() {
        let accepted = vec!["a".repeat(64); CLOUD_RUN_DELETE_BATCH_LIMIT];
        let rejected = vec!["a".repeat(64); CLOUD_RUN_DELETE_BATCH_LIMIT + 1];

        assert!(cloud_run_delete_blobs_body(&accepted, "configured-bucket").is_ok());
        assert!(cloud_run_delete_blobs_body(&rejected, "configured-bucket").is_err());
    }

    #[test]
    fn cloud_cleanup_chunks_above_the_request_contract() {
        let hashes = (0..CLOUD_RUN_DELETE_BATCH_LIMIT + 1)
            .map(|index| format!("{index:064x}"))
            .collect::<Vec<_>>();
        let derived_audio = hashes
            .iter()
            .map(|hash| format!("{:064x}", hash.bytes().next().unwrap_or(0) as u16 + 1_000))
            .collect::<Vec<_>>();
        let mut erase_hashes = hashes.clone();
        erase_hashes.extend(derived_audio);
        erase_hashes.sort();
        erase_hashes.dedup();

        let chunks = plan_cloud_run_delete_chunks(&erase_hashes);

        assert!(erase_hashes.len() > CLOUD_RUN_DELETE_BATCH_LIMIT);
        assert!(chunks
            .iter()
            .all(|chunk| chunk.len() <= CLOUD_RUN_DELETE_BATCH_LIMIT));
        assert_eq!(
            chunks.iter().map(|chunk| chunk.len()).sum::<usize>(),
            erase_hashes.len()
        );
        assert!(cloud_run_delete_blobs_body(chunks[0], "configured-bucket").is_ok());
    }

    #[test]
    fn cloud_cleanup_response_distinguishes_retryable_and_permanent_failures() {
        let completed = classify_cloud_cleanup_response(
            fastly::http::StatusCode::OK,
            r#"{"status":"completed","deleted":1}"#,
        );
        let retryable = classify_cloud_cleanup_response(
            fastly::http::StatusCode::SERVICE_UNAVAILABLE,
            r#"{"status":"retryable","error":"storage unavailable"}"#,
        )
        .expect_err("retryable cleanup must fail closed");
        let permanent = classify_cloud_cleanup_response(
            fastly::http::StatusCode::BAD_REQUEST,
            r#"{"status":"permanent","error":"invalid request"}"#,
        )
        .expect_err("permanent cleanup must fail closed");

        assert!(completed.is_ok());
        assert!(matches!(retryable, crate::error::BlossomError::StorageError(_)));
        assert!(matches!(permanent, crate::error::BlossomError::Internal(_)));
    }

    #[test]
    fn cloud_cleanup_response_treats_route_absence_as_retryable() {
        let error =
            classify_cloud_cleanup_response(fastly::http::StatusCode::NOT_FOUND, "route not found")
                .expect_err("an absent route must not complete erasure");

        assert!(matches!(error, crate::error::BlossomError::StorageError(_)));
    }

    #[test]
    fn batch_cloud_cleanup_returns_only_incomplete_or_missing_hashes() {
        let completed = "A".repeat(64);
        let completed_result = completed.to_lowercase();
        let retryable = "b".repeat(64);
        let missing = "c".repeat(64);
        let body = format!(
            r#"{{"status":"retryable","results":[{{"hash":"{completed_result}","status":"completed"}},{{"hash":"{retryable}","status":"retryable"}}]}}"#
        );

        let failed = failed_cloud_cleanup_hashes(
            fastly::http::StatusCode::SERVICE_UNAVAILABLE,
            &body,
            &[completed.clone(), retryable.clone(), missing.clone()],
        );

        assert!(!failed.contains(&completed));
        assert!(failed.contains(&retryable));
        assert!(failed.contains(&missing));
    }

    #[test]
    fn batch_cloud_cleanup_rejects_completed_body_with_error_status() {
        let hash = "a".repeat(64);
        let body = format!(
            r#"{{"status":"completed","results":[{{"hash":"{hash}","status":"completed"}}]}}"#
        );

        let failed = failed_cloud_cleanup_hashes(
            fastly::http::StatusCode::SERVICE_UNAVAILABLE,
            &body,
            std::slice::from_ref(&hash),
        );

        assert!(failed.contains(&hash));
    }

    #[test]
    fn fos_delete_request_uses_the_replica_backend_address_and_delete_method() {
        let config = S3Config {
            access_key: "synthetic-access-key".into(),
            secret_key: "synthetic-secret-key".into(),
            bucket: "replica-bucket".into(),
            host: "replica.example".into(),
            region: "test-region".into(),
        };

        let req = build_fos_delete_request("abc123", &config).expect("request should sign");

        assert_eq!(FOS_BACKEND, "fos_storage");
        assert_eq!(req.get_method(), fastly::http::Method::DELETE);
        assert_eq!(
            req.get_url().as_str(),
            "https://replica.example/replica-bucket/abc123"
        );
        assert_eq!(req.get_header_str("Host"), Some("replica.example"));
        assert!(req.contains_header("Authorization"));
    }

    #[test]
    fn fos_multi_delete_request_batches_keys_and_signs_the_payload() {
        let config = S3Config {
            access_key: "synthetic-access-key".into(),
            secret_key: "synthetic-secret-key".into(),
            bucket: "replica-bucket".into(),
            host: "replica.example".into(),
            region: "test-region".into(),
        };
        let keys = vec!["a".repeat(64), format!("{}.jpg", "b".repeat(64))];

        let mut req =
            build_multi_delete_request(&keys, &config, "fos_main").expect("request should sign");

        assert_eq!(req.get_method(), fastly::http::Method::POST);
        assert_eq!(
            req.get_url().as_str(),
            "https://replica.example/replica-bucket?delete"
        );
        assert!(req.contains_header("Authorization"));
        assert!(req.contains_header("Content-MD5"));
        assert_eq!(req.take_body().into_string(), multi_delete_body(&keys));
    }

    #[test]
    fn gcs_multi_delete_request_has_the_exact_required_shape() {
        let config = S3Config {
            access_key: "synthetic-access-key".into(),
            secret_key: "synthetic-secret-key".into(),
            bucket: "gcs-bucket".into(),
            host: "storage.googleapis.com".into(),
            region: "auto".into(),
        };
        let keys = vec!["a".repeat(64)];

        let req =
            build_multi_delete_request(&keys, &config, "gcs_main").expect("request should sign");

        assert_eq!(req.get_method(), fastly::http::Method::POST);
        assert_eq!(
            req.get_url().as_str(),
            "https://storage.googleapis.com/gcs-bucket?delete"
        );
        assert_eq!(req.get_header_str("Host"), Some("storage.googleapis.com"));
        assert_eq!(
            req.get_header_str("Content-MD5"),
            Some("IqZiGqcRnGzSA6fkBIAnEQ==")
        );
        assert!(req
            .get_header_str("Authorization")
            .expect("signed authorization")
            .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
    }

    #[test]
    fn signer_uses_the_requests_actual_host_header() {
        let config = S3Config {
            access_key: "synthetic-access-key".into(),
            secret_key: "synthetic-secret-key".into(),
            bucket: "bucket".into(),
            host: "configured.example".into(),
            region: "test-region".into(),
        };
        let now = Duration::from_secs(1_700_000_000);
        let mut first = Request::post("https://configured.example/bucket?delete");
        first.set_header("Host", "first.example");
        sign_request_at(&mut first, &config, Some("payload".into()), now)
            .expect("first request should sign");
        let mut second = Request::post("https://configured.example/bucket?delete");
        second.set_header("Host", "second.example");
        sign_request_at(&mut second, &config, Some("payload".into()), now)
            .expect("second request should sign");

        assert_ne!(
            first.get_header_str("Authorization"),
            second.get_header_str("Authorization")
        );
    }

    #[test]
    fn multi_delete_wire_query_has_a_canonical_empty_value() {
        let config = S3Config {
            access_key: "synthetic-access-key".into(),
            secret_key: "synthetic-secret-key".into(),
            bucket: "bucket".into(),
            host: "storage.example".into(),
            region: "test-region".into(),
        };
        let now = Duration::from_secs(1_700_000_000);
        let mut wire = Request::post("https://storage.example/bucket?delete");
        wire.set_header("Host", "storage.example");
        sign_request_at(&mut wire, &config, Some("payload".into()), now)
            .expect("wire request should sign");
        let mut canonical = Request::post("https://storage.example/bucket?delete=");
        canonical.set_header("Host", "storage.example");
        sign_request_at(&mut canonical, &config, Some("payload".into()), now)
            .expect("canonical request should sign");

        assert_eq!(canonical_query_string(Some("delete")), "delete=");
        assert_eq!(
            wire.get_header_str("Authorization"),
            canonical.get_header_str("Authorization")
        );
    }

    #[test]
    fn vanish_delete_plan_chunks_every_provider_request() {
        let hashes = (0..1_001)
            .map(|index| format!("{index:064x}"))
            .collect::<Vec<_>>();
        let batches = plan_vanish_delete_batches(&hashes);

        assert!(batches
            .iter()
            .all(|batch| batch.keys.len() <= PROVIDER_MULTI_DELETE_LIMIT));
        assert!(batches.iter().any(|batch| {
            batch.target == VanishDeleteTarget::GcsMain && batch.stage == "gcs_main:1"
        }));
        assert!(batches.iter().any(|batch| {
            batch.target == VanishDeleteTarget::FosMain && batch.stage == "fos_main:1"
        }));
        assert_eq!(batches.len(), 4);
    }

    #[test]
    fn multi_delete_response_requires_a_result_for_every_key() {
        let deleted = "a".repeat(64);
        let failed = "b".repeat(64);
        let missing = "c".repeat(64);
        let body = format!(
            "<DeleteResult><Deleted><Key>{}</Key></Deleted><Error><Key>{}</Key><Code>Denied</Code></Error></DeleteResult>",
            deleted, failed
        );
        let response = Response::from_status(fastly::http::StatusCode::OK).with_body(body);

        let failures = failed_multi_delete_keys(
            response,
            &[deleted.clone(), failed.clone(), missing.clone()],
            "test",
        );

        assert!(!failures.contains(&deleted));
        assert!(failures.contains(&failed));
        assert!(failures.contains(&missing));
    }

    #[test]
    fn multi_delete_response_treats_explicit_absence_as_success() {
        let absent = "a".repeat(64);
        let denied = "b".repeat(64);
        let body = format!(
            "<DeleteResult><Error><Key>{}</Key><Code>NoSuchKey</Code></Error><Error><Key>{}</Key><Code>Denied</Code></Error></DeleteResult>",
            absent, denied
        );
        let response = Response::from_status(fastly::http::StatusCode::OK).with_body(body);

        let failures =
            failed_multi_delete_keys(response, &[absent.clone(), denied.clone()], "test");

        assert!(!failures.contains(&absent));
        assert!(failures.contains(&denied));
    }

    #[test]
    fn multi_delete_response_treats_an_active_hold_as_failure() {
        let held = "a".repeat(64);
        let body = format!(
            "<DeleteResult><Error><Key>{held}</Key><Code>ObjectUnderActiveHold</Code><Message>object is held</Message></Error></DeleteResult>"
        );
        let response = Response::from_status(fastly::http::StatusCode::OK).with_body(body);

        let failures = failed_multi_delete_keys(response, std::slice::from_ref(&held), "test");

        assert!(failures.contains(&held));
    }

    #[test]
    fn unattributed_failed_stage_fails_the_whole_batch_closed() {
        let hashes = vec!["a".repeat(64), "b".repeat(64)];
        let mut result = VanishStorageResult::default();

        mark_failed_stage(&mut result, &HashMap::new(), "", &hashes);

        assert_eq!(result.failed_hashes.len(), hashes.len());
        assert!(hashes
            .iter()
            .all(|hash| result.failed_hashes.contains(hash)));
    }

    #[test]
    fn storage_cache_miss_fetches_the_complete_object() {
        let mut req = Request::get("https://storage.example/object");
        req.set_header(header::RANGE, "bytes=0-1023");

        prepare_storage_cache_miss(&mut req);

        assert!(!req.contains_header(header::RANGE));
    }

    #[test]
    fn storage_cache_state_uses_the_compute_cache_result() {
        assert_eq!(normalize_storage_cache_state("HIT, MISS"), Some("MISS"));
        assert_eq!(normalize_storage_cache_state("MISS, HIT"), Some("HIT"));
        assert_eq!(normalize_storage_cache_state("hit"), Some("HIT"));
        assert_eq!(normalize_storage_cache_state("backend-only"), None);
    }

    #[test]
    fn storage_cache_state_uses_the_last_x_cache_header_line() {
        let mut resp = Response::new();
        resp.append_header("X-Cache", "HIT");
        resp.append_header("X-Cache", "HIT");
        resp.append_header("X-Cache", "MISS");

        preserve_storage_cache_state(&mut resp);

        assert_eq!(resp.get_header_str(STORAGE_CACHE_HEADER), Some("MISS"));
    }

    #[test]
    fn storage_cache_state_drops_an_unrecognized_backend_value() {
        let mut resp = Response::new();
        resp.append_header("X-Cache", "backend-only");

        preserve_storage_cache_state(&mut resp);

        assert!(!resp.contains_header(STORAGE_CACHE_HEADER));
    }

    #[test]
    fn parses_funnelcake_audio_reuse_allow_flag() {
        assert!(parse_funnelcake_audio_reuse_response(
            r#"{"allow_audio_reuse":true}"#
        ));
        assert!(!parse_funnelcake_audio_reuse_response(
            r#"{"allow_audio_reuse":false}"#
        ));
    }

    #[test]
    fn defaults_funnelcake_audio_reuse_to_false_on_invalid_body() {
        assert!(!parse_funnelcake_audio_reuse_response("not json"));
        assert!(!parse_funnelcake_audio_reuse_response(r#"{"unexpected":true}"#));
    }

    #[test]
    fn parses_audio_extraction_error_response() {
        assert_eq!(
            parse_audio_extraction_error_response(r#"{"error":"no_audio_track"}"#),
            Some("no_audio_track".to_string())
        );
        assert_eq!(parse_audio_extraction_error_response("not json"), None);
    }
}
