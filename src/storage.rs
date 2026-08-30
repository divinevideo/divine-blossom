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
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Backend name (must match fastly.toml)
const GCS_BACKEND: &str = "gcs_storage";

/// Fastly Object Storage backend name (must exist on the service).
const FOS_BACKEND: &str = "fos_storage";

/// Cloud Run backend for uploads/migrations
const CLOUD_RUN_BACKEND: &str = "cloud_run_upload";

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

const VANISH_ARTIFACT_SUFFIXES: &[&str] = &[
    ".jpg",
    "/hls/master.m3u8",
    "/hls/stream_720p.m3u8",
    "/hls/stream_720p.ts",
    "/hls/stream_480p.m3u8",
    "/hls/stream_480p.ts",
    "/hls/stream_720p.mp4",
    "/hls/stream_480p.mp4",
    "/vtt/main.vtt",
];

#[derive(Debug, Default, serde::Serialize)]
pub(crate) struct VanishStorageTimings {
    pub gcs_main_ms: u64,
    pub gcs_artifacts_ms: u64,
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
        self.timings.gcs_artifacts_ms = self
            .timings
            .gcs_artifacts_ms
            .saturating_add(retry.timings.gcs_artifacts_ms);
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

fn build_multi_delete_request(
    keys: &[String],
    config: &S3Config,
    stage: &str,
    content_md5: bool,
) -> Result<Request> {
    let body = multi_delete_body(keys);
    let payload_hash = hex::encode(Sha256::digest(body.as_bytes()));
    let path = format!("/{}?delete=", config.bucket);
    let mut req = Request::new(Method::POST, format!("{}{}", config.endpoint(), path));
    req.set_header("Host", config.host());
    req.set_header("Content-Type", "application/xml");
    req.set_header("Content-Length", body.len().to_string());
    req.set_header("X-Divine-Vanish-Stage", stage);
    if content_md5 {
        use base64::Engine as _;
        let checksum = Md5::digest(body.as_bytes());
        req.set_header(
            "Content-MD5",
            base64::engine::general_purpose::STANDARD.encode(checksum),
        );
    }
    sign_request(&mut req, config, Some(payload_hash))?;
    req.set_body(body);
    Ok(req)
}

fn keys_in_xml_section(xml: &str, section: &str) -> HashSet<String> {
    let mut keys = HashSet::new();
    let open = format!("<{}>", section);
    let close = format!("</{}>", section);
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let after_open = &rest[start + open.len()..];
        let Some(end) = after_open.find(&close) else {
            break;
        };
        let block = &after_open[..end];
        if let Some(key_start) = block.find("<Key>") {
            let key_value = &block[key_start + 5..];
            if let Some(key_end) = key_value.find("</Key>") {
                keys.insert(key_value[..key_end].to_string());
            }
        }
        rest = &after_open[end + close.len()..];
    }
    keys
}

fn failed_multi_delete_keys(mut response: Response, requested: &[String]) -> HashSet<String> {
    if !response.get_status().is_success() {
        return requested.iter().cloned().collect();
    }

    let body = response.take_body().into_string();
    let deleted = keys_in_xml_section(&body, "Deleted");
    let errors = keys_in_xml_section(&body, "Error");
    requested
        .iter()
        .filter(|key| errors.contains(*key) || !deleted.contains(*key))
        .cloned()
        .collect()
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
    result.failed_hashes.extend(
        keys.iter()
            .filter_map(|key| hash_for_vanish_key(key)),
    );
}

fn purge_vanish_hashes(hashes: &[String], result: &mut VanishStorageResult) {
    if hashes.is_empty() {
        return;
    }

    let api_token = match get_secret("fastly_api_token") {
        Ok(token) if !token.is_empty() => token,
        _ => {
            result.failed_hashes.extend(hashes.iter().cloned());
            return;
        }
    };
    let services = [
        ("ML7R82HKfmTaqTpHExIDVN", "purge_vcl"),
        ("pOvEEWykEbpnylqst1KTrR", "purge_compute"),
    ];
    let started = Instant::now();
    let mut pending = Vec::new();
    let mut stage_hashes = HashMap::<String, Vec<String>>::new();

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
            stage_hashes.insert(stage_id, chunk.to_vec());
            match req.send_async("fastly_api") {
                Ok(request) => pending.push(request),
                Err(_) => result.failed_hashes.extend(chunk.iter().cloned()),
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
                let duration = elapsed_ms(started);
                if stage.starts_with("purge_vcl") {
                    result.timings.purge_vcl_ms = duration;
                } else if stage.starts_with("purge_compute") {
                    result.timings.purge_compute_ms = duration;
                }
                if !response.get_status().is_success() {
                    if let Some(failed) = stage_hashes.get(&stage) {
                        result.failed_hashes.extend(failed.iter().cloned());
                    }
                }
            }
            Err(error) => {
                let request = error.into_sent_req();
                let stage = request
                    .get_header_str("X-Divine-Vanish-Stage")
                    .unwrap_or_default()
                    .to_string();
                if let Some(failed) = stage_hashes.get(&stage) {
                    result.failed_hashes.extend(failed.iter().cloned());
                }
            }
        }
    }
}

/// Erase one bounded vanish batch from both origins and both CDN services.
pub(crate) fn erase_vanish_batch(hashes: &[String]) -> VanishStorageResult {
    let mut result = VanishStorageResult::default();
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
    let main_keys = hashes.to_vec();
    let artifact_keys: Vec<String> = hashes
        .iter()
        .flat_map(|hash| {
            VANISH_ARTIFACT_SUFFIXES
                .iter()
                .map(move |suffix| format!("{}{}", hash, suffix))
        })
        .collect();
    let requests = [
        ("gcs_main", &main_keys, &gcs, GCS_BACKEND, false),
        ("gcs_artifacts", &artifact_keys, &gcs, GCS_BACKEND, false),
        ("fos_main", &main_keys, &fos, FOS_BACKEND, true),
    ];
    let started = Instant::now();
    let mut pending = Vec::new();
    let requested_by_stage: HashMap<&str, &[String]> = requests
        .iter()
        .map(|(stage, keys, _, _, _)| (*stage, keys.as_slice()))
        .collect();

    for (stage, keys, config, backend, content_md5) in requests {
        match build_multi_delete_request(keys, config, stage, content_md5)
            .and_then(|request| {
                request.send_async(backend).map_err(|error| {
                    BlossomError::StorageError(format!("{} batch delete failed: {}", stage, error))
                })
            }) {
            Ok(request) => pending.push(request),
            Err(_) => result.failed_hashes.extend(hashes.iter().cloned()),
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
                let duration = elapsed_ms(started);
                match stage.as_str() {
                    "gcs_main" => result.timings.gcs_main_ms = duration,
                    "gcs_artifacts" => result.timings.gcs_artifacts_ms = duration,
                    "fos_main" => result.timings.fos_main_ms = duration,
                    _ => {}
                }
                if let Some(requested) = requested_by_stage.get(stage.as_str()) {
                    let failed = failed_multi_delete_keys(response, requested);
                    mark_failed_keys(&mut result, &failed);
                } else {
                    result.failed_hashes.extend(hashes.iter().cloned());
                }
            }
            Err(error) => {
                let request = error.into_sent_req();
                let stage = request
                    .get_header_str("X-Divine-Vanish-Stage")
                    .unwrap_or_default();
                if let Some(requested) = requested_by_stage.get(stage) {
                    let failed: HashSet<String> = requested.iter().cloned().collect();
                    mark_failed_keys(&mut result, &failed);
                } else {
                    result.failed_hashes.extend(hashes.iter().cloned());
                }
            }
        }
    }

    let purgeable: Vec<String> = hashes
        .iter()
        .filter(|hash| !result.failed_hashes.contains(*hash))
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
    let timestamp = current_timestamp();

    let mut entry = format!(
        r#"{{"action":"{}","sha256":"{}","actor_pubkey":"{}","timestamp":"{}""#,
        action, sha256, actor_pubkey, timestamp
    );

    if let Some(auth) = auth_event_json {
        entry.push_str(&format!(r#","auth_event":{}"#, auth));
    }
    if let Some(meta) = metadata_snapshot {
        entry.push_str(&format!(r#","metadata_snapshot":{}"#, meta));
    }
    if let Some(r) = reason {
        entry.push_str(&format!(r#","reason":"{}""#, r.replace('"', "\\\"")));
    }
    entry.push('}');

    // Fire-and-forget POST to Cloud Run /audit endpoint
    // Cloud Run prints structured JSON → auto-ingested by Cloud Logging
    const CLOUD_RUN_HOST: &str = "blossom-upload-rust-149672065768.us-central1.run.app";
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

/// Persist one vanish timing record through the existing Cloud Logging bridge.
pub fn write_vanish_timing_log(entry: &serde_json::Value) -> Result<()> {
    const CLOUD_RUN_HOST: &str = "blossom-upload-rust-149672065768.us-central1.run.app";
    let mut payload = entry.clone();
    payload["action"] = serde_json::json!("vanish_timing");
    payload["timestamp"] = serde_json::json!(current_timestamp());

    let mut req = Request::new(Method::POST, format!("https://{}/audit", CLOUD_RUN_HOST));
    req.set_header("Host", CLOUD_RUN_HOST);
    req.set_header("Content-Type", "application/json");
    req.set_body(payload.to_string());
    let response = req.send(CLOUD_RUN_BACKEND).map_err(|error| {
        BlossomError::Internal(format!("Failed to persist vanish timing: {}", error))
    })?;
    if !response.get_status().is_success() {
        return Err(BlossomError::Internal(format!(
            "Vanish timing sink returned status {}",
            response.get_status()
        )));
    }
    Ok(())
}

/// Fire-and-forget: ask Cloud Run to delete a blob's GCS objects (main + prefix).
/// This is a backstop for thorough cleanup including any HLS/VTT files
/// that might not have been caught by the deterministic path deletion.
pub fn trigger_cloud_run_delete_blob(hash: &str) {
    let webhook_secret = match get_secret("webhook_secret") {
        Ok(s) => s,
        Err(_) => {
            eprintln!("[DELETE] webhook_secret not configured, skipping Cloud Run delete");
            return;
        }
    };

    let body = format!(r#"{{"hash":"{}"}}"#, hash);

    const CLOUD_RUN_HOST: &str = "blossom-upload-rust-149672065768.us-central1.run.app";
    let mut req = Request::new(
        Method::POST,
        format!("https://{}/delete-blob", CLOUD_RUN_HOST),
    );
    req.set_header("Host", CLOUD_RUN_HOST);
    req.set_header("Content-Type", "application/json");
    req.set_header("Authorization", format!("Bearer {}", webhook_secret));
    req.set_body(Body::from(body));

    match req.send_async(CLOUD_RUN_BACKEND) {
        Ok(_) => {
            eprintln!("[DELETE] Triggered Cloud Run delete-blob for {}", hash);
        }
        Err(e) => {
            eprintln!(
                "[DELETE] Failed to trigger Cloud Run delete-blob for {}: {}",
                hash, e
            );
        }
    }
}

/// Fire-and-forget: ask Cloud Run to delete all GCS objects for a user (vanish).
/// Cloud Run does prefix-based listing + deletion as a thorough safety net.
pub fn trigger_cloud_run_bulk_delete(pubkey: &str, hashes: &[String]) {
    let webhook_secret = match get_secret("webhook_secret") {
        Ok(s) => s,
        Err(_) => {
            eprintln!("[VANISH] webhook_secret not configured, skipping Cloud Run bulk delete");
            return;
        }
    };

    let body = serde_json::json!({
        "pubkey": pubkey,
        "known_hashes": hashes,
    })
    .to_string();

    const CLOUD_RUN_HOST: &str = "blossom-upload-rust-149672065768.us-central1.run.app";
    let mut req = Request::new(
        Method::POST,
        format!("https://{}/delete-blobs-by-owner", CLOUD_RUN_HOST),
    );
    req.set_header("Host", CLOUD_RUN_HOST);
    req.set_header("Content-Type", "application/json");
    req.set_header("Authorization", format!("Bearer {}", webhook_secret));
    req.set_body(Body::from(body));

    match req.send_async(CLOUD_RUN_BACKEND) {
        Ok(_) => {
            eprintln!(
                "[VANISH] Triggered Cloud Run bulk delete for pubkey={}",
                pubkey
            );
        }
        Err(e) => {
            eprintln!("[VANISH] Failed to trigger Cloud Run bulk delete: {}", e);
        }
    }
}

/// Fire-and-forget: ask Cloud Run to mark a pubkey for audit log anonymization.
pub fn trigger_audit_anonymize(pubkey: &str) {
    let webhook_secret = match get_secret("webhook_secret") {
        Ok(s) => s,
        Err(_) => {
            eprintln!("[VANISH] webhook_secret not configured, skipping audit anonymize");
            return;
        }
    };

    let body = format!(r#"{{"pubkey":"{}"}}"#, pubkey);

    const CLOUD_RUN_HOST: &str = "blossom-upload-rust-149672065768.us-central1.run.app";
    let mut req = Request::new(
        Method::POST,
        format!("https://{}/audit/anonymize", CLOUD_RUN_HOST),
    );
    req.set_header("Host", CLOUD_RUN_HOST);
    req.set_header("Content-Type", "application/json");
    req.set_header("Authorization", format!("Bearer {}", webhook_secret));
    req.set_body(Body::from(body));

    match req.send_async(CLOUD_RUN_BACKEND) {
        Ok(_) => {
            eprintln!("[VANISH] Triggered audit anonymize for pubkey={}", pubkey);
        }
        Err(e) => {
            eprintln!("[VANISH] Failed to trigger audit anonymize: {}", e);
        }
    }
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
    const CLOUD_RUN_HOST: &str = "blossom-upload-rust-149672065768.us-central1.run.app";
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
        build_fos_delete_request, build_multi_delete_request, failed_multi_delete_keys,
        multi_delete_body, normalize_storage_cache_state,
        parse_audio_extraction_error_response, parse_funnelcake_audio_reuse_response,
        prepare_storage_cache_miss, preserve_storage_cache_state, S3Config, FOS_BACKEND,
        STORAGE_CACHE_HEADER,
    };
    use fastly::http::header;
    use fastly::{Request, Response};

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
    fn multi_delete_request_batches_keys_and_signs_the_payload() {
        let config = S3Config {
            access_key: "synthetic-access-key".into(),
            secret_key: "synthetic-secret-key".into(),
            bucket: "replica-bucket".into(),
            host: "replica.example".into(),
            region: "test-region".into(),
        };
        let keys = vec!["a".repeat(64), format!("{}.jpg", "b".repeat(64))];

        let mut req = build_multi_delete_request(&keys, &config, "fos_main", true)
            .expect("request should sign");

        assert_eq!(req.get_method(), fastly::http::Method::POST);
        assert_eq!(
            req.get_url().as_str(),
            "https://replica.example/replica-bucket?delete="
        );
        assert!(req.contains_header("Authorization"));
        assert!(req.contains_header("Content-MD5"));
        assert_eq!(req.take_body().into_string(), multi_delete_body(&keys));
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
        );

        assert!(!failures.contains(&deleted));
        assert!(failures.contains(&failed));
        assert!(failures.contains(&missing));
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
