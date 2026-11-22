// ABOUTME: Object storage operations against GCS, Fastly Object Storage, and the gated B2 replica
// ABOUTME: Implements signed delivery, read-through mirroring, and fail-closed vanish erasure

use crate::error::{BlossomError, Result};
use blossom_core::cache_policy::{immutable_storage_cache_policy, ImmutableStorageCachePolicy};
use blossom_core::read_through::{
    check_mirror_response, object_path, parse_bool_flag, replica_delete_outcome,
    write_back_decision, ReplicaDeleteOutcome, MAX_WRITE_BACK_BYTES, SOURCE_FOS, SOURCE_GCS,
};
use blossom_core::storage_origin::{
    ErasurePolicy, ErasurePolicyInputs, MediaReadPolicy, StorageProvider,
};
use fastly::http::{Method, StatusCode};
use fastly::{Backend, Body, Request, Response};
use md5::Md5;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Backend name (must match fastly.toml)
const GCS_BACKEND: &str = "gcs_storage";
const B2_MEDIA_BACKEND: &str = "b2_storage";

/// Fastly Object Storage backend name (must exist on the service).
const FOS_BACKEND: &str = "fos_storage";

/// Backblaze Native API and bunny control-plane backends.
const B2_API_BACKEND: &str = "b2_api";
const BUNNY_API_BACKEND: &str = "bunny_api";

/// Cloud Run backend for uploads/migrations
pub(crate) const CLOUD_RUN_BACKEND: &str = "cloud_run_upload";
pub(crate) const CLOUD_RUN_HOST: &str = "blossom-upload-rust-149672065768.us-central1.run.app";
const CLOUD_RUN_DELIVERY_PROBE_PATH: &str = "/probe-delivery";

/// Bounded sample size for the post-purge delivery probe. One probe origin
/// observes only the POP serving it, so more samples add latency without
/// meaningfully widening coverage.
pub(crate) const DELIVERY_PROBE_LIMIT: usize = 3;

/// Legacy CDN runtime fallback is intentionally disabled.
///
/// If a migration miss is discovered, backfill the verified bytes into GCS
/// instead of reintroducing legacy hosts into the hot delivery path.
const FALLBACK_BACKENDS: &[(&str, &str, &str)] = &[];

#[cfg(test)]
std::thread_local! {
    static TEST_STORAGE_CACHE_BYPASS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Viceroy does not implement the HTTP cache host calls used for originals.
/// Keep that unsupported transport isolated from exact-route policy tests.
#[cfg(test)]
pub(crate) fn with_uncached_storage_for_test<T>(operation: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_STORAGE_CACHE_BYPASS.with(|value| value.set(self.0));
        }
    }
    let _reset = Reset(TEST_STORAGE_CACHE_BYPASS.with(|value| value.replace(true)));
    operation()
}

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
const B2_REPLICA_FLAG: &str = "b2_replica_enabled";
// One B2-enabled vanish wave covers at most a source blob and its derived
// audio, each listing bounded pages in media and private-control namespaces,
// deleting a shared bounded version set, and confirming both absent. The vanish wave loop in main.rs asserts that this whole
// wave plus the execution's audit and timing requests fits Fastly Compute's
// 32-backend-request per-execution limit. A larger version set is drained
// across caller retries as pending work instead of exhausting the execution.
const B2_LIST_PAGE_SIZE: usize = 6;
// Two namespace lists and confirmations share the original eight-request
// per-hash ceiling. Retained history drains through caller retries.
const B2_ERASE_DELETES_PER_HASH: usize = 4;
const B2_ERASE_LISTS_PER_HASH: usize = 4;
const MAX_BUNNY_DELIVERY_ZONES: usize = 2;
pub(crate) const B2_VANISH_MAX_HASHES_PER_WAVE: usize = 2;
pub(crate) const B2_VANISH_MAX_STORAGE_BACKEND_REQUESTS: usize = 2 // GCS and FOS multi-delete
    + 1 // B2 authorization
    + B2_VANISH_MAX_HASHES_PER_WAVE * (B2_ERASE_LISTS_PER_HASH + B2_ERASE_DELETES_PER_HASH)
    + 1 // Cloud Run derivative cleanup
    + 2 // Fastly VCL and Compute purges
    + B2_VANISH_MAX_HASHES_PER_WAVE * MAX_BUNNY_DELIVERY_ZONES;

/// Header copied from the storage subrequest before the outer VCL service
/// replaces `X-Cache` with its own cache result. This is intentionally only a
/// cache-state label (HIT/MISS), never a credential or storage identifier.
pub const STORAGE_CACHE_HEADER: &str = "X-Divine-Storage-Cache";

/// Multipart upload threshold (5MB)
const MULTIPART_THRESHOLD: u64 = 5 * 1024 * 1024;

/// Part size for multipart uploads (5MB)
const PART_SIZE: u64 = 5 * 1024 * 1024;

/// Get config value
pub(crate) fn get_config(key: &str) -> Result<String> {
    optional_config(key)?
        .ok_or_else(|| BlossomError::Internal(format!("Missing config: {}", key)))
}

pub(crate) fn optional_config(key: &str) -> Result<Option<String>> {
    crate::request_bindings::config(key)
}

/// Check if running in local/e2e mode (stubs external services)
pub fn is_local_mode() -> bool {
    get_config("local_mode")
        .map(|v| v == "true")
        .unwrap_or(false)
}

/// Get secret value
pub(crate) fn get_secret(key: &str) -> Result<String> {
    crate::request_bindings::secret(key)?.ok_or_else(|| BlossomError::Internal(format!("Missing secret: {key}")))
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PilotKey {
    id: String,
    key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PilotCleanup {
    eraser: PilotKey,
    bunny_api_key: String,
    fastly_api_token: String,
}

fn pilot_binding<T: serde::de::DeserializeOwned>(name: &str) -> Result<T> {
    serde_json::from_str(&get_secret(name)?)
        .map_err(|_| BlossomError::StorageError(format!("Invalid pilot credential binding {name}")))
}

fn pilot_cleanup() -> Result<PilotCleanup> {
    pilot_binding("bunny_pilot_cleanup_v1")
}

impl S3Config {
    fn load_b2_media() -> Result<Self> {
        let region = get_config("b2_media_region")?;
        let host =
            StorageProvider::b2_host(&region).map_err(|e| BlossomError::StorageError(e.into()))?;
        Ok(Self {
            access_key: get_secret("b2_media_access_key")?,
            secret_key: get_secret("b2_media_secret_key")?,
            bucket: get_config("b2_media_bucket")?,
            host,
            region,
        })
    }

    fn load_gcs() -> Result<Self> {
        Ok(Self {
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

fn media_read_policy() -> Result<MediaReadPolicy> {
    MediaReadPolicy::parse(
        get_config("media_read_primary").ok().as_deref(),
        get_config("gcs_fallback_enabled").ok().as_deref(),
    )
    .map_err(|e| BlossomError::StorageError(e.into()))
}

fn build_media_read_request(
    config: &S3Config,
    key: &str,
    range: Option<&str>,
    immutable: bool,
    uncached: bool,
) -> Result<Request> {
    #[cfg(test)]
    let uncached = uncached || TEST_STORAGE_CACHE_BYPASS.with(|value| value.get());
    let mut req = Request::get(format!("{}{}", config.endpoint(), config.object_path(key)));
    req.set_stale_if_error(0);
    req.set_header("Host", config.host());
    if let Some(range) = range {
        req.set_header("Range", range);
    }
    sign_request(&mut req, config, Some("UNSIGNED-PAYLOAD".into()))?;
    if uncached {
        req.set_pass(true);
    } else if immutable {
        enable_immutable_storage_cache(&mut req, key);
    }
    Ok(req)
}

enum MediaFetchError {
    Configuration(BlossomError),
    Transport,
}

impl MediaFetchError {
    fn into_storage_error(self) -> BlossomError {
        match self {
            Self::Configuration(error) => error,
            Self::Transport => BlossomError::StorageError("media origin request failed".into()),
        }
    }
}

fn fetch_media_origin(
    provider: StorageProvider,
    key: &str,
    range: Option<&str>,
    immutable: bool,
    uncached: bool,
) -> std::result::Result<Response, MediaFetchError> {
    let (config, backend) = match provider {
        StorageProvider::Gcs => (S3Config::load_gcs(), GCS_BACKEND),
        StorageProvider::B2 => (S3Config::load_b2_media(), B2_MEDIA_BACKEND),
    };
    let config = config.map_err(MediaFetchError::Configuration)?;
    let req = build_media_read_request(&config, key, range, immutable, uncached)
        .map_err(MediaFetchError::Configuration)?;
    let mut response = req.send(backend).map_err(|_| MediaFetchError::Transport)?;
    if immutable {
        preserve_storage_cache_state(&mut response);
    }
    Ok(response)
}

/// Callers enforce viewer policy before entering this provider-only boundary.
/// Configuration/auth failures are not interpreted as an object being absent.
fn download_media_object(
    key: &str,
    range: Option<&str>,
    immutable: bool,
    uncached: bool,
) -> Result<(Response, &'static str)> {
    download_object_with_policy(media_read_policy()?, key, range, immutable, uncached)
}

fn download_derived_media_object(
    key: &str,
    range: Option<&str>,
    uncached: bool,
) -> Result<Response> {
    download_derived_media_object_reserving_fallback_secrets(key, range, uncached, &[])
}

fn download_derived_media_object_reserving_fallback_secrets(
    key: &str,
    range: Option<&str>,
    uncached: bool,
    reserve_on_b2_miss: &[&str],
) -> Result<Response> {
    // Originals and derived artifacts are migrated independently. Never inherit
    // an original-only rollout flag before the artifact family is available.
    let policy = MediaReadPolicy::parse(
        get_config("derived_media_read_primary").ok().as_deref(),
        get_config("derived_media_gcs_fallback_enabled").ok().as_deref(),
    )
    .map_err(|_| BlossomError::StorageError("Invalid derived media origin policy".into()))?;
    let (mut response, source) = download_object_with_policy_reserving_fallback_secrets(
        policy,
        key,
        range,
        false,
        uncached,
        reserve_on_b2_miss,
    )?;
    // Attribute the selected transport, never an origin-supplied claim. Cached
    // downstream responses retain fill provenance, not a new provider read.
    response.set_header("X-Divine-Source", source);
    if source == "b2" {
        // Existing derivative handlers consume the GCS spellings. Preserve the
        // public provenance contract when the private storage provider changes.
        for name in ["c2pa-manifest-id", "source-sha256"] {
            if let Some(value) = response.get_header(format!("x-amz-meta-{name}")).cloned() {
                response.set_header(format!("x-goog-meta-{name}"), value);
            }
        }
    }
    Ok(response)
}

fn download_object_with_policy(
    policy: MediaReadPolicy,
    key: &str,
    range: Option<&str>,
    immutable: bool,
    uncached: bool,
) -> Result<(Response, &'static str)> {
    download_object_with_policy_reserving_fallback_secrets(
        policy,
        key,
        range,
        immutable,
        uncached,
        &[],
    )
}

fn download_object_with_policy_reserving_fallback_secrets(
    policy: MediaReadPolicy,
    key: &str,
    range: Option<&str>,
    immutable: bool,
    uncached: bool,
    reserve_on_b2_miss: &[&str],
) -> Result<(Response, &'static str)> {
    download_object_with_policy_details_reserving(
        policy,
        key,
        range,
        immutable,
        uncached,
        reserve_on_b2_miss,
    )
    .map(|result| (result.response, result.source))
}

struct MediaDownload {
    response: Response,
    source: &'static str,
    b2_missing: bool,
}

fn download_object_with_policy_details(
    policy: MediaReadPolicy,
    key: &str,
    range: Option<&str>,
    immutable: bool,
    uncached: bool,
) -> Result<MediaDownload> {
    download_object_with_policy_details_reserving(policy, key, range, immutable, uncached, &[])
}

fn download_object_with_policy_details_reserving(
    policy: MediaReadPolicy,
    key: &str,
    range: Option<&str>,
    immutable: bool,
    uncached: bool,
    reserve_on_b2_miss: &[&str],
) -> Result<MediaDownload> {
    let response = fetch_media_origin(policy.primary, key, range, immutable, uncached);
    let b2_missing = policy.primary == StorageProvider::B2
        && response
            .as_ref()
            .is_ok_and(|response| response.get_status() == StatusCode::NOT_FOUND);
    let should_fallback = match &response {
        Ok(resp) => policy.should_fallback(resp.get_status().as_u16()),
        Err(MediaFetchError::Transport) => policy.should_fallback(503),
        Err(MediaFetchError::Configuration(_)) => false,
    };
    if should_fallback {
        if b2_missing && !reserve_on_b2_miss.is_empty() {
            let mut required = Vec::with_capacity(2 + reserve_on_b2_miss.len());
            required.extend_from_slice(&["gcs_access_key", "gcs_secret_key"]);
            required.extend_from_slice(reserve_on_b2_miss);
            if !crate::request_bindings::has_secret_budget(&required) {
                eprintln!(
                    "[MEDIA_ORIGIN] primary=b2 fallback=gcs skipped=secret_budget_reserved"
                );
                return response
                    .map(|response| MediaDownload {
                        response,
                        source: policy.primary.name(),
                        b2_missing,
                    })
                    .map_err(MediaFetchError::into_storage_error);
            }
        }
        let cause = match &response {
            Ok(response) => format!("http_{}", response.get_status().as_u16()),
            Err(_) => "transport".to_string(),
        };
        eprintln!("[MEDIA_ORIGIN] primary=b2 fallback=gcs cause={cause}");
        let resp = fetch_media_origin(StorageProvider::Gcs, key, range, immutable, uncached)
            .map_err(MediaFetchError::into_storage_error)?;
        return Ok(MediaDownload {
            response: resp,
            source: SOURCE_GCS,
            b2_missing,
        });
    }
    response
        .map(|response| MediaDownload {
            response,
            source: policy.primary.name(),
            b2_missing: false,
        })
        .map_err(MediaFetchError::into_storage_error)
}

fn transient_canary_origin_error(cause: &fastly::http::request::SendErrorCause) -> bool {
    use fastly::http::request::SendErrorCause;
    matches!(
        cause,
        SendErrorCause::DnsTimeout
            | SendErrorCause::DnsError { .. }
            | SendErrorCause::DestinationUnavailable
            | SendErrorCause::DestinationIpUnroutable
            | SendErrorCause::ConnectionRefused
            | SendErrorCause::ConnectionTerminated
            | SendErrorCause::ConnectionTimeout
            | SendErrorCause::ConnectionLimitReached
            | SendErrorCause::HttpIncompleteResponse
            | SendErrorCause::HttpResponseTimeout
            | SendErrorCause::IoError(_)
    )
}

/// Strict canary reads bypass FOS, GCS fallback, and storage caches.
/// Native erasure auth proves read bucket membership in the erasure mapping.
pub(crate) fn download_canary_original(
    ready: &blossom_core::canary::Readiness,
    method: &Method,
    range: Option<&str>,
) -> Result<Response> {
    if !b2_replica_enabled() {
        return Err(BlossomError::StorageError("B2 erasure is disabled".into()));
    }
    let config = S3Config::load_b2_media()
        .map_err(|_| BlossomError::StorageError("B2 canary configuration unavailable".into()))?;
    let authorization = authorize_b2_vanish().map_err(|_| {
        BlossomError::StorageError("B2 canary erasure authorization unavailable".into())
    })?;
    if authorization.bucket_name.as_deref() != Some(config.bucket.as_str()) {
        return Err(BlossomError::StorageError(
            "B2 read and erasure buckets do not match".into(),
        ));
    }
    let version = ready
        .destination_version_id
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect::<String>();
    let mut request = Request::new(
        method.clone(),
        format!(
            "{}{}?versionId={version}",
            config.endpoint(),
            config.object_path(&ready.key)
        ),
    );
    request.set_header("Host", config.host());
    if let Some(range) = range {
        request.set_header(
            "Range",
            blossom_core::canary::normalize_origin_range(range, ready.size),
        );
    }
    request.set_pass(true);
    sign_request(&mut request, &config, Some("UNSIGNED-PAYLOAD".into()))?;
    crate::delivery_telemetry::media_origin_attempt(
        blossom_core::delivery_telemetry::Provider::B2,
    );
    let mut response = match request.send(B2_MEDIA_BACKEND) {
        Ok(response) => response,
        Err(error) if transient_canary_origin_error(error.root_cause()) => {
            return Ok(crate::canary::unavailable());
        }
        Err(_) => {
            return Err(BlossomError::StorageError(
                "B2 canary origin setup or protocol failure".into(),
            ))
        }
    };
    let status = response.get_status();
    if status == StatusCode::NOT_FOUND || status.is_server_error() {
        return Ok(crate::canary::unavailable());
    }
    if status != StatusCode::OK
        && status != StatusCode::PARTIAL_CONTENT
        && status != StatusCode::RANGE_NOT_SATISFIABLE
    {
        return Err(BlossomError::StorageError(
            "B2 canary origin rejected read".into(),
        ));
    }
    if status == StatusCode::RANGE_NOT_SATISFIABLE
        && !blossom_core::canary::unsatisfied_range_matches(
            response.get_header_str("Content-Range"),
            ready.size,
            range,
        )
    {
        return Err(BlossomError::StorageError(
            "B2 canary unsatisfied range verification failed".into(),
        ));
    }
    if status != StatusCode::RANGE_NOT_SATISFIABLE {
        if response.get_header_str("x-amz-version-id")
            != Some(ready.destination_version_id.as_str())
        {
            return Err(BlossomError::StorageError(
                "B2 canary version verification failed".into(),
            ));
        }
        if !blossom_core::canary::origin_size_matches(
            status.as_u16(),
            response.get_header_str("Content-Length"),
            response.get_header_str("Content-Range"),
            ready.size,
        ) {
            return Err(BlossomError::StorageError(
                "B2 canary size verification failed".into(),
            ));
        }
    }
    // Forward delivery headers only; origin error/authentication details stay private.
    let mut delivery = Response::from_status(status);
    for name in ["Content-Length", "Content-Range", "ETag", "Last-Modified"] {
        if let Some(value) = response.get_header(name) {
            delivery.set_header(name, value);
        }
    }
    if status == StatusCode::RANGE_NOT_SATISFIABLE {
        delivery.set_header("Content-Length", "0");
        delivery.set_header("Content-Range", format!("bytes */{}", ready.size));
    } else if *method != Method::HEAD {
        delivery.set_body(response.take_body());
    }
    Ok(delivery)
}

/// Demand mode keeps absence separate from availability and terminal errors.
pub(crate) enum CanaryOrigin {
    Delivered(Response),
    Missing,
    Unavailable,
}

/// The entire demand execution leaves room for final policy reads and enqueue.
pub(crate) const DEMAND_IO_BUDGET: Duration = Duration::from_secs(12);
const DEMAND_ATTEMPT_BUDGET: Duration = Duration::from_secs(3);

#[allow(deprecated)]
fn send_demand(request: Request, backend: &str, deadline: Instant) -> Result<Option<Response>> {
    if Instant::now() >= deadline {
        return Ok(None);
    }
    // Only actual media-origin sends update this field. Erasure authorization
    // shares this bounded send helper but is not a media fetch.
    let provider = match backend {
        B2_MEDIA_BACKEND => Some(blossom_core::delivery_telemetry::Provider::B2),
        GCS_BACKEND => Some(blossom_core::delivery_telemetry::Provider::Gcs),
        _ => None,
    };
    if let Some(provider) = provider {
        crate::delivery_telemetry::media_origin_attempt(provider);
    }
    let (request, body) = request.into_handles();
    let pending = match request.send_async_to_backend(
        body.unwrap_or_else(fastly::handle::BodyHandle::new),
        &fastly::Backend::from_name(backend).expect("valid static backend name"),
    ) {
        Ok(pending) => pending,
        Err(cause) if transient_canary_origin_error(&cause) => return Ok(None),
        Err(_) => {
            return Err(BlossomError::StorageError(
                "Demand origin setup failed".into(),
            ))
        }
    };
    if wait_for_probe_io(pending.as_u32(), deadline).is_err() {
        return Ok(None);
    }
    match pending.wait() {
        Ok((response, body)) => Ok(Some(Response::from_handles(response, body))),
        Err(cause) if transient_canary_origin_error(&cause) => Ok(None),
        Err(_) => Err(BlossomError::StorageError(
            "Demand origin protocol failed".into(),
        )),
    }
}

#[allow(deprecated)]
fn bounded_demand_body(response: Response, deadline: Instant) -> Result<Option<String>> {
    let (_, mut body) = response.into_handles();
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        if let Err(error) = wait_for_probe_io(unsafe { body.as_u32() }, deadline) {
            if error.kind() == io::ErrorKind::TimedOut {
                return Ok(None);
            }
            return Err(BlossomError::StorageError(
                "Demand authorization protocol failed".into(),
            ));
        }
        let read = match body.read(&mut chunk) {
            Ok(read) => read,
            Err(_) => return Ok(None),
        };
        if read == 0 {
            break;
        }
        if bytes.len() + read > 16384 {
            return Err(BlossomError::StorageError(
                "Demand authorization too large".into(),
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| BlossomError::StorageError("Demand authorization invalid".into()))
}

/// Internal caching remains opt-in and is called only by the demand test host.
pub(crate) fn b2_canary_cache_enabled() -> bool {
    config_flag("b2_canary_cache_enabled")
}

pub(crate) fn download_demand_b2(
    ready: &blossom_core::canary::Readiness,
    method: &Method,
    range: Option<&str>,
    deadline: Instant,
) -> Result<CanaryOrigin> {
    if !b2_replica_enabled() {
        return Err(BlossomError::StorageError("B2 erasure is disabled".into()));
    }
    let config = S3Config::load_b2_media()
        .map_err(|_| BlossomError::StorageError("B2 demand configuration unavailable".into()))?;
    let Some(authorization) = authorize_b2_vanish_with_deadline(Some(
        (Instant::now() + DEMAND_ATTEMPT_BUDGET).min(deadline),
    ))
    .map_err(|_| {
        BlossomError::StorageError("B2 demand erasure authorization unavailable".into())
    })?
    else {
        return Ok(CanaryOrigin::Unavailable);
    };
    if authorization.bucket_name.as_deref() != Some(config.bucket.as_str()) {
        return Err(BlossomError::StorageError(
            "B2 read and erasure buckets do not match".into(),
        ));
    }
    let version = ready
        .destination_version_id
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect::<String>();
    let mut request = Request::new(
        method.clone(),
        format!(
            "{}{}?versionId={version}",
            config.endpoint(),
            config.object_path(&ready.key)
        ),
    );
    request.set_header("Host", config.host());
    if let Some(range) = range {
        request.set_header(
            "Range",
            blossom_core::canary::normalize_origin_range(range, ready.size),
        );
    }
    request.set_pass(true);
    sign_request(&mut request, &config, Some("UNSIGNED-PAYLOAD".into()))?;
    let fetch = || {
        let Some(response) = send_demand(
            request,
            B2_MEDIA_BACKEND,
            (Instant::now() + DEMAND_ATTEMPT_BUDGET).min(deadline),
        )?
        else {
            return Ok(CanaryOrigin::Unavailable);
        };
        demand_delivery(
            response,
            ready.size,
            method,
            range,
            Some(&ready.destination_version_id),
        )
    };
    if b2_canary_cache_enabled() {
        crate::playback_cache::read(
            crate::playback_cache::Identity {
                source: "b2",
                host: &config.host,
                bucket: &config.bucket,
                key: &ready.key,
                hash: &ready.sha256,
                size: ready.size,
                version: Some(&ready.destination_version_id),
            },
            method,
            range,
            deadline,
            fetch,
        )
    } else {
        fetch().map(crate::playback_cache::disabled)
    }
}

/// Direct authoritative GCS only: no provider selection or FOS. A separate
/// opt-in may cache verified bytes behind the demand host's policy checks.
pub(crate) fn download_demand_gcs(
    hash: &str,
    size: u64,
    method: &Method,
    range: Option<&str>,
    deadline: Instant,
) -> Result<CanaryOrigin> {
    let config = S3Config::load_gcs()
        .map_err(|_| BlossomError::StorageError("GCS demand configuration unavailable".into()))?;
    let mut request = Request::new(
        method.clone(),
        format!("{}{}", config.endpoint(), config.object_path(hash)),
    );
    request.set_header("Host", config.host());
    if let Some(range) = range {
        request.set_header("Range", range);
    }
    request.set_pass(true);
    sign_request(&mut request, &config, Some("UNSIGNED-PAYLOAD".into()))?;
    let fetch = || {
        let Some(response) = send_demand(
            request,
            GCS_BACKEND,
            (Instant::now() + DEMAND_ATTEMPT_BUDGET).min(deadline),
        )?
        else {
            return Ok(CanaryOrigin::Unavailable);
        };
        demand_delivery(response, size, method, range, None)
    };
    if b2_canary_cache_enabled() {
        crate::playback_cache::read(
            crate::playback_cache::Identity {
                source: "gcs",
                host: &config.host,
                bucket: &config.bucket,
                key: hash,
                hash,
                size,
                version: None,
            },
            method,
            range,
            deadline,
            fetch,
        )
    } else {
        fetch().map(crate::playback_cache::disabled)
    }
}

fn demand_delivery(
    mut response: Response,
    size: u64,
    method: &Method,
    range: Option<&str>,
    version: Option<&str>,
) -> Result<CanaryOrigin> {
    let status = response.get_status();
    if status == StatusCode::NOT_FOUND || status == StatusCode::GONE {
        return Ok(CanaryOrigin::Missing);
    }
    if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        return Ok(CanaryOrigin::Unavailable);
    }
    if version.is_some()
        && status != StatusCode::RANGE_NOT_SATISFIABLE
        && (response.get_header_all("Content-Length").count() != 1
            || response.get_header_all("Content-Range").count() > 1
            || response.contains_header("Transfer-Encoding")
            || !matches!(
                response.get_header_str("Content-Encoding"),
                None | Some("identity")
            ))
    {
        return Err(BlossomError::StorageError(
            "B2 representation framing invalid".into(),
        ));
    }
    if !blossom_core::canary::demand_origin_matches(
        status.as_u16(),
        response.get_header_str("Content-Length"),
        response.get_header_str("Content-Range"),
        size,
        range,
    ) || (status != StatusCode::RANGE_NOT_SATISFIABLE
        && version.is_some_and(|v| response.get_header_str("x-amz-version-id") != Some(v)))
    {
        return Err(BlossomError::StorageError(
            "Demand origin verification failed".into(),
        ));
    }
    let mut delivery = Response::from_status(status);
    for name in ["Content-Length", "Content-Range", "ETag", "Last-Modified"] {
        if let Some(value) = response.get_header(name) {
            delivery.set_header(name, value);
        }
    }
    if status == StatusCode::RANGE_NOT_SATISFIABLE {
        delivery.set_header("Content-Length", "0");
        delivery.set_header("Content-Range", format!("bytes */{size}"));
    } else if *method != Method::HEAD {
        delivery.set_body(response.take_body());
    }
    Ok(CanaryOrigin::Delivered(delivery))
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

/// Download a thumbnail from the independently selected derived-media origin,
/// keeping one Compute secret slot available for `thumbnail_service_token` if
/// a B2 miss falls through to on-demand generation.
pub fn download_thumbnail(gcs_key: &str) -> Result<Response> {
    let resp = download_derived_media_object_reserving_fallback_secrets(
        gcs_key,
        None,
        false,
        &[crate::THUMBNAIL_SERVICE_TOKEN_SECRET],
    )?;

    match resp.get_status() {
        StatusCode::OK => Ok(resp),
        StatusCode::NOT_FOUND => Err(BlossomError::NotFound("Thumbnail not found".into())),
        status => Err(BlossomError::StorageError(format!(
            "Thumbnail download failed with status: {}",
            status
        ))),
    }
}

/// Download HLS and optimized MP4 from the selected derived-media origin.
/// The historical function name is retained for existing callers.
/// gcs_key format: {hash}/hls/{filename}
pub fn download_hls_from_gcs(gcs_key: &str, range: Option<&str>) -> Result<Response> {
    let resp = download_derived_media_object(gcs_key, range, false)?;

    match resp.get_status() {
        StatusCode::OK | StatusCode::PARTIAL_CONTENT => Ok(resp),
        StatusCode::NOT_FOUND => Err(BlossomError::NotFound("HLS content not found".into())),
        status => Err(BlossomError::StorageError(format!(
            "HLS download failed with status: {}",
            status
        ))),
    }
}

/// Download public WebVTT from the selected derived-media origin.
/// gcs_key format: {hash}/vtt/{filename}
pub fn download_transcript_from_gcs(gcs_key: &str) -> Result<Response> {
    transcript_download_response(download_derived_media_object(gcs_key, None, false)?)
}

/// Fetch current public subtitle bytes without caching (translation source).
pub fn download_transcript_uncached(gcs_key: &str) -> Result<Response> {
    transcript_download_response(download_derived_media_object(gcs_key, None, true)?)
}

/// Internal job state stays on its writer origin until coordination migrates.
/// Bypass the backend cache as well as Simple Cache.
pub fn download_transcript_uncached_from_gcs(gcs_key: &str) -> Result<Response> {
    download_transcript_object_from_gcs(gcs_key, true)
}

fn download_transcript_object_from_gcs(gcs_key: &str, uncached: bool) -> Result<Response> {
    let resp = fetch_media_origin(StorageProvider::Gcs, gcs_key, None, false, uncached)
        .map_err(MediaFetchError::into_storage_error)?;
    transcript_download_response(resp)
}

fn transcript_download_response(resp: Response) -> Result<Response> {
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

/// Download a stored sound classification (`{hash}/audio/analysis.json`).
pub fn download_sound_analysis_from_gcs(gcs_key: &str) -> Result<Response> {
    let resp = download_derived_media_object(gcs_key, None, false)?;

    match resp.get_status() {
        StatusCode::OK => Ok(resp),
        StatusCode::NOT_FOUND => Err(BlossomError::NotFound("Sound analysis not found".into())),
        status => Err(BlossomError::StorageError(format!(
            "Sound analysis download failed with status: {}",
            status
        ))),
    }
}

/// Download a blob from GCS (returns the response to stream back)
pub fn download_blob(hash: &str, range: Option<&str>) -> Result<Response> {
    let (resp, _) = download_media_object(hash, range, true, false)?;
    blob_download_response(resp)
}

fn blob_download_response(resp: Response) -> Result<Response> {
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
    /// Only a confirmed B2 404 followed by successful GCS delivery may enqueue
    /// migration. Outages and origin/configuration failures are not absence.
    pub b2_missing: bool,
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
    download_blob_with_fallback_impl(hash, range, true)
}

fn download_blob_with_fallback_impl(
    hash: &str,
    range: Option<&str>,
    immutable: bool,
) -> Result<FallbackDownloadResult> {
    let policy = media_read_policy()?;
    let primary = policy.primary;
    match download_object_with_policy_details(policy, hash, range, immutable, false)
        .and_then(|result| {
            blob_download_response(result.response)
                .map(|response| (response, result.source, result.b2_missing))
        })
    {
        Ok((resp, source, b2_missing)) => {
            return Ok(FallbackDownloadResult {
                response: resp,
                source: source.to_string(),
                diagnostics: None,
                b2_missing,
            });
        }
        Err(BlossomError::NotFound(_)) => {
            // Continue to fallback
        }
        Err(error) => {
            if primary != StorageProvider::Gcs && FALLBACK_BACKENDS.is_empty() {
                return Err(error);
            }
            // Preserve the existing GCS error-to-not-found mapping while B2 is
            // inactive. B2 errors retain their status instead of masking setup
            // and authentication failures as an absent object.
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
                    b2_missing: false,
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
    req.set_stale_if_error(0);
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
    let value = optional_config(key).ok().flatten();
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

/// Whether the approved-only B2 delivery replica participates in storage.
pub fn b2_replica_enabled() -> bool {
    config_flag(B2_REPLICA_FLAG)
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
    // Preserve the pre-0.13 policy: origin failures must not serve stale media.
    req.set_stale_if_error(0);
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
                b2_missing: false,
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
    } else if result.source == "b2" {
        diagnostics.source = Some("b2");
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

fn head_media_origin(
    provider: StorageProvider,
    key: &str,
) -> std::result::Result<Response, MediaFetchError> {
    let (config, backend) = match provider {
        StorageProvider::Gcs => (S3Config::load_gcs(), GCS_BACKEND),
        StorageProvider::B2 => (S3Config::load_b2_media(), B2_MEDIA_BACKEND),
    };
    let config = config.map_err(MediaFetchError::Configuration)?;
    let mut req = Request::new(
        Method::HEAD,
        format!("{}{}", config.endpoint(), config.object_path(key)),
    );
    req.set_stale_if_error(0);
    req.set_header("Host", config.host());
    sign_request(&mut req, &config, Some("UNSIGNED-PAYLOAD".into()))
        .map_err(MediaFetchError::Configuration)?;
    req.set_pass(true);
    req.send(backend).map_err(|_| MediaFetchError::Transport)
}

fn head_exists_status(status: StatusCode) -> Result<bool> {
    match status {
        StatusCode::OK => Ok(true),
        StatusCode::NOT_FOUND => Ok(false),
        other => Err(BlossomError::StorageError(format!(
            "Blob existence check failed with status: {other}"
        ))),
    }
}

/// Check if a blob exists in the configured primary media origin (with optional
/// GCS fallback per `media_read_primary` and `gcs_fallback_enabled`).
pub fn blob_exists(hash: &str) -> Result<bool> {
    let policy = media_read_policy()?;
    let response = head_media_origin(policy.primary, hash);
    if let Ok(ref resp) = response {
        if resp.get_status() == StatusCode::OK {
            return Ok(true);
        }
    }
    let should_fallback = match &response {
        Ok(resp) => policy.should_fallback(resp.get_status().as_u16()),
        Err(MediaFetchError::Transport) => policy.should_fallback(503),
        Err(MediaFetchError::Configuration(_)) => false,
    };
    if should_fallback {
        let cause = match &response {
            Ok(resp) => format!("http_{}", resp.get_status().as_u16()),
            Err(_) => "transport".to_string(),
        };
        eprintln!("[MEDIA_ORIGIN] op=head primary=b2 fallback=gcs cause={cause}");
        let fallback = head_media_origin(StorageProvider::Gcs, hash)
            .map_err(MediaFetchError::into_storage_error)?;
        return head_exists_status(fallback.get_status());
    }
    let resp = response.map_err(MediaFetchError::into_storage_error)?;
    head_exists_status(resp.get_status())
}

/// Check if a blob exists directly in GCS (used by legacy GCS-writing paths).
pub fn blob_exists_in_gcs(hash: &str) -> Result<bool> {
    let resp = head_media_origin(StorageProvider::Gcs, hash)
        .map_err(MediaFetchError::into_storage_error)?;
    head_exists_status(resp.get_status())
}

pub fn erasure_policy() -> Result<ErasurePolicy> {
    let gcs_erasure = optional_config("gcs_erasure_enabled")?;
    let fos_erasure = optional_config("fos_erasure_enabled")?;
    let b2_replica = optional_config(B2_REPLICA_FLAG)?;
    let media_read_primary = optional_config("media_read_primary")?;
    let gcs_fallback_enabled = optional_config("gcs_fallback_enabled")?;
    let derived_media_read_primary = optional_config("derived_media_read_primary")?;
    let derived_media_gcs_fallback_enabled =
        optional_config("derived_media_gcs_fallback_enabled")?;
    let upload_service_all_uploads = optional_config("upload_service_all_uploads")?;
    let b2_demand_mirror_enabled = optional_config("b2_demand_mirror_enabled")?;
    let fos_read = optional_config(FOS_READ_FLAG)?;
    let fos_write_back = optional_config(FOS_WRITE_BACK_FLAG)?;
    ErasurePolicy::parse(ErasurePolicyInputs {
        gcs_erasure: gcs_erasure.as_deref(),
        fos_erasure: fos_erasure.as_deref(),
        b2_replica_enabled: b2_replica.as_deref(),
        media_read_primary: media_read_primary.as_deref(),
        gcs_fallback_enabled: gcs_fallback_enabled.as_deref(),
        derived_media_read_primary: derived_media_read_primary.as_deref(),
        derived_media_gcs_fallback_enabled: derived_media_gcs_fallback_enabled.as_deref(),
        upload_service_all_uploads: upload_service_all_uploads.as_deref(),
        b2_demand_mirror_enabled: b2_demand_mirror_enabled.as_deref(),
        fos_read_enabled: fos_read.as_deref(),
        fos_write_back_enabled: fos_write_back.as_deref(),
    })
    .map_err(|error| BlossomError::StorageError(error.into()))
}

pub fn gcs_erasure_enabled() -> Result<bool> {
    Ok(erasure_policy()?.gcs_enabled)
}

pub fn fos_erasure_enabled() -> Result<bool> {
    Ok(erasure_policy()?.fos_enabled)
}

/// Delete a blob from GCS (skipped when `gcs_erasure_enabled=false` and B2 erasure is active).
pub fn delete_blob(hash: &str) -> Result<()> {
    if !gcs_erasure_enabled()? {
        return Ok(());
    }
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
/// Only explicit `fos_erasure_enabled=false` (with FOS reads/writes disabled) skips it.
pub fn delete_blob_from_fos(key: &str) -> Result<()> {
    if !fos_erasure_enabled()? {
        return Ok(());
    }
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct B2AuthorizeResponse {
    authorization_token: String,
    api_info: B2ApiInfo,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct B2ApiInfo {
    storage_api: B2StorageApi,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct B2StorageApi {
    api_url: String,
    allowed: B2Allowed,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct B2Allowed {
    #[serde(default)]
    buckets: Vec<B2AllowedBucket>,
    #[serde(default)]
    capabilities: Vec<String>,
    name_prefix: Option<String>,
}

#[derive(Debug, Deserialize)]
struct B2AllowedBucket {
    id: String,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug)]
struct B2Authorization {
    api_url: String,
    authorization_token: String,
    bucket_id: String,
    bucket_name: Option<String>,
    backend: Backend,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct B2ListFileVersionsResponse {
    files: Vec<B2FileVersion>,
    next_file_name: Option<String>,
    next_file_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct B2FileVersion {
    file_name: String,
    file_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct B2ErrorResponse {
    code: String,
}

type B2PageCursor = Option<(String, Option<String>)>;

fn b2_prefix_page<'a>(
    prefix: &str,
    page: &'a B2ListFileVersionsResponse,
) -> Result<(&'a [B2FileVersion], B2PageCursor)> {
    let matching = page
        .files
        .iter()
        .take_while(|version| version.file_name.starts_with(prefix))
        .count();
    if page.files[..matching]
        .iter()
        .any(|version| version.file_id.is_none())
        || page.files[matching..].iter().any(|version| {
            version.file_name.starts_with(prefix) || version.file_name.as_str() < prefix
        })
    {
        return Err(BlossomError::StorageError(
            "B2 version listing returned an invalid file entry".into(),
        ));
    }
    if matching < page.files.len() {
        return Ok((&page.files[..matching], None));
    }
    let cursor = match (&page.next_file_name, &page.next_file_id) {
        (Some(file_name), Some(file_id)) if file_name.starts_with(prefix) => {
            Some((file_name.clone(), Some(file_id.clone())))
        }
        (Some(file_name), None) if file_name.starts_with(prefix) => {
            return Err(BlossomError::StorageError(
                "B2 version listing returned an incomplete pagination cursor".into(),
            ))
        }
        (Some(file_name), _) if file_name.as_str() < prefix => {
            return Err(BlossomError::StorageError(
                "B2 version listing cursor moved before the requested prefix".into(),
            ))
        }
        (None, Some(_)) => {
            return Err(BlossomError::StorageError(
                "B2 version listing returned an incomplete pagination cursor".into(),
            ))
        }
        _ => None,
    };
    Ok((&page.files[..matching], cursor))
}

#[derive(Debug)]
struct VanishDeleteBatch {
    stage: String,
    keys: Vec<String>,
}

#[derive(Debug, Default, serde::Serialize)]
pub(crate) struct VanishStorageTimings {
    pub cloud_run_cleanup_ms: u64,
    pub fos_main_ms: u64,
    pub b2_replica_ms: u64,
    pub purge_vcl_ms: u64,
    pub purge_compute_ms: u64,
    pub purge_bunny_ms: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DeliveryProbeCounts {
    pub checked: u32,
    /// 2xx responses: an edge cache still serves an erased object.
    pub present: u32,
    /// Non-2xx, non-404 responses from completed probes.
    pub inconclusive: u32,
    /// 1 when the probe could not complete at all: missing credential,
    /// transport failure, non-2xx response, or malformed response body.
    pub errors: u32,
    pub ms: u64,
}

#[derive(Debug, Default)]
pub(crate) struct VanishStorageResult {
    pub failed_hashes: HashSet<String>,
    /// Hashes whose purge was accepted by every enabled CDN service in
    /// this batch. The post-purge delivery probe samples only these, because a
    /// hash the purge could not reach is not expected to be absent yet.
    pub purged_hashes: HashSet<String>,
    /// Hashes whose provider version set exceeded one bounded slice. Their deletion is
    /// progressing, so they are pending work rather than failures.
    pub remaining_hashes: HashSet<String>,
    /// True when inline Fastly vanish purge was deferred to `Phase::Final`
    /// drain to stay within Fastly Compute's 5-secret per-request limit.
    pub purge_deferred: bool,
    pub timings: VanishStorageTimings,
}

impl VanishStorageResult {
    pub(crate) fn replace_failures_after_retry(&mut self, retry: Self) {
        self.failed_hashes = retry.failed_hashes;
        self.purged_hashes.extend(retry.purged_hashes);
        self.remaining_hashes = retry.remaining_hashes;
        self.purge_deferred |= retry.purge_deferred;
        self.timings.cloud_run_cleanup_ms = self
            .timings
            .cloud_run_cleanup_ms
            .saturating_add(retry.timings.cloud_run_cleanup_ms);
        self.timings.fos_main_ms = self
            .timings
            .fos_main_ms
            .saturating_add(retry.timings.fos_main_ms);
        self.timings.b2_replica_ms = self
            .timings
            .b2_replica_ms
            .saturating_add(retry.timings.b2_replica_ms);
        self.timings.purge_vcl_ms = self
            .timings
            .purge_vcl_ms
            .saturating_add(retry.timings.purge_vcl_ms);
        self.timings.purge_compute_ms = self
            .timings
            .purge_compute_ms
            .saturating_add(retry.timings.purge_compute_ms);
        self.timings.purge_bunny_ms = self
            .timings
            .purge_bunny_ms
            .saturating_add(retry.timings.purge_bunny_ms);
    }
}

fn b2_api_host(api_url: &str) -> Result<&str> {
    let host = api_url.strip_prefix("https://").ok_or_else(|| {
        BlossomError::StorageError("B2 authorization returned a non-HTTPS API URL".into())
    })?;
    if host.is_empty()
        || host.contains('/')
        || (!host.eq("api.backblazeb2.com") && !host.ends_with(".backblazeb2.com"))
    {
        return Err(BlossomError::StorageError(
            "B2 authorization returned an invalid API host".into(),
        ));
    }
    Ok(host)
}

fn b2_dynamic_backend_name(host: &str) -> String {
    format!("b2-api-{}", &hex::encode(Sha256::digest(host.as_bytes()))[..16])
}

fn b2_storage_backend(host: &str) -> Result<Backend> {
    use fastly::backend::BackendCreationError;

    let name = b2_dynamic_backend_name(host);
    match Backend::builder(&name, host)
        .max_connections(0)
        .override_host(host)
        .enable_ssl()
        .check_certificate(host)
        .sni_hostname(host)
        .finish()
    {
        Ok(backend) => Ok(backend),
        Err(BackendCreationError::NameInUse) => Backend::from_name(&name).map_err(|error| {
            BlossomError::StorageError(format!("Failed to reuse B2 API backend: {error}"))
        }),
        Err(error) => Err(BlossomError::StorageError(format!(
            "Failed to create B2 API backend: {error}"
        ))),
    }
}

fn validate_b2_authorization_scope(
    response: &B2AuthorizeResponse,
    expected_bucket_id: &str,
) -> Result<()> {
    let storage = &response.api_info.storage_api;
    b2_api_host(&storage.api_url)?;
    let expected_capabilities = ["deleteFiles", "listFiles"];
    if storage.allowed.buckets.len() != 1
        || storage.allowed.buckets[0].id != expected_bucket_id
        || storage.allowed.name_prefix.is_some()
        || storage.allowed.capabilities.len() != expected_capabilities.len()
        || !expected_capabilities.iter().all(|required| {
            storage
                .allowed
                .capabilities
                .iter()
                .any(|actual| actual == required)
        })
    {
        return Err(BlossomError::StorageError(
            "B2 vanish credential is not restricted to the configured bucket and required capabilities"
                .into(),
        ));
    }
    if response.authorization_token.is_empty() {
        return Err(BlossomError::StorageError(
            "B2 authorization returned an empty token".into(),
        ));
    }
    Ok(())
}

fn validate_b2_authorization(
    response: B2AuthorizeResponse,
    expected_bucket_id: &str,
) -> Result<B2Authorization> {
    validate_b2_authorization_scope(&response, expected_bucket_id)?;
    let storage = response.api_info.storage_api;
    let host = b2_api_host(&storage.api_url)?;
    let backend = b2_storage_backend(host)?;
    let bucket_name = storage.allowed.buckets[0].name.clone();
    Ok(B2Authorization {
        api_url: storage.api_url,
        authorization_token: response.authorization_token,
        bucket_id: expected_bucket_id.to_string(),
        bucket_name,
        backend,
    })
}

fn authorize_b2_vanish() -> Result<B2Authorization> {
    authorize_b2_vanish_with_deadline(None)?
        .ok_or_else(|| BlossomError::StorageError("B2 authorization unavailable".into()))
}

/// Only demand mode treats authorization transport/429/5xx as availability.
/// Strict reads and erasure retain their existing fail-closed error contract.
fn authorize_b2_vanish_with_deadline(deadline: Option<Instant>) -> Result<Option<B2Authorization>> {
    let key_id = get_secret("b2_vanish_application_key_id")?;
    let application_key = get_secret("b2_vanish_application_key")?;
    let bucket_id = get_config("b2_bucket_id")?;
    request_b2_authorization(&key_id, &application_key, deadline)?
        .map(|authorization| validate_b2_authorization(authorization, &bucket_id))
        .transpose()
}

fn request_b2_authorization(
    key_id: &str,
    application_key: &str,
    deadline: Option<Instant>,
) -> Result<Option<B2AuthorizeResponse>> {
    use base64::Engine as _;
    let basic =
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", key_id, application_key));
    let mut request = Request::get("https://api.backblazeb2.com/b2api/v4/b2_authorize_account");
    request.set_header("Host", "api.backblazeb2.com");
    request.set_header("Authorization", format!("Basic {}", basic));
    request.set_pass(true);
    let mut response = if let Some(deadline) = deadline {
        let Some(response) = send_demand(request, B2_API_BACKEND, deadline)? else {
            return Ok(None);
        };
        response
    } else {
        request.send(B2_API_BACKEND).map_err(|error| {
            BlossomError::StorageError(format!("B2 authorization failed: {error}"))
        })?
    };
    if deadline.is_some()
        && (response.get_status() == StatusCode::TOO_MANY_REQUESTS
            || response.get_status().is_server_error())
    {
        return Ok(None);
    }
    if !response.get_status().is_success() {
        return Err(BlossomError::StorageError(format!(
            "B2 authorization failed with status: {}",
            response.get_status()
        )));
    }
    let body = if let Some(deadline) = deadline {
        let Some(body) = bounded_demand_body(response, deadline)? else {
            return Ok(None);
        };
        body
    } else {
        response.take_body().into_string()
    };
    let authorization = serde_json::from_str(&body).map_err(|error| {
        BlossomError::StorageError(format!("Invalid B2 authorization response: {error}"))
    })?;
    Ok(Some(authorization))
}

fn build_b2_list_versions_request(
    authorization: &B2Authorization,
    prefix: &str,
    start: Option<(&str, Option<&str>)>,
) -> Result<Request> {
    let host = b2_api_host(&authorization.api_url)?;
    let mut body = serde_json::json!({
        "bucketId": authorization.bucket_id,
        "prefix": prefix,
        "maxFileCount": B2_LIST_PAGE_SIZE,
    });
    if let Some((file_name, file_id)) = start {
        body["startFileName"] = serde_json::json!(file_name);
        if let Some(file_id) = file_id {
            body["startFileId"] = serde_json::json!(file_id);
        }
    }
    let body = body.to_string();
    let mut request = Request::post(format!(
        "{}/b2api/v4/b2_list_file_versions",
        authorization.api_url
    ));
    request.set_header("Host", host);
    request.set_header("Authorization", &authorization.authorization_token);
    request.set_header("Content-Type", "application/json");
    request.set_header("Content-Length", body.len().to_string());
    request.set_body(body);
    Ok(request)
}

fn list_b2_file_versions(
    authorization: &B2Authorization,
    prefix: &str,
    start: Option<(&str, Option<&str>)>,
) -> Result<B2ListFileVersionsResponse> {
    let request = build_b2_list_versions_request(authorization, prefix, start)?;
    let mut response = request.send(authorization.backend.clone()).map_err(|error| {
        BlossomError::StorageError(format!("B2 version listing failed: {error}"))
    })?;
    if !response.get_status().is_success() {
        return Err(BlossomError::StorageError(format!(
            "B2 version listing failed with status: {}",
            response.get_status()
        )));
    }
    serde_json::from_str(&response.take_body().into_string()).map_err(|error| {
        BlossomError::StorageError(format!("Invalid B2 version listing response: {error}"))
    })
}

fn build_b2_delete_version_request(
    authorization: &B2Authorization,
    version: &B2FileVersion,
) -> Result<Request> {
    let file_id = version.file_id.as_deref().ok_or_else(|| {
        BlossomError::StorageError("B2 version listing returned a file without an ID".into())
    })?;
    let host = b2_api_host(&authorization.api_url)?;
    let body = serde_json::json!({
        "fileName": version.file_name,
        "fileId": file_id,
    })
    .to_string();
    let mut request = Request::post(format!(
        "{}/b2api/v4/b2_delete_file_version",
        authorization.api_url
    ));
    request.set_header("Host", host);
    request.set_header("Authorization", &authorization.authorization_token);
    request.set_header("Content-Type", "application/json");
    request.set_header("Content-Length", body.len().to_string());
    request.set_body(body);
    Ok(request)
}

fn b2_delete_version_succeeded(mut response: Response) -> bool {
    if response.get_status().is_success() {
        return true;
    }
    response.get_status() == StatusCode::BAD_REQUEST
        && serde_json::from_str::<B2ErrorResponse>(&response.take_body().into_string())
            .is_ok_and(|error| error.code == "file_not_present")
}

fn delete_b2_version_page(
    authorization: &B2Authorization,
    versions: &[B2FileVersion],
) -> Result<()> {
    let mut pending = Vec::with_capacity(versions.len());
    for version in versions {
        let request = build_b2_delete_version_request(authorization, version)?;
        pending.push(request.send_async(authorization.backend.clone()).map_err(|error| {
            BlossomError::StorageError(format!("B2 version delete failed to start: {error}"))
        })?);
    }
    let mut failed = false;
    while !pending.is_empty() {
        let (response, remaining) = fastly::http::request::select(pending);
        pending = remaining;
        match response {
            Ok(response) => {
                let status = response.get_status();
                if !b2_delete_version_succeeded(response) {
                    eprintln!("[VANISH] B2 version delete failed status={status}");
                    failed = true;
                }
            }
            Err(error) => {
                eprintln!("[VANISH] B2 version delete failed error={error}");
                failed = true;
            }
        }
    }
    if failed {
        Err(BlossomError::StorageError(
            "One or more B2 version deletes failed".into(),
        ))
    } else {
        Ok(())
    }
}

/// Outcome of one bounded B2 hash erasure attempt.
enum B2HashErasure {
    /// Every listed version was deleted and absence was confirmed.
    Erased,
    /// At least one namespace holds more versions than this attempt can
    /// delete or observes late versions. Caller retries continue the drain.
    MoreRemaining,
}

fn erase_b2_hash_versions(authorization: &B2Authorization, hash: &str) -> Result<B2HashErasure> {
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BlossomError::StorageError("Invalid B2 erasure hash".into()));
    }
    crate::metadata::claim_b2_erasure(hash)?;
    // The private parent namespace is deliberately outside the media prefix.
    // The trailing slash isolates adjacent parent names and includes every
    // control object, including retained completion-marker versions.
    let private_prefix = format!("_private/artifact-families/v1/{hash}/");
    let prefixes = [hash, private_prefix.as_str()];
    // Resolve both inventories before any delete: an unreadable private
    // namespace cannot silently become evidence of complete erasure.
    let pages = prefixes
        .iter()
        .map(|prefix| list_b2_file_versions(authorization, prefix, Some((prefix, None))))
        .collect::<Result<Vec<_>>>()?;
    let inventories = prefixes
        .iter()
        .zip(&pages)
        .map(|(prefix, page)| b2_prefix_page(prefix, page))
        .collect::<Result<Vec<_>>>()?;
    let mut delete_budget = B2_ERASE_DELETES_PER_HASH;
    let mut remaining = false;
    for (versions, next) in inventories {
        let count = versions.len().min(delete_budget);
        delete_b2_version_page(authorization, &versions[..count])?;
        delete_budget -= count;
        remaining |= count < versions.len() || next.is_some();
    }
    if remaining {
        return Ok(B2HashErasure::MoreRemaining);
    }
    // Completion requires confirmed absence in both namespaces. Observed
    // late versions are pending; uncertain listing/deletion stays an error.
    for prefix in prefixes {
        let confirmation = list_b2_file_versions(authorization, prefix, Some((prefix, None)))?;
        let (versions, next) = b2_prefix_page(prefix, &confirmation)?;
        if !versions.is_empty() || next.is_some() {
            return Ok(B2HashErasure::MoreRemaining);
        }
    }
    Ok(B2HashErasure::Erased)
}

/// Returns `(failed, remaining)` hashes. `remaining` hashes made bounded
/// progress and are counted as pending, not failed.
fn erase_b2_replica_hashes(hashes: &[String]) -> (HashSet<String>, HashSet<String>) {
    if !b2_replica_enabled() || hashes.is_empty() {
        return (HashSet::new(), HashSet::new());
    }
    let authorization = match authorize_b2_vanish() {
        Ok(authorization) => authorization,
        Err(error) => {
            eprintln!("[VANISH] B2 setup failed error={error}");
            return (hashes.iter().cloned().collect(), HashSet::new());
        }
    };
    let mut failed = HashSet::new();
    let mut remaining = HashSet::new();
    for hash in hashes {
        match erase_b2_hash_versions(&authorization, hash) {
            Ok(B2HashErasure::Erased) => {}
            Ok(B2HashErasure::MoreRemaining) => {
                remaining.insert(hash.clone());
            }
            Err(error) => {
                eprintln!("[VANISH] B2 erase failed hash={hash} error={error}");
                failed.insert(hash.clone());
            }
        }
    }
    (failed, remaining)
}

/// Creator deletion must erase the same B2 version set as account vanish.
pub(crate) fn erase_b2_creator_replica(hash: &str) -> Result<()> {
    let (failed, remaining) = erase_b2_replica_hashes(&[hash.to_string()]);
    if failed.is_empty() && remaining.is_empty() {
        Ok(())
    } else {
        Err(BlossomError::StorageError(
            "B2 replica erasure incomplete; retry required".into(),
        ))
    }
}

const BUNNY_PUBLISH_FLAG: &str = "bunny_pilot_publish_enabled";
const BUNNY_PILOT_HOSTS: &str = "bunny_pilot_zone_hosts";
const BUNNY_RETAINED_HOSTS: &str = "bunny-pilot-retained-hosts:v1";
const BUNNY_ENROLLED_PREFIX: &str = "bunny-pilot-enrolled:v1:";

pub(crate) fn bunny_pilot_enrolled(hash: &str) -> Result<bool> {
    let entry = crate::kv_origin::lookup(&format!("{BUNNY_ENROLLED_PREFIX}{hash}"))?
        .ok_or_else(|| BlossomError::MetadataError("Bunny enrollment origin unavailable".into()))?;
    match entry {
        None => Ok(false),
        Some(entry) if entry.body == b"1" => Ok(true),
        Some(_) => Err(BlossomError::MetadataError("Invalid Bunny enrollment record".into())),
    }
}

pub(crate) fn bunny_pilot_config_present() -> Result<bool> {
    Ok(optional_config(BUNNY_PILOT_HOSTS)?.is_some()
        || optional_config(BUNNY_PUBLISH_FLAG)?.as_deref() == Some("true"))
}

pub(crate) fn bunny_pilot_configured() -> Result<bool> {
    Ok(bunny_pilot_config_present()?
        || retained_bunny_pilot_hosts()?.is_some()
        || origin_bunny_pilot_hosts()?.is_some())
}

fn checked_bunny_hosts(hosts: String) -> Result<String> {
    if blossom_core::bunny_pilot::zone_hosts(&hosts).is_none() {
        return Err(BlossomError::StorageError(
            "Invalid retained Bunny pilot hosts".into(),
        ));
    }
    Ok(hosts)
}

fn retained_bunny_pilot_hosts() -> Result<Option<String>> {
    use fastly::kv_store::KVStoreError;
    match crate::metadata::open_store()?.lookup(BUNNY_RETAINED_HOSTS) {
        Ok(mut entry) => checked_bunny_hosts(entry.take_body().into_string()).map(Some),
        Err(KVStoreError::ItemNotFound) => Ok(None),
        Err(_) => Err(BlossomError::MetadataError(
            "Bunny target record unavailable".into(),
        )),
    }
}

fn bunny_pilot_hosts() -> Result<String> {
    if let Some(hosts) = retained_bunny_pilot_hosts()? {
        return Ok(hosts);
    }
    if let Some(hosts) = origin_bunny_pilot_hosts()? {
        return Ok(hosts);
    }
    checked_bunny_hosts(get_config(BUNNY_PILOT_HOSTS)?)
}

pub(crate) fn origin_bunny_pilot_hosts() -> Result<Option<String>> {
    crate::request_bindings::cached_origin_kv(BUNNY_RETAINED_HOSTS, || {
        let Some(Some(entry)) = crate::kv_origin::lookup(BUNNY_RETAINED_HOSTS)? else {
            return Ok(None);
        };
        let hosts = String::from_utf8(entry.body)
            .map_err(|_| BlossomError::MetadataError("Invalid Bunny target record".into()))?;
        checked_bunny_hosts(hosts).map(Some)
    })
}

fn retain_bunny_pilot_hosts() -> Result<()> {
    use fastly::kv_store::{InsertMode, KVStoreError};
    let hosts = checked_bunny_hosts(get_config(BUNNY_PILOT_HOSTS)?)?;
    let store = crate::metadata::open_store()?;
    match crate::metadata::retry_throttled_write(|| {
        store
            .build_insert()
            .mode(InsertMode::Add)
            .execute(BUNNY_RETAINED_HOSTS, hosts.clone())
    })
    {
        Ok(()) => {
            crate::request_bindings::invalidate_cached_origin_kv(BUNNY_RETAINED_HOSTS);
            Ok(())
        }
        Err(KVStoreError::ItemPreconditionFailed) => {
            // A publication from a different POP cannot drop the earlier
            // zone's eviction obligation by replacing its hostnames.
            match crate::kv_origin::lookup(BUNNY_RETAINED_HOSTS)? {
                Some(Some(entry)) if entry.body == hosts.as_bytes() => Ok(()),
                _ => Err(BlossomError::Conflict(
                    "Bunny targets differ from the retained pilot".into(),
                )),
            }
        }
        Err(_) => Err(BlossomError::MetadataError(
            "Bunny target record unavailable".into(),
        )),
    }
}

pub(crate) fn validate_bunny_pilot_publication() -> Result<()> {
    if !config_flag(BUNNY_PUBLISH_FLAG) || !b2_replica_enabled() {
        return Err(BlossomError::NotFound(
            "Bunny pilot publication disabled".into(),
        ));
    }
    let configured = checked_bunny_hosts(get_config(BUNNY_PILOT_HOSTS)?)?;
    if retained_bunny_pilot_hosts()?.is_some_and(|retained| retained != configured) {
        return Err(BlossomError::Conflict(
            "Bunny targets differ from the retained pilot".into(),
        ));
    }
    if pilot_cleanup()?.fastly_api_token.trim().is_empty() {
        return Err(BlossomError::StorageError("Canonical purge credential unavailable".into()));
    }
    bunny_pilot_purge_key()?;
    if get_secret("bunny_pilot_worker_token")?.len() < 32 {
        return Err(BlossomError::StorageError("Bunny worker token unavailable".into()));
    }
    Ok(())
}

pub(crate) fn bunny_scope() -> Result<blossom_core::bunny_worker::Scope> {
    let primary = |key| {
        MediaReadPolicy::parse(optional_config(key)?.as_deref(), None)
            .map(|p| p.primary)
            .map_err(|_| BlossomError::StorageError("Invalid Bunny source primary".into()))
    };
    let original = primary("media_read_primary")?;
    let derivative = primary("derived_media_read_primary")?;
    Ok(blossom_core::bunny_worker::Scope {
        original,
        derivative,
        gcs_bucket: if [original, derivative].contains(&StorageProvider::Gcs) {
            Some(get_config("gcs_bucket")?)
        } else {
            None
        },
        b2_bucket: get_config("b2_media_bucket")?,
        b2_bucket_id: get_config("b2_bucket_id")?,
        b2_region: get_config("b2_media_region")?,
    })
}

/// HEAD only the current canonical derivatives of a scope-validated ready record.
/// The producer can replace them before either queued status callback arrives.
pub(crate) struct BunnySourceHeads {
    header: &'static str,
    requests: Vec<(fastly::handle::PendingRequestHandle, String)>,
}

impl BunnySourceHeads {
    #[allow(deprecated)] // Use the pending handle to enforce one deadline across all HEADs.
    pub(crate) fn start(
        parent: &str,
        assets: &[blossom_core::bunny_worker::Verified],
        deadline: Instant,
    ) -> Option<Self> {
        let mut sources = assets
            .iter()
            .map(|v| &v.source)
            .filter(|s| s.key != parent)
            .peekable();
        let provider = sources.peek()?.provider;
        let (config, backend, header) = match provider {
            StorageProvider::B2 => (
                S3Config::load_b2_media().ok()?,
                B2_MEDIA_BACKEND,
                "x-amz-version-id",
            ),
            StorageProvider::Gcs => (S3Config::load_gcs().ok()?, GCS_BACKEND, "x-goog-generation"),
        };
        let mut requests = Vec::new();
        for source in sources {
            if Instant::now() >= deadline
                || source.provider != provider
                || source.bucket != config.bucket
            {
                return None;
            }
            let expected = source.version.clone()?;
            let mut request = Request::head(format!(
                "{}{}",
                config.endpoint(),
                config.object_path(&source.key)
            ));
            request.set_header("Host", config.host());
            request.set_pass(true);
            sign_request(&mut request, &config, Some("UNSIGNED-PAYLOAD".into())).ok()?;
            let (request, body) = request.into_handles();
            let pending = request
                .send_async_to_backend(
                    body.unwrap_or_else(fastly::handle::BodyHandle::new),
                    &fastly::Backend::from_name(backend).expect("valid static backend name"),
                )
                .ok()?;
            requests.push((pending, expected));
        }
        Some(Self { header, requests })
    }

    #[allow(deprecated)]
    pub(crate) fn matches(self, deadline: Instant) -> bool {
        self.requests.into_iter().all(|(pending, expected)| {
            if wait_for_probe_io(pending.as_u32(), deadline).is_err() {
                return false;
            }
            let Ok((response, body)) = pending.wait() else {
                return false;
            };
            let response = Response::from_handles(response, body);
            let mut versions = response.get_header_all(self.header);
            response.get_status() == StatusCode::OK
                && versions
                    .next()
                    .is_some_and(|v| v.as_bytes() == expected.as_bytes())
                && versions.next().is_none()
        })
    }
}

/// Retain every target and verify erasure capability before asking the worker to write.
pub(crate) fn enroll_bunny_parent(hash: &str) -> Result<()> {
    if authorize_pilot_erasure()?.bucket_name.as_deref() != Some(&get_config("b2_media_bucket")?) {
        return Err(BlossomError::StorageError(
            "Bunny erasure bucket mismatch".into(),
        ));
    }
    retain_bunny_pilot_hosts()?;
    let store = crate::metadata::open_store()?;
    let enrollment = format!("{BUNNY_ENROLLED_PREFIX}{hash}");
    crate::metadata::retry_throttled_write(|| store.insert(&enrollment, "1"))
        .map_err(|_| BlossomError::MetadataError("Bunny enrollment record unavailable".into()))
}

fn authorize_pilot_erasure() -> Result<B2Authorization> {
    let eraser = pilot_cleanup()?.eraser;
    let authorization =
        request_b2_authorization(&eraser.id, &eraser.key, None)?.ok_or_else(|| {
            BlossomError::StorageError("Pilot erasure authorization unavailable".into())
        })?;
    validate_b2_authorization(authorization, &get_config("b2_bucket_id")?)
}

fn remove_bunny_delivery_copies(
    hash: &str,
    delete_limit: usize,
    check_gate: &dyn Fn() -> Result<()>,
) -> Result<()> {
    use blossom_core::bunny_pilot::{Asset, DELIVERY_PREFIX};
    let path = format!("/{hash}");
    let asset = Asset::parse(&path)
        .ok_or_else(|| BlossomError::BadRequest("Invalid Bunny revocation hash".into()))?;
    crate::bunny_ready::invalidate(hash)?;
    let prefix = asset.delivery_key();
    let authorization = authorize_pilot_erasure()?;
    let bucket = get_config("b2_media_bucket")?;
    if authorization.bucket_name.as_deref() != Some(bucket.as_str()) {
        return Err(BlossomError::StorageError(
            "Bunny erasure bucket mismatch".into(),
        ));
    }
    let list = || list_b2_file_versions(&authorization, &prefix, Some((&prefix, None)));
    check_gate()?;
    let page = list()?;
    let (versions, next) = b2_prefix_page(&prefix, &page)?;
    if versions.iter().any(|version| {
        let path = version
            .file_name
            .strip_prefix(DELIVERY_PREFIX)
            .map(|path| format!("/{path}"));
        path.as_deref()
            .and_then(Asset::parse)
            .is_none_or(|asset| asset.hash() != hash)
    }) {
        return Err(BlossomError::StorageError(
            "Unexpected Bunny delivery key".into(),
        ));
    }
    let count = versions.len().min(delete_limit);
    check_gate()?;
    delete_b2_version_page(&authorization, &versions[..count])?;
    if count < versions.len() || next.is_some() {
        return Err(BlossomError::StorageError(
            "Bunny delivery versions remain; retry required".into(),
        ));
    }
    let confirmation = list()?;
    let (versions, next) = b2_prefix_page(&prefix, &confirmation)?;
    if !versions.is_empty() || next.is_some() {
        return Err(BlossomError::StorageError(
            "Bunny delivery versions remain; retry required".into(),
        ));
    }
    Ok(())
}

fn bunny_pilot_purge_key() -> Result<String> {
    let key = pilot_cleanup()?.bunny_api_key;
    if key.is_empty() {
        return Err(BlossomError::StorageError(
            "Bunny purge credential unavailable".into(),
        ));
    }
    Ok(key)
}

fn send_bunny_purge_rounds(requests: &[Request], error_message: &'static str) -> Result<()> {
    let mut failed = false;
    for round in 0..2 {
        let mut pending = Vec::new();
        for template in requests {
            match template.clone_without_body().send_async(BUNNY_API_BACKEND) {
                Ok(handle) => pending.push(handle),
                Err(_) => failed = true,
            }
        }
        while !pending.is_empty() {
            let (response, remaining) = fastly::http::request::select(pending);
            pending = remaining;
            failed |= !matches!(response, Ok(response) if response.get_status().is_success());
        }
        if round == 0 {
            wait_b2_cdn_purge_interval()?;
        }
    }
    if failed {
        return Err(BlossomError::StorageError(error_message.into()));
    }
    Ok(())
}

fn purge_bunny_pilot_hosts(hashes: &[String], raw_hosts: &str) -> Result<()> {
    validate_b2_cdn_purge_batch(hashes)?;
    let hosts = blossom_core::bunny_pilot::zone_hosts(raw_hosts)
        .ok_or_else(|| BlossomError::StorageError("Invalid retained Bunny pilot hosts".into()))?;
    let key = bunny_pilot_purge_key()?;
    let requests = hashes
        .iter()
        .flat_map(|hash| {
            let hash = hash.to_ascii_lowercase();
            let key = &key;
            hosts
                .iter()
                .map(move |host| build_bunny_purge_request(host, &hash, key, "bunny-pilot"))
        })
        .collect::<Vec<_>>();
    send_bunny_purge_rounds(&requests, "Bunny pilot eviction incomplete; retry required")
}

const BUNNY_DELIVERY_RETAINED_ZONES: &str = "bunny-delivery-retained-zones:v1";
const MAX_RETAINED_BUNNY_DELIVERY_ZONES: usize = 4;

fn is_valid_bunny_hostname(zone: &str) -> bool {
    if zone.is_empty() || zone.len() > 253 || !zone.contains('.') {
        return false;
    }
    zone.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && label
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphanumeric())
            && label
                .bytes()
                .last()
                .is_some_and(|b| b.is_ascii_alphanumeric())
    })
}

fn parse_bunny_delivery_zone_list(raw: &str, max_zones: usize) -> Result<Vec<String>> {
    let mut zones = Vec::new();
    for segment in raw.split(',') {
        let zone = segment.trim().to_ascii_lowercase();
        if zone.is_empty() || !is_valid_bunny_hostname(&zone) || zones.contains(&zone) {
            return Err(BlossomError::StorageError(format!(
                "bunny_delivery_zones must contain 1..={max_zones} distinct comma-separated hostnames"
            )));
        }
        zones.push(zone);
    }
    if zones.is_empty() || zones.len() > max_zones {
        return Err(BlossomError::StorageError(format!(
            "bunny_delivery_zones must contain 1..={max_zones} distinct comma-separated hostnames (got {})",
            zones.len()
        )));
    }
    Ok(zones)
}

fn parse_bunny_delivery_zones(raw: &str) -> Result<Vec<String>> {
    parse_bunny_delivery_zone_list(raw, MAX_BUNNY_DELIVERY_ZONES)
}

fn parse_retained_bunny_delivery_zones(raw: &str) -> Result<Vec<String>> {
    parse_bunny_delivery_zone_list(raw, MAX_RETAINED_BUNNY_DELIVERY_ZONES)
}

fn fetch_origin_bunny_delivery_entry() -> Result<(Option<String>, Option<u64>)> {
    match crate::kv_origin::lookup(BUNNY_DELIVERY_RETAINED_ZONES)? {
        None => Ok((None, None)),
        Some(None) => Ok((Some(String::new()), None)),
        Some(Some(entry)) => {
            let value = String::from_utf8(entry.body).map_err(|_| {
                BlossomError::MetadataError("Invalid Bunny delivery target record".into())
            })?;
            parse_retained_bunny_delivery_zones(&value)?;
            Ok((Some(value), Some(entry.generation)))
        }
    }
}

fn origin_bunny_delivery_zones() -> Result<Option<Option<Vec<String>>>> {
    // Distinguish "kv_origin unconfigured" (`Ok(None)`) from "authoritatively
    // absent at origin" (`Ok(Some(None))`) so callers only fall back to local
    // edge KV when KV-origin reads are disabled.
    let (cached, _) = crate::request_bindings::cached_origin_kv_with_gen(
        BUNNY_DELIVERY_RETAINED_ZONES,
        fetch_origin_bunny_delivery_entry,
    )?;
    match cached {
        None => Ok(None),
        Some(empty) if empty.is_empty() => Ok(Some(None)),
        Some(value) => parse_retained_bunny_delivery_zones(&value).map(|z| Some(Some(z))),
    }
}

fn retained_bunny_delivery_zones() -> Result<Option<Vec<String>>> {
    use fastly::kv_store::KVStoreError;
    // `bunny-delivery-retained-zones:v1` can grow via CAS merge on rotation.
    // When KV-origin reads are configured, read from origin (cached once per
    // request) so a stale POP never silently drops a rotated zone.
    if let Some(authoritative) = origin_bunny_delivery_zones()? {
        return Ok(authoritative);
    }
    match crate::metadata::open_store()?.lookup(BUNNY_DELIVERY_RETAINED_ZONES) {
        Ok(mut entry) => {
            parse_retained_bunny_delivery_zones(&entry.take_body().into_string()).map(Some)
        }
        Err(KVStoreError::ItemNotFound) => Ok(None),
        Err(_) => Err(BlossomError::MetadataError(
            "Bunny delivery target record unavailable".into(),
        )),
    }
}

fn merge_retained_bunny_delivery_zones(
    existing: &[String],
    configured: &[String],
) -> Result<Option<Vec<String>>> {
    let mut merged = existing.to_vec();
    let mut changed = false;
    for zone in configured {
        if !merged.contains(zone) {
            merged.push(zone.clone());
            changed = true;
        }
    }
    if !changed {
        return Ok(None);
    }
    if merged.len() > MAX_RETAINED_BUNNY_DELIVERY_ZONES {
        return Err(BlossomError::Conflict(
            "Too many retained Bunny delivery zones; retire old zones after cache drain".into(),
        ));
    }
    Ok(Some(merged))
}

fn lookup_local_retained_bunny_delivery_with_generation(
    store: &fastly::kv_store::KVStore,
) -> Result<Option<(Vec<String>, u64)>> {
    use fastly::kv_store::KVStoreError;
    match store.build_lookup().execute(BUNNY_DELIVERY_RETAINED_ZONES) {
        Ok(mut entry) => {
            let generation = entry.current_generation();
            let zones = parse_retained_bunny_delivery_zones(&entry.take_body().into_string())?;
            Ok(Some((zones, generation)))
        }
        Err(KVStoreError::ItemNotFound) => Ok(None),
        Err(_) => Err(BlossomError::MetadataError(
            "Bunny delivery target record unavailable".into(),
        )),
    }
}

fn lookup_origin_retained_bunny_delivery_with_generation(
    store: &fastly::kv_store::KVStore,
    use_cached_origin: bool,
) -> Result<(Option<(Vec<String>, u64)>, bool)> {
    let origin_entry = if use_cached_origin {
        crate::request_bindings::cached_origin_kv_with_gen(
            BUNNY_DELIVERY_RETAINED_ZONES,
            fetch_origin_bunny_delivery_entry,
        )?
    } else {
        let fresh = fetch_origin_bunny_delivery_entry()?;
        crate::request_bindings::invalidate_cached_origin_kv(BUNNY_DELIVERY_RETAINED_ZONES);
        fresh
    };
    match origin_entry {
        (Some(empty), _) if empty.is_empty() => return Ok((None, true)),
        (Some(raw), Some(generation)) => {
            let zones = parse_retained_bunny_delivery_zones(&raw)?;
            return Ok((Some((zones, generation)), true));
        }
        (Some(_), None) => {
            // A local write earlier in this request cached the value without a
            // generation; re-fetch fresh generation from origin before CAS.
            let fresh = fetch_origin_bunny_delivery_entry()?;
            match fresh {
                (Some(empty), _) if empty.is_empty() => return Ok((None, true)),
                (Some(raw), Some(generation)) => {
                    let zones = parse_retained_bunny_delivery_zones(&raw)?;
                    return Ok((Some((zones, generation)), true));
                }
                (None, _) => {}
                _ => return Ok((None, true)),
            }
        }
        (None, _) => {}
    }
    lookup_local_retained_bunny_delivery_with_generation(store).map(|entry| (entry, false))
}

pub(crate) fn retain_bunny_delivery_zones() -> Result<()> {
    use fastly::kv_store::{InsertMode, KVStoreError};
    let Some(raw) = (match optional_config("bunny_delivery_zones") {
        Ok(value) => value,
        // Isolated outbox-only fixtures or transient config-store outages must
        // not prevent persisting the durable purge intent; drain still fails
        // closed until config is readable.
        Err(_) => return Ok(()),
    }) else {
        return Ok(());
    };
    let configured = parse_bunny_delivery_zones(&raw)?;
    let configured_key = configured.join(",");
    if crate::request_bindings::delivery_zones_already_retained(&configured_key) {
        return Ok(());
    }
    let store = crate::metadata::open_store()?;
    for attempt in 0..3 {
        // Attempt 0 uses local KV + atomic origin-enforced Add/CAS so steady-state
        // requests spend zero `kv_origin_read_token` secrets and zero origin HTTP
        // subrequests. Any `ItemPreconditionFailed` escalates to a KV-origin CAS
        // read (failing closed if origin cannot be read) so rotated zones are
        // always durably retained before a policy mutation commits.
        let (current, from_origin) = if attempt == 0 {
            (
                lookup_local_retained_bunny_delivery_with_generation(&store)?,
                false,
            )
        } else {
            lookup_origin_retained_bunny_delivery_with_generation(&store, attempt == 1)?
        };
        if let Some((existing, generation)) = current {
            let Some(merged) = merge_retained_bunny_delivery_zones(&existing, &configured)? else {
                if from_origin {
                    crate::request_bindings::set_cached_origin_kv(
                        BUNNY_DELIVERY_RETAINED_ZONES,
                        Some(existing.join(",")),
                    );
                }
                crate::request_bindings::mark_delivery_zones_retained(&configured_key);
                return Ok(());
            };
            let value = merged.join(",");
            match crate::metadata::retry_throttled_write(|| {
                store
                    .build_insert()
                    .mode(InsertMode::Overwrite)
                    .if_generation_match(generation)
                    .execute(BUNNY_DELIVERY_RETAINED_ZONES, value.as_str())
            }) {
                Ok(()) => {
                    if from_origin {
                        crate::request_bindings::set_cached_origin_kv(
                            BUNNY_DELIVERY_RETAINED_ZONES,
                            Some(value),
                        );
                    } else {
                        crate::request_bindings::invalidate_cached_origin_kv(
                            BUNNY_DELIVERY_RETAINED_ZONES,
                        );
                    }
                    crate::request_bindings::mark_delivery_zones_retained(&configured_key);
                    return Ok(());
                }
                Err(KVStoreError::ItemPreconditionFailed) => continue,
                Err(_) => {
                    return Err(BlossomError::MetadataError(
                        "Bunny delivery target record unavailable".into(),
                    ));
                }
            }
        }
        match crate::metadata::retry_throttled_write(|| {
            store
                .build_insert()
                .mode(InsertMode::Add)
                .execute(BUNNY_DELIVERY_RETAINED_ZONES, configured_key.as_str())
        }) {
            Ok(()) => {
                if from_origin {
                    crate::request_bindings::set_cached_origin_kv(
                        BUNNY_DELIVERY_RETAINED_ZONES,
                        Some(configured_key.clone()),
                    );
                } else {
                    crate::request_bindings::invalidate_cached_origin_kv(
                        BUNNY_DELIVERY_RETAINED_ZONES,
                    );
                }
                crate::request_bindings::mark_delivery_zones_retained(&configured_key);
                return Ok(());
            }
            Err(KVStoreError::ItemPreconditionFailed) => continue,
            Err(_) => {
                return Err(BlossomError::MetadataError(
                    "Bunny delivery target record unavailable".into(),
                ));
            }
        }
    }
    Err(BlossomError::MetadataError(
        "Bunny delivery target record unavailable".into(),
    ))
}

pub(crate) fn bunny_delivery_config_present() -> Result<bool> {
    Ok(optional_config("bunny_delivery_zones")?.is_some())
}

pub(crate) fn bunny_delivery_configured() -> Result<bool> {
    use fastly::kv_store::KVStoreError;
    if bunny_delivery_config_present()? {
        return Ok(true);
    }
    match crate::metadata::open_store()?.lookup(BUNNY_DELIVERY_RETAINED_ZONES) {
        Ok(mut entry) => {
            parse_retained_bunny_delivery_zones(&entry.take_body().into_string())?;
            return Ok(true);
        }
        Err(KVStoreError::ItemNotFound) => {}
        Err(_) => {
            return Err(BlossomError::MetadataError(
                "Bunny delivery target record unavailable".into(),
            ));
        }
    }
    Ok(origin_bunny_delivery_zones()?.flatten().is_some())
}

fn bunny_delivery_purge_key() -> Result<String> {
    let packed_key = || {
        pilot_cleanup()
            .ok()
            .map(|binding| binding.bunny_api_key.trim().to_string())
            .filter(|key| !key.is_empty())
    };
    if crate::request_bindings::secret_cached("bunny_pilot_cleanup_v1") {
        if let Some(key) = packed_key() {
            return Ok(key);
        }
    }
    if crate::request_bindings::can_read_secret("bunny_api_key") {
        if let Ok(key) = get_secret("bunny_api_key") {
            let trimmed = key.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }
    }
    if crate::request_bindings::can_read_secret("bunny_pilot_cleanup_v1") {
        if let Some(key) = packed_key() {
            return Ok(key);
        }
    }
    Err(BlossomError::StorageError(
        "Bunny delivery purge credential unavailable".into(),
    ))
}

fn invalidate_bunny_delivery(hashes: &[String], zones: &[String]) -> Result<()> {
    if hashes.is_empty() {
        return Ok(());
    }
    validate_b2_cdn_purge_batch(hashes)?;
    if zones.is_empty() {
        return Err(BlossomError::StorageError(
            "bunny_delivery_zones not configured".into(),
        ));
    }
    let key = bunny_delivery_purge_key()?;
    let requests = hashes
        .iter()
        .flat_map(|hash| {
            let hash = hash.to_ascii_lowercase();
            let key = &key;
            zones
                .iter()
                .map(move |zone| build_bunny_purge_request(zone, &hash, key, "bunny-delivery"))
        })
        .collect::<Vec<_>>();
    send_bunny_purge_rounds(&requests, "Bunny delivery eviction incomplete; retry required")
}

fn bunny_delivery_purge_targets() -> Result<Vec<String>> {
    retain_bunny_delivery_zones()?;
    let configured = match optional_config("bunny_delivery_zones")? {
        Some(raw) => Some(parse_bunny_delivery_zones(&raw)?),
        None => None,
    };
    let retained = retained_bunny_delivery_zones()?;
    let mut zones = Vec::new();
    if let Some(configured) = configured {
        for zone in configured {
            if !zones.contains(&zone) {
                zones.push(zone);
            }
        }
    }
    if let Some(retained) = retained {
        for zone in retained {
            if !zones.contains(&zone) {
                zones.push(zone);
            }
        }
    }
    if zones.is_empty() {
        return Err(BlossomError::StorageError(
            "bunny_delivery_zones not configured".into(),
        ));
    }
    if zones.len() > MAX_RETAINED_BUNNY_DELIVERY_ZONES {
        return Err(BlossomError::StorageError(
            "Too many retained Bunny delivery zones; retire old zones after cache drain".into(),
        ));
    }
    Ok(zones)
}

fn build_bunny_purge_request(zone: &str, hash: &str, api_key: &str, stage: &str) -> Request {
    let purge_url = format!("https%3A%2F%2F{zone}%2F{hash}%2A");
    let mut request = Request::post(format!(
        "https://api.bunny.net/purge?url={purge_url}&async=false"
    ));
    request.set_header("Host", "api.bunny.net");
    request.set_header("AccessKey", api_key);
    request.set_header("X-Divine-Vanish-Stage", stage);
    request
}

pub(crate) fn purge_bunny_hashes(hashes: &[String], result: &mut VanishStorageResult) {
    if !b2_replica_enabled() || hashes.is_empty() {
        return;
    }
    // When durable CDN invalidation is active (which is always true whenever
    // `bunny_delivery_zones` is configured or retained), phased vanish and
    // creator physical delete block completion until the dedicated `Phase::Final`
    // drain executes two checked Bunny delivery purge rounds in a fresh Compute
    // secret/subrequest budget. Deferring Bunny eviction to `Phase::Final` avoids
    // breaching the vanish wave's 5-secret and 32-backend-request limits.
    if cdn_invalidation_configured() {
        return;
    }
    let raw = match optional_config("bunny_delivery_zones") {
        Ok(Some(raw)) => raw,
        Ok(None) => return,
        Err(error) => {
            eprintln!("[VANISH] bunny purge setup failed error={error}");
            result.failed_hashes.extend(hashes.iter().cloned());
            return;
        }
    };
    let zones = match parse_bunny_delivery_zones(&raw) {
        Ok(zones) => zones,
        Err(error) => {
            eprintln!("[VANISH] bunny purge setup failed error={error}");
            result.failed_hashes.extend(hashes.iter().cloned());
            return;
        }
    };
    let api_key = match get_secret("bunny_api_key") {
        Ok(api_key) if !api_key.trim().is_empty() => api_key.trim().to_string(),
        _ => {
            eprintln!("[VANISH] bunny purge setup failed error=missing_api_key");
            result.failed_hashes.extend(hashes.iter().cloned());
            return;
        }
    };
    let mut pending = Vec::new();
    let mut stage_hashes = HashMap::<String, String>::new();
    for hash in hashes {
        for (zone_index, zone) in zones.iter().enumerate() {
            let stage = format!("purge_bunny:{zone_index}:{hash}");
            let request = build_bunny_purge_request(zone, hash, &api_key, &stage);
            stage_hashes.insert(stage.clone(), hash.clone());
            match request.send_async(BUNNY_API_BACKEND) {
                Ok(request) => pending.push(request),
                Err(error) => {
                    eprintln!("[VANISH] bunny purge failed hash={hash} error={error}");
                    result.failed_hashes.insert(hash.clone());
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
                    .unwrap_or_default();
                if !response.get_status().is_success() {
                    eprintln!(
                        "[VANISH] bunny purge failed stage={} status={}",
                        stage,
                        response.get_status()
                    );
                    if let Some(hash) = stage_hashes.get(stage) {
                        result.failed_hashes.insert(hash.clone());
                    } else {
                        result.failed_hashes.extend(hashes.iter().cloned());
                    }
                }
            }
            Err(error) => {
                let request = error.into_sent_req();
                let stage = request
                    .get_header_str("X-Divine-Vanish-Stage")
                    .unwrap_or_default();
                if let Some(hash) = stage_hashes.get(stage) {
                    result.failed_hashes.insert(hash.clone());
                } else {
                    result.failed_hashes.extend(hashes.iter().cloned());
                }
            }
        }
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

fn plan_vanish_delete_batches(
    hashes: &[String],
    local_mode: bool,
) -> Vec<VanishDeleteBatch> {
    let mut batches = Vec::new();
    let stage = if local_mode {
        "gcs_main"
    } else {
        "fos_main"
    };

    for (index, keys) in hashes.chunks(PROVIDER_MULTI_DELETE_LIMIT).enumerate() {
        batches.push(VanishDeleteBatch {
            stage: format!("{}:{}", stage, index),
            keys: keys.to_vec(),
        });
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

/// Production CDN invalidation is opt-in with the production delivery path.
pub(crate) fn b2_cdn_invalidation_enabled() -> bool {
    // Disabling admission does not revoke a stored outer response. Retained
    // purge hosts keep invalidation active throughout rollback and draining.
    crate::b2_cdn_purge::configured()
}

fn b2_cdn_purge_urls(hash: &str, hosts: &str, current_host: &str) -> Result<Vec<String>> {
    let invalid = || BlossomError::StorageError("B2 CDN purge configuration invalid".into());
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let names = blossom_core::b2_cdn::purge_hosts(Some(hosts), Some(current_host))
        .ok_or_else(invalid)?;
    Ok(names.into_iter().map(|host| format!("https://{host}/{}", hash.to_ascii_lowercase())).collect())
}

/// Send targeted URL purges as well as committed hash-variant purges.
/// In-flight cache behavior still requires live provider acceptance tests.
/// All requests are drained; no acknowledgement is returned on partial failure.
pub(crate) fn invalidate_b2_cdn(hashes: &[String]) -> Result<()> {
    // A discovered durable intent is still owed an eviction even if an operator
    // removed admission/purge configuration. Missing configuration must fail
    // this checked operation, never masquerade as a successful empty purge.
    if hashes.is_empty() {
        return Ok(());
    }
    validate_b2_cdn_purge_batch(hashes)?;
    let fastly = crate::b2_cdn_purge::fastly_configured();
    let bunny = bunny_pilot_configured();
    let delivery = bunny_delivery_configured();
    let bunny_configured = matches!(&bunny, Ok(true));
    let delivery_configured = matches!(&delivery, Ok(true));
    let targets = fastly.and_then(|include_b2| {
        if include_b2 || bunny_configured || delivery_configured {
            Ok(include_b2)
        } else {
            Err(BlossomError::StorageError(
                "CDN purge configuration unavailable".into(),
            ))
        }
    });

    // Stale or missing priority hints never authorize clearing an intent.
    // A lost hint simply repeats the checked fallback on another drain.
    let mut packed_priority = Vec::new();
    let mut orphaned_bunny_retry = Vec::new();
    if let Ok(store) = crate::metadata::open_store() {
        let mut standalone_priority = Vec::new();
        let mut bunny_retry_priority = Vec::new();
        for hash in hashes {
            let key = canonical_priority_key(hash);
            if let Ok(mut record) = store.lookup(&key) {
                match record.take_body().into_bytes().as_slice() {
                    b"packed" => packed_priority.push(key),
                    b"1" => standalone_priority.push(key),
                    b"bunny-retry" => bunny_retry_priority.push(key),
                    _ => {}
                }
            }
        }
        if !bunny_retry_priority.is_empty() && delivery_configured {
            // Priority hint only: purge Bunny delivery so a Fastly outage or
            // missing pilot bundle never starves outer Bunny eviction under a
            // 1-slot secret budget. Always advance or clear the hint (even if
            // target resolution fails) and return Err so Fastly/pilot eviction
            // still runs before any intent clears.
            let delivery_attempt = bunny_delivery_purge_targets()
                .and_then(|zones| invalidate_bunny_delivery(hashes, &zones));
            if bunny_configured {
                stage_canonical_priority(hashes, CanonicalCredential::Packed)?;
            } else {
                clear_canonical_priority(&store, &bunny_retry_priority)?;
            }
            delivery_attempt?;
            return Err(BlossomError::StorageError(
                "Bunny delivery eviction completed; canonical retry pending".into(),
            ));
        }
        orphaned_bunny_retry = bunny_retry_priority;
        if !standalone_priority.is_empty() {
            let canonical = get_secret("fastly_api_token").and_then(|token| {
                invalidate_fastly_cdn(hashes, targets?, &token, None)
            });
            if let Err(error) = canonical {
                // This dedicated retry reserves its secret budget for Fastly.
                // Even a missing key or sustained 5xx must give the independent
                // Bunny delivery and pilot purges the next bounded execution.
                if delivery_configured {
                    stage_canonical_priority(hashes, CanonicalCredential::BunnyRetry)?;
                } else if bunny_configured {
                    stage_canonical_priority(hashes, CanonicalCredential::Packed)?;
                }
                return Err(error);
            }
            if delivery_configured {
                stage_canonical_priority(hashes, CanonicalCredential::BunnyRetry)?;
            } else {
                clear_canonical_priority(&store, &standalone_priority)?;
            }
            return Err(BlossomError::StorageError(
                "Canonical eviction completed; CDN intent pending".into(),
            ));
        }
    }

    // An unrelated hash spends its standalone purge credential even on the
    // cold webhook path. Read enrollment once; origin errors still permit
    // independent Fastly eviction and keep the Bunny obligation pending.
    let enrolled = bunny.and_then(|configured| {
        let mut enrolled = Vec::new();
        if configured {
            for hash in hashes {
                let parent = hash.to_ascii_lowercase();
                if bunny_pilot_enrolled(&parent)? {
                    enrolled.push(parent);
                }
            }
        }
        Ok(enrolled)
    });
    // Resolve delivery targets before checking `has_secret_budget` so any
    // `kv_origin_read_token` read is already accounted for in the 5-secret budget.
    let delivery_zones = delivery.and_then(|configured| {
        if configured {
            bunny_delivery_purge_targets().map(Some)
        } else {
            Ok(None)
        }
    });
    let pilot_needs_bundle =
        bunny_configured && !matches!(&enrolled, Ok(parents) if parents.is_empty());
    let delivery_needs_bundle = delivery_configured
        && !crate::request_bindings::has_secret_budget(&["fastly_api_token", "bunny_api_key"]);
    let needs_bundle = pilot_needs_bundle || delivery_needs_bundle;
    let fastly_result = targets.and_then(|include_b2| {
        let (token, retry) =
            canonical_purge_token(hashes, needs_bundle, !packed_priority.is_empty())?;
        invalidate_fastly_cdn(hashes, include_b2, &token, retry)
    });
    let delivery_target_count = delivery_zones
        .as_ref()
        .ok()
        .and_then(|zones| zones.as_ref().map(Vec::len))
        .unwrap_or(0);
    let delivery_result = delivery_zones.and_then(|zones| match zones {
        Some(zones) => invalidate_bunny_delivery(hashes, &zones),
        None => Ok(()),
    });
    let pilot_result = enrolled.and_then(|parents| {
        invalidate_bunny_pilot(&parents, delivery_target_count)
    });
    pilot_result.and(delivery_result).and(fastly_result)?;
    // The packed Fastly key and Bunny cleanup capabilities share one native
    // lookup. Keep this preference across partial cleanup until both succeed.
    if !packed_priority.is_empty() || !orphaned_bunny_retry.is_empty() {
        let store = crate::metadata::open_store()?;
        if !packed_priority.is_empty() {
            clear_canonical_priority(&store, &packed_priority)?;
        }
        if !orphaned_bunny_retry.is_empty() {
            clear_canonical_priority(&store, &orphaned_bunny_retry)?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum CanonicalCredential {
    Standalone,
    Packed,
    BunnyRetry,
}

fn clear_canonical_priority(store: &fastly::kv_store::KVStore, keys: &[String]) -> Result<()> {
    for key in keys {
        match crate::metadata::retry_throttled_write(|| store.delete(key)) {
            Ok(()) | Err(fastly::kv_store::KVStoreError::ItemNotFound) => {}
            Err(_) => {
                return Err(BlossomError::MetadataError(
                    "Canonical purge checkpoint unavailable".into(),
                ))
            }
        }
    }
    Ok(())
}

fn canonical_priority_key(hash: &str) -> String {
    format!("canonical-purge-priority:v1:{}", hash.to_ascii_lowercase())
}

fn canonical_purge_token(
    hashes: &[String],
    use_pilot: bool,
    prefer_packed: bool,
) -> Result<(String, Option<CanonicalCredential>)> {
    #[derive(Deserialize)]
    struct FastlyPurge {
        fastly_api_token: String,
    }
    let bundled = if use_pilot {
        pilot_binding::<FastlyPurge>("bunny_pilot_cleanup_v1")
            .ok()
            .map(|b| b.fastly_api_token)
            .filter(|t| !t.trim().is_empty())
    } else {
        None
    };
    if (!prefer_packed || bundled.is_none())
        && crate::request_bindings::can_read_secret("fastly_api_token")
    {
        match get_secret("fastly_api_token") {
            Ok(token) if !token.trim().is_empty() => {
                return Ok((token, use_pilot.then_some(CanonicalCredential::Packed)))
            }
            Err(error) if bundled.is_none() => return Err(error),
            _ => {}
        }
    }
    if let Some(token) = bundled {
        return Ok((token, Some(CanonicalCredential::Standalone)));
    }
    stage_canonical_priority(hashes, CanonicalCredential::Standalone)?;
    Err(BlossomError::StorageError(
        "Canonical eviction pending dedicated retry".into(),
    ))
}

fn stage_canonical_priority(hashes: &[String], credential: CanonicalCredential) -> Result<()> {
    let preference = match credential {
        CanonicalCredential::Standalone => "1", // existing v1 checkpoints
        CanonicalCredential::Packed => "packed",
        CanonicalCredential::BunnyRetry => "bunny-retry",
    };
    let store = crate::metadata::open_store()?;
    for hash in hashes {
        crate::metadata::retry_throttled_write(|| {
            store.insert(&canonical_priority_key(hash), preference)
        })
        .map_err(|_| {
            BlossomError::MetadataError("Canonical purge checkpoint unavailable".into())
        })?;
    }
    Ok(())
}

fn invalidate_bunny_pilot(hashes: &[String], delivery_targets: usize) -> Result<()> {
    if hashes.is_empty() {
        return Ok(());
    }
    let hosts = bunny_pilot_hosts()?;
    for hash in hashes {
        // Keep copy exclusion through all-version deletion and both purge rounds.
        crate::parent_gate::with_delivery_removal(
            hash,
            || match crate::metadata::bunny_public_metadata(hash) {
                Ok(_) => Ok(false),
                Err(BlossomError::NotFound(_)) => Ok(true),
                Err(error) => Err(error),
            },
            |newly_denied, check_gate| {
                // The first execution may also spend seven policy reads and two
                // gate-claim reads. When outer Bunny delivery zones also purge
                // in this execution (up to four hosts during rotation), claim
                // the denial gate first and defer B2/pilot work to drain so the
                // execution stays within Fastly's 32-subrequest ceiling.
                if newly_denied && delivery_targets > 0 {
                    crate::bunny_ready::invalidate(hash)?;
                    return Err(BlossomError::StorageError(
                        "Bunny pilot eviction pending bounded retry".into(),
                    ));
                }
                let limit = if newly_denied || delivery_targets > MAX_BUNNY_DELIVERY_ZONES {
                    1
                } else if delivery_targets > 0 {
                    B2_ERASE_DELETES_PER_HASH.saturating_sub(2).max(1)
                } else {
                    B2_ERASE_DELETES_PER_HASH
                };
                remove_bunny_delivery_copies(hash, limit, check_gate)?;
                purge_bunny_pilot_hosts(std::slice::from_ref(hash), &hosts)
            },
        )?;
    }
    Ok(())
}

fn invalidate_fastly_cdn(
    hashes: &[String],
    include_b2_hosts: bool,
    token: &str,
    retry: Option<CanonicalCredential>,
) -> Result<()> {
    let mut requests = Vec::new();
    if include_b2_hosts {
        let hosts = get_config("b2_cdn_purge_hosts")?;
        let current_host = get_config("b2_cdn_host")?;
        for hash in hashes {
            for url in b2_cdn_purge_urls(hash, &hosts, &current_host)? {
                // Modern domains require the outer service ID and a scheme-free
                // target. Both retained hosts belong to that same outer service;
                // the host and lowercase hash path were validated above.
                let target = url.strip_prefix("https://").ok_or_else(|| {
                    BlossomError::StorageError("B2 CDN purge target invalid".into())
                })?;
                requests.push(Request::post(format!(
                    "https://api.fastly.com/service/ML7R82HKfmTaqTpHExIDVN/purge_url/{target}"
                )));
            }
        }
    }
    if token.is_empty() {
        return Err(BlossomError::StorageError(
            "B2 CDN purge credential unavailable".into(),
        ));
    }
    for chunk in hashes.chunks(256) {
        for service in ["ML7R82HKfmTaqTpHExIDVN", "pOvEEWykEbpnylqst1KTrR"] {
            let mut request =
                Request::post(format!("https://api.fastly.com/service/{service}/purge"));
            request.set_header(
                "Surrogate-Key",
                chunk
                    .iter()
                    .map(|hash| hash.to_ascii_lowercase())
                    .collect::<Vec<_>>()
                    .join(" "),
            );
            requests.push(request);
        }
    }
    let mut failed = false;
    let mut token_rejected = false;
    for round in 0..2 {
        let mut pending = Vec::new();
        for template in &requests {
            let mut request = template.clone_without_body();
            request.set_header("Host", "api.fastly.com");
            request.set_header("Fastly-Key", token);
            request.set_header("Accept", "application/json");
            match request.send_async("fastly_api") {
                Ok(handle) => pending.push(handle),
                Err(_) => failed = true,
            }
        }
        while !pending.is_empty() {
            let (response, remaining) = fastly::http::request::select(pending);
            pending = remaining;
            // A 404 does not prove that a retained host is unbound or evicted.
            // Every URL and service-key request must independently acknowledge.
            if matches!(&response, Ok(r) if matches!(r.get_status(), StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN))
            {
                token_rejected = true;
            }
            let acknowledged =
                matches!(response, Ok(response) if response.get_status().is_success());
            if !acknowledged {
                failed = true;
            }
        }
        if token_rejected {
            if let Some(credential) = retry {
                // All handles from this round have settled. A fresh request can
                // spend its quota on two complete rounds with the alternate.
                stage_canonical_priority(hashes, credential)?;
                return Err(BlossomError::StorageError(
                    "Canonical purge credential rejected; retry pending".into(),
                ));
            }
        }
        if round == 0 {
            wait_b2_cdn_purge_interval()?;
        }
    }
    if failed {
        Err(BlossomError::StorageError(
            "B2 CDN invalidation incomplete; retry required".into(),
        ))
    } else {
        Ok(())
    }
}

fn validate_b2_cdn_purge_batch(hashes: &[String]) -> Result<()> {
    let mut seen = HashSet::new();
    if hashes.len() > 4 || hashes.iter().any(|hash| {
        hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !seen.insert(hash.to_ascii_lowercase())
    }) {
        return Err(BlossomError::StorageError("B2 CDN purge batch invalid or over budget".into()));
    }
    Ok(())
}

/// Fastly documents a second URL/key purge after about two seconds for
/// shield ordering races. Yield to the host timer instead of consuming CPU.
fn wait_b2_cdn_purge_interval() -> Result<()> {
    let handles: [fastly_sys::AsyncItemHandle; 0] = [];
    let mut index = u32::MAX;
    // SAFETY: the empty slice pointer and output pointer remain valid for this
    // hostcall. The timeout is strictly positive (zero would wait indefinitely).
    let status = unsafe { fastly_sys::fastly_async_io::select(handles.as_ptr(), 0, 2000, &mut index) };
    if status.is_err() || index != u32::MAX {
        return Err(BlossomError::StorageError("B2 CDN purge interval unavailable; retry required".into()));
    }
    Ok(())
}

/// Retain legacy best-effort behavior until production CDN mode is enabled.
pub(crate) fn purge_policy_cache(hash: &str) -> Result<()> {
    if b2_cdn_invalidation_enabled() { invalidate_b2_cdn(&[hash.to_string()]) }
    else { crate::purge_edge_cache(hash); Ok(()) }
}

fn vanish_inline_fastly_purge_has_budget() -> bool {
    let reserve_kv_origin = !b2_replica_enabled()
        && optional_config("metadata_kv_store_id").map_or(true, |value| {
            value.as_deref().is_some_and(|id| !id.trim().is_empty())
        });
    if reserve_kv_origin {
        crate::request_bindings::has_secret_budget(&[
            "fastly_api_token",
            "kv_origin_read_token",
            "webhook_secret",
        ])
    } else {
        crate::request_bindings::has_secret_budget(&["fastly_api_token", "webhook_secret"])
    }
}

/// Purge the given hashes by surrogate key from both CDN services and return
/// the hashes whose purge request both services accepted.
fn purge_vanish_hashes(hashes: &[String], result: &mut VanishStorageResult) -> HashSet<String> {
    let mut purged = HashSet::new();
    if hashes.is_empty() {
        return purged;
    }
    // When durable CDN invalidation is active and this request cannot spare a
    // secret slot for `fastly_api_token` (while keeping room for downstream
    // `kv_origin_read_token` and `webhook_secret` calls), defer inline Fastly
    // eviction to the dedicated `Phase::Final` drain so physical waves stay
    // within Fastly's 5-secret limit. When budget remains, run the immediate
    // Fastly purge so #279 delivery probes and immediate eviction continue.
    if cdn_invalidation_configured() && !vanish_inline_fastly_purge_has_budget() {
        result.purge_deferred = true;
        return purged;
    }

    let api_token = match get_secret("fastly_api_token") {
        Ok(token) if !token.is_empty() => token,
        _ => {
            eprintln!(
                "[VANISH] purge stage=setup error=missing_or_empty_token key_count={}",
                hashes.len()
            );
            result.failed_hashes.extend(hashes.iter().cloned());
            return purged;
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
                } else if let Some(stage_keys) = stage_hashes.get(&stage) {
                    purged.extend(stage_keys.iter().cloned());
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
    purged
}

/// Whether a warm outer CDN copy could exist for this object. Invalidation
/// depends only on retained CDN configuration, never on the admission or
/// replica flags: turning either off does not revoke an already-stored outer
/// response.
pub(crate) fn cdn_invalidation_configured() -> bool {
    crate::b2_cdn_purge::configured()
}

/// Decide the physical outcome for one hash. Pure so the rollback trap is
/// covered without a provider.
///
/// A skipped B2 erase is never `Absent`: with the replica flag off the versions
/// were not deleted, so claiming absence would mark warm content safe while it
/// still exists. It is a failure that keeps the hash pending.
fn vanish_physical_outcome(
    hash: &str,
    failed: &HashSet<String>,
    remaining: &HashSet<String>,
    replica_enabled: bool,
) -> crate::b2_cdn_phase::Physical {
    use crate::b2_cdn_phase::Physical;
    if failed.contains(hash) || !replica_enabled {
        Physical::Failed
    } else if remaining.contains(hash) {
        // A version set larger than one bounded page is known, safe progress:
        // the next wave continues it. It is not an uncertain outcome, so it
        // stays Pending and may run again.
        Physical::Pending
    } else {
        Physical::Absent
    }
}

/// Split candidate hashes into those allowed to run the bounded physical wave
/// and those that must be held this pass.
///
/// A hash runs only when it has a durable attempt epoch and its phase record is
/// readable and says the wave may run. Anything else — a missing epoch from a
/// failed `begin_vanish_phase`, or an unreadable phase record — is held rather
/// than erased without durable progress, so a partial failure can never cause a
/// destructive wave with no record of it.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct VanishPhysicalPlan {
    /// Hashes that may run the bounded physical wave this request.
    pub run: Vec<String>,
    /// Hashes with no durable epoch or unreadable phase: hold, never erase.
    pub held: Vec<String>,
    /// Hashes the phase says need no wave (Absent/Complete). Normal completion,
    /// never pending work.
    pub skipped: Vec<String>,
}

/// Plan the bounded physical wave.
///
/// With phase not configured this is byte-for-byte the legacy behavior: every
/// hash runs and nothing is held, so enabling the feature cannot change what an
/// ordinary vanish deletes.
pub(crate) fn plan_vanish_physical(
    hashes: &[String],
    epochs: &std::collections::HashMap<String, String>,
    configured: bool,
    mut may_run: impl FnMut(&str) -> Result<bool>,
) -> VanishPhysicalPlan {
    let mut plan = VanishPhysicalPlan::default();
    if !configured {
        plan.run.extend(hashes.iter().cloned());
        return plan;
    }
    for hash in hashes {
        if !epochs.contains_key(&hash.to_ascii_lowercase()) {
            plan.held.push(hash.clone());
            continue;
        }
        match may_run(hash) {
            Ok(true) => plan.run.push(hash.clone()),
            // The phase says the wave already finished; skip quietly.
            Ok(false) => plan.skipped.push(hash.clone()),
            // Unreadable state fails closed: hold, never erase.
            Err(_) => plan.held.push(hash.clone()),
        }
    }
    plan
}

/// Backwards-compatible two-list view for callers that already distinguish run
/// from held. Skips are returned as run=false but not held only through the
/// full [`plan_vanish_physical`] API.
pub(crate) fn plan_vanish_physical_with(
    hashes: &[String],
    epochs: &std::collections::HashMap<String, String>,
    may_run: impl FnMut(&str) -> Result<bool>,
) -> (Vec<String>, Vec<String>) {
    let plan = plan_vanish_physical(hashes, epochs, true, may_run);
    (plan.run, plan.held)
}

/// Whether a local phased-erasure record is already open for `hash` OR CDN
/// invalidation is configured. Checking the local phase key first avoids
/// re-spending a `kv_origin_read_token` secret slot on physical-erasure retries
/// after Attempt 1 has opened the phase.
pub(crate) fn phase_or_cdn_invalidation_active(hash: &str) -> bool {
    crate::b2_cdn_phase::epoch(hash).map_or(true, |epoch| epoch.is_some())
        || cdn_invalidation_configured()
}

/// Classification of the current request's remaining 5-secret Compute budget
/// for `erase_vanish_batch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VanishPhysicalSecretBudget {
    /// Current request has room within Fastly's 5-secret limit to run
    /// `erase_vanish_batch` now.
    Ready,
    /// Current request spent a slot on `kv_origin_read_token` (e.g. cold-POP
    /// origin-retention lookup on Attempt 1), and a retry that hits the local
    /// phase record without `kv_origin_read_token` will fit within 5 secrets.
    DeferForKvOriginRetry,
    /// Even without `kv_origin_read_token`, already-cached secrets in this
    /// request (such as `admin_token` alongside `b2_replica_enabled=true`)
    /// leave fewer slots than `erase_vanish_batch` requires; deferring would
    /// loop forever without progress.
    Exhausted,
}

/// Classify whether the current Compute request has enough of its 5-secret
/// budget to run `erase_vanish_batch`, can retry once `kv_origin_read_token`
/// is skipped, or can never fit under the current request's cached auth.
pub(crate) fn vanish_physical_secret_budget() -> VanishPhysicalSecretBudget {
    vanish_physical_secret_budget_for(is_local_mode(), b2_replica_enabled())
}

pub(crate) fn vanish_physical_secret_budget_for(
    local_mode: bool,
    b2_replica: bool,
) -> VanishPhysicalSecretBudget {
    if local_mode {
        return VanishPhysicalSecretBudget::Ready;
    }
    let required: &[&str] = if b2_replica {
        &[
            "fos_access_key",
            "fos_secret_key",
            "b2_vanish_application_key_id",
            "b2_vanish_application_key",
            "webhook_secret",
        ]
    } else {
        &["fos_access_key", "fos_secret_key", "webhook_secret"]
    };
    if crate::request_bindings::has_secret_budget(required) {
        VanishPhysicalSecretBudget::Ready
    } else if crate::request_bindings::secret_cached("kv_origin_read_token")
        && crate::request_bindings::has_secret_budget_excluding(
            required,
            "kv_origin_read_token",
        )
    {
        VanishPhysicalSecretBudget::DeferForKvOriginRetry
    } else {
        VanishPhysicalSecretBudget::Exhausted
    }
}

/// Persist the deny/erasing gate and open a phased physical attempt for a hash
/// the caller is about to erase. Must run before the physical wave so a warm
/// outer entry is invalidated even if the wave is interrupted.
///
/// Gated only on CDN invalidation configuration (or an already-open phase).
/// Returns the attempt's epoch, or `None` when CDN invalidation is not configured.
pub(crate) fn begin_vanish_phase(hash: &str) -> Result<Option<String>> {
    if !phase_or_cdn_invalidation_active(hash) {
        return Ok(None);
    }
    crate::metadata::claim_b2_erasure(hash)?;
    Ok(Some(crate::b2_cdn_phase::begin_erase(hash)?))
}

/// Whether the bounded wave must run for this hash.
///
/// An unreadable phase record returns `Err`, and the caller holds the hash.
/// Defaulting to "run" here would turn a KV read failure into a destructive
/// erase with no durable progress.
pub(crate) fn vanish_needs_physical(hash: &str) -> Result<bool> {
    crate::b2_cdn_phase::needs_physical(hash)
}

fn b2_replica_required_for_cdn() -> bool {
    crate::b2_cdn_purge::fastly_configured().unwrap_or(true)
        || bunny_pilot_configured().unwrap_or(true)
}

/// Record the wave's outcome for the exact attempt and queue the blocking final
/// purge when the outcome is definite. A failed or replica-skipped wave is
/// purged too, so cached bytes leave the CDN; it simply can never complete. An
/// unknown outcome stays pending for a read-only reconcile and is not purged.
///
/// Returns `true` when a final intent was queued.
pub(crate) fn finish_vanish_phase(
    hash: &str,
    epoch: &str,
    failed: &HashSet<String>,
    remaining: &HashSet<String>,
) -> Result<bool> {
    if !phase_or_cdn_invalidation_active(hash) {
        return Ok(false);
    }
    let replica_satisfied = b2_replica_enabled() || !b2_replica_required_for_cdn();
    let outcome = vanish_physical_outcome(hash, failed, remaining, replica_satisfied);
    crate::b2_cdn_phase::record_physical(hash, epoch, outcome)?;
    if !crate::b2_cdn_phase::final_purge_pending(hash)? {
        return Ok(false);
    }
    crate::b2_cdn_purge::enqueue(hash, crate::b2_cdn_purge::Phase::Final)?;
    Ok(true)
}

/// Whether erasure for this hash may be reported complete: bytes proven absent
/// and the final purge acknowledged. A failed or replica-skipped wave can never
/// be complete.
pub(crate) fn vanish_complete(hash: &str) -> bool {
    crate::b2_cdn_phase::complete_ready(hash).unwrap_or(false)
}

/// One full vanish attempt for one hash, in the same order `execute_vanish`
/// uses: open the attempt, run the bounded wave only if still needed, record
/// the outcome, and report whether the hash may be finalized.
///
/// `wave` is the caller's bounded physical erase so the test can count how many
/// times it actually runs. Returns `(physical_ran, may_finalize)`.
#[cfg(test)]
pub(crate) fn vanish_attempt_for_test(
    hash: &str,
    wave: impl FnOnce(&[String]) -> HashSet<String>,
) -> (bool, bool) {
    let Some(epoch) = begin_vanish_phase(hash).ok().flatten() else {
        return (false, true);
    };
    let ran = if vanish_needs_physical(hash).unwrap_or(false) {
        let failed = wave(&[hash.to_string()]);
        if let Err(error) = finish_vanish_phase(hash, &epoch, &failed, &HashSet::new()) {
            eprintln!("[test] finish_vanish_phase failed: {error}");
        }
        true
    } else {
        false
    };
    (ran, vanish_complete(hash))
}

#[cfg(test)]
mod vanish_phase_tests {
    use super::{plan_vanish_physical, plan_vanish_physical_with, vanish_physical_outcome};
    use crate::b2_cdn_phase::Physical;
    use std::collections::HashSet;

    #[test]
    fn known_remaining_progress_is_not_an_uncertain_outcome() {
        let hash = "b".repeat(64);
        let failed: HashSet<String> = HashSet::new();
        let remaining: HashSet<String> = [hash.clone()].into_iter().collect();
        // B2 versions beyond one bounded page is known safe progress: it must
        // retry the wave next time, not become an unreconcilable Unknown.
        assert_eq!(
            vanish_physical_outcome(&hash, &failed, &remaining, true),
            Physical::Pending
        );
    }

    #[test]
    fn planning_is_default_parity_when_phase_is_not_configured() {
        // With CDN invalidation off every hash must run the ordinary wave,
        // exactly as before this feature. No epoch is required and nothing is
        // held, or existing vanish would stop deleting anything.
        let hashes: Vec<String> = ["10", "11", "12"]
            .iter()
            .map(|h| h.repeat(32))
            .collect();
        let empty = std::collections::HashMap::new();
        let plan = plan_vanish_physical(&hashes, &empty, false, |_| Ok(true));
        assert_eq!(plan.run, hashes, "default-off must run every hash");
        assert!(plan.held.is_empty(), "default-off must hold nothing");
        assert!(plan.skipped.is_empty());
    }

    #[test]
    fn an_already_finished_hash_is_skipped_not_held() {
        // Configured, but the phase says the wave must not run (Absent or
        // Complete). That is normal completion, not an error: skip it without
        // holding or counting it pending forever.
        let hash = "13".repeat(32);
        let hashes = vec![hash.clone()];
        let mut epochs = std::collections::HashMap::new();
        epochs.insert(hash.clone(), "0".repeat(32));
        let plan = plan_vanish_physical(&hashes, &epochs, true, |_| Ok(false));
        assert!(plan.run.is_empty(), "a finished hash must not re-run");
        assert!(plan.held.is_empty(), "a finished hash must not be held");
        assert_eq!(plan.skipped, hashes, "it is skipped, not pending work");
    }

    #[test]
    fn the_physical_wave_excludes_hashes_without_a_durable_epoch() {
        let with_epoch = "c".repeat(64);
        let no_epoch = "d".repeat(64);
        let unsafe_state = "e".repeat(64);
        let hashes = vec![with_epoch.clone(), no_epoch.clone(), unsafe_state.clone()];
        let mut epochs = std::collections::HashMap::new();
        epochs.insert(with_epoch.clone(), "0".repeat(32));
        epochs.insert(unsafe_state.clone(), "1".repeat(32));
        let (run, held) = plan_vanish_physical_with(&hashes, &epochs, |hash| {
            if hash == unsafe_state {
                Err(crate::error::BlossomError::MetadataError("unreadable".into()))
            } else {
                Ok(true)
            }
        });
        assert_eq!(run, vec![with_epoch], "only a durable, readable hash may run");
        assert_eq!(
            held,
            vec![no_epoch, unsafe_state],
            "missing epoch and unreadable state are held, never erased"
        );
    }

    #[test]
    fn a_skipped_replica_erase_is_never_reported_absent() {
        let hash = "a".repeat(64);
        let failed: HashSet<String> = HashSet::new();
        let remaining: HashSet<String> = HashSet::new();
        // Normal success.
        assert_eq!(
            vanish_physical_outcome(&hash, &failed, &remaining, true),
            Physical::Absent
        );
        // Replica flag off means versions were not deleted: never Absent, so the
        // hash can never be marked complete while outer bytes may survive.
        assert_eq!(
            vanish_physical_outcome(&hash, &failed, &remaining, false),
            Physical::Failed
        );
        // A provider failure dominates a clean remainder.
        let failed: HashSet<String> = [hash.clone()].into_iter().collect();
        assert_eq!(
            vanish_physical_outcome(&hash, &failed, &remaining, true),
            Physical::Failed
        );
        // Still-progressing versions are known safe progress: Pending, so the
        // next wave continues them. Not an uncertain Unknown.
        let failed: HashSet<String> = HashSet::new();
        let remaining: HashSet<String> = [hash.clone()].into_iter().collect();
        assert_eq!(
            vanish_physical_outcome(&hash, &failed, &remaining, true),
            Physical::Pending
        );
    }
}

/// Erase one bounded vanish batch from every enabled origin and CDN service.
pub(crate) fn erase_vanish_batch(hashes: &[String]) -> VanishStorageResult {
    let mut result = VanishStorageResult::default();
    let mut main_origin_failures = HashSet::new();
    if hashes.is_empty() {
        return result;
    }

    let local_mode = is_local_mode();
    let erasure = match erasure_policy() {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!("[VANISH] invalid erasure policy: {error}");
            result.failed_hashes.extend(hashes.iter().cloned());
            return result;
        }
    };
    let run_primary_multi_delete = if local_mode {
        erasure.gcs_enabled
    } else {
        erasure.fos_enabled
    };
    if run_primary_multi_delete {
        let (storage_config, storage_backend) = if local_mode {
            (S3Config::load_gcs(), GCS_BACKEND)
        } else {
            (S3Config::load_fos(), FOS_BACKEND)
        };
        let storage_config = match storage_config {
            Ok(config) => config,
            Err(_) => {
                result.failed_hashes.extend(hashes.iter().cloned());
                return result;
            }
        };
        let mut pending = Vec::new();
        let mut stage_started = HashMap::<String, Instant>::new();
        let mut requested_by_stage = HashMap::<String, Vec<String>>::new();

        for batch in plan_vanish_delete_batches(hashes, local_mode) {
            let stage = batch.stage;
            let keys = batch.keys;
            stage_started.insert(stage.clone(), Instant::now());
            requested_by_stage.insert(stage.clone(), keys.clone());
            match build_multi_delete_request(&keys, &storage_config, &stage).and_then(|request| {
                request.send_async(storage_backend).map_err(|error| {
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
                        if stage.starts_with("fos_main:") {
                            result.timings.fos_main_ms = result.timings.fos_main_ms.max(duration);
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
                    let key_count = requested_by_stage
                        .get(stage)
                        .map_or(hashes.len(), Vec::len);
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
    }

    let b2_started = Instant::now();
    let (b2_failures, b2_remaining) = erase_b2_replica_hashes(hashes);
    result.timings.b2_replica_ms = elapsed_ms(b2_started);
    result.failed_hashes.extend(b2_failures.iter().cloned());
    main_origin_failures.extend(b2_failures);
    main_origin_failures.extend(b2_remaining.iter().cloned());
    result.remaining_hashes.extend(b2_remaining);

    // Run after the provider responses are drained so `fos_main_ms` measures
    // provider completion instead of the Cloud Run wait.
    let cloud_cleanup_started = Instant::now();
    if erasure.gcs_enabled {
        if local_mode {
            for hash in hashes {
                if crate::delete_blob_gcs_artifacts(hash).is_err() {
                    result.failed_hashes.insert(hash.clone());
                }
            }
        } else {
            match trigger_cloud_run_delete_blobs(hashes) {
                Ok(outcome) => {
                    apply_cloud_cleanup_outcome(&mut result, &mut main_origin_failures, outcome);
                }
                Err(_) => {
                    result.failed_hashes.extend(hashes.iter().cloned());
                    main_origin_failures.extend(hashes.iter().cloned());
                }
            }
        }
    }
    result.timings.cloud_run_cleanup_ms = elapsed_ms(cloud_cleanup_started);

    let purgeable: Vec<String> = hashes
        .iter()
        .filter(|hash| !main_origin_failures.contains(*hash))
        .cloned()
        .collect();
    let purged = purge_vanish_hashes(&purgeable, &mut result);
    let bunny_started = Instant::now();
    purge_bunny_hashes(&purgeable, &mut result);
    result.timings.purge_bunny_ms = elapsed_ms(bunny_started);
    let purged: HashSet<String> = purged
        .into_iter()
        .filter(|hash| !result.failed_hashes.contains(hash))
        .collect();
    result.purged_hashes.extend(purged);
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
    if blob_exists_in_gcs(&hash)? {
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
    if blob_exists_in_gcs(&hash)? {
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
    sign_copy_request_at(req, config, copy_source, now)
}

fn sign_copy_request_at(
    req: &mut Request,
    config: &S3Config,
    copy_source: &str,
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

    let authorization = blossom_core::s3_signing::authorization(
        &config.access_key,
        &config.secret_key,
        config.region(),
        &date_stamp,
        &amz_date,
        &canonical_request,
        signed_headers,
    )
    .map_err(|error| BlossomError::Internal(error.into()))?;

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

    let authorization = blossom_core::s3_signing::authorization(
        &config.access_key,
        &config.secret_key,
        config.region(),
        &date_stamp,
        &amz_date,
        &canonical_request,
        signed_headers,
    )
    .map_err(|error| BlossomError::Internal(error.into()))?;

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
    sign_request_with_owner_at(req, config, payload_hash, owner, now)
}

fn sign_request_with_owner_at(
    req: &mut Request,
    config: &S3Config,
    payload_hash: Option<String>,
    owner: &str,
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

    let authorization = blossom_core::s3_signing::authorization(
        &config.access_key,
        &config.secret_key,
        config.region(),
        &date_stamp,
        &amz_date,
        &canonical_request,
        signed_headers,
    )
    .map_err(|error| BlossomError::Internal(error.into()))?;

    req.set_header("Authorization", authorization);

    Ok(())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PrivateFamilyCleanup {
    Absent,
    Remaining,
}

#[derive(Deserialize)]
struct CloudCleanupResponse {
    status: CloudCleanupStatus,
    private_family: Option<PrivateFamilyCleanup>,
    #[serde(default)]
    bounded_progress: bool,
}

#[derive(Deserialize)]
struct BatchHashCleanupResponse {
    hash: String,
    status: CloudCleanupStatus,
    main_deleted_or_absent: bool,
    private_family: Option<PrivateFamilyCleanup>,
    #[serde(default)]
    bounded_progress: bool,
    failures: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct BatchCleanupResponse {
    status: CloudCleanupStatus,
    results: Vec<BatchHashCleanupResponse>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct CloudBatchCleanupOutcome {
    failed_hashes: HashSet<String>,
    remaining_hashes: HashSet<String>,
    main_failures: HashSet<String>,
}

fn fail_all_cloud_cleanup(hashes: &[String]) -> CloudBatchCleanupOutcome {
    CloudBatchCleanupOutcome {
        failed_hashes: hashes.iter().cloned().collect(),
        remaining_hashes: HashSet::new(),
        main_failures: hashes.iter().cloned().collect(),
    }
}

fn classify_cloud_cleanup_response(status: StatusCode, body: &str) -> Result<()> {
    let cleanup = serde_json::from_str::<CloudCleanupResponse>(body).map_err(|_| {
        BlossomError::StorageError(format!(
            "Cloud Run derivative cleanup returned an untyped response with status {}",
            status
        ))
    })?;

    match cleanup.status {
        CloudCleanupStatus::Completed if status.is_success()
            && cleanup.private_family == Some(PrivateFamilyCleanup::Absent)
            && !cleanup.bounded_progress => Ok(()),
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
) -> CloudBatchCleanupOutcome {
    let Ok(response) = serde_json::from_str::<BatchCleanupResponse>(body) else {
        return fail_all_cloud_cleanup(requested);
    };
    if response.status == CloudCleanupStatus::Permanent
        || (response.status == CloudCleanupStatus::Completed && !status.is_success())
        || (response.status == CloudCleanupStatus::Retryable
            && status != StatusCode::SERVICE_UNAVAILABLE)
    {
        return fail_all_cloud_cleanup(requested);
    }

    let requested_normalized = requested
        .iter()
        .map(|hash| hash.to_lowercase())
        .collect::<HashSet<_>>();
    let mut outcomes = HashMap::new();
    for result in response.results {
        let hash = result.hash.to_lowercase();
        if !requested_normalized.contains(&hash) || outcomes.insert(hash, result).is_some() {
            return fail_all_cloud_cleanup(requested);
        }
    }
    let all_completed = outcomes.len() == requested_normalized.len()
        && outcomes
            .values()
            .all(|result| result.status == CloudCleanupStatus::Completed);
    if (response.status == CloudCleanupStatus::Completed) != all_completed {
        return fail_all_cloud_cleanup(requested);
    }
    let failed_hashes: HashSet<String> = requested
        .iter()
        .filter(|hash| {
            !outcomes.get(&hash.to_lowercase()).is_some_and(|result| {
                result.main_deleted_or_absent
                    && result.failures.as_ref().is_some_and(Vec::is_empty)
                    && ((result.status == CloudCleanupStatus::Completed
                        && result.private_family == Some(PrivateFamilyCleanup::Absent)
                        && !result.bounded_progress)
                        || (result.status == CloudCleanupStatus::Retryable
                            && result.private_family.is_some()
                            && result.bounded_progress))
            })
        })
        .cloned()
        .collect();
    let main_failures = requested
        .iter()
        .filter(|hash| {
            !outcomes.get(&hash.to_lowercase()).is_some_and(|result| {
                result.main_deleted_or_absent
                    && result.private_family == Some(PrivateFamilyCleanup::Absent)
            })
        })
        .cloned()
        .collect();
    let remaining_hashes = requested
        .iter()
        .filter(|hash| {
            outcomes.get(&hash.to_lowercase()).is_some_and(|result| {
                result.status == CloudCleanupStatus::Retryable
                    && result.main_deleted_or_absent
                    && result.private_family.is_some()
                    && result.bounded_progress
                    && result.failures.as_ref().is_some_and(Vec::is_empty)
            })
        })
        .filter(|hash| !failed_hashes.contains(*hash))
        .cloned()
        .collect();
    CloudBatchCleanupOutcome {
        failed_hashes,
        remaining_hashes,
        main_failures,
    }
}

fn apply_cloud_cleanup_outcome(
    result: &mut VanishStorageResult,
    main_origin_failures: &mut HashSet<String>,
    outcome: CloudBatchCleanupOutcome,
) {
    result.failed_hashes.extend(outcome.failed_hashes);
    main_origin_failures.extend(outcome.main_failures);
    main_origin_failures.extend(outcome.remaining_hashes.iter().cloned());
    result.remaining_hashes.extend(outcome.remaining_hashes);
}

fn plan_cloud_run_delete_chunks(hashes: &[String]) -> Vec<&[String]> {
    hashes.chunks(CLOUD_RUN_DELETE_BATCH_LIMIT).collect()
}

fn trigger_cloud_run_delete_blobs(hashes: &[String]) -> Result<CloudBatchCleanupOutcome> {
    if hashes.is_empty() {
        return Ok(CloudBatchCleanupOutcome::default());
    }
    let webhook_secret = get_secret("webhook_secret")?;
    let expected_bucket = get_config("gcs_bucket")?;
    let mut outcome = CloudBatchCleanupOutcome::default();
    for chunk in plan_cloud_run_delete_chunks(hashes) {
        let chunk_outcome = trigger_cloud_run_delete_blobs_chunk(
            chunk,
            &webhook_secret,
            &expected_bucket,
        )?;
        outcome.failed_hashes.extend(chunk_outcome.failed_hashes);
        outcome.remaining_hashes.extend(chunk_outcome.remaining_hashes);
        outcome.main_failures.extend(chunk_outcome.main_failures);
    }
    Ok(outcome)
}

fn trigger_cloud_run_delete_blobs_chunk(
    hashes: &[String],
    webhook_secret: &str,
    expected_bucket: &str,
) -> Result<CloudBatchCleanupOutcome> {
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

/// Pick the bounded post-purge probe sample: main source hashes whose purge
/// succeeded, sorted so the same batch always probes the same hashes.
pub(crate) fn delivery_probe_sample(
    purged_hashes: &HashSet<String>,
    main_candidates: &HashSet<String>,
    limit: usize,
) -> Vec<String> {
    let mut sample: Vec<String> = purged_hashes
        .iter()
        .filter(|hash| main_candidates.contains(*hash))
        .cloned()
        .collect();
    sample.sort();
    sample.truncate(limit);
    sample
}

struct DeliveryProbeReport {
    counts: DeliveryProbeCounts,
    present_hashes: Vec<(String, Option<u16>)>,
}

fn delivery_probe_report_from_body(body: &str) -> Option<DeliveryProbeReport> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let checked = value.get("checked")?.as_u64()? as u32;
    let present = value
        .get("present")
        .and_then(|value| value.as_u64())
        .unwrap_or(0) as u32;
    let inconclusive = value
        .get("inconclusive")
        .and_then(|value| value.as_u64())
        .unwrap_or(0) as u32;
    let present_hashes = value
        .get("results")
        .and_then(|value| value.as_array())
        .map(|results| {
            results
                .iter()
                .filter_map(|result| {
                    if result.get("outcome")?.as_str()? != "present" {
                        return None;
                    }
                    let hash = result.get("hash")?.as_str()?.to_string();
                    let status = result
                        .get("status")
                        .and_then(|value| value.as_u64())
                        .map(|value| value.min(u64::from(u16::MAX)) as u16);
                    Some((hash, status))
                })
                .collect()
        })
        .unwrap_or_default();
    Some(DeliveryProbeReport {
        counts: DeliveryProbeCounts {
            checked,
            present,
            inconclusive,
            errors: 0,
            ms: 0,
        },
        present_hashes,
    })
}

/// Wait on a borrowed pending-request or body handle without extending the
/// caller's absolute deadline. The host API treats a zero timeout as infinite.
pub(crate) fn wait_for_demand_io(handle: u32, deadline: Instant) -> io::Result<()> {
    wait_for_probe_io(handle, deadline)
}

fn wait_for_probe_io(handle: u32, deadline: Instant) -> io::Result<()> {
    let timeout_ms = deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .min(u128::from(u32::MAX)) as u32;
    if timeout_ms == 0 {
        return Err(io::ErrorKind::TimedOut.into());
    }
    let mut ready_index = u32::MAX;
    // SAFETY: both pointers are valid for the duration of the hostcall. The
    // caller retains ownership of the live handle; select only checks readiness.
    let status =
        unsafe { fastly_sys::fastly_async_io::select(&handle, 1, timeout_ms, &mut ready_index) };
    if status.is_err() {
        return Err(io::Error::other(format!("probe readiness: {status:?}")));
    }
    if ready_index != 0 || Instant::now() >= deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    Ok(())
}

/// Bound both response headers and each body read to the same erase deadline.
#[allow(deprecated)] // The pinned SDK exposes raw handles for the WASI p1 ABI.
fn send_delivery_probe(request: Request, deadline: Instant) -> io::Result<(StatusCode, String)> {
    if Instant::now() >= deadline {
        return Err(io::ErrorKind::TimedOut.into());
    }
    let (request, body) = request.into_handles();
    let pending = request
        .send_async_to_backend(
            body.unwrap_or_else(fastly::handle::BodyHandle::new),
            &fastly::Backend::from_name(CLOUD_RUN_BACKEND).expect("valid static backend name"),
        )
        .map_err(|error| io::Error::other(format!("probe send: {error}")))?;
    wait_for_probe_io(pending.as_u32(), deadline)?;
    let (response, mut body) = pending
        .wait()
        .map_err(|error| io::Error::other(format!("probe response: {error}")))?;
    let status = response.get_status();
    if !status.is_success() {
        return Ok((status, String::new()));
    }
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        // SAFETY: borrow this owned body handle only for the readiness check.
        wait_for_probe_io(unsafe { body.as_u32() }, deadline)?;
        // BodyHandle is unbuffered. Read only once per readiness notification:
        // read_to_end/into_string could block again after consuming ready bytes.
        let read = body.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8(bytes)
        .map(|body| (status, body))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Fetch a bounded sample of just-erased blobs through the public media host
/// and report whether an edge cache still serves them.
///
/// Best-effort: this never changes the erase result. A 2xx is a failure signal
/// for `vanish_timing` (`present`), any other status is inconclusive, and a
/// probe that cannot run to completion sets `errors` so an all-zero result is
/// not mistaken for a probe that simply had nothing to check.
pub(crate) fn probe_erased_delivery(hashes: &[String], deadline: Instant) -> DeliveryProbeCounts {
    let mut counts = DeliveryProbeCounts::default();
    if hashes.is_empty() {
        return counts;
    }
    let started = Instant::now();
    let webhook_secret = match get_secret("webhook_secret") {
        Ok(secret) if !secret.is_empty() => secret,
        _ => {
            eprintln!(
                "[VANISH] delivery_probe stage=setup error=missing_or_empty_webhook_secret key_count={}",
                hashes.len()
            );
            counts.errors = 1;
            counts.ms = elapsed_ms(started);
            return counts;
        }
    };
    let body = match serde_json::to_string(&serde_json::json!({ "hashes": hashes })) {
        Ok(body) => body,
        Err(error) => {
            eprintln!(
                "[VANISH] delivery_probe stage=setup error={} key_count={}",
                error,
                hashes.len()
            );
            counts.errors = 1;
            counts.ms = elapsed_ms(started);
            return counts;
        }
    };

    let mut request = Request::new(
        Method::POST,
        format!(
            "https://{}{}",
            CLOUD_RUN_HOST, CLOUD_RUN_DELIVERY_PROBE_PATH
        ),
    );
    request.set_header("Host", CLOUD_RUN_HOST);
    request.set_header("Content-Type", "application/json");
    request.set_header("Authorization", format!("Bearer {}", webhook_secret));
    request.set_body(Body::from(body));

    match send_delivery_probe(request, deadline) {
        Ok((status, body)) => {
            if !status.is_success() {
                eprintln!(
                    "[VANISH] delivery_probe stage=request status={} key_count={}",
                    status.as_u16(),
                    hashes.len()
                );
                counts.errors = 1;
            } else if let Some(report) = delivery_probe_report_from_body(&body) {
                for (hash, status) in &report.present_hashes {
                    eprintln!(
                        "[VANISH] delivery_probe hash={} outcome=present status={}",
                        hash,
                        status.unwrap_or(0)
                    );
                }
                counts = report.counts;
            } else {
                eprintln!(
                    "[VANISH] delivery_probe stage=parse error=invalid_body key_count={}",
                    hashes.len()
                );
                counts.errors = 1;
            }
        }
        Err(error) => {
            eprintln!(
                "[VANISH] delivery_probe stage=request error={} key_count={}",
                error,
                hashes.len()
            );
            counts.errors = 1;
        }
    }
    counts.ms = elapsed_ms(started);
    counts
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
    req.set_stale_if_error(0);
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
    #[test]
    fn cdn_invalidation_rejects_unbounded_or_ambiguous_batches_before_dispatch() {
        let hashes: Vec<String> = (0..5).map(|n| format!("{n:064x}")).collect();
        assert!(super::validate_b2_cdn_purge_batch(&hashes[..4]).is_ok());
        assert!(super::validate_b2_cdn_purge_batch(&hashes).is_err());
        assert!(super::validate_b2_cdn_purge_batch(&[hashes[0].clone(), hashes[0].clone()]).is_err());
        assert!(super::validate_b2_cdn_purge_batch(&["not-a-hash".into()]).is_err());
    }
    #[test]
    fn b2_cdn_purge_urls_cover_only_configured_normalized_keys() {
        let hash = "A".repeat(64);
        let urls = super::b2_cdn_purge_urls(&hash, "media-b2-cdn.divine.video,media-b2.divine.video", "media-b2-cdn.divine.video").unwrap();
        assert_eq!(urls, vec![format!("https://media-b2-cdn.divine.video/{}", "a".repeat(64)), format!("https://media-b2.divine.video/{}", "a".repeat(64))]);
        for hosts in ["", "https://media-b2-cdn.divine.video", "media-b2-cdn.divine.video:443", "media-b2-cdn.divine.video/path", "media-b2-cdn.divine.video\r\nX:bad", "other.divine.video", "media-b2-cdn.divine.video, media-b2.divine.video"] {
            assert!(super::b2_cdn_purge_urls(&hash, hosts, "media-b2-cdn.divine.video").is_err(), "invalid purge host set accepted");
        }
        assert!(super::b2_cdn_purge_urls("bad", "media-b2-cdn.divine.video", "media-b2-cdn.divine.video").is_err());
        assert!(super::b2_cdn_purge_urls(&hash, "media-b2-cdn.divine.video,media-b2-cdn.divine.video", "media-b2-cdn.divine.video").is_err());
    }
    #[test]
    fn canary_transient_transport_classification_preserves_setup_failures() {
        use fastly::http::request::SendErrorCause;
        for cause in [
            SendErrorCause::ConnectionTerminated,
            SendErrorCause::ConnectionTimeout,
            SendErrorCause::HttpResponseTimeout,
            SendErrorCause::HttpIncompleteResponse,
        ] {
            assert!(super::transient_canary_origin_error(&cause));
        }
        for cause in [
            SendErrorCause::DestinationNotFound,
            SendErrorCause::TlsConfigurationError,
            SendErrorCause::TlsCertificateError,
            SendErrorCause::HttpRequestUriInvalid,
            SendErrorCause::HttpResponseStatusInvalid,
            SendErrorCause::InternalError(None),
        ] {
            assert!(!super::transient_canary_origin_error(&cause));
        }
    }

    #[test]
    #[ignore = "requires synthetic storage backends; run-media-origin-tests.py"]
    fn derived_origin_b2_without_gcs_contract() {
        for mut response in [
            super::download_thumbnail("fixture.jpg").unwrap(),
            super::download_hls_from_gcs("fixture/hls/720p.mp4", Some("bytes=1-3")).unwrap(),
            super::download_transcript_from_gcs("fixture/vtt/main.vtt").unwrap(),
            super::download_transcript_uncached("fixture/vtt/main.vtt").unwrap(),
            super::download_sound_analysis_from_gcs("fixture/audio/analysis.json").unwrap(),
        ] {
            assert_eq!(response.get_header_str("X-Divine-Source"), Some("b2"));
            assert_eq!(response.get_header_str("x-goog-meta-c2pa-manifest-id"), Some("synthetic-manifest"));
            assert_eq!(response.get_header_str("x-goog-meta-source-sha256"), Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
            if response.get_status() == fastly::http::StatusCode::PARTIAL_CONTENT {
                assert_eq!(response.get_header_str("Content-Range"), Some("bytes 1-3/8"));
                assert_eq!(response.take_body().into_string(), "2 b");
            } else {
                assert_eq!(response.take_body().into_string(), "b2 bytes");
            }
        }
        assert!(super::download_thumbnail("missing").is_err());
        assert!(super::download_thumbnail("forbidden").is_err());
    }

    #[test]
    #[ignore = "requires synthetic storage backends; run-media-origin-tests.py"]
    fn derived_origin_default_independent_contract() {
        let mut response = super::download_hls_from_gcs("fixture/hls/720p.mp4", None).unwrap();
        assert_eq!(response.get_header_str("X-Divine-Source"), Some("gcs"));
        assert_eq!(response.take_body().into_string(), "gcs bytes");
    }

    #[test]
    #[ignore = "requires synthetic storage backends; run-media-origin-tests.py"]
    fn derived_origin_fallback_contract() {
        let mut response = super::download_thumbnail("missing").unwrap();
        assert_eq!(response.get_header_str("X-Divine-Source"), Some("gcs"));
        assert_eq!(response.take_body().into_string(), "gcs bytes");
        assert!(super::download_thumbnail("forbidden").is_err());
        let mut job = super::download_transcript_uncached_from_gcs("fixture/vtt/job.json").unwrap();
        assert_eq!(job.take_body().into_string(), "gcs bytes");
    }

    #[test]
    #[ignore = "requires synthetic storage backends; run-media-origin-tests.py"]
    fn derived_origin_invalid_config_contract() {
        assert!(super::download_thumbnail("fixture.jpg").is_err());
    }

    #[test]
    #[ignore = "requires synthetic storage backends; run-media-origin-tests.py"]
    fn media_origin_routing_contract() {
        let (mut response, source) = super::download_media_object("hit", None, false, false).unwrap();
        assert_eq!(source, "b2");
        assert_eq!(response.take_body().into_string(), "b2 bytes");
        let (mut response, source) = super::download_media_object("missing", None, false, false).unwrap();
        assert_eq!(source, "gcs");
        assert_eq!(response.take_body().into_string(), "gcs bytes");
        let (response, source) = super::download_media_object("transient", Some("bytes=1-3"), false, false).unwrap();
        assert_eq!(source, "gcs");
        assert_eq!(response.get_status(), fastly::http::StatusCode::PARTIAL_CONTENT);
        let error = match super::download_blob_with_fallback_impl("forbidden", None, false) {
            Ok(_) => panic!("B2 authentication failure must not fall back"),
            Err(error) => error,
        };
        assert_eq!(error.status_code().as_u16(), 502);
        let (mut response, source) = super::download_media_object("transport", None, false, false).unwrap();
        assert_eq!(source, "gcs");
        assert_eq!(response.take_body().into_string(), "gcs bytes");
    }

    #[test]
    #[ignore = "requires synthetic storage backends; run-media-origin-tests.py"]
    fn media_origin_disabled_fallback_contract() {
        let (response, source) = super::download_media_object("missing", None, false, false).unwrap();
        assert_eq!(source, "b2");
        assert_eq!(response.get_status(), fastly::http::StatusCode::NOT_FOUND);
    }

    #[test]
    #[ignore = "requires synthetic storage backends; run-media-origin-tests.py"]
    fn blob_exists_b2_without_gcs_contract() {
        assert!(super::blob_exists("hit").unwrap());
        assert!(!super::blob_exists("missing").unwrap());
        assert!(super::blob_exists("forbidden").is_err());
        assert!(super::blob_exists("transient").is_err());
        super::delete_blob("hit").unwrap();
        super::delete_blob_from_fos("hit").unwrap();
        crate::delete_blob_gcs_artifacts("hit").unwrap();
    }

    #[test]
    #[ignore = "requires synthetic storage backends; run-media-origin-tests.py"]
    fn blob_exists_b2_with_gcs_fallback_contract() {
        assert!(super::blob_exists("hit").unwrap());
        assert!(super::blob_exists("missing").unwrap());
        assert!(super::blob_exists("transient").unwrap());
        assert!(super::blob_exists("transport").unwrap());
        assert!(super::blob_exists("forbidden").is_err());
    }

    #[test]
    #[ignore = "requires synthetic config store; run-media-origin-tests.py"]
    fn media_origin_invalid_config_contract() {
        assert!(super::download_media_object("hit", None, false, false).is_err());
    }

    #[test]
    #[ignore = "requires synthetic storage backends; run-media-origin-tests.py"]
    fn media_origin_gcs_errors_contract() {
        for key in ["forbidden", "unavailable", "invalid-range", "disconnect"] {
            let error = match super::download_blob_with_fallback_impl(key, None, false) {
                Ok(_) => panic!("expected legacy GCS failure"),
                Err(error) => error,
            };
            assert_eq!(error.status_code().as_u16(), 404, "{key}");
        }
    }

    #[test]
    #[ignore = "requires synthetic config store; run-media-origin-tests.py"]
    fn media_origin_gcs_missing_config_contract() {
        let error = match super::download_blob_with_fallback_impl("hit", None, false) {
            Ok(_) => panic!("expected missing GCS configuration"),
            Err(error) => error,
        };
        assert_eq!(error.status_code().as_u16(), 404);
    }

    #[test]
    fn b2_media_read_signs_region_and_preserves_range() {
        let config = super::S3Config {
            access_key: "synthetic-access".into(),
            secret_key: "synthetic-secret".into(),
            bucket: "synthetic-authority".into(),
            host: "s3.us-west-004.backblazeb2.com".into(),
            region: "us-west-004".into(),
        };
        let req = super::build_media_read_request(
            &config,
            "abc/hls/main.ts",
            Some("bytes=1-3"),
            false,
            false,
        )
        .unwrap();
        assert_eq!(
            req.get_url().as_str(),
            "https://s3.us-west-004.backblazeb2.com/synthetic-authority/abc/hls/main.ts"
        );
        assert_eq!(req.get_header_str("Range"), Some("bytes=1-3"));
        assert!(req
            .get_header_str("Authorization")
            .unwrap()
            .contains("/us-west-004/s3/aws4_request"));
    }

    use super::{
        audit_log_entry, b2_api_host, b2_delete_version_succeeded, b2_dynamic_backend_name,
        b2_prefix_page, build_b2_delete_version_request, build_b2_list_versions_request,
        build_bunny_purge_request, build_fos_delete_request, build_multi_delete_request,
        canonical_query_string, classify_cloud_cleanup_response, cloud_run_delete_blob_body,
        cloud_run_delete_blobs_body, delivery_probe_report_from_body, delivery_probe_sample,
        failed_cloud_cleanup_hashes, failed_multi_delete_keys, mark_failed_stage,
        multi_delete_body, normalize_storage_cache_state, parse_audio_extraction_error_response,
        parse_funnelcake_audio_reuse_response, plan_cloud_run_delete_chunks,
        plan_vanish_delete_batches, prepare_storage_cache_miss, preserve_storage_cache_state,
        sign_request_at, validate_b2_authorization_scope, vanish_audit_entry, B2Authorization,
        B2AuthorizeResponse, B2FileVersion, B2ListFileVersionsResponse, DeliveryProbeCounts,
        S3Config, VanishAuditInitiator, VanishAuditPhase, VanishStorageResult,
        B2_LIST_PAGE_SIZE, CLOUD_RUN_DELETE_BATCH_LIMIT, FOS_BACKEND, PROVIDER_MULTI_DELETE_LIMIT,
        STORAGE_CACHE_HEADER,
    };
    use fastly::http::header;
    use fastly::{Request, Response};
    use std::{
        collections::{HashMap, HashSet},
        time::Duration,
    };

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
            r#"{"status":"completed","private_family":"absent","deleted":1}"#,
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
            r#"{{"status":"retryable","results":[{{"hash":"{completed_result}","status":"completed","main_deleted_or_absent":true,"private_family":"absent","failures":[]}},{{"hash":"{retryable}","status":"retryable","main_deleted_or_absent":true,"private_family":"absent","failures":["derivative failure"]}}]}}"#
        );

        let outcome = failed_cloud_cleanup_hashes(
            fastly::http::StatusCode::SERVICE_UNAVAILABLE,
            &body,
            &[completed.clone(), retryable.clone(), missing.clone()],
        );

        assert!(!outcome.failed_hashes.contains(&completed));
        assert!(outcome.failed_hashes.contains(&retryable));
        assert!(outcome.failed_hashes.contains(&missing));
        assert!(!outcome.main_failures.contains(&completed));
        assert!(!outcome.main_failures.contains(&retryable));
        assert!(outcome.main_failures.contains(&missing));
    }

    #[test]
    fn private_cloud_progress_is_pending_not_failed() {
        let hash = "a".repeat(64);
        let body = serde_json::json!({"status":"retryable","results":[{
            "hash":hash,"status":"retryable","main_deleted_or_absent":true,
            "private_family":"remaining","bounded_progress":true,"failures":[]
        }]})
        .to_string();
        let outcome = failed_cloud_cleanup_hashes(
            fastly::http::StatusCode::SERVICE_UNAVAILABLE,
            &body,
            std::slice::from_ref(&hash),
        );
        assert!(
            !outcome.failed_hashes.contains(&hash),
            "known private remainder must be Pending, not Failed"
        );
    }

    #[test]
    fn private_cloud_progress_requires_explicit_bounded_evidence() {
        let hash = "a".repeat(64);
        for receipt in ["absent", "remaining"] {
            for signal in [
                None,
                Some(serde_json::Value::Null),
                Some(false.into()),
                Some(true.into()),
                Some("true".into()),
            ] {
                let expected = signal == Some(serde_json::Value::Bool(true));
                let mut entry = serde_json::json!({"hash":hash,"status":"retryable",
                    "main_deleted_or_absent":true,"private_family":receipt,"failures":[]});
                if let Some(signal) = signal {
                    entry["bounded_progress"] = signal;
                }
                let body = serde_json::json!({"status":"retryable","results":[entry]}).to_string();
                let outcome = failed_cloud_cleanup_hashes(
                    fastly::http::StatusCode::SERVICE_UNAVAILABLE,
                    &body,
                    std::slice::from_ref(&hash),
                );
                assert_eq!(outcome.failed_hashes.is_empty(), expected);
                assert_eq!(outcome.remaining_hashes.contains(&hash), expected);
                if expected {
                    let mut result = super::VanishStorageResult::default();
                    let mut blocked = HashSet::new();
                    super::apply_cloud_cleanup_outcome(&mut result, &mut blocked, outcome);
                    assert!(
                        blocked.contains(&hash),
                        "known media remainder must block inline purge even with private absence"
                    );
                }
            }
        }
    }

    #[test]
    fn private_cloud_single_creator_requires_private_absence() {
        for receipt in [None, Some("remaining"), Some("absent")] {
            let mut body = serde_json::json!({"status":"completed"});
            if let Some(receipt) = receipt {
                body["private_family"] = receipt.into();
            }
            assert_eq!(
                classify_cloud_cleanup_response(fastly::http::StatusCode::OK, &body.to_string())
                    .is_ok(),
                receipt == Some("absent")
            );
        }
        assert!(classify_cloud_cleanup_response(
            fastly::http::StatusCode::OK,
            r#"{"status":"completed","private_family":"absent","bounded_progress":true}"#
        )
        .is_err());
    }

    #[test]
    fn private_cloud_completion_requires_private_absence_receipt() {
        let hash = "a".repeat(64);
        for receipt in [None, Some("remaining"), Some("unknown"), Some("absent")] {
            let mut result = serde_json::json!({"hash":hash,"status":"completed",
                "main_deleted_or_absent":true,"failures":[]});
            if let Some(receipt) = receipt {
                result["private_family"] = receipt.into();
            }
            let body = serde_json::json!({"status":"completed","results":[result]}).to_string();
            let outcome = failed_cloud_cleanup_hashes(
                fastly::http::StatusCode::OK,
                &body,
                std::slice::from_ref(&hash),
            );
            assert_eq!(outcome.failed_hashes.is_empty(), receipt == Some("absent"));
        }
    }

    #[test]
    fn private_cloud_progress_cannot_hide_uncertainty() {
        let hash = "a".repeat(64);
        for (main, failures, status) in [
            (
                false,
                serde_json::json!([]),
                fastly::http::StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                true,
                serde_json::json!(["listing failed"]),
                fastly::http::StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                true,
                serde_json::Value::Null,
                fastly::http::StatusCode::SERVICE_UNAVAILABLE,
            ),
            (true, serde_json::json!([]), fastly::http::StatusCode::OK),
        ] {
            let body = serde_json::json!({"status":"retryable","results":[{
                "hash":hash,"status":"retryable","main_deleted_or_absent":main,
                "private_family":"remaining","bounded_progress":true,"failures":failures
            }]})
            .to_string();
            assert!(
                failed_cloud_cleanup_hashes(status, &body, std::slice::from_ref(&hash))
                    .failed_hashes
                    .contains(&hash)
            );
        }
    }

    #[test]
    fn batch_cloud_cleanup_keeps_main_success_separate_from_derivative_failure() {
        let hash = "a".repeat(64);
        let body = format!(
            r#"{{"status":"retryable","results":[{{"hash":"{hash}","status":"retryable","main_deleted_or_absent":true,"private_family":"absent","failures":["derivative failure"]}}]}}"#
        );

        let outcome = failed_cloud_cleanup_hashes(
            fastly::http::StatusCode::SERVICE_UNAVAILABLE,
            &body,
            std::slice::from_ref(&hash),
        );

        assert!(outcome.failed_hashes.contains(&hash));
        assert!(!outcome.main_failures.contains(&hash));
    }

    #[test]
    fn batch_cloud_cleanup_rejects_completion_without_main_confirmation() {
        let hash = "a".repeat(64);
        let body = format!(
            r#"{{"status":"completed","results":[{{"hash":"{hash}","status":"completed","main_deleted_or_absent":false}}]}}"#
        );

        let outcome = failed_cloud_cleanup_hashes(
            fastly::http::StatusCode::OK,
            &body,
            std::slice::from_ref(&hash),
        );

        assert!(outcome.failed_hashes.contains(&hash));
        assert!(outcome.main_failures.contains(&hash));
    }

    #[test]
    fn batch_cloud_cleanup_rejects_completed_body_with_error_status() {
        let hash = "a".repeat(64);
        let body = format!(
            r#"{{"status":"completed","results":[{{"hash":"{hash}","status":"completed","main_deleted_or_absent":true,"private_family":"absent","failures":[]}}]}}"#
        );

        let outcome = failed_cloud_cleanup_hashes(
            fastly::http::StatusCode::SERVICE_UNAVAILABLE,
            &body,
            std::slice::from_ref(&hash),
        );

        assert!(outcome.failed_hashes.contains(&hash));
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

    fn b2_authorize_response(capabilities: &[&str], buckets: &[&str]) -> B2AuthorizeResponse {
        serde_json::from_value(serde_json::json!({
            "authorizationToken": "account-token",
            "apiInfo": {
                "storageApi": {
                    "apiUrl": "https://api001.backblazeb2.com",
                    "allowed": {
                        "buckets": buckets
                            .iter()
                            .map(|id| serde_json::json!({"id": id, "name": "replica"}))
                            .collect::<Vec<_>>(),
                        "capabilities": capabilities,
                        "namePrefix": null
                    }
                }
            }
        }))
        .expect("valid authorization response")
    }

    #[test]
    fn b2_vanish_authorization_requires_one_bucket_and_exact_capabilities() {
        let accepted = b2_authorize_response(&["listFiles", "deleteFiles"], &["bucket-id"]);
        assert!(validate_b2_authorization_scope(&accepted, "bucket-id").is_ok());

        let broad = b2_authorize_response(
            &["listFiles", "deleteFiles", "deleteBuckets"],
            &["bucket-id"],
        );
        assert!(validate_b2_authorization_scope(&broad, "bucket-id").is_err());
        let all_buckets = b2_authorize_response(&["listFiles", "deleteFiles"], &[]);
        assert!(validate_b2_authorization_scope(&all_buckets, "bucket-id").is_err());
    }

    #[test]
    fn b2_api_host_rejects_redirects_outside_backblaze() {
        assert_eq!(
            b2_api_host("https://api001.backblazeb2.com").expect("B2 API host"),
            "api001.backblazeb2.com"
        );
        assert!(b2_api_host("http://api001.backblazeb2.com").is_err());
        assert!(b2_api_host("https://backblazeb2.com.example").is_err());
        assert_ne!(
            b2_dynamic_backend_name("api001.backblazeb2.com"),
            b2_dynamic_backend_name("api002.backblazeb2.com")
        );
    }

    #[test]
    fn b2_prefix_page_stops_after_the_prefix_and_rejects_backtracking() {
        let hash = "a".repeat(64);
        let page = B2ListFileVersionsResponse {
            files: vec![
                B2FileVersion {
                    file_name: format!("{hash}/720p.mp4"),
                    file_id: Some("version-id".into()),
                },
                B2FileVersion {
                    file_name: "beyond-prefix".into(),
                    file_id: Some("other-id".into()),
                },
            ],
            next_file_name: Some("later".into()),
            next_file_id: Some("later-id".into()),
        };
        let (matching, next) = b2_prefix_page(&hash, &page).expect("ordered prefix page");
        assert_eq!(matching.len(), 1);
        assert!(next.is_none());

        let backtracking = B2ListFileVersionsResponse {
            files: vec![B2FileVersion {
                file_name: "0-before-prefix".into(),
                file_id: Some("version-id".into()),
            }],
            next_file_name: None,
            next_file_id: None,
        };
        assert!(b2_prefix_page(&hash, &backtracking).is_err());
    }

    #[test]
    fn b2_prefix_page_distinguishes_remaining_versions_from_terminal_absence() {
        let hash = "a".repeat(64);
        let remaining = B2ListFileVersionsResponse {
            files: vec![B2FileVersion {
                file_name: hash.clone(),
                file_id: Some("version-id".into()),
            }],
            next_file_name: None,
            next_file_id: None,
        };
        let scanning = B2ListFileVersionsResponse {
            files: vec![],
            next_file_name: Some(format!("{hash}/next")),
            next_file_id: Some("id".into()),
        };
        let absent = B2ListFileVersionsResponse {
            files: vec![B2FileVersion {
                file_name: "beyond-prefix".into(),
                file_id: Some("other-id".into()),
            }],
            next_file_name: Some("later".into()),
            next_file_id: Some("later-id".into()),
        };

        let (versions, _) = b2_prefix_page(&hash, &remaining).expect("remaining page");
        assert_eq!(versions.len(), 1);
        let (versions, next) = b2_prefix_page(&hash, &scanning).expect("scanning page");
        assert!(versions.is_empty());
        assert!(next.is_some());
        let (versions, next) = b2_prefix_page(&hash, &absent).expect("terminal page");
        assert!(versions.is_empty());
        assert!(next.is_none());
    }

    #[test]
    #[ignore = "loopback Cloud Run fixture and persistent local KV required"]
    fn private_cloud_progress_reaches_physical_pending_and_retains_audio_discovery() {
        use crate::b2_cdn_phase::{self, Physical};
        let source = "4".repeat(64);
        let audio = "5".repeat(64);
        let hashes = vec![source.clone(), audio.clone()];
        crate::metadata::put_audio_mapping(&crate::blossom::AudioMapping {
            source_sha256: source.clone(),
            audio_sha256: audio.clone(),
            duration_seconds: 6.0,
            size_bytes: 1,
            mime_type: "audio/aac".into(),
        })
        .unwrap();
        let plan = crate::prepare_derived_audio_cleanup(&source)
            .unwrap()
            .unwrap();
        let store = crate::metadata::open_store().unwrap();
        for attempt in 0..3 {
            let outcome =
                super::trigger_cloud_run_delete_blobs_chunk(&hashes, "synthetic", "synthetic")
                    .unwrap();
            let mut result = super::VanishStorageResult::default();
            let mut blocked = HashSet::new();
            super::apply_cloud_cleanup_outcome(&mut result, &mut blocked, outcome);
            let expected = if attempt == 0 {
                hashes.iter().cloned().collect()
            } else if attempt == 1 {
                HashSet::from([audio.clone()])
            } else {
                HashSet::new()
            };
            assert!(
                result.failed_hashes.is_empty(),
                "bounded GCS progress must not count as error"
            );
            assert_eq!(result.remaining_hashes, expected);
            assert_eq!(
                blocked, expected,
                "pending private versions cannot reach inline purge"
            );
            for hash in &hashes {
                let epoch = super::begin_vanish_phase(hash).unwrap().unwrap();
                super::finish_vanish_phase(
                    hash,
                    &epoch,
                    &result.failed_hashes,
                    &result.remaining_hashes,
                )
                .unwrap();
                b2_cdn_phase::ensure_final_intent(hash).unwrap();
                if expected.contains(hash) {
                    assert_eq!(
                        b2_cdn_phase::physical_state(hash).unwrap(),
                        Some(Physical::Pending)
                    );
                    assert!(!b2_cdn_phase::final_queued(hash).unwrap());
                    assert!(!super::vanish_complete(hash));
                } else {
                    assert_eq!(
                        b2_cdn_phase::physical_state(hash).unwrap(),
                        Some(Physical::Absent)
                    );
                    // Synthetic acknowledgement after the final intent, matching
                    // the existing separately executed purge receipt contract.
                    let _ = b2_cdn_phase::mark_final_purged(&store, hash, &epoch).unwrap();
                    assert!(super::vanish_complete(hash));
                }
            }
            let deferred = if expected.contains(&audio) {
                HashSet::from([source.clone()])
            } else {
                HashSet::new()
            };
            assert_eq!(
                crate::vanish_blob_disposition(
                    &source,
                    &result.failed_hashes,
                    &result.remaining_hashes,
                    &HashSet::new(),
                    &deferred
                ),
                if attempt < 2 {
                    crate::VanishBlobDisposition::Deferred
                } else {
                    crate::VanishBlobDisposition::Finalize
                }
            );
            assert!(crate::metadata::get_audio_mapping(&source)
                .unwrap()
                .is_some());
            if attempt == 2 {
                crate::finalize_derived_audio_cleanup(&plan).unwrap();
            }
        }
        assert!(crate::metadata::get_audio_mapping(&source)
            .unwrap()
            .is_none());
    }

    #[test]
    #[ignore = "loopback provider fixture and persistent local KV required"]
    fn private_family_erasure_contract() {
        let authorization = B2Authorization {
            api_url: "https://api001.backblazeb2.com".into(),
            authorization_token: "synthetic".into(),
            bucket_id: "synthetic".into(),
            bucket_name: None,
            backend: fastly::Backend::from_name("b2_api").unwrap(),
        };
        {
            let letter = super::get_config("fixture_case").unwrap();
            let letter = letter.chars().next().unwrap();
            let attempts: usize = super::get_config("fixture_attempts")
                .unwrap()
                .parse()
                .unwrap();
            let letters = if letter == '0' {
                vec!['0', '1']
            } else {
                vec![letter]
            };
            for hash_letter in letters {
                let hash = hash_letter.to_string().repeat(64);
                for attempt in 0..attempts {
                    assert_eq!(
                        Request::get(format!(
                            "https://api001.backblazeb2.com/fixture/begin/{hash}/{attempt}"
                        ))
                        .send("b2_api")
                        .unwrap()
                        .get_status(),
                        200
                    );
                    let result = super::erase_b2_hash_versions(&authorization, &hash);
                    assert_eq!(
                        Request::get("https://api001.backblazeb2.com/fixture/end")
                            .send("b2_api")
                            .unwrap()
                            .get_status(),
                        200
                    );
                    if letter == '3' {
                        assert!(result.is_err(), "uncertain copy gate must retain erasure");
                    } else if attempt + 1 == attempts {
                        assert!(
                            matches!(result, Ok(super::B2HashErasure::Erased)),
                            "{letter}: final attempt did not prove both namespaces absent"
                        );
                    } else if letter == 'b' || letter == 'f' {
                        assert!(
                            matches!(result, Ok(super::B2HashErasure::MoreRemaining)),
                            "large retained marker history must remain pending"
                        );
                    } else {
                        assert!(result.is_err(), "{letter}: uncertainty must fail closed");
                    }
                }
                let mut entry = fastly::kv_store::KVStore::open("blossom_metadata")
                    .unwrap()
                    .unwrap()
                    .lookup(&format!("b2-sync:v1:{hash}"))
                    .unwrap();
                assert!(entry.take_body().into_string().contains(if letter == '3' {
                    "copying"
                } else {
                    "erasing"
                }));
            }
            assert_eq!(super::B2_VANISH_MAX_STORAGE_BACKEND_REQUESTS, 26);
        }
    }

    #[test]
    fn b2_version_requests_use_native_version_apis() {
        let authorization = B2Authorization {
            api_url: "https://api001.backblazeb2.com".into(),
            authorization_token: "account-token".into(),
            bucket_id: "bucket-id".into(),
            bucket_name: Some("private-test".into()),
            backend: fastly::Backend::from_name("b2_api").expect("backend name"),
        };
        let hash = "a".repeat(64);
        let mut list = build_b2_list_versions_request(
            &authorization,
            &hash,
            Some(("next-name", Some("next-id"))),
        )
        .expect("list request");
        assert_eq!(
            list.get_url().as_str(),
            "https://api001.backblazeb2.com/b2api/v4/b2_list_file_versions"
        );
        let list_body: serde_json::Value =
            serde_json::from_str(&list.take_body().into_string()).expect("list JSON");
        assert_eq!(list_body["bucketId"], "bucket-id");
        assert_eq!(list_body["prefix"], hash);
        assert_eq!(list_body["startFileName"], "next-name");
        assert_eq!(list_body["startFileId"], "next-id");

        let mut initial = build_b2_list_versions_request(
            &authorization,
            &hash,
            Some((&hash, None)),
        )
        .expect("initial list request");
        let initial_body: serde_json::Value =
            serde_json::from_str(&initial.take_body().into_string()).expect("initial list JSON");
        assert_eq!(initial_body["startFileName"], hash);
        assert!(initial_body.get("startFileId").is_none());
        assert_eq!(initial_body["maxFileCount"], B2_LIST_PAGE_SIZE);

        let version = B2FileVersion {
            file_name: format!("{hash}/720p.mp4"),
            file_id: Some("version-id".into()),
        };
        let mut delete =
            build_b2_delete_version_request(&authorization, &version).expect("delete request");
        assert_eq!(
            delete.get_url().as_str(),
            "https://api001.backblazeb2.com/b2api/v4/b2_delete_file_version"
        );
        let delete_body: serde_json::Value =
            serde_json::from_str(&delete.take_body().into_string()).expect("delete JSON");
        assert_eq!(delete_body["fileName"], version.file_name);
        assert_eq!(delete_body["fileId"], "version-id");
    }

    #[test]
    fn bunny_delivery_zone_parser_rejects_malformed_duplicates_and_empty_segments() {
        assert_eq!(
            super::parse_bunny_delivery_zones(" Media.Divine.Video , divine-media-cdn.b-cdn.net ")
                .unwrap(),
            vec![
                "media.divine.video".to_string(),
                "divine-media-cdn.b-cdn.net".to_string()
            ]
        );
        for bad in [
            "",
            "   ",
            "media.divine.video,",
            ",media.divine.video",
            "media.divine.video,,divine-media-cdn.b-cdn.net",
            "media.divine.video,MEDIA.DIVINE.VIDEO",
            "localhost",
            "-bad.divine.video",
            "bad-.divine.video",
            "a..b.divine.video",
            "a.divine.video,b.divine.video,c.divine.video",
        ] {
            assert!(
                super::parse_bunny_delivery_zones(bad).is_err(),
                "expected invalid bunny_delivery_zones to fail: {bad:?}"
            );
        }
    }

    #[test]
    fn b2_version_listing_keeps_uploads_and_hide_markers_for_deletion() {
        let hash = "a".repeat(64);
        let body = format!(
            r#"{{"files":[{{"action":"upload","fileName":"{hash}","fileId":"upload-id"}},{{"action":"hide","fileName":"{hash}","fileId":"hide-id"}}],"nextFileName":null,"nextFileId":null}}"#
        );

        let page: B2ListFileVersionsResponse =
            serde_json::from_str(&body).expect("version listing");

        assert_eq!(page.files.len(), 2);
        assert_eq!(page.files[0].file_id.as_deref(), Some("upload-id"));
        assert_eq!(page.files[1].file_id.as_deref(), Some("hide-id"));
    }

    #[test]
    fn b2_version_delete_is_idempotent_only_for_file_not_present() {
        let absent = Response::from_status(fastly::http::StatusCode::BAD_REQUEST)
            .with_body(r#"{"code":"file_not_present"}"#);
        let denied = Response::from_status(fastly::http::StatusCode::BAD_REQUEST)
            .with_body(r#"{"code":"access_denied"}"#);

        assert!(b2_delete_version_succeeded(absent));
        assert!(!b2_delete_version_succeeded(denied));
    }

    #[test]
    fn bunny_purge_uses_the_bare_hash_wildcard() {
        let hash = "a".repeat(64);
        let request = build_bunny_purge_request(
            "v-a.divine.video",
            &hash,
            "synthetic-api-key",
            "purge_bunny:0",
        );

        assert_eq!(
            request.get_url().as_str(),
            format!("https://api.bunny.net/purge?url=https%3A%2F%2Fv-a.divine.video%2F{hash}%2A&async=false")
        );
        assert_eq!(
            request.get_header_str("AccessKey"),
            Some("synthetic-api-key")
        );
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
    fn shared_signer_preserves_edge_golden_requests_and_unsigned_ranges() {
        let cases: serde_json::Value =
            serde_json::from_str(include_str!("../blossom-core/tests/s3_signing_golden.json")).unwrap();
        let config = S3Config {
            access_key: "synthetic-access".into(),
            secret_key: "synthetic-secret".into(),
            bucket: "private-test".into(),
            host: "s3.us-west-004.backblazeb2.com".into(),
            region: "us-west-004".into(),
        };
        let now = Duration::from_secs(1_794_013_323);
        for case in cases.as_array().unwrap() {
            let canonical = case["canonical_request"].as_str().unwrap();
            let lines: Vec<_> = canonical.split('\n').collect();
            let host = lines[3].strip_prefix("host:").unwrap();
            let url = format!("https://{}{}?{}", config.host, lines[1], lines[2]);
            for range in ["bytes=0-3", "bytes=4-"] {
                let mut req = Request::new(lines[0], &url);
                req.set_header("Host", host);
                req.set_header("Range", range);
                let payload = Some(lines.last().unwrap().to_string());
                match case["name"].as_str().unwrap() {
                    "owner_metadata" => super::sign_request_with_owner_at(
                        &mut req,
                        &config,
                        payload,
                        &"c".repeat(64),
                        now,
                    )
                    .unwrap(),
                    "copy_metadata" => {
                        super::sign_copy_request_at(&mut req, &config, "/source/key%2Bvalue", now)
                            .unwrap()
                    }
                    _ => sign_request_at(&mut req, &config, payload, now).unwrap(),
                }
                assert_eq!(
                    req.get_header_str("Authorization"),
                    case["authorization"].as_str(),
                    "{} {range}",
                    case["name"]
                );
            }
        }
    }

    #[test]
    fn shared_signer_bad_configuration_never_adds_authorization() {
        let now = Duration::from_secs(1_794_013_323);
        for (access_key, secret_key, region) in [
            ("", "synthetic-secret", "us-west-004"),
            ("synthetic-access", "", "us-west-004"),
            ("synthetic-access", "synthetic-secret", ""),
        ] {
            let config = S3Config {
                access_key: access_key.into(),
                secret_key: secret_key.into(),
                bucket: "private-test".into(),
                host: "synthetic.example".into(),
                region: region.into(),
            };
            let mut req = Request::get("https://synthetic.example/object");
            req.set_header("Host", "synthetic.example");
            assert!(sign_request_at(&mut req, &config, None, now).is_err());
            assert!(!req.contains_header("Authorization"));
        }
        let config = S3Config {
            access_key: "synthetic-access".into(),
            secret_key: "synthetic-secret".into(),
            bucket: "private-test".into(),
            host: "synthetic.example".into(),
            region: "us-west-004".into(),
        };
        let mut req = Request::get("https://synthetic.example/object");
        req.remove_header("Host");
        assert!(sign_request_at(&mut req, &config, None, now).is_err());
        assert!(!req.contains_header("Authorization"));
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
    fn vanish_delete_plan_selects_one_provider_per_runtime() {
        let hashes = (0..1_001)
            .map(|index| format!("{index:064x}"))
            .collect::<Vec<_>>();
        let production_batches = plan_vanish_delete_batches(&hashes, false);
        let local_batches = plan_vanish_delete_batches(&hashes, true);

        assert!(production_batches
            .iter()
            .all(|batch| batch.keys.len() <= PROVIDER_MULTI_DELETE_LIMIT));
        assert!(production_batches
            .iter()
            .all(|batch| batch.stage.starts_with("fos_main:")));
        assert!(local_batches
            .iter()
            .all(|batch| batch.stage.starts_with("gcs_main:")));
        assert_eq!(production_batches.len(), 2);
        assert_eq!(local_batches.len(), 2);
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

    // These use a loopback upload stub supplied by the deadline test runner.
    #[test]
    #[ignore = "requires scripts/run-probe-deadline-tests.py"]
    fn delivery_probe_deadline_bounds_headers_and_body() {
        for marker in ['a', 'b', 'c', 'd'] {
            let started = std::time::Instant::now();
            let counts = super::probe_erased_delivery(
                &[marker.to_string().repeat(64)],
                started + Duration::from_millis(400),
            );
            eprintln!(
                "deadline case {marker}: completed in {:?}",
                started.elapsed()
            );
            assert_eq!(
                counts.errors, 1,
                "{marker}: incomplete probe must be recorded"
            );
            assert_eq!(
                counts.checked, 0,
                "{marker}: incomplete report is not a clean probe"
            );
            assert!(
                started.elapsed() < Duration::from_millis(550),
                "{marker}: probe outlived its 400ms budget: {:?}",
                started.elapsed()
            );
        }
    }

    #[test]
    #[ignore = "requires scripts/run-probe-deadline-tests.py"]
    fn delivery_probe_deadline_preserves_completed_results() {
        let counts = super::probe_erased_delivery(
            &["e".repeat(64)],
            std::time::Instant::now() + Duration::from_millis(400),
        );
        assert_eq!(counts.errors, 0);
        assert_eq!(counts.checked, 1);
        assert_eq!(counts.present, 1);
    }

    #[test]
    fn delivery_probe_deadline_never_waits_indefinitely_for_zero_budget() {
        let now = std::time::Instant::now();
        // A zero host timeout means infinite wait, so reject before touching
        // even a ready handle. An invalid handle proves no hostcall is made.
        for deadline in [now, now + Duration::from_nanos(1)] {
            assert_eq!(
                super::wait_for_probe_io(u32::MAX, deadline)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::TimedOut
            );
        }
    }

    #[test]
    fn delivery_probe_samples_only_purged_main_hashes_in_stable_order() {
        let main_a = "a".repeat(64);
        let main_b = "b".repeat(64);
        let main_c = "c".repeat(64);
        let main_d = "d".repeat(64);
        let audio = "e".repeat(64);

        let purged: HashSet<String> = [&main_c, &main_a, &main_b, &audio, &main_d]
            .into_iter()
            .cloned()
            .collect();
        let candidates: HashSet<String> = [&main_a, &main_b, &main_c, &main_d]
            .into_iter()
            .cloned()
            .collect();

        assert_eq!(
            delivery_probe_sample(&purged, &candidates, 3),
            vec![main_a.clone(), main_b.clone(), main_c.clone()]
        );
        assert!(delivery_probe_sample(&purged, &candidates, 0).is_empty());
    }

    #[test]
    fn delivery_probe_report_extracts_counts_and_present_hashes() {
        let body = format!(
            r#"{{"checked":3,"absent":1,"present":1,"inconclusive":1,"results":[{{"hash":"{}","outcome":"absent","status":404}},{{"hash":"{}","outcome":"present","status":200}},{{"hash":"{}","outcome":"inconclusive"}}]}}"#,
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
        );

        let report = delivery_probe_report_from_body(&body).expect("valid report");
        assert_eq!(
            report.counts,
            DeliveryProbeCounts {
                checked: 3,
                present: 1,
                inconclusive: 1,
                errors: 0,
                ms: 0,
            }
        );
        assert_eq!(report.present_hashes, vec![("b".repeat(64), Some(200))]);
    }

    #[test]
    fn delivery_probe_report_rejects_a_body_without_counts() {
        assert!(delivery_probe_report_from_body("not json").is_none());
        assert!(delivery_probe_report_from_body(r#"{"present":1}"#).is_none());
    }

    #[test]
    fn vanish_storage_retry_keeps_purged_hashes_and_replaces_failures() {
        let mut first = VanishStorageResult::default();
        first.failed_hashes.insert("a".repeat(64));
        first.purged_hashes.insert("b".repeat(64));

        let mut retry = VanishStorageResult::default();
        retry.failed_hashes.insert("c".repeat(64));
        retry.purged_hashes.insert("a".repeat(64));

        first.replace_failures_after_retry(retry);

        assert_eq!(
            first.failed_hashes,
            ["c".repeat(64)].into_iter().collect::<HashSet<_>>()
        );
        assert_eq!(
            first.purged_hashes,
            ["a".repeat(64), "b".repeat(64)]
                .into_iter()
                .collect::<HashSet<_>>()
        );
    }

    #[test]
    fn vanish_inline_fastly_purge_respects_5_secret_budget_and_records_deferral() {
        let _scope = crate::request_bindings::begin();
        for key in ["fos_access_key", "fos_secret_key", "webhook_secret"] {
            let _ = crate::request_bindings::secret(key);
        }
        assert!(
            super::vanish_inline_fastly_purge_has_budget(),
            "3-secret wave with webhook_secret cached must still afford fastly_api_token + kv_origin_read_token"
        );

        let _ = crate::request_bindings::secret("admin_token");
        assert!(
            !super::vanish_inline_fastly_purge_has_budget(),
            "4-secret wave reserving kv_origin_read_token must defer inline Fastly purge"
        );

        let hash = "a".repeat(64);
        let mut result = VanishStorageResult::default();
        let purged = super::purge_vanish_hashes(std::slice::from_ref(&hash), &mut result);
        assert!(purged.is_empty());
        assert!(result.purge_deferred);
    }

    #[test]
    fn vanish_physical_secret_budget_distinguishes_kv_origin_retry_from_exhausted_auth() {
        {
            let _scope = crate::request_bindings::begin();
            assert_eq!(
                super::vanish_physical_secret_budget_for(false, true),
                super::VanishPhysicalSecretBudget::Ready
            );
            let _ = crate::request_bindings::secret("webhook_secret");
            assert_eq!(
                super::vanish_physical_secret_budget_for(false, true),
                super::VanishPhysicalSecretBudget::Ready
            );
            let _ = crate::request_bindings::secret("kv_origin_read_token");
            assert_eq!(
                super::vanish_physical_secret_budget_for(false, true),
                super::VanishPhysicalSecretBudget::DeferForKvOriginRetry
            );
        }
        {
            let _scope = crate::request_bindings::begin();
            let _ = crate::request_bindings::secret("admin_token");
            assert_eq!(
                super::vanish_physical_secret_budget_for(false, true),
                super::VanishPhysicalSecretBudget::Exhausted
            );
            let _ = crate::request_bindings::secret("kv_origin_read_token");
            assert_eq!(
                super::vanish_physical_secret_budget_for(false, true),
                super::VanishPhysicalSecretBudget::Exhausted
            );
            let _ = crate::request_bindings::secret("webhook_secret");
            assert_eq!(
                super::vanish_physical_secret_budget_for(false, true),
                super::VanishPhysicalSecretBudget::Exhausted
            );
        }
        {
            let _scope = crate::request_bindings::begin();
            for key in ["admin_token", "webhook_secret", "kv_origin_read_token"] {
                let _ = crate::request_bindings::secret(key);
            }
            assert_eq!(
                super::vanish_physical_secret_budget_for(false, false),
                super::VanishPhysicalSecretBudget::Ready
            );
        }
    }
}

/// Archive originals bypass legacy global origin policy; public policy ran at the caller.
pub(crate) fn download_archive_original(hash:&str, range:Option<&str>, receipt:&crate::blossom::ArchiveStorage)->Result<FallbackDownloadResult> {
    if receipt.bucket!=get_config("b2_media_bucket")? {return Err(BlossomError::StorageError("Archive bucket mismatch".into()));}
    let response=fetch_media_origin(StorageProvider::B2,hash,range,true,false).map_err(MediaFetchError::into_storage_error)?;
    Ok(FallbackDownloadResult{response:blob_download_response(response)?,source:"b2".into(),diagnostics:None,b2_missing:false})
}
