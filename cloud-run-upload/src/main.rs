// ABOUTME: Rust Cloud Run service for Blossom blob uploads
// ABOUTME: Handles Nostr auth validation, streaming upload to GCS, and SHA-256 hashing

mod resumable;
mod thumbnail;

use anyhow::{anyhow, Result};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, head, options, post, put},
    Router,
};
use bytes::Bytes;
use futures::StreamExt;
use google_cloud_storage::{
    client::{Client as GcsClient, ClientConfig},
    http::objects::{
        download::Range as DownloadRange,
        get::GetObjectRequest,
        upload::{Media, UploadObjectRequest, UploadType},
        Object,
    },
};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder;
use k256::schnorr::{
    signature::hazmat::PrehashVerifier, signature::Signer, Signature, SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    env,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::NamedTempFile;
use tower::Service;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};

// Configuration
#[derive(Clone)]
struct Config {
    gcs_bucket: String,
    cdn_base_url: String,
    upload_base_url: String,
    port: u16,
    migration_nsec: Option<String>,
    transcoder_url: Option<String>,
    transcriber_url: Option<String>,
    resumable_session_ttl_secs: u64,
    resumable_chunk_size: u64,
}

impl Config {
    fn from_env() -> Self {
        Self {
            gcs_bucket: env::var("GCS_BUCKET")
                .unwrap_or_else(|_| "divine-blossom-media".to_string()),
            cdn_base_url: env::var("CDN_BASE_URL")
                .unwrap_or_else(|_| "https://media.divine.video".to_string()),
            upload_base_url: env::var("UPLOAD_BASE_URL")
                .unwrap_or_else(|_| "https://upload.divine.video".to_string()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .unwrap_or(8080),
            migration_nsec: env::var("MIGRATION_NSEC").ok(),
            // URL of the divine-transcoder service for HLS generation
            transcoder_url: env::var("TRANSCODER_URL").ok(),
            // URL of the transcription service (defaults to TRANSCODER_URL when not explicitly set)
            transcriber_url: env::var("TRANSCRIBER_URL")
                .ok()
                .or_else(|| env::var("TRANSCODER_URL").ok()),
            resumable_session_ttl_secs: env::var("RESUMABLE_SESSION_TTL_SECS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(resumable::DEFAULT_RESUMABLE_SESSION_TTL_SECS),
            resumable_chunk_size: env::var("RESUMABLE_CHUNK_SIZE")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(resumable::DEFAULT_RESUMABLE_CHUNK_SIZE),
        }
    }
}

fn init_sentry(service_name: &str) -> sentry::ClientInitGuard {
    let environment = env::var("SENTRY_ENVIRONMENT")
        .ok()
        .filter(|value| !value.is_empty());
    let server_name = env::var("SENTRY_SERVER_NAME")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| service_name.to_string());

    sentry::init(sentry::ClientOptions {
        dsn: env::var("SENTRY_DSN")
            .ok()
            .filter(|value| !value.is_empty())
            .and_then(|value| value.parse().ok()),
        environment: environment.map(Into::into),
        server_name: Some(server_name.into()),
        release: sentry::release_name!(),
        ..Default::default()
    })
}

fn report_derivative_failure_to_sentry(
    service: &'static str,
    derivative: &'static str,
    hash: &str,
    error_code: &str,
    error_message: &str,
    terminal: bool,
    content_type: Option<&str>,
    owner: Option<&str>,
) {
    // User-caused invalid media (corrupt uploads, missing moov atom, etc.) are warnings,
    // not errors — they don't indicate system failures.
    let level = if error_code == "invalid_media" {
        sentry::Level::Warning
    } else {
        sentry::Level::Error
    };
    let fingerprint = [service, derivative, error_code];
    sentry::with_scope(
        |scope| {
            scope.set_level(Some(level));
            scope.set_fingerprint(Some(fingerprint.as_ref()));
            scope.set_tag("service", service);
            scope.set_tag("derivative", derivative);
            scope.set_tag("error_code", error_code);
            scope.set_tag("terminal", terminal.to_string());
            if let Some(content_type) = content_type {
                scope.set_tag("content_type", content_type);
            }
            scope.set_extra("sha256", serde_json::json!(hash));
            if let Some(owner) = owner {
                scope.set_extra("owner", serde_json::json!(owner));
            }
        },
        || {
            sentry::capture_message(error_message, level);
        },
    );
}

// App state shared across handlers
struct AppState {
    gcs_client: GcsClient,
    config: Config,
}

// Nostr auth event structure
#[derive(Debug, Deserialize)]
struct NostrEvent {
    id: String,
    pubkey: String,
    created_at: i64,
    kind: u32,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}

// Upload response
#[derive(Serialize)]
struct UploadResponse {
    sha256: String,
    size: u64,
    #[serde(rename = "type")]
    content_type: String,
    uploaded: u64,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    thumbnail_url: Option<String>,
    /// Video dimensions as "WIDTHxHEIGHT" (display dimensions after rotation)
    #[serde(skip_serializing_if = "Option::is_none")]
    dim: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transcode_error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transcode_error_message: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    transcode_terminal: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    transcript_error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transcript_error_message: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    transcript_terminal: bool,
}

// Migration request
#[derive(Deserialize)]
struct MigrateRequest {
    source_url: String,
    expected_hash: Option<String>,
    owner: Option<String>, // Owner pubkey for GCS metadata durability
}

// Migration response
#[derive(Serialize)]
struct MigrateResponse {
    sha256: String,
    size: u64,
    #[serde(rename = "type")]
    content_type: String,
    migrated: bool,
    source_url: String,
}

// Error response
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DerivativeFailureSignal {
    error_code: String,
    error_message: String,
    terminal: bool,
}

const BLOSSOM_AUTH_KIND: u32 = 24242;

fn is_false(value: &bool) -> bool {
    !*value
}

#[tokio::main]
async fn main() -> Result<()> {
    let _sentry_guard = init_sentry("divine-upload");

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("blossom_upload=info".parse()?),
        )
        .init();

    let config = Config::from_env();
    let port = config.port;

    // Initialize GCS client
    let gcs_config = ClientConfig::default().with_auth().await?;
    let gcs_client = GcsClient::new(gcs_config);

    let state = Arc::new(AppState { gcs_client, config });

    // CORS configuration
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([
            Method::GET,
            Method::HEAD,
            Method::PUT,
            Method::POST,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::CONTENT_RANGE,
        ])
        .expose_headers([
            HeaderName::from_static("upload-offset"),
            HeaderName::from_static("upload-length"),
            HeaderName::from_static("upload-expires"),
            HeaderName::from_static("x-divine-chunk-size"),
        ])
        .max_age(std::time::Duration::from_secs(86400));

    // Build router
    let app = Router::new()
        .route("/upload", put(handle_upload))
        .route("/upload", options(handle_cors_preflight))
        .route("/upload/init", post(handle_resumable_init))
        .route("/upload/init", options(handle_cors_preflight))
        .route(
            "/upload/:upload_id/complete",
            post(handle_resumable_complete),
        )
        .route(
            "/upload/:upload_id/complete",
            options(handle_cors_preflight),
        )
        .route("/upload/:upload_id", delete(handle_resumable_abort))
        .route("/upload/:upload_id", options(handle_cors_preflight))
        .route("/sessions/:upload_id", put(handle_session_chunk))
        .route("/sessions/:upload_id", head(handle_session_head))
        .route("/sessions/:upload_id", options(handle_cors_preflight))
        .route("/migrate", post(handle_migrate))
        .route("/migrate", options(handle_cors_preflight))
        .route("/audit", post(handle_audit_log))
        .route("/thumbnail/:hash", get(handle_thumbnail_generate))
        .route("/thumbnail/:hash", options(handle_cors_preflight))
        .route("/", put(handle_upload))
        .route("/", options(handle_cors_preflight))
        .layer(cors)
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    info!("Starting HTTP/2 server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    // Use hyper's auto builder which supports both HTTP/1 and HTTP/2
    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let app = app.clone();

        tokio::spawn(async move {
            let builder = Builder::new(hyper_util::rt::TokioExecutor::new());
            if let Err(e) = builder
                .serve_connection(
                    io,
                    hyper::service::service_fn(move |req| {
                        let mut app = app.clone();
                        async move { app.call(req).await }
                    }),
                )
                .await
            {
                error!("Connection error: {}", e);
            }
        });
    }
}

async fn handle_cors_preflight() -> impl IntoResponse {
    StatusCode::NO_CONTENT
}

fn auth_error_response(error: anyhow::Error) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse {
            error: error.to_string(),
        }),
    )
        .into_response()
}

fn resumable_error_response(error: resumable::ResumableError) -> Response {
    (
        error.status_code(),
        Json(ErrorResponse {
            error: error.to_string(),
        }),
    )
        .into_response()
}

async fn collect_body_bytes(body: Body) -> Result<Bytes> {
    let mut stream = body.into_data_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        bytes.extend_from_slice(&chunk.map_err(|error| anyhow!("Stream error: {}", error))?);
    }
    Ok(Bytes::from(bytes))
}

fn header_value(value: u64) -> HeaderValue {
    HeaderValue::from_str(&value.to_string()).expect("numeric header values must be valid")
}

/// POST /audit - Receive audit log entries from Fastly edge and write as structured logs.
/// Cloud Run structured logging: JSON on stdout is auto-ingested by Cloud Logging.
/// This gives us: queryable logs, retention policies, export to BigQuery, alerting.
async fn handle_audit_log(body: axum::body::Bytes) -> impl IntoResponse {
    // Parse and re-emit as structured log with severity
    match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(mut entry) => {
            // Add Cloud Logging severity field for proper log level
            entry["severity"] = serde_json::json!("NOTICE");
            entry["logging.googleapis.com/labels"] = serde_json::json!({
                "service": "divine-blossom",
                "component": "audit"
            });
            // Print as JSON to stdout — Cloud Run auto-ingests this into Cloud Logging
            println!("{}", entry);
            StatusCode::OK
        }
        Err(e) => {
            error!("Invalid audit log entry: {}", e);
            StatusCode::BAD_REQUEST
        }
    }
}

async fn handle_upload(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    body: Body,
) -> Response {
    match process_upload(state, headers, body).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => {
            error!("Upload error: {}", e);
            let status = if e.to_string().contains("auth") || e.to_string().contains("Auth") {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (
                status,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
    }
}

fn resumable_manager(
    state: &AppState,
) -> resumable::ResumableManager<resumable::GcsResumableBackend, resumable::GcsSessionStore> {
    resumable::ResumableManager::new(
        resumable::GcsResumableBackend::new(
            state.gcs_client.clone(),
            state.config.gcs_bucket.clone(),
        ),
        resumable::GcsSessionStore::new(state.gcs_client.clone(), state.config.gcs_bucket.clone()),
        state.config.upload_base_url.clone(),
        state.config.resumable_chunk_size,
        state.config.resumable_session_ttl_secs,
    )
}

async fn handle_resumable_init(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(request): Json<resumable::ResumableUploadInitRequest>,
) -> Response {
    let auth_event = match validate_auth(&headers, "upload") {
        Ok(event) => event,
        Err(error) => return auth_error_response(error),
    };

    if let Some(expected_hash) = get_tag_value(&auth_event.tags, "x") {
        if expected_hash.to_lowercase() != request.sha256.to_lowercase() {
            return resumable_error_response(resumable::ResumableError::BadRequest(
                "Declared sha256 does not match Blossom auth hash tag".to_string(),
            ));
        }
    }

    let manager = resumable_manager(state.as_ref());
    match manager.init_session(&auth_event.pubkey, request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => resumable_error_response(error),
    }
}

async fn handle_session_head(
    State(state): State<Arc<AppState>>,
    Path(upload_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let manager = resumable_manager(state.as_ref());
    match manager
        .head_session(
            &upload_id,
            headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
        )
        .await
    {
        Ok(status) => {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::NO_CONTENT;
            response.headers_mut().insert(
                resumable::SESSION_OFFSET_HEADER,
                header_value(status.next_offset),
            );
            response.headers_mut().insert(
                resumable::SESSION_LENGTH_HEADER,
                header_value(status.declared_size),
            );
            response.headers_mut().insert(
                resumable::SESSION_EXPIRES_HEADER,
                HeaderValue::from_str(&status.expires_at)
                    .expect("session expiry header must be valid ASCII"),
            );
            response.headers_mut().insert(
                resumable::SESSION_CHUNK_SIZE_HEADER,
                header_value(status.chunk_size),
            );
            response
        }
        Err(error) => resumable_error_response(error),
    }
}

async fn handle_session_chunk(
    State(state): State<Arc<AppState>>,
    Path(upload_id): Path<String>,
    headers: axum::http::HeaderMap,
    body: Body,
) -> Response {
    let content_range = match headers
        .get(header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
    {
        Some(value) => value.to_string(),
        None => {
            return resumable_error_response(resumable::ResumableError::BadRequest(
                "Content-Range header required".to_string(),
            ))
        }
    };

    let chunk = match collect_body_bytes(body).await {
        Ok(bytes) => bytes,
        Err(error) => {
            return resumable_error_response(resumable::ResumableError::BadRequest(format!(
                "Failed to read request body: {}",
                error
            )))
        }
    };

    let manager = resumable_manager(state.as_ref());
    match manager
        .upload_chunk(
            &upload_id,
            headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            &content_range,
            chunk,
        )
        .await
    {
        Ok(status) => {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::NO_CONTENT;
            response.headers_mut().insert(
                resumable::SESSION_OFFSET_HEADER,
                header_value(status.next_offset),
            );
            response.headers_mut().insert(
                resumable::SESSION_LENGTH_HEADER,
                header_value(status.declared_size),
            );
            response.headers_mut().insert(
                resumable::SESSION_EXPIRES_HEADER,
                HeaderValue::from_str(&status.expires_at)
                    .expect("session expiry header must be valid ASCII"),
            );
            response.headers_mut().insert(
                resumable::SESSION_CHUNK_SIZE_HEADER,
                header_value(status.chunk_size),
            );
            response
        }
        Err(error) => resumable_error_response(error),
    }
}

async fn handle_resumable_complete(
    State(state): State<Arc<AppState>>,
    Path(upload_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let auth_event = match validate_auth(&headers, "upload") {
        Ok(event) => event,
        Err(error) => return auth_error_response(error),
    };

    let manager = resumable_manager(state.as_ref());
    match manager
        .complete_session(&upload_id, &auth_event.pubkey)
        .await
    {
        Ok(response) => {
            maybe_trigger_derivatives(
                state.config.transcoder_url.as_deref(),
                state.config.transcriber_url.as_deref(),
                &response,
                &auth_event.pubkey,
            )
            .await;

            (StatusCode::OK, Json(response)).into_response()
        }
        Err(error) => resumable_error_response(error),
    }
}

async fn handle_resumable_abort(
    State(state): State<Arc<AppState>>,
    Path(upload_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let manager = resumable_manager(state.as_ref());
    match manager
        .abort_session(
            &upload_id,
            headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => resumable_error_response(error),
    }
}

async fn process_upload(
    state: Arc<AppState>,
    headers: axum::http::HeaderMap,
    body: Body,
) -> Result<UploadResponse> {
    // Validate auth
    let auth_event = validate_auth(&headers, "upload")?;

    // Get content type
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    // Stream body while hashing (with owner metadata for durability)
    let (sha256_hash, size, all_bytes, sanitize_error) = stream_to_gcs_with_hash(
        &state.gcs_client,
        &state.config.gcs_bucket,
        &content_type,
        body,
        &auth_event.pubkey,
    )
    .await?;

    let mut thumbnail_error: Option<String> = None;
    // Extract thumbnail for videos (non-blocking - failures don't fail the upload)
    let thumbnail_url = if thumbnail::is_video_type(&content_type) {
        match extract_and_upload_thumbnail(
            &state.gcs_client,
            &state.config.gcs_bucket,
            &state.config.cdn_base_url,
            &sha256_hash,
            &all_bytes,
        )
        .await
        {
            Ok(url) => {
                info!("Generated thumbnail for {}", sha256_hash);
                Some(url)
            }
            Err(e) => {
                error!("Thumbnail extraction failed for {}: {}", sha256_hash, e);
                thumbnail_error = Some(e.to_string());
                None
            }
        }
    } else {
        None
    };

    let mut probe_error: Option<String> = None;
    // Probe video dimensions (non-blocking - failures don't fail the upload)
    let dim = if thumbnail::is_video_type(&content_type) {
        match probe_video_dimensions(&all_bytes).await {
            Ok(d) => {
                info!("Probed video dimensions for {}: {}", sha256_hash, d);
                Some(d)
            }
            Err(e) => {
                error!("Video probe failed for {}: {}", sha256_hash, e);
                probe_error = Some(e.to_string());
                None
            }
        }
    } else {
        None
    };

    let derivative_failure = classify_invalid_media_signal(
        &content_type,
        sanitize_error.as_deref(),
        thumbnail_error.as_deref(),
        probe_error.as_deref(),
    );

    if let Some(signal) = derivative_failure.as_ref() {
        report_derivative_failure_to_sentry(
            "divine-upload",
            "derivative-validation",
            &sha256_hash,
            &signal.error_code,
            &signal.error_message,
            signal.terminal,
            Some(&content_type),
            Some(&auth_event.pubkey),
        );
    }

    // Trigger HLS transcoding for videos (fire-and-forget)
    if thumbnail::is_video_type(&content_type) && derivative_failure.is_none() {
        if let Some(ref transcoder_url) = state.config.transcoder_url {
            // Spawn background task to trigger transcoder - don't block upload response
            let transcoder_url = transcoder_url.clone();
            let hash = sha256_hash.clone();
            let owner = auth_event.pubkey.clone();
            tokio::spawn(async move {
                if let Err(e) = trigger_transcoding(&transcoder_url, &hash, &owner).await {
                    error!("Failed to trigger transcoding for {}: {}", hash, e);
                }
            });
        } else {
            info!(
                "TRANSCODER_URL not configured, skipping HLS transcoding for {}",
                sha256_hash
            );
        }
    } else if let Some(signal) = derivative_failure.as_ref() {
        warn!(
            "Skipping HLS transcoding for {} due to terminal derivative validation failure {}",
            sha256_hash, signal.error_code
        );
    }

    // Trigger transcript generation for transcribable media (audio/video)
    if is_transcribable_type(&content_type) && derivative_failure.is_none() {
        if let Some(ref transcriber_url) = state.config.transcriber_url {
            let transcriber_url = transcriber_url.clone();
            let hash = sha256_hash.clone();
            let owner = auth_event.pubkey.clone();
            tokio::spawn(async move {
                if let Err(e) = trigger_transcription(&transcriber_url, &hash, &owner).await {
                    error!("Failed to trigger transcription for {}: {}", hash, e);
                }
            });
        } else {
            info!(
                "TRANSCRIBER_URL not configured, skipping transcript generation for {}",
                sha256_hash
            );
        }
    } else if let Some(signal) = derivative_failure.as_ref() {
        warn!(
            "Skipping transcript generation for {} due to terminal derivative validation failure {}",
            sha256_hash, signal.error_code
        );
    }

    // Build response
    let extension = get_extension(&content_type);
    let uploaded = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let transcode_error_code = derivative_failure
        .as_ref()
        .map(|signal| signal.error_code.clone());
    let transcode_error_message = derivative_failure
        .as_ref()
        .map(|signal| signal.error_message.clone());
    let transcode_terminal = derivative_failure
        .as_ref()
        .map(|signal| signal.terminal)
        .unwrap_or(false);

    let transcript_error_code = derivative_failure
        .as_ref()
        .map(|signal| signal.error_code.clone());
    let transcript_error_message = derivative_failure
        .as_ref()
        .map(|signal| signal.error_message.clone());
    let transcript_terminal = derivative_failure
        .as_ref()
        .map(|signal| signal.terminal)
        .unwrap_or(false);

    Ok(UploadResponse {
        sha256: sha256_hash.clone(),
        size,
        content_type,
        uploaded,
        url: format!(
            "{}/{}.{}",
            state.config.cdn_base_url, sha256_hash, extension
        ),
        thumbnail_url,
        dim,
        transcode_error_code,
        transcode_error_message,
        transcode_terminal,
        transcript_error_code,
        transcript_error_message,
        transcript_terminal,
    })
}

async fn stream_to_gcs_with_hash(
    client: &GcsClient,
    bucket: &str,
    content_type: &str,
    body: Body,
    owner: &str,
) -> Result<(String, u64, Vec<u8>, Option<String>)> {
    let mut original_bytes = Vec::new();

    // Collect body stream first; original bytes remain the source of truth for hashing/storage.
    let mut stream = body.into_data_stream();
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| anyhow!("Stream error: {}", e))?;
        original_bytes.extend_from_slice(&chunk);
    }

    // Keep original bytes immutable for hash/storage integrity.
    // Derivative generation (thumbnail/probe/transcode) can use sanitized bytes.
    let mut derivative_bytes = original_bytes.clone();
    let mut sanitize_error = None;

    // Sanitize video bytes for derivative processing only.
    if thumbnail::is_video_type(content_type) {
        match sanitize_video(&derivative_bytes).await {
            Ok(sanitized) => {
                info!(
                    "Prepared sanitized derivative bytes: {} -> {} bytes",
                    derivative_bytes.len(),
                    sanitized.len(),
                );
                derivative_bytes = sanitized;
            }
            Err(e) => {
                // Non-fatal: user-caused (corrupt upload, missing moov atom, etc.)
                // Keep original bytes for derivative processing if sanitization fails
                warn!(
                    "Video sanitization failed for derivatives, using original: {}",
                    e
                );
                sanitize_error = Some(e.to_string());
            }
        }
    }

    // Hash and store the original uploaded bytes.
    let mut hasher = Sha256::new();
    hasher.update(&original_bytes);
    let total_size = original_bytes.len() as u64;
    let sha256_hash = hex::encode(hasher.finalize());

    // Check if blob already exists
    let exists = client
        .get_object(
            &google_cloud_storage::http::objects::get::GetObjectRequest {
                bucket: bucket.to_string(),
                object: sha256_hash.clone(),
                ..Default::default()
            },
        )
        .await
        .is_ok();

    if exists {
        info!("Blob {} already exists, skipping upload", sha256_hash);
        return Ok((sha256_hash, total_size, derivative_bytes, sanitize_error));
    }

    // Upload to GCS
    let upload_type = UploadType::Simple(Media::new(sha256_hash.clone()));
    let req = UploadObjectRequest {
        bucket: bucket.to_string(),
        ..Default::default()
    };

    client
        .upload_object(&req, Bytes::from(original_bytes.clone()), &upload_type)
        .await
        .map_err(|e| anyhow!("GCS upload failed: {}", e))?;

    // Set content type and owner metadata for durability
    let mut metadata_map = std::collections::HashMap::new();
    metadata_map.insert("owner".to_string(), owner.to_string());

    let update_req = google_cloud_storage::http::objects::patch::PatchObjectRequest {
        bucket: bucket.to_string(),
        object: sha256_hash.clone(),
        metadata: Some(Object {
            content_type: Some(content_type.to_string()),
            metadata: Some(metadata_map),
            ..Default::default()
        }),
        ..Default::default()
    };
    let _ = client.patch_object(&update_req).await;

    info!(
        "Uploaded {} bytes as {} (owner: {})",
        total_size, sha256_hash, owner
    );
    Ok((sha256_hash, total_size, derivative_bytes, sanitize_error))
}

/// Extract thumbnail from video and upload to GCS
/// Returns the thumbnail URL on success
async fn extract_and_upload_thumbnail(
    client: &GcsClient,
    bucket: &str,
    cdn_base_url: &str,
    hash: &str,
    video_data: &[u8],
) -> Result<String> {
    // Extract thumbnail using ffmpeg
    let thumb_result = thumbnail::extract_thumbnail(video_data)?;

    // Upload thumbnail to GCS with path: {hash}.jpg (same as video hash but with .jpg extension)
    // This allows serving via CDN at media.divine.video/{hash}.jpg
    let thumb_path = format!("{}.jpg", hash);

    let mut media = Media::new(thumb_path.clone());
    media.content_type = "image/jpeg".into();
    let upload_type = UploadType::Simple(media);
    let req = UploadObjectRequest {
        bucket: bucket.to_string(),
        ..Default::default()
    };

    client
        .upload_object(&req, Bytes::from(thumb_result.data), &upload_type)
        .await
        .map_err(|e| anyhow!("GCS thumbnail upload failed: {}", e))?;

    // Return CDN URL for thumbnail - stored at {hash}.jpg, served via CDN
    Ok(format!("{}/{}.jpg", cdn_base_url, hash))
}

fn media_source_candidates(hash: &str) -> [String; 3] {
    [
        hash.to_string(),
        format!("{}/hls/stream_720p.ts", hash),
        format!("{}/hls/stream_480p.ts", hash),
    ]
}

async fn download_best_available_media_bytes(
    client: &GcsClient,
    bucket: &str,
    hash: &str,
) -> Result<(Vec<u8>, String)> {
    let mut failures = Vec::new();

    for object in media_source_candidates(hash) {
        match client
            .download_object(
                &GetObjectRequest {
                    bucket: bucket.to_string(),
                    object: object.clone(),
                    ..Default::default()
                },
                &DownloadRange::default(),
            )
            .await
        {
            Ok(data) => {
                if object == hash {
                    return Ok((data, object));
                }

                warn!(
                    "Original blob missing for {}, using fallback media source {} for thumbnail generation",
                    hash, object
                );
                return Ok((data, object));
            }
            Err(e) => failures.push(format!("{}: {}", object, e)),
        }
    }

    Err(anyhow!(
        "No recoverable media source found for {} ({})",
        hash,
        failures.join(" | ")
    ))
}

/// On-demand thumbnail generation endpoint
/// Downloads video from GCS, generates thumbnail, stores it, returns the image
async fn handle_thumbnail_generate(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    // Validate hash format (64 hex characters)
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "application/json")],
            Json(ErrorResponse {
                error: "Invalid hash format".to_string(),
            })
            .into_response(),
        )
            .into_response();
    }

    let hash = hash.to_lowercase();

    // First check if thumbnail already exists
    let thumb_path = format!("{}.jpg", hash);
    let thumb_exists = state
        .gcs_client
        .get_object(&GetObjectRequest {
            bucket: state.config.gcs_bucket.clone(),
            object: thumb_path.clone(),
            ..Default::default()
        })
        .await
        .is_ok();

    if thumb_exists {
        // Thumbnail already exists, download and return it
        match state
            .gcs_client
            .download_object(
                &GetObjectRequest {
                    bucket: state.config.gcs_bucket.clone(),
                    object: thumb_path,
                    ..Default::default()
                },
                &DownloadRange::default(),
            )
            .await
        {
            Ok(data) => {
                return (StatusCode::OK, [(header::CONTENT_TYPE, "image/jpeg")], data)
                    .into_response();
            }
            Err(e) => {
                error!("Failed to download existing thumbnail: {}", e);
            }
        }
    }

    // Download the original blob, or fall back to the best available HLS transport stream.
    let (video_data, source_object) = match download_best_available_media_bytes(
        &state.gcs_client,
        &state.config.gcs_bucket,
        &hash,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to download video {}: {}", hash, e);
            return (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "application/json")],
                Json(ErrorResponse {
                    error: "Video not found".to_string(),
                })
                .into_response(),
            )
                .into_response();
        }
    };

    if source_object != hash {
        warn!(
            "Generating thumbnail for {} from fallback source {}",
            hash, source_object
        );
    }

    // Generate thumbnail
    let thumb_result = match thumbnail::extract_thumbnail(&video_data) {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to generate thumbnail for {}: {}", hash, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "application/json")],
                Json(ErrorResponse {
                    error: "Failed to generate thumbnail".to_string(),
                })
                .into_response(),
            )
                .into_response();
        }
    };

    // Upload thumbnail to GCS
    let thumb_path = format!("{}.jpg", hash);
    let mut media = Media::new(thumb_path.clone());
    media.content_type = "image/jpeg".into();
    let upload_type = UploadType::Simple(media);
    let req = UploadObjectRequest {
        bucket: state.config.gcs_bucket.clone(),
        ..Default::default()
    };

    if let Err(e) = state
        .gcs_client
        .upload_object(&req, Bytes::from(thumb_result.data.clone()), &upload_type)
        .await
    {
        error!("Failed to upload thumbnail for {}: {}", hash, e);
        // Still return the thumbnail even if upload failed
    }

    info!("Generated on-demand thumbnail for {}", hash);

    // Return the thumbnail image
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "image/jpeg")],
        thumb_result.data,
    )
        .into_response()
}

fn new_temp_media_path(suffix: &str) -> Result<tempfile::TempPath> {
    NamedTempFile::with_suffix(suffix)
        .map(|file| file.into_temp_path())
        .map_err(|e| anyhow!("Failed to create temp file {}: {}", suffix, e))
}

/// Sanitize a video file by remuxing with ffmpeg
/// This strips invalid MP4 atoms (e.g. malformed clap boxes from iPhone),
/// ensures faststart (moov before mdat), and produces a web-compatible MP4.
/// Uses -c copy so it's lossless and fast (no re-encoding).
async fn sanitize_video(input_bytes: &[u8]) -> Result<Vec<u8>> {
    use tokio::process::Command;

    let input_path = new_temp_media_path(".mp4")?;
    let output_path = new_temp_media_path(".mp4")?;

    // Write input to temp file
    tokio::fs::write(&input_path, input_bytes)
        .await
        .map_err(|e| anyhow!("Failed to write temp input: {}", e))?;

    // Remux with ffmpeg: -c copy (no re-encode), +faststart (moov at front)
    let output = Command::new("ffmpeg")
        .args([
            "-y", // Overwrite output
            "-v",
            "warning", // Only show warnings/errors
            "-i",
            input_path.to_str().unwrap(),
            "-c",
            "copy", // Copy streams without re-encoding
            "-movflags",
            "+faststart", // Put moov atom at front
            output_path.to_str().unwrap(),
        ])
        .output()
        .await
        .map_err(|e| anyhow!("Failed to run ffmpeg: {}", e))?;

    // Clean up input
    let _ = input_path.close();

    if !output.status.success() {
        let _ = output_path.close();
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("ffmpeg sanitize failed: {}", stderr));
    }

    // Read sanitized output
    let sanitized = tokio::fs::read(&output_path)
        .await
        .map_err(|e| anyhow!("Failed to read sanitized output: {}", e))?;

    // Clean up output
    let _ = output_path.close();

    Ok(sanitized)
}

/// Probe video data with ffprobe to get display dimensions (respecting rotation metadata).
/// Returns "WIDTHxHEIGHT" string suitable for the Nostr `dim` imeta tag.
async fn probe_video_dimensions(video_bytes: &[u8]) -> Result<String> {
    use tokio::process::Command;

    let probe_path = new_temp_media_path(".mp4")?;

    // Write to temp file for ffprobe
    tokio::fs::write(&probe_path, video_bytes)
        .await
        .map_err(|e| anyhow!("Failed to write temp file for probe: {}", e))?;

    let output = Command::new("ffprobe")
        .args([
            "-v",
            "quiet",
            "-print_format",
            "json",
            "-show_streams",
            "-select_streams",
            "v:0",
            probe_path.to_str().unwrap(),
        ])
        .output()
        .await
        .map_err(|e| anyhow!("Failed to run ffprobe: {}", e))?;

    // Clean up temp file
    let _ = probe_path.close();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("ffprobe failed: {}", stderr));
    }

    let json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| anyhow!("Failed to parse ffprobe output: {}", e))?;

    let stream = json["streams"]
        .as_array()
        .and_then(|s| s.first())
        .ok_or_else(|| anyhow!("No video stream found"))?;

    let width = stream["width"].as_u64().unwrap_or(0) as u32;
    let height = stream["height"].as_u64().unwrap_or(0) as u32;

    if width == 0 || height == 0 {
        return Err(anyhow!("Could not determine video dimensions"));
    }

    // Check rotation from tags (older FFmpeg / older files)
    let mut rotation: i32 = stream["tags"]["rotate"]
        .as_str()
        .and_then(|r| r.parse().ok())
        .unwrap_or(0);

    // Check side_data_list for Display Matrix rotation (newer FFmpeg)
    if rotation == 0 {
        if let Some(side_data) = stream["side_data_list"].as_array() {
            for sd in side_data {
                if sd["side_data_type"].as_str() == Some("Display Matrix") {
                    if let Some(r) = sd["rotation"].as_f64() {
                        rotation = r.round() as i32;
                    } else if let Some(r) =
                        sd["rotation"].as_str().and_then(|s| s.parse::<f64>().ok())
                    {
                        rotation = r.round() as i32;
                    }
                }
            }
        }
    }

    let rotation_abs = rotation.unsigned_abs() % 360;

    // Compute display dimensions (after applying rotation)
    let (display_width, display_height) = if rotation_abs == 90 || rotation_abs == 270 {
        (height, width)
    } else {
        (width, height)
    };

    Ok(format!("{}x{}", display_width, display_height))
}

#[cfg(test)]
mod tests {
    use super::{classify_invalid_media_signal, media_source_candidates, new_temp_media_path};

    #[test]
    fn temp_media_paths_are_unique_per_request() {
        let first = new_temp_media_path(".mp4").expect("first temp path");
        let second = new_temp_media_path(".mp4").expect("second temp path");
        let first_path = first.to_string_lossy().to_string();
        let second_path = second.to_string_lossy().to_string();

        assert_ne!(first_path, second_path);
        assert!(first_path.ends_with(".mp4"));
        assert!(second_path.ends_with(".mp4"));
    }

    #[test]
    fn media_source_candidates_prefer_original_then_hls_variants() {
        let hash = "5b48aa1fcf30af61243ac9307eb98b7fa22df1c58573c3ca5d1b14fc30099929";
        let candidates = media_source_candidates(hash);

        assert_eq!(candidates[0], hash);
        assert_eq!(candidates[1], format!("{}/hls/stream_720p.ts", hash));
        assert_eq!(candidates[2], format!("{}/hls/stream_480p.ts", hash));
    }

    #[test]
    fn invalid_media_classification_marks_sanitize_failure_terminal() {
        let signal = classify_invalid_media_signal(
            "video/mp4",
            Some("ffmpeg sanitize failed: moov atom not found"),
            None,
            None,
        )
        .expect("sanitize failure should mark invalid media");

        assert_eq!(signal.error_code, "invalid_media");
        assert!(signal.terminal);
        assert!(signal.error_message.contains("moov atom not found"));
    }

    #[test]
    fn invalid_media_classification_marks_probe_failure_terminal() {
        let signal = classify_invalid_media_signal(
            "video/mp4",
            None,
            None,
            Some("ffprobe failed: Invalid data found when processing input"),
        )
        .expect("probe failure should mark invalid media");

        assert_eq!(signal.error_code, "invalid_media");
        assert!(signal.terminal);
        assert!(signal
            .error_message
            .contains("Invalid data found when processing input"));
    }

    #[test]
    fn invalid_media_classification_ignores_thumbnail_only_failures() {
        let signal = classify_invalid_media_signal(
            "video/mp4",
            None,
            Some("thumbnail extraction failed"),
            None,
        );

        assert!(signal.is_none());
    }
}

/// Regression tests for `maybe_trigger_derivatives`.
///
/// These tests guard against the regression reported in PR #59, where
/// `handle_resumable_complete` did not call `trigger_transcoding` or
/// `trigger_transcription` after a successful session completion.  Any future
/// refactor that removes or misconditions those calls will cause at least one
/// of these tests to fail.
///
/// Each test spins up a `wiremock` mock HTTP server in-process, points
/// `maybe_trigger_derivatives` at it, and asserts on which mock endpoints were
/// (or were not) reached.  The spawned tasks are fire-and-forget, so we give
/// them a short yield before asserting received requests.
#[cfg(test)]
mod derivative_trigger_tests {
    use super::{maybe_trigger_derivatives, resumable::CompleteUploadResponse};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Build a minimal `CompleteUploadResponse` for the given content type.
    fn fake_response(content_type: &str) -> CompleteUploadResponse {
        CompleteUploadResponse {
            sha256: "abc123".to_string(),
            size: 1024,
            content_type: content_type.to_string(),
            thumbnail_url: None,
            dim: None,
        }
    }

    /// Wait long enough for fire-and-forget spawned tasks to complete their
    /// HTTP round-trip against the in-process wiremock server. Tests run on a
    /// multi_thread runtime so the spawned tasks can make real localhost
    /// requests concurrently with this sleep. 200ms is ample for a loopback
    /// POST to a mock server; tune upward only if you see CI flakes.
    async fn drain_spawned_tasks() {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    /// video/mp4 → transcoder /transcode should be called.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawns_transcoder_for_video() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/transcode"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        // Transcriber also responds (video is transcribable too).
        Mock::given(method("POST"))
            .and(path("/transcribe"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let response = fake_response("video/mp4");
        maybe_trigger_derivatives(
            Some(&server.uri()),
            Some(&server.uri()),
            &response,
            "pubkey_abc",
        )
        .await;

        drain_spawned_tasks().await;

        // wiremock verifies the `expect(1)` on drop.
        server.verify().await;
    }

    /// audio/mpeg → transcriber /transcribe should be called; transcoder should NOT.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawns_transcriber_for_audio_not_transcoder() {
        let server = MockServer::start().await;

        // /transcode must NOT be called for audio.
        Mock::given(method("POST"))
            .and(path("/transcode"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/transcribe"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let response = fake_response("audio/mpeg");
        maybe_trigger_derivatives(
            Some(&server.uri()),
            Some(&server.uri()),
            &response,
            "pubkey_abc",
        )
        .await;

        drain_spawned_tasks().await;

        server.verify().await;
    }

    /// image/jpeg → neither transcoder nor transcriber should be called.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn noop_for_image() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/transcode"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/transcribe"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let response = fake_response("image/jpeg");
        maybe_trigger_derivatives(
            Some(&server.uri()),
            Some(&server.uri()),
            &response,
            "pubkey_abc",
        )
        .await;

        drain_spawned_tasks().await;

        server.verify().await;
    }

    /// video/mp4 with TRANSCODER_URL=None → no HTTP calls, no panic.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn skips_when_transcoder_url_missing() {
        let server = MockServer::start().await;

        // Nothing should be called on the transcoder endpoint.
        Mock::given(method("POST"))
            .and(path("/transcode"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        // Transcription may still be called when a transcriber_url is provided.
        Mock::given(method("POST"))
            .and(path("/transcribe"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let response = fake_response("video/mp4");
        // transcoder_url = None, transcriber_url = Some
        maybe_trigger_derivatives(None, Some(&server.uri()), &response, "pubkey_abc").await;

        drain_spawned_tasks().await;

        server.verify().await;
    }

    /// video/mp4, transcoder returns HTTP 500 → spawn completes without propagating the error
    /// (fire-and-forget contract is preserved; the handler still returns 200 to the client).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handles_transcoder_errors_gracefully() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/transcode"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/transcribe"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&server)
            .await;

        let response = fake_response("video/mp4");
        // This must not panic even though the transcoder returns 500.
        maybe_trigger_derivatives(
            Some(&server.uri()),
            Some(&server.uri()),
            &response,
            "pubkey_abc",
        )
        .await;

        drain_spawned_tasks().await;

        // The requests were sent (transcoder was hit), just with an error response.
        server.verify().await;
    }
}

fn validate_auth(headers: &axum::http::HeaderMap, required_action: &str) -> Result<NostrEvent> {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| anyhow!("Authorization header required"))?
        .to_str()
        .map_err(|_| anyhow!("Invalid authorization header"))?;

    if !auth_header.starts_with("Nostr ") {
        return Err(anyhow!("Authorization must start with 'Nostr '"));
    }

    // Decode base64 event
    let event_json = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &auth_header[6..],
    )
    .map_err(|e| anyhow!("Invalid base64: {}", e))?;

    let event: NostrEvent =
        serde_json::from_slice(&event_json).map_err(|e| anyhow!("Invalid event JSON: {}", e))?;

    validate_event(&event, required_action)?;

    Ok(event)
}

fn validate_event(event: &NostrEvent, required_action: &str) -> Result<()> {
    // Check kind
    if event.kind != BLOSSOM_AUTH_KIND {
        return Err(anyhow!(
            "Invalid event kind: expected {}",
            BLOSSOM_AUTH_KIND
        ));
    }

    // Check action tag
    let action = get_tag_value(&event.tags, "t");
    if action.as_deref() != Some(required_action) {
        return Err(anyhow!(
            "Action mismatch: expected {}, got {:?}",
            required_action,
            action
        ));
    }

    // Check expiration
    if let Some(expiration) = get_tag_value(&event.tags, "expiration") {
        let exp: i64 = expiration.parse().unwrap_or(0);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        if now > exp {
            return Err(anyhow!("Authorization expired"));
        }
    }

    // Verify event ID
    let computed_id = compute_event_id(event)?;
    if computed_id != event.id {
        return Err(anyhow!("Invalid event ID"));
    }

    // Verify signature
    verify_signature(event)?;

    Ok(())
}

fn get_tag_value(tags: &[Vec<String>], tag_name: &str) -> Option<String> {
    tags.iter()
        .find(|tag| tag.len() >= 2 && tag[0] == tag_name)
        .map(|tag| tag[1].clone())
}

fn compute_event_id(event: &NostrEvent) -> Result<String> {
    let serialized = serde_json::to_string(&(
        0,
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    ))
    .map_err(|e| anyhow!("Serialization error: {}", e))?;

    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn verify_signature(event: &NostrEvent) -> Result<()> {
    let pubkey_bytes = hex::decode(&event.pubkey).map_err(|_| anyhow!("Invalid pubkey hex"))?;
    let sig_bytes = hex::decode(&event.sig).map_err(|_| anyhow!("Invalid signature hex"))?;
    let msg_bytes = hex::decode(&event.id).map_err(|_| anyhow!("Invalid event ID hex"))?;

    // Convert Vec<u8> to [u8; 32] for pubkey
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| anyhow!("Invalid pubkey length"))?;

    let verifying_key =
        VerifyingKey::from_bytes(&pubkey_array).map_err(|e| anyhow!("Invalid pubkey: {}", e))?;

    let signature = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| anyhow!("Invalid signature: {}", e))?;

    // Use verify_prehash since the event ID is already a SHA-256 hash
    verifying_key
        .verify_prehash(&msg_bytes, &signature)
        .map_err(|_| anyhow!("Invalid signature"))?;

    Ok(())
}

fn get_extension(content_type: &str) -> &'static str {
    match content_type {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "video/mp4" => "mp4",
        "video/webm" => "webm",
        "video/quicktime" => "mov",
        "audio/mpeg" => "mp3",
        "audio/ogg" => "ogg",
        "application/pdf" => "pdf",
        _ => "bin",
    }
}

fn is_transcribable_type(content_type: &str) -> bool {
    content_type.starts_with("video/") || content_type.starts_with("audio/")
}

/// Spawn derivative-generation tasks (transcoding + transcription) for a newly completed upload.
///
/// This is the authoritative branching point: video → transcode + transcribe, audio → transcribe
/// only, image → neither. Extracted from `handle_resumable_complete` so it can be unit-tested in
/// isolation. See PR #59 for the regression where resumable uploads skipped these triggers.
async fn maybe_trigger_derivatives(
    transcoder_url: Option<&str>,
    transcriber_url: Option<&str>,
    response: &resumable::CompleteUploadResponse,
    pubkey: &str,
) {
    // Trigger HLS transcoding for videos (fire-and-forget).
    // Without this, resumable uploads never reach the transcoder and
    // /{hash}/720p.mp4 stays in "Processing" forever. See the
    // 2026-04-05 720p-mp4-stuck investigation.
    if thumbnail::is_video_type(&response.content_type) {
        if let Some(url) = transcoder_url {
            let transcoder_url = url.to_owned();
            let hash = response.sha256.clone();
            let owner = pubkey.to_owned();
            tokio::spawn(async move {
                if let Err(e) = trigger_transcoding(&transcoder_url, &hash, &owner).await {
                    error!("Failed to trigger transcoding for {}: {}", hash, e);
                }
            });
        } else {
            info!(
                "TRANSCODER_URL not configured, skipping HLS transcoding for {}",
                response.sha256
            );
        }
    }

    // Trigger transcript generation for transcribable media (audio/video).
    if is_transcribable_type(&response.content_type) {
        if let Some(url) = transcriber_url {
            let transcriber_url = url.to_owned();
            let hash = response.sha256.clone();
            let owner = pubkey.to_owned();
            tokio::spawn(async move {
                if let Err(e) = trigger_transcription(&transcriber_url, &hash, &owner).await {
                    error!("Failed to trigger transcription for {}: {}", hash, e);
                }
            });
        } else {
            info!(
                "TRANSCRIBER_URL not configured, skipping transcript generation for {}",
                response.sha256
            );
        }
    }
}

/// Classify whether the upload produced signals indicating the media is
/// fundamentally invalid (corrupt container, missing moov atom, etc.).
/// Returns a terminal failure signal that the edge can record to avoid
/// retrying derivatives on media that will never transcode.
fn classify_invalid_media_signal(
    content_type: &str,
    sanitize_error: Option<&str>,
    _thumbnail_error: Option<&str>,
    probe_error: Option<&str>,
) -> Option<DerivativeFailureSignal> {
    if !thumbnail::is_video_type(content_type) {
        return None;
    }

    if let Some(message) = sanitize_error {
        return Some(DerivativeFailureSignal {
            error_code: "invalid_media".to_string(),
            error_message: message.to_string(),
            terminal: true,
        });
    }

    if let Some(message) = probe_error {
        return Some(DerivativeFailureSignal {
            error_code: "invalid_media".to_string(),
            error_message: message.to_string(),
            terminal: true,
        });
    }

    None
}

/// Trigger HLS transcoding for a video (fire-and-forget)
/// Sends a POST request to the divine-transcoder service
async fn trigger_transcoding(transcoder_url: &str, hash: &str, owner: &str) -> Result<()> {
    info!(
        "Triggering HLS transcoding for {} via {}",
        hash, transcoder_url
    );

    let client = reqwest::Client::new();
    let transcode_request = serde_json::json!({
        "hash": hash,
        "owner": owner
    });

    let response = client
        .post(format!("{}/transcode", transcoder_url))
        .header("Content-Type", "application/json")
        .json(&transcode_request)
        .send()
        .await
        .map_err(|e| anyhow!("Failed to call transcoder: {}", e))?;

    if response.status().is_success() {
        info!("Transcoding triggered successfully for {}", hash);
        Ok(())
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(anyhow!("Transcoder returned error {}: {}", status, body))
    }
}

/// Trigger transcript generation for audio/video (fire-and-forget)
async fn trigger_transcription(transcriber_url: &str, hash: &str, owner: &str) -> Result<()> {
    info!(
        "Triggering transcript generation for {} via {}",
        hash, transcriber_url
    );

    let client = reqwest::Client::new();
    let request_payload = serde_json::json!({
        "hash": hash,
        "owner": owner
    });

    let response = client
        .post(format!("{}/transcribe", transcriber_url))
        .header("Content-Type", "application/json")
        .json(&request_payload)
        .send()
        .await
        .map_err(|e| anyhow!("Failed to call transcriber: {}", e))?;

    if response.status().is_success() {
        info!("Transcription triggered successfully for {}", hash);
        Ok(())
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(anyhow!("Transcriber returned error {}: {}", status, body))
    }
}

/// Handle migration requests - fetch from URL and upload to GCS
/// POST /migrate { "source_url": "https://cdn.example.com/hash", "expected_hash": "abc123" }
async fn handle_migrate(
    State(state): State<Arc<AppState>>,
    Json(request): Json<MigrateRequest>,
) -> Response {
    match process_migrate(state, request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => {
            error!("Migration error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
    }
}

async fn process_migrate(state: Arc<AppState>, request: MigrateRequest) -> Result<MigrateResponse> {
    info!("Migration request for: {}", request.source_url);

    // Validate URL is from allowed Blossom/CDN sources
    // Expanded to include popular Blossom servers for BUD-04 mirror support
    let allowed_domains = [
        // Divine infrastructure
        "cdn.divine.video",
        "blossom.divine.video",
        // Satellite.earth
        "cdn.satellite.earth",
        "satellite.earth",
        // nostr.build - popular media host
        "nostr.build",
        "image.nostr.build",
        "media.nostr.build",
        "video.nostr.build",
        // void.cat - another popular host
        "void.cat",
        // Primal
        "primal.b-cdn.net",
        "media.primal.net",
        // Other Blossom servers
        "blossom.oxtr.dev",
        "blossom.primal.net",
        "files.sovbit.host",
        "blossom.f7z.io",
        "nostrcheck.me",
    ];
    let url = url::Url::parse(&request.source_url).map_err(|e| anyhow!("Invalid URL: {}", e))?;

    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("URL must have a host"))?;
    if !allowed_domains.iter().any(|d| host.ends_with(d)) {
        return Err(anyhow!("Source URL must be from an allowed domain"));
    }

    // Fetch content from source
    let client = reqwest::Client::new();
    let mut response = client
        .get(&request.source_url)
        .send()
        .await
        .map_err(|e| anyhow!("Failed to fetch source: {}", e))?;

    // If we get 401, try with Nostr auth
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        info!("Source requires auth, attempting Nostr auth...");

        if let Some(nsec) = &state.config.migration_nsec {
            let auth_header = create_blossom_auth(nsec, "get", &request.source_url)?;
            response = client
                .get(&request.source_url)
                .header("Authorization", auth_header)
                .send()
                .await
                .map_err(|e| anyhow!("Failed to fetch source with auth: {}", e))?;
        } else {
            return Err(anyhow!(
                "Source requires auth but no MIGRATION_NSEC configured"
            ));
        }
    }

    if !response.status().is_success() {
        return Err(anyhow!("Source returned status: {}", response.status()));
    }

    // Get content type from response
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    // Stream and hash the content
    let mut hasher = Sha256::new();
    let mut all_bytes = Vec::new();
    let mut total_size: u64 = 0;

    let mut stream = response.bytes_stream();
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| anyhow!("Stream error: {}", e))?;
        hasher.update(&chunk);
        total_size += chunk.len() as u64;
        all_bytes.extend_from_slice(&chunk);
    }

    let sha256_hash = hex::encode(hasher.finalize());

    // Verify hash if expected_hash is provided
    if let Some(expected) = &request.expected_hash {
        if &sha256_hash != expected {
            return Err(anyhow!(
                "Hash mismatch: expected {}, got {}",
                expected,
                sha256_hash
            ));
        }
    }

    // Check if blob already exists in GCS
    let exists = state
        .gcs_client
        .get_object(
            &google_cloud_storage::http::objects::get::GetObjectRequest {
                bucket: state.config.gcs_bucket.clone(),
                object: sha256_hash.clone(),
                ..Default::default()
            },
        )
        .await
        .is_ok();

    if exists {
        info!("Blob {} already exists, skipping migration", sha256_hash);
        return Ok(MigrateResponse {
            sha256: sha256_hash,
            size: total_size,
            content_type,
            migrated: false,
            source_url: request.source_url,
        });
    }

    // Upload to GCS
    let upload_type = UploadType::Simple(Media::new(sha256_hash.clone()));
    let req = UploadObjectRequest {
        bucket: state.config.gcs_bucket.clone(),
        ..Default::default()
    };

    state
        .gcs_client
        .upload_object(&req, Bytes::from(all_bytes), &upload_type)
        .await
        .map_err(|e| anyhow!("GCS upload failed: {}", e))?;

    // Set content type and owner metadata for durability
    let metadata_map = request.owner.as_ref().map(|owner| {
        let mut m = std::collections::HashMap::new();
        m.insert("owner".to_string(), owner.clone());
        m
    });

    let update_req = google_cloud_storage::http::objects::patch::PatchObjectRequest {
        bucket: state.config.gcs_bucket.clone(),
        object: sha256_hash.clone(),
        metadata: Some(Object {
            content_type: Some(content_type.clone()),
            metadata: metadata_map,
            ..Default::default()
        }),
        ..Default::default()
    };
    let _ = state.gcs_client.patch_object(&update_req).await;

    info!(
        "Migrated {} bytes as {} from {} (owner: {:?})",
        total_size, sha256_hash, request.source_url, request.owner
    );

    Ok(MigrateResponse {
        sha256: sha256_hash,
        size: total_size,
        content_type,
        migrated: true,
        source_url: request.source_url,
    })
}

/// Create a Blossom auth header from an nsec
/// nsec is a bech32-encoded Nostr secret key
fn create_blossom_auth(nsec: &str, action: &str, _url: &str) -> Result<String> {
    // Decode nsec (bech32)
    let secret_key_bytes = decode_nsec(nsec)?;

    // Create signing key
    let signing_key = SigningKey::from_bytes(&secret_key_bytes)
        .map_err(|e| anyhow!("Invalid secret key: {}", e))?;

    // Get public key
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes = verifying_key.to_bytes();
    let pubkey_hex = hex::encode(pubkey_bytes);

    // Create event timestamp
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Create expiration (5 minutes from now)
    let expiration = now + 300;

    // Create tags
    let tags = vec![
        vec!["t".to_string(), action.to_string()],
        vec!["expiration".to_string(), expiration.to_string()],
    ];

    // Create event (without id and sig)
    let event_data = serde_json::json!([0, pubkey_hex, now, BLOSSOM_AUTH_KIND, tags, ""]);

    // Hash to get event ID
    let event_str = serde_json::to_string(&event_data)?;
    let mut hasher = Sha256::new();
    hasher.update(event_str.as_bytes());
    let event_id = hex::encode(hasher.finalize());

    // Sign the event ID
    let id_bytes = hex::decode(&event_id)?;
    let signature = signing_key.sign(&id_bytes);
    let sig_hex = hex::encode(signature.to_bytes());

    // Create full event
    let event = serde_json::json!({
        "id": event_id,
        "pubkey": pubkey_hex,
        "created_at": now,
        "kind": BLOSSOM_AUTH_KIND,
        "tags": tags,
        "content": "",
        "sig": sig_hex
    });

    // Base64 encode for Authorization header
    let event_json = serde_json::to_string(&event)?;
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, event_json);

    Ok(format!("Nostr {}", encoded))
}

/// Decode an nsec (bech32-encoded Nostr secret key) to raw bytes
fn decode_nsec(nsec: &str) -> Result<[u8; 32]> {
    if !nsec.starts_with("nsec1") {
        return Err(anyhow!("Invalid nsec: must start with 'nsec1'"));
    }

    // Simple bech32 decode (Nostr uses bech32 without checksum verification for keys)
    let data = &nsec[5..]; // Skip "nsec1" prefix

    // Bech32 alphabet
    const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    let mut bits: Vec<u8> = Vec::new();
    for c in data.chars() {
        let val = CHARSET
            .find(c)
            .ok_or_else(|| anyhow!("Invalid bech32 character: {}", c))? as u8;
        bits.push(val);
    }

    // Convert 5-bit groups to 8-bit bytes
    let mut result = Vec::new();
    let mut acc: u32 = 0;
    let mut bits_count = 0;

    for val in bits {
        acc = (acc << 5) | (val as u32);
        bits_count += 5;
        while bits_count >= 8 {
            bits_count -= 8;
            result.push((acc >> bits_count) as u8);
            acc &= (1 << bits_count) - 1;
        }
    }

    // Take the first 32 bytes (ignore any padding/checksum)
    if result.len() < 32 {
        return Err(anyhow!("Invalid nsec: decoded data too short"));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    Ok(key)
}
