// ABOUTME: GPU video transcoding Cloud Run service for HLS generation
// ABOUTME: Downloads video from GCS, transcodes to HLS with NVENC, uploads segments

use anyhow::{anyhow, Result};
use base64::Engine as _;
use axum::{
    extract::State,
    http::{header, Method, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, options, post},
    Router,
};
use bytes::Bytes;
use google_cloud_storage::{
    client::{Client as GcsClient, ClientConfig},
    http::objects::{
        delete::DeleteObjectRequest,
        download::Range as DownloadRange,
        get::GetObjectRequest,
        patch::PatchObjectRequest,
        upload::{Media, UploadObjectRequest, UploadType},
        Object,
    },
};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env,
    path::Path,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;
use tokio::process::Command;
use tokio::sync::Semaphore;
use tower::Service;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};

// Configuration
struct Config {
    gcs_bucket: String,
    port: u16,
    use_gpu: bool,
    /// URL of the Fastly edge service for status webhook callbacks
    webhook_url: Option<String>,
    /// Secret for authenticating webhook calls
    webhook_secret: Option<String>,
    /// URL of transcription provider API (e.g. OpenAI /audio/transcriptions endpoint)
    transcription_api_url: Option<String>,
    /// API key for the transcription provider
    transcription_api_key: Option<String>,
    /// Model name for transcription API requests
    transcription_model: String,
    /// Transcription provider: "gemini" or "openai"
    transcription_provider: String,
    /// GCP project ID for Vertex AI (required for Gemini provider)
    gcp_project_id: String,
    /// GCP region for Vertex AI
    gcp_region: String,
    /// URL of the Fastly edge service for transcript status webhook callbacks
    transcript_webhook_url: Option<String>,
    transcription_max_in_flight: usize,
    transcription_max_retries: u32,
    transcription_retry_base_ms: u64,
    transcription_retry_max_ms: u64,
    transcription_retry_total_ms: u64,
}

impl Config {
    fn from_env() -> Self {
        Self::from_lookup(|key| env::var(key).ok())
    }

    fn from_lookup<F>(mut lookup: F) -> Self
    where
        F: FnMut(&str) -> Option<String>,
    {
        fn parse_value<F, T>(lookup: &mut F, key: &str, default: T) -> T
        where
            F: FnMut(&str) -> Option<String>,
            T: std::str::FromStr,
        {
            lookup(key)
                .and_then(|value| value.parse::<T>().ok())
                .unwrap_or(default)
        }

        fn parse_bool<F>(lookup: &mut F, key: &str, default: bool) -> bool
        where
            F: FnMut(&str) -> Option<String>,
        {
            lookup(key)
                .map(|value| {
                    let normalized = value.to_ascii_lowercase();
                    normalized == "true" || normalized == "1"
                })
                .unwrap_or(default)
        }

        // Check if GPU is explicitly enabled via env var (more reliable than checking NVIDIA_VISIBLE_DEVICES)
        // Set USE_GPU=true when deploying with actual GPU support
        Self {
            gcs_bucket: lookup("GCS_BUCKET").unwrap_or_else(|| "divine-blossom-media".to_string()),
            port: parse_value(&mut lookup, "PORT", 8080),
            use_gpu: parse_bool(&mut lookup, "USE_GPU", false),
            // Webhook URL for status updates (e.g., https://media.divine.video/admin/transcode-status)
            webhook_url: lookup("WEBHOOK_URL"),
            // Secret for webhook authentication
            webhook_secret: lookup("WEBHOOK_SECRET"),
            // Transcription provider URL (defaults to OpenAI transcription endpoint)
            transcription_api_url: lookup("TRANSCRIPTION_API_URL")
                .or_else(|| lookup("OPENAI_API_URL"))
                .or_else(|| Some("https://api.openai.com/v1/audio/transcriptions".to_string())),
            // Provider auth token
            transcription_api_key: lookup("TRANSCRIPTION_API_KEY")
                .or_else(|| lookup("OPENAI_API_KEY")),
            // Provider model
            transcription_model: lookup("TRANSCRIPTION_MODEL")
                .or_else(|| lookup("OPENAI_MODEL"))
                .unwrap_or_else(|| "whisper-1".to_string()),
            transcription_provider: lookup("TRANSCRIPTION_PROVIDER")
                .unwrap_or_else(|| "gemini".to_string()),
            gcp_project_id: lookup("GCP_PROJECT_ID")
                .unwrap_or_else(|| "rich-compiler-479518-d2".to_string()),
            gcp_region: lookup("GCP_REGION")
                .unwrap_or_else(|| "us-central1".to_string()),
            // Transcript webhook URL (defaults to same host + /admin/transcript-status)
            transcript_webhook_url: lookup("TRANSCRIPT_WEBHOOK_URL"),
            transcription_max_in_flight: parse_value(&mut lookup, "TRANSCRIPTION_MAX_IN_FLIGHT", 4)
                .max(1),
            transcription_max_retries: parse_value(&mut lookup, "TRANSCRIPTION_MAX_RETRIES", 3),
            transcription_retry_base_ms: parse_value(
                &mut lookup,
                "TRANSCRIPTION_RETRY_BASE_MS",
                1_000,
            )
            .max(1),
            transcription_retry_max_ms: parse_value(
                &mut lookup,
                "TRANSCRIPTION_RETRY_MAX_MS",
                15_000,
            )
            .max(1),
            transcription_retry_total_ms: parse_value(
                &mut lookup,
                "TRANSCRIPTION_RETRY_TOTAL_MS",
                30_000,
            )
            .max(1_000),
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
    attempt_count: Option<u32>,
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
            if let Some(attempt_count) = attempt_count {
                scope.set_extra("attempt_count", serde_json::json!(attempt_count));
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
    provider_semaphore: Arc<Semaphore>,
}

// Transcode request
#[derive(Debug, Deserialize)]
struct TranscodeRequest {
    /// SHA256 hash of the original video
    hash: String,
    /// Optional owner pubkey for metadata
    #[serde(default)]
    owner: Option<String>,
    /// Optional subtitle job id from API layer
    #[serde(default)]
    job_id: Option<String>,
    /// Optional requested language code
    #[serde(default)]
    lang: Option<String>,
}

// Audio extraction request
#[derive(Debug, Deserialize)]
struct AudioExtractRequest {
    /// SHA256 hash of the source video
    sha256: String,
    /// Owner pubkey
    owner: String,
}

// Audio extraction response
#[derive(Serialize)]
struct AudioExtractResponse {
    audio_sha256: String,
    duration: f64,
    size: u64,
    mime_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AudioExtractErrorKind {
    NotAVideo,
    NoAudioTrack,
    Other,
}

fn classify_audio_extract_error(message: &str) -> AudioExtractErrorKind {
    if message.contains("not_a_video") {
        AudioExtractErrorKind::NotAVideo
    } else if message.contains("no_audio_track") {
        AudioExtractErrorKind::NoAudioTrack
    } else {
        AudioExtractErrorKind::Other
    }
}

// Transcode response
#[derive(Serialize)]
struct TranscodeResponse {
    hash: String,
    status: String,
    hls_master: String,
    variants: Vec<HlsVariant>,
    /// Display width after rotation (visual width)
    #[serde(skip_serializing_if = "Option::is_none")]
    display_width: Option<u32>,
    /// Display height after rotation (visual height)
    #[serde(skip_serializing_if = "Option::is_none")]
    display_height: Option<u32>,
}

// Transcript response
#[derive(Serialize)]
struct TranscribeResponse {
    hash: String,
    status: String,
    vtt_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    transcript_confidence: Option<TranscriptConfidence>,
}

struct ParsedVtt {
    content: String,
    text: String,
    language: Option<String>,
    duration_ms: u64,
    cue_count: u32,
    confidence: Option<TranscriptConfidence>,
}

impl ParsedVtt {
    fn empty(duration_ms: u64) -> Self {
        Self {
            content: "WEBVTT\n\n".to_string(),
            text: String::new(),
            language: None,
            duration_ms,
            cue_count: 0,
            confidence: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
struct TranscriptConfidence {
    average_token_confidence: f64,
    average_logprob: f64,
    low_confidence_token_ratio: f64,
    token_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderFailure {
    status_code: Option<u16>,
    retry_after: Option<Duration>,
    body: String,
    timed_out: bool,
}

#[derive(Debug, Clone)]
struct ProviderError {
    failure: ProviderFailure,
    exhausted_retryable: bool,
    attempts: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum TranscriptLockStatus {
    Processing,
    CoolingDown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TranscriptLockState {
    status: TranscriptLockStatus,
    started_at_epoch_secs: u64,
    cooldown_until_epoch_secs: Option<u64>,
    error_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TranscriptLockAction {
    StartWork,
    AlreadyProcessing,
    ReclaimStaleLock,
    CoolingDown,
}

#[derive(Debug, Clone)]
struct TranscriptLockHandle {
    path: String,
    generation: i64,
}

impl ProviderError {
    fn error_code(&self) -> &'static str {
        if self.exhausted_retryable {
            "provider_rate_limited"
        } else {
            "provider_failed"
        }
    }

    fn retry_after(&self) -> Option<Duration> {
        self.failure.retry_after
    }
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let suffix = if self.exhausted_retryable {
            " after exhausting retries"
        } else {
            ""
        };
        match self.failure.status_code {
            Some(status) => write!(
                f,
                "Transcription provider returned {}{}: {}",
                status, suffix, self.failure.body
            ),
            None => write!(
                f,
                "Transcription provider request failed{}: {}",
                suffix, self.failure.body
            ),
        }
    }
}

impl std::error::Error for ProviderError {}

fn decide_transcript_lock_action(
    now_epoch_secs: u64,
    existing: Option<&TranscriptLockState>,
    stale_after_secs: u64,
) -> TranscriptLockAction {
    let Some(existing) = existing else {
        return TranscriptLockAction::StartWork;
    };

    match existing.status {
        TranscriptLockStatus::CoolingDown
            if existing
                .cooldown_until_epoch_secs
                .map(|cooldown_until| cooldown_until > now_epoch_secs)
                .unwrap_or(false) =>
        {
            TranscriptLockAction::CoolingDown
        }
        TranscriptLockStatus::Processing
            if now_epoch_secs.saturating_sub(existing.started_at_epoch_secs) < stale_after_secs =>
        {
            TranscriptLockAction::AlreadyProcessing
        }
        _ => TranscriptLockAction::ReclaimStaleLock,
    }
}

impl TranscriptConfidence {
    fn from_logprobs(logprobs: &[f64]) -> Option<Self> {
        if logprobs.is_empty() {
            return None;
        }

        let token_count = logprobs.len().min(u32::MAX as usize) as u32;
        let average_logprob = logprobs.iter().sum::<f64>() / logprobs.len() as f64;
        let average_token_confidence = logprobs
            .iter()
            .map(|logprob| logprob.exp().clamp(0.0, 1.0))
            .sum::<f64>()
            / logprobs.len() as f64;
        let low_confidence_token_ratio =
            logprobs.iter().filter(|&&v| v <= -1.0).count() as f64 / logprobs.len() as f64;

        Some(Self {
            average_token_confidence,
            average_logprob,
            low_confidence_token_ratio,
            token_count,
        })
    }

    fn is_low_confidence(&self) -> bool {
        self.average_logprob <= -1.0
            || self.low_confidence_token_ratio >= 0.5
            || (self.token_count <= 4 && self.average_token_confidence <= 0.45)
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct AudioAnalysis {
    duration_ms: u64,
    silent_duration_ms: u64,
    mean_volume_db: Option<f64>,
    max_volume_db: Option<f64>,
}

impl AudioAnalysis {
    fn silence_ratio(&self) -> f64 {
        if self.duration_ms == 0 {
            return 0.0;
        }
        self.silent_duration_ms as f64 / self.duration_ms as f64
    }

    fn is_effectively_silent(&self) -> bool {
        let silence_ratio = self.silence_ratio();
        let max_is_very_quiet = self.max_volume_db.map(|db| db <= -33.0).unwrap_or(false);
        let mean_is_very_quiet = self.mean_volume_db.map(|db| db <= -45.0).unwrap_or(false);

        self.duration_ms > 0
            && (silence_ratio >= 0.98
                || (silence_ratio >= 0.95 && mean_is_very_quiet)
                || (silence_ratio >= 0.90 && max_is_very_quiet)
                || (max_is_very_quiet && mean_is_very_quiet))
    }

    fn is_low_signal(&self) -> bool {
        let silence_ratio = self.silence_ratio();
        let max_is_quiet = self.max_volume_db.map(|db| db <= -26.0).unwrap_or(false);
        let mean_is_quiet = self.mean_volume_db.map(|db| db <= -38.0).unwrap_or(false);

        silence_ratio >= 0.85 || (max_is_quiet && (mean_is_quiet || silence_ratio >= 0.60))
    }
}

/// Video probe result from ffprobe
#[derive(Debug, Clone)]
struct VideoInfo {
    /// Raw pixel width from codec
    width: u32,
    /// Raw pixel height from codec
    height: u32,
    /// Rotation from metadata (0, 90, 180, 270)
    rotation: u32,
    /// Visual width after applying rotation
    display_width: u32,
    /// Visual height after applying rotation
    display_height: u32,
    /// Whether the video has an audio stream
    has_audio: bool,
}

#[derive(Serialize)]
struct HlsVariant {
    resolution: String,
    playlist: String,
    bandwidth: u32,
}

#[derive(Debug, Clone, Default)]
struct SourceObjectMetadata {
    content_type: Option<String>,
    custom: HashMap<String, String>,
}

// Error response
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// Health check response
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    gpu_available: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _sentry_guard = init_sentry("divine-transcoder");

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("divine_transcoder=info".parse()?),
        )
        .init();

    let config = Config::from_env();
    let port = config.port;
    let use_gpu = config.use_gpu;

    info!(
        "GPU acceleration: {}",
        if use_gpu {
            "enabled"
        } else {
            "disabled (CPU fallback)"
        }
    );

    // Initialize GCS client
    let gcs_config = ClientConfig::default().with_auth().await?;
    let gcs_client = GcsClient::new(gcs_config);
    let provider_semaphore = Arc::new(Semaphore::new(config.transcription_max_in_flight));

    let state = Arc::new(AppState {
        gcs_client,
        config,
        provider_semaphore,
    });

    // CORS configuration
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(std::time::Duration::from_secs(86400));

    // Build router
    let app = Router::new()
        .route("/transcode", post(handle_transcode))
        .route("/transcode", options(handle_cors_preflight))
        .route("/transcribe", post(handle_transcribe))
        .route("/transcribe", options(handle_cors_preflight))
        .route("/backfill-fmp4", post(handle_backfill_fmp4))
        .route("/audio/extract", post(handle_audio_extract))
        .route("/audio/extract", options(handle_cors_preflight))
        .route("/health", get(handle_health))
        .route("/", get(handle_health))
        .layer(cors)
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    info!("Starting transcoder service on {}", addr);

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

async fn handle_health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "healthy".to_string(),
        gpu_available: state.config.use_gpu,
    })
}

async fn handle_transcode(
    State(state): State<Arc<AppState>>,
    Json(request): Json<TranscodeRequest>,
) -> Response {
    match process_transcode(state, request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => {
            error!("Transcode error: {}", e);
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

async fn handle_transcribe(
    State(state): State<Arc<AppState>>,
    Json(request): Json<TranscodeRequest>,
) -> Response {
    match process_transcribe(state, request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => {
            error!("Transcribe error: {}", e);
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

async fn handle_backfill_fmp4(
    State(state): State<Arc<AppState>>,
    Json(request): Json<TranscodeRequest>,
) -> Response {
    let hash = request.hash.to_lowercase();

    // Download .ts files from GCS
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();

    for variant in &["stream_720p", "stream_480p"] {
        let gcs_key = format!("{}/hls/{}.ts", hash, variant);
        let ts_path = temp_path.join(format!("{}.ts", variant));

        if let Err(e) = download_from_gcs(
            &state.gcs_client,
            &state.config.gcs_bucket,
            &gcs_key,
            &ts_path,
        )
        .await
        {
            warn!("Backfill: {} not found for {}: {}", variant, hash, e);
            continue;
        }
    }

    // Remux .ts to .mp4
    if let Err(e) = remux_ts_to_fmp4(temp_path).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }

    // Remove .ts files from temp dir so upload_hls_to_gcs only uploads .mp4
    for variant in &["stream_720p", "stream_480p"] {
        let ts_path = temp_path.join(format!("{}.ts", variant));
        let _ = tokio::fs::remove_file(&ts_path).await;
    }

    // Upload only the new .mp4 files
    let source_metadata = SourceObjectMetadata::default();
    if let Err(e) = upload_hls_to_gcs(
        &state.gcs_client,
        &state.config.gcs_bucket,
        &hash,
        temp_path,
        &source_metadata,
    )
    .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }

    Json(serde_json::json!({"status": "ok", "hash": hash})).into_response()
}

async fn handle_audio_extract(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AudioExtractRequest>,
) -> Response {
    match process_audio_extract(state, request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => {
            let msg = e.to_string();
            match classify_audio_extract_error(&msg) {
                AudioExtractErrorKind::NotAVideo => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(ErrorResponse {
                        error: "not_a_video".to_string(),
                    }),
                )
                    .into_response(),
                AudioExtractErrorKind::NoAudioTrack => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(ErrorResponse {
                        error: "no_audio_track".to_string(),
                    }),
                )
                    .into_response(),
                AudioExtractErrorKind::Other => {
                    error!("Audio extract error: {}", e);
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
    }
}

async fn process_audio_extract(
    state: Arc<AppState>,
    request: AudioExtractRequest,
) -> Result<AudioExtractResponse> {
    let hash = request.sha256.to_lowercase();

    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("Invalid hash format"));
    }

    info!("Starting audio extraction for {}", hash);

    let temp_dir = TempDir::new()?;
    let input_path = temp_dir.path().join("input");

    // Download source video from GCS
    download_from_gcs(
        &state.gcs_client,
        &state.config.gcs_bucket,
        &hash,
        &input_path,
    )
    .await?;

    // Verify it's a video with an audio track using ffprobe
    let probe_output = Command::new("ffprobe")
        .args([
            "-v",
            "quiet",
            "-print_format",
            "json",
            "-show_streams",
            &input_path.to_string_lossy(),
        ])
        .output()
        .await?;

    let probe_json: serde_json::Value =
        serde_json::from_slice(&probe_output.stdout).map_err(|_| anyhow!("not_a_video"))?;

    let streams = probe_json
        .get("streams")
        .and_then(|s| s.as_array())
        .ok_or_else(|| anyhow!("not_a_video"))?;

    let has_video = streams
        .iter()
        .any(|s| s.get("codec_type").and_then(|t| t.as_str()) == Some("video"));
    let has_audio = streams
        .iter()
        .any(|s| s.get("codec_type").and_then(|t| t.as_str()) == Some("audio"));

    if !has_video {
        return Err(anyhow!("not_a_video"));
    }
    if !has_audio {
        return Err(anyhow!("no_audio_track"));
    }

    // Extract audio with ffmpeg: AAC in M4A container
    let output_path = temp_dir.path().join("output.m4a");
    let extract_output = Command::new("ffmpeg")
        .args([
            "-y",
            "-i",
            &input_path.to_string_lossy(),
            "-vn",
            "-acodec",
            "aac",
            "-b:a",
            "128k",
            &output_path.to_string_lossy().to_string(),
        ])
        .output()
        .await?;

    if !extract_output.status.success() {
        let stderr = String::from_utf8_lossy(&extract_output.stderr);
        return Err(anyhow!("FFmpeg audio extraction failed: {}", stderr));
    }

    // Get duration with ffprobe
    let duration_output = Command::new("ffprobe")
        .args([
            "-v",
            "quiet",
            "-show_entries",
            "format=duration",
            "-of",
            "csv=p=0",
            &output_path.to_string_lossy().to_string(),
        ])
        .output()
        .await?;

    let duration: f64 = String::from_utf8_lossy(&duration_output.stdout)
        .trim()
        .parse()
        .unwrap_or(0.0);

    // SHA256 the output file
    let audio_data = tokio::fs::read(&output_path).await?;
    use sha2::{Digest, Sha256};
    let audio_sha256 = hex::encode(Sha256::digest(&audio_data));
    let size = audio_data.len() as u64;

    // Upload to GCS if not already present
    if !check_gcs_exists(&state.gcs_client, &state.config.gcs_bucket, &audio_sha256).await? {
        let mut custom_metadata = HashMap::new();
        custom_metadata.insert("source_sha256".to_string(), hash.clone());
        custom_metadata.insert("derivative".to_string(), "audio".to_string());
        custom_metadata.insert("owner".to_string(), request.owner.clone());

        let mut media = Media::new(audio_sha256.clone());
        media.content_type = "audio/mp4".into();
        let upload_type = UploadType::Simple(media);

        let req = UploadObjectRequest {
            bucket: state.config.gcs_bucket.clone(),
            ..Default::default()
        };

        state
            .gcs_client
            .upload_object(&req, Bytes::from(audio_data), &upload_type)
            .await
            .map_err(|e| anyhow!("Failed to upload audio to GCS: {}", e))?;

        // Set custom metadata on the uploaded object
        let patch_req = PatchObjectRequest {
            bucket: state.config.gcs_bucket.clone(),
            object: audio_sha256.clone(),
            metadata: Some(Object {
                metadata: Some(custom_metadata),
                cache_control: Some("public, max-age=31536000, immutable".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let _ = state.gcs_client.patch_object(&patch_req).await;

        info!(
            "Uploaded audio {} ({} bytes) for source {}",
            audio_sha256, size, hash
        );
    } else {
        info!("Audio {} already exists in GCS", audio_sha256);
    }

    Ok(AudioExtractResponse {
        audio_sha256,
        duration,
        size,
        mime_type: "audio/mp4".to_string(),
    })
}

async fn process_transcode(
    state: Arc<AppState>,
    request: TranscodeRequest,
) -> Result<TranscodeResponse> {
    let hash = request.hash.to_lowercase();

    // Validate hash format
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("Invalid hash format: must be 64 hex characters"));
    }

    info!("Starting transcode for {}", hash);

    // Check if HLS already exists
    let master_path = format!("{}/hls/master.m3u8", hash);
    if check_gcs_exists(&state.gcs_client, &state.config.gcs_bucket, &master_path).await? {
        info!("HLS already exists for {}, skipping transcode", hash);
        // Still update status to complete in case it was pending (no size change for already-transcoded)
        send_status_webhook(
            &state.config,
            &hash,
            "complete",
            None,
            None,
            None,
            None,
            None,
            false,
        )
        .await;
        return Ok(TranscodeResponse {
            hash: hash.clone(),
            status: "already_exists".to_string(),
            hls_master: master_path,
            variants: vec![
                HlsVariant {
                    resolution: "720p".to_string(),
                    playlist: format!("{}/hls/stream_720p.m3u8", hash),
                    bandwidth: 2_500_000,
                },
                HlsVariant {
                    resolution: "480p".to_string(),
                    playlist: format!("{}/hls/stream_480p.m3u8", hash),
                    bandwidth: 1_000_000,
                },
            ],
            display_width: None,
            display_height: None,
        });
    }

    // Update status to processing
    send_status_webhook(
        &state.config,
        &hash,
        "processing",
        None,
        None,
        None,
        None,
        None,
        false,
    )
    .await;

    // Create temp directory for processing
    let temp_dir = TempDir::new()?;
    let temp_path = temp_dir.path();

    // Download original video from GCS
    let input_path = temp_path.join("input.mp4");
    let download_result = download_from_gcs(
        &state.gcs_client,
        &state.config.gcs_bucket,
        &hash,
        &input_path,
    )
    .await;

    if let Err(e) = download_result {
        send_status_webhook(
            &state.config,
            &hash,
            "failed",
            None,
            None,
            Some("download_failed"),
            Some(&e.to_string()),
            None,
            false,
        )
        .await;
        return Err(e);
    }

    info!("Downloaded video to {:?}", input_path);

    // Read source metadata once so HLS derivatives can preserve provenance.
    let mut source_metadata = match get_source_object_metadata(
        &state.gcs_client,
        &state.config.gcs_bucket,
        &hash,
    )
    .await
    {
        Ok(meta) => meta,
        Err(e) => {
            warn!("Failed to load source metadata for {}: {}", hash, e);
            SourceObjectMetadata::default()
        }
    };
    if let Some(owner) = request.owner.clone() {
        source_metadata
            .custom
            .entry("owner".to_string())
            .or_insert(owner);
    }

    // Probe video to get dimensions and rotation metadata
    let video_info = match probe_video(&input_path).await {
        Ok(info) => info,
        Err(e) => {
            warn!(
                "Failed to probe video, using default landscape dimensions: {}",
                e
            );
            // Fallback: assume landscape 1920x1080 with audio so old behavior is preserved
            VideoInfo {
                width: 1920,
                height: 1080,
                rotation: 0,
                display_width: 1920,
                display_height: 1080,
                has_audio: true,
            }
        }
    };

    // NOTE: We do NOT modify the original file - SHA256 hash must remain valid for
    // content-addressable storage and ProofMode verification. HLS provides streaming.

    // Create output directory for HLS
    let output_dir = temp_path.join("hls");
    tokio::fs::create_dir_all(&output_dir).await?;

    // Run FFmpeg to generate HLS with orientation-aware scaling
    let ffmpeg_result =
        run_ffmpeg_hls(&input_path, &output_dir, state.config.use_gpu, &video_info).await;

    let variants = match ffmpeg_result {
        Ok(v) => v,
        Err(e) => {
            let error_message = e.to_string();
            let (error_code, terminal) =
                classify_invalid_media_error(&error_message, "transcode_failed");
            if terminal {
                report_derivative_failure_to_sentry(
                    "divine-transcoder",
                    "hls",
                    &hash,
                    error_code,
                    &error_message,
                    true,
                    Some("video/mp4"),
                    request.owner.as_deref(),
                    Some(1),
                );
            }
            send_status_webhook(
                &state.config,
                &hash,
                "failed",
                None,
                Some(&video_info),
                Some(error_code),
                Some(&error_message),
                None,
                terminal,
            )
            .await;
            return Err(e);
        }
    };

    info!("Generated HLS with {} variants", variants.len());

    if let Err(e) = remux_ts_to_fmp4(&output_dir).await {
        warn!("fMP4 remux step failed: {} (continuing with .ts only)", e);
    }

    // Upload all HLS files to GCS
    let upload_result = upload_hls_to_gcs(
        &state.gcs_client,
        &state.config.gcs_bucket,
        &hash,
        &output_dir,
        &source_metadata,
    )
    .await;

    if let Err(e) = upload_result {
        send_status_webhook(
            &state.config,
            &hash,
            "failed",
            None,
            Some(&video_info),
            Some("upload_failed"),
            Some(&e.to_string()),
            None,
            false,
        )
        .await;
        return Err(e);
    }

    info!("Uploaded HLS files for {}", hash);

    // Update status to complete with video dimensions for the edge service
    send_status_webhook(
        &state.config,
        &hash,
        "complete",
        None,
        Some(&video_info),
        None,
        None,
        None,
        false,
    )
    .await;

    Ok(TranscodeResponse {
        hash: hash.clone(),
        status: "complete".to_string(),
        hls_master: format!("{}/hls/master.m3u8", hash),
        variants,
        display_width: Some(video_info.display_width),
        display_height: Some(video_info.display_height),
    })
}

async fn process_transcribe(
    state: Arc<AppState>,
    request: TranscodeRequest,
) -> Result<TranscribeResponse> {
    let hash = request.hash.to_lowercase();
    let job_id = request.job_id.clone();
    let requested_lang = request.lang.clone();

    // Validate hash format
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("Invalid hash format: must be 64 hex characters"));
    }

    info!("Starting transcription for {}", hash);

    let vtt_path = format!("{}/vtt/main.vtt", hash);
    if check_gcs_exists(&state.gcs_client, &state.config.gcs_bucket, &vtt_path).await? {
        info!(
            "Transcript already exists for {}, skipping transcription",
            hash
        );
        send_transcript_status_webhook(
            &state.config,
            &hash,
            "complete",
            job_id.as_deref(),
            requested_lang.as_deref(),
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        )
        .await;
        return Ok(TranscribeResponse {
            hash,
            status: "already_exists".to_string(),
            vtt_path,
            transcript_confidence: None,
        });
    }

    let transcript_lock =
        match acquire_transcript_lock(&state.gcs_client, &state.config.gcs_bucket, &hash, 900)
            .await?
        {
            Ok(handle) => handle,
            Err(TranscriptLockAction::AlreadyProcessing) => {
                info!(
                    "Transcript already processing for {}, skipping duplicate request",
                    hash
                );
                return Ok(TranscribeResponse {
                    hash,
                    status: "already_processing".to_string(),
                    vtt_path,
                    transcript_confidence: None,
                });
            }
            Err(TranscriptLockAction::CoolingDown) => {
                info!(
                    "Transcript cooldown active for {}, skipping duplicate request",
                    hash
                );
                return Ok(TranscribeResponse {
                    hash,
                    status: "cooling_down".to_string(),
                    vtt_path,
                    transcript_confidence: None,
                });
            }
            Err(TranscriptLockAction::StartWork | TranscriptLockAction::ReclaimStaleLock) => {
                unreachable!("acquire_transcript_lock resolves start/reclaim internally")
            }
        };

    send_transcript_status_webhook(
        &state.config,
        &hash,
        "processing",
        job_id.as_deref(),
        requested_lang.as_deref(),
        None,
        None,
        None,
        None,
        None,
        None,
        false,
    )
    .await;

    let temp_dir = TempDir::new()?;
    let temp_path = temp_dir.path();

    let input_path = temp_path.join("input_media");
    if let Err(e) = download_from_gcs(
        &state.gcs_client,
        &state.config.gcs_bucket,
        &hash,
        &input_path,
    )
    .await
    {
        if let Err(lock_error) = delete_transcript_lock(
            &state.gcs_client,
            &state.config.gcs_bucket,
            &transcript_lock,
        )
        .await
        {
            warn!(
                "Failed to release transcript lock for {}: {}",
                hash, lock_error
            );
        }
        send_transcript_status_webhook(
            &state.config,
            &hash,
            "failed",
            job_id.as_deref(),
            requested_lang.as_deref(),
            None,
            None,
            None,
            None,
            Some("download_failed"),
            Some(&e.to_string()),
            false,
        )
        .await;
        return Err(e);
    }

    if !check_has_audio(&input_path).await {
        info!(
            "Skipping provider call for {} because the source has no audio stream",
            hash
        );
        let parsed_vtt = ParsedVtt::empty(0);
        let result = finalize_transcript(
            &state,
            &hash,
            job_id.as_deref(),
            requested_lang.as_deref(),
            parsed_vtt,
            &vtt_path,
        )
        .await;
        if let Err(lock_error) = delete_transcript_lock(
            &state.gcs_client,
            &state.config.gcs_bucket,
            &transcript_lock,
        )
        .await
        {
            warn!(
                "Failed to release transcript lock for {}: {}",
                hash, lock_error
            );
        }
        return result;
    }

    let audio_path = temp_path.join("transcribe.wav");
    if let Err(e) = extract_audio_for_transcription(&input_path, &audio_path).await {
        let error_message = e.to_string();
        let (error_code, terminal) =
            classify_invalid_media_error(&error_message, "audio_extract_failed");
        if terminal {
            report_derivative_failure_to_sentry(
                "divine-transcoder",
                "transcript",
                &hash,
                error_code,
                &error_message,
                true,
                Some("video/mp4"),
                request.owner.as_deref(),
                Some(1),
            );
        }
        if let Err(lock_error) = delete_transcript_lock(
            &state.gcs_client,
            &state.config.gcs_bucket,
            &transcript_lock,
        )
        .await
        {
            warn!(
                "Failed to release transcript lock for {}: {}",
                hash, lock_error
            );
        }
        send_transcript_status_webhook(
            &state.config,
            &hash,
            "failed",
            job_id.as_deref(),
            requested_lang.as_deref(),
            None,
            None,
            None,
            None,
            Some(error_code),
            Some(&error_message),
            terminal,
        )
        .await;
        return Err(e);
    }

    let audio_analysis = match analyze_audio_signal(&audio_path).await {
        Ok(analysis) => analysis,
        Err(e) => {
            warn!(
                "Audio analysis failed for {}; continuing without silence guardrails: {}",
                hash, e
            );
            AudioAnalysis {
                duration_ms: audio_duration_ms(&audio_path).await.unwrap_or(0),
                ..AudioAnalysis::default()
            }
        }
    };
    if audio_analysis.is_effectively_silent() {
        info!(
            "Skipping provider call for {} because audio is effectively silent (duration_ms={}, silence_ratio={:.3}, mean_volume_db={:?}, max_volume_db={:?})",
            hash,
            audio_analysis.duration_ms,
            audio_analysis.silence_ratio(),
            audio_analysis.mean_volume_db,
            audio_analysis.max_volume_db
        );
        let parsed_vtt = ParsedVtt::empty(audio_analysis.duration_ms);
        let result = finalize_transcript(
            &state,
            &hash,
            job_id.as_deref(),
            requested_lang.as_deref(),
            parsed_vtt,
            &vtt_path,
        )
        .await;
        if let Err(lock_error) = delete_transcript_lock(
            &state.gcs_client,
            &state.config.gcs_bucket,
            &transcript_lock,
        )
        .await
        {
            warn!(
                "Failed to release transcript lock for {}: {}",
                hash, lock_error
            );
        }
        return result;
    }

    let provider_wait_started = Instant::now();
    let provider_permit = state
        .provider_semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|e| anyhow!("Provider semaphore closed: {}", e))?;
    let provider_wait_ms = provider_wait_started
        .elapsed()
        .as_millis()
        .min(u64::MAX as u128) as u64;
    let in_flight = state
        .config
        .transcription_max_in_flight
        .saturating_sub(state.provider_semaphore.available_permits());
    info!(
        hash,
        in_flight, provider_wait_ms, "Acquired transcription provider permit"
    );

    let raw_output =
        match transcribe_audio_via_provider(&state.config, &audio_path, requested_lang.as_deref())
            .await
        {
            Ok(output) => output,
            Err(e) => {
                drop(provider_permit);
                if e.exhausted_retryable {
                    report_derivative_failure_to_sentry(
                        "divine-transcoder",
                        "transcript",
                        &hash,
                        e.error_code(),
                        &e.to_string(),
                        false,
                        None,
                        request.owner.as_deref(),
                        Some(e.attempts),
                    );
                }
                if e.exhausted_retryable {
                    let retry_after = e.retry_after().unwrap_or_else(|| {
                        Duration::from_millis(state.config.transcription_retry_max_ms)
                    });
                    if let Err(lock_error) = write_transcript_cooldown(
                        &state.gcs_client,
                        &state.config.gcs_bucket,
                        &hash,
                        &transcript_lock,
                        retry_after,
                        e.error_code(),
                    )
                    .await
                    {
                        warn!(
                            "Failed to persist transcript cooldown for {}: {}",
                            hash, lock_error
                        );
                    }
                } else if let Err(lock_error) = delete_transcript_lock(
                    &state.gcs_client,
                    &state.config.gcs_bucket,
                    &transcript_lock,
                )
                .await
                {
                    warn!(
                        "Failed to release transcript lock for {}: {}",
                        hash, lock_error
                    );
                }
                send_transcript_status_webhook(
                    &state.config,
                    &hash,
                    "failed",
                    job_id.as_deref(),
                    requested_lang.as_deref(),
                    None,
                    None,
                    None,
                    e.retry_after().map(|duration| duration.as_secs().max(1)),
                    Some(e.error_code()),
                    Some(&e.to_string()),
                    false,
                )
                .await;
                return Err(e.into());
            }
        };
    drop(provider_permit);

    let parsed_vtt = match normalize_transcript_to_vtt(&raw_output) {
        Ok(vtt) => vtt,
        Err(e) => {
            if let Err(lock_error) = delete_transcript_lock(
                &state.gcs_client,
                &state.config.gcs_bucket,
                &transcript_lock,
            )
            .await
            {
                warn!(
                    "Failed to release transcript lock for {}: {}",
                    hash, lock_error
                );
            }
            send_transcript_status_webhook(
                &state.config,
                &hash,
                "failed",
                job_id.as_deref(),
                requested_lang.as_deref(),
                None,
                None,
                None,
                None,
                Some("normalize_failed"),
                Some(&e.to_string()),
                false,
            )
            .await;
            return Err(e);
        }
    };

    if let Some(confidence) = parsed_vtt.confidence {
        info!(
            "Provider transcript confidence for {}: avg_token_confidence={:.3}, avg_logprob={:.3}, low_confidence_token_ratio={:.3}, token_count={}",
            hash,
            confidence.average_token_confidence,
            confidence.average_logprob,
            confidence.low_confidence_token_ratio,
            confidence.token_count
        );
    }

    let parsed_vtt = match transcript_drop_reason(&audio_analysis, &parsed_vtt) {
        Some(TranscriptDropReason::LowProviderConfidence) => {
            warn!(
                "Dropping low-confidence transcript for {} (text={:?}, confidence={:?})",
                hash, parsed_vtt.text, parsed_vtt.confidence
            );
            ParsedVtt::empty(audio_analysis.duration_ms)
        }
        Some(TranscriptDropReason::LowSignalHeuristic) => {
            warn!(
                "Dropping likely hallucinated transcript for {} (silence_ratio={:.3}, mean_volume_db={:?}, max_volume_db={:?}, text={:?})",
                hash,
                audio_analysis.silence_ratio(),
                audio_analysis.mean_volume_db,
                audio_analysis.max_volume_db,
                parsed_vtt.text
            );
            ParsedVtt::empty(audio_analysis.duration_ms)
        }
        None => parsed_vtt,
    };

    let result = finalize_transcript(
        &state,
        &hash,
        job_id.as_deref(),
        requested_lang.as_deref(),
        parsed_vtt,
        &vtt_path,
    )
    .await;
    if let Err(lock_error) = delete_transcript_lock(
        &state.gcs_client,
        &state.config.gcs_bucket,
        &transcript_lock,
    )
    .await
    {
        warn!(
            "Failed to release transcript lock for {}: {}",
            hash, lock_error
        );
    }
    result
}

async fn check_gcs_exists(client: &GcsClient, bucket: &str, object: &str) -> Result<bool> {
    match client
        .get_object(&GetObjectRequest {
            bucket: bucket.to_string(),
            object: object.to_string(),
            ..Default::default()
        })
        .await
    {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

async fn download_from_gcs(
    client: &GcsClient,
    bucket: &str,
    object: &str,
    output_path: &Path,
) -> Result<()> {
    let data = client
        .download_object(
            &GetObjectRequest {
                bucket: bucket.to_string(),
                object: object.to_string(),
                ..Default::default()
            },
            &DownloadRange::default(),
        )
        .await
        .map_err(|e| anyhow!("Failed to download from GCS: {}", e))?;

    tokio::fs::write(output_path, &data).await?;
    Ok(())
}

/// Extract mono 16kHz PCM WAV audio for transcription.
async fn extract_audio_for_transcription(input_path: &Path, audio_path: &Path) -> Result<()> {
    let input_str = input_path.to_string_lossy();
    let audio_str = audio_path.to_string_lossy();

    let output = Command::new("ffmpeg")
        .args([
            "-y",
            "-i",
            &input_str,
            "-vn",
            "-ac",
            "1",
            "-ar",
            "16000",
            "-c:a",
            "pcm_s16le",
            &audio_str,
        ])
        .output()
        .await
        .map_err(|e| anyhow!("Failed to run ffmpeg audio extraction: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("ffmpeg audio extraction failed: {}", stderr));
    }

    let metadata = tokio::fs::metadata(audio_path)
        .await
        .map_err(|e| anyhow!("Audio output missing after extraction: {}", e))?;

    if metadata.len() == 0 {
        return Err(anyhow!("Extracted audio is empty"));
    }

    Ok(())
}

async fn analyze_audio_signal(audio_path: &Path) -> Result<AudioAnalysis> {
    let duration_ms = audio_duration_ms(audio_path).await?;
    let audio_str = audio_path.to_string_lossy().to_string();

    let output = Command::new("ffmpeg")
        .args([
            "-hide_banner",
            "-nostats",
            "-i",
            &audio_str,
            "-af",
            "silencedetect=noise=-38dB:d=0.5,volumedetect",
            "-f",
            "null",
            "-",
        ])
        .output()
        .await
        .map_err(|e| anyhow!("Failed to analyze extracted audio: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("ffmpeg audio analysis failed: {}", stderr));
    }

    Ok(parse_audio_analysis_output(
        &String::from_utf8_lossy(&output.stderr),
        duration_ms,
    ))
}

async fn audio_duration_ms(audio_path: &Path) -> Result<u64> {
    let metadata = tokio::fs::metadata(audio_path)
        .await
        .map_err(|e| anyhow!("Failed to stat extracted audio: {}", e))?;

    if metadata.len() <= 44 {
        return Ok(0);
    }

    let pcm_bytes = metadata.len().saturating_sub(44);
    Ok(((pcm_bytes as f64 / 32000.0) * 1000.0).round() as u64)
}

fn parse_audio_analysis_output(stderr: &str, duration_ms: u64) -> AudioAnalysis {
    let mut analysis = AudioAnalysis {
        duration_ms,
        ..AudioAnalysis::default()
    };
    let mut current_silence_start_ms: Option<u64> = None;

    for line in stderr.lines() {
        if let Some(value) = line.split("silence_start:").nth(1) {
            current_silence_start_ms = parse_seconds_to_ms(value.trim());
            continue;
        }

        if let Some(value) = line.split("silence_end:").nth(1) {
            let end_ms = value
                .split('|')
                .next()
                .and_then(|part| parse_seconds_to_ms(part.trim()))
                .unwrap_or(duration_ms);
            if let Some(start_ms) = current_silence_start_ms.take() {
                analysis.silent_duration_ms = analysis
                    .silent_duration_ms
                    .saturating_add(end_ms.saturating_sub(start_ms));
            }
            continue;
        }

        if let Some(value) = line.split("mean_volume:").nth(1) {
            analysis.mean_volume_db = parse_volume_db(value.trim());
            continue;
        }

        if let Some(value) = line.split("max_volume:").nth(1) {
            analysis.max_volume_db = parse_volume_db(value.trim());
        }
    }

    if let Some(start_ms) = current_silence_start_ms {
        analysis.silent_duration_ms = analysis
            .silent_duration_ms
            .saturating_add(duration_ms.saturating_sub(start_ms));
    }

    analysis.silent_duration_ms = analysis.silent_duration_ms.min(duration_ms);
    analysis
}

fn parse_seconds_to_ms(input: &str) -> Option<u64> {
    let value = input.split_whitespace().next()?;
    let seconds = value.parse::<f64>().ok()?;
    Some((seconds.max(0.0) * 1000.0).round() as u64)
}

fn parse_volume_db(input: &str) -> Option<f64> {
    let value = input.split_whitespace().next()?;
    if value.eq_ignore_ascii_case("-inf") {
        return Some(f64::NEG_INFINITY);
    }
    value.parse::<f64>().ok()
}

fn parse_retry_after_header(value: Option<&str>) -> Option<Duration> {
    let seconds = value?.trim().parse::<u64>().ok()?;
    Some(Duration::from_secs(seconds))
}

fn parse_provider_status(
    status_code: Option<u16>,
    retry_after_header: Option<&str>,
    body: &str,
    timed_out: bool,
) -> ProviderFailure {
    ProviderFailure {
        status_code,
        retry_after: parse_retry_after_header(retry_after_header),
        body: body.to_string(),
        timed_out,
    }
}

fn is_retryable_provider_failure(failure: &ProviderFailure) -> bool {
    failure.timed_out || matches!(failure.status_code, Some(429 | 500 | 502 | 503 | 504))
}

fn retry_delay_for_attempt(
    attempt: u32,
    base_delay_ms: u64,
    max_delay_ms: u64,
    retry_after: Option<Duration>,
    jitter_ratio: f64,
) -> Duration {
    let exponential = base_delay_ms
        .saturating_mul(2u64.saturating_pow(attempt))
        .min(max_delay_ms);
    let requested_delay = retry_after
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(exponential)
        .min(max_delay_ms);
    if requested_delay >= max_delay_ms {
        return Duration::from_millis(max_delay_ms.max(1));
    }
    let clamped_ratio = jitter_ratio.clamp(0.0, 1.0);
    let jittered = ((requested_delay as f64) * (0.75 + (0.25 * clamped_ratio))).round() as u64;
    Duration::from_millis(jittered.max(1))
}

fn retry_jitter_ratio() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| f64::from(duration.subsec_micros()) / 1_000_000.0)
        .unwrap_or(0.5)
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn transcript_lock_path(hash: &str) -> String {
    format!("{}/vtt/.lock", hash)
}

async fn fetch_transcript_lock(
    client: &GcsClient,
    bucket: &str,
    hash: &str,
) -> Result<Option<(TranscriptLockState, i64)>> {
    let path = transcript_lock_path(hash);
    let object = match client
        .get_object(&GetObjectRequest {
            bucket: bucket.to_string(),
            object: path.clone(),
            ..Default::default()
        })
        .await
    {
        Ok(object) => object,
        Err(_) => return Ok(None),
    };

    let raw = client
        .download_object(
            &GetObjectRequest {
                bucket: bucket.to_string(),
                object: path,
                ..Default::default()
            },
            &DownloadRange::default(),
        )
        .await
        .map_err(|e| anyhow!("Failed to download transcript lock: {}", e))?;
    let state = serde_json::from_slice::<TranscriptLockState>(&raw)
        .map_err(|e| anyhow!("Failed to parse transcript lock: {}", e))?;

    Ok(Some((state, object.generation)))
}

async fn write_transcript_lock(
    client: &GcsClient,
    bucket: &str,
    hash: &str,
    state: &TranscriptLockState,
    if_generation_match: Option<i64>,
) -> Result<TranscriptLockHandle> {
    let path = transcript_lock_path(hash);
    let mut media = Media::new(path.clone());
    media.content_type = "application/json".into();
    let upload = client
        .upload_object(
            &UploadObjectRequest {
                bucket: bucket.to_string(),
                if_generation_match,
                ..Default::default()
            },
            Bytes::from(
                serde_json::to_vec(state)
                    .map_err(|e| anyhow!("Failed to serialize transcript lock: {}", e))?,
            ),
            &UploadType::Simple(media),
        )
        .await
        .map_err(|e| anyhow!("Failed to write transcript lock: {}", e))?;

    Ok(TranscriptLockHandle {
        path,
        generation: upload.generation,
    })
}

async fn delete_transcript_lock(
    client: &GcsClient,
    bucket: &str,
    handle: &TranscriptLockHandle,
) -> Result<()> {
    client
        .delete_object(&DeleteObjectRequest {
            bucket: bucket.to_string(),
            object: handle.path.clone(),
            if_generation_match: Some(handle.generation),
            ..Default::default()
        })
        .await
        .map_err(|e| anyhow!("Failed to delete transcript lock: {}", e))?;
    Ok(())
}

async fn acquire_transcript_lock(
    client: &GcsClient,
    bucket: &str,
    hash: &str,
    stale_after_secs: u64,
) -> Result<std::result::Result<TranscriptLockHandle, TranscriptLockAction>> {
    let processing_state = TranscriptLockState {
        status: TranscriptLockStatus::Processing,
        started_at_epoch_secs: current_epoch_secs(),
        cooldown_until_epoch_secs: None,
        error_code: None,
    };

    match write_transcript_lock(client, bucket, hash, &processing_state, Some(0)).await {
        Ok(handle) => return Ok(Ok(handle)),
        Err(write_error) => {
            let Some((existing, generation)) = fetch_transcript_lock(client, bucket, hash).await?
            else {
                return Err(write_error);
            };
            let action = decide_transcript_lock_action(
                current_epoch_secs(),
                Some(&existing),
                stale_after_secs,
            );
            if action != TranscriptLockAction::ReclaimStaleLock {
                return Ok(Err(action));
            }

            let stale_handle = TranscriptLockHandle {
                path: transcript_lock_path(hash),
                generation,
            };
            delete_transcript_lock(client, bucket, &stale_handle).await?;
            write_transcript_lock(client, bucket, hash, &processing_state, Some(0))
                .await
                .map(Ok)
        }
    }
}

async fn write_transcript_cooldown(
    client: &GcsClient,
    bucket: &str,
    hash: &str,
    handle: &TranscriptLockHandle,
    retry_after: Duration,
    error_code: &str,
) -> Result<()> {
    let now = current_epoch_secs();
    let retry_after_secs = retry_after.as_secs().max(1);
    let cooldown_state = TranscriptLockState {
        status: TranscriptLockStatus::CoolingDown,
        started_at_epoch_secs: now,
        cooldown_until_epoch_secs: Some(now.saturating_add(retry_after_secs)),
        error_code: Some(error_code.to_string()),
    };

    write_transcript_lock(
        client,
        bucket,
        hash,
        &cooldown_state,
        Some(handle.generation),
    )
    .await?;
    Ok(())
}

async fn transcribe_audio_via_provider_once(
    config: &Config,
    audio_path: &Path,
    language: Option<&str>,
) -> std::result::Result<String, ProviderFailure> {
    if config.transcription_provider == "gemini" {
        return transcribe_via_gemini(config, audio_path, language).await;
    }

    // --- OpenAI path (original) ---
    let api_url = config.transcription_api_url.as_ref().ok_or_else(|| {
        parse_provider_status(None, None, "TRANSCRIPTION_API_URL is not configured", false)
    })?;

    let audio_bytes = tokio::fs::read(audio_path).await.map_err(|e| {
        parse_provider_status(
            None,
            None,
            &format!("Failed to read extracted audio: {}", e),
            false,
        )
    })?;
    let filename = audio_path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("audio.wav")
        .to_string();

    let file_part = reqwest::multipart::Part::bytes(audio_bytes)
        .file_name(filename)
        .mime_str("audio/wav")
        .map_err(|e| {
            parse_provider_status(
                None,
                None,
                &format!("Failed to build multipart audio part: {}", e),
                false,
            )
        })?;

    let response_format = transcription_response_format(&config.transcription_model);
    let mut form = reqwest::multipart::Form::new()
        .text("model", config.transcription_model.clone())
        .text("response_format", response_format.to_string())
        .part("file", file_part);
    if transcription_supports_logprobs(&config.transcription_model) {
        form = form.text("include[]", "logprobs");
    }
    if let Some(lang) = language {
        if !lang.trim().is_empty() {
            form = form.text("language", lang.trim().to_string());
        }
    }

    let client = reqwest::Client::new();
    let mut request = client.post(api_url).multipart(form);

    if let Some(api_key) = &config.transcription_api_key {
        request = request.bearer_auth(api_key);
    }

    let response = request.send().await.map_err(|e| {
        parse_provider_status(
            None,
            None,
            &format!("Failed to call transcription provider: {}", e),
            e.is_timeout(),
        )
    })?;

    let status = response.status();
    let retry_after_header = response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());
    let body = response.text().await.map_err(|e| {
        parse_provider_status(
            Some(status.as_u16()),
            retry_after_header.as_deref(),
            &format!("Failed to read transcription response: {}", e),
            e.is_timeout(),
        )
    })?;

    if !status.is_success() {
        return Err(parse_provider_status(
            Some(status.as_u16()),
            retry_after_header.as_deref(),
            &body,
            false,
        ));
    }

    Ok(body)
}

/// Call a configured transcription provider and return raw response text.
async fn transcribe_audio_via_provider(
    config: &Config,
    audio_path: &Path,
    language: Option<&str>,
) -> std::result::Result<String, ProviderError> {
    let started = Instant::now();
    let mut attempt: u32 = 0;

    loop {
        match transcribe_audio_via_provider_once(config, audio_path, language).await {
            Ok(body) => return Ok(body),
            Err(failure) if !is_retryable_provider_failure(&failure) => {
                return Err(ProviderError {
                    failure,
                    exhausted_retryable: false,
                    attempts: attempt.saturating_add(1),
                });
            }
            Err(failure) => {
                if attempt >= config.transcription_max_retries {
                    return Err(ProviderError {
                        failure,
                        exhausted_retryable: true,
                        attempts: attempt.saturating_add(1),
                    });
                }

                let delay = retry_delay_for_attempt(
                    attempt,
                    config.transcription_retry_base_ms,
                    config.transcription_retry_max_ms,
                    failure.retry_after,
                    retry_jitter_ratio(),
                );
                let waited_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
                let next_wait_ms = delay.as_millis().min(u64::MAX as u128) as u64;
                if waited_ms.saturating_add(next_wait_ms) > config.transcription_retry_total_ms {
                    return Err(ProviderError {
                        failure,
                        exhausted_retryable: true,
                        attempts: attempt.saturating_add(1),
                    });
                }

                warn!(
                    attempt = attempt.saturating_add(1),
                    delay_ms = next_wait_ms,
                    retry_after_ms = failure
                        .retry_after
                        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64),
                    status_code = failure.status_code,
                    timed_out = failure.timed_out,
                    "Retrying transcription provider call"
                );
                tokio::time::sleep(delay).await;
                attempt = attempt.saturating_add(1);
            }
        }
    }
}

fn transcription_supports_logprobs(model: &str) -> bool {
    let model = model.trim().to_ascii_lowercase();
    model.contains("gpt-4o-mini-transcribe") || model.contains("gpt-4o-transcribe")
}

fn transcription_response_format(model: &str) -> &'static str {
    // OpenAI gpt-* transcribe models reject `response_format=vtt`.
    // `json` keeps compatibility; the response is normalized into VTT downstream.
    if transcription_supports_logprobs(model) {
        "json"
    } else {
        "vtt"
    }
}

/// Fetch a GCP access token from the metadata server (works on Cloud Run)
/// or fall back to `gcloud auth print-access-token` locally.
async fn fetch_gcp_access_token() -> std::result::Result<String, ProviderFailure> {
    let metadata_url =
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
    let client = reqwest::Client::new();
    let resp = client
        .get(metadata_url)
        .header("Metadata-Flavor", "Google")
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let body = r.text().await.map_err(|e| {
                parse_provider_status(
                    None,
                    None,
                    &format!("Failed to read metadata token: {}", e),
                    false,
                )
            })?;
            let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
                parse_provider_status(
                    None,
                    None,
                    &format!("Failed to parse metadata token: {}", e),
                    false,
                )
            })?;
            json["access_token"]
                .as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    parse_provider_status(
                        None,
                        None,
                        "No access_token in metadata response",
                        false,
                    )
                })
        }
        _ => {
            // Fallback: try gcloud CLI for local development
            let output = tokio::process::Command::new("gcloud")
                .args(["auth", "print-access-token"])
                .output()
                .await
                .map_err(|e| {
                    parse_provider_status(
                        None,
                        None,
                        &format!("gcloud auth failed: {}", e),
                        false,
                    )
                })?;
            if output.status.success() {
                Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
            } else {
                Err(parse_provider_status(
                    None,
                    None,
                    "Failed to get GCP access token (no metadata server, gcloud failed)",
                    false,
                ))
            }
        }
    }
}

/// Transcribe audio using Gemini via Vertex AI generateContent.
/// Returns raw JSON text with segments and timestamps.
async fn transcribe_via_gemini(
    config: &Config,
    audio_path: &Path,
    _language: Option<&str>,
) -> std::result::Result<String, ProviderFailure> {
    let audio_bytes = tokio::fs::read(audio_path).await.map_err(|e| {
        parse_provider_status(
            None,
            None,
            &format!("Failed to read audio: {}", e),
            false,
        )
    })?;
    let audio_b64 = base64::engine::general_purpose::STANDARD.encode(&audio_bytes);

    let access_token = fetch_gcp_access_token().await?;

    let url = format!(
        "https://{}-aiplatform.googleapis.com/v1/projects/{}/locations/{}/publishers/google/models/{}:generateContent",
        config.gcp_region, config.gcp_project_id, config.gcp_region, config.transcription_model,
    );

    let body = serde_json::json!({
        "contents": [{
            "role": "user",
            "parts": [
                {"text": "Transcribe this audio. Return every spoken segment with start and end timestamps in seconds and the text. If there is no speech, return an empty segments array."},
                {"inlineData": {"mimeType": "audio/wav", "data": audio_b64}}
            ]
        }],
        "generationConfig": {
            "audioTimestamp": true,
            "responseMimeType": "application/json",
            "responseSchema": {
                "type": "object",
                "properties": {
                    "language": {"type": "string"},
                    "segments": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "start": {"type": "number"},
                                "end": {"type": "number"},
                                "text": {"type": "string"}
                            }
                        }
                    }
                }
            }
        }
    });

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .bearer_auth(&access_token)
        .json(&body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| {
            parse_provider_status(
                None,
                None,
                &format!("Failed to call Vertex AI: {}", e),
                e.is_timeout(),
            )
        })?;

    let status = response.status();
    let retry_after_header = response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());
    let resp_body = response.text().await.map_err(|e| {
        parse_provider_status(
            Some(status.as_u16()),
            retry_after_header.as_deref(),
            &format!("Failed to read Vertex AI response: {}", e),
            e.is_timeout(),
        )
    })?;

    if !status.is_success() {
        return Err(parse_provider_status(
            Some(status.as_u16()),
            retry_after_header.as_deref(),
            &resp_body,
            false,
        ));
    }

    // Extract text from Vertex AI response: candidates[0].content.parts[0].text
    let resp_json: serde_json::Value = serde_json::from_str(&resp_body).map_err(|e| {
        parse_provider_status(
            None,
            None,
            &format!("Invalid Vertex AI JSON: {}", e),
            false,
        )
    })?;

    resp_json["candidates"][0]["content"]["parts"][0]["text"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| {
            parse_provider_status(
                None,
                None,
                &format!("No text in Vertex AI response: {}", resp_body),
                false,
            )
        })
}

/// Normalize transcription output to WebVTT and collect summary metadata.
fn normalize_transcript_to_vtt(raw: &str) -> Result<ParsedVtt> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Transcription output is empty"));
    }

    if trimmed.starts_with("WEBVTT") {
        let normalized = format!("{}\n", trimmed.trim_end());
        let (cue_count, duration_ms) = summarize_vtt(&normalized);
        return Ok(ParsedVtt {
            content: normalized,
            text: extract_text_from_vtt(trimmed),
            language: None,
            duration_ms,
            cue_count,
            confidence: None,
        });
    }

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(trimmed) {
        let mut parsed_language = json["language"].as_str().map(|s| s.to_string());
        let confidence = extract_transcript_confidence(&json);

        if let Some(segments) = json["segments"].as_array() {
            let mut vtt = String::from("WEBVTT\n\n");
            let mut cue_index: usize = 1;
            let mut last_end_secs = 0.0_f64;
            let mut text_parts: Vec<String> = Vec::new();

            for segment in segments {
                let start = segment["start"]
                    .as_f64()
                    .or_else(|| {
                        segment["start"]
                            .as_str()
                            .and_then(|s| s.parse::<f64>().ok())
                    })
                    .unwrap_or(0.0);
                let end = segment["end"]
                    .as_f64()
                    .or_else(|| segment["end"].as_str().and_then(|s| s.parse::<f64>().ok()))
                    .unwrap_or(start + 1.0);
                let text = segment["text"]
                    .as_str()
                    .or_else(|| segment["transcript"].as_str())
                    .unwrap_or("")
                    .trim();
                if parsed_language.is_none() {
                    parsed_language = segment["language"].as_str().map(|s| s.to_string());
                }

                if text.is_empty() {
                    continue;
                }

                text_parts.push(text.to_string());
                let end_secs = end.max(start + 0.001);
                last_end_secs = last_end_secs.max(end_secs);

                vtt.push_str(&format!(
                    "{}\n{} --> {}\n{}\n\n",
                    cue_index,
                    format_vtt_timestamp(start),
                    format_vtt_timestamp(end_secs),
                    text
                ));
                cue_index += 1;
            }

            if cue_index > 1 {
                return Ok(ParsedVtt {
                    content: vtt,
                    text: text_parts.join(" "),
                    language: parsed_language,
                    duration_ms: (last_end_secs * 1000.0).round() as u64,
                    cue_count: (cue_index - 1) as u32,
                    confidence,
                });
            }
        }

        if let Some(text) = json["text"].as_str() {
            let merged = text
                .split('\n')
                .map(|line| line.trim())
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            if !merged.is_empty() {
                return Ok(ParsedVtt {
                    content: format!("WEBVTT\n\n1\n00:00:00.000 --> 99:59:59.000\n{}\n", merged),
                    text: merged,
                    language: parsed_language,
                    duration_ms: 0,
                    cue_count: 1,
                    confidence,
                });
            }
        }
    }

    // If we parsed valid JSON but found no segments and no text,
    // this is a valid API response with no transcribable content (e.g. silent video).
    // Don't let it fall through to the plain text path, which would wrap the raw
    // JSON string in a VTT cue and render it as captions.
    if serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
        return Err(anyhow!("Transcription response contained no usable text"));
    }

    // Plain text fallback when the provider does not return timestamps.
    let merged = trimmed
        .split('\n')
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");

    if merged.is_empty() {
        return Err(anyhow!("Transcription output had no usable text"));
    }

    Ok(ParsedVtt {
        content: format!("WEBVTT\n\n1\n00:00:00.000 --> 99:59:59.000\n{}\n", merged),
        text: merged,
        language: None,
        duration_ms: 0,
        cue_count: 1,
        confidence: None,
    })
}

fn extract_transcript_confidence(json: &serde_json::Value) -> Option<TranscriptConfidence> {
    let mut logprobs = Vec::new();
    collect_logprob_values(json, &mut logprobs);
    TranscriptConfidence::from_logprobs(&logprobs)
}

fn collect_logprob_values(value: &serde_json::Value, out: &mut Vec<f64>) {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                collect_logprob_values(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            if let Some(logprob) = map.get("logprob").and_then(|v| v.as_f64()) {
                out.push(logprob);
            }
            for child in map.values() {
                collect_logprob_values(child, out);
            }
        }
        _ => {}
    }
}

fn extract_text_from_vtt(vtt: &str) -> String {
    vtt.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.eq_ignore_ascii_case("WEBVTT"))
        .filter(|line| !line.contains("-->"))
        .filter(|line| !line.chars().all(|c| c.is_ascii_digit()))
        .collect::<Vec<_>>()
        .join(" ")
}

fn should_drop_low_signal_transcript(audio: &AudioAnalysis, parsed_vtt: &ParsedVtt) -> bool {
    if parsed_vtt.text.trim().is_empty() || !audio.is_low_signal() {
        return false;
    }

    let normalized = parsed_vtt
        .text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    let normalized_words_only = normalized
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch.is_ascii_whitespace() {
                ch
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let word_count = normalized.split_whitespace().count();
    let short_transcript = parsed_vtt.cue_count <= 2 || word_count <= 12;
    let has_url = normalized.contains("http://")
        || normalized.contains("https://")
        || normalized.contains("www.")
        || normalized.contains(".com")
        || normalized.contains(".net")
        || normalized.contains(".org")
        || normalized.contains(".io");
    let has_outro_phrase = [
        "thank you for watching",
        "thanks for watching",
        "subscribe",
        "follow for more",
        "see you next time",
        "visit our website",
        "links in the description",
    ]
    .iter()
    .any(|phrase| normalized.contains(phrase));
    let is_trivial_courtesy_phrase = [
        "thank you",
        "thank you so much",
        "thanks",
        "thanks so much",
        "okay",
        "ok",
        "bye",
        "goodbye",
    ]
    .iter()
    .any(|phrase| normalized_words_only == *phrase);

    short_transcript && (has_url || has_outro_phrase || is_trivial_courtesy_phrase)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TranscriptDropReason {
    LowProviderConfidence,
    LowSignalHeuristic,
}

fn transcript_drop_reason(
    audio: &AudioAnalysis,
    parsed_vtt: &ParsedVtt,
) -> Option<TranscriptDropReason> {
    if parsed_vtt.text.trim().is_empty() {
        return None;
    }

    if parsed_vtt
        .confidence
        .map(|confidence| confidence.is_low_confidence())
        .unwrap_or(false)
    {
        return Some(TranscriptDropReason::LowProviderConfidence);
    }

    if should_drop_low_signal_transcript(audio, parsed_vtt) {
        return Some(TranscriptDropReason::LowSignalHeuristic);
    }

    None
}

async fn finalize_transcript(
    state: &AppState,
    hash: &str,
    job_id: Option<&str>,
    requested_lang: Option<&str>,
    parsed_vtt: ParsedVtt,
    vtt_path: &str,
) -> Result<TranscribeResponse> {
    if let Err(e) = upload_transcript_to_gcs(
        &state.gcs_client,
        &state.config.gcs_bucket,
        hash,
        &parsed_vtt.content,
    )
    .await
    {
        send_transcript_status_webhook(
            &state.config,
            hash,
            "failed",
            job_id,
            requested_lang,
            Some(parsed_vtt.duration_ms),
            Some(parsed_vtt.cue_count),
            parsed_vtt.confidence,
            None,
            Some("upload_failed"),
            Some(&e.to_string()),
            false,
        )
        .await;
        return Err(e);
    }

    send_transcript_status_webhook(
        &state.config,
        hash,
        "complete",
        job_id,
        parsed_vtt.language.as_deref().or(requested_lang),
        Some(parsed_vtt.duration_ms),
        Some(parsed_vtt.cue_count),
        parsed_vtt.confidence,
        None,
        None,
        None,
        false,
    )
    .await;

    Ok(TranscribeResponse {
        hash: hash.to_string(),
        status: "complete".to_string(),
        vtt_path: vtt_path.to_string(),
        transcript_confidence: parsed_vtt.confidence,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        build_transcode_status_webhook_payload, classify_audio_extract_error,
        decide_transcript_lock_action, is_retryable_provider_failure, normalize_transcript_to_vtt,
        parse_audio_analysis_output, parse_provider_status, retry_delay_for_attempt,
        should_drop_low_signal_transcript, transcript_drop_reason, transcription_response_format,
        AudioAnalysis, AudioExtractErrorKind, Config, ParsedVtt, TranscriptConfidence,
        TranscriptDropReason, TranscriptLockAction, TranscriptLockState, TranscriptLockStatus,
        VideoInfo,
    };
    use std::time::Duration;

    #[test]
    fn gpt_transcribe_uses_json_response_format() {
        assert_eq!(
            transcription_response_format("gpt-4o-mini-transcribe"),
            "json"
        );
        assert_eq!(transcription_response_format("gpt-4o-transcribe"), "json");
    }

    #[test]
    fn whisper_uses_vtt_response_format() {
        assert_eq!(transcription_response_format("whisper-1"), "vtt");
    }

    #[test]
    fn classifies_audio_extract_errors() {
        assert_eq!(
            classify_audio_extract_error("not_a_video"),
            AudioExtractErrorKind::NotAVideo
        );
        assert_eq!(
            classify_audio_extract_error("no_audio_track"),
            AudioExtractErrorKind::NoAudioTrack
        );
        assert_eq!(
            classify_audio_extract_error("ffmpeg exploded"),
            AudioExtractErrorKind::Other
        );
    }

    #[test]
    fn transcode_webhook_payload_includes_failure_fields() {
        let video_info = VideoInfo {
            width: 1920,
            height: 1080,
            rotation: 0,
            display_width: 1080,
            display_height: 1920,
            has_audio: true,
        };

        let payload = build_transcode_status_webhook_payload(
            "abc123",
            "failed",
            Some(42),
            Some(&video_info),
            Some("invalid_media"),
            Some("moov atom not found"),
            Some(30),
            true,
        );

        assert_eq!(payload["sha256"], "abc123");
        assert_eq!(payload["status"], "failed");
        assert_eq!(payload["new_size"], 42);
        assert_eq!(payload["display_width"], 1080);
        assert_eq!(payload["display_height"], 1920);
        assert_eq!(payload["error_code"], "invalid_media");
        assert_eq!(payload["error_message"], "moov atom not found");
        assert_eq!(payload["retry_after"], 30);
        assert_eq!(payload["terminal"], true);
    }

    #[test]
    fn transcode_webhook_payload_omits_optional_failure_fields_when_absent() {
        let payload = build_transcode_status_webhook_payload(
            "abc123",
            "processing",
            None,
            None,
            None,
            None,
            None,
            false,
        );

        assert_eq!(payload["sha256"], "abc123");
        assert_eq!(payload["status"], "processing");
        assert!(payload.get("new_size").is_none());
        assert!(payload.get("display_width").is_none());
        assert!(payload.get("display_height").is_none());
        assert!(payload.get("error_code").is_none());
        assert!(payload.get("error_message").is_none());
        assert!(payload.get("retry_after").is_none());
        assert!(payload.get("terminal").is_none());
    }

    #[test]
    fn extracts_confidence_from_json_logprobs() {
        let parsed = normalize_transcript_to_vtt(
            r#"{
                "text": "hello there",
                "language": "en",
                "logprobs": [
                    {"token": "hello", "logprob": -0.05},
                    {"token": "there", "logprob": -0.20}
                ]
            }"#,
        )
        .expect("json transcript should parse");

        let confidence = parsed.confidence.expect("confidence should be present");
        assert_eq!(confidence.token_count, 2);
        assert!(confidence.average_token_confidence > 0.85);
        assert!(confidence.average_logprob > -0.2);
        assert_eq!(confidence.low_confidence_token_ratio, 0.0);
    }

    #[test]
    fn audio_analysis_parses_silence_and_volume() {
        let stderr = r#"
[silencedetect @ 0x1] silence_start: 0
[silencedetect @ 0x1] silence_end: 9.9 | silence_duration: 9.9
[Parsed_volumedetect_1 @ 0x2] mean_volume: -58.3 dB
[Parsed_volumedetect_1 @ 0x2] max_volume: -34.7 dB
"#;
        let analysis = parse_audio_analysis_output(stderr, 10_000);
        assert_eq!(analysis.silent_duration_ms, 9_900);
        assert_eq!(analysis.mean_volume_db, Some(-58.3));
        assert_eq!(analysis.max_volume_db, Some(-34.7));
        assert!(analysis.is_effectively_silent());
    }

    #[test]
    fn treats_mostly_silent_very_quiet_audio_as_effectively_silent() {
        let analysis = AudioAnalysis {
            duration_ms: 6_303,
            silent_duration_ms: 6_037,
            mean_volume_db: Some(-48.3),
            max_volume_db: Some(-31.7),
        };

        assert!(analysis.is_effectively_silent());
    }

    #[test]
    fn drops_common_hallucination_when_audio_is_low_signal() {
        let analysis = AudioAnalysis {
            duration_ms: 20_000,
            silent_duration_ms: 19_000,
            mean_volume_db: Some(-52.0),
            max_volume_db: Some(-31.0),
        };
        let parsed_vtt = ParsedVtt {
            content: "WEBVTT\n\n1\n00:00:00.000 --> 00:00:03.000\nThank you for watching\n"
                .to_string(),
            text: "Thank you for watching".to_string(),
            language: None,
            duration_ms: 3_000,
            cue_count: 1,
            confidence: None,
        };

        assert!(should_drop_low_signal_transcript(&analysis, &parsed_vtt));
    }

    #[test]
    fn drops_trivial_courtesy_phrase_when_audio_is_low_signal() {
        let analysis = AudioAnalysis {
            duration_ms: 6_303,
            silent_duration_ms: 6_037,
            mean_volume_db: Some(-48.3),
            max_volume_db: Some(-31.7),
        };
        let parsed_vtt = ParsedVtt {
            content: "WEBVTT\n\n1\n00:00:00.000 --> 00:00:05.000\nThank you.\n".to_string(),
            text: "Thank you.".to_string(),
            language: None,
            duration_ms: 5_000,
            cue_count: 1,
            confidence: None,
        };

        assert!(should_drop_low_signal_transcript(&analysis, &parsed_vtt));
    }

    #[test]
    fn keeps_real_transcript_when_audio_has_signal() {
        let analysis = AudioAnalysis {
            duration_ms: 20_000,
            silent_duration_ms: 2_000,
            mean_volume_db: Some(-20.0),
            max_volume_db: Some(-3.0),
        };
        let parsed_vtt = ParsedVtt {
            content:
                "WEBVTT\n\n1\n00:00:00.000 --> 00:00:03.000\nthank you for watching this demo\n"
                    .to_string(),
            text: "thank you for watching this demo".to_string(),
            language: None,
            duration_ms: 3_000,
            cue_count: 1,
            confidence: None,
        };

        assert!(!should_drop_low_signal_transcript(&analysis, &parsed_vtt));
    }

    #[test]
    fn drops_low_confidence_transcript_even_with_audio_signal() {
        let analysis = AudioAnalysis {
            duration_ms: 6_000,
            silent_duration_ms: 0,
            mean_volume_db: Some(-18.0),
            max_volume_db: Some(-2.0),
        };
        let parsed_vtt = ParsedVtt {
            content: "WEBVTT\n\n1\n00:00:00.000 --> 00:00:05.000\nrandom guess\n".to_string(),
            text: "random guess".to_string(),
            language: Some("en".to_string()),
            duration_ms: 5_000,
            cue_count: 1,
            confidence: Some(TranscriptConfidence {
                average_token_confidence: 0.31,
                average_logprob: -1.28,
                low_confidence_token_ratio: 1.0,
                token_count: 2,
            }),
        };

        assert_eq!(
            transcript_drop_reason(&analysis, &parsed_vtt),
            Some(TranscriptDropReason::LowProviderConfidence)
        );
    }

    #[test]
    fn classifies_rate_limited_provider_responses_as_retryable() {
        let failure = parse_provider_status(Some(429), Some("12"), "rate limit exceeded", false);

        assert_eq!(failure.status_code, Some(429));
        assert_eq!(failure.retry_after, Some(Duration::from_secs(12)));
        assert_eq!(failure.body, "rate limit exceeded");
        assert!(is_retryable_provider_failure(&failure));
    }

    #[test]
    fn classifies_transient_5xx_provider_responses_as_retryable() {
        for status in [500, 502, 503, 504] {
            let failure = parse_provider_status(Some(status), None, "temporary failure", false);

            assert_eq!(failure.status_code, Some(status));
            assert!(is_retryable_provider_failure(&failure));
        }
    }

    #[test]
    fn classifies_bad_request_provider_responses_as_non_retryable() {
        let failure = parse_provider_status(Some(400), None, "invalid request", false);

        assert_eq!(failure.status_code, Some(400));
        assert!(!is_retryable_provider_failure(&failure));
    }

    #[test]
    fn caps_exponential_backoff_at_maximum_delay() {
        assert_eq!(
            retry_delay_for_attempt(0, 1_000, 5_000, None, 0.0),
            Duration::from_millis(750)
        );
        assert_eq!(
            retry_delay_for_attempt(3, 1_000, 5_000, None, 0.0),
            Duration::from_millis(5_000)
        );
        assert_eq!(
            retry_delay_for_attempt(2, 1_000, 5_000, Some(Duration::from_secs(10)), 0.0),
            Duration::from_millis(5_000)
        );
    }

    #[test]
    fn config_defaults_provider_retry_settings() {
        let config = Config::from_lookup(|_| None);

        assert_eq!(config.transcription_max_in_flight, 4);
        assert_eq!(config.transcription_max_retries, 3);
        assert_eq!(config.transcription_retry_base_ms, 1_000);
        assert_eq!(config.transcription_retry_max_ms, 15_000);
    }

    #[test]
    fn config_parses_provider_retry_settings_from_env() {
        let config = Config::from_lookup(|key| match key {
            "TRANSCRIPTION_MAX_IN_FLIGHT" => Some("7".to_string()),
            "TRANSCRIPTION_MAX_RETRIES" => Some("5".to_string()),
            "TRANSCRIPTION_RETRY_BASE_MS" => Some("250".to_string()),
            "TRANSCRIPTION_RETRY_MAX_MS" => Some("4000".to_string()),
            _ => None,
        });

        assert_eq!(config.transcription_max_in_flight, 7);
        assert_eq!(config.transcription_max_retries, 5);
        assert_eq!(config.transcription_retry_base_ms, 250);
        assert_eq!(config.transcription_retry_max_ms, 4_000);
    }

    #[test]
    fn lock_state_without_existing_lock_starts_work() {
        assert_eq!(
            decide_transcript_lock_action(1_000, None, 600),
            TranscriptLockAction::StartWork
        );
    }

    #[test]
    fn lock_state_with_fresh_processing_lock_returns_already_processing() {
        let existing = TranscriptLockState {
            status: TranscriptLockStatus::Processing,
            started_at_epoch_secs: 1_000,
            cooldown_until_epoch_secs: None,
            error_code: None,
        };

        assert_eq!(
            decide_transcript_lock_action(1_300, Some(&existing), 600),
            TranscriptLockAction::AlreadyProcessing
        );
    }

    #[test]
    fn lock_state_with_stale_processing_lock_can_be_reclaimed() {
        let existing = TranscriptLockState {
            status: TranscriptLockStatus::Processing,
            started_at_epoch_secs: 1_000,
            cooldown_until_epoch_secs: None,
            error_code: None,
        };

        assert_eq!(
            decide_transcript_lock_action(1_700, Some(&existing), 600),
            TranscriptLockAction::ReclaimStaleLock
        );
    }

    #[test]
    fn empty_text_json_response_is_rejected_not_rendered() {
        // Whisper returns this for silent videos. The raw JSON must not
        // fall through to the plain text path and become a VTT cue.
        let result = normalize_transcript_to_vtt(
            r#"{"text":"","usage":{"type":"tokens","total_tokens":52,"input_tokens":50,"input_token_details":{"text_tokens":0,"audio_tokens":50},"output_tokens":2}}"#,
        );
        assert!(result.is_err(), "empty-text JSON should be rejected");
    }

    #[test]
    fn empty_segments_json_response_is_rejected() {
        // gpt-4o-transcribe with no speech: segments array present but empty
        let result = normalize_transcript_to_vtt(r#"{"text":"","language":"en","segments":[]}"#);
        assert!(result.is_err(), "empty-segments JSON should be rejected");
    }

    #[test]
    fn json_with_only_whitespace_text_is_rejected() {
        let result = normalize_transcript_to_vtt(r#"{"text":"   \n  "}"#);
        assert!(
            result.is_err(),
            "whitespace-only text JSON should be rejected"
        );
    }

    #[test]
    fn json_with_null_text_is_rejected() {
        let result = normalize_transcript_to_vtt(r#"{"text":null,"language":"en"}"#);
        assert!(result.is_err(), "null-text JSON should be rejected");
    }

    #[test]
    fn json_with_no_text_field_is_rejected() {
        // API error response or malformed output
        let result = normalize_transcript_to_vtt(
            r#"{"error":{"message":"Invalid file format","type":"invalid_request_error"}}"#,
        );
        assert!(result.is_err(), "error JSON should be rejected");
    }

    #[test]
    fn json_with_text_is_still_accepted() {
        let parsed = normalize_transcript_to_vtt(r#"{"text":"hello world"}"#)
            .expect("json with text should parse");
        assert!(parsed.content.starts_with("WEBVTT"));
        assert_eq!(parsed.text, "hello world");
    }

    #[test]
    fn json_with_segments_is_still_accepted() {
        let parsed = normalize_transcript_to_vtt(
            r#"{"text":"hello there","language":"en","segments":[{"start":0.0,"end":1.5,"text":"hello there"}]}"#,
        )
        .expect("json with segments should parse");
        assert!(parsed.content.starts_with("WEBVTT"));
        assert!(parsed.content.contains("hello there"));
        assert_eq!(parsed.cue_count, 1);
    }

    #[test]
    fn valid_vtt_passthrough_still_works() {
        let vtt = "WEBVTT\n\n1\n00:00:00.000 --> 00:00:02.000\nHello\n";
        let parsed = normalize_transcript_to_vtt(vtt).expect("valid VTT should pass through");
        assert!(parsed.content.starts_with("WEBVTT"));
        assert_eq!(parsed.text, "Hello");
    }

    #[test]
    fn plain_text_input_still_works() {
        let parsed = normalize_transcript_to_vtt("This is spoken text from the video")
            .expect("plain text should still work");
        assert!(parsed.content.starts_with("WEBVTT"));
        assert_eq!(parsed.text, "This is spoken text from the video");
    }
}

fn summarize_vtt(vtt: &str) -> (u32, u64) {
    let mut cues: u32 = 0;
    let mut max_end_ms: u64 = 0;
    for line in vtt.lines() {
        if !line.contains("-->") {
            continue;
        }
        cues = cues.saturating_add(1);
        let parts: Vec<&str> = line.split("-->").collect();
        if parts.len() != 2 {
            continue;
        }
        if let Some(end_ms) = parse_vtt_timestamp_ms(parts[1].trim()) {
            max_end_ms = max_end_ms.max(end_ms);
        }
    }
    (cues, max_end_ms)
}

fn parse_vtt_timestamp_ms(input: &str) -> Option<u64> {
    let parts: Vec<&str> = input.trim().split(':').collect();
    if parts.len() != 3 {
        return None;
    }

    let hours: u64 = parts[0].trim().parse().ok()?;
    let minutes: u64 = parts[1].trim().parse().ok()?;
    let sec_parts: Vec<&str> = parts[2].trim().split('.').collect();
    if sec_parts.len() != 2 {
        return None;
    }
    let seconds: u64 = sec_parts[0].trim().parse().ok()?;
    let millis: u64 = sec_parts[1].trim().parse().ok()?;

    Some((((hours * 60 + minutes) * 60 + seconds) * 1000) + millis)
}

fn format_vtt_timestamp(seconds: f64) -> String {
    let total_ms = (seconds.max(0.0) * 1000.0).round() as u64;
    let ms = total_ms % 1000;
    let total_seconds = total_ms / 1000;
    let s = total_seconds % 60;
    let total_minutes = total_seconds / 60;
    let m = total_minutes % 60;
    let h = total_minutes / 60;
    format!("{:02}:{:02}:{:02}.{:03}", h, m, s, ms)
}

async fn upload_transcript_to_gcs(
    client: &GcsClient,
    bucket: &str,
    hash: &str,
    vtt_content: &str,
) -> Result<()> {
    let gcs_path = format!("{}/vtt/main.vtt", hash);
    let mut media = Media::new(gcs_path.clone());
    media.content_type = "text/vtt".into();
    let upload_type = UploadType::Simple(media);

    let req = UploadObjectRequest {
        bucket: bucket.to_string(),
        ..Default::default()
    };

    client
        .upload_object(
            &req,
            Bytes::from(vtt_content.as_bytes().to_vec()),
            &upload_type,
        )
        .await
        .map_err(|e| anyhow!("Failed to upload transcript {}: {}", gcs_path, e))?;

    info!("Uploaded transcript {}", gcs_path);
    Ok(())
}

/// Probe video file with ffprobe to get dimensions and rotation metadata
async fn probe_video(input_path: &Path) -> Result<VideoInfo> {
    let input_str = input_path.to_string_lossy();

    let output = Command::new("ffprobe")
        .args([
            "-v",
            "quiet",
            "-print_format",
            "json",
            "-show_streams",
            "-select_streams",
            "v:0",
            &input_str,
        ])
        .output()
        .await
        .map_err(|e| anyhow!("Failed to run ffprobe: {}", e))?;

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
        return Err(anyhow!(
            "Could not determine video dimensions: {}x{}",
            width,
            height
        ));
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
                    // rotation can be a number or string in ffprobe output
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

    let rotation_abs = rotation.unsigned_abs();
    // Normalize to 0, 90, 180, 270
    let rotation_abs = match rotation_abs % 360 {
        r @ (0 | 90 | 180 | 270) => r,
        r if r > 315 || r < 45 => 0,
        r if r >= 45 && r < 135 => 90,
        r if r >= 135 && r < 225 => 180,
        _ => 270,
    };

    // Compute display dimensions (after applying rotation)
    let (display_width, display_height) = if rotation_abs == 90 || rotation_abs == 270 {
        (height, width)
    } else {
        (width, height)
    };

    // Check for audio streams with a second ffprobe call
    let has_audio = check_has_audio(input_path).await;

    info!(
        "Video probe: raw={}x{}, rotation={}, display={}x{}, has_audio={}",
        width, height, rotation_abs, display_width, display_height, has_audio
    );

    Ok(VideoInfo {
        width,
        height,
        rotation: rotation_abs,
        display_width,
        display_height,
        has_audio,
    })
}

/// Check if the video file has an audio stream
async fn check_has_audio(input_path: &Path) -> bool {
    let input_str = input_path.to_string_lossy();
    let output = Command::new("ffprobe")
        .args([
            "-v",
            "quiet",
            "-print_format",
            "json",
            "-show_streams",
            "-select_streams",
            "a:0",
            &input_str,
        ])
        .output()
        .await;

    match output {
        Ok(out) if out.status.success() => {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                json["streams"]
                    .as_array()
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
            } else {
                true // assume audio exists if parse fails (safe default)
            }
        }
        _ => true, // assume audio exists if probe fails (safe default)
    }
}

/// Compute target scale dimensions that fit within a bounding box while preserving aspect ratio.
/// Returns (target_width, target_height) with both values even (required by h264).
fn compute_scale_dimensions(
    display_width: u32,
    display_height: u32,
    max_long: u32,
    max_short: u32,
) -> (u32, u32) {
    let is_portrait = display_height > display_width;

    let (max_w, max_h) = if is_portrait {
        (max_short, max_long)
    } else {
        (max_long, max_short)
    };

    // Scale to fit within max_w x max_h while maintaining aspect ratio
    let scale_w = max_w as f64 / display_width as f64;
    let scale_h = max_h as f64 / display_height as f64;
    let scale = scale_w.min(scale_h).min(1.0); // Don't upscale

    // Round to even numbers (h264 requirement)
    let target_w = (((display_width as f64 * scale).round() as u32) + 1) & !1;
    let target_h = (((display_height as f64 * scale).round() as u32) + 1) & !1;

    (target_w.max(2), target_h.max(2))
}

async fn run_ffmpeg_hls(
    input_path: &Path,
    output_dir: &Path,
    use_gpu: bool,
    video_info: &VideoInfo,
) -> Result<Vec<HlsVariant>> {
    let input_str = input_path.to_string_lossy();
    let output_pattern = output_dir.join("stream_%v.m3u8");
    let master_playlist = output_dir.join("master.m3u8");

    // Compute orientation-aware target dimensions
    let (w_720, h_720) = compute_scale_dimensions(
        video_info.display_width,
        video_info.display_height,
        1280,
        720,
    );
    let (w_480, h_480) = compute_scale_dimensions(
        video_info.display_width,
        video_info.display_height,
        854,
        480,
    );
    let has_rotation = video_info.rotation == 90 || video_info.rotation == 270;

    info!(
        "Scale targets: 720p={}x{}, 480p={}x{}, has_rotation={}",
        w_720, h_720, w_480, h_480, has_rotation
    );

    // GPU path cannot handle rotation (scale_cuda doesn't auto-rotate),
    // so fall back to CPU when rotation metadata is present
    let effective_gpu = use_gpu && !has_rotation;

    if has_rotation && use_gpu {
        warn!(
            "Video has {}° rotation - falling back to CPU encoding for correct orientation",
            video_info.rotation
        );
    }

    // Build FFmpeg command
    let mut cmd = Command::new("ffmpeg");
    cmd.arg("-y"); // Overwrite output

    if effective_gpu {
        // GPU-accelerated decoding with NVENC
        // -hwaccel cuda: Use CUDA for decoding
        // -hwaccel_output_format cuda: Keep frames in GPU memory
        cmd.args(["-hwaccel", "cuda", "-hwaccel_output_format", "cuda"]);
    }

    cmd.args(["-i", &input_str]);

    // Output mapping: create two video streams (720p, 480p), with audio if present
    if video_info.has_audio {
        cmd.args([
            "-map", "0:v:0", "-map", "0:a:0", // 720p with audio
            "-map", "0:v:0", "-map", "0:a:0", // 480p with audio
        ]);
    } else {
        cmd.args([
            "-map", "0:v:0", // 720p video only
            "-map", "0:v:0", // 480p video only
        ]);
    }

    // Build scale filter strings with computed dimensions.
    // For CPU path, use -2 for the non-constraining dimension so FFmpeg auto-computes
    // the exact value to preserve aspect ratio (rounded to even).
    // For GPU path (scale_cuda), we must specify both dimensions explicitly since
    // scale_cuda doesn't support -2.
    let is_portrait = video_info.display_height > video_info.display_width;

    let scale_720 = if effective_gpu {
        format!("scale_cuda={}:{}:interp_algo=lanczos", w_720, h_720)
    } else if is_portrait {
        // Portrait: constrain height to h_720, auto-compute width
        format!("scale=-2:{}", h_720)
    } else {
        // Landscape: constrain width to w_720, auto-compute height
        format!("scale={}:-2", w_720)
    };
    let scale_480 = if effective_gpu {
        format!("scale_cuda={}:{}:interp_algo=lanczos", w_480, h_480)
    } else if is_portrait {
        format!("scale=-2:{}", h_480)
    } else {
        format!("scale={}:-2", w_480)
    };

    if effective_gpu {
        cmd.args([
            // 720p variant
            "-filter:v:0",
            &scale_720,
            "-c:v:0",
            "h264_nvenc",
            "-profile:v:0",
            "main",
            "-level:v:0",
            "3.1",
            "-cq:v:0",
            "23",
            "-maxrate:v:0",
            "2500k",
            "-bufsize:v:0",
            "5000k",
            // 480p variant
            "-filter:v:1",
            &scale_480,
            "-c:v:1",
            "h264_nvenc",
            "-profile:v:1",
            "main",
            "-level:v:1",
            "3.0",
            "-cq:v:1",
            "23",
            "-maxrate:v:1",
            "1000k",
            "-bufsize:v:1",
            "2000k",
        ]);
    } else {
        // CPU encoding with libx264 (also used as fallback for rotated videos)
        cmd.args([
            // 720p variant
            "-filter:v:0",
            &scale_720,
            "-c:v:0",
            "libx264",
            "-profile:v:0",
            "main",
            "-level:v:0",
            "3.1",
            "-crf:v:0",
            "23",
            "-maxrate:v:0",
            "2500k",
            "-bufsize:v:0",
            "5000k",
            "-preset:v:0",
            "fast",
            "-bf:v:0",
            "0",
            // 480p variant
            "-filter:v:1",
            &scale_480,
            "-c:v:1",
            "libx264",
            "-profile:v:1",
            "main",
            "-level:v:1",
            "3.0",
            "-crf:v:1",
            "23",
            "-maxrate:v:1",
            "1000k",
            "-bufsize:v:1",
            "2000k",
            "-preset:v:1",
            "fast",
            "-bf:v:1",
            "0",
        ]);
    }

    // Audio encoding (only if audio stream exists)
    if video_info.has_audio {
        cmd.args(["-c:a", "aac", "-b:a:0", "128k", "-b:a:1", "96k"]);
    }

    // HLS output settings
    // -hls_time 10: 10 second segments (but for 6s clips, this means 1 segment)
    // -hls_playlist_type vod: VOD playlist (all segments available)
    // -hls_flags single_file: Put all segments in single .ts file (efficient for short clips)
    // -master_pl_name: Name of master playlist
    // -var_stream_map: Map variants to output streams
    let var_stream_map = if video_info.has_audio {
        "v:0,a:0,name:720p v:1,a:1,name:480p"
    } else {
        "v:0,name:720p v:1,name:480p"
    };

    cmd.args([
        "-f",
        "hls",
        "-hls_time",
        "10",
        "-hls_playlist_type",
        "vod",
        "-hls_flags",
        "single_file",
        "-master_pl_name",
        "master.m3u8",
        "-var_stream_map",
        var_stream_map,
        &output_pattern.to_string_lossy(),
    ]);

    info!("Running FFmpeg: {:?}", cmd);

    let output = cmd.output().await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("FFmpeg failed: {}", stderr);
        return Err(anyhow!("FFmpeg failed: {}", stderr));
    }

    // Verify outputs exist
    if !master_playlist.exists() {
        return Err(anyhow!("Master playlist not created"));
    }

    Ok(vec![
        HlsVariant {
            resolution: "720p".to_string(),
            playlist: "stream_720p.m3u8".to_string(),
            bandwidth: 2_500_000,
        },
        HlsVariant {
            resolution: "480p".to_string(),
            playlist: "stream_480p.m3u8".to_string(),
            bandwidth: 1_000_000,
        },
    ])
}

/// Remux HLS .ts files to regular MP4 with faststart for progressive download.
/// Video is copied without re-encoding. Audio is re-encoded to AAC-LC
/// because the ADTS-to-ASC bitstream filter produces invalid headers.
/// Uses regular MP4 (not fragmented) with moov at front — same approach as
/// TikTok/Instagram for short-form video delivery.
async fn remux_ts_to_fmp4(hls_dir: &Path) -> Result<()> {
    for variant in &["stream_720p", "stream_480p"] {
        let ts_path = hls_dir.join(format!("{}.ts", variant));
        let mp4_path = hls_dir.join(format!("{}.mp4", variant));

        if !ts_path.exists() {
            warn!("Skipping MP4 remux: {} not found", ts_path.display());
            continue;
        }

        let output = tokio::process::Command::new("ffmpeg")
            .args([
                "-y",
                "-v",
                "warning",
                "-i",
                &ts_path.to_string_lossy(),
                "-c:v",
                "copy",
                "-c:a",
                "aac",
                "-b:a",
                "128k",
                "-movflags",
                "+faststart",
                &mp4_path.to_string_lossy(),
            ])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("MP4 remux failed for {}: {}", variant, stderr);
            continue;
        }

        info!("Remuxed {} to MP4", variant);
    }

    Ok(())
}

async fn upload_hls_to_gcs(
    client: &GcsClient,
    bucket: &str,
    hash: &str,
    hls_dir: &Path,
    source_metadata: &SourceObjectMetadata,
) -> Result<()> {
    // Read directory and upload each file
    let mut entries = tokio::fs::read_dir(hls_dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let filename = path.file_name().unwrap().to_string_lossy();
        let gcs_path = format!("{}/hls/{}", hash, filename);

        // Determine content type
        let content_type = if filename.ends_with(".m3u8") {
            "application/vnd.apple.mpegurl"
        } else if filename.ends_with(".ts") {
            "video/mp2t"
        } else if filename.ends_with(".mp4") {
            "video/mp4"
        } else {
            "application/octet-stream"
        };

        // Read file
        let data = tokio::fs::read(&path).await?;

        // Upload to GCS
        let mut media = Media::new(gcs_path.clone());
        media.content_type = content_type.into();
        let upload_type = UploadType::Simple(media);

        let req = UploadObjectRequest {
            bucket: bucket.to_string(),
            ..Default::default()
        };

        client
            .upload_object(&req, Bytes::from(data), &upload_type)
            .await
            .map_err(|e| anyhow!("Failed to upload {}: {}", gcs_path, e))?;

        let mut derivative_metadata = source_metadata.custom.clone();
        derivative_metadata.insert("source_sha256".to_string(), hash.to_string());
        derivative_metadata.insert("derivative".to_string(), "hls".to_string());
        derivative_metadata.insert("hls_filename".to_string(), filename.to_string());
        if let Some(src_ct) = &source_metadata.content_type {
            derivative_metadata
                .entry("source_content_type".to_string())
                .or_insert_with(|| src_ct.clone());
        }

        let patch_req = PatchObjectRequest {
            bucket: bucket.to_string(),
            object: gcs_path.clone(),
            metadata: Some(Object {
                metadata: Some(derivative_metadata),
                cache_control: Some("public, max-age=31536000, immutable".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        if let Err(e) = client.patch_object(&patch_req).await {
            warn!("Failed to patch metadata for {}: {}", gcs_path, e);
        }

        info!("Uploaded {}", gcs_path);
    }

    Ok(())
}

async fn get_source_object_metadata(
    client: &GcsClient,
    bucket: &str,
    hash: &str,
) -> Result<SourceObjectMetadata> {
    let obj = client
        .get_object(&GetObjectRequest {
            bucket: bucket.to_string(),
            object: hash.to_string(),
            ..Default::default()
        })
        .await
        .map_err(|e| anyhow!("Failed to read source object metadata: {}", e))?;

    Ok(SourceObjectMetadata {
        content_type: obj.content_type,
        custom: obj.metadata.unwrap_or_default(),
    })
}

/// Send transcode status update to the Fastly edge webhook
/// This is fire-and-forget - failures are logged but don't fail the transcode
async fn send_status_webhook(
    config: &Config,
    hash: &str,
    status: &str,
    new_size: Option<u64>,
    video_info: Option<&VideoInfo>,
    error_code: Option<&str>,
    error_message: Option<&str>,
    retry_after_secs: Option<u64>,
    terminal: bool,
) {
    let webhook_url = match &config.webhook_url {
        Some(url) => url,
        None => {
            info!(
                "WEBHOOK_URL not configured, skipping status update for {}",
                hash
            );
            return;
        }
    };

    let client = reqwest::Client::new();
    let payload = build_transcode_status_webhook_payload(
        hash,
        status,
        new_size,
        video_info,
        error_code,
        error_message,
        retry_after_secs,
        terminal,
    );

    if let Some(size) = new_size {
        info!("Including new_size {} in webhook for {}", size, hash);
    }

    if let Some(info) = video_info {
        info!(
            "Including dimensions {}x{} in webhook for {}",
            info.display_width, info.display_height, hash
        );
    }

    let mut request = client.post(webhook_url).json(&payload);

    // Add auth header if secret is configured
    if let Some(secret) = &config.webhook_secret {
        request = request.header("Authorization", format!("Bearer {}", secret));
    }

    match request.send().await {
        Ok(response) => {
            if response.status().is_success() {
                info!("Status webhook sent for {}: {}", hash, status);
            } else {
                error!(
                    "Status webhook failed for {}: {} - {}",
                    hash,
                    response.status(),
                    response.text().await.unwrap_or_default()
                );
            }
        }
        Err(e) => {
            error!("Status webhook request failed for {}: {}", hash, e);
        }
    }
}

fn resolve_transcript_webhook_url(config: &Config) -> Option<String> {
    if let Some(url) = &config.transcript_webhook_url {
        return Some(url.clone());
    }

    if let Some(url) = &config.webhook_url {
        if let Some(prefix) = url.strip_suffix("/admin/transcode-status") {
            return Some(format!("{}/admin/transcript-status", prefix));
        }
    }

    None
}

fn build_transcode_status_webhook_payload(
    hash: &str,
    status: &str,
    new_size: Option<u64>,
    video_info: Option<&VideoInfo>,
    error_code: Option<&str>,
    error_message: Option<&str>,
    retry_after_secs: Option<u64>,
    terminal: bool,
) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "sha256": hash,
        "status": status
    });

    if let Some(size) = new_size {
        payload["new_size"] = serde_json::json!(size);
    }

    if let Some(info) = video_info {
        payload["display_width"] = serde_json::json!(info.display_width);
        payload["display_height"] = serde_json::json!(info.display_height);
    }

    if let Some(code) = error_code {
        payload["error_code"] = serde_json::json!(code);
    }

    if let Some(message) = error_message {
        payload["error_message"] = serde_json::json!(message);
    }

    if let Some(retry_after_secs) = retry_after_secs {
        payload["retry_after"] = serde_json::json!(retry_after_secs);
    }

    if terminal {
        payload["terminal"] = serde_json::json!(true);
    }

    payload
}

fn classify_invalid_media_error(
    message: &str,
    fallback_code: &'static str,
) -> (&'static str, bool) {
    let message = message.to_ascii_lowercase();
    if message.contains("moov atom not found")
        || message.contains("invalid data found when processing input")
        || message.contains("not_a_video")
        || message.contains("error reading header")
        || message.contains("could not find codec parameters")
    {
        ("invalid_media", true)
    } else {
        (fallback_code, false)
    }
}

/// Send transcript status update to the Fastly edge webhook.
async fn send_transcript_status_webhook(
    config: &Config,
    hash: &str,
    status: &str,
    job_id: Option<&str>,
    language: Option<&str>,
    duration_ms: Option<u64>,
    cue_count: Option<u32>,
    transcript_confidence: Option<TranscriptConfidence>,
    retry_after_secs: Option<u64>,
    error_code: Option<&str>,
    error_message: Option<&str>,
    terminal: bool,
) {
    let webhook_url = match resolve_transcript_webhook_url(config) {
        Some(url) => url,
        None => {
            info!(
                "TRANSCRIPT_WEBHOOK_URL not configured, skipping transcript status update for {}",
                hash
            );
            return;
        }
    };

    let client = reqwest::Client::new();
    let mut payload = serde_json::json!({
        "sha256": hash,
        "status": status
    });
    if let Some(id) = job_id {
        payload["job_id"] = serde_json::json!(id);
    }
    if let Some(lang) = language {
        payload["language"] = serde_json::json!(lang);
    }
    if let Some(ms) = duration_ms {
        payload["duration_ms"] = serde_json::json!(ms);
    }
    if let Some(cues) = cue_count {
        payload["cue_count"] = serde_json::json!(cues);
    }
    if let Some(confidence) = transcript_confidence {
        payload["transcript_confidence"] = serde_json::json!(confidence);
    }
    if let Some(retry_after_secs) = retry_after_secs {
        payload["retry_after"] = serde_json::json!(retry_after_secs);
    }
    if let Some(code) = error_code {
        payload["error_code"] = serde_json::json!(code);
    }
    if let Some(msg) = error_message {
        payload["error_message"] = serde_json::json!(msg);
    }
    if terminal {
        payload["terminal"] = serde_json::json!(true);
    }

    let mut request = client.post(webhook_url).json(&payload);
    if let Some(secret) = &config.webhook_secret {
        request = request.header("Authorization", format!("Bearer {}", secret));
    }

    match request.send().await {
        Ok(response) => {
            if response.status().is_success() {
                info!("Transcript status webhook sent for {}: {}", hash, status);
            } else {
                error!(
                    "Transcript status webhook failed for {}: {} - {}",
                    hash,
                    response.status(),
                    response.text().await.unwrap_or_default()
                );
            }
        }
        Err(e) => {
            error!(
                "Transcript status webhook request failed for {}: {}",
                hash, e
            );
        }
    }
}
