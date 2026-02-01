// ABOUTME: GPU video transcoding Cloud Run service for HLS generation
// ABOUTME: Downloads video from GCS, transcodes to HLS with NVENC, uploads segments

use anyhow::{anyhow, Result};
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
        download::Range as DownloadRange,
        get::GetObjectRequest,
        upload::{Media, UploadObjectRequest, UploadType},
    },
};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder;
use serde::{Deserialize, Serialize};
use std::{env, path::Path, sync::Arc};
use tempfile::TempDir;
use tokio::process::Command;
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
}

impl Config {
    fn from_env() -> Self {
        // Check if GPU is explicitly enabled via env var (more reliable than checking NVIDIA_VISIBLE_DEVICES)
        // Set USE_GPU=true when deploying with actual GPU support
        let use_gpu = env::var("USE_GPU")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        Self {
            gcs_bucket: env::var("GCS_BUCKET").unwrap_or_else(|_| "divine-blossom-media".to_string()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .unwrap_or(8080),
            use_gpu,
            // Webhook URL for status updates (e.g., https://media.divine.video/admin/transcode-status)
            webhook_url: env::var("WEBHOOK_URL").ok(),
            // Secret for webhook authentication
            webhook_secret: env::var("WEBHOOK_SECRET").ok(),
        }
    }
}

// App state shared across handlers
struct AppState {
    gcs_client: GcsClient,
    config: Config,
}

// Transcode request
#[derive(Debug, Deserialize)]
struct TranscodeRequest {
    /// SHA256 hash of the original video
    hash: String,
    /// Optional owner pubkey for metadata
    #[serde(default)]
    owner: Option<String>,
}

// Transcode response
#[derive(Serialize)]
struct TranscodeResponse {
    hash: String,
    status: String,
    hls_master: String,
    variants: Vec<HlsVariant>,
}

#[derive(Serialize)]
struct HlsVariant {
    resolution: String,
    playlist: String,
    bandwidth: u32,
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

    info!("GPU acceleration: {}", if use_gpu { "enabled" } else { "disabled (CPU fallback)" });

    // Initialize GCS client
    let gcs_config = ClientConfig::default().with_auth().await?;
    let gcs_client = GcsClient::new(gcs_config);

    let state = Arc::new(AppState { gcs_client, config });

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
        send_status_webhook(&state.config, &hash, "complete", None).await;
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
        });
    }

    // Update status to processing
    send_status_webhook(&state.config, &hash, "processing", None).await;

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
        send_status_webhook(&state.config, &hash, "failed", None).await;
        return Err(e);
    }

    info!("Downloaded video to {:?}", input_path);

    // NOTE: We do NOT modify the original file - SHA256 hash must remain valid for
    // content-addressable storage and ProofMode verification. HLS provides streaming.

    // Create output directory for HLS
    let output_dir = temp_path.join("hls");
    tokio::fs::create_dir_all(&output_dir).await?;

    // Run FFmpeg to generate HLS
    let ffmpeg_result = run_ffmpeg_hls(&input_path, &output_dir, state.config.use_gpu).await;

    let variants = match ffmpeg_result {
        Ok(v) => v,
        Err(e) => {
            send_status_webhook(&state.config, &hash, "failed", None).await;
            return Err(e);
        }
    };

    info!("Generated HLS with {} variants", variants.len());

    // Upload all HLS files to GCS
    let upload_result = upload_hls_to_gcs(
        &state.gcs_client,
        &state.config.gcs_bucket,
        &hash,
        &output_dir,
    )
    .await;

    if let Err(e) = upload_result {
        send_status_webhook(&state.config, &hash, "failed", None).await;
        return Err(e);
    }

    info!("Uploaded HLS files for {}", hash);

    // Update status to complete (no size change - original file preserved)
    send_status_webhook(&state.config, &hash, "complete", None).await;

    Ok(TranscodeResponse {
        hash: hash.clone(),
        status: "complete".to_string(),
        hls_master: format!("{}/hls/master.m3u8", hash),
        variants,
    })
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

/// Optimize video for web streaming by moving moov atom to the beginning
/// This enables progressive download/streaming in browsers
async fn run_ffmpeg_faststart(input_path: &Path, output_path: &Path) -> Result<()> {
    let input_str = input_path.to_string_lossy();
    let output_str = output_path.to_string_lossy();

    info!("Running faststart optimization: {} -> {}", input_str, output_str);

    let mut cmd = Command::new("ffmpeg");
    cmd.args([
        "-y",                           // Overwrite output
        "-i", &input_str,               // Input file
        "-c", "copy",                   // Copy streams without re-encoding (fast!)
        "-movflags", "+faststart",      // Move moov atom to beginning
        &output_str,                    // Output file
    ]);

    let output = cmd.output().await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("FFmpeg faststart failed: {}", stderr);
        return Err(anyhow!("FFmpeg faststart failed: {}", stderr));
    }

    info!("Faststart optimization complete");
    Ok(())
}

/// Upload the faststart-optimized video to GCS, replacing the original
/// Returns the new file size in bytes
async fn upload_faststart_to_gcs(
    client: &GcsClient,
    bucket: &str,
    object: &str,
    file_path: &Path,
) -> Result<u64> {
    let data = tokio::fs::read(file_path).await?;
    let new_size = data.len() as u64;
    let content_type = "video/mp4";

    info!("Uploading faststart video ({} bytes) to gs://{}/{}", new_size, bucket, object);

    let bytes_data: Bytes = data.into();
    client
        .upload_object(
            &UploadObjectRequest {
                bucket: bucket.to_string(),
                ..Default::default()
            },
            bytes_data,
            &UploadType::Simple(Media {
                name: object.to_string().into(),
                content_type: content_type.to_string().into(),
                content_length: None,
            }),
        )
        .await
        .map_err(|e| anyhow!("Failed to upload faststart video: {}", e))?;

    Ok(new_size)
}

async fn run_ffmpeg_hls(
    input_path: &Path,
    output_dir: &Path,
    use_gpu: bool,
) -> Result<Vec<HlsVariant>> {
    let input_str = input_path.to_string_lossy();
    let output_pattern = output_dir.join("stream_%v.m3u8");
    let master_playlist = output_dir.join("master.m3u8");

    // Build FFmpeg command based on GPU availability
    let mut cmd = Command::new("ffmpeg");
    cmd.arg("-y"); // Overwrite output

    if use_gpu {
        // GPU-accelerated encoding with NVENC
        // -hwaccel cuda: Use CUDA for decoding
        // -hwaccel_output_format cuda: Keep frames in GPU memory
        cmd.args(["-hwaccel", "cuda", "-hwaccel_output_format", "cuda"]);
    }

    cmd.args(["-i", &input_str]);

    // Output mapping: create two video streams (720p, 480p) with audio
    cmd.args([
        "-map", "0:v:0", "-map", "0:a:0?", // 720p with audio (audio optional)
        "-map", "0:v:0", "-map", "0:a:0?", // 480p with audio (audio optional)
    ]);

    if use_gpu {
        // GPU encoding with scale_cuda for in-GPU scaling
        cmd.args([
            // 720p variant
            "-filter:v:0", "scale_cuda=1280:720:interp_algo=lanczos",
            "-c:v:0", "h264_nvenc",
            "-profile:v:0", "main",  // main profile for better compatibility
            "-level:v:0", "3.1",
            "-cq:v:0", "23",
            "-maxrate:v:0", "2500k",
            "-bufsize:v:0", "5000k",
            // 480p variant
            "-filter:v:1", "scale_cuda=854:480:interp_algo=lanczos",
            "-c:v:1", "h264_nvenc",
            "-profile:v:1", "main",
            "-level:v:1", "3.0",
            "-cq:v:1", "23",
            "-maxrate:v:1", "1000k",
            "-bufsize:v:1", "2000k",
        ]);
    } else {
        // CPU encoding fallback with libx264
        cmd.args([
            // 720p variant
            "-filter:v:0", "scale=1280:720",
            "-c:v:0", "libx264",
            "-profile:v:0", "main",
            "-level:v:0", "3.1",
            "-crf:v:0", "23",
            "-maxrate:v:0", "2500k",
            "-bufsize:v:0", "5000k",
            "-preset:v:0", "fast",
            // 480p variant
            "-filter:v:1", "scale=854:480",
            "-c:v:1", "libx264",
            "-profile:v:1", "main",
            "-level:v:1", "3.0",
            "-crf:v:1", "23",
            "-maxrate:v:1", "1000k",
            "-bufsize:v:1", "2000k",
            "-preset:v:1", "fast",
        ]);
    }

    // Audio encoding (same for both)
    cmd.args([
        "-c:a", "aac",
        "-b:a:0", "128k",
        "-b:a:1", "96k",
    ]);

    // HLS output settings
    // -hls_time 10: 10 second segments (but for 6s clips, this means 1 segment)
    // -hls_playlist_type vod: VOD playlist (all segments available)
    // -hls_flags single_file: Put all segments in single .ts file (efficient for short clips)
    // -master_pl_name: Name of master playlist
    // -var_stream_map: Map variants to output streams
    cmd.args([
        "-f", "hls",
        "-hls_time", "10",
        "-hls_playlist_type", "vod",
        "-hls_flags", "single_file",
        "-master_pl_name", "master.m3u8",
        "-var_stream_map", "v:0,a:0,name:720p v:1,a:1,name:480p",
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

async fn upload_hls_to_gcs(
    client: &GcsClient,
    bucket: &str,
    hash: &str,
    hls_dir: &Path,
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

        info!("Uploaded {}", gcs_path);
    }

    Ok(())
}

/// Send transcode status update to the Fastly edge webhook
/// This is fire-and-forget - failures are logged but don't fail the transcode
async fn send_status_webhook(config: &Config, hash: &str, status: &str, new_size: Option<u64>) {
    let webhook_url = match &config.webhook_url {
        Some(url) => url,
        None => {
            info!("WEBHOOK_URL not configured, skipping status update for {}", hash);
            return;
        }
    };

    let client = reqwest::Client::new();
    let mut payload = serde_json::json!({
        "sha256": hash,
        "status": status
    });

    // Include new_size if the original file was replaced (faststart optimization)
    if let Some(size) = new_size {
        payload["new_size"] = serde_json::json!(size);
        info!("Including new_size {} in webhook for {}", size, hash);
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
