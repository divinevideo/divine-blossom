// ABOUTME: Rust Cloud Run service for Blossom blob uploads
// ABOUTME: Handles Nostr auth validation, streaming upload to GCS, and SHA-256 hashing

mod thumbnail;

use anyhow::{anyhow, Result};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, Method, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, put, post, options},
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
use k256::schnorr::{signature::hazmat::PrehashVerifier, signature::Signer, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{env, sync::Arc, time::{SystemTime, UNIX_EPOCH}};
use tower_http::cors::{Any, CorsLayer};
use tower::Service;
use tracing::{error, info};

// Configuration
struct Config {
    gcs_bucket: String,
    cdn_base_url: String,
    port: u16,
    migration_nsec: Option<String>,
    transcoder_url: Option<String>,
}

impl Config {
    fn from_env() -> Self {
        Self {
            gcs_bucket: env::var("GCS_BUCKET").unwrap_or_else(|_| "divine-blossom-media".to_string()),
            cdn_base_url: env::var("CDN_BASE_URL").unwrap_or_else(|_| "https://media.divine.video".to_string()),
            port: env::var("PORT").unwrap_or_else(|_| "8080".to_string()).parse().unwrap_or(8080),
            migration_nsec: env::var("MIGRATION_NSEC").ok(),
            // URL of the divine-transcoder service for HLS generation
            transcoder_url: env::var("TRANSCODER_URL").ok(),
        }
    }
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
}

// Migration request
#[derive(Deserialize)]
struct MigrateRequest {
    source_url: String,
    expected_hash: Option<String>,
    owner: Option<String>,  // Owner pubkey for GCS metadata durability
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

const BLOSSOM_AUTH_KIND: u32 = 24242;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("blossom_upload=info".parse()?)
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
        .allow_methods([Method::GET, Method::PUT, Method::POST, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(std::time::Duration::from_secs(86400));

    // Build router
    let app = Router::new()
        .route("/upload", put(handle_upload))
        .route("/upload", options(handle_cors_preflight))
        .route("/migrate", post(handle_migrate))
        .route("/migrate", options(handle_cors_preflight))
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
            if let Err(e) = builder.serve_connection(io, hyper::service::service_fn(move |req| {
                let mut app = app.clone();
                async move {
                    app.call(req).await
                }
            })).await {
                error!("Connection error: {}", e);
            }
        });
    }
}

async fn handle_cors_preflight() -> impl IntoResponse {
    StatusCode::NO_CONTENT
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
            (status, Json(ErrorResponse { error: e.to_string() })).into_response()
        }
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
    let (sha256_hash, size, all_bytes) = stream_to_gcs_with_hash(
        &state.gcs_client,
        &state.config.gcs_bucket,
        &content_type,
        body,
        &auth_event.pubkey,
    ).await?;

    // Extract thumbnail for videos (non-blocking - failures don't fail the upload)
    let thumbnail_url = if thumbnail::is_video_type(&content_type) {
        match extract_and_upload_thumbnail(
            &state.gcs_client,
            &state.config.gcs_bucket,
            &state.config.cdn_base_url,
            &sha256_hash,
            &all_bytes,
        ).await {
            Ok(url) => {
                info!("Generated thumbnail for {}", sha256_hash);
                Some(url)
            }
            Err(e) => {
                error!("Thumbnail extraction failed for {}: {}", sha256_hash, e);
                None
            }
        }
    } else {
        None
    };

    // Trigger HLS transcoding for videos (fire-and-forget)
    if thumbnail::is_video_type(&content_type) {
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
            info!("TRANSCODER_URL not configured, skipping HLS transcoding for {}", sha256_hash);
        }
    }

    // Build response
    let extension = get_extension(&content_type);
    let uploaded = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    Ok(UploadResponse {
        sha256: sha256_hash.clone(),
        size,
        content_type,
        uploaded,
        url: format!("{}/{}.{}", state.config.cdn_base_url, sha256_hash, extension),
        thumbnail_url,
    })
}

async fn stream_to_gcs_with_hash(
    client: &GcsClient,
    bucket: &str,
    content_type: &str,
    body: Body,
    owner: &str,
) -> Result<(String, u64, Vec<u8>)> {
    let mut hasher = Sha256::new();
    let mut total_size: u64 = 0;
    let mut all_bytes = Vec::new();

    // Collect body stream while hashing
    let mut stream = body.into_data_stream();
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| anyhow!("Stream error: {}", e))?;
        hasher.update(&chunk);
        total_size += chunk.len() as u64;
        all_bytes.extend_from_slice(&chunk);
    }

    // Get final hash
    let sha256_hash = hex::encode(hasher.finalize());

    // Check if blob already exists
    let exists = client
        .get_object(&google_cloud_storage::http::objects::get::GetObjectRequest {
            bucket: bucket.to_string(),
            object: sha256_hash.clone(),
            ..Default::default()
        })
        .await
        .is_ok();

    if exists {
        info!("Blob {} already exists, skipping upload", sha256_hash);
        return Ok((sha256_hash, total_size, all_bytes));
    }

    // Upload to GCS
    let upload_type = UploadType::Simple(Media::new(sha256_hash.clone()));
    let req = UploadObjectRequest {
        bucket: bucket.to_string(),
        ..Default::default()
    };

    client
        .upload_object(&req, Bytes::from(all_bytes.clone()), &upload_type)
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

    info!("Uploaded {} bytes as {} (owner: {})", total_size, sha256_hash, owner);
    Ok((sha256_hash, total_size, all_bytes))
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
            Json(ErrorResponse { error: "Invalid hash format".to_string() }).into_response(),
        ).into_response();
    }

    let hash = hash.to_lowercase();

    // First check if thumbnail already exists
    let thumb_path = format!("{}.jpg", hash);
    let thumb_exists = state.gcs_client
        .get_object(&GetObjectRequest {
            bucket: state.config.gcs_bucket.clone(),
            object: thumb_path.clone(),
            ..Default::default()
        })
        .await
        .is_ok();

    if thumb_exists {
        // Thumbnail already exists, download and return it
        match state.gcs_client.download_object(
            &GetObjectRequest {
                bucket: state.config.gcs_bucket.clone(),
                object: thumb_path,
                ..Default::default()
            },
            &DownloadRange::default(),
        ).await {
            Ok(data) => {
                return (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "image/jpeg")],
                    data,
                ).into_response();
            }
            Err(e) => {
                error!("Failed to download existing thumbnail: {}", e);
            }
        }
    }

    // Download the video from GCS
    let video_data = match state.gcs_client.download_object(
        &GetObjectRequest {
            bucket: state.config.gcs_bucket.clone(),
            object: hash.clone(),
            ..Default::default()
        },
        &DownloadRange::default(),
    ).await {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to download video {}: {}", hash, e);
            return (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "application/json")],
                Json(ErrorResponse { error: "Video not found".to_string() }).into_response(),
            ).into_response();
        }
    };

    // Generate thumbnail
    let thumb_result = match thumbnail::extract_thumbnail(&video_data) {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to generate thumbnail for {}: {}", hash, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "application/json")],
                Json(ErrorResponse { error: "Failed to generate thumbnail".to_string() }).into_response(),
            ).into_response();
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

    if let Err(e) = state.gcs_client
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
    ).into_response()
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

    let event: NostrEvent = serde_json::from_slice(&event_json)
        .map_err(|e| anyhow!("Invalid event JSON: {}", e))?;

    validate_event(&event, required_action)?;

    Ok(event)
}

fn validate_event(event: &NostrEvent, required_action: &str) -> Result<()> {
    // Check kind
    if event.kind != BLOSSOM_AUTH_KIND {
        return Err(anyhow!("Invalid event kind: expected {}", BLOSSOM_AUTH_KIND));
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
    let pubkey_bytes = hex::decode(&event.pubkey)
        .map_err(|_| anyhow!("Invalid pubkey hex"))?;
    let sig_bytes = hex::decode(&event.sig)
        .map_err(|_| anyhow!("Invalid signature hex"))?;
    let msg_bytes = hex::decode(&event.id)
        .map_err(|_| anyhow!("Invalid event ID hex"))?;

    // Convert Vec<u8> to [u8; 32] for pubkey
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| anyhow!("Invalid pubkey length"))?;

    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|e| anyhow!("Invalid pubkey: {}", e))?;

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

/// Trigger HLS transcoding for a video (fire-and-forget)
/// Sends a POST request to the divine-transcoder service
async fn trigger_transcoding(transcoder_url: &str, hash: &str, owner: &str) -> Result<()> {
    info!("Triggering HLS transcoding for {} via {}", hash, transcoder_url);

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
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })).into_response()
        }
    }
}

async fn process_migrate(
    state: Arc<AppState>,
    request: MigrateRequest,
) -> Result<MigrateResponse> {
    info!("Migration request for: {}", request.source_url);

    // Validate URL is from allowed Blossom/CDN sources
    // Expanded to include popular Blossom servers for BUD-04 mirror support
    let allowed_domains = [
        // Divine infrastructure
        "cdn.divine.video",
        "blossom.divine.video",
        "stream.bunny.net",
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
    let url = url::Url::parse(&request.source_url)
        .map_err(|e| anyhow!("Invalid URL: {}", e))?;

    let host = url.host_str().ok_or_else(|| anyhow!("URL must have a host"))?;
    if !allowed_domains.iter().any(|d| host.ends_with(d)) {
        return Err(anyhow!("Source URL must be from an allowed domain"));
    }

    // Fetch content from source
    let client = reqwest::Client::new();
    let mut response = client.get(&request.source_url)
        .send()
        .await
        .map_err(|e| anyhow!("Failed to fetch source: {}", e))?;

    // If we get 401, try with Nostr auth
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        info!("Source requires auth, attempting Nostr auth...");

        if let Some(nsec) = &state.config.migration_nsec {
            let auth_header = create_blossom_auth(nsec, "get", &request.source_url)?;
            response = client.get(&request.source_url)
                .header("Authorization", auth_header)
                .send()
                .await
                .map_err(|e| anyhow!("Failed to fetch source with auth: {}", e))?;
        } else {
            return Err(anyhow!("Source requires auth but no MIGRATION_NSEC configured"));
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
    let exists = state.gcs_client
        .get_object(&google_cloud_storage::http::objects::get::GetObjectRequest {
            bucket: state.config.gcs_bucket.clone(),
            object: sha256_hash.clone(),
            ..Default::default()
        })
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

    state.gcs_client
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

    info!("Migrated {} bytes as {} from {} (owner: {:?})", total_size, sha256_hash, request.source_url, request.owner);

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
    let event_data = serde_json::json!([
        0,
        pubkey_hex,
        now,
        BLOSSOM_AUTH_KIND,
        tags,
        ""
    ]);

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
        let val = CHARSET.find(c).ok_or_else(|| anyhow!("Invalid bech32 character: {}", c))? as u8;
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
