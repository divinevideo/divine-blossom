// ABOUTME: Rust Cloud Run service for Blossom blob uploads
// ABOUTME: Handles Nostr auth validation, streaming upload to GCS, and SHA-256 hashing

use anyhow::{anyhow, Result};
use axum::{
    body::Body,
    extract::State,
    http::{header, Method, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{put, options},
    Router,
};
use bytes::Bytes;
use futures::StreamExt;
use google_cloud_storage::{
    client::{Client as GcsClient, ClientConfig},
    http::objects::{
        upload::{Media, UploadObjectRequest, UploadType},
        Object,
    },
};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder;
use k256::schnorr::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
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
}

impl Config {
    fn from_env() -> Self {
        Self {
            gcs_bucket: env::var("GCS_BUCKET").unwrap_or_else(|_| "divine-blossom-media".to_string()),
            cdn_base_url: env::var("CDN_BASE_URL").unwrap_or_else(|_| "https://cdn.divine.video".to_string()),
            port: env::var("PORT").unwrap_or_else(|_| "8080".to_string()).parse().unwrap_or(8080),
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
        .allow_methods([Method::PUT, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(std::time::Duration::from_secs(86400));

    // Build router
    let app = Router::new()
        .route("/upload", put(handle_upload))
        .route("/upload", options(handle_cors_preflight))
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
    let _auth_event = validate_auth(&headers, "upload")?;

    // Get content type
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    // Stream body while hashing
    let (sha256_hash, size) = stream_to_gcs_with_hash(
        &state.gcs_client,
        &state.config.gcs_bucket,
        &content_type,
        body,
    ).await?;

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
    })
}

async fn stream_to_gcs_with_hash(
    client: &GcsClient,
    bucket: &str,
    content_type: &str,
    body: Body,
) -> Result<(String, u64)> {
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
        return Ok((sha256_hash, total_size));
    }

    // Upload to GCS
    let upload_type = UploadType::Simple(Media::new(sha256_hash.clone()));
    let req = UploadObjectRequest {
        bucket: bucket.to_string(),
        ..Default::default()
    };

    client
        .upload_object(&req, Bytes::from(all_bytes), &upload_type)
        .await
        .map_err(|e| anyhow!("GCS upload failed: {}", e))?;

    // Set content type
    let update_req = google_cloud_storage::http::objects::patch::PatchObjectRequest {
        bucket: bucket.to_string(),
        object: sha256_hash.clone(),
        metadata: Some(Object {
            content_type: Some(content_type.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let _ = client.patch_object(&update_req).await;

    info!("Uploaded {} bytes as {}", total_size, sha256_hash);
    Ok((sha256_hash, total_size))
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
