// ABOUTME: Main entry point for Fastly Blossom server
// ABOUTME: Routes requests to appropriate handlers for BUD-01 and BUD-02

mod auth;
mod blossom;
mod error;
mod metadata;
mod storage;

use crate::auth::{optional_auth, validate_auth, validate_hash_match};
use crate::blossom::{
    is_hash_path, parse_hash_from_path, AuthAction, BlobDescriptor, BlobMetadata, BlobStatus,
    UploadRequirements,
};
use crate::error::{BlossomError, Result};
use crate::metadata::{
    add_to_user_list, check_ownership, delete_blob_metadata, get_blob_metadata,
    list_blobs_with_metadata, put_blob_metadata, remove_from_user_list,
};
use crate::storage::{blob_exists, current_timestamp, delete_blob as storage_delete, download_blob, upload_blob};

use fastly::http::{header, Method, StatusCode};
use fastly::{Error, Request, Response};
use sha2::{Digest, Sha256};

/// Maximum upload size (100 MB)
const MAX_UPLOAD_SIZE: u64 = 100 * 1024 * 1024;

/// Entry point
#[fastly::main]
fn main(req: Request) -> std::result::Result<Response, Error> {
    match handle_request(req) {
        Ok(resp) => Ok(resp),
        Err(e) => Ok(error_response(&e)),
    }
}

/// Route and handle the request
fn handle_request(req: Request) -> Result<Response> {
    let method = req.get_method().clone();
    let path = req.get_path().to_string();

    match (method, path.as_str()) {
        // Version check
        (Method::GET, "/version") => Ok(Response::from_status(StatusCode::OK)
            .with_body("v57-fixbackend-20251203")),

        // BUD-01: Blob retrieval
        (Method::GET, p) if is_hash_path(p) => handle_get_blob(req, p),
        (Method::HEAD, p) if is_hash_path(p) => handle_head_blob(p),

        // BUD-02: Upload
        (Method::PUT, "/upload") => handle_upload(req),
        (Method::HEAD, "/upload") => handle_upload_requirements(),

        // BUD-02: Delete
        (Method::DELETE, p) if is_hash_path(p) => handle_delete(req, p),

        // BUD-02: List
        (Method::GET, p) if p.starts_with("/list/") => handle_list(req, p),

        // CORS preflight
        (Method::OPTIONS, _) => Ok(cors_preflight_response()),

        // Not found
        _ => Err(BlossomError::NotFound("Not found".into())),
    }
}

/// GET /<sha256>[.ext] - Retrieve blob
fn handle_get_blob(req: Request, path: &str) -> Result<Response> {
    let hash = parse_hash_from_path(path)
        .ok_or_else(|| BlossomError::BadRequest("Invalid hash in path".into()))?;

    // Check metadata for access control
    let metadata = get_blob_metadata(&hash)?;

    if let Some(ref meta) = metadata {
        // Handle restricted content
        if meta.status == BlobStatus::Restricted {
            // Check if requester is owner
            if let Ok(Some(auth)) = optional_auth(&req, AuthAction::List) {
                if auth.pubkey.to_lowercase() != meta.owner.to_lowercase() {
                    return Err(BlossomError::NotFound("Blob not found".into()));
                }
            } else {
                return Err(BlossomError::NotFound("Blob not found".into()));
            }
        }
    }

    // Get range header for partial content
    let range = req
        .get_header(header::RANGE)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Download from B2
    let mut resp = download_blob(&hash, range.as_deref())?;

    // Add CORS headers
    add_cors_headers(&mut resp);

    // Add Blossom headers
    if let Some(meta) = metadata {
        resp.set_header("X-Sha256", &meta.sha256);
        resp.set_header("X-Content-Length", meta.size.to_string());
    }

    Ok(resp)
}

/// HEAD /<sha256>[.ext] - Check blob existence
fn handle_head_blob(path: &str) -> Result<Response> {
    let hash = parse_hash_from_path(path)
        .ok_or_else(|| BlossomError::BadRequest("Invalid hash in path".into()))?;

    // Check metadata
    let metadata = get_blob_metadata(&hash)?
        .ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;

    // Don't reveal restricted content exists
    if metadata.status == BlobStatus::Restricted {
        return Err(BlossomError::NotFound("Blob not found".into()));
    }

    let mut resp = Response::from_status(StatusCode::OK);
    resp.set_header("Content-Type", &metadata.mime_type);
    resp.set_header("Content-Length", metadata.size.to_string());
    resp.set_header("X-Sha256", &metadata.sha256);
    add_cors_headers(&mut resp);

    Ok(resp)
}

/// PUT /upload - Upload blob
fn handle_upload(mut req: Request) -> Result<Response> {
    // Validate auth
    let auth = validate_auth(&req, AuthAction::Upload)?;

    // Get content type
    let content_type = req
        .get_header(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    // Get content length
    let content_length: u64 = req
        .get_header(header::CONTENT_LENGTH)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| BlossomError::BadRequest("Content-Length required".into()))?;

    if content_length > MAX_UPLOAD_SIZE {
        return Err(BlossomError::BadRequest(format!(
            "File too large. Maximum size is {} bytes",
            MAX_UPLOAD_SIZE
        )));
    }

    // Read body and compute hash
    let body_bytes = req.take_body().into_bytes();
    let actual_size = body_bytes.len() as u64;

    if actual_size != content_length {
        return Err(BlossomError::BadRequest(
            "Content-Length doesn't match body size".into(),
        ));
    }

    // Compute SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&body_bytes);
    let hash = hex::encode(hasher.finalize());

    // Check if blob already exists
    if blob_exists(&hash)? {
        // Return existing blob descriptor
        if let Some(metadata) = get_blob_metadata(&hash)? {
            let descriptor = metadata.to_descriptor(&get_base_url());
            return Ok(json_response(StatusCode::OK, &descriptor));
        }
    }

    // Upload to B2
    upload_blob(
        &hash,
        fastly::Body::from(body_bytes),
        &content_type,
        actual_size,
    )?;

    // Store metadata
    let metadata = BlobMetadata {
        sha256: hash.clone(),
        size: actual_size,
        mime_type: content_type,
        uploaded: current_timestamp(),
        owner: auth.pubkey.clone(),
        status: BlobStatus::Pending, // Start as pending for moderation
        thumbnail: None,
        moderation: None,
    };

    put_blob_metadata(&metadata)?;

    // Add to user's list
    add_to_user_list(&auth.pubkey, &hash)?;

    // Return blob descriptor
    let descriptor = metadata.to_descriptor(&get_base_url());
    let mut resp = json_response(StatusCode::OK, &descriptor);
    add_cors_headers(&mut resp);

    Ok(resp)
}

/// HEAD /upload - Get upload requirements
fn handle_upload_requirements() -> Result<Response> {
    let requirements = UploadRequirements {
        max_size: Some(MAX_UPLOAD_SIZE),
        allowed_types: None, // Accept all types
    };

    let mut resp = json_response(StatusCode::OK, &requirements);
    add_cors_headers(&mut resp);

    Ok(resp)
}

/// DELETE /<sha256> - Delete blob
fn handle_delete(req: Request, path: &str) -> Result<Response> {
    let hash = parse_hash_from_path(path)
        .ok_or_else(|| BlossomError::BadRequest("Invalid hash in path".into()))?;

    // Validate auth with hash check
    let auth = validate_auth(&req, AuthAction::Delete)?;
    validate_hash_match(&auth, &hash)?;

    // Verify ownership
    if !check_ownership(&hash, &auth.pubkey)? {
        return Err(BlossomError::Forbidden(
            "You don't own this blob".into(),
        ));
    }

    // Delete from B2
    storage_delete(&hash)?;

    // Delete metadata
    delete_blob_metadata(&hash)?;

    // Remove from user's list
    remove_from_user_list(&auth.pubkey, &hash)?;

    let mut resp = Response::from_status(StatusCode::OK);
    add_cors_headers(&mut resp);

    Ok(resp)
}

/// GET /list/<pubkey> - List user's blobs
fn handle_list(req: Request, path: &str) -> Result<Response> {
    let pubkey = path
        .strip_prefix("/list/")
        .ok_or_else(|| BlossomError::BadRequest("Invalid list path".into()))?;

    // Check if authenticated as the owner (to include restricted blobs)
    let is_owner = if let Ok(Some(auth)) = optional_auth(&req, AuthAction::List) {
        auth.pubkey.to_lowercase() == pubkey.to_lowercase()
    } else {
        false
    };

    // Get blobs with metadata
    let blobs = list_blobs_with_metadata(pubkey, is_owner)?;

    // Convert to descriptors
    let base_url = get_base_url();
    let descriptors: Vec<BlobDescriptor> = blobs
        .iter()
        .map(|m| m.to_descriptor(&base_url))
        .collect();

    let mut resp = json_response(StatusCode::OK, &descriptors);
    add_cors_headers(&mut resp);

    Ok(resp)
}

/// Create JSON response
fn json_response<T: serde::Serialize>(status: StatusCode, body: &T) -> Response {
    let json = serde_json::to_string(body).unwrap_or_else(|_| "{}".into());
    let mut resp = Response::from_status(status);
    resp.set_header(header::CONTENT_TYPE, "application/json");
    resp.set_body(json);
    resp
}

/// Create error response
fn error_response(error: &BlossomError) -> Response {
    let mut resp = Response::from_status(error.status_code());
    resp.set_header(header::CONTENT_TYPE, "application/json");

    let body = serde_json::json!({
        "error": error.message()
    });
    resp.set_body(body.to_string());
    add_cors_headers(&mut resp);

    resp
}

/// Add CORS headers
fn add_cors_headers(resp: &mut Response) {
    resp.set_header("Access-Control-Allow-Origin", "*");
    resp.set_header("Access-Control-Allow-Methods", "GET, HEAD, PUT, DELETE, OPTIONS");
    resp.set_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Sha256");
    resp.set_header("Access-Control-Expose-Headers", "X-Sha256, X-Content-Length");
}

/// CORS preflight response
fn cors_preflight_response() -> Response {
    let mut resp = Response::from_status(StatusCode::NO_CONTENT);
    add_cors_headers(&mut resp);
    resp.set_header("Access-Control-Max-Age", "86400");
    resp
}

/// Get base URL for blob descriptors
fn get_base_url() -> String {
    // In production, this would come from config
    // For now, use a placeholder that should be configured
    std::env::var("BLOSSOM_BASE_URL").unwrap_or_else(|_| "https://blossom.example.com".into())
}
