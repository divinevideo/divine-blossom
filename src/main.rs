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
        // Landing page
        (Method::GET, "/") => Ok(handle_landing_page()),

        // Version check
        (Method::GET, "/version") => Ok(Response::from_status(StatusCode::OK)
            .with_body("v62-baseurl-fix")),

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
            let descriptor = metadata.to_descriptor(&get_base_url(&req));
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
    let descriptor = metadata.to_descriptor(&get_base_url(&req));
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
    let base_url = get_base_url(&req);
    let descriptors: Vec<BlobDescriptor> = blobs
        .iter()
        .map(|m| m.to_descriptor(&base_url))
        .collect();

    let mut resp = json_response(StatusCode::OK, &descriptors);
    add_cors_headers(&mut resp);

    Ok(resp)
}

/// GET / - Landing page
fn handle_landing_page() -> Response {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Divine Blossom Server</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f8fafc;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
        }
        header {
            text-align: center;
            margin-bottom: 3rem;
            padding: 2rem 0;
        }
        h1 {
            font-size: 2.5rem;
            color: #1a202c;
            margin-bottom: 0.5rem;
        }
        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            margin-left: 0.5rem;
        }
        .badge-beta { background: #c6f6d5; color: #276749; }
        .badge-fastly { background: #fed7d7; color: #c53030; }
        .tagline {
            color: #718096;
            font-size: 1.1rem;
            margin-top: 1rem;
        }
        section {
            background: white;
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        h2 {
            font-size: 1.25rem;
            color: #2d3748;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid #e2e8f0;
        }
        .endpoint {
            display: flex;
            align-items: flex-start;
            padding: 0.75rem 0;
            border-bottom: 1px solid #edf2f7;
        }
        .endpoint:last-child { border-bottom: none; }
        .method {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            font-family: monospace;
            min-width: 60px;
            text-align: center;
            margin-right: 1rem;
        }
        .method-get { background: #c6f6d5; color: #276749; }
        .method-head { background: #bee3f8; color: #2b6cb0; }
        .method-put { background: #feebc8; color: #c05621; }
        .method-delete { background: #fed7d7; color: #c53030; }
        .endpoint-info { flex: 1; }
        .endpoint-path {
            font-family: monospace;
            font-weight: 600;
            color: #5a67d8;
        }
        .endpoint-desc {
            color: #718096;
            font-size: 0.9rem;
            margin-top: 0.25rem;
        }
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        .feature {
            padding: 1rem;
            background: #f7fafc;
            border-radius: 8px;
        }
        .feature h3 {
            font-size: 0.9rem;
            color: #4a5568;
            margin-bottom: 0.5rem;
        }
        .feature p {
            font-size: 0.85rem;
            color: #718096;
        }
        footer {
            text-align: center;
            padding: 2rem 0;
            color: #a0aec0;
            font-size: 0.875rem;
        }
        footer a {
            color: #5a67d8;
            text-decoration: none;
        }
        footer a:hover { text-decoration: underline; }
        code {
            background: #edf2f7;
            padding: 0.125rem 0.375rem;
            border-radius: 4px;
            font-size: 0.875rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Divine Blossom Server <span class="badge badge-beta">BETA</span><span class="badge badge-fastly">FASTLY</span></h1>
            <p class="tagline">Content-addressable blob storage implementing the Blossom protocol with AI-powered content moderation</p>
        </header>

        <section>
            <h2>API Endpoints</h2>
            <div class="endpoint">
                <span class="method method-get">GET</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/&lt;sha256&gt;</span>
                    <p class="endpoint-desc">Retrieve a blob by its SHA-256 hash. Supports optional file extension.</p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-head">HEAD</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/&lt;sha256&gt;</span>
                    <p class="endpoint-desc">Check if a blob exists and get its metadata.</p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-put">PUT</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/upload</span>
                    <p class="endpoint-desc">Upload a new blob. Requires Nostr authentication.</p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-head">HEAD</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/upload</span>
                    <p class="endpoint-desc">Get upload requirements (max size, allowed types).</p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-get">GET</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/list/&lt;pubkey&gt;</span>
                    <p class="endpoint-desc">List all blobs uploaded by a public key.</p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-delete">DELETE</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/&lt;sha256&gt;</span>
                    <p class="endpoint-desc">Delete a blob. Requires Nostr authentication and ownership.</p>
                </div>
            </div>
        </section>

        <section>
            <h2>Features</h2>
            <div class="features">
                <div class="feature">
                    <h3>Nostr Authentication</h3>
                    <p>Secure uploads using NIP-98 HTTP Auth with Schnorr signatures.</p>
                </div>
                <div class="feature">
                    <h3>Content Moderation</h3>
                    <p>AI-powered moderation with SAFE, REVIEW, AGE_RESTRICTED, and PERMANENT_BAN levels.</p>
                </div>
                <div class="feature">
                    <h3>Edge Computing</h3>
                    <p>Powered by Fastly Compute for low-latency global delivery.</p>
                </div>
                <div class="feature">
                    <h3>GCS Storage</h3>
                    <p>Reliable blob storage backed by Google Cloud Storage.</p>
                </div>
            </div>
        </section>

        <section>
            <h2>Protocol</h2>
            <p>This server implements the <a href="https://github.com/hzrd149/blossom">Blossom protocol</a> (BUD-01 and BUD-02) for decentralized media hosting on Nostr.</p>
            <p style="margin-top: 0.5rem;">Maximum upload size: <code>100 MB</code></p>
        </section>

        <footer>
            <p>Powered by <a href="https://www.fastly.com/products/edge-compute">Fastly Compute</a> | <a href="https://divine.video">Divine</a></p>
        </footer>
    </div>
</body>
</html>"#;

    let mut resp = Response::from_status(StatusCode::OK);
    resp.set_header(header::CONTENT_TYPE, "text/html; charset=utf-8");
    resp.set_body(html);
    resp
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

/// Get base URL for blob descriptors from request Host header
fn get_base_url(req: &Request) -> String {
    req.get_header(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|host| format!("https://{}", host))
        .unwrap_or_else(|| "https://blossom.divine.video".into())
}
