// ABOUTME: Main entry point for Fastly Blossom server
// ABOUTME: Routes requests to appropriate handlers for BUD-01 and BUD-02

mod admin;
mod auth;
mod blossom;
mod error;
mod metadata;
mod storage;

use crate::auth::{optional_auth, validate_auth, validate_hash_match};
use crate::blossom::{
    is_hash_path, is_video_mime_type, parse_hash_from_path, parse_thumbnail_path, AuthAction, BlobDescriptor, BlobMetadata, BlobStatus,
    TranscodeStatus, UploadRequirements,
};
use crate::error::{BlossomError, Result};
use crate::metadata::{
    add_to_recent_index, add_to_user_index, add_to_user_list, check_ownership,
    delete_blob_metadata, get_blob_metadata, list_blobs_with_metadata, put_blob_metadata,
    remove_from_recent_index, remove_from_user_list, update_blob_status, update_stats_on_add,
    update_stats_on_remove,
};
use crate::storage::{blob_exists, current_timestamp, delete_blob as storage_delete, download_blob_with_fallback, download_thumbnail, trigger_background_migration, upload_blob};

use fastly::http::{header, Method, StatusCode};
use fastly::{Error, Request, Response};
use sha2::{Digest, Sha256};

/// Maximum upload size (50 GB) - Cloud Run with HTTP/2 has no size limit
const MAX_UPLOAD_SIZE: u64 = 50 * 1024 * 1024 * 1024;

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
    let host = req.get_header_str("host").unwrap_or("unknown");

    eprintln!("[BLOSSOM ROUTE] method={} path={} host={}", method, path, host);

    match (method, path.as_str()) {
        // Landing page
        (Method::GET, "/") => Ok(handle_landing_page()),

        // Version check
        (Method::GET, "/version") => Ok(Response::from_status(StatusCode::OK)
            .with_body("v124-update-size-on-faststart")),

        // HLS: /{sha256}.hls -> serve master manifest
        (Method::GET, p) if p.ends_with(".hls") => handle_get_hls_master(req, p),
        (Method::HEAD, p) if p.ends_with(".hls") => handle_head_hls_master(p),

        // HLS: /{sha256}/hls/* -> serve HLS segments/playlists
        (Method::GET, p) if p.contains("/hls/") => handle_get_hls_content(req, p),
        (Method::HEAD, p) if p.contains("/hls/") => handle_head_hls_content(p),

        // Direct quality variant access: /{sha256}/720p, /{sha256}/480p
        (Method::GET, p) if is_quality_variant_path(p) => handle_get_quality_variant(req, p),
        (Method::HEAD, p) if is_quality_variant_path(p) => handle_head_quality_variant(p),

        // BUD-01: Blob retrieval
        (Method::GET, p) if is_hash_path(p) => handle_get_blob(req, p),
        (Method::HEAD, p) if is_hash_path(p) => handle_head_blob(p),

        // BUD-02: Upload
        (Method::PUT, "/upload") => handle_upload(req),
        // BUD-06: Upload requirements/pre-validation
        (Method::HEAD, "/upload") => handle_upload_requirements(req),

        // BUD-02: Delete
        (Method::DELETE, p) if is_hash_path(p) => handle_delete(req, p),

        // BUD-02: List
        (Method::GET, p) if p.starts_with("/list/") => handle_list(req, p),

        // BUD-09: Report
        (Method::PUT, "/report") => handle_report(req),

        // BUD-04: Mirror
        (Method::PUT, "/mirror") => handle_mirror(req),

        // Admin: Moderation webhook from divine-moderation-service
        (Method::POST, "/admin/moderate") => handle_admin_moderate(req),

        // Admin: Transcode status webhook from divine-transcoder service
        (Method::POST, "/admin/transcode-status") => handle_transcode_status(req),

        // Admin: OAuth login
        (Method::POST, "/admin/auth/google") => admin::handle_google_auth(req),
        (Method::GET, "/admin/auth/github") => admin::handle_github_auth_redirect(req),
        (Method::GET, p) if p.starts_with("/admin/auth/github/callback") => admin::handle_github_callback(req),
        (Method::POST, "/admin/logout") => admin::handle_logout(req),

        // Admin Dashboard
        (Method::GET, "/admin") => admin::handle_admin_dashboard(req),
        (Method::GET, "/admin/api/stats") => admin::handle_admin_stats(req),
        (Method::GET, "/admin/api/recent") => admin::handle_admin_recent(req),
        (Method::GET, "/admin/api/users") => admin::handle_admin_users(req),
        (Method::GET, p) if p.starts_with("/admin/api/user/") => {
            let pubkey = p.strip_prefix("/admin/api/user/").unwrap_or("");
            admin::handle_admin_user_blobs(req, pubkey)
        }
        (Method::GET, p) if p.starts_with("/admin/api/blob/") => {
            let hash = p.strip_prefix("/admin/api/blob/").unwrap_or("");
            admin::handle_admin_blob_detail(req, hash)
        }
        (Method::POST, "/admin/api/moderate") => admin::handle_admin_moderate_action(req),
        (Method::POST, "/admin/api/backfill") => admin::handle_admin_backfill(req),

        // CORS preflight
        (Method::OPTIONS, _) => Ok(cors_preflight_response()),

        // Not found
        _ => Err(BlossomError::NotFound("Not found".into())),
    }
}

/// GET /<sha256>[.ext] - Retrieve blob
fn handle_get_blob(req: Request, path: &str) -> Result<Response> {
    // Check if this is a thumbnail request ({hash}.jpg)
    if let Some(thumbnail_key) = parse_thumbnail_path(path) {
        let video_hash = thumbnail_key.trim_end_matches(".jpg");

        // Check parent video's moderation status - thumbnails inherit video access rules
        if let Ok(Some(meta)) = get_blob_metadata(video_hash) {
            if meta.status == BlobStatus::Banned {
                return Err(BlossomError::NotFound("Blob not found".into()));
            }
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

        // Try to download existing thumbnail from GCS
        match download_thumbnail(&thumbnail_key) {
            Ok(mut resp) => {
                resp.set_header("Content-Type", "image/jpeg");
                resp.set_header("Accept-Ranges", "bytes");
                add_cors_headers(&mut resp);
                return Ok(resp);
            }
            Err(BlossomError::NotFound(_)) => {
                // Thumbnail doesn't exist, generate on-demand via Cloud Run
                match generate_thumbnail_on_demand(video_hash) {
                    Ok(mut resp) => {
                        resp.set_header("Content-Type", "image/jpeg");
                        resp.set_header("Accept-Ranges", "bytes");
                        add_cors_headers(&mut resp);
                        return Ok(resp);
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        }
    }

    let hash = parse_hash_from_path(path)
        .ok_or_else(|| BlossomError::BadRequest("Invalid hash in path".into()))?;

    // Check metadata for access control
    let metadata = get_blob_metadata(&hash)?;

    if let Some(ref meta) = metadata {
        // Handle banned content - no access for anyone
        if meta.status == BlobStatus::Banned {
            return Err(BlossomError::NotFound("Blob not found".into()));
        }

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

    // Download from GCS with fallback to CDNs
    let result = download_blob_with_fallback(&hash, range.as_deref())?;
    let mut resp = result.response;

    // Surface provenance metadata if present on the origin object.
    let c2pa_manifest_id = resp
        .get_header_str("x-goog-meta-c2pa-manifest-id")
        .map(|s| s.to_string());
    let source_sha256 = resp
        .get_header_str("x-goog-meta-source-sha256")
        .map(|s| s.to_string());

    // Add CORS headers
    add_cors_headers(&mut resp);

    // Always indicate range request support for video streaming
    resp.set_header("Accept-Ranges", "bytes");

    // Add Blossom headers and ensure correct Content-Type from metadata
    // IMPORTANT: Don't overwrite Content-Length for 206 Partial Content responses
    // as the backend sets it to the partial content size
    let is_partial = resp.get_status() == StatusCode::PARTIAL_CONTENT;

    if let Some(ref meta) = metadata {
        // Set Content-Type from stored metadata (more reliable than origin server)
        resp.set_header("Content-Type", &meta.mime_type);
        resp.set_header("X-Sha256", &meta.sha256);
        resp.set_header("X-Content-Length", meta.size.to_string());

        // Only set Content-Length for full responses (200), not partial (206)
        if !is_partial {
            resp.set_header("Content-Length", meta.size.to_string());
        }
    } else {
        // No metadata in KV store - get info from GCS response headers
        // This handles videos uploaded directly to Cloud Run (bypassing Fastly)
        if let Some(mime_type) = infer_mime_from_path(path) {
            resp.set_header("Content-Type", mime_type);
        }
        // Try to get Content-Length from GCS response (extract first to avoid borrow issues)
        if !is_partial {
            let content_length: Option<String> = resp.get_header_str("content-length")
                .map(|s| s.to_string())
                .or_else(|| resp.get_header_str("x-goog-stored-content-length").map(|s| s.to_string()));
            if let Some(cl) = content_length {
                resp.set_header("Content-Length", &cl);
            }
        }
        resp.set_header("X-Sha256", &hash);
    }

    if let Some(c2pa) = c2pa_manifest_id {
        resp.set_header("X-C2PA-Manifest-Id", &c2pa);
    }
    if let Some(source_hash) = source_sha256 {
        resp.set_header("X-Source-Sha256", &source_hash);
    }

    // Add header indicating the source (useful for debugging/monitoring)
    if result.source != "gcs" {
        resp.set_header("X-Blossom-Source", &result.source);

        // Trigger background migration to GCS via Cloud Run
        // This is fire-and-forget - we don't wait for completion
        let _ = trigger_background_migration(&hash, &result.source);
    }

    Ok(resp)
}

/// HEAD /<sha256>[.ext] - Check blob existence
fn handle_head_blob(path: &str) -> Result<Response> {
    // Check if this is a thumbnail request ({hash}.jpg)
    if let Some(thumbnail_key) = parse_thumbnail_path(path) {
        let resp = download_thumbnail(&thumbnail_key)?;
        let content_length = resp.get_header_str("x-goog-stored-content-length")
            .or_else(|| resp.get_header_str("content-length"))
            .unwrap_or("0")
            .to_string();
        let mut head_resp = Response::from_status(StatusCode::OK);
        head_resp.set_header("Content-Type", "image/jpeg");
        head_resp.set_header("Content-Length", &content_length);
        head_resp.set_header("Accept-Ranges", "bytes");
        add_cors_headers(&mut head_resp);
        return Ok(head_resp);
    }

    let hash = parse_hash_from_path(path)
        .ok_or_else(|| BlossomError::BadRequest("Invalid hash in path".into()))?;

    // Check metadata
    let metadata = get_blob_metadata(&hash)?
        .ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;

    // Don't reveal restricted or banned content exists
    if metadata.status == BlobStatus::Restricted || metadata.status == BlobStatus::Banned {
        return Err(BlossomError::NotFound("Blob not found".into()));
    }

    let mut resp = Response::from_status(StatusCode::OK);
    resp.set_header(header::CONTENT_TYPE, &metadata.mime_type);
    // Note: For HEAD responses, Fastly/HTTP/2 may strip Content-Length when there's no body
    // X-Content-Length provides the size info as a workaround
    resp.set_header(header::CONTENT_LENGTH, metadata.size.to_string());
    resp.set_header("X-Sha256", &metadata.sha256);
    resp.set_header("X-Content-Length", metadata.size.to_string());
    resp.set_header("Accept-Ranges", "bytes");
    add_cors_headers(&mut resp);

    Ok(resp)
}

/// GET /<sha256>.hls - Serve HLS master manifest
fn handle_get_hls_master(req: Request, path: &str) -> Result<Response> {
    // Extract hash from path (remove leading / and .hls suffix)
    let path_trimmed = path.trim_start_matches('/');
    let hash = path_trimmed
        .strip_suffix(".hls")
        .ok_or_else(|| BlossomError::BadRequest("Invalid HLS path".into()))?;

    // Validate hash format
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BlossomError::BadRequest("Invalid hash in path".into()));
    }
    let hash = hash.to_lowercase();

    // Check metadata for access control and transcode status
    let metadata = get_blob_metadata(&hash)?;

    if let Some(ref meta) = metadata {
        // Handle banned content
        if meta.status == BlobStatus::Banned {
            return Err(BlossomError::NotFound("Content not found".into()));
        }

        // Handle restricted content
        if meta.status == BlobStatus::Restricted {
            if let Ok(Some(auth)) = optional_auth(&req, AuthAction::List) {
                if auth.pubkey.to_lowercase() != meta.owner.to_lowercase() {
                    return Err(BlossomError::NotFound("Content not found".into()));
                }
            } else {
                return Err(BlossomError::NotFound("Content not found".into()));
            }
        }

        // Check transcode status
        match meta.transcode_status {
            Some(TranscodeStatus::Complete) => {
                // Transcoding done, serve the manifest
            }
            Some(TranscodeStatus::Processing) => {
                // Transcoding in progress, return 202 Accepted with Retry-After
                let mut resp = Response::from_status(StatusCode::ACCEPTED);
                resp.set_header("Retry-After", "5");
                resp.set_header("Content-Type", "application/json");
                resp.set_body(r#"{"status":"processing","message":"HLS transcoding in progress"}"#);
                add_cors_headers(&mut resp);
                return Ok(resp);
            }
            Some(TranscodeStatus::Failed) => {
                return Err(BlossomError::Internal("HLS transcoding failed".into()));
            }
            Some(TranscodeStatus::Pending) | None => {
                // Not yet started - trigger on-demand transcoding
                // Update status to Processing first to prevent duplicate triggers
                use crate::metadata::update_transcode_status;
                if let Err(e) = update_transcode_status(&hash, TranscodeStatus::Processing) {
                    eprintln!("[HLS] Failed to update transcode status: {}", e);
                }

                // Trigger transcoding (fire and forget)
                let _ = trigger_on_demand_transcoding(&hash, &meta.owner);

                // Return 202 Accepted with Retry-After
                let mut resp = Response::from_status(StatusCode::ACCEPTED);
                resp.set_header("Retry-After", "10");
                resp.set_header("Content-Type", "application/json");
                resp.set_body(r#"{"status":"processing","message":"HLS transcoding started, please retry in 10 seconds"}"#);
                add_cors_headers(&mut resp);
                return Ok(resp);
            }
        }
    } else {
        return Err(BlossomError::NotFound("Content not found".into()));
    }

    // Download master manifest from GCS
    let gcs_path = format!("{}/hls/master.m3u8", hash);
    let result = download_hls_content(&gcs_path)?;
    let mut resp = result;

    let c2pa_manifest_id = resp
        .get_header_str("x-goog-meta-c2pa-manifest-id")
        .map(|s| s.to_string());
    let source_sha256 = resp
        .get_header_str("x-goog-meta-source-sha256")
        .map(|s| s.to_string());

    // Set correct content type for HLS manifest
    resp.set_header("Content-Type", "application/vnd.apple.mpegurl");
    resp.set_header("Cache-Control", "public, max-age=31536000"); // HLS manifests are immutable for VOD
    resp.set_header("X-Sha256", &hash);
    if let Some(c2pa) = c2pa_manifest_id {
        resp.set_header("X-C2PA-Manifest-Id", &c2pa);
    }
    if let Some(source_hash) = source_sha256 {
        resp.set_header("X-Source-Sha256", &source_hash);
    }
    add_cors_headers(&mut resp);

    Ok(resp)
}

/// HEAD /<sha256>.hls - Check HLS master manifest existence
fn handle_head_hls_master(path: &str) -> Result<Response> {
    // Extract hash from path
    let path_trimmed = path.trim_start_matches('/');
    let hash = path_trimmed
        .strip_suffix(".hls")
        .ok_or_else(|| BlossomError::BadRequest("Invalid HLS path".into()))?;

    // Validate hash format
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BlossomError::BadRequest("Invalid hash in path".into()));
    }
    let hash = hash.to_lowercase();

    // Check metadata for transcode status
    let metadata = get_blob_metadata(&hash)?
        .ok_or_else(|| BlossomError::NotFound("Content not found".into()))?;

    // Don't reveal restricted/banned content
    if metadata.status == BlobStatus::Restricted || metadata.status == BlobStatus::Banned {
        return Err(BlossomError::NotFound("Content not found".into()));
    }

    match metadata.transcode_status {
        Some(TranscodeStatus::Complete) => {
            let mut resp = Response::from_status(StatusCode::OK);
            resp.set_header("Content-Type", "application/vnd.apple.mpegurl");
            resp.set_header("X-Sha256", &hash);
            add_cors_headers(&mut resp);
            Ok(resp)
        }
        Some(TranscodeStatus::Processing) => {
            let mut resp = Response::from_status(StatusCode::ACCEPTED);
            resp.set_header("Retry-After", "5");
            add_cors_headers(&mut resp);
            Ok(resp)
        }
        _ => Err(BlossomError::NotFound("HLS not available".into())),
    }
}

/// GET /<sha256>/hls/* - Serve HLS segments and variant playlists
fn handle_get_hls_content(_req: Request, path: &str) -> Result<Response> {
    // Path format: /{hash}/hls/{filename}
    // Extract hash and validate
    let path_trimmed = path.trim_start_matches('/');
    let parts: Vec<&str> = path_trimmed.splitn(3, '/').collect();

    if parts.len() < 3 || parts[1] != "hls" {
        return Err(BlossomError::BadRequest("Invalid HLS path format".into()));
    }

    let hash = parts[0];
    let filename = parts[2];

    // Validate hash format
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BlossomError::BadRequest("Invalid hash in path".into()));
    }
    let hash = hash.to_lowercase();

    // Construct GCS path
    let gcs_path = format!("{}/hls/{}", hash, filename);

    // Try to download from GCS first
    match download_hls_content(&gcs_path) {
        Ok(mut resp) => {
            let c2pa_manifest_id = resp
                .get_header_str("x-goog-meta-c2pa-manifest-id")
                .map(|s| s.to_string());
            let source_sha256 = resp
                .get_header_str("x-goog-meta-source-sha256")
                .map(|s| s.to_string());

            // Set content type based on file extension
            let content_type = if filename.ends_with(".m3u8") {
                "application/vnd.apple.mpegurl"
            } else if filename.ends_with(".ts") {
                "video/mp2t"
            } else {
                "application/octet-stream"
            };

            resp.set_header("Content-Type", content_type);
            resp.set_header("Cache-Control", "public, max-age=31536000"); // Immutable for VOD
            resp.set_header("X-Sha256", &hash);
            if let Some(c2pa) = c2pa_manifest_id {
                resp.set_header("X-C2PA-Manifest-Id", &c2pa);
            }
            if let Some(source_hash) = source_sha256 {
                resp.set_header("X-Source-Sha256", &source_hash);
            }
            add_cors_headers(&mut resp);
            Ok(resp)
        }
        Err(BlossomError::NotFound(_)) if filename == "master.m3u8" => {
            // HLS not found - check metadata and trigger on-demand transcoding
            let metadata = get_blob_metadata(&hash)?;

            if let Some(ref meta) = metadata {
                // Handle banned content
                if meta.status == BlobStatus::Banned {
                    return Err(BlossomError::NotFound("Content not found".into()));
                }

                match meta.transcode_status {
                    Some(TranscodeStatus::Complete) => {
                        // Metadata says complete but file not in GCS - re-trigger
                        eprintln!("[HLS] master.m3u8 not found in GCS for {} despite Complete status, re-triggering", hash);
                        use crate::metadata::update_transcode_status;
                        let _ = update_transcode_status(&hash, TranscodeStatus::Processing);
                        let _ = trigger_on_demand_transcoding(&hash, &meta.owner);

                        let mut resp = Response::from_status(StatusCode::ACCEPTED);
                        resp.set_header("Retry-After", "10");
                        resp.set_header("Content-Type", "application/json");
                        resp.set_body(r#"{"status":"processing","message":"HLS transcoding re-triggered, please retry"}"#);
                        add_cors_headers(&mut resp);
                        Ok(resp)
                    }
                    Some(TranscodeStatus::Processing) => {
                        let mut resp = Response::from_status(StatusCode::ACCEPTED);
                        resp.set_header("Retry-After", "5");
                        resp.set_header("Content-Type", "application/json");
                        resp.set_body(r#"{"status":"processing","message":"HLS transcoding in progress"}"#);
                        add_cors_headers(&mut resp);
                        Ok(resp)
                    }
                    Some(TranscodeStatus::Failed) => {
                        // Failed previously - re-trigger
                        eprintln!("[HLS] Re-triggering failed transcode for {}", hash);
                        use crate::metadata::update_transcode_status;
                        let _ = update_transcode_status(&hash, TranscodeStatus::Processing);
                        let _ = trigger_on_demand_transcoding(&hash, &meta.owner);

                        let mut resp = Response::from_status(StatusCode::ACCEPTED);
                        resp.set_header("Retry-After", "10");
                        resp.set_header("Content-Type", "application/json");
                        resp.set_body(r#"{"status":"processing","message":"HLS transcoding re-started, please retry"}"#);
                        add_cors_headers(&mut resp);
                        Ok(resp)
                    }
                    Some(TranscodeStatus::Pending) | None => {
                        // Not yet started - trigger on-demand transcoding
                        use crate::metadata::update_transcode_status;
                        if let Err(e) = update_transcode_status(&hash, TranscodeStatus::Processing) {
                            eprintln!("[HLS] Failed to update transcode status: {}", e);
                        }
                        let _ = trigger_on_demand_transcoding(&hash, &meta.owner);

                        let mut resp = Response::from_status(StatusCode::ACCEPTED);
                        resp.set_header("Retry-After", "10");
                        resp.set_header("Content-Type", "application/json");
                        resp.set_body(r#"{"status":"processing","message":"HLS transcoding started, please retry in 10 seconds"}"#);
                        add_cors_headers(&mut resp);
                        Ok(resp)
                    }
                }
            } else {
                Err(BlossomError::NotFound("Content not found".into()))
            }
        }
        Err(e) => Err(e),
    }
}

/// HEAD /<sha256>/hls/* - Check HLS content existence
fn handle_head_hls_content(path: &str) -> Result<Response> {
    // Path format: /{hash}/hls/{filename}
    let path_trimmed = path.trim_start_matches('/');
    let parts: Vec<&str> = path_trimmed.splitn(3, '/').collect();

    if parts.len() < 3 || parts[1] != "hls" {
        return Err(BlossomError::BadRequest("Invalid HLS path format".into()));
    }

    let hash = parts[0];
    let filename = parts[2];

    // Validate hash format
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BlossomError::BadRequest("Invalid hash in path".into()));
    }

    // Check if file exists in GCS
    let gcs_path = format!("{}/hls/{}", hash.to_lowercase(), filename);

    // Try to get the content (HEAD-like check)
    download_hls_content(&gcs_path)?;

    let content_type = if filename.ends_with(".m3u8") {
        "application/vnd.apple.mpegurl"
    } else if filename.ends_with(".ts") {
        "video/mp2t"
    } else {
        "application/octet-stream"
    };

    let mut resp = Response::from_status(StatusCode::OK);
    resp.set_header("Content-Type", content_type);
    resp.set_header("X-Sha256", hash.to_lowercase());
    add_cors_headers(&mut resp);

    Ok(resp)
}

/// Download HLS content from GCS
fn download_hls_content(gcs_path: &str) -> Result<Response> {
    use crate::storage::download_hls_from_gcs;
    download_hls_from_gcs(gcs_path)
}

/// Valid quality variant suffixes
const QUALITY_VARIANTS: &[(&str, &str)] = &[
    ("/720p", "stream_720p.ts"),
    ("/480p", "stream_480p.ts"),
];

/// Check if a path is a quality variant request like /{hash}/720p
fn is_quality_variant_path(path: &str) -> bool {
    let path = path.trim_start_matches('/');
    for (suffix, _) in QUALITY_VARIANTS {
        let suffix = suffix.trim_start_matches('/');
        if path.ends_with(suffix) {
            let hash_part = &path[..path.len() - suffix.len() - 1]; // -1 for the /
            if hash_part.len() == 64 && hash_part.chars().all(|c| c.is_ascii_hexdigit()) {
                return true;
            }
        }
    }
    false
}

/// Parse quality variant path into (hash, ts_filename)
fn parse_quality_variant_path(path: &str) -> Option<(String, &'static str)> {
    let path = path.trim_start_matches('/');
    for (suffix, ts_file) in QUALITY_VARIANTS {
        let suffix = suffix.trim_start_matches('/');
        if path.ends_with(suffix) {
            let hash_part = &path[..path.len() - suffix.len() - 1];
            if hash_part.len() == 64 && hash_part.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some((hash_part.to_lowercase(), ts_file));
            }
        }
    }
    None
}

/// GET /<sha256>/720p or /<sha256>/480p - Direct access to transcoded quality variant
fn handle_get_quality_variant(req: Request, path: &str) -> Result<Response> {
    let (hash, ts_filename) = parse_quality_variant_path(path)
        .ok_or_else(|| BlossomError::BadRequest("Invalid quality variant path".into()))?;

    // Check metadata for access control
    let metadata = get_blob_metadata(&hash)?;
    if let Some(ref meta) = metadata {
        if meta.status == BlobStatus::Banned {
            return Err(BlossomError::NotFound("Content not found".into()));
        }
        if meta.status == BlobStatus::Restricted {
            if let Ok(Some(auth)) = optional_auth(&req, AuthAction::List) {
                if auth.pubkey.to_lowercase() != meta.owner.to_lowercase() {
                    return Err(BlossomError::NotFound("Content not found".into()));
                }
            } else {
                return Err(BlossomError::NotFound("Content not found".into()));
            }
        }
    } else {
        return Err(BlossomError::NotFound("Content not found".into()));
    }

    let meta = metadata.as_ref().unwrap();
    let gcs_path = format!("{}/hls/{}", hash, ts_filename);

    match download_hls_content(&gcs_path) {
        Ok(mut resp) => {
            resp.set_header("Content-Type", "video/mp2t");
            resp.set_header("Cache-Control", "public, max-age=31536000");
            resp.set_header("Accept-Ranges", "bytes");
            add_cors_headers(&mut resp);
            Ok(resp)
        }
        Err(BlossomError::NotFound(_)) => {
            // HLS not ready - trigger on-demand transcoding
            match meta.transcode_status {
                Some(TranscodeStatus::Processing) => {
                    let mut resp = Response::from_status(StatusCode::ACCEPTED);
                    resp.set_header("Retry-After", "5");
                    resp.set_header("Content-Type", "application/json");
                    resp.set_body(r#"{"status":"processing","message":"Video is being transcoded, please retry"}"#);
                    add_cors_headers(&mut resp);
                    Ok(resp)
                }
                Some(TranscodeStatus::Complete) | Some(TranscodeStatus::Failed) | Some(TranscodeStatus::Pending) | None => {
                    use crate::metadata::update_transcode_status;
                    let _ = update_transcode_status(&hash, TranscodeStatus::Processing);
                    let _ = trigger_on_demand_transcoding(&hash, &meta.owner);

                    let mut resp = Response::from_status(StatusCode::ACCEPTED);
                    resp.set_header("Retry-After", "10");
                    resp.set_header("Content-Type", "application/json");
                    resp.set_body(r#"{"status":"processing","message":"Transcoding started, please retry in 10 seconds"}"#);
                    add_cors_headers(&mut resp);
                    Ok(resp)
                }
            }
        }
        Err(e) => Err(e),
    }
}

/// HEAD /<sha256>/720p or /<sha256>/480p
fn handle_head_quality_variant(path: &str) -> Result<Response> {
    let (hash, ts_filename) = parse_quality_variant_path(path)
        .ok_or_else(|| BlossomError::BadRequest("Invalid quality variant path".into()))?;

    let metadata = get_blob_metadata(&hash)?
        .ok_or_else(|| BlossomError::NotFound("Content not found".into()))?;

    if metadata.status == BlobStatus::Banned || metadata.status == BlobStatus::Restricted {
        return Err(BlossomError::NotFound("Content not found".into()));
    }

    let gcs_path = format!("{}/hls/{}", hash, ts_filename);
    download_hls_content(&gcs_path)?;

    let mut resp = Response::from_status(StatusCode::OK);
    resp.set_header("Content-Type", "video/mp2t");
    resp.set_header("Accept-Ranges", "bytes");
    add_cors_headers(&mut resp);
    Ok(resp)
}

/// Maximum size for in-process upload (500KB) - larger files proxy to Cloud Run
const CLOUD_RUN_THRESHOLD: u64 = 500 * 1024;

/// Cloud Run upload backend name (must match fastly.toml)
const CLOUD_RUN_BACKEND: &str = "cloud_run_upload";

/// Cloud Run host for on-demand thumbnail generation
const CLOUD_RUN_THUMBNAIL_HOST: &str = "blossom-upload-rust-149672065768.us-central1.run.app";

/// Cloud Run host for on-demand transcoding
const CLOUD_RUN_TRANSCODER_HOST: &str = "divine-transcoder-149672065768.us-central1.run.app";

/// Generate thumbnail on-demand by proxying to Cloud Run
fn generate_thumbnail_on_demand(hash: &str) -> Result<Response> {
    let url = format!("https://{}/thumbnail/{}", CLOUD_RUN_THUMBNAIL_HOST, hash);

    let mut proxy_req = Request::new(Method::GET, &url);
    proxy_req.set_header("Host", CLOUD_RUN_THUMBNAIL_HOST);

    let resp = proxy_req
        .send(CLOUD_RUN_BACKEND)
        .map_err(|e| BlossomError::StorageError(format!("Cloud Run thumbnail request failed: {}", e)))?;

    match resp.get_status() {
        StatusCode::OK => Ok(resp),
        StatusCode::NOT_FOUND => Err(BlossomError::NotFound("Video not found for thumbnail generation".into())),
        status => Err(BlossomError::StorageError(format!("Thumbnail generation failed with status: {}", status))),
    }
}

/// Trigger on-demand HLS transcoding via Cloud Run transcoder service
/// This is fire-and-forget - we update metadata to Processing and return immediately
fn trigger_on_demand_transcoding(hash: &str, owner: &str) -> Result<()> {
    let url = format!("https://{}/transcode", CLOUD_RUN_TRANSCODER_HOST);

    let body = format!(
        r#"{{"hash":"{}","owner":"{}"}}"#,
        hash, owner
    );

    let mut proxy_req = Request::new(Method::POST, &url);
    proxy_req.set_header("Host", CLOUD_RUN_TRANSCODER_HOST);
    proxy_req.set_header("Content-Type", "application/json");
    proxy_req.set_body(body);

    // Fire and forget - we don't wait for transcoding to complete
    // The transcoder will callback via webhook when done
    match proxy_req.send_async(CLOUD_RUN_BACKEND) {
        Ok(_) => {
            eprintln!("[HLS] Triggered on-demand transcoding for {}", hash);
            Ok(())
        }
        Err(e) => {
            eprintln!("[HLS] Failed to trigger transcoding for {}: {}", hash, e);
            Err(BlossomError::Internal(format!("Failed to trigger transcoding: {}", e)))
        }
    }
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

    let base_url = get_base_url(&req);

    // Proxy to Cloud Run for:
    // 1. Large uploads (> 500KB) to avoid WASM memory limits
    // 2. Video uploads (any size) for thumbnail generation
    if content_length > CLOUD_RUN_THRESHOLD || is_video_mime_type(&content_type) {
        return handle_cloud_run_proxy(req, auth, content_type, content_length, base_url);
    }

    // For small files, buffer in memory (safe for <= 500KB)
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
            let descriptor = metadata.to_descriptor(&base_url);
            return Ok(json_response(StatusCode::OK, &descriptor));
        }
    }

    // Upload to GCS (with owner metadata for durability)
    upload_blob(
        &hash,
        fastly::Body::from(body_bytes),
        &content_type,
        actual_size,
        &auth.pubkey,
    )?;

    // Store metadata
    let metadata = BlobMetadata {
        sha256: hash.clone(),
        size: actual_size,
        mime_type: content_type.clone(),
        uploaded: current_timestamp(),
        owner: auth.pubkey.clone(),
        status: BlobStatus::Pending, // Start as pending for moderation
        thumbnail: None,
        moderation: None,
        transcode_status: if is_video_mime_type(&content_type) {
            Some(TranscodeStatus::Pending)
        } else {
            None
        },
        dim: None, // Set by transcoder webhook when transcoding completes
    };

    put_blob_metadata(&metadata)?;

    // Add to user's list
    add_to_user_list(&auth.pubkey, &hash)?;

    // Update admin indices (best effort - don't fail upload if these fail)
    let _ = update_stats_on_add(&metadata);
    let _ = add_to_recent_index(&hash);
    // Add user to index if new, increment unique_uploaders count
    if let Ok(is_new) = add_to_user_index(&auth.pubkey) {
        if is_new {
            let _ = crate::metadata::increment_unique_uploaders();
        }
    }

    // Return blob descriptor
    let descriptor = metadata.to_descriptor(&base_url);
    let mut resp = json_response(StatusCode::OK, &descriptor);
    add_cors_headers(&mut resp);

    Ok(resp)
}

/// Handle large uploads by proxying to Cloud Run
/// Fastly Compute has WASM memory limits (~5MB), so large files must be proxied
fn handle_cloud_run_proxy(
    mut req: Request,
    auth: crate::blossom::BlossomAuthEvent,
    content_type: String,
    content_length: u64,
    base_url: String,
) -> Result<Response> {
    // Get the original Authorization header to forward
    let auth_header = req
        .get_header(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| BlossomError::AuthRequired("Missing authorization header".into()))?;

    // Get the body to forward
    let body = req.take_body();

    // Build request to Cloud Run
    // NOTE: Use the actual Cloud Run hostname as the Host header, not the custom domain
    // Cloud Run uses the Host header for routing - if the custom domain isn't configured,
    // Cloud Run returns 404
    const CLOUD_RUN_HOST: &str = "blossom-upload-rust-149672065768.us-central1.run.app";
    let mut proxy_req = Request::new(
        fastly::http::Method::PUT,
        format!("https://{}/upload", CLOUD_RUN_HOST),
    );
    proxy_req.set_header("Host", CLOUD_RUN_HOST);
    proxy_req.set_header(header::AUTHORIZATION, &auth_header);
    proxy_req.set_header(header::CONTENT_TYPE, &content_type);
    proxy_req.set_header(header::CONTENT_LENGTH, content_length.to_string());
    proxy_req.set_body(body);

    // Send to Cloud Run
    let mut proxy_resp = proxy_req
        .send(CLOUD_RUN_BACKEND)
        .map_err(|e| BlossomError::Internal(format!("Failed to proxy to Cloud Run: {}", e)))?;

    // Check for errors from Cloud Run
    if !proxy_resp.get_status().is_success() {
        let status = proxy_resp.get_status();
        let body = proxy_resp.take_body().into_string();
        return Err(BlossomError::Internal(format!(
            "Cloud Run upload failed ({}): {}",
            status, body
        )));
    }

    // Parse Cloud Run response to get the hash
    let resp_body = proxy_resp.take_body().into_string();
    let cloud_run_resp: serde_json::Value = serde_json::from_str(&resp_body)
        .map_err(|e| BlossomError::Internal(format!("Invalid Cloud Run response: {}", e)))?;

    let hash = cloud_run_resp["sha256"]
        .as_str()
        .ok_or_else(|| BlossomError::Internal("Missing sha256 in Cloud Run response".into()))?
        .to_string();

    let size = cloud_run_resp["size"]
        .as_u64()
        .unwrap_or(content_length);

    // Parse thumbnail URL if present (for video uploads)
    let thumbnail_url = cloud_run_resp["thumbnail_url"]
        .as_str()
        .map(|s| s.to_string());

    // Parse video dimensions if present (from ffprobe in upload service)
    let dim = cloud_run_resp["dim"]
        .as_str()
        .map(|s| s.to_string());

    // Check if metadata already exists (dedupe case)
    if let Some(mut metadata) = get_blob_metadata(&hash)? {
        // Even for dedupe, update dim if we got it and it wasn't set before
        if dim.is_some() && metadata.dim.is_none() {
            metadata.dim = dim;
            let _ = put_blob_metadata(&metadata);
        }
        let descriptor = metadata.to_descriptor(&base_url);
        let mut resp = json_response(StatusCode::OK, &descriptor);
        add_cors_headers(&mut resp);
        return Ok(resp);
    }

    // Store metadata in Fastly's KV store
    // For video uploads, transcode_status starts as Pending (Cloud Run upload service triggers transcoder)
    let metadata = BlobMetadata {
        sha256: hash.clone(),
        size,
        mime_type: content_type.clone(),
        uploaded: current_timestamp(),
        owner: auth.pubkey.clone(),
        status: BlobStatus::Pending,
        thumbnail: thumbnail_url,
        moderation: None,
        transcode_status: if is_video_mime_type(&content_type) {
            Some(TranscodeStatus::Pending)
        } else {
            None
        },
        dim: dim.clone(), // From ffprobe in upload service; updated by transcoder webhook
    };

    put_blob_metadata(&metadata)?;

    // Add to user's list
    add_to_user_list(&auth.pubkey, &hash)?;

    // Update admin indices (best effort - don't fail upload if these fail)
    let _ = update_stats_on_add(&metadata);
    let _ = add_to_recent_index(&hash);
    // Add user to index if new, increment unique_uploaders count
    if let Ok(is_new) = add_to_user_index(&auth.pubkey) {
        if is_new {
            let _ = crate::metadata::increment_unique_uploaders();
        }
    }

    // Return blob descriptor with Fastly's CDN URL
    let descriptor = metadata.to_descriptor(&base_url);
    let mut resp = json_response(StatusCode::OK, &descriptor);
    add_cors_headers(&mut resp);

    Ok(resp)
}

/// HEAD /upload - BUD-06 upload pre-validation
/// Clients can send X-SHA-256, X-Content-Length, X-Content-Type headers
/// to check if an upload would be accepted before sending the full file
fn handle_upload_requirements(req: Request) -> Result<Response> {
    // Check for BUD-06 pre-validation headers
    let sha256 = req
        .get_header("X-SHA-256")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let content_length: Option<u64> = req
        .get_header("X-Content-Length")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse().ok());
    let content_type = req
        .get_header("X-Content-Type")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // If pre-validation headers provided, validate them
    if sha256.is_some() || content_length.is_some() || content_type.is_some() {
        // Validate SHA-256 format (must be 64 hex chars)
        if let Some(ref hash) = sha256 {
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                let mut resp = Response::from_status(StatusCode::BAD_REQUEST);
                resp.set_header("X-Reason", "Invalid X-SHA-256 format (must be 64 hex characters)");
                add_cors_headers(&mut resp);
                return Ok(resp);
            }

            // Check if blob already exists (optimization - client can skip upload)
            if blob_exists(hash)? {
                let mut resp = Response::from_status(StatusCode::OK);
                resp.set_header("X-Reason", "Blob already exists");
                resp.set_header("X-Exists", "true");
                add_cors_headers(&mut resp);
                return Ok(resp);
            }
        }

        // Validate content length
        if let Some(size) = content_length {
            if size > MAX_UPLOAD_SIZE {
                let mut resp = Response::from_status(StatusCode::from_u16(413).unwrap());
                resp.set_header("X-Reason", &format!(
                    "File too large. Maximum size is {} bytes",
                    MAX_UPLOAD_SIZE
                ));
                add_cors_headers(&mut resp);
                return Ok(resp);
            }
            if size == 0 {
                let mut resp = Response::from_status(StatusCode::BAD_REQUEST);
                resp.set_header("X-Reason", "File cannot be empty");
                add_cors_headers(&mut resp);
                return Ok(resp);
            }
        }

        // Content type validation - we accept all types, so this always passes
        // If we wanted to restrict, we'd check content_type here

        // All validations passed
        let mut resp = Response::from_status(StatusCode::OK);
        resp.set_header("X-Reason", "Upload would be accepted");
        add_cors_headers(&mut resp);
        return Ok(resp);
    }

    // No pre-validation headers - return general requirements
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

    // Get metadata before deletion for stats update
    let metadata = get_blob_metadata(&hash)?;

    // Delete from B2
    storage_delete(&hash)?;

    // Delete metadata
    delete_blob_metadata(&hash)?;

    // Remove from user's list
    remove_from_user_list(&auth.pubkey, &hash)?;

    // Update admin indices (best effort)
    if let Some(meta) = metadata {
        let _ = update_stats_on_remove(&meta);
    }
    let _ = remove_from_recent_index(&hash);

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

/// PUT /report - BUD-09 blob reporting
/// Accepts a NIP-56 report event in the body to report problematic content
fn handle_report(mut req: Request) -> Result<Response> {
    // Parse the report event from body
    let body = req.take_body().into_string();
    let report_event: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| BlossomError::BadRequest(format!("Invalid JSON: {}", e)))?;

    // Validate it's a NIP-56 report event (kind 1984)
    let kind = report_event["kind"].as_u64()
        .ok_or_else(|| BlossomError::BadRequest("Missing 'kind' field".into()))?;

    if kind != 1984 {
        return Err(BlossomError::BadRequest(format!(
            "Invalid event kind: expected 1984 (NIP-56 report), got {}",
            kind
        )));
    }

    // Extract x tags (blob sha256 hashes being reported)
    let tags = report_event["tags"].as_array()
        .ok_or_else(|| BlossomError::BadRequest("Missing 'tags' field".into()))?;

    let mut reported_hashes: Vec<String> = Vec::new();
    let mut report_type: Option<String> = None;

    for tag in tags {
        let tag_arr = tag.as_array();
        if let Some(arr) = tag_arr {
            if arr.len() >= 2 {
                let tag_name = arr[0].as_str().unwrap_or("");
                let tag_value = arr[1].as_str().unwrap_or("");

                if tag_name == "x" && tag_value.len() == 64 {
                    // Validate it's a valid hex hash
                    if tag_value.chars().all(|c| c.is_ascii_hexdigit()) {
                        reported_hashes.push(tag_value.to_string());
                    }
                }

                // Capture report type from "report" tag if present
                if tag_name == "report" {
                    report_type = Some(tag_value.to_string());
                }
            }
        }
    }

    if reported_hashes.is_empty() {
        return Err(BlossomError::BadRequest(
            "No valid 'x' tags found with blob hashes".into()
        ));
    }

    // Get report content (description)
    let content = report_event["content"].as_str().unwrap_or("");

    // Get reporter pubkey
    let reporter = report_event["pubkey"].as_str()
        .ok_or_else(|| BlossomError::BadRequest("Missing 'pubkey' field".into()))?;

    // Log the report for operator review
    // In production, this would be stored in a database or sent to a moderation queue
    eprintln!(
        "BUD-09 REPORT: reporter={}, hashes={:?}, type={:?}, content={}",
        reporter,
        reported_hashes,
        report_type,
        content
    );

    // Check which blobs actually exist
    let mut found_blobs = 0;
    for hash in &reported_hashes {
        if let Ok(Some(_)) = get_blob_metadata(hash) {
            found_blobs += 1;
        }
    }

    // Return success - report received
    let response = serde_json::json!({
        "status": "received",
        "reported_blobs": reported_hashes.len(),
        "found_blobs": found_blobs,
        "message": "Report submitted for review"
    });

    let mut resp = json_response(StatusCode::OK, &response);
    add_cors_headers(&mut resp);

    Ok(resp)
}

/// PUT /mirror - BUD-04 blob mirroring
/// Downloads a blob from a remote URL and stores it locally
/// Proxies to Cloud Run which handles the actual fetch, hash, and upload
fn handle_mirror(mut req: Request) -> Result<Response> {
    // Validate auth (upload permission required)
    let auth = validate_auth(&req, AuthAction::Upload)?;

    // Parse request body as JSON
    let body = req.take_body().into_string();
    if body.is_empty() {
        return Err(BlossomError::BadRequest("Request body required".into()));
    }

    let mirror_req: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| BlossomError::BadRequest(format!("Invalid JSON: {}", e)))?;

    // Extract and validate URL
    let url = mirror_req["url"]
        .as_str()
        .ok_or_else(|| BlossomError::BadRequest("Missing 'url' field".into()))?;

    // Basic URL validation
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(BlossomError::BadRequest("Invalid URL: must start with http:// or https://".into()));
    }

    // Get expected hash from auth event's x tag (optional per BUD-04)
    let expected_hash = auth.get_hash();

    let base_url = get_base_url(&req);

    // Proxy to Cloud Run /migrate endpoint which handles the actual work
    // This avoids WASM memory limits for large blobs
    // Include owner pubkey for GCS metadata durability
    let migrate_body = if let Some(hash) = &expected_hash {
        serde_json::json!({
            "source_url": url,
            "expected_hash": hash,
            "owner": &auth.pubkey
        })
    } else {
        serde_json::json!({
            "source_url": url,
            "owner": &auth.pubkey
        })
    };

    let migrate_json = serde_json::to_string(&migrate_body)
        .map_err(|e| BlossomError::Internal(format!("JSON error: {}", e)))?;

    // Use actual Cloud Run hostname - see handle_cloud_run_proxy comment
    const CLOUD_RUN_HOST: &str = "blossom-upload-rust-149672065768.us-central1.run.app";
    let mut proxy_req = Request::new(
        fastly::http::Method::POST,
        format!("https://{}/migrate", CLOUD_RUN_HOST),
    );
    proxy_req.set_header("Host", CLOUD_RUN_HOST);
    proxy_req.set_header("Content-Type", "application/json");
    proxy_req.set_header("Content-Length", migrate_json.len().to_string());
    proxy_req.set_body(migrate_json);

    let mut proxy_resp = proxy_req
        .send(CLOUD_RUN_BACKEND)
        .map_err(|e| BlossomError::Internal(format!("Failed to proxy to Cloud Run: {}", e)))?;

    if !proxy_resp.get_status().is_success() {
        let status = proxy_resp.get_status();
        let body = proxy_resp.take_body().into_string();
        return Err(BlossomError::Internal(format!(
            "Mirror failed ({}): {}",
            status, body
        )));
    }

    // Parse Cloud Run response
    let resp_body = proxy_resp.take_body().into_string();
    let cloud_run_resp: serde_json::Value = serde_json::from_str(&resp_body)
        .map_err(|e| BlossomError::Internal(format!("Invalid Cloud Run response: {}", e)))?;

    let hash = cloud_run_resp["sha256"]
        .as_str()
        .ok_or_else(|| BlossomError::Internal("Missing sha256 in response".into()))?
        .to_string();

    let size = cloud_run_resp["size"].as_u64().unwrap_or(0);
    let content_type = cloud_run_resp["type"]
        .as_str()
        .unwrap_or("application/octet-stream")
        .to_string();

    // Check if metadata already exists
    if let Some(metadata) = get_blob_metadata(&hash)? {
        let descriptor = metadata.to_descriptor(&base_url);
        let mut resp = json_response(StatusCode::OK, &descriptor);
        add_cors_headers(&mut resp);
        return Ok(resp);
    }

    // Store metadata
    let metadata = BlobMetadata {
        sha256: hash.clone(),
        size,
        mime_type: content_type.clone(),
        uploaded: current_timestamp(),
        owner: auth.pubkey.clone(),
        status: BlobStatus::Pending,
        thumbnail: None,
        moderation: None,
        transcode_status: if is_video_mime_type(&content_type) {
            Some(TranscodeStatus::Pending)
        } else {
            None
        },
        dim: None, // Set by transcoder webhook when transcoding completes
    };

    put_blob_metadata(&metadata)?;
    add_to_user_list(&auth.pubkey, &hash)?;

    // Update admin indices (best effort - don't fail mirror if these fail)
    let _ = update_stats_on_add(&metadata);
    let _ = add_to_recent_index(&hash);
    // Add user to index if new, increment unique_uploaders count
    if let Ok(is_new) = add_to_user_index(&auth.pubkey) {
        if is_new {
            let _ = crate::metadata::increment_unique_uploaders();
        }
    }

    // Return blob descriptor per BUD-04
    let descriptor = metadata.to_descriptor(&base_url);
    let mut resp = json_response(StatusCode::OK, &descriptor);
    add_cors_headers(&mut resp);

    Ok(resp)
}

/// POST /admin/moderate - Webhook from divine-moderation-service
/// Receives moderation decisions and updates blob status
fn handle_admin_moderate(mut req: Request) -> Result<Response> {
    // Try to get webhook secret from secret store (optional)
    let expected_secret: Option<String> = fastly::secret_store::SecretStore::open("blossom_secrets")
        .ok()
        .and_then(|store| store.get("webhook_secret"))
        .map(|secret| {
            String::from_utf8(secret.plaintext().to_vec())
                .unwrap_or_default()
        });

    // Get Authorization header
    let auth_header = req
        .get_header(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Validate secret if configured
    if let Some(ref expected) = expected_secret {
        match auth_header {
            Some(ref header) if header.starts_with("Bearer ") => {
                let provided = header.strip_prefix("Bearer ").unwrap_or("");
                if provided != expected.trim() {
                    eprintln!("[ADMIN] Invalid webhook secret");
                    return Err(BlossomError::Forbidden("Invalid webhook secret".into()));
                }
            }
            _ => {
                eprintln!("[ADMIN] Missing or invalid Authorization header");
                return Err(BlossomError::AuthRequired("Webhook secret required".into()));
            }
        }
    } else {
        // Fail closed: reject requests if webhook_secret is not configured
        eprintln!("[ADMIN] webhook_secret not configured, rejecting request");
        return Err(BlossomError::Forbidden("Webhook secret not configured".into()));
    }

    // Parse JSON body
    let body = req.take_body().into_string();
    let payload: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| BlossomError::BadRequest(format!("Invalid JSON: {}", e)))?;

    let sha256 = payload["sha256"]
        .as_str()
        .ok_or_else(|| BlossomError::BadRequest("Missing 'sha256' field".into()))?;

    let action = payload["action"]
        .as_str()
        .ok_or_else(|| BlossomError::BadRequest("Missing 'action' field".into()))?;

    eprintln!("[ADMIN] Moderation webhook: sha256={}, action={}", sha256, action);

    // Validate sha256 format
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BlossomError::BadRequest("Invalid sha256 format".into()));
    }

    // Map action to BlobStatus
    let new_status = match action.to_uppercase().as_str() {
        "BLOCK" | "BAN" | "PERMANENT_BAN" => BlobStatus::Banned,
        "RESTRICT" | "AGE_RESTRICTED" => BlobStatus::Restricted,
        "APPROVE" | "SAFE" => BlobStatus::Active,
        _ => {
            return Err(BlossomError::BadRequest(format!(
                "Unknown action: {}. Expected BLOCK, RESTRICT, or APPROVE",
                action
            )));
        }
    };

    // Update blob status
    match update_blob_status(sha256, new_status) {
        Ok(()) => {
            eprintln!("[ADMIN] Updated blob {} to status {:?}", sha256, new_status);
            let response = serde_json::json!({
                "success": true,
                "sha256": sha256,
                "status": format!("{:?}", new_status).to_lowercase(),
                "message": "Blob status updated"
            });
            let mut resp = json_response(StatusCode::OK, &response);
            add_cors_headers(&mut resp);
            Ok(resp)
        }
        Err(BlossomError::NotFound(_)) => {
            eprintln!("[ADMIN] Blob {} not found", sha256);
            let response = serde_json::json!({
                "success": false,
                "sha256": sha256,
                "error": "Blob not found"
            });
            let mut resp = json_response(StatusCode::NOT_FOUND, &response);
            add_cors_headers(&mut resp);
            Ok(resp)
        }
        Err(e) => {
            eprintln!("[ADMIN] Failed to update blob {}: {:?}", sha256, e);
            Err(e)
        }
    }
}

/// POST /admin/transcode-status - Webhook from divine-transcoder service
/// Updates transcode status for a blob after HLS generation
fn handle_transcode_status(mut req: Request) -> Result<Response> {
    // Try to get webhook secret from secret store (same as moderation webhook)
    let expected_secret: Option<String> = fastly::secret_store::SecretStore::open("blossom_secrets")
        .ok()
        .and_then(|store| store.get("webhook_secret"))
        .map(|secret| {
            String::from_utf8(secret.plaintext().to_vec())
                .unwrap_or_default()
        });

    // Get Authorization header
    let auth_header = req
        .get_header(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Validate secret if configured
    if let Some(ref expected) = expected_secret {
        match auth_header {
            Some(ref header) if header.starts_with("Bearer ") => {
                let provided = header.strip_prefix("Bearer ").unwrap_or("");
                if provided != expected.trim() {
                    eprintln!("[TRANSCODE] Invalid webhook secret");
                    return Err(BlossomError::Forbidden("Invalid webhook secret".into()));
                }
            }
            _ => {
                eprintln!("[TRANSCODE] Missing or invalid Authorization header");
                return Err(BlossomError::AuthRequired("Webhook secret required".into()));
            }
        }
    } else {
        // Fail closed: reject requests if webhook_secret is not configured
        eprintln!("[TRANSCODE] webhook_secret not configured, rejecting request");
        return Err(BlossomError::Forbidden("Webhook secret not configured".into()));
    }

    // Parse JSON body
    let body = req.take_body().into_string();
    let payload: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| BlossomError::BadRequest(format!("Invalid JSON: {}", e)))?;

    let sha256 = payload["sha256"]
        .as_str()
        .ok_or_else(|| BlossomError::BadRequest("Missing 'sha256' field".into()))?;

    let status_str = payload["status"]
        .as_str()
        .ok_or_else(|| BlossomError::BadRequest("Missing 'status' field".into()))?;

    // Optional new_size field - provided when faststart optimization replaces the original file
    let new_size = payload["new_size"].as_u64();

    // Optional display dimensions from transcoder's ffprobe
    let display_width = payload["display_width"].as_u64().map(|v| v as u32);
    let display_height = payload["display_height"].as_u64().map(|v| v as u32);
    let dim = match (display_width, display_height) {
        (Some(w), Some(h)) if w > 0 && h > 0 => Some(format!("{}x{}", w, h)),
        _ => None,
    };

    eprintln!(
        "[TRANSCODE] Status webhook: sha256={}, status={}, new_size={:?}, dim={:?}",
        sha256, status_str, new_size, dim
    );

    // Validate sha256 format
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BlossomError::BadRequest("Invalid sha256 format".into()));
    }

    // Map status string to TranscodeStatus
    let new_status = match status_str.to_lowercase().as_str() {
        "pending" => TranscodeStatus::Pending,
        "processing" => TranscodeStatus::Processing,
        "complete" | "completed" => TranscodeStatus::Complete,
        "failed" | "error" => TranscodeStatus::Failed,
        _ => {
            return Err(BlossomError::BadRequest(format!(
                "Unknown status: {}. Expected pending, processing, complete, or failed",
                status_str
            )));
        }
    };

    // Update transcode status (and optionally file size and dimensions if provided)
    use crate::metadata::update_transcode_status_with_size;
    match update_transcode_status_with_size(sha256, new_status, new_size, dim.clone()) {
        Ok(()) => {
            if let Some(ref d) = dim {
                eprintln!(
                    "[TRANSCODE] Updated blob {} to transcode status {:?} with dim {}",
                    sha256, new_status, d
                );
            } else if let Some(size) = new_size {
                eprintln!(
                    "[TRANSCODE] Updated blob {} to transcode status {:?} with new size {}",
                    sha256, new_status, size
                );
            } else {
                eprintln!("[TRANSCODE] Updated blob {} to transcode status {:?}", sha256, new_status);
            }
            let response = serde_json::json!({
                "success": true,
                "sha256": sha256,
                "transcode_status": format!("{:?}", new_status).to_lowercase(),
                "message": "Transcode status updated"
            });
            let mut resp = json_response(StatusCode::OK, &response);
            add_cors_headers(&mut resp);
            Ok(resp)
        }
        Err(BlossomError::NotFound(_)) => {
            eprintln!("[TRANSCODE] Blob {} not found", sha256);
            let response = serde_json::json!({
                "success": false,
                "sha256": sha256,
                "error": "Blob not found"
            });
            let mut resp = json_response(StatusCode::NOT_FOUND, &response);
            add_cors_headers(&mut resp);
            Ok(resp)
        }
        Err(e) => {
            eprintln!("[TRANSCODE] Failed to update blob {}: {:?}", sha256, e);
            Err(e)
        }
    }
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
                    <span class="endpoint-path">/&lt;sha256&gt;[.ext]</span>
                    <p class="endpoint-desc">Retrieve a blob by its SHA-256 hash. Supports optional file extension and range requests. Use <code>.jpg</code> extension to get video thumbnails. <em>(BUD-01)</em></p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-get">GET</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/&lt;sha256&gt;.hls</span>
                    <p class="endpoint-desc">Get HLS master manifest for adaptive streaming. Automatically triggers on-demand transcoding for videos that haven't been transcoded yet. Returns <code>202 Accepted</code> with <code>Retry-After</code> header while transcoding is in progress.</p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-get">GET</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/&lt;sha256&gt;/hls/master.m3u8</span>
                    <p class="endpoint-desc">Alternative HLS manifest URL for player compatibility. Same behavior as the <code>.hls</code> endpoint above.</p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-get">GET</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/&lt;sha256&gt;/720p</span>
                    <p class="endpoint-desc">Direct download of the 720p H.264 transcoded variant (2.5 Mbps). Triggers transcoding on-demand if not yet available.</p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-get">GET</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/&lt;sha256&gt;/480p</span>
                    <p class="endpoint-desc">Direct download of the 480p H.264 transcoded variant (1 Mbps). Triggers transcoding on-demand if not yet available.</p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-head">HEAD</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/&lt;sha256&gt;[.ext]</span>
                    <p class="endpoint-desc">Check if a blob exists and get its metadata. <em>(BUD-01)</em></p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-put">PUT</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/upload</span>
                    <p class="endpoint-desc">Upload a new blob. Requires Nostr authentication (kind 24242 event). Video uploads automatically generate a thumbnail. <em>(BUD-02)</em></p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-head">HEAD</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/upload</span>
                    <p class="endpoint-desc">Pre-validate upload with X-SHA-256, X-Content-Length, X-Content-Type headers. <em>(BUD-06)</em></p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-get">GET</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/list/&lt;pubkey&gt;</span>
                    <p class="endpoint-desc">List all blobs uploaded by a public key. <em>(BUD-02)</em></p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-delete">DELETE</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/&lt;sha256&gt;</span>
                    <p class="endpoint-desc">Delete a blob. Requires Nostr authentication and ownership. <em>(BUD-02)</em></p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-put">PUT</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/report</span>
                    <p class="endpoint-desc">Report problematic content using NIP-56 events (kind 1984). <em>(BUD-09)</em></p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-put">PUT</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/mirror</span>
                    <p class="endpoint-desc">Mirror a blob from a remote URL. Requires Nostr authentication. <em>(BUD-04)</em></p>
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
                    <h3>Video Thumbnails</h3>
                    <p>Automatic JPEG thumbnail generation for uploaded videos, accessible at <code>/&lt;sha256&gt;.jpg</code>.</p>
                </div>
                <div class="feature">
                    <h3>HLS Video Streaming</h3>
                    <p>On-demand H.264 transcoding to 720p and 480p with HLS adaptive streaming. Direct quality access via <code>/&lt;sha256&gt;/720p</code> and <code>/&lt;sha256&gt;/480p</code>.</p>
                </div>
                <div class="feature">
                    <h3>GCS Storage</h3>
                    <p>Reliable blob storage backed by Google Cloud Storage.</p>
                </div>
            </div>
        </section>

        <section>
            <h2>Protocol</h2>
            <p>This server implements the <a href="https://github.com/hzrd149/blossom">Blossom protocol</a> for decentralized media hosting on Nostr.</p>
            <p style="margin-top: 0.5rem;"><strong>Implemented BUDs:</strong> BUD-01 (Blob Retrieval), BUD-02 (Upload/List/Delete), BUD-04 (Mirroring), BUD-06 (Upload Pre-validation), BUD-09 (Reporting)</p>
            <p style="margin-top: 0.5rem;">Maximum upload size: <code>50 GB</code></p>
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
    resp.set_header(
        "Access-Control-Expose-Headers",
        "X-Sha256, X-Content-Length, X-C2PA-Manifest-Id, X-Source-Sha256",
    );
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
        .unwrap_or_else(|| "https://media.divine.video".into())
}

/// Infer MIME type from file extension in path
fn infer_mime_from_path(path: &str) -> Option<&'static str> {
    let path_lower = path.to_lowercase();

    // Video types
    if path_lower.ends_with(".mp4") || path_lower.ends_with(".m4v") {
        return Some("video/mp4");
    }
    if path_lower.ends_with(".webm") {
        return Some("video/webm");
    }
    if path_lower.ends_with(".mov") {
        return Some("video/quicktime");
    }
    if path_lower.ends_with(".avi") {
        return Some("video/x-msvideo");
    }
    if path_lower.ends_with(".mkv") {
        return Some("video/x-matroska");
    }
    if path_lower.ends_with(".ogv") {
        return Some("video/ogg");
    }

    // Image types
    if path_lower.ends_with(".jpg") || path_lower.ends_with(".jpeg") {
        return Some("image/jpeg");
    }
    if path_lower.ends_with(".png") {
        return Some("image/png");
    }
    if path_lower.ends_with(".gif") {
        return Some("image/gif");
    }
    if path_lower.ends_with(".webp") {
        return Some("image/webp");
    }
    if path_lower.ends_with(".svg") {
        return Some("image/svg+xml");
    }
    if path_lower.ends_with(".avif") {
        return Some("image/avif");
    }

    // Audio types
    if path_lower.ends_with(".mp3") {
        return Some("audio/mpeg");
    }
    if path_lower.ends_with(".wav") {
        return Some("audio/wav");
    }
    if path_lower.ends_with(".ogg") || path_lower.ends_with(".oga") {
        return Some("audio/ogg");
    }
    if path_lower.ends_with(".flac") {
        return Some("audio/flac");
    }
    if path_lower.ends_with(".m4a") {
        return Some("audio/mp4");
    }

    None
}
