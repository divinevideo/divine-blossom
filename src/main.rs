// ABOUTME: Main entry point for Fastly Blossom server
// ABOUTME: Routes requests to appropriate handlers for BUD-01 and BUD-02

mod admin;
mod admin_sweep;
mod auth;
mod blossom;
mod delete_policy;
mod error;
mod media_auth_log;
mod metadata;
mod storage;
mod viewer_auth;

use crate::auth::{diagnose_viewer_auth, validate_auth, validate_hash_match, viewer_pubkey};
use crate::blossom::{
    is_audio_path, is_hash_path, is_transcribable_mime_type, is_video_mime_type, parse_audio_path,
    parse_hash_from_path, parse_thumbnail_path, AudioMapping, AuthAction, BlobAccess,
    BlobDescriptor, BlobMetadata, BlobStatus, ResumableUploadCompleteResponse,
    ResumableUploadInitRequest, ResumableUploadInitResponse, SubtitleJob, SubtitleJobCreateRequest,
    SubtitleJobStatus, TranscodeStatus, TranscriptStatus, UploadRequirements,
};
use crate::delete_policy::{plan_user_delete, soft_delete_blob, DeletePlan};
use crate::error::{BlossomError, Result};
use crate::media_auth_log::format_media_auth_log;
use crate::metadata::{
    add_to_audio_source_refs, add_to_blob_refs, add_to_recent_index, add_to_user_index,
    add_to_user_list, delete_audio_mapping, delete_audio_source_refs, delete_auth_events,
    delete_blob_metadata, delete_blob_refs, delete_subtitle_data, delete_user_list,
    get_audio_mapping, get_audio_source_refs, get_auth_event, get_blob_metadata, get_blob_refs,
    get_subtitle_job, get_subtitle_job_by_hash, get_tombstone, get_user_blobs,
    list_blobs_with_metadata, put_audio_mapping, put_auth_event, put_blob_metadata,
    put_subtitle_job, remove_from_audio_source_refs, remove_from_blob_refs,
    remove_from_recent_index, remove_from_user_index, remove_from_user_list,
    set_subtitle_job_id_for_hash, update_blob_status, update_stats_on_add, update_stats_on_remove,
    TranscodeMetadataUpdate, TranscriptMetadataUpdate,
};
use crate::storage::{
    blob_exists, check_funnelcake_audio_reuse, current_timestamp, delete_blob as storage_delete,
    download_blob_with_fallback, download_thumbnail, trigger_audio_extraction,
    trigger_audit_anonymize, trigger_cloud_run_bulk_delete, trigger_cloud_run_delete_blob,
    upload_blob, write_audit_log,
};
use crate::viewer_auth::{ViewerAuthDiagnostics, ViewerAuthState};
use fastly_blossom::resumable_complete::parse_resumable_complete_request_body;

use fastly::cache::simple as simple_cache;
use fastly::http::{header, Method, StatusCode};
use fastly::{Error, Request, Response};
use sha2::{Digest, Sha256};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

/// TTL for cached HLS manifests (1 hour) — immutable once transcoding completes
const HLS_CACHE_TTL: Duration = Duration::from_secs(3600);
/// TTL for cached transcript content (1 hour) — immutable once transcription completes
const TRANSCRIPT_CACHE_TTL: Duration = Duration::from_secs(3600);

/// Maximum upload size (50 GB) - Cloud Run with HTTP/2 has no size limit
const MAX_UPLOAD_SIZE: u64 = 50 * 1024 * 1024 * 1024;
/// Divine upload extension name for resumable session support.
const DIVINE_UPLOAD_EXTENSION_RESUMABLE: &str = "resumable-sessions";
/// Max automatic subtitle transcription attempts before poison state.
const SUBTITLE_MAX_ATTEMPTS: u32 = 3;
/// Max derivative failures before public endpoints stop re-triggering work.
const DERIVATIVE_MAX_ATTEMPTS: u32 = 3;

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

    eprintln!(
        "[BLOSSOM ROUTE] method={} path={} host={}",
        method, path, host
    );

    match (method, path.as_str()) {
        // Landing page
        (Method::GET, "/") => Ok(handle_landing_page()),

        // Version check
        (Method::GET, "/version") => {
            Ok(Response::from_status(StatusCode::OK).with_body("v127-gdpr-vanish-delete-cleanup"))
        }

        // HLS: /{sha256}.hls -> serve master manifest
        (Method::GET, p) if p.ends_with(".hls") => handle_get_hls_master(req, p),
        (Method::HEAD, p) if p.ends_with(".hls") => handle_head_hls_master(p),

        // HLS: /{sha256}/hls/* -> serve HLS segments/playlists
        (Method::GET, p) if p.contains("/hls/") => handle_get_hls_content(req, p),
        (Method::HEAD, p) if p.contains("/hls/") => handle_head_hls_content(p),

        // Transcript file URL: /{sha256}.vtt
        (Method::GET, p) if is_vtt_file_path(p) => handle_get_transcript_file(req, p),
        (Method::HEAD, p) if is_vtt_file_path(p) => handle_head_transcript_file(p),

        // Transcript: /{sha256}/VTT or /{sha256}/vtt
        (Method::GET, p) if is_transcript_path(p) => handle_get_transcript(req, p),
        (Method::HEAD, p) if is_transcript_path(p) => handle_head_transcript(p),

        // Subtitle jobs API
        (Method::POST, "/v1/subtitles/jobs") => handle_create_subtitle_job(req),
        (Method::GET, p) if p.starts_with("/v1/subtitles/jobs/") => handle_get_subtitle_job(p),
        (Method::GET, p) if p.starts_with("/v1/subtitles/by-hash/") => {
            handle_get_subtitle_by_hash(req, p)
        }

        // Provenance: /{sha256}/provenance - get cryptographic proof of upload
        (Method::GET, p) if p.ends_with("/provenance") => handle_get_provenance(p),

        // Audio extraction: /{sha256}.audio.m4a
        (Method::GET, p) if is_audio_path(p) => handle_get_audio(req, p),
        (Method::HEAD, p) if is_audio_path(p) => handle_head_audio(p),

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
        // Divine resumable control plane
        (Method::POST, "/upload/init") => handle_upload_init(req),
        (Method::POST, p) if p.starts_with("/upload/") && p.ends_with("/complete") => {
            handle_upload_complete(req, p)
        }

        // BUD-02: Delete
        (Method::DELETE, p) if is_hash_path(p) => handle_delete(req, p),

        // GDPR Right to Erasure: user-initiated vanish
        (Method::DELETE, "/vanish") => handle_vanish(req),

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
        (Method::POST, "/admin/transcript-status") => handle_transcript_status(req),

        // Admin: OAuth login
        (Method::POST, "/admin/auth/google") => admin::handle_google_auth(req),
        (Method::GET, "/admin/auth/github") => admin::handle_github_auth_redirect(req),
        (Method::GET, p) if p.starts_with("/admin/auth/github/callback") => {
            admin::handle_github_callback(req)
        }
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
        (Method::GET, p) if p.starts_with("/admin/api/blob/") && p.ends_with("/content") => {
            let hash = p
                .strip_prefix("/admin/api/blob/")
                .unwrap_or("")
                .strip_suffix("/content")
                .unwrap_or("");
            admin::handle_admin_blob_content(req, hash)
        }
        // Admin bypass for transcoded quality variants (720p.mp4, 480p.mp4, etc.)
        (Method::GET, p)
            if p.starts_with("/admin/api/blob/") && is_admin_quality_variant_path(p) =>
        {
            handle_admin_quality_variant(req, p)
        }
        // Admin bypass for HLS content (master.m3u8, segments, etc.)
        (Method::GET, p) if p.starts_with("/admin/api/blob/") && p.contains("/hls/") => {
            handle_admin_hls_content(req, p)
        }
        (Method::GET, p) if p.starts_with("/admin/api/blob/") => {
            let hash = p.strip_prefix("/admin/api/blob/").unwrap_or("");
            admin::handle_admin_blob_detail(req, hash)
        }
        (Method::POST, "/admin/api/moderate") => admin::handle_admin_moderate_action(req),
        (Method::POST, "/admin/api/bulk-approve") => admin::handle_admin_bulk_approve(req),
        (Method::POST, "/admin/api/scan-flagged") => admin::handle_admin_scan_flagged(req),
        (Method::POST, "/admin/api/delete") => handle_admin_force_delete(req),
        (Method::POST, "/admin/api/restore") => admin::handle_admin_restore_action(req),
        (Method::POST, "/admin/api/vanish") => handle_admin_vanish(req),
        (Method::POST, "/admin/api/backfill") => admin::handle_admin_backfill(req),
        (Method::POST, "/admin/api/backfill-vtt") => handle_admin_backfill_vtt(req),
        (Method::POST, "/admin/api/reset-stuck-transcodes") => {
            admin::handle_admin_reset_stuck_transcodes(req)
        }

        // CORS preflight
        (Method::OPTIONS, _) => Ok(cors_preflight_response()),

        // Not found
        _ => Err(BlossomError::NotFound("Not found".into())),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AudioReuseAvailability {
    Allowed,
    Denied,
    LookupUnavailable,
}

fn media_viewer_context(
    req: &Request,
    route: &str,
) -> Result<(Option<String>, ViewerAuthDiagnostics)> {
    let diagnostics = diagnose_viewer_auth(req)?;

    match diagnostics.auth_state {
        ViewerAuthState::Missing => Ok((None, diagnostics)),
        ViewerAuthState::Valid => Ok((diagnostics.viewer_pubkey.clone(), diagnostics)),
        _ => {
            eprintln!(
                "{}",
                format_media_auth_log(route, &diagnostics, "auth_invalid")
            );
            Err(BlossomError::AuthInvalid(
                diagnostics
                    .auth_error
                    .clone()
                    .unwrap_or_else(|| "Invalid viewer authorization".into()),
            ))
        }
    }
}

fn log_media_outcome(route: &str, diagnostics: &ViewerAuthDiagnostics, outcome: &str) {
    eprintln!("{}", format_media_auth_log(route, diagnostics, outcome));
}

fn classify_audio_reuse_availability(result: &Result<bool>) -> AudioReuseAvailability {
    match result {
        Ok(true) => AudioReuseAvailability::Allowed,
        Ok(false) => AudioReuseAvailability::Denied,
        Err(_) => AudioReuseAvailability::LookupUnavailable,
    }
}

fn is_alias_only_audio_blob(has_audio_sources: bool, blob_refs: &[String]) -> bool {
    has_audio_sources && blob_refs.is_empty()
}

fn should_delete_derived_audio_blob(
    remaining_audio_sources: &[String],
    blob_refs: &[String],
) -> bool {
    remaining_audio_sources.is_empty() && blob_refs.is_empty()
}

fn should_hide_direct_blob(hash: &str, is_admin: bool) -> Result<bool> {
    if is_admin {
        return Ok(false);
    }

    let audio_sources = get_audio_source_refs(hash)?;
    if audio_sources.is_empty() {
        return Ok(false);
    }

    let blob_refs = get_blob_refs(hash)?;
    Ok(is_alias_only_audio_blob(true, &blob_refs))
}

fn audio_lookup_unavailable_response() -> Response {
    let mut resp = Response::from_status(StatusCode::SERVICE_UNAVAILABLE);
    resp.set_header("Content-Type", "application/json");
    resp.set_header("Retry-After", "30");
    resp.set_body(r#"{"error":"permission_lookup_unavailable"}"#);
    add_no_cache_headers(&mut resp);
    add_cors_headers(&mut resp);
    resp
}

fn audio_reuse_denied_response() -> Response {
    let mut resp = Response::from_status(StatusCode::FORBIDDEN);
    resp.set_header("Content-Type", "application/json");
    resp.set_body(r#"{"error":"audio_reuse_not_allowed"}"#);
    add_no_cache_headers(&mut resp);
    add_cors_headers(&mut resp);
    resp
}

fn add_audio_response_headers(
    resp: &mut Response,
    source_hash: &str,
    private_cache: bool,
    mime_type: &str,
    size_bytes: u64,
    duration_seconds: f64,
) {
    let set_full_content_length = should_set_audio_content_length(resp.get_status());
    resp.set_header("Content-Type", mime_type);
    if set_full_content_length {
        resp.set_header("Content-Length", size_bytes.to_string());
    }
    resp.set_header("X-Audio-Duration", format!("{}", duration_seconds));
    resp.set_header("X-Audio-Size", size_bytes.to_string());
    resp.set_header("Accept-Ranges", "bytes");
    if private_cache {
        add_private_cache_headers(resp, source_hash);
    } else {
        add_cache_headers(resp, source_hash);
    }
    add_cors_headers(resp);
}

fn should_set_audio_content_length(status: StatusCode) -> bool {
    status != StatusCode::PARTIAL_CONTENT
}

fn clear_stale_audio_mapping(source_hash: &str, audio_hash: &str) {
    let _ = delete_audio_mapping(source_hash);
    match remove_from_audio_source_refs(audio_hash, source_hash) {
        Ok(remaining_sources) if remaining_sources.is_empty() => {
            let _ = delete_audio_source_refs(audio_hash);
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!(
                "[AUDIO] Failed to remove stale audio ref {} <- {}: {}",
                audio_hash, source_hash, e
            );
        }
    }
}

fn cleanup_derived_audio_for_source(source_hash: &str) {
    let mapping = match get_audio_mapping(source_hash) {
        Ok(Some(mapping)) => mapping,
        Ok(None) => return,
        Err(e) => {
            eprintln!(
                "[AUDIO] Failed to load audio mapping for cleanup {}: {}",
                source_hash, e
            );
            return;
        }
    };

    let remaining_audio_sources =
        match remove_from_audio_source_refs(&mapping.audio_sha256, source_hash) {
            Ok(remaining) => remaining,
            Err(e) => {
                eprintln!(
                    "[AUDIO] Failed to remove audio ref {} <- {}: {}",
                    mapping.audio_sha256, source_hash, e
                );
                let _ = delete_audio_mapping(source_hash);
                return;
            }
        };

    let _ = delete_audio_mapping(source_hash);

    if !remaining_audio_sources.is_empty() {
        return;
    }

    let blob_refs = match get_blob_refs(&mapping.audio_sha256) {
        Ok(refs) => refs,
        Err(e) => {
            eprintln!(
                "[AUDIO] Failed to load blob refs for derived audio {}: {}",
                mapping.audio_sha256, e
            );
            return;
        }
    };

    if should_delete_derived_audio_blob(&remaining_audio_sources, &blob_refs) {
        let _ = storage_delete(&mapping.audio_sha256);
        let _ = delete_blob_metadata(&mapping.audio_sha256);
        let _ = delete_audio_source_refs(&mapping.audio_sha256);
        purge_vcl_cache(&mapping.audio_sha256);
    } else {
        let _ = delete_audio_source_refs(&mapping.audio_sha256);
    }
}

/// GET /<sha256>[.ext] - Retrieve blob
fn handle_get_blob(req: Request, path: &str) -> Result<Response> {
    // Check if this is a thumbnail request ({hash}.jpg)
    if let Some(thumbnail_key) = parse_thumbnail_path(path) {
        let video_hash = thumbnail_key.trim_end_matches(".jpg");

        // Admin Bearer token bypasses moderation checks (used by moderation service proxy)
        let is_admin = admin::validate_bearer_token(&req).is_ok();

        // Check parent video's moderation status - thumbnails inherit video access rules
        let mut is_restricted = false;
        if let Ok(Some(meta)) = get_blob_metadata(video_hash) {
            let (requester_pk, auth_diagnostics) = media_viewer_context(&req, "thumbnail")?;
            match meta.access_for(requester_pk.as_deref(), is_admin) {
                BlobAccess::Allowed => {
                    log_media_outcome("thumbnail", &auth_diagnostics, "allowed");
                    // Authenticated access to restricted/age-restricted thumbnails
                    // must stay private in cache below.
                    if meta.status.requires_private_cache() {
                        is_restricted = true;
                    }
                }
                BlobAccess::NotFound => {
                    log_media_outcome("thumbnail", &auth_diagnostics, "not_found");
                    return Err(BlossomError::NotFound("Blob not found".into()));
                }
                BlobAccess::AgeGated => {
                    log_media_outcome("thumbnail", &auth_diagnostics, "age_gated");
                    return Err(BlossomError::AuthRequired("age_restricted".into()));
                }
            }
        }

        // Try to download existing thumbnail from GCS
        let set_thumb_cache = |resp: &mut Response| {
            if is_restricted {
                add_private_cache_headers(resp, video_hash);
            } else {
                add_cache_headers(resp, video_hash);
            }
        };
        match download_thumbnail(&thumbnail_key) {
            Ok(mut resp) => {
                resp.set_header("Content-Type", "image/jpeg");
                set_thumb_cache(&mut resp);
                resp.set_header("Accept-Ranges", "bytes");
                add_cors_headers(&mut resp);
                return Ok(resp);
            }
            Err(BlossomError::NotFound(_)) => {
                // Thumbnail doesn't exist, generate on-demand via Cloud Run
                match generate_thumbnail_on_demand(video_hash) {
                    Ok(mut resp) => {
                        resp.set_header("Content-Type", "image/jpeg");
                        set_thumb_cache(&mut resp);
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

    // Admin Bearer token bypasses moderation checks (used by moderation service proxy)
    let is_admin = admin::validate_bearer_token(&req).is_ok();

    if should_hide_direct_blob(&hash, is_admin)? {
        return Err(BlossomError::NotFound("Blob not found".into()));
    }

    if let Some(ref meta) = metadata {
        let (requester_pk, auth_diagnostics) = media_viewer_context(&req, "blob")?;
        match meta.access_for(requester_pk.as_deref(), is_admin) {
            BlobAccess::Allowed => log_media_outcome("blob", &auth_diagnostics, "allowed"),
            BlobAccess::NotFound => {
                log_media_outcome("blob", &auth_diagnostics, "not_found");
                return Err(BlossomError::NotFound("Blob not found".into()));
            }
            BlobAccess::AgeGated => {
                log_media_outcome("blob", &auth_diagnostics, "age_gated");
                return Err(BlossomError::AuthRequired("age_restricted".into()));
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
            let content_length: Option<String> = resp
                .get_header_str("content-length")
                .map(|s| s.to_string())
                .or_else(|| {
                    resp.get_header_str("x-goog-stored-content-length")
                        .map(|s| s.to_string())
                });
            if let Some(cl) = content_length {
                resp.set_header("Content-Length", &cl);
            }
        }
        resp.set_header("X-Sha256", &hash);
    }

    // Content is addressed by SHA256 hash, so it's immutable - cache aggressively.
    // Exception: restricted/admin content must not be publicly cached.
    if is_admin {
        // Admin bypass: never cache, expose moderation status
        resp.set_header("Cache-Control", "private, no-store");
        if let Some(ref meta) = metadata {
            resp.set_header("X-Moderation-Status", &format!("{:?}", meta.status));
        }
    } else {
        let is_restricted = metadata
            .as_ref()
            .map(|m| m.status != BlobStatus::Active)
            .unwrap_or(false);
        if is_restricted {
            add_private_cache_headers(&mut resp, &hash);
        } else {
            add_cache_headers(&mut resp, &hash);
        }
    }

    if let Some(c2pa) = c2pa_manifest_id {
        resp.set_header("X-C2PA-Manifest-Id", &c2pa);
    }
    if let Some(source_hash) = source_sha256 {
        resp.set_header("X-Source-Sha256", &source_hash);
    }

    Ok(resp)
}

/// HEAD /<sha256>[.ext] - Check blob existence
fn handle_head_blob(path: &str) -> Result<Response> {
    // Check if this is a thumbnail request ({hash}.jpg)
    if let Some(thumbnail_key) = parse_thumbnail_path(path) {
        let resp = download_thumbnail(&thumbnail_key)?;
        let content_length = resp
            .get_header_str("x-goog-stored-content-length")
            .or_else(|| resp.get_header_str("content-length"))
            .unwrap_or("0")
            .to_string();
        let mut head_resp = Response::from_status(StatusCode::OK);
        head_resp.set_header("Content-Type", "image/jpeg");
        head_resp.set_header("Content-Length", &content_length);
        let thumb_hash = thumbnail_key.trim_end_matches(".jpg");
        add_cache_headers(&mut head_resp, thumb_hash);
        head_resp.set_header("Accept-Ranges", "bytes");
        add_cors_headers(&mut head_resp);
        return Ok(head_resp);
    }

    let hash = parse_hash_from_path(path)
        .ok_or_else(|| BlossomError::BadRequest("Invalid hash in path".into()))?;

    if should_hide_direct_blob(&hash, false)? {
        return Err(BlossomError::NotFound("Blob not found".into()));
    }

    // Check metadata
    let metadata =
        get_blob_metadata(&hash)?.ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;

    // HEAD has no auth context, so non-owner gating applies. Banned/Deleted/Restricted
    // collapse to 404; AgeRestricted surfaces as 401 so the client knows to age-gate.
    match metadata.access_for(None, false) {
        BlobAccess::Allowed => {}
        BlobAccess::NotFound => return Err(BlossomError::NotFound("Blob not found".into())),
        BlobAccess::AgeGated => return Err(BlossomError::AuthRequired("age_restricted".into())),
    }

    let mut resp = Response::from_status(StatusCode::OK);
    resp.set_header(header::CONTENT_TYPE, &metadata.mime_type);
    // Note: For HEAD responses, Fastly/HTTP/2 may strip Content-Length when there's no body
    // X-Content-Length provides the size info as a workaround
    resp.set_header(header::CONTENT_LENGTH, metadata.size.to_string());
    resp.set_header("X-Sha256", &metadata.sha256);
    resp.set_header("X-Content-Length", metadata.size.to_string());
    add_cache_headers(&mut resp, &hash);
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

    // Check metadata for access control
    let metadata = get_blob_metadata(&hash)?;

    // Admin Bearer token bypasses moderation checks (used by moderation service proxy)
    let is_admin = admin::validate_bearer_token(&req).is_ok();

    if let Some(ref meta) = metadata {
        let (requester_pk, auth_diagnostics) = media_viewer_context(&req, "hls_master")?;
        match meta.access_for(requester_pk.as_deref(), is_admin) {
            BlobAccess::Allowed => log_media_outcome("hls_master", &auth_diagnostics, "allowed"),
            BlobAccess::NotFound => {
                log_media_outcome("hls_master", &auth_diagnostics, "not_found");
                return Err(BlossomError::NotFound("Content not found".into()));
            }
            BlobAccess::AgeGated => {
                log_media_outcome("hls_master", &auth_diagnostics, "age_gated");
                return Err(BlossomError::AuthRequired("age_restricted".into()));
            }
        }
    } else {
        return Err(BlossomError::NotFound("Content not found".into()));
    }

    // Try GCS first — many videos have HLS in GCS but metadata wasn't updated.
    // GCS is the source of truth: if the manifest exists, serve it.
    let gcs_path = format!("{}/hls/master.m3u8", hash);
    match download_hls_content(&gcs_path, None) {
        Ok(result) => {
            // HLS exists in GCS — serve it and fix metadata if needed
            let meta = metadata.as_ref().unwrap();
            if meta.transcode_status != Some(TranscodeStatus::Complete) {
                eprintln!(
                    "[HLS] Fixing metadata: {} has HLS in GCS but status was {:?}",
                    hash, meta.transcode_status
                );
                use crate::metadata::update_transcode_status;
                let _ = update_transcode_status(&hash, TranscodeStatus::Complete);
            }
            let mut resp = result;

            let c2pa_manifest_id = resp
                .get_header_str("x-goog-meta-c2pa-manifest-id")
                .map(|s| s.to_string());
            let source_sha256 = resp
                .get_header_str("x-goog-meta-source-sha256")
                .map(|s| s.to_string());

            resp.set_header("Content-Type", "application/vnd.apple.mpegurl");
            if is_admin || meta.status.requires_private_cache() {
                add_private_cache_headers(&mut resp, &hash);
            } else {
                add_cache_headers(&mut resp, &hash);
            }
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
        Err(BlossomError::NotFound(_)) => {
            // HLS not in GCS — check metadata and trigger transcoding if needed
            let meta = metadata.as_ref().unwrap();
            match decide_transcode_fetch_action(
                meta.transcode_status,
                meta.transcode_retry_after,
                meta.transcode_attempt_count,
                meta.transcode_terminal,
                unix_timestamp_secs(),
            ) {
                TranscodeFetchAction::Accepted {
                    state,
                    retry_after_secs,
                } => {
                    let mut resp = Response::from_status(StatusCode::ACCEPTED);
                    resp.set_header("Retry-After", retry_after_secs.to_string());
                    resp.set_header("Content-Type", "application/json");
                    let body = match state {
                        TranscriptPendingState::InProgress => {
                            r#"{"status":"processing","message":"HLS transcoding in progress"}"#
                        }
                        TranscriptPendingState::CoolingDown => {
                            r#"{"status":"cooling_down","message":"HLS transcoding cooling down before retry"}"#
                        }
                    };
                    resp.set_body(body);
                    add_no_cache_headers(&mut resp);
                    add_cors_headers(&mut resp);
                    Ok(resp)
                }
                TranscodeFetchAction::Trigger {
                    retry_after_secs,
                    should_repair,
                } => {
                    // Pending, Failed, Complete-but-missing, or None — trigger transcoding
                    use crate::metadata::update_transcode_status;
                    if let Err(e) = update_transcode_status(&hash, TranscodeStatus::Processing) {
                        eprintln!("[HLS] Failed to update transcode status: {}", e);
                    }
                    let _ = trigger_on_demand_transcoding(&hash, &meta.owner);

                    let mut resp = Response::from_status(StatusCode::ACCEPTED);
                    resp.set_header("Retry-After", retry_after_secs.to_string());
                    resp.set_header("Content-Type", "application/json");
                    if should_repair {
                        resp.set_body(
                            r#"{"status":"repairing","message":"HLS transcoding repair started, please retry soon"}"#,
                        );
                    } else {
                        resp.set_body(
                            r#"{"status":"processing","message":"HLS transcoding started, please retry soon"}"#,
                        );
                    }
                    add_no_cache_headers(&mut resp);
                    add_cors_headers(&mut resp);
                    Ok(resp)
                }
                TranscodeFetchAction::Terminal => Ok(derivative_failure_response(
                    meta.transcode_error_code.as_deref(),
                    meta.transcode_error_message.as_deref(),
                    "HLS generation failed for this blob",
                )),
            }
        }
        Err(e) => Err(e),
    }
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

    // HEAD has no req/admin context. Banned/Restricted collapse to 404; AgeRestricted
    // surfaces as 401 so the client knows to age-gate.
    match metadata.access_for(None, false) {
        BlobAccess::Allowed => {}
        BlobAccess::NotFound => return Err(BlossomError::NotFound("Content not found".into())),
        BlobAccess::AgeGated => return Err(BlossomError::AuthRequired("age_restricted".into())),
    }

    // Check GCS first (source of truth), then fall back to metadata status
    let gcs_path = format!("{}/hls/master.m3u8", hash);
    match download_hls_content(&gcs_path, None) {
        Ok(_) => {
            // Fix metadata if needed
            if metadata.transcode_status != Some(TranscodeStatus::Complete) {
                use crate::metadata::update_transcode_status;
                let _ = update_transcode_status(&hash, TranscodeStatus::Complete);
            }
            let mut resp = Response::from_status(StatusCode::OK);
            resp.set_header("Content-Type", "application/vnd.apple.mpegurl");
            add_cache_headers(&mut resp, &hash);
            resp.set_header("X-Sha256", &hash);
            add_cors_headers(&mut resp);
            Ok(resp)
        }
        Err(BlossomError::NotFound(_)) => match decide_transcode_fetch_action(
            metadata.transcode_status,
            metadata.transcode_retry_after,
            metadata.transcode_attempt_count,
            metadata.transcode_terminal,
            unix_timestamp_secs(),
        ) {
            TranscodeFetchAction::Accepted {
                retry_after_secs, ..
            }
            | TranscodeFetchAction::Trigger {
                retry_after_secs, ..
            } => {
                let mut resp = Response::from_status(StatusCode::ACCEPTED);
                resp.set_header("Retry-After", retry_after_secs.to_string());
                add_no_cache_headers(&mut resp);
                add_cors_headers(&mut resp);
                Ok(resp)
            }
            TranscodeFetchAction::Terminal => Ok(derivative_failure_head_response(
                &hash,
                metadata.transcode_error_code.as_deref(),
                "application/vnd.apple.mpegurl",
            )),
        },
        Err(e) => Err(e),
    }
}

/// GET /<sha256>/hls/* - Serve HLS segments and variant playlists
fn handle_get_hls_content(req: Request, path: &str) -> Result<Response> {
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

    // Check metadata for moderation/access control
    let is_admin = admin::validate_bearer_token(&req).is_ok();
    let mut is_restricted = false;

    if let Ok(Some(ref meta)) = get_blob_metadata(&hash) {
        let (requester_pk, auth_diagnostics) = media_viewer_context(&req, "hls_content")?;
        match meta.access_for(requester_pk.as_deref(), is_admin) {
            BlobAccess::Allowed => {
                log_media_outcome("hls_content", &auth_diagnostics, "allowed");
                if meta.status.requires_private_cache() {
                    is_restricted = true;
                }
            }
            BlobAccess::NotFound => {
                log_media_outcome("hls_content", &auth_diagnostics, "not_found");
                return Err(BlossomError::NotFound("Blob not found".into()));
            }
            BlobAccess::AgeGated => {
                log_media_outcome("hls_content", &auth_diagnostics, "age_gated");
                return Err(BlossomError::AuthRequired("age_restricted".into()));
            }
        }
    }

    // Construct GCS path
    let gcs_path = format!("{}/hls/{}", hash, filename);

    // Try to download from GCS first
    match download_hls_content(&gcs_path, None) {
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
            if is_restricted {
                add_private_cache_headers(&mut resp, &hash);
            } else {
                add_cache_headers(&mut resp, &hash);
            }
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
                // Handle banned/deleted content
                if !is_admin && meta.status.blocks_public_access() {
                    return Err(BlossomError::NotFound("Content not found".into()));
                }

                match decide_transcode_fetch_action(
                    meta.transcode_status,
                    meta.transcode_retry_after,
                    meta.transcode_attempt_count,
                    meta.transcode_terminal,
                    unix_timestamp_secs(),
                ) {
                    TranscodeFetchAction::Accepted {
                        state,
                        retry_after_secs,
                    } => {
                        let mut resp = Response::from_status(StatusCode::ACCEPTED);
                        resp.set_header("Retry-After", retry_after_secs.to_string());
                        resp.set_header("Content-Type", "application/json");
                        let body = match state {
                            TranscriptPendingState::InProgress => {
                                r#"{"status":"processing","message":"HLS transcoding in progress"}"#
                            }
                            TranscriptPendingState::CoolingDown => {
                                r#"{"status":"cooling_down","message":"HLS transcoding cooling down before retry"}"#
                            }
                        };
                        resp.set_body(body);
                        add_no_cache_headers(&mut resp);
                        add_cors_headers(&mut resp);
                        Ok(resp)
                    }
                    TranscodeFetchAction::Trigger {
                        retry_after_secs,
                        should_repair,
                    } => {
                        use crate::metadata::update_transcode_status;
                        let _ = update_transcode_status(&hash, TranscodeStatus::Processing);
                        let _ = trigger_on_demand_transcoding(&hash, &meta.owner);

                        let mut resp = Response::from_status(StatusCode::ACCEPTED);
                        resp.set_header("Retry-After", retry_after_secs.to_string());
                        resp.set_header("Content-Type", "application/json");
                        if should_repair {
                            resp.set_body(
                                r#"{"status":"repairing","message":"HLS transcoding repair started, please retry soon"}"#,
                            );
                        } else {
                            resp.set_body(
                                r#"{"status":"processing","message":"HLS transcoding started, please retry soon"}"#,
                            );
                        }
                        add_no_cache_headers(&mut resp);
                        add_cors_headers(&mut resp);
                        Ok(resp)
                    }
                    TranscodeFetchAction::Terminal => Ok(derivative_failure_response(
                        meta.transcode_error_code.as_deref(),
                        meta.transcode_error_message.as_deref(),
                        "HLS generation failed for this blob",
                    )),
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

    let hash_lower = hash.to_lowercase();

    // HEAD has no req/admin context. Banned/Restricted collapse to 404; AgeRestricted
    // surfaces as 401 so the client knows to age-gate.
    let metadata = get_blob_metadata(&hash_lower)?;
    if let Some(ref meta) = metadata {
        match meta.access_for(None, false) {
            BlobAccess::Allowed => {}
            BlobAccess::NotFound => {
                return Err(BlossomError::NotFound("Content not found".into()));
            }
            BlobAccess::AgeGated => {
                return Err(BlossomError::AuthRequired("age_restricted".into()));
            }
        }
    }

    // Check if file exists in GCS
    let gcs_path = format!("{}/hls/{}", hash_lower, filename);

    let content_type = if filename.ends_with(".m3u8") {
        "application/vnd.apple.mpegurl"
    } else if filename.ends_with(".ts") {
        "video/mp2t"
    } else {
        "application/octet-stream"
    };
    match download_hls_content(&gcs_path, None) {
        Ok(_) => {
            let mut resp = Response::from_status(StatusCode::OK);
            resp.set_header("Content-Type", content_type);
            add_cache_headers(&mut resp, &hash_lower);
            resp.set_header("X-Sha256", &hash_lower);
            add_cors_headers(&mut resp);
            Ok(resp)
        }
        Err(BlossomError::NotFound(_)) if filename == "master.m3u8" => {
            let meta = metadata
                .as_ref()
                .ok_or_else(|| BlossomError::NotFound("Content not found".into()))?;
            match decide_transcode_fetch_action(
                meta.transcode_status,
                meta.transcode_retry_after,
                meta.transcode_attempt_count,
                meta.transcode_terminal,
                unix_timestamp_secs(),
            ) {
                TranscodeFetchAction::Accepted {
                    retry_after_secs, ..
                }
                | TranscodeFetchAction::Trigger {
                    retry_after_secs, ..
                } => {
                    let mut resp = Response::from_status(StatusCode::ACCEPTED);
                    resp.set_header("Retry-After", retry_after_secs.to_string());
                    add_no_cache_headers(&mut resp);
                    add_cors_headers(&mut resp);
                    Ok(resp)
                }
                TranscodeFetchAction::Terminal => Ok(derivative_failure_head_response(
                    &hash_lower,
                    meta.transcode_error_code.as_deref(),
                    content_type,
                )),
            }
        }
        Err(e) => Err(e),
    }
}

/// Download HLS content from GCS (with POP-local Simple Cache for non-range requests)
fn download_hls_content(gcs_path: &str, range: Option<&str>) -> Result<Response> {
    use crate::storage::download_hls_from_gcs;

    // Only cache full (non-range) requests for m3u8 manifests (small text)
    if range.is_some() || !gcs_path.ends_with(".m3u8") {
        return download_hls_from_gcs(gcs_path, range);
    }

    let cache_key = format!("hls:{}", gcs_path);

    // Try Simple Cache first
    if let Ok(Some(body)) = simple_cache::get(cache_key.clone()) {
        let mut resp = Response::from_status(StatusCode::OK);
        resp.set_body(body);
        return Ok(resp);
    }

    // Cache miss: fetch from GCS
    let mut gcs_resp = download_hls_from_gcs(gcs_path, None)?;

    // Extract body, cache it, return a new response
    let body_bytes = gcs_resp.take_body().into_bytes();

    // Cache the manifest content
    let _ = simple_cache::get_or_set(cache_key, body_bytes.as_slice(), HLS_CACHE_TTL);

    // Reconstruct response with the body and preserve GCS metadata headers
    let mut resp = Response::from_status(gcs_resp.get_status());
    // Preserve provenance headers from GCS
    if let Some(val) = gcs_resp.get_header_str("x-goog-meta-c2pa-manifest-id") {
        resp.set_header("x-goog-meta-c2pa-manifest-id", val);
    }
    if let Some(val) = gcs_resp.get_header_str("x-goog-meta-source-sha256") {
        resp.set_header("x-goog-meta-source-sha256", val);
    }
    resp.set_body(body_bytes);
    Ok(resp)
}

/// Parse transcript path: /{sha256}/VTT (case-insensitive).
fn parse_transcript_path(path: &str) -> Option<String> {
    let path_trimmed = path.trim_start_matches('/');
    let mut parts = path_trimmed.split('/');
    let hash = parts.next()?;
    let suffix = parts.next()?;

    if parts.next().is_some() {
        return None;
    }

    if suffix.eq_ignore_ascii_case("vtt")
        && hash.len() == 64
        && hash.chars().all(|c| c.is_ascii_hexdigit())
    {
        Some(hash.to_lowercase())
    } else {
        None
    }
}

/// Parse transcript file path: /{sha256}.vtt.
fn parse_vtt_file_path(path: &str) -> Option<String> {
    let path_trimmed = path.trim_start_matches('/');
    if !path_trimmed.ends_with(".vtt") {
        return None;
    }
    let hash = path_trimmed.strip_suffix(".vtt")?;
    if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(hash.to_lowercase())
    } else {
        None
    }
}

/// Check if a path is a transcript request path.
fn is_transcript_path(path: &str) -> bool {
    parse_transcript_path(path).is_some()
}

/// Check if a path is a transcript file request path.
fn is_vtt_file_path(path: &str) -> bool {
    parse_vtt_file_path(path).is_some()
}

/// Download transcript content from GCS
/// Download transcript content from GCS (with POP-local Simple Cache)
fn download_transcript_content(gcs_path: &str) -> Result<Response> {
    use crate::storage::download_transcript_from_gcs;

    let cache_key = format!("vtt:{}", gcs_path);

    // Try Simple Cache first
    if let Ok(Some(body)) = simple_cache::get(cache_key.clone()) {
        // Detect corrupted VTT (raw JSON stored as subtitles) and skip cache
        let body_bytes = body.into_bytes();
        let body_str = std::str::from_utf8(&body_bytes).unwrap_or("");
        let is_corrupted =
            body_str.contains("\"total_tokens\"") || body_str.contains("\"usage\":{");
        if !is_corrupted {
            let mut resp = Response::from_status(StatusCode::OK);
            resp.set_body(body_bytes);
            return Ok(resp);
        }
        // Corrupted VTT in cache — purge and fetch fresh from GCS
        let _ = simple_cache::purge(cache_key.clone());
    }

    // Cache miss: fetch from GCS
    let mut gcs_resp = download_transcript_from_gcs(gcs_path)?;

    // Extract body, cache it, return a new response
    let body_bytes = gcs_resp.take_body().into_bytes();

    // Cache the transcript content
    let _ = simple_cache::get_or_set(cache_key, body_bytes.as_slice(), TRANSCRIPT_CACHE_TTL);

    let mut resp = Response::from_status(gcs_resp.get_status());
    resp.set_body(body_bytes);
    Ok(resp)
}

fn purge_transcript_content_cache(hash: &str) {
    let cache_key = format!("vtt:{}/vtt/main.vtt", hash.to_lowercase());
    let _ = simple_cache::purge(cache_key);
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedTranscodeStatusWebhook {
    sha256: String,
    status: TranscodeStatus,
    new_size: Option<u64>,
    dim: Option<String>,
    error_code: Option<String>,
    error_message: Option<String>,
    retry_after_epoch_secs: Option<u64>,
    terminal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedTranscriptStatusWebhook {
    sha256: String,
    status: TranscriptStatus,
    job_id: Option<String>,
    language: Option<String>,
    duration_ms: Option<u64>,
    cue_count: Option<u32>,
    error_code: Option<String>,
    error_message: Option<String>,
    retry_after_epoch_secs: Option<u64>,
    terminal: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TranscriptPendingState {
    InProgress,
    CoolingDown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TranscriptFetchAction {
    Accepted {
        state: TranscriptPendingState,
        retry_after_secs: u64,
    },
    Trigger {
        retry_after_secs: u64,
        should_repair: bool,
    },
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TranscodeFetchAction {
    Accepted {
        state: TranscriptPendingState,
        retry_after_secs: u64,
    },
    Trigger {
        retry_after_secs: u64,
        should_repair: bool,
    },
    Terminal,
}

fn parse_optional_retry_after_epoch(
    payload: &serde_json::Value,
    now_epoch_secs: u64,
) -> Option<u64> {
    let retry_after_secs = payload["retry_after"].as_u64().or_else(|| {
        payload["retry_after"]
            .as_str()
            .and_then(|value| value.parse().ok())
    })?;
    Some(now_epoch_secs.saturating_add(retry_after_secs))
}

fn parse_optional_bool(payload: &serde_json::Value, field: &str) -> Option<bool> {
    payload[field]
        .as_bool()
        .or_else(|| payload[field].as_str().and_then(|value| value.parse().ok()))
}

fn parse_transcode_status_webhook_payload(
    payload: &serde_json::Value,
    now_epoch_secs: u64,
) -> Result<ParsedTranscodeStatusWebhook> {
    let sha256 = payload["sha256"]
        .as_str()
        .ok_or_else(|| BlossomError::BadRequest("Missing 'sha256' field".into()))?
        .to_string();

    let status_str = payload["status"]
        .as_str()
        .ok_or_else(|| BlossomError::BadRequest("Missing 'status' field".into()))?;

    let status = match status_str.to_lowercase().as_str() {
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

    let display_width = payload["display_width"].as_u64().map(|v| v as u32);
    let display_height = payload["display_height"].as_u64().map(|v| v as u32);
    let dim = match (display_width, display_height) {
        (Some(w), Some(h)) if w > 0 && h > 0 => Some(format!("{}x{}", w, h)),
        _ => None,
    };

    Ok(ParsedTranscodeStatusWebhook {
        sha256,
        status,
        new_size: payload["new_size"].as_u64(),
        dim,
        error_code: payload["error_code"].as_str().map(|s| s.to_string()),
        error_message: payload["error_message"].as_str().map(|s| s.to_string()),
        retry_after_epoch_secs: parse_optional_retry_after_epoch(payload, now_epoch_secs),
        terminal: parse_optional_bool(payload, "terminal").unwrap_or(false),
    })
}

fn parse_transcript_status_webhook_payload(
    payload: &serde_json::Value,
    now_epoch_secs: u64,
) -> Result<ParsedTranscriptStatusWebhook> {
    let sha256 = payload["sha256"]
        .as_str()
        .ok_or_else(|| BlossomError::BadRequest("Missing 'sha256' field".into()))?
        .to_string();

    let status_str = payload["status"]
        .as_str()
        .ok_or_else(|| BlossomError::BadRequest("Missing 'status' field".into()))?;

    let status = match status_str.to_lowercase().as_str() {
        "pending" => TranscriptStatus::Pending,
        "processing" => TranscriptStatus::Processing,
        "complete" | "completed" | "ready" => TranscriptStatus::Complete,
        "failed" | "error" => TranscriptStatus::Failed,
        _ => {
            return Err(BlossomError::BadRequest(format!(
                "Unknown status: {}. Expected pending, processing, complete, or failed",
                status_str
            )));
        }
    };

    Ok(ParsedTranscriptStatusWebhook {
        sha256,
        status,
        job_id: payload["job_id"].as_str().map(|s| s.to_string()),
        language: payload["language"].as_str().map(|s| s.to_string()),
        duration_ms: payload["duration_ms"].as_u64(),
        cue_count: payload["cue_count"].as_u64().map(|value| value as u32),
        error_code: payload["error_code"].as_str().map(|s| s.to_string()),
        error_message: payload["error_message"].as_str().map(|s| s.to_string()),
        retry_after_epoch_secs: parse_optional_retry_after_epoch(payload, now_epoch_secs),
        terminal: parse_optional_bool(payload, "terminal").unwrap_or(false),
    })
}

fn decide_transcript_fetch_action(
    status: Option<TranscriptStatus>,
    retry_after_epoch_secs: Option<u64>,
    attempt_count: u32,
    terminal: bool,
    now_epoch_secs: u64,
) -> TranscriptFetchAction {
    if terminal
        || (matches!(status, Some(TranscriptStatus::Failed))
            && attempt_count >= DERIVATIVE_MAX_ATTEMPTS)
    {
        return TranscriptFetchAction::Terminal;
    }

    if matches!(status, Some(TranscriptStatus::Processing)) {
        return TranscriptFetchAction::Accepted {
            state: TranscriptPendingState::InProgress,
            retry_after_secs: 5,
        };
    }

    if let Some(retry_after_epoch_secs) = retry_after_epoch_secs {
        if retry_after_epoch_secs > now_epoch_secs {
            return TranscriptFetchAction::Accepted {
                state: TranscriptPendingState::CoolingDown,
                retry_after_secs: retry_after_epoch_secs.saturating_sub(now_epoch_secs).max(1),
            };
        }
    }

    TranscriptFetchAction::Trigger {
        retry_after_secs: 10,
        should_repair: matches!(status, Some(TranscriptStatus::Complete)),
    }
}

fn decide_transcode_fetch_action(
    status: Option<TranscodeStatus>,
    retry_after_epoch_secs: Option<u64>,
    attempt_count: u32,
    terminal: bool,
    now_epoch_secs: u64,
) -> TranscodeFetchAction {
    if terminal
        || (matches!(status, Some(TranscodeStatus::Failed))
            && attempt_count >= DERIVATIVE_MAX_ATTEMPTS)
    {
        return TranscodeFetchAction::Terminal;
    }

    if matches!(status, Some(TranscodeStatus::Processing)) {
        return TranscodeFetchAction::Accepted {
            state: TranscriptPendingState::InProgress,
            retry_after_secs: 5,
        };
    }

    if let Some(retry_after_epoch_secs) = retry_after_epoch_secs {
        if retry_after_epoch_secs > now_epoch_secs {
            return TranscodeFetchAction::Accepted {
                state: TranscriptPendingState::CoolingDown,
                retry_after_secs: retry_after_epoch_secs.saturating_sub(now_epoch_secs).max(1),
            };
        }
    }

    TranscodeFetchAction::Trigger {
        retry_after_secs: 10,
        should_repair: matches!(status, Some(TranscodeStatus::Complete)),
    }
}

fn derivative_failure_response(
    error_code: Option<&str>,
    error_message: Option<&str>,
    default_message: &str,
) -> Response {
    let body = serde_json::json!({
        "status": "failed",
        "error_code": error_code.unwrap_or("derivative_failed"),
        "message": error_message.unwrap_or(default_message),
        "retryable": false
    });
    let mut resp = json_response(StatusCode::UNPROCESSABLE_ENTITY, &body);
    add_no_cache_headers(&mut resp);
    add_cors_headers(&mut resp);
    resp
}

fn derivative_failure_head_response(
    hash: &str,
    error_code: Option<&str>,
    content_type: &str,
) -> Response {
    let mut resp = Response::from_status(StatusCode::UNPROCESSABLE_ENTITY);
    resp.set_header("Content-Type", content_type);
    resp.set_header("X-Sha256", hash);
    if let Some(error_code) = error_code {
        resp.set_header("X-Error-Code", error_code);
    }
    add_no_cache_headers(&mut resp);
    add_cors_headers(&mut resp);
    resp
}

fn serve_transcript_by_hash(
    req: Option<&Request>,
    route: &str,
    hash: &str,
    can_trigger: bool,
) -> Result<Response> {
    let metadata = get_blob_metadata(hash)?
        .ok_or_else(|| BlossomError::NotFound("Content not found".into()))?;

    // Admin Bearer token bypasses moderation checks
    let is_admin = req
        .map(|r| admin::validate_bearer_token(r).is_ok())
        .unwrap_or(false);

    let (requester_pk, auth_diagnostics) = match req {
        Some(request) => {
            let (requester_pk, diagnostics) = media_viewer_context(request, route)?;
            (requester_pk, Some(diagnostics))
        }
        None => (None, None),
    };
    match metadata.access_for(requester_pk.as_deref(), is_admin) {
        BlobAccess::Allowed => {
            if let Some(ref diagnostics) = auth_diagnostics {
                log_media_outcome(route, diagnostics, "allowed");
            }
        }
        BlobAccess::NotFound => {
            if let Some(ref diagnostics) = auth_diagnostics {
                log_media_outcome(route, diagnostics, "not_found");
            }
            return Err(BlossomError::NotFound("Content not found".into()));
        }
        BlobAccess::AgeGated => {
            if let Some(ref diagnostics) = auth_diagnostics {
                log_media_outcome(route, diagnostics, "age_gated");
            }
            return Err(BlossomError::AuthRequired("age_restricted".into()));
        }
    }

    if !is_transcribable_mime_type(&metadata.mime_type) {
        return Err(BlossomError::NotFound(
            "Transcript not available for this media type".into(),
        ));
    }

    let gcs_path = format!("{}/vtt/main.vtt", hash);

    match download_transcript_content(&gcs_path) {
        Ok(mut resp) => {
            if metadata.transcript_status != Some(TranscriptStatus::Complete) {
                use crate::metadata::update_transcript_status;
                let _ = update_transcript_status(
                    hash,
                    TranscriptStatus::Complete,
                    TranscriptMetadataUpdate {
                        last_attempt_at: Some(current_timestamp()),
                        ..Default::default()
                    },
                );
            }
            resp.set_header("Content-Type", "text/vtt; charset=utf-8");
            if is_admin || metadata.status.requires_private_cache() {
                add_private_cache_headers(&mut resp, &hash);
            } else {
                add_cache_headers(&mut resp, &hash);
            }
            add_cors_headers(&mut resp);
            Ok(resp)
        }
        Err(BlossomError::NotFound(_)) if can_trigger => {
            // Transcript does not exist yet. Trigger transcription if needed.
            match decide_transcript_fetch_action(
                metadata.transcript_status,
                metadata.transcript_retry_after,
                metadata.transcript_attempt_count,
                metadata.transcript_terminal,
                unix_timestamp_secs(),
            ) {
                TranscriptFetchAction::Accepted {
                    state,
                    retry_after_secs,
                } => {
                    let mut resp = Response::from_status(StatusCode::ACCEPTED);
                    resp.set_header("Retry-After", retry_after_secs.to_string());
                    resp.set_header("Content-Type", "application/json");
                    let body = match state {
                        TranscriptPendingState::InProgress => {
                            r#"{"status":"in_progress","message":"Transcript generation in progress"}"#
                        }
                        TranscriptPendingState::CoolingDown => {
                            r#"{"status":"cooling_down","message":"Transcript generation cooling down before retry"}"#
                        }
                    };
                    resp.set_body(body);
                    add_no_cache_headers(&mut resp);
                    add_cors_headers(&mut resp);
                    Ok(resp)
                }
                TranscriptFetchAction::Trigger {
                    retry_after_secs,
                    should_repair,
                } => {
                    use crate::metadata::update_transcript_status;
                    let _ = update_transcript_status(
                        hash,
                        TranscriptStatus::Processing,
                        TranscriptMetadataUpdate {
                            last_attempt_at: Some(current_timestamp()),
                            ..Default::default()
                        },
                    );
                    let _ = trigger_on_demand_transcription(hash, &metadata.owner, None, None);

                    let mut resp = Response::from_status(StatusCode::ACCEPTED);
                    resp.set_header("Retry-After", retry_after_secs.to_string());
                    resp.set_header("Content-Type", "application/json");
                    if should_repair {
                        resp.set_body(
                            r#"{"status":"repairing","message":"Transcript repair started, please retry soon"}"#,
                        );
                    } else {
                        resp.set_body(
                            r#"{"status":"processing","message":"Transcript generation started, please retry soon"}"#,
                        );
                    }
                    add_no_cache_headers(&mut resp);
                    add_cors_headers(&mut resp);
                    Ok(resp)
                }
                TranscriptFetchAction::Terminal => Ok(derivative_failure_response(
                    metadata.transcript_error_code.as_deref(),
                    metadata.transcript_error_message.as_deref(),
                    "Transcript generation failed for this blob",
                )),
            }
        }
        Err(e) => Err(e),
    }
}

/// GET /<sha256>/VTT - Serve transcript in WebVTT format
fn handle_get_transcript(req: Request, path: &str) -> Result<Response> {
    let hash = parse_transcript_path(path)
        .ok_or_else(|| BlossomError::BadRequest("Invalid transcript path".into()))?;
    serve_transcript_by_hash(Some(&req), "transcript_file", &hash, true)
}

/// HEAD /<sha256>/VTT - Check transcript existence/status
fn handle_head_transcript(path: &str) -> Result<Response> {
    let hash = parse_transcript_path(path)
        .ok_or_else(|| BlossomError::BadRequest("Invalid transcript path".into()))?;
    handle_head_transcript_by_hash(&hash)
}

/// GET /<sha256>.vtt - Stable transcript file URL
fn handle_get_transcript_file(req: Request, path: &str) -> Result<Response> {
    let hash = parse_vtt_file_path(path)
        .ok_or_else(|| BlossomError::BadRequest("Invalid VTT path".into()))?;
    serve_transcript_by_hash(Some(&req), "transcript", &hash, true)
}

/// HEAD /<sha256>.vtt - Check transcript file URL status
fn handle_head_transcript_file(path: &str) -> Result<Response> {
    let hash = parse_vtt_file_path(path)
        .ok_or_else(|| BlossomError::BadRequest("Invalid VTT path".into()))?;
    handle_head_transcript_by_hash(&hash)
}

fn handle_head_transcript_by_hash(hash: &str) -> Result<Response> {
    let metadata = get_blob_metadata(hash)?
        .ok_or_else(|| BlossomError::NotFound("Content not found".into()))?;

    // HEAD has no req/admin context. Banned/Restricted collapse to 404; AgeRestricted
    // surfaces as 401 so the client knows to age-gate.
    match metadata.access_for(None, false) {
        BlobAccess::Allowed => {}
        BlobAccess::NotFound => return Err(BlossomError::NotFound("Content not found".into())),
        BlobAccess::AgeGated => return Err(BlossomError::AuthRequired("age_restricted".into())),
    }

    if !is_transcribable_mime_type(&metadata.mime_type) {
        return Err(BlossomError::NotFound(
            "Transcript not available for this media type".into(),
        ));
    }

    let gcs_path = format!("{}/vtt/main.vtt", hash);
    match download_transcript_content(&gcs_path) {
        Ok(_) => {
            if metadata.transcript_status != Some(TranscriptStatus::Complete) {
                use crate::metadata::update_transcript_status;
                let _ = update_transcript_status(
                    hash,
                    TranscriptStatus::Complete,
                    TranscriptMetadataUpdate {
                        last_attempt_at: Some(current_timestamp()),
                        ..Default::default()
                    },
                );
            }
            let mut resp = Response::from_status(StatusCode::OK);
            resp.set_header("Content-Type", "text/vtt; charset=utf-8");
            add_cache_headers(&mut resp, hash);
            add_cors_headers(&mut resp);
            Ok(resp)
        }
        Err(BlossomError::NotFound(_)) => match decide_transcript_fetch_action(
            metadata.transcript_status,
            metadata.transcript_retry_after,
            metadata.transcript_attempt_count,
            metadata.transcript_terminal,
            unix_timestamp_secs(),
        ) {
            TranscriptFetchAction::Accepted {
                retry_after_secs, ..
            }
            | TranscriptFetchAction::Trigger {
                retry_after_secs, ..
            } => {
                let mut resp = Response::from_status(StatusCode::ACCEPTED);
                resp.set_header("Retry-After", retry_after_secs.to_string());
                add_no_cache_headers(&mut resp);
                add_cors_headers(&mut resp);
                Ok(resp)
            }
            TranscriptFetchAction::Terminal => Ok(derivative_failure_head_response(
                hash,
                metadata.transcript_error_code.as_deref(),
                "text/vtt; charset=utf-8",
            )),
        },
        Err(e) => Err(e),
    }
}

fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn generate_subtitle_job_id(hash: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seed = format!("{}:{}:{}", hash, now.as_secs(), now.subsec_nanos());
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("sub_{}", &digest[..24])
}

fn subtitle_backoff_seconds(attempt_count: u32) -> u64 {
    match attempt_count {
        0 | 1 => 30,
        2 => 120,
        _ => 300,
    }
}

fn apply_subtitle_job_failure(
    job: &mut SubtitleJob,
    error_code: Option<String>,
    error_message: Option<String>,
) {
    job.status = SubtitleJobStatus::Failed;
    job.updated_at = current_timestamp();
    job.error_code = error_code;
    job.error_message = error_message;

    if job.attempt_count >= job.max_attempts {
        if job.error_code.is_none() {
            job.error_code = Some("poison_queue".to_string());
        }
        if job.error_message.is_none() {
            job.error_message =
                Some("Maximum retry attempts reached; job moved to poison queue".to_string());
        }
        job.next_retry_at_unix = None;
    } else {
        let delay = subtitle_backoff_seconds(job.attempt_count);
        job.next_retry_at_unix = Some(unix_timestamp_secs() + delay);
    }
}

fn dispatch_subtitle_job(job: &mut SubtitleJob, owner: &str) -> Result<()> {
    job.status = SubtitleJobStatus::Processing;
    job.updated_at = current_timestamp();
    job.attempt_count = job.attempt_count.saturating_add(1);
    job.next_retry_at_unix = None;
    job.error_code = None;
    job.error_message = None;
    put_subtitle_job(job)?;
    let _ = crate::metadata::update_transcript_status(
        &job.video_sha256,
        TranscriptStatus::Processing,
        TranscriptMetadataUpdate {
            last_attempt_at: Some(current_timestamp()),
            ..Default::default()
        },
    );

    let lang_for_provider = job
        .language
        .as_deref()
        .filter(|lang| !lang.eq_ignore_ascii_case("auto") && !lang.eq_ignore_ascii_case("und"));

    match trigger_on_demand_transcription(
        &job.video_sha256,
        owner,
        Some(&job.job_id),
        lang_for_provider,
    ) {
        Ok(()) => Ok(()),
        Err(e) => {
            apply_subtitle_job_failure(
                job,
                Some("dispatch_failed".to_string()),
                Some(e.to_string()),
            );
            let _ = put_subtitle_job(job);
            Err(e)
        }
    }
}

/// POST /v1/subtitles/jobs
fn handle_create_subtitle_job(mut req: Request) -> Result<Response> {
    let body = req.take_body().into_string();
    let create_req: SubtitleJobCreateRequest = serde_json::from_str(&body)
        .map_err(|e| BlossomError::BadRequest(format!("Invalid JSON: {}", e)))?;

    let hash = create_req.video_sha256.to_lowercase();
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BlossomError::BadRequest(
            "Invalid video_sha256 format".into(),
        ));
    }

    let metadata = get_blob_metadata(&hash)?
        .ok_or_else(|| BlossomError::NotFound("Video hash not found".into()))?;

    if !is_transcribable_mime_type(&metadata.mime_type) {
        return Err(BlossomError::BadRequest(
            "Media type is not transcribable".into(),
        ));
    }

    if !create_req.force {
        if let Some(mut existing) = get_subtitle_job_by_hash(&hash)? {
            if existing.status == SubtitleJobStatus::Failed
                && existing.attempt_count < existing.max_attempts
            {
                let now = unix_timestamp_secs();
                if existing
                    .next_retry_at_unix
                    .map(|t| now >= t)
                    .unwrap_or(true)
                {
                    let _ = dispatch_subtitle_job(&mut existing, &metadata.owner);
                }
            }
            let mut resp = json_response(StatusCode::OK, &existing);
            add_cors_headers(&mut resp);
            return Ok(resp);
        }
    }

    if !create_req.force && metadata.transcript_status == Some(TranscriptStatus::Complete) {
        let ready_job = SubtitleJob {
            job_id: generate_subtitle_job_id(&hash),
            video_sha256: hash.clone(),
            status: SubtitleJobStatus::Ready,
            text_track_url: Some(format!("{}/{}.vtt", get_base_url(&req), hash)),
            language: create_req
                .lang
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .or_else(|| Some("auto".to_string())),
            duration_ms: None,
            cue_count: None,
            sha256: hash.clone(),
            attempt_count: 1,
            max_attempts: SUBTITLE_MAX_ATTEMPTS,
            next_retry_at_unix: None,
            error_code: None,
            error_message: None,
            created_at: current_timestamp(),
            updated_at: current_timestamp(),
        };
        put_subtitle_job(&ready_job)?;
        set_subtitle_job_id_for_hash(&hash, &ready_job.job_id)?;

        let mut resp = json_response(StatusCode::OK, &ready_job);
        add_cors_headers(&mut resp);
        return Ok(resp);
    }

    let text_track_url = format!("{}/{}.vtt", get_base_url(&req), hash);
    let language = create_req
        .lang
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .or_else(|| Some("auto".to_string()));
    let mut job = SubtitleJob {
        job_id: generate_subtitle_job_id(&hash),
        video_sha256: hash.clone(),
        status: SubtitleJobStatus::Queued,
        text_track_url: Some(text_track_url),
        language,
        duration_ms: None,
        cue_count: None,
        sha256: hash.clone(),
        attempt_count: 0,
        max_attempts: SUBTITLE_MAX_ATTEMPTS,
        next_retry_at_unix: None,
        error_code: None,
        error_message: None,
        created_at: current_timestamp(),
        updated_at: current_timestamp(),
    };

    put_subtitle_job(&job)?;
    set_subtitle_job_id_for_hash(&hash, &job.job_id)?;

    let dispatch_result = dispatch_subtitle_job(&mut job, &metadata.owner);
    if let Err(e) = dispatch_result {
        let mut resp = json_response(StatusCode::BAD_GATEWAY, &job);
        add_cors_headers(&mut resp);
        resp.set_header("X-Error", format!("Dispatch failed: {}", e));
        return Ok(resp);
    }

    let mut resp = json_response(StatusCode::ACCEPTED, &job);
    add_no_cache_headers(&mut resp);
    add_cors_headers(&mut resp);
    Ok(resp)
}

/// GET /v1/subtitles/jobs/{job_id}
fn handle_get_subtitle_job(path: &str) -> Result<Response> {
    let job_id = path
        .strip_prefix("/v1/subtitles/jobs/")
        .ok_or_else(|| BlossomError::BadRequest("Invalid subtitle job path".into()))?;

    if job_id.is_empty() {
        return Err(BlossomError::BadRequest("Missing job_id".into()));
    }

    let job = get_subtitle_job(job_id)?
        .ok_or_else(|| BlossomError::NotFound("Subtitle job not found".into()))?;

    let mut resp = json_response(StatusCode::OK, &job);
    add_cors_headers(&mut resp);
    Ok(resp)
}

/// GET /v1/subtitles/by-hash/{sha256}
fn handle_get_subtitle_by_hash(req: Request, path: &str) -> Result<Response> {
    let hash = path
        .strip_prefix("/v1/subtitles/by-hash/")
        .ok_or_else(|| BlossomError::BadRequest("Invalid subtitle hash path".into()))?
        .to_lowercase();

    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BlossomError::BadRequest("Invalid sha256 format".into()));
    }

    // Don't leak subtitle info for moderated content. Use the blob's access_for so
    // age-restricted videos surface as 401 (age gate) instead of 404.
    let is_admin = admin::validate_bearer_token(&req).is_ok();
    if let Some(meta) = get_blob_metadata(&hash)? {
        let (requester_pk, auth_diagnostics) = media_viewer_context(&req, "subtitle_by_hash")?;
        match meta.access_for(requester_pk.as_deref(), is_admin) {
            BlobAccess::Allowed => {
                log_media_outcome("subtitle_by_hash", &auth_diagnostics, "allowed")
            }
            BlobAccess::NotFound => {
                log_media_outcome("subtitle_by_hash", &auth_diagnostics, "not_found");
                return Err(BlossomError::NotFound("Video hash not found".into()));
            }
            BlobAccess::AgeGated => {
                log_media_outcome("subtitle_by_hash", &auth_diagnostics, "age_gated");
                return Err(BlossomError::AuthRequired("age_restricted".into()));
            }
        }
    }

    if let Some(job) = get_subtitle_job_by_hash(&hash)? {
        let mut resp = json_response(StatusCode::OK, &job);
        add_cors_headers(&mut resp);
        return Ok(resp);
    }

    let metadata = get_blob_metadata(&hash)?
        .ok_or_else(|| BlossomError::NotFound("Video hash not found".into()))?;

    if metadata.transcript_status == Some(TranscriptStatus::Complete) {
        let job = SubtitleJob {
            job_id: generate_subtitle_job_id(&hash),
            video_sha256: hash.clone(),
            status: SubtitleJobStatus::Ready,
            text_track_url: Some(format!("{}/{}.vtt", get_base_url(&req), hash)),
            language: None,
            duration_ms: None,
            cue_count: None,
            sha256: hash.clone(),
            attempt_count: 1,
            max_attempts: SUBTITLE_MAX_ATTEMPTS,
            next_retry_at_unix: None,
            error_code: None,
            error_message: None,
            created_at: current_timestamp(),
            updated_at: current_timestamp(),
        };
        put_subtitle_job(&job)?;
        set_subtitle_job_id_for_hash(&hash, &job.job_id)?;

        let mut resp = json_response(StatusCode::OK, &job);
        add_cors_headers(&mut resp);
        return Ok(resp);
    }

    Err(BlossomError::NotFound(
        "Subtitle job not found for hash".into(),
    ))
}

/// Valid quality variant suffixes: (url_suffix, gcs_filename, content_type)
const QUALITY_VARIANTS: &[(&str, &str, &str)] = &[
    ("/720p", "stream_720p.ts", "video/mp2t"),
    ("/480p", "stream_480p.ts", "video/mp2t"),
    ("/720p.mp4", "stream_720p.mp4", "video/mp4"),
    ("/480p.mp4", "stream_480p.mp4", "video/mp4"),
];

/// GET /{sha256}.audio.m4a - Extract and serve audio from a video blob.
///
/// Permission is hash-level: if ANY public current video event for this sha256
/// opts into audio reuse via Funnelcake, extraction is allowed. This collapses
/// event-level permission to hash-level because Blossom is content-addressed.
fn handle_get_audio(req: Request, path: &str) -> Result<Response> {
    let hash = parse_audio_path(path)
        .ok_or_else(|| BlossomError::BadRequest("Invalid hash in audio path".into()))?;

    // 1. Look up source blob metadata
    let metadata =
        get_blob_metadata(&hash)?.ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;

    // 2. Access control. Audio extraction requires the source video to be accessible to
    //    the caller — banned/deleted/shadow-restricted source -> 404; anonymous
    //    age-restricted source -> 401 (age gate). Any authenticated viewer may access
    //    age-restricted content, while shadow-restricted content stays owner/admin only.
    let (requester_pk, auth_diagnostics) = media_viewer_context(&req, "audio")?;
    let is_admin = admin::validate_bearer_token(&req).is_ok();
    match metadata.access_for(requester_pk.as_deref(), is_admin) {
        BlobAccess::Allowed => log_media_outcome("audio", &auth_diagnostics, "allowed"),
        BlobAccess::NotFound => {
            log_media_outcome("audio", &auth_diagnostics, "not_found");
            return Err(BlossomError::NotFound("Blob not found".into()));
        }
        BlobAccess::AgeGated => {
            log_media_outcome("audio", &auth_diagnostics, "age_gated");
            return Err(BlossomError::AuthRequired("age_restricted".into()));
        }
    }

    // 3. Check Funnelcake permission
    let permission = match check_funnelcake_audio_reuse(&hash) {
        ok @ Ok(_) => classify_audio_reuse_availability(&ok),
        Err(e) => {
            eprintln!("[AUDIO] Funnelcake unavailable for {}: {}", hash, e);
            AudioReuseAvailability::LookupUnavailable
        }
    };

    match permission {
        AudioReuseAvailability::Allowed => {}
        AudioReuseAvailability::Denied => return Ok(audio_reuse_denied_response()),
        AudioReuseAvailability::LookupUnavailable => return Ok(audio_lookup_unavailable_response()),
    }

    let private_cache = is_admin || metadata.status.requires_private_cache();

    // 4. Must be a video source
    if !is_video_mime_type(&metadata.mime_type) {
        let mut resp = Response::from_status(StatusCode::UNPROCESSABLE_ENTITY);
        resp.set_header("Content-Type", "application/json");
        resp.set_body(r#"{"error":"not_a_video"}"#);
        add_cors_headers(&mut resp);
        return Ok(resp);
    }

    let range = req
        .get_header(header::RANGE)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // 5. Check cache: source->audio mapping
    if let Some(mapping) = get_audio_mapping(&hash)? {
        // Verify the audio blob still exists in GCS
        if blob_exists(&mapping.audio_sha256)? {
            add_to_audio_source_refs(&mapping.audio_sha256, &hash).map_err(|e| {
                BlossomError::Internal(format!("Failed to persist audio source refs: {}", e))
            })?;
            // Serve cached audio via redirect or proxy
            let result = download_blob_with_fallback(&mapping.audio_sha256, range.as_deref())?;
            let mut resp = result.response;
            add_audio_response_headers(
                &mut resp,
                &hash,
                private_cache,
                &mapping.mime_type,
                mapping.size_bytes,
                mapping.duration_seconds,
            );
            return Ok(resp);
        }
        // Audio blob gone, fall through to re-extract
        clear_stale_audio_mapping(&hash, &mapping.audio_sha256);
    }

    // 6. Trigger Cloud Run audio extraction (synchronous)
    let extraction = trigger_audio_extraction(&hash, &metadata.owner)?;

    // Handle extraction-level errors
    if let Some(ref error) = extraction.error {
        if error == "not_a_video" || error == "no_audio_track" {
            let mut resp = Response::from_status(StatusCode::UNPROCESSABLE_ENTITY);
            resp.set_header("Content-Type", "application/json");
            resp.set_body(format!(r#"{{"error":"{}"}}"#, error));
            add_cors_headers(&mut resp);
            return Ok(resp);
        }
        return Err(BlossomError::Internal(format!(
            "Audio extraction failed: {}",
            error
        )));
    }

    let audio_sha256 = extraction
        .audio_sha256
        .ok_or_else(|| BlossomError::Internal("Audio extraction returned no hash".into()))?;
    let duration = extraction.duration.unwrap_or(0.0);
    let size = extraction.size.unwrap_or(0);
    let mime_type = extraction
        .mime_type
        .unwrap_or_else(|| "audio/mp4".to_string());

    // 7. Store audio blob metadata (so /{audio_sha256} works as normal Blossom blob)
    // Do NOT add to user lists or recent indexes for derived blobs.
    let audio_metadata = BlobMetadata {
        sha256: audio_sha256.clone(),
        size,
        mime_type: mime_type.clone(),
        uploaded: current_timestamp(),
        owner: metadata.owner.clone(),
        status: BlobStatus::Active,
        thumbnail: None,
        moderation: None,
        transcode_status: None,
        transcode_error_code: None,
        transcode_error_message: None,
        transcode_last_attempt_at: None,
        transcode_retry_after: None,
        transcode_attempt_count: 0,
        transcode_terminal: false,
        dim: None,
        transcript_status: None,
        transcript_error_code: None,
        transcript_error_message: None,
        transcript_last_attempt_at: None,
        transcript_retry_after: None,
        transcript_attempt_count: 0,
        transcript_terminal: false,
    };
    let _ = put_blob_metadata(&audio_metadata);

    // 8. Store source->audio mapping and reverse refs.
    let mapping = AudioMapping {
        source_sha256: hash.clone(),
        audio_sha256: audio_sha256.clone(),
        duration_seconds: duration,
        size_bytes: size,
        mime_type: mime_type.clone(),
    };
    put_audio_mapping(&mapping)?;
    add_to_audio_source_refs(&audio_sha256, &hash).map_err(|e| {
        BlossomError::Internal(format!("Failed to persist audio source refs: {}", e))
    })?;

    // 8. Download and serve the audio
    let result = download_blob_with_fallback(&audio_sha256, range.as_deref())?;
    let mut resp = result.response;
    add_audio_response_headers(&mut resp, &hash, private_cache, &mime_type, size, duration);
    Ok(resp)
}

/// HEAD /{sha256}.audio.m4a - Check audio extraction status
fn handle_head_audio(path: &str) -> Result<Response> {
    let hash = parse_audio_path(path)
        .ok_or_else(|| BlossomError::BadRequest("Invalid hash in audio path".into()))?;

    let metadata =
        get_blob_metadata(&hash)?.ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;

    // HEAD has no req/admin context. Banned/Restricted collapse to 404; AgeRestricted
    // surfaces as 401 so the client knows to age-gate.
    match metadata.access_for(None, false) {
        BlobAccess::Allowed => {}
        BlobAccess::NotFound => return Err(BlossomError::NotFound("Blob not found".into())),
        BlobAccess::AgeGated => return Err(BlossomError::AuthRequired("age_restricted".into())),
    }

    let permission = classify_audio_reuse_availability(&check_funnelcake_audio_reuse(&hash));
    match permission {
        AudioReuseAvailability::Allowed => {}
        AudioReuseAvailability::Denied => return Ok(audio_reuse_denied_response()),
        AudioReuseAvailability::LookupUnavailable => return Ok(audio_lookup_unavailable_response()),
    }

    if !is_video_mime_type(&metadata.mime_type) {
        let mut resp = Response::from_status(StatusCode::UNPROCESSABLE_ENTITY);
        resp.set_header("Content-Type", "application/json");
        resp.set_body(r#"{"error":"not_a_video"}"#);
        add_no_cache_headers(&mut resp);
        add_cors_headers(&mut resp);
        return Ok(resp);
    }

    // Check if audio mapping exists
    if let Some(mapping) = get_audio_mapping(&hash)? {
        if blob_exists(&mapping.audio_sha256)? {
            add_to_audio_source_refs(&mapping.audio_sha256, &hash).map_err(|e| {
                BlossomError::Internal(format!("Failed to persist audio source refs: {}", e))
            })?;
            let mut resp = Response::from_status(StatusCode::OK);
            add_audio_response_headers(
                &mut resp,
                &hash,
                metadata.status.requires_private_cache(),
                &mapping.mime_type,
                mapping.size_bytes,
                mapping.duration_seconds,
            );
            return Ok(resp);
        }
        clear_stale_audio_mapping(&hash, &mapping.audio_sha256);
    }

    // No audio extracted yet
    Err(BlossomError::NotFound("Audio not yet extracted".into()))
}

/// Check if a path is a quality variant request like /{hash}/720p
fn is_quality_variant_path(path: &str) -> bool {
    let path = path.trim_start_matches('/');
    for (suffix, _, _) in QUALITY_VARIANTS {
        let suffix = suffix.trim_start_matches('/');
        // Need at least hash(64) + '/' + suffix
        if path.ends_with(suffix) && path.len() > suffix.len() + 1 {
            let hash_part = &path[..path.len() - suffix.len() - 1];
            if hash_part.len() == 64 && hash_part.chars().all(|c| c.is_ascii_hexdigit()) {
                return true;
            }
        }
    }
    false
}

/// Parse quality variant path into (hash, gcs_filename, content_type)
fn parse_quality_variant_path(path: &str) -> Option<(String, &'static str, &'static str)> {
    let path = path.trim_start_matches('/');
    for (suffix, filename, content_type) in QUALITY_VARIANTS {
        let suffix = suffix.trim_start_matches('/');
        if path.ends_with(suffix) && path.len() > suffix.len() + 1 {
            let hash_part = &path[..path.len() - suffix.len() - 1];
            if hash_part.len() == 64 && hash_part.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some((hash_part.to_lowercase(), filename, content_type));
            }
        }
    }
    None
}

/// GET /<sha256>/720p or /<sha256>/480p - Direct access to transcoded quality variant
fn handle_get_quality_variant(req: Request, path: &str) -> Result<Response> {
    let (hash, ts_filename, content_type) = parse_quality_variant_path(path)
        .ok_or_else(|| BlossomError::BadRequest("Invalid quality variant path".into()))?;

    // Check metadata for access control
    let is_admin = admin::validate_bearer_token(&req).is_ok();
    let metadata = get_blob_metadata(&hash)?;
    if let Some(ref meta) = metadata {
        let (requester_pk, auth_diagnostics) = media_viewer_context(&req, "quality_variant")?;
        match meta.access_for(requester_pk.as_deref(), is_admin) {
            BlobAccess::Allowed => {
                log_media_outcome("quality_variant", &auth_diagnostics, "allowed")
            }
            BlobAccess::NotFound => {
                log_media_outcome("quality_variant", &auth_diagnostics, "not_found");
                return Err(BlossomError::NotFound("Content not found".into()));
            }
            BlobAccess::AgeGated => {
                log_media_outcome("quality_variant", &auth_diagnostics, "age_gated");
                return Err(BlossomError::AuthRequired("age_restricted".into()));
            }
        }
    } else {
        return Err(BlossomError::NotFound("Content not found".into()));
    }

    let meta = metadata.as_ref().unwrap();
    let gcs_path = format!("{}/hls/{}", hash, ts_filename);

    // Extract Range header from client request to forward to GCS
    let range = req
        .get_header(header::RANGE)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    match download_hls_content(&gcs_path, range.as_deref()) {
        Ok(mut resp) => {
            resp.set_header("Content-Type", content_type);
            if is_admin || meta.status.requires_private_cache() {
                add_private_cache_headers(&mut resp, &hash);
            } else {
                add_cache_headers(&mut resp, &hash);
            }
            resp.set_header("Accept-Ranges", "bytes");
            add_cors_headers(&mut resp);
            Ok(resp)
        }
        Err(BlossomError::NotFound(_)) => {
            // For .mp4 requests, check if the .ts counterpart exists for lazy remux
            if content_type == "video/mp4" {
                let ts_name = ts_filename.replace(".mp4", ".ts");
                let ts_gcs_path = format!("{}/hls/{}", hash, ts_name);
                if download_hls_content(&ts_gcs_path, Some("bytes=0-0")).is_ok() {
                    let _ = trigger_fmp4_backfill(&hash);

                    let mut resp = Response::from_status(StatusCode::ACCEPTED);
                    resp.set_header("Retry-After", "3");
                    resp.set_header("Content-Type", "application/json");
                    resp.set_body(
                        r#"{"status":"processing","message":"Remuxing to fMP4, please retry"}"#,
                    );
                    add_no_cache_headers(&mut resp);
                    add_cors_headers(&mut resp);
                    return Ok(resp);
                }
            }

            // HLS not ready — use the bounding classifier to decide whether to
            // trigger, return "in progress", or declare terminal failure.
            match decide_transcode_fetch_action(
                meta.transcode_status,
                meta.transcode_retry_after,
                meta.transcode_attempt_count,
                meta.transcode_terminal,
                unix_timestamp_secs(),
            ) {
                TranscodeFetchAction::Terminal => Ok(derivative_failure_response(
                    meta.transcode_error_code.as_deref(),
                    meta.transcode_error_message.as_deref(),
                    "Video transcoding permanently failed",
                )),
                TranscodeFetchAction::Accepted {
                    retry_after_secs, ..
                } => {
                    let mut resp = Response::from_status(StatusCode::ACCEPTED);
                    resp.set_header("Retry-After", retry_after_secs.to_string());
                    resp.set_header("Content-Type", "application/json");
                    resp.set_body(r#"{"status":"processing","message":"Video is being transcoded, please retry"}"#);
                    add_no_cache_headers(&mut resp);
                    add_cors_headers(&mut resp);
                    Ok(resp)
                }
                TranscodeFetchAction::Trigger {
                    retry_after_secs, ..
                } => {
                    use crate::metadata::update_transcode_status;
                    let _ = update_transcode_status(&hash, TranscodeStatus::Processing);
                    let _ = trigger_on_demand_transcoding(&hash, &meta.owner);

                    let mut resp = Response::from_status(StatusCode::ACCEPTED);
                    resp.set_header("Retry-After", retry_after_secs.to_string());
                    resp.set_header("Content-Type", "application/json");
                    resp.set_body(
                        r#"{"status":"processing","message":"Transcoding started, please retry"}"#,
                    );
                    add_no_cache_headers(&mut resp);
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
    let (hash, ts_filename, content_type) = parse_quality_variant_path(path)
        .ok_or_else(|| BlossomError::BadRequest("Invalid quality variant path".into()))?;

    let metadata = get_blob_metadata(&hash)?
        .ok_or_else(|| BlossomError::NotFound("Content not found".into()))?;

    // HEAD has no req/admin context. Banned/Restricted collapse to 404; AgeRestricted
    // surfaces as 401 so the client knows to age-gate.
    match metadata.access_for(None, false) {
        BlobAccess::Allowed => {}
        BlobAccess::NotFound => return Err(BlossomError::NotFound("Content not found".into())),
        BlobAccess::AgeGated => return Err(BlossomError::AuthRequired("age_restricted".into())),
    }

    let gcs_path = format!("{}/hls/{}", hash, ts_filename);
    download_hls_content(&gcs_path, None)?;

    let mut resp = Response::from_status(StatusCode::OK);
    resp.set_header("Content-Type", content_type);
    resp.set_header("Accept-Ranges", "bytes");
    add_cors_headers(&mut resp);
    Ok(resp)
}

/// Check if an admin API path contains a quality variant suffix
/// e.g. /admin/api/blob/{hash}/720p.mp4
fn is_admin_quality_variant_path(path: &str) -> bool {
    let rest = path.strip_prefix("/admin/api/blob/").unwrap_or("");
    for (suffix, _, _) in QUALITY_VARIANTS {
        let suffix = suffix.trim_start_matches('/');
        if rest.ends_with(suffix) && rest.len() > suffix.len() + 1 {
            let hash_part = &rest[..rest.len() - suffix.len() - 1];
            if hash_part.len() == 64 && hash_part.chars().all(|c| c.is_ascii_hexdigit()) {
                return true;
            }
        }
    }
    false
}

/// Parse admin quality variant path into (hash, gcs_filename, content_type)
fn parse_admin_quality_variant_path(path: &str) -> Option<(String, &'static str, &'static str)> {
    let rest = path.strip_prefix("/admin/api/blob/").unwrap_or("");
    for (suffix, filename, content_type) in QUALITY_VARIANTS {
        let suffix = suffix.trim_start_matches('/');
        if rest.ends_with(suffix) && rest.len() > suffix.len() + 1 {
            let hash_part = &rest[..rest.len() - suffix.len() - 1];
            if hash_part.len() == 64 && hash_part.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some((hash_part.to_lowercase(), filename, content_type));
            }
        }
    }
    None
}

/// GET /admin/api/blob/{hash}/720p.mp4 (etc.) - Serve transcoded variant regardless of moderation status
/// Used by divine-moderation-service admin proxy for moderator review of flagged content
fn handle_admin_quality_variant(req: Request, path: &str) -> Result<Response> {
    admin::validate_admin_auth(&req)?;

    let (hash, ts_filename, content_type) = parse_admin_quality_variant_path(path)
        .ok_or_else(|| BlossomError::BadRequest("Invalid admin quality variant path".into()))?;

    // Verify blob exists (but don't check moderation status)
    let meta =
        get_blob_metadata(&hash)?.ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;

    let gcs_path = format!("{}/hls/{}", hash, ts_filename);

    let range = req
        .get_header(header::RANGE)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    match download_hls_content(&gcs_path, range.as_deref()) {
        Ok(mut resp) => {
            resp.set_header("Content-Type", content_type);
            resp.set_header("X-Sha256", &hash);
            resp.set_header("X-Moderation-Status", &format!("{:?}", meta.status));
            resp.set_header("Accept-Ranges", "bytes");
            resp.set_header("Cache-Control", "private, no-store");
            add_cors_headers(&mut resp);
            Ok(resp)
        }
        Err(BlossomError::NotFound(_)) => {
            // For .mp4 requests, check if .ts counterpart exists for lazy remux
            if content_type == "video/mp4" {
                let ts_name = ts_filename.replace(".mp4", ".ts");
                let ts_gcs_path = format!("{}/hls/{}", hash, ts_name);
                if download_hls_content(&ts_gcs_path, Some("bytes=0-0")).is_ok() {
                    let _ = trigger_fmp4_backfill(&hash);

                    let mut resp = Response::from_status(StatusCode::ACCEPTED);
                    resp.set_header("Retry-After", "3");
                    resp.set_header("Content-Type", "application/json");
                    resp.set_body(
                        r#"{"status":"processing","message":"Remuxing to fMP4, please retry"}"#,
                    );
                    add_no_cache_headers(&mut resp);
                    add_cors_headers(&mut resp);
                    return Ok(resp);
                }
            }

            // Not transcoded yet — trigger on-demand transcoding
            match decide_transcode_fetch_action(
                meta.transcode_status,
                meta.transcode_retry_after,
                meta.transcode_attempt_count,
                meta.transcode_terminal,
                unix_timestamp_secs(),
            ) {
                TranscodeFetchAction::Terminal => Ok(derivative_failure_response(
                    meta.transcode_error_code.as_deref(),
                    meta.transcode_error_message.as_deref(),
                    "Video transcoding permanently failed",
                )),
                TranscodeFetchAction::Accepted {
                    retry_after_secs, ..
                } => {
                    let mut resp = Response::from_status(StatusCode::ACCEPTED);
                    resp.set_header("Retry-After", retry_after_secs.to_string());
                    resp.set_header("Content-Type", "application/json");
                    resp.set_body(r#"{"status":"processing","message":"Video is being transcoded, please retry"}"#);
                    add_no_cache_headers(&mut resp);
                    add_cors_headers(&mut resp);
                    Ok(resp)
                }
                TranscodeFetchAction::Trigger {
                    retry_after_secs, ..
                } => {
                    use crate::metadata::update_transcode_status;
                    let _ = update_transcode_status(&hash, TranscodeStatus::Processing);
                    let _ = trigger_on_demand_transcoding(&hash, &meta.owner);

                    let mut resp = Response::from_status(StatusCode::ACCEPTED);
                    resp.set_header("Retry-After", retry_after_secs.to_string());
                    resp.set_header("Content-Type", "application/json");
                    resp.set_body(
                        r#"{"status":"processing","message":"Transcoding started, please retry"}"#,
                    );
                    add_no_cache_headers(&mut resp);
                    add_cors_headers(&mut resp);
                    Ok(resp)
                }
            }
        }
        Err(e) => Err(e),
    }
}

/// GET /admin/api/blob/{hash}/hls/{filename} - Serve HLS content regardless of moderation status
/// Used by divine-moderation-service admin proxy for moderator review of flagged content
fn handle_admin_hls_content(req: Request, path: &str) -> Result<Response> {
    admin::validate_admin_auth(&req)?;

    // Parse: /admin/api/blob/{hash}/hls/{filename}
    let rest = path
        .strip_prefix("/admin/api/blob/")
        .ok_or_else(|| BlossomError::BadRequest("Invalid admin HLS path".into()))?;
    let parts: Vec<&str> = rest.splitn(3, '/').collect();
    if parts.len() < 3 || parts[1] != "hls" {
        return Err(BlossomError::BadRequest(
            "Invalid admin HLS path format".into(),
        ));
    }

    let hash = parts[0];
    let filename = parts[2];

    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BlossomError::BadRequest("Invalid hash in path".into()));
    }
    let hash = hash.to_lowercase();

    // Verify blob exists (but don't check moderation status)
    let meta =
        get_blob_metadata(&hash)?.ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;

    let gcs_path = format!("{}/hls/{}", hash, filename);

    match download_hls_content(&gcs_path, None) {
        Ok(mut resp) => {
            let content_type = if filename.ends_with(".m3u8") {
                "application/vnd.apple.mpegurl"
            } else if filename.ends_with(".ts") {
                "video/mp2t"
            } else {
                "application/octet-stream"
            };

            resp.set_header("Content-Type", content_type);
            resp.set_header("X-Sha256", &hash);
            resp.set_header("X-Moderation-Status", &format!("{:?}", meta.status));
            resp.set_header("Cache-Control", "private, no-store");
            add_cors_headers(&mut resp);
            Ok(resp)
        }
        Err(BlossomError::NotFound(_)) if filename == "master.m3u8" => {
            // HLS not ready — trigger on-demand transcoding
            match decide_transcode_fetch_action(
                meta.transcode_status,
                meta.transcode_retry_after,
                meta.transcode_attempt_count,
                meta.transcode_terminal,
                unix_timestamp_secs(),
            ) {
                TranscodeFetchAction::Terminal => Ok(derivative_failure_response(
                    meta.transcode_error_code.as_deref(),
                    meta.transcode_error_message.as_deref(),
                    "HLS generation failed for this blob",
                )),
                TranscodeFetchAction::Accepted {
                    retry_after_secs, ..
                } => {
                    let mut resp = Response::from_status(StatusCode::ACCEPTED);
                    resp.set_header("Retry-After", retry_after_secs.to_string());
                    resp.set_header("Content-Type", "application/json");
                    resp.set_body(
                        r#"{"status":"processing","message":"HLS transcoding in progress"}"#,
                    );
                    add_no_cache_headers(&mut resp);
                    add_cors_headers(&mut resp);
                    Ok(resp)
                }
                TranscodeFetchAction::Trigger {
                    retry_after_secs, ..
                } => {
                    use crate::metadata::update_transcode_status;
                    let _ = update_transcode_status(&hash, TranscodeStatus::Processing);
                    let _ = trigger_on_demand_transcoding(&hash, &meta.owner);

                    let mut resp = Response::from_status(StatusCode::ACCEPTED);
                    resp.set_header("Retry-After", retry_after_secs.to_string());
                    resp.set_header("Content-Type", "application/json");
                    resp.set_body(r#"{"status":"processing","message":"HLS transcoding started, please retry soon"}"#);
                    add_no_cache_headers(&mut resp);
                    add_cors_headers(&mut resp);
                    Ok(resp)
                }
            }
        }
        Err(e) => Err(e),
    }
}

/// Maximum size for in-process upload (500KB) - larger files proxy to the upload service
const UPLOAD_SERVICE_THRESHOLD: u64 = 500 * 1024;

/// Upload service backend name (must match a backend configured in the
/// Fastly dashboard whose address is `upload.divine.video`).
const UPLOAD_SERVICE_BACKEND: &str = "upload_service";
/// Public hostname for the upload service.
const UPLOAD_SERVICE_HOST: &str = "upload.divine.video";

/// Upload service host for on-demand thumbnail generation
const UPLOAD_SERVICE_THUMBNAIL_HOST: &str = UPLOAD_SERVICE_HOST;

/// Cloud Run host for on-demand transcoding
const CLOUD_RUN_TRANSCODER_HOST: &str = "divine-transcoder-149672065768.us-central1.run.app";

/// Backend name for the Cloud Run transcoder. MUST be configured in the
/// Fastly dashboard as a separate backend pointing at CLOUD_RUN_TRANSCODER_HOST
/// (address: divine-transcoder-149672065768.us-central1.run.app, port 443,
/// SSL on, SNI = host, override_host = host). Without this, calls to
/// /transcode, /backfill-fmp4, /transcribe silently misroute to the upload
/// service and 404, leaving videos stuck in `Processing` forever.
const TRANSCODER_BACKEND: &str = "cloud_run_transcoder";

/// Generate thumbnail on-demand by proxying to Cloud Run
fn generate_thumbnail_on_demand(hash: &str) -> Result<Response> {
    if crate::storage::is_local_mode() {
        eprintln!(
            "[THUMB][LOCAL] Returning placeholder thumbnail for {}",
            hash
        );
        // Minimal valid JPEG (smallest possible)
        let jpeg: Vec<u8> = vec![
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43, 0x00, 0x08, 0x06, 0x06,
            0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09, 0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D,
            0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12, 0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D,
            0x1A, 0x1C, 0x1C, 0x20, 0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28,
            0x37, 0x29, 0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
            0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01,
            0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x05, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0xFF, 0xDA, 0x00, 0x08, 0x01,
            0x01, 0x00, 0x00, 0x3F, 0x00, 0x7B, 0x94, 0x11, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD9,
        ];
        let thumb_key = format!("{}.jpg", hash);
        if let Err(e) = crate::storage::upload_blob(
            &thumb_key,
            fastly::Body::from(jpeg.as_slice()),
            "image/jpeg",
            jpeg.len() as u64,
            "",
        ) {
            eprintln!("[THUMB][LOCAL] Failed to store placeholder: {}", e);
        }
        let mut resp = Response::from_status(StatusCode::OK);
        resp.set_header("Content-Type", "image/jpeg");
        resp.set_body(fastly::Body::from(jpeg));
        return Ok(resp);
    }

    let url = format!(
        "https://{}/thumbnail/{}",
        UPLOAD_SERVICE_THUMBNAIL_HOST, hash
    );

    let mut proxy_req = Request::new(Method::GET, &url);
    proxy_req.set_header("Host", UPLOAD_SERVICE_THUMBNAIL_HOST);

    let resp = proxy_req.send(UPLOAD_SERVICE_BACKEND).map_err(|e| {
        BlossomError::StorageError(format!("Cloud Run thumbnail request failed: {}", e))
    })?;

    match resp.get_status() {
        StatusCode::OK => Ok(resp),
        StatusCode::NOT_FOUND => Err(BlossomError::NotFound(
            "Video not found for thumbnail generation".into(),
        )),
        status => Err(BlossomError::StorageError(format!(
            "Thumbnail generation failed with status: {}",
            status
        ))),
    }
}

/// Trigger on-demand HLS transcoding via Cloud Run transcoder service
/// This is fire-and-forget - we update metadata to Processing and return immediately
fn trigger_on_demand_transcoding(hash: &str, owner: &str) -> Result<()> {
    if crate::storage::is_local_mode() {
        eprintln!("[HLS][LOCAL] Stubbing transcode for {}", hash);

        // Master playlist — matches production transcoder output (two variants)
        let manifest = format!(
            "#EXTM3U\n\
             #EXT-X-VERSION:3\n\
             #EXT-X-STREAM-INF:BANDWIDTH=2500000,RESOLUTION=1280x720\n\
             /{}/hls/stream_720p.m3u8\n\
             #EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=854x480\n\
             /{}/hls/stream_480p.m3u8\n",
            hash, hash
        );
        let manifest_key = format!("{}/hls/master.m3u8", hash);
        crate::storage::upload_blob(
            &manifest_key,
            fastly::Body::from(manifest.as_bytes()),
            "application/vnd.apple.mpegurl",
            manifest.len() as u64,
            owner,
        )?;

        // Variant playlists — each points to the raw blob as a single segment
        let variant_playlist = format!(
            "#EXTM3U\n\
             #EXT-X-VERSION:3\n\
             #EXT-X-TARGETDURATION:3600\n\
             #EXT-X-MEDIA-SEQUENCE:0\n\
             #EXT-X-PLAYLIST-TYPE:VOD\n\
             #EXTINF:3600.0,\n\
             /{}\n\
             #EXT-X-ENDLIST\n",
            hash
        );
        for variant_name in &["stream_720p", "stream_480p"] {
            let key = format!("{}/hls/{}.m3u8", hash, variant_name);
            crate::storage::upload_blob(
                &key,
                fastly::Body::from(variant_playlist.as_bytes()),
                "application/vnd.apple.mpegurl",
                variant_playlist.len() as u64,
                owner,
            )?;
        }

        // Stub .ts and .mp4 files — write raw blob reference so /{hash}/720p, /{hash}/480p,
        // /{hash}/720p.mp4, and /{hash}/480p.mp4 routes work.
        // Downloads the original blob from storage and writes it as both variant types.
        match crate::storage::download_blob(hash, None) {
            Ok(blob_resp) => {
                let blob_bytes: Vec<u8> = blob_resp.into_body().into_bytes();
                let blob_len = blob_bytes.len() as u64;
                for variant_name in &["stream_720p", "stream_480p"] {
                    let key = format!("{}/hls/{}.ts", hash, variant_name);
                    crate::storage::upload_blob(
                        &key,
                        fastly::Body::from(blob_bytes.as_slice()),
                        "video/mp2t",
                        blob_len,
                        owner,
                    )?;
                    // New .mp4 stub (same bytes, different content-type)
                    let mp4_key = format!("{}/hls/{}.mp4", hash, variant_name);
                    crate::storage::upload_blob(
                        &mp4_key,
                        fastly::Body::from(blob_bytes.as_slice()),
                        "video/mp4",
                        blob_len,
                        owner,
                    )?;
                }
            }
            Err(e) => {
                eprintln!("[HLS][LOCAL] Could not copy blob as .ts/.mp4 stubs: {}", e);
            }
        }

        use crate::metadata::update_transcode_status;
        update_transcode_status(hash, crate::blossom::TranscodeStatus::Complete)?;
        return Ok(());
    }

    let url = format!("https://{}/transcode", CLOUD_RUN_TRANSCODER_HOST);

    let body = format!(r#"{{"hash":"{}","owner":"{}"}}"#, hash, owner);

    let mut proxy_req = Request::new(Method::POST, &url);
    proxy_req.set_header("Host", CLOUD_RUN_TRANSCODER_HOST);
    proxy_req.set_header("Content-Type", "application/json");
    proxy_req.set_body(body);

    // Fire and forget - we don't wait for transcoding to complete
    // The transcoder will callback via webhook when done
    match proxy_req.send_async(TRANSCODER_BACKEND) {
        Ok(_) => {
            eprintln!("[HLS] Triggered on-demand transcoding for {}", hash);
            Ok(())
        }
        Err(e) => {
            eprintln!("[HLS] Failed to trigger transcoding for {}: {}", hash, e);
            Err(BlossomError::Internal(format!(
                "Failed to trigger transcoding: {}",
                e
            )))
        }
    }
}

/// Trigger fMP4 backfill via Cloud Run transcoder — remuxes existing .ts to .mp4
fn trigger_fmp4_backfill(hash: &str) -> Result<()> {
    if crate::storage::is_local_mode() {
        eprintln!("[HLS][LOCAL] Stubbing fMP4 backfill for {}", hash);
        return Ok(());
    }

    let url = format!("https://{}/backfill-fmp4", CLOUD_RUN_TRANSCODER_HOST);
    let body = format!(r#"{{"hash":"{}"}}"#, hash);

    let mut proxy_req = Request::new(Method::POST, &url);
    proxy_req.set_header("Host", CLOUD_RUN_TRANSCODER_HOST);
    proxy_req.set_header("Content-Type", "application/json");
    proxy_req.set_body(body);

    match proxy_req.send_async(TRANSCODER_BACKEND) {
        Ok(_) => {
            eprintln!("[HLS] Triggered fMP4 backfill for {}", hash);
            Ok(())
        }
        Err(e) => {
            eprintln!("[HLS] Failed to trigger fMP4 backfill for {}: {}", hash, e);
            Err(BlossomError::Internal(format!(
                "Failed to trigger fMP4 backfill: {}",
                e
            )))
        }
    }
}

/// Trigger on-demand transcript generation via Cloud Run transcoder service.
fn trigger_on_demand_transcription(
    hash: &str,
    owner: &str,
    job_id: Option<&str>,
    lang: Option<&str>,
) -> Result<()> {
    if crate::storage::is_local_mode() {
        eprintln!("[VTT][LOCAL] Stubbing transcription for {}", hash);
        let vtt = "WEBVTT\n\n00:00:00.000 --> 00:00:01.000\n[local mode stub transcript]\n";
        let vtt_key = format!("{}/vtt/main.vtt", hash);
        crate::storage::upload_blob(
            &vtt_key,
            fastly::Body::from(vtt.as_bytes()),
            "text/vtt",
            vtt.len() as u64,
            owner,
        )?;
        use crate::metadata::{update_transcript_status, TranscriptMetadataUpdate};
        update_transcript_status(
            hash,
            crate::blossom::TranscriptStatus::Complete,
            TranscriptMetadataUpdate::default(),
        )?;
        if let Some(id) = job_id {
            if let Ok(Some(mut job)) = crate::metadata::get_subtitle_job(id) {
                job.status = crate::blossom::SubtitleJobStatus::Ready;
                job.text_track_url = Some(format!("/{}.vtt", hash));
                let _ = crate::metadata::put_subtitle_job(&job);
            }
        }
        return Ok(());
    }

    let url = format!("https://{}/transcribe", CLOUD_RUN_TRANSCODER_HOST);

    let mut payload = serde_json::json!({
        "hash": hash,
        "owner": owner
    });
    if let Some(id) = job_id {
        payload["job_id"] = serde_json::json!(id);
    }
    if let Some(language) = lang {
        payload["lang"] = serde_json::json!(language);
    }
    let body = payload.to_string();

    let mut proxy_req = Request::new(Method::POST, &url);
    proxy_req.set_header("Host", CLOUD_RUN_TRANSCODER_HOST);
    proxy_req.set_header("Content-Type", "application/json");
    proxy_req.set_body(body);

    match proxy_req.send_async(TRANSCODER_BACKEND) {
        Ok(_) => {
            eprintln!("[VTT] Triggered on-demand transcription for {}", hash);
            Ok(())
        }
        Err(e) => {
            eprintln!("[VTT] Failed to trigger transcription for {}: {}", hash, e);
            Err(BlossomError::Internal(format!(
                "Failed to trigger transcription: {}",
                e
            )))
        }
    }
}

fn should_eagerly_trigger_transcription(
    mime_type: &str,
    transcript_status: Option<TranscriptStatus>,
) -> bool {
    is_transcribable_mime_type(mime_type)
        && matches!(transcript_status, None | Some(TranscriptStatus::Pending))
}

fn eagerly_trigger_transcription_if_needed(
    hash: &str,
    owner: &str,
    mime_type: &str,
    transcript_status: Option<TranscriptStatus>,
) {
    if !should_eagerly_trigger_transcription(mime_type, transcript_status) {
        return;
    }

    match trigger_on_demand_transcription(hash, owner, None, None) {
        Ok(()) => {
            if !crate::storage::is_local_mode() {
                let _ = crate::metadata::update_transcript_status(
                    hash,
                    TranscriptStatus::Processing,
                    TranscriptMetadataUpdate {
                        last_attempt_at: Some(current_timestamp()),
                        ..Default::default()
                    },
                );
            }
        }
        Err(error) => {
            eprintln!(
                "[VTT] Failed to eagerly trigger transcription for {}: {}",
                hash, error
            );
        }
    }
}

/// Moderation API backend name (must match fastly.toml)
const MODERATION_API_BACKEND: &str = "moderation_api";

/// Trigger content moderation scan via divine-moderation-api worker.
/// Fire-and-forget — upload should never fail because moderation is down.
fn trigger_moderation_scan(sha256: &str, pubkey: &str) {
    if crate::storage::is_local_mode() {
        eprintln!(
            "[MODERATION][LOCAL] Auto-approving {} for {}",
            sha256, pubkey
        );
        let _ = crate::metadata::update_blob_status(sha256, crate::blossom::BlobStatus::Active);
        return;
    }

    let token = match fastly::secret_store::SecretStore::open("blossom_secrets")
        .ok()
        .and_then(|store| store.get("moderation_api_token"))
        .map(|secret| String::from_utf8(secret.plaintext().to_vec()).unwrap_or_default())
    {
        Some(t) if !t.is_empty() => t,
        _ => {
            eprintln!("[MODERATION] moderation_api_token not configured, skipping scan");
            return;
        }
    };

    let body = format!(
        r#"{{"sha256":"{}","source":"blossom","pubkey":"{}"}}"#,
        sha256, pubkey
    );

    let mut req = Request::new(
        Method::POST,
        "https://moderation-api.divine.video/api/v1/scan",
    );
    req.set_header("Host", "moderation-api.divine.video");
    req.set_header("Content-Type", "application/json");
    req.set_header("Authorization", &format!("Bearer {}", token.trim()));
    req.set_body(body);

    match req.send_async(MODERATION_API_BACKEND) {
        Ok(_) => {
            eprintln!("[MODERATION] Queued scan for {}", sha256);
        }
        Err(e) => {
            eprintln!("[MODERATION] Failed to queue scan for {}: {}", sha256, e);
            // Don't fail the upload — moderation is best-effort
        }
    }
}

/// PUT /upload - Upload blob
fn handle_upload(mut req: Request) -> Result<Response> {
    // Validate auth
    let auth = validate_auth(&req, AuthAction::Upload)?;

    // Serialize auth event for provenance (before consuming request)
    let auth_event_json = serde_json::to_string(&auth).unwrap_or_default();

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
    // In local mode, handle all uploads inline (no Cloud Run available).
    // Viceroy doesn't have WASM heap limits, but very large files (>50MB) may be slow.
    if !crate::storage::is_local_mode()
        && (content_length > UPLOAD_SERVICE_THRESHOLD || is_video_mime_type(&content_type))
    {
        return handle_upload_service_proxy(req, auth, content_type, content_length, base_url);
    }

    // For small files (or all files in local mode), buffer in memory
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

    // Check for tombstone (legally removed content cannot be re-uploaded)
    if let Ok(Some(_tombstone)) = get_tombstone(&hash) {
        return Err(BlossomError::Forbidden(
            "This content has been removed and cannot be re-uploaded".into(),
        ));
    }

    // Check if blob already exists (first-uploader-wins)
    if blob_exists(&hash)? {
        // Return existing blob descriptor but track this re-uploader
        if let Some(mut metadata) = get_blob_metadata(&hash)? {
            // Add re-uploader to their list and refs (best effort)
            let _ = add_to_user_list(&auth.pubkey, &hash);
            let _ = add_to_blob_refs(&hash, &auth.pubkey);

            if is_transcribable_mime_type(&metadata.mime_type)
                && metadata.transcript_status.is_none()
            {
                metadata.transcript_status = Some(TranscriptStatus::Pending);
                let _ = put_blob_metadata(&metadata);
            }
            eagerly_trigger_transcription_if_needed(
                &hash,
                &auth.pubkey,
                &metadata.mime_type,
                metadata.transcript_status,
            );
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
        transcode_error_code: None,
        transcode_error_message: None,
        transcode_last_attempt_at: None,
        transcode_retry_after: None,
        transcode_attempt_count: 0,
        transcode_terminal: false,
        dim: None, // Set by transcoder webhook when transcoding completes
        transcript_status: if is_transcribable_mime_type(&content_type) {
            Some(TranscriptStatus::Pending)
        } else {
            None
        },
        transcript_error_code: None,
        transcript_error_message: None,
        transcript_last_attempt_at: None,
        transcript_retry_after: None,
        transcript_attempt_count: 0,
        transcript_terminal: false,
    };

    put_blob_metadata(&metadata)?;

    // Add to user's list and refs
    add_to_user_list(&auth.pubkey, &hash)?;
    let _ = add_to_blob_refs(&hash, &auth.pubkey);

    // Store provenance: signed auth event as cryptographic proof of upload
    let _ = put_auth_event(&hash, "upload", &auth_event_json);

    // Write audit log to GCS (best effort)
    let meta_json = serde_json::to_string(&metadata).ok();
    write_audit_log(
        &hash,
        "upload",
        &auth.pubkey,
        Some(&auth_event_json),
        meta_json.as_deref(),
        None,
    );

    // Update admin indices (best effort - don't fail upload if these fail)
    let _ = update_stats_on_add(&metadata);
    let _ = add_to_recent_index(&hash);
    // Add user to index if new, increment unique_uploaders count
    if let Ok(is_new) = add_to_user_index(&auth.pubkey) {
        if is_new {
            let _ = crate::metadata::increment_unique_uploaders();
        }
    }

    // Trigger content moderation for video uploads (fire-and-forget)
    if is_video_mime_type(&content_type) {
        trigger_moderation_scan(&hash, &auth.pubkey);
    }
    eagerly_trigger_transcription_if_needed(
        &hash,
        &auth.pubkey,
        &content_type,
        metadata.transcript_status,
    );

    // Return blob descriptor
    let descriptor = metadata.to_descriptor(&base_url);
    let mut resp = json_response(StatusCode::OK, &descriptor);
    add_cors_headers(&mut resp);

    Ok(resp)
}

#[derive(Debug, Clone)]
struct UploadServicePublishedUpload {
    sha256: String,
    size: u64,
    content_type: String,
    thumbnail_url: Option<String>,
    dim: Option<String>,
}

fn extract_authorization_header(req: &Request) -> Result<String> {
    req.get_header(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
        .ok_or_else(|| BlossomError::AuthRequired("Missing authorization header".into()))
}

fn extract_upload_service_error_message(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value["error"].as_str().map(|error| error.to_string()))
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| body.trim().to_string())
}

fn map_upload_service_error(status: StatusCode, body: &str) -> BlossomError {
    let message = extract_upload_service_error_message(body);
    match status {
        StatusCode::BAD_REQUEST => BlossomError::BadRequest(message),
        StatusCode::UNAUTHORIZED => BlossomError::AuthInvalid(message),
        StatusCode::FORBIDDEN => BlossomError::Forbidden(message),
        StatusCode::NOT_FOUND => BlossomError::NotFound(message),
        StatusCode::CONFLICT => BlossomError::Conflict(message),
        StatusCode::GONE => BlossomError::Gone(message),
        s if s == StatusCode::from_u16(416).unwrap() => BlossomError::RangeNotSatisfiable(message),
        s if s == StatusCode::from_u16(422).unwrap() => BlossomError::UnprocessableEntity(message),
        StatusCode::INTERNAL_SERVER_ERROR | StatusCode::BAD_GATEWAY => {
            BlossomError::Internal(message)
        }
        _ => BlossomError::StorageError(format!(
            "Cloud Run request failed ({}): {}",
            status, message
        )),
    }
}

fn publish_upload_service_upload(
    auth: crate::blossom::BlossomAuthEvent,
    base_url: String,
    upload: UploadServicePublishedUpload,
) -> Result<Response> {
    let hash = upload.sha256;
    let size = upload.size;
    let content_type = upload.content_type;
    let thumbnail_url = upload.thumbnail_url;
    let dim = upload.dim;

    if let Ok(Some(_tombstone)) = get_tombstone(&hash) {
        return Err(BlossomError::Forbidden(
            "This content has been removed and cannot be re-uploaded".into(),
        ));
    }

    let auth_event_json = serde_json::to_string(&auth).unwrap_or_default();

    // Derivative failure fields — populated when the upload service detects
    // invalid media (corrupt container, missing moov atom, etc.) during
    // sanitization/probing. Currently defaults to None/false since the typed
    // upload response struct doesn't carry these yet; once the upload service
    // is updated to return them, wire them through here.
    let transcode_error_code: Option<String> = None;
    let transcode_error_message: Option<String> = None;
    let transcode_terminal = false;
    let transcript_error_code: Option<String> = None;
    let transcript_error_message: Option<String> = None;
    let transcript_terminal = false;
    let has_transcode_error = transcode_error_code.is_some();
    let has_transcript_error = transcript_error_code.is_some();
    let derivative_failure_recorded_at: Option<String> = None;

    // Check if metadata already exists (dedupe/re-upload case)
    if let Some(mut metadata) = get_blob_metadata(&hash)? {
        let _ = add_to_user_list(&auth.pubkey, &hash);
        let _ = add_to_blob_refs(&hash, &auth.pubkey);

        if thumbnail_url.is_some() && metadata.thumbnail.is_none() {
            metadata.thumbnail = thumbnail_url.clone();
        }
        // Even for dedupe, update dim if we got it and it wasn't set before
        if dim.is_some() && metadata.dim.is_none() {
            metadata.dim = dim.clone();
        }
        if let Some(ref error_code) = transcode_error_code {
            metadata.transcode_status = Some(TranscodeStatus::Failed);
            metadata.transcode_error_code = Some(error_code.clone());
            metadata.transcode_error_message = transcode_error_message.clone();
            metadata.transcode_last_attempt_at = derivative_failure_recorded_at.clone();
            metadata.transcode_retry_after = None;
            metadata.transcode_attempt_count = metadata.transcode_attempt_count.max(1);
            metadata.transcode_terminal = transcode_terminal;
        } else if is_video_mime_type(&metadata.mime_type) && metadata.transcode_status.is_none() {
            metadata.transcode_status = Some(TranscodeStatus::Pending);
        }
        if let Some(ref error_code) = transcript_error_code {
            metadata.transcript_status = Some(TranscriptStatus::Failed);
            metadata.transcript_error_code = Some(error_code.clone());
            metadata.transcript_error_message = transcript_error_message.clone();
            metadata.transcript_last_attempt_at = derivative_failure_recorded_at.clone();
            metadata.transcript_retry_after = None;
            metadata.transcript_attempt_count = metadata.transcript_attempt_count.max(1);
            metadata.transcript_terminal = transcript_terminal;
        } else if is_transcribable_mime_type(&metadata.mime_type)
            && metadata.transcript_status.is_none()
        {
            metadata.transcript_status = Some(TranscriptStatus::Pending);
        }
        let _ = put_blob_metadata(&metadata);
        eagerly_trigger_transcription_if_needed(
            &hash,
            &auth.pubkey,
            &metadata.mime_type,
            metadata.transcript_status,
        );
        let descriptor = metadata.to_descriptor(&base_url);
        let mut resp = json_response(StatusCode::OK, &descriptor);
        add_cors_headers(&mut resp);
        return Ok(resp);
    }

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
            if transcode_error_code.is_some() {
                Some(TranscodeStatus::Failed)
            } else {
                Some(TranscodeStatus::Pending)
            }
        } else {
            None
        },
        transcode_error_code,
        transcode_error_message,
        transcode_last_attempt_at: derivative_failure_recorded_at.clone(),
        transcode_retry_after: None,
        transcode_attempt_count: if is_video_mime_type(&content_type) && has_transcode_error {
            1
        } else {
            0
        },
        transcode_terminal,
        dim: dim.clone(),
        transcript_status: if is_transcribable_mime_type(&content_type) {
            if transcript_error_code.is_some() {
                Some(TranscriptStatus::Failed)
            } else {
                Some(TranscriptStatus::Pending)
            }
        } else {
            None
        },
        transcript_error_code,
        transcript_error_message,
        transcript_last_attempt_at: derivative_failure_recorded_at,
        transcript_retry_after: None,
        transcript_attempt_count: if is_transcribable_mime_type(&content_type)
            && has_transcript_error
        {
            1
        } else {
            0
        },
        transcript_terminal,
    };

    put_blob_metadata(&metadata)?;
    add_to_user_list(&auth.pubkey, &hash)?;
    let _ = add_to_blob_refs(&hash, &auth.pubkey);
    let _ = put_auth_event(&hash, "upload", &auth_event_json);

    let meta_json = serde_json::to_string(&metadata).ok();
    write_audit_log(
        &hash,
        "upload",
        &auth.pubkey,
        Some(&auth_event_json),
        meta_json.as_deref(),
        None,
    );

    let _ = update_stats_on_add(&metadata);
    let _ = add_to_recent_index(&hash);
    if let Ok(is_new) = add_to_user_index(&auth.pubkey) {
        if is_new {
            let _ = crate::metadata::increment_unique_uploaders();
        }
    }

    if is_video_mime_type(&content_type) {
        trigger_moderation_scan(&hash, &auth.pubkey);
    }
    eagerly_trigger_transcription_if_needed(
        &hash,
        &auth.pubkey,
        &content_type,
        metadata.transcript_status,
    );

    let descriptor = metadata.to_descriptor(&base_url);
    let mut resp = json_response(StatusCode::OK, &descriptor);
    add_cors_headers(&mut resp);

    Ok(resp)
}

fn handle_upload_init(mut req: Request) -> Result<Response> {
    let auth = validate_auth(&req, AuthAction::Upload)?;
    let auth_header = extract_authorization_header(&req)?;
    let base_url = get_base_url(&req);
    let control_host = get_public_host(&req).unwrap_or_else(|| "media.divine.video".into());
    let body = req.take_body().into_string();
    if body.is_empty() {
        return Err(BlossomError::BadRequest("Request body required".into()));
    }

    let init_request: ResumableUploadInitRequest = serde_json::from_str(&body)
        .map_err(|e| BlossomError::BadRequest(format!("Invalid JSON: {}", e)))?;

    if init_request.size == 0 {
        return Err(BlossomError::BadRequest(
            "Upload size must be greater than zero".into(),
        ));
    }
    if init_request.size > MAX_UPLOAD_SIZE {
        return Err(BlossomError::BadRequest(format!(
            "File too large. Maximum size is {} bytes",
            MAX_UPLOAD_SIZE
        )));
    }
    if init_request.sha256.len() != 64
        || !init_request
            .sha256
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(BlossomError::BadRequest(
            "sha256 must be a 64-character hexadecimal string".into(),
        ));
    }
    if init_request.content_type.trim().is_empty() {
        return Err(BlossomError::BadRequest("Content type is required".into()));
    }

    if let Some(expected_hash) = auth.get_hash() {
        if expected_hash.to_lowercase() != init_request.sha256.to_lowercase() {
            return Err(BlossomError::AuthInvalid(
                "Hash in auth event doesn't match init request".into(),
            ));
        }
    }

    if let Ok(Some(_tombstone)) = get_tombstone(&init_request.sha256) {
        return Err(BlossomError::Forbidden(
            "This content has been removed and cannot be re-uploaded".into(),
        ));
    }

    if blob_exists(&init_request.sha256)? {
        let payload = if let Some(metadata) = get_blob_metadata(&init_request.sha256)? {
            serde_json::json!({
                "error": "Blob already exists",
                "descriptor": metadata.to_descriptor(&base_url),
            })
        } else {
            serde_json::json!({
                "error": "Blob already exists",
                "sha256": init_request.sha256,
            })
        };
        let mut resp = json_response(StatusCode::CONFLICT, &payload);
        add_upload_capability_headers(&mut resp, &control_host);
        add_cors_headers(&mut resp);
        return Ok(resp);
    }

    let mut proxy_req = Request::new(
        fastly::http::Method::POST,
        format!("https://{}/upload/init", UPLOAD_SERVICE_HOST),
    );
    proxy_req.set_header("Host", UPLOAD_SERVICE_HOST);
    proxy_req.set_header(header::AUTHORIZATION, &auth_header);
    proxy_req.set_header(header::CONTENT_TYPE, "application/json");
    proxy_req.set_header(header::CONTENT_LENGTH, body.len().to_string());
    proxy_req.set_body(body);

    let mut proxy_resp = proxy_req
        .send(UPLOAD_SERVICE_BACKEND)
        .map_err(|e| BlossomError::Internal(format!("Failed to proxy to Cloud Run: {}", e)))?;
    if !proxy_resp.get_status().is_success() {
        let status = proxy_resp.get_status();
        let body = proxy_resp.take_body().into_string();
        return Err(map_upload_service_error(status, &body));
    }

    let response_body = proxy_resp.take_body().into_string();
    let init_response: ResumableUploadInitResponse = serde_json::from_str(&response_body)
        .map_err(|e| BlossomError::Internal(format!("Invalid Cloud Run init response: {}", e)))?;

    let mut resp = json_response(StatusCode::OK, &init_response);
    add_upload_capability_headers(&mut resp, &control_host);
    add_cors_headers(&mut resp);
    Ok(resp)
}

fn handle_upload_complete(mut req: Request, path: &str) -> Result<Response> {
    let auth = validate_auth(&req, AuthAction::Upload)?;
    let auth_header = extract_authorization_header(&req)?;
    let base_url = get_base_url(&req);
    let upload_id = path
        .strip_prefix("/upload/")
        .and_then(|suffix| suffix.strip_suffix("/complete"))
        .ok_or_else(|| BlossomError::BadRequest("Invalid upload complete path".into()))?;
    let request_body = req.take_body().into_string();
    let expected_request_hash =
        parse_resumable_complete_request_body(&request_body).map_err(BlossomError::BadRequest)?;

    if let Some(expected_hash) = auth.get_hash() {
        if let Some(ref request_hash) = expected_request_hash {
            if expected_hash.to_lowercase() != request_hash.to_lowercase() {
                return Err(BlossomError::AuthInvalid(
                    "Hash in auth event doesn't match completion request".into(),
                ));
            }
        }
    }

    let mut proxy_req = Request::new(
        fastly::http::Method::POST,
        format!(
            "https://{}/upload/{}/complete",
            UPLOAD_SERVICE_HOST, upload_id
        ),
    );
    proxy_req.set_header("Host", UPLOAD_SERVICE_HOST);
    proxy_req.set_header(header::AUTHORIZATION, &auth_header);
    if expected_request_hash.is_some() {
        proxy_req.set_header(header::CONTENT_TYPE, "application/json");
        proxy_req.set_header(header::CONTENT_LENGTH, request_body.len().to_string());
        proxy_req.set_body(request_body);
    }

    let mut proxy_resp = proxy_req
        .send(UPLOAD_SERVICE_BACKEND)
        .map_err(|e| BlossomError::Internal(format!("Failed to proxy to Cloud Run: {}", e)))?;
    if !proxy_resp.get_status().is_success() {
        let status = proxy_resp.get_status();
        let body = proxy_resp.take_body().into_string();
        return Err(map_upload_service_error(status, &body));
    }

    let response_body = proxy_resp.take_body().into_string();
    let complete_response: ResumableUploadCompleteResponse = serde_json::from_str(&response_body)
        .map_err(|e| {
        BlossomError::Internal(format!("Invalid Cloud Run completion response: {}", e))
    })?;

    if let Some(ref request_hash) = expected_request_hash {
        if request_hash.to_lowercase() != complete_response.sha256.to_lowercase() {
            return Err(BlossomError::Conflict(
                "Completion response hash did not match requested hash".into(),
            ));
        }
    }

    publish_upload_service_upload(
        auth,
        base_url,
        UploadServicePublishedUpload {
            sha256: complete_response.sha256,
            size: complete_response.size,
            content_type: complete_response.content_type,
            thumbnail_url: complete_response.thumbnail_url,
            dim: complete_response.dim,
        },
    )
}

/// Handle large uploads by proxying to the upload service
/// Fastly Compute has WASM memory limits (~5MB), so large files must be proxied
fn handle_upload_service_proxy(
    mut req: Request,
    auth: crate::blossom::BlossomAuthEvent,
    content_type: String,
    content_length: u64,
    base_url: String,
) -> Result<Response> {
    let auth_header = extract_authorization_header(&req)?;

    // Get the body to forward
    let body = req.take_body();

    // Build request to the upload service.
    let mut proxy_req = Request::new(
        fastly::http::Method::PUT,
        format!("https://{}/upload", UPLOAD_SERVICE_HOST),
    );
    proxy_req.set_header("Host", UPLOAD_SERVICE_HOST);
    proxy_req.set_header(header::AUTHORIZATION, &auth_header);
    proxy_req.set_header(header::CONTENT_TYPE, &content_type);
    proxy_req.set_header(header::CONTENT_LENGTH, content_length.to_string());
    proxy_req.set_body(body);

    // Send to Cloud Run
    let mut proxy_resp = proxy_req
        .send(UPLOAD_SERVICE_BACKEND)
        .map_err(|e| BlossomError::Internal(format!("Failed to proxy to Cloud Run: {}", e)))?;

    // Check for errors from Cloud Run
    if !proxy_resp.get_status().is_success() {
        let status = proxy_resp.get_status();
        let body = proxy_resp.take_body().into_string();
        return Err(map_upload_service_error(status, &body));
    }

    // Parse Cloud Run response to get the hash
    let resp_body = proxy_resp.take_body().into_string();
    let cloud_run_resp: serde_json::Value = serde_json::from_str(&resp_body)
        .map_err(|e| BlossomError::Internal(format!("Invalid Cloud Run response: {}", e)))?;
    let upload = UploadServicePublishedUpload {
        sha256: cloud_run_resp["sha256"]
            .as_str()
            .ok_or_else(|| BlossomError::Internal("Missing sha256 in Cloud Run response".into()))?
            .to_string(),
        size: cloud_run_resp["size"].as_u64().unwrap_or(content_length),
        content_type: content_type.clone(),
        thumbnail_url: cloud_run_resp["thumbnail_url"]
            .as_str()
            .map(|value| value.to_string()),
        dim: cloud_run_resp["dim"]
            .as_str()
            .map(|value| value.to_string()),
    };

    publish_upload_service_upload(auth, base_url, upload)
}

/// HEAD /upload - BUD-06 upload pre-validation
/// Clients can send X-SHA-256, X-Content-Length, X-Content-Type headers
/// to check if an upload would be accepted before sending the full file
fn handle_upload_requirements(req: Request) -> Result<Response> {
    let control_host = upload_control_host(get_public_host(&req).as_deref());
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
                resp.set_header(
                    "X-Reason",
                    "Invalid X-SHA-256 format (must be 64 hex characters)",
                );
                add_upload_capability_headers(&mut resp, &control_host);
                add_cors_headers(&mut resp);
                return Ok(resp);
            }

            // Check if blob already exists (optimization - client can skip upload)
            if blob_exists(hash)? {
                let mut resp = Response::from_status(StatusCode::OK);
                resp.set_header("X-Reason", "Blob already exists");
                resp.set_header("X-Exists", "true");
                add_upload_capability_headers(&mut resp, &control_host);
                add_cors_headers(&mut resp);
                return Ok(resp);
            }
        }

        // Validate content length
        if let Some(size) = content_length {
            if size > MAX_UPLOAD_SIZE {
                let mut resp = Response::from_status(StatusCode::from_u16(413).unwrap());
                resp.set_header(
                    "X-Reason",
                    &format!("File too large. Maximum size is {} bytes", MAX_UPLOAD_SIZE),
                );
                add_upload_capability_headers(&mut resp, &control_host);
                add_cors_headers(&mut resp);
                return Ok(resp);
            }
            if size == 0 {
                let mut resp = Response::from_status(StatusCode::BAD_REQUEST);
                resp.set_header("X-Reason", "File cannot be empty");
                add_upload_capability_headers(&mut resp, &control_host);
                add_cors_headers(&mut resp);
                return Ok(resp);
            }
        }

        // Content type validation - we accept all types, so this always passes
        // If we wanted to restrict, we'd check content_type here

        // All validations passed
        let mut resp = Response::from_status(StatusCode::OK);
        resp.set_header("X-Reason", "Upload would be accepted");
        add_upload_capability_headers(&mut resp, &control_host);
        add_cors_headers(&mut resp);
        return Ok(resp);
    }

    // No pre-validation headers - return general requirements
    let requirements = UploadRequirements {
        max_size: Some(MAX_UPLOAD_SIZE),
        allowed_types: None, // Accept all types
        extensions: Some(vec![DIVINE_UPLOAD_EXTENSION_RESUMABLE.to_string()]),
    };

    let mut resp = json_response(StatusCode::OK, &requirements);
    add_upload_capability_headers(&mut resp, &control_host);
    add_cors_headers(&mut resp);

    Ok(resp)
}

/// Delete all GCS artifacts for a blob (thumbnail, HLS, VTT).
/// The main blob itself is NOT deleted here (caller handles that).
/// Best-effort: logs errors but never fails.
fn delete_blob_gcs_artifacts(hash: &str) {
    // Thumbnail
    let _ = storage_delete(&format!("{}.jpg", hash));

    // HLS files (deterministic paths from transcoder using -hls_flags single_file)
    let hls_paths = [
        format!("{}/hls/master.m3u8", hash),
        format!("{}/hls/stream_720p.m3u8", hash),
        format!("{}/hls/stream_720p.ts", hash),
        format!("{}/hls/stream_480p.m3u8", hash),
        format!("{}/hls/stream_480p.ts", hash),
        format!("{}/hls/stream_720p.mp4", hash),
        format!("{}/hls/stream_480p.mp4", hash),
    ];
    for path in &hls_paths {
        let _ = storage_delete(path);
    }

    // VTT transcript
    let _ = storage_delete(&format!("{}/vtt/main.vtt", hash));

    // Fire-and-forget Cloud Run request for thorough prefix-based cleanup
    // (catches any files we missed with deterministic paths)
    trigger_cloud_run_delete_blob(hash);
}

/// Delete all KV artifacts for a blob (refs, auth events, subtitle data).
/// Best-effort: logs errors but never fails.
fn delete_blob_kv_artifacts(hash: &str) {
    let _ = delete_blob_refs(hash);
    let _ = delete_auth_events(hash);
    let _ = delete_subtitle_data(hash);
}

/// DELETE /<sha256> - Preserve-first delete with ref unlinking for non-owners
fn handle_delete(req: Request, path: &str) -> Result<Response> {
    let hash = parse_hash_from_path(path)
        .ok_or_else(|| BlossomError::BadRequest("Invalid hash in path".into()))?;

    // Validate auth with hash check
    let auth = validate_auth(&req, AuthAction::Delete)?;
    validate_hash_match(&auth, &hash)?;

    // Serialize auth event for provenance
    let auth_event_json = serde_json::to_string(&auth).unwrap_or_default();

    // Get metadata and refs
    let metadata =
        get_blob_metadata(&hash)?.ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;
    let meta_json = serde_json::to_string(&metadata).ok();
    let refs = get_blob_refs(&hash).unwrap_or_default();

    let is_owner = metadata.owner.to_lowercase() == auth.pubkey.to_lowercase();
    let is_ref = refs
        .iter()
        .any(|r| r.to_lowercase() == auth.pubkey.to_lowercase());

    if !is_owner && !is_ref {
        return Err(BlossomError::Forbidden("You don't own this blob".into()));
    }

    // Store provenance: signed delete auth event
    let _ = put_auth_event(&hash, "delete", &auth_event_json);

    // Write audit log before deletion
    write_audit_log(
        &hash,
        "delete",
        &auth.pubkey,
        Some(&auth_event_json),
        meta_json.as_deref(),
        None,
    );

    match plan_user_delete(is_owner) {
        DeletePlan::SoftDelete => {
            soft_delete_blob(&hash, &metadata, "Owner delete", false)?;
            eprintln!("[DELETE] Soft-deleted {} by owner {}", hash, auth.pubkey);
        }
        DeletePlan::UnlinkOnly => {
            let _ = remove_from_user_list(&auth.pubkey, &hash);
            let _ = remove_from_blob_refs(&hash, &auth.pubkey);
            eprintln!("[DELETE] Unlinked ref {} from blob {}", auth.pubkey, hash);
        }
    }

    let mut resp = Response::from_status(StatusCode::OK);
    add_cors_headers(&mut resp);

    Ok(resp)
}

/// GET /{sha256}/provenance - Get cryptographic proof of upload authorization
fn handle_get_provenance(path: &str) -> Result<Response> {
    let hash = path
        .trim_start_matches('/')
        .strip_suffix("/provenance")
        .and_then(|h| {
            if h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) {
                Some(h.to_lowercase())
            } else {
                None
            }
        })
        .ok_or_else(|| BlossomError::BadRequest("Invalid hash in provenance path".into()))?;

    let upload_auth = get_auth_event(&hash, "upload")?;
    let delete_auth = get_auth_event(&hash, "delete")?;

    // Get blob refs (all uploaders)
    let refs = get_blob_refs(&hash).unwrap_or_default();

    // Get current metadata if it exists
    let metadata = get_blob_metadata(&hash)?;
    let owner = metadata.as_ref().map(|m| m.owner.as_str());

    let mut provenance = serde_json::json!({
        "sha256": hash,
        "owner": owner,
        "uploaders": refs,
    });

    if let Some(auth) = upload_auth {
        if let Ok(event) = serde_json::from_str::<serde_json::Value>(&auth) {
            provenance["upload_auth_event"] = event;
        }
    }
    if let Some(auth) = delete_auth {
        if let Ok(event) = serde_json::from_str::<serde_json::Value>(&auth) {
            provenance["delete_auth_event"] = event;
        }
    }

    // Check tombstone
    if let Ok(Some(tombstone)) = get_tombstone(&hash) {
        if let Ok(t) = serde_json::from_str::<serde_json::Value>(&tombstone) {
            provenance["tombstone"] = t;
        }
    }

    let mut resp = json_response(StatusCode::OK, &provenance);
    add_cors_headers(&mut resp);
    Ok(resp)
}

/// POST /admin/api/delete - Admin soft-delete with optional legal hold
fn handle_admin_force_delete(req: Request) -> Result<Response> {
    // Validate admin auth
    admin::validate_admin_auth(&req)?;

    // Parse request body
    let body = req.into_body_str();
    let request: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| BlossomError::BadRequest(format!("Invalid JSON: {}", e)))?;

    let hash = request["sha256"]
        .as_str()
        .ok_or_else(|| BlossomError::BadRequest("Missing 'sha256' field".into()))?
        .to_lowercase();

    let reason = request["reason"].as_str().unwrap_or("Admin force-delete");

    let legal_hold = request["legal_hold"].as_bool().unwrap_or(false);

    // Validate hash format
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BlossomError::BadRequest("Invalid SHA-256 hash".into()));
    }

    // Get metadata before deletion for audit
    let metadata =
        get_blob_metadata(&hash)?.ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;
    let meta_json = serde_json::to_string(&metadata).ok();

    // Write audit log BEFORE deletion
    write_audit_log(
        &hash,
        "admin_delete",
        "admin",
        None,
        meta_json.as_deref(),
        Some(reason),
    );

    soft_delete_blob(&hash, &metadata, reason, legal_hold)?;

    eprintln!(
        "[ADMIN DELETE] hash={} reason={} legal_hold={}",
        hash, reason, legal_hold
    );

    let result = serde_json::json!({
        "deleted": true,
        "preserved": true,
        "sha256": hash,
        "legal_hold": legal_hold,
    });

    let mut resp = json_response(StatusCode::OK, &result);
    add_cors_headers(&mut resp);
    Ok(resp)
}

/// Execute vanish (GDPR right to erasure) for a given pubkey.
/// For each blob the user owns or references:
/// - Sole owner: full delete (GCS + KV + VCL cache purge)
/// - Shared content: unlink (remove from refs, transfer ownership if needed)
/// Returns (fully_deleted, unlinked, errors) counts.
fn execute_vanish(pubkey: &str) -> (u32, u32, u32) {
    let mut fully_deleted: u32 = 0;
    let mut unlinked: u32 = 0;
    let mut errors: u32 = 0;

    // Get all hashes from user's list
    let hashes = match get_user_blobs(pubkey) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[VANISH] Failed to get user blobs for {}: {}", pubkey, e);
            return (0, 0, 1);
        }
    };

    let hashes_for_cloud_run = hashes.clone();

    for hash in &hashes {
        // Get metadata for this blob
        let metadata = match get_blob_metadata(hash) {
            Ok(Some(m)) => m,
            Ok(None) => {
                // Metadata missing - clean up refs and move on
                let _ = remove_from_blob_refs(hash, pubkey);
                continue;
            }
            Err(e) => {
                eprintln!("[VANISH] Failed to get metadata for {}: {}", hash, e);
                errors += 1;
                continue;
            }
        };

        let is_owner = metadata.owner.to_lowercase() == pubkey.to_lowercase();

        // Remove self from refs
        let remaining_refs = remove_from_blob_refs(hash, pubkey).unwrap_or_default();
        let other_refs: Vec<String> = remaining_refs
            .iter()
            .filter(|r| r.to_lowercase() != pubkey.to_lowercase())
            .cloned()
            .collect();

        if is_owner && other_refs.is_empty() {
            // Sole owner: full delete
            cleanup_derived_audio_for_source(hash);
            let _ = storage_delete(hash);
            delete_blob_gcs_artifacts(hash);
            let _ = delete_blob_metadata(hash);
            delete_blob_kv_artifacts(hash);
            let _ = update_stats_on_remove(&metadata);
            let _ = remove_from_recent_index(hash);
            purge_vcl_cache(hash);
            fully_deleted += 1;
        } else if is_owner {
            // Transfer ownership to next ref
            let new_owner = other_refs[0].clone();
            let mut updated_meta = metadata;
            updated_meta.owner = new_owner;
            let _ = put_blob_metadata(&updated_meta);
            unlinked += 1;
        } else {
            // Non-owner ref: already unlinked from refs above
            unlinked += 1;
        }
    }

    // Delete user's KV list and remove from user index
    let _ = delete_user_list(pubkey);
    let _ = remove_from_user_index(pubkey);

    // Fire-and-forget Cloud Run bulk delete for thorough GCS cleanup
    trigger_cloud_run_bulk_delete(pubkey, &hashes_for_cloud_run);

    // Trigger audit anonymization
    trigger_audit_anonymize(pubkey);

    eprintln!(
        "[VANISH] pubkey={} fully_deleted={} unlinked={} errors={}",
        pubkey, fully_deleted, unlinked, errors
    );

    (fully_deleted, unlinked, errors)
}

/// DELETE /vanish - User-initiated GDPR right to erasure
fn handle_vanish(req: Request) -> Result<Response> {
    // Validate Blossom delete auth.
    let auth = validate_auth(&req, AuthAction::Delete)?;
    let auth_event_json = serde_json::to_string(&auth).unwrap_or_default();

    // Write audit log before erasure
    write_audit_log(
        "all",
        "vanish",
        &auth.pubkey,
        Some(&auth_event_json),
        None,
        Some("User-initiated GDPR right to erasure"),
    );

    let (fully_deleted, unlinked, errors) = execute_vanish(&auth.pubkey);

    let result = serde_json::json!({
        "vanished": true,
        "pubkey": auth.pubkey,
        "fully_deleted": fully_deleted,
        "unlinked": unlinked,
        "errors": errors,
    });

    let mut resp = json_response(StatusCode::OK, &result);
    add_cors_headers(&mut resp);
    Ok(resp)
}

/// POST /admin/api/vanish - Admin-initiated vanish (for funnelcake janitor NIP-62 integration)
fn handle_admin_vanish(req: Request) -> Result<Response> {
    // Validate admin auth
    admin::validate_admin_auth(&req)?;

    // Parse request body
    let body = req.into_body_str();
    let request: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| BlossomError::BadRequest(format!("Invalid JSON: {}", e)))?;

    let pubkey = request["pubkey"]
        .as_str()
        .ok_or_else(|| BlossomError::BadRequest("Missing 'pubkey' field".into()))?
        .to_lowercase();

    let reason = request["reason"]
        .as_str()
        .unwrap_or("Admin-initiated vanish");

    // Validate pubkey format (64 hex chars)
    if pubkey.len() != 64 || !pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BlossomError::BadRequest("Invalid pubkey format".into()));
    }

    // Write audit log before erasure
    write_audit_log("all", "admin_vanish", &pubkey, None, None, Some(reason));

    let (fully_deleted, unlinked, errors) = execute_vanish(&pubkey);

    let result = serde_json::json!({
        "vanished": true,
        "pubkey": pubkey,
        "reason": reason,
        "fully_deleted": fully_deleted,
        "unlinked": unlinked,
        "errors": errors,
    });

    let mut resp = json_response(StatusCode::OK, &result);
    add_cors_headers(&mut resp);
    Ok(resp)
}

/// GET /list/<pubkey> - List user's blobs
fn handle_list(req: Request, path: &str) -> Result<Response> {
    let pubkey = path
        .strip_prefix("/list/")
        .ok_or_else(|| BlossomError::BadRequest("Invalid list path".into()))?;

    // Check if authenticated as the owner (to include restricted blobs)
    let is_owner = viewer_pubkey(&req)?
        .map(|viewer| viewer.eq_ignore_ascii_case(pubkey))
        .unwrap_or(false);

    // Get blobs with metadata
    let blobs = list_blobs_with_metadata(pubkey, is_owner)?;

    // Convert to descriptors
    let base_url = get_base_url(&req);
    let descriptors: Vec<BlobDescriptor> =
        blobs.iter().map(|m| m.to_descriptor(&base_url)).collect();

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
    let kind = report_event["kind"]
        .as_u64()
        .ok_or_else(|| BlossomError::BadRequest("Missing 'kind' field".into()))?;

    if kind != 1984 {
        return Err(BlossomError::BadRequest(format!(
            "Invalid event kind: expected 1984 (NIP-56 report), got {}",
            kind
        )));
    }

    // Extract x tags (blob sha256 hashes being reported)
    let tags = report_event["tags"]
        .as_array()
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
            "No valid 'x' tags found with blob hashes".into(),
        ));
    }

    // Get report content (description)
    let content = report_event["content"].as_str().unwrap_or("");

    // Get reporter pubkey
    let reporter = report_event["pubkey"]
        .as_str()
        .ok_or_else(|| BlossomError::BadRequest("Missing 'pubkey' field".into()))?;

    // Log the report for operator review
    // In production, this would be stored in a database or sent to a moderation queue
    eprintln!(
        "BUD-09 REPORT: reporter={}, hashes={:?}, type={:?}, content={}",
        reporter, reported_hashes, report_type, content
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
        return Err(BlossomError::BadRequest(
            "Invalid URL: must start with http:// or https://".into(),
        ));
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

    let mut proxy_req = Request::new(
        fastly::http::Method::POST,
        format!("https://{}/migrate", UPLOAD_SERVICE_HOST),
    );
    proxy_req.set_header("Host", UPLOAD_SERVICE_HOST);
    proxy_req.set_header("Content-Type", "application/json");
    proxy_req.set_header("Content-Length", migrate_json.len().to_string());
    proxy_req.set_body(migrate_json);

    let mut proxy_resp = proxy_req
        .send(UPLOAD_SERVICE_BACKEND)
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
    if let Some(mut metadata) = get_blob_metadata(&hash)? {
        if is_transcribable_mime_type(&metadata.mime_type) && metadata.transcript_status.is_none() {
            metadata.transcript_status = Some(TranscriptStatus::Pending);
            let _ = put_blob_metadata(&metadata);
        }
        eagerly_trigger_transcription_if_needed(
            &hash,
            &auth.pubkey,
            &metadata.mime_type,
            metadata.transcript_status,
        );
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
        transcode_error_code: None,
        transcode_error_message: None,
        transcode_last_attempt_at: None,
        transcode_retry_after: None,
        transcode_attempt_count: 0,
        transcode_terminal: false,
        dim: None, // Set by transcoder webhook when transcoding completes
        transcript_status: if is_transcribable_mime_type(&content_type) {
            Some(TranscriptStatus::Pending)
        } else {
            None
        },
        transcript_error_code: None,
        transcript_error_message: None,
        transcript_last_attempt_at: None,
        transcript_retry_after: None,
        transcript_attempt_count: 0,
        transcript_terminal: false,
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
    eagerly_trigger_transcription_if_needed(
        &hash,
        &auth.pubkey,
        &content_type,
        metadata.transcript_status,
    );

    // Return blob descriptor per BUD-04
    let descriptor = metadata.to_descriptor(&base_url);
    let mut resp = json_response(StatusCode::OK, &descriptor);
    add_cors_headers(&mut resp);

    Ok(resp)
}

/// POST /admin/api/backfill-vtt - Trigger VTT transcription for all video/audio blobs missing transcripts
/// Iterates through user index, finds transcribable blobs without VTT, and triggers transcription.
/// Query params: ?offset=N&limit=M (paginate through users, default limit=50)
#[derive(Debug, Clone, serde::Serialize)]
struct TranscriptBackfillCandidate {
    sha256: String,
    owner: String,
    uploaded: String,
    transcript_status: Option<String>,
    retry_after_epoch_secs: Option<u64>,
    cooldown_remaining_secs: Option<u64>,
}

fn backfill_batch_cursor(
    offset: usize,
    end: usize,
    total: usize,
    hit_trigger_limit: bool,
) -> (bool, Option<usize>) {
    if hit_trigger_limit && offset < total {
        return (true, Some(offset));
    }

    if end < total {
        return (true, Some(end));
    }

    (false, None)
}

fn handle_admin_backfill_vtt(req: Request) -> Result<Response> {
    // Accept webhook secret (same as transcoder uses) OR admin session
    let webhook_ok = fastly::secret_store::SecretStore::open("blossom_secrets")
        .ok()
        .and_then(|store| store.get("webhook_secret"))
        .and_then(|secret| {
            let expected = String::from_utf8(secret.plaintext().to_vec()).unwrap_or_default();
            let provided = req
                .get_header(header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))?;
            if provided.trim() == expected.trim() {
                Some(())
            } else {
                None
            }
        })
        .is_some();

    if !webhook_ok {
        admin::validate_admin_auth(&req)?;
    }

    let url = req.get_url();
    let query_pairs: std::collections::HashMap<_, _> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let offset: usize = query_pairs
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let limit: usize = query_pairs
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    let scope = query_pairs
        .get("scope")
        .map(|value| value.as_str())
        .unwrap_or("users");
    let dry_run = query_pairs
        .get("dry_run")
        .map(|value| value == "true")
        .unwrap_or(false);

    // Max triggers per request to avoid Fastly Compute timeout (~30s wall time)
    let max_triggers: u32 = query_pairs
        .get("max_triggers")
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);

    // Reset stale "processing" items back to pending so they get re-triggered
    let reset_processing: bool = query_pairs
        .get("reset_processing")
        .map(|v| v == "true")
        .unwrap_or(false);

    // Force re-transcription of "complete" items (to re-run with updated phantom detection)
    let force_retranscribe: bool = query_pairs
        .get("force_retranscribe")
        .map(|v| v == "true")
        .unwrap_or(false);

    let now_epoch_secs = unix_timestamp_secs();
    let mut triggered = 0u32;
    let mut already_complete = 0u32;
    let mut already_processing = 0u32;
    let mut cooling_down = 0u32;
    let mut reset_count = 0u32;
    let mut not_transcribable = 0u32;
    let mut errors = 0u32;
    let mut hit_limit = false;
    let mut candidates = Vec::new();
    let mut processed_hashes = 0usize;

    let mut process_hash = |hash: &str| -> bool {
        let Ok(Some(mut metadata)) = crate::metadata::get_blob_metadata_uncached(hash) else {
            return false;
        };

        processed_hashes += 1;

        if !is_transcribable_mime_type(&metadata.mime_type) {
            not_transcribable += 1;
            return false;
        }

        match metadata.transcript_status {
            Some(TranscriptStatus::Complete) if !force_retranscribe => {
                already_complete += 1;
                return false;
            }
            Some(TranscriptStatus::Complete) => {
                reset_count += 1;
            }
            Some(TranscriptStatus::Processing) if !reset_processing => {
                already_processing += 1;
                return false;
            }
            Some(TranscriptStatus::Processing) => {
                reset_count += 1;
            }
            _ => {}
        }

        if metadata
            .transcript_retry_after
            .map(|retry_after| retry_after > now_epoch_secs)
            .unwrap_or(false)
            && !force_retranscribe
        {
            cooling_down += 1;
            return false;
        }

        if dry_run {
            candidates.push(TranscriptBackfillCandidate {
                sha256: metadata.sha256.clone(),
                owner: metadata.owner.clone(),
                uploaded: metadata.uploaded.clone(),
                transcript_status: metadata
                    .transcript_status
                    .map(|status| format!("{:?}", status).to_lowercase()),
                retry_after_epoch_secs: metadata.transcript_retry_after,
                cooldown_remaining_secs: metadata
                    .transcript_retry_after
                    .map(|retry_after| retry_after.saturating_sub(now_epoch_secs))
                    .filter(|remaining| *remaining > 0),
            });
            return false;
        }

        if triggered >= max_triggers {
            return true;
        }

        // Update status to Processing and trigger transcription (async/fire-and-forget)
        metadata.transcript_status = Some(TranscriptStatus::Processing);
        let _ = put_blob_metadata(&metadata);

        match trigger_on_demand_transcription(hash, &metadata.owner, None, None) {
            Ok(_) => triggered += 1,
            Err(_) => errors += 1,
        }
        false
    };

    let (has_more, next_offset, processed_users) = if scope == "recent" {
        let recent_index = crate::metadata::get_recent_index()?;
        let total_hashes = recent_index.hashes.len();
        let end = std::cmp::min(offset + limit, total_hashes);
        let hashes_to_process = if offset < total_hashes {
            &recent_index.hashes[offset..end]
        } else {
            &[] as &[String]
        };

        for hash in hashes_to_process {
            if hit_limit {
                break;
            }
            if process_hash(hash) {
                hit_limit = true;
                break;
            }
        }

        let (has_more, next_offset) = backfill_batch_cursor(offset, end, total_hashes, hit_limit);

        (has_more, next_offset, None)
    } else {
        let user_index = crate::metadata::get_user_index()?;
        let total_users = user_index.pubkeys.len();
        let end = std::cmp::min(offset + limit, total_users);
        let pubkeys_to_process = if offset < total_users {
            &user_index.pubkeys[offset..end]
        } else {
            &[] as &[String]
        };

        for pubkey in pubkeys_to_process {
            if hit_limit {
                break;
            }

            let hashes = crate::metadata::get_user_blobs(pubkey).unwrap_or_default();
            for hash in hashes {
                if hit_limit {
                    break;
                }
                if process_hash(&hash) {
                    hit_limit = true;
                    break;
                }
            }
        }

        let (has_more, next_offset) = backfill_batch_cursor(offset, end, total_users, hit_limit);

        (has_more, next_offset, Some(pubkeys_to_process.len()))
    };

    let response = serde_json::json!({
        "success": true,
        "batch": {
            "scope": scope,
            "offset": offset,
            "limit": limit,
            "processed_users": processed_users,
            "processed_hashes": processed_hashes,
            "next_offset": next_offset,
            "has_more": has_more
        },
        "results": {
            "dry_run": dry_run,
            "triggered": triggered,
            "already_complete": already_complete,
            "already_processing": already_processing,
            "cooling_down": cooling_down,
            "not_transcribable": not_transcribable,
            "reset_from_processing": reset_count,
            "errors": errors,
            "hit_trigger_limit": hit_limit,
            "candidates": candidates
        }
    });

    let mut resp = json_response(StatusCode::OK, &response);
    add_cors_headers(&mut resp);
    Ok(resp)
}

/// POST /admin/moderate - Webhook from divine-moderation-service
/// Receives moderation decisions and updates blob status
fn handle_admin_moderate(mut req: Request) -> Result<Response> {
    // Try to get webhook secret from secret store (optional)
    let expected_secret: Option<String> =
        fastly::secret_store::SecretStore::open("blossom_secrets")
            .ok()
            .and_then(|store| store.get("webhook_secret"))
            .map(|secret| String::from_utf8(secret.plaintext().to_vec()).unwrap_or_default());

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
        return Err(BlossomError::Forbidden(
            "Webhook secret not configured".into(),
        ));
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

    eprintln!(
        "[ADMIN] Moderation webhook: sha256={}, action={}",
        sha256, action
    );

    // Validate sha256 format
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BlossomError::BadRequest("Invalid sha256 format".into()));
    }

    // Map action to BlobStatus.
    //
    // AGE_RESTRICTED is intentionally split out from RESTRICT/QUARANTINE: it lands on
    // BlobStatus::AgeRestricted, which serves as a 401 age gate to anonymous viewers
    // instead of the 404 shadow-ban that RESTRICT/QUARANTINE produce.
    let new_status = match action.to_uppercase().as_str() {
        "BLOCK" | "BAN" | "PERMANENT_BAN" => BlobStatus::Banned,
        "AGE_RESTRICTED" | "AGE_RESTRICT" => BlobStatus::AgeRestricted,
        "RESTRICT" | "QUARANTINE" => BlobStatus::Restricted,
        "APPROVE" | "SAFE" => BlobStatus::Active,
        _ => {
            return Err(BlossomError::BadRequest(format!(
                "Unknown action: {}. Expected BLOCK, RESTRICT, QUARANTINE, AGE_RESTRICTED, or APPROVE",
                action
            )));
        }
    };

    // Update blob status
    match update_blob_status(sha256, new_status) {
        Ok(()) => {
            eprintln!("[ADMIN] Updated blob {} to status {:?}", sha256, new_status);

            // Purge VCL cache so the new status takes effect immediately.
            // Banned/restricted content will 404 on next request; approved content will 200.
            purge_vcl_cache(sha256);

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
    let expected_secret: Option<String> =
        fastly::secret_store::SecretStore::open("blossom_secrets")
            .ok()
            .and_then(|store| store.get("webhook_secret"))
            .map(|secret| String::from_utf8(secret.plaintext().to_vec()).unwrap_or_default());

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
        return Err(BlossomError::Forbidden(
            "Webhook secret not configured".into(),
        ));
    }

    // Parse JSON body
    let body = req.take_body().into_string();
    let payload: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| BlossomError::BadRequest(format!("Invalid JSON: {}", e)))?;

    let parsed = parse_transcode_status_webhook_payload(&payload, unix_timestamp_secs())?;
    let sha256 = parsed.sha256.as_str();

    eprintln!(
        "[TRANSCODE] Status webhook: sha256={}, status={:?}, new_size={:?}, dim={:?}, error_code={:?}, terminal={}",
        sha256,
        parsed.status,
        parsed.new_size,
        parsed.dim,
        parsed.error_code,
        parsed.terminal
    );

    // Validate sha256 format
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BlossomError::BadRequest("Invalid sha256 format".into()));
    }

    // Update transcode status (and optionally file size and dimensions if provided)
    use crate::metadata::update_transcode_status_with_metadata;
    match update_transcode_status_with_metadata(
        sha256,
        parsed.status,
        parsed.new_size,
        parsed.dim.clone(),
        TranscodeMetadataUpdate {
            error_code: parsed.error_code.clone(),
            error_message: parsed.error_message.clone(),
            last_attempt_at: Some(current_timestamp()),
            retry_after: parsed.retry_after_epoch_secs,
            terminal: Some(parsed.terminal),
            increment_attempt_count: matches!(parsed.status, TranscodeStatus::Failed),
        },
    ) {
        Ok(()) => {
            if let Some(ref d) = parsed.dim {
                eprintln!(
                    "[TRANSCODE] Updated blob {} to transcode status {:?} with dim {}",
                    sha256, parsed.status, d
                );
            } else if let Some(size) = parsed.new_size {
                eprintln!(
                    "[TRANSCODE] Updated blob {} to transcode status {:?} with new size {}",
                    sha256, parsed.status, size
                );
            } else {
                eprintln!(
                    "[TRANSCODE] Updated blob {} to transcode status {:?}",
                    sha256, parsed.status
                );
            }

            // Purge VCL cache on transcode completion so any cached 202 is evicted
            // and clients get the actual content on next request.
            if matches!(
                parsed.status,
                TranscodeStatus::Complete | TranscodeStatus::Failed
            ) {
                purge_vcl_cache(sha256);
            }

            let response = serde_json::json!({
                "success": true,
                "sha256": sha256,
                "transcode_status": format!("{:?}", parsed.status).to_lowercase(),
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

/// POST /admin/transcript-status - Webhook from divine-transcoder service
/// Updates transcript status for a blob after VTT generation
fn handle_transcript_status(mut req: Request) -> Result<Response> {
    // Try to get webhook secret from secret store (same as moderation/transcode webhook)
    let expected_secret: Option<String> =
        fastly::secret_store::SecretStore::open("blossom_secrets")
            .ok()
            .and_then(|store| store.get("webhook_secret"))
            .map(|secret| String::from_utf8(secret.plaintext().to_vec()).unwrap_or_default());

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
                    eprintln!("[TRANSCRIPT] Invalid webhook secret");
                    return Err(BlossomError::Forbidden("Invalid webhook secret".into()));
                }
            }
            _ => {
                eprintln!("[TRANSCRIPT] Missing or invalid Authorization header");
                return Err(BlossomError::AuthRequired("Webhook secret required".into()));
            }
        }
    } else {
        // Fail closed: reject requests if webhook_secret is not configured
        eprintln!("[TRANSCRIPT] webhook_secret not configured, rejecting request");
        return Err(BlossomError::Forbidden(
            "Webhook secret not configured".into(),
        ));
    }

    // Parse JSON body
    let body = req.take_body().into_string();
    let payload: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| BlossomError::BadRequest(format!("Invalid JSON: {}", e)))?;

    let parsed = parse_transcript_status_webhook_payload(&payload, unix_timestamp_secs())?;
    let sha256 = parsed.sha256.as_str();

    eprintln!(
        "[TRANSCRIPT] Status webhook: sha256={}, status={:?}, job_id={:?}",
        sha256, parsed.status, parsed.job_id
    );

    // Validate sha256 format
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BlossomError::BadRequest("Invalid sha256 format".into()));
    }

    use crate::metadata::update_transcript_status;
    match update_transcript_status(
        sha256,
        parsed.status,
        TranscriptMetadataUpdate {
            error_code: parsed.error_code.clone(),
            error_message: parsed.error_message.clone(),
            last_attempt_at: Some(current_timestamp()),
            retry_after: parsed.retry_after_epoch_secs,
            terminal: Some(parsed.terminal),
            increment_attempt_count: matches!(parsed.status, TranscriptStatus::Failed),
        },
    ) {
        Ok(()) => {
            eprintln!(
                "[TRANSCRIPT] Updated blob {} to transcript status {:?}",
                sha256, parsed.status
            );

            // If a subtitle job exists, keep it in sync with webhook status and metadata.
            let mut updated_job: Option<SubtitleJob> = if let Some(ref id) = parsed.job_id {
                get_subtitle_job(id)?
            } else {
                get_subtitle_job_by_hash(sha256)?
            };

            if let Some(mut job) = updated_job.take() {
                job.updated_at = current_timestamp();
                match parsed.status {
                    TranscriptStatus::Pending => {
                        job.status = SubtitleJobStatus::Queued;
                    }
                    TranscriptStatus::Processing => {
                        job.status = SubtitleJobStatus::Processing;
                    }
                    TranscriptStatus::Complete => {
                        job.status = SubtitleJobStatus::Ready;
                        if job.text_track_url.is_none() {
                            job.text_track_url =
                                Some(format!("https://media.divine.video/{}.vtt", sha256));
                        }
                        if let Some(lang) = parsed.language.clone() {
                            job.language = Some(lang);
                        }
                        if let Some(ms) = parsed.duration_ms {
                            job.duration_ms = Some(ms);
                        }
                        if let Some(cues) = parsed.cue_count {
                            job.cue_count = Some(cues);
                        }
                        job.next_retry_at_unix = None;
                        job.error_code = None;
                        job.error_message = None;
                    }
                    TranscriptStatus::Failed => {
                        apply_subtitle_job_failure(
                            &mut job,
                            parsed.error_code.clone(),
                            parsed.error_message.clone(),
                        );
                    }
                }
                set_subtitle_job_id_for_hash(sha256, &job.job_id)?;
                put_subtitle_job(&job)?;
            }

            // Purge VCL cache on transcript completion so cached 202s are evicted
            if matches!(
                parsed.status,
                TranscriptStatus::Complete | TranscriptStatus::Failed
            ) {
                purge_transcript_content_cache(sha256);
                purge_vcl_cache(sha256);
            }

            let response = serde_json::json!({
                "success": true,
                "sha256": sha256,
                "transcript_status": format!("{:?}", parsed.status).to_lowercase(),
                "message": "Transcript status updated"
            });
            let mut resp = json_response(StatusCode::OK, &response);
            add_cors_headers(&mut resp);
            Ok(resp)
        }
        Err(BlossomError::NotFound(_)) => {
            eprintln!(
                "[TRANSCRIPT] Reconciliation pending for missing blob {} status={:?} error_code={:?} retry_after={:?}",
                sha256,
                parsed.status,
                parsed.error_code,
                parsed.retry_after_epoch_secs
            );
            let response = serde_json::json!({
                "success": true,
                "sha256": sha256,
                "reconciliation": "pending",
                "message": "Transcript status accepted for later reconciliation"
            });
            let mut resp = json_response(StatusCode::ACCEPTED, &response);
            add_cors_headers(&mut resp);
            Ok(resp)
        }
        Err(e) => {
            eprintln!("[TRANSCRIPT] Failed to update blob {}: {:?}", sha256, e);
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
            <p class="tagline">Content-addressable blob storage implementing the Blossom protocol with AI-powered moderation, HLS, and transcript generation</p>
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
                <span class="method method-get">GET</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/&lt;sha256&gt;.vtt</span>
                    <p class="endpoint-desc">Stable WebVTT URL for audio/video transcripts. Automatically triggers on-demand transcription if it has not been generated yet.</p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-get">GET</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/&lt;sha256&gt;/VTT</span>
                    <p class="endpoint-desc">Alias for transcript retrieval, compatible with legacy clients.</p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-put">POST</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/v1/subtitles/jobs</span>
                    <p class="endpoint-desc">Create or reuse a subtitle job by hash. Request body: <code>video_sha256</code>, optional <code>lang</code>, optional <code>force</code>.</p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-get">GET</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/v1/subtitles/jobs/&lt;job_id&gt;</span>
                    <p class="endpoint-desc">Get subtitle job status: <code>queued</code>, <code>processing</code>, <code>ready</code>, or <code>failed</code>.</p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-get">GET</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/v1/subtitles/by-hash/&lt;sha256&gt;</span>
                    <p class="endpoint-desc">Idempotent lookup for the current subtitle job by media hash.</p>
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
                    <p class="endpoint-desc">Soft-delete a blob you own so it stops serving publicly while remaining recoverable. Non-owner refs only unlink themselves. Requires Nostr authentication. <em>(BUD-02)</em></p>
                </div>
            </div>
            <div class="endpoint">
                <span class="method method-delete">DELETE</span>
                <div class="endpoint-info">
                    <span class="endpoint-path">/vanish</span>
                    <p class="endpoint-desc">GDPR Right to Erasure. Deletes all blobs and data for the authenticated user. Requires Nostr authentication.</p>
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
                    <p>Viewer requests accept Blossom list auth or NIP-98 HTTP auth. Upload and delete operations require signed Blossom events (kind <code>24242</code>).</p>
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
                    <h3>WebVTT Transcripts</h3>
                    <p>On-demand transcript generation for audio/video blobs, served from immutable URLs at <code>/&lt;sha256&gt;.vtt</code>.</p>
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
/// Set immutable cache headers and surrogate key for content-addressed responses.
/// - Cache-Control: tells browsers to cache for 1 year
/// - Surrogate-Control: tells Fastly edge to cache for 1 year (stripped before client)
/// - Surrogate-Key: enables targeted purging via `fastly purge --key {hash}`
fn add_cache_headers(resp: &mut Response, hash: &str) {
    resp.set_header("Cache-Control", "public, max-age=31536000, immutable");
    resp.set_header("Surrogate-Control", "max-age=31536000");
    resp.set_header("Surrogate-Key", hash);
}

/// Like add_cache_headers but for authenticated or admin-only content that must
/// not be stored in shared caches.
fn add_private_cache_headers(resp: &mut Response, hash: &str) {
    resp.set_header("Cache-Control", "private, no-store");
    resp.set_header("Surrogate-Control", "no-store");
    resp.set_header("Surrogate-Key", hash);
}

/// Mark a response as explicitly uncacheable (used for 202 in-progress responses).
/// Defence-in-depth: VCL vcl_fetch also marks 202s uncacheable, but belt-and-suspenders.
fn add_no_cache_headers(resp: &mut Response) {
    resp.set_header("Cache-Control", "no-store");
    resp.set_header("Surrogate-Control", "no-store");
}

/// Purge content from the VCL caching layer by Surrogate-Key.
/// Calls POST /service/{service_id}/purge/{key} on api.fastly.com.
/// Best-effort: logs errors but never fails the calling request.
pub(crate) fn purge_vcl_cache(surrogate_key: &str) {
    let api_token = match fastly::secret_store::SecretStore::open("blossom_secrets")
        .ok()
        .and_then(|store| store.get("fastly_api_token"))
        .map(|secret| String::from_utf8(secret.plaintext().to_vec()).unwrap_or_default())
    {
        Some(token) if !token.is_empty() => token,
        _ => {
            eprintln!("[PURGE] fastly_api_token not configured, skipping VCL cache purge");
            return;
        }
    };

    // VCL service ID for the caching layer (Divine.Video's website)
    let vcl_service_id = "ML7R82HKfmTaqTpHExIDVN";
    let url = format!(
        "https://api.fastly.com/service/{}/purge/{}",
        vcl_service_id, surrogate_key
    );

    let mut purge_req = Request::new(Method::POST, &url);
    purge_req.set_header("Host", "api.fastly.com");
    purge_req.set_header("Fastly-Key", &api_token);
    purge_req.set_header("Accept", "application/json");

    match purge_req.send("fastly_api") {
        Ok(resp) => {
            let status = resp.get_status();
            if status.is_success() {
                eprintln!("[PURGE] VCL cache purged for key={}", surrogate_key);
            } else {
                eprintln!(
                    "[PURGE] VCL purge failed for key={}: HTTP {}",
                    surrogate_key,
                    status.as_u16()
                );
            }
        }
        Err(e) => {
            eprintln!(
                "[PURGE] VCL purge request failed for key={}: {}",
                surrogate_key, e
            );
        }
    }
}

fn add_cors_headers(resp: &mut Response) {
    resp.set_header("Access-Control-Allow-Origin", "*");
    resp.set_header(
        "Access-Control-Allow-Methods",
        "GET, HEAD, PUT, POST, DELETE, OPTIONS",
    );
    resp.set_header(
        "Access-Control-Allow-Headers",
        "Authorization, Content-Type, X-Sha256",
    );
    resp.set_header("Access-Control-Expose-Headers", upload_exposed_headers());
}

#[derive(Debug, PartialEq, Eq)]
struct UploadCapabilityHeaders {
    extensions: &'static str,
    control_host: String,
    data_host: &'static str,
}

fn upload_exposed_headers() -> &'static str {
    "X-Sha256, X-Content-Length, X-C2PA-Manifest-Id, X-Source-Sha256, X-Content-SHA256, X-Audio-Duration, X-Audio-Size, X-Divine-Upload-Extensions, X-Divine-Upload-Control-Host, X-Divine-Upload-Data-Host"
}

fn upload_control_host(public_host: Option<&str>) -> String {
    public_host.unwrap_or("media.divine.video").to_string()
}

fn upload_capability_headers(control_host: &str) -> UploadCapabilityHeaders {
    UploadCapabilityHeaders {
        extensions: DIVINE_UPLOAD_EXTENSION_RESUMABLE,
        control_host: control_host.to_string(),
        data_host: UPLOAD_SERVICE_HOST,
    }
}

fn add_upload_capability_headers(resp: &mut Response, control_host: &str) {
    let headers = upload_capability_headers(control_host);
    resp.set_header("X-Divine-Upload-Extensions", headers.extensions);
    resp.set_header("X-Divine-Upload-Control-Host", headers.control_host);
    resp.set_header("X-Divine-Upload-Data-Host", headers.data_host);
}

/// CORS preflight response
fn cors_preflight_response() -> Response {
    let mut resp = Response::from_status(StatusCode::NO_CONTENT);
    add_cors_headers(&mut resp);
    resp.set_header("Access-Control-Max-Age", "86400");
    resp
}

/// Get base URL for blob descriptors from request Host header.
/// Prefers X-Original-Host (set by VCL when service-chaining) over the Host header,
/// so that BlobDescriptor URLs reflect the public-facing domain.
fn get_base_url(req: &Request) -> String {
    format!(
        "https://{}",
        upload_control_host(get_public_host(req).as_deref())
    )
}

fn get_public_host(req: &Request) -> Option<String> {
    req.get_header_str("X-Original-Host")
        .or_else(|| req.get_header(header::HOST).and_then(|h| h.to_str().ok()))
        .map(str::to_string)
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
    if path_lower.ends_with(".vtt") {
        return Some("text/vtt");
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{
        backfill_batch_cursor, classify_audio_reuse_availability, decide_transcode_fetch_action,
        decide_transcript_fetch_action, error_response, is_alias_only_audio_blob,
        is_quality_variant_path, parse_quality_variant_path,
        parse_transcript_status_webhook_payload, should_delete_derived_audio_blob,
        should_eagerly_trigger_transcription, should_set_audio_content_length,
        upload_capability_headers, upload_control_host, upload_exposed_headers,
        AudioReuseAvailability, TranscodeFetchAction, TranscriptFetchAction,
        TranscriptPendingState,
    };
    use crate::blossom::{TranscodeStatus, TranscriptStatus};
    use crate::error::{BlossomError, Result as BlossomResult};
    use fastly::http::StatusCode;

    #[test]
    fn quality_variant_path_valid() {
        let hash = "a".repeat(64);
        assert!(is_quality_variant_path(&format!("/{}/720p", hash)));
        assert!(is_quality_variant_path(&format!("/{}/480p", hash)));
        assert!(is_quality_variant_path(&format!("/{}/720p.mp4", hash)));
        assert!(is_quality_variant_path(&format!("/{}/480p.mp4", hash)));

        let (parsed_hash, filename, ct) =
            parse_quality_variant_path(&format!("/{}/720p", hash)).unwrap();
        assert_eq!(parsed_hash, hash);
        assert_eq!(filename, "stream_720p.ts");
        assert_eq!(ct, "video/mp2t");

        let (parsed_hash, filename, ct) =
            parse_quality_variant_path(&format!("/{}/720p.mp4", hash)).unwrap();
        assert_eq!(parsed_hash, hash);
        assert_eq!(filename, "stream_720p.mp4");
        assert_eq!(ct, "video/mp4");
    }

    #[test]
    fn quality_variant_path_no_underflow_on_short_input() {
        // These must not panic (previously caused u32::MAX underflow)
        assert!(!is_quality_variant_path("/720p"));
        assert!(!is_quality_variant_path("/480p"));
        assert!(!is_quality_variant_path("/720p.mp4"));
        assert!(!is_quality_variant_path("/480p.mp4"));
        assert!(!is_quality_variant_path("720p"));
        assert!(!is_quality_variant_path("480p"));
        assert!(!is_quality_variant_path(""));
        assert!(parse_quality_variant_path("/480p").is_none());
        assert!(parse_quality_variant_path("720p").is_none());
        assert!(parse_quality_variant_path("/720p.mp4").is_none());
        assert!(parse_quality_variant_path("480p.mp4").is_none());
    }

    #[test]
    fn mp4_variant_maps_to_ts_counterpart() {
        let hash = "a".repeat(64);

        // 720p.mp4 derives correct .ts counterpart for backfill check
        let (_, filename, ct) = parse_quality_variant_path(&format!("/{}/720p.mp4", hash)).unwrap();
        assert_eq!(ct, "video/mp4");
        assert_eq!(filename.replace(".mp4", ".ts"), "stream_720p.ts");

        // 480p.mp4 likewise
        let (_, filename, ct) = parse_quality_variant_path(&format!("/{}/480p.mp4", hash)).unwrap();
        assert_eq!(ct, "video/mp4");
        assert_eq!(filename.replace(".mp4", ".ts"), "stream_480p.ts");

        // .ts variants have different content type — backfill path won't trigger
        let (_, _, ct) = parse_quality_variant_path(&format!("/{}/720p", hash)).unwrap();
        assert_eq!(ct, "video/mp2t");
    }

    #[test]
    fn parses_transcript_webhook_error_code_fields() {
        let payload = serde_json::json!({
            "sha256": "50dfc6758bb3cdf823ef33315e72642ebb881a0b1d0f6b0d8bade0f0fad30c3a",
            "status": "failed",
            "error_code": "normalize_failed",
            "error_message": "bad transcript body"
        });

        let parsed = parse_transcript_status_webhook_payload(&payload, 1_000).unwrap();

        assert_eq!(parsed.error_code.as_deref(), Some("normalize_failed"));
        assert_eq!(parsed.error_message.as_deref(), Some("bad transcript body"));
        assert_eq!(parsed.retry_after_epoch_secs, None);
    }

    #[test]
    fn parses_transcript_webhook_retry_after_for_provider_rate_limited() {
        let payload = serde_json::json!({
            "sha256": "50dfc6758bb3cdf823ef33315e72642ebb881a0b1d0f6b0d8bade0f0fad30c3a",
            "status": "failed",
            "error_code": "provider_rate_limited",
            "retry_after": 15
        });

        let parsed = parse_transcript_status_webhook_payload(&payload, 1_000).unwrap();

        assert_eq!(parsed.error_code.as_deref(), Some("provider_rate_limited"));
        assert_eq!(parsed.retry_after_epoch_secs, Some(1_015));
    }

    #[test]
    fn transcript_fetch_action_cools_down_when_retry_after_is_in_future() {
        assert_eq!(
            decide_transcript_fetch_action(
                Some(TranscriptStatus::Failed),
                Some(1_030),
                1,
                false,
                1_000,
            ),
            TranscriptFetchAction::Accepted {
                state: TranscriptPendingState::CoolingDown,
                retry_after_secs: 30,
            }
        );
    }

    #[test]
    fn transcript_fetch_action_keeps_processing_items_in_progress() {
        assert_eq!(
            decide_transcript_fetch_action(
                Some(TranscriptStatus::Processing),
                None,
                0,
                false,
                1_000,
            ),
            TranscriptFetchAction::Accepted {
                state: TranscriptPendingState::InProgress,
                retry_after_secs: 5,
            }
        );
    }

    #[test]
    fn transcript_fetch_action_triggers_pending_items_without_cooldown() {
        assert_eq!(
            decide_transcript_fetch_action(Some(TranscriptStatus::Pending), None, 0, false, 1_000,),
            TranscriptFetchAction::Trigger {
                retry_after_secs: 10,
                should_repair: false,
            }
        );
    }

    #[test]
    fn transcript_fetch_action_repairs_missing_vtt_for_complete_status() {
        assert_eq!(
            decide_transcript_fetch_action(Some(TranscriptStatus::Complete), None, 0, false, 1_000,),
            TranscriptFetchAction::Trigger {
                retry_after_secs: 10,
                should_repair: true,
            }
        );
    }

    #[test]
    fn transcript_fetch_action_retries_failed_items_under_cap() {
        assert_eq!(
            decide_transcript_fetch_action(Some(TranscriptStatus::Failed), None, 2, false, 1_000,),
            TranscriptFetchAction::Trigger {
                retry_after_secs: 10,
                should_repair: false,
            }
        );
    }

    #[test]
    fn transcript_fetch_action_stops_retrying_at_cap() {
        assert_eq!(
            decide_transcript_fetch_action(Some(TranscriptStatus::Failed), None, 3, false, 1_000,),
            TranscriptFetchAction::Terminal
        );
    }

    #[test]
    fn transcript_fetch_action_honors_terminal_failure() {
        assert_eq!(
            decide_transcript_fetch_action(Some(TranscriptStatus::Failed), None, 1, true, 1_000,),
            TranscriptFetchAction::Terminal
        );
    }

    #[test]
    fn eagerly_triggers_transcription_for_pending_transcribable_media() {
        assert!(should_eagerly_trigger_transcription(
            "video/mp4",
            Some(TranscriptStatus::Pending)
        ));
        assert!(should_eagerly_trigger_transcription("audio/mp4", None));
    }

    #[test]
    fn does_not_eagerly_trigger_transcription_for_non_pending_or_non_transcribable_media() {
        assert!(!should_eagerly_trigger_transcription("image/jpeg", None));
        assert!(!should_eagerly_trigger_transcription(
            "video/mp4",
            Some(TranscriptStatus::Processing)
        ));
        assert!(!should_eagerly_trigger_transcription(
            "video/mp4",
            Some(TranscriptStatus::Complete)
        ));
        assert!(!should_eagerly_trigger_transcription(
            "video/mp4",
            Some(TranscriptStatus::Failed)
        ));
    }

    #[test]
    fn backfill_cursor_retries_same_window_after_hitting_trigger_limit() {
        assert_eq!(backfill_batch_cursor(50, 100, 250, true), (true, Some(50)));
    }

    #[test]
    fn backfill_cursor_advances_when_batch_completes_without_hitting_limit() {
        assert_eq!(
            backfill_batch_cursor(50, 100, 250, false),
            (true, Some(100))
        );
    }

    #[test]
    fn backfill_cursor_finishes_on_last_page_without_hitting_limit() {
        assert_eq!(backfill_batch_cursor(200, 250, 250, false), (false, None));
    }

    #[test]
    fn transcode_fetch_action_retries_failed_items_under_cap() {
        assert_eq!(
            decide_transcode_fetch_action(Some(TranscodeStatus::Failed), None, 2, false, 1_000,),
            TranscodeFetchAction::Trigger {
                retry_after_secs: 10,
                should_repair: false,
            }
        );
    }

    #[test]
    fn transcode_fetch_action_stops_retrying_at_cap() {
        assert_eq!(
            decide_transcode_fetch_action(Some(TranscodeStatus::Failed), None, 3, false, 1_000,),
            TranscodeFetchAction::Terminal
        );
    }

    #[test]
    fn transcode_fetch_action_repairs_missing_manifest_for_complete_status() {
        assert_eq!(
            decide_transcode_fetch_action(Some(TranscodeStatus::Complete), None, 0, false, 1_000,),
            TranscodeFetchAction::Trigger {
                retry_after_secs: 10,
                should_repair: true,
            }
        );
    }

    #[test]
    fn audio_reuse_availability_classifies_lookup_outcomes() {
        let allowed: BlossomResult<bool> = Ok(true);
        let denied: BlossomResult<bool> = Ok(false);
        let unavailable: BlossomResult<bool> = Err(BlossomError::Internal("down".into()));

        assert_eq!(
            classify_audio_reuse_availability(&allowed),
            AudioReuseAvailability::Allowed
        );
        assert_eq!(
            classify_audio_reuse_availability(&denied),
            AudioReuseAvailability::Denied
        );
        assert_eq!(
            classify_audio_reuse_availability(&unavailable),
            AudioReuseAvailability::LookupUnavailable
        );
    }

    #[test]
    fn alias_only_audio_blob_requires_reverse_refs_without_public_blob_refs() {
        assert!(is_alias_only_audio_blob(true, &[]));
        assert!(!is_alias_only_audio_blob(false, &[]));
        assert!(!is_alias_only_audio_blob(
            true,
            &[String::from("pubkey"), String::from("another")]
        ));
    }

    #[test]
    fn derived_audio_cleanup_only_deletes_when_no_sources_or_blob_refs_remain() {
        assert!(should_delete_derived_audio_blob(&[], &[]));
        assert!(!should_delete_derived_audio_blob(
            &[String::from("source")],
            &[]
        ));
        assert!(!should_delete_derived_audio_blob(
            &[],
            &[String::from("pubkey")]
        ));
    }

    #[test]
    fn audio_response_headers_keep_partial_content_length_from_storage() {
        assert!(!should_set_audio_content_length(
            StatusCode::PARTIAL_CONTENT
        ));
    }

    #[test]
    fn audio_response_headers_set_full_content_length_for_complete_responses() {
        assert!(should_set_audio_content_length(StatusCode::OK));
        assert!(should_set_audio_content_length(StatusCode::CREATED));
    }

    #[test]
    fn upload_capability_headers_advertise_resumable_extension() {
        let resp = upload_capability_headers("media.divine.video");

        assert_eq!(resp.extensions, "resumable-sessions");
    }

    #[test]
    fn upload_capability_headers_advertise_control_and_data_hosts() {
        let resp = upload_capability_headers("media.divine.video");

        assert_eq!(resp.control_host, "media.divine.video");
        assert_eq!(resp.data_host, "upload.divine.video");
    }

    #[test]
    fn upload_control_host_defaults_to_media_domain() {
        assert_eq!(upload_control_host(None), "media.divine.video");
        assert_eq!(
            upload_control_host(Some("staging-media.divine.video")),
            "staging-media.divine.video"
        );
    }

    #[test]
    fn upload_capability_headers_are_exposed_for_cors() {
        let exposed_headers = upload_exposed_headers();

        assert!(exposed_headers.contains("X-Divine-Upload-Extensions"));
        assert!(exposed_headers.contains("X-Divine-Upload-Control-Host"));
        assert!(exposed_headers.contains("X-Divine-Upload-Data-Host"));
    }

    #[test]
    fn complete_rejects_unknown_upload_session_with_404() {
        let resp = error_response(&BlossomError::NotFound("Upload session not found".into()));

        assert_eq!(resp.get_status(), StatusCode::NOT_FOUND);
    }
}
