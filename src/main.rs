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
mod rate_limit;
mod req_id;
mod request_log;
mod storage;
mod upload_log;
mod viewer_auth;

use crate::auth::{diagnose_viewer_auth, validate_auth, validate_hash_match, viewer_pubkey};
use crate::blossom::{
    is_audio_path, is_hash_path, is_quality_variant_path, is_transcribable_mime_type,
    is_transcript_path, is_video_mime_type, is_vtt_file_path, parse_audio_path,
    parse_hash_from_path, parse_quality_variant_path, parse_thumbnail_path, parse_transcript_path,
    parse_vtt_file_path, AudioMapping, AuthAction, BlobAccess, BlobDescriptor, BlobMetadata,
    BlobStatus, ResumableUploadCompleteResponse, ResumableUploadInitRequest,
    ResumableUploadInitResponse, SubtitleJob, SubtitleJobCreateRequest, SubtitleJobStatus,
    TranscodeStatus, TranscriptStatus, UploadRequirements, QUALITY_VARIANTS,
};
use crate::delete_policy::{
    build_creator_delete_response, finalize_erased_vanish_blob_with_ops, handle_creator_delete,
    map_webhook_moderate_action, plan_user_delete, prepare_vanish_blob_with_ops, soft_delete_blob,
    validate_sha256_format, DefaultCreatorDeleteOps, DeletePlan, PreparedVanishBlobOrOutcome,
    VanishBlobOutcome,
};
use crate::error::{BlossomError, Result};
use crate::media_auth_log::format_media_auth_log;
use crate::metadata::{
    add_to_audio_source_refs, add_to_blob_refs, add_to_recent_index, add_to_user_index,
    add_to_user_list, claim_vanish_audit_completion, delete_audio_mapping,
    delete_audio_source_refs, delete_auth_events, delete_blob_metadata, delete_blob_refs,
    delete_subtitle_data, delete_user_list, delete_vanish_audit_state, get_audio_mapping,
    get_audio_source_refs, get_auth_event,
    get_blob_metadata, get_blob_metadata_uncached, get_blob_refs, get_subtitle_job,
    get_subtitle_job_by_hash, get_tombstone, get_user_blobs, get_vanish_audit_state,
    list_blobs_with_metadata, move_user_list_entries_to_end, put_audio_mapping, put_auth_event,
    put_blob_metadata, put_subtitle_job, put_vanish_audit_state, remove_from_audio_source_refs,
    remove_from_blob_refs, remove_from_user_index, remove_from_user_list,
    set_subtitle_job_id_for_hash, update_blob_status, update_stats_on_add, StatusUpdateOutcome,
    TranscodeMetadataUpdate, TranscriptMetadataUpdate, VanishAuditState,
};
use crate::storage::{
    blob_exists, check_funnelcake_audio_reuse, current_timestamp, delete_blob as storage_delete,
    download_blob_read_through, download_blob_with_fallback, download_thumbnail,
    dispatch_vanish_timing_log, erase_vanish_batch, trigger_audio_extraction,
    trigger_cloud_run_delete_blob, upload_blob, write_audit_log, write_vanish_audit_log,
    VanishAuditInitiator, VanishAuditPhase,
};
use crate::viewer_auth::{ViewerAuthDiagnostics, ViewerAuthState};
use blossom_core::cache_policy::{
    blob_cache_policy, cache_headers_for_policy, mutable_derivative_cache_headers,
    status_requires_private_response, BlobCachePolicy, CacheHeaders,
};
use blossom_core::request_diagnostics::{diagnostic_probe_id, route_category};
use blossom_core::upload_log::{
    record_failure, record_response, record_send_attempt, OriginSendResult, UploadLogRecord,
    UploadRoute,
};
use fastly_blossom::resumable_complete::parse_resumable_complete_request_body;

use fastly::cache::simple as simple_cache;
use fastly::http::{header, Method, StatusCode};
use fastly::kv_store::KVStore;
use fastly::{Error, Request, Response};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::time::Duration;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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
fn main(mut req: Request) -> std::result::Result<Response, Error> {
    // Route Rust panics to the persistent diagnostics endpoint so a
    // non-returning guest failure still leaves a record. The message is the
    // panic text, not the compute_request JSON schema. Fails open when the
    // endpoint is not configured, matching request_log::emit.
    let _ = fastly::log::set_panic_endpoint(request_log::ENDPOINT_NAME);
    let started = Instant::now();
    let request_id = req_id::for_request(&req);
    req.set_header(req_id::REQUEST_ID_HEADER, &request_id);
    let method = req.get_method().as_str().to_string();
    let route = route_category(req.get_path());
    let path = req.get_path().to_string();
    let result = handle_request(req);
    let (mut response, error) = match result {
        Ok(response) => (response, None),
        Err(error) => (error_response(&error), Some(error)),
    };

    // 404s on hash-addressed blobs are cached at the edge for 60s
    // (vcl/fetch.vcl). Tag them with the blob's Surrogate-Key so the targeted
    // purge path the operator docs promote (`fastly purge --key <hash>`) can
    // evict a stale negative entry when moderation status flips.
    if response.get_status() == StatusCode::NOT_FOUND {
        if let Some(hash) = surrogate_key_hash_from_path(&path) {
            response.set_header("Surrogate-Key", hash);
        }
    }

    let status = response.get_status().as_u16();
    request_log::emit(
        &mut response,
        &request_id,
        &method,
        route,
        status,
        error.as_ref(),
        started.elapsed(),
    );
    Ok(response)
}

/// Route and handle the request
fn handle_request(req: Request) -> Result<Response> {
    let method = req.get_method().clone();
    let path = req.get_path().to_string();
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
        (Method::PUT, "/upload") => with_upload_log(req, UploadRoute::DirectPut, handle_upload),
        // BUD-06: Upload requirements/pre-validation
        (Method::HEAD, "/upload") => handle_upload_requirements(req),
        // Synchronous audio transcription — thin forward to the upload service's
        // authenticated /transcribe proxy (which calls the transcoder).
        (Method::POST, "/transcribe") => handle_transcribe_proxy(req),
        // Divine resumable control plane
        (Method::POST, "/upload/init") => {
            with_upload_log(req, UploadRoute::ResumableInit, handle_upload_init)
        }
        (Method::POST, p) if p.starts_with("/upload/") && p.ends_with("/complete") => {
            with_upload_log(req, UploadRoute::ResumableComplete, |req, record| {
                handle_upload_complete(req, p, record)
            })
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
        // Postel: a malformed/invalid viewer auth header degrades to anonymous.
        // `BlobMetadata::access_for(None, ...)` is the single source of truth on
        // whether the blob requires auth — public blobs serve, restricted blobs
        // 401 the same way they would for a request with no header at all.
        _ => {
            eprintln!(
                "{}",
                format_media_auth_log(route, &diagnostics, "auth_invalid_degraded_to_anonymous")
            );
            Ok((None, diagnostics))
        }
    }
}

fn log_media_outcome(route: &str, diagnostics: &ViewerAuthDiagnostics, outcome: &str) {
    eprintln!("{}", format_media_auth_log(route, diagnostics, outcome));
}

/// Run an edge-proxied upload handler and emit exactly one structured log line
/// for it, whatever the outcome.
///
/// The wrapper owns emission rather than the handlers because handlers have
/// many early returns via `?`. Logging inside them would mean one emit site per
/// return, and the failure paths — the entire reason this exists — are the ones
/// most likely to be missed.
fn with_upload_log<F>(req: Request, route: UploadRoute, handler: F) -> Result<Response>
where
    F: FnOnce(Request, &mut UploadLogRecord) -> Result<Response>,
{
    let started = Instant::now();
    let mut record = upload_log::start_record(&req, route, req_id::for_request(&req));

    let result = handler(req, &mut record);

    record.duration_ms = duration_millis(started.elapsed());
    match &result {
        Ok(resp) => record_response(&mut record, resp.get_status().as_u16()),
        Err(e) => record_failure(&mut record, e),
    }

    upload_log::emit(&record);
    result
}

/// Send a prepared request to the upload service, recording the attempt.
///
/// A failed `send` means the edge received no complete origin response. Origin
/// may still have received or processed some or all of the request, so this is
/// deliberately not described as evidence that origin was never reached. The
/// timing is captured before the match so it survives that path too.
fn send_to_upload_service(proxy_req: Request, record: &mut UploadLogRecord) -> Result<Response> {
    let started = Instant::now();
    let sent = proxy_req.send(UPLOAD_SERVICE_BACKEND);
    let elapsed = duration_millis(started.elapsed());

    match sent {
        Ok(resp) => {
            record_send_attempt(
                record,
                OriginSendResult::Replied(resp.get_status().as_u16()),
                elapsed,
            );
            Ok(resp)
        }
        Err(e) => {
            let message = e.to_string();
            record_send_attempt(record, OriginSendResult::Failed(&message), elapsed);
            Err(BlossomError::Internal(format!(
                "Failed to proxy to upload service: {}",
                message
            )))
        }
    }
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
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
    cache_policy: BlobCachePolicy,
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
    apply_cache_headers(resp, &cache_headers_for_policy(cache_policy, source_hash));
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

pub(crate) fn cleanup_derived_audio_for_source(source_hash: &str) -> Result<()> {
    let mapping = match get_audio_mapping(source_hash) {
        Ok(Some(mapping)) => mapping,
        Ok(None) => return Ok(()),
        Err(error) => return Err(error),
    };

    let remaining_audio_sources: Vec<String> = get_audio_source_refs(&mapping.audio_sha256)?
        .into_iter()
        .filter(|hash| !hash.eq_ignore_ascii_case(source_hash))
        .collect();

    if !remaining_audio_sources.is_empty() {
        remove_from_audio_source_refs(&mapping.audio_sha256, source_hash)?;
        delete_audio_mapping(source_hash)?;
        return Ok(());
    }

    let blob_refs = get_blob_refs(&mapping.audio_sha256)?;

    if should_delete_derived_audio_blob(&remaining_audio_sources, &blob_refs) {
        // Cloud Run rechecks the main object and every derivative, so verified
        // cleanup can resolve a failed direct main-object delete.
        let _ = storage_delete(&mapping.audio_sha256);
        let derivative_result = delete_blob_gcs_artifacts(&mapping.audio_sha256);
        let replica_result = storage::delete_blob_from_fos(&mapping.audio_sha256);
        purge_edge_cache(&mapping.audio_sha256);
        derivative_result?;
        replica_result?;
        delete_blob_kv_artifacts(&mapping.audio_sha256);
        delete_blob_metadata(&mapping.audio_sha256)?;
    }
    delete_audio_source_refs(&mapping.audio_sha256)?;
    delete_audio_mapping(source_hash)?;
    Ok(())
}

#[derive(Debug)]
struct PreparedDerivedAudioCleanup {
    source_hash: String,
    audio_hash: String,
}

fn prepare_derived_audio_cleanup(source_hash: &str) -> Result<Option<PreparedDerivedAudioCleanup>> {
    let Some(mapping) = get_audio_mapping(source_hash)? else {
        return Ok(None);
    };

    let remaining_audio_sources: Vec<String> = get_audio_source_refs(&mapping.audio_sha256)?
        .into_iter()
        .filter(|hash| !hash.eq_ignore_ascii_case(source_hash))
        .collect();
    let blob_refs = get_blob_refs(&mapping.audio_sha256)?;
    if !should_delete_derived_audio_blob(&remaining_audio_sources, &blob_refs) {
        remove_from_audio_source_refs(&mapping.audio_sha256, source_hash)?;
        delete_audio_mapping(source_hash)?;
        return Ok(None);
    }

    Ok(Some(PreparedDerivedAudioCleanup {
        source_hash: source_hash.to_string(),
        audio_hash: mapping.audio_sha256.to_ascii_lowercase(),
    }))
}

fn finalize_derived_audio_cleanup(plan: &PreparedDerivedAudioCleanup) -> Result<()> {
    delete_blob_kv_artifacts(&plan.audio_hash);
    delete_blob_metadata(&plan.audio_hash)?;
    delete_audio_source_refs(&plan.audio_hash)?;
    delete_audio_mapping(&plan.source_hash)?;
    Ok(())
}

/// GET /<sha256>[.ext] - Retrieve blob
fn handle_get_blob(req: Request, path: &str) -> Result<Response> {
    // Check if this is a thumbnail request ({hash}.jpg)
    if let Some(thumbnail_key) = parse_thumbnail_path(path) {
        let video_hash = thumbnail_key.trim_end_matches(".jpg");

        // Admin Bearer token bypasses moderation checks (used by moderation service proxy)
        let is_admin = admin::validate_bearer_token(&req).is_ok();

        // Check parent video's moderation status - thumbnails inherit video access rules
        let mut cache_status: Option<BlobStatus> = None;
        match get_blob_metadata(video_hash)? {
            Some(meta) => {
                let (requester_pk, auth_diagnostics) = media_viewer_context(&req, "thumbnail")?;
                match meta.access_for(requester_pk.as_deref(), is_admin) {
                    BlobAccess::Allowed => {
                        log_media_outcome("thumbnail", &auth_diagnostics, "allowed");
                        cache_status = Some(meta.status);
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
            None => {
                if !is_admin {
                    eprintln!("[ACCESS] thumbnail hash={} metadata=None denied (non-admin)", video_hash);
                    return Err(BlossomError::NotFound("Blob not found".into()));
                }
                eprintln!("[ACCESS] thumbnail hash={} metadata=None allowed (admin bypass)", video_hash);
            }
        }

        // Try to download existing thumbnail from GCS
        let set_thumb_cache = |resp: &mut Response| {
            // Admin bypass responses stay private, mirroring handle_get_blob.
            if is_admin {
                add_private_cache_headers(resp, video_hash);
            } else {
                add_blob_response_cache_headers(resp, video_hash, cache_status);
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
    let authorization_present = req.contains_header(header::AUTHORIZATION);
    let probe_id = req
        .get_header_str(request_log::PROBE_REQUEST_HEADER)
        .and_then(diagnostic_probe_id);

    // Check metadata for access control
    let metadata = get_blob_metadata(&hash)?;

    // Admin Bearer token bypasses moderation checks (used by moderation service proxy)
    let is_admin = admin::validate_bearer_token(&req).is_ok();

    if should_hide_direct_blob(&hash, is_admin)? {
        return Err(BlossomError::NotFound("Blob not found".into()));
    }

    match metadata {
        Some(ref meta) => {
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
        None => {
            if !is_admin {
                eprintln!("[ACCESS] hash={} metadata=None denied (no metadata, non-admin)", hash);
                return Err(BlossomError::NotFound("Blob not found".into()));
            }
            eprintln!("[ACCESS] hash={} metadata=None allowed (admin bypass)", hash);
        }
    }

    // Get range header for partial content
    let range = req
        .get_header(header::RANGE)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Serve from the FOS mirror when it has the object, otherwise GCS (with
    // CDN fallback) and lazily copy the object into the mirror.
    let result = download_blob_read_through(
        &hash,
        range.as_deref(),
        metadata.as_ref().map(|meta| meta.size),
    )?;
    let diagnostics = result.diagnostics;
    let mut resp = result.response;
    if let Some(diagnostics) = diagnostics {
        request_log::attach_blob_phases(
            &mut resp,
            diagnostics,
            authorization_present,
            probe_id.as_deref(),
        );
    }

    // Surface provenance metadata if present on the origin object. GCS returns
    // custom metadata as `x-goog-meta-*`; S3-compatible mirrors return the same
    // values as `x-amz-meta-*`, so accept either spelling.
    let c2pa_manifest_id = resp
        .get_header_str("x-goog-meta-c2pa-manifest-id")
        .or_else(|| resp.get_header_str("x-amz-meta-c2pa-manifest-id"))
        .map(|s| s.to_string());
    let source_sha256 = resp
        .get_header_str("x-goog-meta-source-sha256")
        .or_else(|| resp.get_header_str("x-amz-meta-source-sha256"))
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

    // Active content is addressed by SHA256 hash, so it's immutable - cache aggressively.
    // Pending blobs are public while moderation runs, but keep browser caches revocable.
    if is_admin {
        // Admin bypass: never cache, expose moderation status
        add_private_cache_headers(&mut resp, &hash);
        if let Some(ref meta) = metadata {
            resp.set_header("X-Moderation-Status", format!("{:?}", meta.status));
        }
    } else {
        add_blob_response_cache_headers(&mut resp, &hash, metadata.as_ref().map(|m| m.status));
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
        let thumb_hash = thumbnail_key.trim_end_matches(".jpg");

        // HEAD has no auth context — apply non-owner access rules.
        let meta = match get_blob_metadata(thumb_hash)? {
            Some(meta) => meta,
            None => return Err(BlossomError::NotFound("Blob not found".into())),
        };
        match meta.access_for(None, false) {
            BlobAccess::Allowed => {}
            BlobAccess::NotFound => {
                return Err(BlossomError::NotFound("Blob not found".into()));
            }
            BlobAccess::AgeGated => {
                return Err(BlossomError::AuthRequired("age_restricted".into()));
            }
        }

        let resp = match download_thumbnail(&thumbnail_key) {
            Ok(resp) => resp,
            Err(BlossomError::NotFound(_)) => generate_thumbnail_on_demand(thumb_hash)?,
            Err(e) => return Err(e),
        };
        let content_length = resp
            .get_header_str("x-goog-stored-content-length")
            .or_else(|| resp.get_header_str("content-length"))
            .unwrap_or("0")
            .to_string();
        let mut head_resp = Response::from_status(StatusCode::OK);
        head_resp.set_header("Content-Type", "image/jpeg");
        head_resp.set_header("Content-Length", &content_length);
        add_blob_response_cache_headers(&mut head_resp, thumb_hash, Some(meta.status));
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
    add_blob_response_cache_headers(&mut resp, &hash, Some(metadata.status));
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
            if is_admin || status_requires_private_response(meta.status) {
                add_private_cache_headers(&mut resp, &hash);
            } else {
                add_derivative_cache_headers(&mut resp, &hash);
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
            add_derivative_cache_headers(&mut resp, &hash);
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

    // Propagate KV errors instead of swallowing them as "no metadata, allow":
    // a transient KV failure must fail closed so we don't leak HLS variants
    // for moderated/vanished blobs.
    match get_blob_metadata(&hash)? {
        Some(ref meta) => {
            let (requester_pk, auth_diagnostics) = media_viewer_context(&req, "hls_content")?;
            match meta.access_for(requester_pk.as_deref(), is_admin) {
                BlobAccess::Allowed => {
                    log_media_outcome("hls_content", &auth_diagnostics, "allowed");
                    if status_requires_private_response(meta.status) {
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
        None => {
            // Metadata may be missing because vanish/soft-delete removed it while
            // GCS bytes survive. Mirror handle_get_blob: 404 for non-admin, log
            // and allow admin so the moderation proxy can preview orphaned bytes.
            if !is_admin {
                eprintln!(
                    "[ACCESS] hash={} metadata=None denied (no metadata, non-admin, hls_content)",
                    hash
                );
                return Err(BlossomError::NotFound("Content not found".into()));
            }
            eprintln!(
                "[ACCESS] hash={} metadata=None allowed (admin bypass, hls_content)",
                hash
            );
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
            // Admin bypass responses stay private, mirroring handle_get_blob
            // and the HLS master route.
            if is_admin || is_restricted {
                add_private_cache_headers(&mut resp, &hash);
            } else {
                add_derivative_cache_headers(&mut resp, &hash);
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
    let metadata = get_blob_metadata(&hash_lower)?
        .ok_or_else(|| BlossomError::NotFound("Content not found".into()))?;
    match metadata.access_for(None, false) {
        BlobAccess::Allowed => {}
        BlobAccess::NotFound => {
            return Err(BlossomError::NotFound("Content not found".into()));
        }
        BlobAccess::AgeGated => {
            return Err(BlossomError::AuthRequired("age_restricted".into()));
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
            add_derivative_cache_headers(&mut resp, &hash_lower);
            resp.set_header("X-Sha256", &hash_lower);
            add_cors_headers(&mut resp);
            Ok(resp)
        }
        Err(BlossomError::NotFound(_)) if filename == "master.m3u8" => {
            match decide_transcode_fetch_action(
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
                    &hash_lower,
                    metadata.transcode_error_code.as_deref(),
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

fn edge_transcript_metadata_update(status: TranscriptStatus) -> TranscriptMetadataUpdate {
    TranscriptMetadataUpdate {
        generation: crate::metadata::edge_transcript_status_generation(status),
        ..TranscriptMetadataUpdate::default()
    }
}

fn edge_transcript_metadata_update_now(status: TranscriptStatus) -> TranscriptMetadataUpdate {
    TranscriptMetadataUpdate {
        last_attempt_at: Some(current_timestamp()),
        ..edge_transcript_metadata_update(status)
    }
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
    generation: Option<u64>,
    malformed_generation: bool,
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
    generation: Option<u64>,
    malformed_generation: bool,
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

fn parse_generation_field(payload: &serde_json::Value) -> (Option<u64>, bool) {
    match payload.get("generation") {
        None | Some(serde_json::Value::Null) => (None, false),
        Some(value) => match value.as_u64() {
            Some(generation) => (Some(generation), false),
            None => (None, true),
        },
    }
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

    let (generation, malformed_generation) = parse_generation_field(payload);

    Ok(ParsedTranscodeStatusWebhook {
        sha256,
        status,
        new_size: payload["new_size"].as_u64(),
        dim,
        error_code: payload["error_code"].as_str().map(|s| s.to_string()),
        error_message: payload["error_message"].as_str().map(|s| s.to_string()),
        retry_after_epoch_secs: parse_optional_retry_after_epoch(payload, now_epoch_secs),
        terminal: parse_optional_bool(payload, "terminal").unwrap_or(false),
        generation,
        malformed_generation,
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

    let (generation, malformed_generation) = parse_generation_field(payload);

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
        generation,
        malformed_generation,
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
                    edge_transcript_metadata_update_now(TranscriptStatus::Complete),
                );
            }
            resp.set_header("Content-Type", "text/vtt; charset=utf-8");
            if is_admin || status_requires_private_response(metadata.status) {
                add_private_cache_headers(&mut resp, &hash);
            } else {
                add_derivative_cache_headers(&mut resp, hash);
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
                        edge_transcript_metadata_update_now(TranscriptStatus::Processing),
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
                    edge_transcript_metadata_update_now(TranscriptStatus::Complete),
                );
            }
            let mut resp = Response::from_status(StatusCode::OK);
            resp.set_header("Content-Type", "text/vtt; charset=utf-8");
            add_derivative_cache_headers(&mut resp, hash);
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
        edge_transcript_metadata_update_now(TranscriptStatus::Processing),
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
    match get_blob_metadata(&hash)? {
        Some(meta) => {
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
        None => {
            if !is_admin {
                eprintln!("[ACCESS] subtitle hash={} metadata=None denied (non-admin)", hash);
                return Err(BlossomError::NotFound("Video hash not found".into()));
            }
            eprintln!("[ACCESS] subtitle hash={} metadata=None allowed (admin bypass)", hash);
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

    // Admin responses stay private; otherwise the source video's moderation
    // status drives the policy (Pending source => revocable public caching).
    let audio_cache_policy = if is_admin {
        BlobCachePolicy::PrivateNoStore
    } else {
        blob_cache_policy(metadata.status)
    };

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
                audio_cache_policy,
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
        transcode_generation: None,
        dim: None,
        transcript_status: None,
        transcript_error_code: None,
        transcript_error_message: None,
        transcript_last_attempt_at: None,
        transcript_retry_after: None,
        transcript_attempt_count: 0,
        transcript_terminal: false,
        transcript_generation: None,
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
    add_audio_response_headers(
        &mut resp,
        &hash,
        audio_cache_policy,
        &mime_type,
        size,
        duration,
    );
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
                blob_cache_policy(metadata.status),
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
            if is_admin || status_requires_private_response(meta.status) {
                add_private_cache_headers(&mut resp, &hash);
            } else {
                add_derivative_cache_headers(&mut resp, &hash);
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
    // Non-owner gating above means a 200 here is always public content, so the
    // same derivative policy as GET applies: repairable renditions must not be
    // pinned immutable in browser caches.
    add_derivative_cache_headers(&mut resp, &hash);
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
            add_private_cache_headers(&mut resp, &hash);
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
            add_private_cache_headers(&mut resp, &hash);
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
        status if status == StatusCode::from_u16(422).unwrap() => {
            Err(BlossomError::UnprocessableEntity(
                "Thumbnail cannot be generated for this video".into(),
            ))
        }
        StatusCode::SERVICE_UNAVAILABLE => Err(BlossomError::StorageError(
            "Thumbnail generation is busy".into(),
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
        use crate::metadata::update_transcript_status;
        update_transcript_status(
            hash,
            crate::blossom::TranscriptStatus::Complete,
            edge_transcript_metadata_update(crate::blossom::TranscriptStatus::Complete),
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
                    edge_transcript_metadata_update_now(TranscriptStatus::Processing),
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
fn handle_upload(mut req: Request, record: &mut UploadLogRecord) -> Result<Response> {
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
        return handle_upload_service_proxy(
            req,
            auth,
            content_type,
            content_length,
            base_url,
            record,
        );
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
        transcode_generation: None,
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
        transcript_generation: None,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DerivativeObservation {
    Unavailable,
    Evaluated,
}

#[derive(Debug, Clone)]
struct UploadServicePublishedUpload {
    sha256: String,
    size: u64,
    content_type: String,
    thumbnail_url: Option<String>,
    dim: Option<String>,
    transcode_observation: DerivativeObservation,
    transcode_error_code: Option<String>,
    transcode_error_message: Option<String>,
    transcode_terminal: bool,
    transcript_observation: DerivativeObservation,
    transcript_error_code: Option<String>,
    transcript_error_message: Option<String>,
    transcript_terminal: bool,
}

fn trusted_upload_service_terminal_derivative_error(
    error_code: Option<&str>,
    upload_service_terminal: bool,
) -> bool {
    upload_service_terminal
        && matches!(
            error_code,
            // Do not include invalid_media here. The upload service currently
            // uses that broad code for sanitize/probe failures that can be
            // recoverable by the transcoder's full re-encode path.
            Some("unsupported_media_type")
        )
}

fn parse_upload_service_response(
    resp: &serde_json::Value,
    content_type: &str,
    fallback_size: u64,
) -> Result<UploadServicePublishedUpload> {
    let video_derivatives_evaluated = is_video_mime_type(content_type);
    let transcode_error_code = resp["transcode_error_code"].as_str().map(|v| v.to_string());
    let transcript_error_code = resp["transcript_error_code"]
        .as_str()
        .map(|v| v.to_string());
    let transcode_terminal = trusted_upload_service_terminal_derivative_error(
        transcode_error_code.as_deref(),
        resp["transcode_terminal"].as_bool().unwrap_or(false),
    );
    let transcript_terminal = trusted_upload_service_terminal_derivative_error(
        transcript_error_code.as_deref(),
        resp["transcript_terminal"].as_bool().unwrap_or(false),
    );

    Ok(UploadServicePublishedUpload {
        sha256: resp["sha256"]
            .as_str()
            .ok_or_else(|| BlossomError::Internal("Missing sha256 in Cloud Run response".into()))?
            .to_string(),
        size: resp["size"].as_u64().unwrap_or(fallback_size),
        content_type: content_type.to_string(),
        thumbnail_url: resp["thumbnail_url"].as_str().map(|v| v.to_string()),
        dim: resp["dim"].as_str().map(|v| v.to_string()),
        transcode_observation: if video_derivatives_evaluated {
            DerivativeObservation::Evaluated
        } else {
            DerivativeObservation::Unavailable
        },
        transcode_error_code,
        transcode_error_message: resp["transcode_error_message"]
            .as_str()
            .map(|v| v.to_string()),
        transcode_terminal,
        transcript_observation: if video_derivatives_evaluated {
            DerivativeObservation::Evaluated
        } else {
            DerivativeObservation::Unavailable
        },
        transcript_error_code,
        transcript_error_message: resp["transcript_error_message"]
            .as_str()
            .map(|v| v.to_string()),
        transcript_terminal,
    })
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

fn should_record_upload_service_transcode_failure(
    current_status: Option<TranscodeStatus>,
    incoming_error_code: Option<&str>,
) -> bool {
    // Never stomp a derivative that is already Complete, and never interrupt one
    // that is currently Processing — the in-flight run's webhook is authoritative.
    incoming_error_code.is_some()
        && !matches!(
            current_status,
            Some(TranscodeStatus::Complete) | Some(TranscodeStatus::Processing)
        )
}

fn should_reset_transcode_failure_on_clean_upload(
    mime_type: &str,
    current_status: Option<TranscodeStatus>,
    observation: DerivativeObservation,
    incoming_error_code: Option<&str>,
) -> bool {
    observation == DerivativeObservation::Evaluated
        && incoming_error_code.is_none()
        && is_video_mime_type(mime_type)
        && matches!(current_status, None | Some(TranscodeStatus::Failed))
}

fn should_record_upload_service_transcript_failure(
    current_status: Option<TranscriptStatus>,
    incoming_error_code: Option<&str>,
) -> bool {
    // Never stomp a derivative that is already Complete, and never interrupt one
    // that is currently Processing — the in-flight run's webhook is authoritative.
    incoming_error_code.is_some()
        && !matches!(
            current_status,
            Some(TranscriptStatus::Complete) | Some(TranscriptStatus::Processing)
        )
}

fn should_reset_transcript_failure_on_clean_upload(
    mime_type: &str,
    current_status: Option<TranscriptStatus>,
    observation: DerivativeObservation,
    incoming_error_code: Option<&str>,
) -> bool {
    observation == DerivativeObservation::Evaluated
        && incoming_error_code.is_none()
        && is_transcribable_mime_type(mime_type)
        && matches!(current_status, None | Some(TranscriptStatus::Failed))
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

    let transcode_error_code = upload.transcode_error_code.clone();
    let transcode_error_message = upload.transcode_error_message.clone();
    let transcode_terminal = upload.transcode_terminal;
    let transcript_error_code = upload.transcript_error_code.clone();
    let transcript_error_message = upload.transcript_error_message.clone();
    let transcript_terminal = upload.transcript_terminal;
    let has_transcode_error = transcode_error_code.is_some();
    let has_transcript_error = transcript_error_code.is_some();
    let derivative_failure_recorded_at: Option<String> =
        if has_transcode_error || has_transcript_error {
            Some(current_timestamp())
        } else {
            None
        };

    // Read authoritative metadata before updating the full record.
    if let Some(mut metadata) = get_blob_metadata_uncached(&hash)? {
        let _ = add_to_user_list(&auth.pubkey, &hash);
        let _ = add_to_blob_refs(&hash, &auth.pubkey);

        if thumbnail_url.is_some() && metadata.thumbnail.is_none() {
            metadata.thumbnail = thumbnail_url.clone();
        }
        // Even for dedupe, update dim if we got it and it wasn't set before
        if dim.is_some() && metadata.dim.is_none() {
            metadata.dim = dim.clone();
        }
        if should_record_upload_service_transcode_failure(
            metadata.transcode_status,
            transcode_error_code.as_deref(),
        ) {
            let error_code = transcode_error_code.as_ref().unwrap();
            metadata.transcode_status = Some(TranscodeStatus::Failed);
            metadata.transcode_error_code = Some(error_code.clone());
            metadata.transcode_error_message = transcode_error_message.clone();
            metadata.transcode_last_attempt_at = derivative_failure_recorded_at.clone();
            metadata.transcode_retry_after = None;
            metadata.transcode_attempt_count = metadata.transcode_attempt_count.max(1);
            // A previously recorded terminal verdict (e.g. from the transcoder
            // webhook) stays terminal — a reupload of the same bytes is not
            // evidence that the media became transcodable.
            metadata.transcode_terminal = metadata.transcode_terminal || transcode_terminal;
        } else if should_reset_transcode_failure_on_clean_upload(
            &metadata.mime_type,
            metadata.transcode_status,
            upload.transcode_observation,
            transcode_error_code.as_deref(),
        ) {
            metadata.transcode_status = Some(TranscodeStatus::Pending);
            metadata.transcode_error_code = None;
            metadata.transcode_error_message = None;
            metadata.transcode_last_attempt_at = None;
            metadata.transcode_retry_after = None;
            metadata.transcode_attempt_count = 0;
            metadata.transcode_terminal = false;
        }
        if should_record_upload_service_transcript_failure(
            metadata.transcript_status,
            transcript_error_code.as_deref(),
        ) {
            let error_code = transcript_error_code.as_ref().unwrap();
            metadata.transcript_status = Some(TranscriptStatus::Failed);
            metadata.transcript_error_code = Some(error_code.clone());
            metadata.transcript_error_message = transcript_error_message.clone();
            metadata.transcript_last_attempt_at = derivative_failure_recorded_at.clone();
            metadata.transcript_retry_after = None;
            metadata.transcript_attempt_count = metadata.transcript_attempt_count.max(1);
            // See transcode note above: an existing terminal verdict is sticky.
            metadata.transcript_terminal = metadata.transcript_terminal || transcript_terminal;
        } else if should_reset_transcript_failure_on_clean_upload(
            &metadata.mime_type,
            metadata.transcript_status,
            upload.transcript_observation,
            transcript_error_code.as_deref(),
        ) {
            metadata.transcript_status = Some(TranscriptStatus::Pending);
            metadata.transcript_error_code = None;
            metadata.transcript_error_message = None;
            metadata.transcript_last_attempt_at = None;
            metadata.transcript_retry_after = None;
            metadata.transcript_attempt_count = 0;
            metadata.transcript_terminal = false;
        }
        put_blob_metadata(&metadata)?;
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
        transcode_generation: None,
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
        transcript_generation: None,
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

fn handle_upload_init(mut req: Request, record: &mut UploadLogRecord) -> Result<Response> {
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

    // Overwrite the header-derived values: on this route the request body is a
    // small JSON control message, so its own Content-Length says nothing useful.
    // The declared upload size is what makes init lines comparable to direct_put.
    record.content_length = Some(init_request.size);
    record.content_type = Some(init_request.content_type.clone());

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
    proxy_req.set_header(upload_log::CORRELATION_HEADER, &record.req_id);
    proxy_req.set_body(body);

    let mut proxy_resp = send_to_upload_service(proxy_req, record)?;
    if !proxy_resp.get_status().is_success() {
        let status = proxy_resp.get_status();
        let body = proxy_resp.take_body().into_string();
        return Err(map_upload_service_error(status, &body));
    }

    let response_body = proxy_resp.take_body().into_string();
    let init_response: ResumableUploadInitResponse = serde_json::from_str(&response_body)
        .map_err(|e| {
            BlossomError::Internal(format!("Invalid upload service init response: {}", e))
        })?;

    let mut resp = json_response(StatusCode::OK, &init_response);
    add_upload_capability_headers(&mut resp, &control_host);
    add_cors_headers(&mut resp);
    Ok(resp)
}

fn upload_from_resumable_completion(
    response: ResumableUploadCompleteResponse,
) -> UploadServicePublishedUpload {
    UploadServicePublishedUpload {
        sha256: response.sha256,
        size: response.size,
        content_type: response.content_type,
        thumbnail_url: response.thumbnail_url,
        dim: response.dim,
        // TODO(#151): resumable completion does not probe/classify invalid media
        // yet, so derivative observations and failure fields are unavailable.
        transcode_observation: DerivativeObservation::Unavailable,
        transcode_error_code: None,
        transcode_error_message: None,
        transcode_terminal: false,
        transcript_observation: DerivativeObservation::Unavailable,
        transcript_error_code: None,
        transcript_error_message: None,
        transcript_terminal: false,
    }
}

fn handle_upload_complete(
    mut req: Request,
    path: &str,
    record: &mut UploadLogRecord,
) -> Result<Response> {
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
    proxy_req.set_header(upload_log::CORRELATION_HEADER, &record.req_id);
    if expected_request_hash.is_some() {
        proxy_req.set_header(header::CONTENT_TYPE, "application/json");
        proxy_req.set_header(header::CONTENT_LENGTH, request_body.len().to_string());
        proxy_req.set_body(request_body);
    }

    let mut proxy_resp = send_to_upload_service(proxy_req, record)?;
    if !proxy_resp.get_status().is_success() {
        let status = proxy_resp.get_status();
        let body = proxy_resp.take_body().into_string();
        return Err(map_upload_service_error(status, &body));
    }

    let response_body = proxy_resp.take_body().into_string();
    let complete_response: ResumableUploadCompleteResponse = serde_json::from_str(&response_body)
        .map_err(|e| {
        BlossomError::Internal(format!("Invalid upload service completion response: {}", e))
    })?;

    if let Some(ref request_hash) = expected_request_hash {
        if request_hash.to_lowercase() != complete_response.sha256.to_lowercase() {
            return Err(BlossomError::Conflict(
                "Completion response hash did not match requested hash".into(),
            ));
        }
    }

    // The request body is a small control message; log the completed upload's
    // declared media size and type so completion rows match init rows.
    record.content_length = Some(complete_response.size);
    record.content_type = Some(complete_response.content_type.clone());

    publish_upload_service_upload(
        auth,
        base_url,
        upload_from_resumable_completion(complete_response),
    )
}

/// Per-pubkey and per-IP fixed-window throttle for the transcription proxy.
///
/// Returns `Some(429)` when either limit is exceeded, `None` to let the request
/// through. Best-effort: if the KV store is unavailable the request is allowed
/// — the transcoder's in-flight semaphore is the hard backstop. The per-pubkey
/// charge is applied only after the event validates against the transcription
/// authorization contract (`validate_transcribe_event`), so a forged or
/// replayed token can't burn a victim's budget; the upload service still does
/// full validation downstream.
fn enforce_transcribe_rate_limit(req: &Request, auth_header: &str) -> Option<Response> {
    let store = KVStore::open("blossom_metadata").ok().flatten()?;
    let counter = rate_limit::KvCounterStore(&store);
    let now = unix_timestamp_secs();

    // IP first: always trustworthy (it's the connection source) and cheap, so a
    // flood is throttled before we spend a signature verification on the
    // forgeable pubkey below.
    if let Some(ip) = req.get_client_ip_addr().map(|ip| ip.to_string()) {
        let cfg = rate_limit::RateLimit::new(rate_limit::IP_LIMIT, rate_limit::IP_WINDOW_SECS);
        if let Some(retry_after) = rate_limit::enforce(&counter, "ip", &ip, cfg, now) {
            return Some(too_many_requests(retry_after));
        }
    }

    // Pubkey only after the event satisfies the transcription authorization
    // contract (kind 24242, exact `t=media`, required unexpired expiration,
    // Divine-scoped `server` tag, valid signature) — the same contract the
    // upload service enforces. Charging an event it would reject burns a
    // signer's budget on a doomed request, and a signature-only check would
    // even let a replayed `t=get` token charge a victim. `parse_auth_header`
    // decodes attacker-controlled JSON, so the pubkey is untrusted until then.
    if let Some(pubkey) = crate::viewer_auth::transcribe_charge_pubkey(auth_header, now) {
        let cfg =
            rate_limit::RateLimit::new(rate_limit::PUBKEY_LIMIT, rate_limit::PUBKEY_WINDOW_SECS);
        if let Some(retry_after) = rate_limit::enforce(&counter, "pk", &pubkey, cfg, now) {
            return Some(too_many_requests(retry_after));
        }
    }

    None
}

fn too_many_requests(retry_after_secs: u64) -> Response {
    let mut resp = Response::from_status(StatusCode::TOO_MANY_REQUESTS)
        .with_header(header::RETRY_AFTER, retry_after_secs.to_string())
        .with_header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .with_body("Rate limit exceeded for transcription. Try again shortly.\n");
    add_cors_headers(&mut resp);
    resp
}

/// POST /transcribe — thin forward to the upload service's authenticated
/// transcription proxy (`upload.divine.video/transcribe`), which validates the
/// Blossom auth and calls the transcoder. The mobile editor only addresses this
/// edge host, so transcription has to enter here.
///
/// The body (audio) is streamed straight through — Fastly Compute has a ~5 MB
/// WASM memory limit, so we never buffer it. Auth is passed through unchanged;
/// the upload service is the authority that validates it (`t=media`). A
/// per-pubkey and per-IP fixed-window rate limit is applied here first, since
/// the edge sees the request before the expensive transcoder work begins.
fn handle_transcribe_proxy(mut req: Request) -> Result<Response> {
    let auth_header = extract_authorization_header(&req)?;

    if let Some(limited) = enforce_transcribe_rate_limit(&req, &auth_header) {
        return Ok(limited);
    }

    let content_type = req
        .get_header(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("audio/wav")
        .to_string();
    let query = req.get_query_str().map(str::to_string);
    let body = req.take_body();

    let mut url = format!("https://{}/transcribe", UPLOAD_SERVICE_HOST);
    if let Some(query) = query.filter(|q| !q.is_empty()) {
        url.push('?');
        url.push_str(&query);
    }

    let mut proxy_req = Request::new(Method::POST, &url);
    proxy_req.set_header("Host", UPLOAD_SERVICE_HOST);
    proxy_req.set_header(header::AUTHORIZATION, &auth_header);
    proxy_req.set_header(header::CONTENT_TYPE, &content_type);
    proxy_req.set_body(body);

    let mut proxy_resp = proxy_req
        .send(UPLOAD_SERVICE_BACKEND)
        .map_err(|e| BlossomError::Internal(format!("Failed to proxy transcription: {}", e)))?;

    // Return the upstream response as-is — its status and every header
    // (Content-Type, and a future 429's `Retry-After`) — then add CORS.
    // Reconstructing the response would silently drop those headers.
    add_cors_headers(&mut proxy_resp);
    Ok(proxy_resp)
}

/// Handle large uploads by proxying to the upload service
/// Fastly Compute has WASM memory limits (~5MB), so large files must be proxied
fn handle_upload_service_proxy(
    mut req: Request,
    auth: crate::blossom::BlossomAuthEvent,
    content_type: String,
    content_length: u64,
    base_url: String,
    record: &mut UploadLogRecord,
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
    proxy_req.set_header(upload_log::CORRELATION_HEADER, &record.req_id);
    proxy_req.set_body(body);
    record.proxied_body = true;

    let mut proxy_resp = send_to_upload_service(proxy_req, record)?;

    // Check for errors from the upload service
    if !proxy_resp.get_status().is_success() {
        let status = proxy_resp.get_status();
        let body = proxy_resp.take_body().into_string();
        return Err(map_upload_service_error(status, &body));
    }

    // Parse Cloud Run response to get the hash
    let resp_body = proxy_resp.take_body().into_string();
    let cloud_run_resp: serde_json::Value = serde_json::from_str(&resp_body)
        .map_err(|e| BlossomError::Internal(format!("Invalid Cloud Run response: {}", e)))?;
    let upload = parse_upload_service_response(&cloud_run_resp, &content_type, content_length)?;

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

/// Delete and verify the main GCS object plus every thumbnail, HLS, VTT, and prefix artifact.
fn local_derivative_cleanup_result(
    local_mode: bool,
    deterministic_failures: &[String],
) -> Option<Result<()>> {
    if !local_mode {
        return None;
    }
    Some(if deterministic_failures.is_empty() {
        Ok(())
    } else {
        Err(BlossomError::StorageError(format!(
            "{} required local derivative cleanup operation(s) failed: {}",
            deterministic_failures.len(),
            deterministic_failures.join("; ")
        )))
    })
}

pub(crate) fn delete_blob_gcs_artifacts(hash: &str) -> Result<()> {
    let paths = [
        format!("{}.jpg", hash),
        format!("{}/hls/master.m3u8", hash),
        format!("{}/hls/stream_720p.m3u8", hash),
        format!("{}/hls/stream_720p.ts", hash),
        format!("{}/hls/stream_480p.m3u8", hash),
        format!("{}/hls/stream_480p.ts", hash),
        format!("{}/hls/stream_720p.mp4", hash),
        format!("{}/hls/stream_480p.mp4", hash),
        format!("{}/vtt/main.vtt", hash),
    ];
    let mut deterministic_failures = Vec::new();
    for path in &paths {
        if let Err(error) = storage_delete(path) {
            deterministic_failures.push(format!("{}: {}", path, error));
        }
    }

    if let Some(result) = local_derivative_cleanup_result(
        crate::storage::is_local_mode(),
        &deterministic_failures,
    ) {
        return result;
    }

    match trigger_cloud_run_delete_blob(hash) {
        Ok(()) => Ok(()),
        Err(cloud_error) => {
            deterministic_failures.push(format!("prefix cleanup: {}", cloud_error));
            Err(BlossomError::StorageError(format!(
                "{} required derivative cleanup operation(s) failed: {}",
                deterministic_failures.len(),
                deterministic_failures.join("; ")
            )))
        }
    }
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

const VANISH_BATCH_SIZE: usize = 10;
const VANISH_STORAGE_ATTEMPTS: u8 = 2;
const _: () = assert!(VANISH_BATCH_SIZE * 2 <= storage::CLOUD_RUN_DELETE_BATCH_LIMIT);

#[derive(Debug)]
struct VanishExecution {
    fully_deleted: u32,
    unlinked: u32,
    errors: u32,
    malformed_hash_exceptions: u32,
    pending: u32,
    finalized: bool,
}

impl VanishExecution {
    fn vanished(&self) -> bool {
        self.finalized && self.errors == 0 && self.pending == 0
    }
}

fn select_vanish_batch(hashes: &[String]) -> (Vec<String>, Vec<String>, u32) {
    let (valid, malformed) = hashes
        .iter()
        .take(VANISH_BATCH_SIZE)
        .partition::<Vec<_>, _>(|hash| validate_sha256_format(hash).is_ok());
    let valid = valid.into_iter().map(|hash| hash.to_lowercase()).collect();
    let malformed = malformed.into_iter().cloned().collect();
    let pending = hashes
        .len()
        .saturating_sub(VANISH_BATCH_SIZE)
        .min(u32::MAX as usize) as u32;
    (valid, malformed, pending)
}

fn record_malformed_vanish_hash(hash: &str, pubkey: &str) {
    let fingerprint = hex::encode(Sha256::digest(hash.as_bytes()));
    write_audit_log(
        &fingerprint,
        "vanish_malformed_hash_exception",
        pubkey,
        None,
        None,
        Some("Malformed blob-list entry skipped; sha256 is a fingerprint of the invalid value"),
    );
    eprintln!(
        "[VANISH] pubkey={} skipped malformed blob-list entry fingerprint={}",
        pubkey, fingerprint
    );
}

fn increment_vanish_outcome(execution: &mut VanishExecution, outcome: VanishBlobOutcome) {
    match outcome {
        VanishBlobOutcome::FullyDeleted => execution.fully_deleted += 1,
        VanishBlobOutcome::Unlinked => execution.unlinked += 1,
    }
}

/// Execute one bounded account-erasure batch.
fn execute_vanish(pubkey: &str) -> VanishExecution {
    let started = Instant::now();
    let mut execution = VanishExecution {
        fully_deleted: 0,
        unlinked: 0,
        errors: 0,
        malformed_hash_exceptions: 0,
        pending: 0,
        finalized: false,
    };
    let hashes = match get_user_blobs(pubkey) {
        Ok(hashes) => hashes,
        Err(error) => {
            eprintln!(
                "[VANISH] pubkey={} failed to get user blobs: {}",
                pubkey, error
            );
            execution.errors = 1;
            return execution;
        }
    };
    let (selected, malformed, pending) = select_vanish_batch(&hashes);
    execution.pending = pending;

    let prepare_started = Instant::now();
    let mut erase = Vec::new();
    let mut retry_hashes = Vec::new();
    for hash in &malformed {
        record_malformed_vanish_hash(hash, pubkey);
        if let Err(error) = remove_from_user_list(pubkey, hash) {
            eprintln!(
                "[VANISH] pubkey={} failed to remove malformed blob-list entry: {}",
                pubkey, error
            );
            execution.errors += 1;
            retry_hashes.push(hash.clone());
        } else {
            execution.malformed_hash_exceptions += 1;
        }
    }
    for hash in &selected {
        match prepare_vanish_blob_with_ops(hash, pubkey, &DefaultCreatorDeleteOps) {
            Ok(PreparedVanishBlobOrOutcome::Erase(blob)) => erase.push(*blob),
            Ok(PreparedVanishBlobOrOutcome::Completed(outcome)) => {
                increment_vanish_outcome(&mut execution, outcome);
            }
            Err(error) => {
                eprintln!(
                    "[VANISH] pubkey={} hash={} failed to prepare blob: {}",
                    pubkey, hash, error
                );
                execution.errors += 1;
                retry_hashes.push(hash.clone());
            }
        }
    }
    let prepare_ms = prepare_started.elapsed().as_millis();

    let mut cleanup_ready = Vec::with_capacity(erase.len());
    let mut derived_cleanup = Vec::new();
    for blob in erase {
        match prepare_derived_audio_cleanup(&blob.hash) {
            Ok(plan) => {
                if let Some(plan) = plan {
                    derived_cleanup.push(plan);
                }
                cleanup_ready.push(blob);
            }
            Err(error) => {
                eprintln!(
                    "[VANISH] pubkey={} hash={} failed to clean up derived audio: {}",
                    pubkey, blob.hash, error
                );
                execution.errors += 1;
                retry_hashes.push(blob.hash);
            }
        }
    }
    let erase = cleanup_ready;
    let mut erase_hashes: Vec<String> = erase.iter().map(|blob| blob.hash.clone()).collect();
    erase_hashes.extend(derived_cleanup.iter().map(|plan| plan.audio_hash.clone()));
    erase_hashes.sort();
    erase_hashes.dedup();
    let mut storage_result = erase_vanish_batch(&erase_hashes);
    let mut storage_attempts = u8::from(!erase_hashes.is_empty());
    while storage_attempts < VANISH_STORAGE_ATTEMPTS && !storage_result.failed_hashes.is_empty() {
        let storage_retry_hashes: Vec<String> =
            storage_result.failed_hashes.iter().cloned().collect();
        let retry = erase_vanish_batch(&storage_retry_hashes);
        storage_result.replace_failures_after_retry(retry);
        storage_attempts += 1;
    }
    let finalize_started = Instant::now();
    let mut failed_derived_sources = HashSet::new();
    for plan in &derived_cleanup {
        if storage_result.failed_hashes.contains(&plan.audio_hash) {
            failed_derived_sources.insert(plan.source_hash.clone());
            continue;
        }
        if let Err(error) = finalize_derived_audio_cleanup(plan) {
            eprintln!(
                "[VANISH] pubkey={} hash={} failed to finalize derived audio: {}",
                pubkey, plan.source_hash, error
            );
            failed_derived_sources.insert(plan.source_hash.clone());
        }
    }
    for blob in &erase {
        if storage_result.failed_hashes.contains(&blob.hash)
            || failed_derived_sources.contains(&blob.hash)
        {
            eprintln!(
                "[VANISH] pubkey={} hash={} required storage erasure failed after {} attempts",
                pubkey, blob.hash, storage_attempts
            );
            execution.errors += 1;
            retry_hashes.push(blob.hash.clone());
            continue;
        }
        match finalize_erased_vanish_blob_with_ops(blob, pubkey, &DefaultCreatorDeleteOps) {
            Ok(()) => increment_vanish_outcome(&mut execution, VanishBlobOutcome::FullyDeleted),
            Err(error) => {
                eprintln!(
                    "[VANISH] pubkey={} hash={} failed to finalize erased blob: {}",
                    pubkey, blob.hash, error
                );
                execution.errors += 1;
                retry_hashes.push(blob.hash.clone());
            }
        }
    }
    let kv_finalize_ms = finalize_started.elapsed().as_millis();

    if let Err(error) = move_user_list_entries_to_end(pubkey, &retry_hashes) {
        eprintln!(
            "[VANISH] pubkey={} failed to rotate retry entries: {}",
            pubkey, error
        );
    }

    if execution.pending == 0 && execution.errors == 0 {
        if let Err(error) = delete_user_list(pubkey) {
            eprintln!(
                "[VANISH] pubkey={} failed to delete user list: {}",
                pubkey, error
            );
            execution.errors += 1;
        } else if let Err(error) = remove_from_user_index(pubkey) {
            eprintln!(
                "[VANISH] pubkey={} failed to remove account from user index: {}",
                pubkey, error
            );
            execution.errors += 1;
        } else {
            execution.finalized = true;
        }
    }

    let timing = serde_json::json!({
        "selected": selected.len(),
        "erase_candidates": erase.len(),
        "storage_attempts": storage_attempts,
        "fully_deleted": execution.fully_deleted,
        "unlinked": execution.unlinked,
        "errors": execution.errors,
        "malformed_hash_exceptions": execution.malformed_hash_exceptions,
        "pending": execution.pending,
        "prepare_ms": prepare_ms.min(u128::from(u64::MAX)) as u64,
        "gcs_main_ms": storage_result.timings.gcs_main_ms,
        "cloud_run_cleanup_ms": storage_result.timings.cloud_run_cleanup_ms,
        "fos_main_ms": storage_result.timings.fos_main_ms,
        "purge_vcl_ms": storage_result.timings.purge_vcl_ms,
        "purge_compute_ms": storage_result.timings.purge_compute_ms,
        "kv_finalize_ms": kv_finalize_ms.min(u128::from(u64::MAX)) as u64,
        "total_ms": started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
    });
    if let Err(error) = dispatch_vanish_timing_log(&timing) {
        eprintln!(
            "[VANISH] pubkey={} failed to dispatch timing: {}",
            pubkey, error
        );
    }

    eprintln!(
        "[VANISH] pubkey={} fully_deleted={} unlinked={} errors={} malformed_hash_exceptions={} pending={} vanished={}",
        pubkey,
        execution.fully_deleted,
        execution.unlinked,
        execution.errors,
        execution.malformed_hash_exceptions,
        execution.pending,
        execution.vanished()
    );
    execution
}

fn vanish_response_status(errors: u32, pending: u32) -> StatusCode {
    if pending > 0 {
        StatusCode::ACCEPTED
    } else if errors > 0 {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::OK
    }
}

fn ensure_vanish_authorization_audit(
    pubkey: &str,
    initiator: VanishAuditInitiator,
) -> Result<VanishAuditState> {
    let mut state = match get_vanish_audit_state(pubkey, initiator.as_str())? {
        Some(state) => state,
        None => {
            let authorized_at = current_timestamp();
            let operation_id = hex::encode(Sha256::digest(
                format!(
                    "vanish-audit-operation:v1:{pubkey}:{}:{authorized_at}",
                    initiator.as_str()
                )
                .as_bytes(),
            ));
            let state = VanishAuditState::new(operation_id, authorized_at);
            put_vanish_audit_state(pubkey, initiator.as_str(), &state)?;
            state
        }
    };

    if state.needs_authorization_delivery() {
        write_vanish_audit_log(
            pubkey,
            &state.operation_id,
            &state.authorized_at,
            initiator,
            VanishAuditPhase::Authorized,
        )?;
        state.mark_authorized_delivered();
        put_vanish_audit_state(pubkey, initiator.as_str(), &state)?;
    }
    Ok(state)
}

fn complete_vanish_audit(
    pubkey: &str,
    initiator: VanishAuditInitiator,
    state: &mut VanishAuditState,
) -> Result<()> {
    let Some(claimed) = claim_vanish_audit_completion(
        pubkey,
        initiator.as_str(),
        current_timestamp(),
    )? else {
        return Ok(());
    };
    *state = claimed;
    let completed_at = state
        .completed_at
        .as_deref()
        .ok_or_else(|| BlossomError::Internal("Missing vanish completion timestamp".into()))?;
    write_vanish_audit_log(
        pubkey,
        &state.operation_id,
        completed_at,
        initiator,
        VanishAuditPhase::Completed,
    )?;
    // Retain the identity until deletion succeeds so a retry reuses the same record.
    delete_vanish_audit_state(pubkey, initiator.as_str())
}

fn complete_open_vanish_audits(
    pubkey: &str,
    initiator: VanishAuditInitiator,
    state: &mut VanishAuditState,
) -> Result<()> {
    let other = initiator.other();
    if let Some(mut other_state) = get_vanish_audit_state(pubkey, other.as_str())? {
        complete_vanish_audit(pubkey, other, &mut other_state)?;
    }
    complete_vanish_audit(pubkey, initiator, state)
}

/// DELETE /vanish - User-initiated GDPR right to erasure
fn handle_vanish(req: Request) -> Result<Response> {
    // Validate Blossom delete auth.
    let auth = validate_auth(&req, AuthAction::Delete)?;
    let initiator = VanishAuditInitiator::Account;
    let mut audit_state = ensure_vanish_authorization_audit(&auth.pubkey, initiator)?;

    let mut execution = execute_vanish(&auth.pubkey);
    if execution.vanished() {
        if let Err(error) = complete_open_vanish_audits(&auth.pubkey, initiator, &mut audit_state) {
            eprintln!(
                "[VANISH] pubkey={} failed to deliver completion audit: {}",
                auth.pubkey, error
            );
            execution.errors += 1;
        }
    }

    let result = serde_json::json!({
        "vanished": execution.vanished(),
        "pubkey": auth.pubkey,
        "fully_deleted": execution.fully_deleted,
        "unlinked": execution.unlinked,
        "errors": execution.errors,
        "malformed_hash_exceptions": execution.malformed_hash_exceptions,
        "pending": execution.pending,
    });

    let mut resp = json_response(
        vanish_response_status(execution.errors, execution.pending),
        &result,
    );
    if execution.pending > 0 {
        add_no_cache_headers(&mut resp);
    }
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

    let initiator = VanishAuditInitiator::Admin;
    let mut audit_state = ensure_vanish_authorization_audit(&pubkey, initiator)?;

    let mut execution = execute_vanish(&pubkey);
    if execution.vanished() {
        if let Err(error) = complete_open_vanish_audits(&pubkey, initiator, &mut audit_state) {
            eprintln!(
                "[VANISH] pubkey={} failed to deliver completion audit: {}",
                pubkey, error
            );
            execution.errors += 1;
        }
    }

    let result = serde_json::json!({
        "vanished": execution.vanished(),
        "pubkey": pubkey,
        "reason": reason,
        "fully_deleted": execution.fully_deleted,
        "unlinked": execution.unlinked,
        "errors": execution.errors,
        "malformed_hash_exceptions": execution.malformed_hash_exceptions,
        "pending": execution.pending,
    });

    let mut resp = json_response(
        vanish_response_status(execution.errors, execution.pending),
        &result,
    );
    if execution.pending > 0 {
        add_no_cache_headers(&mut resp);
    }
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
        transcode_generation: None,
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
        transcript_generation: None,
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
    let req_id = crate::req_id::for_request(&req);

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
                    eprintln!("[req={}] [ADMIN] Invalid webhook secret", req_id);
                    return Err(BlossomError::Forbidden("Invalid webhook secret".into()));
                }
            }
            _ => {
                eprintln!(
                    "[req={}] [ADMIN] Missing or invalid Authorization header",
                    req_id
                );
                return Err(BlossomError::AuthRequired("Webhook secret required".into()));
            }
        }
    } else {
        // Fail closed: reject requests if webhook_secret is not configured
        eprintln!(
            "[req={}] [ADMIN] webhook_secret not configured, rejecting request",
            req_id
        );
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
        "[req={}] [ADMIN] Moderation webhook: sha256={}, action={}",
        req_id, sha256, action
    );

    validate_sha256_format(sha256)?;

    // Creator-delete: thin adapter over handle_creator_delete so /admin/moderate
    // and /admin/api/moderate produce the same response contract.
    //
    // Audit strategy: write `creator_delete_attempt` before the helper call and
    // `creator_delete` after success. A failure path leaves an attempt entry
    // without a paired success, which operators can query for directly. This
    // closes the audit gap that would otherwise exist if a soft-delete
    // succeeded but the physical byte delete failed (soft-delete is durable
    // even though we propagate the error to the caller).
    if action.eq_ignore_ascii_case("DELETE") {
        let metadata = get_blob_metadata(sha256)?
            .ok_or_else(|| BlossomError::NotFound("Blob not found".into()))?;

        let reason = payload["reason"]
            .as_str()
            .unwrap_or("Creator-initiated deletion via kind 5");

        let physical_delete_enabled = config_flag_enabled("ENABLE_PHYSICAL_DELETE", false);

        let meta_json = serde_json::to_string(&metadata).ok();

        write_audit_log(
            sha256,
            "creator_delete_attempt",
            &metadata.owner,
            None,
            meta_json.as_deref(),
            Some(reason),
        );

        let outcome =
            handle_creator_delete(sha256, &metadata, reason, physical_delete_enabled, &req_id)
                .map_err(|e| {
                    eprintln!(
                        "[req={}] [CREATOR-DELETE] handle_creator_delete failed for {}: {}",
                        req_id, sha256, e
                    );
                    e
                })?;

        write_audit_log(
            sha256,
            "creator_delete",
            &metadata.owner,
            None,
            meta_json.as_deref(),
            Some(reason),
        );

        let response = build_creator_delete_response(sha256, &outcome);
        let mut resp = json_response(StatusCode::OK, &response);
        add_cors_headers(&mut resp);
        return Ok(resp);
    }

    let new_status = map_webhook_moderate_action(action)?;

    // Update blob status
    match update_blob_status(sha256, new_status) {
        Ok(()) => {
            eprintln!("[ADMIN] Updated blob {} to status {:?}", sha256, new_status);

            // Purge VCL cache so the new status takes effect immediately.
            // Banned/restricted content will 404 on next request; approved content will 200.
            purge_edge_cache(sha256);

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

fn validate_transcoder_webhook(req: &Request, label: &str) -> Result<()> {
    let Some(provided) = admin::extract_bearer_token(req) else {
        eprintln!("[{}] Missing or invalid Authorization header", label);
        return Err(BlossomError::AuthRequired("Webhook secret required".into()));
    };

    match admin::validate_bearer_token_against_secret_keys(
        &provided,
        &["webhook_secret", "transcoder_webhook_secret"],
    ) {
        Ok(()) => Ok(()),
        Err(BlossomError::Forbidden(message)) if message == "Secret store not available" => {
            eprintln!("[{}] secret store not available, rejecting request", label);
            Err(BlossomError::Forbidden("Secret store not available".into()))
        }
        Err(_) => {
            eprintln!("[{}] Invalid webhook secret", label);
            Err(BlossomError::Forbidden("Invalid webhook secret".into()))
        }
    }
}

fn config_flag_enabled(key: &str, default: bool) -> bool {
    match crate::admin::get_config(key) {
        Some(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" => true,
            "false" | "0" => false,
            _ => default,
        },
        None => default,
    }
}

fn derivative_generation_guard_enabled() -> bool {
    config_flag_enabled("REQUIRE_DERIVATIVE_STATUS_GENERATION", true)
}

fn ignored_generation_response(
    sha256: &str,
    reason: &str,
    incoming: Option<u64>,
    stored: Option<u64>,
) -> Response {
    let response = serde_json::json!({
        "success": true,
        "sha256": sha256,
        "ignored": reason,
        "incoming_generation": incoming,
        "stored_generation": stored
    });
    let mut resp = json_response(StatusCode::OK, &response);
    add_cors_headers(&mut resp);
    resp
}

fn derivative_reconciliation_response(sha256: &str, label: &str, status: &str) -> Response {
    let response = serde_json::json!({
        "success": true,
        "sha256": sha256,
        "reconciliation": "pending",
        "message": format!("{} status accepted for later reconciliation", label),
        "status": status
    });
    let mut resp = json_response(StatusCode::ACCEPTED, &response);
    add_cors_headers(&mut resp);
    resp
}

fn generation_ignore_response(
    outcome: StatusUpdateOutcome,
    sha256: &str,
    label: &str,
) -> Option<Response> {
    let (reason, incoming, stored, log_detail) = match outcome {
        StatusUpdateOutcome::Applied => return None,
        StatusUpdateOutcome::StaleGeneration { incoming, stored } => (
            "stale_generation",
            incoming,
            stored,
            format!("incoming gen {:?} < stored {:?}", incoming, stored),
        ),
        StatusUpdateOutcome::DuplicateGeneration { incoming, stored } => (
            "duplicate_generation",
            incoming,
            stored,
            format!("incoming gen {:?} == stored {:?}", incoming, stored),
        ),
        StatusUpdateOutcome::MissingGeneration { stored } => (
            "missing_generation",
            None,
            stored,
            format!("stored gen {:?}", stored),
        ),
        StatusUpdateOutcome::MalformedGeneration { stored } => (
            "malformed_generation",
            None,
            stored,
            format!("stored gen {:?}", stored),
        ),
    };
    eprintln!(
        "[{}] Ignoring {} callback for {}: {}",
        label, reason, sha256, log_detail
    );
    Some(ignored_generation_response(
        sha256, reason, incoming, stored,
    ))
}

/// POST /admin/transcode-status - Webhook from divine-transcoder service
/// Updates transcode status for a blob after HLS generation
fn handle_transcode_status(mut req: Request) -> Result<Response> {
    validate_transcoder_webhook(&req, "TRANSCODE")?;

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

    validate_sha256_format(sha256)?;

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
            generation: parsed.generation,
            require_generation_after_versioned: derivative_generation_guard_enabled(),
            malformed_generation: parsed.malformed_generation,
        },
    ) {
        Ok(outcome) => {
            if let Some(resp) = generation_ignore_response(outcome, sha256, "TRANSCODE") {
                return Ok(resp);
            }
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
                purge_edge_cache(sha256);
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
            eprintln!(
                "[TRANSCODE] Reconciliation pending for missing blob {} status={:?} error_code={:?} retry_after={:?}",
                sha256,
                parsed.status,
                parsed.error_code,
                parsed.retry_after_epoch_secs
            );
            Ok(derivative_reconciliation_response(
                sha256,
                "Transcode",
                &format!("{:?}", parsed.status).to_lowercase(),
            ))
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
    validate_transcoder_webhook(&req, "TRANSCRIPT")?;

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

    validate_sha256_format(sha256)?;

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
            generation: parsed.generation,
            require_generation_after_versioned: derivative_generation_guard_enabled(),
            malformed_generation: parsed.malformed_generation,
        },
    ) {
        Ok(outcome) => {
            if let Some(resp) = generation_ignore_response(outcome, sha256, "TRANSCRIPT") {
                return Ok(resp);
            }
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
                purge_edge_cache(sha256);
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
            Ok(derivative_reconciliation_response(
                sha256,
                "Transcript",
                &format!("{:?}", parsed.status).to_lowercase(),
            ))
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

/// Extract the leading SHA-256 hash from a hash-addressed path
/// (`/<hash>`, `/<hash>.mp4`, `/<hash>/hls/...`), matching the prefix shape
/// that vcl/recv.vcl routes to the Compute lookup backend. Returns the
/// lowercased hash so the key matches the Surrogate-Key set on successful
/// responses.
fn surrogate_key_hash_from_path(path: &str) -> Option<String> {
    let hash = path.strip_prefix('/')?.get(..64)?;
    if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(hash.to_lowercase())
    } else {
        None
    }
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

    // Cap how long CDN caches 404s from access-controlled blobs.
    // Without this, moderation status changes (e.g. Restricted -> Active)
    // stay invisible at the edge until Fastly's default TTL expires.
    if error.status_code() == StatusCode::NOT_FOUND {
        resp.set_header("Cache-Control", "no-store");
        resp.set_header("Surrogate-Control", "max-age=60");
    }

    resp
}

fn apply_cache_headers(resp: &mut Response, headers: &CacheHeaders<'_>) {
    resp.set_header("Cache-Control", headers.cache_control);
    resp.set_header("Surrogate-Control", headers.surrogate_control);
    resp.set_header("Surrogate-Key", headers.surrogate_key);
}

/// Cache headers for *derived* content: renditions, HLS manifests and segments,
/// and transcripts.
///
/// Unlike the blob, these are not immutable. The transcoder regenerates renditions
/// via `/backfill-fmp4`, and `scan_and_repair_vtts.py` rewrites transcripts — both
/// while the URL stays the same. Marking them `immutable` tells a browser never to
/// revalidate, even on reload, and browser caches cannot be purged; a client that
/// fetched a broken transcript would keep it for the full year.
///
/// The edge TTL stays long because `purge_edge_cache` can invalidate it instantly by
/// Surrogate-Key. Only the browser TTL needs to be short enough that a repair reaches
/// clients that already cached the old version.
fn add_derivative_cache_headers(resp: &mut Response, hash: &str) {
    apply_cache_headers(resp, &mutable_derivative_cache_headers(hash));
}

/// Apply the moderation-status cache policy to a blob response. `None` (no
/// metadata) fails closed to the private policy so no caller can silently hand
/// out an immutable public copy for content whose status is unknown.
fn add_blob_response_cache_headers(resp: &mut Response, hash: &str, status: Option<BlobStatus>) {
    let policy = status
        .map(blob_cache_policy)
        .unwrap_or(BlobCachePolicy::PrivateNoStore);
    apply_cache_headers(resp, &cache_headers_for_policy(policy, hash));
}

/// Cache headers for authenticated or admin-only content that must not be
/// stored in shared caches.
fn add_private_cache_headers(resp: &mut Response, hash: &str) {
    apply_cache_headers(
        resp,
        &cache_headers_for_policy(BlobCachePolicy::PrivateNoStore, hash),
    );
}

/// Mark a response as explicitly uncacheable (used for 202 in-progress responses).
/// Defence-in-depth: VCL vcl_fetch also marks 202s uncacheable, but belt-and-suspenders.
fn add_no_cache_headers(resp: &mut Response) {
    resp.set_header("Cache-Control", "no-store");
    resp.set_header("Surrogate-Control", "no-store");
}

/// Purge content from both the VCL website cache and the Compute media cache
/// by Surrogate-Key. Calls POST /service/{id}/purge/{key} on api.fastly.com
/// for each service. Best-effort: logs errors but never fails the calling request.
pub(crate) fn purge_edge_cache(surrogate_key: &str) {
    let api_token = match fastly::secret_store::SecretStore::open("blossom_secrets")
        .ok()
        .and_then(|store| store.get("fastly_api_token"))
        .map(|secret| String::from_utf8(secret.plaintext().to_vec()).unwrap_or_default())
    {
        Some(token) if !token.is_empty() => token,
        _ => {
            eprintln!("[PURGE] fastly_api_token not configured, skipping cache purge");
            return;
        }
    };

    let services: &[(&str, &str)] = &[
        ("ML7R82HKfmTaqTpHExIDVN", "VCL"),     // divine.video website
        ("pOvEEWykEbpnylqst1KTrR", "Compute"),  // media.divine.video (Blossom)
    ];

    for &(service_id, label) in services {
        let url = format!(
            "https://api.fastly.com/service/{}/purge/{}",
            service_id, surrogate_key
        );

        let mut purge_req = Request::new(Method::POST, &url);
        purge_req.set_header("Host", "api.fastly.com");
        purge_req.set_header("Fastly-Key", &api_token);
        purge_req.set_header("Accept", "application/json");

        match purge_req.send("fastly_api") {
            Ok(resp) => {
                let status = resp.get_status();
                if status.is_success() {
                    eprintln!("[PURGE] {} cache purged for key={}", label, surrogate_key);
                } else {
                    eprintln!(
                        "[PURGE] {} purge failed for key={}: HTTP {}",
                        label, surrogate_key, status.as_u16()
                    );
                }
            }
            Err(e) => {
                eprintln!(
                    "[PURGE] {} purge request failed for key={}: {}",
                    label, surrogate_key, e
                );
            }
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
        "Authorization, Content-Type, X-Sha256, X-Request-Id",
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
    // Retry-After lets a browser client read the throttle backoff on a 429.
    "X-Sha256, X-Content-Length, X-C2PA-Manifest-Id, X-Source-Sha256, X-Content-SHA256, X-Audio-Duration, X-Audio-Size, X-Divine-Upload-Extensions, X-Divine-Upload-Control-Host, X-Divine-Upload-Data-Host, Retry-After"
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
        add_audio_response_headers, add_blob_response_cache_headers, backfill_batch_cursor,
        classify_audio_reuse_availability, decide_transcode_fetch_action,
        decide_transcript_fetch_action, derivative_reconciliation_response, error_response,
        ignored_generation_response, is_alias_only_audio_blob, local_derivative_cleanup_result,
        parse_transcode_status_webhook_payload, parse_transcript_status_webhook_payload,
        parse_upload_service_response, select_vanish_batch, should_delete_derived_audio_blob,
        should_eagerly_trigger_transcription, should_record_upload_service_transcode_failure,
        should_record_upload_service_transcript_failure,
        should_reset_transcode_failure_on_clean_upload,
        should_reset_transcript_failure_on_clean_upload, should_set_audio_content_length,
        surrogate_key_hash_from_path, trusted_upload_service_terminal_derivative_error,
        upload_capability_headers, upload_control_host, upload_exposed_headers,
        upload_from_resumable_completion, vanish_response_status, AudioReuseAvailability,
        DerivativeObservation, TranscodeFetchAction, TranscriptFetchAction, TranscriptPendingState,
        VANISH_BATCH_SIZE,
    };
    use crate::blossom::{
        BlobStatus, ResumableUploadCompleteResponse, TranscodeStatus, TranscriptStatus,
    };
    use crate::error::{BlossomError, Result as BlossomResult};
    use blossom_core::cache_policy::BlobCachePolicy;
    use fastly::http::StatusCode;
    use fastly::Response;

    #[test]
    fn vanish_response_distinguishes_continuation_from_terminal_failure() {
        assert_eq!(vanish_response_status(0, 0), StatusCode::OK);
        assert_eq!(vanish_response_status(0, 1), StatusCode::ACCEPTED);
        assert_eq!(
            vanish_response_status(1, 0),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            vanish_response_status(1, 1),
            StatusCode::ACCEPTED
        );
    }

    #[test]
    fn vanish_batch_is_bounded_and_normalizes_valid_legacy_hashes() {
        let hashes: Vec<String> = (0..1_015).map(|index| format!("{:064X}", index)).collect();

        let (selected, malformed, pending) = select_vanish_batch(&hashes);

        assert_eq!(selected.len(), VANISH_BATCH_SIZE);
        assert!(malformed.is_empty());
        assert_eq!(pending, 1_005);
        assert!(selected.iter().all(|hash| hash == &hash.to_lowercase()));
    }

    #[test]
    fn vanish_batch_separates_malformed_entries_before_cleanup() {
        let valid = "a".repeat(64);
        let malformed = "not-a-hash".to_string();

        let (selected, exceptions, pending) =
            select_vanish_batch(&[malformed.clone(), valid.clone()]);

        assert_eq!(selected, vec![valid]);
        assert_eq!(exceptions, vec![malformed]);
        assert_eq!(pending, 0);
    }

    #[test]
    fn local_derivative_cleanup_requires_every_deterministic_delete() {
        assert!(local_derivative_cleanup_result(true, &[])
            .expect("local mode should decide cleanup locally")
            .is_ok());
        assert!(local_derivative_cleanup_result(true, &["delete failed".into()])
            .expect("local mode should decide cleanup locally")
            .is_err());
        assert!(local_derivative_cleanup_result(false, &[]).is_none());
    }

    #[test]
    fn upload_service_response_records_failure_fields_but_clamps_broad_invalid_media_terminal() {
        let resp = serde_json::json!({
            "sha256": "c".repeat(64),
            "size": 5016_u64,
            "thumbnail_url": null,
            "dim": null,
            "transcode_error_code": "invalid_media",
            "transcode_error_message": "ffprobe failed: moov atom not found",
            "transcode_terminal": true,
            "transcript_error_code": "invalid_media",
            "transcript_error_message": "ffprobe failed: moov atom not found",
            "transcript_terminal": true
        });

        let upload = parse_upload_service_response(&resp, "video/webm", 0).unwrap();

        assert_eq!(upload.sha256, "c".repeat(64));
        assert_eq!(upload.size, 5016);
        assert_eq!(upload.content_type, "video/webm");
        assert_eq!(
            upload.transcode_error_code.as_deref(),
            Some("invalid_media")
        );
        assert_eq!(
            upload.transcode_error_message.as_deref(),
            Some("ffprobe failed: moov atom not found")
        );
        assert!(!upload.transcode_terminal);
        assert_eq!(
            upload.transcript_error_code.as_deref(),
            Some("invalid_media")
        );
        assert!(!upload.transcript_terminal);
    }

    #[test]
    fn upload_service_response_honors_trusted_terminal_error_codes() {
        let resp = serde_json::json!({
            "sha256": "d".repeat(64),
            "size": 10_u64,
            "transcode_error_code": "unsupported_media_type",
            "transcode_terminal": true,
            "transcript_error_code": "unsupported_media_type",
            "transcript_terminal": true
        });

        let upload = parse_upload_service_response(&resp, "video/example", 99).unwrap();

        assert_eq!(upload.size, 10);
        assert!(upload.transcode_terminal);
        assert!(upload.transcript_terminal);
    }

    #[test]
    fn upload_service_response_defaults_when_failure_fields_are_absent() {
        let resp = serde_json::json!({
            "sha256": "e".repeat(64),
            "thumbnail_url": "https://cdn.example.com/thumb.jpg",
            "dim": "1920x1080"
        });

        let upload = parse_upload_service_response(&resp, "video/mp4", 512).unwrap();

        assert_eq!(upload.size, 512);
        assert_eq!(upload.transcode_error_code, None);
        assert!(!upload.transcode_terminal);
        assert_eq!(upload.transcript_error_code, None);
        assert!(!upload.transcript_terminal);
        assert_eq!(
            upload.transcode_observation,
            DerivativeObservation::Evaluated
        );
        assert_eq!(
            upload.transcript_observation,
            DerivativeObservation::Evaluated
        );
        assert_eq!(
            upload.thumbnail_url.as_deref(),
            Some("https://cdn.example.com/thumb.jpg")
        );
        assert_eq!(upload.dim.as_deref(), Some("1920x1080"));
    }

    #[test]
    fn upload_service_response_requires_sha256() {
        let resp = serde_json::json!({ "size": 10_u64 });

        assert!(parse_upload_service_response(&resp, "video/mp4", 10).is_err());
    }

    #[test]
    fn direct_audio_upload_leaves_derivative_observations_unavailable() {
        let resp = serde_json::json!({
            "sha256": "a".repeat(64),
            "size": 2048_u64
        });

        let upload = parse_upload_service_response(&resp, "audio/mpeg", 0).unwrap();

        assert_eq!(
            upload.transcode_observation,
            DerivativeObservation::Unavailable
        );
        assert_eq!(
            upload.transcript_observation,
            DerivativeObservation::Unavailable
        );
    }

    #[test]
    fn upload_service_terminal_trust_requires_code_and_allowlist_match() {
        assert!(trusted_upload_service_terminal_derivative_error(
            Some("unsupported_media_type"),
            true
        ));
        assert!(!trusted_upload_service_terminal_derivative_error(
            Some("invalid_media"),
            true
        ));
        assert!(!trusted_upload_service_terminal_derivative_error(
            None, true
        ));
        assert!(!trusted_upload_service_terminal_derivative_error(
            Some("unsupported_media_type"),
            false
        ));
    }

    #[test]
    fn upload_service_dedupe_failure_decisions_preserve_complete_status() {
        assert!(should_record_upload_service_transcode_failure(
            Some(TranscodeStatus::Pending),
            Some("invalid_media")
        ));
        assert!(!should_record_upload_service_transcode_failure(
            Some(TranscodeStatus::Complete),
            Some("invalid_media")
        ));
        assert!(should_record_upload_service_transcript_failure(
            Some(TranscriptStatus::Failed),
            Some("invalid_media")
        ));
        assert!(!should_record_upload_service_transcript_failure(
            Some(TranscriptStatus::Complete),
            Some("invalid_media")
        ));
    }

    #[test]
    fn upload_service_dedupe_failure_does_not_stomp_in_flight_derivatives() {
        assert!(!should_record_upload_service_transcode_failure(
            Some(TranscodeStatus::Processing),
            Some("invalid_media")
        ));
        assert!(!should_record_upload_service_transcript_failure(
            Some(TranscriptStatus::Processing),
            Some("invalid_media")
        ));
    }

    #[test]
    fn resumable_completion_leaves_derivative_observations_unavailable() {
        let upload = upload_from_resumable_completion(ResumableUploadCompleteResponse {
            sha256: "f".repeat(64),
            size: 1024,
            content_type: "video/mp4".to_string(),
            thumbnail_url: None,
            dim: None,
        });

        assert_eq!(
            upload.transcode_observation,
            DerivativeObservation::Unavailable
        );
        assert_eq!(
            upload.transcript_observation,
            DerivativeObservation::Unavailable
        );
    }

    #[test]
    fn evaluated_clean_upload_resets_missing_or_failed_derivative_state_only() {
        assert!(should_reset_transcode_failure_on_clean_upload(
            "video/mp4",
            Some(TranscodeStatus::Failed),
            DerivativeObservation::Evaluated,
            None
        ));
        assert!(should_reset_transcode_failure_on_clean_upload(
            "video/mp4",
            None,
            DerivativeObservation::Evaluated,
            None
        ));
        assert!(!should_reset_transcode_failure_on_clean_upload(
            "video/mp4",
            Some(TranscodeStatus::Complete),
            DerivativeObservation::Evaluated,
            None
        ));
        assert!(!should_reset_transcode_failure_on_clean_upload(
            "image/jpeg",
            Some(TranscodeStatus::Failed),
            DerivativeObservation::Evaluated,
            None
        ));
        assert!(should_reset_transcript_failure_on_clean_upload(
            "video/mp4",
            Some(TranscriptStatus::Failed),
            DerivativeObservation::Evaluated,
            None
        ));
        assert!(!should_reset_transcript_failure_on_clean_upload(
            "video/mp4",
            Some(TranscriptStatus::Complete),
            DerivativeObservation::Evaluated,
            None
        ));
    }

    #[test]
    fn unavailable_upload_preserves_failed_derivative_state() {
        assert!(!should_reset_transcode_failure_on_clean_upload(
            "video/mp4",
            Some(TranscodeStatus::Failed),
            DerivativeObservation::Unavailable,
            None
        ));
        assert!(!should_reset_transcript_failure_on_clean_upload(
            "video/mp4",
            Some(TranscriptStatus::Failed),
            DerivativeObservation::Unavailable,
            None
        ));
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
    fn parses_transcode_webhook_generation() {
        let payload = serde_json::json!({
            "sha256": "50dfc6758bb3cdf823ef33315e72642ebb881a0b1d0f6b0d8bade0f0fad30c3a",
            "status": "complete",
            "generation": 1_700_000_000_123_u64
        });

        let parsed = parse_transcode_status_webhook_payload(&payload, 1_000).unwrap();

        assert_eq!(parsed.generation, Some(1_700_000_000_123));
        assert!(!parsed.malformed_generation);
    }

    #[test]
    fn parses_transcript_webhook_generation() {
        let payload = serde_json::json!({
            "sha256": "50dfc6758bb3cdf823ef33315e72642ebb881a0b1d0f6b0d8bade0f0fad30c3a",
            "status": "processing",
            "generation": 42_u64
        });

        let parsed = parse_transcript_status_webhook_payload(&payload, 1_000).unwrap();

        assert_eq!(parsed.generation, Some(42));
        assert!(!parsed.malformed_generation);
    }

    #[test]
    fn parses_missing_webhook_generation_as_legacy_absent() {
        let payload = serde_json::json!({
            "sha256": "50dfc6758bb3cdf823ef33315e72642ebb881a0b1d0f6b0d8bade0f0fad30c3a",
            "status": "complete"
        });

        let parsed = parse_transcode_status_webhook_payload(&payload, 1_000).unwrap();

        assert_eq!(parsed.generation, None);
        assert!(!parsed.malformed_generation);
    }

    #[test]
    fn parses_malformed_webhook_generation_distinctly() {
        let payload = serde_json::json!({
            "sha256": "50dfc6758bb3cdf823ef33315e72642ebb881a0b1d0f6b0d8bade0f0fad30c3a",
            "status": "failed",
            "generation": "123"
        });

        let parsed = parse_transcode_status_webhook_payload(&payload, 1_000).unwrap();

        assert_eq!(parsed.generation, None);
        assert!(parsed.malformed_generation);
    }

    #[test]
    fn ignored_generation_response_returns_successful_ignore() {
        let hash = "50dfc6758bb3cdf823ef33315e72642ebb881a0b1d0f6b0d8bade0f0fad30c3a";
        let resp = ignored_generation_response(hash, "stale_generation", Some(3), Some(5));

        assert_eq!(resp.get_status(), StatusCode::OK);
        assert_eq!(
            resp.get_header_str("Access-Control-Allow-Origin"),
            Some("*")
        );
        assert!(resp
            .into_body_str()
            .contains("\"ignored\":\"stale_generation\""));
    }

    #[test]
    fn ignored_generation_response_can_omit_incoming_generation() {
        let hash = "50dfc6758bb3cdf823ef33315e72642ebb881a0b1d0f6b0d8bade0f0fad30c3a";
        let resp = ignored_generation_response(hash, "missing_generation", None, Some(5));

        assert_eq!(resp.get_status(), StatusCode::OK);
        assert!(resp
            .into_body_str()
            .contains("\"ignored\":\"missing_generation\""));
    }

    #[test]
    fn derivative_reconciliation_response_acknowledges_missing_blob() {
        let hash = "50dfc6758bb3cdf823ef33315e72642ebb881a0b1d0f6b0d8bade0f0fad30c3a";
        let resp = derivative_reconciliation_response(hash, "Transcode", "failed");

        assert_eq!(resp.get_status(), StatusCode::ACCEPTED);
        assert!(resp
            .into_body_str()
            .contains("\"reconciliation\":\"pending\""));
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
        // Browser clients must be able to read the 429 throttle backoff.
        assert!(exposed_headers.contains("Retry-After"));
    }

    #[test]
    fn pending_blob_get_uses_short_browser_cache_with_purgeable_edge_ttl() {
        let mut resp = Response::from_status(StatusCode::OK);

        add_blob_response_cache_headers(&mut resp, "abc123", Some(BlobStatus::Pending));

        assert_eq!(
            resp.get_header_str("Cache-Control"),
            Some("public, max-age=86400")
        );
        assert_eq!(
            resp.get_header_str("Surrogate-Control"),
            Some("max-age=31536000")
        );
        assert_eq!(resp.get_header_str("Surrogate-Key"), Some("abc123"));
    }

    #[test]
    fn active_blob_get_keeps_immutable_cache_policy() {
        let mut resp = Response::from_status(StatusCode::OK);

        add_blob_response_cache_headers(&mut resp, "abc123", Some(BlobStatus::Active));

        assert_eq!(
            resp.get_header_str("Cache-Control"),
            Some("public, max-age=31536000, immutable"),
        );
        assert_eq!(
            resp.get_header_str("Surrogate-Control"),
            Some("max-age=31536000")
        );
        assert_eq!(resp.get_header_str("Surrogate-Key"), Some("abc123"));
    }

    #[test]
    fn moderated_blob_get_statuses_are_not_cacheable() {
        for status in [
            BlobStatus::Restricted,
            BlobStatus::AgeRestricted,
            BlobStatus::Banned,
            BlobStatus::Deleted,
        ] {
            let mut resp = Response::from_status(StatusCode::OK);

            add_blob_response_cache_headers(&mut resp, "abc123", Some(status));

            assert_eq!(
                resp.get_header_str("Cache-Control"),
                Some("private, no-store")
            );
            assert_eq!(resp.get_header_str("Surrogate-Control"), Some("no-store"));
            assert_eq!(resp.get_header_str("Surrogate-Key"), Some("abc123"));
        }
    }

    #[test]
    fn blob_get_without_metadata_fails_closed_to_private_cache() {
        let mut resp = Response::from_status(StatusCode::OK);

        add_blob_response_cache_headers(&mut resp, "abc123", None);

        assert_eq!(
            resp.get_header_str("Cache-Control"),
            Some("private, no-store")
        );
        assert_eq!(resp.get_header_str("Surrogate-Control"), Some("no-store"));
        assert_eq!(resp.get_header_str("Surrogate-Key"), Some("abc123"));
    }

    #[test]
    fn audio_responses_follow_the_source_cache_policy() {
        for (policy, cache_control) in [
            (
                BlobCachePolicy::ImmutablePublic,
                "public, max-age=31536000, immutable",
            ),
            (BlobCachePolicy::RevocablePublic, "public, max-age=86400"),
            (BlobCachePolicy::PrivateNoStore, "private, no-store"),
        ] {
            let mut resp = Response::from_status(StatusCode::OK);

            add_audio_response_headers(&mut resp, "src123", policy, "audio/mp4", 42, 1.5);

            assert_eq!(resp.get_header_str("Cache-Control"), Some(cache_control));
            // Audio responses are keyed by the source video hash so moderation
            // purges invalidate them together with the source.
            assert_eq!(resp.get_header_str("Surrogate-Key"), Some("src123"));
        }
    }

    #[test]
    fn complete_rejects_unknown_upload_session_with_404() {
        let resp = error_response(&BlossomError::NotFound("Upload session not found".into()));

        assert_eq!(resp.get_status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn error_response_404_has_short_cdn_ttl() {
        let resp = error_response(&BlossomError::NotFound("Blob not found".into()));

        assert_eq!(resp.get_status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.get_header_str("Cache-Control"),
            Some("no-store"),
        );
        assert_eq!(
            resp.get_header_str("Surrogate-Control"),
            Some("max-age=60"),
        );
    }

    #[test]
    fn error_response_non_404_has_no_cdn_cache_headers() {
        let resp = error_response(&BlossomError::BadRequest("bad input".into()));

        assert_eq!(resp.get_status(), StatusCode::BAD_REQUEST);
        assert_eq!(resp.get_header_str("Cache-Control"), None);
        assert_eq!(resp.get_header_str("Surrogate-Control"), None);
    }

    #[test]
    fn surrogate_key_hash_from_path_extracts_hash_addressed_prefixes() {
        let hash = "a".repeat(64);
        let upper_hash = "A".repeat(64);

        assert_eq!(
            surrogate_key_hash_from_path(&format!("/{hash}")),
            Some(hash.clone())
        );
        assert_eq!(
            surrogate_key_hash_from_path(&format!("/{hash}.mp4")),
            Some(hash.clone())
        );
        assert_eq!(
            surrogate_key_hash_from_path(&format!("/{hash}/hls/master.m3u8")),
            Some(hash.clone())
        );
        assert_eq!(
            surrogate_key_hash_from_path(&format!("/{upper_hash}")),
            Some(hash.clone())
        );

        assert_eq!(surrogate_key_hash_from_path("/"), None);
        assert_eq!(surrogate_key_hash_from_path("/upload"), None);
        assert_eq!(surrogate_key_hash_from_path("/admin/api/stats"), None);
        assert_eq!(
            surrogate_key_hash_from_path(&format!("/{}", "a".repeat(63))),
            None
        );
        assert_eq!(
            surrogate_key_hash_from_path(&format!("/{}z", "a".repeat(63))),
            None
        );
    }
}
