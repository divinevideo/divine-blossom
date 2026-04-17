// ABOUTME: Request-bound auth wrappers for Blossom media and management routes
// ABOUTME: Uses pure validation helpers from viewer_auth and adapts Fastly Request inputs

use crate::blossom::{AuthAction, BlossomAuthEvent};
use crate::error::{BlossomError, Result};
use crate::viewer_auth::{
    authenticate_blob_viewer, authenticate_generic_viewer, diagnose_viewer_auth_request,
    parse_auth_header, public_request_url, validate_blossom_event, ViewerAuthDiagnostics,
};
use fastly::http::header::{AUTHORIZATION, HOST};
use fastly::Request;
use std::time::{SystemTime, UNIX_EPOCH};

/// Extract and validate Blossom auth from request.
pub fn validate_auth(req: &Request, required_action: AuthAction) -> Result<BlossomAuthEvent> {
    let event = parse_request_auth_event(req)?;
    validate_blossom_event(&event, required_action, unix_now())?;
    Ok(event)
}

/// Extract the authenticated viewer pubkey for media/list requests.
///
/// Supports both Blossom list auth (kind 24242) and NIP-98 HTTP auth
/// (kind 27235). If an auth header is present but invalid, this returns an
/// error instead of silently treating the request as anonymous.
pub fn viewer_pubkey(req: &Request) -> Result<Option<String>> {
    let auth_headers = request_auth_headers(req)?;
    if auth_headers.is_empty() {
        return Ok(None);
    }

    let request_url = public_request_url(
        &req.get_url().to_string(),
        req.get_header(HOST).and_then(|h| h.to_str().ok()),
    )?;
    let scope = match blob_hash_from_path(req.get_path()) {
        Some(hash) => ViewerScope::Blob(hash),
        None => ViewerScope::Generic,
    };

    let event = match scope {
        ViewerScope::Generic => authenticate_generic_viewer(
            &auth_headers,
            req.get_method().as_str(),
            &request_url,
            unix_now(),
        )?,
        ViewerScope::Blob(hash) => authenticate_blob_viewer(
            &auth_headers,
            req.get_method().as_str(),
            &request_url,
            &hash,
            unix_now(),
        )?,
    };

    Ok(Some(event.pubkey))
}

pub fn diagnose_viewer_auth(req: &Request) -> Result<ViewerAuthDiagnostics> {
    let first_auth_header = request_auth_headers(req)?.into_iter().next();
    Ok(diagnose_viewer_auth_request(
        req.get_method().as_str(),
        req.get_path(),
        req.get_header(HOST).and_then(|h| h.to_str().ok()),
        &req.get_url().to_string(),
        first_auth_header,
        unix_now(),
    ))
}

fn parse_request_auth_event(req: &Request) -> Result<BlossomAuthEvent> {
    let auth_header = req
        .get_header(AUTHORIZATION)
        .ok_or_else(|| BlossomError::AuthRequired("Authorization header required".into()))?
        .to_str()
        .map_err(|_| BlossomError::AuthInvalid("Invalid authorization header".into()))?;

    parse_auth_header(auth_header)
}

fn request_auth_headers(req: &Request) -> Result<Vec<&str>> {
    req.get_header_all_str(AUTHORIZATION)
        .into_iter()
        .map(|value| {
            if value.is_empty() {
                Err(BlossomError::AuthInvalid(
                    "Invalid authorization header".into(),
                ))
            } else {
                Ok(value)
            }
        })
        .collect()
}

enum ViewerScope {
    Generic,
    Blob(String),
}

fn blob_hash_from_path(path: &str) -> Option<String> {
    let first_segment = path.trim_start_matches('/').split('/').next()?;
    let candidate = first_segment.split('.').next().unwrap_or(first_segment);

    if candidate.len() == 64 && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(candidate.to_lowercase())
    } else {
        None
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Validate that the auth event matches a specific blob hash (for delete).
pub fn validate_hash_match(event: &BlossomAuthEvent, expected_hash: &str) -> Result<()> {
    let event_hash = event
        .get_hash()
        .ok_or_else(|| BlossomError::AuthInvalid("Missing hash tag in auth event".into()))?;

    if event_hash.to_lowercase() != expected_hash.to_lowercase() {
        return Err(BlossomError::AuthInvalid(
            "Hash in auth event doesn't match requested blob".into(),
        ));
    }

    Ok(())
}
