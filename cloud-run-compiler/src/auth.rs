// ABOUTME: Verifies NIP-98 editor requests and the signed Nostr list they compile
// ABOUTME: Binds request body, public URL, HTTP method, and list ownership together

use crate::domain::CompileRequest;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nostr::{nips::nip98::HttpData, Event, JsonUtil, Kind};
use sha2::{Digest, Sha256};
use thiserror::Error;

const AUTH_MAX_AGE_SECONDS: u64 = 300;
const AUTH_MAX_FUTURE_SECONDS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub pubkey: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("authorization must use the Nostr scheme")]
    MissingScheme,
    #[error("authorization payload is not valid base64")]
    InvalidEncoding,
    #[error("authorization payload is not a valid Nostr event")]
    InvalidEvent,
    #[error("authorization event signature is invalid")]
    InvalidSignature,
    #[error("authorization event must be kind 27235")]
    InvalidKind,
    #[error("authorization event is outside the accepted time window")]
    Stale,
    #[error("authorization URL does not match the public request URL")]
    UrlMismatch,
    #[error("authorization HTTP method does not match")]
    MethodMismatch,
    #[error("authorization event has no payload hash")]
    MissingPayload,
    #[error("authorization payload hash does not match the request body")]
    PayloadMismatch,
    #[error("source list signature is invalid")]
    InvalidListSignature,
    #[error("authorization signer must own the source list")]
    AuthorMismatch,
}

pub fn verify_editor_request(
    authorization: &str,
    method: &str,
    public_url: &str,
    body: &[u8],
    request: &CompileRequest,
    now: u64,
) -> Result<VerifiedIdentity, AuthError> {
    let encoded = authorization
        .strip_prefix("Nostr ")
        .ok_or(AuthError::MissingScheme)?;
    let event_json = STANDARD
        .decode(encoded)
        .map_err(|_| AuthError::InvalidEncoding)?;
    let event_json = std::str::from_utf8(&event_json).map_err(|_| AuthError::InvalidEvent)?;
    let event = Event::from_json(event_json).map_err(|_| AuthError::InvalidEvent)?;

    event.verify().map_err(|_| AuthError::InvalidSignature)?;
    if event.kind != Kind::HttpAuth {
        return Err(AuthError::InvalidKind);
    }

    let created_at = event.created_at.as_u64();
    if created_at > now.saturating_add(AUTH_MAX_FUTURE_SECONDS)
        || now.saturating_sub(created_at) > AUTH_MAX_AGE_SECONDS
    {
        return Err(AuthError::Stale);
    }

    let http_data = HttpData::try_from(event.tags.clone()).map_err(|_| AuthError::InvalidEvent)?;
    if http_data.url.to_string() != public_url {
        return Err(AuthError::UrlMismatch);
    }
    if http_data.method.to_string() != method {
        return Err(AuthError::MethodMismatch);
    }

    let payload = http_data.payload.ok_or(AuthError::MissingPayload)?;
    let body_hash = format!("{:x}", Sha256::digest(body));
    if payload.to_string() != body_hash {
        return Err(AuthError::PayloadMismatch);
    }

    let list_json = serde_json::to_string(&request.source.list_event)
        .map_err(|_| AuthError::InvalidListSignature)?;
    let list_event = Event::from_json(list_json).map_err(|_| AuthError::InvalidListSignature)?;
    list_event
        .verify()
        .map_err(|_| AuthError::InvalidListSignature)?;

    let signer = event.pubkey.to_string();
    if signer != list_event.pubkey.to_string() {
        return Err(AuthError::AuthorMismatch);
    }

    Ok(VerifiedIdentity { pubkey: signer })
}
