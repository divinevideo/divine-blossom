// ABOUTME: Nostr authentication for Blossom (kind 24242)
// ABOUTME: Validates signatures, expiration, and authorization events using k256

use crate::blossom::{AuthAction, BlossomAuthEvent};
use crate::error::{BlossomError, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use fastly::http::header::AUTHORIZATION;
use fastly::Request;
use k256::schnorr::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Blossom auth event kind
const BLOSSOM_AUTH_KIND: u32 = 24242;

/// Extract and validate Blossom auth from request
pub fn validate_auth(req: &Request, required_action: AuthAction) -> Result<BlossomAuthEvent> {
    let auth_header = req
        .get_header(AUTHORIZATION)
        .ok_or_else(|| BlossomError::AuthRequired("Authorization header required".into()))?
        .to_str()
        .map_err(|_| BlossomError::AuthInvalid("Invalid authorization header".into()))?;

    // Parse "Nostr <base64>" format
    let base64_event = auth_header
        .strip_prefix("Nostr ")
        .ok_or_else(|| BlossomError::AuthInvalid("Authorization must start with 'Nostr '".into()))?;

    // Decode base64
    let event_json = BASE64
        .decode(base64_event)
        .map_err(|_| BlossomError::AuthInvalid("Invalid base64 in authorization".into()))?;

    // Parse JSON
    let event: BlossomAuthEvent = serde_json::from_slice(&event_json)
        .map_err(|e| BlossomError::AuthInvalid(format!("Invalid event JSON: {}", e)))?;

    // Validate the event
    validate_event(&event, required_action)?;

    Ok(event)
}

/// Validate a Blossom auth event
fn validate_event(event: &BlossomAuthEvent, required_action: AuthAction) -> Result<()> {
    // Check kind
    if event.kind != BLOSSOM_AUTH_KIND {
        return Err(BlossomError::AuthInvalid(format!(
            "Invalid event kind: expected {}, got {}",
            BLOSSOM_AUTH_KIND, event.kind
        )));
    }

    // Check action tag
    let action = event
        .get_action()
        .ok_or_else(|| BlossomError::AuthInvalid("Missing action tag".into()))?;

    if action != required_action {
        return Err(BlossomError::AuthInvalid(format!(
            "Action mismatch: expected {:?}, got {:?}",
            required_action, action
        )));
    }

    // Check expiration
    if let Some(expiration) = event.get_expiration() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now > expiration {
            return Err(BlossomError::AuthInvalid("Authorization expired".into()));
        }
    }

    // Verify event ID
    let computed_id = compute_event_id(event)?;
    if computed_id != event.id {
        return Err(BlossomError::AuthInvalid("Invalid event ID".into()));
    }

    // Verify signature
    verify_signature(event)?;

    Ok(())
}

/// Compute the event ID (sha256 of serialized event)
fn compute_event_id(event: &BlossomAuthEvent) -> Result<String> {
    // NIP-01 serialization: [0, pubkey, created_at, kind, tags, content]
    let serialized = serde_json::to_string(&(
        0u8,
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    ))
    .map_err(|e| BlossomError::Internal(format!("Failed to serialize event: {}", e)))?;

    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    let hash = hasher.finalize();

    Ok(hex::encode(hash))
}

/// Verify the Schnorr signature using k256
fn verify_signature(event: &BlossomAuthEvent) -> Result<()> {
    // Parse public key (32 bytes, x-only)
    let pubkey_bytes = hex::decode(&event.pubkey)
        .map_err(|_| BlossomError::AuthInvalid("Invalid public key hex".into()))?;

    if pubkey_bytes.len() != 32 {
        return Err(BlossomError::AuthInvalid(format!(
            "Invalid public key length: expected 32, got {}",
            pubkey_bytes.len()
        )));
    }

    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|_| BlossomError::AuthInvalid("Invalid public key".into()))?;

    // Parse signature (64 bytes)
    let sig_bytes = hex::decode(&event.sig)
        .map_err(|_| BlossomError::AuthInvalid("Invalid signature hex".into()))?;

    if sig_bytes.len() != 64 {
        return Err(BlossomError::AuthInvalid(format!(
            "Invalid signature length: expected 64, got {}",
            sig_bytes.len()
        )));
    }

    let signature = Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| BlossomError::AuthInvalid("Invalid signature format".into()))?;

    // Parse message (event ID as raw bytes - this is already a SHA-256 hash)
    let msg_bytes = hex::decode(&event.id)
        .map_err(|_| BlossomError::AuthInvalid("Invalid event ID hex".into()))?;

    // Verify using BIP-340 Schnorr with prehashed message
    // The event ID is already a SHA-256 hash, so we use verify_prehash
    use k256::schnorr::signature::hazmat::PrehashVerifier;
    verifying_key
        .verify_prehash(&msg_bytes, &signature)
        .map_err(|_| BlossomError::AuthInvalid("Invalid signature".into()))?;

    Ok(())
}

/// Optional auth - returns None if no auth header, error if invalid auth
pub fn optional_auth(req: &Request, action: AuthAction) -> Result<Option<BlossomAuthEvent>> {
    if req.get_header(AUTHORIZATION).is_none() {
        return Ok(None);
    }
    validate_auth(req, action).map(Some)
}

/// Validate that the auth event matches a specific blob hash (for delete)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_event_id() {
        // This is a simplified test - real tests would use known test vectors
        let event = BlossomAuthEvent {
            id: "test".into(),
            pubkey: "a".repeat(64),
            created_at: 1234567890,
            kind: 24242,
            tags: vec![vec!["t".into(), "upload".into()]],
            content: "test".into(),
            sig: "b".repeat(128),
        };

        let id = compute_event_id(&event).unwrap();
        assert_eq!(id.len(), 64); // SHA-256 hex
    }
}
