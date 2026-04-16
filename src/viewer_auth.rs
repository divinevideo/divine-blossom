// ABOUTME: Pure Nostr HTTP auth validation for Blossom media viewers
// ABOUTME: Supports Divine Blossom auth (kind 24242) and NIP-98 (kind 27235)

use crate::blossom::{AuthAction, BlossomAuthEvent};
use crate::error::{BlossomError, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use k256::schnorr::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// Divine Blossom auth event kind.
pub const BLOSSOM_AUTH_KIND: u32 = 24242;
/// NIP-98 HTTP auth event kind.
pub const NIP98_AUTH_KIND: u32 = 27235;
/// Suggested freshness window from NIP-98.
pub const NIP98_MAX_AGE_SECS: u64 = 60;
/// Public hostname clients use for media viewer requests.
pub const PUBLIC_MEDIA_HOST: &str = "media.divine.video";

pub fn parse_auth_header(auth_header: &str) -> Result<BlossomAuthEvent> {
    let base64_event = auth_header.strip_prefix("Nostr ").ok_or_else(|| {
        BlossomError::AuthInvalid("Authorization must start with 'Nostr '".into())
    })?;

    let event_json = BASE64
        .decode(base64_event)
        .map_err(|_| BlossomError::AuthInvalid("Invalid base64 in authorization".into()))?;

    serde_json::from_slice(&event_json)
        .map_err(|e| BlossomError::AuthInvalid(format!("Invalid event JSON: {}", e)))
}

pub fn validate_blossom_event(
    event: &BlossomAuthEvent,
    required_action: AuthAction,
    now: u64,
) -> Result<()> {
    if event.kind != BLOSSOM_AUTH_KIND {
        return Err(BlossomError::AuthInvalid(format!(
            "Invalid event kind: expected {}, got {}",
            BLOSSOM_AUTH_KIND, event.kind
        )));
    }

    let action = event
        .get_action()
        .ok_or_else(|| BlossomError::AuthInvalid("Missing action tag".into()))?;
    if action != required_action {
        return Err(BlossomError::AuthInvalid(format!(
            "Action mismatch: expected {:?}, got {:?}",
            required_action, action
        )));
    }

    if let Some(expiration) = event.get_expiration() {
        if now > expiration {
            return Err(BlossomError::AuthInvalid("Authorization expired".into()));
        }
    }

    validate_event_integrity(event)
}

pub fn validate_nip98_event(
    event: &BlossomAuthEvent,
    request_method: &str,
    request_url: &str,
    now: u64,
) -> Result<()> {
    if event.kind != NIP98_AUTH_KIND {
        return Err(BlossomError::AuthInvalid(format!(
            "Invalid event kind: expected {}, got {}",
            NIP98_AUTH_KIND, event.kind
        )));
    }

    let oldest_allowed = now.saturating_sub(NIP98_MAX_AGE_SECS);
    let newest_allowed = now.saturating_add(NIP98_MAX_AGE_SECS);
    if event.created_at < oldest_allowed || event.created_at > newest_allowed {
        return Err(BlossomError::AuthInvalid(
            "Authorization timestamp outside allowed NIP-98 window".into(),
        ));
    }

    let event_url = get_tag_value(event, "u")
        .ok_or_else(|| BlossomError::AuthInvalid("Missing u tag".into()))?;
    if event_url != request_url {
        return Err(BlossomError::AuthInvalid(format!(
            "URL mismatch: expected {}, got {}",
            request_url, event_url
        )));
    }

    let event_method = get_tag_value(event, "method")
        .ok_or_else(|| BlossomError::AuthInvalid("Missing method tag".into()))?;
    if event_method != request_method {
        return Err(BlossomError::AuthInvalid(format!(
            "Method mismatch: expected {}, got {}",
            request_method, event_method
        )));
    }

    validate_event_integrity(event)
}

pub fn validate_viewer_event(
    event: &BlossomAuthEvent,
    request_method: &str,
    request_url: &str,
    now: u64,
) -> Result<()> {
    match event.kind {
        BLOSSOM_AUTH_KIND => validate_blossom_event(event, AuthAction::List, now),
        NIP98_AUTH_KIND => validate_nip98_event(event, request_method, request_url, now),
        kind => Err(BlossomError::AuthInvalid(format!(
            "Invalid event kind: expected {} or {}, got {}",
            BLOSSOM_AUTH_KIND, NIP98_AUTH_KIND, kind
        ))),
    }
}

pub fn public_request_url(request_url: &str, host_override: Option<&str>) -> Result<String> {
    let scheme_end = request_url
        .find("://")
        .ok_or_else(|| BlossomError::AuthInvalid("Invalid request URL: missing scheme".into()))?;
    let authority_start = scheme_end + 3;
    let path_start = request_url[authority_start..]
        .find(['/', '?', '#'])
        .map(|offset| authority_start + offset)
        .unwrap_or(request_url.len());

    let scheme = &request_url[..authority_start];
    let authority = &request_url[authority_start..path_start];
    let suffix = &request_url[path_start..];
    let host_override = host_override.map(str::trim).filter(|host| !host.is_empty());

    let effective_authority = match host_override {
        Some(host) if !is_internal_edge_host(host) => host,
        _ if is_internal_edge_host(authority) => PUBLIC_MEDIA_HOST,
        _ => authority,
    };

    Ok(format!("{}{}{}", scheme, effective_authority, suffix))
}

fn is_internal_edge_host(authority: &str) -> bool {
    authority.ends_with(".edgecompute.app")
}

fn get_tag_value<'a>(event: &'a BlossomAuthEvent, tag_name: &str) -> Option<&'a str> {
    event.tags.iter().find_map(|tag| {
        if tag.len() >= 2 && tag[0] == tag_name {
            Some(tag[1].as_str())
        } else {
            None
        }
    })
}

fn validate_event_integrity(event: &BlossomAuthEvent) -> Result<()> {
    let computed_id = compute_event_id(event)?;
    if computed_id != event.id {
        return Err(BlossomError::AuthInvalid("Invalid event ID".into()));
    }

    verify_signature(event)?;
    Ok(())
}

fn compute_event_id(event: &BlossomAuthEvent) -> Result<String> {
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

fn verify_signature(event: &BlossomAuthEvent) -> Result<()> {
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

    let msg_bytes = hex::decode(&event.id)
        .map_err(|_| BlossomError::AuthInvalid("Invalid event ID hex".into()))?;

    use k256::schnorr::signature::hazmat::PrehashVerifier;
    verifying_key
        .verify_prehash(&msg_bytes, &signature)
        .map_err(|_| BlossomError::AuthInvalid("Invalid signature".into()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::{signature::hazmat::PrehashSigner, SigningKey};

    const TEST_URL: &str =
        "https://media.divine.video/4a31d696c2275e60dbfe2359e6ff006f78a30f5df11c7290233a7860c4e8c31e";

    #[test]
    fn blossom_list_auth_is_valid_for_viewer_requests() {
        let event = signed_event(
            BLOSSOM_AUTH_KIND,
            vec![
                vec!["t".into(), "list".into()],
                vec!["expiration".into(), "1300".into()],
            ],
            1_000,
        );

        assert!(validate_viewer_event(&event, "GET", TEST_URL, 1_100).is_ok());
    }

    #[test]
    fn nip98_auth_is_valid_for_matching_request() {
        let event = signed_event(
            NIP98_AUTH_KIND,
            vec![
                vec!["u".into(), TEST_URL.into()],
                vec!["method".into(), "GET".into()],
            ],
            1_000,
        );

        assert!(validate_viewer_event(&event, "GET", TEST_URL, 1_000).is_ok());
    }

    #[test]
    fn nip98_auth_rejects_url_mismatch() {
        let event = signed_event(
            NIP98_AUTH_KIND,
            vec![
                vec!["u".into(), "https://media.divine.video/different".into()],
                vec!["method".into(), "GET".into()],
            ],
            1_000,
        );

        let error = validate_viewer_event(&event, "GET", TEST_URL, 1_000)
            .expect_err("url mismatch should fail");
        assert_eq!(
            error.message(),
            "URL mismatch: expected https://media.divine.video/4a31d696c2275e60dbfe2359e6ff006f78a30f5df11c7290233a7860c4e8c31e, got https://media.divine.video/different"
        );
    }

    #[test]
    fn nip98_auth_rejects_method_mismatch() {
        let event = signed_event(
            NIP98_AUTH_KIND,
            vec![
                vec!["u".into(), TEST_URL.into()],
                vec!["method".into(), "HEAD".into()],
            ],
            1_000,
        );

        let error = validate_viewer_event(&event, "GET", TEST_URL, 1_000)
            .expect_err("method mismatch should fail");
        assert_eq!(error.message(), "Method mismatch: expected GET, got HEAD");
    }

    #[test]
    fn nip98_auth_rejects_stale_timestamp() {
        let event = signed_event(
            NIP98_AUTH_KIND,
            vec![
                vec!["u".into(), TEST_URL.into()],
                vec!["method".into(), "GET".into()],
            ],
            900,
        );

        let error = validate_viewer_event(&event, "GET", TEST_URL, 1_000)
            .expect_err("stale timestamp should fail");
        assert_eq!(
            error.message(),
            "Authorization timestamp outside allowed NIP-98 window"
        );
    }

    #[test]
    fn blossom_only_validation_rejects_nip98() {
        let event = signed_event(
            NIP98_AUTH_KIND,
            vec![
                vec!["u".into(), TEST_URL.into()],
                vec!["method".into(), "DELETE".into()],
            ],
            1_000,
        );

        let error = validate_blossom_event(&event, AuthAction::Delete, 1_000)
            .expect_err("delete routes should still require Blossom auth");
        assert_eq!(
            error.message(),
            "Invalid event kind: expected 24242, got 27235"
        );
    }

    #[test]
    fn parse_auth_header_rejects_wrong_scheme() {
        let error = parse_auth_header("Bearer nope").expect_err("wrong scheme should fail");
        assert_eq!(error.message(), "Authorization must start with 'Nostr '");
    }

    #[test]
    fn public_request_url_rewrites_internal_edge_host_to_public_host() {
        let internal =
            "https://separately-robust-roughy.edgecompute.app/4a31d696c2275e60dbfe2359e6ff006f78a30f5df11c7290233a7860c4e8c31e";
        let public = public_request_url(internal, None)
            .expect("public host rewrite should succeed");

        assert_eq!(public, TEST_URL);
    }

    #[test]
    fn public_request_url_preserves_query_and_port_override() {
        let internal = "https://edgecompute.app/path/to/blob?foo=bar";
        let public = public_request_url(internal, Some("media.divine.video:8443"))
            .expect("public host rewrite should succeed");

        assert_eq!(public, "https://media.divine.video:8443/path/to/blob?foo=bar");
    }

    #[test]
    fn public_request_url_ignores_edge_host_override() {
        let internal =
            "https://separately-robust-roughy.edgecompute.app/4a31d696c2275e60dbfe2359e6ff006f78a30f5df11c7290233a7860c4e8c31e";
        let public = public_request_url(internal, Some("separately-robust-roughy.edgecompute.app"))
            .expect("edge host override should fall back to public media host");

        assert_eq!(public, TEST_URL);
    }

    fn signed_event(kind: u32, tags: Vec<Vec<String>>, created_at: u64) -> BlossomAuthEvent {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]).expect("test key should be valid");
        let mut event = BlossomAuthEvent {
            id: String::new(),
            pubkey: hex::encode(signing_key.verifying_key().to_bytes()),
            created_at,
            kind,
            tags,
            content: String::new(),
            sig: String::new(),
        };

        event.id = compute_event_id(&event).expect("event id should compute");
        let id_bytes = hex::decode(&event.id).expect("event id should be valid hex");
        let signature: Signature = signing_key
            .sign_prehash(&id_bytes)
            .expect("event id prehash should sign");
        event.sig = hex::encode(signature.to_bytes());
        event
    }
}
