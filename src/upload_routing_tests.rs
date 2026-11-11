//! Loopback-only canonical upload routing integration (no provider credentials).
use super::*;
use base64::Engine;
use k256::schnorr::{signature::hazmat::PrehashSigner, Signature, SigningKey};

fn upload_request(authenticated: bool) -> Request {
    let body = b"synthetic image";
    let mut request = Request::put("https://media.divine.video/upload");
    request.set_header("Content-Type", "image/jpeg");
    request.set_header("Content-Length", body.len().to_string());
    request.set_body(body.as_slice());
    if authenticated {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let key = SigningKey::from_bytes(&[7u8; 32]).unwrap();
        let mut event = blossom::BlossomAuthEvent {
            id: String::new(),
            pubkey: hex::encode(key.verifying_key().to_bytes()),
            created_at: now,
            kind: 24242,
            tags: vec![
                vec!["t".into(), "upload".into()],
                vec!["expiration".into(), (now + 300).to_string()],
            ],
            content: String::new(),
            sig: String::new(),
        };
        let serialized = serde_json::to_vec(&serde_json::json!([
            0,
            event.pubkey,
            now,
            24242,
            event.tags,
            ""
        ]))
        .unwrap();
        event.id = hex::encode(Sha256::digest(serialized));
        let signature: Signature = key.sign_prehash(&hex::decode(&event.id).unwrap()).unwrap();
        event.sig = hex::encode(signature.to_bytes());
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&event).unwrap());
        request.set_header("Authorization", format!("Nostr {encoded}"));
    }
    request
}

#[test]
#[ignore = "loopback config/backend fixtures; scripts/run-upload-routing-tests.py"]
fn canonical_upload_routing_contract() {
    let settings = fastly::config_store::ConfigStore::open("routing_test");
    let case = settings.get("test_case").unwrap();
    if case == "default" || case == "disabled" {
        assert!(!should_proxy_direct_upload(15, "image/jpeg").unwrap());
        assert!(should_proxy_direct_upload(512_001, "image/jpeg").unwrap());
        assert!(should_proxy_direct_upload(15, "video/mp4").unwrap());
        return;
    }
    if case == "missing_store" {
        assert!(should_proxy_direct_upload(15, "image/jpeg").is_err());
        return;
    }
    if case == "dedupe" {
        let hash = hex::encode(Sha256::digest(b"synthetic image"));
        let store = crate::metadata::open_store().unwrap();
        let auth = validate_auth(&upload_request(true), AuthAction::Upload).unwrap();
        for status in ["active", "deleted"] {
            let value = serde_json::json!({"sha256": hash, "size": 15, "type": "image/jpeg", "uploaded": "2026-01-01T00:00:00Z", "owner": "b".repeat(64), "status": status}).to_string();
            let key = format!("blob:{hash}");
            store.insert(&key, value.as_str()).unwrap();
            let generation = store.lookup(&key).unwrap().current_generation();
            let upload = UploadServicePublishedUpload {
                sha256: hash.clone(),
                size: 15,
                content_type: "image/jpeg".into(),
                thumbnail_url: Some("https://media.divine.video/synthetic.jpg".into()),
                dim: Some("40x30".into()),
                transcode_observation: DerivativeObservation::Unavailable,
                transcode_error_code: None,
                transcode_error_message: None,
                transcode_terminal: false,
                transcript_observation: DerivativeObservation::Unavailable,
                transcript_error_code: None,
                transcript_error_message: None,
                transcript_terminal: false,
            };
            publish_upload_service_upload_with_policy(
                auth.clone(),
                "https://media.divine.video".into(),
                upload,
                true,
            )
            .unwrap();
            let mut after = store.lookup(&key).unwrap();
            assert_eq!(
                after.current_generation(),
                generation,
                "image dedupe must not rewrite stale policy"
            );
            assert_eq!(after.take_body().into_string(), value);
        }
        return;
    }
    let mut request = upload_request(case != "invalid_auth");
    if case == "bad_size" {
        request.set_body(vec![0u8; 512_002]);
        request.set_header("Content-Length", "15");
    }
    let mut record = UploadLogRecord::new(UploadRoute::DirectPut, "synthetic-routing".into(), 0);
    let error = handle_upload(request, &mut record)
        .expect_err("fixture backend fails; never fall back to GCS");
    match case.as_str() {
        "enabled" | "busy_retry_date" | "busy_invalid_retry_after" | "busy_without_retry_after" => {
            assert!(record.proxied_body);
            assert_eq!(record.origin_status, Some(503));
            record_failure(&mut record, &error);
            assert_eq!(record.response_status, 503);
            assert_eq!(record.error_kind, Some("service_unavailable"));

            let expected_retry = match case.as_str() {
                "enabled" => Some("5"),
                "busy_retry_date" => Some("Wed, 11 Nov 2026 00:00:00 GMT"),
                _ => None,
            };
            let mut response = error_response(&error);
            assert_eq!(response.get_status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.get_header_str("Retry-After"), expected_retry);
            assert_eq!(response.get_header_str("Cache-Control"), Some("no-store"));
            assert_eq!(
                response.get_header_str("Content-Type"),
                Some("application/json")
            );
            assert_eq!(
                response.get_header_str("Access-Control-Allow-Origin"),
                Some("*")
            );
            assert!(response
                .get_header_str("Access-Control-Expose-Headers")
                .unwrap()
                .split(", ")
                .any(|name| name == "Retry-After"));
            let body: serde_json::Value =
                serde_json::from_str(&response.take_body().into_string()).unwrap();
            let expected_error = if case == "busy_without_retry_after" {
                "Upload service unavailable"
            } else {
                "fixture busy"
            };
            assert_eq!(body, serde_json::json!({ "error": expected_error }));
        }
        "origin_error" => {
            assert!(record.proxied_body);
            assert_eq!(record.origin_status, Some(500));
            assert_eq!(error.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(error_response(&error).get_header_str("Retry-After"), None);
        }
        "invalid" => {
            assert!(!record.proxied_body);
            assert_eq!(record.origin_status, None);
            assert_eq!(error.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        }
        "tombstone" => {
            assert!(
                !record.proxied_body,
                "tombstoned bytes must not reach storage"
            );
            assert_eq!(record.origin_status, None);
            assert_eq!(error.status_code(), StatusCode::FORBIDDEN);
        }
        "missing_policy" => {
            assert!(!record.proxied_body);
            assert_eq!(record.origin_status, None);
            assert_eq!(error.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        }
        "bad_size" => {
            assert!(!record.proxied_body);
            assert_eq!(record.origin_status, None);
            assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);
        }
        "hash_mismatch" => {
            assert!(record.proxied_body);
            assert_eq!(record.origin_status, Some(200));
            assert!(error.message().contains("different content hash"));
        }
        "invalid_auth" => {
            assert!(!record.proxied_body);
            assert_eq!(record.origin_status, None);
            assert_eq!(error.status_code(), StatusCode::UNAUTHORIZED);
        }
        _ => panic!("unknown synthetic routing case"),
    }
}
