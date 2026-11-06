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
    let request = upload_request(case != "invalid_auth");
    let mut record = UploadLogRecord::new(UploadRoute::DirectPut, "synthetic-routing".into(), 0);
    let error = handle_upload(request, &mut record)
        .expect_err("fixture backend fails; never fall back to GCS");
    match case.as_str() {
        "enabled" => {
            assert!(record.proxied_body);
            assert_eq!(record.origin_status, Some(503));
            assert!(error.message().contains("fixture busy"));
            assert_eq!(error.status_code(), StatusCode::BAD_GATEWAY);
        }
        "invalid" => {
            assert!(!record.proxied_body);
            assert_eq!(record.origin_status, None);
            assert_eq!(error.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        }
        "invalid_auth" => {
            assert!(!record.proxied_body);
            assert_eq!(record.origin_status, None);
            assert_eq!(error.status_code(), StatusCode::UNAUTHORIZED);
        }
        _ => panic!("unknown synthetic routing case"),
    }
}
