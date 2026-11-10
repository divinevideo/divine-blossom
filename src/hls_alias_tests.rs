use super::*;

fn response(request: Request) -> Response {
    handle_request(request).unwrap_or_else(|error| error_response(&error))
}

fn metadata(hash: &str, status: &str, transcode: &str) {
    let value: BlobMetadata = serde_json::from_value(serde_json::json!({
        "sha256": hash, "size": 10, "type": "video/mp4",
        "uploaded": "2026-01-01T00:00:00Z", "owner": "b".repeat(64),
        "status": status, "transcode_status": transcode
    }))
    .unwrap();
    put_blob_metadata(&value).unwrap();
}

#[test]
#[ignore = "requires local synthetic metadata and HLS origin"]
fn hls_alias_relative_playlist_http_contract() {
    let hash = "a".repeat(64);
    metadata(&hash, "active", "complete");
    let alias = format!("https://media.example.test/{hash}.hls");
    let initial = response(Request::get(&alias));
    let status = initial.get_status();
    assert_eq!(
        initial.get_header_str("Access-Control-Allow-Origin"),
        Some("*")
    );
    assert!(initial
        .get_header_str("Cache-Control")
        .unwrap()
        .contains("public"));
    assert_eq!(status, StatusCode::OK);
    assert!(initial.get_header_str("Location").is_none());
    assert!(initial.get_header_str("ETag").is_none());
    let base = Request::get(&alias).get_url().clone();
    let mut master = initial;
    assert_eq!(master.get_status(), StatusCode::OK);
    let body = master.take_body_str();
    assert!(body.starts_with("#EXTM3U"));
    let variant = body
        .lines()
        .find(|line| !line.starts_with('#') && !line.is_empty())
        .unwrap();
    // Exercise standard URL resolution against the actual handler response.
    let variant = base.join(variant).unwrap();
    assert!(
        variant.path().starts_with(&format!("/{hash}/hls/")),
        "playlist escaped its video directory: {variant}"
    );
    assert_eq!(status, StatusCode::OK);
    let mut playlist = response(Request::get(variant.as_str()));
    assert_eq!(playlist.get_status(), StatusCode::OK);
    let body = playlist.take_body_str();
    let segment = body
        .lines()
        .find(|line| !line.starts_with('#') && !line.is_empty())
        .unwrap();
    let segment = variant.join(segment).unwrap();
    assert!(segment.path().starts_with(&format!("/{hash}/hls/")));
    let mut segment = response(Request::get(segment.as_str()));
    assert_eq!(segment.get_status(), StatusCode::OK);
    assert_eq!(segment.take_body_bytes(), b"segment-bytes");
    let mut request = Request::get(format!("https://media.example.test/{hash}/480p.mp4"));
    request.set_header("Range", "bytes=0-3");
    let mut segment = response(request);
    assert_eq!(segment.get_status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        segment.get_header_str("Content-Range"),
        Some("bytes 0-3/13")
    );
    assert_eq!(segment.take_body_bytes(), b"segm");

    let mut canonical = response(Request::get(format!(
        "https://media.example.test/{hash}/hls/master.m3u8"
    )));
    assert_eq!(canonical.get_status(), StatusCode::OK);
    assert!(canonical.take_body_str().contains("\nstream_480p.m3u8\n"));

    // Rewriting is not an access grant; denied requests never reach the origin.
    metadata(&hash, "banned", "complete");
    assert_eq!(
        response(Request::get(&alias)).get_status(),
        StatusCode::NOT_FOUND
    );
    let mut admin = Request::get(&alias);
    admin.set_header("Authorization", "Bearer synthetic-admin-token");
    let admin = response(admin);
    assert_eq!(admin.get_status(), StatusCode::OK);
    assert!(admin
        .get_header_str("Cache-Control")
        .unwrap()
        .contains("private"));

    let pending = "c".repeat(64);
    metadata(&pending, "active", "processing");
    let pending = response(Request::get(format!(
        "https://media.example.test/{pending}.hls"
    )));
    assert_eq!(pending.get_status(), StatusCode::ACCEPTED);
    assert!(pending.get_header_str("Location").is_none());
}

#[test]
#[ignore = "requires local synthetic metadata and HLS origin"]
fn hls_alias_url_bound_viewer_http_contract() {
    use base64::Engine;
    use k256::schnorr::{signature::hazmat::PrehashSigner, SigningKey};
    let key = SigningKey::from_bytes(&[7u8; 32]).unwrap();
    let owner = hex::encode(key.verifying_key().to_bytes());
    let hash = "a".repeat(64);
    let alias = format!("https://media.example.test/{hash}.hls");
    for status in ["age_restricted", "restricted"] {
        let value: BlobMetadata = serde_json::from_value(serde_json::json!({
            "sha256": hash, "size": 10, "type": "video/mp4", "owner": owner,
            "uploaded": "2026-01-01T00:00:00Z", "status": status,
            "transcode_status": "complete"
        }))
        .unwrap();
        put_blob_metadata(&value).unwrap();
        let now = unix_timestamp_secs();
        let mut event = crate::blossom::BlossomAuthEvent {
            id: String::new(),
            pubkey: owner.clone(),
            created_at: now,
            kind: 27235,
            tags: vec![
                vec!["u".into(), alias.clone()],
                vec!["method".into(), "GET".into()],
            ],
            content: String::new(),
            sig: String::new(),
        };
        let canonical = serde_json::json!([0, event.pubkey, now, 27235, event.tags, ""]);
        let id = Sha256::digest(serde_json::to_vec(&canonical).unwrap());
        let signature: k256::schnorr::Signature = key.sign_prehash(&id).unwrap();
        event.id = hex::encode(id);
        event.sig = hex::encode(signature.to_bytes());
        let mut request = Request::get(&alias);
        request.set_header(
            "Authorization",
            format!(
                "Nostr {}",
                base64::engine::general_purpose::STANDARD
                    .encode(serde_json::to_vec(&event).unwrap())
            ),
        );
        let mut response = response(request);
        assert_eq!(
            response.get_status(),
            StatusCode::OK,
            "URL-bound viewer must receive the alias manifest without re-signing a redirect"
        );
        assert!(response
            .get_header_str("Cache-Control")
            .unwrap()
            .contains("private"));
        assert!(response.get_header_str("Location").is_none());
        assert!(response
            .take_body_str()
            .contains(&format!("/{hash}/hls/stream_480p.m3u8")));
    }
}
