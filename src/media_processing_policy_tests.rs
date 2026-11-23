use super::*;

fn sample(hash: &str, allowed: bool) -> BlobMetadata {
    serde_json::from_value(serde_json::json!({
        "sha256": hash, "size": 10, "type": "video/mp4",
        "uploaded": "2026-01-01T00:00:00Z", "owner": "b".repeat(64),
        "status": "active", "video_encoding_allowed": allowed
    }))
    .unwrap()
}

fn response(request: Request) -> Response {
    handle_request(request).unwrap_or_else(|error| error_response(&error))
}

fn lookup(hash: &str, token: Option<&str>) -> Response {
    let mut req = Request::get(format!(
        "https://media.example.test/internal/media-policy/{hash}"
    ));
    if let Some(token) = token {
        req.set_header("Authorization", format!("Bearer {token}"));
    }
    response(req)
}

#[test]
fn media_policy_header_can_only_reduce_processing() {
    let mut req = Request::put("https://media.example.test/upload");
    assert!(upload_encoding_requested(&req).unwrap());
    req.set_header("X-Divine-Video-Processing", "copy-only");
    assert!(!upload_encoding_requested(&req).unwrap());
    for invalid in ["allow_encode", "Copy-only", "", "copy-only, allow_encode"] {
        req.set_header("X-Divine-Video-Processing", invalid);
        assert!(upload_encoding_requested(&req).is_err());
    }
}

#[test]
#[ignore = "requires synthetic Viceroy KV and webhook secret"]
fn media_policy_http_auth_retry_and_metadata_contract() {
    let hash = "1".repeat(64);
    assert_eq!(lookup(&hash, None).get_status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        lookup(&hash, Some("wrong")).get_status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        lookup("invalid", Some("synthetic-webhook")).get_status(),
        StatusCode::BAD_REQUEST
    );
    let missing = lookup(&hash, Some("synthetic-webhook"));
    assert_eq!(missing.get_status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(missing.get_header_str("Retry-After"), Some("5"));
    put_blob_metadata(&sample(&hash, true)).unwrap();
    let mut allowed = lookup(&hash, Some("synthetic-webhook"));
    assert_eq!(allowed.get_status(), StatusCode::OK);
    assert!(allowed
        .get_header_str("Cache-Control")
        .unwrap()
        .contains("no-store"));
    assert_eq!(
        allowed.get_header_str("Surrogate-Control"),
        Some("no-store")
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&allowed.take_body_str()).unwrap(),
        serde_json::json!({"sha256":hash,"policy":"allow_encode"})
    );
    // A cached allow response must not hide a later reduction in processing.
    put_blob_metadata(&sample(&hash, false)).unwrap();
    let mut copy = lookup(&hash, Some("synthetic-webhook"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&copy.take_body_str()).unwrap(),
        serde_json::json!({"sha256":hash,"policy":"copy_only"})
    );
}

#[test]
#[ignore = "requires synthetic Viceroy KV"]
fn media_policy_stale_writes_never_upgrade_or_erase_archive_policy() {
    let hash = "2".repeat(64);
    let stale_user_record = sample(&hash, true);
    put_blob_metadata(&stale_user_record).unwrap();
    let mut archive = sample(&hash, false);
    archive.archive_storage = Some(
        serde_json::from_value(serde_json::json!({
            "bucket":"synthetic", "key":hash, "file_id":"synthetic-version",
            "content_type":"video/mp4", "size":10
        }))
        .unwrap(),
    );
    put_blob_metadata(&archive).unwrap();
    put_blob_metadata(&stale_user_record).unwrap();
    let stored = get_blob_metadata_uncached(&hash).unwrap().unwrap();
    assert!(!stored.allows_video_encoding());
    assert!(stored.archive_storage.is_some());
    // A legacy record also cannot be upgraded by an overlapping new upload.
    let legacy = "3".repeat(64);
    put_blob_metadata(&sample(&legacy, false)).unwrap();
    put_blob_metadata(&sample(&legacy, true)).unwrap();
    assert!(
        !get_blob_metadata_uncached(&legacy)
            .unwrap()
            .unwrap()
            .video_encoding_allowed
    );
}

#[test]
#[ignore = "requires synthetic Viceroy KV and upload backend"]
fn media_policy_authenticated_upload_routes_and_duplicates() {
    for (index, route, copy_only, video) in [
        (4, "direct", false, true),
        (5, "direct", true, true),
        (6, "complete", false, true),
        (7, "complete", true, true),
        (8, "mirror", false, true),
        (9, "mirror", true, true),
    ] {
        let hash = format!("{index:x}").repeat(64);
        let authorized = crate::upload_routing_tests::upload_request(true);
        let auth = authorized
            .get_header(header::AUTHORIZATION)
            .unwrap()
            .clone();
        let mut request = match route {
            "complete" => Request::post("https://media.divine.video/upload/synthetic/complete")
                .with_body(serde_json::json!({"sha256":hash}).to_string()),
            "mirror" => Request::put("https://media.divine.video/mirror").with_body(
                serde_json::json!({"url":format!("https://synthetic.example/{hash}")}).to_string(),
            ),
            _ => Request::put("https://media.divine.video/upload").with_body(hash.clone()),
        };
        request.set_header(header::AUTHORIZATION, auth);
        request.set_header(
            "Content-Type",
            if video { "video/mp4" } else { "image/jpeg" },
        );
        request.set_header("Content-Length", "64");
        if copy_only {
            request.set_header("X-Divine-Video-Processing", "copy-only");
        }
        let result = response(request);
        assert_eq!(result.get_status(), StatusCode::OK, "{route} {copy_only}");
        let stored = get_blob_metadata_uncached(&hash).unwrap().unwrap();
        assert_eq!(stored.allows_video_encoding(), !copy_only && video);
        // Repeat the same media without opt-out; it must never upgrade policy.
        let mut duplicate = crate::upload_routing_tests::upload_request(true);
        duplicate.set_header("Content-Type", "video/mp4");
        duplicate.set_body(hash.clone());
        duplicate.set_header("Content-Length", "64");
        assert_eq!(response(duplicate).get_status(), StatusCode::OK);
        assert_eq!(
            get_blob_metadata_uncached(&hash)
                .unwrap()
                .unwrap()
                .allows_video_encoding(),
            !copy_only && video
        );
    }
    // Init cannot silently accept an opt-out that an old resumable service would lose.
    let authorized = crate::upload_routing_tests::upload_request(true);
    let mut init = Request::post("https://media.divine.video/upload/init");
    init.set_header(
        header::AUTHORIZATION,
        authorized.get_header(header::AUTHORIZATION).unwrap(),
    );
    init.set_header("X-Divine-Video-Processing", "copy-only");
    assert_eq!(response(init).get_status(), StatusCode::BAD_REQUEST);
}
