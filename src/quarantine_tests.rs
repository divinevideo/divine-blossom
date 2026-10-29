use super::*;

const HASH_BYTE: char = 'a';

fn hash() -> String {
    HASH_BYTE.to_string().repeat(64)
}

fn request(method: Method, path: &str, authenticated: bool) -> Request {
    let mut req = Request::new(method, format!("https://media.divine.video{path}"));
    if authenticated {
        req.set_header("Authorization", "Bearer synthetic-admin-token");
    }
    req
}

fn call(req: Request) -> Response {
    handle_request(req).unwrap_or_else(|error| error_response(&error))
}

fn change(action: &str, hold_id: &str) -> serde_json::Value {
    change_version(action, hold_id, if action == "hold" { 1 } else { 2 })
}

fn change_version(action: &str, hold_id: &str, version: u64) -> serde_json::Value {
    let mut req = request(Method::POST, "/admin/api/quarantine", true);
    req.set_body(
        serde_json::json!({"sha256": hash(), "hold_id": hold_id, "version": version, "action": action}).to_string(),
    );
    let mut resp = call(req);
    assert_eq!(resp.get_status(), StatusCode::OK);
    assert_eq!(
        resp.get_header_str("Cache-Control"),
        Some("private, no-store")
    );

    serde_json::from_str(&resp.take_body_str()).unwrap()
}

fn status() -> serde_json::Value {
    let mut resp = call(request(
        Method::GET,
        &format!("/admin/api/quarantine/{}", hash()),
        true,
    ));
    assert_eq!(resp.get_status(), StatusCode::OK);
    serde_json::from_str(&resp.take_body_str()).unwrap()
}

#[test]
fn quarantine_response_source_hashes_cover_public_media_only() {
    let sha = "c".repeat(64);
    for path in [
        format!("/{sha}"),
        format!("/{sha}.mp4"),
        format!("/{sha}.jpg"),
        format!("/{sha}.hls"),
        format!("/{sha}/hls/master.m3u8"),
        format!("/{sha}/hls/stream_720p.ts"),
        format!("/{sha}/720p.mp4"),
        format!("/{sha}/480p"),
        format!("/{sha}.vtt"),
        format!("/{sha}/VTT"),
        format!("/{sha}.audio.m4a"),
        format!("/v1/subtitles/by-hash/{sha}"),
    ] {
        assert_eq!(quarantine_source_hash(&path), Some(sha.clone()), "{path}");
        assert_eq!(
            quarantine_source_hash(&path.replace(&sha, &sha.to_uppercase())),
            Some(sha.clone())
        );
    }
    for path in [
        format!("/admin/api/blob/{sha}/content"),
        format!("/admin/api/blob/{sha}/720p.mp4"),
        format!("/{sha}/provenance"),
        format!("/{sha}0/hls/master.m3u8"),
        "/version".into(),
    ] {
        assert_eq!(quarantine_source_hash(&path), None, "{path}");
    }
}

fn late_quarantine_guard_contract() {
    let sha = "c".repeat(64);
    let key = format!("quarantine:v1:{sha}");
    let store = open_store().unwrap();
    // Simulate routing/origin work completing after state changes. In particular,
    // original and audio production HTTP cache transport is unavailable in Viceroy.
    for suffix in [
        "",
        ".mp4",
        ".jpg",
        ".hls",
        "/hls/master.m3u8",
        "/720p.mp4",
        ".vtt",
        "/VTT",
        ".audio.m4a",
    ] {
        for method in [Method::GET, Method::HEAD] {
            for admin in [false, true] {
                let path = format!("/{sha}{suffix}");
                let result =
                    with_quarantine_response_guard(request(method.clone(), &path, admin), |_| {
                        store
                        .insert(
                            &key,
                            r#"{"version":1,"holds":{"review:late":{"version":1,"active":true}}}"#,
                        )
                        .unwrap();
                        Ok(Response::from_status(StatusCode::PARTIAL_CONTENT)
                            .with_header("Surrogate-Control", "max-age=31536000")
                            .with_body("synthetic bytes that must be dropped"))
                    });
                assert!(
                    matches!(result, Err(BlossomError::NotFound(_))),
                    "{method} {path} admin={admin}"
                );
            }
        }
    }
    let result =
        with_quarantine_response_guard(request(Method::GET, &format!("/{sha}.mp4"), false), |_| {
            store.insert(&key, "malformed".to_string()).unwrap();
            Ok(Response::from_status(StatusCode::OK).with_body("must be dropped"))
        });
    assert!(matches!(result, Err(BlossomError::MetadataError(_))));
    // Failure in the final read must not retain headers from the origin response.
    let error = error_response(&result.unwrap_err());
    assert_eq!(error.get_status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_ne!(
        error.get_header_str("Surrogate-Control"),
        Some("max-age=31536000")
    );
    let mut preview = with_quarantine_response_guard(
        request(Method::GET, &format!("/{sha}/720p.mp4"), true),
        |_| {
            let mut response = Response::from_status(StatusCode::OK).with_body("private preview");
            add_private_cache_headers(&mut response, &sha);
            Ok(response)
        },
    )
    .unwrap();
    assert_eq!(
        preview.get_header_str("Cache-Control"),
        Some("private, no-store")
    );
    assert_eq!(preview.take_body_str(), "private preview");
}

#[test]
#[ignore = "requires the synthetic local KV/storage configuration in run-quarantine-tests.py"]
fn quarantine_hold_http_contract() {
    late_quarantine_guard_contract();
    let store = open_store().unwrap();
    let key = format!("blob:{}", hash());
    let base = serde_json::json!({"sha256": hash(), "size": 10, "type": "video/mp4",
        "owner": "b".repeat(64), "uploaded": "2026-01-01T00:00:00Z", "status": "active"});
    store.insert(&key, base.to_string()).unwrap();
    assert_eq!(
        get_blob_metadata(&hash())
            .unwrap()
            .unwrap()
            .access_for(None, false),
        BlobAccess::Allowed
    );

    let unauthorized = call(request(Method::POST, "/admin/api/quarantine", false));
    assert_eq!(unauthorized.get_status(), StatusCode::UNAUTHORIZED);
    assert_eq!(status()["base_status"], "active");

    assert_eq!(change("hold", "review:first")["quarantined"], true);
    assert_eq!(
        change("hold", "review:second")["hold_ids"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        change("hold", "review:first")["hold_ids"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(status()["effective_status"], "quarantined");
    assert_eq!(
        call(request(
            Method::GET,
            &format!("/admin/api/quarantine/{}", hash()),
            false
        ))
        .get_status(),
        StatusCode::UNAUTHORIZED
    );
    let canary = crate::canary::handle(Request::get(format!(
        "https://media-b2.divine.video/{}",
        hash()
    )));
    assert!(matches!(canary, Err(BlossomError::NotFound(_))));
    let raw: serde_json::Value =
        serde_json::from_str(&store.lookup(&key).unwrap().take_body().into_string()).unwrap();
    assert_eq!(raw["status"], "active");
    assert!(raw.get("quarantine_hold_ids").is_none());

    let paths = [
        format!("/{}.mp4", hash()),
        format!("/{}.jpg", hash()),
        format!("/{}.hls", hash()),
        format!("/{}/hls/master.m3u8", hash()),
        format!("/{}/hls/stream_720p.ts", hash()),
        format!("/{}/720p.mp4", hash()),
        format!("/{}.vtt", hash()),
        format!("/{}.audio.m4a", hash()),
    ];
    for path in paths {
        for method in [Method::GET, Method::HEAD] {
            let mut req = request(method.clone(), &path, false);
            req.set_header("Range", "bytes=1-3");
            assert_eq!(
                call(req).get_status(),
                StatusCode::NOT_FOUND,
                "{method} {path}"
            );
        }
    }
    let owner = "b".repeat(64);
    assert_eq!(
        get_blob_metadata(&hash())
            .unwrap()
            .unwrap()
            .access_for(Some(&owner), false),
        BlobAccess::NotFound
    );

    let mut preview = request(
        Method::GET,
        &format!("/admin/api/blob/{}/720p.mp4", hash()),
        true,
    );
    preview.set_header("Range", "bytes=1-3");
    let mut resp = call(preview);
    assert_eq!(
        resp.get_status(),
        StatusCode::PARTIAL_CONTENT,
        "{}",
        resp.take_body_str()
    );
    assert_eq!(
        resp.get_header_str("Cache-Control"),
        Some("private, no-store")
    );

    // This is the exact original-byte route used by the reviewer proxy, with no
    // transcode metadata or quality derivative required. Viceroy's unsupported
    // HTTP cache transport is bypassed only within this test scope.
    let original_path = format!("/admin/api/blob/{}/content", hash());
    assert_eq!(
        call(request(Method::GET, &original_path, false)).get_status(),
        StatusCode::UNAUTHORIZED
    );
    let mut cache_probe =
        Request::get("https://storage.googleapis.com/quarantine-test/original-cache-probe");
    cache_probe.set_before_send(|_| Ok(()));
    let cache_error = cache_probe
        .send("gcs_storage")
        .expect_err("Viceroy 0.20.1 has no HTTP cache host calls");
    assert!(matches!(
        cache_error.root_cause(),
        fastly::http::request::SendErrorCause::HttpCacheApiUnsupported
    ));
    crate::storage::with_uncached_storage_for_test(|| {
        let mut original = call(request(Method::GET, &original_path, true));
        assert_eq!(original.get_status(), StatusCode::OK);
        assert_eq!(
            original.get_header_str("Cache-Control"),
            Some("private, no-store")
        );
        assert_eq!(
            original.get_header_str("Surrogate-Control"),
            Some("no-store")
        );
        assert_eq!(original.take_body_str(), "0123456789");
        let mut range = request(Method::GET, &original_path, true);
        range.set_header("Range", "bytes=1-3");
        let mut range = call(range);
        assert_eq!(range.get_status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(range.get_header_str("Content-Range"), Some("bytes 1-3/10"));
        assert_eq!(
            range.get_header_str("Cache-Control"),
            Some("private, no-store")
        );
        assert_eq!(range.take_body_str(), "123");
    });

    assert_eq!(
        change("release", "review:first")["hold_ids"],
        serde_json::json!(["review:second"])
    );
    assert_eq!(change("release", "review:first")["quarantined"], true);
    update_blob_status(&hash(), BlobStatus::AgeRestricted).unwrap();
    assert_eq!(status()["base_status"], "age_restricted");
    assert_eq!(
        change("release", "review:second")["effective_status"],
        "age_restricted"
    );
    assert_eq!(
        get_blob_metadata(&hash())
            .unwrap()
            .unwrap()
            .access_for(None, false),
        BlobAccess::AgeGated
    );

    for base_status in [
        BlobStatus::Banned,
        BlobStatus::Deleted,
        BlobStatus::Restricted,
    ] {
        update_blob_status(&hash(), base_status).unwrap();
        let id = format!("review:{}", base_status.as_api_str());
        change("hold", &id);
        change("release", &id);
        assert_eq!(
            get_blob_metadata(&hash()).unwrap().unwrap().status,
            base_status
        );
        assert_eq!(status()["effective_status"], base_status.as_api_str());
    }

    change_version("release", "review:release-first", 4);
    let late = change_version("hold", "review:release-first", 3);
    assert_eq!(late["quarantined"], false);
    let released = late["holds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["hold_id"] == "review:release-first")
        .unwrap();
    assert_eq!(released["version"], 4);
    assert_eq!(released["active"], false);
    let mut conflicting = request(Method::POST, "/admin/api/quarantine", true);
    conflicting.set_body(
        serde_json::json!({"sha256": hash(), "hold_id": "review:release-first",
        "version": 4, "action": "hold"})
        .to_string(),
    );
    assert_eq!(call(conflicting).get_status(), StatusCode::CONFLICT);

    for version in [
        serde_json::json!(0),
        serde_json::json!(-1),
        serde_json::json!(1.5),
        serde_json::json!(9_007_199_254_740_992u64),
    ] {
        let mut invalid = request(Method::POST, "/admin/api/quarantine", true);
        invalid.set_body(serde_json::json!({"sha256": hash(), "hold_id": "review:invalid", "version": version, "action": "hold"}).to_string());
        assert_eq!(call(invalid).get_status(), StatusCode::BAD_REQUEST);
    }

    let mut absent = request(Method::POST, "/admin/api/quarantine", true);
    absent.set_body(serde_json::json!({"sha256": "d".repeat(64), "hold_id": "review:absent", "version": 1, "action": "hold"}).to_string());
    let mut absent = call(absent);
    assert_eq!(absent.get_status(), StatusCode::OK);
    let absent: serde_json::Value = serde_json::from_str(&absent.take_body_str()).unwrap();
    assert!(absent["base_status"].is_null());
    assert_eq!(absent["effective_status"], "quarantined");

    let holds_key = format!("quarantine:v1:{}", hash());
    store.insert(&holds_key, "malformed".to_string()).unwrap();
    assert!(
        get_blob_metadata(&hash()).is_err(),
        "warm metadata must not bypass invalid holds"
    );
    assert!(get_blob_metadata_uncached(&hash()).is_err());
    assert_eq!(
        call(request(Method::GET, &format!("/{}.mp4", hash()), false)).get_status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}
