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
#[ignore = "requires failing then recovering local purge backend"]
fn pending_cdn_intent_cannot_clear_when_purge_configuration_disappears() {
    let store = open_store().unwrap();
    let token = b2_cdn_purge::begin(&hash()).unwrap();
    assert_eq!(b2_cdn_purge::commit(&store, &token).unwrap(), b2_cdn_purge::CommitOutcome::Committed);
    let mut response = call(request(Method::POST, "/admin/api/b2-cdn-purge/drain?max=1", true));
    assert_eq!(response.get_status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&response.take_body_str()).unwrap();
    assert_eq!(body["result"], 0);
    assert_eq!(body["errors"], 1);
    assert_eq!(body["pending"], 1);
    let entries = store.build_list().prefix("b2-cdn-purge").execute().unwrap();
    for key in entries.keys() {
        let mut entry = store.lookup(key).unwrap();
        let value: serde_json::Value = serde_json::from_str(&entry.take_body().into_string()).unwrap();
        assert_eq!(value["state"], "committed");
    }
}

#[test]
#[ignore = "requires failing then recovering local purge backend"]
fn restore_without_cdn_keeps_existing_non_deleted_rejection() {
    let metadata: BlobMetadata = serde_json::from_value(serde_json::json!({
        "sha256": hash(), "size": 9, "type": "video/mp4", "uploaded": "2026-01-01T00:00:00Z",
        "owner": "b".repeat(64), "status": "active"
    })).unwrap();
    put_blob_metadata(&metadata).unwrap();
    let mut req = request(Method::POST, "/admin/api/restore", true);
    req.set_body(serde_json::json!({"sha256": hash()}).to_string());
    assert_eq!(call(req).get_status(), StatusCode::BAD_REQUEST);
}

#[test]
#[ignore = "requires failing then recovering local purge backend"]
fn bulk_approve_skip_purge_reports_durable_pending_hashes() {
    let metadata: BlobMetadata = serde_json::from_value(serde_json::json!({
        "sha256": hash(), "size": 9, "type": "video/mp4", "uploaded": "2026-01-01T00:00:00Z",
        "owner": "b".repeat(64), "status": "banned"
    })).unwrap();
    put_blob_metadata(&metadata).unwrap();
    let mut req = request(Method::POST, "/admin/api/bulk-approve", true);
    req.set_body(serde_json::json!({"hashes": [hash()], "skip_purge": true}).to_string());
    let mut response = call(req);
    assert_eq!(response.get_status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&response.take_body_str()).unwrap();
    assert_eq!(body["cdn_purge_pending_hashes"], serde_json::json!([hash()]));
    let store = open_store().unwrap();
    assert!(!store.build_list().prefix("b2-cdn-purge").execute().unwrap().keys().is_empty());
}

#[test]
#[ignore = "requires failing then recovering local purge backend"]
fn soft_delete_cdn_failure_cannot_be_acknowledged_before_eviction() {
    let metadata: BlobMetadata = serde_json::from_value(serde_json::json!({
        "sha256": hash(), "size": 9, "type": "video/mp4", "uploaded": "2026-01-01T00:00:00Z",
        "owner": "b".repeat(64), "status": "active"
    })).unwrap();
    put_blob_metadata(&metadata).unwrap();
    let mutate = || {
        let mut req = request(Method::POST, "/admin/api/moderate", true);
        req.set_body(serde_json::json!({"sha256": hash(), "action": "DELETE"}).to_string());
        call(req)
    };
    assert_eq!(mutate().get_status(), StatusCode::BAD_GATEWAY);
    assert_eq!(get_blob_metadata_uncached(&hash()).unwrap().unwrap().status, BlobStatus::Deleted);
    assert_eq!(mutate().get_status(), StatusCode::OK);
    assert_eq!(mutate().get_status(), StatusCode::OK);
}

#[test]
#[ignore = "requires failing then recovering local purge backend"]
fn restore_cdn_failure_keeps_durable_retry_after_status_commits() {
    let metadata: BlobMetadata = serde_json::from_value(serde_json::json!({
        "sha256": hash(), "size": 9, "type": "video/mp4", "uploaded": "2026-01-01T00:00:00Z",
        "owner": "b".repeat(64), "status": "deleted"
    })).unwrap();
    put_blob_metadata(&metadata).unwrap();
    let mutate = || {
        let mut req = request(Method::POST, "/admin/api/restore", true);
        req.set_body(serde_json::json!({"sha256": hash()}).to_string());
        call(req)
    };
    assert_eq!(mutate().get_status(), StatusCode::BAD_GATEWAY);
    assert_eq!(get_blob_metadata_uncached(&hash()).unwrap().unwrap().status, BlobStatus::Active);
    assert_eq!(mutate().get_status(), StatusCode::OK);
    assert_eq!(mutate().get_status(), StatusCode::OK);
}

#[test]
#[ignore = "requires failing then recovering local purge backend"]
fn cdn_purge_drain_requires_admin_and_rejects_oversized_batches() {
    for method in [Method::GET, Method::POST] {
        assert_eq!(call(request(method, "/admin/api/b2-cdn-purge/drain", false)).get_status(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(call(request(Method::GET, "/admin/api/b2-cdn-purge/drain", true)).get_status(), StatusCode::BAD_REQUEST);
    assert_eq!(call(request(Method::POST, "/admin/api/b2-cdn-purge/drain?max=3", true)).get_status(), StatusCode::BAD_REQUEST);
}

#[test]
#[ignore = "requires failing then recovering local purge backend"]
fn moderation_cdn_purge_failure_is_durable_and_same_status_retry_purges() {
    let metadata: BlobMetadata = serde_json::from_value(serde_json::json!({
        "sha256": hash(), "size": 9, "type": "video/mp4", "uploaded": "2026-01-01T00:00:00Z",
        "owner": "b".repeat(64), "status": "active"
    })).unwrap();
    put_blob_metadata(&metadata).unwrap();
    let mutate = |action: &str| {
        let mut req = request(Method::POST, "/admin/api/moderate", true);
        req.set_body(serde_json::json!({"sha256": hash(), "action": action}).to_string());
        call(req)
    };
    assert_eq!(mutate("BAN").get_status(), StatusCode::BAD_GATEWAY);
    assert_eq!(get_blob_metadata_uncached(&hash()).unwrap().unwrap().status, BlobStatus::Banned);
    let store = open_store().unwrap();
    assert!(!store.build_list().prefix("b2-cdn-purge").execute().unwrap().keys().is_empty());
    // The already-banned status must not skip a previously failed purge.
    assert_eq!(mutate("BAN").get_status(), StatusCode::OK);
    assert_eq!(mutate("APPROVE").get_status(), StatusCode::OK);
    assert_eq!(get_blob_metadata_uncached(&hash()).unwrap().unwrap().status, BlobStatus::Active);
}

#[test]
#[ignore = "requires failing then recovering local purge backend"]
fn quarantine_cdn_purge_failure_remains_denied_and_idempotently_retries() {
    let mutate = |action: &str, version: u64| {
        let mut req = request(Method::POST, "/admin/api/quarantine", true);
        req.set_body(serde_json::json!({
            "sha256": hash(), "hold_id": "synthetic", "version": version, "action": action
        }).to_string());
        call(req)
    };
    assert_eq!(mutate("hold", 1).get_status(), StatusCode::BAD_GATEWAY);
    assert_eq!(status()["quarantined"], true);
    let store = open_store().unwrap();
    let pending = store.build_list().prefix("b2-cdn-purge").execute().unwrap();
    assert!(!pending.keys().is_empty(), "failed purge lost durable retry discovery");
    for key in pending.keys() {
        let mut entry = store.lookup(key).unwrap();
        let value: serde_json::Value = serde_json::from_str(&entry.take_body().into_string()).unwrap();
        assert_eq!(value["state"], "committed");
    }
    // The state mutation is idempotent, but a failed invalidation is not an ack.
    assert_eq!(mutate("hold", 1).get_status(), StatusCode::OK);
    assert_eq!(status()["quarantined"], true);
    assert_eq!(mutate("release", 2).get_status(), StatusCode::OK);
    assert_eq!(status()["quarantined"], false);
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
        format!("/{sha}/sound"),
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

    let full_hash = "e".repeat(64);
    let full_key = format!("quarantine:v1:{full_hash}");
    let entries: serde_json::Map<String, serde_json::Value> = (0..128)
        .map(|index| {
            (
                format!("review:{index}"),
                serde_json::json!({"version": 2, "active": false}),
            )
        })
        .collect();
    let full_record = serde_json::json!({"version": 1, "holds": entries}).to_string();
    store.insert(&full_key, full_record.clone()).unwrap();
    let mut overflow = request(Method::POST, "/admin/api/quarantine", true);
    overflow.set_body(serde_json::json!({"sha256": full_hash, "hold_id": "review:new", "version": 1, "action": "hold"}).to_string());
    assert_eq!(call(overflow).get_status(), StatusCode::CONFLICT);
    assert_eq!(
        store.lookup(&full_key).unwrap().take_body().into_string(),
        full_record
    );
    let mut existing = request(Method::POST, "/admin/api/quarantine", true);
    existing.set_body(serde_json::json!({"sha256": full_hash, "hold_id": "review:0", "version": 3, "action": "hold"}).to_string());
    let mut existing = call(existing);
    assert_eq!(existing.get_status(), StatusCode::OK);
    let existing: serde_json::Value = serde_json::from_str(&existing.take_body_str()).unwrap();
    assert_eq!(existing["hold_ids"], serde_json::json!(["review:0"]));

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

#[test]
#[ignore = "requires failing then recovering local purge backend"]
fn creator_physical_delete_waits_for_final_purge_without_replaying_absent_bytes() {
    let metadata: BlobMetadata = serde_json::from_value(serde_json::json!({
        "sha256": hash(), "size": 9, "type": "video/mp4", "uploaded": "2026-01-01T00:00:00Z",
        "owner": "b".repeat(64), "status": "active"
    })).unwrap();
    put_blob_metadata(&metadata).unwrap();
    let epoch = storage::begin_vanish_phase(&hash()).unwrap().unwrap();
    b2_cdn_phase::record_physical(&hash(), &epoch, b2_cdn_phase::Physical::Absent).unwrap();
    let result = delete_policy::handle_creator_delete(&hash(), &metadata, "synthetic", true, "synthetic");
    assert!(matches!(result, Err(BlossomError::Conflict(_))), "must report pending final purge, never replay physical or purge inline: {result:?}");
    assert_eq!(get_blob_metadata_uncached(&hash()).unwrap().unwrap().status, BlobStatus::Deleted);
    let store = open_store().unwrap();
    assert!(b2_cdn_phase::mark_final_purged(&store, &hash(), &epoch).unwrap());
    let deleted = get_blob_metadata_uncached(&hash()).unwrap().unwrap();
    let result = delete_policy::handle_creator_delete(&hash(), &deleted, "synthetic", true, "synthetic").unwrap();
    assert!(result.physical_deleted);
}

#[test]
#[ignore = "requires failing then recovering local purge backend"]
fn creator_physical_delete_retains_audio_discovery_until_both_final_receipts() {
    let metadata: BlobMetadata = serde_json::from_value(serde_json::json!({
        "sha256": hash(), "size": 9, "type": "video/mp4", "uploaded": "2026-01-01T00:00:00Z",
        "owner": "b".repeat(64), "status": "active"
    })).unwrap();
    put_blob_metadata(&metadata).unwrap();
    let audio = "c".repeat(64);
    metadata::put_audio_mapping(&blossom::AudioMapping {
        source_sha256: hash(), audio_sha256: audio.clone(), duration_seconds: 6.0,
        size_bytes: 3, mime_type: "audio/aac".into(),
    }).unwrap();
    let store = open_store().unwrap();
    for candidate in [&hash(), &audio] {
        let epoch = storage::begin_vanish_phase(candidate).unwrap().unwrap();
        b2_cdn_phase::record_physical(candidate, &epoch, b2_cdn_phase::Physical::Absent).unwrap();
        if candidate != &audio {
            b2_cdn_phase::ensure_final_intent(candidate).unwrap();
            assert!(b2_cdn_phase::mark_final_purged(&store, candidate, &epoch).unwrap());
        }
    }
    assert!(matches!(delete_policy::handle_creator_delete(&hash(), &metadata, "synthetic", true, "synthetic"), Err(BlossomError::Conflict(_))));
    assert!(metadata::get_audio_mapping(&hash()).unwrap().is_some(), "retry must still discover audio awaiting final purge");
    let epoch = b2_cdn_phase::epoch(&audio).unwrap().unwrap();
    assert!(b2_cdn_phase::mark_final_purged(&store, &audio, &epoch).unwrap());
    let deleted = get_blob_metadata_uncached(&hash()).unwrap().unwrap();
    assert!(delete_policy::handle_creator_delete(&hash(), &deleted, "synthetic", true, "synthetic").unwrap().physical_deleted);
    assert!(metadata::get_audio_mapping(&hash()).unwrap().is_none());
}

#[test]
#[ignore = "requires failing then recovering local purge backend"]
fn creator_physical_delete_unreadable_phase_fails_before_policy_mutation() {
    let metadata: BlobMetadata = serde_json::from_value(serde_json::json!({
        "sha256": hash(), "size": 9, "type": "video/mp4", "uploaded": "2026-01-01T00:00:00Z",
        "owner": "b".repeat(64), "status": "active"
    })).unwrap();
    put_blob_metadata(&metadata).unwrap();
    open_store().unwrap().insert(&format!("b2-cdn-phase:v1:{}", hash()), "{foreign}").unwrap();
    assert!(delete_policy::handle_creator_delete(&hash(), &metadata, "synthetic", true, "synthetic").is_err());
    assert_eq!(get_blob_metadata_uncached(&hash()).unwrap().unwrap().status, BlobStatus::Active);
}

#[test]
#[ignore = "requires failing then recovering local purge backend"]
fn cdn_drain_service_token_is_not_an_admin_credential() {
    let mut drain = request(Method::POST, "/admin/api/b2-cdn-purge/drain?max=2", false);
    drain.set_header("Authorization", "Bearer synthetic-drain-token");
    assert_eq!(call(drain).get_status(), StatusCode::OK);
    let mut moderation = request(Method::POST, "/admin/api/moderate", false);
    moderation.set_header("Authorization", "Bearer synthetic-drain-token");
    moderation.set_body(serde_json::json!({"sha256": hash(), "action": "BAN"}).to_string());
    assert_eq!(call(moderation).get_status(), StatusCode::UNAUTHORIZED);
    let mut wrong = request(Method::POST, "/admin/api/b2-cdn-purge/drain?max=2", false);
    wrong.set_header("Authorization", "Bearer invalid-drain-token");
    assert_eq!(call(wrong).get_status(), StatusCode::UNAUTHORIZED);
}

#[test]
#[ignore = "requires successful local service-scoped URL and realistic bulk-map purge backend"]
fn service_scoped_url_and_bulk_key_acknowledgements_complete_final_purge() {
    let epoch = b2_cdn_phase::begin_erase(&hash()).unwrap();
    assert!(b2_cdn_phase::record_physical(&hash(), &epoch, b2_cdn_phase::Physical::Absent).unwrap());
    assert!(b2_cdn_phase::ensure_final_intent(&hash()).unwrap());
    let mut response = call(request(Method::POST, "/admin/api/b2-cdn-purge/drain?max=1", true));
    assert_eq!(response.get_status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&response.take_body_str()).unwrap();
    assert_eq!(body["result"], 1);
    assert_eq!(body["errors"], 0);
    assert_eq!(body["pending"], 0);
    assert!(b2_cdn_phase::final_acked(&hash()).unwrap());
    assert!(b2_cdn_phase::complete_ready(&hash()).unwrap());
}

#[test]
#[ignore = "requires local URL404 and successful bulk purge backend"]
fn url_404_keeps_committed_final_purge_pending_without_ack() {
    let epoch = b2_cdn_phase::begin_erase(&hash()).unwrap();
    assert!(b2_cdn_phase::record_physical(&hash(), &epoch, b2_cdn_phase::Physical::Absent).unwrap());
    assert!(b2_cdn_phase::ensure_final_intent(&hash()).unwrap());
    let mut response = call(request(Method::POST, "/admin/api/b2-cdn-purge/drain?max=1", true));
    assert_eq!(response.get_status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&response.take_body_str()).unwrap();
    assert_eq!(body["result"], 0);
    assert_eq!(body["errors"], 1);
    assert_eq!(body["pending"], 1);
    assert!(!b2_cdn_phase::final_acked(&hash()).unwrap());
    assert!(!b2_cdn_phase::complete_ready(&hash()).unwrap());
    let store = open_store().unwrap();
    let entries = store.build_list().prefix("b2-cdn-purge").execute().unwrap();
    let mut retained = 0;
    for key in entries.keys() {
        if !key.starts_with("b2-cdn-purge:v1:") { continue; }
        let mut entry = store.lookup(key).unwrap();
        let record: serde_json::Value = serde_json::from_str(&entry.take_body().into_string()).unwrap();
        assert_eq!(record["state"], "committed");
        retained += 1;
    }
    assert_eq!(retained, 1);
}

#[test]
#[ignore = "requires failing then recovering local purge backend"]
fn missing_hash_key_purge_acknowledgement_is_not_success() {
    assert!(storage::invalidate_b2_cdn(&[hash()]).is_err());
}

#[test]
#[ignore = "requires failing then recovering local purge backend"]
fn unavailable_config_store_cannot_disable_durable_eviction() {
    assert!(b2_cdn_purge::configured(), "configuration read failure must not impersonate explicitly absent CDN keys");
}

#[test]
#[ignore = "requires synthetic B2 and Bunny providers; scripts/run-bunny-pilot-revocation-tests.py"]
fn bunny_pilot_age_gate_eviction_retries() {
    // Viceroy does not rate-limit writes. Inject the provider's 1/s rejection
    // before executing a real generation-conditional insert.
    let throttle_store = open_store().unwrap();
    let throttle_key = "fixture-bunny-kv-throttle";
    throttle_store.insert(throttle_key, "before").unwrap();
    let observed = throttle_store.lookup(throttle_key).unwrap().current_generation();
    let written = std::time::Instant::now();
    let mut attempts = 0;
    crate::metadata::retry_throttled_write(|| {
        attempts += 1;
        if written.elapsed() < std::time::Duration::from_secs(1) {
            return Err(fastly::kv_store::KVStoreError::TooManyRequests);
        }
        throttle_store.build_insert().if_generation_match(observed).execute(throttle_key,"after")
    }).unwrap();
    assert_eq!(attempts, 2);
    assert_eq!(throttle_store.lookup(throttle_key).unwrap().take_body().into_string(), "after");

    let hash = hash();
    let metadata = serde_json::from_value(serde_json::json!({
        "sha256": hash, "size": 9, "type": "video/mp4", "uploaded": "2026-01-01T00:00:00Z",
        "owner": "b".repeat(64), "status": "active"
    }))
    .unwrap();
    put_blob_metadata(&metadata).unwrap();
    // A previous runner held revocation but exited before doing any I/O.
    if storage::config_flag("bunny_fixture_resume_revoke") {
        parent_gate::archive_claim(&hash, &format!("bunny-revoke-{hash}")).unwrap();
    }

    let ready_key = format!("bunny-ready:v1:{hash}");
    open_store()
        .unwrap()
        .insert(&ready_key, "previous readiness")
        .unwrap();

    let meter = |phase: &str| {
        let response = Request::post("http://fixture.invalid/fixture/meter")
            .with_body(phase)
            .send("fixture_control")
            .unwrap();
        assert_eq!(response.get_status(), StatusCode::OK);
    };
    let mut moderate = request(Method::POST, "/admin/api/moderate", true);
    moderate.set_body(serde_json::json!({"sha256": hash, "action": "AGE_RESTRICT"}).to_string());
    assert_eq!(crate::request_bindings::metered(moderate).get_status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        get_blob_metadata_uncached(&hash).unwrap().unwrap().status,
        BlobStatus::AgeRestricted
    );
    assert_eq!(
        call(request(Method::GET, &format!("/{hash}"), false)).get_status(),
        StatusCode::UNAUTHORIZED
    );

    let store = open_store().unwrap();
    assert!(matches!(
        store.lookup(&ready_key),
        Err(fastly::kv_store::KVStoreError::ItemNotFound)
    ));
    let queue = store
        .build_list()
        .prefix("b2-cdn-purge:v1:")
        .execute()
        .unwrap();
    assert_eq!(queue.keys().len(), 1);
    let key = &queue.keys()[0];
    let intent_state = || {
        let record: serde_json::Value =
            serde_json::from_str(&store.lookup(key).unwrap().take_body().into_string()).unwrap();
        record["state"].clone()
    };
    assert_eq!(intent_state(), "committed");
    // Up to four version deletes per execution (or one per pass during 4-host
    // delivery rotation to stay within the 32-backend-request budget). The
    // first verified empty listing reaches the configured transient purge
    // failure and stays pending.
    for _ in 0..20 {
        let req = request(Method::POST, "/admin/api/b2-cdn-purge/drain?max=1", false)
            .with_header("Authorization", "Bearer synthetic-webhook-token");
        let mut retry = crate::request_bindings::metered(req);
        assert_eq!(retry.get_status(), StatusCode::OK);
        let reply: serde_json::Value = serde_json::from_str(&retry.take_body_str()).unwrap();
        if reply["result"] == 1 {
            break;
        }
        assert_eq!(intent_state(), "committed");
    }
    assert_eq!(intent_state(), "cleared");

    meter("unrelated");
    // Unenrolled hashes must not acquire or interfere with shared mirror gates.
    let unrelated = "c".repeat(64);
    crate::storage::invalidate_b2_cdn(&[unrelated.clone()]).unwrap();
    assert!(matches!(
        store.lookup(&format!("b2-sync:v1:{unrelated}")),
        Err(fastly::kv_store::KVStoreError::ItemNotFound)
    ));
    parent_gate::archive_claim(&unrelated, "unrelated-mirror").unwrap();
    crate::storage::invalidate_b2_cdn(&[unrelated.clone()]).unwrap();
    assert!(parent_gate::archive_owned(&unrelated, "unrelated-mirror").unwrap());
}


#[test]
#[ignore = "requires retained pilot with missing/malformed bundle"]
fn bunny_legacy_canonical_fallback() {
    let hash = if storage::config_flag("fixture_unenrolled") {
        "c".repeat(64)
    } else {
        hash()
    };
    b2_cdn_purge::enqueue(&hash, b2_cdn_purge::Phase::Single).unwrap();
    let drain = |auth| {
        let req = request(Method::POST, "/admin/api/b2-cdn-purge/drain?max=1", false)
            .with_header("Authorization", format!("Bearer {auth}"));
        let mut response = crate::request_bindings::metered(req);
        assert_eq!(response.get_status(), StatusCode::OK);
        serde_json::from_str::<serde_json::Value>(&response.take_body_str()).unwrap()["result"]
            .clone()
    };
    if storage::config_flag("fixture_failed_standalone_hint") {
        let store = open_store().unwrap();
        store.insert(&format!("canonical-purge-priority:v1:{hash}"), "1").unwrap();
        let key = store.build_list().prefix("b2-cdn-purge:v1:").execute().unwrap().keys()[0].clone();
        for _ in 0..7 {
            assert_eq!(drain("synthetic-drain-token"), 0);
            let body = store.lookup(&key).unwrap().take_body().into_string();
            assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["state"], "committed");
        }
        return;
    }
    if storage::config_flag("fixture_standalone_rejected") {
        let store = open_store().unwrap();
        let records = store
            .build_list()
            .prefix("b2-cdn-purge:v1:")
            .execute()
            .unwrap();
        assert_eq!(records.keys().len(), 1);
        let state = || {
            let body = store
                .lookup(&records.keys()[0])
                .unwrap()
                .take_body()
                .into_string();
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["state"].clone()
        };
        assert_eq!(drain("synthetic-drain-token"), 0);
        assert_eq!(state(), "committed");
        assert_eq!(
            drain("synthetic-drain-token"),
            0,
            "Bunny failure must keep the outbox pending after canonical success"
        );
        assert_eq!(state(), "committed");
        assert_eq!(
            drain("synthetic-drain-token"),
            1,
            "the other valid purge credential must finish both rounds"
        );
        assert_eq!(state(), "cleared");
        assert!(matches!(
            store.lookup(&format!("canonical-purge-priority:v1:{hash}")),
            Err(fastly::kv_store::KVStoreError::ItemNotFound)
        ));
        return;
    }
    let key = format!("canonical-purge-priority:v1:{hash}");
    if !storage::config_flag("fixture_immediate") {
        assert_eq!(drain("synthetic-webhook-token"), 0);
        assert!(
            open_store().unwrap().lookup(&key).is_ok(),
            "retry must reserve canonical priority"
        );
        assert_eq!(
            drain("synthetic-webhook-token"),
            0,
            "canonical-only retry cannot acknowledge Bunny"
        );
        assert!(open_store().unwrap().lookup(&key).is_err());
        let store = open_store().unwrap();
        let records = store
            .build_list()
            .prefix("b2-cdn-purge:v1:")
            .execute()
            .unwrap();
        assert_eq!(records.keys().len(), 1);
        let record = store
            .lookup(&records.keys()[0])
            .unwrap()
            .take_body()
            .into_string();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&record).unwrap()["state"],
            "committed"
        );
    } else {
        let result = drain(if storage::config_flag("fixture_webhook") {
            "synthetic-webhook-token"
        } else {
            "synthetic-drain-token"
        });
        assert_eq!(result, u8::from(storage::config_flag("fixture_unenrolled")));
    }
}

#[test]
#[ignore = "requires synthetic Fastly and Bunny providers; scripts/run-bunny-delivery-invalidation-tests.py"]
fn bunny_delivery_policy_purge_and_durable_retry() {
    let mode = storage::optional_config("fixture_delivery_mode")
        .unwrap()
        .unwrap_or_else(|| "bunny-only".to_string());

    if mode == "invalid-config" {
        assert!(b2_cdn_purge::configured());
        assert!(storage::invalidate_b2_cdn(&[hash()]).is_err());
        return;
    }

    if mode == "webhook-packed-budget" {
        let hash = "c".repeat(64);
        b2_cdn_purge::enqueue(&hash, b2_cdn_purge::Phase::Single).unwrap();
        let req = request(Method::POST, "/admin/api/b2-cdn-purge/drain?max=2", false)
            .with_header("Authorization", "Bearer synthetic-webhook-token");
        let mut response = crate::request_bindings::metered(req);
        assert_eq!(response.get_status(), StatusCode::OK);
        let reply: serde_json::Value = serde_json::from_str(&response.take_body_str()).unwrap();
        assert_eq!(reply["result"], 1);
        assert_eq!(reply["errors"], 0);
        assert_eq!(reply["pending"], 0);
        return;
    }

    if mode == "webhook-no-bundle-safe-failclosed" {
        b2_cdn_purge::enqueue(&hash(), b2_cdn_purge::Phase::Single).unwrap();
        let drain_with = |token: &str| {
            let req = request(Method::POST, "/admin/api/b2-cdn-purge/drain?max=2", false)
                .with_header("Authorization", format!("Bearer {token}"));
            let mut response = crate::request_bindings::metered(req);
            assert_eq!(response.get_status(), StatusCode::OK);
            serde_json::from_str::<serde_json::Value>(&response.take_body_str()).unwrap()
        };
        // Pass 1 (webhook, 4 secrets used): missing bundle stages standalone Fastly priority.
        assert_eq!(drain_with("synthetic-webhook-token")["result"], 0);
        // Pass 2 (webhook): Fastly purges and stages Bunny retry hint without clearing.
        assert_eq!(drain_with("synthetic-webhook-token")["result"], 0);
        // Pass 3 (webhook): Bunny delivery purges and clears hint, STILL does not clear intent
        // so Fastly is never bypassed on a stale priority hint.
        assert_eq!(drain_with("synthetic-webhook-token")["result"], 0);
        // Pass 4 (dedicated drain token): both Fastly and Bunny succeed together and clear intent.
        let final_reply = drain_with("synthetic-drain-token");
        assert_eq!(final_reply["result"], 1);
        assert_eq!(final_reply["errors"], 0);
        assert_eq!(final_reply["pending"], 0);
        return;
    }

    if mode == "cold-pop-origin-retention" || mode == "stale-pop-origin-rotation" {
        assert!(b2_cdn_purge::configured());
        b2_cdn_purge::enqueue(&hash(), b2_cdn_purge::Phase::Single).unwrap();
        let req = request(Method::POST, "/admin/api/b2-cdn-purge/drain?max=2", false)
            .with_header("Authorization", "Bearer synthetic-drain-token");
        let mut response = crate::request_bindings::metered(req);
        assert_eq!(response.get_status(), StatusCode::OK);
        let reply: serde_json::Value = serde_json::from_str(&response.take_body_str()).unwrap();
        assert_eq!(reply["result"], 1);
        assert_eq!(reply["errors"], 0);
        assert_eq!(reply["pending"], 0);
        return;
    }

    if mode == "bunny-only-vanish-no-replica" || mode == "vanish-b2-replica-budget" {
        let hash = hash();
        if mode == "vanish-b2-replica-budget" {
            // Simulate a real vanish wave that has already spent 5 secrets before
            // reaching inline `purge_bunny_hashes`: phased CDN invalidation must
            // defer Bunny purging to `Phase::Final` drain without failing the wave.
            let _scope = crate::request_bindings::begin();
            for secret_name in [
                "b2_cdn_purge_drain_token",
                "admin_token",
                "webhook_secret",
                "fastly_api_token",
                "kv_origin_read_token",
            ] {
                let _ = crate::request_bindings::secret(secret_name);
            }
            let mut vanish_result = storage::VanishStorageResult::default();
            storage::purge_bunny_hashes(std::slice::from_ref(&hash), &mut vanish_result);
            assert!(
                vanish_result.failed_hashes.is_empty(),
                "phased vanish must not fail inline Bunny purge when 5 secrets are spent"
            );
        }
        let epoch = storage::begin_vanish_phase(&hash).unwrap().unwrap();
        let empty = std::collections::HashSet::new();
        assert!(storage::finish_vanish_phase(&hash, &epoch, &empty, &empty).unwrap());
        assert!(b2_cdn_phase::ensure_final_intent(&hash).unwrap());
        assert!(b2_cdn_phase::physical_absent(&hash).unwrap());
        let req = request(Method::POST, "/admin/api/b2-cdn-purge/drain?max=2", false)
            .with_header("Authorization", "Bearer synthetic-drain-token");
        let mut response = crate::request_bindings::metered(req);
        assert_eq!(response.get_status(), StatusCode::OK);
        let reply: serde_json::Value = serde_json::from_str(&response.take_body_str()).unwrap();
        assert_eq!(reply["result"], 1);
        assert!(storage::vanish_complete(&hash));
        return;
    }

    if mode == "pilot-plus-delivery-missing-bundle-webhook" {
        let hash = hash();
        b2_cdn_purge::enqueue(&hash, b2_cdn_purge::Phase::Single).unwrap();
        // Pass 1: webhook drain with 4 secrets spent tries missing bundle,
        // stages Standalone ("1").
        // Pass 2: Standalone purges Fastly and stages BunnyRetry ("bunny-retry")
        // even though bunny_pilot_configured() is also true.
        // Pass 3: BunnyRetry purges outer Bunny delivery zones and stages Packed
        // ("packed") so neither Fastly nor outer Bunny delivery is starved.
        for _ in 0..3 {
            let req = request(Method::POST, "/admin/api/b2-cdn-purge/drain?max=2", false)
                .with_header("Authorization", "Bearer synthetic-webhook-token");
            let mut resp = crate::request_bindings::metered(req);
            assert_eq!(resp.get_status(), StatusCode::OK);
            let reply: serde_json::Value = serde_json::from_str(&resp.take_body_str()).unwrap();
            assert_eq!(reply["result"], 0);
            assert_eq!(reply["pending"], 1);
        }
        return;
    }

    if mode == "vanish-kv-origin-5-secret-budget"
        || mode == "vanish-cold-pop-rollback-5-secret-budget"
    {
        let hash = hash();
        let metadata = serde_json::from_value(serde_json::json!({
            "sha256": hash,
            "size": 9,
            "type": "video/mp4",
            "uploaded": "2026-01-01T00:00:00Z",
            "owner": "b".repeat(64),
            "status": "active"
        }))
        .unwrap();
        put_blob_metadata(&metadata).unwrap();
        // Physical creator delete with kv_origin + bunny_delivery_zones (both
        // active and cold-POP rollback where only KV origin retains zones) must
        // stay within the 5-secret Compute limit without failing the physical
        // wave, then complete after bounded Phase::Final drain.
        let mut delete_req = request(Method::POST, "/admin/api/moderate", true);
        delete_req.set_body(serde_json::json!({"sha256": hash, "action": "DELETE"}).to_string());
        let delete_resp = crate::request_bindings::metered(delete_req);
        assert_eq!(delete_resp.get_status(), StatusCode::CONFLICT);
        assert!(b2_cdn_phase::physical_absent(&hash).unwrap());

        // `handle_phased_creator_delete` enqueues both policy and Phase::Final
        // intents under random nonces while `handle_drain` clamps `limit = 1`.
        // Drain in a bounded loop until the queue is empty (`result == 0`).
        let mut cleared = 0u64;
        for _ in 0..5 {
            let drain_req = request(Method::POST, "/admin/api/b2-cdn-purge/drain?max=2", false)
                .with_header("Authorization", "Bearer synthetic-drain-token");
            let mut drain_resp = crate::request_bindings::metered(drain_req);
            assert_eq!(drain_resp.get_status(), StatusCode::OK);
            let reply: serde_json::Value =
                serde_json::from_str(&drain_resp.take_body_str()).unwrap();
            assert_eq!(reply["errors"], 0);
            let drained = reply["result"].as_u64().unwrap_or(0);
            cleared += drained;
            if drained == 0 && reply["pending"] == 0 {
                break;
            }
        }
        assert!(cleared >= 1, "expected queued intents to drain");
        assert!(storage::vanish_complete(&hash));

        let mut finish_req = request(Method::POST, "/admin/api/moderate", true);
        finish_req.set_body(serde_json::json!({"sha256": hash, "action": "DELETE"}).to_string());
        let mut finish_resp = crate::request_bindings::metered(finish_req);
        assert_eq!(finish_resp.get_status(), StatusCode::OK);
        let finish_body: serde_json::Value =
            serde_json::from_str(&finish_resp.take_body_str()).unwrap();
        assert_eq!(finish_body["physical_deleted"], true);
        return;
    }

    if mode == "bunny-retry-clears-on-target-error" {
        let hash = hash();
        let store = open_store().unwrap();
        let hint_key = format!("canonical-purge-priority:v1:{hash}");
        store.insert(&hint_key, "bunny-retry").unwrap();
        assert!(storage::invalidate_b2_cdn(std::slice::from_ref(&hash)).is_err());
        assert!(
            matches!(
                store.lookup(&hint_key),
                Err(fastly::kv_store::KVStoreError::ItemNotFound)
            ),
            "bunny-retry hint must clear even when bunny_delivery_purge_targets fails"
        );
        return;
    }

    if mode == "rotation-overflow" {
        let err = b2_cdn_purge::enqueue(&hash(), b2_cdn_purge::Phase::Single);
        assert!(err.is_err(), "third rotation exceeding 4 retained zones must fail closed");
        return;
    }

    if mode == "webhook-admin-moderate" {
        let hash = hash();
        let metadata = serde_json::from_value(serde_json::json!({
            "sha256": hash,
            "size": 9,
            "type": "video/mp4",
            "uploaded": "2026-01-01T00:00:00Z",
            "owner": "b".repeat(64),
            "status": "active"
        }))
        .unwrap();
        put_blob_metadata(&metadata).unwrap();
        let mut moderate = request(Method::POST, "/admin/moderate", false)
            .with_header("Authorization", "Bearer synthetic-webhook-token");
        moderate.set_body(serde_json::json!({"sha256": hash, "action": "BAN"}).to_string());
        let response = crate::request_bindings::metered(moderate);
        assert_eq!(response.get_status(), StatusCode::OK);
        assert_eq!(
            get_blob_metadata_uncached(&hash).unwrap().unwrap().status,
            BlobStatus::Banned
        );
        return;
    }

    if mode == "retained-after-removal" || mode == "zone-rotation" {
        assert!(b2_cdn_purge::configured());
        b2_cdn_purge::enqueue(&hash(), b2_cdn_purge::Phase::Single).unwrap();
        if mode == "zone-rotation" {
            let retained = open_store()
                .unwrap()
                .lookup("bunny-delivery-retained-zones:v1")
                .unwrap()
                .take_body()
                .into_string();
            assert_eq!(
                retained,
                "old.divine.video,old-cdn.b-cdn.net,media.divine.video,divine-media-cdn.b-cdn.net"
            );
        }
        let req = request(Method::POST, "/admin/api/b2-cdn-purge/drain?max=2", false)
            .with_header("Authorization", "Bearer synthetic-drain-token");
        let mut response = crate::request_bindings::metered(req);
        assert_eq!(response.get_status(), StatusCode::OK);
        let reply: serde_json::Value = serde_json::from_str(&response.take_body_str()).unwrap();
        assert_eq!(reply["result"], 1);
        assert_eq!(reply["errors"], 0);
        assert_eq!(reply["pending"], 0);
        return;
    }

    let hash = hash();
    let metadata = serde_json::from_value(serde_json::json!({
        "sha256": hash,
        "size": 9,
        "type": "video/mp4",
        "uploaded": "2026-01-01T00:00:00Z",
        "owner": "b".repeat(64),
        "status": "active"
    }))
    .unwrap();
    put_blob_metadata(&metadata).unwrap();

    let mut moderate = request(Method::POST, "/admin/api/moderate", true);
    moderate.set_body(serde_json::json!({"sha256": hash, "action": "BAN"}).to_string());
    assert_eq!(
        crate::request_bindings::metered(moderate).get_status(),
        StatusCode::BAD_GATEWAY
    );
    assert_eq!(
        get_blob_metadata_uncached(&hash).unwrap().unwrap().status,
        BlobStatus::Banned
    );
    assert_eq!(
        call(request(Method::GET, &format!("/{hash}"), false)).get_status(),
        StatusCode::NOT_FOUND
    );

    let store = open_store().unwrap();
    let retained = store
        .lookup("bunny-delivery-retained-zones:v1")
        .unwrap()
        .take_body()
        .into_string();
    assert_eq!(retained, "media.divine.video,divine-media-cdn.b-cdn.net");

    let queue = store
        .build_list()
        .prefix("b2-cdn-purge:v1:")
        .execute()
        .unwrap();
    assert_eq!(queue.keys().len(), 1);
    let key = &queue.keys()[0];
    let intent_state = || {
        let record: serde_json::Value =
            serde_json::from_str(&store.lookup(key).unwrap().take_body().into_string()).unwrap();
        record["state"].clone()
    };
    assert_eq!(intent_state(), "committed");

    // First drain still fails on one Bunny alias: intent must remain committed.
    let first_drain = request(Method::POST, "/admin/api/b2-cdn-purge/drain?max=2", false)
        .with_header("Authorization", "Bearer synthetic-drain-token");
    let mut first_resp = crate::request_bindings::metered(first_drain);
    assert_eq!(first_resp.get_status(), StatusCode::OK);
    let first_body: serde_json::Value =
        serde_json::from_str(&first_resp.take_body_str()).unwrap();
    assert_eq!(first_body["result"], 0);
    assert_eq!(first_body["errors"], 1);
    assert_eq!(first_body["pending"], 1);
    assert_eq!(intent_state(), "committed");

    // Second drain succeeds across both aliases and both rounds: intent clears.
    let second_drain = request(Method::POST, "/admin/api/b2-cdn-purge/drain?max=2", false)
        .with_header("Authorization", "Bearer synthetic-drain-token");
    let mut second_resp = crate::request_bindings::metered(second_drain);
    assert_eq!(second_resp.get_status(), StatusCode::OK);
    let second_body: serde_json::Value =
        serde_json::from_str(&second_resp.take_body_str()).unwrap();
    assert_eq!(second_body["result"], 1);
    assert_eq!(second_body["errors"], 0);
    assert_eq!(second_body["pending"], 0);
    assert_eq!(intent_state(), "cleared");
}
