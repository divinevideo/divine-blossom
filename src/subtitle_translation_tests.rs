// ABOUTME: Exercises the actual VTT GET routes under Viceroy with loopback storage.
// ABOUTME: Run by scripts/run-subtitle-translation-tests.py, never against live services.

use super::*;

thread_local! {
    static CLIENT_REQUEST: Request = Request::from_client();
}

fn client_request(url: &str) -> Request {
    CLIENT_REQUEST.with(|client| {
        let mut request = client.clone_without_body();
        request.set_url(url);
        request
    })
}

fn seed(marker: char, status: &str, terminal: bool) -> String {
    let hash = marker.to_string().repeat(64);
    let metadata: BlobMetadata = serde_json::from_value(serde_json::json!({
        "sha256": hash, "size": 1, "type": "video/mp4", "uploaded": "2026-01-01T00:00:00Z",
        "owner": "f".repeat(64), "status": "active", "transcript_status": status,
        "transcript_terminal": terminal, "transcript_error_code": if terminal { Some("no_speech") } else { None },
    })).unwrap();
    put_blob_metadata(&metadata).unwrap();
    hash
}

fn translated_get(hash: &str, alias: bool) -> Result<Response> {
    let path = if alias {
        format!("/{hash}/VTT")
    } else {
        format!("/{hash}.vtt")
    };
    let request = client_request(&format!("https://media.divine.video{path}?lang=pt-BR"));
    if alias {
        handle_get_transcript(request, &path)
    } else {
        handle_get_transcript_file(request, &path)
    }
}

#[test]
#[ignore = "requires loopback storage configured by run-subtitle-translation-tests.py"]
fn subtitle_translation_routes_use_source_lifecycle_and_versioned_artifacts() {
    let hash = seed('a', "pending", false);
    let mut response = translated_get(&hash, false).unwrap();
    assert_eq!(response.get_status(), StatusCode::ACCEPTED);
    assert!(response.take_body_str().contains("processing"));

    let hash = seed('b', "failed", true);
    let mut response = translated_get(&hash, true).unwrap();
    assert_ne!(response.get_status(), StatusCode::ACCEPTED);
    assert!(response.take_body_str().contains("no_speech"));

    let hash = seed('c', "processing", false);
    let mut response = translated_get(&hash, false).unwrap();
    assert_eq!(response.get_status(), StatusCode::OK);
    assert_eq!(
        response.get_header_str("X-Divine-Machine-Translated"),
        Some("true")
    );
    assert_eq!(response.get_header_str("Content-Language"), Some("pt-BR"));
    assert!(response
        .get_header_str("Access-Control-Expose-Headers")
        .unwrap()
        .contains("X-Divine-Machine-Translated"));
    assert!(response.take_body_str().contains("Original translation"));
    assert_eq!(
        get_blob_metadata(&hash).unwrap().unwrap().transcript_status,
        Some(TranscriptStatus::Processing)
    );
    // The source changes between requests, including within one POP cache lifetime.
    let mut repaired = translated_get(&hash, true).unwrap();
    assert!(repaired.take_body_str().contains("Repaired translation"));

    let hash = seed('d', "complete", false);
    let mut response = translated_get(&hash, false).unwrap();
    assert_eq!(response.get_status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.take_body_str().contains("translation_rejected"));

    let hash = seed('e', "complete", false);
    assert_eq!(
        translated_get(&hash, true).unwrap().get_status(),
        StatusCode::ACCEPTED
    );

    let hash = seed('f', "complete", false);
    assert!(matches!(
        translated_get(&hash, false),
        Err(BlossomError::StorageError(_))
    ));

    let hash = seed('1', "complete", false);
    assert_eq!(
        translated_get(&hash, true).unwrap().get_status(),
        StatusCode::ACCEPTED
    );
    finish_subtitle_translation();
    let hash = seed('2', "complete", false);
    assert_eq!(
        translated_get(&hash, false).unwrap().get_status(),
        StatusCode::ACCEPTED
    );
    finish_subtitle_translation();
    let mut rejected = translated_get(&hash, false).unwrap();
    assert_eq!(rejected.get_status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(rejected.take_body_str().contains("dispatch_unavailable"));

    // Only the two worker deliveries above should have consumed the IP budget.
    let ip = CLIENT_REQUEST.with(|client| client.get_client_ip_addr().unwrap().to_string());
    let store = KVStore::open("blossom_metadata").unwrap().unwrap();
    let key = rate_limit::counter_key(
        "ip",
        &ip,
        rate_limit::bucket_for(unix_timestamp_secs(), rate_limit::IP_WINDOW_SECS),
    );
    let mut count = store.lookup(&key).unwrap();
    assert_eq!(count.take_body().into_string(), "2");

    // Exhaust the same connection budget used by transcription. Cache hits still work.
    let limiter_request = client_request("https://media.divine.video/");
    assert!(limiter_request.get_client_ip_addr().is_some());
    for _ in 0..rate_limit::IP_LIMIT {
        enforce_transcribe_rate_limit(&limiter_request, "");
    }
    let hash = seed('5', "complete", false);
    assert_eq!(
        translated_get(&hash, false).unwrap().get_status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let hash = seed('c', "complete", false);
    assert_eq!(
        translated_get(&hash, true).unwrap().get_status(),
        StatusCode::OK
    );

    let hash = seed('3', "complete", false);
    let mut metadata = get_blob_metadata(&hash).unwrap().unwrap();
    metadata.status = BlobStatus::Banned;
    put_blob_metadata(&metadata).unwrap();
    assert!(matches!(
        translated_get(&hash, true),
        Err(BlossomError::NotFound(_))
    ));
}

#[test]
#[ignore = "requires loopback storage configured by run-subtitle-translation-tests.py"]
fn subtitle_translation_disabled_returns_contract_without_storage() {
    let hash = seed('4', "complete", false);
    for alias in [false, true] {
        let mut response = translated_get(&hash, alias).unwrap();
        assert_eq!(response.get_status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.get_header_str("Cache-Control"), Some("no-store"));
        assert!(response.take_body_str().contains("translation_unavailable"));
    }
}
