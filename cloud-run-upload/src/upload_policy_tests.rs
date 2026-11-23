use super::*;
use k256::schnorr::signature::hazmat::PrehashSigner;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const POLICY_HEADER: &str = "x-divine-video-processing";

fn authenticated_headers() -> HeaderMap {
    let key = SigningKey::from_bytes(&[7; 32]).unwrap();
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let tags = serde_json::json!([["t", "upload"], ["expiration", (now + 300).to_string()]]);
    let data = serde_json::json!([0, pubkey, now, BLOSSOM_AUTH_KIND, tags, ""]);
    let id = Sha256::digest(serde_json::to_vec(&data).unwrap());
    let signature: Signature = key.sign_prehash(&id).unwrap();
    let event = serde_json::json!({"id": hex::encode(id), "pubkey": pubkey,
        "created_at": now, "kind": BLOSSOM_AUTH_KIND, "tags": tags, "content": "",
        "sig": hex::encode(signature.to_bytes())});
    let auth = format!(
        "Nostr {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_vec(&event).unwrap()
        )
    );
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, auth.parse().unwrap());
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("video/mp4"));
    headers
}

fn state(storage: &MockServer, derivatives: &MockServer) -> Arc<AppState> {
    Arc::new(AppState {
        gcs_client: GcsClient::new(
            ClientConfig {
                storage_endpoint: storage.uri(),
                ..Default::default()
            }
            .anonymous(),
        ),
        config: Config {
            gcs_bucket: "synthetic-media".into(),
            cdn_base_url: "https://media.example".into(),
            upload_base_url: "https://upload.example".into(),
            port: 8080,
            migration_nsec: None,
            webhook_secret: None,
            transcoder_url: Some(derivatives.uri()),
            transcriber_url: Some(derivatives.uri()),
            resumable_session_ttl_secs: 86400,
            resumable_chunk_size: 8 * 1024 * 1024,
            transcode_queue: None,
        },
    })
}

async fn dispatch_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transcode/queue"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/transcribe"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    server
}

async fn assert_dispatch(server: &MockServer, hls: bool) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let requests = server.received_requests().await.unwrap();
            if requests.iter().any(|r| r.url.path() == "/transcribe")
                && (!hls || requests.iter().any(|r| r.url.path() == "/transcode/queue"))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("derivatives must be dispatched");
    // Allow an incorrectly spawned HLS task to reach the loopback endpoint.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.url.path() == "/transcribe")
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.url.path() == "/transcode/queue")
            .count(),
        usize::from(hls)
    );
    assert!(!requests.iter().any(|r| r.url.path() == "/transcode"));
}

#[tokio::test]
async fn invalid_processing_header_rejects_both_routes_before_storage_or_dispatch() {
    let storage = MockServer::start().await;
    let derivatives = dispatch_server().await;
    let state = state(&storage, &derivatives);
    let bad_values = [
        vec!["allow_encode"],
        vec![""],
        vec!["copy-only, allow_encode"],
        vec!["copy-only", "copy-only"],
        vec!["copy-only", "invalid"],
    ];
    for values in bad_values {
        let mut headers = authenticated_headers();
        for value in values {
            headers.append(POLICY_HEADER, value.parse().unwrap());
        }
        let put = handle_upload(State(state.clone()), headers.clone(), Body::empty()).await;
        assert_eq!(put.status(), StatusCode::BAD_REQUEST);
        let complete = handle_resumable_complete(
            State(state.clone()),
            Path("synthetic-session".into()),
            headers,
        )
        .await;
        assert_eq!(complete.status(), StatusCode::BAD_REQUEST);
    }
    assert!(storage.received_requests().await.unwrap().is_empty());
    assert!(derivatives.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn completion_copy_only_suppresses_hls_but_preserves_transcription_and_completed_storage() {
    for copy_only in [false, true] {
        let storage = MockServer::start().await;
        let derivatives = dispatch_server().await;
        let mut headers = authenticated_headers();
        let owner = validate_auth(&headers, "upload").unwrap().pubkey;
        if copy_only {
            headers.insert(POLICY_HEADER, HeaderValue::from_static("copy-only"));
        }
        let manifest = resumable::UploadSession {
            upload_id: "synthetic-session".into(),
            owner,
            final_sha256: HASH.into(),
            declared_size: 1024,
            content_type: "video/mp4".into(),
            file_name: None,
            expires_at_epoch_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 600,
            next_offset: 1024,
            session_url: "https://storage.example/session".into(),
            session_token: "synthetic-token".into(),
            temp_object: "synthetic-temp".into(),
            storage_complete: true,
            finalized_object: Some(HASH.into()),
        };
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&manifest))
            .expect(1)
            .mount(&storage)
            .await;
        let response = handle_resumable_complete(
            State(state(&storage, &derivatives)),
            Path("synthetic-session".into()),
            headers,
        )
        .await;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["sha256"], HASH);
        assert_eq!(
            body["thumbnailUrl"],
            format!("https://media.example/{HASH}.jpg")
        );
        assert_dispatch(&derivatives, !copy_only).await;
        assert!(storage
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method == wiremock::http::Method::Get));
    }
}

#[tokio::test]
async fn duplicate_put_copy_only_suppresses_hls_but_keeps_transcription() {
    // Keep the external media probe isolated from other tests. CI does not
    // install FFprobe until after the upload suite; this test concerns request
    // admission and dispatch, so provide the synthetic fixture's probe result.
    if std::env::var_os("DIVINE_UPLOAD_POLICY_TEST_CHILD").is_none() {
        use std::os::unix::fs::PermissionsExt;
        let bin = tempfile::tempdir().unwrap();
        let probe = bin.path().join("ffprobe");
        std::fs::write(&probe, r#"#!/bin/sh
for arg in "$@"; do input="$arg"; done
[ -f "$input" ] || exit 1
printf '%s' '{"streams":[{"codec_type":"video","codec_name":"h264","width":64,"height":64,"tags":{},"side_data_list":[]}]}'
"#).unwrap();
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "upload_policy_tests::duplicate_put_copy_only_suppresses_hls_but_keeps_transcription", "--nocapture"])
            .env("DIVINE_UPLOAD_POLICY_TEST_CHILD", "1")
            .env("PATH", bin.path())
            .output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    // Synthetic faststart video: no sanitize subprocess is necessary.
    let bytes = include_bytes!("fixtures/policy-upload.mp4").to_vec();
    let hash = hex::encode(Sha256::digest(&bytes));
    for copy_only in [false, true] {
        let storage = MockServer::start().await;
        let derivatives = dispatch_server().await;
        let mut headers = authenticated_headers();
        if copy_only {
            headers.insert(POLICY_HEADER, HeaderValue::from_static("copy-only"));
        }
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": hash, "bucket": "synthetic-media", "size": bytes.len().to_string(), "generation": "1", "metageneration": "1", "id": "synthetic", "etag": "synthetic", "selfLink": "", "mediaLink": ""
        }))).expect(1).mount(&storage).await;
        let response = handle_upload(
            State(state(&storage, &derivatives)),
            headers,
            Body::from(bytes.clone()),
        )
        .await;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["sha256"], hash);
        assert_dispatch(&derivatives, !copy_only).await;
        assert!(storage
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method == wiremock::http::Method::Get));
    }
}
