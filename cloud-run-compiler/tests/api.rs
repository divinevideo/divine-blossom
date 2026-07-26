use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use divine_compiler::{
    domain::{
        Aspect, AudioSettings, CompileRequest, CreditSettings, FitMode, RenderRequest, Source,
        Watermark,
    },
    http::{router, ApiState},
    store::MemoryJobStore,
};
use nostr::{
    hashes::{sha256, Hash},
    nips::nip98::{HttpData, HttpMethod},
    EventBuilder, JsonUtil, Keys, Kind, Tag, UncheckedUrl,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tower::ServiceExt;

const SECRET_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const VIDEO_PUBKEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PUBLIC_URL: &str = "https://compiler.divine.video/api/compile";

fn signed_body() -> (Vec<u8>, String) {
    let keys = Keys::parse(SECRET_KEY).unwrap();
    let coordinate = format!("34236:{VIDEO_PUBKEY}:first");
    let list_event = EventBuilder::new(
        Kind::Custom(30_005),
        "",
        vec![
            Tag::parse(&["d", "staff-picks"]).unwrap(),
            Tag::parse(&["a", coordinate.as_str()]).unwrap(),
        ],
    )
    .to_event(&keys)
    .unwrap();
    let request = CompileRequest {
        source: Source {
            list_event: serde_json::from_str(&list_event.as_json()).unwrap(),
        },
        renders: vec![RenderRequest {
            aspect: Aspect::Portrait,
            default_fit: FitMode::BlurPad,
            clip_overrides: vec![],
        }],
        watermark: Watermark::default(),
        credit: CreditSettings::default(),
        audio: AudioSettings::default(),
        max_duration_sec: 600,
    };
    let body = serde_json::to_vec(&request).unwrap();
    let digest = Sha256::digest(&body);
    let payload = sha256::Hash::from_slice(&digest).unwrap();
    let auth = EventBuilder::http_auth(
        HttpData::new(UncheckedUrl::from(PUBLIC_URL), HttpMethod::POST).payload(payload),
    )
    .to_event(&keys)
    .unwrap();
    (
        body,
        format!("Nostr {}", STANDARD.encode(auth.as_json().as_bytes())),
    )
}

fn state(max_jobs_per_hour: usize) -> ApiState {
    ApiState::new(
        Arc::new(MemoryJobStore::default()),
        "https://compiler.divine.video",
        max_jobs_per_hour,
    )
}

async fn json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}

#[tokio::test]
async fn creates_job_from_signed_body_and_access_identity() {
    let (body, authorization) = signed_body();
    let response = router(state(10))
        .oneshot(
            Request::post("/api/compile")
                .header("content-type", "application/json")
                .header("x-compiler-initiated-by", "editor@example.com")
                .header("x-compiler-nostr-authorization", authorization)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = json(response).await;
    assert_eq!(body["status"], "queued");
    assert_eq!(body["job"]["initiated_by"], "editor@example.com");
    assert!(body["job"]["id"].as_str().unwrap().len() > 20);
}

#[tokio::test]
async fn job_reads_are_scoped_to_access_identity() {
    let app = router(state(10));
    let (body, authorization) = signed_body();
    let created = app
        .clone()
        .oneshot(
            Request::post("/api/compile")
                .header("content-type", "application/json")
                .header("x-compiler-initiated-by", "editor@example.com")
                .header("x-compiler-nostr-authorization", authorization)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let id = json(created).await["job"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let response = app
        .oneshot(
            Request::get(format!("/api/compile/{id}"))
                .header("x-compiler-initiated-by", "other@example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn rate_limit_is_applied_atomically_per_access_identity() {
    let app = router(state(1));
    for expected in [StatusCode::ACCEPTED, StatusCode::TOO_MANY_REQUESTS] {
        let (body, authorization) = signed_body();
        let response = app
            .clone()
            .oneshot(
                Request::post("/api/compile")
                    .header("content-type", "application/json")
                    .header("x-compiler-initiated-by", "editor@example.com")
                    .header("x-compiler-nostr-authorization", authorization)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}
