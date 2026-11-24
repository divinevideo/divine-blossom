// divine-upload-server#52: this service's public /thumbnail/<hash> reads the
// same media bucket, so it takes the same service-token guard.
use super::*;
use crate::thumbnail_auth::{Policy, HEADER};
use wiremock::matchers::{method, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const HASH: &str = "abababababababababababababababababababababababababababababababab";

/// Storage that holds a stored `<hash>.jpg` for every lookup, so any request
/// that reaches storage would be served from the cache.
async fn storage_with_cached_thumbnail() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(query_param("alt", "media"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"stored-jpeg".to_vec()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "x.jpg", "bucket": "synthetic-media", "generation": "1",
            "metageneration": "1", "selfLink": "t", "mediaLink": "t", "etag": "t",
            "id": "t", "size": "11", "contentType": "image/jpeg"
        })))
        .mount(&server)
        .await;
    server
}

fn state(storage: &MockServer, policy: Policy) -> Arc<AppState> {
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
            transcoder_url: None,
            transcriber_url: None,
            resumable_session_ttl_secs: 86400,
            resumable_chunk_size: 8 * 1024 * 1024,
            transcode_queue: None,
            thumbnail_auth: policy,
        },
    })
}

fn headers(token: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(token) = token {
        headers.insert(HEADER, token.parse().unwrap());
    }
    headers
}

async fn call(state: Arc<AppState>, hash: &str, token: Option<&str>) -> Response {
    handle_thumbnail_generate(State(state), Path(hash.to_string()), headers(token))
        .await
        .into_response()
}

async fn body(response: Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap()
        .to_vec()
}

fn assert_not_shared_cacheable(response: &Response, case: &str) {
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .map(|v| v.to_str().unwrap()),
        Some("private, no-store"),
        "{case}"
    );
    let vary = response
        .headers()
        .get_all(header::VARY)
        .iter()
        .map(|v| v.to_str().unwrap().to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(",");
    assert!(vary.contains(HEADER), "{case}: vary={vary}");
}

#[tokio::test]
async fn required_token_refuses_without_touching_storage() {
    let storage = storage_with_cached_thumbnail().await;
    let state = state(&storage, Policy::Required("svc-token".into()));
    for presented in [None, Some("wrong-token"), Some("svc-token-extra")] {
        let response = call(state.clone(), HASH, presented).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{presented:?}");
        assert_not_shared_cacheable(&response, "refused");
        assert_eq!(body(response).await, br#"{"error":"Video not found"}"#);
    }
    assert!(storage.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn required_token_serves_the_stored_thumbnail_with_the_token() {
    let storage = storage_with_cached_thumbnail().await;
    let state = state(&storage, Policy::Required("svc-token".into()));
    let response = call(state, HASH, Some("svc-token")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_not_shared_cacheable(&response, "served");
    assert_eq!(body(response).await, b"stored-jpeg");
}

#[tokio::test]
async fn observed_token_serves_requests_without_it() {
    let storage = storage_with_cached_thumbnail().await;
    let state = state(&storage, Policy::Observe("svc-token".into()));
    let response = call(state.clone(), HASH, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_not_shared_cacheable(&response, "observe without token");
    let invalid = call(state, "zz", Some("svc-token")).await;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_not_shared_cacheable(&invalid, "observe invalid hash");
}

#[tokio::test]
async fn open_route_keeps_its_existing_headers() {
    let storage = storage_with_cached_thumbnail().await;
    let response = call(state(&storage, Policy::Open), HASH, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(header::CACHE_CONTROL).is_none());
    assert!(response.headers().get(header::VARY).is_none());
}

#[tokio::test]
async fn router_reads_the_token_header() {
    use tower::ServiceExt;
    let storage = storage_with_cached_thumbnail().await;
    let app = build_router(state(&storage, Policy::Required("svc-token".into())));
    let uri = format!("/thumbnail/{HASH}");
    let refused = app
        .clone()
        .oneshot(
            axum::http::Request::get(&uri)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::NOT_FOUND);
    let served = app
        .oneshot(
            axum::http::Request::get(&uri)
                .header(HEADER, "svc-token")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(served.status(), StatusCode::OK);
}
