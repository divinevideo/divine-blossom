// ABOUTME: Translation lifecycle tests against a local GCS protocol double.
// ABOUTME: Exercises conditional claims, source revisions, failures, and route auth.

use super::*;
use axum::body::{to_bytes, Body};
use std::sync::atomic::AtomicUsize;
use tokio::sync::Mutex;

const SOURCE: &[u8] = b"WEBVTT\n\n00:00:00.000 --> 00:00:01.000\nHello\n";
type Objects = Arc<Mutex<HashMap<String, (Vec<u8>, i64)>>>;

struct StorageDouble {
    objects: Objects,
    state: Arc<AppState>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for StorageDouble {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn object_response(path: String, generation: i64) -> Response {
    let value = serde_json::json!({
        "kind": "storage#object", "id": path, "name": path, "bucket": "test",
        "generation": generation.to_string(), "metageneration": "1", "size": "0",
        "selfLink": "http://storage/object", "mediaLink": "http://storage/object?alt=media",
        "etag": "synthetic", "storageClass": "STANDARD", "crc32c": "synthetic", "md5Hash": "synthetic"
    });
    Json(value).into_response()
}

async fn storage_request(State(objects): State<Objects>, request: Request) -> Response {
    let method = request.method().clone();
    let url = reqwest::Url::parse(&format!("http://storage{}", request.uri())).unwrap();
    let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
    let path = if method == Method::POST {
        query["name"].clone()
    } else {
        let encoded = url.path().split("/o/").nth(1).unwrap();
        reqwest::Url::parse(&format!("http://storage/?name={encoded}"))
            .unwrap()
            .query_pairs()
            .next()
            .unwrap()
            .1
            .into_owned()
    };
    let body = to_bytes(request.into_body(), 1_000_000).await.unwrap();
    let mut objects = objects.lock().await;
    let existing = objects.get(&path).cloned();
    let error = |code: u16| {
        (
            StatusCode::from_u16(code).unwrap(),
            Json(serde_json::json!({
                "error": { "code": code, "message": "synthetic storage error", "errors": [] }
            })),
        )
            .into_response()
    };
    if path.starts_with("forbidden/") {
        return error(403);
    }
    if method == Method::POST {
        let expected: i64 = query
            .get("ifGenerationMatch")
            .map(|v| v.parse().unwrap())
            .unwrap_or(-1);
        let generation = existing
            .as_ref()
            .map(|(_, generation)| *generation)
            .unwrap_or(0);
        if expected >= 0 && expected != generation {
            return error(412);
        }
        let generation = generation + 1;
        objects.insert(path.clone(), (body.to_vec(), generation));
        return object_response(path, generation);
    }
    let Some((body, generation)) = existing else {
        return error(404);
    };
    if query.get("alt").map(String::as_str) == Some("media") {
        return Response::new(Body::from(body));
    }
    object_response(path, generation)
}

impl StorageDouble {
    async fn new() -> Self {
        let objects = Objects::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .fallback(storage_request)
            .with_state(objects.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let state = Arc::new(AppState {
            gcs_client: GcsClient::new(ClientConfig {
                storage_endpoint: endpoint,
                ..ClientConfig::default().anonymous()
            }),
            config: Config::from_lookup(|key| (key == "GCS_BUCKET").then(|| "test".to_string())),
            provider_semaphore: Arc::new(Semaphore::new(4)),
        });
        Self {
            objects,
            state,
            server,
        }
    }

    async fn source(&self, source: &[u8]) {
        self.objects.lock().await.insert(
            format!("{}/vtt/main.vtt", "a".repeat(64)),
            (source.to_vec(), 1),
        );
    }
}

fn request(source: &[u8]) -> TranslateRequest {
    TranslateRequest {
        hash: "a".repeat(64),
        source_digest: hex::encode(Sha256::digest(source)),
        lang: "pt-BR".into(),
    }
}

#[tokio::test]
async fn translation_claim_deduplicates_concurrent_workers_and_cached_requests() {
    let storage = StorageDouble::new().await;
    storage.source(SOURCE).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let translate = |_: String, texts: Vec<String>| {
        let calls = calls.clone();
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(80)).await;
            Ok(texts.into_iter().map(|_| "Olá".into()).collect())
        }
    };
    let (one, two) = tokio::join!(
        process_translate_with(storage.state.clone(), request(SOURCE), &translate),
        process_translate_with(storage.state.clone(), request(SOURCE), &translate),
    );
    let statuses = [one.unwrap().status, two.unwrap().status];
    assert!(statuses.contains(&"complete".into()));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        process_translate_with(storage.state.clone(), request(SOURCE), &translate)
            .await
            .unwrap()
            .status,
        "already_exists"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn translation_source_repair_uses_new_artifact_and_rejects_old_request() {
    let storage = StorageDouble::new().await;
    storage.source(SOURCE).await;
    let translate = |_: String, texts: Vec<String>| async move { Ok(texts) };
    let old = process_translate_with(storage.state.clone(), request(SOURCE), translate)
        .await
        .unwrap();
    let repaired = b"WEBVTT\n\n00:00:00.000 --> 00:00:01.000\nCorrected\n";
    storage.source(repaired).await;
    let new = process_translate_with(storage.state.clone(), request(repaired), translate)
        .await
        .unwrap();
    assert_ne!(old.vtt_path, new.vtt_path);
    let objects = storage.objects.lock().await;
    let new_text = String::from_utf8_lossy(&objects[&new.vtt_path].0);
    assert!(new_text.contains("Corrected"));
    assert!(new_text.contains("Machine-translated"));
    assert!(new_text.contains("Target-Language: pt-BR"));
    drop(objects);
    let mut stale = request(SOURCE);
    stale.lang = "es".into(); // No cached artifact: must detect changed source before billing.
    assert_eq!(
        process_translate_with(storage.state.clone(), stale, |_, _| async {
            panic!("stale source reached provider")
        })
        .await
        .unwrap()
        .status,
        "source_changed"
    );
}

#[tokio::test]
async fn translation_provider_rejection_is_terminal_and_transient_failure_cools_down() {
    for (status, terminal) in [(400, true), (503, false)] {
        let storage = StorageDouble::new().await;
        storage.source(SOURCE).await;
        let result = process_translate_with(
            storage.state.clone(),
            request(SOURCE),
            move |_, _| async move {
                Err(parse_provider_status(
                    Some(status),
                    None,
                    "synthetic failure",
                    false,
                ))
            },
        )
        .await
        .unwrap();
        assert_eq!(result.status, "failed");
        let objects = storage.objects.lock().await;
        let job: TranslationJob =
            serde_json::from_slice(&objects[&format!("{}.json", result.vtt_path)].0).unwrap();
        assert!(
            matches!(job, TranslationJob::Failed { retry_at, .. } if retry_at.is_none() == terminal)
        );
        drop(objects);
        process_translate_with(storage.state.clone(), request(SOURCE), |_, _| async {
            panic!("failure retried before allowed")
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn translation_missing_source_and_storage_permission_failures_are_distinct() {
    let storage = StorageDouble::new().await;
    let result = process_translate_with(storage.state.clone(), request(SOURCE), |_, _| async {
        panic!("missing source reached provider")
    })
    .await
    .unwrap();
    assert_eq!(result.status, "no_source");
    assert!(
        read_translation_object(&storage.state.gcs_client, "test", "forbidden/object")
            .await
            .is_err()
    );
}

#[test]
fn translation_auth_fails_closed_and_requires_matching_secret() {
    let mut config = Config::from_lookup(|_| None);
    let mut headers = axum::http::HeaderMap::new();
    assert_eq!(
        authorize_translate(&config, &headers).unwrap_err().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    config.translate_shared_secret = Some("synthetic-secret".into());
    assert_eq!(
        authorize_translate(&config, &headers).unwrap_err().status(),
        StatusCode::UNAUTHORIZED
    );
    headers.insert(TRANSLATE_SECRET_HEADER, "wrong".parse().unwrap());
    assert_eq!(
        authorize_translate(&config, &headers).unwrap_err().status(),
        StatusCode::UNAUTHORIZED
    );
    headers.insert(TRANSLATE_SECRET_HEADER, "synthetic-secret".parse().unwrap());
    assert!(authorize_translate(&config, &headers).is_ok());
}

#[tokio::test]
async fn translation_expired_claim_is_recovered_and_empty_source_is_terminal() {
    let storage = StorageDouble::new().await;
    let source = b"WEBVTT\n\n";
    storage.source(source).await;
    let req = request(source);
    let path = translated_vtt_path(&req.hash, &req.source_digest, &req.lang);
    storage.objects.lock().await.insert(
        format!("{path}.json"),
        (
            serde_json::to_vec(&TranslationJob::Processing { retry_at: 0 }).unwrap(),
            1,
        ),
    );
    let result = process_translate_with(storage.state.clone(), req, |_, _| async {
        panic!("empty source reached provider")
    })
    .await;
    assert!(result.is_err());
    let objects = storage.objects.lock().await;
    let job: TranslationJob = serde_json::from_slice(&objects[&format!("{path}.json")].0).unwrap();
    assert_eq!(
        job,
        TranslationJob::Failed {
            code: "empty_source".into(),
            retry_at: None
        }
    );
    assert!(!objects.contains_key(&path));
}

#[tokio::test]
async fn translation_partial_provider_response_does_not_store_mixed_languages() {
    let storage = StorageDouble::new().await;
    storage.source(SOURCE).await;
    let req = request(SOURCE);
    let path = translated_vtt_path(&req.hash, &req.source_digest, &req.lang);
    assert!(
        process_translate_with(storage.state.clone(), req, |_, _| async { Ok(Vec::new()) })
            .await
            .is_err()
    );
    assert!(!storage.objects.lock().await.contains_key(&path));
}

#[tokio::test]
async fn translation_route_auth_runs_before_json_extraction() {
    let storage = StorageDouble::new().await;
    let mut config = Config::from_lookup(|_| None);
    config.translate_shared_secret = Some("synthetic-secret".into());
    let state = Arc::new(AppState {
        config,
        gcs_client: storage.state.gcs_client.clone(),
        provider_semaphore: Arc::new(Semaphore::new(1)),
    });
    let app = Router::new()
        .route(
            "/translate",
            post(handle_translate).route_layer(middleware::from_fn_with_state(
                state.clone(),
                require_translate_secret,
            )),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/translate", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body("not JSON")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);
    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header(TRANSLATE_SECRET_HEADER, "synthetic-secret")
        .body("not JSON")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 400);
    server.abort();
    assert!(storage.objects.lock().await.is_empty());
}
