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

fn object_response(path: String, generation: i64, size: usize) -> Response {
    let value = serde_json::json!({
        "kind": "storage#object", "id": path, "name": path, "bucket": "test",
        "generation": generation.to_string(), "metageneration": "1", "size": size.to_string(),
        "contentType": "text/vtt",
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
    if path.ends_with("/vtt/.lock") && objects.contains_key("__fail_transcript_lock") {
        return error(if method == Method::POST { 503 } else { 404 });
    }
    if path.ends_with("/vtt/main.vtt")
        && method == Method::GET
        && !query.contains_key("alt")
        && objects.remove("__fail_vtt_metadata_once").is_some()
    {
        return error(503);
    }
    if method == Method::DELETE {
        if query
            .get("ifGenerationMatch")
            .is_some_and(|v| Some(v.parse::<i64>().unwrap()) != existing.as_ref().map(|(_, g)| *g))
        {
            return error(412);
        }
        objects.remove(&path);
        return StatusCode::NO_CONTENT.into_response();
    }
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
        let size = body.len();
        objects.insert(path.clone(), (body.to_vec(), generation));
        return object_response(path, generation, size);
    }
    let Some((body, generation)) = existing else {
        return error(404);
    };
    if query
        .get("generation")
        .is_some_and(|value| value != &generation.to_string())
    {
        return error(404);
    }
    if query.get("alt").map(String::as_str) == Some("media") {
        return Response::new(Body::from(body));
    }
    object_response(path, generation, body.len())
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
        let gcs_client = GcsClient::new(ClientConfig {
            storage_endpoint: endpoint,
            ..ClientConfig::default().anonymous()
        });
        let state = Arc::new(AppState {
            media_storage: object_storage::MediaStorage::gcs(gcs_client.clone(), "test".into()),
            gcs_client,
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

fn with_media(
    storage: &StorageDouble,
    media_storage: object_storage::MediaStorage,
) -> Arc<AppState> {
    Arc::new(AppState {
        media_storage,
        gcs_client: storage.state.gcs_client.clone(),
        config: Config::from_lookup(|key| (key == "GCS_BUCKET").then(|| "test".to_string())),
        provider_semaphore: Arc::new(Semaphore::new(4)),
    })
}

fn transcribe_request() -> TranscodeRequest {
    TranscodeRequest {
        hash: "a".repeat(64),
        force: false,
        owner: None,
        job_id: None,
        lang: None,
    }
}

#[tokio::test]
async fn selected_and_legacy_transcripts_reach_translation_and_transcription_dedup() {
    for legacy in [false, true] {
        let storage = StorageDouble::new().await;
        let origin = object_storage::tests::Origin::start().await;
        let media = origin.store();
        if legacy {
            storage.source(SOURCE).await;
        } else {
            upload_transcript_to_storage(
                &media,
                &"a".repeat(64),
                std::str::from_utf8(SOURCE).unwrap(),
            )
            .await
            .unwrap();
        }
        let state = with_media(&storage, media);
        let cached = process_transcribe(state.clone(), transcribe_request()).await;
        if legacy {
            // Translation may read an old GCS transcript, but that read cannot
            // acknowledge output absent from the selected primary. This fixture
            // has no original, so attempted regeneration fails before a provider.
            assert!(cached.is_err());
        } else {
            assert_eq!(cached.unwrap().status, "already_exists");
        }
        let translated = process_translate_with(state, request(SOURCE), |_, texts| async move {
            assert_eq!(texts, ["Hello"]);
            Ok(vec!["Olá".into()])
        })
        .await
        .unwrap();
        assert_eq!(translated.status, "complete");
        // Translation output and coordination records remain in GCS, not B2.
        let objects = storage.objects.lock().await;
        assert!(objects.contains_key(&translated.vtt_path));
        assert!(objects.contains_key(&format!("{}.json", translated.vtt_path)));
        assert_eq!(
            objects.contains_key(&format!("{}/vtt/main.vtt", "a".repeat(64))),
            legacy
        );
        drop(objects);
        let origin = origin.objects.lock().await;
        assert!(origin
            .requests
            .iter()
            .all(|(method, key, _)| key.ends_with("/vtt/main.vtt")
                || (legacy && method == "HEAD" && key == &"a".repeat(64))));
        if !legacy {
            assert!(origin
                .requests
                .iter()
                .filter(|(method, _, _)| method == "GET")
                .all(|(_, _, version)| version.is_some()));
        }
    }
}

#[tokio::test]
async fn selected_transcript_errors_never_use_available_legacy_source() {
    for status in [StatusCode::FORBIDDEN, StatusCode::INTERNAL_SERVER_ERROR] {
        let storage = StorageDouble::new().await;
        storage.source(SOURCE).await;
        let origin = object_storage::tests::Origin::start().await;
        origin.objects.lock().await.fail = Some(status);
        let state = with_media(&storage, origin.store());
        assert!(process_transcribe(state.clone(), transcribe_request())
            .await
            .is_err());
        assert!(
            process_translate_with(state, request(SOURCE), |_, _| async {
                panic!("selected source failure reached translation provider")
            })
            .await
            .is_err()
        );
        assert_eq!(storage.objects.lock().await.len(), 1);
    }
    // Even a 404 from the pinned byte GET is not absence at source selection.
    for status in [
        StatusCode::NOT_FOUND,
        StatusCode::FORBIDDEN,
        StatusCode::INTERNAL_SERVER_ERROR,
    ] {
        let storage = StorageDouble::new().await;
        storage.source(SOURCE).await;
        let origin = object_storage::tests::Origin::start().await;
        let media = origin.store();
        upload_transcript_to_storage(
            &media,
            &"a".repeat(64),
            std::str::from_utf8(SOURCE).unwrap(),
        )
        .await
        .unwrap();
        origin.objects.lock().await.get_status = Some(status);
        assert!(process_translate_with(
            with_media(&storage, media),
            request(SOURCE),
            |_, _| async { panic!("pinned read failure reached translation provider") }
        )
        .await
        .is_err());
        assert_eq!(storage.objects.lock().await.len(), 1);
    }
}

#[tokio::test]
async fn selected_source_digest_and_pinned_revision_control_translation() {
    let storage = StorageDouble::new().await;
    // A matching legacy digest must not override an available selected source.
    storage.source(SOURCE).await;
    let origin = object_storage::tests::Origin::start().await;
    let media = origin.store();
    let key = format!("{}/vtt/main.vtt", "a".repeat(64));
    upload_transcript_to_storage(
        &media,
        &"a".repeat(64),
        std::str::from_utf8(SOURCE).unwrap(),
    )
    .await
    .unwrap();
    let state = with_media(&storage, media.clone());
    let (_, pinned) = find_transcript(&state, &key).await.unwrap().unwrap();
    let revised = "WEBVTT\n\n00:00:00.000 --> 00:00:01.000\nRevised\n";
    upload_transcript_to_storage(&media, &"a".repeat(64), revised)
        .await
        .unwrap();
    assert_eq!(media.read(&pinned).await.unwrap(), SOURCE);
    assert_eq!(
        process_translate_with(state.clone(), request(SOURCE), |_, _| async {
            panic!("stale digest reached translation provider")
        })
        .await
        .unwrap()
        .status,
        "source_changed"
    );
    origin.objects.lock().await.corrupt = true;
    assert_eq!(
        process_translate_with(state.clone(), request(revised.as_bytes()), |_, _| async {
            panic!("corrupt pinned bytes reached translation provider")
        })
        .await
        .unwrap()
        .status,
        "source_changed"
    );
    origin.objects.lock().await.corrupt = false;
    assert_eq!(
        process_translate_with(state, request(revised.as_bytes()), |_, texts| async {
            assert_eq!(texts, ["Revised"]);
            Ok(texts)
        })
        .await
        .unwrap()
        .status,
        "complete"
    );
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
async fn translation_provider_failures_expire_and_cool_down() {
    for status in [400, 503] {
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
        assert!(matches!(job, TranslationJob::Failed { retry_at, .. } if retry_at.is_some()));
        assert!(!job.can_start(current_epoch_secs()));
        assert!(job.can_start(current_epoch_secs() + 3600));
        drop(objects);
        process_translate_with(storage.state.clone(), request(SOURCE), |_, _| async {
            panic!("failure retried before allowed")
        })
        .await
        .unwrap();
        // Simulate the cooldown expiring: a repaired provider can complete the same job.
        storage.objects.lock().await.insert(
            format!("{}.json", result.vtt_path),
            (
                serde_json::to_vec(&TranslationJob::Failed {
                    code: "translation_rejected".into(),
                    retry_at: Some(0),
                })
                .unwrap(),
                3,
            ),
        );
        let recovered =
            process_translate_with(storage.state.clone(), request(SOURCE), |_, _| async {
                Ok(vec!["Olá".into()])
            })
            .await
            .unwrap();
        assert_eq!(recovered.status, "complete");
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
        media_storage: storage.state.media_storage.clone(),
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

#[tokio::test]
async fn translation_unsupported_language_never_creates_job_or_calls_provider() {
    let storage = StorageDouble::new().await;
    let mut unsupported = request(SOURCE);
    unsupported.lang = "zz".into();
    let error = process_translate_with(storage.state.clone(), unsupported, |_, _| async {
        panic!("unsupported language reached provider")
    })
    .await
    .err()
    .unwrap();
    assert_eq!(error.to_string(), "Invalid target language");
    assert!(storage.objects.lock().await.is_empty());
}

async fn review360_status_state(
    storage: &StorageDouble,
    media: object_storage::MediaStorage,
) -> (
    Arc<AppState>,
    tokio::sync::mpsc::Receiver<serde_json::Value>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let app = Router::new().route(
        "/status",
        axum::routing::post(move |Json(payload): Json<serde_json::Value>| {
            let tx = tx.clone();
            async move {
                tx.send(payload).await.unwrap();
                StatusCode::OK
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/status", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let config = Config::from_lookup(|key| match key {
        "GCS_BUCKET" => Some("test".into()),
        "TRANSCRIPT_WEBHOOK_URL" => Some(endpoint.clone()),
        _ => None,
    });
    (
        Arc::new(AppState {
            media_storage: media,
            gcs_client: storage.state.gcs_client.clone(),
            config,
            provider_semaphore: Arc::new(Semaphore::new(4)),
        }),
        rx,
        task,
    )
}

#[tokio::test]
async fn review360_cache_lookup_failure_delivers_terminal_status() {
    let storage = StorageDouble::new().await;
    let origin = object_storage::tests::Origin::start().await;
    origin.objects.lock().await.fail = Some(StatusCode::FORBIDDEN);
    let (state, mut rx, task) = review360_status_state(&storage, origin.store()).await;
    assert!(process_transcribe(state, transcribe_request())
        .await
        .is_err());
    task.abort();
    let status = rx.try_recv().expect("cache failure must deliver a terminal webhook even when edge drops the worker HTTP response");
    assert_eq!(status["status"], "failed");
    assert_eq!(status["error_code"], "cache_validation_failed");
    assert!(status["error_message"]
        .as_str()
        .unwrap()
        .contains("metadata response required"));
}

#[tokio::test]
async fn review360_default_gcs_metadata_error_falls_through_to_locked_processing() {
    let storage = StorageDouble::new().await;
    storage.source(SOURCE).await;
    storage
        .objects
        .lock()
        .await
        .insert("__fail_vtt_metadata_once".into(), (vec![], 1));
    let (state, mut rx, task) =
        review360_status_state(&storage, storage.state.media_storage.clone()).await;
    assert!(process_transcribe(state, transcribe_request())
        .await
        .is_err()); // No original in this fixture.
    task.abort();
    let status = rx.try_recv().expect("GCS cache lookup failure must fall through to ordinary processing under the transcript lock");
    assert_eq!(status["status"], "processing");
    assert_eq!(rx.try_recv().unwrap()["status"], "failed");
}

#[tokio::test]
async fn review360_failed_output_status_retains_sanitized_cause_chain() {
    let storage = StorageDouble::new().await;
    let origin = object_storage::tests::Origin::start().await;
    origin.objects.lock().await.fail = Some(StatusCode::FORBIDDEN);
    let (state, mut rx, task) = review360_status_state(&storage, origin.store()).await;
    assert!(finalize_transcript(
        &state,
        &"a".repeat(64),
        None,
        None,
        ParsedVtt::empty(1),
        &format!("{}/vtt/main.vtt", "a".repeat(64)),
        1
    )
    .await
    .is_err());
    task.abort();
    let status = rx.try_recv().unwrap();
    assert_eq!(status["status"], "failed");
    assert!(
        status["error_message"].as_str().unwrap().contains("403"),
        "status must preserve the adapter's sanitized provider status cause"
    );
}

#[tokio::test]
async fn review360_force_requires_existing_repair_credential_and_bypasses_selected_cache() {
    for case in ["unconfigured", "wrong", "valid"] {
        let storage = StorageDouble::new().await;
        storage.source(SOURCE).await;
        let mut state = with_media(&storage, storage.state.media_storage.clone());
        if case != "unconfigured" {
            Arc::get_mut(&mut state)
                .unwrap()
                .config
                .transcode_repair_secret = Some("synthetic-repair".into());
        }
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-divine-repair-secret",
            if case == "valid" {
                "synthetic-repair"
            } else {
                "wrong"
            }
            .parse()
            .unwrap(),
        );
        let mut request = transcribe_request();
        request.force = true;
        let app = Router::new()
            .route("/transcribe", axum::routing::post(handle_transcribe))
            .with_state(state);
        let body = serde_json::json!({"hash":request.hash,"force":true});
        use tower::ServiceExt;
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri("/transcribe")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        req.headers_mut().extend(headers);
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), match case {"unconfigured"=>StatusCode::SERVICE_UNAVAILABLE,"wrong"=>StatusCode::UNAUTHORIZED,_=>StatusCode::INTERNAL_SERVER_ERROR}, "force case {case}; authorized force must attempt regeneration (fixture original is missing), never return cached complete");
    }
}

#[tokio::test]
async fn review360_lock_failure_reports_terminal_job_generation() {
    let storage = StorageDouble::new().await;
    storage.source(SOURCE).await;
    storage
        .objects
        .lock()
        .await
        .insert("__fail_transcript_lock".into(), (vec![], 1));
    let (state, mut rx, task) =
        review360_status_state(&storage, storage.state.media_storage.clone()).await;
    let mut request = transcribe_request();
    request.job_id = Some("synthetic-subtitle-job".into());
    assert!(process_transcribe(state, request).await.is_err());
    task.abort();
    let status = rx
        .try_recv()
        .expect("a failed mandatory lock must not leave the edge job processing forever");
    assert_eq!(status["status"], "failed");
    assert_eq!(status["job_id"], "synthetic-subtitle-job");
    assert!(status["generation"].as_u64().unwrap() > 0);
    assert!(
        rx.try_recv().is_err(),
        "one failed path emits one terminal status"
    );
    assert_eq!(
        storage.objects.lock().await.len(),
        2,
        "no transcript or lock was written"
    );
}
