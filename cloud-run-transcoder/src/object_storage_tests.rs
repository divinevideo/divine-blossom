use super::*;
use axum::response::IntoResponse;
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{Response, StatusCode},
    Json, Router,
};
use blossom_core::storage_origin::StorageProvider;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
struct Stored {
    bytes: Bytes,
    mime: String,
    metadata: HashMap<String, String>,
    cache_control: Option<String>,
}
#[derive(Default)]
pub(crate) struct Objects {
    versions: HashMap<(String, String), Stored>,
    latest: HashMap<String, String>,
    pub(crate) requests: Vec<(String, String, Option<String>)>,
    pub(crate) fail: Option<StatusCode>,
    missing_version: bool,
    pub(crate) corrupt: bool,
    pub(crate) get_status: Option<StatusCode>,
    head_status: Option<StatusCode>,
    content_range: bool,
    wrong_get_metadata: bool,
    next_version: Option<String>,
}
pub(crate) struct Origin {
    endpoint: String,
    pub(crate) objects: Arc<Mutex<Objects>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Origin {
    pub(crate) async fn start() -> Self {
        let objects = Arc::new(Mutex::new(Objects::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(request).with_state(objects.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            endpoint,
            objects,
            task,
        }
    }
    pub(crate) fn store(&self) -> MediaStorage {
        MediaStorage::b2_for_test(&self.endpoint, "synthetic-bucket").unwrap()
    }
}
async fn request(State(state): State<Arc<Mutex<Objects>>>, req: Request) -> Response<Body> {
    let method = req.method().to_string();
    let url = reqwest::Url::parse(&format!("http://synthetic{}", req.uri())).unwrap();
    let version = url
        .query_pairs()
        .find(|(key, _)| key == "versionId")
        .map(|(_, value)| value.into_owned());
    let key = url
        .path()
        .strip_prefix("/synthetic-bucket/")
        .unwrap_or("")
        .to_string();
    let key = reqwest::Url::parse(&format!(
        "http://synthetic/?key={}",
        key.replace('+', "%2B")
    ))
    .unwrap()
    .query_pairs()
    .next()
    .unwrap()
    .1
    .into_owned();
    let mut state = state.lock().await;
    state
        .requests
        .push((method.clone(), key.clone(), version.clone()));
    if let Some(status) = state.fail {
        return Response::builder()
            .status(status)
            .body(Body::empty())
            .unwrap();
    }
    assert!(req
        .headers()
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("AWS4-HMAC-SHA256 Credential=synthetic-access/"));
    // Verify the actual wire target and canonical headers independently of
    // the adapter's request construction; signing crypto has separate goldens.
    let authorization = req.headers()["authorization"].to_str().unwrap();
    let signed = authorization
        .split("SignedHeaders=")
        .nth(1)
        .unwrap()
        .split(',')
        .next()
        .unwrap();
    let mut canonical_headers = String::new();
    for name in signed.split(';') {
        let value = req.headers()[name]
            .to_str()
            .unwrap()
            .split_ascii_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(&value);
        canonical_headers.push('\n');
    }
    let timestamp = req.headers()["x-amz-date"].to_str().unwrap();
    let payload_hash = req.headers()["x-amz-content-sha256"].to_str().unwrap();
    let canonical = format!(
        "{method}\n{}\n{}\n{canonical_headers}\n{signed}\n{payload_hash}",
        req.uri().path(),
        req.uri().query().unwrap_or("")
    );
    assert_eq!(
        authorization,
        blossom_core::s3_signing::authorization(
            "synthetic-access",
            "synthetic-secret",
            "us-west-004",
            &timestamp[..8],
            timestamp,
            &canonical,
            signed
        )
        .unwrap()
    );
    if method == "PUT" {
        let mime = req.headers()["content-type"].to_str().unwrap().to_string();
        let cache_control = req
            .headers()
            .get("cache-control")
            .map(|v| v.to_str().unwrap().to_string());
        let metadata = req
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                name.as_str()
                    .strip_prefix("x-amz-meta-")
                    .map(|key| (key.to_string(), value.to_str().unwrap().to_string()))
            })
            .collect();
        let payload_sha = req.headers()["x-amz-content-sha256"]
            .to_str()
            .unwrap()
            .to_string();
        let body = to_bytes(req.into_body(), 1024 * 1024).await.unwrap();
        assert_eq!(hex::encode(Sha256::digest(&body)), payload_sha);
        let v = state
            .next_version
            .take()
            .unwrap_or_else(|| format!("synthetic-version-{}", state.versions.len() + 1));
        state.latest.insert(key.clone(), v.clone());
        state.versions.insert(
            (key, v.clone()),
            Stored {
                bytes: body,
                mime,
                metadata,
                cache_control,
            },
        );
        let mut response = Response::builder().status(200);
        if !state.missing_version {
            response = response.header("x-amz-version-id", v);
        }
        return response.body(Body::empty()).unwrap();
    }
    let selected = version.or_else(|| state.latest.get(&key).cloned());
    let Some(version) = selected else {
        return Response::builder().status(404).body(Body::empty()).unwrap();
    };
    let Some(object) = state.versions.get(&(key, version.clone())) else {
        return Response::builder().status(404).body(Body::empty()).unwrap();
    };
    let mut response = Response::builder()
        .status(if method == "GET" {
            state.get_status.unwrap_or(StatusCode::OK)
        } else {
            state.head_status.unwrap_or(StatusCode::OK)
        })
        .header("x-amz-version-id", version)
        .header("content-type", &object.mime)
        .header("content-length", object.bytes.len());
    if method == "GET" && state.content_range {
        response = response.header(
            "content-range",
            format!("bytes 0-{}/{}", object.bytes.len() - 1, object.bytes.len()),
        );
    }
    if method == "GET" && state.wrong_get_metadata {
        response = response.header("x-amz-meta-unexpected", "changed");
    }
    if let Some(cache) = &object.cache_control {
        response = response.header("cache-control", cache);
    }
    for (key, value) in &object.metadata {
        response = response.header(format!("x-amz-meta-{key}"), value);
    }
    let body = if method == "HEAD" {
        Bytes::new()
    } else if state.corrupt {
        Bytes::from(vec![b'x'; object.bytes.len()])
    } else {
        object.bytes.clone()
    };
    response.body(Body::from(body)).unwrap()
}

#[tokio::test]
async fn b2_round_trip_preserves_real_object_contract_without_gcs() {
    let origin = Origin::start().await;
    let store = origin.store();
    let original = Bytes::from_static(b"synthetic original");
    let parent = hex::encode(Sha256::digest(&original));
    let custom = HashMap::from([
        ("owner".into(), "c".repeat(64)),
        ("source_sha256".into(), parent.clone()),
    ]);
    let receipt = store
        .put_verified(&parent, original.clone(), "video/mp4", custom.clone(), None)
        .await
        .unwrap();
    assert_eq!(receipt.object.reference.provider, StorageProvider::B2);
    assert_eq!(receipt.sha256, parent);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("original");
    store
        .download_original(&receipt.object, &parent, &path)
        .await
        .unwrap();
    assert_eq!(tokio::fs::read(path).await.unwrap(), original);
    for (key, mime) in [
        (format!("{parent}/hls/stream_720p.mp4"), "video/mp4"),
        (format!("{parent}/hls/stream_720p.ts"), "video/mp2t"),
        (
            format!("{parent}/hls/master.m3u8"),
            "application/vnd.apple.mpegurl",
        ),
        (format!("{parent}.jpg"), "image/jpeg"),
        (hex::encode(Sha256::digest(b"audio")), "audio/mp4"),
    ] {
        let body = if mime == "audio/mp4" {
            Bytes::from_static(b"audio")
        } else {
            Bytes::from_static(b"artifact bytes")
        };
        let receipt = store
            .put_verified(
                &key,
                body.clone(),
                mime,
                custom.clone(),
                Some("public, max-age=31536000, immutable".into()),
            )
            .await
            .unwrap();
        assert_eq!(receipt.object.reference.key, key);
        assert!(receipt.object.reference.version.is_some());
        assert_eq!(receipt.object.size, body.len() as u64);
        assert_eq!(receipt.object.content_type, mime);
        assert_eq!(receipt.object.custom, custom);
        assert_eq!(receipt.sha256, hex::encode(Sha256::digest(&body)));
    }
    let state = origin.objects.lock().await;
    assert!(state
        .requests
        .iter()
        .filter(|(method, _, _)| method == "GET")
        .all(|(_, _, version)| version.is_some()));
}

#[tokio::test]
async fn pinned_original_read_does_not_follow_a_changed_latest_version() {
    let origin = Origin::start().await;
    let store = origin.store();
    let body = Bytes::from_static(b"original");
    let hash = hex::encode(Sha256::digest(&body));
    let receipt = store
        .put_verified(&hash, body.clone(), "video/mp4", HashMap::new(), None)
        .await
        .unwrap();
    {
        let mut state = origin.objects.lock().await;
        state.latest.insert(hash.clone(), "replacement".into());
        state.versions.insert(
            (hash.clone(), "replacement".into()),
            Stored {
                bytes: Bytes::from_static(b"different"),
                mime: "video/mp4".into(),
                metadata: HashMap::new(),
                cache_control: None,
            },
        );
    }
    let pinned = store
        .stat_reference(&receipt.object.reference)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pinned, receipt.object);
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("input");
    store
        .download_original(&receipt.object, &hash, &output)
        .await
        .unwrap();
    assert_eq!(tokio::fs::read(output).await.unwrap(), body);
}

#[tokio::test]
async fn unverified_writes_and_auth_failures_never_return_receipts_or_fallback() {
    let origin = Origin::start().await;
    let store = origin.store();
    origin.objects.lock().await.missing_version = true;
    assert!(store
        .put_verified(
            "artifact.mp4",
            Bytes::from_static(b"bytes"),
            "video/mp4",
            HashMap::new(),
            None
        )
        .await
        .is_err());
    assert_eq!(origin.objects.lock().await.requests.len(), 1);
    origin.objects.lock().await.missing_version = false;
    origin.objects.lock().await.corrupt = true;
    assert!(store
        .put_verified(
            "artifact.mp4",
            Bytes::from_static(b"bytes"),
            "video/mp4",
            HashMap::new(),
            None
        )
        .await
        .is_err());
    origin.objects.lock().await.fail = Some(StatusCode::FORBIDDEN);
    assert!(store.stat("artifact.mp4").await.is_err());
    origin.objects.lock().await.fail = Some(StatusCode::NOT_FOUND);
    assert!(store.stat("artifact.mp4").await.unwrap().is_none());
}

#[test]
fn storage_configuration_is_default_gcs_and_explicit_b2_fail_closed() {
    assert!(matches!(
        StorageConfiguration::parse(|_| None).unwrap(),
        StorageConfiguration::Gcs
    ));
    assert!(StorageConfiguration::parse(
        |key| (key == "MEDIA_STORAGE_PROVIDER").then(|| "unknown".into())
    )
    .is_err());
    assert!(StorageConfiguration::parse(
        |key| (key == "MEDIA_STORAGE_PROVIDER").then(|| "b2".into())
    )
    .is_err());
}

#[test]
fn b2_primary_configuration_requires_b2_credentials_and_gcs_backup() {
    let values = HashMap::from([
        ("MEDIA_STORAGE_PROVIDER", "b2_primary"),
        ("B2_MEDIA_BUCKET", "synthetic-bucket"),
        ("B2_REGION", "us-west-004"),
        ("B2_ACCESS_KEY_ID", "synthetic-access"),
        ("B2_SECRET_ACCESS_KEY", "synthetic-secret"),
    ]);
    let configured = StorageConfiguration::parse(|name| values.get(name).map(|v| (*v).into()));
    assert!(
        configured.is_ok(),
        "explicit B2-primary with required backup must be supported"
    );
    assert!(MediaStorage::configured(configured.unwrap(), None, "synthetic-gcs".into()).is_err());
    for missing in [
        "B2_MEDIA_BUCKET",
        "B2_REGION",
        "B2_ACCESS_KEY_ID",
        "B2_SECRET_ACCESS_KEY",
    ] {
        assert!(
            StorageConfiguration::parse(|name| {
                (name != missing)
                    .then(|| values.get(name).map(|v| (*v).into()))
                    .flatten()
            })
            .is_err(),
            "missing {missing} must not select a partial writer"
        );
    }
}

fn b2_primary_store(origin: &Origin, gcs: GcsClient) -> MediaStorage {
    let values = HashMap::from([
        ("MEDIA_STORAGE_PROVIDER", "b2_primary"),
        ("B2_MEDIA_BUCKET", "synthetic-bucket"),
        ("B2_REGION", "us-west-004"),
        ("B2_ACCESS_KEY_ID", "synthetic-access"),
        ("B2_SECRET_ACCESS_KEY", "synthetic-secret"),
    ]);
    let config = StorageConfiguration::parse(|name| values.get(name).map(|v| (*v).into())).unwrap();
    let mut store = MediaStorage::configured(config, Some(gcs), "synthetic-gcs".into()).unwrap();
    if let Backend::B2 { endpoint, .. } = &mut store.backend {
        *endpoint = origin.endpoint.clone();
    } else {
        panic!("B2 must remain the primary backend");
    }
    store
}

async fn deduplicate_transcript(state: Arc<crate::AppState>) -> anyhow::Result<String> {
    let response = crate::process_transcribe(
        state,
        crate::TranscodeRequest {
            hash: "a".repeat(64),
            force: false,
            owner: None,
            job_id: None,
            lang: None,
        },
    )
    .await?;
    Ok(response.status)
}

fn transcript_state(store: MediaStorage, client: GcsClient) -> Arc<crate::AppState> {
    Arc::new(crate::AppState {
        media_storage: store,
        gcs_client: client,
        config: crate::Config::from_lookup(|key| {
            (key == "GCS_BUCKET").then(|| "synthetic-gcs".to_string())
        }),
        provider_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
    })
}

#[tokio::test]
async fn transcription_dedup_repairs_required_backup_without_rewriting_primary_or_matching_backup()
{
    for damage in ["missing", "bytes", "metadata"] {
        let origin = Origin::start().await;
        let (backup, client, task) = gcs_origin().await;
        let store = b2_primary_store(&origin, client.clone());
        let key = format!("{}/vtt/main.vtt", "a".repeat(64));
        let bytes = Bytes::from_static(b"WEBVTT\n\n00:00:00.000 --> 00:00:01.000\nHello\n");
        let custom = HashMap::from([("source_sha256".into(), "a".repeat(64))]);
        let primary = origin
            .store()
            .put_verified(
                &key,
                bytes.clone(),
                "text/vtt",
                custom.clone(),
                Some("no-cache".into()),
            )
            .await
            .unwrap()
            .object;
        if damage != "missing" {
            store.ensure_required_backup(&primary).await.unwrap();
            let mut backup = backup.lock().await;
            if damage == "bytes" {
                // Same length and unchanged metadata: only a pinned byte comparison detects this.
                backup.bytes = "x".repeat(bytes.len());
            } else {
                backup.object.as_mut().unwrap()["metadata"]["source_sha256"] =
                    "b".repeat(64).into();
            }
        }
        let state = transcript_state(store.clone(), client);
        assert_eq!(
            deduplicate_transcript(state.clone()).await.unwrap(),
            "already_exists"
        );
        let writes = {
            let backup = backup.lock().await;
            assert_eq!(backup.bytes.as_bytes(), bytes.as_ref());
            assert_eq!(
                backup.object.as_ref().unwrap()["metadata"]["source_sha256"],
                custom["source_sha256"]
            );
            assert_eq!(backup.object.as_ref().unwrap()["cacheControl"], "no-cache");
            backup
                .requests
                .iter()
                .filter(|(method, _)| method == "POST")
                .count()
        };
        assert_eq!(
            deduplicate_transcript(state).await.unwrap(),
            "already_exists"
        );
        assert_eq!(
            backup
                .lock()
                .await
                .requests
                .iter()
                .filter(|(method, _)| method == "POST")
                .count(),
            writes
        );
        assert_eq!(store.stat(&key).await.unwrap().unwrap(), primary);
        assert_eq!(
            origin
                .objects
                .lock()
                .await
                .requests
                .iter()
                .filter(|(method, _, _)| method == "PUT")
                .count(),
            1
        );
        task.abort();
    }
}

#[tokio::test]
async fn transcription_dedup_cannot_acknowledge_failed_backup_and_repairs_on_retry() {
    let origin = Origin::start().await;
    let (backup, client, task) = gcs_origin().await;
    let store = b2_primary_store(&origin, client.clone());
    let key = format!("{}/vtt/main.vtt", "a".repeat(64));
    let bytes = Bytes::from_static(b"WEBVTT\n\n00:00:00.000 --> 00:00:01.000\nHello\n");
    backup.lock().await.fail_upload = Some(StatusCode::FORBIDDEN);
    // Reproduce the partial write left behind by a failed required-backup upload.
    assert!(store
        .put_verified(&key, bytes.clone(), "text/vtt", HashMap::new(), None)
        .await
        .is_err());
    let primary = store.stat(&key).await.unwrap().unwrap();
    let state = transcript_state(store.clone(), client);
    assert!(deduplicate_transcript(state.clone()).await.is_err());
    assert!(backup.lock().await.object.is_none());
    backup.lock().await.fail_upload = None;
    assert_eq!(
        deduplicate_transcript(state.clone()).await.unwrap(),
        "already_exists"
    );
    assert_eq!(backup.lock().await.bytes.as_bytes(), bytes.as_ref());
    // Read failures also fail closed rather than treating a backup as absent.
    backup.lock().await.fail = Some(StatusCode::FORBIDDEN);
    assert!(deduplicate_transcript(state.clone()).await.is_err());
    backup.lock().await.fail = None;
    assert_eq!(
        deduplicate_transcript(state).await.unwrap(),
        "already_exists"
    );
    assert_eq!(store.stat(&key).await.unwrap().unwrap(), primary);
    assert_eq!(
        origin
            .objects
            .lock()
            .await
            .requests
            .iter()
            .filter(|(method, _, _)| method == "PUT")
            .count(),
        1
    );
    task.abort();
}

#[tokio::test]
async fn processing_reads_missing_primary_from_pinned_legacy_gcs_original() {
    let origin = Origin::start().await;
    let (backup, client, task) = gcs_origin().await;
    let bytes = Bytes::from_static(b"legacy original still awaiting bulk copy");
    let hash = hex::encode(Sha256::digest(&bytes));
    let gcs = MediaStorage::gcs(client.clone(), "synthetic-gcs".into());
    gcs.put_verified(
        &hash,
        bytes.clone(),
        "video/mp4",
        HashMap::from([("owner".into(), "c".repeat(64))]),
        None,
    )
    .await
    .unwrap();
    backup.lock().await.requests.clear();
    let store = b2_primary_store(&origin, client);
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("original");
    let verified = crate::download_media_original(&store, &hash, &output)
        .await
        .expect("a missing B2 original must preserve legacy GCS processing");
    assert_eq!(tokio::fs::read(output).await.unwrap(), bytes);
    assert_eq!(verified.object.reference.provider, StorageProvider::Gcs);
    assert_eq!(
        verified.object.reference.version.as_deref(),
        Some("123456789")
    );
    assert_eq!(verified.object.custom["owner"], "c".repeat(64));
    assert_eq!(verified.sha256, hash);
    assert_eq!(
        origin.objects.lock().await.requests,
        vec![("HEAD".into(), hash, None)]
    );
    let backup = backup.lock().await;
    assert!(backup.requests.iter().all(|(method, _)| method == "GET"));
    assert!(backup
        .requests
        .iter()
        .any(|(_, uri)| uri.contains("alt=media")
            && uri.contains("generation=123456789")
            && uri.contains("ifMetagenerationMatch=1")));
    task.abort();
}

#[tokio::test]
async fn processing_prefers_primary_and_never_masks_primary_errors_with_gcs() {
    for failure in [
        "none",
        "forbidden",
        "unavailable",
        "corrupt",
        "lost_version",
    ] {
        let origin = Origin::start().await;
        let (backup, client, task) = gcs_origin().await;
        let store = b2_primary_store(&origin, client);
        let bytes = Bytes::from_static(b"verified primary original");
        let hash = hex::encode(Sha256::digest(&bytes));
        store
            .put_verified(&hash, bytes.clone(), "video/mp4", HashMap::new(), None)
            .await
            .unwrap();
        backup.lock().await.requests.clear();
        {
            let mut state = origin.objects.lock().await;
            state.fail = match failure {
                "forbidden" => Some(StatusCode::FORBIDDEN),
                "unavailable" => Some(StatusCode::SERVICE_UNAVAILABLE),
                _ => None,
            };
            state.corrupt = failure == "corrupt";
            state.get_status = (failure == "lost_version").then_some(StatusCode::NOT_FOUND);
        }
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("original");
        let result = crate::download_media_original(&store, &hash, &output).await;
        if failure == "none" {
            assert_eq!(
                result.unwrap().object.reference.provider,
                StorageProvider::B2
            );
            assert_eq!(tokio::fs::read(output).await.unwrap(), bytes);
        } else {
            assert!(result.is_err(), "primary {failure} must fail closed");
            assert!(!output.exists());
        }
        assert!(
            backup.lock().await.requests.is_empty(),
            "unexpected GCS read for {failure}"
        );
        task.abort();
    }
}

#[tokio::test]
async fn backfill_segments_use_pinned_b2_and_fall_back_only_when_missing() {
    let origin = Origin::start().await;
    let (gcs_state, client, task) = gcs_origin().await;
    let legacy = MediaStorage::gcs(client.clone(), "synthetic-gcs".into());
    let store = b2_primary_store(&origin, client);
    let prefix = format!("{}/hls", "a".repeat(64));
    let primary_key = format!("{prefix}/stream_720p.ts");
    let legacy_key = format!("{prefix}/stream_480p.ts");
    let primary = origin
        .store()
        .put_verified(
            &primary_key,
            Bytes::from_static(b"B2 segment"),
            "video/mp2t",
            HashMap::new(),
            None,
        )
        .await
        .unwrap();
    legacy
        .put_verified(
            &primary_key,
            Bytes::from_static(b"GCS segment"),
            "video/mp2t",
            HashMap::new(),
            None,
        )
        .await
        .unwrap();
    gcs_state.lock().await.requests.clear();
    origin.objects.lock().await.requests.clear();

    let dir = tempfile::tempdir().unwrap();
    let b2_file = dir.path().join("720p.ts");
    assert!(store
        .download_processing_segment(&primary_key, &b2_file)
        .await
        .unwrap());
    assert_eq!(tokio::fs::read(&b2_file).await.unwrap(), b"B2 segment");
    assert!(gcs_state.lock().await.requests.is_empty());
    assert!(origin.objects.lock().await.requests.contains(&(
        "GET".into(),
        primary_key.clone(),
        primary.object.reference.version,
    )));

    origin.objects.lock().await.get_status = Some(StatusCode::NOT_FOUND);
    let lost_version = dir.path().join("lost.ts");
    assert!(store
        .download_processing_segment(&primary_key, &lost_version)
        .await
        .is_err());
    assert!(!lost_version.exists());
    assert!(gcs_state.lock().await.requests.is_empty());

    legacy
        .put_verified(
            &legacy_key,
            Bytes::from_static(b"GCS segment"),
            "video/mp2t",
            HashMap::new(),
            None,
        )
        .await
        .unwrap();
    gcs_state.lock().await.requests.clear();
    let legacy_file = dir.path().join("480p.ts");
    assert!(store
        .download_processing_segment(&legacy_key, &legacy_file)
        .await
        .unwrap());
    assert_eq!(tokio::fs::read(&legacy_file).await.unwrap(), b"GCS segment");
    assert!(gcs_state
        .lock()
        .await
        .requests
        .iter()
        .any(|(method, path)| method == "GET" && path.contains("stream_480p.ts")));
    task.abort();
}

#[tokio::test]
async fn backfill_cannot_report_success_without_a_segment_in_either_store() {
    let origin = Origin::start().await;
    let (gcs_state, client, task) = gcs_origin().await;
    let store = b2_primary_store(&origin, client);
    let error = crate::backfill_fmp4(&store, &"b".repeat(64))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("did not produce any MP4"));
    assert!(origin
        .objects
        .lock()
        .await
        .requests
        .iter()
        .all(|(method, _, _)| method == "HEAD"));
    assert!(gcs_state
        .lock()
        .await
        .requests
        .iter()
        .all(|(method, _)| method == "GET"));
    task.abort();
}

#[tokio::test]
async fn processing_legacy_fallback_still_rejects_corrupt_or_changed_gcs_source() {
    for corrupt in [false, true] {
        let origin = Origin::start().await;
        let (backup, client, task) = gcs_origin().await;
        let bytes = Bytes::from_static(b"legacy source must remain verified");
        let hash = hex::encode(Sha256::digest(&bytes));
        MediaStorage::gcs(client.clone(), "synthetic-gcs".into())
            .put_verified(&hash, bytes, "video/mp4", HashMap::new(), None)
            .await
            .unwrap();
        {
            let mut state = backup.lock().await;
            state.requests.clear();
            state.corrupt = corrupt;
            state.patch_after_metadata = !corrupt;
        }
        let store = b2_primary_store(&origin, client);
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("original");
        assert!(crate::download_media_original(&store, &hash, &output)
            .await
            .is_err());
        assert!(!output.exists());
        assert!(
            !backup.lock().await.requests.is_empty(),
            "legacy source was never checked"
        );
        task.abort();
    }
}

#[tokio::test]
async fn processing_legacy_fallback_does_not_hide_missing_or_unavailable_gcs() {
    for status in [
        StatusCode::NOT_FOUND,
        StatusCode::FORBIDDEN,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let origin = Origin::start().await;
        let (backup, client, task) = gcs_origin().await;
        backup.lock().await.fail = Some(status);
        let store = b2_primary_store(&origin, client);
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("original");
        assert!(
            crate::download_media_original(&store, &"a".repeat(64), &output)
                .await
                .is_err()
        );
        assert!(!output.exists());
        assert!(backup
            .lock()
            .await
            .requests
            .iter()
            .all(|(method, _)| method == "GET"));
        assert!(origin
            .objects
            .lock()
            .await
            .requests
            .iter()
            .all(|(method, _, _)| method == "HEAD"));
        task.abort();
    }
}

#[tokio::test]
async fn b2_primary_writes_and_verifies_required_gcs_backup_before_success() {
    let origin = Origin::start().await;
    let (backup, client, task) = gcs_origin().await;
    let store = b2_primary_store(&origin, client);
    let bytes = Bytes::from_static(b"replicated media");
    let receipt = store
        .put_verified(
            "artifact.mp4",
            bytes.clone(),
            "video/mp4",
            HashMap::new(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(receipt.object.reference.provider, StorageProvider::B2);
    assert_eq!(receipt.sha256, hex::encode(Sha256::digest(&bytes)));
    let backup = backup.lock().await;
    assert_eq!(
        backup
            .requests
            .iter()
            .filter(|(method, _)| method == "POST")
            .count(),
        1
    );
    assert!(backup.requests.iter().any(|(method, uri)| method == "GET"
        && uri.contains("alt=media")
        && uri.contains("generation=123456789")
        && uri.contains("ifMetagenerationMatch=1")));
    assert_eq!(backup.bytes.as_bytes(), bytes.as_ref());
    let replica = receipt
        .required_backup
        .as_ref()
        .expect("verified backup identity must be returned");
    assert_eq!(replica.reference.provider, StorageProvider::Gcs);
    assert_eq!(replica.reference.version.as_deref(), Some("123456789"));
    assert_eq!(replica.size, receipt.object.size);
    drop(backup);
    task.abort();
}

#[tokio::test]
async fn b2_primary_cannot_acknowledge_failed_or_corrupt_required_backup() {
    for corrupt in [false, true] {
        let origin = Origin::start().await;
        let (backup, client, task) = gcs_origin().await;
        {
            let mut state = backup.lock().await;
            state.fail = (!corrupt).then_some(StatusCode::FORBIDDEN);
            state.corrupt = corrupt;
        }
        let store = b2_primary_store(&origin, client);
        assert!(
            store
                .put_verified(
                    "artifact.mp4",
                    Bytes::from_static(b"replicated media"),
                    "video/mp4",
                    HashMap::new(),
                    None
                )
                .await
                .is_err(),
            "backup corruption={corrupt} must not become successful processing output"
        );
        assert_eq!(
            origin.objects.lock().await.requests.len(),
            3,
            "primary must have been verified before backup is attempted"
        );
        task.abort();
    }
}

#[tokio::test]
async fn existing_audio_backup_repair_preserves_primary_version_and_provenance() {
    let origin = Origin::start().await;
    let (backup, client, task) = gcs_origin().await;
    let bytes = Bytes::from_static(b"shared media");
    let custom = HashMap::from([
        ("owner".into(), "original-owner".into()),
        ("source_sha256".into(), "original-source".into()),
    ]);
    let primary = origin
        .store()
        .put_verified(
            "audio.mp4",
            bytes.clone(),
            "audio/mp4",
            custom.clone(),
            None,
        )
        .await
        .unwrap();
    let store = b2_primary_store(&origin, client);
    let before = origin.objects.lock().await.requests.len();
    store
        .ensure_existing_backup(&primary.object, bytes)
        .await
        .unwrap();
    let objects = origin.objects.lock().await;
    assert_eq!(
        objects.requests.len(),
        before + 1,
        "repair only verifies the pinned primary, without another primary PUT"
    );
    assert_eq!(
        objects.latest["audio.mp4"],
        primary.object.reference.version.unwrap()
    );
    assert_eq!(
        backup.lock().await.object.as_ref().unwrap()["metadata"]["owner"],
        "original-owner"
    );
    assert_eq!(
        backup.lock().await.object.as_ref().unwrap()["metadata"]["source_sha256"],
        "original-source"
    );
    task.abort();
}

#[tokio::test]
async fn b2_primary_never_writes_backup_when_primary_verification_fails() {
    let origin = Origin::start().await;
    origin.objects.lock().await.corrupt = true;
    let (backup, client, task) = gcs_origin().await;
    let store = b2_primary_store(&origin, client);
    assert!(store
        .put_verified(
            "artifact.mp4",
            Bytes::from_static(b"replicated media"),
            "video/mp4",
            HashMap::new(),
            None
        )
        .await
        .is_err());
    assert!(backup.lock().await.requests.is_empty());
    task.abort();
}

#[tokio::test]
async fn hls_reuse_checks_all_required_copies_without_rewriting_them() {
    let primary = Origin::start().await;
    let replica = Origin::start().await;
    // Use two versioned loopback stores for the backend-independent family
    // comparison; the GCS-specific backup wire path is covered above.
    let mut store = primary.store();
    store.required_backup = Some(Box::new(replica.store()));
    let hash = "a".repeat(64);
    let prefix = format!("{hash}/hls");
    let files = [
        "master.m3u8",
        "stream_720p.m3u8",
        "stream_480p.m3u8",
        "stream_720p.ts",
        "stream_480p.ts",
    ];
    for filename in files {
        assert!(!store.can_reuse_hls(&hash).await.unwrap());
        store
            .put_verified(
                &format!("{prefix}/{filename}"),
                Bytes::from_static(b"synthetic media"),
                "application/octet-stream",
                HashMap::new(),
                None,
            )
            .await
            .unwrap();
    }
    // The best-effort progressive outputs need not exist, but every produced
    // copy must match. A successful duplicate performs reads only.
    let writes_before = primary.objects.lock().await.versions.len();
    let replicas_before = replica.objects.lock().await.versions.len();
    assert!(store.can_reuse_hls(&hash).await.unwrap());
    assert_eq!(primary.objects.lock().await.versions.len(), writes_before);
    assert_eq!(replica.objects.lock().await.versions.len(), replicas_before);

    let key = format!("{prefix}/stream_480p.ts");
    replica.objects.lock().await.latest.remove(&key);
    assert!(!store.can_reuse_hls(&hash).await.unwrap());
    // A primary overwrite whose backup failed cannot be acknowledged merely
    // because the old backup and master still exist.
    primary
        .store()
        .put_verified(
            &key,
            Bytes::from_static(b"altered media!!"),
            "application/octet-stream",
            HashMap::new(),
            None,
        )
        .await
        .unwrap();
    let old_version = replica
        .objects
        .lock()
        .await
        .versions
        .keys()
        .find(|(name, _)| name == &key)
        .unwrap()
        .1
        .clone();
    replica.objects.lock().await.latest.insert(key, old_version);
    assert!(!store.can_reuse_hls(&hash).await.unwrap());
}

#[tokio::test]
async fn hls_reuse_requires_backups_for_present_progressive_outputs() {
    let primary = Origin::start().await;
    let replica = Origin::start().await;
    let mut store = primary.store();
    store.required_backup = Some(Box::new(replica.store()));
    let hash = "b".repeat(64);
    for filename in [
        "master.m3u8",
        "stream_720p.m3u8",
        "stream_480p.m3u8",
        "stream_720p.ts",
        "stream_480p.ts",
        "stream_720p.mp4",
        "stream_480p.mp4",
    ] {
        store
            .put_verified(
                &format!("{hash}/hls/{filename}"),
                Bytes::from_static(b"synthetic media"),
                "application/octet-stream",
                HashMap::new(),
                None,
            )
            .await
            .unwrap();
    }
    assert!(store.can_reuse_hls(&hash).await.unwrap());
    replica
        .objects
        .lock()
        .await
        .latest
        .remove(&format!("{hash}/hls/stream_480p.mp4"));
    assert!(!store.can_reuse_hls(&hash).await.unwrap());
    // Legacy modes retain master-only reuse even with missing variants.
    assert!(primary.store().can_reuse_hls(&hash).await.unwrap());
}

#[tokio::test]
async fn full_reads_reject_partial_responses_and_preserve_destination() {
    let origin = Origin::start().await;
    let store = origin.store();
    let body = Bytes::from_static(b"original");
    let hash = hex::encode(Sha256::digest(&body));
    let receipt = store
        .put_verified(&hash, body, "video/mp4", HashMap::new(), None)
        .await
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("original");
    tokio::fs::write(&path, b"existing destination")
        .await
        .unwrap();
    for mode in 0..4 {
        {
            let mut state = origin.objects.lock().await;
            state.get_status = (mode == 0).then_some(StatusCode::PARTIAL_CONTENT);
            state.content_range = mode == 1;
            state.wrong_get_metadata = mode == 2;
            state.corrupt = mode == 3;
        }
        assert!(
            store
                .download_original(&receipt.object, &hash, &path)
                .await
                .is_err(),
            "mode {mode}"
        );
        assert_eq!(
            tokio::fs::read(&path).await.unwrap(),
            b"existing destination"
        );
    }
}

#[tokio::test]
async fn foreign_and_unpinned_references_are_rejected_without_network_io() {
    let origin = Origin::start().await;
    let store = origin.store();
    let bytes = Bytes::from_static(b"original");
    let hash = hex::encode(Sha256::digest(&bytes));
    let receipt = store
        .put_verified(&hash, bytes, "video/mp4", HashMap::new(), None)
        .await
        .unwrap();
    let before = origin.objects.lock().await.requests.len();
    for mode in 0..3 {
        let mut object = receipt.object.clone();
        match mode {
            0 => object.reference.provider = StorageProvider::Gcs,
            1 => object.reference.bucket = "other-bucket".into(),
            _ => object.reference.version = None,
        }
        assert!(store.verify_sha256(&object, &hash).await.is_err());
        assert!(store.stat_reference(&object.reference).await.is_err());
    }
    assert_eq!(origin.objects.lock().await.requests.len(), before);
}

#[tokio::test]
async fn encoded_keys_and_opaque_versions_preserve_exact_identity() {
    let origin = Origin::start().await;
    let store = origin.store();
    let key = "family/space + percent% unicode-é.mp4";
    let version = "version+/= ?%";
    origin.objects.lock().await.next_version = Some(version.into());
    let receipt = store
        .put_verified(
            key,
            Bytes::from_static(b"bytes"),
            "video/mp4",
            HashMap::new(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(receipt.object.reference.key, key);
    assert_eq!(receipt.object.reference.version.as_deref(), Some(version));
    let state = origin.objects.lock().await;
    assert!(state
        .requests
        .iter()
        .all(|(_, actual_key, _)| actual_key == key));
    assert!(state
        .requests
        .iter()
        .filter(|(method, _, _)| method != "PUT")
        .all(|(_, _, actual)| actual.as_deref() == Some(version)));
}

#[tokio::test]
async fn production_helpers_preserve_hls_provenance_without_gcs() {
    let origin = Origin::start().await;
    let store = origin.store();
    let bytes = Bytes::from_static(b"synthetic source");
    let hash = hex::encode(Sha256::digest(&bytes));
    store
        .put_verified(&hash, bytes.clone(), "video/mp4", HashMap::new(), None)
        .await
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input");
    let source = crate::download_media_original(&store, &hash, &input)
        .await
        .unwrap();
    assert_eq!(source.sha256, hash);
    assert_eq!(tokio::fs::read(&input).await.unwrap(), bytes);
    let outputs = directory.path().join("hls");
    tokio::fs::create_dir(&outputs).await.unwrap();
    for name in ["master.m3u8", "stream_720p.ts", "stream_720p.mp4"] {
        tokio::fs::write(outputs.join(name), b"output bytes")
            .await
            .unwrap();
    }
    let custom = HashMap::from([("owner".into(), "c".repeat(64))]);
    let receipts = crate::upload_hls(
        &store,
        &hash,
        &outputs,
        &crate::SourceObjectMetadata {
            content_type: Some("video/mp4".into()),
            custom: custom.clone(),
        },
    )
    .await
    .unwrap();
    assert_eq!(receipts.len(), 3);
    for receipt in receipts {
        let name = receipt.object.reference.key.rsplit('/').next().unwrap();
        assert_eq!(receipt.object.custom.get("hls_filename").unwrap(), name);
        assert_eq!(receipt.object.custom.get("source_sha256").unwrap(), &hash);
        assert_eq!(receipt.object.custom.get("derivative").unwrap(), "hls");
        assert_eq!(
            receipt.object.custom.get("source_content_type").unwrap(),
            "video/mp4"
        );
        assert_eq!(receipt.object.custom.get("owner"), custom.get("owner"));
        assert_eq!(receipt.object.size, 12);
        assert_eq!(
            receipt.object.cache_control.as_deref(),
            Some("public, max-age=31536000, immutable")
        );
        assert_eq!(
            receipt.object.content_type,
            if name.ends_with("m3u8") {
                "application/vnd.apple.mpegurl"
            } else if name.ends_with("ts") {
                "video/mp2t"
            } else {
                "video/mp4"
            }
        );
    }
}

#[derive(Default)]
struct GcsObjects {
    object: Option<serde_json::Value>,
    bytes: String,
    patch_after_metadata: bool,
    fail: Option<StatusCode>,
    fail_upload: Option<StatusCode>,
    corrupt: bool,
    requests: Vec<(String, String)>,
    locks: HashMap<String, (Vec<u8>, i64)>,
    lock_requests: Vec<String>,
    require_transcript_lock: bool,
    race_on_repair: bool,
}
async fn gcs_request(State(state): State<Arc<Mutex<GcsObjects>>>, req: Request) -> Response<Body> {
    let method = req.method().to_string();
    let uri = req.uri().to_string();
    let mut state = state.lock().await;
    let url = reqwest::Url::parse(&format!("http://synthetic{uri}")).unwrap();
    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
    let encoded = uri
        .split("/o/")
        .nth(1)
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap();
    let key = query.get("name").cloned().unwrap_or_else(|| {
        reqwest::Url::parse(&format!("http://synthetic/?name={encoded}"))
            .unwrap()
            .query_pairs()
            .next()
            .unwrap()
            .1
            .into_owned()
    });
    let error = |code: u16| {
        Response::builder()
            .status(code)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                "{{\"error\":{{\"code\":{code},\"message\":\"synthetic failure\",\"errors\":[]}}}}"
            )))
            .unwrap()
    };
    if key.ends_with("/vtt/.lock") {
        state.lock_requests.push(method.clone());
        let current = state.locks.get(&key).cloned();
        let generation = current.as_ref().map(|(_, g)| *g).unwrap_or(0);
        if query
            .get("ifGenerationMatch")
            .is_some_and(|v| v != &generation.to_string())
        {
            return error(412);
        }
        if method == "DELETE" {
            state.locks.remove(&key);
            return Response::builder().status(204).body(Body::empty()).unwrap();
        }
        if method == "POST" {
            let bytes = to_bytes(req.into_body(), 1_000_000).await.unwrap().to_vec();
            state.locks.insert(key.clone(), (bytes, generation + 1));
        } else if current.is_none() {
            return error(404);
        }
        let (bytes, generation) = &state.locks[&key];
        if query.get("alt").is_some_and(|v| v == "media") {
            return Response::new(Body::from(bytes.clone()));
        }
        return Json(serde_json::json!({"name":key,"bucket":"synthetic-gcs","generation":generation.to_string(),"metageneration":"1","size":bytes.len().to_string(),"contentType":"application/json","selfLink":"test","mediaLink":"test","etag":"test","id":"test"})).into_response();
    }
    state.requests.push((method.clone(), uri.clone()));
    if let Some(status) = state
        .fail
        .or_else(|| (method == "POST").then_some(state.fail_upload).flatten())
    {
        return Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                "{{\"error\":{{\"code\":{},\"message\":\"synthetic failure\",\"errors\":[]}}}}",
                status.as_u16()
            )))
            .unwrap();
    }
    if method == "POST" {
        assert!(uri.starts_with("/upload/storage/v1/b/synthetic-gcs/o?uploadType=multipart"));
        if state.require_transcript_lock && state.locks.is_empty() {
            return error(409);
        }
        if state.race_on_repair && query.contains_key("ifGenerationMatch") {
            state.race_on_repair = false;
            state.object.as_mut().unwrap()["generation"] = "123456790".into();
            state.bytes = "concurrent writer".into();
        }
        let generation = state
            .object
            .as_ref()
            .and_then(|o| o["generation"].as_str())
            .unwrap_or("0");
        if query
            .get("ifGenerationMatch")
            .is_some_and(|v| v != generation)
        {
            return error(412);
        }
        let next_generation = generation.parse::<u64>().unwrap().max(123456788) + 1;
        let content_type = req.headers()["content-type"].to_str().unwrap();
        let boundary = content_type.split("boundary=").nth(1).unwrap().to_string();
        let body = String::from_utf8(
            to_bytes(req.into_body(), 1024 * 1024)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let parts: Vec<_> = body.split(&format!("--{boundary}")).collect();
        let metadata = parts[1]
            .split_once("\r\n\r\n")
            .unwrap()
            .1
            .trim_end_matches("\r\n");
        let mut object: serde_json::Value = serde_json::from_str(metadata).unwrap();
        state.bytes = parts[2]
            .split_once("\r\n\r\n")
            .unwrap()
            .1
            .trim_end_matches("\r\n")
            .into();
        let map = object.as_object_mut().unwrap();
        for key in ["selfLink", "mediaLink", "etag", "id"] {
            map.insert(key.into(), "synthetic".into());
        }
        map.insert("generation".into(), next_generation.to_string().into());
        map.insert("metageneration".into(), "1".into());
        map.insert("size".into(), state.bytes.len().to_string().into());
        map.insert("bucket".into(), "synthetic-gcs".into());
        state.object = Some(object);
    } else {
        assert_eq!(method, "GET");
        assert!(uri.starts_with("/storage/v1/b/synthetic-gcs/o/"));
        if state.object.is_none() {
            return Response::builder()
                .status(404)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"error":{"code":404,"message":"synthetic missing object","errors":[]}}"#,
                ))
                .unwrap();
        }
        if uri.contains("alt=media") {
            assert!(uri.contains(&format!(
                "generation={}",
                state.object.as_ref().unwrap()["generation"]
                    .as_str()
                    .unwrap()
            )));
            let url = reqwest::Url::parse(&format!("http://synthetic{uri}")).unwrap();
            let supplied = url
                .query_pairs()
                .find(|(name, _)| name == "ifMetagenerationMatch")
                .map(|(_, value)| value.into_owned());
            if supplied.is_some_and(|value| {
                value
                    != state.object.as_ref().unwrap()["metageneration"]
                        .as_str()
                        .unwrap()
            }) {
                return Response::builder()
                    .status(412)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"error":{"code":412,"message":"synthetic precondition mismatch"}}"#,
                    ))
                    .unwrap();
            }
            let body = if state.corrupt {
                "x".repeat(state.bytes.len())
            } else {
                state.bytes.clone()
            };
            return Response::new(Body::from(body));
        }
    }
    let body = state.object.as_ref().unwrap().to_string();
    if state.patch_after_metadata {
        state.patch_after_metadata = false;
        let object = state.object.as_mut().unwrap();
        object["metadata"]["owner"] = "d".repeat(64).into();
        object["metageneration"] = "3".into();
    }
    Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

async fn gcs_origin() -> (
    Arc<Mutex<GcsObjects>>,
    GcsClient,
    tokio::task::JoinHandle<()>,
) {
    let state = Arc::new(Mutex::new(GcsObjects::default()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .fallback(gcs_request)
        .with_state(state.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let config = google_cloud_storage::client::ClientConfig {
        storage_endpoint: endpoint,
        ..Default::default()
    }
    .anonymous();
    (state, GcsClient::new(config), task)
}

#[tokio::test]
async fn default_gcs_uses_atomic_metadata_and_pinned_verified_reads() {
    let (state, client, task) = gcs_origin().await;
    let store = MediaStorage::configured(
        StorageConfiguration::parse(|_| None).unwrap(),
        Some(client),
        "synthetic-gcs".into(),
    )
    .unwrap();
    let bytes = Bytes::from_static(b"synthetic gcs bytes");
    let hash = hex::encode(Sha256::digest(&bytes));
    let custom = HashMap::from([("owner".into(), "c".repeat(64))]);
    let receipt = store
        .put_verified(
            &hash,
            bytes.clone(),
            "video/mp4",
            custom.clone(),
            Some("public, max-age=31536000, immutable".into()),
        )
        .await
        .unwrap();
    assert_eq!(receipt.object.reference.provider, StorageProvider::Gcs);
    assert_eq!(
        receipt.object.reference.version.as_deref(),
        Some("123456789")
    );
    assert_eq!(receipt.object.custom, custom);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("original");
    store
        .download_original(&receipt.object, &hash, &path)
        .await
        .unwrap();
    assert_eq!(tokio::fs::read(path).await.unwrap(), bytes);
    {
        let state = state.lock().await;
        assert_eq!(state.requests.len(), 6);
        assert!(state
            .requests
            .iter()
            .filter(|(_, uri)| uri.contains("alt=media"))
            .all(|(_, uri)| uri.contains("ifMetagenerationMatch=1")));
    }
    let mut wrong_metadata = receipt.object.clone();
    wrong_metadata.content_type = "audio/mp4".into();
    assert!(store.verify_sha256(&wrong_metadata, &hash).await.is_err());
    {
        let mut state = state.lock().await;
        let object = state.object.as_mut().unwrap();
        object["metadata"]["owner"] = "d".repeat(64).into();
        object["metageneration"] = "2".into();
    }
    assert!(store.verify_sha256(&receipt.object, &hash).await.is_err());
    {
        let mut state = state.lock().await;
        state.object.as_mut().unwrap()["metadata"]["owner"] = "c".repeat(64).into();
        state.patch_after_metadata = true;
    }
    assert!(store.verify_sha256(&receipt.object, &hash).await.is_err());
    task.abort();
}

#[tokio::test]
async fn signed_metadata_preserves_internal_spaces() {
    let origin = Origin::start().await;
    let custom = HashMap::from([("description".into(), "synthetic  label".into())]);
    let receipt = origin
        .store()
        .put_verified(
            "artifact.mp4",
            Bytes::from_static(b"bytes"),
            "video/mp4",
            custom.clone(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(receipt.object.custom, custom);
}

#[tokio::test]
async fn invalid_metadata_and_content_address_are_rejected_before_writes() {
    let origin = Origin::start().await;
    let store = origin.store();
    for (name, value) in [
        ("Owner", "value"),
        ("owner", " leading"),
        ("owner", "line\nfeed"),
        ("owner", "non-ascii-é"),
    ] {
        assert!(store
            .put_verified(
                "artifact.mp4",
                Bytes::from_static(b"bytes"),
                "video/mp4",
                HashMap::from([(name.into(), value.into())]),
                None
            )
            .await
            .is_err());
    }
    assert!(store
        .put_verified(
            &"a".repeat(64),
            Bytes::from_static(b"bytes"),
            "video/mp4",
            HashMap::new(),
            None
        )
        .await
        .is_err());
    assert!(origin.objects.lock().await.requests.is_empty());
}

#[tokio::test]
async fn mismatched_pinned_metadata_never_verifies_bytes() {
    let origin = Origin::start().await;
    let store = origin.store();
    let bytes = Bytes::from_static(b"original");
    let hash = hex::encode(Sha256::digest(&bytes));
    let receipt = store
        .put_verified(&hash, bytes, "video/mp4", HashMap::new(), None)
        .await
        .unwrap();
    for mode in 0..5 {
        let mut object = receipt.object.clone();
        match mode {
            0 => object.reference.version = Some("wrong-version".into()),
            1 => object.content_type = "audio/mp4".into(),
            2 => object.size += 1,
            3 => {
                object.custom.insert("owner".into(), "c".repeat(64));
            }
            _ => object.cache_control = Some("public".into()),
        }
        assert!(store.verify_sha256(&object, &hash).await.is_err());
    }
}

#[tokio::test]
async fn version_header_constraints_are_fail_closed() {
    let origin = Origin::start().await;
    let store = origin.store();
    for version in ["", "version-é", "version\tvalue", "version\nvalue"] {
        let reference = ObjectRef {
            provider: StorageProvider::B2,
            bucket: "synthetic-bucket".into(),
            key: "artifact".into(),
            version: Some(version.into()),
        };
        assert!(store.stat_reference(&reference).await.is_err());
    }
    assert!(origin.objects.lock().await.requests.is_empty());
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-amz-version-id",
        reqwest::header::HeaderValue::from_bytes(b"non-ascii-\xc3\xa9").unwrap(),
    );
    assert!(from_b2("synthetic-bucket", "artifact", &headers).is_err());
}

#[tokio::test]
async fn current_selection_requires_full_metadata_and_real_version() {
    let origin = Origin::start().await;
    let store = origin.store();
    store
        .put_verified(
            "artifact",
            Bytes::from_static(b"bytes"),
            "video/mp4",
            HashMap::new(),
            None,
        )
        .await
        .unwrap();
    origin.objects.lock().await.head_status = Some(StatusCode::PARTIAL_CONTENT);
    assert!(store.stat("artifact").await.is_err());
}

#[tokio::test]
async fn unversioned_sentinel_never_returns_a_verification_receipt() {
    let origin = Origin::start().await;
    let store = origin.store();
    origin.objects.lock().await.next_version = Some("null".into());
    assert!(store
        .put_verified(
            "artifact",
            Bytes::from_static(b"bytes"),
            "video/mp4",
            HashMap::new(),
            None
        )
        .await
        .is_err());
}

#[tokio::test]
async fn transcript_output_uses_selected_media_provider_and_pinned_verification() {
    let origin = Origin::start().await;
    let store = origin.store();
    let hash = "a".repeat(64);
    let vtt = "WEBVTT\n\n00:00.000 --> 00:01.000\nSynthetic subtitle\n";
    super::super::upload_transcript_to_storage(&store, &hash, vtt)
        .await
        .unwrap();
    let objects = origin.objects.lock().await;
    let key = format!("{hash}/vtt/main.vtt");
    let version = &objects.latest[&key];
    let written = &objects.versions[&(key.clone(), version.clone())];
    assert_eq!(written.bytes.as_ref(), vtt.as_bytes());
    assert_eq!(written.mime, "text/vtt");
    assert_eq!(
        objects.requests.len(),
        3,
        "PUT, pinned HEAD and pinned byte verification"
    );
}

#[tokio::test]
async fn transcript_output_propagates_failed_provider_verification() {
    let origin = Origin::start().await;
    origin.objects.lock().await.corrupt = true;
    assert!(super::super::upload_transcript_to_storage(
        &origin.store(),
        &"a".repeat(64),
        "WEBVTT\n"
    )
    .await
    .is_err());
}

#[tokio::test]
async fn review360_missing_primary_never_acknowledges_backup_as_complete() {
    let origin = Origin::start().await;
    let (_, client, task) = gcs_origin().await;
    let legacy = MediaStorage::gcs(client.clone(), "synthetic-gcs".into());
    legacy
        .put_verified(
            &format!("{}/vtt/main.vtt", "a".repeat(64)),
            Bytes::from_static(b"WEBVTT\n"),
            "text/vtt",
            HashMap::new(),
            None,
        )
        .await
        .unwrap();
    let result = deduplicate_transcript(transcript_state(
        b2_primary_store(&origin, client.clone()),
        client,
    ))
    .await;
    task.abort();
    assert!(
        result.is_err(),
        "missing selected primary must reach regeneration, not return complete from its GCS backup"
    );
}

#[tokio::test]
async fn review360_backup_repair_requires_transcript_lock() {
    let origin = Origin::start().await;
    let (backup, client, task) = gcs_origin().await;
    let store = b2_primary_store(&origin, client.clone());
    let key = format!("{}/vtt/main.vtt", "a".repeat(64));
    origin
        .store()
        .put_verified(
            &key,
            Bytes::from_static(b"WEBVTT\n"),
            "text/vtt",
            HashMap::new(),
            None,
        )
        .await
        .unwrap();
    backup.lock().await.require_transcript_lock = true;
    let before = origin
        .objects
        .lock()
        .await
        .requests
        .iter()
        .filter(|(method, _, _)| method == "GET")
        .count();
    let result = deduplicate_transcript(transcript_state(store, client)).await;
    task.abort();
    assert_eq!(result.unwrap(), "already_exists");
    assert_eq!(backup.lock().await.lock_requests, ["POST", "DELETE"]);
    assert!(backup
        .lock()
        .await
        .requests
        .iter()
        .any(|(method, uri)| method == "POST" && uri.contains("ifGenerationMatch=0")));
    assert_eq!(
        origin
            .objects
            .lock()
            .await
            .requests
            .iter()
            .filter(|(method, _, _)| method == "GET")
            .count()
            - before,
        1,
        "repair reuses the already read pinned primary bytes"
    );
}

#[tokio::test]
async fn review360_backup_cas_preserves_concurrent_generation() {
    let origin = Origin::start().await;
    let (backup, client, task) = gcs_origin().await;
    let store = b2_primary_store(&origin, client);
    let key = format!("{}/vtt/main.vtt", "a".repeat(64));
    let primary = origin
        .store()
        .put_verified(
            &key,
            Bytes::from_static(b"primary"),
            "text/vtt",
            HashMap::new(),
            None,
        )
        .await
        .unwrap()
        .object;
    store.ensure_required_backup(&primary).await.unwrap();
    {
        let mut b = backup.lock().await;
        b.bytes = "changed".into();
        b.race_on_repair = true;
    }
    let result = store.ensure_required_backup(&primary).await;
    task.abort();
    assert!(
        result.is_err(),
        "repair must not overwrite a different concurrently written GCS generation"
    );
    assert_eq!(backup.lock().await.bytes, "concurrent writer");
}

#[tokio::test]
async fn review360_existing_writer_lock_blocks_duplicate_cache_repair() {
    let origin = Origin::start().await;
    let (backup, client, task) = gcs_origin().await;
    let store = b2_primary_store(&origin, client.clone());
    let hash = "a".repeat(64);
    origin
        .store()
        .put_verified(
            &format!("{hash}/vtt/main.vtt"),
            Bytes::from_static(b"WEBVTT\n"),
            "text/vtt",
            HashMap::new(),
            None,
        )
        .await
        .unwrap();
    let owner = crate::acquire_transcript_lock(&client, "synthetic-gcs", &hash, 900)
        .await
        .unwrap()
        .unwrap();
    let state = transcript_state(store, client.clone());
    assert_eq!(
        deduplicate_transcript(state.clone()).await.unwrap(),
        "already_processing"
    );
    assert!(
        backup.lock().await.object.is_none(),
        "duplicate must not repair before owning the transcript lock"
    );
    crate::delete_transcript_lock(&client, "synthetic-gcs", &owner)
        .await
        .unwrap();
    assert_eq!(
        deduplicate_transcript(state).await.unwrap(),
        "already_exists"
    );
    assert!(backup.lock().await.object.is_some());
    task.abort();
}

#[tokio::test]
async fn review360_forced_selected_cache_and_backup_failures_report_terminal_status() {
    for case in ["b2_force", "primary_force", "backup_failure"] {
        let origin = Origin::start().await;
        let (backup, client, task) = gcs_origin().await;
        let hash = "a".repeat(64);
        origin
            .store()
            .put_verified(
                &format!("{hash}/vtt/main.vtt"),
                Bytes::from_static(b"bad cached transcript"),
                "text/vtt",
                HashMap::new(),
                None,
            )
            .await
            .unwrap();
        let media = if case == "b2_force" {
            origin.store()
        } else {
            b2_primary_store(&origin, client.clone())
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
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
        let status_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut state = transcript_state(media, client);
        let config = &mut Arc::get_mut(&mut state).unwrap().config;
        config.transcript_webhook_url = Some(endpoint);
        config.transcode_repair_secret = Some("synthetic-repair".into());
        let force = case != "backup_failure";
        if !force {
            backup.lock().await.fail = Some(StatusCode::SERVICE_UNAVAILABLE);
        }
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-divine-repair-secret",
            "synthetic-repair".parse().unwrap(),
        );
        let response = crate::handle_transcribe(
            State(state),
            headers,
            Json(crate::TranscodeRequest {
                hash,
                force,
                owner: None,
                job_id: None,
                lang: None,
            }),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "fixture has no original / denies required backup"
        );
        let mut statuses = vec![];
        while let Ok(status) = rx.try_recv() {
            statuses.push(status);
        }
        assert_eq!(statuses.last().unwrap()["status"], "failed");
        assert!(statuses.iter().all(|s| s["status"] != "complete"));
        assert!(
            backup.lock().await.object.is_none(),
            "force must not copy the known-bad cached B2 transcript back to GCS"
        );
        task.abort();
        status_task.abort();
    }
}
