use super::*;
use axum::{
    extract::{Request, State},
    response::{IntoResponse, Response},
    Json, Router,
};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};
use tokio::{sync::Mutex, task::JoinHandle};

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[derive(Default)]
struct Objects {
    next_generation: i64,
    live: HashMap<String, Value>,
    media: HashMap<String, Bytes>,
    fail_key: Option<String>,
    claim_write_interval: Option<Duration>,
    last_claim_write: HashMap<String, tokio::time::Instant>,
    claim_writes: HashMap<String, usize>,
    claim_throttles: usize,
    throttle_next_claim_write: bool,
    delay_next_claim_ack: Option<Duration>,
}

struct Origin {
    endpoint: String,
    objects: Arc<Mutex<Objects>>,
    task: JoinHandle<()>,
}

impl Origin {
    async fn start() -> Self {
        let objects = Arc::new(Mutex::new(Objects::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(gcs).with_state(objects.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            endpoint,
            objects,
            task,
        }
    }

    fn client(&self) -> GcsClient {
        GcsClient::new(
            google_cloud_storage::client::ClientConfig {
                storage_endpoint: self.endpoint.clone(),
                ..Default::default()
            }
            .anonymous(),
        )
    }

    fn store(&self) -> ClaimStore {
        ClaimStore::new(self.client(), "synthetic-gcs")
    }

    async fn age(&self, hash: &str) {
        let mut objects = self.objects.lock().await;
        objects.live.get_mut(&lock_key(hash)).unwrap()["timeCreated"] =
            json!("2000-01-01T00:00:00Z");
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn gcs(State(objects): State<Arc<Mutex<Objects>>>, req: Request) -> Response {
    let error = |code: u16| {
        (
            axum::http::StatusCode::from_u16(code).unwrap(),
            Json(json!({"error":{"code":code,"message":"synthetic","errors":[]}})),
        )
            .into_response()
    };
    let method = req.method().clone();
    let uri = req.uri().clone();
    let url = reqwest::Url::parse(&format!("http://test{uri}")).unwrap();
    let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
    let mut new_object: Option<(Value, Bytes)> = None;
    let key = if method == "POST" {
        let ct = req.headers()["content-type"].to_str().unwrap();
        let boundary = format!("--{}", ct.split("boundary=").nth(1).unwrap());
        let body = axum::body::to_bytes(req.into_body(), 8 * 1024 * 1024)
            .await
            .unwrap();
        let boundary = boundary.as_bytes();
        let parts: Vec<_> = split_bytes(&body, boundary).collect();
        let field = |part: &[u8]| -> usize {
            part.windows(4)
                .position(|window| window == b"\r\n\r\n")
                .unwrap()
                + 4
        };
        let object: Value = serde_json::from_slice(&parts[1][field(parts[1])..]).unwrap();
        let key = object["name"].as_str().unwrap().to_owned();
        let bytes = Bytes::copy_from_slice(&parts[2][field(parts[2])..parts[2].len() - 2]);
        new_object = Some((object, bytes));
        key
    } else {
        let escaped = uri.path().split_once("/o/").unwrap().1;
        reqwest::Url::parse(&format!("http://test/?key={escaped}"))
            .unwrap()
            .query_pairs()
            .next()
            .unwrap()
            .1
            .into_owned()
    };
    let mut objects = objects.lock().await;
    let live = objects.live.get(&key);
    if method == "GET" {
        let Some(live) = live else { return error(404) };
        if query
            .get("ifGenerationMatch")
            .is_some_and(|expected| Some(expected.as_str()) != live["generation"].as_str())
        {
            return error(412);
        }
        if let Some(generation) = query.get("generation") {
            if Some(generation.as_str()) != live["generation"].as_str() {
                return error(404);
            }
        }
        if query.get("alt").is_some_and(|value| value == "media") {
            return objects.media[&key].clone().into_response();
        }
        return Json(live.clone()).into_response();
    }
    if method == "POST" && objects.fail_key.as_deref() == Some(&key) {
        return error(403);
    }
    let current = live
        .and_then(|value| value["generation"].as_str())
        .unwrap_or("0");
    let is_claim = key.starts_with(".internal/hls-claims/");
    let precondition = query.get("ifGenerationMatch");
    if is_claim
        || new_object
            .as_ref()
            .is_some_and(|(metadata, _)| metadata["metadata"][WRITE_ID].is_string())
    {
        assert!(
            precondition.is_some(),
            "coordinated writes must carry the live generation"
        );
    }
    if precondition.is_some_and(|generation| generation != current) {
        return error(412);
    }
    if is_claim {
        let now = tokio::time::Instant::now();
        let too_soon = objects.claim_write_interval.is_some_and(|interval| {
            objects
                .last_claim_write
                .get(&key)
                .is_some_and(|last| now - *last < interval)
        });
        if too_soon || std::mem::take(&mut objects.throttle_next_claim_write) {
            objects.claim_throttles += 1;
            return error(429);
        }
        objects.last_claim_write.insert(key.clone(), now);
        *objects.claim_writes.entry(key.clone()).or_default() += 1;
    }
    if let Some((mut object, bytes)) = new_object {
        objects.next_generation += 1;
        let now = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        object["generation"] = json!(objects.next_generation.to_string());
        object["timeCreated"] = json!(now);
        object["metageneration"] = json!("1");
        object["size"] = json!(bytes.len().to_string());
        object["bucket"] = json!("synthetic-gcs");
        for name in ["selfLink", "mediaLink", "etag", "id"] {
            object[name] = json!("synthetic");
        }
        objects.media.insert(key.clone(), bytes);
        objects.live.insert(key, object.clone());
        let ack_delay = if is_claim {
            objects.delay_next_claim_ack.take()
        } else {
            None
        };
        drop(objects);
        if let Some(delay) = ack_delay {
            tokio::time::sleep(delay).await;
        }
        return Json(object).into_response();
    }
    assert_eq!(method, "DELETE");
    objects.live.remove(&key);
    axum::http::StatusCode::NO_CONTENT.into_response()
}

fn split_bytes<'a>(mut remaining: &'a [u8], delimiter: &'a [u8]) -> impl Iterator<Item = &'a [u8]> {
    std::iter::from_fn(move || {
        let offset = remaining
            .windows(delimiter.len())
            .position(|window| window == delimiter)?;
        let piece = &remaining[..offset];
        remaining = &remaining[offset + delimiter.len()..];
        Some(piece)
    })
}

#[tokio::test]
async fn independent_instances_claim_one_hash_and_can_run_a_different_hash() {
    let origin = Origin::start().await;
    let first = origin.store();
    let second = origin.store();
    let (first, second, different) = tokio::join!(
        first.claim(A, None),
        second.claim(A, None),
        second.claim(B, None),
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert!(different.is_ok());
    assert!(first.err().or_else(|| second.err()).unwrap().is::<Busy>());
}

#[tokio::test]
async fn stale_encoding_cannot_publish_or_release_the_replacement_lock() {
    let origin = Origin::start().await;
    let mut old = origin.store().claim(A, None).await.unwrap();
    origin.age(A).await;
    let replacement = origin.store().claim(A, None).await.unwrap();
    assert!(old.confirm().await.unwrap_err().is::<OwnershipLost>());
    assert!(old
        .begin_write(true, &format!("{A}/hls/master.m3u8"), "old")
        .await
        .is_err());
    assert!(old.finish(true).await.is_err());
    assert!(origin
        .store()
        .claim(A, None)
        .await
        .unwrap_err()
        .is::<Busy>());
    replacement.finish(true).await.unwrap();
    assert!(origin.store().claim(A, None).await.is_ok());
}

#[tokio::test]
async fn stale_unconfirmed_write_retains_exclusive_publication_rights() {
    let origin = Origin::start().await;
    let mut old = origin.store().claim(A, None).await.unwrap();
    old.begin_write(true, &format!("{A}/hls/master.m3u8"), "old")
        .await
        .unwrap();
    origin.age(A).await;
    assert!(origin
        .store()
        .claim(A, None)
        .await
        .unwrap_err()
        .is::<Busy>());
    old.reject_write().await.unwrap();
    old.finish(false).await.unwrap();
    assert!(origin.store().claim(A, None).await.unwrap().dirty() == Dirty::Hls);
}

fn request(hash: &str, force: bool) -> crate::TranscodeRequest {
    crate::TranscodeRequest {
        hash: hash.to_owned(),
        force,
        owner: None,
        job_id: None,
        lang: None,
    }
}

fn instance(
    origin: &Origin,
    media: &crate::object_storage::tests::Origin,
    webhook: &str,
) -> Arc<crate::AppState> {
    let gcs_client = origin.client();
    Arc::new(crate::AppState {
        media_storage: media.with_gcs_backup(gcs_client.clone()),
        gcs_client,
        config: crate::Config::from_lookup(|key| match key {
            "GCS_BUCKET" => Some("synthetic-gcs".into()),
            "WEBHOOK_URL" => Some(webhook.to_owned()),
            _ => None,
        }),
        provider_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
    })
}

#[derive(Default)]
struct Callbacks {
    events: Mutex<Vec<Value>>,
    wait_at_processing: std::sync::atomic::AtomicBool,
    processing: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

async fn webhook() -> (String, Arc<Callbacks>, JoinHandle<()>) {
    async fn callback(State(callbacks): State<Arc<Callbacks>>, Json(event): Json<Value>) {
        let processing = event["status"] == "processing";
        callbacks.events.lock().await.push(event);
        if processing
            && callbacks
                .wait_at_processing
                .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            callbacks.processing.notify_one();
            callbacks.resume.notified().await;
        }
    }

    let callbacks = Arc::new(Callbacks::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/", axum::routing::post(callback))
        .with_state(callbacks.clone());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, callbacks, task)
}

async fn seed_video(origin: &crate::object_storage::tests::Origin, color: &str) -> String {
    seed_generated_video(
        &origin.store(),
        &format!("color={color}:s=144x256:d=0.6:r=12"),
    )
    .await
}

async fn seed_generated_video(storage: &MediaStorage, filter: &str) -> String {
    use sha2::{Digest, Sha256};

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("synthetic.mp4");
    let ffmpeg = tokio::process::Command::new("ffmpeg")
        .args(["-hide_banner", "-loglevel", "error", "-f", "lavfi", "-i"])
        .arg(filter)
        .args(["-c:v", "libx264", "-pix_fmt", "yuv420p"])
        .arg(&file)
        .output()
        .await
        .expect("ffmpeg required by the HLS integration test");
    assert!(
        ffmpeg.status.success(),
        "{}",
        String::from_utf8_lossy(&ffmpeg.stderr)
    );
    let body = Bytes::from(tokio::fs::read(&file).await.unwrap());
    let hash = hex::encode(Sha256::digest(&body));
    storage
        .put_verified(
            &hash,
            body,
            "video/mp4",
            HashMap::from([("c2pa-manifest-id".into(), "synthetic-manifest".into())]),
            None,
        )
        .await
        .unwrap();
    hash
}

#[tokio::test]
#[ignore = "requires ffmpeg and ffprobe with libx264"]
async fn service_instances_encode_once_while_other_hashes_and_repairs_keep_their_semantics() {
    let locks = Origin::start().await;
    let media = crate::object_storage::tests::Origin::start().await;
    let hash = seed_video(&media, "green").await;
    let other = seed_video(&media, "red").await;
    let seed_reads = media
        .objects
        .lock()
        .await
        .requests
        .iter()
        .filter(|(method, key, _)| method == "GET" && key == &hash)
        .count();
    let (url, callbacks, webhook) = webhook().await;
    callbacks
        .wait_at_processing
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let first = {
        let state = instance(&locks, &media, &url);
        let request = request(&hash.to_ascii_uppercase(), false);
        tokio::spawn(crate::process_transcode(state, request))
    };
    tokio::time::timeout(Duration::from_secs(5), callbacks.processing.notified())
        .await
        .unwrap();
    let independent = instance(&locks, &media, &url);
    assert!(
        crate::process_transcode(independent.clone(), request(&hash, false))
            .await
            .err()
            .unwrap()
            .is::<Busy>()
    );
    assert!(
        crate::process_transcode(independent.clone(), request(&hash, true))
            .await
            .err()
            .unwrap()
            .is::<Busy>()
    );
    assert_eq!(
        crate::process_transcode(independent.clone(), request(&other, false))
            .await
            .unwrap()
            .status,
        "complete"
    );
    callbacks.resume.notify_one();
    assert_eq!(first.await.unwrap().unwrap().status, "complete");
    assert_eq!(
        crate::process_transcode(independent, request(&hash, false))
            .await
            .unwrap()
            .status,
        "already_exists"
    );

    let state = media.objects.lock().await;
    let uploads: Vec<_> = state
        .requests
        .iter()
        .filter(|(method, key, _)| method == "PUT" && key.starts_with(&format!("{hash}/hls/")))
        .collect();
    assert_eq!(uploads.len(), 7);
    assert_eq!(uploads.last().unwrap().1, format!("{hash}/hls/master.m3u8"));
    let reads = state
        .requests
        .iter()
        .filter(|(method, key, _)| method == "GET" && key == &hash)
        .count();
    assert_eq!(reads - seed_reads, 1);
    drop(state);
    let events = callbacks.events.lock().await;
    let statuses: Vec<_> = events
        .iter()
        .filter(|event| event["sha256"] == hash)
        .map(|event| event["status"].as_str().unwrap())
        .collect();
    assert_eq!(statuses, ["processing", "complete", "complete"]);
    assert!(events
        .iter()
        .filter(|event| event["sha256"] == hash)
        .map(|event| event["generation"].as_u64().unwrap())
        .is_sorted());
    let backup = locks.objects.lock().await;
    for name in crate::object_storage::REQUIRED_HLS_FILES
        .into_iter()
        .chain(crate::object_storage::OPTIONAL_HLS_FILES)
    {
        let artifact = &backup.live[&format!("{hash}/hls/{name}")];
        assert_eq!(
            artifact["metadata"]["c2pa-manifest-id"],
            "synthetic-manifest"
        );
        assert_eq!(artifact["metadata"]["source_sha256"], hash);
    }
    webhook.abort();
}

#[tokio::test]
#[ignore = "requires ffmpeg and ffprobe with libx264"]
async fn primary_master_without_backup_fails_then_recovers_before_complete_callback() {
    let locks = Origin::start().await;
    let media = crate::object_storage::tests::Origin::start().await;
    let hash = seed_video(&media, "blue").await;
    let (url, callbacks, webhook) = webhook().await;
    let master = format!("{hash}/hls/master.m3u8");
    locks.objects.lock().await.fail_key = Some(master.clone());
    let first =
        crate::process_transcode(instance(&locks, &media, &url), request(&hash, false)).await;
    assert!(first.is_err());
    assert!(media.store().stat(&master).await.unwrap().is_some());
    assert!(!locks.objects.lock().await.live.contains_key(&master));
    assert!(callbacks
        .events
        .lock()
        .await
        .iter()
        .all(|event| event["status"] != "complete"));
    locks.objects.lock().await.fail_key = None;
    let replacement = instance(&locks, &media, &url);
    assert_eq!(
        crate::process_transcode(replacement.clone(), request(&hash, false))
            .await
            .unwrap()
            .status,
        "complete"
    );
    assert!(replacement
        .media_storage
        .can_reuse_hls(&hash)
        .await
        .unwrap());
    let events = callbacks.events.lock().await;
    let statuses: Vec<_> = events
        .iter()
        .map(|event| event["status"].as_str().unwrap())
        .collect();
    assert_eq!(statuses, ["processing", "failed", "processing", "complete"]);
    webhook.abort();
}

#[tokio::test]
async fn a_committed_b2_put_can_recover_after_worker_crash_without_unfencing_the_old_worker() {
    let locks = Origin::start().await;
    let media = crate::object_storage::tests::Origin::start().await;
    let storage = media.with_gcs_backup(locks.client());
    let mut owner = locks.store().claim(A, Some(&storage)).await.unwrap();
    let key = format!("{A}/hls/master.m3u8");
    let id = owner.write_id();
    owner.begin_write(false, &key, &id).await.unwrap();
    media
        .store()
        .put_verified(
            &key,
            Bytes::from_static(b"synthetic"),
            "application/vnd.apple.mpegurl",
            HashMap::from([(WRITE_ID.into(), id.clone())]),
            None,
        )
        .await
        .unwrap();
    locks.age(A).await;
    let replacement = locks.store().claim(A, Some(&storage)).await.unwrap();
    assert_eq!(replacement.dirty(), Dirty::Hls);
    owner.acknowledge_write();
    assert!(owner
        .begin_write(true, &key, &id)
        .await
        .unwrap_err()
        .is::<OwnershipLost>());
    assert!(owner.finish(false).await.is_err());
    assert!(locks
        .store()
        .claim(A, Some(&storage))
        .await
        .unwrap_err()
        .is::<Busy>());
    replacement.finish(false).await.unwrap();
}

#[tokio::test]
async fn cancelling_the_response_waiter_does_not_interrupt_a_claimed_job() {
    use tokio::sync::oneshot;

    let origin = Origin::start().await;
    let store = origin.store();
    let (claimed_tx, claimed_rx) = oneshot::channel();
    let (work_tx, work_rx) = oneshot::channel();
    let (released_tx, released_rx) = oneshot::channel();
    let waiter = tokio::spawn(crate::await_repair(async move {
        let mut claim = store.claim(A, None).await?;
        claimed_tx.send(()).unwrap();
        work_rx.await.unwrap();
        claim
            .begin_write(true, &format!("{A}/hls/master.m3u8"), "synthetic")
            .await?;
        claim.acknowledge_write();
        claim.finish(true).await?;
        released_tx.send(()).unwrap();
        Ok(())
    }));
    claimed_rx.await.unwrap();
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    assert!(origin
        .store()
        .claim(A, None)
        .await
        .unwrap_err()
        .is::<Busy>());
    work_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), released_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(origin.store().claim(A, None).await.is_ok());
}

#[tokio::test]
async fn expired_preparation_budget_stops_work_without_touching_renditions() {
    let origin = Origin::start().await;
    let mut claim = origin.store().claim(A, None).await.unwrap();
    claim.deadline = tokio::time::Instant::now() + Duration::from_millis(20);
    assert!(claim
        .hold(std::future::pending::<Result<()>>())
        .await
        .is_err());
    assert!(claim
        .begin_write(true, &format!("{A}/hls/master.m3u8"), "synthetic")
        .await
        .is_err());
    claim.finish(false).await.unwrap();
    assert!(origin.store().claim(A, None).await.is_ok());
}

#[tokio::test]
async fn claim_lifecycle_obeys_the_provider_mutation_limit() {
    let origin = Origin::start().await;
    origin.objects.lock().await.claim_write_interval = Some(Duration::from_secs(1));
    let mut owner = origin.store().claim(A, None).await.unwrap();
    owner.confirm().await.unwrap();
    owner
        .begin_write(true, &format!("{A}/hls/master.m3u8"), "synthetic")
        .await
        .unwrap();
    owner.acknowledge_write();
    owner.mark_verified().await.unwrap();
    owner.finish(true).await.unwrap();
    let state = origin.objects.lock().await;
    assert_eq!(
        state.claim_throttles, 0,
        "normal ownership must not depend on 429 retries"
    );
    assert_eq!(state.claim_writes[&lock_key(A)], 4);
    assert!(!state.live.contains_key(&lock_key(A)));
}

#[tokio::test]
async fn explicit_429_is_retried_for_claim_creation_and_release() {
    let origin = Origin::start().await;
    origin.objects.lock().await.throttle_next_claim_write = true;
    let owner = origin.store().claim(A, None).await.unwrap();
    origin.objects.lock().await.throttle_next_claim_write = true;
    owner.finish(true).await.unwrap();
    let state = origin.objects.lock().await;
    assert_eq!(state.claim_throttles, 2);
    assert_eq!(state.claim_writes[&lock_key(A)], 2);
    assert!(!state.live.contains_key(&lock_key(A)));
}

#[tokio::test]
#[ignore = "requires ffmpeg and ffprobe with libx264"]
async fn short_media_meets_the_same_key_quota_with_and_without_backups() {
    let gcs = Origin::start().await;
    gcs.objects.lock().await.claim_write_interval = Some(Duration::from_secs(1));
    let b2 = crate::object_storage::tests::Origin::start().await;

    let (single, dual, primary_only) = tokio::join!(
        measured_pipeline(
            &gcs,
            MediaStorage::gcs(gcs.client(), "synthetic-gcs".into()),
            "testsrc2=size=640x360:rate=24:duration=6",
            10
        ),
        measured_pipeline(
            &gcs,
            b2.with_gcs_backup(gcs.client()),
            "testsrc2=size=640x352:rate=24:duration=6",
            17
        ),
        measured_pipeline(
            &gcs,
            b2.with_gcs_input_only(gcs.client()),
            "testsrc2=size=640x344:rate=24:duration=6",
            10
        ),
    );
    eprintln!("6s FFmpeg fixtures with loopback storage: GCS-only {single:?}; B2 with backup {dual:?}; B2 without backup {primary_only:?}");
    assert_eq!(gcs.objects.lock().await.claim_throttles, 0);
}

async fn measured_pipeline(
    gcs: &Origin,
    storage: MediaStorage,
    filter: &str,
    expected_claim_writes: usize,
) -> Duration {
    let hash = seed_generated_video(&storage, filter).await;
    let (url, callbacks, webhook) = webhook().await;
    let state = Arc::new(crate::AppState {
        media_storage: storage,
        gcs_client: gcs.client(),
        config: crate::Config::from_lookup(|key| match key {
            "GCS_BUCKET" => Some("synthetic-gcs".into()),
            "WEBHOOK_URL" => Some(url.clone()),
            _ => None,
        }),
        provider_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
    });
    let started = Instant::now();
    let result = crate::process_transcode(state.clone(), request(&hash, false))
        .await
        .unwrap();
    let elapsed = started.elapsed();

    assert_eq!(result.status, "complete");
    assert!(state.media_storage.can_reuse_hls(&hash).await.unwrap());
    let state = gcs.objects.lock().await;
    assert_eq!(state.claim_writes[&lock_key(&hash)], expected_claim_writes);
    assert!(!state.live.contains_key(&lock_key(&hash)));
    let events = callbacks.events.lock().await;
    assert_eq!(events.last().unwrap()["status"], "complete");
    webhook.abort();
    elapsed
}

#[tokio::test]
async fn a_release_throttled_before_takeover_cannot_delete_the_replacement() {
    let origin = Origin::start().await;
    let mut owner = origin.store().claim(A, None).await.unwrap();
    // Let deletion reach the fake provider immediately. Age the claim for
    // takeover only after the provider has rejected that first attempt.
    owner.next_mutation = Instant::now();
    origin.objects.lock().await.throttle_next_claim_write = true;
    let release = tokio::spawn(owner.finish(true));
    tokio::time::timeout(Duration::from_secs(3), async {
        while origin.objects.lock().await.claim_throttles == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    origin.age(A).await;
    let replacement = origin.store().claim(A, None).await.unwrap();
    assert!(release.await.unwrap().is_err());
    assert!(origin
        .store()
        .claim(A, None)
        .await
        .unwrap_err()
        .is::<Busy>());
    replacement.finish(true).await.unwrap();
}

#[tokio::test]
async fn mutation_pacing_cannot_admit_a_put_past_the_attempt_deadline() {
    let origin = Origin::start().await;
    let mut owner = origin.store().claim(A, None).await.unwrap();
    owner.deadline = Instant::now() + Duration::from_millis(20);
    assert!(owner
        .begin_write(true, &format!("{A}/hls/master.m3u8"), "synthetic")
        .await
        .is_err());
    let state = origin.objects.lock().await;
    assert_eq!(state.claim_writes[&lock_key(A)], 1);
    drop(state);
    owner.finish(false).await.unwrap();
}

#[tokio::test]
async fn a_predeadline_intent_cas_can_acknowledge_after_the_admission_deadline() {
    let origin = Origin::start().await;
    let mut owner = origin.store().claim(A, None).await.unwrap();
    owner.next_mutation = Instant::now();
    owner.deadline = Instant::now() + Duration::from_millis(200);
    origin.objects.lock().await.delay_next_claim_ack = Some(Duration::from_millis(400));
    owner
        .begin_write(true, &format!("{A}/hls/master.m3u8"), "synthetic")
        .await
        .unwrap();
    assert!(Instant::now() >= owner.deadline);
    assert_eq!(
        origin.objects.lock().await.live[&lock_key(A)]["generation"],
        owner.generation.to_string(),
    );
    owner.reject_write().await.unwrap();
    owner.finish(false).await.unwrap();
}

#[tokio::test]
async fn a_throttled_marker_based_takeover_cannot_replace_an_advanced_intent() {
    let locks = Origin::start().await;
    let media = crate::object_storage::tests::Origin::start().await;
    let storage = media.with_gcs_backup(locks.client());
    let mut owner = locks.store().claim(A, Some(&storage)).await.unwrap();
    let key = format!("{A}/hls/master.m3u8");
    let id = owner.write_id();
    owner.begin_write(false, &key, &id).await.unwrap();
    media
        .store()
        .put_verified(
            &key,
            Bytes::from_static(b"synthetic"),
            "application/vnd.apple.mpegurl",
            HashMap::from([(WRITE_ID.into(), id.clone())]),
            None,
        )
        .await
        .unwrap();
    owner.acknowledge_write();

    locks.age(A).await;
    locks.objects.lock().await.throttle_next_claim_write = true;
    let contender = locks.store();
    let recovery = tokio::spawn(async move { contender.claim(A, Some(&storage)).await });
    tokio::time::timeout(Duration::from_secs(3), async {
        while locks.objects.lock().await.claim_throttles == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    // The simulated old generation has aged past the write interval. Advance
    // its durable journal before the contender retries the old generation.
    owner.next_mutation = Instant::now();
    owner.begin_write(true, &key, &id).await.unwrap();
    assert!(recovery.await.unwrap().unwrap_err().is::<Busy>());
    assert_eq!(
        locks.objects.lock().await.live[&lock_key(A)]["generation"],
        owner.generation.to_string(),
    );
    owner.reject_write().await.unwrap();
    owner.finish(false).await.unwrap();
}

#[tokio::test]
async fn disabling_backups_recovers_old_gcs_writes_only_with_matching_commit_markers() {
    for committed in [false, true] {
        let locks = Origin::start().await;
        let media = crate::object_storage::tests::Origin::start().await;
        let storage = media.with_gcs_input_only(locks.client());
        let mut owner = locks.store().claim(A, Some(&storage)).await.unwrap();
        let key = format!("{A}/hls/master.m3u8");
        let id = owner.write_id();
        owner.begin_write(true, &key, &id).await.unwrap();
        locks
            .client()
            .upload_object(
                &UploadObjectRequest {
                    bucket: "synthetic-gcs".into(),
                    if_generation_match: Some(0),
                    ..Default::default()
                },
                Bytes::from_static(b"synthetic previous backup"),
                &UploadType::Multipart(Box::new(Object {
                    name: key.clone(),
                    content_type: Some("text/plain".into()),
                    metadata: Some(HashMap::from([(
                        WRITE_ID.into(),
                        if committed {
                            id.clone()
                        } else {
                            "other-attempt".into()
                        },
                    )])),
                    ..Default::default()
                })),
            )
            .await
            .unwrap();
        locks.age(A).await;
        let replacement = locks.store().claim(A, Some(&storage)).await;
        if committed {
            let replacement = replacement.unwrap();
            assert_eq!(replacement.dirty(), Dirty::Hls);
            assert!(owner.confirm().await.is_err());
            assert!(owner.finish(false).await.is_err());
            replacement.finish(false).await.unwrap();
        } else {
            assert!(
                replacement.is_err(),
                "unknown earlier writes must remain fenced"
            );
            assert!(locks.objects.lock().await.live.contains_key(&lock_key(A)));
        }
    }
}
