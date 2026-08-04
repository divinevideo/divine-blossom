// ABOUTME: End-to-end compilation test against the live Divine relay and media CDN
// ABOUTME: Resolves real kind-34236 clips, renders every aspect with FFmpeg, and publishes through a local resumable upload stub

use axum::{
    body::Bytes,
    extract::{Path as AxumPath, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{post, put},
    Json, Router,
};
use divine_compiler::{
    domain::{
        Aspect, AudioSettings, CompileRequest, CreditSettings, FitMode, Job, JobStatus, NostrEvent,
        RenderRequest, Source, Watermark,
    },
    pipeline::CompilationPipeline,
    source::RelaySourceRepository,
    upload::ResumablePublisher,
    worker::JobExecutor,
};
use nostr::Keys;
use nostr_sdk::{EventSource, Filter, JsonUtil, Kind, PublicKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Real kind-34236 Divine videos, each roughly five seconds long. Override with
/// `DIVINE_E2E_COORDINATES` (comma separated `34236:<pubkey>:<d-tag>` values).
const DEFAULT_COORDINATES: &[&str] = &[
    "34236:87c3f90c2e30e4d67fd84ac9c57211ba9489e11c501eac1a8cb1227f9e5c4ee5:6a0b902286407a6d2ba4e2206896292e63ca742202c022b032ae79e6dec76470",
    "34236:07989c6c944db9ffece3a9cd5242aafb003cb954cab0530e1c9b5b83dcdae9be:1255a71d5b8a56004fc2368c3019e7605f3117a998590c539edba0d39471fffe",
];

/// A real kind-30005 list published by the Divine app, which references clips
/// with ordered `e` tags rather than addressable coordinates. Override with
/// `DIVINE_E2E_LIST`.
const DEFAULT_LIST: &str =
    "30005:bb274909e1d0cdfe1b42ce1385273933675488dc17b67efa64914325b4b8a0a9:list_1785619462240";

const RELAY: &str = "wss://relay.divine.video";

/// Clips taken from an app-authored list, bounded to keep the render short.
const DEFAULT_MAX_CLIPS: usize = 2;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires network access to relay.divine.video, media.divine.video, and system ffmpeg"]
async fn compiles_an_editor_authored_coordinate_list_into_every_aspect() {
    let coordinates: Vec<String> = match std::env::var("DIVINE_E2E_COORDINATES") {
        Ok(value) => value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(String::from)
            .collect(),
        Err(_) => DEFAULT_COORDINATES.iter().map(|v| String::from(*v)).collect(),
    };
    assert!(!coordinates.is_empty(), "no source coordinates configured");

    let tags = coordinates
        .iter()
        .map(|coordinate| vec!["a".to_string(), coordinate.clone()])
        .collect();
    compile_and_verify(list_event(tags), coordinates.len()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires network access to relay.divine.video, media.divine.video, and system ffmpeg"]
async fn compiles_a_real_app_authored_list_referenced_by_event_id() {
    let reference = std::env::var("DIVINE_E2E_LIST").unwrap_or_else(|_| DEFAULT_LIST.into());
    let max_clips = std::env::var("DIVINE_E2E_MAX_CLIPS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_MAX_CLIPS);

    let published = fetch_list(&reference).await;
    let event_tags = published.tags.iter().filter(|tag| tag[0] == "e").count();
    assert!(
        event_tags >= max_clips,
        "{reference} has {event_tags} e tags, needs at least {max_clips}"
    );
    assert_eq!(
        published.tags.iter().filter(|tag| tag[0] == "a").count(),
        0,
        "expected an app-authored list that uses only e tags"
    );

    compile_and_verify(take_clips(published, max_clips), max_clips).await;
}

/// Fetches a signed list straight off the relay so the test compiles exactly
/// what the Divine app published.
async fn fetch_list(reference: &str) -> NostrEvent {
    let mut parts = reference.splitn(3, ':');
    assert_eq!(parts.next(), Some("30005"), "list reference must be kind 30005");
    let author = PublicKey::from_hex(parts.next().expect("list author")).expect("valid author");
    let identifier = parts.next().expect("list identifier");

    let client = nostr_sdk::Client::default();
    client.add_relay(RELAY).await.expect("add relay");
    client.connect().await;
    let events = client
        .get_events_of(
            vec![Filter::new()
                .kind(Kind::Custom(30_005))
                .author(author)
                .identifier(identifier)],
            EventSource::relays(Some(Duration::from_secs(20))),
        )
        .await
        .expect("query list");
    let newest = events
        .into_iter()
        .max_by_key(|event| event.created_at)
        .unwrap_or_else(|| panic!("no kind 30005 list found for {reference}"));
    serde_json::from_str(&newest.as_json()).expect("decode list event")
}

/// Keeps the first `count` video references and every non-video tag, so the
/// test renders a bounded slice of a long list in its published order.
fn take_clips(mut event: NostrEvent, count: usize) -> NostrEvent {
    let mut kept = 0;
    event.tags.retain(|tag| {
        if tag[0] != "e" && tag[0] != "a" {
            return true;
        }
        kept += 1;
        kept <= count
    });
    event
}

async fn compile_and_verify(list: NostrEvent, expected_clips: usize) {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("divine-compiler-e2e-{suffix}"));
    let uploads = root.join("uploads");
    let work = root.join("work");
    std::fs::create_dir_all(&uploads).unwrap();
    std::fs::create_dir_all(&work).unwrap();

    let stub = UploadStub::start(uploads.clone()).await;
    let publisher =
        ResumablePublisher::new(&stub.origin, &stub.origin, Keys::generate()).expect("publisher");

    let repository = RelaySourceRepository::connect(&[RELAY.into()], Duration::from_secs(20))
        .await
        .expect("connect to relay");

    let pipeline = CompilationPipeline::new(
        Arc::new(repository),
        publisher,
        work.clone(),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/divine-logo.png"),
        PathBuf::from(
            std::env::var("CREDIT_FONT_PATH")
                .unwrap_or_else(|_| divine_compiler::render::DEFAULT_FONT_PATH.into()),
        ),
        ["media.divine.video".to_string()],
        false,
    )
    .expect("pipeline");

    let job = job_for(list);
    job.request.validate().expect("request is valid");

    let result = pipeline.execute(&job).await.expect("pipeline executed");

    assert!(
        result.aspect_failures.is_empty(),
        "aspect failures: {:?}",
        result.aspect_failures
    );
    assert_eq!(
        result.clips_used, expected_clips,
        "clips dropped: {:?}",
        result.clips_dropped
    );
    assert_eq!(result.outputs.len(), 3, "expected one output per aspect");
    assert!(result.duration_sec > 0.0);
    assert_eq!(result.credits.len(), expected_clips);

    let stored = stub.stored();
    for output in &result.outputs {
        let (width, height) = output.aspect.dimensions();
        assert_eq!(output.dim, format!("{width}x{height}"));
        assert!(output.size > 0);
        assert!(output.url.ends_with(&output.sha256));

        let name = format!("{}.mp4", aspect_file_name(output.aspect));
        let path = stored
            .get(&name)
            .unwrap_or_else(|| panic!("{name} was never uploaded; stored: {stored:?}"));
        let bytes = std::fs::read(path).expect("read uploaded compilation");
        assert_eq!(bytes.len() as u64, output.size);
        assert_eq!(hex::encode(Sha256::digest(&bytes)), output.sha256);

        let probe = probe(path);
        assert_eq!(
            probe.dimensions,
            (width, height),
            "{name} rendered at the wrong size"
        );
        assert!(probe.has_audio, "{name} has no audio track");
        assert!(
            probe.duration_sec >= result.duration_sec - 1.0,
            "{name} is shorter than the source clips ({} < {})",
            probe.duration_sec,
            result.duration_sec
        );
    }

    // Set DIVINE_E2E_KEEP_OUTPUT to inspect the rendered compilations by hand.
    if std::env::var("DIVINE_E2E_KEEP_OUTPUT").is_ok() {
        for (name, path) in &stored {
            println!("kept {name}: {}", path.display());
        }
    } else {
        let _ = std::fs::remove_dir_all(&root);
    }
}

fn aspect_file_name(aspect: Aspect) -> &'static str {
    match aspect {
        Aspect::Portrait => "portrait",
        Aspect::Square => "square",
        Aspect::Landscape => "landscape",
    }
}

fn list_event(mut tags: Vec<Vec<String>>) -> NostrEvent {
    tags.insert(0, vec!["d".into(), "compiler-end-to-end".into()]);
    NostrEvent {
        id: "0".repeat(64),
        pubkey: "1".repeat(64),
        created_at: 1,
        kind: 30_005,
        tags,
        content: String::new(),
        sig: "2".repeat(128),
    }
}

fn job_for(list_event: NostrEvent) -> Job {
    Job {
        id: format!("e2e-{}", uuid::Uuid::new_v4()),
        status: JobStatus::Running,
        progress: 0.0,
        request: CompileRequest {
            source: Source { list_event },
            renders: vec![
                RenderRequest {
                    aspect: Aspect::Portrait,
                    default_fit: FitMode::BlurPad,
                    clip_overrides: vec![],
                },
                RenderRequest {
                    aspect: Aspect::Square,
                    default_fit: FitMode::CenterCrop,
                    clip_overrides: vec![],
                },
                RenderRequest {
                    aspect: Aspect::Landscape,
                    default_fit: FitMode::Letterbox,
                    clip_overrides: vec![],
                },
            ],
            watermark: Watermark::default(),
            credit: CreditSettings::default(),
            audio: AudioSettings::default(),
            max_duration_sec: 600,
        },
        signer_pubkey: "1".repeat(64),
        initiated_by: "end-to-end@divine.video".into(),
        created_at: 1,
        updated_at: 1,
        result: None,
        error: None,
    }
}

struct Probe {
    dimensions: (u32, u32),
    has_audio: bool,
    duration_sec: f64,
}

fn probe(path: &PathBuf) -> Probe {
    let output = std::process::Command::new("ffprobe")
        .args([
            "-v",
            "error",
            "-show_entries",
            "format=duration:stream=codec_type,width,height",
            "-of",
            "json",
        ])
        .arg(path)
        .output()
        .expect("run ffprobe");
    assert!(output.status.success(), "ffprobe rejected {path:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("ffprobe json");
    let streams = value["streams"].as_array().cloned().unwrap_or_default();
    let video = streams
        .iter()
        .find(|stream| stream["codec_type"] == "video")
        .expect("no video stream");

    Probe {
        dimensions: (
            video["width"].as_u64().unwrap() as u32,
            video["height"].as_u64().unwrap() as u32,
        ),
        has_audio: streams
            .iter()
            .any(|stream| stream["codec_type"] == "audio"),
        duration_sec: value["format"]["duration"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
    }
}

/// Minimal stand-in for the `upload.divine.video` resumable API so the test
/// exercises the real publisher without writing to production storage.
#[derive(Clone)]
struct StubState {
    directory: PathBuf,
    origin: String,
    sessions: Arc<Mutex<HashMap<String, PathBuf>>>,
    counter: Arc<AtomicUsize>,
}

struct UploadStub {
    origin: String,
    sessions: Arc<Mutex<HashMap<String, PathBuf>>>,
}

impl UploadStub {
    async fn start(directory: PathBuf) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let state = StubState {
            directory,
            origin: origin.clone(),
            sessions: sessions.clone(),
            counter: Arc::new(AtomicUsize::new(0)),
        };
        let app = Router::new()
            .route("/upload/init", post(init))
            .route("/upload/:id/complete", post(complete))
            .route("/put/:id", put(put_chunk).head(head_offset))
            .with_state(state);

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        Self { origin, sessions }
    }

    fn stored(&self) -> HashMap<String, PathBuf> {
        self.sessions
            .lock()
            .unwrap()
            .values()
            .map(|path| {
                (
                    path.file_name().unwrap().to_string_lossy().into_owned(),
                    path.clone(),
                )
            })
            .collect()
    }
}

async fn init(
    State(state): State<StubState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        authorization.starts_with("Nostr "),
        "publisher must send a Blossom authorization header"
    );
    assert_eq!(body["generateDerivatives"], json!(false));
    assert_eq!(body["contentType"], json!("video/mp4"));

    let id = format!("upload-{}", state.counter.fetch_add(1, Ordering::SeqCst));
    let file_name = body["fileName"].as_str().expect("fileName").to_string();
    let path = state.directory.join(&file_name);
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, b"").unwrap();
    state.sessions.lock().unwrap().insert(id.clone(), path);

    Json(json!({
        "uploadId": id,
        "uploadUrl": format!("{}/put/{id}", state.origin),
        "chunkSize": 1024 * 1024,
        "nextOffset": 0,
        "requiredHeaders": {},
    }))
    .into_response()
}

async fn put_chunk(
    State(state): State<StubState>,
    AxumPath(id): AxumPath<String>,
    body: Bytes,
) -> Response {
    let path = match state.sessions.lock().unwrap().get(&id).cloned() {
        Some(path) => path,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let mut existing = std::fs::read(&path).unwrap_or_default();
    existing.extend_from_slice(&body);
    std::fs::write(&path, &existing).unwrap();
    offset_response(existing.len() as u64)
}

async fn head_offset(State(state): State<StubState>, AxumPath(id): AxumPath<String>) -> Response {
    let path = match state.sessions.lock().unwrap().get(&id).cloned() {
        Some(path) => path,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let size = std::fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
    offset_response(size)
}

fn offset_response(offset: u64) -> Response {
    ([("Upload-Offset", offset.to_string())], StatusCode::OK).into_response()
}

async fn complete(State(state): State<StubState>, AxumPath(id): AxumPath<String>) -> Response {
    let path = match state.sessions.lock().unwrap().get(&id).cloned() {
        Some(path) => path,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let bytes = std::fs::read(&path).unwrap();
    Json(json!({
        "sha256": hex::encode(Sha256::digest(&bytes)),
        "size": bytes.len(),
        "dim": serde_json::Value::Null,
    }))
    .into_response()
}
