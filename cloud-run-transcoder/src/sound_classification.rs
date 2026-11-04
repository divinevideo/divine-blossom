//! Sound classification for audio-only uploads (divine-blossom#319).
//!
//! Audio uploads already reach `POST /transcribe`. Next to transcription the
//! transcoder sends the original blob to the private `divine-audio-analyzer`
//! sidecar and stores its JSON verdict (music / sfx / neither, genre and
//! instrument tags, scores) beside the transcript as
//! `{hash}/audio/analysis.json`. The edge serves it at `/<hash>/sound`.
//! `POST /analyze-sound` runs the same step for one hash, which is how
//! existing sounds are backfilled, and with `force` re-runs it over a stored
//! verdict. The service is public, so that route takes the same
//! `X-Divine-Transcribe-Secret` header as `/transcribe/audio`.

use std::{
    collections::HashSet,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use anyhow::{anyhow, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use google_cloud_storage::http::objects::{
    download::Range as DownloadRange,
    get::GetObjectRequest,
    upload::{Media, UploadObjectRequest, UploadType},
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{check_gcs_exists, fetch_gcp_identity_token, AppState};

/// The analyzer rejects bodies above 50 MB; skip those before downloading them.
const MAX_SOUND_BYTES: i64 = 50 * 1024 * 1024;
const ANALYZER_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ClassifyOutcome {
    Classified,
    AlreadyExists,
    NotAudio,
    TooLarge,
    NotConfigured,
    /// No source blob under this hash (deleted, or never stored).
    Missing,
    /// Another request on this instance is classifying the same hash.
    InProgress,
}

/// Hashes being classified on this instance. `/transcribe` is called several
/// times for one upload within seconds (upload service, edge, subtitle jobs),
/// and each call would otherwise download the blob and queue on the analyzer.
fn in_flight() -> &'static Mutex<HashSet<String>> {
    static IN_FLIGHT: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    IN_FLIGHT.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Holds a hash in the in-flight set until dropped.
pub(crate) struct InFlightClaim(String);

impl InFlightClaim {
    pub(crate) fn try_claim(hash: &str) -> Option<Self> {
        let mut set = in_flight().lock().expect("in-flight set poisoned");
        set.insert(hash.to_string())
            .then(|| InFlightClaim(hash.to_string()))
    }
}

impl Drop for InFlightClaim {
    fn drop(&mut self) {
        if let Ok(mut set) = in_flight().lock() {
            set.remove(&self.0);
        }
    }
}

pub(crate) fn analysis_object_path(hash: &str) -> String {
    format!("{}/audio/analysis.json", hash)
}

pub(crate) fn analyzer_request_url(base: &str) -> String {
    let trimmed = base.trim().trim_end_matches('/');
    if trimmed.ends_with("/v1/analyze") {
        trimmed.to_string()
    } else {
        format!("{}/v1/analyze", trimmed)
    }
}

/// Only standalone audio is a sound; videos keep their audio inside the video.
pub(crate) fn skip_reason(content_type: &str, size: i64) -> Option<ClassifyOutcome> {
    if !content_type
        .trim()
        .to_ascii_lowercase()
        .starts_with("audio/")
    {
        return Some(ClassifyOutcome::NotAudio);
    }
    if size > MAX_SOUND_BYTES {
        return Some(ClassifyOutcome::TooLarge);
    }
    None
}

fn is_valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
}

/// Accept the analyzer's body only if it is the JSON object the edge will
/// serve, and return its `silent` flag. Funnelcake hides silent sounds, so a
/// verdict without the flag must not be stored.
pub(crate) fn validate_verdict(body: &[u8]) -> Result<bool> {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| anyhow!("analyzer returned invalid JSON: {}", e))?;
    if !matches!(value.get("tags"), Some(serde_json::Value::Array(_))) {
        return Err(anyhow!("analyzer response has no tags array"));
    }
    value
        .get("silent")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| anyhow!("analyzer response has no silent flag"))
}

/// What one classification did, and for a fresh verdict whether it is silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Classification {
    pub(crate) status: ClassifyOutcome,
    pub(crate) silent: Option<bool>,
}

impl From<ClassifyOutcome> for Classification {
    fn from(status: ClassifyOutcome) -> Self {
        Classification {
            status,
            silent: None,
        }
    }
}

/// Classify the stored blob `hash`. A stored verdict is kept unless `force`
/// is set; then it is replaced.
pub(crate) async fn classify_sound(
    state: &AppState,
    hash: &str,
    force: bool,
) -> Result<Classification> {
    let Some(base_url) = state.config.audio_analyzer_url.as_deref() else {
        return Ok(ClassifyOutcome::NotConfigured.into());
    };
    let Some(_claim) = InFlightClaim::try_claim(hash) else {
        return Ok(ClassifyOutcome::InProgress.into());
    };
    let bucket = &state.config.gcs_bucket;
    let source = GetObjectRequest {
        bucket: bucket.clone(),
        object: hash.to_string(),
        ..Default::default()
    };
    let object = match state.gcs_client.get_object(&source).await {
        Ok(object) => object,
        Err(google_cloud_storage::http::Error::Response(e)) if e.code == 404 => {
            return Ok(ClassifyOutcome::Missing.into());
        }
        Err(e) => return Err(anyhow!("Failed to read source object metadata: {}", e)),
    };
    let content_type = object.content_type.unwrap_or_default();
    if let Some(skip) = skip_reason(&content_type, object.size) {
        return Ok(skip.into());
    }

    let path = analysis_object_path(hash);
    if !force && check_gcs_exists(&state.gcs_client, bucket, &path).await? {
        return Ok(ClassifyOutcome::AlreadyExists.into());
    }

    let audio = state
        .gcs_client
        .download_object(&source, &DownloadRange::default())
        .await
        .map_err(|e| anyhow!("Failed to download from GCS: {}", e))?;
    let (verdict, silent) = call_analyzer(base_url, &content_type, audio).await?;

    let mut media = Media::new(path.clone());
    media.content_type = "application/json".into();
    state
        .gcs_client
        .upload_object(
            &UploadObjectRequest {
                bucket: bucket.clone(),
                ..Default::default()
            },
            verdict,
            &UploadType::Simple(media),
        )
        .await
        .map_err(|e| anyhow!("Failed to upload {}: {}", path, e))?;
    Ok(Classification {
        status: ClassifyOutcome::Classified,
        silent: Some(silent),
    })
}

/// The analyzer's verdict body and its `silent` flag.
async fn call_analyzer(
    base_url: &str,
    content_type: &str,
    audio: Vec<u8>,
) -> Result<(Bytes, bool)> {
    // Audience for the OIDC token is the sidecar's base URL (no path).
    let audience = base_url.trim().trim_end_matches('/').to_string();
    let token = fetch_gcp_identity_token(&audience)
        .await
        .map_err(|e| anyhow!("identity token unavailable: {:?}", e))?;
    let response = reqwest::Client::new()
        .post(analyzer_request_url(base_url))
        .bearer_auth(token)
        .header(reqwest::header::CONTENT_TYPE, content_type)
        .body(audio)
        .timeout(ANALYZER_TIMEOUT)
        .send()
        .await
        .map_err(|e| anyhow!("Failed to call audio analyzer: {}", e))?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|e| anyhow!("Failed to read audio analyzer response: {}", e))?;
    if !status.is_success() {
        let detail: String = String::from_utf8_lossy(&body).chars().take(300).collect();
        return Err(anyhow!("audio analyzer returned {}: {}", status, detail));
    }
    let silent = validate_verdict(&body)?;
    Ok((body, silent))
}

/// Classifies `hash` in the background while `/transcribe` does its own work.
/// The transcoder runs without CPU throttling, so the task keeps running after
/// the response. Failures are only logged; `POST /analyze-sound` retries.
pub(crate) fn spawn_classification(state: Arc<AppState>, hash: String) {
    if state.config.audio_analyzer_url.is_none() || !is_valid_hash(&hash) {
        return;
    }
    tokio::spawn(async move {
        match classify_sound(&state, &hash, false).await {
            Ok(Classification {
                status: ClassifyOutcome::Classified,
                silent,
            }) => info!("Classified sound {} (silent: {:?})", hash, silent),
            Ok(_) => {}
            Err(e) => warn!("Sound classification failed for {}: {:#}", hash, e),
        }
    });
}

#[derive(Debug, Deserialize)]
pub(crate) struct AnalyzeSoundRequest {
    hash: String,
    /// Replace a stored verdict, after the analyzer's rules changed.
    #[serde(default)]
    force: bool,
}

#[derive(Debug, Serialize)]
struct AnalyzeSoundResponse {
    hash: String,
    status: ClassifyOutcome,
    path: String,
    /// Whether a verdict written by this request is silent; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    silent: Option<bool>,
}

/// `POST /analyze-sound {"hash": "<sha256>", "force": false}`: classify one
/// stored sound now. Idempotent: a stored verdict is kept and reported as
/// `already_exists`, unless `force` asks to replace it.
/// Guarded by `require_transcribe_secret` in the router.
pub(crate) async fn handle_analyze_sound(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AnalyzeSoundRequest>,
) -> Response {
    let hash = request.hash.trim().to_lowercase();
    if !is_valid_hash(&hash) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "hash must be 64 hex characters"})),
        )
            .into_response();
    }
    match classify_sound(&state, &hash, request.force).await {
        Ok(Classification { status, silent }) => (
            StatusCode::OK,
            Json(AnalyzeSoundResponse {
                path: analysis_object_path(&hash),
                hash,
                status,
                silent,
            }),
        )
            .into_response(),
        Err(e) => {
            warn!("Sound classification failed for {}: {:#}", hash, e);
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_lives_beside_the_transcript() {
        assert_eq!(analysis_object_path("ab12"), "ab12/audio/analysis.json");
    }

    #[test]
    fn analyzer_url_gets_the_endpoint_once() {
        for base in [
            "https://analyzer.example.com",
            "https://analyzer.example.com/",
            "https://analyzer.example.com/v1/analyze",
        ] {
            assert_eq!(
                analyzer_request_url(base),
                "https://analyzer.example.com/v1/analyze"
            );
        }
    }

    #[test]
    fn only_audio_within_the_size_limit_is_classified() {
        assert_eq!(skip_reason("audio/wav", 1_000), None);
        assert_eq!(skip_reason("Audio/MP4", 1_000), None);
        assert_eq!(
            skip_reason("video/mp4", 1_000),
            Some(ClassifyOutcome::NotAudio)
        );
        assert_eq!(skip_reason("", 1_000), Some(ClassifyOutcome::NotAudio));
        assert_eq!(
            skip_reason("audio/mpeg", MAX_SOUND_BYTES + 1),
            Some(ClassifyOutcome::TooLarge)
        );
    }

    #[test]
    fn verdict_must_be_an_object_with_tags_and_a_silent_flag() {
        assert!(!validate_verdict(br#"{"silent":false,"kind":"music","tags":["music"]}"#).unwrap());
        assert!(validate_verdict(br#"{"silent":true,"kind":null,"tags":[]}"#).unwrap());
        assert!(validate_verdict(br#"{"silent":false,"kind":"music"}"#).is_err());
        assert!(validate_verdict(br#"{"kind":null,"tags":[]}"#).is_err());
        assert!(validate_verdict(br#"{"silent":"no","tags":[]}"#).is_err());
        assert!(validate_verdict(b"<html>502</html>").is_err());
    }

    #[test]
    fn force_defaults_to_off() {
        let request: AnalyzeSoundRequest =
            serde_json::from_str(&format!(r#"{{"hash":"{}"}}"#, "a".repeat(64))).unwrap();
        assert!(!request.force);
        let request: AnalyzeSoundRequest =
            serde_json::from_str(&format!(r#"{{"hash":"{}","force":true}}"#, "a".repeat(64)))
                .unwrap();
        assert!(request.force);
    }

    #[test]
    fn silent_is_reported_only_for_a_fresh_verdict() {
        let fresh = AnalyzeSoundResponse {
            hash: "a".repeat(64),
            status: ClassifyOutcome::Classified,
            path: analysis_object_path(&"a".repeat(64)),
            silent: Some(true),
        };
        assert_eq!(serde_json::to_value(&fresh).unwrap()["silent"], true);
        let kept = AnalyzeSoundResponse {
            silent: Classification::from(ClassifyOutcome::AlreadyExists).silent,
            ..fresh
        };
        assert!(serde_json::to_value(&kept).unwrap().get("silent").is_none());
    }

    #[test]
    fn a_hash_is_classified_once_at_a_time_per_instance() {
        let hash = "c".repeat(64);
        let first = InFlightClaim::try_claim(&hash).expect("first claim");
        assert!(InFlightClaim::try_claim(&hash).is_none());
        assert!(InFlightClaim::try_claim(&"d".repeat(64)).is_some());
        drop(first);
        assert!(InFlightClaim::try_claim(&hash).is_some());
    }

    #[test]
    fn outcomes_serialize_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&ClassifyOutcome::AlreadyExists).unwrap(),
            "\"already_exists\""
        );
    }
}
