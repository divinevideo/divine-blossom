// ABOUTME: Google Cloud Speech-to-Text V2 (Chirp 3) provider.
// ABOUTME: Sync `recognize` REST API → ParsedVtt with word-grouped cues.

#![allow(dead_code)] // wired up incrementally in subsequent tasks

use std::path::Path;

use base64::Engine as _;
use crate::{AudioAnalysis, Config, ParsedVtt, ProviderFailure, parse_provider_status};

/// STT V2 sync `recognize` accepts up to 10 MB inline audio per the
/// public docs; we cap at 9 MB to leave headroom for JSON envelope.
pub(crate) const SYNC_RECOGNIZE_MAX_BYTES: usize = 9 * 1024 * 1024;
/// Sync recognize duration cap (milliseconds; 5 minutes). Past this we
/// error out as non-retryable so the caller can decide whether to fall back.
// TODO(chunk-5): enforce this duration cap once AudioAnalysis is plumbed
// through the dispatch path. Today only the byte-size cap is checked in
// `transcribe`; this constant is reserved for the duration check.
pub(crate) const SYNC_RECOGNIZE_MAX_DURATION_MS: u64 = 5 * 60 * 1000;

pub(crate) fn recognize_url(config: &Config) -> String {
    let recognizer = config.google_stt_recognizer.trim();
    if recognizer.starts_with("projects/") {
        return format!("https://speech.googleapis.com/v2/{}:recognize", recognizer);
    }
    format!(
        "https://speech.googleapis.com/v2/projects/{}/locations/{}/recognizers/{}:recognize",
        config.gcp_project_id,
        config.google_stt_location,
        recognizer,
    )
}

pub(crate) fn build_recognize_request(config: &Config, audio_bytes: &[u8]) -> String {
    let audio_b64 = base64::engine::general_purpose::STANDARD.encode(audio_bytes);
    let body = serde_json::json!({
        "config": {
            "model": config.google_stt_model,
            "languageCodes": config.google_stt_language_codes,
            "features": {
                "enableAutomaticPunctuation": config.google_stt_enable_automatic_punctuation,
                "enableWordTimeOffsets": config.google_stt_enable_word_time_offsets,
                "maxAlternatives": config.google_stt_max_alternatives,
            },
            "autoDecodingConfig": {},
        },
        "content": audio_b64,
    });
    body.to_string()
}

/// Convenience constructor used by the dispatch path when the audio
/// signal is already known to be silent — keeps the call site shape
/// identical to the OpenAI / Gemini paths.
pub(crate) fn empty_for_audio(audio: &AudioAnalysis) -> ParsedVtt {
    ParsedVtt::empty(audio.duration_ms)
}

pub(crate) async fn transcribe(
    config: &Config,
    audio_path: &Path,
    _language: Option<&str>,
) -> std::result::Result<String, ProviderFailure> {
    let audio_bytes = tokio::fs::read(audio_path).await.map_err(|e| {
        parse_provider_status(None, None, &format!("Failed to read audio: {}", e), false)
    })?;

    if audio_bytes.len() > SYNC_RECOGNIZE_MAX_BYTES {
        // Non-retryable: caller may choose fallback.
        return Err(parse_provider_status(
            Some(413),
            None,
            &format!(
                "audio_too_large_for_sync_recognize: {} bytes > {}",
                audio_bytes.len(),
                SYNC_RECOGNIZE_MAX_BYTES
            ),
            false,
        ));
    }

    let access_token = crate::fetch_gcp_access_token().await?;
    let url = recognize_url(config);
    let body = build_recognize_request(config, &audio_bytes);

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .bearer_auth(&access_token)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .timeout(std::time::Duration::from_secs(120))
        .send()
        .await
        .map_err(|e| {
            parse_provider_status(
                None,
                None,
                &format!("Failed to call STT V2: {}", e),
                e.is_timeout(),
            )
        })?;

    let status = response.status();
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());
    let resp_body = response.text().await.map_err(|e| {
        parse_provider_status(
            Some(status.as_u16()),
            retry_after.as_deref(),
            &format!("Failed to read STT V2 response: {}", e),
            e.is_timeout(),
        )
    })?;

    if !status.is_success() {
        return Err(parse_provider_status(
            Some(status.as_u16()),
            retry_after.as_deref(),
            &resp_body,
            false,
        ));
    }

    Ok(resp_body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_sane() {
        assert!(SYNC_RECOGNIZE_MAX_BYTES > 1_000_000);
        assert!(SYNC_RECOGNIZE_MAX_DURATION_MS >= 60_000);
    }

    #[test]
    fn builds_recognize_request_body_with_word_offsets() {
        let cfg = test_config();
        let body = build_recognize_request(&cfg, &b"FAKE_WAV_BYTES"[..]);
        let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(v["config"]["model"], "chirp_3");
        assert_eq!(v["config"]["languageCodes"][0], "en-US");
        assert_eq!(v["config"]["features"]["enableAutomaticPunctuation"], true);
        assert_eq!(v["config"]["features"]["enableWordTimeOffsets"], true);
        assert!(v["config"]["autoDecodingConfig"].is_object());
        assert!(v["content"].is_string(), "audio bytes must be base64-encoded `content`");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(v["content"].as_str().unwrap())
            .expect("content is valid base64");
        assert_eq!(decoded, b"FAKE_WAV_BYTES");
    }

    #[test]
    fn recognize_url_uses_project_location_recognizer() {
        let mut env = std::collections::HashMap::new();
        env.insert("GCP_PROJECT_ID", "test-proj");
        env.insert("GOOGLE_CLOUD_LOCATION", "global");
        let cfg = crate::Config::from_lookup(|k| env.get(k).map(|v| v.to_string()));
        let url = recognize_url(&cfg);
        assert_eq!(
            url,
            "https://speech.googleapis.com/v2/projects/test-proj/locations/global/recognizers/_:recognize"
        );
    }

    #[test]
    fn recognize_url_passes_through_full_recognizer_path() {
        let mut env = std::collections::HashMap::new();
        env.insert(
            "GOOGLE_STT_RECOGNIZER",
            "projects/p/locations/global/recognizers/my-rec",
        );
        let cfg = crate::Config::from_lookup(|k| env.get(k).map(|v| v.to_string()));
        let url = recognize_url(&cfg);
        assert!(url.ends_with("/projects/p/locations/global/recognizers/my-rec:recognize"));
    }

    fn test_config() -> crate::Config {
        crate::Config::from_lookup(|_| None)
    }
}
