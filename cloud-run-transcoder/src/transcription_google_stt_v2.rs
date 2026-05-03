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
pub(crate) const SYNC_RECOGNIZE_MAX_DURATION_MS: u64 = 5 * 60 * 1000;

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
    _config: &Config,
    _audio_path: &Path,
    _language: Option<&str>,
) -> std::result::Result<String, ProviderFailure> {
    Err(parse_provider_status(
        None,
        None,
        "google_stt_v2 transcribe is not yet implemented",
        false,
    ))
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
    }

    #[cfg(test)]
    fn test_config() -> crate::Config {
        crate::Config::from_lookup(|_| None)
    }
}
