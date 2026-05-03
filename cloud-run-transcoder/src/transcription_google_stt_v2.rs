// ABOUTME: Google Cloud Speech-to-Text V2 (Chirp 3) provider.
// ABOUTME: Sync `recognize` REST API → ParsedVtt with word-grouped cues.

#![allow(dead_code)] // wired up incrementally in subsequent tasks

use crate::{AudioAnalysis, ParsedVtt};

/// STT V2 sync `recognize` accepts up to 10 MB inline audio per the
/// public docs; we cap at 9 MB to leave headroom for JSON envelope.
pub(crate) const SYNC_RECOGNIZE_MAX_BYTES: usize = 9 * 1024 * 1024;
/// Sync recognize duration cap (seconds). Past this we error out as
/// non-retryable so the caller can decide whether to fall back.
pub(crate) const SYNC_RECOGNIZE_MAX_DURATION_MS: u64 = 5 * 60 * 1000;

/// Convenience constructor used by the dispatch path when the audio
/// signal is already known to be silent — keeps the call site shape
/// identical to the OpenAI / Gemini paths.
pub(crate) fn empty_for_audio(audio: &AudioAnalysis) -> ParsedVtt {
    ParsedVtt::empty(audio.duration_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_sane() {
        assert!(SYNC_RECOGNIZE_MAX_BYTES > 1_000_000);
        assert!(SYNC_RECOGNIZE_MAX_DURATION_MS >= 60_000);
    }
}
