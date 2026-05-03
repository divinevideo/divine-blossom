// ABOUTME: Google Cloud Speech-to-Text V2 (Chirp 3) provider.
// ABOUTME: Sync `recognize` REST API → ParsedVtt with word-grouped cues.

use std::path::Path;

use base64::Engine as _;
use crate::{Config, ParsedVtt, ProviderFailure, parse_provider_status};

/// STT V2 sync `recognize` accepts up to 10 MB inline audio per the
/// public docs; we cap at 9 MB to leave headroom for JSON envelope.
/// The byte cap also effectively bounds duration: 16kHz mono PCM = 32 KB/s,
/// so 9 MB ≈ 281 s — well within the 5-minute sync recognize limit.
pub(crate) const SYNC_RECOGNIZE_MAX_BYTES: usize = 9 * 1024 * 1024;

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

/// Parse a protobuf Duration string (e.g. "1.5s", "500ms", bare float) to
/// milliseconds.  Returns `None` for unrecognised formats.
pub(crate) fn parse_offset_to_ms(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if let Some(stripped) = trimmed.strip_suffix("ms") {
        return stripped.trim().parse::<f64>().ok().map(|n| n.round() as u64);
    }
    if let Some(stripped) = trimmed.strip_suffix('s') {
        return stripped
            .trim()
            .parse::<f64>()
            .ok()
            .map(|n| (n * 1000.0).round() as u64);
    }
    // Bare number → treat as seconds (some SDKs serialize this way).
    trimmed
        .parse::<f64>()
        .ok()
        .map(|n| (n * 1000.0).round() as u64)
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SttWord {
    pub(crate) text: String,
    pub(crate) start_ms: u64,
    pub(crate) end_ms: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SttResult {
    pub(crate) transcript: String,
    pub(crate) language: Option<String>,
    pub(crate) words: Vec<SttWord>,
}

const CUE_MIN_SPAN_MS: u64 = 1_500;
const CUE_MAX_SPAN_MS: u64 = 3_000;
const CUE_MAX_LINE_CHARS: usize = 84; // two ~42-char lines tolerated by most players
const CUE_BREAK_GAP_MS: u64 = 800;    // gap between words that forces a cue break

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Cue {
    pub(crate) start_ms: u64,
    pub(crate) end_ms: u64,
    pub(crate) text: String,
}

pub(crate) fn group_words_into_cues(words: &[SttWord]) -> Vec<Cue> {
    fn flush_buf(buf: &mut Vec<&SttWord>, cues: &mut Vec<Cue>) {
        if buf.is_empty() {
            return;
        }
        let start_ms = buf.first().unwrap().start_ms;
        let end_ms = buf.last().unwrap().end_ms.max(start_ms + 1);
        let text = buf
            .iter()
            .map(|w| w.text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        cues.push(Cue { start_ms, end_ms, text });
        buf.clear();
    }

    let mut cues: Vec<Cue> = Vec::new();
    let mut buf: Vec<&SttWord> = Vec::new();

    for word in words {
        if let Some(last) = buf.last() {
            let gap = word.start_ms.saturating_sub(last.end_ms);
            let span = word.end_ms.saturating_sub(buf.first().unwrap().start_ms);
            let pending_text_len: usize =
                buf.iter().map(|w| w.text.len() + 1).sum::<usize>() + word.text.len();
            let too_long = span > CUE_MAX_SPAN_MS;
            let big_gap = gap >= CUE_BREAK_GAP_MS;
            let too_wide = pending_text_len > CUE_MAX_LINE_CHARS && span >= CUE_MIN_SPAN_MS;
            if too_long || big_gap || too_wide {
                flush_buf(&mut buf, &mut cues);
            }
        }
        buf.push(word);
    }
    flush_buf(&mut buf, &mut cues);
    cues
}

pub(crate) fn transcript_only_to_parsed_vtt(
    transcript: &str,
    language: Option<String>,
    audio_duration_ms: u64,
) -> ParsedVtt {
    let trimmed = transcript.trim();
    if trimmed.is_empty() {
        return ParsedVtt {
            content: "WEBVTT\n\n".to_string(),
            text: String::new(),
            language,
            duration_ms: audio_duration_ms,
            cue_count: 0,
            confidence: None,
        };
    }
    let end_secs = if audio_duration_ms == 0 {
        // 24h ceiling — caller never knew the duration here. Distinct from the
        // 99:59:59.000 sentinel `normalize_transcript_to_vtt` uses; both are
        // valid WebVTT but this one stays under the standard 24h horizon.
        86_400.0
    } else {
        audio_duration_ms as f64 / 1000.0
    };
    let content = format!(
        "WEBVTT\n\n1\n{} --> {}\n{}\n\n",
        crate::format_vtt_timestamp(0.0),
        crate::format_vtt_timestamp(end_secs),
        trimmed,
    );
    ParsedVtt {
        content,
        text: trimmed.to_string(),
        language,
        duration_ms: audio_duration_ms,
        cue_count: 1,
        confidence: None,
    }
}

pub(crate) fn cues_to_parsed_vtt(cues: &[Cue], language: Option<String>) -> ParsedVtt {
    if cues.is_empty() {
        return ParsedVtt {
            content: "WEBVTT\n\n".to_string(),
            text: String::new(),
            language,
            duration_ms: 0,
            cue_count: 0,
            confidence: None,
        };
    }
    let mut content = String::from("WEBVTT\n\n");
    let mut text_parts: Vec<&str> = Vec::with_capacity(cues.len());
    for (i, cue) in cues.iter().enumerate() {
        content.push_str(&format!(
            "{}\n{} --> {}\n{}\n\n",
            i + 1,
            crate::format_vtt_timestamp(cue.start_ms as f64 / 1000.0),
            crate::format_vtt_timestamp(cue.end_ms as f64 / 1000.0),
            cue.text,
        ));
        text_parts.push(cue.text.as_str());
    }
    let duration_ms = cues.last().map(|c| c.end_ms).unwrap_or(0);
    ParsedVtt {
        content,
        text: text_parts.join(" "),
        language,
        duration_ms,
        cue_count: cues.len() as u32,
        confidence: None,
    }
}

pub(crate) fn parse_stt_v2_response(
    raw: &str,
) -> std::result::Result<Vec<SttResult>, anyhow::Error> {
    let v: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| anyhow::anyhow!("Invalid STT V2 JSON: {}", e))?;
    let results = match v.get("results").and_then(|r| r.as_array()) {
        Some(arr) => arr,
        None => return Ok(Vec::new()),
    };
    let mut out = Vec::with_capacity(results.len());
    for result in results {
        let alt = match result
            .get("alternatives")
            .and_then(|a| a.as_array())
            .and_then(|a| a.first())
        {
            Some(a) => a,
            None => continue,
        };
        let transcript = alt
            .get("transcript")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if transcript.is_empty() {
            continue;
        }
        let language = result
            .get("languageCode")
            .and_then(|l| l.as_str())
            .map(|s| s.to_string());
        let words = alt
            .get("words")
            .and_then(|w| w.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|w| {
                        let text = w.get("word").and_then(|v| v.as_str())?.trim().to_string();
                        if text.is_empty() {
                            return None;
                        }
                        let start_ms = w
                            .get("startOffset")
                            .and_then(|v| v.as_str())
                            .and_then(parse_offset_to_ms)
                            .unwrap_or(0);
                        let end_ms = w
                            .get("endOffset")
                            .and_then(|v| v.as_str())
                            .and_then(parse_offset_to_ms)
                            .unwrap_or(start_ms.saturating_add(1));
                        Some(SttWord { text, start_ms, end_ms })
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.push(SttResult { transcript, language, words });
    }
    Ok(out)
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

pub(crate) fn contains_provider_json_artifact(text: &str) -> bool {
    let needles = [
        "\"total_tokens\"",
        "\"usage\":{",
        "\"results\":[",
        "\"alternatives\":[",
    ];
    needles.iter().any(|n| text.contains(n))
}

/// Drop the transcript if a single token, bigram, or trigram dominates
/// it (≥ 60% of tokens). Avoids the "thanks thanks thanks ..." failure
/// mode without hurting legitimate short utterances.
pub(crate) fn is_repeated_phrase_hallucination(text: &str) -> bool {
    let tokens: Vec<String> = text
        .split_whitespace()
        .map(|t| {
            t.chars()
                .filter(|c| c.is_alphanumeric())
                .flat_map(|c| c.to_lowercase())
                .collect::<String>()
        })
        .filter(|t| !t.is_empty())
        .collect();
    let n = tokens.len();
    if n < 6 {
        return false;
    }

    fn dominates<F: Fn(&[String], usize) -> Option<String>>(
        tokens: &[String],
        gram_size: usize,
        threshold_ratio: f64,
        gram_at: F,
    ) -> bool {
        if tokens.len() < gram_size * 2 {
            return false;
        }
        let mut counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let total = tokens.len() + 1 - gram_size;
        for i in 0..total {
            if let Some(g) = gram_at(tokens, i) {
                *counts.entry(g).or_insert(0) += 1;
            }
        }
        // Approximate coverage as fraction of total tokens. Cap at the
        // total so the ratio stays in [0, 1] for fully-repeated input
        // (overlapping windows would otherwise push it above 1.0).
        counts
            .values()
            .max()
            .copied()
            .map(|m| {
                let covered = (m * gram_size).min(tokens.len());
                covered as f64 / tokens.len() as f64 >= threshold_ratio
            })
            .unwrap_or(false)
    }

    dominates(&tokens, 1, 0.6, |t, i| Some(t[i].clone()))
        || dominates(&tokens, 2, 0.6, |t, i| {
            Some(format!("{} {}", t[i], t[i + 1]))
        })
        || dominates(&tokens, 3, 0.6, |t, i| {
            Some(format!("{} {} {}", t[i], t[i + 1], t[i + 2]))
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GoogleDropReason {
    JsonArtifact,
    RepeatedPhrase,
}

pub(crate) fn google_drop_reason(parsed: &ParsedVtt) -> Option<GoogleDropReason> {
    if parsed.text.trim().is_empty() {
        return None; // already empty — nothing to drop further
    }
    // Check parsed.content (the rendered WebVTT) as well as parsed.text
    // because malformed STT responses sometimes leak the JSON envelope into
    // cue bodies. False-positive risk: tech-podcast transcripts that
    // literally pronounce JSON syntax ('"results":[' etc.); deemed acceptable.
    if contains_provider_json_artifact(&parsed.text)
        || contains_provider_json_artifact(&parsed.content)
    {
        return Some(GoogleDropReason::JsonArtifact);
    }
    if is_repeated_phrase_hallucination(&parsed.text) {
        return Some(GoogleDropReason::RepeatedPhrase);
    }
    None
}

/// Whether word-level timestamps, degraded single-cue, or empty output was
/// produced by `parse_response_to_parsed_vtt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParseTimingMode {
    WordLevel,
    Degraded,
    Empty,
}

/// Parse an STT V2 response body into a ParsedVtt, applying the
/// word-grouping or single-cue fallback as appropriate. Does NOT apply
/// the silence/repeat/json guards — the caller decides those (so they
/// can branch on whether to fall back to another provider).
pub(crate) fn parse_response_to_parsed_vtt(
    raw: &str,
    audio_duration_ms: u64,
) -> std::result::Result<(ParsedVtt, ParseTimingMode), anyhow::Error> {
    let results = parse_stt_v2_response(raw)?;
    if results.is_empty() {
        return Ok((
            ParsedVtt {
                content: "WEBVTT\n\n".to_string(),
                text: String::new(),
                language: None,
                duration_ms: audio_duration_ms,
                cue_count: 0,
                confidence: None,
            },
            ParseTimingMode::Empty,
        ));
    }
    let language = results.iter().find_map(|r| r.language.clone());
    let mut all_words: Vec<SttWord> = Vec::new();
    let mut all_text: Vec<String> = Vec::new();
    for r in &results {
        all_words.extend(r.words.iter().cloned());
        all_text.push(r.transcript.clone());
    }
    if all_words.is_empty() {
        let combined = all_text.join(" ");
        return Ok((
            transcript_only_to_parsed_vtt(&combined, language, audio_duration_ms),
            ParseTimingMode::Degraded,
        ));
    }
    let cues = group_words_into_cues(&all_words);
    let parsed = cues_to_parsed_vtt(&cues, language);
    Ok((parsed, ParseTimingMode::WordLevel))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_sane() {
        assert!(SYNC_RECOGNIZE_MAX_BYTES > 1_000_000);
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

    #[test]
    fn parses_protobuf_duration_strings() {
        assert_eq!(parse_offset_to_ms("0s"), Some(0));
        assert_eq!(parse_offset_to_ms("1.5s"), Some(1500));
        assert_eq!(parse_offset_to_ms("12.345s"), Some(12_345));
        assert_eq!(parse_offset_to_ms("500ms"), Some(500));
        // Bare-number branch: treat as seconds.
        assert_eq!(parse_offset_to_ms("1.5"), Some(1500));
        // Empty / unparseable inputs return None, not Some(0).
        assert_eq!(parse_offset_to_ms(""), None);
        assert_eq!(parse_offset_to_ms("garbage"), None);
    }

    #[test]
    fn parses_stt_v2_response_with_words() {
        let raw = r#"{
            "results": [
                {
                    "alternatives": [
                        {
                            "transcript": "Hello world this is a test",
                            "confidence": 0.92,
                            "words": [
                                {"startOffset": "0s",     "endOffset": "0.4s", "word": "Hello"},
                                {"startOffset": "0.4s",   "endOffset": "0.9s", "word": "world"},
                                {"startOffset": "1.0s",   "endOffset": "1.2s", "word": "this"},
                                {"startOffset": "1.2s",   "endOffset": "1.4s", "word": "is"},
                                {"startOffset": "1.4s",   "endOffset": "1.6s", "word": "a"},
                                {"startOffset": "1.6s",   "endOffset": "2.1s", "word": "test"}
                            ]
                        }
                    ],
                    "languageCode": "en-us"
                }
            ]
        }"#;
        let parsed = parse_stt_v2_response(raw).expect("parses");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].transcript, "Hello world this is a test");
        assert_eq!(parsed[0].language.as_deref(), Some("en-us"));
        assert_eq!(parsed[0].words.len(), 6);
        assert_eq!(parsed[0].words[0].start_ms, 0);
        assert_eq!(parsed[0].words[0].end_ms, 400);
    }

    #[test]
    fn parses_stt_v2_response_without_words() {
        let raw = r#"{
            "results": [
                { "alternatives": [{ "transcript": "Hello world" }] }
            ]
        }"#;
        let parsed = parse_stt_v2_response(raw).expect("parses");
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].words.is_empty());
        assert_eq!(parsed[0].transcript, "Hello world");
    }

    #[test]
    fn parses_stt_v2_empty_results_to_empty_vec() {
        let raw = r#"{ "results": [] }"#;
        let parsed = parse_stt_v2_response(raw).expect("parses");
        assert!(parsed.is_empty());
    }

    #[test]
    fn groups_words_into_short_cues() {
        let words = vec![
            SttWord { text: "Hello".into(),   start_ms: 0,    end_ms: 400 },
            SttWord { text: "world".into(),   start_ms: 400,  end_ms: 900 },
            SttWord { text: "this".into(),    start_ms: 1000, end_ms: 1200 },
            SttWord { text: "is".into(),      start_ms: 1200, end_ms: 1400 },
            SttWord { text: "a".into(),       start_ms: 1400, end_ms: 1500 },
            SttWord { text: "test".into(),    start_ms: 1500, end_ms: 2100 },
            SttWord { text: "of".into(),      start_ms: 2200, end_ms: 2400 },
            SttWord { text: "grouping".into(),start_ms: 2400, end_ms: 3100 },
            SttWord { text: "cues".into(),    start_ms: 3100, end_ms: 3700 },
        ];
        let cues = group_words_into_cues(&words);
        assert!(cues.len() >= 2, "should split into multiple cues");
        for cue in &cues {
            let span_ms = cue.end_ms - cue.start_ms;
            assert!(span_ms <= 3500, "cue too long: {}ms", span_ms);
            assert!(!cue.text.trim().is_empty());
        }
        let stitched = cues.iter().map(|c| c.text.as_str()).collect::<Vec<_>>().join(" ");
        assert!(stitched.contains("Hello world"));
        assert!(stitched.contains("grouping cues"));
    }

    #[test]
    fn group_words_into_cues_handles_empty() {
        assert!(group_words_into_cues(&[]).is_empty());
    }

    #[test]
    fn group_words_breaks_on_long_silence_gap() {
        let words = vec![
            SttWord { text: "Hello".into(), start_ms: 0,     end_ms: 400 },
            SttWord { text: "world".into(), start_ms: 400,   end_ms: 900 },
            SttWord { text: "later".into(), start_ms: 5_000, end_ms: 5_400 },
        ];
        let cues = group_words_into_cues(&words);
        assert_eq!(cues.len(), 2);
        assert_eq!(cues[0].text, "Hello world");
        assert_eq!(cues[1].text, "later");
    }

    #[test]
    fn cues_to_parsed_vtt_emits_valid_webvtt() {
        let cues = vec![
            Cue { start_ms: 0,    end_ms: 1500, text: "Hello world".into() },
            Cue { start_ms: 2000, end_ms: 3000, text: "second cue".into() },
        ];
        let parsed = cues_to_parsed_vtt(&cues, Some("en-US".to_string()));
        assert!(parsed.content.starts_with("WEBVTT"));
        assert_eq!(parsed.cue_count, 2);
        assert_eq!(parsed.duration_ms, 3000);
        assert_eq!(parsed.language.as_deref(), Some("en-US"));
        assert!(parsed.content.contains("00:00:00.000 --> 00:00:01.500"));
        assert!(parsed.content.contains("00:00:02.000 --> 00:00:03.000"));
        assert!(parsed.text.contains("Hello world"));
    }

    #[test]
    fn empty_cues_return_empty_vtt() {
        let parsed = cues_to_parsed_vtt(&[], None);
        assert_eq!(parsed.content, "WEBVTT\n\n");
        assert_eq!(parsed.cue_count, 0);
        assert!(parsed.text.is_empty());
    }

    #[test]
    fn single_cue_fallback_when_no_word_offsets() {
        let parsed = transcript_only_to_parsed_vtt(
            "Hello world without timing",
            Some("en-US".into()),
            6_000,
        );
        assert_eq!(parsed.cue_count, 1);
        assert_eq!(parsed.duration_ms, 6_000);
        assert!(parsed.content.contains("00:00:00.000 --> 00:00:06.000"));
        assert!(parsed.content.contains("Hello world without timing"));
    }

    #[test]
    fn single_cue_fallback_uses_24h_when_duration_unknown() {
        let parsed = transcript_only_to_parsed_vtt("text", None, 0);
        assert!(parsed.content.contains("--> "));
        assert!(parsed.cue_count == 1);
    }

    #[test]
    fn detects_json_artifacts_in_transcript_text() {
        assert!(contains_provider_json_artifact("\"total_tokens\": 42"));
        assert!(contains_provider_json_artifact("foo \"usage\":{ bar"));
        assert!(contains_provider_json_artifact("\"results\":[ ..."));
        assert!(contains_provider_json_artifact("\"alternatives\":["));
        assert!(!contains_provider_json_artifact("Hello world"));
    }

    #[test]
    fn repeated_word_dominance_is_flagged() {
        // 6 of 7 tokens are the same word -> dropped.
        let text = "thanks thanks thanks thanks thanks thanks bye";
        assert!(is_repeated_phrase_hallucination(text));
    }

    #[test]
    fn repeated_short_phrase_is_flagged() {
        let text = "you know you know you know you know you know really";
        assert!(is_repeated_phrase_hallucination(text));
    }

    #[test]
    fn normal_transcripts_are_not_flagged() {
        let text = "Hello world this is a perfectly normal sentence about cats";
        assert!(!is_repeated_phrase_hallucination(text));
    }

    #[test]
    fn repeated_trigram_is_flagged() {
        // 12 tokens, structure "abc abc abc xyz". No unigram or bigram
        // dominates by ≥60% (each unigram = 25%, "alpha bravo" bigram
        // covers 6/12 = 50%), but the trigram "alpha bravo charlie"
        // repeats three times → covers 9/12 = 75% and trips the guard.
        let text = "alpha bravo charlie alpha bravo charlie alpha bravo charlie xray yankee zulu";
        assert!(is_repeated_phrase_hallucination(text));
    }

    #[test]
    fn empty_transcript_is_not_flagged_by_repeat_guard() {
        assert!(!is_repeated_phrase_hallucination(""));
    }

    #[test]
    fn google_guard_drops_json_artifact_text() {
        let parsed = ParsedVtt {
            content: "WEBVTT\n\n1\n00:00:00.000 --> 00:00:01.000\n\"total_tokens\": 5\n\n".into(),
            text: "\"total_tokens\": 5".into(),
            language: None,
            duration_ms: 1000,
            cue_count: 1,
            confidence: None,
        };
        assert_eq!(google_drop_reason(&parsed), Some(GoogleDropReason::JsonArtifact));
    }

    #[test]
    fn google_guard_drops_repeated_phrase() {
        let parsed = ParsedVtt {
            content: String::new(),
            text: "thanks thanks thanks thanks thanks thanks ok".into(),
            language: None,
            duration_ms: 5000,
            cue_count: 1,
            confidence: None,
        };
        assert_eq!(google_drop_reason(&parsed), Some(GoogleDropReason::RepeatedPhrase));
    }

    #[test]
    fn google_guard_keeps_normal_transcript() {
        let parsed = ParsedVtt {
            content: String::new(),
            text: "Hello world this is fine".into(),
            language: None,
            duration_ms: 2000,
            cue_count: 1,
            confidence: None,
        };
        assert_eq!(google_drop_reason(&parsed), None);
    }

    #[test]
    fn end_to_end_word_level_parse() {
        let raw = include_str!("../tests/fixtures/stt_v2_with_words.json");
        let (parsed, mode) = parse_response_to_parsed_vtt(raw, 6_000).unwrap();
        assert_eq!(mode, ParseTimingMode::WordLevel);
        assert!(parsed.cue_count >= 1);
        assert!(parsed.content.starts_with("WEBVTT"));
    }

    #[test]
    fn end_to_end_degraded_parse_when_no_offsets() {
        let raw = r#"{ "results": [ { "alternatives": [ { "transcript": "no times here" } ] } ] }"#;
        let (parsed, mode) = parse_response_to_parsed_vtt(raw, 4_000).unwrap();
        assert_eq!(mode, ParseTimingMode::Degraded);
        assert_eq!(parsed.cue_count, 1);
        assert_eq!(parsed.duration_ms, 4_000);
    }

    #[test]
    fn end_to_end_empty_results_yields_empty_vtt() {
        let raw = r#"{ "results": [] }"#;
        let (parsed, mode) = parse_response_to_parsed_vtt(raw, 2_000).unwrap();
        assert_eq!(mode, ParseTimingMode::Empty);
        assert_eq!(parsed.content, "WEBVTT\n\n");
        assert_eq!(parsed.cue_count, 0);
    }

    #[test]
    fn fallback_selection_on_provider_error() {
        let mut env = std::collections::HashMap::new();
        env.insert("TRANSCRIPTION_PROVIDER", "google_stt_v2");
        env.insert("TRANSCRIPTION_FALLBACK_PROVIDER", "openai");
        let cfg = crate::Config::from_lookup(|k| env.get(k).map(|v| v.to_string()));
        assert_eq!(cfg.transcription_fallback_provider.as_deref(), Some("openai"));
        assert!(cfg.transcription_fallback_on_provider_error);
    }

    #[test]
    fn no_fallback_when_disabled() {
        let mut env = std::collections::HashMap::new();
        env.insert("TRANSCRIPTION_FALLBACK_PROVIDER", "openai");
        env.insert("TRANSCRIPTION_FALLBACK_ON_PROVIDER_ERROR", "false");
        let cfg = crate::Config::from_lookup(|k| env.get(k).map(|v| v.to_string()));
        assert!(!cfg.transcription_fallback_on_provider_error);
    }
}
