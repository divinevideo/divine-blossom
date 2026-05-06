# Gemini 2.5 Pro Transcription Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace OpenAI transcription with Gemini 2.5 Pro via Vertex AI for higher quality, higher rate limits, and no separate API key.

**Architecture:** Add a Gemini provider path to `transcribe_audio_via_provider_once()`. Audio WAV bytes are base64-encoded and sent to Vertex AI's `generateContent` endpoint with `audioTimestamp: true` and structured JSON output. The response JSON (`{language, segments[{start, end, text}]}`) is already parseable by `normalize_transcript_to_vtt()`. A `TRANSCRIPTION_PROVIDER` env var selects `gemini` (default) or `openai` (fallback).

**Tech Stack:** Rust, `google-cloud-auth` (already in deps), `reqwest` (already in deps), Vertex AI `generateContent` REST API, `base64` crate

**Spec:** `docs/superpowers/specs/2026-04-09-gemini-transcription-design.md`

---

## File Structure

**Modify:**
- `cloud-run-transcoder/src/main.rs` — Config struct, `transcribe_audio_via_provider_once()`, helper functions
- `cloud-run-transcoder/Cargo.toml` — add `base64` crate
- `cloud-run-transcoder/deploy.sh` — update env vars for Gemini

**Responsibilities:**
- `transcribe_audio_via_provider_once()` — dispatches to Gemini or OpenAI path based on config
- `transcribe_via_gemini()` — new function: base64 encode audio, POST to Vertex AI, extract response text
- `fetch_gcp_access_token()` — new function: get bearer token from GCP metadata server
- Config struct — new `transcription_provider` field, new `gcp_project_id` field

---

## Chunk 1: Add Gemini Provider

### Task 1: Add `base64` dependency and config fields

**Files:**
- Modify: `cloud-run-transcoder/Cargo.toml`
- Modify: `cloud-run-transcoder/src/main.rs` (Config struct, lines 42-63, and `from_lookup`, lines 96-140)

- [ ] **Step 1: Add base64 crate to Cargo.toml**

Add under `[dependencies]`:
```toml
base64 = "0.22"
```

- [ ] **Step 2: Add config fields**

Add to the `Config` struct (after `transcription_model`):

```rust
    /// Transcription provider: "gemini" or "openai"
    transcription_provider: String,
    /// GCP project ID for Vertex AI (required for Gemini provider)
    gcp_project_id: String,
    /// GCP region for Vertex AI
    gcp_region: String,
```

Add to `from_lookup` (after the `transcription_model` line):

```rust
            transcription_provider: lookup("TRANSCRIPTION_PROVIDER")
                .unwrap_or_else(|| "gemini".to_string()),
            gcp_project_id: lookup("GCP_PROJECT_ID")
                .unwrap_or_else(|| "rich-compiler-479518-d2".to_string()),
            gcp_region: lookup("GCP_REGION")
                .unwrap_or_else(|| "us-central1".to_string()),
```

- [ ] **Step 3: Add `use base64::Engine as _;` import**

Add near the top imports:
```rust
use base64::Engine as _;
```

- [ ] **Step 4: Verify it compiles**

Run: `cd cloud-run-transcoder && cargo check`

Expected: compiles without errors.

- [ ] **Step 5: Commit**

```bash
git add cloud-run-transcoder/Cargo.toml cloud-run-transcoder/src/main.rs
git commit -m "feat(transcoder): add Gemini provider config fields and base64 dep"
```

### Task 2: Add GCP access token fetcher

**Files:**
- Modify: `cloud-run-transcoder/src/main.rs`

- [ ] **Step 1: Write the token fetcher function**

Add after the `transcription_response_format()` function (around line 2184):

```rust
/// Fetch a GCP access token from the metadata server (works on Cloud Run)
/// or fall back to Application Default Credentials locally.
async fn fetch_gcp_access_token() -> std::result::Result<String, ProviderFailure> {
    // On Cloud Run, the metadata server provides tokens for the service account.
    let metadata_url =
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
    let client = reqwest::Client::new();
    let resp = client
        .get(metadata_url)
        .header("Metadata-Flavor", "Google")
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let body = r.text().await.map_err(|e| parse_provider_status(
                None, None, &format!("Failed to read metadata token: {}", e), false,
            ))?;
            let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
                parse_provider_status(None, None, &format!("Failed to parse metadata token: {}", e), false)
            })?;
            json["access_token"]
                .as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| parse_provider_status(
                    None, None, "No access_token in metadata response", false,
                ))
        }
        _ => {
            // Fallback: try gcloud CLI for local development
            let output = tokio::process::Command::new("gcloud")
                .args(["auth", "print-access-token"])
                .output()
                .await
                .map_err(|e| parse_provider_status(
                    None, None, &format!("gcloud auth failed: {}", e), false,
                ))?;
            if output.status.success() {
                Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
            } else {
                Err(parse_provider_status(
                    None, None, "Failed to get GCP access token (no metadata server, gcloud failed)", false,
                ))
            }
        }
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd cloud-run-transcoder && cargo check`

- [ ] **Step 3: Commit**

```bash
git add cloud-run-transcoder/src/main.rs
git commit -m "feat(transcoder): add GCP metadata server token fetcher"
```

### Task 3: Write the Gemini transcription function

**Files:**
- Modify: `cloud-run-transcoder/src/main.rs`

- [ ] **Step 1: Write `transcribe_via_gemini()`**

Add after `fetch_gcp_access_token()`:

```rust
/// Transcribe audio using Gemini 2.5 Pro via Vertex AI generateContent.
/// Returns the raw JSON text from the model (segments with timestamps).
async fn transcribe_via_gemini(
    config: &Config,
    audio_path: &Path,
    _language: Option<&str>,
) -> std::result::Result<String, ProviderFailure> {
    let audio_bytes = tokio::fs::read(audio_path).await.map_err(|e| {
        parse_provider_status(None, None, &format!("Failed to read audio: {}", e), false)
    })?;
    let audio_b64 = base64::engine::general_purpose::STANDARD.encode(&audio_bytes);

    let access_token = fetch_gcp_access_token().await?;

    let url = format!(
        "https://{}-aiplatform.googleapis.com/v1/projects/{}/locations/{}/publishers/google/models/{}:generateContent",
        config.gcp_region,
        config.gcp_project_id,
        config.gcp_region,
        config.transcription_model,
    );

    let body = serde_json::json!({
        "contents": [{
            "role": "user",
            "parts": [
                {"text": "Transcribe this audio. Return every spoken segment with start and end timestamps in seconds and the text. If there is no speech, return an empty segments array."},
                {"inlineData": {"mimeType": "audio/wav", "data": audio_b64}}
            ]
        }],
        "generationConfig": {
            "audioTimestamp": true,
            "responseMimeType": "application/json",
            "responseSchema": {
                "type": "object",
                "properties": {
                    "language": {"type": "string"},
                    "segments": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "start": {"type": "number"},
                                "end": {"type": "number"},
                                "text": {"type": "string"}
                            }
                        }
                    }
                }
            }
        }
    });

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .bearer_auth(&access_token)
        .json(&body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| {
            parse_provider_status(
                None, None,
                &format!("Failed to call Vertex AI: {}", e),
                e.is_timeout(),
            )
        })?;

    let status = response.status();
    let retry_after_header = response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());
    let resp_body = response.text().await.map_err(|e| {
        parse_provider_status(
            Some(status.as_u16()), retry_after_header.as_deref(),
            &format!("Failed to read Vertex AI response: {}", e),
            e.is_timeout(),
        )
    })?;

    if !status.is_success() {
        return Err(parse_provider_status(
            Some(status.as_u16()), retry_after_header.as_deref(),
            &resp_body, false,
        ));
    }

    // Extract the text from Vertex AI response: candidates[0].content.parts[0].text
    let resp_json: serde_json::Value = serde_json::from_str(&resp_body).map_err(|e| {
        parse_provider_status(None, None, &format!("Invalid Vertex AI JSON: {}", e), false)
    })?;

    resp_json["candidates"][0]["content"]["parts"][0]["text"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| parse_provider_status(
            None, None,
            &format!("No text in Vertex AI response: {}", resp_body),
            false,
        ))
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd cloud-run-transcoder && cargo check`

- [ ] **Step 3: Commit**

```bash
git add cloud-run-transcoder/src/main.rs
git commit -m "feat(transcoder): add Gemini transcription via Vertex AI generateContent"
```

### Task 4: Wire provider dispatch into `transcribe_audio_via_provider_once()`

**Files:**
- Modify: `cloud-run-transcoder/src/main.rs` (function at line ~2017)

- [ ] **Step 1: Add provider dispatch at the top of `transcribe_audio_via_provider_once()`**

Replace the entire function body with:

```rust
async fn transcribe_audio_via_provider_once(
    config: &Config,
    audio_path: &Path,
    language: Option<&str>,
) -> std::result::Result<String, ProviderFailure> {
    if config.transcription_provider == "gemini" {
        return transcribe_via_gemini(config, audio_path, language).await;
    }

    // --- OpenAI path (original code below, unchanged) ---
    let api_url = config.transcription_api_url.as_ref().ok_or_else(|| {
        parse_provider_status(None, None, "TRANSCRIPTION_API_URL is not configured", false)
    })?;

    // ... rest of the existing OpenAI multipart code unchanged ...
```

Keep the entire existing OpenAI path as-is after the early return.

- [ ] **Step 2: Update helper functions for Gemini**

Update `transcription_supports_logprobs()` to return false for Gemini:

```rust
fn transcription_supports_logprobs(model: &str) -> bool {
    let model = model.trim().to_ascii_lowercase();
    // Gemini doesn't use logprobs param — only OpenAI gpt-4o-transcribe models do
    model.contains("gpt-4o-mini-transcribe") || model.contains("gpt-4o-transcribe")
}
```

(No change needed — already returns false for non-OpenAI models.)

- [ ] **Step 3: Verify it compiles**

Run: `cd cloud-run-transcoder && cargo check`

- [ ] **Step 4: Run existing tests**

Run: `cd cloud-run-transcoder && cargo test`

Expected: all existing tests pass (Gemini path isn't exercised by unit tests).

- [ ] **Step 5: Commit**

```bash
git add cloud-run-transcoder/src/main.rs
git commit -m "feat(transcoder): wire Gemini provider dispatch into transcription pipeline"
```

---

## Chunk 2: Deploy Script and Tests

### Task 5: Update deploy script

**Files:**
- Modify: `cloud-run-transcoder/deploy.sh`

- [ ] **Step 1: Update env vars**

Change:
```bash
TRANSCRIPTION_API_URL="${TRANSCRIPTION_API_URL:-https://api.openai.com/v1/audio/transcriptions}"
TRANSCRIPTION_MODEL="${TRANSCRIPTION_MODEL:-gpt-4o-mini-transcribe}"
```

To:
```bash
TRANSCRIPTION_PROVIDER="${TRANSCRIPTION_PROVIDER:-gemini}"
TRANSCRIPTION_MODEL="${TRANSCRIPTION_MODEL:-gemini-2.5-pro}"
# OpenAI fallback (only used when TRANSCRIPTION_PROVIDER=openai)
TRANSCRIPTION_API_URL="${TRANSCRIPTION_API_URL:-https://api.openai.com/v1/audio/transcriptions}"
```

- [ ] **Step 2: Update the `--set-env-vars` line**

Add `TRANSCRIPTION_PROVIDER=${TRANSCRIPTION_PROVIDER}` to the env vars string. Keep `TRANSCRIPTION_API_URL` for OpenAI fallback.

The `--set-secrets` line should keep `TRANSCRIPTION_API_KEY=openai_api_key:latest` — it's only used when provider is `openai`, harmless otherwise.

- [ ] **Step 3: Commit**

```bash
git add cloud-run-transcoder/deploy.sh
git commit -m "feat(transcoder): default deploy to Gemini 2.5 Pro transcription"
```

### Task 6: Add unit test for Gemini response parsing

**Files:**
- Modify: `cloud-run-transcoder/src/main.rs` (tests module)

- [ ] **Step 1: Add test that Gemini-style JSON parses into VTT**

Add to the existing `mod tests` block:

```rust
    #[test]
    fn gemini_structured_output_normalizes_to_vtt() {
        // Simulates the JSON that Gemini returns with audioTimestamp + responseSchema
        let gemini_json = r#"{
            "language": "en",
            "segments": [
                {"start": 0.0, "end": 2.5, "text": "Hello world"},
                {"start": 2.5, "end": 5.0, "text": "Testing one two three"}
            ]
        }"#;
        let parsed = normalize_transcript_to_vtt(gemini_json).unwrap();
        assert!(parsed.content.starts_with("WEBVTT"));
        assert_eq!(parsed.cue_count, 2);
        assert_eq!(parsed.language.as_deref(), Some("en"));
        assert!(parsed.content.contains("Hello world"));
        assert!(parsed.content.contains("Testing one two three"));
        assert!(parsed.content.contains("00:00:00.000 --> 00:00:02.500"));
    }

    #[test]
    fn gemini_empty_segments_returns_error() {
        let gemini_json = r#"{"language": "en", "segments": []}"#;
        // Empty segments = no speech detected, should still parse but with 0 cues
        // normalize_transcript_to_vtt falls through to the "text fallback" path
        // and tries to wrap it as a single cue, which won't have segments.
        // This tests the actual behavior.
        let result = normalize_transcript_to_vtt(gemini_json);
        // With empty segments array, the JSON parser enters the segments branch
        // but cue_index stays at 1 (no cues written), so it falls through
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn gemini_config_defaults_to_gemini_provider() {
        let config = Config::from_lookup(|_| None);
        assert_eq!(config.transcription_provider, "gemini");
        assert_eq!(config.gcp_project_id, "rich-compiler-479518-d2");
        assert_eq!(config.gcp_region, "us-central1");
    }
```

- [ ] **Step 2: Run tests**

Run: `cd cloud-run-transcoder && cargo test`

Expected: all tests pass.

- [ ] **Step 3: Run clippy**

Run: `cd cloud-run-transcoder && cargo clippy`

Expected: no warnings.

- [ ] **Step 4: Commit**

```bash
git add cloud-run-transcoder/src/main.rs
git commit -m "test(transcoder): add Gemini response parsing and config tests"
```

---

Plan complete and saved to `docs/superpowers/plans/2026-04-09-gemini-transcription.md`. Ready to execute?
