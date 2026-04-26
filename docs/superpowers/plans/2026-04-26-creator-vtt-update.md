# Creator VTT Update Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow the original uploader of a video to overwrite its WebVTT transcript with a manually edited version, and protect manual edits from being clobbered by later transcoder webhook callbacks.

**Architecture:** Add a `PUT /<sha256>/vtt` (and twin `PUT /<sha256>.vtt`) route on the Fastly Compute service. Auth reuses Blossom kind 24242 with `t=upload` plus an `x=<hash>` tag binding (same shape as delete auth, just with an upload action). The handler enforces sole-owner access, validates the body, writes `{hash}/vtt/main.vtt` to GCS, and stamps `transcript_source = Manual` on `BlobMetadata`. The transcoder webhook learns to refuse transcript writes when `transcript_source = Manual`.

**Tech Stack:** Rust, Fastly Compute, existing Blossom auth (`crate::auth`), GCS S3-compat upload (`crate::storage`), KV metadata (`crate::metadata`), Simple Cache + VCL purge.

**Worktree:** This plan should execute on a dedicated worktree branched from `origin/main` (`creator-vtt-update`). Current session is on an unrelated docs branch.

---

## File Map

- Modify: `src/blossom.rs` — add `TranscriptSource` enum + `transcript_source` field on `BlobMetadata`; getter helpers if needed.
- Modify: `src/storage.rs` — add `upload_transcript_to_gcs(hash, body, size)` (small-PUT only — VTTs are < 1MB).
- Modify: `src/main.rs` — add `validate_vtt_body`, `handle_put_transcript`, route dispatch, and Manual-source guard inside `handle_transcript_status`.
- Modify: `src/main.rs` (tests) — pure-function unit tests for body validation + the Manual-source webhook guard.

No new files. Total surface ~150 LOC.

---

## Open Decisions Locked in by This Plan

- **Auth shape:** Blossom kind 24242 with `t=upload` and `x=<hash>` (NOT NIP-98). Matches every other write endpoint in this service. Using `AuthAction::Upload` plus `validate_hash_match` rejects replay against another blob.
- **Owner gating:** Sole-owner only. `auth.pubkey == metadata.owner` (case-insensitive). Re-uploaders in `refs:<hash>` are rejected. Mirrors creator-delete semantics.
- **Race protection:** `transcript_source` field on `BlobMetadata`. `Auto` is implicit for `None` (backward-compat for existing rows). Manual writes set `Manual`. Transcoder webhook refuses to mutate transcript fields when current value is `Manual`.
- **Body validation:** Must start with `WEBVTT` magic line; size cap 512 KB (matches "small file" threshold and is comfortably above any real-world transcript). Bodies that look like JSON (start with `{` or `[`, ignoring BOM and whitespace) are rejected up front with an explicit "this looks like a transcription API response, send the WebVTT text instead" error — defends against the same LLM-output-mishandled-as-VTT class of bug that produced 27,726 corrupted VTTs in the 2026-03-09 cleanup. Yes, the `WEBVTT` magic check already rejects these; the JSON-shape branch exists purely for a debuggable error message.
- **Status side effects:** Manual write sets `transcript_status = Complete`, clears `transcript_error_code/message/retry_after/terminal`, resets `transcript_attempt_count = 0`, sets `transcript_last_attempt_at = now`.
- **Cache:** Invalidate metadata Simple Cache (`meta:<hash>`), transcript Simple Cache (`vtt:<hash>/vtt/main.vtt`), and VCL surrogate-key `<hash>` after a successful write.
- **Out of scope:** Versioning / history of edits (provenance system already records the signed auth event), language metadata (today's transcoder writes one VTT; multi-lang is a separate effort), client tooling (mobile/web update happens in their repos).

---

## Chunk 1: Implementation

### Task 1: Add `TranscriptSource` to `BlobMetadata`

**Files:**
- Modify: `src/blossom.rs` (TranscriptStatus block around line 211)

- [ ] **Step 1: Write the failing test**

Add to the existing `#[cfg(test)] mod tests` in `src/blossom.rs`:

```rust
#[test]
fn test_transcript_source_serializes_lowercase() {
    assert_eq!(
        serde_json::to_string(&TranscriptSource::Auto).unwrap(),
        "\"auto\""
    );
    assert_eq!(
        serde_json::to_string(&TranscriptSource::Manual).unwrap(),
        "\"manual\""
    );
}

#[test]
fn test_blob_metadata_omits_transcript_source_when_none() {
    let mut meta = make_test_metadata(); // existing helper, see other tests
    meta.transcript_source = None;
    let json = serde_json::to_string(&meta).unwrap();
    assert!(!json.contains("transcript_source"));
}

#[test]
fn test_blob_metadata_round_trip_manual_source() {
    let mut meta = make_test_metadata();
    meta.transcript_source = Some(TranscriptSource::Manual);
    let json = serde_json::to_string(&meta).unwrap();
    let back: BlobMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(back.transcript_source, Some(TranscriptSource::Manual));
}
```

If `make_test_metadata` doesn't exist, copy the inline construction from `test_descriptor_includes_vtt_when_transcript_complete` (around line 834).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib blossom::tests::test_transcript_source -v`
Expected: FAIL — `TranscriptSource` undefined.

- [ ] **Step 3: Add the enum and field**

In `src/blossom.rs`, immediately after the `TranscriptStatus` block (around line 229), add:

```rust
/// Origin of the current transcript artifact.
///
/// `Manual` means the blob owner uploaded an edited VTT via
/// `PUT /<hash>/vtt`. The transcoder webhook MUST refuse to overwrite
/// transcript fields when this is set, to prevent a queued machine
/// transcription from clobbering the owner's edit.
///
/// `None` (omitted in JSON) is treated as `Auto` by readers — that
/// keeps old KV rows backward-compatible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TranscriptSource {
    Auto,
    Manual,
}
```

In the `BlobMetadata` struct (`src/blossom.rs:38-103`), add this field at the end of the transcript group (after `transcript_terminal`):

```rust
    /// Origin of the current transcript (auto vs manual). When `Some(Manual)`
    /// the transcoder webhook refuses to overwrite transcript fields.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub transcript_source: Option<TranscriptSource>,
```

- [ ] **Step 4: Update every existing `BlobMetadata { ... }` literal to set the new field**

Run: `grep -n "BlobMetadata {" src/main.rs src/metadata.rs`

Each construction site must add `transcript_source: None,`. Likely sites (verify with grep before editing):
- `src/main.rs` `handle_upload` (~line 3140)
- `src/main.rs` resumable complete branch (~line 4370)
- `src/main.rs` audio mapping construction (~line 2160)
- Any other matches.

- [ ] **Step 5: Run all tests**

Run: `cargo test --lib`
Expected: PASS — all old tests green, three new tests green.

- [ ] **Step 6: Commit**

```bash
git add src/blossom.rs src/main.rs src/metadata.rs
git commit -m "feat(blossom): add TranscriptSource for manual-vs-auto VTT origin"
```

---

### Task 2: Pure body validator `validate_vtt_body`

**Files:**
- Modify: `src/main.rs` (add helper + tests near other VTT helpers, ~line 1190)

- [ ] **Step 1: Write the failing tests**

Add to the existing `#[cfg(test)] mod tests` in `src/main.rs`:

```rust
#[test]
fn validate_vtt_body_accepts_minimal_webvtt() {
    let body = b"WEBVTT\n\n00:00:00.000 --> 00:00:01.000\nhello\n";
    assert!(validate_vtt_body(body).is_ok());
}

#[test]
fn validate_vtt_body_accepts_webvtt_with_bom() {
    let mut body = vec![0xEF, 0xBB, 0xBF];
    body.extend_from_slice(b"WEBVTT\n");
    assert!(validate_vtt_body(&body).is_ok());
}

#[test]
fn validate_vtt_body_rejects_missing_magic() {
    let body = b"not a vtt";
    let err = validate_vtt_body(body).unwrap_err();
    assert!(matches!(err, BlossomError::BadRequest(_)));
}

#[test]
fn validate_vtt_body_rejects_empty() {
    let err = validate_vtt_body(b"").unwrap_err();
    assert!(matches!(err, BlossomError::BadRequest(_)));
}

#[test]
fn validate_vtt_body_rejects_oversized() {
    let body = vec![b'A'; (MAX_MANUAL_VTT_SIZE as usize) + 1];
    let err = validate_vtt_body(&body).unwrap_err();
    assert!(matches!(err, BlossomError::BadRequest(_)));
}

#[test]
fn validate_vtt_body_rejects_json_object() {
    let body = br#"{"text":"hello","usage":{"total_tokens":42}}"#;
    let err = validate_vtt_body(body).unwrap_err();
    match err {
        BlossomError::BadRequest(msg) => assert!(msg.to_lowercase().contains("json")),
        _ => panic!("expected BadRequest with JSON-specific message"),
    }
}

#[test]
fn validate_vtt_body_rejects_json_array() {
    let body = br#"[{"start":0,"end":1,"text":"hi"}]"#;
    let err = validate_vtt_body(body).unwrap_err();
    assert!(matches!(err, BlossomError::BadRequest(_)));
}

#[test]
fn validate_vtt_body_rejects_json_with_leading_whitespace() {
    let body = b"   \n\t{\"text\":\"hi\"}";
    let err = validate_vtt_body(body).unwrap_err();
    match err {
        BlossomError::BadRequest(msg) => assert!(msg.to_lowercase().contains("json")),
        _ => panic!("expected BadRequest"),
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib validate_vtt_body -v`
Expected: FAIL — `validate_vtt_body` and `MAX_MANUAL_VTT_SIZE` undefined.

- [ ] **Step 3: Add the constant and helper**

Near other VTT helpers in `src/main.rs` (after `is_vtt_file_path`, around line 1194), add:

```rust
/// Upper bound for a manually uploaded VTT body. 512 KB is well above any
/// realistic transcript (a 60-minute talk transcribes to ~80 KB) and stays
/// inside the WASM heap budget for inline buffering.
const MAX_MANUAL_VTT_SIZE: u64 = 512 * 1024;

/// Validate a manually uploaded VTT body.
///
/// - Must be non-empty.
/// - Must NOT look like JSON (defends against the LLM-output-pasted-as-VTT
///   bug class that produced 27,726 corrupted VTTs in March 2026).
/// - Must start with the `WEBVTT` magic line (BOM tolerated per WebVTT spec).
/// - Must be ≤ MAX_MANUAL_VTT_SIZE bytes.
fn validate_vtt_body(body: &[u8]) -> Result<()> {
    if body.is_empty() {
        return Err(BlossomError::BadRequest("Empty VTT body".into()));
    }
    if body.len() as u64 > MAX_MANUAL_VTT_SIZE {
        return Err(BlossomError::BadRequest(format!(
            "VTT body too large (max {} bytes)",
            MAX_MANUAL_VTT_SIZE
        )));
    }
    // Skip optional UTF-8 BOM.
    let payload = body.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(body);

    // JSON-shape check first — gives a clearer error than "missing WEBVTT magic"
    // when a client accidentally pastes the raw transcription API response.
    let first_non_ws = payload.iter().find(|b| !b.is_ascii_whitespace()).copied();
    if matches!(first_non_ws, Some(b'{') | Some(b'[')) {
        return Err(BlossomError::BadRequest(
            "VTT body looks like JSON — did you paste a raw transcription API response? \
             Send the WebVTT text (starting with `WEBVTT`) instead."
                .into(),
        ));
    }

    if !payload.starts_with(b"WEBVTT") {
        return Err(BlossomError::BadRequest(
            "VTT body must start with WEBVTT magic".into(),
        ));
    }
    Ok(())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib validate_vtt_body -v`
Expected: PASS (5 new).

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "feat(blossom): add validate_vtt_body helper for manual VTT uploads"
```

---

### Task 3: GCS upload helper `upload_transcript_to_gcs`

**Files:**
- Modify: `src/storage.rs` (add helper near `download_transcript_from_gcs`, ~line 199)

- [ ] **Step 1: Write the failing test**

The existing storage.rs is integration-flavored (talks to GCS). Pure-unit testing the upload path here is not feasible without mocking the SDK. Instead, gate behavior at the call site (Task 4 covers the handler test). For this task, only verify the function compiles and accepts the expected signature.

Add a smoke test (or skip — see Step 2):

```rust
#[cfg(test)]
mod transcript_upload_tests {
    use super::*;

    #[test]
    fn upload_transcript_to_gcs_signature_compiles() {
        // Compile-only: ensures the public signature is stable for callers.
        fn _assert_callable() -> fn(&str, fastly::Body, u64) -> Result<()> {
            upload_transcript_to_gcs
        }
        let _ = _assert_callable;
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib upload_transcript_to_gcs_signature_compiles -v`
Expected: FAIL — function does not exist.

- [ ] **Step 3: Implement `upload_transcript_to_gcs`**

In `src/storage.rs`, add (model on `upload_blob` at line 102):

```rust
/// Upload a manually edited transcript to GCS at `{hash}/vtt/main.vtt`.
///
/// VTTs are small (< 512 KB), so this always uses a single signed PUT —
/// no multipart path needed. The owner is recorded in `x-amz-meta-owner`
/// for the same provenance reasons as `upload_blob`.
pub fn upload_transcript_to_gcs(hash: &str, body: Body, size: u64) -> Result<()> {
    let config = GCSConfig::load()?;
    let object_path = format!("{}/vtt/main.vtt", hash);
    let path = format!("/{}/{}", config.bucket, object_path);

    let mut req = Request::new(Method::PUT, format!("{}{}", config.endpoint(), path));
    req.set_header("Content-Type", "text/vtt; charset=utf-8");
    req.set_header("Content-Length", size.to_string());
    req.set_header("Host", config.host());

    sign_request(&mut req, &config, Some(hash_body_for_signing(size)))?;

    req.set_body(body);

    let resp = req.send(GCS_BACKEND).map_err(|e| {
        BlossomError::StorageError(format!("Failed to upload transcript: {}", e))
    })?;

    if !resp.get_status().is_success() {
        return Err(BlossomError::StorageError(format!(
            "Transcript upload failed with status: {}",
            resp.get_status()
        )));
    }

    Ok(())
}
```

Note: `sign_request` (not `sign_request_with_owner`) is correct here — we don't need an `x-amz-meta-owner` header on a derived asset. Double-check by reading the function around `src/storage.rs:118-142` to confirm the helper used.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib upload_transcript_to_gcs_signature_compiles -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/storage.rs
git commit -m "feat(storage): add upload_transcript_to_gcs for manual VTT writes"
```

---

### Task 4: `PUT /<hash>/vtt` handler + route dispatch

**Files:**
- Modify: `src/main.rs` (route table around line 105-115; new handler near other transcript handlers)

- [ ] **Step 1: Write the failing tests**

These cover the pure decisions inside the handler. The full HTTP path is exercised by `cargo test --features local-mode` integration runs (see existing patterns in `handle_create_subtitle_job` tests).

```rust
#[test]
fn put_transcript_rejects_when_pubkey_mismatches_owner() {
    let auth_pubkey = "aaaa".repeat(16);
    let owner = "bbbb".repeat(16);
    let allowed = caller_may_update_transcript(&auth_pubkey, &owner);
    assert!(!allowed);
}

#[test]
fn put_transcript_allows_when_pubkey_matches_owner_case_insensitive() {
    let owner_lower = "abcd".repeat(16);
    let owner_upper = owner_lower.to_uppercase();
    assert!(caller_may_update_transcript(&owner_upper, &owner_lower));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib caller_may_update_transcript -v`
Expected: FAIL — helper undefined.

- [ ] **Step 3: Implement the helper and the handler**

In `src/main.rs`, near the other transcript handlers (after `handle_head_transcript_by_hash`, ~line 1740), add:

```rust
/// Owner-only gate for manual VTT updates. Re-uploaders in `refs:<hash>`
/// are not allowed to edit; this matches creator-delete's sole-owner rule.
fn caller_may_update_transcript(auth_pubkey: &str, owner: &str) -> bool {
    auth_pubkey.eq_ignore_ascii_case(owner)
}

/// PUT /<sha256>/vtt — owner uploads an edited transcript.
fn handle_put_transcript(mut req: Request, path: &str) -> Result<Response> {
    use crate::auth::{validate_auth, validate_hash_match};
    use crate::blossom::{AuthAction, TranscriptSource, TranscriptStatus};
    use crate::metadata::{
        get_blob_metadata_uncached, invalidate_metadata_cache, put_blob_metadata,
    };
    use crate::storage::upload_transcript_to_gcs;

    let hash = parse_transcript_path(path)
        .or_else(|| parse_vtt_file_path(path))
        .ok_or_else(|| BlossomError::BadRequest("Invalid VTT path".into()))?;

    // Auth: signed Blossom upload event bound to this hash.
    let auth = validate_auth(&req, AuthAction::Upload)?;
    validate_hash_match(&auth, &hash)?;

    // Sole-owner check. Read uncached so we don't trust a 5-min stale cache for an auth gate.
    let mut metadata = get_blob_metadata_uncached(&hash)?
        .ok_or_else(|| BlossomError::NotFound("Content not found".into()))?;

    if metadata.status.blocks_public_access() {
        // Banned/Deleted: hide existence per BlobAccess::NotFound semantics.
        return Err(BlossomError::NotFound("Content not found".into()));
    }

    if !is_transcribable_mime_type(&metadata.mime_type) {
        return Err(BlossomError::BadRequest(
            "Transcript not available for this media type".into(),
        ));
    }

    if !caller_may_update_transcript(&auth.pubkey, &metadata.owner) {
        return Err(BlossomError::Forbidden(
            "Only the original uploader may update the transcript".into(),
        ));
    }

    // Read body. Content-Length pre-check keeps us from buffering ridiculous payloads.
    let content_length: u64 = req
        .get_header(fastly::http::header::CONTENT_LENGTH)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| BlossomError::BadRequest("Content-Length required".into()))?;

    if content_length > MAX_MANUAL_VTT_SIZE {
        return Err(BlossomError::BadRequest(format!(
            "VTT body too large (max {} bytes)",
            MAX_MANUAL_VTT_SIZE
        )));
    }

    let body_bytes = req.take_body().into_bytes();
    if body_bytes.len() as u64 != content_length {
        return Err(BlossomError::BadRequest(
            "Content-Length doesn't match body size".into(),
        ));
    }
    validate_vtt_body(&body_bytes)?;

    let actual_size = body_bytes.len() as u64;

    // Write to GCS. If this fails, abort before mutating metadata.
    upload_transcript_to_gcs(&hash, fastly::Body::from(body_bytes), actual_size)?;

    // Stamp metadata: Manual source, transcript ready, error fields cleared.
    metadata.transcript_status = Some(TranscriptStatus::Complete);
    metadata.transcript_source = Some(TranscriptSource::Manual);
    metadata.transcript_error_code = None;
    metadata.transcript_error_message = None;
    metadata.transcript_last_attempt_at = Some(current_timestamp());
    metadata.transcript_retry_after = None;
    metadata.transcript_attempt_count = 0;
    metadata.transcript_terminal = false;
    put_blob_metadata(&metadata)?;

    // Cache invalidation: metadata cache (already done by put_blob_metadata),
    // transcript content cache, and VCL surrogate-key.
    invalidate_metadata_cache(&hash);
    purge_transcript_content_cache(&hash);
    purge_vcl_cache(&hash);

    let body = serde_json::json!({
        "sha256": hash,
        "vtt": format!("{}/{}.vtt", get_base_url(&req), hash),
        "size": actual_size,
        "transcript_source": "manual",
    });
    let mut resp = json_response(StatusCode::OK, &body);
    add_cors_headers(&mut resp);
    Ok(resp)
}
```

- [ ] **Step 4: Wire route dispatch**

In `src/main.rs` `handle_request` (~line 105-115), add two route arms next to the existing `Method::GET if is_transcript_path(p)` arm:

```rust
        (Method::PUT, p) if is_transcript_path(p) => handle_put_transcript(req, p),
        (Method::PUT, p) if is_vtt_file_path(p) => handle_put_transcript(req, p),
```

Place them above the GET arms (route order doesn't matter functionally — `match` is exhaustive — but reads better grouped by path).

- [ ] **Step 5: Run all tests**

Run: `cargo test --lib`
Expected: PASS — handler unit tests pass, nothing else regressed.

- [ ] **Step 6: Commit**

```bash
git add src/main.rs
git commit -m "feat(blossom): add PUT /<hash>/vtt for owner transcript edits"
```

---

### Task 5: Transcoder webhook respects `Manual` source

**Files:**
- Modify: `src/main.rs` `handle_transcript_status` (around line 5050-5080) and `crate::metadata::update_transcript_status`.

- [ ] **Step 1: Inspect current update path**

Run: `grep -n "fn update_transcript_status\|TranscriptMetadataUpdate" src/metadata.rs`

Confirm where the webhook applies updates. The guard MUST live close to the KV write to be race-safe; the call-site check in `handle_transcript_status` is also fine since the webhook is the only Auto writer.

- [ ] **Step 2: Write the failing test**

Add to the test module nearest `update_transcript_status` (in `src/metadata.rs` if there are unit tests there, otherwise inline in main.rs as a behavioral test on the public helper):

```rust
#[test]
fn webhook_skip_when_manual_source_present() {
    // Pure decision helper — extract the conditional out of the webhook handler
    // so it's testable without KV.
    use crate::blossom::TranscriptSource;

    assert!(should_skip_transcript_webhook_write(Some(TranscriptSource::Manual)));
    assert!(!should_skip_transcript_webhook_write(Some(TranscriptSource::Auto)));
    assert!(!should_skip_transcript_webhook_write(None));
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --lib webhook_skip_when_manual_source_present -v`
Expected: FAIL — helper undefined.

- [ ] **Step 4: Add the decision helper and use it in the webhook**

In `src/main.rs`, near `handle_transcript_status` (~line 5000), add:

```rust
/// Webhook write-guard: refuse to mutate transcript fields if the current
/// source is `Manual`. Owner-edited VTTs must not be clobbered by a
/// late/retried machine transcription job.
fn should_skip_transcript_webhook_write(current: Option<TranscriptSource>) -> bool {
    matches!(current, Some(TranscriptSource::Manual))
}
```

Then in `handle_transcript_status`, immediately before the call to `update_transcript_status` (~line 5069), add:

```rust
    // Race guard: if the owner has uploaded a manual VTT, the transcoder
    // callback must not overwrite it. We re-read uncached because the 5-min
    // metadata cache could otherwise hide a recent manual write.
    if let Some(existing) = crate::metadata::get_blob_metadata_uncached(sha256)? {
        if should_skip_transcript_webhook_write(existing.transcript_source) {
            eprintln!(
                "[TRANSCRIPT] Skipping webhook write for {} — transcript_source=manual",
                sha256
            );
            let response = serde_json::json!({
                "success": true,
                "sha256": sha256,
                "skipped": "manual_transcript",
                "message": "Transcript is owner-edited; webhook ignored"
            });
            let mut resp = json_response(StatusCode::OK, &response);
            add_cors_headers(&mut resp);
            return Ok(resp);
        }
    }
```

Place this **after** the webhook secret check (so unauth'd callers still get 403) and **before** the `update_transcript_status` call.

Also update the GCS-deletion path in `handle_transcript_status` if any: currently the webhook does not delete VTTs, so no further changes — but verify by grepping `delete_transcript` and `vtt/main.vtt` in `src/main.rs`.

- [ ] **Step 5: Run all tests**

Run: `cargo test --lib`
Expected: PASS — all old tests green, new test green.

- [ ] **Step 6: Commit**

```bash
git add src/main.rs
git commit -m "fix(blossom): transcoder webhook skips writes when transcript_source=manual"
```

---

### Task 6: Manual integration verification

This step is exercised by hand (no automated harness for cross-service flows on this repo).

- [ ] **Step 1: Local-mode smoke test**

```bash
# Build + run viceroy with local mode.
fastly compute serve

# In another terminal, with a previously-uploaded test blob:
HASH=<known sha256>
PUBKEY=<owner pubkey>
AUTH=$(./scripts/sign-blossom-event.sh upload "$HASH")  # adapt to local helper
curl -sS -X PUT "http://localhost:7676/${HASH}/vtt" \
  -H "Authorization: Nostr $AUTH" \
  -H "Content-Type: text/vtt" \
  --data-binary $'WEBVTT\n\n00:00:00.000 --> 00:00:01.000\nhello\n' \
  | jq .
```

Expected: 200 with `transcript_source: "manual"`, `vtt` URL set.

- [ ] **Step 2: Negative tests**

```bash
# Wrong owner — should 403.
curl -sS -X PUT "http://localhost:7676/${HASH}/vtt" \
  -H "Authorization: Nostr $WRONG_OWNER_AUTH" \
  --data-binary 'WEBVTT'
# Expect: 403 Forbidden

# Missing magic — should 400.
curl -sS -X PUT "http://localhost:7676/${HASH}/vtt" \
  -H "Authorization: Nostr $AUTH" \
  --data-binary 'not a vtt'
# Expect: 400 BadRequest

# JSON pasted as VTT (the LLM-output bug class) — should 400 with a
# JSON-specific message, not the generic "missing WEBVTT magic" one.
curl -sS -X PUT "http://localhost:7676/${HASH}/vtt" \
  -H "Authorization: Nostr $AUTH" \
  -H "Content-Type: text/vtt" \
  --data-binary '{"text":"hello","usage":{"total_tokens":42}}'
# Expect: 400 with body containing "looks like JSON"

# Auth bound to a different hash — should 401/AuthInvalid.
curl -sS -X PUT "http://localhost:7676/${HASH}/vtt" \
  -H "Authorization: Nostr $AUTH_FOR_OTHER_HASH" \
  --data-binary 'WEBVTT'
# Expect: 401 AuthInvalid
```

- [ ] **Step 3: Webhook race verification**

```bash
# After a successful manual write, fire a fake transcoder webhook for the same hash.
curl -sS -X POST "http://localhost:7676/admin/transcript-status" \
  -H "X-Webhook-Secret: $WEBHOOK_SECRET" \
  -H "Content-Type: application/json" \
  -d "{\"sha256\":\"${HASH}\",\"status\":\"complete\"}" \
  | jq .
# Expect: {"success": true, "skipped": "manual_transcript", ...}

# Confirm metadata still says manual:
curl -sS "http://localhost:7676/${HASH}" -I
# Then read the KV (or call /provenance) to verify transcript_source=manual.
```

- [ ] **Step 4: Deploy + production purge**

```bash
fastly compute publish --comment "feat: manual VTT update endpoint" \
  && fastly purge --all --service-id pOvEEWykEbpnylqst1KTrR
```

Allow ~5 minutes for full POP propagation (per CLAUDE.md). Re-run the smoke test against `media.divine.video` with a real owner key.

- [ ] **Step 5: No commit needed for this task** (verification only).

---

## Verification Before Completion

Per `superpowers:verification-before-completion`, before claiming done:

```bash
cargo build --release
cargo test --lib
cargo clippy --all-targets -- -D warnings
```

All three must pass. Record output in the PR description.

---

## What This Plan Deliberately Does NOT Do

- **Multi-language VTTs.** Today the schema is `{hash}/vtt/main.vtt` — single track. If multi-language is needed later, that is a separate plan with a `lang` query param and a different GCS path layout.
- **Versioning / rollback.** The signed Blossom event is stored in the existing provenance KV; the VTT itself is overwritten in place. If audit-grade history is required, route the write through Cloud Run with the existing audit-log endpoint.
- **NIP-98 auth on this route.** Rejected in favor of Blossom kind 24242 for consistency with `PUT /upload` and `DELETE /<hash>`. If a NIP-98 path is later wanted (e.g. for clients that don't speak Blossom auth), add it as an *additional* accepted scheme inside `validate_auth`, not as a route-specific exception.
- **Re-uploader edits.** Refs (`refs:<hash>`) cannot edit. If the product later wants shared edit rights, the auth check moves to "is in refs OR is owner" — explicit decision needed.
- **Client-side wiring.** divine-mobile and divine-web changes ship in their own PRs. This plan only delivers the server endpoint.
