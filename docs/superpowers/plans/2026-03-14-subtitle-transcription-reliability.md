# Subtitle Transcription Reliability Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore reliable subtitle generation for new uploads, prevent provider throttling from cascading into repeated failed transcription attempts, and make clients wait for ready subtitles instead of snapshotting "not ready yet" as "no subtitles."

**Architecture:** Keep the existing Blossom -> Cloud Run transcoder -> GCS pipeline, but harden each boundary. Cloud Run must become rate-aware and idempotent around provider calls. Blossom must stop blindly retriggering failed or cooling-down jobs. The mobile client must treat `202 Accepted` plus `Retry-After` as a temporary state and repoll while the video remains visible.

**Tech Stack:** Fastly Compute Rust, Cloud Run Rust, GCS, OpenAI Audio Transcriptions API, Flutter/Riverpod

---

## Research Summary

- Production switched from `whisper-1` to `gpt-4o-mini-transcribe` on Cloud Run revision `divine-transcoder-00019-lv4`, created `2026-03-08T03:13:24Z`.
- The first widespread provider failure starts at `2026-03-10T14:46:29Z`, where Cloud Run logs `Transcription provider returned 429 Too Many Requests`.
- In the `2026-03-10T14:40Z` to `2026-03-10T14:46:28Z` window, sampled `/transcribe` request logs were `8x 200`, `1x 500`. From `2026-03-10T14:46:29Z` to `2026-03-10T15:20Z`, the same endpoint flips to `9x 200`, `77x 500`.
- Blossom retriggers transcription whenever `/{sha256}/vtt` is missing and metadata is `Failed`, `Pending`, `Complete`, or `None` in [`src/main.rs`](/Users/rabble/code/divine/divine-blossom/src/main.rs#L933). That is a retry amplifier.
- For the current failing hash `50dfc6758bb3cdf823ef33315e72642ebb881a0b1d0f6b0d8bade0f0fad30c3a`, Cloud Run logged `6` separate `Starting transcription` events in about `77` seconds.
- The mobile subtitle provider does a single GET to Blossom and treats non-`200` as no cues in [`subtitle_providers.dart`](/Users/rabble/code/divine/divine-mobile/mobile/lib/providers/subtitle_providers.dart#L40). That turns temporary `202` states into missing captions.

## Scope

This plan fixes the outage in three layers:

1. Stop rate-limit storms and duplicate work in Cloud Run.
2. Stop Blossom from re-enqueueing doomed work on every VTT request.
3. Make the mobile client wait for subtitles instead of giving up after one pre-ready fetch.

The plan intentionally does not redesign the whole media pipeline. It restores reliability first, then backfills recent broken uploads.

## Chunk 1: Stabilize Cloud Run Provider Calls

### Task 1: Classify retryable transcription failures and add bounded backoff

**Files:**
- Modify: `cloud-run-transcoder/src/main.rs`
- Test: `cloud-run-transcoder/src/main.rs`

- [ ] **Step 1: Write failing unit tests for retry classification and backoff**

Add tests near the existing transcription unit tests for:
- `429 Too Many Requests` -> retryable
- `500/502/503/504` -> retryable
- malformed request / `400` -> non-retryable
- bounded exponential backoff respects max delay

- [ ] **Step 2: Run the transcoder tests to verify the new cases fail**

Run:

```bash
cargo test --manifest-path cloud-run-transcoder/Cargo.toml
```

Expected: the new retry/backoff tests fail because the helpers do not exist yet.

- [ ] **Step 3: Implement provider error classification helpers**

Add small focused helpers in `cloud-run-transcoder/src/main.rs`:
- `parse_provider_status(...)`
- `is_retryable_provider_failure(...)`
- `retry_delay_for_attempt(...)`

Requirements:
- respect HTTP `429`
- respect transient `5xx`
- support network timeouts as retryable
- preserve the original provider body for logs

- [ ] **Step 4: Wrap `transcribe_audio_via_provider` in bounded retry logic**

Requirements:
- use jittered exponential backoff
- honor `Retry-After` if the provider returns it
- cap retries and total wait time via env vars
- on exhausted retries, return a stable error code like `provider_rate_limited`

- [ ] **Step 5: Re-run the transcoder tests**

Run:

```bash
cargo test --manifest-path cloud-run-transcoder/Cargo.toml
```

Expected: retry classification tests pass and existing transcription normalization tests still pass.

- [ ] **Step 6: Commit**

```bash
git add cloud-run-transcoder/src/main.rs
git commit -m "fix: retry rate-limited transcription requests"
```

### Task 2: Cap provider concurrency independent of HTTP concurrency

**Files:**
- Modify: `cloud-run-transcoder/src/main.rs`
- Modify: `cloud-run-transcoder/deploy.sh`
- Test: `cloud-run-transcoder/src/main.rs`

- [ ] **Step 1: Write a failing test for config parsing of provider concurrency settings**

Add tests for defaults and explicit env parsing, for example:
- `TRANSCRIPTION_MAX_IN_FLIGHT`
- `TRANSCRIPTION_MAX_RETRIES`
- `TRANSCRIPTION_RETRY_BASE_MS`
- `TRANSCRIPTION_RETRY_MAX_MS`

- [ ] **Step 2: Run transcoder tests to confirm new config tests fail**

Run:

```bash
cargo test --manifest-path cloud-run-transcoder/Cargo.toml config
```

Expected: missing fields or defaults fail the new assertions.

- [ ] **Step 3: Add a semaphore around the provider call path**

Requirements:
- store `tokio::sync::Semaphore` in app state
- acquire permit only for the upstream provider call, not for download or FFmpeg work
- log `in_flight` and wait duration for observability

- [ ] **Step 4: Lower Cloud Run request concurrency in deploy config**

Update `cloud-run-transcoder/deploy.sh` to:
- set `--concurrency` to a safe value such as `8` or `16`
- pass explicit env vars for provider concurrency and retry caps

- [ ] **Step 5: Re-run transcoder tests**

Run:

```bash
cargo test --manifest-path cloud-run-transcoder/Cargo.toml
```

Expected: config tests pass and no existing test regresses.

- [ ] **Step 6: Commit**

```bash
git add cloud-run-transcoder/src/main.rs cloud-run-transcoder/deploy.sh
git commit -m "fix: cap transcription provider concurrency"
```

### Task 3: Deduplicate duplicate `/transcribe` requests in Cloud Run

**Files:**
- Modify: `cloud-run-transcoder/src/main.rs`
- Test: `cloud-run-transcoder/src/main.rs`

- [ ] **Step 1: Write failing tests for lock-state decisions**

Add tests for a small lock-state helper:
- no lock -> start work
- fresh lock present -> return `already_processing`
- stale lock -> reclaim and continue

- [ ] **Step 2: Run transcoder tests to verify the new lock-state tests fail**

Run:

```bash
cargo test --manifest-path cloud-run-transcoder/Cargo.toml lock
```

Expected: missing lock helpers fail.

- [ ] **Step 3: Add a central transcript lock in GCS**

Design:
- use a per-hash object such as `{sha256}/vtt/.lock`
- write with create-if-absent semantics
- include timestamp and attempt metadata in the lock body
- reclaim only if the lock is older than a conservative stale threshold

Behavior:
- if lock acquisition fails because another worker owns it, return success with status `already_processing`
- do not call the provider when lock acquisition fails

- [ ] **Step 4: Release or rewrite the lock on terminal transitions**

Requirements:
- remove the lock on `complete`
- on retryable provider failure, keep cooldown data somewhere durable
- on non-retryable failure, release the lock and surface a stable failure code

- [ ] **Step 5: Re-run transcoder tests**

Run:

```bash
cargo test --manifest-path cloud-run-transcoder/Cargo.toml
```

Expected: lock tests pass and the binary still compiles cleanly.

- [ ] **Step 6: Commit**

```bash
git add cloud-run-transcoder/src/main.rs
git commit -m "fix: dedupe concurrent transcription requests"
```

## Chunk 2: Stop Blossom From Re-triggering the Same Failure

### Task 4: Extend transcript metadata with retry and error state

**Files:**
- Modify: `src/blossom.rs`
- Modify: `src/metadata.rs`
- Modify: `src/main.rs`
- Test: `src/main.rs`

- [ ] **Step 1: Add failing tests for transcript status parsing and state transitions**

Cover:
- webhook payload with `error_code`
- webhook payload with `retry_after`
- webhook payload with `provider_rate_limited`
- GET `/vtt` when cooldown is active

- [ ] **Step 2: Run Blossom tests to confirm the new cases fail**

Run:

```bash
cargo test
```

Expected: new transcript metadata assertions fail.

- [ ] **Step 3: Add transcript retry metadata fields**

Add small optional fields to `BlobMetadata`, for example:
- `transcript_error_code`
- `transcript_error_message`
- `transcript_last_attempt_at`
- `transcript_retry_after`

Update `handle_transcript_status` to persist them.

- [ ] **Step 4: Re-run Blossom tests**

Run:

```bash
cargo test
```

Expected: metadata parsing tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/blossom.rs src/metadata.rs src/main.rs
git commit -m "feat: persist transcript retry metadata"
```

### Task 5: Honor cooldowns and stop auto-retrying `Failed` work immediately

**Files:**
- Modify: `src/main.rs`
- Test: `src/main.rs`

- [ ] **Step 1: Add failing tests for `/vtt` trigger behavior**

Cover:
- `Processing` + missing VTT -> return `202 in progress`, no trigger
- `Failed` + future `retry_after` -> return `202`, no trigger
- `Pending` + no cooldown -> trigger once
- `Complete` + missing VTT -> allow one repair trigger only if cooldown expired

- [ ] **Step 2: Run Blossom tests to verify the new request-path tests fail**

Run:

```bash
cargo test transcript
```

Expected: GET `/vtt` behavior tests fail before implementation.

- [ ] **Step 3: Change `serve_transcript_by_hash` to respect cooldown metadata**

Requirements:
- only trigger if there is no active cooldown
- return `Retry-After` when cooldown is active
- do not convert every `Failed` state into an immediate new `/transcribe` call

- [ ] **Step 4: Preserve cache behavior but avoid lying about state**

Requirements:
- keep `no-cache` headers on `202`
- make response bodies distinguish `in_progress` from `cooling_down`

- [ ] **Step 5: Re-run Blossom tests**

Run:

```bash
cargo test
```

Expected: transcript-trigger tests pass and no unrelated tests regress.

- [ ] **Step 6: Commit**

```bash
git add src/main.rs
git commit -m "fix: honor transcript retry cooldowns"
```

### Task 6: Make transcript-status webhook failures non-fatal to state reconciliation

**Files:**
- Modify: `src/main.rs`
- Test: `src/main.rs`

- [ ] **Step 1: Add failing tests for webhook behavior on missing blob metadata**

Cases:
- unknown `sha256` should not return a hard 404 that causes endless worker retries
- retryable storage error should preserve enough information for later reconciliation

- [ ] **Step 2: Run Blossom tests to verify the new cases fail**

Run:

```bash
cargo test transcript_status
```

Expected: missing-blob webhook handling tests fail.

- [ ] **Step 3: Implement safer webhook semantics**

Recommended behavior:
- return `202 Accepted` for unknown blobs instead of `404`
- log structured reconciliation data
- do not encourage Cloud Run to re-hit the webhook in a tight loop

- [ ] **Step 4: Re-run Blossom tests**

Run:

```bash
cargo test
```

Expected: transcript-status tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "fix: soften transcript webhook reconciliation failures"
```

## Chunk 3: Make the App Wait for Ready Subtitles

### Task 7: Treat `202 Accepted` as "not ready yet", not "no subtitles"

**Files:**
- Modify: `/Users/rabble/code/divine/divine-mobile/mobile/lib/providers/subtitle_providers.dart`
- Modify: `/Users/rabble/code/divine/divine-mobile/mobile/test/providers/subtitle_providers_test.dart`

- [ ] **Step 1: Add failing mobile tests for Blossom `202` handling**

Add tests for:
- `202` with `Retry-After: 5` schedules a retry
- `404` still falls through to relay path
- `200` with VTT parses immediately
- repeated `202` stops after a bounded retry window

- [ ] **Step 2: Run the mobile subtitle provider tests and verify they fail**

Run:

```bash
cd /Users/rabble/code/divine/divine-mobile/mobile && flutter test test/providers/subtitle_providers_test.dart
```

Expected: the new `202` retry cases fail because the provider does only one fetch.

- [ ] **Step 3: Implement bounded polling using `Retry-After`**

Requirements:
- on `202`, wait for `Retry-After` or a sensible default
- retry while the provider instance is alive
- cap total wait time and attempt count
- keep existing relay fallback behavior

- [ ] **Step 4: Re-run the mobile subtitle provider tests**

Run:

```bash
cd /Users/rabble/code/divine/divine-mobile/mobile && flutter test test/providers/subtitle_providers_test.dart
```

Expected: subtitle provider tests pass.

- [ ] **Step 5: Commit**

```bash
git -C /Users/rabble/code/divine/divine-mobile add mobile/lib/providers/subtitle_providers.dart mobile/test/providers/subtitle_providers_test.dart
git -C /Users/rabble/code/divine/divine-mobile commit -m "fix: retry pending subtitle fetches"
```

## Chunk 4: Backfill and Verify

### Task 8: Backfill recent videos missing `vtt/main.vtt`

**Files:**
- Create: `scripts/backfill_missing_transcripts.sh`
- Modify: `README.md` or operational docs if a better location already exists

- [ ] **Step 1: Write the backfill script**

Requirements:
- enumerate recent transcribable hashes missing `{sha256}/vtt/main.vtt`
- enqueue work at a controlled rate
- log successes, duplicates, and permanent failures separately

- [ ] **Step 2: Dry-run the script against a small sample**

Run:

```bash
bash scripts/backfill_missing_transcripts.sh --dry-run --limit 20
```

Expected: lists candidate hashes without triggering provider work.

- [ ] **Step 3: Run the bounded backfill after Cloud Run and Blossom fixes are deployed**

Run:

```bash
bash scripts/backfill_missing_transcripts.sh --limit 200 --sleep 2
```

Expected: recent hashes begin producing `vtt/main.vtt` without flooding the provider.

- [ ] **Step 4: Commit**

```bash
git add scripts/backfill_missing_transcripts.sh README.md
git commit -m "chore: add transcript backfill tooling"
```

### Task 9: Verify production recovery in the right order

**Files:**
- No code changes required

- [ ] **Step 1: Deploy Cloud Run fixes first**

Success checks:
- `/transcribe` 500 rate drops sharply
- `Transcription provider returned 429` logs stop dominating
- duplicate `Starting transcription for <same hash>` bursts disappear

- [ ] **Step 2: Deploy Blossom cooldown and webhook fixes**

Success checks:
- repeated GETs to `/{sha256}/vtt` return stable `202` with `Retry-After`
- the same hash is not re-enqueued on every request

- [ ] **Step 3: Deploy mobile polling fix**

Success checks:
- captions appear on videos whose transcript completes after playback begins
- app no longer freezes "empty cues" after the first `202`

- [ ] **Step 4: Confirm end-to-end on one old-bad hash and one fresh upload**

Verify:
- fresh upload gets VTT within the expected window
- a formerly broken hash eventually transitions from `202` to `200`
- cue-bearing VTT is visible in-app after the transcript becomes ready

- [ ] **Step 5: Document remaining follow-up**

Track separately if still needed:
- intermittent `ffmpeg audio extraction failed`
- transcript webhook reconciliation for hashes unknown to Blossom
- optional move to a proper queue such as Cloud Tasks if burst load remains high

## Recommended Execution Order

1. Chunk 1 first. This is the outage stop.
2. Chunk 2 second. This removes the retry amplifier at the edge.
3. Chunk 3 third. This fixes the user-visible CC behavior during normal async processing.
4. Chunk 4 last. This repairs already-broken uploads after the pipeline is stable.

## Notes For The Implementer

- OpenAI’s official rate-limit guidance explicitly expects clients to handle `429` with retry/backoff, and their model pages document rate limits by usage tier. The March 10 production cliff matches that pattern.
- Do not ship only the mobile retry fix. It improves symptoms for `202`, but it does not solve provider saturation or duplicate worker starts.
- Do not ship only provider backoff. Without duplicate suppression and Blossom cooldowns, the edge will keep creating needless work.

Plan complete and saved to `docs/superpowers/plans/2026-03-14-subtitle-transcription-reliability.md`. Ready to execute?
