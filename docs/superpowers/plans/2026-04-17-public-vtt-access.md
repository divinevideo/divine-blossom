# Public VTT Access Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make transcript routes public so WebVTT files never return `401 age_restricted`, while preserving existing moderation concealment for non-public statuses.

**Architecture:** Keep the change narrow to transcript routes in `divine-blossom`. Raw media, HLS, audio, and quality variants should continue using the normal blob viewer-auth policy, but transcript routes should stop inheriting `AgeRestricted` gating from `BlobMetadata::access_for`. Under this plan, VTT is public for `Active`, `Pending`, and `AgeRestricted`, while `Restricted`, `Banned`, and `Deleted` still remain hidden via `404`.

**Tech Stack:** Rust, Fastly Compute, existing Blossom moderation model, unit tests in `src/main.rs`

---

## File Map

- Modify: `src/main.rs`
  Purpose: transcript GET/HEAD handlers currently call `metadata.access_for(...)` and surface `401 age_restricted`; this is the primary policy change site.
- Optionally modify: `src/blossom.rs`
  Purpose: only if extracting a small transcript-specific access helper makes the policy easier to test and reuse cleanly.
- Modify: `README.md`
  Purpose: document that transcript routes are public and no longer require viewer auth for age-restricted media.
- Test: `src/main.rs` unit test module
  Purpose: add pure policy tests for transcript visibility by status so the VTT behavior stays stable.

## Chunk 1: Isolate Transcript Visibility Policy

### Task 1: Add a transcript-specific access decision with failing tests first

**Files:**
- Modify: `src/main.rs`
- Optionally modify: `src/blossom.rs`

- [ ] **Step 1: Write the failing policy tests**

Add unit tests that prove transcript visibility behaves like this:
- `Active` transcript: public
- `Pending` transcript: public
- `AgeRestricted` transcript: public
- `Restricted` transcript: hidden
- `Banned` transcript: hidden
- `Deleted` transcript: hidden

Prefer a pure helper test over a route test if Fastly request construction would make the test brittle.

- [ ] **Step 2: Run the focused tests and verify they fail**

Run: `cd /Users/rabble/code/divine/divine-blossom && cargo test transcript`

Expected: FAIL because transcript routes still inherit `AgeGated` behavior from `metadata.access_for(...)`.

- [ ] **Step 3: Implement a transcript-specific policy helper**

Introduce a small helper with one job:
- input: `BlobStatus`
- output: public transcript allowed vs hidden

Keep the helper narrow. Do not change `BlobMetadata::access_for(...)`, because that logic still correctly governs raw media and HLS.

If the helper fits naturally in `src/main.rs`, keep it there. Only move it into `src/blossom.rs` if that clearly improves reuse and testability without spreading transcript policy across multiple files.

- [ ] **Step 4: Re-run the focused policy tests**

Run: `cd /Users/rabble/code/divine/divine-blossom && cargo test transcript`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/rabble/code/divine/divine-blossom
git add src/main.rs src/blossom.rs
git commit -m "feat(transcript): make age-restricted vtt public"
```

## Chunk 2: Rewire Transcript GET and HEAD Routes

### Task 2: Stop transcript handlers from returning `401 age_restricted`

**Files:**
- Modify: `src/main.rs:1460-1660`

- [ ] **Step 1: Write failing route-behavior tests**

Add tests covering the transcript route behavior at the policy layer, including:
- transcript GET path no longer returns `AuthRequired(\"age_restricted\")` for `AgeRestricted`
- transcript HEAD path no longer returns `AuthRequired(\"age_restricted\")` for `AgeRestricted`
- transcript routes still return `NotFound` for `Restricted`

If direct route tests are awkward, add narrowly-scoped helper tests that prove the route branches cannot produce `AgeGated` for transcripts anymore.

- [ ] **Step 2: Run the focused tests and verify they fail**

Run: `cd /Users/rabble/code/divine/divine-blossom && cargo test vtt`

Expected: FAIL because:
- `serve_transcript_by_hash(...)` currently calls `metadata.access_for(...)` at `src/main.rs:1477`
- `handle_head_transcript_by_hash(...)` currently calls `metadata.access_for(None, false)` at `src/main.rs:1618`

- [ ] **Step 3: Update `serve_transcript_by_hash(...)`**

Replace the transcript route’s moderation gate with the transcript-specific helper from Chunk 1.

Requirements:
- never return `AuthRequired(\"age_restricted\")` for transcript routes
- keep `Restricted`, `Banned`, and `Deleted` hidden as `NotFound`
- keep transcription generation, repair, retry, and terminal-failure behavior unchanged
- keep existing `text/vtt` content type and on-demand generation behavior unchanged

- [ ] **Step 4: Update `handle_head_transcript_by_hash(...)`**

Mirror the same transcript visibility policy in HEAD handling so HEAD and GET stay consistent.

Requirements:
- no `401 age_restricted`
- same hidden statuses as GET
- same existing `202`/`422`/`200` semantics for transcript generation state

- [ ] **Step 5: Re-run the focused transcript tests**

Run:
- `cd /Users/rabble/code/divine/divine-blossom && cargo test transcript`
- `cd /Users/rabble/code/divine/divine-blossom && cargo test vtt`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/rabble/code/divine/divine-blossom
git add src/main.rs
git commit -m "fix(transcript): bypass age gate on public vtt routes"
```

## Chunk 3: Caching and Documentation

### Task 3: Make sure public VTT behavior is documented and cache semantics stay coherent

**Files:**
- Modify: `src/main.rs`
- Modify: `README.md`

- [ ] **Step 1: Verify transcript cache headers still match the new policy**

Inspect the transcript response branches in `serve_transcript_by_hash(...)` and `handle_head_transcript_by_hash(...)`.

Confirm the intended behavior:
- VTT stays cacheable as public content for `Active`, `Pending`, and `AgeRestricted`
- no private-cache requirement remains for `AgeRestricted` VTT

If any branch still conditions transcript cacheability on `metadata.status.requires_private_cache()`, remove that dependency for transcript routes only.

- [ ] **Step 2: Document the contract**

Update `README.md` so it explicitly states:
- transcript routes `/{sha256}.vtt` and `/{sha256}/vtt` are public
- age-restricted media may still require viewer auth for playback routes
- transcript routes do not use the age-gated viewer-auth contract

- [ ] **Step 3: Run the relevant tests**

Run:
- `cd /Users/rabble/code/divine/divine-blossom && cargo test transcript`
- `cd /Users/rabble/code/divine/divine-blossom && cargo test --lib`

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
cd /Users/rabble/code/divine/divine-blossom
git add src/main.rs README.md
git commit -m "docs(transcript): record public vtt access policy"
```

## Chunk 4: Final Verification

### Task 4: Prove the new transcript contract without touching playback routes

**Files:**
- No additional code changes expected

- [ ] **Step 1: Run final verification**

Run:
- `cd /Users/rabble/code/divine/divine-blossom && cargo test --lib`
- `cd /Users/rabble/code/divine/divine-blossom && cargo check --target wasm32-wasi`

Expected:
- tests pass
- `cargo check` passes, allowing for pre-existing warnings only

- [ ] **Step 2: Summarize the behavioral contract in the PR description**

Include this exact contract:
- `/{sha256}.vtt` and `/{sha256}/vtt` are public
- they never return `401 {"error":"age_restricted"}`
- `Restricted`, `Banned`, and `Deleted` transcript routes still return `404`
- raw media, HLS, audio, and quality variants still use the normal blob access policy

- [ ] **Step 3: Commit if any verification-driven tweaks were needed**

```bash
cd /Users/rabble/code/divine/divine-blossom
git add README.md src/main.rs src/blossom.rs
git commit -m "test(transcript): lock public vtt policy"
```

