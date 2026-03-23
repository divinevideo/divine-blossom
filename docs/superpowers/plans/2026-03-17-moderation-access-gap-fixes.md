# Moderation Access Gap Fixes Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the remaining moderation bypasses in HLS and thumbnail HEAD serving, and restore owner/admin access for restricted subtitle-by-hash lookups without changing banned/deleted behavior.

**Architecture:** Keep the existing `BlobStatus` helper methods as the source of truth, but add one small access-policy helper in `src/main.rs` so the route handlers stop re-encoding moderation rules inline. Use that helper before any GCS existence or download check on leak-prone routes. Preserve the current policy split: `Banned` and `Deleted` always 404, `Restricted` stays owner/admin-visible on authenticated GET routes, and unauthenticated HEAD routes stay opaque for all moderated content.

**Tech Stack:** Fastly Compute Rust, existing auth helpers in `src/auth.rs`, blob metadata in `src/blossom.rs`, `cargo test`

---

## File Map

- Modify: `src/main.rs`
  - Add a small, pure moderation access helper for route handlers.
  - Apply the helper to `handle_get_hls_content`, `handle_head_blob` thumbnail handling, and `handle_get_subtitle_by_hash`.
  - Add unit tests for the access matrix and the route-specific policy choices.
- Reuse only:
  - `BlobStatus::blocks_public_access`
  - `BlobStatus::requires_owner_auth`
  - `admin::validate_bearer_token`
  - `optional_auth`

## Scope Notes

- Do not refactor unrelated content handlers in this pass.
- Do not change the external API shape or status codes outside the three reported gaps.
- Do not weaken the current HEAD behavior: restricted content should still 404 on HEAD because there is no authenticated request context on those routes.

## Chunk 1: Centralize the Moderation Access Decision

### Task 1: Add a focused access-policy helper and test the status matrix

**Files:**
- Modify: `src/main.rs`
- Test: `src/main.rs`

- [ ] **Step 1: Add failing unit tests for the moderation access matrix**

Add a `#[cfg(test)] mod tests` block in `src/main.rs` if the branch does not already have one, or extend the existing one if it does.

Cover these cases with small pure tests:
- `Banned` blocks public GET access
- `Deleted` blocks public GET access
- `Restricted` allows owner-visible GET access when `is_owner = true`
- `Restricted` allows owner-visible GET access when `is_admin = true`
- `Restricted` blocks owner-visible GET access when `is_owner = false` and `is_admin = false`
- `Restricted` blocks opaque HEAD access even if the blob owner would otherwise be allowed on GET
- `Active` and `Pending` stay publicly visible

- [ ] **Step 2: Run the focused test target to confirm it fails**

Run:

```bash
cargo test moderation_access
```

Expected: FAIL because the new helper and tests do not exist yet.

- [ ] **Step 3: Implement the pure helper**

Add a small helper near the existing access-control code in `src/main.rs`, for example:
- an enum describing route policy, such as `PublicGet`, `OwnerOrAdminGet`, and `OpaqueHead`
- a pure function that takes `BlobStatus`, `is_admin`, `is_owner`, and the route policy and returns allow/deny

Requirements:
- use `blocks_public_access()` for banned/deleted decisions
- use `requires_owner_auth()` for restricted decisions
- keep `Active` and `Pending` open
- avoid embedding route-specific strings or HTTP response construction in the pure helper

- [ ] **Step 4: Re-run the focused tests**

Run:

```bash
cargo test moderation_access
```

Expected: PASS for the new access-matrix tests.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "test: codify moderation access policy"
```

## Chunk 2: Fix the Two Remaining Existence Leaks

### Task 2: Enforce moderation before any HLS object read

**Files:**
- Modify: `src/main.rs`
- Test: `src/main.rs`

- [ ] **Step 1: Add failing tests for the HLS route policy choices**

Add small unit tests that describe the intended policy for `GET /{hash}/hls/*`:
- banned and deleted return deny
- restricted returns allow only when the caller is owner or admin
- active and pending return allow

These can reuse the pure helper from Task 1 with a route policy dedicated to HLS GET.

- [ ] **Step 2: Run the focused HLS tests and confirm the branch fails**

Run:

```bash
cargo test hls_access
```

Expected: FAIL until the HLS handler is switched to the shared policy helper.

- [ ] **Step 3: Move the moderation check to the top of `handle_get_hls_content`**

Implementation requirements:
- fetch blob metadata before the initial `download_hls_content(&gcs_path, None)` call
- if metadata is missing, return the existing `404`
- compute `is_admin` once from the request
- if status is `Restricted`, allow only owner or admin
- if status is `Banned` or `Deleted`, return `404` before any GCS lookup
- reuse the same decision path in both the success path and the `master.m3u8` fallback path so the logic cannot diverge again

- [ ] **Step 4: Re-check the fallback branch for restricted handling**

Verify in code review that the fallback branch no longer only checks `blocks_public_access()`.

Requirements:
- restricted blobs must not re-trigger transcoding for unauthenticated callers
- restricted owners and admins must still receive the existing `202/Retry-After` behavior when HLS is not ready yet

- [ ] **Step 5: Add failing tests for thumbnail HEAD opacity**

Add tests describing the thumbnail HEAD rule:
- a thumbnail for restricted, banned, or deleted content must return deny under opaque HEAD policy
- active and pending thumbnails remain visible

- [ ] **Step 6: Run the focused thumbnail tests and confirm failure**

Run:

```bash
cargo test thumbnail_head_access
```

Expected: FAIL until the thumbnail branch in `handle_head_blob` uses the shared policy helper.

- [ ] **Step 7: Apply the same opaque HEAD policy to `HEAD /{hash}.jpg`**

Implementation requirements:
- look up the parent blob metadata before `download_thumbnail(&thumbnail_key)?`
- preserve the existing response headers and cache behavior for allowed thumbnails
- keep the route unauthenticated; do not add owner auth support to HEAD

- [ ] **Step 8: Re-run the focused tests**

Run:

```bash
cargo test hls_access
cargo test thumbnail_head_access
```

Expected: PASS for the new HLS and thumbnail tests.

- [ ] **Step 9: Commit**

```bash
git add src/main.rs
git commit -m "fix: close hls and thumbnail moderation leaks"
```

## Chunk 3: Restore Restricted Subtitle Lookup Semantics

### Task 3: Make subtitle-by-hash match transcript GET access rules

**Files:**
- Modify: `src/main.rs`
- Test: `src/main.rs`

- [ ] **Step 1: Add failing tests for subtitle-by-hash access**

Add unit tests covering:
- banned and deleted are denied
- restricted is denied for unauthenticated callers
- restricted is allowed for owner-visible GET policy
- restricted is allowed for admin-visible GET policy
- active and pending remain visible

These tests should describe the same access contract already used by `serve_transcript_by_hash`.

- [ ] **Step 2: Run the focused subtitle tests and confirm failure**

Run:

```bash
cargo test subtitle_by_hash_access
```

Expected: FAIL because the current handler hard-blocks `Restricted` before checking owner/admin context.

- [ ] **Step 3: Update `handle_get_subtitle_by_hash` to mirror transcript access**

Implementation requirements:
- compute `is_admin` from the request
- if metadata is `Restricted`, allow only owner or admin
- if metadata is `Banned` or `Deleted`, return the existing `404`
- perform the moderation check before returning an existing subtitle job and before synthesizing a ready job from `transcript_status == Complete`
- keep the existing response body shape and status codes

- [ ] **Step 4: Compare the branch against `serve_transcript_by_hash`**

Verify the subtitle-by-hash access behavior matches transcript GET behavior for:
- admin bearer access
- owner-authenticated restricted access
- unauthenticated restricted denial
- banned/deleted denial

- [ ] **Step 5: Re-run the focused subtitle tests**

Run:

```bash
cargo test subtitle_by_hash_access
```

Expected: PASS for the new subtitle access tests.

- [ ] **Step 6: Commit**

```bash
git add src/main.rs
git commit -m "fix: restore restricted subtitle lookup access"
```

## Chunk 4: Full Verification and Review

### Task 4: Run full Blossom verification before review

**Files:**
- Modify: none
- Test: `src/main.rs`, `src/blossom.rs`

- [ ] **Step 1: Run the full test suite**

Run:

```bash
cargo test
```

Expected: PASS with the new moderation regression tests included.

- [ ] **Step 2: Inspect the final diff for drift**

Run:

```bash
git diff --stat
git diff -- src/main.rs
```

Expected:
- only `src/main.rs` changes unless a branch-specific test module location forces a second file
- no unrelated access-control routes changed

- [ ] **Step 3: Request code review**

Use the local review workflow and explicitly ask the reviewer to verify:
- HLS moderation now runs before any GCS fetch
- thumbnail HEAD no longer leaks moderated content
- subtitle-by-hash preserves owner/admin access for restricted blobs

- [ ] **Step 4: Prepare merge after review**

If review passes and `cargo test` stays green, proceed with the normal branch-finishing workflow.
