# Media Age Auth Debug Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make blossom authenticate the media requests the web client actually sends, stop silently downgrading bad auth to anonymous, and lock in the intended age-gate contract with regression coverage.

**Architecture:** `divine-web` sends NIP-98 HTTP auth (`kind 27235`) for media fetches, but blossom currently only accepts Blossom auth (`kind 24242`) and most media routes ignore auth-validation errors by calling `optional_auth(...).ok().flatten()`. The fix is to centralize viewer auth parsing for media/list routes, accept both Blossom list auth and valid NIP-98 auth, and change `BlobStatus::AgeRestricted` to mean "any authenticated viewer" while preserving `Restricted` as the owner/admin-only shadow-ban path.

**Tech Stack:** Rust, Fastly Compute, existing auth helpers in `src/auth.rs`, media route handlers in `src/main.rs`, blob access policy in `src/blossom.rs`.

---

## Chunk 1: Viewer Auth Contract

### Task 1: Add failing auth-mode tests

**Files:**
- Modify: `src/auth.rs`

- [ ] **Step 1: Write failing tests for viewer auth parsing**

Add unit tests that prove:
- a valid Blossom list event is accepted
- a valid NIP-98 GET event is accepted for the matching URL/method
- a NIP-98 event with the wrong URL or method is rejected
- a `kind 27235` event is not treated as anonymous when an auth header is present but invalid

- [ ] **Step 2: Run the focused test target and confirm it fails for the intended reason**

Run: `cargo test --lib`

Expected: new auth tests fail because auth only supports `kind 24242`.

### Task 2: Implement dual-mode viewer auth

**Files:**
- Modify: `src/auth.rs`

- [ ] **Step 3: Add a viewer-auth helper**

Implement a helper that:
- returns `Ok(None)` when no `Authorization` header is present
- validates Blossom list auth (`kind 24242`, `t=list`) when present
- validates NIP-98 auth (`kind 27235`) for the exact absolute URL and HTTP method when present
- returns an error instead of `None` when auth is present but invalid

- [ ] **Step 4: Re-run the focused auth tests**

Run: `cargo test --lib`

Expected: auth tests pass.

## Chunk 2: Route Wiring

### Task 3: Route media fetches through strict viewer auth

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 5: Write failing pure tests around route auth decisions**

Add tests for the route-facing auth helper / access decision layer covering:
- no auth header on age-restricted content => `age_restricted`
- invalid auth header => auth error, not anonymous fallback
- valid NIP-98 auth for non-owner age-restricted content => allowed
- valid auth for owner/admin => allowed

- [ ] **Step 6: Run the focused test target and confirm the invalid-auth case fails first**

Run: `cargo test --lib`

Expected: invalid-auth case still behaves like anonymous before the fix.

- [ ] **Step 7: Replace `optional_auth(...).ok().flatten()` on viewer/media routes**

Wire the blob, thumbnail, HLS, transcript, subtitles-by-hash, audio, and quality-variant GET routes through the new strict viewer-auth helper.

- [ ] **Step 8: Re-run the focused test target**

Run: `cargo test --lib`

Expected: new auth-routing tests pass.

## Chunk 3: Verification And Contract

### Task 4: Verify the supported build/test commands and capture the contract

**Files:**
- Modify: `README.md` if auth contract text needs correction

- [ ] **Step 9: Run supported verification commands**

Run:
- `cargo test --lib`
- `cargo check --target wasm32-wasi`

Expected:
- unit tests pass
- wasm target compiles cleanly for the Fastly service

- [ ] **Step 10: Update docs if needed**

Document that:
- blossom accepts Blossom auth and NIP-98 for viewer/list requests
- `BlobStatus::AgeRestricted` serves any authenticated viewer while anonymous requests get `401 age_restricted`
- `BlobStatus::Restricted` remains owner/admin-only and 404s for everyone else
- blossom does not currently inspect hosted-session age claims or any viewer adult-verification service
