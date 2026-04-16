# Media Request Auth Observability Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add targeted ingress diagnostics for media routes so one failing age-restricted request can be traced through auth presence, NIP-98 validation, and access outcome.

**Architecture:** Keep the existing viewer auth contract intact, but introduce a small auth-diagnostics helper that classifies media request auth without logging secrets. Route handlers will log one structured line containing method, path, host, auth presence, normalized request URL, validation result, and access decision before returning. This keeps the change scoped to observability rather than policy changes.

**Tech Stack:** Rust, Fastly Compute, existing auth helpers in `src/auth.rs`, viewer auth validation in `src/viewer_auth.rs`, media handlers in `src/main.rs`.

---

## Chunk 1: Auth Diagnostics Helper

### Task 1: Add failing auth diagnostics tests

**Files:**
- Modify: `src/auth.rs`

- [ ] **Step 1: Write failing tests for diagnostics classification**

Add unit tests covering:
- no Authorization header => `auth_present=false`, `auth_state=missing`
- malformed Authorization header => `auth_present=true`, `auth_state=invalid_scheme`
- valid NIP-98 header => `auth_present=true`, `auth_state=valid`, includes normalized request URL and pubkey
- URL/method mismatch => `auth_present=true`, `auth_state=validation_failed`

- [ ] **Step 2: Run the focused auth tests and confirm they fail**

Run: `cargo test --lib auth::tests::`
Expected: FAIL because diagnostics helper/types do not exist yet.

- [ ] **Step 3: Implement minimal diagnostics helper**

Add a helper that:
- accepts a `Request`
- records method/path/host and whether `Authorization` exists
- normalizes the request URL the same way viewer auth validation does
- validates viewer auth without logging secrets
- returns both the existing pubkey result and a diagnostics struct suitable for logging

- [ ] **Step 4: Re-run the focused auth tests**

Run: `cargo test --lib auth::tests::`
Expected: PASS

## Chunk 2: Media Route Logging

### Task 2: Log auth and access outcome on media GET routes

**Files:**
- Modify: `src/main.rs`
- Test: `src/main.rs`

- [ ] **Step 5: Write failing tests for the structured log formatter**

Add unit tests for a pure formatter/helper covering:
- anonymous auth diagnostics + `AgeGated` access outcome
- valid viewer auth + `Allowed` outcome
- validation failure + auth error outcome

- [ ] **Step 6: Run the focused formatter tests and confirm they fail**

Run: `cargo test --lib main::tests::`
Expected: FAIL because the formatter/helper does not exist yet.

- [ ] **Step 7: Implement structured media auth logging**

Wire the diagnostics helper into the GET media handlers that can return `age_restricted`:
- direct blob / thumbnail
- HLS master / HLS content
- transcript / subtitle by hash
- audio / quality variant

For each request, log one structured line with:
- route name
- method
- path
- host
- auth_present
- auth_state
- normalized_request_url
- viewer_pubkey_present
- access outcome or auth error

Do not log raw `Authorization` headers, signatures, or full events.

- [ ] **Step 8: Re-run the focused formatter tests**

Run: `cargo test --lib main::tests::`
Expected: PASS

## Chunk 3: Verification

### Task 3: Verify the repo still builds and tests cleanly

**Files:**
- Modify: none unless small doc wording is needed

- [ ] **Step 9: Run targeted verification**

Run:
- `cargo test --lib auth::tests::`
- `cargo test --lib main::tests::`

Expected: PASS

- [ ] **Step 10: Run broader verification**

Run:
- `cargo test --lib`

Expected: PASS
