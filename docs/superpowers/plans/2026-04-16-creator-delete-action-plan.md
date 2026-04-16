# Blossom `DELETE` Action Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire a `DELETE` action into Blossom's `/admin/api/moderate` endpoint that dispatches to a shared physical-delete helper extracted from the existing admin DMCA cascade. Gate the destructive step on a new `ENABLE_PHYSICAL_DELETE` config flag (default off) so the first production deploy is inert.

**Architecture:** Extract `perform_physical_delete(hash, actor, reason, legal_hold)` from `handle_admin_force_delete` into a shared helper. Both admin DMCA (unconditional) and creator-delete (flag-gated) call it. Creator-delete ingress stays on the existing `/admin/api/moderate` endpoint so moderation-service's single call pattern is preserved.

**Tech Stack:** Rust on Fastly Compute (WASM), `fastly` crate, `serde_json`. Tests via inline `#[cfg(test)] mod tests` — standard Rust pattern. Local dev via MinIO + `fastly compute serve`.

**Spec:** `docs/superpowers/specs/2026-04-16-creator-delete-action-design.md` on this branch.

---

## File Structure

**Files to modify:**
- `src/main.rs` — extract `perform_physical_delete` helper (~55 lines moved from `handle_admin_force_delete`), update `handle_admin_force_delete` to call it.
- `src/admin.rs` — add `reason` field to `ModerateRequest` struct, wire `DELETE` action dispatch with `ENABLE_PHYSICAL_DELETE` flag check.
- `config-store-data.json` — add `ENABLE_PHYSICAL_DELETE = "false"` for local dev.

**Files to create:**
- None. Tests live alongside production code in `#[cfg(test)]` modules within the modified files.

---

## Guardrails — do not do these without checkpointing with Matt first

### Scope

- Do not add new dependencies in `Cargo.toml`.
- Do not refactor any file not listed above.
- Do not modify `handle_admin_force_delete`'s behavior — only its internals (extract to helper; caller is equivalent).
- Do not change the auth path on `/admin/api/moderate`. Existing Bearer auth (admin_token OR webhook_secret) remains.
- Do not modify `BlobStatus` enum. `Deleted` already exists.
- Do not change any existing tests. Add new tests; don't reshape existing.
- Do not change the Fastly Purge logic (`purge_vcl_cache`). Reuse it verbatim.
- Do not add new logging beyond the eprintln lines specified in the spec.

### Safety measures — DO NOT REMOVE OR SIMPLIFY

These are required by the spec:

- `ENABLE_PHYSICAL_DELETE` flag check in the creator-delete DELETE branch. Flag off → status flip only, return `physical_delete_skipped: true`.
- `actor: "creator_delete"` passed to `perform_physical_delete` (and `"admin"` from the force-delete endpoint). This is the audit-log distinguisher.
- `legal_hold: false` on the creator-delete ingress (creator re-upload is not blocked).
- Failure of `perform_physical_delete` is logged but does NOT block the 200 response — the status flip is the load-bearing compliance guarantee.
- `get_config("ENABLE_PHYSICAL_DELETE")` comparison uses `eq_ignore_ascii_case` on the value OR exact `== Some("true")`; pick ONE and be consistent. The spec uses `as_deref() == Some("true")` — follow it.

### When in doubt

Stop and ask. A checkpoint question is cheaper than reverting a commit.

---

## Per-task review checklist (orchestrator uses this on every subagent output)

- [ ] Tests written before implementation (visible in git history or commit body).
- [ ] `cargo test` passes all tests (existing + new).
- [ ] `cargo build --target wasm32-wasi --release` succeeds (or the repo's documented build command).
- [ ] No new dependencies in `Cargo.toml`.
- [ ] No files touched outside the task's "Files" list.
- [ ] Safety measures from Guardrails present and unaltered.
- [ ] Existing `handle_admin_force_delete` test (if any) still passes after the refactor — behavior equivalence.
- [ ] Commit message follows existing Blossom convention (check `git log --oneline -10` on main for style; no Claude attribution).
- [ ] Rust doc comments on new public/pub(crate) functions.

### Red flags to escalate

- Subagent adds a dependency, refactors an unrelated file, or changes `BlobStatus`.
- `handle_admin_force_delete`'s tests or behavior change beyond the extraction.
- The DELETE branch returns anything other than 200 on status-flip-only or full-cascade success.
- The flag check is bypassed, inverted, or gated on the wrong value.

---

## Staging Preflight

- [ ] **Build works at baseline.** `cargo build --target wasm32-wasi --release` on the current branch (before any changes) succeeds. Note the current Fastly CLI version (`fastly version`) — the local dev loop wants ≥14.0.4.

- [ ] **Local dev loop operational.** `docker compose -f docker-compose.local.yml up minio minio-init -d` starts MinIO on :9000. `cp fastly.toml.local fastly.toml` then `fastly compute serve` brings Blossom up on :7676. `curl http://localhost:7676/admin/api/stats -H 'Authorization: Bearer <admin_token>'` returns 200 (admin auth configured for local).

- [ ] **Existing DELETE action confirms baseline.** `curl -X POST http://localhost:7676/admin/api/moderate -H 'Content-Type: application/json' -H 'Authorization: Bearer <admin_token>' -d '{"sha256":"aaaa...","action":"DELETE"}'` returns `400 Unknown action: DELETE`. This is the state this PR changes.

- [ ] **Existing `handle_admin_force_delete` works.** `curl -X POST http://localhost:7676/admin/api/delete -d '{"sha256":"...","reason":"preflight"}'` against a test blob shows the existing cascade. Record the response shape so the refactor in Task 1 can be verified equivalent.

Any preflight failure is a redirect signal.

---

## Task 1: Extract `perform_physical_delete` helper

**Files:**
- Modify: `src/main.rs`

Refactor `handle_admin_force_delete` (currently ~89 lines, `main.rs:3152-3240`) so its cascade body lives in a new `pub(crate) fn perform_physical_delete(...)` called by the handler. Behavior must be equivalent.

- [ ] **Step 1: Locate the current function**

    ```bash
    grep -n "^fn handle_admin_force_delete\|^pub fn handle_admin_force_delete" src/main.rs
    ```

    Confirm the line range (should be roughly 3152-3240). Read it top-to-bottom to understand the flow.

- [ ] **Step 2: Add `perform_physical_delete` above `handle_admin_force_delete`**

    Insert the helper verbatim from the spec (Component 1 code block). Signature:

    ```rust
    pub(crate) fn perform_physical_delete(
        hash: &str,
        actor: &str,
        reason: &str,
        legal_hold: bool,
    ) -> Result<()> { /* body */ }
    ```

    The body mirrors `handle_admin_force_delete`'s cascade exactly (from "Get metadata before deletion for audit" through "Purge VCL cache"), with `actor` parameterized (was hardcoded `"admin_delete"` / `"admin"`).

- [ ] **Step 3: Update `handle_admin_force_delete` to call the helper**

    Replace the extracted body (between "Get metadata before deletion for audit" and "Purge VCL cache" inclusive) with a single call:

    ```rust
    perform_physical_delete(&hash, "admin", reason, legal_hold)?;
    ```

    The surrounding code (hash validation, response construction) stays as-is.

- [ ] **Step 4: Build and verify existing tests pass**

    ```bash
    cargo build --target wasm32-wasi --release
    cargo test
    ```

    Expected: build succeeds, all existing tests pass. The refactor is behavior-equivalent — any test failure here indicates we dropped something in the move.

- [ ] **Step 5: Manual equivalence check against preflight baseline**

    If you captured a response shape from the preflight `handle_admin_force_delete` call, compare the post-refactor response. Should match field-for-field.

- [ ] **Step 6: Commit**

    ```bash
    git add src/main.rs
    git commit -m "refactor: extract perform_physical_delete helper from handle_admin_force_delete"
    ```

---

## Task 2: Add optional `reason` to `ModerateRequest`

**Files:**
- Modify: `src/admin.rs`

The creator-delete ingress will eventually want to pass a reason for audit purposes. Struct extension is minimal and safe — existing callers that omit `reason` continue to work via `Option<String>`.

- [ ] **Step 1: Update the struct**

    Find `struct ModerateRequest` in `src/admin.rs` (around line 728-732). Change from:

    ```rust
    #[derive(Deserialize)]
    struct ModerateRequest {
        sha256: String,
        action: String,
    }
    ```

    to:

    ```rust
    #[derive(Deserialize)]
    struct ModerateRequest {
        sha256: String,
        action: String,
        #[serde(default)]
        reason: Option<String>,
    }
    ```

- [ ] **Step 2: Build**

    ```bash
    cargo build --target wasm32-wasi --release
    ```
    Expected: succeeds. No callers changed; `reason` defaults to `None`.

- [ ] **Step 3: Commit**

    ```bash
    git add src/admin.rs
    git commit -m "feat(admin): accept optional reason field in ModerateRequest"
    ```

---

## Task 3: Wire DELETE action with `ENABLE_PHYSICAL_DELETE` flag check

**Files:**
- Modify: `src/admin.rs`

Add the new action to `BLOSSOM_ACTION_MAP` (implicit via the match in `handle_admin_moderate_action`) and dispatch to `perform_physical_delete` when the flag is on.

- [ ] **Step 1: Write the failing test first**

    Add to `src/admin.rs` inside the existing `#[cfg(test)] mod tests` block:

    ```rust
    #[test]
    fn test_delete_action_with_flag_off_returns_physical_delete_skipped() {
        // Build a ModerateRequest with action "DELETE"
        // Mock get_config to return None for ENABLE_PHYSICAL_DELETE
        // Call handle_admin_moderate_action
        // Assert: 200 status, body contains physical_delete_skipped: true,
        //         blob status updated to Deleted.
        todo!("build minimal viceroy mocks or use real local fastly dev harness");
    }

    #[test]
    fn test_delete_action_with_flag_on_invokes_physical_delete() {
        // Mock get_config to return Some("true") for ENABLE_PHYSICAL_DELETE
        // Call handle_admin_moderate_action with action "DELETE"
        // Assert: 200 status, body contains physical_deleted: true
        // Assert: audit log written with actor="creator_delete"
        todo!("same mocking as above");
    }
    ```

    These are marked `todo!()` to serve as failing-test stubs. If the repo has a mocking harness for `get_config` + storage, expand them. Otherwise, replace `todo!()` with integration tests via local `fastly compute serve` driven by a test script.

    **Fallback if Viceroy/Rust mocking is too heavy:** run the test cases manually via `curl` in the preflight loop and document results in the commit body. Rust mocks for `fastly::config_store` are non-trivial; pragmatic manual verification is acceptable for this narrowly-scoped behavior.

- [ ] **Step 2: Run tests — confirm they're marked todo / fail as expected**

    ```bash
    cargo test
    ```

- [ ] **Step 3: Implement the DELETE branch**

    Find `handle_admin_moderate_action` in `src/admin.rs` (around line 734). After the existing `update_blob_status` + `update_stats_on_status_change` + `purge_vcl_cache` calls, AND BEFORE the existing `json_response(StatusCode::OK, &response)` return, insert the DELETE dispatch per the spec Component 2 code block:

    ```rust
    if moderate_req.action.eq_ignore_ascii_case("DELETE") {
        let physical_delete_enabled = get_config("ENABLE_PHYSICAL_DELETE")
            .as_deref()
            == Some("true");

        if physical_delete_enabled {
            let reason = moderate_req
                .reason
                .as_deref()
                .unwrap_or("Creator-initiated deletion via kind 5");

            if let Err(e) = crate::perform_physical_delete(
                &moderate_req.sha256,
                "creator_delete",
                reason,
                false,
            ) {
                eprintln!(
                    "[CREATOR-DELETE] perform_physical_delete failed for {}: {}. \
                     Status is still Deleted; bytes may remain. Operator follow-up required.",
                    moderate_req.sha256, e
                );
            }

            let response = serde_json::json!({
                "success": true,
                "sha256": moderate_req.sha256,
                "old_status": format!("{:?}", old_status).to_lowercase(),
                "new_status": format!("{:?}", new_status).to_lowercase(),
                "physical_deleted": true
            });
            return json_response(StatusCode::OK, &response);
        } else {
            let response = serde_json::json!({
                "success": true,
                "sha256": moderate_req.sha256,
                "old_status": format!("{:?}", old_status).to_lowercase(),
                "new_status": format!("{:?}", new_status).to_lowercase(),
                "physical_delete_skipped": true
            });
            return json_response(StatusCode::OK, &response);
        }
    }
    ```

    The existing action-map match in `handle_admin_moderate_action` handles `DELETE` by mapping to `BlobStatus::Deleted` (once the arm is added). Find the match that sets `new_status` from the action string and add a `"DELETE" | "delete"` arm:

    ```rust
    let new_status = match moderate_req.action.to_uppercase().as_str() {
        "BAN" | "BLOCK" => BlobStatus::Banned,
        "RESTRICT" => BlobStatus::Restricted,
        "APPROVE" | "ACTIVE" => BlobStatus::Active,
        "PENDING" => BlobStatus::Pending,
        "AGE_RESTRICTED" | "AGERESTRICTED" => BlobStatus::AgeRestricted,
        "DELETE" => BlobStatus::Deleted,  // NEW
        _ => {
            return Err(BlossomError::BadRequest(format!(
                "Unknown action: {}",
                moderate_req.action
            )))
        }
    };
    ```

    (The exact existing match arms may vary; confirm against the current file and add `"DELETE" => BlobStatus::Deleted` consistent with the style.)

- [ ] **Step 4: Build**

    ```bash
    cargo build --target wasm32-wasi --release
    ```
    Expected: succeeds.

- [ ] **Step 5: Local e2e validation (manual)**

    Start the local dev stack (per preflight). Then:

    ```bash
    # Flag off (default): expect physical_delete_skipped=true, blob still in GCS
    curl -X POST http://localhost:7676/admin/api/moderate \
      -H 'Content-Type: application/json' \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -d '{"sha256":"<test_blob_hash>","action":"DELETE"}'
    # Expect: 200 {..., "physical_delete_skipped": true}
    # Verify: minio bucket still has the blob (mc ls local/divine-blossom-local)
    # Verify: Blossom serves 404 on the blob URL (status = Deleted)

    # Flag on: expect physical_deleted=true, blob gone from GCS
    # Set ENABLE_PHYSICAL_DELETE=true in config-store-data.json (see Task 4)
    # Restart fastly compute serve
    curl -X POST http://localhost:7676/admin/api/moderate \
      -H 'Content-Type: application/json' \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -d '{"sha256":"<different_test_blob>","action":"DELETE"}'
    # Expect: 200 {..., "physical_deleted": true}
    # Verify: minio bucket no longer has the blob
    ```

    Record both results in the commit body.

- [ ] **Step 6: Run cargo test**

    ```bash
    cargo test
    ```
    Existing tests must still pass. If the `todo!()` tests from Step 1 are still stubs, they'll panic and fail — expected; remove them or replace with real assertions as a follow-up if you can build a mocking harness, OR delete them in favor of the manual local-e2e approach (note in commit body either way).

- [ ] **Step 7: Commit**

    ```bash
    git add src/admin.rs
    git commit -m "feat(admin): add DELETE action dispatching to perform_physical_delete

    Wires DELETE into /admin/api/moderate's BLOSSOM_ACTION_MAP (new arm:
    DELETE → BlobStatus::Deleted) and, after the status flip + VCL purge,
    dispatches to the extracted perform_physical_delete helper when
    ENABLE_PHYSICAL_DELETE config flag is 'true'. Flag off returns
    {physical_delete_skipped: true} — first-prod deploy is inert.

    Admin DMCA path (/admin/api/delete) unchanged — always destructive.
    Shared helper distinguishes callers via audit-log actor field
    ('admin' vs 'creator_delete').

    Caller: divinevideo/divine-moderation-service#92.
    "
    ```

---

## Task 4: Local dev config

**Files:**
- Modify: `config-store-data.json`

- [ ] **Step 1: Add the flag**

    Open `config-store-data.json` in the repo root. Add `"ENABLE_PHYSICAL_DELETE": "false"` alongside other config keys. Keep it as a string (Fastly config store semantic).

- [ ] **Step 2: Verify local dev picks it up**

    Restart `fastly compute serve`. Confirm via a Task-3-style curl that `physical_delete_skipped: true` is returned.

- [ ] **Step 3: Commit**

    ```bash
    git add config-store-data.json
    git commit -m "config: add ENABLE_PHYSICAL_DELETE=false for local dev"
    ```

---

## Task 5: Documentation + PR polish

**Files:**
- Modify: `README.md` (if the "Configure secrets" section mentions all config keys — add the flag alongside existing `google_allowed_domain`, `gcs_bucket`, etc.).
- Optionally: `CHANGELOG.md` if the repo maintains one.

- [ ] **Step 1: Document the flag in README**

    Find the "Configure secrets" or "Configuration" section. Add:

    ```markdown
    - `ENABLE_PHYSICAL_DELETE` (config store `blossom_config`): when `"true"`, creator-delete actions via `/admin/api/moderate` physically remove bytes from GCS and purge edge caches. Default `"false"` — status flip only. Flip to `"true"` after end-to-end validation in the creator-delete rollout. Admin DMCA via `/admin/api/delete` is unconditionally destructive regardless of this flag.
    ```

- [ ] **Step 2: Commit**

    ```bash
    git add README.md
    git commit -m "docs(readme): document ENABLE_PHYSICAL_DELETE config flag"
    ```

---

## Self-Review checklist

After writing the plan, check:

**Spec coverage:**
- [x] `perform_physical_delete` helper extraction — Task 1
- [x] `reason` field on `ModerateRequest` — Task 2
- [x] `DELETE` action dispatch with flag check — Task 3
- [x] `ENABLE_PHYSICAL_DELETE` config store entry — Task 4
- [x] Documentation — Task 5
- [x] Failure handling matrix — covered in Task 3's implementation (eprintln on helper failure, 200 still returned)
- [x] Observability — existing `[PURGE]` and new `[CREATOR-DELETE]` / `[PHYSICAL-DELETE]` logs
- [x] Tests — Task 3 with fallback to local e2e if Viceroy mocking is too heavy
- [x] Dependencies and sequencing — spec section is authoritative
- [x] Local dev loop — preflight + Task 3 Step 5

**Placeholder scan:** The `todo!()` in Task 3 Step 1 is an acknowledged stub with a fallback — manual local e2e driven by the Step 5 curl commands. This is pragmatic for Rust + Fastly Compute where mocking `fastly::config_store` is non-trivial.

**Type consistency:** `perform_physical_delete(hash: &str, actor: &str, reason: &str, legal_hold: bool) -> Result<()>` — signature consistent across Tasks 1 and 3.

---

## Execution handoff

Plan complete and committed to `docs/superpowers/plans/2026-04-16-creator-delete-action-plan.md` on branch `feat/creator-delete-action`. Two execution options:

**1. Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — execute in this session using executing-plans, batch execution with checkpoints.

For this PR's scope (5 small tasks, mostly file edits in two files), either approach works. Subagent-driven preserves the per-task review rhythm we've established on the moderation-service side.
