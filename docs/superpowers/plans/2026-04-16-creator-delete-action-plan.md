# Blossom `DELETE` Action Implementation Plan (revised)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire a `DELETE` action into Blossom's `/admin/api/moderate` endpoint that composes `soft_delete_blob` (stops serving) with physical GCS byte removal (when the `ENABLE_PHYSICAL_DELETE` flag is on). New helper lives in `delete_policy.rs` alongside the existing soft-delete helper.

**Architecture:** `perform_physical_delete` = `soft_delete_blob` + byte destruction. DELETE handled as a special-case branch in `handle_admin_moderate_action` (not a new arm in the bare-status-flip match). Admin DMCA endpoint and GDPR vanish are untouched.

**Tech Stack:** Rust on Fastly Compute (WASM target `wasm32-wasip1`), `fastly` crate, `serde_json`. Tests via `cargo check --tests --locked` (the edge crate's FFI symbols don't link for `cargo test` on host). Local e2e via MinIO + `fastly compute serve`.

**Spec:** `docs/superpowers/specs/2026-04-16-creator-delete-action-design.md` (revised).

---

## File Structure

**Files to modify:**
- `src/delete_policy.rs` — add `perform_physical_delete` (new public function, ~20 lines)
- `src/admin.rs` — add `reason` field to `ModerateRequest`; add DELETE special-case branch in `handle_admin_moderate_action` (~40 lines)
- `config-store-data.json` — add `ENABLE_PHYSICAL_DELETE = "false"` for local dev
- `README.md` — document the flag

**Files NOT modified:**
- `src/main.rs` — no changes. `handle_admin_force_delete` stays soft-delete. `execute_vanish` stays inline.

---

## Guardrails

- Do not add new dependencies in `Cargo.toml`.
- Do not modify `handle_admin_force_delete` or `execute_vanish`.
- Do not modify any existing tests.
- Do not delete the metadata row via `delete_blob_metadata`. Metadata stays with `status: Deleted` for audit.
- Do not delete KV artifacts via `delete_blob_kv_artifacts`. Same reason.
- `ENABLE_PHYSICAL_DELETE` flag check uses `get_config("ENABLE_PHYSICAL_DELETE").as_deref() == Some("true")`.
- `write_audit_log` call: action = `"creator_delete"`, actor_pubkey = `&metadata.owner`. Do NOT pass actor into the action slot.
- `legal_hold: false` on all creator-delete calls. Tombstone is a legal mechanism.
- Failure of `perform_physical_delete` is logged but does NOT block the 200 response.
- Build target: `wasm32-wasip1` (NOT `wasm32-wasi`).
- Verification: `cargo check --tests --locked` (NOT `cargo test`).

---

## Staging Preflight

- [ ] `cargo build --target wasm32-wasip1 --release` succeeds on the current branch (baseline).
- [ ] `cargo check --tests --locked` succeeds (baseline).
- [ ] Local dev: `docker compose -f docker-compose.local.yml up minio minio-init -d` + `cp fastly.toml.local fastly.toml` + `fastly compute serve` starts Blossom on :7676.
- [ ] `POST /admin/api/moderate` with `action: "DELETE"` returns `400 Unknown action: DELETE` (pre-change baseline).

---

## Task 1: Add `perform_physical_delete` to `delete_policy.rs`

**Files:** Modify `src/delete_policy.rs`

- [ ] **Step 1: Read the existing helpers.** `soft_delete_blob` is at line 39. Understand its signature, what it does, what it imports. Read the module's `use crate::...` block at the top — you'll need additional imports for the byte-destruction functions.

- [ ] **Step 2: Add imports for byte-destruction helpers.** At the top of `delete_policy.rs`, the existing imports include `update_blob_status`, `remove_from_user_list`, etc. Add the functions `perform_physical_delete` will call that aren't already imported. These live in `crate` (main.rs) and will need `pub(crate)` visibility there:
    - `crate::cleanup_derived_audio_for_source`
    - `crate::storage_delete`
    - `crate::delete_blob_gcs_artifacts`
    - `crate::purge_vcl_cache`

    Check whether these are already `pub(crate)` in main.rs. If they're private (`fn` without `pub`), add `pub(crate)` to each. Do NOT change their signatures or behavior; only their visibility.

- [ ] **Step 3: Add `perform_physical_delete` below `soft_delete_blob`.**

    ```rust
    /// Physical deletion: soft-delete (stops serving) + GCS byte removal.
    /// Metadata row is preserved (status=Deleted) for audit/support visibility.
    pub fn perform_physical_delete(
        hash: &str,
        metadata: &BlobMetadata,
        reason: &str,
        legal_hold: bool,
    ) -> Result<()> {
        soft_delete_blob(hash, metadata, reason, legal_hold)?;
        crate::cleanup_derived_audio_for_source(hash);
        let _ = crate::storage_delete(hash);
        crate::delete_blob_gcs_artifacts(hash);
        crate::purge_vcl_cache(hash);
        Ok(())
    }
    ```

- [ ] **Step 4: Build.**

    ```bash
    cargo build --target wasm32-wasip1 --release
    cargo check --tests --locked
    ```
    Expected: success (new function is defined but not yet called — dead code warning is OK).

- [ ] **Step 5: Commit.** (Matt commits from his shell.)

---

## Task 2: Add optional `reason` to `ModerateRequest`

**Files:** Modify `src/admin.rs`

- [ ] **Step 1: Find the struct.**

    ```bash
    grep -n "struct ModerateRequest" src/admin.rs
    ```

- [ ] **Step 2: Add the field.**

    ```rust
    #[derive(Deserialize)]
    struct ModerateRequest {
        sha256: String,
        action: String,
        #[serde(default)]
        reason: Option<String>,
    }
    ```

- [ ] **Step 3: Build.** `cargo build --target wasm32-wasip1 --release`. Expected: succeeds. No callers changed.

- [ ] **Step 4: Commit.** (Matt commits.)

---

## Task 3: Wire DELETE special-case in `handle_admin_moderate_action`

**Files:** Modify `src/admin.rs`

This is the core wiring task. DELETE is a special-case branch BEFORE the existing action-map match.

- [ ] **Step 1: Read the current handler.** Find `handle_admin_moderate_action` (around line 848). Read the full function to understand the flow: auth, parse, validate sha256, fetch metadata, action match, status flip, response.

- [ ] **Step 2: Add necessary imports at the top of `admin.rs`.**

    ```rust
    use crate::delete_policy::{perform_physical_delete, soft_delete_blob};
    use crate::storage::write_audit_log;
    ```

    Check whether these are already imported. Add only what's missing.

- [ ] **Step 3: Insert the DELETE branch.** After the `metadata` fetch and BEFORE the `let new_status = match ...` block, add:

    ```rust
    // Creator-delete: special-case because DELETE needs soft_delete_blob's full
    // index/user-list cleanup, not the bare update_blob_status the action-map
    // match provides for BAN/RESTRICT/etc.
    if moderate_req.action.eq_ignore_ascii_case("DELETE") {
        let reason = moderate_req
            .reason
            .as_deref()
            .unwrap_or("Creator-initiated deletion via kind 5");

        let meta_json = serde_json::to_string(&metadata).ok();
        crate::write_audit_log(
            &moderate_req.sha256,
            "creator_delete",
            &metadata.owner,
            None,
            meta_json.as_deref(),
            Some(reason),
        );

        let physical_delete_enabled = get_config("ENABLE_PHYSICAL_DELETE")
            .as_deref()
            == Some("true");

        if physical_delete_enabled {
            if let Err(e) = perform_physical_delete(
                &moderate_req.sha256,
                &metadata,
                reason,
                false,
            ) {
                eprintln!(
                    "[CREATOR-DELETE] perform_physical_delete failed for {}: {}",
                    moderate_req.sha256, e
                );
            }
        } else {
            if let Err(e) = soft_delete_blob(
                &moderate_req.sha256,
                &metadata,
                reason,
                false,
            ) {
                eprintln!(
                    "[CREATOR-DELETE] soft_delete_blob failed for {}: {}",
                    moderate_req.sha256, e
                );
                return Err(e);
            }
        }

        let response = serde_json::json!({
            "success": true,
            "sha256": moderate_req.sha256,
            "old_status": format!("{:?}", old_status).to_lowercase(),
            "new_status": "deleted",
            "physical_deleted": physical_delete_enabled,
            "physical_delete_skipped": !physical_delete_enabled
        });
        return json_response(StatusCode::OK, &response);
    }
    ```

- [ ] **Step 4: Build.**

    ```bash
    cargo build --target wasm32-wasip1 --release
    cargo check --tests --locked
    ```
    Expected: success. The dead-code warning on `perform_physical_delete` should be gone (it's now called).

- [ ] **Step 5: Local e2e test — flag off.**

    Start local dev stack (MinIO + `fastly compute serve`). Upload a test blob if one doesn't exist. Then:

    ```bash
    curl -X POST http://localhost:7676/admin/api/moderate \
      -H 'Content-Type: application/json' \
      -H "Authorization: Bearer <admin_token_from_secret_store_data>" \
      -d '{"sha256":"<test_blob_hash>","action":"DELETE"}'
    ```

    Expected: 200 with `"physical_delete_skipped": true`, `"new_status": "deleted"`. Blob serves 404 on `http://localhost:7676/<hash>`. MinIO bucket still has the bytes.

- [ ] **Step 6: Local e2e test — flag on.**

    Edit `config-store-data.json` to set `"ENABLE_PHYSICAL_DELETE": "true"`. Restart `fastly compute serve`. Upload a NEW test blob (different hash since the first is now `Deleted`).

    ```bash
    curl -X POST http://localhost:7676/admin/api/moderate \
      -H 'Content-Type: application/json' \
      -H "Authorization: Bearer <admin_token>" \
      -d '{"sha256":"<new_test_blob_hash>","action":"DELETE"}'
    ```

    Expected: 200 with `"physical_deleted": true`. MinIO bucket no longer has the blob bytes. Thumbnail and VTT also gone (verify via `mc ls`).

- [ ] **Step 7: Verify existing actions still work.**

    ```bash
    # BAN should still work as before
    curl -X POST http://localhost:7676/admin/api/moderate \
      -H 'Content-Type: application/json' \
      -H "Authorization: Bearer <admin_token>" \
      -d '{"sha256":"<another_hash>","action":"BAN"}'
    ```
    Expected: 200 with `"new_status": "banned"`. No `physical_deleted` or `physical_delete_skipped` fields.

- [ ] **Step 8: Verify admin DMCA endpoint unchanged.**

    ```bash
    curl -X POST http://localhost:7676/admin/api/delete \
      -H 'Content-Type: application/json' \
      -H "Authorization: Bearer <admin_token>" \
      -d '{"sha256":"<another_hash>","reason":"test"}'
    ```
    Expected: 200 with `"preserved": true`. Bytes still on MinIO. Unchanged behavior.

- [ ] **Step 9: Commit.** (Matt commits.)

---

## Task 4: Local dev config

**Files:** Modify `config-store-data.json`

- [ ] **Step 1: Add the flag.** `"ENABLE_PHYSICAL_DELETE": "false"` alongside other config keys.
- [ ] **Step 2: Commit.** (Matt commits.)

---

## Task 5: Documentation

**Files:** Modify `README.md`

- [ ] **Step 1: Document the flag.** In the Configuration or Environment section, add:

    `ENABLE_PHYSICAL_DELETE` (config store `blossom_config`): when `"true"`, creator-delete actions via `/admin/api/moderate` physically remove bytes from GCS and purge edge caches. Default `"false"` (status flip only). Flip to `"true"` after end-to-end validation in the creator-delete rollout. Admin DMCA via `/admin/api/delete` is unconditionally soft-delete regardless of this flag.

- [ ] **Step 2: Commit.** (Matt commits.)

---

## Execution order

Task 1 → Task 2 → Task 3 → Task 4 → Task 5

Tasks 1-2 can run in either order. Task 3 depends on both (imports `perform_physical_delete` + uses `moderate_req.reason`). Tasks 4-5 are independent cleanups.

## Self-Review checklist

- [x] Spec coverage: `perform_physical_delete` (Task 1), DELETE wiring + flag (Task 3), reason field (Task 2), config (Task 4), docs (Task 5)
- [x] Existing endpoints untouched: `handle_admin_force_delete` and `execute_vanish` have no changes in any task
- [x] Build target correct: `wasm32-wasip1` everywhere
- [x] Test command correct: `cargo check --tests --locked` (not `cargo test`)
- [x] `write_audit_log` call: action=`"creator_delete"`, actor=`&metadata.owner` (not `actor` in both slots)
- [x] DELETE is a special-case branch, not an action-map arm (so `soft_delete_blob` runs, not bare `update_blob_status`)
- [x] `perform_physical_delete` composes `soft_delete_blob` + byte destruction, preserves metadata row
- [x] Guardrails documented for subagents
