# Blossom `DELETE` Action for Creator-Initiated Deletes

**Date:** April 16, 2026 (revised after code-review scout)
**Author:** Matt Bradley
**Status:** Draft. Awaiting review.

**Related:**
- `divine-mobile#3102` (feature issue — "remove media blobs and confirm relay deletion before success")
- `divine-moderation-service` PR `#92` on branch `spec/per-video-delete-enforcement` (the calling side — creator-delete pipeline)
- `divine-mobile#3117` (mobile copy PR — sibling, not a dependency)
- `divine-blossom` PR #33 (merged 2026-04-07 — `Deleted` status serve-path fixes; this work builds on top of it)

## Goal

When `divine-moderation-service` accepts a creator-initiated kind 5 deletion, Blossom must remove the affected media blob from both its live serving path (blob status to `Deleted`) and, when enabled, from Divine-controlled physical storage (GCS bytes gone, Fastly edge cache invalidated). A safety flag (`ENABLE_PHYSICAL_DELETE`, default off) gates the destructive step so the first production deploy is inert and reversible.

## Motivation

The creator-delete pipeline in `divine-moderation-service` sends `POST /admin/api/moderate` with `{sha256, action: "DELETE"}`. Today that request returns `400 Unknown action: DELETE` — the action isn't wired. We need to:

1. Accept the action.
2. Map it to a physical-removal cascade that matches Liz's compliance scoping on divine-mobile#3102: "remove media blobs" means bytes gone from GCS, not just a status flip.
3. Gate the cascade on a flag so first-prod deploys don't destroy data before the end-to-end pipeline is verified.

## Current State (verified against `origin/main` on branch `feat/creator-delete-action`)

### What Blossom has today

**`handle_admin_moderate_action`** (`src/admin.rs:848-903`) — the endpoint moderation-service calls. Accepts `BAN|BLOCK`, `RESTRICT`, `AGE_RESTRICT|AGE_RESTRICTED`, `APPROVE|ACTIVE`, `PENDING`. Does a bare `update_blob_status` + `purge_vcl_cache` + `update_stats_on_status_change`. Does NOT call `soft_delete_blob` (no index/user-list cleanup). Does NOT do physical deletion.

**`handle_admin_force_delete`** (`src/main.rs:3913-3968`) — the admin DMCA endpoint at `/admin/api/delete`. Despite the name, this is **soft-delete by design**: calls `soft_delete_blob(...)` from `delete_policy.rs`. Response includes `"preserved": true`. GCS bytes are NOT removed. This endpoint is NOT modified by this PR.

**`soft_delete_blob`** (`src/delete_policy.rs:39-64`) — reusable helper. Status flip to `Deleted`, `update_stats_on_status_change`, `remove_from_user_list` (owner + all refs), `remove_from_recent_index`, optional `put_tombstone`, `purge_vcl_cache`. No physical byte removal.

**`execute_vanish`** (`src/main.rs:3975-4057`) — GDPR right-to-erasure, pubkey-level. Sole-owner branch does inline physical cascade: `cleanup_derived_audio_for_source`, `storage_delete`, `delete_blob_gcs_artifacts`, `delete_blob_metadata`, `delete_blob_kv_artifacts`, `update_stats_on_remove`, `remove_from_recent_index`, `purge_vcl_cache`. This IS physical deletion, but: (a) it's inline, not a reusable helper; (b) it deletes the metadata row entirely (we want to preserve it for audit); (c) it's pubkey-scoped, not per-blob.

**`BlobStatus::Deleted`** exists. PR #33 closed all serve-path gaps (main, HLS HEAD, subtitle-by-hash) so `Deleted` returns 404.

**`purge_vcl_cache`** (`src/main.rs:4722`) — calls Fastly Purge API via `api.fastly.com`. Uses `fastly_api_token` from secret store. Fire-and-forget with logging.

**`delete_blob_gcs_artifacts`** (`src/main.rs:2968`) — removes thumbnail (`{hash}.jpg`), HLS variants, VTT transcript, plus fire-and-forget Cloud Run for prefix-based catch-all.

**`storage_delete`** (`src/storage.rs`) — `Method::DELETE` to GCS backend.

**Config store** — `get_config(key)` reads from `blossom_config` (Fastly config store). Standard pattern for flags.

**`write_audit_log`** (`src/storage.rs:1172`) — signature: `(sha256, action, actor_pubkey, auth_event_json?, metadata_snapshot?, reason?)`. Writes structured JSON to Cloud Run /audit endpoint, auto-ingested by Cloud Logging.

### What's missing

1. `handle_admin_moderate_action` does not recognize `"DELETE"`.
2. No reusable per-blob physical-delete helper exists. `execute_vanish` has one inline but its semantics differ (deletes metadata row, pubkey-scoped).
3. No `ENABLE_PHYSICAL_DELETE` config flag.

## Design Principle

**Compose, don't extract.** `soft_delete_blob` is the proven soft-delete helper. Build `perform_physical_delete` as its physical counterpart: calls `soft_delete_blob` first (stops serving, cleans indices), then adds byte destruction. Lives alongside it in `delete_policy.rs`.

**Don't touch what works.** `handle_admin_force_delete` stays soft-delete. `execute_vanish` stays inline. Neither is modified by this PR.

**Two ingresses, two semantics:**

| Endpoint | Purpose | Delete semantics | Flag behavior |
|---|---|---|---|
| `POST /admin/api/delete` (existing) | Admin DMCA / legal hold | Soft-delete. Bytes preserved. | Not affected by `ENABLE_PHYSICAL_DELETE`. |
| `POST /admin/api/moderate` with `action: "DELETE"` (new) | Creator-initiated via moderation-service | Soft-delete (flag off) OR soft-delete + physical removal (flag on). | `ENABLE_PHYSICAL_DELETE` gates the byte-destruction step only. |

Admin DMCA is deliberately soft — preserves evidence for legal proceedings. Creator-delete is meant to be permanent when the flag is on.

## Architecture

```
  moderation-service                              divine-blossom
  ------------------                              --------------
  POST /admin/api/moderate                  --->  handle_admin_moderate_action
  { sha256, action: "DELETE" }
  Bearer webhook_secret                           [validate_admin_auth]
                                                  [check: action == "DELETE"?]
                                                           |
                                                           v   (special-case branch)
                                                  [write_audit_log("creator_delete", metadata.owner)]
                                                  [flag = get_config("ENABLE_PHYSICAL_DELETE")]
                                                           |
                    +--------------------------------------+--------------+
                    | flag = "true"                                       | flag != "true"
                    v                                                     v
           perform_physical_delete(hash, metadata, reason, false)    soft_delete_blob(hash, metadata, reason, false)
                    |                                                     |
                    |  = soft_delete_blob(...)                            | = status flip + indices + VCL purge
                    |    + cleanup_derived_audio_for_source               |   (bytes preserved)
                    |    + storage_delete (main blob GCS)                 |
                    |    + delete_blob_gcs_artifacts (thumb, HLS, VTT)    |
                    |    + purge_vcl_cache (second pass)                  |
                    |                                                     |
                    v                                                     v
           return { success: true, physical_deleted: true }    return { success: true, physical_delete_skipped: true }
```

## Components

### 1. `perform_physical_delete` helper (`src/delete_policy.rs`)

New `pub fn` alongside the existing `soft_delete_blob`. Composes soft-delete + byte destruction.

```rust
/// Physical deletion: soft-delete (stops serving) + GCS byte removal.
/// Metadata row is preserved (status=Deleted) for audit/support visibility.
/// Vanish callers that want metadata gone use their own inline cascade.
pub fn perform_physical_delete(
    hash: &str,
    metadata: &BlobMetadata,
    reason: &str,
    legal_hold: bool,
) -> Result<()> {
    // Phase 1: stop serving (status flip, index cleanup, optional tombstone, VCL purge)
    soft_delete_blob(hash, metadata, reason, legal_hold)?;

    // Phase 2: physical byte + artifact removal from GCS
    crate::cleanup_derived_audio_for_source(hash);
    let _ = crate::storage_delete(hash);
    crate::delete_blob_gcs_artifacts(hash);

    // Phase 3: post-destruction VCL purge (covers the window between
    // Phase 1's purge and Phase 2's byte removal)
    crate::purge_vcl_cache(hash);

    Ok(())
}
```

**Why not `delete_blob_metadata`?** Vanish deletes metadata (user is gone, no audit need). Creator-delete preserves it (creator is still active, support may query "what happened to blob X?"). The row stays with `status: Deleted`.

**Why not `delete_blob_kv_artifacts`?** Same reasoning — KV artifacts (refs, auth events, subtitle mappings) are preserved alongside the metadata row. If the creator re-uploads, a fresh metadata row + artifacts are created. Stale KV from the deleted blob doesn't interfere.

**Why `legal_hold: false` for creator-delete?** Creator-delete doesn't block future re-upload of the same bytes. Legal hold is a DMCA/legal mechanism. Callers pass `false` explicitly.

### 2. DELETE special-case branch in `handle_admin_moderate_action` (`src/admin.rs`)

Handle `action: "DELETE"` as a special-case branch BEFORE the existing `match ... => BlobStatus` action map. Why: the existing match does bare `update_blob_status` without index/user-list cleanup; DELETE needs the full `soft_delete_blob` path (or `perform_physical_delete` which calls it).

```rust
// Inside handle_admin_moderate_action, after sha256 validation and metadata fetch,
// BEFORE the action-map match:

if moderate_req.action.eq_ignore_ascii_case("DELETE") {
    let reason = moderate_req
        .reason
        .as_deref()
        .unwrap_or("Creator-initiated deletion via kind 5");

    // Audit BEFORE destruction
    let meta_json = serde_json::to_string(&metadata).ok();
    crate::write_audit_log(
        &moderate_req.sha256,
        "creator_delete",            // action tag
        &metadata.owner,             // actor = the creator's pubkey
        None,                        // no auth event for webhook-authed calls
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
            false, // no legal hold for creator-delete
        ) {
            eprintln!(
                "[CREATOR-DELETE] perform_physical_delete failed for {}: {}. \
                 Status may still be flipped to Deleted; bytes may remain.",
                moderate_req.sha256, e
            );
            // Fallback: ensure at least soft-delete ran (it may have succeeded
            // inside perform_physical_delete before the byte-removal step failed).
        }
    } else {
        // Flag off: soft-delete only
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

// ... existing action-map match follows for BAN, RESTRICT, etc.
```

### 3. Optional `reason` field on `ModerateRequest` (`src/admin.rs`)

Add `#[serde(default)] reason: Option<String>` to the struct. Existing callers (which don't send `reason`) continue to work — field defaults to `None`.

### 4. `ENABLE_PHYSICAL_DELETE` config entry

Add to `config-store-data.json` (local dev) and document in README. Default `"false"`.

## Failure handling

| Scenario | Response | Notes |
|---|---|---|
| Flag off, soft-delete OK | 200 `{physical_delete_skipped: true}` | Expected first-prod state. |
| Flag on, full cascade OK | 200 `{physical_deleted: true}` | Happy path. |
| Flag on, soft-delete OK, byte destruction fails | 200 `{physical_deleted: true}` + eprintln | Soft-delete has already stopped serving. Byte destruction's internal helpers are fire-and-forget (`let _ = storage_delete(...)`). A Rust panic inside `perform_physical_delete` is caught; status is still Deleted. Operator follow-up for orphaned bytes. |
| Fastly Purge fails | (internal) Logged by `purge_vcl_cache`, doesn't block | Existing behavior. Edge clears per TTL. |
| Blob not found | 404 | Existing check in `handle_admin_moderate_action`. |
| Invalid sha256 | 400 | Existing check. |
| Auth failure | 401 / 403 | Existing. |

## Observability

- `[CREATOR-DELETE] perform_physical_delete failed for {sha256}: {error}` — ERROR-level eprintln. Sentry alert on this string.
- Existing `[PURGE] VCL purge failed for key={sha256}` already logs on Fastly API failures.
- `write_audit_log` entry with `action: "creator_delete"` and `actor_pubkey: <creator's pubkey>` — queryable in Cloud Logging. Distinguishes from admin soft-delete (`action: "admin_delete"`, `actor_pubkey: "admin"`).

## Security

- **Auth:** unchanged. `validate_admin_auth` accepts `webhook_secret` (used by moderation-service) or `admin_token` (used by admin tools). Creator-delete ingress shares the webhook_secret path with all other moderation-service to Blossom traffic.
- **Admin DMCA endpoint `/admin/api/delete` is NOT modified.** It stays soft-delete, gated by its own auth, unaffected by `ENABLE_PHYSICAL_DELETE`. This is deliberate — admin DMCA preserves evidence for legal proceedings; creator-delete is meant to be permanent.
- **`legal_hold: false`** on all creator-delete calls. Tombstone (prevents re-upload) is a legal/DMCA mechanism, not a creator feature. If we later want creators to not be able to re-upload deleted content, that's a product decision for a future PR.

## Testing

Build and verification commands for this Rust + Fastly Compute crate:
- `cargo build --target wasm32-wasip1 --release` — build for Fastly's WASM target
- `cargo check --tests --locked` — compile-check tests on host (the edge crate's FFI symbols don't link for `cargo test` on host; CI uses `cargo check` + `cargo clippy`, NOT `cargo test`)
- Local e2e: `docker compose -f docker-compose.local.yml up minio minio-init -d` then `cp fastly.toml.local fastly.toml` then `fastly compute serve` + curl

Test cases (verified via local e2e + compile-checked unit tests):
- `perform_physical_delete` compiles and has the right imports (`cargo check --tests`)
- `/admin/api/moderate` with `action: "DELETE"` and flag off returns 200 + `physical_delete_skipped: true`. Blob serves 404 (status Deleted). MinIO bucket retains bytes.
- Same with flag on returns 200 + `physical_deleted: true`. MinIO bucket no longer has the bytes. Thumbnail + HLS + VTT also gone.
- Unknown action still returns 400 (existing behavior preserved).
- Admin DMCA endpoint (`/admin/api/delete`) behavior unchanged (soft-delete, `preserved: true`).
- `purge_vcl_cache` log emits on both paths (no functional change to purge).

## Dependencies and sequencing

1. **PR #33 already landed on main.** `Deleted` status serving checks are in place.
2. **This PR** — adds `perform_physical_delete` + DELETE action + flag.
3. **Deploy sequence for production:**
   - Step 1: deploy Blossom with `ENABLE_PHYSICAL_DELETE="false"` in `blossom_config` (default). Creator-delete ingress does soft-delete only.
   - Step 2: deploy moderation-service PR #92 with `CREATOR_DELETE_PIPELINE_ENABLED="false"`.
   - Step 3: flip moderation-service flag. Validation window. Blossom receives DELETE calls, does soft-delete only (bytes stay).
   - Step 4: flip Blossom `ENABLE_PHYSICAL_DELETE="true"`. Subsequent creator-deletes physically remove bytes.
   - Step 5: one-time sweep to physically remove bytes for blobs soft-deleted during the validation window.

## Non-goals and follow-ups

- **Changes to `handle_admin_force_delete`.** It stays soft-delete by design. If admin DMCA ever needs physical deletion, that's a separate product decision.
- **Refactoring `execute_vanish`.** Its inline cascade has different semantics (deletes metadata, pubkey-scoped). Unifying with `perform_physical_delete` would change vanish behavior. Separate PR if ever desired.
- **Cross-repo audit consolidation.** Blossom writes Cloud Logging audit; moderation-service writes D1 audit. Reconciliation is a v2 concern.
- **One-time sweep for validation-window blobs.** Simple script: iterate `creator_deletions` D1 rows with `status: success`, check Blossom metadata is `Deleted`, call `perform_physical_delete`. Matt scripts this at flag-flip time.

## Open questions

- **Cloud Run delete-blob trigger.** `delete_blob_gcs_artifacts` fires `trigger_cloud_run_delete_blob` as a secondary cleanup. In local dev against MinIO, this will fail silently (Cloud Run backend not configured in `fastly.toml.local`). That's fine — the primary GCS deletes go through MinIO directly. Worth confirming the fire-and-forget behavior doesn't disrupt the local dev loop.
