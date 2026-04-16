# Blossom `DELETE` Action for Creator-Initiated Deletes

**Date:** April 16, 2026
**Author:** Matt Bradley
**Status:** Draft. Awaiting review.

**Related:**
- `divine-mobile#3102` (feature issue — "remove media blobs and confirm relay deletion before success")
- `divine-moderation-service` PR `#92` on branch `spec/per-video-delete-enforcement` (the calling side — creator-delete pipeline)
- `divine-mobile#3117` (mobile copy PR — sibling, not a dependency)
- `divine-blossom` PR #33 (merged 2026-04-07 — `Deleted` status serve-path fixes; this work builds on top of it)

## Goal

When `divine-moderation-service` accepts a creator-initiated kind 5 deletion, Blossom must remove the affected media blob from both its live serving path (blob status → `Deleted`) and, when enabled, from Divine-controlled physical storage (GCS bytes gone, Fastly edge cache invalidated). A safety flag (`ENABLE_PHYSICAL_DELETE`, default off) gates the destructive step so the first production deploy is inert and reversible.

## Motivation

The creator-delete pipeline in `divine-moderation-service` sends `POST /admin/api/moderate` with `{sha256, action: "DELETE"}`. Today that request returns `400 Unknown action: DELETE` — the action isn't wired. We need to:

1. Accept the action.
2. Map it to a physical-removal cascade that matches Liz's compliance scoping on divine-mobile#3102: "remove media blobs" means bytes gone from GCS, not just a status flip.
3. Gate the cascade on a flag so first-prod deploys don't destroy data before the end-to-end pipeline is verified.

## Current State

Blossom already has most of what we need:

**`handle_admin_force_delete`** (`src/main.rs:3152-3240`) is a working endpoint for admin DMCA / legal-hold force-deletion. It calls:
- `storage_delete(hash)` — GCS main blob delete (via `Method::DELETE` to gcs_storage backend)
- `delete_blob_gcs_artifacts(hash)` — thumbnail (`{hash}.jpg`), HLS variants (master.m3u8, stream_720p/480p.m3u8/.ts/.mp4), VTT (`{hash}/vtt/main.vtt`), plus a Cloud Run fire-and-forget for prefix-based catch-all cleanup
- `cleanup_derived_audio_for_source(hash)` — derived audio cleanup
- `delete_blob_metadata(hash)` — KV metadata delete
- `delete_blob_kv_artifacts(hash)` — refs, auth events, subtitle data
- `remove_from_user_list` / `remove_from_recent_index`
- `update_stats_on_remove`
- `write_audit_log` — persisted audit trail
- `purge_vcl_cache(hash)` — Fastly Purge API call (external `POST https://api.fastly.com/service/{id}/purge/{surrogate_key}` with `fastly_api_token` from secret store; fire-and-forget with logging)
- Optional `put_tombstone(hash, reason)` (when `legal_hold: true` — prevents future re-upload of the same bytes)

**`handle_admin_moderate_action`** (`src/admin.rs:734-788`) accepts `BAN | BLOCK | RESTRICT | APPROVE | ACTIVE | PENDING | AGE_RESTRICTED` via `BLOSSOM_ACTION_MAP`. Status flip is applied, then `purge_vcl_cache` runs. Auth is Bearer (`admin_token` or `webhook_secret` from `blossom_secrets`, both accepted) or session cookie.

**`BlobStatus::Deleted`** already exists in the blob-status enum. PR #33 (merged) closed route gaps so all serving paths (main, HLS HEAD, subtitle-by-hash) reject `Deleted` blobs with 404.

**Config store access** uses `get_config(key)` against `blossom_config` (`admin.rs:203`). Adding a new flag is standard.

## Gap

Three things are missing:

1. `handle_admin_moderate_action` does not recognize `"DELETE"` — returns 400.
2. The physical-delete cascade inside `handle_admin_force_delete` is a monolithic 89-line block; not reusable from `handle_admin_moderate_action`.
3. No `ENABLE_PHYSICAL_DELETE` config flag exists — all force-delete paths are unconditionally destructive (appropriate for admin DMCA, but creator-delete needs a safer first-deploy path).

## Design Principle

**Reuse everything that exists.** The existing force-delete cascade is production-tested for admin DMCA. The creator-delete path should invoke the same cascade, just gated differently. Refactor the cascade into a shared helper so both ingresses call a single source of truth.

Two ingresses, two semantics:

| Ingress | Purpose | Flag behavior |
|---|---|---|
| `POST /admin/api/delete` (existing) | Admin DMCA / legal hold | Unconditionally destructive. No flag check. |
| `POST /admin/api/moderate` with `action: "DELETE"` (new) | Creator-initiated deletion from moderation-service | Gated on `ENABLE_PHYSICAL_DELETE`. Flag off → status flip only. Flag on → full cascade. |

Same helper, different call sites, different semantics. Audit log's `actor` field distinguishes them ("admin" vs "creator_delete").

## Architecture

```
  moderation-service                              divine-blossom
  ------------------                              --------------
  POST /admin/api/moderate                  --->  handle_admin_moderate_action
  { sha256, action: "DELETE" }
  Bearer webhook_secret                           [validate_bearer_token]
                                                  [BLOSSOM_ACTION_MAP: DELETE -> Deleted]
                                                  [update_blob_status(sha256, Deleted)]
                                                  [update_stats_on_status_change]
                                                  [purge_vcl_cache(sha256)]
                                                           |
                                                           v
                                         [flag = get_config("ENABLE_PHYSICAL_DELETE")]
                                                           |
                    +--------------------------------------+--------------+
                    | flag = "true"                                       | flag != "true"
                    v                                                     v
           perform_physical_delete(sha256, "creator_delete", reason)    return {
                    |                                                      success: true,
                    |  (existing helpers, reused verbatim)                  physical_delete_skipped: true,
                    |                                                      ...
                    v                                                    }
           cleanup_derived_audio_for_source
           storage_delete (main blob)
           delete_blob_gcs_artifacts (thumb, HLS, VTT, derived)
           delete_blob_metadata
           remove_from_user_list (owner + all refs)
           delete_blob_kv_artifacts
           update_stats_on_remove
           remove_from_recent_index
           purge_vcl_cache (second pass, post-destruction)
           write_audit_log(sha256, "creator_delete", ...)
                    |
                    v
           return { success: true, physical_deleted: true, ... }
```

## Components

### 1. Extract `perform_physical_delete` helper

**File:** `src/main.rs`

Extract the cascade body from `handle_admin_force_delete` (lines 3175-3230 in the current file, the steps between "Get metadata before deletion for audit" and "Purge VCL cache") into a reusable helper:

```rust
/// Execute full physical deletion of a blob and all derived artifacts.
/// Caller is responsible for having already verified auth + format + blob existence.
/// Returns Ok(()) on success; errors are logged internally and best-effort (most
/// steps are fire-and-forget at the storage/KV layer, matching existing behavior).
///
/// actor: attribution tag for the audit log ("admin", "creator_delete", etc.)
/// reason: free-form reason string for the audit log
/// legal_hold: when true, writes a tombstone that prevents re-upload of the same bytes
pub(crate) fn perform_physical_delete(
    hash: &str,
    actor: &str,
    reason: &str,
    legal_hold: bool,
) -> Result<()> {
    // Get metadata before deletion for audit
    let metadata = get_blob_metadata(hash)?;
    let meta_json = metadata
        .as_ref()
        .and_then(|m| serde_json::to_string(m).ok());

    // Audit log BEFORE deletion
    write_audit_log(
        hash,
        actor, // was "admin_delete" — now parameterized
        actor,
        None,
        meta_json.as_deref(),
        Some(reason),
    );

    // GCS: main blob + derived artifacts + derived audio
    cleanup_derived_audio_for_source(hash);
    let _ = storage_delete(hash);
    delete_blob_gcs_artifacts(hash);

    // KV metadata + user list + artifacts
    let _ = delete_blob_metadata(hash);
    if let Some(ref meta) = metadata {
        let _ = remove_from_user_list(&meta.owner, hash);
    }
    if let Ok(refs) = get_blob_refs(hash) {
        for pubkey in &refs {
            let _ = remove_from_user_list(pubkey, hash);
        }
    }
    delete_blob_kv_artifacts(hash);

    // Stats + recent index
    if let Some(meta) = metadata {
        let _ = update_stats_on_remove(&meta);
    }
    let _ = remove_from_recent_index(hash);

    // Tombstone (prevents re-upload of these exact bytes)
    if legal_hold {
        let _ = put_tombstone(hash, reason);
    }

    // Fastly VCL cache purge
    purge_vcl_cache(hash);

    eprintln!(
        "[PHYSICAL-DELETE] actor={} hash={} legal_hold={}",
        actor, hash, legal_hold
    );

    Ok(())
}
```

Update `handle_admin_force_delete` to call the helper with `actor: "admin"`, `legal_hold` from the request body, and the request's `reason`. Behavior equivalent — existing tests for force-delete must still pass.

### 2. Wire `DELETE` into `handle_admin_moderate_action`

**File:** `src/admin.rs`

Add `"DELETE"` to the action match in `handle_admin_moderate_action` (around line 754), mapping to `BlobStatus::Deleted`. The status flip runs normally (reuses existing `update_blob_status` + `update_stats_on_status_change` + `purge_vcl_cache` path). Then branch on the flag:

```rust
// New DELETE action dispatch — after the existing update_blob_status and
// update_stats_on_status_change calls, BEFORE the json_response return.
if moderate_req.action.eq_ignore_ascii_case("DELETE") {
    let physical_delete_enabled = get_config("ENABLE_PHYSICAL_DELETE")
        .as_deref()
        == Some("true");

    if physical_delete_enabled {
        // Reason defaults for creator-initiated deletes. If the caller ever
        // sends a reason in the body, forward it; else use a stable default.
        let reason = moderate_req
            .reason
            .as_deref()
            .unwrap_or("Creator-initiated deletion via kind 5");

        // perform_physical_delete is the extracted helper from main.rs.
        // Failures are logged internally and don't block the response —
        // the status flip already stopped serving, which is the core
        // compliance guarantee.
        if let Err(e) = crate::perform_physical_delete(
            &moderate_req.sha256,
            "creator_delete",
            reason,
            false, // legal_hold always false for creator-initiated
        ) {
            eprintln!(
                "[CREATOR-DELETE] perform_physical_delete failed for {}: {}. \
                 Status is still Deleted; bytes may remain. Operator follow-up required.",
                moderate_req.sha256, e
            );
            // Continue to return success — the status flip is the load-bearing
            // promise; physical-delete failure is an operator issue.
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

### 3. Extend `ModerateRequest` with an optional `reason` field

**File:** `src/admin.rs`

The `ModerateRequest` struct currently has `{sha256, action}`. Add an optional `reason` for the audit log. Moderation-service's current payload doesn't include it, so we use an `Option<String>` with a sensible default when absent.

```rust
#[derive(Deserialize)]
struct ModerateRequest {
    sha256: String,
    action: String,
    #[serde(default)]
    reason: Option<String>,
}
```

### 4. Local dev config

**File:** `config-store-data.json`

Add `ENABLE_PHYSICAL_DELETE = "false"` to the local config store data. First-prod deploy flips this to `"true"` only after validation.

### 5. Tests

**File:** new test module in `src/admin.rs` (or a new `src/admin/tests.rs` if one exists)

- Test: `DELETE` action with flag off returns 200 with `physical_delete_skipped: true`, status flip happened, `perform_physical_delete` NOT called
- Test: `DELETE` action with flag on returns 200 with `physical_deleted: true`, status flip + cascade both ran, audit log has `actor: "creator_delete"`
- Test: `DELETE` on a non-existent blob returns 404
- Test: `DELETE` with invalid sha256 format returns 400
- Test: unknown action still returns 400 (preserves existing behavior)

For the extracted `perform_physical_delete`:

- Test: helper is called from `handle_admin_force_delete` with `actor: "admin"` — existing force-delete behavior preserved

Tests use Fastly Compute's Viceroy runtime with mocked KV / storage / config stores. Follow existing test conventions in the repo (check `src/*.rs` for `#[cfg(test)]` blocks as precedent).

## Failure handling

| Scenario | Response | Notes |
|---|---|---|
| `ENABLE_PHYSICAL_DELETE=false`, status flip OK | 200 `{physical_delete_skipped: true}` | Expected first-prod state. |
| `ENABLE_PHYSICAL_DELETE=true`, full cascade OK | 200 `{physical_deleted: true}` | Happy path. |
| `ENABLE_PHYSICAL_DELETE=true`, status flip OK, cascade throws | 200 `{physical_deleted: true}` + Sentry log | The cascade helpers are fire-and-forget internally; individual step failures don't propagate. A Rust panic inside `perform_physical_delete` is the one case that logs but doesn't block the response — we preserve the status flip semantics. |
| Fastly Purge fails mid-cascade | (internal to helper) Logged, doesn't block | Existing `purge_vcl_cache` behavior. |
| Blob not found | 404 from earlier in `handle_admin_moderate_action` (existing check) | Pre-cascade. |
| Invalid sha256 | 400 | Existing check. |
| Auth failure | 401 / 403 | Existing. |

## Observability

- `[CREATOR-DELETE] perform_physical_delete failed for {sha256}: {error}` — ERROR-level eprintln on helper failure. Sentry alert on this string surfaces physical-delete regressions without degrading the creator-visible pipeline.
- `[PHYSICAL-DELETE] actor=creator_delete hash=... legal_hold=false` — INFO-level on success. Metric source for throughput + audit trail.
- Existing `[PURGE] VCL purge failed for key={sha256}` already logs on Fastly API failures. Add a Sentry alert on elevated rates.
- Existing `[ADMIN DELETE]` log becomes per-actor; admin DMCA paths still emit `actor=admin`.

## Security

- **Auth:** unchanged. `validate_admin_auth` accepts `webhook_secret` (used by moderation-service) or `admin_token` (used by admin tools). Creator-delete ingress shares the webhook_secret path with all other moderation-service → Blossom traffic.
- **Flag scoping:** `ENABLE_PHYSICAL_DELETE` only affects the creator-delete ingress. Admin DMCA via `/admin/api/delete` remains unconditionally destructive — flipping the flag off does not accidentally protect DMCA targets.
- **Tombstone semantics:** admin DMCA sets `legal_hold: true` when requested (caller's choice). Creator-delete always sets `legal_hold: false` — a creator deleting their own video today can re-upload tomorrow if they choose, and we don't block that at the infrastructure layer.
- **Reason field:** optional, caller-provided. Written to audit log verbatim. Not rendered to user-visible surfaces. No sanitization needed.

## Dependencies and sequencing

1. **PR #33 already landed on main.** `Deleted` status serving checks are in place.
2. **This PR** — adds `perform_physical_delete` extraction + DELETE action + flag.
3. **Deploy sequence for production:**
   - Step 1: deploy Blossom with `ENABLE_PHYSICAL_DELETE="false"` in `blossom_config` (default). Creator-delete ingress works — status flips to `Deleted`, bytes stay on GCS, Fastly Purge runs (OK — idempotent). Moderation-service still needs its own `CREATOR_DELETE_PIPELINE_ENABLED=false` for its half.
   - Step 2: deploy moderation-service PR #92. Still inert (its own feature flag).
   - Step 3: flip moderation-service `CREATOR_DELETE_PIPELINE_ENABLED="true"`. Run validation window (first ~50 creator deletes). Bytes still on GCS.
   - Step 4: flip Blossom `ENABLE_PHYSICAL_DELETE="true"`. Subsequent creator-deletes physically remove bytes. Legacy `Deleted`-status blobs from the validation window can be cleaned by a one-time sweep script (simple iteration + per-blob `perform_physical_delete` call).

## Staging preflight

Before implementation:

- [ ] Confirm PR #33's merge is reflected on `origin/main` (verified — commit `755b7b8` sits above the relevant PR commits).
- [ ] Local dev loop: `docker compose -f docker-compose.local.yml up minio minio-init -d`, `cp fastly.toml.local fastly.toml`, `fastly compute serve`. Issue a `POST /admin/api/moderate` with `{sha256: "...", action: "DELETE"}` and confirm the existing 400 "Unknown action" response (establishes pre-change baseline).
- [ ] Confirm `purge_vcl_cache` emits a log line in local dev (may skip actual Fastly API call if `fastly_api_token` is absent — that's the existing "skipping VCL cache purge" path).
- [ ] Verify `write_audit_log` persists for local dev (check KV store via `fastly kv-store entry list` or equivalent).

## Non-goals and follow-ups

- **Changes to `/admin/api/delete`'s external contract.** It still accepts `{sha256, reason, legal_hold}` and still unconditionally destroys. Only the internal implementation changes (calls the extracted helper).
- **Cross-repo audit consolidation.** moderation-service writes its own D1 audit row; Blossom writes its own KV audit log. Reconciling them into a single audit surface is a v2 concern.
- **Soft-delete grace period for creator deletes.** The spec's moderation-service side already punts creator-initiated un-delete to v2. Blossom mirrors that — no grace window here.
- **One-time sweep of legacy `Deleted`-status blobs** (status was flipped before the physical-delete flag was on). Matt will script this separately after flag flip; it's a simple iteration.
- **Fastly Purge retry on failure.** Current behavior is fire-and-forget; failures log but don't retry. Elevating this to a retry loop is a follow-up if purge-failure rate is ever observed non-trivial.

## Open questions

- **Tests for the extracted helper in Viceroy.** Does the existing repo have an integration test harness for Fastly Compute, or is all testing via manual local e2e + prod smoke? If only the latter, we add unit tests for `handle_admin_moderate_action`'s new DELETE branch using the existing mock-friendly pattern (if any); otherwise we rely on local e2e in preflight.
- **Reason field propagation from moderation-service.** Currently moderation-service's `notifyBlossom` sends `{sha256, action, timestamp}` — no `reason`. This spec treats `reason` as optional on the Blossom side. A follow-up could add a `reason` field from the creator-delete pipeline (e.g., "Creator-initiated delete via kind 5") to enrich the audit log.
