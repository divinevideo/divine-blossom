# Preserve-First Delete Policy Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make ordinary delete and moderation flows preserve stored media while stopping public serving, so content can be restored later unless an explicit erase-only path is invoked.

**Architecture:** Move normal removal behavior onto metadata status transitions instead of storage deletion. Keep public serving semantics unchanged, but route owner delete, admin delete, and moderation-driven removals through a shared soft-delete policy with restore support and non-destructive regression coverage.

**Tech Stack:** Rust Fastly Compute service, Fastly KV metadata helpers, Python Cloud Function moderation hook, Cargo tests, Python `unittest`

---

## File Map

- Modify: `src/main.rs`
  - Replace hard-delete behavior in owner delete and admin delete routes.
  - Register admin restore route if missing.
  - Update landing-page/API descriptions that still promise permanent delete in normal flows.
- Modify: `src/admin.rs`
  - Reintroduce restore helpers and status-transition logic for soft-deleted blobs.
  - Make moderation actions restore from `deleted` instead of bypassing the preserved state.
- Create: `src/delete_policy.rs`
  - Hold shared preserve-first delete/restore helpers and small pure decision helpers that are easy to unit test.
- Modify: `src/blossom.rs`
  - Add or extend unit coverage for deleted-content visibility semantics if needed.
- Modify: `cloud-functions/process-blob/main.py`
  - Remove physical blob deletion from flagged-content moderation handling.
- Create: `cloud-functions/process-blob/test_process_blob.py`
  - Add regression coverage that flagged moderation updates metadata without deleting storage objects.
- Modify: `README.md`
  - Align endpoint and policy docs with preserve-first semantics for owner delete and admin delete.

## Chunk 1: Shared Delete/Restore Policy

### Task 1: Add failing Rust tests for delete-policy decisions

**Files:**
- Create: `src/delete_policy.rs`
- Test: `src/delete_policy.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn owner_delete_plan_is_soft_delete_not_hard_delete() {
    let plan = plan_user_delete(true);
    assert_eq!(plan, DeletePlan::SoftDelete);
}

#[test]
fn non_owner_delete_plan_unlinks_only() {
    let plan = plan_user_delete(false);
    assert_eq!(plan, DeletePlan::UnlinkOnly);
}

#[test]
fn restore_target_rejects_deleted_status() {
    assert!(parse_restore_status(Some("deleted")).is_err());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test delete_policy -- --nocapture`
Expected: FAIL because the new module/functions do not exist yet

- [ ] **Step 3: Write minimal implementation**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletePlan {
    SoftDelete,
    UnlinkOnly,
}

pub fn plan_user_delete(is_owner: bool) -> DeletePlan {
    if is_owner {
        DeletePlan::SoftDelete
    } else {
        DeletePlan::UnlinkOnly
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test delete_policy -- --nocapture`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/delete_policy.rs src/main.rs
git commit -m "test: add preserve-first delete policy helpers"
```

### Task 2: Add shared soft-delete and restore helpers

**Files:**
- Modify: `src/delete_policy.rs`
- Modify: `src/admin.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Write the failing test**

Add tests covering:

```rust
#[test]
fn restore_from_deleted_allows_active_pending_or_restricted() {
    assert_eq!(parse_restore_status(None).unwrap(), BlobStatus::Active);
    assert_eq!(parse_restore_status(Some("pending")).unwrap(), BlobStatus::Pending);
    assert_eq!(parse_restore_status(Some("restricted")).unwrap(), BlobStatus::Restricted);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test restore_from_deleted_allows_active_pending_or_restricted -- --nocapture`
Expected: FAIL on missing parser/helper behavior

- [ ] **Step 3: Write minimal implementation**

Implement shared helpers that:

- set `BlobStatus::Deleted`
- remove hashes from recent/user indexes
- preserve blob metadata, canonical bytes, and derivatives
- optionally record legal hold tombstones
- restore deleted blobs by status and re-index them
- purge caches after state changes

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test delete_policy -- --nocapture`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/delete_policy.rs src/admin.rs src/main.rs
git commit -m "feat: add shared soft-delete and restore helpers"
```

## Chunk 2: Route Behavior and Public Contract

### Task 3: Convert owner delete to preserve-first behavior

**Files:**
- Modify: `src/main.rs`
- Test: `src/delete_policy.rs`

- [ ] **Step 1: Write the failing test**

Add a regression test around the delete-plan branch selection:

```rust
#[test]
fn owner_delete_no_longer_selects_hard_delete_branch() {
    assert_eq!(plan_user_delete(true), DeletePlan::SoftDelete);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test owner_delete_no_longer_selects_hard_delete_branch -- --nocapture`
Expected: FAIL until `handle_delete` is switched to the shared helper

- [ ] **Step 3: Write minimal implementation**

Change `handle_delete` so that:

- owner delete stores provenance and audit as before
- owner delete soft-deletes the blob instead of calling `storage_delete`, `delete_blob_gcs_artifacts`, or `delete_blob_metadata`
- non-owner ref delete still unlinks only

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test delete_policy -- --nocapture`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/main.rs src/delete_policy.rs
git commit -m "feat: soft-delete owner removals"
```

### Task 4: Convert admin delete and restore routes

**Files:**
- Modify: `src/main.rs`
- Modify: `src/admin.rs`
- Modify: `README.md`

- [ ] **Step 1: Write the failing test**

Add tests covering restore parsing and admin status transitions:

```rust
#[test]
fn deleted_content_remains_publicly_blocked() {
    assert!(BlobStatus::Deleted.blocks_public_access());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test deleted_content_remains_publicly_blocked -- --nocapture`
Expected: FAIL only if extra coverage is missing; otherwise write the next missing route/helper test first

- [ ] **Step 3: Write minimal implementation**

Change admin delete so that it:

- writes audit log
- soft-deletes the blob
- preserves storage and metadata
- keeps legal hold/tombstone behavior

Add or re-register `POST /admin/api/restore`, and update the README plus landing-page endpoint description so normal delete semantics no longer claim permanent removal.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/main.rs src/admin.rs README.md
git commit -m "feat: restore admin soft-delete behavior"
```

## Chunk 3: Moderation Preservation

### Task 5: Remove destructive side effects from legacy moderation hook

**Files:**
- Modify: `cloud-functions/process-blob/main.py`
- Create: `cloud-functions/process-blob/test_process_blob.py`

- [ ] **Step 1: Write the failing test**

```python
def test_flagged_content_updates_metadata_without_deleting_blob():
    blob = Mock()
    thumb_blob = Mock()
    bucket = Mock(blob=Mock(side_effect=[blob, thumb_blob]))
    client = Mock(bucket=Mock(return_value=bucket))

    with patch("main.storage.Client", return_value=client):
        handle_moderation_result("bucket", "hash", {"is_flagged": True, "reason": "x", "scores": {}})

    blob.delete.assert_not_called()
    thumb_blob.delete.assert_not_called()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest cloud-functions/process-blob/test_process_blob.py -v`
Expected: FAIL because the handler still deletes storage objects

- [ ] **Step 3: Write minimal implementation**

Update `handle_moderation_result(...)` so flagged content:

- does not call `blob.delete()`
- does not delete thumbnails
- updates metadata status only

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest cloud-functions/process-blob/test_process_blob.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cloud-functions/process-blob/main.py cloud-functions/process-blob/test_process_blob.py
git commit -m "fix: preserve blobs on moderation removal"
```

## Chunk 4: Final Verification

### Task 6: Run full verification and record outcomes

**Files:**
- Modify: `docs/superpowers/plans/2026-04-02-preserve-first-delete-policy.md`

- [ ] **Step 1: Run focused Rust tests**

Run: `cargo test delete_policy -- --nocapture`
Expected: PASS

- [ ] **Step 2: Run full Rust test suite**

Run: `cargo test -q`
Expected: PASS

- [ ] **Step 3: Run Python moderation tests**

Run: `python3 -m unittest cloud-functions/process-blob/test_process_blob.py -v`
Expected: PASS

- [ ] **Step 4: Review docs and route text**

Confirm `README.md` and landing-page/API docs describe normal delete behavior as preserve-first and reserve true erasure for explicit RTBF/legal paths only.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs src/admin.rs src/delete_policy.rs src/blossom.rs cloud-functions/process-blob/main.py cloud-functions/process-blob/test_process_blob.py README.md docs/superpowers/plans/2026-04-02-preserve-first-delete-policy.md
git commit -m "feat: switch normal delete flows to preserve-first policy"
```
