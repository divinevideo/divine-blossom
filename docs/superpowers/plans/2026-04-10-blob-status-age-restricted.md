# `BlobStatus::AgeRestricted` Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop returning `404` for legacy adult/age-restricted content (e.g. Vine archive imports) and instead return `401` so the web player triggers its age-verification UI, by introducing a new `BlobStatus::AgeRestricted` variant that is distinct from the existing shadow-ban `Restricted`.

**Architecture:**
1. New `BlobStatus::AgeRestricted` variant, serialized as `"age_restricted"` in KV.
2. A single helper `BlobMetadata::access_for(requester_pubkey, is_admin) -> BlobAccess` collapses the ~10 duplicated gate sites in `src/main.rs` into one decision point with three outcomes: `Allowed`, `NotFound` (existing Banned / Restricted shadow-ban semantics), and `AgeGated` (new — returns `401 age_restricted`).
3. The moderation webhook (`POST /admin/moderate`) and `delete_policy::parse_restore_status` both learn the `AGE_RESTRICTED` action and route it to the new variant. Existing `RESTRICT` / `QUARANTINE` still go to `Restricted` so true shadow-ban behavior is preserved.
4. A standalone Python backfill script under `scripts/` reads the `blossom_metadata` Fastly KV store, finds existing `status: "restricted"` blobs, reports a per-owner breakdown, and (only with `--apply`) promotes them to `status: "age_restricted"`. Default is dry-run.

**Tech Stack:** Rust (Fastly Compute), serde, `fastly::kv_store`, Python (backfill script using `requests`), Fastly KV API.

---

## Task list summary

1. Add `BlobStatus::AgeRestricted` variant + serde rename + unit tests
2. Add `BlobAccess` enum + `BlobMetadata::access_for` helper + unit tests
3. Refactor all `src/main.rs` gate sites to use the helper
4. Update moderation webhook + admin moderate action + delete_policy parse to map `AGE_RESTRICTED`
5. Update `metadata::list_blobs_with_metadata` so `include_restricted=true` also includes `AgeRestricted`
6. Update `admin::handle_admin_scan_flagged` to include `AgeRestricted` in its match
7. Manual smoke test against staging hashes
8. Build, deploy to Fastly Compute, purge cache, verify with curl
9. Backfill script — dry-run mode + per-owner report
10. Run dry-run, review, then `--apply` for the agreed scope
11. Verify the four known failing hashes return `401` and play with age-gate UI
12. Update `MEMORY.md` with the new status semantics

---

## File Structure

**Modify:**
- `src/blossom.rs` — add variant, helper enum, `access_for` method, tests
- `src/main.rs` — replace ~10 inline gate blocks with `meta.access_for(...)`, map `AgeRestricted` action in `handle_admin_moderate`
- `src/admin.rs` — accept `AGE_RESTRICTED` in `handle_admin_moderate_action`, include `AgeRestricted` in `handle_admin_scan_flagged`, include in bulk-approve
- `src/delete_policy.rs` — accept `AGE_RESTRICTED` in `parse_restore_status`
- `src/metadata.rs` — `list_blobs_with_metadata` includes `AgeRestricted` when `include_restricted=true`
- `MEMORY.md` (project memory under `docs/` if applicable, or `~/.claude/projects/.../memory/`) — document the new status

**Create:**
- `scripts/backfill_restricted_to_age_restricted.py` — dry-run-by-default backfill against the `blossom_metadata` Fastly KV store

**No changes to:** `src/storage.rs`, `src/error.rs` (existing `AuthRequired` → `401` is reused), VCL, Cloud Run services. The `should_hide_direct_blob` audio-alias path is unrelated and untouched.

---

## Chunk 1: Data model + helper

### Task 1: Add `BlobStatus::AgeRestricted` variant

**Files:**
- Modify: `src/blossom.rs` (around lines 105-129)

- [ ] **Step 1: Write the failing serde test**

In `src/blossom.rs` tests module, add:

```rust
#[test]
fn blob_status_serializes_age_restricted_with_underscore() {
    let json = serde_json::to_string(&BlobStatus::AgeRestricted).unwrap();
    assert_eq!(json, "\"age_restricted\"");
}

#[test]
fn blob_status_deserializes_age_restricted() {
    let parsed: BlobStatus = serde_json::from_str("\"age_restricted\"").unwrap();
    assert_eq!(parsed, BlobStatus::AgeRestricted);
}

#[test]
fn blob_status_age_restricted_does_not_block_public_access() {
    // AgeRestricted should NOT be in blocks_public_access (that returns 404).
    // It instead surfaces as an age-gate via access_for.
    assert!(!BlobStatus::AgeRestricted.blocks_public_access());
}

#[test]
fn blob_status_age_restricted_requires_owner_auth() {
    assert!(BlobStatus::AgeRestricted.requires_owner_auth());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```
cargo test -p fastly-blossom blob_status_ -- --nocapture
```

Expected: compile error (variant does not exist).

- [ ] **Step 3: Add the variant**

Edit `src/blossom.rs` enum and helpers:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlobStatus {
    Active,
    Restricted,
    Pending,
    Banned,
    Deleted,
    /// Age-gated content. Non-owners receive 401 (auth_required) so the
    /// client can present an age-verification UI. Distinct from `Restricted`,
    /// which is shadow-banned and 404s to non-owners.
    #[serde(rename = "age_restricted")]
    AgeRestricted,
}

impl BlobStatus {
    pub fn blocks_public_access(self) -> bool {
        matches!(self, BlobStatus::Banned | BlobStatus::Deleted)
    }

    pub fn requires_owner_auth(self) -> bool {
        matches!(self, BlobStatus::Restricted | BlobStatus::AgeRestricted)
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```
cargo test -p fastly-blossom blob_status_
```

Expected: 4 new tests pass; existing `BlobStatus` tests still pass.

- [ ] **Step 5: Commit**

```
git add src/blossom.rs
git commit -m "feat(blossom): add BlobStatus::AgeRestricted variant"
```

---

### Task 2: Add `BlobAccess` enum + `BlobMetadata::access_for`

**Files:**
- Modify: `src/blossom.rs` (alongside `BlobStatus`)

- [ ] **Step 1: Write failing tests for access_for**

```rust
#[cfg(test)]
mod access_for_tests {
    use super::*;

    fn fixture(status: BlobStatus, owner: &str) -> BlobMetadata {
        BlobMetadata {
            sha256: "x".into(),
            size: 1,
            mime_type: "video/mp4".into(),
            uploaded: "2026-04-10T00:00:00Z".into(),
            owner: owner.into(),
            status,
            ..Default::default()
        }
    }

    #[test]
    fn admin_always_allowed() {
        let m = fixture(BlobStatus::Banned, "owner");
        assert_eq!(m.access_for(None, true), BlobAccess::Allowed);
    }

    #[test]
    fn active_allowed_for_anyone() {
        let m = fixture(BlobStatus::Active, "owner");
        assert_eq!(m.access_for(None, false), BlobAccess::Allowed);
        assert_eq!(m.access_for(Some("stranger"), false), BlobAccess::Allowed);
    }

    #[test]
    fn banned_is_notfound_to_everyone_non_admin() {
        let m = fixture(BlobStatus::Banned, "owner");
        assert_eq!(m.access_for(Some("owner"), false), BlobAccess::NotFound);
    }

    #[test]
    fn deleted_is_notfound_to_everyone_non_admin() {
        let m = fixture(BlobStatus::Deleted, "owner");
        assert_eq!(m.access_for(Some("owner"), false), BlobAccess::NotFound);
    }

    #[test]
    fn restricted_is_notfound_to_non_owner_and_anonymous() {
        let m = fixture(BlobStatus::Restricted, "owner");
        assert_eq!(m.access_for(None, false), BlobAccess::NotFound);
        assert_eq!(m.access_for(Some("stranger"), false), BlobAccess::NotFound);
    }

    #[test]
    fn restricted_is_allowed_to_owner() {
        let m = fixture(BlobStatus::Restricted, "owner");
        assert_eq!(m.access_for(Some("owner"), false), BlobAccess::Allowed);
        // Case-insensitive comparison
        assert_eq!(m.access_for(Some("OWNER"), false), BlobAccess::Allowed);
    }

    #[test]
    fn age_restricted_is_age_gated_to_non_owner_and_anonymous() {
        let m = fixture(BlobStatus::AgeRestricted, "owner");
        assert_eq!(m.access_for(None, false), BlobAccess::AgeGated);
        assert_eq!(m.access_for(Some("stranger"), false), BlobAccess::AgeGated);
    }

    #[test]
    fn age_restricted_is_allowed_to_owner() {
        let m = fixture(BlobStatus::AgeRestricted, "owner");
        assert_eq!(m.access_for(Some("owner"), false), BlobAccess::Allowed);
    }

    #[test]
    fn pending_is_allowed() {
        // Existing behavior: Pending blobs are publicly served while waiting
        // for moderation. Don't change that here.
        let m = fixture(BlobStatus::Pending, "owner");
        assert_eq!(m.access_for(None, false), BlobAccess::Allowed);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```
cargo test -p fastly-blossom access_for_tests
```

Expected: compile error (`BlobAccess` does not exist, `access_for` does not exist).

- [ ] **Step 3: Implement `BlobAccess` + `access_for`**

Add to `src/blossom.rs` (just after the `BlobStatus` impl):

```rust
/// Result of evaluating whether a viewer is allowed to fetch a blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobAccess {
    /// Viewer may fetch the content.
    Allowed,
    /// Hide the existence of the blob (Banned / Deleted / shadow-Restricted to non-owners).
    /// Maps to HTTP 404.
    NotFound,
    /// Age-gated content. Maps to HTTP 401 so the client can present an age-verification UI.
    AgeGated,
}

impl BlobMetadata {
    /// Decide whether a viewer is allowed to access this blob.
    ///
    /// `requester_pubkey` is the authenticated viewer's pubkey, if any.
    /// `is_admin` is true when the request carries a valid admin Bearer token.
    pub fn access_for(&self, requester_pubkey: Option<&str>, is_admin: bool) -> BlobAccess {
        if is_admin {
            return BlobAccess::Allowed;
        }

        let is_owner = requester_pubkey
            .map(|p| p.eq_ignore_ascii_case(&self.owner))
            .unwrap_or(false);

        match self.status {
            BlobStatus::Active | BlobStatus::Pending => BlobAccess::Allowed,
            BlobStatus::Banned | BlobStatus::Deleted => BlobAccess::NotFound,
            BlobStatus::Restricted => {
                if is_owner {
                    BlobAccess::Allowed
                } else {
                    BlobAccess::NotFound
                }
            }
            BlobStatus::AgeRestricted => {
                if is_owner {
                    BlobAccess::Allowed
                } else {
                    BlobAccess::AgeGated
                }
            }
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```
cargo test -p fastly-blossom access_for_tests
```

Expected: all 9 tests pass.

- [ ] **Step 5: Commit**

```
git add src/blossom.rs
git commit -m "feat(blossom): add BlobMetadata::access_for + BlobAccess enum"
```

---

## Chunk 2: Wire the helper through `src/main.rs`

This chunk replaces every inline `if meta.status == BlobStatus::Restricted` block with a single `match meta.access_for(...)`. Each gate site is one task; do them sequentially because they share the same import + helper but each call site has slightly different request/response context.

For every site, the new shape is:

```rust
let requester = optional_auth(&req, AuthAction::List)
    .ok()
    .flatten()
    .map(|a| a.pubkey);
match meta.access_for(requester.as_deref(), is_admin) {
    BlobAccess::Allowed => {}
    BlobAccess::NotFound => {
        return Err(BlossomError::NotFound("Blob not found".into()));
    }
    BlobAccess::AgeGated => {
        return Err(BlossomError::AuthRequired("age_restricted".into()));
    }
}
```

For HEAD endpoints (which don't have admin/auth context), the call simplifies to:

```rust
match meta.access_for(None, false) {
    BlobAccess::Allowed => {}
    BlobAccess::NotFound => return Err(BlossomError::NotFound("Content not found".into())),
    BlobAccess::AgeGated => return Err(BlossomError::AuthRequired("age_restricted".into())),
}
```

### Task 3: `handle_get_blob` thumbnail branch (`src/main.rs:374-391`)

- [ ] **Step 1: Replace the inline branch with `access_for`**

Read `src/main.rs:364-424` and replace the `if let Ok(Some(meta)) = ... { if !is_admin { ... } }` block with:

```rust
let mut is_age_gated_thumb = false;
let mut is_restricted_thumb = false;
if let Ok(Some(meta)) = get_blob_metadata(video_hash) {
    let requester = optional_auth(&req, AuthAction::List)
        .ok()
        .flatten()
        .map(|a| a.pubkey);
    match meta.access_for(requester.as_deref(), is_admin) {
        BlobAccess::Allowed => {
            // Distinguish so cache headers stay private when the owner views their own restricted thumb.
            if meta.status == BlobStatus::Restricted || meta.status == BlobStatus::AgeRestricted {
                is_restricted_thumb = true;
            }
        }
        BlobAccess::NotFound => {
            return Err(BlossomError::NotFound("Blob not found".into()));
        }
        BlobAccess::AgeGated => {
            is_age_gated_thumb = true;
        }
    }
}

if is_age_gated_thumb {
    return Err(BlossomError::AuthRequired("age_restricted".into()));
}
```

Then thread `is_restricted_thumb` into the existing `set_thumb_cache` closure (replacing the old `is_restricted` variable).

- [ ] **Step 2: Build**

```
cargo build -p fastly-blossom
```

Expected: compiles cleanly.

- [ ] **Step 3: Commit**

```
git add src/main.rs
git commit -m "refactor(main): use access_for for thumbnail gate"
```

### Task 4: `handle_get_blob` main blob branch (`src/main.rs:439-458`)

- [ ] Replace the `if let Some(ref meta) = metadata { if !is_admin { ... } }` block with the `access_for` shape above. Keep the `is_partial`/`is_restricted`/`metadata` plumbing for cache headers — derive `is_restricted` from `meta.status == BlobStatus::Restricted || meta.status == BlobStatus::AgeRestricted` after the gate.
- [ ] Build, then commit:

```
git add src/main.rs
git commit -m "refactor(main): use access_for for handle_get_blob"
```

### Task 5: `handle_head_blob` (`src/main.rs:578-585`)

- [ ] Replace the `if metadata.status == BlobStatus::Restricted || == BlobStatus::Banned` block with `match metadata.access_for(None, false) { ... }`. Keep the existing `should_hide_direct_blob` call as-is.
- [ ] Build + commit.

### Task 6: `handle_get_hls_master` (`src/main.rs:621-641`)

- [ ] Replace the if/else chain with `match meta.access_for(requester.as_deref(), is_admin)`. Note this branch wraps in `if let Some(ref meta) = metadata { ... } else { return NotFound }` — preserve that envelope.
- [ ] Build + commit.

### Task 7: `handle_head_hls_master` (`src/main.rs:766-769`)

- [ ] Replace the inline match with `metadata.access_for(None, false)`.
- [ ] Build + commit.

### Task 8: `handle_get_hls_content` (`src/main.rs:840-856`)

- [ ] Same shape as Task 6. Preserve the `is_restricted` variable so cache headers stay private when the owner is fetching their own restricted/age-restricted segments.
- [ ] Build + commit.

### Task 9: `handle_head_hls_content` (`src/main.rs:986-992`)

- [ ] Replace the inline match with `meta.access_for(None, false)`.
- [ ] Build + commit.

### Task 10: `serve_transcript_by_hash` (`src/main.rs:1453-1471`)

- [ ] Replace the nested if-else blocks. Note `req` is `Option<&Request>` here, so:

```rust
let (requester, is_admin) = match req {
    Some(r) => {
        let admin = admin::validate_bearer_token(r).is_ok();
        let pk = optional_auth(r, AuthAction::List).ok().flatten().map(|a| a.pubkey);
        (pk, admin)
    }
    None => (None, false),
};
match metadata.access_for(requester.as_deref(), is_admin) {
    BlobAccess::Allowed => {}
    BlobAccess::NotFound => return Err(BlossomError::NotFound("Content not found".into())),
    BlobAccess::AgeGated => return Err(BlossomError::AuthRequired("age_restricted".into())),
}
```

- [ ] Build + commit.

### Task 11: `handle_head_transcript_by_hash` (`src/main.rs:1602-1604`)

- [ ] Replace with `metadata.access_for(None, false)`.
- [ ] Build + commit.

### Task 12: `handle_get_quality_variant` (`src/main.rs:2183-2200`)

- [ ] Same shape as Task 6.
- [ ] Build + commit.

### Task 13: `handle_head_quality_variant` (`src/main.rs:2295-2297`)

- [ ] Replace with `metadata.access_for(None, false)`.
- [ ] Build + commit.

### Task 14: Sanity build of the whole crate

- [ ] **Step 1: Full build**

```
cargo build -p fastly-blossom
cargo test -p fastly-blossom
```

Expected: clean build, all existing tests pass, new tests pass.

- [ ] **Step 2: Commit any leftover formatting**

```
cargo fmt -p fastly-blossom
git diff
git commit -am "style: cargo fmt after access_for refactor" || true
```

---

## Chunk 3: Webhook + admin + delete_policy + listing

### Task 15: Moderation webhook routes `AGE_RESTRICTED` to the new variant

**Files:**
- Modify: `src/main.rs:4402-4413`

- [ ] **Step 1: Edit the action map**

```rust
let new_status = match action.to_uppercase().as_str() {
    "BLOCK" | "BAN" | "PERMANENT_BAN" => BlobStatus::Banned,
    "AGE_RESTRICTED" => BlobStatus::AgeRestricted,
    "RESTRICT" | "QUARANTINE" => BlobStatus::Restricted,
    "APPROVE" | "SAFE" => BlobStatus::Active,
    _ => {
        return Err(BlossomError::BadRequest(format!(
            "Unknown action: {}. Expected BLOCK, RESTRICT, QUARANTINE, AGE_RESTRICTED, or APPROVE",
            action
        )));
    }
};
```

- [ ] **Step 2: Build**

```
cargo build -p fastly-blossom
```

- [ ] **Step 3: Commit**

```
git add src/main.rs
git commit -m "feat(moderation): route AGE_RESTRICTED action to AgeRestricted status"
```

### Task 16: Admin moderate-action UI maps `AGE_RESTRICT`

**Files:**
- Modify: `src/admin.rs:783-790` (the `match moderate_req.action`)

- [ ] **Step 1: Add `"AGE_RESTRICT"` arm**

```rust
let new_status = match moderate_req.action.to_uppercase().as_str() {
    "BAN" | "BLOCK" => BlobStatus::Banned,
    "RESTRICT" => BlobStatus::Restricted,
    "AGE_RESTRICT" | "AGE_RESTRICTED" => BlobStatus::AgeRestricted,
    "APPROVE" | "ACTIVE" => BlobStatus::Active,
    _ => return Err(BlossomError::BadRequest("Unknown moderation action".into())),
};
```

- [ ] **Step 2: Build + commit**

```
cargo build -p fastly-blossom
git add src/admin.rs
git commit -m "feat(admin): accept AGE_RESTRICT moderation action"
```

### Task 17: `handle_admin_scan_flagged` includes `AgeRestricted`

**Files:**
- Modify: `src/admin.rs:961-975`

- [ ] **Step 1: Add the variant to the match + a new bucket in the response**

```rust
let mut age_restricted: Vec<String> = Vec::new();
// ...
match meta.status {
    BlobStatus::Banned => banned.push(hash.clone()),
    BlobStatus::Restricted => restricted.push(hash.clone()),
    BlobStatus::AgeRestricted => age_restricted.push(hash.clone()),
    BlobStatus::Active => active += 1,
    BlobStatus::Pending => pending += 1,
    BlobStatus::Deleted => not_found += 1,
},
```

Then add `"age_restricted": age_restricted` to the JSON response.

- [ ] **Step 2: Update `handle_admin_bulk_approve` similarly**

`src/admin.rs:892` — extend the condition:

```rust
if meta.status == BlobStatus::Banned
    || meta.status == BlobStatus::Restricted
    || meta.status == BlobStatus::AgeRestricted
{
    // ...promote to Active...
}
```

- [ ] **Step 3: Build + commit**

```
cargo build -p fastly-blossom
git add src/admin.rs
git commit -m "feat(admin): handle AgeRestricted in scan-flagged + bulk-approve"
```

### Task 18: `delete_policy::parse_restore_status` accepts `AGE_RESTRICTED`

**Files:**
- Modify: `src/delete_policy.rs:23-36`

- [ ] **Step 1: Add a failing test**

In the existing tests module:

```rust
#[test]
fn restore_target_accepts_age_restricted() {
    assert_eq!(
        parse_restore_status(Some("age_restricted")).unwrap(),
        BlobStatus::AgeRestricted
    );
    assert_eq!(
        parse_restore_status(Some("AGE_RESTRICTED")).unwrap(),
        BlobStatus::AgeRestricted
    );
}
```

- [ ] **Step 2: Run + verify it fails**

```
cargo test -p fastly-blossom restore_target_accepts_age_restricted
```

Expected: fails (BadRequest "Unknown restore status").

- [ ] **Step 3: Add the arm**

```rust
"AGE_RESTRICT" | "AGE_RESTRICTED" => Ok(BlobStatus::AgeRestricted),
```

- [ ] **Step 4: Run test, expect pass**

```
cargo test -p fastly-blossom restore_target_accepts_age_restricted
```

- [ ] **Step 5: Commit**

```
git add src/delete_policy.rs
git commit -m "feat(delete_policy): accept AGE_RESTRICTED in parse_restore_status"
```

### Task 19: `metadata::list_blobs_with_metadata` includes `AgeRestricted` when listing

**Files:**
- Modify: `src/metadata.rs:497-515`

- [ ] **Step 1: Update the filter**

```rust
if metadata.status == BlobStatus::Active
    || (include_restricted
        && (metadata.status == BlobStatus::Restricted
            || metadata.status == BlobStatus::AgeRestricted))
{
    results.push(metadata);
}
```

- [ ] **Step 2: Build + commit**

```
cargo build -p fastly-blossom
git add src/metadata.rs
git commit -m "feat(metadata): include AgeRestricted in list_blobs_with_metadata"
```

### Task 20: Final test sweep

- [ ] **Step 1: Run the full test suite**

```
cargo test -p fastly-blossom
```

Expected: green.

- [ ] **Step 2: Format**

```
cargo fmt -p fastly-blossom
```

- [ ] **Step 3: Commit any formatting changes**

---

## Chunk 4: Deploy + verify

### Task 21: Local serve + smoke test

- [ ] **Step 1:** `fastly compute serve` (in another terminal)
- [ ] **Step 2:** Manually curl a fake `Active` and a fake `Restricted` and a fake `AgeRestricted` blob if local fixtures exist; otherwise skip and rely on staging.

### Task 22: Deploy to Fastly Compute

- [ ] **Step 1: Publish + purge** (per project convention)

```
fastly compute publish --comment "Add BlobStatus::AgeRestricted; route AGE_RESTRICTED action; surface 401 instead of 404 to non-owners" \
  && fastly purge --all --service-id pOvEEWykEbpnylqst1KTrR
```

- [ ] **Step 2: Wait for propagation** (several minutes — see CLAUDE.md note)

### Task 23: Confirm baseline behavior didn't regress for `Active` blobs

- [ ] **Step 1:**

```
curl -sI "https://media.divine.video/5da39e5f34971e6840f59cb9335ef9bf4996798f86cf5eb966808d1fb016b1ef?cb=$RANDOM" | head
```

Expected: `HTTP/2 200`.

### Task 24: Confirm existing `Restricted` blobs still 404 (shadow-ban preserved)

- [ ] **Step 1:** Same curl as Task 23 against one of the four known failing hashes BEFORE the backfill.

Expected: `HTTP/2 404` (still Restricted in KV, not yet promoted). This proves the shadow-ban path survived the refactor.

---

## Chunk 5: Backfill

### Task 25: Backfill script — list + report

**Files:**
- Create: `scripts/backfill_restricted_to_age_restricted.py`

- [ ] **Step 1: Write the script**

```python
#!/usr/bin/env python3
"""
Promote `BlobStatus::Restricted` blobs to `BlobStatus::AgeRestricted` in the
Fastly KV store `blossom_metadata`.

Default mode is dry-run: scans all blob:* keys, fetches each metadata record,
groups by owner pubkey, and prints how many would be promoted.

Pass --apply to actually write the new status. The script never deletes a key
and only mutates the `status` field.

Required env:
  FASTLY_API_TOKEN
  FASTLY_KV_STORE_ID    (default: 07pggadpgda8plydnkt5el)

Optional env:
  ONLY_OWNER_PUBKEYS    comma-separated; if set, only blobs owned by these
                        pubkeys are eligible for promotion (otherwise all
                        currently-Restricted blobs are eligible).
"""
import argparse
import json
import os
import sys
import time
from collections import defaultdict
from urllib.parse import urlencode

import requests

KV_STORE_ID_DEFAULT = "07pggadpgda8plydnkt5el"
KV_API = "https://api.fastly.com/resources/stores/kv"
PAGE_LIMIT = 1000


def session():
    token = os.environ["FASTLY_API_TOKEN"]
    s = requests.Session()
    s.headers.update({"Fastly-Key": token, "Accept": "application/json"})
    return s


def list_blob_keys(s, store_id):
    cursor = None
    while True:
        params = {"prefix": "blob", "limit": PAGE_LIMIT}
        if cursor:
            params["cursor"] = cursor
        url = f"{KV_API}/{store_id}/keys?{urlencode(params)}"
        r = s.get(url, timeout=30)
        r.raise_for_status()
        body = r.json()
        for key in body.get("data", []):
            if key.startswith("blob:") and len(key) == len("blob:") + 64:
                yield key
        cursor = body.get("meta", {}).get("next_cursor")
        if not cursor:
            return


def get_metadata(s, store_id, key):
    url = f"{KV_API}/{store_id}/keys/{key}"
    r = s.get(url, timeout=30)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def put_metadata(s, store_id, key, metadata):
    url = f"{KV_API}/{store_id}/keys/{key}"
    r = s.put(url, data=json.dumps(metadata), timeout=30,
              headers={"Content-Type": "application/octet-stream"})
    r.raise_for_status()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true",
                    help="Actually write changes (default: dry-run)")
    ap.add_argument("--store-id", default=os.environ.get("FASTLY_KV_STORE_ID", KV_STORE_ID_DEFAULT))
    args = ap.parse_args()

    only_owners = {p.strip().lower() for p in os.environ.get("ONLY_OWNER_PUBKEYS", "").split(",") if p.strip()}

    s = session()

    by_owner = defaultdict(int)
    eligible = []
    scanned = 0
    restricted_total = 0

    print(f"Scanning KV store {args.store_id} for blob:* keys...", file=sys.stderr)

    for key in list_blob_keys(s, args.store_id):
        scanned += 1
        if scanned % 500 == 0:
            print(f"  scanned {scanned} blob keys, {restricted_total} restricted...", file=sys.stderr)

        meta = get_metadata(s, args.store_id, key)
        if not meta:
            continue
        if meta.get("status") != "restricted":
            continue
        restricted_total += 1

        owner = (meta.get("owner") or "").lower()
        if only_owners and owner not in only_owners:
            continue

        by_owner[owner] += 1
        eligible.append((key, meta))

    print(f"\nScan complete: {scanned} blob records, {restricted_total} currently restricted, "
          f"{len(eligible)} eligible for promotion.\n", file=sys.stderr)

    print("Per-owner breakdown of eligible blobs:")
    for owner, count in sorted(by_owner.items(), key=lambda kv: -kv[1]):
        print(f"  {owner}  {count}")

    if not args.apply:
        print("\nDry-run only. Re-run with --apply to promote these blobs.", file=sys.stderr)
        return 0

    print(f"\nPromoting {len(eligible)} blobs to age_restricted...", file=sys.stderr)
    promoted = 0
    failed = 0
    for key, meta in eligible:
        meta["status"] = "age_restricted"
        try:
            put_metadata(s, args.store_id, key, meta)
            promoted += 1
        except Exception as e:
            failed += 1
            print(f"  FAILED {key}: {e}", file=sys.stderr)
        if promoted % 100 == 0:
            print(f"  promoted {promoted}/{len(eligible)}...", file=sys.stderr)
        time.sleep(0.02)  # gentle pacing to avoid KV write hot-spots

    print(f"\nDone. Promoted: {promoted}, Failed: {failed}", file=sys.stderr)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Mark executable**

```
chmod +x scripts/backfill_restricted_to_age_restricted.py
```

- [ ] **Step 3: Commit**

```
git add scripts/backfill_restricted_to_age_restricted.py
git commit -m "feat(scripts): add Restricted -> AgeRestricted backfill (dry-run by default)"
```

### Task 26: Run dry-run to see the population

- [ ] **Step 1:**

```
FASTLY_API_TOKEN=<token> ./scripts/backfill_restricted_to_age_restricted.py
```

- [ ] **Step 2: Review the per-owner breakdown.** If almost all are owned by `vine-archive-importer`-style pubkeys (e.g. those matching the four known hashes), proceed to apply against everything. If the breakdown shows other pubkeys with non-trivial counts, narrow scope via `ONLY_OWNER_PUBKEYS=<csv>` and re-run dry-run before applying.

### Task 27: Apply the backfill

- [ ] **Step 1:** Run with the agreed scope:

```
FASTLY_API_TOKEN=<token> [ONLY_OWNER_PUBKEYS=...] \
  ./scripts/backfill_restricted_to_age_restricted.py --apply
```

- [ ] **Step 2:** Note the promoted/failed counts. If there are failures, inspect the listed keys and retry individually.

### Task 28: Purge VCL cache for promoted blobs

The script does NOT call `purge_vcl_cache` because that's an internal Compute helper. The simplest path is a blanket purge after the backfill:

- [ ] **Step 1:** Purge all on the service:

```
fastly purge --all --service-id pOvEEWykEbpnylqst1KTrR
```

- [ ] **Step 2:** Wait for propagation.

---

## Chunk 6: End-to-end verification

### Task 29: Confirm the four known failing hashes now return `401`

- [ ] **Step 1:**

```
for h in 1a2f755fc7dfdcb267b945e76ad959ff585c2990e88fd5ba088098e5d1b43cea \
         6e4a6f2021867d43fdee1d490af8333b18d14684a87b4eee3d520092aec39765 \
         f8ae52951ca4c5d1b90b8790bda4f5c354f783dce063d77e25029b498889b946 \
         d56e525a15ef23d4dacce354a9d32fe3e50559971d9532f7e4ad8d21443d716a; do
  echo "=== $h ==="
  curl -sI "https://media.divine.video/$h?cb=$RANDOM" | head -3
done
```

Expected: `HTTP/2 401` for each (no longer 404).

- [ ] **Step 2: Confirm the working hashes still return `200`**

```
for h in 5da39e5f34971e6840f59cb9335ef9bf4996798f86cf5eb966808d1fb016b1ef \
         e2d44560303bf68a9dd04cf6172ee4e053df1e6443bb359bfe58ebbfd8987601; do
  echo "=== $h ==="
  curl -sI "https://media.divine.video/$h?cb=$RANDOM" | head -3
done
```

Expected: `HTTP/2 200`.

### Task 30: Confirm the web player triggers age-gate UI

- [ ] **Step 1:** Open Divine Web `/hashtag/twerking` and scroll to one of the four hashes.
- [ ] **Step 2:** Verify age-verification UI appears (instead of permanent error).

### Task 31: Update project memory

- [ ] **Step 1:** Update `~/.claude/projects/-Users-rabble-code-divine-divine-blossom/memory/MEMORY.md` to add a section noting the new `BlobStatus::AgeRestricted` semantics, the moderation webhook action mapping, and the backfill script.
- [ ] **Step 2:** No commit needed (memory is outside the repo).

---

## Out of scope (intentionally not in this plan)

- Changing how `moderation-api.divine.video` decides which content to flag as adult — that classifier already exists and labels things via `AGE_RESTRICTED`; this plan only fixes how Blossom translates that label into an HTTP response.
- Changing the web player's age-verification UI — the player already triggers it on `401`/`403`, which is what this plan starts emitting.
- Removing the existing `BlobStatus::Restricted` shadow-ban variant — it stays as a distinct outcome for true takedowns.
- Cloud Run / VCL changes — none required.
