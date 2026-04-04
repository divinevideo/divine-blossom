# Preserve-First Delete Policy Design

## Problem

`divine-blossom` currently mixes two incompatible deletion policies:

1. Public serving already treats `deleted`, `banned`, and unauthorized `restricted` content as opaque `404`, which is the right "stop serving" behavior.
2. Some delete paths still physically remove media bytes and metadata, which makes moderation and admin actions irreversible.

That mismatch means operators can think they are only removing content from public view while the system is actually destroying the stored blob and derivatives.

## Goals

- Preserve uploaded media and derivatives for all normal delete and moderation flows.
- Stop public serving of removed content with opaque `404` responses.
- Allow admins to restore soft-deleted content later.
- Keep true irreversible erasure out of normal product flows for now.
- Align code with the documented soft-delete contract.

## Non-Goals

- Implement a new legal RTBF erase API in this change.
- Change the public response shape for moderated or deleted blobs.
- Redesign the moderation model beyond removing destructive side effects.

## Recommended Approach

Make metadata status the only source of truth for ordinary removals.

- Owner delete becomes a soft-delete that sets `BlobStatus::Deleted`.
- Admin delete becomes a soft-delete that sets `BlobStatus::Deleted`.
- Moderation actions continue to set `Restricted`, `Banned`, or `Active`, but never delete storage.
- Restore moves a soft-deleted blob back to `Active`, `Pending`, or `Restricted`.

Stored media, thumbnails, HLS, subtitles, and related artifacts remain in storage unless a future explicit erase-only path is invoked.

## Serving Semantics

Public serving behavior remains intentionally opaque:

- `Deleted` returns `404`.
- `Banned` returns `404`.
- `Restricted` returns `404` unless the owner is authenticated.

This means the operational change is preservation, not exposure. Removed content remains hidden from the public even though bytes are still retained.

## Delete Semantics

### Owner Delete

`DELETE /<sha256>` should:

- validate ownership as it does today
- change blob status to `deleted`
- remove the blob from public-facing user and recent indexes
- preserve storage objects and derivative artifacts
- purge caches
- retain enough metadata for provenance and restore

### Admin Delete

`POST /admin/api/delete` should:

- require admin auth as it does today
- write an audit log
- change blob status to `deleted`
- remove the blob from public-facing user and recent indexes
- preserve storage objects and derivative artifacts
- optionally record legal hold / tombstone data without erasing bytes

### Moderation

Moderation actions should only update metadata state. Any path that currently calls storage deletion for flagged content must stop doing that.

## Restore Semantics

`POST /admin/api/restore` should restore a soft-deleted blob to one of:

- `active`
- `pending`
- `restricted`

Restore should re-add the blob to the appropriate indexes and purge caches so the restored state takes effect immediately.

## Data and Audit Expectations

- Blob metadata must survive soft-delete.
- Provenance and audit records must remain queryable after soft-delete.
- Legal hold remains compatible with preservation by blocking re-upload without requiring physical deletion.

## Implementation Notes

The current repo already contains a prior soft-delete implementation in commit `09749df`. This change should restore that policy direction while also extending it to owner delete and removing the destructive legacy moderation behavior.

The main files expected to change are:

- `src/main.rs`
- `src/admin.rs`
- `src/blossom.rs`
- `cloud-functions/process-blob/main.py`

## Testing Strategy

- Add Fastly unit tests proving owner delete transitions status to `deleted` without invoking storage deletion.
- Add Fastly unit tests proving admin delete transitions status to `deleted` without invoking storage deletion.
- Add tests covering restore from `deleted` back to an allowed status.
- Keep or extend tests proving public requests still return opaque `404` for deleted content.
- Add a regression test for the legacy moderation function so flagged content updates metadata without deleting the underlying blob.

## Rollout Notes

- This is a behavior change in deletion policy, not in public serving semantics.
- Existing public `404`s for moderated/deleted content will continue.
- Operationally, the important difference after rollout is that normal product removals become reversible.
