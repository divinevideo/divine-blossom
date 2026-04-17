# Creator-delete contract

The cross-service contract between Blossom and callers (primarily `divine-moderation-service`) for creator-initiated video deletes triggered by a signed kind 5 event. This doc is the source of truth; read the code if a detail here and the code disagree, and update the doc.

## Endpoints

Two admin endpoints accept creator-delete requests. Both dispatch to the same shared helper (`delete_policy::handle_creator_delete`) and return the same core response fields. Pick based on caller convenience.

| Endpoint | Handler | Auth | Typical caller |
|---|---|---|---|
| `POST /admin/moderate` | `main::handle_admin_moderate` | Bearer token (`webhook_secret` from Secret Store) | moderation-service webhook |
| `POST /admin/api/moderate` | `admin::handle_admin_moderate_action` | Admin Bearer or admin session | admin UI, internal tooling |

## Request

```json
{
  "sha256": "<64-char hex blob hash>",
  "action": "DELETE",
  "reason": "Creator-initiated deletion via kind 5"
}
```

- `sha256` — required. 64 hex characters. Invalid format returns `400`.
- `action` — required. Case-insensitive. Must be `"DELETE"` for this path.
- `reason` — optional. Free-text; recorded in audit entries. Defaults to `"Creator-initiated deletion via kind 5"` if omitted.

## Response (success)

```json
{
  "success": true,
  "sha256": "<same as request>",
  "old_status": "active",
  "new_status": "deleted",
  "physical_deleted": false,
  "physical_delete_skipped": true
}
```

Field semantics:

| Field | Type | Meaning |
|---|---|---|
| `success` | bool | Always `true` when HTTP 200. |
| `sha256` | string | Echoes the request blob hash. |
| `old_status` | string | Lowercase `BlobStatus` the blob was in before this call. Current values: `active`, `restricted`, `agerestricted`, `pending`, `banned`, `deleted`. See [note on status rendering](#note-status-string-rendering). |
| `new_status` | string | Always `"deleted"` on success. |
| `physical_deleted` | bool | `true` only when the main GCS blob delete succeeded. `false` when the flag is off *or* when physical delete wasn't attempted. |
| `physical_delete_skipped` | bool | `true` when `ENABLE_PHYSICAL_DELETE` was off; `false` when it was on. |

Callers can rely on these fields without reading Blossom source. Additional fields may be added; clients must ignore unknown fields.

#### Note: status string rendering

The response currently renders `BlobStatus` via `format!("{:?}", status).to_lowercase()`, which bypasses serde's `#[serde(rename = "age_restricted")]` attribute on `BlobStatus::AgeRestricted`. As a result, `old_status` emits `"agerestricted"` (no underscore) on this path, while serde-serialized status strings elsewhere in the API render as `"age_restricted"`.

Tracked as [blossom#95](https://github.com/divinevideo/divine-blossom/issues/95). Until that lands, callers matching on `old_status` should accept `"agerestricted"` for the age-gated variant on creator-delete/moderate/restore responses specifically. Other status variants are unaffected because their `Debug` form lowercases cleanly to the same string serde produces.

### Mapping between outcomes and response

| Operator intent | `physical_delete_enabled` | Byte delete | HTTP | `physical_deleted` | `physical_delete_skipped` |
|---|---|---|---|---|---|
| Validation window (flag off) | false | not attempted | 200 | `false` | `true` |
| Full delete succeeds | true | ok | 200 | `true` | `false` |
| Soft delete ok, byte delete fails | true | error | **5xx** | n/a (error response) | n/a |
| Blob already `deleted` (idempotent retry) | either | 404-from-GCS treated as success | 200 | `true` if flag on, else `false` | `!physical_delete_enabled` |
| Soft delete itself fails | either | not attempted | **5xx** | n/a | n/a |

## Error responses

| Condition | HTTP | Body |
|---|---|---|
| Invalid bearer / missing auth | 401 or 403 | `{"error":"<reason>"}` |
| Malformed JSON | 400 | `{"error":"Invalid JSON: ..."}` |
| `sha256` missing or not 64 hex chars | 400 | `{"error":"Invalid sha256 format"}` |
| Blob not found in KV | 404 | `{"error":"Blob not found"}` |
| Soft-delete failure (KV write error) | 5xx | `{"error":"<BlossomError>"}` |
| Physical-delete failure (GCS write error, flag on) | 5xx | `{"error":"<BlossomError>"}` |

## Failure states

Two internal mutation steps can fail, and the observable state after each failure differs. All failures propagate to the caller as `5xx` with `{"error":"<detail>"}`.

### Soft-delete fails

Triggered by a KV write error in `soft_delete_blob`. State after:

- Blob metadata unchanged. Status remains what it was.
- GCS bytes unchanged.
- Audit: `creator_delete_attempt` entry exists (the attempt audit runs before the helper call). No paired `creator_delete` entry.
- Response: `5xx`.

### Byte-delete fails (flag on only)

Triggered by a GCS failure in `storage::delete_blob`, after `soft_delete_blob` has already succeeded. State after:

- Blob metadata is in `Deleted` status. Content stops serving to public viewers (BlobStatus::Deleted returns 404 to non-owners).
- Main GCS blob bytes may remain. Best-effort artifact cleanup (HLS variants, VTT, derived audio) was not attempted because the byte-delete failure aborts the happy path.
- Audit: `creator_delete_attempt` entry exists. No paired `creator_delete` entry.
- Response: `5xx`.

### Pre-flight errors

Bad sha256, missing blob, malformed JSON, and auth failures return their error codes *before* any audit or mutation. These are traced via the handler-level log line (`[ADMIN] Moderation webhook: ...`) but not the audit log.

## Idempotency

**Repeated `action: "DELETE"` for the same `sha256` is safe.** On retry:

- `soft_delete_blob` is a no-op when the blob is already in `Deleted` status. Status, user-list cleanup, recent-index, and VCL cache purge are all idempotent.
- `storage::delete_blob` treats a missing GCS object as success (404 response from GCS → `Ok`). A retry after a previous byte delete succeeded still returns `Ok`.
- Audit writes are append-only. Each retry adds one `creator_delete_attempt` entry; each successful completion adds one `creator_delete` entry. Retries increase audit volume; they do not corrupt state.

Moderation-service can safely retry on 5xx:
- Previous attempt's soft-delete succeeded but byte-delete failed → retry runs byte-delete only (soft-delete is no-op) and converges. `physical_deleted` will be `true` in the retry response if GCS is healthy.
- Previous attempt failed at soft-delete → retry re-runs the full flow from a clean state (nothing mutated).

Callers should treat partial failure as non-terminal and retry with the same request body.

### Response variance across retries

Retry responses are not byte-equivalent to the original request's response — they describe the current operation, not the aggregate history:

- `old_status` reflects the blob's status at the start of the retry call. After a prior attempt that applied soft-delete, the retry sees `old_status: "deleted"` where the first attempt saw `old_status: "active"`.
- `physical_deleted` reflects whether the current call's byte-delete step succeeded. If the prior call's byte-delete failed and the retry's byte-delete succeeds, the retry returns `physical_deleted: true`.
- `new_status` is always `"deleted"` on success.

Mod-service retry logic should compare outcomes, not response bytes.

## Audit trail

Requests that pass validation (auth ok, valid JSON, valid sha256, blob found in KV) produce audit entries via `storage::write_audit_log`. Pre-flight errors do not audit. Two action values are used:

- `creator_delete_attempt` — written immediately before `handle_creator_delete` is called, once all input validation has passed.
- `creator_delete` — written after `handle_creator_delete` returns `Ok`. Absent when the operation failed mid-flight.

A failed mid-flight attempt therefore leaves an `attempt` entry with no paired `creator_delete` entry. Operators can query for this pattern to enumerate failures:

```sql
-- conceptual; audit entries live in Cloud Logging, not a SQL store
SELECT sha256 FROM audit
WHERE action = 'creator_delete_attempt'
  AND sha256 NOT IN (SELECT sha256 FROM audit WHERE action = 'creator_delete')
```

## Config

- `ENABLE_PHYSICAL_DELETE` — key in the `blossom_config` Config Store. Value `"true"` enables main-blob GCS deletion; anything else (including absent) disables it. Default posture is off during the validation window; flip on after the sample passes per the rollout plan.

## Observability

On every creator-delete attempt:

- Handler-level log: `[req=<id>] [ADMIN] Moderation webhook: sha256=<hash>, action=DELETE` (main.rs handler) — from blossom#86 once merged.
- Failure log: `[req=<id>] [CREATOR-DELETE] ...` — same source.
- Purge log: `[PURGE] VCL cache purged for key=<hash>` — cross-references via sha256 when triggered from a delete/moderate path.

See `docs/superpowers/plans/2026-04-16-creator-delete-action-plan.md` for design rationale and the review history.

## Related

- Rollout plan: `support-trust-safety/docs/rollout/2026-04-16-creator-delete-rollout.md`
- Moderation-service caller: `divine-moderation-service/src/blossom-client.mjs` (function `notifyBlossom`)
- Follow-up: blossom#87 (test coverage), blossom#90 (validation-window sweep), moderation-service#100 (NIP-98 URL normalization), moderation-service#102 (this contract referenced from moderation-service side).
