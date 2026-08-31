# Vanish media-erasure contract

`DELETE /vanish` and `POST /admin/api/vanish` remove media associated with an account. Shared blobs are unlinked and transferred to another reference; sole-owner blobs are physically erased.

## Completion response

Both endpoints return the same completion fields:

```json
{
  "vanished": true,
  "fully_deleted": 2,
  "unlinked": 1,
  "errors": 0,
  "malformed_hash_exceptions": 1,
  "pending": 0
}
```

The admin endpoint additionally echoes its `reason`; both responses identify the requested account.

- HTTP `200` and `vanished: true` mean every discovered blob was either erased or safely unlinked.
- HTTP `202`, `vanished: false`, and `pending > 0` mean the call completed within its bound but more entries remain. The response can also contain `errors > 0` for entries that were attempted and failed. Callers must retry the same account until it returns a terminal response, applying backoff and alerting when repeated responses report errors with both per-call completion counters, `fully_deleted` and `unlinked`, equal to zero.
- HTTP `5xx`, `vanished: false`, `pending: 0`, and `errors > 0` mean the call reached a terminal server failure instead of completing the account. Callers must retry the same account.
- `fully_deleted` counts only sole-owner blobs whose main objects are confirmed absent from both GCS and Fastly Object Storage (FOS), whose complete GCS hash prefixes and unshared derived audio are confirmed absent, whose erasure evidence was durably recorded, and whose required metadata cleanup and CDN purge completed.
- `unlinked` counts shared blobs that remain because another account still references them.
- `malformed_hash_exceptions` counts account-list entries rejected by the edge's 64-character hexadecimal hash validation. Those entries cannot address stored media, so Blossom audits a fingerprint of the invalid value, removes the entry without dispatching cleanup, and may still complete the account erasure. A cleanup failure for any valid hash remains an error and blocks completion.
- `pending` counts entries deferred by the per-call bound. Failed attempted entries are counted in `errors`, not `pending`, and remain discoverable for retry.

`vanished` is true only when `pending == 0`, `errors == 0`, and account-list finalization completed. This field, not the HTTP status, gates irreversible downstream deletion. A response never contains both `pending > 0` and `vanished: true`.

## Retry behavior

Origin DELETE operations are idempotent: a 404 means that origin is already erased. If GCS succeeds and FOS fails, the response remains retryable (`202` when bounded work is pending, otherwise `5xx`); the next attempt accepts GCS's 404 and retries FOS. The verified GCS cleanup lists every object under each hash prefix, deletes those objects, and lists the prefix again before reporting completion. A configured-bucket mismatch or any cleanup result other than `completed` is retryable and blocks account completion.

When any blob fails required-origin deletion, erasure-evidence persistence, or required metadata/reference cleanup, Blossom preserves that blob's account-list entry so the next request can rediscover unfinished work. Failed entries move behind untouched entries, allowing subsequent calls to advance through the bounded list before cycling back to persistent failures. Completed blobs are removed from the list individually, so a later failure elsewhere in the same account does not cause them to be processed again. Blossom does not increment `fully_deleted` or `unlinked` until that per-blob list update succeeds.

Each call attempts at most 10 list entries. The edge batches the main GCS objects and FOS delivery replicas into concurrent multi-object deletes. It sends one authenticated Cloud Run request containing the source hashes and any unreferenced derived-audio hashes, up to 20 hashes total. Cloud Run handles eight hashes concurrently and deletes at most 25 prefix objects per hash in one pass. If more objects remain, that hash returns `retryable`; later edge or caller retries continue the same idempotent cleanup. One slow or unexpectedly large prefix therefore cannot make a Cloud Run request unbounded.

CDN invalidation uses concurrent batch surrogate-key purges as soon as both main origins confirm deletion. A derivative cleanup failure still blocks `fully_deleted` and remains retryable, but it does not leave a successfully deleted main object available from CDN cache. Failed storage hashes are retried once within the call. `errors` counts source hashes still failed after both attempts, never individual provider attempts or derived-audio hashes.

If a retry finds a list entry whose metadata was already deleted, Blossom first removes the account from the blob's references. When other references remain, it treats the entry as a shared unlink. Otherwise it idempotently reconfirms deletion from both origins, records erasure evidence, and only then removes the dangling list entry. This covers an earlier attempt that erased the blob and metadata but failed to update the account list without erasing bytes still referenced by another account.

The account list and user-index entry are part of completion. A failure to delete either returns the same retryable failure response rather than reporting that vanish completed.

FOS erasure is not gated by `fos_read_enabled` or `fos_write_back_enabled`. Historical bulk-mirror copies may exist independently of both flags.

## Deliberate exclusions

- Reversible moderation bans do not use this physical-erasure contract.
- Legal `/admin/api/delete` remains a soft-delete path that may preserve evidence.
- Erasure evidence is per valid blob. It does not record account-level completion or malformed-list exceptions; those are reported in the completion response.
- A Cloud Run transport failure, malformed response, missing per-hash result, or non-completed per-hash result is not completion evidence.

## Audit and diagnostics

Before erasure starts, Blossom synchronously delivers a minimal account-linked authorization record through the authenticated `/audit/vanish` endpoint. User-signed requests emit `vanish_authorized`; admin API requests emit `admin_vanish_authorized` and do not identify the target account as the actor. After account-list finalization, each path emits its corresponding completion action. Operational KV state is scoped by account and initiator and preserves the operation ID and each phase timestamp across retries; Cloud Logging therefore receives the same insert ID and timestamp when delivery is retried and can deduplicate the entry. The KV state is removed after terminal delivery and expires seven days after the last retry-state write if the operation is abandoned (Fastly may take up to 24 additional hours to delete an expired key). The records contain the account pubkey, initiator, action, audit version, operation ID, timestamp, and insert ID. User-signed records also identify the account as the actor. They do not contain the signed authorization event, content hashes, free-text reason, or aggregate timing. Only records delivered through authenticated `/audit/vanish`, not the legacy best-effort `/audit` route, carry vanish evidentiary weight.

These account-linked records use the active Cloud Logging `_Default` bucket in project `rich-compiler-479518-d2`. Its verified retention is one day. Access is inherited from project IAM and is limited to principals holding project Owner, Editor, Viewer, or Logging Viewer roles; the bucket is not public. Changes to that retention or access policy require this contract to be updated.

Account/hash correlation remains in operational retry diagnostics while failures are actionable. Aggregate `vanish_timing` telemetry contains only counters and durations, with no account or content hash. Its asynchronous dispatch is best-effort and does not prove that Cloud Logging persisted the record. The non-account-linked per-blob `erasure:v1` evidence remains durable as described in `docs/erasure-evidence.md`.
