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
  "pending": 0
}
```

The admin endpoint additionally echoes its `reason`; both responses identify the requested account.

- HTTP `200` and `vanished: true` mean every discovered blob was either erased or safely unlinked.
- HTTP `202`, `vanished: false`, and `pending > 0` mean the call completed within its bound but more entries remain. The response can also contain `errors > 0` for entries that were attempted and failed. Callers must retry the same account until it returns a terminal response, applying backoff and alerting when repeated responses report errors without increasing `fully_deleted` or `unlinked`.
- HTTP `5xx`, `vanished: false`, `pending: 0`, and `errors > 0` mean the call reached a terminal server failure instead of completing the account. Callers must retry the same account.
- `fully_deleted` counts only sole-owner blobs whose main objects were confirmed deleted or absent from both GCS and Fastly Object Storage (FOS), whose required GCS derivatives and unshared derived audio were confirmed deleted or absent, whose erasure evidence was durably recorded, and whose metadata cleanup and final CDN purge completed.
- `unlinked` counts shared blobs that remain because another account still references them.
- `pending` counts entries deferred by the per-call bound. Failed attempted entries are counted in `errors`, not `pending`, and remain discoverable for retry.

`vanished` is true only when `pending == 0`, `errors == 0`, and account-list finalization completed. This field, not the HTTP status, gates irreversible downstream deletion. A response never contains both `pending > 0` and `vanished: true`.

## Retry behavior

Origin DELETE operations are idempotent: a 404 means that origin is already erased. If GCS succeeds and FOS fails, the response remains retryable (`202` when bounded work is pending, otherwise `5xx`); the next attempt accepts GCS's 404 and retries FOS.

When any blob fails required-origin deletion, erasure-evidence persistence, or required metadata/reference cleanup, Blossom preserves that blob's account-list entry so the next request can rediscover unfinished work. Failed entries move behind untouched entries, allowing subsequent calls to advance through the bounded list before cycling back to persistent failures. Completed blobs are removed from the list individually, so a later failure elsewhere in the same account does not cause them to be processed again. Blossom does not increment `fully_deleted` or `unlinked` until that per-blob list update succeeds.

Each call attempts at most 100 list entries. Main GCS objects, deterministic GCS derivatives, and FOS delivery replicas are sent as independent concurrent multi-object deletes. CDN invalidation uses concurrent batch surrogate-key purges after both origins confirm deletion.

Failed storage hashes are retried once within the call. `errors` counts hashes still failed after both attempts, never individual provider attempts.

If a retry finds a list entry whose metadata was already deleted, Blossom first removes the account from the blob's references. When other references remain, it treats the entry as a shared unlink. Otherwise it idempotently reconfirms deletion from both origins, records erasure evidence, and only then removes the dangling list entry. This covers an earlier attempt that erased the blob and metadata but failed to update the account list without erasing bytes still referenced by another account.

The account list and user-index entry are part of completion. A failure to delete either returns the same retryable failure response rather than reporting that vanish completed.

FOS erasure is not gated by `fos_read_enabled` or `fos_write_back_enabled`. Historical bulk-mirror copies may exist independently of both flags.

## Deliberate exclusions

- Reversible moderation bans do not use this physical-erasure contract.
- Legal `/admin/api/delete` remains a soft-delete path that may preserve evidence.
- Audit-log anonymization remains separate from the media-object completion counter.
- Fire-and-forget Cloud Run cleanup calls are not completion evidence.
- Erasure evidence is per valid blob. It does not record account-level completion or malformed-list exceptions; those are reported in the completion response, while the separate audit-log write is best-effort.
