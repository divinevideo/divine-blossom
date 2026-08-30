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
  "malformed_hash_exceptions": 1
}
```

The admin endpoint additionally echoes its `reason`; both responses identify the requested account.

- HTTP `200` and `vanished: true` mean every discovered blob was either erased or safely unlinked.
- HTTP `5xx`, `vanished: false`, and `errors > 0` mean at least one blob could not be completed. Callers must retry the same account.
- `fully_deleted` counts only sole-owner blobs whose main objects were confirmed deleted or absent from both GCS and Fastly Object Storage (FOS), whose required GCS derivatives and unshared derived audio were confirmed deleted or absent, whose erasure evidence was durably recorded, and whose metadata cleanup and final CDN purge completed.
- `unlinked` counts shared blobs that remain because another account still references them.
- `malformed_hash_exceptions` counts account-list entries that were not canonical 64-character lowercase hexadecimal hashes. Upload ingress rejects those values before storage, so they cannot address stored media. Blossom skips them before cleanup dispatch, records an audit entry with a safe fingerprint of the invalid value, and may still complete the account erasure. This exception does not increment `fully_deleted`.
- A typed `permanent` cleanup failure for a well-formed hash remains an error and blocks completion. Only edge validation of the list entry can increment `malformed_hash_exceptions`.

## Retry behavior

Origin and derivative DELETE operations are idempotent: a 404 means that object is already erased. If one required delete succeeds and another fails, the response is still a retryable `5xx`; the next attempt accepts earlier 404 responses and retries the outstanding work. The edge deletes the nine deterministic derivative keys directly, then requires an authenticated Cloud Run cleanup response that lists, deletes, and verifies any remaining hash-prefixed GCS objects.

When any blob fails required-origin deletion, erasure-evidence persistence, or required metadata/reference cleanup, Blossom preserves that blob's account-list entry so the next request can rediscover unfinished work. Completed blobs are removed from the list individually, so a later failure elsewhere in the same account does not cause them to be processed again. Blossom does not increment `fully_deleted` or `unlinked` until that per-blob list update succeeds.

If a retry finds a list entry whose metadata was already deleted, Blossom first removes the account from the blob's references. When other references remain, it treats the entry as a shared unlink. Otherwise it idempotently reconfirms deletion from both origins, records erasure evidence, and only then removes the dangling list entry. This covers an earlier attempt that erased the blob and metadata but failed to update the account list without erasing bytes still referenced by another account.

The account list and user-index entry are part of completion. A failure to delete either returns the same retryable failure response rather than reporting that vanish completed.

FOS erasure is not gated by `fos_read_enabled` or `fos_write_back_enabled`. Historical bulk-mirror copies may exist independently of both flags.

## Deliberate exclusions

- Reversible moderation bans do not use this physical-erasure contract.
- Legal `/admin/api/delete` remains a soft-delete path that may preserve evidence.
- Audit-log anonymization remains separate from the media-object completion counter.
- Fire-and-forget Cloud Run cleanup calls are not completion evidence.
- Erasure evidence is per valid blob. It does not record account-level completion or malformed-list exceptions; those are reported in the completion response, while the separate audit-log write is best-effort.
