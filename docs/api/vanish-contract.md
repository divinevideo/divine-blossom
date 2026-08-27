# Vanish media-erasure contract

`DELETE /vanish` and `POST /admin/api/vanish` remove media associated with an account. Shared blobs are unlinked and transferred to another reference; sole-owner blobs are physically erased.

## Completion response

Both endpoints return the same completion fields:

```json
{
  "vanished": true,
  "fully_deleted": 2,
  "unlinked": 1,
  "errors": 0
}
```

The admin endpoint additionally echoes its `reason`; both responses identify the requested account.

- HTTP `200` and `vanished: true` mean every discovered blob was either erased or safely unlinked.
- HTTP `5xx`, `vanished: false`, and `errors > 0` mean at least one blob could not be completed. Callers must retry the same account.
- `fully_deleted` counts only sole-owner blobs whose main object was confirmed absent from both GCS and Fastly Object Storage (FOS) before metadata cleanup and the final CDN purge.
- `unlinked` counts shared blobs that remain because another account still references them.

## Retry behavior

Origin DELETE operations are idempotent: a 404 means that origin is already erased. If GCS succeeds and FOS fails, the response is still a retryable `5xx`; the next attempt accepts GCS's 404 and retries FOS.

When any blob fails required-origin deletion, Blossom preserves the account's blob-list entry so the next request can rediscover unfinished work. It does not delete that blob's metadata or increment `fully_deleted`.

FOS erasure is not gated by `fos_read_enabled` or `fos_write_back_enabled`. Historical bulk-mirror copies may exist independently of both flags.

## Deliberate exclusions

- Reversible moderation bans do not use this physical-erasure contract.
- Legal `/admin/api/delete` remains a soft-delete path that may preserve evidence.
- Fire-and-forget Cloud Run cleanup calls are not completion evidence.
