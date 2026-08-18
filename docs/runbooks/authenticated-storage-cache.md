# Authenticated storage cache

The Compute service authorizes every media request before consulting its
internal read-through cache. This lets restricted media reuse immutable bytes
without allowing a shared cache hit to bypass NIP-98/BUD-01 access checks.

## Request flow

1. The outer VCL service passes requests carrying `Authorization` to Compute.
2. Compute validates the viewer and evaluates the blob's moderation policy.
3. Only an allowed request reaches the internal storage cache.
4. The storage cache looks up the original request, including `Range`. On a
   miss, its `before_send` hook removes `Range` from the backend request so the
   complete `200` object is stored. Fastly can then synthesize the requested
   `206` from that object.

Only complete `200` responses and successful `304` revalidations are admitted.
Entries use the lowercase content hash as their surrogate key, so the existing
targeted moderation purge evicts both outer and internal cached copies.

## Diagnostic header

Public media responses may include:

```text
X-Divine-Storage-Cache: HIT
```

The value is the Compute service's internal cache result, normalized to exactly
`HIT` or `MISS`. Backend-provided `X-Cache` values are not exposed through this
header. The outer VCL service's own state remains in `X-Cache`.

## Live authenticated probe

Run `scripts/test-authenticated-storage-cache.sh` with `nak`, `curl`, the
`fastly` CLI, and a maintained age-restricted test fixture:

```bash
AGE_RESTRICTED_HASH=<64-hex-test-fixture> \
  scripts/test-authenticated-storage-cache.sh
```

Select the fixture from the maintained test accounts used for production media
access checks. Confirm immediately before running that it is still classified
as age-restricted and is safe for operational probing. Do not commit a real
creator identifier or media hash to the repository.

The probe first issues a targeted purge of the fixture's content hash, then
verifies a genuinely cold authorized range request returns `206` with an exact
`X-Divine-Storage-Cache: MISS`, a repeat range request over different bytes is
synthesized from the stored full object with an exact `HIT`, anonymous and
forged requests remain unauthorized after the cache is warm, and authorized
full-object repeats hit the internal cache.

## Purging

Use a targeted purge by content hash against Compute service
`pOvEEWykEbpnylqst1KTrR`:

```bash
fastly purge --key <hash> --service-id pOvEEWykEbpnylqst1KTrR
```

Do not globally purge the cache for routine changes.
