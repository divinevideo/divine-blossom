# ABOUTME: Live takedown drill against the delivery test system, covering B2 deletion semantics and CDN cache purge.
# ABOUTME: Establishes that deleting from the replica does not remove content, and that B2 hide leaves data retrievable.

# Takedown Drill — Delivery Replica and CDN (2026-08-07)

Run against the working test system in
[`2026-08-07-replica-as-acl-validation.md`](./2026-08-07-replica-as-acl-validation.md):
GCS authoritative → Backblaze B2 approved-only replica → bunny Volume → viewer.

The replica-as-ACL design protects content that was **never** replicated. This drill covers the other
case: content that was approved, replicated, served, and must now be removed.

## Finding 1 — deleting from the replica does not take content down

| Step | B2 direct | bunny |
|---|---:|---:|
| Before | 200 | 200 (warm in cache) |
| After `b2_delete_file_version` | **404** | **200 — still served** |
| After bunny purge | 404 | **404** |

The middle row is the point. The replica was empty and the CDN kept serving the content from cache.
**Purge is mandatory, not a tidy-up step**, and it must reach every delivery zone independently —
Volume and Standard zones cache separately.

This is the asymmetry in the design and it should be stated plainly:

- Content **never replicated** → protected structurally. Cannot leak.
- Content **already replicated** → removal is an active, eventually-consistent, multi-target
  operation with the same failure modes as any distributed delete.

Describing replica-as-ACL as "cannot be eventually-consistent-wrong" is only true of the first case.

## Finding 2 — `b2_hide_file` does not remove data

B2 distinguishes hiding from deleting. Hiding is what the "delete" affordance does in the B2 UI, and
it is also how an S3-compatible `DeleteObject` behaves against a versioned bucket.

Uploaded a 4,000-byte object, then called `b2_hide_file`:

```
versions still listed: 2
  action=hide     size=     0
  action=upload   size=  4000     <- the actual bytes

>>> DATA STILL RETRIEVABLE BY fileId: 4000 bytes, status 200
```

The file is gone *by name* but the content is intact and downloadable by `fileId` to anyone holding
a key with `readFiles`. Only `b2_delete_file_version` **on every version** actually removes it:

```
after b2_delete_file_version on all versions:
  versions remaining: 0
```

**Implications for a service with GDPR erasure and legal-hold obligations:**

- A takedown implemented with `b2_hide_file`, the B2 UI, or an S3 SDK's `delete_object` **does not
  erase the content.** It remains retrievable, and remains billable storage.
- Erasure must enumerate versions (`b2_list_file_versions`) and delete each one explicitly.
- B2 lifecycle rules can automate version cleanup, but the shortest supported window still leaves a
  retention period. For legal takedown, delete explicitly rather than relying on lifecycle.
- The same class of trap exists on any versioned object store. Verify the semantics per provider
  before trusting a delete path.

## The fan-out, as measured

Removing one blob from the tested topology requires:

1. Tombstone in GCS (authoritative).
2. `b2_delete_file_version` for **every version** in the replica.
3. Purge the bunny zone — **per zone**, since Volume and Standard cache independently.
4. Surrogate-key purge on Fastly.
5. Whatever deny-list exists in Fastly Compute, for instant enforcement ahead of the above.

Client-side caches are unreachable and out of scope.

Each added delivery CDN or zone adds a step. This is an argument for keeping the number of delivery
zones small, and for making the purge fan-out a single idempotent, retryable job with an audit
trail — not a sequence of calls in a request handler.

## Per-record purge works on both CDNs, keyed on the content hash

Content addressing means every derivative of a blob shares the hash as a path prefix, so **the
SHA-256 is a natural purge key on both CDNs** — no separate tagging scheme is needed.

**Fastly — already implemented.** `src/main.rs` sets `Surrogate-Key: {hash}` on cacheable responses
(`add_cache_headers`, `add_private_cache_headers`), `vcl/deliver.vcl` strips it before the client
sees it, and `purge_edge_cache(surrogate_key)` already calls
`POST /service/{id}/purge/{key}` against both the VCL and Compute services.

**bunny — verified working.** A single wildcard URL purge covers every derivative:

```
POST https://api.bunny.net/purge?url=https://{zone}.b-cdn.net/{sha256}*
     AccessKey: <key>
```

Measured semantics, on a zone with two warm derivative paths:

| Purge URL | `{hash}.mp4` | `{hash}/720p.mp4` |
|---|---|---|
| `{hash}*` | **MISS** (purged) | **MISS** (purged) |
| `{hash}/*` | HIT (untouched) | **MISS** (purged) |

It is a literal prefix match, so `{hash}*` catches `.mp4`, `/720p.mp4`, `/480p.mp4`, `.hls`,
`/hls/*.ts`, `.vtt`, and thumbnails in one call. `{hash}/*` is the narrower form and would **miss**
the extension-suffixed paths — use the bare `{hash}*`. Took effect within ~4 seconds.

### What needs building

1. **Extend `purge_edge_cache` with a bunny leg** — one wildcard purge per delivery zone. The
   function already takes the hash, so the signature does not change.
2. **Make it fail loudly.** As written it is explicitly best-effort: it returns early with only an
   `eprintln!` when `fastly_api_token` is absent, and its own doc comment says it "logs errors but
   never fails the calling request." That is reasonable for a cache optimisation and wrong for a
   moderation control. A takedown that logs an error and reports success is a compliance hole, and
   adding a second CDN doubles the number of ways it can happen. It should return a result the
   moderation path can act on, with retry and alerting.

Neither is large. The mechanism is there; it needs a second target and honest error handling.

## Pre-existing risk this compounds

`vcl/fetch.vcl` documents that the moderation surrogate-key purge "is silently skipped if
`fastly_api_token` is unconfigured." That failure mode already exists with one CDN. Adding a second
delivery CDN multiplies it, and a takedown that succeeds on one CDN and silently fails on another is
worse than one that fails loudly everywhere.

**The purge fan-out should fail loudly before any second CDN carries traffic.**

## What the canary must now assert

Extending the checks in the steering design, a continuous canary should verify:

1. A permanently-tombstoned hash returns 404 on **every** delivery zone.
2. `CacheErrorResponses == False` on every delivery pull zone (see the validation doc — this default
   is what lets approvals take effect immediately).
3. A deliberately-taken-down test blob has **zero versions** in the replica, not merely a hide
   marker.

Check 3 is the one that would have caught Finding 2.

## Test system state after this drill

- `832e9a4d…/480p.mp4` was deleted from B2 and purged from `divine-b2-test`. It remains available on
  Fastly and in the other test zones.
- `takedown-semantics-test.bin` was created and fully deleted; zero versions remain.
