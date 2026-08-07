# ABOUTME: Implementation plan for routing eligible media delivery to a second CDN with moderation-safe replication.
# ABOUTME: Covers the two hook points, client URL migration, moderation wiring, test strategy, and staged rollout.

# bunny Delivery Rollout — Implementation Plan

**Date:** 2026-08-07
**Depends on:** [`../../cdn-evaluation-status.md`](../../cdn-evaluation-status.md),
[`../specs/2026-08-06-cdn-delivery-steering-design.md`](../specs/2026-08-06-cdn-delivery-steering-design.md)

Everything here is validated on a working test system — see `docs/measurements/`. This is the
production wiring.

## The whole thing hooks two functions

The codebase makes this smaller than it looks. Rather than chasing call sites, hook the two
chokepoints every path already flows through:

| Concern | Function | Existing call sites |
|---|---|---|
| **Replicate on approval** | `metadata::update_blob_status(hash, Active)` | `admin.rs:1040` (admin approve), `main.rs:3101` (moderation scan) |
| **Purge and delete** | `purge_edge_cache(hash)` | 10 sites including `delete_policy.rs:34,54`, `admin.rs:949`, `main.rs:4395,5186,5396,5528` |

Deletion already fans out correctly through one function. Extending *that* function covers every
takedown path in the service — creator delete, admin moderation, GDPR vanish, tombstone, legal hold.

## How clients reach the new delivery host

`to_descriptor(&base_url)` in `blossom-core/src/types.rs` builds every URL handed out, fed by
`get_base_url(req)` in `main.rs:6051`, which derives the host from the incoming request. Replacing
that with a selector is the entire client-facing change:

```rust
fn select_delivery_host(req: &Request, meta: &BlobMetadata) -> String {
    // Gate before anything else: ineligible content never leaves the Fastly path.
    if meta.status != BlobStatus::Active || !meta.replicated {
        return fastly_host(req);
    }
    match geo_tier(req) {
        Tier::NorthAmericaOrEurope => volume_host(),   // measured: within 1ms of Fastly
        _                          => standard_host(), // Volume has no PoP; measured 97-144ms
    }
}
```

Geo is available in Compute via `fastly::geo::geo_lookup`. The eligibility gate must come **before**
the geo or percentage bucket, so a routing misconfiguration cannot expose gated content.

### Published URLs do not migrate, and that is a feature

Nostr events embed the blob URL at publish time. Changing `to_descriptor` therefore affects **new
uploads and freshly-generated `/list` responses only** — every already-published event keeps pointing
at `media.divine.video`.

Consequences:

- **Migration is automatic and gradual.** No backfill, no rewriting published events, no way to break
  existing content.
- **It is also self-limiting.** With short-form video's recency-weighted access, new uploads carry
  most traffic, so a large share of bytes moves within weeks without touching a single existing URL.
- **Rollback is trivial** — flip the selector back and new descriptors return to Fastly. Already-
  issued bunny URLs keep working because the replica is still there.
- **Direct `GET /{sha256}` on `media.divine.video` never moves.** Third-party Blossom clients that
  hardcode the base URL stay on Fastly permanently. That bounds blast radius and preserves protocol
  compatibility.

Do not attempt to migrate historical URLs with redirects. It adds a round trip to every request,
still costs a Fastly request fee, and buys little given the recency curve.

## Moderation wiring

### Replicate on approval, never on upload

This is a **correctness** requirement, not an optimisation — the replica *is* the access control. If
anything replicates on upload, gated content lands in a store the CDN will happily serve.

Hook `update_blob_status`. When the transition is *into* `Active`:

1. Enqueue a replication job (Cloud Tasks, consistent with the existing derivative-status queue).
2. Job copies the blob and its derivatives into the replica.
3. Job sets `replicated = true` in metadata **after** verifying the copy.
4. Only then does `select_delivery_host` route that hash to bunny.

Note the ordering: the descriptor must not point at bunny until replication is confirmed, or a
freshly-approved video 404s for its first viewers — the worst possible moment for new content.

`Pending` blobs are currently served publicly while moderation is in flight (`vcl/fetch.vcl`
documents this). They must stay off the replica entirely, or every rejected upload becomes a purge
obligation.

### Extend the deletion fan-out

Inside `purge_edge_cache(hash)`, add:

1. **bunny purge per zone** — `POST https://api.bunny.net/purge?url=https://{zone}/{hash}*`. The
   bare `{hash}*` form is required; `{hash}/*` misses every extension-suffixed path. Verified.
2. **Replica delete** — on B2, `b2_list_file_versions` then `b2_delete_file_version` for **every**
   version. `b2_hide_file`, the B2 UI delete, and an S3 `DeleteObject` against a versioned bucket all
   leave the bytes retrievable by file id. Verified.
3. **Clear `replicated`** so the descriptor stops routing to bunny.

### Make the purge fail loudly

`purge_edge_cache` currently returns early with an `eprintln!` when `fastly_api_token` is missing,
and its doc comment states it "logs errors but never fails the calling request". Correct for a cache
optimisation, wrong for a moderation control — a takedown that logs an error and reports success is
a compliance hole, and a second CDN doubles the ways it half-succeeds.

Change it to return a result the moderation path can act on, with retry and alerting. **Do this
before any traffic is steered**, not after.

## Testing

### Unit

- `select_delivery_host` returns the Fastly host for every non-`Active` status, for `Active` but
  unreplicated, and for tombstoned or legal-hold blobs. Table-driven over the full status enum so a
  new status cannot silently become eligible.
- Geo tier selection maps regions to the intended zone.
- Purge fan-out returns an error when any target fails, and is idempotent on repeat.

### Integration — the one that matters

Against the test system, end to end:

1. Upload → status `Pending` → assert **not** in replica, assert bunny 404s.
2. Approve → assert replicated, assert `replicated` flag set, assert bunny serves 200.
3. Reject a different blob → assert never replicated, assert bunny 404s.
4. Take down an approved blob → assert zero versions in replica, assert bunny 404s, assert Fastly
   404s.
5. Re-approve → assert it serves again (bunny does not cache errors by default, so this should be
   immediate; the test guards that default).

Step 3 is the one that catches a replicate-on-upload regression. Step 4 is the takedown drill.

### Continuous canary

Runs against production, alarms on any failure:

1. A permanently-tombstoned hash returns 404 on **every** delivery zone.
2. `CacheErrorResponses == False` on every delivery pull zone — that default is what lets approvals
   take effect immediately.
3. A known taken-down blob has **zero versions** in the replica, not merely a hide marker.

Gated content is under 1% of the corpus, so a broken exclusion produces no visible symptom until
someone finds it. The canary is the only signal.

### Reconciler

Periodic: for each `Active` blob, assert presence in the replica; for each non-`Active`, assert
absence. Repair drift, alarm on anything it had to repair. Verify by stored SHA-256 rather than
ETag — multipart ETags are not content hashes and differ between providers.

## Staged rollout

| Stage | Action | Exit criteria |
|---|---|---|
| 0 | Purge fan-out fails loudly; canary running against the test system | Canary green 48h; deliberate takedown alarms correctly |
| 1 | Replicate on approval, but keep **all** descriptors on Fastly | Reconciler reports zero drift for 7 days |
| 2 | Route 1% of new uploads by hash bucket, North America only | No 404s on approved content; no gated content on bunny |
| 3 | Ramp to 50% of new uploads in NA and EU | QoE and error rate within margin of Fastly |
| 4 | All new uploads; Standard tier outside NA/EU | — |

Stage 1 is the important one: replication runs in production with nothing depending on it, so drift
and bugs surface before any user is affected.

**Rollback at every stage** is a config flip on the selector. Already-issued bunny URLs keep working
because the replica remains.

## Not resolved by this plan

- **Cache hit ratio on the real library is unmeasured**, and it determines both the bill and how much
  the B2 fill penalty costs. It should be measured during stage 2 when real traffic first hits bunny.
- **Every US latency number came from a datacentre.** 85% of traffic is US, and no consumer-connection
  datapoint exists.
- The delivery corpus grows a second copy; storage cost is small but the compliance surface is not —
  each replica is an independent erasure obligation.
