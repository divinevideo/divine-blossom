# ABOUTME: Design for server-side steering of media delivery between Fastly and a second CDN (bunny.net).
# ABOUTME: Covers the steering point, bucketing strategy, origin prerequisites, eligibility rules, rollback, and how to test it.

# CDN Delivery Steering Design

**Date:** 2026-08-06
**Status:** Design — not implemented
**Related:** `docs/cdn-object-storage-vendor-notes.md` for the vendor limits this design works around;
`docs/measurements/2026-08-07-nz-wellington.md` for the first synthetic regional measurement.

## Goal

Be able to serve a controllable fraction of media bytes from a second CDN (bunny.net) instead of
Fastly, compare the two on real traffic, and roll back without a deploy or any client change. See
Rollback below for what "roll back" reaches: a config flip stops new descriptors, and DNS on the
delivery hostname is what moves already-published URLs.

## Scope

- Server-side only. No mobile or web client changes.
- Read path for media blobs and their derivatives. Upload, moderation, and Blossom protocol
  endpoints stay on Fastly Compute unchanged.
- Steering granularity, rollback, eligibility, and measurement.

Out of scope: which CDN wins (that is what this exists to measure), client-side CDN selection,
and any change to how the app fetches or plays video.

## Prerequisite that constrains everything else

**bunny needs an origin it can read at delivery rates.**

| Origin | Viable? | Note |
|---|---|---|
| **Backblaze B2** | **Selected** | $0 via partner-CDN program (unverified) or $0.01/GB over the 3× allowance |
| Cloudflare R2 | Yes — fallback | $0 egress to any consumer via S3 API; not stood up |
| GCS | Works | but GCS egress returns on bunny's cache misses |
| **Fastly Object Storage** | **No** | **public S3 endpoint capped at ~150 Mbps / 100 req/s per bucket** |

This decision is recorded in the multi-provider delivery plan: B2, private, approved-only. R2 is the
first fallback if partner-CDN egress does not appear on the billing account. Adopting Fastly Object
Storage as the delivery replica would foreclose this entire design.

## Recommended approach

### Steering point

All outbound media URLs already funnel through one function:
`to_descriptor(&base_url)` in `blossom-core/src/types.rs:387`, fed by `get_base_url(&req)`.

Replace the base-URL source with a selector:

```rust
fn select_delivery_host(req: &Request, meta: &BlobMetadata) -> &'static str {
    // Ineligible content never leaves the Fastly Compute path.
    if !is_publicly_cacheable(meta) {
        return FASTLY_HOST;
    }
    // Not yet copied and verified into the replica: bunny would 404 it.
    if !meta.replicated {
        return FASTLY_HOST;
    }
    let pct: u32 = config_store_get("bunny_traffic_pct").unwrap_or(0);
    if bucket_of(&meta.sha256) < pct { BUNNY_HOST } else { FASTLY_HOST }
}

/// Stable 0..99 bucket from the first 8 hex chars of the content hash.
fn bucket_of(sha256: &str) -> u32 {
    sha256
        .get(0..8)
        .and_then(|prefix| u32::from_str_radix(prefix, 16).ok())
        .unwrap_or(0)
        % 100
}
```

`is_publicly_cacheable` is a proposed helper, not an existing `BlobMetadata` method, and
`meta.replicated` is a proposed field, not one that exists today. The bunny rollout plan describes
where replication sets it.

Why here: it is one function, it already governs every URL handed out, and the decision has full
context available — moderation status, client geo, content type.

Limitation: this only moves clients that fetch a fresh descriptor. Direct `GET /{sha256}` hits on
`media.divine.video` bypass it and stay on Fastly. That is acceptable — it bounds blast radius, and
those requests are the ones most likely to be third-party Blossom clients we do not want to
experiment on.

### Bucketing strategy — pick per experiment

| Bucket by | Use for | Why |
|---|---|---|
| **content hash** | cost / cache-efficiency tests | Each blob lives on exactly one CDN, so both get clean hit ratios and nothing is cached twice |
| **client IP or pubkey** | latency / QoE tests | Each viewer consistently sees one CDN, so comparisons are apples-to-apples |
| **client geo** | production rollout | Route to whichever CDN actually serves that region well |

Do not mix strategies within one experiment; the results stop being interpretable.

### Rollback

`bunny_traffic_pct` lives in a Fastly Config Store, so changing it takes effect without a deploy.
`0` stops new descriptors being issued with the second host, and must be tested before the first
non-zero rollout. It is roll-forward control, not a retroactive rollback: a client already holding a
second-provider URL keeps using it until it refreshes the descriptor, so rollback verification has to
cover that window too.

The retroactive lever is DNS on the delivery hostname — it moves already-published URLs back to
Fastly. This works only while descriptors emit a Divine-owned hostname rather than a vendor one.
Coarse and TTL-bound, but independent of Compute, so it still works if Compute is the thing that is
broken.

### Eligibility — the replica is the access control

Only `Active`, public, non-restricted blobs are steerable, **and only once the replica copy has been
verified**. Everything else — `Pending`, `Restricted`, `AgeRestricted`, admin bypass, tombstoned,
legal hold — stays on the Fastly Compute path.

Eligibility and readiness are separate conditions and both are required. Absence from the replica
denies restricted content, which is the access-control property below; but an approved blob that has
not finished copying is also absent, and steering it would 404 the newest content at its worst
moment. Route on the verified flag, not on approval alone.

**Enforce this by replication policy, not by logic at the second CDN.** Replicate to the delivery
store only on moderation-approval, never on upload. A gated blob is then simply not in the replica:

```
Active + public   → in replica → bunny serves it
anything else     → never replicated → origin 404s → bunny 404s
```

bunny cannot leak what it can never fetch. No tokens, no deny-list, no edge scripting, no
per-request logic, and no per-request cost. **Absence is the denial, structurally rather than by
enforcement.**

In the normal path the 404 never happens, because Fastly Compute picks the URL at descriptor time
and already knows the status — gated content is handed a Fastly URL and never points at bunny. The
404 is a safety net for one race: content that was public when its URL was issued and was gated
before that URL was fetched.

Three consequences worth stating plainly:

- **The origin must be the approved-only replica.** A pull zone fetches from origin on miss, so
  pointing bunny at Fastly or at the authoritative store would let it fetch and cache a gated blob
  and defeat the whole mechanism. "Replicate on approval, not on upload" is therefore a
  *correctness* requirement, not a cost optimisation.
- **`Pending` content is currently served publicly.** `vcl/fetch.vcl` documents that Pending blobs
  return 200 to anonymous viewers while moderation is in flight. Those must stay off the replica
  entirely, or every rejected upload becomes a purge obligation.
- **Negative caching needs a short TTL.** bunny will cache the 404. When content is later approved,
  or a replication lag resolves, a stale 404 would persist. Cache 404s briefly and purge on publish.

### Monitoring a control whose correct behaviour is silence

Gated content is a very small fraction of the corpus. That is good for cost — the Fastly fallback
carries a rounding error of traffic — but it means **a broken exclusion produces no visible symptom
until someone finds it.** The cost of a leak is not proportional to its frequency; a single
tombstoned blob served after a takedown is a legal event, not an error rate.

Required: a **canary**, asserting all three of:

1. A permanently-tombstoned hash returns 404 on **every** delivery zone.
2. `CacheErrorResponses == False` on every delivery pull zone — that default is what lets an
   approval take effect immediately instead of being masked by a cached 404.
3. A deliberately-taken-down test blob has **zero versions** in the replica, not merely a hide
   marker. This is the check that catches a delete path which only hides.

### Alternatives considered

Both work and both cost more. Recorded so the choice is not relitigated.

| Mechanism | Cost | Revocation | Why not chosen |
|---|---|---|---|
| **Replica-as-ACL** | $0 | purge | chosen — cannot be eventually-consistent-wrong |
| Token authentication | $0 | token TTL, closed by purge | native bunny SHA256 directory tokens, validated at the edge with no origin call; but revocation is bounded by TTL rather than structural |
| Edge Scripting deny-list | ~$0.20 per million requests, on *every* request | ~refresh interval | bunny's `onClientRequest` runs before cache and can short-circuit, and Deno module scope holds an in-memory bloom filter across requests; genuinely viable, and the right answer if sub-minute revocation of already-replicated content is ever required |

bunny does have a real edge compute runtime (Edge Scripting, Deno/V8, middleware hooks
`onClientRequest`, `onOriginRequest`, `onOriginResponse`, `onClientResponse`). The reason this design
does not use it is cost and certainty, not capability.

### Deletion and takedown

**The design is asymmetric, and this must not be glossed.** Content that was *never* replicated is
protected structurally and cannot leak. Content that was already replicated and served is an
ordinary distributed delete, with ordinary distributed-delete failure modes.

Measured in [`../../measurements/2026-08-07-takedown-drill.md`](../../measurements/2026-08-07-takedown-drill.md),
removing one blob requires all of:

1. Tombstone in GCS (authoritative).
2. Delete **every version** in the replica. On B2 that means `b2_delete_file_version` per version —
   `b2_hide_file`, the B2 UI delete, and an S3 `DeleteObject` against a versioned bucket all leave
   the bytes intact and retrievable by file id.
3. Purge each delivery zone **independently** — Volume and Standard caches are separate. The drill
   confirmed the CDN keeps serving a deleted object until purged.
4. Surrogate-key purge on Fastly.
5. Deny-list check in Compute, for instant enforcement ahead of the above.

Make this **one idempotent, retryable job with an audit trail**, not a sequence of calls in a
request handler. Every added zone adds a step, which is an argument for keeping the number of
delivery zones small.

**Pre-existing risk this compounds:** `vcl/fetch.vcl` documents that the moderation surrogate-key
purge "is silently skipped if `fastly_api_token` is unconfigured". A takedown that succeeds on one
CDN and silently fails on another is worse than one that fails loudly everywhere. **Fix that before
a second CDN carries traffic.**

Token authentication on the delivery zone is probably unnecessary — the content is public,
content-addressed Blossom blobs, so there is nothing to protect.

## What can and cannot be measured server-side

**Can:** per-CDN request counts and bytes, origin fetch latency, error rates, cache hit ratio from
each CDN's own logs and analytics, cost per TB delivered.

**Cannot, without client telemetry:** real client TTFB, startup time, rebuffer ratio — the numbers
that actually decide whether a cheaper CDN is acceptable.

This is why synthetic probing comes first: it is the only way to get comparative latency without
touching the app.

## Testing plan

### Phase 0 — synthetic, no user traffic
Use `scripts/probe_cdn_delivery.py` to fetch identical objects from Fastly, bunny Volume, and each
candidate origin, from VMs in the top measured geographies. **Include Australia** — bunny's Volume
network has no PoP there, so it is the clearest latency risk. Compare TTFB, sustained throughput,
and error rate.

Exit criteria: bunny p95 TTFB within an agreed margin of Fastly in the geographies carrying the bulk
of traffic.

### Phase 1 — 1% by content hash
`bunny_traffic_pct = 1`. Verify the eligibility gate holds, the purge fan-out reaches both CDNs, and
per-CDN cost and hit ratio are separable in logs. Run a deliberate takedown drill.

Exit criteria: zero restricted content observed on the bunny path; takedown verified on both CDNs.

### Phase 2 — ramp by geography
Move to geo-based routing: bunny Volume where it has PoPs (NA, EU, Singapore, Hong Kong, Tokyo,
São Paulo), Fastly elsewhere (Australia, India, MEA). Fastly Compute has client geo available at no
cost.

### Kill criteria — at any phase
- Any restricted, pending, or tombstoned content served from bunny.
- Any takedown that does not complete on both CDNs within the legal SLA.
- p95 TTFB regression beyond the Phase 0 margin in any materially-trafficked region.

## Open questions

- Does bunny's pull-zone origin authentication work against R2 and B2 signed access, or does it
  require public bucket reads?
- What is bunny's purge API latency and rate limit, and is it sufficient for a takedown SLA?
- Does splitting traffic across two CDNs degrade either one's cache hit ratio enough to matter at
  low percentages? (Hash bucketing should prevent this; verify rather than assume.)
- bunny's published Volume pricing stops at 2 PB/month; the rate above that is quote-only, so the
  cost case for a full rollout cannot be closed from public information.
