# ABOUTME: Design for server-side steering of media delivery between Fastly and a second CDN (bunny.net).
# ABOUTME: Covers the steering point, bucketing strategy, origin prerequisites, eligibility rules, rollback, and how to test it.

# CDN Delivery Steering Design

**Date:** 2026-08-06
**Status:** Design — not implemented
**Related:** `docs/cdn-object-storage-vendor-notes.md` for the vendor limits this design works around;
`docs/measurements/2026-08-07-nz-wellington.md` for the first synthetic regional measurement.

## Goal

Be able to serve a controllable fraction of media bytes from a second CDN (bunny.net) instead of
Fastly, compare the two on real traffic, and roll back instantly — without any client change.

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
| Cloudflare R2 | Yes | $0 egress to any consumer via S3 API |
| Backblaze B2 | Yes | $0 via partner-CDN program (unverified) or $0.01/GB over the 3× allowance |
| GCS | Works | but GCS egress returns on bunny's cache misses |
| **Fastly Object Storage** | **No** | **public S3 endpoint capped at ~150 Mbps / 100 req/s per bucket** |

This is the decision that has to be made first. Adopting Fastly Object Storage as the delivery
replica forecloses this entire design.

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

`is_publicly_cacheable` is a proposed helper, not an existing `BlobMetadata` method.

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
`0` is a full rollback. This is the primary safety mechanism and must be tested before the first
non-zero rollout.

Secondary lever: DNS weighting on the delivery hostname. Coarse and TTL-bound, but independent of
Compute, so it still works if Compute is the thing that is broken.

### Eligibility

Only `Active`, public, non-restricted blobs are steerable. Everything else — `Pending`,
`Restricted`, `AgeRestricted`, admin bypass, tombstoned, legal hold — stays on the Fastly Compute
path.

bunny does have an edge compute runtime (Edge Scripting, Deno-based) but no persistent KV store yet,
so a moderation gate there would need an external fetch on every request. Deciding access once, when
the URL is issued, avoids that entirely and is the reason this design does not depend on the second
CDN having compute at all.

This is a hard rule, not a default. The check belongs in `select_delivery_host`, before the
percentage bucket, so a config mistake cannot route restricted content off the enforcing path.

### Deletion and takedown

bunny's purge API becomes an additional fan-out target alongside the existing Fastly surrogate-key
purge. Note the existing failure mode this compounds: `purge_edge_cache` in `src/main.rs:5945`
logs and skips the purge when `fastly_api_token` is unconfigured. **Make the purge fan-out fail
loudly before enabling any bunny traffic**, or a takedown can succeed on one CDN and fail on the
other.

Token authentication on the bunny zone is probably unnecessary — the content is public,
content-addressed Blossom blobs, so there is nothing to protect. Revisit if that changes.

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
