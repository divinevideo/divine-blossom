# ABOUTME: Current state of the CDN and delivery-origin evaluation — what exists, what is measured, what is still open.
# ABOUTME: Read this first; it indexes the vendor notes, steering design, and measurement records.

# CDN and Delivery Evaluation — Status

**Last updated:** 2026-08-07

Entry point for the delivery-origin and second-CDN evaluation. Start here, then follow the links.

| Document | What it holds |
|---|---|
| [cdn-object-storage-vendor-notes.md](cdn-object-storage-vendor-notes.md) | Verified vendor limits, pricing, and API capabilities |
| [superpowers/specs/2026-08-06-cdn-delivery-steering-design.md](superpowers/specs/2026-08-06-cdn-delivery-steering-design.md) | How to steer traffic between two CDNs, server-side |
| [measurements/2026-08-07-four-region-summary.md](measurements/2026-08-07-four-region-summary.md) | **The current headline result** |
| [measurements/2026-08-07-replica-as-acl-validation.md](measurements/2026-08-07-replica-as-acl-validation.md) | Working test system proving absence-is-denial |
| [measurements/2026-08-07-nz-wellington.md](measurements/2026-08-07-nz-wellington.md) | First measurement; superseded in scope, still valid for Oceania |
| [../scripts/probe_cdn_delivery.py](../scripts/probe_cdn_delivery.py) | The measurement tool |

Commercial analysis — traffic volumes, cost models, vendor questions — is deliberately **not** in
this repository, which is public. It lives in `divine-context` under `repo-context/`.

---

## What is established

**bunny's Volume network matches or beats Fastly wherever it has a PoP**, and fails badly where it
does not. Measured across four regions, cache hits only, zero errors:

| Region | Fastly p95 | bunny Volume p95 | bunny Standard p95 |
|---|---:|---:|---:|
| us-central1 | 53 ms | **47 ms** (−11%) | 64 ms |
| europe-west1 | 60 ms | **26 ms** (−56%) | 57 ms |
| australia-southeast1 | 311 ms ⚠ | 302 ms (Singapore) | **38 ms** |
| nz-wellington | 50 ms | 490 ms (Los Angeles) | 58 ms |

The failures are entirely predictable from bunny's published Volume PoP list. That makes them
routable around rather than disqualifying.

**Implied architecture:** Volume in North America and Europe, Standard where Volume has no PoP,
Fastly retained for all request-time logic and as failover. The steering decision must be
**geographic first** — a percentage rollout ignoring geography would look fine in aggregate while
shipping a one-second startup delay to every Oceania viewer.

## What is built

- `scripts/probe_cdn_delivery.py` — standard-library probe, 20 unit tests. Compares edges on p95
  TTFB against a baseline. Errors count against a candidate outright; `NO_DATA` is distinct from
  `FAIL`; `--warmup` prevents mistaking a cache fill for steady-state delivery.
- A repeatable method for measuring from arbitrary regions: throwaway `e2-small` GCE instance per
  region with the probe embedded in `startup-script` metadata, results read from the serial console,
  instance deleted. `--no-service-account --no-scopes` keeps it credential-free.

## What exists in vendor accounts right now

| Thing | State | Notes |
|---|---|---|
| bunny pull zone `divine-probe-volume` | id 6288620, live | Volume tier, origin `media.divine.video` |
| bunny pull zone `divine-probe-standard` | id 6288621, live | Standard tier, same origin |
| bunny storage zone `divine-delivery-test` | id 1722644, region NY | Push replica, 4 approved objects |
| bunny pull zone `divine-delivery-test` | id 6289348, Volume tier | Backed by the storage zone — the working ACL test |
| Backblaze B2 | bucket `divine-delivery-probe`, public, 4 objects | Validated as a bunny pull-zone origin |
| bunny pull zone `divine-b2-test` | id 6289364, Volume tier | Origin is the B2 bucket — full production-shaped topology |
| Cloudflare R2 | not started | account exists; no bucket, no token |

Both bunny zones are **temporary probe infrastructure** and pull through Fastly rather than from a
real delivery origin. They should be deleted when the campaign ends — tracked in #178.

**The B2 key `blossom-dev` is not scoped.** It reports `ALL BUCKETS` with `deleteBuckets`,
`writeKeys`, and `bypassGovernance` — the last of which overrides retention and legal hold. It
should be narrowed to a single delivery bucket before anything production-adjacent uses it.

Credentials are kept outside the repository in `~/.config/divine-cdn/`, mode 600. No credential
belongs in this repo, in `fastly.toml`, or in any committed file.

---

## Two findings that are not yet acted on

### 1. The descriptor URL points at the original, not a rendition

Object sizes measured on real production blobs:

| Path shape | Size |
|---|---:|
| `{sha256}.mp4` — original | **7.93 MB** and **6.49 MB** |
| `{sha256}/720p.mp4` — rendition | **1.38 MB** |

The original is **~5.8× the 720p rendition**. A 7.9 MB original for a short clip is far above the
transcode ladder's 720p `maxrate 2500k` (`cloud-run-transcoder/src/main.rs`).

`blossom-core/src/types.rs` sets the blob descriptor's primary URL to the bare hash:

```rust
url: format!("{}/{}", base_url, self.sha256)
```

That is the original. Any client following the descriptor `url` — the documented Blossom path, and
what third-party clients will use — fetches the original rather than a rendition.

**This is unquantified.** The share of delivered bytes going to bare-hash originals versus renditions
is not known, and cannot be known from current logging (see below). If the share is material, this
is a one-function change in `to_descriptor()` with a larger effect than any CDN decision. It should
be measured before it is assumed either way.

### 2. Current logging cannot see most delivered bytes

`vcl/log_cdn_views.vcl` logs only:

```vcl
req.method == "GET" && req.url ~ "^/[0-9a-fA-F]{64}$" && resp.status == 200
```

That is a **view counter**, and correct for its purpose. But it excludes:

- `.mp4`, `/720p.mp4`, `/480p.mp4` and other rendition paths
- `.hls` manifests and `/hls/*.ts` segments
- `.vtt` tracks and thumbnails
- **all `206` responses** — and the service answers range requests with 206

So the pipeline into ClickHouse cannot answer "how many delivered bytes go to which path shape",
which is the question finding 1 depends on. Answering it needs a **new `vcl_log` line** capturing
path classification and `resp.body_bytes_written` across all media responses, plus a table to
receive it — not a query over what already exists.

---

## Open questions

**Measurement**
- Behaviour against a real delivery origin. Both bunny zones currently pull through Fastly, so
  origin-fetch and cache-fill behaviour is untested.
- Mobile networks and behaviour under load.
- South America, India, Africa. São Paulo is a Volume PoP; India and Africa are not.
- Whether Fastly's Sydney p95 outlier (311 ms against a 21 ms p50) reproduces.

**Vendor**
- bunny's rate above 2 PB/month is quote-only; published tiers stop there.
- Whether Backblaze's partner-CDN free-egress program covers an edge-compute fetch.
- Whether Fastly Compute is available on a Streaming Delivery account.
- Whether Fastly zero-egress treatment survives buckets and Compute being in different accounts.

**Architecture**
- Access control on the second CDN is settled: **the replica is the access control**. Replicating
  only on moderation-approval means a gated blob is never in the replica, so the second CDN cannot
  serve it. No tokens, no deny-list, no edge compute, no per-request cost. This makes "replicate on
  approval, not on upload" a correctness requirement. See the steering design for the alternatives
  considered and why they cost more.
- Takedown gains a fan-out target: bunny's purge API alongside the Fastly surrogate-key purge. The
  existing purge already fails silently if `fastly_api_token` is unconfigured — that should fail
  loudly before a second CDN is added.

## Next steps

1. Ship the `vcl_log` line and table that make finding 1 answerable.
2. Add the tombstoned-hash canary described in the steering design, before any traffic is steered.
3. ~~Stand up a real delivery origin and re-measure~~ — done. Fastly pull-through, bunny Storage,
   and Backblaze B2 origins all land within 6% of each other on cache hits, so **origin choice does
   not affect delivery performance** and can be decided on cost, durability, and lock-in alone.
4. Measure South America and India.
5. Delete the probe zones once the campaign closes (#178).
