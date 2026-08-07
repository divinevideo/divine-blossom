# ABOUTME: Four-region CDN edge comparison of Fastly against bunny Volume and Standard networks.
# ABOUTME: Establishes that bunny Volume matches or beats Fastly where it has a PoP and fails badly where it does not.

# CDN Edge Comparison — Four Regions (2026-08-07)

Companion to [`2026-08-07-nz-wellington.md`](./2026-08-07-nz-wellington.md), which has the method in
full. Same tool, same three real production blobs, 45 measured fetches per edge per region, 3
unmeasured warmups per path. Every measured response was a cache hit, verified via `cdn-cache` /
`x-cache` headers.

Three regions were measured from throwaway `e2-small` GCE instances (since deleted); Wellington was
measured from a consumer connection. **GCE network paths are better than a real user's**, so treat
absolute numbers as optimistic and the *relative* comparison as the signal.

> **SUPERSEDED 2026-08-07.** The numbers below came from a probe that opened a fresh TLS connection
> per request and reported handshake plus response time as a single `ttfb_ms`, which systematically
> overstated distant edges. It also weighted four regions equally when North America is ~85% of
> delivered watch time.
>
> **Corrected results:** [`2026-08-07-four-region-corrected.md`](./2026-08-07-four-region-corrected.md).
> Retained for the record; the PoP-routing observations still hold.

## Results

| Region | Edge | Serving PoP | p50 TTFB | p95 TTFB | Mbps | Verdict |
|---|---|---|---:|---:|---:|---|
| **us-central1** (Iowa) | Fastly | CHI Chicago | 49 ms | 53 ms | 330 | baseline |
| | bunny **Volume** | IL1 Illinois | **43 ms** | **47 ms** | 271 | **PASS −11.1%** |
| | bunny Standard | DEN1 Denver | 42 ms | 64 ms | 321 | FAIL +22.3% |
| **europe-west1** (Belgium) | Fastly | BRU Brussels | 22 ms | 60 ms | 846 | baseline |
| | bunny **Volume** | FR1 Frankfurt | **24 ms** | **26 ms** | 527 | **PASS −56.1%** |
| | bunny Standard | BE1 Belgium | 32 ms | 57 ms | 421 | PASS −5.3% |
| **australia-southeast1** (Sydney) | Fastly | WSI Sydney | 21 ms | 311 ms | 534 | baseline |
| | bunny Volume | SG1 **Singapore** | 294 ms | 302 ms | 40 | PASS −3.0% ⚠ |
| | bunny **Standard** | SYD1 Sydney | **10 ms** | **38 ms** | 1257 | **PASS −87.9%** |
| **nz-wellington** (consumer) | Fastly | CHC Christchurch | 42 ms | 50 ms | 273 | baseline |
| | bunny Volume | LA1 **Los Angeles** | 463 ms | 490 ms | 26 | **FAIL +884%** |
| | bunny **Standard** | AUC1 Auckland | 53 ms | 58 ms | 194 | PASS +16.5% |

## Findings

**1. bunny's Volume network matches or beats Fastly wherever it has a PoP.**
−11% p95 in the US and −56% p95 in Europe, on cache hits, with zero errors. This is the
majority-traffic case and it passes cleanly. The earlier Wellington-only result was misleading
precisely because Wellington is the worst-served location on bunny's Volume map.

**2. Where Volume has no PoP the penalty is severe and entirely predictable from the PoP list.**
Wellington routes to Los Angeles (+884% p95, 26 Mbps). Sydney routes to Singapore (294 ms p50,
40 Mbps). Volume's PoPs are Frankfurt, Paris, Chicago, Dallas, Los Angeles, Miami, São Paulo, Hong
Kong, Singapore, Tokyo — the failures land exactly where that list is empty.

⚠ The Sydney Volume "PASS" is an artifact, not a result. It passed only because Fastly's p95 was
anomalous in that run (see finding 4). Its 294 ms p50 and 40 Mbps are plainly unacceptable.

**3. bunny's Standard network is strong in Oceania, and beat Fastly outright in Sydney** — 10 ms p50
against 21 ms, 38 ms p95 against 311 ms, and 2.4× the throughput. Standard is the right fallback
wherever Volume has no PoP.

**4. Fastly's Sydney p95 was 311 ms against a 21 ms p50.** That distribution implies a small number
of slow requests rather than uniformly poor service. Worth re-running before drawing conclusions —
it could be a cold object, an origin fetch, or a one-off. It is flagged here because it makes one
comparison in this table unreliable.

**5. Volume throughput is consistently below Standard and Fastly in-region** (271 vs 330 Mbps in the
US, 527 vs 846 in the EU). Volume PoPs appear more contended. Still far above what short-form video
needs, but relevant if large originals are being served.

## Conclusion

The evidence supports a **two-tier geographic split**, which is what
[`2026-08-06-cdn-delivery-steering-design.md`](../superpowers/specs/2026-08-06-cdn-delivery-steering-design.md)
already proposes:

- **bunny Volume** in North America and Europe — cheapest tier, and measurably *faster* than the
  current Fastly path.
- **bunny Standard** in Oceania and anywhere else Volume lacks a PoP — comparable to or better than
  Fastly.
- **Fastly** retained for all request-time logic, restricted content, and as failover.

The steering decision must be **geographic first**. A hash-bucketed percentage rollout that ignored
geography would have shipped a one-second startup delay to every Oceania viewer while looking fine
in aggregate.

## Not yet established

- Behaviour with a real delivery origin. Both bunny zones pull through Fastly here, so origin-fetch
  and cache-fill behaviour is untested.
- Performance on mobile networks and under load.
- South America, India, and Africa. São Paulo is a Volume PoP; India and Africa are not, and neither
  is on the Standard network's strongest footing.
- Whether Fastly's Sydney p95 outlier reproduces.

## Reproducing

Startup-script approach used here: create a throwaway `e2-small` per region with the probe embedded
in `startup-script` metadata, read results from the serial console, delete the instance. No service
account or scopes needed — pass `--no-service-account --no-scopes`.

Probe zones `divine-probe-volume` (6288620) and `divine-probe-standard` (6288621) are temporary and
should be deleted when the campaign ends.
