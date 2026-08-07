# ABOUTME: First real CDN edge comparison — Fastly vs bunny Volume vs bunny Standard, measured from Wellington NZ.
# ABOUTME: Establishes that bunny's Volume network has no Oceania PoP and is unusable there, while Standard is viable.

# CDN Edge Comparison — Wellington, NZ (2026-08-07)

Raw data: [`2026-08-07-nz-wellington.json`](./2026-08-07-nz-wellington.json)
Tool: [`scripts/probe_cdn_delivery.py`](../../scripts/probe_cdn_delivery.py)

## Method

45 measured fetches per edge (15 iterations × 3 paths), 3 unmeasured warmup fetches per path first.
Paths were real production blobs: two originals (7.9 MB, 6.5 MB) and one 720p rendition (1.4 MB).

Both bunny pull zones use `https://media.divine.video` as origin, so this measures **bunny's edge
delivery**, not a production origin topology. After warmup every response was a cache HIT on every
edge, verified via `cdn-cache` / `x-cache` headers — these are steady-state delivery numbers, not
cache fills.

## Results

| Edge | Serving PoP | p50 TTFB | p95 TTFB | Throughput | Errors | Verdict |
|---|---|---:|---:|---:|---:|---|
| Fastly | `CHC` Christchurch, NZ | 42 ms | 50 ms | 273 Mbps | 0/45 | baseline |
| bunny Standard | `AUC1` Auckland, NZ | 53 ms | 58 ms | 194 Mbps | 0/45 | **PASS** (+16.5%) |
| bunny Volume | `LA1` Los Angeles, US | 463 ms | 490 ms | 26 Mbps | 0/45 | **FAIL** (+884%) |

## What this establishes

**1. bunny's Volume network has no Oceania PoP, and the penalty is severe.**
Volume traffic from Wellington is served from Los Angeles — roughly 10,500 km. The result is ~10×
the TTFB and ~10× lower throughput, on cache hits. For a 1.4 MB rendition that is ~460 ms of TTFB
plus ~430 ms of transfer, approaching a second before playback can start. That is a product-quality
failure for short-form video, not a marginal regression.

This confirms the PoP-list gap: Volume covers Frankfurt, Paris, Chicago, Dallas, Los Angeles, Miami,
São Paulo, Hong Kong, Singapore, Tokyo — no Australia or New Zealand.

**2. bunny's Standard network is competitive with Fastly, even this far from the major hubs.**
+16.5% p95 TTFB against a Fastly PoP in the same country, zero errors. Standard has 119 PoPs
including Auckland.

**3. Fastly has a Christchurch PoP**, which is better in-country coverage than bunny Standard's
Auckland. The 11 ms difference is small enough to be routing rather than capability.

## What this does NOT establish

- **This is a worst-case region, not a representative one.** The overwhelming majority of delivered
  bytes are North American, where Volume has four PoPs (Chicago, Dallas, Los Angeles, Miami). Volume
  may well be fine there. **It has not been measured.**
- Origin-fetch behaviour, since both bunny zones pull through Fastly here rather than from a real
  delivery origin.
- Behaviour under load, or on mobile networks rather than a fixed connection.

## Implication for the steering design

This validates the geo-routing approach in
[`2026-08-06-cdn-delivery-steering-design.md`](../superpowers/specs/2026-08-06-cdn-delivery-steering-design.md):
Volume where it has PoPs, something else where it does not. It also shows the eligibility check has
to be **geographic**, not just a percentage bucket — a hash-bucketed rollout that ignored geography
would silently ship a one-second startup delay to every Oceania viewer.

## Next measurements needed

1. **United States** — the majority-traffic case, and the one that decides whether Volume is viable
   at all. Run from a US East and a US West VM.
2. **Europe** — second-largest share.
3. **Australia** — separate from NZ; Sydney may route to Singapore rather than Los Angeles.
4. A run with bunny originating from a real delivery store rather than through Fastly.

## Reproducing

```bash
./scripts/probe_cdn_delivery.py \
  --edge fastly=https://media.divine.video \
  --edge bunny-volume=https://divine-probe-volume.b-cdn.net \
  --edge bunny-standard=https://divine-probe-standard.b-cdn.net \
  --path /<sha256>.mp4 --path /<sha256>/720p.mp4 \
  --baseline fastly --region <label> --iterations 15 --warmup 3 \
  --json docs/measurements/<date>-<region>.json
```

TODO(#178): Probe zones `divine-probe-volume` (id 6288620) and `divine-probe-standard`
(id 6288621) are temporary and should be deleted once the measurement campaign is finished.
