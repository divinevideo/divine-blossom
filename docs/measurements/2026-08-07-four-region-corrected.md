# ABOUTME: Corrected four-region CDN comparison using connection reuse and traffic-weighted regions.
# ABOUTME: Supersedes the earlier summary, whose timing method bundled TLS handshake into per-request latency.

# CDN Edge Comparison — Corrected (2026-08-07)

Supersedes [`2026-08-07-four-region-summary.md`](./2026-08-07-four-region-summary.md). Two
corrections, both of which changed conclusions.

## What was wrong

**1. Timing bundled the handshake.** The original probe opened a fresh TLS connection per request
and reported DNS + TCP + TLS + response headers as one `ttfb_ms`. A Wellington-to-Los-Angeles
handshake is ~296 ms on its own, so it was charged to server latency on every request. A client
scrolling a video feed reuses one connection and pays the handshake once per session.

The probe now measures connection setup separately from response latency on an established
connection, and reuses connections by default (`--no-reuse` forces the old behaviour).

**2. Regions were weighted equally. They are not.** Weighted by watch time — active users × average
engagement time, from product analytics for Jul 10 – Aug 6 2026:

| Region | Share of watch time |
|---|---:|
| **North America** (US + Canada) | **85.2%** |
| Europe | 11.1% |
| Asia / Australia / LatAm | 2.8% |
| India / Africa / Saudi | 0.87% |
| *of which Australia* | *0.87%* |

The earlier analysis treated an Oceania result as decisive. Oceania is under 1% of delivered bytes.

## Corrected results

Response latency on an established connection. Three regions from throwaway GCE instances (since
deleted), Wellington from a consumer connection. All cache hits.

| Region | Share | Fastly | bunny Volume | bunny Standard |
|---|---:|---:|---:|---:|
| **us-central1** | **~85%** | 13 ms | **14 ms** | **13 ms** |
| europe-west1 | ~11% | **3 ms** | 9 ms | 11 ms |
| australia-southeast1 | <1% | 2 ms | **97 ms** | 3 ms ✅ |
| nz-wellington † | **0%** | 12 ms | **144 ms** | 18 ms |

**† Wellington is where the team is based, not where users are.** New Zealand does not appear in the
top 24 countries by active users. It is included because it was the available consumer-grade
connection and because it isolates Volume's worst case — not because it represents any user
population.

It carries one operational consequence worth stating: **on bunny Volume the product will feel slow
to the people building it** (144 ms against Fastly's 12 ms) while being indistinguishable for the
85% of users in North America. Staff impressions from Wellington are not a valid signal about user
experience in either direction. If Volume is rolled out, test from a US vantage point rather than
trusting local perception.

Connection setup, measured separately: Fastly 29 ms / Volume 28 ms / Standard 27 ms in us-central1;
Volume 196–297 ms in Oceania, reflecting the trans-Pacific path.

## What this changes

**The claim "bunny Volume beats Fastly in NA/EU" does not hold.** It was an artifact of the
handshake being counted as server time. Corrected, Volume *ties* Fastly in the US and *loses* in
Europe.

**But the decision is unchanged, for a different reason.** In North America — 85% of delivered bytes
— all three are within 1 ms of each other. Volume is therefore free money there: indistinguishable
latency at half the Standard rate.

**Volume's weakness is confined to where it has no PoP**, and that is under 1% of traffic. Sydney
routes to Singapore (97 ms) and Wellington to Los Angeles (144 ms). Standard covers both, at 3 ms
and 18 ms.

| Strategy | Blended $/GB | At 1M DAU |
|---|---:|---:|
| All-Standard | $0.0110 | ~$81,000/mo |
| **Volume in NA+EU, Standard elsewhere** | **$0.0062** | **~$45,500/mo** |

The hybrid gives up a few milliseconds in Europe — imperceptible at these magnitudes — and saves
roughly $35K/month at 1M DAU.

## Caveats

- **GCE network paths are best-case.** A Belgian VM reaching Fastly's Brussels PoP in 3 ms is
  same-metro fibre. **A US consumer-connection datapoint is still missing and is now the most
  valuable outstanding measurement**, since it covers 85% of traffic and every US number here comes
  from a datacentre.
- ~~**The verdict logic manufactures failures at low latency.**~~ **Fixed.** The probe now requires a
  regression to exceed *both* a relative margin and an absolute floor (default 10 ms) before failing.
  Re-judged with the floor, Sydney reads correctly:

  | Edge | Verdict | Reason |
  |---|---|---|
  | bunny Standard | **PASS** | +50.0% but only +1.0 ms, within the 10 ms floor |
  | bunny Volume | **FAIL** | +4750.0% (+95.0 ms), outside both |

  Errors still bypass the floor entirely — an edge that drops requests fails however fast the
  survivors were.
- Cache hit ratio on a real library remains unmeasured and still determines the bill.
