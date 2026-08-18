# ABOUTME: First cold-fill latency baseline for media.divine.video, measured from Christchurch NZ after the 2026-08-18 cache-policy fix.
# ABOUTME: Establishes that cold fills cost 0.7-5.8s TTFB and that the bare-blob route is far slower cold than the derivative route.

# Cold-fill baseline — Christchurch, NZ (2026-08-18)

Tool: `curl`, single client, sequential. Not `probe_cdn_delivery.py` — that harness
warms before measuring, and a warm cache is exactly what had to be avoided here.

Media hashes are omitted, per the convention in
[`docs/incidents/2026-08-18-media-startup-latency.md`](../incidents/2026-08-18-media-startup-latency.md).
Objects are labelled A-G and identified only by size.

## Why this run exists

Section 3 of the incident log records that no cold-fill baseline had ever been
taken, from any region: the 2026-08-07 NZ run warmed the cache first and every
measured response was a HIT. Cold fill was the leading unmeasured candidate for
the reported startup stalls.

Two things made this window usable. The deploy of Compute v339 at 03:06 UTC ran
`fastly purge --all` (the `[purge-cache]` gate had not merged yet), so the whole
catalogue was cold without anyone purging user content deliberately. And v339
made Pending media publicly cacheable, so the bare-blob route could be measured
warm as well as cold for the first time.

## Conditions

- Single client in Christchurch, New Zealand. **No US measurement.** The campaign
  traffic this matters for is US, and that gap is unchanged.
- Anonymous requests. No credentialed path was measured.
- Fastly Compute v339, outer VCL v15.
- Requests are `Range: bytes=0-1`. On a cold miss the `vcl_miss` snippet strips
  the Range and the fill fetches the whole object, so `time_starttransfer` is
  time to first byte of a full-object fill, not of a 2-byte read.
- Objects were sampled from `nostr.popular_videos_snapshot`, restricted to
  `media.divine.video` URLs. Cold objects were selected by low view count;
  "cold" is inferred from that plus the observed timing, not verified against
  cache state before the request.

## 1. Cold vs warm, bare-blob route

Seven long-tail objects, first request then immediate repeat.

| object | cold TTFB | warm TTFB |
|---|---:|---:|
| A | 0.757 s | 0.053 s |
| B | 1.061 s | 0.052 s |
| C | 1.180 s | 0.054 s |
| D | 2.308 s | 0.053 s |
| E | 4.778 s | 0.082 s |
| F | 5.836 s | 0.056 s |
| G (404) | 0.724 s | 0.054 s |

n=7. Cold median ~1.7 s, cold max 5.8 s. Warm is flat at 52-82 ms regardless of
object.

For comparison, the client-side "source ready" delays in the incident handoff
were 0.98 / 1.19 / 2.75 / 3.49 / 3.68 / 3.75 / 6.18 s, and two prefetches were
cancelled at exactly 8.001 s by the wall-clock deadline in the mobile client.
The cold distribution measured here covers that range. This does **not** prove
the reported stalls were cold fills — it establishes that cold fill is capable
of producing them, which was previously unknown.

Object G is referenced by a published nostr event but returns 404 at the edge.
Recorded here because it means the catalogue and the event index disagree.

## 2. Bare-blob route vs derivative route, same object

| object | size | bare-blob TTFB | 720p size | 720p TTFB |
|---|---:|---:|---:|---:|
| H | 6.89 MB | 0.765 s | 2.08 MB | 0.060 s * |
| I | 1.23 MB | **5.107 s** | 0.72 MB | 0.633 s |
| J | 0.79 MB | **3.276 s** | 0.74 MB | 0.451 s |
| K | 5.85 MB | 0.739 s | 1.87 MB | 0.054 s * |
| L | 6.84 MB | 1.200 s | 2.32 MB | 0.054 s * |

`*` = already warm; 54-60 ms is a hit, so those rows are not cold-vs-cold.
Derivatives have been publicly cacheable for weeks while bare blobs became
cacheable only on 2026-08-18, so the derivative side of most pairs was pre-warmed
by real traffic.

Rows I and J are the only clean cold-vs-cold pairs: comparable object sizes
(1.23 vs 0.72 MB, 0.79 vs 0.74 MB) and 7-8x the TTFB on the bare-blob route.
Note also that the *larger* bare blobs (H, K, L at ~6-7 MB) were **faster** than
the smaller ones (I, J at ~1 MB), which rules out byte transfer as the driver and
suggests H, K and L were not fully cold either.

### What this points at, and what it does not establish

The bare-blob route runs `download_blob_read_through` ->
`write_back_if_eligible` -> `buffer_body_up_to`, which buffers the whole object
in Compute memory before emitting a byte. The derivative route uses
`download_hls_content` and does not buffer. Because `vcl_miss` strips the client
Range on a fill, `had_range` is false and every object under the 32 MiB ceiling
is write-back eligible — so the buffer runs on every cold bare-blob fill.

Section 5 of the incident log identified this path and estimated its cost as
"likely sub-second for typical traffic ... not a 6-second smoking gun". These
numbers are not consistent with that estimate.

**This is a hypothesis, not an attribution.** Unresolved confounds:

- The two routes read different objects from GCS, so origin-side variance is not
  controlled.
- The bare-blob route also consults the Fastly Object Storage mirror first; the
  derivative route never does. A mirror miss adds a round trip the derivative
  never pays.
- n=2 for the clean pairs.
- There is still no server-side timing. Slow successful 200/206 responses are not
  recorded anywhere (`src/request_log.rs` persists only 5xx), so the cost cannot
  be split between GCS fetch, mirror lookup, and the buffer. Attributing this
  properly needs that telemetry first.

## 3. Moderation-status distribution of production video objects

40 objects, hash-ordered (uniform over the sampled set), fetched anonymously and
classified by `Cache-Control`:

| policy | count | share |
|---|---:|---:|
| `public, max-age=86400` (Pending) | 29 | 72.5% |
| `public, max-age=31536000, immutable` (Active) | 10 | 25.0% |
| `401` age-gated | 1 | 2.5% |

Before v339 every one of those 29 was served `private, no-store` — uncacheable at
the edge regardless of credentials.

The sample is drawn from popular videos, not the whole catalogue, so it is not a
catalogue-wide status census. It is the more relevant population for cache
behaviour, since it is what traffic actually requests. `GET /admin/api/stats`
returns the true `status_counts` and needs an admin credential.

**This corrects section 0.2 of the incident log.** That section attributed the
byte-offload deficit to authenticated requests bypassing cache. That mechanism is
real, but it cannot be the main one: roughly three quarters of sampled video
objects were uncacheable for anonymous callers too. Note also that these videos
are published as bare-blob URLs (`media.divine.video/<hash>`, no rendition
suffix), so the bare-blob route is a primary delivery path, not a fallback.

## 4. Purge recovery

The 40 popular objects sampled roughly one hour after the 03:06 UTC full purge
were **already warm** — every one answered in 52-82 ms on first request. The head
of the popularity distribution refills from organic traffic within the hour; the
long tail is what stays cold, and the long tail is where the multi-second fills
in section 1 were found.

## Open

- No US cold-fill measurement. Still the largest gap, and the campaign is US.
- No credentialed cold-fill measurement.
- Cannot split cold-fill cost across mirror lookup, GCS fetch and write-back
  buffering without server-side timing.
- Whether request collapsing holds when many clients hit the same cold object is
  unmeasured (section 9 ask 5 of the incident log).
