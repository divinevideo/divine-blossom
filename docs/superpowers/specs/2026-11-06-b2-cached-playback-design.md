# Cached B2 playback test

The user requested cached playback through the existing B2 device setting, warming the first 100 Popular-feed originals, and measurements comparing GCS and B2. This change adds the cached delivery path. End-to-end telemetry is a separate delivery slice because the app must measure first frame; server timing cannot establish client receipt.

## Activation and access control

An exact `b2_canary_cache_enabled=true` enables internal byte caching only in the existing demand-mode test-host path. Missing, malformed, or false means the existing uncached behavior. Strict canary mode, canonical GCS routing, HLS, uploads, worker schemas and replica/erasure settings are unchanged.

The direct hostname continues executing all authoritative metadata, quarantine, tombstone, reference/owner vanish, readiness and copy/erase checks. B2 still verifies the live read/erasure bucket authorization before cache lookup. The handler rechecks policy and gate after every fetch, including cache hits, before releasing a response. Cache contents never grant permission. All outward responses remain `private, no-store` with `Surrogate-Control: no-store`.

## Internal cache contract

Use Fastly Core Cache, separate from outer VCL. Programmable HTTP-cache callbacks are unsupported by the pinned SDK's asynchronous sender; legacy TTL overrides cannot validate the response before storing it.

Cache keys are namespaced SHA256 digests of an unambiguous identity containing source provider, host, bucket, key, content hash, verified size and exact B2 destination version (absent for the authoritative content-addressed GCS fallback). GCS and B2 never share entries. Metadata repeats the identity fingerprint and size and contains only bounded ETag/Last-Modified delivery headers. Entries last 3600 seconds, without stale serving, and carry the existing bare content-hash surrogate key used by erasure purges.

Only complete successful GET representations up to 16 MiB populate the cache. Before insertion, require status 200, matching Content-Length, no Content-Range and exact body length, in addition to the existing origin version/size checks. Buffering is bounded to 16 MiB plus one byte and three seconds within the existing I/O budget. A per-request 25 ms CPU guard reserves processing time for insertion and final policy checks. Unknown CPU accounting or exhausted time/CPU reconstructs the consumed prefix and remaining origin body and continues uncached streaming. Failed cache coordination/insertion must not turn an otherwise valid origin response into a playback failure. Origin version/size integrity failures remain terminal and never populate the cache.

**Integrity ruling:** cache admission trusts the worker-SHA-verified immutable B2 version or the authoritative content-addressed GCS object, as existing origin delivery does. It does not independently rehash video bodies in Compute. An optimized WASM probe took about 51 ms to hash a cohort-sized 7.43 MB object, exceeding the historical default 50 ms CPU allowance before other request work. A whole-body edge hash could therefore turn working playback into a resource-limit failure. Matching version/size headers with same-length corrupt content can be cached for up to one hour under this revised contract. Worker and operator checksum verification detect that content independently; post-fill warm-up checks detect a bad fill but do not prevent its initial insertion. The operator must verify actual bytes before claiming the 100-object warm-up accepted. This is a deliberate trust/performance tradeoff, not equivalent to hashing each fill at the edge.

Cache coordination waits at most 50 ms within the remaining deadline, then uses the existing uncached origin path. Preserve handle ownership on timeout and cancellation. Never leave a cache transaction waiting on abandoned work.

A warm complete object supplies full GET, empty HEAD and validated single-range 206/416 responses. Compute ranges from the known size before using the SDK's stream-range API. A cold HEAD or ranged request uses the existing genuine origin request and does not populate the cache. Invalid/multiple ranges retain the existing demand-mode handling. Larger originals remain available through the existing uncached path.

Successful responses report `X-Divine-Storage-Cache: HIT`, `MISS`, or `BYPASS` and the actual `X-Divine-Source`. A cached GCS fallback remains labeled GCS. Source/version changes cannot reuse an old entry.

## Acceptance and Popular-feed warming

Local tests must exercise a real MISS followed by HIT with only one origin GET, warm HEAD/ranges/416, length/version rejection, version/provider separation, surrogate purge, CPU/time-budget bypass and moderation/erasure denial after warming. Preserve all existing uncached and revocation tests. A wrong-version rejection test must not be described as same-length corrupt-content detection.

After reviewed deployment, the live operator enables only the test-host cache flag and uses owned fixtures to prove cold MISS, warm HIT, correct bytes/ranges, a representative 8 MiB fill without CPU/resource errors, and signed erasure acknowledgement followed by physical all-version absence and public denial with cache populated. Verify canonical playback remains unchanged.

The operator then uses a private, timestamped manifest of the first 100 native Popular-feed originals. Preserve ranks, deduplicate transfers, and refresh policy, size, source generation, B2 readiness and copy/erase gates before copying or warming. Mirror missing eligible originals using the reviewed bounded worker. Stream one full warm GET per approved original with exact checksum verification, then perform one small range/HEAD cache-hit check from the test region. Record failures and skips without repeatedly retrying until green. Enforce explicit count/byte/time bounds and retain private receipts; publish aggregates only. Warming one POP does not establish a global warm cache.

## Metrics follow-up

Correlate sampled edge measurements with random per-playback attempt IDs and app first-frame/error/buffering measurements through an existing verified ingestion path. Separate configured cohort from actual origin, hit/miss/fallback, cold/warm and errors. Do not infer client delivery from returning response headers, and do not add viewer identity or raw media hashes to performance telemetry merely for correlation.
