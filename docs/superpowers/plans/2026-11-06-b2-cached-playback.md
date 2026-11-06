# Cached B2 playback implementation plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans to implement each independently testable slice.

**Goal:** Let the existing B2 device cohort test cached playback and warm 100 Popular-feed originals with verified cache hits.

**Architecture:** Store verified immutable bytes in Fastly Core Cache behind every existing policy and erasure check. Keep the direct host and outward no-store contract. The release operator owns all production changes and bounded warming; telemetry follows the existing ingest architecture after discovery.

**Tech stack:** Existing Rust/Fastly SDK 0.11.12, Core Cache, Viceroy, existing Python mirror and operator tooling.

**Spec:** [Cached playback design](../specs/2026-11-06-b2-cached-playback-design.md).

## Constraints and review focus

- Exact opt-in flag; default-off parity and canonical GCS preserved.
- No cache hit can bypass policy, copy/erase gates, live B2 authorization or final recheck.
- Provider/version identity and full-body size must precede insertion; worker/operator SHA checks remain separate from edge admission.
- Cache lookup, buffer memory/time and cancellation have explicit bounds.
- Warm HEAD/ranges, oversized bodies, truncation, cache outages, purge and post-warm denial require evidence.
- No raw creator/viewer identity in public artifacts or metrics.

## Tasks

- [x] Discover current cache/SDK constraints and collect the private 100-original Popular manifest without media requests.
- [x] Add the real Viceroy cached-playback regression and observe BYPASS where MISS is required.
- [x] Implement `src/playback_cache.rs` with bounded coordination, origin-validated fills and warm range/HEAD delivery; add identity/integrity and CPU-budget tests.
- [ ] Integrate demand B2/GCS origin boundaries and preserve trustworthy cache-result headers in `src/canary.rs`; document activation and limits.
- [ ] Run full edge/core/clippy suites, obtain independent complete-diff review, commit/push and open a ready PR with required reviewers and finished CI.
- [ ] Hand the exact source/flag/key/purge contract to the live operator; deploy/enable under existing user authorization and prove owned warm-cache erasure.
- [ ] Refresh manifest policy/readiness, mirror only missing eligible originals with explicit transfer limits, warm at most 100 and verify actual regional HITs/checksums.
- [ ] Deliver correlated edge/client metrics through the verified ClickHouse ingest path in separately reviewed changes, retaining the cached playback and warming outcome.
