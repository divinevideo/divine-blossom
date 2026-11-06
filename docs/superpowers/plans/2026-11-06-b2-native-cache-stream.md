# Native cache streaming implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fill playback cache through 32 MiB with fragmented origins and prompt streaming.

**Architecture:** Preflight Core Cache insertion/readback, splice the origin body
in the host, finish the producer and return the insertion-owned stream. Future
HITs require completed exact length.

**Tech Stack:** Existing Rust/Fastly 0.11.12 and Viceroy, no dependency change.

**Spec:** docs/superpowers/specs/2026-11-06-b2-native-cache-stream-design.md

## Global Constraints

- Preserve 32 MiB eligibility, 25 ms admission CPU and existing header/lookup deadlines.
- No guest per-fragment body loop, size-proportional buffer or full-body header delay.
- Keep current policy, erasure, version, header integrity, surrogate and no-store checks.
- Report late streaming failures honestly; early failures keep source availability.

## Review Focus

- Origin and cache producer must survive guest exit until stream completion.
- Truncated/failed streams must never become exact-length HITs.
- Cache setup must finish before consuming source ownership.
- Slow bodies must not turn header deadlines into full-download deadlines.
- Existing HEAD/range misses, privacy checks and default-off behavior must remain.

### Task 1: Host stream and lifecycle regression coverage

**Files:** src/playback_cache.rs, src/canary.rs,
scripts/run-b2-canary-tests.py, scripts/run-b2-native-stream-tests.py,
scripts/run-edge-tests.sh, docs/runbooks/b2-playback-canary.md.

**Interfaces:** Preserve read(Identity, method, range, deadline, fetch) and HIT/MISS/BYPASS;
MISS is streaming insertion, completed-length HIT is unchanged.

- [x] Add fragmented 8/16/32 MiB tests and observe the buffered implementation fail.
- [x] Replace guest buffering with preflight/readback then native append/finish.
- [x] Test delayed/truncated bodies, early headers and completion-only cache reuse.
- [x] Test real production-WASM guest exit through the Viceroy HTTP server.
- [ ] Run complete edge suite/clippy, fresh whole-diff review, commit/push/PR and CI.
- [ ] Coordinate merge/release, strict live size/erase proof, then refreshed Popular100.
