# Reuse compatible video implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Reuse compatible compressed short media without video or audio encoding.

**Architecture:** Add a conservative eligibility and stream-copy module, integrate it inside the existing owned generation stage, and preserve the common upload and completion path. Failures fall back to encoding with clean output staging.

**Tech Stack:** Rust, Tokio, FFmpeg/ffprobe, existing object storage and HLS claims.

**Spec:** docs/superpowers/specs/2026-11-18-reuse-compatible-video-design.md

## Global Constraints

Eligibility: H.264 yuv420p progressive, no B frames, <=480x480, <=10 seconds, <=30 fps, <=500000 total bits/s, optional AAC-LC <=96000 bits/s at 44100/48000 Hz and <=2 channels. No nonzero rotation/non-square SAR. Repairs encode. Keep original bytes, both derivative URL families, provenance, required copies, and claim ownership intact.

## Review Focus

- Missing/invalid probe fields must reject reuse, covered by policy table tests.
- Timestamp/keyframe anomalies must reject reuse, covered by packet policy tests.
- Failed staging must not contaminate fallback outputs, covered by real-process failure tests.
- Repackaging must preserve frames/audio/timing, covered by generated-media integration tests.
- New generation must still obey single-writer and backup failures, covered by full existing integration suite.

### Task 1: Implement conservative reuse and integrate generation

**Files:** Create cloud-run-transcoder/src/media_reuse.rs and media_reuse_tests.rs; modify cloud-run-transcoder/src/main.rs; add docs/runbooks/media-reuse.md.

**Interfaces:** media_reuse::try_reuse(input: &Path, output: &Path) -> Result<bool>; returns false for rejected inputs and errors for failed attempts. Caller falls back to normal encoding; the helper stages candidates privately and only commits a complete output set. run_ffmpeg_hls gains an allow_reuse boolean; forced repairs set it false.

- [x] Write policy tests against a rejecting stub. Expect accepted synthetic metadata to fail the assertion while unsafe cases reject.
- [x] Implement eligibility and packet validation; run policy tests until green.
- [x] Add real FFmpeg fixtures and tests proving copied frames, output availability, cleanup, original preservation, and fallback. Observe missing reuse fail before implementation.
- [x] Implement bounded staging and caller integration. Count actual encoding only on the encoding path, reuse separately.
- [x] Run cargo test --manifest-path cloud-run-transcoder/Cargo.toml --locked -- --include-ignored. Expected: all tests pass, including synthetic media and claim/backup integration tests.
- [x] Run Python service tests, formatting and focused Clippy. Document compatibility and rollback.
- [ ] Commit, obtain a fresh independent full-diff review, resolve findings, push a scoped pull request, request the mapped team once and inspect CI.
