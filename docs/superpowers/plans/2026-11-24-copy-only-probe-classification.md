# Copy-only probe failure classification implementation plan

**Goal:** Stop retries for deterministically invalid copy-only originals while retaining retries for operational failures.

**Architecture:** Request structured ffprobe errors and recognize only a normal exit with AVERROR_INVALIDDATA as incompatible source media. Reuse admission returns false for that source; generated-output validation still errors. Existing copy-only terminal handling and durable webhook acknowledgment remain unchanged.

**Tech stack:** Rust, Tokio, FFmpeg/ffprobe, existing media reuse tests.

**Requirements:** Never encode copy-only media, modify original bytes, swallow webhook errors, or change live routing and publishing holds.

**Files:** cloud-run-transcoder/src/media_reuse.rs (probe classification); cloud-run-transcoder/src/media_reuse_tests.rs (synthetic regressions).

**Review focus:** Unknown tool errors, signals, timeouts, invalid JSON, and invalid generated outputs must remain retryable. Ordinary allow-encode fallback stays available.

- [x] Reproduce ffprobe structured invalid-data exit with synthetic bytes.
- [x] Change the existing encoder-boundary regression and observe failure.
- [x] Recognize invalid-data only on normal ffprobe exit; keep generated-output failure retryable.
- [x] Exercise real invalid originals, missing source, unknown error, malformed output, and killed process behavior.
- [x] Run formatting, worker tests, and real media tests.
- [ ] Commit, push, open scoped PR, request Platform once, obtain and publish fresh-context review, inspect CI.
- [ ] Hand reviewed source to the existing runtime owner; preserve publishing hold.

Validation: the changed encoder-boundary test failed with `Reuse media probe failed` before implementation. All 358 worker tests, including real generated-media tests, then passed. Formatting and diff checks passed. FFprobe structured error behavior is documented at https://ffmpeg.org/ffprobe-all.html and AVERROR_INVALIDDATA at https://ffmpeg.org/doxygen/trunk/group__lavu__error.html.
