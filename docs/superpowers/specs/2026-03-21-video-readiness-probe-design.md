# Video Readiness Probe Design

## Goal

Add lightweight diagnostic scripts that can confirm or invalidate the hypothesis that newly uploaded videos fail on first playback because progressive `720p.mp4` becomes available later than HLS.

## Scope

- Add a single-hash probe script for repeated live checks over time.
- Add a batch coverage script for one-shot checks across many hashes.
- Add unit tests for the diagnosis/classification logic so the scripts stay trustworthy.

## Recommended Approach

Use Python scripts in `scripts/` with only standard-library dependencies.

Why this approach:

- Python is already used for operational scripts in this repo.
- The diagnosis logic can be tested directly.
- CLI output can stay readable without brittle shell parsing.

## Script Design

### `scripts/probe_video_readiness.py`

Inputs:

- `--hash`
- `--domain` defaulting to `media.divine.video`
- `--interval-seconds`
- `--attempts`
- `--timeout-seconds`
- `--method` defaulting to `HEAD`

Behavior:

- Poll these URLs on every attempt:
  - `https://{domain}/{hash}/720p.mp4`
  - `https://{domain}/{hash}.hls`
  - `https://{domain}/{hash}/hls/stream_720p.m3u8`
- Print timestamped status rows.
- Classify the final result into a small, explicit verdict set.

Verdicts:

- `mp4_ready_immediately`
- `mp4_delayed_hls_ready_first`
- `mp4_never_ready_hls_ready`
- `both_delayed`
- `still_processing`
- `no_ready_endpoints_observed`

### `scripts/check_progressive_coverage.py`

Inputs:

- hashes as CLI args, `--hash-file`, or stdin
- `--domain`
- `--timeout-seconds`
- `--method`

Behavior:

- Perform one probe per hash.
- Report per-hash statuses.
- Summarize counts for:
  - MP4 ready
  - HLS ready
  - both ready
  - HLS ready while MP4 missing

## Testing

Unit tests will cover:

- verdict classification for delayed MP4, immediate MP4, and missing MP4 cases
- hash extraction and de-duplication from mixed input
- URL construction for the probe endpoints

## Non-Goals

- No upload automation.
- No changes to playback or transcoding behavior.
- No speculative production fixes in these scripts.
