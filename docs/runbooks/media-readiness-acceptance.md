# Production media readiness acceptance

Use `scripts/probe_video_readiness.py --assert` after uploading a fresh media
fixture to the deployed Blossom service. This checks the production edge and
transcoder path; it is not a Viceroy test and does not upload the fixture.

Full readiness means all three playback surfaces are available:

- progressive 720p MP4;
- the HLS master manifest; and
- the 720p HLS variant manifest.

The default 180-second deadline is a liveness guard, not a latency objective or
service-level target. During the 2026-09-06 production validation, the good
fixture was ready on the first probe no more than 35 seconds after its upload
request began. The deadline is the next round number above five times that
observed upper bound. Service objectives belong in #284.

## Run the assertion

For a public fixture:

```bash
python3 scripts/probe_video_readiness.py \
  --hash <sha256> \
  --assert \
  --deadline-seconds 180
```

For an age-restricted fixture, pass a precomputed authorization value. The
script switches to GET because deployed HEAD handlers cannot evaluate viewer
authentication:

```bash
python3 scripts/probe_video_readiness.py \
  --hash <sha256> \
  --assert \
  --deadline-seconds 180 \
  --auth-header '<precomputed Authorization header>'
```

The authorization value is accepted only in assertion mode and is never
printed. Do not store it in source, shell history, fixtures, logs, or PR output.
Follow the precomputed-header convention used by `debug_upload_harness.py`.

Use `--require` to narrow the pass condition, for example
`--require mp4_720 hls_master`. The probe always checks the HLS master because
it is the deployed terminal-state sentinel: MP4 and variant-manifest routes can
still return 404 after a terminal transcode.

## Exit contract

| Code | Meaning |
| ---: | --- |
| 0 | Every required endpoint became ready. |
| 1 | Readiness was not reached before the deadline. |
| 2 | An endpoint reported terminal derivative failure. |
| 3 | Invalid usage, or the deadline ended with a required endpoint in network error. |

The last observation reports `Ready`, `Pending`, `Terminal`, `Unavailable`,
`Blocked`, `NetworkError`, or `Unknown` for each required endpoint. Public edge
routes deliberately return the same 404 for absent and moderation-hidden blobs,
so `Unavailable` must not be interpreted as proof that metadata is absent.
Age-gated unauthenticated requests return 401; 403 is also reported as blocked.

Each request wait and sleep is capped to the remaining wall-clock budget,
including DNS, redirects, and error-body reads. An in-flight read can finish in a
daemon thread after its wait expires; it cannot delay the assertion's return or
process exit. Timing arguments must be finite.
The assertion stops immediately when all required endpoints are ready or the
first endpoint reports 422. It checks the HLS master first in assertion mode.

## Production validation

Upload `scripts/tests/fixtures/readiness_ok.mp4` through the normal production
upload path and expect exit 0. Upload `readiness_terminal.mp4` and expect exit 2
with `invalid_media`. When recording evidence, redact authorization completely
and abbreviate media hashes to a short leading prefix.

Terminal status can currently oscillate from 422 back to 202 when a newer
processing callback clears the terminal flag; see #179. Failing on the first
422 avoids that race. Audio-only input is not a reliable terminal fixture
because its stream-map failure is not classified as terminal; see #230.

The 2026-09-06 production run confirmed exit 0 for the good fixture. The
moov-stripped fixture remained `202/202/404` through a 180-second assertion and
a separate 60-second assertion at one-second cadence, so production did not
surface the expected terminal state. That is evidence about the deployed
failure pipeline, not a reason to weaken this assertion's first-422 contract.
