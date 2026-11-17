# Reusing compatible compressed video

The transcoder can package an already small, compatible original into the existing HLS variants without re-encoding its video or audio. This reduces encoder work on qualifying inputs. It does not guarantee a fleet-wide saving: measure the accepted fraction and billed CPU after rollout. Original blobs and subtitle processing are unchanged. No bulk regeneration is required.

## Admission and fallback

The original must pass the existing pinned-object download and hash verification. Reuse accepts only MP4-family inputs with one H.264 video stream, zero or one AAC-LC audio stream, and no other streams:

- Video: Baseline, Constrained Baseline, Main or High profile; level 1.0 through 3.1; yuv420p; progressive; no B frames; even dimensions from 2 through 480 pixels in each direction; at most 30 fps and 10 seconds.
- Actual input bytes divided by video duration: at most 500,000 bits/s, including audio and container overhead. This ceiling fits both rendition policies. Larger inputs still receive compression.
- Audio, if present: mono or stereo, 44.1 or 48 kHz, at most 96,000 bits/s, and duration/start close to the video timeline.
- Square or unspecified pixel aspect, no nonzero rotation, and no display matrix. Finite, contiguous video packet timestamps must start with a keyframe and cover the advertised duration without reordering.

Missing required metadata rejects reuse. FFprobe 4.4 can omit `field_order`; when it does, every decoded video frame must explicitly be progressive. Unknown frame properties reject reuse as well. Explicit repairs and recovered repair jobs always use the encoder.

Packaging happens in a private temporary directory under the existing renewable claim. It produces both `stream_720p` and `stream_480p` playlists and single-file TS assets, even though their underlying streams are identical. One copy is strictly decoded before local publication. Failed or cancelled attempts cannot leave partial candidate files in the encoding output directory. Failures and rejected candidates fall back to normal encoding.

The shared progressive MP4 remux (including loop-duration correction and AAC recovery), required-copy verification, provenance, master-last publication and completion callback remain the common path. The rendition names preserve client contracts; they are not a promise to upscale the original.

## Verification

Run the service suite with FFmpeg and ffprobe on PATH:

```sh
cargo test --manifest-path cloud-run-transcoder/Cargo.toml --locked -- --include-ignored
python3 -m unittest discover -s cloud-run-transcoder/tests -p 'test_*.py'
```

The generated-media tests compare every decoded video frame and compressed AAC packet, verify both playback variants, original preservation, loop timing, forced repair, high-bitrate fallback and staging cleanup. CI installs FFmpeg and runs ignored media integration tests too. Verify with the deployed FFmpeg 4.4 version before rollout; newer host versions alone are insufficient.

## Rollout and measurement

This change depends on the single-writer implementation. Follow [the single-writer runbook](hls-single-writer.md), particularly the mixed-revision and queue-draining rules. A code merge is not evidence of a live transcoder revision.

During an authorized candidate rollout, use synthetic qualifying, high-bitrate and rotated inputs plus a forced repair. Verify both variant HLS playlists, ranged TS reads, progressive MP4s, duration/orientation, preserved originals, required backups, completion callbacks and subtitle dispatch. Keep any sampled real media and its identifiers private.

The existing `hls_claim` event counters gain `stream_copy_completed`, `stream_copy_rejected` and `stream_copy_failed`. `stream_copy_completed` means local HLS packaging succeeded, not that backup publication or the job completed. `encode_started` now counts only calls that actually enter the encoder. Compare matched windows for these events, successful jobs, media duration, CPU-seconds/job, billed compute, delivery bytes and failures. Rejection still incurs metadata probing; include that overhead in measurements. Do not extrapolate synthetic timing into dollar savings.

If playback or publication regressions appear, roll back this reuse commit in a build that retains the single-writer protocol. Follow its drain/rollback procedure; do not restore an older concurrent writer. No originals or existing derivatives need deletion for rollback.
