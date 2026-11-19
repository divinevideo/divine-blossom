# Reuse compatible short video streams

Rabble authorized reusing suitable existing compressed archive media instead of encoding new copies. The implementation reuses the verified original already available to the transcoder; it does not fetch arbitrary archive URLs or change the original blob.

## Approach

Blindly serving every original risks increasing repeated delivery bandwidth. Removing rendition URLs breaks current clients. Instead, conservatively stream-copy compatible short SD originals into the existing two HLS variants and progressive MP4 paths; keep encoding for other inputs. Both alternatives remain stored through the common provenance, backup, and completion path. Subtitle processing is unchanged.

## Eligibility

An engineering default limits reuse to videos no larger than 480 by 480 pixels, at most 10 seconds long, at most 30 fps, H.264 Baseline/Constrained Baseline/Main/High at level 3.1 or below, yuv420p, progressive, without B frames or nonzero rotation/display transforms, with square or unspecified pixel aspect. There must be exactly one video stream and zero or one audio stream. Optional audio must be AAC-LC, mono/stereo, 44.1 or 48 kHz, at most 96 kbps. The actual file size divided by duration must not exceed 500,000 bits/second. Unknown or malformed required facts reject reuse. Explicit repairs always encode.

Confirm the first video packet is a keyframe and video packet timestamps are finite, ordered, and bounded by the short clip duration. Check every decoded frame and reject in-band AVC parameter sets so the initial configuration cannot change mid-clip. Reject edited AAC timelines beyond ordinary encoder priming/padding. Explicit color properties must survive the staged TS container. Stream-copy into a separate staging directory with a bounded, cancellable process. Validate nonempty expected output artifacts before exposing them to the common path. A rejected or failed candidate leaves no partial outputs for fallback encoding. Preserve both variant filenames and use the existing progressive remux/loop correction and backup verification.

## Validation and rollout

Use generated media only in committed tests. Prove accepted input preserves decoded frames and audio, both MP4s and both HLS variants play, originals remain unchanged, and output duration/rotation agree. Reject high bitrate, rotation, non-square pixels, unsupported codec/audio, excessive size/duration/frame rate, malformed or missing metadata and unsafe timestamps. Exercise fallback and existing claim/backup tests. Compare accepted output sizes and local processing time with encoding, without treating local timings as a cloud savings forecast.

The implementation builds on the single-writer change in PR 385, preserving cancellation and claim ownership. No production deploy or historical media rewrite is part of this pull request. A canary must verify playback and output bytes before rollout; existing artifacts remain reusable without regeneration.
