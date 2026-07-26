#!/bin/bash
# ABOUTME: Exercises real FFmpeg compilation for all supported output aspects
# ABOUTME: Verifies the host or container has the filters and codecs the service needs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

ffmpeg -hide_banner -encoders 2>/dev/null | grep -q libx264
ffprobe -version >/dev/null

cargo test \
  --manifest-path "${SERVICE_DIR}/Cargo.toml" \
  --test render \
  cpu_render_smoke_handles_clips_with_and_without_audio \
  --locked \
  -- \
  --ignored
