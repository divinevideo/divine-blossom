#!/bin/bash
# ABOUTME: Exercises real FFmpeg compilation for all supported output aspects
# ABOUTME: Verifies the host or container has the filters and codecs the service needs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

FONT_PATH="${CREDIT_FONT_PATH:-/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf}"

ffmpeg -hide_banner -encoders 2>/dev/null | grep -q libx264
ffprobe -version >/dev/null

if ! ffmpeg -hide_banner -filters 2>/dev/null | grep -q drawtext; then
  echo "This ffmpeg has no drawtext filter, so creator credits cannot be rendered." >&2
  echo "Run scripts/end-to-end.sh instead, which uses the production toolchain." >&2
  exit 1
fi

if [ ! -f "${FONT_PATH}" ]; then
  echo "Credit font ${FONT_PATH} is missing; set CREDIT_FONT_PATH." >&2
  echo "Run scripts/end-to-end.sh instead, which uses the production toolchain." >&2
  exit 1
fi

cargo test \
  --manifest-path "${SERVICE_DIR}/Cargo.toml" \
  --test render \
  cpu_render_smoke_handles_clips_with_and_without_audio \
  --locked \
  -- \
  --ignored
