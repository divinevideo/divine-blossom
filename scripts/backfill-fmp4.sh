#!/bin/bash
# ABOUTME: Regenerate MP4 variants from B2 or legacy GCS HLS using authenticated repair.
# ABOUTME: See docs/runbooks/fmp4-backfill.md for configuration and validation.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$SCRIPT_DIR/backfill_fmp4.py" "$@"
