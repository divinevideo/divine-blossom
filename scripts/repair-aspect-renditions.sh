#!/bin/bash
# ABOUTME: Regenerate audited aspect-distorted renditions serially and verify them in storage.
# ABOUTME: See docs/runbooks/repair-aspect-renditions.md for configuration and validation.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$SCRIPT_DIR/repair_aspect_renditions.py" "$@"
