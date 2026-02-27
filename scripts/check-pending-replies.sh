#!/bin/bash
PANE="${TMUX_PANE:-$(tmux display-message -p '#{pane_id}' 2>/dev/null)}"
[ -z "$PANE" ] && exit 0
curl -sf -X POST "http://localhost:${OUIJA_PORT:-7880}/api/hooks/stop" \
  -H "Content-Type: application/json" -d "{\"pane\":\"${PANE}\"}" >/dev/null 2>&1
