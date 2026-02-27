#!/bin/bash
PANE="${TMUX_PANE:-$(tmux display-message -p '#{pane_id}' 2>/dev/null)}"
[ -z "$PANE" ] && exit 0
RESP=$(curl -sf -X POST "http://localhost:${OUIJA_PORT:-7880}/api/hooks/session-start" \
  -H "Content-Type: application/json" \
  -d "{\"pane\":\"${PANE}\",\"cwd\":\"${PWD}\"}" 2>/dev/null) || exit 0
echo "$RESP" | jq -r '.output // empty' 2>/dev/null
