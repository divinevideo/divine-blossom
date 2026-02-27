#!/bin/bash
cat > /dev/null
PANE="${TMUX_PANE:-$(tmux display-message -p '#{pane_id}' 2>/dev/null)}"
[ -z "$PANE" ] && exit 0
RESP=$(curl -sf -X POST "http://localhost:${OUIJA_PORT:-7880}/api/hooks/prompt-submit" \
  -H "Content-Type: application/json" -d "{\"pane\":\"${PANE}\"}" 2>/dev/null)
[ -n "$RESP" ] && echo "$RESP" | jq -r '.output // empty' 2>/dev/null
echo "ok" >&2
