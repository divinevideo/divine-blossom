#!/bin/bash
# Ouija mesh status line for Claude Code.
# Receives JSON session data on stdin from Claude Code.

# Read stdin JSON (Claude Code sends session data)
INPUT=$(cat)

PORT="${OUIJA_PORT:-7880}"
STATUS=$(curl -sf "http://localhost:${PORT}/api/status" 2>/dev/null) || { echo "ouija | offline"; exit 0; }

PANE="${TMUX_PANE:-$(tmux display-message -p '#{pane_id}' 2>/dev/null)}"

# My session ID — tmux pane option (set by register hook) is fastest and most current,
# then API, then derive from cwd as last resort.
MY_ID=""
if [ -n "$PANE" ]; then
  MY_ID=$(tmux display-message -t "$PANE" -p '#{@ouija_id}' 2>/dev/null)
  [ -z "$MY_ID" ] && MY_ID=$(echo "$STATUS" | jq -r --arg pane "$PANE" '.sessions[] | select(.pane == $pane) | .id' 2>/dev/null)
  if [ -z "$MY_ID" ]; then
    CWD=$(echo "$INPUT" | jq -r '.cwd // empty' 2>/dev/null)
    [ -z "$CWD" ] && CWD="$PWD"
    # Resolve worktree paths to project root
    CWD=$(echo "$CWD" | sed 's|/\.claude/worktrees/.*||')
    MY_ID=$(basename "$CWD" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-' | sed 's/^-//;s/-$//')
  fi
fi

# Peer counts (local + remote, excluding self)
if [ -n "$MY_ID" ]; then
  LOCAL_PEERS=$(echo "$STATUS" | jq --arg me "$MY_ID" '[.sessions[] | select(.id != $me and .origin == "local")] | length' 2>/dev/null)
  REMOTE_PEERS=$(echo "$STATUS" | jq '[.sessions[] | select(.origin != "local" and .origin != "human")] | length' 2>/dev/null)
else
  LOCAL_PEERS=$(echo "$STATUS" | jq '[.sessions[] | select(.origin == "local")] | length' 2>/dev/null)
  REMOTE_PEERS=$(echo "$STATUS" | jq '[.sessions[] | select(.origin != "local" and .origin != "human")] | length' 2>/dev/null)
fi

# Version
DAEMON_V=$(echo "$STATUS" | jq -r '.version // ""' 2>/dev/null)
PLUGIN_V=""
for d in "$HOME"/.claude/plugins/cache/ouija/ouija/*/; do
  [ -f "${d}.version" ] && PLUGIN_V=$(cat "${d}.version" 2>/dev/null) && break
done

# Build parts
PARTS=()

if [ -n "$MY_ID" ]; then
  PARTS+=("ouija id: $MY_ID")
elif [ -n "$PANE" ]; then
  PARTS+=("ouija id: \033[33mregistering…\033[0m")
else
  PARTS+=("ouija id: \033[33munregistered\033[0m")
fi

if [ "${REMOTE_PEERS:-0}" -gt 0 ]; then
  PARTS+=("peers: ${LOCAL_PEERS:-0} local + ${REMOTE_PEERS} remote")
else
  PARTS+=("peers: ${LOCAL_PEERS:-0}")
fi

if [ -n "$DAEMON_V" ] && [ -n "$PLUGIN_V" ] && [ "$DAEMON_V" != "$PLUGIN_V" ]; then
  PARTS+=("\033[33m⚠ daemon=${DAEMON_V} plugin=${PLUGIN_V}\033[0m")
else
  PARTS+=("v${DAEMON_V}")
fi

echo -e "$(IFS='|'; echo "${PARTS[*]}" | sed 's/|/ | /g')"
