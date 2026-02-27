#!/bin/bash
# Shared helpers for ouija e2e tests. Source this from test scripts.

# ── Color constants ─────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

# ── Logging and assertions ──────────────────────────────────────────
log()  { echo -e "${YELLOW}>>> $*${NC}"; }
pass() { echo -e "  ${GREEN}PASS${NC}: $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}FAIL${NC}: $1 (expected: $2, got: $3)"; FAIL=$((FAIL + 1)); }

assert_eq() {
    local desc="$1" actual="$2" expected="$3"
    if [ "$actual" = "$expected" ]; then pass "$desc"; else fail "$desc" "$expected" "$actual"; fi
}

assert_contains() {
    local desc="$1" haystack="$2" needle="$3"
    if echo "$haystack" | grep -qF "$needle"; then pass "$desc"; else fail "$desc" "contains '$needle'" "$haystack"; fi
}

assert_not_contains() {
    local desc="$1" haystack="$2" needle="$3"
    if ! echo "$haystack" | grep -qF "$needle"; then pass "$desc"; else fail "$desc" "not contains '$needle'" "$haystack"; fi
}

# ── wait_for — poll until a command succeeds or timeout ─────────────
# Usage: wait_for TIMEOUT_SECS COMMAND [ARGS...]
# Polls every 0.5s, returns 0 on success, 1 on timeout.
wait_for() {
    local timeout="$1"; shift
    local end=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$end" ]; do
        if "$@" 2>/dev/null; then return 0; fi
        sleep 0.5
    done
    return 1
}

# ── API helper ──────────────────────────────────────────────────────
# Usage: api BASE_URL METHOD PATH [extra curl args...]
api() {
    local base="$1" method="$2" path="$3"
    shift 3
    curl -sf -X "$method" "${base}${path}" \
        -H 'Content-Type: application/json' "$@" 2>/dev/null || echo '{"error":"curl failed"}'
}

# ── Session query helpers (all take a base URL) ─────────────────────
session_ids() {
    api "$1" GET /api/status | jq -r '[.sessions[].id] | join(" ")'
}

session_count() {
    api "$1" GET /api/status | jq -r '.sessions | length'
}

session_field() {
    local base="$1" sid="$2" field="$3"
    api "$base" GET /api/status | jq -r --arg id "$sid" --arg f "$field" \
        '.sessions[] | select(.id == $id) | .[$f] // ""'
}

remote_session_ids() {
    api "$1" GET /api/status | jq -r '[.sessions[] | select(.origin == "remote") | .id] | join(" ")'
}

transport_names() {
    api "$1" GET /api/status | jq -r '[.transports[].name] | join(" ")'
}

# ── Tmux helpers ────────────────────────────────────────────────────
# Creates a fake "claude" binary from /bin/sleep in the given dir (or a temp dir).
# Prints the directory path.
create_fake_claude() {
    local fake_bin="${1:-$(mktemp -d)}"
    cp /bin/sleep "$fake_bin/claude"
    chmod +x "$fake_bin/claude"
    echo "$fake_bin"
}

# Creates a new tmux window in the "test" session running the fake claude.
# Prints the pane ID.
create_claude_pane() {
    local fake_bin="$1"
    tmux new-window -t test
    local pane
    pane=$(tmux display-message -t test -p '#{pane_id}')
    tmux send-keys -t "$pane" "$fake_bin/claude 3600" Enter
    echo "$pane"
}

# ── MCP JSON-RPC helpers ────────────────────────────────────────────
# The MCP streamable HTTP transport returns SSE (text/event-stream).
# We extract JSON from "data: {..." lines and session ID from headers.
MCP_ID=0
MCP_SESSION=""

mcp_init() {
    local base="$1"
    MCP_ID=$((MCP_ID + 1))
    # Step 1: Send initialize request (SSE keeps connection open, timeout kills it)
    timeout 5 curl -s -D /tmp/mcp-headers -X POST "$base/mcp" \
        -H 'Content-Type: application/json' \
        -H 'Accept: application/json, text/event-stream' \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"params\":{\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1.0\"},\"protocolVersion\":\"2025-03-26\"},\"id\":$MCP_ID}" \
        >/tmp/mcp-body 2>/dev/null || true
    MCP_SESSION=$(sed -n 's/^mcp-session-id: *//Ip' /tmp/mcp-headers | tr -d '\r\n')

    # Step 2: Send notifications/initialized (required by MCP before tool calls)
    timeout 2 curl -s -X POST "$base/mcp" \
        -H 'Content-Type: application/json' \
        -H 'Accept: application/json, text/event-stream' \
        -H "Mcp-Session-Id: $MCP_SESSION" \
        -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
        >/dev/null 2>&1 || true

    # Extract JSON from SSE data: lines
    { grep '^data: {' /tmp/mcp-body || true; } | sed 's/^data: //'
}

mcp_call_tool() {
    local base="$1" tool="$2" args="$3"
    MCP_ID=$((MCP_ID + 1))
    timeout 5 curl -s -X POST "$base/mcp" \
        -H 'Content-Type: application/json' \
        -H 'Accept: application/json, text/event-stream' \
        -H "Mcp-Session-Id: $MCP_SESSION" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"$tool\",\"arguments\":$args},\"id\":$MCP_ID}" \
        >/tmp/mcp-tool-body 2>/dev/null || true
    { grep '^data: {' /tmp/mcp-tool-body || true; } | sed 's/^data: //'
}

# ── Daemon start helper ────────────────────────────────────────────
# Usage: start_daemon PORT NAME DATA_DIR [extra ouija args...]
# Prints the daemon PID. Waits up to 10s for HTTP readiness.
start_daemon() {
    local port="$1" name="$2" data_dir="$3"; shift 3
    mkdir -p "$data_dir"
    # Write default settings only if caller hasn't pre-created one
    if [ ! -f "${data_dir}/settings.json" ]; then
        echo '{"auto_register":false}' > "${data_dir}/settings.json"
    fi
    RUST_LOG=ouija=debug ouija start --port "$port" --name "$name" --data "$data_dir" "$@" \
        >"${data_dir}/daemon.log" 2>&1 &
    local pid=$!
    wait_for 10 curl -sf "http://127.0.0.1:${port}/api/status" -o /dev/null
    echo "$pid"
}

# ── Find script helper (used by hook tests) ────────────────────────
find_script() {
    local name="$1"
    local p
    for p in "$(pwd)/scripts/${name}" "/app/scripts/${name}"; do
        [ -f "$p" ] && echo "$p" && return
    done
}

# ── Export helpers for use in bash -c subshells (e.g. wait_for) ────
export -f api session_ids session_count session_field remote_session_ids transport_names

# ── Results ─────────────────────────────────────────────────────────
print_results() {
    echo ""
    echo "════════════════════════════════════════════"
    echo -e "Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}"
    if [ "$FAIL" -eq 0 ]; then
        echo -e "${GREEN}ALL TESTS PASSED${NC}"
    else
        echo -e "${RED}SOME TESTS FAILED${NC}"
    fi
    echo "════════════════════════════════════════════"
}
