#!/bin/bash
set -euo pipefail

# These tests must run inside Docker (via run-e2e.sh) for isolation.
# Running directly on the host picks up live tmux panes and will fail.
if [ -z "${OUIJA_E2E:-}" ] && [ ! -f /.dockerenv ]; then
    echo "ERROR: e2e tests require Docker for tmux isolation." >&2
    echo "Run:  bash tests/e2e/run-e2e.sh local" >&2
    echo "Or:   bash tests/e2e/run-e2e.sh        (all suites)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

PORT=17880
BASE="http://127.0.0.1:$PORT"

# ── Setup: tmux server ──────────────────────────────────────────────
log "Starting tmux server"
tmux new-session -d -s test -x 200 -y 50

# Create panes that simulate "claude" by running a long-lived process named claude
FAKE_BIN=$(create_fake_claude)
export PATH="$FAKE_BIN:$PATH"

PANE_A=$(create_claude_pane "$FAKE_BIN")
PANE_B=$(create_claude_pane "$FAKE_BIN")

# A pane running a normal shell (for reaper tests)
tmux new-window -t test
PANE_SHELL=$(tmux display-message -t test -p '#{pane_id}')
# Don't run anything special — default shell (bash)

# Wait for processes to start
sleep 0.5

log "Panes: claude-A=$PANE_A  claude-B=$PANE_B  shell=$PANE_SHELL"
tmux list-panes -a -F '#{pane_id} #{pane_current_command}'

# ── Setup: ouija daemon ─────────────────────────────────────────────
log "Starting ouija daemon"
rm -rf /tmp/ouija-test
mkdir -p /tmp/ouija-test
echo '{"auto_register":false,"reaper_interval_secs":1}' > /tmp/ouija-test/settings.json
DAEMON_PID=$(start_daemon $PORT "local" /tmp/ouija-test)
log "Daemon started (PID $DAEMON_PID, logs in /tmp/ouija-test/daemon.log)"

# ═══════════════════════════════════════════════════════════════════
# TESTS
# ═══════════════════════════════════════════════════════════════════

log "Test 1: Register with explicit pane"
result=$(api "$BASE" POST /api/register -d "{\"id\":\"sess-a\",\"pane\":\"$PANE_A\"}")
assert_contains "register returns id" "$result" '"registered":"sess-a"'
assert_contains "register returns pane" "$result" "\"pane\":\"$PANE_A\""
assert_eq "session count is 1" "$(session_count "$BASE")" "1"

log "Test 2: Register second session"
result=$(api "$BASE" POST /api/register -d "{\"id\":\"sess-b\",\"pane\":\"$PANE_B\"}")
assert_contains "register returns id" "$result" '"registered":"sess-b"'
assert_eq "session count is 2" "$(session_count "$BASE")" "2"

log "Test 3: Pane dedup — re-register same pane with new ID replaces old"
result=$(api "$BASE" POST /api/register -d "{\"id\":\"sess-a-renamed\",\"pane\":\"$PANE_A\"}")
assert_contains "dedup replaces old session" "$result" '"registered":"sess-a-renamed"'
assert_contains "reports replaced session" "$result" '"pane"'
ids=$(session_ids "$BASE")
assert_contains "new id present" "$ids" "sess-a-renamed"
assert_not_contains "old id gone" "$ids" "sess-a "
assert_eq "session count still 2" "$(session_count "$BASE")" "2"

log "Test 4: Rename via API"
result=$(api "$BASE" POST /api/rename -d '{"old_id":"sess-a-renamed","new_id":"sess-a2"}')
assert_contains "rename response" "$result" '"renamed"'
ids=$(session_ids "$BASE")
assert_contains "new name exists" "$ids" "sess-a2"
assert_not_contains "old name gone" "$ids" "sess-a-renamed"

log "Test 5: Remove via API"
api "$BASE" POST /api/register -d '{"id":"doomed"}' >/dev/null
count_before=$(session_count "$BASE")
result=$(api "$BASE" POST /api/remove -d '{"id":"doomed"}')
assert_contains "remove response" "$result" '"removed":"doomed"'
count_after=$(session_count "$BASE")
assert_eq "count decreased" "$count_after" "$((count_before - 1))"

log "Test 6: Remove non-existent returns error"
result=$(api "$BASE" POST /api/remove -d '{"id":"nope"}')
assert_contains "error for missing session" "$result" '"error"'

log "Test 7: Reaper removes session with dead pane"
api "$BASE" POST /api/register -d '{"id":"ghost","pane":"%99999"}' >/dev/null
log "  Waiting for reaper..."
wait_for 5 bash -c '[ "$(session_count "'"$BASE"'")" = "2" ]'
assert_eq "ghost reaped" "$(session_count "$BASE")" "2"
ids=$(session_ids "$BASE")
assert_not_contains "ghost gone" "$ids" "ghost"
assert_contains "sess-a2 survived" "$ids" "sess-a2"
assert_contains "sess-b survived" "$ids" "sess-b"

log "Test 8: Reaper keeps live claude pane"
# sess-a2 and sess-b have live panes running /tmp/claude — wait 2 reaper cycles
sleep 3
assert_eq "live sessions survive reaper" "$(session_count "$BASE")" "2"

log "Test 9: Reaper removes session whose pane runs non-claude process"
api "$BASE" POST /api/register -d "{\"id\":\"shell-session\",\"pane\":\"$PANE_SHELL\"}" >/dev/null
log "  Waiting for reaper..."
wait_for 5 bash -c '[ "$(session_count "'"$BASE"'")" = "2" ]'
assert_eq "shell pane reaped" "$(session_count "$BASE")" "2"
assert_not_contains "shell-session gone" "$(session_ids "$BASE")" "shell-session"

log "Test 10: Hook-based registration via ouija-register.sh"
mkdir -p /tmp/my-project
# Find the register hook script (local dev or Docker)
REGISTER_SCRIPT=$(find_script "ouija-register.sh")
# Enable auto-register
api "$BASE" POST /api/settings -d '{"auto_register":true}' >/dev/null
# Remove existing registration on PANE_A so the hook can register fresh
api "$BASE" POST /api/remove -d '{"id":"sess-a2"}' >/dev/null 2>&1 || true
# Run the hook — it should register a session named "my-project"
HOOK_OUT=$(echo '{"source":"startup"}' | TMUX_PANE="$PANE_A" OUIJA_PORT=$PORT bash -c "cd /tmp/my-project && bash '$REGISTER_SCRIPT'" 2>&1)
assert_contains "hook registers session" "$HOOK_OUT" "Registered as my-project on the ouija mesh"
ids=$(session_ids "$BASE")
assert_contains "hook-registered session in list" "$ids" "my-project"
# Clean up
api "$BASE" POST /api/remove -d '{"id":"my-project"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/register -d "{\"id\":\"sess-a2\",\"pane\":\"$PANE_A\"}" >/dev/null
api "$BASE" POST /api/register -d "{\"id\":\"sess-b\",\"pane\":\"$PANE_B\"}" >/dev/null

log "Test 10b: Hook respects auto_register=false setting"
api "$BASE" POST /api/settings -d '{"auto_register":false}' >/dev/null
# Remove sess-a2 so we can try to re-register on its pane
api "$BASE" POST /api/remove -d '{"id":"sess-a2"}' >/dev/null 2>&1 || true
HOOK_OUT=$(echo '{"source":"startup"}' | TMUX_PANE="$PANE_A" OUIJA_PORT=$PORT bash -c "cd /tmp/my-project && bash '$REGISTER_SCRIPT'" 2>&1)
assert_eq "hook skips when auto_register=false" "$HOOK_OUT" ""
ids=$(session_ids "$BASE")
assert_not_contains "session not registered when disabled" "$ids" "my-project"
# Restore
api "$BASE" POST /api/settings -d '{"auto_register":true}' >/dev/null
api "$BASE" POST /api/register -d "{\"id\":\"sess-a2\",\"pane\":\"$PANE_A\"}" >/dev/null

log "Test 10b2: Register hook outputs mesh state"
# Set up: register a session with role and bulletin so the hook has peers to show
api "$BASE" POST /api/register -d "{\"id\":\"hook-peer\",\"pane\":\"$PANE_B\",\"role\":\"testing\",\"bulletin\":\"can help with tests\"}" >/dev/null
# Remove existing registration on PANE_A so the hook can register fresh
api "$BASE" POST /api/remove -d '{"id":"sess-a2"}' >/dev/null 2>&1 || true
# Run the register hook script directly, simulating a SessionStart
SCRIPT_PATH=$(find_script "ouija-register.sh")
HOOK_OUTPUT=$(echo '{"source":"startup"}' | TMUX_PANE="$PANE_A" OUIJA_PORT=$PORT bash -c "cd /tmp/my-project && bash '$SCRIPT_PATH'" 2>&1)
assert_contains "hook output has registered message" "$HOOK_OUTPUT" "Registered as my-project on the ouija mesh"
assert_contains "hook output shows peer" "$HOOK_OUTPUT" "hook-peer"
assert_contains "hook output shows role" "$HOOK_OUTPUT" "testing"
assert_contains "hook output shows bulletin" "$HOOK_OUTPUT" "can help with tests"
# Clean up
api "$BASE" POST /api/remove -d '{"id":"my-project"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/remove -d '{"id":"hook-peer"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/register -d "{\"id\":\"sess-a2\",\"pane\":\"$PANE_A\"}" >/dev/null
api "$BASE" POST /api/register -d "{\"id\":\"sess-b\",\"pane\":\"$PANE_B\"}" >/dev/null

log "Test 10c: Register without pane"
result=$(api "$BASE" POST /api/register -d '{"id":"no-pane"}')
assert_contains "register without pane" "$result" '"registered":"no-pane"'
# Clean up
api "$BASE" POST /api/remove -d '{"id":"no-pane"}' >/dev/null

log "Test 10d: Register with bulletin"
result=$(api "$BASE" POST /api/register -d "{\"id\":\"bull-sess\",\"pane\":\"$PANE_A\",\"role\":\"tester\",\"bulletin\":\"need help with auth\"}")
assert_contains "register with bulletin" "$result" '"registered":"bull-sess"'
bull=$(session_field "$BASE" "bull-sess" "bulletin")
assert_eq "bulletin in status" "$bull" "need help with auth"
# Rename back for later tests
api "$BASE" POST /api/register -d "{\"id\":\"sess-a2\",\"pane\":\"$PANE_A\"}" >/dev/null

log "Test 10e: Update bulletin via API"
result=$(api "$BASE" POST /api/sessions/update -d '{"id":"sess-a2","bulletin":"offering Rust help"}')
assert_contains "update returns bulletin" "$result" '"bulletin":"offering Rust help"'
bull=$(session_field "$BASE" "sess-a2" "bulletin")
assert_eq "updated bulletin in status" "$bull" "offering Rust help"

log "Test 10f: MCP session_update sets bulletin"
result=$(mcp_call_tool "$BASE" "session_update" '{"id":"sess-b","bulletin":"can review PRs"}')
bull=$(session_field "$BASE" "sess-b" "bulletin")
assert_eq "MCP bulletin in status" "$bull" "can review PRs"

log "Test 11: Message injection into tmux pane"
result=$(api "$BASE" POST /api/send -d "{\"from\":\"sess-b\",\"to\":\"sess-a2\",\"message\":\"hello from test\",\"expects_reply\":false}")
assert_contains "send delivered" "$result" '"status":"delivered"'
wait_for 5 bash -c "tmux capture-pane -t '$PANE_A' -p | grep -qF 'hello from test'"
pane_content=$(tmux capture-pane -t "$PANE_A" -p)
assert_contains "message appears in pane" "$pane_content" "hello from test"
assert_contains "XML format no reply attr" "$pane_content" '<msg from="sess-b"'
assert_not_contains "no reply attr when expects_reply=false" "$pane_content" 'reply="true"'

log "Test 11b: Long message injection (>200 chars, uses load-buffer)"
LONG_MSG="This is a long test message that exceeds 200 characters to exercise the inject_long code path which uses tmux load-buffer and paste-buffer instead of send-keys. It includes backticks \`like this\` and parentheses (like these) to test special character handling. Padding: AAAAAAAAAAAAA done."
result=$(api "$BASE" POST /api/send -d "{\"from\":\"sess-b\",\"to\":\"sess-a2\",\"message\":\"$LONG_MSG\",\"expects_reply\":false}")
assert_contains "long send delivered" "$result" '"status":"delivered"'
wait_for 5 bash -c "tmux capture-pane -t '$PANE_A' -p -S -20 | grep -qF 'inject_long code path'"
pane_content=$(tmux capture-pane -t "$PANE_A" -p -S -20)
assert_contains "long message appears in pane" "$pane_content" "inject_long code path"

log "Test 11c: expects_reply=true adds reply attr in XML"
result=$(api "$BASE" POST /api/send -d "{\"from\":\"sess-b\",\"to\":\"sess-a2\",\"message\":\"reply needed\",\"expects_reply\":true}")
assert_contains "expects_reply send delivered" "$result" '"status":"delivered"'
assert_contains "response includes msg_id" "$result" '"msg_id"'
wait_for 5 bash -c "tmux capture-pane -t '$PANE_A' -p -S -20 | grep -qF 'reply=\"true\"'"
pane_content=$(tmux capture-pane -t "$PANE_A" -p -S -20)
assert_contains "XML format with reply attr" "$pane_content" 'reply="true"'
assert_contains "XML has from attr" "$pane_content" '<msg from="sess-b"'
assert_contains "XML has id attr" "$pane_content" 'id="'

log "Test 11d: pending-replies endpoint includes message"
PANE_A_NUM="${PANE_A#%}"
result=$(api "$BASE" GET "/api/pane/${PANE_A_NUM}/pending-replies")
assert_contains "pending replies has count" "$result" '"count"'
assert_contains "pending replies has message field" "$result" '"message"'
assert_contains "pending replies message content" "$result" "reply needed"

log "Test 11e: DELETE pending reply clears it"
delete_status=$(curl -sf -o /dev/null -w '%{http_code}' -X DELETE "${BASE}/api/pane/${PANE_A_NUM}/pending-replies/sess-b" 2>/dev/null)
assert_eq "delete pending reply returns 200" "$delete_status" "200"
# Verify it's gone
result_after=$(api "$BASE" GET "/api/pane/${PANE_A_NUM}/pending-replies")
assert_contains "pending replies count is 0" "$result_after" '"count":0'

log "Test 11f: MCP clear_pending_reply tool"
# Create a new pending reply
api "$BASE" POST /api/send -d "{\"from\":\"sess-b\",\"to\":\"sess-a2\",\"message\":\"another reply needed\",\"expects_reply\":true}" >/dev/null
sleep 0.5
# Clear it via MCP
mcp_call_tool "$BASE" "clear_pending_reply" '{"session":"sess-a2","from":"sess-b"}' >/dev/null
result_after=$(api "$BASE" GET "/api/pane/${PANE_A_NUM}/pending-replies")
assert_contains "MCP clear leaves 0 pending" "$result_after" '"count":0'

log "Test 12: Send to non-existent session"
result=$(api "$BASE" POST /api/send -d '{"from":"sess-b","to":"nobody","message":"hi"}')
assert_contains "send error for missing" "$result" '"error"'

log "Test 12a: Self-send rejected with hint"
result=$(curl -s -X POST "${BASE}/api/send" -H 'Content-Type: application/json' -d '{"from":"sess-b","to":"sess-b","message":"hi"}')
assert_contains "self-send error" "$result" '"error"'
assert_contains "self-send mentions yourself" "$result" 'cannot send a message to yourself'

# ═══════════════════════════════════════════════════════════════════
# PERSISTENCE TESTS
# ═══════════════════════════════════════════════════════════════════

log "Test 12b: Sessions persisted to disk"
assert_eq "sessions.json exists" "$(test -f /tmp/ouija-test/sessions.json && echo yes)" "yes"
persisted_count=$(jq 'length' /tmp/ouija-test/sessions.json 2>/dev/null || echo 0)
assert_eq "persisted session count matches" "$persisted_count" "$(session_count "$BASE")"

log "Test 12c: Sessions restored after daemon restart"
# Disable auto-register so restarted daemon doesn't discover extra panes
api "$BASE" POST /api/settings -d '{"auto_register":false}' >/dev/null
count_before=$(session_count "$BASE")
ids_before=$(session_ids "$BASE")
log "  Sessions before restart: $ids_before ($count_before)"
# Kill and restart daemon
kill $DAEMON_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
sleep 0.5
RUST_LOG=ouija=debug ouija start --port $PORT --data /tmp/ouija-test >/tmp/daemon-restart.log 2>&1 &
DAEMON_PID=$!
# Wait for HTTP to be ready
wait_for 10 curl -sf "$BASE/api/status" -o /dev/null
# Wait for async session restoration (runs in background spawn after HTTP is up)
for i in $(seq 1 50); do
    count_after=$(session_count "$BASE")
    if [ "$count_after" = "$count_before" ]; then break; fi
    sleep 0.2
done
count_after=$(session_count "$BASE")
ids_after=$(session_ids "$BASE")
log "  Sessions after restart: $ids_after ($count_after)"
assert_eq "session count preserved after restart" "$count_after" "$count_before"
# Check that each session ID survived
for sid in $ids_before; do
    assert_contains "session $sid survived restart" "$ids_after" "$sid"
done
# Restore auto_register
api "$BASE" POST /api/settings -d '{"auto_register":true}' >/dev/null

log "Test 12d: Custom session names survive restart with auto-register ON"
# Register a session with a custom name that differs from its directory basename
api "$BASE" POST /api/register -d "{\"id\":\"my-custom-name\",\"pane\":\"$PANE_A\",\"metadata\":{\"project_dir\":\"/tmp\"}}" >/dev/null
ids_before=$(session_ids "$BASE")
assert_contains "custom name registered" "$ids_before" "my-custom-name"
# Restart daemon WITH auto_register enabled — the bug would overwrite "my-custom-name" with "tmp"
kill $DAEMON_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
sleep 0.5
echo '{"auto_register":true,"reaper_interval_secs":1}' > /tmp/ouija-test/settings.json
RUST_LOG=ouija=debug ouija start --port $PORT --data /tmp/ouija-test >/tmp/daemon-restart2.log 2>&1 &
DAEMON_PID=$!
wait_for 10 curl -sf "$BASE/api/status" -o /dev/null
# Wait for session restoration
for i in $(seq 1 50); do
    ids_after=$(session_ids "$BASE")
    if echo "$ids_after" | grep -qF "my-custom-name"; then break; fi
    sleep 0.2
done
ids_after=$(session_ids "$BASE")
assert_contains "custom name survives restart" "$ids_after" "my-custom-name"
assert_not_contains "auto-register did not overwrite with basename" "$ids_after" " tmp"
# Clean up: remove custom session and disable auto_register for remaining tests
api "$BASE" POST /api/remove -d '{"id":"my-custom-name"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/settings -d '{"auto_register":false}' >/dev/null

# ═══════════════════════════════════════════════════════════════════
# MCP PROTOCOL TESTS
# ═══════════════════════════════════════════════════════════════════

# Clean up API sessions first
api "$BASE" POST /api/remove -d '{"id":"sess-a2"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/remove -d '{"id":"sess-b"}' >/dev/null 2>&1 || true

log "Test 13: MCP initialize — server info returned"
mcp_init "$BASE" >/dev/null
init_result=$(grep '^data: {' /tmp/mcp-body | sed 's/^data: //')
assert_contains "init has server info" "$init_result" '"serverInfo"'
# stateful_mode=false means no session ID header — that's expected
if [ -n "$MCP_SESSION" ]; then
    log "  MCP session: $MCP_SESSION"
else
    log "  (stateless mode — no session ID, expected)"
fi

log "Test 14: MCP session_register without pane — auto-detects or errors"
result=$(mcp_call_tool "$BASE" "session_register" '{"id":"mcp-no-pane"}')
# If an unregistered claude pane exists, auto-detect succeeds; otherwise it errors.
if echo "$result" | grep -qF "registered as mcp-no-pane"; then
    pass "register without pane auto-detected"
    api "$BASE" POST /api/remove -d '{"id":"mcp-no-pane"}' >/dev/null 2>&1 || true
else
    assert_contains "error about pane" "$result" "pane is required"
    assert_contains "tells to run echo" "$result" 'echo $TMUX_PANE'
    assert_not_contains "not registered" "$(session_ids "$BASE")" "mcp-no-pane"
fi

log "Test 15: MCP session_register with pane — succeeds"
result=$(mcp_call_tool "$BASE" "session_register" "{\"id\":\"mcp-ok\",\"pane\":\"$PANE_A\"}")
assert_contains "registered via MCP" "$result" "registered as mcp-ok"
ids=$(session_ids "$BASE")
assert_contains "MCP session in list" "$ids" "mcp-ok"

log "Test 16: MCP session_list — returns sessions"
result=$(mcp_call_tool "$BASE" "session_list" '{}')
assert_contains "list contains session" "$result" "mcp-ok"

log "Test 17: MCP session_send — delivers message"
# Register a second session for messaging
api "$BASE" POST /api/register -d "{\"id\":\"mcp-target\",\"pane\":\"$PANE_B\"}" >/dev/null
result=$(mcp_call_tool "$BASE" "session_send" '{"from":"mcp-ok","to":"mcp-target","message":"hello via mcp","expects_reply":false}')
assert_contains "MCP send delivered" "$result" "delivered"
wait_for 5 bash -c "tmux capture-pane -t '$PANE_B' -p | grep -qF 'hello via mcp'"
pane_content=$(tmux capture-pane -t "$PANE_B" -p)
assert_contains "MCP message in pane" "$pane_content" "hello via mcp"

log "Test 18: MCP session_send to missing session — error"
result=$(mcp_call_tool "$BASE" "session_send" '{"from":"mcp-ok","to":"ghost","message":"hi","expects_reply":false}')
assert_contains "MCP send error" "$result" "not found"

log "Test 19: MCP pane dedup — re-register same pane via MCP replaces old"
result=$(mcp_call_tool "$BASE" "session_register" "{\"id\":\"mcp-renamed\",\"pane\":\"$PANE_A\"}")
assert_contains "MCP dedup replaces" "$result" "registered as mcp-renamed"
ids=$(session_ids "$BASE")
assert_contains "new MCP id present" "$ids" "mcp-renamed"
assert_not_contains "old MCP id gone" "$ids" "mcp-ok"

log "Test 19b: MCP re-register same ID updates metadata"
result=$(mcp_call_tool "$BASE" "session_register" "{\"id\":\"mcp-ok\",\"pane\":\"$PANE_A\",\"role\":\"updated-role\"}")
assert_contains "same-id re-register succeeds" "$result" "registered as mcp-ok"

# Cleanup MCP sessions
api "$BASE" POST /api/remove -d '{"id":"mcp-ok"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/remove -d '{"id":"mcp-target"}' >/dev/null 2>&1 || true

log "Test 19c: MCP session_rename — rename preserves session"
api "$BASE" POST /api/register -d "{\"id\":\"rename-src\",\"pane\":\"$PANE_A\",\"role\":\"tester\"}" >/dev/null
result=$(mcp_call_tool "$BASE" "session_rename" '{"old_id":"rename-src","new_id":"rename-dst"}')
assert_contains "19c: rename succeeded" "$result" "renamed 'rename-src' to 'rename-dst'"
ids=$(session_ids "$BASE")
assert_contains "19c: new name present" "$ids" "rename-dst"
assert_not_contains "19c: old name gone" "$ids" "rename-src"
# Verify role preserved after rename
role_after=$(session_field "$BASE" "rename-dst" "role")
assert_eq "19c: role preserved after rename" "$role_after" "tester"

log "Test 19d: MCP session_send to old name returns alias hint"
api "$BASE" POST /api/register -d "{\"id\":\"rename-sender\",\"pane\":\"$PANE_B\"}" >/dev/null
result=$(mcp_call_tool "$BASE" "session_send" '{"from":"rename-sender","to":"rename-src","message":"hello old name","expects_reply":false}')
assert_contains "19d: error mentions rename" "$result" "was renamed to"
# Cleanup
api "$BASE" POST /api/remove -d '{"id":"rename-dst"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/remove -d '{"id":"rename-sender"}' >/dev/null 2>&1 || true

log "Test 19e: MCP session_send auto-starts session from project index"
# Create a temp project directory
AUTOSTART_DIR=$(mktemp -d)
mkdir -p "$AUTOSTART_DIR/autostart-proj"
# Configure projects_dir
api "$BASE" POST /api/settings -d "{\"projects_dir\":\"$AUTOSTART_DIR\"}" >/dev/null
# Wait for project index to refresh
sleep 2
# Register a sender session
api "$BASE" POST /api/register -d "{\"id\":\"autostart-sender\",\"pane\":\"$PANE_A\"}" >/dev/null
# Send to a session name that matches the project (session doesn't exist yet)
result=$(mcp_call_tool "$BASE" "session_send" '{"from":"autostart-sender","to":"autostart-proj","message":"hello auto","expects_reply":false}')
assert_contains "19e: auto-started" "$result" "auto-started"
# Verify the session was created
wait_for 5 bash -c "session_ids '$BASE' | grep -qF 'autostart-proj'"
ids=$(session_ids "$BASE")
assert_contains "19e: session registered" "$ids" "autostart-proj"
# Cleanup: kill the auto-started session, remove temp dir
api "$BASE" POST /api/sessions/kill -d '{"name":"autostart-proj"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/remove -d '{"id":"autostart-sender"}' >/dev/null 2>&1 || true
rm -rf "$AUTOSTART_DIR"
# Restore projects_dir
api "$BASE" POST /api/settings -d '{"projects_dir":"/tmp/projects"}' >/dev/null

# ══════════════════════════════════════════════════════════════════════
# ── Scheduled Tasks ─────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════
log "Scheduled Tasks tests"

# T1: Create task via API
T1=$(api "$BASE" POST /api/tasks -d '{"name":"test-task","cron":"*/5 * * * *","target_session":"e2e-test","prompt":"hello from scheduler"}')
T1_ID=$(echo "$T1" | jq -r '.created // ""')
assert_contains "T1: create task returns id" "$T1" "created"

# T2: List tasks shows it
T2=$(api "$BASE" GET /api/tasks)
assert_contains "T2: list tasks contains task" "$T2" "$T1_ID"
assert_contains "T2: list tasks has name" "$T2" "test-task"

# T3: Trigger task manually (session doesn't exist, so it'll fail — but the trigger endpoint works)
T3=$(api "$BASE" POST /api/tasks/trigger -d "{\"id\":\"$T1_ID\"}")
assert_contains "T3: trigger task returns id" "$T3" "$T1_ID"

# T4: Task runs logged
T4=$(api "$BASE" GET /api/task-runs)
assert_contains "T4: task runs has entry" "$T4" "$T1_ID"

# T5: Disable task
T5=$(api "$BASE" POST /api/tasks/disable -d "{\"id\":\"$T1_ID\"}")
assert_contains "T5: disable task" "$T5" "$T1_ID"
T5_CHECK=$(api "$BASE" GET /api/tasks)
assert_contains "T5: task is disabled" "$T5_CHECK" "\"enabled\":false"

# T6: Enable task
T6=$(api "$BASE" POST /api/tasks/enable -d "{\"id\":\"$T1_ID\"}")
assert_contains "T6: enable task" "$T6" "$T1_ID"
T6_CHECK=$(api "$BASE" GET /api/tasks)
assert_contains "T6: task is enabled" "$T6_CHECK" "\"enabled\":true"

# T7: Delete task
T7=$(api "$BASE" DELETE /api/tasks -d "{\"id\":\"$T1_ID\"}")
assert_contains "T7: delete task" "$T7" "$T1_ID"

# T8: List tasks empty after delete
T8=$(api "$BASE" GET /api/tasks)
assert_not_contains "T8: task gone after delete" "$T8" "$T1_ID"

# ═══════════════════════════════════════════════════════════════════
# HUMAN SESSION TESTS (API level)
# ═══════════════════════════════════════════════════════════════════
log "Test H1: Add human session via API"
H1=$(api "$BASE" POST /api/humans -d '{"name":"daniel","npub":"npub1testfake"}')
assert_contains "H1: add human" "$H1" '"status":"added"'

log "Test H2: List humans shows the new entry"
H2=$(api "$BASE" GET /api/humans)
assert_contains "H2: list has daniel" "$H2" '"name":"daniel"'
assert_contains "H2: list has npub" "$H2" '"npub":"npub1testfake"'

log "Test H3: Human appears in session list with origin human"
H3_ORIGIN=$(session_field "$BASE" "daniel" "origin")
assert_eq "H3: human session has origin human" "$H3_ORIGIN" "human"

log "Test H4: Duplicate human name rejected"
H4=$(api "$BASE" POST /api/humans -d '{"name":"daniel","npub":"npub1other"}')
assert_contains "H4: duplicate rejected" "$H4" '"error"'

log "Test H5: Remove human session"
H5=$(api "$BASE" DELETE /api/humans -d '{"name":"daniel"}')
assert_contains "H5: remove human" "$H5" '"status":"removed"'

log "Test H6: Human gone from session list"
H6_IDS=$(session_ids "$BASE")
assert_not_contains "H6: daniel gone" "$H6_IDS" "daniel"

log "Test H7: Human gone from humans list"
H7=$(api "$BASE" GET /api/humans)
assert_not_contains "H7: humans list empty" "$H7" '"name":"daniel"'

log "Test H8: Remove nonexistent human returns not found"
H8=$(api "$BASE" DELETE /api/humans -d '{"name":"ghost"}')
assert_contains "H8: not found" "$H8" '"error"'

# ═══════════════════════════════════════════════════════════════════
# SESSION LIFECYCLE TESTS (kill / start / restart)
# ═══════════════════════════════════════════════════════════════════

# Configure projects_dir for start/restart tests
api "$BASE" POST /api/settings -d '{"projects_dir":"/tmp/projects"}' >/dev/null

log "Test L1: Start session via REST API"
L1=$(api "$BASE" POST /api/sessions/start -d '{"name":"lifecycle-test"}')
assert_contains "L1: start returns 202 session name" "$L1" "lifecycle-test"
assert_contains "L1: start returns starting status" "$L1" "starting"
# Wait for async session to register
wait_for 10 bash -c "session_ids '$BASE' | grep -qF 'lifecycle-test'"
L1_IDS=$(session_ids "$BASE")
assert_contains "L1: session registered" "$L1_IDS" "lifecycle-test"
# Verify directory was created
assert_eq "L1: project dir created" "$(test -d /tmp/projects/lifecycle-test && echo yes)" "yes"
# Verify tmux session exists with matching window name
tmux_sessions=$(tmux list-sessions -F '#{session_name}' 2>/dev/null)
assert_contains "L1: tmux session created" "$tmux_sessions" "lifecycle-test"
L1_PANE=$(session_field "$BASE" "lifecycle-test" "pane")
L1_WIN_NAME=$(tmux display-message -t "$L1_PANE" -p '#{window_name}' 2>/dev/null)
assert_eq "L1: window name matches session name" "$L1_WIN_NAME" "lifecycle-test"

log "Test L1b: Start session when tmux session name already taken"
# Create a bare tmux session with a name that will collide
tmux new-session -d -s "tmux-collide"
L1B=$(api "$BASE" POST /api/sessions/start -d '{"name":"tmux-collide","project_dir":"/tmp/projects/tmux-collide"}')
assert_contains "L1b: start returns 202" "$L1B" "tmux-collide"
wait_for 10 bash -c "session_ids '$BASE' | grep -qF 'tmux-collide'"
# Verify the new pane lives as a window inside the existing tmux session
L1B_PANE=$(session_field "$BASE" "tmux-collide" "pane")
L1B_TMUX_SESS=$(tmux display-message -t "$L1B_PANE" -p '#{session_name}' 2>/dev/null)
assert_eq "L1b: pane is a window in the existing tmux session" "$L1B_TMUX_SESS" "tmux-collide"
# Verify window name matches ouija session name
L1B_WIN_NAME=$(tmux display-message -t "$L1B_PANE" -p '#{window_name}' 2>/dev/null)
assert_eq "L1b: window named after ouija session" "$L1B_WIN_NAME" "tmux-collide"
# Clean up
api "$BASE" POST /api/sessions/kill -d '{"name":"tmux-collide"}' >/dev/null 2>&1 || true
tmux kill-session -t tmux-collide 2>/dev/null || true

log "Test L2: Start duplicate session restarts existing"
L2=$(api "$BASE" POST /api/sessions/start -d '{"name":"lifecycle-test"}')
assert_contains "L2: duplicate returns 202 (restart)" "$L2" "lifecycle-test"

log "Test L3: Kill session via REST API"
# Wait for session to have a pane (async start may still be in progress)
wait_for 10 bash -c "session_field '$BASE' 'lifecycle-test' 'pane' | grep -q '%'"
L3=$(api "$BASE" POST /api/sessions/kill -d '{"name":"lifecycle-test"}')
assert_contains "L3: kill response" "$L3" "removed"
wait_for 5 bash -c "! session_ids '$BASE' | grep -qF 'lifecycle-test'"
# Verify session removed from daemon
L3_IDS=$(session_ids "$BASE")
assert_not_contains "L3: session removed" "$L3_IDS" "lifecycle-test"

log "Test L4: Kill non-existent session"
L4=$(api "$BASE" POST /api/sessions/kill -d '{"name":"no-such-session"}')
assert_contains "L4: not found" "$L4" "not found"

log "Test L5: Restart session via REST API (creates new if not running)"
L5=$(api "$BASE" POST /api/sessions/restart -d '{"name":"restart-test"}')
assert_contains "L5: restart response has pane" "$L5" "pane"
wait_for 5 bash -c "session_ids '$BASE' | grep -qF 'restart-test'"
L5_IDS=$(session_ids "$BASE")
assert_contains "L5: restarted session registered" "$L5_IDS" "restart-test"

log "Test L6: Restart existing session (kill + start)"
L6=$(api "$BASE" POST /api/sessions/restart -d '{"name":"restart-test"}')
assert_contains "L6: restart response" "$L6" "restarted"
wait_for 5 bash -c "session_ids '$BASE' | grep -qF 'restart-test'"
L6_IDS=$(session_ids "$BASE")
assert_contains "L6: session still registered after restart" "$L6_IDS" "restart-test"

log "Test L6b: Metadata preserved after restart"
# Register a session with rich metadata, restart, verify metadata survives
# Use a pane with fake claude process so pane_alive (has_claude_descendant) passes
L6B_PANE=$(create_claude_pane "$FAKE_BIN")
sleep 0.5
api "$BASE" POST /api/register -d "{\"id\":\"meta-restart\",\"pane\":\"$L6B_PANE\",\"vim_mode\":true,\"role\":\"backend\",\"project_dir\":\"/tmp/meta-test\"}" >/dev/null
L6B_ROLE_BEFORE=$(session_field "$BASE" "meta-restart" "role")
assert_eq "L6b: role set before restart" "$L6B_ROLE_BEFORE" "backend"
# Restart and check metadata survived
api "$BASE" POST /api/sessions/restart -d '{"name":"meta-restart"}' >/dev/null
wait_for 5 bash -c "session_ids '$BASE' | grep -qF 'meta-restart'"
L6B_VIM=$(session_field "$BASE" "meta-restart" "vim_mode")
L6B_ROLE=$(session_field "$BASE" "meta-restart" "role")
L6B_DIR=$(session_field "$BASE" "meta-restart" "project_dir")
assert_eq "L6b: vim_mode preserved" "$L6B_VIM" "true"
assert_eq "L6b: role preserved" "$L6B_ROLE" "backend"
assert_eq "L6b: project_dir preserved" "$L6B_DIR" "/tmp/meta-test"

log "Test L6c: Pane ID changes after restart"
L6C_PANE_BEFORE=$(session_field "$BASE" "meta-restart" "pane")
api "$BASE" POST /api/sessions/restart -d '{"name":"meta-restart"}' >/dev/null
wait_for 5 bash -c '[ "$(session_field "'"$BASE"'" "meta-restart" "pane")" != "'"$L6C_PANE_BEFORE"'" ]'
L6C_PANE_AFTER=$(session_field "$BASE" "meta-restart" "pane")
if [ -n "$L6C_PANE_BEFORE" ] && [ -n "$L6C_PANE_AFTER" ] && [ "$L6C_PANE_BEFORE" != "$L6C_PANE_AFTER" ]; then
    pass "L6c: pane changed after restart ($L6C_PANE_BEFORE -> $L6C_PANE_AFTER)"
else
    fail "L6c: pane should change after restart" "different pane" "before=$L6C_PANE_BEFORE after=$L6C_PANE_AFTER"
fi

log "Test L6d: Restart pane runs correct command"
L6D_PANE=$(session_field "$BASE" "meta-restart" "pane")
wait_for 5 bash -c "tmux capture-pane -t '$L6D_PANE' -p 2>/dev/null | grep -qE '(--resume|--continue)'"
L6D_CONTENT=$(tmux capture-pane -t "$L6D_PANE" -p 2>/dev/null || echo "")
if echo "$L6D_CONTENT" | grep -qE '(--resume|--continue)'; then
    pass "L6d: restart pane has --resume or --continue flag"
else
    fail "L6d: restart pane should have --resume or --continue" "--resume or --continue" "$L6D_CONTENT"
fi

log "Test L6e: Reaper grace period — session survives reaper cycle after restart"
api "$BASE" POST /api/sessions/restart -d '{"name":"meta-restart"}' >/dev/null
sleep 3
L6E_IDS=$(session_ids "$BASE")
assert_contains "L6e: session survives reaper after restart" "$L6E_IDS" "meta-restart"

log "Test L6f: Fresh restart via API"
L6F=$(api "$BASE" POST /api/sessions/restart -d '{"name":"meta-restart","fresh":true}')
assert_contains "L6f: fresh restart response" "$L6F" "restarted"
wait_for 5 bash -c "session_ids '$BASE' | grep -qF 'meta-restart'"
L6F_IDS=$(session_ids "$BASE")
assert_contains "L6f: session survived fresh restart" "$L6F_IDS" "meta-restart"

# ═══════════════════════════════════════════════════════════════════
# (Mesh context embedded resources were removed in favor of the session-diff hook)

# Clean up lifecycle sessions
api "$BASE" POST /api/sessions/kill -d '{"name":"meta-restart"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/sessions/kill -d '{"name":"restart-test"}' >/dev/null 2>&1 || true

# --- MCP lifecycle tests ---

log "Test L7: MCP session_start"
L7=$(mcp_call_tool "$BASE" "session_start" '{"name":"mcp-lifecycle"}')
assert_contains "L7: MCP start has pane" "$L7" "pane"
wait_for 5 bash -c "session_ids '$BASE' | grep -qF 'mcp-lifecycle'"
L7_IDS=$(session_ids "$BASE")
assert_contains "L7: MCP started session registered" "$L7_IDS" "mcp-lifecycle"

log "Test L8: MCP session_kill"
L8=$(mcp_call_tool "$BASE" "session_kill" '{"name":"mcp-lifecycle"}')
assert_contains "L8: MCP kill removed" "$L8" "removed"
wait_for 5 bash -c "! session_ids '$BASE' | grep -qF 'mcp-lifecycle'"
L8_IDS=$(session_ids "$BASE")
assert_not_contains "L8: MCP killed session gone" "$L8_IDS" "mcp-lifecycle"

log "Test L9: MCP session_restart"
# Start first, then restart
mcp_call_tool "$BASE" "session_start" '{"name":"mcp-restart"}' >/dev/null
wait_for 5 bash -c "session_ids '$BASE' | grep -qF 'mcp-restart'"
L9=$(mcp_call_tool "$BASE" "session_restart" '{"name":"mcp-restart"}')
assert_contains "L9: MCP restart response" "$L9" "restarted"
wait_for 5 bash -c "session_ids '$BASE' | grep -qF 'mcp-restart'"
L9_IDS=$(session_ids "$BASE")
assert_contains "L9: MCP restarted session registered" "$L9_IDS" "mcp-restart"

log "Test L10: MCP session_restart with fresh=true"
L10=$(mcp_call_tool "$BASE" "session_restart" '{"name":"mcp-restart","fresh":true}')
assert_contains "L10: MCP fresh restart response" "$L10" "restarted"
wait_for 5 bash -c "session_ids '$BASE' | grep -qF 'mcp-restart'"
L10_IDS=$(session_ids "$BASE")
assert_contains "L10: MCP fresh restarted session registered" "$L10_IDS" "mcp-restart"

log "Test L11: Task creation with on_fire new_session"
L11=$(api "$BASE" POST /api/tasks -d '{"name":"fresh-task","cron":"0 0 * * *","target_session":"mcp-restart","prompt":"test prompt","on_fire":{"mode":"new_session"}}')
assert_contains "L11: create new_session task returns id" "$L11" "created"
L11_ID=$(echo "$L11" | jq -r '.created')
L11_TASK=$(api "$BASE" GET "/api/tasks")
L11_MODE=$(echo "$L11_TASK" | jq -r --arg id "$L11_ID" '.tasks[] | select(.id == $id) | .on_fire.mode')
assert_eq "L11: task on_fire mode is new_session" "$L11_MODE" "new_session"
api "$BASE" DELETE "/api/tasks/$L11_ID" >/dev/null

log "Test L12: Task creation with persistent_worktree"
L12=$(api "$BASE" POST /api/tasks -d '{"name":"wt-task","cron":"0 0 * * *","target_session":"mcp-restart","prompt":"test prompt","on_fire":{"mode":"persistent_worktree"}}')
assert_contains "L12: create persistent worktree task returns id" "$L12" "created"
L12_ID=$(echo "$L12" | jq -r '.created')
L12_TASK=$(api "$BASE" GET "/api/tasks")
L12_MODE=$(echo "$L12_TASK" | jq -r --arg id "$L12_ID" '.tasks[] | select(.id == $id) | .on_fire.mode')
assert_eq "L12: task on_fire mode is persistent_worktree" "$L12_MODE" "persistent_worktree"
api "$BASE" DELETE "/api/tasks/$L12_ID" >/dev/null

log "Test L13: Task creation with disposable_worktree"
L13=$(api "$BASE" POST /api/tasks -d '{"name":"pf-task","cron":"0 0 * * *","target_session":"mcp-restart","prompt":"test prompt","on_fire":{"mode":"disposable_worktree"}}')
assert_contains "L13: create disposable worktree task returns id" "$L13" "created"
L13_ID=$(echo "$L13" | jq -r '.created')
L13_TASK=$(api "$BASE" GET "/api/tasks")
L13_MODE=$(echo "$L13_TASK" | jq -r --arg id "$L13_ID" '.tasks[] | select(.id == $id) | .on_fire.mode')
assert_eq "L13: task on_fire mode is disposable_worktree" "$L13_MODE" "disposable_worktree"
api "$BASE" DELETE "/api/tasks/$L13_ID" >/dev/null

log "Test L15: Auto-worktree when directory conflicts"
# Register a session with project_dir that will conflict with a new session_start
mkdir -p /tmp/projects/auto-wt-test
git init /tmp/projects/auto-wt-test >/dev/null 2>&1
api "$BASE" POST /api/register -d "{\"id\":\"existing-sess\",\"pane\":\"$PANE_A\",\"project_dir\":\"/tmp/projects/auto-wt-test\"}" >/dev/null
L15=$(api "$BASE" POST /api/sessions/start -d '{"name":"auto-wt-test"}')
assert_contains "L15: start succeeds" "$L15" "started"
assert_contains "L15: auto-worktree noted" "$L15" "auto-enabled"
L15_STATUS=$(api "$BASE" GET /api/status)
L15_WT=$(echo "$L15_STATUS" | jq -r '.sessions[] | select(.id == "auto-wt-test") | .worktree')
assert_eq "L15: auto-worktree session has worktree=true" "$L15_WT" "true"
api "$BASE" POST /api/sessions/kill -d '{"name":"auto-wt-test"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/remove -d '{"id":"existing-sess"}' >/dev/null 2>&1 || true

log "Test L14: Start session with worktree=true"
mkdir -p /tmp/projects/wt-sess
git init /tmp/projects/wt-sess >/dev/null 2>&1
L14=$(api "$BASE" POST /api/sessions/start -d '{"name":"wt-sess","worktree":true}')
assert_contains "L14: start worktree session" "$L14" "started"
L14_STATUS=$(api "$BASE" GET /api/status)
L14_WT=$(echo "$L14_STATUS" | jq -r '.sessions[] | select(.id == "wt-sess") | .worktree')
assert_eq "L14: session has worktree=true in metadata" "$L14_WT" "true"
api "$BASE" POST /api/sessions/kill -d '{"name":"wt-sess"}' >/dev/null 2>&1 || true

# Install fake claude globally for prompt injection tests (L16-L18).
# Needs to: (1) accept any args, (2) report as "claude" to pane_current_command.
# Solution: script that exec's into a sleep binary named "claude".
mkdir -p /tmp/fakebin
cp /bin/sleep /tmp/fakebin/claude
chmod +x /tmp/fakebin/claude
printf '#!/bin/bash\nexec /tmp/fakebin/claude 3600\n' > /usr/local/bin/claude
chmod +x /usr/local/bin/claude

log "Test L16: session_start with from param uses XML format with reply=true"
L16=$(api "$BASE" POST /api/sessions/start -d '{"name":"from-test","prompt":"what is your status?","from":"orchestrator"}')
assert_contains "L16: start succeeds" "$L16" "started"
wait_for 5 bash -c "session_ids '$BASE' | grep -qF 'from-test'"
L16_PANE=$(session_field "$BASE" "from-test" "pane")
wait_for 12 bash -c "tmux capture-pane -t '$L16_PANE' -p -J -S -30 | grep -qF 'from=\"orchestrator\"'"
L16_CONTENT=$(tmux capture-pane -t "$L16_PANE" -p -J -S -30)
assert_contains "L16: prompt has XML from attr" "$L16_CONTENT" 'from="orchestrator"'
assert_contains "L16: prompt has reply attr" "$L16_CONTENT" 'reply="true"'
assert_contains "L16: prompt has message content" "$L16_CONTENT" "what is your status?"
# Kill pane directly (fake claude makes API kill slow due to /exit timeout)
tmux kill-pane -t "$L16_PANE" 2>/dev/null || true
api "$BASE" POST /api/remove -d '{"id":"from-test"}' >/dev/null 2>&1 || true

log "Test L17: session_start with from + expects_reply=false omits reply attr"
L17=$(api "$BASE" POST /api/sessions/start -d '{"name":"from-noreply","prompt":"FYI deployed v2","from":"deployer","expects_reply":false}')
assert_contains "L17: start succeeds" "$L17" "started"
wait_for 5 bash -c "session_ids '$BASE' | grep -qF 'from-noreply'"
L17_PANE=$(session_field "$BASE" "from-noreply" "pane")
wait_for 12 bash -c "tmux capture-pane -t '$L17_PANE' -p -J -S -30 | grep -qF 'from=\"deployer\"'"
L17_CONTENT=$(tmux capture-pane -t "$L17_PANE" -p -J -S -30)
assert_contains "L17: prompt has XML from attr" "$L17_CONTENT" 'from="deployer"'
assert_not_contains "L17: no reply attr" "$L17_CONTENT" 'reply="true"'
tmux kill-pane -t "$L17_PANE" 2>/dev/null || true
api "$BASE" POST /api/remove -d '{"id":"from-noreply"}' >/dev/null 2>&1 || true

log "Test L18: session_start without from injects plain prompt"
L18=$(api "$BASE" POST /api/sessions/start -d '{"name":"plain-prompt","prompt":"just a plain prompt"}')
assert_contains "L18: start succeeds" "$L18" "started"
wait_for 5 bash -c "session_ids '$BASE' | grep -qF 'plain-prompt'"
L18_PANE=$(session_field "$BASE" "plain-prompt" "pane")
wait_for 12 bash -c "tmux capture-pane -t '$L18_PANE' -p -J -S -30 | grep -qF 'just a plain prompt'"
L18_CONTENT=$(tmux capture-pane -t "$L18_PANE" -p -J -S -30)
assert_contains "L18: plain prompt injected" "$L18_CONTENT" "just a plain prompt"
assert_not_contains "L18: no XML msg tag" "$L18_CONTENT" "<msg "
tmux kill-pane -t "$L18_PANE" 2>/dev/null || true
api "$BASE" POST /api/remove -d '{"id":"plain-prompt"}' >/dev/null 2>&1 || true

log "Test L19: Sessions sharing project_dir are grouped in same tmux session"
mkdir -p /tmp/projects/grouped-repo
L19A=$(api "$BASE" POST /api/sessions/start -d '{"name":"group-a","project_dir":"/tmp/projects/grouped-repo"}')
assert_contains "L19a: first start succeeds" "$L19A" "started"
wait_for 5 bash -c "session_ids '$BASE' | grep -qF 'group-a'"
L19A_PANE=$(session_field "$BASE" "group-a" "pane")
# Get the tmux session name of the first pane
L19A_TMUX_SESS=$(tmux display-message -t "$L19A_PANE" -p '#{session_name}')
assert_eq "L19a: tmux session named after directory" "$L19A_TMUX_SESS" "grouped-repo"
L19B=$(api "$BASE" POST /api/sessions/start -d '{"name":"group-b","project_dir":"/tmp/projects/grouped-repo","worktree":true}')
assert_contains "L19b: second start succeeds" "$L19B" "started"
wait_for 5 bash -c "session_ids '$BASE' | grep -qF 'group-b'"
L19B_PANE=$(session_field "$BASE" "group-b" "pane")
L19B_TMUX_SESS=$(tmux display-message -t "$L19B_PANE" -p '#{session_name}')
assert_eq "L19b: second session in same tmux session" "$L19B_TMUX_SESS" "$L19A_TMUX_SESS"
# Verify window names match ouija session names
L19A_WIN=$(tmux display-message -t "$L19A_PANE" -p '#{window_name}')
L19B_WIN=$(tmux display-message -t "$L19B_PANE" -p '#{window_name}')
assert_eq "L19c: first window named after ouija session" "$L19A_WIN" "group-a"
assert_eq "L19d: second window named after ouija session" "$L19B_WIN" "group-b"
tmux kill-pane -t "$L19A_PANE" 2>/dev/null || true
tmux kill-pane -t "$L19B_PANE" 2>/dev/null || true
api "$BASE" POST /api/remove -d '{"id":"group-a"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/remove -d '{"id":"group-b"}' >/dev/null 2>&1 || true

# Remove fake claude to avoid slowing down subsequent kill operations
rm -f /usr/local/bin/claude

# Clean up
api "$BASE" POST /api/sessions/kill -d '{"name":"mcp-restart"}' >/dev/null 2>&1 || true

# ═══════════════════════════════════════════════════════════════════
# IDLE DETECTION TESTS
# ═══════════════════════════════════════════════════════════════════

log "Test 20: Idle detection via /stopped and /active"
# Set idle timeout to 2 seconds for fast test
api "$BASE" POST /api/settings -d '{"idle_timeout_secs":2}' >/dev/null
# Register fresh session
api "$BASE" POST /api/register -d "{\"id\":\"idle-test\",\"pane\":\"$PANE_A\"}" >/dev/null 2>&1 || true
PANE_A_NUM="${PANE_A#%}"
# Signal stopped — should start idle timer
stopped_status=$(curl -sf -o /dev/null -w '%{http_code}' -X POST "${BASE}/api/pane/${PANE_A_NUM}/stopped" 2>/dev/null)
assert_eq "stopped returns 200" "$stopped_status" "200"
# Signal active — should cancel idle timer
active_status=$(curl -sf -o /dev/null -w '%{http_code}' -X POST "${BASE}/api/pane/${PANE_A_NUM}/active" 2>/dev/null)
assert_eq "active returns 200" "$active_status" "200"
pass "idle detection endpoints respond"
# Clean up
api "$BASE" POST /api/remove -d '{"id":"idle-test"}' >/dev/null 2>&1 || true
# Restore idle timeout
api "$BASE" POST /api/settings -d '{"idle_timeout_secs":60}' >/dev/null

log "Test 20a: Idle reminder re-injects unanswered pending replies"
# Set idle timeout to 2 seconds for fast test
api "$BASE" POST /api/settings -d '{"idle_timeout_secs":2}' >/dev/null
# Register fresh session on PANE_A
api "$BASE" POST /api/remove -d '{"id":"reminder-test"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/register -d "{\"id\":\"reminder-test\",\"pane\":\"$PANE_A\"}" >/dev/null
PANE_A_NUM="${PANE_A#%}"
# Send a ? message to create a pending reply
api "$BASE" POST /api/send -d "{\"from\":\"asker\",\"to\":\"reminder-test\",\"message\":\"do you have the answer?\",\"expects_reply\":true}" >/dev/null
sleep 0.5
# Verify pending reply exists
result=$(api "$BASE" GET "/api/pane/${PANE_A_NUM}/pending-replies")
assert_contains "pending reply tracked" "$result" '"count":1'
# Clear the pane so we can detect the reminder injection
tmux send-keys -t "$PANE_A" "clear" Enter
sleep 0.5
# Signal stopped — starts idle timer (2s)
curl -sf -X POST "${BASE}/api/pane/${PANE_A_NUM}/stopped" >/dev/null 2>&1
# Wait for idle timeout + reminder injection
wait_for 8 bash -c "tmux capture-pane -t '$PANE_A' -p -S -20 | grep -qF 'Pending reply owed'"
pane_content=$(tmux capture-pane -t "$PANE_A" -p -S -20)
assert_contains "reminder injected on idle" "$pane_content" "Pending reply owed"
assert_contains "reminder includes sender" "$pane_content" "from asker"
# Clean up
api "$BASE" POST /api/remove -d '{"id":"reminder-test"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/settings -d '{"idle_timeout_secs":60}' >/dev/null

log "Test 20b: idle_timeout_secs persisted in settings"
api "$BASE" POST /api/settings -d '{"idle_timeout_secs":120}' >/dev/null
settings_json=$(cat /tmp/ouija-test/settings.json 2>/dev/null)
assert_contains "idle timeout saved to disk" "$settings_json" '"idle_timeout_secs": 120'
# Restore
api "$BASE" POST /api/settings -d '{"idle_timeout_secs":60}' >/dev/null

# ═══════════════════════════════════════════════════════════════════
# AUTO-CLOSE IDLE SESSIONS
# ═══════════════════════════════════════════════════════════════════

log "Test 21: Max local sessions — auto-close most idle when over limit"
# Set max to 2, then register 3 sessions. The most idle one should be closed.
# Backdate one session so it's clearly the most idle.
PANE_C=$(create_claude_pane "$FAKE_BIN")
sleep 0.5
api "$BASE" POST /api/register -d "{\"id\":\"keep-a\",\"pane\":\"$PANE_A\"}" >/dev/null
api "$BASE" POST /api/register -d "{\"id\":\"keep-b\",\"pane\":\"$PANE_B\"}" >/dev/null
api "$BASE" POST /api/register -d "{\"id\":\"evict-me\",\"pane\":\"$PANE_C\"}" >/dev/null
assert_eq "21: 3 sessions before limit" "$(session_count "$BASE")" "3"
# Backdate evict-me so it's the most idle, then restart to load it
jq 'map(if .id == "evict-me" then .last_activity_at = "2000-01-01T00:00:00Z" else . end)' \
    /tmp/ouija-test/sessions.json > /tmp/ouija-test/sessions.json.tmp \
    && mv /tmp/ouija-test/sessions.json.tmp /tmp/ouija-test/sessions.json
kill $DAEMON_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
sleep 0.5
RUST_LOG=ouija=debug ouija start --port $PORT --data /tmp/ouija-test >/tmp/ouija-test/daemon.log 2>&1 &
DAEMON_PID=$!
wait_for 10 curl -sf "$BASE/api/status" -o /dev/null
# Wait for session restoration
wait_for 10 bash -c '[ "$(session_count "'"$BASE"'")" -ge 3 ]'
# Now set max_local_sessions=2 — the reaper should evict the most idle
api "$BASE" POST /api/settings -d '{"max_local_sessions":2}' >/dev/null
# Wait for reaper to close the excess session
wait_for 15 bash -c '[ "$(session_count "'"$BASE"'")" -le 2 ]'
ids_after=$(session_ids "$BASE")
assert_not_contains "21: most idle session evicted" "$ids_after" "evict-me"
assert_contains "21: active session a survived" "$ids_after" "keep-a"
assert_contains "21: active session b survived" "$ids_after" "keep-b"
# Verify it was logged
daemon_log=$(cat /tmp/ouija-test/daemon.log 2>/dev/null)
assert_contains "21: auto-close logged" "$daemon_log" "auto-closing idle session"
# Disable
api "$BASE" POST /api/settings -d '{"max_local_sessions":0}' >/dev/null
# Clean up
api "$BASE" POST /api/remove -d '{"id":"keep-a"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/remove -d '{"id":"keep-b"}' >/dev/null 2>&1 || true

# ═══════════════════════════════════════════════════════════════════
# ALIAS RESOLUTION AFTER RENAME
# ═══════════════════════════════════════════════════════════════════

# Restart daemon with clean state and auto_register=false
kill $DAEMON_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
rm -rf /tmp/ouija-test2
mkdir -p /tmp/ouija-test2
echo '{"auto_register":false,"reaper_interval_secs":1}' > /tmp/ouija-test2/settings.json
DAEMON_PID=$(start_daemon $PORT "local" /tmp/ouija-test2)
log "Restarted daemon for alias/pending-reply tests (PID $DAEMON_PID)"

log "Test 22: Send to renamed session returns alias hint"
api "$BASE" POST /api/register -d "{\"id\":\"alias-orig\",\"pane\":\"$PANE_A\"}" >/dev/null
api "$BASE" POST /api/register -d "{\"id\":\"alias-sender\",\"pane\":\"$PANE_B\"}" >/dev/null
api "$BASE" POST /api/rename -d '{"old_id":"alias-orig","new_id":"alias-new"}' >/dev/null
# Send to old name — should get error with hint
result=$(curl -s -X POST "${BASE}/api/send" -H 'Content-Type: application/json' \
    -d '{"from":"alias-sender","to":"alias-orig","message":"hi"}')
assert_contains "22: error mentions rename" "$result" "was renamed to"
assert_contains "22: error has renamed_to field" "$result" '"renamed_to":"alias-new"'
# Clean up
api "$BASE" POST /api/remove -d '{"id":"alias-new"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/remove -d '{"id":"alias-sender"}' >/dev/null 2>&1 || true

log "Test 22b: Alias chain flattened after multiple renames"
api "$BASE" POST /api/register -d "{\"id\":\"chain-a\",\"pane\":\"$PANE_A\"}" >/dev/null
api "$BASE" POST /api/register -d "{\"id\":\"chain-sender\",\"pane\":\"$PANE_B\"}" >/dev/null
api "$BASE" POST /api/rename -d '{"old_id":"chain-a","new_id":"chain-b"}' >/dev/null
api "$BASE" POST /api/rename -d '{"old_id":"chain-b","new_id":"chain-c"}' >/dev/null
# Send to the original name — should resolve all the way to chain-c
result=$(curl -s -X POST "${BASE}/api/send" -H 'Content-Type: application/json' \
    -d '{"from":"chain-sender","to":"chain-a","message":"hi"}')
assert_contains "22b: chain resolves to final name" "$result" '"renamed_to":"chain-c"'
# Clean up
api "$BASE" POST /api/remove -d '{"id":"chain-c"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/remove -d '{"id":"chain-sender"}' >/dev/null 2>&1 || true

log "Test 22c: Alias returns nothing when renamed target is removed"
api "$BASE" POST /api/register -d "{\"id\":\"gone-orig\",\"pane\":\"$PANE_A\"}" >/dev/null
api "$BASE" POST /api/register -d "{\"id\":\"gone-sender\",\"pane\":\"$PANE_B\"}" >/dev/null
api "$BASE" POST /api/rename -d '{"old_id":"gone-orig","new_id":"gone-new"}' >/dev/null
api "$BASE" POST /api/remove -d '{"id":"gone-new"}' >/dev/null
# Send to old name — target gone, alias should not resolve
result=$(curl -s -X POST "${BASE}/api/send" -H 'Content-Type: application/json' \
    -d '{"from":"gone-sender","to":"gone-orig","message":"hi"}')
assert_contains "22c: error for gone target" "$result" '"error"'
assert_not_contains "22c: no rename hint for removed target" "$result" "renamed_to"
# Clean up
api "$BASE" POST /api/remove -d '{"id":"gone-sender"}' >/dev/null 2>&1 || true

# ═══════════════════════════════════════════════════════════════════
# PENDING REPLY CLEANUP ON SESSION REMOVAL
# ═══════════════════════════════════════════════════════════════════

log "Test 23: Pending reply cleared when sender session is removed"
api "$BASE" POST /api/register -d "{\"id\":\"pr-target\",\"pane\":\"$PANE_A\"}" >/dev/null
api "$BASE" POST /api/register -d "{\"id\":\"pr-sender\",\"pane\":\"$PANE_B\"}" >/dev/null
sleep 0.5
# Send expects_reply=true to create a pending reply on pr-target
send_result=$(api "$BASE" POST /api/send -d '{"from":"pr-sender","to":"pr-target","message":"pending q","expects_reply":true}')
assert_contains "23: send delivered" "$send_result" '"status":"delivered"'
sleep 1
PANE_A_NUM="${PANE_A#%}"
result=$(api "$BASE" GET "/api/pane/${PANE_A_NUM}/pending-replies")
assert_contains "23: pending reply exists before removal" "$result" '"count":1'
# Remove the sender session — should auto-clear the pending reply
api "$BASE" POST /api/remove -d '{"id":"pr-sender"}' >/dev/null
sleep 1
result=$(api "$BASE" GET "/api/pane/${PANE_A_NUM}/pending-replies")
assert_contains "23: pending reply cleared after sender removal" "$result" '"count":0'
# Clean up
api "$BASE" POST /api/remove -d '{"id":"pr-target"}' >/dev/null 2>&1 || true

log "Test 23b: Pending reply cleared when sender session reaped"
PANE_EPHEMERAL=$(create_claude_pane "$FAKE_BIN")
sleep 0.5
api "$BASE" POST /api/register -d "{\"id\":\"pr-asker\",\"pane\":\"$PANE_A\"}" >/dev/null
api "$BASE" POST /api/register -d "{\"id\":\"pr-ghost\",\"pane\":\"$PANE_EPHEMERAL\"}" >/dev/null
sleep 0.5
# Create pending reply on pr-asker from pr-ghost
send_result=$(api "$BASE" POST /api/send -d '{"from":"pr-ghost","to":"pr-asker","message":"ghost q","expects_reply":true}')
assert_contains "23b: send delivered" "$send_result" '"status":"delivered"'
sleep 1
PANE_A_NUM="${PANE_A#%}"
result=$(api "$BASE" GET "/api/pane/${PANE_A_NUM}/pending-replies")
assert_contains "23b: pending reply from ghost exists" "$result" '"count":1'
# Kill the ghost's tmux pane so the reaper removes it
tmux kill-pane -t "$PANE_EPHEMERAL" 2>/dev/null || true
# Wait for reaper to remove pr-ghost and clear the pending reply
wait_for 15 bash -c "! session_ids '$BASE' | grep -qF 'pr-ghost'" || true
sleep 1
ids_after=$(session_ids "$BASE")
assert_not_contains "23b: ghost session reaped" "$ids_after" "pr-ghost"
result=$(api "$BASE" GET "/api/pane/${PANE_A_NUM}/pending-replies")
assert_contains "23b: pending reply cleared after reap" "$result" '"count":0'
# Clean up
api "$BASE" POST /api/remove -d '{"id":"pr-asker"}' >/dev/null 2>&1 || true

# ═══════════════════════════════════════════════════════════════════
# FIFO INJECTION QUEUE ORDERING
# ═══════════════════════════════════════════════════════════════════

log "Test 24: Multiple sequential messages arrive in FIFO order"
api "$BASE" POST /api/register -d "{\"id\":\"fifo-target\",\"pane\":\"$PANE_A\"}" >/dev/null
api "$BASE" POST /api/register -d "{\"id\":\"fifo-sender\",\"pane\":\"$PANE_B\"}" >/dev/null
# Clear the pane
tmux send-keys -t "$PANE_A" "clear" Enter
sleep 0.5
# Send 5 messages sequentially — FIFO queue should preserve this order
for i in 1 2 3 4 5; do
    api "$BASE" POST /api/send -d "{\"from\":\"fifo-sender\",\"to\":\"fifo-target\",\"message\":\"fifo-msg-$i\",\"expects_reply\":false}" >/dev/null
done
# Wait for all messages to arrive
wait_for 10 bash -c "tmux capture-pane -t '$PANE_A' -p -S -30 | grep -qF 'fifo-msg-5'"
pane_content=$(tmux capture-pane -t "$PANE_A" -p -S -30)
# Verify all 5 messages arrived
for i in 1 2 3 4 5; do
    assert_contains "24: fifo-msg-$i delivered" "$pane_content" "fifo-msg-$i"
done
# Check ordering — each message's line number should be after the previous
PREV_LINE=0
ORDER_OK=1
for i in 1 2 3 4 5; do
    LINE=$(echo "$pane_content" | grep -n "fifo-msg-$i" | head -1 | cut -d: -f1)
    if [ -n "$LINE" ] && [ "$LINE" -gt "$PREV_LINE" ]; then
        PREV_LINE=$LINE
    else
        ORDER_OK=0
        break
    fi
done
if [ "$ORDER_OK" -eq 1 ]; then
    pass "24: messages in FIFO order"
else
    fail "24: messages in FIFO order" "sequential line numbers" "$pane_content"
fi
# Clean up
api "$BASE" POST /api/remove -d '{"id":"fifo-target"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/remove -d '{"id":"fifo-sender"}' >/dev/null 2>&1 || true

# ═══════════════════════════════════════════════════════════════════
# REGISTER HOOK RACE — DAEMON PRE-REGISTERS, HOOK SKIPS
# ═══════════════════════════════════════════════════════════════════

log "Test 26: XML message format in pane injection"
api "$BASE" POST /api/register -d "{\"id\":\"xml-target\",\"pane\":\"$PANE_A\"}" >/dev/null 2>&1 || true
api "$BASE" POST /api/register -d "{\"id\":\"xml-sender\",\"pane\":\"$PANE_B\"}" >/dev/null 2>&1 || true
tmux send-keys -t "$PANE_A" "clear" Enter
sleep 0.5
result=$(api "$BASE" POST /api/send -d '{"from":"xml-sender","to":"xml-target","message":"hello xml","expects_reply":true}')
assert_contains "26: send delivered" "$result" '"status":"delivered"'
assert_contains "26: response has msg_id" "$result" '"msg_id"'
wait_for 5 bash -c "tmux capture-pane -t '$PANE_A' -p -S -10 | grep -qF 'from=\"xml-sender\"'"
pane_content=$(tmux capture-pane -t "$PANE_A" -p -S -10)
assert_contains "26: XML format in pane" "$pane_content" '<msg from="xml-sender"'
assert_contains "26: has reply attr" "$pane_content" 'reply="true"'
assert_contains "26: has id attr" "$pane_content" 'id="'
assert_contains "26: has message content" "$pane_content" "hello xml"
assert_contains "26: has closing tag" "$pane_content" "</msg>"
api "$BASE" POST /api/remove -d '{"id":"xml-target"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/remove -d '{"id":"xml-sender"}' >/dev/null 2>&1 || true

log "Test 27: responds_to clears pending reply"
api "$BASE" POST /api/register -d "{\"id\":\"rt-target\",\"pane\":\"$PANE_A\"}" >/dev/null 2>&1 || true
api "$BASE" POST /api/register -d "{\"id\":\"rt-sender\",\"pane\":\"$PANE_B\"}" >/dev/null 2>&1 || true
sleep 0.5
# Send with expects_reply=true, get msg_id from response
result=$(api "$BASE" POST /api/send -d '{"from":"rt-sender","to":"rt-target","message":"do this","expects_reply":true}')
msg_id=$(echo "$result" | python3 -c "import sys,json; print(json.load(sys.stdin)['msg_id'])" 2>/dev/null || echo "")
[ -n "$msg_id" ] && pass "27: got msg_id" || fail "27: got msg_id (empty)"
PANE_A_NUM="${PANE_A#%}"
sleep 0.5
# Verify pending reply exists
pending=$(api "$BASE" GET "/api/pane/${PANE_A_NUM}/pending-replies")
assert_contains "27: pending exists before ack" "$pending" '"count":1'
# Ack without responds_to — pending should still exist
api "$BASE" POST /api/send -d '{"from":"rt-target","to":"rt-sender","message":"ack"}' >/dev/null
sleep 0.5
pending=$(api "$BASE" GET "/api/pane/${PANE_A_NUM}/pending-replies")
assert_contains "27: pending still exists after plain ack" "$pending" '"count":1'
# Reply with responds_to + done=true — pending should clear
api "$BASE" POST /api/send -d "{\"from\":\"rt-target\",\"to\":\"rt-sender\",\"message\":\"done\",\"responds_to\":$msg_id,\"done\":true}" >/dev/null
sleep 0.5
pending=$(api "$BASE" GET "/api/pane/${PANE_A_NUM}/pending-replies")
assert_contains "27: pending cleared after responds_to" "$pending" '"count":0'
api "$BASE" POST /api/remove -d '{"id":"rt-target"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/remove -d '{"id":"rt-sender"}' >/dev/null 2>&1 || true

log "Test 28: responds_to adds re attr in XML"
api "$BASE" POST /api/register -d "{\"id\":\"re-target\",\"pane\":\"$PANE_A\"}" >/dev/null 2>&1 || true
api "$BASE" POST /api/register -d "{\"id\":\"re-sender\",\"pane\":\"$PANE_B\"}" >/dev/null 2>&1 || true
sleep 0.5
# Send and get msg_id
result=$(api "$BASE" POST /api/send -d '{"from":"re-sender","to":"re-target","message":"question","expects_reply":true}')
msg_id=$(echo "$result" | python3 -c "import sys,json; print(json.load(sys.stdin)['msg_id'])" 2>/dev/null || echo "")
[ -n "$msg_id" ] && pass "28: got msg_id" || fail "28: got msg_id (empty)"
tmux send-keys -t "$PANE_B" "clear" Enter
sleep 0.5
# Reply with responds_to — should include re= attr in the injected XML
api "$BASE" POST /api/send -d "{\"from\":\"re-target\",\"to\":\"re-sender\",\"message\":\"answer\",\"responds_to\":$msg_id}" >/dev/null
wait_for 5 bash -c "tmux capture-pane -t '$PANE_B' -p -S -10 | grep -qF 're=\"$msg_id\"'"
pane_content=$(tmux capture-pane -t "$PANE_B" -p -S -10)
assert_contains "28: re attr in XML" "$pane_content" "re=\"$msg_id\""
assert_contains "28: from attr" "$pane_content" 'from="re-target"'
assert_contains "28: message content" "$pane_content" "answer"
api "$BASE" POST /api/remove -d '{"id":"re-target"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/remove -d '{"id":"re-sender"}' >/dev/null 2>&1 || true

log "Test 29: Three-tier replies — progress does not clear, done does"
api "$BASE" POST /api/register -d "{\"id\":\"tt-target\",\"pane\":\"$PANE_A\"}" >/dev/null 2>&1 || true
api "$BASE" POST /api/register -d "{\"id\":\"tt-sender\",\"pane\":\"$PANE_B\"}" >/dev/null 2>&1 || true
sleep 0.5
# Send with expects_reply=true
result=$(api "$BASE" POST /api/send -d '{"from":"tt-sender","to":"tt-target","message":"do task","expects_reply":true}')
msg_id=$(echo "$result" | python3 -c "import sys,json; print(json.load(sys.stdin)['msg_id'])" 2>/dev/null || echo "")
[ -n "$msg_id" ] && pass "29: got msg_id" || fail "29: got msg_id (empty)"
PANE_A_NUM="${PANE_A#%}"
sleep 0.5
pending=$(api "$BASE" GET "/api/pane/${PANE_A_NUM}/pending-replies")
assert_contains "29: pending exists" "$pending" '"count":1'

# Ack without responds_to — should NOT clear
api "$BASE" POST /api/send -d '{"from":"tt-target","to":"tt-sender","message":"ack"}' >/dev/null
sleep 0.5
pending=$(api "$BASE" GET "/api/pane/${PANE_A_NUM}/pending-replies")
assert_contains "29: ack without re does not clear" "$pending" '"count":1'

# Progress with responds_to but no done — should NOT clear
api "$BASE" POST /api/send -d "{\"from\":\"tt-target\",\"to\":\"tt-sender\",\"message\":\"working\",\"responds_to\":$msg_id}" >/dev/null
sleep 0.5
pending=$(api "$BASE" GET "/api/pane/${PANE_A_NUM}/pending-replies")
assert_contains "29: progress does not clear" "$pending" '"count":1'

# Done with responds_to + done=true — SHOULD clear
api "$BASE" POST /api/send -d "{\"from\":\"tt-target\",\"to\":\"tt-sender\",\"message\":\"all done\",\"responds_to\":$msg_id,\"done\":true}" >/dev/null
sleep 0.5
pending=$(api "$BASE" GET "/api/pane/${PANE_A_NUM}/pending-replies")
assert_contains "29: done clears pending" "$pending" '"count":0'
api "$BASE" POST /api/remove -d '{"id":"tt-target"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/remove -d '{"id":"tt-sender"}' >/dev/null 2>&1 || true

log "Test 30: done=true adds done attribute to XML"
api "$BASE" POST /api/register -d "{\"id\":\"done-target\",\"pane\":\"$PANE_A\"}" >/dev/null 2>&1 || true
api "$BASE" POST /api/register -d "{\"id\":\"done-sender\",\"pane\":\"$PANE_B\"}" >/dev/null 2>&1 || true
sleep 0.5
tmux send-keys -t "$PANE_A" "clear" Enter
sleep 0.3
api "$BASE" POST /api/send -d '{"from":"done-sender","to":"done-target","message":"result","responds_to":999,"done":true}' >/dev/null
wait_for 5 bash -c "tmux capture-pane -t '$PANE_A' -p -S -10 | grep -qF 'done=\"true\"'"
pane_content=$(tmux capture-pane -t "$PANE_A" -p -S -10)
assert_contains "30: done attr in XML" "$pane_content" 'done="true"'
api "$BASE" POST /api/remove -d '{"id":"done-target"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/remove -d '{"id":"done-sender"}' >/dev/null 2>&1 || true

log "Test 25: Hook skips registration when pane already registered by daemon"
REGISTER_SCRIPT=$(find_script "ouija-register.sh")
api "$BASE" POST /api/settings -d '{"auto_register":true}' >/dev/null
# Pre-register a session on PANE_A (simulates daemon auto-registration)
api "$BASE" POST /api/register -d "{\"id\":\"pre-registered\",\"pane\":\"$PANE_A\"}" >/dev/null
# Run the hook — it should detect the pane is already registered and skip
HOOK_OUT=$(echo '{"source":"startup"}' | TMUX_PANE="$PANE_A" OUIJA_PORT=$PORT bash -c "cd /tmp/my-project && bash '$REGISTER_SCRIPT'" 2>&1)
# Verify hook did NOT register (output should be empty or say already registered)
ids=$(session_ids "$BASE")
assert_not_contains "25: hook did not create duplicate session" "$ids" "my-project"
assert_contains "25: pre-registered session still exists" "$ids" "pre-registered"
# Clean up
api "$BASE" POST /api/remove -d '{"id":"pre-registered"}' >/dev/null 2>&1 || true

# ═══════════════════════════════════════════════════════════════════
# LOOP / REMINDER TESTS
# ═══════════════════════════════════════════════════════════════════

log "Test 26: Register with reminder field"
api "$BASE" POST /api/register -d "{\"id\":\"loop-sess\",\"pane\":\"$PANE_A\",\"reminder\":\"call loop_next when done\"}" >/dev/null
reminder=$(api "$BASE" GET /api/status | jq -r '.sessions[] | select(.id == "loop-sess") | .reminder // ""')
assert_eq "26: reminder stored" "$reminder" "call loop_next when done"
api "$BASE" POST /api/remove -d '{"id":"loop-sess"}' >/dev/null 2>&1 || true
# Restore sess-a2
api "$BASE" POST /api/register -d "{\"id\":\"sess-a2\",\"pane\":\"$PANE_A\"}" >/dev/null

log "Test 27: session_start via HTTP with reminder and prompt"
# Start a session with prompt + reminder
result=$(api "$BASE" POST /api/sessions/start -d "{\"name\":\"loop-test\",\"project_dir\":\"/tmp/loop-test-proj\",\"prompt\":\"do the work\",\"reminder\":\"if done call loop_next\"}")
assert_contains "27: session started" "$result" "started"
# Verify prompt and reminder are in metadata
sleep 1
status=$(api "$BASE" GET /api/status)
orig_prompt=$(echo "$status" | jq -r '.sessions[] | select(.id == "loop-test") | .prompt // ""')
sess_reminder=$(echo "$status" | jq -r '.sessions[] | select(.id == "loop-test") | .reminder // ""')
assert_eq "27: prompt stored" "$orig_prompt" "do the work"
assert_eq "27: reminder stored" "$sess_reminder" "if done call loop_next"
# Verify prompt + reminder was concatenated in pane
loop_pane=$(echo "$status" | jq -r '.sessions[] | select(.id == "loop-test") | .pane // ""')
if [ -n "$loop_pane" ]; then
    wait_for 5 bash -c "tmux capture-pane -t '$loop_pane' -p 2>/dev/null | grep -qF 'if done call loop_next'"
    pane_text=$(tmux capture-pane -t "$loop_pane" -p 2>/dev/null || true)
    assert_contains "27: reminder in pane" "$pane_text" "if done call loop_next"
fi

log "Test 28: loop_next via MCP increments iteration"
# First verify iteration is 0
iter_before=$(echo "$status" | jq -r '.sessions[] | select(.id == "loop-test") | .iteration // 0')
assert_eq "28: iteration starts at 0" "$iter_before" "0"
# Call loop_next
mcp_result=$(mcp_call_tool "$BASE" "loop_next" '{"from":"loop-test","message":"finished first batch","clean_context":true}')
assert_contains "28: loop_next response" "$mcp_result" "loop_next"
# Wait for restart to complete
sleep 3
status2=$(api "$BASE" GET /api/status)
iter_after=$(echo "$status2" | jq -r '.sessions[] | select(.id == "loop-test") | .iteration // 0')
assert_eq "28: iteration incremented to 1" "$iter_after" "1"
# Verify loop log has the message
log_msg=$(echo "$status2" | jq -r '.sessions[] | select(.id == "loop-test") | .iteration_log[0].message // ""')
assert_eq "28: loop log message" "$log_msg" "finished first batch"

log "Test 29: loop_next preserves prompt across restart"
orig_after=$(echo "$status2" | jq -r '.sessions[] | select(.id == "loop-test") | .prompt // ""')
reminder_after=$(echo "$status2" | jq -r '.sessions[] | select(.id == "loop-test") | .reminder // ""')
assert_eq "29: prompt preserved" "$orig_after" "do the work"
assert_eq "29: reminder preserved" "$reminder_after" "if done call loop_next"

log "Test 30: loop_next without prompt returns error"
# Register a bare session (no prompt)
api "$BASE" POST /api/register -d "{\"id\":\"bare-sess\",\"pane\":\"$PANE_B\"}" >/dev/null
mcp_result=$(mcp_call_tool "$BASE" "loop_next" '{"from":"bare-sess"}')
assert_contains "30: error without prompt" "$mcp_result" "no prompt"
# Clean up
api "$BASE" POST /api/remove -d '{"id":"bare-sess"}' >/dev/null 2>&1 || true

# Clean up loop-test session
api "$BASE" POST /api/sessions/kill -d '{"name":"loop-test"}' >/dev/null 2>&1 || true
sleep 1
api "$BASE" POST /api/remove -d '{"id":"loop-test"}' >/dev/null 2>&1 || true
# Restore
api "$BASE" POST /api/register -d "{\"id\":\"sess-a2\",\"pane\":\"$PANE_A\"}" >/dev/null
api "$BASE" POST /api/register -d "{\"id\":\"sess-b\",\"pane\":\"$PANE_B\"}" >/dev/null

log "Test 30b: loop_next with clean_context=false returns iteration without restart"
# Start a session with a prompt for looping
api "$BASE" POST /api/sessions/start -d "{\"name\":\"loop-norest\",\"project_dir\":\"/tmp/loop-norest-proj\",\"prompt\":\"iterate work\",\"reminder\":\"keep looping\"}" >/dev/null
sleep 2
norest_pane=$(api "$BASE" GET /api/status | jq -r '.sessions[] | select(.id == "loop-norest") | .pane // ""')
# Call loop_next with clean_context=false (default)
mcp_result=$(mcp_call_tool "$BASE" "loop_next" '{"from":"loop-norest","message":"first pass"}')
assert_contains "30b: response has iteration" "$mcp_result" '<loop iteration="1" />'
# Verify iteration incremented
status=$(api "$BASE" GET /api/status)
iter=$(echo "$status" | jq -r '.sessions[] | select(.id == "loop-norest") | .iteration // 0')
assert_eq "30b: iteration is 1" "$iter" "1"
# Verify last_iteration_at is set
last_ln=$(echo "$status" | jq -r '.sessions[] | select(.id == "loop-norest") | .last_iteration_at // "null"')
if [ "$last_ln" = "null" ]; then fail "30b: last_iteration_at should be set"; else pass "30b: last_iteration_at set"; fi

log "Test 30c: loop_next clean_context=false increments without session restart"
# Call again — session should still be alive (no restart)
mcp_result2=$(mcp_call_tool "$BASE" "loop_next" '{"from":"loop-norest","message":"second pass"}')
assert_contains "30c: response has iteration 2" "$mcp_result2" '<loop iteration="2" />'
status2=$(api "$BASE" GET /api/status)
iter2=$(echo "$status2" | jq -r '.sessions[] | select(.id == "loop-norest") | .iteration // 0')
assert_eq "30c: iteration is 2" "$iter2" "2"
# Verify the pane is still the same (not restarted)
pane_after=$(echo "$status2" | jq -r '.sessions[] | select(.id == "loop-norest") | .pane // ""')
assert_eq "30c: pane unchanged" "$pane_after" "$norest_pane"

log "Test 30d: loop_next clean_context=false includes reminder every 10th iteration"
# Currently at iteration 2. Fast-forward via HTTP API to avoid MCP session expiry.
# Use the HTTP send endpoint to trigger loop_next calls reliably.
for i in $(seq 3 9); do
    api "$BASE" POST /api/loop-next -d "{\"from\":\"loop-norest\",\"message\":\"pass $i\"}" >/dev/null 2>&1 || \
    mcp_call_tool "$BASE" "loop_next" "{\"from\":\"loop-norest\",\"message\":\"pass $i\"}" >/dev/null
done
# Verify we're at iteration 9
iter9=$(api "$BASE" GET /api/status | jq -r '.sessions[] | select(.id == "loop-norest") | .iteration // 0')
# If MCP calls dropped some iterations, catch up
while [ "$iter9" -lt 9 ] 2>/dev/null; do
    mcp_call_tool "$BASE" "loop_next" '{"from":"loop-norest","message":"catchup"}' >/dev/null
    iter9=$(api "$BASE" GET /api/status | jq -r '.sessions[] | select(.id == "loop-norest") | .iteration // 0')
done
# The 10th call should include the reminder text
mcp_result10=$(mcp_call_tool "$BASE" "loop_next" '{"from":"loop-norest","message":"pass 10"}')
assert_contains "30d: 10th iteration includes reminder" "$mcp_result10" "keep looping"
# Clean up
api "$BASE" POST /api/sessions/kill -d '{"name":"loop-norest"}' >/dev/null 2>&1 || true
sleep 1
api "$BASE" POST /api/remove -d '{"id":"loop-norest"}' >/dev/null 2>&1 || true
api "$BASE" POST /api/register -d "{\"id\":\"sess-a2\",\"pane\":\"$PANE_A\"}" >/dev/null
api "$BASE" POST /api/register -d "{\"id\":\"sess-b\",\"pane\":\"$PANE_B\"}" >/dev/null

log "Test 31: Re-registration preserves loop state"
# Register a session directly with loop metadata (no session_start, avoids worktree complexity)
api "$BASE" POST /api/register -d "{\"id\":\"reregtest\",\"pane\":\"$PANE_A\",\"reminder\":\"call loop_next when done\"}" >/dev/null
# Manually set prompt via a second register with all fields
# (simulates what session_start does internally)
api "$BASE" POST /api/register -d "{\"id\":\"reregtest\",\"pane\":\"$PANE_A\",\"reminder\":\"call loop_next when done\",\"role\":\"looping\"}" >/dev/null
# Verify fields are set
status=$(api "$BASE" GET /api/status)
rem=$(echo "$status" | jq -r '.sessions[] | select(.id == "reregtest") | .reminder // ""')
role1=$(echo "$status" | jq -r '.sessions[] | select(.id == "reregtest") | .role // ""')
assert_eq "31a: reminder set" "$rem" "call loop_next when done"
assert_eq "31a: role set" "$role1" "looping"
# Simulate startup hook: re-register same ID+pane with new role but NO reminder (..Default)
api "$BASE" POST /api/register -d "{\"id\":\"reregtest\",\"pane\":\"$PANE_A\",\"role\":\"re-registered\"}" >/dev/null
status2=$(api "$BASE" GET /api/status)
rem2=$(echo "$status2" | jq -r '.sessions[] | select(.id == "reregtest") | .reminder // ""')
role2=$(echo "$status2" | jq -r '.sessions[] | select(.id == "reregtest") | .role // ""')
assert_eq "31b: reminder preserved after re-register" "$rem2" "call loop_next when done"
assert_eq "31b: role updated" "$role2" "re-registered"
# Same test via MCP session_register (the actual hook path)
mcp_call_tool "$BASE" "session_register" "{\"id\":\"reregtest\",\"pane\":\"$PANE_A\",\"role\":\"hook-registered\"}" >/dev/null
status3=$(api "$BASE" GET /api/status)
rem3=$(echo "$status3" | jq -r '.sessions[] | select(.id == "reregtest") | .reminder // ""')
role3=$(echo "$status3" | jq -r '.sessions[] | select(.id == "reregtest") | .role // ""')
assert_eq "31c: reminder preserved after MCP re-register" "$rem3" "call loop_next when done"
assert_eq "31c: role updated via MCP" "$role3" "hook-registered"
# Clean up — restore sess-a2 on PANE_A
api "$BASE" POST /api/register -d "{\"id\":\"sess-a2\",\"pane\":\"$PANE_A\"}" >/dev/null
api "$BASE" POST /api/register -d "{\"id\":\"sess-b\",\"pane\":\"$PANE_B\"}" >/dev/null

# ═══════════════════════════════════════════════════════════════════
# WORKFLOW ACTOR TESTS — Full User Journey
# One workflow script, two sessions, tests: happy path, shared state,
# lifecycle events, crash recovery, effort budget, verify field.
# ═══════════════════════════════════════════════════════════════════

WF_STATE="/tmp/ouija-test/wf-journey-state.json"
rm -f "$WF_STATE"

JOURNEY_SCRIPT="/tmp/ouija-test/journey-workflow.py"
cat > "$JOURNEY_SCRIPT" << 'PYEOF'
#!/usr/bin/env python3
"""Comprehensive test workflow exercising all workflow actor features."""
import json, sys, os

STATE_FILE = os.environ.get("WF_STATE", "/tmp/ouija-test/wf-journey-state.json")

def load_state():
    try: return json.load(open(STATE_FILE))
    except: return {"tasks": ["alpha", "beta", "gamma"], "done": {}, "sessions": {}, "call_count": 0, "crashed": False}

def save_state(s):
    json.dump(s, open(STATE_FILE, "w"), indent=2)

envelope = json.loads(sys.stdin.read())
event = envelope.get("event")
action = envelope.get("action")
sid = envelope.get("session_id", "?")
params = envelope.get("params") or {}

# ── Lifecycle events ──
if event == "register":
    state = load_state()
    state["sessions"][sid] = "registered"
    save_state(state)
    print(json.dumps({
        "instructions": f"Worker {sid}. Call workflow('init') for tasks.",
        "inject_on_start": "Call workflow('init').",
        "max_calls": params.get("max_calls", 10)
    }))
    sys.exit(0)

if event == "session_died":
    state = load_state()
    state["sessions"][sid] = "died"
    save_state(state)
    print(json.dumps({}))
    sys.exit(0)

if event == "session_restarted":
    state = load_state()
    state["sessions"][sid] = "restarted"
    save_state(state)
    print(json.dumps({}))
    sys.exit(0)

# ── Runtime actions ──
state = load_state()
state["call_count"] += 1
save_state(state)

if action == "init":
    remaining = [t for t in state["tasks"] if t not in state["done"]]
    if not remaining:
        print(json.dumps({"message": "All tasks complete."}))
    else:
        print(json.dumps({
            "message": f"Task: {remaining[0]}. Call workflow('done', {{task: '{remaining[0]}'}})",
            "verify": f"test '{remaining[0]}' = '{remaining[0]}'"
        }))

elif action == "done":
    task = params.get("task")
    if not task:
        print(json.dumps({"error": "missing 'task' param. Call workflow('done', {task: 'name'})"}))
    else:
        state["done"][task] = sid
        save_state(state)
        remaining = [t for t in state["tasks"] if t not in state["done"]]
        msg = f"Completed {task} by {sid}. {len(remaining)} remaining."
        if remaining:
            msg += f" Next: call workflow('init')."
        else:
            msg += " All done."
        print(json.dumps({"message": msg}))

elif action == "status":
    print(json.dumps({"message": json.dumps(state)}))

elif action == "crash_test":
    # Simulate a crash on demand
    print("this is not json and also", file=sys.stderr)
    sys.exit(1)

elif action == "error_test":
    print(json.dumps({"error": "intentional error for testing"}))

else:
    print(json.dumps({"error": f"unknown action: {action}"}))
PYEOF
chmod +x "$JOURNEY_SCRIPT"

log "Test 32: Workflow journey — register session A with workflow"
api "$BASE" POST /api/register \
    -d "{\"id\":\"wf-a\",\"pane\":\"$PANE_A\",\"workflow\":\"$JOURNEY_SCRIPT\",\"workflow_max_calls\":10}" >/dev/null
status=$(api "$BASE" GET /api/status)
wf=$(echo "$status" | jq -r '.sessions[] | select(.id == "wf-a") | .workflow // ""')
assert_eq "32: workflow path stored" "$wf" "$JOURNEY_SCRIPT"
wf_max=$(echo "$status" | jq -r '.sessions[] | select(.id == "wf-a") | .workflow_max_calls')
assert_eq "32: max_calls stored" "$wf_max" "10"

log "Test 33: Workflow journey — session A calls init, gets first task + verify"
result=$(mcp_call_tool "$BASE" "workflow" '{"from":"wf-a","action":"init"}')
result_text=$(echo "$result" | jq -r '.result.content[0].text // ""')
assert_contains "33: init returns task alpha" "$result_text" "alpha"
assert_contains "33: verify criteria included" "$result_text" "Verify before proceeding"

log "Test 34: Workflow journey — session A completes alpha"
result=$(mcp_call_tool "$BASE" "workflow" '{"from":"wf-a","action":"done","params":{"task":"alpha"}}')
result_text=$(echo "$result" | jq -r '.result.content[0].text // ""')
assert_contains "34: alpha completed" "$result_text" "Completed alpha"
assert_contains "34: 2 remaining" "$result_text" "2 remaining"

log "Test 35: Workflow journey — register session B on SAME workflow (shared state)"
api "$BASE" POST /api/register \
    -d "{\"id\":\"wf-b\",\"pane\":\"$PANE_B\",\"workflow\":\"$JOURNEY_SCRIPT\",\"workflow_max_calls\":4}" >/dev/null

log "Test 36: Workflow journey — session B calls init, gets beta (not alpha)"
result=$(mcp_call_tool "$BASE" "workflow" '{"from":"wf-b","action":"init"}')
result_text=$(echo "$result" | jq -r '.result.content[0].text // ""')
assert_contains "36: B gets beta (alpha already done by A)" "$result_text" "beta"

log "Test 37: Workflow journey — session B completes beta"
result=$(mcp_call_tool "$BASE" "workflow" '{"from":"wf-b","action":"done","params":{"task":"beta"}}')
result_text=$(echo "$result" | jq -r '.result.content[0].text // ""')
assert_contains "37: beta completed by wf-b" "$result_text" "Completed beta by wf-b"

log "Test 38: Workflow journey — session_died lifecycle event"
# Remove session A (simulates kill) — daemon fires NotifyWorkflow
api "$BASE" POST /api/remove -d '{"id":"wf-a"}' >/dev/null
sleep 0.5
# Verify the workflow recorded the death in its state file
wf_state=$(cat "$WF_STATE")
died_status=$(echo "$wf_state" | jq -r '.sessions["wf-a"]')
assert_eq "38: session_died recorded in workflow state" "$died_status" "died"

log "Test 39: Workflow journey — re-register A, state persists (gamma still pending)"
api "$BASE" POST /api/register \
    -d "{\"id\":\"wf-a\",\"pane\":\"$PANE_A\",\"workflow\":\"$JOURNEY_SCRIPT\",\"workflow_max_calls\":10}" >/dev/null
result=$(mcp_call_tool "$BASE" "workflow" '{"from":"wf-a","action":"init"}')
result_text=$(echo "$result" | jq -r '.result.content[0].text // ""')
assert_contains "39: A gets gamma after restart (state survived)" "$result_text" "gamma"

log "Test 40: Workflow journey — workflow crash returns actionable error"
result=$(mcp_call_tool "$BASE" "workflow" '{"from":"wf-a","action":"crash_test"}')
result_text=$(echo "$result" | jq -r '.result.content[0].text // ""')
assert_contains "40: crash error is actionable" "$result_text" "crashed"
assert_contains "40: recovery guidance included" "$result_text" "workflow(action='status')"

log "Test 41: Workflow journey — workflow error field propagation"
result=$(mcp_call_tool "$BASE" "workflow" '{"from":"wf-a","action":"error_test"}')
result_text=$(echo "$result" | jq -r '.result.content[0].text // ""')
assert_contains "41: error field propagated" "$result_text" "intentional error"

log "Test 42: Workflow journey — unknown action returns error"
result=$(mcp_call_tool "$BASE" "workflow" '{"from":"wf-a","action":"nonexistent"}')
result_text=$(echo "$result" | jq -r '.result.content[0].text // ""')
assert_contains "42: unknown action error" "$result_text" "unknown action"

log "Test 43: Workflow journey — effort budget exhaustion"
# wf-b has max_calls=4, already used 2 (init + done). Use 2 more then hit limit.
mcp_call_tool "$BASE" "workflow" '{"from":"wf-b","action":"status"}' >/dev/null
mcp_call_tool "$BASE" "workflow" '{"from":"wf-b","action":"status"}' >/dev/null
# 5th call should be refused
result=$(mcp_call_tool "$BASE" "workflow" '{"from":"wf-b","action":"status"}')
result_text=$(echo "$result" | jq -r '.result.content[0].text // ""')
assert_contains "43: budget exhausted after max_calls" "$result_text" "budget exhausted"

log "Test 44: Workflow journey — no workflow returns helpful error"
# wf-b is now budget-exhausted. Re-register its pane without workflow.
api "$BASE" POST /api/remove -d '{"id":"wf-b"}' >/dev/null
api "$BASE" POST /api/register -d "{\"id\":\"no-wf\",\"pane\":\"$PANE_B\"}" >/dev/null
result=$(mcp_call_tool "$BASE" "workflow" '{"from":"no-wf","action":"init"}')
result_text=$(echo "$result" | jq -r '.result.content[0].text // ""')
assert_contains "44: no workflow error" "$result_text" "no workflow configured"

log "Test 45: Workflow journey — complete gamma, verify shared state final"
result=$(mcp_call_tool "$BASE" "workflow" '{"from":"wf-a","action":"done","params":{"task":"gamma"}}')
result_text=$(echo "$result" | jq -r '.result.content[0].text // ""')
assert_contains "45: gamma completed" "$result_text" "Completed gamma"
assert_contains "45: all done" "$result_text" "All done"
# Verify final state file
wf_state=$(cat "$WF_STATE")
done_count=$(echo "$wf_state" | jq '.done | length')
assert_eq "45: all 3 tasks in done" "$done_count" "3"
alpha_by=$(echo "$wf_state" | jq -r '.done.alpha')
beta_by=$(echo "$wf_state" | jq -r '.done.beta')
gamma_by=$(echo "$wf_state" | jq -r '.done.gamma')
assert_eq "45: alpha done by wf-a" "$alpha_by" "wf-a"
assert_eq "45: beta done by wf-b" "$beta_by" "wf-b"
assert_eq "45: gamma done by wf-a" "$gamma_by" "wf-a"

# Clean up
api "$BASE" POST /api/remove -d '{"id":"wf-a"}' >/dev/null
api "$BASE" POST /api/remove -d '{"id":"wf-b"}' >/dev/null
api "$BASE" POST /api/register -d "{\"id\":\"sess-a2\",\"pane\":\"$PANE_A\"}" >/dev/null
api "$BASE" POST /api/register -d "{\"id\":\"sess-b\",\"pane\":\"$PANE_B\"}" >/dev/null

# ── Daemon logs ──────────────────────────────────────────────────────
log "Daemon logs:"
cat /tmp/ouija-test/daemon.log 2>/dev/null || true

# ── Results ──────────────────────────────────────────────────────────
print_results

# Cleanup
kill $DAEMON_PID 2>/dev/null || true
exit "$FAIL"
