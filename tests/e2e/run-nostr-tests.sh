#!/bin/bash
set -euo pipefail

# These tests must run inside Docker (via run-e2e.sh) for isolation.
# They need a local Nostr relay which the Docker compose provides.
if [ -z "${OUIJA_E2E:-}" ] && [ ! -f /.dockerenv ]; then
    echo "ERROR: e2e tests require Docker for tmux and relay isolation." >&2
    echo "Run:  bash tests/e2e/run-e2e.sh nostr" >&2
    echo "Or:   bash tests/e2e/run-e2e.sh         (all suites)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

PORT_A=7880
PORT_B=7881
RELAY_URL="ws://127.0.0.1:8080"
BASE_A="http://127.0.0.1:$PORT_A"
BASE_B="http://127.0.0.1:$PORT_B"

# ── Setup: tmux server ──────────────────────────────────────────────
log "Starting tmux server"
tmux new-session -d -s test -x 200 -y 50

FAKE_BIN=$(create_fake_claude)

PANE_A1=$(create_claude_pane "$FAKE_BIN")
PANE_A2=$(create_claude_pane "$FAKE_BIN")
PANE_B1=$(create_claude_pane "$FAKE_BIN")
PANE_B2=$(create_claude_pane "$FAKE_BIN")

sleep 1

log "Panes: A1=$PANE_A1  A2=$PANE_A2  B1=$PANE_B1  B2=$PANE_B2"
tmux list-panes -a -F '#{pane_id} #{pane_current_command}'

# ── Setup: wait for relay ──────────────────────────────────────────
log "Waiting for Nostr relay at $RELAY_URL..."
wait_for 30 bash -c "curl -sf --max-time 2 'http://127.0.0.1:8080' >/dev/null 2>&1 || bash -c 'echo >/dev/tcp/127.0.0.1/8080' 2>/dev/null"
log "Relay ready"

# ── Setup: two ouija daemons with nostr transport ─────────────────
log "Starting daemon A (alpha) on port $PORT_A with nostr relay"
PID_A=$(start_daemon $PORT_A "alpha" /tmp/ouija-A --relay "$RELAY_URL")
log "Daemon A started (PID $PID_A)"

log "Starting daemon B (beta) on port $PORT_B with nostr relay"
PID_B=$(start_daemon $PORT_B "beta" /tmp/ouija-B --relay "$RELAY_URL")
log "Daemon B started (PID $PID_B)"

# Wait for nostr transport to be ready (poll /api/ticket until valid)
log "Waiting for nostr transport initialization..."
wait_for 30 bash -c "ticket_a=\$(curl -sf '$BASE_A/api/ticket' | jq -r '.ticket // \"\"'); ticket_b=\$(curl -sf '$BASE_B/api/ticket' | jq -r '.ticket // \"\"'); [ -n \"\$ticket_a\" ] && [ -n \"\$ticket_b\" ]"
log "Nostr transport initialized on both daemons"

# ═══════════════════════════════════════════════════════════════════
# TESTS
# ═══════════════════════════════════════════════════════════════════

log "Test 1: Nostr transport is active on both daemons"
assert_contains "daemon A has nostr transport" "$(transport_names "$BASE_A")" "nostr"
assert_contains "daemon B has nostr transport" "$(transport_names "$BASE_B")" "nostr"

log "Test 2: Nostr tickets are nprofile bech32 strings"
ticket_a=$(api "$BASE_A" GET "/api/ticket" | jq -r '.ticket // ""')
ticket_b=$(api "$BASE_B" GET "/api/ticket" | jq -r '.ticket // ""')
assert_contains "A ticket starts with nprofile" "$ticket_a" "nprofile1"
assert_contains "B ticket starts with nprofile" "$ticket_b" "nprofile1"

log "Test 3: B connects to A using nprofile ticket"
result=$(api "$BASE_B" POST /api/connect -d "{\"ticket\":\"$ticket_a\"}")
# Both daemons start with --relay, so auto-discovery may have already connected them.
# Accept either "connected" or "already connected" as success.
if echo "$result" | grep -qF '"status":"connected"' || echo "$result" | grep -qF '"error":"already connected'; then
    pass "connect returns connected or already-connected"
else
    fail "connect returns status" "connected or already-connected" "$result"
fi

# Give relay time to establish subscriptions
sleep 3

# Register sessions AFTER connect
log "  Registering sessions on both daemons..."
api "$BASE_A" POST /api/register -d "{\"id\":\"sess-alpha\",\"pane\":\"$PANE_A1\"}" >/dev/null
api "$BASE_B" POST /api/register -d "{\"id\":\"sess-beta\",\"pane\":\"$PANE_B1\"}" >/dev/null

log "Test 4: Peer discovery — remote sessions appear with daemon prefix"
log "  Waiting for session propagation via nostr DMs..."
wait_for 30 bash -c "remote_session_ids '$BASE_A' | grep -qF 'beta/sess-beta' && remote_session_ids '$BASE_B' | grep -qF 'alpha/sess-alpha'"
assert_contains "A has beta/sess-beta as remote" "$(remote_session_ids "$BASE_A")" "beta/sess-beta"
assert_contains "B has alpha/sess-alpha as remote" "$(remote_session_ids "$BASE_B")" "alpha/sess-alpha"

log "Test 5: Message A->B via nostr DM"
result=$(api "$BASE_A" POST /api/send -d '{"from":"sess-alpha","to":"beta/sess-beta","message":"hello via nostr"}')
assert_contains "send via gossip" "$result" "nostr"
log "  Waiting for nostr DM delivery..."
wait_for 10 bash -c "tmux capture-pane -t '$PANE_B1' -p -S -30 | grep -qF 'hello via nostr'"
pane_content=$(tmux capture-pane -t "$PANE_B1" -p -S -30)
assert_contains "message appears in B's pane" "$pane_content" "hello via nostr"

log "Test 6: Message B->A via nostr DM"
result=$(api "$BASE_B" POST /api/send -d '{"from":"sess-beta","to":"alpha/sess-alpha","message":"reply via nostr"}')
assert_contains "send via gossip" "$result" "nostr"
log "  Waiting for nostr DM delivery..."
wait_for 10 bash -c "tmux capture-pane -t '$PANE_A1' -p -S -30 | grep -qF 'reply via nostr'"
pane_content=$(tmux capture-pane -t "$PANE_A1" -p -S -30)
assert_contains "message appears in A's pane" "$pane_content" "reply via nostr"

log "Test 7: Local delivery still works alongside nostr transport"
api "$BASE_A" POST /api/register -d "{\"id\":\"local-a2\",\"pane\":\"$PANE_A2\"}" >/dev/null
result=$(api "$BASE_A" POST /api/send -d '{"from":"sess-alpha","to":"local-a2","message":"local nostr test"}')
assert_contains "local send delivered" "$result" "delivered"
assert_contains "method is tmux" "$result" "tmux"
sleep 1
pane_content=$(tmux capture-pane -t "$PANE_A2" -p)
assert_contains "local message appears in pane" "$pane_content" "local nostr test"
api "$BASE_A" POST /api/remove -d '{"id":"local-a2"}' >/dev/null

log "Test 8: Session removal propagates via nostr"
api "$BASE_A" POST /api/remove -d '{"id":"sess-alpha"}' >/dev/null
log "  Waiting for removal propagation..."
wait_for 20 bash -c "! session_ids '$BASE_B' | grep -qF 'alpha/sess-alpha'"
assert_not_contains "B no longer has alpha/sess-alpha" "$(session_ids "$BASE_B")" "alpha/sess-alpha"

log "Test 9: Dashboard shows nostr transport"
curl -sL --max-time 5 "$BASE_A/" > /tmp/dashboard-page.html 2>/dev/null || true
if grep -qiF "nostr" /tmp/dashboard-page.html 2>/dev/null; then
    pass "dashboard A shows nostr"
else
    fail "dashboard A shows nostr" "contains 'nostr'" "$(wc -c < /tmp/dashboard-page.html 2>/dev/null || echo 0) bytes, first 300: $(head -c 300 /tmp/dashboard-page.html 2>/dev/null)"
fi

# Cleanup remaining sessions
api "$BASE_B" POST /api/remove -d '{"id":"sess-beta"}' >/dev/null 2>&1 || true

# ═══════════════════════════════════════════════════════════════════
# PEER PUBKEY PERSISTENCE — restart A, verify B's connection survives
# ═══════════════════════════════════════════════════════════════════

log "Test 9b: Peer pubkeys persist across daemon restart"
# Re-register sessions for this test
api "$BASE_A" POST /api/register -d "{\"id\":\"sess-persist-a\",\"pane\":\"$PANE_A1\"}" >/dev/null
api "$BASE_B" POST /api/register -d "{\"id\":\"sess-persist-b\",\"pane\":\"$PANE_B1\"}" >/dev/null

# Wait for session propagation so B sees A's sessions
wait_for 15 bash -c "remote_session_ids '$BASE_B' | grep -qF 'alpha/sess-persist-a'"
assert_contains "B sees A before restart" "$(remote_session_ids "$BASE_B")" "alpha/sess-persist-a"

# Kill daemon A and restart it
log "  Restarting daemon A..."
kill $PID_A 2>/dev/null || true
wait $PID_A 2>/dev/null || true
sleep 1
RUST_LOG=ouija=debug ouija start --port $PORT_A --name alpha --data /tmp/ouija-A \
    --relay "$RELAY_URL" >/tmp/ouija-A/daemon.log 2>&1 &
PID_A=$!
wait_for 10 curl -sf "$BASE_A/api/status" -o /dev/null
log "  Daemon A restarted (PID $PID_A)"

# Wait for sessions to be restored and propagation to resume
wait_for 10 bash -c "api '$BASE_A' GET /api/status | jq '[.sessions[] | select(.origin == \"local\")] | length' | grep -qv '^0$'"

# Verify: persisted pubkeys file exists
assert_eq "peer_pubkeys.json exists" "$(test -f /tmp/ouija-A/peer_pubkeys.json && echo yes)" "yes"

# Test that B can still send a message to A after restart
# First re-register a session on A for the message target
api "$BASE_A" POST /api/register -d "{\"id\":\"sess-after-restart\",\"pane\":\"$PANE_A2\"}" >/dev/null

# Wait for B to see the new session
wait_for 20 bash -c "remote_session_ids '$BASE_B' | grep -qF 'alpha/sess-after-restart'"

result=$(api "$BASE_B" POST /api/send -d '{"from":"sess-persist-b","to":"alpha/sess-after-restart","message":"post-restart msg"}')
assert_contains "B sends to restarted A" "$result" "nostr"
log "  Waiting for post-restart message delivery..."
wait_for 10 bash -c "tmux capture-pane -t '$PANE_A2' -p -S -30 | grep -qF 'post-restart msg'"
pane_content=$(tmux capture-pane -t "$PANE_A2" -p -S -30)
assert_contains "post-restart message delivered" "$pane_content" "post-restart msg"

# Cleanup
api "$BASE_A" POST /api/remove -d '{"id":"sess-persist-a"}' >/dev/null 2>&1 || true
api "$BASE_A" POST /api/remove -d '{"id":"sess-after-restart"}' >/dev/null 2>&1 || true
api "$BASE_B" POST /api/remove -d '{"id":"sess-persist-b"}' >/dev/null 2>&1 || true

# ═══════════════════════════════════════════════════════════════════
# THREE-DAEMON TESTS — daemon C connects to A via nprofile
# This tests the real-world scenario where a new daemon connects to
# an existing peer using only the nprofile ticket.
# ═══════════════════════════════════════════════════════════════════

PORT_C=7882
BASE_C="http://127.0.0.1:$PORT_C"

# Extra pane for daemon C
PANE_C1=$(create_claude_pane "$FAKE_BIN")
sleep 1

log "Starting daemon C (gamma) on port $PORT_C with default relay"
PID_C=$(start_daemon $PORT_C "gamma" /tmp/ouija-C --relay "$RELAY_URL")
log "Daemon C started (PID $PID_C)"

# Wait for nostr transport to register
wait_for 30 bash -c "transport_names '$BASE_C' | grep -qF 'nostr'"

log "Test 10: C has nostr transport"
assert_contains "C has nostr transport" "$(transport_names "$BASE_C")" "nostr"

# Re-register a session on A for these tests
api "$BASE_A" POST /api/register -d "{\"id\":\"sess-alpha2\",\"pane\":\"$PANE_A1\"}" >/dev/null

log "Test 11: C connects to A using nprofile ticket"
# Get A's nostr ticket
ticket_a=$(api "$BASE_A" GET "/api/ticket" | jq -r '.ticket // ""')
result=$(api "$BASE_C" POST /api/connect -d "{\"ticket\":\"$ticket_a\"}")
assert_contains "C connects to A via nostr" "$result" '"status":"connected"'

# Register session on C
api "$BASE_C" POST /api/register -d "{\"id\":\"sess-gamma\",\"pane\":\"$PANE_C1\"}" >/dev/null

log "Test 12: Bidirectional session discovery (A <-> C via nostr)"
log "  Waiting for session propagation..."
wait_for 30 bash -c "remote_session_ids '$BASE_A' | grep -qF 'gamma/sess-gamma' && remote_session_ids '$BASE_C' | grep -qF 'alpha/sess-alpha2'"
assert_contains "A sees gamma/sess-gamma" "$(remote_session_ids "$BASE_A")" "gamma/sess-gamma"
assert_contains "C sees alpha/sess-alpha2" "$(remote_session_ids "$BASE_C")" "alpha/sess-alpha2"

log "Test 13: Message A->C via nostr (lazy-activated peer)"
result=$(api "$BASE_A" POST /api/send -d '{"from":"sess-alpha2","to":"gamma/sess-gamma","message":"hello lazy gamma"}')
assert_contains "send via gossip" "$result" "nostr"
log "  Waiting for nostr DM delivery..."
wait_for 10 bash -c "tmux capture-pane -t '$PANE_C1' -p -S -30 | grep -qF 'hello lazy gamma'"
pane_content=$(tmux capture-pane -t "$PANE_C1" -p -S -30)
assert_contains "message appears in C's pane" "$pane_content" "hello lazy gamma"

log "Test 14: Message C->A via nostr (lazy-activated peer sends)"
result=$(api "$BASE_C" POST /api/send -d '{"from":"sess-gamma","to":"alpha/sess-alpha2","message":"reply from gamma"}')
assert_contains "send via gossip" "$result" "nostr"
log "  Waiting for nostr DM delivery..."
wait_for 10 bash -c "tmux capture-pane -t '$PANE_A1' -p -S -30 | grep -qF 'reply from gamma'"
pane_content=$(tmux capture-pane -t "$PANE_A1" -p -S -30)
assert_contains "message appears in A's pane" "$pane_content" "reply from gamma"

# Cleanup
api "$BASE_A" POST /api/remove -d '{"id":"sess-alpha2"}' >/dev/null 2>&1 || true
api "$BASE_C" POST /api/remove -d '{"id":"sess-gamma"}' >/dev/null 2>&1 || true

# ═══════════════════════════════════════════════════════════════════
# CROSS-DAEMON SESSION RENAME (SessionRenamed wire message)
# ═══════════════════════════════════════════════════════════════════

log "Setting up rename propagation test..."
api "$BASE_A" POST /api/register -d "{\"id\":\"rename-src\",\"pane\":\"$PANE_A1\"}" >/dev/null
api "$BASE_B" POST /api/register -d "{\"id\":\"rename-observer\",\"pane\":\"$PANE_B1\"}" >/dev/null

# Wait for B to see A's session
wait_for 20 bash -c "remote_session_ids '$BASE_B' | grep -qF 'alpha/rename-src'"
assert_contains "pre-rename: B sees alpha/rename-src" "$(remote_session_ids "$BASE_B")" "alpha/rename-src"

log "Test R1: SessionRenamed propagates across daemons"
api "$BASE_A" POST /api/rename -d '{"old_id":"rename-src","new_id":"rename-dst"}' >/dev/null
# Wait for B to see the renamed session
wait_for 20 bash -c "remote_session_ids '$BASE_B' | grep -qF 'alpha/rename-dst'"
remote_b=$(remote_session_ids "$BASE_B")
assert_contains "R1: B sees alpha/rename-dst after rename" "$remote_b" "alpha/rename-dst"
assert_not_contains "R1: old name gone from B" "$remote_b" "alpha/rename-src"

log "Test R2: Cross-daemon alias resolution after rename"
# B sends to old name — should get error with rename hint
result=$(curl -s -X POST "${BASE_B}/api/send" -H 'Content-Type: application/json' \
    -d '{"from":"rename-observer","to":"alpha/rename-src","message":"hi old name"}')
assert_contains "R2: error mentions rename" "$result" "was renamed to"
assert_contains "R2: error has renamed_to field" "$result" "rename-dst"

log "Test R3: Message to renamed session succeeds with new name"
result=$(api "$BASE_B" POST /api/send -d '{"from":"rename-observer","to":"alpha/rename-dst","message":"hello renamed"}')
assert_contains "R3: send via gossip" "$result" "nostr"
log "  Waiting for nostr DM delivery..."
wait_for 10 bash -c "tmux capture-pane -t '$PANE_A1' -p -S -30 | grep -qF 'hello renamed'"
pane_content=$(tmux capture-pane -t "$PANE_A1" -p -S -30)
assert_contains "R3: message delivered to renamed session" "$pane_content" "hello renamed"

# Cleanup
api "$BASE_A" POST /api/remove -d '{"id":"rename-dst"}' >/dev/null 2>&1 || true
api "$BASE_B" POST /api/remove -d '{"id":"rename-observer"}' >/dev/null 2>&1 || true

# ═══════════════════════════════════════════════════════════════════
# CROSS-DAEMON FROM-PREFIX ROUTING
# ═══════════════════════════════════════════════════════════════════

log "Setting up from-prefix routing test..."
api "$BASE_A" POST /api/register -d "{\"id\":\"route-a\",\"pane\":\"$PANE_A1\"}" >/dev/null
api "$BASE_B" POST /api/register -d "{\"id\":\"route-b\",\"pane\":\"$PANE_B1\"}" >/dev/null

# Wait for mutual visibility
wait_for 20 bash -c "remote_session_ids '$BASE_A' | grep -qF 'beta/route-b' && remote_session_ids '$BASE_B' | grep -qF 'alpha/route-a'"

log "Test R4: Cross-daemon message shows from-prefix in pane"
tmux send-keys -t "$PANE_A1" "clear" Enter
sleep 0.5
result=$(api "$BASE_B" POST /api/send -d '{"from":"route-b","to":"alpha/route-a","message":"routed hello","expects_reply":true}')
assert_contains "R4: send via gossip" "$result" "nostr"
wait_for 10 bash -c "tmux capture-pane -t '$PANE_A1' -p -S -30 | grep -qF 'routed hello'"
pane_content=$(tmux capture-pane -t "$PANE_A1" -p -S -30)
assert_contains "R4: message has from prefix" "$pane_content" '<msg from="beta/route-b"'
assert_contains "R4: message content delivered" "$pane_content" "routed hello"

log "Test R5: Cross-daemon message without expects_reply omits ?"
tmux send-keys -t "$PANE_A1" "clear" Enter
sleep 0.5
result=$(api "$BASE_B" POST /api/send -d '{"from":"route-b","to":"alpha/route-a","message":"fyi only","expects_reply":false}')
wait_for 10 bash -c "tmux capture-pane -t '$PANE_A1' -p -S -30 | grep -qF 'fyi only'"
pane_content=$(tmux capture-pane -t "$PANE_A1" -p -S -30)
# Check the specific line containing "fyi only" has no ? prefix
fyi_line=$(echo "$pane_content" | grep -F "fyi only" | head -1)
assert_contains "R5: fyi line has from prefix" "$fyi_line" '<msg from="beta/route-b"'
assert_not_contains "R5: fyi line has no reply attr" "$fyi_line" 'reply="true"'

# Cleanup
api "$BASE_A" POST /api/remove -d '{"id":"route-a"}' >/dev/null 2>&1 || true
api "$BASE_B" POST /api/remove -d '{"id":"route-b"}' >/dev/null 2>&1 || true

# ═══════════════════════════════════════════════════════════════════
# SINGLE-USE TICKET TEST — ticket voided after C connected
# The ticket C used in test 11 should be invalidated. D tries to
# reuse it and should be rejected (unauthorized).
# ═══════════════════════════════════════════════════════════════════

PORT_D=7883
BASE_D="http://127.0.0.1:$PORT_D"

PANE_D1=$(create_claude_pane "$FAKE_BIN")
sleep 1

log "Starting daemon D (delta) on port $PORT_D — single-use ticket test"
PID_D=$(start_daemon $PORT_D "delta" /tmp/ouija-D --relay "$RELAY_URL")
log "Daemon D started (PID $PID_D)"

# Wait for nostr transport
wait_for 30 bash -c "transport_names '$BASE_D' | grep -qF 'nostr'"

log "Test 14b: Reused ticket rejected (single-use)"
# ticket_a was captured in test 11 — C already used it, so it should be voided
result=$(api "$BASE_D" POST /api/connect -d "{\"ticket\":\"$ticket_a\"}")
if echo "$result" | grep -qF '"status":"connected"' || echo "$result" | grep -qF '"error":"already connected'; then
    pass "D connect call succeeds locally (ticket sent)"
else
    fail "D connect call" "connected or already-connected" "$result"
fi

# Register session on D and wait — A should NOT authorize D
api "$BASE_D" POST /api/register -d "{\"id\":\"sess-delta\",\"pane\":\"$PANE_D1\"}" >/dev/null
sleep 5

remote_a=$(remote_session_ids "$BASE_A")
assert_not_contains "A rejects reused ticket (D not visible)" "$remote_a" "delta/sess-delta"

# Check A's log for the rejection
daemon_a_log=$(cat /tmp/ouija-A/daemon.log 2>/dev/null || echo "")
assert_contains "A log rejects invalid secret" "$daemon_a_log" "rejected connect with invalid secret"

# ═══════════════════════════════════════════════════════════════════
# UNAUTHORIZED SENDER TEST — daemon D connects without secret
# Verifies that peers who don't present the connect secret are rejected.
# (D is already running from the single-use ticket test above)
# ═══════════════════════════════════════════════════════════════════

# Re-register a session on A for this test
api "$BASE_A" POST /api/register -d "{\"id\":\"sess-alpha3\",\"pane\":\"$PANE_A1\"}" >/dev/null

# Get A's FRESH ticket and strip the secret — D only gets the nprofile
ticket_a=$(api "$BASE_A" GET "/api/ticket" | jq -r '.ticket // ""')
nprofile_only=$(echo "$ticket_a" | cut -d'#' -f1)

log "Test 15: D connects to A without secret (nprofile only)"
# Remove D's old session from single-use test, re-register fresh
api "$BASE_D" POST /api/remove -d '{"id":"sess-delta"}' >/dev/null 2>&1 || true

result=$(curl -s -X POST "${BASE_D}/api/connect" -H 'Content-Type: application/json' -d "{\"ticket\":\"$nprofile_only\"}")
# Connect itself will succeed (adds relay + pubkey locally) but A won't authorize D
# Use curl -s (not -sf) because "already connected" returns HTTP 409
if echo "$result" | grep -qF '"status":"connected"' || echo "$result" | grep -qF '"error":"already connected'; then
    pass "D connect call succeeds (local setup)"
else
    fail "D connect call" "connected or already-connected" "$result"
fi

# Register session on D and wait briefly
api "$BASE_D" POST /api/register -d "{\"id\":\"sess-delta\",\"pane\":\"$PANE_D1\"}" >/dev/null
sleep 5

log "Test 16: A does NOT see delta's sessions (unauthorized peer)"
remote_a=$(remote_session_ids "$BASE_A")
assert_not_contains "A does not have delta/sess-delta" "$remote_a" "delta/sess-delta"

log "Test 17: D sends message to A — message NOT delivered (unauthorized)"
# Clear A's pane first
tmux send-keys -t "$PANE_A1" '' Enter
sleep 0.5
result=$(api "$BASE_D" POST /api/send -d '{"from":"sess-delta","to":"alpha/sess-alpha3","message":"unauthorized msg"}')
sleep 5
pane_content=$(tmux capture-pane -t "$PANE_A1" -p -S -30)
assert_not_contains "unauthorized message NOT in A's pane" "$pane_content" "unauthorized msg"

log "Test 18: A's log shows rejection of unauthorized sender"
daemon_a_log=$(cat /tmp/ouija-A/daemon.log 2>/dev/null || echo "")
assert_contains "A log has rejection" "$daemon_a_log" "rejected message from unauthorized sender"

# Cleanup
api "$BASE_A" POST /api/remove -d '{"id":"sess-alpha3"}' >/dev/null 2>&1 || true
api "$BASE_D" POST /api/remove -d '{"id":"sess-delta"}' >/dev/null 2>&1 || true

# ═══════════════════════════════════════════════════════════════════
# HUMAN NOSTR SESSION TESTS
# ═══════════════════════════════════════════════════════════════════
log "Setting up human DM tests..."

# Re-register sess-alpha (removed in test 8)
api "$BASE_A" POST /api/register -d "{\"id\":\"sess-alpha\",\"pane\":\"$PANE_A1\"}" >/dev/null

# Generate a human keypair
HUMAN_KEYS=$(human-dm-helper keygen)
HUMAN_NPUB=$(echo "$HUMAN_KEYS" | head -1)
HUMAN_NSEC=$(echo "$HUMAN_KEYS" | tail -1)
log "Human npub: $HUMAN_NPUB"

# Get daemon A's npub
DAEMON_A_NPUB=$(api "$BASE_A" GET /api/status | jq -r '.daemon_id // ""')
log "Daemon A npub: $DAEMON_A_NPUB"

log "Test H1: Add human session to daemon A"
H1=$(api "$BASE_A" POST /api/humans -d "{\"name\":\"testhuman\",\"npub\":\"$HUMAN_NPUB\"}")
assert_contains "H1: add human" "$H1" '"status":"added"'

log "Test H2: Human appears in session list"
H2=$(session_field "$BASE_A" "testhuman" "origin")
assert_eq "H2: human session origin" "$H2" "human"

log "Test H3: Outbound DM — session sends message to human"
# Start human-dm-helper recv in background to catch the DM
human-dm-helper recv "$RELAY_URL" --nsec "$HUMAN_NSEC" --timeout 20 > /tmp/human-recv.txt 2>/tmp/human-recv-err.txt &
HUMAN_RECV_PID=$!
sleep 3  # let it subscribe

# Send message from a session to the human
api "$BASE_A" POST /api/send -d '{"from":"sess-alpha","to":"testhuman","message":"hello human"}' >/dev/null

# Wait for delivery
for i in $(seq 1 15); do
    if [ -s /tmp/human-recv.txt ]; then break; fi
    sleep 1
done

# Check if the human received the DM
HUMAN_RECV=$(cat /tmp/human-recv.txt 2>/dev/null || echo "")
kill $HUMAN_RECV_PID 2>/dev/null || true
wait $HUMAN_RECV_PID 2>/dev/null || true
assert_contains "H3: human received DM" "$HUMAN_RECV" "hello human"
assert_contains "H3: DM has from header" "$HUMAN_RECV" "[from sess-alpha]"

log "Test H4: Inbound DM — human sends message to daemon session"
# Clear the target pane first
tmux send-keys -t "$PANE_A1" '' Enter
sleep 0.5

# Human sends a DM to the daemon addressed to a session
human-dm-helper send "$RELAY_URL" "$DAEMON_A_NPUB" "@sess-alpha hello from human" --nsec "$HUMAN_NSEC"

# Wait for delivery
wait_for 15 bash -c "tmux capture-pane -t '$PANE_A1' -p -S -30 | grep -qF 'hello from human'"
pane_content=$(tmux capture-pane -t "$PANE_A1" -p -S -30)
assert_contains "H4: human message delivered to pane" "$pane_content" "hello from human"

log "Test H5: Inbound /help command"
# Start receiver to catch daemon's reply
human-dm-helper recv "$RELAY_URL" --nsec "$HUMAN_NSEC" --timeout 20 > /tmp/human-help.txt 2>/tmp/human-help-err.txt &
HUMAN_HELP_PID=$!
sleep 3

# Human sends /help
human-dm-helper send "$RELAY_URL" "$DAEMON_A_NPUB" "/help" --nsec "$HUMAN_NSEC"

for i in $(seq 1 15); do
    if [ -s /tmp/human-help.txt ]; then break; fi
    sleep 1
done

HELP_REPLY=$(cat /tmp/human-help.txt 2>/dev/null || echo "")
kill $HUMAN_HELP_PID 2>/dev/null || true
wait $HUMAN_HELP_PID 2>/dev/null || true
assert_contains "H5: help reply contains daemon name" "$HELP_REPLY" "alpha"
assert_contains "H5: help reply contains /list" "$HELP_REPLY" "/list"

log "Test H6: Inbound /list command"
human-dm-helper recv "$RELAY_URL" --nsec "$HUMAN_NSEC" --timeout 20 > /tmp/human-list.txt 2>/tmp/human-list-err.txt &
HUMAN_LIST_PID=$!
sleep 3

human-dm-helper send "$RELAY_URL" "$DAEMON_A_NPUB" "/list" --nsec "$HUMAN_NSEC"

for i in $(seq 1 15); do
    if [ -s /tmp/human-list.txt ]; then break; fi
    sleep 1
done

LIST_REPLY=$(cat /tmp/human-list.txt 2>/dev/null || echo "")
kill $HUMAN_LIST_PID 2>/dev/null || true
wait $HUMAN_LIST_PID 2>/dev/null || true
assert_contains "H6: list reply contains sessions" "$LIST_REPLY" "sess-alpha"

log "Test H7: Inbound bare text routes to default session"
# Set default session first
human-dm-helper recv "$RELAY_URL" --nsec "$HUMAN_NSEC" --timeout 10 > /dev/null 2>&1 &
HUMAN_DEFAULT_PID=$!
sleep 2

human-dm-helper send "$RELAY_URL" "$DAEMON_A_NPUB" "/default sess-alpha" --nsec "$HUMAN_NSEC"
sleep 3
kill $HUMAN_DEFAULT_PID 2>/dev/null || true
wait $HUMAN_DEFAULT_PID 2>/dev/null || true

# Now send bare text
tmux send-keys -t "$PANE_A1" '' Enter
sleep 0.5
human-dm-helper send "$RELAY_URL" "$DAEMON_A_NPUB" "bare text message" --nsec "$HUMAN_NSEC"

wait_for 15 bash -c "tmux capture-pane -t '$PANE_A1' -p -S -30 | grep -qF 'bare text message'"
pane_content=$(tmux capture-pane -t "$PANE_A1" -p -S -30)
assert_contains "H7: bare text delivered to default session" "$pane_content" "bare text message"

log "Test H8: Inbound /nodes command"
human-dm-helper recv "$RELAY_URL" --nsec "$HUMAN_NSEC" --timeout 20 > /tmp/human-nodes.txt 2>/tmp/human-nodes-err.txt &
HUMAN_NODES_PID=$!
sleep 3

human-dm-helper send "$RELAY_URL" "$DAEMON_A_NPUB" "/nodes" --nsec "$HUMAN_NSEC"

for i in $(seq 1 15); do
    if [ -s /tmp/human-nodes.txt ]; then break; fi
    sleep 1
done

NODES_REPLY=$(cat /tmp/human-nodes.txt 2>/dev/null || echo "")
kill $HUMAN_NODES_PID 2>/dev/null || true
wait $HUMAN_NODES_PID 2>/dev/null || true
# Should get a reply (might show connected nodes or "no connected nodes")
if [ -n "$NODES_REPLY" ]; then
    pass "H8: nodes command got reply"
else
    fail "H8: nodes command got reply" "non-empty reply" "(empty)"
fi

# Cleanup human
api "$BASE_A" DELETE /api/humans -d '{"name":"testhuman"}' >/dev/null 2>&1 || true

# ── Daemon logs ──────────────────────────────────────────────────────
echo ""
log "Daemon A logs:"
cat /tmp/ouija-A/daemon.log 2>/dev/null || true
echo ""
log "Daemon B logs:"
cat /tmp/ouija-B/daemon.log 2>/dev/null || true
echo ""
log "Daemon C logs:"
cat /tmp/ouija-C/daemon.log 2>/dev/null || true
echo ""
log "Daemon D logs:"
cat /tmp/ouija-D/daemon.log 2>/dev/null || true

# ── Results ──────────────────────────────────────────────────────────
print_results

# Cleanup
kill $PID_A 2>/dev/null || true
kill $PID_B 2>/dev/null || true
kill $PID_C 2>/dev/null || true
kill $PID_D 2>/dev/null || true
exit "$FAIL"
