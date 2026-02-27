#!/bin/bash
set -euo pipefail

source /lib.sh

echo "=== Install experience e2e tests ==="
echo ""

# ── T1: Binary installed and --help works ─────────────────────────
log "T1: binary installed"
HELP_OUTPUT=$(ouija --help 2>&1)
assert_contains "ouija --help outputs usage info" "$HELP_OUTPUT" "ouija"

# ── T2: Preflight — tmux missing ──────────────────────────────────
log "T2: tmux missing"
PREFLIGHT_OUT=$(ouija start --port 17880 2>&1 || true)
assert_contains "error mentions tmux not found" "$PREFLIGHT_OUT" "tmux not found"
assert_contains "shows apt install hint" "$PREFLIGHT_OUT" "apt install tmux"
STARTED="no"
curl -sf http://127.0.0.1:17880/api/status >/dev/null 2>&1 && STARTED="yes"
assert_eq "daemon did not start without tmux" "$STARTED" "no"

# ── T3: Preflight — tmux present, claude missing ─────────────────
log "T3: tmux present, no claude"
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq --no-install-recommends tmux >/dev/null 2>&1

DATA_T3=$(mktemp -d)
echo '{"auto_register":false}' > "$DATA_T3/settings.json"
tmux new-session -d -s preflight

ouija start --port 17881 --data "$DATA_T3" >"$DATA_T3/output.log" 2>&1 &
PID_T3=$!

if wait_for 15 curl -sf http://127.0.0.1:17881/api/status -o /dev/null; then
    pass "daemon started without claude"
else
    echo "--- daemon output ---"
    cat "$DATA_T3/output.log" || true
    echo "---"
    fail "daemon should start without claude" "running" "not responding"
fi

LOG_T3=$(cat "$DATA_T3/output.log")
assert_contains "claude warning printed" "$LOG_T3" "claude not found"

kill "$PID_T3" 2>/dev/null || true
wait "$PID_T3" 2>/dev/null || true

# ── T4: Preflight — both tmux and claude present ─────────────────
log "T4: tmux + claude present"
cp /bin/true /usr/local/bin/claude
chmod +x /usr/local/bin/claude

DATA_T4=$(mktemp -d)
echo '{"auto_register":false}' > "$DATA_T4/settings.json"

ouija start --port 17882 --data "$DATA_T4" >"$DATA_T4/output.log" 2>&1 &
PID_T4=$!

if wait_for 15 curl -sf http://127.0.0.1:17882/api/status -o /dev/null; then
    pass "daemon started with both present"
else
    echo "--- daemon output ---"
    cat "$DATA_T4/output.log" || true
    echo "---"
    fail "daemon should start with both present" "running" "not responding"
fi

LOG_T4=$(cat "$DATA_T4/output.log")
assert_not_contains "no claude warning when claude is on PATH" "$LOG_T4" "claude not found"

kill "$PID_T4" 2>/dev/null || true
wait "$PID_T4" 2>/dev/null || true

# ── Results ───────────────────────────────────────────────────────
print_results
[ "$FAIL" -eq 0 ]
