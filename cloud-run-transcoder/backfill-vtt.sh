#!/bin/bash
# ABOUTME: Backfill VTT transcripts via the admin API endpoint
# ABOUTME: Iterates through all users in batches, triggering transcription for missing VTTs

set -e

ADMIN_URL="${ADMIN_URL:-https://media.divine.video}"
BATCH_SIZE="${BATCH_SIZE:-50}"
COOKIE="${ADMIN_COOKIE:?Set ADMIN_COOKIE to your admin session cookie}"

offset=0
total_triggered=0
total_complete=0
total_errors=0

echo "=== VTT Transcript Backfill ==="
echo "Server: $ADMIN_URL"
echo "Batch size: $BATCH_SIZE"
echo ""

while true; do
    echo "[$(date '+%H:%M:%S')] Processing users at offset $offset..."

    response=$(curl -s -X POST \
        "${ADMIN_URL}/admin/api/backfill-vtt?offset=${offset}&limit=${BATCH_SIZE}" \
        -H "Cookie: session=${COOKIE}")

    # Parse response
    has_more=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['batch']['has_more'])" 2>/dev/null)
    triggered=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['results']['triggered'])" 2>/dev/null)
    complete=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['results']['already_complete'])" 2>/dev/null)
    errors=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['results']['errors'])" 2>/dev/null)
    next_offset=$(echo "$response" | python3 -c "import sys,json; r=json.load(sys.stdin)['batch']['next_offset']; print(r if r else '')" 2>/dev/null)

    if [[ -z "$has_more" ]]; then
        echo "ERROR: Failed to parse response:"
        echo "$response"
        exit 1
    fi

    total_triggered=$((total_triggered + triggered))
    total_complete=$((total_complete + complete))
    total_errors=$((total_errors + errors))

    echo "  Triggered: $triggered | Already complete: $complete | Errors: $errors"

    if [[ "$has_more" == "False" ]] || [[ -z "$next_offset" ]]; then
        break
    fi

    offset=$next_offset

    # Small delay between batches to avoid overwhelming the transcoder
    sleep 2
done

echo ""
echo "=== Backfill complete ==="
echo "Total triggered: $total_triggered"
echo "Already complete: $total_complete"
echo "Total errors: $total_errors"
