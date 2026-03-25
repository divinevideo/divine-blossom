#!/bin/bash
# ABOUTME: Backfill VTT transcripts for all videos missing them
# ABOUTME: Uses Fastly admin API to scan KV metadata + trigger Cloud Run transcriber

set -e

ADMIN_URL="${ADMIN_URL:-https://media.divine.video}"
BATCH_SIZE="${BATCH_SIZE:-50}"
DELAY="${DELAY:-3}"  # seconds between batches (each batch triggers up to 10 transcriptions)
RESET_STALE="${RESET_STALE:-false}"  # set to true to re-trigger stuck "processing" items
MAX_RETRIES=3

# Auth: prefer webhook secret from GCP, fall back to env var or cookie
GCP_PROJECT="${GCP_PROJECT:-rich-compiler-479518-d2}"
if [[ -z "$WEBHOOK_SECRET" ]]; then
    echo "Fetching webhook secret from GCP (project=${GCP_PROJECT})..."
    WEBHOOK_SECRET=$(gcloud secrets versions access latest --secret=webhook_secret --project="${GCP_PROJECT}" 2>/dev/null || true)
fi

if [[ -n "$WEBHOOK_SECRET" ]]; then
    AUTH_HEADER="Authorization: Bearer ${WEBHOOK_SECRET}"
    AUTH_TYPE="Bearer token"
elif [[ -n "$ADMIN_COOKIE" ]]; then
    AUTH_HEADER="Cookie: session=${ADMIN_COOKIE}"
    AUTH_TYPE="session cookie"
else
    echo "ERROR: Need WEBHOOK_SECRET or ADMIN_COOKIE"
    exit 1
fi

echo "=== VTT Transcript Backfill ==="
echo "Server: ${ADMIN_URL}"
echo "Auth: ${AUTH_TYPE}"
echo "Batch: ${BATCH_SIZE} users, 10 triggers per call"
echo "Reset stale: ${RESET_STALE}"
echo ""

offset=0
total_triggered=0
total_complete=0
total_errors=0
total_processing=0
consecutive_failures=0

while true; do
    echo -n "[$(date '+%H:%M:%S')] offset=${offset} "

    # Use -s (silent) but NOT -f so we can see error bodies
    response=$(curl -s -X POST \
        "${ADMIN_URL}/admin/api/backfill-vtt?offset=${offset}&limit=${BATCH_SIZE}&reset_processing=${RESET_STALE}" \
        -H "${AUTH_HEADER}" \
        --max-time 60 2>&1)
    curl_exit=$?

    if [[ $curl_exit -ne 0 ]]; then
        echo "CURL ERROR (exit ${curl_exit})"
        consecutive_failures=$((consecutive_failures + 1))
        if [[ $consecutive_failures -ge $MAX_RETRIES ]]; then
            echo "  Too many consecutive failures, advancing offset..."
            offset=$((offset + BATCH_SIZE))
            consecutive_failures=0
        else
            echo "  Retrying in ${DELAY}s..."
        fi
        sleep "$DELAY"
        continue
    fi

    # Check for error responses (503, 401, etc.)
    is_error=$(echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('yes' if 'error' in d and 'success' not in d else 'no')
except:
    print('yes')
" 2>/dev/null)

    if [[ "$is_error" == "yes" ]]; then
        echo "ERROR: ${response}"
        consecutive_failures=$((consecutive_failures + 1))
        if [[ $consecutive_failures -ge $MAX_RETRIES ]]; then
            echo "  Too many consecutive failures, advancing offset..."
            offset=$((offset + BATCH_SIZE))
            consecutive_failures=0
        else
            echo "  Retrying in ${DELAY}s..."
        fi
        sleep "$DELAY"
        continue
    fi

    consecutive_failures=0

    # Parse response fields
    has_more=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['batch']['has_more'])")
    next_offset=$(echo "$response" | python3 -c "import sys,json; r=json.load(sys.stdin)['batch'].get('next_offset'); print(r if r is not None else '')")
    triggered=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['results']['triggered'])")
    complete=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['results']['already_complete'])")
    processing=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['results'].get('already_processing', 0))")
    errors=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['results'].get('errors', 0))")
    hit_limit=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['results'].get('hit_trigger_limit', False))")

    total_triggered=$((total_triggered + triggered))
    total_complete=$((total_complete + complete))
    total_errors=$((total_errors + errors))
    total_processing=$((total_processing + processing))

    echo "triggered=${triggered} complete=${complete} processing=${processing} errors=${errors}"

    # If we hit the trigger limit, re-run same offset to catch remaining videos
    # (already-triggered items are now "Processing" and will be skipped)
    if [[ "$hit_limit" == "True" ]]; then
        echo "  → more videos at this offset, re-scanning..."
        sleep "$DELAY"
        continue
    fi

    # Move to next batch of users
    if [[ "$has_more" == "False" ]] || [[ -z "$next_offset" ]]; then
        break
    fi

    offset=$next_offset
    sleep "$DELAY"
done

echo ""
echo "=== Done ==="
echo "Triggered: ${total_triggered}"
echo "Already complete: ${total_complete}"
echo "Already processing: ${total_processing}"
echo "Errors: ${total_errors}"
echo ""
echo "Transcriptions run async on Cloud Run (~30-60s each)."
echo "VTTs will appear at https://media.divine.video/{hash}.vtt as they complete."
