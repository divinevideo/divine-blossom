#!/bin/bash
# Re-transcribe all VTTs for blobs uploaded since March 8, 2026
# Uses force_retranscribe=true which tells the Cloud Run transcoder
# to overwrite existing VTT files (force=true in the JSON payload).
#
# Run this after OpenAI API quota resets.
# Usage: ./backfill-vtt-force.sh
#
# To resume from a specific offset: OFFSET=500 ./backfill-vtt-force.sh

URL="https://separately-robust-roughy.edgecompute.app/admin/api/backfill-vtt"

# Auth: prefer webhook secret from env, fall back to GCP Secret Manager
if [[ -z "$WEBHOOK_SECRET" ]]; then
    echo "Fetching webhook secret from GCP..."
    WEBHOOK_SECRET=$(gcloud secrets versions access latest --secret=webhook_secret --project=rich-compiler-479518-d2 2>/dev/null || true)
fi

if [[ -z "$WEBHOOK_SECRET" ]]; then
    echo "ERROR: Could not fetch WEBHOOK_SECRET from GCP and none set in environment"
    exit 1
fi

AUTH="Authorization: Bearer ${WEBHOOK_SECRET}"
OFFSET=${OFFSET:-0}
LIMIT=1
MAX_TRIGGERS=${MAX_TRIGGERS:-10}
TOTAL=0
BATCH=0
CONSECUTIVE_ERRORS=0
MAX_CONSECUTIVE_ERRORS=5

echo "Starting VTT force re-transcription backfill from offset=$OFFSET"
echo "Using force_retranscribe=true (overwrites existing VTTs)"
echo ""

while true; do
    BATCH=$((BATCH + 1))

    RESPONSE=$(curl -s -X POST -H "$AUTH" \
        "${URL}?offset=${OFFSET}&limit=${LIMIT}&max_triggers=${MAX_TRIGGERS}&force_retranscribe=true" \
        2>/dev/null)

    # Check for errors
    if echo "$RESPONSE" | grep -q '"error":"' 2>/dev/null || [ -z "$RESPONSE" ] || echo "$RESPONSE" | grep -q "Service Unavailable"; then
        CONSECUTIVE_ERRORS=$((CONSECUTIVE_ERRORS + 1))
        if [ $CONSECUTIVE_ERRORS -ge $MAX_CONSECUTIVE_ERRORS ]; then
            echo "Errors at offset=$OFFSET, skipping ahead"
            OFFSET=$((OFFSET + LIMIT))
            CONSECUTIVE_ERRORS=0
        else
            echo "Error at offset=$OFFSET (attempt $CONSECUTIVE_ERRORS/$MAX_CONSECUTIVE_ERRORS), retrying..."
            sleep 2
        fi
        continue
    fi

    CONSECUTIVE_ERRORS=0

    # Parse response
    TRIGGERED=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['results']['triggered'])" 2>/dev/null)
    HAS_MORE=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['batch']['has_more'])" 2>/dev/null)
    ERRORS=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['results']['errors'])" 2>/dev/null)
    RESET=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['results'].get('reset_from_processing',0))" 2>/dev/null)

    if [ -z "$TRIGGERED" ]; then
        echo "Failed to parse response at offset=$OFFSET"
        OFFSET=$((OFFSET + LIMIT))
        continue
    fi

    TOTAL=$((TOTAL + TRIGGERED))
    echo "Batch $BATCH (offset=$OFFSET): triggered=$TRIGGERED reset=$RESET errors=$ERRORS | total=$TOTAL"

    # Always advance offset
    OFFSET=$((OFFSET + LIMIT))

    # Stop if no more users
    if [ "$HAS_MORE" = "False" ] || [ "$HAS_MORE" = "false" ]; then
        echo ""
        echo "=== COMPLETE ==="
        echo "Total transcriptions triggered: $TOTAL"
        echo "Final offset: $OFFSET"
        break
    fi

    # Rate limit: scale delay based on how many we triggered
    # gpt-4o-mini-transcribe has ~100 RPM on most tiers
    if [ "$TRIGGERED" -gt 5 ]; then
        sleep 10
    elif [ "$TRIGGERED" -gt 0 ]; then
        sleep 5
    else
        sleep 1
    fi
done
