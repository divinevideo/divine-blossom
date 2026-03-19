#!/bin/bash
# ABOUTME: Adaptive MP4 backfill — remuxes existing .ts variants to regular MP4 with faststart
# ABOUTME: Idempotent: tracks done hashes, skips on re-run. Streams from GCS or uses cached list.
#
# Prerequisites:
#   gcloud config configurations activate divine  # need GCS access to divine-blossom-media bucket
#
# To generate the hash list (takes ~15 min for 200k+ videos):
#   gcloud storage ls "gs://divine-blossom-media/**/stream_720p.ts" --project rich-compiler-479518-d2 \
#     | sed 's|.*/\([a-f0-9]\{64\}\)/hls/stream_720p.ts|\1|' | sort -u > scripts/backfill-fmp4-all-hashes.txt
#
# Usage:
#   ./scripts/backfill-fmp4.sh              # stream from GCS, process as hashes arrive
#   ./scripts/backfill-fmp4.sh --dry-run    # count hashes without processing
#
# State files (in scripts/):
#   backfill-fmp4-done.txt    — processed hashes (append-only, sorted on exit)
#   backfill-fmp4-failed.txt  — hashes that returned non-200

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TRANSCODER_URL="https://divine-transcoder-149672065768.us-central1.run.app/backfill-fmp4"
GCS_BUCKET="gs://divine-blossom-media"

DONE_FILE="$SCRIPT_DIR/backfill-fmp4-done.txt"
FAILED_FILE="$SCRIPT_DIR/backfill-fmp4-failed.txt"

CONCURRENCY=50
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --concurrency) CONCURRENCY="${2:?missing value}"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        -h|--help) sed -n '2,12s/^# //p' "$0"; exit 0 ;;
        *) echo "Unknown: $1" >&2; exit 1 ;;
    esac
done

touch "$DONE_FILE" "$FAILED_FILE"

# Build a set of done hashes for fast lookup
DONE_SET=$(mktemp)
sort -u "$DONE_FILE" > "$DONE_SET"
done_count=$(wc -l < "$DONE_SET")
echo "Already processed: $done_count" >&2
echo "Streaming hashes from GCS and processing at concurrency $CONCURRENCY..." >&2
echo "" >&2

# Activate divine config for GCS access
gcloud config configurations activate divine 2>/dev/null

success=0
skipped=0
failed=0
total=0
start_time=$(date +%s)

# Stream hashes from GCS, extract hash, skip done, process in parallel
gcloud storage ls "$GCS_BUCKET/**/stream_720p.ts" --project rich-compiler-479518-d2 2>/dev/null \
| sed -n 's|.*/\([a-f0-9]\{64\}\)/hls/stream_720p.ts|\1|p' \
| while IFS= read -r hash; do
    total=$((total + 1))

    # Skip if already done
    if grep -qF "$hash" "$DONE_SET"; then
        skipped=$((skipped + 1))
        # Progress every 500 skips
        if (( skipped % 500 == 0 )); then
            printf "\r[scanning] seen:%d skipped:%d queued:%d    " "$total" "$skipped" "$((success + failed))" >&2
        fi
        continue
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        echo "$hash"
        continue
    fi

    # Process: call backfill endpoint
    (
        code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TRANSCODER_URL" \
            -H "Content-Type: application/json" \
            -d "{\"hash\": \"$hash\"}" \
            --max-time 60 --retry 1 --retry-delay 3)

        if [[ "$code" == "200" ]]; then
            echo "$hash" >> "$DONE_FILE"
        else
            echo "$hash" >> "$FAILED_FILE"
            echo "FAIL $hash HTTP $code" >&2
        fi
    ) &

    # Throttle: wait if we have too many background jobs
    while (( $(jobs -r | wc -l) >= CONCURRENCY )); do
        sleep 0.1
    done

    # Progress every 10 hashes processed
    processed=$(wc -l < "$DONE_FILE")
    failed_count=$(wc -l < "$FAILED_FILE")
    elapsed=$(( $(date +%s) - start_time ))
    rate=0
    [[ "$elapsed" -gt 0 ]] && rate=$(( (processed - done_count) / elapsed ))
    printf "\r[backfill] seen:%d skip:%d done:%d fail:%d %d/s conc:%d    " \
        "$total" "$skipped" "$processed" "$failed_count" "$rate" "$(jobs -r | wc -l)" >&2
done

# Wait for remaining jobs
wait

rm -f "$DONE_SET"

gcloud config configurations activate default 2>/dev/null

# Sort done file for fast lookup on next run
sort -uo "$DONE_FILE" "$DONE_FILE"

elapsed=$(( $(date +%s) - start_time ))
final_done=$(wc -l < "$DONE_FILE")
final_failed=$(wc -l < "$FAILED_FILE")
new_done=$((final_done - done_count))

echo "" >&2
echo "" >&2
echo "=== Backfill complete ===" >&2
echo "New: $new_done | Total done: $final_done | Failed: $final_failed | Time: ${elapsed}s" >&2
[[ -s "$FAILED_FILE" ]] && echo "Retry: $0 (failed hashes auto-skipped on next run)" >&2
