#!/bin/bash
# ABOUTME: Fix portrait videos that were transcoded as landscape before the orientation fix (1d49c0b, Feb 7 2026).
# ABOUTME: Detects orientation mismatch between original blob and 720p variant, deletes bad HLS so on-demand re-transcoding rebuilds correctly.
# ABOUTME: Idempotent: tracks done hashes, skips on re-run.
#
# Prerequisites:
#   gcloud config configurations activate divine  # need GCS access to divine-blossom-media bucket
#   ffprobe installed
#
# Usage:
#   ./scripts/backfill-orientation.sh --dry-run     # detect and list affected hashes without deleting
#   ./scripts/backfill-orientation.sh               # detect and delete bad HLS for affected hashes
#   ./scripts/backfill-orientation.sh --hash abc123  # check/fix a single hash
#
# State files (in scripts/):
#   backfill-orientation-done.txt      — checked hashes (append-only, sorted on exit)
#   backfill-orientation-affected.txt  — hashes that had orientation mismatch (for cache purge)
#   backfill-orientation-failed.txt    — hashes where probe/delete failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MEDIA_BASE="https://media.divine.video"
GCS_BUCKET="gs://divine-blossom-media"
GCS_PROJECT="rich-compiler-479518-d2"

DONE_FILE="$SCRIPT_DIR/backfill-orientation-done.txt"
AFFECTED_FILE="$SCRIPT_DIR/backfill-orientation-affected.txt"
FAILED_FILE="$SCRIPT_DIR/backfill-orientation-failed.txt"

CONCURRENCY=10
DRY_RUN=false
SINGLE_HASH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --concurrency) CONCURRENCY="${2:?missing value}"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        --hash) SINGLE_HASH="${2:?missing hash}"; shift 2 ;;
        -h|--help) sed -n '2,10s/^# //p' "$0"; exit 0 ;;
        *) echo "Unknown: $1" >&2; exit 1 ;;
    esac
done

touch "$DONE_FILE" "$AFFECTED_FILE" "$FAILED_FILE"

# Probe video coded dimensions from a URL (ignores rotation metadata).
# We only care about natively portrait videos (coded h > w) — videos that are
# portrait via rotation metadata were handled correctly by the old GPU transcoder
# (scale_cuda did a valid landscape-to-landscape scale on the unrotated frames).
# Returns "WIDTHxHEIGHT" or empty on failure.
probe_dimensions() {
    local url="$1"
    ffprobe -v quiet -print_format json -show_entries stream=width,height -select_streams v:0 "$url" 2>/dev/null \
        | python3 -c "
import sys, json
try:
    s = json.load(sys.stdin)['streams'][0]
    print(f\"{s['width']}x{s['height']}\")
except:
    pass
"
}

# Check if original is portrait but 720p is landscape (orientation mismatch)
check_orientation_mismatch() {
    local hash="$1"

    local orig_dim
    orig_dim=$(probe_dimensions "$MEDIA_BASE/$hash")
    if [[ -z "$orig_dim" ]]; then
        echo "PROBE_FAIL" # can't determine original dimensions
        return
    fi

    local orig_w="${orig_dim%%x*}"
    local orig_h="${orig_dim##*x}"

    # Only portrait originals can be affected
    if (( orig_h <= orig_w )); then
        echo "OK_LANDSCAPE"
        return
    fi

    # Original is portrait — check the 720p variant
    local v720_dim
    v720_dim=$(probe_dimensions "$MEDIA_BASE/$hash/720p.mp4")
    if [[ -z "$v720_dim" ]]; then
        echo "NO_720P" # 720p.mp4 doesn't exist or can't be probed
        return
    fi

    local v720_w="${v720_dim%%x*}"
    local v720_h="${v720_dim##*x}"

    if (( v720_w > v720_h )); then
        echo "MISMATCH:orig=${orig_dim},720p=${v720_dim}"
    else
        echo "OK_PORTRAIT"
    fi
}

# Delete HLS directory for a hash
delete_hls() {
    local hash="$1"
    gcloud storage rm "$GCS_BUCKET/$hash/hls/**" --project "$GCS_PROJECT" 2>/dev/null
}

# Process a single hash
process_hash() {
    local hash="$1"

    local result
    result=$(check_orientation_mismatch "$hash")

    case "$result" in
        MISMATCH:*)
            echo "$result" >&2
            if [[ "$DRY_RUN" == "true" ]]; then
                echo "DRY_RUN: would delete HLS for $hash ($result)" >&2
                echo "$hash" >> "$AFFECTED_FILE"
            else
                if delete_hls "$hash"; then
                    echo "DELETED HLS for $hash ($result)" >&2
                    echo "$hash" >> "$AFFECTED_FILE"
                else
                    echo "DELETE_FAIL $hash" >&2
                    echo "$hash" >> "$FAILED_FILE"
                    return
                fi
            fi
            ;;
        PROBE_FAIL)
            echo "$hash" >> "$FAILED_FILE"
            ;;
    esac

    echo "$hash" >> "$DONE_FILE"
}

# --- Single hash mode ---
if [[ -n "$SINGLE_HASH" ]]; then
    echo "Checking single hash: $SINGLE_HASH" >&2
    result=$(check_orientation_mismatch "$SINGLE_HASH")
    echo "$SINGLE_HASH: $result"
    if [[ "$result" == MISMATCH:* && "$DRY_RUN" == "false" ]]; then
        echo "Deleting HLS..." >&2
        delete_hls "$SINGLE_HASH"
        echo "Done. Next request for 720p.mp4 will trigger re-transcoding." >&2
    fi
    exit 0
fi

# --- Batch mode ---
DONE_SET=$(mktemp)
sort -u "$DONE_FILE" > "$DONE_SET"
done_count=$(wc -l < "$DONE_SET")
echo "Already checked: $done_count" >&2
echo "Streaming hashes from GCS (concurrency $CONCURRENCY)..." >&2
echo "" >&2

gcloud config configurations activate divine 2>/dev/null

total=0
start_time=$(date +%s)

# Stream hashes from GCS, skip done via awk hash set (O(1) per lookup, streaming output)
# stdbuf forces line-buffered output so awk receives hashes without waiting for 64KB buffer fills
stdbuf -oL gcloud storage ls "$GCS_BUCKET/**/stream_720p.ts" --project "$GCS_PROJECT" 2>/dev/null \
| stdbuf -oL sed -n 's|.*/\([a-f0-9]\{64\}\)/hls/stream_720p.ts|\1|p' \
| stdbuf -oL awk 'NR==FNR { done[$0]; next } !($0 in done)' "$DONE_SET" - \
| while IFS= read -r hash; do
    total=$((total + 1))

    process_hash "$hash" &

    while (( $(jobs -r | wc -l) >= CONCURRENCY )); do
        sleep 0.2
    done

    checked=$(wc -l < "$DONE_FILE")
    affected=$(wc -l < "$AFFECTED_FILE")
    elapsed=$(( $(date +%s) - start_time ))
    rate=0
    [[ "$elapsed" -gt 0 ]] && rate=$(( (checked - done_count) / elapsed ))
    printf "\r[backfill] queued:%d checked:%d affected:%d %d/s conc:%d    " \
        "$total" "$checked" "$affected" "$rate" "$(jobs -r | wc -l)" >&2
done

wait
rm -f "$DONE_SET"

gcloud config configurations activate default 2>/dev/null
sort -uo "$DONE_FILE" "$DONE_FILE"

elapsed=$(( $(date +%s) - start_time ))
final_checked=$(wc -l < "$DONE_FILE")
final_affected=$(wc -l < "$AFFECTED_FILE")
final_failed=$(wc -l < "$FAILED_FILE")
new_checked=$((final_checked - done_count))

echo "" >&2
echo "" >&2
echo "=== Orientation backfill complete ===" >&2
echo "Checked: $new_checked | Affected: $final_affected | Failed: $final_failed | Time: ${elapsed}s" >&2
if [[ -s "$AFFECTED_FILE" ]]; then
    echo "" >&2
    echo "Affected hashes saved to: $AFFECTED_FILE" >&2
    echo "Next requests to these videos will trigger correct re-transcoding." >&2
    echo "Consider purging CDN cache: fastly purge --service-id pOvEEWykEbpnylqst1KTrR --file $AFFECTED_FILE" >&2
fi
