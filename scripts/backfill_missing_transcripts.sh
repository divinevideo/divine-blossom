#!/bin/bash
# ABOUTME: Backfill missing transcript VTTs through the Blossom admin API
# ABOUTME: Supports recent-scope dry runs and bounded enqueueing with pacing

set -euo pipefail

ADMIN_URL="${ADMIN_URL:-https://media.divine.video}"
SCOPE="${SCOPE:-recent}"
OFFSET=0
LIMIT=50
MAX_TRIGGERS="${MAX_TRIGGERS:-10}"
SLEEP_SECONDS="${SLEEP_SECONDS:-2}"
DRY_RUN=false
RESET_PROCESSING=false
FORCE_RETRANSCRIBE=false

usage() {
    cat <<'EOF'
Usage: backfill_missing_transcripts.sh [options]

Options:
  --dry-run               List candidate hashes without enqueueing transcription
  --limit N               Batch size per request (default: 50)
  --offset N              Starting offset within the selected scope (default: 0)
  --scope recent|users    Enumerate the recent index or the full user index (default: recent)
  --max-triggers N        Max enqueue operations per API request (default: 10)
  --sleep N               Delay in seconds between batches (default: 2)
  --reset-processing      Requeue blobs stuck in processing
  --force-retranscribe    Requeue blobs currently marked complete
  --admin-url URL         Blossom base URL (default: $ADMIN_URL)
  -h, --help              Show this help text

Authentication:
  Set either ADMIN_BEARER_TOKEN or ADMIN_COOKIE.

Examples:
  ADMIN_BEARER_TOKEN=... bash scripts/backfill_missing_transcripts.sh --dry-run --limit 20
  ADMIN_BEARER_TOKEN=... bash scripts/backfill_missing_transcripts.sh --limit 200 --sleep 2
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --limit)
            LIMIT="${2:?missing value for --limit}"
            shift 2
            ;;
        --offset)
            OFFSET="${2:?missing value for --offset}"
            shift 2
            ;;
        --scope)
            SCOPE="${2:?missing value for --scope}"
            shift 2
            ;;
        --max-triggers)
            MAX_TRIGGERS="${2:?missing value for --max-triggers}"
            shift 2
            ;;
        --sleep)
            SLEEP_SECONDS="${2:?missing value for --sleep}"
            shift 2
            ;;
        --reset-processing)
            RESET_PROCESSING=true
            shift
            ;;
        --force-retranscribe)
            FORCE_RETRANSCRIBE=true
            shift
            ;;
        --admin-url)
            ADMIN_URL="${2:?missing value for --admin-url}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ -z "${ADMIN_BEARER_TOKEN:-}" && -z "${ADMIN_COOKIE:-}" ]]; then
    echo "Set ADMIN_BEARER_TOKEN or ADMIN_COOKIE before running this script." >&2
    exit 1
fi

if [[ "$SCOPE" != "recent" && "$SCOPE" != "users" ]]; then
    echo "--scope must be 'recent' or 'users'." >&2
    exit 1
fi

request_backfill() {
    local offset="$1"
    local url="${ADMIN_URL}/admin/api/backfill-vtt?offset=${offset}&limit=${LIMIT}&scope=${SCOPE}&dry_run=${DRY_RUN}&max_triggers=${MAX_TRIGGERS}&reset_processing=${RESET_PROCESSING}&force_retranscribe=${FORCE_RETRANSCRIBE}"
    local curl_args=(
        -sS
        -X POST
        "$url"
    )

    if [[ -n "${ADMIN_BEARER_TOKEN:-}" ]]; then
        curl_args+=(-H "Authorization: Bearer ${ADMIN_BEARER_TOKEN}")
    else
        curl_args+=(-H "Cookie: session=${ADMIN_COOKIE}")
    fi

    curl "${curl_args[@]}"
}

parse_json_field() {
    local json="$1"
    local expression="$2"
    printf '%s' "$json" | python3 -c "import json,sys; data=json.load(sys.stdin); print(${expression})"
}

print_candidates() {
    local json="$1"
    printf '%s' "$json" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
candidates = data.get("results", {}).get("candidates", [])
if not candidates:
    print("  (no eligible hashes in this batch)")
    raise SystemExit(0)

for candidate in candidates:
    status = candidate.get("transcript_status") or "missing"
    retry_after = candidate.get("cooldown_remaining_secs")
    suffix = f" cooldown={retry_after}s" if retry_after is not None else ""
    print(
        f"  {candidate['sha256']} uploaded={candidate.get('uploaded')} "
        f"owner={candidate.get('owner')} status={status}{suffix}"
    )
'
}

total_triggered=0
total_duplicates=0
total_complete=0
total_cooling_down=0
total_errors=0

echo "=== Transcript backfill ==="
echo "Server: $ADMIN_URL"
echo "Scope: $SCOPE"
echo "Batch size: $LIMIT"
echo "Dry run: $DRY_RUN"
echo ""

while true; do
    echo "[$(date '+%H:%M:%S')] Processing scope=$SCOPE offset=$OFFSET..."
    response="$(request_backfill "$OFFSET")"

    has_more="$(parse_json_field "$response" "data['batch']['has_more']")"
    next_offset="$(parse_json_field "$response" "data['batch']['next_offset'] or ''")"
    processed_hashes="$(parse_json_field "$response" "data['batch'].get('processed_hashes', 0)")"
    triggered="$(parse_json_field "$response" "data['results']['triggered']")"
    already_processing="$(parse_json_field "$response" "data['results']['already_processing']")"
    already_complete="$(parse_json_field "$response" "data['results']['already_complete']")"
    cooling_down="$(parse_json_field "$response" "data['results'].get('cooling_down', 0)")"
    errors="$(parse_json_field "$response" "data['results']['errors']")"

    total_triggered=$((total_triggered + triggered))
    total_duplicates=$((total_duplicates + already_processing))
    total_complete=$((total_complete + already_complete))
    total_cooling_down=$((total_cooling_down + cooling_down))
    total_errors=$((total_errors + errors))

    echo "  Processed hashes: $processed_hashes"
    echo "  Triggered: $triggered | In progress: $already_processing | Already complete: $already_complete | Cooling down: $cooling_down | Errors: $errors"

    if [[ "$DRY_RUN" == "true" ]]; then
        echo "  Candidates:"
        print_candidates "$response"
    fi

    if [[ "$has_more" == "False" || -z "$next_offset" || "$DRY_RUN" == "true" ]]; then
        break
    fi

    OFFSET="$next_offset"
    sleep "$SLEEP_SECONDS"
done

echo ""
echo "=== Summary ==="
echo "Triggered: $total_triggered"
echo "Duplicates/in progress: $total_duplicates"
echo "Already complete: $total_complete"
echo "Cooling down: $total_cooling_down"
echo "Errors: $total_errors"
