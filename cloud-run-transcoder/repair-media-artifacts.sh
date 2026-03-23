#!/bin/bash
# ABOUTME: Repair bad transcript and thumbnail artifacts for specific media hashes
# ABOUTME: Forces retranscription via the public subtitles API and regenerates thumbnails via Cloud Run upload

set -euo pipefail

MEDIA_URL="${MEDIA_URL:-https://media.divine.video}"
UPLOAD_URL="${UPLOAD_URL:-https://blossom-upload-rust-149672065768.us-central1.run.app}"
BUCKET="${BUCKET:-divine-blossom-media}"
WAIT_FOR_TRANSCRIPT="${WAIT_FOR_TRANSCRIPT:-false}"
DELETE_VTT_FIRST="${DELETE_VTT_FIRST:-false}"
POLL_INTERVAL="${POLL_INTERVAL:-5}"
POLL_ATTEMPTS="${POLL_ATTEMPTS:-24}"

usage() {
    cat <<'EOF'
Usage:
  repair-media-artifacts.sh [options] <hash> [<hash> ...]
  repair-media-artifacts.sh [options] --hash-file hashes.txt

Options:
  --transcript-only        Only repair transcripts
  --thumbnail-only         Only repair thumbnails
  --wait                   Poll subtitle jobs until ready/failed
  --delete-vtt-first       Delete the existing VTT object before forcing retranscription
  --hash-file PATH         Read one SHA-256 hash per line from PATH
  -h, --help               Show this help

Env:
  MEDIA_URL                Public Blossom base URL
  UPLOAD_URL               Cloud Run upload service base URL
  BUCKET                   GCS bucket containing blobs
  WAIT_FOR_TRANSCRIPT      true/false
  DELETE_VTT_FIRST         true/false
  POLL_INTERVAL            Seconds between subtitle job polls
  POLL_ATTEMPTS            Max subtitle job polls

Examples:
  repair-media-artifacts.sh 5ea8...  ae09...
  repair-media-artifacts.sh --thumbnail-only --hash-file bad-thumbnails.txt
  WAIT_FOR_TRANSCRIPT=true repair-media-artifacts.sh --transcript-only 5ea8...
EOF
}

repair_transcript=true
repair_thumbnail=true
declare -a hashes

while [[ $# -gt 0 ]]; do
    case "$1" in
        --transcript-only)
            repair_transcript=true
            repair_thumbnail=false
            shift
            ;;
        --thumbnail-only)
            repair_transcript=false
            repair_thumbnail=true
            shift
            ;;
        --wait)
            WAIT_FOR_TRANSCRIPT=true
            shift
            ;;
        --delete-vtt-first)
            DELETE_VTT_FIRST=true
            shift
            ;;
        --hash-file)
            if [[ $# -lt 2 ]]; then
                echo "ERROR: --hash-file requires a path" >&2
                exit 1
            fi
            while IFS= read -r line; do
                line="${line%%#*}"
                line="$(echo "$line" | tr '[:upper:]' '[:lower:]' | xargs)"
                [[ -z "$line" ]] && continue
                hashes+=("$line")
            done < "$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            hashes+=("$(echo "$1" | tr '[:upper:]' '[:lower:]')")
            shift
            ;;
    esac
done

if [[ ${#hashes[@]} -eq 0 ]]; then
    usage >&2
    exit 1
fi

for hash in "${hashes[@]}"; do
    if [[ ! "$hash" =~ ^[0-9a-f]{64}$ ]]; then
        echo "ERROR: invalid hash: $hash" >&2
        exit 1
    fi
done

if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl is required" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required" >&2
    exit 1
fi

if [[ "$repair_thumbnail" == "true" || "$DELETE_VTT_FIRST" == "true" ]]; then
    if ! command -v gsutil >/dev/null 2>&1; then
        echo "ERROR: gsutil is required for thumbnail repair and --delete-vtt-first" >&2
        exit 1
    fi
fi

poll_subtitle_job() {
    local job_id="$1"
    local hash="$2"
    local attempt=1

    while [[ $attempt -le $POLL_ATTEMPTS ]]; do
        local response
        response="$(curl -fsS "${MEDIA_URL}/v1/subtitles/jobs/${job_id}")"
        local status
        status="$(printf '%s' "$response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')"
        echo "  transcript job ${job_id}: ${status} (attempt ${attempt}/${POLL_ATTEMPTS})"

        if [[ "$status" == "ready" ]]; then
            curl -fsS -H "Cache-Control: no-cache" -o /dev/null "${MEDIA_URL}/${hash}.vtt"
            return 0
        fi
        if [[ "$status" == "failed" ]]; then
            printf '%s\n' "$response"
            return 1
        fi

        attempt=$((attempt + 1))
        sleep "$POLL_INTERVAL"
    done

    echo "  transcript job ${job_id}: timed out waiting for completion" >&2
    return 1
}

force_retranscribe() {
    local hash="$1"

    if [[ "$DELETE_VTT_FIRST" == "true" ]]; then
        gsutil -q rm "gs://${BUCKET}/${hash}/vtt/main.vtt" 2>/dev/null || true
    fi

    local payload
    payload="$(printf '{"video_sha256":"%s","force":true}' "$hash")"
    local response
    response="$(curl -fsS \
        -H "Content-Type: application/json" \
        -X POST \
        -d "$payload" \
        "${MEDIA_URL}/v1/subtitles/jobs")"

    local job_id
    local status
    job_id="$(printf '%s' "$response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["job_id"])')"
    status="$(printf '%s' "$response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')"
    echo "  transcript job ${job_id}: ${status}"

    if [[ "$WAIT_FOR_TRANSCRIPT" == "true" ]]; then
        poll_subtitle_job "$job_id" "$hash"
    fi
}

regenerate_thumbnail() {
    local hash="$1"

    gsutil -q rm "gs://${BUCKET}/${hash}.jpg" 2>/dev/null || true
    curl -fsS -o /dev/null "${UPLOAD_URL}/thumbnail/${hash}"
    curl -fsS -H "Cache-Control: no-cache" -o /dev/null "${MEDIA_URL}/${hash}.jpg"
    echo "  thumbnail regenerated"
}

echo "Repair target count: ${#hashes[@]}"
echo "Transcript repair: ${repair_transcript}"
echo "Thumbnail repair: ${repair_thumbnail}"
echo "Wait for transcript completion: ${WAIT_FOR_TRANSCRIPT}"
echo ""

for hash in "${hashes[@]}"; do
    echo "=== ${hash} ==="

    if [[ "$repair_transcript" == "true" ]]; then
        force_retranscribe "$hash"
    fi

    if [[ "$repair_thumbnail" == "true" ]]; then
        regenerate_thumbnail "$hash"
    fi

    echo ""
done

echo "Done."
