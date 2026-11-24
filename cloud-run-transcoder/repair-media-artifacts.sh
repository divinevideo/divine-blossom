#!/bin/bash
# ABOUTME: Repair bad transcript and thumbnail artifacts for specific media hashes
# ABOUTME: Forces retranscription via the public subtitles API and regenerates thumbnails via Cloud Run upload

set -euo pipefail

MEDIA_URL="${MEDIA_URL:-https://media.divine.video}"
DEFAULT_UPLOAD_URL="https://blossom-upload-rust-149672065768.us-central1.run.app"
UPLOAD_URL="${UPLOAD_URL:-$DEFAULT_UPLOAD_URL}"
UPLOAD_URL="${UPLOAD_URL%/}"
ALLOW_NON_DEFAULT_UPLOAD_URL="${ALLOW_NON_DEFAULT_UPLOAD_URL:-false}"
# Token the upload service can require on /thumbnail (divine-upload-server#52).
THUMBNAIL_SERVICE_TOKEN="$(printf '%s' "${THUMBNAIL_SERVICE_TOKEN:-}" | tr -d '[:space:]')"
BUCKET="${BUCKET:-divine-blossom-media}"
WAIT_FOR_TRANSCRIPT="${WAIT_FOR_TRANSCRIPT:-false}"
DELETE_VTT_FIRST="${DELETE_VTT_FIRST:-false}"
AUTHENTICATED_REPAIR_REQUESTED=false
if [[ "${TRANSCODER_URL+x}" == "x" || "${TRANSCODE_REPAIR_SECRET_FILE+x}" == "x" ]]; then
    AUTHENTICATED_REPAIR_REQUESTED=true
fi
TRANSCODER_URL="${TRANSCODER_URL:-}"
TRANSCODE_REPAIR_SECRET_FILE="${TRANSCODE_REPAIR_SECRET_FILE:-}"
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
  ALLOW_NON_DEFAULT_UPLOAD_URL true/false; allow non-default HTTPS upload host (or local loopback HTTP)
  THUMBNAIL_SERVICE_TOKEN  Upload service thumbnail token, sent on /thumbnail when set
  BUCKET                   GCS bucket containing blobs
  WAIT_FOR_TRANSCRIPT      true/false
  DELETE_VTT_FIRST         true/false
  TRANSCODER_URL           Approved worker base URL for authenticated repair
  TRANSCODE_REPAIR_SECRET_FILE Existing repair credential file (never its value)
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

if [[ "$repair_transcript" == "true" && "$AUTHENTICATED_REPAIR_REQUESTED" == "true" && ( -z "$TRANSCODER_URL" || -z "$TRANSCODE_REPAIR_SECRET_FILE" ) ]]; then
    echo "ERROR: authenticated repair requires worker URL and existing credential file" >&2
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl is required" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required" >&2
    exit 1
fi

if [[ "$repair_thumbnail" == "true" || ( "$DELETE_VTT_FIRST" == "true" && -z "$TRANSCODER_URL" ) ]]; then
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

    if [[ "$AUTHENTICATED_REPAIR_REQUESTED" == "true" ]]; then
        if [[ -z "$TRANSCODER_URL" || -z "$TRANSCODE_REPAIR_SECRET_FILE" ]]; then
            echo "ERROR: authenticated repair requires worker URL and existing credential file" >&2
            return 1
        fi
        python3 "$(dirname "$0")/repair_recent_bad_vtts.py" --repair-hash "$hash" \
            --transcoder-url "$TRANSCODER_URL" --repair-secret-file "$TRANSCODE_REPAIR_SECRET_FILE" --timeout 900
        return
    fi

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

validate_upload_url() {
    local has_token="false"
    if [[ -n "$THUMBNAIL_SERVICE_TOKEN" ]]; then
        has_token="true"
    fi
    python3 - "$UPLOAD_URL" "$DEFAULT_UPLOAD_URL" "$ALLOW_NON_DEFAULT_UPLOAD_URL" "$has_token" <<'PY'
import sys
from urllib import parse

url, default_url, allow_non_default, has_token = (
    sys.argv[1].rstrip("/"),
    sys.argv[2].rstrip("/"),
    sys.argv[3] == "true",
    sys.argv[4] == "true",
)
parsed = parse.urlsplit(url)
local = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
scheme_ok = parsed.scheme == "https" or (
    parsed.scheme == "http" and local and allow_non_default
)
if (
    not scheme_ok
    or not parsed.hostname
    or parsed.username is not None
    or parsed.password is not None
    or parsed.query
    or parsed.fragment
    or parsed.path not in ("", "/")
):
    print(
        "ERROR: UPLOAD_URL must be a bare HTTPS origin (local HTTP requires ALLOW_NON_DEFAULT_UPLOAD_URL=true)",
        file=sys.stderr,
    )
    raise SystemExit(1)
if has_token and url != default_url and not allow_non_default:
    host = parsed.netloc or url
    print(
        f"ERROR: refusing to send THUMBNAIL_SERVICE_TOKEN to non-default upload host {host} without ALLOW_NON_DEFAULT_UPLOAD_URL=true",
        file=sys.stderr,
    )
    raise SystemExit(1)
PY
}

preflight_thumbnail_auth() {
    local status
    if [[ -n "$THUMBNAIL_SERVICE_TOKEN" ]]; then
        status="$(printf 'X-Divine-Thumbnail-Token: %s\n' "$THUMBNAIL_SERVICE_TOKEN" |
            curl -sS -H @- -o /dev/null -w '%{http_code}' "${UPLOAD_URL}/thumbnail/auth-check")"
    else
        status="$(curl -sS -o /dev/null -w '%{http_code}' "${UPLOAD_URL}/thumbnail/auth-check")"
    fi
    if [[ "$status" != "400" ]]; then
        echo "ERROR: upload service /thumbnail preflight returned HTTP ${status} (expected 400); aborting before deleting thumbnails" >&2
        exit 1
    fi
}

regenerate_thumbnail() {
    local hash="$1"

    gsutil -q rm "gs://${BUCKET}/${hash}.jpg" 2>/dev/null || true
    if [[ -n "$THUMBNAIL_SERVICE_TOKEN" ]]; then
        # Headers on stdin keep the token out of the process list.
        printf 'X-Divine-Thumbnail-Token: %s\n' "$THUMBNAIL_SERVICE_TOKEN" |
            curl -fsS -H @- -o /dev/null "${UPLOAD_URL}/thumbnail/${hash}"
    else
        curl -fsS -o /dev/null "${UPLOAD_URL}/thumbnail/${hash}"
    fi
    curl -fsS -H "Cache-Control: no-cache" -o /dev/null "${MEDIA_URL}/${hash}.jpg"
    echo "  thumbnail regenerated"
}

if [[ "$repair_thumbnail" == "true" ]]; then
    validate_upload_url
    if [[ -z "$THUMBNAIL_SERVICE_TOKEN" ]]; then
        echo "WARNING: THUMBNAIL_SERVICE_TOKEN is not set; once the upload service requires it, thumbnail regeneration fails with 404" >&2
    elif [[ "${UPLOAD_URL%/}" != "$DEFAULT_UPLOAD_URL" ]]; then
        upload_host="${UPLOAD_URL#*://}"
        echo "WARNING: sending THUMBNAIL_SERVICE_TOKEN to a non-default upload host: ${upload_host%%/*}" >&2
    fi
    preflight_thumbnail_auth
fi

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
