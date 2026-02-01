#!/bin/bash
# ABOUTME: Prioritized HLS backfill - native uploads first, then Vine imports
# ABOUTME: Fetches video hashes from relay API and triggers transcoding

set -e

RELAY_API="${RELAY_API:-https://relay.divine.video/api}"
TRANSCODER_URL="${TRANSCODER_URL:-https://divine-transcoder-149672065768.us-central1.run.app}"
BUCKET="${GCS_BUCKET:-divine-blossom-media}"
BATCH_SIZE=100
DELAY_BETWEEN_REQUESTS=1  # seconds between transcode triggers

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Extract sha256 hash from video_url (handles URLs with .mp4 extension)
extract_hash() {
    local url="$1"
    local filename=$(basename "$url")
    # Strip .mp4 extension if present
    echo "${filename%.mp4}"
}

# Check if URL is from media.divine.video (blossom storage)
is_blossom_url() {
    local url="$1"
    [[ "$url" == *"media.divine.video"* ]]
}

# Check if HLS already exists for a hash
hls_exists() {
    local hash="$1"
    gsutil -q stat "gs://${BUCKET}/${hash}/hls/master.m3u8" 2>/dev/null
}

# Trigger transcoding for a video
trigger_transcode() {
    local hash="$1"
    local owner="$2"

    response=$(curl -s -w "\n%{http_code}" -X POST "${TRANSCODER_URL}/transcode" \
        -H "Content-Type: application/json" \
        -d "{\"hash\": \"${hash}\", \"owner\": \"${owner}\"}" 2>/dev/null)

    http_code=$(echo "$response" | tail -n1)

    if [[ "$http_code" == "200" ]] || [[ "$http_code" == "202" ]]; then
        return 0
    else
        return 1
    fi
}

# Process videos from a specific platform (or all if empty)
process_videos() {
    local platform_filter="$1"
    local priority_label="$2"
    local offset=0
    local processed=0
    local skipped=0
    local failed=0

    log "=== Processing ${priority_label} videos ==="

    while true; do
        # Build API URL with optional platform filter
        if [[ -n "$platform_filter" ]]; then
            api_url="${RELAY_API}/videos?platform=${platform_filter}&limit=${BATCH_SIZE}&offset=${offset}"
        else
            # For native videos, we need to exclude vine
            # The API doesn't have a "not vine" filter, so we fetch all and filter
            api_url="${RELAY_API}/videos?limit=${BATCH_SIZE}&offset=${offset}"
        fi

        log "Fetching batch at offset ${offset}..."

        # Fetch batch of videos
        videos=$(curl -s "$api_url")
        count=$(echo "$videos" | jq 'length')

        if [[ "$count" -eq 0 ]]; then
            log "No more videos at offset ${offset}"
            break
        fi

        log "Processing ${count} videos..."

        # Process each video
        echo "$videos" | jq -r '.[] | [.video_url, .pubkey, .platform // "native"] | @tsv' | while IFS=$'\t' read -r video_url pubkey platform; do
            # Skip if not from media.divine.video (blossom storage)
            if ! is_blossom_url "$video_url"; then
                # Silently skip non-blossom URLs (stream.divine.video, cdn.divine.video, etc.)
                continue
            fi

            # Extract hash from URL
            hash=$(extract_hash "$video_url")

            # Skip if not valid hash
            if [[ ! "$hash" =~ ^[a-f0-9]{64}$ ]]; then
                log "  SKIP: Invalid hash format: $hash"
                ((skipped++)) || true
                continue
            fi

            # For non-Vine processing, skip Vine videos
            if [[ -z "$platform_filter" ]] && [[ "$platform" == "vine" ]]; then
                continue
            fi

            # Check if HLS already exists
            if hls_exists "$hash"; then
                log "  SKIP: $hash (HLS exists)"
                ((skipped++)) || true
                continue
            fi

            # Trigger transcoding
            log "  TRANSCODE: $hash ($platform)"
            if trigger_transcode "$hash" "$pubkey"; then
                ((processed++)) || true
            else
                log "  FAILED: $hash"
                ((failed++)) || true
            fi

            sleep "$DELAY_BETWEEN_REQUESTS"
        done

        offset=$((offset + BATCH_SIZE))

        # Safety limit - remove for full backfill
        if [[ "$offset" -ge 50000 ]]; then
            log "Reached safety limit at offset ${offset}"
            break
        fi
    done

    log "=== ${priority_label} complete: processed=${processed}, skipped=${skipped}, failed=${failed} ==="
}

main() {
    log "=========================================="
    log "HLS Backfill - Prioritized Processing"
    log "=========================================="
    log "Relay API: $RELAY_API"
    log "Transcoder: $TRANSCODER_URL"
    log "Bucket: $BUCKET"
    log ""

    # Phase 1: Process native (non-Vine) videos first
    log "PHASE 1: Native uploads (high priority)"
    process_videos "" "Native"

    log ""

    # Phase 2: Process Vine imports
    log "PHASE 2: Vine imports (low priority)"
    process_videos "vine" "Vine"

    log ""
    log "=========================================="
    log "Backfill complete!"
    log "=========================================="
}

# Run main function
main "$@"
