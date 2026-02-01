#!/bin/bash
# ABOUTME: Backfill HLS transcoding for existing videos in GCS
# ABOUTME: Lists all video files and triggers transcoding for each

set -e

BUCKET="${GCS_BUCKET:-divine-blossom-media}"
TRANSCODER_URL="${TRANSCODER_URL:-https://divine-transcoder-149672065768.us-central1.run.app}"
OWNER="${DEFAULT_OWNER:-system}"  # Default owner for backfill

echo "=== HLS Backfill Script ==="
echo "Bucket: $BUCKET"
echo "Transcoder: $TRANSCODER_URL"
echo ""

# List all top-level files (videos are stored as {sha256} without extension)
# Skip directories (thumbnails, hls folders)
echo "Listing videos in GCS..."
gsutil ls "gs://${BUCKET}/" | while read -r line; do
    # Extract just the filename (hash)
    hash=$(basename "$line")

    # Skip if it's a directory or has an extension
    if [[ "$hash" == */ ]] || [[ "$hash" == *.* ]]; then
        continue
    fi

    # Skip if not a valid 64-char hex hash
    if [[ ! "$hash" =~ ^[a-f0-9]{64}$ ]]; then
        continue
    fi

    # Check if HLS already exists
    if gsutil -q stat "gs://${BUCKET}/${hash}/hls/master.m3u8" 2>/dev/null; then
        echo "SKIP: $hash (HLS exists)"
        continue
    fi

    # Check if it's a video by content type
    content_type=$(gsutil stat "gs://${BUCKET}/${hash}" 2>/dev/null | grep "Content-Type:" | awk '{print $2}')

    if [[ "$content_type" != video/* ]]; then
        echo "SKIP: $hash (not video: $content_type)"
        continue
    fi

    echo "TRANSCODE: $hash ($content_type)"

    # Trigger transcoding
    response=$(curl -s -w "\n%{http_code}" -X POST "${TRANSCODER_URL}/transcode" \
        -H "Content-Type: application/json" \
        -d "{\"hash\": \"${hash}\", \"owner\": \"${OWNER}\"}")

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [[ "$http_code" == "200" ]] || [[ "$http_code" == "202" ]]; then
        echo "  -> Triggered (HTTP $http_code)"
    else
        echo "  -> FAILED (HTTP $http_code): $body"
    fi

    # Small delay to avoid overwhelming the transcoder
    sleep 1
done

echo ""
echo "=== Backfill complete ==="
