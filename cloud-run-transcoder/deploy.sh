#!/bin/bash
# ABOUTME: Deploy divine-transcoder to Cloud Run with GPU support
# ABOUTME: Requires L4 GPU quota to be approved in your GCP project

set -e

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="divine-transcoder"
IMAGE="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"

echo "Building and pushing Docker image..."
docker build --platform linux/amd64 -t "${IMAGE}" .
docker push "${IMAGE}"

echo "Deploying to Cloud Run with GPU..."
gcloud run deploy "${SERVICE_NAME}" \
  --image "${IMAGE}" \
  --region "${REGION}" \
  --gpu 1 \
  --gpu-type nvidia-l4 \
  --cpu 4 \
  --memory 16Gi \
  --concurrency 8 \
  --min-instances 1 \
  --max-instances 10 \
  --no-cpu-throttling \
  --set-env-vars "GCS_BUCKET=divine-blossom-media" \
  --set-env-vars "WEBHOOK_URL=https://media.divine.video/admin/transcode-status" \
  --set-env-vars "TRANSCRIPT_WEBHOOK_URL=https://media.divine.video/admin/transcript-status" \
  --set-env-vars "TRANSCRIPTION_API_URL=https://api.openai.com/v1/audio/transcriptions" \
  --set-env-vars "TRANSCRIPTION_MODEL=whisper-1" \
  --set-env-vars "TRANSCRIPTION_MAX_IN_FLIGHT=4" \
  --set-env-vars "TRANSCRIPTION_MAX_RETRIES=3" \
  --set-env-vars "TRANSCRIPTION_RETRY_BASE_MS=1000" \
  --set-env-vars "TRANSCRIPTION_RETRY_MAX_MS=15000" \
  --set-env-vars "TRANSCRIPTION_RETRY_TOTAL_MS=30000" \
  --set-secrets "WEBHOOK_SECRET=webhook_secret:latest,TRANSCRIPTION_API_KEY=openai_api_key:latest" \
  --allow-unauthenticated

echo "Done! Service URL:"
gcloud run services describe "${SERVICE_NAME}" --region "${REGION}" --format='value(status.url)'
