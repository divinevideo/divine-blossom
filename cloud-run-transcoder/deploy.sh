#!/bin/bash
# ABOUTME: Deploy divine-transcoder to Cloud Run with GPU support
# ABOUTME: Requires L4 GPU quota to be approved in your GCP project
# ABOUTME: Uses --update-env-vars to avoid wiping env vars set outside this script

set -e

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="divine-transcoder"
REGISTRY="${REGISTRY:-${REGION}-docker.pkg.dev/${PROJECT_ID}/cloud-run-source-deploy}"
IMAGE="${REGISTRY}/${SERVICE_NAME}"
MEMORY="${MEMORY:-16Gi}"
CONCURRENCY="${CONCURRENCY:-8}"

echo "Building and pushing Docker image..."
docker build --platform linux/amd64 -t "${IMAGE}" .
docker push "${IMAGE}"

echo "Deploying to Cloud Run with GPU..."
gcloud run deploy "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --image "${IMAGE}" \
  --region "${REGION}" \
  --gpu 1 \
  --gpu-type nvidia-l4 \
  --cpu 4 \
  --memory "${MEMORY}" \
  --concurrency "${CONCURRENCY}" \
  --min-instances 1 \
  --max-instances 10 \
  --no-cpu-throttling \
  --update-env-vars "GCS_BUCKET=divine-blossom-media" \
  --update-env-vars "USE_GPU=true" \
  --update-env-vars "WEBHOOK_URL=https://media.divine.video/admin/transcode-status" \
  --update-env-vars "TRANSCRIPT_WEBHOOK_URL=https://media.divine.video/admin/transcript-status" \
  --update-env-vars "TRANSCRIPTION_API_URL=https://api.openai.com/v1/audio/transcriptions" \
  --update-env-vars "TRANSCRIPTION_MODEL=gpt-4o-mini-transcribe" \
  --update-env-vars "TRANSCRIPTION_MAX_IN_FLIGHT=4" \
  --update-env-vars "TRANSCRIPTION_MAX_RETRIES=3" \
  --update-env-vars "TRANSCRIPTION_RETRY_BASE_MS=1000" \
  --update-env-vars "TRANSCRIPTION_RETRY_MAX_MS=15000" \
  --update-env-vars "TRANSCRIPTION_RETRY_TOTAL_MS=30000" \
  --set-secrets "WEBHOOK_SECRET=webhook_secret:latest,TRANSCRIPTION_API_KEY=openai_api_key:latest" \
  --allow-unauthenticated

echo "Done! Service URL:"
gcloud run services describe "${SERVICE_NAME}" --project "${PROJECT_ID}" --region "${REGION}" --format='value(status.url)'
