#!/bin/bash
# ABOUTME: Deploy divine-transcoder to Cloud Run with the current production runtime settings
# ABOUTME: Builds in Cloud Build, then deploys with webhook, transcription, and Sentry secrets wired

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-divine-transcoder}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-149672065768-compute@developer.gserviceaccount.com}"
IMAGE_TAG="${IMAGE_TAG:-$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M%S)}"
IMAGE="gcr.io/${PROJECT_ID}/${SERVICE_NAME}:${IMAGE_TAG}"

GCS_BUCKET="${GCS_BUCKET:-divine-blossom-media}"
WEBHOOK_URL="${WEBHOOK_URL:-https://media.divine.video/admin/transcode-status}"
TRANSCRIPT_WEBHOOK_URL="${TRANSCRIPT_WEBHOOK_URL:-https://media.divine.video/admin/transcript-status}"
TRANSCRIPTION_PROVIDER="${TRANSCRIPTION_PROVIDER:-gemini}"
TRANSCRIPTION_MODEL="${TRANSCRIPTION_MODEL:-gemini-2.5-pro}"
# OpenAI fallback (only used when TRANSCRIPTION_PROVIDER=openai)
TRANSCRIPTION_API_URL="${TRANSCRIPTION_API_URL:-https://api.openai.com/v1/audio/transcriptions}"
USE_GPU="${USE_GPU:-false}"
SENTRY_ENVIRONMENT="${SENTRY_ENVIRONMENT:-production}"
SENTRY_SECRET="${SENTRY_SECRET:-sentry_dsn}"

echo "Building ${IMAGE} in Cloud Build..."
gcloud builds submit "${SCRIPT_DIR}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --tag "${IMAGE}"

echo "Deploying ${SERVICE_NAME} to Cloud Run..."
gcloud run deploy "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --image "${IMAGE}" \
  --allow-unauthenticated \
  --service-account "${SERVICE_ACCOUNT}" \
  --cpu 4 \
  --memory 8Gi \
  --concurrency 320 \
  --timeout 900 \
  --max-instances 10 \
  --no-cpu-throttling \
  --set-env-vars "GCS_BUCKET=${GCS_BUCKET},WEBHOOK_URL=${WEBHOOK_URL},TRANSCRIPT_WEBHOOK_URL=${TRANSCRIPT_WEBHOOK_URL},TRANSCRIPTION_PROVIDER=${TRANSCRIPTION_PROVIDER},TRANSCRIPTION_MODEL=${TRANSCRIPTION_MODEL},TRANSCRIPTION_API_URL=${TRANSCRIPTION_API_URL},USE_GPU=${USE_GPU},SENTRY_ENVIRONMENT=${SENTRY_ENVIRONMENT}" \
  --set-secrets "WEBHOOK_SECRET=webhook_secret:latest,TRANSCRIPTION_API_KEY=openai_api_key:latest,SENTRY_DSN=${SENTRY_SECRET}:latest"

echo "Done! Service URL:"
gcloud run services describe "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --format='value(status.url)'
