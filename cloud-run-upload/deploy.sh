#!/bin/bash
# ABOUTME: Deploy blossom-upload-rust to Cloud Run from source with the live production runtime settings
# ABOUTME: Includes the transcoder wiring used by Fastly and binds the Sentry secret for worker-side reporting

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-blossom-upload-rust}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-149672065768-compute@developer.gserviceaccount.com}"

CDN_BASE_URL="${CDN_BASE_URL:-https://media.divine.video}"
TRANSCODER_URL="${TRANSCODER_URL:-https://divine-transcoder-149672065768.us-central1.run.app}"
TRANSCRIBER_URL="${TRANSCRIBER_URL:-${TRANSCODER_URL}}"
SENTRY_ENVIRONMENT="${SENTRY_ENVIRONMENT:-production}"
SENTRY_SECRET="${SENTRY_SECRET:-sentry_dsn}"

echo "Deploying ${SERVICE_NAME} from source..."
gcloud run deploy "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --source "${SCRIPT_DIR}" \
  --allow-unauthenticated \
  --service-account "${SERVICE_ACCOUNT}" \
  --cpu 1 \
  --memory 512Mi \
  --concurrency 80 \
  --timeout 300 \
  --max-instances 100 \
  --set-env-vars "CDN_BASE_URL=${CDN_BASE_URL},TRANSCODER_URL=${TRANSCODER_URL},TRANSCRIBER_URL=${TRANSCRIBER_URL},SENTRY_ENVIRONMENT=${SENTRY_ENVIRONMENT}" \
  --set-secrets "SENTRY_DSN=${SENTRY_SECRET}:latest"

echo "Done! Service URL:"
gcloud run services describe "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --format='value(status.url)'
