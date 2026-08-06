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

# --- Autoscaling -----------------------------------------------------------
#
# This service streams uploads to GCS rather than buffering them, so it is
# I/O-bound and a high concurrency per instance is appropriate here -- unlike
# the CPU-bound transcoder, where the same setting prevents scale-out.
CONCURRENCY="${CONCURRENCY:-80}"
MAX_INSTANCES="${MAX_INSTANCES:-100}"

# This service sits in the synchronous upload path, so a cold start is visible
# to the user who is waiting on it. MIN_INSTANCES is billed continuously, so it
# defaults to scale-to-zero; raise it ahead of scheduled traffic events, where
# autoscaling reacts far slower than a burst arrives.
MIN_INSTANCES="${MIN_INSTANCES:-0}"

echo "Deploying ${SERVICE_NAME} from source..."
gcloud run deploy "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --source "${SCRIPT_DIR}" \
  --allow-unauthenticated \
  --service-account "${SERVICE_ACCOUNT}" \
  --cpu 1 \
  --memory 512Mi \
  --concurrency "${CONCURRENCY}" \
  --timeout 300 \
  --max-instances "${MAX_INSTANCES}" \
  --min-instances "${MIN_INSTANCES}" \
  --set-env-vars "CDN_BASE_URL=${CDN_BASE_URL},TRANSCODER_URL=${TRANSCODER_URL},TRANSCRIBER_URL=${TRANSCRIBER_URL},SENTRY_ENVIRONMENT=${SENTRY_ENVIRONMENT}" \
  --set-secrets "SENTRY_DSN=${SENTRY_SECRET}:latest"

echo "Done! Service URL:"
gcloud run services describe "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --format='value(status.url)'
