#!/bin/bash
# ABOUTME: Deploy blossom-upload-rust to Cloud Run from source with the live production runtime settings
# ABOUTME: Includes the transcoder wiring used by Fastly and binds the Sentry secret for worker-side reporting

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-blossom-upload-rust}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-149672065768-compute@developer.gserviceaccount.com}"
GCS_BUCKET="${GCS_BUCKET:-divine-blossom-media}"

PRODUCTION_PROJECT_ID="rich-compiler-479518-d2"
PRODUCTION_SERVICE_NAME="blossom-upload-rust"
PRODUCTION_GCS_BUCKET="divine-blossom-media"
if [ "${PROJECT_ID}" = "${PRODUCTION_PROJECT_ID}" ] && \
  [ "${SERVICE_NAME}" = "${PRODUCTION_SERVICE_NAME}" ] && \
  [ "${GCS_BUCKET}" != "${PRODUCTION_GCS_BUCKET}" ]; then
  echo "Refusing production deploy: GCS_BUCKET must be ${PRODUCTION_GCS_BUCKET} for ${PRODUCTION_SERVICE_NAME} in ${PRODUCTION_PROJECT_ID}." >&2
  echo "Unset the exported GCS_BUCKET and retry." >&2
  exit 1
fi

CDN_BASE_URL="${CDN_BASE_URL:-https://media.divine.video}"
SENTRY_ENVIRONMENT="${SENTRY_ENVIRONMENT:-production}"
SENTRY_SECRET="${SENTRY_SECRET:-sentry_dsn}"
WEBHOOK_SECRET="${WEBHOOK_SECRET:-webhook_secret}"

# --- Autoscaling -----------------------------------------------------------
#
# This service handles both streaming uploads and CPU-bound on-demand ffmpeg
# thumbnail extraction (bounded per instance by MAX_CONCURRENT_THUMBNAIL_EXTRACTIONS).
# Keeping per-instance concurrency at 16 with 2 vCPU / 1 GiB ensures Cloud Run
# scales out promptly under cold-cache thumbnail bursts instead of queuing 80
# requests behind a single instance's extraction semaphore.
CONCURRENCY="${CONCURRENCY:-16}"
MAX_INSTANCES="${MAX_INSTANCES:-100}"

# Keep one warm instance so synchronous PUT /upload and on-demand thumbnail
# requests avoid 15s cold-start stalls.
MIN_INSTANCES="${MIN_INSTANCES:-1}"

# Production CI inherits derivative routes and the legacy queue bindings.
# Explicit operator values still update those settings, including an empty value.
if [ "${PROJECT_ID}" != "${PRODUCTION_PROJECT_ID}" ] ||
   [ "${SERVICE_NAME}" != "${PRODUCTION_SERVICE_NAME}" ]; then
  TRANSCODER_URL="${TRANSCODER_URL:-https://divine-transcoder-149672065768.us-central1.run.app}"
  TRANSCRIBER_URL="${TRANSCRIBER_URL:-${TRANSCODER_URL}}"
fi
UPLOAD_ENV_VARS="GCS_BUCKET=${GCS_BUCKET},CDN_BASE_URL=${CDN_BASE_URL},SENTRY_ENVIRONMENT=${SENTRY_ENVIRONMENT}"
for binding in TRANSCODER_URL TRANSCRIBER_URL TRANSCODE_QUEUE TRANSCODE_QUEUE_INVOKER_SA; do
  if [ "${!binding+present}" = present ]; then
    UPLOAD_ENV_VARS+=",${binding}=${!binding}"
  fi
done

BUILD_CONTEXT="$(mktemp -d)"
trap 'rm -rf "${BUILD_CONTEXT}"' EXIT
bash "${SCRIPT_DIR}/prepare-build-context.sh" "${BUILD_CONTEXT}"

echo "Deploying ${SERVICE_NAME} from source..."
gcloud run deploy "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --source "${BUILD_CONTEXT}" \
  --allow-unauthenticated \
  --service-account "${SERVICE_ACCOUNT}" \
  --cpu 2 \
  --memory 1Gi \
  --concurrency "${CONCURRENCY}" \
  --timeout 300 \
  --max-instances "${MAX_INSTANCES}" \
  --min-instances "${MIN_INSTANCES}" \
  --update-env-vars "${UPLOAD_ENV_VARS}" \
  --update-secrets "SENTRY_DSN=${SENTRY_SECRET}:latest,WEBHOOK_SECRET=${WEBHOOK_SECRET}:latest"

echo "Done! Service URL:"
gcloud run services describe "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --format='value(status.url)'
