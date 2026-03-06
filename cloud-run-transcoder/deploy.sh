#!/bin/bash
# ABOUTME: Deploy divine-transcoder to Cloud Run using the current production CPU shape by default
# ABOUTME: GPU deployment remains opt-in via USE_GPU=true for projects with approved GPU quota

set -euo pipefail

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-divine-transcoder}"
IMAGE_REPO="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
IMAGE="${IMAGE_REPO}:${IMAGE_TAG}"

USE_GPU="${USE_GPU:-false}"
CPU="${CPU:-4}"
MEMORY="${MEMORY:-}"
MAX_INSTANCES="${MAX_INSTANCES:-10}"
CONCURRENCY="${CONCURRENCY:-320}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-900}"
MIN_INSTANCES="${MIN_INSTANCES:-}"
GPU_COUNT="${GPU_COUNT:-1}"
GPU_TYPE="${GPU_TYPE:-nvidia-l4}"

if [[ "${USE_GPU}" == "true" ]]; then
  MEMORY="${MEMORY:-16Gi}"
  MIN_INSTANCES="${MIN_INSTANCES:-1}"
else
  MEMORY="${MEMORY:-8Gi}"
fi

echo "Building and pushing Docker image ${IMAGE}..."
docker build --platform linux/amd64 -t "${IMAGE}" .
docker push "${IMAGE}"

deploy_args=(
  --image "${IMAGE}"
  --region "${REGION}"
  --cpu "${CPU}"
  --memory "${MEMORY}"
  --max-instances "${MAX_INSTANCES}"
  --concurrency "${CONCURRENCY}"
  --timeout "${TIMEOUT_SECONDS}"
  --no-cpu-throttling
  --set-env-vars "GCS_BUCKET=divine-blossom-media,WEBHOOK_URL=https://media.divine.video/admin/transcode-status,TRANSCRIPT_WEBHOOK_URL=https://media.divine.video/admin/transcript-status,TRANSCRIPTION_API_URL=https://api.openai.com/v1/audio/transcriptions,TRANSCRIPTION_MODEL=whisper-1"
  --set-secrets "WEBHOOK_SECRET=webhook_secret:latest,TRANSCRIPTION_API_KEY=openai_api_key:latest"
  --allow-unauthenticated
)

if [[ -n "${MIN_INSTANCES}" ]]; then
  deploy_args+=(--min-instances "${MIN_INSTANCES}")
fi

if [[ "${USE_GPU}" == "true" ]]; then
  deploy_args+=(--gpu "${GPU_COUNT}" --gpu-type "${GPU_TYPE}")
  echo "Deploying to Cloud Run with GPU support..."
else
  echo "Deploying to Cloud Run with CPU defaults..."
fi

gcloud run deploy "${SERVICE_NAME}" "${deploy_args[@]}"

echo "Done. Service URL:"
gcloud run services describe "${SERVICE_NAME}" --region "${REGION}" --format='value(status.url)'
