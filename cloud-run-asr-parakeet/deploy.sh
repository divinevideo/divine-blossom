#!/bin/bash
# ABOUTME: Deploy divine-asr-parakeet (NeMo Parakeet TDT v3) to Cloud Run on an L4 GPU.
# ABOUTME: Service is private — only the transcoder service-account may invoke it.
#
# Cloud Run GPU prerequisites (one-time per project/region):
#   gcloud services enable run.googleapis.com aiplatform.googleapis.com
#   gcloud beta run regions list-gpu-types --region=us-central1
#
# Grant the transcoder runtime SA invoker on this service after first deploy:
#   gcloud run services add-iam-policy-binding divine-asr-parakeet \
#     --region us-central1 --project "$PROJECT_ID" \
#     --member="serviceAccount:$TRANSCODER_SA" --role=roles/run.invoker

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-divine-asr-parakeet}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-149672065768-compute@developer.gserviceaccount.com}"
GPU_TYPE="${GPU_TYPE:-nvidia-l4}"
PARAKEET_MODEL_NAME="${PARAKEET_MODEL_NAME:-nvidia/parakeet-tdt-0.6b-v3}"
IMAGE_TAG="${IMAGE_TAG:-$(git -C "${SCRIPT_DIR}" rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M%S)}"
IMAGE="gcr.io/${PROJECT_ID}/${SERVICE_NAME}:${IMAGE_TAG}"

echo "Building ${IMAGE} in Cloud Build (this also bakes ${PARAKEET_MODEL_NAME} into the image)..."
gcloud builds submit "${SCRIPT_DIR}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --tag "${IMAGE}" \
  --machine-type=e2-highcpu-32

echo "Deploying ${SERVICE_NAME} to Cloud Run (GPU=${GPU_TYPE})..."
gcloud beta run deploy "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --image "${IMAGE}" \
  --no-allow-unauthenticated \
  --service-account "${SERVICE_ACCOUNT}" \
  --cpu 4 \
  --memory 16Gi \
  --gpu 1 \
  --gpu-type "${GPU_TYPE}" \
  --concurrency 1 \
  --timeout 900 \
  --max-instances 10 \
  --no-cpu-throttling \
  --set-env-vars "PARAKEET_MODEL_NAME=${PARAKEET_MODEL_NAME}"

URL=$(gcloud run services describe "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" --region "${REGION}" --format='value(status.url)')

echo "Done. Service URL: ${URL}"
echo
echo "Next: wire the transcoder to call it ↓"
echo "  gcloud run services update divine-transcoder \\"
echo "    --project ${PROJECT_ID} --region ${REGION} \\"
echo "    --update-env-vars PARAKEET_ASR_URL=${URL},TRANSCRIPTION_PROVIDER=parakeet"
