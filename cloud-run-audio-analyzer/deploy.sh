#!/bin/bash
# ABOUTME: Deploy divine-audio-analyzer (PANNs CNN14 AudioSet tagger) to Cloud Run on CPU.
# ABOUTME: Service is private — grant run.invoker to whichever service calls it.
#
# The script owns this service's whole configuration. max-instances is the
# cost ceiling: one instance busy for a whole month costs about $76 at
# 1 vCPU / 2 GiB and handles roughly 8 million sounds.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-divine-audio-analyzer}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-149672065768-compute@developer.gserviceaccount.com}"
MAX_INSTANCES="${MAX_INSTANCES:-2}"
IMAGE_TAG="${IMAGE_TAG:-$(git -C "${SCRIPT_DIR}" rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M%S)}"
IMAGE="gcr.io/${PROJECT_ID}/${SERVICE_NAME}:${IMAGE_TAG}"

echo "Building ${IMAGE} in Cloud Build (this also bakes the PANNs checkpoint into the image)..."
gcloud builds submit "${SCRIPT_DIR}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --tag "${IMAGE}" \
  --machine-type=e2-highcpu-8

echo "Deploying ${SERVICE_NAME} to Cloud Run (CPU, max ${MAX_INSTANCES} instances)..."
gcloud run deploy "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --image "${IMAGE}" \
  --no-allow-unauthenticated \
  --service-account "${SERVICE_ACCOUNT}" \
  --cpu 1 \
  --memory 2Gi \
  --cpu-boost \
  --concurrency 1 \
  --timeout 120 \
  --min-instances 0 \
  --max-instances "${MAX_INSTANCES}"

URL=$(gcloud run services describe "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" --region "${REGION}" --format='value(status.url)')

echo "Done. Service URL: ${URL}"
echo
echo "Next: grant the calling service's runtime SA invoker on this service ↓"
echo "  gcloud run services add-iam-policy-binding ${SERVICE_NAME} \\"
echo "    --project ${PROJECT_ID} --region ${REGION} \\"
echo "    --member=serviceAccount:<caller-sa> --role=roles/run.invoker"
