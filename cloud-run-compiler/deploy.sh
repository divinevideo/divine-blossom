#!/bin/bash
# ABOUTME: Builds and deploys the private GPU compilation service to Cloud Run
# ABOUTME: Grants invocation only to the Cloudflare edge service account

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-divine-compiler}"
RUNTIME_SERVICE_ACCOUNT="${RUNTIME_SERVICE_ACCOUNT:-divine-compiler@${PROJECT_ID}.iam.gserviceaccount.com}"
EDGE_SERVICE_ACCOUNT="${EDGE_SERVICE_ACCOUNT:?Set EDGE_SERVICE_ACCOUNT to the Cloudflare Worker Google service account}"
OUTPUT_NSEC_SECRET="${OUTPUT_NSEC_SECRET:-compiler_output_nsec}"
IMAGE_TAG="${IMAGE_TAG:-$(git -C "${REPO_ROOT}" rev-parse --short HEAD)}"
IMAGE="gcr.io/${PROJECT_ID}/${SERVICE_NAME}:${IMAGE_TAG}"

PUBLIC_ORIGIN="${PUBLIC_ORIGIN:-https://compiler.divine.video}"
FIRESTORE_PROJECT="${FIRESTORE_PROJECT:-${PROJECT_ID}}"
FIRESTORE_COLLECTION="${FIRESTORE_COLLECTION:-compilation_jobs}"
SOURCE_RELAYS="${SOURCE_RELAYS:-wss://relay.divine.video}"
UPLOAD_SERVICE_URL="${UPLOAD_SERVICE_URL:-https://upload.divine.video}"
MEDIA_ORIGIN="${MEDIA_ORIGIN:-https://media.divine.video}"
ALLOWED_MEDIA_HOSTS="${ALLOWED_MEDIA_HOSTS:-media.divine.video}"
MAX_CONCURRENT_JOBS="${MAX_CONCURRENT_JOBS:-4}"
RATE_LIMIT_PER_HOUR="${RATE_LIMIT_PER_HOUR:-20}"

echo "Building ${IMAGE}..."
gcloud builds submit "${SCRIPT_DIR}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --tag "${IMAGE}"

echo "Deploying private GPU service ${SERVICE_NAME}..."
gcloud run deploy "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --image "${IMAGE}" \
  --no-allow-unauthenticated \
  --invoker-iam-check \
  --ingress all \
  --service-account "${RUNTIME_SERVICE_ACCOUNT}" \
  --execution-environment gen2 \
  --cpu 8 \
  --memory 32Gi \
  --gpu 1 \
  --gpu-type nvidia-l4 \
  --no-gpu-zonal-redundancy \
  --concurrency 80 \
  --timeout 300 \
  --min-instances 1 \
  --max-instances 2 \
  --no-cpu-throttling \
  --set-env-vars "^@@^PUBLIC_ORIGIN=${PUBLIC_ORIGIN}@@FIRESTORE_PROJECT=${FIRESTORE_PROJECT}@@FIRESTORE_COLLECTION=${FIRESTORE_COLLECTION}@@SOURCE_RELAYS=${SOURCE_RELAYS}@@UPLOAD_SERVICE_URL=${UPLOAD_SERVICE_URL}@@MEDIA_ORIGIN=${MEDIA_ORIGIN}@@ALLOWED_MEDIA_HOSTS=${ALLOWED_MEDIA_HOSTS}@@MAX_CONCURRENT_JOBS=${MAX_CONCURRENT_JOBS}@@RATE_LIMIT_PER_HOUR=${RATE_LIMIT_PER_HOUR}@@USE_GPU=true" \
  --set-secrets "COMPILER_OUTPUT_NSEC=${OUTPUT_NSEC_SECRET}:latest"

gcloud run services add-iam-policy-binding "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --member "serviceAccount:${EDGE_SERVICE_ACCOUNT}" \
  --role roles/run.invoker

echo "Private service URL:"
gcloud run services describe "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --format='value(status.url)'
