#!/bin/bash
# ABOUTME: Deploy divine-transcoder to Cloud Run with the current production runtime settings
# ABOUTME: Builds in Cloud Build, then deploys with webhook, transcription, and Sentry secrets wired
#
# To use Google Cloud Speech-to-Text V2 (Chirp 3):
#   TRANSCRIPTION_PROVIDER=google_stt_v2 \
#   GCP_PROJECT_ID=<your-project> \
#   ./deploy.sh
# Default GOOGLE_CLOUD_LOCATION is `us` (Chirp 3 is only served on
# `us`/`eu` multi-region endpoints; `global` does NOT serve `chirp_3`).
# Default GOOGLE_STT_MODEL is `chirp_3`.
#
# Cloud Run runtime SA needs roles/speech.client on the project. Grant once:
#   gcloud projects add-iam-policy-binding "$PROJECT_ID" \
#     --member="serviceAccount:$SERVICE_ACCOUNT" --role=roles/speech.client
# Also enable the API once per project:
#   gcloud services enable speech.googleapis.com --project "$PROJECT_ID"
#
# To canary with fallback to current provider:
#   TRANSCRIPTION_PROVIDER=google_stt_v2 \
#   TRANSCRIPTION_FALLBACK_PROVIDER=gemini \
#   ./deploy.sh
# Recommended for production canary: STT V2 sync recognize is capped at
# ~60 s of 16 kHz mono PCM audio; longer clips return 413 and require a
# fallback provider to deliver a VTT.

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
GOOGLE_CLOUD_LOCATION="${GOOGLE_CLOUD_LOCATION:-us}"
GOOGLE_STT_RECOGNIZER="${GOOGLE_STT_RECOGNIZER:-_}"
GOOGLE_STT_MODEL="${GOOGLE_STT_MODEL:-chirp_3}"
# Multi-language detection default. Chirp 3's `languageCodes` accepts a
# comma list and the model picks per-clip. Without this, every transcription
# is forced to English and non-English audio is mis-transcribed. Override
# at deploy time if a stricter single-language policy is wanted (e.g.
# GOOGLE_STT_LANGUAGE_CODES=en-US for English-only).
GOOGLE_STT_LANGUAGE_CODES="${GOOGLE_STT_LANGUAGE_CODES:-en-US,es-US,es-ES,pt-BR,fr-FR,de-DE,it-IT,ja-JP,ko-KR,zh-CN}"
TRANSCRIPTION_FALLBACK_PROVIDER="${TRANSCRIPTION_FALLBACK_PROVIDER:-}"
TRANSCRIPTION_FALLBACK_ON_PROVIDER_ERROR="${TRANSCRIPTION_FALLBACK_ON_PROVIDER_ERROR:-true}"
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
  --set-env-vars "^@@^GCS_BUCKET=${GCS_BUCKET}@@WEBHOOK_URL=${WEBHOOK_URL}@@TRANSCRIPT_WEBHOOK_URL=${TRANSCRIPT_WEBHOOK_URL}@@TRANSCRIPTION_PROVIDER=${TRANSCRIPTION_PROVIDER}@@TRANSCRIPTION_MODEL=${TRANSCRIPTION_MODEL}@@TRANSCRIPTION_API_URL=${TRANSCRIPTION_API_URL}@@USE_GPU=${USE_GPU}@@SENTRY_ENVIRONMENT=${SENTRY_ENVIRONMENT}@@GOOGLE_CLOUD_LOCATION=${GOOGLE_CLOUD_LOCATION}@@GOOGLE_STT_RECOGNIZER=${GOOGLE_STT_RECOGNIZER}@@GOOGLE_STT_MODEL=${GOOGLE_STT_MODEL}@@GOOGLE_STT_LANGUAGE_CODES=${GOOGLE_STT_LANGUAGE_CODES}@@TRANSCRIPTION_FALLBACK_PROVIDER=${TRANSCRIPTION_FALLBACK_PROVIDER}@@TRANSCRIPTION_FALLBACK_ON_PROVIDER_ERROR=${TRANSCRIPTION_FALLBACK_ON_PROVIDER_ERROR}" \
  --set-secrets "WEBHOOK_SECRET=webhook_secret:latest,TRANSCRIPTION_API_KEY=openai_api_key:latest,SENTRY_DSN=${SENTRY_SECRET}:latest"

echo "Done! Service URL:"
gcloud run services describe "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --format='value(status.url)'
