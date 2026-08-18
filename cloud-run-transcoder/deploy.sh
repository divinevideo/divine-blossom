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
#   gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" \
#     --member="serviceAccount:$SERVICE_ACCOUNT" --role=roles/speech.client
# Also enable the API once per project:
#   gcloud services enable speech.googleapis.com --project "$GCP_PROJECT_ID"
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
GCP_PROJECT_ID="${GCP_PROJECT_ID:-${PROJECT_ID}}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SERVICE_NAME:-divine-transcoder}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-}"
if [ -z "${SERVICE_ACCOUNT}" ]; then
  PROJECT_NUMBER="$(gcloud projects describe "${GCP_PROJECT_ID}" --format="value(projectNumber)")"
  SERVICE_ACCOUNT="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
fi
IMAGE_TAG="${IMAGE_TAG:-$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M%S)}"
IMAGE="gcr.io/${PROJECT_ID}/${SERVICE_NAME}:${IMAGE_TAG}"

GCS_BUCKET="${GCS_BUCKET:-divine-blossom-media}"
PRODUCTION_PROJECT_ID="rich-compiler-479518-d2"
PRODUCTION_SERVICE_NAME="divine-transcoder"
PRODUCTION_GCS_BUCKET="divine-blossom-media"
if [ "${PROJECT_ID}" = "${PRODUCTION_PROJECT_ID}" ] && \
  [ "${SERVICE_NAME}" = "${PRODUCTION_SERVICE_NAME}" ] && \
  [ "${GCS_BUCKET}" != "${PRODUCTION_GCS_BUCKET}" ]; then
  echo "Refusing production deploy: GCS_BUCKET must be ${PRODUCTION_GCS_BUCKET} for ${PRODUCTION_SERVICE_NAME} in ${PRODUCTION_PROJECT_ID}." >&2
  echo "Unset the exported GCS_BUCKET and retry." >&2
  exit 1
fi
WEBHOOK_URL="${WEBHOOK_URL:-https://media.divine.video/admin/transcode-status}"
TRANSCRIPT_WEBHOOK_URL="${TRANSCRIPT_WEBHOOK_URL:-https://media.divine.video/admin/transcript-status}"
TRANSCRIPTION_PROVIDER="${TRANSCRIPTION_PROVIDER:-gemini}"
# Default to Gemini Flash: ~10-15× cheaper than gemini-2.5-pro for audio
# input and adequate for transcription. Pro can be opted into per-deploy
# by setting TRANSCRIPTION_MODEL=gemini-2.5-pro.
TRANSCRIPTION_MODEL="${TRANSCRIPTION_MODEL:-gemini-2.5-flash}"
# OpenAI fallback (only used when TRANSCRIPTION_PROVIDER=openai)
TRANSCRIPTION_API_URL="${TRANSCRIPTION_API_URL:-https://api.openai.com/v1/audio/transcriptions}"
USE_GPU="${USE_GPU:-false}"
SENTRY_ENVIRONMENT="${SENTRY_ENVIRONMENT:-production}"

# --- Autoscaling -----------------------------------------------------------
#
# CONCURRENCY must stay low. Cloud Run scales out on concurrency utilization,
# so this value is a promise about how many requests one instance can actually
# serve at once. A single POST /transcode runs one ffmpeg process that encodes
# both the 720p and 480p variants together (-var_stream_map), and no -threads
# limit is set, so libx264 takes every core on the instance. One request
# therefore saturates all 4 vCPUs.
#
# With a high value here, Cloud Run believes an instance has spare capacity,
# declines to add instances, and piles jobs onto one box until they timeshare
# into the 900 s timeout -- without ever reaching MAX_INSTANCES. 2 lets one
# request occupy the CPU while another is in its GCS download or upload phase,
# which is I/O-bound and uses no CPU.
CONCURRENCY="${CONCURRENCY:-2}"

# MAX_INSTANCES is a ceiling, not a reservation: unused instances cost nothing,
# so it is set well above steady-state need to absorb bursts. Note this is
# capped in turn by the project's regional Cloud Run vCPU quota, which fails
# silently when exceeded -- MAX_INSTANCES x CPU must fit inside it.
MAX_INSTANCES="${MAX_INSTANCES:-100}"

# MIN_INSTANCES is billed whether or not it serves traffic, so it defaults to
# scale-to-zero. Raise it ahead of any scheduled traffic event: autoscaling
# reacts in tens of seconds, which is far slower than a burst arrives.
MIN_INSTANCES="${MIN_INSTANCES:-0}"
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
STATUS_QUEUE_ENABLED="${STATUS_QUEUE_ENABLED:-false}"
STATUS_QUEUE_LOCATION="${STATUS_QUEUE_LOCATION:-${REGION}}"
STATUS_QUEUE_NAME="${STATUS_QUEUE_NAME:-derivative-status}"
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
  --concurrency "${CONCURRENCY}" \
  --timeout 900 \
  --max-instances "${MAX_INSTANCES}" \
  --min-instances "${MIN_INSTANCES}" \
  --no-cpu-throttling \
  --update-env-vars "^@@^GCP_PROJECT_ID=${GCP_PROJECT_ID}@@GCS_BUCKET=${GCS_BUCKET}@@WEBHOOK_URL=${WEBHOOK_URL}@@TRANSCRIPT_WEBHOOK_URL=${TRANSCRIPT_WEBHOOK_URL}@@TRANSCRIPTION_PROVIDER=${TRANSCRIPTION_PROVIDER}@@TRANSCRIPTION_MODEL=${TRANSCRIPTION_MODEL}@@TRANSCRIPTION_API_URL=${TRANSCRIPTION_API_URL}@@USE_GPU=${USE_GPU}@@SENTRY_ENVIRONMENT=${SENTRY_ENVIRONMENT}@@GOOGLE_CLOUD_LOCATION=${GOOGLE_CLOUD_LOCATION}@@GOOGLE_STT_RECOGNIZER=${GOOGLE_STT_RECOGNIZER}@@GOOGLE_STT_MODEL=${GOOGLE_STT_MODEL}@@GOOGLE_STT_LANGUAGE_CODES=${GOOGLE_STT_LANGUAGE_CODES}@@TRANSCRIPTION_FALLBACK_PROVIDER=${TRANSCRIPTION_FALLBACK_PROVIDER}@@TRANSCRIPTION_FALLBACK_ON_PROVIDER_ERROR=${TRANSCRIPTION_FALLBACK_ON_PROVIDER_ERROR}@@STATUS_QUEUE_ENABLED=${STATUS_QUEUE_ENABLED}@@STATUS_QUEUE_LOCATION=${STATUS_QUEUE_LOCATION}@@STATUS_QUEUE_NAME=${STATUS_QUEUE_NAME}" \
  --update-secrets "WEBHOOK_SECRET=webhook_secret:latest,TRANSCRIPTION_API_KEY=openai_api_key:latest,SENTRY_DSN=${SENTRY_SECRET}:latest,TRANSCRIBE_SHARED_SECRET=transcribe_shared_secret:latest"

echo "Done! Service URL:"
gcloud run services describe "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --format='value(status.url)'
