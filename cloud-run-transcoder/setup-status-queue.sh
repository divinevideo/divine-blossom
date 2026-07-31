#!/bin/bash
# ABOUTME: Create or update the Cloud Tasks queue used for derivative status callbacks
# ABOUTME: Keeps queue concurrency serialized so generation ordering remains valid

set -euo pipefail

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${REGION:-us-central1}"
QUEUE_NAME="${QUEUE_NAME:-derivative-status}"
PROJECT_NUMBER="$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)")"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-${PROJECT_NUMBER}-compute@developer.gserviceaccount.com}"

gcloud services enable cloudtasks.googleapis.com \
  --project "${PROJECT_ID}"

if gcloud tasks queues describe "${QUEUE_NAME}" \
  --project "${PROJECT_ID}" \
  --location "${REGION}" >/dev/null 2>&1; then
  gcloud tasks queues update "${QUEUE_NAME}" \
    --project "${PROJECT_ID}" \
    --location "${REGION}" \
    --max-attempts=10 \
    --min-backoff=5s \
    --max-backoff=600s \
    --max-concurrent-dispatches=1
else
  gcloud tasks queues create "${QUEUE_NAME}" \
    --project "${PROJECT_ID}" \
    --location "${REGION}" \
    --max-attempts=10 \
    --min-backoff=5s \
    --max-backoff=600s \
    --max-concurrent-dispatches=1
fi

QUEUE_STATE="$(gcloud tasks queues describe "${QUEUE_NAME}" \
  --project "${PROJECT_ID}" \
  --location "${REGION}" \
  --format="value(state)")"
if [ "${QUEUE_STATE}" = "PAUSED" ]; then
  gcloud tasks queues resume "${QUEUE_NAME}" \
    --project "${PROJECT_ID}" \
    --location "${REGION}"
  QUEUE_STATE="$(gcloud tasks queues describe "${QUEUE_NAME}" \
    --project "${PROJECT_ID}" \
    --location "${REGION}" \
    --format="value(state)")"
fi

if [ "${QUEUE_STATE}" != "RUNNING" ]; then
  echo "Queue ${QUEUE_NAME} is ${QUEUE_STATE}, expected RUNNING" >&2
  exit 1
fi

gcloud tasks queues add-iam-policy-binding "${QUEUE_NAME}" \
  --project "${PROJECT_ID}" \
  --location "${REGION}" \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role=roles/cloudtasks.enqueuer \
  --condition=None
