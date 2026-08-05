#!/bin/bash
# ABOUTME: Create or update the Cloud Tasks queue used for derivative status callbacks
# ABOUTME: Keeps queue concurrency serialized so generation ordering remains valid

set -euo pipefail

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
GCP_PROJECT_ID="${GCP_PROJECT_ID:-${PROJECT_ID}}"
REGION="${REGION:-us-central1}"
STATUS_QUEUE_LOCATION="${STATUS_QUEUE_LOCATION:-${REGION}}"
STATUS_QUEUE_NAME="${STATUS_QUEUE_NAME:-derivative-status}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-}"
if [ -z "${SERVICE_ACCOUNT}" ]; then
  PROJECT_NUMBER="$(gcloud projects describe "${GCP_PROJECT_ID}" --format="value(projectNumber)")"
  SERVICE_ACCOUNT="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
fi

gcloud services enable cloudtasks.googleapis.com \
  --project "${GCP_PROJECT_ID}"

if gcloud tasks queues describe "${STATUS_QUEUE_NAME}" \
  --project "${GCP_PROJECT_ID}" \
  --location "${STATUS_QUEUE_LOCATION}" >/dev/null 2>&1; then
  gcloud tasks queues update "${STATUS_QUEUE_NAME}" \
    --project "${GCP_PROJECT_ID}" \
    --location "${STATUS_QUEUE_LOCATION}" \
    --max-attempts=10 \
    --min-backoff=5s \
    --max-backoff=600s \
    --max-concurrent-dispatches=1
else
  gcloud tasks queues create "${STATUS_QUEUE_NAME}" \
    --project "${GCP_PROJECT_ID}" \
    --location "${STATUS_QUEUE_LOCATION}" \
    --max-attempts=10 \
    --min-backoff=5s \
    --max-backoff=600s \
    --max-concurrent-dispatches=1
fi

QUEUE_STATE="$(gcloud tasks queues describe "${STATUS_QUEUE_NAME}" \
  --project "${GCP_PROJECT_ID}" \
  --location "${STATUS_QUEUE_LOCATION}" \
  --format="value(state)")"
if [ "${QUEUE_STATE}" = "PAUSED" ]; then
  gcloud tasks queues resume "${STATUS_QUEUE_NAME}" \
    --project "${GCP_PROJECT_ID}" \
    --location "${STATUS_QUEUE_LOCATION}"
  QUEUE_STATE="$(gcloud tasks queues describe "${STATUS_QUEUE_NAME}" \
    --project "${GCP_PROJECT_ID}" \
    --location "${STATUS_QUEUE_LOCATION}" \
    --format="value(state)")"
fi

if [ "${QUEUE_STATE}" != "RUNNING" ]; then
  echo "Queue ${STATUS_QUEUE_NAME} is ${QUEUE_STATE}, expected RUNNING" >&2
  exit 1
fi

gcloud tasks queues add-iam-policy-binding "${STATUS_QUEUE_NAME}" \
  --project "${GCP_PROJECT_ID}" \
  --location "${STATUS_QUEUE_LOCATION}" \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role=roles/cloudtasks.enqueuer \
  --condition=None
