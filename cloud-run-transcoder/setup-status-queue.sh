#!/bin/bash
# ABOUTME: Create or update the Cloud Tasks queue used for derivative status callbacks
# ABOUTME: Keeps queue concurrency serialized so generation ordering remains valid

set -euo pipefail

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${REGION:-us-central1}"
QUEUE_NAME="${QUEUE_NAME:-derivative-status}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-149672065768-compute@developer.gserviceaccount.com}"

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

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role=roles/cloudtasks.enqueuer \
  --condition=None
