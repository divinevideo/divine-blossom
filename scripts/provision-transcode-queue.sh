#!/bin/bash
# ABOUTME: Creates or updates the Cloud Tasks queue that buffers transcode jobs.
# ABOUTME: The dispatch limits here are the rate limit into the transcoder and the cost control.
#
# The queue is what lets a traffic burst become a backlog that drains, instead
# of a wall of simultaneous requests against a service that scales out in tens
# of seconds. It also owns retries, so a transcode survives the upload instance
# that requested it being terminated mid-flight.
#
# Idempotent: creates the queue if absent, updates its limits if present.
#
#   ./scripts/provision-transcode-queue.sh
#   MAX_CONCURRENT=200 ./scripts/provision-transcode-queue.sh
#
# After provisioning, redeploy the upload service with the queue wired in:
#
#   TRANSCODE_QUEUE="projects/${PROJECT_ID}/locations/${REGION}/queues/${QUEUE_NAME}" \
#     ./cloud-run-upload/deploy.sh

set -euo pipefail

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project)}"
REGION="${REGION:-us-central1}"
QUEUE_NAME="${QUEUE_NAME:-divine-transcode}"

# MAX_CONCURRENT is the ceiling on transcodes running at once, and therefore the
# real limit on transcoder fleet size and spend. The transcoder runs
# --concurrency 2 per instance, so this divided by 2 is roughly the number of
# instances it will drive. Keep it at or below (transcoder max-instances x 2),
# or the queue will push harder than the fleet is allowed to scale.
MAX_CONCURRENT="${MAX_CONCURRENT:-100}"

# Smooths the arrival rate so a burst of uploads does not become a burst of
# cold starts. The backlog absorbs the difference.
MAX_RATE="${MAX_RATE:-50}"

# Transcodes are idempotent because blobs are content-addressed, so retrying is
# always safe. Backoff is generous because the common failure is the fleet being
# saturated, which retrying harder makes worse.
MAX_ATTEMPTS="${MAX_ATTEMPTS:-5}"
MIN_BACKOFF="${MIN_BACKOFF:-10s}"
MAX_BACKOFF="${MAX_BACKOFF:-300s}"

echo "Project : ${PROJECT_ID}"
echo "Region  : ${REGION}"
echo "Queue   : ${QUEUE_NAME}"
echo "Limits  : ${MAX_CONCURRENT} concurrent, ${MAX_RATE}/s, ${MAX_ATTEMPTS} attempts"
echo

gcloud services enable cloudtasks.googleapis.com --project "${PROJECT_ID}"

if gcloud tasks queues describe "${QUEUE_NAME}" \
    --project "${PROJECT_ID}" --location "${REGION}" >/dev/null 2>&1; then
  echo "Queue exists; updating limits."
  ACTION="update"
else
  echo "Queue not found; creating."
  ACTION="create"
fi

gcloud tasks queues "${ACTION}" "${QUEUE_NAME}" \
  --project "${PROJECT_ID}" \
  --location "${REGION}" \
  --max-concurrent-dispatches "${MAX_CONCURRENT}" \
  --max-dispatches-per-second "${MAX_RATE}" \
  --max-attempts "${MAX_ATTEMPTS}" \
  --min-backoff "${MIN_BACKOFF}" \
  --max-backoff "${MAX_BACKOFF}"

echo
echo "Done. Wire it into the upload service with:"
echo
echo "  TRANSCODE_QUEUE=\"projects/${PROJECT_ID}/locations/${REGION}/queues/${QUEUE_NAME}\" \\"
echo "    ./cloud-run-upload/deploy.sh"
echo
echo "Watch depth during a traffic event with:"
echo
echo "  gcloud tasks queues describe ${QUEUE_NAME} \\"
echo "    --project ${PROJECT_ID} --location ${REGION}"
