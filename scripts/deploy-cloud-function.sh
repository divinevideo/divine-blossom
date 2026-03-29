#!/bin/bash
# ABOUTME: Deploy the process-blob service as Cloud Run with Eventarc GCS trigger
# ABOUTME: Requires gcloud CLI authenticated and configured

set -e

PROJECT_ID="${GCP_PROJECT_ID:-}"
BUCKET_NAME="${GCS_BUCKET_NAME:-blossom-media}"
REGION="${GCS_REGION:-us-central1}"
SERVICE_NAME="process-blob"

if [ -z "$PROJECT_ID" ]; then
    echo "Error: GCP_PROJECT_ID environment variable required"
    exit 1
fi

echo "Deploying Cloud Run service..."
echo "Project: $PROJECT_ID"
echo "Bucket: $BUCKET_NAME"
echo "Region: $REGION"

cd "$(dirname "$0")/../cloud-functions/process-blob"

# Build and deploy to Cloud Run
gcloud run deploy "$SERVICE_NAME" \
    --project="$PROJECT_ID" \
    --region="$REGION" \
    --source=. \
    --memory=1Gi \
    --timeout=300s \
    --no-allow-unauthenticated \
    --set-env-vars="\
METADATA_WEBHOOK_URL=${METADATA_WEBHOOK_URL:-},\
METADATA_WEBHOOK_SECRET=${METADATA_WEBHOOK_SECRET:-},\
C2PA_MODE=${C2PA_MODE:-off},\
C2PA_TRUST_ANCHORS=${C2PA_TRUST_ANCHORS:-/app/trust_anchors.pem},\
C2PA_CHECK_IMAGES=${C2PA_CHECK_IMAGES:-false}"

echo ""
echo "Cloud Run service deployed!"

# Create Eventarc trigger for GCS object finalization
TRIGGER_NAME="${SERVICE_NAME}-gcs-trigger"
EXISTING_TRIGGER=$(gcloud eventarc triggers list \
    --project="$PROJECT_ID" \
    --location="$REGION" \
    --filter="name:${TRIGGER_NAME}" \
    --format="value(name)" 2>/dev/null || true)

if [ -z "$EXISTING_TRIGGER" ]; then
    echo "Creating Eventarc trigger..."
    gcloud eventarc triggers create "$TRIGGER_NAME" \
        --project="$PROJECT_ID" \
        --location="$REGION" \
        --destination-run-service="$SERVICE_NAME" \
        --destination-run-region="$REGION" \
        --event-filters="type=google.cloud.storage.object.v1.finalized" \
        --event-filters="bucket=$BUCKET_NAME" \
        --service-account="${PROJECT_ID}-compute@developer.gserviceaccount.com"
    echo "Eventarc trigger created!"
else
    echo "Eventarc trigger already exists: $TRIGGER_NAME"
fi

echo ""
echo "View logs: gcloud run services logs read $SERVICE_NAME --region=$REGION"
