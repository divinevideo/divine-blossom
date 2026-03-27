#!/bin/bash
# ABOUTME: Creates GCS bucket for persistent Fastly Compute application logs
# ABOUTME: Sets 7-day lifecycle delete policy for automatic log rotation

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

BUCKET_NAME="divine-blossom-logs"
LOCATION="US"

echo -e "${GREEN}=== Fastly Logging GCS Bucket Setup ===${NC}\n"

if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}Error: gcloud CLI is not installed${NC}"
    exit 1
fi

PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
if [ -z "$PROJECT_ID" ]; then
    echo -e "${RED}Error: no GCP project set. Run: gcloud config set project <PROJECT_ID>${NC}"
    exit 1
fi
echo "Project: ${PROJECT_ID}"

# Create bucket if it doesn't exist
if gsutil ls -b "gs://${BUCKET_NAME}" &> /dev/null 2>&1; then
    echo -e "${YELLOW}Bucket ${BUCKET_NAME} already exists${NC}"
else
    echo -e "${GREEN}Creating bucket gs://${BUCKET_NAME}...${NC}"
    gsutil mb -p "${PROJECT_ID}" -c STANDARD -l "${LOCATION}" "gs://${BUCKET_NAME}"
    echo -e "${GREEN}Bucket created${NC}"
fi

# Set 7-day lifecycle delete policy
echo -e "${GREEN}Setting 7-day lifecycle delete policy...${NC}"
cat > /tmp/lifecycle-logging.json <<'EOF'
{
  "rule": [
    {
      "action": {"type": "Delete"},
      "condition": {"age": 7}
    }
  ]
}
EOF
gsutil lifecycle set /tmp/lifecycle-logging.json "gs://${BUCKET_NAME}"
rm /tmp/lifecycle-logging.json
echo -e "${GREEN}Lifecycle policy set${NC}"

# Grant the existing service account write access
SA_EMAIL="blossom-storage-sa@${PROJECT_ID}.iam.gserviceaccount.com"
echo -e "${GREEN}Granting write access to ${SA_EMAIL}...${NC}"
gsutil iam ch "serviceAccount:${SA_EMAIL}:objectCreator" "gs://${BUCKET_NAME}"
gsutil iam ch "serviceAccount:${SA_EMAIL}:objectViewer" "gs://${BUCKET_NAME}"
echo -e "${GREEN}Permissions granted${NC}"

echo -e "\n${GREEN}=== Done ===${NC}"
echo "Bucket: gs://${BUCKET_NAME}"
echo "Retention: 7 days (auto-delete)"
echo ""
echo -e "${YELLOW}Next: configure the Fastly logging endpoint 'app_logs' to write to this bucket.${NC}"
echo "See: https://docs.fastly.com/en/guides/log-streaming-google-cloud-storage"
