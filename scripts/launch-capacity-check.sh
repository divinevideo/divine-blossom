#!/bin/bash
# ABOUTME: Read-only preflight that compares live Cloud Run capacity against what the deploy scripts intend.
# ABOUTME: Reports autoscaling drift, queue presence, and budget coverage before a scheduled traffic event.
#
# Changes nothing. Run it before a launch, and again after deploying, to confirm
# production actually matches intent -- editing a deploy script does not change
# a running service.
#
#   ./scripts/launch-capacity-check.sh

set -uo pipefail

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${REGION:-us-central1}"
BILLING_ACCOUNT="${BILLING_ACCOUNT:-01F7FB-6E8CEA-FC485A}"
QUEUE_NAME="${QUEUE_NAME:-divine-transcode}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=============================================="
echo " Launch capacity preflight"
echo " project ${PROJECT_ID}   region ${REGION}"
echo "=============================================="
echo

# --- Cloud Run services ----------------------------------------------------
#
# Reports live autoscaling settings next to the deploy script's defaults. A
# mismatch means the fix is committed but not deployed, which is the failure
# mode most likely to be mistaken for "already handled".

check_service() {
  local service="$1" deploy_script="$2" expected_concurrency="$3"

  echo "--- ${service} ---"
  if ! gcloud run services describe "${service}" \
      --project "${PROJECT_ID}" --region "${REGION}" \
      --format="value(spec.template.spec.containerConcurrency)" >/dev/null 2>&1; then
    echo "  could not read the service (missing, wrong region, or no access)"
    echo
    return
  fi

  local concurrency max_scale min_scale cpu
  concurrency=$(gcloud run services describe "${service}" \
    --project "${PROJECT_ID}" --region "${REGION}" \
    --format="value(spec.template.spec.containerConcurrency)" 2>/dev/null)
  max_scale=$(gcloud run services describe "${service}" \
    --project "${PROJECT_ID}" --region "${REGION}" \
    --format="value(spec.template.metadata.annotations['autoscaling.knative.dev/maxScale'])" 2>/dev/null)
  min_scale=$(gcloud run services describe "${service}" \
    --project "${PROJECT_ID}" --region "${REGION}" \
    --format="value(spec.template.metadata.annotations['autoscaling.knative.dev/minScale'])" 2>/dev/null)
  cpu=$(gcloud run services describe "${service}" \
    --project "${PROJECT_ID}" --region "${REGION}" \
    --format="value(spec.template.spec.containers[0].resources.limits.cpu)" 2>/dev/null)

  echo "  live : concurrency=${concurrency:-?}  maxScale=${max_scale:-?}  minScale=${min_scale:-0}  cpu=${cpu:-?}"

  if [ -f "${REPO_ROOT}/${deploy_script}" ]; then
    local intended
    intended=$(grep -oE 'CONCURRENCY="\$\{CONCURRENCY:-[0-9]+\}"' "${REPO_ROOT}/${deploy_script}" \
      | grep -oE '[0-9]+' | head -1)
    echo "  intended concurrency per ${deploy_script}: ${intended:-unset}"
    if [ -n "${intended}" ] && [ "${concurrency}" != "${intended}" ]; then
      echo "  DRIFT: live concurrency ${concurrency} != intended ${intended} -- not yet deployed"
    fi
  fi

  if [ -n "${concurrency}" ] && [ "${concurrency}" -gt "${expected_concurrency}" ] 2>/dev/null; then
    echo "  WARNING: concurrency ${concurrency} is high for this service. Cloud Run"
    echo "           scales out on concurrency utilization, so an inflated value"
    echo "           suppresses scale-out under load."
  fi

  # maxScale x cpu is what must fit inside the regional Cloud Run CPU quota.
  if [ -n "${max_scale}" ] && [ -n "${cpu}" ]; then
    echo "  peak vCPU if fully scaled: ${max_scale} instances x ${cpu} cpu (check against quota below)"
  fi
  echo
}

check_service "divine-transcoder" "cloud-run-transcoder/deploy.sh" 4
check_service "blossom-upload-rust" "cloud-run-upload/deploy.sh" 200

# --- Regional CPU quota ----------------------------------------------------

echo "--- Cloud Run CPU quota ---"
echo "  maxScale x cpu must fit inside the regional Cloud Run CPU quota, which"
echo "  caps scale-out silently when exceeded. Quota increases take roughly a"
echo "  week, so request before you need the headroom, not when you hit it."
echo
echo "  Read current quota (needs the gcloud alpha component):"
echo "    gcloud alpha quotas info list --service=run.googleapis.com --project=${PROJECT_ID}"
echo "  Or in the console:"
echo "    https://console.cloud.google.com/iam-admin/quotas?project=${PROJECT_ID}&service=run.googleapis.com"
echo

# --- Transcode queue -------------------------------------------------------

echo "--- transcode queue ---"
if gcloud tasks queues describe "${QUEUE_NAME}" \
    --project "${PROJECT_ID}" --location "${REGION}" >/dev/null 2>&1; then
  gcloud tasks queues describe "${QUEUE_NAME}" \
    --project "${PROJECT_ID}" --location "${REGION}" \
    --format="value[separator='  '](state,rateLimits.maxConcurrentDispatches,rateLimits.maxDispatchesPerSecond)" \
    2>/dev/null | while read -r line; do
      echo "  state/concurrent/rate: ${line}"
    done
  echo "  Confirm the upload service has TRANSCODE_QUEUE set, or it still"
  echo "  dispatches directly and loses work when instances churn."
else
  echo "  NOT FOUND -- transcode dispatch is still direct and loses work on"
  echo "  instance churn. Create it with scripts/provision-transcode-queue.sh"
fi
echo

# --- Budgets ---------------------------------------------------------------

echo "--- billing budgets ---"
gcloud billing budgets list --billing-account="${BILLING_ACCOUNT}" \
  --format="table(displayName,amount.specifiedAmount.units,amount.specifiedAmount.currencyCode)" \
  2>/dev/null || echo "  could not read budgets (check billing account access)"
echo
echo "  A budget goes quiet once every threshold has fired, so a budget sized"
echo "  for today's spend becomes a single binary alarm during a launch rather"
echo "  than graduated signal. Size one for the expected peak."
echo
echo "  GCP budgets cannot see Fastly, which is the largest line at scale."
echo "  Use scripts/burn_rate_monitor.py for that."
echo

echo "=============================================="
echo " Preflight complete. Nothing was changed."
echo "=============================================="
