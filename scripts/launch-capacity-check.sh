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

echo "--- Cloud Run regional quota headroom ---"
echo "  CPU quota is enforced on CPU actually allocated at once, across every"
echo "  Cloud Run service in the region -- not on configured maxima. Summing"
echo "  maxScale x cpu therefore gives the worst case if everything scaled out"
echo "  together, which is the number worth having before a traffic event."
echo

CPU_QUOTA=$(gcloud alpha quotas info list --service=run.googleapis.com \
  --project "${PROJECT_ID}" --filter="quotaId=CpuAllocPerProjectRegion" \
  --format="value(dimensionsInfos[0].details.value)" 2>/dev/null | head -1)

if [ -z "${CPU_QUOTA}" ]; then
  echo "  could not read quota. Needs the gcloud alpha component:"
  echo "    gcloud components install alpha"
  echo "  Or read it in the console:"
  echo "    https://console.cloud.google.com/iam-admin/quotas?project=${PROJECT_ID}&service=run.googleapis.com"
else
  gcloud run services list --project "${PROJECT_ID}" --region "${REGION}" \
    --format="csv[no-heading](metadata.name,spec.template.spec.containers[0].resources.limits.cpu,spec.template.metadata.annotations['autoscaling.knative.dev/maxScale'])" \
    2>/dev/null \
    | CPU_QUOTA="${CPU_QUOTA}" python3 -c '
import os, sys

quota = float(os.environ["CPU_QUOTA"])
total = 0.0
rows = []

for line in sys.stdin:
    parts = line.strip().split(",")
    if len(parts) < 3 or not parts[0]:
        continue
    name, cpu, max_scale = parts[0], parts[1], parts[2]
    # Cloud Run reports cpu either as millicores ("1000m") or cores ("4").
    millicores = float(cpu[:-1]) if cpu.endswith("m") else float(cpu) * 1000
    scale = float(max_scale) if max_scale else 0.0
    peak = millicores * scale
    total += peak
    rows.append((name, cpu, int(scale), peak))

rows.sort(key=lambda r: -r[3])
for name, cpu, scale, peak in rows:
    print(f"    {name:<26s} {cpu:>6s} x {scale:>4d} = {peak/1000:>8,.0f} vCPU")

print()
# Labels are bound to names rather than written inline: this block is passed to
# python via `sh -c "..."`, where an inline single-quoted string would terminate
# the surrounding shell quoting.
label_total = "worst-case total"
label_quota = "regional quota"
label_headroom = "headroom"
print(f"    {label_total:<26s} {total/1000:>22,.0f} vCPU")
print(f"    {label_quota:<26s} {quota/1000:>22,.0f} vCPU")
headroom = quota - total
pct = total / quota * 100 if quota else 0
print(f"    {label_headroom:<26s} {headroom/1000:>22,.0f} vCPU  ({pct:.0f}% consumed)")
print()
if pct >= 100:
    print("    OVER QUOTA: services cannot all reach maxScale. Scale-out will")
    print("    fail silently once the regional limit is hit.")
elif pct >= 85:
    print("    TIGHT: little room to raise maxScale anywhere without a quota")
    print("    increase, which takes roughly a week to be granted.")
else:
    print("    Sufficient headroom for the configured maxima.")
print()
print("    Services no longer serving traffic still count toward this worst")
print("    case. Retiring one reclaims its whole reservation.")
'
fi
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
