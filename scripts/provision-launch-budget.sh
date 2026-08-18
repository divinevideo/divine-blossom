#!/bin/bash
# ABOUTME: Creates a launch-scale GCP billing budget with graduated thresholds across orders of magnitude.
# ABOUTME: Complements the existing guards, which go silent once spend passes their ceiling.
#
# Why a second, larger budget rather than raising the existing ones:
#
# A budget stops being useful once every threshold has fired. The existing
# guards are sized near current spend, so during a launch they all trip in the
# first hours and then say nothing further -- they become a binary "we are over"
# with no sense of how far. Keep them: tripping early is exactly the "something
# changed" signal you want. Add this one alongside, sized for the expected peak
# with low-percentage thresholds, so alerts keep arriving as spend climbs.
#
# This budget notifies. It does not cap: GCP billing budgets are observability,
# not enforcement, and nothing here will stop spend on its own.
#
# It also cannot see Fastly, which is the largest line at scale. Delivery
# bandwidth is covered by scripts/burn_rate_monitor.py.
#
#   ./scripts/provision-launch-budget.sh                 # show what it would do
#   APPLY=1 ./scripts/provision-launch-budget.sh         # create it

set -euo pipefail

BILLING_ACCOUNT="${BILLING_ACCOUNT:-01F7FB-6E8CEA-FC485A}"
PROJECT_NUMBER="${PROJECT_NUMBER:-149672065768}"
DISPLAY_NAME="${DISPLAY_NAME:-divine launch scale}"
CURRENCY="${CURRENCY:-NZD}"

# Sized for the expected launch peak, not for today. The existing project guard
# sits at 5,000 NZD, roughly current spend, so this spans about 20x above it and
# the low thresholds below give useful signal from well under current spend all
# the way up.
AMOUNT="${AMOUNT:-100000}"

# Existing channel, shared with the current budgets so alerts land where people
# already look. Override to add a launch-specific channel.
NOTIFICATION_CHANNEL="${NOTIFICATION_CHANNEL:-projects/rich-compiler-479518-d2/notificationChannels/16993136770876051955}"

APPLY="${APPLY:-0}"

# Graduated thresholds. Against a 100,000 budget these fire at roughly 1k, 2.5k,
# 5k, 10k, 25k, 50k, 75k and 100k, so each order of magnitude gets its own
# alert instead of everything collapsing into one.
THRESHOLDS=(0.01 0.025 0.05 0.10 0.25 0.50 0.75 1.0)

# Forecasted thresholds fire before the spend arrives, which is the only kind of
# billing alert with any lead time. Billing data still lags hours -- for
# real-time signal use the burn-rate monitor.
FORECAST_THRESHOLDS=(0.25 0.50 1.0)

args=(
  --billing-account="${BILLING_ACCOUNT}"
  --display-name="${DISPLAY_NAME}"
  --budget-amount="${AMOUNT}${CURRENCY}"
  --filter-projects="projects/${PROJECT_NUMBER}"
  --calendar-period=month
)

for threshold in "${THRESHOLDS[@]}"; do
  args+=(--threshold-rule=percent="${threshold}")
done
for threshold in "${FORECAST_THRESHOLDS[@]}"; do
  args+=(--threshold-rule=percent="${threshold}",basis=forecasted-spend)
done

if [ -n "${NOTIFICATION_CHANNEL}" ]; then
  args+=(--notifications-rule-monitoring-notification-channels="${NOTIFICATION_CHANNEL}")
fi

echo "Billing account : ${BILLING_ACCOUNT}"
echo "Budget          : ${DISPLAY_NAME} at ${AMOUNT} ${CURRENCY}/month"
echo "Scoped to       : projects/${PROJECT_NUMBER}"
echo "Alerts at       : ${THRESHOLDS[*]} of budget (current spend)"
echo "                  ${FORECAST_THRESHOLDS[*]} of budget (forecasted)"
echo

if [ "${APPLY}" != "1" ]; then
  echo "Dry run. Would run:"
  echo
  printf '  gcloud billing budgets create'
  printf ' \\\n    %q' "${args[@]}"
  printf '\n\n'
  echo "Re-run with APPLY=1 to create it."
  exit 0
fi

echo "Creating budget..."
gcloud billing budgets create "${args[@]}"

echo
echo "Created. Verify with:"
echo "  gcloud billing budgets list --billing-account=${BILLING_ACCOUNT}"
