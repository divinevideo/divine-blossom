# ABOUTME: Emits daily infrastructure cost observations in divine-brain's cost_observations shape.
# ABOUTME: GCP costs are actual invoiced amounts from the BigQuery billing export; Fastly costs are modeled.

"""Daily infrastructure cost report.

divine-brain tracks cost, but only LLM cost: `src/cost/rollup.ts` has exactly
one source, `langfuse`, and its `vendor` column means Anthropic or OpenAI rather
than Fastly or Google. Infrastructure spend -- which is the larger number at any
meaningful scale -- is absent entirely. This produces the missing rows.

Output matches `cost_observations` (see divine-brain `db/schema/silver.ts`), so
no schema migration is needed: `input_tokens` and `output_tokens` default to 0
and simply go unused by infrastructure rows.

Two very different kinds of number are emitted, and the distinction matters more
than the totals:

  basis=actual   GCP, from the BigQuery billing export. Genuinely invoiced,
                 broken out per SKU, converted from the billing account's
                 currency to USD via the export's own conversion rate.

  basis=modeled  Fastly, from the stats API multiplied by list rates. Fastly
                 publishes no rate at the volumes Divine is heading for, so
                 these are estimates and must never be presented as invoiced.

BEFORE INGESTING INTO divine-brain, read the warning in `--help` about
`src/cost/alerts.ts`. Its daily total sums `v_cost_daily` with no vendor or
source filter, so infrastructure rows would silently inflate an alerter whose
thresholds are calibrated for LLM spend, and page continuously.

Usage:
    python3 scripts/infra_cost_report.py                    # yesterday, JSON lines
    python3 scripts/infra_cost_report.py --day 2026-08-04
    python3 scripts/infra_cost_report.py --table            # human-readable
    python3 scripts/infra_cost_report.py --gcp-only

Requires the `bq` and `fastly` CLIs, authenticated. Never prints credentials.
"""

import argparse
import datetime
import json
import subprocess
import sys

# Rates and service IDs are shared with the real-time monitor so the two cannot
# drift apart and disagree about what a byte costs.
from burn_rate_monitor import COMPUTE_SERVICE, GB, RATES, VCL_SERVICE

BILLING_PROJECT = "rich-compiler-479518-d2"
BILLING_TABLE = (
    "rich-compiler-479518-d2.billing_export."
    "gcp_billing_export_v1_01F7FB_6E8CEA_FC485A"
)

# The media stack's project. Other projects on the same billing account are
# deliberately excluded: this report is about what media delivery costs.
MEDIA_PROJECT = "rich-compiler-479518-d2"

GCP_SOURCE = "gcp-billing-export"
FASTLY_SOURCE = "fastly-stats"


class ReportError(Exception):
    """Raised when a cost source could not be read."""


def run(cmd, what):
    """Run a command and return stdout, raising ReportError on failure."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReportError(f"could not run {what}: {exc}") from exc

    if result.returncode != 0:
        # stderr from bq/fastly describes the failure and carries no secrets.
        raise ReportError(f"{what} failed: {result.stderr.strip()[:500]}")
    return result.stdout


def fetch_gcp_costs(day, project=MEDIA_PROJECT):
    """Actual GCP cost for `day`, per service and SKU, converted to USD.

    Partition filtering uses a window around the day rather than an exact
    match: usage is partitioned by export time, which does not align exactly
    with usage date, so a narrow filter silently drops rows.
    """
    query = f"""
    SELECT service.description AS service,
           sku.description AS sku,
           SUM(cost / NULLIF(currency_conversion_rate, 0)) AS cost_usd
      FROM `{BILLING_TABLE}`
     WHERE DATE(_PARTITIONTIME)
           BETWEEN DATE_SUB(DATE('{day}'), INTERVAL 2 DAY)
               AND DATE_ADD(DATE('{day}'), INTERVAL 2 DAY)
       AND DATE(usage_start_time) = DATE('{day}')
       AND project.id = '{project}'
     GROUP BY service, sku
    HAVING cost_usd > 0
     ORDER BY cost_usd DESC
    """
    output = run(
        [
            "bq", "query", f"--project_id={BILLING_PROJECT}",
            "--nouse_legacy_sql", "--format=json", "--quiet", query,
        ],
        "the BigQuery billing export query",
    )

    try:
        rows = json.loads(output or "[]")
    except ValueError as exc:
        raise ReportError(f"could not parse the billing export response: {exc}") from exc

    return [
        {
            "observed_for_day": day,
            "vendor": "gcp",
            # Service is the useful grouping dimension ("Cloud Storage"), and
            # SKU is where the detail that matters lives -- egress is a SKU,
            # not a service.
            "surface": row["service"],
            "model": row["sku"],
            "source": GCP_SOURCE,
            "cost_usd": round(float(row["cost_usd"]), 4),
            "basis": "actual",
        }
        for row in rows
    ]


def fetch_fastly_day(service_id, day):
    """Sum one day of Fastly historical stats for a service.

    The window is half-open: `--from` and `--to` set to the same date describe a
    zero-width range and return no records at all, silently. The end is
    therefore the following midnight.
    """
    end = (datetime.date.fromisoformat(day) + datetime.timedelta(days=1)).isoformat()
    output = run(
        [
            "fastly", "stats", "historical", "--service-id", service_id,
            "--from", f"{day} 00:00", "--to", f"{end} 00:00",
            "--by", "day", "--json",
        ],
        f"the Fastly stats query for {service_id}",
    )

    totals = {}
    records = 0
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        records += 1
        for key, value in record.items():
            if isinstance(value, (int, float)):
                totals[key] = totals.get(key, 0) + value

    # An empty response must not be reported as zero cost. Zero spend and a
    # failed query look identical downstream, and the wrong one of those reads
    # as good news.
    if records == 0:
        raise ReportError(
            f"Fastly returned no records for {service_id} on {day} "
            "(day out of retention, or the service had no traffic)"
        )
    return totals


def fetch_fastly_costs(day):
    """Modeled Fastly cost for `day`, from stats multiplied by list rates."""
    return build_fastly_rows(
        day, fetch_fastly_day(VCL_SERVICE, day), fetch_fastly_day(COMPUTE_SERVICE, day)
    )


def build_fastly_rows(day, vcl, compute):
    """Convert a day of Fastly counters into cost observation rows."""
    delivered_bytes = vcl.get("resp_body_bytes", 0)
    requests = vcl.get("requests", 0)
    compute_requests = compute.get("compute_requests", 0)
    compute_ms = compute.get("compute_request_time_billed_ms", 0)

    # Bytes Compute pulled from its backends. This is predominantly GCS reads,
    # and it is the cross-check on the GCP egress SKU above: two independent
    # sources for the same bytes.
    origin_bytes = compute.get("compute_beresp_body_bytes", 0)

    rows = [
        ("delivery", "viewer-bandwidth",
         delivered_bytes / GB * RATES["fastly_delivery_per_gb"]),
        ("requests", "cdn-requests",
         requests / 10_000 * RATES["fastly_requests_per_10k"]),
        ("compute", "compute-requests",
         compute_requests / 1e6 * RATES["compute_requests_per_million"]),
        ("compute", "compute-time",
         compute_ms / 1e6 * RATES["compute_vcpu_ms_per_million"]),
        # Recorded against Fastly because that is where the bytes were
        # observed, but the charge lands on the GCP invoice. Cross-check it
        # against the GCP egress SKU rather than adding the two together.
        ("origin-egress-observed", "gcs-egress-bytes",
         origin_bytes / GB * RATES["gcs_egress_per_gb"]),
    ]

    return [
        {
            "observed_for_day": day,
            "vendor": "fastly",
            "surface": surface,
            "model": model,
            "source": FASTLY_SOURCE,
            "cost_usd": round(cost, 4),
            "basis": "modeled",
        }
        for surface, model, cost in rows
        if cost > 0
    ]


def render_table(observations):
    if not observations:
        print("No cost observations for this day.")
        return

    by_basis = {}
    for row in observations:
        by_basis.setdefault(row["basis"], []).append(row)

    for basis in ("actual", "modeled"):
        rows = by_basis.get(basis)
        if not rows:
            continue
        heading = {
            "actual": "ACTUAL — invoiced, from the GCP billing export",
            "modeled": "MODELED — estimated at list rates, NOT invoiced amounts",
        }[basis]
        print(f"\n{heading}")
        rows.sort(key=lambda r: -r["cost_usd"])
        for row in rows:
            label = f"{row['vendor']}/{row['surface']}"
            print(f"  {label:<34s} {row['model'][:38]:<40s} ${row['cost_usd']:>10,.2f}")
        print(f"  {'subtotal':<34s} {'':<40s} "
              f"${sum(r['cost_usd'] for r in rows):>10,.2f}")

    print(
        "\nActual and modeled are not additive: the modeled "
        "origin-egress-observed row\nis a second view of bytes already invoiced "
        "under a GCP egress SKU."
    )


def main():
    yesterday = datetime.date.today() - datetime.timedelta(days=1)
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "WARNING for divine-brain ingest: src/cost/alerts.ts totals\n"
            "v_cost_daily with no vendor or source filter. Scope that query to\n"
            "the langfuse source BEFORE loading infrastructure rows, or its\n"
            "warn/page thresholds -- calibrated for LLM spend -- will page\n"
            "continuously the moment these land."
        ),
    )
    parser.add_argument(
        "--day", default=yesterday.isoformat(),
        help="day to report, YYYY-MM-DD (default: yesterday, because the "
             "billing export lags several hours and today is always partial)",
    )
    parser.add_argument("--table", action="store_true",
                        help="human-readable output instead of JSON lines")
    parser.add_argument("--gcp-only", action="store_true")
    parser.add_argument("--fastly-only", action="store_true")
    args = parser.parse_args()

    try:
        datetime.date.fromisoformat(args.day)
    except ValueError:
        parser.error("--day must be YYYY-MM-DD")

    observations = []
    failures = []

    if not args.fastly_only:
        try:
            observations.extend(fetch_gcp_costs(args.day))
        except ReportError as exc:
            failures.append(str(exc))

    if not args.gcp_only:
        try:
            observations.extend(fetch_fastly_costs(args.day))
        except ReportError as exc:
            failures.append(str(exc))

    for failure in failures:
        print(f"ERROR: {failure}", file=sys.stderr)

    if args.table:
        render_table(observations)
    else:
        for row in observations:
            print(json.dumps(row))

    # A partial report is worse than a loud failure: a missing source would
    # otherwise read as a genuine drop in spend.
    if failures:
        return 3
    return 0 if observations else 1


if __name__ == "__main__":
    sys.exit(main())
