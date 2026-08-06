# ABOUTME: Samples Fastly real-time stats and converts them into a dollars-per-hour burn rate.
# ABOUTME: Alerts on cost thresholds far sooner than billing data, which lags by hours.

"""Real-time cost burn-rate monitor for Divine media delivery.

Billing data is the wrong instrument for a launch spike: GCP billing lags hours
and Fastly invoices lag longer. This samples Fastly's real-time stats API, which
reports per-second, and converts the byte and request counters into a
dollars-per-hour run rate that can be alerted on within seconds of a spike.

Two services are sampled because they bill differently and independently:

  VCL service     - `resp_body_bytes` is bytes delivered to viewers. This is the
                    single largest line on the bill at every modeled scale.
  Compute service - `compute_beresp_body_bytes` is bytes Compute fetched from
                    its backends, which is predominantly GCS. That is Google's
                    egress bill, and it appears on no Fastly invoice at all.
                    It is the line most likely to surprise someone.

Rates below are list prices and MUST be replaced with contract rates once they
are known. They are labelled as assumptions in the output so a reader is never
misled into treating a modeled figure as an invoice.

Usage:
    python3 scripts/burn_rate_monitor.py                 # one 10-second sample
    python3 scripts/burn_rate_monitor.py --seconds 30
    python3 scripts/burn_rate_monitor.py --watch          # loop until interrupted
    python3 scripts/burn_rate_monitor.py --json           # machine-readable

Exit codes:
    0  all lines below warning thresholds
    1  at least one line above its warning threshold
    2  at least one line above its critical threshold
    3  could not collect data (auth, network, or CLI failure)

Requires the `fastly` CLI, authenticated. Never reads or prints credentials.
"""

import argparse
import json
import shutil
import subprocess
import sys
import threading
import time

# Fastly service IDs. These match scripts/monitor-vcl-cache.sh.
VCL_SERVICE = "ML7R82HKfmTaqTpHExIDVN"
COMPUTE_SERVICE = "pOvEEWykEbpnylqst1KTrR"

# ---------------------------------------------------------------------------
# Rate assumptions. Replace with contract rates as they are confirmed.
#
# Fastly delivery is list North America pricing; the published tiers stop at
# 20 TB/month, so anything at launch scale is a negotiated rate we do not have.
# Treating list as the estimate is deliberately pessimistic, which is the safe
# direction for an alerting threshold.
# ---------------------------------------------------------------------------
RATES = {
    "fastly_delivery_per_gb": 0.12,
    "fastly_requests_per_10k": 0.0095,
    "compute_requests_per_million": 0.20,
    "compute_vcpu_ms_per_million": 0.02,
    "gcs_egress_per_gb": 0.08,
    "kv_class_a_per_1k": 0.0025,
    "kv_class_b_per_1k": 0.0004,
}

# Alert thresholds in dollars per hour, per line.
#
# Baseline for calibration: at the measured 1,200 DAU the service delivers
# ~294 GB/day, or ~12 GB/hour, which is ~$1.47/hour at list. Warning is set
# near 30x that baseline and critical near 300x, so ordinary daily variation
# stays quiet while a genuine step change pages immediately.
THRESHOLDS = {
    "viewer_delivery": {"warn": 50.0, "critical": 500.0},
    "gcs_egress": {"warn": 25.0, "critical": 250.0},
    "fastly_requests": {"warn": 20.0, "critical": 200.0},
    "compute": {"warn": 10.0, "critical": 100.0},
    "kv_operations": {"warn": 10.0, "critical": 100.0},
    "TOTAL": {"warn": 100.0, "critical": 1000.0},
}

GB = 1e9
SECONDS_PER_HOUR = 3600


class CollectionError(Exception):
    """Raised when real-time stats could not be collected for a service."""


def sample_service(service_id, seconds):
    """Collect `seconds` of real-time stats for one service.

    Returns the summed `aggregated` counters across all samples, plus the
    number of samples actually observed. The real-time API emits roughly one
    record per second, but that is not guaranteed, so the caller divides by the
    observed sample count rather than by the requested duration.
    """
    if shutil.which("fastly") is None:
        raise CollectionError("the `fastly` CLI is not on PATH")

    cmd = ["fastly", "stats", "realtime", "--service-id", service_id, "--json"]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
    except OSError as exc:
        raise CollectionError(f"could not start the fastly CLI: {exc}") from exc

    totals = {}
    samples = 0
    deadline = time.monotonic() + seconds

    try:
        # The CLI streams one JSON object per line and never terminates on its
        # own, so read line by line until the sampling window closes.
        for line in proc.stdout:
            line = line.strip()
            if line:
                try:
                    record = json.loads(line)
                except ValueError:
                    # A partial or non-JSON line is not worth aborting the run
                    # over; the sample count reflects what actually parsed.
                    continue
                aggregated = record.get("aggregated")
                if isinstance(aggregated, dict):
                    samples += 1
                    for key, value in aggregated.items():
                        if isinstance(value, (int, float)):
                            totals[key] = totals.get(key, 0) + value
            if time.monotonic() >= deadline:
                break
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    if samples == 0:
        stderr = (proc.stderr.read() or "").strip() if proc.stderr else ""
        detail = f": {stderr}" if stderr else ""
        raise CollectionError(f"no samples returned for service {service_id}{detail}")

    return totals, samples


def sample_both(seconds):
    """Sample both services over the SAME wall-clock window, concurrently.

    Byte offload is a ratio between a counter on the VCL service and one on the
    Compute service. Sampling them sequentially would compare two different
    windows and produce a meaningless ratio, so both are collected in parallel.
    """
    results = {}

    def collect(name, service_id):
        try:
            results[name] = sample_service(service_id, seconds)
        except CollectionError as exc:
            results[name] = exc

    threads = [
        threading.Thread(target=collect, args=("vcl", VCL_SERVICE)),
        threading.Thread(target=collect, args=("compute", COMPUTE_SERVICE)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        # Allow generous headroom over the sampling window for CLI startup and
        # teardown, but never block forever if the CLI wedges.
        thread.join(timeout=seconds + 30)

    for name in ("vcl", "compute"):
        outcome = results.get(name)
        if outcome is None:
            raise CollectionError(f"sampling {name} did not finish in time")
        if isinstance(outcome, CollectionError):
            raise outcome

    return results["vcl"], results["compute"]


def per_hour(total, samples):
    """Extrapolate a counter summed over `samples` seconds to an hourly rate."""
    if samples <= 0:
        return 0.0
    return total / samples * SECONDS_PER_HOUR


def build_report(vcl, vcl_samples, compute, compute_samples):
    """Convert raw counters into per-hour volumes and dollar burn rates."""
    delivered_bytes_hr = per_hour(vcl.get("resp_body_bytes", 0), vcl_samples)
    requests_hr = per_hour(vcl.get("requests", 0), vcl_samples)
    hits_hr = per_hour(vcl.get("hits", 0), vcl_samples)
    errors_hr = per_hour(vcl.get("errors", 0), vcl_samples)

    # Bytes Compute pulled from its backends. Predominantly GCS reads, so this
    # stands in for Google's egress bill.
    origin_bytes_hr = per_hour(
        compute.get("compute_beresp_body_bytes", 0), compute_samples
    )
    compute_requests_hr = per_hour(compute.get("compute_requests", 0), compute_samples)
    compute_ms_hr = per_hour(
        compute.get("compute_request_time_billed_ms", 0), compute_samples
    )
    class_a_hr = per_hour(
        compute.get("kv_store_class_a_operations", 0), compute_samples
    )
    class_b_hr = per_hour(
        compute.get("kv_store_class_b_operations", 0), compute_samples
    )

    costs = {
        "viewer_delivery": delivered_bytes_hr / GB * RATES["fastly_delivery_per_gb"],
        "gcs_egress": origin_bytes_hr / GB * RATES["gcs_egress_per_gb"],
        "fastly_requests": requests_hr / 10_000 * RATES["fastly_requests_per_10k"],
        "compute": (
            compute_requests_hr / 1e6 * RATES["compute_requests_per_million"]
            + compute_ms_hr / 1e6 * RATES["compute_vcpu_ms_per_million"]
        ),
        "kv_operations": (
            class_a_hr / 1_000 * RATES["kv_class_a_per_1k"]
            + class_b_hr / 1_000 * RATES["kv_class_b_per_1k"]
        ),
    }
    costs["TOTAL"] = sum(costs.values())

    # Byte offload is the leading indicator for the GCS egress line: it moves
    # before the dollar figure does, and a drop predicts an origin cost spike.
    byte_offload = None
    if delivered_bytes_hr > 0:
        byte_offload = (1 - origin_bytes_hr / delivered_bytes_hr) * 100

    return {
        "volumes": {
            "delivered_gb_per_hour": delivered_bytes_hr / GB,
            "origin_gb_per_hour": origin_bytes_hr / GB,
            "requests_per_hour": requests_hr,
            "requests_per_second": requests_hr / SECONDS_PER_HOUR,
            "gbps_delivered": delivered_bytes_hr * 8 / SECONDS_PER_HOUR / 1e9,
            "errors_per_hour": errors_hr,
            "request_hit_ratio_pct": (hits_hr / requests_hr * 100) if requests_hr else None,
            "byte_offload_pct": byte_offload,
        },
        "costs_per_hour": costs,
        "costs_per_day": {k: v * 24 for k, v in costs.items()},
        "costs_per_month": {k: v * 24 * 30 for k, v in costs.items()},
        "samples": {"vcl": vcl_samples, "compute": compute_samples},
    }


def evaluate(report):
    """Return (worst_severity, [alert strings]) for the report's cost lines."""
    alerts = []
    worst = 0
    for line, cost in report["costs_per_hour"].items():
        limits = THRESHOLDS.get(line)
        if not limits:
            continue
        if cost >= limits["critical"]:
            worst = max(worst, 2)
            alerts.append(
                f"CRITICAL  {line}: ${cost:,.2f}/hr "
                f"(threshold ${limits['critical']:,.2f}) "
                f"= ${cost * 24 * 30:,.0f}/mo at this rate"
            )
        elif cost >= limits["warn"]:
            worst = max(worst, 1)
            alerts.append(
                f"WARNING   {line}: ${cost:,.2f}/hr "
                f"(threshold ${limits['warn']:,.2f}) "
                f"= ${cost * 24 * 30:,.0f}/mo at this rate"
            )

    # Byte offload falling is an early warning that the origin cost line is
    # about to climb, so surface it even when the dollar figure is still low.
    offload = report["volumes"]["byte_offload_pct"]
    if offload is not None and offload < 50:
        worst = max(worst, 1)
        alerts.append(
            f"WARNING   byte offload has fallen to {offload:.1f}% "
            "— origin cost will follow"
        )

    return worst, alerts


def render(report, alerts):
    v = report["volumes"]
    c = report["costs_per_hour"]

    print(
        f"Sampled {report['samples']['vcl']}s of VCL and "
        f"{report['samples']['compute']}s of Compute real-time stats"
    )
    print()
    print("VOLUME")
    print(f"  delivered to viewers : {v['delivered_gb_per_hour']:,.2f} GB/hr "
          f"({v['gbps_delivered']:,.2f} Gbps)")
    print(f"  fetched from origin  : {v['origin_gb_per_hour']:,.2f} GB/hr")
    print(f"  requests             : {v['requests_per_second']:,.0f}/sec")
    if v["request_hit_ratio_pct"] is not None:
        print(f"  request hit ratio    : {v['request_hit_ratio_pct']:.1f}%")
    if v["byte_offload_pct"] is not None:
        print(f"  byte offload         : {v['byte_offload_pct']:.1f}%")
    print(f"  errors               : {v['errors_per_hour']:,.0f}/hr")
    print()
    print("BURN RATE (list rates — assumptions, not invoiced amounts)")
    for line in ("viewer_delivery", "gcs_egress", "fastly_requests", "compute",
                 "kv_operations"):
        print(f"  {line:<20s} : ${c[line]:>10,.2f}/hr   "
              f"${report['costs_per_month'][line]:>12,.0f}/mo at this rate")
    print(f"  {'TOTAL':<20s} : ${c['TOTAL']:>10,.2f}/hr   "
          f"${report['costs_per_month']['TOTAL']:>12,.0f}/mo at this rate")
    print()

    if alerts:
        print("ALERTS")
        for alert in alerts:
            print(f"  {alert}")
    else:
        print("ALERTS\n  none — all lines below warning thresholds")


def main():
    parser = argparse.ArgumentParser(
        description="Real-time cost burn-rate monitor for Divine media delivery."
    )
    parser.add_argument(
        "--seconds", type=int, default=10,
        help="length of each sampling window (default: 10)",
    )
    parser.add_argument(
        "--watch", action="store_true",
        help="loop continuously instead of taking a single sample",
    )
    parser.add_argument(
        "--interval", type=int, default=60,
        help="seconds between samples when watching (default: 60)",
    )
    parser.add_argument(
        "--json", action="store_true", dest="as_json",
        help="emit machine-readable JSON instead of a rendered report",
    )
    args = parser.parse_args()

    if args.seconds < 1:
        parser.error("--seconds must be at least 1")

    worst_seen = 0
    while True:
        try:
            (vcl, vcl_samples), (compute, compute_samples) = sample_both(args.seconds)
        except CollectionError as exc:
            # Collection failure is itself actionable during a launch: it means
            # the monitor is blind, which must never be mistaken for "quiet".
            print(f"ERROR: could not collect stats: {exc}", file=sys.stderr)
            if not args.watch:
                return 3
            worst_seen = max(worst_seen, 3)
            time.sleep(args.interval)
            continue

        report = build_report(vcl, vcl_samples, compute, compute_samples)
        severity, alerts = evaluate(report)
        worst_seen = max(worst_seen, severity)

        if args.as_json:
            print(json.dumps({**report, "alerts": alerts, "severity": severity}))
        else:
            render(report, alerts)
        sys.stdout.flush()

        if not args.watch:
            return severity
        print()
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
