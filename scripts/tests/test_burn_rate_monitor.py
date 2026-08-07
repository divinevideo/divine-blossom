# ABOUTME: Tests for the burn-rate monitor's rate extrapolation, cost math, and alert thresholds.
# ABOUTME: Covers the pure functions so the launch-day alerting path is verified without network access.

"""Tests for scripts/burn_rate_monitor.py.

The collection path talks to the real Fastly CLI and is exercised by running the
script; these tests cover the pure logic that decides whether an alert fires,
which is the part that must not be wrong during a launch.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from burn_rate_monitor import (  # noqa: E402
    GB,
    RATES,
    THRESHOLDS,
    build_report,
    evaluate,
    format_alert_message,
    per_hour,
    should_alert,
)


class TestPerHour(unittest.TestCase):
    def test_extrapolates_to_hourly_rate(self):
        # 10 units observed over 10 samples is 1/sec, so 3600/hr.
        self.assertEqual(per_hour(10, 10), 3600.0)

    def test_uses_observed_sample_count_not_requested_duration(self):
        # The real-time API does not guarantee exactly one record per second,
        # so a short count must scale up, not silently under-report.
        self.assertEqual(per_hour(10, 5), 7200.0)

    def test_zero_samples_does_not_divide_by_zero(self):
        self.assertEqual(per_hour(100, 0), 0.0)

    def test_zero_total_is_zero(self):
        self.assertEqual(per_hour(0, 30), 0.0)


def make_report(delivered_bytes=0, origin_bytes=0, requests=0, hits=0,
                errors=0, compute_requests=0, compute_ms=0,
                class_a=0, class_b=0, samples=1):
    """Build a report from one second's worth of counters, for readability."""
    vcl = {
        "resp_body_bytes": delivered_bytes,
        "requests": requests,
        "hits": hits,
        "errors": errors,
    }
    compute = {
        "compute_beresp_body_bytes": origin_bytes,
        "compute_requests": compute_requests,
        "compute_request_time_billed_ms": compute_ms,
        "kv_store_class_a_operations": class_a,
        "kv_store_class_b_operations": class_b,
    }
    return build_report(vcl, samples, compute, samples)


class TestBuildReport(unittest.TestCase):
    def test_viewer_delivery_cost_matches_rate(self):
        # 1 GB/sec is 3600 GB/hr.
        report = make_report(delivered_bytes=GB)
        expected = 3600 * RATES["fastly_delivery_per_gb"]
        self.assertAlmostEqual(
            report["costs_per_hour"]["viewer_delivery"], expected, places=6
        )

    def test_gcs_egress_is_derived_from_compute_backend_bytes(self):
        # This is the line that appears on no Fastly invoice, so it must be
        # attributed to the Compute service's backend fetch counter.
        report = make_report(origin_bytes=GB)
        expected = 3600 * RATES["gcs_egress_per_gb"]
        self.assertAlmostEqual(
            report["costs_per_hour"]["gcs_egress"], expected, places=6
        )

    def test_total_is_the_sum_of_the_component_lines(self):
        report = make_report(
            delivered_bytes=GB, origin_bytes=GB, requests=1000,
            compute_requests=100, compute_ms=500, class_a=10, class_b=20,
        )
        costs = report["costs_per_hour"]
        components = sum(v for k, v in costs.items() if k != "TOTAL")
        self.assertAlmostEqual(costs["TOTAL"], components, places=9)

    def test_day_and_month_projections_scale_from_hourly(self):
        report = make_report(delivered_bytes=GB)
        hourly = report["costs_per_hour"]["TOTAL"]
        self.assertAlmostEqual(report["costs_per_day"]["TOTAL"], hourly * 24, places=9)
        self.assertAlmostEqual(
            report["costs_per_month"]["TOTAL"], hourly * 24 * 30, places=9
        )

    def test_byte_offload_matches_the_historical_definition(self):
        # Same formula as scripts/monitor-vcl-cache.sh: 1 - origin/delivered.
        report = make_report(delivered_bytes=100 * GB, origin_bytes=15 * GB)
        self.assertAlmostEqual(report["volumes"]["byte_offload_pct"], 85.0, places=6)

    def test_byte_offload_goes_negative_when_origin_exceeds_delivery(self):
        # Ranged misses pulling whole objects genuinely produce this, so the
        # metric must not be clamped — a negative value is real signal.
        report = make_report(delivered_bytes=10 * GB, origin_bytes=15 * GB)
        self.assertLess(report["volumes"]["byte_offload_pct"], 0)

    def test_byte_offload_is_none_when_nothing_was_delivered(self):
        report = make_report(delivered_bytes=0, origin_bytes=0)
        self.assertIsNone(report["volumes"]["byte_offload_pct"])

    def test_hit_ratio_is_none_when_there_are_no_requests(self):
        report = make_report(requests=0, hits=0)
        self.assertIsNone(report["volumes"]["request_hit_ratio_pct"])

    def test_gbps_conversion_uses_bits(self):
        # 1 GB/sec delivered is 8 Gbps.
        report = make_report(delivered_bytes=GB)
        self.assertAlmostEqual(report["volumes"]["gbps_delivered"], 8.0, places=6)

    def test_idle_service_reports_zero_and_no_alerts(self):
        report = make_report()
        self.assertEqual(report["costs_per_hour"]["TOTAL"], 0.0)
        severity, alerts = evaluate(report)
        self.assertEqual(severity, 0)
        self.assertEqual(alerts, [])


class TestEvaluate(unittest.TestCase):
    def _report_with(self, line, cost_per_hour):
        """A report whose only signal is one cost line at a chosen rate."""
        report = make_report(delivered_bytes=0, origin_bytes=0)
        report["costs_per_hour"] = {k: 0.0 for k in THRESHOLDS}
        report["costs_per_hour"][line] = cost_per_hour
        return report

    def test_below_warning_is_quiet(self):
        report = self._report_with(
            "viewer_delivery", THRESHOLDS["viewer_delivery"]["warn"] - 1
        )
        severity, alerts = evaluate(report)
        self.assertEqual(severity, 0)
        self.assertEqual(alerts, [])

    def test_warning_threshold_is_inclusive(self):
        report = self._report_with(
            "viewer_delivery", THRESHOLDS["viewer_delivery"]["warn"]
        )
        severity, alerts = evaluate(report)
        self.assertEqual(severity, 1)
        self.assertIn("WARNING", alerts[0])

    def test_critical_threshold_is_inclusive_and_outranks_warning(self):
        report = self._report_with(
            "viewer_delivery", THRESHOLDS["viewer_delivery"]["critical"]
        )
        severity, alerts = evaluate(report)
        self.assertEqual(severity, 2)
        self.assertIn("CRITICAL", alerts[0])

    def test_worst_severity_wins_across_lines(self):
        report = make_report()
        report["costs_per_hour"] = {k: 0.0 for k in THRESHOLDS}
        report["costs_per_hour"]["viewer_delivery"] = THRESHOLDS["viewer_delivery"]["warn"]
        report["costs_per_hour"]["gcs_egress"] = THRESHOLDS["gcs_egress"]["critical"]
        severity, alerts = evaluate(report)
        self.assertEqual(severity, 2)
        self.assertEqual(len(alerts), 2)

    def test_falling_byte_offload_warns_before_the_dollar_figure_moves(self):
        # The whole point: offload drops first, origin cost follows.
        report = make_report(delivered_bytes=100 * GB, origin_bytes=60 * GB)
        report["costs_per_hour"] = {k: 0.0 for k in THRESHOLDS}
        severity, alerts = evaluate(report)
        self.assertEqual(severity, 1)
        self.assertTrue(any("byte offload" in a for a in alerts))

    def test_healthy_offload_does_not_warn(self):
        report = make_report(delivered_bytes=100 * GB, origin_bytes=15 * GB)
        report["costs_per_hour"] = {k: 0.0 for k in THRESHOLDS}
        severity, alerts = evaluate(report)
        self.assertEqual(severity, 0)

    def test_launch_scale_traffic_trips_critical(self):
        # 3M DAU is ~734 TB/day, or ~30.6 TB/hr. This must page, loudly.
        report = make_report(delivered_bytes=30.6e12 / 3600)
        severity, alerts = evaluate(report)
        self.assertEqual(severity, 2)
        self.assertTrue(any("CRITICAL" in a and "viewer_delivery" in a for a in alerts))


class TestShouldAlert(unittest.TestCase):
    COOLDOWN = 900

    def test_escalation_sends_immediately_despite_cooldown(self):
        # A spike must never wait out a cooldown started by a lesser alert.
        self.assertTrue(
            should_alert(2, 1, last_sent_at=100.0, cooldown=self.COOLDOWN, now=101.0)
        )

    def test_first_alert_at_a_severity_sends(self):
        self.assertTrue(
            should_alert(1, 0, last_sent_at=None, cooldown=self.COOLDOWN, now=0.0)
        )

    def test_steady_state_is_suppressed_within_cooldown(self):
        self.assertFalse(
            should_alert(2, 2, last_sent_at=100.0, cooldown=self.COOLDOWN, now=500.0)
        )

    def test_steady_state_repeats_after_cooldown(self):
        self.assertTrue(
            should_alert(2, 2, last_sent_at=100.0, cooldown=self.COOLDOWN, now=1100.0)
        )

    def test_recovery_to_ok_sends_once(self):
        self.assertTrue(
            should_alert(0, 2, last_sent_at=100.0, cooldown=self.COOLDOWN, now=101.0)
        )

    def test_staying_ok_stays_quiet(self):
        self.assertFalse(
            should_alert(0, 0, last_sent_at=100.0, cooldown=self.COOLDOWN, now=99999.0)
        )

    def test_de_escalation_is_not_treated_as_recovery(self):
        # Critical falling to warning is still a problem, so it should respect
        # the cooldown rather than firing a fresh page.
        self.assertFalse(
            should_alert(1, 2, last_sent_at=100.0, cooldown=self.COOLDOWN, now=200.0)
        )


class TestFormatAlertMessage(unittest.TestCase):
    def test_includes_severity_burn_rate_and_alert_detail(self):
        # 2 GB/sec delivered is $864/hr, clear of the $500 critical threshold.
        report = make_report(delivered_bytes=2 * GB, origin_bytes=GB)
        severity, alerts = evaluate(report)
        self.assertEqual(severity, 2)
        message = format_alert_message(severity, alerts, report)
        self.assertIn("CRITICAL", message)
        self.assertIn("/hr", message)
        self.assertIn("Gbps", message)
        self.assertIn("assumptions", message)

    def test_survives_a_missing_report_when_collection_failed(self):
        # The blind-monitor path has no report, and must still produce a
        # sendable message rather than throwing inside the alert path.
        message = format_alert_message(3, ["could not collect stats: boom"], None)
        self.assertIn("MONITOR BLIND", message)
        self.assertIn("boom", message)


if __name__ == "__main__":
    unittest.main()
