# ABOUTME: Tests for the daily infra cost report's row shape, cost math, and failure handling.
# ABOUTME: Guards the contract with divine-brain's cost_observations table.

"""Tests for scripts/infra_cost_report.py.

The emitted rows are a contract with divine-brain's `cost_observations` table,
so the shape is asserted explicitly rather than assumed.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from burn_rate_monitor import GB, RATES  # noqa: E402
from infra_cost_report import (  # noqa: E402
    FASTLY_SOURCE,
    GCP_SOURCE,
    build_fastly_rows,
    render_table,
)

DAY = "2026-08-04"

# One day of counters, sized so each line lands on a round number.
VCL = {"resp_body_bytes": 100 * GB, "requests": 1_000_000}
COMPUTE = {
    "compute_beresp_body_bytes": 50 * GB,
    "compute_requests": 500_000,
    "compute_request_time_billed_ms": 2_000_000,
}

# Every column in cost_observations that the loader must supply. `model` is part
# of the primary key there, so a row missing it would collide with siblings.
REQUIRED_KEYS = {
    "observed_for_day", "vendor", "surface", "model", "source", "cost_usd", "basis",
}


class TestFastlyRows(unittest.TestCase):
    def setUp(self):
        self.rows = build_fastly_rows(DAY, VCL, COMPUTE)

    def test_every_row_carries_the_full_cost_observation_shape(self):
        for row in self.rows:
            self.assertEqual(REQUIRED_KEYS, set(row), f"row shape drifted: {row}")

    def test_rows_are_tagged_modeled_not_actual(self):
        # Fastly publishes no rate at Divine's volumes, so these must never be
        # presented as invoiced amounts.
        for row in self.rows:
            self.assertEqual(row["basis"], "modeled")

    def test_rows_use_the_fastly_source_not_langfuse(self):
        # Sharing the langfuse source would fold infra spend into the existing
        # LLM rollup and silently move its alert thresholds.
        for row in self.rows:
            self.assertEqual(row["source"], FASTLY_SOURCE)
            self.assertNotEqual(row["source"], "langfuse")

    def test_all_rows_carry_the_requested_day(self):
        for row in self.rows:
            self.assertEqual(row["observed_for_day"], DAY)

    def test_delivery_cost_matches_the_shared_rate(self):
        delivery = next(r for r in self.rows if r["surface"] == "delivery")
        self.assertAlmostEqual(
            delivery["cost_usd"], 100 * RATES["fastly_delivery_per_gb"], places=4
        )

    def test_origin_egress_is_derived_from_compute_backend_bytes(self):
        egress = next(
            r for r in self.rows if r["surface"] == "origin-egress-observed"
        )
        self.assertAlmostEqual(
            egress["cost_usd"], 50 * RATES["gcs_egress_per_gb"], places=4
        )

    def test_zero_cost_lines_are_omitted(self):
        # An idle day should produce no rows rather than a page of zeroes.
        self.assertEqual(build_fastly_rows(DAY, {}, {}), [])

    def test_missing_counters_do_not_raise(self):
        # Fastly omits counters entirely when a metric had no activity.
        rows = build_fastly_rows(DAY, {"resp_body_bytes": GB}, {})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["surface"], "delivery")


class TestSourcesAreDistinct(unittest.TestCase):
    def test_gcp_and_fastly_sources_differ(self):
        # They land in the same table and are distinguished only by `source`.
        self.assertNotEqual(GCP_SOURCE, FASTLY_SOURCE)

    def test_neither_source_collides_with_the_existing_llm_source(self):
        self.assertNotIn("langfuse", (GCP_SOURCE, FASTLY_SOURCE))


class TestRenderTable(unittest.TestCase):
    def test_empty_report_does_not_crash(self):
        render_table([])

    def test_mixed_actual_and_modeled_renders(self):
        rows = build_fastly_rows(DAY, VCL, COMPUTE) + [
            {
                "observed_for_day": DAY, "vendor": "gcp", "surface": "Cloud Storage",
                "model": "Download Worldwide Destinations", "source": GCP_SOURCE,
                "cost_usd": 11.45, "basis": "actual",
            }
        ]
        render_table(rows)


if __name__ == "__main__":
    unittest.main()
