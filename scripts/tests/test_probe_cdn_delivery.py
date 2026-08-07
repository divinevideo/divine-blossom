# ABOUTME: Unit tests for the pure measurement and classification logic in probe_cdn_delivery.py.
# ABOUTME: Covers percentile maths, per-edge summarisation, and comparison verdicts against a baseline edge.

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from probe_cdn_delivery import (  # noqa: E402
    Sample,
    compare_to_baseline,
    percentile,
    summarize,
)


class TestPercentile(unittest.TestCase):
    def test_single_value(self):
        self.assertEqual(percentile([42.0], 95), 42.0)

    def test_median_of_odd_count(self):
        self.assertEqual(percentile([1.0, 2.0, 3.0], 50), 2.0)

    def test_p95_picks_near_top(self):
        # Linear interpolation between order statistics, as numpy/pandas default.
        values = [float(n) for n in range(1, 101)]
        self.assertAlmostEqual(percentile(values, 95), 95.05, places=6)

    def test_p0_and_p100_are_bounds(self):
        values = [5.0, 1.0, 9.0]
        self.assertEqual(percentile(values, 0), 1.0)
        self.assertEqual(percentile(values, 100), 9.0)

    def test_empty_returns_none(self):
        self.assertIsNone(percentile([], 50))

    def test_unsorted_input_is_sorted(self):
        self.assertEqual(percentile([3.0, 1.0, 2.0], 50), 2.0)


class TestSummarize(unittest.TestCase):
    def _samples(self, ttfbs, size=1_000_000, ok=True):
        return [
            Sample(edge="e", region="r", ttfb_ms=t, total_ms=t + 50.0, bytes_read=size, error=None if ok else "boom")
            for t in ttfbs
        ]

    def test_counts_and_percentiles(self):
        s = summarize("edge-a", "us-east", self._samples([100.0, 200.0, 300.0]))
        self.assertEqual(s.edge, "edge-a")
        self.assertEqual(s.region, "us-east")
        self.assertEqual(s.n, 3)
        self.assertEqual(s.errors, 0)
        self.assertEqual(s.ttfb_p50_ms, 200.0)

    def test_errors_excluded_from_timing_but_counted(self):
        good = self._samples([100.0, 200.0])
        bad = self._samples([999.0], ok=False)
        s = summarize("edge-a", "us-east", good + bad)
        self.assertEqual(s.n, 3)
        self.assertEqual(s.errors, 1)
        # 999.0 must not pollute the timing distribution.
        self.assertEqual(s.ttfb_p50_ms, 150.0)

    def test_all_errors_yields_no_timings(self):
        s = summarize("edge-a", "us-east", self._samples([1.0], ok=False))
        self.assertEqual(s.errors, 1)
        self.assertIsNone(s.ttfb_p50_ms)
        self.assertIsNone(s.throughput_mbps)

    def test_throughput_uses_total_time_and_bytes(self):
        # 1 MB in 1000 ms total => 8 Mbps.
        samples = [Sample(edge="e", region="r", ttfb_ms=100.0, total_ms=1000.0, bytes_read=1_000_000, error=None)]
        s = summarize("e", "r", samples)
        self.assertAlmostEqual(s.throughput_mbps, 8.0, places=3)

    def test_empty_sample_list(self):
        s = summarize("edge-a", "us-east", [])
        self.assertEqual(s.n, 0)
        self.assertIsNone(s.ttfb_p95_ms)


class TestCompareToBaseline(unittest.TestCase):
    def _summary(self, edge, p95, errors=0, n=10):
        return summarize(
            edge,
            "us-east",
            [
                Sample(edge=edge, region="us-east", ttfb_ms=p95, total_ms=p95 + 50, bytes_read=1_000_000, error=None)
                for _ in range(n - errors)
            ]
            + [
                Sample(edge=edge, region="us-east", ttfb_ms=0.0, total_ms=0.0, bytes_read=0, error="e")
                for _ in range(errors)
            ],
        )

    def test_faster_edge_passes(self):
        base = self._summary("fastly", 200.0)
        cand = self._summary("bunny", 180.0)
        v = compare_to_baseline(cand, base, margin_pct=20.0)
        self.assertEqual(v.verdict, "PASS")

    def test_within_margin_passes(self):
        base = self._summary("fastly", 200.0)
        cand = self._summary("bunny", 235.0)  # +17.5%, inside a 20% margin
        self.assertEqual(compare_to_baseline(cand, base, margin_pct=20.0).verdict, "PASS")

    def test_beyond_margin_fails(self):
        base = self._summary("fastly", 200.0)
        cand = self._summary("bunny", 300.0)  # +50%
        v = compare_to_baseline(cand, base, margin_pct=20.0)
        self.assertEqual(v.verdict, "FAIL")
        self.assertAlmostEqual(v.delta_pct, 50.0, places=3)

    def test_errors_force_fail_regardless_of_latency(self):
        base = self._summary("fastly", 200.0)
        cand = self._summary("bunny", 100.0, errors=2)
        self.assertEqual(compare_to_baseline(cand, base, margin_pct=20.0).verdict, "FAIL")

    def test_missing_data_is_inconclusive_not_pass(self):
        base = self._summary("fastly", 200.0)
        empty = summarize("bunny", "us-east", [])
        self.assertEqual(compare_to_baseline(empty, base, margin_pct=20.0).verdict, "NO_DATA")


if __name__ == "__main__":
    unittest.main()
