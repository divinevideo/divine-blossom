#!/usr/bin/env python3
# ABOUTME: Compares CDN and origin edges by fetching identical objects and measuring TTFB and throughput.
# ABOUTME: Standard library only; run from VMs in each target region and compare candidates to a baseline edge.

"""Probe candidate delivery edges against a baseline.

The point is to answer "would a second CDN be acceptable for our traffic" without
touching the app or sending real users anywhere new. Run it from a VM in each
region that carries meaningful traffic, pointing every edge at the same content.

Example:

    ./probe_cdn_delivery.py \\
        --edge fastly=https://media.divine.video \\
        --edge bunny=https://divine-test.b-cdn.net \\
        --path /<sha256>.mp4 --path /<sha256>/720p.mp4 \\
        --baseline fastly --region ap-southeast-2 --iterations 20

Edges are compared on p95 TTFB against the baseline. Any error on a candidate
fails it outright: a cheaper edge that intermittently 5xxs is not cheaper.

Note on caching: the first fetch of a path on a cold edge measures a cache fill,
not steady-state delivery. --warmup (default 2) issues unmeasured fetches first.
"""

import argparse
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

READ_CHUNK = 65536
DEFAULT_TIMEOUT = 30.0


@dataclass
class Sample:
    """One fetch of one path from one edge."""

    edge: str
    region: str
    ttfb_ms: float
    total_ms: float
    bytes_read: int
    error: Optional[str] = None
    path: str = ""
    status: Optional[int] = None
    cache_status: Optional[str] = None


@dataclass
class Summary:
    edge: str
    region: str
    n: int
    errors: int
    ttfb_p50_ms: Optional[float] = None
    ttfb_p95_ms: Optional[float] = None
    total_p95_ms: Optional[float] = None
    throughput_mbps: Optional[float] = None
    bytes_total: int = 0
    cache_statuses: Dict[str, int] = field(default_factory=dict)


@dataclass
class Verdict:
    edge: str
    region: str
    verdict: str  # PASS | FAIL | NO_DATA
    delta_pct: Optional[float]
    reason: str


def percentile(values: List[float], p: float) -> Optional[float]:
    """Linear interpolation between order statistics (numpy/pandas default).

    Returns None for an empty input rather than raising, because a probe run
    against a broken edge legitimately produces no timings.
    """
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (p / 100.0) * (len(ordered) - 1)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    frac = rank - low
    return ordered[low] + frac * (ordered[high] - ordered[low])


def summarize(edge: str, region: str, samples: List[Sample]) -> Summary:
    """Collapse samples into per-edge statistics.

    Failed fetches are counted but excluded from timings — a request that errored
    after 20 ms would otherwise flatter the edge that dropped it.
    """
    ok = [s for s in samples if s.error is None]
    errors = len(samples) - len(ok)

    cache_statuses: Dict[str, int] = {}
    for s in ok:
        if s.cache_status:
            key = s.cache_status.strip().lower()
            cache_statuses[key] = cache_statuses.get(key, 0) + 1

    bytes_total = sum(s.bytes_read for s in ok)
    elapsed_s = sum(s.total_ms for s in ok) / 1000.0
    throughput = (bytes_total * 8.0) / elapsed_s / 1_000_000.0 if elapsed_s > 0 and bytes_total else None

    return Summary(
        edge=edge,
        region=region,
        n=len(samples),
        errors=errors,
        ttfb_p50_ms=percentile([s.ttfb_ms for s in ok], 50),
        ttfb_p95_ms=percentile([s.ttfb_ms for s in ok], 95),
        total_p95_ms=percentile([s.total_ms for s in ok], 95),
        throughput_mbps=throughput,
        bytes_total=bytes_total,
        cache_statuses=cache_statuses,
    )


def compare_to_baseline(candidate: Summary, baseline: Summary, margin_pct: float) -> Verdict:
    """Judge a candidate edge against the baseline on p95 TTFB.

    NO_DATA is deliberately distinct from FAIL: an edge we failed to measure has
    not passed, but it has not been shown to be worse either.
    """
    if candidate.n == 0 or candidate.ttfb_p95_ms is None:
        return Verdict(candidate.edge, candidate.region, "NO_DATA", None, "no successful samples")
    if baseline.ttfb_p95_ms is None or baseline.ttfb_p95_ms <= 0:
        return Verdict(candidate.edge, candidate.region, "NO_DATA", None, "baseline has no usable timings")
    if candidate.errors:
        return Verdict(
            candidate.edge,
            candidate.region,
            "FAIL",
            None,
            f"{candidate.errors}/{candidate.n} requests failed",
        )

    delta = (candidate.ttfb_p95_ms - baseline.ttfb_p95_ms) / baseline.ttfb_p95_ms * 100.0
    if delta <= margin_pct:
        return Verdict(candidate.edge, candidate.region, "PASS", delta, f"p95 TTFB {delta:+.1f}% vs baseline")
    return Verdict(
        candidate.edge,
        candidate.region,
        "FAIL",
        delta,
        f"p95 TTFB {delta:+.1f}% vs baseline, outside {margin_pct:.0f}% margin",
    )


def fetch(url: str, edge: str, region: str, path: str, timeout: float) -> Sample:
    """One measured fetch. TTFB is time to response headers; total includes the body."""
    req = urllib.request.Request(url, headers={"User-Agent": "divine-cdn-probe/1"})
    ctx = ssl.create_default_context()
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            ttfb = (time.perf_counter() - started) * 1000.0
            read = 0
            while True:
                chunk = resp.read(READ_CHUNK)
                if not chunk:
                    break
                read += len(chunk)
            total = (time.perf_counter() - started) * 1000.0
            cache = (
                resp.headers.get("x-cache")
                or resp.headers.get("cdn-cache")
                or resp.headers.get("cf-cache-status")
            )
            return Sample(edge, region, ttfb, total, read, None, path, resp.status, cache)
    except urllib.error.HTTPError as exc:
        elapsed = (time.perf_counter() - started) * 1000.0
        return Sample(edge, region, elapsed, elapsed, 0, f"HTTP {exc.code}", path, exc.code)
    except Exception as exc:  # noqa: BLE001 - any failure to fetch is a failed sample
        elapsed = (time.perf_counter() - started) * 1000.0
        return Sample(edge, region, elapsed, elapsed, 0, type(exc).__name__, path)


def parse_edge(spec: str) -> tuple:
    if "=" not in spec:
        raise argparse.ArgumentTypeError(f"--edge expects name=baseurl, got {spec!r}")
    name, base = spec.split("=", 1)
    if not name or not base.startswith(("http://", "https://")):
        raise argparse.ArgumentTypeError(f"--edge expects name=http(s)://host, got {spec!r}")
    return name, base.rstrip("/")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--edge", action="append", required=True, type=parse_edge, metavar="NAME=BASEURL")
    ap.add_argument("--path", action="append", required=True, metavar="/path")
    ap.add_argument("--baseline", required=True, help="edge name to compare the others against")
    ap.add_argument("--region", default="unknown", help="label for where this probe is running")
    ap.add_argument("--iterations", type=int, default=10, help="measured fetches per path per edge")
    ap.add_argument("--warmup", type=int, default=2, help="unmeasured fetches per path per edge first")
    ap.add_argument("--margin-pct", type=float, default=20.0, help="allowed p95 TTFB regression")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--json", metavar="FILE", help="write full results as JSON")
    args = ap.parse_args(argv)

    edges = dict(args.edge)
    if args.baseline not in edges:
        print(f"error: --baseline {args.baseline!r} is not one of {sorted(edges)}", file=sys.stderr)
        return 2

    by_edge: Dict[str, List[Sample]] = {name: [] for name in edges}
    for name, base in edges.items():
        for path in args.path:
            url = base + path
            for _ in range(max(0, args.warmup)):
                fetch(url, name, args.region, path, args.timeout)
            for _ in range(args.iterations):
                by_edge[name].append(fetch(url, name, args.region, path, args.timeout))
        print(f"probed {name}: {len(by_edge[name])} samples", file=sys.stderr)

    summaries = {name: summarize(name, args.region, s) for name, s in by_edge.items()}
    baseline = summaries[args.baseline]
    verdicts = [
        compare_to_baseline(s, baseline, args.margin_pct) for name, s in summaries.items() if name != args.baseline
    ]

    width = max(len(n) for n in edges)
    print(f"\nregion={args.region}  baseline={args.baseline}  margin={args.margin_pct:.0f}%\n")
    print(f"{'edge'.ljust(width)}  {'p50 TTFB':>9}  {'p95 TTFB':>9}  {'Mbps':>7}  {'err':>4}  verdict")
    for name, s in summaries.items():
        p50 = f"{s.ttfb_p50_ms:.0f}ms" if s.ttfb_p50_ms is not None else "-"
        p95 = f"{s.ttfb_p95_ms:.0f}ms" if s.ttfb_p95_ms is not None else "-"
        mbps = f"{s.throughput_mbps:.1f}" if s.throughput_mbps is not None else "-"
        verdict = "baseline" if name == args.baseline else next(v.verdict for v in verdicts if v.edge == name)
        print(f"{name.ljust(width)}  {p50:>9}  {p95:>9}  {mbps:>7}  {s.errors:>4}  {verdict}")

    for v in verdicts:
        print(f"\n{v.edge}: {v.verdict} — {v.reason}")

    if args.json:
        payload = {
            "region": args.region,
            "baseline": args.baseline,
            "margin_pct": args.margin_pct,
            "summaries": {k: asdict(v) for k, v in summaries.items()},
            "verdicts": [asdict(v) for v in verdicts],
            "samples": {k: [asdict(s) for s in v] for k, v in by_edge.items()},
        }
        with open(args.json, "w") as fh:
            json.dump(payload, fh, indent=2)
        print(f"\nwrote {args.json}", file=sys.stderr)

    return 0 if all(v.verdict == "PASS" for v in verdicts) else 1


if __name__ == "__main__":
    sys.exit(main())
