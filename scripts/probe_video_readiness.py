#!/usr/bin/env python3
"""Probe MP4 vs HLS readiness for a single media hash over time."""

from __future__ import annotations

import argparse
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Iterable


READY_STATUSES = {200, 206}
PROCESSING_STATUSES = {202}
HASH_PATTERN = re.compile(r"([0-9a-fA-F]{64})")
ENDPOINT_ORDER = ("mp4_720", "hls_master", "hls_variant_manifest")

VERDICT_EXPLANATIONS = {
    "mp4_ready_immediately": (
        "MP4 was already ready on the first probe, so this hash does not support "
        "the delayed-progressive hypothesis."
    ),
    "mp4_delayed_hls_ready_first": (
        "HLS was ready before progressive MP4. This supports the hypothesis that "
        "first-play failures come from MP4 readiness lag."
    ),
    "mp4_never_ready_hls_ready": (
        "HLS was ready but progressive MP4 never became ready during the probe "
        "window. This points to missing or stalled MP4 derivative generation."
    ),
    "both_delayed": (
        "Neither MP4 nor HLS was ready immediately, and MP4 was not uniquely late. "
        "This suggests general transcode latency rather than an MP4-only gap."
    ),
    "still_processing": (
        "At least one endpoint reported processing and no endpoint became ready "
        "during the probe window."
    ),
    "no_ready_endpoints_observed": (
        "No ready endpoints were observed. This does not support the hypothesis "
        "yet and may indicate the hash is missing or blocked."
    ),
}


def build_target_urls(domain: str, media_hash: str) -> dict[str, str]:
    domain = domain.strip().strip("/")
    media_hash = validate_hash(media_hash)
    return {
        "mp4_720": f"https://{domain}/{media_hash}/720p.mp4",
        "hls_master": f"https://{domain}/{media_hash}.hls",
        "hls_variant_manifest": f"https://{domain}/{media_hash}/hls/stream_720p.m3u8",
    }


def validate_hash(value: str) -> str:
    match = HASH_PATTERN.search(value.strip())
    if not match:
        raise ValueError(f"expected a 64-character media hash, got: {value!r}")
    return match.group(1).lower()


def extract_hashes(lines: Iterable[str]) -> list[str]:
    hashes: list[str] = []
    seen: set[str] = set()
    for line in lines:
        match = HASH_PATTERN.search(line)
        if not match:
            continue
        media_hash = match.group(1).lower()
        if media_hash in seen:
            continue
        seen.add(media_hash)
        hashes.append(media_hash)
    return hashes


def is_ready_status(status: int | None) -> bool:
    return status in READY_STATUSES


def _first_ready_index(observations: list[dict[str, int]], key: str) -> int | None:
    for index, observation in enumerate(observations):
        if is_ready_status(observation.get(key)):
            return index
    return None


def _first_hls_ready_index(observations: list[dict[str, int]]) -> int | None:
    indices = [
        index
        for index in (
            _first_ready_index(observations, "hls_master"),
            _first_ready_index(observations, "hls_variant_manifest"),
        )
        if index is not None
    ]
    if not indices:
        return None
    return min(indices)


def classify_observations(observations: list[dict[str, int]]) -> str:
    if not observations:
        return "no_ready_endpoints_observed"

    first_mp4_ready = _first_ready_index(observations, "mp4_720")
    first_hls_ready = _first_hls_ready_index(observations)

    if first_mp4_ready == 0:
        return "mp4_ready_immediately"

    if first_mp4_ready is not None:
        if first_hls_ready is not None and first_hls_ready < first_mp4_ready:
            return "mp4_delayed_hls_ready_first"
        return "both_delayed"

    if first_hls_ready is not None:
        return "mp4_never_ready_hls_ready"

    if any(
        status in PROCESSING_STATUSES
        for observation in observations
        for status in observation.values()
    ):
        return "still_processing"

    return "no_ready_endpoints_observed"


def verdict_explanation(verdict: str) -> str:
    return VERDICT_EXPLANATIONS.get(verdict, verdict)


def fetch_status(url: str, method: str, timeout_seconds: float) -> tuple[int, str]:
    request = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return response.status, ""
    except urllib.error.HTTPError as exc:
        return exc.code, ""
    except urllib.error.URLError as exc:
        return 0, str(exc.reason)
    except Exception as exc:  # pragma: no cover - defensive
        return 0, str(exc)


def probe_once(
    urls: dict[str, str],
    method: str = "HEAD",
    timeout_seconds: float = 10.0,
) -> dict[str, int | str | float]:
    observation: dict[str, int | str | float] = {}
    for key in ENDPOINT_ORDER:
        status, error = fetch_status(urls[key], method=method, timeout_seconds=timeout_seconds)
        observation[key] = status
        if error:
            observation[f"{key}_error"] = error
    observation["observed_at"] = datetime.now(timezone.utc).isoformat()
    return observation


def format_status(value: int | str | float | None) -> str:
    if value is None:
        return "-"
    return str(value)


def print_probe_header() -> None:
    print("attempt elapsed_s mp4_720 hls_master hls_variant_manifest")


def print_probe_row(attempt: int, elapsed_seconds: float, observation: dict[str, int | str | float]) -> None:
    print(
        f"{attempt:>7} "
        f"{elapsed_seconds:>9.1f} "
        f"{format_status(observation.get('mp4_720')):>7} "
        f"{format_status(observation.get('hls_master')):>10} "
        f"{format_status(observation.get('hls_variant_manifest')):>20}"
    )


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Probe readiness of progressive MP4 versus HLS endpoints for a media hash.",
    )
    parser.add_argument("--hash", required=True, dest="media_hash", help="64-character media hash")
    parser.add_argument("--domain", default="media.divine.video", help="media domain to probe")
    parser.add_argument(
        "--interval-seconds",
        type=float,
        default=15.0,
        help="seconds to wait between attempts",
    )
    parser.add_argument(
        "--attempts",
        type=int,
        default=5,
        help="number of probe attempts to run",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=10.0,
        help="per-request timeout in seconds",
    )
    parser.add_argument(
        "--method",
        choices=("HEAD", "GET"),
        default="HEAD",
        help="HTTP method to use for the probe",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    try:
        media_hash = validate_hash(args.media_hash)
    except ValueError as exc:
        parser.error(str(exc))

    urls = build_target_urls(args.domain, media_hash)
    observations: list[dict[str, int]] = []
    start = time.monotonic()

    print(f"hash: {media_hash}")
    print(f"domain: {args.domain}")
    print(f"method: {args.method}")
    print_probe_header()

    for attempt in range(1, args.attempts + 1):
        observation = probe_once(urls, method=args.method, timeout_seconds=args.timeout_seconds)
        elapsed_seconds = time.monotonic() - start
        print_probe_row(attempt, elapsed_seconds, observation)
        observations.append(
            {key: int(observation[key]) for key in ENDPOINT_ORDER if isinstance(observation[key], int)}
        )
        if attempt < args.attempts:
            time.sleep(args.interval_seconds)

    verdict = classify_observations(observations)
    print("")
    print(f"verdict: {verdict}")
    print(verdict_explanation(verdict))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
