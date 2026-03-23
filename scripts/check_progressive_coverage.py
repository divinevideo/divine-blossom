#!/usr/bin/env python3
"""Check one-shot MP4 vs HLS availability across multiple media hashes."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from probe_video_readiness import (
    build_target_urls,
    classify_observations,
    extract_hashes,
    is_ready_status,
    probe_once,
)


def load_hash_inputs(args: argparse.Namespace) -> list[str]:
    values: list[str] = list(args.hashes)

    if args.hash_file:
        values.extend(Path(args.hash_file).read_text(encoding="utf-8").splitlines())

    if not sys.stdin.isatty():
        values.extend(sys.stdin.read().splitlines())

    hashes = extract_hashes(values)
    if not hashes:
        raise ValueError("no media hashes supplied via args, --hash-file, or stdin")
    return hashes


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check progressive MP4 and HLS readiness across multiple hashes.",
    )
    parser.add_argument("hashes", nargs="*", help="media hashes or URLs containing media hashes")
    parser.add_argument("--hash-file", help="file containing media hashes or URLs")
    parser.add_argument("--domain", default="media.divine.video", help="media domain to probe")
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
        hashes = load_hash_inputs(args)
    except ValueError as exc:
        parser.error(str(exc))

    total = len(hashes)
    mp4_ready = 0
    hls_ready = 0
    both_ready = 0
    mp4_missing_hls_ready = 0

    print("hash mp4_720 hls_master hls_variant verdict")

    for media_hash in hashes:
        observation = probe_once(
            build_target_urls(args.domain, media_hash),
            method=args.method,
            timeout_seconds=args.timeout_seconds,
        )
        status_row = {key: int(observation[key]) for key in ("mp4_720", "hls_master", "hls_variant_manifest")}
        verdict = classify_observations([status_row])
        mp4_is_ready = is_ready_status(status_row["mp4_720"])
        hls_is_ready = is_ready_status(status_row["hls_master"]) or is_ready_status(
            status_row["hls_variant_manifest"]
        )

        if mp4_is_ready:
            mp4_ready += 1
        if hls_is_ready:
            hls_ready += 1
        if mp4_is_ready and hls_is_ready:
            both_ready += 1
        if (not mp4_is_ready) and hls_is_ready:
            mp4_missing_hls_ready += 1

        print(
            f"{media_hash} "
            f"{status_row['mp4_720']:>7} "
            f"{status_row['hls_master']:>10} "
            f"{status_row['hls_variant_manifest']:>11} "
            f"{verdict}"
        )

    print("")
    print(f"total_hashes: {total}")
    print(f"mp4_ready: {mp4_ready}")
    print(f"hls_ready: {hls_ready}")
    print(f"both_ready: {both_ready}")
    print(f"mp4_missing_hls_ready: {mp4_missing_hls_ready}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
