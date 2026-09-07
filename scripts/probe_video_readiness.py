#!/usr/bin/env python3
"""Probe MP4 vs HLS readiness for a single media hash over time."""

from __future__ import annotations

import argparse
import http.client
import json
import math
import queue
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable


READY_STATUSES = {200, 206}
PROCESSING_STATUSES = {202}
TERMINAL_STATUSES = {422}
HASH_PATTERN = re.compile(r"([0-9a-fA-F]{64})")
ENDPOINT_ORDER = ("mp4_720", "hls_master", "hls_variant_manifest")

EXIT_READY = 0
EXIT_NOT_READY = 1
EXIT_TERMINAL = 2
EXIT_USAGE_OR_NETWORK = 3


class ReadinessArgumentParser(argparse.ArgumentParser):
    usage_exit_code = 2

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(self.usage_exit_code, f"{self.prog}: error: {message}\n")


@dataclass(frozen=True)
class FetchResult:
    status: int
    network_error: str = ""
    error_code: str = ""
    message: str = ""


@dataclass(frozen=True)
class AssertionResult:
    exit_code: int
    reason: str
    observations: tuple[dict[str, int | str | float], ...]

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


def fetch_endpoint(
    url: str,
    method: str,
    timeout_seconds: float,
    auth_header: str | None = None,
) -> FetchResult:
    headers = {"Authorization": auth_header} if auth_header else {}
    request = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return FetchResult(response.status)
    except urllib.error.HTTPError as exc:
        error_code = exc.headers.get("X-Error-Code", "")
        message = ""
        try:
            if method == "GET":
                try:
                    payload = json.loads(exc.read(65_536).decode("utf-8"))
                    if isinstance(payload, dict):
                        body_error_code = payload.get("error_code")
                        body_message = payload.get("message")
                        if isinstance(body_error_code, str):
                            error_code = body_error_code
                        if isinstance(body_message, str):
                            message = body_message
                except (ValueError, OSError, http.client.HTTPException):
                    pass
        finally:
            exc.close()
        return FetchResult(exc.code, error_code=error_code, message=message)
    except urllib.error.URLError as exc:
        return FetchResult(0, network_error=str(exc.reason))
    except Exception as exc:  # pragma: no cover - defensive
        return FetchResult(0, network_error=type(exc).__name__)


def fetch_status(url: str, method: str, timeout_seconds: float) -> tuple[int, str]:
    """Return the legacy status/error tuple used by diagnostic callers."""
    result = fetch_endpoint(url, method, timeout_seconds)
    return result.status, result.network_error


def probe_once(
    urls: dict[str, str],
    method: str = "HEAD",
    timeout_seconds: float = 10.0,
    auth_header: str | None = None,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, int | str | float]:
    observation: dict[str, int | str | float] = {}
    keys = ("hls_master", "mp4_720", "hls_variant_manifest") if deadline is not None else ENDPOINT_ORDER
    for key in keys:
        request_timeout = timeout_seconds
        if deadline is not None:
            remaining = deadline - clock()
            if remaining <= 0:
                break
            request_timeout = min(request_timeout, remaining)
        if deadline is None:
            result = fetch_endpoint(urls[key], method, request_timeout, auth_header)
        else:
            # Socket timeouts do not bound DNS, redirects, or trickling bodies.
            # A daemon lets assertion callers return without waiting for that I/O.
            results: queue.Queue[FetchResult] = queue.Queue(maxsize=1)

            def fetch(url=urls[key], timeout=request_timeout, output=results):
                try:
                    output.put(fetch_endpoint(url, method, timeout, auth_header))
                except Exception as exc:
                    output.put(FetchResult(0, network_error=type(exc).__name__))

            threading.Thread(target=fetch, daemon=True).start()
            try:
                result = results.get(timeout=max(0.0, min(request_timeout, deadline - clock())))
            except queue.Empty:
                result = FetchResult(0, network_error="request deadline expired")
            if result.status == 0 and clock() >= deadline:
                observation[f"{key}_error"] = "readiness deadline expired before response"
                break
        observation[key] = result.status
        if result.network_error:
            observation[f"{key}_error"] = result.network_error
        if result.error_code:
            observation[f"{key}_error_code"] = result.error_code
        if result.message:
            observation[f"{key}_message"] = result.message
        if deadline is not None and result.status in TERMINAL_STATUSES:
            break
    observation["observed_at"] = datetime.now(timezone.utc).isoformat()
    return observation


def resolve_endpoint_state(status: int | None) -> str:
    if status in READY_STATUSES:
        return "Ready"
    if status in PROCESSING_STATUSES:
        return "Pending"
    if status in TERMINAL_STATUSES:
        return "Terminal"
    if status == 404:
        return "Unavailable"  # Public routes intentionally hide moderated blobs as 404.
    if status in {401, 403}:
        return "Blocked"
    if status == 0:
        return "NetworkError"
    return "Unknown"


def _status(value: int | str | float | None) -> int | None:
    return value if isinstance(value, int) else None


def _terminal_reason(observation: dict[str, int | str | float]) -> str | None:
    # HLS master is the reliable sentinel, but any observed 422 is terminal,
    # including on a non-required endpoint; --require narrows readiness only.
    for key in ENDPOINT_ORDER:
        if observation.get(key) in TERMINAL_STATUSES:
            code = str(observation.get(f"{key}_error_code") or "derivative_failed")
            message = str(observation.get(f"{key}_message") or "terminal derivative failure")
            return f"{key}: {code}: {message}"
    return None


def assert_readiness(
    urls: dict[str, str],
    required_endpoints: Iterable[str] = ENDPOINT_ORDER,
    deadline_seconds: float = 180.0,
    interval_seconds: float = 5.0,
    timeout_seconds: float = 10.0,
    method: str = "HEAD",
    auth_header: str | None = None,
    probe: Callable[..., dict[str, int | str | float]] = probe_once,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> AssertionResult:
    required = tuple(required_endpoints)
    invalid = set(required) - set(ENDPOINT_ORDER)
    if not required or invalid:
        raise ValueError(f"invalid required endpoints: {sorted(invalid) if invalid else 'none'}")
    if (
        not all(math.isfinite(value) for value in (deadline_seconds, interval_seconds, timeout_seconds))
        or deadline_seconds <= 0 or interval_seconds < 0 or timeout_seconds <= 0
    ):
        raise ValueError("timings must be finite; deadline and timeout positive; interval non-negative")

    deadline = clock() + deadline_seconds
    observations: list[dict[str, int | str | float]] = []

    while True:
        observation = probe(
            urls,
            method=method,
            timeout_seconds=timeout_seconds,
            auth_header=auth_header,
            deadline=deadline,
            clock=clock,
        )
        observation["elapsed_seconds"] = max(0.0, clock() - (deadline - deadline_seconds))
        observations.append(observation)

        terminal_reason = _terminal_reason(observation)
        if terminal_reason:
            return AssertionResult(EXIT_TERMINAL, terminal_reason, tuple(observations))

        remaining = deadline - clock()
        if remaining <= 0:
            return _deadline_failure(required, observation, observations)

        if all(resolve_endpoint_state(_status(observation.get(key))) == "Ready" for key in required):
            return AssertionResult(EXIT_READY, "all required endpoints are ready", tuple(observations))

        sleep(min(interval_seconds, remaining))
        if clock() >= deadline:
            return _deadline_failure(required, observation, observations)


def _deadline_failure(
    required: tuple[str, ...],
    observation: dict[str, int | str | float],
    observations: list[dict[str, int | str | float]],
) -> AssertionResult:
    reported = required
    if (
        "hls_master" not in reported
        and resolve_endpoint_state(_status(observation.get("hls_master"))) == "NetworkError"
    ):
        reported += ("hls_master",)
    states = ", ".join(_format_endpoint_result(key, observation) for key in reported)
    has_network_error = any(
        resolve_endpoint_state(_status(observation.get(key))) == "NetworkError"
        for key in reported
    )
    exit_code = EXIT_USAGE_OR_NETWORK if has_network_error else EXIT_NOT_READY
    reason = "deadline expired"
    if all(resolve_endpoint_state(_status(observation.get(key))) == "Ready" for key in required):
        reason = "readiness observed after the deadline"
    return AssertionResult(exit_code, f"{reason}; {states}", tuple(observations))


def _format_endpoint_result(
    key: str,
    observation: dict[str, int | str | float],
) -> str:
    value = observation.get(key)
    result = f"{key}={resolve_endpoint_state(_status(value))}({format_status(value)})"
    detail = observation.get(f"{key}_error")
    if detail:
        result += f": {detail}"
    return result


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


def build_argument_parser() -> ReadinessArgumentParser:
    parser = ReadinessArgumentParser(
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
        help="HTTP method (default: HEAD, or GET for authenticated assertions)",
    )
    parser.add_argument(
        "--assert",
        action="store_true",
        dest="assert_mode",
        help="exit non-zero unless required production derivatives become ready",
    )
    parser.add_argument(
        "--deadline-seconds",
        type=float,
        default=180.0,
        help="wall-clock readiness deadline in assertion mode",
    )
    parser.add_argument(
        "--require",
        nargs="+",
        choices=ENDPOINT_ORDER,
        default=list(ENDPOINT_ORDER),
        help="required endpoints in assertion mode (default: all three)",
    )
    parser.add_argument(
        "--auth-header",
        help="precomputed Authorization header; never printed (assertion mode only)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser()
    arguments = list(argv) if argv is not None else sys.argv[1:]
    if "--assert" in arguments:
        parser.usage_exit_code = EXIT_USAGE_OR_NETWORK
    args = parser.parse_args(arguments)

    try:
        media_hash = validate_hash(args.media_hash)
    except ValueError as exc:
        parser.error(str(exc))

    if args.auth_header and not args.assert_mode:
        parser.error("--auth-header is only supported with --assert")
    if args.auth_header and args.method == "HEAD":
        parser.error("authenticated assertions require GET; omit --method or use --method GET")

    method = args.method or ("GET" if args.assert_mode and args.auth_header else "HEAD")

    urls = build_target_urls(args.domain, media_hash)
    if args.assert_mode:
        try:
            result = assert_readiness(
                urls,
                required_endpoints=args.require,
                deadline_seconds=args.deadline_seconds,
                interval_seconds=args.interval_seconds,
                timeout_seconds=args.timeout_seconds,
                method=method,
                auth_header=args.auth_header,
            )
        except ValueError as exc:
            parser.error(str(exc))

        print(f"hash: {media_hash}")
        print(f"domain: {args.domain}")
        print(f"method: {method}")
        print(f"required: {','.join(args.require)}")
        print_probe_header()
        for attempt, observation in enumerate(result.observations, start=1):
            print_probe_row(attempt, float(observation.get("elapsed_seconds", 0.0)), observation)
        print("")
        print(f"assertion: {'ready' if result.exit_code == EXIT_READY else 'failed'}")
        print(f"reason: {result.reason}")
        return result.exit_code

    observations: list[dict[str, int]] = []
    start = time.monotonic()

    print(f"hash: {media_hash}")
    print(f"domain: {args.domain}")
    print(f"method: {method}")
    print_probe_header()

    for attempt in range(1, args.attempts + 1):
        observation = probe_once(urls, method=method, timeout_seconds=args.timeout_seconds)
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
