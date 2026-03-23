#!/usr/bin/env python3
# ABOUTME: Fetch recent videos from relay.divine.video, detect corrupted VTTs, and force retranscription
# ABOUTME: Reuses the public subtitles job API instead of modifying storage directly

from __future__ import annotations

import argparse
import json
import string
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib import error, parse, request


RELAY_API = "https://relay.divine.video/api"
MEDIA_URL = "https://media.divine.video"
REQUEST_TIMEOUT = 30
JSON_CORRUPTION_MARKERS = (
    '"total_tokens"',
    '"usage":{',
    '"prompt_tokens"',
)
USER_AGENT = "divine-blossom/repair_recent_bad_vtts"


@dataclass
class RepairSummary:
    recent_hashes: int = 0
    checked_vtts: int = 0
    bad_vtts: int = 0
    clean_vtts: int = 0
    skipped_status: int = 0
    triggered_repairs: int = 0
    failed_repairs: int = 0


def extract_media_hash(video_url: str) -> str | None:
    if not video_url:
        return None

    parsed = parse.urlparse(video_url)
    if parsed.netloc.lower() != "media.divine.video":
        return None

    filename = parsed.path.rsplit("/", 1)[-1]
    stem = filename.split(".", 1)[0].lower()
    if len(stem) != 64:
        return None
    if any(ch not in string.hexdigits for ch in stem):
        return None
    return stem


def video_timestamp(video: dict[str, Any]) -> int:
    for key in ("published_at", "created_at"):
        value = video.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return 0


def collect_recent_media_hashes(
    videos: list[dict[str, Any]], cutoff_unix: int
) -> list[str]:
    hashes: list[str] = []
    seen: set[str] = set()

    for video in videos:
        if video_timestamp(video) < cutoff_unix:
            continue

        media_hash = extract_media_hash(str(video.get("video_url", "")))
        if media_hash is None or media_hash in seen:
            continue

        hashes.append(media_hash)
        seen.add(media_hash)

    return hashes


def is_bad_vtt_body(body: str) -> bool:
    return any(marker in body for marker in JSON_CORRUPTION_MARKERS)


def is_empty_vtt_body(body: str) -> bool:
    trimmed = body.strip()
    return trimmed == "" or trimmed == "WEBVTT"


def http_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    timeout: int = REQUEST_TIMEOUT,
) -> tuple[int, str]:
    req = request.Request(
        url,
        data=data,
        headers=headers or {},
        method=method,
    )

    try:
        with request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, body


def fetch_recent_hashes(
    relay_api: str,
    cutoff_unix: int,
    page_size: int,
    limit_videos: int | None,
    timeout: int,
    verbose: bool,
) -> list[str]:
    offset = 0
    recent_hashes: list[str] = []
    seen_hashes: set[str] = set()

    while True:
        url = (
            f"{relay_api.rstrip('/')}/videos?"
            f"limit={page_size}&offset={offset}"
        )
        status, body = http_request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
            timeout=timeout,
        )
        if status != 200:
            raise RuntimeError(f"relay api returned {status}: {body[:500]}")

        payload = json.loads(body)
        if not isinstance(payload, list) or not payload:
            break

        page_hashes = collect_recent_media_hashes(payload, cutoff_unix)
        for media_hash in page_hashes:
            if media_hash in seen_hashes:
                continue
            recent_hashes.append(media_hash)
            seen_hashes.add(media_hash)
            if limit_videos is not None and len(recent_hashes) >= limit_videos:
                return recent_hashes

        if verbose:
            print(
                f"fetched relay page offset={offset} size={len(payload)} "
                f"recent_hashes={len(page_hashes)}"
            )

        if not any(video_timestamp(video) >= cutoff_unix for video in payload):
            break

        offset += page_size

    return recent_hashes


def fetch_vtt(media_url: str, media_hash: str, timeout: int) -> tuple[int, str]:
    return http_request(
        f"{media_url.rstrip('/')}/{media_hash}.vtt",
        headers={
            "Accept": "text/vtt,text/plain,*/*",
            "Cache-Control": "no-cache",
            "User-Agent": USER_AGENT,
        },
        timeout=timeout,
    )


def trigger_retranscription(
    media_url: str, media_hash: str, timeout: int
) -> tuple[int, dict[str, Any]]:
    status, body = http_request(
        f"{media_url.rstrip('/')}/v1/subtitles/jobs",
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        },
        data=json.dumps(
            {"video_sha256": media_hash, "force": True}
        ).encode("utf-8"),
        timeout=timeout,
    )

    try:
        payload = json.loads(body) if body else {}
    except json.JSONDecodeError:
        payload = {"raw_body": body}
    return status, payload


def wait_for_job(
    media_url: str,
    job_id: str,
    timeout: int,
    poll_interval: float,
    poll_attempts: int,
) -> dict[str, Any]:
    for attempt in range(1, poll_attempts + 1):
        status, body = http_request(
            f"{media_url.rstrip('/')}/v1/subtitles/jobs/{job_id}",
            headers={
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
            timeout=timeout,
        )
        if status != 200:
            raise RuntimeError(f"job lookup returned {status}: {body[:500]}")

        payload = json.loads(body)
        job_status = payload.get("status", "unknown")
        print(
            f"  job {job_id}: {job_status} "
            f"(attempt {attempt}/{poll_attempts})"
        )
        if job_status in {"ready", "failed"}:
            return payload
        time.sleep(poll_interval)

    raise RuntimeError(f"timed out waiting for job {job_id}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch recent videos from relay.divine.video, detect corrupted "
            "VTTs, and force retranscription for the bad ones."
        )
    )
    parser.add_argument("--relay-api", default=RELAY_API)
    parser.add_argument("--media-url", default=MEDIA_URL)
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--page-size", type=int, default=100)
    parser.add_argument("--limit-videos", type=int)
    parser.add_argument("--sleep", type=float, default=1.0)
    parser.add_argument("--timeout", type=int, default=REQUEST_TIMEOUT)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--wait", action="store_true")
    parser.add_argument("--poll-interval", type=float, default=5.0)
    parser.add_argument("--poll-attempts", type=int, default=24)
    parser.add_argument("--check-empty", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    cutoff = datetime.now(timezone.utc) - timedelta(days=args.days)
    cutoff_unix = int(cutoff.timestamp())

    print("=== Recent Bad VTT Repair ===")
    print(f"Relay API: {args.relay_api}")
    print(f"Media URL: {args.media_url}")
    print(f"Cutoff UTC: {cutoff.isoformat()}")
    print(f"Dry run: {args.dry_run}")
    print("")

    recent_hashes = fetch_recent_hashes(
        args.relay_api,
        cutoff_unix,
        args.page_size,
        args.limit_videos,
        args.timeout,
        args.verbose,
    )

    summary = RepairSummary(recent_hashes=len(recent_hashes))
    print(f"Recent relay videos to inspect: {summary.recent_hashes}")

    for media_hash in recent_hashes:
        status, body = fetch_vtt(args.media_url, media_hash, args.timeout)
        summary.checked_vtts += 1

        if status != 200:
            summary.skipped_status += 1
            if args.verbose:
                print(f"SKIP {media_hash}: vtt status={status}")
            continue

        bad_vtt = is_bad_vtt_body(body)
        empty_vtt = args.check_empty and is_empty_vtt_body(body)
        if not bad_vtt and not empty_vtt:
            summary.clean_vtts += 1
            if args.verbose:
                print(f"CLEAN {media_hash}")
            continue

        summary.bad_vtts += 1
        reason = "json" if bad_vtt else "empty"
        print(f"BAD {media_hash}: {reason}")

        if args.dry_run:
            continue

        status, payload = trigger_retranscription(
            args.media_url, media_hash, args.timeout
        )
        if status not in (200, 202):
            summary.failed_repairs += 1
            print(f"  FAILED repair: status={status} payload={payload}")
            continue

        summary.triggered_repairs += 1
        job_id = str(payload.get("job_id", ""))
        job_status = payload.get("status", "unknown")
        print(f"  repair job {job_id or '<unknown>'}: {job_status}")

        if args.wait and job_id:
            try:
                wait_for_job(
                    args.media_url,
                    job_id,
                    args.timeout,
                    args.poll_interval,
                    args.poll_attempts,
                )
            except RuntimeError as exc:
                summary.failed_repairs += 1
                print(f"  FAILED wait: {exc}")

        time.sleep(args.sleep)

    print("")
    print("=== Summary ===")
    print(f"Recent relay hashes: {summary.recent_hashes}")
    print(f"Checked VTTs: {summary.checked_vtts}")
    print(f"Bad VTTs: {summary.bad_vtts}")
    print(f"Clean VTTs: {summary.clean_vtts}")
    print(f"Skipped non-200 VTTs: {summary.skipped_status}")
    print(f"Triggered repairs: {summary.triggered_repairs}")
    print(f"Failed repairs: {summary.failed_repairs}")

    return 0 if summary.failed_repairs == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
