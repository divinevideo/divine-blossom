#!/usr/bin/env python3
# ABOUTME: Fetch recent videos from relay.divine.video, detect corrupted VTTs, and force retranscription
# ABOUTME: Supports authenticated worker regeneration; legacy public job mode does not bypass worker cache

from __future__ import annotations

import argparse
import json
import string
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib import error, parse, request

# Share one definition of the quality heuristics with the scanner so the two
# operator tools (and their marker lists) cannot drift apart. The scan module
# is a sibling script with no import-time side effects.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_and_repair_vtts import (  # noqa: E402
    has_instruction_echo,
    has_json_artifact,
    has_json_envelope_leak,
    vtt_spoken_text,
)


RELAY_API = "https://relay.divine.video/api"
MEDIA_URL = "https://media.divine.video"
REQUEST_TIMEOUT = 30
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


def bad_vtt_reason(body: str) -> str | None:
    """Classify a VTT body the same way the deployed gate and scanner do.

    Detectors run on the *spoken* text (not the raw body) so a leaked
    instruction split across cue boundaries — the normal one-cue-per-segment
    shape — is still seen as a contiguous phrase. Returns a short reason
    string for the operator log, or None when the body looks clean.
    """
    if has_json_artifact(body):
        return "json_artifact"
    spoken = vtt_spoken_text(body)
    if has_json_envelope_leak(spoken):
        return "json_envelope_leak"
    if has_instruction_echo(spoken):
        return "instruction_echo"
    return None


def is_bad_vtt_body(body: str) -> bool:
    return bad_vtt_reason(body) is not None


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


def trigger_authenticated_retranscription(
    transcoder_url: str, media_hash: str, timeout: int, repair_secret_file: str
) -> tuple[int, dict[str, Any]]:
    """One trusted forced-worker request; never delete artifacts or retry it."""
    endpoint = parse.urlsplit(transcoder_url)
    local = endpoint.hostname in {"127.0.0.1", "::1", "localhost"}
    if (endpoint.scheme != "https" and not (endpoint.scheme == "http" and local)) or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment or endpoint.path not in {"", "/"}:
        raise ValueError("use the approved HTTPS worker base URL without credentials or query")
    if len(media_hash) != 64 or any(c not in string.hexdigits for c in media_hash):
        raise ValueError("repair requires exactly one SHA-256 hash")
    if not 0 < timeout <= 900:
        raise ValueError("repair timeout must be between 1 and 900 seconds")
    with Path(repair_secret_file).open() as secret_file:
        secret = secret_file.read(4097).strip()
    if not secret or len(secret) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in secret):
        raise ValueError("repair credential file must contain one nonempty header-safe token")

    class NoRedirect(request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    req = request.Request(transcoder_url.rstrip("/") + "/transcribe", method="POST",
        headers={"Content-Type": "application/json", "x-divine-repair-secret": secret},
        data=json.dumps({"hash": media_hash.lower(), "force": True}).encode("utf-8"))
    try:
        with request.build_opener(NoRedirect()).open(req, timeout=timeout) as response:
            raw = response.read(65537)
            if response.status != 200 or len(raw) > 65536:
                raise RuntimeError("worker repair response was not a bounded success")
    except error.HTTPError as exc:
        raise RuntimeError(f"worker repair rejected with HTTP {exc.code}; no retry issued") from None
    except (error.URLError, TimeoutError, OSError):
        raise RuntimeError("worker repair outcome unknown; inspect worker status before retrying") from None
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("worker repair response was not valid JSON") from None
    if not isinstance(payload, dict) or payload.get("hash") != media_hash.lower() or payload.get("status") != "complete":
        raise RuntimeError("worker repair has not completed; inspect status before retrying")
    # Never print arbitrary worker response fields beside a private credential.
    return 200, {"hash": media_hash.lower(), "status": "complete"}


def trigger_retranscription(
    media_url: str, media_hash: str, timeout: int, *, transcoder_url: str | None = None, repair_secret_file: str | None = None
) -> tuple[int, dict[str, Any]]:
    if transcoder_url or repair_secret_file:
        if not transcoder_url or not repair_secret_file:
            raise ValueError("authenticated repair requires both worker URL and existing credential file")
        return trigger_authenticated_retranscription(transcoder_url, media_hash, timeout, repair_secret_file)
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
    parser.add_argument("--transcoder-url", help="Approved worker base URL for authenticated regeneration")
    parser.add_argument("--repair-secret-file", help="File containing the existing TRANSCODE_REPAIR_SECRET; never pass its value")
    parser.add_argument("--repair-hash", help="Repair one exact hash through the authenticated worker without scanning")
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
    if args.repair_hash:
        if not args.transcoder_url or not args.repair_secret_file:
            print("single-hash repair requires worker URL and existing repair credential file", file=sys.stderr)
            return 2
        if args.dry_run:
            if len(args.repair_hash) != 64 or any(c not in string.hexdigits for c in args.repair_hash):
                print("repair requires exactly one SHA-256 hash", file=sys.stderr)
                return 2
            print(json.dumps({"hash": args.repair_hash.lower(), "status": "dry_run"}))
            return 0
        try:
            _, payload = trigger_authenticated_retranscription(args.transcoder_url, args.repair_hash, args.timeout, args.repair_secret_file)
        except (ValueError, OSError, RuntimeError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(json.dumps(payload))
        return 0
    if bool(args.transcoder_url) != bool(args.repair_secret_file):
        print("authenticated repair requires both worker URL and existing credential file", file=sys.stderr)
        return 2
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

        reason = bad_vtt_reason(body)
        empty_vtt = args.check_empty and is_empty_vtt_body(body)
        if reason is None and not empty_vtt:
            summary.clean_vtts += 1
            if args.verbose:
                print(f"CLEAN {media_hash}")
            continue

        summary.bad_vtts += 1
        reason = reason or "empty"
        print(f"BAD {media_hash}: {reason}")

        if args.dry_run:
            continue

        status, payload = trigger_retranscription(
            args.media_url, media_hash, args.timeout,
            transcoder_url=args.transcoder_url, repair_secret_file=args.repair_secret_file,
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
