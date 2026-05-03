#!/usr/bin/env python3
# ABOUTME: Scan recent + popular videos for low-quality VTTs and trigger retranscription.
# ABOUTME: Mirrors the Rust transcoder's deployed quality heuristics (JSON artifacts,
# ABOUTME: n-gram dominance, sentence-level loop hallucination, empty) so the operator
# ABOUTME: catches the same failure modes the new pipeline would reject going forward.

from __future__ import annotations

import argparse
import json
import re
import string
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from urllib import error, parse, request


RELAY_API = "https://relay.divine.video/api"
MEDIA_URL = "https://media.divine.video"
VIDEO_PAGE_URL = "https://divine.video/video"
REQUEST_TIMEOUT = 30
USER_AGENT = "divine-blossom/scan_and_repair_vtts"
PREVIEW_MAX_CHARS = 240

JSON_CORRUPTION_MARKERS = (
    '"total_tokens"',
    '"usage":{',
    '"prompt_tokens"',
    '"completion_tokens"',
    '"finish_reason"',
)

# Mirrors cloud-run-transcoder/src/main.rs `is_loop_hallucination` and
# `is_repeated_phrase_hallucination`. Keep parameters in lockstep so the
# scanner flags exactly what the deployed service would reject.
LOOP_PROBE_MIN_CHARS = 250
LOOP_PROBE_MAX_LEN = 60
LOOP_PROBE_MIN_HITS = 3
NGRAM_DOMINANCE_THRESHOLD = 0.80
NGRAM_MIN_TOKENS = 6

# Strip standard VTT cue/header lines; only the spoken text contributes to
# the heuristic checks.
TIMESTAMP_LINE_RE = re.compile(r"\d\d:\d\d[:.]\d{2,3}")
TOKEN_RE = re.compile(r"[A-Za-z0-9']+")


@dataclass
class ScanSummary:
    seen_hashes: int = 0
    checked_vtts: int = 0
    skipped_status: int = 0
    clean: int = 0
    bad: int = 0
    bad_by_reason: dict[str, int] = field(default_factory=dict)
    triggered_repairs: int = 0
    failed_repairs: int = 0


def http_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    timeout: int = REQUEST_TIMEOUT,
) -> tuple[int, str]:
    req = request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, body


def extract_media_hash(video_url: str) -> str | None:
    if not video_url:
        return None
    parsed = parse.urlparse(video_url)
    if parsed.netloc.lower() != "media.divine.video":
        return None
    stem = parsed.path.rsplit("/", 1)[-1].split(".", 1)[0].lower()
    if len(stem) != 64 or any(ch not in string.hexdigits for ch in stem):
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


def fetch_videos_page(
    relay_api: str, sort: str, limit: int, offset: int, timeout: int
) -> list[dict[str, Any]]:
    url = f"{relay_api.rstrip('/')}/videos?sort={sort}&limit={limit}&offset={offset}"
    status, body = http_request(
        url,
        headers={"Accept": "application/json", "User-Agent": USER_AGENT},
        timeout=timeout,
    )
    if status != 200:
        raise RuntimeError(f"relay api {sort} returned {status}: {body[:300]}")
    payload = json.loads(body)
    if not isinstance(payload, list):
        raise RuntimeError(f"relay api {sort} returned non-list payload")
    return payload


def collect_recent_hashes(
    relay_api: str,
    days: int,
    page_size: int,
    limit: int | None,
    timeout: int,
    verbose: bool,
) -> list[str]:
    cutoff = int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp())
    out: list[str] = []
    seen: set[str] = set()
    offset = 0
    while True:
        page = fetch_videos_page(relay_api, "recent", page_size, offset, timeout)
        if not page:
            break
        new_in_page = 0
        for video in page:
            if video_timestamp(video) < cutoff:
                continue
            sha = extract_media_hash(str(video.get("video_url", "")))
            if sha is None or sha in seen:
                continue
            out.append(sha)
            seen.add(sha)
            new_in_page += 1
            if limit is not None and len(out) >= limit:
                return out
        if verbose:
            print(f"  recent offset={offset} added={new_in_page} total={len(out)}")
        if not any(video_timestamp(v) >= cutoff for v in page):
            break
        offset += page_size
    return out


def collect_popular_hashes(
    relay_api: str,
    page_size: int,
    limit: int,
    min_views: int,
    timeout: int,
    verbose: bool,
) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    offset = 0
    while len(out) < limit:
        page = fetch_videos_page(relay_api, "popular", page_size, offset, timeout)
        if not page:
            break
        new_in_page = 0
        for video in page:
            views = int(video.get("views", 0) or 0)
            if views < min_views:
                continue
            sha = extract_media_hash(str(video.get("video_url", "")))
            if sha is None or sha in seen:
                continue
            out.append(sha)
            seen.add(sha)
            new_in_page += 1
            if len(out) >= limit:
                break
        if verbose:
            print(f"  popular offset={offset} added={new_in_page} total={len(out)}")
        if new_in_page == 0:
            break
        offset += page_size
    return out


def fetch_vtt(media_url: str, sha: str, timeout: int) -> tuple[int, str]:
    return http_request(
        f"{media_url.rstrip('/')}/{sha}.vtt",
        headers={
            "Accept": "text/vtt,text/plain,*/*",
            "Cache-Control": "no-cache",
            "User-Agent": USER_AGENT,
        },
        timeout=timeout,
    )


def vtt_spoken_text(body: str) -> str:
    """Return only the spoken transcript lines from a VTT body."""
    lines: list[str] = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line == "WEBVTT" or line.startswith(("WEBVTT ", "NOTE", "STYLE", "REGION")):
            continue
        if "-->" in line or TIMESTAMP_LINE_RE.match(line):
            continue
        if line.isdigit():
            continue
        lines.append(line)
    return " ".join(lines)


def is_empty_text(text: str) -> bool:
    return not text.strip()


def has_json_artifact(body: str) -> bool:
    return any(marker in body for marker in JSON_CORRUPTION_MARKERS)


def is_loop_hallucination(text: str) -> bool:
    """Sentence-level autoregressive loop guard.

    Mirrors `is_loop_hallucination` in cloud-run-transcoder/src/main.rs:
    take a ~60-char prefix of the whitespace-collapsed text and count its
    non-overlapping occurrences. >=3 hits flags the cue.
    """
    collapsed = " ".join(text.split())
    if len(collapsed) < LOOP_PROBE_MIN_CHARS:
        return False
    probe_len = min(LOOP_PROBE_MAX_LEN, len(collapsed) // 4)
    probe = collapsed[:probe_len]
    if not probe:
        return False
    count = 0
    cursor = 0
    while True:
        pos = collapsed.find(probe, cursor)
        if pos == -1:
            return False
        count += 1
        cursor = pos + len(probe)
        if count >= LOOP_PROBE_MIN_HITS:
            return True


def is_repeated_phrase_hallucination(text: str) -> bool:
    """Token-level n-gram dominance guard.

    Mirrors `is_repeated_phrase_hallucination` in the Rust transcoder:
    for n in {1, 2, 3}, compute coverage = min(max_count * n, n_tokens) / n_tokens.
    Flags when coverage >= 0.60. Catches "thanks thanks thanks ..." style repeats
    that the prefix-probe loop guard would miss when the loop unit is shorter
    than the 60-char probe.
    """
    tokens = TOKEN_RE.findall(text.lower())
    n = len(tokens)
    if n < NGRAM_MIN_TOKENS:
        return False
    for gram_size in (1, 2, 3):
        if n < gram_size:
            continue
        counts: dict[tuple[str, ...], int] = {}
        for i in range(n - gram_size + 1):
            key = tuple(tokens[i : i + gram_size])
            counts[key] = counts.get(key, 0) + 1
        if not counts:
            continue
        max_count = max(counts.values())
        coverage = min(max_count * gram_size, n) / n
        if coverage >= NGRAM_DOMINANCE_THRESHOLD:
            return True
    return False


def classify_vtt(body: str, *, check_empty: bool) -> str | None:
    """Return a short reason string when the VTT looks bad, else None.

    Order is intentional: cheap string checks first, then token work.
    """
    if has_json_artifact(body):
        return "json_artifact"
    text = vtt_spoken_text(body)
    if check_empty and is_empty_text(text):
        return "empty"
    if is_loop_hallucination(text):
        return "loop_hallucination"
    if is_repeated_phrase_hallucination(text):
        return "ngram_dominance"
    return None


def preview(text: str) -> str:
    text = text.strip()
    if not text:
        return "[empty]"
    if len(text) <= PREVIEW_MAX_CHARS:
        return text
    return text[:PREVIEW_MAX_CHARS] + f"... (+{len(text) - PREVIEW_MAX_CHARS} chars)"


def wait_for_new_vtt(
    media_url: str,
    sha: str,
    old_body: str,
    timeout: int,
    poll_interval: float,
    poll_attempts: int,
) -> tuple[str | None, str]:
    """Poll {sha}.vtt until body differs from old_body or attempts exhausted.

    Returns (status_label, new_spoken_text). status_label is None when the
    new VTT arrived; otherwise one of "timeout" / "still_processing".
    """
    last_body = old_body
    for _ in range(poll_attempts):
        time.sleep(poll_interval)
        status, body = fetch_vtt(media_url, sha, timeout)
        if status == 202:
            last_body = body
            continue
        if status == 200 and body != old_body:
            return None, vtt_spoken_text(body)
        last_body = body if status == 200 else last_body
    label = "still_processing" if last_body != old_body else "timeout"
    return label, vtt_spoken_text(last_body)


def trigger_retranscription(
    media_url: str, sha: str, timeout: int
) -> tuple[int, dict[str, Any]]:
    status, body = http_request(
        f"{media_url.rstrip('/')}/v1/subtitles/jobs",
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        },
        data=json.dumps({"video_sha256": sha, "force": True}).encode("utf-8"),
        timeout=timeout,
    )
    try:
        payload = json.loads(body) if body else {}
    except json.JSONDecodeError:
        payload = {"raw_body": body[:300]}
    return status, payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan recent + popular videos on relay.divine.video, classify their "
            "VTTs against the deployed quality heuristics (JSON artifact, "
            "loop hallucination, n-gram dominance, optional empty), and trigger "
            "retranscription for the bad ones."
        )
    )
    parser.add_argument("--relay-api", default=RELAY_API)
    parser.add_argument("--media-url", default=MEDIA_URL)

    parser.add_argument(
        "--sources",
        default="recent,popular",
        help="Comma list of sources to scan (recent, popular). Default: both.",
    )
    parser.add_argument("--days", type=int, default=7, help="Lookback window for recent.")
    parser.add_argument(
        "--limit-recent",
        type=int,
        default=500,
        help="Cap on recent hashes (None to disable via --no-limit-recent).",
    )
    parser.add_argument("--no-limit-recent", action="store_true")
    parser.add_argument(
        "--limit-popular",
        type=int,
        default=500,
        help="Cap on popular hashes to inspect.",
    )
    parser.add_argument(
        "--min-views",
        type=int,
        default=100,
        help="Skip popular videos below this view count.",
    )

    parser.add_argument("--page-size", type=int, default=100)
    parser.add_argument("--sleep", type=float, default=0.25, help="Pause between repairs.")
    parser.add_argument("--timeout", type=int, default=REQUEST_TIMEOUT)
    parser.add_argument("--check-empty", action="store_true")
    parser.add_argument(
        "--force-all",
        action="store_true",
        help=(
            "Skip quality classification and retranscribe every collected hash. "
            "Use this to backfill all popular videos through the new pipeline; "
            "the deployed guards will protect against bad output."
        ),
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--no-show",
        action="store_true",
        help="Suppress before/after transcript preview and video link.",
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help=(
            "Skip polling for the new VTT after retranscribe. Use for bulk "
            "runs where you don't need the after-text inline (faster)."
        ),
    )
    parser.add_argument("--poll-interval", type=float, default=4.0)
    parser.add_argument("--poll-attempts", type=int, default=20)
    return parser.parse_args()


def merged_unique(*lists: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for source in lists:
        for sha in source:
            if sha in seen:
                continue
            seen.add(sha)
            out.append(sha)
    return out


def main() -> int:
    args = parse_args()
    sources = {s.strip() for s in args.sources.split(",") if s.strip()}
    unknown = sources - {"recent", "popular"}
    if unknown:
        print(f"unknown sources: {sorted(unknown)}", file=sys.stderr)
        return 2

    print("=== VTT Scan & Repair ===")
    print(f"Relay API: {args.relay_api}")
    print(f"Media URL: {args.media_url}")
    print(f"Sources: {sorted(sources)}")
    print(
        f"Dry run: {args.dry_run}  Check empty: {args.check_empty}  "
        f"Force all: {args.force_all}"
    )
    print()

    recent: list[str] = []
    popular: list[str] = []
    if "recent" in sources:
        limit = None if args.no_limit_recent else args.limit_recent
        print(f"Fetching recent (last {args.days}d, limit={limit})...")
        recent = collect_recent_hashes(
            args.relay_api, args.days, args.page_size, limit, args.timeout, args.verbose
        )
        print(f"  -> {len(recent)} unique recent hashes")
    if "popular" in sources:
        print(
            f"Fetching popular (limit={args.limit_popular}, "
            f"min_views={args.min_views})..."
        )
        popular = collect_popular_hashes(
            args.relay_api,
            args.page_size,
            args.limit_popular,
            args.min_views,
            args.timeout,
            args.verbose,
        )
        print(f"  -> {len(popular)} unique popular hashes")

    hashes = merged_unique(recent, popular)
    summary = ScanSummary(seen_hashes=len(hashes))
    print(f"\nUnique hashes to inspect: {summary.seen_hashes}\n")

    for sha in hashes:
        # Always fetch the current VTT so we can show "before" — even in
        # --force-all mode the operator still wants to see what existed.
        cur_status, cur_body = fetch_vtt(args.media_url, sha, args.timeout)
        summary.checked_vtts += 1

        if args.force_all:
            if cur_status == 200:
                old_body = cur_body
            else:
                old_body = ""
            reason = "force_all"
            summary.bad += 1
            summary.bad_by_reason[reason] = summary.bad_by_reason.get(reason, 0) + 1
            print(f"FORCE {sha}")
        else:
            if cur_status != 200:
                summary.skipped_status += 1
                if args.verbose:
                    print(f"SKIP {sha}: vtt status={cur_status}")
                continue
            old_body = cur_body
            reason = classify_vtt(old_body, check_empty=args.check_empty)
            if reason is None:
                summary.clean += 1
                if args.verbose:
                    print(f"CLEAN {sha}")
                continue
            summary.bad += 1
            summary.bad_by_reason[reason] = summary.bad_by_reason.get(reason, 0) + 1
            print(f"BAD {sha}: {reason}")

        if not args.no_show:
            print(f"  video:  {VIDEO_PAGE_URL}/{sha}")
            print(f"  vtt:    {args.media_url.rstrip('/')}/{sha}.vtt")
            print(f"  before: {preview(vtt_spoken_text(old_body))}")

        if args.dry_run:
            continue

        rstatus, payload = trigger_retranscription(args.media_url, sha, args.timeout)
        if rstatus not in (200, 202):
            summary.failed_repairs += 1
            print(f"  FAILED repair: status={rstatus} payload={payload}")
            continue

        summary.triggered_repairs += 1
        job_id = payload.get("job_id", "<unknown>")
        job_status = payload.get("status", "unknown")
        print(f"  job:    {job_id} ({job_status})")

        if not args.no_wait and not args.no_show:
            label, after_text = wait_for_new_vtt(
                args.media_url,
                sha,
                old_body,
                args.timeout,
                args.poll_interval,
                args.poll_attempts,
            )
            tag = f" [{label}]" if label else ""
            print(f"  after:  {preview(after_text)}{tag}")

        time.sleep(args.sleep)

    print("\n=== Summary ===")
    print(f"Hashes inspected:   {summary.seen_hashes}")
    print(f"VTTs checked:       {summary.checked_vtts}")
    print(f"Skipped non-200:    {summary.skipped_status}")
    print(f"Clean:              {summary.clean}")
    print(f"Bad:                {summary.bad}")
    for reason in sorted(summary.bad_by_reason):
        print(f"  - {reason}: {summary.bad_by_reason[reason]}")
    print(f"Triggered repairs:  {summary.triggered_repairs}")
    print(f"Failed repairs:     {summary.failed_repairs}")

    return 0 if summary.failed_repairs == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
