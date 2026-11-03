#!/usr/bin/env python3
# ABOUTME: Classify existing published sounds by asking the transcoder to analyze each one.
# ABOUTME: Pages Funnelcake's /api/sounds for Blossom-hosted sounds; safe to re-run.
"""Backfill sound classifications (music / sfx tags) for existing sounds.

New audio uploads are classified when they reach the transcoder's
/transcribe route. Sounds published before that need one call each to
`POST /analyze-sound` on the transcoder, which skips any sound that already
has a stored verdict, so the script can be stopped and re-run.

`/analyze-sound` takes the transcoder's `X-Divine-Transcribe-Secret`; pass it
in TRANSCRIBE_SHARED_SECRET (Secret Manager: transcribe_shared_secret).

Examples:
  python3 scripts/backfill_sound_analysis.py --transcoder-url https://<transcoder> --dry-run
  TRANSCRIBE_SHARED_SECRET=... python3 scripts/backfill_sound_analysis.py \
      --transcoder-url https://<transcoder> --concurrency 2
"""

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, Iterator, List, Optional

DEFAULT_API_BASE = "https://api.divine.video"
BLOSSOM_HOSTS = {"media.divine.video"}
PAGE_SIZE = 100
SECRET_HEADER = "X-Divine-Transcribe-Secret"
# Outcomes that need no operator action. `missing` means the sound's blob is gone.
SETTLED = {"classified", "already_exists", "not_audio", "too_large", "missing", "in_progress"}


def is_sha256(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower())


def blossom_sound_hashes(rows: Iterable[dict]) -> List[str]:
    """Hashes of sounds whose audio Blossom stores; other hosts cannot be analyzed."""
    hashes = []
    for row in rows:
        sha = str(row.get("sha256") or "").lower()
        host = urllib.parse.urlparse(str(row.get("audio_url") or "")).hostname or ""
        if is_sha256(sha) and host in BLOSSOM_HOSTS:
            hashes.append(sha)
    return hashes


def sounds_page_url(api_base: str, offset: int, limit: int = PAGE_SIZE) -> str:
    query = urllib.parse.urlencode({"sort": "recent", "limit": limit, "offset": offset})
    return f"{api_base.rstrip('/')}/api/sounds?{query}"


def _get_json(url: str):
    with urllib.request.urlopen(url, timeout=60) as resp:
        return json.load(resp)


def iter_sound_hashes(api_base: str, max_sounds: Optional[int]) -> Iterator[str]:
    """Unique Blossom sound hashes, newest first, until the API runs dry."""
    seen = set()
    offset = 0
    while max_sounds is None or len(seen) < max_sounds:
        rows = _get_json(sounds_page_url(api_base, offset))
        if not rows:
            return
        offset += len(rows)
        for sha in blossom_sound_hashes(rows):
            if sha in seen:
                continue
            seen.add(sha)
            yield sha
            if max_sounds is not None and len(seen) >= max_sounds:
                return


def analyze(transcoder_url: str, secret: str, sha: str) -> str:
    request = urllib.request.Request(
        f"{transcoder_url.rstrip('/')}/analyze-sound",
        data=json.dumps({"hash": sha}).encode(),
        headers={"Content-Type": "application/json", SECRET_HEADER: secret},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as resp:
            return json.load(resp).get("status", "unknown")
    except urllib.error.HTTPError as exc:
        return f"http_{exc.code}"
    except (urllib.error.URLError, TimeoutError) as exc:
        return f"error:{type(exc).__name__}"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--transcoder-url", required=True, help="divine-transcoder base URL")
    parser.add_argument("--api-base", default=DEFAULT_API_BASE, help="Funnelcake API base URL")
    parser.add_argument("--max-sounds", type=int, default=None, help="stop after this many sounds")
    parser.add_argument(
        "--concurrency",
        type=int,
        default=2,
        help="parallel requests; keep at or below the analyzer's max-instances (default 2)",
    )
    parser.add_argument("--dry-run", action="store_true", help="list hashes without analyzing")
    args = parser.parse_args(argv)

    hashes = list(iter_sound_hashes(args.api_base, args.max_sounds))
    print(f"{len(hashes)} Blossom-hosted sounds found", file=sys.stderr)
    if args.dry_run:
        for sha in hashes:
            print(sha)
        return 0
    secret = os.environ.get("TRANSCRIBE_SHARED_SECRET", "").strip()
    if not secret:
        print("TRANSCRIBE_SHARED_SECRET is not set", file=sys.stderr)
        return 2

    outcomes: Counter = Counter()
    failed: List[str] = []
    with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
        results = pool.map(lambda sha: (sha, analyze(args.transcoder_url, secret, sha)), hashes)
        for i, (sha, status) in enumerate(results, 1):
            outcomes[status] += 1
            if status not in SETTLED:
                failed.append(sha)
                print(f"failed {sha}: {status}", file=sys.stderr)
            if i % 100 == 0:
                print(f"{i}/{len(hashes)} {dict(outcomes)}", file=sys.stderr)
    print(json.dumps(dict(outcomes), sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
