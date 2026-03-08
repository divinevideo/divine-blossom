#!/usr/bin/env python3
"""Delete, regenerate, and revalidate thumbnails for a set of video hashes."""

import argparse
import concurrent.futures
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_BUCKET = "divine-blossom-media"
DEFAULT_UPLOAD_URL = "https://blossom-upload-rust-149672065768.us-central1.run.app"
DEFAULT_MEDIA_URL = "https://media.divine.video"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Backfill thumbnails by deleting the stored JPEG, regenerating it, and revalidating the CDN URL."
    )
    parser.add_argument(
        "hashes",
        nargs="*",
        help="Optional SHA-256 hashes to repair.",
    )
    parser.add_argument(
        "--hash-file",
        help="Read one SHA-256 hash per line from this file.",
    )
    parser.add_argument(
        "--bucket",
        default=DEFAULT_BUCKET,
        help=f"GCS bucket holding thumbnail objects. Default: {DEFAULT_BUCKET}",
    )
    parser.add_argument(
        "--upload-url",
        default=DEFAULT_UPLOAD_URL,
        help=f"Upload service base URL. Default: {DEFAULT_UPLOAD_URL}",
    )
    parser.add_argument(
        "--media-url",
        default=DEFAULT_MEDIA_URL,
        help=f"Public media base URL. Default: {DEFAULT_MEDIA_URL}",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=32,
        help="Concurrent worker count. Default: 32",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Process only the first N hashes after loading input.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=100,
        help="Emit progress every N completed hashes. Default: 100",
    )
    parser.add_argument(
        "--failure-file",
        help="Write per-hash failures here.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate input and print planned count without changing anything.",
    )
    return parser.parse_args()


def load_hashes(args: argparse.Namespace) -> list[str]:
    hashes: list[str] = []

    if args.hash_file:
        with open(args.hash_file, encoding="utf-8") as handle:
            for line in handle:
                line = line.split("#", 1)[0].strip().lower()
                if line:
                    hashes.append(line)

    hashes.extend(hash_.lower() for hash_ in args.hashes)

    if not hashes:
        raise SystemExit("No hashes provided. Use positional hashes or --hash-file.")

    deduped: list[str] = []
    seen: set[str] = set()
    for hash_ in hashes:
        if len(hash_) != 64 or any(ch not in "0123456789abcdef" for ch in hash_):
            raise SystemExit(f"Invalid SHA-256 hash: {hash_}")
        if hash_ in seen:
            continue
        seen.add(hash_)
        deduped.append(hash_)

    if args.limit is not None:
        deduped = deduped[: args.limit]

    return deduped


class TokenManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._token = ""
        self._expires_at = 0.0

    def get(self, force_refresh: bool = False) -> str:
        now = time.time()
        with self._lock:
            if force_refresh or not self._token or now >= self._expires_at:
                self._token = subprocess.check_output(
                    ["gcloud", "auth", "print-access-token"], text=True
                ).strip()
                self._expires_at = now + 45 * 60
            return self._token


TOKEN_MANAGER = TokenManager()
THREAD_LOCAL = threading.local()


def get_opener():
    opener = getattr(THREAD_LOCAL, "opener", None)
    if opener is None:
        opener = urllib.request.build_opener()
        THREAD_LOCAL.opener = opener
    return opener


def request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: int = 60,
    auth: bool = False,
) -> int:
    opener = get_opener()
    final_headers = dict(headers or {})

    for attempt in range(2):
        if auth:
            token = TOKEN_MANAGER.get(force_refresh=attempt > 0)
            final_headers["Authorization"] = f"Bearer {token}"

        req = urllib.request.Request(url, method=method, headers=final_headers)
        try:
            with opener.open(req, timeout=timeout) as resp:
                return resp.status
        except urllib.error.HTTPError as exc:
            if auth and exc.code in (401, 403) and attempt == 0:
                continue
            return exc.code

    return 599


def process_hash(
    hash_: str, bucket: str, upload_url: str, media_url: str
) -> tuple[str, str | None]:
    object_name = urllib.parse.quote(f"{hash_}.jpg", safe="")
    delete_url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o/{object_name}"
    delete_status = request(delete_url, method="DELETE", auth=True)
    delete_error = None if delete_status in (200, 204, 404) else f"delete:{delete_status}"

    regenerate_status = request(f"{upload_url}/thumbnail/{hash_}")
    if regenerate_status != 200:
        errors = [err for err in (delete_error, f"regenerate:{regenerate_status}") if err]
        return hash_, ",".join(errors)

    revalidate_status = request(
        f"{media_url}/{hash_}.jpg", headers={"Cache-Control": "no-cache"}
    )
    revalidate_error = (
        None if revalidate_status == 200 else f"revalidate:{revalidate_status}"
    )

    errors = [err for err in (delete_error, revalidate_error) if err]
    return hash_, ",".join(errors) if errors else None


def main() -> None:
    args = parse_args()
    hashes = load_hashes(args)
    total = len(hashes)

    if args.dry_run:
        print(f"would_process={total}")
        return

    failure_handle = (
        open(args.failure_file, "a", encoding="utf-8") if args.failure_file else None
    )
    completed = 0
    failures = 0
    started_at = time.time()

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_hash = {
                executor.submit(
                    process_hash, hash_, args.bucket, args.upload_url, args.media_url
                ): hash_
                for hash_ in hashes
            }

            for future in concurrent.futures.as_completed(future_to_hash):
                hash_ = future_to_hash[future]
                try:
                    _, error = future.result()
                except Exception as exc:  # pragma: no cover - operational logging
                    error = f"exception:{type(exc).__name__}"

                completed += 1
                if error:
                    failures += 1
                    line = f"{hash_} {error}\n"
                    if failure_handle:
                        failure_handle.write(line)
                    else:
                        sys.stderr.write(line)

                if completed % args.progress_every == 0 or completed == total:
                    elapsed = max(time.time() - started_at, 1e-6)
                    rate = completed / elapsed
                    print(
                        f"completed={completed}/{total} failures={failures} rate={rate:.2f}/s",
                        file=sys.stderr,
                    )
    finally:
        if failure_handle:
            failure_handle.close()


if __name__ == "__main__":
    main()
