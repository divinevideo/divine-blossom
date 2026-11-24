#!/usr/bin/env python3
"""Delete, regenerate, and revalidate thumbnails for a set of video hashes."""

import argparse
import concurrent.futures
import os
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
        description=(
            "Backfill thumbnails by deleting the stored JPEG, regenerating it, "
            "and revalidating the CDN URL. Only run against a stable deployment "
            "(never during a token rollout flip, token rotation, or mixed-replica rollout)."
        )
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
    parser.add_argument(
        "--allow-non-default-upload-url",
        action="store_true",
        help="Allow sending THUMBNAIL_SERVICE_TOKEN to a non-default HTTPS upload host (or local loopback HTTP).",
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


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get_opener(*, follow_redirects: bool = True):
    attr = "opener" if follow_redirects else "no_redirect_opener"
    opener = getattr(THREAD_LOCAL, attr, None)
    if opener is None:
        opener = (
            urllib.request.build_opener()
            if follow_redirects
            else urllib.request.build_opener(NoRedirect())
        )
        setattr(THREAD_LOCAL, attr, opener)
    return opener


def request_with_headers(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: int = 60,
    auth: bool = False,
    follow_redirects: bool = True,
) -> tuple[int, dict[str, str]]:
    opener = get_opener(follow_redirects=follow_redirects)
    final_headers = dict(headers or {})

    for attempt in range(2):
        if auth:
            token = TOKEN_MANAGER.get(force_refresh=attempt > 0)
            final_headers["Authorization"] = f"Bearer {token}"

        req = urllib.request.Request(url, method=method, headers=final_headers)
        try:
            with opener.open(req, timeout=timeout) as resp:
                resp_headers = {
                    key.lower(): value.strip() for key, value in resp.headers.items()
                }
                return resp.status, resp_headers
        except urllib.error.HTTPError as exc:
            try:
                if auth and exc.code in (401, 403) and attempt == 0:
                    continue
                resp_headers = (
                    {key.lower(): value.strip() for key, value in exc.headers.items()}
                    if exc.headers is not None
                    else {}
                )
                return exc.code, resp_headers
            finally:
                exc.close()

    return 599, {}


def request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: int = 60,
    auth: bool = False,
    follow_redirects: bool = True,
) -> int:
    status, _ = request_with_headers(
        url,
        method=method,
        headers=headers,
        timeout=timeout,
        auth=auth,
        follow_redirects=follow_redirects,
    )
    return status


AUTH_STATUS_HEADER = "x-divine-thumbnail-auth"


def _classify_auth_header(raw_value: str | None) -> str:
    """Classify the auth marker without echoing raw unrecognized header values."""
    if not raw_value:
        return "missing"
    if raw_value in ("verified", "open"):
        return raw_value
    return "unexpected"


def thumbnail_service_headers() -> dict[str, str]:
    """The upload service's thumbnail token, which it can require on /thumbnail."""
    token = os.environ.get("THUMBNAIL_SERVICE_TOKEN", "").strip()
    return {"X-Divine-Thumbnail-Token": token} if token else {}


def validate_upload_url(
    upload_url: str, *, allow_non_default: bool, has_token: bool
) -> str:
    """Validate upload_url before sending credentials or deleting thumbnails."""
    normalized = upload_url.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(normalized)
    local = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    scheme_ok = parsed.scheme == "https" or (
        parsed.scheme == "http" and local and allow_non_default
    )
    if (
        not scheme_ok
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ValueError(
            "upload_url must be a bare HTTPS origin (local HTTP allowed only with --allow-non-default-upload-url)"
        )
    if has_token and normalized != DEFAULT_UPLOAD_URL and not allow_non_default:
        host = parsed.netloc or normalized
        raise ValueError(
            f"Refusing to send THUMBNAIL_SERVICE_TOKEN to non-default upload host {host} "
            "without --allow-non-default-upload-url"
        )
    return normalized


def thumbnail_token_warnings(upload_url: str) -> list[str]:
    """Operator warnings about the /thumbnail service token for this run."""
    if not os.environ.get("THUMBNAIL_SERVICE_TOKEN", "").strip():
        return [
            "warning: THUMBNAIL_SERVICE_TOKEN is not set; once the upload service "
            "requires it, every regeneration fails as regenerate:404"
        ]
    if upload_url.rstrip("/") != DEFAULT_UPLOAD_URL:
        host = urllib.parse.urlparse(upload_url).netloc or upload_url
        return [f"warning: sending THUMBNAIL_SERVICE_TOKEN to a non-default upload host: {host}"]
    return []


def preflight_thumbnail_auth(upload_url: str) -> None:
    """Confirm /thumbnail/auth-check positively verifies access before deleting any JPEGs."""
    headers = thumbnail_service_headers()
    try:
        status, resp_headers = request_with_headers(
            f"{upload_url.rstrip('/')}/thumbnail/auth-check",
            headers=headers,
            follow_redirects=False,
        )
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Upload service /thumbnail preflight failed ({exc.reason}); aborting before deleting thumbnails"
        ) from exc

    auth_kind = _classify_auth_header(resp_headers.get(AUTH_STATUS_HEADER))
    if headers:
        if status == 204 and auth_kind == "verified":
            return
        if status == 204 and auth_kind == "open":
            raise RuntimeError(
                "Upload service /thumbnail preflight reported open mode while THUMBNAIL_SERVICE_TOKEN is set; "
                "wait for a stable deployment or unset the token before deleting thumbnails"
            )
        if status == 404:
            raise RuntimeError(
                "Upload service /thumbnail preflight returned HTTP 404; "
                "check THUMBNAIL_SERVICE_TOKEN before deleting thumbnails"
            )
        raise RuntimeError(
            f"Upload service /thumbnail preflight failed before deleting thumbnails "
            f"(HTTP {status}, {AUTH_STATUS_HEADER}={auth_kind}; expected 204 verified)"
        )

    if status == 204 and auth_kind == "open":
        return
    if status == 404:
        raise RuntimeError(
            "Upload service /thumbnail preflight returned HTTP 404; "
            "target server has THUMBNAIL_SERVICE_TOKEN configured (set it before deleting thumbnails)"
        )
    raise RuntimeError(
        f"Upload service /thumbnail preflight failed before deleting thumbnails "
        f"(HTTP {status}, {AUTH_STATUS_HEADER}={auth_kind}; expected 204 open)"
    )


def process_hash(
    hash_: str, bucket: str, upload_url: str, media_url: str
) -> tuple[str, str | None]:
    object_name = urllib.parse.quote(f"{hash_}.jpg", safe="")
    delete_url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o/{object_name}"
    delete_status = request(delete_url, method="DELETE", auth=True)
    delete_error = None if delete_status in (200, 204, 404) else f"delete:{delete_status}"

    regenerate_status = request(
        f"{upload_url.rstrip('/')}/thumbnail/{hash_}",
        headers=thumbnail_service_headers(),
        follow_redirects=False,
    )
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
    has_token = bool(thumbnail_service_headers())
    try:
        upload_url = validate_upload_url(
            args.upload_url,
            allow_non_default=args.allow_non_default_upload_url,
            has_token=has_token,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    for warning in thumbnail_token_warnings(upload_url):
        print(warning, file=sys.stderr)
    hashes = load_hashes(args)
    total = len(hashes)

    if args.dry_run:
        print(f"would_process={total}")
        return

    try:
        preflight_thumbnail_auth(upload_url)
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc

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
                    process_hash, hash_, args.bucket, upload_url, args.media_url
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
