#!/usr/bin/env python3
"""Regenerate audited aspect-distorted renditions one at a time and verify them in storage."""
import argparse
from fractions import Fraction
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib import error, parse, request

HASH = re.compile(r"[0-9a-f]{64}")
DEFAULT_URL = "https://divine-transcoder-149672065768.us-central1.run.app/transcode"
# Edge aliases serve the MP4s; HLS playlists reference the TS files.
OUTPUTS = ("hls/stream_720p.mp4", "hls/stream_480p.mp4", "hls/stream_720p.ts", "hls/stream_480p.ts")
AUDIT_SCRIPT = Path(__file__).resolve().parents[1] / "cloud-run-transcoder" / "audit_aspect_renditions.py"
TOLERANCE = Fraction(1, 100)
LOCK_ERROR = re.compile(r"\block\b", re.IGNORECASE)


def load_audit():
    """Reuse the audit's geometry rules so selection and verification cannot drift."""
    spec = importlib.util.spec_from_file_location("audit_aspect_renditions", AUDIT_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def candidates(path):
    """Return audited hashes that carry a forced repair request, in file order."""
    found = []
    with Path(path).open() as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            record = json.loads(line)
            repair = record.get("request") if isinstance(record, dict) else None
            if repair is None:
                continue
            media_hash = record.get("hash")
            if (not isinstance(media_hash, str) or not HASH.fullmatch(media_hash)
                    or repair != {"hash": media_hash, "force": True}):
                raise ValueError(f"audit line {number} has a malformed repair request")
            if media_hash not in found:
                found.append(media_hash)
    return found


def repair_secret(path):
    with Path(path).open() as handle:
        secret = handle.read(4097).strip()
    if not secret or len(secret) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in secret):
        raise ValueError("repair credential must be one nonempty header-safe token")
    return secret


def endpoint_url(value):
    endpoint = parse.urlsplit(value)
    local = endpoint.hostname in {"127.0.0.1", "::1", "localhost"}
    if (not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query
            or endpoint.fragment or (endpoint.scheme != "https" and not (local and endpoint.scheme == "http"))
            or endpoint.path not in ("", "/", "/transcode")):
        raise ValueError("transcoder URL must be an HTTPS worker or transcode endpoint")
    return parse.urlunsplit((endpoint.scheme, endpoint.netloc, "/transcode", "", ""))


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def classify_error(code, body):
    """Classify an HTTP error. Only bodies the worker itself writes count as definite."""
    if code == 401:
        return "stop", "repair credential rejected"
    if code == 503 and body.strip() == b"repair not configured":
        return "stop", "repair not configured"
    if 300 <= code < 500:
        # Rejected before any work started: a redirect, bad request, or front-end denial.
        return "stop", f"unexpected HTTP {code}"
    if code == 500:
        try:
            message = json.loads(body).get("error")
        except (ValueError, AttributeError):
            message = None
        if isinstance(message, str):
            if LOCK_ERROR.search(message):
                # Lock contention, a failed release, or a stopped task: inspect the lock first.
                return "review", "worker error involves the repair lock"
            return "failed", "worker reported a repair error"
    return "review", f"HTTP {code} without a worker result"


def regenerate(endpoint, secret, media_hash, timeout):
    """Submit one forced transcode. Return (outcome, reason).

    Outcomes: "complete", "failed" (the worker answered with an error), "stop" (configuration
    or deployment problem; nothing more should be submitted), and "review" (the result is
    unknown or needs an operator before the next repair). Forced requests are never retried:
    a lost response can follow a successful write, and the writer may still hold its lock.
    """
    req = request.Request(endpoint, method="POST", headers={
        "Content-Type": "application/json", "x-divine-repair-secret": secret,
    }, data=json.dumps({"hash": media_hash, "force": True}).encode())
    try:
        with request.build_opener(NoRedirect()).open(req, timeout=timeout) as response:
            raw = response.read(65537)
            status = response.status
    except error.HTTPError as exc:
        try:
            body = exc.read(4096)
        except (OSError, http.client.HTTPException):
            body = b""
        exc.close()
        return classify_error(exc.code, body)
    except (error.URLError, OSError, http.client.HTTPException) as exc:
        return "review", f"no complete response ({type(exc).__name__}); the writer may still be running"
    try:
        payload = json.loads(raw) if status == 200 and len(raw) <= 65536 else None
    except ValueError:
        payload = None
    if not isinstance(payload, dict) or payload.get("hash") != media_hash:
        return "review", "unrecognized worker response"
    if payload.get("status") == "already_exists":
        # A revision without repair support ignores `force` and keeps the old derivatives.
        return "stop", "worker ignored force; deploy a revision with repair support"
    if payload.get("status") != "complete":
        return "review", "unrecognized worker status"
    if payload.get("repair_lock_warning"):
        return "review", "repair lock was not released"
    return "complete", ""


def b2_fetcher():
    import boto3
    from botocore.config import Config
    bucket, region = os.environ["B2_MEDIA_BUCKET"], os.environ["B2_REGION"]
    if not bucket or not re.fullmatch(r"[a-z0-9-]+", region):
        raise ValueError("invalid B2 configuration")
    client = boto3.client(
        "s3", endpoint_url=f"https://s3.{region}.backblazeb2.com", region_name=region,
        aws_access_key_id=os.environ["B2_APPLICATION_KEY_ID"],
        aws_secret_access_key=os.environ["B2_APPLICATION_KEY"],
        config=Config(signature_version="s3v4", connect_timeout=10, read_timeout=60,
                      retries={"total_max_attempts": 3}, s3={"addressing_style": "path"}))
    return lambda key, dest: client.download_file(bucket, key, str(dest))


def gcs_fetcher():
    from google.cloud import storage
    bucket = storage.Client().bucket(os.environ.get("GCS_BUCKET", "divine-blossom-media").removeprefix("gs://"))
    return lambda key, dest: bucket.blob(key).download_to_filename(str(dest), timeout=60)


FETCHERS = {"b2": b2_fetcher, "gcs": gcs_fetcher}


def verify(fetch_original, fetch_output, media_hash, probe):
    """Return the outputs whose display aspect differs from the original's; [] when all match."""
    with tempfile.TemporaryDirectory() as folder:
        original = Path(folder) / "original"
        fetch_original(media_hash, original)
        source_ratio = probe(str(original))[1]
        mismatched = []
        for key in OUTPUTS:
            local = Path(folder) / key.replace("/", "_")
            try:
                fetch_output(f"{media_hash}/{key}", local)
                ratio = probe(str(local))[1]
            except Exception:
                mismatched.append(key)
                continue
            if abs(ratio / source_ratio - 1) > TOLERANCE:
                mismatched.append(key)
        return mismatched


def read_hashes(path):
    if not path.exists():
        return set()
    return {line.split("\t", 1)[0] for line in path.read_text().splitlines() if line}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-file", required=True, type=Path,
                        help="JSONL from cloud-run-transcoder/audit_aspect_renditions.py")
    parser.add_argument("--state-dir", type=Path,
                        help="where progress files live (default: next to the audit file)")
    parser.add_argument("--storage", choices=("b2", "gcs"), default="b2",
                        help="primary store to read regenerated outputs from")
    parser.add_argument("--original-storage", choices=("gcs", "b2"), default="gcs",
                        help="store to read the unchanged original from")
    parser.add_argument("--limit", type=int, help="repair at most this many hashes")
    parser.add_argument("--timeout", type=int, default=900, help="seconds to wait per repair")
    parser.add_argument("--retry-failed", action="store_true",
                        help="resubmit hashes the worker previously reported as failed")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--transcoder-url", default=os.environ.get("TRANSCODER_URL", DEFAULT_URL))
    args = parser.parse_args(argv)
    if (args.limit is not None and args.limit < 1) or args.timeout < 1:
        parser.error("limit and timeout must be positive")
    try:
        endpoint = endpoint_url(args.transcoder_url)
        hashes = candidates(args.audit_file)
    except (OSError, ValueError) as exc:
        print(f"Cannot start: {exc}", file=sys.stderr)
        return 2

    state_dir = args.state_dir or args.audit_file.resolve().parent
    done_file = state_dir / "aspect-repair-done.txt"
    failed_file = state_dir / "aspect-repair-failed.txt"
    review_file = state_dir / "aspect-repair-review.txt"
    inflight_file = state_dir / "aspect-repair-inflight.txt"
    try:
        done, failed, review = (read_hashes(path) for path in (done_file, failed_file, review_file))
        # A hash still in flight belongs to a run that was killed mid-repair: its outcome is
        # unknown and its writer may still hold the lock, so it is never resubmitted here.
        # Terminal entries can belong to an older attempt (notably --retry-failed).
        # They cannot establish the outcome of the request this marker describes.
        interrupted = sorted(read_hashes(inflight_file))
    except OSError:
        print("Cannot read repair state", file=sys.stderr)
        return 2
    # Review entries wait for an operator to clear them; they are never resubmitted here.
    skip = done | review | set(interrupted) | (set() if args.retry_failed else failed)
    pending = [media_hash for media_hash in hashes if media_hash not in skip]
    if args.limit is not None:
        pending = pending[:args.limit]
    if args.dry_run:
        for media_hash in pending:
            print(media_hash)
        print(json.dumps({"candidates": len(hashes), "pending": len(pending),
                          "interrupted": len(interrupted)}), file=sys.stderr)
        return 0

    try:
        secret = repair_secret(os.environ["TRANSCODE_REPAIR_SECRET_FILE"])
        fetchers = {store: FETCHERS[store]() for store in {args.storage, args.original_storage}}
        probe = load_audit().probe
        state_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        # Provider errors can carry credential-bearing details.
        print("Missing/invalid TRANSCODE_REPAIR_SECRET_FILE, storage configuration or state dir",
              file=sys.stderr)
        return 2

    counts = {"repaired": 0, "failed": 0, "review": 0, "remaining": len(pending)}

    def record(path, media_hash, reason=""):
        with path.open("a") as handle:
            handle.write(media_hash + (f"\t{reason}" if reason else "") + "\n")

    def attempt(media_hash):
        outcome, reason = regenerate(endpoint, secret, media_hash, args.timeout)
        if outcome != "complete":
            return outcome, reason
        try:
            mismatched = verify(fetchers[args.original_storage], fetchers[args.storage],
                                media_hash, probe)
        except Exception:
            return "review", "verification could not read or probe the original"
        if mismatched:
            return "review", "verification failed: " + ",".join(mismatched)
        return "complete", ""

    try:
        if interrupted:
            for media_hash in interrupted:
                record(review_file, media_hash, "interrupted run; outcome unknown")
                print(f"REVIEW {media_hash}: interrupted run; outcome unknown", file=sys.stderr)
            inflight_file.unlink()
            # Inspect the interrupted repair before submitting anything else (runbook).
            return 1
        exit_code = 0
        for media_hash in pending:
            inflight_file.write_text(media_hash + "\n")
            try:
                outcome, reason = attempt(media_hash)
            except Exception as exc:
                outcome, reason = "review", f"unexpected {type(exc).__name__}; outcome unknown"
            except BaseException:
                record(review_file, media_hash, "interrupted; outcome unknown")
                inflight_file.unlink()
                raise
            if outcome == "stop":
                # The worker rejected the request before doing any work.
                inflight_file.unlink()
                print(f"STOP {media_hash}: {reason}", file=sys.stderr)
                exit_code = 2
                break
            counts["remaining"] -= 1
            if outcome == "complete":
                record(done_file, media_hash)
                counts["repaired"] += 1
                print(f"OK {media_hash}", file=sys.stderr)
            elif outcome == "failed":
                record(failed_file, media_hash, reason)
                counts["failed"] += 1
                exit_code = 1
                print(f"FAIL {media_hash}: {reason}", file=sys.stderr)
            else:
                record(review_file, media_hash, reason)
                counts["review"] += 1
                exit_code = 1
                print(f"REVIEW {media_hash}: {reason}", file=sys.stderr)
            inflight_file.unlink()
            if outcome == "review":
                # Inspect the lock and outputs before the next repair (runbook).
                break
    except OSError:
        print("Cannot persist repair results", file=sys.stderr)
        return 2
    print(json.dumps(counts), file=sys.stderr)
    return exit_code

if __name__ == "__main__":
    raise SystemExit(main())
