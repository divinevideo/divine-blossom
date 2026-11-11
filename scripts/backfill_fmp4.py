#!/usr/bin/env python3
"""Discover HLS inputs and regenerate MP4s with the existing repair credential."""
import argparse
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
import json
import os
from pathlib import Path
import re
import sys
from urllib import error, parse, request

HASH_KEY = re.compile(r"([0-9a-f]{64})/hls/stream_(?:720|480)p\.ts\Z")
DEFAULT_URL = "https://divine-transcoder-149672065768.us-central1.run.app/backfill-fmp4"


def b2_keys():
    import boto3
    from botocore.config import Config
    bucket, region = os.environ["B2_MEDIA_BUCKET"], os.environ["B2_REGION"]
    if not bucket or not re.fullmatch(r"[a-z0-9-]+", region):
        raise ValueError("invalid B2 configuration")
    client = boto3.client(
        "s3", endpoint_url=f"https://s3.{region}.backblazeb2.com", region_name=region,
        aws_access_key_id=os.environ["B2_APPLICATION_KEY_ID"],
        aws_secret_access_key=os.environ["B2_APPLICATION_KEY"],
        config=Config(signature_version="s3v4", connect_timeout=10, read_timeout=30,
                      retries={"total_max_attempts": 3}, s3={"addressing_style": "path"},
                      request_checksum_calculation="when_required",
                      response_checksum_validation="when_required"))
    for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            yield obj["Key"]


def gcs_keys():
    from google.cloud import storage
    bucket = os.environ.get("GCS_BUCKET", "divine-blossom-media").removeprefix("gs://")
    for blob in storage.Client().list_blobs(bucket, timeout=30):
        yield blob.name


def discover(source):
    seen = set()
    for keys in ([b2_keys] if source == "b2" else [gcs_keys] if source == "gcs"
                 else [b2_keys, gcs_keys]):
        for key in keys():
            match = HASH_KEY.fullmatch(key)
            if match and match[1] not in seen:
                seen.add(match[1])
                yield match[1]


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
            or endpoint.path not in ("", "/", "/backfill-fmp4")):
        raise ValueError("transcoder URL must be an HTTPS worker or backfill endpoint")
    return parse.urlunsplit((endpoint.scheme, endpoint.netloc, "/backfill-fmp4", "", ""))


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def regenerate(endpoint, secret, media_hash):
    req = request.Request(endpoint, method="POST", headers={
        "Content-Type": "application/json", "x-divine-repair-secret": secret,
    }, data=json.dumps({"hash": media_hash, "force": True}).encode())
    try:
        with request.build_opener(NoRedirect()).open(req, timeout=60) as response:
            raw = response.read(65537)
            if response.status != 200 or len(raw) > 65536:
                return False
            payload = json.loads(raw)
            return (isinstance(payload, dict) and payload.get("hash") == media_hash
                    and payload.get("status") in ("ok", "already_exists"))
    except error.HTTPError as exc:
        exc.close()
        return False
    except (error.URLError, OSError, ValueError):
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=("b2", "gcs", "both"), default="b2")
    parser.add_argument("--concurrency", type=int, default=50)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--state-dir", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--transcoder-url", default=os.environ.get("TRANSCODER_URL", DEFAULT_URL))
    args = parser.parse_args(argv)
    if args.concurrency < 1:
        parser.error("concurrency must be positive")
    try:
        endpoint = endpoint_url(args.transcoder_url)
        secret = None if args.dry_run else repair_secret(os.environ["TRANSCODE_REPAIR_SECRET_FILE"])
    except (KeyError, OSError, ValueError):
        print("Invalid worker URL or missing/invalid TRANSCODE_REPAIR_SECRET_FILE", file=sys.stderr)
        return 2

    done_file = args.state_dir / "backfill-fmp4-done.txt"
    failed_file = args.state_dir / "backfill-fmp4-failed.txt"
    try:
        done = set(done_file.read_text().splitlines()) if done_file.exists() else set()
        if not args.dry_run:
            args.state_dir.mkdir(parents=True, exist_ok=True)
            done_file.touch(exist_ok=True)
            failed_file.touch(exist_ok=True)
    except OSError:
        print("Cannot read or create backfill state", file=sys.stderr)
        return 2

    counts = {"done": 0, "failed": 0, "skipped": 0}
    discovery_failed = False

    def record(future):
        media_hash = pending.pop(future)
        try:
            successful = future.result()
        except Exception:
            successful = False
        state_file = done_file if successful else failed_file
        with state_file.open("a") as handle:
            handle.write(media_hash + "\n")
        counts["done" if successful else "failed"] += 1
        if not successful:
            print(f"FAIL {media_hash}", file=sys.stderr)

    pending = {}
    try:
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            try:
                for media_hash in discover(args.source):
                    if media_hash in done:
                        counts["skipped"] += 1
                        continue
                    if args.dry_run:
                        print(media_hash)
                        continue
                    pending[pool.submit(regenerate, endpoint, secret, media_hash)] = media_hash
                    if len(pending) >= args.concurrency:
                        finished, _ = wait(pending, return_when=FIRST_COMPLETED)
                        for future in finished:
                            record(future)
            except Exception:
                # Provider errors can carry credential-bearing URLs or response bodies.
                print("Storage discovery failed; inventory is incomplete", file=sys.stderr)
                discovery_failed = True
            finally:
                for future in as_completed(list(pending)):
                    record(future)
    except OSError:
        print("Cannot persist backfill results", file=sys.stderr)
        return 1
    print(json.dumps(counts), file=sys.stderr)
    return 1 if discovery_failed or counts["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
