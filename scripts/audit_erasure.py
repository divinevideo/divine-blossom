#!/usr/bin/env python3
"""Audit durable vanish evidence without emitting content identifiers."""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import quote

try:
    import requests
except ImportError:  # Optional until the executable audit is run.
    requests = None


ERASURE_DOMAIN = "divine-blossom-erasure-v1:"
EXPECTED_EVIDENCE = {"version": 1, "evidence": "vanish_erasure"}
INCOMPLETE = "incomplete"
NOT_RECORDED = "not_recorded"
PRESENT_UNRECORDED = "present_unrecorded"
PROBE_ERROR = "probe_error"
INVALID_EVIDENCE = "invalid_evidence"


def erasure_evidence_key(sha256: str) -> str:
    digest = hashlib.sha256(f"{ERASURE_DOMAIN}{sha256.lower()}".encode()).hexdigest()
    return f"erasure:v1:{digest}"


def valid_hash(value: str) -> str:
    value = value.strip().lower()
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError("input contains an invalid SHA-256 identifier")
    return value


def read_hash_file(path: Path) -> list[str]:
    hashes = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            hashes.append(valid_hash(line))
    return list(dict.fromkeys(hashes))


def fetch_erasure_evidence(session, store_id: str, sha256: str) -> Optional[dict]:
    key = quote(erasure_evidence_key(sha256), safe="")
    response = session.get(
        f"https://api.fastly.com/resources/stores/kv/{store_id}/keys/{key}",
        timeout=15,
    )
    if response.status_code == 404:
        return None
    response.raise_for_status()
    evidence = response.json()
    if evidence != EXPECTED_EVIDENCE:
        raise ValueError("erasure evidence has an unexpected value")
    return evidence


def existing_objects(bucket, sha256: str) -> list[str]:
    hash_lower = sha256.lower()
    return sorted(blob.name for blob in bucket.list_blobs(prefix=hash_lower))


def classify_erasure(evidence: Optional[dict], survivors: list[str]) -> str:
    if evidence is not None and evidence != EXPECTED_EVIDENCE:
        return INVALID_EVIDENCE
    if survivors:
        return INCOMPLETE if evidence is not None else PRESENT_UNRECORDED
    if evidence is None:
        return NOT_RECORDED
    return "complete"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--hash-file",
        required=True,
        type=Path,
        help="private file with one full hash per line; never print or commit it",
    )
    parser.add_argument("--bucket", default=os.environ.get("GCS_BUCKET", "divine-blossom-media"))
    args = parser.parse_args()

    api_token = os.environ.get("FASTLY_API_TOKEN")
    store_id = os.environ.get("KV_STORE_ID")
    if not api_token or not store_id:
        parser.error("FASTLY_API_TOKEN and KV_STORE_ID are required")

    try:
        hashes = read_hash_file(args.hash_file)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    try:
        if requests is None:
            raise ImportError
        from cleanup_orphan_kv import fastly_session
        from google.cloud import storage
    except ImportError:
        print("requests, cleanup_orphan_kv, and google-cloud-storage are required", file=sys.stderr)
        return 2

    session = fastly_session(api_token)
    bucket = storage.Client().bucket(args.bucket)
    counts = {}
    errors = 0

    for sha256 in hashes:
        try:
            evidence = fetch_erasure_evidence(session, store_id, sha256)
            survivors = existing_objects(bucket, sha256)
            status = classify_erasure(evidence, survivors)
        except Exception as error:
            print(f"probe failed: {type(error).__name__}", file=sys.stderr)
            status = PROBE_ERROR if not isinstance(error, ValueError) else INVALID_EVIDENCE
            errors += 1
        counts[status] = counts.get(status, 0) + 1

    print(json.dumps({"counts": dict(sorted(counts.items())), "privacy": "aggregate_only"}, indent=2))
    if errors:
        return 2
    if counts.get(INCOMPLETE, 0) or counts.get(PRESENT_UNRECORDED, 0):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
