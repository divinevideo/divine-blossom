#!/usr/bin/env python3
"""Audit durable vanish evidence and deterministic GCS object absence.

Only explicitly supplied content hashes are accepted. The evidence key is a
domain-separated digest, and the stored value contains no account identifier,
content hash, media bytes, reason, or request timestamp.
"""

import argparse
import hashlib
import json
import os
import sys
from typing import Optional
from urllib.parse import quote

import requests


ERASURE_DOMAIN = "divine-blossom-erasure-v1:"


def erasure_evidence_key(sha256: str) -> str:
    digest = hashlib.sha256(f"{ERASURE_DOMAIN}{sha256.lower()}".encode()).hexdigest()
    return f"erasure:v1:{digest}"


def deterministic_object_keys(sha256: str) -> list[str]:
    hash_lower = sha256.lower()
    return [
        hash_lower,
        f"{hash_lower}.jpg",
        f"{hash_lower}/hls/master.m3u8",
        f"{hash_lower}/hls/stream_720p.m3u8",
        f"{hash_lower}/hls/stream_720p.ts",
        f"{hash_lower}/hls/stream_480p.m3u8",
        f"{hash_lower}/hls/stream_480p.ts",
        f"{hash_lower}/hls/stream_720p.mp4",
        f"{hash_lower}/hls/stream_480p.mp4",
        f"{hash_lower}/vtt/main.vtt",
    ]


def fetch_erasure_evidence(store_id: str, api_token: str, sha256: str) -> Optional[dict]:
    key = quote(erasure_evidence_key(sha256), safe="")
    url = f"https://api.fastly.com/resources/stores/kv/{store_id}/keys/{key}"
    response = requests.get(url, headers={"Fastly-Key": api_token}, timeout=15)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return response.json()


def existing_objects(bucket, sha256: str) -> list[str]:
    return [key for key in deterministic_object_keys(sha256) if bucket.blob(key).exists()]


def classify_erasure(evidence: Optional[dict], survivors: list[str]) -> str:
    if evidence is None:
        return "not_recorded"
    if survivors:
        return "incomplete"
    return "complete"


def valid_hash(value: str) -> str:
    value = value.lower()
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise argparse.ArgumentTypeError("hash must be 64 hexadecimal characters")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hashes", nargs="+", type=valid_hash, metavar="SHA256")
    parser.add_argument("--bucket", default=os.environ.get("GCS_BUCKET", "divine-blossom-media"))
    args = parser.parse_args()

    api_token = os.environ.get("FASTLY_API_TOKEN")
    store_id = os.environ.get("KV_STORE_ID")
    if not api_token or not store_id:
        parser.error("FASTLY_API_TOKEN and KV_STORE_ID are required")

    try:
        from google.cloud import storage
    except ImportError:
        print("google-cloud-storage is required", file=sys.stderr)
        return 2

    bucket = storage.Client().bucket(args.bucket)
    results = []
    for sha256 in args.hashes:
        evidence = fetch_erasure_evidence(store_id, api_token, sha256)
        survivors = existing_objects(bucket, sha256)
        results.append(
            {
                "sha256": sha256,
                "status": classify_erasure(evidence, survivors),
                "surviving_objects": survivors,
            }
        )

    print(json.dumps({"results": results}, indent=2, sort_keys=True))
    return 1 if any(result["status"] == "incomplete" for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
