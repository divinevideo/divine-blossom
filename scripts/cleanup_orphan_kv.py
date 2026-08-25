#!/usr/bin/env python3
"""Classify and reconcile event-referenced Blossom blobs without emitting IDs.

Input hashes stay in a local file or come from the Fastly KV key listing. Output
contains aggregate counts only. Missing bytes may be reconciled by soft-deleting
the stale metadata through the existing admin API from a curated hash file;
whole-store scans are always read-only. All other classes are
read-only because reconstructing metadata or changing moderation state without
their original evidence would weaken access controls.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Optional

import requests


class Presence(Enum):
    PRESENT = "present"
    MISSING = "missing"
    ERROR = "error"


@dataclass(frozen=True)
class MetadataProbe:
    presence: Presence
    status: Optional[str] = None
    consistent: bool = True


AVAILABLE = "available"
MISSING_BYTES = "missing_bytes"
MISSING_METADATA = "missing_metadata"
STALE_EVENT_REFERENCE = "stale_event_reference"
MODERATION_HIDDEN = "moderation_hidden"
AGE_RESTRICTED = "age_restricted"
DELETED = "deleted"
DELIVERY_PATH_FAILURE = "delivery_path_failure"
INCONSISTENT_METADATA = "inconsistent_metadata"
PROBE_ERROR = "probe_error"

EXPECTED_PUBLIC_STATUS = {
    "active": {200, 206},
    "pending": {200, 206},
    "restricted": {404},
    "banned": {404},
    "deleted": {404},
    "age_restricted": {401},
}

ACTION_BY_CLASS = {
    AVAILABLE: "none",
    MISSING_BYTES: "soft_delete_stale_metadata",
    MISSING_METADATA: "restore_original_metadata_from_verified_backup",
    STALE_EVENT_REFERENCE: "repair_at_event_source",
    MODERATION_HIDDEN: "none",
    AGE_RESTRICTED: "none",
    DELETED: "none",
    DELIVERY_PATH_FAILURE: "investigate_delivery_path",
    INCONSISTENT_METADATA: "quarantine_then_restore_original_metadata_from_verified_backup",
    PROBE_ERROR: "retry_probe",
}


def classify_blob(
    metadata: MetadataProbe,
    storage: Presence,
    public_status: Optional[int] = None,
) -> str:
    """Classify one referenced hash without retaining the hash itself."""
    if metadata.presence is Presence.ERROR or storage is Presence.ERROR:
        return PROBE_ERROR
    if public_status == -1:
        return PROBE_ERROR
    if metadata.presence is Presence.MISSING:
        return MISSING_METADATA if storage is Presence.PRESENT else STALE_EVENT_REFERENCE
    if not metadata.consistent:
        return INCONSISTENT_METADATA

    status = (metadata.status or "").lower()
    if status not in EXPECTED_PUBLIC_STATUS:
        return PROBE_ERROR
    if status == "deleted":
        if public_status is not None and public_status not in EXPECTED_PUBLIC_STATUS[status]:
            return DELIVERY_PATH_FAILURE
        return DELETED
    if status in {"restricted", "banned"}:
        if public_status is not None and public_status not in EXPECTED_PUBLIC_STATUS[status]:
            return DELIVERY_PATH_FAILURE
        return MODERATION_HIDDEN
    if status == "age_restricted":
        if public_status is not None and public_status not in EXPECTED_PUBLIC_STATUS[status]:
            return DELIVERY_PATH_FAILURE
        return AGE_RESTRICTED
    if storage is Presence.MISSING:
        return MISSING_BYTES
    if public_status is not None and public_status not in EXPECTED_PUBLIC_STATUS[status]:
        return DELIVERY_PATH_FAILURE
    return AVAILABLE


def validate_hash(value: str) -> str:
    value = value.strip().lower()
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("input contains an invalid SHA-256 identifier")
    return value


def read_hash_file(path: Path) -> list[str]:
    hashes = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            hashes.append(validate_hash(line))
    return list(dict.fromkeys(hashes))


def list_blob_hashes(store_id: str, api_token: str, hex_prefix: Optional[str]) -> list[str]:
    headers = {"Fastly-Key": api_token, "Accept": "application/json"}
    hashes: list[str] = []
    cursor: Optional[str] = None
    while True:
        params = {"limit": 1000, "prefix": "blob:"}
        if cursor:
            params["cursor"] = cursor
        response = requests.get(
            f"https://api.fastly.com/resources/stores/kv/{store_id}/keys",
            headers=headers,
            params=params,
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()
        for item in payload.get("data", []):
            key = item if isinstance(item, str) else item.get("name", item.get("key", ""))
            if not key.startswith("blob:"):
                continue
            try:
                blob_hash = validate_hash(key.removeprefix("blob:"))
            except ValueError:
                continue
            if hex_prefix is None or blob_hash.startswith(hex_prefix):
                hashes.append(blob_hash)
        cursor = payload.get("meta", {}).get("next_cursor")
        if not cursor:
            return list(dict.fromkeys(hashes))


def probe_metadata(store_id: str, api_token: str, blob_hash: str) -> MetadataProbe:
    key = requests.utils.quote(f"blob:{blob_hash}", safe="")
    try:
        response = requests.get(
            f"https://api.fastly.com/resources/stores/kv/{store_id}/keys/{key}",
            headers={"Fastly-Key": api_token},
            timeout=15,
        )
        if response.status_code == 404:
            return MetadataProbe(Presence.MISSING)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            return MetadataProbe(Presence.PRESENT, consistent=False)
        status = payload.get("status")
        required_strings = ("sha256", "type", "uploaded", "owner")
        consistent = (
            isinstance(status, str)
            and status in EXPECTED_PUBLIC_STATUS
            and all(isinstance(payload.get(field), str) for field in required_strings)
            and payload.get("sha256", "").lower() == blob_hash
            and len(payload.get("owner", "")) == 64
            and all(char in "0123456789abcdef" for char in payload.get("owner", "").lower())
            and isinstance(payload.get("size"), int)
            and payload.get("size", -1) >= 0
        )
        return MetadataProbe(Presence.PRESENT, status, consistent)
    except (requests.RequestException, ValueError):
        return MetadataProbe(Presence.ERROR)


def probe_storage(bucket: object, blob_hash: str) -> Presence:
    try:
        bucket.blob(blob_hash).reload()
        return Presence.PRESENT
    except Exception as error:  # google-cloud-storage exception types load lazily
        if error.__class__.__name__ == "NotFound":
            return Presence.MISSING
        return Presence.ERROR


def probe_public(endpoint: str, blob_hash: str) -> Optional[int]:
    try:
        response = requests.get(
            f"{endpoint.rstrip('/')}/{blob_hash}",
            headers={"Range": "bytes=0-0"},
            allow_redirects=False,
            timeout=15,
        )
        return response.status_code
    except requests.RequestException:
        return -1


def soft_delete_missing_bytes(endpoint: str, token: str, blob_hash: str) -> bool:
    try:
        response = requests.post(
            f"{endpoint.rstrip('/')}/admin/api/delete",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={
                "sha256": blob_hash,
                "reason": "Reconcile metadata whose object bytes are unavailable",
                "legal_hold": False,
            },
            timeout=30,
        )
        return response.status_code in {200, 404}
    except requests.RequestException:
        return False


def scan(
    hashes: Iterable[str],
    metadata_probe: Callable[[str], MetadataProbe],
    storage_probe: Callable[[str], Presence],
    public_probe: Optional[Callable[[str], Optional[int]]] = None,
    repair: Optional[Callable[[str], bool]] = None,
    max_repairs: int = 0,
    confirm_missing_count: Optional[int] = None,
    curated_input: bool = False,
) -> dict[str, object]:
    counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    repair_counts: Counter[str] = Counter()
    classifications: list[tuple[str, str]] = []
    for blob_hash in hashes:
        metadata = metadata_probe(blob_hash)
        storage = storage_probe(blob_hash)
        public_status = public_probe(blob_hash) if public_probe else None
        classification = classify_blob(metadata, storage, public_status)
        counts[classification] += 1
        action_counts[ACTION_BY_CLASS[classification]] += 1
        classifications.append((blob_hash, classification))

    repair_candidates = [
        blob_hash
        for blob_hash, classification in classifications
        if classification == MISSING_BYTES
    ]
    if repair and not curated_input:
        raise ValueError("repair requires a curated hash file")
    if repair and confirm_missing_count is None:
        raise ValueError("repair requires the confirmed missing-byte count from a prior scan")
    # Curation is the defence against a systematically wrong storage probe.
    # Count equality detects drift between the read-only and repair scans.
    if repair and len(repair_candidates) > max_repairs:
        repair_counts["skipped_over_limit"] = len(repair_candidates)
    # Aggregate-only output cannot bind approval to specific hashes. Equality is
    # deliberately a blast-radius check, while every candidate is reclassified.
    elif repair and len(repair_candidates) != confirm_missing_count:
        repair_counts["skipped_count_mismatch"] = len(repair_candidates)
    elif repair:
        for blob_hash in repair_candidates:
            repair_counts["soft_deleted" if repair(blob_hash) else "failed"] += 1

    return {
        "total_scanned": sum(counts.values()),
        "counts": dict(sorted(counts.items())),
        "recommended_actions": dict(sorted(action_counts.items())),
        "repairs": dict(sorted(repair_counts.items())),
        "privacy": "aggregate_only",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--hash-file", type=Path, help="Private file with one full hash per line")
    source.add_argument("--all", action="store_true", help="Scan all blob metadata keys")
    parser.add_argument("--hex-prefix", help="Restrict --all to a lowercase hex prefix")
    parser.add_argument("--limit", type=int, help="Scan at most this many hashes")
    parser.add_argument(
        "--public-endpoint",
        help="Diagnose anonymous HTTP status; CDN responses are not origin proof",
    )
    parser.add_argument(
        "--repair-missing-bytes",
        action="store_true",
        help="Soft-delete visible metadata after confirmed missing storage bytes",
    )
    parser.add_argument(
        "--max-repairs",
        type=int,
        default=0,
        help="Hard cap required with --repair-missing-bytes",
    )
    parser.add_argument(
        "--confirm-missing-count",
        type=int,
        help="Exact missing_bytes count from a prior read-only scan",
    )
    return parser.parse_args()


def validate_repair_request(
    repair_requested: bool,
    admin_token: Optional[str],
    admin_endpoint: Optional[str],
    max_repairs: int,
    confirm_missing_count: Optional[int],
    curated_input: bool,
) -> Optional[str]:
    if not repair_requested:
        return None
    if not admin_token or not admin_endpoint:
        return "repair requires FASTLY_ADMIN_TOKEN and BLOSSOM_ADMIN_ENDPOINT"
    if not curated_input:
        return "repair requires --hash-file; --all is read-only"
    if max_repairs < 1:
        return "repair requires a positive --max-repairs cap"
    if confirm_missing_count is None or confirm_missing_count < 1:
        return "repair requires a positive --confirm-missing-count from a prior scan"
    if confirm_missing_count > max_repairs:
        return "--confirm-missing-count cannot exceed --max-repairs"
    return None


def repair_did_not_complete(result: dict[str, object]) -> bool:
    repairs = result.get("repairs")
    return isinstance(repairs, dict) and any(
        key.startswith("skipped_") or key == "failed" for key in repairs
    )


def main() -> int:
    args = parse_args()
    api_token = os.environ.get("FASTLY_API_TOKEN")
    store_id = os.environ.get("KV_STORE_ID")
    if not api_token or not store_id:
        print("FASTLY_API_TOKEN and KV_STORE_ID are required", file=sys.stderr)
        return 2

    if args.hex_prefix and any(char not in "0123456789abcdef" for char in args.hex_prefix):
        print("--hex-prefix must contain lowercase hexadecimal characters", file=sys.stderr)
        return 2

    try:
        hashes = (
            read_hash_file(args.hash_file)
            if args.hash_file
            else list_blob_hashes(store_id, api_token, args.hex_prefix)
        )
    except (OSError, ValueError, requests.RequestException) as error:
        print(str(error), file=sys.stderr)
        return 2

    if args.limit is not None:
        if args.limit < 1:
            print("--limit must be positive", file=sys.stderr)
            return 2
        hashes = hashes[: args.limit]

    try:
        from google.cloud import storage as gcs
    except ImportError:
        print("google-cloud-storage is required", file=sys.stderr)
        return 2

    bucket = gcs.Client().bucket(os.environ.get("GCS_BUCKET", "divine-blossom-media"))
    metadata_fn = lambda value: probe_metadata(store_id, api_token, value)
    storage_fn = lambda value: probe_storage(bucket, value)
    public_fn = (
        (lambda value: probe_public(args.public_endpoint, value)) if args.public_endpoint else None
    )

    repair_fn = None
    if args.repair_missing_bytes:
        admin_token = os.environ.get("FASTLY_ADMIN_TOKEN")
        admin_endpoint = os.environ.get("BLOSSOM_ADMIN_ENDPOINT")
        repair_error = validate_repair_request(
            True,
            admin_token,
            admin_endpoint,
            args.max_repairs,
            args.confirm_missing_count,
            args.hash_file is not None,
        )
        if repair_error:
            print(repair_error, file=sys.stderr)
            return 2
        repair_fn = lambda value: soft_delete_missing_bytes(admin_endpoint, admin_token, value)

    result = scan(
        hashes,
        metadata_fn,
        storage_fn,
        public_fn,
        repair_fn,
        args.max_repairs,
        args.confirm_missing_count,
        args.hash_file is not None,
    )
    print(json.dumps(result, sort_keys=True))
    return 3 if args.repair_missing_bytes and repair_did_not_complete(result) else 0


if __name__ == "__main__":
    raise SystemExit(main())
