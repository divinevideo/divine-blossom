#!/usr/bin/env python3
"""Classify and reconcile event-referenced Blossom blobs without emitting IDs.

Input hashes stay in a local file or come from the Fastly KV key listing. Output
contains aggregate counts only. Missing bytes may be reconciled by soft-deleting
the stale metadata through the existing admin API from a curated hash file;
whole-store scans are always read-only. All other classes are
read-only because reconstructing metadata or changing moderation state without
their original evidence would weaken access controls.

Dependencies: pip install requests google-cloud-storage
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class Presence(Enum):
    PRESENT = "present"
    MISSING = "missing"
    ERROR = "error"


class DeliveryRoute(Enum):
    DIRECT = "direct"
    ALIAS_ONLY_DERIVED_AUDIO = "alias_only_derived_audio"
    ERROR = "error"


class VanishRetryMarker(Enum):
    OUTSTANDING = "outstanding"
    ABSENT = "absent"
    ERROR = "error"


@dataclass(frozen=True)
class MetadataProbe:
    presence: Presence
    status: Optional[str] = None
    consistent: bool = True
    owner: Optional[str] = None


AVAILABLE = "available"
MISSING_BYTES = "missing_bytes"
UNVERIFIED_MISSING_BYTES = "unverified_missing_bytes"
MISSING_METADATA = "missing_metadata"
STALE_EVENT_REFERENCE = "stale_event_reference"
MODERATION_HIDDEN = "moderation_hidden"
AGE_RESTRICTED = "age_restricted"
DELETED = "deleted"
DELIVERY_PATH_FAILURE = "delivery_path_failure"
STORAGE_PATH_DIVERGENCE = "storage_path_divergence"
INCONSISTENT_METADATA = "inconsistent_metadata"
PROBE_ERROR = "probe_error"
ALIAS_ONLY_DERIVED_AUDIO = "alias_only_derived_audio"

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
    UNVERIFIED_MISSING_BYTES: "probe_public_delivery_before_repair",
    MISSING_METADATA: "restore_original_metadata_from_verified_backup",
    STALE_EVENT_REFERENCE: "repair_at_event_source",
    MODERATION_HIDDEN: "none",
    AGE_RESTRICTED: "none",
    DELETED: "none",
    DELIVERY_PATH_FAILURE: "investigate_delivery_path",
    STORAGE_PATH_DIVERGENCE: "investigate_storage_origins",
    INCONSISTENT_METADATA: "quarantine_then_restore_original_metadata_from_verified_backup",
    PROBE_ERROR: "retry_probe",
    ALIAS_ONLY_DERIVED_AUDIO: "none",
}

RETRY_STATUS = (429, 500, 502, 503, 504)
PROGRESS_INTERVAL = 100


def classify_blob(
    metadata: MetadataProbe,
    storage: Presence,
    public_status: Optional[int] = None,
    delivery_route: DeliveryRoute = DeliveryRoute.DIRECT,
) -> str:
    """Classify one referenced hash without retaining the hash itself."""
    if (
        metadata.presence is Presence.ERROR
        or storage is Presence.ERROR
        or delivery_route is DeliveryRoute.ERROR
    ):
        return PROBE_ERROR
    if public_status == -1:
        return PROBE_ERROR
    if metadata.presence is Presence.MISSING:
        return MISSING_METADATA if storage is Presence.PRESENT else STALE_EVENT_REFERENCE
    if not metadata.consistent:
        return INCONSISTENT_METADATA

    status = (metadata.status or "").lower()
    if status not in EXPECTED_PUBLIC_STATUS:
        return INCONSISTENT_METADATA
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
    if delivery_route is DeliveryRoute.ALIAS_ONLY_DERIVED_AUDIO:
        return ALIAS_ONLY_DERIVED_AUDIO
    if storage is Presence.MISSING:
        if public_status is None:
            return UNVERIFIED_MISSING_BYTES
        if public_status in EXPECTED_PUBLIC_STATUS[status]:
            return STORAGE_PATH_DIVERGENCE
        if public_status == 404:
            return MISSING_BYTES
        return DELIVERY_PATH_FAILURE
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


def fastly_session(api_token: str) -> requests.Session:
    session = requests.Session()
    session.headers.update({"Fastly-Key": api_token, "Accept": "application/json"})
    retry = Retry(
        total=5,
        status_forcelist=RETRY_STATUS,
        allowed_methods=("GET",),
        backoff_factor=1.0,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    return session


def list_blob_hashes(
    session: requests.Session,
    store_id: str,
    hex_prefix: Optional[str],
    limit: Optional[int] = None,
) -> list[str]:
    hashes: list[str] = []
    seen: set[str] = set()
    cursor: Optional[str] = None
    while True:
        page_limit = min(1000, limit - len(hashes)) if limit else 1000
        params = {"limit": page_limit, "prefix": f"blob:{hex_prefix or ''}"}
        if cursor:
            params["cursor"] = cursor
        response = session.get(
            f"https://api.fastly.com/resources/stores/kv/{store_id}/keys",
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
            if (hex_prefix is None or blob_hash.startswith(hex_prefix)) and blob_hash not in seen:
                seen.add(blob_hash)
                hashes.append(blob_hash)
                if limit and len(hashes) >= limit:
                    return hashes
        cursor = payload.get("meta", {}).get("next_cursor")
        if not cursor:
            return list(dict.fromkeys(hashes))


def probe_metadata(
    session: requests.Session,
    store_id: str,
    blob_hash: str,
) -> MetadataProbe:
    key = requests.utils.quote(f"blob:{blob_hash}", safe="")
    try:
        response = session.get(
            f"https://api.fastly.com/resources/stores/kv/{store_id}/keys/{key}",
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
        owner = payload.get("owner")
        return MetadataProbe(
            Presence.PRESENT,
            status,
            consistent,
            owner.lower() if isinstance(owner, str) else None,
        )
    except (requests.RequestException, ValueError):
        return MetadataProbe(Presence.ERROR)


def probe_json_list(
    session: requests.Session,
    store_id: str,
    key: str,
) -> tuple[Presence, list[str]]:
    encoded_key = requests.utils.quote(key, safe="")
    try:
        response = session.get(
            f"https://api.fastly.com/resources/stores/kv/{store_id}/keys/{encoded_key}",
            timeout=15,
        )
        if response.status_code == 404:
            return Presence.MISSING, []
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, list):
            return Presence.ERROR, []
        try:
            validated = [validate_hash(value) for value in payload]
        except (TypeError, ValueError):
            return Presence.ERROR, []
        return Presence.PRESENT, validated
    except (requests.RequestException, ValueError):
        return Presence.ERROR, []


def probe_delivery_route(
    session: requests.Session,
    store_id: str,
    blob_hash: str,
) -> DeliveryRoute:
    audio_presence, audio_refs = probe_json_list(session, store_id, f"audio_refs:{blob_hash}")
    if audio_presence is Presence.ERROR:
        return DeliveryRoute.ERROR
    if not audio_refs:
        return DeliveryRoute.DIRECT

    refs_presence, blob_refs = probe_json_list(session, store_id, f"refs:{blob_hash}")
    if refs_presence is Presence.ERROR:
        return DeliveryRoute.ERROR
    return (
        DeliveryRoute.ALIAS_ONLY_DERIVED_AUDIO
        if not blob_refs
        else DeliveryRoute.DIRECT
    )


def probe_vanish_retry_marker(
    session: requests.Session,
    store_id: str,
    blob_hash: str,
) -> VanishRetryMarker:
    # TODO(#246): Replace list membership with a vanish-specific durable marker.
    # Account vanish keeps these entries until all blob erasure work succeeds.
    metadata = probe_metadata(session, store_id, blob_hash)
    if (
        metadata.presence is not Presence.PRESENT
        or not metadata.consistent
        or not metadata.owner
        or metadata.status != "active"
    ):
        return VanishRetryMarker.ERROR

    refs_presence, referrers = probe_json_list(session, store_id, f"refs:{blob_hash}")
    if refs_presence is Presence.ERROR:
        return VanishRetryMarker.ERROR

    # Do not cache lists across candidates: each repair mutates them, and a
    # concurrent vanish must be visible to the next candidate's live probe.
    for pubkey in dict.fromkeys([metadata.owner, *referrers]):
        list_presence, hashes = probe_json_list(session, store_id, f"list:{pubkey}")
        if list_presence is Presence.ERROR:
            return VanishRetryMarker.ERROR
        if blob_hash in hashes:
            return VanishRetryMarker.OUTSTANDING
    return VanishRetryMarker.ABSENT


def get_bucket(client: object, bucket_name: str, not_found_type: type[Exception]) -> object:
    try:
        return client.get_bucket(bucket_name)
    except not_found_type as error:
        raise ValueError(f"configured GCS bucket does not exist: {bucket_name}") from error


def probe_storage(
    bucket: object,
    blob_hash: str,
    not_found_type: type[Exception],
) -> Presence:
    try:
        bucket.blob(blob_hash).reload()
        return Presence.PRESENT
    except not_found_type:
        return Presence.MISSING
    except Exception:
        return Presence.ERROR


def probe_public(endpoint: str, blob_hash: str) -> Optional[int]:
    cache_buster = secrets.token_hex(8)
    try:
        response = requests.get(
            f"{endpoint.rstrip('/')}/{blob_hash}?_={cache_buster}",
            headers={"Range": "bytes=0-0", "Cache-Control": "no-cache"},
            allow_redirects=False,
            stream=True,
            timeout=15,
        )
        try:
            return response.status_code
        finally:
            response.close()
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
        return response.status_code == 200
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
    progress: Optional[Callable[[int], None]] = None,
    delivery_route_probe: Optional[Callable[[str], DeliveryRoute]] = None,
    vanish_retry_probe: Optional[Callable[[str], VanishRetryMarker]] = None,
) -> dict[str, object]:
    counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    repair_counts: Counter[str] = Counter()
    classifications: list[tuple[str, str]] = []
    for scanned, blob_hash in enumerate(hashes, start=1):
        metadata = metadata_probe(blob_hash)
        storage = storage_probe(blob_hash)
        delivery_route = (
            delivery_route_probe(blob_hash)
            if delivery_route_probe
            else DeliveryRoute.DIRECT
        )
        public_status = (
            public_probe(blob_hash)
            if public_probe and delivery_route is DeliveryRoute.DIRECT
            else None
        )
        classification = classify_blob(metadata, storage, public_status, delivery_route)
        counts[classification] += 1
        action_counts[ACTION_BY_CLASS[classification]] += 1
        classifications.append((blob_hash, classification))
        if progress and scanned % PROGRESS_INTERVAL == 0:
            progress(scanned)

    repair_candidates = [
        blob_hash
        for blob_hash, classification in classifications
        if classification == MISSING_BYTES
    ]
    if repair and not curated_input:
        raise ValueError("repair requires a curated hash file")
    if repair and confirm_missing_count is None:
        raise ValueError("repair requires the confirmed missing-byte count from a prior scan")
    if repair and not vanish_retry_probe:
        raise ValueError("repair requires a live vanish retry marker probe")
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
            marker = vanish_retry_probe(blob_hash)
            if marker is VanishRetryMarker.OUTSTANDING:
                repair_counts["excluded_vanish_retry"] += 1
            elif marker is VanishRetryMarker.ERROR:
                repair_counts["failed_vanish_retry_probe"] += 1
            else:
                repair_counts["soft_deleted" if repair(blob_hash) else "failed"] += 1

    return {
        "total_scanned": sum(counts.values()),
        "counts": dict(sorted(counts.items())),
        "recommended_actions": dict(sorted(action_counts.items())),
        "repairs": dict(sorted(repair_counts.items())),
        "privacy": "aggregate_only",
    }


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
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
        help="Hard cap required with --repair-missing-bytes",
    )
    parser.add_argument(
        "--confirm-missing-count",
        type=int,
        help="Exact missing_bytes count from a prior read-only scan",
    )
    return parser.parse_args(argv)


def validate_cli_request(args: argparse.Namespace) -> Optional[str]:
    if args.hex_prefix is not None:
        if args.hash_file:
            return "--hex-prefix can only be used with --all"
        if not args.hex_prefix or len(args.hex_prefix) > 64 or any(
            char not in "0123456789abcdef" for char in args.hex_prefix
        ):
            return "--hex-prefix must contain 1-64 lowercase hexadecimal characters"
    if args.limit is not None and args.limit < 1:
        return "--limit must be positive"
    if args.max_repairs is not None and args.max_repairs < 0:
        return "--max-repairs cannot be negative"
    if not args.repair_missing_bytes:
        if args.max_repairs is not None:
            return "--max-repairs requires --repair-missing-bytes"
        if args.confirm_missing_count is not None:
            return "--confirm-missing-count requires --repair-missing-bytes"
    else:
        if not args.hash_file:
            return "--repair-missing-bytes requires --hash-file; --all is read-only"
        if args.limit is not None:
            return "--limit cannot be used with --repair-missing-bytes"
        if not args.public_endpoint:
            return "--repair-missing-bytes requires --public-endpoint"
        repair_error = validate_repair_parameters(
            args.max_repairs, args.confirm_missing_count
        )
        if repair_error:
            return repair_error
    return None


def validate_repair_parameters(
    max_repairs: Optional[int], confirm_missing_count: Optional[int]
) -> Optional[str]:
    if max_repairs is None or max_repairs < 1:
        return "repair requires a positive --max-repairs cap"
    if confirm_missing_count is None or confirm_missing_count < 1:
        return "repair requires a positive --confirm-missing-count from a prior scan"
    if confirm_missing_count > max_repairs:
        return "--confirm-missing-count cannot exceed --max-repairs"
    return None


def validate_repair_request(
    repair_requested: bool,
    admin_token: Optional[str],
    admin_endpoint: Optional[str],
    public_endpoint: Optional[str],
    max_repairs: Optional[int],
    confirm_missing_count: Optional[int],
    curated_input: bool,
) -> Optional[str]:
    if not repair_requested:
        return None
    if not admin_token or not admin_endpoint:
        return "repair requires FASTLY_ADMIN_TOKEN and BLOSSOM_ADMIN_ENDPOINT"
    if not public_endpoint:
        return "repair requires --public-endpoint to rule out replica-served bytes"
    if not curated_input:
        return "repair requires --hash-file; --all is read-only"
    return validate_repair_parameters(max_repairs, confirm_missing_count)


def repair_did_not_complete(result: dict[str, object]) -> bool:
    repairs = result.get("repairs")
    return isinstance(repairs, dict) and any(
        key.startswith(("skipped_", "excluded_", "failed")) for key in repairs
    )


def main() -> int:
    args = parse_args()
    cli_error = validate_cli_request(args)
    if cli_error:
        print(cli_error, file=sys.stderr)
        return 2

    api_token = os.environ.get("FASTLY_API_TOKEN")
    store_id = os.environ.get("KV_STORE_ID")
    if not api_token or not store_id:
        print("FASTLY_API_TOKEN and KV_STORE_ID are required", file=sys.stderr)
        return 2

    session = fastly_session(api_token)

    try:
        hashes = (
            read_hash_file(args.hash_file)
            if args.hash_file
            else list_blob_hashes(session, store_id, args.hex_prefix, args.limit)
        )
    except (OSError, ValueError, requests.RequestException) as error:
        print(str(error), file=sys.stderr)
        return 2

    if args.limit is not None:
        hashes = hashes[: args.limit]

    try:
        from google.cloud import storage as gcs
        from google.api_core.exceptions import NotFound
    except ImportError:
        print("google-cloud-storage is required", file=sys.stderr)
        return 2

    bucket_name = os.environ.get("GCS_BUCKET")
    if not bucket_name:
        print("GCS_BUCKET is required", file=sys.stderr)
        return 2
    try:
        bucket = get_bucket(gcs.Client(), bucket_name, NotFound)
    except Exception as error:
        print(str(error), file=sys.stderr)
        return 2
    metadata_fn = lambda value: probe_metadata(session, store_id, value)
    storage_fn = lambda value: probe_storage(bucket, value, NotFound)
    delivery_route_fn = lambda value: probe_delivery_route(session, store_id, value)
    vanish_retry_fn = lambda value: probe_vanish_retry_marker(session, store_id, value)
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
            args.public_endpoint,
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
        public_probe=public_fn,
        delivery_route_probe=delivery_route_fn,
        vanish_retry_probe=vanish_retry_fn,
        repair=repair_fn,
        max_repairs=args.max_repairs or 0,
        confirm_missing_count=args.confirm_missing_count,
        curated_input=args.hash_file is not None,
        progress=lambda count: print(f"scanned={count}", file=sys.stderr),
    )
    print(json.dumps(result, sort_keys=True))
    return 3 if args.repair_missing_bytes and repair_did_not_complete(result) else 0


if __name__ == "__main__":
    raise SystemExit(main())
