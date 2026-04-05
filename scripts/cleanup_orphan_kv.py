#!/usr/bin/env python3
"""
Cleanup orphan KV metadata records in the Blossom metadata KV store.

An "orphan" is a KV record (blob:{hash}) whose corresponding GCS object does not exist.
These arise from two confirmed root causes:

  1. Race in the old (pre-PR #57) full-delete path: storage_delete(hash) succeeded but
     delete_blob_metadata(hash) failed (or was never reached due to an error), leaving
     the KV record behind with status still set to the pre-delete value.

  2. Partial vanish: the execute_vanish() path deletes GCS and KV atomically for sole
     owners, but a Cloud Run timeout or error could leave GCS deleted and KV intact if
     storage_delete() succeeded but delete_blob_metadata() was never reached.

A secondary non-orphan class is covered for diagnostic purposes only:

  3. "Ghost" hash (Case 2 from the investigation): the /provenance endpoint returns
     {"owner": null, "uploaders": []} for ANY valid 64-char hex hash because it never
     errors on unknown hashes. A hash in this state has NO KV record AND no GCS object —
     it just appears as a potential problem but there is nothing to clean up.

Usage:
    # Dry-run (default): print what would be deleted but do nothing
    python cleanup_orphan_kv.py --hashes ae1102b3... ff63ea82...

    # Dry-run against all blob:* keys in the KV store
    python cleanup_orphan_kv.py --all --dry-run

    # Wet-run (delete): only do this after PR #59 is confirmed stable
    python cleanup_orphan_kv.py --hashes ae1102b3... --admin-endpoint https://blossom.dvines.org

    # Limit to one hex prefix (0-f) for parallelism
    python cleanup_orphan_kv.py --all --hex-prefix a --dry-run

Environment variables:
    FASTLY_API_TOKEN   — Fastly API token with kv_store.read permission
    FASTLY_ADMIN_TOKEN — Bearer token for POST /admin/api/delete (same as admin_token secret)
    KV_STORE_ID        — Fastly KV store ID (find with: fastly kv-store list)
    GCS_BUCKET         — GCS bucket name (default: divine-blossom-media)
    GOOGLE_APPLICATION_CREDENTIALS — path to GCS service account key

Dependencies:
    pip install requests google-cloud-storage

IMPORTANT: Run with --dry-run first. Do not run on production until PR #59 deploy is
confirmed stable (check that resumable uploads complete correctly end-to-end).
"""

import argparse
import csv
import io
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Optional

import requests

try:
    from google.cloud import storage as gcs
    from google.cloud.exceptions import NotFound
except ImportError:
    print("Error: google-cloud-storage not installed")
    print("Install with: pip install google-cloud-storage")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Configuration helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_env(name: str, default: Optional[str] = None) -> Optional[str]:
    val = os.environ.get(name, default)
    return val if val else default


def require_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        print(f"Error: {name} environment variable is required")
        sys.exit(1)
    return val


# ─────────────────────────────────────────────────────────────────────────────
# Fastly KV store access (read-only — for listing blob:* keys and fetching values)
# ─────────────────────────────────────────────────────────────────────────────

def fastly_kv_list_blob_keys(store_id: str, api_token: str, hex_prefix: Optional[str] = None) -> list[str]:
    """
    List all blob:{hash} keys from the Fastly KV store.

    If hex_prefix is given (e.g. "a"), only keys whose hash starts with that
    prefix are returned. This allows parallel runs across 16 shards.
    """
    headers = {
        "Fastly-Key": api_token,
        "Accept": "application/json",
    }

    keys: list[str] = []
    cursor: Optional[str] = None
    page = 0

    while True:
        params: dict = {"limit": 1000, "prefix": "blob:"}
        if cursor:
            params["cursor"] = cursor

        url = f"https://api.fastly.com/resources/stores/kv/{store_id}/keys"
        resp = requests.get(url, headers=headers, params=params, timeout=30)

        if resp.status_code != 200:
            print(f"Error listing KV keys (page {page}): {resp.status_code} — {resp.text[:200]}")
            sys.exit(1)

        data = resp.json()
        page += 1

        for item in data.get("data", []):
            key: str = item if isinstance(item, str) else item.get("name", item.get("key", ""))
            if not key.startswith("blob:"):
                continue
            hash_part = key[len("blob:"):]
            if len(hash_part) != 64:
                continue  # skip malformed keys
            if hex_prefix and not hash_part.startswith(hex_prefix.lower()):
                continue
            keys.append(hash_part)

        cursor = data.get("meta", {}).get("next_cursor")
        if not cursor:
            break

        if page % 10 == 0:
            print(f"  ... listed {len(keys)} blob keys so far (page {page})", file=sys.stderr)

    return keys


def fastly_kv_get_blob_metadata(store_id: str, api_token: str, sha256: str) -> Optional[dict]:
    """Fetch a single blob:{hash} record from the KV store."""
    headers = {"Fastly-Key": api_token}
    key = f"blob:{sha256.lower()}"
    encoded_key = requests.utils.quote(key, safe="")
    url = f"https://api.fastly.com/resources/stores/kv/{store_id}/keys/{encoded_key}"
    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code == 200:
        try:
            return resp.json()
        except Exception:
            return None
    if resp.status_code == 404:
        return None
    print(f"  Warning: KV lookup for {sha256[:8]} returned {resp.status_code}", file=sys.stderr)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# GCS existence check (read-only)
# ─────────────────────────────────────────────────────────────────────────────

def gcs_blob_exists(bucket: "gcs.Bucket", sha256: str) -> bool:
    """Return True if the main blob object exists in GCS."""
    blob = bucket.blob(sha256.lower())
    try:
        blob.reload()  # lightweight metadata-only HEAD
        return True
    except NotFound:
        return False
    except Exception as exc:
        print(f"  Warning: GCS check for {sha256[:8]} raised {exc}", file=sys.stderr)
        # Treat errors as "exists" so we don't accidentally delete anything
        return True


# ─────────────────────────────────────────────────────────────────────────────
# Fastly Compute admin delete (writes — only in wet-run mode)
# ─────────────────────────────────────────────────────────────────────────────

def fastly_admin_delete(
    admin_endpoint: str,
    admin_token: str,
    sha256: str,
    reason: str = "Orphan KV cleanup — GCS blob missing",
    legal_hold: bool = False,
) -> bool:
    """
    Call POST /admin/api/delete on the Fastly Compute endpoint.

    This soft-deletes the blob record (sets status=deleted, removes from user lists,
    purges VCL cache). It does NOT remove the KV record itself — that only happens
    in the full hard-delete / vanish path. For the orphan case this is fine: the record
    is effectively invisible once status=deleted, and can be hard-purged later via the
    Fastly KV API directly if needed.

    Returns True if successful.
    """
    url = f"{admin_endpoint.rstrip('/')}/admin/api/delete"
    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json",
    }
    body = {
        "sha256": sha256.lower(),
        "reason": reason,
        "legal_hold": legal_hold,
    }
    try:
        resp = requests.post(url, headers=headers, json=body, timeout=30)
        if resp.status_code == 200:
            return True
        if resp.status_code == 404:
            # Already gone from KV — treat as success
            print(f"  Note: {sha256[:16]}... already absent from KV (404)", file=sys.stderr)
            return True
        print(
            f"  Error: admin delete for {sha256[:16]}... returned {resp.status_code}: {resp.text[:200]}",
            file=sys.stderr,
        )
        return False
    except Exception as exc:
        print(f"  Error: admin delete for {sha256[:16]}... raised {exc}", file=sys.stderr)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Classification logic
# ─────────────────────────────────────────────────────────────────────────────

CLASSIFICATION_ORPHAN_KV = "orphan_kv"       # KV record exists, GCS blob missing
CLASSIFICATION_GHOST_HASH = "ghost_hash"      # No KV record, no GCS object (case 2)
CLASSIFICATION_HEALTHY = "healthy"            # KV record exists and GCS blob exists
CLASSIFICATION_SOFT_DELETED = "soft_deleted"  # KV record exists, status=deleted, GCS might be gone


def classify_hash(
    sha256: str,
    kv_metadata: Optional[dict],
    gcs_exists: bool,
) -> str:
    has_kv = kv_metadata is not None
    status = (kv_metadata or {}).get("status", "unknown")

    if not has_kv and not gcs_exists:
        return CLASSIFICATION_GHOST_HASH
    if not has_kv and gcs_exists:
        # GCS object exists but no KV record — unusual (orphan GCS)
        return "orphan_gcs"
    if has_kv and gcs_exists:
        return CLASSIFICATION_HEALTHY
    # has_kv and not gcs_exists
    if status == "deleted":
        # Soft-deleted: KV status=deleted but GCS was already removed.
        # This is normal for the preserve-first policy where GCS was cleaned
        # in an earlier full-delete and then metadata was changed to soft-delete.
        # Not an error case — do not touch.
        return CLASSIFICATION_SOFT_DELETED
    return CLASSIFICATION_ORPHAN_KV


# ─────────────────────────────────────────────────────────────────────────────
# Main scan loop
# ─────────────────────────────────────────────────────────────────────────────

def run_scan(
    hashes: list[str],
    kv_store_id: str,
    api_token: str,
    gcs_bucket_obj: "gcs.Bucket",
    dry_run: bool,
    admin_endpoint: Optional[str],
    admin_token: Optional[str],
    limit: Optional[int],
    reason: str,
) -> dict:
    results = []
    counts = {
        CLASSIFICATION_HEALTHY: 0,
        CLASSIFICATION_ORPHAN_KV: 0,
        CLASSIFICATION_GHOST_HASH: 0,
        CLASSIFICATION_SOFT_DELETED: 0,
        "orphan_gcs": 0,
        "deleted_ok": 0,
        "delete_failed": 0,
        "skipped_limit": 0,
    }

    total = len(hashes)
    for i, sha256 in enumerate(hashes):
        if limit is not None and i >= limit:
            counts["skipped_limit"] = total - i
            break

        if (i + 1) % 50 == 0 or i == 0:
            print(f"  [{i+1}/{total}] scanning {sha256[:16]}...", file=sys.stderr)

        kv_meta = fastly_kv_get_blob_metadata(kv_store_id, api_token, sha256)
        gcs_exists = gcs_blob_exists(gcs_bucket_obj, sha256)

        classification = classify_hash(sha256, kv_meta, gcs_exists)
        counts[classification] = counts.get(classification, 0) + 1

        owner = (kv_meta or {}).get("owner", "")
        status = (kv_meta or {}).get("status", "")
        mime = (kv_meta or {}).get("type", "")
        uploaded = (kv_meta or {}).get("uploaded", "")

        action_taken = "none"

        if classification == CLASSIFICATION_ORPHAN_KV:
            if dry_run:
                action_taken = "would_delete"
                print(f"  [DRY-RUN] Would soft-delete orphan KV record: {sha256[:16]}... owner={owner[:12]}... status={status}")
            else:
                if not admin_endpoint or not admin_token:
                    print(f"  [SKIP] --admin-endpoint and FASTLY_ADMIN_TOKEN required for wet-run", file=sys.stderr)
                    action_taken = "skipped_no_creds"
                else:
                    ok = fastly_admin_delete(admin_endpoint, admin_token, sha256, reason=reason)
                    if ok:
                        action_taken = "soft_deleted"
                        counts["deleted_ok"] += 1
                        print(f"  [DELETE] Soft-deleted orphan KV: {sha256[:16]}...")
                    else:
                        action_taken = "delete_failed"
                        counts["delete_failed"] += 1
        elif classification == CLASSIFICATION_GHOST_HASH:
            print(f"  [GHOST] Hash {sha256[:16]}... has no KV record and no GCS object — nothing to clean up")

        results.append({
            "sha256": sha256,
            "classification": classification,
            "kv_owner": owner,
            "kv_status": status,
            "kv_mime": mime,
            "kv_uploaded": uploaded,
            "gcs_exists": gcs_exists,
            "action_taken": action_taken,
        })

        # Polite rate-limiting: 100ms pause every 20 items to avoid hammering APIs
        if (i + 1) % 20 == 0:
            time.sleep(0.1)

    return {"results": results, "counts": counts}


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--hashes",
        nargs="+",
        metavar="SHA256",
        help="One or more 64-char hex hashes to check.",
    )
    source_group.add_argument(
        "--all",
        action="store_true",
        help="Scan all blob:* keys from the Fastly KV store. Requires FASTLY_API_TOKEN and KV_STORE_ID.",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Do not delete anything, only report (default: true). Pass --no-dry-run to write.",
    )
    parser.add_argument(
        "--no-dry-run",
        dest="dry_run",
        action="store_false",
        help="Actually perform deletes. Requires --admin-endpoint and FASTLY_ADMIN_TOKEN.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Stop after scanning N hashes (useful for small test runs).",
    )
    parser.add_argument(
        "--hex-prefix",
        metavar="HEX",
        default=None,
        help="Only scan hashes starting with this hex prefix (0-9, a-f). Enables parallel sharding.",
    )
    parser.add_argument(
        "--admin-endpoint",
        metavar="URL",
        default="https://blossom.dvines.org",
        help="Base URL of the Fastly Compute endpoint (default: https://blossom.dvines.org).",
    )
    parser.add_argument(
        "--reason",
        default="Orphan KV cleanup — GCS blob missing (cleanup_orphan_kv.py)",
        help="Deletion reason written to audit log.",
    )
    parser.add_argument(
        "--output-csv",
        metavar="FILE",
        default=None,
        help="Write results to a CSV file in addition to JSON summary on stdout.",
    )
    parser.add_argument(
        "--output-json",
        metavar="FILE",
        default=None,
        help="Write full JSON results to this file.",
    )

    args = parser.parse_args()

    # ── Read environment ──────────────────────────────────────────────────────
    api_token = get_env("FASTLY_API_TOKEN")
    kv_store_id = get_env("KV_STORE_ID")
    admin_token = get_env("FASTLY_ADMIN_TOKEN")
    gcs_bucket_name = get_env("GCS_BUCKET", "divine-blossom-media")

    if args.all and (not api_token or not kv_store_id):
        print("Error: --all requires FASTLY_API_TOKEN and KV_STORE_ID environment variables")
        sys.exit(1)

    if not args.dry_run and not admin_token:
        print("Error: --no-dry-run requires FASTLY_ADMIN_TOKEN environment variable")
        sys.exit(1)

    # ── Build hash list ───────────────────────────────────────────────────────
    if args.hashes:
        hashes = [h.lower() for h in args.hashes]
        for h in hashes:
            if len(h) != 64 or not all(c in "0123456789abcdef" for c in h):
                print(f"Error: invalid hash: {h}")
                sys.exit(1)
        # For explicit hash list, we still need api_token + kv_store_id to read KV
        if not api_token:
            print("Warning: FASTLY_API_TOKEN not set — KV metadata will not be checked (GCS check only)")
        if not kv_store_id:
            print("Warning: KV_STORE_ID not set — KV metadata will not be checked (GCS check only)")
    else:
        print("Listing blob:* keys from Fastly KV store...")
        hashes = fastly_kv_list_blob_keys(kv_store_id, api_token, hex_prefix=args.hex_prefix)
        print(f"Found {len(hashes)} blob keys" + (f" with prefix '{args.hex_prefix}'" if args.hex_prefix else ""))

    if args.limit:
        print(f"Limiting scan to first {args.limit} hashes")

    # ── GCS client ────────────────────────────────────────────────────────────
    print(f"Connecting to GCS bucket: {gcs_bucket_name}")
    gcs_client = gcs.Client()
    bucket = gcs_client.bucket(gcs_bucket_name)

    # ── Mode banner ───────────────────────────────────────────────────────────
    if args.dry_run:
        print("Mode: DRY-RUN (no deletes will happen)")
    else:
        print(f"Mode: WET-RUN — orphans will be soft-deleted via {args.admin_endpoint}")
        print("      Press Ctrl-C within 5 seconds to abort...")
        time.sleep(5)

    print(f"Scanning {len(hashes)} hash(es)...")
    print()

    started_at = datetime.now(timezone.utc)

    scan = run_scan(
        hashes=hashes,
        kv_store_id=kv_store_id or "",
        api_token=api_token or "",
        gcs_bucket_obj=bucket,
        dry_run=args.dry_run,
        admin_endpoint=args.admin_endpoint,
        admin_token=admin_token,
        limit=args.limit,
        reason=args.reason,
    )

    finished_at = datetime.now(timezone.utc)
    elapsed = (finished_at - started_at).total_seconds()

    # ── Summary ───────────────────────────────────────────────────────────────
    counts = scan["counts"]
    print()
    print("=" * 60)
    print(f"Scan complete in {elapsed:.1f}s")
    print(f"  healthy           : {counts.get(CLASSIFICATION_HEALTHY, 0)}")
    print(f"  orphan_kv         : {counts.get(CLASSIFICATION_ORPHAN_KV, 0)}  ← KV present, GCS missing")
    print(f"  ghost_hash        : {counts.get(CLASSIFICATION_GHOST_HASH, 0)}  ← no KV, no GCS (nothing to do)")
    print(f"  soft_deleted      : {counts.get(CLASSIFICATION_SOFT_DELETED, 0)}  ← status=deleted, GCS already gone")
    print(f"  orphan_gcs        : {counts.get('orphan_gcs', 0)}  ← GCS present, no KV (rare)")
    if not args.dry_run:
        print(f"  deleted_ok        : {counts.get('deleted_ok', 0)}")
        print(f"  delete_failed     : {counts.get('delete_failed', 0)}")
    if counts.get("skipped_limit", 0):
        print(f"  skipped (limit)   : {counts.get('skipped_limit', 0)}")
    print("=" * 60)

    # ── JSON output ───────────────────────────────────────────────────────────
    summary = {
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "elapsed_secs": elapsed,
        "dry_run": args.dry_run,
        "hex_prefix": args.hex_prefix,
        "total_scanned": len(scan["results"]),
        "counts": counts,
        "results": scan["results"],
    }

    if args.output_json:
        with open(args.output_json, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"JSON written to {args.output_json}")
    else:
        print(json.dumps({"counts": counts, "dry_run": args.dry_run}, indent=2))

    # ── CSV output ────────────────────────────────────────────────────────────
    if args.output_csv:
        with open(args.output_csv, "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["sha256", "classification", "kv_owner", "kv_status",
                            "kv_mime", "kv_uploaded", "gcs_exists", "action_taken"],
            )
            writer.writeheader()
            writer.writerows(scan["results"])
        print(f"CSV written to {args.output_csv}")


if __name__ == "__main__":
    main()
