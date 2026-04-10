#!/usr/bin/env python3
"""
Promote `BlobStatus::Restricted` blobs to `BlobStatus::AgeRestricted` in the
Fastly KV store `blossom_metadata`.

Default mode is dry-run: scans all blob:* keys, fetches each metadata record,
groups by owner pubkey, and prints how many would be promoted.

Pass --apply to actually write the new status. The script never deletes a key
and only mutates the `status` field.

Required env:
  FASTLY_API_TOKEN
  FASTLY_KV_STORE_ID    (default: 07pggadpgda8plydnkt5el)

Optional env:
  ONLY_OWNER_PUBKEYS    comma-separated; if set, only blobs owned by these
                        pubkeys are eligible for promotion (otherwise all
                        currently-Restricted blobs are eligible).

Optional env (DNS-bypass for VPN-broken api.fastly.com):
  FASTLY_API_RESOLVE_IP   manually pin api.fastly.com to this IP. If unset,
                          uses requests' default resolution.
"""
import argparse
import json
import os
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

KV_STORE_ID_DEFAULT = "07pggadpgda8plydnkt5el"
KV_API = "https://api.fastly.com/resources/stores/kv"
PAGE_LIMIT = 1000
RETRY_STATUS = {429, 500, 502, 503, 504}


def session():
    token = os.environ.get("FASTLY_API_TOKEN")
    if not token:
        print("ERROR: FASTLY_API_TOKEN not set", file=sys.stderr)
        sys.exit(2)
    s = requests.Session()
    s.headers.update({"Fastly-Key": token, "Accept": "application/json"})
    # Larger pool so ThreadPoolExecutor workers don't serialize on a single conn
    retry = Retry(
        total=5,
        status_forcelist=list(RETRY_STATUS),
        allowed_methods=["GET", "PUT"],
        backoff_factor=1.0,
    )
    adapter = HTTPAdapter(pool_connections=64, pool_maxsize=64, max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


def _process_batch(s, store_id, keys, by_owner, eligible, only_owners, workers):
    """Fetch a batch of blob: keys in parallel and append eligible records."""
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(get_metadata, s, store_id, k): k for k in keys}
        for fut in as_completed(futures):
            key = futures[fut]
            try:
                meta = fut.result()
            except Exception as e:
                print(f"  WARN {key}: {e}", file=sys.stderr)
                continue
            if meta is None:
                continue
            if meta.get("status") != "restricted":
                continue
            owner = (meta.get("owner") or "").lower()
            if only_owners and owner not in only_owners:
                continue
            by_owner[owner] += 1
            eligible.append((key, meta))


def list_blob_keys(s, store_id):
    cursor = None
    while True:
        params = {"prefix": "blob", "limit": PAGE_LIMIT}
        if cursor:
            params["cursor"] = cursor
        url = f"{KV_API}/{store_id}/keys?{urlencode(params)}"
        r = s.get(url, timeout=30)
        r.raise_for_status()
        body = r.json()
        for key in body.get("data", []):
            if key.startswith("blob:") and len(key) == len("blob:") + 64:
                yield key
        cursor = body.get("meta", {}).get("next_cursor")
        if not cursor:
            return


def get_metadata(s, store_id, key):
    url = f"{KV_API}/{store_id}/keys/{key}"
    r = s.get(url, timeout=30)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    try:
        return r.json()
    except json.JSONDecodeError as e:
        print(f"  WARN: {key} has unparseable JSON body: {e}", file=sys.stderr)
        return None


def put_metadata(s, store_id, key, metadata):
    url = f"{KV_API}/{store_id}/keys/{key}"
    r = s.put(
        url,
        data=json.dumps(metadata),
        timeout=30,
        headers={"Content-Type": "application/octet-stream"},
    )
    r.raise_for_status()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--apply",
        action="store_true",
        help="Actually write changes (default: dry-run)",
    )
    ap.add_argument(
        "--store-id",
        default=os.environ.get("FASTLY_KV_STORE_ID", KV_STORE_ID_DEFAULT),
    )
    ap.add_argument(
        "--limit-scan",
        type=int,
        default=0,
        help="If >0, stop after scanning this many blob keys (for sampling)",
    )
    ap.add_argument(
        "--workers",
        type=int,
        default=32,
        help="Concurrent KV fetches (default 32)",
    )
    args = ap.parse_args()

    only_owners = {
        p.strip().lower()
        for p in os.environ.get("ONLY_OWNER_PUBKEYS", "").split(",")
        if p.strip()
    }

    s = session()

    by_owner = defaultdict(int)
    eligible = []
    scanned = 0

    print(
        f"Scanning KV store {args.store_id} for blob:* keys "
        f"(workers={args.workers}, limit_scan={args.limit_scan or 'unlimited'}, "
        f"only_owners={len(only_owners) or 'all'})...",
        file=sys.stderr,
    )

    # Process keys in batches: each batch fetches in parallel via ThreadPool.
    BATCH = max(args.workers * 4, 64)

    def process_key(key):
        meta = get_metadata(s, args.store_id, key)
        return key, meta

    try:
        batch = []
        for key in list_blob_keys(s, args.store_id):
            batch.append(key)
            scanned += 1
            if args.limit_scan and scanned > args.limit_scan:
                break
            if len(batch) >= BATCH:
                _process_batch(
                    s,
                    args.store_id,
                    batch,
                    by_owner,
                    eligible,
                    only_owners,
                    args.workers,
                )
                # update counters from results that flowed into mutable args
                batch = []
                if scanned % 1000 == 0:
                    print(
                        f"  scanned {scanned} keys, eligible so far: {len(eligible)}",
                        file=sys.stderr,
                    )
        if batch:
            _process_batch(
                s,
                args.store_id,
                batch,
                by_owner,
                eligible,
                only_owners,
                args.workers,
            )
        restricted_total = len(eligible) if not only_owners else None
        # When only_owners is set, eligible is already filtered; we no longer
        # know the global restricted_total without re-counting.
    except KeyboardInterrupt:
        print("\nInterrupted by user, showing partial results...", file=sys.stderr)

    print(
        f"\nScan complete: {scanned} blob records, "
        f"{len(eligible)} eligible for promotion.\n",
        file=sys.stderr,
    )

    print("Per-owner breakdown of eligible blobs (top 50):")
    for owner, count in sorted(by_owner.items(), key=lambda kv: -kv[1])[:50]:
        print(f"  {count:6d}  {owner}")
    if len(by_owner) > 50:
        print(f"  ... ({len(by_owner) - 50} more owners)")

    if not args.apply:
        print(
            "\nDry-run only. Re-run with --apply to promote these blobs.",
            file=sys.stderr,
        )
        return 0

    if not eligible:
        print("\nNothing to apply.", file=sys.stderr)
        return 0

    print(
        f"\nPromoting {len(eligible)} blobs from restricted to age_restricted...",
        file=sys.stderr,
    )
    promoted = 0
    failed = 0
    for key, meta in eligible:
        meta["status"] = "age_restricted"
        try:
            put_metadata(s, args.store_id, key, meta)
            promoted += 1
        except Exception as e:
            failed += 1
            print(f"  FAILED {key}: {e}", file=sys.stderr)
        if promoted % 100 == 0 and promoted > 0:
            print(
                f"  promoted {promoted}/{len(eligible)}...",
                file=sys.stderr,
            )
        time.sleep(0.02)  # gentle pacing to avoid KV write hot-spots

    print(
        f"\nDone. Promoted: {promoted}, Failed: {failed}",
        file=sys.stderr,
    )
    print(
        "\nNext step: purge VCL cache so the new status takes effect:\n"
        "  fastly purge --all --service-id pOvEEWykEbpnylqst1KTrR",
        file=sys.stderr,
    )
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
