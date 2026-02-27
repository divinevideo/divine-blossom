#!/usr/bin/env python3
# ABOUTME: Migrate all content from Bunny CDN to GCS by triggering on-demand migration
# ABOUTME: Fetches blob hashes from relay, requests each via Compute to trigger migration

import asyncio
import json
import sys
import time
from pathlib import Path

import aiohttp
import websockets

RELAY_URL = "wss://relay.divine.video"
# Hit Compute directly (not VCL) so we always trigger migration logic
COMPUTE_ORIGIN = "https://separately-robust-roughy.edgecompute.app"
PROGRESS_FILE = Path("bunny_migration_progress.json")
CONCURRENT = 5  # Parallel requests to Compute
BATCH_SAVE_INTERVAL = 50


def extract_hashes_from_event(event: dict) -> set[str]:
    """Extract all SHA256 hashes from imeta tags in a nostr event."""
    hashes = set()
    for tag in event.get("tags", []):
        if not tag or tag[0] != "imeta":
            continue
        entries = tag[1:]
        # Detect format
        if entries and " " in str(entries[0]):
            for entry in entries:
                if isinstance(entry, str):
                    if " " in entry:
                        key, value = entry.split(" ", 1)
                        if key == "x":
                            hashes.add(value.lower())
                        elif key == "url":
                            h = extract_hash_from_url(value)
                            if h:
                                hashes.add(h)
                        elif key == "image":
                            h = extract_hash_from_url(value)
                            if h:
                                hashes.add(h)
        else:
            i = 0
            while i < len(entries) - 1:
                key = entries[i]
                value = entries[i + 1]
                if key == "x":
                    hashes.add(value.lower())
                elif key in ("url", "image"):
                    h = extract_hash_from_url(value)
                    if h:
                        hashes.add(h)
                i += 2
    return hashes


def extract_hash_from_url(url: str) -> str | None:
    if not url:
        return None
    path = url.split("/")[-1]
    filename = path.split(".")[0]
    if len(filename) == 64 and all(c in '0123456789abcdef' for c in filename.lower()):
        return filename.lower()
    return None


async def fetch_all_events(relay_url: str, kinds: list[int]) -> list[dict]:
    """Fetch all events of given kinds from relay using pagination."""
    all_events = []
    seen_ids = set()
    batch_limit = 5000
    until = None

    print(f"Connecting to {relay_url}...")
    async with websockets.connect(relay_url) as ws:
        page = 0
        while True:
            page += 1
            filter_obj = {"kinds": kinds, "limit": batch_limit}
            if until is not None:
                filter_obj["until"] = until

            sub_id = f"migrate_{page}"
            await ws.send(json.dumps(["REQ", sub_id, filter_obj]))
            print(f"  Page {page}: fetching events until={until or 'now'}...")

            batch_events = []
            oldest_timestamp = None

            while True:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=30)
                    data = json.loads(msg)
                    if data[0] == "EVENT":
                        event = data[2]
                        eid = event.get("id")
                        if eid and eid not in seen_ids:
                            seen_ids.add(eid)
                            batch_events.append(event)
                            ts = event.get("created_at", 0)
                            if oldest_timestamp is None or ts < oldest_timestamp:
                                oldest_timestamp = ts
                    elif data[0] == "EOSE":
                        break
                    elif data[0] == "NOTICE":
                        print(f"  Relay notice: {data[1]}")
                except asyncio.TimeoutError:
                    print("  Timeout waiting for events")
                    break

            await ws.send(json.dumps(["CLOSE", sub_id]))
            all_events.extend(batch_events)
            print(f"  Page {page}: {len(batch_events)} events (total: {len(all_events)})")

            if len(batch_events) < batch_limit or oldest_timestamp is None:
                break
            until = oldest_timestamp - 1

    return all_events


async def check_and_migrate(
    session: aiohttp.ClientSession,
    sha256: str,
    stats: dict,
    verbose: bool = False,
) -> str | None:
    """HEAD request to Compute origin. If it responds, content is accessible.
    If source is cdn_divine, the synchronous migration we deployed will handle it.
    Returns the source header if successful, None on failure."""
    url = f"{COMPUTE_ORIGIN}/{sha256}"
    try:
        async with session.head(url, timeout=aiohttp.ClientTimeout(total=120)) as resp:
            source = resp.headers.get("X-Blossom-Source", "gcs")
            if resp.status == 200:
                if source != "gcs":
                    stats["migrated"] += 1
                    if verbose:
                        print(f"  MIGRATED {sha256[:16]}... (from {source})")
                else:
                    stats["already_in_gcs"] += 1
                    if verbose and stats["already_in_gcs"] % 100 == 0:
                        print(f"  ... {stats['already_in_gcs']} already in GCS")
                return source
            elif resp.status == 404:
                stats["not_found"] += 1
                if verbose:
                    print(f"  NOT_FOUND {sha256[:16]}...")
                return None
            else:
                stats["errors"] += 1
                if verbose:
                    print(f"  ERROR {resp.status} for {sha256[:16]}...")
                return None
    except Exception as e:
        stats["errors"] += 1
        if verbose:
            print(f"  EXCEPTION for {sha256[:16]}...: {e}")
        return None


def load_progress() -> set[str]:
    if PROGRESS_FILE.exists():
        with open(PROGRESS_FILE) as f:
            return set(json.load(f))
    return set()


def save_progress(done: set[str]):
    with open(PROGRESS_FILE, "w") as f:
        json.dump(sorted(done), f)


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="Migrate Bunny CDN content to GCS")
    parser.add_argument("--test", type=int, help="Only process N hashes")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--force", action="store_true", help="Re-check already-done hashes")
    args = parser.parse_args()

    print("=== Bunny CDN → GCS Migration ===\n")

    # Step 1: Fetch events from relay
    print("Step 1: Fetching blob metadata from relay...")
    events = await fetch_all_events(RELAY_URL, [34235, 34236])
    print(f"  Total events: {len(events)}")

    # Step 2: Extract unique hashes
    print("\nStep 2: Extracting blob hashes...")
    all_hashes = set()
    for event in events:
        all_hashes.update(extract_hashes_from_event(event))
    print(f"  Unique hashes: {len(all_hashes)}")

    # Step 3: Load progress
    done = load_progress() if not args.force else set()
    remaining = all_hashes - done
    print(f"  Already processed: {len(done)}")
    print(f"  Remaining: {len(remaining)}")

    if args.test:
        remaining = set(list(remaining)[:args.test])
        print(f"  Test mode: processing {len(remaining)} hashes")

    if not remaining:
        print("\nAll hashes already processed!")
        return

    # Step 4: Check each hash via Compute (triggers migration for Bunny-hosted content)
    print(f"\nStep 3: Checking/migrating {len(remaining)} hashes via Compute...")
    stats = {"already_in_gcs": 0, "migrated": 0, "not_found": 0, "errors": 0}

    connector = aiohttp.TCPConnector(limit=CONCURRENT)
    async with aiohttp.ClientSession(connector=connector) as session:
        hash_list = sorted(remaining)
        processed = 0

        for i in range(0, len(hash_list), CONCURRENT):
            batch = hash_list[i:i + CONCURRENT]
            tasks = [check_and_migrate(session, h, stats, args.verbose) for h in batch]
            await asyncio.gather(*tasks)
            done.update(batch)
            processed += len(batch)

            if processed % BATCH_SAVE_INTERVAL == 0:
                save_progress(done)
                total = sum(stats.values())
                print(f"  Progress: {processed}/{len(hash_list)} | "
                      f"GCS: {stats['already_in_gcs']} | "
                      f"Migrated: {stats['migrated']} | "
                      f"NotFound: {stats['not_found']} | "
                      f"Errors: {stats['errors']}")

    save_progress(done)

    print(f"\n=== Migration Complete ===")
    print(f"  Already in GCS: {stats['already_in_gcs']}")
    print(f"  Migrated from Bunny: {stats['migrated']}")
    print(f"  Not found anywhere: {stats['not_found']}")
    print(f"  Errors: {stats['errors']}")

    if stats['not_found'] > 0:
        print(f"\n  Note: {stats['not_found']} blobs not found on any source.")
        print(f"  These may be deleted content or from external blossom servers.")


if __name__ == "__main__":
    asyncio.run(main())
