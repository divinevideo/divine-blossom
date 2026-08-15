#!/usr/bin/env python3
# ABOUTME: Backfill legacy Bunny Stream GUID media whose event imeta tags carry Blossom hashes.
# ABOUTME: Mirrors through Blossom so verified bytes and public metadata are restored together.

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse


RELAY_URL = "wss://relay.divine.video"
MIRROR_URL = "https://media.divine.video/mirror"
UPLOAD_URL = "https://media.divine.video/upload"
MIGRATE_URL = "https://upload.divine.video/migrate"
CDN_BASE_URL = "https://cdn.divine.video"
PROGRESS_FILES = {
    "blossom": Path("bunny_stream_guid_backfill_progress.json"),
    "upload-service": Path("bunny_stream_guid_upload_service_backfill_progress.json"),
}
KINDS = [34235, 34236]
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class BackfillCandidate:
    sha256: str
    guid: str
    event_id: str
    pubkey: str
    created_at: int
    source_urls: tuple[str, ...]


def parse_imeta_tag(tag: list) -> dict:
    """Parse both known imeta tag encodings and preserve repeated URL fields."""
    result = {}
    urls = []
    images = []
    entries = tag[1:]

    if entries and isinstance(entries[0], str) and " " in entries[0]:
        for entry in entries:
            if not isinstance(entry, str) or " " not in entry:
                continue
            key, value = entry.split(" ", 1)
            if key == "url":
                urls.append(value)
            elif key == "image":
                images.append(value)
                result[key] = value
            else:
                result[key] = value
    else:
        i = 0
        while i < len(entries) - 1:
            key = entries[i]
            value = entries[i + 1]
            if key == "url":
                urls.append(value)
            elif key == "image":
                images.append(value)
                result[key] = value
            else:
                result[key] = value
            i += 2

    result["urls"] = urls
    result["images"] = images
    if urls:
        result["url"] = urls[0]
    return result


def normalize_sha256(value: str | None) -> str | None:
    if not value:
        return None
    value = value.lower()
    if SHA256_RE.match(value):
        return value
    return None


def filename_sha256(url: str) -> str | None:
    filename = urlparse(url).path.rsplit("/", 1)[-1].split(".", 1)[0].lower()
    return normalize_sha256(filename)


def stream_guid_from_url(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.hostname != "stream.divine.video":
        return None
    first_segment = parsed.path.strip("/").split("/", 1)[0]
    if GUID_RE.match(first_segment):
        return first_segment.lower()
    return None


def source_urls_for_sha(imeta: dict, sha256: str) -> tuple[str, ...]:
    urls = []
    for url in imeta.get("urls", []):
        parsed = urlparse(url)
        if parsed.hostname == "cdn.divine.video" and filename_sha256(url) == sha256:
            urls.append(url)

    urls.extend([
        f"{CDN_BASE_URL}/{sha256}",
        f"{CDN_BASE_URL}/{sha256}.mp4",
    ])

    deduped = []
    seen = set()
    for url in urls:
        if url not in seen:
            deduped.append(url)
            seen.add(url)
    return tuple(deduped)


def extract_candidates(event: dict) -> list[BackfillCandidate]:
    candidates = []
    for tag in event.get("tags", []):
        if not tag or tag[0] != "imeta":
            continue

        imeta = parse_imeta_tag(tag)
        sha256 = normalize_sha256(imeta.get("x"))
        if not sha256:
            continue

        media_urls = [*imeta.get("urls", []), *imeta.get("images", [])]
        guid = next((g for g in (stream_guid_from_url(url) for url in media_urls) if g), None)
        if not guid:
            continue

        candidates.append(
            BackfillCandidate(
                sha256=sha256,
                guid=guid,
                event_id=event.get("id", ""),
                pubkey=event.get("pubkey", ""),
                created_at=int(event.get("created_at", 0)),
                source_urls=source_urls_for_sha(imeta, sha256),
            )
        )
    return candidates


def dedupe_candidates(candidates: Iterable[BackfillCandidate]) -> list[BackfillCandidate]:
    by_hash: dict[str, BackfillCandidate] = {}
    for candidate in candidates:
        existing = by_hash.get(candidate.sha256)
        if existing is None:
            by_hash[candidate.sha256] = candidate
            continue

        merged_urls = tuple(dict.fromkeys([*existing.source_urls, *candidate.source_urls]))
        by_hash[candidate.sha256] = replace(existing, source_urls=merged_urls)

    return sorted(by_hash.values(), key=lambda c: (c.created_at, c.sha256))


async def fetch_all_events(relay_url: str, since: int | None, until: int | None) -> list[dict]:
    try:
        import websockets
        from websockets.exceptions import ConnectionClosed
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "Missing dependency: websockets. Install migration script dependencies "
            "with `python3 -m pip install aiohttp websockets`."
        ) from exc

    all_events = []
    seen_ids = set()
    batch_limit = 5000
    page_until = until

    async with websockets.connect(relay_url) as ws:
        page = 0
        while True:
            page += 1
            filter_obj = {"kinds": KINDS, "limit": batch_limit}
            if since is not None:
                filter_obj["since"] = since
            if page_until is not None:
                filter_obj["until"] = page_until

            sub_id = f"bunny_guid_backfill_{page}"
            await ws.send(json.dumps(["REQ", sub_id, filter_obj]))

            batch_events = []
            oldest_timestamp = None
            while True:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=30)
                except asyncio.TimeoutError:
                    break
                except ConnectionClosed:
                    break

                data = json.loads(msg)
                if data[0] == "EVENT":
                    event = data[2]
                    event_id = event.get("id")
                    if event_id and event_id in seen_ids:
                        continue
                    if event_id:
                        seen_ids.add(event_id)
                    batch_events.append(event)
                    created_at = event.get("created_at", 0)
                    if oldest_timestamp is None or created_at < oldest_timestamp:
                        oldest_timestamp = created_at
                elif data[0] == "EOSE":
                    break
                elif data[0] == "NOTICE":
                    print(f"Relay notice: {data[1]}")

            await ws.send(json.dumps(["CLOSE", sub_id]))
            all_events.extend(batch_events)

            if len(batch_events) < batch_limit or oldest_timestamp is None:
                break
            page_until = oldest_timestamp - 1

    return all_events


def load_progress(path: Path) -> set[str]:
    if not path.exists():
        return set()
    with path.open() as f:
        return set(json.load(f))


def save_progress(path: Path, done: set[str]) -> None:
    path.write_text(json.dumps(sorted(done), indent=2) + "\n")


async def migrate_candidate(session, migrate_url: str, candidate: BackfillCandidate) -> tuple[str, str]:
    for source_url in candidate.source_urls:
        payload = {
            "source_url": source_url,
            "expected_hash": candidate.sha256,
        }
        if candidate.pubkey:
            payload["owner"] = candidate.pubkey

        async with session.post(migrate_url, json=payload) as resp:
            text = await resp.text()
            if resp.status != 200:
                last_error = f"{source_url} -> HTTP {resp.status}: {text[:200]}"
                continue

            body = json.loads(text)
            if body.get("sha256") != candidate.sha256:
                return "failed", f"{source_url} -> migrate returned wrong hash {body.get('sha256')}"
            if body.get("migrated"):
                return "migrated", source_url
            return "already_present", source_url

    return "not_found", last_error if "last_error" in locals() else "no source URLs"


def load_nostr_keys(nsec: str | None):
    try:
        from nostr_sdk import Keys
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "Missing dependency: nostr-sdk. Install migration script dependencies "
            "with `python3 -m pip install aiohttp websockets nostr-sdk`."
        ) from exc

    if nsec:
        return Keys.parse(nsec)
    return Keys.generate()


def create_blossom_auth_header(keys, action: str, sha256: str) -> str:
    from nostr_sdk import EventBuilder, Kind, Tag

    expiration = int(time.time()) + 300
    builder = EventBuilder(Kind(24242), "").tags([
        Tag.parse(["t", action]),
        Tag.parse(["x", sha256]),
        Tag.parse(["expiration", str(expiration)]),
    ])
    if hasattr(builder, "sign_with_keys"):
        event = builder.sign_with_keys(keys)
    else:
        event = keys.sign_event(builder.finalize_unsigned(keys.public_key()))
    return "Nostr " + base64.b64encode(event.as_json().encode()).decode()


def should_try_local_upload(detail: str) -> bool:
    return "MIGRATION_NSEC" in detail or "requires auth" in detail


async def upload_bytes_from_source(
    session,
    upload_url: str,
    keys,
    candidate: BackfillCandidate,
    source_url: str,
) -> tuple[str, str]:
    get_headers = {
        "Authorization": create_blossom_auth_header(keys, "get", candidate.sha256),
    }
    async with session.get(source_url, headers=get_headers) as resp:
        if resp.status != 200:
            text = await resp.text()
            return "not_found", f"{source_url} authenticated GET -> HTTP {resp.status}: {text[:200]}"
        content_type = resp.headers.get("Content-Type", "application/octet-stream")
        body = await resp.read()

    actual_hash = hashlib.sha256(body).hexdigest()
    if actual_hash != candidate.sha256:
        return "failed", f"{source_url} local hash mismatch: expected {candidate.sha256}, got {actual_hash}"

    upload_headers = {
        "Authorization": create_blossom_auth_header(keys, "upload", candidate.sha256),
        "Content-Type": content_type,
    }
    async with session.put(upload_url, data=body, headers=upload_headers) as resp:
        text = await resp.text()
        if resp.status not in (200, 201):
            return "failed", f"{upload_url} -> HTTP {resp.status}: {text[:200]}"
        descriptor = json.loads(text)
        if descriptor.get("sha256") != candidate.sha256:
            return "failed", f"{upload_url} -> upload returned wrong hash {descriptor.get('sha256')}"
        return "ok", f"{source_url} -> local authenticated upload"


async def mirror_candidate(
    session,
    mirror_url: str,
    upload_url: str,
    keys,
    candidate: BackfillCandidate,
    local_upload_fallback: bool,
) -> tuple[str, str]:
    fallback_sources = []
    for source_url in candidate.source_urls:
        headers = {
            "Authorization": create_blossom_auth_header(keys, "upload", candidate.sha256),
            "Content-Type": "application/json",
        }
        async with session.put(mirror_url, json={"url": source_url}, headers=headers) as resp:
            text = await resp.text()
            if resp.status != 200:
                last_error = f"{source_url} -> HTTP {resp.status}: {text[:200]}"
                if should_try_local_upload(last_error):
                    fallback_sources.append(source_url)
                continue

            body = json.loads(text)
            if body.get("sha256") != candidate.sha256:
                return "failed", f"{source_url} -> mirror returned wrong hash {body.get('sha256')}"
            return "ok", source_url

    if local_upload_fallback:
        for source_url in fallback_sources:
            status, detail = await upload_bytes_from_source(
                session, upload_url, keys, candidate, source_url
            )
            if status == "ok":
                return status, detail

    return "not_found", last_error if "last_error" in locals() else "no source URLs"


async def run_backfill(args) -> None:
    events = await fetch_all_events(args.relay_url, args.since, args.until)
    candidates = dedupe_candidates(
        candidate
        for event in events
        for candidate in extract_candidates(event)
    )
    total_candidates = len(candidates)
    if args.limit:
        candidates = candidates[: args.limit]

    done = load_progress(args.progress_file)
    pending = [candidate for candidate in candidates if candidate.sha256 not in done]

    print(
        f"events={len(events)} candidates={total_candidates} "
        f"selected={len(candidates)} done={len(done)} pending={len(pending)}"
    )
    if not args.execute:
        for candidate in pending[:10]:
            print(f"dry-run {candidate.sha256} guid={candidate.guid} source={candidate.source_urls[0]}")
        if len(pending) > 10:
            print(f"dry-run ... {len(pending) - 10} more")
        print("Dry run only. Pass --execute to call the selected write endpoint.")
        return

    try:
        import aiohttp
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "Missing dependency: aiohttp. Install migration script dependencies "
            "with `python3 -m pip install aiohttp websockets`."
        ) from exc

    keys = load_nostr_keys(args.nsec) if args.target == "blossom" else None
    stats = {"ok": 0, "migrated": 0, "already_present": 0, "not_found": 0, "failed": 0}
    connector = aiohttp.TCPConnector(limit=args.concurrency)
    async with aiohttp.ClientSession(connector=connector) as session:
        for offset in range(0, len(pending), args.concurrency):
            batch = pending[offset: offset + args.concurrency]
            if args.target == "blossom":
                results = await asyncio.gather(
                    *(
                        mirror_candidate(
                            session,
                            args.mirror_url,
                            args.upload_url,
                            keys,
                            candidate,
                            args.local_upload_fallback,
                        )
                        for candidate in batch
                    )
                )
            else:
                results = await asyncio.gather(
                    *(migrate_candidate(session, args.migrate_url, candidate) for candidate in batch)
                )
            for candidate, (status, detail) in zip(batch, results):
                stats[status] += 1
                if status in ("ok", "migrated", "already_present"):
                    done.add(candidate.sha256)
                if args.verbose or status not in ("ok", "migrated", "already_present"):
                    print(f"{status} {candidate.sha256} {detail}")
            save_progress(args.progress_file, done)

    print("complete " + " ".join(f"{key}={value}" for key, value in stats.items()))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Backfill Blossom blobs for Bunny Stream GUID-era events."
    )
    parser.add_argument("--execute", action="store_true", help="Call the selected write endpoint. Default is dry-run.")
    parser.add_argument(
        "--target",
        choices=["blossom", "upload-service"],
        default="blossom",
        help="Use Blossom /mirror for storage plus metadata, or upload-service /migrate for storage only.",
    )
    parser.add_argument("--relay-url", default=RELAY_URL)
    parser.add_argument("--mirror-url", default=MIRROR_URL)
    parser.add_argument("--upload-url", default=UPLOAD_URL)
    parser.add_argument("--migrate-url", default=MIGRATE_URL)
    parser.add_argument("--nsec", help="Nostr nsec for Blossom upload auth. Defaults to a generated migration key.")
    parser.add_argument(
        "--local-upload-fallback",
        action="store_true",
        help="For auth-protected legacy sources, fetch locally with Nostr get auth, verify SHA, then PUT /upload.",
    )
    parser.add_argument("--progress-file", type=Path)
    parser.add_argument("--since", type=int, help="Relay since timestamp.")
    parser.add_argument("--until", type=int, help="Relay until timestamp.")
    parser.add_argument("--limit", type=int, help="Only process the first N deduped candidates.")
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)
    if args.progress_file is None:
        args.progress_file = PROGRESS_FILES[args.target]
    if args.concurrency < 1:
        parser.error("--concurrency must be at least 1")
    return args


def main() -> None:
    asyncio.run(run_backfill(parse_args()))


if __name__ == "__main__":
    main()
