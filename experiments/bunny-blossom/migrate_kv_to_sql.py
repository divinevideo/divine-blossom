#!/usr/bin/env python3
"""Migrate Divine Blossom metadata from Fastly KV (blossom_metadata) into the Bunny SQL schema.

Supports:
  - Reading directly from a local JSON backup (scripts/backup_kv_store.py format) via --from-backup
  - Reading live paginated keys from Fastly KV API via --kv-store-id (uses FASTLY_API_TOKEN)
  - Writing to local SQLite (--sqlite-path) OR remote libSQL/Bunny DB HTTP pipeline (--sql-url + SQL_TOKEN env)
  - Safe --dry-run mode and idempotent upserts (preserves higher revisions if already present)

Never logs credentials, owner pubkeys, or real object hashes in aggregate summaries.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable

HASH_RE = re.compile(r"^[0-9a-f]{64}$")

STATUS_MAP = {
    "active": "active",
    "restricted": "restricted",
    "pending": "pending",
    "banned": "banned",
    "deleted": "deleted",
    "age_restricted": "age_restricted",
    "agerestricted": "age_restricted",
}


def parse_unix_ts(value: Any) -> int:
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and value.strip():
        raw = value.strip()
        if raw.isdigit():
            return int(raw)
        try:
            parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return max(0, int(parsed.timestamp()))
        except ValueError:
            pass
    return 0


def transform_kv_blob(
    kv_key: str,
    raw_meta: dict[str, Any],
    extra_owners: Iterable[str] = (),
    is_tombstone: bool = False,
) -> dict[str, Any] | None:
    """Convert a Fastly KV `blob:<hash>` JSON entry into a normalized Bunny SQL BlobRecord."""
    if not kv_key.startswith("blob:"):
        return None
    hash_val = kv_key[len("blob:"):].strip().lower()
    if not HASH_RE.fullmatch(hash_val):
        return None

    raw_status = str(raw_meta.get("status", "pending")).strip().lower()
    status = STATUS_MAP.get(raw_status)
    if not status:
        return None

    owners: list[str] = []
    primary_owner = str(raw_meta.get("owner", "")).strip().lower()
    if HASH_RE.fullmatch(primary_owner):
        owners.append(primary_owner)
    for o in extra_owners:
        low = str(o).strip().lower()
        if HASH_RE.fullmatch(low) and low not in owners:
            owners.append(low)

    uploaded = parse_unix_ts(raw_meta.get("uploaded"))
    size = int(raw_meta.get("size") or 0)
    mime_type = str(raw_meta.get("type") or "application/octet-stream")

    record: dict[str, Any] = {
        "revision": 1,
        "hash": hash_val,
        "size": max(0, size),
        "type": mime_type,
        "uploaded": uploaded,
        "owners": owners,
        "status": "deleted" if is_tombstone else status,
        "ageRestricted": status == "age_restricted",
        "held": bool(is_tombstone),
        "gate": None,
        "cleanupPending": False,
    }
    for src, dst in (
        ("thumbnail", "thumbnail"),
        ("dim", "dim"),
        ("moderation", "moderation"),
        ("archive_storage", "archiveStorage"),
        ("transcode_status", "transcodeStatus"),
        ("transcode_generation", "transcodeGeneration"),
        ("transcode_error_code", "transcodeErrorCode"),
        ("transcode_error_message", "transcodeErrorMessage"),
        ("transcode_last_attempt_at", "transcodeLastAttemptAt"),
        ("transcode_attempt_count", "transcodeAttemptCount"),
        ("transcode_terminal", "transcodeTerminal"),
        ("transcript_status", "transcriptStatus"),
        ("transcript_generation", "transcriptGeneration"),
        ("transcript_error_code", "transcriptErrorCode"),
        ("transcript_error_message", "transcriptErrorMessage"),
        ("transcript_last_attempt_at", "transcriptLastAttemptAt"),
        ("transcript_attempt_count", "transcriptAttemptCount"),
        ("transcript_terminal", "transcriptTerminal"),
    ):
        if raw_meta.get(src) is not None:
            record[dst] = raw_meta[src]

    return record


def build_upsert_statements(record: dict[str, Any]) -> list[tuple[str, list[Any]]]:
    """Produce parameterized SQL statements to idempotently upsert a blob and its owners."""
    encoded = json.dumps(record, separators=(",", ":"), sort_keys=True)
    primary_owner = record["owners"][0] if record["owners"] else ""
    stmts: list[tuple[str, list[Any]]] = [
        (
            """INSERT INTO blobs(
                hash, revision, status, age_restricted, held, size, mime_type, uploaded, owner,
                transcode_status, transcode_generation, transcript_status, transcript_generation,
                gate, cleanup_pending, body
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hash) DO UPDATE SET
                status = excluded.status,
                age_restricted = excluded.age_restricted,
                held = excluded.held,
                size = excluded.size,
                mime_type = excluded.mime_type,
                uploaded = excluded.uploaded,
                owner = excluded.owner,
                transcode_status = excluded.transcode_status,
                transcode_generation = excluded.transcode_generation,
                transcript_status = excluded.transcript_status,
                transcript_generation = excluded.transcript_generation,
                body = excluded.body
            WHERE blobs.revision <= excluded.revision""",
            [
                record["hash"],
                record["revision"],
                record["status"],
                1 if record["ageRestricted"] else 0,
                1 if record["held"] else 0,
                record["size"],
                record["type"],
                record["uploaded"],
                primary_owner,
                record.get("transcodeStatus"),
                record.get("transcodeGeneration"),
                record.get("transcriptStatus"),
                record.get("transcriptGeneration"),
                record["gate"],
                1 if record["cleanupPending"] else 0,
                encoded,
            ],
        )
    ]
    if record["status"] == "deleted" or record["held"]:
        stmts.append((
            "DELETE FROM blob_owners WHERE hash = ? AND EXISTS (SELECT 1 FROM blobs WHERE hash = ? AND revision <= ?)",
            [record["hash"], record["hash"], record["revision"]],
        ))
    else:
        for owner in record["owners"]:
            stmts.append((
                """INSERT OR REPLACE INTO blob_owners(owner, hash, uploaded)
                SELECT ?, ?, ? WHERE EXISTS (
                    SELECT 1 FROM blobs WHERE hash = ? AND revision <= ? AND status != 'deleted' AND held = 0
                )""",
                [owner, record["hash"], record["uploaded"], record["hash"], record["revision"]],
            ))
    return stmts


def _libsql_arg(val: Any) -> dict[str, Any]:
    if val is None:
        return {"type": "null"}
    if isinstance(val, int):
        return {"type": "integer", "value": str(val)}
    return {"type": "text", "value": str(val)}


def execute_libsql_batch(sql_url: str, token: str, stmts: list[tuple[str, list[Any]]]) -> None:
    http_url = sql_url.replace("libsql://", "https://").rstrip("/") + "/v2/pipeline"
    requests_list = [
        {"type": "execute", "stmt": {"sql": sql, "args": [_libsql_arg(a) for a in args]}}
        for sql, args in stmts
    ]
    requests_list.append({"type": "close"})
    req = urllib.request.Request(
        http_url,
        data=json.dumps({"requests": requests_list}).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read().decode())
    for item in result.get("results", []):
        if item.get("type") == "error":
            raise RuntimeError(f"libSQL batch error: {item.get('error')}")


def list_fastly_kv_keys(
    store_id: str,
    token: str,
    *,
    prefix: str,
    max_pages: int = 0,
    page_size: int = 100,
    allow_truncated: bool = False,
) -> list[str]:
    """List Fastly KV keys for a prefix. `max_pages=0` paginates until exhausted."""
    keys: list[str] = []
    cursor: str | None = None
    pages = 0
    while True:
        if max_pages > 0 and pages >= max_pages:
            if cursor and not allow_truncated:
                raise RuntimeError(
                    f"Fastly KV listing for prefix {prefix!r} truncated at {max_pages} pages "
                    "(pass --max-pages 0 for full scan or --allow-truncated for bounded sample)"
                )
            break
        params = {"prefix": prefix, "limit": str(page_size)}
        if cursor:
            params["cursor"] = cursor
        qs = urllib.parse.urlencode(params)
        req = urllib.request.Request(
            f"https://api.fastly.com/resources/stores/kv/{store_id}/keys?{qs}",
            headers={"Fastly-Key": token, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            page = json.loads(resp.read().decode())
        keys.extend(page.get("data", []))
        pages += 1
        cursor = page.get("meta", {}).get("next_cursor")
        if not cursor:
            break
    return keys


def fetch_fastly_kv_entries(
    store_id: str,
    token: str,
    prefix: str = "blob:",
    max_pages: int = 0,
    page_size: int = 100,
    allow_truncated: bool = False,
) -> list[tuple[str, dict[str, Any]]]:
    entries: list[tuple[str, dict[str, Any]]] = []
    keys = list_fastly_kv_keys(
        store_id,
        token,
        prefix=prefix,
        max_pages=max_pages,
        page_size=page_size,
        allow_truncated=allow_truncated,
    )
    for key in keys:
        kreq = urllib.request.Request(
            f"https://api.fastly.com/resources/stores/kv/{store_id}/keys/{urllib.parse.quote(key, safe='')}",
            headers={"Fastly-Key": token},
        )
        try:
            with urllib.request.urlopen(kreq, timeout=15) as kr:
                meta = json.loads(kr.read().decode())
            if isinstance(meta, dict):
                entries.append((key, meta))
        except (urllib.error.HTTPError, json.JSONDecodeError):
            continue
    return entries


def fetch_fastly_kv_tombstones(
    store_id: str,
    token: str,
    *,
    max_pages: int = 0,
    page_size: int = 100,
    allow_truncated: bool = False,
) -> set[str]:
    keys = list_fastly_kv_keys(
        store_id,
        token,
        prefix="tombstone:",
        max_pages=max_pages,
        page_size=page_size,
        allow_truncated=allow_truncated,
    )
    return {
        k[len("tombstone:"):].strip().lower()
        for k in keys
        if k.startswith("tombstone:") and HASH_RE.fullmatch(k[len("tombstone:"):].strip().lower())
    }


def migrate_entries(
    entries: list[tuple[str, dict[str, Any]]],
    *,
    tombstones: set[str] | None = None,
    sqlite_path: Path | None = None,
    sql_url: str | None = None,
    sql_token: str | None = None,
    dry_run: bool = False,
) -> dict[str, int]:
    tombstones = tombstones or set()
    records: list[dict[str, Any]] = []
    skipped = 0
    for key, meta in entries:
        h = key[len("blob:"):].strip().lower() if key.startswith("blob:") else ""
        rec = transform_kv_blob(key, meta, is_tombstone=(h in tombstones))
        if rec is None:
            skipped += 1
        else:
            records.append(rec)

    written = 0
    if not dry_run:
        if sqlite_path is not None:
            schema = (Path(__file__).parent / "schema.sql").read_text()
            conn = sqlite3.connect(str(sqlite_path))
            try:
                conn.executescript(schema)
                with conn:
                    for rec in records:
                        for sql, args in build_upsert_statements(rec):
                            conn.execute(sql, args)
                        written += 1
            finally:
                conn.close()
        elif sql_url and sql_token:
            batch: list[tuple[str, list[Any]]] = []
            for rec in records:
                batch.extend(build_upsert_statements(rec))
                written += 1
                if len(batch) >= 50:
                    execute_libsql_batch(sql_url, sql_token, batch)
                    batch.clear()
            if batch:
                execute_libsql_batch(sql_url, sql_token, batch)
        else:
            raise ValueError("Specify --sqlite-path or --sql-url (with BLOSSOM_SQL_TOKEN) unless --dry-run")

    return {"transformed": len(records), "written": written, "skipped": skipped}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Migrate Fastly blossom_metadata KV into Bunny SQL.")
    parser.add_argument("--from-backup", type=Path, help="Local JSON map of KV key -> JSON object")
    parser.add_argument("--kv-store-id", help="Fastly KV store ID (reads FASTLY_API_TOKEN from env)")
    parser.add_argument("--max-pages", type=int, default=0, help="Max Fastly KV list pages (0 = full scan)")
    parser.add_argument("--allow-truncated", action="store_true", help="Allow stopping early when --max-pages is reached")
    parser.add_argument("--page-size", type=int, default=100, help="Fastly KV keys per page")
    parser.add_argument("--sqlite-path", type=Path, help="Target local SQLite database path")
    parser.add_argument("--sql-url", help="Target libSQL/Bunny DB HTTPS/libsql URL")
    parser.add_argument("--dry-run", action="store_true", help="Transform and validate without writing")
    args = parser.parse_args(argv)

    entries: list[tuple[str, dict[str, Any]]] = []
    tombstones: set[str] = set()
    if args.from_backup:
        raw = json.loads(args.from_backup.read_text())
        for k, v in raw.items():
            if k.startswith("tombstone:"):
                tombstones.add(k[len("tombstone:"):].strip().lower())
            elif k.startswith("blob:") and isinstance(v, dict):
                entries.append((k, v))
    elif args.kv_store_id:
        token = os.environ.get("FASTLY_API_TOKEN", "").strip()
        if not token:
            print("FASTLY_API_TOKEN environment variable required", file=sys.stderr)
            return 2
        tombstones = fetch_fastly_kv_tombstones(
            args.kv_store_id,
            token,
            max_pages=args.max_pages,
            page_size=args.page_size,
            allow_truncated=args.allow_truncated,
        )
        entries = fetch_fastly_kv_entries(
            args.kv_store_id,
            token,
            max_pages=args.max_pages,
            page_size=args.page_size,
            allow_truncated=args.allow_truncated,
        )
    else:
        parser.error("Provide --from-backup or --kv-store-id")

    sql_token = os.environ.get("BLOSSOM_SQL_TOKEN", "").strip() or os.environ.get("SQL_TOKEN", "").strip()
    summary = migrate_entries(
        entries,
        tombstones=tombstones,
        sqlite_path=args.sqlite_path,
        sql_url=args.sql_url,
        sql_token=sql_token or None,
        dry_run=args.dry_run,
    )
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
