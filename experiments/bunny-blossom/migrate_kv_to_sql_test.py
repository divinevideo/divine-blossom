#!/usr/bin/env python3
"""Unit tests for Fastly KV -> Bunny SQL metadata migration."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from migrate_kv_to_sql import migrate_entries, parse_unix_ts, transform_kv_blob

H1 = "a" * 64
H2 = "b" * 64
OWNER = "c" * 64


class MigrateKvToSqlTests(unittest.TestCase):
    def test_parse_unix_ts(self) -> None:
        self.assertEqual(parse_unix_ts(1700000000), 1700000000)
        self.assertEqual(parse_unix_ts("2026-11-21T06:34:42Z"), 1795242882)
        self.assertEqual(parse_unix_ts("invalid"), 0)

    def test_transform_and_migrate_sqlite_idempotent(self) -> None:
        entries = [
            (
                f"blob:{H1}",
                {
                    "sha256": H1,
                    "size": 12345,
                    "type": "video/mp4",
                    "uploaded": "2026-11-21T06:34:42Z",
                    "owner": OWNER,
                    "status": "active",
                    "transcode_status": "complete",
                    "transcode_generation": 42,
                    "dim": "720x1280",
                },
            ),
            (
                f"blob:{H2}",
                {
                    "sha256": H2,
                    "size": 999,
                    "type": "video/mp4",
                    "uploaded": "2026-11-21T06:35:00Z",
                    "owner": OWNER,
                    "status": "age_restricted",
                },
            ),
            ("list:" + OWNER, {"hashes": [H1, H2]}),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "blossom.db"
            summary1 = migrate_entries(entries, tombstones={H2}, sqlite_path=db_path)
            self.assertEqual(summary1, {"transformed": 2, "written": 2, "skipped": 1})

            # Idempotent re-run
            summary2 = migrate_entries(entries, tombstones={H2}, sqlite_path=db_path)
            self.assertEqual(summary2, {"transformed": 2, "written": 2, "skipped": 1})

            conn = sqlite3.connect(str(db_path))
            try:
                rows = conn.execute("SELECT hash, status, held, transcode_status FROM blobs ORDER BY hash").fetchall()
                self.assertEqual(rows, [
                    (H1, "active", 0, "complete"),
                    (H2, "deleted", 1, None),
                ])
                owners = conn.execute("SELECT owner, hash FROM blob_owners").fetchall()
                self.assertEqual(owners, [(OWNER, H1)])
            finally:
                conn.close()

    def test_transform_rejects_bad_hash(self) -> None:
        self.assertIsNone(transform_kv_blob("blob:notahash", {"status": "active"}))


if __name__ == "__main__":
    unittest.main()
