#!/usr/bin/env python3
"""Bounded, restartable approved-video mirror. Nothing runs until explicitly invoked.

GCS remains authoritative. Fastly writes are limited to readiness, owned copy
gates and generation-matched demand acknowledgement; source objects and B2
versions are never deleted. See
docs/runbooks/b2-original-sync.md.
"""
import argparse
import base64
from collections import Counter
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

HEX = re.compile(r"[0-9a-f]{64}\Z")
MIB = 1024 * 1024
DEMAND_PREFIX = "b2-demand:v1:"


def valid_generation(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9]+", value) and 0 < int(value) < 2 ** 64


def valid_hint(key, value):
    if not isinstance(value, dict) or type(value.get("version")) is not int or value["version"] != 1:
        return False
    fields = {"version", "sha256", "reason"}
    if value.get("reason") == "missing_version":
        fields.add("observed_destination_version_id")
        version = value.get("observed_destination_version_id")
        if not isinstance(version, str) or not 1 <= len(version) <= 1024:
            return False
    elif value.get("reason") != "missing_readiness":
        return False
    return set(value) == fields and value.get("sha256") == key and HEX.fullmatch(key) is not None


def readiness_matches(record, key, info, source, destination):
    return (isinstance(record, dict) and type(record.get("version")) is int and record["version"] == 1
            and record.get("sha256") == record.get("verified_sha256") == record.get("key") == key
            and record.get("bucket") == destination and record.get("source_bucket") == source
            and record.get("source_generation") == info["generation"]
            and type(record.get("size")) is int and record["size"] == info["size"]
            and type(record.get("verified_at")) is int and record["verified_at"] > 0
            and isinstance(record.get("destination_version_id"), str)
            and 1 <= len(record["destination_version_id"]) <= 1024)


class Budget:
    def __init__(self, limit):
        self.limit, self.used = limit, 0

    @property
    def remaining(self):
        return self.limit - self.used

    def spend(self, size):
        if size < 0 or size > self.remaining:
            raise ValueError("transfer budget exhausted")
        self.used += size


def quarantine_allows_copy(record):
    """Match the independent review-hold schema; malformed state fails closed."""
    if record is None:
        return True
    if (not isinstance(record, dict) or set(record) != {"version", "holds"}
            or type(record["version"]) is not int or record["version"] != 1
            or not isinstance(record["holds"], dict) or len(record["holds"]) > 128):
        return False
    for hold_id, hold in record["holds"].items():
        if (not isinstance(hold_id, str) or not re.fullmatch(r"[A-Za-z0-9:_-]{1,128}", hold_id)
                or not isinstance(hold, dict) or set(hold) != {"version", "active"}
                or type(hold["version"]) is not int or not 0 < hold["version"] <= 9007199254740991
                or type(hold["active"]) is not bool or hold["active"]):
            return False
    return True


def approved_metadata(kv, key):
    """Uncached authoritative policy; errors propagate and cannot grant readiness."""
    meta = kv.get("blob:" + key)
    if not isinstance(meta, dict) or meta.get("sha256") != key:
        return None
    if meta.get("status") != "active" or not str(meta.get("type", "")).startswith("video/"):
        return None
    if not quarantine_allows_copy(kv.get("quarantine:v1:" + key)):
        return None
    owner = meta.get("owner")
    if not isinstance(owner, str) or not HEX.fullmatch(owner.lower()):
        return None
    if kv.get("tombstone:" + key) is not None:
        return None
    refs = kv.get("refs:" + key)
    if refs is None:
        refs = []
    if not isinstance(refs, list) or len(refs) > 1000:
        return None
    for uploader in [owner, *refs]:
        if not isinstance(uploader, str) or not HEX.fullmatch(uploader.lower()):
            return None
        if kv.get("vanish_in_progress:v1:" + uploader.lower()) is not None:
            return None
    return meta


def demand_policy(kv, key):
    """Distinguish reconsiderable approval from terminal revocation; never grant on error."""
    meta = kv.get("blob:" + key)
    if kv.get("tombstone:" + key) is not None:
        return "terminal"
    if not isinstance(meta, dict) or meta.get("sha256") != key:
        return "deferred"
    if meta.get("status") in ("restricted", "age_restricted", "banned", "deleted"):
        return "terminal"
    mime = meta.get("type")
    if isinstance(mime, str) and "/" in mime and not mime.startswith("video/"):
        return "terminal"
    refs = kv.get("refs:" + key)
    refs = [] if refs is None else refs
    owner = meta.get("owner")
    if not isinstance(refs, list) or len(refs) > 1000:
        return "deferred"
    for uploader in [owner, *refs]:
        if not isinstance(uploader, str) or not HEX.fullmatch(uploader.lower()):
            return "deferred"
        if kv.get("vanish_in_progress:v1:" + uploader.lower()) is not None:
            return "terminal"
    return "deferred"


class State:
    """SQLite schedule and fsynced partial objects; keep this directory across runs."""
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.directory / "state.sqlite3")
        self.db.execute("CREATE TABLE IF NOT EXISTS objects (hash TEXT PRIMARY KEY, generation TEXT, size INTEGER, checked INTEGER DEFAULT 0, ready TEXT)")
        self.db.execute("CREATE INDEX IF NOT EXISTS objects_checked ON objects(checked,hash)")
        self.db.execute("CREATE TABLE IF NOT EXISTS upload_queue (hash TEXT PRIMARY KEY, generation TEXT NOT NULL, available_at INTEGER NOT NULL DEFAULT 0)")
        self.db.execute("UPDATE upload_queue SET available_at=? WHERE available_at=0",(int(time.time()),))
        self.db.execute("CREATE INDEX IF NOT EXISTS uploads_due ON upload_queue(available_at,hash)")
        self.db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        self.db.execute("CREATE TABLE IF NOT EXISTS demand_queue (hash TEXT PRIMARY KEY, hint TEXT NOT NULL, available_at INTEGER NOT NULL, created_at INTEGER NOT NULL)")
        self.db.execute("CREATE INDEX IF NOT EXISTS demand_due ON demand_queue(available_at,hash)")
        self.db.execute("CREATE TABLE IF NOT EXISTS object_age (hash TEXT PRIMARY KEY, first_seen INTEGER NOT NULL, checked_at INTEGER NOT NULL)")
        self.db.execute("INSERT OR IGNORE INTO object_age SELECT hash,?,? FROM objects", (int(time.time()), int(time.time())))
        self.db.commit()

    def close(self):
        self.db.close()

    def spool(self, key):
        if not HEX.fullmatch(key):
            raise ValueError("invalid object key")
        return self.directory / (key + ".part")

    def setting(self, key):
        row = self.db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def set_setting(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (key, value))
        self.db.commit()

    def bind(self, identity):
        encoded = json.dumps(identity, sort_keys=True)
        old = self.setting("identity")
        if old is not None and old != encoded:
            raise ValueError("state directory belongs to another source/destination/store")
        self.set_setting("identity", encoded)

    def remember(self, key):
        self.db.execute("INSERT OR IGNORE INTO objects(hash) VALUES (?)", (key,))
        self.db.execute("INSERT OR IGNORE INTO object_age VALUES (?,?,?)", (key, int(time.time()), 0))
        self.db.commit()

    def queue_upload(self, key, generation, now=None):
        if not HEX.fullmatch(key) or not re.fullmatch(r"[1-9][0-9]{0,29}", generation):
            raise ValueError("invalid upload notification identity")
        due = int(time.time()) if now is None else now
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO objects(hash) VALUES (?)", (key,))
            old = self.db.execute("SELECT generation FROM upload_queue WHERE hash=?", (key,)).fetchone()
            if old is None:
                self.db.execute("INSERT INTO upload_queue(hash,generation,available_at) VALUES (?,?,?)", (key,generation,due))
            elif int(generation) > int(old[0]):
                self.db.execute("UPDATE upload_queue SET generation=?,available_at=? WHERE hash=?", (generation,due,key))

    def queued_uploads(self, limit, now=None):
        return self.db.execute("SELECT hash,generation FROM upload_queue WHERE available_at<=? ORDER BY available_at,hash LIMIT ?",
                               (int(time.time()) if now is None else now,limit)).fetchall()

    def queue_demand(self, key, hint, cap=10000, now=None):
        if not valid_hint(key, hint):
            raise ValueError("invalid demand hint")
        due = int(time.time()) if now is None else now
        with self.db:
            if self.db.execute("SELECT 1 FROM demand_queue WHERE hash=?", (key,)).fetchone():
                return True
            if self.db.execute("SELECT COUNT(*) FROM demand_queue").fetchone()[0] >= cap:
                return False
            self.db.execute("INSERT OR IGNORE INTO objects(hash) VALUES (?)", (key,))
            self.db.execute("INSERT INTO demand_queue VALUES (?,?,?,?)", (key, json.dumps(hint), due, due))
        return True

    def queued_demands(self, limit, now=None):
        return [row[0] for row in self.db.execute(
            "SELECT hash FROM demand_queue WHERE available_at<=? ORDER BY available_at,hash LIMIT ?",
            (int(time.time()) if now is None else now, limit))]

    def defer_demand(self, key, now=None):
        with self.db:
            self.db.execute("UPDATE demand_queue SET available_at=? WHERE hash=?",
                            ((int(time.time()) if now is None else now) + 300, key))

    def finish_demand(self, key):
        with self.db:
            self.db.execute("DELETE FROM demand_queue WHERE hash=?", (key,))

    def defer_upload(self, key, generation, now=None):
        with self.db:
            self.db.execute("UPDATE upload_queue SET available_at=? WHERE hash=? AND generation=?",
                            ((int(time.time()) if now is None else now)+300,key,generation))

    def finish_upload(self, key, generation):
        with self.db:
            self.db.execute("DELETE FROM upload_queue WHERE hash=? AND generation=?", (key,generation))

    def row(self, key):
        self.remember(key)
        return self.db.execute("SELECT generation,size,ready FROM objects WHERE hash=?", (key,)).fetchone()

    def reset(self, key, info=None):
        self.spool(key).unlink(missing_ok=True)
        self.db.execute("UPDATE objects SET generation=?,size=?,ready=NULL WHERE hash=?",
                        (info["generation"] if info else None, info["size"] if info else None, key))
        self.db.commit()

    def ready(self, key, record):
        self.db.execute("UPDATE objects SET ready=? WHERE hash=?", (json.dumps(record), key))
        self.db.commit()
        self.spool(key).unlink(missing_ok=True)

    def checked(self, key):
        # Monotonic across process restarts, including clock changes.
        sequence = int(self.setting("sequence") or 0) + 1
        self.set_setting("sequence", str(sequence))
        self.db.execute("UPDATE objects SET checked=? WHERE hash=?", (sequence, key))
        self.db.execute("UPDATE object_age SET checked_at=? WHERE hash=?", (int(time.time()), key))
        self.db.commit()


class Worker:
    def __init__(self, source, destination, kv, state, *, max_object_bytes, chunk_bytes, max_spool_bytes):
        self.source, self.destination, self.kv, self.state = source, destination, kv, state
        self.max_object_bytes = max_object_bytes
        self.chunk_bytes, self.max_spool_bytes = chunk_bytes, max_spool_bytes
        self.metrics = Counter()

    def invalidate(self, key, info=None):
        snapshot = self.kv.snapshot("b2-ready:" + key)
        if snapshot is not None and not self.kv.delete_if_generation("b2-ready:" + key, snapshot[1]):
            raise RuntimeError("readiness changed during invalidation")
        self.state.reset(key, info)

    def process(self, key, budget, reconcile=False):
        if not HEX.fullmatch(key):
            return "ignored"
        generation, size, ready = self.state.row(key)
        meta = approved_metadata(self.kv, key)
        if meta is None:
            self.invalidate(key)
            return demand_policy(self.kv, key) if reconcile else "blocked"
        info = self.source.head(key)
        if info is None:
            self.invalidate(key)
            return "missing"
        if info["size"] <= 0 or info["size"] > self.max_object_bytes:
            self.invalidate(key)
            return "oversized"
        if type(meta.get("size")) is not int or meta["size"] != info["size"]:
            self.invalidate(key)
            return "changed"
        gate = self.kv.get("b2-sync:v1:" + key)
        if gate is not None:
            return "terminal" if reconcile and gate == {"state": "erasing"} else "locked"
        observed = self.kv.snapshot("b2-ready:" + key) if reconcile else None
        if observed is not None:
            record = observed[0]
            if not readiness_matches(record, key, info, self.source.bucket, self.destination.bucket):
                raise ValueError("remote readiness cannot be adopted or repaired")
            present = self.destination.exists(key, record["destination_version_id"], info["size"])
            if approved_metadata(self.kv, key) != meta:
                self.invalidate(key)
                return demand_policy(self.kv, key)
            if self.source.head(key) != info or self.kv.snapshot("b2-ready:" + key) != observed:
                return "changed"
            if self.kv.get("b2-sync:v1:" + key) is not None:
                return "locked"
            if present:
                self.state.reset(key, info)
                self.state.ready(key, record)
                self.metrics["readiness_adopted"] += 1
                return "ready"
        if (generation, size) != (info["generation"], info["size"]):
            if reconcile:
                self.state.reset(key, info)
            else:
                self.invalidate(key, info)
            ready = None
        elif not reconcile and ready is not None and self.kv.get("b2-ready:" + key) == json.loads(ready):
            return "ready"
        generation, size = info["generation"], info["size"]
        path = self.state.spool(key)
        offset = path.stat().st_size if path.exists() else 0
        if offset > size:
            self.invalidate(key, info)
            offset = 0
        spool_bytes = sum(p.stat().st_size for p in self.state.directory.glob("*.part"))
        # Leave space to finish this original before starting another partial file.
        # The scheduler prioritizes existing partials; without this admission check
        # several partials could consume all spool capacity while none can finish.
        if offset == 0 and self.max_spool_bytes - spool_bytes < size:
            return "pending"
        while offset < size:
            count = min(self.chunk_bytes, size - offset, budget.remaining,
                        self.max_spool_bytes - spool_bytes)
            if count <= 0:
                return "pending"
            budget.spend(count)
            data = self.source.read(key, generation, offset, count)
            if len(data) != count:
                raise ValueError("source range length mismatch")
            with path.open("ab") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            offset += count
            spool_bytes += count
        with path.open("rb") as handle:
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
        if digest != key:
            self.invalidate(key, info)
            raise ValueError("source checksum mismatch")
        # Reserve both upload and independent full download before starting either.
        if budget.remaining < 2 * size:
            return "pending"
        if self.source.head(key) != info:
            self.invalidate(key)
            return "changed"
        if approved_metadata(self.kv, key) != meta:
            self.invalidate(key)
            return "blocked"
        attempt = str(uuid.uuid4())
        if not self.kv.claim_copy(key, attempt):
            return "locked"
        upload_state = {"uncertain": False}
        try:
            if approved_metadata(self.kv, key) != meta or self.source.head(key) != info:
                self.invalidate(key)
                return demand_policy(self.kv, key) if reconcile else "blocked"
            if reconcile:
                if self.kv.snapshot("b2-ready:" + key) != observed:
                    return "changed"
                if observed is not None:
                    # Keep durable retry responsibility before touching remote state.
                    if not self.state.queue_demand(key, {"version": 1, "sha256": key,
                            "reason": "missing_version", "observed_destination_version_id": observed[0]["destination_version_id"]}):
                        return "pending"
                    with self.state.db:
                        self.state.db.execute("UPDATE objects SET generation=?,size=?,ready=NULL WHERE hash=?",
                                              (info["generation"], info["size"], key))
                    if not self.kv.delete_if_generation("b2-ready:" + key, observed[1]):
                        return "changed"
            result = self.transfer(key, budget, path, size, generation, info, meta, upload_state)
            if reconcile and observed is not None and result == "ready":
                self.metrics["repairs_completed"] += 1
            return demand_policy(self.kv, key) if reconcile and result == "blocked" else result
        finally:
            # No TTL: an interrupted/uncertain PUT must block erasure completion
            # until an operator has drained that writer and reconciled versions.
            if not upload_state["uncertain"]:
                self.kv.release_copy(key, attempt)

    def transfer(self, key, budget, path, size, generation, info, meta, upload_state):
        budget.spend(size)
        upload_state["uncertain"] = True
        version = self.destination.upload(key, path, size)
        upload_state["uncertain"] = False
        if not isinstance(version, str) or not version or version == "null":
            raise ValueError("destination did not return immutable version")
        digest = hashlib.sha256()
        for start in range(0, size, self.chunk_bytes):
            count = min(self.chunk_bytes, size - start)
            budget.spend(count)
            data = self.destination.read(key, version, start, count, size)
            if len(data) != count:
                raise ValueError("destination range length mismatch")
            digest.update(data)
        if digest.hexdigest() != key:
            self.invalidate(key, info)
            raise ValueError("destination checksum mismatch")
        if self.source.head(key) != info:
            self.invalidate(key)
            return "changed"
        if approved_metadata(self.kv, key) != meta:
            self.invalidate(key)
            return "blocked"
        record = {"version": 1, "sha256": key, "verified_sha256": key,
                  "source_bucket": self.source.bucket, "source_generation": generation,
                  "bucket": self.destination.bucket, "key": key, "size": size,
                  "destination_version_id": version, "verified_at": int(time.time())}
        self.kv.put("b2-ready:" + key, record)
        if self.kv.get("b2-ready:" + key) != record:
            raise ValueError("readiness publication not confirmed")
        # No cross-service transaction exists. Endpoint independently gates policy on
        # every request, including a vanish between this last check and publication.
        if approved_metadata(self.kv, key) != meta:
            self.invalidate(key)
            return "blocked"
        self.state.ready(key, record)
        self.metrics["copies_completed"] += 1
        return "ready"

    def cycle(self, *, max_objects, max_bytes, discovery_limit=None, notifications=None, demand=None):
        report = Counter()
        self.metrics.clear()
        demand_enabled = demand is not None or bool(self.state.db.execute("SELECT 1 FROM demand_queue LIMIT 1").fetchone())
        upload_enabled = notifications is not None or bool(self.state.db.execute("SELECT 1 FROM upload_queue LIMIT 1").fetchone())
        lanes = (["demand"] if demand_enabled else []) + (["uploads"] if upload_enabled else []) + ["history"]
        if max_objects < len(lanes):
            raise ValueError("scheduling needs one object slot per configured lane")
        for intake, label in [(demand, "demand"), (notifications, "notification")]:
            if intake is not None:
                try:
                    report.update(intake.ingest(self.state, min(max_objects, 100)))
                except Exception:
                    report[label + "_errors"] += 1
                    report["errors"] += 1
        try:
            keys, cursor = self.source.page(self.state.setting("cursor"), discovery_limit or max_objects)
            for key in keys:
                if HEX.fullmatch(key):
                    self.state.remember(key)
            self.state.set_setting("cursor", cursor)
        except Exception:
            report["discovery_errors"] += 1
            report["errors"] += 1
        now = int(time.time())
        # A hint cannot bypass an upload's existing backoff, or vice versa.
        demands = [key for key in self.state.queued_demands(max_objects, now)
                   if not self.state.db.execute("SELECT 1 FROM upload_queue WHERE hash=? AND available_at>?", (key, now)).fetchone()]
        uploads = [(key, generation) for key, generation in self.state.queued_uploads(max_objects, now)
                   if not self.state.db.execute("SELECT 1 FROM demand_queue WHERE hash=? AND available_at>?", (key, now)).fetchone()]
        upload_generations = dict(uploads)
        partials = {p.stem for p in self.state.directory.glob("*.part") if HEX.fullmatch(p.stem)}
        history_partials = [key for key in sorted(partials) if self.state.db.execute(
            "SELECT 1 FROM objects WHERE hash=? AND NOT EXISTS (SELECT 1 FROM upload_queue WHERE hash=?) AND NOT EXISTS (SELECT 1 FROM demand_queue WHERE hash=?)",
            (key, key, key)).fetchone()]
        historical = [row[0] for row in self.state.db.execute(
            "SELECT hash FROM objects WHERE NOT EXISTS (SELECT 1 FROM upload_queue WHERE upload_queue.hash=objects.hash) AND NOT EXISTS (SELECT 1 FROM demand_queue WHERE demand_queue.hash=objects.hash) ORDER BY checked,hash LIMIT ?",
            (max_objects,))]
        groups = {"demand": demands, "uploads": [key for key, _ in uploads],
                  "history": list(dict.fromkeys(history_partials + historical))[:max_objects]}
        for group in groups.values():
            group.sort(key=lambda key: key not in partials)
        turn = int(self.state.setting("lane_turn") or 0) % len(lanes)
        self.state.set_setting("lane_turn", str((turn + 1) % len(lanes)))
        lanes = lanes[turn:] + lanes[:turn]
        candidates = []
        for index in range(max_objects):
            for lane in lanes:
                if index < len(groups[lane]) and groups[lane][index] not in candidates:
                    candidates.append(groups[lane][index])
        # Existing partials get first use of spool/bytes; lane rotation determines
        # fair admission whenever no resumable copy holds the spool.
        candidates.sort(key=lambda key: key not in partials)
        budget = Budget(max_bytes)
        for key in candidates[:max_objects]:
            generation = upload_generations.get(key)
            reconciles = key in demands
            result = "errors"
            try:
                metadata = self.kv.get("blob:" + key) if generation is not None and self.kv is not None else None
                mime = metadata.get("type") if isinstance(metadata, dict) else None
                if isinstance(mime, str) and "/" in mime and not mime.startswith("video/"):
                    self.invalidate(key)
                    result = "ignored"
                elif reconciles:
                    result = self.process(key, budget, reconcile=True)
                else:
                    result = self.process(key, budget)
                report[result] += 1
            except Exception:
                # SDK exceptions may contain signed URLs or identifiers.
                report["errors"] += 1
            finally:
                if generation is not None:
                    if result in ("ready", "missing", "oversized", "ignored", "terminal"):
                        self.state.finish_upload(key, generation)
                    else:
                        self.state.defer_upload(key, generation)
                if reconciles:
                    if result in ("ready", "missing", "oversized", "ignored", "terminal"):
                        self.state.finish_demand(key)
                    else:
                        self.state.defer_demand(key)
                self.state.checked(key)
        for lane, table, age_column in [("demand", "demand_queue", "created_at"),
                                         ("notification", "upload_queue", "available_at")]:
            count, oldest = self.state.db.execute(f"SELECT COUNT(*),MIN({age_column}) FROM {table}").fetchone()
            report[lane + "_pending"] = count
            report[lane + "_oldest_seconds"] = max(0, now - oldest) if oldest is not None else 0
        count = self.state.db.execute("SELECT COUNT(*) FROM objects").fetchone()[0]
        report["history_known"] = count
        oldest = self.state.db.execute("SELECT MIN(CASE WHEN checked_at>0 THEN checked_at ELSE first_seen END) FROM object_age").fetchone()[0]
        report["history_oldest_seconds"] = max(0, now - oldest) if oldest is not None else 0
        report["spool_bytes"] = sum(p.stat().st_size for p in self.state.directory.glob("*.part"))
        report["transfer_bytes_reserved"] = budget.used
        report.update(self.metrics)
        return dict(report)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def unambiguous_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object member")
        result[key] = value
    return result


class JsonHTTP:
    def __init__(self, headers=None):
        self.headers = headers or {}
        self.opener = urllib.request.build_opener(NoRedirect)

    def request(self, url, method="GET", value=None, missing=False, conflict=False, headers=None, include_headers=False, max_response_bytes=MIB):
        body = json.dumps(value).encode() if value is not None else None
        request = urllib.request.Request(url, data=body, method=method,
                                         headers={**self.headers, "Content-Type": "application/json", **(headers or {})})
        try:
            with self.opener.open(request, timeout=30) as response:
                data = response.read(max_response_bytes + 1)
                if len(data) > max_response_bytes:
                    raise ValueError("control response too large")
                value = json.loads(data, object_pairs_hook=unambiguous_json_object) if data else None
                return (value, response.headers) if include_headers else value
        except urllib.error.HTTPError as error:
            try:
                if missing and error.code == 404:
                    return None
                if conflict and error.code in (409, 412):
                    return False
                raise ControlAPIError(error.code) from None
            finally:
                error.close()


class ControlAPIError(RuntimeError):
    def __init__(self, status):
        self.status = status
        super().__init__("control API HTTP failure")


class DemandHints:
    """Bounded durable handoff. Hints request reconciliation, never authorize it."""
    def __init__(self, kv, pending_cap=10000):
        if type(pending_cap) is not int or not 1 <= pending_cap <= 100000:
            raise ValueError("invalid pending demand cap")
        self.kv, self.pending_cap = kv, pending_cap

    def ingest(self, state, limit):
        report = Counter()
        try:
            keys, cursor = self.kv.demand_page(state.setting("demand_cursor"), min(limit, 100))
        except ControlAPIError as error:
            if error.status == 400 and state.setting("demand_cursor") is not None:
                state.set_setting("demand_cursor", None)
            raise
        for key in keys:
            report["demand_received"] += 1
            if not key.startswith(DEMAND_PREFIX) or not HEX.fullmatch(key[len(DEMAND_PREFIX):]):
                report["demand_unknown_key"] += 1
                continue
            try:
                snapshot = self.kv.snapshot(key)
            except Exception:
                # Retain this key for the next scan without letting an oversized
                # or unavailable value strand every later page indefinitely.
                report["demand_snapshot_errors"] += 1
                report["errors"] += 1
                continue
            if snapshot is None:
                continue
            record, generation = snapshot
            version = record.get("version") if isinstance(record, dict) else None
            if type(version) is int and version > 1:
                report["demand_future_schema"] += 1
                continue
            hash_key = key[len(DEMAND_PREFIX):]
            if valid_hint(hash_key, record):
                if not state.queue_demand(hash_key, record, cap=self.pending_cap):
                    report["demand_saturated"] += 1
                    continue
                report["demand_enqueued"] += 1
            else:
                report["demand_invalid"] += 1
            if self.kv.delete_if_generation(key, generation):
                report["demand_acknowledged"] += 1
            else:
                report["demand_conflicts"] += 1
        # Retained/saturated entries are reconsidered at cursor wrap; no dropped
        # work and no unbounded rescanning of the first page in one invocation.
        state.set_setting("demand_cursor", cursor)
        return dict(report)


class PubSubNotifications:
    """At-least-once hints; only SQLite commit permits acknowledgement."""
    def __init__(self, subscription, source_bucket, credentials, http=None):
        if not re.fullmatch(r"projects/[A-Za-z0-9][A-Za-z0-9._:-]*/subscriptions/[A-Za-z][A-Za-z0-9._~-]*", subscription):
            raise ValueError("invalid notification subscription")
        self.subscription, self.source_bucket = subscription, source_bucket
        self.credentials, self.http = credentials, http or JsonHTTP()

    def request(self, operation, value):
        if operation not in ("pull","acknowledge"):
            raise ValueError("unsupported notification operation")
        if not self.credentials.valid:
            from google.auth.transport.requests import Request
            self.credentials.refresh(Request())
        return self.http.request("https://pubsub.googleapis.com/v1/"+self.subscription+":"+operation,
                                 "POST",value,headers={"Authorization":"Bearer "+self.credentials.token})

    def ingest(self, state, limit):
        if type(limit) is not int or not 1<=limit<=1000:
            raise ValueError("invalid notification pull limit")
        reply = self.request("pull", {"maxMessages":limit,"returnImmediately":True})
        messages = reply.get("receivedMessages",[]) if isinstance(reply,dict) else None
        if not isinstance(messages,list) or len(messages)>limit:
            raise ValueError("invalid notification response")
        ack_ids, enqueued, ignored = [],0,0
        for message in messages:
            ack = message.get("ackId") if isinstance(message,dict) else None
            if not isinstance(ack,str) or not 1<=len(ack)<=4096:
                raise ValueError("missing notification acknowledgement")
            ack_ids.append(ack)
            envelope = message.get("message",{})
            attributes = envelope.get("attributes",{}) if isinstance(envelope,dict) else {}
            if not isinstance(attributes,dict):
                attributes = {}
            key, generation = attributes.get("objectId"), attributes.get("objectGeneration")
            if (attributes.get("eventType")=="OBJECT_FINALIZE" and attributes.get("bucketId")==self.source_bucket
                and isinstance(key,str) and HEX.fullmatch(key) and isinstance(generation,str)
                and re.fullmatch(r"[1-9][0-9]{0,29}",generation)):
                state.queue_upload(key,generation)
                enqueued += 1
            else:
                ignored += 1
        # Every queued item is committed before any message can leave Pub/Sub.
        if ack_ids:
            self.request("acknowledge", {"ackIds":ack_ids})
        return {"notifications_received":len(messages),"notifications_enqueued":enqueued,"notifications_ignored":ignored}


class FastlyKV:
    def __init__(self, store_id, token, http=None):
        if not re.fullmatch(r"[A-Za-z0-9_-]+", store_id):
            raise ValueError("invalid KV store id")
        self.base = "https://api.fastly.com/resources/stores/kv/" + store_id + "/keys/"
        self.http = http or JsonHTTP({"Fastly-Key": token})

    def url(self, key):
        return self.base + urllib.parse.quote(key, safe="")

    def get(self, key):
        if key.startswith("quarantine:v1:"):
            # HTTP 404 means no holds; a present JSON null is malformed, not absent.
            result = self.http.request(self.url(key), missing=True, include_headers=True)
            if result is None:
                return None
            record, _ = result
            return {} if record is None else record
        return self.http.request(self.url(key), missing=True)

    def put(self, key, value):
        if not key.startswith("b2-ready:") or not HEX.fullmatch(key[9:]):
            raise ValueError("only readiness keys may be written")
        self.http.request(self.url(key), "PUT", value)

    def delete(self, key):
        if not key.startswith("b2-ready:") or not HEX.fullmatch(key[9:]):
            raise ValueError("only readiness keys may be deleted")
        snapshot = self.snapshot(key)
        if snapshot is not None and not self.delete_if_generation(key, snapshot[1]):
            raise RuntimeError("readiness changed during deletion")

    def snapshot(self, key):
        if not ((key.startswith("b2-ready:") and HEX.fullmatch(key[9:]))
                or (key.startswith(DEMAND_PREFIX) and HEX.fullmatch(key[len(DEMAND_PREFIX):]))):
            raise ValueError("only readiness and demand snapshots are supported")
        result = self.http.request(self.url(key), missing=True, include_headers=True,
                                   max_response_bytes=4096)
        if result is None:
            return None
        value, headers = result
        generation = headers.get("generation")
        if not valid_generation(generation):
            raise ValueError("snapshot generation unavailable")
        # A present null must not look like an absent readiness/hint.
        return ({} if value is None else value), generation

    def delete_if_generation(self, key, generation):
        if not valid_generation(generation):
            raise ValueError("conditional deletion requires a generation")
        if not ((key.startswith("b2-ready:") and HEX.fullmatch(key[9:]))
                or (key.startswith(DEMAND_PREFIX) and HEX.fullmatch(key[len(DEMAND_PREFIX):]))):
            raise ValueError("conditional deletion namespace denied")
        return self.http.request(self.url(key), "DELETE", missing=True, conflict=True,
                                 headers={"if-generation-match": generation}) is not False

    def demand_page(self, cursor, limit):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("demand page limit must be 1..100")
        # The control API rejects colons in list prefixes (verified against live API).
        params = {"prefix": "b2-demand", "limit": limit}
        if cursor is not None:
            if not isinstance(cursor, str) or not 1 <= len(cursor) <= 4096:
                raise ValueError("invalid demand cursor")
            params["cursor"] = cursor
        reply = self.http.request(self.base.rstrip("/") + "?" + urllib.parse.urlencode(params))
        keys = reply.get("data") if isinstance(reply, dict) else None
        meta = reply.get("meta", {}) if isinstance(reply, dict) else {}
        if not isinstance(keys, list) or len(keys) > limit or not isinstance(meta, dict):
            raise ValueError("invalid demand listing")
        next_cursor = meta.get("next_cursor")
        if next_cursor is not None and (not isinstance(next_cursor, str) or len(next_cursor) > 4096):
            raise ValueError("invalid next demand cursor")
        if any(not isinstance(k, str) or not k.startswith("b2-demand") or len(k) > 1024 for k in keys):
            raise ValueError("out-of-prefix demand listing")
        return keys, next_cursor or None

    def claim_copy(self, key, attempt):
        if not HEX.fullmatch(key):
            raise ValueError("invalid copy gate hash")
        value = {"state": "copying", "attempt_id": attempt}
        result = self.http.request(self.url("b2-sync:v1:" + key) + "?add=true", "PUT", value, conflict=True)
        if result is False:
            return False
        if self.get("b2-sync:v1:" + key) != value:
            raise ValueError("copy gate acquisition not confirmed")
        return True

    def release_copy(self, key, attempt):
        if not HEX.fullmatch(key):
            raise ValueError("invalid copy gate hash")
        gate = "b2-sync:v1:" + key
        value, headers = self.http.request(self.url(gate), include_headers=True)
        if value != {"state": "copying", "attempt_id": attempt}:
            raise ValueError("copy gate ownership lost")
        generation = headers.get("generation")
        if not isinstance(generation, str) or not re.fullmatch(r"[0-9]+", generation) or not 0 < int(generation) < 2 ** 64:
            raise ValueError("copy gate generation unavailable")
        self.http.request(self.url(gate), "DELETE", headers={"if-generation-match": generation})


class GCSSource:
    def __init__(self, bucket, client):
        self.bucket, self.client = bucket, client
        self.handle = client.bucket(bucket)

    def head(self, key):
        blob = self.handle.get_blob(key, timeout=30, retry=None)
        return {"generation": str(blob.generation), "size": blob.size} if blob else None

    def read(self, key, generation, start, length):
        # Read current live object with generation precondition, not a stale retained
        # generation. raw_download prevents transparent decompression changing bytes.
        return self.handle.blob(key).download_as_bytes(start=start, end=start + length - 1,
                   if_generation_match=int(generation), raw_download=True, checksum=None,
                   timeout=30, retry=None)

    def page(self, cursor, limit):
        blobs = self.client.list_blobs(self.bucket, page_token=cursor, page_size=limit,
                                      max_results=limit, timeout=30, retry=None)
        page = next(blobs.pages, None)
        if page is None:
            return [], None
        return [blob.name for blob in page], blobs.next_page_token


class B2Destination:
    def __init__(self, bucket, client):
        self.bucket, self.client = bucket, client

    def upload(self, key, path, size):
        # Bounded originals use one PUT. No managed multipart/retry worker can
        # silently exceed the reservation or create abandoned multipart uploads.
        with path.open("rb") as handle:
            result = self.client.put_object(Bucket=self.bucket, Key=key, Body=handle,
                       ContentLength=size, ContentType="application/octet-stream")
        return result.get("VersionId")

    def read(self, key, version, start, length, total_size):
        result = self.client.get_object(Bucket=self.bucket, Key=key, VersionId=version,
                   Range=f"bytes={start}-{start + length - 1}")
        body = result["Body"]
        try:
            if result.get("VersionId") != version or result.get("ContentLength") != length:
                raise ValueError("destination version or length mismatch")
            if result.get("ContentRange") != f"bytes {start}-{start + length - 1}/{total_size}":
                raise ValueError("destination range mismatch")
            return body.read(length + 1)
        finally:
            body.close()

    def exists(self, key, version, size):
        from botocore.exceptions import ClientError
        try:
            result = self.client.head_object(Bucket=self.bucket, Key=key, VersionId=version)
        except ClientError as error:
            # HEAD has no XML body: S3-compatible providers can return a generic
            # 404 rather than a modeled NoSuchVersion exception. No other failure
            # is evidence of absence, especially auth, throttling and transport.
            status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            code = error.response.get("Error", {}).get("Code")
            if status == 404 and code in ("404", "NoSuchKey", "NoSuchVersion", "NotFound"):
                return False
            raise
        if result.get("VersionId") != version or result.get("ContentLength") != size:
            raise ValueError("destination probe version or size mismatch")
        return True


def private_b2_endpoint(bucket, bucket_id, key_id, key, http_factory=JsonHTTP):
    """Verify actual private bucket identity and obtain its S3 endpoint, read-only."""
    auth_header = base64.b64encode((key_id + ":" + key).encode()).decode()
    auth = http_factory({"Authorization": "Basic " + auth_header}).request(
        "https://api.backblazeb2.com/b2api/v4/b2_authorize_account")
    storage = auth["apiInfo"]["storageApi"]
    endpoint = storage["s3ApiUrl"]
    if not re.fullmatch(r"https://s3\.[a-z0-9-]+\.backblazeb2\.com", endpoint):
        raise ValueError("unexpected B2 S3 endpoint")
    if not re.fullmatch(r"https://api[0-9]+\.backblazeb2\.com", storage["apiUrl"]):
        raise ValueError("unexpected B2 control endpoint")
    result = http_factory({"Authorization": auth["authorizationToken"]}).request(
        storage["apiUrl"] + "/b2api/v4/b2_list_buckets", "POST",
        {"accountId": auth["accountId"], "bucketId": bucket_id})
    buckets = result.get("buckets", [])
    if len(buckets) != 1 or buckets[0].get("bucketName") != bucket or buckets[0].get("bucketId") != bucket_id or buckets[0].get("bucketType") != "allPrivate":
        raise ValueError("destination is not the configured private erasure bucket")
    lock = buckets[0].get("fileLockConfiguration") or {}
    value = lock.get("value") or {}
    retention = value.get("defaultRetention") or {}
    if lock.get("isClientAuthorizedToRead") is not True or value.get("isFileLockEnabled") is not False or "mode" not in retention or retention["mode"] is not None:
        raise ValueError("destination retention must be visible and Object Lock disabled")
    return endpoint


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-bucket", required=True)
    parser.add_argument("--destination-bucket", required=True)
    parser.add_argument("--destination-bucket-id", required=True)
    parser.add_argument("--erasure-bucket", required=True)
    parser.add_argument("--erasure-bucket-id", required=True)
    parser.add_argument("--kv-store-id", required=True)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--notification-subscription", help="Dedicated GCS OBJECT_FINALIZE subscription; disabled by default")
    parser.add_argument("--demand-intake", action="store_true", help="Intake bounded demand hints; disabled by default. Committed demand is processed even when intake is off.")
    parser.add_argument("--max-pending-demand", type=int, default=10000)
    parser.add_argument("--discovery-limit", type=int, help="Source names discovered per pass (1..1000); defaults to max-objects")
    parser.add_argument("--max-objects", type=int, default=10)
    parser.add_argument("--max-bytes", type=int, default=256 * MIB)
    parser.add_argument("--max-object-bytes", type=int, default=64 * MIB)
    parser.add_argument("--max-spool-bytes", type=int, default=256 * MIB)
    parser.add_argument("--chunk-bytes", type=int, default=MIB)
    args = parser.parse_args(argv)
    if (args.destination_bucket, args.destination_bucket_id) != (args.erasure_bucket, args.erasure_bucket_id):
        parser.error("destination must equal the configured all-version erasure bucket")
    if any(getattr(args, name) <= 0 for name in ("max_objects", "max_bytes", "max_object_bytes", "max_spool_bytes", "chunk_bytes")):
        parser.error("all budgets must be positive")
    if args.max_object_bytes > 64 * MIB or args.chunk_bytes > MIB:
        parser.error("canary ceiling is 64 MiB per original and 1 MiB per chunk")
    if args.max_bytes < 2 * args.max_object_bytes or args.max_spool_bytes < args.max_object_bytes:
        parser.error("budgets must permit upload plus verification of one maximum-sized object")
    if args.discovery_limit is not None and not 1<=args.discovery_limit<=1000:
        parser.error("discovery limit must be between 1 and 1000")
    if args.notification_subscription and args.max_objects<2:
        parser.error("notification scheduling requires at least two object slots")
    if not 1 <= args.max_objects <= 1000 or not 1 <= args.max_pending_demand <= 100000:
        parser.error("object slots must be 1..1000 and pending demand cap 1..100000")
    if args.demand_intake and args.max_objects < (3 if args.notification_subscription else 2):
        parser.error("demand scheduling needs one object slot per configured lane")
    os.umask(0o077)
    args.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (args.state_dir / "worker.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        from google.cloud import storage
        import boto3
        from botocore.config import Config
        key_id, key = os.environ["B2_APPLICATION_KEY_ID"], os.environ["B2_APPLICATION_KEY"]
        endpoint = private_b2_endpoint(args.destination_bucket, args.destination_bucket_id, key_id, key)
        client = boto3.client("s3", endpoint_url=endpoint,
                 region_name=endpoint.split(".")[1], aws_access_key_id=key_id,
                 aws_secret_access_key=key, config=Config(signature_version="s3v4",
                   retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=30,
                   s3={"addressing_style": "path"}, request_checksum_calculation="when_required",
                   response_checksum_validation="when_required"))
        state = State(args.state_dir)
        try:
            state.bind({"source": args.source_bucket, "destination": args.destination_bucket,
                        "bucket_id": args.destination_bucket_id, "kv_store": args.kv_store_id})
            worker = Worker(GCSSource(args.source_bucket, storage.Client()),
                        B2Destination(args.destination_bucket, client),
                        FastlyKV(args.kv_store_id, os.environ["FASTLY_API_TOKEN"]), state,
                        max_object_bytes=args.max_object_bytes, chunk_bytes=args.chunk_bytes,
                        max_spool_bytes=args.max_spool_bytes)
            notifications = None
            if args.notification_subscription:
                bound = state.setting("notification_subscription")
                if bound is not None and bound != args.notification_subscription:
                    raise ValueError("state belongs to another notification subscription")
                state.set_setting("notification_subscription",args.notification_subscription)
                import google.auth
                credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/pubsub"])
                notifications = PubSubNotifications(args.notification_subscription,args.source_bucket,credentials)
            report = worker.cycle(max_objects=args.max_objects, max_bytes=args.max_bytes,
                                  discovery_limit=args.discovery_limit, notifications=notifications,
                                  demand=DemandHints(worker.kv, args.max_pending_demand) if args.demand_intake else None)
            print(json.dumps(report, sort_keys=True))
            return 1 if report.get("errors") else 0
        finally:
            state.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("Mirror failed; inspect configuration and retry. Provider details suppressed.", file=sys.stderr)
        sys.exit(1)
