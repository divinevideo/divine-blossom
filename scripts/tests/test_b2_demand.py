"""Demand work survives restarts, respects policy, and repairs only proven misses."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from test_sync_b2_originals import mirror, Source, Destination, KV, HASH, DATA, boto3, Config


def hint(reason="missing_readiness", version=None):
    value = {"version": 1, "sha256": HASH, "reason": reason}
    if version is not None:
        value["observed_destination_version_id"] = version
    return value


class WorkerFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = mirror.State(Path(self.temp.name))
        self.addCleanup(lambda: self.state.close())
        self.source, self.dest, self.kv = Source(), Destination(), KV()
        self.worker = mirror.Worker(self.source, self.dest, self.kv, self.state,
                                   max_object_bytes=100, chunk_bytes=5, max_spool_bytes=200)

    def process(self):
        return self.worker.process(HASH, mirror.Budget(1000), reconcile=True)


class DemandTests(WorkerFixture):

    def test_absent_readiness_invalidation_never_claims_a_copy_gate(self):
        self.state.remember(HASH)
        self.state.spool(HASH).write_bytes(b"unfinished")
        self.kv.values["blob:" + HASH]["status"] = "restricted"
        self.kv.claim_copy = lambda *args: self.fail("local cleanup must not block erasure")
        self.assertEqual(self.process(), "terminal")
        self.assertFalse(self.state.spool(HASH).exists())
        self.assertIsNone(self.kv.get("b2-sync:v1:" + HASH))

    def test_local_only_invalidation_preserves_concurrently_published_readiness(self):
        self.state.remember(HASH)
        replacement = {"destination_version_id": "new-version"}
        def changed_remote_state():
            self.kv.values["b2-ready:" + HASH] = replacement
            return True
        self.kv.claim_copy = lambda *args: self.fail("local cleanup must not claim a gate")
        self.assertTrue(self.worker.invalidate(HASH, observed=None, allowed=changed_remote_state))
        self.assertEqual(self.kv.get("b2-ready:" + HASH), replacement)

    def test_local_only_invalidation_rechecks_its_decision(self):
        self.state.remember(HASH)
        self.state.spool(HASH).write_bytes(b"unfinished")
        self.assertFalse(self.worker.invalidate(HASH, observed=None, allowed=lambda: False))
        self.assertEqual(self.state.spool(HASH).read_bytes(), b"unfinished")

    def test_stale_policy_observer_cannot_delete_newer_readiness_before_snapshot(self):
        self.process()
        replacement = dict(self.kv.get("b2-ready:" + HASH), destination_version_id="new-version")
        lookup = self.kv.get
        armed = [True]
        def read(key):
            if key == "blob:" + HASH and armed[0]:
                armed[0] = False
                stale = dict(lookup(key), status="restricted")
                self.kv.values["b2-ready:" + HASH] = replacement
                return stale
            return lookup(key)
        self.kv.get = read
        self.process()
        self.assertEqual(self.kv.get("b2-ready:" + HASH), replacement)

    def test_spool_never_opens_second_partial_and_recovers_older_overcommit(self):
        other = "b" * 64
        self.worker.max_spool_bytes = 40
        self.state.spool(other).write_bytes(b"x" * 30)
        self.worker.max_object_bytes = 40
        self.source.data = b"x" * 40
        self.kv.values["blob:" + HASH]["size"] = 40
        self.assertEqual(self.process(), "pending")
        self.assertFalse(self.state.spool(HASH).exists())
        self.state.spool(HASH).write_bytes(b"x" * 5)
        self.assertEqual(self.process(), "pending")
        self.assertFalse(self.state.spool(HASH).exists())
        self.assertEqual(self.state.spool(other).stat().st_size, 30)

    def test_source_generation_refresh_survives_overlapping_demand_and_upload(self):
        for version_present in (False, True):
            with self.subTest(version_present=version_present):
                self.source.generation = "7"
                self.assertEqual(self.process(), "ready")
                self.source.generation = "8"
                if not version_present:
                    self.dest.versions.clear()
                self.state.queue_demand(HASH, hint())
                self.state.queue_upload(HASH, "8")
                report = self.worker.cycle(max_objects=3, max_bytes=200)
                self.assertEqual(report.get("errors", 0), 0)
                self.assertEqual(self.kv.get("b2-ready:" + HASH)["source_generation"], "8")
                self.assertEqual(self.state.queued_demands(10), [])
                self.assertEqual(self.state.queued_uploads(10), [])

    def test_duplicate_and_restart_preserve_retry_deadline_and_pending_cap(self):
        self.assertTrue(self.state.queue_demand(HASH, hint(), cap=1, now=100))
        self.state.defer_demand(HASH, now=100)
        self.assertTrue(self.state.queue_demand(HASH, hint("missing_version", "old"), cap=1, now=101))
        self.assertFalse(self.state.queue_demand("b" * 64, dict(hint(), sha256="b" * 64), cap=1))
        self.state.close()
        self.state = mirror.State(Path(self.temp.name))
        self.assertEqual(self.state.queued_demands(10, now=399), [])
        self.assertEqual(self.state.queued_demands(10, now=400), [HASH])

    def test_remote_verified_readiness_is_adopted_without_another_upload(self):
        self.assertEqual(self.process(), "ready")
        self.state.reset(HASH)
        self.dest.upload = lambda *args: self.fail("existing verified version must be adopted")
        self.assertEqual(self.process(), "ready")
        self.assertIsNotNone(self.state.row(HASH)[2])
        self.assertEqual(self.worker.metrics["copies_completed"], 1)
        self.assertEqual(self.worker.metrics["readiness_adopted"], 1)

    def test_generic_hint_repairs_missing_version_instead_of_trusting_local_ready(self):
        self.assertEqual(self.process(), "ready")
        self.dest.versions.clear()
        uploaded = self.dest.upload
        def under_gate(*args):
            self.assertEqual(self.kv.get("b2-sync:v1:" + HASH)["state"], "copying")
            self.assertIsNone(self.kv.get("b2-ready:" + HASH))
            self.assertEqual(self.state.queued_demands(10), [HASH])
            return uploaded(*args)
        self.dest.upload = under_gate
        self.assertEqual(self.process(), "ready")
        self.assertIsNotNone(self.kv.get("b2-ready:" + HASH))
        self.assertEqual(self.worker.metrics["repairs_completed"], 1)

    def test_readiness_advancing_before_gate_is_not_deleted_or_recopied(self):
        self.process()
        self.dest.versions.clear()
        replacement = dict(self.kv.get("b2-ready:" + HASH), destination_version_id="new-version")
        claim = self.kv.claim_copy
        def racing_claim(*args):
            result = claim(*args)
            self.kv.values["b2-ready:" + HASH] = replacement
            return result
        self.kv.claim_copy = racing_claim
        self.dest.upload = lambda *args: self.fail("stale observer copied")
        self.assertEqual(self.process(), "changed")
        self.assertEqual(self.kv.get("b2-ready:" + HASH), replacement)

    def test_probe_outage_and_malformed_readiness_preserve_remote_record(self):
        self.process()
        record = copy.deepcopy(self.kv.get("b2-ready:" + HASH))
        self.dest.exists = lambda *args: (_ for _ in ()).throw(OSError("synthetic unavailable"))
        with self.assertRaises(OSError):
            self.process()
        self.assertEqual(self.kv.get("b2-ready:" + HASH), record)
        self.kv.values["b2-ready:" + HASH] = {"version": 1}
        with self.assertRaises(ValueError):
            self.process()
        self.assertEqual(self.kv.get("b2-ready:" + HASH), {"version": 1})

    def test_public_pending_is_eligible_but_holds_and_malformed_policy_defer(self):
        self.kv.values["blob:" + HASH]["status"] = "pending"
        self.assertEqual(self.process(), "ready")
        self.assertEqual(self.kv.get("blob:" + HASH)["status"], "pending")
        versions = dict(self.dest.versions)
        for status, expected in [("restricted", "terminal"),
                                 ("banned", "terminal"), ("deleted", "terminal")]:
            self.kv.values["blob:" + HASH]["status"] = status
            self.assertEqual(self.process(), expected)
        self.kv.values["blob:" + HASH]["status"] = "active"
        self.kv.values["quarantine:v1:" + HASH] = {"version": 1, "holds": {"review": {"version": 1, "active": True}}}
        self.assertEqual(self.process(), "deferred")
        self.kv.values.pop("quarantine:v1:" + HASH)
        self.kv.values["blob:" + HASH]["owner"] = None
        self.assertEqual(self.process(), "deferred")
        self.assertEqual(self.dest.versions, versions)

    def test_revocation_during_probe_does_not_adopt_or_copy(self):
        self.process()
        probe = self.dest.exists
        def revoke(*args):
            self.kv.values["tombstone:" + HASH] = {}
            return probe(*args)
        self.dest.exists = revoke
        self.assertEqual(self.process(), "terminal")
        self.assertIsNone(self.kv.get("b2-ready:" + HASH))

    def test_conditional_invalidation_does_not_reset_local_state_on_conflict(self):
        self.process()
        ready = self.state.row(HASH)[2]
        self.kv.delete_if_generation = lambda *args: False
        self.assertFalse(self.worker.invalidate(HASH, observed=self.kv.snapshot("b2-ready:" + HASH)))
        self.assertEqual(self.state.row(HASH)[2], ready)


class IntakeTests(unittest.TestCase):
    def test_unreadable_first_hint_does_not_strand_later_pages(self):
        with tempfile.TemporaryDirectory() as directory:
            state = mirror.State(directory)
            self.addCleanup(state.close)
            kv = KV()
            bad, good = "b2-demand:v1:" + "b" * 64, "b2-demand:v1:" + HASH
            kv.values[good] = hint()
            kv.demand_page = lambda cursor, limit: ([bad, good], "next-page")
            snapshot = kv.snapshot
            def read(key):
                if key == bad:
                    raise ValueError("synthetic oversized record or missing generation")
                return snapshot(key)
            kv.snapshot = read
            report = mirror.DemandHints(kv).ingest(state, 10)
            self.assertEqual(state.queued_demands(10), [HASH])
            self.assertEqual(state.setting("demand_cursor"), "next-page")
            self.assertEqual(report["demand_snapshot_errors"], 1)

    def test_invalid_cursor_resets_only_cursor_and_leaves_committed_jobs(self):
        with tempfile.TemporaryDirectory() as directory:
            state = mirror.State(directory)
            self.addCleanup(state.close)
            state.queue_demand(HASH, hint())
            state.set_setting("demand_cursor", "expired")
            kv = KV()
            kv.demand_page = lambda *args: (_ for _ in ()).throw(mirror.ControlAPIError(400))
            with self.assertRaises(mirror.ControlAPIError):
                mirror.DemandHints(kv).ingest(state, 10)
            self.assertIsNone(state.setting("demand_cursor"))
            self.assertEqual(state.queued_demands(10), [HASH])

    def test_commit_precedes_conditional_removal_and_crash_redelivery_coalesces(self):
        with tempfile.TemporaryDirectory() as directory:
            state = mirror.State(directory)
            self.addCleanup(state.close)
            kv = KV()
            key = "b2-demand:v1:" + HASH
            kv.values[key] = hint()
            kv.demand_page = lambda cursor, limit: ([key], None)
            def remove(key, generation):
                self.assertEqual(state.queued_demands(10), [HASH])
                raise OSError("lost acknowledgement")
            kv.delete_if_generation = remove
            intake = mirror.DemandHints(kv)
            with self.assertRaises(OSError):
                intake.ingest(state, 10)
            self.assertIsNotNone(kv.get(key))
            state.defer_demand(HASH, now=100)
            kv.delete_if_generation = lambda *args: True
            intake.ingest(state, 10)
            self.assertEqual(state.queued_demands(10, now=399), [])
            self.assertEqual(state.queued_demands(10, now=400), [HASH])

    def test_future_schema_is_retained_and_saturation_never_acknowledges_new_work(self):
        with tempfile.TemporaryDirectory() as directory:
            state = mirror.State(directory)
            self.addCleanup(state.close)
            kv = KV()
            future, valid = "b2-demand:v1:" + "b"*64, "b2-demand:v1:" + HASH
            kv.values[future] = {"version": 2}
            kv.values[valid] = hint()
            kv.demand_page = lambda cursor, limit: ([future, valid], "next-page")
            report = mirror.DemandHints(kv, pending_cap=1).ingest(state, 10)
            self.assertIsNotNone(kv.get(future))
            self.assertIsNone(kv.get(valid))
            self.assertEqual(state.setting("demand_cursor"), "next-page")
            other = "c" * 64
            kv.values["b2-demand:v1:" + other] = dict(hint(), sha256=other)
            kv.demand_page = lambda cursor, limit: (["b2-demand:v1:" + other], None)
            report = mirror.DemandHints(kv, pending_cap=1).ingest(state, 10)
            self.assertEqual(report["demand_saturated"], 1)
            self.assertIsNotNone(kv.get("b2-demand:v1:" + other))

    def test_real_kv_adapter_lists_with_supported_prefix_and_deletes_only_observed_generation(self):
        calls, key = [], "b2-demand:v1:" + HASH
        generation = ["7"]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def reply(self, status, value=None):
                data = json.dumps(value).encode() if value is not None else b""
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                if generation[0] is not None:
                    self.send_header("generation", generation[0])
                self.end_headers()
                self.wfile.write(data)
            def do_GET(self):
                calls.append(("GET", self.path))
                parsed = urlsplit(self.path)
                if parsed.path == "/keys":
                    if parse_qs(parsed.query).get("prefix") != ["b2-demand"]:
                        return self.reply(400)
                    return self.reply(200, {"data": [key], "meta": {"next_cursor": "opaque +/=", "limit": 1}})
                self.reply(200, hint())
            def do_DELETE(self):
                calls.append(("DELETE", self.headers.get("if-generation-match")))
                self.reply(204 if self.headers.get("if-generation-match") == generation[0] else 412)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        kv = mirror.FastlyKV("synthetic", "synthetic-token")
        kv.base = f"http://127.0.0.1:{server.server_port}/keys/"
        self.assertEqual(kv.demand_page(None, 1), ([key], "opaque +/="))
        record, observed = kv.snapshot(key)
        self.assertEqual(record, hint())
        generation[0] = "8"
        self.assertFalse(kv.delete_if_generation(key, observed))
        generation[0] = None
        with self.assertRaises(ValueError):
            kv.snapshot(key)
        self.assertEqual([call for call in calls if call[0] == "DELETE"], [("DELETE", "7")])
        with self.assertRaises(ValueError):
            kv.delete_if_generation("blob:" + HASH, "8")


class SchedulerTests(WorkerFixture):
    def test_many_gated_partials_eventually_give_healthy_history_an_object_slot(self):
        self.state.remember(HASH)
        self.source.page = lambda *args: ([], None)
        for number in range(17):
            closed = f"{number:064x}"
            self.state.remember(closed)
            self.state.db.execute("UPDATE objects SET size=24 WHERE hash=?", (closed,))
            self.state.spool(closed).write_bytes(b"x")
            self.kv.values["b2-sync:v1:" + closed] = {"state": "copying", "attempt_id": "synthetic-uncertain"}
        self.state.db.commit()
        self.worker.max_spool_bytes = 1000
        # Seventeen initial lock observations can occupy six three-object passes.
        # They must then defer, leaving the seventh pass for the healthy object.
        for _ in range(7):
            self.worker.cycle(max_objects=3, max_bytes=200)
        self.assertIsNotNone(self.kv.get("b2-ready:" + HASH))
        self.assertEqual(len([k for k in self.kv.values if k.startswith("b2-sync:v1:")]), 17)

    def test_spool_probe_cap_retains_progress_across_restart(self):
        from unittest.mock import patch
        for number in range(17):
            closed = f"{number:064x}"
            self.state.remember(closed)
            self.state.db.execute("UPDATE objects SET size=24 WHERE hash=?", (closed,))
            self.state.spool(closed).write_bytes(b"x")
            self.kv.values["b2-sync:v1:" + closed] = {"state": "copying", "attempt_id": "synthetic-uncertain"}
        self.state.db.commit()
        self.worker.max_spool_bytes = 1000
        with patch.object(mirror.time, "time", return_value=100):
            self.assertEqual(self.process(), "pending")
        self.assertEqual(self.worker.metrics["spool_gate_probes"], 16)
        self.state.close()
        self.state = mirror.State(Path(self.temp.name))
        self.worker.state = self.state
        self.worker.metrics.clear()
        with patch.object(mirror.time, "time", return_value=400):
            self.assertEqual(self.process(), "ready")
        self.assertEqual(self.worker.metrics["spool_gate_probes"], 1)

    def test_complete_locked_history_does_not_monopolize_every_pass(self):
        from unittest.mock import patch
        for number in range(3):
            closed = f"{number:064x}"
            self.state.remember(closed)
            self.state.db.execute("UPDATE objects SET size=24 WHERE hash=?", (closed,))
            self.state.spool(closed).write_bytes(b"x" * 24)
            self.kv.values["b2-sync:v1:" + closed] = {"state": "copying", "attempt_id": "synthetic-uncertain"}
        self.state.db.commit()
        self.state.remember(HASH)
        self.source.page = lambda *args: ([], None)
        self.worker.max_spool_bytes = 1000
        with patch.object(mirror.time, "time", return_value=100):
            self.worker.cycle(max_objects=3, max_bytes=200)
        with patch.object(mirror.time, "time", return_value=400):
            self.worker.cycle(max_objects=3, max_bytes=200)
        self.assertIsNotNone(self.kv.get("b2-ready:" + HASH))

    def test_erasing_partial_does_not_block_unrelated_copy_or_clear_erasing_gate(self):
        closed = "b" * 64
        self.state.spool(closed).write_bytes(b"old partial")
        self.kv.values["b2-sync:v1:" + closed] = {"state": "erasing"}
        self.assertEqual(self.process(), "ready")
        self.assertEqual(self.kv.get("b2-sync:v1:" + closed), {"state": "erasing"})
        self.assertEqual(self.worker.process(closed, mirror.Budget(200)), "locked")
        self.assertFalse(self.state.spool(closed).exists())

    def test_uncertain_put_retains_its_gate_without_stopping_unrelated_copies(self):
        import hashlib
        bodies = [b"a" * 24, b"b" * 22]
        keys = [hashlib.sha256(body).hexdigest() for body in bodies]
        content = dict(zip(keys, bodies))
        self.source.head = lambda key: {"generation": "7", "size": len(content[key])}
        self.source.read = lambda key, generation, start, length: content[key][start:start + length]
        self.source.page = lambda *args: ([], None)
        for key, body in zip(keys, bodies):
            self.kv.values["blob:" + key] = dict(self.kv.values["blob:" + HASH], sha256=key, size=len(body))
            self.state.remember(key)
        upload = self.dest.upload
        def uncertain(key, *args):
            if key == keys[0]:
                raise OSError("synthetic uncertain PUT")
            return upload(key, *args)
        self.dest.upload = uncertain
        with self.assertRaises(OSError):
            self.worker.process(keys[0], mirror.Budget(200))
        self.worker.cycle(max_objects=2, max_bytes=200)
        self.assertIsNotNone(self.kv.get("b2-ready:" + keys[1]))
        self.assertEqual(self.kv.get("b2-sync:v1:" + keys[0])["state"], "copying")
        self.assertEqual(self.state.spool(keys[0]).stat().st_size, 24)

    def test_upload_retry_age_tracks_enqueue_time_instead_of_retry_deadline(self):
        from unittest.mock import patch
        self.state.queue_upload(HASH, "7", now=100)
        self.state.defer_upload(HASH, "7", now=400)
        self.source.page = lambda *args: ([], None)
        with patch.object(mirror.time, "time", return_value=401):
            report = self.worker.cycle(max_objects=2, max_bytes=200)
        self.assertEqual(report["notification_oldest_seconds"], 301)

    def test_legacy_overcommitted_partials_recover_and_both_copies_finish(self):
        import hashlib
        bodies = [b"a" * 40, b"b" * 35]
        keys = [hashlib.sha256(body).hexdigest() for body in bodies]
        content = dict(zip(keys, bodies))
        self.source.head = lambda key: {"generation": "7", "size": len(content[key])}
        self.source.read = lambda key, generation, start, length: content[key][start:start + length]
        for key, body, offset in zip(keys, bodies, [5, 30]):
            self.kv.values["blob:" + key] = dict(self.kv.values["blob:" + HASH], sha256=key, size=len(body))
            self.state.remember(key)
            self.state.db.execute("UPDATE objects SET generation='7',size=? WHERE hash=?", (len(body), key))
            self.state.spool(key).write_bytes(body[:offset])
        self.state.db.commit()
        self.worker.max_spool_bytes = 40
        self.assertEqual(self.worker.process(keys[0], mirror.Budget(200)), "pending")
        self.assertEqual(self.worker.process(keys[1], mirror.Budget(200)), "ready")
        self.assertEqual(self.worker.process(keys[0], mirror.Budget(200)), "ready")
        self.assertFalse(list(self.state.directory.glob("*.part")))

    def test_all_three_lanes_progress_rotate_and_do_not_double_attempt_a_hash(self):
        self.state.queue_demand(HASH, hint())
        upload, history = "e" * 64, "f" * 64
        self.state.queue_upload(upload, "7")
        self.state.remember(history)
        self.source.page = lambda *args: ([], None)
        orders = []
        def attempt(key, budget, reconcile=False):
            orders.append((key, reconcile))
            return "pending"
        self.worker.process = attempt
        for _ in range(3):
            self.worker.cycle(max_objects=3, max_bytes=200)
            self.state.db.execute("UPDATE demand_queue SET available_at=0")
            self.state.db.execute("UPDATE upload_queue SET available_at=0")
            self.state.db.commit()
        self.assertEqual([orders[i][0] for i in (0, 3, 6)], [HASH, upload, history])
        for start in (0, 3, 6):
            self.assertEqual({key for key, _ in orders[start:start+3]}, {HASH, upload, history})
        self.assertTrue(all(reconcile for key, reconcile in orders if key == HASH))

    def test_intake_and_discovery_outages_preserve_durable_work(self):
        self.state.queue_demand(HASH, hint())
        self.source.page = lambda *args: (_ for _ in ()).throw(OSError("synthetic listing outage"))
        class Outage:
            def ingest(self, *args): raise OSError("synthetic intake outage")
        report = self.worker.cycle(max_objects=3, max_bytes=200, demand=Outage())
        self.assertIsNotNone(self.kv.get("b2-ready:" + HASH))
        self.assertEqual(report["demand_errors"], 1)
        self.assertEqual(report["discovery_errors"], 1)
        self.assertEqual(report["demand_pending"], 0)

    def test_queue_overlap_satisfies_only_current_upload_generation(self):
        self.state.queue_demand(HASH, hint())
        self.state.queue_upload(HASH, "7")
        self.source.page = lambda *args: ([], None)
        upload = self.dest.upload
        def newer(*args):
            self.state.queue_upload(HASH, "8")
            return upload(*args)
        self.dest.upload = newer
        report = self.worker.cycle(max_objects=3, max_bytes=200)
        self.assertEqual(report["ready"], 1)
        self.assertEqual(self.state.queued_uploads(10), [(HASH, "8")])
        self.assertEqual(self.state.queued_demands(10), [])

    def test_existing_partial_is_finished_before_opening_another_spool(self):
        self.worker.max_spool_bytes = len(DATA)
        self.worker.process(HASH, mirror.Budget(5))
        self.state.queue_demand("b" * 64, dict(hint(), sha256="b" * 64))
        self.source.page = lambda *args: ([], None)
        self.state.remember(HASH)
        report = self.worker.cycle(max_objects=3, max_bytes=200)
        self.assertIsNotNone(self.kv.get("b2-ready:" + HASH))
        self.assertLessEqual(sum(p.stat().st_size for p in self.state.directory.glob("*.part")), len(DATA))

    def test_too_few_slots_cannot_silently_starve_a_configured_lane(self):
        self.state.queue_demand(HASH, hint())
        self.state.queue_upload("e" * 64, "7")
        with self.assertRaises(ValueError):
            self.worker.cycle(max_objects=2, max_bytes=200)


@unittest.skipIf(boto3 is None, "install real SDK dependencies")
class ProbeSDKTests(unittest.TestCase):
    def test_real_sdk_head_pins_version_and_only_not_found_means_absence(self):
        calls, settings = [], {"status": 200, "version": "synthetic-version", "size": len(DATA)}
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_HEAD(self):
                calls.append((self.command, self.path))
                self.send_response(settings["status"])
                self.send_header("Content-Length", str(settings["size"]))
                self.send_header("x-amz-version-id", settings["version"])
                self.end_headers()
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        client = boto3.client("s3", endpoint_url=f"http://127.0.0.1:{server.server_port}",
                              region_name="us-east-005", aws_access_key_id="synthetic",
                              aws_secret_access_key="synthetic", config=Config(retries={"total_max_attempts": 1}))
        dest = mirror.B2Destination("synthetic-b2", client)
        self.assertTrue(dest.exists(HASH, "synthetic-version", len(DATA)))
        settings["status"] = 404
        self.assertFalse(dest.exists(HASH, "synthetic-version", len(DATA)))
        for status in (401, 403, 429, 503):
            settings["status"] = status
            with self.subTest(status=status), self.assertRaises(Exception):
                dest.exists(HASH, "synthetic-version", len(DATA))
        settings.update(status=200, version="wrong-version")
        with self.assertRaises(ValueError):
            dest.exists(HASH, "synthetic-version", len(DATA))
        self.assertTrue(all(method == "HEAD" and parse_qs(urlsplit(path).query) == {"versionId": ["synthetic-version"]}
                            for method, path in calls))
