"""Synthetic mirror lifecycle tests; no cloud credentials or network required."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import urllib.request
from urllib.parse import parse_qs, urlsplit

try:
    import boto3
    from botocore.config import Config
    from google.auth.credentials import AnonymousCredentials
    from google.cloud import storage
except ImportError:
    boto3 = None

SPEC = importlib.util.spec_from_file_location(
    "sync_b2_originals", Path(__file__).parents[1] / "sync_b2_originals.py")
mirror = importlib.util.module_from_spec(SPEC)
if SPEC.loader and Path(SPEC.origin).exists():
    SPEC.loader.exec_module(mirror)

DATA = b"synthetic video original"
HASH = hashlib.sha256(DATA).hexdigest()
OWNER = "a" * 64


class Source:
    bucket = "synthetic-gcs"

    def __init__(self):
        self.generation = "7"
        self.data = DATA
        self.reads = []
        self.interrupt = False
        self.present = True

    def head(self, key):
        return {"generation": self.generation, "size": len(self.data)} if self.present else None

    def read(self, key, generation, start, length):
        self.reads.append((generation, start, length))
        if self.interrupt:
            self.interrupt = False
            raise OSError("synthetic interruption")
        if generation != self.generation:
            raise ValueError("generation changed")
        return self.data[start:start + length]

    def page(self, cursor, limit):
        return ([HASH] if self.present else []), None


class Destination:
    bucket = "synthetic-private-b2"

    def __init__(self):
        self.versions = {}
        self.corrupt = False
        self.after_upload = lambda: None

    def upload(self, key, path, size):
        data = path.read_bytes()
        self.versions["version-1"] = b"x" * len(data) if self.corrupt else data
        self.after_upload()
        return "version-1"

    def read(self, key, version, start, length, total_size):
        return self.versions[version][start:start + length]


class KV:
    def __init__(self):
        self.values = {"blob:" + HASH: {"sha256": HASH, "size": len(DATA),
                       "type": "video/mp4", "owner": OWNER, "status": "active"}}
        self.after_put = lambda: None

    def get(self, key):
        return self.values.get(key)

    def put(self, key, value):
        self.values[key] = value
        self.after_put()

    def delete(self, key):
        self.values.pop(key, None)

    def claim_copy(self, key, attempt):
        gate = "b2-sync:v1:" + key
        if gate in self.values:
            return False
        self.values[gate] = {"state": "copying", "attempt_id": attempt}
        return True

    def release_copy(self, key, attempt):
        gate = "b2-sync:v1:" + key
        if self.values.get(gate) != {"state": "copying", "attempt_id": attempt}:
            raise ValueError("not owned")
        self.values.pop(gate)


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(hasattr(mirror, "State"), "durable mirror state is not implemented")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source, self.dest, self.kv = Source(), Destination(), KV()
        self.state = mirror.State(Path(self.temp.name))
        self.addCleanup(lambda: self.state.close())
        self.worker = mirror.Worker(self.source, self.dest, self.kv, self.state,
                                    max_object_bytes=100, chunk_bytes=5, max_spool_bytes=200)

    def copy(self, budget=1000):
        return self.worker.process(HASH, mirror.Budget(budget))

    def ready(self):
        return self.kv.get("b2-ready:" + HASH)

    def test_verified_version_published_only_after_independent_read(self):
        self.assertEqual(self.copy(), "ready")
        ready = self.ready()
        self.assertEqual(ready["destination_version_id"], "version-1")
        self.assertEqual(ready["verified_sha256"], HASH)
        self.assertEqual(ready["source_generation"], "7")
        self.assertEqual(ready["bucket"], self.dest.bucket)
        self.assertEqual(ready["size"], len(DATA))

    def test_budget_bounds_bytes_and_resume_survives_reopen(self):
        budget = mirror.Budget(10)
        self.assertEqual(self.worker.process(HASH, budget), "pending")
        self.assertEqual(budget.used, 10)
        self.assertIsNone(self.ready())
        self.state.close()
        self.state = mirror.State(Path(self.temp.name))
        self.worker.state = self.state
        self.assertEqual(self.copy(), "ready")
        self.assertEqual(self.source.reads[2][1], 10)

    def test_interrupted_read_does_not_advance_spool(self):
        self.copy(5)
        self.source.interrupt = True
        with self.assertRaises(OSError):
            self.copy()
        self.assertIsNone(self.ready())
        self.assertEqual(self.copy(), "ready")
        self.assertEqual(self.source.reads[1][1], self.source.reads[2][1])

    def test_changed_generation_discards_partial_copy(self):
        self.copy(5)
        self.source.generation = "8"
        self.assertEqual(self.copy(), "ready")
        self.assertEqual(self.source.reads[1][:2], ("8", 0))
        self.assertEqual(self.ready()["source_generation"], "8")

    def test_generation_change_after_transfer_never_publishes(self):
        self.dest.after_upload = lambda: setattr(self.source, "generation", "8")
        self.assertEqual(self.copy(), "changed")
        self.assertIsNone(self.ready())

    def test_corrupt_destination_is_not_ready(self):
        self.dest.corrupt = True
        with self.assertRaises(ValueError):
            self.copy()
        self.assertIsNone(self.ready())

    def test_corrupt_source_is_not_uploaded(self):
        self.source.data = b"x" * len(DATA)
        with self.assertRaises(ValueError):
            self.copy()
        self.assertFalse(self.dest.versions)

    def test_revoked_policy_during_upload_prevents_ready(self):
        self.dest.after_upload = lambda: self.kv.values["blob:" + HASH].update(status="restricted")
        self.assertEqual(self.copy(), "blocked")
        self.assertIsNone(self.ready())

    def test_vanish_race_during_publication_removes_readiness(self):
        self.kv.after_put = lambda: self.kv.values.update({"tombstone:" + HASH: {"reason": "synthetic"}})
        self.assertEqual(self.copy(), "blocked")
        self.assertIsNone(self.ready())
        self.assertEqual(self.copy(), "blocked")

    def test_missing_source_and_policy_reconciliation_remove_ready(self):
        self.copy()
        self.source.present = False
        self.assertEqual(self.copy(), "missing")
        self.assertIsNone(self.ready())
        self.source.present = True
        self.copy()
        self.kv.values.pop("blob:" + HASH)
        self.assertEqual(self.copy(), "blocked")
        self.assertIsNone(self.ready())

    def test_object_limit_and_upload_verify_reservation(self):
        self.worker.max_object_bytes = 5
        self.assertEqual(self.copy(), "oversized")
        self.assertFalse(self.source.reads)
        self.worker.max_object_bytes = 100
        self.assertEqual(self.copy(len(DATA)), "pending")
        self.assertFalse(self.dest.versions)
        self.assertEqual(self.copy(2 * len(DATA)), "ready")

    def test_policy_is_deny_by_default_for_status_owner_refs_and_vanish(self):
        for status in ("pending", "banned", "deleted", "restricted", "age_restricted", None):
            self.kv.values["blob:" + HASH]["status"] = status
            self.assertIsNone(mirror.approved_metadata(self.kv, HASH))
        self.kv.values["blob:" + HASH]["status"] = "active"
        self.assertIsNotNone(mirror.approved_metadata(self.kv, HASH))
        self.kv.values["refs:" + HASH] = ["b" * 64]
        self.kv.values["vanish_in_progress:v1:" + "b" * 64] = {}
        self.assertIsNone(mirror.approved_metadata(self.kv, HASH))

    def test_cycle_retains_removed_objects_for_bounded_reconciliation(self):
        self.worker.cycle(max_objects=2, max_bytes=1000)
        self.assertIsNotNone(self.ready())
        self.source.present = False
        report = self.worker.cycle(max_objects=2, max_bytes=1000)
        self.assertEqual(report["missing"], 1)
        self.assertIsNone(self.ready())

    def test_erasure_gate_prevents_late_copy_after_all_version_delete(self):
        # Erasure acquired its durable gate, deleted all versions and completed.
        self.kv.values["b2-sync:v1:" + HASH] = {"state": "erasing"}
        self.assertEqual(self.copy(), "locked")
        self.assertFalse(self.dest.versions)
        self.assertIsNone(self.ready())

    def test_uncertain_put_retains_durable_gate_for_erasure_retry(self):
        def uncertain_put(key, path, size):
            self.dest.versions["late-version"] = path.read_bytes()
            raise TimeoutError("response lost after commit")
        self.dest.upload = uncertain_put
        with self.assertRaises(TimeoutError):
            self.copy()
        self.assertEqual(self.kv.get("b2-sync:v1:" + HASH)["state"], "copying")
        self.assertFalse(self.kv.claim_copy(HASH, str(uuid.uuid4())))
        self.assertIsNone(self.ready())
        self.assertEqual(self.copy(), "locked")

    def test_successful_copy_releases_gate_for_erasure(self):
        self.copy()
        self.assertIsNone(self.kv.get("b2-sync:v1:" + HASH))

    def test_crash_after_ready_publication_does_not_hide_held_gate(self):
        self.copy()
        self.kv.values["b2-sync:v1:" + HASH] = {"state": "copying", "attempt_id": "synthetic-crashed-attempt"}
        self.assertEqual(self.copy(), "locked")

    def test_policy_api_failure_cannot_publish_readiness(self):
        def failed_lookup(key):
            raise OSError("synthetic unavailable control plane")
        self.kv.get = failed_lookup
        with self.assertRaises(OSError):
            self.copy()
        self.assertNotIn("b2-ready:" + HASH, self.kv.values)
        self.assertFalse(self.dest.versions)

    def test_policy_revoked_at_gate_claim_prevents_put(self):
        claim = self.kv.claim_copy
        def revoke_at_claim(key, attempt):
            result = claim(key, attempt)
            self.kv.values["blob:" + HASH]["status"] = "deleted"
            return result
        self.kv.claim_copy = revoke_at_claim
        self.assertEqual(self.copy(), "blocked")
        self.assertFalse(self.dest.versions)
        self.assertIsNone(self.kv.get("b2-sync:v1:" + HASH))

    def test_spool_limit_never_exceeded(self):
        self.worker.max_spool_bytes = 8
        self.assertEqual(self.copy(), "pending")
        self.assertEqual(self.state.spool(HASH).stat().st_size, 8)
        self.assertIsNone(self.ready())

    def test_state_cannot_be_reused_for_another_bucket(self):
        self.state.bind({"source": "synthetic", "destination": "one"})
        with self.assertRaises(ValueError):
            self.state.bind({"source": "synthetic", "destination": "two"})


class PreflightTests(unittest.TestCase):
    def bucket(self):
        return {"bucketName": "synthetic", "bucketId": "bucket-id", "bucketType": "allPrivate",
                "fileLockConfiguration": {"isClientAuthorizedToRead": True,
                    "value": {"isFileLockEnabled": False, "defaultRetention": {"mode": None, "period": None}}}}

    def run_preflight(self, bucket):
        class HTTP:
            def request(self, url, *args, **kwargs):
                if url.endswith("b2_authorize_account"):
                    return {"apiInfo": {"storageApi": {"s3ApiUrl": "https://s3.us-east-005.backblazeb2.com", "apiUrl": "https://api005.backblazeb2.com"}},
                            "accountId": "synthetic-account", "authorizationToken": "synthetic-token"}
                return {"buckets": [bucket]}
        return mirror.private_b2_endpoint("synthetic", "bucket-id", "synthetic-id", "synthetic-key",
                                          http_factory=lambda headers: HTTP())

    def test_preflight_requires_exact_private_bucket_without_retention(self):
        self.assertEqual(self.run_preflight(self.bucket()), "https://s3.us-east-005.backblazeb2.com")
        for changes in ({"bucketType": "allPublic"}, {"bucketId": "other"},
                        {"fileLockConfiguration": {"isClientAuthorizedToRead": False, "value": None}},
                        {"fileLockConfiguration": {"isClientAuthorizedToRead": True,
                         "value": {"isFileLockEnabled": True, "defaultRetention": {"mode": "governance"}}}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.run_preflight({**self.bucket(), **changes})


class FastlyHTTPTests(unittest.TestCase):
    def test_redirects_fail_without_forwarding_credentials_or_changing_global_opener(self):
        received = []
        redirect = {"status": 302}

        class DestinationHandler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                received.append(dict(self.headers))
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

        destination = ThreadingHTTPServer(("127.0.0.1", 0), DestinationHandler)

        class RedirectHandler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                self.send_response(redirect["status"])
                self.send_header("Location", f"http://127.0.0.1:{destination.server_port}/capture")
                self.send_header("Content-Length", "0")
                self.end_headers()

        source = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        for server in (destination, source):
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
        original_opener = urllib.request._opener
        http = mirror.JsonHTTP({"Authorization": "synthetic-private-token", "Fastly-Key": "synthetic-fastly-token"})
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                redirect["status"] = status
                with self.assertRaises(RuntimeError):
                    http.request(f"http://127.0.0.1:{source.server_port}/redirect")
                self.assertEqual(received, [])
                self.assertIs(urllib.request._opener, original_opener)

    def test_atomic_add_gate_and_readiness_over_real_http(self):
        values = {}
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def reply(self, status, value=None):
                data = json.dumps(value).encode() if value is not None else b""
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("generation", "1")
                self.end_headers()
                self.wfile.write(data)

            def do_PUT(self):
                requests.append(self.path)
                key = urlsplit(self.path).path
                value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if parse_qs(urlsplit(self.path).query).get("add") == ["true"] and key in values:
                    return self.reply(412)
                values[key] = value
                self.reply(200)

            def do_GET(self):
                key = urlsplit(self.path).path
                self.reply(200, values[key]) if key in values else self.reply(404)

            def do_DELETE(self):
                values.pop(urlsplit(self.path).path, None)
                self.reply(204)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        kv = mirror.FastlyKV("synthetic", "synthetic-token")
        kv.base = f"http://127.0.0.1:{server.server_port}/keys/"
        self.assertTrue(kv.claim_copy(HASH, "synthetic-attempt"))
        self.assertFalse(kv.claim_copy(HASH, "second-attempt"))
        with self.assertRaises(ValueError):
            kv.release_copy(HASH, "second-attempt")
        kv.release_copy(HASH, "synthetic-attempt")
        self.assertTrue(kv.claim_copy(HASH, "second-attempt"))
        kv.put("b2-ready:" + HASH, {"version": 1})
        self.assertEqual(kv.get("b2-ready:" + HASH), {"version": 1})
        kv.delete("b2-ready:" + HASH)
        self.assertIsNone(kv.get("b2-ready:" + HASH))
        self.assertTrue(any("b2-sync%3Av1%3A" in path and "?add=true" in path for path in requests))
        for key in ("blob:" + HASH, "b2-ready:bad"):
            with self.assertRaises(ValueError):
                kv.put(key, {})
            with self.assertRaises(ValueError):
                kv.delete(key)

    def test_generation_matched_release_preserves_a_replacement_erasure_gate(self):
        value = {"state": "copying", "attempt_id": "synthetic-attempt"}
        state = {"value": value, "generation": "7", "replace_on_read": True}
        deletes = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                data = json.dumps(state["value"]).encode()
                generation = state["generation"]
                if state["replace_on_read"]:
                    state.update(value={"state": "erasing"}, generation="8")
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                if generation is not None:
                    self.send_header("generation", generation)
                self.end_headers()
                self.wfile.write(data)

            def do_DELETE(self):
                generation = self.headers.get("if-generation-match")
                deletes.append(generation)
                # Fastly supports unconditional DELETE too; the caller must send
                # a precondition to protect a newer value after the ownership read.
                if generation is not None and generation != state["generation"]:
                    self.send_response(412)
                else:
                    state["value"] = None
                    self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        kv = mirror.FastlyKV("synthetic", "synthetic-token")
        kv.base = f"http://127.0.0.1:{server.server_port}/keys/"
        with self.assertRaises(RuntimeError):
            kv.release_copy(HASH, "synthetic-attempt")
        self.assertEqual(state["value"], {"state": "erasing"})
        self.assertEqual(deletes, ["7"])
        state["replace_on_read"] = False
        for generation in (None, "invalid", "0", str(2 ** 64)):
            state.update(value=value, generation=generation)
            with self.subTest(generation=generation), self.assertRaises(ValueError):
                kv.release_copy(HASH, "synthetic-attempt")
        self.assertEqual(deletes, ["7"])
        state.update(value=value, generation="9")
        kv.release_copy(HASH, "synthetic-attempt")
        self.assertIsNone(state["value"])
        self.assertEqual(deletes, ["7", "9"])


@unittest.skipIf(boto3 is None, "install scripts/requirements-b2-sync.txt for real SDK HTTP integration")
class SDKHTTPTests(unittest.TestCase):
    def test_real_gcs_and_s3_clients_generation_range_version_and_pagination(self):
        requests = []
        versions = {}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def reply(self, data, headers=None):
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(data)

            def do_PUT(self):
                requests.append(("PUT", self.path, dict(self.headers)))
                versions["version-1"] = self.rfile.read(int(self.headers["Content-Length"]))
                self.reply(b"", {"x-amz-version-id": "version-1"})

            def do_GET(self):
                requests.append(("GET", self.path, dict(self.headers)))
                parsed = urlsplit(self.path)
                query = parse_qs(parsed.query)
                if parsed.path == "/storage/v1/b/synthetic-gcs/o":
                    self.reply(json.dumps({"items": [{"name": HASH, "size": str(len(DATA)), "generation": "7"}],
                                           "nextPageToken": "synthetic-next-page"}).encode(), {"Content-Type": "application/json"})
                elif parsed.path.startswith("/storage/v1/"):
                    self.reply(json.dumps({"name": HASH, "size": str(len(DATA)), "generation": "7"}).encode(), {"Content-Type": "application/json"})
                else:
                    start, end = map(int, self.headers["Range"][6:].split("-"))
                    data = DATA if "ifGenerationMatch" in query else versions[query["versionId"][0]]
                    self.send_response(206)
                    self.send_header("Content-Length", str(end - start + 1))
                    self.send_header("Content-Range", f"bytes {start}-{end}/{len(data)}")
                    self.send_header("x-amz-version-id", "version-1")
                    self.end_headers()
                    self.wfile.write(data[start:end + 1])

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        endpoint = f"http://127.0.0.1:{server.server_port}"
        source = mirror.GCSSource("synthetic-gcs", storage.Client(project="synthetic", credentials=AnonymousCredentials(),
                                   client_options={"api_endpoint": endpoint}))
        self.assertEqual(source.page(None, 1), ([HASH], "synthetic-next-page"))
        self.assertEqual(source.head(HASH), {"generation": "7", "size": len(DATA)})
        self.assertEqual(source.read(HASH, "7", 2, 5), DATA[2:7])
        client = boto3.client("s3", endpoint_url=endpoint, region_name="us-east-005",
                    aws_access_key_id="synthetic", aws_secret_access_key="synthetic-secret",
                    config=Config(retries={"total_max_attempts": 1},
                                  request_checksum_calculation="when_required"))
        dest = mirror.B2Destination("synthetic-b2", client)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "original"
            path.write_bytes(DATA)
            self.assertEqual(dest.upload(HASH, path, len(DATA)), "version-1")
        self.assertEqual(dest.read(HASH, "version-1", 0, 5, len(DATA)), DATA[:5])
        self.assertTrue(any("ifGenerationMatch=7" in path for _, path, _ in requests))
        self.assertTrue(any("versionId=version-1" in path for _, path, _ in requests))


if __name__ == "__main__":
    unittest.main()
