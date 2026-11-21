#!/usr/bin/env python3
"""Exercise Bunny publication with synthetic policy, storage, and CDN backends."""

from base64 import b64encode
from contextlib import closing, contextmanager
from http.client import HTTPConnection
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
from pathlib import Path
import shlex
import socket
import sys
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit


BODY = b"abc"
HASH = hashlib.sha256(BODY).hexdigest()
OWNER = "b" * 64
BUCKET = "fixture-bucket"
BUCKET_ID = "fixture-bucket-id"
PREFIX = "bunny-delivery/"
CDN_HOSTS = ("media-bunny.divine.video", "fixture-pilot.b-cdn.net")
B2_API_HOST = "api.backblazeb2.com"
KV_BASE = "/resources/stores/kv/fixture-store/keys/"
CASES = ("source_unavailable", "pending_zero", "lost_permit_reply", "denied_during_prep", "ready_delete_failure", "permit_contract", "delayed_publish", "hls_family", "disabled_four", "active", "active_rendition", "pending", "age_restricted", "checksum_mismatch",
         "age_gate_after_put", "appeal", "unverified_retry", "rejected_put", "uncertain_put",
         "disabled", "webhook_token", "wrong_writer_scope", "lost_worker_reply", "invalid_worker_evidence", "wrong_worker_primary")
SECRETS = {
    "bunny_playback_geo_key": "synthetic-test-key-with-32-or-more-bytes",
    "bunny_pilot_worker_token": "synthetic-private-worker-token-at-least-32-characters",
    "admin_token": "fixture-admin",
    "webhook_secret": "fixture-webhook",
    "bunny_pilot_readers_v1": {"b2": {"id":"fixture-reader-id", "key":"fixture-reader-key"},
                              "gcs": {"id":"fixture-gcs-id", "key":"fixture-gcs-key"}},
    "bunny_pilot_writer_v1": {"id":"fixture-writer-id", "key":"fixture-writer-key"},
    "bunny_pilot_cleanup_v1": {"eraser":{"id":"fixture-eraser-id", "key":"fixture-eraser-key"},
                              "bunny_api_key":"fixture-purge", "fastly_api_token":"fixture-fastly-purge"},
    "kv_origin_read_token": "fixture-policy-reader",
}


def family(derived_bucket, maximum):
    source = {}
    root = f"/{HASH}/hls/"
    master = "#EXTM3U\n#EXT-X-VERSION:4\n"
    for r in ("720p", "480p"):
        source[root + f"stream_{r}.ts"] = (b"t" * (16 * 1024 * 1024) if maximum else r.encode() * 47, "video/mp2t")
    for r in ("720p", "480p"):
        playlist = (f"#EXTM3U\n#EXT-X-VERSION:4\n#EXT-X-TARGETDURATION:6\n#EXT-X-PLAYLIST-TYPE:VOD\n"
                    f"#EXTINF:5.980,\n#EXT-X-BYTERANGE:{len(source[root + f'stream_{r}.ts'][0])}@0\n{root}stream_{r}.ts\n#EXT-X-ENDLIST\n")
        source[root + f"stream_{r}.m3u8"] = (playlist.encode(), "application/vnd.apple.mpegurl")
        master += f"#EXT-X-STREAM-INF:BANDWIDTH=1000\n{root}stream_{r}.m3u8\n"
    source[root + "master.m3u8"] = (master.encode(), "application/vnd.apple.mpegurl")
    for path in (f"/{HASH}", f"/{HASH}/720p.mp4", f"/{HASH}/480p.mp4"):
        source[path] = (BODY, "video/mp4")
    # Normal-size media must never be hashed or transported through Compute.
    source[f"/{HASH}/480p.mp4"] = (b"s" * (16 * 1024 * 1024), "video/mp4")
    inventory, objects, destinations = [], {}, {}
    for path, (body, mime) in source.items():
        delivery = body.replace(root.encode(), b"") if path.endswith(".m3u8") else body
        source_key = path.replace("/720p.mp4", "/hls/stream_720p.mp4").replace("/480p.mp4", "/hls/stream_480p.mp4")
        source_bucket = BUCKET if path == f"/{HASH}" else derived_bucket
        objects[f"/{source_bucket}{source_key}"] = (body, mime)
        destinations[f"/{BUCKET}/{PREFIX}{path[1:]}"] = (delivery, mime)
        inventory.append({"path": path, "source_sha256": hashlib.sha256(body).hexdigest(),
                          "delivery_sha256": hashlib.sha256(delivery).hexdigest()})
    return inventory, objects, destinations


def basic(key_type):
    plain = f"fixture-{key_type}-id:fixture-{key_type}-key".encode()
    return f"Basic {b64encode(plain).decode()}"


class Origin(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        if self.command != "HEAD" and self.path != "/" and not self.path.startswith("/fixture/") and self.headers.get("User-Agent") != "divine-bunny-worker/1":
            if self.server.in_permit:
                self.server.permit_queries[-1] += 1
            else:
                self.server.meter[-1][1] += 1

    def reply(self, status, body=b"", headers=None):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def reply_json(self, value, headers=None):
        self.reply(200, json.dumps(value).encode(), {"Content-Type": "application/json", **(headers or {})})

    def read_body(self):
        return self.rfile.read(int(self.headers.get("Content-Length", "0")))

    def do_GET(self):
        if self.path == "/":  # Viceroy backend health probe
            return self.reply(200)
        if self.path.startswith(KV_BASE):
            assert self.headers.get("Fastly-Key") == SECRETS["kv_origin_read_token"]
            key = self.path.removeprefix(KV_BASE)
            if key == f"b2-sync:v1:{HASH}":
                if self.server.permit_gate:
                    attempt, generation = self.server.permit_gate
                    return self.reply_json({"state":"copying","attempt_id":attempt},{"generation":generation})
                if self.server.ready_generation:
                    return self.reply_json({"state":"released","version":1,"settled_attempt_id":"fixture-published",
                        "released_from_generation":"1"}, {"generation":str(self.server.ready_generation)})
                return self.reply(404)
            if key == "bunny-pilot-retained-hosts:v1":
                return self.reply(200, ",".join(CDN_HOSTS).encode(), {"generation": "1"})
            if key == f"bunny-pilot-enrolled:v1:{HASH}":
                return self.reply(200, b"1", {"generation": "1"})
            if self.server.policy_blocker == "quarantine" and key == f"quarantine:v1:{HASH}":
                return self.reply_json({"version":1,"holds":{"fixture":{"version":1,"active":True}}}, {"generation":"1"})
            if ((self.server.policy_blocker == "tombstone" and key == f"tombstone:{HASH}") or
                (self.server.policy_blocker == "vanish" and key == f"vanish_in_progress:v1:{OWNER}")):
                return self.reply_json(1, {"generation":"1"})
            if self.server.case in ("hls_family","disabled_four"):
                if key == f"bunny-ready:v1:{HASH}":
                    captured = self.server.ready
                    if self.server.retire_during_read:
                        # The read captured a prior inventory. Before returning it, removal
                        # completed and an appeal is active under a newer released gate.
                        self.server.ready = None
                        self.server.ready_generation += 1
                        self.server.policy_status = "active"
                        self.server.retire_during_read = False
                    return self.reply(200, captured, {"generation":"1"}) if captured else self.reply(404)
                if key == f"refs:{HASH}":
                    return self.reply_json([c * 64 for c in self.server.uploaders], {"generation":"1"})
                if key.startswith("vanish_in_progress:v1:"):
                    return self.reply(404)
            if key != f"blob:{HASH}":
                assert key in {f"tombstone:{HASH}", f"quarantine:v1:{HASH}", f"refs:{HASH}",
                               f"vanish_in_progress:v1:{OWNER}"}, key
                return self.reply(404)
            status = self.server.policy_status
            if self.server.case in ("age_gate_after_put", "ready_delete_failure") and self.server.delivered is not None:
                status = "age_restricted"
            self.server.events.append(("policy", status))
            return self.reply_json({
                "sha256": HASH,
                "size": len(BODY),
                "type": "video/quicktime" if self.server.case == "active_rendition" else "video/mp4",
                "uploaded": "2026-01-01T00:00:00Z",
                "owner": OWNER,
                "status": status,
                **self.server.transcode,
            }, {"generation": "1"})

        if self.path == "/b2api/v4/b2_authorize_account":
            is_writer = self.headers.get("Authorization") == basic("writer")
            assert is_writer or self.headers.get("Authorization") == basic("eraser")
            return self.reply_json({"authorizationToken": "fixture-native-token", "apiInfo": {"storageApi": {
                "apiUrl": f"https://{B2_API_HOST}",
                "allowed": {"buckets": [{"id": BUCKET_ID, "name": BUCKET}],
                            "namePrefix": PREFIX if is_writer else None,
                            "capabilities": (["writeFiles","listFiles"] if self.server.case == "wrong_writer_scope" else ["writeFiles"]) if is_writer else ["listFiles", "deleteFiles"]},
            }}})

        assert self.headers.get("User-Agent") == "divine-bunny-worker/1", self.path
        reader = "fixture-gcs-id" if self.path.startswith("/fixture-gcs/") else "fixture-reader-id"
        assert f"Credential={reader}/" in self.headers.get("Authorization", "")
        self.server.events.append(("read", self.path))
        if self.server.case == "hls_family":
            if self.path not in self.server.objects:
                return self.reply(404)
            body, mime = self.server.objects[self.path]
            version = self.server.source_versions.get(self.path, self.server.source_version)
            version_header = "x-goog-generation" if reader == "fixture-gcs-id" else "x-amz-version-id"
            return self.reply(200, body, {"Content-Type": mime, version_header:
                "fixture-version-1" if self.path in self.server.destinations else version})
        if self.path == f"/{BUCKET}/{self.server.source_key}":
            if self.server.case == "source_unavailable":
                return self.reply(503)
            if self.server.case == "denied_during_prep":
                self.server.policy_status = "age_restricted"
            if self.server.case == "delayed_publish" and self.server.delivered is None:
                time.sleep(16)
            body = b"wrong bytes" if self.server.case == "checksum_mismatch" else BODY
        else:
            assert self.path == f"/{BUCKET}/{self.server.delivery_key}", self.path
            body = self.server.delivered
            if self.server.case == "unverified_retry" and body is not None:
                return self.reply(503)
        if body is None:
            return self.reply(404)
        return self.reply(200, body, {"Content-Type": "video/mp4", "x-amz-version-id": "fixture-version-1"})

    def do_HEAD(self):
        server = self.server
        # Count at arrival, including responses completing after the edge deadline.
        with server.arrivals_lock:
            server.meter[-1][1] += 1
        prefix = f"/{server.derived_bucket}/{HASH}/hls/"
        assert self.path.startswith(prefix) and self.path in server.objects, self.path
        assert not urlsplit(self.path).query
        gcs = server.derived_bucket == "fixture-gcs"
        host = "storage.googleapis.com" if gcs else "s3.us-west-004.backblazeb2.com"
        assert self.headers["Host"] == host
        assert "Credential=fixture-canonical-reader/" in self.headers["Authorization"]
        fault = server.head_fault
        if fault == "batch":
            with server.arrivals_lock:
                server.batch_keys.add(self.path)
                if len(server.batch_keys) == 7:
                    server.batch_arrived.set()
            server.batch_arrived.wait(1)
        status = 200
        version = server.source_versions.get(self.path, server.source_version)
        # Fault a leaf, while all top-level files still match.
        if self.path.endswith("/stream_480p.ts"):
            if fault == "slow":
                time.sleep(1.1)
            status = {"missing":404, "unreadable":503}.get(fault, 200)
        self.send_response(status)
        self.send_header("Content-Length", str(len(server.objects[self.path][0])))
        self.send_header("Cache-Control", "public, max-age=600")
        name = "x-goog-generation" if gcs else "x-amz-version-id"
        if not (fault == "unversioned" and self.path.endswith("/stream_480p.ts")):
            self.send_header(name, version)
        if fault == "duplicate" and self.path.endswith("/stream_480p.ts"):
            self.send_header(name, "999")
        self.end_headers()

    def do_PUT(self):
        assert self.headers.get("User-Agent") == "divine-bunny-worker/1"
        if self.server.case == "hls_family":
            body, mime = self.server.destinations[self.path]
            assert self.path not in self.server.objects
            assert self.read_body() == body and self.headers.get("Content-Type") == mime
            assert self.headers.get("x-amz-content-sha256") == hashlib.sha256(body).hexdigest()
            assert "Credential=fixture-writer-id/" in self.headers.get("Authorization", "")
            self.server.objects[self.path] = (body, mime)
            return self.reply(200, headers={"x-amz-version-id": "fixture-version-1"})
        assert self.path == f"/{BUCKET}/{self.server.delivery_key}"
        assert "Credential=fixture-writer-id/" in self.headers.get("Authorization", "")
        assert self.headers.get("x-amz-content-sha256") == HASH
        assert self.headers.get("Content-Type") == "video/mp4"
        body = self.read_body()
        assert body == BODY
        assert self.server.delivered is None
        if self.server.case in ("rejected_put", "uncertain_put"):
            self.server.events.append(("rejected-put", self.path))
            return self.reply(403 if self.server.case == "rejected_put" else 503)
        self.server.events.append(("put", self.path))
        self.server.delivered = body
        self.reply(200, headers={"x-amz-version-id": "fixture-version-1"})

    def do_POST(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/admin/api/bunny-pilot/permit":
            assert self.headers.get("Host") == "media.divine.video"
            assert self.headers.get("User-Agent") == "divine-bunny-worker/1"
            assert self.headers.get("Authorization") == "Bearer " + SECRETS["bunny_pilot_worker_token"]
            body = self.read_body()
            self.server.permit_queries.append(0)
            self.server.in_permit = True
            try:
                with closing(HTTPConnection("127.0.0.1", self.server.permit_port, timeout=15)) as edge:
                    edge.request("POST", parsed.path, body, {"Host":"media.divine.video","Authorization":self.headers["Authorization"]})
                    response = edge.getresponse()
                    payload = response.read()
                    if self.server.case == "lost_permit_reply":
                        return self.reply(503)
                    return self.reply(response.status, payload)
            finally:
                self.server.in_permit = False
        if parsed.path == "/internal/bunny-pilot/v1":
            assert self.headers.get("Host") == "blossom-upload-rust-149672065768.us-central1.run.app"
            assert self.headers.get("Authorization") == "Bearer " + SECRETS["bunny_pilot_worker_token"]
            body = self.read_body()
            op = json.loads(body)["operation"]
            if op["operation"] == "publish":
                self.server.permit_gate = (op["attempt"],op["generation"])
            with closing(HTTPConnection("127.0.0.1", self.server.worker_port, timeout=90)) as worker:
                worker.request("POST", parsed.path, body, {"Authorization": self.headers["Authorization"]})
                started = time.monotonic()
                response = worker.getresponse()
                payload = response.read()
                self.server.permit_gate = None
                if op["operation"] == "finalize" and self.server.repair_during_finalize:
                    self.server.transcode["transcode_generation"] += 1
                    self.server.repair_during_finalize = False
                self.server.worker_times.append((json.loads(body)["operation"]["operation"],time.monotonic() - started))
                if self.server.case == "lost_worker_reply":
                    return self.reply(503)
                if self.server.case == "invalid_worker_evidence":
                    evidence = json.loads(payload)
                    evidence["result"]["verified"]["source"]["key"] = "outside-scope"
                    payload = json.dumps(evidence).encode()
                return self.reply(response.status, payload, {"Content-Type":"application/json"})
        if parsed.path == "/fixture/permit-gate":
            self.server.permit_gate = json.loads(self.read_body())
            return self.reply(200)
        if parsed.path == "/fixture/meter":
            phase = self.read_body().decode()
            if phase == "outside" and self.server.meter[-1][0] == "publish":
                self.server.publish_times.append(time.monotonic() - self.server.request_started)
            if phase == "outside" and self.server.meter[-1][0] == "selection" and self.server.head_fault:
                self.server.probe_times[self.server.head_fault] = time.monotonic() - self.server.request_started
            self.server.request_started = time.monotonic()
            self.server.meter.append([phase, 0])
            return self.reply(200)
        if parsed.path == "/fixture/uploaders":
            self.server.uploaders = self.read_body().decode()
            return self.reply(200)
        if parsed.path == "/fixture/retire-during-read":
            self.server.retire_during_read = True
            return self.reply(200)
        if parsed.path == "/fixture/repair":
            key = f"/{self.server.derived_bucket}/{HASH}/hls/stream_720p.mp4"
            body = self.read_body()
            if body in (b"restore-original", b"restore-with-new-version"):
                self.server.objects[key] = (BODY, "video/mp4")
                self.server.source_versions[key] = "123" if body == b"restore-original" else "125"
            else:
                self.server.objects[key] = (body, "video/mp4")
                self.server.source_versions[key] = "124"
            return self.reply(200)
        if parsed.path == "/fixture/head-fault":
            self.server.head_fault = self.read_body().decode()
            return self.reply(200)
        if parsed.path == "/fixture/transcode":
            self.server.transcode = json.loads(self.read_body())
            return self.reply(200)
        if parsed.path == "/fixture/repair-during-finalize":
            self.server.repair_during_finalize = True
            return self.reply(200)
        if parsed.path == "/fixture/source-version":
            self.server.source_version = self.read_body().decode()
            return self.reply(200)
        if parsed.path == "/fixture/ready":
            self.server.ready_generation = 10
            self.server.ready = self.read_body()
            return self.reply(200)
        if parsed.path == "/fixture/policy-blocker":
            self.server.policy_blocker = self.read_body().decode()
            return self.reply(200)
        if parsed.path == "/fixture/policy-status":
            assert self.server.case in ("appeal", "hls_family")
            self.server.policy_status = self.read_body().decode()
            assert self.server.policy_status in ("active", "age_restricted", "pending")
            return self.reply(200)

        if parsed.path.startswith("/service/"):
            assert self.server.case in ("appeal", "unverified_retry", "age_gate_after_put", "ready_delete_failure")
            assert parsed.path.endswith("/purge")
            assert self.headers.get("Fastly-Key") == SECRETS["bunny_pilot_cleanup_v1"]["fastly_api_token"]
            assert self.headers.get("Surrogate-Key") == HASH
            return self.reply_json({HASH: "fixture-purge-id"})

        if parsed.path == "/purge":
            assert self.headers.get("AccessKey") == SECRETS["bunny_pilot_cleanup_v1"]["bunny_api_key"]
            target = parse_qs(parsed.query)["url"][0]
            assert target in {f"https://{host}/{HASH}*" for host in CDN_HOSTS}
            assert self.server.delivered is None, "Purge must follow replica deletion"
            self.server.events.append(("purge", target))
            if self.server.case == "unverified_retry" and sum(
                kind == "purge" for kind, _ in self.server.events
            ) <= 4:
                return self.reply(503)
            return self.reply(200)

        assert self.headers.get("Authorization") == "fixture-native-token"
        params = json.loads(self.read_body())
        if parsed.path == "/b2api/v4/b2_list_file_versions":
            assert params["bucketId"] == BUCKET_ID and params["prefix"] == f"{PREFIX}{HASH}"
            files = [] if self.server.delivered is None else [
                {"fileName": self.server.delivery_key, "fileId": "fixture-file-id"}]
            return self.reply_json({"files": files, "nextFileName": None, "nextFileId": None})

        assert parsed.path == "/b2api/v4/b2_delete_file_version", self.path
        assert params == {"fileName": self.server.delivery_key, "fileId": "fixture-file-id"}
        assert self.server.delivered is not None
        self.server.events.append(("delete", params["fileName"]))
        self.server.delivered = None
        self.reply_json({})


def check_enrollment_reply(directory, operation, status, body, retryable):
    """Pass the actual routed Compute status/body through the operator and SQLite."""
    from publish_bunny_media import BunnyAdmin, Reconciler, State
    from sync_b2_originals import ControlAPIError
    from tests.test_publish_bunny_media import API, KV, PARENT, Producer, Source

    source, catalog = Source(), KV()
    delivery = API(source)
    catalog.pages = [([PARENT], None)]

    class Transport:
        def request(self, url, method, payload, **kwargs):
            op = url.rsplit('/', 1)[-1]
            assert method == "POST"
            if op != operation:
                return getattr(delivery, op)(payload)
            if status >= 400:
                raise ControlAPIError(status)
            return json.loads(body)

    with tempfile.TemporaryDirectory(dir=directory) as journal:
        state = State(Path(journal) / "journal.sqlite", {})
        try:
            runner = Reconciler(catalog, source, source, Producer(), BunnyAdmin("fixture-admin", Transport()), state)
            bounds = dict(max_pages=1, page_size=1, max_parents=1, max_bytes=1024**3)
            result = runner.cycle(**bounds)
            assert result.get("retryable_no_write" if retryable else "uncertain") == 1, result
            acknowledged = len(delivery.order)
            runner.api = delivery
            second = runner.cycle(**bounds)
            if retryable:
                assert second.get("ready") == 1 and len(delivery.order) == 6
            else:
                assert state.status(PARENT) == "uncertain" and len(delivery.order) == acknowledged
        finally:
            state.close()


def assert_case(server, case):
    events = server.events
    actions = [name for name, _ in events]
    if case == "hls_family":
        assert all(server.objects.get(k) == v for k, v in server.destinations.items())
        assert len(server.batch_keys) == 7
        assert server.probe_times["batch"] < 1 and server.probe_times["slow"] < 1, server.probe_times
        print(f"Routed full-family source HEAD batch {server.probe_times['batch']:.3f}s; slow-origin fallback {server.probe_times['slow']:.3f}s")
        for operation in ("publish", "finalize", "selection"):
            counts = [n for name, n in server.meter if name == operation]
            assert max(counts) <= 32, server.meter
            print(f"Maximum {operation} backend requests: {max(counts)}")
    elif case in ("lost_worker_reply","invalid_worker_evidence"):
        assert actions.count("put") == 1 and server.delivered == BODY, events
    elif case == "denied_during_prep":
        assert actions.count("put") == 0 and server.delivered is None, events
        assert [value for action,value in events if action == "policy"] == ["active","age_restricted"], events
    elif case in ("active", "active_rendition", "delayed_publish"):
        assert actions.count("put") == 1 and server.delivered == BODY, events
        assert [status for name, status in events if name == "policy"] == ["active"] * 5, events
        assert not any(action in actions for action in ("delete", "purge")), events
    elif case in ("age_gate_after_put", "ready_delete_failure"):
        critical = [(name, value) for name, value in events if name != "read"]
        assert critical[:5] == [
            ("policy", "active"),
            ("policy", "active"), ("put", f"/{BUCKET}/{server.delivery_key}"),
            ("policy", "age_restricted"), ("delete", server.delivery_key),
        ], events
        assert sorted(critical[5:]) == sorted(
            ("purge", f"https://{host}/{HASH}*") for host in CDN_HOSTS for _ in range(2)
        ), events
        assert server.delivered is None
    elif case == "appeal":
        assert actions.count("put") == 2 and actions.count("delete") == 1, events
        assert actions.index("put") < actions.index("delete"), events
        assert actions.index("delete") < len(actions) - 1 - actions[::-1].index("put"), events
        assert actions.count("purge") == 4 and server.delivered == BODY, events
    elif case == "unverified_retry":
        assert actions.count("put") == actions.count("delete") == 1, events
        assert actions.count("purge") == 8 and server.delivered is None, events
    elif case in ("rejected_put", "uncertain_put"):
        assert actions.count("rejected-put") == 1 and server.delivered is None, events
        assert "put" not in actions and "delete" not in actions and "purge" not in actions, events
    else:
        assert all(action in ("read", "policy") for action in actions), events
        assert server.delivered is None
        if case in ("disabled", "webhook_token"):
            assert not events
        if case in ("pending", "age_restricted"):
            assert [(name, value) for name, value in events if name == "policy"] == [("policy", case)], events


@contextmanager
def native_worker(executable, directory, server, bindings):
    port_file = directory / "worker.port"
    port_file.unlink(missing_ok=True)
    env = dict(os.environ, BUNNY_PILOT_WORKER_TOKEN=SECRETS["bunny_pilot_worker_token"],
               BUNNY_ORIGINAL_PRIMARY="gcs" if server.case == "wrong_worker_primary" else "b2", BUNNY_DERIVED_PRIMARY="b2" if server.derived_bucket == BUCKET else "gcs",
               B2_MEDIA_BUCKET=BUCKET, B2_BUCKET_ID=BUCKET_ID, B2_REGION="us-west-004", GCS_BUCKET="fixture-gcs",
               BUNNY_PILOT_READERS_V1=json.dumps(bindings["bunny_pilot_readers_v1"]),
               BUNNY_PILOT_WRITER_V1=json.dumps(bindings["bunny_pilot_writer_v1"]),
               BUNNY_TEST_ORIGIN=f"http://127.0.0.1:{server.server_port}", BUNNY_TEST_PORT_FILE=str(port_file))
    proc = subprocess.Popen([executable, "bunny_worker::tests::serve_fixture", "--exact", "--ignored"],
                            env=env, stdout=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if port_file.exists() and port_file.read_text():
                server.worker_port = int(port_file.read_text())
                break
            if proc.poll() is not None:
                raise RuntimeError("fixture worker exited before listening")
            time.sleep(0.05)
        else:
            raise RuntimeError("fixture worker did not start")
        yield
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def run(server, repo, directory):
    global BODY, HASH
    build = subprocess.run(["cargo","test","--locked","--manifest-path","cloud-run-upload/Cargo.toml","--no-run","--message-format=json"],
                           cwd=repo,check=True,capture_output=True,text=True)
    executable = next(obj["executable"] for line in build.stdout.splitlines()
                      if (obj := json.loads(line)).get("executable"))
    settings, kv, config = (directory / name for name in ("settings.json", "kv.json", "fastly.toml"))
    dynamic_b2 = f"b2-api-{hashlib.sha256(B2_API_HOST.encode()).hexdigest()[:16]}"
    backend_names = ("cloud_run_upload","gcs_storage", "b2_storage", "b2_api", "bunny_api", "kv-origin-api", dynamic_b2, "fastly_api", "fixture_control")
    backends = "\n".join(
        f'[local_server.backends."{name}"]\nurl = "http://127.0.0.1:{server.server_port}"'
        for name in backend_names
    )
    backends += f'\n[local_server.backends.upload_service]\nurl = "http://127.0.0.1:{server.trap.server_port}"'
    subprocess.run(["cargo","build","--locked","--target","wasm32-wasip1","--bin","fastly-blossom"],cwd=repo,check=True)
    env = os.environ.copy()
    env["CARGO_TARGET_WASM32_WASIP1_RUNNER"] = shlex.join([
        env.get("VICEROY", "viceroy"), "run", "-C", str(config), "--",
    ])
    for label in (sys.argv[1:] or ("hls_family_b2", *CASES)):
        maximum = label == "hls_family_b2"
        BODY = b"b" * (16*1024*1024) if maximum else b"abc"
        HASH = hashlib.sha256(BODY).hexdigest()
        server.publish_times = []
        server.worker_times = []
        server.permit_gate = None
        server.permit_queries = []
        server.in_permit = False
        case = "hls_family" if label == "hls_family_b2" else label
        server.case = case
        server.derived_bucket = "fixture-gcs" if label == "hls_family" else BUCKET
        bindings = dict(SECRETS)
        canonical_reader = "gcs" if server.derived_bucket == "fixture-gcs" else "b2_media"
        bindings[canonical_reader + "_access_key"] = "fixture-canonical-reader"
        bindings[canonical_reader + "_secret_key"] = "fixture-canonical-secret"
        if server.derived_bucket == BUCKET:
            bindings["bunny_pilot_readers_v1"] = {"b2": SECRETS["bunny_pilot_readers_v1"]["b2"]}
        secrets = ", ".join(f'{{ key = "{key}", data = {json.dumps(json.dumps(value) if isinstance(value, dict) else value)} }}'
                            for key, value in bindings.items() if key not in ("bunny_pilot_readers_v1","bunny_pilot_writer_v1"))
        config.write_text(f'''manifest_version = 3
name = "bunny-pilot-publication-fixture"
language = "rust"
{backends}
[local_server.kv_stores.blossom_metadata]
file = "{kv}"
format = "json"
[local_server.config_stores.blossom_config]
file = "{settings}"
format = "json"
[local_server.secret_stores]
blossom_secrets = [{secrets}]
''')

        server.transcode = {"transcode_status": "complete", "transcode_generation": 17}
        server.repair_during_finalize = False
        server.policy_blocker = ""
        server.policy_status = "pending" if case == "pending_zero" else case if case in ("pending", "age_restricted") else "active"
        server.source_key = f"{HASH}/hls/stream_720p.mp4" if case == "active_rendition" else HASH
        server.delivery_key = f"{PREFIX}{HASH}/720p.mp4" if case == "active_rendition" else f"{PREFIX}{HASH}"
        server.delivered = None
        inventory, server.objects, server.destinations = family(server.derived_bucket,maximum)
        server.meter = [["start", 0]]
        server.source_version = "123"
        server.source_versions = {}
        server.head_fault = ""
        server.batch_keys = set()
        server.arrivals_lock = threading.Lock()
        server.batch_arrived = threading.Event()
        server.probe_times = {}
        server.uploaders = "cde" if case == "disabled_four" else "cd"
        server.ready_generation = 0
        server.retire_during_read = False
        server.ready = None
        server.events = []
        kv.write_text("{}")
        settings.write_text(json.dumps({
            "bunny_fixture_case": case,
            "bunny_playback_compute_host": "compute.fixture.example",
            "fixture_parent": HASH,
            "fixture_inventory": json.dumps(inventory),
            "gcs_bucket": "fixture-gcs",
            "media_read_primary": "b2",
            "derived_media_read_primary": "gcs" if label == "hls_family" else "b2",
            "bunny_playback_rollout_percent": "0" if case in ("disabled_four", "pending_zero") else "100",
            "bunny_playback_countries": "US",
            "bunny_fixture_local_gate": "true",
            "bunny_fixture_meter_gate": "true" if case == "hls_family" else "false",
            "bunny_pilot_publish_enabled": "false" if case == "disabled" else "true",
            "bunny_pilot_zone_hosts": ",".join(CDN_HOSTS),
            "b2_replica_enabled": "true",
            "b2_bucket_id": BUCKET_ID,
            "b2_media_bucket": BUCKET,
            "b2_media_region": "us-west-004",
            "metadata_kv_store_id": "fixture-store",
        }))
        with permit_edge(repo, config, server), native_worker(executable,directory,server,bindings):
            result = subprocess.run([
                "cargo", "test", "--locked", "--target", "wasm32-wasip1", "--bin", "fastly-blossom",
                {"pending_zero":"pending_bunny_playback_falls_back","hls_family":"bunny_hls_family_contract","disabled_four":"bunny_disabled_four_uploaders","permit_contract":"bunny_worker_permit_contract"}.get(case,
                    "bunny_publication_respects_authoritative_policy_and_releases_clean_attempts"),
                "--", "--ignored", "--nocapture",
            ], cwd=repo, env=env, capture_output=True, text=True, timeout=240)
        if result.returncode or "test result: ok. 1 passed" not in result.stdout:
            raise RuntimeError(f"{case}: {result.stdout}{result.stderr}\nFixture events: {server.events}")
        for report in result.stderr.splitlines():
            if report.startswith("BUNNY_QUOTA "):
                print(report)
            if report.startswith("BUNNY_ADMIN_REPLY "):
                _, operation, status, body = report.split(" ", 3)
                check_enrollment_reply(directory, operation, int(status), body, case == "source_unavailable")
                print(f"PASS routed {case} {operation} to enrollment journal")
        for phase, count in server.meter:
            if phase not in ("outside", "start"):
                assert count <= 32, (label, phase, count)
                print(f"BUNNY_HTTP {phase} {count}")
        assert server.trap.hits == 0, "unexpected job sent to GKE"
        assert all(0 < count <= 32 for count in server.permit_queries)
        if server.permit_queries:
            print(f"BUNNY_HTTP worker permit max {max(server.permit_queries)}")
        if case == "delayed_publish":
            snippet = (repo / "vcl/pass.vcl").read_text().split('req.url ~ "^/admin/api/bunny-pilot/(publish|finalize)$"')[1]
            outer_timeout = int(re.match(r'\) \{\s+set bereq.first_byte_timeout = (\d+)s;', snippet)[1])
            inner = max(t for op,t in server.worker_times)
            outer = max(server.publish_times)
            assert 15 < inner < 45 and inner <= outer < outer_timeout, (inner, outer)
            print(f"Delayed publication worker {inner:.3f}s, complete admin request {outer:.3f}s, VCL allowance {outer_timeout}s")
        assert_case(server, case)
        if maximum:
            print(f"Maximum-size 8-object worker finalize wall time {max(t for op,t in server.worker_times if op == 'finalize'):.3f}s")
        print(f"PASS {label}")


@contextmanager
def permit_edge(repo, config, server):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0))
        server.permit_port = sock.getsockname()[1]
    addr = f"127.0.0.1:{server.permit_port}"
    with subprocess.Popen([os.environ.get("VICEROY","viceroy"),"serve","--addr",addr,"-C",str(config),
                           str(repo/"target/wasm32-wasip1/debug/fastly-blossom.wasm")],
                          cwd=repo,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL) as proc:
        try:
            deadline = time.monotonic()+45
            while True:
                try:
                    with socket.create_connection(("127.0.0.1",server.permit_port), timeout=1):
                        break
                except OSError:
                    if time.monotonic()>deadline or proc.poll() is not None:
                        raise RuntimeError("permit edge failed to listen")
                    time.sleep(.1)
            yield
        finally:
            proc.terminate()


class GkeTrap(BaseHTTPRequestHandler):
    def do_POST(self):
        self.server.hits += 1
        self.send_error(503)

    def log_message(self, *_args):
        pass


def main():
    repo = Path(__file__).resolve().parent.parent
    with ThreadingHTTPServer(("127.0.0.1", 0), Origin) as server, ThreadingHTTPServer(("127.0.0.1", 0), GkeTrap) as trap:
        trap.hits = 0
        server.trap = trap
        threading.Thread(target=trap.serve_forever,daemon=True).start()
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory(prefix="bunny-pilot-publication-") as directory:
                run(server, repo, Path(directory))
        finally:
            server.shutdown()


if __name__ == "__main__":
    main()
