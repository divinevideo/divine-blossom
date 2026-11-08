#!/usr/bin/env python3
"""Real WASM/HTTP range-policy races; this does not emulate an outer VCL cache."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from urllib.error import URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

ROOT = Path(__file__).resolve().parent.parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


native = load("native_stream_fixture", "run-b2-native-stream-tests.py")
purge = load("checked_purge_fixture", "run-b2-cdn-invalidation-tests.py")
HOST, ORIGIN = "media-b2-cdn.divine.video", "synthetic.edgecompute.app"
HOSTS = HOST + ",media-b2.divine.video"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


native.urlopen = build_opener(ProxyHandler({}), NoRedirect()).open


class HeldOrigin(native.Origin):
    def do_GET(self):
        gate = getattr(self.server, "pre_header_gate", None)
        if self.path.startswith("/private-test/") and gate is not None:
            self.server.gate_started.set()
            if not gate.wait(8):
                self.server.gate_timed_out = True
        super().do_GET()


class ObservedPurge(purge.Purge):
    def do_POST(self):
        super().do_POST()
        self.server.first_purge.set()


def get(base, key, range_header="bytes=0-1048575"):
    return native.open_response(base, "/" + key, extra={
        "Host": ORIGIN, "X-Original-Host": HOST, "Range": range_header,
    })


def main():
    subprocess.run(["cargo", "build", "--locked", "--target", "wasm32-wasip1",
                    "--bin", "fastly-blossom"], cwd=ROOT, check=True)
    bodies = {mode: byte * (2 * 1024 * 1024)
              for mode, byte in [("pre_header", b"P"), ("mid_body", b"M")]}
    keys = {mode: hashlib.sha256(body).hexdigest() for mode, body in bodies.items()}
    owner, version = "b" * 64, native.fixtures.VERSION
    os.environ["TEST_CDN_URL_OK"] = "1"
    os.environ["TEST_CDN_PURGE_HOSTS"] = HOSTS
    with ThreadingHTTPServer(("127.0.0.1", 0), HeldOrigin) as origin, \
            ThreadingHTTPServer(("127.0.0.1", 0), ObservedPurge) as checked, \
            tempfile.TemporaryDirectory(prefix="segment-policy-race-") as directory:
        directory = Path(directory)
        metadata = {}
        for mode, key in keys.items():
            size = len(bodies[mode])
            metadata["blob:" + key] = {"data": json.dumps(dict(
                sha256=key, size=size, type="video/mp4", uploaded="2026-01-01T00:00:00Z",
                owner=owner, status="active"))}
            metadata["b2-ready:" + key] = {"data": json.dumps(dict(
                version=1, sha256=key, verified_sha256=key, size=size, key=key,
                bucket="private-test", destination_version_id=version, verified_at=1))}
        kv, settings, config = [directory / name for name in ("kv.json", "settings.json", "fastly.toml")]
        kv.write_text(json.dumps(metadata))
        settings.write_text(json.dumps(dict(
            b2_cdn_enabled="true", b2_cdn_host=HOST, b2_cdn_origin_host=ORIGIN,
            b2_cdn_purge_hosts=HOSTS, b2_replica_enabled="true",
            b2_media_region="us-west-004", b2_media_bucket="private-test",
            b2_bucket_id="synthetic-bucket-id", gcs_bucket="gcs-test")))
        config.write_text(f'''manifest_version = 3
name = "segment-policy-race"
language = "rust"
[local_server.backends.b2_storage]
url = "http://127.0.0.1:{origin.server_port}"
[local_server.backends.gcs_storage]
url = "http://127.0.0.1:{origin.server_port}"
[local_server.backends.b2_api]
url = "http://127.0.0.1:{origin.server_port}"
[local_server.backends.fastly_api]
url = "http://127.0.0.1:{checked.server_port}"
[local_server.kv_stores.blossom_metadata]
file = "{kv}"
format = "json"
[local_server.config_stores.blossom_config]
file = "{settings}"
format = "json"
[local_server.secret_stores]
blossom_secrets = [{{key="admin_token",data="synthetic-admin"}},{{key="fastly_api_token",data="synthetic-purge"}},{{key="gcs_access_key",data="synthetic"}},{{key="gcs_secret_key",data="synthetic"}},{{key="b2_media_access_key",data="synthetic"}},{{key="b2_media_secret_key",data="synthetic"}},{{key="b2_vanish_application_key_id",data="synthetic"}},{{key="b2_vanish_application_key",data="synthetic"}}]
''')
        origin.requests, checked.calls = [], []
        origin.status, origin.version, origin.auth_status = 200, version, 200
        origin.gcs_status, origin.gcs_size, origin.range_mode = 200, 9, "normal"
        origin.bucket_name, origin.bucket_id = "private-test", "synthetic-bucket-id"
        origin.advertised, origin.fragment_bytes = None, 0
        origin.normalized_resource_ranges = True
        origin.completed = {key: threading.Event() for key in keys.values()}
        checked.first_purge = threading.Event()
        threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in [origin, checked]]
        for thread in threads:
            thread.start()
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        with (directory / "viceroy.log").open("w+") as log:
            server = subprocess.Popen([os.environ.get("VICEROY", "viceroy"), "serve",
                "--addr", f"127.0.0.1:{port}", "-C", str(config),
                str(ROOT / "target/wasm32-wasip1/debug/fastly-blossom.wasm")],
                cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 45
                while True:
                    try:
                        with native.open_response(base, "/version", admin=True) as response:
                            assert response.status == 200
                        break
                    except (URLError, TimeoutError):
                        assert server.poll() is None and time.monotonic() < deadline, "Viceroy startup failed"
                        time.sleep(0.1)
                with ThreadPoolExecutor(max_workers=3) as pool:
                    for mode, body in bodies.items():
                        key = keys[mode]
                        origin.hash, origin.body_override = key, body
                        origin.gate_started, origin.gate_timed_out = threading.Event(), False
                        release = threading.Event()
                        origin.pre_header_gate = release if mode == "pre_header" else None
                        origin.media_body_gate = release if mode == "mid_body" else None
                        origin.media_prefix_bytes = 65536
                        purge.HASH = key
                        checked.calls.clear()
                        checked.first_purge.clear()
                        pending = pool.submit(get, base, key)
                        try:
                            assert origin.gate_started.wait(5), "origin did not reach the held barrier"
                            response, prefix = None, b""
                            if mode == "mid_body":
                                response = pending.result(timeout=5)
                                assert response.status == 206
                                assert response.headers.get("Content-Length") == "1048576"
                                assert response.headers.get("X-Divine-B2-CDN-Admission") == "original-segment-v1"
                                prefix = pool.submit(response.read, 65536).result(timeout=5)
                                assert prefix == body[:65536] and not release.is_set()
                                assert not origin.gate_timed_out, "prefix arrived only after origin timed out"
                            mutation = pool.submit(native.open_response, base, "/admin/api/quarantine", "POST",
                                dict(sha256=key, hold_id="review:segment:" + mode, version=1, action="hold"), True)
                            assert checked.first_purge.wait(2), "normal policy did not reach checked purge"
                            if mode == "pre_header":
                                release.set()
                                response = pending.result(timeout=5)
                                assert response.status == 404 and response.headers.get("X-Divine-B2-CDN-Admission") is None
                                response.close()
                            with mutation.result(timeout=8) as changed:
                                assert changed.status == 200
                                changed.read()
                            expected = purge.expected_requests()
                            assert len(checked.calls) == 2 * len(expected)
                            for start in range(0, len(checked.calls), len(expected)):
                                assert sorted(checked.calls[start:start + len(expected)]) == sorted(expected)
                            if mode == "mid_body":
                                assert not origin.gate_timed_out and not release.is_set(), "origin released before the checked purge barrier"
                                release.set()
                                digest = hashlib.sha256(prefix)
                                length = len(prefix)
                                with response:
                                    while chunk := response.read(65536):
                                        digest.update(chunk)
                                        length += len(chunk)
                                assert length == 1048576 and digest.hexdigest() == hashlib.sha256(body[:1048576]).hexdigest()
                            reads = len(origin.requests)
                            for interval in ["bytes=0-1048575", "bytes=1048576-2097151"]:
                                with get(base, key, interval) as denied:
                                    assert denied.status == 404 and "no-store" in denied.headers.get("Cache-Control", "")
                                    assert denied.headers.get("X-Divine-B2-CDN-Admission") is None
                                    denied.read()
                            assert len(origin.requests) == reads, "post-hold range reached an origin"
                            print(f"PASS source HTTP {mode}: checked two-host purge, verified range stream and future disjoint denial", flush=True)
                        finally:
                            release.set()
            except BaseException:
                log.flush()
                log.seek(0)
                print(log.read()[-8000:])
                raise
            finally:
                if getattr(origin, "pre_header_gate", None):
                    origin.pre_header_gate.set()
                if getattr(origin, "media_body_gate", None):
                    origin.media_body_gate.set()
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
                for service in [origin, checked]:
                    service.shutdown()
                for thread in threads:
                    thread.join(timeout=5)


if __name__ == "__main__":
    main()
