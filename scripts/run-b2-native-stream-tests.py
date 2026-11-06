#!/usr/bin/env python3
"""Production-WASM guest-exit tests against fragmented synthetic origins only."""

from http.client import IncompleteRead
from http.server import ThreadingHTTPServer
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
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "canary_fixtures", REPO / "scripts/run-b2-canary-tests.py"
)
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


class Origin(fixtures.Origin):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        key = self.path.split("?", 1)[0].rsplit("/", 1)[-1]
        try:
            super().do_GET()
        finally:
            if self.command == "GET" and "/private-test/" in self.path:
                self.server.completed[key].set()

    def send_header(self, name, value):
        if (
            name.lower() == "content-length"
            and "/private-test/" in self.path
            and self.server.advertised is not None
        ):
            value = str(self.server.advertised)
        super().send_header(name, value)


def open_response(base, path, method="GET", data=None, admin=False, extra=None):
    headers = {"Host": "media.divine.video" if admin else "media-b2.divine.video"}
    if admin:
        headers.update(
            {
                "Authorization": "Bearer synthetic-admin",
                "Content-Type": "application/json",
            }
        )
    headers.update(extra or {})
    req = Request(
        base + path,
        method=method,
        data=None if data is None else json.dumps(data).encode(),
        headers=headers,
    )
    try:
        return urlopen(req, timeout=30)
    except HTTPError as error:
        return error


def consume(response):
    digest = hashlib.sha256()
    size = 0
    with response:
        while chunk := response.read(64 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def main():
    subprocess.run(
        [
            "cargo",
            "build",
            "--locked",
            "--target",
            "wasm32-wasip1",
            "--bin",
            "fastly-blossom",
        ],
        cwd=REPO,
        check=True,
    )
    cases = [
        (mib * 1024 * 1024, hashlib.sha256(b"A" * (mib * 1024 * 1024)).hexdigest())
        for mib in [8, 16, 32]
    ]
    broken = hashlib.sha256(b"B" * (8 * 1024 * 1024)).hexdigest()
    concurrent = hashlib.sha256(b"C" * (8 * 1024 * 1024)).hexdigest()
    with ThreadingHTTPServer(
        ("127.0.0.1", 0), Origin
    ) as origin, tempfile.TemporaryDirectory(
        prefix="native-cache-server-"
    ) as temporary:
        root = Path(temporary)
        kv = root / "kv.json"
        settings = root / "settings.json"
        config = root / "fastly.toml"
        metadata = {}
        owner = "b" * 64
        all_cases = [*cases, (8 * 1024 * 1024, broken), (8 * 1024 * 1024, concurrent)]
        for size, key in all_cases:
            metadata["blob:" + key] = {
                "data": json.dumps(
                    {
                        "sha256": key,
                        "size": size,
                        "type": "video/mp4",
                        "uploaded": "2026-01-01T00:00:00Z",
                        "owner": owner,
                        "status": "active",
                    }
                )
            }
            metadata["b2-ready:" + key] = {
                "data": json.dumps(
                    {
                        "version": 1,
                        "sha256": key,
                        "verified_sha256": key,
                        "bucket": "private-test",
                        "key": key,
                        "size": size,
                        "verified_at": 1,
                        "destination_version_id": fixtures.VERSION,
                    }
                )
            }
        kv.write_text(json.dumps(metadata))
        settings.write_text(
            json.dumps(
                {
                    "b2_canary_host": "media-b2.divine.video",
                    "b2_replica_enabled": "true",
                    "b2_demand_mirror_enabled": "true",
                    "b2_canary_cache_enabled": "true",
                    "b2_media_region": "us-west-004",
                    "b2_media_bucket": "private-test",
                    "b2_bucket_id": "synthetic-bucket-id",
                    "gcs_bucket": "gcs-test",
                }
            )
        )
        config.write_text(f"""manifest_version = 3
name = "native-stream-test"
language = "rust"
[local_server.backends.b2_storage]
url = "http://127.0.0.1:{origin.server_port}"
[local_server.backends.gcs_storage]
url = "http://127.0.0.1:{origin.server_port}"
[local_server.backends.b2_api]
url = "http://127.0.0.1:{origin.server_port}"
[local_server.kv_stores.blossom_metadata]
file = "{kv}"
format = "json"
[local_server.config_stores.blossom_config]
file = "{settings}"
format = "json"
[local_server.secret_stores]
blossom_secrets = [{{key="admin_token",data="synthetic-admin"}},{{key="gcs_access_key",data="synthetic"}},{{key="gcs_secret_key",data="synthetic"}},{{key="b2_media_access_key",data="synthetic"}},{{key="b2_media_secret_key",data="synthetic"}},{{key="b2_vanish_application_key_id",data="synthetic"}},{{key="b2_vanish_application_key",data="synthetic"}}]
""")
        origin.requests = []
        origin.status = 200
        origin.version = fixtures.VERSION
        origin.auth_status = 200
        origin.gcs_status = 200
        origin.gcs_size = 9
        origin.range_mode = "normal"
        origin.bucket_name = "private-test"
        origin.bucket_id = "synthetic-bucket-id"
        origin.advertised = None
        origin.fragment_bytes = 1024
        origin.completed = {key: threading.Event() for _, key in all_cases}
        thread = threading.Thread(target=origin.serve_forever, daemon=True)
        thread.start()
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        with (root / "viceroy.log").open("w+") as log:
            server = subprocess.Popen(
                [
                    os.environ.get("VICEROY", "viceroy"),
                    "serve",
                    "--addr",
                    f"127.0.0.1:{port}",
                    "-C",
                    str(config),
                    str(REPO / "target/wasm32-wasip1/debug/fastly-blossom.wasm"),
                ],
                cwd=REPO,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            try:
                deadline = time.monotonic() + 45
                while True:
                    try:
                        with open_response(base, "/version", admin=True) as response:
                            assert response.status == 200
                        break
                    except (URLError, TimeoutError):
                        if server.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError("Viceroy did not start")
                        time.sleep(0.1)
                for size, key in cases:
                    origin.hash = key
                    origin.body_override = b"A" * size
                    before = len(
                        [
                            r
                            for r in origin.requests
                            if r[1].startswith("/private-test/")
                        ]
                    )
                    began = time.monotonic()
                    cold = open_response(base, "/" + key)
                    header_seconds = time.monotonic() - began
                    assert (
                        cold.status == 200
                        and cold.headers.get("X-Divine-Storage-Cache") == "MISS"
                    )
                    assert (
                        cold.headers.get("X-Divine-Storage-Cache-Fill-Mode")
                        == "host-stream"
                    )
                    assert cold.headers.get(
                        "X-Divine-Storage-Cache-Expected-Bytes"
                    ) == str(size)
                    assert (
                        cold.headers.get("X-Divine-Storage-Cache-Buffer-Reads") == "0"
                    )
                    assert (
                        cold.headers.get("X-Divine-Storage-Cache-Buffered-Bytes") == "0"
                    )
                    assert "no-store" in cold.headers.get("Cache-Control", "")
                    cpu = cold.headers.get("X-Divine-Storage-Cache-Cpu-Ms")
                    memory = cold.headers.get(
                        "X-Divine-Storage-Cache-Linear-Memory-Bytes"
                    )
                    assert (
                        header_seconds < 1 and not origin.completed[key].is_set()
                    ), "headers waited for body"
                    assert consume(cold) == (size, key), "cold stream checksum failed"
                    full_seconds = time.monotonic() - began
                    warm = open_response(base, "/" + key)
                    assert warm.headers.get("X-Divine-Storage-Cache") == "HIT"
                    assert consume(warm) == (size, key), "warm stream checksum failed"
                    with open_response(base, "/" + key, "HEAD") as head:
                        assert (
                            head.status == 200
                            and head.headers.get("X-Divine-Storage-Cache") == "HIT"
                        )
                    with open_response(
                        base, "/" + key, extra={"Range": "bytes=0-31"}
                    ) as span:
                        assert (
                            span.status == 206
                            and span.headers.get("X-Divine-Storage-Cache") == "HIT"
                        )
                        assert (
                            span.read() == b"A" * 32
                            and span.headers.get("Content-Range")
                            == f"bytes 0-31/{size}"
                        )
                    reads = [
                        r for r in origin.requests if r[1].startswith("/private-test/")
                    ]
                    assert len(reads) == before + 1, reads
                    print(
                        f"PASS native guest-exit {size//1024//1024}MiB 1KiB fragments early-headers/checksums/MISS-HIT/HEAD/range one-origin headers_s={header_seconds:.3f} full_s={full_seconds:.3f} cpu_ms={cpu} linear_bytes={memory}",
                        flush=True,
                    )
                held = cases[-1][1]
                with open_response(
                    base,
                    "/admin/api/quarantine",
                    "POST",
                    {
                        "sha256": held,
                        "hold_id": "review:native",
                        "version": 1,
                        "action": "hold",
                    },
                    True,
                ) as change:
                    assert change.status == 200
                with open_response(base, "/" + held) as denied:
                    assert denied.status == 404 and "no-store" in denied.headers.get(
                        "Cache-Control", ""
                    )
                print("PASS native warm cache obeys new policy hold", flush=True)
                origin.hash = concurrent
                origin.body_override = b"C" * (8 * 1024 * 1024)
                origin.fragment_bytes = 4096

                def concurrent_read():
                    started = time.monotonic()
                    response = open_response(base, "/" + concurrent)
                    marker = response.headers.get("X-Divine-Storage-Cache")
                    reason = response.headers.get("X-Divine-Storage-Cache-Reason")
                    cpu = response.headers.get("X-Divine-Storage-Cache-Cpu-Ms")
                    assert response.status == 200
                    assert consume(response) == (8 * 1024 * 1024, concurrent)
                    return marker, started, time.monotonic(), reason, cpu

                with ThreadPoolExecutor(max_workers=16) as readers:
                    pending = []
                    for _ in range(16):
                        pending.append(readers.submit(concurrent_read))
                        time.sleep(0.25)
                    results = [future.result() for future in pending]
                print("native staggered cache diagnostics: " + json.dumps(results), flush=True)
                misses = [row for row in results if row[0] == "MISS"]
                assert len(misses) == 1, "followers replaced a healthy cache fill"
                later = [row for row in results if row[1] > misses[0][2]]
                assert later and all(row[0] == "HIT" for row in later), results
                print(
                    "PASS native staggered GETs reach HIT without idle period or replacing healthy fill",
                    flush=True,
                )
                origin.hash = broken
                origin.fragment_bytes = 1024
                origin.body_override = b"B" * (8 * 1024 * 1024 - 1024)
                origin.advertised = 8 * 1024 * 1024
                failed = False
                try:
                    count, digest = consume(open_response(base, "/" + broken))
                    failed = count != 8 * 1024 * 1024 or digest != broken
                except (IncompleteRead, URLError, ConnectionResetError):
                    failed = True
                assert failed, "truncated origin unexpectedly passed checksum"
                with open_response(base, "/" + broken, "HEAD") as head:
                    assert (
                        head.headers.get("X-Divine-Storage-Cache") != "HIT"
                    ), "truncated entry became HIT"
                print(
                    "PASS native truncated stream never becomes completed HIT",
                    flush=True,
                )
                origin.body_override = b"B" * (8 * 1024 * 1024)
                origin.advertised = None
                origin.completed[broken].clear()
                recovered = open_response(base, "/" + broken)
                assert (
                    recovered.headers.get("X-Divine-Storage-Cache") == "MISS"
                ), "failed entry prevented refill"
                assert not origin.completed[broken].is_set()
                overlapping = open_response(base, "/" + broken)
                assert (
                    overlapping.headers.get("X-Divine-Storage-Cache") == "BYPASS"
                ), "healthy in-flight fill was replaced"
                assert consume(recovered) == (
                    8 * 1024 * 1024,
                    broken,
                ), "recovered stream checksum failed"
                assert consume(overlapping) == (
                    8 * 1024 * 1024,
                    broken,
                ), "replacement disrupted healthy in-flight delivery"
                warm = open_response(base, "/" + broken)
                assert warm.headers.get("X-Divine-Storage-Cache") == "HIT"
                assert consume(warm) == (
                    8 * 1024 * 1024,
                    broken,
                ), "recovered HIT checksum failed"
                print(
                    "PASS native failed fill recovers via MISS to completed HIT with overlapping healthy delivery",
                    flush=True,
                )
            except BaseException:
                log.flush()
                log.seek(0)
                print(log.read())
                raise
            finally:
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
                origin.shutdown()
                thread.join(timeout=5)


if __name__ == "__main__":
    main()
