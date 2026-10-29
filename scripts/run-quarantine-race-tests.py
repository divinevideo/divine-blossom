#!/usr/bin/env python3
"""Race a real production-WASM public response against a synthetic review hold."""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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


class Origin(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        # Viceroy sends local backend health probes without media credentials.
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        assert self.headers.get("Authorization", "").startswith("AWS4-HMAC-SHA256 "), self.path
        self.server.reads.append(self.path)
        self.server.entered.set()
        assert self.server.release.wait(15), "test did not release synthetic origin"
        body = b"WEBVTT\n\n00:00.000 --> 00:01.000\nSynthetic\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def request(base, path, method="GET", body=None, admin=False):
    headers = {"Authorization": "Bearer synthetic-admin-token"} if admin else {}
    if body is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(body).encode()
    req = Request(base + path, data=body, method=method, headers=headers)
    try:
        response = urlopen(req, timeout=25)
    except HTTPError as error:
        response = error
    with response:
        return response.status, response.headers, response.read()


def main():
    repo = Path(__file__).resolve().parent.parent
    # This is the shipped binary target: no cfg(test) storage-cache bypass.
    subprocess.run(["cargo", "build", "--locked", "--target", "wasm32-wasip1",
                    "--bin", "fastly-blossom"], cwd=repo, check=True)
    paths = ["/{hash}/720p.mp4", "/{hash}/hls/stream_720p.ts", "/{hash}.hls",
             "/{hash}/hls/master.m3u8", "/{hash}.jpg", "/{hash}.vtt", "/{hash}/VTT"]
    cases = [(path, method, False) for path in paths for method in ("GET", "HEAD")]
    # An authorized public reviewer request must still finish privately under a hold.
    cases.append(("/{hash}/720p.mp4", "GET", True))
    # Public HEAD handlers do not consume admin auth and can prepare public headers.
    cases.extend((path, "HEAD", True) for path in paths)
    hashes = [f"{index + 1:064x}" for index in range(len(cases))]
    metadata = {f"blob:{sha}": {"sha256": sha, "size": 10, "type": "video/mp4",
        "owner": "b" * 64, "uploaded": "2026-01-01T00:00:00Z", "status": "active",
        "transcode_status": "complete", "transcript_status": "complete"} for sha in hashes}
    with ThreadingHTTPServer(("127.0.0.1", 0), Origin) as origin:
        origin.entered, origin.release, origin.reads = threading.Event(), threading.Event(), []
        thread = threading.Thread(target=origin.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="quarantine-race-test-") as directory:
                root = Path(directory)
                kv, settings, config = root / "kv.json", root / "settings.json", root / "fastly.toml"
                kv.write_text(json.dumps({key: {"data": json.dumps(value)}
                                          for key, value in metadata.items()}))
                settings.write_text(json.dumps({"gcs_bucket": "quarantine-race-test"}))
                config.write_text(f'''manifest_version = 3
name = "quarantine-race-test"
language = "rust"
[local_server.backends.gcs_storage]
url = "http://127.0.0.1:{origin.server_port}"
[local_server.kv_stores.blossom_metadata]
file = "{kv}"
format = "json"
[local_server.config_stores.blossom_config]
file = "{settings}"
format = "json"
[local_server.secret_stores]
blossom_secrets = [{{key="admin_token",data="synthetic-admin-token"}},{{key="gcs_access_key",data="synthetic"}},{{key="gcs_secret_key",data="synthetic"}}]
''')
                with socket.socket() as reservation:
                    reservation.bind(("127.0.0.1", 0))
                    port = reservation.getsockname()[1]
                base = f"http://127.0.0.1:{port}"
                with (root / "viceroy.log").open("w+") as log:
                    process = subprocess.Popen([os.environ.get("VICEROY", "viceroy"), "serve",
                        "--addr", f"127.0.0.1:{port}", "-C", str(config),
                        str(repo / "target/wasm32-wasip1/debug/fastly-blossom.wasm")],
                        cwd=repo, stdout=log, stderr=subprocess.STDOUT)
                    try:
                        deadline = time.monotonic() + 45
                        while True:
                            try:
                                assert request(base, "/version")[0] == 200
                                break
                            except (URLError, TimeoutError):
                                if process.poll() is not None or time.monotonic() > deadline:
                                    raise RuntimeError("Viceroy did not start")
                                time.sleep(0.1)
                        with ThreadPoolExecutor(max_workers=1) as pool:
                            for sha, (template, method, admin) in zip(hashes, cases):
                                path = template.format(hash=sha)
                                origin.entered.clear()
                                origin.release.clear()
                                before = len(origin.reads)
                                pending = pool.submit(request, base, path, method, None, admin)
                                try:
                                    assert origin.entered.wait(10), f"{method} {path} did not reach origin"
                                    changed = request(base, "/admin/api/quarantine", "POST", {
                                        "sha256": sha, "hold_id": "review:race", "version": 1,
                                        "action": "hold"}, True)
                                    assert changed[0] == 200, changed
                                    assert json.loads(changed[2])["quarantined"] is True
                                finally:
                                    origin.release.set()
                                status, headers, body = pending.result()
                                assert len(origin.reads) == before + 1, origin.reads[before:]
                                private_review = admin and method == "GET"
                                if private_review:
                                    assert status == 200, (method, path, status, body)
                                    assert headers.get("Cache-Control") == "private, no-store", headers
                                    assert headers.get("Surrogate-Control") == "no-store", headers
                                else:
                                    assert status == 404, (method, path, status, dict(headers), body)
                                    assert headers.get("Cache-Control") == "no-store", headers
                                    assert headers.get("Surrogate-Control") != "max-age=31536000", headers
                                print(f"PASS late hold blocks {method} {template} admin={admin}" if not private_review else
                                      "PASS authorized review remains private after late hold")
                    except BaseException:
                        log.flush()
                        log.seek(0)
                        print(log.read())
                        raise
                    finally:
                        origin.release.set()
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
        finally:
            origin.shutdown()
            thread.join()


if __name__ == "__main__":
    main()
