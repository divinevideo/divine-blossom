"""Exercise a recovered Compute service against isolated, empty local stores."""
import argparse
import hashlib
from http.client import HTTPConnection
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument("--wasm", type=Path, required=True)
parser.add_argument("--viceroy", default="viceroy")
args = parser.parse_args()
profile = json.loads(Path(__file__).with_name("profile.json").read_text())
wasm = args.wasm.resolve()

with tempfile.TemporaryDirectory(prefix="recovered-compute-smoke-") as temp:
    directory = Path(temp)
    (directory / "jobs.json").write_text("{}")
    settings = 'manifest_version = 3\nname = "recovered-service-smoke"\nlanguage = "rust"\n'
    if profile["kind"] == "ai":
        settings += f'\n[local_server.kv_stores.jobs]\nfile = "{directory / "jobs.json"}"\nformat = "json"\n'
        settings += '\n[local_server.secret_stores]\nsecrets = []\n'
        for name in ["relay_divine_video", "nostr_rest_gateway", "reality_defender", "hive_ai", "sensity"]:
            settings += f'\n[local_server.backends.{name}]\nurl = "http://127.0.0.1:9"\n'
    config = directory / "fastly.toml"
    config.write_text(settings)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    with (directory / "viceroy.log").open("w") as log:
        proc = subprocess.Popen([args.viceroy, "serve", "--addr", f"127.0.0.1:{port}", "-C", str(config), str(wasm)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 45
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=1):
                        break
                except OSError:
                    if proc.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("Viceroy did not start: " + (directory / "viceroy.log").read_text())
                    time.sleep(0.05)

            def request(method, path, body=None):
                connection = HTTPConnection("127.0.0.1", port, timeout=10)
                try:
                    connection.request(method, path, body, {"Content-Type": "application/json"})
                    response = connection.getresponse()
                    return response.status, dict(response.getheaders()), response.read()
                finally:
                    connection.close()

            status, headers, body = request("GET", "/")
            assert status == 200
            assert hashlib.sha256(body).hexdigest() == profile["root_sha256"], "landing body differs from the original live service"
            assert request("GET", "/missing-smoke-route")[0] == 404
            checks = 2
            if profile["kind"] == "starter":
                assert request("HEAD", "/")[0::2] == (200, b"")
                assert request("OPTIONS", "/")[0] == 200
                for method in ["POST", "PUT", "PATCH", "DELETE"]:
                    status, headers, body = request(method, "/", "{}")
                    assert status == 405
                    assert headers.get("allow") == "GET, HEAD, PURGE" or headers.get("Allow") == "GET, HEAD, PURGE"
                checks += 6
            else:
                assert request("GET", "/health")[0::2] == (200, b"OK")
                status, _, body = request("GET", "/api/jobs?limit=2&offset=1")
                value = json.loads(body)
                assert status == 200 and value == {"jobs": [], "count": 0, "total": 0, "limit": 2, "offset": 1}
                assert request("GET", "/api/jobs/invalid")[0] == 400
                assert request("GET", "/api/jobs/" + "a" * 64)[0] == 404
                assert request("POST", "/analyze", "{}")[0] == 400
                assert request("POST", "/analyze", '{"eventId":"synthetic","videoUrl":""}')[0] == 400
                checks += 6
            print(f"PASS {profile['kind']}: {checks} HTTP checks, original landing hash, isolated local stores")
        finally:
            proc.terminate()
            proc.wait(timeout=10)
