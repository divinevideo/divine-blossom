#!/usr/bin/env python3
"""Exercise the edge probe against delayed loopback response headers and bodies."""
import json
import os
import re
from pathlib import Path
import shlex
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class ProbeBackend(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        marker = request["hashes"][0][0]
        body = json.dumps({"checked": 1, "present": 1, "inconclusive": 0,
                           "results": [{"hash": "e" * 64, "status": 200, "outcome": "present"}]}).encode()
        try:
            if marker == "a":  # no headers before the deadline
                time.sleep(1.2)
            elif marker == "d":  # headers and body share one deadline
                time.sleep(0.3)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.flush()
            if marker == "b":  # headers arrive, then the body stalls
                time.sleep(1.2)
            elif marker == "d":
                time.sleep(0.3)
            if marker == "c":  # progress must not reset the deadline
                for byte in body:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.08)
            else:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # Expected when the edge abandons an expired optional probe.


def main():
    repo = Path(__file__).resolve().parent.parent
    with ThreadingHTTPServer(("127.0.0.1", 0), ProbeBackend) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="probe-deadline-") as directory:
                config = Path(directory) / "fastly.toml"
                config.write_text(f'''manifest_version = 3
name = "probe-deadline-test"
language = "rust"
[local_server.backends.cloud_run_upload]
url = "http://127.0.0.1:{server.server_port}"
[local_server.secret_stores]
blossom_secrets = [{{ key = "webhook_secret", data = "synthetic-local-test-secret" }}]
''')
                env = os.environ.copy()
                runner = [env.get("VICEROY", "viceroy"), "run", "-C", str(config), "--"]
                env["CARGO_TARGET_WASM32_WASIP1_RUNNER"] = shlex.join(runner)
                result = subprocess.run(["cargo", "test", "--locked", "--target", "wasm32-wasip1",
                                "--bin", "fastly-blossom", "delivery_probe_deadline", "--",
                                "--ignored", "--nocapture"], cwd=repo, env=env, check=True,
                               timeout=180, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
                print(result.stdout, end="")
                if not re.search(r"test result: ok\. 2 passed; 0 failed; 0 ignored;", result.stdout):
                    raise RuntimeError("expected both delivery probe deadline tests to execute")
        finally:
            server.shutdown()
            thread.join()


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(error.stdout or "", end="")
        raise SystemExit(error.returncode)
