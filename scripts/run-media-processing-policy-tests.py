#!/usr/bin/env python3
"""Execute media processing policy handlers against synthetic Viceroy KV/secrets."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class UploadService(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_PUT(self):
        self.deliver()

    def do_POST(self):
        self.deliver()

    def deliver(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path == "/upload":
            media_hash = body.decode()
        elif self.path.endswith("/complete"):
            media_hash = json.loads(body)["sha256"]
        elif self.path == "/migrate":
            media_hash = json.loads(body)["source_url"].rsplit("/", 1)[-1]
        else:
            self.send_error(404)
            return
        payload = json.dumps({"sha256": media_hash, "size": 64, "type": "video/mp4",
                              "contentType": "video/mp4"}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

server = ThreadingHTTPServer(("127.0.0.1", 0), UploadService)
threading.Thread(target=server.serve_forever, daemon=True).start()
repo = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix="media-policy-") as directory:
    root = Path(directory)
    kv = root / "kv.json"
    kv.write_text("{}")
    settings = root / "settings.json"
    settings.write_text(json.dumps({"local_mode":"false", "upload_service_all_uploads":"true"}))
    config = root / "fastly.toml"
    config.write_text(f'''manifest_version = 3
name = "media-policy-test"
language = "rust"
[local_server.backends.upload_service]
url = "http://127.0.0.1:{server.server_port}"
[local_server.config_stores.blossom_config]
file = "{settings}"
format = "json"
[local_server.kv_stores.blossom_metadata]
file = "{kv}"
format = "json"
[local_server.secret_stores]
blossom_secrets = [{{key="webhook_secret",data="synthetic-webhook"}}]
''')
    env = os.environ.copy()
    env.pop("CARGO_TARGET_WASM32_WASIP1_RUNNER", None)
    runner = json.dumps([env.get("VICEROY", "viceroy"), "run", "-C", str(config), "--"])
    result = subprocess.run([
        "cargo", "--config", f"target.wasm32-wasip1.runner={runner}", "test", "--locked", "--target", "wasm32-wasip1", "--bin", "fastly-blossom",
        "media_policy_", "--", "--include-ignored", "--nocapture"],
        cwd=repo, env=env, capture_output=True, text=True, timeout=900)
    if result.returncode or "test result: ok. 4 passed; 0 failed; 0 ignored;" not in result.stdout:
        raise RuntimeError(result.stdout + result.stderr)
    print("PASS media processing permission, authenticated policy, retry, and stale metadata contracts")
