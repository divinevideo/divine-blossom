#!/usr/bin/env python3
"""Exercise reversible holds against local synthetic KV and a private origin."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Origin(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.reads.append((self.path, self.headers.get("Range")))
        assert self.headers.get("Authorization", "").startswith("AWS4-HMAC-SHA256 ")
        body = b"0123456789"
        partial = self.headers.get("Range") == "bytes=1-3"
        if partial:
            body = body[1:4]
        self.send_response(206 if partial else 200)
        self.send_header("Content-Length", str(len(body)))
        if partial:
            self.send_header("Content-Range", "bytes 1-3/10")
        self.end_headers()
        self.wfile.write(body)


def main():
    repo = Path(__file__).resolve().parent.parent
    with ThreadingHTTPServer(("127.0.0.1", 0), Origin) as server:
        server.reads = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="quarantine-test-") as directory:
                root = Path(directory)
                config, kv = root / "fastly.toml", root / "kv.json"
                settings = root / "settings.json"
                kv.write_text("{}")
                settings.write_text(json.dumps({"gcs_bucket": "quarantine-test"}))
                config.write_text(f'''manifest_version = 3
name = "quarantine-test"
language = "rust"
[local_server.backends.gcs_storage]
url = "http://127.0.0.1:{server.server_port}"
[local_server.kv_stores.blossom_metadata]
file = "{kv}"
format = "json"
[local_server.config_stores.blossom_config]
file = "{settings}"
format = "json"
[local_server.secret_stores]
blossom_secrets = [{{key="admin_token",data="synthetic-admin-token"}},{{key="gcs_access_key",data="synthetic"}},{{key="gcs_secret_key",data="synthetic"}}]
''')
                env = os.environ.copy()
                env["CARGO_TARGET_WASM32_WASIP1_RUNNER"] = shlex.join([
                    env.get("VICEROY", "viceroy"), "run", "-C", str(config), "--"])
                result = subprocess.run(["cargo", "test", "--locked", "--target", "wasm32-wasip1",
                    "--bin", "fastly-blossom", "quarantine_hold_http_contract", "--", "--ignored", "--nocapture"],
                    cwd=repo, env=env, text=True, capture_output=True, timeout=900)
                if result.returncode or "test result: ok. 1 passed; 0 failed; 0 ignored;" not in result.stdout:
                    raise RuntimeError(result.stdout + result.stderr + f"\nSynthetic origin reads: {server.reads}")
                expected = [
                    (f"/quarantine-test/{'a' * 64}/hls/stream_720p.mp4", "bytes=1-3"),
                    (f"/quarantine-test/{'a' * 64}", None),
                    (f"/quarantine-test/{'a' * 64}", "bytes=1-3"),
                ]
                assert server.reads == expected, server.reads
                print("PASS named holds deny all public media routes, preserve base policy, and retain private admin review")
        finally:
            server.shutdown()
            thread.join()


if __name__ == "__main__":
    main()
