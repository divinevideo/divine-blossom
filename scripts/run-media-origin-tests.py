#!/usr/bin/env python3
"""Verify B2 origin selection and GCS fallback against synthetic local backends."""
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Storage(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        bucket, key = self.path.strip("/").split("/", 1)
        self.server.reads.append((bucket, key, self.headers.get("Range")))
        scope = "/us-west-004/s3/aws4_request" if bucket == "b2" else "/auto/s3/aws4_request"
        assert scope in self.headers.get("Authorization", "")
        if key == "disconnect" or (bucket == "b2" and key == "transport"):
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        status = 200
        if bucket == "b2":
            status = {"missing": 404, "transient": 503, "forbidden": 403}.get(key, 200)
        elif key == "transient":
            status = 206
        else:
            status = {"forbidden": 403, "unavailable": 503, "invalid-range": 416}.get(key, 200)
        body = f"{bucket} bytes".encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        if status == 206:
            self.send_header("Content-Range", "bytes 1-3/9")
        self.end_headers()
        self.wfile.write(body)


def main():
    repo = Path(__file__).resolve().parent.parent
    with ThreadingHTTPServer(("127.0.0.1", 0), Storage) as server:
        server.reads = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="media-origins-") as directory:
                root = Path(directory)
                config = root / "fastly.toml"
                settings = root / "settings.json"
                config.write_text(f'''manifest_version = 3
name = "media-origins-test"
language = "rust"
[local_server.backends.gcs_storage]
url = "http://127.0.0.1:{server.server_port}"
[local_server.backends.b2_storage]
url = "http://127.0.0.1:{server.server_port}"
[local_server.config_stores.blossom_config]
file = "{settings}"
format = "json"
[local_server.secret_stores]
blossom_secrets = [{{key="gcs_access_key",data="synthetic"}},{{key="gcs_secret_key",data="synthetic"}},{{key="b2_media_access_key",data="synthetic"}},{{key="b2_media_secret_key",data="synthetic"}}]
''')
                env = os.environ.copy()
                env["CARGO_TARGET_WASM32_WASIP1_RUNNER"] = shlex.join([
                    env.get("VICEROY", "viceroy"), "run", "-C", str(config), "--"
                ])
                cases = [
                    ("media_origin_routing_contract", "b2", "true"),
                    ("media_origin_disabled_fallback_contract", "b2", "false"),
                    ("media_origin_invalid_config_contract", "invalid", "true"),
                    ("media_origin_gcs_errors_contract", None, "true"),
                    ("media_origin_gcs_missing_config_contract", None, "true"),
                ]
                for test, primary, fallback in cases:
                    values = {
                        "media_read_primary": primary, "gcs_fallback_enabled": fallback,
                        "gcs_bucket": "gcs", "b2_media_bucket": "b2",
                        "b2_media_region": "us-west-004",
                    }
                    if primary is None:
                        del values["media_read_primary"]
                    if test == "media_origin_gcs_missing_config_contract":
                        del values["gcs_bucket"]
                    settings.write_text(json.dumps(values))
                    before = len(server.reads)
                    result = subprocess.run([
                        "cargo", "test", "--locked", "--target", "wasm32-wasip1",
                        "--bin", "fastly-blossom", test, "--", "--ignored", "--nocapture"
                    ], cwd=repo, env=env, capture_output=True, text=True, timeout=180)
                    if result.returncode or "test result: ok. 1 passed; 0 failed; 0 ignored;" not in result.stdout:
                        raise RuntimeError(result.stdout + result.stderr)
                    if test == "media_origin_routing_contract":
                        assert "primary=b2 fallback=gcs cause=transport" in result.stdout + result.stderr
                    reads = server.reads[before:]
                    if test == "media_origin_routing_contract":
                        assert reads == [
                            ("b2", "hit", None), ("b2", "missing", None), ("gcs", "missing", None),
                            ("b2", "transient", "bytes=1-3"), ("gcs", "transient", "bytes=1-3"),
                            ("b2", "forbidden", None),
                            ("b2", "transport", None), ("gcs", "transport", None),
                        ], reads
                    elif test == "media_origin_disabled_fallback_contract":
                        assert reads == [("b2", "missing", None)], reads
                    elif test == "media_origin_gcs_errors_contract":
                        assert reads == [("gcs", key, None) for key in
                                         ("forbidden", "unavailable", "invalid-range", "disconnect")], reads
                    else:
                        assert reads == [], reads
                    print(f"PASS {test}")
        finally:
            server.shutdown()
            thread.join()


if __name__ == "__main__":
    main()
