#!/usr/bin/env python3
"""Run real HLS alias, URL-resolution, policy and range handlers under Viceroy."""
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
        assert self.headers.get("Authorization", "").startswith("AWS4-HMAC-SHA256 ")
        self.server.reads.append((self.path, self.headers.get("Range")))
        hash_value = "a" * 64
        prefix = f"/hls-test/{hash_value}/hls/"
        bodies = {
            prefix + "master.m3u8": b"#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=100\nstream_480p.m3u8\n",
            prefix + "stream_480p.m3u8": b"#EXTM3U\n#EXTINF:4,\nsegment_0.ts\n#EXT-X-ENDLIST\n",
            prefix + "segment_0.ts": b"segment-bytes",
            prefix + "stream_480p.mp4": b"segment-bytes",
        }
        status, body = (200, bodies[self.path]) if self.path in bodies else (404, b"missing")
        if status == 200 and self.headers.get("Range") == "bytes=0-3":
            status, body = 206, body[:4]
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("ETag", '"synthetic-origin-body"')
        if status == 206:
            self.send_header("Content-Range", "bytes 0-3/13")
        self.end_headers()
        self.wfile.write(body)


def main():
    repo = Path(__file__).resolve().parent.parent
    with ThreadingHTTPServer(("127.0.0.1", 0), Origin) as origin:
        origin.reads = []
        thread = threading.Thread(target=origin.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="hls-alias-test-") as directory:
                root = Path(directory)
                config, kv, settings = root / "fastly.toml", root / "kv.json", root / "settings.json"
                kv.write_text("{}")
                settings.write_text(json.dumps({"gcs_bucket": "hls-test"}))
                config.write_text(f'''manifest_version = 3
name = "hls-alias-test"
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
                env = os.environ.copy()
                env["CARGO_TARGET_WASM32_WASIP1_RUNNER"] = shlex.join([
                    env.get("VICEROY", "viceroy"), "run", "-C", str(config), "--"])
                result = subprocess.run([
                    "cargo", "test", "--locked", "--target", "wasm32-wasip1", "--bin", "fastly-blossom",
                    "hls_alias_relative_playlist_http_contract", "--", "--ignored", "--nocapture"],
                    cwd=repo, env=env, capture_output=True, text=True, timeout=900)
                if result.returncode or "test result: ok. 1 passed; 0 failed; 0 ignored;" not in result.stdout:
                    raise RuntimeError(result.stdout + result.stderr)
                prefix = f"/hls-test/{'a' * 64}/hls/"
                required = {
                    (prefix + "master.m3u8", None),
                    (prefix + "stream_480p.m3u8", None),
                    (prefix + "segment_0.ts", None),
                    (prefix + "stream_480p.mp4", "bytes=0-3"),
                    (f"/hls-test/{'c' * 64}/hls/master.m3u8", None),
                }
                # Alias, canonical and admin requests may share the cached origin master.
                assert set(origin.reads) == required and len(origin.reads) <= 7, origin.reads
                print("PASS HLS alias follows canonical playlists/segments and ranged MP4 while preserving access and cache policy")
        finally:
            origin.shutdown()
            thread.join()


if __name__ == "__main__":
    main()
