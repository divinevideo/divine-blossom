#!/usr/bin/env python3
"""Exercise the thumbnail service token against a loopback upload service.

divine-upload-server#52: Blossom sends X-Divine-Thumbnail-Token on its
/thumbnail/<hash> calls when blossom_secrets holds thumbnail_service_token.
The loopback backend echoes the token and request id it received, so the edge
tests can assert the real host send path: the configured secret is sent, an
existing store without the key sends nothing, and a viewer's header is never
forwarded.
"""
import json
import os
import re
import shlex
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

VIEWER_HASH = "b" * 64


class UploadAndStorageBackend(BaseHTTPRequestHandler):
    """Stands in for upload_service (/thumbnail) and storage (404 for everything else)."""

    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path.startswith("/thumbnail/"):
            self.server.thumbnail_requests.append((
                self.headers.get("X-Divine-Thumbnail-Token") or "-",
                self.headers.get("x-request-id") or "-",
            ))
            body = b"\xff\xd8\xff\xe0loopback-jpeg"
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("x-seen-token", self.headers.get("X-Divine-Thumbnail-Token") or "-")
            self.send_header("x-seen-request-id", self.headers.get("x-request-id") or "-")
            self.send_header("Cache-Control", "private, no-store")
            self.send_header("Vary", "x-divine-thumbnail-token")
            self.end_headers()
            self.wfile.write(body)
            return
        self.server.storage_paths.append(self.path)
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_HEAD = do_GET


def manifest(directory, port, secrets, extra_config=None):
    """Write the store files and return the manifest text for one scenario."""
    metadata = json.dumps({
        "sha256": VIEWER_HASH, "size": 1, "type": "video/mp4",
        "uploaded": "2026-01-01T00:00:00Z", "owner": "c" * 64, "status": "active",
    })
    kv = Path(directory) / "kv.json"
    kv.write_text(json.dumps({f"blob:{VIEWER_HASH}": metadata}))
    settings = Path(directory) / "config.json"
    config = {"gcs_bucket": "synthetic-media", "local_mode": "false"}
    if extra_config:
        config.update(extra_config)
    settings.write_text(json.dumps(config))
    backends = "\n".join(
        f'[local_server.backends.{name}]\nurl = "http://127.0.0.1:{port}"'
        for name in ("upload_service", "gcs_storage", "b2_storage", "cdn_divine")
    )
    secret_rows = ", ".join(f'{{ key = "{k}", data = "{v}" }}' for k, v in secrets.items())
    return f'''manifest_version = 3
name = "thumbnail-token-test"
language = "rust"
{backends}
[local_server.kv_stores.blossom_metadata]
file = "{kv}"
format = "json"
[local_server.config_stores.blossom_config]
file = "{settings}"
format = "json"
[local_server.secret_stores]
blossom_secrets = [{secret_rows}]
'''


def run(repo, port, secrets, test_filter, expected, exact=False, extra_config=None):
    with tempfile.TemporaryDirectory(prefix="thumbnail-token-") as directory:
        config = Path(directory) / "fastly.toml"
        config.write_text(manifest(directory, port, secrets, extra_config=extra_config))
        env = os.environ.copy()
        runner = [env.get("VICEROY", "viceroy"), "run", "-C", str(config), "--"]
        env["CARGO_TARGET_WASM32_WASIP1_RUNNER"] = shlex.join(runner)
        result = subprocess.run(
            ["cargo", "test", "--locked", "--target", "wasm32-wasip1", "--bin", "fastly-blossom",
             test_filter, "--", "--ignored", "--nocapture", *(["--exact"] if exact else [])],
            cwd=repo, env=env, check=True, timeout=300, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        print(result.stdout, end="")
        if not re.search(rf"test result: ok\. {expected} passed; 0 failed; 0 ignored;", result.stdout):
            raise RuntimeError(f"expected {expected} {test_filter} test(s) to execute")


def main():
    repo = Path(__file__).resolve().parent.parent
    base = {"gcs_access_key": "synthetic", "gcs_secret_key": "synthetic"}
    with ThreadingHTTPServer(("127.0.0.1", 0), UploadAndStorageBackend) as server:
        server.thumbnail_requests = []
        server.storage_paths = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_port
            with_key = {**base, "thumbnail_service_token": "loopback-token"}
            run(repo, port, with_key, "thumbnail_token_loopback_sends_the_configured_secret", 1)
            run(repo, port, with_key, "tests::thumbnail_token_loopback_never_forwards_a_viewer_token", 1, exact=True)
            # The production pre-secret state: the store exists, the key doesn't.
            run(repo, port, base, "thumbnail_token_loopback_sends_nothing_when_the_key_is_missing", 1)
            # Nothing overwrites the header here, so a forwarded viewer token would show.
            run(repo, port, base, "thumbnail_token_loopback_never_forwards_a_viewer_token_without_a_key", 1)

            b2_secrets = {
                **with_key,
                "b2_media_access_key": "synthetic",
                "b2_media_secret_key": "synthetic",
                "admin_token": "loopback-admin",
            }
            b2_config = {
                "derived_media_read_primary": "b2",
                "derived_media_gcs_fallback_enabled": "true",
                "b2_media_bucket": "b2",
                "b2_media_region": "us-west-004",
            }
            server.thumbnail_requests.clear()
            server.storage_paths.clear()
            run(
                repo,
                port,
                b2_secrets,
                "thumbnail_token_loopback_b2_miss_reserves_budget_for_token",
                1,
                extra_config=b2_config,
            )
            assert any(p.startswith("/b2/") for p in server.storage_paths), server.storage_paths
            assert not any(p.startswith("/synthetic-media/") for p in server.storage_paths), server.storage_paths
            assert server.thumbnail_requests == [("loopback-token", "blossom-thumbnail-b2-miss-req-1")], server.thumbnail_requests

            server.thumbnail_requests.clear()
            run(repo, port, with_key, "thumbnail_token_loopback_head_sends_token_and_request_id", 1)
            assert server.thumbnail_requests == [("loopback-token", "blossom-thumbnail-head-req-1")], server.thumbnail_requests

            print("PASS all 6 thumbnail token loopback tests")
        finally:
            server.shutdown()
            thread.join()


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(error.stdout or "", end="")
        raise SystemExit(error.returncode)
