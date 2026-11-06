#!/usr/bin/env python3
"""Exercise policy mutation and checked purge against loopback only."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Purge(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        assert self.headers.get("Fastly-Key") == "synthetic-purge"
        assert self.headers.get("Host") == "api.fastly.com"
        assert self.path.startswith(("/purge/", "/service/"))
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        self.server.calls.append((self.path, self.headers.get("Surrogate-Key")))
        self.send_response(503 if len(self.server.calls) <= 6 else 200)
        self.send_header("Content-Length", "0")
        self.end_headers()


def main():
    repo = Path(__file__).resolve().parent.parent
    with ThreadingHTTPServer(("127.0.0.1", 0), Purge) as server:
        server.calls = []
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory(prefix="cdn-purge-contract-") as directory:
                root = Path(directory)
                config, settings, kv = (root / name for name in ("fastly.toml", "settings.json", "kv.json"))
                settings.write_text(json.dumps({
                    "b2_cdn_enabled": os.environ.get("TEST_CDN_ADMISSION", "true"),
                    "b2_cdn_host": "media-b2-cdn.divine.video",
                    "b2_cdn_purge_hosts": "media-b2-cdn.divine.video",
                }))
                kv.write_text("{}")
                config.write_text(f'''manifest_version = 3
name = "synthetic-cdn-purge"
language = "rust"
[local_server.backends.fastly_api]
url = "http://127.0.0.1:{server.server_port}"
[local_server.kv_stores.blossom_metadata]
file = "{kv}"
format = "json"
[local_server.config_stores.blossom_config]
file = "{settings}"
format = "json"
[local_server.secret_stores]
blossom_secrets = [{{key="admin_token",data="synthetic-admin-token"}},{{key="fastly_api_token",data="synthetic-purge"}}]
''')
                env = os.environ.copy()
                env["CARGO_TARGET_WASM32_WASIP1_RUNNER"] = shlex.join([
                    env.get("VICEROY", "viceroy"), "run", "-C", str(config), "--"])
                result = subprocess.run([
                    "cargo", "test", "--locked", "--target", "wasm32-wasip1", "--bin", "fastly-blossom",
                    os.environ.get("TEST_CDN_CONTRACT", "quarantine_cdn_purge_failure_remains_denied_and_idempotently_retries"), "--", "--ignored", "--nocapture"
                ], cwd=repo, env=env, text=True, capture_output=True, timeout=900)
                if result.returncode or "test result: ok. 1 passed; 0 failed; 0 ignored;" not in result.stdout:
                    raise RuntimeError(result.stdout + result.stderr + f"\nSynthetic purge count: {len(server.calls)}")
                expected = [
                    (f"/purge/https%3A%2F%2Fmedia-b2-cdn.divine.video%2F{'a' * 64}", None),
                    ("/service/ML7R82HKfmTaqTpHExIDVN/purge", "a" * 64),
                    ("/service/pOvEEWykEbpnylqst1KTrR/purge", "a" * 64),
                ]
                if os.environ.get("TEST_CDN_CONTRACT") in (
                    "cdn_purge_drain_requires_admin_and_rejects_oversized_batches",
                    "bulk_approve_skip_purge_reports_durable_pending_hashes",
                ):
                    assert not server.calls
                    print(f"PASS {os.environ['TEST_CDN_CONTRACT']}: no inline purge requests")
                    return
                assert len(server.calls) == 18, len(server.calls)
                for start in range(0, 18, 3):
                    assert sorted(server.calls[start:start + 3]) == sorted(expected)
                print(f"PASS {os.environ.get('TEST_CDN_CONTRACT', 'quarantine_cdn_purge_failure_remains_denied_and_idempotently_retries')}: checked failure and bounded retry")
        finally:
            server.shutdown()


if __name__ == "__main__":
    main()
