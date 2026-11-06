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
        if os.environ.get("TEST_CDN_URL404") == "1":
            self.send_response(404 if self.path.startswith("/purge/") else 200)
        elif os.environ.get("TEST_CDN_KEY404") == "1":
            self.send_response(404 if self.path.startswith("/service/") else 200)
        else:
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
                values = {
                    "b2_cdn_enabled": os.environ.get("TEST_CDN_ADMISSION", "true"),
                    "b2_cdn_host": "media-b2-cdn.divine.video",
                    "b2_cdn_purge_hosts": "media-b2-cdn.divine.video",
                }
                if os.environ.get("TEST_CDN_ABSENT") == "1":
                    values = {}
                settings.write_text(json.dumps(values))
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
blossom_secrets = [{{key="b2_cdn_purge_drain_token",data="synthetic-drain-token"}},{{key="admin_token",data="synthetic-admin-token"}},{{key="fastly_api_token",data="synthetic-purge"}}]
''')
                if os.environ.get("TEST_CDN_MISSING_STORE") == "1":
                    section = f'[local_server.config_stores.blossom_config]\nfile = "{settings}"\nformat = "json"\n'
                    contents = config.read_text()
                    assert section in contents
                    config.write_text(contents.replace(section, "", 1))
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
                    "cdn_drain_service_token_is_not_an_admin_credential",
                    "unavailable_config_store_cannot_disable_durable_eviction",
                    "creator_physical_delete_waits_for_final_purge_without_replaying_absent_bytes",
                    "creator_physical_delete_retains_audio_discovery_until_both_final_receipts",
                    "creator_physical_delete_unreadable_phase_fails_before_policy_mutation",
                    "bulk_approve_skip_purge_reports_durable_pending_hashes",
                    "restore_without_cdn_keeps_existing_non_deleted_rejection",
                    "pending_cdn_intent_cannot_clear_when_purge_configuration_disappears",
                ):
                    assert not server.calls
                    print(f"PASS {os.environ['TEST_CDN_CONTRACT']}: no inline purge requests")
                    return
                if os.environ.get("TEST_CDN_URL404") == "1" or os.environ.get("TEST_CDN_KEY404") == "1":
                    assert len(server.calls) == 6, len(server.calls)
                    for start in range(0, 6, 3):
                        assert sorted(server.calls[start:start + 3]) == sorted(expected)
                    if os.environ.get("TEST_CDN_URL404") == "1":
                        print("PASS retained unbound host: URL404 plus both service key acknowledgements")
                    else:
                        print("PASS missing key acknowledgement: URL success cannot acknowledge eviction")
                    return
                assert len(server.calls) == 18, len(server.calls)
                for start in range(0, 18, 3):
                    assert sorted(server.calls[start:start + 3]) == sorted(expected)
                print(f"PASS {os.environ.get('TEST_CDN_CONTRACT', 'quarantine_cdn_purge_failure_remains_denied_and_idempotently_retries')}: checked failure and bounded retry")
        finally:
            server.shutdown()


if __name__ == "__main__":
    main()
