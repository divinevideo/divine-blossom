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

OUTER_SERVICE = "ML7R82HKfmTaqTpHExIDVN"
COMPUTE_SERVICE = "pOvEEWykEbpnylqst1KTrR"
HASH = "a" * 64


def expected_requests():
    hosts = os.environ.get("TEST_CDN_PURGE_HOSTS", "media-b2-cdn.divine.video").split(",")
    return [
        (f"/service/{OUTER_SERVICE}/purge_url/{host}/{HASH}", None)
        for host in hosts
    ] + [(f"/service/{service}/purge", HASH) for service in (OUTER_SERVICE, COMPUTE_SERVICE)]


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
        # Modern domains require a service-scoped host/path URL purge. Legacy
        # raw/encoded URLs, a target scheme, or the wrong service all get 404.
        valid = (self.path, self.headers.get("Surrogate-Key")) in expected_requests()
        is_url = "/purge_url/" in self.path
        if not valid:
            status = 404
        elif os.environ.get("TEST_CDN_URL404") == "1":
            status = 404 if is_url else 200
        elif os.environ.get("TEST_CDN_URL_OK") == "1":
            status = 200
        elif os.environ.get("TEST_CDN_KEY404") == "1":
            status = 200 if is_url else 404
        else:
            status = 503 if len(self.server.calls) <= 2 * len(expected_requests()) else 200
        # Bulk purge responds with key -> purge ID, not {status:ok}.
        keys = self.headers.get("Surrogate-Key", "").split()
        body = json.dumps({key: "synthetic-purge-id" for key in keys} if keys else
                          {"status": "ok", "id": "synthetic-url-id"}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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
                    "b2_cdn_purge_hosts": os.environ.get("TEST_CDN_PURGE_HOSTS", "media-b2-cdn.divine.video"),
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
                expected = expected_requests()
                per_round = len(expected)
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
                if any(os.environ.get(key) == "1" for key in ("TEST_CDN_URL404", "TEST_CDN_KEY404", "TEST_CDN_URL_OK")):
                    assert len(server.calls) == 2 * per_round, len(server.calls)
                    for start in range(0, len(server.calls), per_round):
                        assert sorted(server.calls[start:start + per_round]) == sorted(expected)
                    if os.environ.get("TEST_CDN_URL404") == "1":
                        print("PASS URL404: both rounds' bulk key acknowledgements cannot clear durable final purge")
                    elif os.environ.get("TEST_CDN_URL_OK") == "1":
                        print("PASS service-scoped URL: both retained hosts and real bulk-key map acknowledgements complete final purge")
                    else:
                        print("PASS missing key acknowledgement: URL success cannot acknowledge eviction")
                    return
                assert len(server.calls) == 6 * per_round, len(server.calls)
                for start in range(0, len(server.calls), per_round):
                    assert sorted(server.calls[start:start + per_round]) == sorted(expected)
                print(f"PASS {os.environ.get('TEST_CDN_CONTRACT', 'quarantine_cdn_purge_failure_remains_denied_and_idempotently_retries')}: checked failure and bounded retry")
        finally:
            server.shutdown()


if __name__ == "__main__":
    main()
