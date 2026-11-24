#!/usr/bin/env python3
"""Exercise Bunny edge cache purging under metered Viceroy secret and backend budgets."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import threading


class PurgeBackends(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        self.handle_req()

    def do_DELETE(self):
        self.handle_req()

    def handle_req(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        host = (self.headers.get("Host") or "").lower()
        if host == "fixture.invalid" and self.path == "/fixture/meter":
            phase = body.decode("utf-8", errors="replace")
            if phase == "outside":
                self.server.in_meter = False
            else:
                self.server.in_meter = True
                self.server.metered_calls = []
            self.send_response(200)
            self.end_headers()
            return

        record = {
            "method": self.command,
            "path": self.path,
            "host": host,
            "fastly_key": self.headers.get("Fastly-Key"),
            "access_key": self.headers.get("AccessKey"),
            "surrogate_key": self.headers.get("Surrogate-Key"),
        }
        if self.server.in_meter:
            self.server.metered_calls.append(record)
        self.server.all_calls.append(record)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')


def parse_quota(output):
    match = re.search(r"BUNNY_QUOTA (\S+) (\d+) (\d+) (\d+)", output)
    if not match:
        raise AssertionError(f"Missing BUNNY_QUOTA line in output:\n{output}")
    return {
        "path": match.group(1),
        "config": int(match.group(2)),
        "secrets": int(match.group(3)),
        "plaintext": int(match.group(4)),
    }


def run_case(repo, server, config_dir, test_name, settings_data, secrets_list, metered=True):
    kv = config_dir / "kv.json"
    settings = config_dir / "settings.json"
    fastly_toml = config_dir / "fastly.toml"
    kv.write_text("{}")
    settings.write_text(json.dumps(settings_data))
    secrets_toml = ", ".join(
        f'{{key="{k}",data={json.dumps(v)}}}' for k, v in secrets_list
    )
    port = server.server_port
    fastly_toml.write_text(f'''manifest_version = 3
name = "bunny-edge-purge-test"
language = "rust"

[local_server.backends.fixture_control]
url = "http://127.0.0.1:{port}"
[local_server.backends.fastly_api]
url = "http://127.0.0.1:{port}"
[local_server.backends.bunny_api]
url = "http://127.0.0.1:{port}"
[local_server.backends.gcs_storage]
url = "http://127.0.0.1:{port}"
[local_server.backends.fos_storage]
url = "http://127.0.0.1:{port}"

[local_server.kv_stores.blossom_metadata]
file = "{kv}"
format = "json"

[local_server.config_stores.blossom_config]
file = "{settings}"
format = "json"

[local_server.secret_stores]
blossom_secrets = [{secrets_toml}]
''')
    server.in_meter = False
    server.metered_calls = []
    server.all_calls = []
    env = os.environ.copy()
    env["CARGO_TARGET_WASM32_WASIP1_RUNNER"] = shlex.join([
        env.get("VICEROY", "viceroy"), "run", "-C", str(fastly_toml), "--"
    ])
    proc = subprocess.run(
        [
            "cargo", "test", "--locked", "--target", "wasm32-wasip1",
            "--bin", "fastly-blossom", f"bunny_edge_purge_tests::{test_name}",
            "--", "--ignored", "--exact", "--nocapture",
        ],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        timeout=180,
    )
    combined = proc.stdout + "\n" + proc.stderr
    if proc.returncode != 0 or "test result: ok. 1 passed; 0 failed;" not in proc.stdout:
        raise AssertionError(f"{test_name} failed:\n{combined}")
    if metered:
        quota = parse_quota(combined)
        calls = list(server.metered_calls)
    else:
        quota = None
        calls = list(server.all_calls)
    assert len(calls) <= 32, f"{test_name}: exceeded 32 backend requests ({len(calls)})"
    return quota, calls


def main():
    repo = Path(__file__).resolve().parent.parent
    zones = " Media.Divine.Video , divine-media-cdn.b-cdn.net "
    with ThreadingHTTPServer(("127.0.0.1", 0), PurgeBackends) as server:
        server.in_meter = False
        server.metered_calls = []
        server.all_calls = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="bunny-edge-purge-") as directory:
                cfg = Path(directory)

                # 1. Transcode webhook: Fastly first, then Bunny wildcard purges
                q1, c1 = run_case(
                    repo, server, cfg,
                    "transcode_webhook_purges_fastly_then_bunny_within_budget",
                    {"bunny_delivery_zones": zones},
                    [
                        ("webhook_secret", "synthetic-webhook-secret"),
                        ("fastly_api_token", " fastly-tok\n"),
                        ("bunny_api_key", " bunny-tok\r\n"),
                    ],
                )
                assert q1["secrets"] == 3, q1
                fastly_idx = [i for i, c in enumerate(c1) if c["host"] == "api.fastly.com"]
                bunny_idx = [i for i, c in enumerate(c1) if c["host"] == "api.bunny.net"]
                assert len(fastly_idx) == 2 and len(bunny_idx) == 2, c1
                assert max(fastly_idx) < min(bunny_idx), c1
                h1 = f"{1:064x}"
                assert all(c1[i]["fastly_key"] == "fastly-tok" for i in fastly_idx), c1
                assert {c1[i]["path"] for i in bunny_idx} == {
                    f"/purge?url=https%3A%2F%2Fmedia.divine.video%2F{h1}%2A&async=false",
                    f"/purge?url=https%3A%2F%2Fdivine-media-cdn.b-cdn.net%2F{h1}%2A&async=false",
                }, c1
                assert all(c1[i]["access_key"] == "bunny-tok" for i in bunny_idx), c1
                print("PASS transcode_webhook_purges_fastly_then_bunny_within_budget", flush=True)

                # 2. Missing fastly_api_token still purges Bunny
                q2, c2 = run_case(
                    repo, server, cfg,
                    "missing_fastly_token_still_purges_bunny",
                    {"bunny_delivery_zones": zones},
                    [
                        ("webhook_secret", "synthetic-webhook-secret"),
                        ("bunny_api_key", "bunny-tok"),
                    ],
                )
                assert q2["secrets"] == 3, q2
                assert sum(1 for c in c2 if c["host"] == "api.fastly.com") == 0, c2
                assert sum(1 for c in c2 if c["host"] == "api.bunny.net") == 2, c2
                print("PASS missing_fastly_token_still_purges_bunny", flush=True)

                # 3. /admin/moderate tracks webhook_secret in request_bindings
                q3, c3 = run_case(
                    repo, server, cfg,
                    "admin_moderate_webhook_tracks_webhook_secret_and_purges_bunny",
                    {"bunny_delivery_zones": zones},
                    [
                        ("webhook_secret", "synthetic-webhook-secret"),
                        ("fastly_api_token", "fastly-tok"),
                        ("bunny_api_key", "bunny-tok"),
                    ],
                )
                assert q3["secrets"] <= 5 and q3["plaintext"] == 3, q3
                assert sum(1 for c in c3 if c["host"] == "api.fastly.com") == 2, c3
                assert sum(1 for c in c3 if c["host"] == "api.bunny.net") == 2, c3
                print("PASS admin_moderate_webhook_tracks_webhook_secret_and_purges_bunny", flush=True)

                # 4. Admin soft delete (session cookie) purges Fastly + Bunny within budget
                q4_soft, c4_soft = run_case(
                    repo, server, cfg,
                    "admin_soft_delete_purges_fastly_and_bunny_within_budget",
                    {"bunny_delivery_zones": zones},
                    [
                        ("fastly_api_token", "fastly-tok"),
                        ("bunny_api_key", "bunny-tok"),
                    ],
                )
                assert q4_soft["secrets"] <= 5 and q4_soft["plaintext"] == 2, q4_soft
                assert sum(1 for c in c4_soft if c["host"] == "api.fastly.com") == 2, c4_soft
                assert sum(1 for c in c4_soft if c["host"] == "api.bunny.net") == 2, c4_soft
                print("PASS admin_soft_delete_purges_fastly_and_bunny_within_budget", flush=True)

                # 5. Legacy physical creator delete defers Bunny during soft_delete so GCS + FOS succeed
                _, c4 = run_case(
                    repo, server, cfg,
                    "legacy_physical_creator_delete_preserves_origin_secret_budget",
                    {
                        "bunny_delivery_zones": zones,
                        "ENABLE_PHYSICAL_DELETE": "true",
                        "local_mode": "true",
                        "gcs_bucket": "synthetic-gcs",
                        "fos_bucket": "synthetic-fos",
                    },
                    [
                        ("fastly_api_token", "fastly-tok"),
                        ("bunny_api_key", "bunny-tok"),
                        ("gcs_access_key", "gcs-ak"),
                        ("gcs_secret_key", "gcs-sk"),
                        ("fos_access_key", "fos-ak"),
                        ("fos_secret_key", "fos-sk"),
                    ],
                    metered=False,
                )
                assert any(c["method"] == "DELETE" and "/synthetic-gcs/" in c["path"] for c in c4), c4
                assert any(c["method"] == "DELETE" and "/synthetic-fos/" in c["path"] for c in c4), c4
                assert sum(1 for c in c4 if c["host"] == "api.fastly.com") == 4, c4
                assert sum(1 for c in c4 if c["host"] == "api.bunny.net") == 0, c4
                print("PASS legacy_physical_creator_delete_preserves_origin_secret_budget", flush=True)

                # 5. Bulk approve batches Fastly and caps Bunny purges within 32-request budget
                q5, c5 = run_case(
                    repo, server, cfg,
                    "bulk_approve_batches_fastly_and_bounds_bunny_within_backend_limit",
                    {"bunny_delivery_zones": zones},
                    [
                        ("fastly_api_token", "fastly-tok"),
                        ("bunny_api_key", "bunny-tok"),
                    ],
                )
                assert q5["secrets"] <= 5 and q5["plaintext"] == 2, q5
                fastly_calls = [c for c in c5 if c["host"] == "api.fastly.com"]
                bunny_calls = [c for c in c5 if c["host"] == "api.bunny.net"]
                assert len(fastly_calls) == 2, fastly_calls
                assert len(bunny_calls) == 28, len(bunny_calls)
                assert len(c5) == 30, len(c5)
                for fc in fastly_calls:
                    keys = fc["surrogate_key"].split()
                    assert len(keys) == 16, fc
                print("PASS bulk_approve_batches_fastly_and_bounds_bunny_within_backend_limit", flush=True)
        finally:
            server.shutdown()
            thread.join()


if __name__ == "__main__":
    main()
