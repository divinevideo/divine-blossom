#!/usr/bin/env python3
"""Exercise Bunny delivery zone policy purging, partial-alias failure, retention, and secret budgets."""

from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import threading
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent.parent
HASH = "a" * 64
UNENROLLED_HASH = "c" * 64
PRIMARY_HOST = "media.divine.video"
ALIAS_HOST = "divine-media-cdn.b-cdn.net"
OLD_PRIMARY_HOST = "old.divine.video"
OLD_ALIAS_HOST = "old-cdn.b-cdn.net"
FASTLY_SERVICES = {"ML7R82HKfmTaqTpHExIDVN", "pOvEEWykEbpnylqst1KTrR"}
TEST = "quarantine_tests::bunny_delivery_policy_purge_and_durable_retry"


class Provider(BaseHTTPRequestHandler):
    def log_message(self, *_):
        if self.path != "/fixture/meter":
            with self.server.lock:
                self.server.meter[-1][1] += 1

    def reply(self, status, payload, generation=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "application/json")
        if generation is not None:
            self.send_header("generation", generation)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/resources/stores/kv/fixture-store/keys/"):
            assert self.headers.get("Fastly-Key") == "synthetic-policy-key"
            if (
                self.server.origin_retained_zones is not None
                and self.path.endswith("/bunny-delivery-retained-zones:v1")
            ):
                body = self.server.origin_retained_zones.encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("generation", "1")
                self.end_headers()
                return self.wfile.write(body)
            return self.reply(404, {})
        return self.reply(404, {})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        if self.path == "/fixture/meter":
            with self.server.lock:
                self.server.meter.append([raw.decode(), 0])
            return self.reply(200, {})
        with self.server.lock:
            try:
                status, payload = self.dispatch()
            except (AssertionError, ValueError, KeyError) as error:
                self.server.errors.append(f"{self.path}: {error}")
                status, payload = 500, {}
        return self.reply(status, payload)

    def dispatch(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/purge":
            return self.bunny(parse_qs(parsed.query))
        return self.fastly(parsed.path)

    def bunny(self, params):
        assert self.headers.get("Host") == "api.bunny.net"
        assert self.headers.get("AccessKey") == self.server.expected_bunny_key
        assert params["async"] == ["false"]
        assert len(params["url"]) == 1
        target = urlsplit(params["url"][0])
        assert target.scheme == "https"
        assert target.netloc in self.server.allowed_bunny_hosts, target.netloc
        assert target.path == f"/{self.server.expected_hash}*" and not target.query
        self.server.bunny_counts[target.netloc] += 1
        # Fail one alias across the initial moderate (2 rounds) and first drain
        # (2 rounds) so partial-alias failure must keep the intent committed.
        if (
            self.server.fail_primary_first_n > 0
            and target.netloc == PRIMARY_HOST
            and self.server.bunny_counts[PRIMARY_HOST] <= self.server.fail_primary_first_n
        ):
            return 503, {}
        return 200, {}

    def fastly(self, path):
        assert self.headers.get("Host") == "api.fastly.com"
        assert self.headers.get("Fastly-Key") == self.server.expected_fastly_key
        if "/purge_url/" in path:
            assert path.startswith("/service/ML7R82HKfmTaqTpHExIDVN/purge_url/")
            self.server.fastly_url_purges.append(path)
            return 200, {}
        assert self.headers.get("Surrogate-Key") == self.server.expected_hash
        service = path.removeprefix("/service/").removesuffix("/purge")
        assert service in FASTLY_SERVICES and path == f"/service/{service}/purge"
        self.server.fastly_services[service] += 1
        return 200, {self.server.expected_hash: "synthetic-purge-id"}


def manifest(port, kv, settings, secrets):
    backends = ("bunny_api", "fastly_api", "kv-origin-api", "fixture_control")
    backend_sections = "\n".join(
        f'[local_server.backends."{name}"]\nurl = "http://127.0.0.1:{port}"'
        for name in backends
    )
    secret_lines = ",\n  ".join(
        f"{{key={json.dumps(k)},data='{v}'}}" for k, v in secrets.items()
    )
    return f"""manifest_version = 3
name = "synthetic-bunny-delivery-invalidation"
language = "rust"
{backend_sections}
[local_server.kv_stores.blossom_metadata]
file = "{kv}"
format = "json"
[local_server.config_stores.blossom_config]
file = "{settings}"
format = "json"
[local_server.secret_stores]
blossom_secrets = [
  {secret_lines}
]
"""


def run_case(mode):
    with ThreadingHTTPServer(("127.0.0.1", 0), Provider) as server:
        server.lock = threading.Lock()
        server.meter = [["setup", 0]]
        server.errors = []
        server.bunny_counts = Counter()
        server.fastly_services = Counter()
        server.fastly_url_purges = []
        server.fail_primary_first_n = 4 if mode == "bunny-only" else 0
        if mode in (
            "cold-pop-origin-retention",
            "webhook-packed-budget",
            "webhook-no-bundle-safe-failclosed",
            "webhook-admin-moderate",
        ):
            server.origin_retained_zones = f"{PRIMARY_HOST},{ALIAS_HOST}"
        elif mode == "stale-pop-origin-rotation":
            server.origin_retained_zones = (
                f"{OLD_PRIMARY_HOST},{OLD_ALIAS_HOST},{PRIMARY_HOST},{ALIAS_HOST}"
            )
        else:
            server.origin_retained_zones = None
        server.allowed_bunny_hosts = (
            {PRIMARY_HOST, ALIAS_HOST, OLD_PRIMARY_HOST, OLD_ALIAS_HOST}
            if mode in ("zone-rotation", "stale-pop-origin-rotation")
            else {PRIMARY_HOST, ALIAS_HOST}
        )
        server.expected_hash = UNENROLLED_HASH if mode == "webhook-packed-budget" else HASH
        server.expected_bunny_key = (
            "synthetic-packed-bunny-key" if mode == "webhook-packed-budget" else "synthetic-bunny-key"
        )
        server.expected_fastly_key = (
            "synthetic-packed-fastly-key" if mode == "webhook-packed-budget" else "synthetic-fastly-key"
        )
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory(prefix=f"bunny-delivery-{mode}-") as directory:
                root = Path(directory)
                config, kv, settings = (root / name for name in ("fastly.toml", "kv.json", "settings.json"))
                kv_initial = {}
                secrets = {
                    "b2_cdn_purge_drain_token": "synthetic-drain-token",
                    "admin_token": "synthetic-admin-token",
                    "webhook_secret": "synthetic-webhook-token",
                    "fastly_api_token": "synthetic-fastly-key",
                    "bunny_api_key": "synthetic-bunny-key",
                }
                if mode == "bunny-only":
                    configuration = {
                        "fixture_delivery_mode": mode,
                        "bunny_delivery_zones": f"{PRIMARY_HOST},{ALIAS_HOST}",
                    }
                elif mode == "retained-after-removal":
                    configuration = {
                        "fixture_delivery_mode": mode,
                        "b2_cdn_host": "media-b2-cdn.divine.video",
                        "b2_cdn_purge_hosts": "media-b2-cdn.divine.video,media-b2.divine.video",
                    }
                    kv_initial["bunny-delivery-retained-zones:v1"] = f"{PRIMARY_HOST},{ALIAS_HOST}"
                elif mode == "zone-rotation":
                    configuration = {
                        "fixture_delivery_mode": mode,
                        "bunny_delivery_zones": f"{PRIMARY_HOST},{ALIAS_HOST}",
                    }
                    kv_initial["bunny-delivery-retained-zones:v1"] = f"{OLD_PRIMARY_HOST},{OLD_ALIAS_HOST}"
                elif mode == "rotation-overflow":
                    configuration = {
                        "fixture_delivery_mode": mode,
                        "bunny_delivery_zones": "third.divine.video,third-cdn.b-cdn.net",
                    }
                    kv_initial["bunny-delivery-retained-zones:v1"] = (
                        f"{OLD_PRIMARY_HOST},{OLD_ALIAS_HOST},{PRIMARY_HOST},{ALIAS_HOST}"
                    )
                elif mode == "webhook-no-bundle-safe-failclosed":
                    configuration = {
                        "fixture_delivery_mode": mode,
                        "bunny_delivery_zones": f"{PRIMARY_HOST},{ALIAS_HOST}",
                        "metadata_kv_store_id": "fixture-store",
                    }
                    secrets["kv_origin_read_token"] = "synthetic-policy-key"
                elif mode == "cold-pop-origin-retention":
                    configuration = {
                        "fixture_delivery_mode": mode,
                        "b2_cdn_host": "media-b2-cdn.divine.video",
                        "b2_cdn_purge_hosts": "media-b2-cdn.divine.video,media-b2.divine.video",
                        "metadata_kv_store_id": "fixture-store",
                    }
                    secrets["kv_origin_read_token"] = "synthetic-policy-key"
                elif mode == "stale-pop-origin-rotation":
                    # Edge KV holds stale old.* while origin already has old.*,new.* and
                    # bunny_delivery_zones was removed from config during rollback.
                    configuration = {
                        "fixture_delivery_mode": mode,
                        "b2_cdn_host": "media-b2-cdn.divine.video",
                        "b2_cdn_purge_hosts": "media-b2-cdn.divine.video,media-b2.divine.video",
                        "metadata_kv_store_id": "fixture-store",
                    }
                    kv_initial["bunny-delivery-retained-zones:v1"] = (
                        f"{OLD_PRIMARY_HOST},{OLD_ALIAS_HOST}"
                    )
                    secrets["kv_origin_read_token"] = "synthetic-policy-key"
                elif mode == "bunny-only-vanish-no-replica":
                    configuration = {
                        "fixture_delivery_mode": mode,
                        "bunny_delivery_zones": f"{PRIMARY_HOST},{ALIAS_HOST}",
                        "b2_replica_enabled": "false",
                    }
                elif mode == "webhook-admin-moderate":
                    configuration = {
                        "fixture_delivery_mode": mode,
                        "bunny_delivery_zones": f"{PRIMARY_HOST},{ALIAS_HOST}",
                        "metadata_kv_store_id": "fixture-store",
                    }
                    secrets["kv_origin_read_token"] = "synthetic-policy-key"
                elif mode == "webhook-packed-budget":
                    configuration = {
                        "fixture_delivery_mode": mode,
                        "bunny_delivery_zones": f"{PRIMARY_HOST},{ALIAS_HOST}",
                        "bunny_pilot_zone_hosts": "media-bunny.divine.video,divine-media-bunny-pilot.b-cdn.net",
                        "metadata_kv_store_id": "fixture-store",
                    }
                    secrets["kv_origin_read_token"] = "synthetic-policy-key"
                    secrets["bunny_pilot_cleanup_v1"] = json.dumps(
                        {
                            "eraser": {"id": "synthetic-b2-id", "key": "synthetic-b2-key"},
                            "bunny_api_key": "synthetic-packed-bunny-key",
                            "fastly_api_token": "synthetic-packed-fastly-key",
                        }
                    )
                elif mode == "invalid-config":
                    configuration = {
                        "fixture_delivery_mode": mode,
                        "bunny_delivery_zones": "   ",
                    }
                else:
                    raise ValueError(f"Unknown mode {mode}")

                kv.write_text(json.dumps(kv_initial))
                settings.write_text(json.dumps(configuration))
                config.write_text(manifest(server.server_port, kv, settings, secrets))

                env = os.environ.copy()
                env["CARGO_TARGET_WASM32_WASIP1_RUNNER"] = shlex.join(
                    [env.get("VICEROY", "viceroy"), "run", "-C", str(config), "--"]
                )
                result = subprocess.run(
                    [
                        "cargo",
                        "test",
                        "--locked",
                        "--target",
                        "wasm32-wasip1",
                        "--bin",
                        "fastly-blossom",
                        TEST,
                        "--",
                        "--ignored",
                        "--exact",
                        "--nocapture",
                    ],
                    cwd=ROOT,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=900,
                )
                if result.returncode or "1 passed; 0 failed" not in result.stdout or server.errors:
                    raise RuntimeError(result.stdout + result.stderr + repr(server.errors))

                if mode in ("invalid-config", "rotation-overflow"):
                    assert not server.bunny_counts
                    print(f"PASS {mode}: fails closed")
                    return

                assert max(n for _, n in server.meter) <= 32, server.meter
                if mode == "bunny-only":
                    # 3 executions (moderate + 2 drains) * 2 rounds = 6 purges per alias.
                    assert server.bunny_counts == {PRIMARY_HOST: 6, ALIAS_HOST: 6}, server.bunny_counts
                    assert server.fastly_services == dict.fromkeys(FASTLY_SERVICES, 6), server.fastly_services
                    assert not server.fastly_url_purges
                elif mode in ("retained-after-removal", "cold-pop-origin-retention"):
                    assert server.bunny_counts == {PRIMARY_HOST: 2, ALIAS_HOST: 2}, server.bunny_counts
                    assert server.fastly_services == dict.fromkeys(FASTLY_SERVICES, 2), server.fastly_services
                    assert len(server.fastly_url_purges) == 4, server.fastly_url_purges
                elif mode in ("zone-rotation", "stale-pop-origin-rotation"):
                    assert server.bunny_counts == {
                        PRIMARY_HOST: 2,
                        ALIAS_HOST: 2,
                        OLD_PRIMARY_HOST: 2,
                        OLD_ALIAS_HOST: 2,
                    }, server.bunny_counts
                    assert server.fastly_services == dict.fromkeys(FASTLY_SERVICES, 2), server.fastly_services
                elif mode == "webhook-no-bundle-safe-failclosed":
                    # Pass 2 (Fastly) + Pass 3 (Bunny retry) + Pass 4 (both together) = 4 each.
                    assert server.bunny_counts == {PRIMARY_HOST: 4, ALIAS_HOST: 4}, server.bunny_counts
                    assert server.fastly_services == dict.fromkeys(FASTLY_SERVICES, 4), server.fastly_services
                elif mode in (
                    "webhook-packed-budget",
                    "bunny-only-vanish-no-replica",
                    "webhook-admin-moderate",
                ):
                    assert server.bunny_counts == {PRIMARY_HOST: 2, ALIAS_HOST: 2}, server.bunny_counts
                    assert server.fastly_services == dict.fromkeys(FASTLY_SERVICES, 2), server.fastly_services
                print(f"PASS {mode}: bunny={dict(server.bunny_counts)} fastly={dict(server.fastly_services)}")
        finally:
            server.shutdown()


if __name__ == "__main__":
    cases = sys.argv[1:] or (
        "bunny-only",
        "retained-after-removal",
        "cold-pop-origin-retention",
        "stale-pop-origin-rotation",
        "zone-rotation",
        "rotation-overflow",
        "webhook-packed-budget",
        "webhook-no-bundle-safe-failclosed",
        "bunny-only-vanish-no-replica",
        "webhook-admin-moderate",
        "invalid-config",
    )
    for case in cases:
        run_case(case)
