#!/usr/bin/env python3
"""Verify typed delivery observations against local cache and origin execution."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import threading
from http.server import ThreadingHTTPServer

path = Path(__file__).with_name("run-b2-canary-tests.py")
spec = importlib.util.spec_from_file_location("canary_fixtures", path)
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
repo = path.parent.parent
cases = {
    "cold_miss": ("b2", "miss", "none", True, True),
    "warm_hit": ("none", "hit", "none", False, True),
    "bypass": ("b2", "bypass", "none", True, True),
    "fallback_hit": ("none", "hit", "missing_readiness", False, False),
    "failed_b2_fallback_hit": ("none", "hit", "unavailable", True, False),
}
failures = []
with ThreadingHTTPServer(("127.0.0.1", 0), fixtures.Origin) as server:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="playback-cache-telemetry-") as directory:
            root = Path(directory)
            config, settings, kv = root / "fastly.toml", root / "settings.json", root / "kv.json"
            config.write_text(f'''manifest_version = 3
name = "playback-cache-telemetry"
language = "rust"
[local_server.backends.b2_storage]
url = "http://127.0.0.1:{server.server_port}"
[local_server.backends.gcs_storage]
url = "http://127.0.0.1:{server.server_port}"
[local_server.backends.b2_api]
url = "http://127.0.0.1:{server.server_port}"
[local_server.kv_stores.blossom_metadata]
file = "{kv}"
format = "json"
[local_server.config_stores.blossom_config]
file = "{settings}"
format = "json"
[local_server.secret_stores]
blossom_secrets = [{{key="gcs_access_key",data="synthetic"}},{{key="gcs_secret_key",data="synthetic"}},{{key="b2_media_access_key",data="synthetic"}},{{key="b2_media_secret_key",data="synthetic"}},{{key="b2_vanish_application_key_id",data="synthetic"}},{{key="b2_vanish_application_key",data="synthetic"}}]
''')
            env = os.environ.copy()
            env["CARGO_TARGET_WASM32_WASIP1_RUNNER"] = shlex.join([env.get("VICEROY", "viceroy"), "run", "-C", str(config), "--"])
            selected = os.environ.get("B2_TELEMETRY_CACHE_CASE")
            for scenario in [selected] if selected else cases:
                provider, cache, fallback, attempted, ready_at_start = cases[scenario]
                server.requests = []
                server.bucket_name, server.bucket_id = "private-test", "synthetic-bucket-id"
                server.status = 503 if scenario == "failed_b2_fallback_hit" else 200
                server.version, server.auth_status = fixtures.VERSION, 200
                server.gcs_status, server.gcs_size, server.range_mode = 200, 9, "normal"
                body = "b2 bytes!" if ready_at_start else "gcsbytes!"
                server.hash = hashlib.sha256(body.encode()).hexdigest()
                values = {
                    "b2_canary_host": "media-b2.divine.video", "b2_replica_enabled": "true",
                    "b2_media_region": "us-west-004", "b2_media_bucket": "private-test",
                    "b2_bucket_id": "synthetic-bucket-id", "gcs_bucket": "gcs-test",
                    "b2_demand_mirror_enabled": "true", "b2_canary_cache_enabled": "true",
                    "b2_playback_telemetry_enabled": "true", "test_hash": server.hash,
                    "test_body": body, "test_cache_observation_scenario": scenario,
                    "test_telemetry_provider": provider, "test_telemetry_storage_cache": cache,
                    "test_telemetry_fallback": fallback, "test_origin_attempted": str(attempted).lower(),
                }
                ready = {"version": 1, "sha256": server.hash, "verified_sha256": server.hash,
                         "bucket": "private-test", "key": server.hash, "size": 9,
                         "verified_at": 1, "destination_version_id": fixtures.VERSION}
                values["test_readiness"] = json.dumps(ready)
                data = {f"blob:{server.hash}": {"sha256": server.hash, "size": 9, "type": "video/mp4",
                        "uploaded": "2026-01-01T00:00:00Z", "owner": "b" * 64, "status": "active"}}
                if ready_at_start:
                    data[f"b2-ready:{server.hash}"] = ready
                settings.write_text(json.dumps(values))
                kv.write_text(json.dumps({key: json.dumps(value) for key, value in data.items()}))
                result = subprocess.run(["cargo", "test", "--locked", "--target", "wasm32-wasip1", "--bin", "fastly-blossom",
                    "delivery_telemetry::tests::cache_delivery_observation_contract", "--", "--ignored", "--nocapture"],
                    cwd=repo, env=env, text=True, capture_output=True, timeout=180)
                if result.returncode or "test result: ok. 1 passed; 0 failed;" not in result.stdout:
                    failures.append(f"{scenario}\n{result.stdout}{result.stderr}")
                    print(f"FAIL {scenario}", flush=True)
                    continue
                media = [request for request in server.requests if request[1].startswith(("/private-test/", "/gcs-test/"))]
                expected_media = [("HEAD" if scenario == "bypass" else "GET", f"/private-test/{server.hash}" if ready_at_start else f"/gcs-test/{server.hash}")]
                if scenario == "failed_b2_fallback_hit":
                    expected_media.append(("GET", f"/private-test/{server.hash}?versionId={fixtures.VERSION.replace('+', '%2B')}"))
                # B2 query encoding is checked by the shared fixture itself.
                assert [(method, url.split("?", 1)[0]) for method, url, _ in media] == [(method, url.split("?", 1)[0]) for method, url in expected_media], media
                auth = [request for request in server.requests if request[1] == "/b2api/v4/b2_authorize_account"]
                assert len(auth) == (2 if scenario == "warm_hit" else 1 if ready_at_start or scenario == "failed_b2_fallback_hit" else 0), server.requests
                print(f"PASS cache telemetry {scenario}", flush=True)
    finally:
        server.shutdown()
        thread.join()
if failures:
    raise RuntimeError("\n".join(failures))
