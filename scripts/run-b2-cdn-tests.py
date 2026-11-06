#!/usr/bin/env python3
"""Run real Compute CDN route/admission against synthetic private B2/GCS only."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shlex
import tempfile
import threading
from http.server import ThreadingHTTPServer

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("canary_fixture", ROOT / "scripts/run-b2-canary-tests.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
HASH, OWNER, VERSION = fixture.HASH, fixture.OWNER, fixture.VERSION
HOST = "media-b2-cdn.divine.video"
ORIGIN = "synthetic.edgecompute.app"


def main():
    with ThreadingHTTPServer(("127.0.0.1", 0), fixture.Origin) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory(prefix="b2-cdn-tests-") as directory:
                root = Path(directory)
                settings, kv, manifest = root / "settings.json", root / "kv.json", root / "fastly.toml"
                manifest.write_text(f'''manifest_version = 3
name = "b2-cdn-test"
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
blossom_secrets = [{{key="fastly_api_token",data="synthetic"}},{{key="gcs_access_key",data="synthetic"}},{{key="gcs_secret_key",data="synthetic"}},{{key="b2_media_access_key",data="synthetic"}},{{key="b2_media_secret_key",data="synthetic"}},{{key="b2_vanish_application_key_id",data="synthetic"}},{{key="b2_vanish_application_key",data="synthetic"}}]
''')
                manifest_text = manifest.read_text()
                env = os.environ.copy()
                env["CARGO_TARGET_WASM32_WASIP1_RUNNER"] = shlex.join([env.get("VICEROY", "viceroy"), "run", "-C", str(manifest), "--"])
                base = dict(b2_cdn_enabled="true", b2_cdn_host=HOST, b2_cdn_origin_host=ORIGIN, b2_cdn_purge_hosts=HOST,
                            b2_canary_host="media-b2.divine.video", b2_replica_enabled="true",
                            b2_media_region="us-west-004", b2_media_bucket="private-test",
                            b2_bucket_id="synthetic-bucket-id", gcs_bucket="gcs-test",
                            test_forwarded=HOST, test_status="200", test_admitted="true",
                            test_source="b2", test_body="b2 bytes!")
                metadata = dict(sha256=HASH, size=9, type="video/mp4", uploaded="2026-01-01T00:00:00Z", owner=OWNER, status="active")
                ready = dict(version=1, sha256=HASH, verified_sha256=HASH, bucket="private-test", key=HASH, size=9, verified_at=1, destination_version_id=VERSION)
                cases = ["missing_purge", "missing_token", "wrong_purge", "forwarded", "head", "direct", "mp4_query", "disabled", "malformed_flag", "missing_host", "missing_origin", "unknown_origin", "unknown_forwarded", "mismatched_authority", "port", "authorization", "empty_authorization", "cookie", "empty_cookie", "upload", "admin", "derivative", "uppercase", "range", "gcs_fallback", "b2_missing_fallback", "wrong_version", "wrong_size", "native_auth", "restricted", "deleted", "vanish", "quarantine", "erasing", "copying", "missing_metadata", "forwarded_canary", "direct_canary", "configured_canary"]
                for case in cases:
                    if os.environ.get("B2_CDN_CASE") not in (None, case):
                        continue
                    values = copy.deepcopy(base)
                    data = {f"blob:{HASH}": copy.deepcopy(metadata), f"b2-ready:{HASH}": copy.deepcopy(ready)}
                    server.requests = []
                    server.bucket_name, server.bucket_id = "private-test", "synthetic-bucket-id"
                    server.status, server.version, server.auth_status = 200, VERSION, 200
                    server.gcs_status, server.gcs_size, server.range_mode = 200, 9, "normal"
                    if case == "head": values["test_method"] = "HEAD"; values["test_body"] = ""
                    if case in ("direct", "mp4_query", "port", "mismatched_authority"):
                        values.pop("test_forwarded")
                        values["test_url"] = f"https://{HOST}/{HASH}"
                    if case == "mp4_query": values["test_url"] += ".mp4?download=1&synthetic=1"
                    denied = case in ("missing_purge", "missing_token", "wrong_purge", "disabled", "malformed_flag", "missing_host", "missing_origin", "unknown_origin", "unknown_forwarded", "mismatched_authority", "port", "authorization", "empty_authorization", "cookie", "empty_cookie", "upload", "admin", "derivative", "uppercase", "restricted", "deleted", "vanish", "quarantine", "erasing", "missing_metadata", "forwarded_canary")
                    if denied: values.update(test_status="404", test_admitted="false")
                    manifest.write_text(manifest_text.replace('{key="fastly_api_token",data="synthetic"},', '') if case == "missing_token" else manifest_text)
                    if case == "missing_purge": values.pop("b2_cdn_purge_hosts")
                    if case == "wrong_purge": values["b2_cdn_purge_hosts"] = "media-b2.divine.video"
                    if case == "disabled": values.pop("b2_cdn_enabled")
                    if case == "malformed_flag": values["b2_cdn_enabled"] = "TRUE"
                    if case == "missing_host": values.pop("b2_cdn_host")
                    if case == "missing_origin": values.pop("b2_cdn_origin_host")
                    if case == "unknown_origin": values["test_url"] = f"https://other.edgecompute.app/{HASH}"
                    if case == "unknown_forwarded": values["test_url"] = f"https://{HOST}/{HASH}"; values["test_forwarded"] = "other.example"
                    if case == "mismatched_authority": values["test_host"] = ORIGIN
                    if case == "port": values["test_url"] = f"https://{HOST}:8443/{HASH}"
                    if case in ("authorization", "empty_authorization"): values["test_auth"] = "Bearer synthetic" if case == "authorization" else ""
                    if case in ("cookie", "empty_cookie"): values["test_cookie"] = "session=synthetic" if case == "cookie" else ""
                    if case in ("upload", "admin", "derivative", "uppercase"):
                        path = {"upload": "/upload", "admin": "/admin", "derivative": f"/{HASH}/720p", "uppercase": f"/{HASH.upper()}"}[case]
                        values["test_url"] = f"https://{ORIGIN}{path}"
                        if case == "upload": values["test_method"] = "PUT"
                    if case == "range": values.update(test_range="bytes=1-3", test_status="206", test_admitted="false", test_body="2 b")
                    if case in ("gcs_fallback", "b2_missing_fallback", "copying"):
                        values.update(test_source="gcs", test_body="gcsbytes!", test_admitted="false")
                        if case == "gcs_fallback": data.pop(f"b2-ready:{HASH}")
                        if case == "b2_missing_fallback": server.status = 404
                        if case == "copying": data[f"b2-sync:v1:{HASH}"] = dict(state="copying", attempt_id="synthetic")
                    if case in ("wrong_version", "wrong_size", "native_auth"):
                        values.update(test_status="502", test_admitted="false")
                        if case == "wrong_version": server.version = "unverified"
                        if case == "wrong_size": data[f"blob:{HASH}"]["size"] = 10; data[f"b2-ready:{HASH}"]["size"] = 10
                        if case == "native_auth": server.auth_status = 403
                    if case in ("restricted", "deleted"): data[f"blob:{HASH}"]["status"] = case
                    if case == "vanish": data[f"vanish_in_progress:v1:{OWNER}"] = {"timestamp": 1}
                    if case == "quarantine": data[f"quarantine:v1:{HASH}"] = {"version": 1, "holds": {"synthetic": {"version": 1, "active": True}}}
                    if case == "erasing": data[f"b2-sync:v1:{HASH}"] = {"state": "erasing"}
                    if case == "missing_metadata": data.pop(f"blob:{HASH}")
                    if case in ("forwarded_canary", "direct_canary", "configured_canary"):
                        values["test_forwarded"] = "media-b2.divine.video"
                        if case == "configured_canary": values["b2_cdn_host"] = "media-b2.divine.video"; values["b2_cdn_purge_hosts"] = "media-b2.divine.video"
                        if case == "direct_canary":
                            values.pop("test_forwarded")
                            values.update(test_url=f"https://media-b2.divine.video/{HASH}", test_admitted="false")
                    settings.write_text(json.dumps(values))
                    kv.write_text(json.dumps({k: json.dumps(v) for k, v in data.items()}))
                    fixture.run(ROOT, env, "production_cdn_endpoint_contract")
                    # Entry-point/auth/routing denials must never reach an origin.
                    if denied and case not in ("restricted", "deleted", "vanish", "quarantine", "erasing", "missing_metadata"):
                        assert not server.requests, (case, server.requests)
                    print(f"PASS B2 CDN {case}")
                    if case == "forwarded":
                        fixture.run(ROOT, env, "final_hold_cannot_refill_b2_cdn_after_prepared_origin_response")
                        print("PASS B2 CDN final hold blocks prepared origin response")
        finally:
            server.shutdown()


if __name__ == "__main__":
    main()
