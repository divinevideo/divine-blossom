#!/usr/bin/env python3
"""Exercise actual Compute policy, private-origin reads and erasure mutex."""
import copy
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HASH, OWNER, VERSION = "a" * 64, "b" * 64, "4_zSynthetic+version"
BODY = b"b2 bytes!"


class Origin(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        self.server.requests.append((self.command, self.path, self.headers.get("Range")))
        if self.path == "/b2api/v4/b2_authorize_account":
            assert self.headers.get("Authorization", "").startswith("Basic ")
            allowed = {"buckets": [{"id": self.server.bucket_id, "name": self.server.bucket_name}],
                       "capabilities": ["listFiles", "deleteFiles"], "namePrefix": None}
            body = json.dumps({"authorizationToken": "synthetic-token", "apiInfo": {"storageApi": {
                "apiUrl": "https://api.backblazeb2.com", "allowed": allowed}}}).encode()
            self.send_response(200)
        else:
            parsed = urlparse(self.path)
            assert parsed.path == f"/private-test/{HASH}", self.path
            assert parse_qs(parsed.query) == {"versionId": [VERSION]}, self.path
            assert "/us-west-004/s3/aws4_request" in self.headers.get("Authorization", "")
            assert self.headers.get("Host") == "s3.us-west-004.backblazeb2.com"
            status, body = self.server.status, BODY
            if self.headers.get("Range") == "bytes=99-":
                status, body = 416, b"range error"
            elif self.headers.get("Range"):
                status, body = 206, BODY[1:4]
            self.send_response(status)
            self.send_header("x-amz-version-id", self.server.version)
            if status == 206:
                self.send_header("Content-Range", "bytes 1-3/9")
            elif status == 416:
                self.send_header("Content-Range", "bytes */9")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


def run(repo, env, test):
    result = subprocess.run(["cargo", "test", "--locked", "--target", "wasm32-wasip1",
                             "--bin", "fastly-blossom", test, "--", "--ignored", "--nocapture"],
                            cwd=repo, env=env, text=True, capture_output=True, timeout=180)
    if result.returncode or "test result: ok. 1 passed; 0 failed; 0 ignored;" not in result.stdout:
        raise RuntimeError(result.stdout + result.stderr)


def main():
    repo = Path(__file__).resolve().parent.parent
    with ThreadingHTTPServer(("127.0.0.1", 0), Origin) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="b2-canary-test-") as directory:
                root = Path(directory)
                config, settings, kv = root / "fastly.toml", root / "settings.json", root / "kv.json"
                config.write_text(f'''manifest_version = 3
name = "b2-canary-test"
language = "rust"
[local_server.backends.b2_storage]
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
blossom_secrets = [{{key="b2_media_access_key",data="synthetic"}},{{key="b2_media_secret_key",data="synthetic"}},{{key="b2_vanish_application_key_id",data="synthetic"}},{{key="b2_vanish_application_key",data="synthetic"}}]
''')
                env = os.environ.copy()
                env["CARGO_TARGET_WASM32_WASIP1_RUNNER"] = shlex.join([
                    env.get("VICEROY", "viceroy"), "run", "-C", str(config), "--"])
                base = {"b2_canary_host": "media-b2.divine.video", "b2_replica_enabled": "true",
                        "b2_media_region": "us-west-004", "b2_media_bucket": "private-test",
                        "b2_bucket_id": "synthetic-bucket-id"}
                metadata = {"sha256": HASH, "size": 9, "type": "video/mp4",
                            "uploaded": "2026-01-01T00:00:00Z", "owner": OWNER, "status": "active"}
                ready = {"version": 1, "sha256": HASH, "verified_sha256": HASH,
                         "bucket": "private-test", "key": HASH, "size": 9,
                         "verified_at": 1, "destination_version_id": VERSION}
                cases = [("valid", 200), ("disabled", 404), ("pending", 404), ("restricted", 404),
                         ("banned", 404), ("deleted", 404), ("age_restricted", 404),
                         ("missing_metadata", 404), ("tombstone", 404), ("vanish_owner", 404),
                         ("vanish_ref", 404), ("copying", 404), ("erasing", 404),
                         ("missing_ready", 503), ("invalid_ready", 503), ("wrong_ready_bucket", 503),
                         ("wrong_ready_hash", 503), ("no_version", 503), ("erasure_disabled", 502),
                         ("wrong_erasure_name", 502), ("wrong_erasure_id", 502),
                         ("wrong_origin_version", 502), ("origin_missing", 503),
                         ("origin_forbidden", 502), ("origin_failed", 502)]
                for case, expected in cases:
                    server.requests = []
                    server.bucket_name, server.bucket_id = "private-test", "synthetic-bucket-id"
                    server.status, server.version = 200, VERSION
                    values, meta, readiness = copy.deepcopy(base), copy.deepcopy(metadata), copy.deepcopy(ready)
                    data = {f"blob:{HASH}": meta, f"b2-ready:{HASH}": readiness}
                    if case == "disabled":
                        del values["b2_canary_host"]
                    if case in ("pending", "restricted", "banned", "deleted", "age_restricted"):
                        meta["status"] = case
                    if case == "missing_metadata":
                        del data[f"blob:{HASH}"]
                    if case == "tombstone":
                        data[f"tombstone:{HASH}"] = {}
                    if case == "vanish_owner":
                        data[f"vanish_in_progress:v1:{OWNER}"] = {}
                    if case == "vanish_ref":
                        data[f"refs:{HASH}"] = ["c" * 64]
                        data[f"vanish_in_progress:v1:{'c' * 64}"] = {}
                    if case in ("copying", "erasing"):
                        data[f"b2-sync:v1:{HASH}"] = {"state": case}
                    if case == "missing_ready":
                        del data[f"b2-ready:{HASH}"]
                    if case == "invalid_ready":
                        data[f"b2-ready:{HASH}"] = "malformed"
                    if case == "wrong_ready_bucket":
                        readiness["bucket"] = "other"
                    if case == "wrong_ready_hash":
                        readiness["verified_sha256"] = "f" * 64
                    if case == "no_version":
                        readiness["destination_version_id"] = ""
                    if case == "erasure_disabled":
                        values["b2_replica_enabled"] = "false"
                    if case == "wrong_erasure_name":
                        server.bucket_name = "other"
                    if case == "wrong_erasure_id":
                        server.bucket_id = "other"
                    if case == "wrong_origin_version":
                        server.version = "unverified"
                    if case.startswith("origin_"):
                        server.status = {"origin_missing": 404, "origin_forbidden": 403, "origin_failed": 503}[case]
                    values["test_expected_status"] = str(expected)
                    settings.write_text(json.dumps(values))
                    kv.write_text(json.dumps({k: json.dumps(v) for k, v in data.items()}))
                    run(repo, env, "canary_endpoint_integration_contract")
                    storage = [r for r in server.requests if r[1].startswith("/private-test/")]
                    if case == "valid":
                        assert [r[0] for r in storage] == ["GET", "GET", "GET", "HEAD"], storage
                        assert storage[1][2] == "bytes=1-3"
                        assert len(server.requests) == 8, server.requests
                    elif case in ("wrong_origin_version", "origin_missing", "origin_forbidden", "origin_failed"):
                        assert len(storage) == 1, server.requests
                    else:
                        assert not storage, server.requests
                    print(f"PASS canary {case}")
                    if case == "valid":
                        server.requests = []
                        run(repo, env, "canary_revocation_bypasses_warm_metadata_and_readiness")
                        assert len(server.requests) == 2, server.requests
                        print("PASS live policy/readiness revocation bypass warm canonical metadata")
                kv.write_text("{}")
                run(repo, env, "canary_sync_erasure_mutex")
                print("PASS crashed copy blocks erasure and erasing blocks late copy")
        finally:
            server.shutdown()
            thread.join()


if __name__ == "__main__":
    main()
