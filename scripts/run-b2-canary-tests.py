#!/usr/bin/env python3
"""Exercise actual Compute policy, private-origin reads and erasure mutex."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HASH, OWNER, VERSION = "a" * 64, "b" * 64, "4_zSynthetic+version"
BODY = b"b2 bytes!"


class Origin(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        # No all-version listing/deletion may start while a copy lock exists.
        self.server.requests.append((self.command, self.path, None))
        self.send_response(500)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self.server.requests.append((self.command, self.path, self.headers.get("Range")))
        if self.path == "/b2api/v4/b2_authorize_account":
            assert self.headers.get("Authorization", "").startswith("Basic ")
            if self.server.auth_status == "disconnect":
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            if self.server.auth_status == "slow":
                time.sleep(3.5)
            allowed = {"buckets": [{"id": self.server.bucket_id, "name": self.server.bucket_name}],
                       "capabilities": ["listFiles", "deleteFiles"], "namePrefix": None}
            body = json.dumps({"authorizationToken": "synthetic-token", "apiInfo": {"storageApi": {
                "apiUrl": "https://api.backblazeb2.com", "allowed": allowed}}}).encode()
            if self.server.auth_status == "malformed":
                body = b"invalid authorization JSON"
            self.send_response(self.server.auth_status if isinstance(self.server.auth_status, int) else 200)
        else:
            parsed = urlparse(self.path)
            current_hash = getattr(self.server, "hash", HASH)
            is_gcs = parsed.path == f"/gcs-test/{current_hash}"
            assert is_gcs or parsed.path == f"/private-test/{current_hash}", self.path
            assert parse_qs(parsed.query) == ({} if is_gcs else {"versionId": [VERSION]}), self.path
            assert ("/auto/s3/aws4_request" if is_gcs else "/us-west-004/s3/aws4_request") in self.headers.get("Authorization", "")
            assert self.headers.get("Host") == ("storage.googleapis.com" if is_gcs else "s3.us-west-004.backblazeb2.com")
            if not is_gcs and self.server.status == "disconnect":
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            status, body = (self.server.gcs_status, b"gcsbytes!") if is_gcs else (self.server.status, BODY)
            if getattr(self.server, "body_override", None) is not None:
                body = self.server.body_override
            if status == "slow":
                time.sleep(3.5)
                status = 200
            content_range = "bytes 1-3/9"
            requested = self.headers.get("Range", "")
            # Real B2 returns 500 when a range component exceeds signed i64.
            overflow = any(int(part) > 2**63 - 1 for part in requested.removeprefix("bytes=").split("-") if part.isdigit())
            if overflow and not is_gcs:
                status, body = 500, b"provider range overflow"
            elif requested in ("bytes=99-", "bytes=9-") or self.server.range_mode == "force":
                status, body = 416, b"range error"
            elif requested == "bytes=0-8":
                status, content_range = 206, "bytes 0-8/9"
            elif requested in ("bytes=4-", "bytes=4-8"):
                status, body, content_range = 206, body[4:], "bytes 4-8/9"
            elif requested in ("bytes=-3", "bytes=6-8"):
                status, body, content_range = 206, body[-3:], "bytes 6-8/9"
            elif self.headers.get("Range"):
                status, body = 206, body[1:4]
            version = self.server.version
            if getattr(self.server, "wrong_version_once", False):
                self.server.wrong_version_once = False
                version = "unverified-version"
            self.send_response(status)
            self.send_header("x-amz-version-id", version)
            if status == 206:
                self.send_header("Content-Range", content_range)
            elif status == 416 and self.server.range_mode != "missing":
                self.send_header("Content-Range", "bytes */10" if self.server.range_mode == "wrong" else "bytes */9")
        self.send_header("Content-Length", str(self.server.gcs_size if self.path.startswith("/gcs-test/") and self.command == "HEAD" else len(body)))
        self.end_headers()
        if self.command != "HEAD":
            if self.path == "/b2api/v4/b2_authorize_account" and self.server.auth_status == "slow_body":
                time.sleep(3.5)
            try:
                if self.path != "/b2api/v4/b2_authorize_account" and getattr(self.server, "slow_body_once", False):
                    self.server.slow_body_once = False
                    self.wfile.write(body[:3])
                    self.wfile.flush()
                    time.sleep(3.5)
                    self.wfile.write(body[3:])
                else:
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass


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
                manifest = config.read_text()
                env = os.environ.copy()
                env["CARGO_TARGET_WASM32_WASIP1_RUNNER"] = shlex.join([
                    env.get("VICEROY", "viceroy"), "run", "-C", str(config), "--"])
                base = {"b2_canary_host": "media-b2.divine.video", "b2_replica_enabled": "true",
                        "b2_media_region": "us-west-004", "b2_media_bucket": "private-test",
                        "b2_bucket_id": "synthetic-bucket-id", "gcs_bucket": "gcs-test"}
                metadata = {"sha256": HASH, "size": 9, "type": "video/mp4",
                            "uploaded": "2026-01-01T00:00:00Z", "owner": OWNER, "status": "active"}
                ready = {"version": 1, "sha256": HASH, "verified_sha256": HASH,
                         "bucket": "private-test", "key": HASH, "size": 9,
                         "verified_at": 1, "destination_version_id": VERSION}
                cases = [("flag_off", 503), ("flag_malformed", 503), ("auth429", 502), ("auth_disconnect", 502),
                         ("cache_flag_strict", 200),
                         ("range_overflow_open", 416), ("range_overflow_end", 206), ("range_overflow_suffix", 206),
                         ("range_missing", 416), ("range_wrong", 502), ("range_satisfiable", 502),
                         ("range_malformed", 502), ("range_multiple", 502),
                         ("valid", 200), ("disabled", 404), ("pending", 200),
                         ("pending_missing_ready", 503), ("pending_quarantine", 404),
                         ("pending_tombstone", 404), ("pending_vanish_ref", 404),
                         ("pending_erasing", 404), ("restricted", 404),
                         ("banned", 404), ("deleted", 404), ("age_restricted", 404),
                         ("missing_metadata", 404), ("tombstone", 404), ("vanish_owner", 404),
                         ("vanish_ref", 404), ("copying", 503), ("copying_restricted", 404), ("malformed_gate", 404), ("erasing", 404),
                         ("missing_ready", 503), ("invalid_ready", 503), ("wrong_ready_bucket", 503),
                         ("wrong_ready_hash", 503), ("no_version", 503), ("erasure_disabled", 502),
                         ("wrong_erasure_name", 502), ("wrong_erasure_id", 502),
                         ("missing_region", 502), ("missing_read_bucket", 502), ("missing_backend", 502), ("erasure_auth_failed", 502),
                         ("wrong_origin_version", 502), ("origin_missing", 503),
                         ("origin_forbidden", 502), ("origin_unauthorized", 502), ("origin_failed", 503), ("origin_disconnect", 503)]
                demand_cases = [("demand_b2_416_missing", 416), ("demand_gcs_416_missing", 416),
                                ("demand_cached_b2", 200), ("demand_cached_gcs", 200),
                                ("demand_cached_wrong_version_b2", 200), ("demand_cached_timeout_b2", 200),
                                ("demand_cached_large_b2", 200),
                                ("demand_b2_overflow_open", 416), ("demand_b2_overflow_end", 206), ("demand_b2_overflow_suffix", 206),
                                ("demand_b2_416_wrong", 502), ("demand_gcs_416_wrong", 502),
                                ("demand_b2_416_satisfiable", 502), ("demand_gcs_416_satisfiable", 502),
                                ("demand_b2_416_malformed", 502), ("demand_gcs_416_malformed", 502),
                                ("demand_b2_416_multiple", 502), ("demand_gcs_416_multiple", 502),
                                ("demand_pending", 200), ("demand_pending_missing_ready", 200),
                                ("demand_pending_quarantine", 404), ("demand_pending_tombstone", 404),
                                ("demand_pending_vanish_ref", 404), ("demand_pending_erasing", 404),
                                ("demand_auth503", 200), ("demand_auth429", 200),
                                ("demand_auth_disconnect", 200), ("demand_auth_slow", 200),
                                ("demand_auth_slow_body", 200), ("demand_auth401", 502),
                                ("demand_auth403", 502), ("demand_auth_malformed", 502),
                                ("demand_missing_ready", 200), ("demand_origin_missing", 200),
                                ("demand_origin_gone", 200), ("demand_origin_failed", 200),
                                ("demand_origin_disconnect", 200), ("demand_origin_rate", 200), ("demand_origin_slow", 200),
                                ("demand_invalid_ready", 502), ("demand_wrong_ready_bucket", 502),
                                ("demand_wrong_origin_version", 502), ("demand_erasure_disabled", 502),
                                ("demand_copying", 200), ("demand_erasing", 404),
                                ("demand_oversized", 200), ("demand_missing_ready_head", 200),
                                ("demand_missing_ready_range", 206), ("demand_missing_ready_416", 416),
                                ("demand_gcs_missing", 404), ("demand_gcs_failed", 503),
                                ("demand_gcs_forbidden", 502), ("demand_dedup", 200),
                                ("demand_fanout", 404), ("demand_max_fanout", 200), ("demand_max_fanout_fallback", 200),
                                ("demand_valid", 200), ("demand_b2_head", 200),
                                ("demand_b2_open", 206), ("demand_b2_suffix", 206),
                                ("demand_b2_416", 416), ("demand_multiple", 200),
                                ("demand_malformed", 200), ("demand_origin_forbidden", 502),
                                ("demand_origin_unauthorized", 502), ("demand_missing_backend", 502),
                                ("demand_wrong_erasure_name", 502), ("demand_wrong_erasure_id", 502),
                                ("demand_quarantine", 404)]
                server.bucket_name, server.bucket_id = "private-test", "synthetic-bucket-id"
                server.status, server.version, server.auth_status = 200, VERSION, 200
                server.gcs_status, server.gcs_size, server.range_mode = 200, 9, "normal"
                selected = os.environ.get("B2_CANARY_CASE")
                for original_case, expected in cases + demand_cases:
                    if selected and selected != original_case:
                        continue
                    demand = original_case.startswith("demand_")
                    case = original_case.removeprefix("demand_")
                    if case == "cache_flag_strict":
                        case = "valid"
                    if original_case.startswith("demand_cached_"):
                        case = "valid" if original_case.endswith("_b2") else "missing_ready"
                    case = "missing_ready" if case in ("flag_off", "flag_malformed") else case
                    case = "origin_missing" if original_case == "demand_max_fanout_fallback" else case
                    case = "missing_ready" if case.startswith("gcs_416_") else case
                    case = "valid" if case.startswith("b2_") or case in ("multiple", "malformed") else case
                    case = "missing_ready" if case in ("max_fanout","missing_ready_head", "missing_ready_range", "missing_ready_416", "gcs_missing", "gcs_failed", "gcs_forbidden", "dedup") else case
                    server.requests = []
                    server.bucket_name, server.bucket_id = "private-test", "synthetic-bucket-id"
                    server.status, server.version, server.auth_status = 200, VERSION, 200
                    server.gcs_status, server.gcs_size, server.range_mode = 200, 9, "normal"
                    server.wrong_version_once = original_case == "demand_cached_wrong_version_b2"
                    server.slow_body_once = original_case == "demand_cached_timeout_b2"
                    server.body_override = None
                    values, meta, readiness = copy.deepcopy(base), copy.deepcopy(metadata), copy.deepcopy(ready)
                    data = {f"blob:{HASH}": meta, f"b2-ready:{HASH}": readiness}
                    if original_case == "cache_flag_strict":
                        values["b2_canary_cache_enabled"] = "true"
                    if original_case in ("flag_off", "flag_malformed"):
                        values["b2_demand_mirror_enabled"] = "false" if original_case == "flag_off" else "TRUE"
                    if demand:
                        values["b2_demand_mirror_enabled"] = "true"
                        if original_case.startswith("demand_cached_"):
                            values["b2_canary_cache_enabled"] = "true"
                        values["media_read_primary"] = "b2"
                        values["fos_read_enabled"] = "true"
                        values["test_source"] = "b2" if case in ("valid", "pending") else "gcs"
                        values["test_body"] = "b2 bytes!" if case in ("valid", "pending") else "gcsbytes!"
                        if original_case == "demand_max_fanout_fallback":
                            data[f"refs:{HASH}"] = [f"{i:064x}" for i in range(16)]
                        if original_case == "demand_max_fanout":
                            data[f"refs:{HASH}"] = [f"{i:064x}" for i in range(16)]
                            values["test_hint"] = "missing_readiness"
                        if original_case == "demand_quarantine":
                            data[f"quarantine:v1:{HASH}"] = {"version": 1, "holds": {"review": {"version": 1, "active": True}}}
                        if original_case == "demand_b2_open":
                            values["test_range"], values["test_body"] = "bytes=4-", "ytes!"
                        if original_case == "demand_b2_suffix":
                            values["test_range"], values["test_body"] = "bytes=-3", "es!"
                        if original_case == "demand_multiple":
                            values["test_range"] = "bytes=0-1,3-4"
                        if original_case == "demand_malformed":
                            values["test_range"] = "invalid"
                        if original_case in ("demand_missing_ready", "demand_missing_ready_head", "demand_missing_ready_range"):
                            values["test_hint"] = "missing_readiness"
                        if case in ("origin_missing", "origin_gone"):
                            values["test_hint"] = "missing_version"
                        if original_case.endswith("_head"):
                            values["test_method"], values["test_body"] = "HEAD", ""
                        if original_case.endswith("_range"):
                            values["test_range"], values["test_body"] = "bytes=1-3", "csb"
                        if original_case.endswith("_416"):
                            values["test_range"] = "bytes=99-"
                        if case == "oversized":
                            meta["size"] = server.gcs_size = 67108865
                            values["test_method"], values["test_body"] = "HEAD", ""
                        if case == "fanout":
                            data[f"refs:{HASH}"] = [f"{i:064x}" for i in range(17)]
                        if original_case == "demand_dedup":
                            data[f"b2-demand:v1:{HASH}"] = {"version": 1, "sha256": HASH, "reason": "missing_version", "observed_destination_version_id": VERSION}
                            values["test_hint"] = "missing_version"
                        if original_case in ("demand_gcs_missing", "demand_gcs_failed", "demand_gcs_forbidden"):
                            server.gcs_status = {"demand_gcs_missing": 404, "demand_gcs_failed": 503, "demand_gcs_forbidden": 403}[original_case]
                    range_case = original_case if original_case.startswith("range_") else original_case.split("_416_", 1)[1] if "_416_" in original_case else None
                    if range_case is not None and "overflow" not in range_case:
                        variant = range_case.removeprefix("range_")
                        values["test_range"] = {"missing": "bytes=99-", "wrong": "bytes=99-", "satisfiable": "bytes=1-3", "malformed": "invalid", "multiple": "bytes=99-,1-2"}[variant]
                        server.range_mode = variant if variant in ("missing", "wrong") else "force"
                    if "_overflow_" in original_case:
                        variant = original_case.rsplit("_", 1)[1]
                        values["test_range"] = {"open": "bytes=9223372036854775808-", "end": "bytes=0-18446744073709551615", "suffix": "bytes=-18446744073709551615"}[variant]
                        values["test_body"] = BODY.decode()
                        values["test_source"] = "b2"
                    if original_case == "demand_pending_missing_ready":
                        values["test_hint"] = "missing_readiness"
                    if case == "disabled":
                        del values["b2_canary_host"]
                    if case in ("pending", "restricted", "banned", "deleted", "age_restricted"):
                        meta["status"] = case
                    if case.startswith("pending_"):
                        meta["status"] = "pending"
                    if case == "pending_quarantine":
                        data[f"quarantine:v1:{HASH}"] = {
                            "version": 1, "holds": {"review:synthetic": {"version": 1, "active": True}}}
                    if case == "missing_metadata":
                        del data[f"blob:{HASH}"]
                    if case in ("tombstone", "pending_tombstone"):
                        data[f"tombstone:{HASH}"] = {}
                    if case == "vanish_owner":
                        data[f"vanish_in_progress:v1:{OWNER}"] = {}
                    if case in ("vanish_ref", "pending_vanish_ref"):
                        data[f"refs:{HASH}"] = ["c" * 64]
                        data[f"vanish_in_progress:v1:{'c' * 64}"] = {}
                    if case in ("copying", "copying_restricted"):
                        data[f"b2-sync:v1:{HASH}"] = {"state": "copying", "attempt_id": "synthetic"}
                    if case == "copying_restricted":
                        meta["status"] = "restricted"
                    if case in ("erasing", "pending_erasing"):
                        data[f"b2-sync:v1:{HASH}"] = {"state": "erasing"}
                    if case == "malformed_gate":
                        data[f"b2-sync:v1:{HASH}"] = {"state": "copying"}
                    if case in ("missing_ready", "pending_missing_ready"):
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
                    if case == "missing_region":
                        del values["b2_media_region"]
                    if case == "missing_read_bucket":
                        del values["b2_media_bucket"]
                    if case.startswith("auth"):
                        server.auth_status = {"auth503": 503, "auth429": 429, "auth401": 401, "auth403": 403, "auth_disconnect": "disconnect", "auth_slow": "slow", "auth_slow_body": "slow_body", "auth_malformed": "malformed"}[case]
                    if case == "erasure_auth_failed":
                        server.auth_status = 503
                    if case == "wrong_origin_version":
                        server.version = "unverified"
                    if case.startswith("origin_"):
                        server.status = {"origin_missing": 404, "origin_gone": 410, "origin_rate": 429, "origin_slow": "slow", "origin_forbidden": 403, "origin_unauthorized": 401, "origin_failed": 503, "origin_disconnect": "disconnect"}[case]
                    config.write_text(manifest.replace(
                        f'[local_server.backends.b2_storage]\nurl = "http://127.0.0.1:{server.server_port}"\n', ""
                    ) if case == "missing_backend" else manifest)
                    values["test_expected_status"] = str(expected)
                    server.hash = HASH
                    if original_case.startswith("demand_cached_"):
                        payload = b'A' * (8 * 1024 * 1024) if "_large_" in original_case else values["test_body"].encode()
                        current_hash = hashlib.sha256(payload).hexdigest()
                        values["test_hash"] = current_hash
                        values["test_size"] = str(len(payload))
                        meta["size"] = len(payload)
                        values["test_cache_failure"] = "timeout" if "_timeout_" in original_case else "integrity"
                        meta["sha256"] = current_hash
                        readiness.update(sha256=current_hash, verified_sha256=current_hash, key=current_hash, size=len(payload))
                        data = {k.replace(HASH, current_hash): v for k, v in data.items()}
                        server.hash = current_hash
                        if "_large_" in original_case:
                            server.body_override = payload
                    settings.write_text(json.dumps(values))
                    kv.write_text(json.dumps({k: json.dumps(v) for k, v in data.items()}))
                    started = time.monotonic()
                    run(repo, env, "demand_cached_large_contract" if original_case == "demand_cached_large_b2" else "demand_cached_fill_failure_contract" if original_case in ("demand_cached_wrong_version_b2", "demand_cached_timeout_b2") else "demand_cached_playback_contract" if original_case.startswith("demand_cached_") else "demand_endpoint_contract" if demand or original_case.startswith("range_") else "canary_endpoint_integration_contract")
                    if original_case == "demand_origin_slow":
                        assert time.monotonic() - started < 8, "origin timeout exceeded request budget"
                    storage = [r for r in server.requests if r[1].startswith("/private-test/")]
                    if original_case.startswith("demand_cached_"):
                        origin = "/private-test/" if original_case.endswith("_b2") else "/gcs-test/"
                        reads = [r for r in server.requests if r[1].startswith(origin)]
                        assert [r[0] for r in reads] == (["GET"] if "_large_" in original_case else ["GET", "GET"]), server.requests
                        detail = "8MiB MISS/checksum then warm HEAD/range with one origin GET" if "_large_" in original_case else "buffer timeout preserves streaming and later fill" if "_timeout_" in original_case else "wrong version rejected, recovery MISS then HIT" if "_wrong_version_" in original_case else "warm GET/HEAD/range/416, purge and policy/erasure denial"
                        print(f"PASS {original_case} {detail}")
                        continue
                    if "_overflow_" in original_case:
                        expected_range = "bytes=9-" if original_case.endswith("_open") else "bytes=0-8"
                        assert len(storage) == 1 and storage[0][2] == expected_range, server.requests
                    if demand:
                        gcs = [r for r in server.requests if r[1].startswith("/gcs-test/")]
                        assert len(storage) <= 1 and len(gcs) <= 1, server.requests
                        if case in ("valid", "pending"):
                            assert not gcs and len(storage) == 1, server.requests
                        elif expected in (200, 206, 416, 503) or original_case.startswith("demand_gcs_"):
                            assert len(gcs) == 1, server.requests
                        else:
                            assert not gcs, server.requests
                        if original_case.endswith("_head"):
                            assert (storage if case == "valid" else gcs)[0][0] == "HEAD", server.requests
                        print(f"PASS {original_case}")
                        continue
                    if case in ("valid", "pending"):
                        assert [r[0] for r in storage] == ["GET", "GET", "GET", "HEAD"], storage
                        assert storage[1][2] == "bytes=1-3"
                        assert len(server.requests) == 8, server.requests
                    elif original_case.startswith("range_"):
                        assert len(storage) == 1, server.requests
                    elif case in ("wrong_origin_version", "origin_missing", "origin_forbidden", "origin_unauthorized", "origin_failed", "origin_disconnect"):
                        assert len(storage) == 1, server.requests
                    else:
                        assert not storage, server.requests
                    print(f"PASS canary {case}")
                    if case in ("origin_failed", "origin_disconnect"):
                        server.requests = []
                        run(repo, env, "canary_origin_outage_during_revocation_is_terminal")
                        assert len(server.requests) == 2, server.requests
                        print(f"PASS {case} with policy revoked during origin I/O remains terminal")
                    if case in ("valid", "pending"):
                        server.requests = []
                        run(repo, env, "canary_revocation_bypasses_warm_metadata_and_readiness")
                        assert len(server.requests) == 2, server.requests
                        print("PASS live policy/readiness revocation bypass warm canonical metadata")
                for phase, initial_policy in ([(phase, policy) for phase in ("b2", "gcs") for policy in ("active", "pending")] if selected in (None, "races") else []):
                    race_cases = [(change, 200) for change in ("restricted", "size", "type", "quarantine", "vanish", "erasing", "malformed_gate", "copying")]
                    race_cases += [("restricted", 503), ("restricted", 403)]
                    for change, origin_status in race_cases:
                        server.requests = []
                        server.status = origin_status if phase == "b2" else 200
                        server.gcs_status = origin_status if phase == "gcs" else 200
                        values = dict(base, b2_demand_mirror_enabled="true", test_revoke_phase=phase, test_revoke_change=change)
                        data = {f"blob:{HASH}": dict(metadata, status=initial_policy)}
                        if phase == "b2":
                            data[f"b2-ready:{HASH}"] = ready
                        settings.write_text(json.dumps(values))
                        kv.write_text(json.dumps({k: json.dumps(v) for k, v in data.items()}))
                        run(repo, env, "demand_revocation_after_each_origin_is_terminal")
                        b2_reads = [r for r in server.requests if r[1].startswith("/private-test/")]
                        gcs_reads = [r for r in server.requests if r[1].startswith("/gcs-test/")]
                        assert len(b2_reads) == (1 if phase == "b2" else 0), server.requests
                        assert len(gcs_reads) == (1 if phase == "gcs" or change == "copying" else 0), server.requests
                        print(f"PASS demand {initial_policy} {phase} {origin_status} then {change}")
                if selected in (None, "auth_races"):
                    for auth_status in (503, 429, "disconnect", "slow_body"):
                        server.requests = []
                        server.status, server.auth_status, server.gcs_status = 200, auth_status, 200
                        values = dict(base, b2_demand_mirror_enabled="true", test_revoke_phase="b2", test_revoke_change="restricted")
                        settings.write_text(json.dumps(values))
                        kv.write_text(json.dumps({f"blob:{HASH}": json.dumps(metadata), f"b2-ready:{HASH}": json.dumps(ready)}))
                        run(repo, env, "demand_revocation_after_each_origin_is_terminal")
                        assert server.requests == [("GET", "/b2api/v4/b2_authorize_account", None)], server.requests
                        print(f"PASS demand native auth {auth_status} then revocation denies fallback")
                    server.auth_status = 200
                if selected in (None, "deadline"):
                    settings.write_text(json.dumps(base))
                    kv.write_text(json.dumps({f"blob:{HASH}": json.dumps(metadata)}))
                    server.requests = []
                    run(repo, env, "demand_exhausted_deadline_starts_no_origin_request")
                    assert not server.requests, server.requests
                    print("PASS demand exhausted deadline starts no origin")
                if selected in (None, "cache_lookup"):
                    server.requests = []
                    config.write_text(manifest)
                    settings.write_text(json.dumps(base))
                    kv.write_text("{}")
                    run(repo, env, "cache_lookup_wait_is_bounded")
                    assert not server.requests, server.requests
                    print("PASS busy cache lookup times out to uncached origin without waiting for leader")
                kv.write_text("{}")
                server.hash = HASH
                server.auth_status = 200
                server.requests = []
                run(repo, env, "canary_sync_erasure_mutex")
                assert server.requests == [("GET", "/b2api/v4/b2_authorize_account", None)], server.requests
                print("PASS crashed copy blocks all-version erasure and erasing blocks late copy")
        finally:
            server.shutdown()
            thread.join()


if __name__ == "__main__":
    main()
