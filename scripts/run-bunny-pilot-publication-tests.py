#!/usr/bin/env python3
"""Exercise Bunny publication with synthetic policy, storage, and CDN backends."""

from base64 import b64encode
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import threading
from urllib.parse import parse_qs, urlsplit


BODY = b"abc"
HASH = hashlib.sha256(BODY).hexdigest()
OWNER = "b" * 64
BUCKET = "fixture-bucket"
BUCKET_ID = "fixture-bucket-id"
PREFIX = "bunny-delivery/"
CDN_HOSTS = ("media-bunny.divine.video", "fixture-pilot.b-cdn.net")
B2_API_HOST = "api.backblazeb2.com"
KV_BASE = "/resources/stores/kv/fixture-store/keys/"
CASES = ("active", "active_rendition", "pending", "age_restricted", "checksum_mismatch",
         "age_gate_after_put", "appeal", "unverified_retry", "rejected_put", "uncertain_put",
         "disabled", "webhook_token")
SECRETS = {
    "admin_token": "fixture-admin",
    "webhook_secret": "fixture-webhook",
    "b2_media_access_key": "fixture-reader-id",
    "b2_media_secret_key": "fixture-reader-key",
    "bunny_b2_publish_key_id": "fixture-writer-id",
    "bunny_b2_publish_key": "fixture-writer-key",
    "b2_vanish_application_key_id": "fixture-eraser-id",
    "b2_vanish_application_key": "fixture-eraser-key",
    "bunny_api_key": "fixture-purge",
    "fastly_api_token": "fixture-fastly-purge",
    "kv_origin_read_token": "fixture-policy-reader",
}


def basic(key_type):
    plain = f"fixture-{key_type}-id:fixture-{key_type}-key".encode()
    return f"Basic {b64encode(plain).decode()}"


class Origin(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, status, body=b"", headers=None):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def reply_json(self, value, headers=None):
        self.reply(200, json.dumps(value).encode(), {"Content-Type": "application/json", **(headers or {})})

    def read_body(self):
        return self.rfile.read(int(self.headers.get("Content-Length", "0")))

    def do_GET(self):
        if self.path.startswith(KV_BASE):
            assert self.headers.get("Fastly-Key") == SECRETS["kv_origin_read_token"]
            key = self.path.removeprefix(KV_BASE)
            if key == "bunny-pilot-retained-hosts:v1":
                return self.reply(200, ",".join(CDN_HOSTS).encode(), {"generation": "1"})
            if key == f"bunny-pilot-enrolled:v1:{HASH}":
                return self.reply(200, b"1", {"generation": "1"})
            if key != f"blob:{HASH}":
                assert key in {f"tombstone:{HASH}", f"quarantine:v1:{HASH}", f"refs:{HASH}",
                               f"vanish_in_progress:v1:{OWNER}"}, key
                return self.reply(404)
            status = self.server.policy_status
            if self.server.case == "age_gate_after_put" and self.server.delivered is not None:
                status = "age_restricted"
            self.server.events.append(("policy", status))
            return self.reply_json({
                "sha256": HASH,
                "size": len(BODY),
                "type": "video/quicktime" if self.server.case == "active_rendition" else "video/mp4",
                "uploaded": "2026-01-01T00:00:00Z",
                "owner": OWNER,
                "status": status,
            }, {"generation": "1"})

        if self.path == "/b2api/v4/b2_authorize_account":
            is_writer = self.headers.get("Authorization") == basic("writer")
            assert is_writer or self.headers.get("Authorization") == basic("eraser")
            return self.reply_json({"authorizationToken": "fixture-native-token", "apiInfo": {"storageApi": {
                "apiUrl": f"https://{B2_API_HOST}",
                "allowed": {"buckets": [{"id": BUCKET_ID, "name": BUCKET}],
                            "namePrefix": PREFIX if is_writer else None,
                            "capabilities": ["writeFiles"] if is_writer else ["listFiles", "deleteFiles"]},
            }}})

        assert "Credential=fixture-reader-id/" in self.headers.get("Authorization", "")
        self.server.events.append(("read", self.path))
        if self.path == f"/{BUCKET}/{self.server.source_key}":
            body = b"wrong bytes" if self.server.case == "checksum_mismatch" else BODY
        else:
            assert self.path == f"/{BUCKET}/{self.server.delivery_key}", self.path
            body = self.server.delivered
            if self.server.case == "unverified_retry" and body is not None:
                return self.reply(503)
        if body is None:
            return self.reply(404)
        return self.reply(200, body, {"Content-Type": "video/mp4"})

    def do_PUT(self):
        assert self.path == f"/{BUCKET}/{self.server.delivery_key}"
        assert "Credential=fixture-writer-id/" in self.headers.get("Authorization", "")
        assert self.headers.get("x-amz-content-sha256") == HASH
        assert self.headers.get("Content-Type") == "video/mp4"
        body = self.read_body()
        assert body == BODY
        assert self.server.delivered is None
        if self.server.case in ("rejected_put", "uncertain_put"):
            self.server.events.append(("rejected-put", self.path))
            return self.reply(403 if self.server.case == "rejected_put" else 503)
        self.server.events.append(("put", self.path))
        self.server.delivered = body
        self.reply(200)

    def do_POST(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/fixture/policy-status":
            assert self.server.case == "appeal"
            self.server.policy_status = self.read_body().decode()
            assert self.server.policy_status in ("active", "age_restricted")
            return self.reply(200)

        if parsed.path.startswith("/service/"):
            assert self.server.case in ("appeal", "unverified_retry")
            assert parsed.path.endswith("/purge")
            assert self.headers.get("Fastly-Key") == SECRETS["fastly_api_token"]
            assert self.headers.get("Surrogate-Key") == HASH
            return self.reply_json({HASH: "fixture-purge-id"})

        if parsed.path == "/purge":
            assert self.headers.get("AccessKey") == SECRETS["bunny_api_key"]
            target = parse_qs(parsed.query)["url"][0]
            assert target in {f"https://{host}/{HASH}*" for host in CDN_HOSTS}
            assert self.server.delivered is None, "Purge must follow replica deletion"
            self.server.events.append(("purge", target))
            if self.server.case == "unverified_retry" and sum(
                kind == "purge" for kind, _ in self.server.events
            ) <= 4:
                return self.reply(503)
            return self.reply(200)

        assert self.headers.get("Authorization") == "fixture-native-token"
        params = json.loads(self.read_body())
        if parsed.path == "/b2api/v4/b2_list_file_versions":
            assert params["bucketId"] == BUCKET_ID and params["prefix"] == f"{PREFIX}{HASH}"
            files = [] if self.server.delivered is None else [
                {"fileName": self.server.delivery_key, "fileId": "fixture-file-id"}]
            return self.reply_json({"files": files, "nextFileName": None, "nextFileId": None})

        assert parsed.path == "/b2api/v4/b2_delete_file_version", self.path
        assert params == {"fileName": self.server.delivery_key, "fileId": "fixture-file-id"}
        assert self.server.delivered is not None
        self.server.events.append(("delete", params["fileName"]))
        self.server.delivered = None
        self.reply_json({})


def assert_case(server, case):
    events = server.events
    actions = [name for name, _ in events]
    if case in ("active", "active_rendition"):
        assert actions.count("put") == 1 and server.delivered == BODY, events
        assert [status for name, status in events if name == "policy"] == ["active"] * 4, events
        assert not any(action in actions for action in ("delete", "purge")), events
    elif case == "age_gate_after_put":
        critical = [(name, value) for name, value in events if name != "read"]
        assert critical[:4] == [
            ("policy", "active"), ("put", f"/{BUCKET}/{server.delivery_key}"),
            ("policy", "age_restricted"), ("delete", server.delivery_key),
        ], events
        assert sorted(critical[4:]) == sorted(
            ("purge", f"https://{host}/{HASH}*") for host in CDN_HOSTS for _ in range(2)
        ), events
        assert server.delivered is None
    elif case == "appeal":
        assert actions.count("put") == 2 and actions.count("delete") == 1, events
        assert actions.index("put") < actions.index("delete"), events
        assert actions.index("delete") < len(actions) - 1 - actions[::-1].index("put"), events
        assert actions.count("purge") == 4 and server.delivered == BODY, events
    elif case == "unverified_retry":
        assert actions.count("put") == actions.count("delete") == 1, events
        assert actions.count("purge") == 8 and server.delivered is None, events
    elif case in ("rejected_put", "uncertain_put"):
        assert actions.count("rejected-put") == 1 and server.delivered is None, events
        assert "put" not in actions and "delete" not in actions and "purge" not in actions, events
    else:
        assert all(action in ("read", "policy") for action in actions), events
        assert server.delivered is None
        if case in ("disabled", "webhook_token"):
            assert not events
        if case in ("pending", "age_restricted"):
            assert [(name, value) for name, value in events if name == "policy"] == [("policy", case)], events


def run(server, repo, directory):
    settings, kv, config = (directory / name for name in ("settings.json", "kv.json", "fastly.toml"))
    dynamic_b2 = f"b2-api-{hashlib.sha256(B2_API_HOST.encode()).hexdigest()[:16]}"
    backend_names = ("b2_storage", "b2_api", "bunny_api", "kv-origin-api", dynamic_b2, "fastly_api", "fixture_control")
    backends = "\n".join(
        f'[local_server.backends."{name}"]\nurl = "http://127.0.0.1:{server.server_port}"'
        for name in backend_names
    )
    secrets = ", ".join(f'{{ key = "{key}", data = "{value}" }}' for key, value in SECRETS.items())
    config.write_text(f'''manifest_version = 3
name = "bunny-pilot-publication-fixture"
language = "rust"
{backends}
[local_server.kv_stores.blossom_metadata]
file = "{kv}"
format = "json"
[local_server.config_stores.blossom_config]
file = "{settings}"
format = "json"
[local_server.secret_stores]
blossom_secrets = [{secrets}]
''')
    env = os.environ.copy()
    env["CARGO_TARGET_WASM32_WASIP1_RUNNER"] = shlex.join([
        env.get("VICEROY", "viceroy"), "run", "-C", str(config), "--",
    ])
    for case in CASES:
        server.case = case
        server.policy_status = case if case in ("pending", "age_restricted") else "active"
        server.source_key = f"{HASH}/hls/stream_720p.mp4" if case == "active_rendition" else HASH
        server.delivery_key = f"{PREFIX}{HASH}/720p.mp4" if case == "active_rendition" else f"{PREFIX}{HASH}"
        server.delivered = None
        server.events = []
        kv.write_text("{}")
        settings.write_text(json.dumps({
            "bunny_fixture_case": case,
            "bunny_fixture_local_gate": "true",
            "bunny_pilot_publish_enabled": "false" if case == "disabled" else "true",
            "bunny_pilot_zone_hosts": ",".join(CDN_HOSTS),
            "b2_replica_enabled": "true",
            "b2_bucket_id": BUCKET_ID,
            "b2_media_bucket": BUCKET,
            "b2_media_region": "us-west-004",
            "metadata_kv_store_id": "fixture-store",
        }))
        result = subprocess.run([
            "cargo", "test", "--locked", "--target", "wasm32-wasip1", "--bin", "fastly-blossom",
            "bunny_publication_respects_authoritative_policy_and_releases_clean_attempts",
            "--", "--ignored", "--nocapture",
        ], cwd=repo, env=env, capture_output=True, text=True, timeout=240)
        if result.returncode or "test result: ok. 1 passed" not in result.stdout:
            raise RuntimeError(f"{case}: {result.stdout}{result.stderr}\nFixture events: {server.events}")
        assert_case(server, case)
        print(f"PASS {case}")


def main():
    repo = Path(__file__).resolve().parent.parent
    with ThreadingHTTPServer(("127.0.0.1", 0), Origin) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory(prefix="bunny-pilot-publication-") as directory:
                run(server, repo, Path(directory))
        finally:
            server.shutdown()


if __name__ == "__main__":
    main()
