#!/usr/bin/env python3
"""Exercise translated VTT routes using synthetic storage and transcoder backends."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SOURCE = b"WEBVTT\n\n00:00:00.000 --> 00:00:01.000\nOriginal\n"
REPAIRED = SOURCE.replace(b"Original", b"Repaired")
SECRET = "synthetic-translation-test-secret"


class Backend(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, status, body=b""):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        marker = path.split("/")[2][0]
        self.server.reads.append(path)
        if marker in "ab":
            return self.reply(404)
        if marker == "f":
            return self.reply(503)
        if path.endswith("/main.vtt"):
            source = SOURCE
            if marker == "c":
                self.server.source_reads += 1
                if self.server.source_reads > 1:
                    source = REPAIRED
            return self.reply(200, source)
        if marker == "c" and path.endswith(".vtt"):
            digest = hashlib.sha256(REPAIRED if self.server.source_reads > 1 else SOURCE).hexdigest()
            assert f"/translations/{digest}/pt-BR.vtt" in path, path
            text = b"Repaired translation" if self.server.source_reads > 1 else b"Original translation"
            return self.reply(200, b"WEBVTT\n\nNOTE\nMachine-translated\n\n00:00:00.000 --> 00:00:01.000\n" + text)
        if path.endswith(".json"):
            if marker == "d":
                return self.reply(200, json.dumps({"status": "failed", "code": "translation_rejected", "retry_at": None}).encode())
            if marker == "e":
                return self.reply(200, json.dumps({"status": "processing", "retry_at": 4102444800}).encode())
        self.reply(404)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.posts.append((self.path, body, self.headers.get("X-Divine-Translate-Secret")))
        self.reply(403 if body["hash"][0] == "2" else 200, b"{}")


def main():
    repo = Path(__file__).resolve().parent.parent
    with ThreadingHTTPServer(("127.0.0.1", 0), Backend) as server:
        server.reads, server.posts, server.source_reads = [], [], 0
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="subtitle-translation-") as directory:
                root = Path(directory)
                (root / "kv.json").write_text("{}")
                (root / "config.json").write_text(json.dumps({"gcs_bucket": "test", "local_mode": "false"}))
                config = root / "fastly.toml"
                config.write_text(f'''manifest_version = 3
name = "subtitle-translation-test"
language = "rust"
[local_server.backends.gcs_storage]
url = "http://127.0.0.1:{server.server_port}"
[local_server.backends.cloud_run_transcoder]
url = "http://127.0.0.1:{server.server_port}"
[local_server.kv_stores.blossom_metadata]
file = "{root / 'kv.json'}"
format = "json"
[local_server.config_stores.blossom_config]
file = "{root / 'config.json'}"
format = "json"
[local_server.secret_stores]
blossom_secrets = [{{ key = "gcs_access_key", data = "synthetic-key" }}, {{ key = "gcs_secret_key", data = "synthetic-secret" }}, {{ key = "translate_shared_secret", data = "{SECRET}" }}]
''')
                env = os.environ.copy()
                env["CARGO_TARGET_WASM32_WASIP1_RUNNER"] = shlex.join([env.get("VICEROY", "viceroy"), "run", "-C", str(config), "--"])
                result = subprocess.run(["cargo", "test", "--locked", "--target", "wasm32-wasip1", "--bin", "fastly-blossom", "subtitle_translation_routes", "--", "--ignored", "--nocapture"], cwd=repo, env=env, check=True, timeout=180, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                print(result.stdout, end="")
                if not re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", result.stdout):
                    raise RuntimeError("expected the subtitle routing test to execute")
                transcription = [body for path, body, _ in server.posts if path == "/transcribe"]
                translation = [(body, secret) for path, body, secret in server.posts if path == "/translate" and body["hash"][0] == "1"]
                rejected = [body for path, body, _ in server.posts if path == "/translate" and body["hash"][0] == "2"]
                assert len(rejected) == 1, server.posts
                assert not any(path.split("/")[2][0] == "3" for path in server.reads)
                assert len(transcription) == 1 and transcription[0]["hash"] == "a" * 64, server.posts
                assert len(translation) == 1, server.posts
                body, secret = translation[0]
                assert body == {"hash": "1" * 64, "source_digest": hashlib.sha256(SOURCE).hexdigest(), "lang": "pt-BR"}, body
                assert secret == SECRET
                assert not any("/translations/" in path for path in server.reads if path.split("/")[2][0] in "ab")
        finally:
            server.shutdown()
            thread.join()


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(error.stdout or "", end="")
        raise SystemExit(error.returncode)
