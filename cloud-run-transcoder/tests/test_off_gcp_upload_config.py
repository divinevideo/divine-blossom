"""Regression checks for off-GCP co-located upload Caddy and Compose config."""

import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest


OFF_GCP_DIR = Path(__file__).resolve().parents[1] / "deploy" / "off-gcp"
CADDYFILE = OFF_GCP_DIR / "Caddyfile"
UPLOAD_CADDYFILE = OFF_GCP_DIR / "Caddyfile.upload.example"
UPLOAD_COMPOSE = OFF_GCP_DIR / "docker-compose.upload.yml"
UPLOAD_ENV_EXAMPLE = OFF_GCP_DIR / ".env.upload.example"


class OffGcpUploadConfigTest(unittest.TestCase):
    def test_upload_caddyfile_wraps_proxy_and_fallback_in_handle_blocks(self) -> None:
        text = UPLOAD_CADDYFILE.read_text(encoding="utf-8")

        # Caddy 2 executes bare `respond` before `reverse_proxy`; both must live
        # inside `handle` blocks so the 404 fallback cannot shadow allowed routes.
        self.assertRegex(text, r"(?m)^\thandle @public_upload \{$")
        self.assertRegex(text, r"(?m)^\t\treverse_proxy upload:8080 \{$")
        self.assertRegex(text, r"(?m)^\thandle \{$")
        self.assertRegex(text, r"(?m)^\t\trespond 404$")
        self.assertNotRegex(text, r"(?m)^\trespond 404$")
        self.assertNotRegex(text, r"(?m)^\treverse_proxy @public_upload\b")

    def test_upload_caddyfile_allowlist_covers_public_routes_and_blocks_internal(self) -> None:
        text = UPLOAD_CADDYFILE.read_text(encoding="utf-8")
        cel_match = re.search(r"@public_upload <<CEL\n(.*?)\n\t\tCEL", text, re.DOTALL)
        self.assertIsNotNone(cel_match, "Expected @public_upload CEL block")
        cel = cel_match.group(1)

        for required in (
            "method('PUT', 'OPTIONS') && path('/upload', '/')",
            "method('GET', 'HEAD') && path('/')",
            "method('POST', 'OPTIONS') && path('/upload/init', '/transcribe', '/migrate')",
            "method('POST', 'OPTIONS') && path_regexp('^/upload/[^/]+/complete$')",
            "method('DELETE', 'OPTIONS') && path_regexp('^/upload/[^/]+$')",
            "method('PUT', 'HEAD', 'OPTIONS') && path_regexp('^/sessions/[^/]+$')",
            "method('GET', 'HEAD', 'OPTIONS') && path_regexp('^/thumbnail/[^/]+$')",
        ):
            self.assertIn(required, cel)

        self.assertNotIn("/audit", cel)
        self.assertNotIn("/metrics", cel)

    def test_upload_compose_decouples_caddy_and_preserves_env_file_tuning(self) -> None:
        text = UPLOAD_COMPOSE.read_text(encoding="utf-8")

        # Co-located upload health must never block Caddy / transcoder ingress.
        self.assertNotRegex(text, r"(?m)^  caddy:")
        self.assertNotIn("depends_on:", text)
        # Match divine-upload-server's 300s graceful shutdown drain window (GKE: 330s).
        self.assertRegex(text, r"(?m)^\s+stop_grace_period:\s+330s$")

        # Concurrency limits belong in .env.upload so they are not shadowed by
        # static compose `environment:` entries.
        env_block = text.split("environment:", 1)[1].split("volumes:", 1)[0]
        for key in (
            "MAX_CONCURRENT_UPLOADS",
            "MAX_CONCURRENT_THUMBNAILS",
            "THUMBNAIL_WAIT_SECS",
            "MAX_CONCURRENT_MIRRORS",
        ):
            self.assertNotIn(key, env_block)

    def test_upload_env_example_documents_parity_keys(self) -> None:
        text = UPLOAD_ENV_EXAMPLE.read_text(encoding="utf-8")
        for key in (
            "UPLOAD_BASE_URL=",
            "B2_MEDIA_BUCKET=",
            "MAX_CONCURRENT_THUMBNAILS=",
            "THUMBNAIL_WAIT_SECS=",
            "TRANSCRIBE_SHARED_SECRET=",
            "MIGRATION_NSEC=",
            "AI_DETECTOR_BASE_URL=",
            "MAX_UPLOAD_BYTES=",
            "MIRROR_FETCH_TIMEOUT_SECS=",
        ):
            self.assertIn(key, text)

        # TRANSCRIBER_URL must be explicitly set (not commented out) to an origin
        # that serves POST /transcribe/audio rather than falling back to the worker
        # Caddy vhost (which returns 404 for /transcribe/audio).
        transcriber_match = re.search(r"(?m)^TRANSCRIBER_URL=(\S+)$", text)
        self.assertIsNotNone(transcriber_match, "Expected active TRANSCRIBER_URL in .env.upload.example")
        self.assertNotIn("transcoder-worker.divine.video", transcriber_match.group(1))

    def test_caddy_adapt_orders_upload_proxy_before_404_fallback(self) -> None:
        caddy_bin = shutil.which("caddy")
        if caddy_bin is None:
            self.skipTest("caddy binary not installed in this environment")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            conf_d = tmp_path / "conf.d"
            conf_d.mkdir()

            base_text = CADDYFILE.read_text(encoding="utf-8").replace(
                "/etc/caddy/conf.d/*.caddy",
                f"{conf_d}/*.caddy",
            )
            test_caddyfile = tmp_path / "Caddyfile"
            test_caddyfile.write_text(base_text, encoding="utf-8")

            env = os.environ.copy()
            env.update(
                {
                    "TRANSCODER_DOMAIN": "transcoder-worker.example.test",
                    "UPLOAD_DOMAIN": "upload.example.test",
                    "TRANSCODE_ADMISSION_AUTH_REQUIRED": "true",
                    "TRANSCODE_ADMISSION_SECRET": "synthetic-secret",
                }
            )

            # 1. Transcoder-only host (empty conf.d/) must adapt cleanly.
            only_transcoder = subprocess.run(
                [caddy_bin, "adapt", "--config", str(test_caddyfile), "--adapter", "caddyfile"],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(only_transcoder.returncode, 0, only_transcoder.stderr)

            # 2. Co-located host with conf.d/upload.caddy must route upload:8080
            #    ahead of the 404 fallback inside a subroute for upload.example.test.
            (conf_d / "upload.caddy").write_text(
                UPLOAD_CADDYFILE.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            colocated = subprocess.run(
                [caddy_bin, "adapt", "--config", str(test_caddyfile), "--adapter", "caddyfile"],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(colocated.returncode, 0, colocated.stderr)

            adapted = json.loads(colocated.stdout)
            servers = adapted["apps"]["http"]["servers"]
            upload_route = None
            for server in servers.values():
                for route in server.get("routes", []):
                    for matcher in route.get("match", []):
                        if "upload.example.test" in matcher.get("host", []):
                            upload_route = route
                            break
            self.assertIsNotNone(upload_route, "upload.example.test host route missing")

            subroutes = upload_route["handle"][0]["routes"]
            self.assertEqual(len(subroutes), 2, f"Expected proxy + 404 subroutes, got: {subroutes}")

            first_handler = subroutes[0]["handle"][0]
            second_handler = subroutes[1]["handle"][0]
            self.assertEqual(first_handler["handler"], "subroute")
            proxy_handler = first_handler["routes"][0]["handle"][0]
            self.assertEqual(proxy_handler["handler"], "reverse_proxy")
            self.assertEqual(proxy_handler["upstreams"][0]["dial"], "upload:8080")
            self.assertEqual(proxy_handler["flush_interval"], -1)

            self.assertEqual(second_handler["handler"], "subroute")
            fallback_handler = second_handler["routes"][0]["handle"][0]
            self.assertEqual(fallback_handler["handler"], "static_response")
            self.assertEqual(fallback_handler["status_code"], 404)

    def test_caddy_live_loopback_enforces_upload_allowlist_and_blocks_worker_transcribe_audio(
        self,
    ) -> None:
        caddy_bin = shutil.which("caddy")
        if caddy_bin is None:
            self.skipTest("caddy binary not installed in this environment")

        recorded: list[tuple[str, str, str]] = []

        class StubUpstream(BaseHTTPRequestHandler):
            def log_message(self, *_args) -> None:
                pass

            def _ok(self, tag: str) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                recorded.append((tag, self.command, self.path))
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(f"upstream:{tag}".encode("utf-8"))

            def do_GET(self) -> None:
                self._ok(self.server.tag)

            def do_HEAD(self) -> None:
                self._ok(self.server.tag)

            def do_PUT(self) -> None:
                self._ok(self.server.tag)

            def do_POST(self) -> None:
                self._ok(self.server.tag)

            def do_DELETE(self) -> None:
                self._ok(self.server.tag)

            def do_OPTIONS(self) -> None:
                self._ok(self.server.tag)

        upload_server = ThreadingHTTPServer(("127.0.0.1", 0), StubUpstream)
        upload_server.tag = "upload"
        transcoder_server = ThreadingHTTPServer(("127.0.0.1", 0), StubUpstream)
        transcoder_server.tag = "transcoder"
        upload_thread = threading.Thread(target=upload_server.serve_forever, daemon=True)
        transcoder_thread = threading.Thread(target=transcoder_server.serve_forever, daemon=True)
        upload_thread.start()
        transcoder_thread.start()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            caddy_port = probe.getsockname()[1]

        proc = None
        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                conf_d = tmp_path / "conf.d"
                conf_d.mkdir()

                base_text = (
                    "{\n\tadmin off\n\tauto_https off\n}\n\n"
                    + CADDYFILE.read_text(encoding="utf-8")
                    .replace("/etc/caddy/conf.d/*.caddy", f"{conf_d}/*.caddy")
                    .replace("transcoder:8080", f"127.0.0.1:{transcoder_server.server_port}")
                )
                test_caddyfile = tmp_path / "Caddyfile"
                test_caddyfile.write_text(base_text, encoding="utf-8")

                upload_text = UPLOAD_CADDYFILE.read_text(encoding="utf-8").replace(
                    "upload:8080", f"127.0.0.1:{upload_server.server_port}"
                )
                (conf_d / "upload.caddy").write_text(upload_text, encoding="utf-8")

                env = os.environ.copy()
                env.update(
                    {
                        "TRANSCODER_DOMAIN": f"http://transcoder-worker.example.test:{caddy_port}",
                        "UPLOAD_DOMAIN": f"http://upload.example.test:{caddy_port}",
                        "TRANSCODE_ADMISSION_AUTH_REQUIRED": "true",
                        "TRANSCODE_ADMISSION_SECRET": "synthetic-secret",
                    }
                )

                proc = subprocess.Popen(
                    [caddy_bin, "run", "--config", str(test_caddyfile), "--adapter", "caddyfile"],
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )

                deadline = time.monotonic() + 10.0
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        _, err = proc.communicate(timeout=2)
                        self.fail(f"caddy exited early ({proc.returncode}): {err}")
                    try:
                        with socket.create_connection(("127.0.0.1", caddy_port), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.05)
                else:
                    self.fail("caddy did not open loopback port in time")

                def send(host: str, method: str, path: str) -> int:
                    conn = http.client.HTTPConnection("127.0.0.1", caddy_port, timeout=5)
                    try:
                        conn.request(method, path, headers={"Host": f"{host}:{caddy_port}"})
                        resp = conn.getresponse()
                        resp.read()
                        return resp.status
                    finally:
                        conn.close()

                allowed_upload = [
                    ("GET", "/"),
                    ("HEAD", "/"),
                    ("PUT", "/"),
                    ("OPTIONS", "/"),
                    ("PUT", "/upload"),
                    ("OPTIONS", "/upload"),
                    ("POST", "/upload/init"),
                    ("OPTIONS", "/upload/init"),
                    ("POST", "/transcribe"),
                    ("OPTIONS", "/transcribe"),
                    ("POST", "/migrate"),
                    ("OPTIONS", "/migrate"),
                    ("POST", "/upload/sess-1/complete"),
                    ("OPTIONS", "/upload/sess-1/complete"),
                    ("DELETE", "/upload/sess-1"),
                    ("OPTIONS", "/upload/sess-1"),
                    ("PUT", "/sessions/sess-1"),
                    ("HEAD", "/sessions/sess-1"),
                    ("OPTIONS", "/sessions/sess-1"),
                    ("GET", "/thumbnail/abc123"),
                    ("HEAD", "/thumbnail/abc123"),
                    ("OPTIONS", "/thumbnail/abc123"),
                ]
                for method, path in allowed_upload:
                    recorded.clear()
                    status = send("upload.example.test", method, path)
                    self.assertEqual(status, 200, f"Expected 200 for {method} {path}")
                    self.assertEqual(
                        recorded,
                        [("upload", method, path)],
                        f"Expected {method} {path} to reach upload upstream",
                    )

                blocked_upload = [
                    ("POST", "/audit"),
                    ("GET", "/metrics"),
                    ("GET", "/upload"),
                    ("HEAD", "/upload"),
                    ("DELETE", "/upload/sess-1/extra"),
                    ("GET", "/unknown"),
                ]
                for method, path in blocked_upload:
                    recorded.clear()
                    status = send("upload.example.test", method, path)
                    self.assertEqual(status, 404, f"Expected 404 for {method} {path}")
                    self.assertEqual(recorded, [], f"Blocked route {method} {path} hit upstream")

                # Worker vhost intentionally returns 404 for /transcribe/audio, proving
                # why upload's TRANSCRIBER_URL must not fall back to transcoder-worker.
                recorded.clear()
                self.assertEqual(
                    send("transcoder-worker.example.test", "POST", "/transcribe/audio"),
                    404,
                )
                self.assertEqual(recorded, [])
        finally:
            if proc is not None:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
                if proc.stdout is not None:
                    proc.stdout.close()
                if proc.stderr is not None:
                    proc.stderr.close()
            upload_server.shutdown()
            upload_server.server_close()
            transcoder_server.shutdown()
            transcoder_server.server_close()


if __name__ == "__main__":
    unittest.main()
