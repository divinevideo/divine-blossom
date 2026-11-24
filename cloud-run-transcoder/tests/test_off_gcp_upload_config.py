"""Regression checks for off-GCP co-located upload Caddy and Compose config."""

from __future__ import annotations

import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
OFF_GCP_DIR = Path(__file__).resolve().parents[1] / "deploy" / "off-gcp"
BASE_COMPOSE = OFF_GCP_DIR / "docker-compose.yml"
CADDYFILE = OFF_GCP_DIR / "Caddyfile"
UPLOAD_CADDYFILE = OFF_GCP_DIR / "Caddyfile.upload.example"
UPLOAD_COMPOSE = OFF_GCP_DIR / "docker-compose.upload.yml"
UPLOAD_ENV_EXAMPLE = OFF_GCP_DIR / ".env.upload.example"
GITIGNORE = REPO_ROOT / ".gitignore"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def _stop_process(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=5)
    if proc.stdout is not None:
        proc.stdout.close()
    if proc.stderr is not None:
        proc.stderr.close()


class OffGcpUploadConfigTest(unittest.TestCase):
    def _require_caddy_bin(self) -> str:
        caddy_bin = shutil.which("caddy")
        if caddy_bin is None:
            if os.environ.get("REQUIRE_CADDY_TESTS") == "1" or os.environ.get("CI"):
                self.fail("caddy binary is required in CI / when REQUIRE_CADDY_TESTS=1")
            self.skipTest("caddy binary not installed in this environment")
        return caddy_bin

    def test_upload_caddyfile_wraps_proxy_and_fallback_in_handle_blocks(self) -> None:
        text = UPLOAD_CADDYFILE.read_text(encoding="utf-8")

        # Caddy 2 executes bare `respond` before `reverse_proxy`; both must live
        # inside `handle` blocks so the 404 fallback cannot shadow allowed routes.
        self.assertRegex(text, r"(?m)^\thandle @public_upload \{$")
        self.assertRegex(text, r"(?m)^\t\trequest_body \{$")
        self.assertRegex(text, r"(?m)^\t\t\tmax_size 16MiB$")
        self.assertRegex(text, r"(?m)^\t\treverse_proxy upload:8080 \{$")
        self.assertRegex(text, r"(?m)^\thandle \{$")
        self.assertRegex(text, r"(?m)^\t\trespond 404$")
        self.assertNotRegex(text, r"(?m)^\trespond 404$")
        self.assertNotRegex(text, r"(?m)^\treverse_proxy @public_upload\b")
        # Do not encourage setting UPLOAD_DOMAIN in .env (recreates transcoder/caddy).
        self.assertNotIn("set UPLOAD_DOMAIN=", text)

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
        base_text = BASE_COMPOSE.read_text(encoding="utf-8")
        text = UPLOAD_COMPOSE.read_text(encoding="utf-8")

        # Base Caddy service must drain past the 910s upstream transcode timeout
        # and avoid unused UPLOAD_DOMAIN env plumbing.
        base_caddy = base_text.split("  caddy:", 1)[1].split("  transcoder:", 1)[0]
        grace_match = re.search(r"(?m)^\s+stop_grace_period:\s+(\d+)s$", base_caddy)
        self.assertIsNotNone(grace_match, "Expected stop_grace_period on caddy service")
        self.assertGreaterEqual(int(grace_match.group(1)), 910)
        self.assertNotIn("UPLOAD_DOMAIN", base_caddy)

        # Co-located upload health must never block Caddy / transcoder ingress.
        self.assertNotIn("depends_on:", text)
        self.assertNotRegex(text, r"(?m)^  transcoder:")
        # Match divine-upload-server's 300s graceful shutdown drain window (GKE: 330s).
        self.assertRegex(text, r"(?m)^\s+stop_grace_period:\s+330s$")

        # Back /tmp with a required bounded host scratch mount and sweep orphaned
        # dotfiles/spools on container start (never tmpfs or unbounded upload_tmp).
        self.assertNotIn("tmpfs:", text)
        self.assertNotIn("upload_tmp", text)
        self.assertIn("type: bind", text)
        self.assertIn(
            "source: ${UPLOAD_TMP_DIR:-/var/lib/divine-upload/scratch/tmp}", text
        )
        self.assertIn("target: /tmp", text)
        self.assertIn("create_host_path: false", text)
        self.assertIn(
            "find /tmp -mindepth 1 -maxdepth 1 ! -name lost+found -exec rm -rf -- {} + && exec /app/divine-upload-server",
            text,
        )

        # Isolate upload on upload_edge; attach caddy to both default and upload_edge.
        caddy_overlay = text.split("  caddy:", 1)[1].split("  upload:", 1)[0]
        self.assertRegex(caddy_overlay, r"(?m)^\s+-\s+default$")
        self.assertRegex(caddy_overlay, r"(?m)^\s+-\s+upload_edge$")

        upload_block = text.split("  upload:", 1)[1].split("\nnetworks:", 1)[0]
        upload_networks = upload_block.split("networks:", 1)[1].split("healthcheck:", 1)[0]
        self.assertRegex(upload_networks, r"(?m)^\s+-\s+upload_edge$")
        self.assertNotRegex(upload_networks, r"(?m)^\s+-\s+default$")
        self.assertRegex(text, r"(?m)^networks:\n\s+upload_edge:$")

        # Concurrency limits belong in .env.upload so they are not shadowed by
        # static compose `environment:` entries.
        env_block = upload_block.split("environment:", 1)[1].split("volumes:", 1)[0]
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
            "# MAX_UPLOAD_BYTES=1073741824",
            "# TRANSCODE_ADMISSION_SECRET=",
            "MIRROR_FETCH_TIMEOUT_SECS=",
        ):
            self.assertIn(key, text)

        self.assertNotIn("104857600", text)
        self.assertNotRegex(text, r"(?m)^TRANSCODE_ADMISSION_SECRET=")
        # divine-upload-server has no Sentry integration.
        self.assertNotIn("SENTRY_DSN", text)
        self.assertNotIn("SENTRY_ENVIRONMENT", text)

        # Keep TRANSCODER_URL aligned with Cloud Run prod while admission secret is unset.
        transcoder_match = re.search(r"(?m)^TRANSCODER_URL=(\S+)$", text)
        self.assertIsNotNone(transcoder_match, "Expected active TRANSCODER_URL in .env.upload.example")
        self.assertEqual(
            transcoder_match.group(1),
            "https://divine-transcoder-149672065768.us-central1.run.app",
        )

        # TRANSCRIBER_URL is explicitly set to the Cloud Run transcription origin
        # so switching TRANSCODER_URL to the off-GCP worker cannot fall back to
        # the worker's Caddy vhost (which returns 404 for /transcribe/audio).
        transcriber_match = re.search(r"(?m)^TRANSCRIBER_URL=(\S+)$", text)
        self.assertIsNotNone(transcriber_match, "Expected active TRANSCRIBER_URL in .env.upload.example")
        self.assertNotIn("transcoder-worker.divine.video", transcriber_match.group(1))

    def test_gitignore_covers_populated_off_gcp_deployment_files(self) -> None:
        text = GITIGNORE.read_text(encoding="utf-8")
        for pattern in (
            "cloud-run-transcoder/deploy/off-gcp/.env",
            "cloud-run-transcoder/deploy/off-gcp/.env.upload",
            "cloud-run-transcoder/deploy/off-gcp/conf.d/*.caddy",
            "cloud-run-transcoder/deploy/off-gcp/conf.d/certs/",
        ):
            self.assertRegex(text, rf"(?m)^{re.escape(pattern)}$")

    def test_ci_workflow_pins_and_requires_caddy_tests(self) -> None:
        base_text = BASE_COMPOSE.read_text(encoding="utf-8")
        ci_text = CI_WORKFLOW.read_text(encoding="utf-8")

        compose_match = re.search(r"(?m)^\s+image:\s+caddy:([0-9]+\.[0-9]+\.[0-9]+)-alpine$", base_text)
        self.assertIsNotNone(compose_match, "Expected pinned caddy:<ver>-alpine image in docker-compose.yml")
        ci_match = re.search(r"(?m)^\s+CADDY_VERSION:\s+([0-9]+\.[0-9]+\.[0-9]+)$", ci_text)
        self.assertIsNotNone(ci_match, "Expected pinned CADDY_VERSION in .github/workflows/ci.yml")
        self.assertEqual(compose_match.group(1), ci_match.group(1))
        self.assertIn("sha512sum -c -", ci_text)
        self.assertRegex(ci_text, r'(?m)^\s+REQUIRE_CADDY_TESTS:\s+"1"$')

    def test_caddy_adapt_orders_upload_proxy_before_404_fallback(self) -> None:
        caddy_bin = self._require_caddy_bin()

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

            # 2. Co-located host with literal hostname in conf.d/upload.caddy must
            #    route upload:8080 ahead of the 404 fallback inside a subroute.
            (conf_d / "upload.caddy").write_text(
                UPLOAD_CADDYFILE.read_text(encoding="utf-8").replace(
                    "{$UPLOAD_DOMAIN}", "upload.example.test"
                ),
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
            first_handlers = first_handler["routes"][0]["handle"]
            self.assertEqual(len(first_handlers), 2, f"Expected request_body + reverse_proxy, got: {first_handlers}")
            self.assertEqual(first_handlers[0]["handler"], "request_body")
            self.assertEqual(first_handlers[0]["max_size"], 16 * 1024 * 1024)
            proxy_handler = first_handlers[1]
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
        caddy_bin = self._require_caddy_bin()

        recorded: list[tuple[str, str, str]] = []

        class StubUpstream(BaseHTTPRequestHandler):
            def log_message(self, *_args) -> None:
                pass

            def _ok(self, tag: str) -> None:
                remaining = int(self.headers.get("Content-Length") or 0)
                while remaining > 0:
                    chunk = self.rfile.read(min(remaining, 65536))
                    if not chunk:
                        return
                    remaining -= len(chunk)
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

                upload_template = UPLOAD_CADDYFILE.read_text(encoding="utf-8").replace(
                    "upload:8080", f"127.0.0.1:{upload_server.server_port}"
                )

                # Retry ephemeral port binding to avoid flaking if another local
                # process claims the probe port before Caddy binds it.
                caddy_port = None
                last_bind_err = ""
                for _attempt in range(5):
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                        probe.bind(("127.0.0.1", 0))
                        candidate_port = probe.getsockname()[1]

                    (conf_d / "upload.caddy").write_text(
                        upload_template.replace(
                            "{$UPLOAD_DOMAIN}", f"http://upload.example.test:{candidate_port}"
                        ),
                        encoding="utf-8",
                    )

                    env = os.environ.copy()
                    env.update(
                        {
                            "TRANSCODER_DOMAIN": f"http://transcoder-worker.example.test:{candidate_port}",
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
                        start_new_session=True,
                    )

                    bind_conflict = False
                    deadline = time.monotonic() + 10.0
                    while time.monotonic() < deadline:
                        if proc.poll() is not None:
                            _, err = proc.communicate(timeout=2)
                            _stop_process(proc)
                            proc = None
                            if "address already in use" in err.lower() or "bind:" in err.lower():
                                last_bind_err = err
                                bind_conflict = True
                                break
                            self.fail(f"caddy exited early: {err}")
                        conn = None
                        try:
                            recorded.clear()
                            conn = http.client.HTTPConnection("127.0.0.1", candidate_port, timeout=0.2)
                            conn.request(
                                "GET",
                                "/health",
                                headers={"Host": f"transcoder-worker.example.test:{candidate_port}"},
                            )
                            resp = conn.getresponse()
                            body = resp.read()
                            if (
                                resp.status == 200
                                and body == b"upstream:transcoder"
                                and ("transcoder", "GET", "/health") in recorded
                                and proc.poll() is None
                            ):
                                caddy_port = candidate_port
                                break
                        except (OSError, http.client.HTTPException):
                            pass
                        finally:
                            if conn is not None:
                                conn.close()
                        time.sleep(0.05)

                    if caddy_port is not None:
                        break
                    if bind_conflict:
                        continue
                    _stop_process(proc)
                    proc = None
                    self.fail("caddy did not open loopback port in time")

                if caddy_port is None:
                    self.fail(f"caddy failed to bind loopback port after retries: {last_bind_err}")

                def send(host: str, method: str, path: str, body: bytes | None = None) -> int:
                    conn = http.client.HTTPConnection("127.0.0.1", caddy_port, timeout=5)
                    headers = {"Host": f"{host}:{caddy_port}"}
                    if body is not None:
                        headers["Content-Length"] = str(len(body))
                    try:
                        try:
                            conn.request(method, path, body=body, headers=headers)
                        except (BrokenPipeError, ConnectionResetError):
                            pass
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

                # Positive control: worker vhost matches transcoder-worker.example.test
                # and forwards /health to the transcoder upstream.
                recorded.clear()
                self.assertEqual(
                    send("transcoder-worker.example.test", "GET", "/health"),
                    200,
                )
                self.assertEqual(recorded, [("transcoder", "GET", "/health")])

                # Worker vhost intentionally returns 404 for /transcribe/audio, proving
                # why upload's TRANSCRIBER_URL must not fall back to transcoder-worker.
                recorded.clear()
                self.assertEqual(
                    send("transcoder-worker.example.test", "POST", "/transcribe/audio"),
                    404,
                )
                self.assertEqual(recorded, [])

                # Enforce 16 MiB request body cap on allowed upload routes.
                limit = 16 * 1024 * 1024
                recorded.clear()
                self.assertEqual(
                    send("upload.example.test", "PUT", "/upload", body=b"x" * limit),
                    200,
                )
                self.assertEqual(recorded, [("upload", "PUT", "/upload")])

                recorded.clear()
                self.assertEqual(
                    send("upload.example.test", "PUT", "/upload", body=b"x" * (limit + 1)),
                    413,
                )
                self.assertEqual(recorded, [])
        finally:
            if proc is not None:
                _stop_process(proc)
            upload_server.shutdown()
            upload_server.server_close()
            transcoder_server.shutdown()
            transcoder_server.server_close()


if __name__ == "__main__":
    unittest.main()
