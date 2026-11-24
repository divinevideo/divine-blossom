"""Regression checks for off-GCP co-located upload Caddy and Compose config."""

from __future__ import annotations

import concurrent.futures
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
UPLOAD_PROXY_NGINX = OFF_GCP_DIR / "nginx.upload-proxy.conf"
UPLOAD_COMPOSE = OFF_GCP_DIR / "docker-compose.upload.yml"
UPLOAD_ENV_EXAMPLE = OFF_GCP_DIR / ".env.upload.example"
GITIGNORE = REPO_ROOT / ".gitignore"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
RUNBOOK = REPO_ROOT / "docs" / "runbooks" / "off-cloud-run-worker.md"


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

    def _require_docker_bin(self) -> str:
        docker_bin = shutil.which("docker")
        require = os.environ.get("REQUIRE_NGINX_TESTS") == "1"
        if docker_bin is None:
            if require:
                self.fail("docker CLI is required when REQUIRE_NGINX_TESTS=1")
            self.skipTest("docker CLI not installed in this environment")
        probe = subprocess.run(
            [docker_bin, "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if probe.returncode != 0:
            if require:
                self.fail(f"docker daemon unavailable when REQUIRE_NGINX_TESTS=1: {probe.stderr}")
            self.skipTest(f"docker daemon unavailable: {probe.stderr.strip()}")
        return docker_bin

    def test_upload_caddyfile_wraps_proxy_and_fallback_in_handle_blocks(self) -> None:
        text = UPLOAD_CADDYFILE.read_text(encoding="utf-8")

        # Caddy 2 executes bare `respond` before `reverse_proxy`; both must live
        # inside `handle` blocks so the 404 fallback cannot shadow allowed routes.
        self.assertRegex(text, r"(?m)^\thandle @public_upload \{$")
        self.assertRegex(text, r"(?m)^\t\trequest_body \{$")
        self.assertRegex(text, r"(?m)^\t\t\tmax_size 16MiB$")
        self.assertRegex(text, r"(?m)^\t\treverse_proxy upload-proxy:8081 \{$")
        self.assertNotIn("request_buffers", text)
        self.assertRegex(text, r"(?m)^\t\t\t\tresponse_header_timeout 310s$")
        self.assertRegex(text, r"(?m)^\t\t\t\tkeepalive 60s$")
        self.assertNotIn("read_timeout", text)
        self.assertNotIn("write_timeout", text)
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
        def strip_yaml_comments(raw: str) -> str:
            return "\n".join(
                line for line in raw.splitlines() if not line.lstrip().startswith("#")
            )

        base_text = strip_yaml_comments(BASE_COMPOSE.read_text(encoding="utf-8"))
        text = strip_yaml_comments(UPLOAD_COMPOSE.read_text(encoding="utf-8"))

        # Base Caddy service should keep Docker's default stop timeout so routine stops
        # never hold ports 80/443 closed for 15 minutes across all vhosts, and avoid
        # unused UPLOAD_DOMAIN env plumbing.
        base_caddy = base_text.split("  caddy:", 1)[1].split("  transcoder:", 1)[0]
        self.assertNotIn("stop_grace_period", base_caddy)
        self.assertNotIn("UPLOAD_DOMAIN", base_caddy)

        # Co-located upload health must never block Caddy / transcoder ingress.
        self.assertNotIn("depends_on:", text)
        self.assertNotRegex(text, r"(?m)^  transcoder:")
        # Match divine-upload-server's 300s graceful shutdown drain window (GKE: 330s).
        self.assertRegex(text, r"(?m)^\s+stop_grace_period:\s+330s$")

        # Back /tmp with required bounded host scratch mounts, check sentinel
        # markers, sweep only .tmp* / proxy spools without crash-looping, and cap logs.
        caddy_overlay = text.split("  caddy:", 1)[1].split("  upload-proxy:", 1)[0]
        self.assertRegex(caddy_overlay, r"(?m)^\s+mem_limit:\s+\$\{CADDY_MEM_LIMIT:-2g\}$")
        self.assertRegex(caddy_overlay, r"(?m)^\s+GOMEMLIMIT:\s+\$\{CADDY_GOMEMLIMIT:-1600MiB\}$")
        self.assertRegex(caddy_overlay, r"(?m)^\s+-\s+default$")
        self.assertRegex(caddy_overlay, r"(?m)^\s+-\s+upload_edge$")

        upload_proxy_block = text.split("  upload-proxy:", 1)[1].split("  upload:", 1)[0]
        self.assertIn("image: nginx:1.30.8-alpine", upload_proxy_block)
        self.assertIn('user: "101:101"', upload_proxy_block)
        self.assertRegex(upload_proxy_block, r"(?m)^\s+stop_grace_period:\s+330s$")
        self.assertRegex(upload_proxy_block, r"(?m)^\s+mem_limit:\s+\$\{UPLOAD_PROXY_MEM_LIMIT:-512m\}$")
        self.assertIn("read_only: true", upload_proxy_block)
        self.assertIn("no-new-privileges:true", upload_proxy_block)
        self.assertIn("driver: json-file", upload_proxy_block)
        self.assertIn("./nginx.upload-proxy.conf:/etc/nginx/nginx.conf:ro", upload_proxy_block)
        self.assertIn(
            "source: ${UPLOAD_PROXY_TMP_DIR:-/var/lib/divine-upload/scratch/proxy-tmp}",
            upload_proxy_block,
        )
        self.assertIn("create_host_path: false", upload_proxy_block)
        self.assertIn("/tmp/.divine-upload-scratch", upload_proxy_block)
        proxy_networks = upload_proxy_block.split("networks:", 1)[1].split("healthcheck:", 1)[0]
        self.assertRegex(proxy_networks, r"(?m)^\s+-\s+upload_edge$")
        self.assertNotRegex(proxy_networks, r"(?m)^\s+-\s+default$")

        upload_block = text.split("  upload:", 1)[1].split("\nnetworks:", 1)[0]
        upload_volumes = upload_block.split("volumes:", 1)[1].split("networks:", 1)[0]
        self.assertNotIn("tmpfs:", text)
        self.assertNotIn("upload_tmp", text)
        self.assertIn("type: bind", upload_volumes)
        self.assertIn(
            "source: ${UPLOAD_TMP_DIR:-/var/lib/divine-upload/scratch/tmp}",
            upload_volumes,
        )
        self.assertIn("target: /tmp", upload_volumes)
        self.assertIn("create_host_path: false", upload_volumes)
        self.assertIn("/tmp/.divine-upload-scratch", upload_block)
        self.assertIn("-name '.tmp*'", upload_block)
        self.assertIn("|| echo 'tmp sweep incomplete' >&2; exec /app/divine-upload-server", upload_block)
        self.assertIn("driver: json-file", upload_block)
        self.assertIn('max-size: "50m"', upload_block)
        self.assertIn('max-file: "5"', upload_block)

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

    def test_upload_proxy_nginx_config_bounds_concurrency_and_buffers_to_disk(self) -> None:
        text = UPLOAD_PROXY_NGINX.read_text(encoding="utf-8")
        for required in (
            "server_tokens off;",
            "keepalive_timeout 130s;",
            "pid /tmp/nginx.pid;",
            "client_body_temp_path /tmp/body 1 2;",
            "real_ip_header X-Forwarded-For;",
            "real_ip_recursive off;",
            "$reject_unexpected_body",
            "~^(GET|HEAD|OPTIONS|DELETE):0*:$",
            "if ($reject_unexpected_body)",
            'default "body";',
            "error_page 429 = @too_many_requests;",
            "error_page 413 = @payload_too_large;",
            "location @too_many_requests",
            'add_header Access-Control-Allow-Origin "*" always;',
            'add_header Access-Control-Allow-Methods "GET, HEAD, PUT, POST, DELETE, OPTIONS" always;',
            'add_header Access-Control-Expose-Headers "Retry-After" always;',
            'add_header Retry-After "5" always;',
            "limit_conn_status 429;",
            "limit_conn upload_body_total 64;",
            "limit_conn upload_all_total 256;",
            "proxy_set_header X-Forwarded-For $remote_addr;",
            "client_max_body_size 16m;",
            "client_body_buffer_size 128k;",
            "client_body_timeout 60s;",
            "proxy_request_buffering on;",
            "proxy_buffering off;",
            "proxy_next_upstream off;",
            "resolver 127.0.0.11 valid=10s ipv6=off;",
            'set $upload_upstream "http://upload:8080";',
            "proxy_pass $upload_upstream;",
            "proxy_connect_timeout 10s;",
            "proxy_read_timeout 310s;",
        ):
            self.assertIn(required, text)
        self.assertRegex(
            text,
            r"if \(\$reject_unexpected_body\)\s*\{\s*return 413;\s*\}",
        )
        self.assertRegex(
            text,
            r"location @too_many_requests\s*\{[^}]*Retry-After \"5\" always;[^}]*return 429\b",
        )
        self.assertRegex(
            text,
            r"location @payload_too_large\s*\{[^}]*Access-Control-Allow-Origin \"\*\"[^}]*return 413\b",
        )
        self.assertNotIn("upload_body_per_ip", text)

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
        self.assertRegex(ci_text, r'(?m)^\s+REQUIRE_NGINX_TESTS:\s+"1"$')

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
            upload_server_cfg = None
            for server in servers.values():
                for route in server.get("routes", []):
                    for matcher in route.get("match", []):
                        if "upload.example.test" in matcher.get("host", []):
                            upload_route = route
                            upload_server_cfg = server
                            break
            self.assertIsNotNone(upload_route, "upload.example.test host route missing")
            self.assertEqual(upload_server_cfg.get("protocols"), ["h1", "h2"])
            self.assertEqual(upload_server_cfg.get("read_timeout"), 300_000_000_000)

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
            self.assertEqual(proxy_handler["upstreams"][0]["dial"], "upload-proxy:8081")
            self.assertNotIn("request_buffers", proxy_handler)
            self.assertEqual(proxy_handler["flush_interval"], -1)
            self.assertEqual(proxy_handler["transport"]["response_header_timeout"], 310_000_000_000)
            self.assertEqual(proxy_handler["transport"]["keep_alive"]["idle_timeout"], 60_000_000_000)
            self.assertNotIn("read_timeout", proxy_handler["transport"])
            self.assertNotIn("write_timeout", proxy_handler["transport"])

            self.assertEqual(second_handler["handler"], "subroute")
            fallback_handler = second_handler["routes"][0]["handle"][0]
            self.assertEqual(fallback_handler["handler"], "static_response")
            self.assertEqual(fallback_handler["status_code"], 404)

            error_routes = upload_server_cfg.get("errors", {}).get("routes", [])
            error_json = json.dumps(error_routes)
            self.assertIn("413", error_json)
            self.assertIn('"Access-Control-Allow-Origin": ["*"]', error_json)
            self.assertIn(
                '"Access-Control-Allow-Methods": ["GET, HEAD, PUT, POST, DELETE, OPTIONS"]',
                error_json,
            )

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

                raw_caddyfile = CADDYFILE.read_text(encoding="utf-8")
                assert raw_caddyfile.startswith("{\n"), "Expected global options block at top of Caddyfile"
                base_text = (
                    raw_caddyfile.replace("{\n", "{\n\tadmin off\n\tauto_https off\n\tpersist_config off\n", 1)
                    .replace("/etc/caddy/conf.d/*.caddy", f"{conf_d}/*.caddy")
                    .replace("transcoder:8080", f"127.0.0.1:{transcoder_server.server_port}")
                )
                test_caddyfile = tmp_path / "Caddyfile"
                test_caddyfile.write_text(base_text, encoding="utf-8")
                xdg_config = tmp_path / "xdg-config"
                xdg_data = tmp_path / "xdg-data"
                xdg_config.mkdir()
                xdg_data.mkdir()

                upload_template = UPLOAD_CADDYFILE.read_text(encoding="utf-8").replace(
                    "upload-proxy:8081", f"127.0.0.1:{upload_server.server_port}"
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
                            "XDG_CONFIG_HOME": str(xdg_config),
                            "XDG_DATA_HOME": str(xdg_data),
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

                def send_with_headers(
                    host: str, method: str, path: str, body: bytes | None = None
                ) -> tuple[int, http.client.HTTPMessage]:
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
                        return resp.status, resp.headers
                    finally:
                        conn.close()

                def send(host: str, method: str, path: str, body: bytes | None = None) -> int:
                    status, _ = send_with_headers(host, method, path, body=body)
                    return status

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
                    ("GET", "/healthz"),
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

                # Enforce 16 MiB request body cap on allowed upload routes with browser CORS on 413.
                limit = 16 * 1024 * 1024
                recorded.clear()
                status_ok, headers_ok = send_with_headers(
                    "upload.example.test", "PUT", "/upload", body=b"x" * limit
                )
                self.assertEqual(status_ok, 200)
                self.assertEqual(recorded, [("upload", "PUT", "/upload")])
                self.assertIsNone(headers_ok.get("Access-Control-Allow-Origin"))

                recorded.clear()
                status_413, headers_413 = send_with_headers(
                    "upload.example.test", "PUT", "/upload", body=b"x" * (limit + 1)
                )
                self.assertEqual(status_413, 413)
                self.assertEqual(headers_413.get_all("Access-Control-Allow-Origin"), ["*"])
                self.assertIn("PUT", headers_413.get("Access-Control-Allow-Methods") or "")
                self.assertEqual(recorded, [])
        finally:
            if proc is not None:
                _stop_process(proc)
            upload_server.shutdown()
            upload_server.server_close()
            transcoder_server.shutdown()
            transcoder_server.server_close()

    def test_upload_proxy_live_nginx_container_enforces_admission_and_cors(self) -> None:
        docker_bin = self._require_docker_bin()
        compose_text = UPLOAD_COMPOSE.read_text(encoding="utf-8")
        image_match = re.search(
            r"(?ms)^  upload-proxy:\n.*?^\s+image:\s*(nginx:[^\s]+)$", compose_text
        )
        self.assertIsNotNone(image_match, "Expected pinned nginx image on upload-proxy")
        nginx_image = image_match.group(1)

        pid = os.getpid()
        net_name = f"divine-upload-nginx-test-{pid}"
        up_name = f"divine-upload-stub-{pid}"
        proxy_name = f"divine-upload-proxy-{pid}"

        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp, 0o755)
            proxy_tmp = Path(tmp) / "proxy-tmp"
            proxy_tmp.mkdir()
            os.chmod(proxy_tmp, 0o777)
            (proxy_tmp / ".divine-upload-scratch").write_text("ok\n", encoding="utf-8")

            events_log = Path(tmp) / "events.log"
            events_log.write_text("", encoding="utf-8")
            os.chmod(events_log, 0o666)

            upstream_py = Path(tmp) / "upstream.py"
            upstream_py.write_text(
                """import http.server, json, socketserver, threading

gate = threading.Event()
gate.set()

def log_event(kind, path):
    with open("/events.log", "a", encoding="utf-8") as fp:
        fp.write(json.dumps({"kind": kind, "path": path}) + "\\n")

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *_args):
        pass
    def _send(self, code, body):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, PUT, POST, DELETE, OPTIONS")
        self.end_headers()
        self.wfile.write(data)
    def do_GET(self):
        log_event("GET", self.path)
        if self.path == "/gate-close":
            gate.clear()
            self._send(200, '{"gate":"closed"}')
            return
        if self.path == "/gate-open":
            gate.set()
            self._send(200, '{"gate":"open"}')
            return
        self._send(200, json.dumps({"path": self.path}))
    def do_DELETE(self):
        log_event("DELETE", self.path)
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self._send(200, '{"deleted":true}')
    def do_PUT(self):
        log_event("PUT_START", self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        log_event("PUT_BODY_LEN", f"{self.path}:{len(body)}")
        if self.path == "/hold":
            gate.wait(timeout=20)
        self._send(200, '{"ok":true}')

class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

Server(("0.0.0.0", 8080), Handler).serve_forever()
""",
                encoding="utf-8",
            )
            os.chmod(upstream_py, 0o644)

            net_created = False
            try:
                net_res = subprocess.run(
                    [docker_bin, "network", "create", net_name],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if net_res.returncode != 0:
                    for third in range(200, 255):
                        alt = subprocess.run(
                            [
                                docker_bin,
                                "network",
                                "create",
                                "--subnet",
                                f"10.249.{third}.0/24",
                                net_name,
                            ],
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                        if alt.returncode == 0:
                            net_res = alt
                            break
                self.assertEqual(net_res.returncode, 0, f"docker network create failed: {net_res.stderr}")
                net_created = True

                subprocess.check_call(
                    [
                        docker_bin,
                        "run",
                        "-d",
                        "--name",
                        up_name,
                        "--network",
                        net_name,
                        "--network-alias",
                        "upload",
                        "-v",
                        f"{upstream_py}:/upstream.py:ro",
                        "-v",
                        f"{events_log}:/events.log",
                        "python:3.12-alpine",
                        "python3",
                        "/upstream.py",
                    ],
                    stdout=subprocess.DEVNULL,
                )

                subprocess.check_call(
                    [
                        docker_bin,
                        "run",
                        "-d",
                        "--name",
                        proxy_name,
                        "--network",
                        net_name,
                        "-p",
                        "127.0.0.1:0:8081",
                        "--read-only",
                        "--cap-drop",
                        "ALL",
                        "--security-opt",
                        "no-new-privileges:true",
                        "--user",
                        "101:101",
                        "-v",
                        f"{UPLOAD_PROXY_NGINX}:/etc/nginx/nginx.conf:ro",
                        "-v",
                        f"{proxy_tmp}:/tmp",
                        nginx_image,
                        "nginx",
                        "-c",
                        "/etc/nginx/nginx.conf",
                        "-g",
                        "daemon off;",
                    ],
                    stdout=subprocess.DEVNULL,
                )

                port_out = subprocess.check_output(
                    [docker_bin, "port", proxy_name, "8081/tcp"], text=True
                ).strip()
                port = int(port_out.rsplit(":", 1)[1])

                deadline = time.monotonic() + 10.0
                while time.monotonic() < deadline:
                    conn = None
                    try:
                        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                        conn.request("GET", "/healthz")
                        resp = conn.getresponse()
                        body = resp.read()
                        if resp.status == 200 and body == b"ok\n":
                            break
                    except (OSError, http.client.HTTPException):
                        pass
                    finally:
                        if conn is not None:
                            conn.close()
                    time.sleep(0.05)
                else:
                    self.fail("nginx upload-proxy container /healthz did not become ready")

                # nginx answers /healthz itself, so also wait for the stub upstream to accept
                # connections; otherwise the first proxied request races its startup and gets 502.
                upstream_deadline = time.monotonic() + 15.0
                while time.monotonic() < upstream_deadline:
                    conn = None
                    try:
                        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                        conn.request("GET", "/ready")
                        resp = conn.getresponse()
                        resp.read()
                        if resp.status == 200:
                            break
                    except (OSError, http.client.HTTPException):
                        pass
                    finally:
                        if conn is not None:
                            conn.close()
                    time.sleep(0.1)
                else:
                    self.fail("stub upstream behind nginx did not become ready")

                # Upstream 200 must keep single Access-Control-Allow-Origin header.
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("GET", "/probe")
                resp = conn.getresponse()
                resp.read()
                conn.close()
                self.assertEqual(resp.status, 200)
                self.assertEqual(resp.headers.get_all("Access-Control-Allow-Origin"), ["*"])

                # Bodyless methods carrying a non-empty body return 413 with CORS before touching upstream.
                before_events = len(events_log.read_text(encoding="utf-8").splitlines())
                for method in ("GET", "HEAD", "OPTIONS", "DELETE"):
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    conn.request(method, "/bodyless", body=b"x" * 1024, headers={"Content-Length": "1024"})
                    resp = conn.getresponse()
                    resp.read()
                    conn.close()
                    self.assertEqual(resp.status, 413, f"Expected 413 for {method} with body")
                    self.assertEqual(resp.headers.get_all("Access-Control-Allow-Origin"), ["*"])
                with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                    sock.sendall(
                        b"GET /chunked HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\na\r\n0\r\n\r\n"
                    )
                    raw_resp = sock.recv(4096).decode("utf-8", errors="replace")
                self.assertTrue(raw_resp.startswith("HTTP/1.1 413 "), raw_resp)
                after_events = len(events_log.read_text(encoding="utf-8").splitlines())
                self.assertEqual(before_events, after_events)

                # DELETE with explicit zero Content-Length reaches upstream normally.
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("DELETE", "/upload/sess-1", headers={"Content-Length": "0"})
                resp = conn.getresponse()
                resp.read()
                conn.close()
                self.assertEqual(resp.status, 200)

                # 1 slow PUT spilling to /tmp/body while arriving (before upstream sees it)
                # + 63 concurrent upstream-held PUTs occupy all 64 body_total slots; 65th gets
                # 429 with CORS + Retry-After:5, while bodyless GET /thumbnail/:hash still succeeds.
                spill_total = 262144
                spill_first = 196608
                spill_rest = spill_total - spill_first
                spill_sock = socket.create_connection(("127.0.0.1", port), timeout=15)
                try:
                    spill_sock.sendall(
                        f"PUT /spill-test HTTP/1.1\r\nHost: localhost\r\nContent-Length: {spill_total}\r\nConnection: close\r\n\r\n".encode("ascii")
                        + (b"s" * spill_first)
                    )
                    spill_probe_cmd = (
                        'for f in /proc/[0-9]*/fd/*; do '
                        't=$(readlink "$f" 2>/dev/null || true); '
                        'case "$t" in /tmp/body/*) '
                        'sz=$(stat -Lc %s "$f" 2>/dev/null || echo 0); '
                        '[ "$sz" -gt 0 ] && echo "$f -> $t size=$sz"; '
                        ';; esac; done'
                    )
                    spill_deadline = time.monotonic() + 5.0
                    spilled_files = ""
                    while time.monotonic() < spill_deadline:
                        spilled_files = subprocess.check_output(
                            [docker_bin, "exec", proxy_name, "sh", "-c", spill_probe_cmd],
                            text=True,
                        ).strip()
                        if spilled_files:
                            break
                        time.sleep(0.05)
                    self.assertTrue(
                        spilled_files,
                        "Expected slow 256 KiB upload to spill to an open /tmp/body scratch file while arriving",
                    )
                    spill_events = [
                        line for line in events_log.read_text(encoding="utf-8").splitlines()
                        if '"/spill-test"' in line
                    ]
                    self.assertEqual(spill_events, [], f"Upstream saw spilled upload before full body arrived: {spill_events}")

                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    conn.request("GET", "/gate-close")
                    conn.getresponse().read()
                    conn.close()

                    def send_held_put() -> int:
                        c = http.client.HTTPConnection("127.0.0.1", port, timeout=25)
                        c.request("PUT", "/hold", body=b"x" * 16)
                        r = c.getresponse()
                        r.read()
                        c.close()
                        return r.status

                    with concurrent.futures.ThreadPoolExecutor(max_workers=65) as ex:
                        futs = [ex.submit(send_held_put) for _ in range(63)]
                        hold_deadline = time.monotonic() + 10.0
                        holds = 0
                        while time.monotonic() < hold_deadline:
                            holds = sum(
                                1
                                for line in events_log.read_text(encoding="utf-8").splitlines()
                                if '"PUT_START"' in line and '"/hold"' in line
                            )
                            if holds >= 63:
                                break
                            time.sleep(0.05)
                        self.assertEqual(holds, 63, f"Expected 63 held PUTs, saw {holds}")
                        spill_events = [
                            line for line in events_log.read_text(encoding="utf-8").splitlines()
                            if '"/spill-test"' in line
                        ]
                        self.assertEqual(spill_events, [], f"Upstream saw incomplete spilled upload under saturation: {spill_events}")

                        c65 = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        c65.request("PUT", "/hold", body=b"y" * 16)
                        r65 = c65.getresponse()
                        r65.read()
                        c65.close()
                        self.assertEqual(r65.status, 429)
                        self.assertEqual(r65.headers.get_all("Access-Control-Allow-Origin"), ["*"])
                        self.assertIn("PUT", r65.headers.get("Access-Control-Allow-Methods") or "")
                        self.assertEqual(r65.headers.get("Access-Control-Expose-Headers"), "Retry-After")
                        self.assertEqual(r65.headers.get("Retry-After"), "5")

                        cg = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        cg.request("GET", "/thumbnail/abc123")
                        rg = cg.getresponse()
                        rg.read()
                        cg.close()
                        self.assertEqual(rg.status, 200)

                        spill_sock.sendall(b"s" * spill_rest)
                        spill_chunks = []
                        while True:
                            chunk = spill_sock.recv(4096)
                            if not chunk:
                                break
                            spill_chunks.append(chunk)
                        spill_resp = b"".join(spill_chunks).decode("utf-8", errors="replace")
                        self.assertTrue(spill_resp.startswith("HTTP/1.1 200 "), spill_resp)
                        body_len_lines = [
                            line for line in events_log.read_text(encoding="utf-8").splitlines()
                            if '"PUT_BODY_LEN"' in line and f'"/spill-test:{spill_total}"' in line
                        ]
                        self.assertTrue(body_len_lines, "Expected upstream to receive complete 262144-byte spilled PUT")

                        co = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        co.request("GET", "/gate-open")
                        co.getresponse().read()
                        co.close()

                        statuses = [f.result(timeout=20) for f in futs]
                        self.assertTrue(all(st == 200 for st in statuses), statuses)
                finally:
                    spill_sock.close()
            finally:
                subprocess.run([docker_bin, "rm", "-f", proxy_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run([docker_bin, "rm", "-f", up_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(
                    [
                        docker_bin,
                        "run",
                        "--rm",
                        "--user",
                        "0:0",
                        "-v",
                        f"{proxy_tmp}:/cleanup",
                        nginx_image,
                        "sh",
                        "-c",
                        "rm -rf /cleanup/* /cleanup/.[!.]* /cleanup/..?* 2>/dev/null || true",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if net_created:
                    subprocess.run([docker_bin, "network", "rm", net_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_runbook_phase_c_health_probes_require_200_transcoder_json_and_reject_redirects(self):
        doc = RUNBOOK.read_text(encoding="utf-8")
        probes = re.findall(
            r"^([ \t]*probe_local_transcoder_health\(\)\s*\{.*?^[ \t]*\})",
            doc,
            re.M | re.S,
        )
        self.assertEqual(len(probes), 2, "Expected Phase C and Phase C recovery probe functions")
        dedented = [
            re.sub(r"(?m)^" + re.escape(re.match(r"([ \t]*)", p).group(1)), "", p)
            for p in probes
        ]
        self.assertEqual(
            dedented[0].replace("docker compose exec -T", "COMPOSE"),
            dedented[1].replace("docker compose -f docker-compose.yml exec -T", "COMPOSE"),
        )

        proxy_hits = 0
        target_hits = 0
        response_spec = {"code": 200, "headers": [], "body": b""}

        class ForgingProxyHandler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass
            def do_CONNECT(self):
                nonlocal proxy_hits
                proxy_hits += 1
                self.send_response(403)
                self.end_headers()
            def do_GET(self):
                nonlocal proxy_hits
                proxy_hits += 1
                body = b'{"status":"healthy","gpu_available":false}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        class MockCaddyHandler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass
            def do_GET(self):
                nonlocal target_hits
                target_hits += 1
                body = response_spec["body"]
                self.send_response(response_spec["code"])
                for hk, hv in response_spec["headers"]:
                    self.send_header(hk, hv)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

        proxy_srv = ThreadingHTTPServer(("127.0.0.1", 0), ForgingProxyHandler)
        target_srv = ThreadingHTTPServer(("127.0.0.1", 0), MockCaddyHandler)
        threading.Thread(target=proxy_srv.serve_forever, daemon=True).start()
        threading.Thread(target=target_srv.serve_forever, daemon=True).start()
        try:
            proxy_url = f"http://127.0.0.1:{proxy_srv.server_address[1]}"
            tport = target_srv.server_address[1]
            with tempfile.TemporaryDirectory() as tmp:
                bin_dir = Path(tmp) / "bin"
                bin_dir.mkdir()
                stub_docker = bin_dir / "docker"
                stub_docker.write_text(
                    '#!/bin/sh\nprintf "%s\\n" "${FAKE_TRANSCODER_DOMAIN:-}"\n',
                    encoding="utf-8",
                )
                stub_docker.chmod(0o755)

                cases = [
                    (308, [("Location", f"https://transcoder-worker.divine.video:{tport}/health")], b"", False),
                    (308, [("Location", f"https://transcoder-worker.divine.video:{tport}/health")], b'{"status":"healthy","gpu_available":false}', False),
                    (301, [("Location", f"https://transcoder-worker.divine.video:{tport}/health")], b"", False),
                    (200, [], b"", False),
                    (200, [("Content-Type", "text/plain")], b"ok", False),
                    (200, [("Content-Type", "application/json")], b'{"status":"unhealthy","gpu_available":false}', False),
                    (200, [("Content-Type", "application/json")], b'{"status":"healthy"}', False),
                    (502, [], b"Bad Gateway", False),
                    (200, [("Content-Type", "application/json")], b'{"status":"healthy","gpu_available":false}', True),
                    (200, [("Content-Type", "application/json")], b'{"status":"healthy","gpu_available":true}', True),
                ]

                for code, headers, body, should_pass in cases:
                    response_spec["code"] = code
                    response_spec["headers"] = headers
                    response_spec["body"] = body
                    for label, fn_src in [("phase_c", dedented[0]), ("phase_c_recovery", dedented[1])]:
                        before_proxy = proxy_hits
                        before_target = target_hits
                        env = os.environ.copy()
                        env["PATH"] = f"{bin_dir}:{env['PATH']}"
                        env["FAKE_TRANSCODER_DOMAIN"] = f"http://transcoder-worker.divine.video:{tport}"
                        env["LOCAL_CADDY_ADDR"] = "127.0.0.1"
                        env["http_proxy"] = proxy_url
                        env["HTTP_PROXY"] = proxy_url
                        env["https_proxy"] = proxy_url
                        env["HTTPS_PROXY"] = proxy_url
                        env["ALL_PROXY"] = proxy_url
                        res = subprocess.run(
                            ["sh", "-c", "set -eu\n" + fn_src + "\nprobe_local_transcoder_health\n"],
                            env=env,
                            text=True,
                            capture_output=True,
                        )
                        self.assertEqual(proxy_hits, before_proxy, f"{label} unexpectedly contacted proxy")
                        self.assertEqual(target_hits, before_target + 1, f"{label} did not hit local listener")
                        if should_pass:
                            self.assertEqual(res.returncode, 0, f"{label} expected 0 for {code} {body!r}: {res.stderr}")
                        else:
                            self.assertNotEqual(res.returncode, 0, f"{label} unexpectedly passed for {code} {body!r}")
        finally:
            proxy_srv.shutdown()
            proxy_srv.server_close()
            target_srv.shutdown()
            target_srv.server_close()


if __name__ == "__main__":
    unittest.main()
