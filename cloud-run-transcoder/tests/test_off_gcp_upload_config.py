"""Regression checks for off-GCP co-located upload Caddy and Compose config."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
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


if __name__ == "__main__":
    unittest.main()
