"""Contracts for the one-time erased-media edge cleanup script."""

from pathlib import Path
import os
import stat
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "purge-erased-edge-copies.sh"
HASH_A = "a" * 64
HASH_B = "b" * 64
ADDRESSES = (
    HASH_A,
    f"/{HASH_A}.jpg",
    f"{HASH_B}/hls/chunk-free-form_001@2x.m4s",
)


def _write_executable(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class PurgeErasedEdgeCopiesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        self.curl_log = self.dir / "curl.log"
        self.sleep_log = self.dir / "sleep.log"
        self.address_file = self.dir / "addresses.txt"
        self.address_file.write_text(
            f"# private remediation set\n{ADDRESSES[0]}\n\n{ADDRESSES[1]}\n{ADDRESSES[2]}\n"
        )
        self.install_curl(
            status="200", body='{"status": "ok", "id": "purge-receipt-1"}'
        )
        _write_executable(
            self.bin / "sleep",
            f"""\
            #!/usr/bin/env bash
            echo "$*" >> "{self.sleep_log}"
            """,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def install_curl(self, status: str, body: str, exit_code: int = 0) -> None:
        _write_executable(
            self.bin / "curl",
            f"""\
            #!/usr/bin/env bash
            echo "$*" >> "{self.curl_log}"
            output=""
            while [ $# -gt 0 ]; do
              if [ "$1" = "--output" ]; then
                output="$2"
                shift
              fi
              shift
            done
            printf '%s' '{body}' > "$output"
            printf '%s' '{status}'
            exit {exit_code}
            """,
        )

    def run_script(self, *args):
        env = dict(
            os.environ,
            PATH=f"{self.bin}:{os.environ['PATH']}",
            FASTLY_API_TOKEN="test-token",
        )
        return subprocess.run(
            [str(SCRIPT), *args],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def curl_calls(self):
        if not self.curl_log.exists():
            return []
        return self.curl_log.read_text().splitlines()

    def sleep_calls(self):
        if not self.sleep_log.exists():
            return []
        return self.sleep_log.read_text().splitlines()

    def test_purges_each_exact_address_with_purge_method_and_rate_limit(self):
        result = self.run_script("--address-file", str(self.address_file))

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.curl_calls()
        self.assertEqual(len(calls), len(ADDRESSES))
        expected_urls = {
            f"https://media.divine.video/{address.lstrip('/')}"
            for address in ADDRESSES
        }
        self.assertEqual({call.rsplit(" ", 1)[-1] for call in calls}, expected_urls)
        self.assertTrue(all("--request PURGE" in call for call in calls))
        self.assertTrue(all("--config" in call for call in calls))
        self.assertTrue(all("--globoff" in call for call in calls))
        self.assertTrue(all("--max-time 20" in call for call in calls))
        self.assertTrue(all("test-token" not in call for call in calls))
        self.assertEqual(self.sleep_calls(), ["0.084"] * len(ADDRESSES))
        self.assertIn("rate_limit=12/s", result.stdout)
        self.assertIn(f"purged={len(ADDRESSES)} failures=0", result.stdout)
        self.assertEqual(
            result.stdout.count("purge_id=purge-receipt-1"), len(ADDRESSES)
        )
        self.assertNotIn(HASH_A[:12], result.stdout)

    def test_non_ok_body_fails_fast_without_purging_later_addresses(self):
        self.install_curl(
            status="200", body='{"status": "error", "id": "purge-receipt-1"}'
        )

        result = self.run_script("--address-file", str(self.address_file))

        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(self.curl_calls()), 1)
        self.assertEqual(self.sleep_calls(), [])
        self.assertIn("unexpected response status=200", result.stderr)

    def test_non_200_response_fails_fast(self):
        self.install_curl(
            status="503", body='{"status": "ok", "id": "purge-receipt-1"}'
        )

        result = self.run_script("--address-file", str(self.address_file))

        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(self.curl_calls()), 1)

    def test_curl_error_fails_fast(self):
        self.install_curl(status="000", body="", exit_code=28)

        result = self.run_script("--address-file", str(self.address_file))

        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(self.curl_calls()), 1)
        self.assertIn("request error", result.stderr)

    def test_missing_purge_id_fails_fast(self):
        self.install_curl(status="200", body='{"status": "ok"}')

        result = self.run_script("--address-file", str(self.address_file))

        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(self.curl_calls()), 1)
        self.assertIn("omitted purge id", result.stderr)

    def test_dry_run_issues_no_requests(self):
        result = self.run_script(
            "--address-file", str(self.address_file), "--dry-run"
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.curl_calls(), [])
        self.assertEqual(self.sleep_calls(), [])
        self.assertEqual(result.stdout.count("would purge address"), len(ADDRESSES))

    def test_domain_override_applies_to_each_request(self):
        result = self.run_script(
            "--address-file",
            str(self.address_file),
            "--domain",
            "staging.example.test",
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(
            all("https://staging.example.test/" in call for call in self.curl_calls())
        )

    def test_malformed_address_stops_before_any_request(self):
        self.address_file.write_text(f"{HASH_A}\nhttps://example.test/{HASH_B}\n")

        result = self.run_script("--address-file", str(self.address_file))

        self.assertEqual(result.returncode, 2)
        self.assertIn("line 2", result.stderr)
        self.assertEqual(self.curl_calls(), [])

    def test_uppercase_hash_stops_before_any_request(self):
        self.address_file.write_text(f"{HASH_A}\n{'B' * 64}.jpg\n")

        result = self.run_script("--address-file", str(self.address_file))

        self.assertEqual(result.returncode, 2)
        self.assertIn("line 2", result.stderr)
        self.assertEqual(self.curl_calls(), [])

    def test_addresses_never_come_from_the_command_line(self):
        result = self.run_script(HASH_A)

        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.curl_calls(), [])

    def test_runbook_describes_exact_addresses_and_purge_contract(self):
        runbook = (
            ROOT / "docs" / "runbooks" / "erased-media-edge-cleanup.md"
        ).read_text()

        self.assertIn("--address-file", runbook)
        self.assertIn("`PURGE` method", runbook)
        self.assertIn('`{"status": "ok"}`', runbook)
        self.assertIn("purge ID", runbook)
        self.assertIn("12 requests per second", runbook)


if __name__ == "__main__":
    unittest.main()
