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
HASH_B = "B" * 64


def _write_executable(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class PurgeErasedEdgeCopiesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        self.fastly_log = self.dir / "fastly.log"
        self.curl_log = self.dir / "curl.log"
        self.hash_file = self.dir / "hashes.txt"
        self.hash_file.write_text(f"# comment\n{HASH_A}\n\n  {HASH_B}  \n")
        _write_executable(
            self.bin / "fastly",
            f"""\
            #!/usr/bin/env bash
            echo "$*" >> "{self.fastly_log}"
            """,
        )
        self.install_curl("404")

    def tearDown(self):
        self.tmp.cleanup()

    def install_curl(self, status: str) -> None:
        _write_executable(
            self.bin / "curl",
            f"""\
            #!/usr/bin/env bash
            echo "$*" >> "{self.curl_log}"
            while [ $# -gt 0 ]; do
              if [ "$1" = "-D" ]; then
                printf 'HTTP/2 {status}\\r\\nx-served-by: cache-test-1\\r\\n\\r\\n' > "$2"
                shift
              fi
              shift
            done
            printf '{status}'
            """,
        )

    def run_script(self, *args):
        env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}")
        return subprocess.run(
            [str(SCRIPT), *args],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def fastly_calls(self):
        if not self.fastly_log.exists():
            return []
        return self.fastly_log.read_text().splitlines()

    def curl_calls(self):
        if not self.curl_log.exists():
            return []
        return self.curl_log.read_text().splitlines()

    def test_purges_every_url_form_by_url_then_probes_bare_url(self):
        result = self.run_script("--hash-file", str(self.hash_file))

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = []
        for content_hash in (HASH_A, HASH_B.lower()):
            for suffix in ("", ".mp4", ".jpg"):
                expected.append(
                    f"purge --url https://media.divine.video/{content_hash}{suffix}"
                )
        self.assertEqual(self.fastly_calls(), expected)
        for call in self.fastly_calls():
            self.assertNotIn("--all", call)
            self.assertNotIn("--key", call)

        probes = self.curl_calls()
        self.assertEqual(len(probes), 2)
        self.assertIn(f"https://media.divine.video/{HASH_A}", probes[0])
        self.assertIn(f"https://media.divine.video/{HASH_B.lower()}", probes[1])
        self.assertIn("purge_failures=0 probe_failures=0", result.stdout)
        self.assertIn("one POP", result.stdout)

    def test_probe_that_still_serves_content_fails_the_run(self):
        self.install_curl("200")

        result = self.run_script("--hash-file", str(self.hash_file))

        self.assertEqual(result.returncode, 1)
        self.assertIn("PROBE FAIL status=200", result.stdout)
        self.assertIn("probe_failures=2", result.stdout)

    def test_dry_run_issues_no_purge_and_no_probe(self):
        result = self.run_script("--hash-file", str(self.hash_file), "--dry-run")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.fastly_calls(), [])
        self.assertEqual(self.curl_calls(), [])
        self.assertIn("would purge", result.stdout)

    def test_probe_only_skips_purging(self):
        result = self.run_script("--hash-file", str(self.hash_file), "--probe-only")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.fastly_calls(), [])
        self.assertEqual(len(self.curl_calls()), 2)

    def test_domain_override_applies_to_purge_and_probe(self):
        result = self.run_script(
            "--hash-file", str(self.hash_file), "--domain", "staging.example.test"
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(
            all("https://staging.example.test/" in call for call in self.fastly_calls())
        )
        self.assertTrue(
            all("https://staging.example.test/" in call for call in self.curl_calls())
        )

    def test_malformed_hash_line_stops_before_any_purge(self):
        self.hash_file.write_text(f"{HASH_A}\nnot-a-hash\n")

        result = self.run_script("--hash-file", str(self.hash_file))

        self.assertEqual(result.returncode, 2)
        self.assertIn("line 2", result.stderr)
        self.assertEqual(self.fastly_calls(), [])

    def test_hashes_never_come_from_the_command_line(self):
        result = self.run_script(HASH_A)

        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.fastly_calls(), [])

    def test_runbook_and_script_agree_on_url_forms_and_probe_limit(self):
        runbook = (ROOT / "docs" / "runbooks" / "erased-media-edge-cleanup.md").read_text()
        script = SCRIPT.read_text()

        self.assertIn('URL_SUFFIXES=("" ".mp4" ".jpg")', script)
        self.assertIn("scripts/purge-erased-edge-copies.sh", runbook)
        self.assertIn("one POP", runbook)
        # The runbook names `purge --all` once, and only to forbid it.
        self.assertEqual(runbook.count("--all"), 1)
        self.assertIn("Do not run\n`fastly purge --all`", runbook)


if __name__ == "__main__":
    unittest.main()
