# ABOUTME: Contract tests for the destructive boundaries and evidence emitted by probe-cold-blob.sh.
# ABOUTME: Prevents global purge, single-service invalidation, or loss of collapse correlation.

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


SCRIPT = (Path(__file__).parent / ".." / "probe-cold-blob.sh").read_text()


class ProbeColdBlobContractTest(unittest.TestCase):
    def test_never_uses_global_purge(self):
        self.assertNotIn("purge --all", SCRIPT)

    def test_purges_outer_and_compute_by_surrogate_key(self):
        self.assertNotIn("${hash,,}", SCRIPT)
        self.assertIn("tr '[:upper:]' '[:lower:]'", SCRIPT)
        self.assertIn('purge --key "$normalized_hash" --service-id "$OUTER_SERVICE_ID"', SCRIPT)
        self.assertIn('purge --key "$normalized_hash" --service-id "$COMPUTE_SERVICE_ID"', SCRIPT)

    def test_executes_targeted_purges_with_portable_lowercase_normalization(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            command_dir = temp / "bin"
            command_dir.mkdir()
            fastly_log = temp / "fastly.log"

            self._write_command(
                command_dir,
                "fastly",
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$FASTLY_LOG"\n',
            )
            self._write_command(command_dir, "sleep", "#!/bin/sh\nexit 0\n")
            self._write_command(
                command_dir,
                "nak",
                '#!/bin/sh\n[ "$1" = curl ] || exit 1\nshift\nexec curl "$@"\n',
            )
            self._write_command(
                command_dir,
                "curl",
                """#!/bin/sh
headers=
while [ "$#" -gt 0 ]; do
  if [ "$1" = -D ]; then
    headers=$2
    shift 2
  else
    shift
  fi
done
cat > "$headers" <<'EOF'
HTTP/1.1 200 OK
X-Served-By: cache-TEST
X-Cache: MISS
Age: 0
X-Divine-Storage-Cache: MISS
X-Divine-Diagnostic-Role: leader
X-Divine-Diagnostic-Source: gcs
X-Divine-Diagnostic-FOS-Outcome: miss
X-Divine-Diagnostic-Buffer: present
X-Divine-Diagnostic-Write-Back: present
EOF
printf '200 0.1 0.2\\n'
""",
            )

            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{command_dir}:{env['PATH']}",
                    "FASTLY_LOG": str(fastly_log),
                    "ANONYMOUS_BLOB_HASH": "A" * 64,
                    "CREDENTIALED_BLOB_HASH": "B" * 64,
                    "CONCURRENT_BLOB_HASH": "C" * 64,
                    "EXPECTED_POP_REGEX": "TEST",
                    "CONCURRENCY": "2",
                }
            )
            result = subprocess.run(
                [str(Path(__file__).parent / ".." / "probe-cold-blob.sh")],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            purges = fastly_log.read_text().splitlines()
            self.assertEqual(len(purges), 6)
            self.assertIn(f"purge --key {'a' * 64}", purges[0])
            self.assertIn(f"purge --key {'b' * 64}", purges[2])
            self.assertIn(f"purge --key {'c' * 64}", purges[4])

    @staticmethod
    def _write_command(directory, name, contents):
        path = directory / name
        path.write_text(contents)
        path.chmod(0o755)

    def test_runs_anonymous_and_credentialed_cold_paths(self):
        self.assertIn('fetch_one anonymous "$ANONYMOUS_BLOB_HASH" "$RUN_ID-anon"', SCRIPT)
        self.assertIn('fetch_one credentialed "$CREDENTIALED_BLOB_HASH" "$RUN_ID-credentialed"', SCRIPT)

    def test_each_case_requires_a_distinct_fresh_object(self):
        self.assertIn("the anonymous, credentialed, and concurrent cases require distinct fresh objects", SCRIPT)

    def test_concurrent_requests_have_a_shared_correlation_prefix(self):
        self.assertIn('prefix="$RUN_ID-concurrent-"', SCRIPT)
        self.assertIn("REQUEST_PREFIX=$prefix", SCRIPT)
        self.assertIn('echo "distinct_compute_fills=$compute_fills"', SCRIPT)
        self.assertIn('echo "distinct_gcs_fills=$gcs_fills"', SCRIPT)
        self.assertIn("the concurrent fresh object did not exercise a GCS fill", SCRIPT)

    def test_full_object_is_the_default_for_buffer_and_write_back_evidence(self):
        self.assertIn('RANGE="${RANGE:-}"', SCRIPT)
        self.assertIn('if [ -n "$RANGE" ]', SCRIPT)
        self.assertIn("anonymous cold request did not exercise buffering", SCRIPT)
        self.assertIn("credentialed cold request did not exercise write-back", SCRIPT)
        self.assertIn("credentialed range request unexpectedly exercised buffering", SCRIPT)

    def test_python_is_checked_before_the_first_purge(self):
        self.assertIn("for command in curl fastly nak python3", SCRIPT)
        self.assertLess(SCRIPT.index("for command in curl"), SCRIPT.index('purge_fixture "$ANONYMOUS_BLOB_HASH"'))

    def test_representative_pop_is_required(self):
        self.assertIn('EXPECTED_POP_REGEX="${EXPECTED_POP_REGEX:-}"', SCRIPT)
        self.assertIn("set EXPECTED_POP_REGEX to the representative US POP pattern", SCRIPT)

    def test_timestamp_keeps_year_month_day_in_order(self):
        self.assertIn("date -u +%Y%m%dt%H%M%Sz", SCRIPT)

    def test_output_explicitly_omits_object_identifier(self):
        self.assertIn("The object identifier is intentionally omitted from output.", SCRIPT)


if __name__ == "__main__":
    unittest.main()
