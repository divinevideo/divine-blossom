# ABOUTME: Contract tests for the destructive boundaries and evidence emitted by probe-cold-blob.sh.
# ABOUTME: Prevents global purge, single-service invalidation, or loss of collapse correlation.

from pathlib import Path
import unittest


SCRIPT = (Path(__file__).parent / ".." / "probe-cold-blob.sh").read_text()


class ProbeColdBlobContractTest(unittest.TestCase):
    def test_never_uses_global_purge(self):
        self.assertNotIn("purge --all", SCRIPT)

    def test_purges_outer_and_compute_by_surrogate_key(self):
        self.assertIn('purge --key "${hash,,}" --service-id "$OUTER_SERVICE_ID"', SCRIPT)
        self.assertIn('purge --key "${hash,,}" --service-id "$COMPUTE_SERVICE_ID"', SCRIPT)

    def test_runs_anonymous_and_credentialed_cold_paths(self):
        self.assertIn('fetch_one anonymous "$ANONYMOUS_BLOB_HASH" "$RUN_ID-anon"', SCRIPT)
        self.assertIn('fetch_one credentialed "$CREDENTIALED_BLOB_HASH" "$RUN_ID-credentialed"', SCRIPT)

    def test_each_case_requires_a_distinct_fresh_object(self):
        self.assertIn("the anonymous, credentialed, and concurrent cases require distinct fresh objects", SCRIPT)

    def test_concurrent_requests_have_a_shared_correlation_prefix(self):
        self.assertIn('prefix="$RUN_ID-concurrent-"', SCRIPT)
        self.assertIn("REQUEST_PREFIX=$prefix", SCRIPT)

    def test_output_explicitly_omits_object_identifier(self):
        self.assertIn("The object identifier is intentionally omitted from output.", SCRIPT)


if __name__ == "__main__":
    unittest.main()
