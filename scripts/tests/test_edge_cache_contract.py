"""Regression contracts for the hand-managed outer Fastly VCL and deploy flow."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class EdgeCacheContractTests(unittest.TestCase):
    def test_private_edge_policy_does_not_disable_short_404_caching(self):
        fetch_vcl = (ROOT / "vcl" / "fetch.vcl").read_text()

        private_guard = (
            'beresp.http.Surrogate-Control ~ "(?i)(private|no-store)"'
        )
        self.assertIn(private_guard, fetch_vcl)
        self.assertNotIn(
            'beresp.http.Cache-Control ~ "(?i)(private|no-store)"', fetch_vcl
        )

        guard_offset = fetch_vcl.index(private_guard)
        success_offset = fetch_vcl.index("beresp.status == 200")
        not_found_offset = fetch_vcl.index("beresp.status == 404")
        short_ttl_offset = fetch_vcl.index("set beresp.ttl = 60s", not_found_offset)

        self.assertLess(guard_offset, success_offset)
        self.assertLess(success_offset, not_found_offset)
        self.assertGreater(short_ttl_offset, not_found_offset)

    def test_global_purge_requires_explicit_manual_workflow_input(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()

        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("purge_cache:", workflow)
        self.assertIn(
            "if: github.event_name == 'workflow_dispatch' && inputs.purge_cache",
            workflow,
        )
        self.assertNotIn("github.event.head_commit.message", workflow)

    def test_operator_docs_do_not_require_a_global_purge(self):
        for relative_path in (
            "AGENTS.md",
            "README.md",
            "OAUTH_SETUP.md",
            "scripts/backfill_restricted_to_age_restricted.py",
        ):
            contents = (ROOT / relative_path).read_text()
            self.assertNotIn("fastly purge --all", contents, relative_path)


if __name__ == "__main__":
    unittest.main()
