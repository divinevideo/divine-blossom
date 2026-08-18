"""Regression contracts for the hand-managed outer Fastly VCL."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class EdgeCacheContractTests(unittest.TestCase):
    def test_hash_paths_fall_through_to_generated_shield_selection(self):
        recv_vcl = (ROOT / "vcl" / "recv.vcl").read_text()
        hash_policy = recv_vcl.split(
            "# Cache hash-based content paths:", maxsplit=1
        )[1]

        self.assertIn('if (req.url !~ "^/[0-9a-fA-F]{64}")', hash_policy)
        self.assertNotIn("return(lookup)", hash_policy)
        self.assertIn("Deliberately fall through", hash_policy)


if __name__ == "__main__":
    unittest.main()
