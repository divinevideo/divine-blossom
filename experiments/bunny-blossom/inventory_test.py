"""Ensure the migration inventory includes routes before the Rust tuple match."""
import json
import unittest
from pathlib import Path


class InventoryTests(unittest.TestCase):
    def test_pre_match_dispatches_are_explicit(self):
        inventory = json.loads((Path(__file__).parent / "routes.json").read_text())
        dispatches = inventory.get("pre_match_dispatches", [])
        self.assertEqual(len(dispatches), 3)
        text = " ".join(row["matcher"] for row in dispatches)
        for dispatch in ("b2_cdn::route", "canary::route", "/api/bunny-playback/"):
            self.assertIn(dispatch, text)


if __name__ == "__main__":
    unittest.main()
