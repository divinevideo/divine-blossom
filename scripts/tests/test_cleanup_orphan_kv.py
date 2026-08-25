import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "cleanup_orphan_kv.py"
SPEC = importlib.util.spec_from_file_location("cleanup_orphan_kv", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ClassificationTests(unittest.TestCase):
    def test_classifies_storage_and_metadata_divergence(self):
        present = MODULE.MetadataProbe(MODULE.Presence.PRESENT, "active")
        missing = MODULE.MetadataProbe(MODULE.Presence.MISSING)

        self.assertEqual(
            MODULE.classify_blob(present, MODULE.Presence.MISSING),
            MODULE.MISSING_BYTES,
        )
        self.assertEqual(
            MODULE.classify_blob(missing, MODULE.Presence.PRESENT),
            MODULE.MISSING_METADATA,
        )
        self.assertEqual(
            MODULE.classify_blob(missing, MODULE.Presence.MISSING),
            MODULE.STALE_EVENT_REFERENCE,
        )

    def test_preserves_moderation_and_deletion_outcomes(self):
        for status in ("restricted", "banned"):
            metadata = MODULE.MetadataProbe(MODULE.Presence.PRESENT, status)
            self.assertEqual(
                MODULE.classify_blob(metadata, MODULE.Presence.PRESENT, 404),
                MODULE.MODERATION_HIDDEN,
            )

        deleted = MODULE.MetadataProbe(MODULE.Presence.PRESENT, "deleted")
        self.assertEqual(
            MODULE.classify_blob(deleted, MODULE.Presence.MISSING, 404),
            MODULE.DELETED,
        )

        age_restricted = MODULE.MetadataProbe(
            MODULE.Presence.PRESENT, "age_restricted"
        )
        self.assertEqual(
            MODULE.classify_blob(age_restricted, MODULE.Presence.PRESENT, 401),
            MODULE.AGE_RESTRICTED,
        )

    def test_probe_errors_never_become_missing_state(self):
        metadata_error = MODULE.MetadataProbe(MODULE.Presence.ERROR)
        active = MODULE.MetadataProbe(MODULE.Presence.PRESENT, "active")

        self.assertEqual(
            MODULE.classify_blob(metadata_error, MODULE.Presence.MISSING),
            MODULE.PROBE_ERROR,
        )
        self.assertEqual(
            MODULE.classify_blob(active, MODULE.Presence.ERROR),
            MODULE.PROBE_ERROR,
        )
        self.assertEqual(
            MODULE.classify_blob(active, MODULE.Presence.PRESENT, -1),
            MODULE.PROBE_ERROR,
        )

    def test_inconsistent_metadata_is_distinct_from_probe_failure(self):
        inconsistent = MODULE.MetadataProbe(
            MODULE.Presence.PRESENT, "active", consistent=False
        )

        self.assertEqual(
            MODULE.classify_blob(inconsistent, MODULE.Presence.PRESENT, 500),
            MODULE.INCONSISTENT_METADATA,
        )

    def test_repaired_synthetic_case_passes_public_delivery_classification(self):
        synthetic_hash = "0123456789abcdef" * 4
        initial = MODULE.MetadataProbe(MODULE.Presence.MISSING)
        repaired = MODULE.MetadataProbe(MODULE.Presence.PRESENT, "active")

        self.assertEqual(len(synthetic_hash), 64)
        self.assertEqual(
            MODULE.classify_blob(initial, MODULE.Presence.PRESENT, 404),
            MODULE.MISSING_METADATA,
        )
        self.assertEqual(
            MODULE.classify_blob(repaired, MODULE.Presence.PRESENT, 206),
            MODULE.AVAILABLE,
        )


class PrivacyTests(unittest.TestCase):
    def test_scan_returns_aggregate_counts_only(self):
        synthetic_hashes = ["1" * 64, "2" * 64]
        metadata = {
            synthetic_hashes[0]: MODULE.MetadataProbe(MODULE.Presence.PRESENT, "active"),
            synthetic_hashes[1]: MODULE.MetadataProbe(MODULE.Presence.MISSING),
        }
        storage = {
            synthetic_hashes[0]: MODULE.Presence.PRESENT,
            synthetic_hashes[1]: MODULE.Presence.MISSING,
        }

        result = MODULE.scan(
            synthetic_hashes,
            metadata.__getitem__,
            storage.__getitem__,
            lambda value: 200 if value == synthetic_hashes[0] else 404,
        )

        rendered = str(result)
        self.assertEqual(result["total_scanned"], 2)
        self.assertEqual(result["privacy"], "aggregate_only")
        self.assertEqual(
            result["recommended_actions"],
            {"none": 1, "repair_at_event_source": 1},
        )
        self.assertNotIn(synthetic_hashes[0], rendered)
        self.assertNotIn(synthetic_hashes[1], rendered)

    def test_repair_only_targets_confirmed_missing_bytes(self):
        synthetic_hashes = ["3" * 64, "4" * 64]
        repaired = []

        result = MODULE.scan(
            synthetic_hashes,
            lambda value: MODULE.MetadataProbe(
                MODULE.Presence.PRESENT,
                "active" if value == synthetic_hashes[0] else "restricted",
            ),
            lambda _value: MODULE.Presence.MISSING,
            repair=lambda value: repaired.append(value) is None,
        )

        self.assertEqual(repaired, [synthetic_hashes[0]])
        self.assertEqual(result["repairs"], {"soft_deleted": 1})


if __name__ == "__main__":
    unittest.main()
