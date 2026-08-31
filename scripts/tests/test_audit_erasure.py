import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).parents[1] / "audit_erasure.py"
SPEC = importlib.util.spec_from_file_location("audit_erasure", SCRIPT)
audit_erasure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_erasure)


class FakeBucket:
    def __init__(self, present_keys):
        self.present_keys = set(present_keys)

    def list_blobs(self, prefix):
        return [
            type("Blob", (), {"name": key})
            for key in self.present_keys
            if key.startswith(prefix)
        ]


class AuditErasureTest(unittest.TestCase):
    def test_completed_erasure_has_evidence_and_no_survivors(self):
        self.assertEqual(
            audit_erasure.classify_erasure(
                {"version": 1, "evidence": "vanish_erasure"}, []
            ),
            "complete",
        )

    def test_surviving_derivative_makes_erasure_incomplete(self):
        sha256 = "a" * 64
        survivor = f"{sha256}/hls/stream_480p.ts"
        survivors = audit_erasure.existing_objects(FakeBucket([survivor]), sha256)

        self.assertEqual(survivors, [survivor])
        self.assertEqual(
            audit_erasure.classify_erasure(
                {"version": 1, "evidence": "vanish_erasure"}, survivors
            ),
            "incomplete",
        )

    def test_absence_without_vanish_evidence_is_not_recorded(self):
        self.assertEqual(audit_erasure.classify_erasure(None, []), "not_recorded")

    def test_survivor_without_vanish_evidence_is_present_unrecorded(self):
        self.assertEqual(
            audit_erasure.classify_erasure(None, ["a" * 64 + ".jpg"]),
            "present_unrecorded",
        )

    def test_evidence_key_does_not_contain_original_hash(self):
        sha256 = "A" * 64

        key = audit_erasure.erasure_evidence_key(sha256)

        self.assertTrue(key.startswith("erasure:v1:"))
        self.assertNotIn(sha256.lower(), key)
        self.assertEqual(key, audit_erasure.erasure_evidence_key(sha256.lower()))

    def test_erasure_key_golden_vector(self):
        self.assertEqual(
            audit_erasure.erasure_evidence_key("a" * 64),
            "erasure:v1:60af600bf402ba1507822131764b39002f969d1fc122f1eda3e7491509505437",
        )

    def test_invalid_evidence_is_not_complete(self):
        self.assertEqual(
            audit_erasure.classify_erasure({"version": 2}, []),
            "invalid_evidence",
        )


if __name__ == "__main__":
    unittest.main()
