import importlib.util
from pathlib import Path
import re
import unittest


SCRIPT = Path(__file__).parents[1] / "audit_erasure.py"
SPEC = importlib.util.spec_from_file_location("audit_erasure", SCRIPT)
audit_erasure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_erasure)


class FakeBlob:
    def __init__(self, present):
        self.present = present

    def exists(self):
        return self.present


class FakeBucket:
    def __init__(self, present_keys):
        self.present_keys = set(present_keys)

    def blob(self, key):
        return FakeBlob(key in self.present_keys)


class AuditErasureTest(unittest.TestCase):
    def test_audit_derivative_keys_match_vanish_cleanup_contract(self):
        sha256 = "a" * 64
        source = (SCRIPT.parents[1] / "src" / "main.rs").read_text()
        cleanup = source.split("pub(crate) fn delete_blob_gcs_artifacts", 1)[1]
        cleanup = cleanup.split("/// Delete all KV artifacts", 1)[0]
        rust_templates = re.findall(r'format!\("([^"]+)"', cleanup)
        rust_keys = {template.replace("{}", sha256) for template in rust_templates}
        audit_keys = set(audit_erasure.deterministic_object_keys(sha256)[1:])

        self.assertEqual(audit_keys, rust_keys)

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

        self.assertIn(survivor, audit_erasure.deterministic_object_keys(sha256))
        self.assertEqual(survivors, [survivor])
        self.assertEqual(
            audit_erasure.classify_erasure(
                {"version": 1, "evidence": "vanish_erasure"}, survivors
            ),
            "incomplete",
        )

    def test_absence_without_vanish_evidence_is_not_recorded(self):
        self.assertEqual(audit_erasure.classify_erasure(None, []), "not_recorded")

    def test_survivor_without_vanish_evidence_is_incomplete(self):
        self.assertEqual(
            audit_erasure.classify_erasure(None, ["a" * 64 + ".jpg"]),
            "incomplete",
        )

    def test_evidence_key_does_not_contain_original_hash(self):
        sha256 = "A" * 64

        key = audit_erasure.erasure_evidence_key(sha256)

        self.assertTrue(key.startswith("erasure:v1:"))
        self.assertNotIn(sha256.lower(), key)
        self.assertEqual(key, audit_erasure.erasure_evidence_key(sha256.lower()))


if __name__ == "__main__":
    unittest.main()
