import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scan_and_repair_vtts.py"


def load_script_module(test_case: unittest.TestCase):
    if not SCRIPT_PATH.exists():
        test_case.fail(f"missing script: {SCRIPT_PATH}")

    spec = importlib.util.spec_from_file_location("scan_and_repair_vtts", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        test_case.fail(f"unable to load script module: {SCRIPT_PATH}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ScanAndRepairVttsTests(unittest.TestCase):
    def test_classifies_instruction_echo(self):
        module = load_script_module(self)
        classifier = getattr(module, "classify_vtt", None)
        self.assertIsNotNone(classifier, "classify_vtt should exist")

        body = (
            "WEBVTT\n\n1\n00:00:00.000 --> 00:00:07.000\n"
            "Well, that's not really freedom now, is it? a single JSON array. "
            "Do not include any extra text outside of the JSON string. "
            "When producing JSON you must follow the schema provided in the context.\n"
        )

        self.assertEqual(classifier(body, check_empty=False), "instruction_echo")

    def test_ignores_technical_json_speech(self):
        module = load_script_module(self)
        classifier = getattr(module, "classify_vtt", None)
        self.assertIsNotNone(classifier, "classify_vtt should exist")

        body = (
            "WEBVTT\n\n1\n00:00:00.000 --> 00:00:08.000\n"
            "Today we're comparing a JSON array with a JSON object and explaining "
            "why valid JSON matters for API compatibility.\n"
        )

        self.assertIsNone(classifier(body, check_empty=False))

    def test_ignores_overlapping_schema_speech(self):
        module = load_script_module(self)
        classifier = getattr(module, "classify_vtt", None)
        self.assertIsNotNone(classifier, "classify_vtt should exist")

        body = (
            "WEBVTT\n\n1\n00:00:00.000 --> 00:00:08.000\n"
            "In our API docs, follow the schema provided for each endpoint "
            "before sending the request body.\n"
        )

        self.assertIsNone(classifier(body, check_empty=False))

    def test_ignores_one_strong_with_weak_json_terms(self):
        module = load_script_module(self)
        classifier = getattr(module, "classify_vtt", None)
        self.assertIsNotNone(classifier, "classify_vtt should exist")

        body = (
            "WEBVTT\n\n1\n00:00:00.000 --> 00:00:08.000\n"
            "Follow the schema for this endpoint: it returns a JSON array, "
            "accepts a JSON object, and the docs call this the response schema.\n"
        )

        self.assertIsNone(classifier(body, check_empty=False))

    def test_ignores_overlapping_strong_markers(self):
        # Several STRONG markers overlapping inside one contiguous clause must
        # not reach the >=2 threshold (cluster counting, not raw substring hits).
        module = load_script_module(self)
        classifier = getattr(module, "classify_vtt", None)
        self.assertIsNotNone(classifier, "classify_vtt should exist")

        body = (
            "WEBVTT\n\n1\n00:00:00.000 --> 00:00:08.000\n"
            "The endpoint should return only a JSON object with the user's data.\n"
        )

        self.assertIsNone(classifier(body, check_empty=False))


if __name__ == "__main__":
    unittest.main()
