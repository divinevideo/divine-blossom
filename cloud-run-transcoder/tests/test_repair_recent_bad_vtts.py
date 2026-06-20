import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1] / "repair_recent_bad_vtts.py"
)


def load_script_module(test_case: unittest.TestCase):
    if not SCRIPT_PATH.exists():
        test_case.fail(f"missing script: {SCRIPT_PATH}")

    spec = importlib.util.spec_from_file_location(
        "repair_recent_bad_vtts", SCRIPT_PATH
    )
    if spec is None or spec.loader is None:
        test_case.fail(f"unable to load script module: {SCRIPT_PATH}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RepairRecentBadVttsTests(unittest.TestCase):
    def test_detects_json_corrupted_vtt_body(self):
        module = load_script_module(self)
        detector = getattr(module, "is_bad_vtt_body", None)
        self.assertIsNotNone(detector, "is_bad_vtt_body should exist")

        body = (
            'WEBVTT\n\n1\n00:00:00.000 --> 99:59:59.000\n{"text":"","usage":'
            '{"type":"tokens","total_tokens":48,"input_tokens":46}}\n'
        )

        self.assertTrue(detector(body))

    def test_ignores_valid_vtt_body(self):
        module = load_script_module(self)
        detector = getattr(module, "is_bad_vtt_body", None)
        self.assertIsNotNone(detector, "is_bad_vtt_body should exist")

        body = "WEBVTT\n\n1\n00:00:00.000 --> 00:00:01.000\nhello there\n"

        self.assertFalse(detector(body))

    def test_detects_instruction_echo_vtt_body(self):
        module = load_script_module(self)
        detector = getattr(module, "is_bad_vtt_body", None)
        self.assertIsNotNone(detector, "is_bad_vtt_body should exist")

        body = (
            "WEBVTT\n\n1\n00:00:00.000 --> 00:00:07.000\n"
            "Well, that's not really freedom now, is it? a single JSON array. "
            "Do not include any extra text outside of the JSON string. "
            "When producing JSON you must follow the schema provided in the context.\n"
        )

        self.assertTrue(detector(body))

    def test_ignores_technical_json_speech(self):
        module = load_script_module(self)
        detector = getattr(module, "is_bad_vtt_body", None)
        self.assertIsNotNone(detector, "is_bad_vtt_body should exist")

        body = (
            "WEBVTT\n\n1\n00:00:00.000 --> 00:00:08.000\n"
            "Today we're comparing a JSON array with a JSON object and explaining "
            "why valid JSON matters for API compatibility.\n"
        )

        self.assertFalse(detector(body))

    def test_ignores_overlapping_schema_speech(self):
        module = load_script_module(self)
        detector = getattr(module, "is_bad_vtt_body", None)
        self.assertIsNotNone(detector, "is_bad_vtt_body should exist")

        body = (
            "WEBVTT\n\n1\n00:00:00.000 --> 00:00:08.000\n"
            "In our API docs, follow the schema provided for each endpoint "
            "before sending the request body.\n"
        )

        self.assertFalse(detector(body))

    def test_ignores_one_strong_with_weak_json_terms(self):
        module = load_script_module(self)
        detector = getattr(module, "is_bad_vtt_body", None)
        self.assertIsNotNone(detector, "is_bad_vtt_body should exist")

        body = (
            "WEBVTT\n\n1\n00:00:00.000 --> 00:00:08.000\n"
            "Follow the schema for this endpoint: it returns a JSON array, "
            "accepts a JSON object, and the docs call this the response schema.\n"
        )

        self.assertFalse(detector(body))

    def test_ignores_overlapping_strong_markers(self):
        # Ordinary speech where several STRONG markers overlap inside one
        # contiguous clause must not trip the gate (cluster counting).
        module = load_script_module(self)
        detector = getattr(module, "is_bad_vtt_body", None)
        self.assertIsNotNone(detector, "is_bad_vtt_body should exist")

        body = (
            "WEBVTT\n\n1\n00:00:00.000 --> 00:00:08.000\n"
            "The endpoint should return only a JSON object with the user's data.\n"
        )

        self.assertFalse(detector(body))

    def test_detects_instruction_echo_split_across_cues(self):
        # The normal Gemini path emits one cue per segment, so a leaked
        # instruction is split across cue boundaries. Detecting on spoken
        # text (not the raw body) keeps the phrases contiguous.
        module = load_script_module(self)
        detector = getattr(module, "is_bad_vtt_body", None)
        self.assertIsNotNone(detector, "is_bad_vtt_body should exist")

        body = (
            "WEBVTT\n\n"
            "1\n00:00:00.000 --> 00:00:03.000\na single JSON array.\n\n"
            "2\n00:00:03.000 --> 00:00:06.000\n"
            "Do not include any extra text outside of the JSON string.\n\n"
            "3\n00:00:06.000 --> 00:00:09.000\n"
            "Follow the schema provided in the context.\n"
        )

        self.assertTrue(detector(body))

    def test_collects_recent_media_hashes_with_age_filter_and_dedupe(self):
        module = load_script_module(self)
        collector = getattr(module, "collect_recent_media_hashes", None)
        self.assertIsNotNone(
            collector, "collect_recent_media_hashes should exist"
        )

        fresh_hash = "a" * 64
        other_hash = "b" * 64
        cutoff_unix = 1_700_000_000
        videos = [
            {
                "created_at": cutoff_unix + 50,
                "video_url": f"https://media.divine.video/{fresh_hash}",
            },
            {
                "published_at": cutoff_unix + 60,
                "video_url": f"https://media.divine.video/{other_hash}.mp4",
            },
            {
                "created_at": cutoff_unix + 70,
                "video_url": f"https://media.divine.video/{fresh_hash}",
            },
            {
                "created_at": cutoff_unix - 1,
                "video_url": (
                    "https://media.divine.video/"
                    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                ),
            },
            {
                "created_at": cutoff_unix + 80,
                "video_url": f"https://cdn.divine.video/{'d' * 64}",
            },
            {
                "created_at": cutoff_unix + 90,
                "video_url": "https://media.divine.video/not-a-hash",
            },
        ]

        self.assertEqual(
            collector(videos, cutoff_unix),
            [fresh_hash, other_hash],
        )


if __name__ == "__main__":
    unittest.main()
