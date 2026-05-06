# ABOUTME: Pure unit tests for the NeMo Hypothesis → wire-format mapping.
# ABOUTME: Does not load NeMo or torch; exercises _hypothesis_to_result directly.

import sys
import types
import unittest
from dataclasses import dataclass

# Stub heavy imports so tests run without torch/nemo installed.
sys.modules.setdefault(
    "torch",
    types.SimpleNamespace(cuda=types.SimpleNamespace(is_available=lambda: False)),
)
sys.modules.setdefault("nemo", types.ModuleType("nemo"))
sys.modules.setdefault("nemo.collections", types.ModuleType("nemo.collections"))
sys.modules.setdefault("nemo.collections.asr", types.ModuleType("nemo.collections.asr"))
sys.modules.setdefault(
    "nemo.collections.asr.models",
    types.SimpleNamespace(ASRModel=types.SimpleNamespace(from_pretrained=lambda **_: None)),
)

# Make `app` importable when running as `python -m unittest discover tests`
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.transcribe import _hypothesis_to_result  # noqa: E402


@dataclass
class FakeHypothesis:
    text: str
    timestamp: dict


class TestHypothesisMapping(unittest.TestCase):
    def test_word_and_segment_timestamps_produce_segments(self):
        hyp = FakeHypothesis(
            text="hello world",
            timestamp={
                "word": [
                    {"word": "hello", "start": 0.0, "end": 0.5},
                    {"word": "world", "start": 0.6, "end": 1.0},
                ],
                "segment": [
                    {"segment": "hello world", "start": 0.0, "end": 1.0},
                ],
            },
        )
        out = _hypothesis_to_result(hyp, language="en")

        self.assertEqual(out.language, "en")
        self.assertEqual(len(out.segments), 1)
        seg = out.segments[0]
        self.assertEqual(seg.text, "hello world")
        self.assertEqual(seg.start, 0.0)
        self.assertEqual(seg.end, 1.0)
        self.assertEqual([w.word for w in seg.words], ["hello", "world"])

    def test_only_word_timestamps_collapse_to_single_segment(self):
        hyp = FakeHypothesis(
            text="just words",
            timestamp={
                "word": [
                    {"word": "just", "start": 0.0, "end": 0.4},
                    {"word": "words", "start": 0.5, "end": 0.9},
                ],
                "segment": [],
            },
        )
        out = _hypothesis_to_result(hyp, language=None)

        self.assertEqual(len(out.segments), 1)
        seg = out.segments[0]
        self.assertEqual(seg.start, 0.0)
        self.assertEqual(seg.end, 0.9)
        self.assertEqual(seg.text, "just words")
        self.assertEqual(len(seg.words), 2)

    def test_empty_text_and_no_timestamps_yields_no_segments(self):
        hyp = FakeHypothesis(text="", timestamp={"word": [], "segment": []})
        out = _hypothesis_to_result(hyp, language=None)
        self.assertEqual(out.segments, [])

    def test_text_without_timestamps_emits_untimed_segment(self):
        hyp = FakeHypothesis(text="some speech", timestamp={})
        out = _hypothesis_to_result(hyp, language=None)
        self.assertEqual(len(out.segments), 1)
        self.assertEqual(out.segments[0].text, "some speech")
        self.assertEqual(out.segments[0].words, [])

    def test_blank_word_entries_are_filtered(self):
        hyp = FakeHypothesis(
            text="hi there",
            timestamp={
                "word": [
                    {"word": "  ", "start": 0.0, "end": 0.1},
                    {"word": "hi", "start": 0.2, "end": 0.4},
                    {"word": "", "start": 0.4, "end": 0.5},
                    {"word": "there", "start": 0.6, "end": 1.0},
                ],
                "segment": [],
            },
        )
        out = _hypothesis_to_result(hyp, language=None)
        self.assertEqual([w.word for w in out.segments[0].words], ["hi", "there"])

    def test_to_dict_shape_matches_wire_format(self):
        hyp = FakeHypothesis(
            text="x",
            timestamp={
                "word": [{"word": "x", "start": 0.1, "end": 0.2}],
                "segment": [{"segment": "x", "start": 0.0, "end": 0.3}],
            },
        )
        out = _hypothesis_to_result(hyp, language="en").to_dict()
        self.assertEqual(out["language"], "en")
        self.assertEqual(out["segments"][0]["text"], "x")
        self.assertEqual(out["segments"][0]["start"], 0.0)
        self.assertEqual(out["segments"][0]["end"], 0.3)
        self.assertEqual(
            out["segments"][0]["words"][0],
            {"word": "x", "start": 0.1, "end": 0.2},
        )


if __name__ == "__main__":
    unittest.main()
