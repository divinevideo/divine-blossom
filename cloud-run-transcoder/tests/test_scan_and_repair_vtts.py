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

    def test_classifies_automated_caption_prompt_echo(self):
        module = load_script_module(self)
        classifier = getattr(module, "classify_vtt", None)
        self.assertIsNotNone(classifier, "classify_vtt should exist")

        body = (
            "WEBVTT\n\n1\n00:00:00.000 --> 00:00:07.000\n"
            "Why this matters this transcript is consumed by an automated caption "
            "pipeline that can only parse the exact JSON shape below.\n"
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

    def test_ignores_split_generic_schema_speech(self):
        # Generic fragments that were once markers ("output requirements",
        # "follow the schema", "provided in the context") must not drop a
        # legitimate transcript when ordinary words separate them.
        module = load_script_module(self)
        classifier = getattr(module, "classify_vtt", None)
        self.assertIsNotNone(classifier, "classify_vtt should exist")

        for spoken in (
            "Our API output requirements changed, so please follow the schema "
            "in the new docs.",
            "You should follow the schema that was provided in the context of "
            "the previous lesson.",
            "Our output requirements say to return only a JSON object for each "
            "user record.",
        ):
            body = f"WEBVTT\n\n1\n00:00:00.000 --> 00:00:08.000\n{spoken}\n"
            self.assertIsNone(
                classifier(body, check_empty=False),
                f"legitimate speech must not classify as bad: {spoken!r}",
            )

    def test_marker_scan_normalizes_c0_controls(self):
        # A single contiguous instruction split only by a C0 control char is
        # one phrase, matching the Rust gate's control normalization.
        module = load_script_module(self)
        has_echo = getattr(module, "has_instruction_echo", None)
        self.assertIsNotNone(has_echo, "has_instruction_echo should exist")
        self.assertFalse(
            has_echo("do not include any extra text\x1coutside of the json")
        )


def _rust_marker_list(declaration: str) -> tuple:
    """Extract a `const NAME: &[&str] = &[...]` string list from main.rs."""
    rust_path = SCRIPT_PATH.parent / "src" / "main.rs"
    source = rust_path.read_text(encoding="utf-8")
    start = source.index(declaration) + len(declaration)
    end = source.index("];", start)
    return tuple(
        line.strip().strip(",").strip('"')
        for line in source[start:end].splitlines()
        if line.strip()
    )


class MarkerParityTests(unittest.TestCase):
    """The Rust gate and the Python scanner must use the same marker list."""

    def test_rust_and_python_strong_markers_match(self):
        module = load_script_module(self)
        python_markers = tuple(module.INSTRUCTION_ECHO_STRONG_MARKERS)
        rust_markers = _rust_marker_list("const STRONG_MARKERS: &[&str] = &[")

        self.assertEqual(
            rust_markers,
            python_markers,
            "STRONG_MARKERS drifted between main.rs and scan_and_repair_vtts.py",
        )

    def test_rust_and_python_current_prompt_markers_match(self):
        module = load_script_module(self)

        self.assertEqual(
            _rust_marker_list("const EXACT_PROMPT_MARKERS_CURRENT: &[&str] = &["),
            tuple(module.INSTRUCTION_ECHO_EXACT_PROMPT_MARKERS_CURRENT),
            "EXACT_PROMPT_MARKERS_CURRENT drifted between main.rs and "
            "scan_and_repair_vtts.py",
        )

    def test_rust_and_python_retired_prompt_markers_match(self):
        module = load_script_module(self)

        self.assertEqual(
            _rust_marker_list("const EXACT_PROMPT_MARKERS_RETIRED: &[&str] = &["),
            tuple(module.INSTRUCTION_ECHO_EXACT_PROMPT_MARKERS_RETIRED),
            "EXACT_PROMPT_MARKERS_RETIRED drifted between main.rs and "
            "scan_and_repair_vtts.py",
        )

    def test_combined_marker_tuple_is_current_plus_retired(self):
        """The combined tuple is what the scanner actually scans.

        Without this, dropping RETIRED from the combination would leave every
        other parity test green while the scanner silently diverged from Rust.
        """
        module = load_script_module(self)

        self.assertEqual(
            module.INSTRUCTION_ECHO_EXACT_PROMPT_MARKERS,
            module.INSTRUCTION_ECHO_EXACT_PROMPT_MARKERS_CURRENT
            + module.INSTRUCTION_ECHO_EXACT_PROMPT_MARKERS_RETIRED,
        )
        self.assertTrue(
            module.INSTRUCTION_ECHO_EXACT_PROMPT_MARKERS_CURRENT
            and module.INSTRUCTION_ECHO_EXACT_PROMPT_MARKERS_RETIRED,
            "neither marker list may be empty; the parity tests would pass vacuously",
        )

    def test_current_prompt_markers_match_the_live_rust_prompt(self):
        """Mirror of the Rust `current_prompt_markers_still_match` guard.

        A marker whose punctuation differs from the prompt would be inert; the
        scanner normalizer does not strip punctuation either.
        """
        module = load_script_module(self)
        rust_path = SCRIPT_PATH.parent / "src" / "main.rs"
        source = rust_path.read_text(encoding="utf-8")
        start = source.index("fn build_gemini_prompt(")
        prompt_source = source[start : source.index("\n}\n", start)]
        normalized = module.normalize_for_marker_scan(
            prompt_source.replace("\\\n", "").replace("\\", "")
        )

        for marker in module.INSTRUCTION_ECHO_EXACT_PROMPT_MARKERS_CURRENT:
            self.assertIn(
                marker,
                normalized,
                f"marker {marker!r} no longer appears in build_gemini_prompt",
            )

    def test_exact_markers_do_not_flag_audio_engineering_speech(self):
        """No exact marker may be a phrase a real speaker could plausibly utter.

        The scanner repairs on a single match, so a generic marker would wipe
        legitimate captions.
        """
        module = load_script_module(self)

        for speech in (
            "The model has to classify the dominant sound in each clip "
            "before we run the tagger.",
            "Our job is to classify the dominant sound in a recording, then label it.",
            "Please classify the dominant sound in every scene before editing.",
            "If the VTT is overwritten, the pipeline cannot recover the "
            "captions automatically.",
            "This bug means the pipeline cannot recover the captions after a failed export.",
            "This transcript is consumed by an automated caption pipeline, so keep it clean.",
            "Our validator can only parse the exact JSON shape below.",
            "Heads up, the importer can only parse the exact JSON shape below.",
            "The old client has no ability to parse markdown, prose preambles, "
            "code fences, or XML.",
        ):
            self.assertFalse(
                module.has_instruction_echo(speech),
                f"legitimate speech must not be flagged: {speech!r}",
            )

    def test_each_exact_prompt_marker_flags_on_its_own(self):
        module = load_script_module(self)

        for marker in module.INSTRUCTION_ECHO_EXACT_PROMPT_MARKERS:
            self.assertTrue(
                module.has_instruction_echo(marker),
                f"exact marker {marker!r} should be conclusive on a single match",
            )


if __name__ == "__main__":
    unittest.main()
