import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "probe_video_readiness.py"


def load_script_module(test_case: unittest.TestCase):
    if not SCRIPT_PATH.exists():
        test_case.fail(f"missing script: {SCRIPT_PATH}")

    spec = importlib.util.spec_from_file_location("probe_video_readiness", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        test_case.fail(f"unable to load script module: {SCRIPT_PATH}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class VideoReadinessProbeTests(unittest.TestCase):
    def test_classifies_mp4_delayed_after_hls(self):
        module = load_script_module(self)
        classify = getattr(module, "classify_observations", None)
        self.assertIsNotNone(classify, "classify_observations should exist")

        observations = [
            {
                "mp4_720": 404,
                "hls_master": 200,
                "hls_variant_manifest": 200,
            },
            {
                "mp4_720": 200,
                "hls_master": 200,
                "hls_variant_manifest": 200,
            },
        ]

        self.assertEqual(classify(observations), "mp4_delayed_hls_ready_first")

    def test_classifies_mp4_missing_while_hls_ready(self):
        module = load_script_module(self)
        classify = getattr(module, "classify_observations", None)
        self.assertIsNotNone(classify, "classify_observations should exist")

        observations = [
            {
                "mp4_720": 404,
                "hls_master": 200,
                "hls_variant_manifest": 200,
            },
            {
                "mp4_720": 404,
                "hls_master": 200,
                "hls_variant_manifest": 200,
            },
        ]

        self.assertEqual(classify(observations), "mp4_never_ready_hls_ready")

    def test_classifies_mp4_ready_immediately(self):
        module = load_script_module(self)
        classify = getattr(module, "classify_observations", None)
        self.assertIsNotNone(classify, "classify_observations should exist")

        observations = [
            {
                "mp4_720": 200,
                "hls_master": 200,
                "hls_variant_manifest": 200,
            }
        ]

        self.assertEqual(classify(observations), "mp4_ready_immediately")

    def test_builds_expected_probe_urls(self):
        module = load_script_module(self)
        builder = getattr(module, "build_target_urls", None)
        self.assertIsNotNone(builder, "build_target_urls should exist")

        media_hash = "a" * 64
        urls = builder("media.divine.video", media_hash)

        self.assertEqual(urls["mp4_720"], f"https://media.divine.video/{media_hash}/720p.mp4")
        self.assertEqual(urls["hls_master"], f"https://media.divine.video/{media_hash}.hls")
        self.assertEqual(
            urls["hls_variant_manifest"],
            f"https://media.divine.video/{media_hash}/hls/stream_720p.m3u8",
        )

    def test_extracts_hashes_from_mixed_lines(self):
        module = load_script_module(self)
        extractor = getattr(module, "extract_hashes", None)
        self.assertIsNotNone(extractor, "extract_hashes should exist")

        lines = [
            "832e9a4d6b9de70ceffb134ddd77b96b9b9de371457892092aa6aa853cd3f8a1",
            "https://media.divine.video/E3C2C5C7CFC7A35ED4120130D0363E25A63420A35642C20393758CB674D245C8/720p.mp4",
            "not a hash",
            "832e9a4d6b9de70ceffb134ddd77b96b9b9de371457892092aa6aa853cd3f8a1",
        ]

        self.assertEqual(
            extractor(lines),
            [
                "832e9a4d6b9de70ceffb134ddd77b96b9b9de371457892092aa6aa853cd3f8a1",
                "e3c2c5c7cfc7a35ed4120130d0363e25a63420a35642c20393758cb674d245c8",
            ],
        )


if __name__ == "__main__":
    unittest.main()
