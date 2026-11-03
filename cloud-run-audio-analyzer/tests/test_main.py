# ABOUTME: Tests the HTTP contract of /v1/analyze with a fake tagger.
# ABOUTME: Needs fastapi, httpx, numpy and ffmpeg; never loads torch.

import os
import shutil
import sys
import unittest

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402
from test_audio import _tone, _wav  # noqa: E402


class FakeTagger:
    model_name = "fake"

    def __init__(self, scores):
        self._scores = scores
        self.calls = 0

    def scores(self, samples):
        self.calls += 1
        return self._scores


@unittest.skipUnless(shutil.which("ffmpeg"), "ffmpeg is not installed")
class TestAnalyzeEndpoint(unittest.TestCase):
    def setUp(self):
        # TestClient without a `with` block skips the lifespan, so no model loads.
        self.client = TestClient(main.app)
        self.tagger = FakeTagger({"Music": 0.9, "Classical music": 0.4, "Piano": 0.8})
        main._tagger = self.tagger

    def tearDown(self):
        main._tagger = None

    def test_returns_kind_tags_and_scores(self):
        r = self.client.post("/v1/analyze", content=_wav(_tone(6.0)))
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["kind"], "music")
        self.assertEqual(body["tags"], ["music", "classical", "piano"])
        self.assertEqual(body["model"], "fake")
        self.assertEqual(body["pipeline_version"], main.PIPELINE_VERSION)
        self.assertAlmostEqual(body["analyzed_seconds"], 6.0, places=1)
        self.assertFalse(body["silent"])

    def test_silent_audio_is_not_classified(self):
        r = self.client.post("/v1/analyze", content=_wav(np.zeros(48000 * 3)))
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body["silent"])
        self.assertIsNone(body["kind"])
        self.assertEqual(body["tags"], [])
        self.assertEqual(self.tagger.calls, 0)

    def test_empty_body_is_rejected(self):
        self.assertEqual(self.client.post("/v1/analyze", content=b"").status_code, 400)

    def test_undecodable_body_is_rejected(self):
        self.assertEqual(self.client.post("/v1/analyze", content=b"not audio").status_code, 422)

    def test_oversized_body_is_rejected(self):
        original = main.MAX_AUDIO_BYTES
        main.MAX_AUDIO_BYTES = 10
        try:
            r = self.client.post("/v1/analyze", content=_wav(_tone(1.0)))
        finally:
            main.MAX_AUDIO_BYTES = original
        self.assertEqual(r.status_code, 413)

    def test_unready_service_returns_503(self):
        main._tagger = None
        self.assertEqual(self.client.post("/v1/analyze", content=_wav(_tone(1.0))).status_code, 503)
        self.assertEqual(self.client.get("/healthz").status_code, 503)


if __name__ == "__main__":
    unittest.main()
