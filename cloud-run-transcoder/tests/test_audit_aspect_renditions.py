import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import subprocess

SPEC = importlib.util.spec_from_file_location(
    "audit_aspect_renditions", Path(__file__).resolve().parents[1] / "audit_aspect_renditions.py"
)
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def geometry(width, height, **fields):
    return audit.geometry({"streams": [{"width": width, "height": height, **fields}]})


class AspectAuditTests(unittest.TestCase):
    def test_probe_disables_network_protocols(self):
        output = subprocess.CompletedProcess([], 0, '{"streams":[{"width":480,"height":480}]}', "")
        with patch.object(audit.subprocess, "run", return_value=output) as run:
            audit.probe("/export/derivatives/hash/hls/stream_720p.m3u8")
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("-protocol_whitelist") + 1], "file,crypto,data")

    def test_square_and_portrait_sources_are_selected(self):
        for source in (geometry(480, 480), geometry(480, 720)):
            for rendition in (geometry(1280, 720), geometry(854, 480)):
                self.assertTrue(audit.is_stretched(source, rendition))

    def test_correct_renditions_and_landscape_sources_are_not_selected(self):
        self.assertFalse(audit.is_stretched(geometry(480, 480), geometry(720, 720)))
        self.assertFalse(audit.is_stretched(geometry(1920, 1080), geometry(854, 480)))

    def test_rotation_and_sample_aspect_ratio_are_respected(self):
        rotated = geometry(1920, 1080, side_data_list=[
            {"side_data_type": "Display Matrix", "rotation": -90}
        ])
        self.assertTrue(audit.is_stretched(rotated, geometry(1280, 720)))
        anamorphic = geometry(720, 576, sample_aspect_ratio="64:45")
        self.assertFalse(audit.is_stretched(anamorphic, geometry(1280, 720)))
        self.assertFalse(audit.is_stretched(geometry(480, 480), geometry(
            1280, 720, sample_aspect_ratio="9:16")))

    def test_bad_probe_data_fails_closed(self):
        for document in ({"streams": []}, {"streams": [{"width": 0, "height": 480}]}):
            with self.assertRaises((ValueError, IndexError)):
                audit.geometry(document)
        with self.assertRaises(ValueError):
            geometry(480, 480, tags={"rotate": "45"})

    def test_checks_all_paths_even_when_one_is_missing(self):
        calls = []

        def probe(url):
            calls.append(url)
            if url.endswith("/stream_480p.mp4"):
                raise ValueError("missing")
            return geometry(480, 480) if url.endswith("/hash") else geometry(1280, 720)

        record = audit.audit_hash("hash", "/export", probe)
        self.assertEqual(len(calls), 5)
        self.assertEqual(record["probe_errors"], ["480p.mp4"])
        self.assertEqual(record["affected"], ["720p.mp4", "hls/stream_720p.m3u8", "hls/stream_480p.m3u8"])
        self.assertEqual(record["request"], {"hash": "hash", "force": True})

    def test_no_candidate_request_for_correct_video(self):
        record = audit.audit_hash("hash", "/export", lambda _: geometry(480, 480))
        self.assertNotIn("request", record)
