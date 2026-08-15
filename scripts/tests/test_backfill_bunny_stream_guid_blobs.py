# ABOUTME: Tests for legacy Bunny Stream GUID extraction and migrate candidate construction.
# ABOUTME: Keeps the one-shot backfill script honest without touching the network.

import contextlib
import io
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "migration"))

from backfill_bunny_stream_guid_blobs import (  # noqa: E402
    BackfillCandidate,
    dedupe_candidates,
    extract_candidates,
    parse_args,
    parse_imeta_tag,
    select_pending_candidates,
    stream_guid_from_url,
)


SHA = "7ff36c72fb2644f1ac1761d0f728b2bb989df9fac0b8c68a716f4023ef4a39e0"
GUID = "35e9a15d-5db2-41f7-96fe-58c573ff8f21"


class TestParseImetaTag(unittest.TestCase):
    def test_space_separated_imeta_preserves_repeated_urls(self):
        parsed = parse_imeta_tag([
            "imeta",
            f"url https://stream.divine.video/{GUID}/play_480p.mp4",
            f"url https://cdn.divine.video/{SHA}.mp4",
            f"image https://stream.divine.video/{GUID}/thumbnail.jpg",
            f"x {SHA}",
        ])

        self.assertEqual(len(parsed["urls"]), 2)
        self.assertEqual(parsed["images"], [f"https://stream.divine.video/{GUID}/thumbnail.jpg"])
        self.assertEqual(parsed["x"], SHA)

    def test_alternating_imeta_preserves_repeated_urls(self):
        parsed = parse_imeta_tag([
            "imeta",
            "url", f"https://stream.divine.video/{GUID}/playlist.m3u8",
            "url", f"https://cdn.divine.video/{SHA}.mp4",
            "x", SHA,
        ])

        self.assertEqual(parsed["urls"], [
            f"https://stream.divine.video/{GUID}/playlist.m3u8",
            f"https://cdn.divine.video/{SHA}.mp4",
        ])
        self.assertEqual(parsed["url"], f"https://stream.divine.video/{GUID}/playlist.m3u8")


class TestCandidateExtraction(unittest.TestCase):
    def _event(self, tag):
        return {
            "id": "event-id",
            "pubkey": "pubkey",
            "created_at": 1750000000,
            "tags": [tag],
        }

    def test_extracts_guid_sha_mapping_from_stream_url_and_x_tag(self):
        candidates = extract_candidates(self._event([
            "imeta",
            f"url https://stream.divine.video/{GUID}/play_480p.mp4",
            f"url https://cdn.divine.video/{SHA}.mp4",
            f"image https://stream.divine.video/{GUID}/thumbnail.jpg",
            f"x {SHA}",
        ]))

        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(candidate.sha256, SHA)
        self.assertEqual(candidate.guid, GUID)
        self.assertEqual(candidate.source_urls[0], f"https://cdn.divine.video/{SHA}.mp4")
        self.assertIn(f"https://cdn.divine.video/{SHA}", candidate.source_urls)

    def test_skips_guid_event_without_x_hash(self):
        candidates = extract_candidates(self._event([
            "imeta",
            f"url https://stream.divine.video/{GUID}/play_480p.mp4",
        ]))

        self.assertEqual(candidates, [])

    def test_skips_non_stream_events(self):
        candidates = extract_candidates(self._event([
            "imeta",
            f"url https://cdn.divine.video/{SHA}.mp4",
            f"x {SHA}",
        ]))

        self.assertEqual(candidates, [])

    def test_extracts_video_hash_when_guid_appears_only_in_image(self):
        candidates = extract_candidates(self._event([
            "imeta",
            f"url https://cdn.divine.video/{SHA}.mp4",
            f"image https://stream.divine.video/{GUID}/thumbnail.jpg",
            f"x {SHA}",
        ]))

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].sha256, SHA)
        self.assertEqual(candidates[0].guid, GUID)

    def test_dedupes_by_hash_and_merges_source_urls(self):
        first = extract_candidates(self._event([
            "imeta",
            f"url https://stream.divine.video/{GUID}/play.mp4",
            f"x {SHA}",
        ]))[0]
        second = extract_candidates(self._event([
            "imeta",
            f"url https://stream.divine.video/{GUID}/playlist.m3u8",
            f"url https://cdn.divine.video/{SHA}.mp4",
            f"x {SHA}",
        ]))[0]

        merged = dedupe_candidates([first, second])

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].sha256, SHA)
        self.assertIn(f"https://cdn.divine.video/{SHA}.mp4", merged[0].source_urls)


class TestGuidParsing(unittest.TestCase):
    def test_extracts_only_stream_guid_path(self):
        self.assertEqual(
            stream_guid_from_url(f"https://stream.divine.video/{GUID}/thumbnail.jpg"),
            GUID,
        )
        self.assertIsNone(stream_guid_from_url(f"https://cdn.divine.video/{GUID}/thumbnail.jpg"))
        self.assertIsNone(stream_guid_from_url("https://stream.divine.video/not-a-guid/thumbnail.jpg"))


class TestArguments(unittest.TestCase):
    def test_write_targets_use_separate_default_progress_files(self):
        blossom_args = parse_args([])
        upload_service_args = parse_args(["--target", "upload-service"])

        self.assertEqual(
            blossom_args.progress_file,
            Path("bunny_stream_guid_backfill_progress.json"),
        )
        self.assertEqual(
            upload_service_args.progress_file,
            Path("bunny_stream_guid_upload_service_backfill_progress.json"),
        )

    def test_explicit_progress_file_is_preserved(self):
        args = parse_args(["--progress-file", "custom-progress.json"])

        self.assertEqual(args.progress_file, Path("custom-progress.json"))

    def test_nsec_cannot_be_passed_on_command_line(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parse_args(["--nsec", "secret"])

    def test_rejects_non_positive_concurrency(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parse_args(["--concurrency", "0"])


class TestPendingSelection(unittest.TestCase):
    def test_limit_is_applied_after_completed_candidates_are_removed(self):
        candidates = [
            BackfillCandidate(
                sha256=str(index).zfill(64),
                guid=GUID,
                event_id=str(index),
                pubkey="pubkey",
                created_at=index,
                source_urls=(f"https://cdn.divine.video/{str(index).zfill(64)}",),
            )
            for index in range(3)
        ]

        pending = select_pending_candidates(candidates, {candidates[0].sha256}, 1)

        self.assertEqual(pending, [candidates[1]])


if __name__ == "__main__":
    unittest.main()
