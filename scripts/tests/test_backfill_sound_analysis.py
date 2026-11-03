import importlib.util
from pathlib import Path
import unittest
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "backfill_sound_analysis.py"
SPEC = importlib.util.spec_from_file_location("backfill_sound_analysis", SCRIPT)
backfill = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backfill)

SHA_A = "a" * 64
SHA_B = "b" * 64


def row(sha, url=None):
    return {"sha256": sha, "audio_url": url or f"https://media.divine.video/{sha}"}


class BlossomSoundHashesTest(unittest.TestCase):
    def test_keeps_blossom_hosted_sounds(self):
        self.assertEqual(backfill.blossom_sound_hashes([row(SHA_A), row(SHA_B.upper())]), [SHA_A, SHA_B])

    def test_skips_other_hosts_and_bad_hashes(self):
        rows = [
            row(SHA_A, "https://audio.nostr.build/x.mp3"),
            row("not-a-hash"),
            {"audio_url": f"https://media.divine.video/{SHA_B}"},
        ]
        self.assertEqual(backfill.blossom_sound_hashes(rows), [])


class IterSoundHashesTest(unittest.TestCase):
    def test_pages_until_empty_and_deduplicates(self):
        pages = {0: [row(SHA_A), row(SHA_B)], 2: [row(SHA_B)], 3: []}
        urls = []

        def fake_get(url):
            urls.append(url)
            offset = int(url.split("offset=")[1])
            return pages[offset]

        with mock.patch.object(backfill, "_get_json", side_effect=fake_get):
            self.assertEqual(list(backfill.iter_sound_hashes("https://api.example", None)), [SHA_A, SHA_B])
        self.assertEqual(len(urls), 3)
        self.assertIn("sort=recent", urls[0])

    def test_stops_at_max_sounds(self):
        with mock.patch.object(backfill, "_get_json", return_value=[row(SHA_A), row(SHA_B)]):
            self.assertEqual(list(backfill.iter_sound_hashes("https://api.example", 1)), [SHA_A])


if __name__ == "__main__":
    unittest.main()
