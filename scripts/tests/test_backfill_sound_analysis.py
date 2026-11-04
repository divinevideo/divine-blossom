import importlib.util
import json
import os
from pathlib import Path
import tempfile
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


class ReadHashesTest(unittest.TestCase):
    def write(self, text):
        f = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        f.write(text)
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_reads_unique_hashes_and_skips_comments(self):
        path = self.write(f"# silent sounds\n{SHA_A}\n\n{SHA_B.upper()}  # click\n{SHA_A}\n")
        self.assertEqual(backfill.read_hashes(path), [SHA_A, SHA_B])

    def test_rejects_a_line_that_is_not_a_hash(self):
        with self.assertRaises(ValueError):
            backfill.read_hashes(self.write("not-a-hash\n"))


class MainTest(unittest.TestCase):
    def run_main(self, results, env=None, args=()):
        calls = []

        def fake_analyze(url, secret, sha, force=False):
            calls.append((sha, force))
            result = results[sha]
            return result if isinstance(result, tuple) else (result, None)

        with mock.patch.object(backfill, "iter_sound_hashes", return_value=[SHA_A, SHA_B]), \
                mock.patch.object(backfill, "analyze", side_effect=fake_analyze), \
                mock.patch.dict(backfill.os.environ, {"TRANSCRIBE_SHARED_SECRET": "s"} if env is None else env, clear=True), \
                mock.patch("sys.stdout") as out, mock.patch("sys.stderr") as err:
            code = backfill.main(["--transcoder-url", "https://t.example", *args])
        self.calls = calls
        self.summary = "".join(str(c.args[0]) for c in out.write.call_args_list)
        return code, "".join(str(c.args[0]) for c in err.write.call_args_list)

    def test_settled_outcomes_exit_zero(self):
        code, _ = self.run_main({SHA_A: "classified", SHA_B: "missing"})
        self.assertEqual(code, 0)
        self.assertEqual(self.calls, [(SHA_A, False), (SHA_B, False)])

    def test_failures_exit_one_and_name_the_hash(self):
        code, err = self.run_main({SHA_A: "classified", SHA_B: "http_502"})
        self.assertEqual(code, 1)
        self.assertIn(f"failed {SHA_B}: http_502", err)

    def test_refuses_to_run_without_the_secret(self):
        code, _ = self.run_main({SHA_A: "classified", SHA_B: "classified"}, env={})
        self.assertEqual(code, 2)

    def test_counts_silent_sounds_and_writes_their_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "silent.txt")
            code, _ = self.run_main(
                {SHA_A: ("classified", True), SHA_B: ("classified", False)},
                args=["--silent-out", out],
            )
            with open(out) as f:
                self.assertEqual(f.read(), f"{SHA_A}\n")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(self.summary)["silent"], 1)

    def test_force_is_passed_to_every_request(self):
        self.run_main({SHA_A: "classified", SHA_B: "classified"}, args=["--force"])
        self.assertEqual(self.calls, [(SHA_A, True), (SHA_B, True)])

    def test_hashes_file_replaces_the_sound_listing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "hashes.txt")
            with open(path, "w") as f:
                f.write(f"{SHA_B}\n")
            self.run_main({SHA_B: "classified"}, args=["--hashes-file", path])
        self.assertEqual(self.calls, [(SHA_B, False)])


if __name__ == "__main__":
    unittest.main()
