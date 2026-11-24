"""repair-media-artifacts.sh sends the upload service's thumbnail token (divine-upload-server#52)."""

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "repair-media-artifacts.sh"
HASH = "c" * 64
DEFAULT_UPLOAD = "https://blossom-upload-rust-149672065768.us-central1.run.app"

# Records each curl call: its argv and, when headers come from stdin, those headers.
FAKE_CURL = r"""#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
stdin_headers = sys.stdin.read() if "@-" in args else ""
with open(os.environ["CURL_LOG"], "a") as log:
    log.write(json.dumps({"args": args, "stdin": stdin_headers}) + "\n")
"""


class RepairThumbnailTokenTests(unittest.TestCase):
    def run_script(self, env_extra):
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = Path(tmp, "bin")
            bin_dir.mkdir()
            for name, body in (("curl", FAKE_CURL), ("gsutil", "#!/bin/sh\nexit 0\n")):
                path = bin_dir / name
                path.write_text(body)
                path.chmod(path.stat().st_mode | stat.S_IEXEC)
            log = Path(tmp, "curl.log")
            env = {
                "PATH": f"{bin_dir}:{os.environ['PATH']}",
                "CURL_LOG": str(log),
                "MEDIA_URL": "https://media.test",
                **env_extra,
            }
            result = subprocess.run(
                ["bash", str(SCRIPT), "--thumbnail-only", HASH],
                env=env, capture_output=True, text=True, check=True,
            )
            calls = [json.loads(line) for line in log.read_text().splitlines()]
        return result, calls

    def thumbnail_call(self, calls):
        matching = [c for c in calls if any(a.endswith(f"/thumbnail/{HASH}") for a in c["args"])]
        self.assertEqual(len(matching), 1)
        return matching[0]

    def test_sends_the_token_on_stdin_never_in_argv(self):
        result, calls = self.run_script({"THUMBNAIL_SERVICE_TOKEN": " svc-token "})
        call = self.thumbnail_call(calls)
        self.assertIn("X-Divine-Thumbnail-Token: svc-token", call["stdin"])
        for c in calls:
            self.assertFalse(any("svc-token" in a for a in c["args"]), c)
        media = [c for c in calls if any("media.test" in a for a in c["args"])]
        self.assertTrue(media)
        self.assertTrue(all("svc-token" not in c["stdin"] for c in media))
        self.assertNotIn("svc-token", result.stdout + result.stderr)

    def test_sends_no_token_and_warns_when_unset(self):
        result, calls = self.run_script({})
        call = self.thumbnail_call(calls)
        self.assertNotIn("X-Divine-Thumbnail-Token", call["stdin"])
        self.assertIn("THUMBNAIL_SERVICE_TOKEN", result.stderr)

    def test_warns_before_sending_the_token_to_another_host(self):
        result, _ = self.run_script(
            {"THUMBNAIL_SERVICE_TOKEN": "svc-token", "UPLOAD_URL": "https://elsewhere.test"}
        )
        self.assertIn("elsewhere.test", result.stderr)
        self.assertNotIn("svc-token", result.stderr)


if __name__ == "__main__":
    unittest.main()
