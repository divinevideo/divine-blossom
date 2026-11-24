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
if "-w" in args:
    sys.stdout.write(os.environ.get("FAKE_PREFLIGHT_STATUS", "400"))
"""

FAKE_GSUTIL = r"""#!/usr/bin/env python3
import json, os, sys
with open(os.environ["GSUTIL_LOG"], "a") as log:
    log.write(json.dumps({"args": sys.argv[1:]}) + "\n")
"""


class RepairThumbnailTokenTests(unittest.TestCase):
    def run_script(self, env_extra, check=True):
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = Path(tmp, "bin")
            bin_dir.mkdir()
            for name, body in (("curl", FAKE_CURL), ("gsutil", FAKE_GSUTIL)):
                path = bin_dir / name
                path.write_text(body)
                path.chmod(path.stat().st_mode | stat.S_IEXEC)
            curl_log = Path(tmp, "curl.log")
            gsutil_log = Path(tmp, "gsutil.log")
            env = {
                "PATH": f"{bin_dir}:{os.environ['PATH']}",
                "CURL_LOG": str(curl_log),
                "GSUTIL_LOG": str(gsutil_log),
                "MEDIA_URL": "https://media.test",
                **env_extra,
            }
            result = subprocess.run(
                ["bash", str(SCRIPT), "--thumbnail-only", HASH],
                env=env, capture_output=True, text=True, check=check,
            )
            calls = (
                [json.loads(line) for line in curl_log.read_text().splitlines()]
                if curl_log.exists()
                else []
            )
            gsutil_calls = (
                [json.loads(line) for line in gsutil_log.read_text().splitlines()]
                if gsutil_log.exists()
                else []
            )
        return result, calls, gsutil_calls

    def thumbnail_call(self, calls):
        matching = [c for c in calls if any(a.endswith(f"/thumbnail/{HASH}") for a in c["args"])]
        self.assertEqual(len(matching), 1)
        return matching[0]

    def test_sends_the_token_on_stdin_never_in_argv(self):
        result, calls, _ = self.run_script({"THUMBNAIL_SERVICE_TOKEN": " svc-token "})
        call = self.thumbnail_call(calls)
        self.assertIn("X-Divine-Thumbnail-Token: svc-token", call["stdin"])
        for c in calls:
            self.assertFalse(any("svc-token" in a for a in c["args"]), c)
            self.assertNotIn("-L", c["args"])
            self.assertNotIn("--location", c["args"])
        media = [c for c in calls if any("media.test" in a for a in c["args"])]
        self.assertTrue(media)
        self.assertTrue(all("svc-token" not in c["stdin"] for c in media))
        self.assertNotIn("svc-token", result.stdout + result.stderr)

    def test_sends_no_token_and_warns_when_unset(self):
        result, calls, _ = self.run_script({})
        call = self.thumbnail_call(calls)
        self.assertNotIn("X-Divine-Thumbnail-Token", call["stdin"])
        self.assertIn("THUMBNAIL_SERVICE_TOKEN", result.stderr)

    def test_warns_before_sending_the_token_to_another_host_with_opt_in(self):
        result, _, _ = self.run_script(
            {
                "THUMBNAIL_SERVICE_TOKEN": "svc-token",
                "UPLOAD_URL": "https://elsewhere.test",
                "ALLOW_NON_DEFAULT_UPLOAD_URL": "true",
            }
        )
        self.assertIn("elsewhere.test", result.stderr)
        self.assertNotIn("svc-token", result.stderr)

    def test_refuses_non_default_host_without_opt_in(self):
        result, calls, gsutil_calls = self.run_script(
            {
                "THUMBNAIL_SERVICE_TOKEN": "svc-token",
                "UPLOAD_URL": "https://elsewhere.test",
            },
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])
        self.assertEqual(gsutil_calls, [])
        self.assertNotIn("svc-token", result.stdout + result.stderr)

    def test_refuses_non_https_upload_url(self):
        result, calls, gsutil_calls = self.run_script(
            {
                "THUMBNAIL_SERVICE_TOKEN": "svc-token",
                "UPLOAD_URL": "http://elsewhere.test",
                "ALLOW_NON_DEFAULT_UPLOAD_URL": "true",
            },
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])
        self.assertEqual(gsutil_calls, [])
        self.assertNotIn("svc-token", result.stdout + result.stderr)

    def test_preflight_404_aborts_before_deleting_stored_thumbnail(self):
        result, calls, gsutil_calls = self.run_script(
            {
                "THUMBNAIL_SERVICE_TOKEN": "svc-token",
                "FAKE_PREFLIGHT_STATUS": "404",
            },
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)
        self.assertTrue(any(a.endswith("/thumbnail/auth-check") for a in calls[0]["args"]))
        self.assertEqual(gsutil_calls, [])
        self.assertNotIn("svc-token", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
