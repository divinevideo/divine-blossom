"""cloud-run-upload/backfill-thumbnails.py sends the thumbnail token (divine-upload-server#52)."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

_spec = importlib.util.spec_from_file_location(
    "cloud_run_upload_backfill_thumbnails",
    Path(__file__).resolve().parents[2] / "cloud-run-upload" / "backfill-thumbnails.py",
)
helper = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(helper)


class ThumbnailServiceTokenTests(unittest.TestCase):
    def regenerate_headers(self, env):
        calls = []

        def fake_request(url, **kwargs):
            calls.append((url, kwargs))
            return 200

        with patch.dict("os.environ", env, clear=True), patch.object(helper, "request", side_effect=fake_request):
            helper.process_hash("a" * 64, "bucket", "https://upload.test", "https://media.test")
        regenerate = [kwargs for url, kwargs in calls if "/thumbnail/" in url]
        self.assertEqual(len(regenerate), 1)
        self.assertIs(regenerate[0].get("follow_redirects"), False)
        others = [kwargs for url, kwargs in calls if "/thumbnail/" not in url]
        for kwargs in others:
            self.assertNotIn("X-Divine-Thumbnail-Token", kwargs.get("headers") or {})
        return regenerate[0].get("headers") or {}

    def test_sends_the_service_token_when_configured(self):
        headers = self.regenerate_headers({"THUMBNAIL_SERVICE_TOKEN": " svc-token "})
        self.assertEqual(headers.get("X-Divine-Thumbnail-Token"), "svc-token")

    def test_sends_no_token_header_when_unset(self):
        self.assertNotIn("X-Divine-Thumbnail-Token", self.regenerate_headers({}))

    def test_warns_when_no_token_is_set(self):
        with patch.dict("os.environ", {}, clear=True):
            warnings = helper.thumbnail_token_warnings(helper.DEFAULT_UPLOAD_URL)
        self.assertEqual(len(warnings), 1)
        self.assertIn("THUMBNAIL_SERVICE_TOKEN", warnings[0])

    def test_quiet_with_a_token_for_the_default_host(self):
        with patch.dict("os.environ", {"THUMBNAIL_SERVICE_TOKEN": "svc"}, clear=True):
            self.assertEqual(helper.thumbnail_token_warnings(helper.DEFAULT_UPLOAD_URL), [])

    def test_warns_before_sending_the_token_to_another_host(self):
        with patch.dict("os.environ", {"THUMBNAIL_SERVICE_TOKEN": "svc"}, clear=True):
            warnings = helper.thumbnail_token_warnings("https://elsewhere.example")
        self.assertEqual(len(warnings), 1)
        self.assertIn("elsewhere.example", warnings[0])
        self.assertNotIn("svc", warnings[0])

    def test_rejects_non_https_and_unapproved_non_default_upload_urls(self):
        with self.assertRaises(ValueError):
            helper.validate_upload_url(
                "http://upload.example", allow_non_default=True, has_token=True
            )
        with self.assertRaises(ValueError):
            helper.validate_upload_url(
                "http://127.0.0.1:8080", allow_non_default=False, has_token=False
            )
        with self.assertRaises(ValueError):
            helper.validate_upload_url(
                "https://elsewhere.example", allow_non_default=False, has_token=True
            )
        self.assertEqual(
            helper.validate_upload_url(
                "https://elsewhere.example/", allow_non_default=True, has_token=True
            ),
            "https://elsewhere.example",
        )
        self.assertEqual(
            helper.validate_upload_url(
                "http://127.0.0.1:8080", allow_non_default=True, has_token=True
            ),
            "http://127.0.0.1:8080",
        )

    def test_redirects_never_forward_the_service_token(self):
        target_calls = []

        class RedirectHandler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                if self.path.startswith("/redirect-source"):
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/leaked")
                    self.end_headers()
                    return
                target_calls.append((self.path, dict(self.headers)))
                self.send_response(200)
                self.end_headers()

        with ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                status = helper.request(
                    f"http://127.0.0.1:{server.server_port}/redirect-source",
                    headers={"X-Divine-Thumbnail-Token": "svc-token"},
                    follow_redirects=False,
                )
            finally:
                server.shutdown()
                thread.join()
        self.assertEqual(status, 302)
        self.assertEqual(target_calls, [])

    def test_preflight_404_aborts_before_deleting_any_thumbnails(self):
        calls = []

        def fake_request(url, **kwargs):
            calls.append((url, kwargs))
            if url.endswith("/thumbnail/auth-check"):
                return 404
            return 200

        with (
            patch.dict("os.environ", {"THUMBNAIL_SERVICE_TOKEN": "svc-token"}, clear=True),
            patch.object(helper, "request", side_effect=fake_request),
            patch("sys.argv", ["backfill-thumbnails.py", "a" * 64]),
        ):
            with self.assertRaises(SystemExit) as ctx:
                helper.main()
        self.assertIn("404", str(ctx.exception))
        self.assertNotIn("svc-token", str(ctx.exception))
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][0].endswith("/thumbnail/auth-check"))
        self.assertIs(calls[0][1].get("follow_redirects"), False)

    def test_preflight_400_allows_batch_to_proceed(self):
        calls = []

        def fake_request(url, **kwargs):
            calls.append((url, kwargs))
            if url.endswith("/thumbnail/auth-check"):
                return 400
            return 200

        with (
            patch.dict("os.environ", {"THUMBNAIL_SERVICE_TOKEN": "svc-token"}, clear=True),
            patch.object(helper, "request", side_effect=fake_request),
            patch("sys.argv", ["backfill-thumbnails.py", "a" * 64]),
        ):
            helper.main()
        self.assertTrue(any(url.endswith("/thumbnail/auth-check") for url, _ in calls))
        self.assertTrue(any("storage.googleapis.com" in url for url, _ in calls))


if __name__ == "__main__":
    unittest.main()
