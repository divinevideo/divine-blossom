import contextlib
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "backfill_fmp4.py"
SPEC = importlib.util.spec_from_file_location("backfill_fmp4", SCRIPT)
backfill = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backfill)
A, B = "a" * 64, "b" * 64


@contextlib.contextmanager
def worker(status=200, payload=None, redirect=None):
    captured = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            captured.append((self.path, self.headers.get("x-divine-repair-secret"), body))
            self.send_response(status)
            if redirect:
                self.send_header("Location", redirect)
            self.end_headers()
            self.wfile.write(payload if payload is not None else json.dumps({"status": "ok", "hash": body["hash"]}).encode())

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", captured
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class DiscoveryTests(unittest.TestCase):
    def test_discovery_matches_both_variants_and_deduplicates_stores(self):
        with mock.patch.object(backfill, "b2_keys", return_value=iter([
            f"{A}/hls/stream_720p.ts", f"{A}/hls/stream_480p.ts",
            "invalid/hls/stream_720p.ts", f"{B}/hls/stream_720p.mp4",
        ])), mock.patch.object(backfill, "gcs_keys", return_value=iter([
            f"{A}/hls/stream_720p.ts", f"{B}/hls/stream_480p.ts",
        ])):
            self.assertEqual(list(backfill.discover("both")), [A, B])

    def test_b2_lists_every_page_and_uses_operator_configuration(self):
        import boto3
        client = mock.Mock()
        client.get_paginator.return_value.paginate.return_value = [
            {"Contents": [{"Key": f"{A}/hls/stream_720p.ts"}]}, {},
            {"Contents": [{"Key": f"{B}/hls/stream_480p.ts"}]},
        ]
        with mock.patch.dict(os.environ, {"B2_MEDIA_BUCKET": "synthetic-bucket", "B2_REGION": "us-west-004",
                "B2_APPLICATION_KEY_ID": "synthetic-key", "B2_APPLICATION_KEY": "synthetic-secret"}), \
                mock.patch.object(boto3, "client", return_value=client) as factory:
            self.assertEqual(list(backfill.discover("b2")), [A, B])
        client.get_paginator.assert_called_once_with("list_objects_v2")
        client.get_paginator.return_value.paginate.assert_called_once_with(Bucket="synthetic-bucket")
        self.assertEqual(factory.call_args.kwargs["endpoint_url"], "https://s3.us-west-004.backblazeb2.com")

    def test_gcs_uses_adc_and_configured_bucket_without_b2(self):
        from google.cloud import storage
        client = mock.Mock()
        client.list_blobs.return_value = [mock.Mock(name="blob")]
        client.list_blobs.return_value[0].name = f"{B}/hls/stream_480p.ts"
        with mock.patch.object(storage, "Client", return_value=client), \
                mock.patch.dict(os.environ, {"GCS_BUCKET": "gs://synthetic-legacy"}), \
                mock.patch.object(backfill, "b2_keys", side_effect=AssertionError("unexpected B2 listing")):
            self.assertEqual(list(backfill.discover("gcs")), [B])
        client.list_blobs.assert_called_once_with("synthetic-legacy", timeout=30)


class RequestTests(unittest.TestCase):
    def test_forced_request_uses_existing_credential_and_matching_response(self):
        with worker() as (url, captured):
            self.assertTrue(backfill.regenerate(backfill.endpoint_url(url), "synthetic-repair", A))
        self.assertEqual(captured, [("/backfill-fmp4", "synthetic-repair", {"hash": A, "force": True})])

    def test_failure_partial_or_malformed_response_is_not_success(self):
        for status, payload in [(500, b'{}'), (200, b'not json'), (200, b'[]'),
                (200, json.dumps({"status": "ok", "hash": B}).encode()),
                (200, json.dumps({"status": "partial", "hash": A}).encode()),
                (401, b'{}'), (503, b'{}')]:
            with self.subTest(status=status, payload=payload), worker(status, payload) as (url, captured):
                self.assertFalse(backfill.regenerate(backfill.endpoint_url(url), "synthetic-repair", A))
                self.assertEqual(len(captured), 1, "forced requests must not retry")

    def test_redirects_do_not_forward_credentials(self):
        for status in [301, 302, 303, 307, 308]:
            with self.subTest(status=status), worker() as (other, leaked), worker(status, redirect=other) as (url, captured):
                self.assertFalse(backfill.regenerate(backfill.endpoint_url(url), "synthetic-repair", A))
                self.assertEqual(leaked, [])
                self.assertEqual(len(captured), 1)

    def test_invalid_credentials_and_remote_http_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "secret"
            for value in ["", "line\nbreak", "x" * 4097]:
                path.write_text(value)
                with self.assertRaises(ValueError):
                    backfill.repair_secret(path)
        for url in ["http://worker.example", "https://user:secret@worker.example", "https://worker.example/?token=x"]:
            with self.assertRaises(ValueError):
                backfill.endpoint_url(url)


class MainTests(unittest.TestCase):
    def invoke(self, folder, hashes=(A, B), results=None, args=(), discovery=None):
        secret = Path(folder) / "secret"
        secret.write_text("synthetic-repair")
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"TRANSCODE_REPAIR_SECRET_FILE": str(secret)}), \
                mock.patch.object(backfill, "discover", side_effect=discovery, return_value=iter(hashes)) as discover, \
                mock.patch.object(backfill, "regenerate", side_effect=lambda _url, _secret, h: (results or {}).get(h, True)) as regenerate, \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = backfill.main(["--state-dir", folder, "--concurrency", "2", *args])
        self.assertNotIn("synthetic-repair", stdout.getvalue() + stderr.getvalue())
        return code, discover, regenerate, stdout.getvalue(), stderr.getvalue()

    def test_default_b2_tracks_only_successes_and_returns_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            code, discover, regenerate, _, _ = self.invoke(folder, results={A: True, B: False})
            self.assertEqual(code, 1)
            discover.assert_called_once_with("b2")
            self.assertEqual(regenerate.call_count, 2)
            self.assertEqual((Path(folder) / "backfill-fmp4-done.txt").read_text(), A + "\n")
            self.assertEqual((Path(folder) / "backfill-fmp4-failed.txt").read_text(), B + "\n")

    def test_existing_done_hashes_are_skipped_and_pending_workers_finish(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "backfill-fmp4-done.txt").write_text(A + "\n")
            code, _, regenerate, _, _ = self.invoke(folder)
            self.assertEqual(code, 0)
            self.assertEqual(regenerate.call_count, 1)
            self.assertEqual(regenerate.call_args.args[2], B)
            self.assertEqual((Path(folder) / "backfill-fmp4-done.txt").read_text(), A + "\n" + B + "\n")

    def test_discovery_failure_does_not_hide_completed_worker(self):
        def interrupted(_source):
            yield A
            raise RuntimeError("private provider diagnostic")
        with tempfile.TemporaryDirectory() as folder:
            code, _, _, _, stderr = self.invoke(folder, discovery=interrupted)
            self.assertEqual(code, 1)
            self.assertNotIn("private provider diagnostic", stderr)
            self.assertEqual((Path(folder) / "backfill-fmp4-done.txt").read_text(), A + "\n")

    def test_dry_run_never_reads_repair_secret_requests_or_writes_state(self):
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(backfill, "repair_secret", side_effect=AssertionError("secret read")):
            code, discover, regenerate, stdout, _ = self.invoke(folder, args=["--dry-run", "--source", "both"])
            self.assertEqual(code, 0)
            discover.assert_called_once_with("both")
            regenerate.assert_not_called()
            self.assertEqual(stdout.splitlines(), [A, B])
            self.assertFalse((Path(folder) / "backfill-fmp4-done.txt").exists())
            self.assertFalse((Path(folder) / "backfill-fmp4-failed.txt").exists())

    def test_missing_credential_stops_before_discovery(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(backfill, "discover") as discovery, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(backfill.main([]), 2)
            discovery.assert_not_called()

    def test_shell_entrypoint_passes_arguments(self):
        result = subprocess.run(["bash", str(SCRIPT.with_name("backfill-fmp4.sh")), "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--source", result.stdout)


if __name__ == "__main__":
    unittest.main()
