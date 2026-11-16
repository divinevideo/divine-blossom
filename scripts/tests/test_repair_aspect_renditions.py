import contextlib
from fractions import Fraction
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "repair_aspect_renditions.py"
SPEC = importlib.util.spec_from_file_location("repair_aspect_renditions", SCRIPT)
repair = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repair)
A, B, C = "a" * 64, "b" * 64, "c" * 64
SQUARE, WIDE = ((480, 480), Fraction(1)), ((1280, 720), Fraction(16, 9))


def audit_line(media_hash, affected=True, request=None):
    record = {"hash": media_hash, "affected": ["720p.mp4"] if affected else [], "probe_errors": []}
    if affected:
        record["request"] = request or {"hash": media_hash, "force": True}
    return json.dumps(record) + "\n"


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
            default = {"status": "complete", "hash": body["hash"], "hls_master": "", "variants": []}
            self.wfile.write(payload if payload is not None else json.dumps(default).encode())

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


class CandidateTests(unittest.TestCase):
    def test_only_audited_repair_requests_are_selected_in_order_once(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "audit.jsonl"
            path.write_text(audit_line(B) + audit_line(C, affected=False) + "\n" + audit_line(A) + audit_line(B))
            self.assertEqual(repair.candidates(path), [B, A])

    def test_malformed_requests_are_rejected(self):
        for request in [{"hash": B, "force": True}, {"hash": A, "force": False}, {"hash": A}]:
            with self.subTest(request=request), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "audit.jsonl"
                path.write_text(audit_line(A, request=request))
                with self.assertRaises(ValueError):
                    repair.candidates(path)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "audit.jsonl"
            path.write_text(json.dumps({"hash": "A" * 64, "request": {"hash": "A" * 64, "force": True}}))
            with self.assertRaises(ValueError):
                repair.candidates(path)


class RequestTests(unittest.TestCase):
    def submit(self, url):
        return repair.regenerate(repair.endpoint_url(url), "synthetic-repair", A, timeout=5)

    def test_forced_request_uses_repair_credential_and_completes(self):
        with worker() as (url, captured):
            self.assertEqual(self.submit(url), ("complete", ""))
        self.assertEqual(captured, [("/transcode", "synthetic-repair", {"hash": A, "force": True})])

    def test_worker_outcomes_are_classified_without_retrying(self):
        cases = [
            (401, b"invalid repair credential", "stop"),
            (503, b"repair not configured", "stop"),
            (400, b"bad request", "stop"),
            (500, b'{"error":"Repair requires an existing HLS master"}', "failed"),
            (502, b"bad gateway", "review"),
            (504, b"gateway timeout", "review"),
            (200, b"not json", "review"),
            (200, json.dumps({"status": "complete", "hash": B}).encode(), "review"),
            (200, json.dumps({"status": "processing", "hash": A}).encode(), "review"),
            (200, json.dumps({"status": "complete", "hash": A, "repair_lock_warning": "x"}).encode(), "review"),
            # A revision without repair support ignores force and keeps the stretched files.
            (200, json.dumps({"status": "already_exists", "hash": A}).encode(), "stop"),
        ]
        for status, payload, expected in cases:
            with self.subTest(status=status, payload=payload), worker(status, payload) as (url, captured):
                self.assertEqual(self.submit(url)[0], expected)
                self.assertEqual(len(captured), 1, "forced requests must not retry")

    def test_redirects_do_not_forward_credentials(self):
        for status in [301, 302, 307, 308]:
            with self.subTest(status=status), worker() as (other, leaked), \
                    worker(status, redirect=other) as (url, captured):
                self.assertEqual(self.submit(url)[0], "stop")
                self.assertEqual(leaked, [])
                self.assertEqual(len(captured), 1)

    def test_missing_response_needs_review(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.assertEqual(self.submit(f"http://127.0.0.1:{port}")[0], "review")

    def test_endpoint_and_credential_validation(self):
        self.assertEqual(repair.endpoint_url("https://worker.example"), "https://worker.example/transcode")
        for url in ["http://worker.example", "https://user:secret@worker.example",
                    "https://worker.example/?token=x", "https://worker.example/backfill-fmp4"]:
            with self.assertRaises(ValueError):
                repair.endpoint_url(url)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "secret"
            for value in ["", "line\nbreak", "x" * 4097]:
                path.write_text(value)
                with self.assertRaises(ValueError):
                    repair.repair_secret(path)


class VerifyTests(unittest.TestCase):
    def run_verify(self, geometries, missing=()):
        fetched = []

        def fetch(store):
            def inner(key, dest):
                fetched.append((store, key))
                if key in missing:
                    raise FileNotFoundError(key)
                Path(dest).write_text(key)
            return inner

        result = repair.verify(fetch("original"), fetch("primary"), A,
                               lambda path: geometries[Path(path).read_text()])
        return result, fetched

    def test_all_outputs_matching_the_original_pass(self):
        geometries = {A: SQUARE, **{f"{A}/{key}": ((720, 720), Fraction(1)) for key in repair.OUTPUTS}}
        result, fetched = self.run_verify(geometries)
        self.assertEqual(result, [])
        self.assertEqual(fetched[0], ("original", A))
        self.assertEqual([key for _store, key in fetched[1:]], [f"{A}/{key}" for key in repair.OUTPUTS])
        self.assertTrue(all(store == "primary" for store, _key in fetched[1:]))

    def test_stretched_or_missing_outputs_are_reported(self):
        geometries = {A: SQUARE, **{f"{A}/{key}": ((720, 720), Fraction(1)) for key in repair.OUTPUTS}}
        geometries[f"{A}/hls/stream_480p.ts"] = WIDE
        result, _ = self.run_verify(geometries, missing={f"{A}/hls/stream_720p.mp4"})
        self.assertEqual(result, ["hls/stream_720p.mp4", "hls/stream_480p.ts"])

    def test_verification_reuses_the_audit_geometry_rules(self):
        self.assertTrue(repair.AUDIT_SCRIPT.exists())
        self.assertTrue(callable(repair.load_audit().probe))


class MainTests(unittest.TestCase):
    def invoke(self, folder, outcomes=None, verified=None, args=(), lines=None):
        audit = Path(folder) / "audit.jsonl"
        audit.write_text("".join(lines if lines is not None else [audit_line(A), audit_line(B), audit_line(C)]))
        secret = Path(folder) / "secret"
        secret.write_text("synthetic-repair")
        stdout, stderr = io.StringIO(), io.StringIO()
        submitted = []

        def regenerate(_url, _secret, media_hash, _timeout):
            submitted.append(media_hash)
            return (outcomes or {}).get(media_hash, ("complete", ""))

        def verify(original_store, output_store, media_hash, _probe):
            # Defaults: the original from authoritative GCS, outputs from the B2 primary.
            self.assertEqual((original_store, output_store), ("gcs", "b2"))
            return (verified or {}).get(media_hash, [])

        with mock.patch.dict(os.environ, {"TRANSCODE_REPAIR_SECRET_FILE": str(secret)}), \
                mock.patch.dict(repair.FETCHERS, {"b2": lambda: "b2", "gcs": lambda: "gcs"}), \
                mock.patch.object(repair, "regenerate", side_effect=regenerate), \
                mock.patch.object(repair, "verify", side_effect=verify), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = repair.main(["--audit-file", str(audit), *args])
        self.assertNotIn("synthetic-repair", stdout.getvalue() + stderr.getvalue())
        return code, submitted, stdout.getvalue()

    def state(self, folder, name):
        path = Path(folder) / f"aspect-repair-{name}.txt"
        return path.read_text().splitlines() if path.exists() else []

    def test_repairs_serially_and_records_only_verified_hashes_as_done(self):
        with tempfile.TemporaryDirectory() as folder:
            code, submitted, _ = self.invoke(folder, outcomes={B: ("failed", "worker reported a repair error")})
            self.assertEqual(code, 1)
            self.assertEqual(submitted, [A, B, C], "a definite worker failure does not block the batch")
            self.assertEqual(self.state(folder, "done"), [A, C])
            self.assertEqual(self.state(folder, "failed"), [f"{B}\tworker reported a repair error"])

    def test_unknown_outcome_or_failed_verification_stops_for_review(self):
        for outcomes, verified in [({A: ("review", "no response")}, {}), ({}, {A: ["hls/stream_720p.mp4"]})]:
            with self.subTest(outcomes=outcomes), tempfile.TemporaryDirectory() as folder:
                code, submitted, _ = self.invoke(folder, outcomes=outcomes, verified=verified)
                self.assertEqual(code, 1)
                self.assertEqual(submitted, [A])
                self.assertEqual(self.state(folder, "done"), [])
                self.assertEqual(len(self.state(folder, "review")), 1)
                self.assertTrue(self.state(folder, "review")[0].startswith(A + "\t"))

    def test_configuration_stop_records_nothing_and_submits_nothing_more(self):
        with tempfile.TemporaryDirectory() as folder:
            code, submitted, _ = self.invoke(folder, outcomes={A: ("stop", "worker ignored force")})
            self.assertEqual(code, 2)
            self.assertEqual(submitted, [A])
            for name in ("done", "failed", "review"):
                self.assertEqual(self.state(folder, name), [])

    def test_previous_state_is_honoured_and_limit_applies(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "aspect-repair-done.txt").write_text(A + "\n")
            Path(folder, "aspect-repair-review.txt").write_text(B + "\tno response\n")
            Path(folder, "aspect-repair-failed.txt").write_text(C + "\terror\n")
            _, submitted, _ = self.invoke(folder)
            self.assertEqual(submitted, [])
            _, submitted, _ = self.invoke(folder, args=["--retry-failed", "--limit", "1"])
            self.assertEqual(submitted, [C])

    def test_dry_run_never_reads_credentials_requests_or_writes_state(self):
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(repair, "repair_secret", side_effect=AssertionError("secret read")):
            Path(folder, "aspect-repair-done.txt").write_text(A + "\n")
            code, submitted, stdout = self.invoke(folder, args=["--dry-run"])
            self.assertEqual(code, 0)
            self.assertEqual(submitted, [])
            self.assertEqual(stdout.splitlines(), [B, C])
            self.assertEqual(sorted(p.name for p in Path(folder).iterdir()),
                             ["aspect-repair-done.txt", "audit.jsonl", "secret"])

    def test_missing_credential_or_bad_audit_stops_before_any_request(self):
        with tempfile.TemporaryDirectory() as folder:
            audit = Path(folder) / "audit.jsonl"
            audit.write_text(audit_line(A))
            with mock.patch.dict(os.environ, {}, clear=True), \
                    mock.patch.object(repair, "regenerate") as regenerate, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(repair.main(["--audit-file", str(audit)]), 2)
                audit.write_text(audit_line(A, request={"hash": B, "force": True}))
                self.assertEqual(repair.main(["--audit-file", str(audit), "--dry-run"]), 2)
            regenerate.assert_not_called()

    def test_shell_entrypoint_passes_arguments(self):
        result = subprocess.run(["bash", str(SCRIPT.with_name("repair-aspect-renditions.sh")), "--help"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--audit-file", result.stdout)


if __name__ == "__main__":
    unittest.main()
