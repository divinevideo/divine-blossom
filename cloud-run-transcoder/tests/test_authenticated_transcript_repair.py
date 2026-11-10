import contextlib
import http.server
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'repair_recent_bad_vtts.py'


@contextlib.contextmanager
def server(response_code=200, redirect=None):
    captured = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers['Content-Length']))
            captured.append((self.path, self.headers.get('x-divine-repair-secret'), json.loads(body)))
            self.send_response(response_code)
            if redirect:
                self.send_header('Location', redirect)
            self.end_headers()
            self.wfile.write(json.dumps({'hash': 'a' * 64, 'status': 'complete'}).encode())

        def do_GET(self):
            captured.append(('GET ' + self.path, None, None))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({'videos': []}).encode())

        def log_message(self, *args):
            pass

    httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{httpd.server_port}', captured
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


class AuthenticatedTranscriptRepairTests(unittest.TestCase):
    def run_repair(self, endpoint, token='synthetic-private-repair', media_hash='a' * 64):
        with tempfile.TemporaryDirectory() as folder:
            secret = Path(folder) / 'existing-secret'
            secret.write_text(token)
            return subprocess.run([sys.executable, str(SCRIPT), '--repair-hash', media_hash,
                                   '--transcoder-url', endpoint, '--repair-secret-file', str(secret),
                                   '--timeout', '2'], capture_output=True, text=True)

    def test_existing_tool_can_force_worker_with_existing_credential(self):
        with server() as (endpoint, captured):
            result = self.run_repair(endpoint)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(captured, [('/transcribe', 'synthetic-private-repair', {'hash': 'a' * 64, 'force': True})])
        self.assertEqual(json.loads(result.stdout)['status'], 'complete')
        self.assertNotIn('synthetic-private-repair', result.stdout + result.stderr)

    def test_redirect_never_forwards_repair_credential(self):
        with server() as (other, leaked), server(307, other + '/transcribe') as (endpoint, captured):
            result = self.run_repair(endpoint)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(captured), 1)
        self.assertEqual(leaked, [])
        self.assertNotIn('synthetic-private-repair', result.stdout + result.stderr)

    def test_invalid_secret_or_hash_has_no_network_effect(self):
        for token, media_hash in [('', 'a' * 64), ('line\nbreak', 'a' * 64), ('valid', 'invalid')]:
            with server() as (endpoint, captured):
                result = self.run_repair(endpoint, token, media_hash)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(captured, [])

    def test_worker_failure_is_not_retried_or_reported_complete(self):
        for code in (401, 503):
            with server(code) as (endpoint, captured):
                result = self.run_repair(endpoint)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(captured), 1)
            self.assertNotIn('synthetic-private-repair', result.stdout + result.stderr)

    def test_scanner_uses_the_same_authenticated_worker_path(self):
        import importlib
        from unittest.mock import patch
        with patch.object(sys, 'path', [str(SCRIPT.parent), *sys.path]):
            scanner = importlib.import_module('scan_and_repair_vtts')
            with tempfile.TemporaryDirectory() as folder, server() as (endpoint, captured):
                secret = Path(folder) / 'secret'
                secret.write_text('synthetic-private-repair')
                status, payload = scanner.trigger_retranscription(
                    'http://127.0.0.1:9', 'a' * 64, 2,
                    transcoder_url=endpoint, repair_secret_file=str(secret))
        self.assertEqual(status, 200)
        self.assertEqual(payload['status'], 'complete')
        self.assertEqual(captured, [('/transcribe', 'synthetic-private-repair', {'hash': 'a' * 64, 'force': True})])

    def test_shell_authenticated_path_does_not_delete_gcs_copy(self):
        import os
        with tempfile.TemporaryDirectory() as folder, server() as (endpoint, captured):
            secret = Path(folder) / 'secret'
            secret.write_text('synthetic-private-repair')
            marker = Path(folder) / 'gsutil-called'
            fake = Path(folder) / 'gsutil'
            fake.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\nexit 99\n')
            fake.chmod(0o755)
            env = dict(os.environ, TRANSCODER_URL=endpoint,
                       TRANSCODE_REPAIR_SECRET_FILE=str(secret),
                       PATH=folder + os.pathsep + os.environ['PATH'])
            result = subprocess.run(['bash', str(SCRIPT.parent / 'repair-media-artifacts.sh'),
                                     '--transcript-only', '--delete-vtt-first', 'a' * 64],
                                    env=env, capture_output=True, text=True)
            self.assertFalse(marker.exists(), 'authenticated repair must not issue a GCS-only delete')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(captured), 1)
        self.assertNotIn('synthetic-private-repair', result.stdout + result.stderr)

    def test_single_hash_dry_run_neither_reads_secret_nor_issues_request(self):
        for existing_secret in (False, True):
            with tempfile.TemporaryDirectory() as folder, server() as (endpoint, captured):
                secret = Path(folder) / 'credential'
                if existing_secret:
                    secret.write_text('synthetic-private-repair')
                result = subprocess.run([sys.executable, str(SCRIPT), '--repair-hash', 'a' * 64,
                                         '--transcoder-url', endpoint, '--repair-secret-file', str(secret),
                                         '--dry-run'], capture_output=True, text=True)
                self.assertEqual(captured, [], 'dry-run must never request regeneration')
            self.assertEqual(result.returncode, 0, 'dry-run must not open even a missing credential file')
            self.assertEqual(json.loads(result.stdout)['status'], 'dry_run')
            self.assertNotIn('synthetic-private-repair', result.stdout + result.stderr)


    def test_empty_single_hash_never_falls_into_batch_scanning(self):
        for dry_run in (False, True):
            with tempfile.TemporaryDirectory() as folder, server() as (endpoint,captured):
                command=[sys.executable,str(SCRIPT),'--repair-hash','', '--transcoder-url',endpoint,
                         '--repair-secret-file',str(Path(folder)/'missing'), '--relay-api',endpoint]
                if dry_run:
                    command.append('--dry-run')
                result=subprocess.run(command,capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(captured,[], 'empty explicit target must never become a scanner request')

    def test_empty_authenticated_options_never_select_legacy_batch(self):
        with server() as (endpoint,captured):
            result=subprocess.run([sys.executable,str(SCRIPT),'--transcoder-url','',
                                   '--repair-secret-file','', '--relay-api',endpoint],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(captured,[])

    def test_shell_empty_explicit_auth_configuration_never_selects_legacy(self):
        import os
        with tempfile.TemporaryDirectory() as folder, server() as (endpoint,captured):
            marker=Path(folder)/'gsutil-called'
            fake=Path(folder)/'gsutil'
            fake.write_text('#!/bin/sh\ntouch "'+str(marker)+'"\nexit 99\n')
            fake.chmod(0o755)
            env=dict(os.environ,TRANSCODER_URL='',TRANSCODE_REPAIR_SECRET_FILE='',MEDIA_URL=endpoint,
                     PATH=folder+os.pathsep+os.environ['PATH'])
            result=subprocess.run(['bash',str(SCRIPT.parent/'repair-media-artifacts.sh'),'--transcript-only',
                                   '--delete-vtt-first','a'*64],env=env,capture_output=True,text=True)
            self.assertFalse(marker.exists(), 'missing explicit auth config must not issue a GCS-only delete')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(captured,[])
