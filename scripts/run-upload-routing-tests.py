#!/usr/bin/env python3
"""Actual upload handlers against a loopback-only provider service."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class UploadService(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_PUT(self):
        self.handle_upload()

    def do_POST(self):
        self.handle_upload()

    def handle_upload(self):
        self.connection.settimeout(5)
        body = self.rfile.read(int(self.headers['Content-Length']))
        self.server.observed.append((self.command, self.path, body, self.headers.get('Content-Type'),
                                     bool(self.headers.get('Authorization', '').startswith('Nostr '))))
        mismatch = self.server.case == 'hash_mismatch'
        payload = json.dumps({'sha256': 'a'*64, 'size': 15, 'content_type': 'image/jpeg'}).encode() if mismatch else b'{"error":"fixture busy"}'
        if self.server.case == 'busy_without_retry_after':
            payload = b''
        if self.server.case == 'busy_non_utf8':
            payload = b'\xff'
        status = 200 if mismatch else 500 if self.server.case.endswith('origin_error') else 503
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        retry_after = {
            'enabled': '5',
            'busy_retry_date': 'Wed, 11 Nov 2026 00:00:00 GMT',
            'busy_rfc850_date': 'Sunday, 06-Nov-94 08:49:37 GMT',
            'busy_malformed_date': 'Sunday, 06-Nov-94X08:49:37 GMT',
            'busy_non_utf8': '5',
            'busy_invalid_retry_after': '+5',
            'origin_error': '5',
            'complete_busy': '5',
            'complete_origin_error': '5',
        }.get(self.server.case)
        if retry_after is not None:
            self.send_header('Retry-After', retry_after)
        self.end_headers()
        self.wfile.write(payload)


def main():
    direct_cases = [
        'enabled', 'busy_retry_date', 'busy_rfc850_date', 'busy_malformed_date',
        'busy_non_utf8', 'busy_invalid_retry_after', 'busy_without_retry_after',
        'origin_error', 'hash_mismatch',
    ]
    complete_cases = ['complete_busy', 'complete_origin_error']
    cases = direct_cases + complete_cases + ['default', 'disabled', 'invalid', 'invalid_auth', 'missing_store', 'tombstone', 'missing_policy', 'dedupe', 'bad_size']
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', choices=cases)
    selected = parser.parse_args().case
    repo = Path(__file__).resolve().parent.parent
    with ThreadingHTTPServer(('127.0.0.1', 0), UploadService) as server:
        server.observed = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix='upload-routing-') as directory:
                root = Path(directory)
                settings, config, case_file, kv = root/'settings.json', root/'fastly.toml', root/'case.json', root/'kv.json'
                for case in ([selected] if selected else cases):
                    values = {'local_mode': 'false'}
                    if case != 'default':
                        values['upload_service_all_uploads'] = {'disabled': 'false', 'invalid': 'invalid'}.get(case, 'true')
                    settings.write_text(json.dumps(values))
                    case_file.write_text(json.dumps({'test_case': case}))
                    values_kv = {}
                    if case == 'tombstone':
                        values_kv['tombstone:' + hashlib.sha256(b'synthetic image').hexdigest()] = json.dumps({'reason': 'synthetic removal'})
                    kv.write_text(json.dumps(values_kv))
                    policy = '' if case == 'missing_policy' else f'''[local_server.kv_stores.blossom_metadata]
file = "{kv}"
format = "json"
'''
                    optional = '' if case == 'missing_store' else f'''[local_server.config_stores.blossom_config]
file = "{settings}"
format = "json"
'''
                    config.write_text(f'''manifest_version = 3
name = "upload-routing-test"
language = "rust"
[local_server.backends.upload_service]
url = "http://127.0.0.1:{server.server_port}"
[local_server.config_stores.routing_test]
file = "{case_file}"
format = "json"
{optional}{policy}''')
                    env = os.environ.copy()
                    # Cargo's environment runner is whitespace-split, not a
                    # shell command; TOML array preserves paths containing spaces.
                    env.pop('CARGO_TARGET_WASM32_WASIP1_RUNNER', None)
                    runner = json.dumps([env.get('VICEROY', 'viceroy'), 'run', '-C', str(config), '--'])
                    before = len(server.observed)
                    server.case = case
                    subprocess.run(['cargo', '--config', f'target.wasm32-wasip1.runner={runner}', 'test', '--locked', '--target', 'wasm32-wasip1',
                                    '--bin', 'fastly-blossom', 'canonical_upload_routing_contract',
                                    '--', '--ignored', '--nocapture'], cwd=repo, env=env, check=True, timeout=120)
                    expected = []
                    if case in direct_cases:
                        expected = [('PUT', '/upload', b'synthetic image', 'image/jpeg', True)]
                    elif case in complete_cases:
                        body = json.dumps({'sha256': 'a' * 64}, separators=(',', ':')).encode()
                        expected = [('POST', '/upload/synthetic/complete', body, 'application/json', True)]
                    if server.observed[before:] != expected:
                        raise AssertionError(f'{case}: unexpected loopback upload calls')
                    print(f'PASS canonical upload routing: {case}', flush=True)
        finally:
            server.shutdown()
            thread.join()


if __name__ == '__main__':
    main()
