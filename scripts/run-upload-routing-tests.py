#!/usr/bin/env python3
"""Actual canonical upload handler against loopback-only provider service."""
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
        body = self.rfile.read(int(self.headers['Content-Length']))
        self.server.observed.append((self.path, body, self.headers.get('Content-Type'),
                                     bool(self.headers.get('Authorization', '').startswith('Nostr '))))
        self.send_response(503)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b'{"error":"fixture busy"}')))
        self.end_headers()
        self.wfile.write(b'{"error":"fixture busy"}')


def main():
    repo = Path(__file__).resolve().parent.parent
    with ThreadingHTTPServer(('127.0.0.1', 0), UploadService) as server:
        server.observed = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix='upload-routing-') as directory:
                root = Path(directory)
                settings, config, case_file = root/'settings.json', root/'fastly.toml', root/'case.json'
                for case in ['enabled', 'default', 'disabled', 'invalid', 'invalid_auth', 'missing_store']:
                    values = {'local_mode': 'false'}
                    if case != 'default':
                        values['upload_service_all_uploads'] = {'disabled': 'false', 'invalid': 'invalid'}.get(case, 'true')
                    settings.write_text(json.dumps(values))
                    case_file.write_text(json.dumps({'test_case': case}))
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
{optional}''')
                    env = os.environ.copy()
                    # Cargo's environment runner is whitespace-split, not a
                    # shell command; TOML array preserves paths containing spaces.
                    env.pop('CARGO_TARGET_WASM32_WASIP1_RUNNER', None)
                    runner = json.dumps([env.get('VICEROY', 'viceroy'), 'run', '-C', str(config), '--'])
                    before = len(server.observed)
                    subprocess.run(['cargo', '--config', f'target.wasm32-wasip1.runner={runner}', 'test', '--locked', '--target', 'wasm32-wasip1',
                                    '--bin', 'fastly-blossom', 'canonical_upload_routing_contract',
                                    '--', '--ignored', '--nocapture'], cwd=repo, env=env, check=True)
                    expected = [('/upload', b'synthetic image', 'image/jpeg', True)] if case == 'enabled' else []
                    if server.observed[before:] != expected:
                        raise AssertionError(f'{case}: unexpected loopback upload calls')
                    print(f'PASS canonical upload routing: {case}', flush=True)
        finally:
            server.shutdown()
            thread.join()


if __name__ == '__main__':
    main()
