#!/usr/bin/env python3
"""Exercise bounded all-version private family erasure against loopback only."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parent.parent
PRIVATE = '_private/artifact-families/v1/'


class Provider(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith('/fixture/begin/'):
            self.server.attempt = int(self.path.rsplit('/', 1)[1])
            self.server.calls = []
            return self.reply(200, {})
        if self.path == '/fixture/end':
            calls = self.server.calls
            deletes = [body for path, body in calls if path.endswith('b2_delete_file_version')]
            ok = len(calls) <= 8 and len(deletes) <= 4
            if self.server.case == 'c' and self.server.attempt == 0:
                ok = ok and not deletes
            self.server.counts.append((len(calls), len(deletes)))
            return self.reply(200 if ok else 500, {})
        self.reply(404, {})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        with self.server.lock:
            if self.path == '/delete-blobs':
                attempt = self.server.cloud_attempts
                self.server.cloud_attempts += 1
                results = []
                for index, hash_value in enumerate(body['hashes']):
                    pending = attempt == 0 or (attempt == 1 and index == 1)
                    results.append({'hash': hash_value, 'status': 'retryable' if pending else 'completed',
                                    'main_deleted_or_absent': True, 'failures': [],
                                    'private_family': 'remaining' if pending and index == 1 else 'absent',
                                    'bounded_progress': pending})
                pending = any(result['status'] == 'retryable' for result in results)
                return self.reply(503 if pending else 200,
                                  {'status': 'retryable' if pending else 'completed', 'results': results})
            self.server.calls.append((self.path, body))
            case, attempt = self.server.case, self.server.attempt
            if self.path.endswith('b2_list_file_versions'):
                prefix = body['prefix']
                private = prefix.startswith(PRIVATE)
                if private and attempt == 0 and case == '2':
                    return self.reply(200, {})
                if private and attempt == 0 and case == 'c':
                    return self.reply(503, {})
                if private and attempt == 0 and case == 'f':
                    self.server.private_lists += 1
                    if self.server.private_lists == 2:
                        self.server.versions.add((prefix + 'complete.json', 'late-version'))
                if private and attempt == 0 and case == 'e':
                    self.server.private_lists += 1
                    if self.server.private_lists == 2:
                        return self.reply(503, {})
                matches = sorted((key, version) for key, version in self.server.versions
                                 if key.startswith(prefix))
                size = body['maxFileCount']
                page, tail = matches[:size], matches[size:]
                return self.reply(200, {
                    'files': [{'fileName': key, 'fileId': version} for key, version in page],
                    'nextFileName': tail[0][0] if tail else None,
                    'nextFileId': tail[0][1] if tail else None,
                })
            if self.path.endswith('b2_delete_file_version'):
                if case == 'd' and attempt == 0:
                    return self.reply(503, {})
                self.server.versions.discard((body['fileName'], body['fileId']))
                return self.reply(200, {})
            self.reply(404, {})


def main():
    for case, attempts in [('a', 1), ('b', 4), ('c', 2), ('d', 2), ('e', 2), ('f', 2), ('0', 1), ('2', 2), ('3', 1), ('4', 3)]:
        hash_value = case * 64
        marker = f'{PRIVATE}{hash_value}/complete.json'
        sibling = (f'{PRIVATE}{hash_value}0/complete.json', 'sibling')
        versions = {(marker, f'version-{index:02}') for index in range(13 if case == 'b' else 2)}
        versions.add(sibling)
        if case == '0':
            for letter in ('0', '1'):
                versions.update({(letter * 64, f'original-{i}') for i in range(2)})
            versions.update({(f'{PRIVATE}{"1" * 64}/complete.json', f'version-{i:02}') for i in range(2)})
        original_versions = versions.copy()
        with ThreadingHTTPServer(('127.0.0.1', 0), Provider) as server:
            server.case, server.attempt = case, 0
            server.versions, server.calls, server.counts = versions, [], []
            server.private_lists, server.lock = 0, threading.Lock()
            server.cloud_attempts = 0
            threading.Thread(target=server.serve_forever, daemon=True).start()
            with tempfile.TemporaryDirectory(prefix='family-erasure-') as directory:
                root = Path(directory)
                config, kv, settings = [root / name for name in ('fastly.toml', 'kv.json', 'settings.json')]
                kv.write_text(json.dumps({f'b2-sync:v1:{hash_value}': {'data': json.dumps({'state': 'copying'})}}
                                         if case == '3' else {}))
                settings.write_text(json.dumps({'fixture_case': case, 'fixture_attempts': str(attempts),
                                               'b2_replica_enabled': 'true',
                                               'b2_cdn_purge_hosts': 'media-b2-cdn.divine.video'}))
                config.write_text(f'''manifest_version = 3
name = "synthetic-family-erasure"
language = "rust"
[local_server.backends.b2_api]
url = "http://127.0.0.1:{server.server_port}"
[local_server.backends.cloud_run_upload]
url = "http://127.0.0.1:{server.server_port}"
[local_server.kv_stores.blossom_metadata]
file = "{kv}"
format = "json"
[local_server.config_stores.blossom_config]
file = "{settings}"
format = "json"
''')
                env = os.environ.copy()
                env['CARGO_TARGET_WASM32_WASIP1_RUNNER'] = shlex.join([
                    env.get('VICEROY', 'viceroy'), 'run', '-C', str(config), '--'])
                result = subprocess.run(['cargo', 'test', '--locked', '--target', 'wasm32-wasip1',
                                         '--bin', 'fastly-blossom',
                                         'storage::tests::private_cloud_progress_reaches_physical_pending_and_retains_audio_discovery'
                                         if case == '4' else 'storage::tests::private_family_erasure_contract',
                                         '--', '--ignored', '--exact', '--nocapture'],
                                        cwd=ROOT, env=env, text=True, capture_output=True, timeout=900)
                if result.returncode or '1 passed; 0 failed' not in result.stdout:
                    raise RuntimeError(result.stdout + result.stderr)
                if case == '4':
                    assert server.cloud_attempts == 3 and not server.calls
                    print('PASS private Cloud Run receipts: Pending convergence, final receipts, and audio discovery retention')
                    server.shutdown()
                    continue
                if case == '3':
                    assert server.versions == original_versions and server.counts == [(0, 0)]
                else:
                    assert server.versions == {sibling}, (case, server.versions)
                assert len(server.counts) == attempts * (2 if case == '0' else 1)
                if case == '0':
                    assert server.counts == [(8, 4), (8, 4)], server.counts
                    assert sum(count for count, _ in server.counts) + 10 == 26
                detail = 'copy gate held without provider requests' if case == '3' else 'retained generations drained'
                print(f'PASS private family {case}: {detail}; attempt (requests,deletes)={server.counts}')
            server.shutdown()


if __name__ == '__main__':
    main()
