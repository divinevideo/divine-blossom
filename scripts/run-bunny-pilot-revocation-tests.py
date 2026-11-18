#!/usr/bin/env python3
"""Exercise Bunny pilot age-gating and checked eviction against loopback only."""

import hashlib
import json
import os
import shlex
import subprocess
import tempfile
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


ROOT = Path(__file__).resolve().parent.parent
HASH = 'a' * 64
B2_HOST = 'api.backblazeb2.com'
BUCKET = 'private-media-fixture'
BUCKET_ID = 'synthetic-bucket-id'
PREFIX = f'bunny-delivery/{HASH}'
CUSTOM_HOST = 'media-bunny.divine.video'
ALIAS = 'divine-media-pilot.b-cdn.net'
FASTLY_SERVICES = {'ML7R82HKfmTaqTpHExIDVN', 'pOvEEWykEbpnylqst1KTrR'}
TEST = 'quarantine_tests::bunny_pilot_age_gate_eviction_retries'
VERSIONS = {(PREFIX, 'original-v1'), (f'{PREFIX}/720p.mp4', '720p-v1'),
            (f'{PREFIX}/720p.mp4', '720p-v2')}


class Provider(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, payload, generation=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Type', 'application/json')
        if generation is not None:
            self.send_header('generation', generation)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith('/resources/stores/kv/fixture-store/keys/'):
            assert self.headers.get('Fastly-Key') == 'synthetic-policy-key'
            if '/bunny-pilot-enrolled:v1:' in self.path:
                if self.path.endswith(f':{HASH}'):
                    return self.reply(200, 1, '1')
                return self.reply(404, {})
            if self.path.endswith('/bunny-pilot-retained-hosts:v1'):
                body = f'{CUSTOM_HOST},{ALIAS}'.encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('generation', '1')
                self.end_headers()
                return self.wfile.write(body)
            assert self.path.endswith(f'/blob:{HASH}')
            return self.reply(200, {'sha256': HASH, 'size': 9, 'type': 'video/mp4',
                                    'uploaded': '2026-01-01T00:00:00Z',
                                    'owner': 'b' * 64, 'status': 'age_restricted'}, '1')
        if self.path != '/b2api/v4/b2_authorize_account':
            return self.reply(404, {})
        assert self.headers.get('Host') == B2_HOST
        assert self.headers.get('Authorization', '').startswith('Basic ')
        self.reply(200, {'authorizationToken': 'synthetic-b2-token', 'apiInfo': {'storageApi': {
            'apiUrl': f'https://{B2_HOST}',
            'allowed': {'buckets': [{'id': BUCKET_ID, 'name': BUCKET}],
                        'capabilities': ['listFiles', 'deleteFiles'], 'namePrefix': None},
        }}})

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        raw = self.rfile.read(length)
        with self.server.lock:
            try:
                status, payload = self.dispatch(raw)
            except (AssertionError, ValueError, KeyError) as error:
                self.server.errors.append(f'{self.path}: {error}')
                status, payload = 500, {}
        return self.reply(status, payload)

    def dispatch(self, raw):
        path = urlsplit(self.path)
        if path.path.startswith('/b2api/v4/'):
            assert self.headers.get('Host') == B2_HOST
            assert self.headers.get('Authorization') == 'synthetic-b2-token'
            return self.b2(path.path.rsplit('/', 1)[-1], json.loads(raw))
        if path.path == '/purge':
            return self.bunny(parse_qs(path.query))
        return self.fastly(path.path)

    def b2(self, operation, body):
        if operation == 'b2_list_file_versions':
            assert body['bucketId'] == BUCKET_ID
            assert body['prefix'] == body['startFileName'] == PREFIX
            versions = sorted(version for version in self.server.versions if version[0].startswith(PREFIX))
            self.server.events.append(('versions', len(versions)))
            return 200, {'files': [{'fileName': key, 'fileId': version} for key, version in versions],
                         'nextFileName': None, 'nextFileId': None}
        assert operation == 'b2_delete_file_version'
        version = (body['fileName'], body['fileId'])
        assert version in VERSIONS and version in self.server.versions
        self.server.versions.remove(version)
        self.server.events.append(('delete', version))
        return 200, body

    def bunny(self, params):
        assert self.headers.get('Host') == 'api.bunny.net'
        assert self.headers.get('AccessKey') == 'synthetic-bunny-key'
        assert params['async'] == ['false']
        assert len(params['url']) == 1
        target = urlsplit(params['url'][0])
        assert target.scheme == 'https' and target.netloc in (CUSTOM_HOST, ALIAS)
        assert target.path == f'/{HASH}*' and not target.query
        assert not (self.server.versions & VERSIONS)
        assert ('versions', 0) in self.server.events
        self.server.events.append(('bunny', target.netloc))
        self.server.bunny_counts[target.netloc] += 1
        if target.netloc == CUSTOM_HOST and self.server.bunny_counts[target.netloc] <= 2:
            return 503, {}
        return 200, {}

    def fastly(self, path):
        assert self.headers.get('Host') == 'api.fastly.com'
        assert self.headers.get('Fastly-Key') == 'synthetic-fastly-key'
        assert self.headers.get('Surrogate-Key') in (HASH, 'c' * 64)
        service = path.removeprefix('/service/').removesuffix('/purge')
        assert service in FASTLY_SERVICES and path == f'/service/{service}/purge'
        self.server.events.append(('fastly', service))
        return 200, {HASH: 'synthetic-purge-id'}


def manifest(port, kv, settings):
    native_backend = 'b2-api-' + hashlib.sha256(B2_HOST.encode()).hexdigest()[:16]
    backends = ('b2_api', native_backend, 'bunny_api', 'fastly_api', 'kv-origin-api')
    backend_sections = '\n'.join(
        f'[local_server.backends."{name}"]\nurl = "http://127.0.0.1:{port}"'
        for name in backends
    )
    return f'''manifest_version = 3
name = "synthetic-bunny-revocation"
language = "rust"
{backend_sections}
[local_server.kv_stores.blossom_metadata]
file = "{kv}"
format = "json"
[local_server.config_stores.blossom_config]
file = "{settings}"
format = "json"
[local_server.secret_stores]
blossom_secrets = [
  {{key="admin_token",data="synthetic-admin-token"}},
  {{key="b2_vanish_application_key_id",data="synthetic-b2-id"}},
  {{key="b2_vanish_application_key",data="synthetic-b2-key"}},
  {{key="bunny_api_key",data="synthetic-bunny-key"}},
  {{key="kv_origin_read_token",data="synthetic-policy-key"}},
  {{key="fastly_api_token",data="synthetic-fastly-key"}}
]
'''


def main():
    unrelated = {(HASH, 'canonical-original'), (f'bunny-delivery/{"b" * 64}', 'other-pilot-asset')}
    with ThreadingHTTPServer(('127.0.0.1', 0), Provider) as server:
        server.lock = threading.Lock()
        server.versions = VERSIONS | unrelated
        server.events, server.errors = [], []
        server.bunny_counts = Counter()
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory(prefix='bunny-pilot-revocation-') as directory:
                config, kv, settings = (Path(directory) / name for name in ('fastly.toml', 'kv.json', 'settings.json'))
                kv.write_text('{}')
                settings.write_text(json.dumps({'b2_bucket_id': BUCKET_ID, 'b2_media_bucket': BUCKET,
                                                'bunny_fixture_local_gate': 'true', 'metadata_kv_store_id': 'fixture-store',
                                                'bunny_pilot_zone_hosts': f'{CUSTOM_HOST},reconfigured-zone.b-cdn.net'}))
                config.write_text(manifest(server.server_port, kv, settings))
                env = os.environ.copy()
                env['CARGO_TARGET_WASM32_WASIP1_RUNNER'] = shlex.join([
                    env.get('VICEROY', 'viceroy'), 'run', '-C', str(config), '--',
                ])
                result = subprocess.run([
                    'cargo', 'test', '--locked', '--target', 'wasm32-wasip1', '--bin', 'fastly-blossom',
                    TEST, '--', '--ignored', '--exact', '--nocapture',
                ], cwd=ROOT, env=env, capture_output=True, text=True, timeout=900)
                if result.returncode or '1 passed; 0 failed' not in result.stdout or server.errors:
                    raise RuntimeError(result.stdout + result.stderr + repr(server.errors))
                assert server.versions == unrelated, server.versions
                assert Counter(entry for event, entry in server.events if event == 'delete') == Counter(VERSIONS)
                assert server.bunny_counts == {CUSTOM_HOST: 4, ALIAS: 4}, server.events
                assert Counter(entry for event, entry in server.events if event == 'fastly') == dict.fromkeys(FASTLY_SERVICES, 8), server.events
                print('PASS Bunny age gate, all-version replica removal, checked canonical and Bunny purges, durable retry')
        finally:
            server.shutdown()


if __name__ == '__main__':
    main()
