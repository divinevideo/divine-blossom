#!/usr/bin/env python3
"""Exercise real Fastly KV, registration, erasure exclusion and signed range delivery."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Origin(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass
    def do_GET(self):
        assert self.path.startswith('/b2/')
        assert self.headers.get('Range') == 'bytes=1-3'
        assert 'Credential=' in self.headers.get('Authorization', '')
        self.server.reads += 1
        self.send_response(206)
        self.send_header('Content-Length', '3')
        self.send_header('Content-Range', 'bytes 1-3/9')
        self.end_headers()
        self.wfile.write(b'ynt')

def main():
    repo = Path(__file__).resolve().parent.parent
    with ThreadingHTTPServer(('127.0.0.1', 0), Origin) as origin:
        origin.reads = 0
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory(prefix='archive-import-fixture-') as directory:
                root = Path(directory)
                kv, settings, config = root/'kv.json', root/'settings.json', root/'fastly.toml'
                settings.write_text(json.dumps({'archive_import_enabled':'true','b2_media_bucket':'b2','b2_media_region':'us-west-004', 'media_read_primary':'gcs','fos_read_enabled':'false'}))
                config.write_text(f'''manifest_version=3
name="archive-import-fixture"
language="rust"
[local_server.backends.b2_storage]
url="http://127.0.0.1:{origin.server_port}"
[local_server.kv_stores.blossom_metadata]
file="{kv}"
format="json"
[local_server.config_stores.blossom_config]
file="{settings}"
format="json"
[local_server.secret_stores]
blossom_secrets=[{{key="archive_import_token",data="fixture-importer"}},{{key="admin_token",data="fixture-admin"}},{{key="b2_media_access_key",data="fixture"}},{{key="b2_media_secret_key",data="fixture"}}]
''')
                env = os.environ.copy()
                env['CARGO_TARGET_WASM32_WASIP1_RUNNER'] = shlex.join([env.get('VICEROY','viceroy'),'run','-C',str(config),'--'])
                for name in ['archive_registration_retry_ownership_erasure_and_range','archive_routes_require_dedicated_auth_and_batch_results','archive_partial_admission_can_settle_without_record','archive_ownership_cas_rejects_writes_prepared_before_unlink','archive_paused_routes_drain_existing_admissions','archive_copy_settlement_requires_exact_release_proof']:
                    kv.write_text('{}')
                    values=json.loads(settings.read_text()); values['archive_import_enabled']='false' if name=='archive_paused_routes_drain_existing_admissions' else 'true'; settings.write_text(json.dumps(values))
                    result = subprocess.run(['cargo','test','--locked','--target','wasm32-wasip1','--bin','fastly-blossom',name,'--','--ignored','--nocapture'],cwd=repo,env=env,capture_output=True,text=True)
                    if result.returncode or 'test result: ok. 1 passed' not in result.stdout:
                        raise SystemExit(result.stdout+result.stderr)
                    print('PASS',name)
                assert origin.reads == 1, 'Registration must not read media; only the explicit range test may read it'
        finally:
            origin.shutdown()
if __name__ == '__main__':
    main()
