#!/usr/bin/env python3
"""Exercise canonical B2 misses and the existing demand queue using local fixtures."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HASH, OWNER = "a" * 64, "b" * 64

class Origin(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_GET(self):
        is_b2 = self.path == f"/private-test/{HASH}"
        assert is_b2 or self.path == f"/gcs-test/{HASH}"
        self.server.reads.append("b2" if is_b2 else "gcs")
        status = self.server.b2_status if is_b2 else self.server.gcs_status
        body = b"b2 bytes!" if is_b2 else b"gcsbytes!"
        if status == 200 and self.headers.get("Range"):
            status, body = 206, body[1:4]
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        if status == 206: self.send_header("Content-Range", "bytes 1-3/9")
        self.end_headers(); self.wfile.write(body)

def main():
    repo = Path(__file__).resolve().parent.parent
    with ThreadingHTTPServer(("127.0.0.1", 0), Origin) as server, tempfile.TemporaryDirectory(prefix="canonical-demand-") as directory:
        thread = threading.Thread(target=server.serve_forever, daemon=True);thread.start()
        try:
            root = Path(directory); config, settings, kv = root/"fastly.toml", root/"settings.json", root/"kv.json"
            config.write_text(f'''manifest_version = 3
name = "canonical-demand-test"
language = "rust"
[local_server.backends.b2_storage]
url = "http://127.0.0.1:{server.server_port}"
[local_server.backends.gcs_storage]
url = "http://127.0.0.1:{server.server_port}"
[local_server.kv_stores.blossom_metadata]
file = "{kv}"
format = "json"
[local_server.config_stores.blossom_config]
file = "{settings}"
format = "json"
[local_server.secret_stores]
blossom_secrets = [{{key="gcs_access_key",data="synthetic"}},{{key="gcs_secret_key",data="synthetic"}},{{key="b2_media_access_key",data="synthetic"}},{{key="b2_media_secret_key",data="synthetic"}}]
''')
            cases = [
                ("missing",404,True,True,200,["b2","gcs"]),
                ("hit",200,True,False,200,["b2"]),
                ("outage",503,True,False,200,["b2","gcs"]),
                ("flag_off",404,False,False,200,["b2","gcs"]),
                ("forbidden",403,True,False,502,["b2"]),
                ("gcs_unavailable",404,True,False,502,["b2","gcs"]),
                ("range",404,True,True,206,["b2","gcs"]),
                ("nonvideo",404,True,False,200,["b2","gcs"]),
                ("copying",404,True,False,200,["b2","gcs"]),
                ("quarantine",404,True,False,404,[]),
                ("authorization_present",404,True,False,401,[]),
                ("cookie_present",404,True,False,200,["b2","gcs"]),
            ]
            for name, status, enabled, hint, expected, reads in cases:
                server.b2_status, server.reads = status, []
                server.gcs_status = 503 if name == "gcs_unavailable" else 200
                metadata = {"sha256":HASH,"size":9,"type":"video/mp4","uploaded":"2026-01-01T00:00:00Z","owner":OWNER,"status":"active"}
                if name == "nonvideo": metadata['type'] = 'image/png'
                data = {f"blob:{HASH}":json.dumps(metadata)}
                if name == "copying": data[f"b2-sync:v1:{HASH}"] = json.dumps({'state':'copying','attempt_id':'synthetic'})
                if name == "quarantine":data[f"quarantine:v1:{HASH}"] = json.dumps({'version':1,'holds':{'review':{'version':1,'active':True}}})
                kv.write_text(json.dumps(data))
                values = {"media_read_primary":"b2","gcs_fallback_enabled":"true","gcs_bucket":"gcs-test","b2_media_bucket":"private-test","b2_media_region":"us-west-004","b2_demand_mirror_enabled":"true" if enabled else "false","test_expected_status":str(expected),"test_hint":"true" if hint else "false","test_body":"gcsbytes!"}
                if name == "hit":values['test_body'] = 'b2 bytes!'
                if name == "range":values.update(test_range='bytes=1-3',test_body='csb')
                if name == "authorization_present":values['test_authorization'] = ''
                if name == "cookie_present":values['test_cookie'] = ''
                settings.write_text(json.dumps(values))
                env = os.environ.copy();env["CARGO_TARGET_WASM32_WASIP1_RUNNER"] = shlex.join([env.get("VICEROY","viceroy"),"run","-C",str(config),"--"])
                result = subprocess.run(["cargo","test","--locked","--target","wasm32-wasip1","--bin","fastly-blossom","canonical_b2_miss_queues_copy_contract","--","--ignored","--nocapture"],cwd=repo,env=env,capture_output=True,text=True,timeout=300)
                if result.returncode or "test result: ok. 1 passed; 0 failed; 0 ignored;" not in result.stdout: raise RuntimeError(result.stdout+result.stderr)
                assert server.reads == reads, (name, server.reads)
                print(f"canonical demand case={name} passed")
        finally: server.shutdown();thread.join(timeout=5)

if __name__ == "__main__": main()
