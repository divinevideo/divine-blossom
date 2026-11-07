#!/usr/bin/env python3
"""Real Viceroy KV/gate route proofs, synthetic stores only; no provider I/O."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    cases = [
        (True, True, "parent_gate_cas_fences_reacquisition_release_and_erase"),
        (True, True, "parent_gate_actual_routes_authenticate_before_body_and_fail_closed"),
        (False, True, "parent_gate_disabled_or_missing_secret_never_mutates"),
        (True, False, "parent_gate_disabled_or_missing_secret_never_mutates"),
        (True, True, "released_parent_gate_can_become_permanent_erasing"),
    ]
    with tempfile.TemporaryDirectory(prefix="parent-gate-tests-") as directory:
        root = Path(directory)
        config, kv, settings = root / "fastly.toml", root / "kv.json", root / "settings.json"
        for enabled, secret, test in cases:
            kv.write_text("{}")
            settings.write_text(json.dumps({"b2_parent_gate_enabled": "true" if enabled else "false"}))
            secrets = [{"key": "admin_token", "data": "fixture-admin-token"},
                       {"key": "b2_cdn_purge_drain_token", "data": "fixture-drain-token"}]
            if secret:
                secrets.append({"key": "b2_storage_coordination_token", "data": "fixture-coordination-token"})
            config.write_text(f'''manifest_version = 3
name = "parent-gate-tests"
language = "rust"
[local_server.kv_stores.blossom_metadata]
file = "{kv}"
format = "json"
[local_server.config_stores.blossom_config]
file = "{settings}"
format = "json"
[local_server.secret_stores]
blossom_secrets = {json.dumps(secrets).replace(': ', '=')}
'''.replace('"key"=', 'key=').replace('"data"=', 'data='))
            env = os.environ.copy()
            env["CARGO_TARGET_WASM32_WASIP1_RUNNER"] = shlex.join(
                [env.get("VICEROY", "viceroy"), "run", "-C", str(config), "--"])
            result = subprocess.run(["cargo", "test", "--locked", "--target", "wasm32-wasip1",
                                     "--bin", "fastly-blossom", test, "--", "--ignored", "--nocapture"],
                                    cwd=ROOT, env=env, capture_output=True, text=True)
            if result.returncode or "test result: ok. 1 passed; 0 failed; 0 ignored;" not in result.stdout:
                raise SystemExit(result.stdout + result.stderr)
            print(f"PASS {test} enabled={enabled} secret={secret}")


if __name__ == "__main__":
    main()
