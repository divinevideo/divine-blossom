#!/usr/bin/env python3
"""Run request-boundary telemetry tests in Viceroy using synthetic local config."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

repo = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix="playback-telemetry-test-") as directory:
    root = Path(directory)
    settings, config = root / "settings.json", root / "fastly.toml"
    config.write_text(f'''manifest_version = 3
name = "playback-telemetry-test"
language = "rust"
[local_server.config_stores.blossom_config]
file = "{settings}"
format = "json"
''')
    env = os.environ.copy()
    env["CARGO_TARGET_WASM32_WASIP1_RUNNER"] = shlex.join([
        env.get("VICEROY", "viceroy"), "run", "-C", str(config), "--"])
    for flag in [None, "false", "TRUE", "true"]:
        values = {"b2_canary_host": "media-b2.divine.video", "test_telemetry_enabled": str(flag == "true").lower()}
        if flag is not None:
            values["b2_playback_telemetry_enabled"] = flag
        settings.write_text(json.dumps(values))
        tests = ["delivery_telemetry::tests::boundary_gates_and_resets_each_request"]
        if flag == "true":
            tests.append("delivery_telemetry::tests::boundary_emits_failures_and_fresh_ids_without_mutating_body_or_cache_policy")
        for test in tests:
            result = subprocess.run(["cargo", "test", "--locked", "--target", "wasm32-wasip1", "--bin", "fastly-blossom", test, "--", "--ignored", "--nocapture"], cwd=repo, env=env, text=True, capture_output=True, timeout=180)
            if result.returncode or "test result: ok. 1 passed; 0 failed;" not in result.stdout:
                raise RuntimeError(result.stdout + result.stderr)
            print(f"telemetry flag={flag}: {test.rsplit('::', 1)[-1]} passed")
