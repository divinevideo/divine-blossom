#!/usr/bin/env python3
"""Run b2_cdn_purge lifecycle tests against a local Viceroy KV store.

Only synthetic configuration and a throwaway local KV store are used. No
Fastly, B2, GCS, purge credential, or network provider is contacted: the purge
callback in each test is a pure function.
"""
import json
import os
import re
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
def storage_tests():
    """Run every ignored lifecycle test, including newly added regressions."""
    source = (ROOT / "src/b2_cdn_purge.rs").read_text().split("mod storage {", 1)[1]
    tests = [
        f"b2_cdn_purge::tests::storage::{name}"
        for name in re.findall(r'#\[ignore = "[^"]*"\]\s*fn (\w+)\(\) \{', source)
    ]
    if not tests:
        raise RuntimeError("No outbox lifecycle tests discovered")
    return tests



def main():
    with tempfile.TemporaryDirectory(prefix="b2-cdn-purge-outbox-") as directory:
        root = Path(directory)
        manifest, kv = root / "fastly.toml", root / "kv.json"
        kv.write_text("{}")
        manifest.write_text(f'''manifest_version = 3
name = "b2-cdn-purge-outbox-test"
language = "rust"
[local_server.kv_stores.blossom_metadata]
file = "{kv}"
format = "json"
''')
        env = os.environ.copy()
        env["CARGO_TARGET_WASM32_WASIP1_RUNNER"] = shlex.join(
            [env.get("VICEROY", "viceroy"), "run", "-C", str(manifest), "--"]
        )
        failed = 0
        tests = storage_tests()
        for test in tests:
            result = subprocess.run(
                ["cargo", "test", "--locked", "--target", "wasm32-wasip1",
                 "--bins", test, "--", "--ignored", "--exact", "--nocapture"],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            if result.returncode != 0 or "1 passed" not in result.stdout:
                failed += 1
                sys.stderr.write(f"FAIL {test}\n{result.stdout}\n{result.stderr}\n")
            else:
                print(f"PASS {test}")
        if failed:
            raise SystemExit(f"{failed} outbox lifecycle tests failed")
        print(f"PASS all {len(tests)} outbox lifecycle tests")


if __name__ == "__main__":
    main()
