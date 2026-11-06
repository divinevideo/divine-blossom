#!/usr/bin/env python3
"""Run B2 CDN phase state-machine tests against a local Viceroy KV store.

Synthetic configuration and a throwaway local KV store only. No Fastly, B2, GCS,
purge credential, or network provider is contacted.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def storage_tests():
    """Only `#[ignore]`d test fns, not test-local helpers like reset_all."""
    source = (ROOT / "src/b2_cdn_phase.rs").read_text().split("mod storage {", 1)[1]
    return [
        f"b2_cdn_phase::tests::storage::{name}"
        for name in re.findall(
            r'#\[ignore = "[^"]*"\]\s*fn (\w+)\(\) \{', source
        )
    ]


def main():
    with tempfile.TemporaryDirectory(prefix="b2-cdn-phase-") as directory:
        root = Path(directory)
        manifest, kv = root / "fastly.toml", root / "kv.json"
        kv.write_text("{}")
        manifest.write_text(f'''manifest_version = 3
name = "b2-cdn-phase-test"
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
            raise SystemExit(f"{failed} phase tests failed")
        print(f"PASS all {len(tests)} phase state-machine tests")


if __name__ == "__main__":
    main()
