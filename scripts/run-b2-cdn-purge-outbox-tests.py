#!/usr/bin/env python3
"""Run b2_cdn_purge lifecycle tests against a local Viceroy KV store.

Only synthetic configuration and a throwaway local KV store are used. No
Fastly, B2, GCS, purge credential, or network provider is contacted: the purge
callback in each test is a pure function.
"""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
TESTS = [
    "b2_cdn_purge::tests::storage::begin_writes_prepared_and_drain_never_clears_it",
    "b2_cdn_purge::tests::storage::commit_then_drain_purges_and_clears",
    "b2_cdn_purge::tests::storage::purge_failure_retains_committed_record_for_retry",
    "b2_cdn_purge::tests::storage::two_concurrent_writers_both_keep_a_retry_record",
    "b2_cdn_purge::tests::storage::a_stale_token_never_commits_a_newer_attempt",
    "b2_cdn_purge::tests::storage::execute_retains_prepared_when_the_mutation_fails",
    "b2_cdn_purge::tests::storage::execute_commits_after_successful_mutation_and_drains",
    "b2_cdn_purge::tests::storage::drain_limit_bounds_one_pass_and_cursor_advances",
    "b2_cdn_purge::tests::storage::foreign_records_are_retained_and_do_not_starve_healthy_suffix",
    "b2_cdn_purge::tests::storage::execute_fails_closed_when_the_prepared_record_disappears_before_commit",
    "b2_cdn_purge::tests::storage::execute_fails_closed_when_the_record_no_longer_describes_the_attempt",
    "b2_cdn_purge::tests::storage::invalid_purge_configuration_is_an_error_and_retains_the_record",
    "b2_cdn_purge::tests::storage::long_cleared_history_does_not_starve_a_healthy_suffix",
    "b2_cdn_purge::tests::storage::receipts_do_not_share_the_queue_list_prefix",
    "b2_cdn_purge::tests::storage::a_partial_pass_does_not_starve_healthy_rows_behind_blocked_ones",
    "b2_cdn_purge::tests::storage::a_precautionary_drain_does_not_break_a_live_writers_commit",
    "b2_cdn_purge::tests::storage::a_stale_purge_callback_cannot_ack_a_physical_state_change",
    "b2_cdn_purge::tests::storage::final_drain_advances_the_phase_and_writes_the_receipt",
    "b2_cdn_purge::tests::storage::a_failed_final_purge_never_acks_or_completes",
    "b2_cdn_purge::tests::storage::receipts_bind_to_one_attempt_and_never_imply_from_absence",
]


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
        for test in TESTS:
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
        print(f"PASS all {len(TESTS)} outbox lifecycle tests")


if __name__ == "__main__":
    main()
