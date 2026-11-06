#!/usr/bin/env python3
"""Reuse synthetic canary fixtures to verify actual telemetry execution state.

No services, media or configuration outside the fixture's temporary directory
are read or changed. Existing canary tests run separately without this wrapper.
"""
import importlib.util
import json
import os
from pathlib import Path
import shlex

path = Path(__file__).with_name("run-b2-canary-tests.py")
spec = importlib.util.spec_from_file_location("canary_fixtures", path)
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
original_run = fixtures.run

# Expected provider is the media request actually attempted, including errors;
# native authorization requests alone do not count as media fetches.
cases = {
    "demand_valid": ("b2", "bypass", "none"),
    "demand_b2_head": ("b2", "bypass", "none"),
    "demand_b2_416": ("b2", "bypass", "none"),
    "demand_missing_ready": ("gcs", "bypass", "missing_readiness"),
    "demand_missing_ready_head": ("gcs", "bypass", "missing_readiness"),
    "demand_origin_missing": ("gcs", "bypass", "missing_version"),
    "demand_origin_failed": ("gcs", "bypass", "unavailable"),
    "demand_copying": ("gcs", "bypass", "copying"),
    "demand_oversized": ("gcs", "bypass", "oversized"),
    "demand_auth503": ("gcs", "bypass", "unavailable"),
    "demand_auth401": ("none", "unknown", "none"),
    "demand_quarantine": ("none", "unknown", "none"),
    "demand_gcs_missing": ("gcs", "bypass", "missing_readiness"),
    "demand_gcs_failed": ("gcs", "bypass", "missing_readiness"),
}

def run(repo, env, test):
    if test == "demand_endpoint_contract":
        args = shlex.split(env["CARGO_TARGET_WASM32_WASIP1_RUNNER"])
        config = Path(args[args.index("-C") + 1])
        settings = config.with_name("settings.json")
        values = json.loads(settings.read_text())
        values["b2_playback_telemetry_enabled"] = "true"
        provider, cache, fallback = cases[os.environ["B2_CANARY_CASE"]]
        values.update(test_telemetry_provider=provider, test_telemetry_storage_cache=cache, test_telemetry_fallback=fallback)
        settings.write_text(json.dumps(values))
        test = "delivery_telemetry::tests::canary_execution_observation_contract"
    return original_run(repo, env, test)

fixtures.run = run
selected = os.environ.get("B2_TELEMETRY_CASE")
for case in [selected] if selected else cases:
    os.environ["B2_CANARY_CASE"] = case
    fixtures.main()
    print(f"PASS actual telemetry {case}")
