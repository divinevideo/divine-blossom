#!/usr/bin/env python3
"""Deploy the bundled native Bunny Blossom Edge Script (Standalone or Pull Zone Middleware)
and configure its fronting Pull Zone with Cache Slicing and pre-cache bypass Edge Rules.

Reads Bunny API key from BUNNY_API_KEY or ~/.config/divine-cdn/bunny-api-key. Never prints secrets.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

API_BASE = "https://api.bunny.net"
DEFAULT_KEY_PATH = Path.home() / ".config" / "divine-cdn" / "bunny-api-key"

SCRIPT_TYPE_MAP = {
    "standalone": 0,
    "middleware": 2,
}


def load_api_key() -> str:
    env_key = os.environ.get("BUNNY_API_KEY", "").strip()
    if env_key:
        return env_key
    if DEFAULT_KEY_PATH.exists():
        val = DEFAULT_KEY_PATH.read_text().strip()
        if val:
            return val
    raise RuntimeError(f"Missing Bunny API key (set BUNNY_API_KEY or {DEFAULT_KEY_PATH})")


class BunnyClient:
    def __init__(self, api_key: str) -> None:
        self._key = api_key

    def req(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"AccessKey": self._key, "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        r = urllib.request.Request(f"{API_BASE}{path}", data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(r, timeout=30) as resp:
                raw = resp.read().decode()
                return json.loads(raw) if raw.strip() else None
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:400]
            raise RuntimeError(f"Bunny API {method} {path} failed ({exc.code}): {detail}") from exc


def find_script(client: BunnyClient, name: str) -> dict[str, Any] | None:
    resp = client.req("GET", "/compute/script")
    items = resp.get("Items", resp) if isinstance(resp, dict) else resp
    for item in items or []:
        if item.get("Name") == name:
            return item
    return None


def upsert_secret_or_var(
    client: BunnyClient,
    script_id: int,
    env_vars: dict[str, str],
    secrets: dict[str, str],
) -> None:
    # Bunny Edge Scripting injects runtime secrets into Deno.env reliably across Standalone and Middleware.
    for k, v in env_vars.items():
        client.req("PUT", f"/compute/script/{script_id}/secrets", {"Name": k, "Secret": v})
    for k, v in secrets.items():
        client.req("PUT", f"/compute/script/{script_id}/secrets", {"Name": k, "Secret": v})


def configure_blossom_pull_zone(client: BunnyClient, pull_zone_id: int) -> None:
    """Configure Pull Zone caching + pre-cache bypass Edge Rules for Blossom."""
    client.req(
        "POST",
        f"/pullzone/{pull_zone_id}",
        {
            "EnableCacheSlice": True,
            "EnableOriginShield": False,
            "CacheErrorResponses": False,
            "UseStaleWhileUpdating": False,
            "UseStaleWhileOffline": False,
            "DisableCookies": True,
            "FollowRedirects": False,
            "EnableSmartCache": False,
            "IgnoreQueryStrings": False,
            "LogAnonymizationType": 1,
        },
    )
    pz = client.req("GET", f"/pullzone/{pull_zone_id}")
    for rule in pz.get("EdgeRules") or []:
        if str(rule.get("Description", "")).startswith("blossom:"):
            client.req("DELETE", f"/pullzone/{pull_zone_id}/edgerules/{rule['Guid']}")

    bypass_rules = [
        {
            "Description": "blossom: bypass cache when Authorization header is present",
            "Enabled": True,
            "ActionType": 3,  # OverrideCacheTime
            "ActionParameter1": "0",
            "TriggerMatchingType": 0,
            "Triggers": [
                {"Type": 1, "PatternMatches": ["*"], "PatternMatchingType": 0, "Parameter1": "Authorization"}
            ],
        },
        {
            "Description": "blossom: bypass cache for non-GET/HEAD methods",
            "Enabled": True,
            "ActionType": 3,
            "ActionParameter1": "0",
            "TriggerMatchingType": 0,
            "Triggers": [
                {"Type": 9, "PatternMatches": ["GET", "HEAD"], "PatternMatchingType": 2, "Parameter1": ""}
            ],
        },
        {
            "Description": "blossom: bypass cache for control plane and API paths",
            "Enabled": True,
            "ActionType": 3,
            "ActionParameter1": "0",
            "TriggerMatchingType": 0,
            "Triggers": [
                {
                    "Type": 0,
                    "PatternMatches": [
                        "https://*/admin*",
                        "https://*/upload*",
                        "https://*/list/*",
                        "https://*/v1/*",
                        "https://*/api/*",
                    ],
                    "PatternMatchingType": 0,
                    "Parameter1": "",
                },
                {
                    "Type": 0,
                    "PatternMatches": [
                        "https://*/internal/*",
                        "https://*/vanish",
                        "https://*/report",
                        "https://*/mirror",
                        "https://*/health",
                    ],
                    "PatternMatchingType": 0,
                    "Parameter1": "",
                },
            ],
        },
    ]
    for rule in bypass_rules:
        client.req("POST", f"/pullzone/{pull_zone_id}/edgerules/addOrUpdate", rule)


def main() -> int:
    parser = argparse.ArgumentParser(description="Bundle and deploy Bunny Blossom Edge Script.")
    parser.add_argument("--name", required=True, help="Bunny Edge Script name")
    parser.add_argument("--mode", choices=["standalone", "middleware"], default="standalone")
    parser.add_argument("--env-file", type=Path, help="Private JSON file with env and secrets maps")
    parser.add_argument("--pull-zone-id", type=int, help="Optional existing Pull Zone ID to link/configure")
    args = parser.parse_args()

    here = Path(__file__).resolve().parent
    entry = here / ("middleware.ts" if args.mode == "middleware" else "bunny.ts")
    bundle_path = Path(f"/tmp/{args.name}-bundle.js")
    subprocess.run(
        ["deno", "bundle", "--platform=deno", str(entry), "-o", str(bundle_path)],
        cwd=here,
        check=True,
    )
    code = bundle_path.read_text()

    client = BunnyClient(load_api_key())
    script = find_script(client, args.name)
    if script is None:
        script = client.req(
            "POST",
            "/compute/script",
            {
                "Name": args.name,
                "Code": code,
                "ScriptType": SCRIPT_TYPE_MAP[args.mode],
                "CreateLinkedPullZone": args.pull_zone_id is None,
            },
        )
        print(f"Created Bunny Edge Script {args.name} id={script['Id']}")
    else:
        print(f"Updating Bunny Edge Script {args.name} id={script['Id']}")

    script_id = int(script["Id"])

    if args.env_file:
        cfg = json.loads(args.env_file.read_text())
        upsert_secret_or_var(
            client,
            script_id,
            cfg.get("env", {}),
            cfg.get("secrets", {}),
        )
        print(f"Bound {len(cfg.get('env', {}))} env vars and {len(cfg.get('secrets', {}))} secrets")

    client.req("POST", f"/compute/script/{script_id}/code", {"Code": code})
    client.req("POST", f"/compute/script/{script_id}/publish", {"Note": f"deploy {args.name}"})
    print(f"Published script id={script_id}")

    refreshed = client.req("GET", f"/compute/script/{script_id}")
    linked = refreshed.get("LinkedPullZones") or []
    pz_id = args.pull_zone_id or (int(linked[0]["Id"]) if linked else None)
    if pz_id:
        configure_blossom_pull_zone(client, pz_id)
        pz = client.req("GET", f"/pullzone/{pz_id}")
        hosts = [h["Value"] for h in pz.get("Hostnames") or []]
        print(f"Configured Pull Zone id={pz_id} hostnames={hosts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
