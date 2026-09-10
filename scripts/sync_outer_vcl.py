#!/usr/bin/env python3
"""Compare and apply outer Fastly VCL snippets from git without activating.

`diff` is read-only against the active version. `apply` clones that version,
updates the snippets listed in vcl/snippets.json, and validates the draft.
This program never activates a Fastly service version.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

API_ROOT = "https://api.fastly.com"
ACTIVATE_PATH_MARKER = "/activate"


@dataclass(frozen=True)
class SnippetSpec:
    file: str
    name: str
    type: str
    priority: int
    content: str


@dataclass
class Drift:
    ok: List[str]
    content: List[str]
    meta: List[str]
    missing_live: List[str]
    extra_live: List[str]

    def clean(self) -> bool:
        return not (self.content or self.meta or self.missing_live or self.extra_live)


RequestFn = Callable[[str, str, Optional[Dict[str, str]]], Any]


class FastlyError(RuntimeError):
    pass


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[1]


def load_manifest(root: Path, manifest_path: Path) -> Dict[str, Any]:
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def load_specs(root: Path, manifest: Dict[str, Any]) -> List[SnippetSpec]:
    vcl_dir = root / "vcl"
    specs = []
    for item in manifest["snippets"]:
        path = vcl_dir / item["file"]
        specs.append(
            SnippetSpec(
                file=item["file"],
                name=item["name"],
                type=item["type"],
                priority=int(item["priority"]),
                content=path.read_text(encoding="utf-8"),
            )
        )
    return specs


def api_request_factory(token: str) -> RequestFn:
    if not token:
        raise FastlyError("FASTLY_API_TOKEN is not set")

    def request(method: str, path: str, fields: Optional[Dict[str, str]] = None) -> Any:
        if ACTIVATE_PATH_MARKER in path:
            raise FastlyError("refusing to call a Fastly activate endpoint")
        url = API_ROOT + path
        data = None
        headers = {
            "Fastly-Key": token,
            "Accept": "application/json",
        }
        if fields is not None:
            data = urllib.parse.urlencode(fields).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            raise FastlyError(
                f"Fastly API {method} {path} failed: HTTP {exc.code}: {detail}"
            ) from None
        if not body:
            return None
        return json.loads(body)

    return request


def active_version(request: RequestFn, service_id: str) -> int:
    versions = request("GET", f"/service/{service_id}/version", None)
    for version in versions:
        if version.get("active"):
            return int(version["number"])
    raise FastlyError("no active Fastly service version")


def list_snippets(request: RequestFn, service_id: str, version: int) -> List[Dict[str, Any]]:
    return request("GET", f"/service/{service_id}/version/{version}/snippet", None) or []


def compare(specs: List[SnippetSpec], live: List[Dict[str, Any]]) -> Drift:
    live_by_name = {item["name"]: item for item in live}
    wanted = {spec.name: spec for spec in specs}
    drift = Drift(ok=[], content=[], meta=[], missing_live=[], extra_live=[])
    for spec in specs:
        item = live_by_name.get(spec.name)
        if item is None:
            drift.missing_live.append(spec.name)
            continue
        problems = []
        if item.get("content") != spec.content:
            drift.content.append(spec.name)
            problems.append("content")
        if item.get("type") != spec.type:
            drift.meta.append(f"{spec.name} type={item.get('type')!r} expected={spec.type!r}")
            problems.append("type")
        if str(item.get("priority")) != str(spec.priority):
            drift.meta.append(
                f"{spec.name} priority={item.get('priority')!r} expected={spec.priority!r}"
            )
            problems.append("priority")
        if str(item.get("dynamic")) not in ("0", "false", "False"):
            drift.meta.append(f"{spec.name} is dynamic; versioned snippets only")
            problems.append("dynamic")
        if not problems:
            drift.ok.append(spec.name)
    for name in live_by_name:
        if name not in wanted:
            drift.extra_live.append(name)
    return drift


def print_drift(drift: Drift, version: int) -> None:
    print(f"active_version {version}")
    for name in drift.ok:
        print(f"OK {name}")
    for name in drift.content:
        print(f"DRIFT {name}")
    for line in drift.meta:
        print(f"META {line}")
    for name in drift.missing_live:
        print(f"MISSING_LIVE {name}")
    for name in drift.extra_live:
        print(f"EXTRA_LIVE {name}")


def clone_version(request: RequestFn, service_id: str, version: int) -> int:
    cloned = request("PUT", f"/service/{service_id}/version/{version}/clone", None)
    return int(cloned["number"])


def update_snippet(
    request: RequestFn,
    service_id: str,
    version: int,
    spec: SnippetSpec,
) -> None:
    fields = {
        "name": spec.name,
        "type": spec.type,
        "content": spec.content,
        "priority": str(spec.priority),
        "dynamic": "0",
    }
    encoded = urllib.parse.quote(spec.name, safe="")
    request(
        "PUT",
        f"/service/{service_id}/version/{version}/snippet/{encoded}",
        fields,
    )


def validate_version(request: RequestFn, service_id: str, version: int) -> None:
    result = request("GET", f"/service/{service_id}/version/{version}/validate", None)
    status = (result or {}).get("status")
    errors = (result or {}).get("errors") or []
    if status != "ok" or errors:
        raise FastlyError(f"Fastly validate failed for version {version}: {result}")


def cmd_diff(request: RequestFn, service_id: str, specs: List[SnippetSpec]) -> int:
    version = active_version(request, service_id)
    drift = compare(specs, list_snippets(request, service_id, version))
    print_drift(drift, version)
    return 0 if drift.clean() else 1


def cmd_apply(request: RequestFn, service_id: str, specs: List[SnippetSpec]) -> int:
    version = active_version(request, service_id)
    live = list_snippets(request, service_id, version)
    drift = compare(specs, live)
    print_drift(drift, version)
    if drift.extra_live:
        print("apply refused: live has snippets not listed in vcl/snippets.json")
        return 1
    if drift.missing_live:
        print("apply refused: managed snippets are missing from the active version")
        return 1
    if not (drift.content or drift.meta):
        print(f"managed snippets already in sync with active {version}")
        return 0
    draft = clone_version(request, service_id, version)
    print(f"cloned {version} -> {draft}")
    for spec in specs:
        update_snippet(request, service_id, draft, spec)
        print(f"updated {spec.name}")
    draft_drift = compare(specs, list_snippets(request, service_id, draft))
    if not draft_drift.clean():
        print_drift(draft_drift, draft)
        print(f"draft {draft} is incomplete; do not activate it")
        raise FastlyError(f"draft {draft} does not match vcl/snippets.json after apply")
    validate_version(request, service_id, draft)
    print(f"validated {draft} ok")
    print(f"DRAFT_VERSION={draft}")
    print("not activated")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Diff or update outer Fastly VCL snippets without activating."
    )
    parser.add_argument("--root", type=Path, default=None)
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--service-id", default=None)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("diff", help="compare git snippets to the active Fastly version")
    sub.add_parser("apply", help="clone active, update git snippets, validate; do not activate")
    return parser


def main(argv: Optional[List[str]] = None, request: Optional[RequestFn] = None) -> int:
    raw = list(argv) if argv is not None else sys.argv[1:]
    if any(token in ("activate", "--activate") for token in raw):
        print("this tool cannot activate a Fastly service version", file=sys.stderr)
        return 2
    parser = build_parser()
    args = parser.parse_args(argv)
    root = (args.root or repo_root_from_script()).resolve()
    manifest_path = args.manifest or (root / "vcl" / "snippets.json")
    manifest = load_manifest(root, manifest_path)
    service_id = args.service_id or manifest["service_id"]
    specs = load_specs(root, manifest)
    if request is None:
        request = api_request_factory(os.environ.get("FASTLY_API_TOKEN", ""))
    if args.command == "diff":
        return cmd_diff(request, service_id, specs)
    if args.command == "apply":
        return cmd_apply(request, service_id, specs)
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except FastlyError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
