"""Contracts for the outer VCL snippet sync tool."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import sync_outer_vcl as sync


MANIFEST_PATH = ROOT / "vcl" / "snippets.json"
SCRIPT = ROOT / "scripts" / "sync_outer_vcl.py"
CI = ROOT / ".github" / "workflows" / "ci.yml"
OUTER_WORKFLOW = ROOT / ".github" / "workflows" / "outer-vcl.yml"


def load_manifest() -> Dict[str, Any]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


class FakeFastly:
    def __init__(self) -> None:
        self.calls: List[Tuple[str, str]] = []
        self.active = 24
        self.live: List[Dict[str, Any]] = []
        self.next_clone = 25
        self.validate_status = "ok"
        self.validate_errors: List[str] = []
        self.draft_live: Optional[List[Dict[str, Any]]] = None
        self.ignore_upserts = False

    def __call__(
        self, method: str, path: str, fields: Optional[Dict[str, str]] = None
    ) -> Any:
        self.calls.append((method, path))
        if "/activate" in path:
            raise sync.FastlyError("activate is forbidden")
        if method == "GET" and path.endswith("/version"):
            return [{"number": self.active, "active": True}]
        if method == "GET" and path.endswith("/snippet"):
            source = self.draft_live if f"/version/{self.next_clone}/" in path else self.live
            return [dict(item) for item in (source or [])]
        if method == "PUT" and path.endswith("/clone"):
            self.draft_live = [dict(item) for item in self.live]
            return {"number": self.next_clone}
        if method == "GET" and path.endswith("/validate"):
            return {"status": self.validate_status, "errors": self.validate_errors}
        if method in ("PUT", "POST") and "/snippet" in path:
            if self.ignore_upserts:
                return {"ok": True}
            assert fields is not None
            assert self.draft_live is not None
            replacement = dict(fields)
            if method == "PUT":
                self.draft_live = [
                    replacement if item["name"] == fields["name"] else item
                    for item in self.draft_live
                ]
            else:
                self.draft_live.append(replacement)
            return {"ok": True}
        raise AssertionError(f"unexpected {method} {path}")


def live_item(spec: sync.SnippetSpec, **overrides: Any) -> Dict[str, Any]:
    item = {
        "name": spec.name,
        "type": spec.type,
        "priority": str(spec.priority),
        "dynamic": "0",
        "content": spec.content,
    }
    item.update(overrides)
    return item


class ManifestContractTest(unittest.TestCase):
    def test_every_vcl_file_is_managed_or_explicitly_unmanaged(self) -> None:
        manifest = load_manifest()
        managed = {item["file"] for item in manifest["snippets"]}
        unmanaged = {item["file"] for item in manifest["unmanaged_files"]}
        on_disk = {path.name for path in (ROOT / "vcl").glob("*.vcl")}
        self.assertEqual(managed & unmanaged, set())
        self.assertEqual(managed | unmanaged, on_disk)
        self.assertEqual(unmanaged, {"log_cdn_views.vcl"})
        self.assertEqual(manifest["service_id"], "ML7R82HKfmTaqTpHExIDVN")

    def test_live_upload_timeout_snippet_is_tracked(self) -> None:
        names = {item["name"] for item in load_manifest()["snippets"]}
        self.assertIn("Upload origin timeout", names)
        pass_vcl = (ROOT / "vcl" / "pass.vcl").read_text(encoding="utf-8")
        self.assertIn("set bereq.first_byte_timeout = 120s;", pass_vcl)

class SyncToolTest(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = load_manifest()
        self.specs = sync.load_specs(ROOT, self.manifest)
        self.fake = FakeFastly()
        self.fake.live = [live_item(spec) for spec in self.specs]

    def test_diff_clean(self) -> None:
        self.assertEqual(sync.main(["diff"], request=self.fake), 0)
        self.assertEqual(
            self.fake.calls,
            [
                ("GET", "/service/ML7R82HKfmTaqTpHExIDVN/version"),
                ("GET", "/service/ML7R82HKfmTaqTpHExIDVN/version/24/snippet"),
            ],
        )

    def test_diff_content_drift(self) -> None:
        self.fake.live[0]["content"] = "stale\n"
        self.assertEqual(sync.main(["diff"], request=self.fake), 1)

    def test_diff_extra_live_snippet(self) -> None:
        self.fake.live.append(
            {
                "name": "mystery",
                "type": "log",
                "priority": "100",
                "dynamic": "0",
                "content": "log {\"x\"};\n",
            }
        )
        self.assertEqual(sync.main(["diff"], request=self.fake), 1)

    def test_apply_is_noop_when_in_sync(self) -> None:
        self.assertEqual(sync.main(["apply"], request=self.fake), 0)
        self.assertFalse(any(path.endswith("/clone") for _, path in self.fake.calls))

    def test_apply_clones_updates_and_validates_without_activate(self) -> None:
        self.fake.live[0]["content"] = "stale\n"
        self.assertEqual(sync.main(["apply"], request=self.fake), 0)
        methods_paths = self.fake.calls
        self.assertIn(
            ("PUT", "/service/ML7R82HKfmTaqTpHExIDVN/version/24/clone"),
            methods_paths,
        )
        self.assertIn(
            ("GET", "/service/ML7R82HKfmTaqTpHExIDVN/version/25/validate"),
            methods_paths,
        )
        self.assertTrue(any(method == "PUT" and "/snippet/" in path for method, path in methods_paths))
        self.assertFalse(any("/activate" in path for _, path in methods_paths))

    def test_apply_creates_missing_snippet_in_draft(self) -> None:
        missing = self.fake.live.pop()
        self.assertEqual(sync.main(["apply"], request=self.fake), 0)
        self.assertEqual(missing["name"], self.specs[-1].name)
        self.assertEqual(
            [path for method, path in self.fake.calls if method == "POST"],
            ["/service/ML7R82HKfmTaqTpHExIDVN/version/25/snippet"],
        )

    def test_apply_refuses_draft_that_does_not_match_after_update(self) -> None:
        self.fake.live[0]["content"] = "stale\n"
        self.fake.ignore_upserts = True
        with self.assertRaisesRegex(sync.FastlyError, "does not match"):
            sync.main(["apply"], request=self.fake)
        self.assertFalse(any(path.endswith("/validate") for _, path in self.fake.calls))

    def test_apply_refuses_unmanaged_live_snippets(self) -> None:
        self.fake.live.append(
            {
                "name": "mystery",
                "type": "log",
                "priority": "100",
                "dynamic": "0",
                "content": "log {\"x\"};\n",
            }
        )
        self.assertEqual(sync.main(["apply"], request=self.fake), 1)
        self.assertFalse(any(path.endswith("/clone") for _, path in self.fake.calls))

    def test_activate_argument_is_rejected(self) -> None:
        self.assertEqual(sync.main(["apply", "--activate"], request=self.fake), 2)
        self.assertEqual(self.fake.calls, [])

    def test_request_factory_refuses_activate_paths(self) -> None:
        request = sync.api_request_factory("token-value")
        with self.assertRaises(sync.FastlyError):
            request("PUT", "/service/x/version/1/activate", {})


class WorkflowContractTest(unittest.TestCase):
    def test_script_and_workflows_never_activate(self) -> None:
        script = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("never activates", script)
        self.assertNotIn("service-version activate", script)
        outer = OUTER_WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("activate", outer.lower())
        self.assertIn("sync_outer_vcl.py", outer)
        self.assertIn("branches: [main]", outer)
        self.assertIn("vcl/**", outer)
        self.assertIn("github.ref == 'refs/heads/main'", outer)
        self.assertIn("Reject draft creation outside main", outer)
        self.assertIn("group: outer-vcl-draft", outer)
        self.assertNotIn("needs:", outer)
        ci = CI.read_text(encoding="utf-8")
        self.assertIn("fastly compute publish", ci)
        self.assertNotIn("sync_outer_vcl.py", ci)
        self.assertNotIn("ML7R82HKfmTaqTpHExIDVN", ci)


if __name__ == "__main__":
    unittest.main()
