"""Regression contracts for the hand-managed outer Fastly VCL and deploy flow."""

from pathlib import Path
import os
import re
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]


class EdgeCacheContractTests(unittest.TestCase):
    def test_outer_header_stripping_activates_before_compute_publish(self):
        diagnostics_runbook = (ROOT / "docs" / "runbooks" / "fastly-5xx.md").read_text()
        cold_fill_runbook = (
            ROOT / "docs" / "runbooks" / "cold-fill-validation.md"
        ).read_text()

        ordering = diagnostics_runbook.split(
            "Activate the separately validated outer VCL version first", 1
        )[1].split("\n5.", 1)[0]
        self.assertIn("then publish the", ordering)
        self.assertIn("before publishing the Compute package", cold_fill_runbook)

        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        deploy_job = workflow.split("\n  deploy:\n", 1)[1].split(
            "\n  purge-cache:\n", 1
        )[0]
        self.assertIn("name: Verify required outer VCL is active", deploy_job)
        self.assertIn(
            'if [ "$FASTLY_OUTER_DIAGNOSTICS_ACTIVE" != "true" ]', deploy_job
        )
        gate_step = deploy_job.split(
            "- name: Verify required outer VCL is active", 1
        )[1].split("\n      -", 1)[0]
        self.assertIn("exit 1", gate_step)
        self.assertIn("inputs.publish_compute", deploy_job)
        self.assertLess(
            deploy_job.index("name: Verify required outer VCL is active"),
            deploy_job.index("name: Install Fastly CLI"),
        )
        self.assertLess(
            deploy_job.index("name: Verify required outer VCL is active"),
            deploy_job.index("name: Deploy to Fastly"),
        )

    def test_probe_metadata_is_compared_then_stripped_at_delivery(self):
        deliver_vcl = (ROOT / "vcl" / "deliver.vcl").read_text()

        self.assertIn("X-Divine-Diagnostic-Role = \"leader\"", deliver_vcl)
        self.assertIn("X-Divine-Diagnostic-Role = \"follower\"", deliver_vcl)
        for header in (
            "X-Divine-Probe-Id",
            "X-Divine-Probe-Source",
            "X-Divine-Probe-FOS-Outcome",
            "X-Divine-Probe-Buffer",
            "X-Divine-Probe-Write-Back",
        ):
            self.assertIn(f"unset resp.http.{header};", deliver_vcl)
            self.assertLess(
                deliver_vcl.index('X-Divine-Diagnostic-Role = "leader"'),
                deliver_vcl.index(f"unset resp.http.{header};"),
            )

    def test_surrogate_headers_are_stripped_only_on_client_facing_delivery(self):
        # The outer backend shields through one POP, so vcl_deliver also runs
        # on the shield hop. An unconditional strip there stores edge copies
        # without their Surrogate-Key, and a purge by key never reaches them
        # (#279). The strip must sit inside the visits_this_service == 0 guard.
        deliver_vcl = (ROOT / "vcl" / "deliver.vcl").read_text()

        guard = "if (fastly.ff.visits_this_service == 0) {"
        self.assertEqual(deliver_vcl.count(guard), 1)
        guard_start = deliver_vcl.index(guard)
        guard_end = deliver_vcl.index("}", guard_start)
        guarded_block = deliver_vcl[guard_start:guard_end]

        for header in ("Surrogate-Key", "Surrogate-Control"):
            unset = f"unset resp.http.{header};"
            self.assertEqual(deliver_vcl.count(unset), 1, header)
            self.assertIn(unset, guarded_block, header)

    def test_cached_probe_labels_are_cleared_before_delivery_evidence(self):
        deliver_vcl = (ROOT / "vcl" / "deliver.vcl").read_text()
        evidence_guard = deliver_vcl.index(
            'if (req.http.X-Divine-Diagnostic-Probe ~ "^coldfill-'
        )

        for header in (
            "X-Divine-Diagnostic-Role",
            "X-Divine-Diagnostic-Source",
            "X-Divine-Diagnostic-FOS-Outcome",
            "X-Divine-Diagnostic-Buffer",
            "X-Divine-Diagnostic-Write-Back",
        ):
            unset_offset = deliver_vcl.index(f"unset resp.http.{header};")
            self.assertLess(unset_offset, evidence_guard)

    def test_internal_compute_diagnostic_headers_have_delivery_backstop(self):
        deliver_vcl = (ROOT / "vcl" / "deliver.vcl").read_text()

        for suffix in (
            "Authorization-Present",
            "Source",
            "Storage-Cache",
            "FOS-Outcome",
            "FOS-Lookup-Ms",
            "GCS-Fetch-Ms",
            "Buffer-Ms",
            "Write-Back-Ms",
            "Probe-Id",
        ):
            self.assertIn(
                f"unset resp.http.X-Divine-Internal-Diagnostic-{suffix};",
                deliver_vcl,
            )

    def test_private_moderation_smoke_is_excluded_from_pull_request_workflows(self):
        workflows = ROOT / ".github" / "workflows"
        for workflow in (*workflows.glob("*.yml"), *workflows.glob("*.yaml")):
            self.assertNotIn(
                "smoke-private-moderation-cache.sh",
                workflow.read_text(),
                workflow,
            )

    def test_private_moderation_smoke_exercises_access_matrix(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            bin_dir = Path(temp_dir)
            fake_curl = bin_dir / "curl"
            fake_curl.write_text(textwrap.dedent("""\
                #!/usr/bin/env python3
                import hashlib
                import os
                from pathlib import Path
                import sys

                args = sys.argv[1:]
                if "-X" in args and args[args.index("-X") + 1] == "HEAD":
                    raise SystemExit("HEAD must use curl -I")
                method = "HEAD" if "-I" in args else "GET"
                with Path(os.environ["SMOKE_FAKE_METHOD_LOG"]).open("a") as log:
                    log.write(method + "\\n")
                headers_path = Path(args[args.index("-D") + 1])
                url = next(arg for arg in args if arg.startswith("https://"))
                path = "/" + url.split("/", 3)[3]
                fixture = path[1:65]
                status = {
                    "a" * 64: "Restricted",
                    "b" * 64: "AgeRestricted",
                    "c" * 64: "Banned",
                    "d" * 64: "Deleted",
                }[fixture]
                auth = os.environ.get("SMOKE_AUTH", "anonymous")
                if "--config" in args:
                    auth = "admin"
                if auth == "owner" and os.environ.get("FAKE_INVALID_OWNER_AUTH"):
                    auth = "anonymous"
                elif auth == "owner" and os.environ.get("FAKE_WRONG_OWNER"):
                    auth = "stranger"
                elif auth == "admin" and os.environ.get("FAKE_INVALID_ADMIN_AUTH"):
                    auth = "anonymous"

                state = Path(os.environ["SMOKE_FAKE_STATE"])
                marker = state / hashlib.sha256(url.encode()).hexdigest()
                bare_marker = state / hashlib.sha256(url.split("?", 1)[0].encode()).hexdigest()

                if auth == "admin":
                    code = "200"
                elif auth == "owner" and status in ("Restricted", "AgeRestricted"):
                    code = "200"
                elif auth == "stranger" and status == "AgeRestricted":
                    code = "200"
                elif status == "AgeRestricted":
                    code = "401"
                else:
                    code = "404"

                if path.split("?", 1)[0].endswith(".audio.m4a") and code == "200":
                    if os.environ.get("FAKE_AUDIO_REUSE_DENIED"):
                        code = "403"
                    elif os.environ.get("FAKE_AUDIO_LOOKUP_UNAVAILABLE"):
                        code = "503"

                if auth != "anonymous" and code == "200":
                    marker.touch()
                    if os.environ.get("FAKE_STRIP_QUERY_LEAK"):
                        bare_marker.touch()
                elif auth == "anonymous" and marker.exists() and os.environ.get("FAKE_LEAK_PRIVATE"):
                    code = "200"
                elif auth == "anonymous" and "?" not in url and bare_marker.exists() and os.environ.get("FAKE_STRIP_QUERY_LEAK"):
                    code = "200"

                headers = [f"HTTP/1.1 {code}"]
                if code == "200":
                    headers += [
                        "Cache-Control: private, no-store",
                        "X-Cache: " + ("HIT" if os.environ.get("FAKE_PRIVATE_HIT") else "MISS"),
                    ]
                    if path.split("?", 1)[0] == f"/{fixture}":
                        headers.append(f"X-Moderation-Status: {status}")
                elif code == "404":
                    headers += [
                        "Cache-Control: no-store",
                    ]
                else:
                    headers.append("X-Cache: MISS")
                headers_path.write_text("\\r\\n".join(headers) + "\\r\\n")
                print(code, end="")
                """))
            fake_nak = bin_dir / "nak"
            fake_nak.write_text(textwrap.dedent("""\
                #!/bin/sh
                if [ "$1" = "--help" ]; then
                  if [ -n "${FAKE_NAK_NOT_NOSTR:-}" ]; then
                    echo "unrelated search utility"
                  else
                    echo "nak: the nostr army knife"
                  fi
                  exit 0
                fi
                [ "$1" = "curl" ] || exit 2
                shift
                SMOKE_AUTH=owner exec curl "$@"
                """))
            fake_curl.chmod(0o755)
            fake_nak.chmod(0o755)

            env = os.environ.copy()
            env.update({
                "PATH": f"{bin_dir}:{env['PATH']}",
                "OWNER_NSEC": "synthetic-owner-key",
                "ADMIN_TOKEN": "synthetic-admin-token",
                "RESTRICTED_HASH": "a" * 64,
                "AGE_RESTRICTED_HASH": "b" * 64,
                "BANNED_HASH": "c" * 64,
                "DELETED_HASH": "d" * 64,
                "SMOKE_FAKE_STATE": str(bin_dir),
                "SMOKE_FAKE_METHOD_LOG": str(bin_dir / "methods.log"),
            })
            smoke = ROOT / "scripts" / "smoke-private-moderation-cache.sh"
            result = subprocess.run(
                [str(smoke)], env=env, text=True, capture_output=True, check=False
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(
                "PASS: all private moderation-status routes preserved access and cache policy",
                result.stdout,
            )
            self.assertEqual(
                set((bin_dir / "methods.log").read_text().splitlines()),
                {"GET", "HEAD"},
            )

            for flag, message in (
                ("FAKE_NAK_NOT_NOSTR", "nak must be the Nostr army knife"),
                ("FAKE_INVALID_OWNER_AUTH", "OWNER_NSEC did not authenticate"),
                ("FAKE_WRONG_OWNER", "OWNER_NSEC is not the fixture owner"),
                ("FAKE_INVALID_ADMIN_AUTH", "ADMIN_TOKEN did not authenticate"),
                ("FAKE_AUDIO_REUSE_DENIED", "audio-reuse policy"),
                ("FAKE_AUDIO_LOOKUP_UNAVAILABLE", "Funnelcake is unavailable"),
            ):
                env[flag] = "1"
                result = subprocess.run(
                    [str(smoke)], env=env, text=True, capture_output=True, check=False
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                env.pop(flag)

            env["FAKE_PRIVATE_HIT"] = "1"
            result = subprocess.run(
                [str(smoke)], env=env, text=True, capture_output=True, check=False
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("stored in the shared edge cache", result.stderr)

            env.pop("FAKE_PRIVATE_HIT")
            env["FAKE_LEAK_PRIVATE"] = "1"
            result = subprocess.run(
                [str(smoke)], env=env, text=True, capture_output=True, check=False
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("anonymous after", result.stderr)

            env.pop("FAKE_LEAK_PRIVATE")
            env["FAKE_STRIP_QUERY_LEAK"] = "1"
            result = subprocess.run(
                [str(smoke)], env=env, text=True, capture_output=True, check=False
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("returned 200", result.stderr)

    def test_private_edge_policy_does_not_disable_short_404_caching(self):
        fetch_vcl = (ROOT / "vcl" / "fetch.vcl").read_text()

        private_guard = (
            'beresp.http.Surrogate-Control ~ "(?i)(private|no-store)"'
        )
        self.assertIn(private_guard, fetch_vcl)
        self.assertNotIn(
            'beresp.http.Cache-Control ~ "(?i)(private|no-store)"', fetch_vcl
        )

        guard_offset = fetch_vcl.index(private_guard)
        success_offset = fetch_vcl.index("beresp.status == 200")
        not_found_offset = fetch_vcl.index("beresp.status == 404")
        short_ttl_offset = fetch_vcl.index("set beresp.ttl = 60s", not_found_offset)

        self.assertLess(guard_offset, success_offset)
        self.assertLess(success_offset, not_found_offset)
        self.assertGreater(short_ttl_offset, not_found_offset)

    def test_global_purge_requires_explicit_manual_workflow_input(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()

        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("purge_cache:", workflow)
        self.assertIn(
            "if: github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.purge_cache && !inputs.publish_compute",
            workflow,
        )
        self.assertNotIn("github.event.head_commit.message", workflow)

        deploy_job = workflow.split("\n  deploy:\n", 1)[1].split(
            "\n  purge-cache:\n", 1
        )[0]
        self.assertIn("\n  purge-cache:\n", workflow)
        purge_job = workflow.split("\n  purge-cache:\n", 1)[1].split(
            "\n  deploy-process-blob:\n", 1
        )[0]

        self.assertIn("github.event_name == 'push'", deploy_job)
        self.assertIn("github.event_name == 'workflow_dispatch'", deploy_job)
        self.assertIn("inputs.publish_compute && !inputs.purge_cache", deploy_job)
        self.assertIn("inputs.purge_cache && !inputs.publish_compute", purge_job)
        self.assertNotIn("fastly compute publish", purge_job)
        self.assertIn("fastly purge --all", purge_job)

    def test_admin_media_routes_apply_browser_and_edge_private_policy(self):
        main_rs = (ROOT / "src" / "main.rs").read_text()

        quality_variant = main_rs.split(
            "fn handle_admin_quality_variant", 1
        )[1].split("fn handle_admin_hls_content", 1)[0]
        hls_content = main_rs.split("fn handle_admin_hls_content", 1)[1].split(
            "fn generate_thumbnail_on_demand", 1
        )[0]

        for route in (quality_variant, hls_content):
            self.assertIn("add_private_cache_headers(&mut resp, &hash);", route)
            self.assertNotIn(
                'resp.set_header("Cache-Control", "private, no-store")', route
            )

    def test_cached_404s_carry_surrogate_key_for_targeted_purge(self):
        main_rs = (ROOT / "src" / "main.rs").read_text()

        # vcl/fetch.vcl caches 404s for 60s and comments that the response
        # Surrogate-Key enables instant purge; the origin must actually set it,
        # or `fastly purge --key <hash>` cannot evict a stale negative entry.
        fetch_vcl = (ROOT / "vcl" / "fetch.vcl").read_text()
        self.assertIn("set beresp.ttl = 60s", fetch_vcl)
        self.assertIn("surrogate_key_hash_from_path", main_rs)
        self.assertIn('response.set_header("Surrogate-Key", hash);', main_rs)

    def test_operator_docs_do_not_require_a_global_purge(self):
        for relative_path in (
            "AGENTS.md",
            "README.md",
            "OAUTH_SETUP.md",
            "scripts/backfill_restricted_to_age_restricted.py",
        ):
            contents = (ROOT / relative_path).read_text()
            self.assertNotIn("fastly purge --all", contents, relative_path)


class ShieldSelectionContractTests(unittest.TestCase):
    def test_hash_paths_fall_through_to_generated_shield_selection(self):
        recv_vcl = (ROOT / "vcl" / "recv.vcl").read_text()
        hash_policy = recv_vcl.split(
            "# Cache hash-based content paths:", maxsplit=1
        )[1]

        self.assertIn('if (req.url !~ "^/[0-9a-fA-F]{64}")', hash_policy)
        # return (lookup) with arbitrary spacing is valid VCL and would bypass
        # Fastly's generated shield selection just like return(lookup).
        self.assertIsNone(re.search(r"return\s*\(\s*lookup\s*\)", hash_policy))
        self.assertIn("Deliberately fall through", hash_policy)


if __name__ == "__main__":
    unittest.main()
