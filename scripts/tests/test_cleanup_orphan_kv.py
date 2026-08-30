import argparse
import importlib.util
import io
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


SCRIPT = Path(__file__).parents[1] / "cleanup_orphan_kv.py"
SPEC = importlib.util.spec_from_file_location("cleanup_orphan_kv", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ClassificationTests(unittest.TestCase):
    def test_classifies_storage_and_metadata_divergence(self):
        present = MODULE.MetadataProbe(MODULE.Presence.PRESENT, "active")
        missing = MODULE.MetadataProbe(MODULE.Presence.MISSING)

        self.assertEqual(
            MODULE.classify_blob(present, MODULE.Presence.MISSING, 404),
            MODULE.MISSING_BYTES,
        )
        self.assertEqual(
            MODULE.classify_blob(missing, MODULE.Presence.PRESENT),
            MODULE.MISSING_METADATA,
        )
        self.assertEqual(
            MODULE.classify_blob(missing, MODULE.Presence.MISSING),
            MODULE.STALE_EVENT_REFERENCE,
        )

    def test_preserves_moderation_and_deletion_outcomes(self):
        for status in ("restricted", "banned"):
            metadata = MODULE.MetadataProbe(MODULE.Presence.PRESENT, status)
            self.assertEqual(
                MODULE.classify_blob(metadata, MODULE.Presence.PRESENT, 404),
                MODULE.MODERATION_HIDDEN,
            )

        deleted = MODULE.MetadataProbe(MODULE.Presence.PRESENT, "deleted")
        self.assertEqual(
            MODULE.classify_blob(deleted, MODULE.Presence.MISSING, 404),
            MODULE.DELETED,
        )

        age_restricted = MODULE.MetadataProbe(
            MODULE.Presence.PRESENT, "age_restricted"
        )
        self.assertEqual(
            MODULE.classify_blob(age_restricted, MODULE.Presence.PRESENT, 401),
            MODULE.AGE_RESTRICTED,
        )

    def test_detects_public_moderation_or_deletion_bypass(self):
        for status in ("restricted", "banned", "deleted"):
            metadata = MODULE.MetadataProbe(MODULE.Presence.PRESENT, status)
            self.assertEqual(
                MODULE.classify_blob(metadata, MODULE.Presence.PRESENT, 200),
                MODULE.DELIVERY_PATH_FAILURE,
            )

    def test_probe_errors_never_become_missing_state(self):
        metadata_error = MODULE.MetadataProbe(MODULE.Presence.ERROR)
        active = MODULE.MetadataProbe(MODULE.Presence.PRESENT, "active")

        self.assertEqual(
            MODULE.classify_blob(metadata_error, MODULE.Presence.MISSING),
            MODULE.PROBE_ERROR,
        )
        self.assertEqual(
            MODULE.classify_blob(active, MODULE.Presence.ERROR),
            MODULE.PROBE_ERROR,
        )
        self.assertEqual(
            MODULE.classify_blob(active, MODULE.Presence.PRESENT, -1),
            MODULE.PROBE_ERROR,
        )

    def test_inconsistent_metadata_is_distinct_from_probe_failure(self):
        inconsistent = MODULE.MetadataProbe(
            MODULE.Presence.PRESENT, "active", consistent=False
        )

        self.assertEqual(
            MODULE.classify_blob(inconsistent, MODULE.Presence.PRESENT, 500),
            MODULE.INCONSISTENT_METADATA,
        )

    def test_repaired_synthetic_case_passes_public_delivery_classification(self):
        synthetic_hash = "0123456789abcdef" * 4
        initial = MODULE.MetadataProbe(MODULE.Presence.MISSING)
        repaired = MODULE.MetadataProbe(MODULE.Presence.PRESENT, "active")

        self.assertEqual(len(synthetic_hash), 64)
        self.assertEqual(
            MODULE.classify_blob(initial, MODULE.Presence.PRESENT, 404),
            MODULE.MISSING_METADATA,
        )
        response = Mock(status_code=206)
        with (
            patch.object(MODULE.secrets, "token_hex", return_value="cache-buster"),
            patch.object(MODULE.requests, "get", return_value=response) as request,
        ):
            public_status = MODULE.probe_public("https://media.example", synthetic_hash)

        request.assert_called_once_with(
            f"https://media.example/{synthetic_hash}?_=cache-buster",
            headers={"Range": "bytes=0-0", "Cache-Control": "no-cache"},
            allow_redirects=False,
            timeout=15,
        )
        self.assertEqual(public_status, 206)
        self.assertEqual(
            MODULE.classify_blob(repaired, MODULE.Presence.PRESENT, public_status),
            MODULE.AVAILABLE,
        )


class PrivacyTests(unittest.TestCase):
    def test_scan_returns_aggregate_counts_only(self):
        synthetic_hashes = ["1" * 64, "2" * 64]
        metadata = {
            synthetic_hashes[0]: MODULE.MetadataProbe(MODULE.Presence.PRESENT, "active"),
            synthetic_hashes[1]: MODULE.MetadataProbe(MODULE.Presence.MISSING),
        }
        storage = {
            synthetic_hashes[0]: MODULE.Presence.PRESENT,
            synthetic_hashes[1]: MODULE.Presence.MISSING,
        }

        result = MODULE.scan(
            synthetic_hashes,
            metadata.__getitem__,
            storage.__getitem__,
            lambda value: 200 if value == synthetic_hashes[0] else 404,
        )

        rendered = str(result)
        self.assertEqual(result["total_scanned"], 2)
        self.assertEqual(result["privacy"], "aggregate_only")
        self.assertEqual(
            result["recommended_actions"],
            {"none": 1, "repair_at_event_source": 1},
        )
        self.assertNotIn(synthetic_hashes[0], rendered)
        self.assertNotIn(synthetic_hashes[1], rendered)

    def test_repair_only_targets_confirmed_missing_bytes(self):
        synthetic_hashes = ["3" * 64, "4" * 64]
        repaired = []

        result = MODULE.scan(
            synthetic_hashes,
            lambda value: MODULE.MetadataProbe(
                MODULE.Presence.PRESENT,
                "active" if value == synthetic_hashes[0] else "restricted",
            ),
            lambda _value: MODULE.Presence.MISSING,
            lambda _value: 404,
            repair=lambda value: repaired.append(value) is None,
            max_repairs=1,
            confirm_missing_count=1,
            curated_input=True,
        )

        self.assertEqual(repaired, [synthetic_hashes[0]])
        self.assertEqual(result["repairs"], {"soft_deleted": 1})

    def test_repair_stops_when_candidates_exceed_cap(self):
        synthetic_hashes = ["5" * 64, "6" * 64]
        repaired = []

        result = MODULE.scan(
            synthetic_hashes,
            lambda _value: MODULE.MetadataProbe(MODULE.Presence.PRESENT, "active"),
            lambda _value: MODULE.Presence.MISSING,
            lambda _value: 404,
            repair=lambda value: repaired.append(value) is None,
            max_repairs=1,
            confirm_missing_count=2,
            curated_input=True,
        )

        self.assertEqual(repaired, [])
        self.assertEqual(result["repairs"], {"skipped_over_limit": 2})

    def test_public_success_prevents_repair_of_replica_or_cache_served_bytes(self):
        metadata = MODULE.MetadataProbe(MODULE.Presence.PRESENT, "active")

        self.assertEqual(
            MODULE.classify_blob(metadata, MODULE.Presence.MISSING, 206),
            MODULE.STORAGE_PATH_DIVERGENCE,
        )

    def test_storage_miss_requires_public_evidence_before_repair(self):
        metadata = MODULE.MetadataProbe(MODULE.Presence.PRESENT, "active")

        self.assertEqual(
            MODULE.classify_blob(metadata, MODULE.Presence.MISSING),
            MODULE.UNVERIFIED_MISSING_BYTES,
        )
        self.assertEqual(
            MODULE.classify_blob(metadata, MODULE.Presence.MISSING, 500),
            MODULE.DELIVERY_PATH_FAILURE,
        )

    def test_alias_only_derived_audio_is_not_a_repair_candidate(self):
        metadata = MODULE.MetadataProbe(MODULE.Presence.PRESENT, "active")

        self.assertEqual(
            MODULE.classify_blob(
                metadata,
                MODULE.Presence.PRESENT,
                delivery_route=MODULE.DeliveryRoute.ALIAS_ONLY_DERIVED_AUDIO,
            ),
            MODULE.ALIAS_ONLY_DERIVED_AUDIO,
        )
        self.assertEqual(
            MODULE.classify_blob(
                metadata,
                MODULE.Presence.ERROR,
                delivery_route=MODULE.DeliveryRoute.ALIAS_ONLY_DERIVED_AUDIO,
            ),
            MODULE.PROBE_ERROR,
        )
        self.assertEqual(
            MODULE.classify_blob(
                metadata,
                MODULE.Presence.MISSING,
                404,
                MODULE.DeliveryRoute.ALIAS_ONLY_DERIVED_AUDIO,
            ),
            MODULE.ALIAS_ONLY_DERIVED_AUDIO,
        )

    def test_alias_only_derived_audio_skips_the_direct_public_probe(self):
        public_probe = Mock(return_value=404)

        result = MODULE.scan(
            ["a" * 64],
            lambda _value: MODULE.MetadataProbe(MODULE.Presence.PRESENT, "active"),
            lambda _value: MODULE.Presence.PRESENT,
            public_probe=public_probe,
            delivery_route_probe=lambda _value: (
                MODULE.DeliveryRoute.ALIAS_ONLY_DERIVED_AUDIO
            ),
        )

        self.assertEqual(result["counts"], {MODULE.ALIAS_ONLY_DERIVED_AUDIO: 1})
        public_probe.assert_not_called()

    def test_unknown_status_is_inconsistent_metadata(self):
        metadata = MODULE.MetadataProbe(MODULE.Presence.PRESENT, "unknown")

        self.assertEqual(
            MODULE.classify_blob(metadata, MODULE.Presence.PRESENT),
            MODULE.INCONSISTENT_METADATA,
        )

    def test_soft_delete_requires_admin_success(self):
        synthetic_hash = "b" * 64
        with patch.object(
            MODULE.requests, "post", return_value=Mock(status_code=200)
        ):
            self.assertTrue(
                MODULE.soft_delete_missing_bytes(
                    "https://admin.example", "token", synthetic_hash
                )
            )
        with patch.object(
            MODULE.requests, "post", return_value=Mock(status_code=404)
        ):
            self.assertFalse(
                MODULE.soft_delete_missing_bytes(
                    "https://admin.example", "token", synthetic_hash
                )
            )

    def test_scan_refuses_repair_without_prior_count_confirmation(self):
        repaired = []

        with self.assertRaisesRegex(ValueError, "confirmed missing-byte count"):
            MODULE.scan(
                ["7" * 64],
                lambda _value: MODULE.MetadataProbe(MODULE.Presence.PRESENT, "active"),
                lambda _value: MODULE.Presence.MISSING,
                repair=lambda value: repaired.append(value) is None,
                max_repairs=1,
                curated_input=True,
            )

        self.assertEqual(repaired, [])

    def test_scan_skips_repair_when_live_count_changed_since_confirmation(self):
        repaired = []

        result = MODULE.scan(
            ["8" * 64, "9" * 64],
            lambda _value: MODULE.MetadataProbe(MODULE.Presence.PRESENT, "active"),
            lambda _value: MODULE.Presence.MISSING,
            lambda _value: 404,
            repair=lambda value: repaired.append(value) is None,
            max_repairs=3,
            confirm_missing_count=1,
            curated_input=True,
        )

        self.assertEqual(repaired, [])
        self.assertEqual(result["repairs"], {"skipped_count_mismatch": 2})

    def test_repair_request_requires_credentials_cap_and_confirmed_count(self):
        self.assertIsNotNone(
            MODULE.validate_repair_request(True, None, None, None, 1, 1, True)
        )
        self.assertIsNotNone(
            MODULE.validate_repair_request(True, "token", "url", None, 1, 1, True)
        )
        self.assertIsNotNone(
            MODULE.validate_repair_request(True, "token", "url", "public", 1, 1, False)
        )
        self.assertIsNotNone(
            MODULE.validate_repair_request(True, "token", "url", "public", 0, 1, True)
        )
        self.assertIsNotNone(
            MODULE.validate_repair_request(True, "token", "url", "public", 1, None, True)
        )
        self.assertIsNotNone(
            MODULE.validate_repair_request(True, "token", "url", "public", 1, 2, True)
        )
        self.assertIsNone(
            MODULE.validate_repair_request(True, "token", "url", "public", 2, 1, True)
        )

    def test_scan_refuses_repair_from_uncurated_all_source(self):
        with self.assertRaisesRegex(ValueError, "curated hash file"):
            MODULE.scan(
                ["a" * 64],
                lambda _value: MODULE.MetadataProbe(MODULE.Presence.PRESENT, "active"),
                lambda _value: MODULE.Presence.MISSING,
                repair=lambda _value: True,
                max_repairs=1,
                confirm_missing_count=1,
            )

    def test_unsuccessful_repair_is_visible_to_exit_code_layer(self):
        self.assertTrue(
            MODULE.repair_did_not_complete({"repairs": {"skipped_count_mismatch": 1}})
        )
        self.assertTrue(
            MODULE.repair_did_not_complete({"repairs": {"skipped_count_mismatch": 0}})
        )
        self.assertTrue(MODULE.repair_did_not_complete({"repairs": {"failed": 1}}))
        self.assertTrue(
            MODULE.repair_did_not_complete(
                {"repairs": {"failed": 1, "soft_deleted": 1}}
            )
        )
        self.assertFalse(MODULE.repair_did_not_complete({"repairs": {"soft_deleted": 1}}))

    def test_progress_reports_counts_without_hashes(self):
        progress = []
        hashes = [f"{value:064x}" for value in range(MODULE.PROGRESS_INTERVAL)]

        MODULE.scan(
            hashes,
            lambda _value: MODULE.MetadataProbe(MODULE.Presence.PRESENT, "active"),
            lambda _value: MODULE.Presence.PRESENT,
            progress=progress.append,
        )

        self.assertEqual(progress, [MODULE.PROGRESS_INTERVAL])


class ProbeTests(unittest.TestCase):
    def test_fastly_session_retries_rate_limits_and_server_errors(self):
        session = MODULE.fastly_session("token")
        retry = session.get_adapter("https://").max_retries

        self.assertEqual(retry.total, 5)
        self.assertEqual(set(retry.status_forcelist), set(MODULE.RETRY_STATUS))
        self.assertEqual(set(retry.allowed_methods), {"GET"})

    def test_probe_metadata_handles_present_missing_and_inconsistent_records(self):
        blob_hash = "a" * 64
        valid = {
            "sha256": blob_hash,
            "type": "video/mp4",
            "uploaded": "2026-08-30T00:00:00Z",
            "owner": "b" * 64,
            "size": 1,
            "status": "active",
        }
        session = Mock()
        session.get.side_effect = [
            Mock(status_code=200, json=Mock(return_value=valid)),
            Mock(status_code=404),
            Mock(status_code=200, json=Mock(return_value=[])),
        ]

        present = MODULE.probe_metadata(session, "store", blob_hash)
        missing = MODULE.probe_metadata(session, "store", blob_hash)
        inconsistent = MODULE.probe_metadata(session, "store", blob_hash)

        self.assertEqual(present, MODULE.MetadataProbe(MODULE.Presence.PRESENT, "active", True))
        self.assertEqual(missing, MODULE.MetadataProbe(MODULE.Presence.MISSING))
        self.assertEqual(inconsistent.presence, MODULE.Presence.PRESENT)
        self.assertFalse(inconsistent.consistent)

    def test_probe_metadata_turns_request_failures_into_probe_errors(self):
        session = Mock()
        session.get.side_effect = MODULE.requests.RequestException("rate limited")

        self.assertEqual(
            MODULE.probe_metadata(session, "store", "a" * 64),
            MODULE.MetadataProbe(MODULE.Presence.ERROR),
        )

    def test_probe_storage_distinguishes_missing_object_from_other_errors(self):
        class NotFound(Exception):
            pass

        missing_bucket = Mock()
        missing_bucket.blob.return_value.reload.side_effect = NotFound()
        error_bucket = Mock()
        error_bucket.blob.return_value.reload.side_effect = RuntimeError("denied")

        self.assertEqual(
            MODULE.probe_storage(missing_bucket, "a" * 64, NotFound),
            MODULE.Presence.MISSING,
        )
        self.assertEqual(
            MODULE.probe_storage(error_bucket, "a" * 64, NotFound),
            MODULE.Presence.ERROR,
        )

    def test_bucket_validation_distinguishes_wrong_bucket_from_missing_object(self):
        class NotFound(Exception):
            pass

        client = Mock()
        client.get_bucket.side_effect = NotFound()

        with self.assertRaisesRegex(ValueError, "configured GCS bucket does not exist"):
            MODULE.get_bucket(client, "wrong-bucket", NotFound)

    def test_delivery_route_detects_alias_only_audio(self):
        session = Mock()
        session.get.side_effect = [
            Mock(status_code=200, json=Mock(return_value=["a" * 64])),
            Mock(status_code=404),
        ]

        route = MODULE.probe_delivery_route(session, "store", "b" * 64)

        self.assertEqual(route, MODULE.DeliveryRoute.ALIAS_ONLY_DERIVED_AUDIO)


class InputAndCliTests(unittest.TestCase):
    def test_hash_file_ignores_comments_deduplicates_and_rejects_invalid_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hashes.txt"
            path.write_text(f"# private\n{'a' * 64}\n{'A' * 64}\n\n", encoding="utf-8")
            self.assertEqual(MODULE.read_hash_file(path), ["a" * 64])
            path.write_text("not-a-hash\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid SHA-256"):
                MODULE.read_hash_file(path)

    def test_listing_follows_pagination_and_deduplicates_hashes(self):
        first_hash = "1" * 64
        second_hash = "2" * 64
        session = Mock()
        session.get.side_effect = [
            Mock(
                json=Mock(
                    return_value={
                        "data": [f"blob:{first_hash}", {"name": "not-a-blob"}],
                        "meta": {"next_cursor": "next"},
                    }
                )
            ),
            Mock(
                json=Mock(
                    return_value={
                        "data": [{"key": f"blob:{first_hash}"}, f"blob:{second_hash}"],
                        "meta": {},
                    }
                )
            ),
        ]

        hashes = MODULE.list_blob_hashes(session, "store", None)

        self.assertEqual(hashes, [first_hash, second_hash])
        self.assertEqual(session.get.call_args_list[1].kwargs["params"]["cursor"], "next")

    def test_listing_pushes_prefix_and_limit_into_fastly_requests(self):
        first_hash = "ab" + "1" * 62
        session = Mock()
        session.get.return_value = Mock(
            json=Mock(
                return_value={
                    "data": [f"blob:{first_hash}"],
                    "meta": {"next_cursor": "unused"},
                }
            )
        )

        hashes = MODULE.list_blob_hashes(session, "store", "ab", 1)

        self.assertEqual(hashes, [first_hash])
        self.assertEqual(
            session.get.call_args.kwargs["params"],
            {"limit": 1, "prefix": "blob:ab"},
        )

    def test_cli_rejects_ignored_flag_combinations(self):
        cases = [
            ["--hash-file", "private.txt", "--hex-prefix", "ab"],
            ["--all", "--max-repairs", "1"],
            ["--all", "--confirm-missing-count", "1"],
            [
                "--all",
                "--repair-missing-bytes",
                "--public-endpoint",
                "https://media.example",
                "--max-repairs",
                "1",
                "--confirm-missing-count",
                "1",
            ],
        ]

        for argv in cases:
            with self.subTest(argv=argv):
                self.assertIsNotNone(MODULE.validate_cli_request(MODULE.parse_args(argv)))


class MainExitCodeTests(unittest.TestCase):
    @staticmethod
    def args(repair=False):
        return argparse.Namespace(
            hash_file=Path("private.txt"),
            all=False,
            hex_prefix=None,
            limit=None,
            public_endpoint="https://media.example" if repair else None,
            repair_missing_bytes=repair,
            max_repairs=1 if repair else None,
            confirm_missing_count=1 if repair else None,
        )

    @staticmethod
    def google_modules():
        google = types.ModuleType("google")
        cloud = types.ModuleType("google.cloud")
        storage = types.ModuleType("google.cloud.storage")
        api_core = types.ModuleType("google.api_core")
        exceptions = types.ModuleType("google.api_core.exceptions")

        class NotFound(Exception):
            pass

        storage.Client = Mock
        exceptions.NotFound = NotFound
        google.cloud = cloud
        google.api_core = api_core
        cloud.storage = storage
        api_core.exceptions = exceptions
        return {
            "google": google,
            "google.cloud": cloud,
            "google.cloud.storage": storage,
            "google.api_core": api_core,
            "google.api_core.exceptions": exceptions,
        }

    def run_main(self, repair, result):
        environment = {
            "FASTLY_API_TOKEN": "fastly-token",
            "KV_STORE_ID": "store",
            "GCS_BUCKET": "expected-bucket",
            "FASTLY_ADMIN_TOKEN": "admin-token",
            "BLOSSOM_ADMIN_ENDPOINT": "https://admin.example",
        }
        with (
            patch.object(MODULE, "parse_args", return_value=self.args(repair)),
            patch.object(MODULE, "read_hash_file", return_value=["a" * 64]),
            patch.object(MODULE, "fastly_session", return_value=Mock()),
            patch.object(MODULE, "get_bucket", return_value=Mock()),
            patch.object(MODULE, "scan", return_value=result),
            patch.object(MODULE.sys, "stdout", new=io.StringIO()),
            patch.object(MODULE.sys, "stderr", new=io.StringIO()),
            patch.dict(MODULE.os.environ, environment, clear=True),
            patch.dict(sys.modules, self.google_modules()),
        ):
            return MODULE.main()

    def test_main_returns_success_for_read_only_scan(self):
        self.assertEqual(self.run_main(False, {"repairs": {}}), 0)

    def test_main_returns_partial_failure_for_incomplete_repair(self):
        self.assertEqual(self.run_main(True, {"repairs": {"failed": 1}}), 3)

    def test_main_returns_usage_error_before_network_work(self):
        args = self.args(False)
        args.max_repairs = 1
        with (
            patch.object(MODULE, "parse_args", return_value=args),
            patch.object(MODULE.sys, "stderr", new=io.StringIO()),
        ):
            self.assertEqual(MODULE.main(), 2)


if __name__ == "__main__":
    unittest.main()
