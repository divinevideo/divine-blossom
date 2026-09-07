import importlib.util
import io
import sys
import threading
import time
import unittest
import urllib.error
from pathlib import Path
from unittest import mock


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "probe_video_readiness.py"


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def observation(mp4=202, master=202, variant=202, **details):
    return {
        "mp4_720": mp4,
        "hls_master": master,
        "hls_variant_manifest": variant,
        **details,
    }


def sequence_probe(clock, values, duration=0.0):
    remaining = list(values)

    def probe(*_args, **_kwargs):
        clock.now += duration
        if len(remaining) > 1:
            return remaining.pop(0)
        return remaining[0]

    return probe


def load_script_module(test_case: unittest.TestCase):
    if not SCRIPT_PATH.exists():
        test_case.fail(f"missing script: {SCRIPT_PATH}")

    spec = importlib.util.spec_from_file_location("probe_video_readiness", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        test_case.fail(f"unable to load script module: {SCRIPT_PATH}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class VideoReadinessProbeTests(unittest.TestCase):
    def test_classifies_mp4_delayed_after_hls(self):
        module = load_script_module(self)
        classify = getattr(module, "classify_observations", None)
        self.assertIsNotNone(classify, "classify_observations should exist")

        observations = [
            {
                "mp4_720": 404,
                "hls_master": 200,
                "hls_variant_manifest": 200,
            },
            {
                "mp4_720": 200,
                "hls_master": 200,
                "hls_variant_manifest": 200,
            },
        ]

        self.assertEqual(classify(observations), "mp4_delayed_hls_ready_first")

    def test_classifies_mp4_missing_while_hls_ready(self):
        module = load_script_module(self)
        classify = getattr(module, "classify_observations", None)
        self.assertIsNotNone(classify, "classify_observations should exist")

        observations = [
            {
                "mp4_720": 404,
                "hls_master": 200,
                "hls_variant_manifest": 200,
            },
            {
                "mp4_720": 404,
                "hls_master": 200,
                "hls_variant_manifest": 200,
            },
        ]

        self.assertEqual(classify(observations), "mp4_never_ready_hls_ready")

    def test_classifies_mp4_ready_immediately(self):
        module = load_script_module(self)
        classify = getattr(module, "classify_observations", None)
        self.assertIsNotNone(classify, "classify_observations should exist")

        observations = [
            {
                "mp4_720": 200,
                "hls_master": 200,
                "hls_variant_manifest": 200,
            }
        ]

        self.assertEqual(classify(observations), "mp4_ready_immediately")

    def test_builds_expected_probe_urls(self):
        module = load_script_module(self)
        builder = getattr(module, "build_target_urls", None)
        self.assertIsNotNone(builder, "build_target_urls should exist")

        media_hash = "a" * 64
        urls = builder("media.divine.video", media_hash)

        self.assertEqual(urls["mp4_720"], f"https://media.divine.video/{media_hash}/720p.mp4")
        self.assertEqual(urls["hls_master"], f"https://media.divine.video/{media_hash}.hls")
        self.assertEqual(
            urls["hls_variant_manifest"],
            f"https://media.divine.video/{media_hash}/hls/stream_720p.m3u8",
        )

    def test_extracts_hashes_from_mixed_lines(self):
        module = load_script_module(self)
        extractor = getattr(module, "extract_hashes", None)
        self.assertIsNotNone(extractor, "extract_hashes should exist")

        lines = [
            "832e9a4d6b9de70ceffb134ddd77b96b9b9de371457892092aa6aa853cd3f8a1",
            "https://media.divine.video/E3C2C5C7CFC7A35ED4120130D0363E25A63420A35642C20393758CB674D245C8/720p.mp4",
            "not a hash",
            "832e9a4d6b9de70ceffb134ddd77b96b9b9de371457892092aa6aa853cd3f8a1",
        ]

        self.assertEqual(
            extractor(lines),
            [
                "832e9a4d6b9de70ceffb134ddd77b96b9b9de371457892092aa6aa853cd3f8a1",
                "e3c2c5c7cfc7a35ed4120130d0363e25a63420a35642c20393758cb674d245c8",
            ],
        )

    def test_assertion_passes_when_all_required_endpoints_are_ready(self):
        module = load_script_module(self)
        clock = FakeClock()
        result = module.assert_readiness(
            {},
            probe=sequence_probe(clock, [observation(200, 200, 200)]),
            clock=clock,
            sleep=clock.sleep,
        )
        self.assertEqual(result.exit_code, module.EXIT_READY)
        self.assertEqual(len(result.observations), 1)

    def test_assertion_retries_pending_until_ready(self):
        module = load_script_module(self)
        clock = FakeClock()
        result = module.assert_readiness(
            {},
            deadline_seconds=10,
            interval_seconds=2,
            probe=sequence_probe(clock, [observation(), observation(200, 200, 200)]),
            clock=clock,
            sleep=clock.sleep,
        )
        self.assertEqual(result.exit_code, module.EXIT_READY)
        self.assertEqual(len(result.observations), 2)

    def test_assertion_times_out_with_last_seen_states(self):
        module = load_script_module(self)
        clock = FakeClock()
        result = module.assert_readiness(
            {},
            deadline_seconds=5,
            interval_seconds=2,
            probe=sequence_probe(clock, [observation()]),
            clock=clock,
            sleep=clock.sleep,
        )
        self.assertEqual(result.exit_code, module.EXIT_NOT_READY)
        self.assertEqual(clock.now, 5)
        self.assertEqual(len(result.observations), 3)
        self.assertIn("mp4_720=Pending(202)", result.reason)

    def test_assertion_fails_immediately_on_hls_master_terminal_sentinel(self):
        module = load_script_module(self)
        clock = FakeClock()
        result = module.assert_readiness(
            {},
            required_endpoints=("mp4_720",),
            probe=sequence_probe(
                clock,
                [
                    observation(
                        404,
                        422,
                        404,
                        hls_master_error_code="invalid_media",
                        hls_master_message="moov atom not found",
                    )
                ],
            ),
            clock=clock,
            sleep=clock.sleep,
        )
        self.assertEqual(result.exit_code, module.EXIT_TERMINAL)
        self.assertEqual(len(result.observations), 1)
        self.assertIn("invalid_media", result.reason)
        self.assertIn("moov atom not found", result.reason)

    def test_unavailable_and_blocked_are_not_collapsed(self):
        module = load_script_module(self)
        self.assertEqual(module.resolve_endpoint_state(404), "Unavailable")
        self.assertEqual(module.resolve_endpoint_state(401), "Blocked")
        self.assertEqual(module.resolve_endpoint_state(403), "Blocked")

    def test_network_error_at_deadline_has_distinct_exit_code(self):
        module = load_script_module(self)
        clock = FakeClock()
        result = module.assert_readiness(
            {},
            deadline_seconds=1,
            probe=sequence_probe(clock, [observation(0, 200, 200)], duration=1),
            clock=clock,
            sleep=clock.sleep,
        )
        self.assertEqual(result.exit_code, module.EXIT_USAGE_OR_NETWORK)

    def test_terminal_sentinel_network_error_is_actionable_for_subset(self):
        module = load_script_module(self)
        clock = FakeClock()
        result = module.assert_readiness(
            {},
            required_endpoints=("mp4_720",),
            deadline_seconds=1,
            probe=sequence_probe(clock, [observation(202, 0, 404)], duration=1),
            clock=clock,
            sleep=clock.sleep,
        )
        self.assertEqual(result.exit_code, module.EXIT_USAGE_OR_NETWORK)
        self.assertIn("hls_master=NetworkError(0)", result.reason)

    def test_probe_caps_each_request_to_remaining_deadline(self):
        module = load_script_module(self)
        clock = FakeClock()
        timeouts = []
        original_fetch = module.fetch_endpoint

        def fake_fetch(_url, method, timeout_seconds, auth_header=None):
            self.assertEqual(method, "HEAD")
            self.assertIsNone(auth_header)
            timeouts.append(timeout_seconds)
            clock.now += 0.4
            return module.FetchResult(202)

        module.fetch_endpoint = fake_fetch
        try:
            module.probe_once(
                {key: f"https://example.test/{key}" for key in module.ENDPOINT_ORDER},
                timeout_seconds=10,
                deadline=1,
                clock=clock,
            )
        finally:
            module.fetch_endpoint = original_fetch

        self.assertEqual(len(timeouts), 3)
        for actual, expected in zip(timeouts, [1, 0.6, 0.2]):
            self.assertAlmostEqual(actual, expected)

    def test_unknown_status_is_reported_explicitly(self):
        module = load_script_module(self)
        self.assertEqual(module.resolve_endpoint_state(500), "Unknown")

    def test_assertion_stops_requests_on_first_terminal_response(self):
        module = load_script_module(self)
        urls = {key: f"https://example.test/{key}" for key in module.ENDPOINT_ORDER}
        for terminal_key in ("hls_master", "mp4_720"):
            with self.subTest(terminal_key=terminal_key):
                calls = []

                def fetch(url, *_args):
                    key = url.rsplit("/", 1)[1]
                    calls.append(key)
                    return module.FetchResult(422 if key == terminal_key else 200)

                with mock.patch.object(module, "fetch_endpoint", side_effect=fetch):
                    result = module.assert_readiness(urls)
                self.assertEqual(result.exit_code, module.EXIT_TERMINAL)
                self.assertEqual(calls[-1], terminal_key)
                self.assertNotIn("hls_variant_manifest", calls)

    def test_assertion_bounds_blocked_io_by_wall_clock(self):
        module = load_script_module(self)
        release = threading.Event()
        finished = threading.Event()

        def blocked_fetch(*_args):
            try:
                release.wait(5)
                return module.FetchResult(200)
            finally:
                finished.set()

        urls = {key: f"https://example.test/{key}" for key in module.ENDPOINT_ORDER}
        try:
            with mock.patch.object(module, "fetch_endpoint", side_effect=blocked_fetch):
                start = time.monotonic()
                result = module.assert_readiness(urls, deadline_seconds=0.1)
                elapsed = time.monotonic() - start
            self.assertEqual(result.exit_code, module.EXIT_NOT_READY)
            self.assertNotIn("NetworkError", result.reason)
            self.assertLess(elapsed, 1)
        finally:
            release.set()
            self.assertTrue(finished.wait(1))

    def test_late_ready_response_does_not_pass(self):
        module = load_script_module(self)
        clock = FakeClock()
        result = module.assert_readiness(
            {}, deadline_seconds=1,
            probe=sequence_probe(clock, [observation(200, 200, 200)], duration=2),
            clock=clock, sleep=clock.sleep,
        )
        self.assertEqual(result.exit_code, module.EXIT_NOT_READY)
        self.assertIn("readiness observed after the deadline", result.reason)

    def test_terminal_on_nonrequired_endpoint_overrides_readiness(self):
        module = load_script_module(self)
        clock = FakeClock()
        result = module.assert_readiness(
            {}, required_endpoints=("mp4_720", "hls_master"),
            probe=sequence_probe(clock, [observation(200, 200, 422)]),
            clock=clock, sleep=clock.sleep,
        )
        self.assertEqual(result.exit_code, module.EXIT_TERMINAL)

    def test_request_timeout_before_global_deadline_remains_network_error(self):
        module = load_script_module(self)
        clock = FakeClock()
        urls = {key: f"https://example.test/{key}" for key in module.ENDPOINT_ORDER}
        with mock.patch.object(module, "fetch_endpoint", return_value=module.FetchResult(
            0, network_error="TimeoutError"
        )):
            observed = module.probe_once(urls, deadline=10, timeout_seconds=1, clock=clock)
        self.assertEqual(module.resolve_endpoint_state(observed["hls_master"]), "NetworkError")

    def test_nonfinite_timings_are_usage_errors(self):
        module = load_script_module(self)
        for name in ("deadline_seconds", "timeout_seconds", "interval_seconds"):
            for value in (float("nan"), float("inf"), float("-inf")):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    module.assert_readiness({}, **{name: value})

    def test_terminal_body_read_failure_preserves_status(self):
        module = load_script_module(self)
        for failure in (TimeoutError(), module.http.client.IncompleteRead(b"partial")):
            body = mock.Mock()
            body.read.side_effect = failure
            error = urllib.error.HTTPError(
                "https://example.test/media", 422, "unprocessable",
                {"X-Error-Code": "invalid_media"}, body,
            )
            with mock.patch.object(module.urllib.request, "urlopen", side_effect=error):
                result = module.fetch_endpoint("https://example.test/media", "GET", 1)
            self.assertEqual(result.status, 422)
            self.assertEqual(result.error_code, "invalid_media")
            body.close.assert_called_once()

    def test_invalid_auth_header_is_not_in_network_error(self):
        module = load_script_module(self)
        with mock.patch.object(module.urllib.request, "urlopen", side_effect=ValueError(
            "Invalid header value b'Nostr synthetic-secret\\n'"
        )):
            result = module.fetch_endpoint("https://example.test/media", "GET", 1)
        self.assertEqual(result.status, 0)
        self.assertNotIn("synthetic-secret", result.network_error)

    def test_get_terminal_response_extracts_error_details_and_auth(self):
        module = load_script_module(self)
        error = urllib.error.HTTPError(
            "https://example.test/media",
            422,
            "unprocessable",
            {"X-Error-Code": "header_code"},
            io.BytesIO(b'{"error_code":"invalid_media","message":"bad container"}'),
        )
        with mock.patch.object(module.urllib.request, "urlopen", side_effect=error) as urlopen:
            result = module.fetch_endpoint(
                "https://example.test/media",
                "GET",
                4,
                auth_header="Nostr synthetic-auth",
            )

        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Nostr synthetic-auth")
        self.assertEqual(result.status, 422)
        self.assertEqual(result.error_code, "invalid_media")
        self.assertEqual(result.message, "bad container")

    def test_assertion_usage_errors_exit_three(self):
        module = load_script_module(self)
        with mock.patch("sys.stderr", new=io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                module.main(["--assert", "--hash", "not-a-hash"])
        self.assertEqual(raised.exception.code, module.EXIT_USAGE_OR_NETWORK)

    def test_authenticated_assertion_does_not_print_auth_header(self):
        module = load_script_module(self)
        ready = module.AssertionResult(
            module.EXIT_READY,
            "all required endpoints are ready",
            (observation(200, 200, 200),),
        )
        output = io.StringIO()
        with mock.patch.object(module, "assert_readiness", return_value=ready):
            with mock.patch("sys.stdout", new=output):
                exit_code = module.main(
                    [
                        "--assert",
                        "--hash",
                        "a" * 64,
                        "--auth-header",
                        "Nostr synthetic-secret",
                    ]
                )
        self.assertEqual(exit_code, module.EXIT_READY)
        self.assertNotIn("synthetic-secret", output.getvalue())

    def test_media_fixtures_have_and_lack_moov_atom(self):
        fixture_dir = Path(__file__).resolve().parent / "fixtures"
        self.assertIn(b"moov", (fixture_dir / "readiness_ok.mp4").read_bytes())
        self.assertNotIn(b"moov", (fixture_dir / "readiness_terminal.mp4").read_bytes())


if __name__ == "__main__":
    unittest.main()
