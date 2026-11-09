"""Bounded confirmation reads never retry a claim write or bypass ownership."""
from collections import deque
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error
import io
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

from test_sync_b2_originals import HASH, KV, Source, Destination, mirror


class Clock:
    def __init__(self):
        self.now, self.sleeps = 0.0, []
    def monotonic(self):
        return self.now
    def sleep(self, delay):
        self.sleeps.append(delay)
        self.now += delay


class Opener:
    """Real JsonHTTP with deterministic transport responses and elapsed time."""
    def __init__(self, clock, replies):
        self.clock, self.replies, self.calls = clock, deque(replies), []
        self.response_headers = {"generation": "7"}
    def open(self, request, timeout):
        self.calls.append((request.method, timeout))
        if request.method == 'PUT':
            self.value = json.loads(request.data)
            body = b''
        else:
            assert request.method == 'GET'
            delay, value = self.replies.popleft()
            self.clock.now += delay
            if value == 'absent':
                raise urllib.error.HTTPError(request.full_url, 404, 'synthetic absent', {}, io.BytesIO())
            if isinstance(value, Exception):
                raise value
            body = json.dumps(self.value if value == 'match' else value).encode()
        class Response:
            headers = {'generation': '7'}
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def read(self, size): return body[:size]
        response = Response()
        response.headers = self.response_headers
        return response


class ConfirmationTests(unittest.TestCase):
    def setup_claim(self, replies):
        clock = Clock()
        self.enterContext(patch.object(mirror.time, 'monotonic', clock.monotonic))
        self.enterContext(patch.object(mirror.time, 'sleep', clock.sleep))
        http = mirror.JsonHTTP()
        opener = Opener(clock, replies)
        http.opener = opener
        return mirror.FastlyKV('synthetic', 'synthetic', http=http), clock, opener

    def test_absent_then_match_retries_only_get_with_bounded_initial_timeout(self):
        kv, clock, opener = self.setup_claim([(0, 'absent'), (0, 'match')])
        self.assertTrue(kv.claim_copy(HASH, 'synthetic'))
        self.assertEqual(opener.calls, [('PUT', 30), ('GET', 1), ('GET', 1)])
        self.assertEqual(clock.sleeps, [1.0])
        self.assertIsNone(kv.claim_failure)

    def test_visibility_after_three_reads_confirms_without_repeating_add(self):
        kv, clock, opener = self.setup_claim([(0, 'absent')] * 6 + [(0, 'match')])
        self.assertTrue(kv.claim_copy(HASH, 'synthetic'))
        self.assertEqual([method for method, _ in opener.calls], ['PUT'] + ['GET'] * 7)
        self.assertGreaterEqual(clock.now, 6)
        self.assertLess(clock.now, 30)
        self.assertTrue(all(timeout <= 1 for method, timeout in opener.calls if method == 'GET'))

    def test_initial_slow_match_expires_without_acceptance(self):
        kv, clock, opener = self.setup_claim([(31, 'match')])
        with self.assertRaises(TimeoutError):
            kv.claim_copy(HASH, 'synthetic')
        self.assertEqual(opener.calls, [('PUT', 30), ('GET', 1)])
        self.assertEqual(clock.sleeps, [])

    def test_initial_slow_absence_expires_without_another_read(self):
        kv, clock, opener = self.setup_claim([(31, 'absent'), (0, 'match')])
        with self.assertRaises(TimeoutError):
            kv.claim_copy(HASH, 'synthetic')
        self.assertEqual(opener.calls, [('PUT', 30), ('GET', 1)])
        self.assertEqual(clock.sleeps, [])

    def test_present_null_is_terminal_even_if_later_read_would_match(self):
        kv, clock, opener = self.setup_claim([(0, None), (0, 'match')])
        with self.assertRaises(ValueError):
            kv.claim_copy(HASH, 'synthetic')
        self.assertEqual(kv.claim_failure, 'confirm_other')
        self.assertEqual(opener.calls, [('PUT', 30), ('GET', 1)])
        self.assertEqual(clock.sleeps, [])

    def test_absent_exhaustion_keeps_category_and_limits_attempts(self):
        kv, clock, opener = self.setup_claim([(0, 'absent')] * 30 + [(0, 'match')])
        with self.assertRaises(ValueError):
            kv.claim_copy(HASH, 'synthetic')
        self.assertEqual(kv.claim_failure, 'confirm_absent')
        self.assertEqual(opener.calls, [('PUT', 30)] + [('GET', 1)] * 30)
        self.assertEqual(clock.sleeps, [1.0] * 29)
        self.assertEqual(len(opener.replies), 1)

    def test_mismatch_or_error_stops_even_when_later_response_would_match(self):
        cases = [({'state': 'erasing'}, 'confirm_erasing', ValueError),
                 ({'state': 'copying', 'attempt_id': 'other'}, 'confirm_wrong_owner', ValueError),
                 ({'state': 'unknown'}, 'confirm_other', ValueError),
                 (TimeoutError('SYNTHETIC_SECRET'), 'confirm_transport', TimeoutError),
                 (ValueError('SYNTHETIC_SECRET'), 'confirm_response_invalid', ValueError)]
        for prefix in ([], [(0, 'absent')]):
            for value, category, exception in cases:
                with self.subTest(prefix=bool(prefix), category=category):
                    kv, _, opener = self.setup_claim(prefix + [(0, value), (0, 'match')])
                    with self.assertRaises(exception):
                        kv.claim_copy(HASH, 'synthetic')
                    self.assertEqual(kv.claim_failure, category)
                    self.assertEqual([m for m, _ in opener.calls], ['PUT'] + ['GET'] * (len(prefix) + 1))
                    self.assertEqual(len(opener.replies), 1)

    def test_invalid_generation_is_terminal_without_another_read_or_add(self):
        for generation in (None, '0', 'invalid'):
            with self.subTest(generation=generation):
                kv, _, opener = self.setup_claim([(0, 'match'), (0, 'match')])
                opener.response_headers = {'generation': generation}
                with self.assertRaises(ValueError):
                    kv.claim_copy(HASH, 'synthetic')
                self.assertEqual(kv.claim_failure, 'confirm_response_invalid')
                self.assertEqual([method for method, _ in opener.calls], ['PUT', 'GET'])
                self.assertEqual(len(opener.replies), 1)

    def test_remaining_budget_caps_timeout_and_late_match_is_rejected(self):
        # First retry's transport overruns its socket timeout; acceptance still expires.
        kv, clock, opener = self.setup_claim([(0, 'absent'), (27.25, 'absent'), (0.8, 'match')])
        with self.assertRaises(TimeoutError):
            kv.claim_copy(HASH, 'synthetic')
        self.assertEqual(kv.claim_failure, 'confirm_transport')
        self.assertEqual(opener.calls, [('PUT', 30), ('GET', 1), ('GET', 1), ('GET', 0.75)])
        self.assertEqual(clock.sleeps, [1.0, 1.0])

    def test_late_nonmatching_gate_is_also_rejected_at_deadline(self):
        for value, category in [({'state': 'erasing'}, 'confirm_erasing'),
                                ({'state': 'copying', 'attempt_id': 'other'}, 'confirm_wrong_owner')]:
            with self.subTest(category=category):
                kv, _, opener = self.setup_claim([(0, 'absent'), (30, value), (0, 'match')])
                with self.assertRaises(TimeoutError):
                    kv.claim_copy(HASH, 'synthetic')
                self.assertEqual(kv.claim_failure, 'confirm_transport')
                self.assertEqual(opener.calls, [('PUT', 30), ('GET', 1), ('GET', 1)])

    def test_expired_deadline_prevents_another_get(self):
        kv, clock, opener = self.setup_claim([(0, 'absent'), (30, 'absent'), (0, 'match')])
        with self.assertRaises(TimeoutError):
            kv.claim_copy(HASH, 'synthetic')
        self.assertEqual(kv.claim_failure, 'confirm_transport')
        self.assertEqual(opener.calls, [('PUT', 30), ('GET', 1), ('GET', 1)])
        self.assertEqual(clock.sleeps, [1.0])

    def test_sleep_overshoot_does_not_start_a_read_after_deadline(self):
        kv, clock, opener = self.setup_claim([(0, 'absent'), (0, 'match')])
        def delayed_sleep(delay):
            clock.now += 31
        with patch.object(mirror.time, 'sleep', delayed_sleep):
            with self.assertRaises(TimeoutError):
                kv.claim_copy(HASH, 'synthetic')
        self.assertEqual(kv.claim_failure, 'confirm_transport')
        self.assertEqual(opener.calls, [('PUT', 30), ('GET', 1)])

    def test_both_callers_wait_for_matching_ownership_before_remote_mutation(self):
        for caller in ('process', 'invalidate'):
            for confirms in (True, False):
                with self.subTest(caller=caller, confirms=confirms):
                    clock = Clock()
                    self.enterContext(patch.object(mirror.time, 'monotonic', clock.monotonic))
                    self.enterContext(patch.object(mirror.time, 'sleep', clock.sleep))
                    values, calls, confirmed = KV().values, [], [False]
                    if caller == 'invalidate':
                        values['blob:' + HASH]['status'] = 'restricted'
                        values['b2-ready:' + HASH] = {'synthetic': 'readiness'}
                    class HTTP:
                        reads = 0
                        def request(self, url, method='GET', value=None, **options):
                            key = unquote(urlsplit(url).path.rsplit('/', 1)[-1])
                            calls.append((method, key))
                            if method == 'PUT':
                                if key.startswith('b2-sync:'):
                                    assert urlsplit(url).query == 'add=true'
                                else:
                                    assert confirmed[0]
                                values[key] = value
                                return None
                            if method == 'DELETE':
                                assert confirmed[0]
                                values.pop(key, None)
                                return None
                            result = values.get(key)
                            if key.startswith('b2-sync:') and result is not None and not confirmed[0]:
                                self.reads += 1
                                if self.reads == 2 and confirms:
                                    confirmed[0] = True
                                else:
                                    return None
                            return (result, {'generation': '7'}) if options.get('include_headers') and result is not None else result
                    directory = tempfile.TemporaryDirectory()
                    self.addCleanup(directory.cleanup)
                    state = mirror.State(Path(directory.name))
                    self.addCleanup(state.close)
                    destination = Destination()
                    upload = destination.upload
                    def checked_upload(*args):
                        self.assertTrue(confirmed[0])
                        return upload(*args)
                    destination.upload = checked_upload
                    worker = mirror.Worker(Source(), destination, mirror.FastlyKV('synthetic', 'synthetic', http=HTTP()),
                                           state, max_object_bytes=100, chunk_bytes=5, max_spool_bytes=100)
                    report = worker.cycle(max_objects=1, max_bytes=1000)
                    self.assertEqual(calls.count(('PUT', 'b2-sync:v1:' + HASH)), 1)
                    if confirms:
                        self.assertEqual(report.get('ready' if caller == 'process' else 'blocked'), 1)
                        self.assertFalse(any(k.startswith('failure_') for k in report))
                        self.assertNotIn('b2-sync:v1:' + HASH, values)
                    else:
                        self.assertEqual(report.get('failure_gate_claim_confirm_absent'), 1)
                        self.assertEqual(report.get('errors'), 1)
                        self.assertEqual(destination.versions, {})
                        self.assertFalse(any(method == 'DELETE' for method, _ in calls))
                        self.assertIn('b2-sync:v1:' + HASH, values)


if __name__ == '__main__':
    unittest.main()
