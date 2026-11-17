"""Finite demand/readiness diagnostics; synthetic requests never leave this process."""
import contextlib
import http.client
import io
import json
import socket
import sqlite3
import ssl
import unittest
import urllib.error
from unittest.mock import patch

from test_b2_demand import WorkerFixture, hint
from test_sync_b2_originals import HASH, mirror

SECRET = 'SYNTHETIC_SECRET_DO_NOT_REPORT'


class Response:
    def __init__(self, body, headers=None):
        self.body, self.headers = body, headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def read(self, size):
        return self.body[:size]


class Opener:
    def __init__(self, *replies):
        self.replies, self.requests = list(replies), []

    def open(self, request, timeout):
        self.requests.append((request.method, dict(request.header_items()), timeout))
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def http_error(status):
    return urllib.error.HTTPError('https://synthetic.invalid/' + SECRET, status,
                                  SECRET, {'Private': SECRET}, io.BytesIO(SECRET.encode()))


class ControlDiagnosticsTests(WorkerFixture):
    def kv_with(self, *replies):
        http = mirror.JsonHTTP()
        opener = Opener(*replies)
        http.opener = opener
        self.worker.kv = mirror.FastlyKV('synthetic', SECRET, http=http)
        return opener

    def cycle(self, demand=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            report = self.worker.cycle(max_objects=1, max_bytes=1000,
                                       demand=demand, demand_only=True)
        encoded = json.dumps(report)
        self.assertEqual(stdout.getvalue() + stderr.getvalue(), '')
        self.assertNotIn(SECRET, encoded)
        self.assertNotIn(HASH, encoded)
        self.assertTrue(all(type(v) is int and v >= 0 for v in report.values()))
        self.assertLessEqual(set(self.diagnostics(report)), mirror.CONTROL_DIAGNOSTIC_COUNTERS)
        return report

    def diagnostics(self, report):
        return {k: v for k, v in report.items() if k.startswith('failure_control_')}

    def test_list_failures_are_finite_private_and_do_not_retry(self):
        cases = [(http_error(code), 'http_' + str(code))
                 for code in (400, 401, 403, 404, 409, 412, 429)]
        cases += [(http_error(503), 'http_5xx'), (http_error(302), 'http_other'),
                  (urllib.error.URLError(TimeoutError(SECRET)), 'timeout'),
                  (urllib.error.URLError(socket.gaierror(SECRET)), 'dns'),
                  (urllib.error.URLError(ssl.SSLError(SECRET)), 'tls'),
                  (urllib.error.URLError(SECRET), 'transport'),
                  (http.client.IncompleteRead(SECRET.encode()), 'transport'),
                  (Response(b'{"secret":'), 'json_invalid'),
                  (Response(b'{"data":[],"data":[]}'), 'json_duplicate'),
                  (Response(b'x' * (mirror.MIB + 1)), 'response_too_large'),
                  (Response(b'{}'), 'list_invalid'),
                  (Response(b'{"data":[],"meta":{"next_cursor":7}}'), 'cursor_invalid'),
                  (RuntimeError(SECRET), 'other')]
        for reply, category in cases:
            with self.subTest(category=category):
                opener = self.kv_with(reply)
                report = self.cycle(mirror.DemandHints(self.worker.kv))
                self.assertEqual(report['demand_errors'], 1)
                self.assertEqual(report['errors'], 1)
                self.assertEqual(self.diagnostics(report),
                                 {'failure_control_demand_list_' + category: 1})
                self.assertEqual([r[0] for r in opener.requests], ['GET'])
                self.assertEqual(self.source.reads, [])
                self.assertEqual(self.dest.versions, {})

    def test_readiness_failures_keep_pending_and_exact_backoff_without_effects(self):
        self.state.queue_demand(HASH, hint(), now=100)
        for reply, category in [(http_error(403), 'http_403'),
                                (Response(b'{}'), 'generation_missing'),
                                (Response(b'{}', {'generation': '0'}), 'generation_invalid'),
                                (Response(b'x' * 4097), 'response_too_large')]:
            with self.subTest(category=category):
                opener = self.kv_with(reply)
                with patch.object(mirror.time, 'time', return_value=100):
                    report = self.cycle()
                self.assertEqual(report['failure_readiness_read'], 1)
                self.assertEqual(self.diagnostics(report),
                                 {'failure_control_readiness_read_' + category: 1})
                self.assertEqual(self.state.queued_demands(1, now=399), [])
                self.assertEqual(self.state.queued_demands(1, now=400), [HASH])
                self.assertEqual([r[0] for r in opener.requests], ['GET'])
                self.assertEqual(self.dest.versions, {})
                # Make the same retained synthetic item due for the next fault.
                self.state.db.execute('UPDATE demand_queue SET available_at=100')
                self.state.db.commit()

    def test_absent_snapshot_stays_normal_and_diagnostics_reset_each_cycle(self):
        opener = self.kv_with(http_error(401), Response(b'{"data":[]}'))
        intake = mirror.DemandHints(self.worker.kv)
        self.assertEqual(self.cycle(intake)['errors'], 1)
        report = self.cycle(intake)
        self.assertEqual(report.get('errors', 0), 0)
        self.assertEqual(self.diagnostics(report), {})
        opener = self.kv_with(Response(json.dumps({'data': [mirror.DEMAND_PREFIX + HASH]}).encode()),
                              http_error(404))
        report = self.cycle(mirror.DemandHints(self.worker.kv))
        self.assertEqual(report.get('errors', 0), 0)
        self.assertEqual(self.diagnostics(report), {})
        self.assertEqual([r[0] for r in opener.requests], ['GET', 'GET'])
        self.kv_with(http_error(404))
        self.assertIsNone(self.worker.kv.snapshot('b2-ready:' + HASH))

    def test_snapshot_failure_is_reported_without_acknowledging_hint(self):
        opener = self.kv_with(Response(json.dumps({'data': [mirror.DEMAND_PREFIX + HASH]}).encode()),
                              http_error(503))
        report = self.cycle(mirror.DemandHints(self.worker.kv))
        self.assertEqual(report['demand_snapshot_errors'], 1)
        self.assertEqual(report['errors'], 1)
        self.assertEqual(self.diagnostics(report), {'failure_control_demand_snapshot_http_5xx': 1})
        self.assertEqual([r[0] for r in opener.requests], ['GET', 'GET'])

    def test_ack_failure_retains_committed_queue_and_conditional_request(self):
        opener = self.kv_with(Response(json.dumps({'data': [mirror.DEMAND_PREFIX + HASH]}).encode()),
                              Response(json.dumps(hint()).encode(), {'generation': '7'}),
                              http_error(403))
        # Keep the newly committed request pending without processing it here.
        with patch.object(self.state, 'queued_demands', return_value=[]):
            report = self.cycle(mirror.DemandHints(self.worker.kv))
        self.assertEqual(report['demand_pending'], 1)
        self.assertEqual(report['errors'], 1)
        self.assertEqual(self.diagnostics(report), {'failure_control_demand_ack_http_403': 1})
        self.assertEqual([r[0] for r in opener.requests], ['GET', 'GET', 'DELETE'])
        self.assertEqual(opener.requests[-1][1]['If-generation-match'], '7')

    def test_state_failure_is_not_mislabeled_as_provider_error(self):
        opener = self.kv_with(Response(json.dumps({'data': [mirror.DEMAND_PREFIX + HASH]}).encode()),
                              Response(json.dumps(hint()).encode(), {'generation': '7'}))
        with patch.object(self.state, 'queue_demand', side_effect=sqlite3.OperationalError(SECRET)):
            report = self.cycle(mirror.DemandHints(self.worker.kv))
        self.assertEqual(self.diagnostics(report), {'failure_control_demand_state_state_error': 1})
        self.assertEqual([r[0] for r in opener.requests], ['GET', 'GET'])

    def test_cursor_rejection_resets_only_cursor_without_immediate_retry(self):
        self.state.set_setting('demand_cursor', SECRET)
        self.state.queue_demand(HASH, hint(), now=100)
        self.state.defer_demand(HASH, now=100)
        opener = self.kv_with(http_error(400))
        with patch.object(mirror.time, 'time', return_value=100):
            report = self.cycle(mirror.DemandHints(self.worker.kv))
        self.assertIsNone(self.state.setting('demand_cursor'))
        self.assertEqual(self.state.queued_demands(1, now=399), [])
        self.assertEqual(self.state.queued_demands(1, now=400), [HASH])
        self.assertEqual(self.diagnostics(report), {'failure_control_demand_list_http_400': 1})
        self.assertEqual([r[0] for r in opener.requests], ['GET'])

    def test_conditional_ack_conflict_is_normal_and_does_not_drop_queued_work(self):
        opener = self.kv_with(Response(json.dumps({'data': [mirror.DEMAND_PREFIX + HASH]}).encode()),
                              Response(json.dumps(hint()).encode(), {'generation': '7'}),
                              http_error(412))
        with patch.object(self.state, 'queued_demands', return_value=[]):
            report = self.cycle(mirror.DemandHints(self.worker.kv))
        self.assertEqual(report.get('errors', 0), 0)
        self.assertEqual(report['demand_conflicts'], 1)
        self.assertEqual(report['demand_pending'], 1)
        self.assertEqual(self.diagnostics(report), {})
        self.assertEqual([r[0] for r in opener.requests], ['GET', 'GET', 'DELETE'])
        self.assertEqual(opener.requests[-1][1]['If-generation-match'], '7')

    def test_first_readiness_failure_survives_later_cleanup_error(self):
        def fail(error):
            raise error
        with self.assertRaises(TimeoutError):
            self.worker.observe('readiness_read', fail, TimeoutError(SECRET))
        with self.assertRaises(mirror.ControlAPIError):
            self.worker.observe('gate_release', fail, mirror.ControlAPIError(403))
        self.assertEqual(self.worker.failure_stage, 'readiness_read')
        self.assertEqual(self.worker.control_failure_kind, 'timeout')

    def test_readiness_timeout_also_covers_confirmation_window_expiry(self):
        reads = []

        def absent(timeout):
            reads.append(timeout)
            return None

        with patch.object(mirror.time, 'monotonic', side_effect=[0, 0, 30]):
            with self.assertRaises(TimeoutError):
                self.worker.observe('readiness_read', mirror.confirm_readback, absent)
        self.assertEqual(reads, [1.0])
        self.assertEqual(self.worker.failure_stage, 'readiness_read')
        self.assertEqual(self.worker.control_failure_kind, 'timeout')

    def test_partial_snapshot_diagnostics_survive_later_intake_abort(self):
        other = 'b' * 64
        listing = {'data': [mirror.DEMAND_PREFIX + other, mirror.DEMAND_PREFIX + HASH]}
        opener = self.kv_with(Response(json.dumps(listing).encode()), http_error(503),
                              Response(json.dumps(hint()).encode(), {'generation': '7'}),
                              http_error(403))
        intake = mirror.DemandHints(self.worker.kv)
        with self.assertRaises(mirror.ControlAPIError):
            intake.ingest(self.state, 2)
        self.assertEqual(dict(intake.diagnostics), {
            'failure_control_demand_snapshot_http_5xx': 1,
            'failure_control_demand_ack_http_403': 1,
        })
        self.assertEqual([r[0] for r in opener.requests], ['GET', 'GET', 'GET', 'DELETE'])
        self.assertEqual(self.state.queued_demands(1), [HASH])

    def test_classifier_never_promotes_unknown_labels_or_exception_strings(self):
        class UnprintableError(RuntimeError):
            def __str__(self):
                raise AssertionError('diagnostics must not format provider exceptions')
        self.assertEqual(mirror.control_failure(UnprintableError(SECRET)), 'other')
        error = ValueError(SECRET)
        error._b2_control_kind = SECRET
        self.assertEqual(mirror.control_failure(error), 'response_invalid')
        self.assertEqual(mirror.control_failure(mirror.ControlAPIError(SECRET)), 'http_other')
        self.assertEqual(mirror.control_failure(urllib.error.URLError(SECRET)), 'transport')
        counters = mirror.CONTROL_DIAGNOSTIC_COUNTERS
        self.assertEqual(len(counters), 115)
        self.assertEqual(len(counters), len(mirror.CONTROL_OPERATIONS) * len(mirror.CONTROL_FAILURES))
        self.assertLess(len(json.dumps(dict.fromkeys(counters, 1))), 12000)
        self.assertNotIn(SECRET, ''.join(counters))


if __name__ == '__main__':
    unittest.main()
