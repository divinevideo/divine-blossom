"""Fixed aggregate claim diagnostics; all services are synthetic and in-process."""
import http.client
import io
import urllib.error
import json
from pathlib import Path
import tempfile
import unittest
from urllib.parse import unquote, urlsplit

from test_sync_b2_originals import DATA, HASH, KV, Source, Destination, mirror

SECRET = 'SYNTHETIC_SECRET'


class ClaimHTTP:
    """Model an accepted add whose reply or confirmation can fail independently."""
    def __init__(self, phase, reply):
        self.values = KV().values
        self.phase, self.reply = phase, reply
        self.methods = []
        self.claimed = False

    def request(self, url, method='GET', value=None, **options):
        key = unquote(urlsplit(url).path.rsplit('/', 1)[-1])
        self.methods.append(method)
        if method == 'PUT':
            assert urlsplit(url).query == 'add=true'
            self.values[key] = value
            self.claimed = True
            if self.phase == 'add':
                raise self.reply
            return None
        assert method == 'GET', 'uncertain claim must not delete a gate'
        if self.claimed and key.startswith('b2-sync:'):
            if isinstance(self.reply, Exception):
                raise self.reply
            return (self.reply, {'generation': '7'}) if options.get('include_headers') and self.reply is not None else self.reply
        result = self.values.get(key)
        return (result, {'generation': '7'}) if options.get('include_headers') and result is not None else result


class ClaimDiagnosticsTests(unittest.TestCase):
    def run_failure(self, caller, phase, reply):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        state = mirror.State(Path(directory.name))
        self.addCleanup(state.close)
        http = ClaimHTTP(phase, reply)
        if caller == 'invalidate':
            http.values['blob:' + HASH]['status'] = 'restricted'
            http.values['b2-ready:' + HASH] = {'synthetic': 'existing readiness'}
        kv = mirror.FastlyKV('synthetic', SECRET, http=http)
        destination = Destination()
        worker = mirror.Worker(Source(), destination, kv, state,
                               max_object_bytes=100, chunk_bytes=5, max_spool_bytes=100)
        report = worker.cycle(max_objects=1, max_bytes=1000)
        self.assertEqual(report['errors'], 1)
        self.assertEqual(report['failure_gate_claim'], 1)
        self.assertEqual(http.methods.count('PUT'), 1)
        self.assertNotIn('DELETE', http.methods)
        self.assertEqual(destination.versions, {})
        self.assertEqual(http.values['b2-sync:v1:' + HASH]['state'], 'copying')
        self.assertEqual('b2-ready:' + HASH in http.values, caller == 'invalidate')
        self.assertNotIn(SECRET, json.dumps(report))
        self.assertNotIn(HASH, json.dumps(report))
        return worker, http, report

    def test_both_callers_classify_failed_claim_without_replay_cleanup_or_upload(self):
        cases = [
            ('add', mirror.ControlAPIError(403), 'add_http'),
            ('add', TimeoutError(SECRET), 'add_transport'),
            ('add', ValueError(SECRET), 'add_response_invalid'),
            ('confirm', mirror.ControlAPIError(503), 'confirm_http'),
            ('confirm', http.client.IncompleteRead(b'SYNTHETIC_SECRET'), 'confirm_transport'),
            ('confirm', ValueError(SECRET), 'confirm_response_invalid'),
            ('confirm', None, 'confirm_absent'),
            ('confirm', {'state': 'copying', 'attempt_id': SECRET}, 'confirm_wrong_owner'),
            ('confirm', {'state': 'erasing'}, 'confirm_erasing'),
            ('confirm', {'state': SECRET}, 'confirm_other'),
        ]
        for caller in ('process', 'invalidate'):
            for phase, reply, category in cases:
                with self.subTest(caller=caller, category=category):
                    _, _, report = self.run_failure(caller, phase, reply)
                    self.assertEqual({k: v for k, v in report.items() if k.startswith('failure_gate_claim_')},
                                     {'failure_gate_claim_' + category: 1})

    def test_detail_does_not_survive_next_object_attempt_or_override_first_failure(self):
        worker, http, _ = self.run_failure('process', 'confirm', None)
        # The next cycle observes the retained gate; no new add is attempted.
        http.claimed = False  # End confirmation fault injection; expose stored gate.
        report = worker.cycle(max_objects=1, max_bytes=1000)
        self.assertEqual(report.get('locked'), 1)
        self.assertFalse(any(k.startswith('failure_') for k in report))
        self.assertEqual(http.methods.count('PUT'), 1)
        # A later claim error cannot replace an earlier operation's diagnosis.
        worker.failure_stage = 'source_read'
        worker.failure_detail = None
        def fail():
            raise ValueError(SECRET)
        with self.assertRaises(ValueError):
            worker.observe('gate_claim', fail)
        self.assertEqual(worker.failure_stage, 'source_read')
        self.assertIsNone(worker.failure_detail)

    def test_unknown_detail_is_not_promoted_to_public_counter(self):
        worker, _, _ = self.run_failure('process', 'confirm', None)
        worker.kv.claim_failure = SECRET
        worker.failure_stage = worker.failure_detail = None
        def fail():
            raise ValueError(SECRET)
        with self.assertRaises(ValueError):
            worker.observe('gate_claim', fail)
        self.assertEqual(worker.failure_stage, 'gate_claim')
        self.assertIsNone(worker.failure_detail)

    def test_real_json_http_classifies_status_transport_and_invalid_response(self):
        class Response:
            headers = {}
            def __init__(self, body):
                self.body = body
            def __enter__(self):
                return self
            def __exit__(self, *_):
                pass
            def read(self, size):
                return self.body[:size]

        class Opener:
            def __init__(self, phase, outcome):
                self.phase, self.outcome, self.methods = phase, outcome, []
            def open(self, request, timeout):
                self.methods.append(request.method)
                if request.method == 'PUT' and self.phase == 'confirm':
                    return Response(b'')
                if isinstance(self.outcome, Exception):
                    raise self.outcome
                return Response(self.outcome)

        for phase in ('add', 'confirm'):
            cases = [
                (urllib.error.HTTPError('https://synthetic.invalid/' + SECRET, 503,
                                        SECRET, {}, io.BytesIO(SECRET.encode())), 'http', mirror.ControlAPIError),
                (urllib.error.URLError(SECRET), 'transport', urllib.error.URLError),
                (b'{"secret":', 'response_invalid', ValueError),
                (b'{"state":"copying","state":"erasing"}', 'response_invalid', ValueError),
                (b'x' * (mirror.MIB + 1), 'response_invalid', ValueError),
            ]
            for outcome, category, error_type in cases:
                with self.subTest(phase=phase, category=category, outcome_type=type(outcome).__name__):
                    http = mirror.JsonHTTP()
                    opener = Opener(phase, outcome)
                    http.opener = opener
                    kv = mirror.FastlyKV('synthetic', SECRET, http=http)
                    with self.assertRaises(error_type):
                        kv.claim_copy(HASH, 'synthetic-attempt')
                    self.assertEqual(kv.claim_failure, phase + '_' + category)
                    self.assertEqual(opener.methods, ['PUT'] if phase == 'add' else ['PUT', 'GET'])

    def test_http_conflict_and_matching_confirmation_keep_existing_outcomes(self):
        class HTTP:
            def __init__(self, conflict):
                self.conflict, self.methods = conflict, []
            def request(self, url, method='GET', value=None, **options):
                self.methods.append(method)
                if method == 'PUT':
                    self.value = value
                    return False if self.conflict else None
                return (self.value, {'generation': '7'}) if options.get('include_headers') else self.value
        for conflict in (True, False):
            http = HTTP(conflict)
            kv = mirror.FastlyKV('synthetic', SECRET, http=http)
            self.assertEqual(kv.claim_copy(HASH, 'synthetic-attempt'), not conflict)
            self.assertEqual(http.methods, ['PUT'] if conflict else ['PUT', 'GET'])
            self.assertIsNone(kv.claim_failure)


if __name__ == '__main__':
    unittest.main()
