"""Explicit invariant diagnostics are fixed counters, never error payloads."""
import copy
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from test_sync_b2_originals import HASH, KV, Source, Destination, mirror

SECRET = 'SYNTHETIC_SECRET https://synthetic.invalid/signed?token=secret ' + 'f' * 64
MESSAGES = {
    'source_length': 'source range length mismatch',
    'source_checksum': 'source checksum mismatch',
    'destination_version': 'destination did not return immutable version',
    'destination_length': 'destination range length mismatch',
    'destination_checksum': 'destination checksum mismatch',
    'readiness_identity': 'remote readiness cannot be adopted or repaired',
    'readiness_publication': 'readiness publication not confirmed',
}


class ValidationDiagnosticsTests(unittest.TestCase):
    def fixture(self, category=None):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        state = mirror.State(Path(directory.name))
        self.addCleanup(state.close)
        source, destination, kv = Source(), Destination(), KV()
        worker = mirror.Worker(source, destination, kv, state,
                               max_object_bytes=100, chunk_bytes=5, max_spool_bytes=100)
        if category == 'source_length':
            source.read = lambda *args: b''
        elif category == 'source_checksum':
            source.read = lambda key, generation, start, length: b'x' * length
        elif category == 'destination_version':
            upload = destination.upload
            def invalid_version(*args):
                upload(*args)
                return None
            destination.upload = invalid_version
        elif category == 'destination_length':
            destination.read = lambda *args: b''
        elif category == 'destination_checksum':
            destination.corrupt = True
        elif category == 'readiness_identity':
            kv.values['b2-ready:' + HASH] = {'untrusted': SECRET}
            state.queue_demand(HASH, {'version': 1, 'sha256': HASH, 'reason': 'missing_readiness'}, now=1)
        elif category == 'readiness_publication':
            kv.after_put = lambda: kv.values.pop('b2-ready:' + HASH)
        return worker, state, source, destination, kv

    def assert_private(self, report):
        encoded = json.dumps(report)
        for value in (SECRET, 'SYNTHETIC_SECRET', 'https://', 'token=secret', 'f' * 64, HASH):
            self.assertNotIn(value, encoded)

    def test_seven_explicit_invariants_keep_broad_counter_and_existing_side_effects(self):
        for category in MESSAGES:
            with self.subTest(category=category):
                worker, _, _, destination, kv = self.fixture(category)
                policy = copy.deepcopy(kv.values['blob:' + HASH])
                report = worker.cycle(max_objects=2, max_bytes=1000)
                self.assertEqual(report.get('errors'), 1)
                self.assertEqual(report.get('failure_validation_or_state'), 1)
                self.assertEqual({k: v for k, v in report.items() if k.startswith('failure_')},
                                 {'failure_validation_or_state': 1, 'failure_validation_' + category: 1})
                if category in ('destination_version', 'readiness_publication'):
                    self.assertEqual(kv.get('b2-sync:v1:' + HASH)['state'], 'copying')
                else:
                    self.assertIsNone(kv.get('b2-sync:v1:' + HASH))
                self.assertEqual(kv.values['blob:' + HASH], policy)
                uploaded = category.startswith('destination_') or category == 'readiness_publication'
                self.assertEqual(bool(destination.versions), uploaded)
                self.assertEqual(kv.get('b2-ready:' + HASH), {'untrusted': SECRET} if category == 'readiness_identity' else None)
                self.assert_private(report)

    def test_tagged_invariants_preserve_exact_valueerror_type_and_message(self):
        for category, message in MESSAGES.items():
            with self.subTest(category=category):
                worker, _, _, _, _ = self.fixture(category)
                with self.assertRaises(ValueError) as caught:
                    worker.process(HASH, mirror.Budget(1000), reconcile=category == 'readiness_identity')
                self.assertIs(type(caught.exception), ValueError)
                self.assertEqual(str(caught.exception), message)
                self.assertEqual(getattr(caught.exception, '_b2_validation_kind', None), category)

    def test_unconfirmed_different_publication_keeps_pointer_private_and_untouched(self):
        worker, _, _, _, kv = self.fixture()
        replacement = {'untrusted': SECRET}
        def replace():
            kv.values['b2-ready:' + HASH] = replacement
        kv.after_put = replace
        report = worker.cycle(max_objects=1, max_bytes=1000)
        self.assertEqual(report.get('failure_validation_readiness_publication'), 1)
        self.assertEqual(report.get('failure_validation_or_state'), 1)
        self.assertIs(kv.values['b2-ready:' + HASH], replacement)
        self.assertEqual(kv.get('b2-sync:v1:' + HASH)['state'], 'copying')
        self.assert_private(report)

    def test_local_state_and_unrecognized_tags_stay_generic(self):
        errors = [sqlite3.OperationalError(SECRET), OSError(SECRET), ValueError(SECRET)]
        for tag in (SECRET, ['source_length'], True, None):
            error = ValueError(SECRET)
            error._b2_validation_kind = tag
            errors.append(error)
        for error in errors:
            with self.subTest(error_type=type(error).__name__, tag=getattr(error, '_b2_validation_kind', None)):
                worker, state, _, _, _ = self.fixture()
                def fail(*args):
                    raise error
                state.row = fail
                report = worker.cycle(max_objects=1, max_bytes=1000)
                self.assertEqual({k: v for k, v in report.items() if k.startswith('failure_')},
                                 {'failure_validation_or_state': 1})
                self.assertEqual(report.get('errors'), 1)
                self.assert_private(report)

    def test_observed_operation_and_cleanup_failures_keep_precedence(self):
        for cleanup in (False, True):
            with self.subTest(cleanup=cleanup):
                worker, _, source, _, kv = self.fixture('destination_length' if cleanup else None)
                error = ValueError(SECRET)
                error._b2_validation_kind = 'source_length'
                def fail(*args):
                    raise error
                if cleanup:
                    kv.release_copy = fail
                else:
                    source.read = fail
                report = worker.cycle(max_objects=1, max_bytes=1000)
                self.assertEqual({k: v for k, v in report.items() if k.startswith('failure_')},
                                 {'failure_gate_release' if cleanup else 'failure_source_read': 1})
                if cleanup:
                    self.assertEqual(kv.get('b2-sync:v1:' + HASH)['state'], 'copying')
                self.assert_private(report)

    def test_next_successful_attempt_has_no_stale_validation_detail(self):
        worker, _, source, _, _ = self.fixture('source_length')
        report = worker.cycle(max_objects=1, max_bytes=1000)
        self.assertEqual(report.get('failure_validation_source_length'), 1)
        source.read = Source().read
        report = worker.cycle(max_objects=1, max_bytes=1000)
        self.assertEqual(report.get('ready'), 1)
        self.assertFalse(any(k.startswith('failure_') for k in report))
        self.assert_private(report)


if __name__ == '__main__':
    unittest.main()
