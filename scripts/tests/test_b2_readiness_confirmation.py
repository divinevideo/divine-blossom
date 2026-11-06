"""Post-publication confirmation retries missing reads without replaying writes."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_b2_claim_confirmation import Clock
from test_sync_b2_originals import DATA, HASH, KV, Source, Destination, mirror


class ReadinessConfirmationTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.enterContext(patch.object(mirror.time, 'monotonic', self.clock.monotonic))
        self.enterContext(patch.object(mirror.time, 'sleep', self.clock.sleep))
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.state = mirror.State(Path(self.directory.name))
        self.addCleanup(self.state.close)
        self.kv, self.destination = KV(), Destination()
        self.worker = mirror.Worker(Source(), self.destination, self.kv, self.state,
                                   max_object_bytes=100, chunk_bytes=5, max_spool_bytes=100)
        self.reads, self.puts, self.uploads = [], [], []
        put, upload = self.kv.put, self.destination.upload
        def counted_put(*args):
            self.puts.append(args)
            return put(*args)
        def counted_upload(*args):
            self.uploads.append(args)
            return upload(*args)
        self.kv.put, self.destination.upload = counted_put, counted_upload

    def responses(self, replies):
        snapshot = self.kv.snapshot
        remaining = iter(replies)
        def read(key, **options):
            actual = snapshot(key)
            if actual is None:
                return None  # Only inject after the readiness PUT.
            self.reads.append(options.get('timeout'))
            delay, value = next(remaining, (0, 'match'))
            self.clock.now += delay
            if isinstance(value, Exception):
                raise value
            return actual if value == 'match' else value
        self.kv.snapshot = read

    def process(self):
        return self.worker.process(HASH, mirror.Budget(1000))

    def test_absent_then_exact_publication_completes_without_reupload_or_rewrite(self):
        self.responses([(0, None), (0, 'match')])
        try:
            outcome = self.process()
        except ValueError:
            outcome = 'publication_failed'
        self.assertEqual(outcome, 'ready')
        self.assertEqual((len(self.uploads), len(self.puts)), (1, 1))
        self.assertEqual(self.reads, [1, 1])
        self.assertIsNotNone(self.state.row(HASH)[2])

    def test_absence_exhaustion_never_marks_ready_or_replays_writes(self):
        self.responses([(0, None)] * 3)
        with self.assertRaises(ValueError):
            self.process()
        self.assertEqual(len(self.reads), 3)
        self.assertEqual((len(self.uploads), len(self.puts)), (1, 1))
        self.assertIsNone(self.state.row(HASH)[2])

    def test_conflict_or_malformed_snapshot_is_not_retried(self):
        for value in [({'version': 99}, '7'), ({}, '7'), ValueError('synthetic malformed')]:
            with self.subTest(value=value):
                # Each fixture needs a fresh worker and local state.
                fixture = ReadinessConfirmationTests()
                fixture.setUp()
                try:
                    fixture.responses([(0, value), (0, 'match')])
                    with self.assertRaises(ValueError):
                        fixture.process()
                    self.assertEqual(len(fixture.reads), 1)
                    self.assertIsNone(fixture.state.row(HASH)[2])
                finally:
                    fixture.doCleanups()

    def test_late_first_match_is_not_ready(self):
        self.responses([(4, 'match')])
        with self.assertRaises(TimeoutError):
            self.process()
        self.assertIsNone(self.state.row(HASH)[2])
        self.assertEqual(len(self.reads), 1)

    def test_confirmation_deadline_retains_existing_read_failure_stage(self):
        self.responses([(4, 'match')])
        report = self.worker.cycle(max_objects=1, max_bytes=1000)
        self.assertEqual(report.get('failure_readiness_read'), 1)
        self.assertEqual(report.get('errors'), 1)
        self.assertIsNone(self.state.row(HASH)[2])

    def test_policy_revoked_while_absent_is_still_rechecked_before_ready(self):
        self.responses([(0, None), (0, 'match')])
        def revoke(delay):
            self.clock.sleep(delay)
            self.kv.values['blob:' + HASH]['status'] = 'restricted'
        with patch.object(mirror.time, 'sleep', revoke):
            self.assertEqual(self.process(), 'blocked')
        self.assertIsNone(self.state.row(HASH)[2])
        self.assertNotIn('b2-ready:' + HASH, self.kv.values)
        self.assertEqual((len(self.uploads), len(self.puts)), (1, 1))
