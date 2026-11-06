"""Permanent erasure finishes every lane without touching remote state."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from test_sync_b2_originals import DATA, HASH, KV, Source, Destination, mirror


class ErasingTerminalTests(unittest.TestCase):
    def fixture(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        state = mirror.State(Path(directory.name))
        self.addCleanup(state.close)
        source, destination, kv = Source(), Destination(), KV()
        worker = mirror.Worker(source, destination, kv, state,
                               max_object_bytes=100, chunk_bytes=5, max_spool_bytes=100)
        return state, source, destination, kv, worker

    def cycle_gate(self, lane, gate, gate_read):
        state, source, destination, kv, worker = self.fixture()
        readiness = {'version': 1, 'sha256': HASH, 'verified_sha256': HASH,
                     'key': HASH, 'size': len(DATA), 'source_bucket': source.bucket,
                     'source_generation': '7', 'bucket': destination.bucket,
                     'destination_version_id': 'synthetic-version', 'verified_at': 1}
        kv.values['b2-ready:' + HASH] = readiness
        kv.values['b2-sync:v1:' + HASH] = gate
        before = copy.deepcopy(kv.values)
        if lane == 'upload':
            state.queue_upload(HASH, '7', now=1)
        elif lane == 'demand':
            state.queue_demand(HASH, {'version': 1, 'sha256': HASH, 'reason': 'missing_readiness'}, now=1)
        gate_reads, seen = [0], [False]
        get = kv.get
        def observe(key):
            if key == 'b2-sync:v1:' + HASH:
                gate_reads[0] += 1
                if gate_reads[0] < gate_read:
                    return None
                seen[0] = True
            else:
                self.assertFalse(seen[0], 'must stop policy/readiness reads after observing gate')
            return get(key)
        kv.get = observe
        def forbidden(*args, **kwargs):
            self.fail('terminal or locked gate must not read media or mutate remote state')
        for operation in ('put', 'delete', 'delete_if_generation', 'claim_copy', 'release_copy'):
            setattr(kv, operation, forbidden)
        source_head = source.head
        def head(key):
            self.assertFalse(seen[0])
            self.assertGreater(gate_read, 1)
            return source_head(key)
        source.head, source.read = head, forbidden
        destination.upload = destination.read = forbidden
        def exists(*args):
            self.assertFalse(seen[0])
            self.assertEqual(gate_read, 3)
            return True
        destination.exists = exists
        report = worker.cycle(max_objects=2 if lane != 'history' else 1, max_bytes=1000)
        self.assertTrue(seen[0])
        self.assertEqual(gate_reads[0], gate_read)
        self.assertEqual(kv.values, before)
        self.assertEqual(destination.versions, {})
        self.assertEqual(report.get('errors', 0), 0)
        self.assertEqual(report['transfer_bytes_reserved'], 0)
        self.assertNotIn(HASH, json.dumps(report))
        self.assertNotIn('SYNTHETIC_SECRET', json.dumps(report))
        return state, report

    def test_exact_erasing_marker_finishes_history_upload_and_demand(self):
        for lane in ('history', 'upload', 'demand'):
            for gate_read in (1, 2):
                with self.subTest(lane=lane, gate_read=gate_read):
                    state, report = self.cycle_gate(lane, {'state': 'erasing'}, gate_read)
                    self.assertEqual(report.get('terminal'), 1)
                    self.assertEqual(report.get('locked', 0), 0)
                    self.assertEqual(state.db.execute('SELECT COUNT(*) FROM upload_queue').fetchone()[0], 0)
                    self.assertEqual(state.db.execute('SELECT COUNT(*) FROM demand_queue').fetchone()[0], 0)
                    # History remains tracked for bounded scheduling, not forgotten.
                    self.assertGreater(state.db.execute('SELECT checked FROM objects WHERE hash=?', (HASH,)).fetchone()[0], 0)

    def test_erasing_observed_during_demand_adoption_is_terminal(self):
        state, report = self.cycle_gate('demand', {'state': 'erasing'}, 3)
        self.assertEqual(report.get('terminal'), 1)
        self.assertEqual(report.get('locked', 0), 0)
        self.assertEqual(state.db.execute('SELECT COUNT(*) FROM demand_queue').fetchone()[0], 0)

    def test_other_gate_values_remain_locked_and_intakes_remain_queued(self):
        gates = [{'state': 'copying', 'attempt_id': 'SYNTHETIC_SECRET'},
                 {'state': 'erasing', 'extra': 'SYNTHETIC_SECRET'},
                 {'state': 'unknown'}, {}, [], False]
        for lane, gate_read in [('history', 1), ('upload', 1), ('demand', 1),
                                ('history', 2), ('upload', 2), ('demand', 2), ('demand', 3)]:
            for gate in gates:
                with self.subTest(lane=lane, gate_read=gate_read, gate=gate):
                    state, report = self.cycle_gate(lane, gate, gate_read)
                    self.assertEqual(report.get('locked'), 1)
                    self.assertEqual(report.get('terminal', 0), 0)
                    self.assertEqual(state.db.execute('SELECT COUNT(*) FROM upload_queue').fetchone()[0], int(lane == 'upload'))
                    self.assertEqual(state.db.execute('SELECT COUNT(*) FROM demand_queue').fetchone()[0], int(lane == 'demand'))

    def test_erased_history_advances_to_unrelated_work_without_clearing_gate(self):
        state, source, destination, kv, worker = self.fixture()
        erased = 'b' * 64
        state.remember(erased)
        state.remember(HASH)
        state.checked(HASH)
        state.spool(erased).write_bytes(b'synthetic unfinished media')
        kv.values['b2-sync:v1:' + erased] = {'state': 'erasing'}
        readiness = {'synthetic': 'old readiness'}
        kv.values['b2-ready:' + erased] = readiness
        source.page = lambda *args: ([], None)
        first = worker.cycle(max_objects=1, max_bytes=1000)
        self.assertEqual(first.get('terminal'), 1)
        self.assertEqual(first.get('locked', 0), 0)
        self.assertFalse(state.spool(erased).exists())
        second = worker.cycle(max_objects=1, max_bytes=1000)
        self.assertEqual(second.get('ready'), 1)
        self.assertEqual(kv.values['b2-sync:v1:' + erased], {'state': 'erasing'})
        self.assertEqual(kv.values['b2-ready:' + erased], readiness)
        self.assertEqual(state.db.execute('SELECT COUNT(*) FROM objects').fetchone()[0], 2)


if __name__ == '__main__':
    unittest.main()
