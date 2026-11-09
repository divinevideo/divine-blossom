"""Synthetic, durable evidence for new attempts; never an unlock mechanism."""
import json
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote
from unittest.mock import patch

from test_sync_b2_originals import DATA, HASH, Destination, KV, Source, mirror


class AttemptJournalTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.state = mirror.State(self.path)
        self.addCleanup(lambda: self.state.close())
        self.attempt = str(uuid.uuid4())
        self.assertTrue(hasattr(self.state, 'begin_attempt'), 'durable attempt journal is missing')

    def events(self):
        with closing(sqlite3.connect(self.path / 'state.sqlite3')) as db:
            return [(phase, json.loads(payload)) for phase, payload in db.execute(
                'SELECT phase,payload FROM attempt_events ORDER BY sequence')]

    def begin(self):
        self.state.begin_attempt(HASH, self.attempt, Source.bucket,
                                 Destination.bucket, '7', len(DATA))

    def test_migration_reopens_legacy_state_without_claiming_old_gate(self):
        self.state.queue_demand(HASH, {'version': 1, 'sha256': HASH,
                                      'reason': 'missing_readiness'}, now=100)
        self.state.close()
        with closing(sqlite3.connect(self.path / 'state.sqlite3')) as db:
            db.execute('DROP TABLE IF EXISTS attempt_events')
            db.commit()
        self.state = mirror.State(self.path)
        self.assertEqual(self.state.queued_demands(10, now=101), [HASH])
        self.assertEqual(self.events(), [])
        self.assertEqual(self.state.db.execute('PRAGMA synchronous').fetchone()[0], 2)

    def test_attempt_mapping_and_effect_intent_survive_reopen(self):
        self.begin()
        self.state.attempt_event(HASH, self.attempt, 'claim_intent', {})
        self.state.close()
        self.state = mirror.State(self.path)
        events = self.events()
        self.assertEqual([x[0] for x in events], ['attempt_started', 'claim_intent'])
        self.assertEqual(events[0][1], {'source_bucket': Source.bucket,
            'destination_bucket': Destination.bucket, 'source_generation': '7',
            'size': len(DATA), 'binding': None})
        for sql in ['UPDATE attempt_events SET phase=phase', 'DELETE FROM attempt_events']:
            with self.assertRaises(sqlite3.IntegrityError):
                self.state.db.execute(sql)
            self.state.db.rollback()

    def test_event_cannot_change_attempt_identity_or_accept_arbitrary_fields(self):
        self.begin()
        for key, attempt, phase, payload in [
            ('f' * 64, self.attempt, 'claim_intent', {}),
            (HASH, str(uuid.uuid4()), 'claim_intent', {}),
            (HASH, self.attempt, 'unknown', {}),
            (HASH, self.attempt, 'claim_ack', {'token': 'SYNTHETIC_SECRET'}),
            (HASH, self.attempt, 'claim_confirmed', {'gate_generation': 'null'}),
        ]:
            with self.subTest(phase=phase):
                with self.assertRaises(ValueError):
                    self.state.attempt_event(key, attempt, phase, payload)
        self.assertNotIn('SYNTHETIC_SECRET', repr(self.events()))

    def test_failed_commit_latches_no_later_effect_even_after_storage_recovers(self):
        self.begin()
        self.state.db.execute("CREATE TRIGGER fail_journal BEFORE INSERT ON attempt_events BEGIN SELECT RAISE(ABORT,'synthetic disk failure'); END")
        self.state.db.commit()
        with self.assertRaises(sqlite3.DatabaseError):
            self.state.attempt_event(HASH, self.attempt, 'claim_intent', {})
        self.state.db.execute('DROP TRIGGER fail_journal')
        self.state.db.commit()
        with self.assertRaises(RuntimeError):
            self.state.attempt_event(HASH, self.attempt, 'release_intent', {})
        self.assertEqual([x[0] for x in self.events()], ['attempt_started'])

    def test_worker_commits_evidence_before_every_existing_write(self):
        test = self
        class RecordedKV(KV):
            def claim_copy(self, key, attempt):
                test.assertEqual(test.events()[-1][0], 'claim_intent')
                return super().claim_copy(key, attempt)
            def put(self, key, value):
                test.assertEqual(test.events()[-1], ('readiness_put_intent', {'record': value}))
                return super().put(key, value)
            def release_copy(self, key, attempt):
                test.assertEqual(test.events()[-1][0], 'release_intent')
                return super().release_copy(key, attempt)
        class RecordedDestination(Destination):
            def upload(self, *args):
                test.assertEqual(test.events()[-1][0], 'destination_put_intent')
                return super().upload(*args)
        kv, destination = RecordedKV(), RecordedDestination()
        worker = mirror.Worker(Source(), destination, kv, self.state,
            max_object_bytes=100, chunk_bytes=5, max_spool_bytes=100)
        self.assertEqual(worker.process(HASH, mirror.Budget(1000)), 'ready')
        phases = [x[0] for x in self.events()]
        self.assertIn('destination_put_returned', phases)
        self.assertIn('destination_verified', phases)
        self.assertIn('readiness_put_ack', phases)
        self.assertIn('readiness_confirmed', phases)
        self.assertEqual(self.events()[phases.index('destination_put_returned')][1],
                         {'destination_version_id': 'version-1'})

    def test_worker_failed_intent_does_not_claim_or_put(self):
        self.state.db.execute("CREATE TRIGGER fail_journal BEFORE INSERT ON attempt_events BEGIN SELECT RAISE(ABORT,'synthetic disk failure'); END")
        self.state.db.commit()
        kv, destination = KV(), Destination()
        worker = mirror.Worker(Source(), destination, kv, self.state,
            max_object_bytes=100, chunk_bytes=5, max_spool_bytes=100)
        with self.assertRaises(sqlite3.DatabaseError):
            worker.process(HASH, mirror.Budget(1000))
        self.assertNotIn('b2-sync:v1:' + HASH, kv.values)
        self.assertEqual(destination.versions, {})

    def test_attempt_pins_existing_source_destination_store_binding(self):
        identity = {'source': Source.bucket, 'destination': Destination.bucket,
                    'bucket_id': 'synthetic-id', 'kv_store': 'synthetic-store'}
        self.state.bind(identity)
        self.begin()
        self.assertEqual(self.events()[0][1]['binding'], identity)

    def test_readiness_evidence_must_match_pinned_source_and_mapping(self):
        self.begin()
        record = {'version': 1, 'sha256': HASH, 'verified_sha256': HASH,
                  'key': HASH, 'source_bucket': Source.bucket, 'source_generation': '7',
                  'bucket': Destination.bucket, 'size': len(DATA),
                  'destination_version_id': 'synthetic-version', 'verified_at': 100}
        for field, changed in [('source_generation', '8'), ('size', len(DATA) + 1),
                               ('source_bucket', 'other-source'), ('bucket', 'other-destination')]:
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    self.state.attempt_event(HASH, self.attempt, 'readiness_put_intent',
                                             {'record': dict(record, **{field: changed})})
        self.assertEqual([x[0] for x in self.events()], ['attempt_started'])

    def test_directory_sync_failure_prevents_effect_and_latches_failure(self):
        self.begin()
        with patch.object(self.state, 'sync_directory', side_effect=OSError('synthetic fsync')):
            with self.assertRaises(OSError):
                self.state.attempt_event(HASH, self.attempt, 'claim_intent', {})
        with self.assertRaises(RuntimeError):
            self.state.attempt_event(HASH, self.attempt, 'release_intent', {})

    def test_failed_put_intent_retains_claim_without_upload_or_release(self):
        self.state.db.execute("CREATE TRIGGER fail_journal BEFORE INSERT ON attempt_events WHEN NEW.phase='destination_put_intent' BEGIN SELECT RAISE(ABORT,'synthetic disk failure'); END")
        self.state.db.commit()
        kv, destination = KV(), Destination()
        worker = mirror.Worker(Source(), destination, kv, self.state,
            max_object_bytes=100, chunk_bytes=5, max_spool_bytes=100)
        with self.assertRaises(sqlite3.DatabaseError):
            worker.process(HASH, mirror.Budget(1000))
        self.assertEqual(kv.values['b2-sync:v1:' + HASH]['state'], 'copying')
        self.assertEqual(destination.versions, {})

    def test_migration_failure_makes_no_network_request(self):
        args = ['--source-bucket', Source.bucket, '--destination-bucket', Destination.bucket,
                '--destination-bucket-id', 'synthetic-id', '--erasure-bucket', Destination.bucket,
                '--erasure-bucket-id', 'synthetic-id', '--kv-store-id', 'synthetic-store',
                '--state-dir', str(self.path / 'new-state')]
        with patch.object(mirror, 'State', side_effect=sqlite3.OperationalError('synthetic migration')), \
             patch.object(mirror, 'private_b2_endpoint', side_effect=AssertionError('network before migration')), \
             patch.dict(mirror.os.environ, {'B2_APPLICATION_KEY_ID': 'synthetic', 'B2_APPLICATION_KEY': 'synthetic'}):
            with self.assertRaises(sqlite3.OperationalError):
                mirror.main(args)

    def test_incompatible_migration_closes_database_and_prevents_network(self):
        self.state.close()
        with closing(sqlite3.connect(self.path / 'state.sqlite3')) as db:
            db.execute('DROP TABLE attempt_events')
            db.execute('CREATE TABLE attempt_events(wrong_schema TEXT)')
            db.commit()
        with self.assertRaisesRegex(ValueError, 'incompatible attempt journal'):
            mirror.State(self.path)
        # No connection retained the failed migration's write lock.
        with closing(sqlite3.connect(self.path / 'state.sqlite3', timeout=0)) as db:
            db.execute('BEGIN EXCLUSIVE')
            db.rollback()

    def test_failed_readiness_ack_commit_retains_gate_and_does_not_release(self):
        kv, destination = KV(), Destination()
        def fail_ack():
            self.state.db.execute("CREATE TRIGGER fail_journal BEFORE INSERT ON attempt_events WHEN NEW.phase='readiness_put_ack' BEGIN SELECT RAISE(ABORT,'synthetic disk failure'); END")
            self.state.db.commit()
        kv.after_put = fail_ack
        worker = mirror.Worker(Source(), destination, kv, self.state,
            max_object_bytes=100, chunk_bytes=5, max_spool_bytes=100)
        with self.assertRaises(sqlite3.DatabaseError):
            worker.process(HASH, mirror.Budget(1000))
        self.assertIn('b2-sync:v1:' + HASH, kv.values)
        self.assertIn('b2-ready:' + HASH, kv.values)
        self.assertEqual(self.events()[-1][0], 'readiness_put_intent')

    def test_real_control_http_records_existing_ack_generations_without_extra_reads(self):
        values, calls, failures = KV().values, [], []
        test = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def reply(self, status, value=None):
                data = json.dumps(value).encode() if value is not None else b''
                self.send_response(status)
                self.send_header('Content-Length', str(len(data)))
                self.send_header('generation', '7')
                self.end_headers()
                self.wfile.write(data)
            def key(self):
                return unquote(self.path.split('?')[0].rsplit('/', 1)[-1])
            def do_GET(self):
                key = self.key(); calls.append(('GET', key))
                self.reply(200, values[key]) if key in values else self.reply(404)
            def check_intent(self, phase):
                if test.events()[-1][0] != phase:
                    failures.append(phase)
                    self.reply(500)
                    return False
                return True
            def do_PUT(self):
                key = self.key(); calls.append(('PUT', key))
                if not self.check_intent('claim_intent' if key.startswith('b2-sync:') else 'readiness_put_intent'):
                    return
                values[key] = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                self.reply(200)
            def do_DELETE(self):
                key = self.key(); calls.append(('DELETE', key))
                if not self.check_intent('release_send'): return
                if self.headers.get('if-generation-match') != '7':
                    self.reply(412); return
                values.pop(key, None)
                self.reply(200)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            kv = mirror.FastlyKV('synthetic-store', 'synthetic-token')
            kv.base = 'http://127.0.0.1:' + str(server.server_port) + '/keys/'
            worker = mirror.Worker(Source(), Destination(), kv, self.state,
                max_object_bytes=100, chunk_bytes=5, max_spool_bytes=100)
            self.assertEqual(worker.process(HASH, mirror.Budget(1000)), 'ready')
        finally:
            server.shutdown(); server.server_close(); thread.join()
        self.assertEqual(failures, [])
        events = dict(self.events())
        self.assertEqual(events['claim_ack'], {'accepted': True})
        self.assertEqual(events['claim_confirmed'], {'gate_generation': '7'})
        self.assertEqual(events['release_ack'], {'gate_generation': '7', 'mode': 'delete'})
        self.assertEqual([method for method, key in calls if key.startswith('b2-sync:')],
                         ['GET', 'GET', 'PUT', 'GET', 'GET', 'DELETE'])
        self.assertEqual([method for method, key in calls if key.startswith('b2-ready:')],
                         ['GET', 'GET', 'PUT', 'GET'])

    def test_abrupt_process_exit_preserves_each_effect_prefix_without_replay(self):
        child = r'''
import os,sys,json
from pathlib import Path
from test_sync_b2_originals import HASH,Source,Destination,KV,mirror
directory=Path(sys.argv[1]);stop=sys.argv[2]
state=mirror.State(directory)
def effect(name):
    with (directory/'synthetic-effects.jsonl').open('a') as f:
        f.write(json.dumps(name)+'\n');f.flush();os.fsync(f.fileno())
    if stop=='after_'+name:os._exit(92)
class K(KV):
    def claim_copy(self,*a):effect('claim');return super().claim_copy(*a)
    def put(self,*a):effect('readiness');return super().put(*a)
    def release_copy(self,*a):effect('release');return super().release_copy(*a)
class D(Destination):
    def upload(self,*a):effect('upload');return super().upload(*a)
original=state.attempt_event
def record(*a):
    original(*a)
    if a[2]==stop:os._exit(91)
state.attempt_event=record
worker=mirror.Worker(Source(),D(),K(),state,max_object_bytes=100,chunk_bytes=5,max_spool_bytes=100)
worker.process(HASH,mirror.Budget(1000))
state.close()
'''
        prefixes = {'attempt_started': [], 'claim_intent': [],
            'destination_put_intent': ['claim'],
            'destination_put_returned': ['claim', 'upload'],
            'destination_verified': ['claim', 'upload'],
            'readiness_put_intent': ['claim', 'upload'],
            'readiness_put_ack': ['claim', 'upload', 'readiness'],
            'readiness_confirmed': ['claim', 'upload', 'readiness'],
            'release_intent': ['claim', 'upload', 'readiness']}
        for stop, effects in prefixes.items():
            with self.subTest(stop=stop), tempfile.TemporaryDirectory() as directory:
                run = subprocess.run([sys.executable, '-c', child, directory, stop],
                    env={**os.environ, 'PYTHONPATH': str(Path(__file__).parent)},
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(run.returncode, 91, run.stderr)
                state = mirror.State(Path(directory))
                try:
                    rows = state.db.execute('SELECT phase FROM attempt_events ORDER BY sequence').fetchall()
                    self.assertEqual(rows[-1][0], stop)
                    trace = Path(directory) / 'synthetic-effects.jsonl'
                    self.assertEqual([json.loads(x) for x in trace.read_text().splitlines()] if trace.exists() else [], effects)
                    self.assertEqual(state.db.execute("SELECT count(*) FROM attempt_events WHERE phase='release_ack'").fetchone()[0], 0)
                finally: state.close()
        for effect_name, last_phase in [('claim', 'claim_intent'), ('upload', 'destination_put_intent'),
                                        ('readiness', 'readiness_put_intent'), ('release', 'release_intent')]:
            with self.subTest(after=effect_name), tempfile.TemporaryDirectory() as directory:
                run = subprocess.run([sys.executable, '-c', child, directory, 'after_' + effect_name],
                    env={**os.environ, 'PYTHONPATH': str(Path(__file__).parent)},
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(run.returncode, 92, run.stderr)
                state = mirror.State(Path(directory))
                try:
                    self.assertEqual(state.db.execute('SELECT phase FROM attempt_events ORDER BY sequence DESC LIMIT 1').fetchone()[0], last_phase)
                finally: state.close()

    def test_old_copy_gate_is_never_adopted_or_journaled_as_owned(self):
        kv, destination = KV(), Destination()
        kv.values['b2-sync:v1:' + HASH] = {'state': 'copying', 'attempt_id': 'old-unproven'}
        worker = mirror.Worker(Source(), destination, kv, self.state,
            max_object_bytes=100, chunk_bytes=5, max_spool_bytes=100)
        self.assertEqual(worker.process(HASH, mirror.Budget(1000)), 'locked')
        self.assertEqual(self.events(), [])
        self.assertEqual(destination.versions, {})


if __name__ == '__main__':
    unittest.main()
