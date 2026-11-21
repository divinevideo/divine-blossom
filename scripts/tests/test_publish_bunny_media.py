"""Behavioral enrollment tests with immutable synthetic storage and a real journal."""
import hashlib
import json
import sqlite3
from pathlib import Path
import tempfile
import unittest
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from publish_bunny_media import State, Reconciler, APIRefused

BODY = b'public original'
PARENT = hashlib.sha256(BODY).hexdigest()
ROOT = f'{PARENT}/hls/'


def fixture():
    objects = {PARENT: BODY}
    for r in ('720p', '480p'):
        objects[ROOT + f'stream_{r}.ts'] = b't' * 188
        objects[ROOT + f'stream_{r}.m3u8'] = (
            '#EXTM3U\n#EXT-X-VERSION:4\n#EXT-X-TARGETDURATION:6\n'
            '#EXT-X-MEDIA-SEQUENCE:0\n#EXT-X-PLAYLIST-TYPE:VOD\n'
            '#EXTINF:6.0,\n#EXT-X-BYTERANGE:188@0\n' +
            f'https://media.divine.video/{ROOT}stream_{r}.ts\n#EXT-X-ENDLIST\n').encode()
    objects[ROOT + 'master.m3u8'] = (
        '#EXTM3U\n#EXT-X-VERSION:4\n#EXT-X-STREAM-INF:BANDWIDTH=1000\n'
        f'/{ROOT}stream_720p.m3u8\n#EXT-X-STREAM-INF:BANDWIDTH=500\n'
        f'/{ROOT}stream_480p.m3u8\n').encode()
    return objects


class Source:
    def __init__(self):
        self.objects = fixture()
        self.versions = {k: 'v1' for k in self.objects}
        self.reads = 0
        self.on_read = lambda: None

    def head(self, key):
        if key not in self.objects:
            return None
        return {'provider': 'b2', 'bucket': 'fixture-bucket', 'key': key,
                'version': self.versions[key], 'size': len(self.objects[key])}

    def read(self, key, identity):
        self.reads += 1
        body = self.objects[key]
        self.on_read()
        if self.head(key) != identity:
            raise ValueError('source version changed')
        return body


class KV:
    def __init__(self):
        self.record = {'sha256': PARENT, 'status': 'active',
                       'transcode_status': 'complete', 'transcode_generation': 7,
                       'type': 'video/mp4', 'size': len(BODY)}
        self.pages = [([PARENT], 'page2'), ([], None)]
        self.calls = []

    def page(self, cursor, limit):
        self.calls.append(cursor)
        return self.pages[0 if cursor is None else 1]

    def metadata(self, parent):
        return self.record.copy()


class Producer:
    busy = False

    def idle(self, parent):
        return not self.busy


class API:
    def __init__(self, source):
        self.source = source
        self.published = {}
        self.order = []
        self.ready = False
        self.break_after = None

    def publish(self, payload):
        path = payload['path']
        if self.break_after == len(self.order):
            raise TimeoutError('lost response')
        key = path[1:]
        if key.endswith('/720p.mp4') or key.endswith('/480p.mp4'):
            key = key.rsplit('/', 1)[0] + '/hls/stream_' + key.rsplit('/', 1)[1]
        body = self.source.objects[key]
        for dep in payload.get('dependencies', []):
            if dep['path'] not in self.published:
                raise APIRefused(409)
        prefix = '/' + path.split('/')[1] + '/hls/'
        delivery = body.replace(('https://media.divine.video' + prefix).encode(), b'').replace(prefix.encode(), b'') if path.endswith('.m3u8') else body
        self.ready = False
        if path in self.published and self.published[path] != delivery:
            raise APIRefused(409)
        self.published[path] = delivery
        self.order.append(path)
        reply = {'result': 'published'}
        if path.endswith('.m3u8'):
            reply['delivery_sha256'] = hashlib.sha256(delivery).hexdigest()
        return reply

    def finalize(self, payload):
        for pin in payload['assets']:
            if pin['path'] not in self.published or hashlib.sha256(self.published[pin['path']]).hexdigest() != pin['delivery_sha256']:
                raise APIRefused(409)
        self.ready = True
        return {'result': 'ready'}


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = State(Path(self.tmp.name) / 'progress.sqlite', {'source': 'fixture'})
        self.addCleanup(self.state.close)
        self.source, self.kv, self.producer = Source(), KV(), Producer()
        self.api = API(self.source)
        self.worker = Reconciler(self.kv, self.source, self.source, self.producer, self.api, self.state)

    def cycle(self, **kwargs):
        return self.worker.cycle(max_pages=1, page_size=100, max_parents=1,
                                 max_bytes=1024 * 1024 * 1024, **kwargs)

    def test_discovers_and_publishes_complete_hls_without_optional_mp4(self):
        report = self.cycle()
        self.assertEqual(report.get('ready'), 1)
        self.assertTrue(self.api.ready)
        self.assertEqual(self.api.order[-1], '/' + ROOT + 'master.m3u8')
        self.assertLess(self.api.order.index('/' + ROOT + 'stream_720p.ts'),
                        self.api.order.index('/' + ROOT + 'stream_720p.m3u8'))
        self.assertEqual(self.state.status(PARENT), 'ready')

    def test_cursor_and_completed_progress_survive_restart(self):
        self.cycle()
        self.state.close()
        self.state = State(Path(self.tmp.name) / 'progress.sqlite', {'source': 'fixture'})
        self.addCleanup(self.state.close)
        worker = Reconciler(self.kv, self.source, self.source, self.producer, self.api, self.state)
        before = len(self.api.order)
        worker.cycle(max_pages=1, page_size=100, max_parents=1, max_bytes=1024 * 1024 * 1024)
        self.assertEqual(self.kv.calls, [None, 'page2'])
        self.assertEqual(len(self.api.order), before)
        self.assertEqual(self.state.status(PARENT), 'ready')

    def test_lost_reply_is_retained_and_never_automatically_retried(self):
        self.api.break_after = 1
        self.cycle()
        self.assertEqual(self.state.status(PARENT), 'uncertain')
        self.api.break_after = None
        self.cycle()
        self.cycle()
        self.assertEqual(len(self.api.order), 1)
        self.assertFalse(self.api.ready)

    def test_malformed_reply_after_put_is_reported_and_retained_as_uncertain(self):
        publish = self.api.publish
        def malformed(payload):
            publish(payload)
            raise ValueError('invalid control response JSON')
        self.api.publish = malformed
        self.assertEqual(self.cycle().get('uncertain'), 1)
        self.assertEqual(self.state.status(PARENT), 'uncertain')
        self.assertEqual(len(self.api.order), 1)
        self.cycle()
        self.assertEqual(len(self.api.order), 1)

    def test_budget_is_reserved_before_any_source_download_or_publication(self):
        report = self.worker.cycle(max_pages=1, page_size=100, max_parents=1, max_bytes=1)
        self.assertEqual(report.get('deferred'), 1)
        self.assertEqual(self.source.reads, 0)
        self.assertEqual(self.api.order, [])

    def test_reserves_unknown_destination_sizes_not_only_small_sources(self):
        report = self.worker.cycle(max_pages=1, page_size=100, max_parents=1,
                                   max_bytes=32 * 1024 * 1024)
        self.assertEqual(report.get('deferred'), 1)
        self.assertEqual(self.source.reads, 0)
        self.assertEqual(self.api.order, [])

    def test_source_version_change_during_read_cannot_finalize(self):
        self.source.on_read = lambda: self.source.versions.update({PARENT: 'v2'})
        report = self.cycle()
        self.assertEqual(report.get('errors'), 1)
        self.assertGreater(report.get('reserved_media_bytes', 0), 0)
        self.assertEqual(self.api.order, [])
        self.assertFalse(self.api.ready)

    def test_active_producer_and_incomplete_metadata_defer(self):
        self.producer.busy = True
        self.assertEqual(self.cycle().get('deferred'), 1)
        self.assertEqual(self.api.order, [])
        self.producer.busy = False
        self.kv.record['transcode_status'] = 'processing'
        self.assertEqual(self.cycle().get('deferred'), 1)
        self.assertEqual(self.api.order, [])

    def test_dry_run_verifies_without_mutating_the_delivery_service(self):
        report = self.cycle(dry_run=True)
        self.assertEqual(report.get('would_publish'), 1)
        self.assertEqual(self.api.order, [])
        self.assertFalse(self.api.ready)

    def test_foreign_manifest_child_is_rejected_before_publication(self):
        key = ROOT + 'master.m3u8'
        self.source.objects[key] = self.source.objects[key].replace(b'/hls/stream_720p.m3u8', b'/hls/foreign.m3u8')
        self.assertEqual(self.cycle().get('errors'), 1)
        self.assertEqual(self.api.order, [])

    def test_changed_source_does_not_overwrite_an_enrolled_object(self):
        self.cycle()
        self.assertTrue(self.api.ready)
        path = '/' + ROOT + 'stream_720p.ts'
        before = self.api.published[path]
        self.source.objects[path[1:]] = b'u' * 188
        self.source.versions[path[1:]] = 'v2'
        self.cycle()
        self.cycle()
        self.assertEqual(self.api.published[path], before)
        self.assertFalse(self.api.ready)

    def test_ready_inventory_exports_only_verified_receipts_to_a_private_file(self):
        self.cycle()
        target = Path(self.tmp.name) / 'fixture.json'
        self.assertTrue(self.state.export_ready(target))
        data = json.loads(target.read_text())
        self.assertEqual(data['parent'], PARENT)
        self.assertEqual(len(data['assets']), 6)
        self.assertTrue(all(a['delivery_size'] > 0 for a in data['assets']))
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_prepublication_read_timeout_retries_without_an_uncertain_write(self):
        self.source.on_read = lambda: (_ for _ in ()).throw(TimeoutError())
        self.cycle()
        self.assertEqual(self.state.status(PARENT), 'pending')
        self.source.on_read = lambda: None
        self.assertEqual(self.cycle().get('ready'), 1)

    def test_restart_between_acknowledged_assets_resumes_without_duplicate_puts(self):
        save = self.state.save
        interrupted = False
        def stop_after_ack(parent, status, data):
            nonlocal interrupted
            save(parent, status, data)
            if status == 'pending' and data.get('published') and not interrupted:
                interrupted = True
                raise KeyboardInterrupt()
        self.state.save = stop_after_ack
        with self.assertRaises(KeyboardInterrupt):
            self.cycle()
        self.assertEqual(len(self.api.order), 1)
        self.state.save = save
        self.assertEqual(self.cycle().get('ready'), 1)
        self.assertEqual(len(self.api.order), 6)

    def test_ready_sources_reverify_and_repair_a_removed_delivery_family(self):
        self.cycle()
        self.assertTrue(self.api.ready)
        self.api.published.clear()
        self.api.ready = False
        self.cycle()
        self.assertEqual(self.cycle().get('refused'), 1)
        self.assertFalse(self.state.data(PARENT).get('ready', False))
        self.cycle()
        self.assertEqual(self.cycle().get('ready'), 1)
        self.assertTrue(self.api.ready)

    def test_a_full_discovery_queue_still_processes_committed_work(self):
        self.state.page([PARENT] + [format(i, '064x') for i in range(9999)], None)
        self.kv.pages = [(['c' * 64], 'page2')]
        report = self.cycle()
        self.assertEqual(report.get('saturated'), 1)
        self.assertEqual(report.get('ready'), 1)
        self.assertIsNone(self.state.setting('cursor'))

    def test_dry_runs_rotate_two_candidates_and_preserve_ready_export(self):
        other = 'f' * 64
        self.kv.pages = [([PARENT, other], None)]
        seen = []
        def metadata(parent):
            if not seen or seen[-1] != parent:
                seen.append(parent)
            return {**self.kv.record, 'sha256': parent, 'type': 'video/webm'}
        self.kv.metadata = metadata
        for key, body in fixture().items():
            if key != PARENT:
                second = key.replace(PARENT, other)
                self.source.objects[second] = body.replace(PARENT.encode(), other.encode())
                self.source.versions[second] = 'v1'
        self.assertEqual(self.cycle().get('ready'), 1)
        before = self.state.data(PARENT)
        seen.clear()
        for _ in range(3):
            self.cycle(dry_run=True)
            self.assertEqual(self.state.data(PARENT), before)
            self.assertTrue(self.state.export_ready(Path(self.tmp.name) / 'ready.json'))
        self.assertEqual(seen, [other, PARENT, other])
        self.assertFalse(self.state.data(other).get('published'))
        for _ in range(2):
            self.cycle()
        self.assertTrue(self.state.data(other)['ready'])

    def test_omits_non_mp4_and_metadata_size_mismatches_from_hls_inventory(self):
        for mime, size in [('video/webm', len(BODY)), ('video/mp4', len(BODY) + 1)]:
            with self.subTest(mime=mime):
                self.kv.pages = [([PARENT], None)]
                self.kv.record.update(type=mime, size=size)
                self.cycle()
                pins = self.state.data(PARENT)['inventory']['assets']
                self.assertEqual(len(pins), 5)
                self.assertTrue(all('/hls/' in p['path'] for p in pins))
                self.assertTrue(self.state.data(PARENT)['ready'])

    def test_missing_acknowledged_child_recovers_before_first_finalize(self):
        self.kv.pages = [([PARENT], None)]
        publish = self.api.publish
        removed = False
        def withdraw(payload):
            nonlocal removed
            if payload.get('dependencies') and not removed:
                removed = True
                del self.api.published[payload['dependencies'][0]['path']]
            return publish(payload)
        self.api.publish = withdraw
        self.assertEqual(self.cycle().get('refused'), 1)
        self.assertFalse(self.api.ready)
        self.assertEqual(self.cycle().get('ready'), 1)
        self.assertTrue(self.api.ready)

    def test_lost_child_before_initial_finalize_is_repaired(self):
        finalize = self.api.finalize
        def withdraw(payload):
            del self.api.published['/' + ROOT + 'stream_720p.ts']
            self.api.finalize = finalize
            return finalize(payload)
        self.api.finalize = withdraw
        self.kv.pages = [([PARENT], None)]
        self.assertEqual(self.cycle().get('refused'), 1)
        self.assertEqual(self.cycle().get('ready'), 1)

    def test_capped_journal_advances_and_rediscovers_changed_eligibility(self):
        earlier = [format(i, '064x') for i in range(9999)]
        later = 'f' * 64
        self.state.page(earlier + [later], 'next')
        self.state.save(earlier[0], 'uncertain', {'published': []})
        self.state.save(earlier[1], 'pending', {'published': [{'path': 'acknowledged'}]})
        self.kv.page = lambda cursor, limit: ([PARENT], None) if cursor == 'next' else ([earlier[2]], 'next')
        eligible = {PARENT}
        def metadata(parent):
            if parent in eligible:
                return {**self.kv.record, 'type':'video/webm', 'sha256':parent}
            return {**self.kv.record, 'sha256':parent, **(
                {'type':'image/png'} if int(parent,16) % 3 == 0 else
                {'status':'banned'} if int(parent,16) % 3 == 1 else {'transcode_status':'processing'})}
        self.kv.metadata = metadata
        def passes(n):
            for _ in range(n):
                self.worker.cycle(max_pages=1, page_size=100, max_parents=1000, max_bytes=1024**3)
        passes(14)
        self.assertTrue(self.state.data(PARENT).get('ready'))
        for key, body in fixture().items():
            if key != PARENT:
                second = key.replace(PARENT, earlier[2])
                self.source.objects[second] = body.replace(PARENT.encode(), earlier[2].encode())
                self.source.versions[second] = 'v1'
        eligible.add(earlier[2])
        passes(14)
        self.assertTrue(self.state.data(earlier[2]).get('ready'))
        self.assertEqual(self.state.status(earlier[0]), 'uncertain')
        self.assertEqual(self.state.data(earlier[1])['published'], [{'path':'acknowledged'}])
        self.assertLessEqual(self.state.db.execute('select count(*) from jobs').fetchone()[0], 10000)

    def test_upgrade_resumes_partial_receipts_and_keeps_uncertain_jobs_fenced(self):
        # A v1 journal used the four original metadata fields in its snapshot.
        def stop_after_ack(parent, status, data):
            State.save(self.state, parent, status, data)
            if status == 'pending':
                raise KeyboardInterrupt()
        self.state.save = stop_after_ack
        with self.assertRaises(KeyboardInterrupt):
            self.cycle()
        progress = self.state.data(PARENT)
        identities = {}
        for key in self.source.objects:
            suffix = key.removeprefix(PARENT).lstrip('/')
            identities[suffix] = self.source.head(key)
        old_metadata = {k:self.kv.record[k] for k in ('sha256','status','transcode_status','transcode_generation')}
        snapshot = json.dumps({'metadata':old_metadata, 'sources':identities}, sort_keys=True).encode()
        progress['fingerprint'] = hashlib.sha256(snapshot).hexdigest()
        path = Path(self.tmp.name) / 'v1.sqlite'
        with sqlite3.connect(path) as db:
            db.execute('create table jobs (parent text primary key,status text,data text,seq integer)')
            db.executemany('insert into jobs values(?,?,?,?)', [
                (PARENT, 'pending', json.dumps(progress), 1), ('a'*64, 'inflight', '{}', 2),
                ('b'*64, 'refused', '{}', 3), ('c'*64, 'refused', json.dumps(progress), 4)])
        path.chmod(0o600)
        upgraded = State(path, {'source':'fixture'})
        self.addCleanup(upgraded.close)
        self.worker.state = upgraded
        self.assertEqual(self.cycle().get('ready'), 1)
        self.assertEqual(upgraded.status('a'*64), 'uncertain')
        self.assertEqual(upgraded.status('b'*64), 'observed')
        self.assertEqual(upgraded.data('c'*64), progress)
        self.assertEqual(len(self.api.order), 6)

    def test_saturated_dry_run_preserves_the_only_ready_export(self):
        self.state.page([PARENT] + [format(i, '064x') for i in range(9999)], None)
        self.cycle()
        self.kv.pages = [(['c' * 64], None)]
        self.state.set_setting('cursor', None)
        self.cycle(dry_run=True)
        self.assertTrue(self.state.export_ready(Path(self.tmp.name) / 'verified.json'))
        self.assertEqual(self.state.status(PARENT), 'ready')

    def test_journal_cannot_be_reused_for_another_source_scope(self):
        with self.assertRaises(ValueError):
            State(Path(self.tmp.name) / 'progress.sqlite', {'source': 'other'})


if __name__ == '__main__':
    unittest.main()
