#!/usr/bin/env python3
"""Bounded restartable Bunny enrollment; never writes source objects or clears gates."""
import argparse
from collections import Counter
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import urllib.parse

from b2_playback_family import _master, _variant, validate_source_identity
from sync_b2_originals import JsonHTTP, ControlAPIError, Budget

HEX = re.compile(r'[0-9a-f]{64}\Z')
MAX_OBJECT = 16 * 1024 * 1024
MAX_PLAYLIST = 64 * 1024
HLS = tuple(f'hls/stream_{r}.ts' for r in ('720p', '480p')) + tuple(
    f'hls/stream_{r}.m3u8' for r in ('720p', '480p')) + ('hls/master.m3u8',)
SUFFIXES = ('', '720p.mp4', '480p.mp4') + HLS


def digest(body):
    return hashlib.sha256(body).hexdigest()


def source_key(parent, suffix):
    if suffix in ('720p.mp4', '480p.mp4'):
        return f'{parent}/hls/stream_{suffix}'
    return parent + ('/' + suffix if suffix else '')


def normalized(parent, suffix, body, sizes):
    """Match the worker's exact URI rewrite and LF/blank-line normalization."""
    if not suffix.endswith('.m3u8'):
        return body
    if len(body) > MAX_PLAYLIST:
        raise ValueError('playlist exceeds bound')
    text = body.decode('utf-8').replace('\r\n', '\n')
    lines = text.split('\n')
    if not lines or lines[0] != '#EXTM3U':
        raise ValueError('invalid playlist')
    prefix = f'/{parent}/hls/'
    out = ['#EXTM3U']
    for line in lines[1:]:
        if any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in line):
            raise ValueError('playlist controls')
        if not line:
            continue
        if not line.startswith('#'):
            for candidate in ('https://media.divine.video' + prefix, prefix):
                if line.startswith(candidate):
                    line = line[len(candidate):]
                    break
        out.append(line)
    delivery = ('\n'.join(out) + '\n').encode()
    if len(delivery) > MAX_PLAYLIST:
        raise ValueError('playlist exceeds bound')
    if suffix == 'hls/master.m3u8':
        _master(delivery)
    else:
        resolution = suffix[len('hls/stream_'):-len('.m3u8')]
        _variant(delivery, resolution, sizes[f'hls/stream_{resolution}.ts'])
    return delivery


class APIRefused(Exception):
    """A definite control-plane HTTP refusal, without provider response text."""
    def __init__(self, status):
        self.status = status
        super().__init__('publication refused')


class Deferred(Exception):
    pass


class QueueFull(Exception):
    pass


class State:
    """A private bounded journal. Crash during an external write stays uncertain."""
    def __init__(self, path, binding):
        self.path = Path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.is_symlink() or self.path.parent.stat().st_mode & 0o077:
            raise ValueError('state must be private and not a symlink')
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        except FileExistsError:
            if self.path.stat().st_mode & 0o077:
                raise ValueError('state must be private')
        self.db = sqlite3.connect(self.path)
        self.db.execute('create table if not exists settings (key text primary key, value text)')
        self.db.execute('create table if not exists jobs (parent text primary key, status text, data text, seq integer)')
        self.db.execute('create index if not exists jobs_seq on jobs(seq)')
        expected = json.dumps({'version': 1, 'scope': binding}, sort_keys=True)
        previous = self.setting('binding')
        if previous is not None and previous != expected:
            self.close()
            raise ValueError('journal belongs to another source scope')
        self.set_setting('binding', expected)
        self.db.execute("update jobs set status='uncertain' where status='inflight'")
        self.db.commit()

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None

    def setting(self, key):
        row = self.db.execute('select value from settings where key=?', (key,)).fetchone()
        return row[0] if row else None

    def set_setting(self, key, value):
        self.db.execute('insert or replace into settings values (?,?)', (key, value))
        self.db.commit()

    def page(self, parents, cursor):
        with self.db:
            for parent in parents:
                if not HEX.fullmatch(parent):
                    raise ValueError('invalid discovered parent')
                row = self.db.execute('select status from jobs where parent=?', (parent,)).fetchone()
                if row is not None:
                    if row[0] != 'uncertain':
                        self.db.execute("update jobs set status='queued' where parent=?", (parent,))
                    continue
                if self.db.execute('select count(*) from jobs').fetchone()[0] >= 10000:
                    self.db.execute("delete from jobs where parent=(select parent from jobs where status='ready' order by seq limit 1)")
                    if self.db.execute('select count(*) from jobs').fetchone()[0] >= 10000:
                        raise QueueFull('journal queue saturated')
                seq = self.db.execute('select coalesce(max(seq),0)+1 from jobs').fetchone()[0]
                self.db.execute("insert into jobs values (?,'queued','{}',?)", (parent, seq))
            self.db.execute('insert or replace into settings values (?,?)', ('cursor', cursor))

    def status(self, parent):
        row = self.db.execute('select status from jobs where parent=?', (parent,)).fetchone()
        return row[0] if row else None

    def data(self, parent):
        row = self.db.execute('select data from jobs where parent=?', (parent,)).fetchone()
        return json.loads(row[0]) if row else {}

    def save(self, parent, status, data):
        seq = self.db.execute('select coalesce(max(seq),0)+1 from jobs').fetchone()[0]
        self.db.execute('update jobs set status=?,data=?,seq=? where parent=?',
                        (status, json.dumps(data, sort_keys=True), seq, parent))
        self.db.commit()

    def export_ready(self, path):
        row = self.db.execute("select data from jobs where status='ready' order by seq desc limit 1").fetchone()
        inventory = json.loads(row[0]).get('inventory') if row else None
        if inventory is None:
            return False
        path = Path(path)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if (path.parent.is_symlink() or path.parent.stat().st_mode & 0o077
                or path.is_symlink() or (path.exists() and path.stat().st_mode & 0o077)):
            raise ValueError('export must be private')
        fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as handle:
            json.dump(inventory, handle, sort_keys=True)
        return True

    def pending(self, limit):
        return [r[0] for r in self.db.execute(
            "select parent from jobs where status in ('queued','pending') order by seq limit ?", (limit,))]


class Reconciler:
    def __init__(self, kv, original, derived, producer, api, state):
        self.kv, self.original, self.derived = kv, original, derived
        self.producer, self.api, self.state = producer, api, state

    def _metadata(self, parent):
        record = self.kv.metadata(parent)
        if (not isinstance(record, dict) or record.get('sha256') != parent
                or record.get('status') != 'active' or record.get('transcode_status') != 'complete'
                or not self.producer.idle(parent)):
            raise Deferred()
        # Keep uploader identities and other sensitive metadata out of the journal.
        return {key: record.get(key) for key in ('sha256', 'status', 'transcode_status', 'transcode_generation')}

    def _prepare(self, parent, budget):
        metadata = self._metadata(parent)
        identities, sources = {}, {}
        for suffix in SUFFIXES:
            source = self.derived if suffix else self.original
            key = source_key(parent, suffix)
            identity = source.head(key)
            if identity is None:
                if suffix in HLS:
                    raise Deferred()
                continue
            size = identity.get('size')
            maximum = MAX_PLAYLIST if suffix.endswith('.m3u8') else MAX_OBJECT
            if type(size) is not int or not 0 < size <= maximum:
                if suffix in ('', '720p.mp4', '480p.mp4'):
                    continue
                raise ValueError('source exceeds family bounds')
            validate_source_identity({k: v for k, v in identity.items() if k != 'size'}, key)
            identities[suffix], sources[suffix] = identity, source
        if not all(s in identities for s in HLS):
            raise Deferred()
        fingerprint = digest(json.dumps({'metadata': metadata, 'sources': identities}, sort_keys=True).encode())
        saved = self.state.data(parent)
        if saved.get('fingerprint') == fingerprint and saved.get('ready'):
            self._check_snapshot(parent, metadata, identities, sources)
            reserved = 3 * sum(MAX_PLAYLIST if s.endswith('.m3u8') else MAX_OBJECT for s in identities)
            if reserved > budget.remaining:
                raise Deferred()
            budget.spend(reserved)
            return None, saved, reserved
        # Current/destination bytes may disagree with the initial source HEAD.
        # Reserve per-object protocol maxima, rather than trusting small source
        # sizes to bound worker reads of conflicting old destination versions.
        # Nine copies covers local reads, worker source/dependencies/existing
        # destination/PUT/readback, and source+destination final verification.
        reserved = 9 * sum(MAX_PLAYLIST if s.endswith('.m3u8') else MAX_OBJECT
                           for s in identities)
        if reserved > budget.remaining:
            raise Deferred()
        budget.spend(reserved)
        bodies = {s: sources[s].read(source_key(parent, s), identity)
                  for s, identity in identities.items()}
        if any(not isinstance(body, bytes) or len(body) != identities[s]['size'] for s, body in bodies.items()):
            raise ValueError('source body differs from snapshot')
        if '' in bodies and digest(bodies['']) != parent:
            raise ValueError('original content address mismatch')
        sizes = {s: i['size'] for s, i in identities.items()}
        assets = {}
        for suffix, body in bodies.items():
            path = '/' + parent + ('/' + suffix if suffix else '')
            delivery = normalized(parent, suffix, body, sizes)
            assets[suffix] = {'path': path, 'source_sha256': digest(body), 'delivery_sha256': digest(delivery)}
        self._check_snapshot(parent, metadata, identities, sources)
        prior = saved.get('published', []) if saved.get('fingerprint') == fingerprint else []
        inventory = {'version': 1, 'parent': parent, 'assets': [
            {**pin, 'delivery_size': len(normalized(parent, suffix, bodies[suffix], sizes))}
            for suffix, pin in assets.items()]}
        return (assets, metadata, identities, sources), {
            'fingerprint': fingerprint, 'published': prior, 'inventory': inventory}, reserved

    def _check_snapshot(self, parent, metadata, identities, sources):
        if self._metadata(parent) != metadata:
            raise Deferred()
        if any(sources[s].head(source_key(parent, s)) != identity for s, identity in identities.items()):
            raise ValueError('source snapshot changed')

    def _publish(self, parent, prepared, progress, dry_run):
        if prepared is None:
            if dry_run:
                return 'would_reverify'
            self.state.save(parent, 'inflight', progress)
            pins = [{key: pin[key] for key in ('path', 'source_sha256', 'delivery_sha256')}
                    for pin in progress['inventory']['assets']]
            try:
                reply = self.api.finalize({'version': 1, 'parent': parent, 'assets': pins})
            except APIRefused as error:
                if error.status == 409:
                    progress.pop('ready', None)
                    progress['published'] = []
                raise
            if reply != {'result': 'ready'}:
                raise TimeoutError('ready family revalidation unverified')
            self.state.save(parent, 'ready', progress)
            return 'unchanged'
        assets, metadata, identities, sources = prepared
        if dry_run:
            return 'would_publish'
        # Leaves first; then variants; master last. The worker revalidates policy
        # and every dependency, and only its finalize response grants readiness.
        order = [s for s in SUFFIXES if s in assets and not s.endswith('.m3u8')] + [s for s in HLS if s.endswith('.m3u8')]
        for suffix in order:
            pin = assets[suffix]
            if pin in progress['published']:
                continue
            self._check_snapshot(parent, metadata, identities, sources)
            request = {'path': pin['path'], 'sha256': pin['source_sha256']}
            children = ('hls/stream_720p.m3u8', 'hls/stream_480p.m3u8') if suffix == 'hls/master.m3u8' else (
                (suffix.replace('.m3u8', '.ts'),) if suffix.endswith('.m3u8') else ())
            if children:
                request['dependencies'] = [{'path': assets[c]['path'], 'sha256': assets[c]['delivery_sha256']} for c in children]
            self.state.save(parent, 'inflight', progress)
            reply = self.api.publish(request)
            if (not isinstance(reply, dict) or reply.get('result') not in ('published', 'already_published')
                    or (suffix.endswith('.m3u8') and reply.get('delivery_sha256') != pin['delivery_sha256'])):
                raise TimeoutError('publication response unverified')
            progress['published'].append(pin)
            self.state.save(parent, 'pending', progress)
        self._check_snapshot(parent, metadata, identities, sources)
        self.state.save(parent, 'inflight', progress)
        reply = self.api.finalize({'version': 1, 'parent': parent, 'assets': list(assets.values())})
        if reply != {'result': 'ready'}:
            raise TimeoutError('finalization response unverified')
        progress['ready'] = True
        self.state.save(parent, 'ready', progress)
        return 'ready'

    def cycle(self, *, max_pages, page_size, max_parents, max_bytes, dry_run=False):
        if not (1 <= max_pages <= 100 and 1 <= page_size <= 100 and 1 <= max_parents <= 1000
                and type(max_bytes) is int and max_bytes > 0):
            raise ValueError('invalid enrollment bounds')
        report = Counter()
        for _ in range(max_pages):
            parents, cursor = self.kv.page(self.state.setting('cursor'), page_size)
            try:
                self.state.page(parents, cursor)
            except QueueFull:
                report['saturated'] += 1
                break
            report['discovered'] += len(parents)
            if cursor is None:
                break
        budget = Budget(max_bytes)
        for parent in self.state.pending(max_parents):
            progress = self.state.data(parent)
            try:
                prepared, progress, size = self._prepare(parent, budget)
                report[self._publish(parent, prepared, progress, dry_run)] += 1
            except Deferred:
                self.state.save(parent, 'pending', progress)
                report['deferred'] += 1
            except APIRefused:
                self.state.save(parent, 'refused', progress)
                report['refused'] += 1
            except (TimeoutError, ConnectionError):
                uncertain = self.state.status(parent) == 'inflight'
                self.state.save(parent, 'uncertain' if uncertain else 'pending', progress)
                report['uncertain' if uncertain else 'errors'] += 1
            except Exception:
                # A crash after the write intent cannot be silently retried.
                status = 'uncertain' if self.state.status(parent) == 'inflight' else 'pending'
                self.state.save(parent, status, progress)
                report['errors'] += 1
        report['reserved_media_bytes'] = budget.used
        return dict(report)


class FastlyCatalog:
    """Read-only paginated current metadata. Listing hints never authorize writes."""
    def __init__(self, store, token, http=None):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', store):
            raise ValueError('invalid store')
        self.base = f'https://api.fastly.com/resources/stores/kv/{store}/keys/'
        self.http = http or JsonHTTP({'Fastly-Key': token})

    def page(self, cursor, limit):
        params = {'prefix': 'blob', 'limit': limit}
        if cursor is not None:
            if not isinstance(cursor, str) or not 1 <= len(cursor) <= 4096:
                raise ValueError('invalid cursor')
            params['cursor'] = cursor
        try:
            reply = self.http.request(self.base.rstrip('/') + '?' + urllib.parse.urlencode(params))
        except ControlAPIError as error:
            if error.status == 400 and cursor is not None:
                return self.page(None, limit)
            raise
        data = reply.get('data') if isinstance(reply, dict) else None
        meta = reply.get('meta', {}) if isinstance(reply, dict) else None
        if (not isinstance(data, list) or len(data) > limit or not isinstance(meta, dict)
                or any(not isinstance(k, str) or not k.startswith('blob') or len(k) > 1024 for k in data)):
            raise ValueError('invalid metadata page')
        next_cursor = meta.get('next_cursor') or None
        if next_cursor is not None and (not isinstance(next_cursor, str) or len(next_cursor) > 4096):
            raise ValueError('invalid metadata cursor')
        return [k[5:] for k in data if k.startswith('blob:') and HEX.fullmatch(k[5:])], next_cursor

    def metadata(self, parent):
        if not HEX.fullmatch(parent):
            raise ValueError('invalid parent')
        return self.http.request(self.base + urllib.parse.quote('blob:' + parent, safe=''), missing=True,
                                 max_response_bytes=64 * 1024)


class BunnyAdmin:
    def __init__(self, token, http=None):
        if not token or '\r' in token or '\n' in token:
            raise ValueError('invalid administrative credential')
        self.token, self.http = token, http or JsonHTTP()

    def _post(self, operation, payload):
        try:
            return self.http.request('https://media.divine.video/admin/api/bunny-pilot/' + operation,
                'POST', payload, headers={'Authorization': 'Bearer ' + self.token},
                max_response_bytes=32768, timeout=150)
        except ControlAPIError as error:
            if error.status >= 500:
                raise ConnectionError('publication outcome uncertain') from None
            raise APIRefused(error.status) from None

    def publish(self, payload):
        return self._post('publish', payload)

    def finalize(self, payload):
        return self._post('finalize', payload)


class S3Source:
    """Current B2 source with immutable-version evidence and bounded GETs."""
    def __init__(self, bucket, client):
        self.bucket, self.client = bucket, client

    def head(self, key):
        from botocore.exceptions import ClientError
        try:
            reply = self.client.head_object(Bucket=self.bucket, Key=key)
        except ClientError as error:
            # S3 HEAD has no modeled error body: only an explicit missing key
            # status/code means absent; auth/throttling/network failures propagate.
            if (error.response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 404
                    and error.response.get('Error', {}).get('Code') in ('404', 'NoSuchKey', 'NotFound')):
                return None
            raise
        identity = {'provider': 'b2', 'bucket': self.bucket, 'key': key,
                    'version': reply.get('VersionId')}
        validate_source_identity(identity, key)
        return {**identity, 'size': reply.get('ContentLength')}

    def read(self, key, identity):
        if self.head(key) != identity:
            raise ValueError('source changed before read')
        reply = self.client.get_object(Bucket=self.bucket, Key=key, VersionId=identity['version'])
        body = reply['Body']
        try:
            if (reply.get('VersionId') != identity['version']
                    or reply.get('ContentLength') != identity['size']):
                raise ValueError('source response not pinned')
            data = body.read(identity['size'] + 1)
            if len(data) != identity['size']:
                raise ValueError('source response length mismatch')
        finally:
            body.close()
        if self.head(key) != identity:
            raise ValueError('source changed after read')
        return data


class GCSSource:
    def __init__(self, bucket, client):
        self.bucket, self.handle = bucket, client.bucket(bucket)

    def head(self, key):
        blob = self.handle.get_blob(key, timeout=30, retry=None)
        if blob is None:
            return None
        identity = {'provider': 'gcs', 'bucket': self.bucket, 'key': key, 'version': str(blob.generation)}
        validate_source_identity(identity, key)
        return {**identity, 'size': blob.size}

    def read(self, key, identity):
        if self.head(key) != identity:
            raise ValueError('source changed before read')
        body = self.handle.blob(key).download_as_bytes(start=0, end=identity['size'],
            if_generation_match=int(identity['version']), raw_download=True, checksum=None,
            timeout=30, retry=None)
        if len(body) != identity['size'] or self.head(key) != identity:
            raise ValueError('source changed after read')
        return body


class GCSProducer:
    def __init__(self, bucket, client):
        self.handle = client.bucket(bucket)

    def idle(self, parent):
        if not HEX.fullmatch(parent):
            raise ValueError('invalid producer parent')
        return self.handle.get_blob('.internal/hls-claims/' + parent, timeout=30, retry=None) is None


def configuration(path):
    if path.stat().st_size > 8192:
        raise ValueError('configuration too large')
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or set(value) != {'original', 'derived', 'b2_region', 'coordination_bucket', 'kv_store_id'}:
        raise ValueError('invalid configuration')
    for name in ('original', 'derived'):
        source = value[name]
        if (not isinstance(source, dict) or set(source) != {'provider', 'bucket'}
                or source['provider'] not in ('gcs', 'b2')
                or not isinstance(source['bucket'], str)
                or not re.fullmatch(r'[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]', source['bucket'])):
            raise ValueError('invalid source configuration')
    if not isinstance(value['b2_region'], str) or not re.fullmatch(r'(us-west|us-east|eu-central|ca-east)-[0-9]{3}', value['b2_region']):
        raise ValueError('invalid B2 region')
    if not isinstance(value['coordination_bucket'], str) or not re.fullmatch(r'[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]', value['coordination_bucket']):
        raise ValueError('invalid coordination bucket')
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path, help='Non-secret source configuration JSON')
    parser.add_argument('--state-dir', required=True, type=Path, help='Private persistent directory, mode 0700')
    parser.add_argument('--max-bytes', required=True, type=int, help='Conservative media I/O reservation ceiling')
    parser.add_argument('--max-pages', type=int, default=1)
    parser.add_argument('--page-size', type=int, default=100)
    parser.add_argument('--max-parents', type=int, default=1)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--export-ready', type=Path, help='Optional private fixture inventory for CDN probes')
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        config = configuration(args.config)
        args.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if args.state_dir.is_symlink() or args.state_dir.stat().st_mode & 0o077:
            raise ValueError('state directory must be private')
        lock_fd = os.open(args.state_dir / 'worker.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(lock_fd, 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            from google.cloud import storage
            gcs = storage.Client()
            s3 = None
            if any(config[name]['provider'] == 'b2' for name in ('original', 'derived')):
                import boto3
                from botocore.config import Config
                s3 = boto3.client('s3', endpoint_url='https://s3.' + config['b2_region'] + '.backblazeb2.com',
                    region_name=config['b2_region'], aws_access_key_id=os.environ['B2_APPLICATION_KEY_ID'],
                    aws_secret_access_key=os.environ['B2_APPLICATION_KEY'],
                    config=Config(signature_version='s3v4', retries={'total_max_attempts': 1},
                        connect_timeout=10, read_timeout=30, s3={'addressing_style': 'path'},
                        request_checksum_calculation='when_required', response_checksum_validation='when_required'))
            def source(name):
                spec = config[name]
                return S3Source(spec['bucket'], s3) if spec['provider'] == 'b2' else GCSSource(spec['bucket'], gcs)
            state = State(args.state_dir / 'progress.sqlite', config)
            try:
                report = Reconciler(FastlyCatalog(config['kv_store_id'], os.environ['FASTLY_API_TOKEN']),
                    source('original'), source('derived'), GCSProducer(config['coordination_bucket'], gcs),
                    BunnyAdmin(os.environ['BUNNY_PILOT_ADMIN_TOKEN']), state).cycle(
                        max_pages=args.max_pages, page_size=args.page_size, max_parents=args.max_parents,
                        max_bytes=args.max_bytes, dry_run=args.dry_run)
                if args.export_ready is not None:
                    report['exported_ready_inventory'] = int(state.export_ready(args.export_ready))
                print(json.dumps(report, sort_keys=True))
                return int(any(report.get(key) for key in ('errors', 'uncertain', 'refused')))
            finally:
                state.close()
    except Exception:
        print('Enrollment did not finish; inspect private configuration or journal. Provider details suppressed.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
