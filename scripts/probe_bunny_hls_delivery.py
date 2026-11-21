#!/usr/bin/env python3
"""Bounded recursive proof; reports counts only, never fixture or user identities."""
import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from b2_playback_family import _master, _variant
from publish_bunny_media import HEX, HLS, MAX_OBJECT, MAX_PLAYLIST, SUFFIXES
from sync_b2_originals import NoRedirect

CUSTOM = 'media-bunny.divine.video'


@dataclass
class Response:
    status: int
    headers: dict
    body: bytes


class HTTP:
    def __init__(self):
        self.opener = urllib.request.build_opener(NoRedirect)

    def request(self, host, path, method='GET', byte_range=None, limit=MAX_OBJECT):
        request = urllib.request.Request('https://' + host + path, method=method)
        if byte_range is not None:
            request.add_header('Range', f'bytes={byte_range[0]}-{byte_range[1]}')
        try:
            response = self.opener.open(request, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        try:
            body = response.read(limit + 1)
            if len(body) > limit:
                raise ValueError('probe body limit')
            return Response(response.status, {k.lower(): v for k, v in response.headers.items()}, body)
        finally:
            response.close()


def valid_host(host):
    return host == CUSTOM or (isinstance(host, str) and len(host) <= 74 and
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.b-cdn\.net', host) is not None)


class Probe:
    def __init__(self, inventory, hosts, client=None, *, max_requests=5000, max_bytes=1024 * 1024 * 1024):
        if (not isinstance(inventory, dict) or type(inventory.get('version')) is not int
                or inventory['version'] != 1 or not isinstance(inventory.get('parent'), str)
                or not HEX.fullmatch(inventory['parent']) or not isinstance(inventory.get('assets'), list)
                or not 1 <= len(inventory['assets']) <= 8):
            raise ValueError('invalid probe inventory')
        parent = inventory['parent']
        self.pins = {}
        for pin in inventory['assets']:
            if not isinstance(pin, dict) or not isinstance(pin.get('path'), str):
                raise ValueError('invalid probe pin')
            path = pin['path']
            suffix = path[len(parent) + 2:] if path.startswith('/' + parent + '/') else ''
            if path != '/' + parent + ('/' + suffix if suffix else '') or suffix not in SUFFIXES:
                raise ValueError('foreign probe pin')
            maximum = MAX_PLAYLIST if suffix.endswith('.m3u8') else MAX_OBJECT
            if (path in self.pins or not isinstance(pin.get('delivery_sha256'), str)
                    or not HEX.fullmatch(pin['delivery_sha256']) or type(pin.get('delivery_size')) is not int
                    or not 0 < pin['delivery_size'] <= maximum):
                raise ValueError('invalid probe size or digest')
            self.pins[path] = pin
        if any('/hls/' in p for p in self.pins) and not all('/' + parent + '/' + s in self.pins for s in HLS):
            raise ValueError('incomplete HLS inventory')
        if (len(hosts) != 2 or len(set(hosts)) != 2 or CUSTOM not in hosts
                or not all(valid_host(h) for h in hosts)):
            raise ValueError('two exact Bunny hostnames are required')
        if not 1 <= max_requests <= 10000 or type(max_bytes) is not int or max_bytes <= 0:
            raise ValueError('invalid probe budget')
        self.parent, self.hosts, self.client = parent, tuple(hosts), client or HTTP()
        self.max_requests, self.max_bytes = max_requests, max_bytes
        self.requests, self.bytes = 0, 0

    def _request(self, host, path, method='GET', byte_range=None, limit=MAX_OBJECT):
        if self.requests >= self.max_requests or self.bytes >= self.max_bytes:
            raise ValueError('probe budget')
        self.requests += 1
        reply = self.client.request(host, path, method, byte_range,
                                     limit=min(limit, self.max_bytes - self.bytes))
        self.bytes += len(reply.body)
        if self.bytes > self.max_bytes:
            raise ValueError('probe byte budget')
        return reply

    @staticmethod
    def _bunny(reply):
        if not reply.headers.get('server', '').lower().startswith('bunnycdn'):
            raise ValueError('unexpected CDN')

    @staticmethod
    def _mime(path, reply):
        mime = reply.headers.get('content-type', '').split(';', 1)[0].lower()
        accepted = {'application/vnd.apple.mpegurl', 'application/x-mpegurl'} if path.endswith('.m3u8') else (
            {'video/mp2t'} if path.endswith('.ts') else {'video/mp4'})
        if mime not in accepted:
            raise ValueError('unexpected media type')

    def _range(self, host, path, body, start, end):
        reply = self._request(host, path, byte_range=(start, end), limit=end - start + 1)
        self._bunny(reply)
        if (reply.status != 206 or reply.headers.get('content-range') != f'bytes {start}-{end}/{len(body)}'
                or reply.body != body[start:end + 1]):
            raise ValueError('range proof failed')

    def _tree(self, host, bodies):
        prefix = '/' + self.parent + '/hls/'
        master_path = prefix + 'master.m3u8'
        if master_path not in bodies:
            return
        _master(bodies[master_path])
        for resolution in ('720p', '480p'):
            variant_path = prefix + f'stream_{resolution}.m3u8'
            ts_path = prefix + f'stream_{resolution}.ts'
            _variant(bodies[variant_path], resolution, len(bodies[ts_path]))
            end = None
            pending = None
            for line in bodies[variant_path].decode().splitlines():
                if line.startswith('#EXT-X-BYTERANGE:'):
                    length, _, offset = line.split(':', 1)[1].partition('@')
                    start = int(offset) if offset else end
                    pending = start, start + int(length) - 1
                    end = pending[1] + 1
                elif line and not line.startswith('#'):
                    target = urllib.parse.urlsplit(urllib.parse.urljoin('https://' + host + variant_path, line))
                    if (target.scheme != 'https' or target.netloc != host or target.path != ts_path
                            or target.query or target.fragment or pending is None):
                        raise ValueError('foreign segment')
                    self._range(host, ts_path, bodies[ts_path], *pending)
                    pending = None

    def run(self, *, require_cold=False, denied=False):
        report = Counter()
        try:
            canonical = self._request('media.divine.video', '/', limit=65536)
            if canonical.status != 200 or 'text/html' not in canonical.headers.get('content-type', ''):
                raise ValueError('canonical landing missing')
            for host in self.hosts:
                landing = self._request(host, '/', limit=65536)
                self._bunny(landing)
                if (landing.status != 200 or landing.body != canonical.body
                        or 'text/html' not in landing.headers.get('content-type', '')):
                    raise ValueError('Bunny landing differs')
                if denied:
                    for path in self.pins:
                        for method, byte_range in (('GET', None), ('HEAD', None), ('GET', (0, 0))):
                            reply = self._request(host, path, method, byte_range, limit=8192)
                            if reply.status not in (401, 403, 404):
                                report['failures'] += 1
                            else:
                                report['denied_requests'] += 1
                    continue
                bodies = {}
                for path, pin in self.pins.items():
                    first = self._request(host, path, limit=pin['delivery_size'])
                    self._bunny(first)
                    self._mime(path, first)
                    if (first.status != 200 or len(first.body) != pin['delivery_size']
                            or hashlib.sha256(first.body).hexdigest() != pin['delivery_sha256']):
                        raise ValueError('delivery bytes differ')
                    if require_cold and first.headers.get('cdn-cache', '').upper() != 'MISS':
                        raise ValueError('fixture was not cold')
                    head = self._request(host, path, method='HEAD', limit=0)
                    self._bunny(head)
                    if head.status != 200 or head.headers.get('content-length') != str(len(first.body)):
                        raise ValueError('HEAD proof failed')
                    warm = self._request(host, path, limit=pin['delivery_size'])
                    self._bunny(warm)
                    if (warm.status != 200 or warm.body != first.body
                            or warm.headers.get('cdn-cache', '').upper() != 'HIT'):
                        raise ValueError('warm cache proof failed')
                    self._range(host, path, first.body, 0, min(31, len(first.body) - 1))
                    bodies[path] = first.body
                    report['verified_objects'] += 1
                self._tree(host, bodies)
        except Exception:
            # Identity, response text and URLs deliberately never enter output.
            report['failures'] += 1
        report['requests'], report['body_bytes'] = self.requests, self.bytes
        return {'ok': not report.get('failures'), **dict(report)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', required=True, type=Path, help='Private ready inventory exported from enrollment journal')
    parser.add_argument('--vendor-host', required=True)
    parser.add_argument('--max-bytes', required=True, type=int)
    parser.add_argument('--max-requests', type=int, default=5000)
    parser.add_argument('--require-cold', action='store_true')
    parser.add_argument('--denied', action='store_true')
    parser.add_argument('--watch-denied-seconds', type=int, default=0)
    args = parser.parse_args(argv)
    try:
        if (args.inventory.is_symlink() or args.inventory.stat().st_mode & 0o077
                or args.inventory.stat().st_size > 32768):
            raise ValueError('inventory must be private and bounded')
        if not 0 <= args.watch_denied_seconds <= 600 or (args.watch_denied_seconds and not args.denied):
            raise ValueError('invalid denied watch')
        inventory = json.loads(args.inventory.read_text())
        probe = Probe(inventory, (CUSTOM, args.vendor_host), max_requests=args.max_requests, max_bytes=args.max_bytes)
        deadline = time.monotonic() + args.watch_denied_seconds
        report = probe.run(require_cold=args.require_cold, denied=args.denied)
        while report['ok'] and args.denied and time.monotonic() < deadline:
            time.sleep(max(0, min(5, deadline - time.monotonic())))
            report = probe.run(denied=True)
        print(json.dumps(report, sort_keys=True))
        return int(not report['ok'])
    except Exception:
        print('CDN proof did not finish; inspect private fixture/configuration. Response details suppressed.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
