"""Recursive CDN proof using synthetic complete immutable families."""
import hashlib
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from probe_bunny_hls_delivery import Probe, Response
from scripts.tests.test_publish_bunny_media import fixture, PARENT, ROOT
from publish_bunny_media import normalized

HOSTS = ('media-bunny.divine.video', 'fixture-zone.b-cdn.net')

class HTTP:
    def __init__(self):
        source = fixture()
        sizes = {key[len(PARENT) + 1:]: len(body) for key, body in source.items() if key != PARENT}
        self.objects = {'/' + key: normalized(PARENT, key[len(PARENT) + 1:] if key != PARENT else '', body, sizes)
                        for key, body in source.items()}
        self.calls, self.warmed = [], set()
        self.denied = False
        self.range_broken = False
        self.override = {}

    def request(self, host, path, method='GET', byte_range=None, limit=0):
        self.calls.append((host, path, method, byte_range))
        if path == '/':
            return Response(200, {'content-type': 'text/html', 'server': 'BunnyCDN'}, b'<html>Divine Blossom Server</html>')
        if self.denied:
            return Response(403, {'server': 'BunnyCDN', 'cache-control':'private, no-store'}, b'')
        body = self.override.get(path, self.objects[path])
        mime = 'application/vnd.apple.mpegurl' if path.endswith('.m3u8') else 'video/mp2t' if path.endswith('.ts') else 'video/mp4'
        warm = (host, path) in self.warmed
        self.warmed.add((host, path))
        headers = {'server': 'BunnyCDN', 'cache-control': 'private, no-store', 'content-type': mime, 'content-length': str(len(body)), 'cdn-cache': 'HIT' if warm else 'MISS'}
        status = 200
        if byte_range is not None and not self.range_broken:
            start, end = byte_range
            headers['content-range'] = f'bytes {start}-{end}/{len(body)}'
            body = body[start:end + 1]
            headers['content-length'] = str(len(body))
            status = 206
        return Response(status, headers, b'' if method == 'HEAD' else body)


def inventory(http):
    return {'version': 1, 'parent': PARENT, 'assets': [
        {'path': path, 'delivery_sha256': hashlib.sha256(body).hexdigest(), 'delivery_size': len(body)}
        for path, body in http.objects.items()]}

class ProbeTests(unittest.TestCase):
    def test_proves_both_hosts_and_every_segment_range(self):
        http = HTTP()
        result = Probe(inventory(http), HOSTS, http).run(require_cold=True)
        self.assertTrue(result.get('ok'))
        for host in HOSTS:
            for resolution in ('720p', '480p'):
                self.assertIn((host, '/' + ROOT + f'stream_{resolution}.ts', 'GET', (0, 187)), http.calls)
        self.assertTrue(any(call[1] == '/' for call in http.calls))

    def test_rejects_off_host_child_and_incomplete_tree(self):
        for replacement in (b'https://example.test/child.m3u8', b'stream_999p.m3u8'):
            http = HTTP()
            path = '/' + ROOT + 'master.m3u8'
            http.objects[path] = http.objects[path].replace(b'stream_720p.m3u8', replacement)
            result = Probe(inventory(http), HOSTS, http).run()
            self.assertFalse(result.get('ok'))
            self.assertTrue(all(call[0] in HOSTS + ('media.divine.video',) for call in http.calls))

    def test_rejects_wrong_bytes_ranges_and_missing_warm_hits(self):
        http = HTTP()
        http.range_broken = True
        self.assertFalse(Probe(inventory(http), HOSTS, http).run().get('ok'))
        http = HTTP()
        pins = inventory(http)
        http.override['/' + ROOT + 'stream_720p.ts'] = b'x' * 188
        self.assertFalse(Probe(pins, HOSTS, http).run().get('ok'))

    def test_denied_mode_checks_all_known_children_instead_of_trusting_master(self):
        http = HTTP()
        pins = inventory(http)
        http.denied = True
        self.assertTrue(Probe(pins, HOSTS, http).run(denied=True).get('ok'))
        requested = {call[1] for call in http.calls}
        self.assertTrue(set(http.objects) <= requested)
        http.denied = False
        self.assertFalse(Probe(pins, HOSTS, http).run(denied=True).get('ok'))

    def test_hls_only_requires_cache_policy_on_each_response_from_either_host(self):
        for host in HOSTS:
            for phase in ('MISS', 'HIT', 'HEAD', 'range', 'segment'):
                for invalid in ('private', 'no-store', 'public, max-age=300'):
                    with self.subTest(host=host, phase=phase, invalid=invalid):
                        http = HTTP()
                        del http.objects['/' + PARENT]
                        origin = http.request
                        def corrupt(h, p, m, r, limit):
                            reply = origin(h, p, m, r, limit)
                            kind = ('HEAD' if m == 'HEAD' else 'segment' if r == (0, 187) else
                                    'range' if r else reply.headers.get('cdn-cache'))
                            if h == host and p.endswith('stream_480p.ts') and kind == phase:
                                reply.headers['cache-control'] = invalid
                            return reply
                        http.request = corrupt
                        self.assertFalse(Probe(inventory(http), HOSTS, http).run(require_cold=True)['ok'])

    def test_denied_hls_child_requires_cdn_and_nonmedia_on_each_method(self):
        for method, byte_range in [('GET', None), ('HEAD', None), ('GET',(0,0))]:
            for headers, body in [({'server':'other'}, b''), ({'content-range':'bytes 0-0/188'}, b''),
                                  ({'accept-ranges':'bytes'}, b''), ({'content-type':'text/plain'}, b't'),
                                  ({'content-type':'application/vnd.apple.mpegurl'}, b''),
                                  ({'content-type':'video/mp2t'}, b''), ({}, b'#EXTM3U\n'),
                                  ({'cache-control':'public'}, b'')]:
                with self.subTest(method=method, byte_range=byte_range, headers=headers, body=body):
                    http = HTTP()
                    del http.objects['/' + PARENT]
                    http.denied = True
                    origin = http.request
                    def corrupt(h, p, m, r, limit):
                        reply = origin(h, p, m, r, limit)
                        if h == HOSTS[1] and p.endswith('stream_480p.m3u8') and (m,r) == (method,byte_range):
                            reply.headers.update(headers)
                            reply.body = body
                        return reply
                    http.request = corrupt
                    self.assertFalse(Probe(inventory(http), HOSTS, http).run(denied=True)['ok'])

    def test_bounds_requests_and_rejects_foreign_inventory(self):
        http = HTTP()
        self.assertFalse(Probe(inventory(http), HOSTS, http, max_requests=1).run().get('ok'))
        pins = inventory(http)
        pins['assets'][0]['path'] = '/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
        with self.assertRaises(ValueError):
            Probe(pins, HOSTS, http)

if __name__ == '__main__':
    unittest.main()
