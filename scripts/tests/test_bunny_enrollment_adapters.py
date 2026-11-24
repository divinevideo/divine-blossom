"""Pinned source/control adapters; no network or account data."""
import hashlib
import io
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from publish_bunny_media import S3Source, FastlyCatalog, BunnyAdmin, GCSProducer, APIRefused
from sync_b2_originals import ControlAPIError

PARENT = 'a' * 64

class HTTP:
    def __init__(self, result):
        self.result = result
        self.calls = []
    def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

class Body(io.BytesIO):
    closed_by_adapter = False
    def close(self):
        self.closed_by_adapter = True
        super().close()

class S3:
    def __init__(self):
        self.body = Body(b'abc')
        self.version = 'immutable-version'
        self.calls = []
    def head_object(self, **kwargs):
        self.calls.append(('HEAD', kwargs))
        return {'ContentLength': 3, 'VersionId': self.version}
    def get_object(self, **kwargs):
        self.calls.append(('GET', kwargs))
        return {'ContentLength': 3, 'VersionId': self.version, 'Body': self.body}

class AdapterTests(unittest.TestCase):
    def test_source_pins_provider_version_and_closes_body(self):
        client = S3()
        source = S3Source('fixture-bucket', client)
        identity = source.head(PARENT)
        self.assertEqual(identity['version'], 'immutable-version')
        self.assertEqual(source.read(PARENT, identity), b'abc')
        self.assertTrue(client.body.closed_by_adapter)
        self.assertEqual(client.calls[2][1]['VersionId'], 'immutable-version')

    def test_source_rejects_changed_or_absent_versions(self):
        client = S3()
        source = S3Source('fixture-bucket', client)
        identity = source.head(PARENT)
        client.version = 'new-current-version'
        with self.assertRaises(ValueError):
            source.read(PARENT, identity)
        client.version = 'null'
        with self.assertRaises(ValueError):
            source.head(PARENT)

    def test_catalog_pages_only_exact_metadata_keys_and_preserves_cursor(self):
        http = HTTP({'data': ['blob:' + PARENT, 'blob:stats'], 'meta': {'next_cursor': 'next'}})
        catalog = FastlyCatalog('fixture-store', 'fixture-token', http=http)
        self.assertEqual(catalog.page('before', 100), ([PARENT], 'next'))
        url = http.calls[0][0][0]
        self.assertIn('prefix=blob', url)
        self.assertIn('cursor=before', url)
        self.assertNotIn('fixture-token', url)
        http.result = {'data': ['not-the-prefix'], 'meta': {}}
        with self.assertRaises(ValueError):
            catalog.page(None, 100)

    def test_expired_cursor_restarts_discovery_without_discarding_committed_work(self):
        http = HTTP({'data': ['blob:' + PARENT], 'meta': {}})
        request = http.request
        def expired(*args, **kwargs):
            if not http.calls:
                http.calls.append((args, kwargs))
                raise ControlAPIError(400)
            return request(*args, **kwargs)
        http.request = expired
        catalog = FastlyCatalog('fixture-store', 'fixture-token', http=http)
        self.assertEqual(catalog.page('expired-cursor', 100), ([PARENT], None))
        self.assertIn('cursor=expired-cursor', http.calls[0][0][0])
        self.assertNotIn('cursor=', http.calls[1][0][0])

    def test_admin_uses_only_canonical_https_and_turns_unknown_server_result_uncertain(self):
        http = HTTP({'result': 'ready'})
        api = BunnyAdmin('fixture-token', http=http)
        self.assertEqual(api.finalize({'version': 1}), {'result': 'ready'})
        self.assertEqual(http.calls[0][0][0], 'https://media.divine.video/admin/api/bunny-pilot/finalize')
        self.assertEqual(http.calls[0][1]['headers']['Authorization'], 'Bearer fixture-token')
        http.result = ControlAPIError(409)
        with self.assertRaises(APIRefused):
            api.publish({})
        http.result = ControlAPIError(502)
        with self.assertRaises(ConnectionError):
            api.publish({})

    def test_any_existing_producer_claim_blocks_snapshot(self):
        class Bucket:
            claim = None
            def get_blob(self, key, **kwargs):
                self.key = key
                return self.claim
        class Client:
            handle = Bucket()
            def bucket(self, name):
                return self.handle
        client = Client()
        producer = GCSProducer('fixture-bucket', client)
        self.assertTrue(producer.idle(PARENT))
        self.assertEqual(client.handle.key, '.internal/hls-claims/' + PARENT)
        client.handle.claim = object()
        self.assertFalse(producer.idle(PARENT))

if __name__ == '__main__':
    unittest.main()
