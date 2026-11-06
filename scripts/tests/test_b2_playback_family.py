"""Pure synthetic playback-family validation; no storage access."""
import unittest

from scripts.b2_playback_family import (
    ObjectIdentity, family_keys, validate_playback_family, validate_source_identity,
)

PARENT = "a" * 64
PREFIX = PARENT + "/hls/"
MASTER = (b'#EXTM3U\n#EXT-X-VERSION:4\n'
          b'#EXT-X-STREAM-INF:BANDWIDTH=2500000,CODECS="avc1.64001f,mp4a.40.2"\nstream_720p.m3u8\n'
          b'#EXT-X-STREAM-INF:BANDWIDTH=1000000\nstream_480p.m3u8\n')


def variant(resolution):
    return (f'#EXTM3U\n#EXT-X-VERSION:4\n#EXT-X-TARGETDURATION:10\n'
            f'#EXT-X-MEDIA-SEQUENCE:0\n#EXT-X-PLAYLIST-TYPE:VOD\n'
            f'#EXTINF:3.0,\n#EXT-X-BYTERANGE:4@0\nstream_{resolution}.ts\n'
            f'#EXTINF:3.0,\n#EXT-X-BYTERANGE:4\nstream_{resolution}.ts\n'
            f'#EXT-X-ENDLIST\n').encode()


def fixtures():
    manifests = {PREFIX + 'master.m3u8': MASTER,
                 **{PREFIX + f'stream_{r}.m3u8': variant(r) for r in ('720p', '480p')}}
    sizes = {PREFIX + f'stream_{r}.{ext}': 8 for r in ('720p', '480p') for ext in ('ts', 'mp4')}
    sizes.update({key: len(body) for key, body in manifests.items()})
    return manifests, sizes


class FamilyTests(unittest.TestCase):
    def test_complete_family_orders_payload_before_playlists_and_master(self):
        manifests, sizes = fixtures()
        order = validate_playback_family(PARENT, manifests, sizes)
        self.assertEqual(set(order), set(sizes))
        self.assertEqual(len(order), 7)
        self.assertTrue(all(not k.endswith('.m3u8') for k in order[:4]))
        self.assertEqual(order[-1], PREFIX + 'master.m3u8')

    def test_parent_and_exact_membership(self):
        for parent in ('', 'a' * 63, 'A' * 64, '../' + PARENT):
            with self.subTest(parent=parent), self.assertRaises(ValueError):
                family_keys(parent)
        manifests, sizes = fixtures()
        for changed in ({k: v for k, v in sizes.items() if not k.endswith('720p.mp4')},
                        {**sizes, PREFIX + 'extra.ts': 1}, {**sizes, 'foreign/master.m3u8': 1}):
            with self.subTest(keys=list(changed)), self.assertRaises(ValueError):
                validate_playback_family(PARENT, manifests, changed)

    def test_sizes_and_manifest_lengths_are_bounded(self):
        manifests, sizes = fixtures()
        for size in (0, -1, True, 1.5, '8', 32 * 1024 * 1024 + 1):
            with self.subTest(size=size), self.assertRaises(ValueError):
                validate_playback_family(PARENT, manifests, {**sizes, PREFIX + 'stream_720p.ts': size})
        large = {k: (32 * 1024 * 1024 if k.endswith('.mp4') else v) for k, v in sizes.items()}
        with self.assertRaises(ValueError):
            validate_playback_family(PARENT, manifests, large)
        for body in (MASTER + b' ' * 65536, b'\xff', MASTER + b'\x00'):
            with self.subTest(body_size=len(body)), self.assertRaises(ValueError):
                validate_playback_family(PARENT, {**manifests, PREFIX + 'master.m3u8': body},
                                         {**sizes, PREFIX + 'master.m3u8': len(body)})
        with self.assertRaises(ValueError):
            validate_playback_family(PARENT, manifests, {**sizes, PREFIX + 'master.m3u8': len(MASTER) + 1})

    def assert_invalid_manifest(self, filename, body):
        manifests, sizes = fixtures()
        key = PREFIX + filename
        manifests[key], sizes[key] = body, len(body)
        with self.assertRaises(ValueError):
            validate_playback_family(PARENT, manifests, sizes)

    def test_master_references_only_both_known_variants_once(self):
        for ref in (b'https://example.test/x', b'//example.test/x', b'../x', b'/x',
                    b'stream_720p.m3u8?x=1', b'%73tream_720p.m3u8', b'stream_480p.m3u8'):
            with self.subTest(ref=ref):
                self.assert_invalid_manifest('master.m3u8', MASTER.replace(b'stream_720p.m3u8', ref))
        self.assert_invalid_manifest('master.m3u8', MASTER.replace(b'#EXT-X-STREAM-INF:BANDWIDTH=1000000\nstream_480p.m3u8\n', b''))
        self.assert_invalid_manifest('master.m3u8', MASTER + b'#EXT-X-STREAM-INF:BANDWIDTH=1\n')
        self.assert_invalid_manifest('master.m3u8', MASTER.replace(b'BANDWIDTH=2500000', b'BANDWIDTH=2500000,URI="https://example.test/x"'))

    def test_media_requires_complete_vod_and_correct_ts(self):
        original = variant('720p')
        for body in (original.replace(b'#EXT-X-ENDLIST\n', b''),
                     original.replace(b'#EXT-X-PLAYLIST-TYPE:VOD', b'#EXT-X-PLAYLIST-TYPE:EVENT'),
                     original.replace(b'stream_720p.ts', b'stream_480p.ts'),
                     original.replace(b'#EXTINF:3.0,\n', b''),
                     original + b'stream_720p.ts\n',
                     original.replace(b'#EXTM3U', b'#bad')):
            self.assert_invalid_manifest('stream_720p.m3u8', body)

    def test_control_characters_in_titles_are_not_ignored(self):
        for control in ('\x7f', '\x85', '\x9f'):
            with self.subTest(control=repr(control)):
                self.assert_invalid_manifest('stream_720p.m3u8',
                    variant('720p').replace(b'3.0,', ('3.0,' + control).encode()))

    def test_manifest_line_bytes_are_not_normalized_into_different_references(self):
        for uri in (b' stream_720p.m3u8', b'stream_720p.m3u8 ',
                    'stream_720p.m3u8\u00a0'.encode()):
            with self.subTest(uri=uri):
                self.assert_invalid_manifest('master.m3u8', MASTER.replace(b'stream_720p.m3u8', uri))
        for separator in (b'\r', '\u2028'.encode(), '\u2029'.encode()):
            with self.subTest(separator=separator):
                self.assert_invalid_manifest('stream_720p.m3u8', variant('720p').replace(b'\n', separator))

    def test_crlf_and_real_empty_lines_are_supported(self):
        manifests, sizes = fixtures()
        manifests = {key: body.replace(b'\n', b'\r\n\r\n') for key, body in manifests.items()}
        sizes.update({key: len(body) for key, body in manifests.items()})
        self.assertEqual(len(validate_playback_family(PARENT, manifests, sizes)), 7)

    def test_range_bounds_and_inheritance(self):
        original = variant('720p')
        for before, after in ((b'4@0', b'4'), (b'4@0', b'9@0'), (b'4@0', b'0@0'),
                              (b'4@0', b'4@-1'), (b'BYTERANGE:4\n', b'BYTERANGE:5\n'),
                              (b'BYTERANGE:4\n', b'BYTERANGE:4@2\n')):
            with self.subTest(after=after):
                self.assert_invalid_manifest('stream_720p.m3u8', original.replace(before, after))

    def test_byterange_requires_compatible_version_and_extinf_comma(self):
        original = variant('720p')
        for body in (original.replace(b'#EXT-X-VERSION:4\n', b''),
                     original.replace(b'#EXT-X-VERSION:4', b'#EXT-X-VERSION:3'),
                     original.replace(b'#EXTINF:3.0,', b'#EXTINF:3.0')):
            self.assert_invalid_manifest('stream_720p.m3u8', body)

    def test_unsupported_hls_features_fail_closed(self):
        for tag in (b'#EXT-X-KEY:METHOD=AES-128,URI="key"',
                    b'#EXT-X-MAP:URI="init.mp4"', b'#EXT-X-MEDIA:URI="audio.m3u8"',
                    b'#EXT-X-SESSION-KEY:URI="key"', b'#EXT-X-UNKNOWN:1'):
            with self.subTest(tag=tag):
                self.assert_invalid_manifest('stream_720p.m3u8', variant('720p').replace(b'#EXTM3U\n', b'#EXTM3U\n' + tag + b'\n'))

    def test_segment_count_is_bounded(self):
        body = b'#EXTM3U\n#EXT-X-TARGETDURATION:1\n#EXT-X-PLAYLIST-TYPE:VOD\n'
        body += b'#EXT-X-VERSION:4\n'
        body += b'#EXTINF:1,\n#EXT-X-BYTERANGE:1@0\nstream_720p.ts\n'
        body += b'#EXTINF:1,\n#EXT-X-BYTERANGE:1\nstream_720p.ts\n' * 1024
        body += b'#EXT-X-ENDLIST\n'
        manifests, sizes = fixtures()
        manifests[PREFIX + 'stream_720p.m3u8'] = body
        sizes[PREFIX + 'stream_720p.m3u8'] = len(body)
        sizes[PREFIX + 'stream_720p.ts'] = 1025
        with self.assertRaisesRegex(ValueError, 'too many segments'):
            validate_playback_family(PARENT, manifests, sizes)


class IdentityTests(unittest.TestCase):
    def test_objectref_accepts_exact_gcs_and_b2_versions(self):
        for provider, version in [('gcs', '123'), ('b2', 'opaque-version-1')]:
            ref = dict(provider=provider, bucket='synthetic-private', key=PARENT, version=version)
            self.assertEqual(validate_source_identity(ref, PARENT), ObjectIdentity(**ref))

    def test_missing_or_retargeted_identity_is_rejected(self):
        valid = dict(provider='gcs', bucket='synthetic-private', key=PARENT, version='123')
        for field, values in {'provider': ['other', None], 'bucket': ['', 'https://example.test', '../x'],
                              'key': ['b' * 64, '../x'], 'version': [None, '', 'null', '0', 'abc', True]}.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    validate_source_identity({**valid, field: value}, PARENT)
        for ref in ({k: v for k, v in valid.items() if k != 'version'}, {**valid, 'url': 'https://example.test'}):
            with self.assertRaises(ValueError):
                validate_source_identity(ref, PARENT)
        with self.assertRaises(ValueError):
            validate_source_identity({**valid, 'provider': 'b2', 'version': 'x\nsecret'}, PARENT)


if __name__ == '__main__':
    unittest.main()
