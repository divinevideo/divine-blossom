"""Synthetic receipt/plan/marker validation; no storage or readiness authority."""
import copy
import hashlib
import json
import unittest

from scripts.tests.test_b2_playback_family import MASTER, variant
from scripts.b2_playback_revision import validate_revision_inventory

PARENT = 'a' * 64
NONCE = 'b' * 32
SOURCE = dict(provider='b2', bucket='synthetic-private', key=PARENT, version='source-1')
REF = dict(SOURCE, key=f'_private/artifact-families/v1/{PARENT}/complete.json', version='marker-1')
NAMES = ['stream_720p.ts', 'stream_720p.mp4', 'stream_480p.ts', 'stream_480p.mp4',
         'stream_720p.m3u8', 'stream_480p.m3u8', 'master.m3u8']


def fixture():
    bodies = {name: (MASTER if name == 'master.m3u8' else
                    variant(name.split('_')[1].split('.')[0]) if name.endswith('.m3u8') else b'12345678')
              for name in NAMES}
    job = hashlib.sha256(json.dumps(['divine-media-processing-v1', 1, SOURCE], separators=(',', ':')).encode()).hexdigest()
    receipt = dict(schema_version=1, processing_job_id=job, input_revision=1, lease_generation=2,
                   state='completed', source=SOURCE.copy(), destinations=[SOURCE.copy()],
                   sha256=PARENT, size=99, content_type='video/owner-hint', pipeline_version=1, manifest=REF.copy())
    attempt = {key: copy.deepcopy(receipt[key]) for key in [
        'processing_job_id', 'input_revision', 'lease_generation', 'source', 'sha256', 'size', 'pipeline_version']}
    attempt.update(attempt_id=NONCE, content_type_hint='video/another-hint', phase='planned', artifacts=[])
    marker = dict(schema_version=1, producer_job_id=job, pipeline_version=1, lease_generation=2,
                  input_revision=1, parent_sha256=PARENT, source=SOURCE.copy(), source_size=99,
                  source_content_type='video/marker-hint', revision_id=NONCE, artifacts=[])
    for name, body in bodies.items():
        mime = ('application/vnd.apple.mpegurl' if name.endswith('.m3u8') else
                'video/mp2t' if name.endswith('.ts') else 'video/mp4')
        target = dict(provider=SOURCE['provider'], bucket=SOURCE['bucket'],
                      key=f'{PARENT}/revisions/v1/{NONCE}/{name}')
        common = dict(filename=name, sha256=hashlib.sha256(body).hexdigest(), size=len(body),
                      content_type=mime, metadata={'source-sha256': PARENT, 'derivative': 'hls', 'hls-filename': name})
        attempt['artifacts'].append(dict(common, target=target))
        marker['artifacts'].append(dict(common, object=dict(target, version='artifact-' + name)))
    playlists = {name: body for name, body in bodies.items() if name.endswith('.m3u8')}
    return receipt, attempt, marker, playlists


def validate(receipt, attempt, marker, playlists, ref=REF):
    return validate_revision_inventory(receipt, attempt, json.dumps(marker).encode(), ref, playlists)


class RevisionTests(unittest.TestCase):
    def test_valid_inventory_retains_exact_refs_and_does_not_claim_provider_readiness(self):
        args = fixture()
        result = validate(*args)
        self.assertEqual(result.revision_id, NONCE)
        self.assertEqual([a.object.key for a in result.artifacts], [a['object']['key'] for a in args[2]['artifacts']])
        self.assertFalse(hasattr(result, 'ready'))

    def test_receipt_and_attempt_bind_every_fence_and_source(self):
        for field, value in [('state', 'pending'), ('manifest', None), ('size', True),
                             ('lease_generation', 3), ('input_revision', 2), ('pipeline_version', 2),
                             ('processing_job_id', 'd' * 64), ('sha256', 'e' * 64)]:
            args = list(fixture()); args[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): validate(*args)
        for field, value in [('phase', 'allocated'), ('attempt_id', 'z' * 32), ('size', 100)]:
            args = list(fixture()); args[1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): validate(*args)

    def test_marker_ref_must_be_exact_pinned_receipt_ref(self):
        for ref in [None, dict(REF, version='latest'), dict(REF, key=PARENT + '/hls/master.m3u8')]:
            with self.subTest(ref=ref), self.assertRaises(ValueError): validate(*fixture(), ref=ref)

    def test_marker_identity_and_fences_match_consistent_receipt_and_plan(self):
        for field, value in [('producer_job_id', 'd' * 64), ('pipeline_version', 2),
                             ('lease_generation', 3), ('input_revision', 2),
                             ('parent_sha256', 'e' * 64), ('revision_id', 'c' * 32)]:
            args = list(fixture())
            args[2][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate(*args)

    def test_matching_noncanonical_processing_identity_is_rejected(self):
        receipt, attempt, marker, playlists = fixture()
        receipt['processing_job_id'] = attempt['processing_job_id'] = marker['producer_job_id'] = 'd' * 64
        with self.assertRaises(ValueError):
            validate(receipt, attempt, marker, playlists)

    def test_plan_target_mime_and_metadata_are_checked_independently(self):
        for field, value in [('target', dict(provider='b2', bucket='foreign-private',
                                           key=f'{PARENT}/revisions/v1/{NONCE}/{NAMES[0]}')),
                             ('content_type', 'text/plain'), ('metadata', {})]:
            args = list(fixture())
            args[1]['artifacts'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate(*args)

    def test_marker_json_rejects_duplicates_unknown_keys_and_wrong_scalar_types(self):
        receipt, attempt, marker, playlists = fixture()
        raw = json.dumps(marker).encode()
        for body in [raw.replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1'),
                     raw.replace(b'"version": "source-1"', b'"version": "source-1", "version": "source-1"'),
                     b' ' * 65537, b'{', raw.replace(b'"source_size": 99', b'"source_size": true')]:
            with self.subTest(body_len=len(body)), self.assertRaises(ValueError):
                validate_revision_inventory(receipt, attempt, body, REF, playlists)
        marker['extra'] = 'unsupported'
        with self.assertRaises(ValueError): validate(receipt, attempt, marker, playlists)

    def test_inventory_must_match_exact_order_plan_metadata_and_immutable_targets(self):
        for field, value in [('sha256', 'c' * 64), ('size', 9), ('content_type', 'text/plain'),
                             ('metadata', {}), ('filename', '../stream_720p.ts')]:
            args = list(fixture()); args[2]['artifacts'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): validate(*args)
        for field, value in [('key', PARENT + '/hls/stream_720p.ts'), ('bucket', 'foreign-private'),
                             ('version', None), ('version', ''), ('version', 'null'), ('provider', 'gcs')]:
            args = list(fixture()); args[2]['artifacts'][0]['object'][field] = value
            with self.subTest(field=field,value=value), self.assertRaises(ValueError): validate(*args)
        args = list(fixture()); args[2]['artifacts'].reverse()
        with self.assertRaises(ValueError): validate(*args)

    def test_playlists_require_exact_bytes_digest_length_and_structural_closure(self):
        for change in ['missing', 'foreign', 'digest', 'closure']:
            args = list(fixture())
            if change == 'missing': args[3].pop('master.m3u8')
            elif change == 'foreign': args[3]['extra.m3u8'] = b''
            elif change == 'digest': args[3]['master.m3u8'] += b'\n'
            else:
                bad = args[3]['master.m3u8'].replace(b'stream_720p.m3u8', b'foreign.m3u8')
                args[3]['master.m3u8'] = bad
                for artifacts in [args[1]['artifacts'], args[2]['artifacts']]:
                    artifacts[-1].update(sha256=hashlib.sha256(bad).hexdigest(), size=len(bad))
            with self.subTest(change=change), self.assertRaises(ValueError): validate(*args)

    def test_wrong_scalar_types_unknown_nested_keys_and_budget_excess_are_rejected(self):
        for location, field, value in [
            ('marker', 'schema_version', True), ('marker', 'revision_id', 1),
            ('receipt', 'lease_generation', True), ('attempt', 'input_revision', True),
            ('marker', 'extra', 1), ('attempt', 'extra', 1), ('receipt', 'extra', 1),
        ]:
            args = list(fixture())
            args[{'receipt': 0, 'attempt': 1, 'marker': 2}[location]][field] = value
            with self.subTest(location=location,field=field), self.assertRaises(ValueError): validate(*args)
        for field, value in [('size', True), ('size', 32 * 1024 * 1024 + 1), ('extra', 1)]:
            args = list(fixture())
            for inventory in [args[1]['artifacts'], args[2]['artifacts']]: inventory[0][field] = value
            with self.subTest(field=field,value=value), self.assertRaises(ValueError): validate(*args)
        args = list(fixture())
        for inventory in [args[1]['artifacts'], args[2]['artifacts']]:
            inventory[0]['size'] = inventory[1]['size'] = 32 * 1024 * 1024
        with self.assertRaises(ValueError): validate(*args)

    def test_returned_inventory_is_immutable_and_detached_from_input(self):
        from dataclasses import FrozenInstanceError
        args = fixture()
        result = validate(*args)
        expected = result.artifacts[0].sha256
        args[2]['artifacts'][0]['sha256'] = 'f' * 64
        self.assertEqual(result.artifacts[0].sha256, expected)
        with self.assertRaises(FrozenInstanceError): result.artifacts[0].size = 99

    def test_source_mime_is_a_hint_not_equality_fence(self):
        receipt, attempt, marker, playlists = fixture()
        self.assertNotEqual(receipt['content_type'], marker['source_content_type'])
        validate(receipt, attempt, marker, playlists)
        marker['source_content_type'] = '\nforged'
        with self.assertRaises(ValueError): validate(receipt, attempt, marker, playlists)


if __name__ == '__main__': unittest.main()
