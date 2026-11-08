"""Pure revision-inventory validation, not provider verification or readiness.

Callers must fetch marker/playlist bytes at the exact supplied pinned refs and
independently verify payloads, current source, policy and exclusion. This module
performs no I/O and grants no write, publication or playback authority.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
import re

from scripts.b2_playback_family import (
    MAX_FAMILY_BYTES, MAX_MANIFEST_BYTES, MAX_OBJECT_BYTES, ObjectIdentity,
    validate_playback_family, validate_source_identity,
)

NAMES = ('stream_720p.ts', 'stream_720p.mp4', 'stream_480p.ts', 'stream_480p.mp4',
         'stream_720p.m3u8', 'stream_480p.m3u8', 'master.m3u8')


@dataclass(frozen=True)
class ArtifactInventoryClaim:
    filename: str
    object: ObjectIdentity
    sha256: str
    size: int
    content_type: str


@dataclass(frozen=True)
class ValidatedRevisionInventory:
    parent_sha256: str
    revision_id: str
    manifest: ObjectIdentity
    artifacts: tuple[ArtifactInventoryClaim, ...]


def _fields(value, names):
    if not isinstance(value, dict) or set(value) != set(names.split()):
        raise ValueError('invalid inventory fields')


def _uint(value, maximum=2**64 - 1):
    if type(value) is not int or not 0 < value <= maximum:
        raise ValueError('invalid positive integer')
    return value


def _hash(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError('invalid checksum identity')
    return value


def _hint(value):
    if (not isinstance(value, str) or not 0 < len(value) <= 255
            or any(not 32 <= ord(c) <= 126 for c in value)):
        raise ValueError('invalid descriptive MIME hint')


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON member')
        result[key] = value
    return result


def _invalid_constant(_):
    raise ValueError('non-JSON numeric constant')


def validate_revision_inventory(receipt, attempt, marker_bytes, marker_ref, playlists):
    """Bind structural claims to one completed receipt and inspected PG plan.

    marker_ref must be the exact receipt ref used by the caller to fetch these
    bytes. The pure validator cannot prove their fetch origin. Only the three
    supplied playlist bodies have their byte digests checked here; TS/MP4
    checksums and versions remain inventory claims until independently verified.
    """
    _fields(receipt, 'schema_version processing_job_id input_revision lease_generation state '
                     'source destinations sha256 size content_type pipeline_version manifest')
    _fields(attempt, 'attempt_id processing_job_id input_revision lease_generation source sha256 '
                     'size content_type_hint pipeline_version phase artifacts')
    if type(receipt['schema_version']) is not int or receipt['schema_version'] != 1 or receipt['state'] != 'completed':
        raise ValueError('completed receipt required')
    parent = _hash(receipt['sha256'])
    source = validate_source_identity(receipt['source'], parent)
    _uint(receipt['size'])
    _uint(receipt['input_revision'], 2**63 - 1)
    _uint(receipt['lease_generation'], 2**63 - 1)
    _uint(receipt['pipeline_version'], 2**32 - 1)
    _hint(receipt['content_type'])
    _hint(attempt['content_type_hint'])
    destinations = receipt['destinations']
    if not isinstance(destinations, list) or not 0 < len(destinations) <= 16:
        raise ValueError('invalid destination inventory')
    identities = [validate_source_identity(value, parent) for value in destinations]
    if len(set(identities)) != len(identities):
        raise ValueError('duplicate destination identity')
    job_bytes = json.dumps(['divine-media-processing-v1', receipt['pipeline_version'], asdict(source)],
                          separators=(',', ':'), ensure_ascii=False).encode()
    if _hash(receipt['processing_job_id']) != hashlib.sha256(job_bytes).hexdigest():
        raise ValueError('processing identity mismatch')
    for field in ['processing_job_id', 'input_revision', 'lease_generation', 'source',
                  'sha256', 'size', 'pipeline_version']:
        # Check scalar types as well: True is not the integer 1 in the wire contract.
        if type(attempt[field]) is not type(receipt[field]) or attempt[field] != receipt[field]:
            raise ValueError('receipt and plan disagree')
    nonce = attempt['attempt_id']
    if (attempt['phase'] != 'planned' or not isinstance(nonce, str)
            or not re.fullmatch('[0-9a-f]{32}', nonce)):
        raise ValueError('planned durable attempt required')
    manifest_key = f'_private/artifact-families/v1/{parent}/complete.json'
    manifest = validate_source_identity(receipt['manifest'], manifest_key)
    if validate_source_identity(marker_ref, manifest_key) != manifest:
        raise ValueError('marker fetch reference mismatch')
    if not isinstance(marker_bytes, bytes) or not 0 < len(marker_bytes) <= MAX_MANIFEST_BYTES:
        raise ValueError('marker body exceeds contract')
    try:
        marker = json.loads(marker_bytes.decode('utf-8'), object_pairs_hook=_object,
                            parse_constant=_invalid_constant)
    except (UnicodeError, RecursionError, ValueError):
        raise ValueError('invalid marker JSON') from None
    _fields(marker, 'schema_version producer_job_id pipeline_version lease_generation input_revision '
                    'parent_sha256 source source_size source_content_type revision_id artifacts')
    for key, expected in [('schema_version', 1), ('producer_job_id', receipt['processing_job_id']),
                          ('pipeline_version', receipt['pipeline_version']),
                          ('lease_generation', receipt['lease_generation']),
                          ('input_revision', receipt['input_revision']), ('parent_sha256', parent),
                          ('source', receipt['source']), ('source_size', receipt['size']), ('revision_id', nonce)]:
        if type(marker[key]) is not type(expected) or marker[key] != expected:
            raise ValueError('marker fence or source mismatch')
    validate_source_identity(marker['source'], parent)
    # Descriptive only; deliberately not an equality fence or a verified probe.
    _hint(marker['source_content_type'])
    claims, planned = marker['artifacts'], attempt['artifacts']
    if not isinstance(claims, list) or not isinstance(planned, list) or len(claims) != 7 or len(planned) != 7:
        raise ValueError('exact seven-artifact plan required')
    refs, sizes, manifests = [], {}, {}
    if not isinstance(playlists, dict) or set(playlists) != {name for name in NAMES if name.endswith('.m3u8')}:
        raise ValueError('exact three playlist bodies required')
    for name, claim, plan in zip(NAMES, claims, planned):
        _fields(claim, 'filename object sha256 size content_type metadata')
        _fields(plan, 'filename target sha256 size content_type metadata')
        _fields(plan['target'], 'provider bucket key')
        expected_key = f'{parent}/revisions/v1/{nonce}/{name}'
        ref = validate_source_identity(claim['object'], expected_key)
        expected_target = {'provider': source.provider, 'bucket': source.bucket, 'key': expected_key}
        if plan['target'] != expected_target or {k: v for k, v in asdict(ref).items() if k != 'version'} != expected_target:
            raise ValueError('immutable revision target mismatch')
        mime = ('application/vnd.apple.mpegurl' if name.endswith('.m3u8') else
                'video/mp2t' if name.endswith('.ts') else 'video/mp4')
        metadata = {'source-sha256': parent, 'derivative': 'hls', 'hls-filename': name}
        if claim['filename'] != name or plan['filename'] != name or claim['content_type'] != mime or plan['content_type'] != mime:
            raise ValueError('artifact order or MIME mismatch')
        if claim['metadata'] != metadata or plan['metadata'] != metadata:
            raise ValueError('artifact metadata mismatch')
        _hash(plan['sha256'])
        _uint(plan['size'], MAX_MANIFEST_BYTES if name.endswith('.m3u8') else MAX_OBJECT_BYTES)
        if type(claim['size']) is not int or claim['size'] != plan['size'] or claim['sha256'] != plan['sha256']:
            raise ValueError('artifact digest or size mismatch')
        legacy_key = f'{parent}/hls/{name}'
        sizes[legacy_key] = claim['size']
        if name.endswith('.m3u8'):
            body = playlists[name]
            if not isinstance(body, bytes) or len(body) != claim['size'] or hashlib.sha256(body).hexdigest() != claim['sha256']:
                raise ValueError('playlist bytes differ from inventory')
            manifests[legacy_key] = body
        refs.append(ArtifactInventoryClaim(name, ref, claim['sha256'], claim['size'], mime))
    if sum(sizes.values()) > MAX_FAMILY_BYTES:
        raise ValueError('family byte budget exceeded')
    # Logical-key adaptation only; never rewrite playlist bytes or URI strings.
    validate_playback_family(parent, manifests, sizes)
    return ValidatedRevisionInventory(parent, nonce, manifest, tuple(refs))
