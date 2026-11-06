"""Pure validation for the existing two-rendition playback family.

This module neither fetches references nor grants storage/delivery readiness.
Producer completion, policy, copying and pinned-version verification are separate
requirements. Unknown HLS features are deliberately unsupported, not ignored.
"""
from dataclasses import dataclass
from decimal import Decimal
import re

MAX_OBJECT_BYTES = 32 * 1024 * 1024
MAX_FAMILY_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_SEGMENTS = 1024
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_VARIANTS = ('720p', '480p')
_NAMES = tuple(f'stream_{r}.{ext}' for r in _VARIANTS for ext in ('ts', 'mp4')) + (
    'stream_720p.m3u8', 'stream_480p.m3u8', 'master.m3u8')


@dataclass(frozen=True)
class ObjectIdentity:
    provider: str
    bucket: str
    key: str
    version: str


def family_keys(parent: str) -> tuple[str, ...]:
    if not isinstance(parent, str) or not _HEX.fullmatch(parent):
        raise ValueError('invalid parent identity')
    return tuple(f'{parent}/hls/{name}' for name in _NAMES)


def validate_source_identity(value: dict, expected_key: str) -> ObjectIdentity:
    """Validate exact internal ObjectRef fields; version is never an ETag/URL."""
    if not isinstance(value, dict) or set(value) != {'provider', 'bucket', 'key', 'version'}:
        raise ValueError('invalid object identity fields')
    if value['provider'] not in ('gcs', 'b2') or value['key'] != expected_key:
        raise ValueError('unexpected object identity')
    if not isinstance(expected_key, str) or not expected_key or len(expected_key) > 1024:
        raise ValueError('invalid expected key')
    bucket = value['bucket']
    if not isinstance(bucket, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{1,220}[A-Za-z0-9]', bucket):
        raise ValueError('invalid bucket identity')
    version = value['version']
    if (not isinstance(version, str) or not version or version == 'null' or len(version) > 1024
            or any(ord(c) < 33 or ord(c) > 126 for c in version) or '://' in version):
        raise ValueError('missing or invalid immutable version')
    if value['provider'] == 'gcs' and (
            not re.fullmatch(r'[1-9][0-9]{0,19}', version) or int(version) >= 2**64):
        raise ValueError('invalid GCS generation')
    return ObjectIdentity(**value)


def _lines(body):
    if not isinstance(body, bytes) or not 0 < len(body) <= MAX_MANIFEST_BYTES:
        raise ValueError('manifest size/type exceeds contract')
    try:
        text = body.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError('manifest must be UTF-8') from None
    if any((ord(c) < 32 and c not in '\r\n') or 127 <= ord(c) <= 159 for c in text):
        raise ValueError('manifest contains control characters')
    # Validate the bytes that will be published, not normalized URI strings.
    # Only LF and CRLF delimit HLS lines; Unicode separators are not newlines.
    text = text.replace('\r\n', '\n')
    if '\r' in text:
        raise ValueError('bare CR is not an HLS line ending')
    lines = text.split('\n')
    if not lines or lines[0] != '#EXTM3U':
        raise ValueError('missing HLS header')
    return [line for line in lines[1:] if line != '']


def _positive_integer(value, maximum):
    if not re.fullmatch(r'[0-9]{1,15}', value):
        raise ValueError('invalid HLS integer')
    number = int(value)
    if not 0 < number <= maximum:
        raise ValueError('HLS integer out of bounds')
    return number


def _stream_attributes(text):
    attributes = {}
    while text:
        match = re.match(r'([A-Z-]+)=("[^"\r\n]*"|[^,]+)(,|$)', text)
        if not match or match[1] in attributes:
            raise ValueError('invalid or duplicate stream attributes')
        attributes[match[1]] = match[2]
        text = text[match.end():]
        if match[3] and not text:
            raise ValueError('trailing stream attribute separator')
    if not set(attributes) <= {'BANDWIDTH', 'AVERAGE-BANDWIDTH', 'RESOLUTION', 'FRAME-RATE', 'CODECS', 'CLOSED-CAPTIONS'}:
        raise ValueError('unsupported stream attributes')
    _positive_integer(attributes.get('BANDWIDTH', ''), 10**12)
    for name, value in attributes.items():
        if name == 'AVERAGE-BANDWIDTH':
            _positive_integer(value, 10**12)
        elif name == 'RESOLUTION' and not re.fullmatch(r'[1-9][0-9]{0,4}x[1-9][0-9]{0,4}', value):
            raise ValueError('invalid resolution')
        elif name == 'FRAME-RATE' and not re.fullmatch(r'[0-9]{1,3}(\.[0-9]{1,3})?', value):
            raise ValueError('invalid frame rate')
        elif name == 'CODECS' and not re.fullmatch(r'"[A-Za-z0-9.,_-]+"', value):
            raise ValueError('invalid codecs')
        elif name == 'CLOSED-CAPTIONS' and value != 'NONE':
            raise ValueError('external captions unsupported')


def _master(body):
    expected = {f'stream_{r}.m3u8' for r in _VARIANTS}
    seen, tags = set(), set()
    awaiting_uri = False
    for line in _lines(body):
        if awaiting_uri:
            if line not in expected or line in seen:
                raise ValueError('missing, duplicate or foreign variant reference')
            seen.add(line)
            awaiting_uri = False
        elif line.startswith('#EXT-X-STREAM-INF:'):
            _stream_attributes(line.split(':', 1)[1])
            awaiting_uri = True
        elif line.startswith('#EXT-X-VERSION:'):
            if 'version' in tags:
                raise ValueError('duplicate HLS version')
            tags.add('version')
            _positive_integer(line.split(':', 1)[1], 7)
        elif line == '#EXT-X-INDEPENDENT-SEGMENTS':
            if line in tags:
                raise ValueError('duplicate independent-segments tag')
            tags.add(line)
        else:
            raise ValueError('unsupported master entry')
    if awaiting_uri or seen != expected:
        raise ValueError('incomplete master closure')


def _variant(body, resolution, ts_size):
    tags = set()
    target = None
    version = None
    duration = None
    byte_range = None
    previous_end = None
    count = 0
    ended = False
    for line in _lines(body):
        if ended:
            raise ValueError('entries after ENDLIST')
        if not line.startswith('#'):
            if line != f'stream_{resolution}.ts' or duration is None or byte_range is None:
                raise ValueError('unexpected segment reference or incomplete segment')
            length, explicit_start = byte_range
            start = explicit_start if explicit_start is not None else previous_end
            if start is None or (previous_end is not None and start < previous_end) or start + length > ts_size:
                raise ValueError('invalid segment byte range')
            previous_end = start + length
            duration, byte_range = None, None
            count += 1
            if count > MAX_SEGMENTS:
                raise ValueError('too many segments')
            continue
        if line.startswith('#EXTINF:'):
            if duration is not None or target is None:
                raise ValueError('invalid segment ordering')
            payload = line.split(':', 1)[1]
            if ',' not in payload:
                raise ValueError('missing EXTINF title separator')
            value = payload.split(',', 1)[0]
            if not re.fullmatch(r'[0-9]{1,5}(\.[0-9]{1,9})?', value):
                raise ValueError('invalid segment duration')
            duration = Decimal(value)
            if duration <= 0 or int(duration + Decimal('0.5')) > target:
                raise ValueError('duration exceeds target')
        elif line.startswith('#EXT-X-BYTERANGE:'):
            if duration is None or byte_range is not None:
                raise ValueError('invalid byte range ordering')
            match = re.fullmatch(r'([0-9]{1,10})(?:@([0-9]{1,10}))?', line.split(':', 1)[1])
            if not match:
                raise ValueError('invalid byte range')
            length = _positive_integer(match[1], MAX_OBJECT_BYTES)
            byte_range = length, int(match[2]) if match[2] is not None else None
        elif line == '#EXT-X-ENDLIST':
            if duration is not None or byte_range is not None or count == 0:
                raise ValueError('unfinished segment')
            ended = True
        else:
            if duration is not None or count:
                raise ValueError('unexpected media tag ordering')
            tag, _, value = line.partition(':')
            if tag in tags:
                raise ValueError('duplicate media tag')
            tags.add(tag)
            if tag == '#EXT-X-VERSION':
                version = _positive_integer(value, 7)
            elif tag == '#EXT-X-TARGETDURATION':
                target = _positive_integer(value, 86400)
            elif tag == '#EXT-X-MEDIA-SEQUENCE' and value == '0':
                pass
            elif tag == '#EXT-X-PLAYLIST-TYPE' and value == 'VOD':
                pass
            else:
                raise ValueError('unsupported media tag')
    if (not ended or '#EXT-X-PLAYLIST-TYPE' not in tags or target is None
            or version is None or version < 4):
        raise ValueError('incomplete VOD playlist')


def validate_playback_family(parent: str, manifests: dict, sizes: dict) -> tuple[str, ...]:
    """Validate bounded complete closure and return safe dependency upload order."""
    keys = family_keys(parent)
    manifest_keys = set(keys[-3:])
    if not isinstance(sizes, dict) or set(sizes) != set(keys):
        raise ValueError('family must contain exactly seven artifacts')
    if any(type(size) is not int or not 0 < size <= MAX_OBJECT_BYTES for size in sizes.values()):
        raise ValueError('artifact size out of bounds')
    if sum(sizes.values()) > MAX_FAMILY_BYTES:
        raise ValueError('family exceeds byte limit')
    if not isinstance(manifests, dict) or set(manifests) != manifest_keys:
        raise ValueError('family must contain exactly three manifests')
    for key, body in manifests.items():
        if not isinstance(body, bytes) or len(body) != sizes[key]:
            raise ValueError('manifest size differs from inventory')
    prefix = f'{parent}/hls/'
    _master(manifests[prefix + 'master.m3u8'])
    for resolution in _VARIANTS:
        _variant(manifests[prefix + f'stream_{resolution}.m3u8'], resolution,
                 sizes[prefix + f'stream_{resolution}.ts'])
    return keys
