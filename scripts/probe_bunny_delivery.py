#!/usr/bin/env python3
# ABOUTME: Verifies media parity and monitors retired fixtures on each Bunny pilot hostname.
# ABOUTME: Sends only read requests and reports status, timing and cache evidence without fixture URLs.

import argparse
import hashlib
import http.client
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

from probe_cdn_delivery import select_cache_status


CANONICAL_HOST = 'media.divine.video'
BUNNY_HOST = 'media-bunny.divine.video'
PILOT_PATH = re.compile(r'/[0-9a-f]{64}(?:/720p\.mp4)?')
BUNNY_ALIAS = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.b-cdn\.net')
DENIED_STATUSES = {401, 403, 404}
MAX_FIXTURE_BYTES = 16 * 1024 * 1024
RANGE_BYTES = 1024


@dataclass(frozen=True)
class Reply:
    status: int
    headers: dict[str, str]
    body: bytes
    ttfb_ms: float = 0.0


def read_paths(file: Path) -> list[str]:
    paths = []
    for line_number, path in enumerate(file.read_text(encoding='utf-8').splitlines(), 1):
        if not PILOT_PATH.fullmatch(path):
            raise ValueError(f'invalid fixture path on line {line_number}')
        if path in paths:
            raise ValueError(f'duplicate fixture path on line {line_number}')
        paths.append(path)
    if not paths:
        raise ValueError('fixture file must contain at least one path')
    return paths


def fetch(
    host: str,
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
    *,
    read_body: bool = True,
) -> Reply:
    connection = http.client.HTTPSConnection(host, timeout=15)
    try:
        connection.connect()
        start = time.monotonic()
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        ttfb_ms = (time.monotonic() - start) * 1000
        response_headers = {name.lower(): value for name, value in response.getheaders()}
        body = b''
        if read_body and response.status in {200, 206}:
            body = response.read(MAX_FIXTURE_BYTES + 1)
        if len(body) > MAX_FIXTURE_BYTES:
            raise ValueError('fixture exceeded size limit')
        return Reply(response.status, response_headers, body, ttfb_ms)
    finally:
        connection.close()


def report(operation: str, response: Reply, ok: bool) -> dict:
    return {
        'operation': operation,
        'status': response.status,
        'cache_status': select_cache_status(response.headers),
        'ttfb_ms': round(response.ttfb_ms, 2),
        'ok': ok,
    }


def denial_checks(host: str, path: str) -> list[dict]:
    checks = []
    for method, range_header in (('HEAD', {}), ('GET', {}), ('GET', {'Range': 'bytes=0-0'})):
        response = fetch(host, method, path, range_header, read_body=False)
        denied = (
            response.status in DENIED_STATUSES
            and 'content-range' not in response.headers
            and not response.headers.get('content-type', '').lower().startswith('video/')
        )
        checks.append(report('range-get' if range_header else method.lower(), response, denied))
    return checks


def valid_media(response: Reply, length: int) -> bool:
    content_type = response.headers.get('content-type', '').split(';', 1)[0].strip().lower()
    cache_control = response.headers.get('cache-control', '').lower().split(',')
    return (
        content_type == 'video/mp4'
        and response.headers.get('content-length') == str(length)
        and response.headers.get('content-encoding', 'identity').lower() == 'identity'
        and any(directive.strip() == 'no-store' for directive in cache_control)
    )


def readiness_checks(host: str, path: str, body: bytes) -> list[dict]:
    if not body:
        raise ValueError('empty canonical fixture')
    size = len(body)
    first = fetch(host, 'GET', path)
    checks = [report('first-get', first, first.status == 200 and valid_media(first, size) and first.body == body)]

    range_starts = [0]
    if size > RANGE_BYTES:
        range_starts.append(size - RANGE_BYTES)
    for start in range_starts:
        end = min(start + RANGE_BYTES, size) - 1
        ranged = fetch(host, 'GET', path, {'Range': f'bytes={start}-{end}'})
        checks.append(report('range-get', ranged, (
            ranged.status == 206
            and valid_media(ranged, end - start + 1)
            and ranged.headers.get('content-range') == f'bytes {start}-{end}/{size}'
            and ranged.body == body[start:end + 1]
        )))

    head = fetch(host, 'HEAD', path)
    checks.append(report('head', head, head.status == 200 and valid_media(head, size)))
    warm = fetch(host, 'GET', path)
    checks.append(report('warm-get', warm, (
        warm.status == 200 and valid_media(warm, size) and warm.body == body
        and warm.headers.get('cdn-cache', '').upper() == 'HIT'
    )))
    return checks


def guard_checks(host: str, path: str) -> list[dict]:
    baseline = fetch(CANONICAL_HOST, 'GET', '/')
    landing = fetch(host, 'GET', '/')
    html = landing.headers.get('content-type', '').split(';', 1)[0].lower() == 'text/html'
    checks = [report('landing-get', landing, baseline.status == landing.status == 200
                     and html and bool(baseline.body) and landing.body == baseline.body)]
    head = fetch(host, 'HEAD', '/', read_body=False)
    checks.append(report('landing-head', head, head.status == 200
                         and head.headers.get('content-length') == str(len(baseline.body))
                         and head.headers.get('content-type', '').split(';', 1)[0].lower() == 'text/html'))
    escaped_path = f'/%{ord(path[1]):02X}{path[2:]}'
    for control, method, target, headers in (
        ('block-root-method', 'POST', '/', {}),
        ('block-query', 'GET', path + '?probe=1', {}),
        ('block-version-query', 'GET', path + '?versionId=pilot-probe-placeholder', {}),
        ('block-escaped-alias', 'GET', escaped_path, {}),
        ('block-auth', 'GET', path, {'Authorization': 'Bearer pilot-probe-placeholder'}),
        ('block-cookie', 'GET', path, {'Cookie': 'pilot_probe=placeholder'}),
        ('block-method', 'OPTIONS', path, {}),
    ):
        response = fetch(host, method, target, headers, read_body=False)
        checks.append(report(control, response, response.status in {400, 401, 403, 404, 405}))
    return checks


def probe(hosts: list[tuple[str, str]], ready: list[str], denied: list[str]) -> list[dict]:
    results = []
    for index, path in enumerate(ready, 1):
        response = fetch(CANONICAL_HOST, 'GET', path)
        is_original = path.count('/') == 1
        canonical_ok = (
            response.status == 200 and bool(response.body)
            and (not is_original or hashlib.sha256(response.body).hexdigest() == path[1:])
        )
        results.append({'host': 'canonical', 'fixture': index, **report('baseline-get', response, canonical_ok)})
        if not canonical_ok:
            continue
        for label, host in hosts:
            checks = readiness_checks(host, path, response.body) + guard_checks(host, path)
            results.extend({'host': label, 'fixture': index, **check} for check in checks)
    for index, path in enumerate(denied, 1):
        for label, host in hosts:
            results.extend({'host': label, 'retired_fixture': index, **check} for check in denial_checks(host, path))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ready-file', type=Path, help='one verified MP4 path per line')
    parser.add_argument('--denied-file', type=Path, required=True, help='one retired owned fixture path per line')
    parser.add_argument('--alias', action='append', required=True, help='assigned Bunny b-cdn.net hostname')
    parser.add_argument('--region', required=True, help='measurement vantage label such as us-home')
    parser.add_argument('--interval', type=int, help='repeat denial-only checks every N seconds, exit on a failure')
    args = parser.parse_args()
    if any(not BUNNY_ALIAS.fullmatch(alias) for alias in args.alias):
        parser.error('aliases must be b-cdn.net hostnames without scheme, port or path')
    if args.interval is not None and (args.interval < 1 or args.ready_file):
        parser.error('--interval requires a positive number of seconds and denial-only mode')
    try:
        ready = read_paths(args.ready_file) if args.ready_file else []
        denied = read_paths(args.denied_file)
    except (OSError, UnicodeError):
        parser.error('unable to read fixture file')
    except ValueError as error:
        parser.error(str(error))
    if set(ready).intersection(denied):
        parser.error('the ready and denied fixture sets must be different')

    hosts = [('bunny', BUNNY_HOST)] + [(f'alias-{index}', host) for index, host in enumerate(args.alias, 1)]
    while True:
        try:
            results = probe(hosts, ready, denied)
            ok = all(check['ok'] for check in results)
            print(json.dumps({'region': args.region, 'ok': ok, 'results': results}), flush=True)
        except (ValueError, OSError, http.client.HTTPException) as error:
            print(json.dumps({'region': args.region, 'ok': False, 'error': type(error).__name__}), flush=True)
            return 1
        if not ok or args.interval is None:
            return 0 if ok else 1
        time.sleep(args.interval)


if __name__ == '__main__':
    raise SystemExit(main())
