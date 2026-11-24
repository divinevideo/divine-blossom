# ABOUTME: Tests read-only acceptance and revocation checks for the Bunny pilot.

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch


SCRIPT = Path(__file__).resolve().parents[1] / 'probe_bunny_delivery.py'
HASH = 'a' * 64
sys.path.insert(0, str(SCRIPT.parent))


class TestCommandLine(unittest.TestCase):
    def test_invalid_fixture_path_fails_before_network_and_is_not_echoed(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = Path(directory) / 'retired-paths.txt'
            invalid_path = f'/{HASH}?versionId=private-example'
            paths.write_text(invalid_path + '\n', encoding='utf-8')
            result = subprocess.run(
                [sys.executable, str(SCRIPT), '--denied-file', str(paths),
                 '--alias', 'test-zone.b-cdn.net', '--region', 'qa'],
                capture_output=True, text=True, check=False, timeout=5,
            )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('invalid fixture path on line 1', result.stderr)
        self.assertNotIn(invalid_path, result.stderr + result.stdout)


class TestAcceptance(unittest.TestCase):
    def test_deny_checks_both_full_and_range_get_even_when_head_denies(self):
        import probe_bunny_delivery as probe

        path = f'/{HASH}/720p.mp4'
        denied = probe.Reply(404, {}, b'not found')
        partial = probe.Reply(206, {'content-range': 'bytes 0-0/10'}, b'x')
        with patch.object(probe, 'fetch', side_effect=(denied, denied, partial)) as fetch:
            checks = probe.denial_checks('test-zone.b-cdn.net', path)
        self.assertEqual([check['ok'] for check in checks], [True, True, False])
        self.assertEqual(fetch.call_args_list, [
            call('test-zone.b-cdn.net', 'HEAD', path, {}, read_body=False),
            call('test-zone.b-cdn.net', 'GET', path, {}, read_body=False),
            call('test-zone.b-cdn.net', 'GET', path, {'Range': 'bytes=0-0'}, read_body=False),
        ])

    def test_success_requires_matching_full_bytes_ranges_and_head(self):
        import probe_bunny_delivery as probe

        path = f'/{HASH}/720p.mp4'
        body = b'test rendition bytes'
        headers = {'content-type': 'video/mp4', 'cache-control': 'private, no-store',
                   'content-length': str(len(body))}
        cold_get = probe.Reply(200, {**headers, 'cdn-cache': 'MISS'}, body)
        warm_get = probe.Reply(200, {**headers, 'cdn-cache': 'HIT'}, body)
        head = probe.Reply(200, headers, b'')
        range_reply = probe.Reply(206, {**headers, 'content-range': f'bytes 0-{len(body)-1}/{len(body)}'}, body)
        fixtures = [cold_get, range_reply, head, warm_get]
        with patch.object(probe, 'fetch', side_effect=fixtures):
            checks = probe.readiness_checks('test-zone.b-cdn.net', path, body)
        self.assertTrue(all(check['ok'] for check in checks), checks)

        corrupt_range = probe.Reply(206, range_reply.headers, b'X' + body[1:])
        with patch.object(probe, 'fetch', side_effect=[cold_get, corrupt_range, head, warm_get]):
            checks = probe.readiness_checks('test-zone.b-cdn.net', path, body)
        self.assertFalse(checks[1]['ok'], checks)

    def test_guard_checks_allow_only_the_matching_public_landing_page(self):
        import probe_bunny_delivery as probe
        body = b'<html>Divine Blossom Server</html>'
        def fetch(host, method, path, headers=None, **kwargs):
            if path == '/' and method in ('GET', 'HEAD'):
                return probe.Reply(200, {'content-type': 'text/html; charset=utf-8',
                    'content-length': str(len(body))}, body if method == 'GET' else b'')
            return probe.Reply(403, {}, b'')
        with patch.object(probe, 'fetch', side_effect=fetch):
            checks = probe.guard_checks('test-zone.b-cdn.net', f'/{HASH}')
        self.assertTrue(all(check['ok'] for check in checks), checks)
        self.assertIn('landing-get', [check['operation'] for check in checks])
        self.assertIn('landing-head', [check['operation'] for check in checks])

    def test_redirect_errors_and_served_mp4_are_not_proof_of_denial(self):
        import probe_bunny_delivery as probe

        for bad in (probe.Reply(302, {}, b''), probe.Reply(503, {}, b''),
                    probe.Reply(404, {'content-type': 'video/mp4'}, b'video bytes')):
            with self.subTest(status=bad.status, headers=bad.headers):
                with patch.object(probe, 'fetch', return_value=bad):
                    checks = probe.denial_checks('test-zone.b-cdn.net', f'/{HASH}')
                self.assertFalse(any(check['ok'] for check in checks), checks)
