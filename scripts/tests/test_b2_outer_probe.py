"""Offline contracts for probe-only VCL evidence; provider compilation stays a release gate."""
from pathlib import Path
import json
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


class B2OuterProbeTests(unittest.TestCase):
    def source(self):
        path = ROOT / 'vcl/log_b2_probe.vcl'
        self.assertTrue(path.exists(), 'missing request-local outer probe logging')
        return path.read_text()

    def test_probe_gate_rejects_arbitrary_or_identity_bearing_values(self):
        source = self.source()
        pattern = re.search(r'req.http.X-Divine-B2-Probe ~ "([^"]+)"', source).group(1)
        valid = 'b2outer-11111111-1111-4111-8111-111111111111'
        self.assertIsNotNone(re.fullmatch(pattern, valid))
        for invalid in ['', 'person@example.test', valid + 'suffix', valid + '\n',
                        valid.replace('-4111-', '-1111-'), valid.upper(), 'prefix' + valid]:
            self.assertIsNone(re.fullmatch(pattern, invalid), repr(invalid))
        for gate in ['fastly.ff.visits_this_service == 0',
                     'req.method == "GET"', 'req.method == "HEAD"',
                     '!req.http.Authorization', '!req.http.Cookie']:
            self.assertIn(gate, source)
        host = re.search(r'req.http.Host ~ "([^"]+)"', source).group(1)
        for allowed in ['media-b2.divine.video', 'media-b2-cdn.divine.video']:
            self.assertIsNotNone(re.fullmatch(host, allowed))
        for denied in ['media.divine.video', 'media-b2.divine.video.attacker.test',
                       'media-b2.divine.video:443', 'MEDIA-B2.DIVINE.VIDEO']:
            self.assertIsNone(re.fullmatch(host, denied))

    def test_backend_boolean_uses_actual_state_with_restart_unknown(self):
        source = self.source()
        hit = re.search(r'fastly_info.state ~ "([^"]+)"', source).group(1)
        miss = re.findall(r'fastly_info.state ~ "([^"]+)"', source)[1]
        # Exercise production patterns against hand-derived platform states.
        cases = [('HIT', 0), ('HIT-CLUSTER', 0), ('MISS', 1), ('PASS', 1),
                 ('MISS-CLUSTER', 1), ('PASS-CLUSTER', 1), ('HITPASS', None),
                 ('HIT-STALE', None), ('HIT-SYNTH', None), ('HIT-REFRESH', None),
                 ('HIT-WAIT', None), ('MISS-WAIT', None), ('ERROR', None),
                 ('ERROR-DISCONNECT', None), ('NONE', None), ('HIT-CLUSTER-WAIT', None)]
        for state, want in cases:
            got = 0 if re.fullmatch(hit, state) else 1 if re.fullmatch(miss, state) else None
            self.assertEqual(got, want, state)
        self.assertIn('set var.backend_fetch = "null";', source)
        self.assertRegex(source, r'if \(req.restarts == 0\)\s*\{\s*if \(fastly_info.state')
        self.assertIn('set var.backend_fetch = "0";', source)
        self.assertIn('set var.backend_fetch = "1";', source)

    def test_probe_is_privacy_bounded_and_uses_no_cached_or_cross_node_counter(self):
        source = self.source()
        self.assertIn('vcl-error-diagnostics ::', source)
        self.assertIn('divine.blossom.b2_outer_probe.v1', source)
        for forbidden in ['resp.http.', 'obj.http.', 'beresp.http.', 'req.url',
                          'X-Playback-Load-Id', 'req.backend', 'client.ip']:
            # URL may gate paths but must never be emitted as a field/expression.
            if forbidden == 'req.url':
                self.assertNotIn('json.escape(req.url)', source)
                continue
            self.assertNotIn(forbidden, source)
        fields = set(re.findall(r'\{""([a-z_]+)":', source))
        self.assertEqual(fields, {'schema', 'phase', 'timestamp', 'request_id',
                                 'probe_id', 'method', 'status', 'cache_state',
                                 'backend_fetch', 'restart_count', 'ff_visits',
                                 'elapsed_ms', 'body_bytes_written'})
        self.assertIn('json.escape(req.http.X-Divine-Edge-Request-Id)', source)
        self.assertIn('json.escape(req.http.X-Divine-B2-Probe)', source)
        self.assertIn('json.escape(fastly_info.state)', source)
        self.assertIn('{""backend_fetch":"} var.backend_fetch', source)

    def test_ingress_preserves_uuid_across_restart_and_shield(self):
        recv = (ROOT / 'vcl/recv.vcl').read_text()
        block = recv.split('# B2 outer request correlation', 1)[1].split('# Keep one correlation', 1)[0]
        self.assertIn('req.restarts == 0', block)
        self.assertIn('fastly.ff.visits_this_service == 0', block)
        self.assertIn('set req.http.X-Request-Id = uuid.version4();', block)
        self.assertNotIn('req.http.X-Divine-B2-Probe', block)

    def test_probe_has_versioned_log_manifest_entry(self):
        self.source()
        manifest = json.loads((ROOT / 'vcl/snippets.json').read_text())
        entries = [x for x in manifest['snippets'] if x['file'] == 'log_b2_probe.vcl']
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['type'], 'log')
        self.assertIsInstance(entries[0]['priority'], int)


if __name__ == '__main__':
    unittest.main()
