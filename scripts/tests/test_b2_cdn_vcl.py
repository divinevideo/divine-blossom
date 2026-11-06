"""Source contracts for B2 cache admission; runtime VCL validation is an operator gate."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class B2CdnVclContractTests(unittest.TestCase):
    def test_b2_paths_are_narrow_and_normalized_before_lookup(self):
        recv = (ROOT / "vcl/recv.vcl").read_text()
        self.assertIn("# B2 original delivery", recv)
        block = recv.split("# B2 original delivery", 1)[1]
        self.assertIn('^media-b2(-cdn)?[.]divine[.]video$', block)
        self.assertIn('^/[0-9a-f]{64}([.]mp4)?([?].*)?$', block)
        self.assertIn('set req.url = regsub(', block)
        self.assertIn('req.http.Cookie', recv)
        self.assertLess(recv.index('req.http.Authorization'), recv.index('set req.url = regsub('))
        self.assertNotIn('return(lookup)', recv)

    def test_b2_admission_precedes_generic_cache_and_disables_all_stale(self):
        fetch = (ROOT / "vcl/fetch.vcl").read_text()
        self.assertIn("# B2 original admission", fetch)
        block = fetch.split("# B2 original admission", 1)[1].split('# Origin owns', 1)[0]
        for source in ['beresp.status != 200', 'beresp.http.X-Divine-B2-CDN-Admission != "original-v1"', 'beresp.http.Surrogate-Key !=', 'beresp.http.Content-Range', 'beresp.http.Set-Cookie', 'return(pass)', 'set beresp.ttl = 365d;', 'set beresp.grace = 0s;', 'set beresp.stale_while_revalidate = 0s;', 'set beresp.stale_if_error = 0s;']:
            self.assertIn(source, block)
        self.assertIn('return(deliver)', block)
        # Canonical GCS still has its existing cache/stale policy.
        self.assertIn('set beresp.grace = 24h;', fetch)

    def test_b2_outer_ids_are_fresh_at_client_ingress_and_preserved_to_shield(self):
        recv = (ROOT / "vcl/recv.vcl").read_text()
        self.assertIn('# B2 outer request correlation', recv)
        block = recv.split('# B2 outer request correlation', 1)[1].split('# Keep one correlation', 1)[0]
        self.assertIn('fastly.ff.visits_this_service == 0', block)
        self.assertIn('set req.http.X-Request-Id = uuid.version4();', block)
        self.assertNotIn('if (!req.http.X-Request-Id)', block)
        deliver = (ROOT / "vcl/deliver.vcl").read_text()
        self.assertIn('unset resp.http.X-Playback-Load-Id;', deliver)

    def test_admission_marker_crosses_shield_but_cached_request_ids_do_not_escape(self):
        deliver = (ROOT / "vcl/deliver.vcl").read_text()
        self.assertIn("# B2 client delivery", deliver)
        block = deliver.split('# B2 client delivery', 1)[1].split('# Add cache debug', 1)[0]
        self.assertIn('fastly.ff.visits_this_service == 0', block)
        self.assertIn('unset resp.http.X-Divine-B2-CDN-Admission;', block)
        self.assertIn('unset resp.http.X-Playback-Request-Id;', block)
        self.assertIn('set resp.http.X-Request-Id = req.http.X-Divine-Edge-Request-Id;', block)
        self.assertIn('unset resp.http.X-Divine-Source;', block)
        self.assertIn('unset resp.http.X-Divine-Storage-Cache;', block)


if __name__ == '__main__':
    unittest.main()
