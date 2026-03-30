import unittest

from scripts.debug_upload_harness import (
    build_complete_body,
    build_proof_headers,
    chunk_ranges,
    normalize_server_url,
)


class DebugUploadHarnessTests(unittest.TestCase):
    def test_normalize_server_url_strips_trailing_slash(self) -> None:
        self.assertEqual(
            normalize_server_url("https://media.divine.video/"),
            "https://media.divine.video",
        )

    def test_chunk_ranges_cover_full_file(self) -> None:
        self.assertEqual(
            chunk_ranges(file_size=10, chunk_size=4),
            [(0, 4), (4, 8), (8, 10)],
        )

    def test_build_complete_body_includes_sha256(self) -> None:
        self.assertEqual(
            build_complete_body("ab" * 32),
            {"sha256": "ab" * 32},
        )

    def test_build_proof_headers_maps_expected_fields(self) -> None:
        proof = {
            "signature": "sig",
            "deviceAttestation": "att",
            "c2pa": {"manifest": "value"},
        }
        headers = build_proof_headers(proof)
        self.assertEqual(headers["X-ProofMode-Signature"], "sig")
        self.assertEqual(headers["X-ProofMode-Attestation"], "att")
        self.assertIn("X-ProofMode-C2PA", headers)
