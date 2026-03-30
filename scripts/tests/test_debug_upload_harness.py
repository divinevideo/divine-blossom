import base64
import io
import json
from pathlib import Path
import unittest
import urllib.error

from scripts.debug_upload_harness import (
    UploadHttpClient,
    build_complete_body,
    build_proof_headers,
    chunk_ranges,
    load_proof_json,
    normalize_server_url,
    should_use_resumable,
    summarize_request_body,
    summarize_response,
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
            "pgpSignature": "sig",
            "deviceAttestation": "att",
            "c2paManifestId": "urn:c2pa:manifest",
        }
        headers = build_proof_headers(proof)
        self.assertEqual(
            headers["X-ProofMode-Manifest"],
            base64.b64encode(
                json.dumps(proof, separators=(",", ":")).encode("utf-8")
            ).decode("ascii"),
        )
        self.assertEqual(
            headers["X-ProofMode-Signature"],
            base64.b64encode(b"sig").decode("ascii"),
        )
        self.assertEqual(
            headers["X-ProofMode-Attestation"],
            base64.b64encode(b"att").decode("ascii"),
        )
        self.assertEqual(
            headers["X-ProofMode-C2PA"],
            base64.b64encode(b"urn:c2pa:manifest").decode("ascii"),
        )

    def test_summarize_response_truncates_large_bodies(self) -> None:
        summary = summarize_response(
            method="POST",
            url="https://media.divine.video/upload/init",
            status=500,
            headers={"content-type": "application/json"},
            body=b'{"error":"' + b"x" * 400 + b'"}',
        )
        self.assertIn("500", summary)
        self.assertIn("content-type", summary)
        self.assertIn("...", summary)

    def test_should_use_resumable_only_when_requested(self) -> None:
        self.assertTrue(should_use_resumable(mode="resumable"))
        self.assertFalse(should_use_resumable(mode="legacy"))

    def test_load_proof_json_accepts_mobile_style_manifest(self) -> None:
        fixture_path = (
            Path(__file__).resolve().parent / "fixtures" / "proofmode.json"
        )
        proof = load_proof_json(fixture_path)
        self.assertEqual(proof["deviceAttestation"], {"nonce": "abc123"})
        self.assertEqual(proof["pgpSignature"], "proof-signature")

    def test_summarize_request_body_hashes_binary_payloads(self) -> None:
        summary = summarize_request_body(
            body=b"\x00\x01\x02\x03",
            headers={"Content-Type": "application/octet-stream"},
        )
        self.assertIn("bytes=4", summary)
        self.assertIn("sha256=", summary)
        self.assertNotIn("\\x00", summary)

    def test_upload_http_client_captures_http_error_response(self) -> None:
        transcript = io.StringIO()

        def fake_opener(request, timeout=0):  # type: ignore[no-untyped-def]
            raise urllib.error.HTTPError(
                request.full_url,
                500,
                "boom",
                {"content-type": "application/json"},
                io.BytesIO(b'{"error":"boom"}'),
            )

        client = UploadHttpClient(opener=fake_opener, output_stream=transcript)
        exchange = client.request(
            "POST",
            "https://media.divine.video/upload/init",
            headers={"Content-Type": "application/json"},
            body=b"{}",
        )

        self.assertEqual(exchange.status, 500)
        self.assertEqual(exchange.response_body, b'{"error":"boom"}')
        self.assertIn("status: 500", transcript.getvalue())
