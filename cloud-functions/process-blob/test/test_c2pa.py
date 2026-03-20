#!/usr/bin/env python3
"""
Tests for C2PA trust checking in process-blob.

Exercises the c2patool integration, trust chain validation, file size guard,
and the Flask endpoint — all without requiring GCS or Vision API credentials.

Usage:
    source test/blossom/bin/activate
    pip install flask requests pytest
    python test/test_c2pa.py

    # or with pytest for nicer output:
    pytest test/test_c2pa.py -v
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Set C2PA env vars BEFORE importing main (module reads them at import time)
TRUST_ANCHORS_PATH = os.path.join(
    os.path.dirname(__file__), '..', 'trust_anchors.pem'
)
os.environ['C2PA_MODE'] = 'log'
os.environ['C2PA_TRUST_ANCHORS'] = os.path.abspath(TRUST_ANCHORS_PATH)
os.environ['C2PA_CHECK_IMAGES'] = 'true'
os.environ['C2PA_MAX_FILE_SIZE'] = str(100 * 1024 * 1024)   # 100MB for tests
os.environ['C2PA_WARN_FILE_SIZE'] = str(10 * 1024 * 1024)   # 10MB for tests

# Mock GCP clients before importing main so it doesn't fail on missing credentials
sys.modules['google.cloud'] = MagicMock()
sys.modules['google.cloud.storage'] = MagicMock()
sys.modules['google.cloud.vision'] = MagicMock()
sys.modules['google.cloud.vision_v1'] = MagicMock()
sys.modules['google.cloud.vision_v1.types'] = MagicMock()
sys.modules['google.cloud.videointelligence'] = MagicMock()

# Add parent dir to path so we can import main
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import main


def c2patool_available():
    """Check if c2patool is installed."""
    return shutil.which('c2patool') is not None


def create_test_image(path):
    """Create a minimal valid JPEG file (no C2PA manifest)."""
    # Smallest valid JPEG: SOI + APP0 + minimal scan + EOI
    jpeg_bytes = bytes([
        0xFF, 0xD8,                         # SOI
        0xFF, 0xE0,                         # APP0 marker
        0x00, 0x10,                         # length 16
        0x4A, 0x46, 0x49, 0x46, 0x00,       # JFIF\0
        0x01, 0x01,                         # version 1.1
        0x00,                               # aspect ratio units
        0x00, 0x01, 0x00, 0x01,             # 1x1 pixel density
        0x00, 0x00,                         # no thumbnail
        0xFF, 0xC0,                         # SOF0 marker
        0x00, 0x0B,                         # length 11
        0x08,                               # 8-bit precision
        0x00, 0x01, 0x00, 0x01,             # 1x1 pixels
        0x01,                               # 1 component
        0x01, 0x11, 0x00,                   # component 1: 1x1 sampling, quant table 0
        0xFF, 0xC4,                         # DHT marker
        0x00, 0x1F,                         # length 31
        0x00,                               # DC table 0
        0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0xFF, 0xDA,                         # SOS marker
        0x00, 0x08,                         # length 8
        0x01,                               # 1 component
        0x01, 0x00,                         # component 1, DC/AC table 0/0
        0x00, 0x3F, 0x00,                   # spectral selection
        0x7B,                               # scan data (one byte)
        0xFF, 0xD9,                         # EOI
    ])
    with open(path, 'wb') as f:
        f.write(jpeg_bytes)


@unittest.skipUnless(c2patool_available(), "c2patool not installed")
class TestC2PAToolDirect(unittest.TestCase):
    """Test the low-level c2patool wrapper functions against real files."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='c2pa_test_')
        self.plain_jpg = os.path.join(self.tmpdir, 'plain.jpg')
        create_test_image(self.plain_jpg)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_read_no_manifest(self):
        """A plain JPEG with no C2PA manifest should return None."""
        result = main._run_c2patool_read(self.plain_jpg)
        self.assertIsNone(result)

    def test_read_nonexistent_file(self):
        """A nonexistent file should return None, not crash."""
        result = main._run_c2patool_read('/tmp/does_not_exist_xyz.jpg')
        self.assertIsNone(result)

    def test_trust_no_manifest(self):
        """Trust check on a file with no manifest should return False."""
        result = main._run_c2patool_trust(self.plain_jpg)
        self.assertFalse(result)


@unittest.skipUnless(c2patool_available(), "c2patool not installed")
class TestC2PAToolSigned(unittest.TestCase):
    """Test c2patool functions against a self-signed C2PA image."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='c2pa_test_signed_')
        self.plain_jpg = os.path.join(self.tmpdir, 'plain.jpg')
        self.signed_jpg = os.path.join(self.tmpdir, 'signed.jpg')
        create_test_image(self.plain_jpg)

        # Create a C2PA-signed image using c2patool
        manifest_json = {
            "claim_generator": "test_c2pa/1.0",
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {"action": "c2pa.created"}
                        ]
                    }
                }
            ]
        }
        self.manifest_path = os.path.join(self.tmpdir, 'manifest.json')
        with open(self.manifest_path, 'w') as f:
            json.dump(manifest_json, f)

        proc = subprocess.run(
            ['c2patool', self.plain_jpg, '--manifest', self.manifest_path,
             '--output', self.signed_jpg, '--force'],
            capture_output=True, text=True
        )
        self.has_signed = proc.returncode == 0 and os.path.exists(self.signed_jpg)
        if not self.has_signed:
            print(f"c2patool sign failed: {proc.stderr}", file=sys.stderr)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_read_has_manifest(self):
        """A c2patool-signed JPEG should return a manifest dict."""
        if not self.has_signed:
            self.skipTest("c2patool failed to sign test image")
        result = main._run_c2patool_read(self.signed_jpg)
        self.assertIsNotNone(result)
        self.assertIn('manifests', result)

    def test_extract_claim_generator(self):
        """Should extract claim_generator from the manifest."""
        if not self.has_signed:
            self.skipTest("c2patool failed to sign test image")
        manifest = main._run_c2patool_read(self.signed_jpg)
        cg = main._extract_claim_generator(manifest)
        self.assertIsNotNone(cg)
        # c2patool signs with its own c2pa-rs identity, overriding our manifest json
        self.assertIn('c2pa', cg.lower())

    def test_extract_issuer(self):
        """Should extract some issuer info from the manifest."""
        if not self.has_signed:
            self.skipTest("c2patool failed to sign test image")
        manifest = main._run_c2patool_read(self.signed_jpg)
        issuer = main._extract_issuer(manifest)
        # c2patool self-signs with its own cert, so issuer should be non-None
        self.assertIsNotNone(issuer)

    def test_trust_self_signed_untrusted(self):
        """A self-signed image should NOT be trusted against our trust anchors."""
        if not self.has_signed:
            self.skipTest("c2patool failed to sign test image")
        result = main._run_c2patool_trust(self.signed_jpg)
        # Self-signed cert is not in trust_anchors.pem, so should be untrusted
        self.assertFalse(result)


class TestFileSizeGuard(unittest.TestCase):
    """Test the file size guard logic in check_c2pa_trust."""

    def _make_mock_blob(self, size, content_type='image/jpeg'):
        mock_blob = MagicMock()
        mock_blob.size = size
        mock_blob.content_type = content_type
        mock_blob.reload = MagicMock()
        mock_blob.download_to_filename = MagicMock()
        return mock_blob

    @patch.object(main.storage, 'Client')
    def test_skip_oversized_file(self, mock_storage_cls):
        """Files above C2PA_MAX_FILE_SIZE should be skipped."""
        mock_blob = self._make_mock_blob(200 * 1024 * 1024)  # 200MB > 100MB limit
        mock_bucket = MagicMock()
        mock_bucket.blob.return_value = mock_blob
        mock_storage_cls.return_value.bucket.return_value = mock_bucket

        result = main.check_c2pa_trust('test-bucket', 'big-video.mp4')

        self.assertFalse(result['has_manifest'])
        self.assertFalse(result['is_trusted'])
        self.assertTrue(any('too large' in e for e in result['errors']))
        mock_blob.download_to_filename.assert_not_called()

    @patch.object(main.storage, 'Client')
    def test_warn_large_file(self, mock_storage_cls):
        """Files above C2PA_WARN_FILE_SIZE but below max should still proceed."""
        mock_blob = self._make_mock_blob(50 * 1024 * 1024)  # 50MB > 10MB warn
        mock_bucket = MagicMock()
        mock_bucket.blob.return_value = mock_blob
        mock_storage_cls.return_value.bucket.return_value = mock_bucket

        # It will proceed to download and then c2patool read will find no manifest
        result = main.check_c2pa_trust('test-bucket', 'medium-video.mp4')

        # Should have attempted the download (not skipped)
        mock_blob.download_to_filename.assert_called_once()

    @patch.object(main.storage, 'Client')
    def test_small_file_no_warning(self, mock_storage_cls):
        """Files below warn threshold should proceed normally."""
        mock_blob = self._make_mock_blob(1024)  # 1KB
        mock_bucket = MagicMock()
        mock_bucket.blob.return_value = mock_blob
        mock_storage_cls.return_value.bucket.return_value = mock_bucket

        result = main.check_c2pa_trust('test-bucket', 'small.jpg')
        mock_blob.download_to_filename.assert_called_once()


class TestExtractHelpers(unittest.TestCase):
    """Test manifest parsing helpers with synthetic data."""

    def test_extract_claim_generator_from_manifests(self):
        manifest = {
            'manifests': {
                'urn:c2pa:test': {
                    'claim_generator': 'ProofMode/1.0'
                }
            }
        }
        self.assertEqual(main._extract_claim_generator(manifest), 'ProofMode/1.0')

    def test_extract_claim_generator_empty(self):
        self.assertIsNone(main._extract_claim_generator({'manifests': {}}))
        self.assertIsNone(main._extract_claim_generator({}))

    def test_extract_issuer_from_signature_info(self):
        manifest = {
            'manifests': {
                'urn:c2pa:test': {
                    'signature_info': {
                        'issuer': 'CN=ProofSign Root CA'
                    }
                }
            }
        }
        self.assertEqual(main._extract_issuer(manifest), 'CN=ProofSign Root CA')

    def test_extract_issuer_cert_serial_fallback(self):
        manifest = {
            'manifests': {
                'urn:c2pa:test': {
                    'signature_info': {
                        'cert_serial_number': 'ABCD1234'
                    }
                }
            }
        }
        self.assertEqual(main._extract_issuer(manifest), 'cert:ABCD1234')

    def test_extract_issuer_empty(self):
        self.assertIsNone(main._extract_issuer({'manifests': {}}))

    def test_extract_digital_source_type(self):
        manifest = {
            'manifests': {
                'urn:c2pa:test': {
                    'assertion_store': {
                        'c2pa.actions.v2': {
                            'actions': [{
                                'action': 'c2pa.created',
                                'digitalSourceType': 'http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture'
                            }]
                        }
                    }
                }
            }
        }
        self.assertEqual(
            main._extract_digital_source_type(manifest),
            'http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture'
        )

    def test_extract_digital_source_type_v1_key(self):
        manifest = {
            'manifests': {
                'urn:c2pa:test': {
                    'assertion_store': {
                        'c2pa.actions': {
                            'actions': [{
                                'action': 'c2pa.created',
                                'digitalSourceType': 'http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia'
                            }]
                        }
                    }
                }
            }
        }
        self.assertEqual(
            main._extract_digital_source_type(manifest),
            'http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia'
        )

    def test_extract_digital_source_type_missing(self):
        manifest = {
            'manifests': {
                'urn:c2pa:test': {
                    'assertion_store': {
                        'c2pa.actions.v2': {
                            'actions': [{'action': 'c2pa.created'}]
                        }
                    }
                }
            }
        }
        self.assertIsNone(main._extract_digital_source_type(manifest))

    def test_extract_digital_source_type_no_actions(self):
        self.assertIsNone(main._extract_digital_source_type({'manifests': {}}))


class TestFlaskEndpoint(unittest.TestCase):
    """Test the Cloud Run HTTP endpoint with mocked GCS/Vision."""

    def setUp(self):
        self.client = main.app.test_client()

    def test_missing_payload(self):
        resp = self.client.post('/', content_type='application/json')
        self.assertEqual(resp.status_code, 400)

    def test_missing_bucket(self):
        resp = self.client.post(
            '/',
            data=json.dumps({'data': {'name': 'test.jpg'}}),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 400)

    def test_skips_derivatives(self):
        resp = self.client.post(
            '/',
            data=json.dumps({
                'data': {
                    'bucket': 'test-bucket',
                    'name': f'{"c" * 64}.jpg',
                    'contentType': 'image/jpeg'
                }
            }),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 200)

    def test_skips_hls(self):
        resp = self.client.post(
            '/',
            data=json.dumps({
                'data': {
                    'bucket': 'test-bucket',
                    'name': f'{"d" * 64}/hls/stream_720p.m3u8',
                    'contentType': 'application/x-mpegURL'
                }
            }),
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, 200)


class TestDerivativeFiltering(unittest.TestCase):
    """Test filtering for real derivative object paths produced by the app."""

    def test_skips_real_hls_variant_playlist(self):
        blob_name = f'{"a" * 64}/hls/stream_720p.m3u8'

        with patch.object(main, 'check_image_safety') as check_image_safety, \
             patch.object(main, 'extract_video_thumbnail') as extract_video_thumbnail, \
             patch.object(main, 'update_metadata') as update_metadata:
            main.process_blob_event('test-bucket', blob_name, 'application/vnd.apple.mpegurl')

        check_image_safety.assert_not_called()
        extract_video_thumbnail.assert_not_called()
        update_metadata.assert_not_called()

    def test_skips_real_hls_segment(self):
        blob_name = f'{"b" * 64}/hls/stream_720p.ts'

        with patch.object(main, 'check_image_safety') as check_image_safety, \
             patch.object(main, 'extract_video_thumbnail') as extract_video_thumbnail, \
             patch.object(main, 'update_metadata') as update_metadata:
            main.process_blob_event('test-bucket', blob_name, 'video/mp2t')

        check_image_safety.assert_not_called()
        extract_video_thumbnail.assert_not_called()
        update_metadata.assert_not_called()


class TestSuffixForBlob(unittest.TestCase):
    """Test file suffix detection."""

    def _blob(self, content_type):
        b = MagicMock()
        b.content_type = content_type
        return b

    def test_mp4(self):
        self.assertEqual(main._suffix_for_blob('vid.mp4', self._blob('video/mp4')), '.mp4')

    def test_jpeg(self):
        self.assertEqual(main._suffix_for_blob('img.jpg', self._blob('image/jpeg')), '.jpg')

    def test_unknown_content_type_uses_extension(self):
        self.assertEqual(main._suffix_for_blob('file.webm', self._blob('video/webm')), '.webm')

    def test_no_extension_defaults_mp4(self):
        self.assertEqual(main._suffix_for_blob('abc123', self._blob('')), '.mp4')


SAMPLES_DIR = os.path.join(os.path.dirname(__file__), '..', 'samples')


@unittest.skipUnless(c2patool_available(), "c2patool not installed")
@unittest.skipUnless(
    os.path.isdir(os.path.join(os.path.dirname(__file__), '..', 'samples')),
    "samples/ directory not found"
)
class TestSampleFiles(unittest.TestCase):
    """Test c2patool functions against real sample files in samples/."""

    def _sample(self, name):
        return os.path.join(SAMPLES_DIR, name)

    def test_signed_sample_has_manifest(self):
        """A ProofMode-signed MP4 should have a C2PA manifest."""
        path = self._sample(
            '51dd154c7b7f4f59ca12b4d496b3d8a8eca61f3d03de6093cd0395ba53b14060.mp4'
        )
        if not os.path.exists(path):
            self.skipTest(f"sample not found: {path}")
        result = main._run_c2patool_read(path)
        self.assertIsNotNone(result, "Expected C2PA manifest in signed sample")
        self.assertIn('manifests', result)

    def test_signed_sample_claim_generator(self):
        """Should extract a claim_generator from a signed sample."""
        path = self._sample(
            '6267d5d946c7c9c99d2aa3be02403f837f844b321540ec7b6f0ab0038a90b11b.mp4'
        )
        if not os.path.exists(path):
            self.skipTest(f"sample not found: {path}")
        manifest = main._run_c2patool_read(path)
        self.assertIsNotNone(manifest)
        cg = main._extract_claim_generator(manifest)
        self.assertIsNotNone(cg, "Expected non-None claim_generator")
        print(f"  claim_generator: {cg}")

    def test_signed_sample_issuer(self):
        """Should extract issuer info from a signed sample."""
        path = self._sample(
            '8011c09d88d78017ff2c8da7e25c00c5620048f93adbf08e0097bffbb29edc85.mp4'
        )
        if not os.path.exists(path):
            self.skipTest(f"sample not found: {path}")
        manifest = main._run_c2patool_read(path)
        self.assertIsNotNone(manifest)
        issuer = main._extract_issuer(manifest)
        self.assertIsNotNone(issuer, "Expected non-None issuer")
        print(f"  issuer: {issuer}")

    def test_proofsign_sample_is_trusted(self):
        """A ProofSign CA-signed sample should be Trusted against trust_anchors.pem."""
        path = self._sample(
            '6267d5d946c7c9c99d2aa3be02403f837f844b321540ec7b6f0ab0038a90b11b.mp4'
        )
        if not os.path.exists(path):
            self.skipTest(f"sample not found: {path}")
        trusted = main._run_c2patool_trust(path)
        self.assertTrue(trusted, "ProofSign-signed sample should be Trusted")

    def test_self_signed_sample_is_not_trusted(self):
        """A self-signed sample should be Valid but NOT Trusted against trust_anchors.pem."""
        path = self._sample(
            '51dd154c7b7f4f59ca12b4d496b3d8a8eca61f3d03de6093cd0395ba53b14060.mp4'
        )
        if not os.path.exists(path):
            self.skipTest(f"sample not found: {path}")
        # This sample is signed with "DiVine App Proofmode Self-Signed" — not in trust_anchors.pem
        trusted = main._run_c2patool_trust(path)
        self.assertFalse(trusted, "Self-signed sample should NOT be Trusted")

    def test_corrupt_file_returns_none(self):
        """A corrupt MP4 should return None for manifest read."""
        path = self._sample('screen recording of ai generated video.mp4')
        if not os.path.exists(path):
            self.skipTest(f"sample not found: {path}")
        result = main._run_c2patool_read(path)
        self.assertIsNone(result, "Expected None for corrupt file")

    def test_signed_sample_is_digital_capture(self):
        """ProofMode samples should have digitalSourceType = digitalCapture."""
        path = self._sample(
            '51dd154c7b7f4f59ca12b4d496b3d8a8eca61f3d03de6093cd0395ba53b14060.mp4'
        )
        if not os.path.exists(path):
            self.skipTest(f"sample not found: {path}")
        manifest = main._run_c2patool_read(path)
        self.assertIsNotNone(manifest)
        dst = main._extract_digital_source_type(manifest)
        self.assertEqual(
            dst,
            'http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture',
            f"Expected digitalCapture, got {dst}"
        )

    def test_all_signed_samples_are_digital_capture(self):
        """All hash-named ProofMode samples should claim digitalCapture."""
        count = 0
        for fname in os.listdir(SAMPLES_DIR):
            if not fname.endswith('.mp4'):
                continue
            name_no_ext = fname.rsplit('.', 1)[0]
            if len(name_no_ext) == 64 and all(c in '0123456789abcdef' for c in name_no_ext):
                path = self._sample(fname)
                manifest = main._run_c2patool_read(path)
                self.assertIsNotNone(manifest, f"Expected manifest in {fname}")
                dst = main._extract_digital_source_type(manifest)
                self.assertEqual(
                    dst,
                    'http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture',
                    f"{fname}: expected digitalCapture, got {dst}"
                )
                count += 1
        self.assertGreater(count, 0)

    def test_all_signed_samples_have_manifests(self):
        """All hash-named MP4 samples should have C2PA manifests."""
        count = 0
        for fname in os.listdir(SAMPLES_DIR):
            if not fname.endswith('.mp4'):
                continue
            # Hash-named files (64-char hex) are the ProofMode-signed ones
            name_no_ext = fname.rsplit('.', 1)[0]
            if len(name_no_ext) == 64 and all(c in '0123456789abcdef' for c in name_no_ext):
                path = self._sample(fname)
                manifest = main._run_c2patool_read(path)
                self.assertIsNotNone(manifest, f"Expected manifest in {fname}")
                count += 1
        print(f"  Verified {count} signed samples")
        self.assertGreater(count, 0, "No hash-named samples found")


if __name__ == '__main__':
    unittest.main(verbosity=2)
