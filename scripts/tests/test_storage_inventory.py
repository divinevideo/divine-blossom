import importlib.util
from pathlib import Path
import unittest
import contextlib
import io
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("storage_inventory", Path(__file__).resolve().parents[1] / "storage_inventory.py")
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class InventoryTest(unittest.TestCase):
    def test_partial_provider_inventory_is_not_success(self):
        for missing in ["not_configured", "unavailable"]:
            data = {"b2": {"status": missing}, "bunny": {"status": "ok", "zones": []}}
            with patch.object(inventory, "collect_inventory", return_value=data), patch("sys.argv", ["storage_inventory.py"]), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(inventory.main(), 2)

    def test_requested_gcs_failure_is_not_success(self):
        data = {"b2": {"status": "ok"}, "bunny": {"status": "ok"}}
        with patch.object(inventory, "collect_inventory", return_value=data), patch("sys.argv", ["storage_inventory.py", "--gcs-bucket", "synthetic-bucket"]), patch.object(inventory.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout="")), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(inventory.main(), 2)

    def test_complete_inventory_succeeds(self):
        data = {"b2": {"status": "ok"}, "bunny": {"status": "ok"}}
        with patch.object(inventory, "collect_inventory", return_value=data), patch("sys.argv", ["storage_inventory.py"]), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(inventory.main(), 0)

    def test_cdn_inventory_never_returns_signing_keys_or_signed_query(self):
        zone = {"Id": 1, "Name": "synthetic", "OriginUrl": "https://user:secret@origin.invalid/private?signature=secret", "AWSSigningKey": "secret", "AWSSigningSecret": "secret", "Hostnames": [{"Value": "media.example", "Token": "secret"}], "AWSSigningEnabled": True, "AWSSigningRegionName": "test"}
        result = inventory.summarize_bunny_zone(zone)
        self.assertNotIn("secret", str(result))
        self.assertEqual(result["origin"], "https://origin.invalid/private")
        self.assertEqual(result["hostnames"], ["media.example"])

    def test_authorization_cannot_redirect_credentials_to_another_host(self):
        for url in ["http://api001.backblazeb2.com", "https://api001.backblazeb2.com.evil.invalid", "https://user@api001.backblazeb2.com", "https://api001.backblazeb2.com:444", "https://evil.invalid"]:
            with self.assertRaises(inventory.InventoryError):
                inventory.validate_b2_api_url(url)
        self.assertEqual(inventory.validate_b2_api_url("https://api001.backblazeb2.com"), "https://api001.backblazeb2.com")

    def test_no_ambient_aws_credentials_are_used(self):
        with patch.dict("os.environ", {"AWS_ACCESS_KEY_ID": "synthetic", "AWS_SECRET_ACCESS_KEY": "synthetic"}, clear=True):
            self.assertEqual(inventory.collect_inventory()["b2"]["status"], "not_configured")


if __name__ == "__main__":
    unittest.main()
