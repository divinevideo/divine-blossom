import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("storage_inventory", Path(__file__).resolve().parents[1] / "storage_inventory.py")
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class InventoryTest(unittest.TestCase):
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
