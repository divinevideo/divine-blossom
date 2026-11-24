import unittest
from unittest.mock import Mock

from deploy_bunny_blossom import configure_blossom_pull_zone, create_passthrough_zone


class PassthroughZoneTest(unittest.TestCase):
    def test_creates_unlinked_volume_zone_with_cache_disabled(self):
        client = self.client()

        zone = create_passthrough_zone(
            client, "media-test", "https://blossom-origin.example.net", "media.example.net"
        )

        self.assertEqual(zone["Id"], 42)
        method, path, config = client.req.call_args_list[0].args
        self.assertEqual((method, path), ("POST", "/pullzone"))
        self.assertEqual(config["Type"], 1)
        self.assertEqual(config["CacheControlMaxAgeOverride"], 0)
        self.assertFalse(config["OriginRetry5XXResponses"])
        self.assertFalse(config["UseStaleWhileUpdating"])
        self.assertTrue(config["VerifyOriginSSL"])
        self.assertNotIn("EdgeScriptId", config)
        self.assertNotIn("MiddlewareScriptId", config)
        self.assertEqual(
            [(rule["ActionType"], rule["ActionParameter1"], rule["ActionParameter2"])
             for rule in zone["EdgeRules"]],
            [(6, "X-Original-Host", "media.example.net"), (5, "Cache-Control", "private, no-store")],
        )

    def test_rejects_zone_if_bunny_ignores_cache_configuration(self):
        client = self.client(CacheControlMaxAgeOverride=-1)
        with self.assertRaisesRegex(RuntimeError, "did not retain"):
            create_passthrough_zone(
                client, "media-test", "https://blossom-origin.example.net", "media.example.net"
            )

    def test_rejects_canonical_host_as_origin_before_calling_bunny(self):
        client = Mock()
        with self.assertRaises(ValueError):
            create_passthrough_zone(
                client, "media-test", "https://media.example.net", "media.example.net"
            )
        client.req.assert_not_called()

    def test_links_middleware_as_a_hook_and_keeps_the_existing_origin(self):
        client = Mock()
        client.req.return_value = {"EdgeRules": []}

        configure_blossom_pull_zone(client, 42, middleware_script_id=17)

        method, path, config = client.req.call_args_list[0].args
        self.assertEqual((method, path), ("POST", "/pullzone/42"))
        self.assertEqual(config["MiddlewareScriptId"], 17)
        self.assertNotIn("EdgeScriptId", config)

    @staticmethod
    def client(**overrides):
        zone = {"Id": 42, "EdgeRules": []}

        def request(method, path, body=None):
            if method == "POST" and path == "/pullzone":
                zone.update(body)
                return {"Id": 42}
            if method == "POST" and path == "/pullzone/42/edgerules/addOrUpdate":
                zone["EdgeRules"].append(body)
                return None
            if method == "GET" and path == "/pullzone/42":
                return {**zone, **overrides}
            raise AssertionError((method, path))

        return Mock(req=Mock(side_effect=request))


if __name__ == "__main__":
    unittest.main()
