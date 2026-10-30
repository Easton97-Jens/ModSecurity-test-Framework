from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import unittest
from pathlib import Path


CONFIG = (
    source_path('connectors/traefik')
    / "config"
    / "traefik-forwardauth-composite-dynamic.yaml"
)


class CompositeConfigTests(unittest.TestCase):
    def test_private_lease_is_not_copied_from_forwardauth_response(self):
        text = CONFIG.read_text(encoding="utf-8")
        self.assertNotIn("authResponseHeaders", text)
        self.assertIn("authRequestHeaders:", text)
        self.assertIn("- X-Msconnector-Composite-Lease", text)
        self.assertNotIn("- X-Msconnector-Composite-Request-Context", text)

    def test_lease_is_stripped_after_forwardauth_before_upstream(self):
        text = CONFIG.read_text(encoding="utf-8")
        chain = [
            "- modsecurity-composite",
            "- modsecurity-composite-forwardauth",
            "- modsecurity-composite-strip-internal-lease",
        ]
        offsets = [text.index(item) for item in chain]
        self.assertEqual(offsets, sorted(offsets))
        strip_start = text.index("modsecurity-composite-strip-internal-lease:")
        self.assertIn("X-Msconnector-Composite-Lease: \"\"", text[strip_start:])
        self.assertIn("X-Msconnector-Composite-Request-Context: \"\"", text[strip_start:])

    def test_upstream_uses_verifying_loopback_tls_transport(self):
        text = CONFIG.read_text(encoding="utf-8")
        self.assertIn("- url: https://__UPSTREAM_ADDRESS__", text)
        self.assertIn("serversTransport: composite-upstream-transport", text)
        self.assertIn("serverName: composite-upstream.local", text)
        self.assertIn("rootCAs:", text)
        self.assertIn("__UPSTREAM_CERTIFICATE__", text)
        self.assertNotIn("insecureSkipVerify", text)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
