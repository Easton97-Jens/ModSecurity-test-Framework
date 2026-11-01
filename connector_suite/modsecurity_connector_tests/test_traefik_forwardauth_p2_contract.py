from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import unittest
from pathlib import Path


ROOT = connector_root()
RUNNER = load_source(source_path('connectors/traefik/scripts/runtime_smoke.py', root=ROOT))


class TraefikForwardAuthP2ContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dynamic = RUNNER.dynamic_config(
            18081, 18082, Path("/run/modsecurity/traefik-forwardauth-companion.sock")
        )
        self.service = (
            source_path('connectors/traefik/config/traefik-forwardauth.conf', root=ROOT)
        ).read_text(encoding="utf-8")

    def test_checked_in_pair_keeps_disclosed_host_body_cap(self) -> None:
        RUNNER.validate_forwardauth_p2_contract(self.dynamic)
        self.assertRegex(self.dynamic, r"(?m)^        forwardBody: true$")
        self.assertRegex(self.dynamic, r"(?m)^        maxBodySize: 4096$")
        self.assertRegex(self.service, r"(?m)^request_body_mode=buffered$")
        self.assertNotRegex(self.service, r"(?m)^(request_body_limit|response_body_limit|body_limit_action)=")

    def test_post_body_fixture_and_oversize_case_are_explicitly_modelled(self) -> None:
        """Source-contract coverage; a Traefik binary is required for host evidence."""

        post_body = b"traefik-forwardauth-p2-body-marker"
        oversized_body = b"x" * (RUNNER.FORWARDAUTH_P2_BODY_LIMIT + 1)
        self.assertLessEqual(len(post_body), RUNNER.FORWARDAUTH_P2_BODY_LIMIT)
        self.assertGreater(len(oversized_body), RUNNER.FORWARDAUTH_P2_BODY_LIMIT)
        self.assertIn("forwardBody: true", self.dynamic)
        self.assertIn("maxBodySize: 4096", self.dynamic)
        self.assertNotIn("request_body_limit=", self.service)

    def test_missing_forward_body_is_rejected(self) -> None:
        missing_forward_body = self.dynamic.replace("        forwardBody: true\n", "")
        with self.assertRaisesRegex(RuntimeError, "forwardBody"):
            RUNNER.validate_forwardauth_p2_contract(missing_forward_body)

    def test_oversized_host_limit_is_rejected(self) -> None:
        oversized = self.dynamic.replace("        maxBodySize: 4096", "        maxBodySize: 4097")
        with self.assertRaisesRegex(RuntimeError, "maxBodySize must equal 4096"):
            RUNNER.validate_forwardauth_p2_contract(oversized)

    def test_host_validator_adds_no_native_engine_body_policy(self) -> None:
        # The host contract checks forwarding and its disclosed full-body cap.
        # Native limit/action live in rules_file, independently of this helper.
        for mode in ("buffered", "streaming"):
            service = self.service.replace("request_body_mode=buffered", f"request_body_mode={mode}")
            self.assertIn(f"request_body_mode={mode}", service)
            RUNNER.validate_forwardauth_p2_contract(self.dynamic)
        source = (source_path('connectors/traefik/scripts/runtime_smoke.py', root=ROOT)).read_text(encoding="utf-8")
        self.assertNotIn("request_body_limit=", source)
        self.assertNotIn("body_limit_action=", source)
        self.assertRegex(self.service, r"(?m)^rules_file=.+$")

    def test_body_headers_are_auth_request_only_and_not_response_or_upstream_headers(self) -> None:
        auth_request, auth_response = self.dynamic.split("        authResponseHeaders:", 1)
        self.assertIn("- Content-Type", auth_request)
        self.assertIn("- Content-Length", auth_request)
        self.assertNotIn("- Content-Type", auth_response)
        self.assertNotIn("- Content-Length", auth_response)
        self.assertNotIn("request_body", auth_response)
        self.assertNotIn("body_marker", auth_response)

    def test_original_method_and_untrusted_forwarding_are_explicit(self) -> None:
        for text in (self.dynamic,
                     (source_path('connectors/traefik/config/traefik-forwardauth-dynamic.yaml', root=ROOT)).read_text(),
                     (source_path('connectors/traefik/config/traefik-forwardauth-composite-dynamic.yaml', root=ROOT)).read_text()):
            with self.subTest(text=text[:80]):
                self.assertRegex(text, r"(?m)^        preserveRequestMethod: true$")
                self.assertRegex(text, r"(?m)^        trustForwardHeader: false$")

    def test_omitted_or_disabled_method_preservation_is_rejected(self) -> None:
        for changed in (self.dynamic.replace("        preserveRequestMethod: true\n", ""),
                        self.dynamic.replace("preserveRequestMethod: true", "preserveRequestMethod: false")):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(RuntimeError, "preserveRequestMethod"):
                    RUNNER.validate_forwardauth_p2_contract(changed)

    def test_untrusted_forwarding_cannot_be_enabled_or_omitted(self) -> None:
        for changed in (self.dynamic.replace("        trustForwardHeader: false\n", ""),
                        self.dynamic.replace("trustForwardHeader: false", "trustForwardHeader: true")):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(RuntimeError, "trustForwardHeader"):
                    RUNNER.validate_forwardauth_p2_contract(changed)

    def test_duplicate_method_setting_is_rejected(self) -> None:
        duplicate = self.dynamic.replace("        preserveRequestMethod: true\n",
                                         "        preserveRequestMethod: true\n        preserveRequestMethod: false\n")
        with self.assertRaisesRegex(RuntimeError, "preserveRequestMethod"):
            RUNNER.validate_forwardauth_p2_contract(duplicate)

    def test_duplicate_forwarding_setting_is_rejected(self) -> None:
        duplicate = self.dynamic.replace("        trustForwardHeader: false\n",
                                         "        trustForwardHeader: false\n        trustForwardHeader: true\n")
        with self.assertRaisesRegex(RuntimeError, "trustForwardHeader"):
            RUNNER.validate_forwardauth_p2_contract(duplicate)

    def test_start_smoke_has_fail_closed_p2_guards(self) -> None:
        script = (source_path('connectors/traefik/scripts/start-smoke.sh', root=ROOT)).read_text(
            encoding="utf-8"
        )
        self.assertIn("forwardAuth P2 requires forwardBody=true and maxBodySize=4096", script)
        self.assertIn("4096-byte host limitation", script)
        self.assertIn("forwardAuth requires preserveRequestMethod=true and trustForwardHeader=false", script)
        self.assertNotIn("request_body_limit=", script)
        self.assertNotIn("body_limit_action=", script)
        self.assertIn("--check-config", script)
        self.assertIn("exit 77", script)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
