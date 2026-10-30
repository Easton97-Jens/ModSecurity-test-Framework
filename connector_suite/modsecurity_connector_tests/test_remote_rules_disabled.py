"""Regression checks for the common remote-rule deny policy.

This test is deliberately source-level: it proves that configuration rejection
and the host-specific directive handlers occur before any libmodsecurity remote
API call.  It does not make a network request.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import re
import unittest
from pathlib import Path


ROOT = connector_root()
POLICY_ERROR = "remote rule loading is disabled by security policy"


class RemoteRulesDisabledTest(unittest.TestCase):
    def test_common_config_and_loader_reject_both_remote_pair_shapes(self) -> None:
        config = (source_path('common/src/config.c', root=ROOT)).read_text(encoding="utf-8")
        loader = (source_path('common/src/rule_loader.c', root=ROOT)).read_text(encoding="utf-8")
        merge = (source_path('common/src/rule_merge.c', root=ROOT)).read_text(encoding="utf-8")

        self.assertIn('if (remote_pair_requested(config))', config)
        self.assertIn(POLICY_ERROR, config)
        self.assertIn('if (remote_pair_requested(config))', loader)
        self.assertIn(POLICY_ERROR, loader)
        self.assertIn('return fail_error(error, MSCONNECTOR_ERROR_UNSUPPORTED_CAPABILITY', loader)
        self.assertNotIn('backend.add_remote(loader->backend.userdata', loader)
        self.assertIn('remote_pair_requested(config->rules_remote_key, config->rules_remote_url)', merge)
        self.assertIn('remote_pair_requested(parent->rules_remote_key, parent->rules_remote_url)', merge)
        self.assertNotIn('remote_pair_complete(', merge)

    def test_common_runtime_has_no_remote_libmodsecurity_sink(self) -> None:
        runtime = (source_path('common/runtime/msconnector_runtime.c', root=ROOT)).read_text(
            encoding="utf-8"
        )

        self.assertIn(POLICY_ERROR, runtime)
        self.assertNotIn("msc_rules_add_remote", runtime)
        self.assertNotIn("rule_backend.add_remote", runtime)

    def test_apache_and_nginx_directives_fail_before_native_conversion(self) -> None:
        apache = (source_path('connectors/apache/src/msc_config.c', root=ROOT)).read_text(
            encoding="utf-8"
        )
        nginx = (
            source_path('connectors/nginx/src/ngx_http_modsecurity_module.c', root=ROOT)
        ).read_text(encoding="utf-8")

        self.assertIn(POLICY_ERROR, apache)
        self.assertIn(POLICY_ERROR, nginx)
        self.assertNotIn("msc_rules_add_remote", apache)
        self.assertNotIn("msc_rules_add_remote", nginx)
        remote_handler = re.search(
            r"ngx_conf_set_rules_remote\([^}]+\}", nginx, re.DOTALL
        )
        self.assertIsNotNone(remote_handler)
        remote_handler = remote_handler.group(0)
        self.assertNotIn("ngx_str_to_char(value[1]", remote_handler)

    def test_all_connector_capabilities_report_remote_rules_disabled(self) -> None:
        for connector in (
            "apache",
            "envoy",
            "haproxy",
            "lighttpd",
            "nginx",
            "traefik",
        ):
            capabilities = json.loads(
                (source_path('connectors', root=ROOT) / connector / "capabilities.json").read_text(
                    encoding="utf-8"
                )
            )
            remote = capabilities["capabilities"]["config_remote_rules"]
            self.assertEqual(remote["state"], "not_implemented", connector)
            self.assertIn("disabled by the common security policy", remote["reason"])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
