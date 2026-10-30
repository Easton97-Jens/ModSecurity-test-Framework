from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import ast
import sys
import unittest
from pathlib import Path


ROOT = connector_root()
DOCUMENTATION_CHECKS = source_path('ci/checks/documentation', root=ROOT)


import modsecurity_connector_ci.checks.documentation.connector_config_reference as REFERENCE


class ConnectorConfigReferenceTests(unittest.TestCase):
    def test_retired_common_keys_are_rejections_instead_of_accepted_inventory(self) -> None:
        source = (source_path('common/runtime/msconnector_runtime.c', root=ROOT)).read_text(encoding="utf-8")
        self.assertNotIn("request_body_limit", REFERENCE.common_runtime_parser_keys(source))
        start = source.index('if (strcmp(key, "request_body_limit")')
        end = source.index("result = assign_boolean_config_value", start)
        rejection = source[start:end]
        for replacement in (
            rejection.replace("return 0;", "return 1;"),
            rejection.replace("was removed", "configured"),
        ):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(ValueError, "explicitly reject"):
                REFERENCE.common_runtime_parser_keys(source[:start] + replacement + source[end:])

    def test_common_runtime_limits_are_extracted_from_enforced_header_caps(self) -> None:
        limits = REFERENCE.common_runtime_limits(ROOT)
        self.assertEqual(
            limits,
            {
                "max_header_count": 256,
                "max_header_name_size": 256,
                "max_header_value_size": 8192,
                "max_total_header_bytes": 65536,
                "max_event_json_bytes": 16384,
            },
        )
        options = {
            option["name"]: option
            for option in REFERENCE.extract_common_runtime(ROOT)
        }
        self.assertEqual(options["max_header_count"]["allowed_values"], "1 through 256")
        self.assertIn(
            "values above the hard cap of 256",
            options["max_header_count"]["validation"],
        )

    def test_lighttpd_native_directive_inventory_is_closed_and_documents_opt_in_evidence(self) -> None:
        directives = {
            option["name"]: option
            for option in REFERENCE.extract_lighttpd(ROOT)
            if option["configuration_layer"] == "host_connector_directive"
        }

        self.assertSetEqual(
            set(directives),
            {
                "msconnector.enabled",
                "msconnector.config-file",
                "msconnector.expose-host-transaction-id",
                "msconnector.request-body-gate",
            },
        )
        evidence = directives["msconnector.expose-host-transaction-id"]
        self.assertEqual(evidence["default"], "off")
        self.assertEqual(
            evidence["syntax"],
            'msconnector.expose-host-transaction-id = "enable" | "disable"',
        )
        self.assertIn("server-generated", evidence["security_relevance"])
        self.assertIn("never reflects a request header", evidence["security_relevance"])
        request_gate = directives["msconnector.request-body-gate"]
        self.assertEqual(
            request_gate["syntax"],
            'msconnector.request-body-gate = "pre-upstream"',
        )
        self.assertIn("P2", request_gate["phase_relevance"])
        self.assertIn("pre-upstream", request_gate["security_relevance"])

    def test_apache_example_file_mapping_is_complete_and_stable(self) -> None:
        example_by_directive = {
            item["name"]: item["example_file"]
            for item in REFERENCE.extract_apache(ROOT)
        }
        source_directives = {
            "modsecurity_rules_remote",
        }
        source_example = "connectors/apache/src/msc_config.c"
        minimal_example = "examples/apache/off/httpd.conf"
        safe_example = "examples/apache/safe/httpd.conf"
        minimal_directives = {
            "modsecurity",
            "modsecurity_rules_file",
            "modsecurity_use_error_log",
        }

        self.assertTrue(
            all(example_by_directive[directive] == source_example for directive in source_directives)
        )
        self.assertSetEqual(
            {
                directive
                for directive, example_file in example_by_directive.items()
                if example_file == minimal_example
            },
            minimal_directives,
        )
        safe_directives = set(example_by_directive) - minimal_directives - source_directives
        self.assertTrue(safe_directives)
        self.assertTrue(
            all(example_by_directive[directive] == safe_example for directive in safe_directives)
        )

    def test_haproxy_spop_limits_match_runtime_contract(self) -> None:
        options = {
            option["name"].split(":", 1)[1]: option
            for option in REFERENCE.extract_haproxy(ROOT)
            if option["name"].startswith("spoe-agent:")
        }
        self.assertEqual(options["worker-count"]["default"], "8")
        self.assertEqual(
            options["worker-count"]["allowed_values"],
            "decimal integer, 2..64; worker-count * max-transactions <= 65536",
        )
        self.assertEqual(
            options["max-transactions"]["allowed_values"],
            "decimal integer, 1..4096; worker-count * max-transactions <= 65536",
        )
        self.assertEqual(options["spoe-timeout"]["allowed_values"], "positive decimal milliseconds, 1..60000")
        self.assertEqual(
            options["response-body-timeout"]["allowed_values"],
            "unsigned decimal milliseconds, 0..60000; must be 0 with response-companion=none",
        )
        self.assertIn(
            "in 0..60000 and must be 0 with response-companion=none",
            options["response-body-timeout"]["validation"],
        )
        self.assertIn("unknown keys and malformed values", options["max-transactions"]["validation"])

        german = REFERENCE._german_option(options["worker-count"])
        self.assertIn("dezimale Ganzzahl", german["allowed_values"])
        self.assertIn("worker-count akzeptiert 2..64", REFERENCE._german_option(options["worker-count"])["validation"])

    def test_generator_preserves_disabled_remote_and_secure_nginx_file_contracts(self) -> None:
        # Header and event bounds remain source-backed independently of body
        # inspection policy, which belongs to the engine.
        self.assertIsNone(REFERENCE._assert_common_source_defaults(ROOT))
        apache = {item["name"]: item for item in REFERENCE.extract_apache(ROOT)}
        nginx = {item["name"]: item for item in REFERENCE.extract_nginx(ROOT)}
        common = {
            item["name"]: item
            for item in REFERENCE.extract_common_runtime(ROOT)
        }

        for option in (
            apache["modsecurity_rules_remote"],
            nginx["modsecurity_rules_remote"],
            common["rules_remote_key"],
            common["rules_remote_url"],
        ):
            self.assertTrue(option["example_unavailable"])
            self.assertIn("no", option["allowed_values"])
            self.assertIn("reject", option["validation"])

        phase4_log = nginx["modsecurity_phase4_log"]
        self.assertNotIn("example_unavailable", phase4_log)
        self.assertTrue(phase4_log["implemented"])
        self.assertIn("no-follow", phase4_log["validation"])
        self.assertIn("regular file", phase4_log["validation"])
        self.assertIn("0600", phase4_log["validation"])
        self.assertIn("configuration reload", phase4_log["validation"])
        self.assertIn("USR1", phase4_log["security_relevance"])

        self.assertNotIn("modsecurity_phase4_content_types_file", nginx)

        self.assertEqual(common["max_event_json_bytes"]["allowed_values"], "1 through 16384 bytes")
        self.assertNotIn("request_body_limit", common)
        self.assertNotIn("body_limit_action", common)
        self.assertIn("65536", common["max_total_header_bytes"]["allowed_values"])

    def test_german_translation_literal_keys_are_unique(self) -> None:
        source = DOCUMENTATION_CHECKS / "connector_config_reference.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        assignment = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "GERMAN_TEXT"
        )
        self.assertIsInstance(assignment.value, ast.Dict)
        literal_keys = [
            key.value
            for key in assignment.value.keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        ]
        self.assertCountEqual(literal_keys, set(literal_keys))

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
