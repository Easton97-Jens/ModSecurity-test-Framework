"""Regression guards for the off/safe/strict Phase-4 migration.

These are source/configuration contracts, not native-host runtime evidence.
The expected modes and MIME ownership come from the migration requirements.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import re
import unittest

from modsecurity_connector_tests.c_source_contract import function_definition


ROOT = connector_root()
WORKFLOWS = (
    "lint.yml",
    "test-nginx.yml",
    "test-apache.yml",
    "test-common.yml",
    "quick-framework-check.yml",
)


class Phase4MigrationContractTests(unittest.TestCase):
    def test_common_default_and_parser_have_only_the_supported_modes(self) -> None:
        options = (source_path('common/include/msconnector/options.h', root=ROOT)).read_text()
        parser = function_definition(
            (source_path('common/src/config_parser.c', root=ROOT)).read_text(),
            "msconnector_parse_phase4_mode",
        )
        self.assertRegex(
            options,
            r"#define\s+MSCONNECTOR_DEFAULT_PHASE4_MODE\s+"
            r"MSCONNECTOR_PHASE4_MODE_OFF\b",
        )
        self.assertNotIn("MSCONNECTOR_PHASE4_MODE_MINIMAL", options)
        self.assertEqual(
            set(re.findall(r'token_equals\(value, "([^"]+)"\)', parser)),
            {"off", "safe", "strict"},
        )
        self.assertIn("else { return 0; }", parser)

    def test_active_configuration_examples_have_no_removed_mode_or_mime_setting(self) -> None:
        old_setting = re.compile(
            r"^\s*(?:(?:modsecurity_)?phase4[_-]mode\s*(?:=|\s)\s*minimal\b|"
            r'(?:modsecurity_)?phase4_content_types_file\b|'
            r'"late_action_policy"\s*:\s*"minimal")',
            re.MULTILINE,
        )
        candidates = list((source_path('examples', root=ROOT)).rglob("*"))
        candidates.extend((source_path('connectors/traefik/config', root=ROOT)).rglob("*"))
        for path in candidates:
            if path.is_file() and path.suffix in {".conf", ".cfg", ".json", ".in", ".yaml"}:
                with self.subTest(path=path.relative_to(ROOT).as_posix()):
                    self.assertIsNone(old_setting.search(path.read_text()))

    def test_native_mime_configuration_is_not_registered_twice(self) -> None:
        for relative in (
            "common/include/msconnector/directives.h",
            "common/include/msconnector/options.h",
            "connectors/apache/src/msc_config.c",
            "connectors/nginx/src/ngx_http_modsecurity_module.c",
        ):
            with self.subTest(path=relative):
                self.assertNotIn("phase4_content_types", (ROOT / relative).read_text().lower())

    def test_prs_do_not_skip_the_post_merge_lint_and_syntax_steps(self) -> None:
        for name in WORKFLOWS:
            with self.subTest(workflow=name):
                text = (source_path('.github/workflows', root=ROOT) / name).read_text()
                self.assertRegex(text, r"(?m)^  pull_request:")
                self.assertNotRegex(
                    text, r"if:.*github\.event_name\s*!=\s*['\"]pull_request['\"]"
                )
                self.assertNotIn("continue-on-error: true", text)
                self.assertRegex(text, r"(?m)^permissions: \{\}$")
                self.assertRegex(text, r"(?m)^    permissions:\n      contents: read$")
                self.assertRegex(text, r"make (?:lint|quick-check)")

    def test_migration_regressions_and_generated_files_are_checked_in_prs(self) -> None:
        text = (source_path('.github/workflows/lint.yml', root=ROOT)).read_text()
        for marker in (
            "modsecurity_connector_tests.test_phase4_migration_contract",
            "modsecurity_connector_tests.test_nginx_native_security_contract",
            "modsecurity_connector_tests.test_nginx_upstream_security_contract",
            "modsecurity_connector_tests.test_nginx_common_adoption",
            "modsecurity_connector_tests.test_connector_config_reference",
            "modsecurity_connector_tests.test_logical_connector_all_examples",
            "generate-connector-config-reference.py --check",
            "ci/checks/documentation/check-connector-config-reference.py",
        ):
            with self.subTest(check=marker):
                self.assertIn(marker, text)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
