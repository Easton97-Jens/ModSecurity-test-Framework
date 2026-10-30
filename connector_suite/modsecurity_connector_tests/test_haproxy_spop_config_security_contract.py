"""Regression contracts for the SPOP production configuration boundary."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SOURCE = (
    connector_root()
    / "connectors"
    / "haproxy"
    / "src"
    / "haproxy_spop_diagnostic_runtime.c"
).read_text(encoding="utf-8")


class HaproxySPOPConfigSecurityContractTests(unittest.TestCase):
    def test_fail_mode_is_exact_and_validated_before_configuration_mutation(self):
        start = SOURCE.index("static int valid_fail_mode(")
        end = SOURCE.index("static int config_set_scalar_flags(", start)
        helpers = SOURCE[start:end]
        scalar_start = SOURCE.index("static int config_set_scalar_identity(")
        scalar_end = SOURCE.index("static int config_set(", scalar_start)
        scalar = SOURCE[scalar_start:scalar_end]
        config_start = scalar_end
        config_end = SOURCE.index("static char *trim_in_place(", config_start)
        config_path = SOURCE[config_start:config_end]

        self.assertIn('strcmp(value, "closed") == 0', helpers)
        self.assertIn('strcmp(value, "open") == 0', helpers)
        self.assertIn("if (!valid_fail_mode(value))", scalar)
        self.assertIn("copy_spop_string(config->fail_mode", scalar)
        self.assertNotIn('SET_STRING_FIELD("fail-mode", fail_mode)', config_path)
        self.assertLess(
            scalar.index("if (!valid_fail_mode(value))"),
            scalar.index("copy_spop_string(config->fail_mode"),
        )

    def test_response_companion_identity_uses_strict_bounded_decimal_parser(self):
        parser_start = SOURCE.index("static int parse_bounded_uint_range(")
        parser_end = SOURCE.index("static int parse_bounded_uint(", parser_start)
        parser = SOURCE[parser_start:parser_end]
        scalar_start = SOURCE.index("static int config_set_scalar_identity(")
        scalar_end = SOURCE.index("static int config_set(", scalar_start)
        scalar = SOURCE[scalar_start:scalar_end]

        self.assertIn("value[0] < '0' || value[0] > '9'", parser)
        self.assertIn("*end != '\\0'", parser)
        self.assertIn("errno != 0", parser)
        self.assertIn("parsed > maximum", parser)
        self.assertIn(
            "parse_bounded_uint_range(value, 0UL, (unsigned long)UINT_MAX",
            scalar,
        )
        self.assertNotIn("response_companion_uid = (unsigned int)strtoul", scalar)
        self.assertNotIn("response_companion_gid = (unsigned int)strtoul", scalar)

    def test_production_validation_rechecks_fail_mode_defensively(self):
        validation_start = SOURCE.index("static int validate_production_config(")
        validation_end = SOURCE.index("static int run_production_agent_command(", validation_start)
        validation = SOURCE[validation_start:validation_end]

        self.assertIn("!valid_fail_mode(config->fail_mode)", validation)
        self.assertIn("invalid value rejected", validation)

    def test_config_loader_rejects_embedded_nul_before_string_validation(self):
        reader_start = SOURCE.index("static int read_config_line(")
        reader_end = SOURCE.index("static int load_config_file(", reader_start)
        reader = SOURCE[reader_start:reader_end]
        loader_start = reader_end
        loader_end = SOURCE.index("static int mode_enforces(", loader_start)
        loader = SOURCE[loader_start:loader_end]

        self.assertIn("character == '\\0'", reader)
        self.assertIn("fgetc(file)", reader)
        self.assertIn("length + 1U >= line_capacity", reader)
        self.assertIn("read_config_line(file, line, sizeof(line))", loader)
        self.assertNotIn("fgets(", loader)

    @unittest.skipUnless(
        os.environ.get("HAPROXY_SPOA_RUNTIME_BIN")
        and os.environ.get("MSCONNECTOR_TEST_TMPDIR"),
        "requires an explicitly built SPOP runtime and registered temporary root",
    )
    def test_runtime_rejects_malformed_config_and_cli_values(self):
        runtime = os.environ["HAPROXY_SPOA_RUNTIME_BIN"]
        with tempfile.TemporaryDirectory(
            prefix="spop-nul-", dir=os.environ["MSCONNECTOR_TEST_TMPDIR"]
        ) as temporary_directory:
            for name, line in {
                "empty_mode": b"fail-mode=\n",
                "unknown_mode": b"fail-mode=openX\n",
                "case_variant": b"fail-mode=OPEN\n",
                "nul_mode": b"fail-mode=open\x00garbage\n",
                "nul_identity": b"response-companion-uid=0\x00garbage\n",
            }.items():
                with self.subTest(config=name):
                    config = Path(temporary_directory) / f"{name}.conf"
                    config.write_bytes(
                        b"listen=127.0.0.1:65530\n"
                        b"rules-file=/dev/null\n"
                        + line
                    )
                    completed = subprocess.run(
                        [runtime, "--config", str(config)],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(completed.returncode, 2, completed.stderr)
                    self.assertIn("failed to load config file", completed.stderr)

        for value in ("", "openX", "OPEN"):
            with self.subTest(cli=value):
                completed = subprocess.run(
                    [
                        runtime,
                        "--listen",
                        "127.0.0.1:65530",
                        "--rules-file",
                        "/dev/null",
                        "--fail-mode",
                        value,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 2, completed.stderr)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
