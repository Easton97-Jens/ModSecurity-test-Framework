"""Compile-and-link regression coverage for HAProxy/libModSecurity API detection."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = connector_root()
CONNECTOR_DIR = source_path('connectors/haproxy', root=ROOT)


class HAProxyLibModSecurityCompatibilityTests(unittest.TestCase):
    """Exercise the real Make target with controlled public C API fixtures."""

    maxDiff = None

    def setUp(self) -> None:
        self.cc = shutil.which("cc")
        self.cxx = shutil.which("c++")
        self.make = shutil.which("make")
        self.assertIsNotNone(self.cc, "cc is required for HAProxy API-probe regression tests")
        self.assertIsNotNone(self.cxx, "c++ is required for HAProxy API-probe regression tests")
        self.assertIsNotNone(self.make, "make is required for HAProxy API-probe regression tests")

    def write_fake_installation(
        self,
        root: Path,
        *,
        optional_declaration: bool,
        optional_symbol: bool,
        omit_baseline_logging: bool = False,
        omit_baseline_logging_symbol: bool = False,
    ) -> tuple[Path, Path]:
        include_dir = root / "include"
        header_dir = include_dir / "modsecurity"
        lib_dir = root / "lib"
        header_dir.mkdir(parents=True)
        lib_dir.mkdir()

        declarations = [
            "typedef struct ModSecurity ModSecurity;",
            "typedef struct RulesSet RulesSet;",
            "typedef struct Transaction Transaction;",
            "typedef struct ModSecurityIntervention {",
            "    int status;",
            "    int pause;",
            "    char *url;",
            "    char *log;",
            "    int disruptive;",
            "} ModSecurityIntervention;",
            "ModSecurity *msc_init(void);",
            "void msc_cleanup(ModSecurity *);",
            "void msc_set_connector_info(ModSecurity *, const char *);",
            "RulesSet *msc_create_rules_set(void);",
            "int msc_rules_add(RulesSet *, const char *, const char **);",
            "int msc_rules_add_file(RulesSet *, const char *, const char **);",
            "void msc_rules_error_cleanup(const char *);",
            "int msc_rules_cleanup(RulesSet *);",
            "Transaction *msc_new_transaction(ModSecurity *, RulesSet *, void *);",
            "Transaction *msc_new_transaction_with_id(ModSecurity *, RulesSet *, const char *, void *);",
            "int msc_process_connection(Transaction *, const char *, int, const char *, int);",
            "int msc_process_uri(Transaction *, const char *, const char *, const char *);",
            "int msc_add_request_header(Transaction *, const unsigned char *, const unsigned char *);",
            "int msc_process_request_headers(Transaction *);",
            "int msc_append_request_body(Transaction *, const unsigned char *, size_t);",
            "int msc_process_request_body(Transaction *);",
            "int msc_add_response_header(Transaction *, const unsigned char *, const unsigned char *);",
            "int msc_process_response_headers(Transaction *, int, const char *);",
            "int msc_append_response_body(Transaction *, const unsigned char *, size_t);",
            "int msc_process_response_body(Transaction *);",
            "int msc_intervention(Transaction *, ModSecurityIntervention *);",
            "void msc_intervention_cleanup(ModSecurityIntervention *);",
            "void msc_transaction_cleanup(Transaction *);",
        ]
        if not omit_baseline_logging:
            declarations.append("int msc_process_logging(Transaction *);")
        if optional_declaration:
            declarations.append(
                "size_t msc_get_rules_messages_rule_ids(const Transaction *, int64_t *, size_t);"
            )
        header = "\n".join(
            [
                "#ifndef TEST_MODSECURITY_H",
                "#define TEST_MODSECURITY_H",
                "#include <stddef.h>",
                "#include <stdint.h>",
                "#ifdef __cplusplus",
                'extern "C" {',
                "#endif",
                *declarations,
                "#ifdef __cplusplus",
                "}",
                "#endif",
                "#endif",
                "",
            ]
        )
        (header_dir / "modsecurity.h").write_text(header, encoding="utf-8")
        (header_dir / "rules_set.h").write_text(
            '#include <modsecurity/modsecurity.h>\n', encoding="utf-8"
        )
        (header_dir / "transaction.h").write_text(
            '#include <modsecurity/modsecurity.h>\n', encoding="utf-8"
        )

        definitions = [
            "#include <modsecurity/modsecurity.h>",
            "#include <string.h>",
            "struct ModSecurity { int value; };",
            "struct RulesSet { int value; };",
            "struct Transaction { int value; };",
            "static ModSecurity MODSECURITY_INSTANCE;",
            "static RulesSet RULES_INSTANCE;",
            "static Transaction TRANSACTION_INSTANCE;",
            "ModSecurity *msc_init(void) { return &MODSECURITY_INSTANCE; }",
            "void msc_cleanup(ModSecurity *value) { (void)value; }",
            "void msc_set_connector_info(ModSecurity *value, const char *info) { (void)value; (void)info; }",
            "RulesSet *msc_create_rules_set(void) { return &RULES_INSTANCE; }",
            "int msc_rules_add(RulesSet *value, const char *rules, const char **error) { (void)value; (void)rules; if (error != 0) *error = 0; return 1; }",
            "int msc_rules_add_file(RulesSet *value, const char *path, const char **error) { (void)value; (void)path; if (error != 0) *error = 0; return 1; }",
            "void msc_rules_error_cleanup(const char *error) { (void)error; }",
            "int msc_rules_cleanup(RulesSet *value) { (void)value; return 1; }",
            "Transaction *msc_new_transaction(ModSecurity *modsec, RulesSet *rules, void *data) { (void)modsec; (void)rules; (void)data; return &TRANSACTION_INSTANCE; }",
            "Transaction *msc_new_transaction_with_id(ModSecurity *modsec, RulesSet *rules, const char *id, void *data) { (void)id; return msc_new_transaction(modsec, rules, data); }",
            "int msc_process_connection(Transaction *value, const char *client, int client_port, const char *server, int server_port) { (void)value; (void)client; (void)client_port; (void)server; (void)server_port; return 1; }",
            "int msc_process_uri(Transaction *value, const char *uri, const char *method, const char *version) { (void)value; (void)uri; (void)method; (void)version; return 1; }",
            "int msc_add_request_header(Transaction *value, const unsigned char *name, const unsigned char *data) { (void)value; (void)name; (void)data; return 1; }",
            "int msc_process_request_headers(Transaction *value) { (void)value; return 1; }",
            "int msc_append_request_body(Transaction *value, const unsigned char *data, size_t length) { (void)value; (void)data; (void)length; return 1; }",
            "int msc_process_request_body(Transaction *value) { (void)value; return 1; }",
            "int msc_add_response_header(Transaction *value, const unsigned char *name, const unsigned char *data) { (void)value; (void)name; (void)data; return 1; }",
            "int msc_process_response_headers(Transaction *value, int status, const char *protocol) { (void)value; (void)status; (void)protocol; return 1; }",
            "int msc_append_response_body(Transaction *value, const unsigned char *data, size_t length) { (void)value; (void)data; (void)length; return 1; }",
            "int msc_process_response_body(Transaction *value) { (void)value; return 1; }",
            "int msc_intervention(Transaction *value, ModSecurityIntervention *intervention) { (void)value; if (intervention != 0) memset(intervention, 0, sizeof(*intervention)); return 0; }",
            "void msc_intervention_cleanup(ModSecurityIntervention *intervention) { (void)intervention; }",
            "void msc_transaction_cleanup(Transaction *value) { (void)value; }",
        ]
        if not omit_baseline_logging and not omit_baseline_logging_symbol:
            definitions.append(
                "int msc_process_logging(Transaction *value) { (void)value; return 1; }"
            )
        if optional_symbol:
            definitions.append(
                "size_t msc_get_rules_messages_rule_ids(const Transaction *value, int64_t *ids, size_t capacity) { (void)value; if (capacity > 0U && ids != 0) ids[0] = 42; return capacity > 0U ? 1U : 0U; }"
            )
        source = root / "fake_modsecurity.c"
        source.write_text("\n".join(definitions) + "\n", encoding="utf-8")
        library = lib_dir / "libmodsecurity.so"
        compiled = subprocess.run(
            [str(self.cc), "-std=c17", "-fPIC", "-shared", "-I", str(include_dir), str(source), "-o", str(library)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
        return include_dir, lib_dir

    def run_binding_build(self, include_dir: Path, lib_dir: Path, build_root: Path) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["CFLAGS"] = "-std=c17 -Wall -Wextra -Werror"
        return subprocess.run(
            [
                str(self.make),
                "-C",
                str(CONNECTOR_DIR),
                "build-modsecurity-binding",
                f"BUILD_ROOT={build_root}",
                f"MODSECURITY_INCLUDE_DIR={include_dir}",
                f"MODSECURITY_LIB_DIR={lib_dir}",
                f"MODSECURITY_INCLUDE_CANDIDATES={include_dir}",
                f"MODSECURITY_LIB_CANDIDATES={lib_dir}",
            ],
            cwd=ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

    def feature_state(self, build_root: Path) -> dict[str, str]:
        path = build_root / "haproxy-modsecurity-binding" / "paths.env"
        self.assertTrue(path.is_file(), f"missing feature-state file: {path}")
        return dict(
            line.split("=", 1)
            for line in path.read_text(encoding="utf-8").splitlines()
            if "=" in line
        )

    def assert_successful_baseline(
        self,
        result: subprocess.CompletedProcess[str],
        build_root: Path,
        expected_feature: str,
    ) -> None:
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        state = self.feature_state(build_root)
        self.assertEqual(state["HAPROXY_MODSECURITY_RULE_IDS_API"], expected_feature)
        expected_cppflags = (
            "-DHAPROXY_HAVE_MSC_GET_RULES_MESSAGES_RULE_IDS=1"
            if expected_feature == "available"
            else ""
        )
        self.assertEqual(state["HAPROXY_MODSECURITY_BINDING_CPPFLAGS"], expected_cppflags)

    def test_baseline_api_without_optional_rule_ids_builds(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-libmodsecurity-baseline-") as temporary:
            root = Path(temporary)
            include_dir, lib_dir = self.write_fake_installation(
                root / "installation", optional_declaration=False, optional_symbol=False
            )
            build_root = root / "build"
            result = self.run_binding_build(include_dir, lib_dir, build_root)

            self.assert_successful_baseline(result, build_root, "unavailable")
            self.assertIn("using the supported 3.0.14 baseline Rule-ID path", result.stdout)
            compile_log = (
                build_root
                / "haproxy-modsecurity-binding"
                / "verify_modsecurity_optional_rule_ids_compile.log"
            )
            self.assertIn("undeclared", compile_log.read_text(encoding="utf-8"))

    def test_optional_rule_ids_requires_matching_declaration_and_symbol(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-libmodsecurity-optional-") as temporary:
            root = Path(temporary)
            include_dir, lib_dir = self.write_fake_installation(
                root / "installation", optional_declaration=True, optional_symbol=True
            )
            build_root = root / "build"
            result = self.run_binding_build(include_dir, lib_dir, build_root)

            self.assert_successful_baseline(result, build_root, "available")
            self.assertIn("compile-and-link probe passed", result.stdout)

    def test_optional_declaration_without_symbol_falls_back_after_link_probe(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-libmodsecurity-header-only-") as temporary:
            root = Path(temporary)
            include_dir, lib_dir = self.write_fake_installation(
                root / "installation", optional_declaration=True, optional_symbol=False
            )
            build_root = root / "build"
            result = self.run_binding_build(include_dir, lib_dir, build_root)

            self.assert_successful_baseline(result, build_root, "unavailable")
            self.assertIn("did not link it", result.stdout)
            link_log = (
                build_root
                / "haproxy-modsecurity-binding"
                / "verify_modsecurity_optional_rule_ids_link.log"
            )
            self.assertIn("undefined reference", link_log.read_text(encoding="utf-8"))

    def test_optional_symbol_without_declaration_falls_back_after_compile_probe(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-libmodsecurity-symbol-only-") as temporary:
            root = Path(temporary)
            include_dir, lib_dir = self.write_fake_installation(
                root / "installation", optional_declaration=False, optional_symbol=True
            )
            build_root = root / "build"
            result = self.run_binding_build(include_dir, lib_dir, build_root)

            self.assert_successful_baseline(result, build_root, "unavailable")
            self.assertIn("unavailable for the selected libModSecurity headers", result.stdout)

    def test_missing_baseline_api_is_a_clear_fatal_error(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-libmodsecurity-missing-baseline-") as temporary:
            root = Path(temporary)
            include_dir, lib_dir = self.write_fake_installation(
                root / "installation",
                optional_declaration=False,
                optional_symbol=False,
                omit_baseline_logging=True,
            )
            result = self.run_binding_build(include_dir, lib_dir, root / "build")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "The HAProxy connector requires the public libModSecurity API available in version 3.0.14 or newer.",
                result.stdout + result.stderr,
            )

    def test_missing_baseline_library_symbol_is_a_clear_fatal_error(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-libmodsecurity-missing-baseline-symbol-") as temporary:
            root = Path(temporary)
            include_dir, lib_dir = self.write_fake_installation(
                root / "installation",
                optional_declaration=False,
                optional_symbol=False,
                omit_baseline_logging_symbol=True,
            )
            result = self.run_binding_build(include_dir, lib_dir, root / "build")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "The HAProxy connector requires the public libModSecurity API available in version 3.0.14 or newer.",
                result.stdout + result.stderr,
            )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
