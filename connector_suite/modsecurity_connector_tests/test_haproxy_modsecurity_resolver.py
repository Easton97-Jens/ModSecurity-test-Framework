"""Focused precedence and rejection tests for the native HAProxy resolver."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import os
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()
RESOLVER = source_path('connectors/haproxy/htx-overlay/resolve-modsecurity.sh', root=ROOT)
CONTRACT = source_path('connectors/haproxy/htx-overlay/version-contract.json', root=ROOT)
CONTRACT_MODULE_PATH = source_path('connectors/haproxy/htx-overlay/version_contract.py', root=ROOT)
CONTRACT_MODULE = load_source(CONTRACT_MODULE_PATH)


class HAProxyModSecurityResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cc = shutil.which("cc")
        self.assertIsNotNone(self.cc, "cc is required for resolver tests")

    def make_installation(self, root: Path) -> tuple[Path, Path]:
        include_dir = root / "include"
        header_dir = include_dir / "modsecurity"
        lib_dir = root / "lib"
        header_dir.mkdir(parents=True)
        lib_dir.mkdir()
        for name in ("modsecurity.h", "rules_set.h", "transaction.h"):
            (header_dir / name).write_text("#pragma once\n", encoding="utf-8")
        source = root / "modsecurity.c"
        source.write_text("int modsecurity_resolver_probe(void) { return 0; }\n", encoding="utf-8")
        subprocess.run(
            [str(self.cc), "-shared", "-fPIC", str(source), "-o", str(lib_dir / "libmodsecurity.so")],
            check=True,
            capture_output=True,
            text=True,
        )
        return include_dir, lib_dir

    def run_resolver(self, output: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(RESOLVER), str(output)],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_explicit_paths_take_precedence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-resolver-explicit-") as temporary:
            root = Path(temporary)
            include_dir, lib_dir = self.make_installation(root / "explicit")
            output = root / "resolution.env"
            env = os.environ.copy()
            env["MODSECURITY_INCLUDE_DIR"] = str(include_dir)
            env["MODSECURITY_LIB_DIR"] = str(lib_dir)
            result = self.run_resolver(output, env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            values = {
                key: value.strip("'")
                for key, value in (line.split("=", 1) for line in output.read_text().splitlines())
            }
            self.assertEqual(values["MODSECURITY_INCLUDE_DIR"], str(include_dir))
            self.assertEqual(values["MODSECURITY_LIB_DIR"], str(lib_dir))
            self.assertEqual(values["MODSECURITY_RESOLUTION"], "explicit")

    def test_pkg_config_is_used_when_paths_are_not_explicit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-resolver-pkgconfig-") as temporary:
            root = Path(temporary)
            include_dir, lib_dir = self.make_installation(root / "installation")
            pkg_dir = root / "pkgconfig"
            pkg_dir.mkdir()
            (pkg_dir / "libmodsecurity.pc").write_text(
                f"prefix={root / 'installation'}\nincludedir={include_dir}\nlibdir={lib_dir}\nName: libmodsecurity\nDescription: test libModSecurity\nVersion: 3.0.14\nLibs: -L{lib_dir} -lmodsecurity\nCflags: -I{include_dir}\n",
                encoding="utf-8",
            )
            output = root / "resolution.env"
            env = os.environ.copy()
            env.pop("MODSECURITY_INCLUDE_DIR", None)
            env.pop("MODSECURITY_LIB_DIR", None)
            env["PKG_CONFIG_LIBDIR"] = str(pkg_dir)
            result = self.run_resolver(output, env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            values = {
                key: value.strip("'")
                for key, value in (line.split("=", 1) for line in output.read_text().splitlines())
            }
            self.assertEqual(values["MODSECURITY_RESOLUTION"], "pkg-config")

    def test_header_library_pairing_mismatch_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-resolver-mismatch-") as temporary:
            root = Path(temporary)
            include_dir = root / "include"
            (include_dir / "modsecurity").mkdir(parents=True)
            (include_dir / "modsecurity/modsecurity.h").write_text("#pragma once\n", encoding="utf-8")
            (include_dir / "modsecurity/rules_set.h").write_text("#pragma once\n", encoding="utf-8")
            (include_dir / "modsecurity/transaction.h").write_text("#pragma once\n", encoding="utf-8")
            lib_dir = root / "lib"
            lib_dir.mkdir()
            (lib_dir / "libmodsecurity.so").write_text("not an ELF library\n", encoding="utf-8")
            env = os.environ.copy()
            env["MODSECURITY_INCLUDE_DIR"] = str(include_dir)
            env["MODSECURITY_LIB_DIR"] = str(lib_dir)
            result = self.run_resolver(root / "resolution.env", env)
            self.assertEqual(result.returncode, 77)
            self.assertIn("architecture", result.stderr)
            self.assertIn("sentinel=architecture_mismatch", result.stderr)

    def test_required_header_failures_are_specific_for_every_header_mask(self) -> None:
        cases = (
            (("modsecurity.h",), "header_modsecurity_h_missing"),
            (("rules_set.h",), "header_rules_set_h_missing"),
            (("transaction.h",), "header_transaction_h_missing"),
            (
                ("modsecurity.h", "rules_set.h"),
                "headers_modsecurity_h_and_rules_set_h_missing",
            ),
            (
                ("modsecurity.h", "transaction.h"),
                "headers_modsecurity_h_and_transaction_h_missing",
            ),
            (
                ("rules_set.h", "transaction.h"),
                "headers_rules_set_h_and_transaction_h_missing",
            ),
            (
                ("modsecurity.h", "rules_set.h", "transaction.h"),
                "headers_modsecurity_h_and_rules_set_h_and_transaction_h_missing",
            ),
        )
        for missing_headers, expected_cause in cases:
            with self.subTest(missing_headers=missing_headers):
                with tempfile.TemporaryDirectory(prefix="haproxy-resolver-header-") as temporary:
                    root = Path(temporary)
                    include_dir, lib_dir = self.make_installation(root / "installation")
                    for header in missing_headers:
                        (include_dir / "modsecurity" / header).unlink()
                    output = root / "resolution.env"
                    env = os.environ.copy()
                    env["MODSECURITY_INCLUDE_DIR"] = str(include_dir)
                    env["MODSECURITY_LIB_DIR"] = str(lib_dir)

                    result = self.run_resolver(output, env)

                    self.assertEqual(result.returncode, 77)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(
                        result.stderr.splitlines()[0],
                        "BLOCKED: HAProxy libModSecurity resolver: sentinel=" + expected_cause,
                    )
                    self.assertFalse(output.exists())

    def test_shared_library_symlink_is_resolved_for_validation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-resolver-symlink-") as temporary:
            root = Path(temporary)
            include_dir, lib_dir = self.make_installation(root / "installation")
            target = lib_dir / "libmodsecurity.so.3.0.14"
            (lib_dir / "libmodsecurity.so").rename(target)
            (lib_dir / "libmodsecurity.so").symlink_to(target.name)
            output = root / "resolution.env"
            env = os.environ.copy()
            env["MODSECURITY_INCLUDE_DIR"] = str(include_dir)
            env["MODSECURITY_LIB_DIR"] = str(lib_dir)
            result = self.run_resolver(output, env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            values = {
                key: value.strip("'")
                for key, value in (line.split("=", 1) for line in output.read_text().splitlines())
            }
            self.assertEqual(values["MODSECURITY_LIBRARY"], str(lib_dir / "libmodsecurity.so"))

    def test_malicious_versioned_library_name_is_blocked_without_execution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-resolver-library-name-") as temporary:
            root = Path(temporary)
            include_dir, lib_dir = self.make_installation(root / "installation")
            valid_library = lib_dir / "libmodsecurity.so"
            malicious_name = "libmodsecurity.so.3'$(touch-marker)'"
            malicious_library = lib_dir / malicious_name
            valid_library.rename(malicious_library)
            marker = root / "touch-marker"
            output = root / "resolution.env"
            env = os.environ.copy()
            env["MODSECURITY_INCLUDE_DIR"] = str(include_dir)
            env["MODSECURITY_LIB_DIR"] = str(lib_dir)
            result = self.run_resolver(output, env)
            self.assertEqual(result.returncode, 77)
            self.assertIn("libmodsecurity is missing", result.stderr)
            self.assertIn("sentinel=library_missing", result.stderr)
            self.assertFalse(marker.exists())
            self.assertFalse(output.exists())

    def test_path_metacharacters_are_blocked_before_env_file_write(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-resolver-injection-") as temporary:
            root = Path(temporary)
            marker = root / "marker"
            output = root / "resolution.env"
            env = os.environ.copy()
            env["MODSECURITY_INCLUDE_DIR"] = f"{root}/include;touch {marker}"
            env["MODSECURITY_LIB_DIR"] = f"{root}/lib"
            result = self.run_resolver(output, env)
            self.assertEqual(result.returncode, 77)
            self.assertIn("sentinel=invalid_path_syntax", result.stderr)
            self.assertFalse(marker.exists())
            self.assertFalse(output.exists())

    def test_output_path_metacharacters_are_blocked(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-resolver-output-") as temporary:
            root = Path(temporary)
            marker = root / "marker"
            output = f"{root}/resolution.env;touch {marker}"
            env = os.environ.copy()
            result = subprocess.run(
                ["sh", str(RESOLVER), output],
                cwd=ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 77)
            self.assertIn("sentinel=invalid_path_syntax", result.stderr)
            self.assertFalse(marker.exists())

    def test_contract_mentions_distro_paths_and_htx_provenance(self) -> None:
        makefile = (source_path('connectors/haproxy/Makefile', root=ROOT)).read_text(encoding="utf-8")
        overlay = (source_path('connectors/haproxy/htx-overlay/build-overlay.sh', root=ROOT)).read_text(encoding="utf-8")
        resolver = RESOLVER.read_text(encoding="utf-8")
        self.assertIn("resolve-modsecurity.sh", makefile)
        self.assertIn("/usr/include", resolver)
        self.assertIn("/usr/lib/x86_64-linux-gnu", resolver)
        self.assertIn("version-contract.json", overlay)
        self.assertIn("HAPROXY_VERSION=$(contract_field version)", overlay)

    def test_resolver_diagnostic_sentinel_contract_is_closed_and_complete(self) -> None:
        resolver = RESOLVER.read_text(encoding="utf-8")
        expected_causes = {
            "invalid_path_syntax",
            "output_path_not_absolute",
            "output_path_symlink",
            "path_contains_whitespace",
            "headers_not_found",
            "library_not_found",
            "headers_missing",
            "headers_modsecurity_h_and_rules_set_h_missing",
            "headers_modsecurity_h_and_transaction_h_missing",
            "headers_rules_set_h_and_transaction_h_missing",
            "headers_modsecurity_h_and_rules_set_h_and_transaction_h_missing",
            "header_modsecurity_h_missing",
            "header_rules_set_h_missing",
            "header_transaction_h_missing",
            "library_missing",
            "readlink_missing",
            "library_target_unresolved",
            "library_target_not_regular",
            "file_missing",
            "architecture_mismatch",
            "ldd_missing",
            "unresolved_runtime_dependencies",
        }
        blocked_causes = set(re.findall(r"\bblocked ([a-z_]+) ", resolver))
        emitted_causes = set(re.findall(r"sentinel=([a-z_]+)'", resolver))

        self.assertEqual(blocked_causes, expected_causes)
        self.assertEqual(emitted_causes, expected_causes)

    def test_spoa_common_sources_receive_the_resolved_modsecurity_include_dir(self) -> None:
        makefile = (source_path('connectors/haproxy/Makefile', root=ROOT)).read_text(encoding="utf-8")
        runtime = (source_path('common/runtime/msconnector_runtime.c', root=ROOT)).read_text(encoding="utf-8")
        spoa_rule = makefile[
            makefile.index("$(SPOA_RUNTIME_BIN):") : makefile.index("$(MODSECURITY_BINDING_BIN):")
        ]

        self.assertIn("$(RESPONSE_COMPANION_SRCS)", spoa_rule)
        self.assertIn('#include "modsecurity/modsecurity.h"', runtime)
        self.assertIn(
            '$(CC) $(CPPFLAGS) $(COMMON_CPPFLAGS) $(CFLAGS) -I"$$MODSECURITY_INCLUDE_DIR" '
            '-I"$(REPO_ROOT)/common/runtime" -Isrc -c "$$src" -o "$$obj"',
            spoa_rule,
        )

    def test_version_contract_accepts_the_repository_contract(self) -> None:
        contract = CONTRACT_MODULE.load_contract(CONTRACT)
        version_parts = contract["version"].split(".")
        self.assertEqual(version_parts[:2], ["3", "2"])
        self.assertTrue(version_parts[2].isdigit())
        self.assertTrue(contract["makefile_patch"].endswith(".patch"))

    def test_version_contract_rejects_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-contract-symlink-") as temporary:
            root = Path(temporary)
            outside = root / "outside.json"
            outside.write_text(CONTRACT.read_text(encoding="utf-8"), encoding="utf-8")
            allowed = root / "allowed"
            allowed.mkdir()
            escaped = allowed / "version-contract.json"
            escaped.symlink_to(outside)
            with mock.patch.object(CONTRACT_MODULE, "CONTRACT_ROOT", allowed.resolve()):
                with self.assertRaisesRegex(ValueError, "symlink"):
                    CONTRACT_MODULE.load_contract(escaped)

    def test_version_contract_rejects_unsafe_patch_and_digest_values(self) -> None:
        with tempfile.TemporaryDirectory(prefix="haproxy-contract-values-") as temporary:
            root = Path(temporary)
            payload = json.loads(CONTRACT.read_text(encoding="utf-8"))
            valid_patch = payload["makefile_patch"]
            payload["makefile_patch"] = "../escape.patch"
            candidate = root / "invalid-patch.json"
            candidate.write_text(json.dumps(payload), encoding="utf-8")
            with mock.patch.object(CONTRACT_MODULE, "CONTRACT_ROOT", root.resolve()):
                with self.assertRaisesRegex(ValueError, "makefile_patch"):
                    CONTRACT_MODULE.load_contract(candidate)
            payload["makefile_patch"] = valid_patch
            payload["sha256"] = "A" * 64
            candidate.write_text(json.dumps(payload), encoding="utf-8")
            with mock.patch.object(CONTRACT_MODULE, "CONTRACT_ROOT", root.resolve()):
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    CONTRACT_MODULE.load_contract(candidate)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
