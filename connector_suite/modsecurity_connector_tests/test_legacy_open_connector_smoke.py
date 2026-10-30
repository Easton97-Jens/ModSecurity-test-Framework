"""Executed Parent-to-Framework legacy runtime handoff contracts."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = connector_root()
LAUNCHER = source_path('ci/runtime/lifecycle/run-legacy-open-connector-smoke.sh', root=ROOT)


class LegacyOpenConnectorSmokeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="legacy-runtime-handoff-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.launcher = self.root / LAUNCHER.relative_to(ROOT)
        self.launcher.parent.mkdir(parents=True)
        shutil.copyfile(LAUNCHER, self.launcher)
        framework = self.root / "modules/ModSecurity-test-Framework/ci"
        (framework / "lib").mkdir(parents=True)
        (framework / "runtime").mkdir()
        self.receipt = self.root / "receipt.json"
        self.service_root = self.root / "build/envoy-connector"
        self.service_root.mkdir(parents=True)
        for name in ("msconnector_envoy_ext_authz", "msconnector_envoy_response_observer"):
            service = self.service_root / name
            service.write_text("#!/bin/sh\nexit 0\n")
            service.chmod(0o700)
        self.binaries = {}
        for connector in ("envoy", "traefik", "lighttpd"):
            binary = self.root / "prepared" / connector / "bin" / connector
            binary.parent.mkdir(parents=True)
            binary.write_text(f"#!/bin/sh\nprintf '%s\\n' '{connector}-prepared-live'\n")
            binary.chmod(0o700)
            self.binaries[connector] = binary
            variable = connector.upper() + "_BIN"
            (framework / "runtime" / f"run-{connector}-smoke.sh").write_text(
                '#!/bin/sh\nset -eu\n"$PYTHON" - <<\'PY\'\n'
                'import json, os, subprocess\nfrom pathlib import Path\n'
                f'variable = "{variable}"\n'
                'binary = os.environ[variable]\n'
                'result = subprocess.run([binary, "--version"], capture_output=True, text=True, check=True)\n'
                'Path(os.environ["TEST_RECEIPT"]).write_text(json.dumps({"binary": binary, "output": result.stdout, "scope": os.environ.get("CASE_SCOPE"), "backend": os.environ.get("DECISION_BACKEND"), "service": os.environ.get("SERVICE_BIN"), "observer": os.environ.get("RESPONSE_OBSERVER_BIN")}))\n'
                'raise SystemExit(int(os.environ.get("TEST_WRAPPER_RC", "0")))\nPY\n'
            )
        (framework / "lib/common.sh").write_text(
            'BUILD_ROOT="$TEST_ROOT/build"\nexport BUILD_ROOT\n'
            'ENVOY_COMPONENT_ROOT="$TEST_ROOT/prepared/envoy"\n'
            'TRAEFIK_BUILD_ROOT="$TEST_ROOT/prepared/traefik"\n'
            'LIGHTTPD_CONNECTOR_BUILD_ROOT="$TEST_ROOT/prepared/lighttpd"\n'
            'envoy_build_paths() { :; }\ntraefik_build_paths() { :; }\nlighttpd_build_paths() { :; }\n'
            'resolve_fixture() {\n'
            ' test "${TEST_RESOLVER_RC:-0}" = 0 || return "$TEST_RESOLVER_RC"\n'
            ' printf "%s\\n" "${TEST_RESOLVED_BINARY:-$TEST_ROOT/prepared/$1/bin/$1}"\n'
            '}\n'
            'require_or_provision_envoy() { resolve_fixture envoy; }\n'
            'require_or_provision_traefik() { resolve_fixture traefik; }\n'
            'require_or_provision_lighttpd() { resolve_fixture lighttpd; }\n'
        )

    def run_launcher(self, connector: str, *arguments: str, **overrides: str):
        environment = {**os.environ, "PYTHON": sys.executable,
                       "TEST_ROOT": str(self.root), "TEST_RECEIPT": str(self.receipt),
                       "CASE_SCOPE": "all", "DECISION_BACKEND": "libmodsecurity"}
        environment.update(overrides)
        return subprocess.run(["/bin/sh", str(self.launcher), connector, *arguments],
                              env=environment, capture_output=True, text=True, check=False)

    def test_all_fixed_wrappers_receive_prepared_binary_not_inherited_overrides(self) -> None:
        for connector, binary in self.binaries.items():
            with self.subTest(connector=connector):
                result = self.run_launcher(connector, ENVOY_BIN="/bin/false", TRAEFIK_BIN="/bin/false",
                                           LIGHTTPD_BIN="/bin/false", FRAMEWORK_ROOT="/missing", CONNECTOR_ROOT="/missing",
                                           SERVICE_BIN="/bin/false", RESPONSE_OBSERVER_BIN="/bin/false")
                self.assertEqual(result.returncode, 0, result.stderr)
                receipt = json.loads(self.receipt.read_text())
                self.assertEqual(receipt["binary"], str(binary))
                self.assertEqual(receipt["output"], f"{connector}-prepared-live\n")
                self.assertEqual(receipt["scope"], "all")
                self.assertEqual(receipt["backend"], "libmodsecurity")
                if connector == "envoy":
                    self.assertEqual(receipt["service"], str(self.service_root / "msconnector_envoy_ext_authz"))
                    self.assertEqual(receipt["observer"], str(self.service_root / "msconnector_envoy_response_observer"))

    def test_envoy_requires_current_service_and_response_observer_without_fallback(self) -> None:
        for name in ("msconnector_envoy_ext_authz", "msconnector_envoy_response_observer"):
            with self.subTest(name=name):
                service = self.service_root / name
                original = service.with_suffix(".old")
                service.rename(original)
                result = self.run_launcher("envoy", SERVICE_BIN=str(original), RESPONSE_OBSERVER_BIN=str(original))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.receipt.exists())
                original.rename(service)

    def test_unknown_connector_and_extra_command_fail_before_wrapper(self) -> None:
        for arguments in (("unknown",), ("envoy", "extra-command"), ("../envoy",)):
            with self.subTest(arguments=arguments):
                result = self.run_launcher(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(self.receipt.exists())

    def test_resolver_failure_never_runs_framework_wrapper(self) -> None:
        for connector in self.binaries:
            with self.subTest(connector=connector):
                result = self.run_launcher(connector, TEST_RESOLVER_RC="77")
                self.assertEqual(result.returncode, 77)
                self.assertFalse(self.receipt.exists())

    def test_wrong_resolved_path_and_unsafe_binary_fail_before_wrapper(self) -> None:
        result = self.run_launcher("envoy", TEST_RESOLVED_BINARY=str(self.binaries["traefik"]))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.receipt.exists())
        binary = self.binaries["envoy"]
        binary.chmod(0o777)
        result = self.run_launcher("envoy")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.receipt.exists())
        binary.chmod(0o700)
        os.link(binary, binary.parent / "hardlink")
        result = self.run_launcher("envoy")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.receipt.exists())

    def test_symlink_binary_is_rejected_and_wrapper_failure_propagates(self) -> None:
        binary = self.binaries["envoy"]
        original = binary.with_name("original")
        binary.rename(original)
        binary.symlink_to(original)
        result = self.run_launcher("envoy")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.receipt.exists())
        result = self.run_launcher("traefik", TEST_WRAPPER_RC="9")
        self.assertEqual(result.returncode, 9)

    def test_actual_make_recipes_execute_the_fixed_launcher(self) -> None:
        source = (source_path('Makefile', root=ROOT)).read_text()
        recipes = []
        for connector in self.binaries:
            recipe = source.split(f"smoke-{connector}: check-framework\n", 1)[1].split("\n\n", 1)[0]
            recipes.append(f"smoke-{connector}:\n{recipe}\n")
        (self.root / "Makefile").write_text("\n".join(recipes))
        for connector, binary in self.binaries.items():
            with self.subTest(connector=connector):
                result = subprocess.run(
                    ["make", "--no-print-directory", f"smoke-{connector}", "WITH_RUNTIME_COMPONENTS=", f"FRAMEWORK_PYTHON={sys.executable}"],
                    cwd=self.root,
                    env={**os.environ, "TEST_ROOT": str(self.root), "TEST_RECEIPT": str(self.receipt)},
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(self.receipt.read_text())["binary"], str(binary))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
