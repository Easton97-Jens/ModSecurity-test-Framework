from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any
import unittest


ROOT = connector_root()
FRAMEWORK = source_path('modules/ModSecurity-test-Framework', root=ROOT)
INIT_STOP = 79


class NginxFullLifecycleProtocolWiringTest(unittest.TestCase):
    """Run the native Make caller and real selection/init, never a host."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="protocol-wiring-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.calls = self.root / "calls.jsonl"
        self.launcher = self.root / "python-recorder"
        self.launcher.write_text(
            f"#!{sys.executable}\n"
            "import json, os, subprocess, sys\n"
            "arguments = sys.argv[1:]\n"
            "is_catalog = bool(arguments) and arguments[0].endswith('/ci/checks/catalog/no_crs_baseline.py')\n"
            "if is_catalog:\n"
            "    with open(os.environ['PROTOCOL_TEST_CALLS'], 'a', encoding='utf-8') as stream:\n"
            "        stream.write(json.dumps({'argv': arguments, 'downstream': os.environ.get('NGINX_DOWNSTREAM_PROTOCOL')}) + '\\n')\n"
            "interpreter = os.environ['PROTOCOL_TEST_FRAMEWORK_PYTHON'] if is_catalog else os.environ['PROTOCOL_TEST_PARENT_PYTHON']\n"
            "result = subprocess.run([interpreter, *arguments], check=False)\n"
            f"sys.exit({INIT_STOP} if is_catalog and arguments[1] == 'init' and result.returncode == 0 else result.returncode)\n",
            encoding="utf-8",
        )
        self.launcher.chmod(0o700)

    def invoke(
        self, target: str = "full-lifecycle-nginx", *, variables: dict[str, str] | None = None,
        fixture_capabilities: bool = False, overpromote_capabilities: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        for name in (
            "NGINX_PROTOCOL_PROFILE", "NGINX_DOWNSTREAM_PROTOCOL", "NGINX_UPSTREAM_PROTOCOL",
            "NO_CRS_ARTIFACT_PROFILE", "FULL_LIFECYCLE_HOST_PROFILE", "FULL_LIFECYCLE_EXECUTED_TARGET",
            "FIVE_CONNECTOR_PROFILE", "RUNTIME_COMPONENT_ENV_SNAPSHOT", "NO_CRS_PROTOCOL_CLIENT",
            "NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR",
        ):
            environment.pop(name, None)
        connector_root = ROOT
        if fixture_capabilities:
            connector_root = self.root / "invocation/build/nginx/protocol-wiring/connector-fixture"
            connector_root.mkdir(parents=True)
            (connector_root / "ci").symlink_to(source_path('ci', root=ROOT), target_is_directory=True)
            capability_path = connector_root / "connectors/nginx/capabilities.json"
            capability_path.parent.mkdir(parents=True)
            capabilities = json.loads((source_path('connectors/nginx/capabilities.json', root=ROOT)).read_text(encoding="utf-8"))
            # Protocol visibility is not an implementation of unrelated
            # future cases or their missing execution descriptors.
            protocol_capabilities = {
                "http2", "http2_downstream", "http2_tls_alpn",
                "http3_downstream", "http3_quic", "http3_alt_svc",
            }
            names = capabilities["capabilities"] if overpromote_capabilities else protocol_capabilities
            for name in names:
                capabilities["capabilities"][name] = {
                    "state": "implemented_not_asserted", "reason": "plan-only protocol fixture",
                }
            capability_path.write_text(json.dumps(capabilities), encoding="utf-8")
        invocation = self.root / "invocation"
        environment.update(
            {
                "CONNECTOR_ROOT": str(connector_root), "FRAMEWORK_ROOT": str(FRAMEWORK),
                "VERIFIED_RUN_ROOT": str(invocation), "BUILD_ROOT": str(invocation / "build"),
                "VERIFIED_EVIDENCE_ROOT": str(invocation / "evidence"),
                "EVIDENCE_ROOT": str(invocation / "evidence/no-crs-evidence"),
                "RUNTIME_RUN_ROOT": str(invocation / "runs"),
                "RUNTIME_LOG_ROOT": str(invocation / "run-logs"),
                "CACHE_ROOT": str(invocation / "cache-v2"), "NO_CRS_RUN_ID": "protocol-wiring",
                "PYTHON": str(self.launcher), "PROTOCOL_TEST_CALLS": str(self.calls),
                "PROTOCOL_TEST_PARENT_PYTHON": sys.executable,
                "PROTOCOL_TEST_FRAMEWORK_PYTHON": os.environ.get("FRAMEWORK_TEST_PYTHON", sys.executable),
                "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
            }
        )
        environment.update(variables or {})
        command = ["make", "--no-print-directory", target]
        if fixture_capabilities:
            command.append(f"CONNECTOR_ROOT={connector_root}")
        return subprocess.run(
            command, cwd=ROOT, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False, timeout=30,
        )

    def assert_native_plan(
        self, result: subprocess.CompletedProcess[str], protocol: str, connector: str = "nginx",
    ) -> dict[str, Any]:
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn(f"Error {INIT_STOP}", result.stderr, result.stdout + result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([call["argv"][1] for call in calls], ["select", "init"])
        for call in calls:
            argv = call["argv"]
            self.assertEqual(argv[argv.index("--downstream-protocol") + 1], protocol)
        raw_plan = self.root / f"invocation/runs/{connector}/protocol-wiring/plan.json"
        plan = json.loads(raw_plan.read_text(encoding="utf-8"))
        self.assertEqual(plan["downstream_protocol"], protocol)
        persisted_plan = self.root / f"invocation/evidence/no-crs-evidence/{connector}/protocol-wiring/plan.json"
        initialized = json.loads(persisted_plan.read_text(encoding="utf-8"))
        self.assertEqual(initialized["downstream_protocol"], protocol)
        self.assertEqual(initialized["cases"], plan["cases"])
        return plan

    def test_standard_make_caller_uses_existing_http1_default(self) -> None:
        plan = self.assert_native_plan(self.invoke(), "http1")
        self.assertEqual(plan["counts"]["SELECTED"], 97)
        calls = [json.loads(line) for line in self.calls.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([call["downstream"] for call in calls], ["http1", "http1"])

    def test_enhanced_build_profile_does_not_invent_a_different_downstream(self) -> None:
        self.assert_native_plan(self.invoke(variables={"NGINX_PROTOCOL_PROFILE": "h1-h2-h3-quic"}), "http1")

    def test_explicit_http1_remains_authoritative(self) -> None:
        self.assert_native_plan(self.invoke(variables={"NGINX_DOWNSTREAM_PROTOCOL": "http1"}), "http1")

    def test_http1_plan_excludes_h2_h3_even_with_capable_fixture(self) -> None:
        plan = self.assert_native_plan(self.invoke(fixture_capabilities=True), "http1")
        self.assertEqual(plan["counts"]["SELECTED"], 97)
        catalog = json.loads((FRAMEWORK / "tests/cases/no-crs-baseline/catalog.json").read_text(encoding="utf-8"))
        selections = {case["case_id"]: case for case in plan["cases"]}
        protocol_cases = [
            case for case in catalog["cases"]
            if case.get("request", {}).get("protocol_profile") in {"h2", "h2c", "h3"}
        ]
        self.assertTrue(protocol_cases)
        for case in protocol_cases:
            self.assertEqual(selections[case["case_id"]]["selection_status"], "NOT_APPLICABLE", case["case_id"])

    def test_explicit_h2_reaches_selection_but_missing_executors_block_init(self) -> None:
        self.assert_protocol_requires_executors("h2", "h1-h2", "protocol_h2_negotiated")

    def test_explicit_h3_reaches_selection_but_missing_executors_block_init(self) -> None:
        self.assert_protocol_requires_executors("h3", "h1-h2-h3-quic", "protocol_h3_negotiated")

    def assert_protocol_requires_executors(self, protocol: str, profile: str, required_case: str) -> None:
        result = self.invoke(
            variables={"NGINX_DOWNSTREAM_PROTOCOL": protocol, "NGINX_PROTOCOL_PROFILE": profile},
            fixture_capabilities=True,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn(required_case + ": selected NGX case has no ", result.stderr)
        self.assertNotIn(f"Error {INIT_STOP}", result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([call["argv"][1] for call in calls], ["select"])
        argv = calls[0]["argv"]
        self.assertEqual(argv[argv.index("--downstream-protocol") + 1], protocol)
        self.assertEqual(calls[0]["downstream"], protocol)
        self.assertFalse((self.root / "invocation/evidence/no-crs-evidence/nginx/protocol-wiring").exists())

    def test_overpromoted_capabilities_do_not_invent_execution_descriptors(self) -> None:
        result = self.invoke(fixture_capabilities=True, overpromote_capabilities=True)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("header_count_at_limit: selected NGX case has no ", result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([call["argv"][1] for call in calls], ["select"])

    def test_invalid_and_conflicting_protocols_fail_before_selection(self) -> None:
        for protocol, profile in (("any", "h1"), ("garbage", "h1"), ("h2", "h1"), ("h3", "h1-h2"), ("http1", "invalid")):
            with self.subTest(protocol=protocol, profile=profile):
                result = self.invoke(variables={"NGINX_DOWNSTREAM_PROTOCOL": protocol, "NGINX_PROTOCOL_PROFILE": profile})
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.calls.exists(), result.stdout + result.stderr)

    def test_generic_nginx_plan_remains_any(self) -> None:
        self.assert_native_plan(self.invoke(target="no-crs-baseline-nginx"), "any")

    def test_other_connector_full_lifecycle_plan_remains_any(self) -> None:
        self.assert_native_plan(self.invoke(target="full-lifecycle-apache"), "any", connector="apache")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
