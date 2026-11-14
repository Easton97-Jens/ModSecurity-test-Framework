"""Regressions for the helper-aware HAProxy Rule-ID adoption check.

Mutate isolated source snapshots, not the working tree. These checks complement
compiled decoder tests; they are not live host or engine evidence.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from modsecurity_connector_tests.checker_fixture_repository import fixture_environment

ROOT = connector_root()
CHECKER = Path("ci/checks/connectors/haproxy/check-haproxy-common-adoption.py")
BINDING = Path("connectors/haproxy/src/haproxy_modsecurity_binding.c")
BOUNDED_MESSAGE = "rule-id extraction only uses positive results"
INITIALIZED_MESSAGE = "rule-id buffer is initialized before extraction"


class HaproxyRuleIdAdoptionTests(unittest.TestCase):
    def run_checker(self, old: str | None = None, new: str = "") -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="haproxy-rule-id-check-") as temporary:
            root = Path(temporary)
            (root / "Makefile").write_text("# isolated checker fixture\n", encoding="utf-8")
            shutil.copytree(source_path('connectors/haproxy', root=ROOT), root / "connectors/haproxy")
            shutil.copytree(source_path("common/include", root=ROOT), root / "common/include")
            (root / CHECKER).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path(str(CHECKER), root=ROOT), root / CHECKER)
            if old is not None:
                path = root / BINDING
                source = path.read_text(encoding="utf-8")
                self.assertEqual(source.count(old), 1, "expected one mutation target")
                path.write_text(source.replace(old, new, 1), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(root / CHECKER)], cwd=root,
                env=fixture_environment(root),
                capture_output=True, text=True, timeout=30, check=False,
            )

    def assert_rejected(self, old: str, new: str, message: str = BOUNDED_MESSAGE) -> None:
        result = self.run_checker(old, new)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("FAIL: " + message, result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_current_helper_passes(self) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS: " + INITIALIZED_MESSAGE, result.stdout)
        self.assertIn("PASS: " + BOUNDED_MESSAGE, result.stdout)

    def test_uninitialized_buffer_is_rejected(self) -> None:
        self.assert_rejected("char common_rule_id[64] = {0};", "char common_rule_id[64];", INITIALIZED_MESSAGE)

    def test_zero_extraction_cannot_reach_conversion(self) -> None:
        self.assert_rejected("sizeof(common_rule_id)) <= 0)", "sizeof(common_rule_id)) < 0)")

    def test_inverted_extraction_guard_is_rejected(self) -> None:
        self.assert_rejected("sizeof(common_rule_id)) <= 0)", "sizeof(common_rule_id)) > 0)")

    def test_comment_cannot_supply_the_guard(self) -> None:
        guard = "if (msconnector_rule_id_extract_from_message(log, common_rule_id,\n            sizeof(common_rule_id)) <= 0) {\n        return;\n    }"
        self.assert_rejected(guard, "/* " + guard + " */")

    def test_missing_conversion_bounds_are_rejected(self) -> None:
        for old, new in (
            ("parsed >= 0L && parsed <= (long)INT_MAX", "parsed >= 0L"),
            ("*end == '\\0' &&", "*end != '\\0' &&"),
            ("end != common_rule_id &&", "end == common_rule_id &&"),
        ):
            with self.subTest(bound=old):
                self.assert_rejected(old, new)

    def test_early_return_is_rejected(self) -> None:
        self.assert_rejected("char common_rule_id[64] = {0};", "char common_rule_id[64] = {0};\n    return;")

    def test_missing_helper_call_is_rejected(self) -> None:
        call = "capture_log_rule_id(decision, intervention->log);"
        self.assert_rejected(call, "/* " + call + " */")


    def test_native_collector_must_check_and_forward_the_real_intervention(self) -> None:
        mutations = (
            ("if (native_result == 1 &&", "if (native_result != 1 &&"),
            ("capture_intervention_details(&intervention, phase, decision,", "capture_intervention_details(0, phase, decision,"),
            ("capture_intervention_details(&intervention, phase, decision,\n            response_append_active, response_body_eos) != 0)",
             "capture_intervention_details(&intervention, phase, decision,\n            response_append_active, response_body_eos) == 0)"),
            ("native_result = msc_intervention(transaction, &intervention);", "native_result = 1;"),
            ("(native_result != 0 && native_result != 1)", "(native_result < 0)"),
        )
        for old, new in mutations:
            with self.subTest(mutation=old):
                self.assert_rejected(old, new)

    def test_details_early_return_and_dead_decode_are_rejected(self) -> None:
        call = "capture_log_rule_id(decision, intervention->log);"
        for changed in ("return 0; " + call, "if (0) { " + call + " }", "/* " + call + " */", "capture_log_rule_id(decision, 0);"):
            with self.subTest(changed=changed):
                self.assert_rejected(call, changed)

    def test_details_cannot_overwrite_or_bypass_the_decoded_decision(self) -> None:
        call = "capture_log_rule_id(decision, intervention->log);"
        for suffix in (
            " decision->rule_id = 42;",
            " init_decision(decision, phase);",
            " memset(decision, 0, sizeof(*decision));",
            " return 0;",
            " if (phase == 4) { return 0; }",
        ):
            with self.subTest(suffix=suffix):
                self.assert_rejected(call, call + suffix)

    def test_details_enforcement_and_native_cleanup_cannot_be_bypassed(self) -> None:
        mutations = (
            ("intervention->disruptive && !decision->body_limit)",
             "intervention->disruptive && decision->body_limit)"),
            ("if (capture_intervention_action(intervention, body_limit, decision) != 0)",
             "if (capture_intervention_action(intervention, body_limit, decision) == 0)"),
            ("decision->disruptive = intervention->disruptive;", "decision->disruptive = 0;"),
            ("decision->status = intervention->status;", "decision->status = 200;"),
            ("capture_intervention_details(&intervention, phase, decision,\n            response_append_active, response_body_eos) != 0) {\n        msc_intervention_cleanup(&intervention);",
             "capture_intervention_details(&intervention, phase, decision,\n            response_append_active, response_body_eos) != 0) {"),
        )
        for old, new in mutations:
            with self.subTest(mutation=old):
                self.assert_rejected(old, new)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
