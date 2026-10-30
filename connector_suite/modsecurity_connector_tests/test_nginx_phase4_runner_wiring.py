from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import os
from pathlib import Path
import tempfile
import unittest

from modsecurity_connector_tests.framework_test_trust import trusted_framework_root


ROOT = connector_root()
FRAMEWORK_ROOT = Path(
    os.environ.get("PARENT_TEST_FRAMEWORK_ROOT", source_path('modules/ModSecurity-test-Framework', root=ROOT))
)


def load_framework_runner_core(framework_root: Path) -> object:
    """Load the caller-validated Framework runner through its public namespace."""
    return load_source(framework_root / "tests/runners/runner_core.py")

class NginxPhase4RunnerWiringTest(unittest.TestCase):
    def trusted_runner_context(self) -> tuple[object, Path]:
        framework_root, error = trusted_framework_root(ROOT, FRAMEWORK_ROOT)
        if framework_root is None:
            self.skipTest(error)
        return load_framework_runner_core(framework_root), framework_root

    def load_fixture(self, filename: str):
        runner_core, framework_root = self.trusted_runner_context()
        fixtures = framework_root / "tests" / "cases" / "connector-specific" / "nginx"
        return runner_core.load_case(fixtures / filename)

    def test_safe_fixture_records_a_real_late_log_only_outcome(self) -> None:
        case = self.load_fixture("nginx_phase4_deny_after_commit_log_only.yaml")
        expect = case["expect"]
        phase4_log = expect["phase4_log"]

        self.assertEqual(case["name"], "phase4_deny_after_commit_log_only")
        self.assertTrue(case["no_crs_baseline"])
        self.assertEqual(case["nginx"]["phase4_mode"], "safe")
        self.assertEqual(expect["status"], 200)
        self.assertEqual(expect["transport"], "http_status")
        self.assertIn("event", case["expected_event_fields"])
        self.assertIn("message_id", case["expected_event_fields"])
        self.assertIn('"message_id":"MSCONN_EVENT_PHASE4_LATE_INTERVENTION"', phase4_log["contains"])
        self.assertIn('"actual_action":"log_only"', phase4_log["contains"])
        self.assertIn('"visible_http_status":200', phase4_log["contains"])
        self.assertIn('"connection_aborted":false', phase4_log["contains"])
        self.assertIn("no-crs-response-body-marker", phase4_log["not_contains"])
        self.assertIn('"intervention_log":', phase4_log["not_contains"])

    def test_strict_fixture_asserts_abort_transport_not_a_rewritten_403(self) -> None:
        case = self.load_fixture("nginx_phase4_deny_after_commit_abort.yaml")
        expect = case["expect"]
        phase4_log = expect["phase4_log"]

        self.assertEqual(case["name"], "phase4_deny_after_commit_abort")
        self.assertTrue(case["no_crs_baseline"])
        self.assertEqual(case["nginx"]["phase4_mode"], "strict")
        self.assertEqual(expect["status"], 200)
        self.assertEqual(expect["transport"], "connection_aborted")
        self.assertIn("event", case["expected_event_fields"])
        self.assertIn("message_id", case["expected_event_fields"])
        self.assertIn('"message_id":"MSCONN_EVENT_PHASE4_HARD_ABORT_AFTER_200"', phase4_log["contains"])
        self.assertIn('"actual_action":"abort_connection"', phase4_log["contains"])
        self.assertIn('"visible_http_status":200', phase4_log["contains"])
        self.assertIn('"connection_aborted":true', phase4_log["contains"])
        self.assertIn('"transport_result":"connection_aborted"', phase4_log["contains"])
        self.assertIn("no-crs-response-body-marker", phase4_log["not_contains"])

    def test_generic_case_environment_carries_only_the_reviewed_mode(self) -> None:
        case = self.load_fixture("nginx_phase4_deny_after_commit_log_only.yaml")
        runner_core, _ = self.trusted_runner_context()
        with tempfile.TemporaryDirectory() as temporary:
            env_file = Path(temporary) / "case.env"
            runner_core.write_shell_env(case, env_file, output_root=temporary)
            content = env_file.read_text(encoding="utf-8")
        self.assertIn("NGINX_PHASE4_MODE=safe", content)
        self.assertNotIn("actual_action", content)
        self.assertNotIn("visible_http_status", content)

    def test_runner_maps_only_selected_canonical_late_paths(self) -> None:
        harness = (source_path('connectors/nginx/harness/run_nginx_smoke.sh', root=ROOT)).read_text(encoding="utf-8")
        template = (source_path('connectors/nginx/harness/nginx_smoke.conf', root=ROOT)).read_text(encoding="utf-8")
        stage = (source_path('ci/runtime/lifecycle/run-connector-stage.sh', root=ROOT)).read_text(encoding="utf-8")
        baseline = (source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=ROOT)).read_text(encoding="utf-8")

        self.assertIn("NO_CRS_SELECTED_CASE_IDS", baseline)
        self.assertIn("NO_CRS_SELECTED_CASE_IDS", stage)
        self.assertIn("phase4_deny_after_commit_log_only", harness)
        self.assertIn("phase4_deny_after_commit_abort", harness)
        self.assertNotIn("phase4_deny_before_commit)\n                append_smoke_case", harness)
        self.assertIn("@@NGINX_PHASE4_MODE_DIRECTIVE@@", template)
        self.assertIn("@@NGINX_TRANSACTION_ID_DIRECTIVE@@", template)
        self.assertIn(
            "modsecurity_transaction_id nginx-${case_name}-\\$connection-\\$connection_requests;",
            harness,
        )

    def test_precommit_phase4_deny_is_not_declared_for_the_body_filter(self) -> None:
        import json

        manifest = json.loads(
            (source_path('connectors/nginx/capabilities.json', root=ROOT)).read_text(encoding="utf-8")
        )
        declaration = manifest["capabilities"]["phase4_pre_commit_deny"]
        self.assertEqual(declaration["state"], "not_implemented")
        self.assertIn("body filter", declaration["reason"])

    def test_apache_declares_progressive_phase4_and_no_false_precommit_claim(self) -> None:
        import json

        manifest = json.loads(
            (source_path('connectors/apache/capabilities.json', root=ROOT)).read_text(encoding="utf-8")
        )
        streaming = manifest["capabilities"]["response_body_streaming"]
        precommit = manifest["capabilities"]["phase4_pre_commit_deny"]
        no_buffer = manifest["capabilities"]["no_full_response_buffering"]
        self.assertEqual(streaming["state"], "implemented_not_asserted")
        self.assertIn("pre-EOS", streaming["reason"])
        self.assertEqual(precommit["state"], "not_implemented")
        self.assertIn("pre-commit", precommit["reason"])
        self.assertEqual(no_buffer["state"], "implemented_not_asserted")
        self.assertIn("full response brigade", no_buffer["reason"])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
