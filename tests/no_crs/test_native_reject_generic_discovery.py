"""Native fixture applicability is distinct from native execution evidence."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/runners"))
import runner_core
from ci.checks.catalog import no_crs_baseline as contract

FIXTURE = ROOT / "tests/cases/connector-specific/nginx/phase4_body_reject.yaml"


class NativeRejectGenericDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.document = runner_core._load_case_mapping(FIXTURE)
        self.cases = {case["case_id"]: case for case in contract.catalog_cases(contract.load_catalog())}

    def test_force_all_generic_discovery_excludes_only_nonmaterializable_inputs(self):
        with patch.dict("os.environ", {"FORCE_ALL_CASES": "1", "MODSECURITY_TEST_VARIANT": "no-crs"}):
            paths = runner_core.discover_case_files(ROOT, "nginx", "all", framework_root=ROOT)
        self.assertNotIn(FIXTURE, paths)
        self.assertIn(ROOT / "tests/cases/connector-specific/nginx/nginx_phase4_deny_after_commit_log_only.yaml", paths)
        self.assertTrue(paths)
        self.assertIs(self.document.get("runtime_materializable"), False)

    def test_none_and_true_do_not_hide_invalid_generic_expectation(self):
        for flag in (None, True):
            document = deepcopy(self.document)
            document["runtime_materializable"] = flag
            with self.subTest(flag=flag):
                self.assertIs(runner_core.is_runtime_materializable(document), True)
                with patch.dict("os.environ", {"FORCE_ALL_CASES": "1"}):
                    self.assertIs(runner_core.is_case_applicable(document, FIXTURE, "nginx", "all"), True)
                expected_error = "runtime_materializable must be a boolean" if flag is None else "integer expect.status"
                with self.assertRaisesRegex(ValueError, expected_error):
                    runner_core.validate_case(document, FIXTURE)

    def test_explicit_false_does_not_weaken_direct_validation(self):
        self.assertEqual(self.document["expect"], {})
        self.assertIs(runner_core.is_runtime_materializable(self.document), False)
        with self.assertRaisesRegex(ValueError, "non-materializable case requires capabilities.runtime_verified=false"):
            runner_core.validate_case(self.document, FIXTURE)

    def test_same_case_remains_required_selected_native_not_yaml(self):
        case = self.cases["phase4_body_reject"]
        capabilities = {name: {"state": "verified", "reason": "controlled selection only"}
                        for name in contract.CAPABILITIES}
        selected = contract.select_catalog_case(case, capabilities, "http1", "nginx")
        self.assertEqual(selected["case_id"], "phase4_body_reject")
        self.assertEqual(selected["required_capabilities"], case["required_capabilities"])
        self.assertEqual(selected["selection_status"], "SELECTED")
        self.assertIsNone(selected["runner_case"])
        self.assertEqual(selected["native_invocation"], case["native_invocations"]["nginx"])
        self.assertEqual(contract.selected_case_invocation_errors(selected, case, "nginx"), [])

    def test_missing_original_native_evidence_cannot_certify_pass(self):
        raw = {"case_id": "phase4_body_reject", "status": "PASS", "live_executed": True,
               "actual_status": 200, "observed_rule_ids": [], "transaction_ids": ["controlled-tx"]}
        with tempfile.TemporaryDirectory(prefix="native-reject-missing-proof-") as temporary:
            context = SimpleNamespace(case_by_id=self.cases, connector="nginx", run_dir=Path(temporary),
                                      artifact_profile="full_lifecycle", native_operation_authority=None,
                                      manifest={"integration_mode": "native-nginx-http-module"},
                                      event_integration_mode="native-nginx-http-module",
                                      plan={"cases": [{"case_id": "phase4_body_reject", "selection_status": "SELECTED"}]})
            record, = contract.normalized_finalize_case_records(context, [raw], [])
        self.assertEqual(record["status"], "FAIL")
        self.assertIn("canonical phase-4 event is missing", record["reason"])
