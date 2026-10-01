"""A configuration subprocess does not prove an HTTP request or daemon start."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "no_crs_configtest_runtime_facts", ROOT / "ci/checks/catalog/no_crs_baseline.py"
)
assert SPEC is not None and SPEC.loader is not None
no_crs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(no_crs)
RECEIPT_SPEC = importlib.util.spec_from_file_location(
    "configtest_unit_receipt_fixture", Path(__file__).with_name("test_configtest_receipt.py")
)
assert RECEIPT_SPEC is not None and RECEIPT_SPEC.loader is not None
fixture = importlib.util.module_from_spec(RECEIPT_SPEC)
RECEIPT_SPEC.loader.exec_module(fixture)


class ConfigtestRuntimeFactsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.cases = {case["case_id"]: case for case in no_crs.catalog_cases(no_crs.load_catalog())}
        self.receipt_fixture = fixture.ConfigtestReceiptTest()
        self.receipt_fixture.setUp()
        self.addCleanup(self.receipt_fixture.doCleanups)
        raw = self.receipt_fixture.valid_raw()
        self.config = no_crs.normalize_case_record(
            raw, "nginx", self.cases, [], "native-nginx-http-module",
            configtest_artifact_root=self.receipt_fixture.artifact_root,
        )
        self.assertEqual(self.config["status"], "PASS", self.config["reason"])
        self.request = {"case_id": "allow_without_marker", "connector": "nginx",
                        "status": "PASS", "live_executed": True, "required_capabilities": [],
                        "observed_rule_ids": [], "transaction_ids": [], "actual_status": 200}

    def summarize(self, records, source_started=False):
        context = SimpleNamespace(
            connector="nginx", event_integration_mode="native-nginx-http-module",
            case_by_id=self.cases, capabilities={"capabilities": {}},
            plan={"cases": [{"case_id": record["case_id"], "selection_status": "SELECTED"}
                            for record in records]}, evidence_stage="no_crs_baseline",
            manifest={"host_version": "nginx-unit", "libmodsecurity_version": "modsecurity-unit"})
        arguments = argparse.Namespace(stage_rc=0, host_version=None, libmodsecurity_version=None)
        # This test concerns operation facts, not the unrelated global PASS gate.
        with mock.patch.object(no_crs, "finalize_pass_gate", return_value=("PASS", False, [])):
            return no_crs.build_finalize_summary(
                context, arguments, records, {record["case_id"]: record for record in records},
                [{"started": source_started}], [], None)

    def test_config_only_summary_does_not_claim_requests_or_started(self):
        summary = self.summarize([self.config])
        self.assertFalse(summary.requests_sent)
        self.assertFalse(summary.started)
        facts, _ = no_crs.status_record_facts([self.config])
        self.assertFalse(facts["requests_sent"])

    def test_config_only_status_facts_do_not_claim_requests(self):
        facts, _ = no_crs.status_record_facts([self.config])
        self.assertFalse(facts["requests_sent"])

    def test_mixed_real_request_fact_remains_true(self):
        summary = self.summarize([self.config, self.request])
        self.assertTrue(summary.requests_sent)
        self.assertTrue(summary.started)
        facts, _ = no_crs.status_record_facts([self.config, self.request])
        self.assertTrue(facts["requests_sent"])

    def test_explicit_source_started_is_retained_without_claiming_request(self):
        summary = self.summarize([self.config], source_started=True)
        self.assertTrue(summary.started)
        self.assertFalse(summary.requests_sent)

    def test_forged_receipt_does_not_relabel_http_case(self):
        self.request["configtest_receipt"] = fixture.ConfigtestReceiptTest.receipt()
        facts, _ = no_crs.status_record_facts([self.request])
        self.assertTrue(facts["requests_sent"])
        self.assertTrue(self.summarize([self.request]).requests_sent)

    def test_other_host_keeps_legacy_live_execution_fact(self):
        self.config["connector"] = "apache"
        facts, _ = no_crs.status_record_facts([self.config])
        self.assertTrue(facts["requests_sent"])


if __name__ == "__main__":
    unittest.main()
