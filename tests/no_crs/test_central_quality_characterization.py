"""Behavior characterization only; controlled fixtures are not runtime proof."""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from tests.no_crs.test_configtest_artifacts import contract
from tests.no_crs import test_valid_rules_quality_characterization as valid_rules


class CentralQualityCharacterization(unittest.TestCase):
    def test_configuration_template_and_diagnostic_precedence(self):
        origin = Path("/unit/config")
        for case_id, value in (("invalid_boolean", "maybe"), ("missing_rules_file", '"/unit/config/missing-rules.conf"'),
                               ("invalid_rule_syntax", '"SecRule REQUEST_URI"'),
                               ("phase4_invalid_scope_file", '"/unit/config/invalid-content-type-scope.txt"')):
            with self.subTest(case_id=case_id):
                invocation = contract.NGINX_CONFIGTEST_CONTRACTS[case_id]
                config = (f'load_module "{origin}/nginx-module.so";\n'
                          f'pid "{origin}/nginx.pid";\nerror_log "{origin}/nginx-error.log";\n'
                          f"events {{}}\nhttp {{\n  {invocation['directive']} {value};\n}}\n").encode()
                captures = {"nginx.conf": config, "stderr.log": b"wrong diagnostic"}
                # Non-PASS retains the closed template but needs no successful diagnostic.
                self.assertIsNone(contract.validate_configtest_bundle_template(
                    {"case_id": case_id, "status": "FAIL"}, origin, captures, canonical=False))
                with self.assertRaisesRegex(contract.ContractError, "^configuration capture lacks the exact parser diagnostic$"):
                    contract.validate_configtest_bundle_template(
                        {"case_id": case_id, "status": "PASS"}, origin, captures, canonical=False)
                changed = {**captures, "nginx.conf": config + b"extra"}
                with self.assertRaisesRegex(contract.ContractError, "^configuration artifact is not the closed nonsecret template$"):
                    contract.validate_configtest_bundle_template(
                        {"case_id": case_id, "status": "PASS"}, origin, changed, canonical=False)
                with self.assertRaisesRegex(contract.ContractError, "^configuration template does not bind its retained module$"):
                    contract.validate_configtest_bundle_template(
                        {"case_id": case_id, "status": "FAIL"}, Path("/foreign"), captures, canonical=False)

    def test_specialized_pass_routes_preserve_early_return_order(self):
        catalog = contract.catalog_cases(contract.load_catalog())
        native_case = next(case for case in catalog if "native_invocations" in case)
        record = {"case_id": native_case["case_id"], "status": "PASS", "native_operation_receipt": {}}
        with mock.patch.object(contract, "native_operation_record_errors", return_value=["proof failed"]):
            self.assertEqual(contract.pass_case_completeness_errors(record, [], "nginx", None), [
                native_case["case_id"] + ": proof failed"])
        record.pop("native_operation_receipt")
        self.assertEqual(contract.pass_case_completeness_errors(
            record, [], "nginx", None, require_native_operation_contract=True), [
            native_case["case_id"] + ": selected native contract requires genuine retained operation evidence"])
        with mock.patch.object(contract, "configtest_receipt_errors", return_value=["receipt failed"]), mock.patch.object(
                contract, "configtest_artifact_errors", return_value=["artifact failed"]):
            self.assertEqual(contract.pass_case_completeness_errors(
                {"case_id": "invalid_boolean", "status": "PASS"}, [], "nginx", None), [
                "invalid_boolean: receipt failed", "invalid_boolean: artifact failed"])

    def test_selected_invocation_errors_preserve_identity_order_and_runner_guards(self):
        case = {"case_id": "unit", "runner_case": "missing.yaml"}
        with mock.patch.object(contract, "native_invocation_for_case", return_value=None), mock.patch.object(
                contract, "derived_invocation_for_case", return_value=None):
            self.assertEqual(contract.selected_case_invocation_errors({}, case, "nginx"), [])
            selection = {"selection_status": "SELECTED", "case_id": "foreign", "runner_case": True,
                         "native_invocation": {}, "derived_invocation": {}, "config_invocation": {}}
            self.assertEqual(contract.selected_case_invocation_errors(selection, case, "nginx"), [
                "unit: selected invocation case identity mismatch",
                "unit: selected native invocation differs from its closed case contract",
                "unit: selected derived invocation differs from its closed existing contract",
                "unit: selected config invocation differs from its closed case contract",
                "unit: selected runner differs from its declared case source",
                "unit: runner_case must be a declared relative YAML path",
            ])
            for runner in ("missing.yaml", "../outside.yaml", "/outside.yaml", "no-crs-baseline.json"):
                with self.subTest(runner=runner):
                    case["runner_case"] = runner
                    selected = {"selection_status": "SELECTED", **case}
                    self.assertEqual(contract.selected_case_invocation_errors(selected, case, "nginx"), [
                        "unit: runner_case must be an existing catalog-local YAML file"])
            case.pop("runner_case")
            self.assertEqual(contract.selected_case_invocation_errors(
                {"selection_status": "SELECTED", **case}, case, "nginx"), [
                "unit: selected NGX case has no native_invocation, config_invocation, derived_invocation or runner_case"])

    def test_invocation_contract_error_replaces_earlier_identity_errors(self):
        selected = {"selection_status": "SELECTED", "case_id": "foreign"}
        with mock.patch.object(contract, "native_invocation_for_case", side_effect=contract.ContractError("closed failure")):
            self.assertEqual(contract.selected_case_invocation_errors(selected, {"case_id": "unit"}, "nginx"), ["closed failure"])

    def test_native_status_reason_branches(self):
        case = {"case_id": "unit"}
        facts = {"unit": "facts"}
        with mock.patch.object(contract, "native_invocation_for_case", return_value={}), mock.patch.object(
                contract, "native_operation_projection", return_value=facts), mock.patch.object(
                contract, "native_effective_case", return_value=case), mock.patch.object(
                contract, "native_operation_record_base", side_effect=lambda raw, case, connector, facts, status, reason: (facts, status, reason)):
            verified_reason = "verified source-bound native operation and original retained bytes"
            rows = (
                ("FAIL", [], "FAIL", "original native invocation FAIL"),
                ("FAIL", ["first", "second"], "FAIL", "original native invocation FAIL"),
                ("BLOCKED", [], "BLOCKED", "original native invocation BLOCKED"),
                ("BLOCKED", ["first", "second"], "BLOCKED", "original native invocation BLOCKED"),
                ("NOT_EXECUTED", [], "PASS", verified_reason),
                ("NOT_EXECUTED", ["first", "second"], "FAIL", "first; second"),
                ("PASS", [], "PASS", verified_reason),
                ("PASS", ["first", "second"], "FAIL", "first; second"),
            )
            for initial, errors, expected_status, expected_reason in rows:
                with self.subTest(initial=initial, errors=errors), mock.patch.object(
                        contract, "native_operation_expectation_errors", return_value=errors):
                    result = contract.normalize_native_operation_record({"status": initial}, case, "nginx", {})
                    self.assertEqual(result, (facts, expected_status, expected_reason))

    def test_native_failure_branches_and_missing_authority(self):
        case = {"case_id": "unit"}
        rows = (("FAIL", None, "FAIL"), ("FAIL", {}, "FAIL"),
                ("BLOCKED", None, "BLOCKED"), ("BLOCKED", {}, "BLOCKED"),
                ("NOT_EXECUTED", None, "NOT_EXECUTED"), ("NOT_EXECUTED", {}, "FAIL"),
                ("PASS", None, "FAIL"), ("PASS", {}, "FAIL"))
        with mock.patch.object(contract, "native_invocation_for_case", return_value={}), mock.patch.object(
                contract, "native_operation_projection", side_effect=ValueError("proof failure")), mock.patch.object(
                contract, "native_operation_record_base", side_effect=lambda raw, case, connector, facts, status, reason: (facts, status, reason)):
            for initial, authority, expected in rows:
                with self.subTest(initial=initial, authority=authority):
                    result = contract.normalize_native_operation_record({"status": initial}, case, "nginx", authority)
                    self.assertEqual(result, (None, expected, "proof failure"))

    def test_generic_pass_completeness_keeps_order(self):
        record = {"status": "PASS", "case_id": "allow_without_marker", "expected_status": 200,
                  "actual_status": 201, "expected_rule_id": 1100001, "expected_event_fields": ["phase"]}
        with mock.patch.object(contract, "canonical_event_errors", return_value=["invalid native"]), mock.patch.object(
                contract, "case_event_identity_errors", return_value=["foreign phase"]), mock.patch.object(
                contract, "full_lifecycle_pass_errors", return_value=["lifecycle missing"]):
            self.assertEqual(contract.pass_case_completeness_errors(record, [], "nginx", None), [
                "allow_without_marker: PASS requires live_executed=true",
                "allow_without_marker: PASS status mismatch",
                "allow_without_marker: PASS missing expected rule ID 1100001",
                "allow_without_marker: PASS missing expected event fields",
                "allow_without_marker: foreign phase", "allow_without_marker: invalid native",
                "allow_without_marker: lifecycle missing",
            ])
            self.assertEqual(contract.pass_case_completeness_errors({"status": "FAIL"}, [], "nginx", None), [])

    def test_finalize_keeps_retention_order_and_missing_native_failure(self):
        case = {"case_id": "unit"}
        context = SimpleNamespace(case_by_id={"unit": case}, connector="nginx", event_integration_mode=None,
                                  run_dir=Path("/unit"), manifest={"integration_mode": "native"},
                                  artifact_profile="full_lifecycle", plan={"cases": [{"case_id": "unit", "selection_status": "SELECTED"}]})
        raw = {"case_id": "unit", "configtest_receipt": {}, "native_operation_receipt": {}}
        calls = []
        def retained(label):
            def callback(ctx, row):
                calls.append(label)
                return row
            return callback
        with mock.patch.object(contract, "retain_finalize_configtest_bundle", side_effect=retained("config")), mock.patch.object(
                contract, "retain_finalize_native_operation_bundle", side_effect=retained("native")), mock.patch.object(
                contract, "normalize_case_record", side_effect=lambda *a, **kw: {"case_id": "unit", "status": "PASS", "reason": ""}), mock.patch.object(
                contract, "native_invocation_for_case", return_value={}):
            self.assertEqual(contract.normalized_finalize_case_records(context, [raw], [])[0]["status"], "PASS")
            self.assertEqual(calls, ["config", "native"])
            result = contract.normalized_finalize_case_records(context, [{"case_id": "unit"}], [])
            self.assertEqual(result[0]["status"], "FAIL")
            self.assertEqual(result[0]["reason"], "runtime evidence invalid: selected native case requires its original source-bound operation bundle")


class ProbeCharacterization(valid_rules.ValidRulesQualityCharacterization):
    def test_unrelated_event_and_duplicate_same_transaction_are_not_ambiguous(self):
        import json
        record = self.unit_bundle()
        captures = self.captures(record)
        original = json.loads(captures["phase1-events.jsonl"])
        unrelated = {**original, "rule_id": 1100002}
        captures["phase1-events.jsonl"] += json.dumps(unrelated).encode() + b"\n" + json.dumps(original).encode() + b"\n"
        self.assertIsNone(valid_rules.receipt_tests.contract.validate_valid_rules_probe(record, captures))


if __name__ == "__main__":
    unittest.main()
