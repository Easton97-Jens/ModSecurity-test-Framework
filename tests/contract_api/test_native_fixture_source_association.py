"""Inventory-only Source association; no native runtime evidence."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from modsecurity_test_framework import contracts


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = "tests/cases/connector-specific/nginx/phase4_body_reject.yaml"
CASE_ID = "phase4_body_reject"
TEST_ID = "no-crs-baseline:" + CASE_ID


class NativeFixtureSourceAssociationTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "source_association_generator", ROOT / "ci/tools/generate-framework-contract-catalog.py")
        self.generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.generator)
        self.records, self.ids = self.generator._catalog_source_records()
        self.path, self.document = self.generator._read_yaml_case(ROOT / FIXTURE)
        self.original = deepcopy(self.records[TEST_ID])

    def association(self, document=None, path=None):
        return self.generator._yaml_record(
            self.document if document is None else document,
            self.path if path is None else path, self.ids)

    def test_actual_deferred_fixture_is_only_a_native_source_association(self):
        test_id, marker, merge = self.association()
        self.assertEqual(test_id, TEST_ID)
        self.assertTrue(merge)
        self.generator._merge_yaml_record(self.records, test_id, marker, merge, self.path)
        associated = self.records[TEST_ID]
        for key in ("expectation", "phase", "required_capabilities", "applicability"):
            self.assertEqual(associated[key], self.original[key])
        self.assertEqual(associated["sources"][-1], {"kind": "native_operation_fixture", "path": FIXTURE})
        self.assertEqual(associated["catalogs"], ["no-crs-baseline", "framework-yaml"])
        self.assertEqual(set(self.records), {"no-crs-baseline:" + case_id for case_id in self.ids})

    def test_source_shape_is_accepted_without_new_public_api_expectation(self):
        test_id, marker, merge = self.association()
        self.generator._merge_yaml_record(self.records, test_id, marker, merge, self.path)
        data = json.loads(self.generator.DEFAULT_OUTPUT.read_text())
        data["tests"] = [self.records[test_id] if row["framework_test_id"] == test_id else row
                         for row in data["tests"]]
        described = contracts.describe_test(TEST_ID, catalog_data=data)
        self.assertEqual(described["test"]["expectation"], contracts.normalize_expectation(self.original["expectation"]))
        self.assertEqual(described["test"]["sources"][-1]["kind"], "native_operation_fixture")
        self.assertEqual(set(described["test"]), set(self.original) | {"expectation_type"})
        self.assertEqual(json.dumps(described, sort_keys=True),
                         json.dumps(contracts.describe_test(TEST_ID, catalog_data=data), sort_keys=True))

    def test_foreign_fixture_identity_and_obsolete_expectation_fail(self):
        mutations = (
            lambda doc: doc.update(connector="apache"),
            lambda doc: doc.update(connector=None),
            lambda doc: doc.update(name="other_case"),
            lambda doc: doc.update(phase=1),
            lambda doc: doc.update(category="generic-smoke"),
            lambda doc: doc.update(no_crs_baseline=False),
            lambda doc: doc.update(phase=4.0),
            lambda doc: doc["nginx"].update(phase4_mode="off"),
            lambda doc: doc["capabilities"].update(phase4=False),
            lambda doc: doc["capabilities"].update(phase4=1),
            lambda doc: doc.update(expect={"status": 200}),
            lambda doc: doc.update(expect={"status": 403, "rule_id": 1100301}),
            lambda doc: doc["full_lifecycle"].update(engine_response_body_limit=65),
            lambda doc: doc["full_lifecycle"].update(engine_response_body_limit=64.0),
            lambda doc: doc["full_lifecycle"].update(engine_response_body_limit_action="ProcessPartial"),
            lambda doc: doc["full_lifecycle"].update(evidence_status="passed"),
            lambda doc: doc["full_lifecycle"].update(requires_real_host_chunk_driver=False),
            lambda doc: doc.pop("full_lifecycle"),
            lambda doc: doc.update(rules=doc["rules"].replace("SecResponseBodyLimitAction Reject", "SecResponseBodyLimitAction ProcessPartial")),
            lambda doc: doc.update(rules=doc["rules"].replace("SecResponseBodyLimit 64", "SecResponseBodyLimit 65")),
            lambda doc: doc.update(rules=doc["rules"] + "SecResponseBodyLimitAction Reject\n"),
            lambda doc: doc.update(rules=doc["rules"].replace("SecRuleEngine On", "SecRuleEngine Off")),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                document = deepcopy(self.document)
                mutation(document)
                with self.assertRaises(self.generator.GenerationError):
                    self.association(document)

    def test_foreign_source_path_and_arbitrary_empty_placeholder_fail(self):
        for path in ("tests/cases/connector-specific/nginx/other.yaml",
                     "tests/cases/connector-specific/apache/phase4_body_reject.yaml"):
            with self.subTest(path=path), self.assertRaises(self.generator.GenerationError):
                self.association(path=path)
        document = deepcopy(self.document)
        document.update(name="foreign_placeholder", category="generic-smoke")
        with self.assertRaises(self.generator.GenerationError):
            self.association(document, "tests/cases/connector-specific/nginx/foreign_placeholder.yaml")

    def test_missing_or_contradictory_catalog_native_descriptor_fail(self):
        source = self.generator._read_json(self.generator.CATALOG_PATH)
        mutations = (
            lambda case: case.pop("native_invocations"),
            lambda case: case["native_invocations"]["nginx"].update(operation="request_sequence"),
            lambda case: case["native_invocations"]["nginx"].update(contract_case_id="phase4_body_at_limit"),
            lambda case: case["native_invocations"]["nginx"]["expected_overrides"].update(expected_rule_id=1100301),
            lambda case: case["native_invocations"]["nginx"]["expected_overrides"].update(expected_status=403),
            lambda case: case["native_invocations"]["nginx"]["expected_overrides"].update(expected_native_status=200),
            lambda case: case["native_invocations"]["nginx"]["expected_overrides"].update(expected_engine_error_class="engine_timeout"),
        )
        read = self.generator._read_json
        for index, mutation in enumerate(mutations):
            changed = deepcopy(source)
            mutation(next(case for case in changed["cases"] if case["case_id"] == CASE_ID))
            def read_changed(path):
                return changed if path == self.generator.CATALOG_PATH else read(path)
            with self.subTest(index=index), patch.object(self.generator, "_read_json", side_effect=read_changed):
                with self.assertRaises(self.generator.GenerationError):
                    self.association()

    def test_generated_catalog_is_deterministic_and_payload_free(self):
        serialized = self.generator._serialized_catalog()
        self.assertEqual(serialized, self.generator._serialized_catalog())
        self.assertNotIn(self.document["rules"], serialized)
        self.assertNotIn(self.document["response"]["body"], serialized)
        self.assertNotIn("expected_native_status", serialized)


if __name__ == "__main__":
    unittest.main()
