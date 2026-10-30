"""Synthetic source-review normalization never supplies historical oracle/host proof."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = connector_root()
HERE = source_path('ci/runtime/lifecycle/i12/envoy', root=ROOT)


def load_validator():
    previous = list(sys.path)
    sys.path.insert(0, str(HERE))
    try:
        module = load_source(HERE / 'validate_oracles.py')
        return module
    finally:
        sys.path[:] = previous


VALIDATOR = load_validator()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
    return path


def reference(path):
    raw = path.read_bytes()
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


class EnvoySourceReviewOfflineTests(unittest.TestCase):
    def setUp(self):
        parent = os.environ.get("RUNNER_TEMP") or os.environ.get("TMPDIR")
        self.assertTrue(parent, "explicit external private temporary root required")
        temporary = tempfile.TemporaryDirectory(prefix="envoy-source-review-", dir=parent)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.assertFalse(self.root.is_relative_to(ROOT))
        boundary = mock.patch.object(VALIDATOR, "STORAGE_ROOTS", (self.root,))
        boundary.start()
        self.addCleanup(boundary.stop)
        self.source = write(self.root / "source/offline-input.c",
                            b"int offline_input(void) { return 1; }\n/* unit data only; never compiled */\n")
        self.source_reference = {**reference(self.source), "line": 1, "symbol": "offline_input",
                                 "claim": "Synthetic source reference; actual historical oracle remains unknown."}
        self.binding_file = write(self.root / "fixture-input.json", {"offline_unit_fixture": True})
        self.baseline = self.root / "baseline.json"
        self.reviews = []
        baseline_rows = []
        self.documents = {}
        for route, (total, selected) in VALIDATOR.ROUTES.items():
            rows = []
            for index in range(total):
                identity = "I12::" + route + "::NEED-offline-" + str(index)
                if route == VALIDATOR.SUPPLEMENT_ROUTE and index == 0:
                    identity = VALIDATOR.SUPPLEMENT_ID
                original = {"scope": "synthetic unit baseline", "historical_host_oracle": "unknown"}
                row = {"run_scoped_case_id": identity, "leg_id": route,
                       "original_oracle_member": index < selected, "original_oracle": original,
                       "oracle_review": {"resolved": index == 0,
                                         "effective_oracle": {"synthetic": "retained"} if index == 0 else None},
                       "qualified_host_lifecycle_pass": index == 0}
                baseline_rows.append(row)
                if index >= selected:
                    continue
                review = {"run_scoped_case_id": identity, "route": route,
                          "original_oracle": copy.deepcopy(original), "lifecycle_qualified": False,
                          "host_lifecycle_qualified": False, "canonical_ledger_resolution_changed": False,
                          "existing_canonical_oracle_resolved": index == 0,
                          "source_refs": [copy.deepcopy(self.source_reference)],
                          "remaining_requirements": ["Actual host qualification and historical oracle remain outside this unit."],
                          "category": "OPEN", "effective_oracle": None, "source_oracle_resolved": False}
                if index == 0:
                    review.update(category="SOURCE_SEMANTICS_CONFIRMED",
                                  effective_oracle={"synthetic": "retained"}, source_oracle_resolved=True)
                elif index == 1:
                    review.update(category="FIXTURE_PENDING", effective_oracle={"synthetic": "partial"},
                                  fixture_binding={"origin": "new_task_fixture_binding", "original_id": identity,
                                                   "route": route, "files": [reference(self.binding_file)]})
                elif index == 2:
                    review["category"] = "SOURCE_SEMANTICS_CONFIRMED"
                rows.append(review)
            document = {"route": route, "records": rows, "lifecycle_qualification_performed": False,
                        "canonical_oracle_inventory_changed": False, "summary": {"new_lifecycle_pass": 0}}
            self.documents[route] = document
            self.reviews.append(self.root / (route + "-review.json"))
        write(self.baseline, {"rows": baseline_rows, "offline_unit_fixture": True})
        self._save_reviews()

    def _save_reviews(self):
        baseline_hash = reference(self.baseline)["sha256"]
        for path, document in zip(self.reviews, self.documents.values()):
            document["baseline_sha256"] = baseline_hash
            write(path, document)

    def validate(self):
        return VALIDATOR.validate(self.baseline, self.reviews)

    def _supplement(self):
        origin = self.reviews[list(VALIDATOR.ROUTES).index(VALIDATOR.SUPPLEMENT_ROUTE)]
        original = self.documents[VALIDATOR.SUPPLEMENT_ROUTE]["records"][0]
        row = copy.deepcopy(original)
        fixture = self.root / "new-fixture"
        shape = write(fixture / "shape.json", {"leg": VALIDATOR.SUPPLEMENT_ROUTE,
                      "parent_sha": "a" * 40, "original_case_ids": [VALIDATOR.SUPPLEMENT_ID]})
        request = write(fixture / "request.raw", b"GET /offline HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n")
        ledger = write(self.root / "seals/new-fixture-ledger.json", {"files": {
            "shape.json": reference(shape)["sha256"], "request.raw": reference(request)["sha256"]}})
        admission = write(self.root / "seals/new-fixture-admission.json", {"bindings": [{
            "target": "/mnt/fixtures", "source": str(fixture), "ledger": str(ledger),
            "ledger_sha256": reference(ledger)["sha256"]}]})
        row["fixture_binding"] = {"origin": "new_task_fixture_binding", "original_id": VALIDATOR.SUPPLEMENT_ID,
                                  "route": VALIDATOR.SUPPLEMENT_ROUTE,
                                  "files": [reference(path) for path in (shape, request, ledger, admission)]}
        path = write(self.root / "supplement.json", {"schema": VALIDATOR.SUPPLEMENT_SCHEMA,
                     "route": VALIDATOR.SUPPLEMENT_ROUTE, "records": [row], "origin_review": reference(origin),
                     "lifecycle_qualification_performed": False, "canonical_oracle_inventory_changed": False,
                     "host_lifecycle_qualified": False, "new_lifecycle_pass": 0})
        return path

    def test_complete_reviews_preserve_the_supplied_baseline_without_new_host_oracle_credit(self):
        before = self.baseline.read_bytes()
        result = self.validate()
        self.assertEqual(result["reviewed_count"], 125)
        self.assertEqual(result["baseline_total_ids"], 284)
        self.assertEqual((result["canonical_resolved"], result["canonical_open"]), (3, 122))
        self.assertEqual(result["proposed_new_source_oracles"], 0)
        self.assertEqual(result["new_lifecycle_pass"], 0)
        self.assertFalse(result["canonical_resolution_changed"])
        self.assertEqual(result["existing_lifecycle_pass"], 3)
        self.assertEqual(self.baseline.read_bytes(), before)
        self.assertTrue(all(not row["lifecycle_qualified"] for row in result["normalized_rows"]))
        self.assertTrue(all(not row["canonical_resolution_changed"] for row in result["normalized_rows"]))
        for route, (_, count) in VALIDATOR.ROUTES.items():
            summary = result["routes"][route]
            self.assertEqual(summary["reviewed_count"], count)
            self.assertEqual(summary["proposed_new_source_oracles"], 0)
            self.assertEqual(len(summary["partial_oracle_proposal_ids"]), 1)
            self.assertEqual(len(summary["source_boundary_only_ids"]), 1)
        selected = result["normalized_rows"][1]
        self.assertFalse(selected["canonical_oracle_resolved"])
        self.assertEqual(selected["source_refs"][0]["sha256"], reference(self.source)["sha256"])
        self.assertTrue(selected["source_refs"][0]["verified"])
        self.assertEqual(selected["fixture_binding"]["references"][0], {**reference(self.binding_file), "verified": True})
        self.assertEqual(result["input_reviews"][0]["sha256"], reference(self.reviews[0])["sha256"])

    def test_supplement_verifies_origin_and_complete_private_fixture_without_promoting_it(self):
        validated = self.validate()
        path = self._supplement()
        result = VALIDATOR.validate_supplement(path, validated)
        self.assertFalse(result["canonical_resolution_changed"])
        self.assertEqual(result["new_lifecycle_pass"], 0)
        self.assertEqual(result["origin_review"], reference(self.reviews[2]))
        row = result["normalized_rows"][0]
        self.assertFalse(row["lifecycle_qualified"])
        self.assertEqual(row["run_scoped_case_id"], VALIDATOR.SUPPLEMENT_ID)
        self.assertEqual(len(row["fixture_binding"]["references"]), 4)
        self.assertEqual(row["source_refs"][0]["sha256"], reference(self.source)["sha256"])
        self.assertFalse(row["proposed_new_source_oracle"])

    def test_duplicate_baseline_identity_is_rejected(self):
        document = json.loads(self.baseline.read_bytes())
        document["rows"][1]["run_scoped_case_id"] = document["rows"][0]["run_scoped_case_id"]
        write(self.baseline, document)
        with self.assertRaisesRegex(ValueError, "duplicate original baseline ID"):
            self.validate()

    def test_changed_physical_source_reference_is_rejected(self):
        self.source.write_bytes(b"changed source\n")
        with self.assertRaisesRegex(ValueError, "reference SHA256 mismatch"):
            self.validate()

    def test_new_fixture_binding_cannot_name_a_sibling_original(self):
        row = self.documents["envoy-ext-proc"]["records"][1]
        row["fixture_binding"]["original_id"] = self.documents["envoy-ext-proc"]["records"][2]["run_scoped_case_id"]
        self._save_reviews()
        with self.assertRaisesRegex(ValueError, "fixture binding names a different original ID"):
            self.validate()

    def test_source_review_cannot_turn_a_row_into_host_qualification(self):
        self.documents["envoy-ext-proc"]["records"][1]["host_lifecycle_qualified"] = True
        self._save_reviews()
        with self.assertRaisesRegex(ValueError, "source row invents lifecycle"):
            self.validate()

    def test_source_review_cannot_omit_remaining_host_requirements(self):
        self.documents["envoy-ext-proc"]["records"][1]["remaining_requirements"] = []
        self._save_reviews()
        with self.assertRaisesRegex(ValueError, "remaining host requirements must remain explicit"):
            self.validate()

    def test_supplement_admission_cannot_substitute_the_fixture_ledger(self):
        validated = self.validate()
        path = self._supplement()
        document = json.loads(path.read_bytes())
        files = document["records"][0]["fixture_binding"]["files"]
        record = next(item for item in files if item["path"].endswith("-admission.json"))
        admission = Path(record["path"])
        value = json.loads(admission.read_bytes())
        value["bindings"][0]["ledger_sha256"] = "0" * 64
        write(admission, value)
        record.update(reference(admission))
        write(path, document)
        with self.assertRaisesRegex(ValueError, "supplement admission fixture binding differs"):
            VALIDATOR.validate_supplement(path, validated)

    def test_supplement_cannot_rewrite_the_normalized_source_semantics(self):
        validated = self.validate()
        path = self._supplement()
        document = json.loads(path.read_bytes())
        document["records"][0]["source_refs"][0]["claim"] = "different synthetic source claim"
        write(path, document)
        with self.assertRaisesRegex(ValueError, "supplement changed source semantics"):
            VALIDATOR.validate_supplement(path, validated)


# Parent default discovery uses the one admitted active-case inventory.
if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
