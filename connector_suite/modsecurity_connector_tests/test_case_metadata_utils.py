from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = connector_root()
CI_LIB = source_path('ci/lib', root=ROOT)


import modsecurity_connector_ci.lib.case_metadata_utils as UTILS
import modsecurity_connector_ci.lib.report_path_safety as report_path_safety


def load_generator(relative_path: str, module_name: str):
    module = load_source(ROOT / relative_path)
    return module


PHASE4 = load_generator(
    "ci/evidence/reports/generate-phase4-hard-abort-capability.py",
    "case_metadata_utils_phase4",
)
REMAINING = load_generator(
    "ci/evidence/reports/generate-remaining-failure-analysis.py",
    "case_metadata_utils_remaining",
)


class StubYaml:
    def __init__(self, value: object | None = None, *, error: Exception | None = None) -> None:
        self.value = value
        self.error = error
        self.calls: list[str] = []

    def safe_load(self, raw: str) -> object:
        self.calls.append(raw)
        if self.error is not None:
            raise self.error
        return self.value


class CaseMetadataUtilsTest(unittest.TestCase):
    def setUp(self) -> None:
        self._safe_roots = set(report_path_safety.SAFE_ROOTS)
        report_path_safety.SAFE_ROOTS.clear()

    def tearDown(self) -> None:
        report_path_safety.SAFE_ROOTS.clear()
        report_path_safety.SAFE_ROOTS.update(self._safe_roots)

    def test_pure_helper_parses_mapping_and_splits_query(self) -> None:
        raw = "request: fixture\n"
        parser = StubYaml(
            {
                "request": {"method": "POST", "path": "/probe?mode=strict"},
                "expect": {"rule_id": 920001},
                "metadata": {"mrts_rule_id": 920002, "phase": 2},
            }
        )

        parsed, request, expect, metadata, path, query = UTILS.parse_case_document(raw, parser)

        self.assertEqual(parsed["request"]["path"], "/probe?mode=strict")
        self.assertEqual(request, {"method": "POST", "path": "/probe?mode=strict"})
        self.assertEqual(expect, {"rule_id": 920001})
        self.assertEqual(metadata, {"mrts_rule_id": 920002, "phase": 2})
        self.assertEqual((path, query), ("/probe", "mode=strict"))
        self.assertEqual(parser.calls, [raw])

    def test_pure_helper_keeps_empty_parser_contract_and_safe_fallbacks(self) -> None:
        empty_parser = StubYaml({})
        defaults = ({}, {}, {}, {}, "-", "-")

        self.assertEqual(UTILS.parse_case_document("", empty_parser), defaults)
        self.assertEqual(empty_parser.calls, [])
        self.assertEqual(UTILS.parse_case_document("", empty_parser, parse_empty=True), defaults)
        self.assertEqual(empty_parser.calls, [""])
        self.assertEqual(UTILS.parse_case_document("fixture", None), defaults)
        self.assertEqual(
            UTILS.parse_case_document("fixture", StubYaml(error=ValueError("invalid YAML"))),
            defaults,
        )
        self.assertEqual(UTILS.parse_case_document("fixture", StubYaml(["not", "a", "mapping"])), defaults)

    def test_pure_helper_normalizes_query_only_request_path(self) -> None:
        parser = StubYaml({"request": {"path": "?key=value"}})

        _, request, _, _, path, query = UTILS.parse_case_document("fixture", parser)

        self.assertEqual(request, {"path": "?key=value"})
        self.assertEqual((path, query), ("/", "key=value"))

    def test_generators_keep_shared_parser_and_safe_path_priority_contracts(self) -> None:
        parsed_case = {
            "rules": 'SecRule ARGS "@rx .+" "id:920001,phase:2,deny"',
            "request": {"method": "GET", "path": "?strict=1"},
            "expect": {"rule_id": 920002, "intervention": "deny"},
            "metadata": {"mrts_rule_id": 920003, "phase": 3, "variables": ["ARGS", "ARGS_NAMES"]},
            "runtime_verified": True,
        }
        parser = StubYaml(parsed_case)
        self.assertIs(PHASE4.parse_case_document, UTILS.parse_case_document)
        self.assertIs(REMAINING.parse_case_document, UTILS.parse_case_document)

        with tempfile.TemporaryDirectory(prefix="case-metadata-utils-") as temporary:
            temporary_root = Path(temporary)
            safe_root = temporary_root / "safe"
            safe_case = safe_root / "cases" / "safe.yaml"
            safe_evidence = safe_root / "evidence.json"
            outside_case = temporary_root / "outside.yaml"
            escaped_case = safe_root / "cases" / "escaped.yaml"
            for path in (safe_case, safe_evidence, outside_case):
                path.parent.mkdir(parents=True, exist_ok=True)
            safe_case.write_text("fixture\n", encoding="utf-8")
            outside_case.write_text("outside\n", encoding="utf-8")
            safe_evidence.write_text(json.dumps({"path": str(safe_case), "runtime_verified": False}), encoding="utf-8")
            escaped_case.symlink_to(outside_case)
            report_path_safety.add_safe_roots(safe_root)

            with mock.patch.object(PHASE4, "yaml", parser), mock.patch.object(REMAINING, "yaml", parser):
                phase4 = PHASE4.case_metadata(
                    {"case_id": "safe", "expected_status": 403, "phase": 9},
                    {"path": str(safe_case), "rule_id": "evidence-rule", "phase": "evidence-phase"},
                )
                remaining = REMAINING.yaml_case_metadata(
                    {"case_id": "safe", "evidence": str(safe_evidence), "phase": 9},
                )
                outside = PHASE4.case_metadata({"case_id": "outside"}, {"path": str(outside_case)})
                escaped = PHASE4.case_metadata({"case_id": "escaped"}, {"path": str(escaped_case)})
                rejected_evidence = REMAINING.yaml_case_metadata(
                    {"case_id": "outside", "evidence": str(outside_case)},
                )

        self.assertEqual(phase4["rule_id"], "evidence-rule")
        self.assertEqual(phase4["phase"], "evidence-phase")
        self.assertEqual(phase4["variable"], "ARGS")
        self.assertEqual((phase4["path"], phase4["query"]), ("/", "strict=1"))
        self.assertEqual(remaining["rule_id"], "920001")
        self.assertEqual(remaining["phase"], "3")
        self.assertEqual(remaining["runtime_verified"], "true")
        self.assertEqual(remaining["variable"], "ARGS")
        self.assertEqual((remaining["path"], remaining["query"]), ("/", "strict=1"))
        for metadata in (outside, escaped, rejected_evidence):
            with self.subTest(case_id=metadata["case_id"]):
                self.assertEqual(metadata["path"], "-")

    def test_phase4_metadata_keeps_evidence_rule_source_and_action_precedence(self) -> None:
        parsed_with_rule = {
            "rules": 'SecRule REQUEST_HEADERS "@rx .+" "id:920001,phase:2,deny"',
            "request": {"method": "POST", "path": "/phase4?strict=1"},
            "expect": {},
            "metadata": {"phase": 3, "variables": ["ARGS", "ARGS_NAMES"]},
        }
        parsed_without_rule = {
            "request": {"method": "GET", "path": "/phase4"},
            "expect": {},
            "metadata": {"phase": 3, "variables": ["ARGS", "ARGS_NAMES"]},
        }

        with tempfile.TemporaryDirectory(prefix="phase4-metadata-") as temporary:
            safe_root = Path(temporary) / "safe"
            case_path = safe_root / "case.yaml"
            case_path.parent.mkdir(parents=True)
            case_path.write_text("fixture\n", encoding="utf-8")
            report_path_safety.add_safe_roots(safe_root)
            with mock.patch.object(PHASE4, "yaml", StubYaml(parsed_with_rule)):
                evidence_first = PHASE4.case_metadata(
                    {"case_id": "evidence", "expected_status": 403, "phase": 9},
                    {"path": str(case_path), "phase": "evidence-phase", "rule_id": "evidence-rule"},
                )
                rule_first = PHASE4.case_metadata(
                    {"case_id": "rule", "expected_status": 403, "phase": 9},
                    {"path": str(case_path)},
                )
            with mock.patch.object(PHASE4, "yaml", StubYaml(parsed_without_rule)):
                source_fallback = PHASE4.case_metadata(
                    {"case_id": "source", "expected_status": 200, "phase": 9},
                    {"path": str(case_path)},
                )

        self.assertEqual(evidence_first["rule_id"], "evidence-rule")
        self.assertEqual(evidence_first["phase"], "evidence-phase")
        self.assertEqual(evidence_first["variable"], "REQUEST_HEADERS")
        self.assertEqual(evidence_first["expected_action"], "deny")
        self.assertEqual((rule_first["phase"], rule_first["variable"]), ("2", "REQUEST_HEADERS"))
        self.assertEqual((source_fallback["phase"], source_fallback["variable"]), ("3", "ARGS, ARGS_NAMES"))
        self.assertEqual(source_fallback["expected_action"], "pass")

    def test_phase4_classification_keeps_priority_and_legitimate_control(self) -> None:
        base = {
            "hard_abort": False,
            "logs": False,
            "entry_classification": "",
            "log_only": False,
            "response_body_truncated": False,
            "expected_action": "deny",
            "known_gap": False,
            "runtime_status": "FAIL",
        }
        priority_cases = (
            ({"hard_abort": True, "logs": True, "entry_classification": "native"}, "phase4_hard_abort_evidence"),
            ({"entry_classification": "native_semantics"}, "phase4_native_semantics"),
            ({"log_only": True}, "phase4_log_only_no_abort"),
            ({"response_body_truncated": True}, "phase4_truncated_not_accepted"),
            ({"known_gap": True}, "phase4_connector_gap"),
            ({}, "phase4_missing_abort_evidence"),
            ({"expected_action": "pass", "logs": True, "runtime_status": "PASS"}, "phase4_no_hard_abort_required"),
        )

        for changes, expected in priority_cases:
            with self.subTest(expected=expected):
                category, _ = PHASE4.phase4_classification(**{**base, **changes})
                self.assertEqual(category, expected)

        category, evidence_categories, abort, logs, action, delivered = PHASE4.classify_case(
            {"connector": "apache", "runtime_status": "PASS", "actual_status": 200},
            {"expected_action": "pass", "phase4_mode": "-"},
            {},
            [],
            [],
        )
        self.assertEqual(category, "phase4_no_hard_abort_required")
        self.assertEqual((evidence_categories, abort, logs, action, delivered), ([], False, False, "-", "full"))

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
