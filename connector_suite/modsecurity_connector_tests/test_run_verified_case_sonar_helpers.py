"""Direct behavior contracts for the verified-case Sonar helper boundaries."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = connector_root()
CI_LIB = source_path('ci/lib', root=ROOT)



def load_verified_case_runner() -> object:
    module = load_source(source_path('ci/runtime/lifecycle/run-verified-case.py', root=ROOT))
    return module


RUNNER = load_verified_case_runner()


class VerifiedCaseSonarHelpersTest(unittest.TestCase):
    def test_find_first_key_keeps_direct_key_precedence_and_recursive_order(self) -> None:
        document = {
            "nested": {"request": {"path": "/nested"}},
            "request": {"path": "/direct"},
        }
        nested_only = {"first": [{"ignored": True}, {"request": {"path": "/later"}}]}

        self.assertEqual(RUNNER.find_first_key(document, {"request"}), {"path": "/direct"})
        self.assertEqual(RUNNER.find_first_key(nested_only, {"request"}), {"path": "/later"})
        self.assertIsNone(RUNNER.find_first_key({"request": None, **nested_only}, {"request"}))

    def test_relevant_log_files_keeps_existing_result_and_case_log_selection(self) -> None:
        with tempfile.TemporaryDirectory(prefix="verified-case-log-selection-") as temporary:
            root = Path(temporary)
            direct = root / "result-decision.jsonl"
            direct.write_text("{}\n", encoding="utf-8")
            case_dir = root / "logs" / "case-a"
            case_dir.mkdir(parents=True)
            access_log = case_dir / "access.log"
            access_log.write_text("entry\n", encoding="utf-8")
            ignored = case_dir / "payload.bin"
            ignored.write_text("payload\n", encoding="utf-8")
            haproxy_root = root / "haproxy-runtime"
            haproxy_root.mkdir()
            status_log = haproxy_root / "status.txt"
            status_log.write_text("status\n", encoding="utf-8")

            actual = RUNNER.relevant_log_files(
                {"logs": root / "logs", "runtime": haproxy_root, "work": root / "missing"},
                "case-a",
                {"decision_log_path": str(direct), "other_path": str(root / "absent.log")},
            )

            self.assertEqual(actual, sorted([direct, access_log, status_log]))
            self.assertNotIn(ignored, actual)

    def test_result_rule_evidence_uses_last_json_from_the_first_decision_artifact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="verified-case-rule-evidence-") as temporary:
            root = Path(temporary)
            first = root / "first-decision.jsonl"
            first.write_text(
                "not-json\n"
                + json.dumps({"rule_id": "first", "matched_data": "discarded"})
                + "\n"
                + json.dumps({"matched_value_snippet": "selected"})
                + "\n",
                encoding="utf-8",
            )
            second = root / "second-decision.jsonl"
            second.write_text(json.dumps({"rule_id": "later"}) + "\n", encoding="utf-8")

            evidence = RUNNER.result_rule_evidence(
                {"rule_id": "fallback", "matched_data": "fallback-data", "reason": "kept"},
                [{"path": str(first)}, {"path": str(second)}],
            )

            self.assertEqual(evidence["decision"], {"matched_value_snippet": "selected"})
            self.assertEqual(evidence["rule_id"], "fallback")
            self.assertEqual(evidence["matched_data"], "selected")
            self.assertEqual(evidence["reason"], "kept")

    def test_load_mismatch_rows_preserves_exact_variant_and_evidence_precedence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="verified-case-mismatch-rows-") as temporary:
            root = Path(temporary)
            report = root / "reports/testing/generated/manifest/verified-runtime-mismatch-analysis.generated.json"
            report.parent.mkdir(parents=True)
            report.write_text(
                json.dumps(
                    {
                        "mismatches": [
                            {
                                "case": "case-a",
                                "connector": "apache",
                                "variant": "no-crs/no-mrts",
                                "evidence_file": "exact.json",
                                "evidence": {"log": "exact.log", "note": "ignored.txt"},
                            },
                            {
                                "case": "case-a",
                                "connector": "apache",
                                "variant": "no-crs",
                                "evidence_path": "fallback.jsonl",
                            },
                            {
                                "case": "case-a",
                                "connector": "nginx",
                                "variant": "with-crs-with-mrts",
                                "evidence_file": "other.json",
                            },
                            {"case": "other", "connector": "haproxy", "variant": "no-crs/no-mrts"},
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            mismatch = RUNNER.load_mismatch_rows(root, "case-a", "apache", "no-crs", "no-mrts")

            self.assertEqual(len(mismatch["case_rows"]), 3)
            self.assertEqual(len(mismatch["exact_rows"]), 2)
            self.assertEqual(mismatch["evidence_files"], ["exact.json", "exact.log", "fallback.jsonl"])
            self.assertEqual(
                mismatch["affected_jobs"],
                [
                    {
                        "connector": "apache",
                        "crs": "no-crs",
                        "mrts": "no-mrts",
                        "command": "make verified-full-matrix-job CONNECTOR=apache CRS=no-crs MRTS=no-mrts",
                    },
                    {
                        "connector": "nginx",
                        "crs": "with-crs",
                        "mrts": "with-mrts",
                        "command": "make verified-full-matrix-job CONNECTOR=nginx CRS=with-crs MRTS=with-mrts",
                    },
                ],
            )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
