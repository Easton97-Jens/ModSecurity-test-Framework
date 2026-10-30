from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()
CI_LIB = source_path('ci/lib', root=ROOT)


import modsecurity_connector_ci.lib.report_path_safety as report_path_safety


def load_report_module(relative_path: str, module_name: str):
    module = load_source(ROOT / relative_path)
    return module


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


CONNECTOR_ROADMAP = load_report_module(
    "ci/evidence/reports/generate-connector-roadmap.py",
    "report_conditional_connector_roadmap",
)
REFRESH = load_report_module(
    "ci/evidence/reports/refresh-connector-reports.py",
    "report_conditional_refresh",
)
NGINX_HTTP500 = load_report_module(
    "ci/evidence/reports/generate-nginx-mrts-http500-cluster-analysis.py",
    "report_conditional_nginx_http500",
)
RUNTIME_MISMATCH = load_report_module(
    "ci/evidence/reports/generate-verified-runtime-mismatch-analysis.py",
    "report_conditional_runtime_mismatch",
)
BODY_PROCESSOR = load_report_module(
    "ci/evidence/reports/generate-body-processor-analysis.py",
    "report_conditional_body_processor",
)
INTERVENTION = load_report_module(
    "ci/evidence/reports/generate-intervention-blocking-analysis.py",
    "report_conditional_intervention",
)
NOLOG = load_report_module(
    "ci/evidence/reports/generate-nolog-audit-evidence-analysis.py",
    "report_conditional_nolog",
)
RESPONSE_HEADERS = load_report_module(
    "ci/evidence/reports/generate-response-header-hook-analysis.py",
    "report_conditional_response_headers",
)
RULE_CHAIN = load_report_module(
    "ci/evidence/reports/generate-rule-chain-semantics-analysis.py",
    "report_conditional_rule_chain",
)


class ReportConditionalRemediationTest(unittest.TestCase):
    def test_action_part_helpers_preserve_quote_transitions(self) -> None:
        cases = (
            (
                "id:1,msg:'one,two',ctl:\"three,four\",tag:five",
                ["id:1", "msg:'one,two'", 'ctl:"three,four"', "tag:five"],
            ),
            (
                "id:2,msg:'outer,\"inside,comma\"',ctl:\"outer,'inside,comma'\",tag:four",
                [
                    "id:2",
                    "msg:'outer,\"inside,comma\"'",
                    'ctl:"outer,\'inside,comma\'"',
                    "tag:four",
                ],
            ),
            (
                "id:3,msg:'unterminated,tag:five",
                ["id:3", "msg:'unterminated,tag:five"],
            ),
        )
        for actions, expected in cases:
            for module in (BODY_PROCESSOR, INTERVENTION, NOLOG, RESPONSE_HEADERS, RULE_CHAIN):
                with self.subTest(module=module.__name__, actions=actions):
                    self.assertEqual(module.action_parts(actions), expected)

    def test_connector_roadmap_keeps_production_and_partial_statuses(self) -> None:
        production = CONNECTOR_ROADMAP.connector_row(ROOT, "apache")
        partial = CONNECTOR_ROADMAP.connector_row(ROOT, "envoy")

        self.assertEqual(production["runtime_evidence"], "yes")
        self.assertEqual(production["modsecurity_integration"], "yes")
        self.assertEqual(partial["runtime_evidence"], "targeted proof required")
        self.assertEqual(partial["modsecurity_integration"], "starter_only")

    def test_access_log_status_is_linear_parser_with_valid_log_control(self) -> None:
        valid = '127.0.0.1 - - [16/Jun/2026:12:00:00 +0000] "GET /ok HTTP/1.1" 503 12 "-" "test"'
        malformed = '"GET ' + ("path HTTP/1.1 " * 800)

        self.assertEqual(NGINX_HTTP500.access_log_status(valid), "503")
        with mock.patch.object(NGINX_HTTP500.re, "search", side_effect=AssertionError("unbounded request regex")):
            self.assertIsNone(NGINX_HTTP500.access_log_status(malformed))

        with tempfile.TemporaryDirectory() as temporary:
            self.enterContext(mock.patch.object(RUNTIME_MISMATCH, "INPUTS", RUNTIME_MISMATCH.EvidenceInputs((ROOT, Path(temporary)))))
            self.enterContext(mock.patch.object(NGINX_HTTP500, "INPUTS", NGINX_HTTP500.EvidenceInputs((ROOT, Path(temporary)))))
            access_log = Path(temporary) / "access.log"
            access_log.write_text(
                "\n".join(
                    (
                        valid,
                        malformed,
                        '127.0.0.1 - - [16/Jun/2026:12:00:01 +0000] "POST /final HTTP/2.0" 502 7 "-" "test"',
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            self.assertEqual(NGINX_HTTP500.access_status(access_log, "2026/06/16"), "502")

    def test_runtime_summary_preserves_mismatch_and_timeout_priorities(self) -> None:
        mismatch_summary = RUNTIME_MISMATCH.command_summary(
            [
                {
                    "logical_target": "full-matrix-parallel",
                    "runtime_complete": True,
                    "runtime_status": "",
                }
            ],
            [{"return_code": 1}],
            "full",
        )
        timeout_summary = RUNTIME_MISMATCH.command_summary(
            [{"logical_target": "full-matrix-parallel", "classification": "blocked_timeout"}],
            [],
            "full",
        )

        self.assertEqual(mismatch_summary["full_matrix_runtime_status"], "runtime_completed_with_mismatches")
        self.assertEqual(timeout_summary["full_matrix_runtime_status"], "runtime_timeout")

    def test_full_matrix_control_evidence_keeps_fixed_case_and_fallback_contracts(self) -> None:
        build_root = Path("/controlled-build-root")
        control_case = RUNTIME_MISMATCH.ARGS_NAMES_CONTROL_CASE
        summaries = {
            ("apache", "no-crs/no-mrts"): {
                "status": "PASS",
                "expected_status": "403",
                "actual_status": "403",
                "live_executed": True,
                "evidence_path": "apache-pass.json",
            },
            ("haproxy", "no-crs/no-mrts"): {
                "status": "pass",
                "expected_status": "403",
                "actual_status": "403",
                "live_executed": False,
                "evidence_path": "haproxy-not-live.json",
            },
            ("haproxy", "with-crs/no-mrts"): {
                "status": "pass",
                "expected_status": "403",
                "actual_status": "200",
                "live_executed": True,
                "evidence_path": "haproxy-wrong-actual.json",
            },
            ("nginx", "no-crs/no-mrts"): {
                "status": "pass",
                "expected_status": "403",
                "observed_status": "403",
                "live_executed": True,
                "evidence_path": "nginx-observed-pass.json",
            },
        }

        def summary_case(build: Path, connector: str, variant: str, case_name: str) -> dict[str, object]:
            self.assertEqual(build, build_root)
            self.assertEqual(case_name, control_case)
            return summaries.get((connector, variant), {})

        with mock.patch.object(RUNTIME_MISMATCH, "full_matrix_summary_case", side_effect=summary_case):
            fixed_case = RUNTIME_MISMATCH.full_matrix_control_evidence(build_root)
            parameterized = RUNTIME_MISMATCH.full_matrix_case_control_evidence(build_root, control_case)

        self.assertEqual(fixed_case, parameterized)
        self.assertEqual(
            list(fixed_case),
            [
                f"apache:no-crs/no-mrts:{control_case}",
                f"apache:with-crs/no-mrts:{control_case}",
                f"haproxy:no-crs/no-mrts:{control_case}",
                f"haproxy:with-crs/no-mrts:{control_case}",
                f"nginx:no-crs/no-mrts:{control_case}",
                f"nginx:with-crs/no-mrts:{control_case}",
            ],
        )
        self.assertEqual(
            fixed_case[f"apache:no-crs/no-mrts:{control_case}"],
            {
                "status": "pass",
                "expected": "403",
                "actual": "403",
                "evidence_file": "apache-pass.json",
            },
        )
        self.assertEqual(
            fixed_case[f"apache:with-crs/no-mrts:{control_case}"],
            {"status": "missing", "expected": "-", "actual": "-", "evidence_file": "-"},
        )
        self.assertEqual(
            fixed_case[f"haproxy:no-crs/no-mrts:{control_case}"],
            {
                "status": "fail",
                "expected": "403",
                "actual": "403",
                "evidence_file": "haproxy-not-live.json",
            },
        )
        self.assertEqual(
            fixed_case[f"haproxy:with-crs/no-mrts:{control_case}"],
            {
                "status": "fail",
                "expected": "403",
                "actual": "200",
                "evidence_file": "haproxy-wrong-actual.json",
            },
        )
        self.assertEqual(fixed_case[f"nginx:no-crs/no-mrts:{control_case}"]["status"], "pass")
        self.assertEqual(fixed_case[f"nginx:with-crs/no-mrts:{control_case}"]["status"], "missing")

    def test_haproxy_xml_parser_evidence_requires_one_safe_non_disruptive_decision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.enterContext(mock.patch.object(RUNTIME_MISMATCH, "INPUTS", RUNTIME_MISMATCH.EvidenceInputs((ROOT, Path(temporary)))))
            self.enterContext(mock.patch.object(NGINX_HTTP500, "INPUTS", NGINX_HTTP500.EvidenceInputs((ROOT, Path(temporary)))))
            build_root = Path(temporary) / "build"
            result_path = build_root / "runtime" / "xml-result.json"
            decision_log = result_path.parent / "decision.jsonl"
            decision_log.parent.mkdir(parents=True)
            result = {
                "modsecurity_processed": True,
                "request_body_seen": True,
                "decision_log_path": str(decision_log),
            }
            valid_decision = {
                "live_executed": True,
                "modsecurity_processed": True,
                "request_body_seen": True,
                "decision": "pass",
                "disruptive": False,
                "rule_id": 4408,
                "matched_variable": "",
                "matched_value_snippet": "",
            }
            row = {"connector": "haproxy"}

            with mock.patch.object(
                RUNTIME_MISMATCH,
                "matching_runtime_result",
                return_value=(result_path, result),
            ):
                decision_log.write_text(json.dumps(valid_decision) + "\n", encoding="utf-8")
                evidence = RUNTIME_MISMATCH.xml_parser_semantics_result_evidence(
                    row,
                    connector_root=Path(temporary) / "connector",
                    build_root=build_root,
                    expected_status="403",
                    native_actual="200",
                )

                self.assertEqual(
                    evidence,
                    {
                        "result": "runtime/xml-result.json",
                        "expected": "403",
                        "actual": "200",
                        "live_executed": "true",
                        "full_matrix_refresh_needed": "false",
                        "observed_transport_result": "http_status",
                        "modsecurity_processed": "true",
                        "request_body_seen": "true",
                        "decision_log": "runtime/decision.jsonl",
                        "decision": "pass",
                        "rule_id": "4408",
                        "matched_variable": "",
                        "matched_value_snippet": "",
                    },
                )

                for invalid_entries in (
                    [valid_decision, valid_decision],
                    [{**valid_decision, "disruptive": True}],
                    [{**valid_decision, "matched_value_snippet": "untrusted"}],
                ):
                    with self.subTest(invalid_entries=invalid_entries):
                        decision_log.write_text(
                            "".join(json.dumps(item) + "\n" for item in invalid_entries),
                            encoding="utf-8",
                        )
                        self.assertIsNone(
                            RUNTIME_MISMATCH.xml_parser_semantics_result_evidence(
                                row,
                                connector_root=Path(temporary) / "connector",
                                build_root=build_root,
                                expected_status="403",
                                native_actual="200",
                            )
                        )

    def test_row_from_case_keeps_overlay_order_and_refuses_to_replace_the_first_classification(self) -> None:
        base_row = {"connector": "apache", "classification": "runtime_regression"}
        expected_order = [
            "multipart",
            "with_mrts",
            "crs_with_mrts",
            "nginx_phase4_enforcement",
            "nginx_phase4_log_only",
            "secaction",
        ]
        observed: list[str] = []

        def evidence(name: str) -> dict[str, str]:
            observed.append(name)
            return {"note": name}

        with (
            mock.patch.object(RUNTIME_MISMATCH, "base_case_row", return_value=(base_row, "result.json")) as base,
            mock.patch.object(RUNTIME_MISMATCH, "multipart_fixture_gap", side_effect=lambda *_args, **_kwargs: evidence("multipart")),
            mock.patch.object(RUNTIME_MISMATCH, "with_mrts_detection_only_overlay", side_effect=lambda *_args, **_kwargs: evidence("with_mrts")),
            mock.patch.object(RUNTIME_MISMATCH, "crs_sqli_with_mrts_detection_only_overlay", side_effect=lambda *_args, **_kwargs: evidence("crs_with_mrts")),
            mock.patch.object(RUNTIME_MISMATCH, "nginx_phase4_response_body_enforcement_gap", side_effect=lambda *_args, **_kwargs: evidence("nginx_phase4_enforcement")),
            mock.patch.object(RUNTIME_MISMATCH, "nginx_phase4_rule_match_no_disruptive_intervention", side_effect=lambda *_args, **_kwargs: evidence("nginx_phase4_log_only")),
            mock.patch.object(RUNTIME_MISMATCH, "secaction_with_mrts_detection_only_overlay", side_effect=lambda *_args, **_kwargs: evidence("secaction")),
        ):
            row = RUNTIME_MISMATCH.row_from_case(
                case={"status": "fail"},
                connector="apache",
                variant="no-crs/no-mrts",
                evidence_file=Path("result.json"),
                source_file=Path("summary.json"),
                source_scope="full_matrix",
                connector_root=Path("/connector-root"),
                build_root=Path("/build-root"),
            )

            self.assertIsNone(
                RUNTIME_MISMATCH.row_from_case(
                    case={"status": "PASS"},
                    connector="apache",
                    variant="no-crs/no-mrts",
                    evidence_file=Path("result.json"),
                    source_file=Path("summary.json"),
                    source_scope="full_matrix",
                    connector_root=Path("/connector-root"),
                    build_root=Path("/build-root"),
                )
            )

        self.assertEqual(observed, expected_order)
        self.assertIs(row, base_row)
        self.assertEqual(row["classification"], "multipart_fixture_gap")
        self.assertTrue(row["code_fix_needed"])
        self.assertEqual(base.call_count, 1)

    def test_refresh_placeholder_retains_evidence_markdown_and_writes_a_safe_placeholder_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.enterContext(mock.patch.object(RUNTIME_MISMATCH, "INPUTS", RUNTIME_MISMATCH.EvidenceInputs((ROOT, Path(temporary)))))
            self.enterContext(mock.patch.object(NGINX_HTTP500, "INPUTS", NGINX_HTTP500.EvidenceInputs((ROOT, Path(temporary)))))
            connector_root = Path(temporary) / "connector"
            framework_root = Path(temporary) / "framework"
            connector_root.mkdir()
            framework_root.mkdir()
            json_path = REFRESH.report_path(connector_root, "final_consistency_audit", "json")
            markdown_path = REFRESH.report_path(connector_root, "final_consistency_audit", "md")
            german_path = markdown_path.with_name(markdown_path.name.removesuffix(".md") + ".de.md")
            markdown_path.parent.mkdir(parents=True)
            markdown_path.write_text("# Evidence\n\nretained proof\n", encoding="utf-8")
            german_path.write_text("# Nachweis\n\nbehaltener Beleg\n", encoding="utf-8")
            spec = REFRESH.ReportSpec(
                name="final_consistency_audit",
                owner="connector",
                generator="tests/refresh",
                make_target="test-refresh",
                inputs=("input.json",),
                outputs=(),
                command=("test-refresh",),
            )
            metadata = {"generated_at": "2026-08-01T00:00:00Z", "verified_run_id": "verified-test-run"}

            with (
                mock.patch.object(report_path_safety, "SAFE_ROOTS", set()),
                mock.patch.object(REFRESH, "build_metadata", return_value=metadata),
            ):
                report_path_safety.add_safe_roots(connector_root, framework_root)
                REFRESH.write_placeholder_outputs(
                    spec,
                    "blocked_missing_input",
                    "verified input unavailable",
                    [json_path, markdown_path],
                    connector_root,
                    framework_root,
                    "2026-08-01T00:00:00Z",
                    preserve_existing=True,
                )

            payload = json.loads(json_path.read_text(encoding="utf-8"))
            retained = markdown_path.read_text(encoding="utf-8")
            retained_german = german_path.read_text(encoding="utf-8")

        self.assertEqual(payload["status"], "blocked_missing_input")
        self.assertEqual(payload["reason"], "verified input unavailable")
        self.assertEqual(payload["rows"], [])
        self.assertEqual(payload["metadata"], metadata)
        self.assertIn("retained proof", retained)
        self.assertIn("retained-historical-generated-output", retained)
        self.assertIn("behaltener Beleg", retained_german)
        self.assertIn("retained-historical-generated-output", retained_german)

    def test_refresh_submodule_and_dashboard_helpers_preserve_order_and_status_rules(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.enterContext(mock.patch.object(RUNTIME_MISMATCH, "INPUTS", RUNTIME_MISMATCH.EvidenceInputs((ROOT, Path(temporary)))))
            self.enterContext(mock.patch.object(NGINX_HTTP500, "INPUTS", NGINX_HTTP500.EvidenceInputs((ROOT, Path(temporary)))))
            root = Path(temporary)
            connector_root = root / "connector"
            framework_root = root / "framework"
            mrts_root = framework_root / "tools" / "MRTS"
            sibling = root / "framework-sibling"
            for path in (connector_root, framework_root, mrts_root, sibling):
                path.mkdir(parents=True, exist_ok=True)
            shas = {
                connector_root: "parent-sha",
                framework_root: "framework-sha",
                mrts_root: "mrts-sha",
                sibling: "sibling-sha",
            }
            with (
                mock.patch.object(REFRESH, "git_sha", side_effect=lambda path: shas[path]),
                mock.patch.object(REFRESH, "git_branch", return_value="detached"),
                mock.patch.object(REFRESH, "git_dirty_status", return_value="clean"),
            ):
                rows = REFRESH.submodule_rows(connector_root, framework_root, mrts_root, sibling)
            REFRESH.apply_expected_submodule_shas(
                rows,
                "\n".join(
                    (
                        f"+framework-expected {REFRESH.FRAMEWORK_SUBMODULE_PATH}",
                        f"-mrts-expected {REFRESH.FRAMEWORK_SUBMODULE_PATH}/tools/MRTS",
                    )
                ),
            )
            REFRESH.mark_sibling_difference(rows, sibling)

        self.assertEqual(
            [row["name"] for row in rows],
            ["parent", "framework_submodule", "mrts_submodule", "framework_sibling_checkout"],
        )
        self.assertEqual(rows[1]["expected"], "framework-expected")
        self.assertEqual(rows[2]["expected"], "mrts-expected")
        self.assertEqual(rows[3]["status"], "differs")

        dashboard = REFRESH.render_merge_dashboard_md(
            {
                "status": "NEEDS_ATTENTION",
                "full_matrix_complete": True,
                "critical_runtime_mismatch_count": 1,
                "full_matrix_totals": {"pass": 4, "fail": 1, "blocked": 0},
            }
        )
        self.assertIn("| Full Runtime Matrix | PASS |", dashboard)
        self.assertIn("| Runtime Mismatch Analysis | FAIL |", dashboard)
        self.assertLess(
            dashboard.index("| Full Runtime Matrix |"),
            dashboard.index("| Runtime Mismatch Analysis |"),
        )
        self.assertLess(
            dashboard.index("| Runtime Mismatch Analysis |"),
            dashboard.index("| Final Consistency Audit |"),
        )

    def test_response_header_metadata_keeps_rule_and_request_priorities(self) -> None:
        parsed = {
            "name": "response-case",
            "category": "response-headers",
            "rules": 'SecRule RESPONSE_HEADERS:Set-Cookie "@contains session" "id:920003,phase:3,deny"',
            "response": {"headers": {"Set-Cookie": "session=1"}},
        }
        with (
            mock.patch.object(RESPONSE_HEADERS, "read_text", return_value="fixture"),
            mock.patch.object(
                RESPONSE_HEADERS,
                "parse_case_document",
                return_value=(parsed, {"method": "GET"}, {"status": 403}, {}, "/response", "mode=strict"),
            ),
        ):
            metadata = RESPONSE_HEADERS.parse_case_metadata(
                Path("response-case.yaml"),
                {"phase": "2", "method": "HEAD", "expected_status": 200},
            )

        self.assertEqual(metadata["case_id"], "response-case")
        self.assertEqual(metadata["phase"], "3")
        self.assertEqual(metadata["header_name"], "Set-Cookie")
        self.assertEqual(metadata["method"], "GET")
        self.assertEqual((metadata["path"], metadata["query"]), ("/response", "mode=strict"))
        self.assertEqual(metadata["expected_status"], 403)
        self.assertEqual(metadata["response_headers"], {"Set-Cookie": "session=1"})

    def test_intervention_metadata_keeps_expected_rule_and_safe_fallbacks(self) -> None:
        case_path = Path("intervention-case.yaml")
        parsed = {
            "request": {"method": "POST", "path": "?strict=1", "headers": {"Content-Type": "text/plain"}},
            "expect": {"rule_id": "920002", "intervention": "deny"},
            "rules": '\n'.join(
                (
                    'SecRule ARGS "@contains first" "id:920001,phase:1,deny"',
                    'SecRule ARGS "@contains second" "id:920002,phase:2,deny"',
                )
            ),
            "known_limitations": ["Classification: connector_gap."],
        }
        with (
            mock.patch.object(INTERVENTION, "safe_existing_file", return_value=case_path),
            mock.patch.object(INTERVENTION, "load_intervention_case", return_value=("fixture", parsed)),
            mock.patch.object(INTERVENTION, "display_case_path", return_value="framework:intervention-case.yaml"),
        ):
            metadata = INTERVENTION.case_metadata({"phase": "9"}, {"path": str(case_path)}, Path("framework"))

        self.assertEqual(metadata["rule_id"], "920002")
        self.assertEqual(metadata["expected_rule_id"], "920002")
        self.assertEqual(metadata["phase"], "2")
        self.assertEqual((metadata["path"], metadata["query"]), ("/", "strict=1"))
        self.assertEqual(metadata["source_classification"], "connector_gap")
        self.assertEqual(
            INTERVENTION.selected_intervention_rule([], "", {"phase": "4"}),
            INTERVENTION.fallback_intervention_rule({"phase": "4"}),
        )

    def test_rule_chain_row_keeps_detection_only_observation_fields(self) -> None:
        entry = {
            "evidence": "ignored.json",
            "connector": "apache",
            "test_variant": "with-crs",
            "mrts_variant": "with-mrts",
            "case_id": "chain-case",
            "expected_status": 403,
            "actual_status": 200,
            "classification": RULE_CHAIN.DETECTION_ONLY_CLASSIFICATION,
        }
        case = {
            "source": "fixture",
            "rules": '\n'.join(
                (
                    'SecRule ARGS "@contains token" "id:920001,phase:1,chain"',
                    'SecRule ARGS "@contains token" "id:920002,phase:1,deny"',
                )
            ),
            "request": {"path": "/?token=1"},
        }
        with (
            mock.patch.object(RULE_CHAIN, "read_json", return_value={"path": "case.yaml"}),
            mock.patch.object(RULE_CHAIN, "load_case", return_value=case),
            mock.patch.object(RULE_CHAIN, "evidence_text", return_value='[id "920001"] ARGS'),
        ):
            row = RULE_CHAIN.chain_row(entry, Path("framework"))

        self.assertEqual(row["chain_parent_matched"], "yes")
        self.assertEqual(row["chain_child_matched"], "yes")
        self.assertEqual(row["full_chain_matched"], "yes")
        self.assertEqual(row["intervention_created"], "no")
        self.assertEqual(row["analysis_classification"], "with_mrts_detection_only_chain_non_disruptive")
        self.assertEqual(row["fixability"], "report_only")

    def test_collection_classifiers_reject_nonpassing_control_evidence(self) -> None:
        def rows_for(cases: set[str]) -> list[dict[str, str]]:
            return [
                {"case": case, "connector": connector, "variant": variant, "category": "collections"}
                for case in cases
                for connector in RUNTIME_MISMATCH.SEMICOLON_COLLECTION_CONNECTORS
                for variant in RUNTIME_MISMATCH.SEMICOLON_COLLECTION_VARIANTS
            ]

        nonpassing_control = {"control": {"status": "fail"}}
        semicolon_rows = rows_for(RUNTIME_MISMATCH.SEMICOLON_COLLECTION_CASES)
        with (
            mock.patch.object(RUNTIME_MISMATCH, "semicolon_collection_result_evidence", return_value={}),
            mock.patch.object(RUNTIME_MISMATCH, "full_matrix_control_evidence", return_value=nonpassing_control),
        ):
            self.assertEqual(
                RUNTIME_MISMATCH.apply_semicolon_collection_semantics_classification(
                    semicolon_rows,
                    connector_root=Path("/connector-root"),
                    build_root=Path("/build-root"),
                ),
                semicolon_rows,
            )

        collection_name_rows = rows_for(RUNTIME_MISMATCH.COLLECTION_NAME_CASE_CASES)
        with (
            mock.patch.object(RUNTIME_MISMATCH, "collection_name_case_result_evidence", return_value={}),
            mock.patch.object(RUNTIME_MISMATCH, "full_matrix_case_control_evidence", return_value=nonpassing_control),
        ):
            self.assertEqual(
                RUNTIME_MISMATCH.apply_collection_name_case_semantics_classification(
                    collection_name_rows,
                    connector_root=Path("/connector-root"),
                    build_root=Path("/build-root"),
                ),
                collection_name_rows,
            )

        self.assertTrue(all("classification" not in row for row in semicolon_rows + collection_name_rows))

    def test_full_runtime_status_preserves_priority_and_laziness(self) -> None:
        class RowsMustNotBeRead(list):
            def __iter__(self):
                raise AssertionError("explicit runtime status must not inspect manifest rows")

        self.assertEqual(
            RUNTIME_MISMATCH.full_runtime_status({"runtime_status": "reported"}, RowsMustNotBeRead(), True),
            "reported",
        )
        self.assertEqual(RUNTIME_MISMATCH.full_runtime_status({}, RowsMustNotBeRead(), False), "not_run")
        self.assertEqual(RUNTIME_MISMATCH.full_runtime_status({}, [], True), "runtime_completed")
        self.assertEqual(RUNTIME_MISMATCH.full_runtime_status({}, [{"return_code": None}], True), "runtime_completed")
        self.assertEqual(
            RUNTIME_MISMATCH.full_runtime_status({}, [{"return_code": 1}], True),
            "runtime_completed_with_mismatches",
        )
        self.assertEqual(
            RUNTIME_MISMATCH.full_runtime_status({"classification": "blocked_timeout"}, [], False),
            "runtime_timeout",
        )
        self.assertEqual(RUNTIME_MISMATCH.full_runtime_status({}, [], False), "not_run")

    def test_no_mrts_control_identity_uses_fixed_connector_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.enterContext(mock.patch.object(RUNTIME_MISMATCH, "INPUTS", RUNTIME_MISMATCH.EvidenceInputs((ROOT, Path(temporary)))))
            self.enterContext(mock.patch.object(NGINX_HTTP500, "INPUTS", NGINX_HTTP500.EvidenceInputs((ROOT, Path(temporary)))))
            build_root = Path(temporary) / "build"
            self.assertEqual(RUNTIME_MISMATCH.NGINX_FORCE_ALL_SUMMARY_FILE, "nginx-summary.json")
            for connector in ("apache", "haproxy", "nginx"):
                with self.subTest(connector=connector):
                    identity = RUNTIME_MISMATCH._no_mrts_control_identity(
                        build_root=build_root,
                        connector=connector,
                        variant="with-crs/with-mrts",
                    )
                    self.assertEqual(
                        identity,
                        ("with-crs", build_root / "full-matrix" / "with-crs" / "no-mrts" / connector),
                    )

            self.assertIsNone(
                RUNTIME_MISMATCH._no_mrts_control_identity(
                    build_root=build_root,
                    connector="envoy",
                    variant="with-crs/with-mrts",
                )
            )
            self.assertIsNone(
                RUNTIME_MISMATCH._no_mrts_control_identity(
                    build_root=build_root,
                    connector="apache",
                    variant="with-crs",
                )
            )

    def test_no_mrts_controls_keep_pass_403_and_missing_evidence_predicates(self) -> None:
        case_name = "control-case"
        with tempfile.TemporaryDirectory() as temporary:
            self.enterContext(mock.patch.object(RUNTIME_MISMATCH, "INPUTS", RUNTIME_MISMATCH.EvidenceInputs((ROOT, Path(temporary)))))
            self.enterContext(mock.patch.object(NGINX_HTTP500, "INPUTS", NGINX_HTTP500.EvidenceInputs((ROOT, Path(temporary)))))
            build_root = Path(temporary) / "build"
            for connector in ("apache", "haproxy", "nginx"):
                with self.subTest(connector=connector):
                    row = {"connector": connector, "variant": "with-crs/with-mrts"}
                    self.assertIsNone(RUNTIME_MISMATCH.no_mrts_control_evidence(row, build_root=build_root))
                    self.assertIsNone(
                        RUNTIME_MISMATCH.no_mrts_case_control_evidence(
                            row,
                            build_root=build_root,
                            case_name=case_name,
                        )
                    )

                    control_root = build_root / "full-matrix" / "with-crs" / "no-mrts" / connector
                    if connector in {"apache", "haproxy"}:
                        secaction_result = (
                            control_root
                            / "logs"
                            / f"{connector}-runtime"
                            / RUNTIME_MISMATCH.SECACTION_DETECTION_ONLY_CASE
                            / "result.json"
                        )
                        case_result = control_root / "logs" / f"{connector}-runtime" / case_name / "result.json"
                    else:
                        secaction_result = build_root / "nginx-results" / "secaction-result.json"
                        case_result = build_root / "nginx-results" / "case-result.json"
                        write_json(
                            control_root
                            / "results"
                            / "force-all"
                            / RUNTIME_MISMATCH.NGINX_FORCE_ALL_SUMMARY_FILE,
                            {
                                "nginx": {
                                    "cases": [
                                        {
                                            "name": RUNTIME_MISMATCH.SECACTION_DETECTION_ONLY_CASE,
                                            "evidence_path": str(secaction_result),
                                        },
                                        {"name": case_name, "evidence_path": str(case_result)},
                                    ]
                                }
                            },
                        )

                    write_json(secaction_result, {"status": "pass", "actual_status": 403})
                    write_json(case_result, {"status": "pass", "actual_status": 403})
                    if connector == "nginx":
                        secaction_result.parent.joinpath("error.log").write_text('[id "3312"]\n', encoding="utf-8")

                    self.assertEqual(
                        RUNTIME_MISMATCH.no_mrts_control_evidence(row, build_root=build_root)["variant"],
                        "with-crs/no-mrts",
                    )
                    self.assertEqual(
                        RUNTIME_MISMATCH.no_mrts_case_control_evidence(
                            row,
                            build_root=build_root,
                            case_name=case_name,
                        )["actual"],
                        "403",
                    )

                    write_json(secaction_result, {"status": "pass", "actual_status": 200})
                    self.assertIsNone(RUNTIME_MISMATCH.no_mrts_control_evidence(row, build_root=build_root))
                    write_json(case_result, {"status": "fail", "actual_status": 403})
                    self.assertIsNone(
                        RUNTIME_MISMATCH.no_mrts_case_control_evidence(
                            row,
                            build_root=build_root,
                            case_name=case_name,
                        )
                    )

    def test_nginx_no_mrts_phase4_control_keeps_summary_and_marker_predicates(self) -> None:
        case_name = "phase4-control"
        row = {"connector": "nginx", "variant": "with-crs/with-mrts", "case": case_name}
        with tempfile.TemporaryDirectory() as temporary:
            self.enterContext(mock.patch.object(RUNTIME_MISMATCH, "INPUTS", RUNTIME_MISMATCH.EvidenceInputs((ROOT, Path(temporary)))))
            self.enterContext(mock.patch.object(NGINX_HTTP500, "INPUTS", NGINX_HTTP500.EvidenceInputs((ROOT, Path(temporary)))))
            build_root = Path(temporary) / "build"
            control_root = build_root / "full-matrix" / "with-crs" / "no-mrts" / "nginx"
            summary_path = (
                control_root
                / "results"
                / "force-all"
                / RUNTIME_MISMATCH.NGINX_FORCE_ALL_SUMMARY_FILE
            )
            evidence_path = build_root / "nginx-results" / "phase4-result.json"
            phase4_log_path = evidence_path.parent / "phase4.log"

            self.assertIsNone(RUNTIME_MISMATCH.nginx_no_mrts_phase4_log_control(row, build_root=build_root))
            phase4_log_path.parent.mkdir(parents=True, exist_ok=True)
            phase4_log_path.write_text("phase4_intervention\n", encoding="utf-8")
            write_json(evidence_path, {"connector_phase4_log_path": str(phase4_log_path)})
            write_json(
                summary_path,
                {"nginx": {"cases": [{"name": case_name, "status": "pass", "evidence_path": str(evidence_path)}]}},
            )

            self.assertEqual(
                RUNTIME_MISMATCH.nginx_no_mrts_phase4_log_control(row, build_root=build_root),
                {
                    "variant": "with-crs/no-mrts",
                    "result": "nginx-results/phase4-result.json",
                    "phase4_log": "nginx-results/phase4.log",
                    "status": "pass",
                },
            )

            write_json(
                summary_path,
                {"nginx": {"cases": [{"name": case_name, "status": "fail", "evidence_path": str(evidence_path)}]}},
            )
            self.assertIsNone(RUNTIME_MISMATCH.nginx_no_mrts_phase4_log_control(row, build_root=build_root))
            write_json(
                summary_path,
                {"nginx": {"cases": [{"name": case_name, "status": "pass", "evidence_path": str(evidence_path)}]}},
            )
            phase4_log_path.write_text("no intervention marker\n", encoding="utf-8")
            self.assertIsNone(RUNTIME_MISMATCH.nginx_no_mrts_phase4_log_control(row, build_root=build_root))

    def test_report_status_branches_keep_existing_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.enterContext(mock.patch.object(RUNTIME_MISMATCH, "INPUTS", RUNTIME_MISMATCH.EvidenceInputs((ROOT, Path(temporary)))))
            self.enterContext(mock.patch.object(NGINX_HTTP500, "INPUTS", NGINX_HTTP500.EvidenceInputs((ROOT, Path(temporary)))))
            root = Path(temporary)
            case_path = root / "case.yaml"
            evidence_path = root / "evidence.json"
            config_path = root / "modsecurity-smoke.conf"
            case_path.write_text("", encoding="utf-8")
            evidence_path.write_text("{}\n", encoding="utf-8")
            for config, expected in (
                ("SecRequestBodyAccess On\nSecRequestBodyAccess Off\n", "yes"),
                ("SecRequestBodyAccess Off\n", "no"),
                ("", "unknown"),
            ):
                with self.subTest(config=config):
                    config_path.write_text(config, encoding="utf-8")
                    with mock.patch.object(BODY_PROCESSOR, "generated_config_path", return_value=config_path):
                        metadata = BODY_PROCESSOR.case_metadata(
                            {"evidence": str(evidence_path), "connector": "nginx"},
                            {"path": str(case_path)},
                            root,
                        )
                    self.assertEqual(metadata["request_body_access"], expected)

            for classification, actual_status, expected in (
                (RULE_CHAIN.DETECTION_ONLY_CLASSIFICATION, 403, "no"),
                ("other", 403, "yes"),
                ("other", 500, "unknown"),
            ):
                with self.subTest(classification=classification, actual_status=actual_status):
                    row = RULE_CHAIN.chain_row(
                        {
                            "evidence": "",
                            "classification": classification,
                            "actual_status": actual_status,
                            "expected_status": actual_status,
                        },
                        root,
                    )
                    self.assertEqual(row["intervention_created"], expected)

            responses = [
                {"metadata": {}, "totals": {}},
                {"metadata": {}, "release_readiness": "ready"},
                {"recommendation": {}},
                {"metadata": {}},
                {
                    "metadata": {},
                    "full_matrix": {"complete": False, "missing_jobs": "invalid"},
                    "evidence_scope": "full",
                    "critical_mismatch_count": 0,
                    "mismatch_count": 0,
                },
                {"missing_job_ids": ["apache", "nginx"]},
                {},
            ]
            with mock.patch.object(REFRESH, "read_json", side_effect=responses):
                dashboard = REFRESH.merge_dashboard_payload(
                    {"verified_run_id": "run", "reports": []},
                    {"reports": []},
                    [],
                    root,
                )

        self.assertEqual(dashboard["full_matrix_missing_jobs"], ["apache", "nginx"])
        self.assertEqual(
            dashboard["reason"],
            "Full-Matrix evidence is incomplete; 0/0 jobs complete; missing jobs: apache, nginx.",
        )
        self.assertIn("| Runtime Mismatch Analysis | UNKNOWN |", REFRESH.render_merge_dashboard_md(dashboard))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
