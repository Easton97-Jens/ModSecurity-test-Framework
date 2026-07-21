import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "ci/reporting/generate-case-matrix.py"
MAKEFILE_PATH = ROOT / "Makefile"


def load_case_matrix_module():
    name = "generate_case_matrix_sonar_test"
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class GenerateCaseMatrixSonarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_case_matrix_module()

    def test_default_build_root_requires_an_explicit_verified_run_root(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(self.module.default_build_root(), self.module.DEFAULT_BUILD_ROOT)
        with tempfile.TemporaryDirectory() as temporary_directory:
            verified_run_root = Path(temporary_directory) / "verified-run"
            with mock.patch.dict(os.environ, {"VERIFIED_RUN_ROOT": str(verified_run_root)}, clear=True):
                self.assertEqual(self.module.default_build_root(), verified_run_root.resolve() / "build")

    def test_report_layout_writes_only_allowlisted_output_paths(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            generated = root / "generated" / "report.md"
            overview = root / "overview.md"
            layout = self.module.ReportLayout(
                output_root=root,
                report_root=root,
                generated_root=generated.parent,
                runtime_snapshot=root / "snapshot.json",
                overview=overview,
                root_summary=None,
                generated_reports={"report.md": generated},
            )
            with mock.patch.object(self.module, "REPORT_UTILS", None):
                layout.write_generated("report.md", "../../untrusted runtime value")
                self.assertEqual(
                    generated.read_text(encoding="utf-8"),
                    "Generated file - do not edit manually.\n\n../../untrusted runtime value\n",
                )
                with self.assertRaises(ValueError):
                    layout._write_known(root.parent / "escape.md", "must not be written")
            self.assertFalse((root.parent / "escape.md").exists())

    def test_connector_report_normalization_does_not_follow_an_untrusted_symlink(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            connector_root = root / "connector"
            report_root = connector_root / "reports" / "testing"
            report_root.mkdir(parents=True)
            target = root / "outside.md"
            original = "docs/testing/generated/case-matrix.generated.md\n"
            target.write_text(original, encoding="utf-8")
            (report_root / "test-coverage-overview.de.md").symlink_to(target)
            with (
                mock.patch.object(self.module, "OUTPUT_ROOT", connector_root),
                mock.patch.object(self.module, "REPORT_ROOT", report_root),
                mock.patch.object(self.module, "REPORT_UTILS", None),
            ):
                self.module.normalize_localized_overview_report_links()
            self.assertEqual(target.read_text(encoding="utf-8"), original)

    def test_report_equivalence_rejects_injected_volatile_metadata_line(self):
        candidate = "\n".join(
            [
                "> Generated file - do not edit manually.",
                ">",
                "> Generated at: `2026-07-20T00:00:00Z`",
                "> Verified run id: `run-1`",
                "> Data source policy: `framework-only`",
                "> Generator: `framework:generator`",
                "> Make target: `generate-test-matrix`",
                "> Owner: `framework`",
                "> Severity: `internal`",
                "> Connector SHA: `0123456789abcdef0123456789abcdef01234567`",
                "> Framework SHA: `89abcdef0123456789abcdef0123456789abcdef`",
                "> Input status: `current`",
                "",
                "# Generated report",
                "",
            ]
        )
        existing = candidate.replace(
            "# Generated report",
            "> Generated at: `2026-01-01` <img src=x onerror=alert(1)>\n# Generated report",
        )
        self.assertFalse(self.module.generated_report_equivalent(existing, candidate))
        volatile_only = candidate.replace("2026-07-20T00:00:00Z", "2026-07-21T00:00:00Z")
        volatile_only = volatile_only.replace("0123456789abcdef0123456789abcdef01234567", "f" * 40)
        volatile_only = volatile_only.replace("89abcdef0123456789abcdef0123456789abcdef", "e" * 40)
        self.assertTrue(self.module.generated_report_equivalent(volatile_only, candidate))

    def test_check_test_matrix_rejects_non_framework_output_roots(self):
        makefile = MAKEFILE_PATH.read_text(encoding="utf-8")
        target = makefile.split("check-test-matrix: refresh-framework-reports", 1)[1].split(
            "\nruntime-matrix:", 1
        )[0]
        self.assertIn("OUTPUT_ROOT must resolve to FRAMEWORK_ROOT", target)
        self.assertNotIn('git -C "$(OUTPUT_ROOT)"', target)

    def test_haproxy_summary_keeps_verified_and_crs_case_semantics(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            results_dir = Path(temporary_directory) / "results"
            results_dir.mkdir()
            summary_path = results_dir / "haproxy-summary.json"
            summary_path.write_text(
                json.dumps(
                    {
                        "haproxy": {
                            "cases": {
                                "forged-pass": {"status": "pass", "requires_crs": True},
                                "no-crs-pass": {"status": "pass", "live_executed": True, "requires_crs": False},
                                "with-crs-pass": {
                                    "status": "PASS",
                                    "live_executed": True,
                                    "requires_crs": True,
                                    "crs_loaded": True,
                                    "crs_verified": True,
                                },
                                "blocked": {"status": "blocked", "requires_crs": True},
                            },
                            "summary": {"blocked": 1},
                        }
                    }
                ),
                encoding="utf-8",
            )
            summary = self.module.load_haproxy_connector_summary(results_dir, summary_path)
            self.assertEqual(summary["status"], "PARTIAL")
            self.assertEqual(summary["verified_cases"], ["no-crs-pass", "with-crs-pass"])
            self.assertEqual(summary["crs_verified_scope"], ["with-crs-pass"])
            self.assertTrue(summary["runtime_verified"])
            self.assertTrue(summary["crs_verified"])
            self.assertEqual(summary["evidence_path"], str(summary_path))

    def test_haproxy_case_extraction_rejects_non_mapping_case_payloads(self):
        self.assertEqual({}, self.module.haproxy_cases_from_summary({}))
        self.assertEqual(
            {}, self.module.haproxy_cases_from_summary({"haproxy": {"cases": []}})
        )
        self.assertEqual(
            {"case-a": {"status": "PASS"}},
            self.module.haproxy_cases_from_summary(
                {"haproxy": {"cases": {"case-a": {"status": "PASS"}}}}
            ),
        )

    def test_haproxy_variant_summary_remains_deduplicated(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            results_dir = Path(temporary_directory) / "results"
            no_crs_path = results_dir / "no-crs" / "haproxy-summary.json"
            with_crs_path = results_dir / "with-crs" / "haproxy-summary.json"
            no_crs_path.parent.mkdir(parents=True)
            with_crs_path.parent.mkdir(parents=True)
            no_crs_path.write_text(
                json.dumps(
                    {
                        "haproxy": {
                            "cases": {
                                "shared": {"status": "pass", "live_executed": True},
                                "no-crs": {"status": "pass", "live_executed": True},
                            },
                            "summary": {"pass": 2},
                        }
                    }
                ),
                encoding="utf-8",
            )
            with_crs_path.write_text(
                json.dumps(
                    {
                        "haproxy": {
                            "cases": {
                                "shared": {"status": "pass", "live_executed": True},
                                "with-crs": {
                                    "status": "pass",
                                    "live_executed": True,
                                    "requires_crs": True,
                                    "crs_loaded": True,
                                    "crs_verified": True,
                                },
                            },
                            "summary": {"pass": 2},
                        }
                    }
                ),
                encoding="utf-8",
            )
            summary = self.module.load_haproxy_connector_summary(results_dir, results_dir / "haproxy-summary.json")
            self.assertEqual(summary["status"], "PARTIAL")
            self.assertEqual(summary["verified_cases"], ["shared", "no-crs", "with-crs"])
            self.assertEqual(summary["crs_verified_scope"], ["with-crs"])
            self.assertEqual(summary["counts"], {"pass": 2})

    def test_connector_smoke_row_preserves_snapshot_details(self):
        row = self.module.new_connector_smoke_evidence_row(
            "haproxy",
            {
                "status": "PARTIAL",
                "runtime_status": "live-yaml-runtime",
                "runtime_verified": True,
                "crs_verified": True,
                "response_body_verified": False,
                "verified_cases": ["case-a", "case-b"],
                "with_crs": {
                    "status": "pass",
                    "crs_loaded": True,
                    "block_probe_status": "pass",
                    "pass_probe_status": "pass",
                    "blocked_reason": "none",
                },
                "evidence_path": "/safe/results/haproxy.json",
            },
        )
        self.assertEqual(
            row,
            "| haproxy | PARTIAL | live-yaml-runtime | yes | yes | no | `case-a, case-b` | "
            "pass crs_loaded=true block=pass pass=pass reason=none | `/safe/results/haproxy.json` |",
        )

    def test_connector_summary_loading_keeps_snapshot_fallbacks(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            build_root = Path(temporary_directory) / "build"
            results_dir = build_root / "results"
            results_dir.mkdir(parents=True)
            envoy_path = results_dir / "envoy-summary.json"
            envoy_path.write_text(json.dumps({"status": "PASS", "runtime_verified": True}), encoding="utf-8")
            snapshot = {
                "runtime_smokes": [
                    {
                        "connector": "haproxy",
                        "status": "pass",
                        "cases": [{"case": "case-a", "status": "pass", "live_executed": True}],
                        "summary_path": "/safe/results/haproxy.json",
                    }
                ]
            }
            with mock.patch.dict(os.environ, {"BUILD_ROOT": str(build_root)}, clear=True):
                summaries = self.module.load_new_connector_smoke_summaries(snapshot)
        self.assertEqual(summaries["envoy"]["status"], "PASS")
        self.assertEqual(summaries["envoy"]["evidence_path"], str(envoy_path))
        self.assertEqual(summaries["haproxy"]["status"], "PARTIAL")
        self.assertEqual(summaries["haproxy"]["verified_cases"], ["case-a"])
        self.assertEqual(summaries["haproxy"]["evidence_path"], "/safe/results/haproxy.json")

    def test_case_metadata_scope_and_tags_are_preserved(self):
        data = {
            "name": "case-id",
            "rules": 'SecRule ARGS "@contains test" "phase:2,t:lowercase"',
            "status": "active",
            "metadata": {
                "connector_scope": ["apache"],
                "classification": "pending",
                "report_labels": ["Security Review"],
                "mrts_corpus": "feature-demo",
            },
        }
        with mock.patch.object(self.module, "read_yaml", return_value=data):
            with mock.patch.object(self.module, "infer_scope", return_value="common"):
                with mock.patch.object(self.module, "is_response_body_related", return_value=False):
                    parsed = self.module.parse_case(Path("/synthetic/case.yaml"))
        self.assertEqual(parsed["scope"], "apache")
        self.assertEqual(parsed["metadata_classification"], "pending")
        self.assertEqual(parsed["report_labels"], ["Security Review"])
        self.assertIn("security review", parsed["tags"])
        self.assertIn("feature-demo", parsed["tags"])
        self.assertIn("pending", parsed["tags"])

    def test_rule_identifier_parser_is_bounded_and_preserves_delimiters(self):
        self.assertEqual(self.module.mrts_rule_id_from_text("mrts_rule_id = 1234"), "1234")
        self.assertEqual(self.module.mrts_rule_id_from_text("rule_id:\t42"), "42")
        self.assertEqual(self.module.mrts_rule_id_from_text("rule_id\n  99"), "99")
        self.assertEqual(self.module.mrts_rule_id_from_text("rule_id:=123"), "")
        self.assertEqual(self.module.mrts_rule_id_from_text("rule_id=123x"), "")
        self.assertEqual(self.module.mrts_rule_id_from_text("rule_id" + " " * 20000 + "= 77"), "77")

    def test_observed_runtime_cell_keeps_non_promotable_control(self):
        case = {
            "id": "case-id",
            "scope": "common",
            "status": "active",
            "category": "synthetic",
            "source": "test",
            "notes": "-",
            "tags": [],
            "variables": [],
            "metadata_classification": "active",
            "path": "synthetic/case.yaml",
            "capabilities": [],
        }
        observed = {
            "status": "pass",
            "matrix_status": "BLOCKED",
            "live_executed": True,
            "expected_status": 200,
            "actual_status": 200,
        }
        with mock.patch.object(self.module, "is_response_body_related", return_value=False):
            cell = self.module.runtime_cell_from_observed(case, observed, "apache")
        self.assertEqual(cell["status"], "BLOCKED")
        self.assertEqual(cell["promotion"], self.module.NOT_PROMOTED)
        self.assertEqual(cell["evidence"], "expected=200; actual=200")

    def test_non_promotable_matrix_suffix_is_not_rendered_as_pass(self):
        row = {
            "status": "pass",
            "matrix_status": "RESPONSE_BODY_PASS_THROUGH",
            "response_body_non_verified": True,
            "promotion_allowed": False,
        }
        self.assertEqual(self.module.normalized_matrix_status_value(row), "NOT_EXECUTABLE")

    def test_phase1_request_body_gap_is_not_promotion_eligible(self):
        source = (ROOT / "tests/cases/phases/phase1/phase1_vs_phase2_request_body_gap.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("classification: connector_gap", source)
        case = {
            "id": "phase1_vs_phase2_request_body_gap",
            "scope": "common",
            "status": "imported",
            "category": "phase-handling",
            "source": "ModSecurity-nginx",
            "notes": "phase-1 reachability only",
            "tags": ["connector-gap"],
            "variables": ["REQUEST_BODY"],
            "metadata_classification": "connector_gap",
            "path": "tests/cases/phases/phase1/phase1_vs_phase2_request_body_gap.yaml",
            "capabilities": ["phase1", "phase2"],
        }
        observed = {
            "status": "pass",
            "matrix_status": "PASS",
            "live_executed": True,
            "expected_status": 403,
            "actual_status": 403,
        }
        with mock.patch.object(self.module, "is_response_body_related", return_value=False):
            cell = self.module.runtime_cell_from_observed(case, observed, "apache")
        self.assertEqual(cell["promotion"], self.module.NOT_PROMOTED)

    def test_runtime_snapshot_sections_keep_shared_status_and_evidence_order(self):
        smoke_rows = [
            {
                "connector": connector,
                "command": f"run-{connector}",
                "status": "PASS",
                "exit_code": 0,
                "counts": {"pass": 1},
                "summary_path": f"/safe/{connector}.json",
            }
            for connector in ("apache", "nginx", "haproxy")
        ]
        snapshot = {
            "snapshot_date": "2026-07-20",
            "captured_at": "2026-07-20T00:00:00Z",
            "branch": "topic",
            "commit": "a" * 40,
            "build_root": "/safe/build",
            "framework_checks": [{"command": "framework", "status": "PASS", "details": "ok"}],
            "readiness_checks": [{"command": "readiness", "status": "PASS", "details": "ok"}],
            "runtime_smokes": smoke_rows,
            "force_all_runtime_smokes": smoke_rows,
            "runtime_verified_status": ["verified evidence"],
            "open_issues": ["tracked follow-up"],
        }
        lines: list[str] = []

        self.module.append_runtime_snapshot_sections(lines, snapshot)

        rendered = "\n".join(lines)
        ordered_sections = (
            "## Framework Check Status",
            "## Readiness / Fetch Status",
            "## Runtime Smoke Status",
            "### Default Runtime Smoke Status",
            "### Force-All Runtime Smoke Status",
            "## Connector Runtime Availability",
            "## Runtime FAIL Details",
        )
        self.assertEqual(sorted(ordered_sections, key=rendered.index), list(ordered_sections))
        self.assertIn("- verified evidence", rendered)
        self.assertIn("- tracked follow-up", rendered)


if __name__ == "__main__":
    unittest.main()
