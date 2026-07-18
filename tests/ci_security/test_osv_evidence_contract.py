from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
JSON_CHECKER_PATH = ROOT / "ci/checks/security/check-json-result.py"
OSV_COMPARATOR_PATH = ROOT / "ci/checks/security/compare-osv-results.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


JSON_CHECKER = load_module("json_evidence_checker", JSON_CHECKER_PATH)
OSV_COMPARATOR = load_module("osv_result_comparator", OSV_COMPARATOR_PATH)


def scan_report(*packages: dict[str, object]) -> dict[str, object]:
    return {"results": [{"packages": list(packages)}]}


def vulnerable_package(
    name: str,
    version: str,
    vulnerability_ids: list[str],
    group_ids: list[str] | None = None,
) -> dict[str, object]:
    return {
        "package": {"name": name, "version": version, "ecosystem": "PyPI"},
        "vulnerabilities": [
            {"id": vulnerability_id, "aliases": []}
            for vulnerability_id in vulnerability_ids
        ],
        "groups": [{"ids": group_ids or vulnerability_ids}],
    }


class JsonEvidenceContractTest(unittest.TestCase):
    def test_regular_bounded_json_object_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            runner_temp = Path(temporary_directory)
            result = runner_temp / "result.json"
            result.write_text('{"score": 10}\n', encoding="utf-8")
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                self.assertEqual(
                    JSON_CHECKER.read_json_object(result, 1024), {"score": 10}
                )

    def test_invalid_symlink_and_oversized_evidence_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            invalid = root / "invalid.json"
            invalid.write_text("not-json", encoding="utf-8")
            oversized = root / "oversized.json"
            oversized.write_text('{"payload":"123456"}', encoding="utf-8")
            symlink = root / "symlink.json"
            symlink.symlink_to(invalid)
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(root)}):
                with self.assertRaisesRegex(
                    JSON_CHECKER.JsonEvidenceError, "valid UTF-8"
                ):
                    JSON_CHECKER.read_json_object(invalid, 1024)
                with self.assertRaisesRegex(
                    JSON_CHECKER.JsonEvidenceError, "retention limit"
                ):
                    JSON_CHECKER.read_json_object(oversized, 8)
                with self.assertRaises(JSON_CHECKER.JsonEvidenceError):
                    JSON_CHECKER.read_json_object(symlink, 1024)

    def test_osv_schema_mode_rejects_generic_json_and_accepts_clean_results(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            JSON_CHECKER.JsonEvidenceError, "not an OSV report"
        ):
            JSON_CHECKER.validate_osv_evidence({})
        JSON_CHECKER.validate_osv_evidence({"results": []})

    def test_evidence_outside_a_trusted_temporary_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            trusted_root = root / "trusted"
            trusted_root.mkdir()
            untrusted = root / "untrusted.json"
            untrusted.write_text('{"score": 10}\n', encoding="utf-8")
            with mock.patch.object(
                JSON_CHECKER,
                "trusted_evidence_roots",
                return_value=(trusted_root.resolve(),),
            ):
                with self.assertRaisesRegex(
                    JSON_CHECKER.JsonEvidenceError,
                    "trusted temporary directory",
                ):
                    JSON_CHECKER.read_json_object(untrusted, 1024)

    def test_runner_temp_excludes_the_general_system_temporary_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            runner_temp = root / "runner-temp"
            runner_temp.mkdir()
            untrusted = root / "untrusted.json"
            untrusted.write_text('{"score": 10}\n', encoding="utf-8")
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                self.assertEqual(
                    JSON_CHECKER.trusted_evidence_roots(), (runner_temp.resolve(),)
                )
                with self.assertRaisesRegex(
                    JSON_CHECKER.JsonEvidenceError,
                    "trusted temporary directory",
                ):
                    JSON_CHECKER.read_json_object(untrusted, 1024)


class OsvComparisonContractTest(unittest.TestCase):
    def test_alias_equivalent_vulnerability_is_not_new_after_version_change(
        self,
    ) -> None:
        base = scan_report(
            vulnerable_package("example", "1.0.0", ["GHSA-example", "CVE-2026-0001"])
        )
        head = scan_report(
            vulnerable_package("example", "1.1.0", ["GHSA-example", "CVE-2026-0001"])
        )
        comparison = OSV_COMPARATOR.compare_reports(base, head, "a" * 40, "b" * 40)
        self.assertEqual(comparison["status"], "no_new_vulnerabilities")
        self.assertEqual(comparison["new_vulnerability_groups"], [])

    def test_alias_enrichment_is_not_a_new_vulnerability_group(self) -> None:
        base = scan_report(vulnerable_package("example", "1.0.0", ["GHSA-example"]))
        head = scan_report(
            vulnerable_package(
                "example",
                "1.1.0",
                ["GHSA-example", "CVE-2026-0001"],
                ["GHSA-example", "CVE-2026-0001"],
            )
        )
        comparison = OSV_COMPARATOR.compare_reports(base, head, "a" * 40, "b" * 40)
        self.assertEqual(comparison["status"], "no_new_vulnerabilities")
        self.assertEqual(comparison["new_vulnerability_groups"], [])

    def test_new_group_is_reported_without_runner_source_paths(self) -> None:
        base = {"results": []}
        head = {
            "results": [
                {
                    "source": {
                        "path": "/private/runner/path/requirements.txt",
                        "type": "lockfile",
                    },
                    "packages": [
                        vulnerable_package("example", "1.1.0", ["GHSA-example"])
                    ],
                }
            ]
        }
        comparison = OSV_COMPARATOR.compare_reports(base, head, "a" * 40, "b" * 40)
        rendered = json.dumps(comparison, sort_keys=True)
        self.assertEqual(comparison["status"], "new_vulnerabilities")
        self.assertEqual(len(comparison["new_vulnerability_groups"]), 1)
        self.assertNotIn("/private/runner/path", rendered)

    def test_malformed_osv_schema_is_rejected(self) -> None:
        with self.assertRaisesRegex(OSV_COMPARATOR.OsvComparisonError, "results list"):
            OSV_COMPARATOR.compare_reports({}, {"results": []}, "a" * 40, "b" * 40)
        malformed_package = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {
                                "name": "example",
                                "version": "1.0.0",
                                "ecosystem": "PyPI",
                            },
                            "vulnerabilities": [{"id": "GHSA-example"}],
                        }
                    ]
                }
            ]
        }
        with self.assertRaisesRegex(OSV_COMPARATOR.OsvComparisonError, "groups"):
            OSV_COMPARATOR.compare_reports(
                malformed_package, {"results": []}, "a" * 40, "b" * 40
            )

    def test_incomplete_or_overlapping_groups_are_rejected(self) -> None:
        incomplete = scan_report(
            vulnerable_package(
                "example",
                "1.0.0",
                ["GHSA-example", "CVE-2026-0001"],
                ["GHSA-example"],
            )
        )
        with self.assertRaisesRegex(
            OSV_COMPARATOR.OsvComparisonError, "cover every listed"
        ):
            OSV_COMPARATOR.compare_reports(
                incomplete, {"results": []}, "a" * 40, "b" * 40
            )

        overlapping = scan_report(
            {
                "package": {
                    "name": "example",
                    "version": "1.0.0",
                    "ecosystem": "PyPI",
                },
                "vulnerabilities": [
                    {"id": "GHSA-example", "aliases": []},
                    {"id": "CVE-2026-0001", "aliases": []},
                ],
                "groups": [
                    {"ids": ["GHSA-example"]},
                    {"ids": ["GHSA-example", "CVE-2026-0001"]},
                ],
            }
        )
        with self.assertRaisesRegex(
            OSV_COMPARATOR.OsvComparisonError, "must not overlap"
        ):
            OSV_COMPARATOR.compare_reports(
                overlapping, {"results": []}, "a" * 40, "b" * 40
            )

    def test_comparator_rejects_untrusted_and_symlinked_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            trusted_root = root / "trusted"
            trusted_root.mkdir()
            untrusted = root / "untrusted.json"
            untrusted.write_text('{"results": []}\n', encoding="utf-8")
            with mock.patch.object(
                OSV_COMPARATOR,
                "trusted_evidence_roots",
                return_value=(trusted_root.resolve(),),
            ):
                with self.assertRaisesRegex(
                    OSV_COMPARATOR.OsvComparisonError,
                    "trusted temporary directory",
                ):
                    OSV_COMPARATOR.read_report(untrusted)
                with self.assertRaisesRegex(
                    OSV_COMPARATOR.OsvComparisonError,
                    "trusted temporary directory",
                ):
                    OSV_COMPARATOR.write_report(untrusted, {"results": []})

            report = trusted_root / "report.json"
            report.write_text('{"results": []}\n', encoding="utf-8")
            symlink = trusted_root / "report-link.json"
            symlink.symlink_to(report)
            with self.assertRaises(OSV_COMPARATOR.OsvComparisonError):
                OSV_COMPARATOR.read_report(symlink)

    def test_comparator_uses_runner_temp_exclusively_when_available(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            runner_temp = root / "runner-temp"
            runner_temp.mkdir()
            untrusted = root / "untrusted.json"
            untrusted.write_text('{"results": []}\n', encoding="utf-8")
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                self.assertEqual(
                    OSV_COMPARATOR.trusted_evidence_roots(), (runner_temp.resolve(),)
                )
                with self.assertRaisesRegex(
                    OSV_COMPARATOR.OsvComparisonError,
                    "trusted temporary directory",
                ):
                    OSV_COMPARATOR.read_report(untrusted)

    def test_comparator_preserves_validated_nested_output_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            runner_temp = Path(temporary_directory)
            output = runner_temp / "nested" / "comparison.json"
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                OSV_COMPARATOR.write_report(output, {"results": []})
                self.assertEqual(
                    json.loads(output.read_text(encoding="utf-8")), {"results": []}
                )

    def test_command_writes_comparison_before_returning_new_group_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            base = root / "base.json"
            head = root / "head.json"
            output = root / "comparison.json"
            base.write_text('{"results": []}\n', encoding="utf-8")
            head.write_text(
                json.dumps(
                    scan_report(
                        vulnerable_package("example", "1.1.0", ["GHSA-example"])
                    )
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(OSV_COMPARATOR_PATH),
                    "--base",
                    str(base),
                    "--head",
                    str(head),
                    "--base-revision",
                    "a" * 40,
                    "--head-revision",
                    "b" * 40,
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                encoding="utf-8",
                env={**os.environ, "RUNNER_TEMP": str(root)},
            )
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "new_vulnerabilities")


if __name__ == "__main__":
    unittest.main()
