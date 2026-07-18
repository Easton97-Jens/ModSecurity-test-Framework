from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
JSON_CHECKER_PATH = ROOT / "ci/checks/security/check-json-result.py"
OSV_COMPARATOR_PATH = ROOT / "ci/checks/security/compare-osv-results.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
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
            result = Path(temporary_directory) / "result.json"
            result.write_text('{"score": 10}\n', encoding="utf-8")
            self.assertEqual(JSON_CHECKER.read_json_object(result, 1024), {"score": 10})

    def test_invalid_symlink_and_oversized_evidence_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            invalid = root / "invalid.json"
            invalid.write_text("not-json", encoding="utf-8")
            with self.assertRaisesRegex(JSON_CHECKER.JsonEvidenceError, "valid UTF-8"):
                JSON_CHECKER.read_json_object(invalid, 1024)

            oversized = root / "oversized.json"
            oversized.write_text('{"payload":"123456"}', encoding="utf-8")
            with self.assertRaisesRegex(
                JSON_CHECKER.JsonEvidenceError, "retention limit"
            ):
                JSON_CHECKER.read_json_object(oversized, 8)

            symlink = root / "symlink.json"
            symlink.symlink_to(invalid)
            with self.assertRaises(JSON_CHECKER.JsonEvidenceError):
                JSON_CHECKER.read_json_object(symlink, 1024)


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
            )
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "new_vulnerabilities")


if __name__ == "__main__":
    unittest.main()
