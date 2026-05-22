#!/usr/bin/env python3
"""Guard against reporting RESPONSE_BODY pass-through evidence as plain PASS."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

import yaml

from response_body_status import RESPONSE_BODY_EVIDENCE_NOTE, is_response_body_related


FRAMEWORK_REPORT_DIR = "docs/testing"
CONNECTOR_REPORT_DIR = "reports/testing"
RUNTIME_SNAPSHOT_FILENAME = "runtime-validation-snapshot.json"


def resolve_root(root: str | Path, *, label: str) -> Path:
    try:
        return Path(root).expanduser().resolve()
    except Exception as exc:
        raise ValueError(f"{label} is not a valid path: {root}") from exc


def report_root_for(framework_root: Path, connector_root: Path, output_root: Path) -> Path:
    if output_root == framework_root:
        return output_root / FRAMEWORK_REPORT_DIR
    if output_root == connector_root:
        return output_root / CONNECTOR_REPORT_DIR
    raise ValueError(f"output root must be the framework root or connector root: {output_root}")


def read_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return raw if isinstance(raw, dict) else {}


def load_cases(framework_root: Path) -> dict[str, dict[str, Any]]:
    cases: dict[str, dict[str, Any]] = {}
    for path in sorted((framework_root / "tests" / "cases").rglob("*.yaml")):
        data = read_yaml(path)
        name = str(data.get("name", path.stem) or path.stem)
        data["path"] = str(path)
        data["id"] = name
        cases[name] = data
    return cases


def case_for_row(row: dict[str, Any], cases: dict[str, dict[str, Any]]) -> dict[str, Any]:
    name = str(row.get("case") or row.get("name") or row.get("case_id") or "").strip()
    case = dict(cases.get(name, {}))
    if name and "name" not in case:
        case["name"] = name
        case["id"] = name
    if row.get("path"):
        case["path"] = str(row["path"])
    if row.get("capabilities"):
        case["capabilities"] = row["capabilities"]
    return case


def is_plain_pass(value: Any) -> bool:
    return str(value).strip() == "PASS"


def validate_response_body_snapshot_row(
    row: dict[str, Any],
    cases: dict[str, dict[str, Any]],
    source: Path,
) -> list[str]:
    case = case_for_row(row, cases)
    if not is_response_body_related(case, case.get("path")):
        return []

    errors: list[str] = []
    case_name = str(row.get("case") or row.get("name") or row.get("case_id") or case.get("name") or "unknown")
    location = f"{source}: case={case_name}"
    if row.get("not_auto_promoted") is not True:
        errors.append(f"{location}: RESPONSE_BODY row must set not_auto_promoted=true")
    if row.get("response_body_non_verified") is not True:
        errors.append(f"{location}: RESPONSE_BODY row must set response_body_non_verified=true")
    if row.get("runtime_verified") is not False:
        errors.append(f"{location}: RESPONSE_BODY row must set runtime_verified=false")
    if row.get("promotion_allowed") is not False:
        errors.append(f"{location}: RESPONSE_BODY row must set promotion_allowed=false")
    if row.get("evidence_note") != RESPONSE_BODY_EVIDENCE_NOTE:
        errors.append(f"{location}: RESPONSE_BODY row must carry the pass-through evidence note")

    if str(row.get("status", "")).strip().lower() == "pass" and is_plain_pass(row.get("matrix_status")):
        errors.append(f"{location}: RESPONSE_BODY runtime PASS must not render as plain PASS")
    return errors


def validate_snapshot(snapshot_path: Path, cases: dict[str, dict[str, Any]]) -> list[str]:
    if not snapshot_path.exists():
        return []
    data = json.loads(snapshot_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    for smoke in data.get("runtime_smokes", []):
        if not isinstance(smoke, dict):
            continue
        for row in smoke.get("cases", []):
            if isinstance(row, dict):
                errors.extend(validate_response_body_snapshot_row(row, cases, snapshot_path))
    return errors


def markdown_cells(line: str) -> list[str] | None:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        return None
    cells = [cell.strip().strip("`") for cell in stripped.strip("|").split("|")]
    if all(set(cell.replace(":", "")) <= {"-"} for cell in cells):
        return None
    return cells


def response_body_case_from_cells(headers: list[str], cells: list[str], cases: dict[str, dict[str, Any]]) -> bool:
    row = dict(zip(headers, cells))
    name = row.get("case_id") or row.get("case") or row.get("case_name") or ""
    case = dict(cases.get(name, {}))
    if name and "name" not in case:
        case["name"] = name
        case["id"] = name
    if row.get("path"):
        case["path"] = row["path"]
    if row.get("category"):
        case["category"] = row["category"]
    return is_response_body_related(case, case.get("path"))


def validate_generated_markdown(path: Path, cases: dict[str, dict[str, Any]]) -> list[str]:
    if not path.exists():
        return []
    errors: list[str] = []
    headers: list[str] = []
    status_headers = {"runtime status", "Apache", "NGINX"}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        cells = markdown_cells(line)
        if cells is None:
            continue
        if any(header in cells for header in ("case_id", "case", "case_name")):
            headers = cells
            continue
        if not headers or len(cells) != len(headers):
            continue
        if not response_body_case_from_cells(headers, cells, cases):
            continue
        row = dict(zip(headers, cells))
        for header in status_headers.intersection(row):
            if is_plain_pass(row[header]):
                errors.append(f"{path}:{line_number}: RESPONSE_BODY generated matrix cell {header} is plain PASS")
    return errors


def generated_markdown_paths(report_root: Path, output_root: Path) -> list[Path]:
    candidates = [
        report_root / "generated" / "runtime-matrix.generated.md",
        report_root / "generated" / "apache-runtime-results.generated.md",
        report_root / "generated" / "nginx-runtime-results.generated.md",
        report_root / "test-coverage-overview.md",
        output_root / "TEST-COVERAGE-SUMMARY.md",
    ]
    return candidates


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--connector-root", default=str(Path.cwd()))
    parser.add_argument("--output-root")
    args = parser.parse_args(argv)

    framework_root = resolve_root(args.framework_root, label="framework root")
    connector_root = resolve_root(args.connector_root, label="connector root")
    output_root = resolve_root(args.output_root, label="output root") if args.output_root else connector_root
    report_root = report_root_for(framework_root, connector_root, output_root)
    cases = load_cases(framework_root)

    errors = validate_snapshot(report_root / RUNTIME_SNAPSHOT_FILENAME, cases)
    for markdown_path in generated_markdown_paths(report_root, output_root):
        errors.extend(validate_generated_markdown(markdown_path, cases))

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("pass: RESPONSE_BODY pass-through promotion guard")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
