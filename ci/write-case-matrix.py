#!/usr/bin/env python3
"""Generate docs/testing/case-matrix.md from YAML cases and optional smoke results."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

FRAMEWORK_ROOT = Path(os.environ.get("FRAMEWORK_ROOT", Path(__file__).resolve().parents[1])).resolve()
CONNECTOR_ROOT = Path(os.environ.get("CONNECTOR_ROOT", Path.cwd())).resolve()
REPO_ROOT = CONNECTOR_ROOT
RUNNERS = FRAMEWORK_ROOT / "tests" / "runners"
sys.path.insert(0, str(RUNNERS))

from runner_core import case_info, load_case  # noqa: E402
from response_body_status import is_response_body_related  # noqa: E402


def result_status(results: dict[str, object], connector: str, name: str, case: dict[str, object], path: Path) -> str:
    summary = results.get(connector, {})
    if not isinstance(summary, dict):
        return "unknown"
    cases = summary.get("cases", {})
    if not isinstance(cases, dict):
        return "unknown"
    result_case = cases.get(name, {})
    if isinstance(result_case, dict):
        status = str(result_case.get("status", "unknown"))
        return status
    return "unknown"


def case_source(info: dict[str, object], path: Path) -> str:
    origins = info.get("origin", [])
    if not isinstance(origins, list):
        return relative_path(path)
    parts = []
    for origin in origins:
        if isinstance(origin, dict):
            parts.append(f"{origin.get('repo', '')}:{origin.get('path', '')}")
    if parts:
        return "; ".join(parts)
    return relative_path(path)


def relative_path(path: Path) -> str:
    resolved = path.resolve()
    for root in (CONNECTOR_ROOT, FRAMEWORK_ROOT):
        try:
            return str(resolved.relative_to(root))
        except ValueError:
            continue
    return str(path)


def case_kind(info: dict[str, object]) -> str:
    scope = str(info.get("scope", ""))
    if scope.startswith(("apache/", "nginx/")):
        return "connector-specific"
    return "common"


def all_case_paths() -> list[Path]:
    roots = [
        FRAMEWORK_ROOT / "tests" / "common" / "cases",
        CONNECTOR_ROOT / "connectors" / "apache" / "tests" / "cases",
        CONNECTOR_ROOT / "connectors" / "nginx" / "tests" / "cases",
    ]
    return sorted(path for root in roots if root.exists() for path in root.rglob("*.yaml"))


def load_results(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def row(path: Path, results: dict[str, object]) -> str:
    case = load_case(path)
    info = case_info(case, path)
    name = str(info["name"])
    capabilities = ", ".join(info.get("capabilities", []))
    category = str(info.get("category", "") or info.get("group", ""))
    notes = "; ".join(info.get("known_limitations", []))
    values = [
        name,
        case_source(info, path),
        category,
        capabilities,
        result_status(results, "apache", name, dict(case), path),
        result_status(results, "nginx", name, dict(case), path),
        case_kind(info),
        notes,
    ]
    return "| " + " | ".join(value.replace("|", "\\|") for value in values) + " |"


def main(argv: list[str]) -> int:
    default_build_root = Path(
        os.environ.get(
            "BUILD_ROOT",
            str(Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state"))) / "ModSecurity-conector-build"),
        )
    )
    results_path = Path(argv[1]) if len(argv) > 1 else default_build_root / "results" / "connector-summary.json"
    output_path = Path(argv[2]) if len(argv) > 2 else REPO_ROOT / "docs" / "testing" / "case-matrix.md"
    results = load_results(results_path)
    lines = [
        "# Case Matrix",
        "",
        "Generated from repository YAML cases and, when present, connector summary results.",
        "",
        "| case_name | source | category | capabilities | apache_status | nginx_status | common_or_connector_specific | notes |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    lines.extend(row(path, results) for path in all_case_paths())
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
