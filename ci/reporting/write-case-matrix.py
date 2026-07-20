#!/usr/bin/env python3
"""Generate a standalone case matrix from YAML cases and optional smoke results."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

FRAMEWORK_ROOT = Path(os.environ.get("FRAMEWORK_ROOT", Path(__file__).resolve().parents[2])).resolve()
CONNECTOR_ROOT = Path(os.environ.get("CONNECTOR_ROOT", Path.cwd())).resolve()
REPO_ROOT = CONNECTOR_ROOT
RUNNERS = FRAMEWORK_ROOT / "tests" / "runners"
LIB_DIR = FRAMEWORK_ROOT / "ci" / "lib"
for path in (RUNNERS, LIB_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from runner_core import case_info, load_case  # noqa: E402
from response_body_status import is_response_body_related  # noqa: E402


def result_status(results: dict[str, object], connector: str, name: str) -> str:
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
        result_status(results, "apache", name),
        result_status(results, "nginx", name),
        case_kind(info),
        notes,
    ]
    return "| " + " | ".join(value.replace("|", "\\|") for value in values) + " |"


def configured_build_root() -> Path:
    configured_build_root = os.environ.get("BUILD_ROOT")
    configured_run_root = os.environ.get("VERIFIED_RUN_ROOT")
    if configured_build_root:
        root = Path(configured_build_root)
    elif configured_run_root:
        root = Path(configured_run_root) / "build"
    else:
        raise ValueError("BUILD_ROOT or VERIFIED_RUN_ROOT must be set")
    if root.exists() and root.is_symlink():
        raise ValueError(f"build root must not be a symlink: {root}")
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    resolved = root.resolve(strict=True)
    metadata = resolved.stat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"build root must be a directory: {resolved}")
    if metadata.st_uid != os.getuid() or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError(f"build root must be private and owned by this user: {resolved}")
    return resolved


def path_under_build_root(raw_path: str | Path, build_root: Path, label: str) -> Path:
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = build_root / candidate
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(build_root)
    except ValueError as exc:
        raise ValueError(f"{label} must stay under {build_root}: {resolved}") from exc
    return resolved


def write_matrix(path: Path, content: str, build_root: Path) -> None:
    output = path_under_build_root(path, build_root, "case matrix output")
    output.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    parent = output.parent.resolve(strict=True)
    try:
        parent.relative_to(build_root)
    except ValueError as exc:
        raise ValueError(f"case matrix output parent must stay under {build_root}: {parent}") from exc
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(output, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)


def main(argv: list[str]) -> int:
    try:
        build_root = configured_build_root()
        results_path = path_under_build_root(
            argv[1] if len(argv) > 1 else "results/connector-summary.json",
            build_root,
            "connector summary input",
        )
        output_path = path_under_build_root(
            argv[2] if len(argv) > 2 else "case-matrix.md",
            build_root,
            "case matrix output",
        )
    except ValueError as exc:
        print(f"invalid case-matrix path: {exc}", file=sys.stderr)
        return 2
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
    try:
        write_matrix(output_path, "\n".join(lines) + "\n", build_root)
    except ValueError as exc:
        print(f"invalid case-matrix output: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
