"""Shared case-root discovery helpers for runner and report tooling."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable


def split_extra_case_roots(raw: str | None = None) -> list[Path]:
    value = os.environ.get("EXTRA_CASE_ROOTS", "") if raw is None else raw
    return [Path(item).expanduser() for item in value.split(":") if item.strip()]


def unique_dirs(paths: Iterable[Path]) -> list[Path]:
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in paths:
        resolved = path.resolve(strict=False)
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(path)
    return unique


def case_dirs(
    repo_root: Path,
    connector: str,
    scope: str,
    framework_root: Path | None = None,
    extra_roots: Iterable[Path] | None = None,
) -> list[Path]:
    common_root = framework_root if framework_root is not None else repo_root
    common_dirs = [common_root / "tests" / "cases"]
    connector_dirs = [common_root / "tests" / "cases" / "connector-specific" / connector]
    extra_dirs = list(extra_roots if extra_roots is not None else split_extra_case_roots())
    if scope == "common":
        return unique_dirs([*common_dirs, *extra_dirs])
    if scope == "connector":
        return unique_dirs(connector_dirs)
    if scope == "all":
        return unique_dirs([*common_dirs, *extra_dirs])
    raise ValueError(f"unsupported case scope: {scope}")


def path_is_under(path: Path, root: Path) -> bool:
    resolved_path = path.resolve(strict=False)
    resolved_root = root.resolve(strict=False)
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError:
        return False
    return True


def path_is_in_extra_root(path: str | Path, extra_roots: Iterable[Path] | None = None) -> bool:
    roots = list(extra_roots if extra_roots is not None else split_extra_case_roots())
    candidate = Path(path)
    return any(path_is_under(candidate, root) for root in roots)


def infer_report_scope(path: str | Path, extra_roots: Iterable[Path] | None = None) -> str:
    candidate = Path(path)
    parts = candidate.parts
    if "tests" in parts:
        index = parts.index("tests")
        tail = parts[index:]
        if len(tail) >= 5 and tail[1] == "cases" and tail[2] == "connector-specific":
            return tail[3]
        if len(tail) >= 3 and tail[1] == "cases":
            return "common"
    if path_is_in_extra_root(candidate, extra_roots):
        return "common"
    return "unknown"


def infer_runner_scope(path: str | Path, extra_roots: Iterable[Path] | None = None) -> str:
    scope = infer_report_scope(path, extra_roots)
    if scope in {"common", "unknown"}:
        return scope
    return f"{scope}/connector-specific"


def all_case_files(framework_root: Path, extra_roots: Iterable[Path] | None = None) -> list[Path]:
    roots = unique_dirs([framework_root / "tests" / "cases", *(extra_roots or split_extra_case_roots())])
    return [
        path
        for root in roots
        if root.is_dir()
        for path in sorted(root.rglob("*.yaml"))
    ]
