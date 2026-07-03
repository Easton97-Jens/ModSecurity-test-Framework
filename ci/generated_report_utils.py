#!/usr/bin/env python3
"""Framework-owned generated report helpers.

Connector repositories are untrusted inputs for report generation; keep helper
code in this repository so generators never import executable connector code.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPORT_OUTPUTS = {
    ("connector_work_queue", "json"): "connector_work_queue.generated.json",
    ("connector_work_queue", "md"): "connector_work_queue.generated.md",
    ("phase_work_queue", "json"): "phase_work_queue.generated.json",
    ("phase_work_queue", "md"): "phase_work_queue.generated.md",
    ("phase_coverage", "md"): "phase_coverage.generated.md",
    ("full_runtime_matrix", "json"): "full_runtime_matrix.generated.json",
    ("runtime_component_cache", "json"): "runtime_component_cache.generated.json",
    ("mrts_native_full", "json"): "mrts_native_full.generated.json",
    ("mrts_native_full", "md"): "mrts_native_full.generated.md",
    ("mrts_native_apache", "json"): "mrts_native_apache.generated.json",
    ("mrts_native_apache", "md"): "mrts_native_apache.generated.md",
    ("mrts_native_nginx", "json"): "mrts_native_nginx.generated.json",
    ("mrts_native_nginx", "md"): "mrts_native_nginx.generated.md",
    ("mrts_native_summary", "json"): "mrts_native_summary.generated.json",
    ("mrts_native_summary", "md"): "mrts_native_summary.generated.md",
}

REPORT_OUTPUT_DIR = Path("reports/testing/generated")
FULL_RUNTIME_MATRIX_INPUT = Path("reports/testing/generated/canonical/full-runtime-matrix.generated.json")



def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _as_posix(path: Path | str) -> str:
    return str(Path(path))


def build_metadata(*, generated_by: str, make_target: str, connector_root: Path | str, framework_root: Path | str, inputs: Iterable[Path | str], generated_at: str | None = None) -> dict[str, Any]:
    return {
        "generated_at": generated_at or utc_now(),
        "generated_by": generated_by,
        "make_target": make_target,
        "connector_root": _as_posix(connector_root),
        "framework_root": _as_posix(framework_root),
        "inputs": [_as_posix(item) for item in inputs],
    }



def trusted_root(value: Path | str, label: str) -> Path:
    reject_path_traversal(value, label)
    return Path(value).resolve()


def require_existing_file_under_approved_roots(candidate: Path | str, approved_roots: Iterable[Path | str], label: str) -> Path:
    reject_path_traversal(candidate, label)
    candidate_path = Path(candidate).resolve(strict=True)
    if not candidate_path.is_file():
        raise ValueError(f"{label} must be a regular file: {candidate_path}")
    for root in approved_roots:
        root_path = Path(root).resolve()
        try:
            candidate_path.relative_to(root_path)
            return candidate_path
        except ValueError:
            continue
    roots = ", ".join(str(Path(root).resolve()) for root in approved_roots)
    raise ValueError(f"{label} must stay under approved roots ({roots}): {candidate_path}")


def metadata_path_label(path: Path, approved_root: Path, root_label: str) -> str:
    resolved = path.resolve(strict=False)
    root = approved_root.resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"metadata path must stay under {root}: {resolved}") from exc
    return f"{root_label}/{relative.as_posix()}"


def resolve_full_runtime_matrix_input(connector_root: Path, explicit_full_matrix: Path | None) -> Path:
    if explicit_full_matrix is not None:
        return require_existing_file_under_approved_roots(explicit_full_matrix, [connector_root], "full runtime matrix")
    return require_under(connector_root, FULL_RUNTIME_MATRIX_INPUT, "default full runtime matrix")


def generated_report_dir(output_root: Path) -> Path:
    return require_under(output_root, REPORT_OUTPUT_DIR, "generated report directory")


def connector_work_queue_output_path(output_dir: Path, suffix: str) -> Path:
    if suffix not in {"json", "md"}:
        raise ValueError(f"unsupported connector work queue output suffix: {suffix}")
    return report_path_from_root(output_dir, "connector_work_queue", suffix)

def report_path_from_root(root: Path | str, name: str, suffix: str) -> Path:
    filename = REPORT_OUTPUTS.get((name, suffix))
    if filename is None:
        raise ValueError(f"unsupported generated report output: {name}.{suffix}")
    return require_under(Path(root).resolve(), Path("canonical") / filename, f"generated report {name}.{suffix}")



def reject_path_traversal(value: Path | str, label: str) -> None:
    raw = str(value)
    path = Path(raw)
    if any(part in {"..", ""} for part in path.parts):
        raise ValueError(f"{label} contains unsafe traversal or empty path segment: {raw}")


def require_under(root: Path | str, candidate: Path | str, label: str) -> Path:
    reject_path_traversal(candidate, label)
    root_path = Path(root).resolve()
    candidate_path = Path(candidate)
    if not candidate_path.is_absolute():
        candidate_path = root_path / candidate_path
    resolved = candidate_path.resolve(strict=False)
    try:
        resolved.relative_to(root_path)
    except ValueError as exc:
        raise ValueError(f"{label} must stay under {root_path}: {resolved}") from exc
    parent = resolved.parent
    existing_parent = parent
    while not existing_parent.exists() and existing_parent != existing_parent.parent:
        existing_parent = existing_parent.parent
    try:
        existing_resolved = existing_parent.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label} parent must be resolvable: {parent}") from exc
    try:
        existing_resolved.relative_to(root_path)
    except ValueError:
        try:
            root_path.relative_to(existing_resolved)
        except ValueError as exc:
            raise ValueError(f"{label} parent must stay under {root_path}: {parent}") from exc
    if existing_parent.is_symlink() and existing_resolved != existing_parent.resolve(strict=False):
        raise ValueError(f"{label} parent resolves through an unsafe symlink: {existing_parent}")
    return resolved

def generated_json_text(payload: Any, metadata: dict[str, Any]) -> str:
    document = {"metadata": metadata, "data": payload}
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def generated_markdown_text(body: str, metadata: dict[str, Any]) -> str:
    generated_at = metadata.get("generated_at", "")
    generated_by = metadata.get("generated_by", "")
    header = [
        "<!-- Generated file - do not edit manually. -->",
        f"> Generated at: `{generated_at}`",
        f"> Generated by: `{generated_by}`",
        "",
    ]
    return "\n".join(header) + body.rstrip() + "\n"
