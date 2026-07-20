#!/usr/bin/env python3
"""Shared resolution rules for Framework-owned report output locations."""

from __future__ import annotations

from pathlib import Path


def resolve_root(root: str | Path, *, label: str) -> Path:
    try:
        return Path(root).expanduser().resolve()
    except Exception as exc:
        raise ValueError(f"{label} is not a valid path: {root}") from exc


def resolve_under_root(root: Path, candidate: Path, *, label: str) -> Path:
    root = root.resolve()
    candidate = candidate.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} must stay under {root}: {candidate}") from exc
    return candidate


def resolve_allowed_output_root(
    output_root: str | Path | None,
    *,
    framework_root: Path,
    connector_root: Path,
) -> Path:
    requested = (
        resolve_root(output_root, label="output root")
        if output_root is not None
        else connector_root
    )
    if requested == framework_root:
        return framework_root
    if requested == connector_root:
        return connector_root
    raise ValueError(
        "output root must resolve exactly to the framework root "
        f"({framework_root}) or connector root ({connector_root}): {requested}"
    )


def report_root_for(
    output_root: Path,
    *,
    framework_root: Path,
    connector_root: Path,
    framework_report_dir: str,
    connector_report_dir: str,
) -> Path:
    if output_root == framework_root:
        return resolve_under_root(
            framework_root,
            framework_root / framework_report_dir,
            label="framework report root",
        )
    if output_root == connector_root:
        return resolve_under_root(
            connector_root,
            connector_root / connector_report_dir,
            label="connector report root",
        )
    raise ValueError(f"unsupported output root: {output_root}")
