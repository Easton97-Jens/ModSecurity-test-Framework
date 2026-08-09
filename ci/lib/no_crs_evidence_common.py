#!/usr/bin/env python3
"""Shared fail-closed primitives for canonical No-CRS evidence checkers."""

from __future__ import annotations

from pathlib import Path
from types import ModuleType
from typing import Any, Sequence


CANONICAL_BASE_CHECKS = (
    "schema",
    "completeness",
    "capability",
    "claim-policy",
    "layout",
    "body-payload",
    "protocol-client",
    "status",
)


def load_json_object(
    no_crs: ModuleType, path: Path, label: str
) -> tuple[dict[str, Any] | None, list[str]]:
    """Load one canonical JSON object while preserving stable CLI errors."""

    try:
        payload = no_crs.load_json(path)
    except Exception as exc:
        return None, [f"{label}: cannot read JSON: {exc}"]
    if not isinstance(payload, dict):
        return None, [f"{label}: must be a JSON object"]
    return payload, []


def canonical_base_errors(
    no_crs: ModuleType,
    run_dir: Path,
    connector: str,
    checks: Sequence[str] = CANONICAL_BASE_CHECKS,
) -> list[str]:
    """Validate the shared canonical evidence baseline for one connector run."""

    capabilities_path = run_dir / "inventory" / "capabilities.json"
    try:
        capabilities = no_crs.load_capability_manifest(capabilities_path, connector)
    except Exception as exc:
        return [f"inventory/capabilities.json: {exc}"]
    return no_crs.validate_run(run_dir, connector, capabilities, checks)
