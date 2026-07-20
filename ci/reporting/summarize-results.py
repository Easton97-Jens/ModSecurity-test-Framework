#!/usr/bin/env python3
"""Print a compact connector smoke summary from connector-summary.json."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def configured_summary_root() -> Path:
    configured_root = os.environ.get("BUILD_ROOT") or os.environ.get("VERIFIED_RUN_ROOT")
    if not configured_root:
        raise ValueError("BUILD_ROOT or VERIFIED_RUN_ROOT must be set for summary input")
    return Path(configured_root).resolve()


def summary_path(raw_path: str, approved_root: Path) -> Path:
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = approved_root / candidate
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(approved_root)
    except ValueError as exc:
        raise ValueError(f"summary input must stay under {approved_root}: {resolved}") from exc
    return resolved


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: summarize-results.py CONNECTOR_SUMMARY_JSON (under BUILD_ROOT or VERIFIED_RUN_ROOT)", file=sys.stderr)
        return 2

    try:
        path = summary_path(argv[1], configured_summary_root())
    except ValueError as exc:
        print(f"invalid summary input: {exc}", file=sys.stderr)
        return 2
    if not path.exists():
        print(f"summary missing: {path}", file=sys.stderr)
        return 1

    data = json.loads(path.read_text(encoding="utf-8"))
    for connector in ("apache", "nginx"):
        summary = data.get(connector)
        if not isinstance(summary, dict):
            print(f"{connector}: missing")
            continue
        counts = summary.get("summary", {})
        variables = ", ".join(summary.get("verified_variables", []))
        print(f"{connector}: {counts}")
        print(f"  environment: {summary.get('environment', '')}")
        print(f"  audit_behavior: {summary.get('audit_behavior', '')}")
        print(f"  verified_variables: {variables}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
