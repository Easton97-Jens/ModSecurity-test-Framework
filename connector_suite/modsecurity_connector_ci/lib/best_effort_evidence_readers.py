#!/usr/bin/env python3
"""Permissive parsers for non-authoritative runtime/report evidence.

Path containment, receipt validation, and status decisions deliberately remain
the responsibility of each caller.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def read_json_object(path: Path) -> dict[str, Any]:
    """Return a JSON object or an empty object for unusable evidence."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def read_jsonl_objects(path: Path) -> list[dict[str, Any]]:
    """Return valid JSON-object rows in source order from a JSONL file."""
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return rows
    for line in lines:
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except Exception:
            continue
        if isinstance(data, dict):
            rows.append(data)
    return rows
