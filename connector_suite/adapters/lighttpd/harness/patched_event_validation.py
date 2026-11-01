"""Shared JSONL event parsing and primitive counter validation for Lighttpd.

Callers provide their established non-object diagnostic template so sharing the
parsing loop does not change their externally visible failure wording.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_events(path: Path, *, non_object_error: str) -> list[dict[str, Any]]:
    """Load non-blank JSONL object records using a caller-owned error message."""
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(
                non_object_error.format(path=path, line_number=line_number)
            )
        events.append(value)
    return events


def phase_is_four(value: object) -> bool:
    return str(value or "").strip().replace("-", "_").lower() in {
        "4",
        "phase4",
        "response_body",
    }


def nonnegative(value: object, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a non-negative integer")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a non-negative integer") from exc
    if number < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return number
