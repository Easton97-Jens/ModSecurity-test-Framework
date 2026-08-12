"""Narrow, test-only helpers for synthetic ``common.sh`` fixture tuples.

The helpers never search for a historical production value.  They replace one
named shell assignment at a time in a caller-owned temporary copy and reject
missing or ambiguous assignments.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path


def replace_single_common_assignment(
    source_text: str, variable: str, replacement: str
) -> str:
    """Replace exactly one supported ``common.sh`` assignment structurally."""

    escaped = re.escape(variable)
    patterns = (
        re.compile(
            rf"^(?P<prefix>:\s*\"\$\{{{escaped}:=)(?P<value>.*)(?P<suffix>\}}\"\s*)$",
            re.MULTILINE,
        ),
        re.compile(
            rf"^(?P<prefix>{escaped}\s*=\s*\"\$\{{{escaped}:=)(?P<value>.*)(?P<suffix>\}}\"\s*)$",
            re.MULTILINE,
        ),
        re.compile(
            rf"^(?P<prefix>{escaped}\s*=\s*\"\$\{{{escaped}:-)(?P<value>.*)(?P<suffix>\}}\"\s*)$",
            re.MULTILINE,
        ),
        re.compile(
            rf"^(?P<prefix>{escaped}\s*=\s*\"\$\{{{escaped}-)(?P<value>.*)(?P<suffix>\}}\"\s*)$",
            re.MULTILINE,
        ),
        re.compile(
            rf"^(?P<prefix>{escaped}\s*=\s*\")(?P<value>[^\"`]*)(?P<suffix>\"\s*)$",
            re.MULTILINE,
        ),
    )

    for pattern in patterns:
        rewritten, count = pattern.subn(
            lambda match: (
                f"{match.group('prefix')}{replacement}{match.group('suffix')}"
            ),
            source_text,
        )
        if count == 1:
            return rewritten
        if count > 1:
            raise AssertionError(
                f"test fixture must contain exactly one {variable} assignment"
            )
    raise AssertionError(f"test fixture is missing a supported {variable} assignment")


def rewrite_common_assignments(
    source_text: str, replacements: Mapping[str, str]
) -> str:
    """Return a fixture source with only the requested defaults replaced."""

    rewritten = source_text
    for variable, replacement in replacements.items():
        rewritten = replace_single_common_assignment(rewritten, variable, replacement)
    return rewritten


def write_common_fixture(
    root: Path, source_text: str, replacements: Mapping[str, str]
) -> Path:
    """Write a rewritten test-local ``ci/lib/common.sh`` below ``root``."""

    fixture = root / "ci" / "lib" / "common.sh"
    fixture.parent.mkdir(parents=True, exist_ok=True)
    fixture.write_text(
        rewrite_common_assignments(source_text, replacements), encoding="utf-8"
    )
    return fixture
