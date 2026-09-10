"""Narrow, test-only helpers for synthetic ``common.sh`` fixture tuples.

The helpers never search for a historical production value or evaluate shell
source.  They read or replace one named shell assignment at a time in a
caller-owned temporary copy and reject missing or ambiguous assignments.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path


def _common_assignment_patterns(variable: str) -> tuple[re.Pattern[str], ...]:
    """Return structural patterns for one supported ``common.sh`` assignment."""

    escaped = re.escape(variable)
    return (
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
            rf"^(?P<prefix>{escaped}\s*=\s*\")(?P<value>[^\"$`]*)(?P<suffix>\"\s*)$",
            re.MULTILINE,
        ),
        # Canonical active pins may be safe derived literals, for example an
        # archive name containing ${RELEASE_TAG#...}.  Test fixtures replace
        # the complete quoted assignment; they never evaluate the expression.
        re.compile(
            rf"^(?P<prefix>{escaped}\s*=\s*\")(?P<value>[^\"\n]*)(?P<suffix>\"\s*)$",
            re.MULTILINE,
        ),
    )


def read_single_common_assignment(source_text: str, variable: str) -> str:
    """Read exactly one supported assignment without evaluating shell source."""

    for pattern in _common_assignment_patterns(variable):
        matches = tuple(pattern.finditer(source_text))
        if len(matches) == 1:
            return matches[0].group("value")
        if len(matches) > 1:
            raise AssertionError(
                f"test fixture must contain exactly one {variable} assignment"
            )
    raise AssertionError(f"test fixture is missing a supported {variable} assignment")


def replace_single_common_assignment(
    source_text: str, variable: str, replacement: str
) -> str:
    """Replace exactly one supported ``common.sh`` assignment structurally."""

    for pattern in _common_assignment_patterns(variable):
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
