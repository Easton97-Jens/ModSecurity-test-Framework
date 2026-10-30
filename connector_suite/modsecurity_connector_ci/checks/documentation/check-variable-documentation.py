#!/usr/bin/env python3
"""Guard the central variable references and unsafe documentation placeholders."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import re
import sys
from pathlib import Path


ROOT = connector_root()
CENTRAL = (
    source_path('docs/reference/variables.md', root=ROOT),
    source_path('docs/reference/variables.de.md', root=ROOT),
    source_path('docs/reference/glossary.md', root=ROOT),
    source_path('docs/reference/glossary.de.md', root=ROOT),
)
BAD_MARKERS = re.compile(r"\b(?:REPLACE_ME|CHANGE_ME)\b")
MARKER_EXPLANATION = re.compile(
    r"(?:explain|explained|erkl[aä]r(?:en|t)|beschreib(?:en|t)|placeholder|Platzhalter)"
    r"[\s\S]{0,240}\b(?:REPLACE_ME|CHANGE_ME)\b|"
    r"\b(?:REPLACE_ME|CHANGE_ME)\b[\s\S]{0,240}"
    r"(?:explain|explained|erkl[aä]r(?:en|t)|beschreib(?:en|t)|placeholder|Platzhalter)",
    re.IGNORECASE,
)
LOCAL_WORKSPACE = re.compile(r"(?:/root/(?:git|conecter)(?:/|\b)|[A-Za-z]:\\Users\\)")
VARIABLE_RE = re.compile(r"(?:\$\{?[A-Z][A-Z0-9_]*\}?|\$\([A-Z][A-Z0-9_]*\))")
SCOPE = (source_path('README.md', root=ROOT), source_path('README.de.md', root=ROOT), source_path('docs', root=ROOT), source_path('examples', root=ROOT), source_path('ci/README.md', root=ROOT), source_path('ci/README.de.md', root=ROOT))


def documents() -> list[Path]:
    result: set[Path] = set()
    for item in SCOPE:
        if item.is_file():
            result.add(item)
        elif item.is_dir():
            result.update(path for path in item.rglob("*.md") if "generated" not in path.parts and "archive" not in path.parts)
    return sorted(result)


def main() -> int:
    errors: list[str] = []
    missing = [path.relative_to(ROOT).as_posix() for path in CENTRAL if not path.is_file()]
    if missing:
        errors.append("missing central reference: " + ", ".join(missing))
    variables_seen: set[str] = set()
    for path in documents():
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT).as_posix()
        variables_seen.update(VARIABLE_RE.findall(text))
        # A style guide may name an otherwise forbidden marker while explaining
        # it.  Treat that as documentation, but keep rejecting a marker that is
        # merely left in a runnable/example document without nearby guidance.
        if BAD_MARKERS.search(text) and not MARKER_EXPLANATION.search(text):
            errors.append(f"{relative}: contains REPLACE_ME or CHANGE_ME")
        if LOCAL_WORKSPACE.search(text):
            errors.append(f"{relative}: contains a local developer path")
    if errors:
        print("variable documentation: FAIL", file=sys.stderr)
        print("\n".join(sorted(set(errors))), file=sys.stderr)
        return 2
    print(f"variable documentation: PASS ({len(variables_seen)} documented variable references scanned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
