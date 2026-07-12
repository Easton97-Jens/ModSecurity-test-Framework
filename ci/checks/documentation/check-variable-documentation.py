#!/usr/bin/env python3
"""Validate the Framework's bilingual variable and placeholder references.

The check deliberately validates documentation inputs rather than shell internals:
it inventories user-facing shell/Make variables and placeholders in maintained
Markdown, verifies that the central English and German references cover them,
and rejects unsafe developer-path and replacement markers. Generated reports and
the MRTS submodule are separate sources of truth and are not rewritten here.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
VARIABLE_REFERENCE = ROOT / "docs/reference/variables.md"
VARIABLE_REFERENCE_DE = ROOT / "docs/reference/variables.de.md"
GLOSSARY = ROOT / "docs/reference/glossary.md"
GLOSSARY_DE = ROOT / "docs/reference/glossary.de.md"

SKIPPED_PREFIXES = (
    "docs/testing/generated/",
    "tools/MRTS/",
)
SKIPPED_NAMES = {
    "TEST-COVERAGE-SUMMARY.md",
    "TEST-COVERAGE-SUMMARY.de.md",
}
SHELL_VARIABLE_RE = re.compile(r"\$(?:\{)?([A-Z][A-Z0-9_]+)")
MAKE_VARIABLE_RE = re.compile(r"\$\(([A-Z][A-Z0-9_]+)\)")
ASSIGNMENT_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Z][A-Z0-9_]+)\s*(?:\?=|:=|=)")
DOCUMENTED_VARIABLE_RE = re.compile(r"\b([A-Z][A-Z0-9_]+)\b")
PLACEHOLDER_RE = re.compile(r"<([A-Za-z][A-Za-z0-9_-]*)>")
EMPTY_PLACEHOLDER_RE = re.compile(r"<\s+>")
LOCAL_PATH_RE = re.compile(r"/root" + r"/git/|[A-Za-z]:\\\\Users\\")
REPLACEMENT_MARKERS = ("REPLACE_ME", "CHANGE_ME")
REQUIRED_GLOSSARY_TERMS = (
    "ABI",
    "ALPN",
    "API",
    "APXS",
    "CRS",
    "EOS",
    "Evidence",
    "ext_authz",
    "ext_proc",
    "Full Lifecycle",
    "HTX",
    "Late Intervention",
    "No-CRS",
    "P1 / P2 / P3 / P4",
    "Promotion",
    "QUIC",
    "SPOE / SPOA / SPOP",
    "TTFB",
    "UDS",
    "Upstream",
    "Wire Body",
    "Entity Body",
    "First Byte Before EOS",
    "No Full Response Buffering",
)


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def is_skipped(path: Path) -> bool:
    name = path.name
    if name in SKIPPED_NAMES:
        return True
    value = relative(path)
    return value.startswith(SKIPPED_PREFIXES)


def markdown_files() -> list[Path]:
    candidates = [
        ROOT / "README.md",
        ROOT / "README.de.md",
        ROOT / "ci/README.md",
        ROOT / "ci/README.de.md",
        ROOT / "tests/README.md",
        ROOT / "tests/README.de.md",
    ]
    candidates.extend(path for path in (ROOT / "docs").rglob("*.md"))
    return sorted({path for path in candidates if path.is_file() and not is_skipped(path)})


def counterpart(path: Path) -> Path:
    if path.name.endswith(".de.md"):
        return path.with_name(path.name.removesuffix(".de.md") + ".md")
    return path.with_name(path.name.removesuffix(".md") + ".de.md")


def variables_in(text: str) -> set[str]:
    return {
        *SHELL_VARIABLE_RE.findall(text),
        *MAKE_VARIABLE_RE.findall(text),
        *ASSIGNMENT_RE.findall(text),
    }


def placeholders_in(text: str) -> set[str]:
    return set(PLACEHOLDER_RE.findall(text))


def format_set(values: set[str]) -> str:
    return ", ".join(sorted(values))


def main() -> int:
    errors: list[str] = []
    required_files = (VARIABLE_REFERENCE, VARIABLE_REFERENCE_DE, GLOSSARY, GLOSSARY_DE)
    for path in required_files:
        if not path.is_file():
            errors.append(f"missing required reference: {relative(path)}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    reference_en = VARIABLE_REFERENCE.read_text(encoding="utf-8")
    reference_de = VARIABLE_REFERENCE_DE.read_text(encoding="utf-8")
    glossary_en = GLOSSARY.read_text(encoding="utf-8")
    glossary_de = GLOSSARY_DE.read_text(encoding="utf-8")
    reference_variables_en = set(DOCUMENTED_VARIABLE_RE.findall(reference_en))
    reference_variables_de = set(DOCUMENTED_VARIABLE_RE.findall(reference_de))
    reference_placeholders_en = placeholders_in(reference_en)
    reference_placeholders_de = placeholders_in(reference_de)

    if reference_variables_en != reference_variables_de:
        only_en = reference_variables_en - reference_variables_de
        only_de = reference_variables_de - reference_variables_en
        if only_en:
            errors.append(f"variables only in English reference: {format_set(only_en)}")
        if only_de:
            errors.append(f"variables only in German reference: {format_set(only_de)}")
    if reference_placeholders_en != reference_placeholders_de:
        only_en = reference_placeholders_en - reference_placeholders_de
        only_de = reference_placeholders_de - reference_placeholders_en
        if only_en:
            errors.append(f"placeholders only in English reference: {format_set(only_en)}")
        if only_de:
            errors.append(f"placeholders only in German reference: {format_set(only_de)}")
    for term in REQUIRED_GLOSSARY_TERMS:
        if term not in glossary_en:
            errors.append(f"English glossary missing term: {term}")
        if term not in glossary_de:
            errors.append(f"German glossary missing term: {term}")

    found_variables: set[str] = set()
    found_placeholders: set[str] = set()
    shell_variables: set[str] = set()
    make_variables: set[str] = set()
    references_found = 0
    for path in markdown_files():
        text = path.read_text(encoding="utf-8")
        text_variables = variables_in(text)
        text_placeholders = placeholders_in(text)
        found_variables.update(text_variables)
        found_placeholders.update(text_placeholders)
        shell_variables.update(SHELL_VARIABLE_RE.findall(text))
        make_variables.update(MAKE_VARIABLE_RE.findall(text))
        references_found += len(re.findall(r"(?<!!)\[[^\]]+\]\([^)]+\)", text))
        peer = counterpart(path)
        if not peer.is_file() and relative(path).startswith("docs/"):
            errors.append(f"missing bilingual partner: {relative(path)} -> {relative(peer)}")
        for marker in REPLACEMENT_MARKERS:
            if marker in text:
                errors.append(f"{relative(path)}: prohibited replacement marker {marker}")
        if LOCAL_PATH_RE.search(text):
            errors.append(f"{relative(path)}: contains a local developer path")
        if EMPTY_PLACEHOLDER_RE.search(text):
            errors.append(f"{relative(path)}: empty placeholder <> is not documented")

    undocumented_variables = found_variables - reference_variables_en - reference_variables_de
    undocumented_placeholders = found_placeholders - reference_placeholders_en - reference_placeholders_de
    if undocumented_variables:
        errors.append("variables without central bilingual reference: " + format_set(undocumented_variables))
    if undocumented_placeholders:
        errors.append("placeholders without central bilingual reference: " + format_set(undocumented_placeholders))

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    print(
        "variable documentation ok: "
        f"shell_variables_found={len(shell_variables)} "
        f"make_variables_found={len(make_variables)} "
        f"variables_documented_centrally={len(reference_variables_en)} "
        f"placeholders_found={len(found_placeholders)} "
        f"placeholders_documented_centrally={len(reference_placeholders_en)} "
        f"references_found={references_found} "
        "approved_exceptions=generated-reports,MRTS-submodule"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
