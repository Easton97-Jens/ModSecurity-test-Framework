#!/usr/bin/env python3
"""Validate paired Framework Change Record structure and language links."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
from typing import Iterable


ENGLISH_HEADINGS = (
    "Identity",
    "Motivation and problem statement",
    "Affected components and security boundaries",
    "Acceptance criteria",
    "Alternatives considered",
    "Implementation decision",
    "Changed files and tests",
    "Commands and results",
    "Security impact",
    "Documentation and runtime evidence",
    "Checks not run",
    "Limitations and residual risk",
    "Final diff and review status",
)
GERMAN_HEADINGS = (
    "Identität",
    "Motivation und Problemstellung",
    "Betroffene Komponenten und Sicherheitsgrenzen",
    "Akzeptanzkriterien",
    "Untersuchte Alternativen",
    "Implementierungsentscheidung",
    "Geänderte Dateien und Tests",
    "Befehle und Ergebnisse",
    "Sicherheitsauswirkung",
    "Dokumentation und Runtime-Evidenz",
    "Nicht ausgeführte Prüfungen",
    "Einschränkungen und Restrisiko",
    "Finaler Diff- und Review-Status",
)
LEGACY_HEADINGS_BY_CHANGE_ID = {
    "20260718-01-fix-framework-actions-sha-pins": {
        "english": (
            "Identity",
            "Motivation and security boundary",
            "Acceptance criteria and implementation decision",
            "Tests and evidence",
            "Documentation, delivery, and residual risk",
        ),
        "german": (
            "Identität",
            "Motivation und Sicherheitsgrenze",
            "Akzeptanzkriterien und Implementierungsentscheidung",
            "Tests und Evidenz",
            "Dokumentation, Delivery und Restrisiko",
        ),
    }
}
TEMPLATE_FILENAMES = {"README.md", "README.de.md", "TEMPLATE.md", "TEMPLATE.de.md"}
CHANGE_ID = re.compile(
    r"^\| (?:Change ID|Change-ID) \| (?P<value>[^|]+) \|$", re.MULTILINE
)
HEADING = re.compile(r"^## (?P<value>.+)$", re.MULTILINE)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc


def record_paths(records_dir: Path) -> Iterable[Path]:
    if not records_dir.is_dir():
        return []
    return sorted(
        path
        for path in records_dir.glob("*.md")
        if path.name not in TEMPLATE_FILENAMES and not path.name.endswith(".de.md")
    )


def headings(text: str) -> tuple[str, ...]:
    return tuple(match.group("value").strip() for match in HEADING.finditer(text))


def permitted_headings(change_id: str, german: bool) -> tuple[tuple[str, ...], ...]:
    primary = GERMAN_HEADINGS if german else ENGLISH_HEADINGS
    language = "german" if german else "english"
    legacy = LEGACY_HEADINGS_BY_CHANGE_ID.get(change_id, {}).get(language)
    return (primary,) if legacy is None else (primary, legacy)


def change_id(text: str) -> str | None:
    match = CHANGE_ID.search(text)
    return match.group("value").strip().strip("`") if match else None


def record_errors(english_path: Path) -> list[str]:
    errors: list[str] = []
    german_path = english_path.with_name(f"{english_path.stem}.de.md")
    try:
        english = read_text(english_path)
    except ValueError as exc:
        return [str(exc)]
    if not german_path.is_file():
        return [f"{english_path}: missing German counterpart {german_path.name}"]
    try:
        german = read_text(german_path)
    except ValueError as exc:
        return [str(exc)]

    expected_id = english_path.stem
    if headings(english) not in permitted_headings(expected_id, german=False):
        errors.append(
            f"{english_path}: English Change Record headings do not match the template"
        )
    if headings(german) not in permitted_headings(expected_id, german=True):
        errors.append(
            f"{german_path}: German Change Record headings do not match the template"
        )
    if change_id(english) != expected_id:
        errors.append(f"{english_path}: Change ID must match filename {expected_id!r}")
    if change_id(german) != expected_id:
        errors.append(f"{german_path}: Change-ID must match filename {expected_id!r}")
    english_link = f"[Deutsch]({german_path.name})"
    german_link = f"[English]({english_path.name})"
    if english_link not in english:
        errors.append(f"{english_path}: missing reciprocal German language link")
    if german_link not in german:
        errors.append(f"{german_path}: missing reciprocal English language link")
    for placeholder in (
        "Record the unique UTC-based ID",
        "Record each executed command",
        "Dokumentiere die eindeutige UTC-basierte ID",
        "Dokumentiere jeden ausgeführten Befehl",
    ):
        if placeholder in english or placeholder in german:
            errors.append(
                f"{english_path}: Change Record still contains a template placeholder"
            )
            break
    return errors


def validate(root: Path, records_dir: Path) -> list[str]:
    resolved_dir = records_dir if records_dir.is_absolute() else root / records_dir
    errors: list[str] = []
    if not resolved_dir.is_dir():
        return [f"{resolved_dir}: required Change Record directory is missing"]
    english_records = tuple(record_paths(resolved_dir))
    if not english_records:
        return [
            f"{resolved_dir}: required Change Record directory has no English records"
        ]
    for english_path in english_records:
        errors.extend(record_errors(english_path))
    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[3]
    )
    parser.add_argument(
        "--records-dir",
        type=Path,
        default=Path("reports/audits/change-records"),
        help="Path relative to --root unless already absolute.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    errors = validate(args.root.resolve(), args.records_dir)
    if errors:
        print("Change Record contract violations:")
        print("\n".join(f"- {error}" for error in errors))
        return 1
    print("Change Record contract passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
