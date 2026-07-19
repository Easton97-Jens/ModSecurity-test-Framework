from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = ROOT / "ci/checks/documentation/check-change-records.py"


def load_checker():
    spec = importlib.util.spec_from_file_location(
        "change_record_contract", CHECKER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {CHECKER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker()


def render_record(change_id: str, german: bool) -> str:
    headings = CHECKER.GERMAN_HEADINGS if german else CHECKER.ENGLISH_HEADINGS
    language = (
        f"**Sprache:** [English]({change_id}.md) | Deutsch"
        if german
        else f"**Language:** English | [Deutsch]({change_id}.de.md)"
    )
    label = "Change-ID" if german else "Change ID"
    header = "Feld | Wert" if german else "Field | Value"
    section_text = "\n\n".join(
        f"## {heading}\n\nConcrete record evidence." for heading in headings[1:]
    )
    return (
        f"# Change record\n\n{language}\n\n## {headings[0]}\n\n"
        f"| {header} |\n| --- | --- |\n| {label} | {change_id} |\n\n"
        f"{section_text}\n"
    )


def render_known_legacy_record(change_id: str, german: bool) -> str:
    language = "german" if german else "english"
    headings = CHECKER.LEGACY_HEADINGS_BY_CHANGE_ID[change_id][language]
    link = (
        f"**Sprache:** [English]({change_id}.md) | Deutsch"
        if german
        else f"**Language:** English | [Deutsch]({change_id}.de.md)"
    )
    label = "Change-ID" if german else "Change ID"
    header = "Feld | Wert" if german else "Field | Value"
    sections = "\n\n".join(
        f"## {heading}\n\nConcrete historic record evidence."
        for heading in headings[1:]
    )
    return (
        f"# Change record\n\n{link}\n\n## {headings[0]}\n\n"
        f"| {header} |\n| --- | --- |\n| {label} | {change_id} |\n\n"
        f"{sections}\n"
    )


class ChangeRecordContractTest(unittest.TestCase):
    def test_checked_in_change_records_pass(self) -> None:
        errors = CHECKER.validate(ROOT, Path("reports/audits/change-records"))
        self.assertFalse(errors, "\n".join(errors))

    def test_rejects_mismatched_id_and_missing_heading(self) -> None:
        change_id = "20260718-99-fixture"
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            records = root / "reports/audits/change-records"
            records.mkdir(parents=True)
            english = records / f"{change_id}.md"
            german = records / f"{change_id}.de.md"
            english.write_text(render_record(change_id, german=False), encoding="utf-8")
            german.write_text(
                render_record("wrong-id", german=True).replace(
                    "## Akzeptanzkriterien\n\nConcrete record evidence.\n\n", ""
                ),
                encoding="utf-8",
            )
            errors = CHECKER.validate(root, Path("reports/audits/change-records"))
        self.assertTrue(
            any("Change-ID must match filename" in error for error in errors)
        )
        self.assertTrue(any("headings do not match" in error for error in errors))

    def test_accepts_only_the_known_legacy_change_record_headings(self) -> None:
        change_id = "20260718-01-fix-framework-actions-sha-pins"
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            records = root / "reports/audits/change-records"
            records.mkdir(parents=True)
            (records / f"{change_id}.md").write_text(
                render_known_legacy_record(change_id, german=False), encoding="utf-8"
            )
            (records / f"{change_id}.de.md").write_text(
                render_known_legacy_record(change_id, german=True), encoding="utf-8"
            )
            errors = CHECKER.validate(root, Path("reports/audits/change-records"))
        self.assertFalse(errors, "\n".join(errors))

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            records = root / "reports/audits/change-records"
            records.mkdir(parents=True)
            other_id = "20260718-99-fixture"
            (records / f"{other_id}.md").write_text(
                render_known_legacy_record(change_id, german=False).replace(
                    change_id, other_id
                ),
                encoding="utf-8",
            )
            (records / f"{other_id}.de.md").write_text(
                render_known_legacy_record(change_id, german=True).replace(
                    change_id, other_id
                ),
                encoding="utf-8",
            )
            errors = CHECKER.validate(root, Path("reports/audits/change-records"))
        self.assertTrue(any("headings do not match" in error for error in errors))

    def test_missing_or_empty_record_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            missing_errors = CHECKER.validate(
                root, Path("reports/audits/change-records")
            )
            self.assertTrue(
                any("directory is missing" in error for error in missing_errors)
            )

            records = root / "reports/audits/change-records"
            records.mkdir(parents=True)
            empty_errors = CHECKER.validate(root, Path("reports/audits/change-records"))
            self.assertTrue(
                any("has no English records" in error for error in empty_errors)
            )


if __name__ == "__main__":
    unittest.main()
