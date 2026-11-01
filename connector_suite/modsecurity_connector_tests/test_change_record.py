"""Regression tests for canonical EN/DE Change Record creation and early checking."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()
RECORD = load_source(source_path('ci/tools/new-change-record.py', root=ROOT))
BASE = "a" * 40
DATE = "2026-09-29"
NAME = "contract-regression"


class ChangeRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / RECORD.RECORDS
        self.directory.mkdir(parents=True)
        self.records = RECORD.render_pair(NAME, DATE, BASE)

    def write_fixture(self) -> None:
        for filename, text in self.records.items():
            (self.directory / filename).write_text(text, encoding="utf-8")

    def snapshot(self) -> dict[str, bytes]:
        return {path.name: path.read_bytes() for path in self.directory.iterdir()}

    def test_generated_pair_passes_the_existing_checker(self) -> None:
        self.write_fixture()
        self.assertEqual(RECORD.check_records(self.root), [])
        self.assertEqual(len(self.records), 2)
        english, german = self.records.values()
        self.assertIn("| Date (UTC) | 2026-09-29 |", english)
        self.assertIn("| Datum (UTC) | 2026-09-29 |", german)
        self.assertIn("Scaffold only.", english)
        self.assertIn("Nur eine Vorlage.", german)

    def test_every_required_heading_is_enforced(self) -> None:
        for language, (filename, text) in zip(RECORD.LANGUAGES, self.records.items(), strict=True):
            for heading in RECORD.CONTRACT.CHANGE_RECORD_REQUIRED_HEADINGS[language]:
                with self.subTest(language=language, heading=heading):
                    self.write_fixture()
                    (self.directory / filename).write_text(
                        text.replace(heading + "\n", "## Invalid heading\n", 1), encoding="utf-8"
                    )
                    self.assertTrue(RECORD.check_records(self.root))

    def test_every_identity_label_is_enforced(self) -> None:
        for index, (filename, text) in enumerate(self.records.items()):
            for labels in RECORD.CONTRACT.CHANGE_RECORD_IDENTITY_LABELS:
                with self.subTest(filename=filename, label=labels[index]):
                    self.write_fixture()
                    (self.directory / filename).write_text(
                        text.replace(f"| {labels[index]} |", "| Invalid label |", 1), encoding="utf-8"
                    )
                    self.assertTrue(RECORD.check_records(self.root))

    def test_different_identity_values_are_rejected(self) -> None:
        self.write_fixture()
        filename, text = list(self.records.items())[1]
        (self.directory / filename).write_text(text.replace(BASE, "b" * 40), encoding="utf-8")
        self.assertTrue(RECORD.check_records(self.root))

    def test_language_switch_and_code_parity_are_enforced(self) -> None:
        filename, text = next(iter(self.records.items()))
        for changed in (
            text.replace("**Language:**", "**Invalid:**"),
            text + "\n```sh\necho extra\n```\n",
        ):
            with self.subTest(changed=changed[-30:]):
                self.write_fixture()
                (self.directory / filename).write_text(changed, encoding="utf-8")
                self.assertTrue(RECORD.check_records(self.root))

    def test_invalid_inputs_are_rejected_before_writing(self) -> None:
        invalid = (
            ("../escape", DATE, BASE), ("a/b", DATE, BASE), ("name\nbad", DATE, BASE),
            ("Uppercase", DATE, BASE), ("a" * 81, DATE, BASE),
            (NAME, "2026-02-30", BASE), (NAME, "20260929", BASE),
            (NAME, DATE, "master"), (NAME, DATE, "a" * 39), (NAME, DATE, "A" * 40),
        )
        for arguments in invalid:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                RECORD.create_pair(self.root, *arguments)
        self.assertEqual(self.snapshot(), {})

    def test_create_writes_only_the_two_expected_files(self) -> None:
        filenames = RECORD.create_pair(self.root, NAME, DATE, BASE)
        self.assertEqual(set(filenames), set(self.records))
        self.assertEqual(RECORD.check_records(self.root), [])
        self.assertEqual(set(self.snapshot()), set(self.records))

    def test_existing_english_record_is_never_overwritten(self) -> None:
        filename = next(iter(self.records))
        (self.directory / filename).write_text("owned\n", encoding="utf-8")
        before = self.snapshot()
        with self.assertRaises(FileExistsError):
            RECORD.create_pair(self.root, NAME, DATE, BASE)
        self.assertEqual(self.snapshot(), before)

    def test_existing_german_record_rolls_back_only_the_new_english_file(self) -> None:
        filename = list(self.records)[1]
        (self.directory / filename).write_text("owned\n", encoding="utf-8")
        before = self.snapshot()
        with self.assertRaises(FileExistsError):
            RECORD.create_pair(self.root, NAME, DATE, BASE)
        self.assertEqual(self.snapshot(), before)

    def test_symlinked_output_ancestor_is_rejected_without_writes(self) -> None:
        real = self.root / "real-reports"
        (self.root / "reports").rename(real)
        (self.root / "reports").symlink_to(real, target_is_directory=True)
        with self.assertRaises(OSError):
            RECORD.create_pair(self.root, NAME, DATE, BASE)
        self.assertEqual(self.snapshot(), {})

    def test_symlinked_output_file_is_never_followed(self) -> None:
        target = self.root / "owned"
        target.write_text("owned\n", encoding="utf-8")
        (self.directory / next(iter(self.records))).symlink_to(target)
        with self.assertRaises(FileExistsError):
            RECORD.create_pair(self.root, NAME, DATE, BASE)
        self.assertEqual(target.read_text(encoding="utf-8"), "owned\n")

    def test_rollback_preserves_replaced_outputs(self) -> None:
        path = self.directory / "created.md"
        path.write_text("original\n", encoding="utf-8")
        metadata = path.stat()
        path.rename(self.directory / "moved.md")
        path.write_text("other writer\n", encoding="utf-8")
        with RECORD.record_directory(self.root) as descriptor:
            RECORD.remove_created_files(descriptor, [("created.md", metadata.st_dev, metadata.st_ino)])
        self.assertEqual(path.read_text(encoding="utf-8"), "other writer\n")

    def test_missing_english_or_german_companion_is_rejected(self) -> None:
        for filename in self.records:
            with self.subTest(filename=filename):
                self.write_fixture()
                (self.directory / filename).unlink()
                self.assertTrue(RECORD.check_records(self.root))

    def test_check_rejects_symlinked_companion_without_reading_it(self) -> None:
        self.write_fixture()
        filename = list(self.records)[1]
        (self.directory / filename).unlink()
        (self.directory / filename).symlink_to(self.root / "missing-target")
        self.assertTrue(RECORD.check_records(self.root))

    def test_schema_drift_fails_before_writing(self) -> None:
        headings = RECORD.CONTRACT.CHANGE_RECORD_REQUIRED_HEADINGS["English"]
        with mock.patch.dict(
            RECORD.CONTRACT.CHANGE_RECORD_REQUIRED_HEADINGS,
            {"English": (*headings, "## New unmatched heading")},
        ), self.assertRaises(ValueError):
            RECORD.create_pair(self.root, NAME, DATE, BASE)
        self.assertEqual(self.snapshot(), {})

    def test_empty_or_missing_archive_is_not_a_pass(self) -> None:
        self.assertTrue(RECORD.check_records(self.root))
        self.directory.rmdir()
        self.assertTrue(RECORD.check_records(self.root))

    def test_check_is_read_only_and_reports_the_cli_status(self) -> None:
        self.write_fixture()
        before = self.snapshot()
        with mock.patch.object(RECORD, "ROOT", self.root), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(RECORD.main(["check"]), 0)
        self.assertEqual(self.snapshot(), before)
        (self.directory / next(iter(self.records))).unlink()
        with mock.patch.object(RECORD, "ROOT", self.root), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(RECORD.main(["check"]), 1)

    def test_cli_create_and_collision_status(self) -> None:
        arguments = ["create", "--name", NAME, "--date", DATE, "--base-revision", BASE]
        with mock.patch.object(RECORD, "ROOT", self.root), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(RECORD.main(arguments), 0)
        before = self.snapshot()
        with mock.patch.object(RECORD, "ROOT", self.root), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(RECORD.main(arguments), 2)
        self.assertEqual(self.snapshot(), before)

    def test_documented_heading_and_identity_tables_match_the_checker(self) -> None:
        for filename in ("change-traceability.md", "change-traceability.de.md"):
            text = (source_path('docs', root=ROOT) / filename).read_text(encoding="utf-8")
            for headings in RECORD.CONTRACT.CHANGE_RECORD_REQUIRED_HEADINGS.values():
                for heading in headings:
                    with self.subTest(filename=filename, heading=heading):
                        self.assertIn(f"<code>{heading}</code>", text)
            for labels in RECORD.CONTRACT.CHANGE_RECORD_IDENTITY_LABELS:
                for label in labels:
                    with self.subTest(filename=filename, label=label):
                        self.assertIn(f"<code>{label}</code>", text)

    def test_early_workflow_runs_regressions_before_lightweight_setup(self) -> None:
        text = (source_path('.github/workflows/quick-framework-check.yml', root=ROOT)).read_text(encoding="utf-8")
        self.assertIn("new-change-record.py check", text)
        self.assertIn("modsecurity_connector_tests.test_change_record", text)
        self.assertLess(text.index("new-change-record.py check"), text.index("make setup-dev"))
        self.assertLess(text.index("modsecurity_connector_tests.test_change_record"), text.index("make setup-dev"))
        self.assertIn("modsecurity_connector_tests.test_prepare_reviewed_framework_handoff", text)
        self.assertIn("make quick-check", text)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
