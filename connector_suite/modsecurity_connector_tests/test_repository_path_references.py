"""Unit tests for the portable repository-path reference checker."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import call, patch


ROOT = connector_root()
CHECKER_PATH = (
    source_path('ci/checks/documentation/check-repository-path-references.py', root=ROOT)
)
CHECKER_ROOT_ATTRIBUTE = "ROOT"
CURRENT_DOCUMENT_FILES_ATTRIBUTE = "current_document_files"
DOCUMENT_DIAGNOSTICS_ATTRIBUTE = "document_diagnostics"
SOURCE_DOCUMENT = "docs/source.md"
UNREADABLE_ERROR = "unreadable"
CHECKER = load_source(CHECKER_PATH)


class RepositoryPathReferenceTests(unittest.TestCase):
    def write(self, root: Path, relative: str, content: str = "") -> Path:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_document_diagnostics_preserve_path_and_link_contract(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = self.write(
                root,
                SOURCE_DOCUMENT,
                """/root/git/example
COMPILE_OLD_GUIDE.md
[encoded](local%20target.md#section)
[angle](<local%20target.md>)
[parent](../shared.md)
[fragment](#section)
[remote](https://example.invalid/remote.md)
[mail](mailto:docs@example.invalid)
[protocol](//example.invalid/remote.md)
[legacy](file.md)
[legacy-german](file.de.md)
[broken](missing%20target.md#section)
""",
            )
            self.write(root, "docs/local target.md")
            self.write(root, "shared.md")

            with patch.object(CHECKER, CHECKER_ROOT_ATTRIBUTE, root):
                diagnostics = CHECKER.document_diagnostics(source)

        self.assertEqual(
            diagnostics,
            [
                "docs/source.md: contains a local developer path",
                "docs/source.md: references a pre-reorganization COMPILE_* guide",
                "docs/source.md: missing link target 'missing%20target.md#section'",
            ],
        )

    def test_local_target_preserves_url_path_decisions(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = self.write(root, SOURCE_DOCUMENT)
            target = self.write(root, "docs/existing file.md")

            for raw_target in (
                "",
                "#section",
                "https://example.invalid/existing.md",
                "mailto:docs@example.invalid",
                "//example.invalid/existing.md",
                "file:///tmp/existing.md",
            ):
                self.assertIsNone(CHECKER.local_target(source, raw_target))
            self.assertEqual(
                CHECKER.local_target(source, "existing%20file.md#section"),
                target.resolve(),
            )
            self.assertEqual(
                CHECKER.local_target(source, "missing.md?revision=1"),
                (source.parent / "missing.md?revision=1").resolve(),
            )

    def test_document_diagnostics_propagate_read_errors(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            source = self.write(Path(temporary_directory), SOURCE_DOCUMENT)

            with patch.object(Path, "read_text", side_effect=OSError(UNREADABLE_ERROR)):
                with self.assertRaisesRegex(OSError, UNREADABLE_ERROR):
                    CHECKER.document_diagnostics(source)

    def test_main_skips_ignored_documents_and_sorts_unique_diagnostics(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first = self.write(root, "docs/a.md")
            second = self.write(root, "docs/z.md")
            ignored = self.write(root, "reports/testing/generated/ignored.md")
            diagnostics = {
                first: ["shared diagnostic", "alpha diagnostic"],
                second: ["zeta diagnostic", "shared diagnostic"],
            }
            stdout = io.StringIO()
            stderr = io.StringIO()

            with (
                patch.object(CHECKER, CHECKER_ROOT_ATTRIBUTE, root),
                patch.object(
                    CHECKER,
                    CURRENT_DOCUMENT_FILES_ATTRIBUTE,
                    return_value=[second, first, ignored, second],
                ),
                patch.object(
                    CHECKER,
                    DOCUMENT_DIAGNOSTICS_ATTRIBUTE,
                    side_effect=lambda path: diagnostics[path],
                ) as scanner,
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                result = CHECKER.main()

        self.assertEqual(result, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "repository path references: FAIL\n"
            "alpha diagnostic\nshared diagnostic\nzeta diagnostic\n",
        )
        self.assertEqual(scanner.call_args_list, [call(second), call(first), call(second)])

    def test_main_prints_pass_only_to_stdout(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            document = self.write(root, SOURCE_DOCUMENT)
            stdout = io.StringIO()
            stderr = io.StringIO()

            with (
                patch.object(CHECKER, CHECKER_ROOT_ATTRIBUTE, root),
                patch.object(CHECKER, CURRENT_DOCUMENT_FILES_ATTRIBUTE, return_value=[document]),
                patch.object(CHECKER, DOCUMENT_DIAGNOSTICS_ATTRIBUTE, return_value=[]),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                result = CHECKER.main()

        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), "repository path references: PASS\n")
        self.assertEqual(stderr.getvalue(), "")

    def test_main_propagates_scan_errors_without_output(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            document = self.write(root, SOURCE_DOCUMENT)
            stdout = io.StringIO()
            stderr = io.StringIO()

            with (
                patch.object(CHECKER, CHECKER_ROOT_ATTRIBUTE, root),
                patch.object(CHECKER, CURRENT_DOCUMENT_FILES_ATTRIBUTE, return_value=[document]),
                patch.object(
                    CHECKER,
                    DOCUMENT_DIAGNOSTICS_ATTRIBUTE,
                    side_effect=OSError(UNREADABLE_ERROR),
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                with self.assertRaisesRegex(OSError, UNREADABLE_ERROR):
                    CHECKER.main()

        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
