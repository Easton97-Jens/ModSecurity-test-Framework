#!/usr/bin/env python3
"""Unit tests for the repository bilingual-documentation checker."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import call, patch


ROOT = connector_root()
CHECKER_PATH = source_path('ci/checks/documentation/check-bilingual-docs.py', root=ROOT)
TOOLS_MRTS_LITERAL = "tools/MRTS"
TOOLS_MRTS_GITKEEP = f"{TOOLS_MRTS_LITERAL}/.gitkeep"
CHECKER = load_source(CHECKER_PATH)


class BilingualDocumentationCheckerTests(unittest.TestCase):
    def test_markdown_counterpart_constructors_are_bidirectional(self) -> None:
        english = Path("docs/example.md")
        german = Path("docs/example.de.md")

        self.assertEqual(CHECKER.german_counterpart(english), german)
        self.assertEqual(CHECKER.english_counterpart(german), english)

    def write(self, root: Path, relative: str, content: str) -> Path:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_docs_require_matching_heading_structure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self.write(
                root,
                "docs/example.md",
                "# Example\n\n**Language:** English | [Deutsch](example.de.md)\n\n## Details\n",
            )
            self.write(
                root,
                "docs/example.de.md",
                "# Beispiel\n\n**Sprache:** [English](example.md) | Deutsch\n\n### Details\n",
            )

            errors = CHECKER.check_pairs_and_switches(root)

        self.assertTrue(any("heading-level structure differs" in error for error in errors))

    def test_license_documents_require_german_companions(self) -> None:
        self.assertTrue(CHECKER.pair_required(Path("licenses/README.md")))

    def test_fenced_code_blocks_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self.write(
                root,
                "docs/example.md",
                "# Example\n\n**Language:** English | [Deutsch](example.de.md)\n\n```sh\necho English\n```\n",
            )
            self.write(
                root,
                "docs/example.de.md",
                "# Beispiel\n\n**Sprache:** [English](example.md) | Deutsch\n\n```sh\necho Deutsch\n```\n",
            )

            errors = CHECKER.check_pairs_and_switches(root)

        self.assertTrue(any("fenced code-block content differs" in error for error in errors))

    def test_mixed_fence_marker_cannot_hide_bilingual_code_block_differences(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self.write(
                root,
                "docs/example.md",
                "# Example\n\n**Language:** English | [Deutsch](example.de.md)\n\n```sh\necho shared\n~~~\necho English-only\n```\n",
            )
            self.write(
                root,
                "docs/example.de.md",
                "# Beispiel\n\n**Sprache:** [English](example.md) | Deutsch\n\n```sh\necho shared\n~~~\necho Deutsch-only\n```\n",
            )

            errors = CHECKER.check_pairs_and_switches(root)

        self.assertTrue(any("fenced code-block content differs" in error for error in errors), errors)

    def test_matching_longer_fences_remain_valid(self) -> None:
        text = "````sh\necho control\n````\n\n~~~text\ncontrol\n~~~~\n"
        self.assertEqual(
            CHECKER.fenced_blocks(text),
            ["````sh\necho control\n````", "~~~text\ncontrol\n~~~~"],
        )

    def test_rejects_local_german_companions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self.write(root, "AGENTS.de.md", "# Verboten\n")

            errors = CHECKER.check_forbidden_local_language_companions(root)

        self.assertEqual(
            errors,
            ["AGENTS.de.md: local Codex configuration must not have a German companion"],
        )

    def test_ignored_local_markdown_is_not_repository_owned_documentation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self.write(root, "local.md", "# Local control file\n")

            with patch.object(
                CHECKER,
                "git_ignored_paths",
                return_value=frozenset({Path("local.md")}),
            ):
                sources = CHECKER.english_sources(root)

        self.assertEqual(sources, [])

    def test_agent_referenced_root_markdown_is_not_repository_owned_documentation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self.write(root, "AGENTS.md", "@local-control.md\n")
            self.write(root, "local-control.md", "# Local control file\n")

            sources = CHECKER.english_sources(root)

        self.assertEqual(sources, [])

    def test_pr_template_requires_all_bilingual_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self.write(
                root,
                CHECKER.PR_TEMPLATE_PATH.as_posix(),
                "## English\n\n## Deutsch\n",
            )

            errors = CHECKER.check_pr_template(root)

        self.assertTrue(any("English required section" in error for error in errors))
        self.assertTrue(any("Deutsch required section" in error for error in errors))

    def test_pr_template_is_exempt_from_pairing_but_included_for_template_checks(self) -> None:
        self.assertFalse(CHECKER.pair_required(CHECKER.PR_TEMPLATE_PATH))

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            pr_template = self.write(
                root,
                CHECKER.PR_TEMPLATE_PATH.as_posix(),
                "## English\n\n## Deutsch\n",
            )

            self.assertEqual(CHECKER.checked_markdown_files(root), [pr_template])
            errors = CHECKER.check_pr_template(root)

        self.assertEqual(
            errors[0],
            f"{CHECKER.PR_TEMPLATE_PATH}: missing English required section '### Summary'",
        )

    def test_change_record_pair_skips_non_records_and_readme(self) -> None:
        self.assertEqual(
            CHECKER.check_change_record_pair(
                Path("docs/example.md"),
                Path("docs/example.de.md"),
                "",
                "",
            ),
            [],
        )
        self.assertEqual(
            CHECKER.check_change_record_pair(
                Path("reports/audits/change-records/README.md"),
                Path("reports/audits/change-records/README.de.md"),
                "",
                "",
            ),
            [],
        )

    def test_change_record_template_reports_only_heading_errors(self) -> None:
        source = Path("reports/audits/change-records/TEMPLATE.md")
        companion = Path("reports/audits/change-records/TEMPLATE.de.md")

        errors = CHECKER.check_change_record_pair(source, companion, "", "")

        expected = [
            *(
                f"{source}: missing Change Record section {heading!r}"
                for heading in CHECKER.CHANGE_RECORD_REQUIRED_HEADINGS["English"]
            ),
            *(
                f"{companion}: missing Change Record section {heading!r}"
                for heading in CHECKER.CHANGE_RECORD_REQUIRED_HEADINGS["Deutsch"]
            ),
        ]
        self.assertEqual(errors, expected)

    def test_change_record_pair_preserves_diagnostic_order(self) -> None:
        source = Path("reports/audits/change-records/invalid.md")
        companion = Path("reports/audits/change-records/invalid.de.md")
        source_text = "| Change ID | english-id |\n| Date (UTC) | same-date |\n"
        companion_text = "| Change-ID | german-id |\n| Datum (UTC) | same-date |\n"

        errors = CHECKER.check_change_record_pair(
            source,
            companion,
            source_text,
            companion_text,
        )

        expected = [
            *(
                f"{source}: missing Change Record section {heading!r}"
                for heading in CHECKER.CHANGE_RECORD_REQUIRED_HEADINGS["English"]
            ),
            *(
                f"{companion}: missing Change Record section {heading!r}"
                for heading in CHECKER.CHANGE_RECORD_REQUIRED_HEADINGS["Deutsch"]
            ),
            f"{source}: Change Record filename must use <change-id>-<name>.md",
            f"{source}: Change Record identity field 'Change ID' differs from "
            f"{companion} ('english-id' != 'german-id')",
            f"{source}: missing Change Record identity field 'Base revision'",
            f"{companion}: missing Change Record identity field 'Basis-Revision'",
        ]
        self.assertEqual(errors, expected)

    def test_change_record_identity_values_must_match(self) -> None:
        english_headings = "\n".join(CHECKER.CHANGE_RECORD_REQUIRED_HEADINGS["English"])
        german_headings = "\n".join(CHECKER.CHANGE_RECORD_REQUIRED_HEADINGS["Deutsch"])
        english = (
            "# Change Record\n\n"
            "**Language:** English | [Deutsch](CR-20260713-example.de.md)\n\n"
            f"{english_headings}\n\n"
            "| Field | Value |\n| --- | --- |\n"
            "| Change ID | CR-20260713-example |\n"
            "| Date (UTC) | 2026-07-13T00:00:00Z |\n"
            "| Base revision | deadbeef |\n"
        )
        german = (
            "# Change Record\n\n"
            "**Sprache:** [English](CR-20260713-example.md) | Deutsch\n\n"
            f"{german_headings}\n\n"
            "| Feld | Wert |\n| --- | --- |\n"
            "| Change-ID | CR-20260713-example |\n"
            "| Datum (UTC) | 2026-07-13T00:00:00Z |\n"
            "| Basis-Revision | differs |\n"
        )

        errors = CHECKER.check_change_record_pair(
            Path("reports/audits/change-records/CR-20260713-example.md"),
            Path("reports/audits/change-records/CR-20260713-example.de.md"),
            english,
            german,
        )

        self.assertTrue(any("Base revision" in error and "differs" in error for error in errors))

    def test_common_design_note_current_contract_passes_for_both_languages(self) -> None:
        self.assertEqual(CHECKER.check_common_design_note_contract(ROOT), [])

    def test_common_design_route_matcher_keeps_routes_and_rejects_malformed_spacing_quickly(self) -> None:
        route_rows = [
            (connector.strip(), route)
            for connector, route in CHECKER.COMMON_DESIGN_ROUTE_ROW_RE.findall(
                "\n".join(
                    (
                        "| Apache | `native-httpd-module` |",
                        "|NGINX|`native-nginx-http-module`|",
                    )
                )
            )
        ]
        malformed_row = "|" + " " * 1024 + "missing-delimiter"
        started = time.perf_counter()

        self.assertEqual(
            route_rows,
            [("Apache", "native-httpd-module"), ("NGINX", "native-nginx-http-module")],
        )
        self.assertEqual(CHECKER.COMMON_DESIGN_ROUTE_ROW_RE.findall(malformed_row), [])
        self.assertLess(time.perf_counter() - started, 0.25)

    def test_common_design_note_rejects_scaffolded_status_and_current_sidecar_route(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            english = (source_path('common/docs/design.md', root=ROOT)).read_text(encoding="utf-8")
            german = (source_path('common/docs/design.de.md', root=ROOT)).read_text(encoding="utf-8")
            self.write(
                root,
                "common/docs/design.md",
                english.replace(
                    "Status: current-boundary reference", "Status: scaffolded"
                ).replace(
                    "| lighttpd | `patched-native-lighttpd` |",
                    "| lighttpd | `sidecar_proxy` |",
                )
                + "\nintegration_mode=sidecar_proxy\n",
            )
            self.write(
                root,
                "common/docs/design.de.md",
                german.replace(
                    "Status: aktuelle Grenzreferenz", "Status: eingerüstet"
                ).replace(
                    "| lighttpd | `patched-native-lighttpd` |",
                    "| lighttpd | `sidecar_proxy` |",
                )
                + "\nintegration_mode=sidecar_proxy\n",
            )

            errors = CHECKER.check_common_design_note_contract(root)

        for relative_path in ("common/docs/design.md", "common/docs/design.de.md"):
            self.assertTrue(
                any(
                    error.startswith(f"{relative_path}:")
                    and "obsolete scaffolded status" in error
                    for error in errors
                )
            )
            self.assertTrue(
                any(
                    error.startswith(f"{relative_path}:")
                    and "selected route for lighttpd" in error
                    for error in errors
                )
            )
            self.assertTrue(
                any(
                    error.startswith(f"{relative_path}:")
                    and "historical integration mode" in error
                    for error in errors
                )
            )

    def test_common_design_note_allows_an_explicitly_historical_compatibility_route(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            english = (source_path('common/docs/design.md', root=ROOT)).read_text(encoding="utf-8")
            german = (source_path('common/docs/design.de.md', root=ROOT)).read_text(encoding="utf-8")
            self.write(
                root,
                "common/docs/design.md",
                english
                + "\nHistorical compatibility material: "
                "integration_mode=sidecar_proxy is compatibility_only.\n",
            )
            self.write(
                root,
                "common/docs/design.de.md",
                german
                + "\nHistorisches Kompatibilitätsmaterial: "
                "integration_mode=sidecar_proxy ist compatibility_only.\n",
            )

            errors = CHECKER.check_common_design_note_contract(root)

        self.assertEqual(errors, [])

    def initialize_git_repository(self, root: Path) -> None:
        subprocess.run(
            ["git", "init", "--quiet"],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def run_git(self, root: Path, *args: str) -> None:
        subprocess.run(
            ["git", *args],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def commit_baseline(self, root: Path, message: str, *paths: str) -> None:
        self.run_git(root, "add", "--", *paths)
        self.run_git(
            root,
            "-c",
            "user.name=Bilingual documentation tests",
            "-c",
            "user.email=bilingual-docs@example.invalid",
            "commit",
            "--quiet",
            "-m",
            message,
        )

    def create_git_hierarchy(self, root: Path) -> Path:
        framework_root = root / "modules" / "ModSecurity-test-Framework"
        framework_root.mkdir(parents=True)
        self.initialize_git_repository(framework_root)
        self.write(framework_root, TOOLS_MRTS_GITKEEP, "framework baseline\n")
        self.write(framework_root, "README.md", "framework baseline\n")
        self.commit_baseline(
            framework_root,
            "framework baseline",
            TOOLS_MRTS_GITKEEP,
            "README.md",
        )

        self.initialize_git_repository(root)
        self.write(root, TOOLS_MRTS_GITKEEP, "parent baseline\n")
        self.write(root, "README.md", "parent baseline\n")
        self.commit_baseline(
            root,
            "parent baseline",
            TOOLS_MRTS_GITKEEP,
            "README.md",
            "modules/ModSecurity-test-Framework",
        )
        return framework_root

    def expected_tools_mrts_status_calls(
        self,
        root: Path,
        framework_root: Path,
    ):
        self.assertEqual(CHECKER.TOOLS_MRTS, TOOLS_MRTS_LITERAL)
        return [
            call(
                root,
                "status",
                "--short",
                "--",
                TOOLS_MRTS_LITERAL,
                f"modules/ModSecurity-test-Framework/{TOOLS_MRTS_LITERAL}",
            ),
            call(framework_root, "status", "--short", "--", TOOLS_MRTS_LITERAL),
        ]

    def test_tools_mrts_clean_allows_unrelated_dirty_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            framework_root = self.create_git_hierarchy(root)
            self.write(root, "docs/unrelated.md", "parent dirt\n")
            self.write(framework_root, "docs/unrelated.md", "framework dirt\n")

            with patch.object(
                CHECKER,
                "git_status",
                wraps=CHECKER.git_status,
            ) as git_status:
                errors = CHECKER.check_tools_mrts_clean(root)

        self.assertEqual(errors, [])
        self.assertEqual(
            git_status.call_args_list,
            self.expected_tools_mrts_status_calls(root, framework_root),
        )

    def test_tools_mrts_clean_reports_dirty_parent_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            framework_root = self.create_git_hierarchy(root)
            self.write(root, TOOLS_MRTS_GITKEEP, "parent dirt\n")

            with patch.object(
                CHECKER,
                "git_status",
                wraps=CHECKER.git_status,
            ) as git_status:
                errors = CHECKER.check_tools_mrts_clean(root)

        self.assertEqual(
            errors,
            [
                f"{TOOLS_MRTS_LITERAL} paths changed in parent repository:\n"
                f"M {TOOLS_MRTS_GITKEEP}"
            ],
        )
        self.assertEqual(
            git_status.call_args_list,
            self.expected_tools_mrts_status_calls(root, framework_root),
        )

    def test_tools_mrts_clean_reports_dirty_framework_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            framework_root = self.create_git_hierarchy(root)
            self.write(
                framework_root,
                TOOLS_MRTS_GITKEEP,
                "framework dirt\n",
            )

            with patch.object(
                CHECKER,
                "git_status",
                wraps=CHECKER.git_status,
            ) as git_status:
                errors = CHECKER.check_tools_mrts_clean(root)

        self.assertEqual(
            errors,
            [
                f"{TOOLS_MRTS_LITERAL} paths changed in framework module:\n"
                f"M {TOOLS_MRTS_GITKEEP}"
            ],
        )
        self.assertEqual(
            git_status.call_args_list,
            self.expected_tools_mrts_status_calls(root, framework_root),
        )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
