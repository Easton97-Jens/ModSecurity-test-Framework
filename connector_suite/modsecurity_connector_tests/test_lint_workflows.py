"""Regression checks for the actionlint self-repository compatibility boundary."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ci.tools import lint_workflows
from ci.tools import lint_installed_workflows


class LintWorkflowsTests(unittest.TestCase):
    def test_local_installed_tool_preserves_sources_shellcheck_and_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = [Path(temporary) / name for name in ("caller.yml", "second.yaml")]
            source = "jobs:\n  call:\n    uses: $/.github/workflows/reusable.yml\n"
            for path in paths:
                path.write_text(source, encoding="utf-8")
            with (
                patch.object(lint_installed_workflows.shutil, "which", return_value="/installed/actionlint"),
                patch.object(lint_installed_workflows, "workflow_paths", return_value=paths),
                patch.object(lint_installed_workflows.subprocess, "run", side_effect=[
                    subprocess.CompletedProcess([], 7),
                    subprocess.CompletedProcess([], 0),
                ]) as run,
            ):
                self.assertEqual(lint_installed_workflows.lint(), 7)
            self.assertEqual(run.call_count, 2)
            for path, invocation in zip(paths, run.call_args_list):
                self.assertEqual(path.read_text(encoding="utf-8"), source)
                self.assertEqual(invocation.args[0], ["/installed/actionlint", "-stdin-filename", str(path), "-"])
                self.assertEqual(invocation.kwargs["input"], source.replace("uses: $/", "uses: ./"))
                self.assertEqual(invocation.kwargs["timeout"], 120)

    def test_local_missing_tool_and_unsafe_source_fail_before_execution(self):
        with patch.object(lint_installed_workflows.shutil, "which", return_value=None):
            with self.assertRaisesRegex(ValueError, "unavailable"):
                lint_installed_workflows.lint()
        with tempfile.TemporaryDirectory() as temporary:
            workflow = Path(temporary) / "caller.yml"
            workflow.write_text("jobs:\n  call:\n    uses: $/../escape\n", encoding="utf-8")
            with (
                patch.object(lint_installed_workflows.shutil, "which", return_value="/installed/actionlint"),
                patch.object(lint_installed_workflows, "workflow_paths", return_value=[workflow]),
                patch.object(lint_installed_workflows.subprocess, "run") as run,
            ):
                with self.assertRaisesRegex(ValueError, "unsafe self-repository"):
                    lint_installed_workflows.lint()
                run.assert_not_called()

    def test_local_cli_rejects_arbitrary_tools_and_file_arguments(self):
        for arguments in (["lint", "--actionlint", "/bin/sh"], ["lint", "../../secret.yml"]):
            with self.subTest(arguments=arguments), patch("sys.argv", arguments), patch.object(lint_installed_workflows, "lint") as lint:
                with self.assertRaises(SystemExit) as error:
                    lint_installed_workflows.main()
                self.assertEqual(error.exception.code, 2)
                lint.assert_not_called()

    def test_normalizes_only_self_repository_uses_and_preserves_columns(self):
        source = (
            "jobs:\n  call:\n    uses: $/.github/workflows/reusable.yml # reviewed\n"
            "  test:\n    steps:\n"
            "      - uses: '$/.github/actions/local'\n"
            '      - uses: "$/another-action"\n'
            "      - uses: owner/action@" + "a" * 40 + "\n"
            "        run: echo '$/literal'\n"
        )
        expected = source.replace("uses: $/", "uses: ./").replace(
            "uses: '$/", "uses: './"
        ).replace('uses: "$/', 'uses: "./')
        normalized = lint_workflows.actionlint_source(source)
        self.assertEqual(normalized, expected)
        self.assertEqual(len(normalized), len(source))

    def test_block_scalar_scripts_and_comments_are_preserved(self):
        source = (
            "jobs:\n  test:\n    steps:\n      - run: |\n"
            "          uses: $/literal\n"
            "          echo 'uses: $/another-literal'\n"
            "        # uses: $/comment\n"
            "      - uses: $/.github/actions/local\n"
        )
        self.assertEqual(
            lint_workflows.actionlint_source(source),
            source.replace("- uses: $/.github/actions/local", "- uses: ./.github/actions/local"),
        )

    def test_rejects_unsafe_self_repository_paths(self):
        for reference in ("$/../escape", "$/a/./b", "$/a//b", "$/a@master", "$/"):
            with self.subTest(reference=reference):
                with self.assertRaisesRegex(ValueError, "unsafe self-repository"):
                    lint_workflows.actionlint_source(f"    uses: {reference}\n")

    def test_runs_all_workflows_propagates_failure_and_preserves_originals(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = [Path(temporary) / name for name in ("caller.yml", "second.yml")]
            source = "jobs:\n  call:\n    uses: $/.github/workflows/reusable.yml\n"
            for path in paths:
                path.write_text(source, encoding="utf-8")
            with (
                patch.object(lint_workflows, "reviewed_actionlint", return_value=Path("/checked/actionlint")),
                patch.object(lint_workflows, "workflow_paths", return_value=paths),
                patch.object(lint_workflows.subprocess, "run", side_effect=[
                    subprocess.CompletedProcess([], 1),
                    subprocess.CompletedProcess([], 0),
                ]) as run,
            ):
                self.assertEqual(lint_workflows.lint(), 1)
            self.assertEqual(run.call_count, 2)
            for path, invocation in zip(paths, run.call_args_list):
                self.assertEqual(path.read_text(encoding="utf-8"), source)
                self.assertEqual(invocation.args[0][0], "/checked/actionlint")
                self.assertIn(invocation.args[0][1], ("-shellcheck=", "-shellcheck=/usr/bin/shellcheck"))
                self.assertEqual(invocation.args[0][2:], ["-stdin-filename", str(path), "-"])
                self.assertEqual(invocation.kwargs["input"], source.replace("uses: $/", "uses: ./"))
                self.assertEqual(invocation.kwargs["timeout"], 120)

    def test_cli_rejects_arbitrary_tools_and_file_arguments_before_execution(self):
        for arguments in (["lint", "--actionlint", "/bin/sh"], ["lint", "../../secret.yml"]):
            with self.subTest(arguments=arguments), patch("sys.argv", arguments), patch.object(lint_workflows, "lint") as lint:
                with self.assertRaises(SystemExit) as error:
                    lint_workflows.main()
                self.assertEqual(error.exception.code, 2)
                lint.assert_not_called()

    def test_fixed_tool_locations_reject_symlinks_and_writable_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tool_dir = root / "security-tools"
            tool_dir.mkdir(mode=0o700)
            executable = tool_dir / "actionlint"
            executable.write_text("#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
            with patch.dict(os.environ, {"RUNNER_TEMP": str(root)}):
                self.assertEqual(lint_workflows.reviewed_actionlint(False), executable)
                executable.chmod(0o777)
                with self.assertRaisesRegex(ValueError, "writable"):
                    lint_workflows.reviewed_actionlint(False)
                executable.chmod(0o755)
                executable.rename(tool_dir / "original")
                executable.symlink_to(tool_dir / "original")
                with self.assertRaisesRegex(ValueError, "symlinks"):
                    lint_workflows.reviewed_actionlint(False)
            alias = root / "alias"
            alias.symlink_to(tool_dir, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlinks"):
                lint_workflows.checked_path(alias / "original")

    def test_workflow_discovery_is_contained_and_keeps_both_yaml_extensions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            fixtures = root / "ci/fixtures/workflow-permission-contract"
            fixtures.mkdir(parents=True)
            expected = [workflows / "one.yml", workflows / "two.yaml", fixtures / "safe.yml", fixtures / "unsafe.yml"]
            for path in expected:
                path.write_text("name: fixture\n")
            (workflows / "ignored.txt").write_text("outside lint scope")
            with patch.object(lint_workflows, "ROOT", root):
                self.assertEqual(lint_workflows.workflow_paths(), expected)
                external = root / "external.yml"
                external.write_text("name: outside\n")
                (workflows / "escape.yml").symlink_to(external)
                with self.assertRaisesRegex(ValueError, "symlinks"):
                    lint_workflows.workflow_paths()

    def test_candidate_mode_and_runner_temp_cannot_escape_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside"
            outside.mkdir(mode=0o700)
            runner_temp = root / "runner-temp"
            runner_temp.mkdir(mode=0o700)
            with patch.object(lint_workflows, "ROOT", outside), patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                with self.assertRaisesRegex(ValueError, "below RUNNER_TEMP"):
                    lint_workflows.reviewed_actionlint(True)
            with patch.dict(os.environ, {"RUNNER_TEMP": "../escape"}):
                with self.assertRaisesRegex(ValueError, "traversal-free"):
                    lint_workflows.reviewed_actionlint(False)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
