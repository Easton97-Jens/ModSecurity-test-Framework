"""Prove that composed workflow checks follow actual immutable source bindings."""
import contextlib
import io
import os
import runpy
import subprocess

import yaml
import sys
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from modsecurity_test_framework.workflow_sources import (
    WorkflowSourceError,
    composite_validation_workflow,
    expand_workflow_source,
    read_connector_workflow,
)


class WorkflowSourcesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.revision = "a" * 40
        self.action = self.root / ".github/actions/connector-ci/test-example/unit/action.yml"
        self.action.parent.mkdir(parents=True)
        self.action.write_text("""name: Selected test action
description: Source inspection fixture
inputs:
  framework-revision:
    required: true
  caller-matrix:
    required: true
outputs:
  matrix:
    description: Actual profile output
    value: ${{ steps.profile.outputs.matrix }}
runs:
  using: composite
  steps:
    - name: Validate actual context
      uses: $/.github/actions/connector-context
      with:
        framework-revision: ${{ inputs.framework-revision }}
    - name: Run actual selected test
      id: profile
      if: fromJSON(inputs.caller-matrix).connector == 'apache'
      shell: bash
      run: echo '${{ fromJSON(inputs.caller-matrix).connector }}'
""")
        context = self.root / ".github/actions/connector-context/action.yml"
        context.parent.mkdir()
        context.write_text("""name: Explicit context
description: Source inspection fixture
inputs:
  framework-revision:
    required: true
runs:
  using: composite
  steps:
    - name: Verify immutable source
      shell: bash
      env:
        EXPECTED: ${{ inputs.framework-revision }}
      run: test -n "$EXPECTED"
""")
        self.workflow = """name: Existing check identity
on: push
permissions: {}
jobs:
  unit:
    name: Retained job name
    permissions:
      contents: read
    runs-on: ubuntu-26.04
    outputs:
      matrix: ${{ steps.framework-ci.outputs.matrix }}
    steps:
      - uses: actions/checkout@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      - name: Execute actual pinned Framework
        id: framework-ci
        if: ${{ always() }}
        uses: Easton97-Jens/ModSecurity-test-Framework/.github/actions/connector-ci/test-example/unit@""" + self.revision + """
        with:
          framework-revision: """ + self.revision + """
          caller-matrix: ${{ toJSON(matrix) }}
"""

    def expand(self, text=None):
        return expand_workflow_source(self.workflow if text is None else text,
                                      framework_root=self.root, framework_revision=self.revision,
                                      workflow_name="test-example.yml")

    def test_actual_composition_preserves_job_permissions_conditions_and_outputs(self):
        expanded = self.expand()
        self.assertIn("name: Retained job name", expanded)
        self.assertIn("      contents: read", expanded)
        self.assertIn("uses: actions/checkout@" + "b" * 40, expanded)
        self.assertIn("      matrix: ${{ steps.profile.outputs.matrix }}", expanded)
        self.assertIn("      - name: Verify immutable source", expanded)
        self.assertIn("EXPECTED: " + self.revision, expanded)
        self.assertIn("      - name: Run actual selected test", expanded)
        self.assertIn("if: matrix.connector == 'apache'", expanded)
        self.assertIn("echo '${{ matrix.connector }}'", expanded)
        self.assertNotIn("fromJSON(inputs.", expanded)
        self.assertNotIn("id: framework-ci", expanded)

    def test_wrong_pin_foreign_action_wrong_caller_or_skipped_wrapper_reject(self):
        for before, after in (
                ("unit@" + self.revision, "unit@" + "c" * 40),
                ("connector-ci/test-example/unit@", "connector-ci/foreign/unit@"),
                ("connector-ci/test-example/unit@", "connector-ci/test-example/foreign@"),
                ("connector-ci/test-example/unit@", "../foreign@"),
                ("if: ${{ always() }}", "if: false"),
                ("id: framework-ci", "id: framework-ci\n        continue-on-error: true"),
                ("toJSON(matrix)", "toJSON(secrets)")):
            with self.subTest(change=after):
                changed_workflow = self.workflow.replace(before, after)
                with self.assertRaises(WorkflowSourceError):
                    self.expand(changed_workflow)

    def test_first_composite_owns_checkout_without_an_outer_always_condition(self):
        first = self.workflow.replace("      - uses: actions/checkout@" + "b" * 40 + "\n", "")
        first = first.replace("        if: ${{ always() }}\n", "")
        self.assertIn("Run actual selected test", self.expand(first))
        skipped_wrapper = first.replace("        id: framework-ci\n",
                                        "        id: framework-ci\n        if: false\n")
        with self.assertRaisesRegex(WorkflowSourceError, "terminal cleanup"):
            self.expand(skipped_wrapper)

    def test_source_symlink_alias_or_unknown_nested_action_rejects(self):
        original = self.action.read_text()
        for modified in (original.replace("$/.github/actions/connector-context", "$/.github/actions/foreign"),
                         original.replace("name: Selected test action", "name: &indirect Selected test action")):
            self.action.write_text(modified)
            with self.assertRaises(WorkflowSourceError):
                self.expand()
        self.action.write_text(original)
        saved = self.action.with_name("saved.yml")
        self.action.rename(saved)
        self.action.symlink_to(saved)
        with self.assertRaisesRegex(WorkflowSourceError, "non-symlink"):
            self.expand()

    def test_missing_source_or_incomplete_pin_never_falls_back_to_old_workflow(self):
        self.action.unlink()
        with self.assertRaises(WorkflowSourceError):
            self.expand()
        with self.assertRaisesRegex(WorkflowSourceError, "complete immutable"):
            expand_workflow_source(self.workflow, framework_root=self.root,
                                   framework_revision="TASK_FRAMEWORK_SHA")

    def test_plain_fixture_workflow_stays_independent_of_connector_context(self):
        path = self.root / "plain.yml"
        plain = "name: Independent Framework check\non: push\njobs: {}\n"
        path.write_text(plain)
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(read_connector_workflow(path), plain)

    def test_static_lint_input_retains_actual_shared_helper_commands(self):
        inspected = composite_validation_workflow(self.action.read_text(), framework_root=self.root)
        self.assertIn("Verify immutable source", inspected)
        self.assertIn('test -n "$EXPECTED"', inspected)
        self.assertIn("Run actual selected test", inspected)
        self.assertIn("fromJSON(inputs.caller-matrix).connector", inspected)
        self.assertNotIn("$/.github/actions/connector-context", inspected)


    def historical_sources(self):
        framework = Path(__file__).resolve().parents[2]
        original = (framework / ".github/workflows/connector-nginx-root-broker-historical.yml").read_text()
        prefix = original[:original.index("jobs:\n")]
        caller = prefix + """jobs:
  framework:
    permissions:
      contents: read
    uses: Easton97-Jens/ModSecurity-test-Framework/.github/workflows/connector-nginx-root-broker-historical.yml@""" + self.revision + """
    with:
      caller_manifest_artifact: ${{ inputs.caller_manifest_artifact }}
      parent_head_sha: ${{ inputs.parent_head_sha }}
      framework_sha: ${{ inputs.framework_sha }}
      protected_broker_sha: ${{ inputs.protected_broker_sha }}
      matrix_variant: ${{ inputs.matrix_variant }}
      run_id: ${{ inputs.run_id }}
"""
        path = self.root / ".github/workflows/connector-nginx-root-broker-historical.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(original)
        return caller, original, path

    def expand_historical(self, caller):
        return expand_workflow_source(caller, framework_root=self.root,
                                      framework_revision=self.revision,
                                      workflow_name="nginx-root-broker.yml")

    def test_historical_broker_preserves_actual_immutable_inner_identity(self):
        caller, _, _ = self.historical_sources()
        composed = self.expand_historical(caller)
        self.assertIn("  immutable-historical-broker:", composed)
        self.assertIn("8ae707d72f1a8acb25d239e55e28a73cbc7522b1", composed)
        self.assertIn("  workflow_call:", composed)
        self.assertNotIn("concurrency:", composed)
        self.assertNotIn("trusted-root-smoke:", composed)

    def test_historical_broker_rejects_changed_source_contracts(self):
        caller, original, path = self.historical_sources()
        mutations = (
            ("8ae707d72f1a8acb25d239e55e28a73cbc7522b1", "b" * 40),
            ("immutable-historical-broker:", "invented-local-job:"),
            ("contents: read", "contents: write"),
            ("type: string", "type: boolean"),
            ("required: true", "required: false"),
            ("${{ inputs.run_id }}", "${{ inputs.parent_head_sha }}"),
            ("jobs:\n", "concurrency: changed\njobs:\n"),
            ("    permissions:\n", "    if: false\n    permissions:\n"),
        )
        for old, new in mutations:
            with self.subTest(old=old):
                self.assertIn(old, original)
                path.write_text(original.replace(old, new, 1))
                with self.assertRaises(WorkflowSourceError):
                    self.expand_historical(caller)
        path.write_text(original)
        invalid_trigger = caller.replace("workflow_call:", "workflow_dispatch:", 1)
        with self.assertRaises(WorkflowSourceError):
            self.expand_historical(invalid_trigger)
        invalid_passthrough = caller.replace("${{ inputs.run_id }}", "foreign", 1)
        with self.assertRaises(WorkflowSourceError):
            self.expand_historical(invalid_passthrough)

    def test_connector_composites_verify_source_before_bootstrapping_python(self):
        framework = Path(__file__).resolve().parents[2]
        checked = 0
        for path in framework.glob(".github/actions/connector-ci/**/action.yml"):
            document = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
            steps = document["runs"]["steps"]
            setup = [i for i, step in enumerate(steps) if step.get("id") == "setup-python"]
            if not setup:
                continue
            with self.subTest(action=str(path.relative_to(framework))):
                gate = next(i for i, step in enumerate(steps) if step.get("name") == "Verify Framework checkout before Python bootstrap")
                verify = next(i for i, step in enumerate(steps) if step.get("name") == "Verify Python interpreter contract")
                context = next(i for i, step in enumerate(steps) if step.get("uses") == "$/.github/actions/connector-context")
                self.assertLess(gate, setup[0])
                self.assertLess(setup[0], verify)
                self.assertLess(verify, context)
                script = steps[gate]["run"]
                self.assertNotIn("python", script)
                # Execute the gate against independent simulated Git results.
                git = self.root / "git"
                git.write_text('#!/bin/sh\ncase "$1" in -C) printf "%s\\n" "$ACTUAL";; *) printf "%s\\n" "$COMMITTED";; esac\n')
                git.chmod(0o700)
                for committed, actual, expected, succeeds in (
                    ("a" * 40, "a" * 40, "a" * 40, True),
                    ("a" * 40, "b" * 40, "a" * 40, False),
                    ("a" * 40, "a" * 40, "b" * 40, False),
                    ("a" * 40, "a" * 40, "invalid", False),
                ):
                    env = {**os.environ, "PATH": str(self.root) + os.pathsep + os.environ["PATH"],
                           "COMMITTED": committed, "ACTUAL": actual,
                           "EXPECTED_FRAMEWORK_REVISION": expected}
                    result = subprocess.run(["bash", "-c", script], env=env, capture_output=True)
                    self.assertEqual(result.returncode == 0, succeeds, result.stderr)
            checked += 1
        self.assertEqual(checked, 18)

    def protected_sources(self):
        caller = """name: Actual protected caller
on:
  workflow_dispatch:
    inputs:
      target:
        required: true
        type: string
      on_demand:
        required: true
        type: boolean
        default: false
permissions: {}
jobs:
  framework:
    permissions:
      contents: read
      statuses: write
    uses: Easton97-Jens/ModSecurity-test-Framework/.github/workflows/connector-trusted-lighttpd-namespace.yml@""" + self.revision + """
    with:
      target: ${{ inputs.target }}
      on_demand: ${{ inputs.on_demand }}
"""
        callee = """name: Actual protected implementation
on:
  workflow_call:
    inputs:
      target:
        required: true
        type: string
      on_demand:
        required: true
        type: boolean
permissions: {}
concurrency:
  group: actual-protected-namespace
  cancel-in-progress: false
jobs:
  trusted-lighttpd-namespace:
    if: github.ref_protected == true
    permissions:
      contents: read
    runs-on: ubuntu-26.04
    steps:
      - name: Actual callee source sentinel
        run: /usr/bin/python3 -I fixed-owned-source.py
  report-trusted-lighttpd-namespace:
    needs: trusted-lighttpd-namespace
    permissions:
      statuses: write
    runs-on: ubuntu-26.04
    steps:
      - run: echo actual report
"""
        path = self.root / ".github/workflows/connector-trusted-lighttpd-namespace.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(callee)
        return caller, callee, path

    def expand_protected(self, caller):
        return expand_workflow_source(caller, framework_root=self.root,
                                      framework_revision=self.revision,
                                      workflow_name="run-trusted-lighttpd-namespace-dispatch.yml")

    def test_protected_reusable_view_contains_actual_inner_jobs_and_parent_trigger(self):
        caller, _, _ = self.protected_sources()
        composed = self.expand_protected(caller)
        self.assertIn("  workflow_dispatch:", composed)
        self.assertNotIn("  workflow_call:", composed)
        self.assertIn("  trusted-lighttpd-namespace:", composed)
        self.assertIn("  report-trusted-lighttpd-namespace:", composed)
        self.assertIn("Actual callee source sentinel", composed)
        self.assertIn("group: actual-protected-namespace", composed)
        self.assertIn("if: github.ref_protected == true", composed)
        self.assertIn("needs: trusted-lighttpd-namespace", composed)
        self.assertNotIn("  framework:", composed)

    def test_protected_reusable_wrong_pin_foreign_callee_and_owner_fail_closed(self):
        caller, _, _ = self.protected_sources()
        for before, after in (
                ("@" + self.revision, "@" + "b" * 40),
                ("@" + self.revision, "@master"),
                ("@" + self.revision, "@__FRAMEWORK_MIGRATION_SHA__"),
                ("connector-trusted-lighttpd-namespace.yml@", "foreign.yml@"),
                ("Easton97-Jens/ModSecurity-test-Framework/", "foreign/ModSecurity-test-Framework/")):
            with self.subTest(change=after):
                changed_caller = caller.replace(before, after)
                with self.assertRaises(WorkflowSourceError):
                    self.expand_protected(changed_caller)

    def test_protected_reusable_wrong_caller_name_is_rejected(self):
        caller, _, _ = self.protected_sources()
        with self.assertRaises(WorkflowSourceError):
            expand_workflow_source(caller, framework_root=self.root,
                                  framework_revision=self.revision, workflow_name="foreign.yml")

    def test_protected_reusable_rejects_input_permission_and_job_overrides(self):
        caller, _, _ = self.protected_sources()
        for before, after in (
                ("target: ${{ inputs.target }}", "target: ${{ secrets.token }}"),
                ("on_demand: ${{ inputs.on_demand }}", "on_demand: true"),
                ("      statuses: write", "      statuses: read"),
                ("  framework:", "  foreign:"),
                ("  framework:", "  framework:\n    continue-on-error: true"),
                ("  framework:", "  framework:\n    env:\n      PYTHONPATH: /foreign"),
                ("  framework:", "  framework:\n    secrets: inherit"),
                ("permissions: {}", "permissions:\n  contents: write")):
            with self.subTest(change=after):
                changed_caller = caller.replace(before, after)
                with self.assertRaises(WorkflowSourceError):
                    self.expand_protected(changed_caller)

    def test_protected_reusable_callee_changes_are_observed(self):
        caller, original, path = self.protected_sources()
        path.write_text(original.replace("Actual callee source sentinel", "Changed actual source sentinel"))
        self.assertIn("Changed actual source sentinel", self.expand_protected(caller))

    def test_protected_reusable_callee_contract_changes_are_rejected(self):
        caller, original, path = self.protected_sources()
        for before, after in (("      contents: read", "      contents: write"),
                              ("    permissions:", "    continue-on-error: true\n    permissions:"),
                              ("    if: github.ref_protected == true", "    env:\n      PYTHONPATH: /foreign"),
                              ("type: string", "type: boolean")):
            path.write_text(original.replace(before, after))
            with self.subTest(change=after), self.assertRaises(WorkflowSourceError):
                self.expand_protected(caller)

    def test_lighttpd_dispatch_default_is_the_only_permitted_interface_difference(self):
        caller, callee, path = self.protected_sources()
        selector = "      on_demand:\n        required: true\n        type: boolean"
        mutations = {
            "caller-default-true": (caller.replace("default: false", "default: true"), callee),
            "caller-default-missing": (caller.replace("        default: false\n", ""), callee),
            "caller-not-required": (caller.replace(selector, selector.replace("required: true", "required: false")), callee),
            "callee-not-required": (caller, callee.replace(selector, selector.replace("required: true", "required: false"))),
            "wrong-type-both": (caller.replace(selector, selector.replace("type: boolean", "type: string")), callee.replace(selector, selector.replace("type: boolean", "type: string"))),
            "callee-default-present": (caller, callee.replace(selector, selector + "\n        default: false")),
            "other-input-change": (caller, callee.replace("type: string", "type: boolean")),
            "nonforwarded-selector": (caller.replace("on_demand: ${{ inputs.on_demand }}", "on_demand: true"), callee),
        }
        for name, (changed_caller, changed_callee) in mutations.items():
            path.write_text(changed_callee)
            with self.subTest(variant=name), self.assertRaises(WorkflowSourceError):
                self.expand_protected(changed_caller)

    def test_protected_reusable_missing_or_symlinked_source_has_no_fallback(self):
        caller, original, path = self.protected_sources()
        path.unlink()
        with self.subTest(source="missing"), self.assertRaises(WorkflowSourceError):
            self.expand_protected(caller)
        saved = path.with_name("saved.yml")
        saved.write_text(original)
        path.symlink_to(saved)
        with self.subTest(source="symlink"), self.assertRaises(WorkflowSourceError):
            self.expand_protected(caller)



class CompositeShellcheckAdmissionTests(unittest.TestCase):
    VALID_VARIANTS = ("absolute", "path-name", "space-containing-literal", "command-shaped-literal")
    INVALID_VARIANTS = ("missing", "not-executable", "directory", "command-string")
    CHANGED_VARIANTS = ("removed-after-admission", "nonexecutable-after-admission")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.framework = self.root / "framework"
        self.output = self.root / "output"
        self.output.mkdir(mode=0o700)
        action = self.framework / ".github/actions/example/action.yml"
        action.parent.mkdir(parents=True)
        action.write_text("name: Example\ndescription: Fixture\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo literal\n")
        (self.framework / ".github/actionlint.yaml").write_text("{}\n")
        script = files("modsecurity_test_framework").parent / "ci/checks/security/check-connector-composite-actions.py"
        self.tool = runpy.run_path(str(script))

    def executable(self, name):
        path = self.root / name
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o700)
        return path

    def arguments(self, value):
        return ["check-composites", "--framework-root", str(self.framework),
                "--output-root", str(self.output), "--actionlint", "selected-actionlint",
                "--shellcheck", value]

    def test_shellcheck_accepts_one_literal_executable(self):
        for variant in self.VALID_VARIANTS:
            with self.subTest(variant=variant):
                name = {"absolute": "shellcheck-absolute", "path-name": "shellcheck-name",
                        "space-containing-literal": "literal shellcheck",
                        "command-shaped-literal": "shellcheck --literal"}[variant]
                executable = self.executable(name)
                value = name if variant == "path-name" else str(executable)
                with (patch.dict(os.environ, {"PATH": str(self.root) + os.pathsep + os.environ.get("PATH", "")}),
                      patch.object(sys, "argv", self.arguments(value)),
                      patch.object(self.tool["subprocess"], "run", return_value=SimpleNamespace(returncode=0)) as process,
                      contextlib.redirect_stdout(io.StringIO())):
                    self.assertEqual(self.tool["main"](), 0)
                command = process.call_args.args[0]
                self.assertEqual(command[0], "selected-actionlint")
                self.assertIn("-shellcheck=" + str(executable.resolve(strict=True)), command)
                self.assertEqual(process.call_count, 1)

    def test_shellcheck_invalid_value_rejected_before_allocation_or_process(self):
        for variant in self.INVALID_VARIANTS:
            with self.subTest(variant=variant):
                selected = self.root / ("invalid-" + variant)
                if variant == "not-executable":
                    selected.write_text("not executable")
                    selected.chmod(0o600)
                elif variant == "directory":
                    selected.mkdir(mode=0o700)
                elif variant == "command-string":
                    selected = self.executable("actual-shellcheck")
                value = str(selected) + (" --extra-argument" if variant == "command-string" else "")
                with (patch.object(sys, "argv", self.arguments(value)),
                      patch.object(self.tool["tempfile"], "mkdtemp", side_effect=AssertionError("allocation before admission")) as allocation,
                      patch.object(self.tool["subprocess"], "run", side_effect=AssertionError("process before admission")) as process,
                      self.assertRaises((ValueError, OSError))):
                    self.tool["main"]()
                allocation.assert_not_called()
                process.assert_not_called()
                self.assertEqual(list(self.output.iterdir()), [])

    def test_shellcheck_rechecked_before_actionlint_process(self):
        for variant in self.CHANGED_VARIANTS:
            with self.subTest(variant=variant):
                selected = self.executable("changed-shellcheck-" + variant)
                read_source = self.tool["read_composite_action_source"]
                def change_after_admission(*args, _variant=variant, _selected=selected, _read_source=read_source, **kwargs):
                    if _variant == "removed-after-admission":
                        _selected.unlink()
                    else:
                        _selected.chmod(0o600)
                    return _read_source(*args, **kwargs)
                with (patch.object(sys, "argv", self.arguments(str(selected))),
                      patch.dict(self.tool["main"].__globals__, {"read_composite_action_source": change_after_admission}),
                      patch.object(self.tool["subprocess"], "run", side_effect=AssertionError("process after tool removal")) as process,
                      self.assertRaises((ValueError, OSError))):
                    self.tool["main"]()
                process.assert_not_called()


def load_tests(loader, standard_tests, pattern):
    return standard_tests if os.environ.get("ON_DEMAND_TESTS") == "1" else unittest.TestSuite()


if __name__ == "__main__":
    unittest.main()
