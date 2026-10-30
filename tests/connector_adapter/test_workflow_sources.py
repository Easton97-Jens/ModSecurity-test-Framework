"""Prove that composed workflow checks follow actual immutable source bindings."""
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

from modsecurity_test_framework.workflow_sources import (
    WorkflowSourceError, composite_validation_workflow, expand_workflow_source, read_connector_workflow,
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


def load_tests(loader, standard_tests, pattern):
    return standard_tests if os.environ.get("ON_DEMAND_TESTS") == "1" else unittest.TestSuite()


if __name__ == "__main__":
    unittest.main()
