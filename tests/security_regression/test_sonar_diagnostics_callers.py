"""Closed diagnostic-role controls independent of the scanner's execution tests."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from modsecurity_test_framework.sonar_diagnostics_contract import (
    ACTION_PATH, COMMIT, REFERENCE, UPSTREAM, canonical_role, scanner_allowed,
    scanner_step, validate_frozen_metadata,
)
from modsecurity_test_framework.workflow_sources import (
    WorkflowSourceError, expand_workflow_source, read_composite_action_source,
)
import yaml

ROOT = Path(__file__).resolve().parents[2]


class DiagnosticCallerTests(unittest.TestCase):
    def test_two_complete_paths_preserve_original_scope(self):
        for owner in ("parent", "framework"):
            for wrapped in (False, True):
                step = scanner_step(owner, wrapped=wrapped)
                self.assertTrue(scanner_allowed(step, owner))
                mutations = []
                for field, value in (("uses", "./.github/actions/sonar-private"),
                                     ("run", "echo unsafe"), ("continue-on-error", True)):
                    mutant = deepcopy(step); mutant[field] = value; mutations.append(mutant)
                for field, value in (("scannerVersion", "latest"), ("args", step["with"]["args"] + " -Dsonar.exclusions=**"),
                                     ("owner-mode", "unrelated"), ("upstream-action", "other/scanner@" + "a" * 40)):
                    mutant = deepcopy(step); mutant["with"][field] = value; mutations.append(mutant)
                mutant = deepcopy(step); mutant["env"]["OTHER_TOKEN"] = "extra"; mutations.append(mutant)
                for mutant in mutations:
                    with self.subTest(owner=owner, wrapped=wrapped, mutant=mutant):
                        self.assertFalse(scanner_allowed(mutant, owner))

    def test_role_is_not_a_generic_repository_pin(self):
        data = {"CI_SONAR_DIAGNOSTIC_REPOSITORY": "Easton97-Jens/ModSecurity-test-Framework",
                "CI_SONAR_DIAGNOSTIC_ACTION_PATH": ACTION_PATH,
                "CI_SONAR_DIAGNOSTIC_COMMIT": COMMIT}
        self.assertEqual(canonical_role(data), REFERENCE)
        for field in data:
            mutant = dict(data); mutant[field] += "other"
            with self.assertRaises(ValueError): canonical_role(mutant)

    def test_frozen_metadata_and_main_are_exact(self):
        validate_frozen_metadata(ROOT, ACTION_PATH + "/action.yml", read_composite_action_source)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); role = root / ACTION_PATH; role.mkdir(parents=True)
            for name in ("action.yml", "main.cjs"):
                (role / name).write_bytes((ROOT / ACTION_PATH / name).read_bytes())
            validate_frozen_metadata(root, ACTION_PATH + "/action.yml", read_composite_action_source)
            for name in ("action.yml", "main.cjs"):
                original = (role / name).read_bytes(); (role / name).write_bytes(original + b"\n")
                with self.assertRaises(ValueError):
                    validate_frozen_metadata(root, ACTION_PATH + "/action.yml", read_composite_action_source)
                (role / name).write_bytes(original)
            with self.assertRaises(ValueError):
                validate_frozen_metadata(root, ACTION_PATH + "/action.yaml", read_composite_action_source)
            (role / "main.cjs").unlink(); (role / "main.cjs").symlink_to(ROOT / ACTION_PATH / "main.cjs")
            with self.assertRaises((ValueError, OSError)):
                validate_frozen_metadata(root, ACTION_PATH + "/action.yml", read_composite_action_source)

    def test_expander_preserves_only_the_complete_parent_role(self):
        with tempfile.TemporaryDirectory() as temporary:
            for selected in (COMMIT, "a" * 40):
                step = scanner_step("parent")
                document = {"name": "Source fixture", "on": "push", "jobs": {"analysis": {"steps": [step]}}}
                text = yaml.safe_dump(document, sort_keys=False)
                self.assertEqual(expand_workflow_source(text, framework_root=Path(temporary),
                                 framework_revision=selected, workflow_name="sonarqube.yml"), text)
                for mutation in ("wrong-sha", "wrong-path", "wrong-profile", "wrong-upstream", "scope"):
                    mutant = deepcopy(document); target = mutant["jobs"]["analysis"]["steps"][0]
                    if mutation == "wrong-sha": target["uses"] = REFERENCE[:-40] + "b" * 40
                    elif mutation == "wrong-path": target["uses"] = REFERENCE.replace("sonar-private", "other-node")
                    elif mutation == "wrong-profile": target["with"]["owner-mode"] = "framework"
                    elif mutation == "wrong-upstream": target["with"]["upstream-action"] = UPSTREAM[:-40] + "b" * 40
                    else: target["with"]["args"] += " -Dsonar.sources=unrelated"
                    serialized = yaml.safe_dump(mutant)
                    with self.assertRaises(WorkflowSourceError):
                        expand_workflow_source(serialized, framework_root=Path(temporary),
                                               framework_revision=selected, workflow_name="sonarqube.yml")
                with self.assertRaises(WorkflowSourceError):
                    expand_workflow_source(text, framework_root=Path(temporary), framework_revision=selected,
                                           workflow_name="different.yml")
