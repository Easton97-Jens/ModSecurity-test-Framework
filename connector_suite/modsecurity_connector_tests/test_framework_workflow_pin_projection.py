"""Offline regression coverage for future Framework integration-pin updates."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from modsecurity_test_framework.connector_context import connector_root, test_root, load_source, source_path
from modsecurity_connector_tests.framework_sha_fixture import set_framework_sha_fixture
from modsecurity_connector_tests.test_update_framework_versions import CURRENT_CANDIDATE_COMMON

SYNC = load_source(source_path("ci/tools/sync-framework-component-versions.py"))
OLD = "b" * 40
NEW = "a" * 40


class FrameworkWorkflowPinProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"])
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repo"
        self.root.mkdir()
        for spec in (*SYNC.TARGET_REGISTRY, *SYNC.FRAMEWORK_SHA_PROJECTION_TARGETS):
            target = self.root / spec.relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(connector_root() / spec.relative_path, target)
        set_framework_sha_fixture(self.root, OLD)
        self.common = Path(self.temporary.name) / "common.sh"
        self.common.write_text(CURRENT_CANDIDATE_COMMON)

    def snapshot(self):
        return {spec.relative_path: (self.root / spec.relative_path).read_bytes()
                for spec in (*SYNC.TARGET_REGISTRY, *SYNC.FRAMEWORK_SHA_PROJECTION_TARGETS)}

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], stderr=subprocess.DEVNULL).decode().strip()

    def baseline(self):
        self.git("init", "--quiet")
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "trusted fixture")
        return self.git("rev-parse", "HEAD")

    def test_all_registered_refs_and_inputs_follow_identity_without_other_byte_changes(self):
        before = self.snapshot()
        rendered = SYNC._render_framework_sha_projection_targets(self.root, NEW)
        self.assertEqual(len(rendered), 23)
        for item in rendered:
            name = str(item.path.relative_to(self.root))
            if name == "ci/tooling/project-versions.lock.json":
                old, new = json.loads(item.original), json.loads(item.replacement)
                self.assertEqual(old.pop("framework_sha"), OLD)
                self.assertEqual(new.pop("framework_sha"), NEW)
                self.assertEqual(old, new)
            else:
                self.assertIn(OLD.encode(), item.original)
                self.assertEqual(item.replacement, item.original.replace(OLD.encode(), NEW.encode()))
            item.path.write_bytes(item.replacement)
        self.assertNotEqual(before, self.snapshot())
        self.assertTrue(all(item.original == item.replacement for item in
                            SYNC._render_framework_sha_projection_targets(self.root, NEW)))

    def test_stale_symbolic_duplicate_or_missing_reference_rejected_without_writes(self):
        path = self.root / ".github/workflows/test-apache.yml"
        original = path.read_text()
        reference = next(line for line in original.splitlines() if "uses: Easton97-Jens/ModSecurity-test-Framework/" in line)
        for name, mutant in (
            ("stale", original.replace("@" + OLD, "@" + "c" * 40, 1)),
            ("symbolic", original.replace("@" + OLD, "@main", 1)),
            ("duplicate", original + reference + "\n"),
            ("missing", original.replace(reference + "\n", "", 1)),
            ("context-mismatch", original.replace("framework-revision: " + OLD,
                                                 "framework-revision: " + "d" * 40, 1)),
        ):
            with self.subTest(name=name):
                path.write_text(mutant)
                before = self.snapshot()
                with self.assertRaises(SYNC.SyncError):
                    SYNC._render_framework_sha_projection_targets(self.root, NEW)
                self.assertEqual(before, self.snapshot())
        path.write_text(original)

    def test_unregistered_workflow_and_historical_proof_are_untouched(self):
        historical = self.root / ".github/workflows/unregistered.yml"
        historical.write_text("proof: " + OLD + "\n")
        target = self.root / ".github/workflows/test-common.yml"
        target.write_text(target.read_text() + "# historical proof: " + OLD + "\n")
        rendered = SYNC._render_framework_sha_projection_targets(self.root, NEW)
        self.assertNotIn(historical, [item.path for item in rendered])
        result = next(item.replacement for item in rendered if item.path == target)
        self.assertTrue(result.endswith(("# historical proof: " + OLD + "\n").encode()))
        self.assertEqual(historical.read_text(), "proof: " + OLD + "\n")

    def test_trusted_base_reconstruction_rejects_unrelated_bytes_and_index_mode(self):
        base = self.baseline()
        values = SYNC.parse_common(self.common)
        for item in SYNC._render_targets(self.root, values, NEW):
            item.path.write_bytes(item.replacement)
        SYNC.verify_primary_changes(self.root, self.common, NEW, base)
        target = self.root / ".github/workflows/test-apache.yml"
        valid = target.read_bytes()
        target.write_bytes(valid + b"# unrelated mutation\n")
        with self.assertRaises(SYNC.SyncError):
            SYNC.verify_primary_changes(self.root, self.common, NEW, base)
        target.write_bytes(valid)
        self.git("add", ".")
        SYNC.verify_primary_changes(self.root, self.common, NEW, base, staged=True)
        self.git("update-index", "--chmod=+x", ".github/workflows/test-apache.yml")
        with self.assertRaises(SYNC.SyncError):
            SYNC.verify_primary_changes(self.root, self.common, NEW, base, staged=True)

    def test_publisher_allowlists_match_every_fixed_projection(self):
        publisher = (connector_root() / ".github/workflows/update-submodules.yml").read_text()
        for spec in SYNC.FRAMEWORK_SHA_PROJECTION_TARGETS:
            if spec.syntax == "framework-workflow":
                self.assertIn("-e " + spec.relative_path + " \\", publisher)
                self.assertIn('$6 == "' + spec.relative_path + '" ||', publisher)
                self.assertIn("            " + spec.relative_path + " \\", publisher)

    def test_ci_validation_bridge_uses_pinned_framework_without_global_product_path(self):
        updater = load_source(source_path("ci/tools/update-workflow-tools.py"), fresh=False)
        gitlink = "160000 commit " + OLD + "\tmodules/ModSecurity-test-Framework\n"
        with (mock.patch.dict(os.environ, {"TEST_ROOT": str(test_root()), "PYTHONPATH": str(connector_root())}),
              mock.patch.object(updater.subprocess, "check_output", side_effect=[NEW + "\n", gitlink, OLD + "\n"]),
              mock.patch.object(updater.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run):
            updater.validate_proposed_tree(connector_root(), {"candidate": "fixture"})
        arguments, options = run.call_args
        self.assertEqual(arguments[0][1:3], ["-P", "-m"])
        self.assertEqual(options["env"]["PYTHONPATH"].split(os.pathsep),
                         [str(test_root()), str(test_root() / "connector_suite")])
        self.assertEqual(options["env"]["FRAMEWORK_REVISION"], OLD)
        self.assertEqual(options["env"]["PYTHONSAFEPATH"], "1")
        self.assertEqual(options["env"]["CONNECTOR_REVISION"], NEW)

    def test_ci_validation_bridge_rejects_framework_checkout_pin_mismatch(self):
        updater = load_source(source_path("ci/tools/update-workflow-tools.py"), fresh=False)
        gitlink = "160000 commit " + OLD + "\tmodules/ModSecurity-test-Framework\n"
        with (mock.patch.dict(os.environ, {"TEST_ROOT": str(test_root())}),
              mock.patch.object(updater.subprocess, "check_output", side_effect=[NEW + "\n", gitlink, NEW + "\n"]),
              mock.patch.object(updater.subprocess, "run") as run):
            with self.assertRaisesRegex(updater.UpdateError, "differs from the pinned Framework gitlink"):
                updater.validate_proposed_tree(connector_root(), {})
        run.assert_not_called()


def load_tests(loader, tests, pattern):
    if os.environ.get("ON_DEMAND_TESTS") != "1":
        return loader.suiteClass()
    return tests
