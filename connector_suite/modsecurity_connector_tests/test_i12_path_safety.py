"""Regression controls for the common I12 evidence filesystem boundary."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = connector_root()

import modsecurity_connector_ci.lib.i12_path_safety as paths


class EvidencePathControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="i12-path-control-", dir=os.environ.get("RUNNER_TEMP"))
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "admitted"
        self.root.mkdir(mode=0o700)
        self.environment = patch.dict(os.environ, {
            "CODEX_TEMP_ROOT": str(self.root), "VERIFIED_RUN_ROOT": "", "I12_TEST_ROOT": "",
            "CODEX_PROJECT_STATE": "",
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_admitted_create_read_and_explicit_replace_preserve_content(self):
        path = paths.create_text(self.root / "receipt.json", "original")
        self.assertEqual(paths.read_text(path), "original")
        paths.replace_text(path, "corrected")
        self.assertEqual(paths.read_text(path), "corrected")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with patch.dict(os.environ, {"CODEX_TEMP_ROOT": "", "CODEX_PROJECT_STATE": str(self.root)}):
            self.assertEqual(paths.output_path(path), path)

    def test_sibling_prefix_cannot_authorize_a_destination(self):
        sibling = self.base / "admitted-sibling"
        sibling.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, "outside approved"):
            paths.create_text(sibling / "receipt.json", "rejected")
        self.assertFalse((sibling / "receipt.json").exists())

    def test_parent_traversal_rejected_before_publication(self):
        target = self.root / ".." / "escaped.json"
        with self.assertRaisesRegex(ValueError, "traverse parents"):
            paths.create_text(target, "rejected")
        self.assertFalse((self.base / "escaped.json").exists())

    def test_symlinked_parent_cannot_redirect_publication(self):
        outside = self.base / "outside"
        outside.mkdir(mode=0o700)
        (self.root / "redirect").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symbolic links"):
            paths.create_text(self.root / "redirect/receipt.json", "rejected")
        self.assertFalse((outside / "receipt.json").exists())

    def test_create_new_never_replaces_existing_evidence(self):
        target = paths.create_text(self.root / "receipt.json", "original")
        with self.assertRaises(FileExistsError):
            paths.create_text(target, "replacement")
        self.assertEqual(target.read_text(), "original")

    def test_checkout_inside_external_storage_remains_read_only(self):
        platform = self.root / "platform"
        platform.mkdir(mode=0o700)
        (platform / ".git").mkdir(mode=0o555)
        runtime = paths.create_text(platform / "runtime.json", "allowed")
        self.assertEqual(paths.read_text(runtime), "allowed")
        checkout = platform / "worktree"
        checkout.mkdir(mode=0o700)
        (checkout / ".git").write_text("gitdir: /unused\n")
        with self.assertRaisesRegex(ValueError, "Git checkouts"):
            paths.create_text(checkout / "product.py", "rejected")
        self.assertFalse((checkout / "product.py").exists())

    def test_untrusted_parent_writes_rejected_before_file_creation(self):
        shared = self.root / "shared"
        shared.mkdir(mode=0o777)
        shared.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "untrusted replacement"):
            paths.create_text(shared / "receipt.json", "rejected")
        self.assertFalse((shared / "receipt.json").exists())

    def test_data_read_is_bounded_before_content_is_returned(self):
        target = self.root / "input.json"
        target.write_text("oversized")
        with self.assertRaisesRegex(ValueError, "bounded regular file"):
            paths.read_text(target, maximum_bytes=2)

    def test_receipt_label_cannot_select_another_directory(self):
        with self.assertRaisesRegex(ValueError, "bounded filename"):
            paths.leaf_name("../neighbor")

    def test_private_configuration_cannot_be_promoted_to_evidence(self):
        private = self.root / ".ssh"
        private.mkdir(mode=0o700)
        (private / "config").write_text("private")
        with self.assertRaisesRegex(ValueError, "private configuration"):
            paths.read_text(private / "config")
        with self.assertRaisesRegex(ValueError, "private configuration"):
            paths.input_directory(private)

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
