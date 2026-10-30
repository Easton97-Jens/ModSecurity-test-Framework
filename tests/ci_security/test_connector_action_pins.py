"""Preserve connector integration authority without borrowing native pin policy."""

from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PINS = runpy.run_path(str(ROOT / "ci/checks/security/connector_action_pins.py"))
CANONICAL = runpy.run_path(str(ROOT / "ci/tools/check-common-versions.py"))
SOURCE = ".github/workflows/connector-protected-nginx-exact-head.yml"


class ConnectorActionPinsTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP"))
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for relative in (PINS["LOCK"], *PINS["load_lock"](ROOT)["sources"]):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / relative).read_bytes())
        return root

    def canonical_findings(self, root):
        return CANONICAL["active_consumer_pin_literals"](ROOT / "ci/lib/common.sh", root)

    def test_all_reviewed_sources_validate_without_connector_checkout(self):
        lock = PINS["load_lock"](ROOT)
        for relative in lock["sources"]:
            with self.subTest(source=relative):
                self.assertEqual(PINS["validate_source"](ROOT, relative), [])
        self.assertEqual(self.canonical_findings(ROOT), [])

    def test_wrong_action_sha_is_rejected(self):
        root = self.fixture()
        path = root / SOURCE
        original = path.read_text()
        path.write_text(
            original.replace(
                "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "actions/checkout@" + "0" * 40,
                1,
            )
        )
        self.assertTrue(PINS["validate_source"](root, SOURCE))
        self.assertTrue(any(SOURCE in error and "reviewed migration contract" in error
                            for error in self.canonical_findings(root)))

    def test_coordinated_workflow_and_lock_rewrite_cannot_reauthorize_itself(self):
        root = self.fixture()
        path = root / SOURCE
        path.write_text(
            path.read_text().replace(
                "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "actions/checkout@" + "0" * 40,
                1,
            )
        )
        lock_path = root / PINS["LOCK"]
        lock = json.loads(lock_path.read_text())
        lock["sources"][SOURCE] = hashlib.sha256(path.read_bytes()).hexdigest()
        lock["actions"]["actions/checkout"]["sha"] = "0" * 40
        lock_path.write_text(json.dumps(lock))
        self.assertTrue(
            any(
                "immutable migration snapshot" in error
                for error in PINS["validate_source"](root, SOURCE)
            )
        )
        self.assertTrue(any("immutable migration snapshot" in error
                            for error in self.canonical_findings(root)))

    def test_protected_runner_and_permission_changes_are_rejected(self):
        root = self.fixture()
        path = root / SOURCE
        path.write_text(
            path.read_text().replace("protected-exact-head-nginx", "ubuntu-26.04")
        )
        self.assertTrue(PINS["validate_source"](root, SOURCE))
        self.assertTrue(any(SOURCE in error and "reviewed migration contract" in error
                            for error in self.canonical_findings(root)))

    def test_unknown_source_path_cannot_borrow_the_integration_authority(self):
        root = self.fixture()
        unknown = ".github/workflows/connector-unregistered.yml"
        (root / unknown).write_bytes((root / SOURCE).read_bytes())
        self.assertTrue(
            any(
                "closed integration registry" in error
                for error in PINS["validate_source"](root, unknown)
            )
        )
        self.assertTrue(any(unknown in error and "CI_ACTION_CHECKOUT_REPOSITORY" in error
                            for error in self.canonical_findings(root)))
