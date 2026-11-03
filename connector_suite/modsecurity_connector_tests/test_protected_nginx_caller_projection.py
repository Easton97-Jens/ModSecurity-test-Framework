"""On-demand Parent integration checks against the exact immutable broker.

Requires an explicit actual Parent checkout, its immutable broker Git object,
and the candidate Parent projection implementation. Not a standalone Framework
selftest and never silently skipped for missing context.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest import mock

from modsecurity_test_framework import protected_nginx_caller as PROJECTION


FRAMEWORK = Path(__file__).resolve().parents[2]
BROKER_SHA = "8ae707d72f1a8acb25d239e55e28a73cbc7522b1"
BROKER_FRAMEWORK_SHA = "99a7985c1be92a2297b1b59208f64df6768f2cbf"
BROKER_SOURCE_SHA256 = "4c85bf823f7c9109706394b422b46a77e24e80808571cb13c7bf1a0a47abf2eb"


class ProtectedCallerProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Exact read-only Git source; no broker/root/publisher actions are invoked.
        selected = os.environ.get("CONNECTOR_ROOT", "").strip()
        if not selected:
            raise ValueError("Parent integration tests require explicit CONNECTOR_ROOT")
        cls.parent = Path(selected)
        if not (cls.parent / "ci/tools/sync-framework-component-versions.py").is_file():
            raise ValueError("Parent integration tests require the actual Parent checkout")
        raw = subprocess.check_output([
            "git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null", "-C", str(cls.parent),
            "show", BROKER_SHA + ":ci/runtime/broker/nginx_root_broker.py"], timeout=30)
        if hashlib.sha256(raw).hexdigest() != BROKER_SOURCE_SHA256:
            raise ValueError("immutable broker source identity mismatch")
        cls.broker = types.ModuleType("immutable_nginx_caller_contract")
        sys.modules[cls.broker.__name__] = cls.broker
        exec(compile(raw, "git:immutable-nginx-root-broker.py", "exec"), cls.broker.__dict__)
        cls.addClassCleanup(sys.modules.pop, cls.broker.__name__, None)
        cls.source = (FRAMEWORK / PROJECTION.SOURCE).read_bytes()
        spec = importlib.util.spec_from_file_location("parent_inline_caller_projection",
            cls.parent / "ci/tools/sync-framework-component-versions.py")
        cls.sync = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.sync
        cls.addClassCleanup(sys.modules.pop, spec.name, None)
        spec.loader.exec_module(cls.sync)

    def validate(self, raw):
        document = self.broker.parse_restricted_caller_workflow_yaml(raw)
        self.broker.validate_caller_workflow_document(
            document, broker_sha=BROKER_SHA, framework_sha=BROKER_FRAMEWORK_SHA)
        return document

    def test_original_delegation_fails_actual_immutable_contract(self):
        raw = (FRAMEWORK / "connector_suite/modsecurity_connector_tests/fixtures/nginx_root_broker/caller-delegated-11fab78.yml.fixture").read_bytes()
        with self.assertRaisesRegex(self.broker.BrokerError, "top-level has an unexpected key set"):
            self.validate(raw)

    def test_generated_current_source_passes_actual_immutable_contract(self):
        raw = PROJECTION.render(self.source, "b" * 40)
        document = self.validate(raw)
        self.assertEqual(set(document["jobs"]), {
            "prepare-manifests", "run-no-crs-broker", "run-with-crs-broker", "verify-evidence", "result"})
        self.assertEqual(document["concurrency"]["cancel-in-progress"], "false")
        self.assertEqual(raw, PROJECTION.render(self.source, "b" * 40))
        self.assertEqual(raw.split(b"# framework-caller-source-sha256: ", 1)[1].splitlines()[0],
                         b"11ee98f070a5a4c088e0c10466c0e867869f1769e5832bacf6bf2c5986a2cb3c")

    def test_weakened_gate_and_mutable_or_changed_protected_pins_fail(self):
        raw = PROJECTION.render(self.source, "b" * 40)
        for before, after in (
            (b"github.event.repository.fork == false", b"github.event.repository.fork != false"),
            (BROKER_SHA.encode(), b"master"),
            (BROKER_FRAMEWORK_SHA.encode(), b"c" * 40),
            (b"permissions: {}", b"permissions:\n  contents: write"),
        ):
            with self.subTest(before=before), self.assertRaises(self.broker.BrokerError):
                self.validate(raw.replace(before, after))


    def test_parent_versioned_caller_is_the_exact_generated_projection(self):
        raw = (self.parent / PROJECTION.TARGET).read_bytes()
        revision = raw.split(b"# framework-caller-revision: ", 1)[1].splitlines()[0].decode("ascii")
        self.assertEqual(raw, PROJECTION.render(PROJECTION.read_source(FRAMEWORK, revision), revision))
        self.validate(raw)

    def test_parent_typed_projector_agrees_with_framework_generator_and_preserves_broker_pins(self):
        spec = types.SimpleNamespace(relative_path=PROJECTION.TARGET)
        before = PROJECTION.render(self.source, "a" * 40)
        after = self.sync._render_inline_caller(spec, before.decode(), "a" * 40, "b" * 40, self.source)
        self.assertEqual(after.encode(), PROJECTION.render(self.source, "b" * 40))
        self.validate(after.encode())
        self.assertEqual(after.count("@" + BROKER_SHA), 2)
        self.assertNotIn("uses: Easton97-Jens/ModSecurity-test-Framework/", after)
        with self.assertRaises(self.sync.SyncError):
            self.sync._render_inline_caller(spec, before.decode().replace("contents: read", "contents: write"),
                                          "a" * 40, "b" * 40, self.source)

    def test_parent_projector_admits_only_exact_historical_migration_bytes(self):
        spec = types.SimpleNamespace(relative_path=PROJECTION.TARGET)
        raw = (FRAMEWORK / "connector_suite/modsecurity_connector_tests/fixtures/nginx_root_broker/caller-delegated-11fab78.yml.fixture").read_text()
        sha = "bb6c7580208a05c17d6d6674571731b6a71028cb"
        actual = self.sync._render_inline_caller(spec, raw, sha, "b" * 40, self.source)
        self.assertEqual(actual.encode(), PROJECTION.render(self.source, "b" * 40))
        with self.assertRaises(self.sync.SyncError):
            self.sync._render_inline_caller(spec, raw + "# changed\n", sha, "b" * 40, self.source)

    def test_parent_reads_fixed_caller_source_from_exact_framework_git_object(self):
        revision = "bb6c7580208a05c17d6d6674571731b6a71028cb"
        self.assertEqual(self.sync._inline_caller_source(self.parent, revision, FRAMEWORK), self.source)
        with mock.patch.object(self.sync.subprocess, "run") as called:
            with self.assertRaises(self.sync.SyncError):
                self.sync._inline_caller_source(self.parent, "master", FRAMEWORK)
            called.assert_not_called()
        bad_source = self.source.replace(b"contents: read", b"contents: write")
        spec = types.SimpleNamespace(relative_path=PROJECTION.TARGET)
        with self.assertRaisesRegex(self.sync.SyncError, "reviewed contract"):
            self.sync._render_inline_caller(spec, "", revision, revision, bad_source)



if __name__ == "__main__":
    unittest.main()
