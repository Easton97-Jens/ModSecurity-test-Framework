"""Maintenance may refresh source hashes without changing behavioral selection."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import copy
import runpy
from types import SimpleNamespace
import json
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest import mock

from modsecurity_connector_ci.lib import active_inventory_updates as updates

ROOT = connector_root()


def encoded(value):
    return (json.dumps(value, indent=2) + "\n").encode()


class InventoryMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.before = {".go-version": b"1.27.3\n"}
        self.after = {".go-version": b"1.27.4\n"}
        self.approved = frozenset(self.before)
        self.test_source = (b"import unittest\nclass Control(unittest.TestCase):\n"
                            b"    def test_core(self): pass\n    def test_offline(self): pass\n")
        sources = [{"path": "tests/fixture.py", "sha256": updates.digest(self.test_source)},
                   {"path": ".go-version", "sha256": updates.digest(self.before[".go-version"])}]
        self.inventory = {"schema_version": 2, "executions": [{
            "id": "fixture.core", "groups": ["control"], "sources": copy.deepcopy(sources),
            "selector": {"kind": "python", "target": "tests.fixture.Control.test_core"},
            "cases": [{"id": "fixture.core.case", "requirement": "Retain the core control.",
                       "profiles": ["parent"]}],
        }], "offline_unit_exceptions": [{
            "id": "offline.fixture", "groups": ["offline-unit"], "sources": copy.deepcopy(sources),
            "selector": {"kind": "python", "target": "tests.fixture.Control.test_offline"},
            "expected_subtests": 0,
            "cases": [{"id": "offline.fixture.case", "requirement": "Retain the offline control.",
                       "profiles": ["parent"]}],
        }]}

    def baseline(self):
        inventory = encoded(self.inventory)
        archive = encoded({"inventory_sha256": updates.digest(inventory),
                           "on_demand_definition_count": 7, "sources": ["unchanged"]})
        return inventory, archive

    def derive(self):
        inventory, archive = self.baseline()
        return updates.derive_companions(inventory, archive, self.before, self.after, self.approved)

    def test_updates_only_hashes_in_both_budget_arrays(self):
        inventory, archive = self.baseline()
        outputs = self.derive()
        expected = copy.deepcopy(self.inventory)
        for group in ("executions", "offline_unit_exceptions"):
            expected[group][0]["sources"][1]["sha256"] = updates.digest(self.after[".go-version"])
        self.assertEqual(json.loads(outputs[updates.INVENTORY]), expected)
        expected_archive = json.loads(archive)
        expected_archive["inventory_sha256"] = updates.digest(outputs[updates.INVENTORY])
        self.assertEqual(json.loads(outputs[updates.ARCHIVE]), expected_archive)
        updates.verify_companions(inventory, archive, self.before, self.after, self.approved, outputs)

    def test_cli_root_accepts_only_actual_canonical_repository(self):
        self.assertEqual(updates._cli_root(str(updates.ROOT)), updates.ROOT)

    def test_copied_script_cli_root_accepts_its_private_source_tree(self):
        # This measures CLI-root admission, not Git execution or publication.
        # The ordinary import retains the private copy's real co_filename.
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory)
            copied = private / "ci/lib/active_inventory_updates.py"
            copied.parent.mkdir(parents=True)
            original = Path(updates.__file__).read_bytes()
            copied.write_bytes(original)
            self.assertEqual(copied.read_bytes(), original)
            marker = private / "modsecurity_test_framework/__init__.py"
            marker.parent.mkdir()
            marker.write_text("# Explicit private Framework-root fixture.\n")
            with mock.patch.dict(os.environ, TEST_ROOT=str(private)):
                module = SimpleNamespace(**runpy.run_path(str(copied)))
                self.assertEqual(module._cli_root(str(private)), private)
                self.assertEqual(module.ROOT, private)
                self.assertEqual(module._cli_root.__code__.co_filename, str(copied))

    def test_cli_root_rejects_sibling_before_git_or_file_operations(self):
        sibling = str(updates.ROOT.parent / (updates.ROOT.name + "-foreign"))
        with mock.patch.object(updates, "language_companions") as derive:
            status = updates.main(["verify", "--kind", "python", "--base", "HEAD", "--root", sibling])
        self.assertEqual(status, 2)
        derive.assert_not_called()

    def test_cli_root_rejects_traversal_alias(self):
        alias = str(updates.ROOT) + "/../" + updates.ROOT.name
        with self.assertRaisesRegex(updates.InventoryUpdateError, "canonical source repository"):
            updates._cli_root(alias)

    def test_cli_root_rejects_symlink_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            alias = Path(directory) / "repository-alias"
            alias.symlink_to(updates.ROOT, target_is_directory=True)
            with self.assertRaisesRegex(updates.InventoryUpdateError, "canonical source repository"):
                updates._cli_root(alias)

    def test_noop_preserves_original_bytes(self):
        inventory, archive = self.baseline()
        compact = json.dumps(json.loads(inventory), separators=(",", ":")).encode()
        archive = encoded({"inventory_sha256": updates.digest(compact), "sources": []})
        outputs = updates.derive_companions(compact, archive, self.before, self.before, self.approved)
        self.assertEqual(outputs, {updates.INVENTORY: compact, updates.ARCHIVE: archive})

    def test_unapproved_primary_path_is_rejected(self):
        inventory, archive = self.baseline()
        with self.assertRaises(updates.InventoryUpdateError):
            updates.derive_companions(inventory, archive, self.before, self.after, frozenset())

    def test_stale_source_binding_is_rejected(self):
        self.inventory["executions"][0]["sources"][1]["sha256"] = "0" * 64
        with self.assertRaises(updates.InventoryUpdateError):
            self.derive()

    def test_stale_archive_binding_is_rejected(self):
        inventory, _archive = self.baseline()
        stale_archive = encoded({"inventory_sha256": "0" * 64})
        with self.assertRaises(updates.InventoryUpdateError):
            updates.derive_companions(inventory, stale_archive,
                                      self.before, self.after, self.approved)

    def test_control_fields_cannot_be_smuggled_into_companions(self):
        inventory, archive = self.baseline()
        valid = self.derive()
        for field in ("selector", "case", "typed-subtest-count"):
            with self.subTest(field=field):
                outputs = dict(valid)
                changed = json.loads(outputs[updates.INVENTORY])
                if field == "selector":
                    changed["executions"][0]["selector"]["target"] = "tests.fixture.Control.test_other"
                elif field == "case":
                    changed["executions"][0]["cases"][0]["id"] = "injected.case"
                else:
                    changed["offline_unit_exceptions"][0]["expected_subtests"] = False
                outputs[updates.INVENTORY] = encoded(changed)
                forged_archive = json.loads(outputs[updates.ARCHIVE])
                forged_archive["inventory_sha256"] = updates.digest(outputs[updates.INVENTORY])
                outputs[updates.ARCHIVE] = encoded(forged_archive)
                with self.assertRaises(updates.InventoryUpdateError):
                    updates.verify_companions(inventory, archive, self.before, self.after,
                                              self.approved, outputs)

    def test_extra_companion_output_is_rejected(self):
        inventory, archive = self.baseline()
        outputs = self.derive()
        outputs["unexpected.json"] = b"{}\n"
        with self.assertRaises(updates.InventoryUpdateError):
            updates.verify_companions(inventory, archive, self.before, self.after, self.approved, outputs)

    def test_archive_source_cycle_is_rejected(self):
        self.inventory["executions"][0]["sources"].append({"path": updates.ARCHIVE, "sha256": "0" * 64})
        with self.assertRaises(updates.InventoryUpdateError):
            self.derive()

    def repository(self):
        temporary = tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"])
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        inventory, archive = self.baseline()
        for name, data in {updates.INVENTORY: inventory, updates.ARCHIVE: archive,
                           "tests/fixture.py": self.test_source, **self.before}.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return root

    def test_finished_update_is_readmitted_with_unchanged_selection(self):
        root = self.repository()
        snapshot = updates.capture_update(root, self.approved)
        (root / ".go-version").write_bytes(self.after[".go-version"])
        written = updates.finish_update(root, snapshot)
        self.assertEqual(set(written), updates.COMPANIONS)
        self.assertEqual({name: (root / name).read_bytes() for name in updates.COMPANIONS}, self.derive())

    def test_unapproved_source_drift_prevents_companion_writes(self):
        root = self.repository()
        original = {name: (root / name).read_bytes() for name in updates.COMPANIONS}
        snapshot = updates.capture_update(root, self.approved)
        (root / ".go-version").write_bytes(self.after[".go-version"])
        (root / "tests/fixture.py").write_bytes(self.test_source + b"# unrelated source drift\n")
        with self.assertRaises(updates.InventoryUpdateError):
            updates.finish_update(root, snapshot)
        self.assertEqual({name: (root / name).read_bytes() for name in updates.COMPANIONS}, original)

    def language_outputs(self, version):
        inventory, archive = self.baseline()
        base = {updates.INVENTORY: inventory, updates.ARCHIVE: archive,
                ".go-version": self.before[".go-version"],
                updates.PROJECT_LOCK: encoded({"go_version": "1.27.3", "python_version": "3.15.1"}),
                "connectors/envoy/ext_proc/go.mod": b"module fixture\n\ngo 1.27.0\n",
                "connectors/envoy/ext_proc/go.sum": b""}
        candidate = dict(base)
        candidate[".go-version"] = (version + "\n").encode()
        candidate[updates.PROJECT_LOCK] = encoded({"go_version": version, "python_version": "3.15.1"})
        def blob(_root, revision, name):
            return {"base": base, "candidate": candidate}[revision][name]
        with mock.patch.object(updates, "trusted_blob", side_effect=blob):
            return updates.language_companions(ROOT, "base", "go", "candidate")

    def test_next_stable_go_minor_remains_eligible(self):
        outputs = self.language_outputs("1.28.0")
        actual = json.loads(outputs[updates.INVENTORY])
        self.assertEqual(actual["executions"][0]["sources"][1]["sha256"],
                         updates.digest(b"1.28.0\n"))

    def test_go_version_regression_is_rejected(self):
        with self.assertRaises(updates.InventoryUpdateError):
            self.language_outputs("1.27.2")

    def script(self, name, relative):
        return load_source(source_path(relative))

    def test_large_companions_roll_back_after_late_transaction_failure(self):
        shared = self.script("maintenance_transaction_unit", "scripts/version_updater_common.py")
        root = self.repository()
        originals = {}
        transactions = []
        for name in sorted(updates.COMPANIONS):
            old = encoded({"padding": "a" * 8192})
            new = encoded({"padding": "b" * 9000})
            (root / name).write_bytes(old)
            originals[name] = old
            parser = lambda value: value
            original, metadata = shared.read_current_version_with_stat(
                root, version_filename=name, parse_stable_version=parser, max_bytes=updates.MAX_BYTES)
            transactions.append((name, new, original, metadata, parser, updates.MAX_BYTES))
        fsync = shared._fsync_directory
        calls = 0
        def fail_once(directory):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected durability failure after both companion replacements")
            return fsync(directory)
        with mock.patch.object(shared, "_fsync_directory", side_effect=fail_once):
            with self.assertRaises(shared.TargetError):
                shared.replace_project_files(root, transactions)
        self.assertEqual({name: (root / name).read_bytes() for name in updates.COMPANIONS}, originals)
        self.assertGreaterEqual(calls, 4)

    def test_actions_rollback_preserves_foreign_companion_replacement(self):
        from modsecurity_connector_ci import workflow_update_validation as validation
        actions = validation.product
        root = self.repository()
        primary = "ci/tooling/security-tools.lock.yml"
        self.assertIn(primary, actions.ALLOWED_UPDATE_PATHS)
        path = root / primary
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"trusted primary\n")
        old_archive = (root / updates.ARCHIVE).read_bytes()
        foreign = b'{"concurrent_owner":"preserve this replacement"}\n'
        def change_then_replace(*_arguments):
            path.write_bytes(b"candidate primary\n")
            (root / updates.INVENTORY).write_bytes(foreign)
            raise updates.InventoryUpdateError("injected candidate failure after concurrent companion replacement")
        with (mock.patch.object(actions, "ALLOWED_UPDATE_PATHS", frozenset({primary})),
              mock.patch.object(actions, "load_lock", return_value=(path, {}, "0" * 64)),
              mock.patch.object(actions, "ensure_locked_action_workflow_coverage"),
              mock.patch.object(actions, "validate_candidate_shape"),
              mock.patch.object(actions, "apply_lock_changes", side_effect=change_then_replace),
              mock.patch.object(actions, "update_workflow_references"),
              mock.patch.object(actions, "update_documentation_references")):
            with self.assertRaises(updates.InventoryUpdateError):
                actions.apply_candidate(root, {})
        self.assertEqual(path.read_bytes(), b"trusted primary\n")
        self.assertEqual((root / updates.INVENTORY).read_bytes(), foreign)
        self.assertEqual((root / updates.ARCHIVE).read_bytes(), old_archive)



class SharedSourceMaintenanceTests(unittest.TestCase):
    baseline = InventoryMaintenanceTests.baseline
    derive = InventoryMaintenanceTests.derive
    repository = InventoryMaintenanceTests.repository
    # Only the explicitly selected methods below are new reviewed executions.
    def setUp(self):
        InventoryMaintenanceTests.setUp(self)
        self.inventory["schema_version"] = 3
        self.inventory["source_bindings"] = copy.deepcopy(self.inventory["executions"][0]["sources"])
        for key in ("executions", "offline_unit_exceptions"):
            self.inventory[key][0]["sources"] = [source["path"] for source in self.inventory["source_bindings"]]

    def test_shared_sha_update_preserves_references_and_selection(self):
        outputs = self.derive()
        expected = copy.deepcopy(self.inventory)
        expected["source_bindings"][1]["sha256"] = updates.digest(self.after[".go-version"])
        self.assertEqual(json.loads(outputs[updates.INVENTORY]), expected)
        self.assertEqual(len(list(updates._records(expected))), 2)

    def test_shared_noop_preserves_noncanonical_format_bytes(self):
        inventory, _ = self.baseline()
        inventory = json.dumps(json.loads(inventory), separators=(",", ":")).encode()
        archive = encoded({"inventory_sha256": updates.digest(inventory)})
        self.assertEqual(updates.derive_companions(inventory, archive, self.before, self.before, self.approved),
                         {updates.INVENTORY: inventory, updates.ARCHIVE: archive})

    def test_shared_publish_rejects_reference_change(self):
        inventory, archive = self.baseline()
        outputs = self.derive()
        forged = json.loads(outputs[updates.INVENTORY])
        forged["offline_unit_exceptions"][0]["sources"].reverse()
        outputs[updates.INVENTORY] = encoded(forged)
        forged_archive = json.loads(outputs[updates.ARCHIVE])
        forged_archive["inventory_sha256"] = updates.digest(outputs[updates.INVENTORY])
        outputs[updates.ARCHIVE] = encoded(forged_archive)
        with self.assertRaises(updates.InventoryUpdateError):
            updates.verify_companions(inventory, archive, self.before, self.after, self.approved, outputs)

    def test_shared_unknown_unselected_reference_rejects_derivation(self):
        self.inventory["offline_unit_exceptions"][0]["sources"].append("unknown.py")
        with self.assertRaises(updates.InventoryUpdateError):
            self.derive()

    def test_shared_duplicate_pool_rejects_derivation(self):
        self.inventory["source_bindings"].append(copy.deepcopy(self.inventory["source_bindings"][0]))
        with self.assertRaises(updates.InventoryUpdateError):
            self.derive()

    def test_shared_unused_pool_rejects_derivation(self):
        self.inventory["source_bindings"].append({"path": "unused.py", "sha256": "a" * 64})
        with self.assertRaises(updates.InventoryUpdateError):
            self.derive()

    def test_shared_inline_override_rejects_derivation(self):
        self.inventory["offline_unit_exceptions"][0]["sources"][0] = self.inventory["source_bindings"][0]
        with self.assertRaises(updates.InventoryUpdateError):
            self.derive()

    def test_shared_noncanonical_pool_path_rejects_derivation(self):
        self.inventory["source_bindings"][0]["path"] = "tests/../fixture.py"
        with self.assertRaises(updates.InventoryUpdateError):
            self.derive()

    def test_shared_boolean_digest_rejects_derivation(self):
        self.inventory["source_bindings"][0]["sha256"] = True
        with self.assertRaises(updates.InventoryUpdateError):
            self.derive()

    def test_shared_explicit_library_root_readmits_update(self):
        root = self.repository()
        self.assertNotEqual(root, updates.ROOT)
        snapshot = updates.capture_update(root, self.approved)
        (root / ".go-version").write_bytes(self.after[".go-version"])
        self.assertEqual(set(updates.finish_update(root, snapshot)), updates.COMPANIONS)
        self.assertEqual({name: (root / name).read_bytes() for name in updates.COMPANIONS}, self.derive())

    def test_shared_source_drift_prevents_companion_write(self):
        root = self.repository()
        original = {name: (root / name).read_bytes() for name in updates.COMPANIONS}
        snapshot = updates.capture_update(root, self.approved)
        (root / "tests/fixture.py").write_bytes(self.test_source + b"# foreign drift\n")
        with self.assertRaises(updates.InventoryUpdateError):
            updates.finish_update(root, snapshot)
        self.assertEqual({name: (root / name).read_bytes() for name in updates.COMPANIONS}, original)


def load_tests(loader, standard_tests, pattern):
    from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
    return module_load_tests(loader, standard_tests, pattern)
