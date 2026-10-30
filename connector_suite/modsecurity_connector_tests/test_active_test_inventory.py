"""Exercise admission and expansion before any selected child starts."""
from modsecurity_test_framework.connector_context import connector_root, source_path
from contextlib import redirect_stderr
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from modsecurity_connector_ci.lib import active_test_inventory as active


class ActiveTestInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP"))
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.root = self.directory / "repository"
        self.root.mkdir()
        self.output = self.directory / "output"
        self.output.mkdir()
        self.source = self.root / "tests/fixture_active.py"
        self.source.parent.mkdir()
        self.source.write_text("import unittest\nclass ControlTests(unittest.TestCase):\n"
                               "    def test_pass(self):\n        self.assertTrue(True)\n", encoding="utf-8")
        self.inventory_path = self.root / "inventory.json"
        self.data = {"schema_version": 1, "executions": [{
            "id": "fixture.control", "groups": ["control"],
            "sources": [{"path": "tests/fixture_active.py", "sha256": hashlib.sha256(self.source.read_bytes()).hexdigest()}],
            "selector": {"kind": "python", "target": "tests.fixture_active.ControlTests.test_pass"},
            "cases": [{"id": "control.positive", "requirement": "A legitimate selected case remains selectable.",
                       "profiles": ["parent"]}],
        }]}

    def load(self):
        self.inventory_path.write_text(json.dumps(self.data), encoding="utf-8")
        return active.load_inventory(self.root, self.inventory_path)

    def test_valid_inventory_preserves_case_identity(self):
        inventory = self.load()
        selected = active.select_executions(inventory, groups=("control",))
        summary = active.selection_summary(inventory, selected)
        self.assertEqual(summary["active_case_count"], 1)
        self.assertEqual(summary["selected_case_ids"], ["control.positive"])
        self.assertEqual(summary["hard_limit"], 100)

    def test_overflow_rejected_before_any_child_starts(self):
        self.data["executions"][0]["cases"] = [
            {"id": f"synthetic.case-{number}", "requirement": "Synthetic overflow admission input.",
             "profiles": ["parent"]} for number in range(101)]
        self.inventory_path.write_text(json.dumps(self.data), encoding="utf-8")
        sentinel = self.output / "child-started"
        with (patch.object(active.subprocess, "Popen", side_effect=lambda *args, **kwargs: sentinel.touch()) as child,
              redirect_stderr(io.StringIO()) as error):
            status = active.main(["--inventory", str(self.inventory_path), "--output-root", str(self.output)],
                                 root=self.root)
        self.assertEqual(status, 2)
        self.assertIn("101 cases; hard limit is 100", error.getvalue())
        child.assert_not_called()
        self.assertFalse(sentinel.exists())

    def test_duplicate_case_id_is_rejected(self):
        self.data["executions"][0]["cases"].append(copy.deepcopy(self.data["executions"][0]["cases"][0]))
        with self.assertRaisesRegex(active.InventoryError, "duplicate expanded case"):
            self.load()

    def test_duplicate_json_key_is_rejected(self):
        self.inventory_path.write_text('{"schema_version":1,"schema_version":1,"executions":[]}',
                                       encoding="utf-8")
        with self.assertRaisesRegex(active.InventoryError, "duplicate JSON key"):
            active.load_inventory(self.root, self.inventory_path)

    def test_unknown_selector_is_rejected(self):
        self.data["executions"][0]["selector"] = {"kind": "shell", "command": "true"}
        with self.assertRaisesRegex(active.InventoryError, "unknown execution selector"):
            self.load()

    def test_source_digest_mismatch_prevents_execution(self):
        inventory = self.load()
        self.source.write_text("raise RuntimeError('unreviewed collector')\n", encoding="utf-8")
        with patch.object(active.subprocess, "Popen") as child:
            with self.assertRaisesRegex(active.InventoryError, "source digest mismatch before execution"):
                active.execute_selected(inventory, inventory.executions, self.output)
        child.assert_not_called()

    def test_duplicate_python_definitions_are_rejected(self):
        variants = {
            "duplicate-method": "import unittest\nclass ControlTests(unittest.TestCase):\n"
                                "    def test_pass(self): pass\n    def test_pass(self): pass\n",
            "duplicate-class": "import unittest\nclass ControlTests(unittest.TestCase):\n"
                               "    def test_pass(self): pass\nclass ControlTests(unittest.TestCase):\n"
                               "    def test_pass(self): pass\n",
        }
        for label, content in variants.items():
            with self.subTest(label=label):
                self.source.write_text(content)
                self.data["executions"][0]["sources"][0]["sha256"] = hashlib.sha256(self.source.read_bytes()).hexdigest()
                with self.assertRaisesRegex(active.InventoryError, "one source-defined test method"):
                    self.load()

    def test_conflicting_shared_source_digests_are_rejected(self):
        self.source.write_text(self.source.read_text() +
                               "    def test_other(self):\n        self.assertTrue(True)\n")
        self.data["executions"][0]["sources"][0]["sha256"] = hashlib.sha256(self.source.read_bytes()).hexdigest()
        second = copy.deepcopy(self.data["executions"][0])
        second["id"] = "fixture.other"
        second["selector"]["target"] = "tests.fixture_active.ControlTests.test_other"
        second["cases"][0]["id"] = "control.other"
        second["sources"][0]["sha256"] = "0" * 64
        self.data["executions"].append(second)
        with self.assertRaisesRegex(active.InventoryError, "reviewed source digest mismatch"):
            self.load()

    def test_parent_traversal_source_is_rejected(self):
        self.data["executions"][0]["sources"] = [{"path": "../outside.py", "sha256": "a" * 64}]
        with self.assertRaisesRegex(active.InventoryError, "traverse outside"):
            self.load()

    def test_symlink_source_is_rejected(self):
        original = self.root / "original.py"
        self.source.rename(original)
        self.source.symlink_to(original)
        with self.assertRaisesRegex(active.InventoryError, "non-symlink"):
            self.load()

    def test_unknown_group_is_rejected(self):
        inventory = self.load()
        with self.assertRaisesRegex(active.InventoryError, "unknown or empty requested group"):
            active.select_executions(inventory, groups=("unlisted",))

    def test_empty_requested_group_is_rejected(self):
        inventory = self.load()
        with self.assertRaisesRegex(active.InventoryError, "unknown or empty requested group"):
            active.select_executions(inventory, groups=("",))

    def test_case_selection_closes_over_execution_variants(self):
        self.data["executions"][0]["cases"].append({
            "id": "control.negative", "requirement": "The second variant cannot hide behind one selector.",
            "profiles": ["parent"]})
        inventory = self.load()
        selected = active.select_executions(inventory, case_ids=("control.negative",))
        self.assertEqual(active.selection_summary(inventory, selected)["selected_case_ids"],
                         ["control.positive", "control.negative"])

    def test_inventory_cannot_raise_hard_limit(self):
        self.data["hard_limit"] = 1000
        with self.assertRaisesRegex(active.InventoryError, "closed inventory schema"):
            self.load()

    def test_offline_exception_counts_are_reported_separately(self):
        self.source.write_text(self.source.read_text() +
                               "    def test_offline(self):\n        self.assertTrue(True)\n")
        binding = {"path": "tests/fixture_active.py",
                   "sha256": hashlib.sha256(self.source.read_bytes()).hexdigest()}
        self.data["executions"][0]["sources"] = [binding]
        self.data["executions"][0]["cases"] = [
            {"id": f"core.case-{number}", "requirement": "Synthetic core admission row.",
             "profiles": ["parent"]} for number in range(100)]
        self.data.update(schema_version=2, offline_unit_exceptions=[{
            "id": "offline.fixture", "groups": ["offline-unit"], "sources": [binding],
            "selector": {"kind": "python", "target": "tests.fixture_active.ControlTests.test_offline"},
            "expected_subtests": 0,
            "cases": [{"id": "offline.fixture.case", "requirement": "One explicitly admitted offline unit.",
                       "profiles": ["parent"]}],
        }])
        inventory = self.load()
        summary = active.selection_summary(inventory, inventory.executions)
        self.assertEqual(summary["active_case_count"], 100)
        self.assertEqual(summary["catalog_case_count"], 101)
        self.assertEqual(summary["core_case_count"], 100)
        self.assertEqual(summary["offline_exception_case_count"], 1)
        self.assertEqual(summary["selected_offline_exception_case_ids"], ["offline.fixture.case"])
        # The same expanded boundary fixture must remain capped through both
        # no-argument and shared-group selection, not merely the core counter.
        self.data["offline_unit_exceptions"][0]["groups"].append("control")
        inventory = self.load()
        default = active.select_executions(inventory)
        self.assertEqual(default, inventory.default_executions)
        self.assertEqual(active.select_executions(inventory, groups=("control",)), default)
        self.assertEqual(len(active.selection_summary(inventory, default)["selected_case_ids"]), 100)
        with patch.object(active.subprocess, "Popen") as child:
            with self.assertRaises(active.InventoryError):
                active.execute_selected(inventory, inventory.executions, self.output)
            with self.assertRaises(active.InventoryError):
                active.select_executions(inventory, execution_ids=("offline.fixture",))
            with self.assertRaisesRegex(active.InventoryError, "explicit"):
                active.select_executions(inventory, on_demand=True)
        child.assert_not_called()
        selected = active.select_executions(inventory, execution_ids=("offline.fixture",), on_demand=True)
        self.assertEqual([item["id"] for item in selected], ["offline.fixture"])

    def test_offline_exception_rejects_native_selector_before_child(self):
        script = self.root / "ci/checks/security/check-workflow-fixture.sh"
        script.parent.mkdir(parents=True)
        script.write_text("#!/bin/sh\nexit 0\n")
        self.data.update(schema_version=2, offline_unit_exceptions=[{
            "id": "offline.native", "groups": ["offline-unit"],
            "sources": [{"path": script.relative_to(self.root).as_posix(),
                         "sha256": hashlib.sha256(script.read_bytes()).hexdigest()}],
            "selector": {"kind": "native", "script": script.relative_to(self.root).as_posix(),
                         "args": ["safe"]},
            "expected_subtests": 0,
            "cases": [{"id": "offline.native.case", "requirement": "Native selectors cannot use the offline exception.",
                       "profiles": ["parent"]}],
        }])
        with patch.object(active.subprocess, "Popen") as child:
            with self.assertRaises(active.InventoryError):
                self.load()
        child.assert_not_called()

    @unittest.skipUnless(os.environ.get("ACTIVE_TEST_OFFLINE_I12") == "1", "requires the isolated offline child")
    def test_offline_guard_rejects_process_before_launch(self):
        active._guard_offline_test_effects()
        sentinel = self.output / "unexpected-child"
        with self.assertRaisesRegex(active.InventoryError, "offline I12 unit cases prohibit"):
            subprocess.Popen([sys.executable, "-c", "from pathlib import Path; Path(__import__('sys').argv[1]).touch()",
                              str(sentinel)])
        self.assertFalse(sentinel.exists())

    @unittest.skipUnless(os.environ.get("ACTIVE_TEST_OFFLINE_I12") == "1", "requires the isolated offline child")
    def test_offline_guard_rejects_network_before_connect(self):
        active._guard_offline_test_effects()
        with socket.socket() as connection:
            with self.assertRaisesRegex(active.InventoryError, "offline I12 unit cases prohibit"):
                connection.connect(("127.0.0.1", 0))

    def test_unittest_discovery_uses_authoritative_inventory(self):
        import modsecurity_connector_tests as tests

        repository = connector_root()
        inventory = active.load_inventory(repository)
        expected = {execution["selector"]["target"] for execution in inventory.default_executions
                    if execution["selector"]["kind"] == "python"}
        selected = tests.load_tests(unittest.TestLoader(), unittest.TestSuite(), None)

        def selected_ids(suite):
            for item in suite:
                if isinstance(item, unittest.TestSuite):
                    yield from selected_ids(item)
                else:
                    yield item.id()

        actual = list(selected_ids(selected))
        self.assertEqual(set(actual), expected)
        self.assertEqual(len(actual), len(expected))

    def test_start_directory_discovery_uses_authoritative_inventory(self):
        repository = connector_root()
        inventory = active.load_inventory(repository)
        expected = {execution["selector"]["target"] for execution in inventory.default_executions
                    if execution["selector"]["kind"] == "python" and
                    execution["selector"]["target"].startswith("modsecurity_connector_tests.test_active_test_inventory.")}
        loader = unittest.TestLoader()
        test_directory = source_path("tests", root=repository)
        with patch.dict(os.environ, {"ON_DEMAND_TESTS": "0"}):
            selected = loader.discover(str(test_directory), pattern="test_active_test_inventory.py",
                                       top_level_dir=str(test_directory))
        self.assertFalse(loader.errors, loader.errors)

        def selected_ids(suite):
            for item in suite:
                if isinstance(item, unittest.TestSuite):
                    yield from selected_ids(item)
                else:
                    yield active.canonical_test_id(item, repository)

        actual = list(selected_ids(selected))
        self.assertTrue(expected)
        self.assertEqual(set(actual), expected)
        self.assertEqual(len(actual), len(expected))

    @unittest.skipUnless(os.name == "posix", "owned process groups require the supported POSIX host")
    def test_timeout_reaps_owned_process_group(self):
        record = self.output / "processes.json"
        log = self.output / "process.log"
        fixture = """import json, os, signal, subprocess, sys, time
child = None
def reap(_signal, _frame):
    if child is not None:
        child.wait(timeout=10)
    raise SystemExit(0)
signal.signal(signal.SIGTERM, reap)
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
with open(sys.argv[1], 'w', encoding='utf-8') as output:
    json.dump([os.getpid(), child.pid], output)
time.sleep(30)
"""
        command = [sys.executable, "-c", fixture, str(record)]
        try:
            with log.open("w", encoding="utf-8") as stream:
                with self.assertRaises(subprocess.TimeoutExpired):
                    active._run_child(command, self.directory, dict(os.environ), stream, timeout=1.0)
            self.assertTrue(record.is_file(), "the genuine parent and descendant must start before timeout")
            identifiers = json.loads(record.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline and any(self.process_exists(pid) for pid in identifiers):
                time.sleep(0.05)
            self.assertFalse(any(self.process_exists(pid) for pid in identifiers),
                             "both owned processes must be reaped after timeout")
        finally:
            if record.is_file():
                for identifier in json.loads(record.read_text(encoding="utf-8")):
                    try:
                        os.kill(identifier, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    @staticmethod
    def process_exists(identifier):
        try:
            os.kill(identifier, 0)
        except ProcessLookupError:
            return False
        return True




class SharedSourceInventoryTests(unittest.TestCase):
    setUp = ActiveTestInventoryTests.setUp
    load = ActiveTestInventoryTests.load

    def shared(self):
        binding = self.data["executions"][0]["sources"][0]
        self.data.update(schema_version=3, source_bindings=[binding], offline_unit_exceptions=[])
        self.data["executions"][0]["sources"] = [binding["path"]]

    def offline(self):
        self.source.write_text(self.source.read_text() + "    def test_offline(self): pass\n")
        self.shared()
        self.data["source_bindings"][0]["sha256"] = hashlib.sha256(self.source.read_bytes()).hexdigest()
        row = copy.deepcopy(self.data["executions"][0])
        row.update(id="offline.fixture", groups=["offline-unit"], expected_subtests=0)
        row["selector"]["target"] = "tests.fixture_active.ControlTests.test_offline"
        row["cases"][0]["id"] = "offline.fixture.case"
        self.data["offline_unit_exceptions"] = [row]

    def rejected_before_child(self):
        self.inventory_path.write_text(json.dumps(self.data))
        with patch.object(active.subprocess, "Popen") as child, redirect_stderr(io.StringIO()):
            self.assertEqual(active.main(["--check", "--inventory", str(self.inventory_path), "--group", "control"],
                                         root=self.root), 2)
        child.assert_not_called()

    def test_schema_versions_preserve_core_execution_maps(self):
        original = copy.deepcopy(self.data)
        expected = self.load().executions
        for version in (1, 2, 3):
            with self.subTest(version=version):
                self.data = copy.deepcopy(original)
                if version == 2:
                    self.data.update(schema_version=2, offline_unit_exceptions=[])
                elif version == 3:
                    self.shared()
                self.assertEqual(self.load().executions, expected)

    def test_shared_sources_preserve_both_budget_partitions(self):
        self.offline()
        shared = self.load()
        binding = self.data.pop("source_bindings")[0]
        self.data["schema_version"] = 2
        for rows in (self.data["executions"], self.data["offline_unit_exceptions"]):
            rows[0]["sources"] = [copy.deepcopy(binding)]
        legacy = self.load()
        self.assertEqual(shared.executions, legacy.executions)
        self.assertEqual(shared.core_case_ids, legacy.core_case_ids)
        self.assertEqual(shared.offline_case_ids, legacy.offline_case_ids)

    def test_unknown_unselected_reference_rejects_before_child(self):
        self.offline()
        self.data["offline_unit_exceptions"][0]["sources"].append("unknown.py")
        self.rejected_before_child()

    def test_duplicate_unselected_reference_rejects_before_child(self):
        self.offline()
        row = self.data["offline_unit_exceptions"][0]
        row["sources"] *= 2
        self.rejected_before_child()

    def test_inline_unselected_override_rejects_before_child(self):
        self.offline()
        self.data["offline_unit_exceptions"][0]["sources"] = [self.data["source_bindings"][0]]
        self.rejected_before_child()

    def test_empty_unselected_references_reject_before_child(self):
        self.offline()
        self.data["offline_unit_exceptions"][0]["sources"] = []
        self.rejected_before_child()

    def test_duplicate_pool_path_rejects_before_child(self):
        self.shared()
        self.data["source_bindings"] *= 2
        self.rejected_before_child()

    def test_unused_pool_record_rejects_before_child(self):
        self.shared()
        self.data["source_bindings"].append({"path": "unused.py", "sha256": "a" * 64})
        self.rejected_before_child()

    def test_extra_pool_field_rejects_before_child(self):
        self.shared()
        self.data["source_bindings"][0]["override"] = True
        self.rejected_before_child()

    def test_boolean_pool_digest_rejects_before_child(self):
        self.shared()
        self.data["source_bindings"][0]["sha256"] = True
        self.rejected_before_child()

    def test_noncanonical_pool_path_rejects_before_child(self):
        self.shared()
        self.data["source_bindings"][0]["path"] = "tests/../fixture_active.py"
        self.rejected_before_child()

    def test_pool_digest_mismatch_rejects_before_child(self):
        self.shared()
        self.data["source_bindings"][0]["sha256"] = "0" * 64
        self.rejected_before_child()

    def test_pool_symlink_rejects_before_child(self):
        self.shared()
        original = self.root / "original.py"
        self.source.rename(original)
        self.source.symlink_to(original)
        self.rejected_before_child()

    def test_shared_source_drift_rejects_before_execution(self):
        self.shared()
        admitted = self.load()
        self.source.write_text(self.source.read_text() + "# drift\n")
        with patch.object(active.subprocess, "Popen") as child:
            with self.assertRaisesRegex(active.InventoryError, "digest mismatch before execution"):
                active.execute_selected(admitted, admitted.executions, self.output)
        child.assert_not_called()

    def test_shared_inventory_drift_rejects_before_execution(self):
        self.shared()
        admitted = self.load()
        self.inventory_path.write_text(self.inventory_path.read_text() + " ")
        with patch.object(active.subprocess, "Popen") as child:
            with self.assertRaisesRegex(active.InventoryError, "inventory changed after admission"):
                active.execute_selected(admitted, admitted.executions, self.output)
        child.assert_not_called()

    def test_shared_core_cap_accepts_100_plus_offline(self):
        self.offline()
        self.data["executions"][0]["cases"] = [
            {"id": f"core.case-{index}", "requirement": "Explicit core admission boundary.",
             "profiles": ["parent"]} for index in range(100)]
        admitted = self.load()
        self.assertEqual(len(admitted.core_case_ids), 100)
        self.assertEqual(len(admitted.offline_case_ids), 1)

    def test_shared_core_cap_rejects_101_before_child(self):
        self.shared()
        self.data["executions"][0]["cases"] = [
            {"id": f"core.case-{index}", "requirement": "Explicit core overflow boundary.",
             "profiles": ["parent"]} for index in range(101)]
        self.rejected_before_child()

    def test_shared_offline_selector_restrictions_remain_binding(self):
        self.offline()
        self.data["offline_unit_exceptions"][0]["groups"] = ["control"]
        self.rejected_before_child()

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
