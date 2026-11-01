"""Exercise admission and expansion before any selected child starts."""
from modsecurity_test_framework.connector_context import connector_root, source_path
from contextlib import redirect_stderr, redirect_stdout, chdir
from contextlib import contextmanager
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import stat
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

class IndexedSourceInventoryTests(unittest.TestCase):
    setUp = ActiveTestInventoryTests.setUp
    load = ActiveTestInventoryTests.load
    shared = SharedSourceInventoryTests.shared
    offline = SharedSourceInventoryTests.offline

    def indexed(self):
        self.offline()
        product = self.root / "product.txt"
        product.write_text("explicit Product snapshot\n")
        self.data.update(schema_version=5, connector_source_paths=["product.txt"])
        for row in self.data["executions"] + self.data["offline_unit_exceptions"]:
            row["sources"] = [0, 1]

    def rejected_before_effects(self, message):
        self.inventory_path.write_text(json.dumps(self.data))
        before = tuple(self.output.iterdir())
        with (patch.object(active.subprocess, "Popen") as child,
              patch.object(active, "_output_directory") as allocate,
              redirect_stderr(io.StringIO()) as error):
            self.assertEqual(active.main(["--inventory", str(self.inventory_path),
                                          "--output-root", str(self.output), "--group", "control"],
                                         root=self.root), 2)
        self.assertRegex(error.getvalue(), message)
        child.assert_not_called()
        allocate.assert_not_called()
        self.assertEqual(tuple(self.output.iterdir()), before)

    def test_schema4_and5_preserve_complete_execution_graph(self):
        self.indexed()
        original = copy.deepcopy(self.data)
        indexed = self.load()
        self.data["schema_version"] = 4
        for row in self.data["executions"] + self.data["offline_unit_exceptions"]:
            row["sources"] = ["tests/fixture_active.py", "product.txt"]
        expanded = self.load()
        self.assertEqual(indexed.executions, expanded.executions)
        self.assertEqual(indexed.case_ids, expanded.case_ids)
        self.assertEqual(indexed.offline_case_ids, expanded.offline_case_ids)
        self.assertEqual(indexed.connector_source_paths, expanded.connector_source_paths)
        self.assertEqual(indexed.default_executions, expanded.default_executions)
        self.assertEqual(original["executions"][0]["sources"], [0, 1])
        self.assertEqual(indexed.executions[0]["sources"], {
            "tests/fixture_active.py": hashlib.sha256(self.source.read_bytes()).hexdigest(),
            "product.txt": hashlib.sha256((self.root / "product.txt").read_bytes()).hexdigest()})

    def test_invalid_indexed_references_reject_before_child(self):
        self.indexed()
        original = copy.deepcopy(self.data)
        variants = {
            "boolean": [True], "negative": [-1], "out-of-range": [2],
            "float": [0.0], "string": ["0"], "null": [None],
            "duplicate": [0, 0], "empty": [], "wrong-container": {"index": 0},
            "mixed": [0, "product.txt"], "unselected-row": [2],
        }
        for label, references in variants.items():
            with self.subTest(label=label):
                self.data = copy.deepcopy(original)
                section = "offline_unit_exceptions" if label == "unselected-row" else "executions"
                self.data[section][0]["sources"] = references
                self.rejected_before_effects("indexed sources")

    def test_invalid_indexed_pool_rejects_before_child(self):
        self.indexed()
        original = copy.deepcopy(self.data)
        variants = {
            "duplicate-fixed": {"source_bindings": original["source_bindings"] * 2},
            "cross-owner": {"connector_source_paths": ["tests/fixture_active.py"]},
            "duplicate-product": {"connector_source_paths": ["product.txt", "product.txt"]},
            "unused-fixed": {"source_bindings": original["source_bindings"] +
                             [{"path": "unused.py", "sha256": "a" * 64}]},
            "unused-product": {"connector_source_paths": ["product.txt", "unused.txt"]},
        }
        (self.root / "unused.txt").write_text("unused Product input\n")
        for label, change in variants.items():
            with self.subTest(label=label):
                self.data = copy.deepcopy(original)
                self.data.update(copy.deepcopy(change))
                # Inserting a fixed binding shifts the Product index. Preserve
                # the intended closure so this control proves the unused guard.
                if label == "unused-fixed":
                    for row in self.data["executions"] + self.data["offline_unit_exceptions"]:
                        row["sources"] = [0, 2]
                self.rejected_before_effects("duplicate reviewed source|source ownership|unused paths")

    def test_indexed_core_overflow_rejects_before_child(self):
        self.indexed()
        self.data["executions"][0]["cases"] = [
            {"id": f"core.case-{index}", "requirement": "Explicit indexed overflow boundary.",
             "profiles": ["parent"]} for index in range(101)]
        self.rejected_before_effects("101 cases; hard limit is 100")

    def test_indexed_input_size_limit_rejects_before_child(self):
        self.indexed()
        self.data["executions"][0]["cases"][0]["requirement"] = "x" * active.MAX_INPUT_BYTES
        self.rejected_before_effects("bounded regular non-symlink")

    def test_indexed_source_expansion_is_bounded_before_source_reads(self):
        self.indexed()
        long_path = "modules/ModSecurity-test-Framework/" + "a" * 32768 + ".py"
        self.data["source_bindings"].append({"path": long_path, "sha256": "a" * 64})
        row = self.data["executions"][0]
        row["sources"] = [0, 1, 2]
        self.data["executions"] = [copy.deepcopy(row) for _ in range(65)]
        self.data["offline_unit_exceptions"][0]["sources"] = [0, 1, 2]
        self.assertLess(len(json.dumps(self.data).encode("utf-8")), active.MAX_INPUT_BYTES)
        with patch.object(active, "read_source") as read:
            self.rejected_before_effects("expanded indexed source paths exceed the 2 MiB size limit")
        read.assert_not_called()

    def test_legacy_index_expansion_is_noop(self):
        original = copy.deepcopy(self.data)
        active._expand_indexed_sources(self.data, self.data["executions"])
        self.assertEqual(self.data, original)


class InventoryInputAuthorityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"])
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name)
        self.authority = self.workspace / "authority"
        self.authority.mkdir(mode=0o700)
        self.root = self.authority / "repository"
        self.root.mkdir(mode=0o700)
        self.framework = self.workspace / "framework"
        self.framework.mkdir(mode=0o700)
        source = self.root / "tests/authority_fixture.py"
        source.parent.mkdir(mode=0o700)
        source.write_text("import unittest\nclass Fixture(unittest.TestCase):\n"
                          "    def test_pass(self):\n        self.assertTrue(True)\n")
        self.data = {"schema_version": 1, "executions": [{
            "id": "fixture.authority", "groups": ["authority"],
            "sources": [{"path": "tests/authority_fixture.py",
                         "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}],
            "selector": {"kind": "python", "target": "tests.authority_fixture.Fixture.test_pass"},
            "cases": [{"id": "fixture.authority.case", "requirement": "Retain an approved fixture identity.",
                       "profiles": ["fixture"]}],
        }]}
        self.path = self.root / "inventory.json"
        self.path.write_text(json.dumps(self.data))
        self.path.chmod(0o600)

    def check(self, path, environment, extra=()):
        output, error = io.StringIO(), io.StringIO()
        with (patch.dict(os.environ, environment, clear=True),
              redirect_stdout(output), redirect_stderr(error)):
            status = active.main(["--check", "--inventory", str(path), *extra], root=self.root)
        return status, output.getvalue(), error.getvalue()

    def test_alternate_inventory_predeclared_authorities_preserve_identity(self):
        for name in ("RUNNER_TEMP", "TMP_ROOT", "CONNECTOR_TEST_OUTPUT_ROOT"):
            with self.subTest(authority=name):
                status, output, error = self.check(self.path, {name: str(self.authority)})
                self.assertEqual(status, 0, error)
                self.assertEqual(json.loads(output)["selected_case_ids"], ["fixture.authority.case"])

    def test_outside_inventory_rejects_before_any_content_open(self):
        outside = self.workspace / "outside.json"
        outside.write_text(json.dumps(self.data))
        for variant in ("outside-declared-root", "no-declaration", "tmpdir-only", "cli-output-root-only"):
            with self.subTest(variant=variant):
                environment = {"RUNNER_TEMP": str(self.authority)} if variant == "outside-declared-root" else {}
                if variant == "tmpdir-only":
                    environment["TMPDIR"] = str(self.workspace)
                extra = ("--output-root", str(self.workspace)) if variant == "cli-output-root-only" else ()
                with patch.object(active.os, "open", wraps=os.open) as opened:
                    status, output, error = self.check(outside, environment, extra)
                self.assertEqual(status, 2)
                self.assertEqual(output, "")
                self.assertNotIn("fixture.authority", error)
                self.assertIn("predeclared external", error)
                opened.assert_not_called()

    def test_inventory_symlink_roots_ancestors_and_leaf_are_rejected(self):
        for variant in ("authority-root", "intermediate", "leaf"):
            with self.subTest(variant=variant):
                alias = self.workspace / ("alias-" + variant)
                environment = {"RUNNER_TEMP": str(self.authority)}
                if variant == "authority-root":
                    alias.symlink_to(self.authority, target_is_directory=True)
                    environment["RUNNER_TEMP"] = str(alias)
                    selected = alias / "repository/inventory.json"
                elif variant == "intermediate":
                    alias = self.authority / "alias-repository"
                    alias.symlink_to(self.root, target_is_directory=True)
                    selected = alias / "inventory.json"
                else:
                    alias = self.authority / "alias-inventory.json"
                    alias.symlink_to(self.path)
                    selected = alias
                before = len(list(Path("/proc/self/fd").iterdir()))
                status, output, _error = self.check(selected, environment)
                self.assertEqual(status, 2)
                self.assertEqual(output, "")
                self.assertEqual(len(list(Path("/proc/self/fd").iterdir())), before)

    def test_inventory_untrusted_permission_modes_are_rejected(self):
        for variant in ("shared-authority", "shared-descendant", "writable-leaf"):
            with self.subTest(variant=variant):
                path = {"shared-authority": self.authority,
                        "shared-descendant": self.root, "writable-leaf": self.path}[variant]
                mode = path.stat().st_mode & 0o777
                try:
                    path.chmod(0o777 if path.is_dir() else 0o666)
                    status, output, _error = self.check(self.path, {"RUNNER_TEMP": str(self.authority)})
                    self.assertEqual(status, 2)
                    self.assertEqual(output, "")
                finally:
                    path.chmod(mode)

    def test_inventory_file_owner_is_required_before_json_parse(self):
        original = os.fstat
        def wrong_owner(descriptor):
            observed = original(descriptor)
            if stat.S_ISREG(observed.st_mode):
                fields = list(observed)
                fields[4] = os.geteuid() + 1
                return os.stat_result(fields)
            return observed
        with patch.object(active.os, "fstat", side_effect=wrong_owner):
            status, output, _error = self.check(self.path, {"RUNNER_TEMP": str(self.authority)})
        self.assertEqual(status, 2)
        self.assertEqual(output, "")

    def test_inventory_regular_file_and_byte_bounds_are_admitted_before_parse(self):
        for variant in ("directory", "fifo", "oversize", "growth-during-read"):
            with self.subTest(variant=variant):
                selected = self.authority / (variant + ".json")
                if variant == "directory":
                    selected.mkdir(mode=0o700)
                elif variant == "fifo":
                    os.mkfifo(selected, 0o600)
                elif variant == "oversize":
                    selected.write_bytes(b"x" * (active.MAX_INPUT_BYTES + 1))
                else:
                    selected.write_text(json.dumps(self.data))
                original = os.fstat
                def grow(descriptor, *, selected=selected, variant=variant, original=original):
                    observed = original(descriptor)
                    if variant == "growth-during-read" and stat.S_ISREG(observed.st_mode):
                        selected.write_bytes(b"x" * (active.MAX_INPUT_BYTES + 1))
                    return observed
                with patch.object(active.os, "fstat", side_effect=grow):
                    status, output, _error = self.check(selected, {"RUNNER_TEMP": str(self.authority)})
                self.assertEqual(status, 2)
                self.assertEqual(output, "")

    def test_inventory_descriptor_failure_paths_close_owned_descriptors(self):
        for variant in ("fdopen-constructor", "read-error", "directory-open"):
            with self.subTest(variant=variant):
                original_open, original_fdopen = os.open, os.fdopen
                class ReadFailure:
                    def __init__(self, stream):
                        self.stream = stream
                    def __enter__(self):
                        return self
                    def __exit__(self, *args):
                        self.stream.close()
                    def read(self, size):
                        raise OSError("private read failure")
                def selected_fdopen(*args, variant=variant, original_fdopen=original_fdopen, **kwargs):
                    if variant == "fdopen-constructor":
                        raise OSError("private constructor failure")
                    return ReadFailure(original_fdopen(*args, **kwargs))
                def selected_open(path, flags, *args, variant=variant, original_open=original_open, **kwargs):
                    if variant == "directory-open" and str(path) == "repository":
                        raise OSError("private directory failure")
                    return original_open(path, flags, *args, **kwargs)
                before = len(list(Path("/proc/self/fd").iterdir()))
                with (patch.object(active.os, "fdopen", side_effect=selected_fdopen),
                      patch.object(active.os, "open", side_effect=selected_open)):
                    status, output, _error = self.check(self.path, {"RUNNER_TEMP": str(self.authority)})
                self.assertEqual(status, 2)
                self.assertEqual(output, "")
                self.assertEqual(len(list(Path("/proc/self/fd").iterdir())), before)

    def test_inventory_authorities_cannot_be_inside_product_or_framework(self):
        for variant in ("product", "framework"):
            with self.subTest(variant=variant):
                authority = (self.root if variant == "product" else self.framework) / "declared"
                authority.mkdir(mode=0o700)
                selected = authority / "inventory.json"
                selected.write_text(json.dumps(self.data))
                with (patch.object(active, "_real_checkout", return_value=True),
                      patch.object(active, "test_root", return_value=self.framework),
                      patch.object(active, "source_path", return_value=self.root / active.INVENTORY_PATH),
                      patch.object(active.os, "open", wraps=os.open) as opened):
                    status, output, error = self.check(selected, {"RUNNER_TEMP": str(authority)})
                self.assertEqual(status, 2)
                self.assertEqual(output, "")
                self.assertIn("predeclared external", error)
                opened.assert_not_called()

    def test_alternate_inventory_inside_real_checkout_rejects_before_open(self):
        for variant in ("product", "framework", "product-alias", "framework-alias"):
            with self.subTest(variant=variant):
                checkout = self.root if variant.startswith("product") else self.framework
                selected = checkout / ("alternate-" + variant + ".json")
                selected.write_text(json.dumps(self.data))
                if variant.endswith("-alias"):
                    selected = Path("/" + str(selected))
                with (patch.object(active, "_real_checkout", return_value=True),
                      patch.object(active, "test_root", return_value=self.framework),
                      patch.object(active, "source_path", return_value=self.root / active.INVENTORY_PATH),
                      patch.object(active.os, "open", wraps=os.open) as opened):
                    status, output, error = self.check(selected, {"RUNNER_TEMP": str(self.workspace)})
                self.assertEqual(status, 2)
                self.assertEqual(output, "")
                self.assertIn("outside Product and Framework checkouts", error)
                self.assertNotIn("fixture.authority", error)
                opened.assert_not_called()

    def test_inventory_double_slash_checkout_alias_rejects_before_open(self):
        for variant in ("product", "framework"):
            with self.subTest(checkout=variant):
                checkout = self.root if variant == "product" else self.framework
                authority = checkout / "double-slash-inventory"
                authority.mkdir(mode=0o700)
                selected = authority / "inventory.json"
                selected.write_text(json.dumps(self.data))
                alias = Path("/" + str(authority))
                with (patch.object(active, "_real_checkout", return_value=True),
                      patch.object(active, "test_root", return_value=self.framework),
                      patch.object(active, "source_path", return_value=self.root / active.INVENTORY_PATH),
                      patch.object(active.os, "open", wraps=os.open) as opened):
                    status, output, error = self.check(alias / selected.name, {"RUNNER_TEMP": str(alias)})
                self.assertEqual(status, 2)
                self.assertEqual(output, "")
                self.assertIn("predeclared external", error)
                opened.assert_not_called()

    def test_inventory_double_slash_external_alias_preserves_identity(self):
        for variant in ("authority", "inventory", "both"):
            with self.subTest(alias=variant):
                authority = Path("/" + str(self.authority)) if variant != "inventory" else self.authority
                selected = Path("/" + str(self.path)) if variant != "authority" else self.path
                status, output, error = self.check(selected, {"RUNNER_TEMP": str(authority)})
                self.assertEqual(status, 0, error)
                self.assertEqual(json.loads(output)["selected_case_ids"], ["fixture.authority.case"])

    def test_output_double_slash_checkout_alias_rejects_before_filesystem_effect(self):
        for variant in ("product", "framework"):
            with self.subTest(checkout=variant):
                checkout = self.root if variant == "product" else self.framework
                selected = checkout / "double-slash-output"
                selected.mkdir(mode=0o700)
                alias = Path("/" + str(selected))
                with (patch.object(active, "_real_checkout", return_value=True),
                      patch.object(active, "test_root", return_value=self.framework),
                      patch.object(active, "_validate_output_ancestry", wraps=active._validate_output_ancestry) as ancestry,
                      patch.object(active.tempfile, "mkdtemp", wraps=tempfile.mkdtemp) as allocated,
                      patch.object(active.os, "open", wraps=os.open) as opened,
                      self.assertRaises(active.InventoryError)):
                    active._output_directory(self.root, alias)
                ancestry.assert_not_called()
                allocated.assert_not_called()
                opened.assert_not_called()
                self.assertEqual(list(selected.iterdir()), [])

    def test_output_double_slash_external_alias_preserves_admission(self):
        for variant in ("ordinary", "double-slash"):
            with self.subTest(alias=variant):
                selected = self.authority if variant == "ordinary" else Path("/" + str(self.authority))
                admitted = active.validate_output_root(self.root, selected)
                self.assertEqual(admitted, self.authority)

    def test_relative_fixture_path_keeps_existing_cli_semantics(self):
        with chdir(self.authority):
            status, output, error = self.check(Path("repository/inventory.json"),
                                               {"RUNNER_TEMP": str(self.authority)})
        self.assertEqual(status, 0, error)
        self.assertEqual(json.loads(output)["selected_case_ids"], ["fixture.authority.case"])

    def test_root_owned_canonical_inventory_retains_unprivileged_reader_policy(self):
        canonical = self.root / active.INVENTORY_PATH
        canonical.parent.mkdir(parents=True, mode=0o700)
        canonical.write_text(json.dumps(self.data))
        original = os.fstat
        def root_owned_policy(descriptor):
            observed = original(descriptor)
            fields = list(observed)
            fields[4] = 0
            fields[0] = (observed.st_mode & ~0o777) | (0o755 if stat.S_ISDIR(observed.st_mode) else 0o644)
            return os.stat_result(fields)
        with (patch.object(active.os, "geteuid", return_value=1001),
              patch.object(active.os, "fstat", side_effect=root_owned_policy)):
            status, output, error = self.check(canonical, {})
        self.assertEqual(status, 0, error)
        self.assertEqual(json.loads(output)["selected_case_ids"], ["fixture.authority.case"])

    def test_canonical_inventory_remains_environment_independent(self):
        canonical = self.root / active.INVENTORY_PATH
        canonical.parent.mkdir(parents=True, mode=0o700)
        canonical.write_text(json.dumps(self.data))
        status, output, error = self.check(canonical, {})
        self.assertEqual(status, 0, error)
        self.assertEqual(json.loads(output)["selected_case_ids"], ["fixture.authority.case"])


def _inventory_owner_metadata(observed, owner, permissions=None):
    fields = list(observed)
    fields[4] = owner
    if permissions is not None:
        fields[0] = (observed.st_mode & ~0o777) | permissions
    return os.stat_result(fields)


class InventoryCanonicalOwnerTests(unittest.TestCase):
    setUp = InventoryInputAuthorityTests.setUp

    def _canonical_fixture(self, *, real=True):
        selected = self.framework if real else self.root
        path = selected / active.INVENTORY_PATH
        path.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
        path.write_text(json.dumps(self.data))
        return selected, path

    @contextmanager
    def _selected_context(self, selected, canonical, *, real=True):
        with (patch.object(active, "_real_checkout", return_value=real),
              patch.object(active, "test_root", return_value=selected),
              patch.object(active, "source_path", return_value=canonical)):
            yield

    @contextmanager
    def _owner_policy(self, selected, *, reader=0, checkout_owner=1001,
                      overrides=None, permissions=None, runner_ancestry=True):
        # Owner-policy model only: held real descriptors and private real bytes
        # remain in use; no actual UID/ownership transition is represented.
        overrides, permissions = overrides or {}, permissions or {}
        original_fstat, original_lstat = os.fstat, Path.lstat

        def descriptor_metadata(descriptor):
            observed = original_fstat(descriptor)
            physical = Path(os.readlink("/proc/self/fd/" + str(descriptor)))
            owner = observed.st_uid
            if physical == selected or selected in physical.parents:
                owner = checkout_owner
            if runner_ancestry and (physical == self.workspace or self.workspace in physical.parents):
                owner = checkout_owner
            return _inventory_owner_metadata(observed, overrides.get(physical, owner), permissions.get(physical))

        def selected_metadata(path, *args, **kwargs):
            observed = original_lstat(path, *args, **kwargs)
            if path == selected:
                return _inventory_owner_metadata(observed, checkout_owner, permissions.get(path))
            return observed

        with (patch.object(active.os, "geteuid", return_value=reader),
              patch.object(active.os, "fstat", side_effect=descriptor_metadata),
              patch.object(Path, "lstat", selected_metadata)):
            yield

    def _assert_owner_denial_before_buffer_read(self, path):
        with (patch.object(active.os, "fdopen", wraps=os.fdopen) as buffered,
              self.assertRaises(active.InventoryError)):
            active._read_inventory(path, root=self.root)
        buffered.assert_not_called()

    def test_canonical_checkout_owner_preserves_selected_reader_roles(self):
        for variant, reader, owner, real in (
            ("root-framework-runner", 0, 1001, True),
            ("root-synthetic-runner", 0, 1001, False),
            ("runner-own-checkout", 1001, 1001, True),
            ("runner-root-checkout", 1001, 0, True),
        ):
            with self.subTest(variant=variant):
                selected, path = self._canonical_fixture(real=real)
                with (self._selected_context(selected, path, real=real),
                      self._owner_policy(selected, reader=reader, checkout_owner=owner)):
                    value, digest = active._read_inventory(path, root=self.root)
                self.assertEqual(value, self.data)
                self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_canonical_checkout_owner_rejects_mismatched_held_owners(self):
        selected, path = self._canonical_fixture()
        for variant, target in (
            ("third-uid-ancestor", self.workspace),
            ("third-uid-descendant", selected / "config"),
            ("third-uid-leaf", path),
            ("selected-root-owner-replaced", selected),
        ):
            with (self.subTest(variant=variant),
                  self._selected_context(selected, path),
                  self._owner_policy(selected, overrides={target: 1002})):
                self._assert_owner_denial_before_buffer_read(path)

    def test_canonical_checkout_owner_rejects_unsafe_roots_and_modes(self):
        selected, path = self._canonical_fixture()
        alias = self.workspace / "framework-alias"
        alias.symlink_to(selected, target_is_directory=True)
        for variant, target, mode in (
            ("selected-group-writable", selected, 0o775),
            ("selected-other-writable", selected, 0o757),
            ("selected-symlink", alias, None),
            ("shared-ancestor", self.workspace, 0o775),
            ("shared-leaf", path, 0o666),
        ):
            with self.subTest(variant=variant):
                chosen = alias if variant == "selected-symlink" else selected
                canonical = chosen / active.INVENTORY_PATH
                modes = {} if mode is None else {target: mode}
                with (self._selected_context(chosen, canonical),
                      self._owner_policy(chosen, permissions=modes)):
                    self._assert_owner_denial_before_buffer_read(canonical)

    def test_alternate_inventory_cannot_inherit_selected_checkout_owner(self):
        selected, canonical = self._canonical_fixture()
        authority = self.workspace / "external-alternate"
        authority.mkdir(mode=0o700)
        path = authority / "inventory.json"
        path.write_text(json.dumps(self.data))
        for variant, target in (
            ("foreign-ancestor", self.workspace),
            ("foreign-authority", authority),
            ("foreign-leaf", path),
        ):
            with (self.subTest(variant=variant),
                  patch.dict(os.environ, {"RUNNER_TEMP": str(authority)}, clear=True),
                  self._selected_context(selected, canonical),
                  self._owner_policy(selected, overrides={target: 1001}, runner_ancestry=False)):
                self._assert_owner_denial_before_buffer_read(path)


# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
