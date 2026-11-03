"""Coverage provenance fails closed before an incomplete report can be imported."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

from contextlib import redirect_stderr
import importlib.util
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = connector_root()
COVERAGE = load_source(source_path('ci/checks/analysis/run-sonar-coverage.py', root=ROOT))


class SonarCoverageTests(unittest.TestCase):
    def write_report(self, directory: str, *, filename: str, hits: str = "1") -> Path:
        report = Path(directory) / "coverage.xml"
        report.write_text(
            f'<coverage><sources><source>.</source></sources><packages><package><classes>'
            f'<class filename="{filename}"><lines><line number="1" hits="{hits}"/></lines>'
            '</class></classes></package></packages></coverage>', encoding="utf-8",
        )
        return report

    def test_accepts_a_measured_repository_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = self.write_report(directory, filename="ci/tools/read-framework-revisions.py")
            self.assertEqual(COVERAGE.validate_python_report(report), 1)

    def test_migrated_framework_source_is_not_parent_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = self.write_report(directory, filename="ci/checks/analysis/check-sonar-scope.py")
            with self.assertRaisesRegex(ValueError, "not a repository file"):
                COVERAGE.validate_python_report(report)

    def test_rejects_external_paths_even_with_execution_counts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = self.write_report(directory, filename="../outside.py")
            with self.assertRaisesRegex(ValueError, "not a repository file"):
                COVERAGE.validate_python_report(report)

    def test_rejects_a_report_without_actual_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = self.write_report(directory, filename="ci/tools/read-framework-revisions.py", hits="0")
            with self.assertRaisesRegex(ValueError, "no measured execution"):
                COVERAGE.validate_python_report(report)

    def test_rejects_stale_report_directory_before_starting_tests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "python").mkdir()
            stale = Path(directory) / "python/python.xml"
            stale.write_text("old revision\n", encoding="utf-8")
            arguments = ["coverage", "--language", "python", "--output-root", directory,
                         "--temp-root", directory, "--on-demand"]
            with (mock.patch("sys.argv", arguments), mock.patch.object(COVERAGE, "run") as run,
                  redirect_stderr(io.StringIO())):
                self.assertEqual(COVERAGE.main(), 1)
            run.assert_not_called()
            self.assertEqual(stale.read_text(encoding="utf-8"), "old revision\n")

    def test_specialist_collection_requires_explicit_on_demand_before_effects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "not-created"
            arguments = ["coverage", "--language", "python", "--output-root", str(output),
                         "--temp-root", directory]
            with (mock.patch("sys.argv", arguments), mock.patch.object(COVERAGE, "run") as run,
                  redirect_stderr(io.StringIO()) as error):
                self.assertEqual(COVERAGE.main(), 1)
            self.assertIn("explicit --on-demand", error.getvalue())
            run.assert_not_called()
            self.assertFalse(output.exists())

    def test_native_notes_without_execution_counters_are_not_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            build = output / "build/common-helper-smoke"
            build.mkdir(parents=True)
            (build / "stale.gcno").write_bytes(b"compile notes without execution")
            with mock.patch.object(COVERAGE, "run"):
                with self.assertRaisesRegex(ValueError, "no execution counters"):
                    COVERAGE.native_coverage(output, {})

    def test_go_coverage_supplies_reviewed_overlay_to_listing_and_measurement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            overlay = output / "module-tests/active-tests-fixture/go-overlay.json"
            calls = []
            def run(command, **keywords):
                calls.append((command, keywords))
                if "--emit-go-overlay" in command:
                    return str(overlay) + "\n"
                if "-list" in command:
                    return "TestExistingSelector\n"
                for argument in command:
                    if argument.startswith("-coverprofile="):
                        Path(argument.split("=", 1)[1]).write_text("mode: set\nmodule/source.go:1.1,2.1 1 1\n")
                return ""
            with (mock.patch.dict(COVERAGE.GO_TESTS, {"module": ("connectors/envoy/ext_proc", ("TestExistingSelector",))}, clear=True),
                  mock.patch.object(COVERAGE, "run", side_effect=run)):
                result = COVERAGE.go_coverage(output, {})
            go_calls = [command for command, _ in calls if command[:2] == ["go", "test"]]
            self.assertEqual(len(go_calls), 2)
            for command in go_calls:
                self.assertIn(f"-overlay={overlay}", command)
                self.assertIn("^(TestExistingSelector)$", command)
            self.assertEqual(result["module"]["test_sources"], str(overlay.parent / "go-overlay-sources.json"))
            self.assertIn("--on-demand", calls[0][0])
            self.assertEqual(calls[0][1]["env"]["ON_DEMAND_TESTS"], "1")

    def offline_fixture(self, *, timing: bool = False) -> dict:
        return {"id": "offline.fixture", "selector": {"kind": "python", "target": "tests.fixture.Case.test_unit"},
                "groups": ["offline-unit", "offline-timing"] if timing else ["offline-unit"]}

    def test_offline_admission_retains_units_without_discovering_other_specialists(self) -> None:
        inventory = SimpleNamespace(offline_case_ids=("unit.case", "new.runtime.case"))
        module = mock.Mock()
        module.load_inventory.return_value = inventory
        module.select_executions.return_value = (self.offline_fixture(),)
        with mock.patch.object(COVERAGE, "load_tool", return_value=module):
            actual, selected = COVERAGE.admitted_offline_inventory()
        self.assertIs(actual, inventory)
        self.assertEqual(selected, (self.offline_fixture(),))
        module.select_executions.assert_called_once_with(
            inventory, groups=("offline-unit",), on_demand=True)

    def test_normal_offline_python_stays_in_measured_partition(self) -> None:
        execution = self.offline_fixture()
        measured, timing = COVERAGE.offline_partitions((execution,))
        self.assertEqual(measured, (execution,))
        self.assertEqual(timing, ())

    def test_timing_offline_python_stays_in_unmeasured_partition(self) -> None:
        execution = self.offline_fixture(timing=True)
        measured, timing = COVERAGE.offline_partitions((execution,))
        self.assertEqual(measured, ())
        self.assertEqual(timing, (execution,))

    def test_offline_measurement_rejects_native_selection(self) -> None:
        execution = self.offline_fixture()
        execution["selector"] = {"kind": "native", "script": "ci/native.sh", "args": []}
        with self.assertRaisesRegex(ValueError, "Python units only"):
            COVERAGE.offline_partitions((execution,))

    def test_timing_command_has_no_inherited_coverage_startup_or_discovery_optin(self) -> None:
        selected = (self.offline_fixture(timing=True),)
        environment = {"COVERAGE_PROCESS_START": "config", "COVERAGE_PROCESS_CONFIG": "serialized",
                       "COVERAGE_FILE": "parent.data", "ON_DEMAND_TESTS": "1", "PATH": "preserved"}
        command, actual = COVERAGE.offline_command(selected, Path("/external/unit-output"),
                                                  environment, measured=False)
        self.assertEqual(command[1], str(source_path("ci/tools/run-active-tests.py", root=ROOT)))
        self.assertIn("--strict-skips", command)
        self.assertEqual(command[-2:], ["--execution", "offline.fixture"])
        self.assertEqual(actual, {"PATH": "preserved"})
        self.assertEqual(environment["ON_DEMAND_TESTS"], "1")

    def test_measured_command_uses_master_rcfile_and_exact_inventory_selector(self) -> None:
        selected = (self.offline_fixture(),)
        command, environment = COVERAGE.offline_command(
            selected, Path("/external/unit-output"), {"ON_DEMAND_TESTS": "1"}, measured=True)
        self.assertEqual(command[1:4], ["-m", "coverage", "run"])
        self.assertIn(f"--rcfile={COVERAGE.RCFILE}", command)
        self.assertIn("--parallel-mode", command)
        self.assertIn(str(source_path("ci/tools/run-active-tests.py", root=ROOT)), command)
        self.assertEqual(command[-2:], ["--execution", "offline.fixture"])
        self.assertNotIn("ON_DEMAND_TESTS", environment)

    def test_subprocess_audit_rejects_data_that_only_imported_the_parent_module(self) -> None:
        data = mock.Mock()
        data.has_arcs.return_value = True
        data.measured_files.return_value = {"ci/lib/active_test_inventory.py"}
        data.lines.return_value = []
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "python.data.parent"
            path.write_bytes(b"unit metadata fixture; no real coverage claim")
            with mock.patch.object(COVERAGE, "read_python_coverage_data", return_value=data):
                with self.assertRaisesRegex(ValueError, "0 measured children; expected 1"):
                    COVERAGE.child_coverage_witnesses({path}, 1)

    def test_subprocess_audit_accepts_a_distinct_file_with_actual_child_body_observation(self) -> None:
        data = mock.Mock()
        data.has_arcs.return_value = True
        data.measured_files.return_value = {"ci/lib/active_test_inventory.py"}
        data.lines.return_value = [COVERAGE.python_child_witness_line()]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "python.data.child"
            path.write_bytes(b"unit metadata fixture; no real coverage claim")
            with mock.patch.object(COVERAGE, "read_python_coverage_data", return_value=data) as read:
                self.assertEqual(COVERAGE.child_coverage_witnesses({path}, 1), [path.name])
        read.assert_called_once_with(path)

    def test_child_witness_ignores_unrelated_framework_sources(self) -> None:
        data = mock.Mock()
        data.has_arcs.return_value = True
        data.measured_files.return_value = {
            str(test_root() / "modsecurity_test_framework/connector_context.py"),
            str(source_path(COVERAGE.ACTIVE_INVENTORY_SOURCE, root=ROOT)),
        }
        data.lines.return_value = [COVERAGE.python_child_witness_line()]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "python.data.child"
            path.write_bytes(b"unit metadata fixture; no real coverage claim")
            with mock.patch.object(COVERAGE, "read_python_coverage_data", return_value=data):
                self.assertTrue(COVERAGE.child_file_has_witness(path, COVERAGE.python_child_witness_line()))

    def test_child_witness_copy_survives_raw_combine_cleanup_with_exact_bytes(self) -> None:
        body = b"synthetic retention fixture; not measured coverage\x00\xff"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            source = output / "python.data.child"
            source.write_bytes(body)
            records = COVERAGE.retain_child_coverage(output, [source.name])
            source.unlink()  # Model reporting's automatic deletion of raw inputs.
            retained = output / records[0]["path"]
            self.assertEqual(retained.read_bytes(), body)
            self.assertEqual(records, [{"path": "child-witness/python.data.child",
                                       "sha256": hashlib.sha256(body).hexdigest(), "size_bytes": len(body)}])
            self.assertEqual(retained.stat().st_mode & 0o777, 0o600)
            self.assertEqual(retained.parent.stat().st_mode & 0o777, 0o700)

    def test_child_witness_retention_rejects_a_symlink_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            target = output / "unrelated"
            target.write_bytes(b"must not be copied")
            source = output / "python.data.child"
            source.symlink_to(target)
            with self.assertRaises(OSError):
                COVERAGE.retain_child_coverage(output, [source.name])
            self.assertEqual(list((output / "child-witness").iterdir()), [])

    def test_timing_stage_rejects_unexpected_parallel_coverage_data(self) -> None:
        execution = self.offline_fixture(timing=True)
        inventory = SimpleNamespace(digest="a" * 64)
        with (mock.patch.object(COVERAGE, "admitted_offline_inventory", return_value=(inventory, (execution,))),
              mock.patch.object(COVERAGE, "run_offline_partition", return_value={}) as runner,
              mock.patch.object(COVERAGE, "parallel_python_files",
                                side_effect=[set(), {Path("python.data.unexpected")}])):
            with self.assertRaisesRegex(ValueError, "timing cases unexpectedly produced coverage data"):
                COVERAGE.offline_python_coverage(Path("/external/output"), {})
        runner.assert_called_once()
        self.assertFalse(runner.call_args.kwargs["measured"])

    def test_offline_summary_cannot_claim_another_admitted_case(self) -> None:
        selected = self.offline_fixture()
        selected["cases"] = [{"id": "offline.fixture.case"}]
        inventory = SimpleNamespace(digest="a" * 64)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "offline"
            def write_wrong_summary(*_arguments, **_keywords):
                leaf = output / "active-tests-fixture"
                leaf.mkdir()
                (leaf / "summary.json").write_text(json.dumps({
                    "inventory_sha256": inventory.digest,
                    "selected_execution_ids": ["offline.fixture"],
                    "selected_case_ids": ["unadmitted.case"], "selected_core_case_ids": [],
                    "results": [{"execution_id": "offline.fixture", "status": "passed"}],
                }), encoding="utf-8")
            with mock.patch.object(COVERAGE, "run", side_effect=write_wrong_summary) as runner:
                with self.assertRaisesRegex(ValueError, "differs from the admitted Python exceptions"):
                    COVERAGE.run_offline_partition(inventory, (selected,), output, {}, measured=True)
            runner.assert_called_once()

    def test_finalization_retains_completed_offline_measurement_evidence(self) -> None:
        offline = {"inventory_sha256": "c" * 64, "measured": {"execution_ids": ["offline.fixture"]},
                   "unmeasured_timing": None, "child_data_files": ["python.data.child"]}
        framework = {"revision": "b" * 40, "uncommitted_changes": False}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for language in ("python", "go", "native"):
                (root / language).mkdir()
                record = {"revision": "a" * 40, "uncommitted_changes": False,
                          "framework": framework,
                          "coverage": {"offline_python": offline} if language == "python" else {}}
                (root / language / "manifest.json").write_text(json.dumps(record), encoding="utf-8")
            with (mock.patch.object(COVERAGE, "publish_python_report", return_value={"report": "python.xml"}),
                  mock.patch.object(COVERAGE, "framework_source_state", return_value=framework)):
                result = COVERAGE.finalize_python(root, {}, "a" * 40)
        self.assertEqual(result["offline_python"], offline)

    def test_finalization_rejects_other_revision_before_combining_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for language in ("python", "go", "native"):
                (root / language).mkdir()
                (root / language / "manifest.json").write_text(
                    json.dumps({"revision": "a" * 40, "uncommitted_changes": False}),
                    encoding="utf-8",
                )
            with mock.patch.object(COVERAGE, "publish_python_report") as publish:
                with self.assertRaisesRegex(ValueError, "revision does not match"):
                    COVERAGE.finalize_python(root, {}, "b" * 40)
            publish.assert_not_called()

    def test_finalization_rejects_other_or_unbound_framework_before_combining(self) -> None:
        current = {"revision": "b" * 40, "uncommitted_changes": False}
        for recorded in (None, {"revision": "c" * 40, "uncommitted_changes": False},
                         {"revision": "b" * 40, "uncommitted_changes": True}):
            with self.subTest(recorded=recorded), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for language in ("python", "go", "native"):
                    (root / language).mkdir()
                    record = {"revision": "a" * 40, "uncommitted_changes": False,
                              "framework": recorded}
                    (root / language / "manifest.json").write_text(json.dumps(record), encoding="utf-8")
                with (mock.patch.object(COVERAGE, "framework_source_state", return_value=current),
                      mock.patch.object(COVERAGE, "publish_python_report") as publish):
                    with self.assertRaisesRegex(ValueError, "Framework"):
                        COVERAGE.finalize_python(root, {}, "a" * 40)
                publish.assert_not_called()


# Parent discovery remains inventory-bound; only an explicit selected Master
# assessment may opt into the complete module without importing helpers eagerly.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
