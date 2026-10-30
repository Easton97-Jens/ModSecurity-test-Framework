"""Static contracts for retained heavy-smoke runtime evidence."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

from pathlib import Path
import importlib.util
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = connector_root()
WORKFLOW = source_path('.github/workflows/test-full-smoke-sequential.yml', root=ROOT)
REPORT_ROOT = source_path('ci/evidence/reports', root=ROOT)

REPORTS = load_source(REPORT_ROOT / 'refresh-connector-reports.py')


class FullSmokeWorkflowContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.native_expected = REPORTS.bounded_smoke_expected_cases(
            ROOT, source_path('modules/ModSecurity-test-Framework', root=ROOT), dict(os.environ), "no-crs"
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="bounded-smoke-contract-")
        self.addCleanup(self.temporary.cleanup)
        self.build = Path(self.temporary.name)
        self.framework = source_path('modules/ModSecurity-test-Framework', root=ROOT)
        self.environment = {"VERIFIED_RUN_ID": "bounded-smoke-unit-test"}
        self.git = mock.patch.object(REPORTS, "git_sha", side_effect=lambda path: "a" * 40 if path == ROOT else "b" * 40)
        self.git.start()
        self.addCleanup(self.git.stop)
        self.pins = mock.patch.object(REPORTS, "verify_framework_revision_pins", return_value={"framework_sha": "b" * 40})
        self.pins.start()
        self.addCleanup(self.pins.stop)
        self.expected = self.native_expected
        self.discovery = mock.patch.object(REPORTS, "bounded_smoke_expected_cases", return_value=self.expected)
        self.discovery.start()
        self.addCleanup(self.discovery.stop)
        self.first_case = self.expected["apache"][0]
        self.snapshot_path = mock.patch.object(REPORTS, "bounded_smoke_snapshot_path", side_effect=lambda _: self.build / "snapshot.json")
        self.snapshot_path.start()
        self.addCleanup(self.snapshot_path.stop)

    def begin_and_write_results(self) -> None:
        REPORTS.begin_bounded_smoke(ROOT, self.framework, self.build, "no-crs", self.environment)
        for connector in ("apache", "nginx"):
            (self.build / "results" / f"{connector}.rc").write_text("0\n")
            (self.build / "results" / f"{connector}-summary.json").write_text(json.dumps({connector: {
                "cases": {name: {"status": "pass", "live_executed": True, "variant": "no-crs", "executed_connector": connector} for name in self.expected[connector]},
                "summary": {"pass": len(self.expected[connector]), "fail": 0, "blocked": 0, "not_executable": 0, "skipped": 0},
            }}))

    def validate(self, environment=None, variant="no-crs"):
        return REPORTS.validate_bounded_smoke_inputs(
            ROOT, self.framework, self.build, variant,
            environment if environment is not None else self.environment,
        )

    def test_fresh_same_identity_results_are_accepted_and_bound_by_hash(self) -> None:
        self.begin_and_write_results()
        receipt = self.validate()
        self.assertEqual(receipt["parent_sha"], "a" * 40)
        self.assertEqual(receipt["framework_sha"], "b" * 40)
        self.assertEqual(len(receipt["input_sha256"]), 4)
        with self.assertRaises(FileExistsError):
            REPORTS.begin_bounded_smoke(ROOT, self.framework, self.build, "no-crs", self.environment)

    def test_identity_variant_and_revision_mismatches_are_rejected(self) -> None:
        self.begin_and_write_results()
        for environment, variant in (({"VERIFIED_RUN_ID": "another-run"}, "no-crs"),
                                     (self.environment, "with-crs")):
            with self.subTest(environment=environment, variant=variant), self.assertRaisesRegex(ValueError, "identity"):
                self.validate(environment, variant)
        with mock.patch.object(REPORTS, "git_sha", return_value="c" * 40), self.assertRaisesRegex(ValueError, "identity"):
            self.validate()

    def test_native_discovery_uses_explicit_variant_and_ignores_inherited_scope_flags(self) -> None:
        self.discovery.stop()
        narrowed = {**os.environ, "MODSECURITY_TEST_VARIANT": "no-crs", "NO_CRS_BASELINE": "1",
                    "FORCE_ALL_CASES": "1", "SMOKE_CASES": "one-case", "TEST_CASE": "one-case"}
        no_crs = REPORTS.bounded_smoke_expected_cases(ROOT, self.framework, narrowed, "no-crs")
        with_crs = REPORTS.bounded_smoke_expected_cases(ROOT, self.framework, narrowed, "with-crs")
        self.assertEqual(no_crs, self.native_expected)
        for connector in ("apache", "nginx"):
            self.assertGreater(len(with_crs[connector]), len(no_crs[connector]))

    def test_native_discovery_clears_force_all_and_baseline_flags_and_has_timeout(self) -> None:
        self.discovery.stop()
        with mock.patch.object(REPORTS.subprocess, "run", return_value=mock.Mock(
                returncode=0, stdout=json.dumps(self.native_expected))) as process:
            REPORTS.bounded_smoke_expected_cases(ROOT, self.framework,
                {"FORCE_ALL_CASES": "1", "NO_CRS_BASELINE": "1"}, "with-crs")
        self.assertEqual(process.call_args.kwargs["env"]["FORCE_ALL_CASES"], "")
        self.assertEqual(process.call_args.kwargs["env"]["NO_CRS_BASELINE"], "")
        self.assertEqual(process.call_args.kwargs["env"]["MODSECURITY_TEST_VARIANT"], "with-crs")
        self.assertEqual(process.call_args.kwargs["timeout"], 30)

    def test_snapshot_command_labels_are_closed_literals_and_invalid_variant_never_executes(self) -> None:
        self.assertEqual(REPORTS.bounded_smoke_command_label("no-crs"), "make test-smoke-sequential-no-crs")
        self.assertEqual(REPORTS.bounded_smoke_command_label("with-crs"), "make test-smoke-sequential-with-crs")
        for variant in (None, "", "no-crs; arbitrary", "with-crs --extra"):
            with (self.subTest(variant=variant), mock.patch.object(REPORTS, "run_command") as execute,
                  self.assertRaisesRegex(ValueError, "explicit supported variant")):
                REPORTS.refresh_bounded_smoke(ROOT, self.framework, self.build, variant, self.environment, [])
            execute.assert_not_called()

    def test_bounded_cli_rejects_other_parent_root_before_any_writer(self) -> None:
        arguments = mock.Mock(profile="bounded-smoke", connector_root=str(self.build),
                              framework_root=None, render_index_only=False)
        with (mock.patch.object(REPORTS, "refresh_arguments", return_value=arguments),
              mock.patch.object(REPORTS, "refresh_roots") as roots,
              mock.patch.object(REPORTS, "begin_bounded_smoke") as begin):
            self.assertEqual(REPORTS.main(), 2)
        roots.assert_not_called()
        begin.assert_not_called()

    def test_fixed_framework_path_and_central_revision_validation_are_mandatory(self) -> None:
        with self.assertRaisesRegex(ValueError, "fixed Parent"):
            REPORTS.begin_bounded_smoke(ROOT, self.framework.parent, self.build, "no-crs", self.environment)
        self.begin_and_write_results()
        with mock.patch.object(REPORTS, "verify_framework_revision_pins", side_effect=ValueError("gitlink mismatch")):
            with self.assertRaisesRegex(ValueError, "gitlink mismatch"):
                self.validate()
        with mock.patch.object(REPORTS, "verify_framework_revision_pins", return_value={"framework_sha": "c" * 40}):
            with self.assertRaisesRegex(ValueError, "identity"):
                self.validate()

    def write_snapshot(self, *_arguments):
        (self.build / "snapshot.json").write_text(json.dumps({"commit": "a" * 7,
            "build_root": str(self.build), "runtime_smokes": [{"connector": connector,
            "summary_path": str(self.build / "results" / f"{connector}-summary.json")}
            for connector in ("apache", "nginx")]}))
        os.utime(self.build / "snapshot.json", ns=(time.time_ns(), time.time_ns()))
        return 0, "", {}

    def test_wrong_or_mixed_row_variants_and_wrong_connector_are_rejected(self) -> None:
        self.begin_and_write_results()
        path = self.build / "results/apache-summary.json"
        original = path.read_text()
        for field, value in (("variant", "with-crs"), ("executed_connector", "nginx")):
            payload = json.loads(original)
            payload["apache"]["cases"][self.first_case][field] = value
            path.write_text(json.dumps(payload))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "variant or executed connector"):
                self.validate()

    def test_no_write_stale_and_wrong_identity_snapshots_are_rejected(self) -> None:
        self.begin_and_write_results()
        for mode in ("missing", "stale", "wrong_commit", "wrong_build", "wrong_summary"):
            def snapshot(*args):
                path = self.build / "snapshot.json"
                if mode == "missing":
                    path.unlink(missing_ok=True)
                    return 0, "", {}
                result = self.write_snapshot(*args)
                payload = json.loads(path.read_text())
                if mode == "wrong_commit":
                    payload["commit"] = "c" * 7
                elif mode == "wrong_build":
                    payload["build_root"] = "another-run"
                elif mode == "wrong_summary":
                    payload["runtime_smokes"][0]["summary_path"] = "historical.json"
                path.write_text(json.dumps(payload))
                if mode == "stale":
                    os.utime(path, ns=(1, 1))
                return result
            with (mock.patch.object(REPORTS, "run_command", side_effect=snapshot),
                  mock.patch.object(REPORTS, "run_spec") as generator,
                  self.subTest(mode=mode), self.assertRaises((ValueError, FileNotFoundError))):
                REPORTS.refresh_bounded_smoke(ROOT, self.framework, self.build, "no-crs", self.environment, [])
            generator.assert_not_called()

    def test_exact_native_case_ids_reject_missing_extra_and_changed_catalog(self) -> None:
        self.begin_and_write_results()
        path = self.build / "results/apache-summary.json"
        original = path.read_text()
        for extra in (False, True):
            payload = json.loads(original)
            cases = payload["apache"]["cases"]
            if extra:
                cases["invented_case"] = {"status": "pass", "live_executed": True}
            else:
                cases.pop(self.first_case)
            payload["apache"]["summary"]["pass"] = len(cases)
            path.write_text(json.dumps(payload))
            with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, "case IDs"):
                self.validate()
        path.write_text(original)
        with mock.patch.object(REPORTS, "bounded_smoke_expected_cases", return_value={"apache": ["different"], "nginx": ["different"]}):
            with self.assertRaisesRegex(ValueError, "selection changed"):
                self.validate()

    def test_missing_stale_symlink_and_failed_producer_inputs_are_rejected(self) -> None:
        self.begin_and_write_results()
        summary = self.build / "results/apache-summary.json"
        original = summary.read_text()
        summary.unlink()
        with self.assertRaises(FileNotFoundError):
            self.validate()
        summary.write_text(original)
        os.utime(summary, ns=(1, 1))
        with self.assertRaisesRegex(ValueError, "stale"):
            self.validate()
        summary.unlink()
        summary.symlink_to(self.build / "results/nginx-summary.json")
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.validate()
        summary.unlink()
        summary.write_text(original)
        for code in ("1", "77", "not_run"):
            (self.build / "results/apache.rc").write_text(code)
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, "did not succeed"):
                self.validate()

    def test_case_failure_unknown_blocked_and_non_live_results_cannot_pass(self) -> None:
        self.begin_and_write_results()
        path = self.build / "results/apache-summary.json"
        payload = json.loads(path.read_text())
        for status in ("fail", "blocked", "unknown", "not_executable", "skipped"):
            payload["apache"]["cases"][self.first_case]["status"] = status
            path.write_text(json.dumps(payload))
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, "successful live"):
                self.validate()
        payload["apache"]["cases"][self.first_case].update(status="pass", live_executed=False)
        path.write_text(json.dumps(payload))
        with self.assertRaisesRegex(ValueError, "successful live"):
            self.validate()

    def test_bounded_catalog_and_report_status_require_all_current_outputs(self) -> None:
        catalog = REPORTS.make_catalog(ROOT, self.framework, self.build, self.build / "native", sys.executable)
        selected = REPORTS.bounded_smoke_catalog(catalog)
        self.assertEqual({spec.name for spec in selected}, REPORTS.BOUNDED_SMOKE_REPORTS)
        self.assertTrue(all(not spec.optional for spec in selected))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            REPORTS.bounded_smoke_catalog(selected[:1])
        reports = [{"report_name": spec.name, "status": "generated", "freshness_status": "fresh",
                    "verified_run_id": self.environment["VERIFIED_RUN_ID"]} for spec in selected]
        self.assertEqual(REPORTS.bounded_smoke_report_status(reports, self.environment["VERIFIED_RUN_ID"]), 0)
        for status in ("failed", "blocked", "skipped_stale_input", "unknown", "interrupted"):
            reports[0]["status"] = status
            with self.subTest(status=status):
                self.assertEqual(REPORTS.bounded_smoke_report_status(reports, self.environment["VERIFIED_RUN_ID"]), 2)
        reports[0]["status"] = "generated"
        reports[0]["verified_run_id"] = "historical-run"
        self.assertEqual(REPORTS.bounded_smoke_report_status(reports, self.environment["VERIFIED_RUN_ID"]), 2)

    def test_scoped_pipeline_generates_only_current_reports_and_rejects_retained_output(self) -> None:
        for stale in (False, True):
            with self.subTest(stale_output=stale), tempfile.TemporaryDirectory(
                prefix="bounded-smoke-pipeline-"
            ) as temporary:
                self.build = Path(temporary)
                self.begin_and_write_results()
                catalog = [REPORTS.ReportSpec(
                    name=name, owner="connector", generator="test-generator", make_target="test-target",
                    inputs=(), outputs=(str(self.build / f"{name}.json"),), command=(), optional=True,
                ) for name in sorted(REPORTS.BOUNDED_SMOKE_REPORTS)]

                def generate(spec, *_arguments):
                    output = Path(spec.outputs[0])
                    output.write_text("{}\n")
                    os.utime(output, ns=(time.time_ns(), time.time_ns()))
                    if stale:
                        os.utime(output, ns=(1, 1))
                    self.assertFalse(spec.optional)
                    return {"report_name": spec.name, "status": "generated", "freshness_status": "fresh",
                            "verified_run_id": self.environment["VERIFIED_RUN_ID"]}

                with (mock.patch.object(REPORTS, "run_command", side_effect=self.write_snapshot) as snapshot,
                      mock.patch.object(REPORTS, "run_spec", side_effect=generate) as generator):
                    status = REPORTS.refresh_bounded_smoke(
                        ROOT, self.framework, self.build, "no-crs", self.environment, catalog
                    )
                self.assertEqual(status, 2 if stale else 0)
                self.assertEqual(generator.call_count, 2)
                self.assertIn("ci/reporting/update-runtime-snapshot.py", " ".join(snapshot.call_args.args[0]))
                self.assertEqual(snapshot.call_args.args[0][-4:], ["--apache-command",
                    "make test-smoke-sequential-no-crs", "--nginx-command", "make test-smoke-sequential-no-crs"])
                receipt = json.loads((self.build / "bounded-smoke-report-refresh.json").read_text())
                self.assertEqual(receipt["status"], "FAIL" if stale else "PASS")
                self.assertEqual(receipt["profile"], "bounded-smoke")

    def test_snapshot_failure_and_result_mutation_stop_before_report_generation(self) -> None:
        self.begin_and_write_results()
        with (mock.patch.object(REPORTS, "run_command", return_value=(77, "", {})),
              mock.patch.object(REPORTS, "run_spec") as generator,
              self.assertRaisesRegex(ValueError, "snapshot generator returned 77")):
            REPORTS.refresh_bounded_smoke(ROOT, self.framework, self.build, "no-crs", self.environment, [])
        generator.assert_not_called()

        def mutate(_command, *_arguments):
            summary = self.build / "results/apache-summary.json"
            payload = json.loads(summary.read_text())
            payload["apache"]["cases"][self.first_case]["diagnostic"] = "changed"
            summary.write_text(json.dumps(payload))
            return 0, "", {}

        with (mock.patch.object(REPORTS, "run_command", side_effect=mutate),
              mock.patch.object(REPORTS, "run_spec") as generator,
              self.assertRaisesRegex(ValueError, "changed during snapshot generation")):
            REPORTS.refresh_bounded_smoke(ROOT, self.framework, self.build, "no-crs", self.environment, [])
        generator.assert_not_called()

    def test_native_make_shell_bootstraps_actual_common_before_fresh_crs_fetch(self) -> None:
        makefile = (source_path('Makefile', root=ROOT)).read_text()
        bounded = makefile.split("test-smoke-sequential-no-crs test-smoke-sequential-with-crs: ", 1)[1]
        producer_line = next(line for line in bounded.splitlines() if "$(WITH_RUNTIME_COMPONENTS) env PYTHON=" in line)
        command = producer_line.strip().removeprefix("$(WITH_RUNTIME_COMPONENTS) ").split(" || runtime_rc=", 1)[0]
        stub_framework = self.build / "framework-seam"
        for directory in ("ci/lib", "ci/provisioning", "ci/runtime"):
            (stub_framework / directory).mkdir(parents=True, exist_ok=True)
        (stub_framework / "ci/lib/common.sh").write_text(
            ". " + shlex.quote(str(self.framework / "ci/lib/common.sh")) + "\n"
        )
        (stub_framework / "ci/provisioning/fetch-crs.sh").write_text(
            'set -eu\n'
            'test "$CRS_SOURCE_DIR" = "$VERIFIED_RUN_ROOT/crs-fresh-source/coreruleset"\n'
            'test "$SOURCE_ROOT" = "$VERIFIED_RUN_ROOT/crs-fresh-source"\n'
            'printf "fetch\\n" >> "$SEAM_TRACE"\n'
        )
        (stub_framework / "ci/provisioning/prepare-crs.sh").write_text(
            'set -eu\n'
            'mkdir -p "$CRS_RUNTIME_DIR"\n'
            'printf "prepared\\n" > "$CRS_RUNTIME_DIR/modsecurity-crs-preamble.conf"\n'
            'printf "prepare\\n" >> "$SEAM_TRACE"\n'
        )
        (stub_framework / "ci/runtime/run-apache-smoke.sh").write_text(
            'set -eu\n'
            'test "$CASE_SCOPE" = all\n'
            'test -z "$FORCE_ALL_CASES$TEST_CASE$SMOKE_CASES$NO_CRS_BASELINE$NO_CRS_SELECTED_CASE_IDS$RUN_ONE_CASE"\n'
            'test "$RESULTS_DIR" = "$smoke_root/results"\n'
            'printf "apache\\n" >> "$SEAM_TRACE"\n'
        )
        stub_coordinator = self.build / "nginx-coordinator-seam.py"
        stub_coordinator.write_text(
            "import os, pathlib, sys\n"
            "assert sys.argv[1:] == ['--variant', os.environ['MODSECURITY_TEST_VARIANT']]\n"
            "assert os.environ['RESULTS_DIR'] == os.environ['smoke_root'] + '/results'\n"
            "with pathlib.Path(os.environ['SEAM_TRACE']).open('a') as trace: trace.write('nginx\\n')\n"
        )
        command = command.replace("$(CURDIR)/ci/runtime/lifecycle/run-bounded-nginx-cases.py", str(stub_coordinator))
        command = command.replace("$(FRAMEWORK_PYTHON)", sys.executable).replace("$(CURDIR)", str(ROOT))
        command = command.replace("$(FRAMEWORK_ROOT)", str(stub_framework)).replace("$$", "$")
        for variant in ("no-crs", "with-crs"):
            trace = self.build / (variant + ".trace")
            (self.build / variant / "results").mkdir(parents=True)
            env = {**os.environ, "variant": variant, "smoke_root": str(self.build / variant),
                   "FRAMEWORK_ROOT": str(stub_framework), "CONNECTOR_ROOT": str(ROOT),
                   "VERIFIED_RUN_ROOT": str(self.build / variant), "CONNECTOR_COMPONENT_CACHE": str(self.build / "cache"),
                   "BUILD_ROOT": str(self.build / variant / "build"),
                   "CRS_RUNTIME_DIR": str(self.build / variant / "build/crs"),
                   "SEAM_TRACE": str(trace), "CASE_SCOPE": "connector", "FORCE_ALL_CASES": "1",
                   "TEST_CASE": "narrowed", "SMOKE_CASES": "narrowed", "NO_CRS_BASELINE": "1",
                   "NO_CRS_SELECTED_CASE_IDS": "narrowed", "RUN_ONE_CASE": "1", "RESULTS_DIR": "historical"}
            result = subprocess.run(["sh", "-eu", "-c", command], env=env, capture_output=True, text=True, timeout=30)
            with self.subTest(variant=variant):
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(trace.read_text().splitlines(), ["fetch", "prepare", "apache", "nginx"]
                                 if variant == "with-crs" else ["apache", "nginx"])
                self.assertEqual((self.build / variant / "results/apache.rc").read_text(), "0\n")
        # The actual Parent helper must execute common.sh's absolute-path guard,
        # rather than a stub accepting invalid roots or a missing function.
        trace.unlink()
        env["VERIFIED_RUN_ROOT"] = "relative-invalid-root"
        result = subprocess.run(["sh", "-eu", "-c", command], env=env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("absolute", result.stdout + result.stderr)
        self.assertNotIn("not found", result.stdout + result.stderr)
        self.assertFalse(trace.exists())

    def test_sequential_workflow_uses_scoped_entries_and_preserves_general_strict_refresh(self) -> None:
        workflow = WORKFLOW.read_text()
        self.assertIn("make test-smoke-sequential-no-crs", workflow)
        self.assertIn("make test-smoke-sequential-with-crs", workflow)
        self.assertIn('make PYTHON="$PWD/.venv/bin/python" check-bounded-smoke-runtime-contract', workflow)
        makefile = (source_path('Makefile', root=ROOT)).read_text()
        contracts = makefile.split("check-bounded-smoke-runtime-contract: check-framework\n", 1)[1].split("\n\n", 1)[0]
        for module in (
            "modsecurity_connector_tests.test_full_smoke_workflow_contract",
            "modsecurity_connector_tests.test_bounded_nginx_cases",
            "modsecurity_connector_tests.test_nginx_harness_path_authority",
            "modsecurity_connector_tests.test_resolve_traefik_host_binary",
        ):
            self.assertIn(module, contracts.split())
        bounded = makefile.split("test-smoke-sequential-no-crs test-smoke-sequential-with-crs: ", 1)[1].split(
            "\n# The dedicated Parent runner", 1
        )[0]
        self.assertIn("mktemp -d", bounded)
        self.assertIn("--begin-bounded-smoke", bounded)
        self.assertIn('RESULTS_DIR="$$smoke_root/results"', bounded)
        self.assertIn("--profile bounded-smoke", bounded)
        self.assertIn("CASE_SCOPE=all FORCE_ALL_CASES= TEST_CASE= SMOKE_CASES= NO_CRS_BASELINE= NO_CRS_SELECTED_CASE_IDS= RUN_ONE_CASE=", bounded)
        full = makefile.split("refresh-all-reports: check-framework\n", 1)[1].split("\ncheck-generated-report-layout:", 1)[0]
        self.assertIn("--strict-inputs", full)
        self.assertIn("$(call RUN_WITH_REFRESH_ALL,", makefile.split("test-no-crs: ", 1)[1].split("\ntest-with-crs:", 1)[0])

    def test_runtime_component_reports_are_private_and_retained(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        initialize_start = workflow.index("      - name: Initialize paths\n")
        initialize_end = workflow.index("\n      - name: Lint and py-compile\n", initialize_start)
        initialize_paths = workflow[initialize_start:initialize_end]
        upload_start = workflow.index("      - name: Upload smoke artifacts\n")
        upload = workflow[upload_start:]

        self.assertIn(
            'echo "RUNTIME_REPORT_OUTPUT_ROOT=$build_root/runtime-component-reports"',
            initialize_paths,
        )
        self.assertIn(
            "${{ steps.paths.outputs.build_root }}/runtime-component-reports",
            upload,
        )
        self.assertNotIn("$GITHUB_WORKSPACE", initialize_paths)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
