"""Unit subprocess boundaries are not genuine NGINX runtime evidence."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest


ROOT = connector_root()
HELPER = source_path('ci/runtime/lifecycle/run-selected-nginx-configtests.py', root=ROOT)
WRAPPER = source_path('ci/runtime/lifecycle/run-nginx-selected-host.sh', root=ROOT)
STORAGE = Path("/var/tmp/codex/ModSecurity-conector")
CONTRACT = {"operation": "configtest", "directive": "modsecurity", "value": "maybe",
            "expected_exit_code": 1, "expected_outcome": "config_rejected",
            "error_class": "invalid_boolean",
            "diagnostic_fragments": ['"modsecurity" directive', "invalid boolean value"]}
SIZE_CONTRACT = {"operation": "configtest", "directive": "modsecurity_phase4_body_limit", "value": "1048576",
                 "expected_exit_code": 1, "expected_outcome": "config_rejected",
                 "error_class": "removed_directive",
                 "diagnostic_fragments": ['unknown directive "modsecurity_phase4_body_limit"']}
TARGET_CONTRACTS = {
    "missing_rules_file": {"directive": "modsecurity_rules_file", "value": "missing-rules.conf",
                           "diagnostic_fragments": ['"modsecurity_rules_file" directive', "missing-rules.conf", "Failed to open the file"]},
    "invalid_rule_syntax": {"directive": "modsecurity_rules", "value": "SecRule REQUEST_URI",
                            "diagnostic_fragments": ['"modsecurity_rules" directive', "syntax error"]},
    "unknown_config_key": {"directive": "modsecurity_unknown_config_key", "value": "on",
                           "diagnostic_fragments": ['unknown directive "modsecurity_unknown_config_key"']},
    "unsafe_event_path": {"directive": "modsecurity_phase4_log", "value": "unsafe-event-directory",
                          "diagnostic_fragments": ['modsecurity_phase4_log "', 'unsafe-event-directory" is not a secure private event file']},
}


class SelectedNginxConfigtestWiringTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="config-dispatch-unit-", dir=STORAGE)
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.framework = self.base / "framework"
        catalog = self.framework / "tests/cases/no-crs-baseline/catalog.json"
        catalog.parent.mkdir(parents=True)
        catalog.write_text(json.dumps({"cases": [{"case_id": "invalid_boolean",
                           "config_invocations": {"nginx": CONTRACT}}]}))
        host = self.framework / "ci/runtime/run-nginx-smoke.sh"
        host.parent.mkdir(parents=True)
        host.write_text('#!/bin/sh\nprintf "http boundary\\n"\nexit "${UNIT_HOST_EXIT:-0}"\n')
        for arguments in (["init", "-q"], ["add", "."],
                          ["update-index", "--add", "--cacheinfo", "160000," + "6" * 40 + ",tools/MRTS"],
                          ["-c", "user.email=unit@example.invalid", "-c", "user.name=unit", "commit", "-qm", "unit fixture"]):
            subprocess.run(["git", "-C", str(self.framework), *arguments], check=True, capture_output=True)
        prefix = self.base / "prefix"
        binary = prefix / "sbin/nginx"
        binary.parent.mkdir(parents=True)
        binary.write_text('#!/bin/sh\necho \'nginx: "modsecurity" directive invalid boolean value\' >&2\nexit 1\n')
        binary.chmod(0o700)
        module = prefix / "modules/ngx_http_modsecurity_module.so"
        module.parent.mkdir()
        module.write_bytes(b"unit module boundary")
        self.build = self.base / "build"
        self.build.mkdir()
        self.build.chmod(0o755)
        self.results = self.build / "results"
        self.results.mkdir()
        self.results.chmod(0o755)
        self.result_file = self.results / "nginx-results.jsonl"
        self.result_file.write_text('{"case_id":"request_control","status":"PASS"}\n')
        self.result_file.chmod(0o644)
        self.environment = {**os.environ, "CONNECTOR_ROOT": str(ROOT),
                            "FRAMEWORK_ROOT": str(self.framework), "BUILD_ROOT": str(self.build),
                            "RESULTS_DIR": str(self.results), "NGINX_PREFIX": str(prefix),
                            "NO_CRS_RUN_ID": "unit-config-dispatch", "PYTHON": "python3",
                            "NO_CRS_SELECTED_CASE_IDS": "invalid_boolean"}
        self.environment.pop("MODSECURITY_LIB_DIR", None)

    def run_helper(self):
        return subprocess.run(["python3", str(HELPER)], env=self.environment,
                              capture_output=True, text=True, check=False)

    def test_selected_case_invokes_config_driver_and_preserves_request_result(self):
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [json.loads(line) for line in self.result_file.read_text().splitlines()]
        self.assertEqual([row["case_id"] for row in rows], ["request_control", "invalid_boolean"])
        self.assertEqual(rows[1]["status"], "PASS")
        self.assertEqual(rows[1]["configtest_receipt"]["observed_exit_code"], 1)
        self.assertFalse(rows[1]["configtest_receipt"]["process_started"])
        self.assertEqual(self.build.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.results.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.result_file.stat().st_mode & 0o777, 0o644)
        self.assertEqual((self.build / "configtests").stat().st_mode & 0o777, 0o700)
        self.assertNotEqual(self.run_helper().returncode, 0, "duplicate invocation must be rejected")

    def test_not_selected_case_is_not_invoked_or_promoted(self):
        self.environment["NO_CRS_SELECTED_CASE_IDS"] = "request_control"
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.build / "configtests").exists())
        self.assertEqual(len(self.result_file.read_text().splitlines()), 1)

    def test_writable_build_is_rejected_before_invocation(self):
        original = self.result_file.read_bytes()
        self.build.chmod(0o777)
        result = self.run_helper()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((self.build / "configtests").exists())
        self.assertEqual(self.result_file.read_bytes(), original)

    def test_writable_config_parent_is_rejected_without_reuse(self):
        parent = self.build / "configtests"
        parent.mkdir()
        parent.chmod(0o770)
        original = self.result_file.read_bytes()
        result = self.run_helper()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((parent / "invalid_boolean").exists())
        self.assertEqual(self.result_file.read_bytes(), original)

    def test_writable_results_is_rejected_before_invocation(self):
        original = self.result_file.read_bytes()
        self.results.chmod(0o777)
        result = self.run_helper()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((self.build / "configtests/invalid_boolean").exists())
        self.assertEqual(self.result_file.read_bytes(), original)

    def test_existing_child_receipt_is_not_appended_after_rejected_invocation(self):
        child = self.build / "configtests/invalid_boolean"
        child.mkdir(parents=True, mode=0o700)
        receipt = child / "source-result.jsonl"
        receipt.write_text('{"case_id":"invalid_boolean","status":"PASS"}\n')
        original = self.result_file.read_bytes()
        result = self.run_helper()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.result_file.read_bytes(), original)
        self.assertEqual(receipt.read_text(), '{"case_id":"invalid_boolean","status":"PASS"}\n')

    def test_hardlinked_result_file_is_rejected_without_append(self):
        alias = self.base / "result-alias.jsonl"
        alias.hardlink_to(self.result_file)
        original = alias.read_bytes()
        result = self.run_helper()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(alias.read_bytes(), original)
        self.assertFalse((self.build / "configtests/invalid_boolean").exists())

    def test_writable_result_file_is_rejected_without_append(self):
        self.result_file.chmod(0o666)
        original = self.result_file.read_bytes()
        result = self.run_helper()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.result_file.read_bytes(), original)
        self.assertFalse((self.build / "configtests/invalid_boolean").exists())

    def test_two_selected_config_cases_use_distinct_fresh_children(self):
        catalog = self.framework / "tests/cases/no-crs-baseline/catalog.json"
        records = json.loads(catalog.read_text())
        records["cases"].append({"case_id": "invalid_size", "config_invocations": {"nginx": SIZE_CONTRACT}})
        catalog.write_text(json.dumps(records))
        binary = Path(self.environment["NGINX_PREFIX"]) / "sbin/nginx"
        binary.write_text(
            '#!/bin/sh\ncase "$(sed -n "6p" "$5")" in\n'
            '  *modsecurity_phase4_body_limit*) echo \'unknown directive "modsecurity_phase4_body_limit"\' >&2 ;;\n'
            '  *) echo \'"modsecurity" directive invalid boolean value\' >&2 ;;\n'
            'esac\nexit 1\n'
        )
        self.environment["NO_CRS_SELECTED_CASE_IDS"] = "invalid_boolean invalid_size"
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [json.loads(line) for line in self.result_file.read_text().splitlines()][1:]
        self.assertEqual([row["case_id"] for row in rows], ["invalid_boolean", "invalid_size"])
        roots = [Path(row["artifacts"]["configtest_dir"]) for row in rows]
        self.assertEqual([path.parent for path in roots], [self.build / "configtests"] * 2)
        self.assertNotEqual(*roots)
        self.assertTrue(all(row["status"] == "PASS" for row in rows))
        self.assertNotEqual(self.run_helper().returncode, 0, "fresh-child reuse remains rejected")

    def test_wrong_diagnostic_remains_fail(self):
        binary = Path(self.environment["NGINX_PREFIX"]) / "sbin/nginx"
        binary.write_text('#!/bin/sh\necho "module missing" >&2\nexit 1\n')
        result = self.run_helper()
        self.assertEqual(result.returncode, 1, result.stderr)
        row = json.loads(self.result_file.read_text().splitlines()[-1])
        self.assertEqual(row["status"], "FAIL")

    def test_four_target_rejections_dispatch_exact_contracts_to_fresh_children(self):
        catalog = self.framework / "tests/cases/no-crs-baseline/catalog.json"
        cases = []
        for case_id, fields in TARGET_CONTRACTS.items():
            contract = {"operation": "configtest", "expected_exit_code": 1,
                        "expected_outcome": "config_rejected", "error_class": case_id, **fields}
            cases.append({"case_id": case_id, "config_invocations": {"nginx": contract}})
        catalog.write_text(json.dumps({"cases": cases}))
        binary = Path(self.environment["NGINX_PREFIX"]) / "sbin/nginx"
        binary.write_text(
            '#!/bin/sh\nroot=${5%/*}\ncase "$(sed -n "6p" "$5")" in\n'
            '  *modsecurity_rules_file*) echo "\\\"modsecurity_rules_file\\\" directive Failed to open the file: $root/missing-rules.conf" >&2 ;;\n'
            '  *modsecurity_unknown_config_key*) echo \'unknown directive "modsecurity_unknown_config_key"\' >&2 ;;\n'
            '  *modsecurity_phase4_log*) echo "modsecurity_phase4_log \\\"$root/unsafe-event-directory\\\" is not a secure private event file" >&2 ;;\n'
            '  *modsecurity_rules*) echo \'"modsecurity_rules" directive syntax error\' >&2 ;;\n'
            '  *) exit 99 ;;\nesac\nexit 1\n'
        )
        self.environment["NO_CRS_SELECTED_CASE_IDS"] = " ".join(TARGET_CONTRACTS)
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [json.loads(line) for line in self.result_file.read_text().splitlines()][1:]
        self.assertEqual([row["case_id"] for row in rows], list(TARGET_CONTRACTS))
        children = [Path(row["artifacts"]["configtest_dir"]) for row in rows]
        self.assertEqual(len(set(children)), 4)
        self.assertEqual([child.parent for child in children], [self.build / "configtests"] * 4)
        self.assertTrue(all(row["status"] == "PASS" for row in rows))
        self.assertNotEqual(self.run_helper().returncode, 0, "existing case outputs are not reusable")

    def test_host_failure_is_retained_after_config_invocation(self):
        self.environment["UNIT_HOST_EXIT"] = "77"
        result = subprocess.run(["sh", str(WRAPPER)], env=self.environment,
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertIn("http boundary", result.stdout)
        self.assertEqual(json.loads(self.result_file.read_text().splitlines()[-1])["case_id"],
                         "invalid_boolean")

    def test_stage_dispatch_reproduces_old_route_and_selects_parent_host_route(self):
        connector = self.base / "connector"
        cache = connector / "ci/provisioning/cache/with-runtime-components.sh"
        cache.parent.mkdir(parents=True)
        cache.write_text('#!/bin/sh\nfor argument do last=$argument; done\nprintf "%s\\n" "$last"\n')
        cache.chmod(0o700)
        common = self.framework / "ci/lib/common.sh"
        common.parent.mkdir(parents=True)
        common.write_text("# unit prerequisite\n")
        environment = {**self.environment, "CONNECTOR_ROOT": str(connector),
                       "NO_CRS_SELECTED_CASES": "allow_without_marker.yaml",
                       "NO_CRS_ARTIFACT_PROFILE": "generic"}
        baseline = self.base / "baseline-stage.sh"
        # Replay only the old routing decision, without requiring historical
        # Git objects (CI may use a shallow checkout). Both scripts execute.
        current_stage = (source_path('ci/runtime/lifecycle/run-connector-stage.sh', root=ROOT)).read_text()
        native_route = '        host_script=$CONNECTOR_ROOT/ci/runtime/lifecycle/run-nginx-selected-host.sh\n'
        legacy_route = '        host_script=$FRAMEWORK_ROOT/ci/runtime/$framework_script\n'
        self.assertEqual(current_stage.count(native_route), 1)
        replayed_stage = current_stage.replace(native_route, legacy_route, 1)
        self.assertNotEqual(replayed_stage, current_stage)
        self.assertNotIn(native_route, replayed_stage)
        baseline.write_text(replayed_stage)
        old = subprocess.run(["sh", str(baseline), "nginx", "no_crs_baseline"],
                             env=environment, capture_output=True, text=True, check=False)
        new = subprocess.run(["sh", str(source_path('ci/runtime/lifecycle/run-connector-stage.sh', root=ROOT)),
                              "nginx", "no_crs_baseline"], env=environment,
                             capture_output=True, text=True, check=False)
        self.assertEqual(old.returncode, 0, old.stderr)
        self.assertEqual(new.returncode, 0, new.stderr)
        self.assertEqual(old.stdout.strip(), str(self.framework / "ci/runtime/run-nginx-smoke.sh"))
        self.assertEqual(new.stdout.strip(), str(connector / "ci/runtime/lifecycle/run-nginx-selected-host.sh"))

    def test_results_escape_and_symlink_are_rejected(self):
        self.environment["RESULTS_DIR"] = str(self.base / "outside-results")
        self.assertNotEqual(self.run_helper().returncode, 0)
        self.environment["RESULTS_DIR"] = str(self.results)
        target = self.base / "protected.jsonl"
        target.write_text("untouched\n")
        self.result_file.unlink()
        self.result_file.symlink_to(target)
        self.assertNotEqual(self.run_helper().returncode, 0)
        self.assertEqual(target.read_text(), "untouched\n")

    def test_unsupported_explicit_config_mapping_is_not_promoted(self):
        catalog = self.framework / "tests/cases/no-crs-baseline/catalog.json"
        records = json.loads(catalog.read_text())
        records["cases"][0]["config_invocations"]["nginx"]["directive"] = "different_directive"
        catalog.write_text(json.dumps(records))
        self.assertNotEqual(self.run_helper().returncode, 0)
        self.assertEqual(len(self.result_file.read_text().splitlines()), 1)

    def test_each_selected_contract_field_is_checked_before_invocation(self):
        mismatches = {"operation": "startup", "directive": "other", "value": "different",
                      "expected_exit_code": 0, "expected_outcome": "config_accepted",
                      "error_class": "different", "diagnostic_fragments": ["missing module"],
                      "unexpected_field": "unapproved"}
        catalog = self.framework / "tests/cases/no-crs-baseline/catalog.json"
        for index, (field, value) in enumerate(mismatches.items()):
            with self.subTest(field=field):
                contract = {**CONTRACT, field: value}
                catalog.write_text(json.dumps({"cases": [{"case_id": "invalid_boolean",
                                   "config_invocations": {"nginx": contract}}]}))
                build = self.base / f"mismatch-{index}"
                build.mkdir()
                results = build / "results"
                results.mkdir()
                self.environment.update(BUILD_ROOT=str(build), RESULTS_DIR=str(results))
                result = self.run_helper()
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse((build / "configtests").exists())

    def test_equal_noninteger_exit_metadata_is_not_an_exact_contract(self):
        catalog = self.framework / "tests/cases/no-crs-baseline/catalog.json"
        for index, value in enumerate((True, 1.0)):
            with self.subTest(value=value):
                contract = {**CONTRACT, "expected_exit_code": value}
                catalog.write_text(json.dumps({"cases": [{"case_id": "invalid_boolean",
                                   "config_invocations": {"nginx": contract}}]}))
                build = self.base / f"exit-type-{index}"
                build.mkdir()
                results = build / "results"
                results.mkdir()
                self.environment.update(BUILD_ROOT=str(build), RESULTS_DIR=str(results))
                result = self.run_helper()
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse((build / "configtests").exists())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
