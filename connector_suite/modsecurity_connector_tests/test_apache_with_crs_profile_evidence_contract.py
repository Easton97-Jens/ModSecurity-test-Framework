"""Static contract checks for the Parent Apache With-CRS evidence handoff."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = connector_root()
HARNESS = source_path('connectors/apache/harness/run_apache_smoke.sh', root=ROOT)
PROFILE = source_path('ci/runtime/lifecycle/with-crs-no-mrts-profile.py', root=ROOT)
WORKFLOW = source_path('.github/workflows/test-connectors-with-crs-no-mrts.yml', root=ROOT)
CASE_CLI = source_path('modules/ModSecurity-test-Framework/tests/runners/case_cli.py', root=ROOT)
CRS_CASE = source_path('modules/ModSecurity-test-Framework/tests/cases/security/crs/crs_sqli_anomaly_block.yaml', root=ROOT)


class ApacheWithCrsProfileEvidenceContractTest(unittest.TestCase):
    @staticmethod
    def block(source: str, start: str, end: str) -> str:
        return source.split(start, 1)[1].split(end, 1)[0]

    def run_profile_audit_path_guard(self, path: str) -> subprocess.CompletedProcess[str]:
        source = HARNESS.read_text(encoding="utf-8")
        guard = "require_safe_apache_config_path() {\n" + self.block(
            source,
            "require_safe_apache_config_path() {\n",
            "configure_apache_profile_audit() {\n",
        )
        script = "\n".join(
            (
                "blocked() { exit 77; }",
                guard,
                'require_safe_apache_config_path "$1" "Apache profile audit path"',
            )
        )
        return subprocess.run(
            ["sh", "-c", script, "sh", path],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def write_selected_case_result(self, result: Path) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(CASE_CLI),
                "case-info",
                "--case",
                str(CRS_CASE),
                "--connector",
                "apache",
                "--status",
                "pass",
                "--actual-status",
                "403",
                "--observed-transport-result",
                "http_status",
                "--output-root",
                str(result.parent),
                "--output",
                str(result),
            ],
            cwd=ROOT,
            env={**os.environ, "FORCE_ALL_CASES": "1", "MODSECURITY_TEST_VARIANT": "with-crs"},
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.stdout, "")

    def run_profile_single_case_publication(
        self, log_dir: Path, results_dir: Path, runtime_root: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        runtime_root = runtime_root or results_dir.parent
        return subprocess.run(
            [
                sys.executable,
                str(PROFILE),
                "publish-apache-selected-results",
                "--runtime-root",
                str(runtime_root),
                "--results-dir",
                str(results_dir),
                "--result-json",
                str(log_dir / "result.json"),
                "--case-cli",
                str(CASE_CLI),
                "--import-status-file",
                str(source_path('config/testing/import-status.json', root=ROOT)),
                "--log-dir",
                str(log_dir),
                "--server-binary",
                "/bin/true",
                "--module",
                "/tmp/mod_security3.so",
                "--libmodsecurity",
                "/tmp/libmodsecurity.so",
                "--origin-source",
                "apache",
                "--origin-source-repo",
                "",
                "--origin-source-url",
                "",
                "--origin-source-commit",
                "",
                "--origin-source-version",
                "",
                "--origin-license",
                "",
                "--origin-imported-path",
                "",
            ],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def prepare_profile_single_case_results(
        self, results_dir: Path, runtime_root: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        runtime_root = runtime_root or results_dir.parent
        return subprocess.run(
            [
                sys.executable,
                str(PROFILE),
                "prepare-apache-selected-results",
                "--runtime-root",
                str(runtime_root),
                "--results-dir",
                str(results_dir),
            ],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_harness_requires_a_transaction_bound_audit_and_proven_cleanup_before_pass(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        self.assertIn("apache_profile_stop_tracked_process()", source)
        self.assertIn("apache_profile_publish_cleanup_receipt()", source)
        self.assertIn(
            '"$PYTHON_BIN" -I "$APACHE_PROFILE_EVIDENCE_SCRIPT" prepare-apache-selected-results',
            source,
        )
        self.assertIn(
            '"$PYTHON_BIN" -I "$APACHE_PROFILE_EVIDENCE_SCRIPT" publish-apache-selected-results',
            source,
        )
        self.assertIn('port_is_free "$PORT"', source)
        self.assertIn('[ ! -e "$RUNTIME_PID_FILE" ]', source)
        success = self.block(
            source,
            'if "$PYTHON_BIN" "$CASE_CLI" assert-status',
            'reason=$(cat "$LOG_DIR/case-assert.log"',
        )
        self.assertIn("verify-apache-audit", success)
        self.assertIn("APACHE_PROFILE_FINAL_CLEANUP=1", success)
        self.assertIn("if ! cleanup; then", success)
        self.assertIn("APACHE_PROFILE_FINAL_CLEANUP=0", success)
        self.assertLess(success.index("verify-apache-audit"), success.index("APACHE_PROFILE_FINAL_CLEANUP=1"))
        self.assertLess(success.index("APACHE_PROFILE_FINAL_CLEANUP=1"), success.index("if ! cleanup; then"))
        self.assertLess(success.index("if ! cleanup; then"), success.index('write_case_result "$TEST_CASE" pass'))

    def test_profile_scoped_audit_configuration_follows_materialization_and_excludes_no_crs(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        audit = self.block(
            source,
            "configure_apache_profile_audit() {\n",
            "apache_profile_stop_tracked_process() {\n",
        )
        self.assertIn("1) return 0 ;;", audit)
        self.assertIn('[ "$MODSECURITY_TEST_VARIANT" = "with-crs" ] ||', audit)
        self.assertIn("SecAuditEngine On", audit)
        self.assertIn("SecAuditLogType Serial", audit)
        self.assertIn("SecAuditLogFormat Native", audit)
        self.assertIn("SecAuditLogParts ABFHZ", audit)
        self.assertIn(
            'require_safe_apache_config_path "$AUDIT_LOG_FILE" "Apache profile audit path"',
            audit,
        )
        self.assertIn('printf \'SecAuditLog "%s"\\n\' "$AUDIT_LOG_FILE"', audit)
        self.assertLess(
            audit.index('require_safe_apache_config_path "$AUDIT_LOG_FILE"'),
            audit.index('printf \'SecAuditLog "%s"\\n\' "$AUDIT_LOG_FILE"'),
        )
        materialization = self.block(
            source,
            'if ! "$PYTHON_BIN" "$CASE_CLI" materialize',
            '. "$CASE_ENV_FILE"',
        )
        self.assertIn("configure_apache_profile_audit", materialization)

    def test_profile_audit_config_path_rejects_unsafe_apache_quoted_value(self) -> None:
        cases = (
            ("/tmp/profile audit-()[]!;,.log", 0),
            ('/tmp/profile-"\nSecAuditLog "/tmp/attacker"\n#', 77),
            ("/tmp/profile\\audit.log", 77),
            ("/tmp/" + "$" + "{AUDIT_TARGET}/audit.log", 77),
        )
        for path, expected_returncode in cases:
            with self.subTest(path=repr(path)):
                result = self.run_profile_audit_path_guard(path)
                self.assertEqual(result.returncode, expected_returncode, result.stderr)

    def test_single_case_creates_results_directory_before_runtime_output(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        single_case = source.split(
            'if [ "$RUN_ONE_CASE" != "1" ]; then\n', 1
        )[1]
        single_case_setup = single_case.split("RUNTIME_PID_FILE=", 1)[0]
        self.assertIn('if [ "$RUN_ONE_CASE" = "1" ]; then', single_case_setup)
        self.assertIn("readonly APACHE_RESULTS_DIR_LABEL='RESULTS_DIR'", source)
        self.assertIn(
            'require_absolute_generated_path "$RESULTS_DIR" "$APACHE_RESULTS_DIR_LABEL"',
            single_case_setup,
        )
        self.assertIn("if apache_profile_enabled; then", single_case_setup)
        self.assertIn('"$APACHE_PROFILE_EVIDENCE_SCRIPT" prepare-apache-selected-results', single_case_setup)
        self.assertIn('--runtime-root "$BUILD_ROOT"', single_case_setup)
        self.assertIn('--results-dir "$RESULTS_DIR"', single_case_setup)
        self.assertIn(
            'else\n        prepare_runtime_directory "$RESULTS_DIR" "$APACHE_RESULTS_DIR_LABEL" 0',
            single_case_setup,
        )
        self.assertLess(
            single_case_setup.index(
                'require_absolute_generated_path "$RESULTS_DIR" "$APACHE_RESULTS_DIR_LABEL"'
            ),
            single_case_setup.index('"$APACHE_PROFILE_EVIDENCE_SCRIPT" prepare-apache-selected-results'),
        )
        all_cases = self.block(source, "run_all_cases() {\n", "write_case_result() {")
        self.assertIn(
            'prepare_runtime_directory "$LOG_DIR" "$APACHE_LOG_DIR_LABEL" 1', all_cases
        )
        self.assertIn(
            'prepare_runtime_directory "$RESULTS_DIR" "RESULTS_DIR" 0', all_cases
        )

    def test_profile_single_case_publishes_fresh_canonical_results_after_cleanup(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        publication = self.block(
            source,
            "publish_profile_single_case_results() {\n",
            "find_apache() {\n",
        )
        for required in (
            '[ "$RUN_ONE_CASE" = "1" ] || return 0',
            "apache_profile_enabled || return 0",
            '"$LOG_DIR/result.json"',
            '"$APACHE_PROFILE_EVIDENCE_SCRIPT" publish-apache-selected-results',
            '--runtime-root "$BUILD_ROOT"',
            '--results-dir "$RESULTS_DIR"',
            '--result-json "$single_case_result"',
            '--case-cli "$CASE_CLI"',
            '--log-dir "$LOG_DIR"',
        ):
            self.assertIn(required, publication)
        self.assertNotIn("cp ", publication)
        self.assertNotIn("summarize-results", publication)
        success = self.block(
            source,
            'if "$PYTHON_BIN" "$CASE_CLI" assert-status',
            'reason=$(cat "$LOG_DIR/case-assert.log"',
        )
        self.assertIn("publish_profile_single_case_results", success)
        self.assertLess(
            success.index("if ! cleanup; then"),
            success.index("publish_profile_single_case_results"),
        )
        self.assertLess(
            success.index('write_case_result "$TEST_CASE" pass'),
            success.index("publish_profile_single_case_results"),
        )

    def test_profile_single_case_publication_materializes_one_fresh_case_and_rejects_stale_outputs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="apache-profile-publication-") as temporary:
            root = Path(temporary)
            log_dir = root / "logs"
            results_dir = root / "results"
            log_dir.mkdir()
            result = log_dir / "result.json"
            self.write_selected_case_result(result)
            self.assertEqual(len(result.read_text(encoding="utf-8").splitlines()), 1)
            prepared = self.prepare_profile_single_case_results(results_dir)
            self.assertEqual(prepared.returncode, 0, prepared.stderr)

            completed = self.run_profile_single_case_publication(log_dir, results_dir)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                (results_dir / "apache-results.jsonl").read_text(encoding="utf-8"),
                result.read_text(encoding="utf-8"),
            )
            summary = json.loads((results_dir / "apache-summary.json").read_text(encoding="utf-8"))
            selected = summary["apache"]["cases"]["crs_sqli_anomaly_block"]
            self.assertEqual(selected["status"], "pass")
            self.assertEqual(selected["actual_status"], 403)
            self.assertEqual(
                (results_dir / "connector-summary.txt").read_text(encoding="utf-8"),
                (results_dir / "apache-summary.txt").read_text(encoding="utf-8"),
            )

            framework_results = root / "framework-results"
            framework_results.mkdir()
            framework_jsonl = framework_results / "apache-results.jsonl"
            framework_jsonl.write_text(result.read_text(encoding="utf-8"), encoding="utf-8")
            subprocess.run(
                [
                    sys.executable,
                    str(CASE_CLI),
                    "summarize-results",
                    "--connector",
                    "apache",
                    "--input-jsonl",
                    str(framework_jsonl),
                    "--summary-json",
                    str(framework_results / "apache-summary.json"),
                    "--summary-text",
                    str(framework_results / "apache-summary.txt"),
                    "--import-status-file",
                    str(source_path('config/testing/import-status.json', root=ROOT)),
                    "--connector-path",
                    "real-world",
                    "--validation-mode",
                    "real-world-connector-path",
                    "--server",
                    "apache",
                    "--server-binary",
                    "/bin/true",
                    "--module",
                    "/tmp/mod_security3.so",
                    "--libmodsecurity",
                    "/tmp/libmodsecurity.so",
                    "--origin-source",
                    "apache",
                    "--origin-source-repo",
                    "",
                    "--origin-source-url",
                    "",
                    "--origin-source-commit",
                    "",
                    "--origin-source-version",
                    "",
                    "--origin-license",
                    "",
                    "--origin-imported-path",
                    "",
                    "--runtime-mode",
                    "selected-case",
                    "--command",
                    "RUN_ONE_CASE=1 make verified-apache-case",
                    "--exit-status",
                    "0",
                    "--per-case-result-root",
                    str(log_dir),
                ],
                cwd=ROOT,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            expected_summary = json.loads(
                (framework_results / "apache-summary.json").read_text(encoding="utf-8")
            )
            expected_summary["apache"]["evidence_root"] = str(results_dir)
            expected_summary["apache"]["jsonl_path"] = str(results_dir / "apache-results.jsonl")
            self.assertEqual(summary, expected_summary)
            self.assertEqual(
                (results_dir / "apache-summary.txt").read_text(encoding="utf-8"),
                (framework_results / "apache-summary.txt").read_text(encoding="utf-8"),
            )

        with tempfile.TemporaryDirectory(prefix="apache-profile-publication-stale-") as temporary:
            root = Path(temporary)
            log_dir = root / "logs"
            results_dir = root / "results"
            log_dir.mkdir()
            self.write_selected_case_result(log_dir / "result.json")
            prepared = self.prepare_profile_single_case_results(results_dir)
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            stale = results_dir / "apache-summary.json"
            stale.write_text("stale\n", encoding="utf-8")

            completed = self.run_profile_single_case_publication(log_dir, results_dir)
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(stale.read_text(encoding="utf-8"), "stale\n")
            self.assertFalse((results_dir / "apache-results.jsonl").exists())

        with tempfile.TemporaryDirectory(prefix="apache-profile-publication-malformed-") as temporary:
            root = Path(temporary)
            log_dir = root / "logs"
            results_dir = root / "results"
            log_dir.mkdir()
            (log_dir / "result.json").write_text('{"status": "pass"}\n', encoding="utf-8")
            prepared = self.prepare_profile_single_case_results(results_dir)
            self.assertEqual(prepared.returncode, 0, prepared.stderr)

            completed = self.run_profile_single_case_publication(log_dir, results_dir)
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse((results_dir / "apache-results.jsonl").exists())
            self.assertFalse((results_dir / "apache-summary.json").exists())

        with tempfile.TemporaryDirectory(prefix="apache-profile-publication-replaced-") as temporary:
            root = Path(temporary)
            log_dir = root / "logs"
            results_dir = root / "results"
            log_dir.mkdir()
            self.write_selected_case_result(log_dir / "result.json")
            prepared = self.prepare_profile_single_case_results(results_dir)
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            original_results = root / "original-results"
            results_dir.rename(original_results)
            results_dir.mkdir()

            completed = self.run_profile_single_case_publication(log_dir, results_dir)
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse((results_dir / "apache-results.jsonl").exists())
            self.assertFalse((original_results / "apache-results.jsonl").exists())

        with tempfile.TemporaryDirectory(prefix="apache-profile-publication-symlink-") as temporary:
            root = Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            canary = outside / "canary"
            canary.write_text("unchanged\n", encoding="utf-8")
            intermediate = root / "intermediate"
            intermediate.symlink_to(outside, target_is_directory=True)

            prepared = self.prepare_profile_single_case_results(intermediate / "results")
            self.assertNotEqual(prepared.returncode, 0)
            self.assertEqual(canary.read_text(encoding="utf-8"), "unchanged\n")
            self.assertFalse((outside / "results").exists())

        with tempfile.TemporaryDirectory(prefix="apache-profile-publication-intermediate-replaced-") as temporary:
            root = Path(temporary)
            log_dir = root / "logs"
            intermediate = root / "intermediate"
            results_dir = intermediate / "results"
            log_dir.mkdir()
            intermediate.mkdir()
            self.write_selected_case_result(log_dir / "result.json")
            prepared = self.prepare_profile_single_case_results(results_dir, root)
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            original_intermediate = root / "original-intermediate"
            intermediate.rename(original_intermediate)
            outside = root / "outside"
            outside.mkdir()
            canary = outside / "canary"
            canary.write_text("unchanged\n", encoding="utf-8")
            intermediate.symlink_to(outside, target_is_directory=True)

            completed = self.run_profile_single_case_publication(log_dir, results_dir, root)
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse((outside / "results").exists())
            self.assertFalse((original_intermediate / "results" / "apache-results.jsonl").exists())
            self.assertEqual(canary.read_text(encoding="utf-8"), "unchanged\n")

    def test_profile_consumes_raw_audit_and_exact_cleanup_receipt_fields(self) -> None:
        source = PROFILE.read_text(encoding="utf-8")
        self.assertIn("APACHE_AUDIT_RELATIVE_PATH", source)
        self.assertIn(
            '"build/verified-apache-case/with-crs-no-mrts-apache/logs/apache-runtime/"\n'
            '    "audit.log"',
            source,
        )
        self.assertNotIn('"crs_sqli_anomaly_block/audit.log"', source)
        self.assertIn("APACHE_CLEANUP_RECEIPT_NAME", source)
        self.assertIn("_apache_audit_block_observation(audit_raw)", source)
        self.assertIn("_apache_cleanup_receipt(", source)
        self.assertIn('"tracked_host_processes_remaining"', source)
        self.assertIn('"tracked_helper_processes_remaining"', source)
        self.assertIn('"selected_listeners_remaining"', source)
        self.assertIn('"github_run_id"', source)
        self.assertIn('"github_run_attempt"', source)
        self.assertIn("os.O_EXCL", source)
        self.assertIn("os.O_NOFOLLOW", source)
        self.assertIn("prepare-apache-selected-results", source)
        self.assertIn("publish-apache-selected-results", source)
        self.assertIn("_runtime_relative_path", source)
        self.assertIn("_open_runtime_child", source)
        self.assertIn("APACHE_SELECTED_DIRECTORY_MARKER_RECORD", source)
        self.assertIn("_verify_apache_selected_marker", source)
        self.assertRegex(
            source,
            r"descriptor\s*=\s*_open_runtime_child\(\s*root_fd,\s*result_components,\s*"
            r"APACHE_SELECTED_RESULTS_DIRECTORY_LABEL\s*\)",
        )
        self.assertIn("APACHE_SELECTED_OUTPUT_NAMES", source)

    def test_workflow_hands_runtime_identity_into_harness_then_requires_source_receipts(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        checkout = self.block(
            source,
            "      - name: Checkout exact Parent head with pinned submodules\n",
            "      - name: Set up locked Python toolchain\n",
        )
        self.assertIn("fetch-depth: 0", checkout)
        revisions = self.block(
            source,
            "      - name: Verify pinned Parent, Framework, and MRTS revisions\n",
            "      - name: Install hash-locked Framework CI dependency\n",
        )
        self.assertIn('base_commit=$(git rev-parse "${EXPECTED_BASE_SHA}^{commit}")', revisions)
        self.assertIn('test "$base_commit" = "$EXPECTED_BASE_SHA"', revisions)
        runtime = self.block(
            source,
            "      - name: Run selected real with-CRS no-MRTS runtime\n",
            "      - name: Project HAProxy runtime evidence\n",
        )
        for assignment in (
            "RUN_ONE_CASE=1",
            'APACHE_PROFILE_CLEANUP_RECEIPT="$VERIFIED_RUN_ROOT/apache-profile-cleanup-receipt.json"',
            'APACHE_PROFILE_CELL_RUN_ID="$CRS_RUNTIME_RUN_ID"',
            'APACHE_PROFILE_GITHUB_RUN_ID="$GITHUB_RUN_ID"',
            'APACHE_PROFILE_GITHUB_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT"',
        ):
            self.assertIn(assignment, runtime)
        validation = self.block(
            source,
            "      - name: Validate Apache runtime evidence\n",
            "      - name: Produce canonical with-CRS no-MRTS profile cell\n",
        )
        self.assertIn("AUDIT_LOG:", validation)
        self.assertIn("CLEANUP_RECEIPT:", validation)
        self.assertIn("verify-apache-audit", validation)
        # The Framework wrapper passes APACHE_RUNTIME_LOG_DIR as the harness's
        # LOG_DIR, and the harness writes its native serial audit directly at
        # "$LOG_DIR/audit.log".  A case-name suffix here would validate a
        # nonexistent path after an otherwise successful real Apache run.
        self.assertIn(
            "AUDIT_LOG: ${{ env.BUILD_ROOT }}/verified-apache-case/"
            "with-crs-no-mrts-apache/logs/apache-runtime/audit.log",
            validation,
        )
        self.assertNotIn(
            "logs/apache-runtime/crs_sqli_anomaly_block/audit.log",
            validation,
        )
        producer = self.block(
            source,
            "      - name: Produce canonical with-CRS no-MRTS profile cell\n",
            "      - name: Upload Apache runtime evidence\n",
        )
        self.assertIn("apache)\n              source_root=\"$VERIFIED_ROOT\"", producer)
        self.assertIn("--crs-source-root \"$crs_source_root\"", producer)
        self.assertIn("HAPROXY_EVIDENCE_UID:", producer)
        self.assertIn("HAPROXY_EVIDENCE_GID:", producer)
        self.assertIn("--haproxy-evidence-uid \"$HAPROXY_EVIDENCE_UID\"", producer)
        self.assertIn("--haproxy-evidence-gid \"$HAPROXY_EVIDENCE_GID\"", producer)
        self.assertIn("steps.validate-apache-runtime-evidence.outcome == 'success'", source)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
