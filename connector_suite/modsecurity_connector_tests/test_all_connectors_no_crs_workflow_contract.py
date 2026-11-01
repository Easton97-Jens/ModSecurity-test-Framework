from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import importlib.util
from pathlib import Path
import re
import unittest
from modsecurity_test_framework.workflow_sources import read_connector_workflow


ROOT = connector_root()
CALLER = source_path('.github/workflows/all-connectors-no-crs.yml', root=ROOT)
REUSABLE = source_path('.github/workflows/reusable-five-connectors-profile.yml', root=ROOT)
PROFILE_RESOLVER = source_path('ci/runtime/lifecycle/five-connector-no-crs-profile.py', root=ROOT)


class AllConnectorsNoCrsWorkflowContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.caller = CALLER.read_text(encoding="utf-8")
        cls.reusable = read_connector_workflow(REUSABLE)
        spec = importlib.util.spec_from_file_location("five_connector_profile", PROFILE_RESOLVER)
        assert spec is not None
        assert spec.loader is not None
        cls.profile = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.profile)

    def test_thin_caller_is_schedule_and_manual_read_only_no_crs(self) -> None:
        self.assertIn("name: Five Connector No-CRS Baseline\n", self.caller)
        self.assertIn("  workflow_dispatch:\n", self.caller)
        self.assertIn("  schedule:\n", self.caller)
        self.assertNotIn("pull_request:", self.caller)
        self.assertNotIn("pull_request_target:", self.caller)
        self.assertNotIn("workflow_call:", self.caller)
        self.assertIn("\npermissions: {}\n", self.caller)
        self.assertIn("  no-crs:\n    permissions:\n      contents: read\n", self.caller)
        self.assertIn("uses: $/.github/workflows/reusable-five-connectors-profile.yml", self.caller)
        self.assertIn("profile: no-crs", self.caller)
        self.assertNotIn("inputs:", self.caller)
        self.assertNotIn("secrets:", self.caller)
        self.assertNotIn("write", self.caller)

    def test_reusable_workflow_is_closed_and_unprivileged(self) -> None:
        self.assertIn("  workflow_call:\n", self.reusable)
        self.assertNotIn("workflow_dispatch:", self.reusable)
        self.assertNotIn("schedule:", self.reusable)
        self.assertNotIn("pull_request:", self.reusable)
        self.assertNotIn("pull_request_target:", self.reusable)
        self.assertIn("\npermissions: {}\n", self.reusable)
        for job in ("resolve-profile", "no-crs", "aggregate"):
            self.assertIn(f"  {job}:\n    permissions:\n      contents: read\n", self.reusable)
        self.assertNotIn("secrets:", self.reusable)
        self.assertNotIn("permissions: write", self.reusable)
        self.assertNotIn("sudo", self.reusable.lower())
        self.assertNotIn("nginx", self.reusable.lower())
        self.assertNotIn("root handoff", self.reusable.lower())
        self.assertNotIn("nginx_", self.reusable.lower())
        self.assertNotIn("inputs.connector", self.reusable)
        self.assertNotIn("github.event.inputs", self.reusable)

    def test_matrix_is_resolver_backed_and_every_row_is_revalidated(self) -> None:
        self.assertIn("python3 -m unittest -v modsecurity_connector_tests.test_all_connectors_no_crs_workflow_contract", self.reusable)
        self.assertIn("five-connector-no-crs-profile.py \\", self.reusable)
        self.assertIn('--profile "$PROFILE" --emit-github-matrix', self.reusable)
        self.assertIn("matrix: ${{ fromJSON(needs.resolve-profile.outputs.matrix) }}", self.reusable)
        for fragment in (
            "--verify-row",
            '--connector "$CONNECTOR"',
            '--integration-mode "$CI_INTEGRATION_MODE"',
            '--protocol "$CI_PROTOCOL"',
            '--phase4-mode "$CI_PHASE4_MODE"',
            '--evidence-scope "$CI_EVIDENCE_SCOPE"',
            '--connector-profile "$CI_CONNECTOR_PROFILE"',
            '--capabilities "connectors/$CONNECTOR/capabilities.json"',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.reusable)

    def test_resolver_declares_the_exact_five_connector_metadata(self) -> None:
        expected = (
            ("apache", "native-httpd-module", "http1", "safe", "full-lifecycle-low-latency", "source-wiring-and-baseline-only"),
            ("haproxy", "spoe-spop-agent", "http1", "not_applicable", "header-compatibility", "no-response-body-host-path"),
            ("envoy", "http-ext-authz-service", "http1", "not_applicable", "request-only-compatibility", "no-response-host-path"),
            ("traefik", "http-forwardauth-service", "http1", "not_applicable", "request-only-compatibility", "no-response-host-path"),
            ("lighttpd", "native-lighttpd-plugin", "http1", "not_applicable", "header-compatibility", "no-native-body-host-path"),
        )
        actual = tuple(
            (
                row["connector"],
                row["integration_mode"],
                row["protocol"],
                row["phase4_mode"],
                row["connector_profile"],
                row["evidence_scope"],
            )
            for row in self.profile.ROWS
        )
        self.assertEqual(self.profile.PROFILE, "no-crs")
        self.assertEqual(self.profile.CONNECTORS, tuple(row[0] for row in expected))
        self.assertEqual(actual, expected)
        self.assertNotIn("nginx", self.profile.CONNECTORS)

    def test_private_roots_bind_profile_commits_connector_and_run(self) -> None:
        expected = (
            'verified_root="$RUNNER_TEMP/ModSecurity-conector-verified/$CI_PROFILE/$parent_commit/$framework_commit/$CONNECTOR/$NO_CRS_RUN_ID"',
            'build_root="$verified_root/build"',
            'verified_evidence_root="$verified_root/evidence"',
            'run_root="$verified_root/runs"',
            'log_root="$verified_root/run-logs"',
            'diagnostic_root="$verified_root/failure-diagnostics"',
            'cache_root="$verified_root/cache-v2"',
            'evidence_root="$verified_evidence_root/no-crs-evidence"',
            'test "$parent_commit" = "$GITHUB_SHA"',
        )
        for fragment in expected:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.reusable)
        self.assertIn(
            "SETUP_PYTHON_PATH: ${{ steps.setup-python.outputs.python-path }}",
            self.reusable,
        )
        self.assertIn('echo "PYTHON=$SETUP_PYTHON_PATH"', self.reusable)
        self.assertIn('echo "FIVE_CONNECTOR_DIAGNOSTIC_ROOT=$diagnostic_root"', self.reusable)
        self.assertNotIn('echo "PYTHON=${{', self.reusable)
        self.assertNotIn('verified_root="$RUNNER_TEMP/ModSecurity-conector-verified"', self.reusable)
        self.assertNotIn('evidence_root="$build_root/no-crs-evidence"', self.reusable)

    def test_provisioning_and_artifacts_are_exactly_the_fixed_profile(self) -> None:
        provision = re.search(
            r"- name: Provision host component\n(?P<body>.*?)(?=\n      - name: Build connector)",
            self.reusable,
            re.DOTALL,
        )
        self.assertIsNotNone(provision)
        body = provision.group("body")
        self.assertIn("apache|haproxy)", body)
        for connector in ("envoy", "traefik", "lighttpd"):
            with self.subTest(connector=connector):
                self.assertIn(f"{connector})", body)
        self.assertIn("outside the fixed profile", body)
        self.assertIn("name: five-no-crs-${{ matrix.connector }}-${{ github.run_id }}-${{ github.run_attempt }}", self.reusable)
        self.assertIn("pattern: five-no-crs-*-${{ github.run_id }}-${{ github.run_attempt }}", self.reusable)
        self.assertIn("--emit-connectors > \"$connector_list\"", self.reusable)
        self.assertIn(
            "path: ${{ runner.temp }}/five-connector-profile-artifacts/${{ github.run_id }}-${{ github.run_attempt }}",
            self.reusable,
        )
        self.assertIn(
            'artifact_root="$RUNNER_TEMP/five-connector-profile-artifacts/$NO_CRS_RUN_ID"',
            self.reusable,
        )
        self.assertIn(
            'artifact_dir="$artifact_root/five-no-crs-$connector-$NO_CRS_RUN_ID"',
            self.reusable,
        )
        self.assertNotIn('path: downloaded', self.reusable)
        self.assertNotIn(
            'artifact_dir="downloaded/five-no-crs-$connector-$NO_CRS_RUN_ID"',
            self.reusable,
        )
        self.assertIn('destination="$EVIDENCE_ROOT/$connector/$NO_CRS_RUN_ID"', self.reusable)
        self.assertIn("- name: Capture bounded connector failure diagnostics", self.reusable)
        self.assertIn("- name: Upload bounded connector failure diagnostics", self.reusable)
        self.assertIn("if: failure()", self.reusable)
        capture = self.reusable.split(
            "- name: Capture bounded connector failure diagnostics", 1
        )[1].split("- name: Upload bounded connector failure diagnostics", 1)[0]
        self.assertIn("env:\n          CONNECTOR: ${{ matrix.connector }}", capture)
        self.assertIn(
            "name: five-connector-diagnostics-${{ matrix.connector }}-${{ github.run_id }}-${{ github.run_attempt }}",
            self.reusable,
        )
        self.assertIn("${{ env.FIVE_CONNECTOR_DIAGNOSTIC_ROOT }}", self.reusable)
        self.assertIn("${{ env.RUNTIME_REPORT_OUTPUT_ROOT }}", self.reusable)
        self.assertNotIn("name: five-no-crs-diagnostics-", self.reusable)

    def test_aggregation_is_fail_closed_and_result_only(self) -> None:
        self.assertIn("if: always()", self.reusable)
        self.assertIn("id: validate-profile-evidence", self.reusable)
        self.assertIn("Missing five-profile artifact for $connector", self.reusable)
        self.assertIn("status=1", self.reusable)
        self.assertIn('exit "$status"', self.reusable)
        self.assertIn("canonical_validation_status=failed", self.reusable)
        self.assertIn(
            '[ "${{ steps.validate-profile-evidence.outcome }}" = "success" ]',
            self.reusable,
        )
        self.assertIn('canonical_validation_status=passed', self.reusable)
        self.assertIn(
            '--canonical-validation-status "$canonical_validation_status"',
            self.reusable,
        )
        self.assertIn("aggregate-five-connector-no-crs.py", self.reusable)
        self.assertIn("five-connectors-no-crs-summary.json", self.reusable)
        self.assertNotIn("continue-on-error", self.reusable)
        self.assertNotIn("|| true", self.reusable)
        self.assertNotIn("capability catalog", self.reusable.lower())
        self.assertNotIn("capabilities-all", self.reusable)
        self.assertNotIn("no_crs_baseline.py summarize", self.reusable)
        self.assertIn("if-no-files-found: error", self.reusable)
        self.assertNotIn("rm -rf", self.reusable)

    def test_actions_are_commit_pinned_and_checkout_does_not_persist_credentials(self) -> None:
        uses = re.findall(r"^\s*uses:\s+([^\s#]+)", self.reusable, re.MULTILINE)
        self.assertGreaterEqual(len(uses), 7)
        for action in uses:
            with self.subTest(action=action):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")
        self.assertEqual(self.reusable.count("persist-credentials: false"), 3)

    def test_makefile_keeps_absent_apr_util_variables_absent(self) -> None:
        makefile = (source_path('Makefile', root=ROOT)).read_text(encoding="utf-8")
        self.assertIn("define export_framework_optional_provenance", makefile)
        export_list = makefile.split("FRAMEWORK_OPTIONAL_PROVENANCE_EXPORTS :=", 1)[1]
        export_list = export_list.split("$(foreach", 1)[0]
        for name in (
            "APR_UTIL_VERSION",
            "APR_UTIL_SOURCE_URL",
            "APR_UTIL_SHA256",
            "APR_UTIL_SHA256_URL",
        ):
            with self.subTest(name=name):
                self.assertIn(name, export_list)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
