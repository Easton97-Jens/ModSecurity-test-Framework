from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = connector_root()
HARNESS = source_path('connectors/envoy/harness/run_envoy_composite_matrix.sh', root=ROOT)


class EnvoyCompositeReceiptContractTest(unittest.TestCase):
    def test_real_cases_bind_receipts_to_started_runtime_inputs(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")

        self.assertIn('"started_binary_artifacts": {"envoy": envoy, "composite": composite}', source)
        self.assertIn('event_artifact = artifact(event_log, "event JSONL", private=True)', source)
        self.assertIn('structural_artifact = artifact(structural, "structural event artifact", private=True)', source)
        self.assertIn('"event_log_artifact": event_artifact', source)
        self.assertIn('"structural_event_artifact_binding": structural_artifact', source)
        self.assertIn('"rendered_config_artifact": config_artifact', source)
        self.assertIn('"client_observation_artifact": probe_artifact', source)
        self.assertIn('"upstream_observation": upstream_artifact', source)
        self.assertIn('"causal_binding": "started_binary_config_client_upstream_artifacts" if upstream_artifact else "started_binary_config_client_no_upstream_request_observed"', source)
        self.assertIn('"upstream_observation_state": upstream_state', source)
        self.assertIn('upstream_observation_state=not_reached', source)
        self.assertIn('upstream_observation_state=request_started', source)
        self.assertIn('upstream_observation_state=response_observed', source)
        self.assertIn('"client_protocol": "HTTP/1.1"', source)
        self.assertIn('MAX_BINARY_BYTES = 512 * 1024 * 1024', source)
        self.assertIn('MAX_PRIVATE_BYTES = 16 * 1024 * 1024', source)
        self.assertIn('chunk = stream.read(1024 * 1024)', source)
        self.assertNotIn('hashlib.sha256(path.read_bytes())', source)
        self.assertIn('stat.S_IMODE(info.st_mode) & 0o77', source)
        self.assertIn('runtime_root = pathlib.Path(runtime_root_text).resolve(strict=True)', source)
        self.assertIn('path.resolve(strict=True).relative_to(runtime_root)', source)
        self.assertIn('info.st_nlink != 1', source)
        self.assertIn('chmod 600 "$VERSION_OUTPUT" || fail "could not restrict Envoy version artifact"', source)
        self.assertIn('PROJECTION_WRITER="$SCRIPT_DIR/write_composite_verifier_projection.py"', source)
        self.assertIn('verifier_case_supported()', source)
        self.assertIn('envoy_response_metadata_omitted', source)
        self.assertIn('run_case p3_redirect P3 GET /vector/p3-redirect', source)
        self.assertIn('headers.append(("X-Msconnector-Vector", "msconnector-p3-redirect"))', source)
        self.assertIn('--require-response-header "Location: $P3_REDIRECT_TARGET"', source)
        self.assertIn('[ "$observed_status" = 302 ] || fail "P3 redirect status was not 302"', source)
        self.assertIn('"redirect_location_verified": False', source)
        self.assertIn('wait_for_event_phase "$case_event_log" terminal timeout', source)
        run_case_source = source[source.index('run_case() {'):source.index('run_follow_up_case() {')]
        self.assertLess(
            run_case_source.index('wait_for_event_phase "$case_event_log" terminal timeout'),
            run_case_source.index('cleanup || fail "bounded cleanup failed for case $case_id"'),
        )
        self.assertIn('maximum_bytes = 256 * 1024', source)
        self.assertIn('maximum_line_bytes = 16 * 1024', source)
        self.assertIn('os.O_RDONLY | no_follow', source)
        self.assertIn('MAX_EVENT_LOG_BYTES = 256 * 1024', source)
        self.assertIn('check_client_probe "$case_probe"', source)
        self.assertIn('upstream-request-observation.json', source)
        self.assertIn('upstream-response-observation.json', source)
        self.assertIn('--upstream-request-observation "$case_upstream_request_observation"', source)
        self.assertIn('--upstream-response-observation "$case_upstream_response_observation"', source)
        self.assertIn('case_verifier_status=LIFECYCLE_ONLY', source)
        self.assertIn('"shared_verifier_manifest_artifact": verifier_manifest_artifact', source)
        self.assertIn('"shared_verifier_summary_artifact": verifier_summary_artifact', source)
        self.assertIn('"shared_verifier_status": verifier_status', source)

    def test_native_oversize_uses_a_complete_sample_within_host_capacity(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        invocation = next(line for line in source.splitlines() if line.startswith("run_case p2_oversize "))
        arguments = shlex.split(invocation)
        template = (source_path('connectors/envoy/config/envoy-ext-authz-composite.yaml.in', root=ROOT)).read_text()
        rules = (source_path('common/rules/modsecurity_p1_p4_vectors.conf', root=ROOT)).read_text()
        host_capacity = int(re.search(r"max_request_bytes: (\d+)", template).group(1))
        native_limit = int(re.search(r"^SecRequestBodyLimit (\d+)$", rules, re.MULTILINE).group(1))
        self.assertEqual(arguments[5], "Content-Type: text/plain")
        self.assertEqual(len(arguments[6].encode("ascii")), 33)
        self.assertGreater(len(arguments[6]), native_limit)
        self.assertLessEqual(len(arguments[6]), host_capacity)
        self.assertIn("allow_partial_message: false", template)
        self.assertIn("SecRequestBodyNoFilesLimit 32", rules)
        self.assertIn("SecRequestBodyLimitAction Reject", rules)

    def test_companion_shutdown_validator_requires_one_closed_restart(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        validator = source.split("check_event_log() {", 1)[1].split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        base = {
            "decision_id": "server-generated-test-decision",
            "connector": "envoy", "phase": "terminal", "outcome": "closed",
            "reason": "restart", "cleanup_outcome": "closed",
            "event_time": "2026-10-11T00:00:00Z",
            "request_path": "envoy.ext_authz", "response_path": "envoy.ext_proc",
            "transport": "envoy_ext_authz_ext_proc_grpc",
        }
        cases = {
            "closed_restart": [base],
            "failed_cleanup": [dict(base, cleanup_outcome="failed")],
            "failed_outcome": [dict(base, outcome="failed")],
            "wrong_cause": [dict(base, reason="timeout")],
            "duplicate_terminal": [base, base],
        }
        self.assertIn('[ "$observed_status" = 500 ] || fail "unavailable companion did not retain native Envoy error status"', source)
        for name, events in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                event_path = Path(temporary) / "events.jsonl"
                output_path = Path(temporary) / "structural.json"
                event_path.write_text("".join(json.dumps(event) + "\n" for event in events))
                event_path.chmod(0o600)
                result = subprocess.run(
                    [sys.executable, "-c", validator, str(event_path), str(output_path), "companion_unavailable"],
                    text=True, capture_output=True, check=False,
                )
                if name == "closed_restart":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(output_path.is_file())
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("one successful native restart cleanup", result.stderr)
                    self.assertFalse(output_path.exists())

    def test_structural_verifier_status_and_payload_free_contract_remain_conservative(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")

        self.assertIn('"host_execution_status": "structural_input_only"', source)
        self.assertIn('"payloads_persisted": False', source)
        self.assertIn('"host_execution_evidence": "real_envoy_http1_client_observation"', source)
        self.assertIn('"verdict": "lifecycle_only_for_supported_cases_not_catalog_acceptance"', source)
        self.assertIn('"catalog_acceptance": False', source)
        self.assertIn('"p4_strict": "not_run_requires_client_visible_reset_or_abort_proof"', source)
        self.assertIn('"same_service_process_verified": True', source)
        self.assertNotIn('"same_service_process_start_token"', source)
        for forbidden in ("request_body", "response_body", "opaque_handle"):
            self.assertNotIn(f'"{forbidden}"', source)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
