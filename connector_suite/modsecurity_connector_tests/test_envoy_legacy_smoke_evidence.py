"""Executed contracts for the native two-request Envoy legacy evidence bridge."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = connector_root()
PRODUCER = '''#!/bin/sh
set -eu
exec "$PYTHON" - "$RUNTIME_ROOT" <<'PY_NATIVE_FIXTURE'
import json
import os
from pathlib import Path
import sys

runtime = Path(sys.argv[1])
mode = os.environ.get("FIXTURE_MODE", "pass")
(runtime / "invoked").write_text("native-producer")
if mode == "failure":
    raise SystemExit(23)
if mode == "blocked":
    raise SystemExit(77)
summary = {
    "status": "PASS", "integration_mode": "ext_authz",
    "allowed_request_status": "200", "blocked_request_status": "403",
    "rule_id": "1000001", "event_log": str(runtime / "events.jsonl"),
    "processes_stopped": "yes", "response_body_verified": "false",
    "production_ready": "false", "response_phase_smoke": "0",
    "terminal_authz_marker_stripped": "yes", "response_observer_started": "yes",
}
if mode == "not-stopped":
    summary["processes_stopped"] = "no"
summary_path = runtime / "runtime-summary.txt"
summary_path.write_text("".join(key + "=" + value + "\\n" for key, value in summary.items()))
if mode == "summary-only":
    raise SystemExit(0)
for filename, status in (("allow-client.json", 200), ("deny-client.json", 403)):
    probe = {
        "schema_version": 1, "evidence_type": "envoy_http_client_probe",
        "http_status": status, "response_bytes": 12,
        "body_payload_persisted": False, "redirect_location_verified": False,
        "composite_lease_header_present": False,
    }
    if mode == "wrong-http" and status == 200:
        probe["http_status"] = 403
    if mode == "float-http":
        probe["http_status"] = float(status)
    if mode == "payload":
        probe["body_payload_persisted"] = True
    path = runtime / filename
    path.write_text(json.dumps(probe))
    if mode == "stale":
        os.utime(path, ns=(1, 1))
    if mode == "symlink" and status == 200:
        actual = runtime / "other-probe"
        path.rename(actual)
        path.symlink_to(actual)
    if mode == "public" and status == 200:
        path.chmod(0o644)
event = {
    "connector": "envoy", "integration_mode": "ext_authz",
    "transaction_id": "envoy-block-1", "rule_id": "1000001",
    "phase": "request_headers", "status": "blocked", "action": "deny",
    "requested_action": "deny", "actual_action": "deny", "http_status": 403,
}
rows = [event]
if mode == "float-event":
    event["http_status"] = 403.0
if mode == "split-event":
    rows = [dict(event, transaction_id="foreign"), dict(event, rule_id="foreign")]
if mode == "wrong-event":
    event["actual_action"] = "allow"
event_path = runtime / "events.jsonl"
event_path.write_text("".join(json.dumps(row) + "\\n" for row in rows))
if mode == "duplicate-event-key":
    event_path.write_text('{"rule_id":"1000001","rule_id":"1000001"}\\n')
if mode == "duplicate-summary-key":
    with summary_path.open("a") as stream:
        stream.write("status=PASS\\n")
PY_NATIVE_FIXTURE
'''


class EnvoyLegacySmokeEvidenceTests(unittest.TestCase):
    def fixture(self, temporary):
        base = Path(temporary)
        checkout = base / "checkout"
        harness = checkout / "connectors/envoy/harness"
        harness.mkdir(parents=True)
        (checkout / "Makefile").write_text("# Fixed test repository boundary.\n")
        for relative in ("connectors/envoy/harness/run_envoy_smoke.sh",
                         "common/scripts/write_smoke_result.py", "ci/lib/runtime_path_utils.py",
                         "common/rules/modsecurity_targeted_smoke.conf"):
            destination = checkout / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        (harness / "run_envoy_connector_runtime.sh").write_text(PRODUCER)
        verified = base / "verified"
        verified.mkdir(mode=0o700)
        environment = dict(os.environ, VERIFIED_RUN_ROOT=str(verified),
                           PYTHON=sys.executable, PYTHONDONTWRITEBYTECODE="1")
        for key in ("BUILD_ROOT", "SOURCE_ROOT", "TMP_ROOT", "LOG_ROOT", "RESULTS_DIR", "CACHE_ROOT",
                    "VERIFIED_BUILD_ROOT", "VERIFIED_SOURCE_ROOT", "VERIFIED_TMP_ROOT", "VERIFIED_LOG_ROOT",
                    "VERIFIED_STATE_ROOT", "VERIFIED_COMPONENT_CACHE", "CONNECTOR_COMPONENT_CACHE",
                    "RUN_ONE_CASE", "TEST_CASE", "SMOKE_CASES", "MODSECURITY_TEST_VARIANT", "MODSECURITY_SMOKE_CASE",
                    "CRS_SMOKE_CASE", "RULES_FILE", "MSCONNECTOR_EXPECTED_RULE_ID", "MSCONNECTOR_RESPONSE_PHASE_SMOKE",
                    "MSCONNECTOR_NO_CRS_BASELINE", "MODSECURITY_RULESET"):
            environment.pop(key, None)
        return harness / "run_envoy_smoke.sh", verified, environment

    def execute(self, script, environment):
        return subprocess.run(["/bin/sh", str(script)], env=environment,
                              capture_output=True, text=True, timeout=20, check=False)

    def test_actual_producer_pair_writes_one_truthful_legacy_record(self):
        for smoke_case in ("", "targeted"):
            with self.subTest(smoke_case=smoke_case), tempfile.TemporaryDirectory() as temporary:
                script, verified, environment = self.fixture(temporary)
                environment["MODSECURITY_SMOKE_CASE"] = smoke_case
                result = self.execute(script, environment)
                self.assertEqual(result.returncode, 0, result.stderr)
                records = (verified / "build/results/envoy-results.jsonl").read_text().splitlines()
                self.assertEqual(len(records), 1)
                record = json.loads(records[0])
                self.assertEqual(record["allowed_request_status"], 200)
                self.assertEqual(record["blocked_request_status"], 403)
                self.assertEqual(record["decision_backend"], "libmodsecurity")
                self.assertEqual(record["modsecurity_rule_id"], "1000001")
                self.assertEqual(record["modsecurity_smoke_case"], "legacy-native-two-request")
                self.assertTrue(record["runtime_verified"])
                for key in ("production_ready", "full_matrix_ready", "crs_complete", "response_body_verified"):
                    self.assertFalse(record[key])
                self.assertNotIn("catalog_case", record)
                evidence = verified / "envoy-smoke"
                self.assertEqual((evidence / "runtime-result.json").read_bytes(), (evidence / "targeted-result.json").read_bytes())
                self.assertEqual((evidence / "runtime-result.json").stat().st_mode & 0o777, 0o600)
                self.assertEqual(len(list(evidence.glob("n.*/invoked"))), 1)

    def test_bad_native_observations_never_produce_pass(self):
        for mode in ("wrong-http", "summary-only", "not-stopped", "split-event", "wrong-event",
                     "duplicate-event-key", "duplicate-summary-key", "stale", "symlink", "public", "payload",
                     "float-http", "float-event"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                script, verified, environment = self.fixture(temporary)
                environment["FIXTURE_MODE"] = mode
                result = self.execute(script, environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((verified / "build/results/envoy-results.jsonl").exists())
                self.assertFalse((verified / "envoy-smoke/runtime-result.json").exists())

    def test_real_failure_exit_preserved_and_prior_pass_invalidated(self):
        for mode, code in (("failure", 23), ("blocked", 77)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                script, verified, environment = self.fixture(temporary)
                first = self.execute(script, environment)
                self.assertEqual(first.returncode, 0, first.stderr)
                environment["FIXTURE_MODE"] = mode
                second = self.execute(script, environment)
                self.assertEqual(second.returncode, code, second.stderr)
                self.assertFalse((verified / "build/results/envoy-results.jsonl").exists())
                self.assertFalse((verified / "envoy-smoke/runtime-result.json").exists())
                self.assertEqual(len(list((verified / "envoy-smoke").glob("n.*/invoked"))), 2)

    def test_unselected_catalog_body_crs_and_rules_never_run_native_pair(self):
        for changes in ({"RUN_ONE_CASE": "1"}, {"MSCONNECTOR_NO_CRS_BASELINE": "1"}, {"TEST_CASE": "foreign.yaml"},
                        {"MODSECURITY_TEST_VARIANT": "with-crs"}, {"MODSECURITY_RULESET": "crs"},
                        {"MODSECURITY_SMOKE_CASE": "request_body"},
                        {"MSCONNECTOR_RESPONSE_PHASE_SMOKE": "1"}, {"MSCONNECTOR_EXPECTED_RULE_ID": "1100001"},
                        {"RULES_FILE": "/foreign/rules.conf"}):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as temporary:
                script, verified, environment = self.fixture(temporary)
                environment.update(changes)
                result = self.execute(script, environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(list((verified / "envoy-smoke").glob("n.*/invoked")))
                self.assertFalse((verified / "build/results/envoy-results.jsonl").exists())

    def test_native_probes_persist_the_fixed_actual_observation_paths(self):
        source = (source_path('connectors/envoy/harness/run_envoy_connector_runtime.sh', root=ROOT)).read_text()
        self.assertIn('ALLOW_PROBE="$RUNTIME_ROOT/allow-client.json"', source)
        self.assertIn('DENY_PROBE="$RUNTIME_ROOT/deny-client.json"', source)
        self.assertIn('--evidence-path "$ALLOW_PROBE"', source)
        self.assertIn('--evidence-path "$DENY_PROBE"', source)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
