from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

from modsecurity_connector_tests.framework_test_trust import trusted_framework_root


ROOT = connector_root()
FRAMEWORK_ROOT = Path(
    os.environ.get("PARENT_TEST_FRAMEWORK_ROOT", source_path('modules/ModSecurity-test-Framework', root=ROOT))
)
collector = load_source(source_path('ci/runtime/lifecycle/collect-no-crs-source.py', root=ROOT))

traefik_smoke = load_source(source_path('connectors/traefik/scripts/runtime_smoke.py', root=ROOT))


def load_trusted_framework_baseline(test_case: unittest.TestCase) -> object:
    framework_root, error = trusted_framework_root(ROOT, FRAMEWORK_ROOT)
    if framework_root is None:
        test_case.skipTest(error)
    assert framework_root is not None
    module = load_source(framework_root / 'ci' / 'checks' / 'catalog' / 'no_crs_baseline.py')
    return module


class CollectNoCrsSourceTest(unittest.TestCase):
    def _apache_host_version(self, stdout: str, stderr: str, exit_code: int) -> subprocess.CompletedProcess[str]:
        source = (source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=ROOT)).read_text(encoding="utf-8")
        inventory = source.split('if [ -n "$host_binary" ] && [ -x "$host_binary" ]; then', 1)[1].split(
            "\nlibmodsecurity_version=", 1
        )[0]
        with tempfile.TemporaryDirectory(prefix="apache-host-version-") as temporary:
            binary = Path(temporary) / "httpd"
            binary.write_text(
                "#!/bin/sh\n"
                'test "$#" -eq 1 && test "$1" = -v || exit 91\n'
                f"printf '%s' {shlex.quote(stdout)}\n"
                f"printf '%s' {shlex.quote(stderr)} >&2\n"
                f"exit {exit_code}\n",
                encoding="utf-8",
            )
            binary.chmod(0o700)
            environment = {
                **os.environ,
                "connector": "apache",
                "host_binary": str(binary),
                "host_version": "not_provisioned",
                "PYTHON": sys.executable,
            }
            command = 'if [ -n "$host_binary" ] && [ -x "$host_binary" ]; then' + inventory
            command += '\nprintf "%s\\n" "$host_version"\n'
            return subprocess.run(
                ["/bin/sh", "-eu", "-c", command],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

    def test_apache_host_version_uses_native_stdout_despite_loader_warning(self) -> None:
        warning = "libpcre2-8.so.0: no version information available\n"
        result = self._apache_host_version(
            "Server version: Apache/2.4.68 (Unix)\nServer built: Oct 3 2026\n", warning, 0
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "Server version: Apache/2.4.68 (Unix)\n")
        self.assertIn(warning, result.stderr)

    def test_apache_host_version_preserves_binary_failure_and_rejects_invalid_output(self) -> None:
        scenarios = (
            ("Server version: Apache/2.4.68 (Unix)\n", "native failure\n", 7, 7),
            ("", "", 0, 2),
            ("libpcre2-8.so.0: no version information available\n", "", 0, 2),
            ("Server version: nginx/1.31.6\n", "", 0, 2),
            ("Server version: Apache/invalid\n", "", 0, 2),
            ("Server version: Apache/٢.4.68\n", "", 0, 2),
            ("Server version: Apache/2.٤.68\n", "", 0, 2),
            ("Server version: Apache/2.4.٦٨\n", "", 0, 2),
            ("Server version: Apache/2.4.68\nServer version: Apache/2.4.69\n", "", 0, 2),
            ("Server version: Apache/2.4.68\nServer version: nginx/1.31.6\n", "", 0, 2),
        )
        for stdout, stderr, exit_code, expected_code in scenarios:
            with self.subTest(stdout=stdout, exit_code=exit_code):
                result = self._apache_host_version(stdout, stderr, exit_code)
                self.assertEqual(result.returncode, expected_code)
                self.assertEqual(result.stdout, "")
                self.assertIn("FAIL: Apache host", result.stderr)

    def test_nonpromoted_native_host_is_not_reclassified_as_source_failure(self) -> None:
        self.assertTrue(
            collector.nonpromoted_host_success(
                [
                    {
                        "status": "PASS",
                        "capability_promotion": "not_permitted",
                        "integration_mode": "native-traefik-middleware",
                    }
                ]
            )
        )
        self.assertFalse(
            collector.nonpromoted_host_success([{"status": "PASS"}])
        )
        self.assertFalse(
            collector.nonpromoted_host_success(
                [{"status": "FAIL", "capability_promotion": "not_permitted"}]
            )
        )

    def test_not_executable_harness_case_is_canonical_not_executed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-collector-") as temporary:
            source = Path(temporary) / "cases.jsonl"
            source.write_text(
                json.dumps({
                    "case_id": "allow_without_marker",
                    "status": "not_executable",
                    "live_executed": False,
                }) + "\n",
                encoding="utf-8",
            )
            cases, _ = collector.case_observations(
                [source],
                "nginx",
                "1100001",
                {"allow_without_marker": (200, None)},
            )
            self.assertEqual(cases[0]["status"], "NOT_EXECUTED")
            self.assertTrue(collector.only_nonexecuted_cases(cases))

    def test_explicit_terminal_statuses_keep_their_existing_precedence(self) -> None:
        expected_statuses = {
            "NOT_EXECUTABLE": "NOT_EXECUTED",
            "SKIPPED": "NOT_EXECUTED",
            "BLOCKED": "BLOCKED",
            "UNSUPPORTED": "UNSUPPORTED",
            "NOT_APPLICABLE": "NOT_APPLICABLE",
            "NOT_EXECUTED": "NOT_EXECUTED",
            "PASS": "PASS",
        }
        with tempfile.TemporaryDirectory(prefix="no-crs-terminal-status-") as temporary:
            source = Path(temporary) / "cases.jsonl"
            for source_status, expected_status in expected_statuses.items():
                with self.subTest(source_status=source_status):
                    source.write_text(
                        json.dumps(
                            {
                                "case_id": "allow_without_marker",
                                "status": source_status,
                                "actual_status": 200,
                                "live_executed": source_status == "PASS",
                            }
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    cases, _ = collector.case_observations(
                        [source],
                        "nginx",
                        "1100001",
                        {"allow_without_marker": (200, None)},
                    )
                    self.assertEqual(cases[0]["status"], expected_status)

    def test_native_rule_engine_summary_keeps_explicit_case_evidence(self) -> None:
        summary = {
            "status": "PASS",
            "capability_promotion": "not_permitted",
            "common_runtime_bridge": True,
            "rule_evaluation": "libmodsecurity",
            "allowed_request_status": 200,
            "phase1_deny_status": 403,
            "p1_alternative_status": 429,
            "phase2_deny_status": 403,
            "phase3_deny_client_status": 403,
            "phase3_redirect_status": 302,
            "phase4_rule_observed_status": 200,
            "phase4_safe_status": 200,
            "phase4_end_of_stream_evaluation_status": 200,
            "phase4_first_byte_before_response_end_status": 200,
            "phase4_no_full_response_buffering_status": 200,
        }
        self.assertTrue(collector.native_rule_engine_observed([summary]))
        self.assertFalse(collector.nonpromoted_host_success([summary]))
        records = {
            record["case_id"]: record
            for record in collector.native_host_summary_cases([summary])
        }
        self.assertEqual(records["allow_without_marker"]["actual_status"], 200)
        self.assertEqual(records["deny_header_marker_403"]["observed_rule_ids"], [1100001])
        self.assertEqual(
            records["deny_with_alternative_status"]["observed_rule_ids"], [1100002]
        )
        self.assertEqual(records["deny_request_body_marker_403"]["observed_rule_ids"], [1100101])
        self.assertEqual(records["deny_response_header_marker_403"]["observed_rule_ids"], [1100201])
        self.assertEqual(records["phase3_redirect_before_commit"]["observed_rule_ids"], [1100202])
        self.assertEqual(records["phase4_rule_observed"]["observed_rule_ids"], [1100301])
        self.assertEqual(
            records["phase4_deny_after_commit_log_only_safe"]["observed_rule_ids"],
            [1100301],
        )
        for case_id in (
            "phase4_end_of_stream_evaluation",
            "phase4_first_byte_before_response_end",
            "phase4_no_full_response_buffering",
        ):
            with self.subTest(case_id=case_id):
                self.assertEqual(records[case_id]["observed_rule_ids"], [1100301])

    def test_native_summary_without_engine_bridge_stays_nonpromoting(self) -> None:
        summary = {
            "status": "PASS",
            "capability_promotion": "not_permitted",
            "p1_allow_status": 200,
            "p1_deny_status": 403,
        }
        self.assertFalse(collector.native_rule_engine_observed([summary]))
        self.assertEqual(collector.native_host_summary_cases([summary]), [])
        self.assertTrue(collector.nonpromoted_host_success([summary]))

    def test_raw_source_event_payload_field_invalidates_absence_claim(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-collector-") as temporary:
            event_path = Path(temporary) / "events.jsonl"
            event_path.write_text(
                json.dumps(
                    {
                        "connector": "apache",
                        "transaction_id": "tx-1",
                        "rule_id": 1100001,
                        "phase": 1,
                        "status": "blocked",
                        "request_body": "no-crs-request-body-marker",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            evidence = collector.event_evidence([event_path], "1100001", [])
            self.assertFalse(evidence["body_payload_absent_from_events"])
            self.assertFalse(evidence["event_metadata_verified"])
            self.assertTrue(evidence["forbidden_event_keys"])
            self.assertEqual(evidence["records"], [])

    def test_unknown_raw_event_field_invalidates_absence_claim(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-collector-") as temporary:
            event_path = Path(temporary) / "events.jsonl"
            event_path.write_text(
                json.dumps(
                    {
                        "connector": "apache",
                        "transaction_id": "tx-unknown-field",
                        "rule_id": 1100001,
                        "phase": 1,
                        "status": "blocked",
                        "data": "arbitrary-full-request-body",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            evidence = collector.event_evidence([event_path], "1100001", [])
            self.assertFalse(evidence["body_payload_absent_from_events"])
            self.assertFalse(evidence["event_metadata_verified"])
            self.assertIn("unapproved-field:data", evidence["forbidden_event_keys"][0])
            self.assertEqual(evidence["records"], [])

    def test_metadata_only_haproxy_decision_schema_is_accepted(self) -> None:
        record = {
            "timestamp": 1,
            "connector": "haproxy",
            "mode": "block",
            "runtime_mode": "test",
            "variant": "no-crs",
            "case": "deny_header_marker_403",
            "request_id": "tx-haproxy",
            "transaction_id": "tx-haproxy",
            "phase": 1,
            "live_executed": True,
            "modsecurity_processed": True,
            "request_headers_seen": True,
            "request_body_seen": False,
            "response_headers_seen": False,
            "response_body_seen": False,
            "expected_status": 403,
            "observed_status": "",
            "result": "",
            "decision": "deny",
            "disruptive": True,
            "intervention_status": 403,
            "redirect_present": False,
            "rule_id": 1100001,
            "anomaly_score": 0,
            "audit_log_path": "/tmp/audit.log",
            "haproxy_log_path": "",
            "spoa_log_path": "/tmp/spoa.log",
            "reason_code": "modsecurity_disruptive_intervention",
            "reason": "modsecurity_disruptive_intervention",
        }
        evidence = collector.event_evidence([], "1100001", [record])
        self.assertTrue(evidence["body_payload_absent_from_events"])
        self.assertTrue(evidence["event_metadata_verified"])
        self.assertEqual(evidence["forbidden_event_keys"], [])

    def test_native_htx_observer_metadata_is_payload_free(self) -> None:
        record = {
            "connector": "haproxy",
            "event": "htx_observed_intervention",
            "message_id": "HAPROXY_HTX_OBSERVED_INTERVENTION",
            "integration_mode": "native_htx_filter",
            "evaluation_mode": "observer_nonpromoted",
            "rule_evaluation": "libmodsecurity_observed",
            "transaction_id": "haproxy-htx-phase4",
            "case": "phase4",
            "phase": 4,
            "rule_id": 910004,
            "status": "not_attempted",
            "requested_action": "deny",
            "host_action": "not_attempted",
            "observed_client_status": 200,
            "payload_recorded": False,
        }
        evidence = collector.event_evidence([], "910004", [record])
        self.assertTrue(evidence["body_payload_absent_from_events"])
        self.assertEqual(evidence["forbidden_event_keys"], [])
        canonical_event = collector.sanitized_event(record)
        self.assertEqual(canonical_event["connector"], "haproxy")
        self.assertEqual(canonical_event["integration_mode"], "native_htx_filter")
        self.assertEqual(canonical_event["status"], "not_attempted")
        self.assertEqual(
            load_trusted_framework_baseline(self).canonical_event_errors(
                canonical_event,
                connector="haproxy",
            ),
            [],
        )

    def test_phase4_aliases_are_projected_without_status_conflation(self) -> None:
        event = collector.sanitized_event(
            {
                "connector": "nginx",
                "transaction_id": "tx-phase4",
                "rule_id": 1100301,
                "phase": "response_body",
                "waf_status": 403,
                "upstream_status": 200,
                "client_status": 200,
                "wanted_action": "deny",
                "actual_action": "connection_abort",
                "intervention": True,
                "header_sent": True,
                "response_body_seen": True,
                "strict_abort": True,
                "response_committed": True,
                "observed_transport_result": "connection_aborted",
            }
        )
        self.assertEqual(event["phase"], 4)
        self.assertEqual(event["http_status"], 403)
        self.assertEqual(event["original_http_status"], 200)
        self.assertEqual(event["visible_http_status"], 200)
        self.assertEqual(event["requested_action"], "deny")
        self.assertEqual(event["actual_action"], "abort_connection")
        self.assertTrue(event["late_intervention"])
        self.assertTrue(event["headers_sent"])
        self.assertTrue(event["body_started"])
        self.assertTrue(event["connection_aborted"])
        self.assertEqual(event["transport_result"], "connection_aborted")

    def test_transport_lifecycle_metadata_is_allowlisted_and_bounded(self) -> None:
        event = collector.sanitized_event(
            {
                "connector": "nginx",
                "transaction_id": "tx-transport-1",
                "phase": 4,
                "transport_case_id": "transport-case-1",
                "requested_protocol": "h2",
                "downstream_protocol": "h2",
                "upstream_protocol": "http1",
                "negotiated_protocol": "h2",
                "transport": "tls_tcp",
                "stream_id": 1,
                "stream_reset": True,
                "reset_by": "strict_intervention",
                "reset_code": "CANCEL",
                "timeout_stage": "after_commit",
                "write_result": "short_write",
                "cleanup_reason": "strict_abort",
                "eos_seen": True,
                "client_disconnected": False,
                "upstream_disconnected": False,
                "cancelled": False,
            }
        )
        self.assertEqual(event["transport_case_id"], "transport-case-1")
        self.assertEqual(event["negotiated_protocol"], "h2")
        self.assertEqual(event["transport"], "tls_tcp")
        self.assertEqual(event["reset_by"], "strict_intervention")
        self.assertEqual(event["write_result"], "short_write")
        self.assertTrue(event["eos_seen"])

    def test_synchronized_first_byte_metadata_is_allowlisted_without_payload(self) -> None:
        event = collector.sanitized_event(
            {
                "connector": "nginx",
                "run_id": "nginx-current-run",
                "transaction_id": "tx-first-byte",
                "rule_id": 1100301,
                "phase": "response_body",
                "status": "blocked",
                "client_first_byte_received": True,
                "first_chunk_size": 17,
                "upstream_paused": True,
                "upstream_eos_sent_at_first_byte": False,
                "first_byte_before_response_end": True,
                "upstream_response_finished_at_first_byte": False,
                "no_full_response_buffering": True,
                "body_bytes_seen": 17,
                "body_bytes_inspected": 17,
            }
        )
        self.assertTrue(event["client_first_byte_received"])
        self.assertEqual(event["first_chunk_size"], 17)
        self.assertTrue(event["upstream_paused"])
        self.assertFalse(event["upstream_eos_sent_at_first_byte"])
        self.assertTrue(event["first_byte_before_response_end"])
        self.assertFalse(event["upstream_response_finished_at_first_byte"])
        self.assertTrue(event["no_full_response_buffering"])
        self.assertEqual(event["run_id"], "nginx-current-run")
        self.assertEqual(event["body_bytes_seen"], 17)
        self.assertEqual(event["body_bytes_inspected"], 17)

    def test_real_host_barrier_only_enriches_observed_phase4_event(self) -> None:
        evidence = {
            "evidence_type": "synchronized_first_byte",
            "evidence_origin": "real_host",
            "promotion_eligible": True,
            "outcome": "PASS",
            "body_payload_persisted": False,
            "client_first_byte_received": True,
            "first_byte_before_response_end": True,
            "first_chunk_size": 17,
            "upstream_paused": True,
            "upstream_eos_sent_at_first_byte": False,
            "upstream_response_finished_at_first_byte": False,
            "response_committed": True,
            "body_bytes_seen": 42,
            "body_bytes_inspected": 42,
            "no_full_response_buffering": True,
            "connector_owned_full_response_buffer": False,
        }
        records = collector.merge_first_byte_evidence(
            [
                {"phase": 1, "rule_id": 1100001},
                {"phase": "response_body", "rule_id": 1100301,
                 "body_bytes_seen": 42, "body_bytes_inspected": 42},
            ],
            evidence,
        )
        self.assertNotIn("first_byte_before_response_end", records[0])
        self.assertTrue(records[1]["first_byte_before_response_end"])
        self.assertTrue(records[1]["no_full_response_buffering"])
        self.assertEqual(records[1]["body_bytes_seen"], 42)

    def test_response_status_is_not_dual_mapped_to_original_and_visible(self) -> None:
        event = collector.sanitized_event({"response_status": 200})
        self.assertNotIn("original_http_status", event)
        self.assertNotIn("visible_http_status", event)
        self.assertNotIn("http_status", event)

    def test_phase4_case_keeps_runtime_semantics_from_event(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-phase4-") as temporary:
            root = Path(temporary)
            phase4_path = root / "phase4.jsonl"
            phase4_path.write_text(
                json.dumps(
                    {
                        "connector": "nginx",
                        "transaction_id": "tx-phase4",
                        "event": "phase4_intervention",
                        "message_id": "MSCONN_EVENT_PHASE4_LATE_INTERVENTION",
                        "phase": "response_body",
                        "status": "blocked",
                        "rule_id": "1100301",
                        "http_status": 403,
                        "original_http_status": 200,
                        "visible_http_status": 200,
                        "requested_action": "deny",
                        "actual_action": "log_only",
                        "late_intervention": True,
                        "late_intervention_mode": "safe",
                        "headers_sent": True,
                        "body_started": True,
                        "connection_aborted": False,
                        "response_committed": True,
                        "transport_result": "log_only",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            results_path = root / "results.jsonl"
            results_path.write_text(
                json.dumps(
                    {
                        "case_id": "phase4_deny_after_commit_log_only",
                        "status": "PASS",
                        "live_executed": True,
                        "actual_status": 200,
                        "connector_phase4_log_path": str(phase4_path),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            cases, _ = collector.case_observations(
                [results_path],
                "nginx",
                "1100001",
                {
                    "phase4_deny_after_commit_log_only": (None, "1100301", 4),
                    "phase4_deny_after_commit_log_only_safe": (None, "1100301", 4),
                },
                allowed_source_root=root,
            )
            self.assertEqual(len(cases), 2)
            by_id = {case["case_id"]: case for case in cases}
            case = by_id["phase4_deny_after_commit_log_only"]
            self.assertEqual(case["status"], "PASS")
            self.assertTrue(case["event_metadata_verified"])
            self.assertEqual(case["requested_action"], "deny")
            self.assertEqual(case["actual_action"], "log_only")
            self.assertEqual(case["late_intervention_mode"], "safe")
            self.assertEqual(case["http_status"], 403)
            self.assertEqual(case["visible_http_status"], 200)
            safe_alias = by_id["phase4_deny_after_commit_log_only_safe"]
            self.assertEqual(safe_alias["status"], "PASS")
            self.assertEqual(safe_alias["transaction_ids"], ["tx-phase4"])
            self.assertIn("reused native nginx event", safe_alias["reason"])

    def test_native_runner_safe_alias_requires_safe_event_semantics(self) -> None:
        safe_event = {
            "phase": 4,
            "rule_id": 1100301,
            "requested_action": "deny",
            "actual_action": "log_only",
            "late_intervention": True,
            "late_intervention_mode": "safe",
            "headers_sent": True,
            "body_started": True,
            "response_committed": True,
            "connection_aborted": False,
            "http_status": 403,
            "original_http_status": 200,
            "visible_http_status": 200,
            "transport_result": "log_only",
        }
        self.assertEqual(
            collector.native_runner_core_case_alias(
                "apache", "phase4_deny_after_commit_log_only", [safe_event]
            ),
            "phase4_deny_after_commit_log_only_safe",
        )
        unsafe_event = dict(safe_event, late_intervention_mode="minimal")
        self.assertIsNone(
            collector.native_runner_core_case_alias(
                "apache", "phase4_deny_after_commit_log_only", [unsafe_event]
            )
        )

    def test_native_runner_aliases_normalize_native_string_phase_and_rule_ids(self) -> None:
        apache_phase3_event = {
            "phase": "response_headers",
            "rule_id": "1100201",
            "requested_action": "deny",
            "actual_action": "deny",
            "headers_sent": False,
            "visible_http_status": 403,
            "late_intervention": False,
            "transport_result": "http_status",
        }
        nginx_phase4_event = {
            "phase": "response_body",
            "rule_id": "1100301",
            "requested_action": "deny",
            "actual_action": "log_only",
            "late_intervention": True,
            "late_intervention_mode": "safe",
            "headers_sent": True,
            "body_started": True,
            "response_committed": True,
            "connection_aborted": False,
            "http_status": 403,
            "original_http_status": 200,
            "visible_http_status": 200,
            "transport_result": "log_only",
        }
        self.assertEqual(
            collector.native_runner_core_case_alias(
                "apache", "phase3_deny_before_commit", [apache_phase3_event]
            ),
            "deny_response_header_marker_403",
        )
        self.assertEqual(
            collector.native_runner_core_case_alias(
                "nginx", "phase4_deny_after_commit_log_only", [nginx_phase4_event]
            ),
            "phase4_deny_after_commit_log_only_safe",
        )
        self.assertIsNone(
            collector.native_runner_core_case_alias(
                "nginx",
                "phase4_deny_after_commit_log_only",
                [dict(nginx_phase4_event, late_intervention_mode="minimal")],
            )
        )

    def test_phase4_rejects_an_unknown_late_intervention_mode(self) -> None:
        event = collector.sanitized_event(
            {
                "phase": "response_body",
                "late_intervention": True,
                "late_intervention_mode": "late-403",
            }
        )
        self.assertTrue(event["late_intervention"])
        self.assertNotIn("late_intervention_mode", event)
        self.assertNotIn(
            "late_intervention_mode", collector.canonical_semantics([event])
        )

    def test_phase3_precommit_case_keeps_header_status_metadata(self) -> None:
        catalog = FRAMEWORK_ROOT / "tests/cases/no-crs-baseline/catalog.json"
        expectations, runner_case_index = collector.catalog_contract(catalog)
        with tempfile.TemporaryDirectory(prefix="no-crs-phase3-") as temporary:
            root = Path(temporary)
            phase3_path = root / "phase3.jsonl"
            phase3_path.write_text(
                json.dumps(
                    {
                        "connector": "apache",
                        "transaction_id": "tx-phase3",
                        "event": "phase3_intervention",
                        "message_id": "MSCONN_EVENT_RESPONSE_BLOCKED",
                        "phase": "response_headers",
                        "status": "blocked",
                        "rule_id": "1100201",
                        "http_status": 403,
                        "original_http_status": 200,
                        "visible_http_status": 403,
                        "requested_action": "deny",
                        "actual_action": "deny",
                        "late_intervention": False,
                        "headers_sent": False,
                        "connection_aborted": False,
                        "response_committed": False,
                        "transport_result": "http_status",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            results_path = root / "results.jsonl"
            results_path.write_text(
                json.dumps(
                    {
                        "name": "phase3_deny_before_commit_fixture",
                        "path": str(
                            catalog.parent
                            / "full-lifecycle/phase3_deny_before_commit.yaml"
                        ),
                        "status": "PASS",
                        "live_executed": True,
                        "actual_status": 403,
                        "connector_phase4_log_path": str(phase3_path),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            cases, _ = collector.case_observations(
                [results_path],
                "apache",
                "1100001",
                expectations,
                allowed_source_root=root,
                runner_case_index=runner_case_index,
            )
            self.assertEqual(len(cases), 2)
            by_id = {case["case_id"]: case for case in cases}
            case = by_id["phase3_deny_before_commit"]
            self.assertEqual(case["case_id"], "phase3_deny_before_commit")
            self.assertEqual(case["status"], "PASS")
            self.assertTrue(case["event_metadata_verified"])
            self.assertEqual(case["requested_action"], "deny")
            self.assertEqual(case["actual_action"], "deny")
            self.assertFalse(case["headers_sent"])
            self.assertEqual(case["visible_http_status"], 403)
            core_alias = by_id["deny_response_header_marker_403"]
            self.assertEqual(core_alias["status"], "PASS")
            self.assertEqual(core_alias["transaction_ids"], ["tx-phase3"])
            self.assertIn("reused native apache event", core_alias["reason"])

    def test_case_event_evidence_is_bound_to_its_declared_transaction(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-transaction-binding-") as temporary:
            root = Path(temporary)
            decision_path = root / "events.jsonl"
            decision_path.write_text(
                "\n".join(
                    json.dumps(event)
                    for event in (
                        {
                            "connector": "lighttpd",
                            "run_id": "lighttpd-current-run",
                            "transaction_id": "tx-real",
                            "event": "MSCONN_EVENT_RESPONSE_BLOCKED",
                            "message_id": "MSCONN_EVENT_RESPONSE_BLOCKED",
                            "rule_id": 1100201,
                            "phase": "response_headers",
                            "status": "blocked",
                            "http_status": 403,
                            "original_http_status": 200,
                            "visible_http_status": 403,
                            "requested_action": "deny",
                            "actual_action": "deny",
                            "headers_sent": False,
                            "connection_aborted": False,
                            "transport_result": "http_status",
                        },
                        {
                            "connector": "lighttpd",
                            "transaction_id": "tx-other",
                            "event": "MSCONN_EVENT_RESPONSE_BLOCKED",
                            "message_id": "MSCONN_EVENT_RESPONSE_BLOCKED",
                            "rule_id": 1100201,
                            "phase": "response_headers",
                            "status": "blocked",
                            "http_status": 403,
                            "original_http_status": 200,
                            "visible_http_status": 200,
                            "requested_action": "deny",
                            "actual_action": "deny",
                            "headers_sent": True,
                            "connection_aborted": False,
                            "transport_result": "http_status",
                        },
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            results_path = root / "results.jsonl"
            results_path.write_text(
                json.dumps(
                    {
                        "case_id": "phase3_deny_before_commit",
                        "status": "PASS",
                        "live_executed": True,
                        "actual_status": 403,
                        "transaction_ids": ["tx-real"],
                        "decision_log_path": str(decision_path),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            cases, derived = collector.case_observations(
                [results_path],
                "lighttpd",
                "1100001",
                {"phase3_deny_before_commit": (403, "1100201", 3)},
                allowed_source_root=root,
            )
            self.assertEqual(cases[0]["status"], "PASS")
            self.assertEqual(cases[0]["transaction_ids"], ["tx-real"])
            self.assertFalse(cases[0]["headers_sent"])
            self.assertEqual(len(derived), 1)
            self.assertEqual(derived[0]["run_id"], "lighttpd-current-run")

    def test_case_cannot_borrow_another_transaction_event(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-transaction-mismatch-") as temporary:
            root = Path(temporary)
            decision_path = root / "events.jsonl"
            decision_path.write_text(
                json.dumps(
                    {
                        "connector": "lighttpd",
                        "transaction_id": "tx-other",
                        "event": "MSCONN_EVENT_RESPONSE_BLOCKED",
                        "message_id": "MSCONN_EVENT_RESPONSE_BLOCKED",
                        "rule_id": 1100201,
                        "phase": "response_headers",
                        "status": "blocked",
                        "http_status": 403,
                        "visible_http_status": 403,
                        "requested_action": "deny",
                        "actual_action": "deny",
                        "headers_sent": False,
                        "connection_aborted": False,
                        "transport_result": "http_status",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            results_path = root / "results.jsonl"
            results_path.write_text(
                json.dumps(
                    {
                        "case_id": "phase3_deny_before_commit",
                        "status": "PASS",
                        "live_executed": True,
                        "actual_status": 403,
                        "transaction_ids": ["tx-real"],
                        "decision_log_path": str(decision_path),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            cases, _ = collector.case_observations(
                [results_path],
                "lighttpd",
                "1100001",
                {"phase3_deny_before_commit": (403, "1100201", 3)},
                allowed_source_root=root,
            )
            self.assertEqual(cases[0]["status"], "FAIL")
            self.assertFalse(cases[0]["event_metadata_verified"])
            self.assertEqual(cases[0]["transaction_ids"], [])

    def test_honest_not_executed_case_stays_not_executed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-not-executed-") as temporary:
            root = Path(temporary)
            results_path = root / "results.jsonl"
            results_path.write_text(
                json.dumps(
                    {
                        "case_id": "phase3_deny_before_commit",
                        "status": "NOT_EXECUTED",
                        "live_executed": False,
                        "reason": "host API has no tested response hook",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            cases, _ = collector.case_observations(
                [results_path],
                "lighttpd",
                "1100001",
                {"phase3_deny_before_commit": (403, "1100201", 3)},
                allowed_source_root=root,
            )
            self.assertEqual(cases[0]["status"], "NOT_EXECUTED")
            self.assertFalse(cases[0]["event_metadata_verified"])

    def test_catalog_runner_case_mapping_does_not_guess_from_fixture_name(self) -> None:
        catalog = FRAMEWORK_ROOT / "tests/cases/no-crs-baseline/catalog.json"
        expectations, runner_case_index = collector.catalog_contract(catalog)
        with tempfile.TemporaryDirectory(prefix="no-crs-runner-name-") as temporary:
            root = Path(temporary)
            results_path = root / "results.jsonl"
            results_path.write_text(
                json.dumps(
                    {
                        "name": "phase3_deny_before_commit_fixture",
                        "status": "PASS",
                        "live_executed": True,
                        "actual_status": 403,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            cases, _ = collector.case_observations(
                [results_path],
                "nginx",
                "1100001",
                expectations,
                allowed_source_root=root,
                runner_case_index=runner_case_index,
            )
            self.assertEqual(cases, [])

    def test_catalog_runner_case_mapping_rejects_duplicate_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-catalog-") as temporary:
            root = Path(temporary)
            (root / "runner.yaml").write_text("name: runner\n", encoding="utf-8")
            catalog = root / "catalog.json"
            catalog.write_text(
                json.dumps(
                    {
                        "cases": [
                            {"case_id": "first", "runner_case": "runner.yaml"},
                            {"case_id": "second", "runner_case": "runner.yaml"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "runner_case is not unique"):
                collector.catalog_contract(catalog)

    def test_phase4_case_rejects_audit_log_as_event_fallback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-phase4-audit-") as temporary:
            root = Path(temporary)
            audit_path = root / "audit.log"
            audit_path.write_text(
                '[id "1100301"] (phase 4) [unique_id "tx-audit-phase4"]\n',
                encoding="utf-8",
            )
            results_path = root / "results.jsonl"
            results_path.write_text(
                json.dumps(
                    {
                        "case_id": "phase4_rule_observed",
                        "status": "PASS",
                        "live_executed": True,
                        "actual_status": 200,
                        "audit_log_path": str(audit_path),
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            cases, events = collector.case_observations(
                [results_path],
                "apache",
                "1100001",
                {"phase4_rule_observed": (None, "1100301")},
                allowed_source_root=root,
            )

            self.assertEqual(events, [])
            self.assertEqual(cases[0]["status"], "FAIL")
            self.assertFalse(cases[0]["event_metadata_verified"])

    def test_structured_request_event_suppresses_weaker_audit_fallback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-structured-request-") as temporary:
            root = Path(temporary)
            event_path = root / "native-events.jsonl"
            event_path.write_text(
                json.dumps(
                    {
                        "connector": "apache",
                        "integration_mode": "native-httpd-module",
                        "event": "MSCONN_EVENT_REQUEST_BLOCKED",
                        "message_id": "MSCONN_EVENT_REQUEST_BLOCKED",
                        "transaction_id": "tx-native-p1",
                        "rule_id": 1100001,
                        "phase": 1,
                        "status": "blocked",
                        "http_status": 403,
                        "visible_http_status": 403,
                        "requested_action": "deny",
                        "actual_action": "deny",
                        "transport_result": "http_status",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            audit_path = root / "audit.log"
            audit_path.write_text(
                '[id "1100001"] (phase 1) [unique_id "tx-native-p1"]\n',
                encoding="utf-8",
            )
            results_path = root / "results.jsonl"
            results_path.write_text(
                json.dumps(
                    {
                        "case_id": "deny_header_marker_403",
                        "status": "PASS",
                        "live_executed": True,
                        "actual_status": 403,
                        "transaction_id": "tx-native-p1",
                        "decision_log_path": str(event_path),
                        "audit_log_path": str(audit_path),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            cases, derived = collector.case_observations(
                [results_path], "apache", "1100001", allowed_source_root=root
            )
            self.assertEqual(cases[0]["status"], "PASS")
            self.assertEqual(len(derived), 1)
            self.assertEqual(derived[0]["integration_mode"], "native-httpd-module")

    def test_traefik_runtime_output_rejects_symlink_before_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="traefik-output-") as temporary:
            root = Path(temporary)
            victim = root / "victim"
            victim.mkdir()
            marker = victim / "keep.txt"
            marker.write_text("keep\n", encoding="utf-8")
            output = root / "runtime-output"
            output.symlink_to(victim, target_is_directory=True)
            with self.assertRaises(traefik_smoke.MissingDependency):
                traefik_smoke.assert_no_symlink_components(output)
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep\n")

    def test_decision_log_is_audited_before_metadata_sanitization(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-collector-") as temporary:
            root = Path(temporary)
            decision_path = root / "decision.jsonl"
            decision_path.write_text(
                json.dumps(
                    {
                        "connector": "apache",
                        "transaction_id": "tx-2",
                        "rule_id": 1100001,
                        "phase": 1,
                        "status": "blocked",
                        "request_body": "no-crs-request-body-marker",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            results_path = root / "results.jsonl"
            results_path.write_text(
                json.dumps(
                    {
                        "case_id": "deny_header_marker_403",
                        "status": "PASS",
                        "live_executed": True,
                        "actual_status": 403,
                        "decision_log_path": str(decision_path),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            cases, derived = collector.case_observations(
                [results_path], "apache", "1100001"
            )
            self.assertEqual(cases[0]["status"], "PASS")
            evidence = collector.event_evidence([], "1100001", derived)
            self.assertFalse(evidence["body_payload_absent_from_events"])
            self.assertFalse(evidence["event_metadata_verified"])
            self.assertTrue(evidence["forbidden_event_keys"])

    def test_source_event_path_must_belong_to_current_raw_run(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-run-") as temporary:
            root = Path(temporary)
            raw_run = root / "raw-run"
            raw_run.mkdir()
            outside = root / "previous-run-event.jsonl"
            outside.write_text("{}\n", encoding="utf-8")
            results_path = raw_run / "results.jsonl"
            results_path.write_text(
                json.dumps(
                    {
                        "case_id": "deny_header_marker_403",
                        "status": "PASS",
                        "live_executed": True,
                        "actual_status": 403,
                        "decision_log_path": str(outside),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "outside the allowed run root"):
                collector.case_observations(
                    [results_path],
                    "apache",
                    "1100001",
                    allowed_source_root=raw_run,
                )

    def test_consumed_run_local_event_is_scrubbed_after_normalization(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-run-") as temporary:
            raw_run = Path(temporary)
            decision_path = raw_run / "decision.jsonl"
            decision_path.write_text(
                json.dumps(
                    {
                        "connector": "haproxy",
                        "transaction_id": "tx-current-run",
                        "rule_id": 1100001,
                        "phase": 1,
                        "status": "blocked",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            results_path = raw_run / "results.jsonl"
            results_path.write_text(
                json.dumps(
                    {
                        "case_id": "deny_header_marker_403",
                        "status": "PASS",
                        "live_executed": True,
                        "actual_status": 403,
                        "decision_log_path": str(decision_path),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            consumed: list[Path] = []
            cases, derived = collector.case_observations(
                [results_path],
                "haproxy",
                "1100001",
                allowed_source_root=raw_run,
                consumed_event_paths=consumed,
            )
            self.assertEqual(cases[0]["status"], "PASS")
            self.assertEqual(len(derived), 1)
            scrub_log = raw_run / "source-event-scrub.log"
            removed = collector.scrub_source_event_paths(consumed, raw_run, scrub_log)
            self.assertEqual(removed, [decision_path])
            self.assertFalse(decision_path.exists())
            self.assertIn(str(decision_path), scrub_log.read_text(encoding="utf-8"))

    def test_source_event_path_rejects_symlink_components(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-run-") as temporary:
            raw_run = Path(temporary)
            real = raw_run / "real"
            real.mkdir()
            event = real / "events.jsonl"
            event.write_text("{}\n", encoding="utf-8")
            alias = raw_run / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "contains a symlink"):
                collector.contained_source_event_path(alias / event.name, raw_run)

    def test_referenced_audit_without_rule_is_still_scrubbed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-run-") as temporary:
            raw_run = Path(temporary)
            audit_path = raw_run / "audit.log"
            audit_path.write_text("metadata without a rule match\n", encoding="utf-8")
            results_path = raw_run / "results.jsonl"
            results_path.write_text(
                json.dumps(
                    {
                        "case_id": "allow_without_marker",
                        "status": "PASS",
                        "live_executed": True,
                        "actual_status": 200,
                        "audit_log_path": str(audit_path),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            consumed: list[Path] = []
            _, derived = collector.case_observations(
                [results_path],
                "apache",
                "1100001",
                allowed_source_root=raw_run,
                consumed_event_paths=consumed,
            )
            self.assertEqual(derived, [])
            self.assertEqual(consumed, [audit_path])
            collector.scrub_source_event_paths(consumed, raw_run)
            self.assertFalse(audit_path.exists())

    def test_collector_keeps_raw_evidence_and_diagnostic_logs_in_distinct_run_roots(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-collector-roots-") as temporary:
            root = Path(temporary)
            raw_run = root / "runs" / "envoy" / "current-run"
            log_run = root / "run-logs" / "envoy" / "current-run"
            prior_log_run = root / "run-logs" / "envoy" / "prior-run"
            framework = root / "framework"
            catalog = framework / "tests/cases/no-crs-baseline/catalog.json"
            raw_run.mkdir(parents=True)
            log_run.mkdir(parents=True)
            prior_log_run.mkdir(parents=True)
            catalog.parent.mkdir(parents=True)
            catalog.write_text("{}\n", encoding="utf-8")
            source_result = raw_run / "source-result.json"
            source_result.write_text("{}\n", encoding="utf-8")
            stdout = log_run / "stdout.log"
            stderr = log_run / "stderr.log"
            stdout.write_text("status=PASS\n", encoding="utf-8")
            stderr.write_text("", encoding="utf-8")
            stale_stdout = prior_log_run / "stdout.log"
            stale_stdout.write_text("status=PASS\n", encoding="utf-8")
            foreign_event = prior_log_run / "events.jsonl"
            foreign_event.write_text("{}\n", encoding="utf-8")

            def arguments(
                *,
                stdout_path: Path,
                source_events: list[Path] | None = None,
                allowed_log_root: Path | None = log_run,
            ) -> list[str]:
                values = [
                    "--connector", "envoy",
                    "--stage-rc", "0",
                    "--framework-root", str(framework),
                    "--catalog", str(catalog),
                    "--allowed-source-root", str(raw_run),
                    "--source-result", str(source_result),
                    "--stdout", str(stdout_path),
                    "--stderr", str(stderr),
                    "--source-event-scrub-log", str(log_run / "source-event-scrub.log"),
                    "--events-output", str(raw_run / "events.normalized.jsonl"),
                    "--output", str(raw_run / "source-result.normalized.json"),
                ]
                if allowed_log_root is not None:
                    values.extend(("--allowed-log-root", str(allowed_log_root)))
                for event in source_events or []:
                    values.extend(("--source-events", str(event)))
                return values

            def assert_rejected(
                parser: argparse.ArgumentParser, parsed: argparse.Namespace
            ) -> None:
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        collector.prepare_collector_arguments(parser, parsed)

            parser = collector.collector_argument_parser()
            parsed = parser.parse_args(arguments(stdout_path=stdout))
            source_root = collector.prepare_collector_arguments(parser, parsed)
            self.assertEqual(source_root, raw_run)
            self.assertEqual(parsed.stdout, stdout)
            self.assertEqual(parsed.stderr, stderr)

            parser = collector.collector_argument_parser()
            parsed = parser.parse_args(arguments(stdout_path=stale_stdout))
            assert_rejected(parser, parsed)

            parser = collector.collector_argument_parser()
            parsed = parser.parse_args(
                arguments(stdout_path=stale_stdout, allowed_log_root=prior_log_run)
            )
            assert_rejected(parser, parsed)

            parser = collector.collector_argument_parser()
            parsed = parser.parse_args(
                arguments(stdout_path=stdout, allowed_log_root=None)
            )
            assert_rejected(parser, parsed)

            parser = collector.collector_argument_parser()
            parsed = parser.parse_args(
                arguments(stdout_path=stdout, source_events=[foreign_event])
            )
            assert_rejected(parser, parsed)

    def test_canonical_runner_routes_native_logs_into_raw_run(self) -> None:
        source = (source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=ROOT)).read_text(encoding="utf-8")
        for assignment in (
            "CANONICAL_VERIFIED_RUN_ROOT=$VERIFIED_RUN_ROOT",
            "STAGE_BUILD_ROOT=$CONNECTOR_RUN_ROOT/haproxy-host-work",
            'VERIFIED_RUN_ROOT="$CANONICAL_VERIFIED_RUN_ROOT"',
            'BUILD_ROOT="$STAGE_BUILD_ROOT"',
            'LOG_ROOT="$STAGE_LOG_ROOT"',
            'RESULTS_DIR="$STAGE_RESULTS_DIR"',
            'RUNTIME_BASE="$STAGE_RUNTIME_ROOT"',
            'APACHE_RUNTIME_LOG_DIR="$HOST_RUNTIME_ROOT/apache-runtime"',
            'NGINX_HARNESS_WORK_ROOT="$NGINX_RUN_ROOT"',
            'HAPROXY_HTX_RUNTIME_ROOT="$STAGE_RUNTIME_ROOT"',
            'ENVOY_EXT_PROC_RUNTIME_ROOT="$HOST_RUNTIME_ROOT"',
            "TRAEFIK_RUNTIME_ROOT=$STAGE_BUILD_ROOT/traefik-runtime",
            'TRAEFIK_NATIVE_RUNTIME_ROOT="$TRAEFIK_RUNTIME_ROOT"',
            'TRAEFIK_FIRST_BYTE_EVIDENCE_ROOT="$CONNECTOR_RUN_ROOT"',
            "TRAEFIK_ARTIFACT_STAGER=$CONNECTOR_ROOT/ci/runtime/lifecycle/stage-traefik-runtime-artifacts.py",
            '--build-root "$STAGE_BUILD_ROOT"',
            '--raw-root "$RAW_DIR"',
            "source_result=$RAW_DIR/traefik-source/result.json",
            "source_events=$RAW_DIR/traefik-source/events.jsonl",
            'LIGHTTPD_PATCHED_ROOT="$HOST_RUNTIME_ROOT/lighttpd-patched"',
            'LIGHTTPD_PATCHED_SMOKE_DIR="$LIGHTTPD_RUNTIME_ROOT"',
            'LIGHTTPD_STAGE_FIRST_BYTE_EVIDENCE=$LIGHTTPD_RUNTIME_ROOT/first-byte-evidence.json',
            'STAGE_FIRST_BYTE_EVIDENCE_OUTPUT=$LIGHTTPD_STAGE_FIRST_BYTE_EVIDENCE',
            'FIRST_BYTE_EVIDENCE_SOURCE=$LIGHTTPD_STAGE_FIRST_BYTE_EVIDENCE',
            'FULL_LIFECYCLE_EVIDENCE_OUTPUT="$STAGE_FIRST_BYTE_EVIDENCE_OUTPUT"',
            'cp "$FIRST_BYTE_EVIDENCE_SOURCE" "$FIRST_BYTE_EVIDENCE"',
            '--framework-root "$FRAMEWORK_ROOT"',
            '--allowed-source-root "$RAW_DIR"',
            '--allowed-log-root "$LOG_DIR"',
            "SOURCE_EVENT_SCRUB_LOG=$CONNECTOR_LOG_ROOT/source-event-scrub.log",
            '--scrub-source-events',
        ):
            self.assertIn(assignment, source)
        self.assertNotIn("SOURCE_EVENT_SCRUB_LOG=$CONNECTOR_RUN_ROOT/", source)

    def test_canonical_runner_records_the_actual_selected_stage_target(self) -> None:
        source = (source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=ROOT)).read_text(encoding="utf-8")
        self.assertIn('minimal_runtime_smoke) executed_target=runtime-smoke-$connector ;;', source)
        self.assertIn('no_crs_baseline) executed_target=no-crs-baseline-$connector ;;', source)

        self.assertIn(
            'if [ "$connector" = lighttpd ] && [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then',
            source,
        )

    def test_synchronized_fallback_is_bound_to_the_current_raw_run(self) -> None:
        source = (source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=ROOT)).read_text(encoding="utf-8")
        fallback = source.split('    elif [ ! -f "$FIRST_BYTE_EVIDENCE" ]; then', 1)[1].split(
            "    fi\nfi\n\nhost_version=", 1
        )[0]
        self.assertIn('--control-root "$CONNECTOR_RUN_ROOT"', fallback)
        self.assertIn('--output "$FIRST_BYTE_EVIDENCE"', fallback)
        self.assertNotIn("|| true", fallback)

    def test_synchronized_fallback_helper_requires_and_honors_control_root(self) -> None:
        framework_root, error = trusted_framework_root(ROOT, FRAMEWORK_ROOT)
        if framework_root is None:
            self.skipTest(error)
        helper = framework_root / "tests" / "runners" / "synchronized_upstream.py"
        with tempfile.TemporaryDirectory(prefix="synchronized-fallback-") as temporary:
            control_root = Path(temporary)
            output = control_root / "first-byte-evidence.json"
            missing_root = subprocess.run(
                [sys.executable, str(helper), "--output", str(output)],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(missing_root.returncode, 0)
            self.assertIn("--control-root", missing_root.stderr)

            completed = subprocess.run(
                [
                    sys.executable,
                    str(helper),
                    "--control-root",
                    str(control_root),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            evidence = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(evidence["evidence_origin"], "synthetic_harness")
            self.assertFalse(evidence["promotion_eligible"])

    def make_provenance_environment(
        self,
        names: tuple[str, ...],
        make_target: str,
        overrides: dict[str, str | None],
    ) -> dict[str, str]:
        environment = os.environ.copy()
        for name in names:
            value = overrides.get(name)
            if value is None:
                environment.pop(name, None)
            else:
                environment[name] = value
        completed = subprocess.run(
            [
                "make",
                "--no-print-directory",
                "-s",
                "--eval",
                f"{make_target}:\n\t@env",
                make_target,
            ],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        return dict(
            line.split("=", 1)
            for line in completed.stdout.splitlines()
            if line.partition("=")[0] in names
        )

    def framework_canonical_apr_util_provenance(
        self, names: tuple[str, ...]
    ) -> dict[str, str]:
        """Read the canonical APR-util tuple without duplicating it in Parent."""

        framework_root, error = trusted_framework_root(ROOT, FRAMEWORK_ROOT)
        if framework_root is None:
            self.skipTest(error)
        completed = subprocess.run(
            [
                "/bin/sh",
                "-c",
                (
                    "set -eu\n"
                    '. "$1/ci/lib/common.sh"\n'
                    "printf '%s\\0' \"$APR_UTIL_VERSION\" \"$APR_UTIL_SOURCE_URL\" "
                    '\"$APR_UTIL_SHA256\" \"$APR_UTIL_SHA256_URL\"'
                ),
                "read-framework-apr-util-provenance",
                str(framework_root),
            ],
            cwd=ROOT,
            env={"LC_ALL": "C", "PATH": os.defpath, "TMPDIR": tempfile.gettempdir()},
            text=True,
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertTrue(completed.stdout.endswith("\0"), completed.stderr)
        values = tuple(completed.stdout[:-1].split("\0"))
        self.assertEqual(len(values), len(names), completed.stderr)
        self.assertTrue(all(values), completed.stderr)
        return dict(zip(names, values))

    def test_make_preserves_nginx_provenance_presence_semantics(self) -> None:
        names = (
            "NGINX_SOURCE_MODE",
            "NGINX_SOURCE_REPO_URL",
            "NGINX_SOURCE_GIT_REF",
            "NGINX_GITHUB_REPO",
            "NGINX_RELEASE_TAG",
        )
        make_target = "print-nginx-provenance-contract"

        absent = self.make_provenance_environment(
            names, make_target, {name: None for name in names}
        )
        self.assertEqual(absent, {})

        explicit_empty = self.make_provenance_environment(
            names, make_target, {name: "" for name in names}
        )
        self.assertEqual(explicit_empty, {name: "" for name in names})

        reviewed = {
            "NGINX_SOURCE_MODE": "github-release",
            "NGINX_SOURCE_REPO_URL": "https://github.com/nginx/nginx",
            "NGINX_SOURCE_GIT_REF": "release-1.31.3",
            "NGINX_GITHUB_REPO": "https://github.com/nginx/nginx",
            "NGINX_RELEASE_TAG": "release-1.31.3",
        }
        self.assertEqual(
            self.make_provenance_environment(names, make_target, reviewed), reviewed
        )

    def test_make_preserves_apr_util_provenance_presence_semantics(self) -> None:
        names = (
            "APR_UTIL_VERSION",
            "APR_UTIL_SOURCE_URL",
            "APR_UTIL_SHA256",
            "APR_UTIL_SHA256_URL",
        )
        make_target = "print-apr-util-provenance-contract"

        absent = self.make_provenance_environment(
            names, make_target, {name: None for name in names}
        )
        self.assertEqual(absent, {})

        explicit_empty = self.make_provenance_environment(
            names, make_target, {name: "" for name in names}
        )
        self.assertEqual(explicit_empty, {name: "" for name in names})

        fixture_version = "9.8.7"
        fixture_url = f"https://fixture.invalid/apr-util-{fixture_version}.tar.bz2"
        reviewed = {
            "APR_UTIL_VERSION": fixture_version,
            "APR_UTIL_SOURCE_URL": fixture_url,
            "APR_UTIL_SHA256": "a" * 64,
            "APR_UTIL_SHA256_URL": f"{fixture_url}.sha256",
        }
        self.assertEqual(
            self.make_provenance_environment(names, make_target, reviewed), reviewed
        )

    def test_make_preserves_framework_active_provenance_presence_semantics(self) -> None:
        names = (
            "CRS_REPO_URL",
            "CRS_GIT_REF",
            "NGINX_SOURCE_MODE",
            "NGINX_SOURCE_REPO_URL",
            "NGINX_SOURCE_GIT_REF",
            "NGINX_GITHUB_REPO",
            "NGINX_RELEASE_TAG",
            "HAPROXY_VERSION",
            "HAPROXY_SOURCE_URL",
            "HAPROXY_SHA256_URL",
            "HAPROXY_SHA256",
            "HTTPD_VERSION",
            "HTTPD_SOURCE_URL",
            "HTTPD_SHA256",
            "HTTPD_SHA256_URL",
            "APR_VERSION",
            "APR_SOURCE_URL",
            "APR_SHA256",
            "APR_SHA256_URL",
            "APR_UTIL_VERSION",
            "APR_UTIL_SOURCE_URL",
            "APR_UTIL_SHA256",
            "APR_UTIL_SHA256_URL",
            "PCRE2_VERSION",
            "PCRE2_SOURCE_URL",
            "PCRE2_SHA256",
            "PCRE2_SHA256_URL",
        )
        make_target = "print-framework-active-provenance-contract"
        self.assertEqual(
            self.make_provenance_environment(names, make_target, {name: None for name in names}),
            {},
        )
        self.assertEqual(
            self.make_provenance_environment(names, make_target, {name: "" for name in names}),
            {name: "" for name in names},
        )
        specified = {
            "CRS_REPO_URL": "https://github.com/coreruleset/coreruleset.git",
            "CRS_GIT_REF": "v4.29.0",
            "NGINX_SOURCE_MODE": "github-release",
            "NGINX_SOURCE_REPO_URL": "https://github.com/nginx/nginx",
            "NGINX_SOURCE_GIT_REF": "release-1.31.3",
            "NGINX_GITHUB_REPO": "https://github.com/nginx/nginx",
            "NGINX_RELEASE_TAG": "release-1.31.3",
            "HAPROXY_VERSION": "3.2.0",
            "HAPROXY_SOURCE_URL": "https://fixture.invalid/haproxy.tar.gz",
            "HAPROXY_SHA256_URL": "https://fixture.invalid/haproxy.tar.gz.sha256",
            "HAPROXY_SHA256": "a" * 64,
            "HTTPD_VERSION": "2.4.0",
            "HTTPD_SOURCE_URL": "https://fixture.invalid/httpd.tar.gz",
            "HTTPD_SHA256": "b" * 64,
            "HTTPD_SHA256_URL": "https://fixture.invalid/httpd.tar.gz.sha256",
            "APR_VERSION": "1.7.0",
            "APR_SOURCE_URL": "https://fixture.invalid/apr.tar.gz",
            "APR_SHA256": "c" * 64,
            "APR_SHA256_URL": "https://fixture.invalid/apr.tar.gz.sha256",
            "PCRE2_VERSION": "10.0",
            "PCRE2_SOURCE_URL": "https://fixture.invalid/pcre2.tar.gz",
            "PCRE2_SHA256": "e" * 64,
            "PCRE2_SHA256_URL": "https://fixture.invalid/pcre2.tar.gz.sha256",
        }
        apr_util_names = (
            "APR_UTIL_VERSION",
            "APR_UTIL_SOURCE_URL",
            "APR_UTIL_SHA256",
            "APR_UTIL_SHA256_URL",
        )
        specified.update(self.framework_canonical_apr_util_provenance(apr_util_names))
        self.assertEqual(set(specified), set(names))
        self.assertEqual(
            self.make_provenance_environment(names, make_target, specified), specified
        )

    def test_protocol_client_bundle_is_root_runner_scoped_and_forwarded(self) -> None:
        source = (source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=ROOT)).read_text(encoding="utf-8")
        makefile = (source_path('Makefile', root=ROOT)).read_text(encoding="utf-8")
        for fragment in (
            "NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR=${NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR:-}",
            "NO_CRS_PROTOCOL_CLIENT=${NO_CRS_PROTOCOL_CLIENT:-0}",
            "NO_CRS_PROTOCOL_CLIENT must be 0 or 1",
            "requires NO_CRS_ARTIFACT_PROFILE=full_lifecycle",
            "must remain inside this raw run",
            "protocol client artifact directory escaped the current raw run",
            'set -- "$@" --protocol-client-artifact-dir "$protocol_client_artifact_dir"',
            "skipping H1 native first-byte helper for NGINX downstream",
        ):
            self.assertIn(fragment, source)
        self.assertIn("NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR ?=", makefile)
        self.assertIn("NO_CRS_PROTOCOL_CLIENT ?= 0", makefile)
        self.assertIn("export NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR", makefile)
        self.assertIn("export NO_CRS_PROTOCOL_CLIENT", makefile)
        transport_checker = makefile.split(
            "define RUN_TRANSPORT_HARDENING_EVIDENCE_CHECK", 1
        )[1].split("endef", 1)[0]
        self.assertIn('PYTHON="$(FRAMEWORK_PYTHON)"', transport_checker)

        completed = subprocess.run(
            ["sh", str(source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=ROOT)), "envoy", "no_crs_baseline"],
            cwd=ROOT,
            env={
                **os.environ,
            "NO_CRS_ARTIFACT_PROFILE": "generic",
            "NO_CRS_PROTOCOL_CLIENT": "1",
            "NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR": "/tmp/not-a-canonical-bundle",
            },
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn(
            "NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR requires NO_CRS_ARTIFACT_PROFILE=full_lifecycle",
            completed.stderr,
        )

    def test_native_first_byte_log_stays_under_connector_run_root(self) -> None:
        source = (source_path('ci/runtime/lifecycle/run-native-first-byte.sh', root=ROOT)).read_text(encoding="utf-8")
        self.assertIn("runtime_root=$HOST_RUNTIME_ROOT/first-byte-$connector", source)
        self.assertIn("log_root=$HOST_RUNTIME_ROOT/$connector-first-byte-logs", source)
        self.assertIn(
            "synchronized_control_root=${SYNCHRONIZED_UPSTREAM_CONTROL_ROOT:-$HOST_RUNTIME_ROOT/..}",
            source,
        )
        self.assertIn(
            'SYNCHRONIZED_UPSTREAM_CONTROL_ROOT="$synchronized_control_root"',
            source,
        )
        self.assertIn(
            'TEST_CASE="$FRAMEWORK_ROOT/tests/cases/no-crs-baseline/full-lifecycle/phase4_first_byte_before_response_end.yaml"',
            source,
        )
        self.assertNotIn(
            'TEST_CASE="$FRAMEWORK_ROOT/tests/cases/no-crs-baseline/allow_without_marker.yaml"',
            source,
        )
        self.assertNotIn("log_root=$runtime_root/logs", source)
        self.assertNotIn("log_root=$HOST_LOG_ROOT/$connector-first-byte", source)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
