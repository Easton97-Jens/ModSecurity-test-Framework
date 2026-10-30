from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest


ROOT = connector_root()
sanitizer = load_source(source_path('ci/runtime/lifecycle/sanitize-full-lifecycle-log.py', root=ROOT))

checker = load_source(source_path('ci/checks/evidence/check-full-lifecycle-evidence.py', root=ROOT))


class FullLifecycleEvidenceTest(unittest.TestCase):
    def phase4_identity_fixture(
        self,
        event_overrides: dict[str, object] | None = None,
        result_overrides: dict[str, object] | None = None,
    ) -> tuple[Path, dict[str, object], dict[str, object], tempfile.TemporaryDirectory[str]]:
        """Create one canonical Apache P4 fixture with a replaceable raw event.

        The result rows model the existing canonical case-to-transaction
        binding.  Each negative test changes only the raw-event identity so a
        matching rule ID and phase cannot stand in for producer/run identity.
        """
        temporary = tempfile.TemporaryDirectory(prefix="full-lifecycle-identity-")
        run = Path(temporary.name)
        event: dict[str, object] = {
            "connector": "apache",
            "run_id": "apache-current-run",
            "integration_mode": "native-httpd-module",
            "transaction_id": "apache-phase4-transaction",
            "rule_id": 1100301,
            "phase": 4,
            "first_byte_before_response_end": True,
            "upstream_response_finished_at_first_byte": False,
            "upstream_paused": True,
            "first_chunk_size": 1,
            "no_full_response_buffering": True,
        }
        if event_overrides:
            event.update(event_overrides)
        (run / "events.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")
        records = (
            {
                "case_id": "phase4_first_byte_before_response_end",
                "status": "PASS",
                "expected_rule_id": 1100301,
                "transaction_ids": ["apache-phase4-transaction"],
            },
            {
                "case_id": "phase4_no_full_response_buffering",
                "status": "PASS",
                "expected_rule_id": 1100301,
                "transaction_ids": ["apache-phase4-transaction"],
            },
        )
        (run / "results.jsonl").write_text(
            "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
        )
        manifest: dict[str, object] = {
            "capabilities": {
                "first_byte_before_response_end": {"state": "verified"},
                "no_full_response_buffering": {"state": "verified"},
            }
        }
        result: dict[str, object] = {
            "artifact_profile": "full_lifecycle",
            "connector": "apache",
            "run_id": "apache-current-run",
            "host_profile": "native-httpd-module",
            "integration_mode": "native-httpd-module",
            "executed_targets": ["full-lifecycle-apache"],
            "capabilities_verified": [
                "first_byte_before_response_end",
                "no_full_response_buffering",
            ],
        }
        if result_overrides:
            result.update(result_overrides)
        return run, manifest, result, temporary

    def assert_phase4_identity_rejected(
        self,
        event_overrides: dict[str, object] | None = None,
        result_overrides: dict[str, object] | None = None,
    ) -> None:
        run, manifest, result, temporary = self.phase4_identity_fixture(
            event_overrides,
            result_overrides,
        )
        with temporary:
            self.assertEqual(
                checker.first_byte_errors(run, manifest, result),
                [
                    "phase4_first_byte_before_response_end: "
                    "missing synchronized first-byte event metadata",
                    "phase4_no_full_response_buffering: "
                    "missing synchronized first-byte event metadata",
                ],
            )
            self.assertEqual(
                checker.no_buffer_errors(run, manifest, result),
                ["no-full-response-buffering PASS lacks the causal first-byte metadata"],
            )

    def test_phase4_events_reject_foreign_run_identity(self) -> None:
        self.assert_phase4_identity_rejected({"run_id": "apache-foreign-run"})

    def test_phase4_events_reject_foreign_result_run_identity(self) -> None:
        self.assert_phase4_identity_rejected(result_overrides={"run_id": "apache-foreign-run"})

    def test_phase4_events_reject_copied_connector_evidence(self) -> None:
        self.assert_phase4_identity_rejected({"connector": "nginx"})

    def test_phase4_events_reject_copied_result_connector_evidence(self) -> None:
        self.assert_phase4_identity_rejected(result_overrides={"connector": "nginx"})

    def test_phase4_events_reject_copied_native_integration_mode_evidence(self) -> None:
        self.assert_phase4_identity_rejected({"integration_mode": "native-nginx-http-module"})

    def test_phase4_events_reject_copied_result_host_profile_evidence(self) -> None:
        self.assert_phase4_identity_rejected(result_overrides={"host_profile": "native-nginx-http-module"})

    def test_phase4_events_reject_wrong_integration_mode(self) -> None:
        self.assert_phase4_identity_rejected({"integration_mode": "compatibility-proxy"})

    def test_phase4_events_reject_foreign_transaction_identity(self) -> None:
        self.assert_phase4_identity_rejected({"transaction_id": "foreign-phase4-transaction"})

    def test_phase4_events_reject_missing_identity(self) -> None:
        for missing_field in ("connector", "run_id", "integration_mode", "transaction_id"):
            with self.subTest(missing_field=missing_field):
                self.assert_phase4_identity_rejected({missing_field: ""})

    def test_phase4_events_accept_same_run_apache_control(self) -> None:
        run, manifest, result, temporary = self.phase4_identity_fixture()
        with temporary:
            self.assertEqual(checker.profile_errors(result, "apache"), [])
            self.assertEqual(checker.first_byte_errors(run, manifest, result), [])
            self.assertEqual(checker.no_buffer_errors(run, manifest, result), [])

    def test_log_sanitizer_drops_fixture_bodies_and_credentials(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-lifecycle-log-") as temporary:
            root = Path(temporary)
            source = root / "raw.log"
            destination = root / "canonical.log"
            source.write_text(
                "Authorization: Bearer private-token\n"
                "response=no-crs-response-body-marker\n"
                "normal diagnostic\n",
                encoding="utf-8",
            )
            self.assertEqual(sanitizer.main([
                "--input", str(source), "--output", str(destination), "--label", "unit",
            ]), 0)
            text = destination.read_text(encoding="utf-8")
            self.assertNotIn("private-token", text)
            self.assertNotIn("no-crs-response-body-marker", text)
            self.assertIn("[body payload line omitted]", text)
            self.assertIn("normal diagnostic", text)

    def test_log_sanitizer_requires_named_root_across_directories(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-lifecycle-log-input-") as input_temp:
            with tempfile.TemporaryDirectory(prefix="full-lifecycle-log-output-") as output_temp:
                source = Path(input_temp) / "raw.log"
                destination = Path(output_temp) / "canonical.log"
                source.write_text("normal diagnostic\n", encoding="utf-8")
                with self.assertRaises(SystemExit) as raised:
                    sanitizer.main([
                        "--input", str(source), "--output", str(destination), "--label", "unit",
                    ])
                self.assertEqual(raised.exception.code, 2)
                self.assertFalse(destination.exists())

    def test_first_byte_promotion_requires_causal_metadata(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-lifecycle-evidence-") as temporary:
            root = Path(temporary)
            run = root / "run"
            run.mkdir()
            (run / "events.jsonl").write_text(
                '{"rule_id":1100301,"phase":4,"first_byte_before_response_end":true,'
                '"upstream_response_finished_at_first_byte":false}\n',
                encoding="utf-8",
            )
            (run / "results.jsonl").write_text(
                '{"case_id":"phase4_first_byte_before_response_end","status":"PASS",'
                '"expected_rule_id":1100301}\n'
                '{"case_id":"phase4_no_full_response_buffering","status":"PASS",'
                '"expected_rule_id":1100301}\n',
                encoding="utf-8",
            )
            manifest = {"capabilities": {"first_byte_before_response_end": {"state": "verified"}}}
            result = {"artifact_profile": "full_lifecycle", "capabilities_verified": ["first_byte_before_response_end"]}
            errors = checker.first_byte_errors(run, manifest, result)
            self.assertEqual(
                errors,
                [
                    "phase4_first_byte_before_response_end: missing synchronized first-byte event metadata",
                    "phase4_no_full_response_buffering: missing synchronized first-byte event metadata",
                ],
            )

    def test_profile_contract_rejects_generic_compatibility_evidence(self) -> None:
        compatibility_result = {
            "artifact_profile": "generic",
            "host_profile": "ext_authz",
            "integration_mode": "ext_authz",
            "executed_targets": ["no-crs-baseline-envoy"],
        }
        errors = checker.profile_errors(compatibility_result, "envoy")
        self.assertIn(
            "canonical full-lifecycle evidence requires artifact_profile=full_lifecycle",
            errors,
        )
        self.assertIn(
            "canonical full-lifecycle evidence requires host_profile='ext_proc'",
            errors,
        )
        self.assertIn(
            "canonical full-lifecycle evidence requires integration_mode='ext_proc'",
            errors,
        )
        self.assertIn(
            "canonical full-lifecycle evidence requires executed_targets=['full-lifecycle-envoy-ext-proc']",
            errors,
        )

    def test_profile_contract_accepts_only_each_connector_native_identity(self) -> None:
        for connector, identity in checker.FULL_LIFECYCLE_IDENTITIES.items():
            result = {
                "artifact_profile": "full_lifecycle",
                "host_profile": identity["host_profile"],
                "integration_mode": identity["integration_mode"],
                "executed_targets": [identity["target"]],
            }
            with self.subTest(connector=connector):
                self.assertEqual(checker.profile_errors(result, connector), [])

    def test_profile_checker_fails_before_capability_claims_for_generic_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-lifecycle-profile-") as temporary:
            evidence_root = Path(temporary) / "evidence"
            run_dir = evidence_root / "envoy" / "compatibility-run"
            run_dir.mkdir(parents=True)
            (run_dir / "result.json").write_text(
                '{"artifact_profile":"generic","capabilities_verified":[]}',
                encoding="utf-8",
            )
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    checker.main([
                        "--connector-root", str(ROOT),
                        "--evidence-root", str(evidence_root),
                        "--run-id", "compatibility-run",
                        "--check", "profile",
                        "--connectors", "envoy",
                    ]),
                    1,
                )

    def test_lifecycle_inventory_rejects_unbalanced_or_unattributed_counters(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-lifecycle-lifecycle-") as temporary:
            run = Path(temporary)
            (run / "events.jsonl").write_text(
                '{"transaction_id":"tx-one","actual_action":"abort_connection",'
                '"late_intervention_mode":"strict","transport_result":"connection_aborted"}\n',
                encoding="utf-8",
            )
            (run / "lifecycle-counters.json").write_text(
                '{"connector":"apache","transactions_started":2,"transactions_finished":1,'
                '"transactions_destroyed":1,"request_body_finishes":0,'
                '"response_body_finishes":0,"intentional_aborts":2,'
                '"client_disconnects":0,"upstream_disconnects":0,"stream_resets":0,'
                '"timeouts":0,"short_writes":0,"write_would_block":0,'
                '"cleanup_normal":0,"cleanup_cancel":0,"cleanup_abort":0,'
                '"unexpected_engine_errors":0,"transport_counters_bound":true}',
                encoding="utf-8",
            )
            inventory = run / "inventory"
            inventory.mkdir()
            (inventory / "connection-lifecycle.json").write_text(
                '{"records":[]}', encoding="utf-8"
            )
            errors = checker.lifecycle_errors(run, "apache")
            self.assertTrue(any("unbalanced" in error for error in errors))
            self.assertTrue(any("intentional_aborts" in error for error in errors))

    def test_lifecycle_inventory_accepts_matching_events_artifact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-lifecycle-lifecycle-") as temporary:
            run = Path(temporary)
            (run / "events.jsonl").write_text(
                '{"transaction_id":"tx-one","actual_action":"abort_connection"}\n',
                encoding="utf-8",
            )
            counters = {name: 0 for name in checker.LIFECYCLE_COUNTERS}
            counters.update({
                "connector": "apache",
                "transactions_started": 1,
                "transactions_finished": 1,
                "transactions_destroyed": 1,
                "intentional_aborts": 1,
                "transport_counters_bound": True,
            })
            (run / "lifecycle-counters.json").write_text(
                json.dumps(counters), encoding="utf-8"
            )
            inventory = run / "inventory"
            inventory.mkdir()
            (inventory / "connection-lifecycle.json").write_text(
                '{"records":[]}', encoding="utf-8"
            )

            self.assertEqual(checker.lifecycle_errors(run, "apache"), [])

    def test_transport_inventory_rejects_unproven_host_survival(self) -> None:
        with tempfile.TemporaryDirectory(prefix="full-lifecycle-transport-") as temporary:
            run = Path(temporary)
            logs = run / "logs"
            inventory = run / "inventory"
            logs.mkdir()
            inventory.mkdir()
            for name in ("client.log", "upstream.log", "transport.log", "cleanup.log"):
                (logs / name).write_text("payload-free\n", encoding="utf-8")
            (inventory / "transport-observations.json").write_text(
                '{"connector":"apache","run_id":"run-one","observations":['
                '{"protocol":"http1","case_id":"strict-http1","transport_case_id":"case-one",'
                '"transaction_id":"tx-one","rule_id":1100301,"phase":4,"event":"phase4",'
                '"message_id":"MSCONN_EVENT","requested_action":"deny","actual_action":"abort_connection",'
                '"response_committed":true,"first_byte_received":true,"eos_received":false,'
                '"client_result":"not_observable","transport_result":"connection_aborted",'
                '"host_survived":true,"followup_request_result":"not_observed"}]}',
                encoding="utf-8",
            )
            (inventory / "connection-lifecycle.json").write_text(
                '{"connector":"apache","run_id":"run-one","records":[]}',
                encoding="utf-8",
            )
            (inventory / "barrier-events.jsonl").write_text("", encoding="utf-8")
            effective = run / "effective-config"
            effective.mkdir()
            (effective / "manifest.json").write_text(
                '{"connector":"apache","run_id":"run-one","files":[]}',
                encoding="utf-8",
            )
            errors = checker.transport_artifact_errors(run, "apache")
            self.assertIn("host_survived=true requires an independent follow-up observation", errors)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
