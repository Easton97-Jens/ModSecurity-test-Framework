from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
NO_CRS_SPEC = importlib.util.spec_from_file_location(
    "no_crs_baseline_transport_tests", ROOT / "ci/checks/catalog/no_crs_baseline.py"
)
assert NO_CRS_SPEC is not None and NO_CRS_SPEC.loader is not None
no_crs = importlib.util.module_from_spec(NO_CRS_SPEC)
NO_CRS_SPEC.loader.exec_module(no_crs)
CHECK_SPEC = importlib.util.spec_from_file_location(
    "check_transport_hardening_evidence", ROOT / "ci/checks/evidence/check_transport_hardening_evidence.py"
)
assert CHECK_SPEC is not None and CHECK_SPEC.loader is not None
transport_check = importlib.util.module_from_spec(CHECK_SPEC)
CHECK_SPEC.loader.exec_module(transport_check)


class TransportHardeningEvidenceTest(unittest.TestCase):
    connector = "envoy"
    integration_mode = "unit-test-host"
    run_id = "transport-unit-1"
    case_id = "phase4_strict_http1_client_abort"
    transaction_id = "tx-transport-1"

    def _write_json(self, path: Path, payload: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")

    def _write_jsonl(self, path: Path, records: list[dict[str, object]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
            encoding="utf-8",
        )

    def _artifact(self, run_dir: Path, relative: str) -> dict[str, str]:
        path = run_dir / relative
        return {
            "path": relative,
            "state": "produced",
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }

    def _build_run(self, root: Path, *, passed: bool = True) -> Path:
        run_dir = root / "run"
        observation = {
            "protocol": "http1",
            "case_id": self.case_id,
            "transport_case_id": self.case_id,
            "transaction_id": self.transaction_id,
            "rule_id": 1100301,
            "phase": 4,
            "event": "phase4_transport",
            "message_id": "msg-transport-1",
            "requested_action": "deny",
            "actual_action": "abort_connection",
            "connection_id": "conn-transport-1",
            "stream_id": None,
            "barrier_id": None,
            "connection_reused": False,
            "response_committed": True,
            "first_byte_received": True,
            "eos_received": False,
            "eos_seen": False,
            "client_result": "premature_eof",
            "transport_result": "connection_aborted",
            "host_survived": True,
            "followup_request_result": "completed",
            "client_disconnected": None,
            "upstream_disconnected": None,
            "cancelled": None,
            "stream_reset": False,
            "reset_by": "strict_intervention",
            "reset_code": None,
            "stream_reset_code": None,
            "timeout_stage": None,
            "write_result": "completed",
            "cleanup_reason": "strict_abort",
        }
        lifecycle = {
            "transaction_id": self.transaction_id,
            "transport_case_id": self.case_id,
            "protocol": "http1",
            "connection_id": "conn-transport-1",
            "stream_id": None,
            "connection_reused": False,
            "transaction_started": 1,
            "transaction_finished": 1,
            "transaction_destroyed": 1,
            "request_body_finished": 1,
            "response_body_finished": 1,
            "eos_seen": 0,
            "intentional_abort": 1,
            "client_disconnect": 0,
            "upstream_disconnect": 0,
            "stream_reset": 0,
            "timeout": 0,
            "short_writes": 0,
            "write_would_block": 0,
            "cleanup_reason": "strict_abort",
        }
        self._write_json(run_dir / "inventory/transport-observations.json", {
            "schema_version": 1,
            "connector": self.connector,
            "integration_mode": self.integration_mode,
            "run_id": self.run_id,
            "observations": [observation],
        })
        self._write_json(run_dir / "inventory/connection-lifecycle.json", {
            "schema_version": 1,
            "connector": self.connector,
            "integration_mode": self.integration_mode,
            "run_id": self.run_id,
            "records": [lifecycle],
        })
        self._write_json(run_dir / "effective-config/manifest.json", {
            "schema_version": 1,
            "connector": self.connector,
            "integration_mode": self.integration_mode,
            "run_id": self.run_id,
            "files": [{"path": "host/config.conf", "sha256": "a" * 64}],
        })
        self._write_jsonl(run_dir / "inventory/barrier-events.jsonl", [])
        self._write_json(run_dir / "transaction-counts.json", {
            "schema_version": 1,
            "connector": self.connector,
            "transactions_observed": 1,
            "transaction_ids": [self.transaction_id],
        })
        self._write_json(run_dir / "lifecycle-counters.json", {
            "schema_version": 1,
            "connector": self.connector,
            "transactions_started": 1,
            "transactions_finished": 1,
            "transactions_destroyed": 1,
            "request_body_finishes": 1,
            "response_body_finishes": 1,
            "interventions_seen": 1,
            "intentional_aborts": 1,
            "unexpected_engine_errors": 0,
            "transport_counters_bound": True,
            "client_disconnects": 0,
            "upstream_disconnects": 0,
            "stream_resets": 0,
            "timeouts": 0,
            "short_writes": 0,
            "write_would_block": 0,
            "cleanup_normal": 0,
            "cleanup_cancel": 0,
            "cleanup_abort": 1,
        })
        for relative in ("logs/client.log", "logs/upstream.log", "logs/transport.log", "logs/cleanup.log"):
            path = run_dir / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("metadata-only\n", encoding="utf-8")
        event = {
            "connector": self.connector,
            "run_id": self.run_id,
            "integration_mode": self.integration_mode,
            "transaction_id": self.transaction_id,
            "transport_case_id": self.case_id,
            "rule_id": 1100301,
            "phase": 4,
            "event": "phase4_transport",
            "message_id": "msg-transport-1",
            "requested_action": "deny",
            "actual_action": "abort_connection",
            "transport_result": "connection_aborted",
            "connection_id": "conn-transport-1",
        }
        self._write_jsonl(run_dir / "events.jsonl", [event])
        record = {
            "connector": self.connector,
            "run_id": self.run_id,
            "integration_mode": self.integration_mode,
            "case_id": self.case_id,
            "status": "PASS" if passed else "NOT_EXECUTED",
            "live_executed": passed,
            "group": "full-lifecycle-transport-hardening",
            "expected_result": "connection_aborted_strict",
            "phase": 4,
            "transaction_ids": [self.transaction_id],
            "observed_rule_ids": [1100301],
            "expected_rule_id": 1100301,
            "requested_action": "deny",
            "actual_action": "abort_connection",
            "transport_result": "connection_aborted",
            "connection_id": "conn-transport-1",
            "stream_id": None,
            "barrier_id": None,
            "negotiated_protocol": "http1",
            "downstream_protocol": "http1",
            "transport_case_id": self.case_id,
            "actual_status": None,
            "visible_http_status": None,
        }
        self._write_jsonl(run_dir / "results.jsonl", [record])
        self._write_json(run_dir / "result.json", {"connector": self.connector})
        artifact_paths = {
            **no_crs.TRANSPORT_HARDENING_ARTIFACT_PATHS,
            "transaction_counts": "transaction-counts.json",
            "lifecycle_counters": "lifecycle-counters.json",
        }
        manifest = {
            "connector": self.connector,
            "integration_mode": self.integration_mode,
            "run_id": self.run_id,
            "artifact_profile": "full_lifecycle",
            "artifacts": {
                name: self._artifact(run_dir, path)
                for name, path in artifact_paths.items()
            },
        }
        self._write_json(run_dir / "manifest.json", manifest)
        return run_dir

    def _errors(self, run_dir: Path) -> list[str]:
        with mock.patch.object(transport_check, "_canonical_base_errors", return_value=[]):
            return transport_check.transport_hardening_errors(run_dir)

    def test_accepts_causally_bound_strict_transport_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transport-hardening-") as temporary:
            self.assertEqual(self._errors(self._build_run(Path(temporary))), [])

    def test_bound_upstream_disconnect_is_cancel_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transport-hardening-") as temporary:
            run_dir = self._build_run(Path(temporary))
            lifecycle = no_crs.load_json(run_dir / "inventory/connection-lifecycle.json")
            counters = no_crs.load_json(run_dir / "lifecycle-counters.json")
            record = lifecycle["records"][0]
            record.update({
                "intentional_abort": 0,
                "upstream_disconnect": 1,
                "cleanup_reason": "upstream_disconnected",
            })
            counters.update({
                "intentional_aborts": 0,
                "upstream_disconnects": 1,
                "cleanup_abort": 0,
                "cleanup_cancel": 1,
            })
            self.assertEqual(
                transport_check._counter_errors(
                    counters, lifecycle["records"], require_bound_counts=True,
                ),
                [],
            )

    def test_normalizes_bounded_transport_metadata_without_payload(self) -> None:
        event = {
            "connector": self.connector,
            "transport_result": "completed",
            "client_disconnected": "true",
            "upstream_disconnected": "false",
            "cancelled": "true",
            "reset_by": "strict-intervention",
            "reset_code": "NO_ERROR",
            "timeout_stage": "client-idle",
            "write_result": "write-would-block",
            "eos_seen": "false",
            "cleanup_reason": "client-disconnected",
            "barrier_id": "barrier-1",
        }
        normalized = no_crs.canonicalize_event_protocol_provenance(event)
        self.assertEqual(normalized["transport_result"], "completed")
        self.assertIs(normalized["client_disconnected"], True)
        self.assertEqual(normalized["reset_by"], "strict_intervention")
        self.assertEqual(normalized["write_result"], "write_would_block")
        self.assertEqual(no_crs.canonical_event_errors(normalized, connector=self.connector), [])
        invalid = dict(normalized, cleanup_reason="no-crs-response-body-marker")
        self.assertTrue(any(
            "cleanup_reason" in error or "body payload" in error
            for error in no_crs.canonical_event_errors(invalid, connector=self.connector)
        ))

    def test_finalizer_copies_all_allowlisted_transport_artifacts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transport-artifact-copy-") as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            logs = {
                "client_log": source / "client.log",
                "upstream_log": source / "upstream.log",
                "transport_log": source / "transport.log",
                "cleanup_log": source / "cleanup.log",
            }
            for name, path in logs.items():
                path.write_text(f"{name}-metadata\n", encoding="utf-8")
            observations = source / "transport-observations.json"
            lifecycle = source / "connection-lifecycle.json"
            config_dir = source / "effective-config"
            config_dir.mkdir()
            config = config_dir / "manifest.json"
            self._write_json(observations, {
                "schema_version": 1, "connector": self.connector,
                "integration_mode": self.integration_mode, "run_id": self.run_id,
                "observations": [],
            })
            self._write_json(lifecycle, {
                "schema_version": 1, "connector": self.connector,
                "integration_mode": self.integration_mode, "run_id": self.run_id,
                "records": [],
            })
            self._write_json(config, {
                "schema_version": 1, "connector": self.connector,
                "integration_mode": self.integration_mode, "run_id": self.run_id,
                "files": [],
            })
            barriers = source / "barrier-events.jsonl"
            barriers.write_text("", encoding="utf-8")
            run_dir = root / "run"
            manifest: dict[str, object] = {"artifacts": {}}
            no_crs.copy_engine_lifecycle_artifacts(
                run_dir,
                [
                    *(f"{name}={path}" for name, path in logs.items()),
                    f"transport_observations={observations}",
                    f"connection_lifecycle={lifecycle}",
                    f"barrier_events={barriers}",
                    f"effective_config={config_dir}",
                ],
                self.connector,
                "full_lifecycle",
                manifest,
                run_id=self.run_id,
                integration_mode=self.integration_mode,
            )
            artifacts = manifest["artifacts"]  # type: ignore[index]
            self.assertEqual(set(no_crs.TRANSPORT_HARDENING_ARTIFACT_PATHS), set(artifacts))
            for name, relative in no_crs.TRANSPORT_HARDENING_ARTIFACT_PATHS.items():
                self.assertTrue((run_dir / relative).is_file(), name)
            self.assertEqual(
                logs["transport_log"].read_text(encoding="utf-8"),
                (run_dir / no_crs.TRANSPORT_HARDENING_ARTIFACT_PATHS["transport_log"]).read_text(encoding="utf-8"),
            )

    def test_diagnostic_abort_sidecars_do_not_promote_a_not_executed_case(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transport-hardening-") as temporary:
            run_dir = self._build_run(Path(temporary), passed=False)
            observations = no_crs.load_json(run_dir / "inventory/transport-observations.json")
            lifecycle = no_crs.load_json(run_dir / "inventory/connection-lifecycle.json")
            self.assertEqual(len(observations["observations"]), 1)
            self.assertEqual(lifecycle["records"][0]["intentional_abort"], 1)
            self.assertEqual(self._errors(run_dir), [])
            record = no_crs.read_jsonl(run_dir / "results.jsonl")[0]
            self.assertEqual(record["status"], "NOT_EXECUTED")
            self.assertEqual(transport_check._transport_passes([record], transport_check._catalog_by_id()), [])

    def test_diagnostic_stream_reset_without_transport_pass_is_non_promoting(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transport-hardening-") as temporary:
            run_dir = self._build_run(Path(temporary), passed=False)
            observations_path = run_dir / "inventory/transport-observations.json"
            lifecycle_path = run_dir / "inventory/connection-lifecycle.json"
            counters_path = run_dir / "lifecycle-counters.json"
            observations = no_crs.load_json(observations_path)
            lifecycle = no_crs.load_json(lifecycle_path)
            counters = no_crs.load_json(counters_path)
            observation = observations["observations"][0]
            observation.update({
                "protocol": "h2",
                "actual_action": "stream_reset",
                "stream_id": 1,
                "client_result": "not_observable",
                "transport_result": "stream_reset",
                "stream_reset": True,
                "reset_by": "host",
                "reset_code": "CANCEL",
                "stream_reset_code": "CANCEL",
                "cleanup_reason": "stream_reset",
            })
            lifecycle_record = lifecycle["records"][0]
            lifecycle_record.update({
                "protocol": "h2",
                "stream_id": 1,
                "intentional_abort": 0,
                "stream_reset": 1,
                "cleanup_reason": "stream_reset",
            })
            counters["intentional_aborts"] = 0
            counters["stream_resets"] = 1
            self._write_json(observations_path, observations)
            self._write_json(lifecycle_path, lifecycle)
            self._write_json(counters_path, counters)
            manifest = no_crs.load_json(run_dir / "manifest.json")
            for name, relative in (
                ("transport_observations", "inventory/transport-observations.json"),
                ("connection_lifecycle", "inventory/connection-lifecycle.json"),
                ("lifecycle_counters", "lifecycle-counters.json"),
            ):
                manifest["artifacts"][name] = self._artifact(run_dir, relative)
            self._write_json(run_dir / "manifest.json", manifest)
            self.assertEqual(self._errors(run_dir), [])
            record = no_crs.read_jsonl(run_dir / "results.jsonl")[0]
            self.assertEqual(record["status"], "NOT_EXECUTED")
            self.assertEqual(transport_check._transport_passes([record], transport_check._catalog_by_id()), [])

    def test_rejects_payload_in_diagnostic_transport_observation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transport-hardening-") as temporary:
            run_dir = self._build_run(Path(temporary), passed=False)
            path = run_dir / "inventory/transport-observations.json"
            payload = no_crs.load_json(path)
            payload["observations"][0]["response_body"] = "no-crs-response-body-marker"
            self._write_json(path, payload)
            manifest = no_crs.load_json(run_dir / "manifest.json")
            manifest["artifacts"]["transport_observations"] = self._artifact(
                run_dir, "inventory/transport-observations.json"
            )
            self._write_json(run_dir / "manifest.json", manifest)
            errors = self._errors(run_dir)
            self.assertTrue(any("transport-observations" in error for error in errors), errors)

    def test_rejects_raw_h3_connection_identifier_in_observation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transport-hardening-") as temporary:
            run_dir = self._build_run(Path(temporary))
            path = run_dir / "inventory/transport-observations.json"
            payload = no_crs.load_json(path)
            payload["observations"][0]["protocol"] = "h3"
            payload["observations"][0]["connection_id"] = "raw-quic-connection-id"
            self._write_json(path, payload)
            manifest = no_crs.load_json(run_dir / "manifest.json")
            manifest["artifacts"]["transport_observations"] = self._artifact(
                run_dir, "inventory/transport-observations.json"
            )
            self._write_json(run_dir / "manifest.json", manifest)
            errors = self._errors(run_dir)
            self.assertTrue(any("raw H3 connection identifiers" in error for error in errors), errors)

    def test_rejects_cross_transaction_observation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transport-hardening-") as temporary:
            run_dir = self._build_run(Path(temporary))
            path = run_dir / "inventory/transport-observations.json"
            payload = no_crs.load_json(path)
            payload["observations"][0]["transaction_id"] = "tx-other"
            self._write_json(path, payload)
            manifest = no_crs.load_json(run_dir / "manifest.json")
            manifest["artifacts"]["transport_observations"] = self._artifact(
                run_dir, "inventory/transport-observations.json"
            )
            self._write_json(run_dir / "manifest.json", manifest)
            errors = self._errors(run_dir)
            self.assertTrue(any("matching transport observation" in error for error in errors), errors)

    def test_rejects_duplicate_lifecycle_finish_in_diagnostic_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transport-hardening-") as temporary:
            run_dir = self._build_run(Path(temporary), passed=False)
            path = run_dir / "inventory/connection-lifecycle.json"
            payload = no_crs.load_json(path)
            payload["records"][0]["response_body_finished"] = 2
            self._write_json(path, payload)
            manifest = no_crs.load_json(run_dir / "manifest.json")
            manifest["artifacts"]["connection_lifecycle"] = self._artifact(
                run_dir, "inventory/connection-lifecycle.json"
            )
            self._write_json(run_dir / "manifest.json", manifest)
            errors = self._errors(run_dir)
            self.assertTrue(any("response_body_finished" in error for error in errors), errors)

    def test_rejects_unbound_stream_reset(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transport-hardening-") as temporary:
            run_dir = self._build_run(Path(temporary))
            path = run_dir / "inventory/connection-lifecycle.json"
            payload = no_crs.load_json(path)
            payload["records"][0]["stream_reset"] = 1
            self._write_json(path, payload)
            manifest = no_crs.load_json(run_dir / "manifest.json")
            manifest["artifacts"]["connection_lifecycle"] = self._artifact(
                run_dir, "inventory/connection-lifecycle.json"
            )
            self._write_json(run_dir / "manifest.json", manifest)
            errors = self._errors(run_dir)
            self.assertTrue(any("stream_reset lacks a matching transport case" in error for error in errors), errors)

    def test_event_error_groups_preserve_canonical_order(self) -> None:
        record = {
            "case_id": "case-order",
            "transport_case_id": "case-order",
            "phase": 4,
            "observed_rule_ids": [1101],
            "expected_rule_id": 1101,
            "requested_action": "deny",
            "actual_action": "abort_connection",
            "transport_result": "connection_aborted",
        }
        event = {
            "connector": "wrong-connector",
            "integration_mode": "wrong-mode",
            "run_id": "wrong-run",
            "transaction_id": "wrong-transaction",
            "transport_case_id": "wrong-case",
            "phase": 3,
            "event": "",
            "message_id": "",
        }
        manifest = {"connector": self.connector, "integration_mode": self.integration_mode, "run_id": self.run_id}

        errors = transport_check._event_errors(record, event, manifest, transaction_id=self.transaction_id)

        self.assertEqual(
            errors[:8],
            [
                "case-order: event connector does not match canonical run",
                "case-order: event integration_mode does not match canonical run",
                "case-order: event run_id does not match canonical run",
                "case-order: event transaction_id does not match case result",
                "case-order: event transport_case_id does not match case result",
                "case-order: event phase does not match case result",
                "case-order: event requires a non-empty event",
                "case-order: event requires a non-empty message_id",
            ],
        )

    def test_invalid_required_counter_still_short_circuits_bound_checks(self) -> None:
        errors = transport_check._counter_errors({}, [], require_bound_counts=True)

        self.assertEqual(
            [
                f"lifecycle_counters.{field} must be a non-negative integer"
                for field in transport_check.REQUIRED_LIFECYCLE_COUNTERS
            ],
            errors,
        )


if __name__ == "__main__":
    unittest.main()
