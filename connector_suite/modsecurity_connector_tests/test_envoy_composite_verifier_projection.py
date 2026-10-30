from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = connector_root()
PROJECTION_PATH = source_path('connectors/envoy/harness/write_composite_verifier_projection.py', root=ROOT)


def load_projection() -> object:
    module = load_source(PROJECTION_PATH)
    return module


class EnvoyCompositeVerifierProjectionTest(unittest.TestCase):
    decision_id = "d" * 64
    event_time = "2026-08-27T12:00:00Z"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "runtime"
        self.root.mkdir(mode=0o700)
        self.root.chmod(0o700)
        self.case_root = self.root / "case"
        self.case_root.mkdir(mode=0o700)
        self.case_root.chmod(0o700)
        self.event_log = self.root / "events.jsonl"
        self.probe = self.case_root / "probe.json"
        self.upstream_request = self.case_root / "upstream-request.json"
        self.upstream_response = self.case_root / "upstream-response.json"
        self.projection = load_projection()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_private(self, path: Path, value: object) -> None:
        text = value if isinstance(value, str) else json.dumps(value, sort_keys=True) + "\n"
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)

    def event(self, phase: str, outcome: str = "observed", **extra: object) -> dict[str, object]:
        return {
            "decision_id": self.decision_id,
            "connector": "envoy",
            "phase": phase,
            "outcome": outcome,
            "event_time": self.event_time,
            "request_path": "envoy.ext_authz",
            "response_path": "envoy.ext_proc",
            "transport": "envoy_ext_authz_ext_proc_grpc",
            **extra,
        }

    def events_for(self, case: str) -> list[dict[str, object]]:
        if case == "p1_deny":
            return [
                self.event("P1", requested_action="deny", rule_id="1101001"),
                self.event(
                    "request_host_action", "recorded", actual_host_action="deny", visible_status=403,
                ),
                self.event("terminal", "closed", cleanup_outcome="closed"),
            ]
        if case == "envoy_response_metadata_omitted":
            return [
                self.event("P1", requested_action="allow"),
                self.event("P2", requested_action="allow"),
                self.event("lease", "issued"),
                self.event("terminal", "closed", reason="timeout", cleanup_outcome="closed"),
            ]
        if case == "p3_redirect":
            return [
                self.event("P1", requested_action="allow"),
                self.event("P2", requested_action="allow"),
                self.event("P3", requested_action="redirect", rule_id="1103002"),
                self.event(
                    "request_host_action", "recorded", actual_host_action="redirect", visible_status=302,
                ),
                self.event("terminal", "closed", cleanup_outcome="closed"),
            ]
        events = [
            self.event("P1", requested_action="allow"),
            self.event("P2", requested_action="allow"),
            self.event("P3", requested_action="allow"),
            self.event("P4", requested_action="deny" if case == "p4_safe" else "allow", **(
                {"rule_id": "1104002"} if case == "p4_safe" else {}
            )),
        ]
        if case == "p4_safe":
            events.append(self.event("host_action", "recorded", actual_host_action="log_only", visible_status=200))
        events.append(self.event("terminal", "closed", cleanup_outcome="closed"))
        return events

    def set_case(
        self,
        case: str,
        *,
        client_lease_header: bool = False,
        redirect_location_verified: bool | None = None,
        upstream: bool = True,
        upstream_response: bool = True,
    ) -> str:
        events = self.events_for(case)
        raw = "".join(json.dumps(event, sort_keys=True) + "\n" for event in events)
        self.write_private(self.event_log, raw)
        status = 403 if case == "p1_deny" else (503 if case == "envoy_response_metadata_omitted" else (302 if case == "p3_redirect" else 200))
        self.write_private(self.probe, {
            "schema_version": 1,
            "evidence_type": "envoy_http_client_probe",
            "http_status": status,
            "response_bytes": 0 if case == "envoy_response_metadata_omitted" else 20,
            "body_payload_persisted": False,
            "redirect_location_verified": case == "p3_redirect" if redirect_location_verified is None else redirect_location_verified,
            "composite_lease_header_present": client_lease_header,
        })
        if upstream:
            self.write_private(self.upstream_request, {
                "request_observed": True,
                "response_observed": False,
                "composite_lease_header_present": False,
            })
        if upstream and upstream_response:
            self.write_private(self.upstream_response, {
                "request_observed": True,
                "response_observed": True,
                "composite_lease_header_present": False,
            })
        return raw

    def project(self, case: str) -> object:
        return self.projection.project_case(
            runtime_root=self.root,
            case_root=self.case_root,
            case=case,
            event_log=self.event_log,
            probe=self.probe,
            upstream_request_observation=self.upstream_request,
            upstream_response_observation=self.upstream_response,
        )

    def assert_no_projection_artifacts(self) -> None:
        for leaf in (
            "verifier-events.jsonl",
            "verifier-client.observation.json",
            "verifier-upstream.observation.json",
            "verifier-manifest.json",
            "verifier-summary.json",
        ):
            self.assertFalse((self.case_root / leaf).exists())
        self.assertFalse(any(
            path.name.startswith(".verifier-") and path.name.endswith(".tmp")
            for path in self.case_root.iterdir()
        ))

    def test_p4_safe_projection_runs_the_common_verifier_without_copying_payloads_or_ids(self) -> None:
        raw = self.set_case("p4_safe")

        result = self.project("p4_safe")

        self.assertEqual(result.status, "LIFECYCLE_ONLY")
        self.assertFalse(result.catalog_acceptance)
        copied = self.case_root / "verifier-events.jsonl"
        self.assertEqual(copied.read_text(encoding="utf-8"), raw)
        client = json.loads((self.case_root / "verifier-client.observation.json").read_text(encoding="utf-8"))
        self.assertEqual(client, {
            "lease_observed": False,
            "visible_status": 200,
            "redirect_location_verified": False,
            "p4_outcome": "none",
            "p4_visible_status": 200,
            "p4_response_committed": True,
        })
        summary = json.loads((self.case_root / "verifier-summary.json").read_text(encoding="utf-8"))
        self.assertEqual(set(summary), {
            "schema_version", "status", "scope", "lifecycle_verified",
            "catalog_acceptance", "payloads_persisted",
        })
        self.assertNotIn("decision_id", summary)
        self.assertFalse(summary["catalog_acceptance"])
        for leaf in (
            "verifier-events.jsonl",
            "verifier-client.observation.json",
            "verifier-upstream.observation.json",
            "verifier-manifest.json",
            "verifier-summary.json",
        ):
            self.assertEqual(stat.S_IMODE((self.case_root / leaf).stat().st_mode), 0o600)

    def test_request_side_deny_without_an_upstream_request_projects_terminal_state(self) -> None:
        self.set_case("p1_deny", upstream=False)

        result = self.project("p1_deny")

        self.assertEqual(result.status, "LIFECYCLE_ONLY")
        upstream = json.loads((self.case_root / "verifier-upstream.observation.json").read_text(encoding="utf-8"))
        self.assertEqual(upstream, {
            "lease_observed": False,
            "request_terminal": True,
            "response_observed": False,
        })

    def test_client_lease_header_observation_is_rejected_without_persisting_a_value(self) -> None:
        self.set_case("p4_safe", client_lease_header=True)

        with self.assertRaisesRegex(self.projection.ProjectionError, "private composite lease header"):
            self.project("p4_safe")

        self.assertFalse((self.case_root / "verifier-summary.json").exists())

    def test_allow_case_without_completed_upstream_observation_is_rejected(self) -> None:
        self.set_case("p1_allow", upstream=False)

        with self.assertRaisesRegex(self.projection.ProjectionError, "upstream observation is required"):
            self.project("p1_allow")

    def test_request_side_deny_rejects_an_upstream_request_without_completed_response(self) -> None:
        self.set_case("p1_deny", upstream=True, upstream_response=False)

        with self.assertRaisesRegex(self.projection.ProjectionError, "did not prove request and completed response"):
            self.project("p1_deny")

    def test_response_metadata_omission_projects_the_late_fail_closed_path(self) -> None:
        self.set_case("envoy_response_metadata_omitted")

        result = self.project("envoy_response_metadata_omitted")

        self.assertEqual(result.status, "LIFECYCLE_ONLY")
        client = json.loads((self.case_root / "verifier-client.observation.json").read_text(encoding="utf-8"))
        self.assertEqual(client, {
            "lease_observed": False,
            "visible_status": 503,
            "redirect_location_verified": False,
            "p4_outcome": "none",
            "p4_visible_status": None,
            "p4_response_committed": False,
        })
        upstream = json.loads((self.case_root / "verifier-upstream.observation.json").read_text(encoding="utf-8"))
        self.assertEqual(upstream, {
            "lease_observed": False,
            "request_terminal": False,
            "response_observed": True,
        })

    def test_p3_redirect_projection_requires_the_client_location_attestation(self) -> None:
        self.set_case("p3_redirect")

        result = self.project("p3_redirect")

        self.assertEqual(result.status, "LIFECYCLE_ONLY")
        client = json.loads((self.case_root / "verifier-client.observation.json").read_text(encoding="utf-8"))
        self.assertTrue(client["redirect_location_verified"])
        self.assertNotIn("msconnector-p3-redirect-target", json.dumps(client, sort_keys=True))

        for leaf in (
            "verifier-events.jsonl",
            "verifier-client.observation.json",
            "verifier-upstream.observation.json",
            "verifier-manifest.json",
            "verifier-summary.json",
        ):
            (self.case_root / leaf).unlink()
        self.set_case("p3_redirect", redirect_location_verified=False)
        with self.assertRaisesRegex(self.projection.ProjectionError, "common verifier rejected"):
            self.project("p3_redirect")
        for leaf in (
            "verifier-events.jsonl",
            "verifier-client.observation.json",
            "verifier-upstream.observation.json",
            "verifier-manifest.json",
        ):
            artifact = self.case_root / leaf
            self.assertTrue(artifact.is_file())
            self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
        self.assertFalse((self.case_root / "verifier-summary.json").exists())

    def test_case_root_traversal_is_rejected_before_projection_artifacts_are_created(self) -> None:
        self.set_case("p3_redirect")
        outside = self.root.parent / "outside"
        outside.mkdir(mode=0o700)
        outside.chmod(0o700)
        escaped_case_root = self.root / "case" / ".." / ".." / "outside"

        with self.assertRaisesRegex(self.projection.ProjectionError, "case root escapes runtime root"):
            self.projection.project_case(
                runtime_root=self.root,
                case_root=escaped_case_root,
                case="p3_redirect",
                event_log=self.event_log,
                probe=self.probe,
                upstream_request_observation=self.upstream_request,
                upstream_response_observation=self.upstream_response,
            )

        for leaf in (
            "verifier-events.jsonl",
            "verifier-client.observation.json",
            "verifier-upstream.observation.json",
            "verifier-manifest.json",
            "verifier-summary.json",
        ):
            self.assertFalse((outside / leaf).exists())

    def test_event_log_uses_the_validated_runtime_root_reader(self) -> None:
        self.set_case("p4_safe")
        original_read_text = self.projection.PrivateRuntimeRoot.read_text

        with patch.object(
            self.projection.PrivateRuntimeRoot,
            "read_text",
            autospec=True,
            side_effect=original_read_text,
        ) as read_text:
            result = self.project("p4_safe")

        self.assertEqual(result.status, "LIFECYCLE_ONLY")
        event_reads = [
            call
            for call in read_text.call_args_list
            if call.args[1] == self.event_log.name
        ]
        self.assertEqual(len(event_reads), 1)
        self.assertEqual(event_reads[0].kwargs, {
            "label": "event log",
            "maximum_bytes": self.projection.MAX_EVENT_LOG_BYTES,
        })

    def test_event_log_outside_the_runtime_root_is_rejected_before_artifact_creation(self) -> None:
        self.set_case("p4_safe")
        outside_event = self.root.parent / "outside-events.jsonl"
        self.write_private(outside_event, self.event_log.read_text(encoding="utf-8"))

        with self.assertRaisesRegex(self.projection.ProjectionError, "direct child"):
            self.projection.project_case(
                runtime_root=self.root,
                case_root=self.case_root,
                case="p4_safe",
                event_log=outside_event,
                probe=self.probe,
                upstream_request_observation=self.upstream_request,
                upstream_response_observation=self.upstream_response,
            )

        self.assertFalse((self.case_root / "verifier-summary.json").exists())

    def test_write_failure_before_atomic_publication_leaves_no_projection_artifacts(self) -> None:
        self.set_case("p4_safe")

        with patch.object(self.projection.os, "fsync", side_effect=OSError("injected fsync failure")):
            with self.assertRaises(OSError):
                self.project("p4_safe")

        self.assert_no_projection_artifacts()

    def test_existing_projection_artifact_is_preserved_when_publication_fails(self) -> None:
        self.set_case("p4_safe")
        existing = self.case_root / "verifier-events.jsonl"
        self.write_private(existing, "existing artifact\n")

        with self.assertRaises(FileExistsError):
            self.project("p4_safe")

        self.assertEqual(existing.read_text(encoding="utf-8"), "existing artifact\n")
        for leaf in (
            "verifier-client.observation.json",
            "verifier-upstream.observation.json",
            "verifier-manifest.json",
            "verifier-summary.json",
        ):
            self.assertFalse((self.case_root / leaf).exists())

    def test_projection_output_requires_anonymous_staging(self) -> None:
        self.set_case("p4_safe")

        with patch.object(self.projection.os, "O_TMPFILE", 0):
            with self.assertRaisesRegex(self.projection.ProjectionError, "O_TMPFILE"):
                self.project("p4_safe")

        self.assert_no_projection_artifacts()

    def test_cleanup_refuses_to_delete_a_replaced_projection_artifact(self) -> None:
        self.set_case("p4_safe")
        replaced = self.case_root / "verifier-events.jsonl"

        def replace_and_reject(*_args: object, **_kwargs: object) -> object:
            replaced.unlink()
            self.write_private(replaced, "replacement artifact\n")
            raise self.projection.EvidenceError("injected verifier rejection")

        with patch.object(self.projection, "verify_manifest", side_effect=replace_and_reject):
            with self.assertRaisesRegex(self.projection.ProjectionError, "common verifier rejected"):
                self.project("p4_safe")

        self.assertEqual(replaced.read_text(encoding="utf-8"), "replacement artifact\n")
        for leaf in (
            "verifier-client.observation.json",
            "verifier-upstream.observation.json",
            "verifier-manifest.json",
        ):
            self.assertTrue((self.case_root / leaf).exists())
        self.assertFalse((self.case_root / "verifier-summary.json").exists())

    def test_forbidden_event_metadata_is_rejected_before_artifact_creation(self) -> None:
        self.set_case("p4_safe")
        events = [
            json.loads(line)
            for line in self.event_log.read_text(encoding="utf-8").splitlines()
        ]
        events[0]["body_payload_persisted"] = False
        self.write_private(
            self.event_log,
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
        )

        with self.assertRaisesRegex(self.projection.ProjectionError, "common verifier schema"):
            self.project("p4_safe")

        for leaf in (
            "verifier-events.jsonl",
            "verifier-client.observation.json",
            "verifier-upstream.observation.json",
            "verifier-manifest.json",
            "verifier-summary.json",
        ):
            self.assertFalse((self.case_root / leaf).exists())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
