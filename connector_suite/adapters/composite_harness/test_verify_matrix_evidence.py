import json
import os
import tempfile
import unittest
from pathlib import Path

from connector_suite.adapters.composite_harness.verify_matrix_evidence import (
    MAX_EVENT_LINE_BYTES,
    EvidenceError,
    verify_manifest,
)
from connector_suite.adapters.traefik.harness.traefik_composite_upstream import response_header_delay_seconds


DECISION = "a" * 64
EVENT_TIME = "2026-08-24T17:00:00Z"
PIPELINES = {
    "envoy": {
        "request_path": "envoy.ext_authz",
        "response_path": "envoy.ext_proc",
        "transport": "envoy_ext_authz_ext_proc_grpc",
    },
    "traefik": {
        "request_path": "traefik.forwardAuth",
        "response_path": "traefik.native_uds",
        "transport": "traefik_forwardauth_private_uds",
    },
}
CASE_RULE_IDS = {
    ("p1_deny", "P1"): "1101001",
    ("p2_deny", "P2"): "1102001",
    ("p3_deny", "P3"): "1103001",
    ("p3_redirect", "P3"): "1103002",
    ("p4_safe", "P4"): "1104002",
}


class CompositeEvidenceVerifierTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tempdir.cleanup()

    @staticmethod
    def pipeline_fields(connector):
        return dict(PIPELINES[connector])

    def write_case(self, *, case="p4_safe", connector="envoy", mutate=None, strict_observation=False):
        directory = Path(self.tempdir.name)
        directory.chmod(0o700)
        phases = {
            "p1_allow": ["P1", "P2", "P3", "P4"],
            "p1_deny": ["P1"],
            "p2_allow": ["P1", "P2", "P3", "P4"],
            "p2_deny": ["P1", "P2"],
            "p2_oversize": ["P1", "P2"],
            "p3_deny": ["P1", "P2", "P3"],
            "p3_redirect": ["P1", "P2", "P3"],
            "p4_safe": ["P1", "P2", "P3", "P4"],
            "p4_strict": ["P1", "P2", "P3", "P4"],
            "metadata_omitted": [],
            "envoy_response_metadata_omitted": ["P1", "P2"],
            "p2_to_p3_timeout": ["P1", "P2"],
        }[case]
        events = []
        for phase in phases:
            if case == "p1_deny" or (case == "p2_deny" and phase == "P2"):
                action = "deny"
            else:
                action = "allow" if phase in {"P1", "P2"} else "deny"
            status = 200 if action == "allow" else 403
            if case == "p2_oversize" and phase == "P2":
                action, status = "deny", 413
            if case == "p3_redirect" and phase == "P3":
                action, status = "redirect", 302
            events.append({
                "decision_id": DECISION,
                "connector": connector,
                "phase": phase,
                "outcome": "observed",
                "requested_action": action,
                "visible_status": status,
                "event_time": EVENT_TIME,
                **self.pipeline_fields(connector),
            })
            rule_id = CASE_RULE_IDS.get((case, phase))
            if rule_id is not None:
                events[-1]["rule_id"] = rule_id
        if case != "metadata_omitted":
            events.insert(len(events), {
                "decision_id": DECISION,
                "connector": connector,
                "phase": "lease",
                "outcome": "issued",
                "event_time": EVENT_TIME,
                **self.pipeline_fields(connector),
            })
            if case == "p2_to_p3_timeout" and connector == "traefik":
                events.insert(0, {
                    "decision_id": DECISION,
                    "connector": connector,
                    "phase": "reservation",
                    "outcome": "reserved",
                    "event_time": EVENT_TIME,
                    **self.pipeline_fields(connector),
                })
        else:
            events.insert(0, {
                "decision_id": DECISION,
                "connector": connector,
                "phase": "reservation",
                "outcome": "reserved",
                "event_time": EVENT_TIME,
                **self.pipeline_fields(connector),
            })
        host_action = None
        host_status = None
        if case == "p4_safe":
            host_action, host_status = "log_only", 200
        elif case in {"p1_deny", "p2_deny", "p3_deny"}:
            host_action, host_status = "deny", 403
        elif case == "p3_redirect":
            host_action, host_status = "redirect", 302
        elif case == "p2_oversize":
            host_action, host_status = "deny", 413
        if host_action is not None:
            events.insert(len(events), {
                "decision_id": DECISION,
                "connector": connector,
                "phase": "host_action" if case == "p4_safe" else "request_host_action",
                "outcome": "recorded",
                "actual_host_action": host_action,
                "visible_status": host_status,
                "event_time": EVENT_TIME,
                **self.pipeline_fields(connector),
            })
        terminal_event = {
            "decision_id": DECISION,
            "connector": connector,
            "phase": "terminal",
            "outcome": "closed",
            "cleanup_outcome": "closed",
            "event_time": EVENT_TIME,
            **self.pipeline_fields(connector),
        }
        if case in {"p2_to_p3_timeout", "envoy_response_metadata_omitted"}:
            terminal_event["reason"] = "timeout"
        if case == "metadata_omitted":
            terminal_event["reason"] = "disconnect"
        events.insert(len(events), terminal_event)
        if mutate:
            mutate(events)
        event_log = directory / "case-001.events.jsonl"
        event_log.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
        event_log.chmod(0o600)
        client_outcome = "none"
        client_status = 503 if case in {"metadata_omitted", "envoy_response_metadata_omitted", "p2_to_p3_timeout"} else 200
        committed = case not in {"metadata_omitted", "envoy_response_metadata_omitted", "p2_to_p3_timeout"}
        if case == "p4_strict" and strict_observation:
            client_outcome, client_status, committed = "abort", None, False
        client_observation = directory / "client.observation.json"
        client_observation.write_text(json.dumps({
            "lease_observed": False,
            "visible_status": 503 if case in {"metadata_omitted", "envoy_response_metadata_omitted", "p2_to_p3_timeout"} else (413 if case == "p2_oversize" else (302 if case == "p3_redirect" else (403 if case in {"p1_deny", "p2_deny", "p3_deny"} else 200))),
            "redirect_location_verified": case == "p3_redirect",
            "p4_outcome": client_outcome,
            "p4_visible_status": client_status if committed else None,
            "p4_response_committed": committed,
        }), encoding="utf-8")
        client_observation.chmod(0o600)
        upstream_observation = directory / "upstream.observation.json"
        upstream_observation.write_text(json.dumps({
            "lease_observed": False,
            "request_terminal": case in {"p1_deny", "p2_deny", "p2_oversize"},
            "response_observed": case in {
                "p1_allow", "p2_allow", "p3_deny", "p3_redirect", "p4_safe",
                "p4_strict", "envoy_response_metadata_omitted", "p2_to_p3_timeout",
            },
        }), encoding="utf-8")
        upstream_observation.chmod(0o600)
        manifest = {
            "schema": "msc-composite-evidence/v1",
            "connector": connector,
            "case": case,
            "case_artifact": {"id": "case-001", "event_log": event_log.name},
            "expected_phases": phases,
            "client_observation": client_observation.name,
            "upstream_observation": upstream_observation.name,
            "cleanup": {"count": 1, "status": "completed"},
        }
        manifest_path = directory / "case-001.manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        manifest_path.chmod(0o600)
        return manifest_path

    def assert_invalid_case(self, pattern, **case_kwargs):
        manifest = self.write_case(**case_kwargs)
        with self.assertRaisesRegex(EvidenceError, pattern):
            verify_manifest(manifest)

    def test_real_observer_schema_passes_with_lifecycle_records(self):
        result = verify_manifest(self.write_case())
        self.assertTrue(result.passed)
        self.assertEqual(result.status, "LIFECYCLE_ONLY")
        self.assertTrue(result.lifecycle_verified)
        self.assertFalse(result.catalog_acceptance)
        self.assertEqual(result.phases, ("P1", "P2", "P3", "P4"))

    def test_explicit_private_runtime_root_is_bound_to_direct_children(self):
        manifest = self.write_case()
        self.assertTrue(verify_manifest(manifest, runtime_root=manifest.parent).passed)
        with self.assertRaisesRegex(EvidenceError, "direct child"):
            verify_manifest(manifest, runtime_root=manifest.parent.parent)

    def test_private_runtime_root_rejects_unsafe_modes(self):
        manifest = self.write_case()
        manifest.parent.chmod(0o755)
        with self.assertRaisesRegex(EvidenceError, "0700"):
            verify_manifest(manifest)

        manifest = self.write_case()
        manifest.chmod(0o644)
        with self.assertRaisesRegex(EvidenceError, "0600"):
            verify_manifest(manifest)

    def test_private_runtime_root_rejects_hardlinks(self):
        manifest = self.write_case()
        duplicate = manifest.parent / "manifest-hardlink.json"
        try:
            os.link(manifest, duplicate)
        except OSError:
            self.skipTest("hard links unavailable")
        with self.assertRaisesRegex(EvidenceError, "hard links"):
            verify_manifest(manifest)

    def test_private_runtime_root_rejects_symlink_and_traversal_leaves(self):
        manifest = self.write_case()
        outside = Path(self.tempdir.name).parent / "outside-event-log.jsonl"
        outside.write_text((manifest.parent / "case-001.events.jsonl").read_text(), encoding="utf-8")
        outside.chmod(0o600)
        event_log = manifest.parent / "case-001.events.jsonl"
        event_log.unlink()
        try:
            os.symlink(outside, event_log)
        except OSError:
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(EvidenceError, "regular file|symlink"):
            verify_manifest(manifest)

        manifest = self.write_case()
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["client_observation"] = "../outside-event-log.jsonl"
        manifest.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "relative basename"):
            verify_manifest(manifest)

    def test_event_line_limit_includes_crlf_terminator(self):
        manifest = self.write_case()
        event_log = manifest.parent / "case-001.events.jsonl"
        event_log.write_bytes(b"{}" + b" " * (MAX_EVENT_LINE_BYTES - 3) + b"\r\n")
        event_log.chmod(0o600)
        with self.assertRaisesRegex(EvidenceError, "exceeds metadata bounds"):
            verify_manifest(manifest)

    def test_strict_requires_actual_client_abort_or_reset_observation(self):
        result = verify_manifest(self.write_case(case="p4_strict"))
        self.assertEqual(result.status, "NON_PASS")
        result = verify_manifest(self.write_case(case="p4_strict", strict_observation=True))
        self.assertEqual(result.status, "NON_PASS")

    def test_metadata_omitted_requires_pre_admission_reservation_and_cleanup(self):
        result = verify_manifest(self.write_case(case="metadata_omitted"))
        self.assertEqual(result.status, "LIFECYCLE_ONLY")
        self.assertEqual(result.phases, ())

        def remove_reservation(events):
            events.pop(0)

        self.assert_invalid_case("pre-admission reservation", case="metadata_omitted", mutate=remove_reservation)

    def test_envoy_response_metadata_omitted_requires_bounded_response_boundary_cleanup(self):
        result = verify_manifest(self.write_case(case="envoy_response_metadata_omitted"))
        self.assertEqual(result.status, "LIFECYCLE_ONLY")
        self.assertEqual(result.phases, ("P1", "P2"))

        def add_claim(events):
            events.insert(-1, {
                "decision_id": DECISION, "connector": "envoy", "phase": "claim",
                "outcome": "claimed", "event_time": EVENT_TIME,
                **self.pipeline_fields("envoy"),
            })

        self.assert_invalid_case(
            "one unclaimed lease", case="envoy_response_metadata_omitted", mutate=add_claim
        )

        def deny_p1(events):
            events[0]["requested_action"] = "deny"

        self.assert_invalid_case("requested_action=allow", case="envoy_response_metadata_omitted", mutate=deny_p1)

        manifest = self.write_case(case="envoy_response_metadata_omitted")
        event_log = manifest.parent / "case-001.events.jsonl"
        events = [json.loads(line) for line in event_log.read_text(encoding="utf-8").splitlines()]
        events[2]["outcome"] = "claimed"
        event_log.write_text(
            "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
        )
        with self.assertRaisesRegex(EvidenceError, "issued lease"):
            verify_manifest(manifest)

        manifest = self.write_case(case="envoy_response_metadata_omitted")
        client = manifest.parent / "client.observation.json"
        data = json.loads(client.read_text(encoding="utf-8"))
        data["p4_visible_status"] = 503
        client.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "before P4 response commitment"):
            verify_manifest(manifest)

        manifest = self.write_case(case="envoy_response_metadata_omitted")
        client = manifest.parent / "client.observation.json"
        data = json.loads(client.read_text(encoding="utf-8"))
        data["visible_status"] = 502
        client.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "fail-closed 503"):
            verify_manifest(manifest)

        manifest = self.write_case(case="envoy_response_metadata_omitted")
        client = manifest.parent / "client.observation.json"
        data = json.loads(client.read_text(encoding="utf-8"))
        data["p4_response_committed"] = True
        client.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "before P4 response commitment"):
            verify_manifest(manifest)

        manifest = self.write_case(case="envoy_response_metadata_omitted")
        upstream = manifest.parent / "upstream.observation.json"
        data = json.loads(upstream.read_text(encoding="utf-8"))
        data["response_observed"] = False
        upstream.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "upstream response"):
            verify_manifest(manifest)

        manifest = self.write_case(case="envoy_response_metadata_omitted")
        event_log = manifest.parent / "case-001.events.jsonl"
        events = [json.loads(line) for line in event_log.read_text(encoding="utf-8").splitlines()]
        events[-1]["reason"] = "disconnect"
        event_log.write_text(
            "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
        )
        with self.assertRaisesRegex(EvidenceError, "timeout cleanup"):
            verify_manifest(manifest)

        def duplicate_lease(events):
            events.insert(-1, dict(events[2]))

        self.assert_invalid_case(
            "one unclaimed lease", case="envoy_response_metadata_omitted", mutate=duplicate_lease
        )

        def replace_with_traefik_reservation(events):
            reservation = dict(events[0])
            reservation.pop("requested_action", None)
            reservation.pop("visible_status", None)
            reservation["phase"] = "reservation"
            reservation["outcome"] = "reserved"
            terminal = dict(events[-1])
            terminal["reason"] = "disconnect"
            events[:] = [reservation, terminal]

        self.assert_invalid_case(
            "missing or out of order", case="envoy_response_metadata_omitted", mutate=replace_with_traefik_reservation
        )

        invalid_connector_manifest = self.write_case(
            case="envoy_response_metadata_omitted", connector="traefik"
        )
        with self.assertRaisesRegex(EvidenceError, "valid only for the Envoy composite"):
            verify_manifest(invalid_connector_manifest)

    def test_p2_to_p3_timeout_requires_upstream_observation_and_timeout_cleanup(self):
        result = verify_manifest(self.write_case(case="p2_to_p3_timeout"))
        self.assertEqual(result.status, "LIFECYCLE_ONLY")
        self.assertEqual(result.phases, ("P1", "P2"))

        def fabricate_p3(events):
            events.insert(2, {
                "decision_id": DECISION, "connector": "envoy", "phase": "P3",
                "outcome": "observed", "event_time": EVENT_TIME,
                **self.pipeline_fields("envoy"),
            })

        self.assert_invalid_case("out of order", case="p2_to_p3_timeout", mutate=fabricate_p3)

        manifest = self.write_case(case="p2_to_p3_timeout")
        upstream = manifest.parent / "upstream.observation.json"
        data = json.loads(upstream.read_text(encoding="utf-8"))
        data["response_observed"] = False
        upstream.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "upstream request observation"):
            verify_manifest(manifest)

        manifest = self.write_case(case="p2_to_p3_timeout")
        event_log = manifest.parent / "case-001.events.jsonl"
        events = [json.loads(line) for line in event_log.read_text(encoding="utf-8").splitlines()]
        events[-1]["reason"] = "other"
        event_log.write_text(
            "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
        )
        with self.assertRaisesRegex(EvidenceError, "timeout cleanup"):
            verify_manifest(manifest)

        manifest = self.write_case(case="p2_to_p3_timeout")
        event_log = manifest.parent / "case-001.events.jsonl"
        events = [json.loads(line) for line in event_log.read_text(encoding="utf-8").splitlines()]
        events[2]["outcome"] = "cancelled"
        event_log.write_text(
            "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
        )
        with self.assertRaisesRegex(EvidenceError, "issued lease"):
            verify_manifest(manifest)

        def add_claim(events):
            events.insert(-1, {
                "decision_id": DECISION, "connector": "envoy", "phase": "claim",
                "outcome": "claimed", "event_time": EVENT_TIME,
                **self.pipeline_fields("envoy"),
            })

        self.assert_invalid_case(
            "unclaimed lease", case="p2_to_p3_timeout", mutate=add_claim
        )

    def test_traefik_p2_to_p3_timeout_requires_one_pre_admission_reservation(self):
        result = verify_manifest(self.write_case(case="p2_to_p3_timeout", connector="traefik"))
        self.assertEqual(result.status, "LIFECYCLE_ONLY")
        self.assertEqual(result.phases, ("P1", "P2"))

        def remove_reservation(events):
            events.pop(0)

        self.assert_invalid_case(
            "unclaimed lease", case="p2_to_p3_timeout", connector="traefik", mutate=remove_reservation
        )

        def corrupt_reservation(events):
            events[0]["outcome"] = "issued"

        self.assert_invalid_case(
            "pre-admission reservation", case="p2_to_p3_timeout", connector="traefik", mutate=corrupt_reservation
        )

    def test_p2_oversize_accepts_matching_native_403(self):
        def native_request_reject(events):
            for event in events:
                if event.get("phase") in {"P2", "request_host_action"}:
                    event["visible_status"] = 403

        for connector in ("envoy", "traefik"):
            with self.subTest(connector=connector):
                manifest = self.write_case(case="p2_oversize", connector=connector, mutate=native_request_reject)
                client = manifest.parent / "client.observation.json"
                data = json.loads(client.read_text(encoding="utf-8"))
                data["visible_status"] = 403
                client.write_text(json.dumps(data), encoding="utf-8")
                self.assertEqual(verify_manifest(manifest).status, "LIFECYCLE_ONLY")

    def test_p2_oversize_rejects_a_different_host_status(self):
        def mismatch(events):
            for event in events:
                if event.get("phase") == "request_host_action":
                    event["visible_status"] = 403

        self.assert_invalid_case("matching native 403/413", case="p2_oversize", mutate=mismatch)

    def test_p2_oversize_requires_native_p2_before_transport_rejection(self):
        def remove_p2(events):
            events[:] = [event for event in events if event.get("phase") != "P2"]

        self.assert_invalid_case(
            "raw P1..P4 observer events are missing or out of order",
            case="p2_oversize",
            mutate=remove_p2,
        )

    def test_p2_oversize_requires_the_matching_observed_client_status(self):
        manifest = self.write_case(case="p2_oversize")
        client = manifest.parent / "client.observation.json"
        data = json.loads(client.read_text(encoding="utf-8"))
        data["visible_status"] = 200
        client.write_text(json.dumps(data), encoding="utf-8")

        with self.assertRaisesRegex(EvidenceError, "matching native 403/413"):
            verify_manifest(manifest)

    def test_p4_safe_requires_matching_committed_client_status(self):
        manifest = self.write_case(case="p4_safe")
        client = manifest.parent / "client.observation.json"
        data = json.loads(client.read_text(encoding="utf-8"))
        data["visible_status"] = 503
        data["p4_visible_status"] = 503
        client.write_text(json.dumps(data), encoding="utf-8")

        with self.assertRaisesRegex(EvidenceError, "matching committed client"):
            verify_manifest(manifest)

        manifest = self.write_case(case="p4_safe")
        event_log = manifest.parent / "case-001.events.jsonl"
        events = [json.loads(line) for line in event_log.read_text(encoding="utf-8").splitlines()]
        events[3]["requested_action"] = "allow"
        event_log.write_text(
            "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
        )

        with self.assertRaisesRegex(EvidenceError, "requested_action=deny"):
            verify_manifest(manifest)

        manifest = self.write_case(case="p4_safe")
        event_log = manifest.parent / "case-001.events.jsonl"
        events = [json.loads(line) for line in event_log.read_text(encoding="utf-8").splitlines()]
        del events[5]["visible_status"]
        event_log.write_text(
            "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
        )
        client = manifest.parent / "client.observation.json"
        data = json.loads(client.read_text(encoding="utf-8"))
        data["visible_status"] = None
        data["p4_visible_status"] = None
        client.write_text(json.dumps(data), encoding="utf-8")

        with self.assertRaisesRegex(EvidenceError, "matching committed client"):
            verify_manifest(manifest)

        manifest = self.write_case(case="p4_safe")
        client = manifest.parent / "client.observation.json"
        data = json.loads(client.read_text(encoding="utf-8"))
        data["p4_visible_status"] = 503
        client.write_text(json.dumps(data), encoding="utf-8")

        with self.assertRaisesRegex(EvidenceError, "matching committed client"):
            verify_manifest(manifest)

    def test_timeout_header_delay_is_selected_only_by_exact_runtime_root(self):
        self.assertEqual(response_header_delay_seconds(Path("/tmp/p2_to_p3_timeout")), 6.0)
        self.assertEqual(response_header_delay_seconds(Path("/tmp/run-p2_to_p3_timeout")), 6.0)
        self.assertEqual(response_header_delay_seconds(Path("/tmp/p2_to_p3_timeout-extra")), 0.0)
        self.assertEqual(response_header_delay_seconds(Path("/tmp/run-p2_to_p3_timeout-extra")), 0.0)

    def test_rejects_unknown_body_and_lease_fields_in_raw_observer_log(self):
        def add_body(events):
            events[0]["request_body"] = "forbidden"

        self.assert_invalid_case("forbidden payload field", mutate=add_body)

        def add_lease(events):
            events[0]["lease"] = "forbidden"

        self.assert_invalid_case("forbidden payload field", mutate=add_lease)

    def test_rejects_lease_exposure_in_separate_client_observation(self):
        manifest = self.write_case()
        observation = manifest.parent / "client.observation.json"
        data = json.loads(observation.read_text(encoding="utf-8"))
        data["lease_observed"] = True
        observation.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "lease observed"):
            verify_manifest(manifest)

    def test_rejects_inline_observation_assertions_and_unsafe_paths(self):
        manifest = self.write_case()
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["observations"] = {"client": {"lease_observed": False}}
        manifest.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "unknown field|forbidden"):
            verify_manifest(manifest)

        manifest = self.write_case()
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["client_observation"] = "../client.observation.json"
        manifest.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "relative basename"):
            verify_manifest(manifest)

    def test_rejects_symlinked_observation_file(self):
        manifest = self.write_case()
        observation = manifest.parent / "client.observation.json"
        target = manifest.parent / "client.observation.target.json"
        target.write_text(observation.read_text(encoding="utf-8"), encoding="utf-8")
        observation.unlink()
        try:
            os.symlink(target, observation)
        except OSError:
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(EvidenceError, "non-symlink"):
            verify_manifest(manifest)

    def test_allow_cases_require_raw_allow_upstream_response_and_no_termination(self):
        for case in ("p1_allow", "p2_allow"):
            with self.subTest(case=case):
                self.assertTrue(verify_manifest(self.write_case(case=case)).passed)

                def deny(events):
                    events[0]["requested_action"] = "deny"

                self.assert_invalid_case("allow", case=case, mutate=deny)

                def request_action(events):
                    events.insert(1, {
                        "decision_id": DECISION, "connector": "envoy", "phase": "request_host_action",
                        "outcome": "recorded", "actual_host_action": "deny", "visible_status": 403,
                        "event_time": EVENT_TIME, **self.pipeline_fields("envoy"),
                    })

                self.assert_invalid_case("request_host_action", case=case, mutate=request_action)

    def test_allow_controls_require_response_lifecycle_on_the_same_receipt(self):
        manifest = self.write_case(case="p1_allow")
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["expected_phases"] = ["P1", "P2"]
        manifest.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "exactly match"):
            verify_manifest(manifest)

    def test_expected_event_log_option_requires_exact_absolute_regular_path(self):
        manifest = self.write_case()
        event_log = manifest.parent / "case-001.events.jsonl"
        self.assertTrue(verify_manifest(manifest, event_log).passed)

        other = manifest.parent / "other.events.jsonl"
        other.write_text(event_log.read_text(encoding="utf-8"), encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "does not match"):
            verify_manifest(manifest, other)

        with self.assertRaisesRegex(EvidenceError, "absolute"):
            verify_manifest(manifest, "case-001.events.jsonl")

    def test_rejects_cross_connector_decision_or_phase_mismatch(self):
        def cross_connector(events):
            events[2]["connector"] = "traefik"

        self.assert_invalid_case("connector", mutate=cross_connector)

        def cross_decision(events):
            events[-1]["decision_id"] = "b" * 64

        self.assert_invalid_case("exactly one", mutate=cross_decision)

        def reorder(events):
            events[0]["phase"], events[1]["phase"] = events[1]["phase"], events[0]["phase"]

        self.assert_invalid_case("order", case="p2_allow", mutate=reorder)

    def test_requires_exactly_one_terminal_cleanup(self):
        def add_terminal(events):
            events.append(dict(events[-1]))

        self.assert_invalid_case("terminal cleanup", mutate=add_terminal)

        def append_after_terminal(events):
            events.append({
                "decision_id": DECISION, "connector": "envoy", "phase": "neutral_outcome",
                "outcome": "allow", "event_time": EVENT_TIME, **self.pipeline_fields("envoy"),
            })

        self.assert_invalid_case("final observer event", mutate=append_after_terminal)

    def test_p4_safe_requires_raw_log_only_action(self):
        def remove_log_only(events):
            events[:] = [event for event in events if event.get("actual_host_action") != "log_only"]

        self.assert_invalid_case("log_only", mutate=remove_log_only)

    def test_requires_connector_pipeline_metadata_and_selected_rule_id(self):
        def missing_pipeline(events):
            del events[0]["transport"]

        self.assert_invalid_case("missing required", mutate=missing_pipeline)

        def wrong_rule(events):
            for event in events:
                if event.get("phase") == "P4":
                    event["rule_id"] = "9999999"

        self.assert_invalid_case("p4_safe.*rule_id=1104002", mutate=wrong_rule)

    def test_p3_deny_rejects_incorrect_raw_outcome(self):
        def replace_deny(events):
            for event in events:
                if event.get("phase") == "request_host_action":
                    event["actual_host_action"] = "allow"

        self.assert_invalid_case("p3_deny", case="p3_deny", mutate=replace_deny)

    def test_p3_redirect_requires_exact_client_boundary_location_attestation(self):
        self.assertTrue(verify_manifest(self.write_case(case="p3_redirect")).passed)
        manifest = self.write_case(case="p3_redirect")
        client = manifest.parent / "client.observation.json"
        data = json.loads(client.read_text(encoding="utf-8"))
        data["redirect_location_verified"] = False
        client.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "Location attestation"):
            verify_manifest(manifest)

    def test_p3_redirect_requires_the_canonical_302_status(self):
        def noncanonical_redirect(events):
            for event in events:
                if event.get("phase") in {"P3", "request_host_action"}:
                    event["visible_status"] = 301

        manifest = self.write_case(case="p3_redirect", mutate=noncanonical_redirect)
        client = manifest.parent / "client.observation.json"
        data = json.loads(client.read_text(encoding="utf-8"))
        data["visible_status"] = 301
        client.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "canonical HTTP 302"):
            verify_manifest(manifest)

    def test_p1_deny_requires_matching_request_side_deny(self):
        self.assertTrue(verify_manifest(self.write_case(case="p1_deny")).passed)

        def replace_deny(events):
            for event in events:
                if event.get("phase") == "request_host_action":
                    event["actual_host_action"] = "allow"

        self.assert_invalid_case("p1_deny", case="p1_deny", mutate=replace_deny)

    def test_p2_deny_requires_matching_request_side_deny(self):
        self.assertTrue(verify_manifest(self.write_case(case="p2_deny")).passed)

        def replace_deny(events):
            for event in events:
                if event.get("phase") == "request_host_action":
                    event["actual_host_action"] = "allow"

        self.assert_invalid_case("p2_deny", case="p2_deny", mutate=replace_deny)

    def test_phase_actions_and_response_observation_cannot_be_relabeled(self):
        def incorrect_p1(events):
            events[0]["requested_action"] = "allow"

        self.assert_invalid_case("p1_deny.*P1", case="p1_deny", mutate=incorrect_p1)

        def incorrect_p3(events):
            for event in events:
                if event.get("phase") == "P3":
                    event["requested_action"] = "allow"

        self.assert_invalid_case("p3_deny.*P3", case="p3_deny", mutate=incorrect_p3)

        manifest = self.write_case(case="p3_redirect")
        upstream = manifest.parent / "upstream.observation.json"
        data = json.loads(upstream.read_text(encoding="utf-8"))
        data["response_observed"] = False
        upstream.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "upstream response observation"):
            verify_manifest(manifest)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
