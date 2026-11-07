"""Opt-in native Traefik H2 evidence contract controls."""

import copy
import unittest
from connector_suite.adapters.traefik.harness import (
    traefik_native_h2_acceptance as harness,
)


def strict_fixture():
    case = "phase4_strict"
    ids = {
        role: f"traefik-native-h2-{case}-{role}"
        for role in ("peer", "target", "followup")
    }
    wire = {
        "alpn": "h2",
        "tls_verified": True,
        "tls_version": "TLSv1.3",
        "requests": [
            {
                "stream_id": stream,
                "transaction_id": ids[role],
                "path": f"/{case}/{role}",
                "method": "GET",
                "body_bytes": 0,
            }
            for role, stream in (("peer", 1), ("target", 3), ("followup", 5))
        ],
        "status": {"1": 200, "3": 200, "5": 200},
        "body_bytes": {"1": 10, "3": 33, "5": 10},
        "terminal": {
            "1": {"type": 0, "flags": 1},
            "3": {"type": 3, "reset_code": 2},
            "5": {"type": 0, "flags": 1},
        },
        "frames": [
            {"type": 0, "stream_id": 3, "size": 6, "monotonic_ns": 1},
            {
                "type": "first_byte_before_eos",
                "peer_held": True,
                "target_eos_held": True,
                "monotonic_ns": 2,
            },
            {
                "type": "native_completion_observed",
                "transaction_id": ids["target"],
                "peer_held": True,
                "monotonic_ns": 3,
            },
        ],
    }
    events = [
        {
            "event": "transaction_cleanup",
            "transaction_id": ids[role],
            "connector": "traefik",
            "integration_mode": "native-traefik-middleware",
            "event_hash": index + 1,
            "sequence": index + 1,
            "response_committed": True,
            "eos_seen": role != "target",
        }
        for index, role in enumerate(ids)
    ]
    events.append(
        {
            "event": "engine_decision",
            "transaction_id": ids["target"],
            "rule_id": "1100301",
            "phase": "response_body",
            "requested_action": "deny",
            "http_status": 403,
            "connector": "traefik",
            "integration_mode": "native-traefik-middleware",
            "uri": f"/{case}/target",
            "method": "GET",
            "body_bytes_seen": 33,
        }
    )
    upstream = []
    access = []
    for number, role in enumerate(ids, 1):
        upstream.append({"event": "upstream_request", "transaction_id": ids[role]})
        if role == "peer":
            upstream.append(
                {
                    "event": "upstream_paused",
                    "transaction_id": ids[role],
                    "eos_sent": False,
                    "monotonic_ns": 1,
                }
            )
        upstream.append(
            {
                "event": "upstream_eos",
                "transaction_id": ids[role],
                "eos_sent": True,
                "monotonic_ns": 4 if role == "peer" else 5,
            }
        )
        access.append(
            {
                "ClientAddr": "127.0.0.1:12345",
                "RequestCount": number,
                "RequestPath": f"/{case}/{role}",
                "RequestMethod": "GET",
                "RequestContentSize": 0,
                "RequestProtocol": "HTTP/2.0",
                "TLSVersion": "1.3",
                "RequestScheme": "https",
                "request_X-Acceptance-Id": ids[role],
                "DownstreamStatus": 200,
                "DownstreamContentSize": 33 if role == "target" else 10,
            }
        )
    return wire, events, upstream, access


class NativeH2ContractTests(unittest.TestCase):
    def setUp(self):
        self.wire, self.events, self.upstream, self.access = strict_fixture()

    def validate(self):
        return harness.validate(
            "phase4_strict", self.wire, self.events, self.upstream, self.access
        )

    def rejected(self):
        with self.assertRaises(ValueError):
            self.validate()

    def test_complete_strict_evidence_is_accepted(self):
        self.assertEqual(self.validate()["status"], "PASS")

    def test_zero_native_rows_fail(self):
        self.events.clear()
        self.rejected()

    def test_missing_wire_traffic_fails(self):
        self.wire["requests"].clear()
        self.rejected()

    def test_wrong_reset_code_fails(self):
        self.wire["terminal"]["3"]["reset_code"] = 0
        self.rejected()

    def test_foreign_transaction_fails(self):
        self.events[1]["transaction_id"] = "foreign"
        self.rejected()

    def test_duplicate_cleanup_fails(self):
        self.events.append(copy.deepcopy(self.events[1]))
        self.rejected()

    def test_wrong_rule_fails(self):
        self.events[-1]["rule_id"] = "1100201"
        self.rejected()

    def test_protocol_fallback_fails(self):
        self.wire["alpn"] = "http/1.1"
        self.rejected()

    def test_reset_peer_fails(self):
        self.wire["terminal"]["1"] = {"type": 3, "reset_code": 2}
        self.rejected()

    def test_cleanup_without_held_peer_fails(self):
        self.wire["frames"][-1]["peer_held"] = False
        self.rejected()

    def test_strict_mislabeled_log_only_fails(self):
        self.events[-1]["actual_action"] = "log_only"
        self.rejected()

    def test_wrong_response_byte_count_fails(self):
        self.wire["body_bytes"]["3"] = 6
        self.rejected()

    def test_incomplete_native_writer_record_fails(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path

        with TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text('{"event":"transaction_cleanup"}')
            with self.assertRaisesRegex(ValueError, "incomplete native JSONL"):
                harness.read_records(path)

    def test_strict_without_target_upstream_eos_fails(self):
        self.upstream = [
            row
            for row in self.upstream
            if not (
                row["transaction_id"].endswith("-target")
                and row["event"] == "upstream_eos"
            )
        ]
        self.rejected()

    def test_strict_upstream_reset_confounds_fail(self):
        self.upstream.append(
            {
                "event": "upstream_abort",
                "transaction_id": "traefik-native-h2-phase4_strict-target",
                "eos_sent": False,
            }
        )
        self.rejected()

    def test_duplicate_peer_missing_followup_access_fails(self):
        self.access[-1] = copy.deepcopy(self.access[0])
        self.access[-1]["RequestCount"] = 3
        self.rejected()

    def test_crossed_native_request_id_fails(self):
        self.access[1]["request_X-Acceptance-Id"] = self.access[0][
            "request_X-Acceptance-Id"
        ]
        self.rejected()

    def test_wrong_native_status_or_bytes_fail(self):
        for field in (
            "DownstreamStatus",
            "DownstreamContentSize",
            "RequestContentSize",
        ):
            with self.subTest(field=field):
                original = self.access[1][field]
                self.access[1][field] = original + 1
                self.rejected()
                self.access[1][field] = original

    def test_native_rule_wrong_uri_or_method_fails(self):
        for field, replacement in (("uri", "/wrong"), ("method", "POST")):
            with self.subTest(field=field):
                original = self.events[-1][field]
                self.events[-1][field] = replacement
                self.rejected()
                self.events[-1][field] = original

    def test_wrong_actual_wire_method_or_entity_fails(self):
        for field, replacement in (("method", "POST"), ("body_bytes", 26)):
            with self.subTest(field=field):
                original = self.wire["requests"][1][field]
                self.wire["requests"][1][field] = replacement
                self.rejected()
                self.wire["requests"][1][field] = original

    def test_native_writer_terminal_states_fail_closed(self):
        healthy = {
            name: {
                "started": True,
                "stopped": True,
                "returncode": 0,
                "forced_kill": False,
            }
            for name in ("host", "engine")
        }
        harness.require_healthy_writers(healthy)
        for change in (
            {"returncode": 1},
            {"forced_kill": True},
            {"stopped": False},
            {"started": False},
            {"returncode": -15},
        ):
            with self.subTest(change=change):
                terminal = copy.deepcopy(healthy)
                terminal["engine"].update(change)
                with self.assertRaises(ValueError):
                    harness.require_healthy_writers(terminal)

    def test_phase2_requires_native_method_uri_and_actual_entity(self):
        event = {
            "transaction_id": "traefik-native-h2-phase2-target",
            "event": "engine_decision",
            "connector": "traefik",
            "integration_mode": "native-traefik-middleware",
            "rule_id": "1100101",
            "phase": "request_body",
            "requested_action": "deny",
            "http_status": 403,
            "method": "POST",
            "uri": "/phase2/target",
            "body_bytes_seen": 26,
        }
        harness.validate_decision("phase2", [event])
        for field, value in (
            ("method", "GET"),
            ("uri", "/wrong"),
            ("body_bytes_seen", 0),
        ):
            with self.subTest(field=field):
                corrupted = event | {field: value}
                with self.assertRaises(ValueError):
                    harness.validate_decision("phase2", [corrupted])
