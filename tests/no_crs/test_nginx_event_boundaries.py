"""Synthetic unit observations are not native event-boundary evidence."""
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runners"))
import nginx_event_boundary_operations as events


def child(case, variant, run_id="unit"):
    spec = events.operation(case, variant)
    uri, truncated, redacted = events.projected_uri(spec["request_path"])
    event = dict(event="rule_match", message_id="MSCONN_EVENT_RULE_MATCHED", connector="nginx",
                 integration_mode="native-nginx-http-module", phase="request_headers", status="ok", action="allow",
                 requested_action="allow", actual_action="allow", rule_id="1100402", reason="non_disruptive_rule_match",
                 method="GET", uri=uri, truncated=truncated, redacted=redacted, transaction_id=run_id + "-2-1")
    receipt = dict(case_id=case, source_record_id=case, operation=spec["operation"], variant=variant,
                   request_method="GET", request_path=spec["request_path"], request_headers=spec["request_headers"],
                   effective_phase4_mode="safe", configtest_exit_code=0, client_exit_code=0, observed_http_status=200,
                   response_bytes_received=27, run_id=run_id, native_events=[event], driver_error=None,
                   parent_sha="a"*40, framework_sha="b"*40, mrts_sha="c"*40)
    receipt["roles"] = dict(run_id=run_id, master_uid=0, worker_uid=65534, master_pid=123, worker_pid=124)
    receipt["cleanup"] = dict(run_id=run_id, master_pid=123, worker_pid=124, verified=True,
                             master_running=False, worker_running=False, listener_open=False)
    raw = {"phase4-events.jsonl": json.dumps(event).encode()+b"\n", "response.bin": events.BODY,
           "response.headers": b"HTTP/1.1 200 OK\r\nContent-Length: 27\r\nContent-Type: text/plain\r\n\r\n",
           "client.stdout": b"200", "client.stderr": b"", "rules.conf": spec["rules"].encode(),
           "nginx.conf": (b'modsecurity on; modsecurity_phase4_mode safe; '
                          b'modsecurity_transaction_id "'+run_id.encode()+b'-$connection-$connection_requests"; '
                          b'modsecurity_phase4_log "/var/tmp/codex/owned/phase4-events.jsonl";')}
    receipt["raw_sha256"] = {name: hashlib.sha256(data).hexdigest() for name, data in raw.items()}
    return receipt, raw


def refresh(receipt, raw):
    raw["phase4-events.jsonl"] = b"".join(json.dumps(event).encode()+b"\n" for event in receipt["native_events"])
    receipt["raw_sha256"] = {name: hashlib.sha256(data).hexdigest() for name, data in raw.items()}


class EventBoundaryTests(unittest.TestCase):
    def test_fixed_255_256_and_long_query_native_shapes(self):
        for case, variant in (("event_metadata_truncation", "long-query"), ("event_json_limit", "at255"),
                              ("event_json_limit", "over256")):
            receipt, raw = child(case, variant)
            self.assertEqual(events.validate_event_boundary_child(case, variant, receipt, raw), [])
        spec = events.operation("event_json_limit", "at255")
        self.assertEqual(len(spec["request_path"]), 255)
        self.assertEqual(events.projected_uri(spec["request_path"])[1:], (False, False))
        self.assertEqual(events.projected_uri(events.operation("event_json_limit", "over256")["request_path"])[1:], (True, False))
        projection = events.projected_uri(events.operation("event_metadata_truncation", "long-query")["request_path"])
        self.assertTrue(projection[0].endswith("?<redacted>"))
        self.assertEqual(len(projection[0]), 255)
        self.assertEqual(projection[1:], (True, True))

    def test_repeatable_set_cookie_does_not_hide_event_wire_contract(self):
        case, variant = "event_metadata_truncation", "long-query"
        receipt, raw = child(case, variant)
        raw["response.headers"] = raw["response.headers"].replace(
            b"\r\n\r\n",
            b"\r\nSet-Cookie: session=token\r\nSet-Cookie: a=b\r\n\r\n",
        )
        refresh(receipt, raw)
        self.assertEqual(events.validate_event_boundary_child(case, variant, receipt, raw), [])

    def test_escaped_prefix_preserves_query_suffix_and_size(self):
        uri, truncated, redacted = events.projected_uri('/'+ '"'*256 + '?probe=non-sensitive')
        self.assertTrue(uri.endswith("?<redacted>"))
        self.assertLess(len(json.dumps(uri).encode())-2, 256)
        self.assertTrue(truncated)
        self.assertTrue(redacted)

    def test_wrong_native_rule_action_tx_flags_payload_and_size_rejected(self):
        case, variant = "event_metadata_truncation", "long-query"
        for field, value in (("rule_id", "1100401"), ("event", "phase1_log_only"),
                             ("actual_action", "log_only"), ("event", "request_rule_match"),
                             ("actual_action", "pass"), ("phase", "response_body"),
                             ("transaction_id", "foreign-2-1"), ("truncated", False),
                             ("redacted", False), ("uri", "?probe=non-sensitive"),
                             ("response_body", "payload"), ("message", "x"*4096)):
            receipt, raw = child(case, variant)
            receipt["native_events"][0][field] = value
            refresh(receipt, raw)
            with self.subTest(field=field):
                self.assertTrue(events.validate_event_boundary_child(case, variant, receipt, raw))
        receipt, raw = child(case, variant)
        raw["client.stdout"] = b"200\ntamper"
        self.assertTrue(events.validate_event_boundary_child(case, variant, receipt, raw))

    def test_two_sealed_distinct_children_required_for_limit_record(self):
        case = "event_json_limit"
        parent = dict(schema_version=1, case_id=case, operation="native_event_boundary_request", run_id="unit",
                      uri_buffer_bytes=256, writer_buffer_bytes=4096, parent_sha="a"*40, framework_sha="b"*40,
                      mrts_sha="c"*40, children=[])
        children = {}
        for variant in ("at255", "over256"):
            receipt, raw = child(case, variant, "unit-"+variant)
            serialized = json.dumps(receipt).encode()+b"\n"
            children[variant] = {"receipt_bytes": serialized, "raw_artifacts": raw}
            parent["children"].append(dict(variant=variant, directory=variant, run_id="unit-"+variant,
                                           receipt_sha256=hashlib.sha256(serialized).hexdigest()))
        self.assertEqual(events.validate_event_boundary_operation(case, parent, children), [])
        original = parent["children"][1]["receipt_sha256"]
        parent["children"][1]["receipt_sha256"] = "0"*64
        self.assertTrue(events.validate_event_boundary_operation(case, parent, children))
        parent["children"][1]["receipt_sha256"] = original
        parent["children"][1]["directory"] = "../at255"
        self.assertTrue(events.validate_event_boundary_operation(case, parent, children))
        parent["children"][1]["directory"] = "over256"
        parent["framework_sha"] = "d"*40
        self.assertTrue(events.validate_event_boundary_operation(case, parent, children))
        parent["framework_sha"] = "b"*40
        self.assertTrue(events.validate_event_boundary_operation(case, parent, {"at255": children["at255"]}))

    def test_child_roles_cleanup_run_and_projection_identity_remain_strict(self):
        case, variant = "event_json_limit", "at255"
        for section, field, value in (("roles", "worker_uid", 0), ("cleanup", "verified", False),
                                      ("cleanup", "run_id", "foreign"), ("cleanup", "worker_pid", 999)):
            receipt, raw = child(case, variant)
            receipt[section][field] = value
            with self.subTest(section=section, field=field):
                self.assertTrue(events.validate_event_boundary_child(case, variant, receipt, raw))
        receipt, raw = child(case, variant)
        receipt["request_path"] = events.operation(case, "over256")["request_path"]
        self.assertTrue(events.validate_event_boundary_child(case, variant, receipt, raw))


if __name__ == "__main__":
    unittest.main()
