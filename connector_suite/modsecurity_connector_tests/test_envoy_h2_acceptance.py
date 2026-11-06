"""Corruption controls for the opt-in real Envoy HTTP/2 evidence join."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import os
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "adapters/envoy/harness/envoy_h2_acceptance.py"
SPEC = importlib.util.spec_from_file_location("envoy_h2_acceptance", SOURCE)
ADAPTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADAPTER)


class EnvoyH2AcceptanceTests(unittest.TestCase):
    def fixture(self, case="phase2"):
        access, completion, requests = [], [], []
        denied = case in ("phase1", "phase2", "phase3")
        for role, stream in (("peer", 1), ("target", 3), ("followup", 5)):
            transaction = f"envoy-h2-{case}-{role}"
            status = 403 if role == "target" and denied else 200
            access.append({"transaction_id": transaction, "protocol": "HTTP/2", "connection_id": "7",
                           "stream_id": str(stream), "status": str(status)})
            size = 26 if role == "target" and case == "phase2" else 0
            requests.append({"stream_id": stream, "transaction_id": transaction, "path": f"/{case}/{role}",
                             "method": "POST" if size else "GET", "body_bytes": size})
            completion.append({"transaction_id": transaction, "rule_evaluation": "libmodsecurity", "request_body_bytes": size,
                               "close_reason": "request_immediate_response" if role == "target" and denied else "response_end_of_stream"})
        body = 33 if case.startswith("phase4") else (6 if case in ("client_cancel", "upstream_reset") else (0 if denied else 10))
        wire = {"alpn": "h2", "tls_verified": True, "tls_version": "TLSv1.3", "requests": requests,
                "body_bytes": {"1": 10, "3": body, "5": 10},
                "terminal": {str(stream): {"type": 0, "flags": 1} for stream in (1, 3, 5)},
                "status": {"1": 200, "3": 403 if denied else 200, "5": 200},
                "frames": [{"type": "native_completion_observed", "transaction_id": f"envoy-h2-{case}-target", "peer_held": True,
                            "target_eos_held": case == "client_cancel", "monotonic_ns": 30}]}
        if case in ("phase4_safe", "phase4_strict", "client_cancel", "upstream_reset"):
            wire["frames"].extend(({"type": 0, "stream_id": 3, "size": 6, "monotonic_ns": 10},
                                   {"type": "first_byte_before_eos", "peer_held": True, "target_eos_held": True, "monotonic_ns": 20}))
        if case == "phase4_safe":
            completion[1]["late_action"] = "log_only"
        if case == "phase4_strict":
            completion[1]["close_reason"] = "late_immediate_response"
        if case in ("client_cancel", "upstream_reset"):
            completion[1]["close_reason"] = "grpc_context_canceled_unattributed"
        if case == "client_cancel":
            wire["frames"].append({"type": "client_rst_stream", "stream_id": 3, "reset_code": 8})
        rules = {"phase1": 1100001, "phase2": 1100101, "phase3": 1100201, "phase4_safe": 1100301, "phase4_strict": 1100301}
        phase = {"phase1": "request_headers", "phase2": "request_body", "phase3": "response_headers"}.get(case, "response_body")
        common = [{"event": "engine_decision", "transaction_id": f"envoy-h2-{case}-target", "rule_id": rules[case],
                   "phase": phase, "http_status": 403, "requested_action": "deny"}] if case in rules else []
        return [case, wire, access, completion, common]

    def test_exact_join(self):
        self.assertEqual(ADAPTER.validate_case(*self.fixture())["status"], "PASS")

    def test_missing_duplicate_and_foreign_correlation_rejected(self):
        mutations = [lambda args: args[2].pop(),
                     lambda args: args[2].append(deepcopy(args[2][0])),
                     lambda args: args[3].pop(),
                     lambda args: args[4][0].update(transaction_id="foreign"),
                     lambda args: args[4][0].update(rule_id=1100001)]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                args = self.fixture()
                mutation(args)
                with self.assertRaises(ValueError):
                    ADAPTER.validate_case(*args)

    def test_protocol_fallback_connection_replacement_peer_damage_rejected(self):
        mutations = [lambda args: args[2][0].update(protocol="HTTP/1.1"),
                     lambda args: args[2][2].update(connection_id="8"),
                     lambda args: args[2][2].update(stream_id="1"),
                     lambda args: args[2][0].update(status="500"),
                     lambda args: args[1]["status"].update({"3": 200}),
                     lambda args: args[1]["status"].pop("3"),
                     lambda args: args[1]["frames"].clear(),
                     lambda args: args[1]["terminal"]["1"].update(type=3),
                     lambda args: args[1]["terminal"].pop("5")]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                args = self.fixture()
                mutation(args)
                with self.assertRaises(ValueError):
                    ADAPTER.validate_case(*args)

    def test_independent_wire_protocol_entities_rule_phase_and_count_are_mandatory(self):
        mutations = [lambda a: a[1].update(alpn="http/1.1"), lambda a: a[1].update(tls_verified=False),
                     lambda a: a[1].update(requests=[]), lambda a: a[1].update(body_bytes={}),
                     lambda a: a[1]["requests"][1].update(method="GET"),
                     lambda a: a[4].append(deepcopy(a[4][0])), lambda a: a[4][0].update(phase="request_headers")]
        for mutation in mutations:
            args = self.fixture(); mutation(args)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                ADAPTER.validate_case(*args)

    def test_cancellation_requires_native_cancel_before_upstream_eos(self):
        args = self.fixture("client_cancel")
        self.assertEqual(ADAPTER.validate_case(*args)["status"], "PASS")
        for mutation in (lambda a: a[3][1].update(close_reason="response_end_of_stream"),
                         lambda a: a[1]["frames"][0].update(target_eos_held=False),
                         lambda a: a[1]["frames"].pop(),
                         lambda a: a[1]["body_bytes"].update({"3": 10})):
            corrupted = deepcopy(args); mutation(corrupted)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                ADAPTER.validate_case(*corrupted)

    def test_real_phase2_request_contains_post_and_entity(self):
        headers = ADAPTER.request_headers(443, "/phase2/target", "tx", "POST", b"probe", False)
        self.assertIn(b"POST", headers)
        self.assertIn(b"content-length", headers)
        self.assertIn(b"text/plain", headers)

    def test_hpack_length_and_frame_boundary(self):
        self.assertEqual(ADAPTER.hpack_string("a" * 127)[:2], bytes((127, 0)))
        self.assertEqual(ADAPTER.hpack_string("a" * 255)[:3], bytes((127, 128, 1)))
        self.assertEqual(ADAPTER.frame(3, 0, 3, b"1234"), b"\x00\x00\x04\x03\x00\x00\x00\x00\x031234")
        with self.assertRaises(ValueError):
            ADAPTER.frame(3, 0, 1 << 31)

    def test_json_evidence_rejects_duplicates_and_nonfinite_numbers(self):
        for value in ('{"same":1,"same":2}', '{"value":NaN}', '{"value":Infinity}'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ADAPTER.load_json(value)

    def test_reader_rejects_symlink_parent_leaf_and_hardlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            regular = root / "regular.jsonl"
            regular.write_text('{"event":"test"}\n')
            self.assertEqual(ADAPTER.read_records(regular), [{"event": "test"}])
            leaf = root / "link.jsonl"
            leaf.symlink_to(regular)
            with self.assertRaises(OSError):
                ADAPTER.read_records(leaf)
            parent = root / "alias"
            parent.symlink_to(root, target_is_directory=True)
            with self.assertRaises(OSError):
                ADAPTER.read_records(parent / "regular.jsonl")
            hardlink = root / "hardlink.jsonl"
            os.link(regular, hardlink)
            with self.assertRaises(ValueError):
                ADAPTER.read_records(hardlink)

    def test_strict_requires_both_actual_reset_and_native_action_correlation(self):
        args = self.fixture("phase4_strict")
        args[2][1].update(status=200, details="msconnector-ext-proc-late-decision")
        args[1]["status"]["3"] = 200
        args[3][1].update(late_action="strict_immediate_response_sent")
        args[4][0].update(rule_id=1100301)
        with self.assertRaises(ValueError):
            ADAPTER.validate_case(*args)
        args[1]["terminal"]["3"].update(type=3, reset_code=2)
        self.assertEqual(ADAPTER.validate_case(*args)["status"], "PASS")
        for incorrect_code in (0, 1, 7, 8):
            args[1]["terminal"]["3"]["reset_code"] = incorrect_code
            with self.subTest(incorrect_code=incorrect_code), self.assertRaises(ValueError):
                ADAPTER.validate_case(*args)
        args[1]["terminal"]["3"]["reset_code"] = 2
        args[2][1]["details"] = "foreign-action"
        with self.assertRaises(ValueError):
            ADAPTER.validate_case(*args)

    def test_native_hpack_status_decoder(self):
        from tests.runners.native_h2_probe import StatusDecoder
        decoder = StatusDecoder()
        try:
            self.assertEqual(decoder.decode(b"\x88"), [200])
            self.assertEqual(decoder.decode(b"\x08\x03403"), [403])
            with self.assertRaises(ValueError):
                decoder.decode(b"\x88\x88")
        finally:
            decoder.close()


if __name__ == "__main__":
    unittest.main()
