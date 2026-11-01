"""The I12 wire observer must reject incomplete evidence instead of guessing."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import hashlib
import copy
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock


PATH = connector_root() / "connectors/haproxy/harness/i12_spop_wire.py"
WIRE = load_source(PATH)
CASE_SPEC = importlib.util.spec_from_file_location("i12_spop_cases", PATH.with_name("i12_spop_cases.py"))
CASES = importlib.util.module_from_spec(CASE_SPEC)
ORACLES = load_source(PATH.with_name('i12_oracle_fixture.py'))
with mock.patch.dict("sys.modules", {"i12_spop_wire": WIRE, "i12_oracle_fixture": ORACLES}):
    CASE_SPEC.loader.exec_module(CASES)
HOST_SPEC = importlib.util.spec_from_file_location("i12_spop_host", PATH.with_name("i12_spop_host.py"))
HOST = importlib.util.module_from_spec(HOST_SPEC)
with mock.patch.dict("sys.modules", {"i12_spop_wire": WIRE, "i12_spop_cases": CASES}):
    HOST_SPEC.loader.exec_module(HOST)


def envelope(payload, kind=3):
    body = bytes([kind]) + b"\x00\x00\x00\x01\x01\x01" + payload
    return struct.pack("!I", len(body)) + body


class HaproxyI12SpopWireTests(unittest.TestCase):
    def test_supplemental_identity_cannot_transfer_a_legacy_or_mistyped_original_id(self):
        spec = importlib.util.spec_from_file_location("i12_spop_host", PATH.with_name("i12_spop_host.py"))
        host = importlib.util.module_from_spec(spec)
        with mock.patch.dict("sys.modules", {"i12_spop_wire": WIRE, "i12_spop_cases": CASES}):
            spec.loader.exec_module(host)
        for value in ("NEED-marker-at-payload-end", "NEED-request-marker-at-payload-end"):
            identity = host.case_identity({"case": "p2-deny", "case_id": value})
            self.assertEqual(identity["diagnostic_id"], "DIAG::haproxy-spop-request::p2-deny")
            self.assertIsNone(identity["original_id"])
            self.assertFalse(identity["original_obligation_eligible"])

    def test_real_signed_haproxy_body_length_and_version_are_preserved(self):
        # HAProxy's integer sample uses INT64, not string or unsigned coercion.
        payload = (b"\x0dcheck-request\x03\x04body\x09\x04test"
                   b"\x08body_len\x04\x04\x0chttp_version\x08\x031.1")
        decoded = WIRE.decode_frame(envelope(payload))
        arguments = decoded["messages"][0]["arguments"]
        self.assertEqual(arguments, [{"name": "body", "tag": 9, "value": "74657374"},
                                    {"name": "body_len", "tag": 4, "value": 4},
                                    {"name": "http_version", "tag": 8, "value": "1.1"}])

    def test_null_sample_is_not_reported_as_empty_binary_sample(self):
        decoded = WIRE.decode_frame(envelope(b"\x0dcheck-request\x01\x04body\x00"))
        self.assertEqual(decoded["messages"][0]["arguments"][0],
                         {"name": "body", "tag": 0, "value": None})

    def test_ack_boolean_status_and_error_remain_independent_fields(self):
        payload = (b"\x01\x03\x02\x07blocked\x11"
                   b"\x01\x03\x02\x06status\x03\xf7\x10"
                   b"\x01\x03\x02\x05error\x08\x07invalid")
        actions = WIRE.decode_frame(envelope(payload, 103))["actions"]
        self.assertEqual([value["value"] for value in actions], [True, 503, "invalid"])

    def test_duplicate_argument_bytes_are_preserved_without_last_value_wins(self):
        decoded = WIRE.decode_frame(envelope(b"\x0dcheck-request\x02\x08body_len\x03\x00\x08body_len\x03\x01"))
        self.assertEqual(len(decoded["messages"][0]["arguments"]), 2)

    def test_every_truncated_prefix_of_complete_frame_is_rejected(self):
        raw = envelope(b"\x0dcheck-request\x01\x08body_len\x04\x00")
        for size in range(len(raw)):
            prefix = raw[:size]
            with self.subTest(size=size), self.assertRaises(WIRE.InvalidFrame):
                WIRE.decode_frame(prefix)

    def test_supported_envelope_cannot_hide_truncated_or_unknown_typed_value(self):
        for payload in (b"\x0dcheck-request\x01\x04body\x09\x04te",
                        b"\x0dcheck-request\x01\x04body\x0f"):
            raw = envelope(payload)
            with self.subTest(payload=payload), self.assertRaises(WIRE.InvalidFrame):
                WIRE.decode_frame(raw)

    def test_frame_size_and_integer_budgets_fail_before_unbounded_decode(self):
        oversized = struct.pack("!I", WIRE.MAX_FRAME + 1)
        with self.assertRaises(WIRE.InvalidFrame):
            WIRE.decode_frame(oversized)
        reader = WIRE.Reader(b"\xff" * 12)
        with self.assertRaises(WIRE.InvalidFrame):
            reader.uint()

    def test_all_original_members_have_unique_pinned_contract_hashes(self):
        self.assertEqual(len(CASES.ORIGINAL_HASHES), 94)
        self.assertEqual(len(set(CASES.ORIGINAL_HASHES.values())), 94)
        self.assertEqual(set(CASES.CONFIG_NAMES), {"valid_rules_file", "missing_rules_file", "unsafe_event_path"})

    def arguments(self, profile=None):
        return WIRE.decode_frame(CASES.constructed_notify(profile or CASES.named_profile("NEED-complete-sample")))["messages"][0]["arguments"]

    def test_source_fixture_int64_size_is_distinct_from_sample_length(self):
        profile = CASES.named_profile("NEED-incomplete-sample")
        measurement = CASES.inspect_sample(self.arguments(profile))
        self.assertEqual(measurement["advertised_body_size_tag"], 4)
        self.assertEqual(measurement["advertised_body_size"], 8)
        self.assertEqual(measurement["body_sample_bytes"], 4)
        self.assertFalse(measurement["finite_sample_complete"])

    def test_supported_versions_preserve_actual_string_and_never_prove_native_lifecycle(self):
        for version in ("1.0", "1.1", "2.0"):
            profile = dict(CASES.named_profile("NEED-complete-sample"), request_version=version)
            result = CASES.inspect_sample(self.arguments(profile))
            self.assertTrue(result["finite_sample_complete"])
            self.assertEqual(result["http_version"], version)
            self.assertFalse(result["fully_inspected_http2"])
            self.assertFalse(result["native_lifecycle_proven"])

    def test_unknown_null_and_duplicate_required_metadata_fail_sample_admission(self):
        for name, tag, value in (("http_version", 8, "3.0"), ("http_version", 0, None),
                                 ("body", 0, None), ("body_len", 8, "0"), ("body_len", 2, 1 << 31)):
            arguments = self.arguments()
            argument = next(row for row in arguments if row["name"] == name)
            argument.update(tag=tag, value=value)
            with self.subTest(name=name, tag=tag, value=value):
                self.assertFalse(CASES.inspect_sample(arguments)["metadata_complete"])
        arguments = self.arguments()
        arguments.append(copy.deepcopy(arguments[-1]))
        self.assertFalse(CASES.inspect_sample(arguments)["metadata_complete"])

    def test_text_binary_header_disagreement_is_not_complete_sample(self):
        arguments = self.arguments()
        next(row for row in arguments if row["name"] == "headers")["value"] = "content-length: 99\r\n\r\n"
        self.assertFalse(CASES.inspect_sample(arguments)["finite_sample_complete"])

    def test_chunked_and_unframed_h2_are_not_full_sample_claims(self):
        for headers, body, advertised, version in (([("Transfer-Encoding", "chunked")], b"test", 4, "1.1"),
                                                   ([], b"", 0, "2.0"),
                                                   ([("Content-Length", "8")], b"test", 8, "1.1"),
                                                   ([("Content-Length", "4"), ("content-length", "4")], b"test", 4, "1.1")):
            self.assertFalse(CASES.framing_predicate(headers, body, advertised, version)[0])
        self.assertTrue(CASES.framing_predicate([("Content-Length", "0")], b"", 0, "2.0")[0])

    def test_corrected_malformed_notify_preserves_real_fin_flag_and_identifiers(self):
        original = CASES.constructed_notify(CASES.named_profile("NEED-complete-sample"))
        damaged = CASES.corrupt_notify_frame(original)
        self.assertEqual(damaged[4:11], original[4:11])
        self.assertEqual(damaged[4], 3)
        self.assertEqual(damaged[5:9], b"\x00\x00\x00\x01")
        self.assertEqual(struct.unpack("!I", damaged[:4])[0], len(damaged) - 4)
        with self.assertRaises(WIRE.InvalidFrame):
            WIRE.decode_frame(damaged)
        self.assertTrue(CASES.inspect_notify_frame(original)["finite_sample_complete"])

    def test_fixture_envelope_matches_primary_product_constants(self):
        source = PATH.parents[1].joinpath("src/haproxy_spop_diagnostic_runtime.c").read_text()
        self.assertIn("#define SPOP_FRM_NOTIFY 3U", source)
        self.assertIn("#define SPOP_FRM_ACK 103U", source)
        self.assertIn("#define SPOP_FIN_FLAG 0x00000001U", source)
        raw = CASES.constructed_notify(CASES.named_profile("NEED-complete-sample"))
        self.assertEqual(raw[4:9], b"\x03\x00\x00\x00\x01")

    def test_ack_correlates_connection_stream_and_frame_not_list_position(self):
        rows = []
        for stream, profile in ((2, CASES.neighbor_profile()), (1, CASES.named_profile("NEED-complete-sample"))):
            decoded = WIRE.decode_frame(CASES.constructed_notify(profile))
            decoded["stream"] = stream
            rows.append({"connection": 4, "decoded": decoded})
        for stream, status in ((2, 200), (1, 403)):
            rows.append({"connection": 4, "decoded": {"kind": 103, "stream": stream, "frame": 1,
                          "actions": [{"name": "status", "value": status}]}})
        main, neighbor = HOST.correlated_actions(rows)
        self.assertEqual([row["status"] for row in main], [403])
        self.assertEqual([row["status"] for row in neighbor], [200])
        self.assertEqual(main[0]["wire_binding"]["stream"], 1)
        self.assertTrue(main[0]["wire_binding"]["notify_observed"])

    def test_p1_intervention_never_predicts_fictional_request_eos(self):
        profile = CASES.named_profile("NEED-complete-sample")
        result = CASES.expected_observations(profile, {"visible_status": 403, "phase": 1})
        self.assertFalse(result["native_request_eos"])

    def test_p1_allow_is_not_a_phase_ceiling_and_does_finalize_request_body(self):
        profile = CASES.named_profile("NEED-complete-sample")
        for status in (200, None):
            result = CASES.expected_observations(profile, {"visible_status": status, "phase": 1})
            self.assertTrue(result["native_request_eos"])
        for status in (302, 403, 429):
            result = CASES.expected_observations(profile, {"visible_status": status, "phase": 1})
            self.assertFalse(result["native_request_eos"])

    def test_atomic_scope_primary_source_only_skips_p2_for_actual_disruption(self):
        source = PATH.parents[1].joinpath("src/haproxy_modsecurity_binding.c").read_text()
        start = source.index("static int begin_atomic_request(")
        end = source.index("int haproxy_modsecurity_transaction_begin(", start)
        atomic = source[start:end]
        self.assertIn("rc != 0 || created == 0 || decision->disruptive != 0", atomic)
        self.assertIn("return haproxy_modsecurity_transaction_finish_request_body(created, decision);", atomic)
        self.assertNotIn("decision->phase == 1", atomic)
        self.assertNotIn("decision->phase != 1", atomic)

    def test_ip_metadata_uses_real_address_type_not_integer_or_display_string(self):
        for tag, value in ((3, 2130706433), (8, "127.0.0.1"), (6, "::1"), (7, "127.0.0.1")):
            arguments = self.arguments()
            next(row for row in arguments if row["name"] == "client_ip").update(tag=tag, value=value)
            self.assertFalse(CASES.inspect_sample(arguments)["metadata_complete"])
        for name in ("client_ip", "server_ip"):
            self.assertEqual(next(row for row in self.arguments() if row["name"] == name)["tag"], 6)
        arguments = self.arguments()
        next(row for row in arguments if row["name"] == "client_ip").update(tag=7, value="::1")
        self.assertTrue(CASES.inspect_sample(arguments)["metadata_complete"])
        self.assertEqual(WIRE.Reader(CASES.encode_typed(7, "::1")).typed(), {"tag": 7, "value": "::1"})

    def valid_ack_rows(self):
        notify = WIRE.decode_frame(CASES.constructed_notify(CASES.named_profile("NEED-complete-sample")))
        ack = {"kind": 103, "flags": 1, "stream": 1, "frame": 1,
               "actions": [{"name": "status", "scope": 2, "tag": 3, "value": 200},
                           {"name": "blocked", "scope": 2, "tag": 1, "value": False}]}
        return [{"connection": 1, "direction": "host-agent", "decoded": notify},
                {"connection": 1, "direction": "agent-host", "decoded": ack}]

    def test_orphan_and_non_fin_ack_cannot_pass_on_plausible_status(self):
        expected = [{"ack_status": 200}]
        valid = self.valid_ack_rows()
        self.assertEqual(HOST.ack_integrity_violations(valid, expected), [])
        orphan = copy.deepcopy(valid[1:])
        orphan[0]["decoded"].update(stream=9, frame=9, flags=0)
        errors = HOST.ack_integrity_violations(orphan, expected)
        self.assertIn("orphan-ack", errors)
        self.assertIn("ack-envelope", errors)

    def test_duplicate_extra_ack_and_notify_reentry_are_observation_failures(self):
        expected = [{"ack_status": 200}]
        rows = self.valid_ack_rows()
        errors = HOST.ack_integrity_violations(rows + [copy.deepcopy(rows[1])], expected)
        self.assertIn("duplicate-ack-identity", errors)
        self.assertIn("main-ack-count", errors)
        errors = HOST.ack_integrity_violations([rows[0], copy.deepcopy(rows[0]), rows[1]], expected)
        self.assertIn("duplicate-notify-identity", errors)
        extra = copy.deepcopy(rows[1])
        extra["decoded"]["stream"] = 2
        errors = HOST.ack_integrity_violations(rows + [extra], expected)
        self.assertIn("orphan-ack", errors)
        self.assertIn("main-ack-count", errors)

    def test_ack_action_types_duplicates_scope_and_direction_are_checked(self):
        for field, value, expected_error in (("tag", 8, "ack-status-type"), ("value", True, "ack-status-type"),
                                               ("scope", 1, "ack-action-scope")):
            rows = self.valid_ack_rows()
            rows[1]["decoded"]["actions"][0][field] = value
            self.assertIn(expected_error, HOST.ack_integrity_violations(rows, [{"ack_status": 200}]))
        rows = self.valid_ack_rows()
        rows[1]["decoded"]["actions"].append(copy.deepcopy(rows[1]["decoded"]["actions"][0]))
        self.assertIn("duplicate-ack-action", HOST.ack_integrity_violations(rows, [{"ack_status": 200}]))
        rows = self.valid_ack_rows()
        rows[1]["direction"] = "host-agent"
        self.assertIn("ack-direction", HOST.ack_integrity_violations(rows, [{"ack_status": 200}]))

    def test_actual_evaluator_rejects_orphan_ack_despite_correct_http_and_backend(self):
        expected = {"client_status": 200, "ack_status": 200, "ack_blocked": False,
                    "backend_requests": 1, "sample_inspection_claim": True}
        measurement = HOST.response_measurement(CASES.BACKEND_RESPONSE)
        clients = [{"neighbor": False, "measurement": measurement, "connection": 1},
                   {"neighbor": True, "measurement": measurement, "connection": 2}]
        frames = self.valid_ack_rows()
        neighbor = self.valid_ack_rows()
        neighbor[0]["decoded"] = WIRE.decode_frame(CASES.constructed_notify(CASES.neighbor_profile()))
        for row in neighbor:
            row["connection"] = 2
        frames += neighbor
        selected = {"effective_oracle": expected, "runtime": {},
                    "neighbor_expected": {"body_sha256": hashlib.sha256(b"BACKEND").hexdigest()}}
        def evaluate(rows):
            readings = {"client.jsonl": clients, HOST.FRAMES_FILE: rows,
                        HOST.BACKEND_FILE: [{"neighbor": False}, {"neighbor": True}]}
            with mock.patch.object(HOST, "read_rows", side_effect=readings.__getitem__), mock.patch.object(HOST, "case_identity", return_value={}), mock.patch.object(HOST, "record") as record:
                HOST.evaluate_original(selected)
            return record.call_args.args[1]
        self.assertEqual(evaluate(frames)["observation_result"], "passed")
        invalid = copy.deepcopy(frames)
        invalid[1]["decoded"].update(stream=9, frame=9, flags=0)
        result = evaluate(invalid)
        self.assertEqual(result["observation_result"], "failed")
        self.assertIn("orphan-ack", result["mismatches"])
        self.assertIsNone(result["full_lifecycle_pass"])

    def test_sample_claim_uses_observed_sample_and_unknown_notify_is_rejected(self):
        rows = self.valid_ack_rows()
        self.assertEqual(HOST.sample_claim_violations(rows, [{"sample_inspection_claim": True}]), [])
        next(item for item in rows[0]["decoded"]["messages"][0]["arguments"] if item["name"] == "body_len")["value"] = 99
        self.assertIn("finite-sample-claim-0", HOST.sample_claim_violations(rows, [{"sample_inspection_claim": True}]))
        rows[0]["decoded"]["messages"][0]["name"] = "unknown-request"
        self.assertIn("notify-envelope-or-direction", HOST.ack_integrity_violations(rows, [{"ack_status": 200}]))

    def test_sealed_fixture_admission_rejects_writable_directories_not_only_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "case"
            directory.mkdir()
            file = directory / "selected.json"
            file.write_text("{}")
            file.chmod(0o444)
            with self.assertRaisesRegex(ValueError, "0o555"):
                CASES.validate_sealed_fixture_tree(root)
            CASES.seal_fixture_tree(root)
            CASES.validate_sealed_fixture_tree(root)
            self.assertEqual(root.stat().st_mode & 0o777, 0o555)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o555)
            self.assertEqual(file.stat().st_mode & 0o777, 0o444)

    def test_fixture_sealing_rejects_symlink_without_changing_target_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_text("unchanged")
            original_mode = target.stat().st_mode
            (root / "link").symlink_to(target)
            with self.assertRaisesRegex(ValueError, "physical"):
                CASES.seal_fixture_tree(root)
            self.assertEqual(target.stat().st_mode, original_mode)

    def test_varint_boundaries_roundtrip_and_excess_fail_closed(self):
        for value in (0, 127, 239, 240, 255, 256, 65532, 1 << 31, (1 << 64) - 1):
            self.assertEqual(WIRE.Reader(CASES.encode_uint(value)).uint(), value)
        for value in (-1, True, 1 << 64):
            with self.assertRaises(ValueError):
                CASES.encode_uint(value)

    def test_unknown_message_and_non_fin_notify_are_uninspected(self):
        raw = bytearray(CASES.constructed_notify(CASES.named_profile("NEED-complete-sample")))
        raw[8] = 0
        self.assertFalse(CASES.inspect_notify_frame(bytes(raw))["finite_sample_complete"])
        raw = CASES.constructed_notify(CASES.named_profile("NEED-complete-sample")).replace(b"check-request", b"other-request")
        self.assertFalse(CASES.inspect_notify_frame(raw)["finite_sample_complete"])

    def test_allow_response_requires_actual_content_length_and_full_payload(self):
        expected = hashlib.sha256(b"BACKEND").hexdigest()
        valid = HOST.response_measurement(CASES.BACKEND_RESPONSE)
        self.assertEqual(valid["body_sha256"], expected)
        self.assertTrue(valid["complete_length_framing"])
        for raw in (CASES.BACKEND_RESPONSE.replace(b"Length: 7", b"Length: 8"),
                    CASES.BACKEND_RESPONSE[:-1], b"HTTP/1.1 200 OK\r\n"):
            self.assertFalse(HOST.response_measurement(raw)["complete_length_framing"])

    def test_neighbor_is_clean_and_smaller_than_native_limit(self):
        neighbor = CASES.neighbor_profile()
        self.assertEqual(neighbor["request_path"], "/i12-neighbor")
        self.assertEqual(neighbor["request_body_hex"], "")
        self.assertEqual(neighbor["body_fetch"], "req.body")
        self.assertEqual(neighbor["body_size_fetch"], "req.body_size")
        for name in ("NEED-incomplete-sample", "NEED-invalid-metadata", "NEED-budget-precommit"):
            profile = CASES.named_profile(name)
            self.assertLess(len(bytes.fromhex(neighbor["request_body_hex"])), profile["native_request_limit"])

    def test_original_transport_scope_faults_are_main_only(self):
        selected = {"runtime": CASES.named_profile("NEED-invalid-metadata")}
        config = 'frontend request_only\n    http-request send-spoe-group modsecurity request-check\n    http-request deny deny_status 503 if { var(txn.modsec.blocked) -m bool }\nbackend be_app\n'
        with mock.patch.object(CASES, "validate_runtime", return_value=selected["runtime"]):
            rendered, spoe, _ = HOST.original_configuration(selected, config, "body=req.body body_len=req.body_size", "")
        self.assertIn('int(99) unless { path -m str /i12-neighbor }', rendered)
        self.assertIn('body_len=var(txn.i12_length)', spoe)
        self.assertIn('http-request deny deny_status 403', rendered)

    def test_native_reject_and_partial_fixture_policies_are_explicit(self):
        for action in ("Reject", "ProcessPartial"):
            profile = dict(CASES.named_profile("NEED-budget-precommit"), native_request_limit_action=action)
            selected = {"runtime": profile, "rules_source": 'SecRuleEngine On\nSecRequestBodyLimit 524288\n'}
            with mock.patch.object(CASES, "validate_runtime", return_value=profile):
                rules = HOST.original_rules(selected)
            self.assertIn('SecRequestBodyLimit 16\n', rules)
            self.assertIn('SecRequestBodyLimitAction ' + action, rules)
            self.assertNotIn('524288', rules)

    def test_original_rules_enable_native_physical_observers_without_body_audit_parts(self):
        profile = CASES.named_profile("NEED-complete-sample")
        canonical = PATH.parents[3].joinpath("modules/ModSecurity-test-Framework/tests/rules/no-crs-baseline.conf").read_text()
        selected = {"runtime": profile, "rules_source": canonical}
        with mock.patch.object(CASES, "validate_runtime", return_value=profile):
            rules = HOST.original_rules(selected)
        self.assertIn(canonical.rstrip(), rules)
        for directive in ("SecAuditEngine On", "SecAuditLogType Serial", "SecAuditLogParts ABFHZ",
                          "SecAuditLog /task/native-audit.log", "SecDebugLog /task/native-debug.log", "SecDebugLogLevel 9"):
            self.assertEqual(rules.splitlines().count(directive), 1)
        parts = next(line.split()[1] for line in rules.splitlines() if line.startswith("SecAuditLogParts "))
        self.assertNotIn("C", parts)
        self.assertNotIn("E", parts)

    def test_observer_accept_finishes_before_closing_peer_snapshot(self):
        observer = object.__new__(HOST.Observer)
        observer.stop = mock.Mock()
        observer.listener = mock.Mock()
        observer.thread = mock.Mock()
        observer.thread.is_alive.return_value = False
        observer.peers = []
        worker = mock.Mock()
        worker.is_alive.return_value = False
        peer = mock.Mock()
        def stop_accept(_timeout):
            observer.peers.append(peer)
            observer.workers.append(worker)
        observer.thread.join.side_effect = stop_accept
        observer.workers = []
        with mock.patch.object(HOST, "record"):
            observer.close()
        peer.close.assert_called_once()
        worker.join.assert_called_once()

    def test_observer_live_accept_is_failure_instead_of_ignored_cleanup(self):
        observer = object.__new__(HOST.Observer)
        observer.stop = mock.Mock()
        observer.listener = mock.Mock()
        observer.thread = mock.Mock()
        observer.thread.is_alive.return_value = True
        with self.assertRaisesRegex(RuntimeError, "accept worker"):
            observer.close()



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
