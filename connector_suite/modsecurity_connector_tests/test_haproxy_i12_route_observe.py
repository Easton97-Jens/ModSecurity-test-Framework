"""Stored native-v1/companion-v1 schema controls, never host verdict fixtures."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = connector_root()
OBSERVE = load_source(source_path('connectors/haproxy/harness/i12_route_observe.py', root=ROOT))
ORACLES = OBSERVE.module_at("route_test_oracles", source_path('connectors/haproxy/harness/i12_oracle_fixture.py', root=ROOT))
with patch.dict("sys.modules", {"i12_spop_wire": OBSERVE.WIRE, "i12_oracle_fixture": ORACLES}):
    ENCODE = OBSERVE.module_at("route_test_spop", source_path('connectors/haproxy/harness/i12_spop_cases.py', root=ROOT))
IDENTITY = "0c5df3ca-9856-401d-9303-8823fc815964"
CASE = "I12::haproxy-spop-htx-response-companion::NEED-client-response-bytes"


def row(function, call, **fields):
    return {"schema": "native-lifecycle-v1", "pid": 233, "uid": 65534, "gid": 65534,
            "run": "host", "profile": OBSERVE.COMPANION, "case": CASE,
            "function": function, "edge": "return", "call": call, "result": 0,
            "transaction_id": IDENTITY, "canonical_transaction_id": None,
            "allocation_scope_call": 2, "allocation_join_verified": False,
            "allocation_scope_kind": "host", "wall_ns": 1792319733359519863, **fields}


def stored_schema_rows():
    # The SDK return precedes the host allocation's verified association. These
    # identity, scope and timestamp shapes come from the retained Safe capture.
    return [row("common_init", 3, canonical_transaction_id="txc-0000000011c639f2-0000000000000000"),
            row("native_new_with_id", 5, result=1, input_transaction_id=IDENTITY),
            row("host_allocation", 2, result=1, transaction_id=None, allocation_join_verified=True),
            row("common_cleanup", 44, allocation_join_verified=True),
            row("native_cleanup", 46, allocation_join_verified=True)]


def stored_spop_backend_rows():
    # Physical pilot attempt 1792320861376221286/c00 backend.jsonl: the
    # producer removes CRLFCRLF before recording header_hex, retaining the
    # independently read body, neighbor marker and actual wall timestamp.
    return [
        {"body_hex": "", "header_hex": "474554202f6e6f2d6372732f616c6c6f7720485454502f312e310d0a686f73743a206c6f63616c686f73740d0a636f6e74656e742d6c656e6774683a20300d0a782d6d6f647365632d736d6f6b653a20616c6c6f77", "neighbor": False, "wall_ns": 1792320902099490750},
        {"body_hex": "", "header_hex": "474554202f6931322d6e65696768626f7220485454502f312e310d0a686f73743a206c6f63616c686f73740d0a636f6e74656e742d6c656e6774683a2030", "neighbor": True, "wall_ns": 1792320902306182549},
    ]


class BackendDecodingTests(unittest.TestCase):
    def setUp(self):
        from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root

        storage = validate_output_root(ROOT, Path(os.environ["RUNNER_TEMP"]))
        selected_storage = patch.object(OBSERVE.CAPTURE, "STORAGE", storage)
        selected_storage.start()
        self.addCleanup(selected_storage.stop)

    def test_physical_count_requires_complete_log_and_positive_zero_control(self):
        with tempfile.TemporaryDirectory(dir=OBSERVE.CAPTURE.STORAGE) as directory:
            root = Path(directory)
            rows = stored_spop_backend_rows()
            wire = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
            (root / "backend.ready").write_bytes(b"ready")
            (root / "cleanup.jsonl").write_text('{"backend_joined":true}\n')
            (root / "response-neighbor.raw").write_bytes(wire)
            route = {"backend": rows, "backend_name": "backend.jsonl", "client": {}, "client_name": "client.jsonl",
                     "all_clients": [{"neighbor": True, "response_sha256": OBSERVE.digest(wire)}]}
            for expected, captured in ((1, rows), (0, rows[1:])):
                with self.subTest(main_count=expected):
                    route["backend"] = captured
                    (root / "backend.jsonl").write_text("".join(json.dumps(row) + "\n" for row in captured))
                    (root / "client.jsonl").write_text("{}\n")
                    readings = OBSERVE.Readings(root)
                    readings.get("backend.jsonl", OBSERVE.ROLE_BACKEND, "jsonl")
                    readings.get("client.jsonl", OBSERVE.ROLE_CLIENT, "jsonl")
                    observations = {}
                    OBSERVE.backend_measurements(observations, route, readings, "/no-crs/allow")
                    self.assertEqual(observations["backend_request_count"]["value"]["matching_path"], expected)
                    self.assertIsNone(observations["client_backend_correlation"]["value"])
            (root / "backend.ready").unlink()
            observations = {}
            OBSERVE.backend_measurements(observations, route, readings, "/no-crs/allow")
            self.assertIsNone(observations["backend_request_count"]["value"])
            route["backend"] = rows + [{}]
            observations = {}
            OBSERVE.backend_measurements(observations, route, readings, "/no-crs/allow")
            self.assertIsNone(observations["backend_request_count"]["value"])
            route["backend"] = rows
            (root / "backend.jsonl").write_text(json.dumps(rows[0]))
            observations = {}
            OBSERVE.backend_measurements(observations, route, readings, "/no-crs/allow")
            self.assertIsNone(observations["backend_request_count"]["value"])

    def test_stored_pilot_allow_and_deny_do_not_become_zero_backend_counts(self):
        raw = stored_spop_backend_rows()
        rows, errors = OBSERVE.normalized_backend_rows({"backend": raw})
        self.assertFalse(errors)
        self.assertEqual([r["path"] for r in rows], ["/no-crs/allow", "/i12-neighbor"])
        self.assertEqual(sum(r["path"] == "/no-crs/allow" for r in rows), 1)
        self.assertEqual(sum(r["neighbor"] for r in rows), 1)
        self.assertEqual(rows[0]["raw_record"], raw[0])
        # c01 has only the neighbor row, with its own physical timestamp.
        deny = {**raw[1], "wall_ns": 1792320911661074927}
        rows, errors = OBSERVE.normalized_backend_rows({"backend": [deny]})
        self.assertFalse(errors)
        self.assertEqual(sum(r["path"] == "/no-crs/deny" for r in rows), 0)
        self.assertEqual(sum(r["neighbor"] for r in rows), 1)

    def test_unknown_or_corrupt_rows_never_report_an_empty_backend(self):
        raw = stored_spop_backend_rows()[0]
        malformed = [None, {}, {"kind": "backend_unknown"}, {**raw, "header_hex": "zz"},
                     {**raw, "body_hex": "a"}, {**raw, "neighbor": True},
                     {**raw, "wall_ns": True}, {**raw, "header_hex": "00" * (OBSERVE.BACKEND_HEADER_LIMIT + 1)}]
        for bad in malformed:
            with self.subTest(row=repr(bad)[:100]):
                route = {"backend": [raw, bad]}
                rows, errors = OBSERVE.normalized_backend_rows(route)
                self.assertEqual(len(rows), 1)
                self.assertEqual(len(errors), 1)
                self.assertEqual(errors[0]["raw_record"], bad)
                self.assertIsNone(OBSERVE.actual_backend_rows(route))

    def test_request_boundary_length_and_header_corruption_are_rejected(self):
        raw = stored_spop_backend_rows()[0]
        requests = [b"GET / HTTP/1.1\r\n\r\n", b"GET / HTTP/1.1\r\nBad Header: x",
                    b"GET / HTTP/1.1\r\nHost: x\nInjected: y",
                    b"GET / HTTP/1.1\r\nContent-Length: 1", b"GET / HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0",
                    b"GET / HTTP/1.1\r\nTransfer-Encoding: chunked", b"GET / HTTP/2.0", b"GET /a b HTTP/1.1"]
        for request in requests:
            with self.subTest(request=request):
                corrupt = {**raw, "header_hex": request.hex()}
                with self.assertRaises(ValueError):
                    OBSERVE.spop_backend_request(corrupt)

    def test_complete_body_and_original_companion_rows_remain_supported(self):
        raw = stored_spop_backend_rows()[0]
        value = OBSERVE.spop_backend_request({**raw, "header_hex": b"POST /body HTTP/1.0\r\nContent-Length: 3".hex(), "body_hex": b"a\x00b".hex()})
        self.assertEqual(value["body_sha256"], OBSERVE.digest(b"a\x00b"))
        self.assertEqual(value["body_bytes"], 3)
        companion = [{"kind": "backend_request", "path": "/i12/0", "body_hex": ""}, {"kind": "backend_chunk", "path": "/i12/0", "bytes": 1}]
        self.assertEqual(OBSERVE.normalized_backend_rows({"backend": companion}), (companion, []))


class RouteObservationTests(unittest.TestCase):
    def setUp(self):
        from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root

        storage = validate_output_root(ROOT, Path(os.environ["RUNNER_TEMP"]))
        self.temp = tempfile.TemporaryDirectory(dir=storage)
        self.addCleanup(self.temp.cleanup)
        selected_storage = patch.object(OBSERVE.CAPTURE, "STORAGE", storage)
        selected_storage.start()
        self.addCleanup(selected_storage.stop)
        self.root = Path(self.temp.name)
        self.attempt = self.root / "attempt-control"
        self.data = self.attempt / "data/host"
        self.data.mkdir(parents=True)
        self.artifacts = self.root / "artifacts"
        self.fixtures = self.root / "fixtures"
        self.artifacts.mkdir()
        self.fixtures.mkdir()
        self.fixture = self.fixtures / "selected.json"
        self.write(self.fixture, {"schema": "i12-companion-source-fixture-v2", "case_id": CASE, "original_oracle": {"native_result": None}})
        images = []
        for name, role in (("haproxy", "companion"), ("haproxy-spop", "agent"), ("libmodsecurity.so.3", "native_engine")):
            path = self.artifacts / name
            path.write_bytes(("unit-control-only:" + name).encode())
            images.append({"role": role, "source": str(path), "sealed_copy": str(path), "sha256": OBSERVE.digest(path.read_bytes())})
        self.build = self.root / "build.json"
        self.write(self.build, {"companion": {"sha256": images[0]["sha256"]}, "agent": {"sha256": images[1]["sha256"]}, "sdk": {"image_sha256": images[2]["sha256"]}})
        self.write(self.artifacts / "source-provenance.json", {"product_revision": "unit-control", "build_receipt": str(self.build), "build_receipt_sha256": OBSERVE.digest(self.build.read_bytes()), "images": images})
        bindings = []
        for source, target in ((self.artifacts, "/mnt/artifacts"), (self.fixtures, "/mnt/fixtures")):
            ledger = self.root / (source.name + "-ledger.json")
            self.write(ledger, {"files": {p.name: OBSERVE.digest(p.read_bytes()) for p in source.iterdir()}})
            bindings.append({"source": str(source), "target": target, "ledger": str(ledger), "ledger_sha256": OBSERVE.digest(ledger.read_bytes())})
        self.spec = self.root / "spec.json"
        argv = ["runner", "--fixture", "/mnt/fixtures/selected.json"]
        self.write(self.spec, {"argv": argv, "bindings": bindings})
        self.write(self.attempt / "admission.original.json", {"argv": argv, "uid": 65534})
        self.write(self.attempt / "controller-result.json", {"spec_sha256": OBSERVE.digest(self.spec.read_bytes()), "admission_sha256": OBSERVE.digest((self.attempt / "admission.original.json").read_bytes()), "executed_input_hashes_before": {str(self.spec): OBSERVE.digest(self.spec.read_bytes())}, "executed_input_hashes_after": {str(self.spec): OBSERVE.digest(self.spec.read_bytes())}, "surviving_namespace_pids": [], "outside_mount_leaks": [], "supervisor_reaped": True})
        self.rows = stored_schema_rows()
        self.jsonl("agent-native.jsonl", self.rows)
        self.jsonl("host-native.jsonl", [])
        self.write(self.data / "client-0.json", {"kind": "client", "index": 0, "length": 0, "time_ns": 1792319733468597711, "error": "SSLEOFError", "tls_eof": "exception", "kernel_tcp_eof": True})
        (self.data / "client-0.request").write_bytes(b"POST /i12/0 HTTP/1.1\r\nContent-Length: 8\r\n\r\nabcdefgh")
        (self.data / "client-0.response").write_bytes(b"")
        self.write(self.data / "receipt.json", {"format": "i12-companion-private-host-v1", "commands": [{"label": "client-0", "exit": 0}]})
        self.write(self.data / "observations.json", [{"kind": "backend_request", "path": "/i12/0", "body_hex": "6162636465666768", "time_ns": 1792319733420023634}])
        (self.data / "agent.conf").write_text("decision-log=/task/host/decision.jsonl\n")
        (self.data / "spoe.cfg").write_text("unit-control SPOE configuration\n")
        for name in ("haproxy.cfg", "rules.conf", "native-debug.log"):
            (self.data / name).write_text("unit control\n")
        notify = ENCODE.encode_notify([("request_id", 8, IDENTITY), ("path", 8, "/i12/0"), ("client_ip", 6, "127.0.0.1"), ("client_port", 4, 12345), ("body", 9, b"abcdefgh"), ("body_len", 4, 8), ("http_version", 8, "1.1")])
        for suffix in (".bin", ".forwarded.bin"):
            (self.data / ("spop-1-notify" + suffix)).write_bytes(notify)
        capability = b"a" * 64
        capability_sha = OBSERVE.digest(capability)
        (self.data / "agent.stderr").write_text('HAPROXY_COMPANION_LIFECYCLE ' + json.dumps({"kind": "spop_registry_handoff", "scope_call": 2, "capability_sha256": capability_sha}) + "\n")
        (self.data / "host.stderr").write_text('HAPROXY_COMPANION_LIFECYCLE ' + json.dumps({"kind": "htx_companion_response_http_end", "scope_call": 0, "capability_sha256": capability_sha}) + "\n")
        (self.data / "mrc1-1-host.forwarded.bin").write_bytes(OBSERVE.CASES.mrc_frame(1, capability) + OBSERVE.CASES.mrc_frame(4))
        (self.data / "mrc1-1-owner.forwarded.bin").write_bytes(OBSERVE.CASES.mrc_frame(128, b"result"))
        (self.data / "agent-before-main.maps").write_text("0000 r-xp 0 0:0 1 /mnt/artifacts/libmodsecurity.so.3\n")
        self.jsonl("decision.jsonl", [{"transaction_id": IDENTITY, "decision": "pass"}, {"transaction_id": IDENTITY, "event": "connector_error"}, {"transaction_id": "neighbor", "event": "connector_error"}])
        (self.data / "native-audit.log").write_text('[unique_id "' + IDENTITY + '"] actual stored-schema control\n')

    @staticmethod
    def write(path, value):
        path.write_text(json.dumps(value) + "\n")

    def jsonl(self, name, rows):
        (self.data / name).write_text("".join(json.dumps(value) + "\n" for value in rows))

    def observe(self):
        return OBSERVE.observe(self.attempt, self.data, self.spec, self.build, self.fixture, OBSERVE.COMPANION, CASE)

    def test_stored_schema_partial_facts_preserve_all_35_fields_and_pending_outcomes(self):
        packet = self.observe()
        self.assertEqual(set(packet["observations"]), set(OBSERVE.LEDGER.ROLES))
        self.assertEqual(packet["observations"]["native_transaction_id"]["value"], IDENTITY)
        self.assertEqual(packet["observations"]["client_bytes"]["value"], 0)
        self.assertEqual(packet["reviewed_by"], "pending_root")
        for name in ("oracle_evaluated", "outcome", "full_lifecycle_qualified"):
            self.assertIsNone(packet[name])
        self.assertIsNone(packet["observations"]["commit_order"]["value"])
        self.assertIn("start", packet["partial_association"]["join"]["time_window_reason"])
        for field, value in packet["observations"].items():
            OBSERVE.LEDGER.measurement(field, value, self.root / "packet.json")

    def test_original_and_forwarded_capture_do_not_double_join_or_double_free(self):
        packet = self.observe()
        cleanup = packet["observations"]["native_free_calls"]["value"]
        self.assertEqual(len(cleanup["actual_native_cleanup_returns"]), 1)
        self.assertTrue(cleanup["common_cleanup_is_not_a_second_native_free"])
        self.assertEqual(len(packet["physical_SPOP_frames"]), 2)
        physical = packet["observations"]["native_events"]["value"]
        self.assertEqual(len(physical["actual_common_rows"]), 1)
        self.assertEqual(len(physical["unmatched_physical_rows"]), 1)

    def test_missing_native_file_cannot_borrow_other_clients(self):
        (self.data / "agent-native.jsonl").unlink()
        packet = self.observe()
        self.assertIsNone(packet["observations"]["native_free_calls"]["value"])
        self.assertIn("agent-native.jsonl", packet["missing_or_corrupt_files"])

    def test_corrupt_frames_and_native_rows_stay_unknown(self):
        (self.data / "spop-1-notify.forwarded.bin").write_bytes(b"broken")
        packet = self.observe()
        self.assertTrue(packet["decode_errors"])
        self.assertIsNone(packet["partial_association"]["join"])
        self.assertEqual(len(packet["unmatched_agent_native_rows"]), len(self.rows))
        (self.data / "agent-native.jsonl").write_text("{broken\n")
        packet = self.observe()
        self.assertIsNone(packet["observations"]["native_transaction_id"]["value"])

    def test_cross_client_uuid_and_ambiguous_scope_are_not_associated(self):
        changed = copy.deepcopy(self.rows)
        changed[1]["transaction_id"] = "neighbor"
        self.jsonl("agent-native.jsonl", changed)
        self.assertIsNone(self.observe()["partial_association"]["join"])
        self.jsonl("agent-native.jsonl", self.rows + [copy.deepcopy(self.rows[1])])
        self.assertIsNone(self.observe()["partial_association"]["join"])

    def test_sibling_case_rows_cannot_supply_native_measurements(self):
        self.jsonl("agent-native.jsonl", [{**row, "case": "I12::haproxy-spop-htx-response-companion::sibling"} for row in self.rows])
        packet = self.observe()
        self.assertIsNone(packet["partial_association"]["join"])
        self.assertEqual(len(packet["unmatched_agent_native_rows"]), len(self.rows))

    def test_client_timestamp_conflict_and_wrong_capability_stay_partial(self):
        self.write(self.data / "client-0.json", {"time_ns": 1})
        self.assertIsNone(self.observe()["partial_association"]["join"])
        self.write(self.data / "client-0.json", {"time_ns": 1792319733468597711})
        (self.data / "mrc1-1-host.forwarded.bin").write_bytes(OBSERVE.CASES.mrc_frame(1, b"b" * 64))
        packet = self.observe()
        self.assertIsNone(packet["observations"]["host_eos"]["value"])
        self.assertIsNotNone(packet["observations"]["native_free_calls"]["value"])

    def test_source_seal_and_namespace_mapping_fail_closed(self):
        spec = json.loads(self.spec.read_text())
        bindings = OBSERVE.Bindings(spec)
        path, _ = bindings.resolve("/mnt/artifacts/libmodsecurity.so.3")
        self.assertEqual(path.parent, self.artifacts)
        with self.assertRaises(ValueError):
            bindings.resolve("/mnt/artifacts/../outside")
        (self.artifacts / "libmodsecurity.so.3").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "sealed input hash differs"):
            self.observe()

    def test_current_completion_seal_provenance_binds_all_images(self):
        direct = self.artifacts / "haproxy-direct"
        direct.write_bytes(b"unit-control-only:haproxy-direct")
        legacy = json.loads((self.artifacts / "source-provenance.json").read_text())
        images = [{"role": "direct", "source": str(direct), "sealed_copy": str(direct),
                   "sha256": OBSERVE.digest(direct.read_bytes())}, *legacy["images"]]
        current = self.root / "completion-seal.json"
        build = {"required_head": "current-control", "host_runs": 0, "runtime_qualified": False,
                 "binaries": {role: {"path": image["source"], "sha256": image["sha256"]}
                              for role, image in (("direct", images[0]), ("companion", images[1]), ("agent", images[2]))}}
        self.write(current, build)
        provenance = {"schema": "haproxy-i12-host-input-provenance-v1",
                      "product_and_capture_revision": "current-control",
                      "build_completion_seal": str(current),
                      "build_completion_seal_sha256": OBSERVE.digest(current.read_bytes()),
                      "images": images}
        actual, actual_images = OBSERVE.verified_provenance_images(provenance, current)
        self.assertEqual(actual["required_head"], "current-control")
        self.assertEqual([image["role"] for image in actual_images],
                         ["direct", "companion", "agent", "native_engine"])
        changed = copy.deepcopy(provenance)
        changed["images"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "sealed input hash differs"):
            OBSERVE.verified_provenance_images(changed, current)
        changed = copy.deepcopy(provenance)
        changed["images"].pop()
        with self.assertRaisesRegex(ValueError, "unexpected image inventory"):
            OBSERVE.verified_provenance_images(changed, current)

    def test_cross_client_payload_and_missing_callback_cannot_complete_association(self):
        (self.data / "client-0.request").write_bytes(b"POST /i12/0 HTTP/1.1\r\nContent-Length: 8\r\n\r\nDIFFERENT")
        self.assertIsNone(self.observe()["partial_association"]["join"])
        (self.data / "client-0.request").write_bytes(b"POST /i12/0 HTTP/1.1\r\nContent-Length: 8\r\n\r\nabcdefgh")
        (self.data / "agent.stderr").unlink()
        packet = self.observe()
        self.assertIsNone(packet["observations"]["capability"]["value"])
        self.assertIsNone(packet["observations"]["host_eos"]["value"])
        self.assertEqual(packet["observations"]["native_transaction_id"]["value"], IDENTITY)

    def test_independent_client_digest_and_host_artifact_seal_are_enforced(self):
        client = json.loads((self.data / "client-0.json").read_text())
        client["request_sha256"] = "0" * 64
        self.write(self.data / "client-0.json", client)
        self.assertIsNone(self.observe()["partial_association"]["join"])
        receipt = json.loads((self.data / "receipt.json").read_text())
        receipt["files"] = {"agent-native.jsonl": "0" * 64}
        self.write(self.data / "receipt.json", receipt)
        with self.assertRaisesRegex(ValueError, "artifact differs from host receipt seal"):
            self.observe()

    def test_original_spop_file_schema_keeps_request_only_native_facts(self):
        case = "I12::haproxy-spop-request::allow_without_marker"
        self.write(self.fixture, {"schema": "i12-spop-original-source-fixture-v1", "case_id": case})
        spec = json.loads(self.spec.read_text())
        ledger_path = Path(spec["bindings"][1]["ledger"])
        ledger = json.loads(ledger_path.read_text())
        ledger["files"]["selected.json"] = OBSERVE.digest(self.fixture.read_bytes())
        self.write(ledger_path, ledger)
        spec["bindings"][1]["ledger_sha256"] = OBSERVE.digest(ledger_path.read_bytes())
        self.write(self.spec, spec)
        controller_path = self.attempt / "controller-result.json"
        controller = json.loads(controller_path.read_text())
        controller["spec_sha256"] = OBSERVE.digest(self.spec.read_bytes())
        for key in ("executed_input_hashes_before", "executed_input_hashes_after"):
            controller[key][str(self.spec)] = controller["spec_sha256"]
        self.write(controller_path, controller)
        rows = [{**row, "case": case, "profile": OBSERVE.REQUEST} for row in self.rows]
        self.jsonl("agent-native-api.jsonl", rows)
        self.jsonl("host-native-api.jsonl", [])
        self.jsonl("client.jsonl", [{"index": 0, "neighbor": False, "connection": 1, "request_sha256": OBSERVE.digest((self.data / "client-0.request").read_bytes())}])
        (self.data / "request-0.raw").write_bytes((self.data / "client-0.request").read_bytes())
        (self.data / "response-0.raw").write_bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        raw = (self.data / "spop-1-notify.forwarded.bin").read_bytes()
        self.jsonl("frames.jsonl", [{"connection": 0, "direction": "host-agent", "sha256": OBSERVE.digest(raw), "hex": raw.hex()}])
        self.jsonl("commands.jsonl", [{"role": "independent-client", "exit": 0}])
        packet = OBSERVE.observe(self.attempt, self.data, self.spec, self.build, self.fixture, OBSERVE.REQUEST, case)
        self.assertEqual(packet["observations"]["native_transaction_id"]["value"], IDENTITY)
        self.assertIsNone(packet["observations"]["observed_handle_association"]["value"])
        self.assertEqual(packet["observations"]["native_phases"]["value"]["native_process_response_body"], [])
        self.assertIsNone(packet["observations"]["native_eos"]["value"]["streaming_eos_argument"])
        self.assertIn("actual_finite_P2_completion", packet["observations"]["native_eos"]["value"])
        self.assertTrue(packet["observations"]["client_exit"]["value"]["individual_request_exit_not_recorded"])

    def test_actual_namespace_maps_bind_sdk_and_both_binary_images(self):
        (self.data / "agent-before-main.maps").write_text("0000 r-xp 0 0:0 1 /mnt/artifacts/libmodsecurity.so.3\n0001 r-xp 0 0:0 2 /mnt/artifacts/haproxy-spop\n")
        (self.data / "host-before-main.maps").write_text("0000 r-xp 0 0:0 1 /mnt/artifacts/libmodsecurity.so.3\n0001 r-xp 0 0:0 2 /mnt/artifacts/haproxy\n")
        value = self.observe()["observations"]["product_host_identity"]["value"]
        self.assertEqual(len(value["actual_loaded_images"]), 4)
        self.assertTrue(all(image["physical_path"].startswith(str(self.artifacts)) for image in value["actual_loaded_images"]))
        spec = json.loads(self.spec.read_text())
        spec["bindings"].append(copy.deepcopy(spec["bindings"][0]))
        bindings = OBSERVE.Bindings(spec)
        with self.assertRaisesRegex(ValueError, "ambiguous sealed binding"):
            bindings.resolve("/mnt/artifacts/haproxy")

    def test_sealed_batch_member_cannot_transfer_to_sibling_data_root(self):
        previous = self.data
        self.data = self.attempt / "data/c00"
        previous.rename(self.data)
        (self.data / "agent.conf").write_text("decision-log=/task/c00/decision.jsonl\n")
        member_dir = self.fixtures / "c00"
        member_dir.mkdir()
        self.fixture.rename(member_dir / "selected.json")
        self.fixture = member_dir / "selected.json"
        queue = {"schema": "i12-haproxy-batch-v1", "cases": [{"member": "c00", "original_id": CASE, "data_root": "/task/c00", "argv": ["runner"], "fixture": {"path": "selected.json"}}]}
        queue_path = self.fixtures / "queue.json"
        self.write(queue_path, queue)
        queue_hash = OBSERVE.digest(queue_path.read_bytes())
        spec = json.loads(self.spec.read_text())
        spec["argv"] = ["batch", "--queue", "/mnt/fixtures/queue.json", "--sha256", queue_hash]
        fixture_binding = spec["bindings"][1]
        ledger = Path(fixture_binding["ledger"])
        self.write(ledger, {"files": {str(p.relative_to(self.fixtures)): OBSERVE.digest(p.read_bytes()) for p in self.fixtures.rglob("*") if p.is_file()}})
        fixture_binding["ledger_sha256"] = OBSERVE.digest(ledger.read_bytes())
        self.write(self.spec, spec)
        self.write(self.attempt / "admission.original.json", {"argv": spec["argv"], "uid": 65534})
        controller_path = self.attempt / "controller-result.json"
        controller = json.loads(controller_path.read_text())
        controller["admission_sha256"] = OBSERVE.digest((self.attempt / "admission.original.json").read_bytes())
        controller["spec_sha256"] = OBSERVE.digest(self.spec.read_bytes())
        for key in ("executed_input_hashes_before", "executed_input_hashes_after"):
            controller[key][str(self.spec)] = controller["spec_sha256"]
        self.write(controller_path, controller)
        self.write(self.attempt / "data/batch-result.json", {"queue_sha256": queue_hash, "members": [{"original_id": CASE, "argv": ["runner"], "cwd": "/task/c00", "waited_exit": 0}]})
        packet = self.observe()
        self.assertEqual(packet["batch_execution_binding"]["actual_execution"]["waited_exit"], 0)
        sibling = self.attempt / "data/c01"
        with self.assertRaisesRegex(ValueError, "data root differs"):
            OBSERVE.observe(self.attempt, sibling, self.spec, self.build, self.fixture, OBSERVE.COMPANION, CASE)

    def test_fresh_actual_client_window_and_endpoint_must_agree(self):
        client = {"schema": "i12-companion-client-capture-v2", "pid": 300,
                  "started_wall_ns": 1792319733359519800, "completed_wall_ns": 1792319733468597711,
                  "connection_local": ["127.0.0.1", 12345]}
        self.write(self.data / "client-0.json", client)
        packet = self.observe()
        self.assertTrue(packet["observations"]["observed_handle_association"]["value"]["client_endpoint_verified"])
        client["connection_local"][1] = 54321
        self.write(self.data / "client-0.json", client)
        self.assertIsNone(self.observe()["partial_association"]["join"])

    def test_specific_waited_child_receipt_preserves_signal_and_missing_exit(self):
        process = {"schema": "i12-companion-client-process-v1", "argv": ["client"],
                   "pid": 300, "exit": -15, "signal": 15, "reaped": True, "timed_out": False}
        self.write(self.data / "client-0.process.json", process)
        packet = self.observe()
        self.assertEqual(packet["observations"]["client_signal"]["value"]["signal"], 15)
        process["exit"] = None
        self.write(self.data / "client-0.process.json", process)
        self.assertIsNone(self.observe()["observations"]["client_exit"]["value"])

    def test_wrong_or_ambiguous_sink_path_is_not_common_event_evidence(self):
        for text in ("decision-log=/task/sibling/decision.jsonl\n", "decision-log=/task/host/decision.jsonl\ndecision-log=/task/host/decision.jsonl\n"):
            with self.subTest(configuration=text):
                (self.data / "agent.conf").write_text(text)
                packet = self.observe()
                self.assertFalse(packet["physical_common_sink_binding"]["configuration_matches"])
                self.assertIsNone(packet["observations"]["physical_event_order"]["value"])
                self.assertTrue(packet["observations"]["native_events"]["partial_facts"]["unbound_physical_rows"])

    def test_neighbor_backend_facts_exclude_driver_expectations(self):
        self.write(self.data / "client-100.json", {"kind": "client", "index": 100, "length": 20})
        self.write(self.data / "observations.json", [{"kind": "backend_request", "path": "/neighbor"}, {"kind": "client", "expected": {"status": 200}, "independent_comparison": {"status_matches": True}}])
        packet = self.observe()
        actual = packet["observations"]["neighbor_health"]["value"]["actual_backend_rows"]
        self.assertEqual(actual, [{"kind": "backend_request", "path": "/neighbor"}])

    def test_failed_connect_report_cannot_inherit_stale_host_execution(self):
        self.write(self.data / "client-0.json", {"schema": "i12-companion-client-capture-v2", "error_type": "ConnectionRefusedError", "request_send_started_wall_ns": None, "completed_wall_ns": 1792319733468597711})
        packet = self.observe()
        self.assertFalse(packet["execution_observed"])
        self.assertIn("no request send start", packet["execution_observed_reason"])
        self.assertIsNone(packet["partial_association"]["join"])
        self.assertIsNone(packet["observations"]["native_transaction_id"]["value"])
        self.assertIsNone(packet["observations"]["observed_handle_association"]["value"])
        self.assertEqual(len(packet["unmatched_agent_native_rows"]), len(self.rows))

    def test_request_authorization_finish_keeps_mask_three_and_no_response_phases(self):
        rows = [row("common_finish_request_authorization", 80, edge="enter", contract_state={"completed_phase_mask": 3}), row("common_finish_request_authorization", 80, contract_state={"completed_phase_mask": 3, "last_completed_phase": 3})]
        transitions = OBSERVE.transitions(rows)
        self.assertEqual(transitions[0]["after"]["completed_phase_mask"], 3)
        self.assertEqual(OBSERVE.calls(rows, "native_process_response_body"), [])
        self.assertEqual(OBSERVE.calls(rows, "native_process_response_headers"), [])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
