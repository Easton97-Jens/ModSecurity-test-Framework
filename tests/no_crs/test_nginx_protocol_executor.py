"""On-demand modern-protocol regression checks; no host launch in selftests."""
from copy import deepcopy
import json
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from tests.runners import nginx_protocol as protocol


class NginxProtocolExecutorTest(unittest.TestCase):
    def client(self, name="h2"):
        return {"http_version": "2" if name == "h2" else "3", "http_code": 403, "exit_code": 0,
                "trace": f"* ALPN: server accepted {name}\n* [HTTP/{name[1]}] [1] OPENED stream for https://127.0.0.1\n"}

    def test_observed_protocol_alpn_and_stream_are_required(self):
        facts = protocol.client_facts(self.client(), "h2")
        self.assertEqual((facts["client_alpn"], facts["stream_id"], facts["fallback_used"]), ("h2", 1, False))
        self.assertTrue(facts["client_alpn_observed"])
        self.assertNotIn("alpn", facts)
        for changed in ({"http_version": "1.1"}, {"trace": "* ALPN: offers h2\n"},
                        {"trace": "* ALPN: server accepted http/1.1\n"}, {"exit_code": 35}):
            client = dict(self.client(), **changed)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                protocol.client_facts(client, "h2")

    def test_real_quic_header_metadata_excludes_payload_and_raw_connection_id(self):
        port = 18443
        ip = bytearray(20)
        ip[0], ip[9], ip[12:16], ip[16:20] = 0x45, 17, b"\x7f\0\0\1", b"\x7f\0\0\1"
        udp = (43210).to_bytes(2, "big") + port.to_bytes(2, "big") + b"\0\x20\0\0"
        quic = b"\xc0\0\0\0\x01\x08" + b"SECRETID" + b"\x00PAYLOAD"
        frame = bytes(12) + b"\x08\0" + ip + udp + quic
        facts = protocol.quic_datagram(frame, port)
        self.assertEqual(facts["direction"], "request")
        self.assertEqual(facts["quic_version"], "0x00000001")
        self.assertNotIn("SECRETID", json.dumps(facts))
        self.assertNotIn("PAYLOAD", json.dumps(facts))
        self.assertIsNone(protocol.quic_datagram(frame, port + 1))
        self.assertIsNone(protocol.quic_datagram(frame[:20], port))

    def test_unsupported_reset_and_multiplex_operations_have_no_executor(self):
        for case in ("h2_client_rst_stream", "h3_server_stream_reset", "h2_phase4_strict",
                     "h3_reset_does_not_abort_unrelated_stream", "h2_parallel_cleanup_balanced"):
            self.assertIsNone(protocol.invocation({"case_id": case}))

    def fixture(self, root, case="protocol_h2_negotiated"):
        run = "protocol-selftest"
        requested, phase, expected_status, rule = protocol.CASES[case]
        transactions = [run + "-1-1", run + "-2-1"]
        rows = [{"uri": path, "transaction_id": transaction, "status": status,
                 "protocol": "HTTP/2.0" if requested == "h2" else "HTTP/3.0", "alpn": requested}
                for path, transaction, status in zip(("/no-crs/protocol/allow", f"/no-crs/protocol/phase{phase}"),
                                                     transactions, (200, expected_status), strict=True)]
        client = dict(self.client(requested), http_code=expected_status)
        packets = [{"direction": direction, "quic_version": "0x00000001",
                    "connection_id": "sha256:" + "c" * 64, "udp_bytes": 1200}
                   for direction in ("request", "response")] if requested == "h3" else []
        objects = {"client.json": client, "quic.json": {"datagrams": packets},
                   "roles.json": {"master_uid": 0, "worker_uid": 65534},
                   "cleanup.json": {"verified": True, "udp_listener_open": False},
                   "observation.json": {"case_id": case, "run_id": run,
                                        "request_path": rows[1]["uri"], "actual_status": expected_status}}
        raws = {leaf: json.dumps(value).encode() for leaf, value in objects.items()}
        raws["access.jsonl"] = b"\n".join(json.dumps(row).encode() for row in rows) + b"\n"
        allow = {"transaction_id": transactions[0], "uri": rows[0]["uri"], "method": "GET",
                 "phase": "request_headers", "connector": "nginx", "integration_mode": protocol.MODE,
                 "event": "request_headers_complete", "status": "ok", "requested_action": "allow", "actual_action": ""}
        native = {"transaction_id": transactions[1], "uri": rows[1]["uri"], "rule_id": rule,
                  "phase": phase, "connector": "nginx", "integration_mode": protocol.MODE,
                  "method": "POST" if phase == 2 else "GET", "event": f"phase{phase}_intervention",
                  "status": "blocked", "requested_action": "deny", "actual_action": "" if phase < 3 else "deny",
                  "http_status": 403, "visible_http_status": 0 if phase < 3 else 403, "response_committed": False}
        if phase == 4 and rule is not None:
            native.update(actual_action="log_only", visible_http_status=200, response_committed=True,
                          headers_sent=True, late_intervention=True, late_intervention_mode="safe", connection_aborted=False)
        if rule is None:
            native = dict(allow, transaction_id=transactions[1], uri=rows[1]["uri"])
        raws["native-events.jsonl"] = b"\n".join(json.dumps(row).encode() for row in (allow, native)) + b"\n"
        receipt = {"case_id": case, "run_id": run, "integration_mode": protocol.MODE,
                   **dict.fromkeys(("parent_sha", "framework_sha", "mrts_sha"), "a" * 40),
                   **dict.fromkeys(("binary_sha256", "module_sha256"), "b" * 64),
                   "sha256": {leaf: protocol.digest(raw) for leaf, raw in raws.items()}}
        framework = Path(__file__).resolve().parents[2]
        receipt.update(contract_sha256=protocol.digest(Path(protocol.__file__).read_bytes()),
                       driver_sha256=protocol.digest((framework / "connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-nginx-protocol-cases.py").read_bytes()),
                       rules_sha256=protocol.digest((framework / "tests/rules/no-crs-baseline.conf").read_bytes()))
        raws["receipt.json"] = json.dumps(receipt).encode()
        for leaf, raw in raws.items():
            (root / leaf).write_bytes(raw)
            (root / leaf).chmod(0o600)
        return case, run, receipt

    def test_reopen_detects_mutation_foreign_request_and_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case, run, receipt = self.fixture(root)
            proof = protocol.validate_bundle(root, case_id=case, run_id=run)
            self.assertEqual(proof["actual_status"], 403)
            self.assertNotIn("stream_id", proof["native_events"][0])
            self.assertEqual(proof["facts"]["stream_id"], 1)
            (root / "client.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                protocol.validate_bundle(root, case_id=case, run_id=run)
        for leaf, mutation, message in (
            ("cleanup.json", {"verified": False}, "cleanup"),
            ("cleanup.json", {"udp_listener_open": True}, "cleanup"),
            ("roles.json", {"worker_uid": 0}, "isolated native roles"),
            ("observation.json", {"run_id": "foreign"}, "identity mismatch"),
            ("observation.json", {"driver_error": "config rejected"}, "original protocol driver failed"),
            ("client.json", {"http_version": "1.1"}, "fallback"),
        ):
            with self.subTest(leaf=leaf), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                case, run, receipt = self.fixture(root)
                value = json.loads((root / leaf).read_bytes())
                value.update(mutation)
                raw = json.dumps(value).encode()
                (root / leaf).write_bytes(raw)
                receipt["sha256"][leaf] = protocol.digest(raw)
                (root / "receipt.json").write_text(json.dumps(receipt))
                with self.assertRaisesRegex(ValueError, message):
                    protocol.validate_bundle(root, case_id=case, run_id=run)

    def test_unknown_shell_protocol_is_rejected_before_host_dispatch(self):
        framework = Path(__file__).resolve().parents[2]
        script = framework / "connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-nginx-selected-host.sh"
        # No smoke/config/native script exists in this private root. Explicit
        # protocol rejection must happen before attempting any of them.
        with tempfile.TemporaryDirectory() as temporary:
            environment = dict(os.environ, FRAMEWORK_ROOT=temporary)
            for value in ("h2c", "unexpected", "H3"):
                environment["NGINX_DOWNSTREAM_PROTOCOL"] = value
                result = subprocess.run(["/bin/sh", str(script)], env=environment,
                                        capture_output=True, timeout=5, check=False)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stderr.strip(), b"unsupported NGINX_DOWNSTREAM_PROTOCOL")

    def test_selected_cli_rejects_unsafe_or_duplicate_identities_before_sources(self):
        framework = Path(__file__).resolve().parents[2]
        script = framework / "connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-selected-nginx-protocol-cases.py"
        for changes, message in (
            ({"NO_CRS_RUN_ID": "../foreign"}, b"path-safe protocol run identity"),
            ({"NO_CRS_SELECTED_CASE_IDS": "h2_phase2_deny h2_phase2_deny"}, b"unique bounded tokens"),
            ({"NO_CRS_SELECTED_CASE_IDS": "../foreign"}, b"unique bounded tokens"),
        ):
            environment = dict(os.environ, NO_CRS_RUN_ID="valid-run", NO_CRS_SELECTED_CASE_IDS="h2_phase2_deny")
            environment.update(changes)
            result = subprocess.run([sys.executable, str(script)], env=environment,
                                    capture_output=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn(message, result.stderr)

    def test_catalog_binding_rejects_changed_rule_or_protocol(self):
        catalog = json.loads((Path(__file__).parents[1] / "cases/no-crs-baseline/catalog.json").read_text())
        for case in catalog["cases"]:
            if case["case_id"] not in protocol.CASES:
                continue
            self.assertEqual(protocol.invocation(case)["operation"], "native_protocol")
            changed = deepcopy(case)
            changed["expected_rule_id"] = 999
            with self.assertRaises(ValueError):
                protocol.invocation(changed)

    def test_executor_forces_protocol_and_rejects_successful_http1_transfer(self):
        from modsecurity_test_framework.connector_context import load_source
        framework = Path(__file__).resolve().parents[2]
        executor = load_source(framework / "connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-nginx-protocol-cases.py")
        for requested, case_id, option in (("h2", "protocol_h2_negotiated", "--http2-prior-knowledge"),
                                            ("h3", "protocol_h3_negotiated", "--http3-only")):
            with self.subTest(requested=requested), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                args = SimpleNamespace(curl="controlled-curl", case_id=case_id, port=18443)
                def response(command, **kwargs):
                    self.assertIn(option, command)
                    self.assertIn("--cacert", command)
                    kwargs["stderr"].write(b"* ALPN: server accepted http/1.1\n")
                    return SimpleNamespace(returncode=0, stdout=b'{"http_code":403,"http_version":"1.1"}')
                with mock.patch.object(executor.subprocess, "run", side_effect=response):
                    with self.assertRaisesRegex(ValueError, "fallback rejected"):
                        executor.request(args, root, {}, requested, "/no-crs/protocol/phase1")

    def test_canonical_roundtrip_keeps_host_facts_separate_and_reopens_bytes(self):
        from ci.checks.catalog import no_crs_baseline as canonical
        with tempfile.TemporaryDirectory() as temporary:
            authority = Path(temporary)
            root = authority / "bundle"
            root.mkdir(mode=0o700)
            case_id, run, _ = self.fixture(root)
            case = next(case for case in canonical.load_catalog()["cases"] if case["case_id"] == case_id)
            raw = {"case_id": case_id, "run_id": run, "connector": "nginx", "status": "PASS",
                   "integration_mode": protocol.MODE, "live_executed": True,
                   "protocol_bundle": str(root), "protocol_receipt_sha256": protocol.digest((root / "receipt.json").read_bytes())}
            record = canonical.normalize_case_record(raw, "nginx", {case_id: case}, [], protocol.MODE,
                                                     configtest_artifact_root=authority)
            self.assertEqual(record["status"], "PASS", record)
            self.assertNotIn("alpn", record["observed_event_fields"])
            self.assertIn("alpn", record["protocol_evidence_mapping"]["host_fields"])
            schema = json.loads((Path(__file__).parents[1] / "schemas/no-crs-baseline/case-result.schema.json").read_bytes())
            self.assertEqual(canonical.json_schema_errors(record, schema), [])
            self.assertEqual(canonical.pass_case_completeness_errors(record, [], "nginx", protocol.MODE,
                                                                    artifact_root=authority), [])
            canonical.bind_case_protocol_provenance([record], {"run_id": run, "integration_mode": protocol.MODE},
                                                     {case_id: case}, [], protocol.MODE, artifact_root=authority)
            canonical.validate_protocol_client_records([record], {case_id: case}, None,
                                                         native_protocol_root=authority)
            self.assertEqual(record["status"], "PASS", record["reason"])
            (authority / canonical.CASE_RESULTS_FILE_NAME).write_text(json.dumps(record) + "\n")
            self.assertEqual(canonical.protocol_client_errors(authority), [])
            (authority / canonical.MANIFEST_FILE_NAME).write_text(json.dumps(
                {"run_id": run, "connector_commit": "b" * 40, "framework_commit": "a" * 40}))
            with mock.patch.object(canonical, "git_value", return_value="a" * 40):
                self.assertTrue(canonical.protocol_record_errors(record, case, "nginx", authority))
            (authority / canonical.MANIFEST_FILE_NAME).unlink()
            mutated = dict(record, alpn="http/1.1")
            self.assertTrue(canonical.pass_case_completeness_errors(mutated, [], "nginx", protocol.MODE,
                                                                   artifact_root=authority))
            (root / "native-events.jsonl").write_text("")
            self.assertTrue(canonical.pass_case_completeness_errors(record, [], "nginx", protocol.MODE,
                                                                   artifact_root=authority))

    def test_canonical_retention_copies_original_bytes_and_pins_exact_pair(self):
        from ci.checks.catalog import no_crs_baseline as canonical
        with tempfile.TemporaryDirectory() as temporary:
            authority = Path(temporary)
            source, destination = authority / "source", authority / "canonical"
            source.mkdir(mode=0o700)
            destination.mkdir(mode=0o700)
            case_id, run, _ = self.fixture(source)
            raw = {"case_id": case_id, "run_id": run, "connector": "nginx", "status": "PASS",
                   "integration_mode": protocol.MODE, "live_executed": True,
                   "protocol_bundle": str(source), "protocol_receipt_sha256": protocol.digest((source / "receipt.json").read_bytes())}
            context = SimpleNamespace(run_dir=destination, configtest_source_roots={id(raw): authority},
                                      manifest={"run_id": run, "connector_commit": "a" * 40,
                                                "framework_commit": "a" * 40, "artifacts": {}})
            with mock.patch.object(canonical, "git_value", return_value="a" * 40):
                retained = canonical.retain_finalize_protocol_bundle(context, raw)
            root = destination / retained["protocol_bundle"]
            self.assertEqual(len(context.manifest["artifacts"]), len(protocol.LEAVES) + 1)
            for leaf in protocol.LEAVES | {"receipt.json"}:
                self.assertEqual((source / leaf).read_bytes(), (root / leaf).read_bytes())
            self.assertEqual(protocol.validate_bundle(root, case_id=case_id, run_id=run)["actual_status"], 403)
            with mock.patch.object(canonical, "git_value", return_value="b" * 40):
                with self.assertRaisesRegex(ValueError, "revision differs"):
                    canonical.retain_finalize_protocol_bundle(context, raw)

    def test_deprecated_alias_preserves_own_allow_bundle_without_borrowing_deny(self):
        from ci.checks.catalog import no_crs_baseline as canonical
        cases = {case["case_id"]: case for case in canonical.load_catalog()["cases"]}
        alias = {"case_id": "transport_http2_if_supported", "status": "PASS", "actual_status": 200,
                 "protocol_bundle": "inventory/native-protocol/transport_http2_if_supported"}
        target = {"case_id": "protocol_h2_negotiated", "status": "PASS", "actual_status": 403,
                  "protocol_bundle": "inventory/native-protocol/protocol_h2_negotiated"}
        original = deepcopy(alias)
        records = [alias, target]
        canonical.resolve_deprecated_aliases(records, cases)
        self.assertEqual(records[0], original)
        self.assertEqual(records[0]["actual_status"], 200)
        # A bundle-shaped claim alone still cannot pass independent validation.
        self.assertTrue(canonical.protocol_record_errors(alias, cases[alias["case_id"]], "nginx", None))

    def reseal_native(self, root, receipt, rows):
        raw = b"\n".join(json.dumps(row).encode() for row in rows) + (b"\n" if rows else b"")
        (root / "native-events.jsonl").write_bytes(raw)
        receipt["sha256"]["native-events.jsonl"] = protocol.digest(raw)
        (root / "receipt.json").write_text(json.dumps(receipt))

    def test_h3_backend_without_client_alpn_requires_independent_server_alpn(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case, run, receipt = self.fixture(root, "protocol_h3_negotiated")
            client = json.loads((root / "client.json").read_bytes())
            client["trace"] = "* [HTTP/3] [0] OPENED stream for https://127.0.0.1\n"
            raw = json.dumps(client).encode()
            (root / "client.json").write_bytes(raw)
            receipt["sha256"]["client.json"] = protocol.digest(raw)
            (root / "receipt.json").write_text(json.dumps(receipt))
            proof = protocol.validate_bundle(root, case_id=case, run_id=run)
            self.assertEqual(proof["facts"]["alpn"], "h3")
            self.assertEqual(proof["facts"]["alpn_source"], "nginx_access_ssl_alpn_protocol")
            self.assertFalse(proof["facts"]["client_alpn_observed"])
            self.assertIsNone(proof["facts"]["client_alpn"])

    def test_h3_missing_or_contradictory_server_or_client_alpn_fails(self):
        for index in (0, 1):
            for value in (None, "", "h2", "http/1.1"):
                with self.subTest(access=index, alpn=value), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    case, run, receipt = self.fixture(root, "protocol_h3_negotiated")
                    client = json.loads((root / "client.json").read_bytes())
                    client["trace"] = "* [HTTP/3] [0] OPENED stream for https://127.0.0.1\n"
                    raw = json.dumps(client).encode()
                    (root / "client.json").write_bytes(raw)
                    receipt["sha256"]["client.json"] = protocol.digest(raw)
                    accesses = [json.loads(line) for line in (root / "access.jsonl").read_bytes().splitlines()]
                    if value is None:
                        accesses[index].pop("alpn")
                    else:
                        accesses[index]["alpn"] = value
                    raw = b"\n".join(json.dumps(row).encode() for row in accesses) + b"\n"
                    (root / "access.jsonl").write_bytes(raw)
                    receipt["sha256"]["access.jsonl"] = protocol.digest(raw)
                    (root / "receipt.json").write_text(json.dumps(receipt))
                    with self.assertRaisesRegex(ValueError, "native access/client protocol"):
                        protocol.validate_bundle(root, case_id=case, run_id=run)
        for token in ("h2", "http/1.1", "h3-draft", "unknown"):
            with self.subTest(client_alpn=token):
                client = self.client("h3")
                client["trace"] = f"* ALPN: server accepted {token}\n* [HTTP/3] [0] OPENED stream for https://127.0.0.1\n"
                with self.assertRaisesRegex(ValueError, "observed client TLS ALPN"):
                    protocol.client_facts(client, "h3")

    def test_native_allow_cannot_prove_phase1_phase2_or_phase3_deny(self):
        for case in ("protocol_h2_negotiated", "h2_phase2_deny", "h2_phase3_deny"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                case, run, receipt = self.fixture(root, case)
                protocol.validate_bundle(root, case_id=case, run_id=run)
                rows = [json.loads(line) for line in (root / "native-events.jsonl").read_bytes().splitlines()]
                rows[-1].update(event="engine_decision", status="allowed", requested_action="allow",
                                actual_action="allow", http_status=200)
                self.reseal_native(root, receipt, rows)
                with self.assertRaisesRegex(ValueError, "semantic witness"):
                    protocol.validate_bundle(root, case_id=case, run_id=run)

    def test_phase4_safe_requires_actual_committed_safe_intervention(self):
        for mutation in ({"response_committed": False}, {"headers_sent": False},
                         {"requested_action": "allow"}, {"late_intervention": False},
                         {"late_intervention_mode": "strict"}, {"visible_http_status": 403},
                         {"actual_action": "deny"}, {"connection_aborted": True}):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                case, run, receipt = self.fixture(root, "h2_phase4_safe")
                proof = protocol.validate_bundle(root, case_id=case, run_id=run)
                self.assertEqual(proof["observed_result"], "late_intervention_log_only_safe")
                rows = [json.loads(line) for line in (root / "native-events.jsonl").read_bytes().splitlines()]
                rows[-1].update(mutation)
                self.reseal_native(root, receipt, rows)
                with self.assertRaisesRegex(ValueError, "semantic witness"):
                    protocol.validate_bundle(root, case_id=case, run_id=run)

    def test_allow_and_legacy_cannot_pass_with_absent_native_transaction(self):
        for case in ("transport_http2_if_supported", "protocol_h2_negotiated"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                case, run, receipt = self.fixture(root, case)
                protocol.validate_bundle(root, case_id=case, run_id=run)
                self.reseal_native(root, receipt, [])
                with self.assertRaisesRegex(ValueError, "allow request lacks original native"):
                    protocol.validate_bundle(root, case_id=case, run_id=run)

    def test_phase3_native_intervention_uses_same_transaction_uri_witness(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case, run, receipt = self.fixture(root, "h2_phase3_deny")
            rows = [json.loads(line) for line in (root / "native-events.jsonl").read_bytes().splitlines()]
            witness = dict(rows[-1], event="request_rule_match", status="ok", requested_action="pass", actual_action="pass")
            rows[-1]["uri"] = ""
            rows.insert(1, witness)
            self.reseal_native(root, receipt, rows)
            proof = protocol.validate_bundle(root, case_id=case, run_id=run)
            self.assertEqual(proof["matching_events"][0]["uri"], "")
            rows[1]["transaction_id"] = "foreign"
            self.reseal_native(root, receipt, rows)
            with self.assertRaisesRegex(ValueError, "original native event"):
                protocol.validate_bundle(root, case_id=case, run_id=run)

    def test_invalid_library_directory_precedes_backend_acquisition(self):
        from modsecurity_test_framework.connector_context import load_source
        framework = Path(__file__).resolve().parents[2]
        executor = load_source(framework / "connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-nginx-protocol-cases.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "fresh"
            args = SimpleNamespace(case_id="protocol_h2_negotiated", library_dir="/does-not-exist-protocol-test",
                                   framework_root=str(framework), curl="controlled-curl")
            client = SimpleNamespace(inspect_curl=lambda value: None,
                                     preflight_curl=lambda *args: SimpleNamespace(status="READY"))
            with mock.patch.object(executor.HOST.BASE, "validate_inputs", return_value=(Path("binary"), Path("module"), root)), \
                 mock.patch.object(executor, "preflight", return_value=0), \
                 mock.patch.object(executor, "load_source", return_value=client), \
                 mock.patch.object(executor.HOST.BASE, "snapshot_artifact", return_value="b" * 64), \
                 mock.patch.object(executor.os, "umask") as umask, \
                 mock.patch.object(executor, "ThreadingHTTPServer") as backend, \
                 mock.patch.object(executor.threading, "Thread") as thread:
                with self.assertRaisesRegex(ValueError, "library directory must exist"):
                    executor.run(args)
                umask.assert_called_once_with(0o077)
                backend.assert_not_called()
                thread.assert_not_called()

    def test_allow_body_has_no_phase4_marker(self):
        from modsecurity_test_framework.connector_context import load_source
        framework = Path(__file__).resolve().parents[2]
        executor = load_source(framework / "connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-nginx-protocol-cases.py")
        for path in ("/no-crs/protocol/allow", "/no-crs/protocol/phase4"):
            output = io.BytesIO()
            handler = SimpleNamespace(path=path, wfile=output, send_response=lambda value: None,
                                      send_header=lambda *values: None, end_headers=lambda: None)
            executor.Backend.do_GET(handler)
            self.assertEqual(b"no-crs-response-body-marker" in output.getvalue(), path.endswith("phase4"))


if __name__ == "__main__":
    unittest.main()
