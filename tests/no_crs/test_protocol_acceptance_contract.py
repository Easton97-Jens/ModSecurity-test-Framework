"""Corruption controls for the independent opt-in acceptance contract.

These fixtures exercise evidence validation, not connector runtime behavior.
"""
import copy
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from tests.runners import protocol_acceptance_contract as contract


class ProtocolAcceptanceContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir="/var/tmp/codex/ModSecurity-conector")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sources = self.root / "sources"
        for name in contract.SOURCE_PATHS:
            path = self.sources / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("source contract " + name)
        self.source_patch = patch.object(contract, "__file__", str(self.sources / "tests/runners/protocol_acceptance_contract.py"))
        self.source_patch.start()
        self.addCleanup(self.source_patch.stop)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir(mode=0o700)

    def evidence(self, protocol="h2", scenario="streaming"):
        run = "unit-run"
        case_id = next(key for key, value in contract.CASES.items()
                       if value["protocol"] == protocol and value["scenario"] == scenario)
        paths = {name: f"/acceptance/{run}/{name}" for name in ("target", "peer", "followup")}
        client, access, native, upstream = [], [], [], {}
        for index, (name, path) in enumerate(paths.items()):
            start, end = ((1, 7) if name == "target" else (2, 8) if name == "peer" else (9, 12))
            connection = 0
            server_connection = index + 10 if protocol == "h3" else 10
            stream = index * 4 if protocol == "h3" else 1 + index * 2
            rule = {"multiplex": "1100001", "phase3": "1100201", "safe": "1100301", "strict": "1100301"}.get(scenario) if name == "target" else None
            status = 403 if name == "target" and scenario in {"multiplex", "phase3"} else 200
            client.extend([
                {"event": "request_started", "name": name, "path": path, "monotonic_ns": start * 10**9},
                {"event": "debug_observation", "name": name, "stream_id": stream,
                 "conn_id": connection, "monotonic_ns": start * 10**9 + 1,
                 "observation": f"[HTTP/{3 if protocol == 'h3' else 2}] [{stream}] OPENED stream"},
            ])
            if scenario != "multiplex" or name != "target":
                data_time = 6 * 10**9 + 1 if name == "peer" and scenario in {"strict", "upstream-reset"} else (start + 2) * 10**9
                client.append({"event": "first_data", "name": name, "bytes": 8, "monotonic_ns": data_time})
            cancelled = name == "target" and scenario == "client-cancel"
            if cancelled:
                client.append({"event": "cancelled", "name": name, "method": "curl_multi_remove_handle", "peer_active": True})
            aborted = name == "target" and scenario in {"strict", "upstream-reset"}
            reset = f"HTTP/{3 if protocol == 'h3' else 2} stream {stream} reset by server (error 0x{102 if protocol == 'h3' else 2} INTERNAL_ERROR)"
            if aborted:
                client.append({"event": "debug_observation", "name": name, "debug_failure": reset, "monotonic_ns": 6 * 10**9})
            completion = {"event": "completed", "name": name, "status": status,
                           "curl_code": None if cancelled else 18 if aborted else 0,
                           "cancelled": cancelled, "error": reset if aborted else "",
                           "http_version": 30 if protocol == "h3" else 3,
                           "conn_id": connection, "monotonic_ns": end * 10**9}
            if aborted:
                completion["debug_failure"] = reset
            client.append(completion)
            tx = f"native-transaction-{index}"
            access.append({"uri": path, "transaction_id": tx, "status": status,
                           "protocol": "HTTP/3.0" if protocol == "h3" else "HTTP/2.0",
                           "alpn": "" if protocol == "h2c" else protocol,
                           "connection_id": str(server_connection), "transport_endpoint": "127.0.0.1:43210"})
            common = {"transaction_id": tx, "connector": "nginx", "integration_mode": contract.MODE,
                      "run_id": run, "transport_case_id": case_id, "connection_id": "nginx-" + str(server_connection),
                      "uri": path, "rule_id": "", "status": "ok"}
            if not (name == "target" and scenario == "multiplex"):
                native.append({**common, "event": "request_headers_complete"})
            if rule:
                phase = {"multiplex": 1, "phase3": 3, "safe": 4, "strict": 4}[scenario]
                native.append({**common, "event": "engine_decision" if phase == 1 else f"phase{phase}_intervention",
                               "phase": "request_headers" if phase == 1 else "response_headers" if phase == 3 else "response_body", "rule_id": rule,
                               "status": "blocked", "requested_action": "deny", "http_status": 403,
                               "actual_action": "log_only" if scenario == "safe" else "abort_connection" if scenario == "strict" else "" if phase == 1 else "deny",
                               "response_committed": scenario in {"safe", "strict"},
                               "headers_sent": scenario in {"safe", "strict"}, "original_http_status": 200,
                               "late_intervention": scenario in {"safe", "strict"},
                               "connection_aborted": scenario == "strict", "visible_http_status": status})
            native.append({**common, "event": "transaction_cleanup", "reason": "common_return=0;common_complete=1;native_cleanup_completed=1;error_class=none"})
            if name != "target" or scenario != "multiplex":
                upstream[path] = {"arrivals": 1, "eos_sent": True,
                                  "first_byte_observed_before_eos": True,
                                  "first_chunk_written_monotonic": start + 1,
                                  "released_monotonic": start + 4,
                                  "eos_monotonic": start + 5,
                                  "first_byte_observation": {"observed_bytes": 8, "upstream_paused": True,
                                      "eos_sent": False, "response_finished": False,
                                      "client_event_monotonic": start + 2, "observation_monotonic": start + 3}}
                if name == "target" and scenario == "upstream-reset":
                    upstream[path].update(eos_sent=False, upstream_aborted=True)
        if scenario in {"multiplex", "strict", "upstream-reset"}:
            peer_start = next(row for row in native if row["transaction_id"] == "native-transaction-1")
            native.remove(peer_start)
            native.insert(0, peer_start)
        data = {"client.jsonl": client, "access.jsonl": access, "native-events.jsonl": native,
                "upstream.json": {"paths": upstream, "driver_error": None, "peer_held_until_target_observed": True},
                "roles.json": {"master_uid": 0, "worker_uid": 65534},
                "cleanup.json": {"verified": True, "udp_listener_open": False, "upstream_stopped": True, "client_stopped": True},
                "quic.json": {"datagrams": []}}
        if scenario in {"strict", "upstream-reset"}:
            data["upstream.json"].update(peer_held_until_reset_observed=True,
                reset_observation={"peer_response_finished": False, "client_event_monotonic_ns": 6 * 10**9})
        if protocol == "h3":
            data["quic.json"] = {"datagrams": [{"direction": direction, "connection_id": "sha256:" + "e" * 64,
                                              "quic_version": "0x00000001"} for direction in ("request", "response")]}
        return case_id, run, data

    def write(self, case_id, run, data):
        data = copy.deepcopy(data)
        case = contract.CASES[case_id]
        rules = (self.sources / "tests/rules/protocol-acceptance.conf").read_bytes()
        if case["scenario"] == "multiplex":
            rules += b'\nSecRule REQUEST_URI "@endsWith /target" "id:1100001,phase:1,deny,status:403,log,t:none,msg:\'protocol acceptance P1\'"\n'
        data.setdefault("rules.conf", rules)
        config = (f'load_module "{self.bundle}/nginx-module.so"; modsecurity on; proxy_buffering off; http2 on; '
                  f'modsecurity_rules_file "{self.bundle}/rules.conf"; '
                  f'modsecurity_phase4_log "{self.bundle}/native-events.jsonl"; '
                  f'modsecurity_phase4_mode {"strict" if case["scenario"] == "strict" else "safe"}; '
                  f'listen 127.0.0.1:1234{"" if case["protocol"] == "h2c" else " ssl"}; '
                  + ('listen 127.0.0.1:1234 quic reuseport;' if case["protocol"] == "h3" else ''))
        data.setdefault("nginx.conf", config.encode())
        artifacts = {}
        for key, leaf in (("nginx_binary", "nginx-binary"), ("module", "nginx-module.so"), ("client_binary", "protocol-client")):
            raw = ("actual artifact fixture " + key).encode()
            (self.bundle / leaf).write_bytes(raw)
            artifacts[key] = contract.digest(raw)
        hashes = {}
        for leaf, value in data.items():
            raw = value if isinstance(value, bytes) else (
                "".join(json.dumps(row) + "\n" for row in value) if leaf.endswith(".jsonl")
                else json.dumps(value) + "\n").encode()
            (self.bundle / leaf).write_bytes(raw)
            hashes[leaf] = contract.digest(raw)
        receipt = {"schema_version": 1, "case_id": case_id, "run_id": run,
                   "protocol": case["protocol"], "scenario": case["scenario"], "profile": contract.MODE,
                   "parent_sha": "a" * 40, "framework_sha": "b" * 40, "mrts_sha": "c" * 40,
                   "artifact_sha256": artifacts,
                   "source_sha256": {name: contract.digest((self.sources / name).read_bytes()) for name in contract.SOURCE_PATHS},
                   "sha256": hashes}
        (self.bundle / "receipt.json").write_text(json.dumps(receipt) + "\n")
        return receipt

    def validate(self, protocol="h2", scenario="streaming"):
        case_id, run, data = self.evidence(protocol, scenario)
        self.write(case_id, run, data)
        return contract.validate_bundle(self.bundle, case_id, run)

    def test_registry_is_separate_and_strict_requires_server_reset(self):
        self.assertEqual(len(contract.CASES), 25)
        self.assertNotIn("h2_phase4_connection_abort_preparation", contract.CASES)
        self.assertEqual(contract.CASES["h2_phase4_strict"]["expectation"], "protocol_server_stream_reset")
        self.assertEqual(contract.CASES["h3_server_stream_reset"]["scenario"], "strict")
        self.assertEqual(contract.CASES["h2c_prior_knowledge_preparation"]["protocol"], "h2c")

    def test_all_preparation_cases_accept_consistent_evidence(self):
        for protocol, scenario in {(row["protocol"], row["scenario"]) for row in contract.CASES.values()}:
            with self.subTest(protocol=protocol, scenario=scenario):
                self.assertTrue(self.validate(protocol, scenario)["validated"])

    def test_corrupted_independent_witnesses_are_rejected(self):
        mutations = {
            "missing request": lambda d: d["client.jsonl"].pop(),
            "client writer failure": lambda d: d["client.jsonl"][0].update(debug_failure=True),
            "zero client cases": lambda d: d["client.jsonl"].clear(),
            "connection crossover": lambda d: d["client.jsonl"][7].update(conn_id=99),
            "stream crossover": lambda d: d["client.jsonl"][5].update(stream_id=1),
            "HTTP1 fallback": lambda d: d["client.jsonl"][3].update(http_version=2),
            "unexpected client error": lambda d: d["client.jsonl"][3].update(curl_code=23),
            "duplicated transaction": lambda d: d["access.jsonl"][1].update(transaction_id="native-transaction-0"),
            "server connection mismatch": lambda d: d["access.jsonl"][1].update(connection_id="99"),
            "server ALPN mismatch": lambda d: d["access.jsonl"][0].update(alpn="http/1.1"),
            "server status mismatch": lambda d: d["access.jsonl"][0].update(status=403),
            "native transaction crossover": lambda d: d["native-events.jsonl"][2].update(transaction_id="native-transaction-0"),
            "native stream mismatch": lambda d: d["native-events.jsonl"][0].update(stream_id="99"),
            "native connection mismatch": lambda d: d["native-events.jsonl"][0].update(connection_id="nginx-999"),
            "native request crossover": lambda d: d["native-events.jsonl"][0].update(uri="/wrong"),
            "rule crossover": lambda d: d["native-events.jsonl"][2].update(rule_id="1100301"),
            "missing cleanup": lambda d: d["native-events.jsonl"].pop(),
            "cleanup failed": lambda d: d["native-events.jsonl"][1].update(reason="native_cleanup_completed=0"),
            "cleanup token prefix": lambda d: d["native-events.jsonl"][1].update(reason="common_return=0;common_complete=1;native_cleanup_completed=10"),
            "native after cleanup": lambda d: d["native-events.jsonl"].append(copy.deepcopy(d["native-events.jsonl"][0])),
            "no overlap": lambda d: d["client.jsonl"][4].update(monotonic_ns=8 * 10**9),
            "queued rather than opened": lambda d: d["client.jsonl"][5].update(monotonic_ns=7 * 10**9),
            "early EOS": lambda d: d["upstream.json"]["paths"]["/acceptance/unit-run/target"]["first_byte_observation"].update(eos_sent=True),
            "fake first byte": lambda d: d["upstream.json"]["paths"]["/acceptance/unit-run/target"]["first_byte_observation"].update(client_event_monotonic=2),
            "upstream writer error": lambda d: d["upstream.json"]["paths"]["/acceptance/unit-run/peer"].update(writer_error="write failed"),
            "barrier absent": lambda d: d["upstream.json"].update(peer_held_until_target_observed=False),
            "driver error": lambda d: d["upstream.json"].update(driver_error="exception"),
            "missing upstream": lambda d: d["upstream.json"]["paths"].pop("/acceptance/unit-run/peer"),
            "false cleanup": lambda d: d["cleanup.json"].update(verified=False),
            "listener alive": lambda d: d["cleanup.json"].update(udp_listener_open=True),
            "threads alive": lambda d: d["cleanup.json"].update(upstream_stopped=False),
            "wrong roles": lambda d: d["roles.json"].update(worker_uid=0),
            "different effective rules": lambda d: d.update({"rules.conf": b"SecRuleEngine Off\n"}),
            "different effective config": lambda d: d.update({"nginx.conf": b"modsecurity off;\n"}),
        }
        for reason, mutate in mutations.items():
            with self.subTest(reason=reason):
                case_id, run, data = self.evidence()
                mutate(data)
                self.write(case_id, run, data)
                with self.assertRaises(ValueError):
                    contract.validate_bundle(self.bundle, case_id, run)

    def test_hash_source_and_external_identity_binding(self):
        case_id, run, data = self.evidence()
        receipt = self.write(case_id, run, data)
        self.assertTrue(contract.validate_bundle(self.bundle, case_id, run, {"parent_sha": receipt["parent_sha"]})["validated"])
        with self.assertRaises(ValueError):
            contract.validate_bundle(self.bundle, case_id, run, {"parent_sha": "f" * 40})
        (self.bundle / "access.jsonl").write_text("{}\n")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            contract.validate_bundle(self.bundle, case_id, run)
        self.write(case_id, run, data)
        (self.sources / "tests/rules/protocol-acceptance.conf").write_text("changed rules")
        with self.assertRaisesRegex(ValueError, "source hash mismatch"):
            contract.validate_bundle(self.bundle, case_id, run)

    def test_h2c_rejects_invented_tls_alpn(self):
        case_id, run, data = self.evidence("h2c", "multiplex")
        data["client.jsonl"].append({"event": "debug_observation", "name": "target", "alpn": "h2"})
        self.write(case_id, run, data)
        with self.assertRaisesRegex(ValueError, "ALPN"):
            contract.validate_bundle(self.bundle, case_id, run)

    def test_h3_requires_bidirectional_actual_quic(self):
        case_id, run, data = self.evidence("h3")
        data["quic.json"]["datagrams"].pop()
        self.write(case_id, run, data)
        with self.assertRaisesRegex(ValueError, "bidirectional"):
            contract.validate_bundle(self.bundle, case_id, run)

    def test_strict_native_action_remains_distinct_from_observed_reset(self):
        for actual in ("log_only", "reset_stream"):
            with self.subTest(action=actual):
                case_id, run, data = self.evidence(scenario="strict")
                next(row for row in data["native-events.jsonl"] if row["event"] == "phase4_intervention")["actual_action"] = actual
                self.write(case_id, run, data)
                with self.assertRaisesRegex(ValueError, "requested/actual"):
                    contract.validate_bundle(self.bundle, case_id, run)

    def test_h3_binds_transport_and_each_native_stream_separately(self):
        for corrupt in ("endpoint", "client connection", "native connection"):
            with self.subTest(corrupt=corrupt):
                case_id, run, data = self.evidence("h3")
                self.assertEqual(len({row["connection_id"] for row in data["access.jsonl"]}), 3)
                if corrupt == "endpoint":
                    data["access.jsonl"][1]["transport_endpoint"] = "127.0.0.1:43211"
                elif corrupt == "client connection":
                    data["client.jsonl"][7]["conn_id"] = 1
                else:
                    data["native-events.jsonl"][2]["connection_id"] = "nginx-10"
                self.write(case_id, run, data)
                with self.assertRaises(ValueError):
                    contract.validate_bundle(self.bundle, case_id, run)

    def test_strict_reset_must_be_observed_on_exact_target_stream(self):
        for protocol in ("h2", "h3"):
            for corrupt in ("wrong stream", "wrong protocol", "zero reset", "no source observation", "new connection", "peer failure", "target succeeded"):
                with self.subTest(protocol=protocol, corrupt=corrupt):
                    case_id, run, data = self.evidence(protocol, "strict")
                    target = next(row for row in data["client.jsonl"] if row["event"] == "completed" and row["name"] == "target")
                    source = next(row for row in data["client.jsonl"] if row["event"] == "debug_observation" and row.get("debug_failure"))
                    if corrupt in {"wrong stream", "wrong protocol", "zero reset"}:
                        old = source["debug_failure"]
                        if corrupt == "wrong stream":
                            new = re.sub(r"stream \d+ ", "stream 99 ", old)
                        elif corrupt == "wrong protocol":
                            new = old.replace("HTTP/2", "HTTP/3") if protocol == "h2" else old.replace("HTTP/3", "HTTP/2")
                        else:
                            new = re.sub(r"0x[0-9a-f]+", "0x0", old)
                        source["debug_failure"] = target["debug_failure"] = target["error"] = new
                    elif corrupt == "no source observation":
                        data["client.jsonl"].remove(source)
                    elif corrupt == "new connection":
                        next(row for row in data["client.jsonl"] if row["event"] == "completed" and row["name"] == "followup")["conn_id"] = 1
                    elif corrupt == "peer failure":
                        next(row for row in data["client.jsonl"] if row["event"] == "completed" and row["name"] == "peer")["curl_code"] = 18
                    else:
                        target["curl_code"] = 0
                    self.write(case_id, run, data)
                    with self.assertRaises(ValueError):
                        contract.validate_bundle(self.bundle, case_id, run)

    def test_native_multiplex_overlap_is_independent_of_queued_client_requests(self):
        case_id, run, data = self.evidence(scenario="multiplex")
        peer_start = data["native-events.jsonl"].pop(0)
        data["native-events.jsonl"].insert(2, peer_start)
        self.write(case_id, run, data)
        with self.assertRaisesRegex(ValueError, "did not overlap"):
            contract.validate_bundle(self.bundle, case_id, run)

    def test_upstream_reset_needs_original_abort_before_eos(self):
        for change in ({"upstream_aborted": False}, {"eos_sent": True}):
            with self.subTest(change=change):
                case_id, run, data = self.evidence(scenario="upstream-reset")
                data["upstream.json"]["paths"]["/acceptance/unit-run/target"].update(change)
                self.write(case_id, run, data)
                with self.assertRaises(ValueError):
                    contract.validate_bundle(self.bundle, case_id, run)

    def test_reset_requires_peer_active_in_client_native_and_upstream_witnesses(self):
        for scenario in ("strict", "upstream-reset"):
            for corrupt in ("peer completed early", "peer bytes early", "native peer created late", "unbound barrier", "peer response finished", "native peer cleaned early"):
                if scenario != "strict" and corrupt == "native peer cleaned early":
                    continue
                with self.subTest(scenario=scenario, corrupt=corrupt):
                    case_id, run, data = self.evidence(scenario=scenario)
                    if corrupt == "peer completed early":
                        next(row for row in data["client.jsonl"] if row["name"] == "peer" and row["event"] == "completed")["monotonic_ns"] = 5 * 10**9
                    elif corrupt == "peer bytes early":
                        next(row for row in data["client.jsonl"] if row["name"] == "peer" and row["event"] == "first_data")["monotonic_ns"] = 5 * 10**9
                    elif corrupt == "native peer created late":
                        peer_start = data["native-events.jsonl"].pop(0)
                        data["native-events.jsonl"].insert(3, peer_start)
                    elif corrupt == "native peer cleaned early":
                        cleanup = next(row for row in data["native-events.jsonl"] if row["transaction_id"] == "native-transaction-1" and row["event"] == "transaction_cleanup")
                        data["native-events.jsonl"].remove(cleanup)
                        data["native-events.jsonl"].insert(1, cleanup)
                    elif corrupt == "unbound barrier":
                        data["upstream.json"]["reset_observation"]["client_event_monotonic_ns"] = 7 * 10**9
                    else:
                        data["upstream.json"]["reset_observation"]["peer_response_finished"] = True
                    self.write(case_id, run, data)
                    with self.assertRaises(ValueError):
                        contract.validate_bundle(self.bundle, case_id, run)

    def test_partial_transfer_wire_status_must_match_original_committed_200(self):
        for scenario in ("strict", "upstream-reset", "client-cancel"):
            for status in (0, 403):
                for witness in ("client", "access", "both"):
                    with self.subTest(scenario=scenario, status=status, witness=witness):
                        case_id, run, data = self.evidence(scenario=scenario)
                        if witness in {"client", "both"}:
                            next(row for row in data["client.jsonl"] if row["name"] == "target" and row["event"] == "completed")["status"] = status
                        if witness in {"access", "both"}:
                            data["access.jsonl"][0]["status"] = status
                        self.write(case_id, run, data)
                        with self.assertRaises(ValueError):
                            contract.validate_bundle(self.bundle, case_id, run)

    def test_intervention_phase_and_commit_facts_are_source_bound(self):
        for scenario, changes in (("phase3", ({"phase": "response_body"}, {"response_committed": True}, {"headers_sent": True}, {"original_http_status": 403}, {"visible_http_status": 200})),
                                  ("safe", ({"phase": "response_headers"}, {"headers_sent": False})),
                                  ("strict", ({"phase": "response_headers"}, {"headers_sent": False}))):
            for change in changes:
                with self.subTest(scenario=scenario, change=change):
                    case_id, run, data = self.evidence(scenario=scenario)
                    next(row for row in data["native-events.jsonl"] if row["event"].endswith("_intervention")).update(change)
                    self.write(case_id, run, data)
                    with self.assertRaisesRegex(ValueError, "requested/actual"):
                        contract.validate_bundle(self.bundle, case_id, run)

    def test_unknown_case_and_cross_run_never_pass(self):
        case_id, run, data = self.evidence()
        self.write(case_id, run, data)
        with self.assertRaises(ValueError):
            contract.validate_bundle(self.bundle, "", run)
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            contract.validate_bundle(self.bundle, case_id, "other-run")


if __name__ == "__main__":
    unittest.main()
