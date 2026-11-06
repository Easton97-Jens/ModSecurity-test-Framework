"""Cross-process claim and lifecycle corruption controls for real SPOP/H2."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import socket
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "adapters/haproxy/harness/haproxy_spop_h2_acceptance.py"
SPEC = importlib.util.spec_from_file_location("spop_h2_acceptance", PATH)
ADAPTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADAPTER)


class SPOPHTTP2AcceptanceTests(unittest.TestCase):
    def test_failed_port_reservation_starts_no_upstream_listener(self):
        allocated = []

        class Upstream:
            def __init__(self, scenario, paths):
                self.listener = socket.socket()
                self.listener.bind(("127.0.0.1", 0))
                self.listener.listen()
                self.stop = threading.Event()
                allocated.append(self)

            def serve_forever(self):
                self.stop.wait(3)

        shared = SimpleNamespace(SCENARIOS={"allow": "streaming"},
                                 STREAM=SimpleNamespace(Upstream=Upstream))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = SimpleNamespace()
            try:
                with patch.object(ADAPTER.subprocess, "run"), patch.object(
                        ADAPTER, "free_port", side_effect=OSError("reservation failed")):
                    with self.assertRaisesRegex(OSError, "reservation failed"):
                        ADAPTER.run_case(args, "allow", root / "case", root / "socket", shared)
            finally:
                for upstream in allocated:
                    upstream.stop.set()
                    upstream.listener.close()
            self.assertEqual(allocated, [], "a failed reservation created a live upstream")

    def test_native_runtime_root_rejects_traversal_links_and_existing_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "owned"
            self.assertEqual(ADAPTER.reserve_runtime_root(candidate), candidate)
            self.assertEqual(candidate.stat().st_mode & 0o777, 0o700)
            (candidate / "sentinel").write_text("retained")
            with self.assertRaises(ValueError):
                ADAPTER.reserve_runtime_root(candidate)
            self.assertEqual((candidate / "sentinel").read_text(), "retained")
            traversal = root / ".." / "forbidden-runtime-root"
            with self.assertRaises(ValueError):
                ADAPTER.reserve_runtime_root(traversal)
            link = root / "link"
            link.symlink_to(candidate, target_is_directory=True)
            linked_child = link / "child"
            with self.assertRaises(ValueError):
                ADAPTER.reserve_runtime_root(linked_child)
            self.assertFalse((candidate / "child").exists())

    def fixture(self):
        access, native, agent, decisions, sent = [], [], [], [], []
        for index, (role, stream) in enumerate((("peer", 1), ("target", 3), ("followup", 5)), 1):
            transaction = f"{index:08x}-0000-4000-8000-000000000000"
            handle_hash = str(index) * 64
            htx = f"haproxy-htx-{index}"
            uri = "/acceptance/spop-allow/" + role
            access.append({"uri": uri, "transaction_id": htx, "spop_transaction_id": transaction,
                           "status": 200, "http_major": 2, "alpn": "h2", "client_port": 12345})
            sent.append({"stream_id": stream, "path": uri})
            native.extend((f"modsecurity-htx-test: cleanup transaction_id={htx} native_released=1 companion_closed=1",
                           f"modsecurity-htx-test: claim transaction_id={htx} handle_sha256={handle_hash}"))
            agent.extend((f"spop-h2-test: event=cleanup transaction_id={transaction} native_cleanup_returned=1 contract_cleared=1",
                          f"spop-h2-test: event=handoff transaction_id={transaction} handle_sha256={handle_hash} lease={index}",
                          f"spop-h2-test: event=claim transaction_id=none handle_sha256={handle_hash} lease={index}"))
            decisions.append({"transaction_id": transaction, "modsecurity_processed": True})
        wire = {"alpn": "h2", "tls_verified": True, "tls_version": "TLSv1.3", "body_bytes": {"1": 26, "3": 26, "5": 26}, "status": {str(value): 200 for value in (1, 3, 5)},
                "frames": [{"type": 0, "stream_id": 3, "size": 18, "monotonic_ns": 20}],
                "terminal": {str(value): {"type": 0, "flags": 1} for value in (1, 3, 5)}, "requests": sent}
        upstream = {"first_byte_before_eos": True, "first_byte_observation": {"stream_id": 3, "wire_data_monotonic_ns": 20,
                    "monotonic_ns": 25, "target_eos_held": True, "target_eos_sent": False, "target_response_finished": False},
                    "paths": {"/acceptance/spop-allow/target": {"first_chunk_written_monotonic": 0.00000001, "released_monotonic": 0.00000003}}, "driver_error": None, "target_cleanup_before_peer_release": True, "all_cleanup_before_tls_close": True}
        cleanup = {"verified": True, "socket_removed": True, "tls_removed": True}
        return ["allow", wire, access, "\n".join(native), "\n".join(agent), decisions, upstream, cleanup]

    def test_actual_three_role_cross_process_join(self):
        self.assertEqual(ADAPTER.validate_case(*self.fixture())["status"], "PASS")

    def test_early_spop_deny_retires_unclaimed_context_without_inventing_lease(self):
        args = self.fixture()
        args[0] = "phase1"
        args[1]["body_bytes"]["3"] = 0
        args[1]["status"]["3"] = 403
        args[2][1]["status"] = 403
        args[5][1]["rule_id"] = 1100001
        args[5][1]["phase"] = 1
        target = args[2][1]["spop_transaction_id"]
        args[3] = "\n".join(line for line in args[3].splitlines() if "transaction_id=haproxy-htx-2 " not in line)
        args[3] += "\nmodsecurity-htx-test: context_detached host_stream_id=2 handle_present=0 native_released=1 companion_closed=0"
        args[4] = "\n".join(line for line in args[4].splitlines() if not
                            (f"event=handoff transaction_id={target}" in line or
                             "event=claim transaction_id=none handle_sha256=" + "2" * 64 in line))
        self.assertEqual(ADAPTER.validate_case(*args)["status"], "PASS")
        args[3] = args[3].replace("handle_present=0", "handle_present=1")
        with self.assertRaises(ValueError):
            ADAPTER.validate_case(*args)

    def test_owner_eos_rule_and_independent_host_action_are_required(self):
        for case, action in (("phase4_safe", "log_only"), ("phase4_strict", "abort_connection")):
            args = self.fixture()
            args[0] = case
            args[1]["body_bytes"]["3"] = 45 if case == "phase4_safe" else 18
            owner = args[2][1]["spop_transaction_id"]
            args[4] += f"\nspop-h2-test: event=owner_eos transaction_id={owner} phase=4 rule_id=1100301 status=403 disruptive=1"
            args[3] += f"\nmodsecurity-htx: response-companion phase-4 intervention; transaction_id=haproxy-htx-2 rule_id= requested=deny host_action={action}"
            if case == "phase4_strict":
                args[1]["terminal"]["3"] = {"type": 3, "reset_code": 8}
            self.assertEqual(ADAPTER.validate_case(*args)["status"], "PASS")
            for old, new in (("rule_id=1100301", "rule_id=1100302"),
                             (f"transaction_id={owner} phase=4", "transaction_id=foreign phase=4"),
                             ("status=403 disruptive=1", "status=200 disruptive=0")):
                corrupted = deepcopy(args)
                corrupted[4] = corrupted[4].replace(old, new)
                with self.subTest(case=case, old=old), self.assertRaises(ValueError):
                    ADAPTER.validate_case(*corrupted)
            duplicate = deepcopy(args)
            duplicate[4] += "\n" + args[4].splitlines()[-1]
            with self.assertRaises(ValueError):
                ADAPTER.validate_case(*duplicate)
            missing_host = deepcopy(args)
            missing_host[3] = "\n".join(args[3].splitlines()[:-1])
            with self.assertRaises(ValueError):
                ADAPTER.validate_case(*missing_host)

    def test_handle_lease_and_cleanup_corruption_fail_closed(self):
        for field, old, replacement in ((3, "handle_sha256=" + "2" * 64, "handle_sha256=" + "9" * 64),
                                        (4, "lease=2", "lease=99"),
                                        (4, "native_cleanup_returned=1", "native_cleanup_returned=0"),
                                        (3, "companion_closed=1", "companion_closed=0")):
            with self.subTest(field=field, old=old):
                args = self.fixture()
                args[field] = args[field].replace(old, replacement, 1)
                with self.assertRaises(ValueError):
                    ADAPTER.validate_case(*args)

    def test_safe_requires_normal_eos_bodies_and_first_byte_barrier(self):
        args = self.fixture(); args[0] = "phase4_safe"; args[1]["body_bytes"]["3"] = 45
        owner = args[2][1]["spop_transaction_id"]
        args[4] += f"\nspop-h2-test: event=owner_eos transaction_id={owner} phase=4 rule_id=1100301 status=403 disruptive=1"
        args[3] += "\nmodsecurity-htx: response-companion phase-4 intervention; transaction_id=haproxy-htx-2 rule_id= requested=deny host_action=log_only"
        self.assertEqual(ADAPTER.validate_case(*args)["status"], "PASS")
        for mutation in (lambda a: a[1]["terminal"].update({"3": {"type": 3, "reset_code": 8}}),
                         lambda a: a[1].update(body_bytes={}), lambda a: a[1]["body_bytes"].update({"3": 0}),
                         lambda a: a[6].pop("first_byte_before_eos"),
                         lambda a: a[6]["first_byte_observation"].update(wire_data_monotonic_ns=99),
                         lambda a: a[6]["paths"]["/acceptance/spop-allow/target"].update(released_monotonic=0.000000015), lambda a: a[1]["terminal"]["3"].update(flags=0)):
            corrupted = deepcopy(args); mutation(corrupted)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                ADAPTER.validate_case(*corrupted)

    def test_real_wire_file_writer_failure_closes_socket_and_retains_failure(self):
        from tests.runners.native_h2_probe import StatusDecoder, WireClient
        left, right = socket.socketpair()
        class TLSWrapper:
            def version(self): return "TLSv1.3"
            def close(self): left.close()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "wire.json"
            output.write_text("existing writer record")
            client = WireClient.__new__(WireClient)
            client.socket = TLSWrapper(); client.decoder = StatusDecoder(); client.output = output
            client.records = []; client.bytes = {}; client.terminal = {}; client.sent = []; client.status = {}
            try:
                error = ADAPTER.close_wire(client, None)
                self.assertIn("wire evidence writer failed", error)
                self.assertEqual(left.fileno(), -1)
                self.assertEqual(output.read_text(), "existing writer record")
            finally:
                right.close()

    def test_reused_cross_process_handle_is_rejected(self):
        args = self.fixture()
        args[3] = args[3].replace("2" * 64, "1" * 64)
        args[4] = args[4].replace("2" * 64, "1" * 64)
        with self.assertRaises(ValueError):
            ADAPTER.validate_case(*args)

    def test_protocol_status_foreign_transactions_and_late_cleanup_fail_closed(self):
        mutations = [lambda args: args[1]["status"].update({"3": 403}),
                     lambda args: args[2][0].update(alpn="http/1.1"),
                     lambda args: args[2][2].update(client_port=12346),
                     lambda args: args[5][1].update(modsecurity_processed=False),
                     lambda args: args[6].update(target_cleanup_before_peer_release=False),
                     lambda args: args[6].update(all_cleanup_before_tls_close=False),
                     lambda args: args[7].update(socket_removed=False),
                     lambda args: args[1]["requests"].pop()]
        for mutation in mutations:
            args = deepcopy(self.fixture())
            mutation(args)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                ADAPTER.validate_case(*args)


if __name__ == "__main__":
    unittest.main()
