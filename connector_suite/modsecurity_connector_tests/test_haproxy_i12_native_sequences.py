"""Component checks only: never start HAProxy or qualify lifecycle evidence."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import json
from pathlib import Path
import sys
from unittest import mock

import pytest

HARNESS = connector_root() / "connectors/haproxy/harness"

sequences = load_source(HARNESS / 'i12_native_sequences.py')


def wire(status, body):
    return f"HTTP/1.1 {status} result\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body


@pytest.mark.parametrize("label", ["NEED-allow", sequences.PREFIX + "allow"])
def test_sequence_identity_accepts_only_known_original_base_versions(label):
    launch = "MSCONNECTOR_LIFECYCLE_CASE=" + repr(label) + "\nreceipt={'selected_id':" + repr(sequences.PREFIX + "allow") + "}"
    for name in sequences.CASE_NAMES:
        changed = sequences.bind_launch_identity(launch, {"original_id": sequences.PREFIX + "allow"}, name)
        assert changed.count("MSCONNECTOR_LIFECYCLE_CASE=" + repr(sequences.PREFIX + name)) == 1
        assert changed.count("'selected_id':" + repr(sequences.PREFIX + name)) == 1


@pytest.mark.parametrize("launch,original", [
    ("MSCONNECTOR_LIFECYCLE_CASE='NEED-allow'", "wrong"),
    ("MSCONNECTOR_LIFECYCLE_CASE='unknown'", sequences.PREFIX + "allow"),
    ("MSCONNECTOR_LIFECYCLE_CASE='NEED-allow'\nMSCONNECTOR_LIFECYCLE_CASE='NEED-allow'", sequences.PREFIX + "allow"),
    ("MSCONNECTOR_LIFECYCLE_CASE='NEED-allow'\nMSCONNECTOR_LIFECYCLE_CASE='" + sequences.PREFIX + "allow'", sequences.PREFIX + "allow"),
    ("MSCONNECTOR_LIFECYCLE_CASE='NEED-allow'\nMSCONNECTOR_LIFECYCLE_CASE='unknown'", sequences.PREFIX + "allow"),
    ("MSCONNECTOR_LIFECYCLE_CASE='NEED-allow'\n'selected_id':'" + sequences.PREFIX + "allow'\n'selected_id':'" + sequences.PREFIX + "allow'", sequences.PREFIX + "allow"),
])
def test_sequence_identity_rejects_unbound_or_ambiguous_anchors(launch, original):
    with pytest.raises(ValueError):
        sequences.bind_launch_identity(launch, {"original_id": original}, sequences.CASE_NAMES[0])


class Socket:
    def __init__(self, chunks):
        self.chunks = iter(chunks)
        self.writes = []
        self.closed = False
        self.close_calls = 0

    def recv(self, unused):
        return next(self.chunks, b"")

    def sendall(self, data):
        self.writes.append(data)

    def close(self):
        self.closed = True
        self.close_calls += 1

    def fileno(self):
        return 12

    def getsockname(self):
        return ("127.0.0.1", 43123)

    def getpeername(self):
        return ("127.0.0.1", 18490)

    def version(self):
        return "TLSv1.3"


def test_fragmented_body_and_surplus_are_distinct_responses():
    first = wire(200, b"a")
    second = wire(403, b"deny")
    connection = Socket([first[:12], first[12:] + second])
    actual, pending = sequences.read_response(connection)
    assert actual["status"] == 200
    assert actual["response_sha256"] == sequences.sha(b"a")
    assert pending == second
    denied, pending = sequences.read_response(connection, pending)
    assert denied["status"] == 403
    assert denied["response_bytes"] == 4
    assert pending == b""


@pytest.mark.parametrize("raw", [
    b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\na",
    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na",
    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\na",
    b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n",
])
def test_incomplete_ambiguous_or_unbounded_framing_rejected(raw):
    connection = Socket([raw])
    with pytest.raises((ValueError, EOFError)):
        sequences.read_response(connection)


def test_keepalive_uses_one_socket_for_three_distinct_responses(tmp_path):
    expected = sequences.expected_sequence()
    connection = Socket([wire(row["status"], body) for row, body in zip(
        expected, [sequences.ALLOW_BODY, sequences.DENY_BODY, sequences.ALLOW_BODY])])
    contract = {"same_tls_socket_required": True, "sequence": expected}
    with mock.patch.object(sequences.ssl, "create_default_context"), \
            mock.patch.object(sequences, "connect", return_value=connection) as connect:
        assert sequences.drive("main", tmp_path, contract) == 0
    assert connect.call_count == 1
    assert len(connection.writes) == 3
    assert connection.writes[1].startswith(b"GET /no-crs/deny HTTP/1.1")
    assert all(b"Connection: keep-alive" in request for request in connection.writes)
    actual = json.loads((tmp_path / "main-client.json").read_text())
    assert [row["status"] for row in actual["requests"]] == [200, 403, 200]
    assert {row["socket"]["connection_serial"] for row in actual["requests"]} == {1}
    assert actual["full_lifecycle_pass"] is None
    assert connection.closed


def test_closed_keepalive_is_retained_without_reconnect(tmp_path):
    expected = sequences.expected_sequence()
    connection = Socket([wire(200, sequences.ALLOW_BODY), b""])
    with mock.patch.object(sequences.ssl, "create_default_context"), \
            mock.patch.object(sequences, "connect", return_value=connection) as connect:
        assert sequences.drive("main", tmp_path, {"same_tls_socket_required": True, "sequence": expected}) == 1
    actual = json.loads((tmp_path / "main-client.json").read_text())
    assert connect.call_count == 1
    assert actual["connections_opened"] == 1
    assert actual["error"]["type"] == "EOFError"
    assert actual["error"]["no_reconnect_attempted"] is True
    assert actual["full_lifecycle_pass"] is None
    assert connection.close_calls == 1


def test_independent_surplus_rejects_after_exactly_one_socket_close(tmp_path):
    expected = sequences.expected_sequence()
    connection = Socket([wire(200, sequences.ALLOW_BODY) + b"unexpected"])
    with mock.patch.object(sequences.ssl, "create_default_context"), \
            mock.patch.object(sequences, "connect", return_value=connection) as connect:
        result = sequences.drive("main", tmp_path, {"same_tls_socket_required": False,
                                                    "sequence": expected})
    assert result == 1
    assert connect.call_count == 1
    assert connection.close_calls == 1
    actual = json.loads((tmp_path / "main-client.json").read_text())
    assert actual["error"]["type"] == "ValueError"
    assert actual["error"]["message"] == "unexpected bytes after independently closed response"
    assert len(actual["requests"]) == 1
    assert actual["full_lifecycle_pass"] is None


def test_sequential_independent_connections(tmp_path):
    bodies = [sequences.ALLOW_BODY, sequences.DENY_BODY, sequences.ALLOW_BODY]
    sockets = [Socket([wire(status, body)]) for status, body in zip([200, 403, 200], bodies)]
    with mock.patch.object(sequences.ssl, "create_default_context"), \
            mock.patch.object(sequences, "connect", side_effect=sockets) as connect:
        assert sequences.drive("main", tmp_path, {"same_tls_socket_required": False,
                                                   "sequence": sequences.expected_sequence()}) == 0
    assert connect.call_count == 3
    assert all(item.closed for item in sockets)
    assert all(item.close_calls == 1 for item in sockets)


def test_native_join_retains_actual_extra_free_and_missing_finish():
    client = {"requests": [{"index": 0, "started_wall_ns": 10, "completed_wall_ns": 20}]}
    allocated = {"function": "host_allocation", "edge": "return", "result": 1,
                 "wall_ns": 15, "allocation_scope_call": 4}
    freed = {"function": "native_cleanup", "edge": "return", "allocation_scope_call": 4}
    actual = sequences.join_native(client, [allocated, freed, freed])
    assert actual["requests"][0]["actual_return_counts"]["native_cleanup"] == 2
    assert actual["requests"][0]["actual_return_counts"]["common_finish"] == 0
    assert actual["full_lifecycle_pass"] is None
    with pytest.raises(ValueError, match="ambiguous"):
        sequences.join_native(client, [allocated, dict(allocated, allocation_scope_call=5)])
    absent = sequences.join_native(client, [])
    assert absent["requests"][0]["actual_allocation"] is None

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
