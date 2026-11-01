#!/usr/bin/env python3
"""Real sequential HTTP/1 exchanges on one owned socket, with explicit framing.

Socket inode/endpoints and every principal/subsequent request are retained.
Response framing is drained before the next send. A strict-path fresh socket
is explicitly new and never relabelled as reused. This helper issues no PASS.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import sys
import time


paths = load_tool('ci/runtime/lifecycle/apache-i12/paths.py')




MAX_RESPONSE = 16 * 1024 * 1024
MIN_PRIVATE_PORT = 1024
MAX_PORT = 65535
REQUEST_JSON = "request.json"
CASES = frozenset(("multiple_sequential_requests", "keep_alive_requests_if_supported",
                  "transport_keep_alive", "transport_sequential_requests", "keepalive_allow_allow",
                  "keepalive_allow_deny_allow", "keepalive_safe_followup",
                  "keepalive_after_strict_new_connection", "NEED-neighbor-connection-stream"))
DENY_SEQUENCES = frozenset(("multiple_sequential_requests", "keep_alive_requests_if_supported",
                            "transport_sequential_requests", "keepalive_allow_deny_allow"))


def save(path, value):
    with paths.new_text(path) as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def prepare_plan(original):
    plan = copy.deepcopy(original)
    if plan["case_id"] not in CASES:
        return plan
    plan["execution_variant"] = {"kind": "real_http11_socket_sequence", "does_not_change_original_oracle": True,
        "source": "Original catalog sequence and Apache KeepAlive host configuration; native decisions measured separately"}
    plan["driver_seams"] = [x for x in plan.get("driver_seams", []) if x != "raw_connection_sequence_transaction_join"]
    if plan["case_id"] == "NEED-neighbor-connection-stream":
        def encoded(data):
            import base64
            return {"encoding": "base64", "data": base64.b64encode(data).decode(), "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest()}
        pieces = [b"Apache-I12-concurrent-prefix\n", b"Apache-I12-concurrent-suffix\n"]
        plan["backend"].update(body=encoded(b"".join(pieces)), chunks=[encoded(x) for x in pieces], framing="chunked",
            barrier={"after_chunk": 1, "release_condition": "independent_neighbor_process_completed_after_main_prefix",
                     "timeout_seconds": 8})
        plan["execution_variant"]["kind"] = "independent_neighbor_while_principal_backend_paused"
    return plan


def sequence_requests(plan):
    principal = copy.deepcopy(plan["request"])
    token = next(value for name, value in principal["headers"] if name.lower() == "x-i12-id")
    healthy = copy.deepcopy(principal)
    healthy.update(method="GET", path="/followup", chunks=[], framing="content_length", peer_action="normal")
    healthy["body"] = {"encoding": "base64", "data": "", "bytes": 0,
                       "sha256": hashlib.sha256(b"").hexdigest()}
    healthy["headers"] = [["X-I12-ID", token + "-sequence-followup"]]
    steps = [{"label": "main", "request": principal}]
    if plan["case_id"] in DENY_SEQUENCES:
        denied = copy.deepcopy(healthy)
        denied["path"] = "/no-crs/deny"
        denied["headers"] = [["X-I12-ID", token + "-sequence-deny"], ["X-Modsec-Smoke", "block"]]
        steps.append({"label": "sequence-deny", "request": denied})
    if plan["case_id"] != "NEED-neighbor-connection-stream":
        steps.append({"label": "sequence-followup", "request": healthy})
    return steps


class IncompleteResponse(ValueError):
    pass


def parse_header(header):
    lines = header.decode("iso-8859-1").split("\r\n")
    status = lines[0].split()
    if len(status) < 2 or status[0] not in ("HTTP/1.0", "HTTP/1.1") or not status[1].isdecimal():
        raise ValueError("invalid keepalive status line")
    fields = []
    for line in lines[1:]:
        if ":" not in line:
            raise ValueError("invalid keepalive response header")
        name, value = line.split(":", 1)
        fields.append((name.lower(), value.strip()))
    lengths = [value for name, value in fields if name == "content-length"]
    transfer = [value.lower() for name, value in fields if name == "transfer-encoding"]
    if lengths and transfer or len(lengths) > 1:
        raise ValueError("ambiguous keepalive response framing")
    if lengths and (not lengths[0].isascii() or not lengths[0].isdecimal()):
        raise ValueError("invalid keepalive response length")
    if transfer and transfer != ["chunked"]:
        raise ValueError("unsupported keepalive response transfer encoding")
    connection = ",".join(value.lower() for name, value in fields if name == "connection")
    reusable = "close" not in connection and (status[0] == "HTTP/1.1" or "keep-alive" in connection)
    return {"status": int(status[1]), "headers": lines, "content_lengths": lengths,
            "transfer_encoding": transfer, "connection_reusable_by_headers": reusable}


class ResponseReader:
    def __init__(self, connection, prefix_callback=None):
        self.connection = connection
        self.pending = bytearray()
        self.prefix_callback = prefix_callback
        self.exchange = None

    def receive(self):
        before = time.monotonic_ns()
        try:
            data = self.connection.recv(65536)
        except ConnectionResetError:
            self.exchange["tcp_reset_observed"] = True
            raise
        after = time.monotonic_ns()
        self.exchange["recv_operations"].append({"started_ns": before, "completed_ns": after, "bytes": len(data)})
        if not data:
            self.exchange.update(tcp_eof_observed=True, eof_ns=after)
            return False
        self.pending.extend(data)
        if len(self.pending) > MAX_RESPONSE:
            raise ValueError("keepalive response capture exceeded bound")
        return True

    def need(self, count):
        if count > MAX_RESPONSE:
            raise ValueError("keepalive frame exceeds bound")
        while len(self.pending) < count:
            if not self.receive():
                raise IncompleteResponse("server EOF before response framing complete")

    def delimiter(self, delimiter, maximum):
        while True:
            index = self.pending.find(delimiter)
            if index >= 0:
                if index > maximum:
                    raise ValueError("keepalive delimiter exceeded bound")
                return index
            if len(self.pending) > maximum or not self.receive():
                raise IncompleteResponse("missing keepalive response delimiter")

    def prefix(self):
        if self.prefix_callback is not None and not self.exchange.get("first_entity_byte_received_ns"):
            self.exchange["first_entity_byte_received_ns"] = time.monotonic_ns()
            self.prefix_callback()

    def chunk_size(self, cursor):
        while b"\r\n" not in self.pending[cursor:]:
            if not self.receive():
                raise IncompleteResponse("server EOF in chunk size")
        end = self.pending.index(b"\r\n", cursor)
        size_text = bytes(self.pending[cursor:end]).split(b";", 1)[0]
        if not size_text or any(c not in b"0123456789abcdefABCDEF" for c in size_text):
            raise ValueError("invalid keepalive chunk size")
        return int(size_text, 16), end + 2

    def chunk_trailers(self, cursor):
        self.need(cursor + 2)
        if self.pending[cursor:cursor + 2] == b"\r\n":
            return cursor + 2
        while b"\r\n\r\n" not in self.pending[cursor:]:
            if len(self.pending) - cursor > 65536 or not self.receive():
                raise IncompleteResponse("server EOF in chunk trailers")
        return self.pending.index(b"\r\n\r\n", cursor) + 4

    def chunked(self, body_start):
        cursor, pieces, total = body_start, [], 0
        while True:
            length, cursor = self.chunk_size(cursor)
            if length == 0:
                return self.chunk_trailers(cursor), b"".join(pieces)
            if total + length > MAX_RESPONSE:
                raise ValueError("keepalive decoded entity exceeds bound")
            self.need(cursor + 1)
            self.prefix()
            self.need(cursor + length + 2)
            if self.pending[cursor + length:cursor + length + 2] != b"\r\n":
                raise ValueError("invalid keepalive chunk delimiter")
            pieces.append(bytes(self.pending[cursor:cursor + length]))
            cursor += length + 2
            total += length

    def content_length(self, body_start, length):
        if length:
            self.need(body_start + 1)
            self.prefix()
        self.need(body_start + length)
        return body_start + length, bytes(self.pending[body_start:body_start + length])

    def final_header(self):
        interim = []
        for _ in range(9):
            header_end = self.delimiter(b"\r\n\r\n", 65536)
            parsed = parse_header(bytes(self.pending[:header_end]))
            if not 100 <= parsed["status"] < 200 or parsed["status"] == 101:
                break
            interim.append(parsed)
            del self.pending[:header_end + 4]
        else:
            raise ValueError("too many interim HTTP responses")
        return header_end, parsed, interim

    def response_entity(self, request_method, parsed, start):
        if request_method == "HEAD" or parsed["status"] in (204, 304):
            return start, b"", "no_entity"
        if parsed["transfer_encoding"]:
            end, body = self.chunked(start)
            return end, body, "chunked"
        if parsed["content_lengths"]:
            end, body = self.content_length(start, int(parsed["content_lengths"][0]))
            return end, body, "content_length"
        if not parsed["connection_reusable_by_headers"]:
            while self.receive():
                if len(self.pending) > start:
                    self.prefix()
            return len(self.pending), bytes(self.pending[start:]), "close_delimited"
        raise ValueError("unframed response cannot be reused")

    def read_response(self, request_method="GET"):
        self.exchange = {"started_ns": time.monotonic_ns(), "recv_operations": [],
                         "tcp_eof_observed": False, "tcp_reset_observed": False,
                         "status": None, "framing_complete": False, "error": None}
        header_end, parsed, interim = self.final_header()
        self.exchange.update(parsed, interim_responses=interim)
        end, body, kind = self.response_entity(request_method, parsed, header_end + 4)
        raw = bytes(self.pending[:end])
        del self.pending[:end]
        self.exchange.update(completed_ns=time.monotonic_ns(), framing_complete=True,
            framing=kind, entity_bytes=len(body), entity_sha256=hashlib.sha256(body).hexdigest())
        return dict(self.exchange), raw, body


def connection_identity(connection):
    return {"fd": connection.fileno(), "socket_inode": os.fstat(connection.fileno()).st_ino,
            "local_endpoint": list(connection.getsockname()), "peer_endpoint": list(connection.getpeername()),
            "observed_ns": time.monotonic_ns()}


def send_exchange(reader, step, target, port, wire_request):
    request = step["request"]
    target.mkdir(mode=0o700)
    head, chunks = wire_request(request, port)
    ending = b"Connection: close\r\n\r\n"
    if not head.endswith(ending):
        raise ValueError("unexpected parent wire-client connection contract")
    head = head[:-len(ending)] + b"Connection: keep-alive\r\n\r\n"
    raw = head + b"".join(chunks)
    save(target / REQUEST_JSON, request)
    (target / "request.raw").write_bytes(raw)
    receipt = {"label": step["label"], "pid": os.getpid(), "socket": connection_identity(reader.connection),
               "request_id": next(v for k, v in request["headers"] if k.lower() == "x-i12-id"),
               "request_send_completed_ns": None, "response": None, "error": None}
    response_raw = b""
    reader.exchange = None
    try:
        reader.connection.sendall(raw)
        receipt["request_send_completed_ns"] = time.monotonic_ns()
        response, response_raw, body = reader.read_response(request["method"])
        receipt["response"] = response
        (target / "response.body").write_bytes(body)
    except (OSError, ValueError) as error:
        response_raw = bytes(reader.pending)
        receipt["response"] = reader.exchange
        receipt["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        (target / "response.raw").write_bytes(response_raw)
        save(target / "receipt.json", receipt)
    return receipt


def concurrent_neighbor(plan, output, port, backend_root):
    """Complete a separately waited client while the main backend is paused."""
    target = output / "concurrent-neighbor"
    target.mkdir(mode=0o700)
    release = target / "own-release"
    release.mkdir(mode=0o700)
    request = sequence_requests(plan)[0]["request"]
    request = copy.deepcopy(request)
    token = next(v for k, v in request["headers"] if k.lower() == "x-i12-id")
    request.update(method="GET", path="/neighbor", chunks=[], framing="content_length", peer_action="normal",
                   body={"encoding": "base64", "data": "", "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()})
    request["headers"] = [["X-I12-ID", token + "-concurrent-neighbor"]]
    save(target / REQUEST_JSON, request)
    command = ["rtk", "proxy", sys.executable, str(Path(__file__).with_name("batch.py")),
        "--client-spec", str(target / REQUEST_JSON), "--output", str(target),
        "--port", str(port), "--backend-root", str(release)]
    result = {"argv": command, "pid": None, "waited_exit": None,
              "started_ns": time.monotonic_ns(), "main_release_ns": None}
    process = None
    try:
        with (target / "stdout").open("xb") as stdout, (target / "stderr").open("xb") as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
            result["pid"] = process.pid
            process.wait(timeout=12)
    except subprocess.TimeoutExpired:
        result["timeout"] = True
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        result["waited_exit"] = process.returncode if process is not None else None
        result["completed_ns"] = time.monotonic_ns()
        result["receipt"] = str(target / "receipt.json")
        # The child writes only its OWN release path. This main barrier is
        # released after the independent process has actually terminated.
        (backend_root / "client-first-body-received.release").touch(mode=0o600)
        result["main_release_ns"] = time.monotonic_ns()
        save(target / "actual-process.json", result)
    return result


def sequence_complete(plan, summary):
    wanted = len(sequence_requests(plan))
    if len(summary["steps"]) != wanted or summary.get("error"):
        return False
    strict = plan["case_id"] == "keepalive_after_strict_new_connection"
    if not all(sequence_step_complete(step, strict and index == 0, summary)
               for index, step in enumerate(summary["steps"])):
        return False
    neighbor = summary.get("concurrent_neighbor")
    return neighbor is not None and neighbor.get("waited_exit") == 0 if plan["case_id"] == "NEED-neighbor-connection-stream" else True


def sequence_step_complete(step, strict_first, summary):
    if step["request_send_completed_ns"] is None:
        return False
    if strict_first:
        return bool(summary["server_close_before_fresh_socket"])
    return not step["error"] and bool((step["response"] or {}).get("framing_complete"))


def private_loopback_port(value):
    if isinstance(value, bool):
        port = None
    elif isinstance(value, str) and value.isascii() and value.isdecimal():
        port = int(value, 10)
    elif isinstance(value, int):
        port = value
    else:
        port = None
    if port is None or not MIN_PRIVATE_PORT <= port <= MAX_PORT:
        raise ValueError("private loopback port is outside the admitted range")
    return port


def open_sequence_connection(plan, output, port, backend_root, summary):
    connection = socket.create_connection(("127.0.0.1", private_loopback_port(port)), timeout=10)
    connection.settimeout(10)
    summary["connections"].append(connection_identity(connection))
    callback = None
    if plan["case_id"] == "NEED-neighbor-connection-stream":
        def observe_neighbor():
            summary["concurrent_neighbor"] = concurrent_neighbor(plan, output, port, backend_root)
        callback = observe_neighbor
    return connection, ResponseReader(connection, callback)


def select_sequence_connection(connection, reader, fresh, plan, args, summary):
    if connection is None or fresh:
        if connection is not None:
            connection.close()
        return open_sequence_connection(plan, args.output, args.port, args.backend_root, summary)
    return connection, reader


def stop_sequence(result, strict, index, summary):
    response = result.get("response") or {}
    if strict and index == 0:
        summary["server_close_before_fresh_socket"] = bool(
            response.get("tcp_eof_observed") or response.get("tcp_reset_observed"))
    if result["error"] and not (strict and index == 0):
        return True
    if not strict and not response.get("connection_reusable_by_headers", False):
        summary["sequence_stopped_reason"] = "server response forbids connection reuse"
        return True
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=private_loopback_port, required=True)
    parser.add_argument("--backend-root", type=Path, required=True)
    args = parser.parse_args()
    batch = load_source(Path(__file__).with_name('batch.py'))
    plan = prepare_plan(json.loads(args.spec.read_text()))
    strict = plan["case_id"] == "keepalive_after_strict_new_connection"
    summary = {"pid": os.getpid(), "case_id": plan["case_id"], "steps": [], "connections": [],
               "server_close_before_fresh_socket": None, "outcome": None, "full_lifecycle_qualification": None}
    connection = reader = None
    try:
        for index, step in enumerate(sequence_requests(plan)):
            connection, reader = select_sequence_connection(
                connection, reader, strict and index == 1, plan, args, summary)
            result = send_exchange(reader, step, args.output / step["label"], args.port, batch.wire_request)
            summary["steps"].append(result)
            if stop_sequence(result, strict, index, summary):
                break
    except (OSError, ValueError) as error:
        summary["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if connection is not None:
            connection.close()
        summary["client_closed_owned_sockets_ns"] = time.monotonic_ns()
        summary["planned_request_count"] = len(sequence_requests(plan))
        summary["actual_requests_sent_count"] = sum(step["request_send_completed_ns"] is not None for step in summary["steps"])
        summary["executed_requested_sequence"] = sequence_complete(plan, summary)
        save(args.output / "sequence-receipt.json", summary)
    return 0 if summary["executed_requested_sequence"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
