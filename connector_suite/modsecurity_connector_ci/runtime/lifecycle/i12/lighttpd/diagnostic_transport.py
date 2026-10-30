#!/usr/bin/env python3
"""Independent bounded private-loopback client for explicit diagnostic wire cases."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import time

# Load the maintained Parent filesystem boundary from this checkout.
import sys as _i12_sys

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths

LIMIT = 131072


class Peer:
    def __init__(self, connection):
        self.connection = connection
        self.pending = bytearray()
        self.raw = bytearray()
        self.eof = False
        self.reset = False
        self.timeout = False
        self.chunks = []
        self.current_response = {}

    def receive(self):
        started = time.monotonic_ns()
        try:
            data = self.connection.recv(4096)
        except ConnectionResetError:
            self.reset = True
            raise
        except TimeoutError:
            self.timeout = True
            raise
        completed = time.monotonic_ns()
        self.chunks.append({"started_ns": started, "completed_ns": completed, "bytes": len(data)})
        if not data:
            self.eof = True
            return False
        self.pending.extend(data)
        self.raw.extend(data)
        if len(self.raw) > LIMIT:
            raise ValueError("Diagnostic responses exceed 128 KiB")
        return True

    def response(self):
        while b"\r\n\r\n" not in self.pending:
            if not self.receive():
                raise EOFError("Peer EOF before HTTP response headers")
        header, _, entity = self.pending.partition(b"\r\n\r\n")
        lines = header.decode("ascii").split("\r\n")
        protocol, status, *_ = lines[0].split()
        if protocol not in ("HTTP/1.0", "HTTP/1.1"):
            raise ValueError("Unexpected actual HTTP response protocol")
        fields = [line.split(":", 1) for line in lines[1:]]
        self.pending = bytearray(entity)
        self.current_response = {"status": int(status), "headers": fields, "actual_message_complete": False,
                                 "framing": "headers_observed_unresolved"}
        lengths = [value.strip() for name, value in fields if name.lower() == "content-length"]
        if any(name.lower() == "transfer-encoding" for name, _ in fields):
            raise ValueError("This diagnostic wire fixture requires identity/length framing")
        body, complete, framing = self.response_entity(lengths)
        return {"status": int(status), "headers": fields, "entity_bytes": len(body),
                "entity_sha256": hashlib.sha256(body).hexdigest(), "framing": framing,
                "actual_message_complete": complete}

    def response_entity(self, lengths):
        if lengths:
            if len(set(lengths)) != 1 or not lengths[0].isdigit():
                raise ValueError("Ambiguous actual Content-Length")
            size = int(lengths[0])
            if size > LIMIT:
                raise ValueError("Actual declared response exceeds 128 KiB")
            self.current_response["framing"] = "content_length"
            while len(self.pending) < size:
                if not self.receive():
                    break
            body = bytes(self.pending[:size])
            del self.pending[:size]
            complete = len(body) == size
            framing = "content_length"
        else:
            self.current_response["framing"] = "peer_eof_delimited"
            while self.receive():
                continue
            body = bytes(self.pending)
            self.pending.clear()
            complete = True
            framing = "peer_eof_delimited"
        return body, complete, framing


def abort_receipt(connection, peer, receipt):
    peer.receive()
    header, boundary, entity = peer.raw.partition(b"\r\n\r\n")
    first_line = header.split(b"\r\n", 1)[0].split()
    lengths = [line.split(b":", 1)[1].strip() for line in header.split(b"\r\n")[1:]
               if line.split(b":", 1)[0].lower() == b"content-length"]
    complete = bool(boundary and len(lengths) == 1 and lengths[0].isdigit()
                    and len(entity) == int(lengths[0]))
    receipt.update(status=int(first_line[1]) if boundary and len(first_line) >= 2 else None,
        headers=header.decode("ascii").split("\r\n")[1:] if boundary else [],
        entity_bytes=len(entity), entity_sha256=hashlib.sha256(entity).hexdigest(),
        actual_message_complete=complete, framing="intentional_client_reset_after_received_bytes",
        intentional_client_reset=True, actual_linger_option=[1, 0])
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    connection.close()
    receipt["actual_reset_socket_close_completed_ns"] = time.monotonic_ns()


def capture_request(connection, peer, sent_wire, identity, index, request):
    timeout = request.get("timeout_seconds", 3)
    if not 0 < timeout <= 3:
        raise ValueError("Declared client timeout must be bounded by three seconds")
    connection.settimeout(timeout)
    raw = bytes.fromhex(request["wire_hex"])
    if len(raw) > 65536:
        raise ValueError("Declared wire request exceeds 64 KiB")
    started = time.monotonic_ns()
    receipt = {"pid": os.getpid(), "uid": os.geteuid(), "gid": os.getegid(),
        "path": request["path"], "started_ns": started,
        "connection_identity": identity, "connection_reused": index > 0,
        "request_wire_bytes": len(raw), "request_wire_sha256": hashlib.sha256(raw).hexdigest(),
        "request_bytes": 0, "request_sha256": hashlib.sha256(b"").hexdigest(),
        "error": None}
    prior_chunks = len(peer.chunks)
    peer.current_response = {}
    try:
        connection.sendall(raw)
        sent_wire.extend(raw)
        receipt["request_sent_ns"] = time.monotonic_ns()
        if request.get("abort_after_first_receive") is True:
            abort_receipt(connection, peer, receipt)
        else:
            receipt.update(peer.response())
    except (OSError, EOFError, ValueError) as error:
        if peer.current_response:
            receipt.update(peer.current_response, entity_bytes=len(peer.pending),
                           entity_sha256=hashlib.sha256(peer.pending).hexdigest())
        receipt["error"] = {"type": type(error).__name__, "message": str(error)}
    receipt.update(completed_ns=time.monotonic_ns(), tcp_eof_observed=peer.eof,
        tcp_reset_observed=peer.reset, timeout_observed=peer.timeout,
        actual_socket_recv_chunks=peer.chunks[prior_chunks:])
    first = next((row for row in peer.chunks[prior_chunks:] if row["bytes"] > 0), None)
    if first:
        receipt["first_response_recv_completed_ns"] = first["completed_ns"]
    return receipt


def loopback_connection(port):
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Diagnostic client requires a valid loopback TCP port")
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection.settimeout(3)
        connection.connect(("127.0.0.1", port))
    except BaseException:
        connection.close()
        raise
    return connection


def capture(port, requests, output):
    output = i12_paths.output_path(output)
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Diagnostic client requires a valid loopback TCP port")
    if not 1 <= len(requests) <= 8:
        raise ValueError("Wire sequence requires one to eight declared requests")
    rows = []
    sent_wire = bytearray()
    with loopback_connection(port) as connection:
        connection.settimeout(3)
        peer = Peer(connection)
        identity = {"local": connection.getsockname(), "peer": connection.getpeername(), "pid": os.getpid()}
        for index, request in enumerate(requests):
            receipt = capture_request(connection, peer, sent_wire, identity, index, request)
            rows.append(receipt)
            if receipt["error"] or not receipt["actual_message_complete"]:
                break
        with output.with_suffix(".wire").open("xb") as stream:
            stream.write(peer.raw)
        with output.with_suffix(".request.wire").open("xb") as stream:
            stream.write(sent_wire)
    result = dict(rows[-1])
    result.update(all_requests=rows, prefix_receipts=rows[:-1], actual_client_socket_closed=True,
                  declared_requests=len(requests), completed_requests=len(rows))
    result["proposed_process_exit"] = 0 if len(rows) == len(requests) and all(not row["error"] and
        (row.get("actual_message_complete") or row.get("intentional_client_reset")) for row in rows) else 1
    with i12_paths.new_text(output) as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    return result["proposed_process_exit"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for path in (args.request, args.output):
        if path.resolve() != path.absolute() or not path.absolute().is_relative_to("/task"):
            raise ValueError("Transport fixtures require physical private task paths")
    if args.request.stat().st_size > 1048576 or args.output.exists():
        raise ValueError("Transport request must be bounded and output fresh")
    raise SystemExit(capture(args.port, json.loads(args.request.read_text())["raw_requests"], args.output))


if __name__ == "__main__":
    main()
