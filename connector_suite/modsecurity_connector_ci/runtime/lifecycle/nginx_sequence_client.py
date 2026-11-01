"""Bounded real HTTP/1.1 sequence client with no implicit reconnect."""
from __future__ import annotations

import http.client
import hashlib
import re
import socket
import time


def capture_http11_wire(port, path):
    """Retain bounded actual socket bytes; the independent parser proves framing."""
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("wire probe port must be an unprivileged local port")
    if not isinstance(path, str) or not re.fullmatch(r"/no-crs/sequence/[A-Za-z0-9_/-]{1,128}", path):
        raise ValueError("wire probe path is outside the closed safe fixture")
    request = f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode("ascii")
    raw = bytearray()
    deadline = time.monotonic() + 3
    with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
        connection.sendall(request)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("bounded raw HTTP/1.1 capture deadline exceeded")
            connection.settimeout(remaining)
            part = connection.recv(min(4096, 32769 - len(raw)))
            if not part:
                return request, bytes(raw)
            raw.extend(part)
            if len(raw) > 32768:
                raise ValueError("bounded raw HTTP/1.1 capture exceeded the wire limit")


def validate_sequence_inputs(port, paths, statuses):
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("sequence port must be an unprivileged local port")
    if len(paths) != len(statuses) or not 1 <= len(paths) <= 3:
        raise ValueError("sequence requires one to three bounded requests")
    if any(not isinstance(path, str) or not re.fullmatch(r"/no-crs/sequence/[A-Za-z0-9_/-]{1,128}", path) for path in paths):
        raise ValueError("sequence path is outside the closed safe fixture")
    if any(type(status) is not int or status not in (200, 403, 500, 504) for status in statuses):
        raise ValueError("sequence only supports defined allow/deny operations")


def sequence_request(path, expected, keepalive):
    connection_header = "keep-alive" if keepalive else "close"
    deny_header = "X-Modsec-Smoke: block\r\n" if expected == 403 else ""
    fault_header = "X-Modsec-Test-Transaction: " + "x" * 128 + "\r\n" if expected == 500 else ""
    return (f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
            f"Connection: {connection_header}\r\n{deny_header}{fault_header}\r\n").encode("ascii")


def read_response_body(response, body_limit, abort_allowed, declared):
    aborted = False
    try:
        body = response.read(body_limit + 1)
        if abort_allowed and declared is not None and len(body) < declared:
            aborted = True
    except http.client.IncompleteRead as exc:
        if not abort_allowed:
            raise
        body = exc.partial
        aborted = True
    if len(body) > body_limit or not response.isclosed():
        raise ValueError("response is not a bounded complete HTTP message")
    return body, aborted


def observe_response(connection, index, path, *, headers_seen, expect_first_abort, backpressure):
    response = http.client.HTTPResponse(connection, method="GET")
    response.begin()
    declared = response.length
    framing = "chunked" if response.chunked else "content_length"
    if headers_seen is not None:
        headers_seen(index)
    if backpressure and index == 0:
        time.sleep(0.25)
    body_limit = 262144 if backpressure else 65536
    abort_allowed = expect_first_abort and index == 0
    body, aborted = read_response_body(response, body_limit, abort_allowed, declared)
    observation = {"path": path, "observed_status": response.status,
                   "bytes_received": len(body), "body_sha256": hashlib.sha256(body).hexdigest(),
                   "http_version": response.version, "declared_length": declared,
                   "framing": framing, "client_error": "incomplete_read" if aborted else None,
                   "transport_result": "connection_aborted" if aborted else "completed"}
    if abort_allowed and (not aborted or not body or (declared is None and framing != "chunked")):
        raise ValueError("strict abort requires observed partial declared framing")
    close = response.will_close
    response.close()
    return observation, close


def run_sequence(port, paths, statuses, *, keepalive, headers_seen=None, expect_first_abort=False, backpressure=False):
    validate_sequence_inputs(port, paths, statuses)
    connection = None
    observations = []
    try:
        for index, (path, expected) in enumerate(zip(paths, statuses)):
            if connection is None:
                connection = socket.socket()
                if backpressure:
                    connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                connection.settimeout(3)
                connection.connect(("127.0.0.1", port))
            connection.sendall(sequence_request(path, expected, keepalive))
            observation, close = observe_response(connection, index, path, headers_seen=headers_seen,
                                                  expect_first_abort=expect_first_abort, backpressure=backpressure)
            observations.append(observation)
            if close and keepalive and len(observations) != len(paths):
                raise ValueError("server closed the connection before sequence completion")
            if not keepalive:
                connection.close()
                connection = None
        return observations
    finally:
        if connection is not None:
            connection.close()
