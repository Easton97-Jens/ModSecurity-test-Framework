"""File streaming HTTP adapters for the existing sealed Traefik host runner.

No host is started here. TCP EOF, HTTP EOS, native EOS, commit and client
delivery remain separate observations. No lifecycle qualification is inferred.
"""

import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sys
import time

if __package__:
    from .source import MAX_FILE, SourceFailure, stream_file
else:
    from connector_suite.adapters.traefik.harness.i12_file.source import MAX_FILE, SourceFailure, stream_file

MAX_WIRE = 1024 * 1024


def process_identity():
    """The parent must independently retain this process's actual wait status."""
    return {"pid": os.getpid(), "ppid": os.getppid(), "uid": os.getuid(),
            "gid": os.getgid(), "executable": sys.executable,
            "parent_wait_status_required": True}


def save_new(root, name, value):
    """Never overwrite a prior process receipt or raw transport artifact."""
    payload = value if isinstance(value, bytes) else (json.dumps(value, indent=2) + "\n").encode()
    fd = os.open(Path(root) / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)


def validate_key(key):
    if (not isinstance(key, str) or not 1 <= len(key) <= 100 or
            any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in key)):
        raise ValueError("literal bounded lowercase transaction key required")
    return key


def stream_chunks(connection, root, spec, receipt):
    """Each physical read becomes exactly one emitted HTTP chunk."""
    chunks = receipt.setdefault("http_chunks", [])

    def send(part, source_read):
        wire = f"{len(part):x}\r\n".encode() + part + b"\r\n"
        event = {"source_offset": source_read["offset"], "entity_bytes": len(part),
                 "entity_sha256": source_read["sha256"], "wire_bytes": len(wire),
                 "wire_sha256": hashlib.sha256(wire).hexdigest(), "started_ns": time.monotonic_ns()}
        chunks.append(event)
        connection.sendall(wire)
        event["sendall_returned_ns"] = time.monotonic_ns()
        event["remote_delivery_proven"] = False

    try:
        receipt["file_source"] = stream_file(root, spec, send)
    except SourceFailure as error:
        receipt["file_source"] = error.receipt
        raise
    # The terminator is emitted only after complete verified file reads/close.
    receipt["http_terminator_send_started_ns"] = time.monotonic_ns()
    receipt["http_terminator_wire_bytes"] = 5
    receipt["http_terminator_wire_sha256"] = hashlib.sha256(b"0\r\n\r\n").hexdigest()
    connection.sendall(b"0\r\n\r\n")
    receipt["http_terminator_sendall_returned_ns"] = time.monotonic_ns()


def receive_bounded(connection, received=None):
    data = bytearray() if received is None else received
    deadline = time.monotonic() + 15
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("bounded response receive deadline expired")
        connection.settimeout(remaining)
        block = connection.recv(min(8192, MAX_WIRE + 1 - len(data)))
        if not block:
            return bytes(data), True
        data.extend(block)
        if len(data) > MAX_WIRE:
            raise ValueError("bounded actual response exceeded")


def response_headers(raw):
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        raise ValueError("incomplete response headers")
    headers = {}
    for line in head.split(b"\r\n")[1:]:
        key, delimiter, value = line.partition(b":")
        if not delimiter or key.lower() in headers:
            raise ValueError("invalid or duplicate response header")
        headers[key.lower()] = value.strip()
    return headers, body


def chunked_entity(body):
    stream, wire = io.BytesIO(body), bytearray()
    entity = bytes(_chunked_request(stream, wire))
    if stream.read(1):
        raise ValueError("extra bytes after response terminator")
    return entity, "chunked"


def content_length_entity(headers, body):
    size = int(headers[b"content-length"])
    if size < 0 or len(body) != size:
        raise ValueError("response Content-Length mismatch")
    return body, "content-length"


def response_entity(raw):
    """Decode only completely observed bounded HTTP framing, without TCP inference."""
    headers, body = response_headers(raw)
    transfer = headers.get(b"transfer-encoding")
    if transfer is not None:
        if transfer != b"chunked" or b"content-length" in headers:
            raise ValueError("unsupported or ambiguous response framing")
        return chunked_entity(body)
    if b"content-length" in headers:
        return content_length_entity(headers, body)
    raise ValueError("explicit response framing required")


def request_client(port, key, private_root, file_spec, evidence_root, uri="/no-crs/request-body",
                   transaction_id=None):
    """Actual client process streams the regular file through the host's HTTP port."""
    validate_key(key)
    transaction_id = validate_key(key if transaction_id is None else transaction_id)
    if type(port) is not int or not 1 <= port <= 65535 or uri not in ("/no-crs/request-body", "/no-crs/allow"):
        raise ValueError("admitted loopback port and URI required")
    receipt = {"schema": "traefik-file-http-client-v1", "key": key, "pid": os.getpid(),
               "transaction_id": transaction_id, "process": process_identity(),
               "started_ns": time.monotonic_ns(), "native_eos": None, "native_file_api": False,
               "qualification": "unqualified", "tcp_eof": False}
    received = bytearray()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=15) as connection:
            connection.settimeout(15)
            receipt.update(local=list(connection.getsockname()), peer=list(connection.getpeername()))
            head = ("POST " + uri + " HTTP/1.1\r\nHost: example.test\r\nContent-Type: text/plain\r\n"
                    "X-Request-Id: " + transaction_id + "\r\nX-I12-Acceptance-Key: " + key +
                    "\r\nX-I12-Probe: " + key + "\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n").encode()
            save_new(evidence_root, key + ".request-head.raw", head)
            receipt.update(request_head_wire_bytes=len(head),
                           request_head_wire_sha256=hashlib.sha256(head).hexdigest(),
                           request_headers_send_started_ns=time.monotonic_ns())
            try:
                connection.sendall(head)
                receipt["request_headers_sendall_returned_ns"] = time.monotonic_ns()
                stream_chunks(connection, private_root, file_spec, receipt)
            except Exception as error:
                # A host may reject before the client finishes its upload. Its
                # actual response must still be read while this socket is open.
                receipt["upload_error"] = {"type": type(error).__name__, "message": str(error)[:256]}
                receipt["error"] = dict(receipt["upload_error"])
            receipt["upload_completed_ns"] = time.monotonic_ns()
            receipt["response_receive_started_ns"] = time.monotonic_ns()
            receipt["response_receive_budget_seconds"] = 15
            try:
                _, receipt["tcp_eof"] = receive_bounded(connection, received)
                receipt["response_completed_ns"] = time.monotonic_ns()
            except Exception as error:
                receipt["receive_error"] = {"type": type(error).__name__, "message": str(error)[:256]}
                receipt.setdefault("error", dict(receipt["receive_error"]))
            receipt["response_receive_finished_ns"] = time.monotonic_ns()
    except Exception as error:
        receipt["error"] = {"type": type(error).__name__, "message": str(error)[:256]}
    raw = bytes(received)
    # Preserve a physical prefix even when a later read/reset/timeout fails.
    save_new(evidence_root, key + ".response.raw", raw)
    head = raw.split(b"\r\n\r\n", 1)[0]
    receipt["response_headers_latin1"] = head.decode("latin1")
    try:
        receipt["actual_status"] = int(head.split(b"\r\n", 1)[0].split()[1])
    except (IndexError, ValueError):
        receipt["actual_status"] = None
    receipt.update(completed_ns=time.monotonic_ns(), client_response_wire_bytes=len(raw),
                   client_response_wire_sha256=hashlib.sha256(raw).hexdigest())
    try:
        entity, framing = response_entity(raw)
        save_new(evidence_root, key + ".response-entity.raw", entity)
        receipt.update(client_response_entity_bytes=len(entity),
                       client_response_entity_sha256=hashlib.sha256(entity).hexdigest(),
                       response_http_framing=framing, response_http_complete=True)
    except ValueError as error:
        receipt.update(response_http_complete=False, response_framing_error=str(error))
    save_new(evidence_root, key + ".client.json", receipt)
    return receipt


def _request_headers(stream, head=None):
    head = bytearray() if head is None else head
    while not head.endswith(b"\r\n\r\n"):
        part = stream.read(1)
        if not part or len(head) >= 32768:
            raise ValueError("incomplete or oversized request headers")
        head.extend(part)
    headers = {}
    for line in bytes(head).split(b"\r\n")[1:-2]:
        name, separator, value = line.partition(b":")
        token = b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if (not separator or not name or any(char not in token for char in name) or
                name.lower() in headers or b"\r" in value or b"\n" in value):
            raise ValueError("invalid or duplicate request header")
        headers[name.lower()] = value.strip(b" \t")
    return head, headers


def _wire_append(wire, part):
    if len(wire) + len(part) > MAX_WIRE:
        raise ValueError("bounded backend request wire exceeded")
    wire.extend(part)


def _exact(stream, wire, size):
    result = bytearray()
    while len(result) < size:
        part = stream.read(size - len(result))
        if not part:
            raise ValueError("short backend HTTP read")
        _wire_append(wire, part)
        result.extend(part)
    return bytes(result)


def _chunked_request(stream, wire):
    entity = bytearray()
    while True:
        line = stream.readline(128)
        _wire_append(wire, line)
        if not line.endswith(b"\r\n"):
            raise ValueError("incomplete HTTP chunk length")
        literal = line[:-2]
        if not literal or any(char not in b"0123456789abcdefABCDEF" for char in literal):
            raise ValueError("unsupported HTTP chunk length syntax")
        size = int(literal, 16)
        if not 0 <= size <= MAX_FILE - len(entity):
            raise ValueError("bounded backend request exceeded")
        if size == 0:
            if _exact(stream, wire, 2) != b"\r\n":
                raise ValueError("unsupported HTTP trailers")
            return entity
        entity.extend(_exact(stream, wire, size))
        if _exact(stream, wire, 2) != b"\r\n":
            raise ValueError("invalid HTTP chunk boundary")


class RequestFramingFailure(ValueError):
    """Retain the physically consumed wire prefix without declaring HTTP EOS."""

    def __init__(self, message, wire):
        super().__init__(message)
        self.wire = bytes(wire)


def _reject_available_trailing(connection):
    """Check only bytes already queued; never wait for peer EOF or later input."""
    previous_timeout = connection.gettimeout()
    try:
        connection.setblocking(False)
        try:
            extra = connection.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
        except BlockingIOError:
            extra = b""
        if extra:
            raise ValueError("unexpected immediately available trailing HTTP bytes")
    finally:
        connection.settimeout(previous_timeout)


def read_request(connection):
    """Bounded exact HTTP parser retaining raw request and entity hashes."""
    stream = connection.makefile("rb", buffering=0)
    wire = bytearray()
    try:
        _, headers = _request_headers(stream, wire)
        transfer = headers.get(b"transfer-encoding")
        if transfer is not None:
            if transfer != b"chunked" or b"content-length" in headers:
                raise ValueError("ambiguous HTTP body framing")
            entity = _chunked_request(stream, wire)
        else:
            literal = headers.get(b"content-length", b"0")
            if not literal or any(char not in b"0123456789" for char in literal):
                raise ValueError("invalid HTTP Content-Length")
            size = int(literal)
            if not 0 <= size <= MAX_FILE:
                raise ValueError("bounded backend request exceeded")
            entity = _exact(stream, wire, size)
        _reject_available_trailing(connection)
        return bytes(wire), bytes(entity), headers
    except Exception as error:
        raise RequestFramingFailure(str(error), wire) from error
    finally:
        stream.close()


def response_backend(port, key, private_root, file_spec, evidence_root, transaction_id=None):
    """Serve exactly one admitted target request; separate from healthy neighbors."""
    validate_key(key)
    transaction_id = validate_key(key if transaction_id is None else transaction_id)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("literal bounded loopback port required")
    receipt = {"schema": "traefik-file-http-backend-v1", "key": key, "pid": os.getpid(),
               "transaction_id": transaction_id, "process": process_identity(),
               "local": ["127.0.0.1", port],
               "started_ns": time.monotonic_ns(), "native_eos": None, "native_file_api": False,
               "qualification": "unqualified", "independent_backend_accept_count": 0}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.settimeout(30)
            listener.bind(("127.0.0.1", port))
            listener.listen(1)
            save_new(evidence_root, key + ".backend-listening.json", {"pid": os.getpid(), "port": port,
                                                                     "monotonic_ns": time.monotonic_ns()})
            connection, peer = listener.accept()
            receipt.update(independent_backend_accept_count=1, peer=list(peer), accepted_ns=time.monotonic_ns())
            # Persist physical accept even if the HTTP body or file subsequently fails.
            save_new(evidence_root, key + ".backend-accept.json", dict(receipt))
            with connection:
                connection.settimeout(15)
                try:
                    wire, entity, headers = read_request(connection)
                except RequestFramingFailure as error:
                    save_new(evidence_root, key + ".backend-request.raw", error.wire)
                    receipt.update(request_wire_bytes=len(error.wire),
                                   request_wire_sha256=hashlib.sha256(error.wire).hexdigest(),
                                   request_http_framing_valid=False)
                    raise
                receipt["observed_correlation"] = {
                    name.decode(): headers.get(name, b"").decode("latin1")
                    for name in (b"x-request-id", b"x-i12-acceptance-key", b"x-i12-probe")}
                save_new(evidence_root, key + ".backend-request.raw", wire)
                receipt.update(request_wire_bytes=len(wire), request_wire_sha256=hashlib.sha256(wire).hexdigest(),
                               request_body_bytes=len(entity), request_body_sha256=hashlib.sha256(entity).hexdigest(),
                               request_http_framing_valid=True,
                               request_trailing_check="no-immediately-available-bytes",
                               request_http_eos_ns=time.monotonic_ns())
                if (headers.get(b"x-request-id") != transaction_id.encode() or
                        headers.get(b"x-i12-acceptance-key") != key.encode()):
                    raise ValueError("backend request missing exact transaction/file-key pair")
                head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                save_new(evidence_root, key + ".backend-response-head.raw", head)
                receipt.update(response_head_wire_bytes=len(head), response_head_wire_sha256=hashlib.sha256(head).hexdigest(),
                               backend_headers_send_started_ns=time.monotonic_ns())
                connection.sendall(head)
                receipt["backend_headers_sendall_returned_ns"] = time.monotonic_ns()
                stream_chunks(connection, private_root, file_spec, receipt)
    except Exception as error:
        receipt["error"] = {"type": type(error).__name__, "message": str(error)[:256]}
    receipt["completed_ns"] = time.monotonic_ns()
    save_new(evidence_root, key + ".backend.json", receipt)
    return receipt
