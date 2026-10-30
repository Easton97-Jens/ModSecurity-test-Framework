#!/usr/bin/env python3
"""Bounded raw-socket proof for a prematurely closed HTTP/1.1 response."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import threading
import time
from typing import Final

DECLARED_LENGTH: Final = 64
SENT_BODY: Final = b"short"
SCHEMA_VERSION: Final = 1
MAX_RECEIPT_BYTES: Final = 65536


class ProbeFailure(RuntimeError):
    """The bounded frontend/upstream exchange did not meet the contract."""


def _safe_receipt_path(runtime_root: Path, path: Path) -> Path:
    runtime_root = Path(os.path.abspath(runtime_root))
    if not path.is_absolute() or path.name in ("", ".", ".."):
        raise ProbeFailure("receipt path must be absolute and have a filename")
    if runtime_root != runtime_root.resolve(strict=True) or path != Path(os.path.abspath(path)):
        raise ProbeFailure("runtime root and receipt path must be normalized and have no symlink")
    try:
        root_details = runtime_root.stat()
    except OSError as exc:
        raise ProbeFailure("trusted runtime root cannot be inspected") from exc
    if not stat.S_ISDIR(root_details.st_mode) or root_details.st_uid != os.geteuid() or stat.S_IMODE(root_details.st_mode) != 0o700:
        raise ProbeFailure("trusted runtime root must be an owned private 0700 directory")
    if path.parent != runtime_root:
        raise ProbeFailure("receipt must be a direct child of the trusted runtime root")
    if path.is_symlink():
        raise ProbeFailure("receipt must not be a symbolic link")
    return path


def _write_receipt(runtime_root: Path, path: Path, payload: bytes) -> None:
    """Create a fresh receipt through a held private runtime-root descriptor."""
    path = _safe_receipt_path(runtime_root, path)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if not getattr(os, "O_DIRECTORY", 0) or not no_follow:
        raise ProbeFailure("private receipt writes require directory and no-follow support")
    try:
        parent_fd = os.open(path.parent, directory_flags)
    except OSError as exc:
        raise ProbeFailure("receipt parent could not be opened as a private runtime root") from exc
    try:
        parent = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
            raise ProbeFailure("receipt parent changed or is not a private runtime root")
        try:
            descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow, 0o600, dir_fd=parent_fd)
        except OSError as exc:
            raise ProbeFailure("receipt must be a fresh non-symlink file") from exc
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
    finally:
        os.close(parent_fd)


def _loopback_port(value: int) -> int:
    if type(value) is not int or not 1024 <= value <= 65535:
        raise ProbeFailure("network port must be an unprivileged TCP port")
    return value


def _loopback_host(value: str) -> str:
    if value != "127.0.0.1":
        raise ProbeFailure("probe network host must be IPv4 loopback")
    return value


def _read_request(connection: socket.socket, expected_path: str, deadline: float) -> None:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeFailure("upstream request-header deadline expired")
        connection.settimeout(remaining)
        chunk = connection.recv(4096)
        if not chunk:
            raise ProbeFailure("frontend closed before upstream request headers")
        data.extend(chunk)
        if len(data) > 65536:
            raise ProbeFailure("frontend request headers exceeded 65536 bytes")
    request_line = bytes(data).split(b"\r\n", 1)[0].split()
    if len(request_line) != 3 or request_line[0] != b"GET" or request_line[1].decode("ascii", "strict") != expected_path or request_line[2] != b"HTTP/1.1":
        raise ProbeFailure("upstream received a request that does not correlate to the probe path")


def _serve_truncated_upstream(
    host: str,
    port: int,
    expected_path: str,
    nonce: str,
    deadline: float,
    receipt: dict[str, object],
    ready: threading.Event,
) -> None:
    host = _loopback_host(host)
    port = _loopback_port(port)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(1)
        listener.settimeout(max(0.01, deadline - time.monotonic()))
        receipt["upstream_bound"] = True
        ready.set()
        try:
            connection, peer = listener.accept()
        except TimeoutError as exc:
            raise ProbeFailure("upstream accept deadline expired") from exc
        with connection:
            _read_request(connection, expected_path, deadline)
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: 64\r\n"
                + b"X-Msconnector-Backend-Close-Nonce: "
                + nonce.encode("ascii")
                + b"\r\n"
                b"Connection: close\r\n\r\n"
                + SENT_BODY
            )
            connection.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                connection.sendall(response)
            except (socket.timeout, TimeoutError) as exc:
                raise ProbeFailure("upstream send deadline expired") from exc
            connection.shutdown(socket.SHUT_WR)
            receipt.update(
                {
                    "upstream_peer": "%s:%s" % peer[:2],
                    "declared_content_length": DECLARED_LENGTH,
                    "body_bytes_sent": len(SENT_BODY),
                    "upstream_nonce_sha256": hashlib.sha256(nonce.encode("ascii")).hexdigest(),
                    "upstream_shutdown_write": True,
                    "upstream_closed": True,
                }
            )
            connection.close()
        receipt["upstream_connection_closed"] = True
    receipt["upstream_listener_closed"] = True


def _read_frontend_bytes(connection: socket.socket, deadline: float) -> tuple[bytes, str, bool]:
    received = bytearray()
    read_error = ""
    frontend_eof = False
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeFailure("frontend read timed out; truncation is not promoted")
        connection.settimeout(remaining)
        try:
            chunk = connection.recv(4096)
        except (socket.timeout, TimeoutError) as exc:
            raise ProbeFailure("frontend read timed out; truncation is not promoted") from exc
        except OSError as exc:
            if exc.errno not in (errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE):
                raise ProbeFailure("frontend read failed with an unapproved socket error") from exc
            read_error = f"{type(exc).__name__}:{exc.errno}"
            break
        if not chunk:
            frontend_eof = True
            break
        received.extend(chunk)
        if len(received) > 131072:
            raise ProbeFailure("frontend response exceeded bounded receipt limit")
    return bytes(received), read_error, frontend_eof


def _header_value(lines: list[bytes], name: bytes, description: str) -> bytes:
    values = [line.split(b":", 1)[1].strip() for line in lines[1:] if line.lower().startswith(name)]
    if len(values) != 1:
        raise ProbeFailure(f"frontend response must contain exactly one {description}")
    return values[0]


def _parse_frontend_response(received: bytes, expected_nonce: str) -> tuple[int, int, bytes, str, str]:
    header_end = received.find(b"\r\n\r\n")
    if header_end < 0:
        raise ProbeFailure("frontend response headers were incomplete")
    lines = received[:header_end].split(b"\r\n")
    status_parts = lines[0].split()
    if len(status_parts) != 3 or status_parts[0] != b"HTTP/1.1":
        raise ProbeFailure("frontend response status line was invalid")
    try:
        status = int(status_parts[1])
    except ValueError as exc:
        raise ProbeFailure("frontend response status was invalid") from exc
    try:
        content_length = int(_header_value(lines, b"content-length:", "Content-Length"))
    except ValueError as exc:
        raise ProbeFailure("frontend Content-Length was invalid") from exc
    try:
        frontend_nonce = _header_value(lines, b"x-msconnector-backend-close-nonce:", "backend-close nonce").decode("ascii", "strict")
    except UnicodeDecodeError as exc:
        raise ProbeFailure("frontend backend-close nonce was not ASCII") from exc
    try:
        host_transaction_id = _header_value(lines, b"x-msconnector-host-transaction-id:", "host transaction ID").decode("ascii", "strict")
    except UnicodeDecodeError as exc:
        raise ProbeFailure("frontend host transaction ID was not ASCII") from exc
    if not host_transaction_id or len(host_transaction_id) > 128 or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-" for character in host_transaction_id):
        raise ProbeFailure("frontend host transaction ID was outside the bounded format")
    body = received[header_end + 4 :]
    if status != 200 or content_length != DECLARED_LENGTH or body != SENT_BODY or frontend_nonce != expected_nonce:
        raise ProbeFailure("frontend response did not match the correlated 200/64/5 fixture")
    return status, content_length, body, frontend_nonce, host_transaction_id


def _read_frontend(host: str, port: int, path: str, expected_nonce: str, deadline: float, receipt: dict[str, object]) -> None:
    host = _loopback_host(host)
    port = _loopback_port(port)
    with socket.create_connection((host, port), timeout=max(0.01, deadline - time.monotonic())) as connection:
        connection.settimeout(max(0.01, deadline - time.monotonic()))
        connection.sendall(
            ("GET %s HTTP/1.1\r\nHost: backend-close-probe\r\nConnection: close\r\n\r\n" % path).encode("ascii")
        )
        received, read_error, frontend_eof = _read_frontend_bytes(connection, deadline)
        status, content_length, body, frontend_nonce, host_transaction_id = _parse_frontend_response(received, expected_nonce)
        if not frontend_eof and not read_error:
            raise ProbeFailure("frontend completed without EOF or read error")
        receipt.update(
            {
                "frontend_eof": frontend_eof,
                "frontend_read_error": read_error or None,
                "frontend_response_bytes": len(received),
                "frontend_status": status,
                "frontend_content_length": content_length,
                "frontend_body_bytes": len(body),
                "frontend_body_sha256": hashlib.sha256(body).hexdigest(),
                "frontend_body_matches_fixture": body == SENT_BODY,
                "frontend_nonce_sha256": hashlib.sha256(frontend_nonce.encode("ascii")).hexdigest(),
                "frontend_nonce_matches_upstream": frontend_nonce == expected_nonce,
                "host_transaction_id": host_transaction_id,
                "host_transaction_id_sha256": hashlib.sha256(host_transaction_id.encode("ascii")).hexdigest(),
                "frontend_observed_before_host_stop": True,
            }
        )


def _validate_run_arguments(args: argparse.Namespace) -> None:
    if args.timeout <= 0 or args.timeout > 30:
        raise ProbeFailure("timeout must be between 0 and 30 seconds")
    if not args.path.startswith("/") or any(ch in args.path for ch in "\r\n"):
        raise ProbeFailure("path must be an HTTP origin-form path")
    args.frontend_host = _loopback_host(args.frontend_host)
    args.upstream_host = _loopback_host(args.upstream_host)
    args.frontend_port = _loopback_port(args.frontend_port)
    args.upstream_port = _loopback_port(args.upstream_port)
    args.receipt = _safe_receipt_path(args.runtime_root, args.receipt)


def _await_upstream_ready(
    args: argparse.Namespace,
    nonce: str,
    deadline: float,
    receipt: dict[str, object],
) -> tuple[threading.Thread, list[Exception]]:
    failure: list[Exception] = []
    ready = threading.Event()

    def serve() -> None:
        try:
            _serve_truncated_upstream(
                args.upstream_host,
                args.upstream_port,
                args.path,
                nonce,
                deadline,
                receipt,
                ready,
            )
        except Exception as exc:
            failure.append(exc)

    thread = threading.Thread(target=serve, name="backend-close-upstream", daemon=True)
    thread.start()
    while not ready.is_set():
        if failure:
            thread.join(max(0.0, deadline - time.monotonic()))
            raise ProbeFailure(str(failure[0])) from failure[0]
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            thread.join(0.0)
            raise ProbeFailure("upstream listener did not become ready by deadline")
        ready.wait(min(0.01, remaining))
    return thread, failure


def _validate_run_receipt(receipt: dict[str, object], thread: threading.Thread, failure: list[Exception]) -> None:
    if thread.is_alive():
        raise ProbeFailure("upstream server thread did not terminate by deadline")
    if failure:
        raise ProbeFailure(str(failure[0])) from failure[0]
    if not receipt.get("upstream_closed") or not receipt.get("upstream_connection_closed"):
        raise ProbeFailure("upstream connection close receipt missing")
    if not receipt.get("upstream_listener_closed"):
        raise ProbeFailure("upstream listener close receipt missing")
    if not receipt.get("frontend_observed_before_host_stop"):
        raise ProbeFailure("frontend observation was not retained before host stop")
    if not receipt.get("frontend_nonce_matches_upstream"):
        raise ProbeFailure("frontend nonce did not match the raw upstream nonce")


def run(args: argparse.Namespace) -> dict[str, object]:
    _validate_run_arguments(args)
    deadline = time.monotonic() + args.timeout
    nonce = secrets.token_hex(24)
    receipt: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "evidence_type": "lighttpd_backend_close_raw_socket",
        "frontend_host": args.frontend_host,
        "frontend_port": args.frontend_port,
        "upstream_host": args.upstream_host,
        "upstream_port": args.upstream_port,
        "path": args.path,
        "nonce_sha256": hashlib.sha256(nonce.encode("ascii")).hexdigest(),
    }
    thread, failure = _await_upstream_ready(args, nonce, deadline, receipt)
    try:
        _read_frontend(args.frontend_host, args.frontend_port, args.path, nonce, deadline, receipt)
    finally:
        thread.join(max(0.0, deadline - time.monotonic()))
    _validate_run_receipt(receipt, thread, failure)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontend-host", default="127.0.0.1")
    parser.add_argument("--frontend-port", type=int, required=True)
    parser.add_argument("--upstream-host", default="127.0.0.1")
    parser.add_argument("--upstream-port", type=int, required=True)
    parser.add_argument("--path", default="/p4/close/")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run(args)
        payload = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if len(payload) > MAX_RECEIPT_BYTES:
            raise ProbeFailure("receipt exceeds bounded size")
        _write_receipt(args.runtime_root, args.receipt, payload)
        print("lighttpd_backend_close_probe: PASS receipt=%s" % args.receipt)
        return 0
    except (ProbeFailure, OSError, ValueError) as exc:
        print("lighttpd_backend_close_probe: FAIL %s" % exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
