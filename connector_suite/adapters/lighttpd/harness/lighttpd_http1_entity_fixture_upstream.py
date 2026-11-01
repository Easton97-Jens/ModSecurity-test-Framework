#!/usr/bin/env python3
"""Serve bounded HTTP/1.1 entity-body fixtures for patched lighttpd.

The daemon sends one Content-Length response and one chunked response.  Each
body contains the canonical Phase-4 marker across separate upstream writes,
but it writes only counts and transport metadata to its control artifacts.
It is deliberately HTTP/1.1-only and does not persist either response body.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import sys
import time
from typing import Callable, Final, Protocol

from adapters.lighttpd.harness.safe_runtime_output import safe_output_path, verified_runtime_output_root, write_text_atomic


CONTENT_LENGTH_PATH: Final = "/p4/fixture/content-length"
CHUNKED_PATH: Final = "/p4/fixture/chunked"

# Keep the marker split across distinct upstream entity writes.  The harness
# checks the patched host's final entity-byte counters, while the core patch
# contract guarantees a borrowed callback before later socket write retries.
CONTENT_LENGTH_PARTS: Final = (
    b"lighttpd-content-length-prefix:",
    b"no-crs-response-",
    b"body-marker",
)
CHUNKED_PARTS: Final = (
    b"lighttpd-chunked-prefix:",
    b"no-crs-response-",
    b"body-marker",
)
READY_FILE_LABEL: Final = "ready file"
RESULT_FILE_LABEL: Final = "result file"


class FixtureError(RuntimeError):
    """A bounded fixture exchange could not be completed."""


def write_json(root: Path, path: Path, value: dict[str, object], label: str) -> None:
    write_text_atomic(root, path, json.dumps(value, indent=2, sort_keys=True) + "\n", label)


class FreshFixtureDirectory(Protocol):
    """Minimal one-shot descriptor API used by the namespace fixture path."""

    def require_absent(self, name: str, label: str) -> None: ...

    def write_text_fresh(self, name: str, value: str, label: str) -> None: ...


def write_bound_json(
    directory: FreshFixtureDirectory, name: str, value: dict[str, object], label: str
) -> None:
    """Publish JSON once; namespace teardown releases failed partial leaves."""

    directory.write_text_fresh(name, json.dumps(value, indent=2, sort_keys=True) + "\n", label)


def receive_request_path(connection: socket.socket, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    data = bytearray()
    while b"\r\n\r\n" not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FixtureError("timed out while reading bounded HTTP request headers")
        connection.settimeout(remaining)
        chunk = connection.recv(4096)
        if not chunk:
            raise FixtureError("client closed before HTTP request headers")
        data.extend(chunk)
        if len(data) > 65536:
            raise FixtureError("HTTP request headers exceed the bounded fixture limit")
    request_line = bytes(data).split(b"\r\n", 1)[0].split()
    if len(request_line) != 3:
        raise FixtureError("fixture received an invalid HTTP request line")
    try:
        method = request_line[0].decode("ascii")
        path = request_line[1].decode("ascii")
        version = request_line[2].decode("ascii")
    except UnicodeDecodeError as exc:
        raise FixtureError("fixture request line is not ASCII") from exc
    if method != "GET" or version != "HTTP/1.1" or not path.startswith("/"):
        raise FixtureError("fixture requires an HTTP/1.1 GET request")
    return path.split("?", 1)[0]


def send_parts(
    connection: socket.socket,
    parts: tuple[bytes, ...],
    *,
    chunked: bool,
    delay: float,
) -> None:
    if chunked:
        connection.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n"
        )
        for index, part in enumerate(parts):
            connection.sendall(f"{len(part):X}\r\n".encode("ascii") + part + b"\r\n")
            if index + 1 < len(parts):
                time.sleep(delay)
        connection.sendall(b"0\r\n\r\n")
        return

    body_size = sum(len(part) for part in parts)
    connection.sendall(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        + f"Content-Length: {body_size}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
    )
    for index, part in enumerate(parts):
        connection.sendall(part)
        if index + 1 < len(parts):
            time.sleep(delay)


def serve_exchange(
    *,
    publish_ready: Callable[[dict[str, object]], None],
    publish_result: Callable[[dict[str, object]], None],
    host: str,
    port: int,
    timeout: float,
    inter_part_delay: float,
) -> None:
    if timeout <= 0 or inter_part_delay <= 0:
        raise FixtureError("timeouts and inter-part delay must be positive")
    fixtures = {
        CONTENT_LENGTH_PATH: (CONTENT_LENGTH_PARTS, False, "content_length"),
        CHUNKED_PATH: (CHUNKED_PARTS, True, "chunked"),
    }
    served: set[str] = set()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(len(fixtures))
        listener.settimeout(timeout)
        address_host, address_port = listener.getsockname()[:2]
        publish_ready(
            {
                "schema_version": 1,
                "evidence_type": "lighttpd_http1_entity_fixture_ready",
                "upstream_host": str(address_host),
                "upstream_port": int(address_port),
                "body_payload_persisted": False,
            },
        )
        while len(served) < len(fixtures):
            try:
                connection, _peer = listener.accept()
            except TimeoutError as exc:
                raise FixtureError("timed out waiting for HTTP/1.1 entity fixture requests") from exc
            with connection:
                path = receive_request_path(connection, timeout)
                fixture = fixtures.get(path)
                if fixture is None or path in served:
                    raise FixtureError("fixture received an unexpected or duplicate request path")
                parts, chunked, label = fixture
                send_parts(
                    connection,
                    parts,
                    chunked=chunked,
                    delay=inter_part_delay,
                )
                served.add(path)
                if label not in {"content_length", "chunked"}:
                    raise FixtureError("fixture label invariant failed")
    publish_result(
        {
            "schema_version": 1,
            "evidence_type": "lighttpd_http1_entity_fixture_result",
            "content_length_requests": int(CONTENT_LENGTH_PATH in served),
            "chunked_requests": int(CHUNKED_PATH in served),
            "content_length_entity_bytes": sum(len(part) for part in CONTENT_LENGTH_PARTS),
            "chunked_entity_bytes": sum(len(part) for part in CHUNKED_PARTS),
            "entity_parts_per_response": len(CONTENT_LENGTH_PARTS),
            "body_payload_persisted": False,
        },
    )


def serve(
    *,
    output_root: Path,
    ready_file: Path,
    result_file: Path,
    host: str,
    port: int,
    timeout: float,
    inter_part_delay: float,
) -> None:
    ready_file = safe_output_path(output_root, ready_file, READY_FILE_LABEL)
    result_file = safe_output_path(output_root, result_file, RESULT_FILE_LABEL)
    if ready_file.exists() or result_file.exists():
        raise FixtureError("fixture control files must be fresh")
    serve_exchange(
        publish_ready=lambda value: write_json(output_root, ready_file, value, READY_FILE_LABEL),
        publish_result=lambda value: write_json(output_root, result_file, value, RESULT_FILE_LABEL),
        host=host,
        port=port,
        timeout=timeout,
        inter_part_delay=inter_part_delay,
    )


def serve_bound(
    *,
    directory: FreshFixtureDirectory,
    ready_name: str,
    result_name: str,
    host: str,
    port: int,
    timeout: float,
    inter_part_delay: float,
) -> None:
    directory.require_absent(ready_name, READY_FILE_LABEL)
    directory.require_absent(result_name, RESULT_FILE_LABEL)
    serve_exchange(
        publish_ready=lambda value: write_bound_json(directory, ready_name, value, READY_FILE_LABEL),
        publish_result=lambda value: write_bound_json(directory, result_name, value, RESULT_FILE_LABEL),
        host=host,
        port=port,
        timeout=timeout,
        inter_part_delay=inter_part_delay,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ready-file", type=Path)
    parser.add_argument("--result-file", type=Path)
    parser.add_argument("--runtime-output-root", type=Path)
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--inter-part-delay", type=float, default=0.35)
    args = parser.parse_args(argv)
    try:
        if not all(
            value is not None
            for value in (args.ready_file, args.result_file, args.runtime_output_root)
        ):
            parser.error("pathname fixture-output mode requires ready file, result file, and root")
        serve(
            output_root=verified_runtime_output_root(args.runtime_output_root),
            ready_file=args.ready_file,
            result_file=args.result_file,
            host=args.listen_host,
            port=args.listen_port,
            timeout=args.timeout,
            inter_part_delay=args.inter_part_delay,
        )
    except (FixtureError, OSError, ValueError) as exc:
        print(f"lighttpd_http1_entity_fixture: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
