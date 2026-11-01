#!/usr/bin/env python3
"""Exercise the patched-lighttpd HTTP/1.1 pre-upstream Phase-2 gate.

The runner starts only task-owned foreground processes. Its loopback upstream
stores bounded framing metadata and counters, never request payloads or header
values. It proves that a delayed chunked request cannot connect to the proxy
upstream before ModSecurity finishes Phase 2, while a complete allowed request
is still delivered after that decision.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import errno
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Callable


MAX_HEADERS = 16 * 1024
MAX_BODY = 1024 * 1024
LOOPBACK_HOST = "127.0.0.1"
MIN_UNPRIVILEGED_PORT = 1024
MAX_TCP_PORT = 65535
SUMMARY_FILE_NAME = "summary.json"
SUMMARY_TEMPORARY_NAME = "summary.json.tmp"
SUMMARY_NAMES = (SUMMARY_FILE_NAME, SUMMARY_TEMPORARY_NAME)


class GateFailure(RuntimeError):
    """A required gate assertion or task-owned cleanup check failed."""


@dataclass(frozen=True)
class LoopbackEndpoint:
    """A runner-owned numeric IPv4-loopback endpoint."""

    port: int

    @classmethod
    def allocate(cls) -> LoopbackEndpoint:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            reservation.bind((LOOPBACK_HOST, 0))
            port = reservation.getsockname()[1]
        if not MIN_UNPRIVILEGED_PORT <= port <= MAX_TCP_PORT:
            raise GateFailure(f"allocated invalid loopback port {port}")
        return cls(port)

    def connect(self, timeout: float = 5.0) -> socket.socket:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(timeout)
        try:
            connection.connect((LOOPBACK_HOST, self.port))
        except Exception:
            connection.close()
            raise
        return connection


def _require_private_task_directory(directory_stat: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(directory_stat.st_mode):
        raise GateFailure(f"{label} must be a directory")
    if directory_stat.st_uid != os.geteuid() or directory_stat.st_mode & (
        stat.S_IWGRP | stat.S_IWOTH
    ):
        raise GateFailure(f"{label} must be private to the invoking user")


@dataclass
class TaskRuntimeDirectory:
    """A private runtime directory held open by descriptor for its whole use."""

    directory_fd: int
    task_root: Path
    task_root_identity: tuple[int, int]

    @staticmethod
    def _component(name: str) -> None:
        if not name or name in {".", ".."} or "/" in name or "\\" in name:
            raise GateFailure("runtime child name must be a single fixed path component")

    def child(self, name: str) -> TaskRuntimeDirectory:
        self._component(name)
        try:
            os.mkdir(name, 0o700, dir_fd=self.directory_fd)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                raise GateFailure(f"runtime child {name!r} must be fresh") from exc
            raise GateFailure(f"could not create runtime child {name!r}") from exc
        try:
            child_fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=self.directory_fd,
            )
        except OSError as exc:
            raise GateFailure(f"could not pin runtime child {name!r}") from exc
        try:
            _require_private_task_directory(os.fstat(child_fd), f"runtime child {name!r}")
        except Exception:
            os.close(child_fd)
            raise
        return TaskRuntimeDirectory(child_fd, self.task_root, self.task_root_identity)

    def _open_new(self, name: str) -> int:
        self._component(name)
        try:
            return os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=self.directory_fd,
            )
        except OSError as exc:
            raise GateFailure(f"could not create runtime file {name!r}") from exc

    def write_text(self, name: str, contents: str) -> None:
        descriptor = self._open_new(name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(contents)

    def write_bytes(self, name: str, contents: bytes) -> None:
        descriptor = self._open_new(name)
        with os.fdopen(descriptor, "wb") as output:
            output.write(contents)

    def open_binary_output(self, name: str) -> Any:
        return os.fdopen(self._open_new(name), "wb")

    def read_bytes_if_present(self, name: str) -> bytes | None:
        self._component(name)
        descriptor: int | None = None
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=self.directory_fd,
            )
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                return None
            raise GateFailure(f"could not open runtime file {name!r}") from exc
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise GateFailure(f"runtime file {name!r} must be regular")
            input_file = os.fdopen(descriptor, "rb")
            descriptor = None
            with input_file:
                return input_file.read()
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def inherited_fds(self) -> tuple[int, ...]:
        return (self.directory_fd,)

    def runtime_path(self, name: str) -> str:
        self._component(name)
        return f"/proc/self/fd/{self.directory_fd}/{name}"

    def event_sink_path(self, name: str) -> str:
        """Use a verified real directory for Common's no-follow parent walker."""
        self._component(name)
        try:
            pinned = os.fstat(self.directory_fd)
            directory = Path(os.readlink(f"/proc/self/fd/{self.directory_fd}"))
            root = ensure_directory(self.task_root, "selected runtime root")
            directory = ensure_directory(directory, "event sink directory")
            root_status = root.stat(follow_symlinks=False)
            directory_status = directory.stat(follow_symlinks=False)
        except OSError as exc:
            raise GateFailure("could not verify pinned event sink directory") from exc
        _require_private_task_directory(pinned, "pinned event sink directory")
        _require_private_task_directory(root_status, "selected runtime root")
        _require_private_task_directory(directory_status, "event sink directory")
        if (root_status.st_dev, root_status.st_ino) != self.task_root_identity:
            raise GateFailure("selected runtime root identity changed")
        if not directory.is_relative_to(root):
            raise GateFailure("event sink directory escaped selected runtime root")
        if (directory_status.st_dev, directory_status.st_ino) != (pinned.st_dev, pinned.st_ino):
            raise GateFailure("event sink directory differs from pinned descriptor")
        return str(directory / name)

    def close(self) -> None:
        if self.directory_fd >= 0:
            os.close(self.directory_fd)
            self.directory_fd = -1


@dataclass
class TaskRuntimeRoot(TaskRuntimeDirectory):
    """A verified task-owned root pinned for descriptor-relative outputs."""


@dataclass(frozen=True)
class RunnerInputs:
    """All validated file inputs plus internally selected loopback endpoints."""

    root: TaskRuntimeRoot
    binary: Path
    module_dir: Path
    rules_file: Path
    library_dir: Path
    host_endpoint: LoopbackEndpoint
    configured_host_endpoint: LoopbackEndpoint
    upstream_endpoint: LoopbackEndpoint

    @property
    def endpoints(self) -> tuple[LoopbackEndpoint, LoopbackEndpoint, LoopbackEndpoint]:
        return (
            self.host_endpoint,
            self.configured_host_endpoint,
            self.upstream_endpoint,
        )


@dataclass
class RunState:
    """Mutable process ownership state for one gate run."""

    upstream: ChunkAwareMetadataUpstream | None = None
    active_host: tuple[subprocess.Popen[bytes], str, str] | None = None


def start_token(pid: int) -> str:
    stat_path = Path(f"/proc/{pid}/stat")
    try:
        suffix = stat_path.read_text(encoding="utf-8").rsplit(")", 1)[1].split()
        token = suffix[19]
    except (IndexError, OSError) as exc:
        raise GateFailure(f"could not read start token for PID {pid}") from exc
    if not token.isdecimal():
        raise GateFailure(f"invalid start token for PID {pid}")
    return token


def still_owned(process: subprocess.Popen[bytes], token: str) -> bool:
    return process.poll() is None and start_token(process.pid) == token


def stop_owned(process: subprocess.Popen[bytes], token: str, label: str) -> dict[str, Any]:
    result: dict[str, Any] = {"label": label, "pid": process.pid, "start_token": token}
    if process.poll() is not None:
        result["already_exited"] = process.returncode
        return result
    if not still_owned(process, token):
        raise GateFailure(f"refusing to signal changed {label} PID")
    process.terminate()
    try:
        result["returncode"] = process.wait(timeout=5)
        result["signal"] = "TERM"
        return result
    except subprocess.TimeoutExpired:
        if not still_owned(process, token):
            raise GateFailure(f"refusing to SIGKILL changed {label} PID")
        process.kill()
        result["returncode"] = process.wait(timeout=5)
        result["signal"] = "KILL"
        return result


def allocate_private_loopback_endpoints(
) -> tuple[LoopbackEndpoint, LoopbackEndpoint, LoopbackEndpoint]:
    endpoints: list[LoopbackEndpoint] = []
    reserved_ports: set[int] = set()
    for _ in range(32):
        endpoint = LoopbackEndpoint.allocate()
        if endpoint.port in reserved_ports:
            continue
        reserved_ports.add(endpoint.port)
        endpoints.append(endpoint)
        if len(endpoints) == 3:
            return (endpoints[0], endpoints[1], endpoints[2])
    raise GateFailure("could not reserve three distinct private loopback ports")


def listener_rows(endpoint: LoopbackEndpoint) -> list[str]:
    """Return metadata-only markers for TCP ``LISTEN`` entries on one port."""

    port_hex = f"{endpoint.port:04X}"
    listeners: list[str] = []
    for table_path in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        try:
            rows = table_path.read_text(encoding="ascii").splitlines()[1:]
        except OSError as exc:
            raise GateFailure(f"could not read {table_path} for listener cleanup") from exc
        for row in rows:
            fields = row.split()
            if len(fields) >= 4 and fields[3] == "0A" and fields[1].endswith(port_hex):
                listeners.append(f"{LOOPBACK_HOST}:{endpoint.port}")
                break
    return listeners


def wait_for_listener(
    endpoint: LoopbackEndpoint, expected: bool, timeout: float = 5.0
) -> list[str]:
    deadline = time.monotonic() + timeout
    latest: list[str] = []
    while time.monotonic() < deadline:
        latest = listener_rows(endpoint)
        if bool(latest) == expected:
            return latest
        time.sleep(0.05)
    state = "present" if expected else "absent"
    raise GateFailure(f"listener on port {endpoint.port} did not become {state}")


class ChunkAwareMetadataUpstream:
    """Task-owned HTTP/1.1 upstream retaining counters and framing only."""

    def __init__(self, endpoint: LoopbackEndpoint) -> None:
        self._endpoint = endpoint
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._records: list[dict[str, Any]] = []
        self._accepted_connections = 0

    def start(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((LOOPBACK_HOST, self._endpoint.port))
        listener.listen(16)
        listener.settimeout(0.2)
        self._listener = listener
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._listener is not None:
            self._listener.close()
        if self._thread is not None:
            self._thread.join(timeout=3)
            if self._thread.is_alive():
                raise GateFailure("metadata upstream did not stop")

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(record) for record in self._records]

    def accepted_connections(self) -> int:
        with self._lock:
            return self._accepted_connections

    def _record(self, metadata: dict[str, Any]) -> None:
        with self._lock:
            metadata["connection_index"] = len(self._records) + 1
            self._records.append(metadata)

    def _serve(self) -> None:
        assert self._listener is not None
        while not self._stop.is_set():
            try:
                connection, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                raise
            with self._lock:
                self._accepted_connections += 1
            threading.Thread(target=self._handle, args=(connection,), daemon=True).start()

    def _read_headers(
        self, connection: socket.socket, metadata: dict[str, Any]
    ) -> tuple[bytes, int | None]:
        received = bytearray()
        while b"\r\n\r\n" not in received:
            data = connection.recv(4096)
            if not data:
                raise GateFailure("upstream client closed before headers")
            received.extend(data)
            if len(received) > MAX_HEADERS:
                raise GateFailure("upstream headers exceeded bound")
        raw_headers, body = bytes(received).split(b"\r\n\r\n", 1)
        header_lines = raw_headers.split(b"\r\n")
        request_line = header_lines[0].split()
        if len(request_line) != 3:
            raise GateFailure("upstream received malformed request line")
        metadata["method"] = request_line[0].decode("ascii", errors="replace")
        metadata["path"] = request_line[1].decode("ascii", errors="replace")
        content_length: int | None = None
        for header in header_lines[1:]:
            content_length = self._record_framing_header(header, content_length, metadata)
        metadata["headers_received"] = True
        metadata["received_body_wire_bytes"] = len(body)
        return body, content_length

    def _record_framing_header(
        self, header: bytes, content_length: int | None, metadata: dict[str, Any]
    ) -> int | None:
        name, separator, value = header.partition(b":")
        if not separator:
            return content_length
        normalized_name = name.strip().lower()
        if normalized_name == b"content-length":
            if content_length is not None:
                raise GateFailure("upstream received duplicate content length")
            return int(value.strip())
        if normalized_name == b"transfer-encoding":
            tokens = {part.strip().lower() for part in value.split(b",")}
            metadata["transfer_encoding_chunked"] = b"chunked" in tokens
        return content_length

    def _read_content_length_body(
        self,
        connection: socket.socket,
        metadata: dict[str, Any],
        content_length: int,
    ) -> None:
        if content_length < 0 or content_length > MAX_BODY:
            raise GateFailure("upstream content length exceeded bound")
        metadata["content_length_present"] = True
        metadata["declared_content_length"] = content_length
        while metadata["received_body_wire_bytes"] < content_length:
            remaining = content_length - metadata["received_body_wire_bytes"]
            data = connection.recv(min(4096, remaining))
            if not data:
                metadata["read_termination"] = "eof"
                break
            metadata["received_body_wire_bytes"] += len(data)
        metadata["complete"] = metadata["received_body_wire_bytes"] == content_length

    def _consume_chunk_size(
        self, wire: bytearray, metadata: dict[str, Any]
    ) -> tuple[str, int, bool, bool]:
        line_end = wire.find(b"\r\n")
        if line_end < 0:
            return "size", 0, False, False
        token = bytes(wire[:line_end]).split(b";", 1)[0].strip()
        del wire[: line_end + 2]
        if not token or len(token) > 16:
            raise GateFailure("upstream chunk-size is invalid")
        remaining = int(token, 16)
        if remaining == 0:
            return "trailers", 0, False, True
        if metadata["received_body_payload_bytes"] + remaining > MAX_BODY:
            raise GateFailure("upstream chunk body exceeded bound")
        metadata["received_chunk_count"] += 1
        return "data", remaining, False, True

    def _consume_chunk_data(
        self, wire: bytearray, metadata: dict[str, Any], remaining: int
    ) -> tuple[str, int, bool, bool]:
        available = min(len(wire), remaining)
        if available:
            del wire[:available]
            metadata["received_body_payload_bytes"] += available
            remaining -= available
        if remaining:
            return "data", remaining, False, False
        return "data_crlf", 0, False, True

    def _consume_chunk_data_crlf(
        self, wire: bytearray
    ) -> tuple[str, int, bool, bool]:
        if len(wire) < 2:
            return "data_crlf", 0, False, False
        if bytes(wire[:2]) != b"\r\n":
            raise GateFailure("upstream chunk data missing CRLF")
        del wire[:2]
        return "size", 0, False, True

    def _consume_chunk_trailers(
        self, wire: bytearray
    ) -> tuple[str, int, bool, bool]:
        line_end = wire.find(b"\r\n")
        if line_end < 0:
            return "trailers", 0, False, False
        del wire[: line_end + 2]
        return "trailers", 0, line_end == 0, True

    def _consume_chunked_buffer(
        self,
        state: str,
        wire: bytearray,
        metadata: dict[str, Any],
        remaining: int,
    ) -> tuple[str, int, bool, bool]:
        if state == "size":
            return self._consume_chunk_size(wire, metadata)
        if state == "data":
            return self._consume_chunk_data(wire, metadata, remaining)
        if state == "data_crlf":
            return self._consume_chunk_data_crlf(wire)
        if state == "trailers":
            return self._consume_chunk_trailers(wire)
        raise GateFailure("invalid upstream chunk parser state")

    def _read_chunked_body(
        self, connection: socket.socket, metadata: dict[str, Any], body: bytes
    ) -> None:
        if len(body) > MAX_BODY:
            raise GateFailure("upstream body wire data exceeded bound")
        wire = bytearray(body)
        metadata["received_body_payload_bytes"] = 0
        metadata["received_chunk_count"] = 0
        metadata["terminal_chunk_seen"] = False
        state = "size"
        remaining = 0
        while not metadata["terminal_chunk_seen"]:
            progressed = True
            while progressed and not metadata["terminal_chunk_seen"]:
                state, remaining, terminal, progressed = self._consume_chunked_buffer(
                    state, wire, metadata, remaining
                )
                metadata["terminal_chunk_seen"] = terminal
            if metadata["terminal_chunk_seen"]:
                break
            data = connection.recv(4096)
            if not data:
                metadata["read_termination"] = "eof"
                break
            metadata["received_body_wire_bytes"] += len(data)
            if metadata["received_body_wire_bytes"] > MAX_BODY:
                raise GateFailure("upstream body wire data exceeded bound")
            wire.extend(data)
        metadata["complete"] = bool(metadata["terminal_chunk_seen"])

    def _send_success(self, connection: socket.socket, metadata: dict[str, Any]) -> None:
        connection.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n"
            b"Connection: close\r\n\r\nok\n"
        )
        metadata["upstream_response_sent"] = True

    def _handle(self, connection: socket.socket) -> None:
        metadata: dict[str, Any] = {
            "complete": False,
            "content_length_present": False,
            "error": None,
            "headers_received": False,
            "received_body_wire_bytes": 0,
            "transfer_encoding_chunked": False,
            "upstream_response_sent": False,
        }
        with connection:
            try:
                connection.settimeout(2)
                body, content_length = self._read_headers(connection, metadata)
                if content_length is not None:
                    self._read_content_length_body(connection, metadata, content_length)
                elif metadata["transfer_encoding_chunked"]:
                    self._read_chunked_body(connection, metadata, body)
                else:
                    metadata["complete"] = True
                    metadata["read_termination"] = "no_body_framing"
                if metadata["complete"]:
                    self._send_success(connection, metadata)
            except Exception as exc:
                metadata["error"] = str(exc)[:256]
            finally:
                self._record(metadata)


def read_status(connection: socket.socket) -> int:
    response = bytearray()
    while b"\r\n\r\n" not in response:
        data = connection.recv(4096)
        if not data:
            raise GateFailure("host closed request before response headers")
        response.extend(data)
        if len(response) > MAX_HEADERS:
            raise GateFailure("host response headers exceeded bound")
    status_line = bytes(response).split(b"\r\n", 1)[0].split()
    if len(status_line) < 2:
        raise GateFailure("host response status line is invalid")
    try:
        return int(status_line[1])
    except ValueError as exc:
        raise GateFailure("host response status is invalid") from exc


def send_content_length(
    endpoint: LoopbackEndpoint,
    label: str,
    body: bytes,
    headers: dict[str, str] | None = None,
) -> int:
    request_headers = [
        f"POST /{label} HTTP/1.1",
        f"Host: {LOOPBACK_HOST}",
        "Content-Type: text/plain",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    if headers is not None:
        request_headers.extend(f"{name}: {value}" for name, value in headers.items())
    request = ("\r\n".join(request_headers) + "\r\n\r\n").encode("ascii") + body
    with endpoint.connect() as connection:
        connection.sendall(request)
        return read_status(connection)


def send_delayed_chunked(
    endpoint: LoopbackEndpoint,
    label: str,
    body: bytes,
    before_terminal: Callable[[], dict[str, Any]],
) -> tuple[int, dict[str, Any]]:
    split = max(1, len(body) // 2)
    chunks = (body[:split], body[split:])
    if not all(chunks):
        raise GateFailure("chunked body must produce two nonempty chunks")
    request = (
        f"POST /{label} HTTP/1.1\r\n"
        f"Host: {LOOPBACK_HOST}\r\n"
        "Content-Type: text/plain\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    with endpoint.connect() as connection:
        connection.sendall(request)
        for chunk in chunks:
            connection.sendall(f"{len(chunk):X}\r\n".encode("ascii"))
            connection.sendall(chunk)
            connection.sendall(b"\r\n")
            time.sleep(0.05)
        observation = before_terminal()
        connection.sendall(b"0\r\n\r\n")
        return read_status(connection), observation


def assert_no_upstream_before_terminal(
    upstream: ChunkAwareMetadataUpstream, baseline: int
) -> dict[str, Any]:
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        accepted = upstream.accepted_connections()
        if accepted != baseline or len(upstream.snapshot()) != baseline:
            raise GateFailure("request reached upstream before terminal Phase-2 decision")
        time.sleep(0.05)
    return {
        "accepted_connections": 0,
        "received_body_payload_bytes": 0,
        "upstream_response_sent": False,
    }


def await_completed_upstream(
    upstream: ChunkAwareMetadataUpstream, baseline: int, label: str
) -> dict[str, Any]:
    deadline = time.monotonic() + 3
    expected_path = f"/{label}"
    while time.monotonic() < deadline:
        records = upstream.snapshot()[baseline:]
        for record in records:
            if record.get("path") == expected_path and record.get("complete"):
                return record
        time.sleep(0.05)
    raise GateFailure("allowed request did not complete at upstream")


def write_runtime_inputs(
    root: TaskRuntimeDirectory,
    *,
    rules_file: Path,
    host_endpoint: LoopbackEndpoint,
    upstream_endpoint: LoopbackEndpoint,
    configured_streaming: bool,
    upgrade_request_body: bool,
) -> dict[str, str]:
    document_root = root.child("document-root")
    upload_dir: TaskRuntimeDirectory | None = None
    try:
        upload_dir = root.child("upload")
        document_root.write_text("index.html", "phase2 pre-upstream gate\n")
        root.write_text("events.jsonl", "")
        document_root_path = root.runtime_path("document-root")
        upload_dir_path = root.runtime_path("upload")
        event_path = root.event_sink_path("events.jsonl")
        runtime_config = root.runtime_path("msconnector-runtime.conf")
        error_log = root.runtime_path("lighttpd-error.log")
        pid_file = root.runtime_path("lighttpd.pid")
        root.write_text(
            "msconnector-runtime.conf",
        "\n".join(
            (
                "enabled=on",
                f"rules_file={rules_file}",
                "transaction_id_header=x-modsec-transaction-id",
                "request_body_mode=streaming",
                "response_body_mode=none",
                "default_block_status=403",
                "default_error_status=500",
                "max_header_count=256",
                "max_header_name_size=256",
                "max_header_value_size=8192",
                "max_total_header_bytes=65536",
                "max_event_json_bytes=16384",
                f"event_path={event_path}",
                "",
            )
        ),
        )
        config_lines = [
            'server.compat-module-load = "disable"',
            'server.modules = ( "mod_proxy", "mod_msconnector" )',
            f'server.document-root = "{document_root_path}"',
            f'server.bind = "{LOOPBACK_HOST}"',
            f"server.port = {host_endpoint.port}",
            f'server.errorlog = "{error_log}"',
            f'server.pid-file = "{pid_file}"',
            f'server.upload-dirs = ( "{upload_dir_path}" )',
            'msconnector.enabled = "enable"',
            'msconnector.request-body-gate = "pre-upstream"',
            f'msconnector.config-file = "{runtime_config}"',
            "proxy.server = (",
            f'  "/" => ( ( "host" => "{LOOPBACK_HOST}", "port" => {upstream_endpoint.port} ) )',
            ")",
            "",
        ]
        if configured_streaming:
            config_lines.insert(7, "server.stream-request-body = 1")
        if upgrade_request_body:
            config_lines.insert(
                8,
                'server.feature-flags += ( "gw.upgrade-with-request-body" => "enable" )',
            )
            config_lines.insert(-1, 'proxy.header = ( "upgrade" => "enable" )')
        root.write_text("lighttpd.conf", "\n".join(config_lines))
        return {"config": root.runtime_path("lighttpd.conf"), "event_path": event_path}
    finally:
        document_root.close()
        if upload_dir is not None:
            upload_dir.close()


def build_lighttpd_argv(
    binary: Path, module_dir: Path, config: str, *, foreground: bool
) -> list[str]:
    if foreground:
        return [str(binary), "-D", "-m", str(module_dir), "-f", str(config)]
    return [str(binary), "-m", str(module_dir), "-tt", "-f", str(config)]


def run_config_check(
    binary: Path,
    module_dir: Path,
    config: str,
    *,
    pass_fds: tuple[int, ...] = (),
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        build_lighttpd_argv(binary, module_dir, config, foreground=False),
        check=False,
        capture_output=True,
        pass_fds=pass_fds,
    )


def start_host(
    *,
    root: TaskRuntimeDirectory,
    binary: Path,
    module_dir: Path,
    config: str,
    library_dir: Path,
) -> tuple[subprocess.Popen[bytes], str]:
    config_check = run_config_check(
        binary, module_dir, config, pass_fds=root.inherited_fds()
    )
    root.write_bytes("config-check.stdout", config_check.stdout)
    root.write_bytes("config-check.stderr", config_check.stderr)
    if config_check.returncode != 0:
        raise GateFailure("lighttpd config check failed")
    environment = dict(os.environ)
    environment["LD_LIBRARY_PATH"] = str(library_dir) + (
        ":" + environment["LD_LIBRARY_PATH"] if environment.get("LD_LIBRARY_PATH") else ""
    )
    stdout = root.open_binary_output("lighttpd.stdout")
    stderr = root.open_binary_output("lighttpd.stderr")
    try:
        process = subprocess.Popen(
            build_lighttpd_argv(binary, module_dir, config, foreground=True),
            stdout=stdout,
            stderr=stderr,
            env=environment,
            pass_fds=root.inherited_fds(),
        )
    finally:
        stdout.close()
        stderr.close()
    return process, start_token(process.pid)


def _reject_config_control_characters(path: Path, label: str) -> None:
    if any(character in str(path) for character in ('"', "\\", "\r", "\n")):
        raise GateFailure(f"{label} contains unsupported configuration path characters")


def _resolve_existing_path_without_symlinks(path: Path, label: str) -> Path:
    _reject_config_control_characters(path, label)
    absolute = path.absolute()
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise GateFailure(f"{label} does not resolve to an existing path") from exc
    if absolute != resolved:
        raise GateFailure(f"{label} must not contain symbolic links")
    return resolved


def ensure_regular(path: Path, label: str, *, executable: bool = False) -> Path:
    resolved = _resolve_existing_path_without_symlinks(path, label)
    if not resolved.is_file():
        raise GateFailure(f"{label} must be a regular file")
    if executable and not os.access(resolved, os.X_OK):
        raise GateFailure(f"{label} must be executable")
    return resolved


def ensure_directory(path: Path, label: str) -> Path:
    resolved = _resolve_existing_path_without_symlinks(path, label)
    if not resolved.is_dir():
        raise GateFailure(f"{label} must be a regular directory")
    return resolved


def ensure_module_dir(path: Path) -> Path:
    module_dir = ensure_directory(path, "connector module directory")
    ensure_regular(module_dir / "mod_msconnector.so", "connector module")
    ensure_regular(module_dir / "mod_proxy.so", "proxy module")
    return module_dir


def _ensure_fresh_summary_target(directory_fd: int) -> None:
    for name in SUMMARY_NAMES:
        try:
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                continue
            raise GateFailure("could not inspect runtime summary target") from exc
        raise GateFailure("runtime root must be fresh without a summary target")


def ensure_runtime_root(path: Path) -> TaskRuntimeRoot:
    root = ensure_directory(path, "runtime root")
    root_stat = root.stat()
    _require_private_task_directory(root_stat, "runtime root")
    try:
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise GateFailure("could not pin runtime root") from exc
    try:
        pinned_stat = os.fstat(directory_fd)
        _require_private_task_directory(pinned_stat, "pinned runtime root")
        _ensure_fresh_summary_target(directory_fd)
    except Exception:
        os.close(directory_fd)
        raise
    return TaskRuntimeRoot(directory_fd, root, (pinned_stat.st_dev, pinned_stat.st_ino))


def write_summary(root: TaskRuntimeRoot, summary: dict[str, Any]) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            SUMMARY_TEMPORARY_NAME,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=root.directory_fd,
        )
        output = os.fdopen(descriptor, "w", encoding="utf-8")
        descriptor = None
        with output:
            output.write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        os.replace(
            SUMMARY_TEMPORARY_NAME,
            SUMMARY_FILE_NAME,
            src_dir_fd=root.directory_fd,
            dst_dir_fd=root.directory_fd,
        )
    except OSError as exc:
        raise GateFailure("could not persist runtime summary under the pinned root") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def parse_runner_inputs(argv: list[str] | None = None) -> RunnerInputs:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--lighttpd-bin", type=Path, required=True)
    parser.add_argument("--module-dir", type=Path, required=True)
    parser.add_argument("--rules-file", type=Path, required=True)
    parser.add_argument("--modsecurity-lib-dir", type=Path, required=True)
    parsed = parser.parse_args(argv)
    root = ensure_runtime_root(parsed.root)
    try:
        endpoints = allocate_private_loopback_endpoints()
        return RunnerInputs(
            root=root,
            binary=ensure_regular(parsed.lighttpd_bin, "lighttpd binary", executable=True),
            module_dir=ensure_module_dir(parsed.module_dir),
            rules_file=ensure_regular(parsed.rules_file, "rules file"),
            library_dir=ensure_directory(parsed.modsecurity_lib_dir, "ModSecurity library directory"),
            host_endpoint=endpoints[0],
            configured_host_endpoint=endpoints[1],
            upstream_endpoint=endpoints[2],
        )
    except Exception:
        root.close()
        raise


def new_summary(inputs: RunnerInputs) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "patched_lighttpd_phase2_pre_upstream_gate",
        "body_payload_persisted": False,
        "host_port": inputs.host_endpoint.port,
        "configured_host_port": inputs.configured_host_endpoint.port,
        "upstream_port": inputs.upstream_endpoint.port,
        "cases": [],
        "cleanup": {},
        "result": "failed",
    }


def ensure_selected_ports_are_unused(inputs: RunnerInputs) -> None:
    if any(listener_rows(endpoint) for endpoint in inputs.endpoints):
        raise GateFailure("an allocated task port is already listening")


def run_delayed_marker_case(
    inputs: RunnerInputs,
    summary: dict[str, Any],
    upstream: ChunkAwareMetadataUpstream,
    marker: bytes,
) -> None:
    baseline = upstream.accepted_connections()
    status, preterminal = send_delayed_chunked(
        inputs.host_endpoint,
        "phase2-marker-delayed",
        marker,
        lambda: assert_no_upstream_before_terminal(upstream, baseline),
    )
    if status != 403 or upstream.accepted_connections() != baseline:
        raise GateFailure("delayed Phase-2 marker did not fail closed")
    summary["cases"].append(
        {
            "label": "delayed_chunked_phase2_marker",
            "http_status": status,
            "request_body_bytes": len(marker),
            "pre_terminal_upstream_observation": preterminal,
            "upstream_connections_after": upstream.accepted_connections(),
            "upstream_connections_before": baseline,
        }
    )


def run_delayed_allow_case(
    inputs: RunnerInputs,
    summary: dict[str, Any],
    upstream: ChunkAwareMetadataUpstream,
) -> None:
    allowed = b"0" * 32
    baseline = upstream.accepted_connections()
    status, preterminal = send_delayed_chunked(
        inputs.host_endpoint,
        "phase2-allow-delayed",
        allowed,
        lambda: assert_no_upstream_before_terminal(upstream, baseline),
    )
    record = await_completed_upstream(upstream, baseline, "phase2-allow-delayed")
    if status != 200 or upstream.accepted_connections() != baseline + 1:
        raise GateFailure("allowed delayed request was not delivered exactly once")
    if record.get("received_body_wire_bytes") != len(allowed):
        raise GateFailure("allowed delayed request had an unexpected upstream byte count")
    if record.get("content_length_present") is not True:
        raise GateFailure("allowed delayed request was not reframed with Content-Length")
    if record.get("declared_content_length") != len(allowed):
        raise GateFailure("allowed delayed request had an unexpected Content-Length")
    if record.get("transfer_encoding_chunked") is not False:
        raise GateFailure("allowed delayed request retained chunked transfer encoding")
    summary["cases"].append(
        {
            "label": "delayed_chunked_phase2_allow",
            "http_status": status,
            "request_body_bytes": len(allowed),
            "pre_terminal_upstream_observation": preterminal,
            "upstream_delivery": {
                "accepted_connections": 1,
                "content_length_present": record.get("content_length_present"),
                "declared_content_length": record.get("declared_content_length"),
                "received_body_wire_bytes": record.get("received_body_wire_bytes"),
                "transfer_encoding_chunked": record.get("transfer_encoding_chunked"),
                "upstream_response_sent": record.get("upstream_response_sent"),
            },
        }
    )


def run_immediate_marker_case(
    inputs: RunnerInputs,
    summary: dict[str, Any],
    upstream: ChunkAwareMetadataUpstream,
    marker: bytes,
) -> None:
    baseline = upstream.accepted_connections()
    status, _ = send_delayed_chunked(
        inputs.host_endpoint,
        "phase2-marker-immediate",
        marker,
        lambda: {"not_delayed": True},
    )
    if status != 403 or upstream.accepted_connections() != baseline:
        raise GateFailure("immediate Phase-2 marker did not fail closed")
    summary["cases"].append(
        {
            "label": "immediate_chunked_phase2_marker",
            "http_status": status,
            "upstream_connections_before": baseline,
            "upstream_connections_after": upstream.accepted_connections(),
        }
    )


def run_incremental_stream_case(
    inputs: RunnerInputs, summary: dict[str, Any], upstream: ChunkAwareMetadataUpstream
) -> None:
    baseline = upstream.accepted_connections()
    status = send_content_length(
        inputs.host_endpoint,
        "incremental-request-stream",
        b"x",
        {"Incremental": "?1"},
    )
    if status != 501 or upstream.accepted_connections() != baseline:
        raise GateFailure("incremental-request-stream did not fail closed")
    summary["cases"].append(
        {
            "label": "incremental-request-stream",
            "http_status": status,
            "upstream_connections_before": baseline,
            "upstream_connections_after": upstream.accepted_connections(),
        }
    )


def run_normal_profile(
    inputs: RunnerInputs,
    summary: dict[str, Any],
    upstream: ChunkAwareMetadataUpstream,
    state: RunState,
) -> None:
    normal_root = inputs.root.child("normal")
    try:
        normal_inputs = write_runtime_inputs(
            normal_root,
            rules_file=inputs.rules_file,
            host_endpoint=inputs.host_endpoint,
            upstream_endpoint=inputs.upstream_endpoint,
            configured_streaming=False,
            upgrade_request_body=False,
        )
        process, token = start_host(
            root=normal_root,
            binary=inputs.binary,
            module_dir=inputs.module_dir,
            config=normal_inputs["config"],
            library_dir=inputs.library_dir,
        )
        state.active_host = (process, token, "normal foreground lighttpd")
        wait_for_listener(inputs.host_endpoint, True)
        if not still_owned(process, token):
            raise GateFailure("normal foreground lighttpd did not remain alive")
        marker = b"msconnector-p2-only"
        run_delayed_marker_case(inputs, summary, upstream, marker)
        run_delayed_allow_case(inputs, summary, upstream)
        run_immediate_marker_case(inputs, summary, upstream, marker)
        run_incremental_stream_case(inputs, summary, upstream)
        summary["cleanup"]["normal_lighttpd"] = stop_owned(
            process, token, "normal foreground lighttpd"
        )
        state.active_host = None
        wait_for_listener(inputs.host_endpoint, False)
    finally:
        normal_root.close()



def run_configured_stream_case(
    inputs: RunnerInputs,
    summary: dict[str, Any],
    upstream: ChunkAwareMetadataUpstream,
    state: RunState,
) -> None:
    case_root = inputs.root.child("configured-stream")
    try:
        case_inputs = write_runtime_inputs(
            case_root,
            rules_file=inputs.rules_file,
            host_endpoint=inputs.configured_host_endpoint,
            upstream_endpoint=inputs.upstream_endpoint,
            configured_streaming=True,
            upgrade_request_body=False,
        )
        process, token = start_host(
            root=case_root,
            binary=inputs.binary,
            module_dir=inputs.module_dir,
            config=case_inputs["config"],
            library_dir=inputs.library_dir,
        )
        state.active_host = (process, token, "configured foreground lighttpd")
        wait_for_listener(inputs.configured_host_endpoint, True)
        baseline = upstream.accepted_connections()
        status = send_content_length(
            inputs.configured_host_endpoint, "configured-request-stream", b"x"
        )
        if status != 501 or upstream.accepted_connections() != baseline:
            raise GateFailure("configured request streaming did not fail closed")
        summary["cases"].append(
            {
                "label": "configured_request_stream",
                "http_status": status,
                "upstream_connections_before": baseline,
                "upstream_connections_after": upstream.accepted_connections(),
            }
        )
        summary["cleanup"]["configured_lighttpd"] = stop_owned(
            process, token, "configured foreground lighttpd"
        )
        state.active_host = None
        wait_for_listener(inputs.configured_host_endpoint, False)
    finally:
        case_root.close()


def run_enabled_upgrade_case(
    inputs: RunnerInputs,
    summary: dict[str, Any],
    upstream: ChunkAwareMetadataUpstream,
    state: RunState,
) -> None:
    case_root = inputs.root.child("enabled-upgrade")
    try:
        case_inputs = write_runtime_inputs(
            case_root,
            rules_file=inputs.rules_file,
            host_endpoint=inputs.configured_host_endpoint,
            upstream_endpoint=inputs.upstream_endpoint,
            configured_streaming=False,
            upgrade_request_body=True,
        )
        process, token = start_host(
            root=case_root,
            binary=inputs.binary,
            module_dir=inputs.module_dir,
            config=case_inputs["config"],
            library_dir=inputs.library_dir,
        )
        state.active_host = (process, token, "enabled-upgrade foreground lighttpd")
        wait_for_listener(inputs.configured_host_endpoint, True)
        baseline = upstream.accepted_connections()
        status = send_content_length(
            inputs.configured_host_endpoint,
            "body-bearing-upgrade-enabled",
            b"x",
            {"Connection": "Upgrade", "Upgrade": "websocket"},
        )
        if status != 501 or upstream.accepted_connections() != baseline:
            raise GateFailure("enabled body-bearing Upgrade did not fail closed")
        summary["cases"].append(
            {
                "label": "body_bearing_upgrade_enabled",
                "http_status": status,
                "upstream_connections_before": baseline,
                "upstream_connections_after": upstream.accepted_connections(),
            }
        )
        summary["cleanup"]["enabled_upgrade_lighttpd"] = stop_owned(
            process, token, "enabled-upgrade foreground lighttpd"
        )
        state.active_host = None
        wait_for_listener(inputs.configured_host_endpoint, False)
    finally:
        case_root.close()


def stop_active_host(state: RunState, summary: dict[str, Any]) -> None:
    if state.active_host is None:
        return
    process, token, label = state.active_host
    try:
        summary["cleanup"]["active_lighttpd"] = stop_owned(process, token, label)
    except Exception as exc:
        summary["cleanup"]["active_lighttpd_error"] = str(exc)
    state.active_host = None


def stop_upstream(state: RunState, summary: dict[str, Any]) -> None:
    if state.upstream is None:
        return
    try:
        state.upstream.stop()
        summary["cleanup"]["upstream"] = "stopped"
    except Exception as exc:
        summary["cleanup"]["upstream_error"] = str(exc)


def record_listener_cleanup(inputs: RunnerInputs, summary: dict[str, Any]) -> None:
    checks = (
        ("host_listener_after", inputs.host_endpoint),
        ("configured_host_listener_after", inputs.configured_host_endpoint),
        ("upstream_listener_after", inputs.upstream_endpoint),
    )
    for cleanup_key, endpoint in checks:
        summary["cleanup"][cleanup_key] = listener_rows(endpoint)
    if summary["result"] == "passed" and any(
        summary["cleanup"][cleanup_key] for cleanup_key, _ in checks
    ):
        summary["result"] = "failed"
        summary["error"] = "task-owned listener cleanup did not pass"


def cleanup_run(inputs: RunnerInputs, summary: dict[str, Any], state: RunState) -> None:
    stop_active_host(state, summary)
    stop_upstream(state, summary)
    try:
        record_listener_cleanup(inputs, summary)
    except Exception as exc:
        summary["cleanup"]["probe_error"] = str(exc)
        summary["result"] = "failed"


def main(argv: list[str] | None = None) -> int:
    inputs = parse_runner_inputs(argv)
    summary = new_summary(inputs)
    state = RunState()
    try:
        ensure_selected_ports_are_unused(inputs)
        state.upstream = ChunkAwareMetadataUpstream(inputs.upstream_endpoint)
        state.upstream.start()
        run_normal_profile(inputs, summary, state.upstream, state)
        run_configured_stream_case(inputs, summary, state.upstream, state)
        run_enabled_upgrade_case(inputs, summary, state.upstream, state)
        summary["upstream"] = state.upstream.snapshot()
        summary["result"] = "passed"
    except Exception as exc:
        summary["error"] = str(exc)
    finally:
        cleanup_run(inputs, summary, state)
        try:
            write_summary(inputs.root, summary)
        finally:
            inputs.root.close()
    return 0 if summary["result"] == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateFailure as exc:
        print(f"lighttpd Phase-2 pre-upstream gate: {exc}", file=sys.stderr)
        raise SystemExit(1)
