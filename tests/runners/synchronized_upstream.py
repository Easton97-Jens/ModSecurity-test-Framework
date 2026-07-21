"""Reusable synchronized streaming upstream for full-lifecycle host tests.

The server deliberately sends a small first response chunk and then waits for
the test harness to release a barrier.  This turns the low-latency assertion
into a causal fact: a client must observe response-body bytes while the
upstream is still paused and before it has sent EOS.

Only bounded metadata is emitted.  Test payloads are kept in memory long
enough to exercise a host path, but they are never copied into JSON evidence.
The direct helper is marked ``synthetic_harness`` by default; callers testing a
real connector must explicitly provide real-host metadata and attest the
origin.  The canonical validator rejects synthetic evidence for promotions.

Network and file-system boundary contract: listeners and probe targets use
only IPv4 loopback, and all control/evidence paths must resolve beneath one
existing absolute control root.  This rejects traversal and symlink escapes
before the harness opens a connection or performs file I/O.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import socket
import threading
import time
from typing import Any, Mapping


EVIDENCE_SCHEMA_VERSION = 1
EVIDENCE_TYPE = "synchronized_first_byte"
EVIDENCE_OUTPUT_PATH_LABEL = "evidence output path"
EVIDENCE_ORIGINS = frozenset({"synthetic_harness", "real_host"})
LOOPBACK_HOST = "127.0.0.1"
MAXIMUM_TCP_PORT = 65535
HOST_METADATA_FIELDS = frozenset(
    {
        "response_committed",
        "body_bytes_seen",
        "body_bytes_inspected",
        "no_full_response_buffering",
        "connector_owned_full_response_buffer",
    }
)
EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "evidence_type",
        "evidence_origin",
        "promotion_eligible",
        "client_first_byte_received",
        "first_byte_before_response_end",
        "first_chunk_size",
        "upstream_paused",
        "upstream_eos_sent_at_first_byte",
        "upstream_response_finished_at_first_byte",
        "response_committed",
        "body_bytes_seen",
        "body_bytes_inspected",
        "no_full_response_buffering",
        "connector_owned_full_response_buffer",
        "transport_protocol",
        "body_payload_persisted",
        "outcome",
    }
)
PAUSED_CONTROL_FIELDS = frozenset(
    {
        "schema_version",
        "evidence_type",
        "first_chunk_size",
        "upstream_paused",
        "upstream_eos_sent",
        "body_payload_persisted",
    }
)


class StreamingProbeError(RuntimeError):
    """Raised when a synchronized upstream/client exchange cannot complete."""


def _bool_or_none(value: object, *, field: str) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    raise ValueError(f"{field} must be Boolean or null")


def _non_negative_int_or_none(value: object, *, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    raise ValueError(f"{field} must be a non-negative integer or null")


def normalize_host_metadata(value: Mapping[str, object] | None) -> dict[str, object]:
    """Accept only bounded, payload-free host observations.

    The values are intentionally host-supplied because the reusable test
    server cannot infer how many bytes a connector handed to Common or whether
    a host committed its response.  The direct test helper leaves those values
    null rather than inventing host facts.
    """
    raw = dict(value or {})
    unknown = sorted(set(raw) - HOST_METADATA_FIELDS)
    if unknown:
        raise ValueError(f"unsupported host metadata fields: {', '.join(unknown)}")
    normalized = {
        "response_committed": _bool_or_none(
            raw.get("response_committed"), field="response_committed"
        ),
        "body_bytes_seen": _non_negative_int_or_none(
            raw.get("body_bytes_seen"), field="body_bytes_seen"
        ),
        "body_bytes_inspected": _non_negative_int_or_none(
            raw.get("body_bytes_inspected"), field="body_bytes_inspected"
        ),
        "no_full_response_buffering": _bool_or_none(
            raw.get("no_full_response_buffering"), field="no_full_response_buffering"
        ),
        "connector_owned_full_response_buffer": _bool_or_none(
            raw.get("connector_owned_full_response_buffer"),
            field="connector_owned_full_response_buffer",
        ),
    }
    seen = normalized["body_bytes_seen"]
    inspected = normalized["body_bytes_inspected"]
    if isinstance(seen, int) and isinstance(inspected, int) and inspected > seen:
        raise ValueError("body_bytes_inspected cannot exceed body_bytes_seen")
    no_buffer = normalized["no_full_response_buffering"]
    owned_buffer = normalized["connector_owned_full_response_buffer"]
    if no_buffer is True and owned_buffer is True:
        raise ValueError(
            "no_full_response_buffering=true conflicts with "
            "connector_owned_full_response_buffer=true"
        )
    return normalized


def _append_evidence_shape_errors(value: Mapping[Any, Any], errors: list[str]) -> None:
    keys = {str(key) for key in value}
    missing = sorted(EVIDENCE_FIELDS - keys)
    if missing:
        errors.append("first-byte evidence is missing fields: " + ", ".join(missing))
    unknown = sorted(keys - EVIDENCE_FIELDS)
    if unknown:
        errors.append(f"first-byte evidence has unsupported fields: {', '.join(unknown)}")
    if value.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
        errors.append("first-byte evidence schema_version must be 1")
    if value.get("evidence_type") != EVIDENCE_TYPE:
        errors.append("first-byte evidence_type is invalid")


def _append_evidence_origin_errors(
    value: Mapping[Any, Any], errors: list[str], require_real_host: bool
) -> None:
    origin = value.get("evidence_origin")
    if origin not in EVIDENCE_ORIGINS:
        errors.append("first-byte evidence_origin is invalid")
    elif value.get("promotion_eligible") is not (origin == "real_host"):
        errors.append("first-byte promotion_eligible does not match evidence_origin")
    if require_real_host and origin != "real_host":
        errors.append("synthetic first-byte evidence cannot support a canonical promotion")


def _append_optional_field_errors(value: Mapping[Any, Any], errors: list[str]) -> None:
    for field in (
        "client_first_byte_received",
        "first_byte_before_response_end",
        "upstream_paused",
        "upstream_eos_sent_at_first_byte",
        "upstream_response_finished_at_first_byte",
        "response_committed",
        "no_full_response_buffering",
        "connector_owned_full_response_buffer",
        "body_payload_persisted",
    ):
        try:
            _bool_or_none(value.get(field), field=field)
        except ValueError as exc:
            errors.append(str(exc))
    for field in ("first_chunk_size", "body_bytes_seen", "body_bytes_inspected"):
        try:
            _non_negative_int_or_none(value.get(field), field=field)
        except ValueError as exc:
            errors.append(str(exc))


def _append_evidence_consistency_errors(
    value: Mapping[Any, Any], errors: list[str]
) -> None:
    seen = value.get("body_bytes_seen")
    inspected = value.get("body_bytes_inspected")
    if isinstance(seen, int) and isinstance(inspected, int) and inspected > seen:
        errors.append("body_bytes_inspected cannot exceed body_bytes_seen")
    if (
        value.get("no_full_response_buffering") is True
        and value.get("connector_owned_full_response_buffer") is True
    ):
        errors.append(
            "no_full_response_buffering=true conflicts with "
            "connector_owned_full_response_buffer=true"
        )
    if value.get("transport_protocol") != "http1":
        errors.append("first-byte transport_protocol must be http1")
    if value.get("body_payload_persisted") is not False:
        errors.append("first-byte evidence must declare body_payload_persisted=false")
    if value.get("outcome") not in {"PASS", "FAIL"}:
        errors.append("first-byte evidence outcome must be PASS or FAIL")


def _append_complete_proof_errors(value: Mapping[Any, Any], errors: list[str]) -> None:
    for field in (
        "client_first_byte_received",
        "first_byte_before_response_end",
        "upstream_paused",
        "response_committed",
    ):
        if value.get(field) is not True:
            errors.append(f"first-byte proof requires {field}=true")
    if value.get("upstream_eos_sent_at_first_byte") is not False:
        errors.append("first-byte proof requires upstream_eos_sent_at_first_byte=false")
    if value.get("upstream_response_finished_at_first_byte") is not False:
        errors.append("first-byte proof requires upstream_response_finished_at_first_byte=false")
    if not isinstance(value.get("first_chunk_size"), int) or value["first_chunk_size"] < 1:
        errors.append("first-byte proof requires first_chunk_size > 0")
    for field in ("body_bytes_seen", "body_bytes_inspected"):
        if not isinstance(value.get(field), int):
            errors.append(f"first-byte proof requires host-supplied {field}")


def first_byte_evidence_errors(
    value: object,
    *,
    require_real_host: bool = False,
    require_complete_proof: bool = False,
) -> list[str]:
    """Validate the stable, payload-free first-byte evidence vocabulary."""
    if not isinstance(value, Mapping):
        return ["first-byte evidence must be a JSON object"]
    errors: list[str] = []
    _append_evidence_shape_errors(value, errors)
    _append_evidence_origin_errors(value, errors, require_real_host)
    _append_optional_field_errors(value, errors)
    _append_evidence_consistency_errors(value, errors)
    if require_complete_proof:
        _append_complete_proof_errors(value, errors)
    return errors


@dataclass(frozen=True)
class UpstreamAddress:
    host: str
    port: int


def _require_loopback_host(host: object, *, field: str) -> str:
    if host != LOOPBACK_HOST:
        raise ValueError(f"{field} must be the IPv4 loopback address {LOOPBACK_HOST}")
    return LOOPBACK_HOST


def _require_tcp_port(port: object, *, field: str, allow_zero: bool) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(port, bool) or not isinstance(port, int) or not minimum <= port <= MAXIMUM_TCP_PORT:
        range_label = f"{minimum}..{MAXIMUM_TCP_PORT}"
        raise ValueError(f"{field} must be an integer in {range_label}")
    return port


def _validated_target_port(host: object, port: object) -> int:
    _require_loopback_host(host, field="target_host")
    return _require_tcp_port(port, field="target_port", allow_zero=False)


def _require_control_root(control_root: str | Path) -> Path:
    """Return an existing, absolute root trusted for control-file I/O."""
    root = Path(control_root)
    if not root.is_absolute():
        raise ValueError("control_root must be an absolute directory")
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise ValueError("control_root must be an existing directory") from exc
    if not resolved.is_dir():
        raise ValueError("control_root must be an existing directory")
    return resolved


def _resolve_control_path(
    path: str | Path,
    *,
    control_root: Path,
    label: str,
) -> Path:
    """Resolve one absolute path and reject any escape from ``control_root``."""
    candidate = Path(path)
    if not candidate.is_absolute():
        raise ValueError(f"{label} must be an absolute path beneath control_root")
    try:
        resolved = candidate.resolve(strict=False)
    except OSError as exc:
        raise ValueError(f"{label} could not be resolved") from exc
    try:
        resolved.relative_to(control_root)
    except ValueError:
        raise ValueError(f"{label} must stay beneath control_root") from None
    return resolved


def _require_control_file(path: str | Path, *, control_root: Path, label: str) -> Path:
    resolved = _resolve_control_path(path, control_root=control_root, label=label)
    if not resolved.is_file():
        raise ValueError(f"{label} must be an existing regular file beneath control_root")
    return resolved


def _write_json_atomically(destination: Path, payload: Mapping[str, object]) -> None:
    """Write a bounded record after its destination has passed containment checks."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_text(
        json.dumps(dict(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(destination)


@dataclass(frozen=True)
class ControlFilePaths:
    """Control-file endpoints resolved below one explicit trusted root."""

    root: Path
    ready_file: Path
    release_file: Path
    paused_file: Path | None
    server_evidence_file: Path | None


def _resolve_control_file_paths(
    *,
    control_root: str | Path,
    ready_file: str | Path,
    release_file: str | Path,
    paused_file: str | Path | None,
    server_evidence_file: str | Path | None,
) -> ControlFilePaths:
    root = _require_control_root(control_root)
    return ControlFilePaths(
        root=root,
        ready_file=_resolve_control_path(ready_file, control_root=root, label="ready_file"),
        release_file=_resolve_control_path(
            release_file, control_root=root, label="release_file"
        ),
        paused_file=(
            _resolve_control_path(paused_file, control_root=root, label="paused_file")
            if paused_file is not None
            else None
        ),
        server_evidence_file=(
            _resolve_control_path(
                server_evidence_file,
                control_root=root,
                label="server_evidence_file",
            )
            if server_evidence_file is not None
            else None
        ),
    )


class SynchronizedStreamingUpstream:
    """A one-request HTTP/1.1 upstream that pauses before its later chunk."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        first_chunk: bytes = b"first-byte-prefix",
        # The canonical P4 rule (1100301) sees this only after the client has
        # received the first chunk and the harness releases the barrier.
        # It is deliberately never copied into JSON/log evidence.
        later_chunk: bytes = b"no-crs-response-body-marker",
        timeout: float = 10.0,
    ) -> None:
        if not first_chunk:
            raise ValueError("first_chunk must not be empty")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._requested_host = _require_loopback_host(host, field="host")
        self._requested_port = _require_tcp_port(port, field="port", allow_zero=True)
        self._first_chunk = bytes(first_chunk)
        self._later_chunk = bytes(later_chunk)
        self._timeout = timeout
        self._listener: socket.socket | None = None
        self._connection: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._first_chunk_sent = threading.Event()
        self._paused = threading.Event()
        self._release = threading.Event()
        self._eos_sent = threading.Event()
        self._closed = threading.Event()
        self._error: BaseException | None = None
        self._address: UpstreamAddress | None = None

    @property
    def address(self) -> UpstreamAddress:
        if self._address is None:
            raise StreamingProbeError("upstream has not been started")
        return self._address

    @property
    def first_chunk_size(self) -> int:
        return len(self._first_chunk)

    @property
    def eos_sent(self) -> bool:
        return self._eos_sent.is_set()

    @property
    def paused(self) -> bool:
        return self._paused.is_set() and not self._eos_sent.is_set()

    def start(self) -> UpstreamAddress:
        if self._thread is not None:
            return self.address
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.settimeout(self._timeout)
        listener.bind((self._requested_host, self._requested_port))
        listener.listen(1)
        bound_host, bound_port = listener.getsockname()[:2]
        self._listener = listener
        self._address = UpstreamAddress(str(bound_host), int(bound_port))
        self._thread = threading.Thread(
            target=self._serve_once,
            name="msconnector-synchronized-upstream",
            daemon=True,
        )
        self._thread.start()
        self._ready.set()
        return self.address

    def wait_until_paused(self, timeout: float | None = None) -> bool:
        waited = self._paused.wait(self._timeout if timeout is None else timeout)
        self._raise_if_failed()
        return waited and not self._eos_sent.is_set()

    def release(self) -> None:
        self._release.set()

    def close(self) -> None:
        self._release.set()
        for connection in (self._connection, self._listener):
            if connection is None:
                continue
            try:
                connection.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=self._timeout)
        self._closed.set()

    def __enter__(self) -> "SynchronizedStreamingUpstream":
        self.start()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def _raise_if_failed(self) -> None:
        if self._error is not None:
            raise StreamingProbeError("synchronized upstream failed") from self._error

    @staticmethod
    def _recv_request_headers(connection: socket.socket) -> None:
        data = bytearray()
        while b"\r\n\r\n" not in data:
            piece = connection.recv(4096)
            if not piece:
                raise StreamingProbeError("client closed before sending HTTP request headers")
            data.extend(piece)
            if len(data) > 65536:
                raise StreamingProbeError("HTTP request headers exceed the bounded test limit")

    @staticmethod
    def _chunk(payload: bytes) -> bytes:
        return f"{len(payload):X}\r\n".encode("ascii") + payload + b"\r\n"

    def _serve_once(self) -> None:
        try:
            listener = self._listener
            if listener is None:
                raise StreamingProbeError("upstream listener is unavailable")
            connection, _peer = listener.accept()
            self._connection = connection
            connection.settimeout(self._timeout)
            self._recv_request_headers(connection)
            connection.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Connection: close\r\n\r\n"
            )
            connection.sendall(self._chunk(self._first_chunk))
            self._first_chunk_sent.set()
            self._paused.set()
            if not self._release.wait(self._timeout):
                raise StreamingProbeError("test harness did not release the upstream barrier")
            connection.sendall(self._chunk(self._later_chunk))
            connection.sendall(b"0\r\n\r\n")
            self._eos_sent.set()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:  # thread errors must surface in the caller
            self._error = exc
        finally:
            if self._connection is not None:
                try:
                    self._connection.close()
                except OSError:
                    pass
            if self._listener is not None:
                try:
                    self._listener.close()
                except OSError:
                    pass
            self._closed.set()


def _read_until(sock: socket.socket, buffer: bytearray, marker: bytes, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while marker not in buffer:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise StreamingProbeError("timed out waiting for HTTP response headers")
        sock.settimeout(remaining)
        chunk = sock.recv(4096)
        if not chunk:
            raise StreamingProbeError("connection closed before the first response body chunk")
        buffer.extend(chunk)


def _read_chunked_first_body(sock: socket.socket, timeout: float) -> int:
    """Read headers and exactly the first chunk, retaining no body beyond it."""
    buffer = bytearray()
    _read_until(sock, buffer, b"\r\n\r\n", timeout)
    headers, remainder = bytes(buffer).split(b"\r\n\r\n", 1)
    if b"transfer-encoding: chunked" not in headers.lower():
        raise StreamingProbeError("synchronized probe requires a chunked HTTP/1.1 response")
    data = bytearray(remainder)
    _read_until(sock, data, b"\r\n", timeout)
    size_line, body = bytes(data).split(b"\r\n", 1)
    try:
        size = int(size_line.split(b";", 1)[0], 16)
    except ValueError as exc:
        raise StreamingProbeError("invalid first HTTP chunk length") from exc
    if size <= 0:
        raise StreamingProbeError("first HTTP chunk must contain response-body bytes")
    deadline = time.monotonic() + timeout
    while len(body) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise StreamingProbeError("timed out waiting for the first response-body chunk")
        sock.settimeout(remaining)
        piece = sock.recv(min(4096, size - len(body)))
        if not piece:
            raise StreamingProbeError("connection closed during the first response-body chunk")
        body += piece
    # ``body`` is intentionally discarded after measuring its length.
    return size


def _drain_response(sock: socket.socket, timeout: float) -> None:
    """Drain the remaining response after release without persisting content."""
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise StreamingProbeError("timed out draining the released response")
        sock.settimeout(remaining)
        data = sock.recv(4096)
        if not data:
            return


def run_client_barrier(
    *,
    target_host: str,
    target_port: int,
    upstream: SynchronizedStreamingUpstream,
    request_path: str = "/",
    timeout: float = 10.0,
    host_metadata: Mapping[str, object] | None = None,
    evidence_origin: str = "synthetic_harness",
) -> dict[str, object]:
    """Drive a client through a configured host while an upstream is paused.

    ``target_host``/``target_port`` may point directly at the reusable server
    for a synthetic unit test, or at a real connector configured to proxy to
    ``upstream.address``.  Both endpoints are restricted to IPv4 loopback, so
    a connector under test must run on the same local test host.  The result
    never contains either response chunk.
    """
    if evidence_origin not in EVIDENCE_ORIGINS:
        raise ValueError("evidence_origin must be synthetic_harness or real_host")
    if not request_path.startswith("/") or "\r" in request_path or "\n" in request_path:
        raise ValueError("request_path must be an absolute HTTP path without control characters")
    target_port = _validated_target_port(target_host, target_port)
    if (
        evidence_origin == "real_host"
        and target_host == upstream.address.host
        and target_port == upstream.address.port
    ):
        raise ValueError(
            "real_host evidence target must be distinct from the synthetic upstream"
        )
    metadata = normalize_host_metadata(host_metadata)
    client_first_byte_received = False
    first_chunk_size = 0
    upstream_paused = False
    upstream_eos_at_first_byte = False
    outcome = "FAIL"
    try:
        with socket.create_connection((LOOPBACK_HOST, target_port), timeout=timeout) as client:
            client.sendall(
                f"GET {request_path} HTTP/1.1\r\n"
                f"Host: {LOOPBACK_HOST}\r\n"
                "Connection: close\r\n\r\n".encode("ascii")
            )
            first_chunk_size = _read_chunked_first_body(client, timeout)
            client_first_byte_received = first_chunk_size > 0
            upstream_paused = upstream.wait_until_paused(timeout=timeout)
            upstream_eos_at_first_byte = upstream.eos_sent
            outcome = "PASS" if client_first_byte_received and upstream_paused and not upstream_eos_at_first_byte else "FAIL"
            upstream.release()
            _drain_response(client, timeout)
    finally:
        upstream.release()
    upstream._raise_if_failed()
    response_committed = metadata["response_committed"]
    if response_committed is None:
        # Delivery of a response-body byte is a client-observed commit fact.
        response_committed = client_first_byte_received
    evidence: dict[str, object] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "evidence_type": EVIDENCE_TYPE,
        "evidence_origin": evidence_origin,
        "promotion_eligible": evidence_origin == "real_host",
        "client_first_byte_received": client_first_byte_received,
        "first_byte_before_response_end": client_first_byte_received and not upstream_eos_at_first_byte,
        "first_chunk_size": first_chunk_size,
        "upstream_paused": upstream_paused,
        "upstream_eos_sent_at_first_byte": upstream_eos_at_first_byte,
        "upstream_response_finished_at_first_byte": upstream_eos_at_first_byte,
        "response_committed": response_committed,
        "body_bytes_seen": metadata["body_bytes_seen"],
        "body_bytes_inspected": metadata["body_bytes_inspected"],
        "no_full_response_buffering": metadata["no_full_response_buffering"],
        "connector_owned_full_response_buffer": metadata["connector_owned_full_response_buffer"],
        "transport_protocol": "http1",
        "body_payload_persisted": False,
        "outcome": outcome,
    }
    errors = first_byte_evidence_errors(evidence)
    if errors:
        raise StreamingProbeError("; ".join(errors))
    return evidence


def write_evidence(
    path: str | Path,
    evidence: Mapping[str, object],
    *,
    control_root: str | Path,
) -> None:
    """Write validated evidence below the caller's explicit trusted root."""
    errors = first_byte_evidence_errors(evidence)
    if errors:
        raise ValueError("; ".join(errors))
    root = _require_control_root(control_root)
    destination = _resolve_control_path(
        path, control_root=root, label=EVIDENCE_OUTPUT_PATH_LABEL
    )
    _write_json_atomically(destination, evidence)


def _load_json_object(
    path: str | Path,
    *,
    control_root: str | Path,
    label: str,
) -> dict[str, object]:
    root = _require_control_root(control_root)
    source = _require_control_file(path, control_root=root, label=label)
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} JSON must be an object")
    return {str(key): value for key, value in payload.items()}


def _load_host_metadata(
    path: str | Path | None,
    *,
    control_root: str | Path,
) -> Mapping[str, object] | None:
    if path is None:
        return None
    return _load_json_object(
        path,
        control_root=control_root,
        label="host metadata",
    )


def _write_control_json(
    path: str | Path,
    payload: Mapping[str, object],
    *,
    control_root: str | Path,
) -> None:
    """Publish a bounded control record below the explicit trusted root."""
    root = _require_control_root(control_root)
    destination = _resolve_control_path(
        path, control_root=root, label="control output path"
    )
    _write_json_atomically(destination, payload)


def _require_fresh_control_files(paths: ControlFilePaths) -> None:
    stale = [
        path
        for path in (paths.ready_file, paths.release_file, paths.paused_file)
        if path is not None and path.exists()
    ]
    if stale:
        raise ValueError(
            "control-file daemon requires fresh paths: "
            + ", ".join(str(path) for path in stale)
        )


def _ready_control_payload(address: UpstreamAddress) -> dict[str, object]:
    return {
        "schema_version": 1,
        "evidence_type": "synchronized_upstream_ready",
        "upstream_host": address.host,
        "upstream_port": address.port,
        "body_payload_persisted": False,
    }


def _paused_control_payload(upstream: SynchronizedStreamingUpstream) -> dict[str, object]:
    return {
        "schema_version": 1,
        "evidence_type": "synchronized_upstream_paused",
        "first_chunk_size": upstream.first_chunk_size,
        "upstream_paused": True,
        "upstream_eos_sent": False,
        "body_payload_persisted": False,
    }


def _server_control_payload(
    upstream: SynchronizedStreamingUpstream, paused_published: bool
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "evidence_type": "synchronized_upstream_server",
        "first_chunk_size": upstream.first_chunk_size,
        "upstream_paused": paused_published,
        "upstream_eos_sent": True,
        "body_payload_persisted": False,
    }


def _publish_pause_record(
    upstream: SynchronizedStreamingUpstream,
    paths: ControlFilePaths,
    paused_published: bool,
) -> bool:
    if not upstream.paused or paused_published:
        return paused_published
    if paths.paused_file is not None:
        _write_control_json(
            paths.paused_file,
            _paused_control_payload(upstream),
            control_root=paths.root,
        )
    return True


def _wait_for_release_file(
    upstream: SynchronizedStreamingUpstream,
    paths: ControlFilePaths,
    deadline: float,
) -> bool:
    paused_published = False
    while not upstream.eos_sent:
        upstream._raise_if_failed()
        paused_published = _publish_pause_record(upstream, paths, paused_published)
        if paths.release_file.exists():
            upstream.release()
        if time.monotonic() >= deadline:
            raise StreamingProbeError("timed out waiting for release-file")
        time.sleep(0.01)
    return paused_published


def serve_with_control_files(
    *,
    control_root: str | Path,
    ready_file: str | Path,
    release_file: str | Path,
    paused_file: str | Path | None = None,
    server_evidence_file: str | Path | None = None,
    host: str = "127.0.0.1",
    port: int = 0,
    timeout: float = 30.0,
) -> None:
    """Run an upstream daemon controlled by ready/paused/release files.

    This is the process-oriented counterpart to :func:`run_client_barrier`.
    A connector harness starts this daemon, configures its proxy upstream from
    ``ready_file``, waits for the client-visible first chunk while
    ``paused_file`` says EOS is still absent, and creates ``release_file``.
    The optional server-evidence record contains counts and state only; the
    host runner must combine its client/connector observations into the
    canonical first-byte evidence artifact.
    """
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    paths = _resolve_control_file_paths(
        control_root=control_root,
        ready_file=ready_file,
        release_file=release_file,
        paused_file=paused_file,
        server_evidence_file=server_evidence_file,
    )
    _require_fresh_control_files(paths)
    deadline = time.monotonic() + timeout
    with SynchronizedStreamingUpstream(host=host, port=port, timeout=timeout) as upstream:
        _write_control_json(
            paths.ready_file,
            _ready_control_payload(upstream.address),
            control_root=paths.root,
        )
        paused_published = _wait_for_release_file(upstream, paths, deadline)
        upstream._raise_if_failed()
        if paths.server_evidence_file is not None:
            _write_control_json(
                paths.server_evidence_file,
                _server_control_payload(upstream, paused_published),
                control_root=paths.root,
            )


def merge_first_byte_evidence(
    paused_record: Mapping[str, object],
    *,
    client_first_byte_received: bool,
    host_metadata: Mapping[str, object] | None = None,
    evidence_origin: str = "synthetic_harness",
) -> dict[str, object]:
    """Merge daemon pause state with client/connector observations safely.

    The merger uses the pause record captured *before* release.  It never
    reads the client-output file or any response payload; callers pass only a
    Boolean established from the file's non-zero byte count.
    """
    if evidence_origin not in EVIDENCE_ORIGINS:
        raise ValueError("evidence_origin must be synthetic_harness or real_host")
    if paused_record.get("schema_version") != 1:
        raise ValueError("paused control record schema_version must be 1")
    unknown = sorted({str(key) for key in paused_record} - PAUSED_CONTROL_FIELDS)
    if unknown:
        raise ValueError("paused control record has unsupported fields: " + ", ".join(unknown))
    if paused_record.get("evidence_type") != "synchronized_upstream_paused":
        raise ValueError("paused control record evidence_type is invalid")
    first_chunk_size = paused_record.get("first_chunk_size")
    if not isinstance(first_chunk_size, int) or isinstance(first_chunk_size, bool) or first_chunk_size < 1:
        raise ValueError("paused control record first_chunk_size must be a positive integer")
    if paused_record.get("upstream_paused") is not True:
        raise ValueError("paused control record must set upstream_paused=true")
    if paused_record.get("upstream_eos_sent") is not False:
        raise ValueError("paused control record must set upstream_eos_sent=false")
    if paused_record.get("body_payload_persisted") is not False:
        raise ValueError("paused control record must set body_payload_persisted=false")
    metadata = normalize_host_metadata(host_metadata)
    response_committed = metadata["response_committed"]
    if response_committed is None:
        response_committed = client_first_byte_received
    evidence: dict[str, object] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "evidence_type": EVIDENCE_TYPE,
        "evidence_origin": evidence_origin,
        "promotion_eligible": evidence_origin == "real_host",
        "client_first_byte_received": client_first_byte_received,
        "first_byte_before_response_end": client_first_byte_received,
        "first_chunk_size": first_chunk_size,
        "upstream_paused": True,
        "upstream_eos_sent_at_first_byte": False,
        "upstream_response_finished_at_first_byte": False,
        "response_committed": response_committed,
        "body_bytes_seen": metadata["body_bytes_seen"],
        "body_bytes_inspected": metadata["body_bytes_inspected"],
        "no_full_response_buffering": metadata["no_full_response_buffering"],
        "connector_owned_full_response_buffer": metadata["connector_owned_full_response_buffer"],
        "transport_protocol": "http1",
        "body_payload_persisted": False,
        "outcome": "PASS" if client_first_byte_received else "FAIL",
    }
    errors = first_byte_evidence_errors(evidence)
    if errors:
        raise ValueError("; ".join(errors))
    return evidence


def _parse_tcp_port_argument(value: str, *, field: str, allow_zero: bool) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{field} must be an integer") from exc
    try:
        return _require_tcp_port(port, field=field, allow_zero=allow_zero)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _parse_listen_port(value: str) -> int:
    return _parse_tcp_port_argument(value, field="listen_port", allow_zero=True)


def _parse_target_port(value: str) -> int:
    return _parse_tcp_port_argument(value, field="target_port", allow_zero=False)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--serve",
        action="store_true",
        help="run a control-file daemon instead of a direct synthetic probe",
    )
    parser.add_argument(
        "--merge-evidence",
        action="store_true",
        help="merge a paused daemon record with bounded client/host observations",
    )
    parser.add_argument(
        "--control-root",
        type=Path,
        required=True,
        help="existing absolute trusted root for every control and evidence file",
    )
    parser.add_argument("--listen-host", choices=(LOOPBACK_HOST,), default=LOOPBACK_HOST)
    parser.add_argument("--listen-port", type=_parse_listen_port, default=0)
    parser.add_argument("--ready-file")
    parser.add_argument("--paused-file")
    parser.add_argument("--release-file")
    parser.add_argument("--server-evidence-file")
    parser.add_argument("--target-host", choices=(LOOPBACK_HOST,), default=LOOPBACK_HOST)
    parser.add_argument("--target-port", type=_parse_target_port)
    parser.add_argument("--request-path", default="/")
    parser.add_argument("--output")
    parser.add_argument(
        "--client-first-byte-file",
        help="client body-output file; only non-zero size is observed",
    )
    parser.add_argument(
        "--client-first-byte-received",
        choices=("true", "false"),
        help="explicit observation when no client output file is available",
    )
    parser.add_argument("--host-metadata-json")
    parser.add_argument(
        "--evidence-origin",
        choices=sorted(EVIDENCE_ORIGINS),
        default="synthetic_harness",
    )
    parser.add_argument("--timeout", type=float, default=10.0)
    return parser


def _parse_control_root(parser: argparse.ArgumentParser, args: argparse.Namespace) -> Path:
    try:
        return _require_control_root(args.control_root)
    except ValueError as exc:
        parser.error(str(exc))
        raise AssertionError("argparse.error unexpectedly returned") from exc


def _client_first_byte_received_from_args(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    control_root: Path,
) -> bool:
    if args.client_first_byte_file:
        client_output = _resolve_control_path(
            args.client_first_byte_file,
            control_root=control_root,
            label="client_first_byte_file",
        )
        return client_output.is_file() and client_output.stat().st_size > 0
    if args.client_first_byte_received is not None:
        return args.client_first_byte_received == "true"
    parser.error(
        "--merge-evidence requires --client-first-byte-file or "
        "--client-first-byte-received"
    )
    raise AssertionError("argparse.error unexpectedly returned")


def _run_serve_mode(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    control_root: Path,
) -> int:
    if not args.ready_file or not args.release_file:
        parser.error("--serve requires --ready-file and --release-file")
    serve_with_control_files(
        control_root=control_root,
        ready_file=args.ready_file,
        paused_file=args.paused_file,
        release_file=args.release_file,
        server_evidence_file=args.server_evidence_file,
        host=args.listen_host,
        port=args.listen_port,
        timeout=args.timeout,
    )
    return 0


def _run_merge_evidence_mode(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    control_root: Path,
) -> int:
    if not args.paused_file or not args.output:
        parser.error("--merge-evidence requires --paused-file and --output")
    client_first_byte_received = _client_first_byte_received_from_args(
        parser, args, control_root
    )
    if args.evidence_origin == "real_host" and not args.client_first_byte_file:
        parser.error(
            "real_host merge evidence requires --client-first-byte-file so the "
            "client observation is file-backed"
        )
    output = _resolve_control_path(
        args.output, control_root=control_root, label=EVIDENCE_OUTPUT_PATH_LABEL
    )
    evidence = merge_first_byte_evidence(
        _load_json_object(
            args.paused_file,
            control_root=control_root,
            label="paused control record",
        ),
        client_first_byte_received=client_first_byte_received,
        host_metadata=_load_host_metadata(
            args.host_metadata_json,
            control_root=control_root,
        ),
        evidence_origin=args.evidence_origin,
    )
    write_evidence(output, evidence, control_root=control_root)
    print(output)
    return 0 if evidence["outcome"] == "PASS" else 1


def _run_direct_mode(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    control_root: Path,
) -> int:
    if not args.output:
        parser.error("--output is required unless --serve is used")
    if args.target_port is None and args.evidence_origin != "synthetic_harness":
        parser.error("a direct probe without --target-port is always synthetic_harness")
    output = _resolve_control_path(
        args.output, control_root=control_root, label=EVIDENCE_OUTPUT_PATH_LABEL
    )
    metadata = _load_host_metadata(args.host_metadata_json, control_root=control_root)

    # With no target port the CLI performs a deliberately synthetic direct
    # proof.  Connector runners normally import the class, start it first,
    # configure their host with ``upstream.address``, then call the client
    # helper against the host endpoint.
    with SynchronizedStreamingUpstream(
        host=args.listen_host, port=args.listen_port, timeout=args.timeout
    ) as upstream:
        target_port = args.target_port or upstream.address.port
        evidence = run_client_barrier(
            target_host=args.target_host,
            target_port=target_port,
            upstream=upstream,
            request_path=args.request_path,
            timeout=args.timeout,
            host_metadata=metadata,
            evidence_origin=args.evidence_origin,
        )
    write_evidence(output, evidence, control_root=control_root)
    print(output)
    return 0 if evidence["outcome"] == "PASS" else 1


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.serve and args.merge_evidence:
        parser.error("--serve and --merge-evidence are mutually exclusive")
    control_root = _parse_control_root(parser, args)
    if args.serve:
        return _run_serve_mode(parser, args, control_root)
    if args.merge_evidence:
        return _run_merge_evidence_mode(parser, args, control_root)
    return _run_direct_mode(parser, args, control_root)


if __name__ == "__main__":
    raise SystemExit(main())
