#!/usr/bin/env python3
"""Small dependency-free upstream/probe helper for the Envoy connector smoke."""

from __future__ import annotations

import argparse
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import sys
import threading
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request


from modsecurity_connector_ci.lib.runtime_path_utils import append_runtime_artifact_text, ensure_safe_runtime_directory, open_runtime_artifact_parent, read_runtime_artifact_text, require_regular_runtime_artifact, runtime_artifact_path, verified_runtime_artifact_root, write_runtime_artifact_text_atomic


P2_BODY_LIMIT_PATH = "/vector/p2-body-limit"
P2_BODY_LIMIT_UPSTREAM_MARKER = "upstream-p2-body-limit.reached"
P3_REDIRECT_PATH = "/vector/p3-redirect"
PHASE4_MARKER_PATH = "/vector/p4-safe"
TEXT_PLAIN_CONTENT_TYPE = "text/plain"
LOOPBACK_HOST = "127.0.0.1"
COMMON_EVENT_LOG_LABEL = "Common event log"
NOFOLLOW_WRITE_ERROR = "safe runtime artifact writes require O_NOFOLLOW"
LOOPBACK_TLS_CERTIFICATE_LABEL = "loopback TLS certificate"
LOOPBACK_TLS_PRIVATE_KEY_LABEL = "loopback TLS private key"


class Phase4HandlerLifecycle:
    """Track accepted request threads until their final path exits."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._active = 0

    def begin(self) -> None:
        with self._condition:
            self._active += 1

    def end(self) -> None:
        with self._condition:
            if self._active < 1:
                raise RuntimeError("phase-4 handler lifecycle underflow")
            self._active -= 1
            if self._active == 0:
                self._condition.notify_all()

    def wait_idle(self, timeout: float) -> None:
        if timeout <= 0:
            raise ValueError("phase-4 handler lifecycle timeout must be positive")
        deadline = time.monotonic() + timeout
        with self._condition:
            while self._active:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("timed out waiting for active phase-4 handlers")
                self._condition.wait(timeout=remaining)


class _Phase4TrackingServer:
    """Mix in request-thread tracking without changing the transport type."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.phase4_handler_lifecycle = Phase4HandlerLifecycle()

    def process_request(self, request: Any, client_address: Any) -> None:
        self.phase4_handler_lifecycle.begin()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.phase4_handler_lifecycle.end()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.phase4_handler_lifecycle.end()


class Phase4TrackingHTTPServer(_Phase4TrackingServer, http.server.ThreadingHTTPServer):
    """Plain HTTP fixture server with request-thread lifecycle tracking."""


class Phase4TrackingHTTPSServer(_Phase4TrackingServer, http.server.ThreadingHTTPSServer):
    """TLS fixture server with request-thread lifecycle tracking."""


def wait_for_phase4_handlers(server: object, timeout: float) -> None:
    """Prove configured phase-4 handlers have left all write/error paths."""

    lifecycle = getattr(server, "phase4_handler_lifecycle", None)
    if lifecycle is not None:
        if not isinstance(lifecycle, Phase4HandlerLifecycle):
            raise TypeError("server phase-4 handler lifecycle has an invalid type")
        lifecycle.wait_idle(timeout)


def verified_runtime_root(value: str) -> Path:
    """Return a private root that may contain this invocation's artifacts."""
    return verified_runtime_artifact_root(value)


def runtime_artifact(root: Path, value: str | Path, label: str) -> Path:
    """Validate one artifact path below the current private runtime root."""

    return runtime_artifact_path(root, value, label)


def runtime_directory(root: Path, value: str | Path, label: str) -> Path:
    """Create or return one safe artifact directory below ``root``."""

    directory = runtime_artifact(root, value, label)
    return ensure_safe_runtime_directory(directory)


def read_runtime_text(root: Path, value: str | Path, label: str) -> str:
    """Read one regular artifact without following its final path component."""
    return read_runtime_artifact_text(root, value, label)


def write_json_atomic(root: Path, value: str | Path, payload: dict[str, object], label: str) -> Path:
    """Replace one private JSON artifact atomically without following links."""

    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    return write_runtime_artifact_text_atomic(root, value, encoded, label)


def append_jsonl(root: Path, value: str | Path, payload: dict[str, object], label: str) -> Path:
    """Append one JSONL record through a no-follow descriptor."""

    encoded = json.dumps(payload, sort_keys=True) + "\n"
    return append_runtime_artifact_text(root, value, encoded, label)


def create_runtime_marker(root: Path, value: str | Path, label: str) -> Path:
    """Create one empty private control marker without replacing an existing file."""

    target = runtime_artifact(root, value, label)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ValueError(NOFOLLOW_WRITE_ERROR)
    parent_descriptor = open_runtime_artifact_parent(target)
    try:
        descriptor = os.open(
            target.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
            0o600,
            dir_fd=parent_descriptor,
        )
        try:
            require_regular_runtime_artifact(descriptor, label)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_descriptor)
    return target


def trusted_loopback_tls_context(root: Path, certificate_path: str) -> ssl.SSLContext:
    """Trust a regular certificate under ``root`` for one loopback client."""

    certificate = runtime_artifact(root, certificate_path, LOOPBACK_TLS_CERTIFICATE_LABEL)
    if not certificate.is_file() or certificate.is_symlink():
        raise ValueError(f"{LOOPBACK_TLS_CERTIFICATE_LABEL} must be a regular file")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=str(certificate))
    return context


def loopback_tls_server_files(root: Path, certificate_path: str, private_key_path: str) -> tuple[Path, Path]:
    """Return regular, runtime-confined certificate files for the fixture server."""

    certificate = runtime_artifact(root, certificate_path, LOOPBACK_TLS_CERTIFICATE_LABEL)
    private_key = runtime_artifact(root, private_key_path, LOOPBACK_TLS_PRIVATE_KEY_LABEL)
    for path, label in ((certificate, LOOPBACK_TLS_CERTIFICATE_LABEL), (private_key, LOOPBACK_TLS_PRIVATE_KEY_LABEL)):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"{label} must be a regular file")
    return certificate, private_key


def checked_loopback_https_url(value: str) -> str:
    """Accept only a credential-free HTTPS endpoint on the fixed smoke host."""

    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("probe URL has an invalid port") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != LOOPBACK_HOST
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port is None
        or port < 1
        or port > 65535
    ):
        raise ValueError("probe URL must be credential-free https://127.0.0.1 with a valid port")
    return value


def checked_loopback_host(value: str) -> str:
    if value != LOOPBACK_HOST:
        raise ValueError("host must be 127.0.0.1")
    return value


class UpstreamHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    client_cancel_delay_seconds = 5.0
    phase4_barrier_dir: Path | None = None
    phase4_barrier_timeout_seconds = 10.0
    runtime_root: Path | None = None

    def log_message(self, fmt: str, *args: object) -> None:
        del fmt, args

    def answer(self) -> None:
        content_length = int(self.headers.get("content-length") or "0")
        if content_length > 0:
            self.rfile.read(content_length)
        if self.path == P2_BODY_LIMIT_PATH and self.runtime_root is not None:
            # The native runner requires this marker to remain absent.  Its
            # presence proves that an over-limit request reached the upstream,
            # while the marker itself contains no client bytes or identity.
            create_runtime_marker(
                self.runtime_root,
                self.runtime_root / P2_BODY_LIMIT_UPSTREAM_MARKER,
                "P2 body-limit upstream marker",
            )
        if self.path == PHASE4_MARKER_PATH and self.phase4_barrier_dir is not None:
            self._answer_phase4_barrier()
            return
        if self.path == "/client-cancel":
            self._answer_client_cancel()
            return
        self._answer_standard()

    def _answer_client_cancel(self) -> None:
        """Send the delayed two-part response used by the cancel probe."""
        # This fixture sends one real response byte and deliberately holds
        # the final bytes open.  The opt-in runtime probe closes the
        # downstream client socket after that first byte.  It is not used
        # to infer a reset code or to promote strict behavior.
        first_chunk = b"envoy-client-cancel-first-byte\n"
        final_chunk = b"envoy-client-cancel-final-byte\n"
        self.send_response(200)
        self.send_header("content-type", TEXT_PLAIN_CONTENT_TYPE)
        self.send_header("content-length", str(len(first_chunk) + len(final_chunk)))
        self.end_headers()
        try:
            self.wfile.write(first_chunk)
            self.wfile.flush()
            time.sleep(self.client_cancel_delay_seconds)
            self.wfile.write(final_chunk)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return

    def _answer_standard(self) -> None:
        response_headers: list[tuple[str, str]] = []
        if self.path == "/phase3-block":
            response_headers.append(("X-Modsec-Upstream", "block"))
        elif self.path == "/vector/p3":
            response_headers.append(("X-Msconnector-Vector", "msconnector-p3-only"))
        elif self.path == P3_REDIRECT_PATH:
            response_headers.append(("X-Msconnector-Vector", "msconnector-p3-redirect"))
        body = self._standard_body()
        self.send_response(200)
        self.send_header("content-type", TEXT_PLAIN_CONTENT_TYPE)
        for name, value in response_headers:
            self.send_header(name, value)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _standard_body(self) -> bytes:
        if self.path == "/phase4-marker":
            return b"no-crs-response-body-marker\n"
        if self.path == "/vector/p4":
            return b"p4-response-msconnector-p4-only"
        if self.path == "/vector/p4-safe":
            return b"p4-safe-response-msconnector-p4-safe"
        return b"envoy connector upstream ok\n"

    def _answer_phase4_barrier(self) -> None:
        """Serve a controlled P4 body without persisting either body chunk.

        The first chunk is intentionally harmless.  The canonical P4 marker
        follows only after the downstream client has read a body chunk while
        the upstream has published its paused/EOS-false control record and
        created the release file.  The JSON controls contain state and sizes
        only; they never contain either fixture payload.
        """
        assert self.phase4_barrier_dir is not None
        assert self.runtime_root is not None
        paths = phase4_barrier_paths(self.runtime_root, self.phase4_barrier_dir)
        first_chunk = b"envoy-first-byte-prefix\n"
        later_chunk = b"p4-safe-response-msconnector-p4-safe"
        self.send_response(200)
        self.send_header("content-type", TEXT_PLAIN_CONTENT_TYPE)
        self.send_header("transfer-encoding", "chunked")
        self.send_header("connection", "close")
        self.end_headers()
        try:
            self._write_chunk(first_chunk)
            write_json_atomic(self.runtime_root, paths["paused"], {
                "schema_version": 1,
                "evidence_type": "envoy_phase4_upstream_paused",
                "first_chunk_size": len(first_chunk),
                "upstream_paused": True,
                "upstream_eos_sent": False,
                "body_payload_persisted": False,
            }, "upstream phase-4 pause record")
            wait_for_release(self.runtime_root, paths["release"], self.phase4_barrier_timeout_seconds)
            self._write_chunk(later_chunk)
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
            write_json_atomic(self.runtime_root, paths["completed"], {
                "schema_version": 1,
                "evidence_type": "envoy_phase4_upstream_completed",
                "first_chunk_size": len(first_chunk),
                "upstream_eos_sent": True,
                "body_payload_persisted": False,
            }, "upstream phase-4 completion record")
        except (BrokenPipeError, ConnectionResetError):
            # A failed client is not a successful barrier observation.  Leave
            # the completed record absent so the probe rejects the run.
            return

    def _write_chunk(self, payload: bytes) -> None:
        self.wfile.write(f"{len(payload):X}\r\n".encode("ascii"))
        self.wfile.write(payload)
        self.wfile.write(b"\r\n")
        self.wfile.flush()

    do_GET = answer
    do_HEAD = answer
    do_POST = answer


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def free_ports(count: int) -> list[int]:
    sockets: list[socket.socket] = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            sockets.append(sock)
        return [int(sock.getsockname()[1]) for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


def phase4_barrier_paths(root: Path, barrier_dir: str | Path) -> dict[str, Path]:
    directory = runtime_directory(root, barrier_dir, "phase-4 barrier directory")
    return {
        "paused": directory / "upstream-paused.json",
        "release": directory / "release",
        "completed": directory / "upstream-completed.json",
    }


def wait_for_release(root: Path, path: Path, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("timed out waiting for phase-4 barrier release")
        time.sleep(0.01)
    read_runtime_text(root, path, "phase-4 barrier release")


def serve_upstream(
    port: int,
    client_cancel_delay: float,
    runtime_root: str,
    tls_certificate: str,
    tls_private_key: str,
    phase4_barrier_dir: str | None = None,
    phase4_barrier_timeout: float = 10.0,
) -> int:
    if client_cancel_delay <= 0 or client_cancel_delay > 30:
        raise ValueError("client cancel delay must be greater than zero and at most 30 seconds")
    if phase4_barrier_timeout <= 0 or phase4_barrier_timeout > 60:
        raise ValueError("phase-4 barrier timeout must be greater than zero and at most 60 seconds")
    root = verified_runtime_root(runtime_root)
    certificate, private_key = loopback_tls_server_files(root, tls_certificate, tls_private_key)
    barrier_directory = (
        runtime_directory(root, phase4_barrier_dir, "phase-4 barrier directory")
        if phase4_barrier_dir
        else None
    )
    if barrier_directory is not None:
        paths = phase4_barrier_paths(root, barrier_directory)
        if any(path.exists() for path in paths.values()):
            raise ValueError("phase-4 barrier paths must be fresh")

    class DelayedUpstreamHandler(UpstreamHandler):
        client_cancel_delay_seconds = client_cancel_delay
        phase4_barrier_dir = barrier_directory
        phase4_barrier_timeout_seconds = phase4_barrier_timeout
        runtime_root = root

    server = Phase4TrackingHTTPSServer(
        (LOOPBACK_HOST, port),
        DelayedUpstreamHandler,
        certfile=str(certificate),
        keyfile=str(private_key),
    )
    server.socket.context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


def parse_headers(header: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in header:
        name, separator, value = item.partition(":")
        if (
            not separator
            or not name.strip()
            or any(control in name or control in value for control in "\r\n\x00")
        ):
            raise ValueError(f"invalid header: {item!r}")
        headers[name.strip()] = value.strip()
    return headers


def parse_header_names(header: list[str]) -> set[str]:
    """Normalize response-header assertions without retaining their values."""

    names: set[str] = set()
    for value in header:
        name = value.strip().lower()
        if not name or any(character in name for character in "\r\n:"):
            raise ValueError(f"invalid header name: {value!r}")
        names.add(name)
    return names


def parse_required_response_headers(header: list[str]) -> dict[str, str]:
    """Normalize exact response-header assertions without retaining them."""

    required: dict[str, str] = {}
    for item in header:
        parsed = parse_headers([item])
        name, value = next(iter(parsed.items()))
        normalized_name = name.lower()
        if normalized_name in required:
            raise ValueError("duplicate required response header")
        required[normalized_name] = value
    return required


def _response_header_values(headers: Any, name: str) -> list[str]:
    """Return every response field value so duplicates cannot satisfy an exact assertion."""

    get_all = getattr(headers, "get_all", None)
    if not callable(get_all):
        raise RuntimeError("response headers do not support complete field inspection")
    values = get_all(name)
    return [] if values is None else list(values)


def _read_probe_response(response, read_error):
    status = int(response.status if hasattr(response, "status") else response.code)
    response_headers = response.headers
    try:
        response_body = response.read()
    except (OSError, http.client.HTTPException) as exc:
        read_error = True
        partial = getattr(exc, "partial", b"")
        response_body = partial if isinstance(partial, bytes) else b""
    return status, response_headers, response_body, read_error



def _matching_probe_transactions(records, request_id):
    return {
        record.get("transaction_id")
        for line in records
        if line.strip()
        for record in [json.loads(line)]
        if isinstance(record, dict) and record.get("transaction_id") == request_id
    }


def _probe_host_transaction(root, observation, event_path):
    try:
        events = Path(event_path)
        observation["decision_log_path"] = str(
            runtime_artifact(root, events, "probe event log")
        )
        if events.is_file() and observation["request_id"]:
            records = read_runtime_text(root, events, "probe event log").splitlines()
            transactions = _matching_probe_transactions(
                records, observation["request_id"]
            )
            if len(transactions) == 1:
                observation["transaction_id"] = transactions.pop()
                observation["transaction_ids"] = [observation["transaction_id"]]
    except (OSError, ValueError):
        observation["identity_error"] = (
            "host transaction evidence could not be read safely"
        )
        observation["status"] = "FAIL"


def _probe_observation_identity(root, url, observation):
    case_ids = {
        "/allowed": "allow_without_marker",
        "/vector/p1": "deny_header_marker_403",
        "/vector/p2": "deny_request_body_marker_403",
        "/vector/p3": "deny_response_header_marker_403",
        "/vector/p3-redirect": "phase3_redirect_before_commit",
    }
    # Persist completed traffic before a client assertion can abort the helper.
    # Readiness and auxiliary probes are observations, not extra unique cases.
    path = urllib.parse.urlsplit(url).path
    if path in case_ids and "readiness" not in str(observation["request_id"]):
        observation["case_id"] = case_ids[path]
    event_path = os.environ.get("COMMON_EVENT_LOG_PATH", "")
    if event_path:
        _probe_host_transaction(root, observation, event_path)
    observation["promotion_allowed"] = bool(
        observation.get("transaction_id")
        and observation["run_id"]
        and observation["source_revision"]
    )


def _probe_response_observation(
    status,
    response_headers,
    response_body,
    read_error,
    headers,
    forbidden_headers,
    required_headers,
):
    forbidden_observed = any(
        _response_header_values(response_headers, name) for name in forbidden_headers
    )
    required_mismatch = any(
        _response_header_values(response_headers, name) != [value]
        for name, value in required_headers.items()
    )
    observation = {
        "schema_version": 1,
        "evidence_type": "envoy_http_client_probe",
        "http_status": status,
        "actual_status": status,
        "status": "FAIL"
        if forbidden_observed or required_mismatch or read_error
        else "PASS",
        "live_executed": True,
        "response_bytes": len(response_body),
        "response_body_completed": not read_error,
        "response_headers_observed": True,
        "body_payload_persisted": False,
        "run_id": os.environ.get("NO_CRS_RUN_ID")
        or os.environ.get("SMOKE_RUN_ID")
        or os.environ.get("VERIFIED_RUN_ID", ""),
        "source_revision": os.environ.get("CONNECTOR_REVISION", ""),
        "request_id": next(
            (
                value
                for name, value in headers.items()
                if name.lower() == "x-request-id"
            ),
            "",
        ),
        "redirect_location_verified": "location" in required_headers
        and not required_mismatch,
        "composite_lease_header_present": bool(
            _response_header_values(response_headers, "x-msconnector-composite-lease")
        ),
    }
    return observation, forbidden_observed, required_mismatch


def probe(
    runtime_root: str,
    tls_certificate: str,
    url: str,
    header: list[str],
    method: str,
    data: str | None,
    no_redirect: bool,
    evidence_path: str | None = None,
    forbid_response_header: list[str] | None = None,
    require_response_header: list[str] | None = None,
) -> int:
    root = verified_runtime_root(runtime_root)
    headers = parse_headers(header)
    forbidden_headers = parse_header_names(forbid_response_header or [])
    required_headers = parse_required_response_headers(require_response_header or [])
    body = None if data is None else data.encode("utf-8")
    request = urllib.request.Request(
        checked_loopback_https_url(url), data=body, headers=headers, method=method
    )
    handlers: list[object] = [
        urllib.request.HTTPSHandler(
            context=trusted_loopback_tls_context(root, tls_certificate)
        ),
    ]
    if no_redirect:
        handlers.append(NoRedirect())
    read_error = False
    try:
        opener = urllib.request.build_opener(*handlers)
        with opener.open(request, timeout=2) as response:
            status, response_headers, response_body, read_error = _read_probe_response(
                response, read_error
            )
    except urllib.error.HTTPError as exc:
        try:
            status, response_headers, response_body, read_error = _read_probe_response(
                exc, read_error
            )
        finally:
            exc.close()
    observation, forbidden_observed, required_mismatch = _probe_response_observation(
        status,
        response_headers,
        response_body,
        read_error,
        headers,
        forbidden_headers,
        required_headers,
    )
    _probe_observation_identity(root, url, observation)
    append_jsonl(
        root, root / "probe-observations.jsonl", observation, "probe observation ledger"
    )
    if evidence_path:
        write_json_atomic(root, evidence_path, observation, "probe evidence output")
    if observation.get("identity_error"):
        raise RuntimeError(str(observation["identity_error"]))
    if read_error:
        raise RuntimeError("HTTP response body did not complete")
    if forbidden_observed:
        # Never retain or print a response header value; this checks only the
        # host boundary's public-header absence.
        raise RuntimeError("forbidden response header observed")
    if required_mismatch:
        # The value is deliberately neither persisted nor included in an error
        # message: this is an exact client-boundary assertion only.
        raise RuntimeError("required response header missing or mismatched")
    print(status)
    return 0


def client_cancel(
    runtime_root: str,
    tls_certificate: str,
    host: str,
    port: int,
    path: str,
    header: list[str],
) -> dict[str, int | bool]:
    """Close a real HTTP/1.1 downstream connection after its first body byte.

    The result is intentionally client-local metadata.  Envoy's ext_proc API
    does not identify the resulting gRPC cancellation as a client or upstream
    reset, so callers must pair this observation with the explicit unattributed
    completion record rather than fabricating a reset cause.
    """
    root = verified_runtime_root(runtime_root)
    host = checked_loopback_host(host)
    if port < 1 or port > 65535:
        raise ValueError("port must be in range 1..65535")
    if not path.startswith("/") or "\r" in path or "\n" in path:
        raise ValueError("path must be an absolute HTTP path")
    headers = parse_headers(header)
    request_lines = [f"GET {path} HTTP/1.1", f"Host: {host}", "Connection: keep-alive"]
    request_lines.extend(f"{name}: {value}" for name, value in headers.items())
    try:
        request = ("\r\n".join(request_lines) + "\r\n\r\n").encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("client-cancel headers must be ASCII") from exc
    context = trusted_loopback_tls_context(root, tls_certificate)
    with (
        socket.create_connection((host, port), timeout=2) as connection,
        context.wrap_socket(connection, server_hostname=host) as tls_connection,
    ):
        tls_connection.settimeout(2)
        tls_connection.sendall(request)
        status = _read_client_cancel_status(tls_connection)
    # Leaving the context closes the TLS connection while the delayed upstream
    # response is still open.  No response payload is persisted.
    return {"client_closed": True, "first_body_byte_received": True, "http_status": status}


def _read_client_cancel_status(connection: socket.socket) -> int:
    received = bytearray()
    while True:
        chunk = connection.recv(4096)
        if not chunk:
            raise RuntimeError("server closed before sending a response body byte")
        received.extend(chunk)
        if len(received) > 64 << 10:
            raise RuntimeError("response headers exceed the client-cancel observation limit")
        header_end = received.find(b"\r\n\r\n")
        if header_end >= 0 and len(received) > header_end + 4:
            break
    status_line = bytes(received[:header_end]).split(b"\r\n", 1)[0]
    try:
        _version, status_text, _reason = status_line.split(b" ", 2)
        return int(status_text)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("server returned an invalid HTTP status line") from exc


def _bounded_token(value: object, *, field: str, maximum: int = 128) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    token = value.strip()
    if not token or len(token) > maximum:
        raise ValueError(f"{field} must be a non-empty bounded token")
    if not all(character.isascii() and (character.isalnum() or character in ":._-") for character in token):
        raise ValueError(f"{field} must be a bounded token")
    return token


def _nonnegative_int(value: object, *, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _http_status(value: object, *, field: str) -> int:
    status = _nonnegative_int(value, field=field)
    if status < 100 or status > 599:
        raise ValueError(f"{field} must be an HTTP status")
    return status


def _load_json_object(root: Path, path: Path, *, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(read_runtime_text(root, path, label))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return {str(key): value for key, value in payload.items()}


def _wait_for_json_object(root: Path, path: Path, *, timeout: float, label: str) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out waiting for {label}")
        time.sleep(0.01)
    return _load_json_object(root, path, label=label)


def _read_until(
    connection: socket.socket,
    buffer: bytearray,
    marker: bytes,
    *,
    timeout: float,
    label: str,
) -> None:
    deadline = time.monotonic() + timeout
    while marker not in buffer:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"timed out waiting for {label}")
        connection.settimeout(remaining)
        piece = connection.recv(4096)
        if not piece:
            raise RuntimeError(f"connection closed before {label}")
        buffer.extend(piece)
        if len(buffer) > 64 << 10:
            raise RuntimeError(f"{label} exceeded the bounded observation limit")


def _read_chunked_first_body(
    connection: socket.socket, *, timeout: float
) -> tuple[int, int]:
    """Return status and first downstream body size, retaining no payload.

    The controlled upstream always uses HTTP/1.1 chunking.  A real proxy may
    legally normalize that framing for the downstream, so the proof accepts a
    first body byte without chunk framing too.  In either case the upstream's
    independently published pause record establishes that its EOS was still
    absent when the client observed that byte.
    """
    received = bytearray()
    _read_until(
        connection,
        received,
        b"\r\n\r\n",
        timeout=timeout,
        label="HTTP response headers",
    )
    headers, remainder = bytes(received).split(b"\r\n\r\n", 1)
    status_line = headers.split(b"\r\n", 1)[0]
    parts = status_line.split(b" ", 2)
    try:
        status = int(parts[1])
    except (IndexError, ValueError) as exc:
        raise RuntimeError("server returned an invalid HTTP status line") from exc
    normalized_headers = b"\r\n" + headers.lower() + b"\r\n"
    if b"\r\ntransfer-encoding: chunked\r\n" not in normalized_headers:
        if remainder:
            return status, 1
        deadline = time.monotonic() + timeout
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timed out waiting for first response body byte")
        connection.settimeout(remaining)
        if connection.recv(1):
            return status, 1
        raise RuntimeError("connection closed before the first response body byte")
    chunk_data = bytearray(remainder)
    _read_until(
        connection,
        chunk_data,
        b"\r\n",
        timeout=timeout,
        label="first response chunk length",
    )
    line_end = chunk_data.find(b"\r\n")
    try:
        size = int(bytes(chunk_data[:line_end]).split(b";", 1)[0], 16)
    except ValueError as exc:
        raise RuntimeError("first response chunk length is invalid") from exc
    if size < 1:
        raise RuntimeError("first response chunk must contain a body byte")
    body_start = line_end + 2
    deadline = time.monotonic() + timeout
    while len(chunk_data) - body_start < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timed out waiting for first response body chunk")
        connection.settimeout(remaining)
        piece = connection.recv(min(4096, size - (len(chunk_data) - body_start)))
        if not piece:
            raise RuntimeError("connection closed during the first response body chunk")
        chunk_data.extend(piece)
    # ``chunk_data`` deliberately goes out of scope without being copied to a
    # file, JSON record, or log.  The observation retains only its byte count.
    return status, size


def _drain_response(connection: socket.socket, *, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timed out draining released phase-4 response")
        connection.settimeout(remaining)
        piece = connection.recv(4096)
        if not piece:
            return


def _validate_phase4_pause_record(paused: dict[str, Any]) -> None:
    required = {
        "schema_version": 1,
        "evidence_type": "envoy_phase4_upstream_paused",
        "upstream_paused": True,
        "upstream_eos_sent": False,
        "body_payload_persisted": False,
    }
    if any(paused.get(field) != expected for field, expected in required.items()):
        raise RuntimeError("upstream phase-4 pause record is invalid")
    if _nonnegative_int(paused.get("first_chunk_size"), field="paused first_chunk_size") < 1:
        raise RuntimeError("upstream phase-4 pause record has no first chunk")


def _validate_phase4_completion_record(completed: dict[str, Any]) -> None:
    required = {
        "schema_version": 1,
        "evidence_type": "envoy_phase4_upstream_completed",
        "upstream_eos_sent": True,
        "body_payload_persisted": False,
    }
    if any(completed.get(field) != expected for field, expected in required.items()):
        raise RuntimeError("upstream phase-4 completion record is invalid")
    _nonnegative_int(completed.get("first_chunk_size"), field="completed first_chunk_size")


def phase4_first_byte(
    runtime_root: str,
    tls_certificate: str,
    host: str,
    port: int,
    path: str,
    header: list[str],
    barrier_dir: str,
    timeout: float,
) -> dict[str, int | bool | str]:
    """Observe one downstream byte while the controlled upstream has no EOS."""
    root = verified_runtime_root(runtime_root)
    host = checked_loopback_host(host)
    if port < 1 or port > 65535:
        raise ValueError("port must be in range 1..65535")
    if not path.startswith("/") or "\r" in path or "\n" in path:
        raise ValueError("path must be an absolute HTTP path")
    if timeout <= 0 or timeout > 60:
        raise ValueError("timeout must be greater than zero and at most 60 seconds")
    paths = phase4_barrier_paths(root, barrier_dir)
    if any(path_value.exists() for path_value in paths.values()):
        raise ValueError("phase-4 barrier paths must be fresh before probing")
    headers = parse_headers(header)
    request_lines = [f"GET {path} HTTP/1.1", f"Host: {host}", "Connection: close"]
    request_lines.extend(f"{name}: {value}" for name, value in headers.items())
    try:
        request = ("\r\n".join(request_lines) + "\r\n\r\n").encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("phase-4 barrier headers must be ASCII") from exc

    context = trusted_loopback_tls_context(root, tls_certificate)
    with (
        socket.create_connection((host, port), timeout=timeout) as connection,
        context.wrap_socket(connection, server_hostname=host) as tls_connection,
    ):
        tls_connection.sendall(request)
        status, first_chunk_size = _read_chunked_first_body(tls_connection, timeout=timeout)
        paused = _wait_for_json_object(
            root, paths["paused"], timeout=timeout, label="upstream phase-4 pause record"
        )
        _validate_phase4_pause_record(paused)
        try:
            create_runtime_marker(root, paths["release"], "phase-4 barrier release")
        except FileExistsError as exc:
            raise RuntimeError("phase-4 barrier release was already present") from exc
        _drain_response(tls_connection, timeout=timeout)

    completed = _wait_for_json_object(
        root, paths["completed"], timeout=timeout, label="upstream phase-4 completion record"
    )
    _validate_phase4_completion_record(completed)
    return {
        "schema_version": 1,
        "evidence_type": "envoy_phase4_first_byte_observation",
        "http_status": status,
        "client_first_byte_received": True,
        "first_byte_before_response_end": True,
        "first_chunk_size": first_chunk_size,
        "upstream_paused": True,
        "upstream_eos_sent_at_first_byte": False,
        "upstream_response_finished_at_first_byte": False,
        "upstream_eos_sent_after_release": True,
        "body_payload_persisted": False,
        "transport_protocol": "http1",
        "outcome": "PASS",
    }


def _is_phase4_safe_event(record: dict[str, Any], transaction_id: str) -> bool:
    rule_id = record.get("rule_id")
    phase = record.get("phase")
    identity_matches = (
        record.get("event") != "phase4_first_byte_barrier"
        and not isinstance(rule_id, bool)
        and str(rule_id) == "1104002"
        and record.get("connector") == "envoy"
        and record.get("integration_mode") == "ext_proc"
        and record.get("transaction_id") == transaction_id
        and phase in {4, "4", "phase4", "response_body"}
    )
    state_matches = (
        record.get("requested_action") == "deny"
        and record.get("actual_action") == "log_only"
        and record.get("late_intervention") is True
        and record.get("late_intervention_mode") == "safe"
        and record.get("headers_sent") is True
        and record.get("body_started") is True
        and record.get("response_committed") is True
        and record.get("connection_aborted") is False
        and record.get("transport_result") == "log_only"
    )
    return identity_matches and state_matches


def _phase4_safe_event(records: list[dict[str, Any]], *, transaction_id: str) -> dict[str, Any]:
    candidates = [record for record in records if _is_phase4_safe_event(record, transaction_id)]
    if len(candidates) != 1:
        raise ValueError(
            "expected exactly one Common P4 safe log-only event for the barrier transaction"
        )
    return candidates[0]


def _load_jsonl(root: Path, path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for number, line in enumerate(read_runtime_text(root, path, COMMON_EVENT_LOG_LABEL).splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Common event log line {number} is not JSON") from exc
        if not isinstance(value, dict):
            raise ValueError(f"Common event log line {number} is not an object")
        records.append({str(key): item for key, item in value.items()})
    return records


def verify_response_phase_events(
    *,
    runtime_root: str,
    event_log: str,
    p3_rule_id: str,
    p3_transaction_id: str,
    p4_rule_id: str,
    p4_transaction_id: str,
) -> None:
    """Require the ext_authz companion's P3 deny and P4 Safe records.

    The event JSONL field order is deliberately not part of the contract.  In
    particular, do not use a line-oriented regular expression that can accept
    a rule ID, transaction ID, and action from different records or reject a
    harmless serializer field-order change.
    """

    root = verified_runtime_root(runtime_root)
    p3_rule = _bounded_token(p3_rule_id, field="p3_rule_id", maximum=256)
    p3_transaction = _bounded_token(
        p3_transaction_id, field="p3_transaction_id", maximum=256
    )
    p4_rule = _bounded_token(p4_rule_id, field="p4_rule_id", maximum=256)
    p4_transaction = _bounded_token(
        p4_transaction_id, field="p4_transaction_id", maximum=256
    )
    records = _load_jsonl(
        root, runtime_artifact(root, event_log, COMMON_EVENT_LOG_LABEL)
    )
    forbidden_body_fields = {
        "request_body",
        "response_body",
        "body_payload",
        "body_snippet",
    }
    p3 = [
        record
        for record in records
        if record.get("connector") == "envoy"
        and record.get("integration_mode") == "ext_authz"
        and record.get("transaction_id") == p3_transaction
        and str(record.get("rule_id")) == p3_rule
        and record.get("phase") == "response_headers"
        and record.get("status") == "blocked"
        and record.get("actual_action") == "deny"
        and record.get("response_committed") is False
    ]
    p4 = [
        record
        for record in records
        if record.get("connector") == "envoy"
        and record.get("integration_mode") == "ext_authz"
        and record.get("transaction_id") == p4_transaction
        and str(record.get("rule_id")) == p4_rule
        and record.get("phase") == "response_body"
        and record.get("status") == "blocked"
        and record.get("actual_action") == "log_only"
        and record.get("response_committed") is True
    ]
    if len(p3) != 1 or len(p4) != 1:
        raise ValueError("Common event log must contain exactly one P3 deny and P4 Safe record")
    if any(forbidden_body_fields.intersection(record) for record in [*p3, *p4]):
        raise ValueError("Common event log contains a forbidden body payload field")


def write_allow_event(
    *,
    runtime_root: str,
    event_log: str,
    probe_evidence_path: str,
    completion_log: str,
    transaction_id: str,
) -> dict[str, object]:
    """Append one real, payload-free P1 allow event for the completed stream.

    The no-rule catalog case is summary-derived, so the event is deliberately
    written after all P4 evidence.  That preserves the association with this
    actual client HTTP 200 instead of letting the generic selector borrow a
    later P4-safe HTTP 200 event.
    """

    root = verified_runtime_root(runtime_root)
    transaction = _bounded_token(transaction_id, field="transaction_id", maximum=256)
    probe = _load_json_object(root, runtime_artifact(root, probe_evidence_path, "allow probe evidence"), label="allow probe evidence")
    if (
        probe.get("schema_version") != 1
        or probe.get("evidence_type") != "envoy_http_client_probe"
        or probe.get("http_status") != 200
        or probe.get("body_payload_persisted") is not False
        or _nonnegative_int(probe.get("response_bytes"), field="allow response_bytes") < 1
    ):
        raise ValueError("allow probe evidence is not a payload-free HTTP 200 response")

    completion_records = [
        record
        for record in _load_jsonl(root, runtime_artifact(root, completion_log, "completion log"))
        if record.get("transaction_id") == transaction
    ]
    if len(completion_records) != 1:
        raise ValueError("allow transaction must have exactly one ext_proc completion")
    completion = completion_records[0]
    if (
        completion.get("event") != "ext_proc_stream_complete"
        or completion.get("integration_mode") != "ext_proc"
        or completion.get("evaluation_mode") != "common_libmodsecurity_nonpromoted"
        or completion.get("rule_evaluation") != "libmodsecurity"
        or completion.get("late_action") != "none"
        or completion.get("close_reason") != "response_end_of_stream"
        or _nonnegative_int(completion.get("response_body_bytes"), field="allow response_body_bytes") < 1
    ):
        raise ValueError("allow ext_proc completion is not a normal streamed response")

    event_path = runtime_artifact(root, event_log, COMMON_EVENT_LOG_LABEL)
    existing = [
        record
        for record in _load_jsonl(root, event_path)
        if record.get("event") == "native_ext_proc_host_forward"
        and record.get("transaction_id") == transaction
    ]
    record: dict[str, object] = {
        # The request and normal ext_proc completion above are the causal
        # evidence.  Do not infer an "allow" action: the canonical action
        # vocabularies deliberately model interventions only.
        "connector": "envoy",
        "integration_mode": "ext_proc",
        "event": "native_ext_proc_host_forward",
        "message_id": "ENVOY_EXT_PROC_NATIVE_P1_ALLOW",
        "transaction_id": transaction,
        "phase": 1,
        "status": "allowed",
        "http_status": 200,
        "visible_http_status": 200,
        "headers_sent": True,
        "response_committed": True,
        "connection_aborted": False,
        "transport_result": "http_status",
    }
    if existing:
        if len(existing) != 1 or existing[0] != record:
            raise ValueError("existing Envoy allow event is not causally bound")
        appended = False
    else:
        append_jsonl(root, event_path, record, COMMON_EVENT_LOG_LABEL)
        appended = True
    return {
        "schema_version": 1,
        "event_appended": appended,
        "transaction_id": transaction,
        "body_payload_persisted": False,
    }


def _phase4_observation(root: Path, path: Path) -> dict[str, Any]:
    observation = _load_json_object(root, path, label="phase-4 first-byte observation")
    expected = {
        "schema_version": 1,
        "evidence_type": "envoy_phase4_first_byte_observation",
        "http_status": 200,
        "client_first_byte_received": True,
        "first_byte_before_response_end": True,
        "upstream_paused": True,
        "upstream_eos_sent_at_first_byte": False,
        "upstream_response_finished_at_first_byte": False,
        "upstream_eos_sent_after_release": True,
        "body_payload_persisted": False,
        "transport_protocol": "http1",
        "outcome": "PASS",
    }
    for field, expected_value in expected.items():
        if observation.get(field) != expected_value:
            raise ValueError(f"phase-4 first-byte observation has invalid {field}")
    if _nonnegative_int(observation.get("first_chunk_size"), field="first_chunk_size") < 1:
        raise ValueError("phase-4 first-byte observation has no first chunk")
    return observation


def _append_phase4_barrier_event(
    root: Path,
    event_path: Path,
    barrier_event: dict[str, object],
    transaction: str,
) -> bool:
    existing_barriers = [
        record
        for record in _load_jsonl(root, event_path)
        if record.get("event") == barrier_event["event"]
        and record.get("transaction_id") == transaction
        and record.get("transport_case_id") == barrier_event["transport_case_id"]
    ]
    if not existing_barriers:
        append_jsonl(root, event_path, barrier_event, COMMON_EVENT_LOG_LABEL)
        return True
    if len(existing_barriers) != 1:
        raise ValueError("phase-4 first-byte barrier event was emitted more than once")
    existing = existing_barriers[0]
    for field in (
        "rule_id",
        "phase",
        "requested_action",
        "actual_action",
        "late_intervention_mode",
        "first_byte_before_response_end",
        "upstream_eos_sent_at_first_byte",
        "no_full_response_buffering",
    ):
        if existing.get(field) != barrier_event[field]:
            raise ValueError("existing phase-4 first-byte barrier event is not causally bound")
    return False


def write_phase4_first_byte_evidence(
    *,
    runtime_root: str,
    event_log: str,
    observation_path: str,
    transaction_id: str,
    evidence_output: str | None = None,
    run_id: str | None = None,
) -> dict[str, object]:
    """Bind the controlled first-byte observation to the real Common P4 event."""
    root = verified_runtime_root(runtime_root)
    transaction = _bounded_token(transaction_id, field="transaction_id", maximum=256)
    event_path = runtime_artifact(root, event_log, COMMON_EVENT_LOG_LABEL)
    observation = _phase4_observation(
        root,
        runtime_artifact(root, observation_path, "phase-4 first-byte observation"),
    )
    source = _phase4_safe_event(_load_jsonl(root, event_path), transaction_id=transaction)
    body_seen = _nonnegative_int(source.get("body_bytes_seen"), field="body_bytes_seen")
    body_inspected = _nonnegative_int(
        source.get("body_bytes_inspected"), field="body_bytes_inspected"
    )
    first_chunk_size = _nonnegative_int(observation.get("first_chunk_size"), field="first_chunk_size")
    if body_inspected > body_seen:
        raise ValueError("Common P4 body_bytes_inspected exceeds body_bytes_seen")
    if body_seen < first_chunk_size or body_inspected < first_chunk_size:
        raise ValueError("Common P4 body counters do not cover the observed first chunk")
    source_http_status = _http_status(source.get("http_status"), field="http_status")
    original_http_status = _http_status(
        source.get("original_http_status"), field="original_http_status"
    )
    visible_http_status = _http_status(
        source.get("visible_http_status"), field="visible_http_status"
    )
    if source_http_status != 451 or original_http_status != 200 or visible_http_status != 200:
        raise ValueError("Common P4 safe event has unexpected status metadata")
    normalized_run_id = (
        _bounded_token(run_id, field="run_id", maximum=256) if run_id else None
    )
    evidence: dict[str, object] = {
        "schema_version": 1,
        "evidence_type": "synchronized_first_byte",
        "evidence_origin": "real_host",
        "promotion_eligible": True,
        "client_first_byte_received": True,
        "first_byte_before_response_end": True,
        "first_chunk_size": first_chunk_size,
        "upstream_paused": True,
        "upstream_eos_sent_at_first_byte": False,
        "upstream_response_finished_at_first_byte": False,
        "response_committed": True,
        "body_bytes_seen": body_seen,
        "body_bytes_inspected": body_inspected,
        "no_full_response_buffering": True,
        "connector_owned_full_response_buffer": False,
        "transport_protocol": "http1",
        "body_payload_persisted": False,
        "outcome": "PASS",
    }
    barrier_event: dict[str, object] = {
        "connector": "envoy",
        "integration_mode": "ext_proc",
        "event": "phase4_first_byte_barrier",
        "message_id": "MSCONN_EVENT_P4_FIRST_BYTE_BARRIER",
        "transaction_id": transaction,
        "rule_id": "1104002",
        "phase": 4,
        "status": "observed",
        "http_status": source_http_status,
        "original_http_status": original_http_status,
        "visible_http_status": visible_http_status,
        "requested_action": "deny",
        "actual_action": "log_only",
        "late_intervention": True,
        "late_intervention_mode": "safe",
        "headers_sent": True,
        "body_started": True,
        "response_committed": True,
        "connection_aborted": False,
        "transport_result": "log_only",
        "end_of_stream_evaluation": True,
        "eos_seen": True,
        "cleanup_reason": "normal",
        "client_first_byte_received": True,
        "first_byte_before_response_end": True,
        "first_chunk_size": first_chunk_size,
        "upstream_paused": True,
        "upstream_eos_sent_at_first_byte": False,
        "upstream_response_finished_at_first_byte": False,
        "body_bytes_seen": body_seen,
        "body_bytes_inspected": body_inspected,
        "no_full_response_buffering": True,
        "negotiated_protocol": "http1",
        "transport": "tcp",
        "transport_case_id": "phase4_first_byte_before_response_end",
        "barrier_id": "envoy-ext-proc-p4-first-byte",
    }
    if normalized_run_id is not None:
        barrier_event["run_id"] = normalized_run_id
    if evidence_output:
        evidence_parent = verified_runtime_root(str(Path(evidence_output).parent))
        write_json_atomic(evidence_parent, evidence_output, evidence, "first-byte evidence output")
    appended = _append_phase4_barrier_event(root, event_path, barrier_event, transaction)
    return {
        "schema_version": 1,
        "evidence_written": bool(evidence_output),
        "event_appended": appended,
        "transaction_id": transaction,
        "body_payload_persisted": False,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("free-port")
    prepare = subparsers.add_parser("prepare-runtime-root")
    prepare.add_argument("--runtime-root", required=True)
    prepare.add_argument("--require-private-mode", action="store_true")
    ports = subparsers.add_parser("free-ports")
    ports.add_argument("--count", required=True, type=int)
    serve = subparsers.add_parser("serve-upstream")
    serve.add_argument("--port", required=True, type=int)
    serve.add_argument("--runtime-root", required=True)
    serve.add_argument("--tls-certificate", required=True)
    serve.add_argument("--tls-private-key", required=True)
    serve.add_argument("--client-cancel-delay", default=5.0, type=float)
    serve.add_argument("--phase4-barrier-dir")
    serve.add_argument("--phase4-barrier-timeout", default=10.0, type=float)
    request = subparsers.add_parser("probe")
    request.add_argument("--runtime-root", required=True)
    request.add_argument("--tls-certificate", required=True)
    request.add_argument("--url", required=True)
    request.add_argument("--header", action="append", default=[])
    request.add_argument("--method", default="GET")
    request.add_argument("--data")
    request.add_argument("--no-redirect", action="store_true")
    request.add_argument("--evidence-path")
    request.add_argument("--forbid-response-header", action="append", default=[])
    request.add_argument("--require-response-header", action="append", default=[])
    cancel = subparsers.add_parser("client-cancel")
    cancel.add_argument("--runtime-root", required=True)
    cancel.add_argument("--tls-certificate", required=True)
    cancel.add_argument("--host", required=True)
    cancel.add_argument("--port", required=True, type=int)
    cancel.add_argument("--path", default="/client-cancel")
    cancel.add_argument("--header", action="append", default=[])
    phase4 = subparsers.add_parser("phase4-first-byte")
    phase4.add_argument("--runtime-root", required=True)
    phase4.add_argument("--tls-certificate", required=True)
    phase4.add_argument("--host", required=True)
    phase4.add_argument("--port", required=True, type=int)
    phase4.add_argument("--path", default=PHASE4_MARKER_PATH)
    phase4.add_argument("--header", action="append", default=[])
    phase4.add_argument("--barrier-dir", required=True)
    phase4.add_argument("--timeout", default=10.0, type=float)
    phase4.add_argument("--output")
    finalize = subparsers.add_parser("write-phase4-first-byte-evidence")
    finalize.add_argument("--runtime-root", required=True)
    finalize.add_argument("--event-log", required=True)
    finalize.add_argument("--observation", required=True)
    finalize.add_argument("--transaction-id", required=True)
    finalize.add_argument("--evidence-output")
    finalize.add_argument("--run-id")
    allow_event = subparsers.add_parser("write-allow-event")
    allow_event.add_argument("--runtime-root", required=True)
    allow_event.add_argument("--event-log", required=True)
    allow_event.add_argument("--probe-evidence", required=True)
    allow_event.add_argument("--completion-log", required=True)
    allow_event.add_argument("--transaction-id", required=True)
    response_events = subparsers.add_parser("verify-response-phase-events")
    response_events.add_argument("--runtime-root", required=True)
    response_events.add_argument("--event-log", required=True)
    response_events.add_argument("--p3-rule-id", required=True)
    response_events.add_argument("--p3-transaction-id", required=True)
    response_events.add_argument("--p4-rule-id", required=True)
    response_events.add_argument("--p4-transaction-id", required=True)
    return parser.parse_args()


def _free_ports_command(args: argparse.Namespace) -> int:
    if args.count < 1 or args.count > 16:
        raise ValueError("free port count must be between 1 and 16")
    print(" ".join(str(port) for port in free_ports(args.count)))
    return 0


def _prepare_runtime_root_command(args: argparse.Namespace) -> int:
    root = verified_runtime_root(args.runtime_root)
    if args.require_private_mode and stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise ValueError("private socket root must have mode 0700")
    return 0


def _serve_upstream_command(args: argparse.Namespace) -> int:
    return serve_upstream(
        args.port,
        args.client_cancel_delay,
        args.runtime_root,
        args.tls_certificate,
        args.tls_private_key,
        args.phase4_barrier_dir,
        args.phase4_barrier_timeout,
    )


def _probe_command(args: argparse.Namespace) -> int:
    return probe(
        args.runtime_root,
        args.tls_certificate,
        args.url,
        args.header,
        args.method,
        args.data,
        args.no_redirect,
        args.evidence_path,
        args.forbid_response_header,
        args.require_response_header,
    )


def _client_cancel_command(args: argparse.Namespace) -> int:
    result = client_cancel(
        args.runtime_root, args.tls_certificate, args.host, args.port, args.path, args.header,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


def _phase4_first_byte_command(args: argparse.Namespace) -> int:
    observation = phase4_first_byte(
        args.runtime_root,
        args.tls_certificate,
        args.host,
        args.port,
        args.path,
        args.header,
        args.barrier_dir,
        args.timeout,
    )
    if args.output:
        write_json_atomic(
            verified_runtime_root(args.runtime_root),
            args.output,
            observation,
            "phase-4 observation output",
        )
    print(json.dumps(observation, sort_keys=True))
    return 0


def _phase4_evidence_command(args: argparse.Namespace) -> int:
    result = write_phase4_first_byte_evidence(
        runtime_root=args.runtime_root,
        event_log=args.event_log,
        observation_path=args.observation,
        transaction_id=args.transaction_id,
        evidence_output=args.evidence_output,
        run_id=args.run_id,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


def _allow_event_command(args: argparse.Namespace) -> int:
    result = write_allow_event(
        runtime_root=args.runtime_root,
        event_log=args.event_log,
        probe_evidence_path=args.probe_evidence,
        completion_log=args.completion_log,
        transaction_id=args.transaction_id,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


def _verify_response_phase_events_command(args: argparse.Namespace) -> int:
    verify_response_phase_events(
        runtime_root=args.runtime_root,
        event_log=args.event_log,
        p3_rule_id=args.p3_rule_id,
        p3_transaction_id=args.p3_transaction_id,
        p4_rule_id=args.p4_rule_id,
        p4_transaction_id=args.p4_transaction_id,
    )
    return 0


def main() -> int:
    args = parse_args()
    handlers = {
        "free-port": lambda: print(free_port()),
        "prepare-runtime-root": lambda: _prepare_runtime_root_command(args),
        "free-ports": lambda: _free_ports_command(args),
        "serve-upstream": lambda: _serve_upstream_command(args),
        "probe": lambda: _probe_command(args),
        "client-cancel": lambda: _client_cancel_command(args),
        "phase4-first-byte": lambda: _phase4_first_byte_command(args),
        "write-phase4-first-byte-evidence": lambda: _phase4_evidence_command(args),
        "write-allow-event": lambda: _allow_event_command(args),
        "verify-response-phase-events": lambda: _verify_response_phase_events_command(args),
    }
    result = handlers[args.command]()
    return int(result or 0)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"envoy_smoke_helper: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
