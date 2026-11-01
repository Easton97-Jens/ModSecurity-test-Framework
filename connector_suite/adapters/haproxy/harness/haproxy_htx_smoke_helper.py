#!/usr/bin/env python3
"""Local-only helpers for real HAProxy HTX host-runtime evidence.

The helper deliberately retains only bounded metadata from the local client,
upstream, and HAProxy process.  It never persists request/response payloads.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
from email.message import Message
import http.client
import http.server
import json
from pathlib import Path
import re
import socket
import ssl
import sys
import threading
import time
from typing import Callable
import urllib.parse

_HELPER_DIR = Path(__file__).resolve().parent


from connector_suite.adapters.haproxy.harness.runtime_artifacts import append_text, artifact_path, read_text, verified_runtime_root, write_text_atomic


REPO_ROOT = connector_root()
CANONICAL_RULES_PATH = (
    source_path('modules/ModSecurity-test-Framework/tests/rules/no-crs-baseline.conf', root=REPO_ROOT)
)
CANONICAL_RULE_SNIPPETS = (
    "id:1100001,phase:1,deny,status:403",
    "id:1100002,phase:1,deny,status:429",
    "id:1100101,phase:2,deny,status:403",
    "id:1100201,phase:3,deny,status:403",
    "id:1100301,phase:4,deny,status:403",
)
UPSTREAM_OK_BODY = b"haproxy-htx-upstream-ok\n"
UPSTREAM_PHASE4_BODY = b"no-crs-response-body-marker\n"
HTX_TRANSACTION_ID_MAX_LENGTH = 127
MAX_HARNESS_HEADER_BYTES = 8 * 1024
MAX_HARNESS_REQUEST_BODY_BYTES = 64 * 1024
MAX_HARNESS_RESPONSE_BODY_BYTES = 64 * 1024
MAX_HARNESS_EVIDENCE_BYTES = 64 * 1024
MAX_HARNESS_LOG_BYTES = 256 * 1024
UPSTREAM_REQUEST_LOG_LABEL = "upstream request log"
FIRST_BYTE_EVIDENCE_LABEL = "first-byte evidence"
PROBE_EVIDENCE_LABEL = "probe evidence"
HAPROXY_HOST_LOG_LABEL = "HAProxy host log"
DECISION_PATTERN = re.compile(
    r"transaction_id=(?P<transaction_id>[A-Za-z0-9._-]+) "
    r"phase=(?P<phase>[0-9]+) status=(?P<status>[0-9]+) "
    r"rule_id=(?P<rule_id>[0-9]+) "
    r"(?:action|requested_action)=(?P<action>[A-Za-z_]+)"
)
LATE_DECISION_PATTERN = re.compile(
    r"transaction_id=(?P<transaction_id>[A-Za-z0-9._-]+) "
    r"phase=(?P<phase>[0-9]+) status=(?P<status>[0-9]+) "
    r"rule_id=(?P<rule_id>[0-9]+) "
    r"requested_action=(?P<requested_action>[A-Za-z_]+) "
    r"resolved_policy_action=(?P<resolved_policy_action>[A-Za-z_]+) "
    r"host_action=(?P<host_action>[A-Za-z_]+)"
)


# A host-evidence record is meaningful only for one of the fixed lifecycle
# cases emitted by the runtime runner.  Keep the runner's host translation in
# this closed mapping so direct helper callers cannot create arbitrary phase,
# action, status, or upstream-count combinations.
HostEvidenceCase = tuple[int, int, int, tuple[int, ...], str, bool]
HOST_EVIDENCE_CASES: dict[str, HostEvidenceCase] = {
    "allow": (1, 0, 200, (1,), "forwarded", False),
    "phase1_403": (1, 1100001, 403, (0,), "enforced_reply", True),
    "phase1_429": (1, 1100002, 429, (0,), "enforced_reply", True),
    "phase2_client_deny": (2, 1100101, 403, (0, 1), "enforced_reply", True),
    "phase2_bodyless_eos": (2, 0, 200, (1,), "observed_only", False),
    "phase3_403": (3, 1100201, 403, (1,), "enforced_reply", True),
    "phase4_bodyless_eos": (4, 0, 200, (1,), "observed_only", False),
    "phase4_safe_barrier": (4, 1100301, 200, (1,), "safe_log_only", True),
}


class UpstreamRequestError(ValueError):
    """Reject malformed or incomplete private upstream request framing."""


class UpstreamRequestTooLarge(UpstreamRequestError):
    """Reject a private upstream request body before buffering it."""


class UpstreamHeaderTooLarge(UpstreamRequestError):
    """Reject private upstream headers before the handler processes a request."""


def checked_path(root: Path, raw_path: str, label: str, *, must_exist: bool) -> Path:
    """Return one CLI path confined to the invocation's private runtime root."""

    return artifact_path(root, raw_path, label, must_exist=must_exist)


def bounded_artifact_text(
    root: Path,
    path: str | Path,
    label: str,
    maximum: int,
    *,
    errors: str | None = None,
) -> str:
    """Read one private regular artifact only after its byte-size limit holds."""

    target = checked_path(root, str(path), label, must_exist=True)
    if target.stat().st_size > maximum:
        raise ValueError(f"{label} exceeds {maximum}-byte limit")
    return read_text(root, target, label, errors=errors)


def shared_artifact_parent(label: str, *paths: Path) -> Path:
    """Require evidence inputs for one claim to remain in one private case root."""

    if not paths:
        raise ValueError(f"{label} requires at least one private artifact")
    parent = paths[0].parent
    if any(path.parent != parent for path in paths[1:]):
        raise ValueError(f"{label} must share one private case root")
    return parent


def prepare_runtime_root(runtime_root: str) -> int:
    """Create and verify the one private root before a shell runner writes."""

    verified_runtime_root(runtime_root)
    return 0


def append_jsonl(root: Path, path: Path, record: dict[str, object]) -> None:
    append_text(
        root,
        path,
        json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n",
        "JSONL evidence output",
    )


def write_json(root: Path, path: Path, record: dict[str, object]) -> None:
    write_text_atomic(
        root,
        path,
        json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n",
        "JSON evidence output",
    )


def load_json_object(root: Path, path: str, label: str) -> dict[str, object]:
    try:
        value = json.loads(bounded_artifact_text(root, path, label, MAX_HARNESS_EVIDENCE_BYTES))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid {label}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not an object")
    return value


def safe_token(value: object, label: str, maximum: int = 128) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum or not re.fullmatch(r"[A-Za-z0-9:._-]+", text):
        raise ValueError(f"invalid {label}")
    return text


def safe_htx_transaction_id(value: object) -> str:
    """Return the request-ID grammar accepted by the native HTX filter."""

    # The native HTX context owns a `char transaction_id[128]`; reserve one
    # byte for its terminating NUL and do not emit evidence the host cannot
    # have accepted as the request correlation token.
    text = safe_token(value, "HTX transaction id", maximum=HTX_TRANSACTION_ID_MAX_LENGTH)
    if re.fullmatch(r"[A-Za-z0-9._-]+", text) is None:
        raise ValueError("invalid HTX transaction id")
    return text


def checked_loopback_port(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError("port out of range")
    return value


def checked_loopback_https_url(value: str) -> tuple[str, int, str]:
    """Accept only a credential-free local HTTPS smoke endpoint."""

    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "127.0.0.1"
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ValueError("probe URL must be a credential-free https://127.0.0.1 endpoint")
    return parsed.hostname, checked_loopback_port(parsed.port or 80), parsed.path or "/"


def trusted_loopback_tls_context(root: Path, certificate_path: str) -> ssl.SSLContext:
    """Trust the current private-root certificate for one TLS smoke client."""

    certificate = checked_path(root, certificate_path, "loopback TLS certificate", must_exist=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=str(certificate))
    return context


def probe_headers(header: list[str]) -> dict[str, str]:
    """Return bounded, injection-free headers for the private HTTPS client."""

    headers: dict[str, str] = {}
    seen_header_names: set[str] = set()
    total_bytes = 0
    for item in header:
        name, separator, value = item.partition(":")
        name = name.strip()
        value = value.strip()
        if not separator or re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is None:
            raise ValueError(f"invalid header: {item!r}")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError(f"invalid header: {item!r}")
        normalized_name = name.lower()
        if normalized_name in seen_header_names:
            raise ValueError(f"duplicate header: {name}")
        try:
            total_bytes += len(name.encode("ascii")) + len(value.encode("latin-1")) + 4
        except UnicodeEncodeError as exc:
            raise ValueError(f"invalid header: {item!r}") from exc
        if total_bytes > MAX_HARNESS_HEADER_BYTES:
            raise ValueError("request headers exceed private harness limit")
        headers[name] = value
        seen_header_names.add(normalized_name)
    return headers


def bounded_request_body(data: str | None) -> bytes | None:
    """Encode one CLI body only when it fits the private harness limit."""

    if data is None:
        return None
    body = data.encode("utf-8")
    if len(body) > MAX_HARNESS_REQUEST_BODY_BYTES:
        raise ValueError("request body exceeds private harness limit")
    return body


def upstream_content_length(headers: Message) -> int:
    """Validate the single supported private upstream request framing mode."""

    transfer_encodings = headers.get_all("transfer-encoding", []) or []
    content_lengths = headers.get_all("content-length", []) or []
    if len(transfer_encodings) > 1:
        raise UpstreamRequestError("duplicate transfer encoding")
    if len(content_lengths) > 1:
        raise UpstreamRequestError("duplicate content length")
    if transfer_encodings and content_lengths:
        raise UpstreamRequestError("conflicting request body framing")
    if transfer_encodings:
        raise UpstreamRequestError("unsupported transfer encoding")
    if not content_lengths:
        return 0
    value = content_lengths[0].strip()
    if re.fullmatch(r"\d+", value, flags=re.ASCII) is None:
        raise UpstreamRequestError("invalid content length")
    length = int(value, 10)
    if length > MAX_HARNESS_REQUEST_BODY_BYTES:
        raise UpstreamRequestTooLarge("request body exceeds private harness limit")
    return length


def upstream_header_bytes(headers: Message) -> int:
    """Reject an aggregate incoming header section over the private limit."""

    total_bytes = 0
    for name, value in headers.items():
        try:
            total_bytes += len(name.encode("ascii")) + len(value.encode("latin-1")) + 4
        except UnicodeEncodeError as exc:
            raise UpstreamRequestError("invalid request header encoding") from exc
        if total_bytes > MAX_HARNESS_HEADER_BYTES:
            raise UpstreamHeaderTooLarge("request headers exceed private harness limit")
    return total_bytes


def read_upstream_request_body(handler: http.server.BaseHTTPRequestHandler) -> bytes:
    """Read a fully framed bounded upstream body or fail before logging it."""

    content_length = upstream_content_length(handler.headers)
    if content_length == 0:
        return b""
    try:
        body = handler.rfile.read(content_length)
    except OSError as exc:
        raise UpstreamRequestError("timed out reading request body") from exc
    if len(body) != content_length:
        raise UpstreamRequestError("incomplete request body")
    return body


def upstream_profile(raw_path: str) -> tuple[str, str | None, bytes]:
    path = raw_path.split("?", 1)[0]
    if path == "/no-crs/request-body":
        return "phase2", None, UPSTREAM_OK_BODY
    if path == "/no-crs/response-header":
        return "phase3", "block", UPSTREAM_OK_BODY
    if path == "/no-crs/response-body":
        return "phase4", None, UPSTREAM_PHASE4_BODY
    return "ordinary", None, UPSTREAM_OK_BODY


class UpstreamHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        del fmt, args

    def parse_request(self) -> bool:
        if not super().parse_request():
            return False
        try:
            upstream_header_bytes(self.headers)
        except UpstreamHeaderTooLarge:
            self.send_error(431)
            self.close_connection = True
            return False
        except UpstreamRequestError:
            self.send_error(400)
            self.close_connection = True
            return False
        return True

    def answer(self) -> None:
        try:
            self.connection.settimeout(2.0)
            read_upstream_request_body(self)
        except UpstreamRequestTooLarge:
            self.send_error(413)
            self.close_connection = True
            return
        except (UpstreamRequestError, OSError):
            self.send_error(400)
            self.close_connection = True
            return
        profile, response_header, response_body = upstream_profile(self.path)
        request_log = getattr(self.server, "request_log", None)
        request_log_lock = getattr(self.server, "request_log_lock", None)
        if isinstance(request_log, Path) and request_log_lock is not None:
            record: dict[str, object] = {
                "method": self.command,
                "response_status": 200,
                "profile": profile,
            }
            # The native HTX overlay accepts this bounded request ID as its
            # transaction ID.  Retain only that already-safe correlation
            # token, never arbitrary request-header data.
            try:
                request_id = safe_htx_transaction_id(self.headers.get("x-request-id"))
            except ValueError:
                request_id = ""
            if request_id:
                record["request_id"] = request_id
            with request_log_lock:
                append_jsonl(getattr(self.server, "runtime_root"), request_log, record)
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        if response_header is not None:
            self.send_header("x-modsec-upstream", response_header)
        self.send_header("content-length", str(len(response_body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response_body)

    do_GET = answer
    do_HEAD = answer
    do_POST = answer


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_port(port: int) -> int:
    with socket.create_connection(("127.0.0.1", checked_loopback_port(port)), timeout=0.5):
        return 0


def wait_for_release(release: Path, timeout: float) -> None:
    """Wait for the runner-created release file without buffering a response."""

    deadline = time.monotonic() + timeout
    while not release.is_file():
        if time.monotonic() >= deadline:
            raise ValueError("timed out waiting for the synchronized upstream release")
        time.sleep(0.01)


def serve_upstream(runtime_root: str, port: int, request_log: str | None = None) -> int:
    root = verified_runtime_root(runtime_root)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", checked_loopback_port(port)), UpstreamHandler)
    server.runtime_root = root
    server.request_log = checked_path(root, request_log, UPSTREAM_REQUEST_LOG_LABEL, must_exist=False) if request_log else None
    server.request_log_lock = threading.Lock()
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


def probe(
    runtime_root: str, url: str, header: list[str], method: str, data: str | None,
    certificate_path: str, evidence_path: str | None = None,
) -> int:
    root = verified_runtime_root(runtime_root)
    headers = probe_headers(header)
    request_body = bounded_request_body(data)
    host, port, request_path = checked_loopback_https_url(url)
    parsed = urllib.parse.urlsplit(url)
    if parsed.query:
        request_path += f"?{parsed.query}"
    connection = http.client.HTTPSConnection(
        host,
        port,
        context=trusted_loopback_tls_context(root, certificate_path),
        timeout=2,
    )
    response: http.client.HTTPResponse | None = None
    try:
        connection.request(method, request_path, body=request_body, headers=headers)
        response = connection.getresponse()
        response_body = response.read(MAX_HARNESS_RESPONSE_BODY_BYTES + 1)
        if len(response_body) > MAX_HARNESS_RESPONSE_BODY_BYTES:
            raise ValueError("HAProxy response body exceeds private harness limit")
        status = int(response.status)
        content_type = str(response.headers.get("content-type") or "")[:256]
    finally:
        if response is not None:
            response.close()
        connection.close()
    if evidence_path:
        write_json(root, checked_path(root, evidence_path, PROBE_EVIDENCE_LABEL, must_exist=False), {
            "status": status,
            "response_bytes": len(response_body),
            "content_type": content_type,
        })
    print(status)
    return 0


def streaming_probe(
    runtime_root: str,
    url: str,
    release_path: str,
    first_byte_path: str,
    evidence_path: str,
    certificate_path: str,
    timeout: float,
) -> int:
    """Read one body byte through HAProxy before releasing a paused upstream.

    The client retains only the current read buffer.  Its two JSON files contain
    status/count metadata, never body bytes.  The caller owns the release file,
    which makes the client-first-byte observation independent of the later
    Phase-4 marker and upstream EOS.
    """

    root = verified_runtime_root(runtime_root)
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    host, port, request_path = checked_loopback_https_url(url)
    parsed = urllib.parse.urlsplit(url)
    if parsed.query:
        request_path += f"?{parsed.query}"
    release = checked_path(root, release_path, "upstream release file", must_exist=False)
    first_byte_output = checked_path(root, first_byte_path, FIRST_BYTE_EVIDENCE_LABEL, must_exist=False)
    evidence_output = checked_path(root, evidence_path, "streaming probe evidence", must_exist=False)
    connection = http.client.HTTPSConnection(
        host,
        port,
        context=trusted_loopback_tls_context(root, certificate_path),
        timeout=timeout,
    )
    response: http.client.HTTPResponse | None = None
    try:
        connection.request(
            "GET",
            request_path,
            headers={
                "Host": host,
                "Connection": "close",
                "X-Request-Id": "haproxy-htx-phase4",
            },
        )
        response = connection.getresponse()
        first = response.read(1)
        if not first:
            raise ValueError("HAProxy response ended before its first response-body byte")
        write_json(root, first_byte_output, {
            "status": int(response.status),
            "client_first_byte_received": True,
            "first_chunk_size": len(first),
            "response_committed": True,
            "body_payload_persisted": False,
        })

        wait_for_release(release, timeout)

        response_bytes = len(first)
        while True:
            chunk = response.read(8192)
            if not chunk:
                break
            response_bytes += len(chunk)
            if response_bytes > MAX_HARNESS_RESPONSE_BODY_BYTES:
                raise ValueError("HAProxy response body exceeds private harness limit")
        write_json(root, evidence_output, {
            "status": int(response.status),
            "response_bytes": response_bytes,
            "content_type": str(response.getheader("content-type") or "")[:256],
        })
    finally:
        if response is not None:
            response.close()
        connection.close()
    print(response.status if response is not None else 0)
    return 0


def wait_for_file(runtime_root: str, path: str, timeout: float) -> int:
    root = verified_runtime_root(runtime_root)
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    target = checked_path(root, path, "control file", must_exist=False)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if target.is_file() and target.stat().st_size > 0:
            return 0
        time.sleep(0.01)
    raise ValueError(f"timed out waiting for payload-free control file: {target}")


def synchronized_upstream_port(runtime_root: str, path: str) -> int:
    root = verified_runtime_root(runtime_root)
    value = load_json_object(root, path, "synchronized upstream ready record")
    if value.get("schema_version") != 1 or value.get("evidence_type") != "synchronized_upstream_ready":
        raise ValueError("invalid synchronized upstream ready record")
    if value.get("body_payload_persisted") is not False:
        raise ValueError("synchronized upstream ready record must be payload-free")
    host = value.get("upstream_host")
    port = value.get("upstream_port")
    if host != "127.0.0.1" or isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("invalid synchronized upstream address")
    return port


def validate_synchronized_upstream_complete(runtime_root: str, path: str) -> int:
    root = verified_runtime_root(runtime_root)
    value = load_json_object(root, path, "synchronized upstream completion record")
    if value.get("schema_version") != 1 or value.get("evidence_type") != "synchronized_upstream_server":
        raise ValueError("invalid synchronized upstream completion record")
    if value.get("body_payload_persisted") is not False:
        raise ValueError("synchronized upstream completion record must be payload-free")
    if value.get("upstream_paused") is not True or value.get("upstream_eos_sent") is not True:
        raise ValueError("synchronized upstream did not record the required pause and EOS")
    size = value.get("first_chunk_size")
    if isinstance(size, bool) or not isinstance(size, int) or size < 1:
        raise ValueError("synchronized upstream completion record has invalid first_chunk_size")
    return 0


def first_byte_evidence(
    root: Path, paused_path: str, client_first_byte_path: str,
) -> dict[str, object]:
    """Bind a real HTTP client first byte to the still-paused upstream state."""

    paused = load_json_object(root, paused_path, "synchronized upstream pause record")
    client = load_json_object(root, client_first_byte_path, "client first-byte record")
    if paused.get("schema_version") != 1 or paused.get("evidence_type") != "synchronized_upstream_paused":
        raise ValueError("invalid synchronized upstream pause record")
    if paused.get("upstream_paused") is not True or paused.get("upstream_eos_sent") is not False:
        raise ValueError("synchronized upstream was not paused before EOS")
    if paused.get("body_payload_persisted") is not False:
        raise ValueError("synchronized upstream pause record must be payload-free")
    upstream_first_chunk = paused.get("first_chunk_size")
    if isinstance(upstream_first_chunk, bool) or not isinstance(upstream_first_chunk, int) or upstream_first_chunk < 1:
        raise ValueError("synchronized upstream pause record has invalid first_chunk_size")
    if client.get("client_first_byte_received") is not True or client.get("response_committed") is not True:
        raise ValueError("HAProxy client did not observe a committed first response-body byte")
    if client.get("body_payload_persisted") is not False:
        raise ValueError("client first-byte record must be payload-free")
    client_first_chunk = client.get("first_chunk_size")
    if isinstance(client_first_chunk, bool) or not isinstance(client_first_chunk, int) or client_first_chunk < 1:
        raise ValueError("client first-byte record has invalid first_chunk_size")
    status = client.get("status")
    if isinstance(status, bool) or not isinstance(status, int) or status != 200:
        raise ValueError("first-byte client did not observe HTTP 200")
    # The filter consumes the current borrowed HTX DATA slice before returning
    # its length.  At the observed first byte, the only connector-side body
    # accounting that can honestly be published is the current upstream chunk.
    return {
        "schema_version": 1,
        "evidence_type": "synchronized_first_byte",
        "evidence_origin": "real_host",
        "promotion_eligible": True,
        "client_first_byte_received": True,
        "first_byte_before_response_end": True,
        "first_chunk_size": upstream_first_chunk,
        "upstream_paused": True,
        "upstream_eos_sent_at_first_byte": False,
        "upstream_response_finished_at_first_byte": False,
        "response_committed": True,
        "body_bytes_seen": upstream_first_chunk,
        "body_bytes_inspected": upstream_first_chunk,
        "no_full_response_buffering": True,
        "connector_owned_full_response_buffer": False,
        "transport_protocol": "http1",
        "body_payload_persisted": False,
        "outcome": "PASS",
    }


def write_first_byte_evidence(
    runtime_root: str,
    path: str,
    paused_path: str,
    client_first_byte_path: str,
    published_path: str | None = None,
) -> int:
    root = verified_runtime_root(runtime_root)
    output = checked_path(root, path, FIRST_BYTE_EVIDENCE_LABEL, must_exist=False)
    paused = checked_path(root, paused_path, "synchronized upstream pause record", must_exist=True)
    client = checked_path(root, client_first_byte_path, "client first-byte record", must_exist=True)
    shared_artifact_parent("first-byte evidence inputs", output, paused, client)
    record = first_byte_evidence(root, str(paused), str(client))
    write_json(root, output, record)
    if published_path:
        published = checked_path(root, published_path, FIRST_BYTE_EVIDENCE_LABEL, must_exist=False)
        if published != output:
            write_json(root, published, record)
    return 0


def canonical_rules_content(root: Path, canonical_rules: str | None = None) -> str:
    if canonical_rules:
        content = read_text(root, canonical_rules, "canonical No-CRS rules")
    else:
        if not CANONICAL_RULES_PATH.is_file():
            raise ValueError(f"canonical No-CRS rules are missing: {CANONICAL_RULES_PATH}")
        content = CANONICAL_RULES_PATH.read_text(encoding="utf-8")
    missing = [snippet for snippet in CANONICAL_RULE_SNIPPETS if snippet not in content]
    if missing:
        raise ValueError(f"canonical No-CRS rules are incomplete: {', '.join(missing)}")
    if "id:91000" in content:
        raise ValueError("canonical No-CRS rules must not use temporary 91000x IDs")
    return content


def write_rules(runtime_root: str, path: str, canonical_rules: str | None = None, *,
                request_body_limit: int, request_body_no_files_limit: int,
                request_body_limit_action: str, response_body_limit: int,
                response_body_limit_action: str) -> int:
    if (request_body_limit <= 0 or request_body_no_files_limit <= 0 or
        request_body_limit_action not in {"Reject", "ProcessPartial"} or
        response_body_limit <= 0 or response_body_limit_action not in {"Reject", "ProcessPartial"}):
        raise ValueError("fixture requires an explicit positive response limit and Reject/ProcessPartial action")
    root = verified_runtime_root(runtime_root)
    write_text_atomic(
        root,
        path,
        canonical_rules_content(root, canonical_rules)
        + f"\nSecRequestBodyLimit {request_body_limit}\nSecRequestBodyNoFilesLimit {request_body_no_files_limit}\nSecRequestBodyLimitAction {request_body_limit_action}\n"
        + f"\nSecResponseBodyLimit {response_body_limit}\nSecResponseBodyLimitAction {response_body_limit_action}\n",
        "HAProxy rules output",
    )
    return 0


def config_value(value: str, name: str) -> str:
    if not value or "\n" in value or "\r" in value:
        raise ValueError(f"invalid {name}")
    return value


def write_config(
    runtime_root: str,
    path: str,
    listen_port: int,
    upstream_port: int,
    rules_file: str,
    certificate_path: str,
) -> int:
    root = verified_runtime_root(runtime_root)
    rules = config_value(
        str(checked_path(root, rules_file, "rules file", must_exist=True)),
        "rules file",
    )
    certificate = config_value(
        str(checked_path(root, certificate_path, "HAProxy TLS certificate", must_exist=True)),
        "HAProxy TLS certificate",
    )
    listen_port = checked_loopback_port(listen_port)
    upstream_port = checked_loopback_port(upstream_port)
    content = f"""global
    log stdout format raw local0

defaults
    mode http
    timeout connect 2s
    timeout client 5s
    timeout server 5s

frontend htx_in
    bind 127.0.0.1:{listen_port} ssl crt {certificate}
    filter modsecurity-htx rules-file {rules} phase4-mode safe
    default_backend htx_upstream

backend htx_upstream
    server upstream 127.0.0.1:{upstream_port}
"""
    write_text_atomic(root, path, content, "HAProxy configuration output")
    return 0


def read_probe(runtime_root: str, path: str) -> dict[str, object]:
    root = verified_runtime_root(runtime_root)
    try:
        value = json.loads(bounded_artifact_text(
            root, path, PROBE_EVIDENCE_LABEL, MAX_HARNESS_EVIDENCE_BYTES,
        ))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid {PROBE_EVIDENCE_LABEL}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{PROBE_EVIDENCE_LABEL} is not an object")
    status = value.get("status")
    response_bytes = value.get("response_bytes")
    content_type = value.get("content_type")
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        raise ValueError("invalid probe status")
    if (
        isinstance(response_bytes, bool)
        or not isinstance(response_bytes, int)
        or not 0 <= response_bytes <= MAX_HARNESS_RESPONSE_BODY_BYTES
    ):
        raise ValueError("invalid probe response size")
    if not isinstance(content_type, str) or len(content_type) > 256:
        raise ValueError("invalid probe content type")
    return value


def probe_status(runtime_root: str, path: str) -> int:
    """Return the validated status from a payload-free completed probe."""

    return int(read_probe(runtime_root, path)["status"])


def upstream_count(runtime_root: str, path: str, profile: str) -> int:
    root = verified_runtime_root(runtime_root)
    target = checked_path(root, path, UPSTREAM_REQUEST_LOG_LABEL, must_exist=False)
    if not target.exists():
        return 0
    count = 0
    for line in bounded_artifact_text(
        root, target, UPSTREAM_REQUEST_LOG_LABEL, MAX_HARNESS_LOG_BYTES,
    ).splitlines():
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid upstream evidence") from exc
        if isinstance(record, dict) and record.get("profile") == profile:
            count += 1
    return count


def upstream_transaction_observed(
    runtime_root: str, path: str, profile: str, transaction_id: str,
) -> bool:
    """Return whether exactly one upstream request preserved the HTX ID."""

    expected_transaction_id = safe_htx_transaction_id(transaction_id)
    root = verified_runtime_root(runtime_root)
    target = checked_path(root, path, UPSTREAM_REQUEST_LOG_LABEL, must_exist=False)
    if not target.is_file():
        return False
    matches = 0
    for line in bounded_artifact_text(
        root, target, UPSTREAM_REQUEST_LOG_LABEL, MAX_HARNESS_LOG_BYTES,
    ).splitlines():
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid upstream evidence") from exc
        if not isinstance(record, dict):
            continue
        if (
            record.get("profile") == profile
            and record.get("request_id") == expected_transaction_id
        ):
            matches += 1
    return matches == 1


def decision_from_log(runtime_root: str, path: str, phase: int, rule_id: int) -> dict[str, object]:
    root = verified_runtime_root(runtime_root)
    matches: list[dict[str, object]] = []
    for line in bounded_artifact_text(
        root, path, HAPROXY_HOST_LOG_LABEL, MAX_HARNESS_LOG_BYTES, errors="replace",
    ).splitlines():
        for match in DECISION_PATTERN.finditer(line):
            result = {
                "transaction_id": safe_htx_transaction_id(match.group("transaction_id")),
                "phase": int(match.group("phase")),
                "status": int(match.group("status")),
                "rule_id": int(match.group("rule_id")),
                "action": match.group("action").lower(),
            }
            if result["phase"] == phase and result["rule_id"] == rule_id:
                matches.append(result)
    if not matches:
        raise ValueError(f"{HAPROXY_HOST_LOG_LABEL} lacks phase {phase} rule {rule_id}")
    if len(matches) != 1:
        raise ValueError(
            f"{HAPROXY_HOST_LOG_LABEL} must contain exactly one phase {phase} rule {rule_id} decision",
        )
    return matches[0]


def late_decision_from_log(runtime_root: str, path: str, phase: int, rule_id: int) -> dict[str, object]:
    root = verified_runtime_root(runtime_root)
    matches: list[dict[str, object]] = []
    for line in bounded_artifact_text(
        root, path, HAPROXY_HOST_LOG_LABEL, MAX_HARNESS_LOG_BYTES, errors="replace",
    ).splitlines():
        for match in LATE_DECISION_PATTERN.finditer(line):
            result: dict[str, object] = {
                "transaction_id": safe_htx_transaction_id(match.group("transaction_id")),
                "phase": int(match.group("phase")),
                "status": int(match.group("status")),
                "rule_id": int(match.group("rule_id")),
                "requested_action": match.group("requested_action").lower(),
                "resolved_policy_action": match.group("resolved_policy_action").lower(),
                "host_action": match.group("host_action").lower(),
            }
            if result["phase"] == phase and result["rule_id"] == rule_id:
                matches.append(result)
    if not matches:
        raise ValueError(f"{HAPROXY_HOST_LOG_LABEL} lacks late phase {phase} rule {rule_id}")
    if len(matches) != 1:
        raise ValueError(
            f"{HAPROXY_HOST_LOG_LABEL} must contain exactly one late phase {phase} rule {rule_id} decision",
        )
    return matches[0]


def checked_host_evidence_case(
    case: str,
    phase: int,
    rule_id: int,
    observed_status: int,
    host_action: str,
) -> HostEvidenceCase:
    """Return the one canonical host translation for a lifecycle case."""

    expected = HOST_EVIDENCE_CASES.get(case)
    if expected is None:
        raise ValueError(f"unsupported HAProxy host-evidence case: {case}")
    expected_phase, expected_rule_id, expected_status, _, expected_action, _ = expected
    if (
        isinstance(phase, bool)
        or isinstance(rule_id, bool)
        or isinstance(observed_status, bool)
        or (phase, rule_id, observed_status, host_action)
        != (expected_phase, expected_rule_id, expected_status, expected_action)
    ):
        raise ValueError(f"HAProxy host evidence does not match the closed contract for {case}")
    return expected


def write_event(
    runtime_root: str, path: str, case: str, decision_log: str, phase: int, rule_id: int,
    observed_status: int, host_action: str, original_http_status: int | None = None,
) -> int:
    root = verified_runtime_root(runtime_root)
    expected = checked_host_evidence_case(case, phase, rule_id, observed_status, host_action)
    if host_action != "enforced_reply" or expected[-1] is not True:
        raise ValueError("canonical event output is reserved for an enforced host reply")
    decision = decision_from_log(runtime_root, decision_log, phase, rule_id)
    if decision["action"] != "deny" or decision["status"] != observed_status:
        raise ValueError("host decision does not match the client-visible enforced reply")
    expected_original_http_status = 200 if case == "phase3_403" else None
    if original_http_status != expected_original_http_status:
        raise ValueError("host event original upstream status does not match its closed case contract")
    record: dict[str, object] = {
        # This is a harness projection of the HAProxy host log and client
        # response, not a Common-runtime event or a capability promotion.
        "connector": "haproxy",
        "event": "native_htx_host_intervention",
        "message_id": "HAPROXY_HTX_NATIVE_PRECOMMIT_DENY",
        "integration_mode": "native-htx-filter",
        "evaluation_mode": "native_host_runtime_nonpromoted",
        "rule_evaluation": "libmodsecurity_host_runtime",
        "transaction_id": decision["transaction_id"],
        "case": case,
        "phase": phase,
        "rule_id": rule_id,
        "status": "blocked",
        "requested_action": "deny",
        "actual_action": "deny",
        "host_action": host_action,
        "http_status": observed_status,
        "observed_status": observed_status,
        "client_status": observed_status,
        "visible_http_status": observed_status,
        "headers_sent": False,
        "response_committed": False,
        "connection_aborted": False,
        "transport_result": "http_status",
    }
    if original_http_status is not None:
        record["original_http_status"] = original_http_status
    append_jsonl(root, checked_path(root, path, "event output", must_exist=False), record)
    return 0


def write_allow_event(
    runtime_root: str, path: str, probe_path: str, upstream_log: str, transaction_id: str,
) -> int:
    """Publish a real, payload-free P1 allow outcome after the full run.

    The event is deliberately appended after the P4 barrier event.  The
    Framework's generic no-rule case selector chooses the final matching 200
    response, so this preserves its causal binding to this actual Phase-1
    request rather than accidentally borrowing the P4 safe response.
    """

    root = verified_runtime_root(runtime_root)
    transaction = safe_htx_transaction_id(transaction_id)
    probe = read_probe(runtime_root, probe_path)
    if probe["status"] != 200 or int(probe["response_bytes"]) < 1:
        raise ValueError("HAProxy allow client outcome must preserve HTTP 200 with a body")
    if not upstream_transaction_observed(runtime_root, upstream_log, "ordinary", transaction):
        raise ValueError("HAProxy allow transaction was not observed exactly once upstream")
    record: dict[str, object] = {
        # This is a projection of the completed client request and the
        # matching upstream request-ID, not a policy decision or capability
        # promotion.  Allow is intentionally absent from the closed action
        # vocabularies, so no requested/actual action is inferred here.
        "connector": "haproxy",
        "event": "native_htx_host_forward",
        "message_id": "HAPROXY_HTX_NATIVE_P1_ALLOW",
        "integration_mode": "native-htx-filter",
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
    append_jsonl(root, checked_path(root, path, "allow-event output", must_exist=False), record)
    return 0


def phase4_safe_event(
    runtime_root: str,
    path: str,
    decision_log: str,
    probe_path: str,
    first_byte_evidence_path: str,
    run_id: str,
    transport_case_id: str,
) -> int:
    """Publish one payload-free host-confirmed P4 safe outcome.

    The decision comes from the native HTX filter's post-EOS log record, the
    visible status comes from the real HTTP/1.1 client, and the barrier fields
    come from the already-written real-host first-byte artifact.  No field is
    inferred from a policy default or fixture payload.
    """

    root = verified_runtime_root(runtime_root)
    decision_path = checked_path(root, decision_log, HAPROXY_HOST_LOG_LABEL, must_exist=True)
    probe_path = checked_path(root, probe_path, PROBE_EVIDENCE_LABEL, must_exist=True)
    evidence_path = checked_path(root, first_byte_evidence_path, FIRST_BYTE_EVIDENCE_LABEL, must_exist=True)
    shared_artifact_parent("phase4 safe evidence", decision_path, probe_path, evidence_path)
    decision = late_decision_from_log(runtime_root, str(decision_path), 4, 1100301)
    if (
        decision["requested_action"] != "deny"
        or decision["resolved_policy_action"] != "log_only"
        or decision["host_action"] != "log_only"
        or decision["status"] != 403
    ):
        raise ValueError("HAProxy late decision is not the required safe log-only outcome")
    probe = read_probe(runtime_root, str(probe_path))
    if probe["status"] != 200 or int(probe["response_bytes"]) < 1:
        raise ValueError("HAProxy safe P4 client outcome must preserve HTTP 200 with a body")
    evidence = load_json_object(root, str(evidence_path), FIRST_BYTE_EVIDENCE_LABEL)
    required_true = (
        "promotion_eligible",
        "client_first_byte_received",
        "first_byte_before_response_end",
        "upstream_paused",
        "response_committed",
        "no_full_response_buffering",
    )
    if (
        evidence.get("schema_version") != 1
        or evidence.get("evidence_type") != "synchronized_first_byte"
        or evidence.get("evidence_origin") != "real_host"
        or evidence.get("outcome") != "PASS"
        or evidence.get("body_payload_persisted") is not False
        or any(evidence.get(name) is not True for name in required_true)
        or evidence.get("upstream_eos_sent_at_first_byte") is not False
        or evidence.get("upstream_response_finished_at_first_byte") is not False
        or evidence.get("connector_owned_full_response_buffer") is not False
    ):
        raise ValueError(f"{FIRST_BYTE_EVIDENCE_LABEL} is not a complete real-host no-buffer proof")
    first_chunk_size = evidence.get("first_chunk_size")
    body_seen = evidence.get("body_bytes_seen")
    body_inspected = evidence.get("body_bytes_inspected")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in (first_chunk_size, body_seen, body_inspected)
    ) or (
        int(first_chunk_size) < 1
        or int(body_inspected) > int(body_seen)
        or int(first_chunk_size) > int(probe["response_bytes"])
    ):
        raise ValueError(f"{FIRST_BYTE_EVIDENCE_LABEL} has invalid body accounting")
    safe_run_id = safe_token(run_id, "run id", maximum=128)
    safe_transport_case = safe_token(transport_case_id, "transport case id")
    transaction_id = safe_htx_transaction_id(decision["transaction_id"])
    record: dict[str, object] = {
        "connector": "haproxy",
        "event": "native_htx_phase4_late_intervention",
        "message_id": "HAPROXY_HTX_NATIVE_LATE_LOG_ONLY",
        "integration_mode": "native-htx-filter",
        "run_id": safe_run_id,
        "transaction_id": transaction_id,
        "phase": 4,
        "rule_id": 1100301,
        "status": "blocked",
        "requested_action": "deny",
        "actual_action": "log_only",
        "http_status": 403,
        "original_http_status": 200,
        "visible_http_status": 200,
        "late_intervention": True,
        "late_intervention_mode": "safe",
        "headers_sent": True,
        "response_started": True,
        "body_started": True,
        "response_committed": True,
        "connection_aborted": False,
        "transport_result": "log_only",
        "negotiated_protocol": "http1",
        "transport": "tcp",
        "transport_case_id": safe_transport_case,
        "barrier_id": f"{transaction_id}.first-byte",
        "client_first_byte_received": True,
        "first_byte_before_response_end": True,
        "first_chunk_size": first_chunk_size,
        "upstream_paused": True,
        "upstream_eos_sent_at_first_byte": False,
        "upstream_response_finished_at_first_byte": False,
        "no_full_response_buffering": True,
        "body_bytes_seen": body_seen,
        "body_bytes_inspected": body_inspected,
        "eos_seen": True,
        "end_of_stream_evaluation": True,
        "cleanup_reason": "normal",
    }
    append_jsonl(root, checked_path(root, path, "phase4 event output", must_exist=False), record)
    return 0


def write_host_evidence(
    runtime_root: str, path: str, case: str, phase: int, rule_id: int, probe_path: str,
    upstream_requests: int, host_action: str, decision_log: str | None = None,
) -> int:
    root = verified_runtime_root(runtime_root)
    probe = read_probe(runtime_root, probe_path)
    expected = checked_host_evidence_case(
        case, phase, rule_id, int(probe["status"]), host_action,
    )
    allowed_upstream_requests = expected[3]
    requires_decision = expected[5]
    if (
        isinstance(upstream_requests, bool)
        or not isinstance(upstream_requests, int)
        or upstream_requests not in allowed_upstream_requests
    ):
        raise ValueError(f"upstream request count does not match the closed contract for {case}")
    if bool(decision_log) != requires_decision:
        raise ValueError(f"decision-log presence does not match the closed contract for {case}")
    if host_action in {"enforced_reply", "safe_log_only"} and int(probe["response_bytes"]) == 0:
        raise ValueError(f"{host_action} host outcome has no client response bytes")
    record: dict[str, object] = {
        "evidence_type": "haproxy_native_htx_host_runtime",
        "evidence_origin": "real_host_socket_traffic",
        "case": case,
        "phase": phase,
        "rule_id": rule_id,
        "client_status": probe["status"],
        "client_response_bytes": probe["response_bytes"],
        "upstream_requests": upstream_requests,
        "host_action": host_action,
    }
    if decision_log:
        decision = decision_from_log(runtime_root, decision_log, phase, rule_id)
        expected_decision_status = 403 if case == "phase4_safe_barrier" else int(probe["status"])
        if decision["action"] != "deny" or decision["status"] != expected_decision_status:
            raise ValueError(f"host decision does not match the closed contract for {case}")
        record.update({
            "transaction_id": decision["transaction_id"],
            "decision_status": decision["status"],
            "requested_action": decision["action"],
        })
    append_jsonl(root, checked_path(root, path, "host-evidence output", must_exist=False), record)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("free-port")
    prepare = subparsers.add_parser("prepare-runtime-root")
    wait = subparsers.add_parser("wait-port")
    wait.add_argument("--port", required=True, type=int)
    serve = subparsers.add_parser("serve-upstream")
    serve.add_argument("--port", required=True, type=int)
    serve.add_argument("--request-log")
    request = subparsers.add_parser("probe")
    request.add_argument("--url", required=True)
    request.add_argument("--header", action="append", default=[])
    request.add_argument("--method", default="GET")
    request.add_argument("--data")
    request.add_argument("--tls-certificate", required=True)
    request.add_argument("--evidence-path")
    streaming = subparsers.add_parser("streaming-probe")
    streaming.add_argument("--url", required=True)
    streaming.add_argument("--release-path", required=True)
    streaming.add_argument("--first-byte-path", required=True)
    streaming.add_argument("--evidence-path", required=True)
    streaming.add_argument("--tls-certificate", required=True)
    streaming.add_argument("--timeout", type=float, default=10.0)
    wait = subparsers.add_parser("wait-file")
    wait.add_argument("--path", required=True)
    wait.add_argument("--timeout", type=float, default=10.0)
    ready = subparsers.add_parser("synchronized-upstream-port")
    ready.add_argument("--path", required=True)
    upstream_complete = subparsers.add_parser("validate-synchronized-upstream")
    upstream_complete.add_argument("--path", required=True)
    first_byte = subparsers.add_parser("write-first-byte-evidence")
    first_byte.add_argument("--path", required=True)
    first_byte.add_argument("--paused-path", required=True)
    first_byte.add_argument("--client-first-byte-path", required=True)
    first_byte.add_argument("--published-path")
    probe_status_parser = subparsers.add_parser("probe-status")
    probe_status_parser.add_argument("--path", required=True)
    rules = subparsers.add_parser("write-rules")
    rules.add_argument("--path", required=True)
    rules.add_argument("--canonical-rules")
    rules.add_argument("--request-body-limit", required=True, type=int)
    rules.add_argument("--request-body-no-files-limit", required=True, type=int)
    rules.add_argument("--request-body-limit-action", required=True, choices=("Reject", "ProcessPartial"))
    rules.add_argument("--response-body-limit", required=True, type=int)
    rules.add_argument("--response-body-limit-action", required=True, choices=("Reject", "ProcessPartial"))
    config = subparsers.add_parser("write-config")
    config.add_argument("--path", required=True)
    config.add_argument("--listen-port", required=True, type=int)
    config.add_argument("--upstream-port", required=True, type=int)
    config.add_argument("--rules-file", required=True)
    config.add_argument("--tls-certificate", required=True)
    count = subparsers.add_parser("upstream-count")
    count.add_argument("--path", required=True)
    count.add_argument("--profile", required=True, choices=("ordinary", "phase2", "phase3", "phase4"))
    event = subparsers.add_parser("write-event")
    event.add_argument("--path", required=True)
    event.add_argument("--case", required=True)
    event.add_argument("--decision-log", required=True)
    event.add_argument("--phase", required=True, type=int)
    event.add_argument("--rule-id", required=True, type=int)
    event.add_argument("--observed-status", required=True, type=int)
    event.add_argument("--host-action", required=True, choices=("enforced_reply",))
    event.add_argument("--original-http-status", type=int)
    allow_event = subparsers.add_parser("write-allow-event")
    allow_event.add_argument("--path", required=True)
    allow_event.add_argument("--probe-path", required=True)
    allow_event.add_argument("--upstream-log", required=True)
    allow_event.add_argument("--transaction-id", required=True)
    evidence = subparsers.add_parser("write-host-evidence")
    evidence.add_argument("--path", required=True)
    evidence.add_argument("--case", required=True)
    evidence.add_argument("--phase", required=True, type=int)
    evidence.add_argument("--rule-id", required=True, type=int)
    evidence.add_argument("--probe-path", required=True)
    evidence.add_argument("--upstream-requests", required=True, type=int)
    evidence.add_argument("--host-action", required=True,
                          choices=("forwarded", "enforced_reply", "observed_only", "safe_log_only", "not_attempted"))
    evidence.add_argument("--decision-log")
    safe_event = subparsers.add_parser("write-phase4-safe-event")
    safe_event.add_argument("--path", required=True)
    safe_event.add_argument("--decision-log", required=True)
    safe_event.add_argument("--probe-path", required=True)
    safe_event.add_argument("--first-byte-evidence", required=True)
    safe_event.add_argument("--run-id", required=True)
    safe_event.add_argument("--transport-case-id", required=True)
    for runtime_command in (
        serve,
        prepare,
        request,
        streaming,
        wait,
        ready,
        upstream_complete,
        first_byte,
        probe_status_parser,
        rules,
        config,
        count,
        event,
        allow_event,
        evidence,
        safe_event,
    ):
        runtime_command.add_argument("--runtime-root", required=True)
    return parser.parse_args()


def print_result(value: int) -> int:
    print(value)
    return 0


def command_handlers(args: argparse.Namespace) -> dict[str, Callable[[], int]]:
    """Map each parser-selected command to its validated implementation."""

    return {
        "free-port": lambda: print_result(free_port()),
        "prepare-runtime-root": lambda: prepare_runtime_root(args.runtime_root),
        "wait-port": lambda: wait_port(args.port),
        "serve-upstream": lambda: serve_upstream(args.runtime_root, args.port, args.request_log),
        "probe": lambda: probe(
            args.runtime_root, args.url, args.header, args.method, args.data,
            args.tls_certificate, args.evidence_path,
        ),
        "streaming-probe": lambda: streaming_probe(
            args.runtime_root, args.url, args.release_path, args.first_byte_path,
            args.evidence_path, args.tls_certificate, args.timeout,
        ),
        "wait-file": lambda: wait_for_file(args.runtime_root, args.path, args.timeout),
        "synchronized-upstream-port": lambda: print_result(
            synchronized_upstream_port(args.runtime_root, args.path),
        ),
        "validate-synchronized-upstream": lambda: validate_synchronized_upstream_complete(
            args.runtime_root, args.path,
        ),
        "write-first-byte-evidence": lambda: write_first_byte_evidence(
            args.runtime_root, args.path, args.paused_path, args.client_first_byte_path,
            args.published_path,
        ),
        "probe-status": lambda: print_result(probe_status(args.runtime_root, args.path)),
        "write-rules": lambda: write_rules(args.runtime_root, args.path, args.canonical_rules, request_body_limit=args.request_body_limit, request_body_no_files_limit=args.request_body_no_files_limit, request_body_limit_action=args.request_body_limit_action, response_body_limit=args.response_body_limit, response_body_limit_action=args.response_body_limit_action),
        "write-config": lambda: write_config(
            args.runtime_root, args.path, args.listen_port, args.upstream_port,
            args.rules_file, args.tls_certificate,
        ),
        "upstream-count": lambda: print_result(
            upstream_count(args.runtime_root, args.path, args.profile),
        ),
        "write-event": lambda: write_event(
            args.runtime_root, args.path, args.case, args.decision_log, args.phase,
            args.rule_id, args.observed_status, args.host_action, args.original_http_status,
        ),
        "write-allow-event": lambda: write_allow_event(
            args.runtime_root, args.path, args.probe_path, args.upstream_log,
            args.transaction_id,
        ),
        "write-host-evidence": lambda: write_host_evidence(
            args.runtime_root, args.path, args.case, args.phase, args.rule_id,
            args.probe_path, args.upstream_requests, args.host_action, args.decision_log,
        ),
        "write-phase4-safe-event": lambda: phase4_safe_event(
            args.runtime_root, args.path, args.decision_log, args.probe_path,
            args.first_byte_evidence, args.run_id, args.transport_case_id,
        ),
    }


def main() -> int:
    args = parse_args()
    return command_handlers(args)[args.command]()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"haproxy_htx_smoke_helper: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
