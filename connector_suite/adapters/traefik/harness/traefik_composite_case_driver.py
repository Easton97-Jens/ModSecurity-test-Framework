#!/usr/bin/env python3
"""Drive one bounded HTTP/1.1 Traefik composite case.

The driver is an operator-side harness helper, not an evidence generator.  It
performs one real request, reads the observer's metadata-only JSONL after the
request, and writes only the verifier's bounded metadata receipts.  Request
and response bytes are held in memory for the request, never logged or saved.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import json
from pathlib import Path
import re
import socket
import sys
import time
from typing import Any, NoReturn

_CI_LIB = connector_root() / "ci" / "lib"


from modsecurity_connector_ci.lib.runtime_path_utils import open_private_runtime_root

SCHEMA = "msc-composite-evidence/v1"
MAX_EVENT_LOG = 256 * 1024
MAX_EVENT_LINE = 16 * 1024
MAX_UPSTREAM_OBSERVATION = 16 * 1024
P2_LIMIT_PROBE_BYTES = 33
DECISION_ID = re.compile(r"^[A-Za-z0-9_-]{16,256}$")
CASES = {
    "p1_allow": ("P1", "P2", "P3", "P4"),
    "p1_deny": ("P1",),
    "p2_allow": ("P1", "P2", "P3", "P4"),
    "p2_deny": ("P1", "P2"),
    "p2_oversize": ("P1", "P2"),
    "p3_deny": ("P1", "P2", "P3"),
    "p3_redirect": ("P1", "P2", "P3"),
    "p4_safe": ("P1", "P2", "P3", "P4"),
    "p4_strict": ("P1", "P2", "P3", "P4"),
    # Omission is pre-admission: ForwardAuth receives no private lease and
    # returns 503 before any Common P1/P2 processing. A truthful receipt has
    # only the payload-free reservation opener and its terminal cleanup.
    "metadata_omitted": (),
    "p2_to_p3_timeout": ("P1", "P2"),
}
VECTOR_FOR_CASE = {
    "p1_allow": "allow_control",
    "p1_deny": "p1_only",
    "p2_allow": "p2_empty_body",
    "p2_deny": "p2_only",
    "p2_oversize": "p2_body_limit",
    "p3_deny": "p3_only",
    "p3_redirect": "p3_redirect",
    "p4_safe": "p4_safe",
    "p4_strict": "p4_strict",
    "metadata_omitted": "allow_control",
    "p2_to_p3_timeout": "allow_control",
}
ALLOWED_EVENT_KEYS = {
    "decision_id", "connector", "phase", "outcome", "reason",
    "requested_action", "actual_host_action", "visible_status",
    "cleanup_outcome", "event_time", "rule_id", "request_path",
    "response_path", "transport",
}
FORBIDDEN_OUTPUT_KEYS = ("body", "payload", "lease", "location", "credential", "secret", "token", "password")


def fail(message: str) -> NoReturn:
    raise RuntimeError(message)


def artifact_leaf(path: Path, root: Path, label: str) -> str:
    if not path.is_absolute() or path.parent != root:
        fail(f"{label} must be an absolute direct child of the runtime root")
    return path.name


def load_catalog(runtime: Any, leaf: str) -> dict[str, Any]:
    value = json.loads(runtime.read_text(leaf, "case input", maximum_bytes=MAX_EVENT_LOG))
    if not isinstance(value, dict) or not isinstance(value.get("vectors"), list):
        fail("case input is not a catalog with vectors")
    return value


def select_case(catalog: dict[str, Any], runtime_root: Path) -> tuple[str, dict[str, Any]]:
    del runtime_root
    selected = catalog.get("selected_case")
    if not isinstance(selected, str) or selected not in CASES:
        fail("selected_case must name one supported verifier case")
    vector_id = VECTOR_FOR_CASE[selected]
    candidates = [v for v in catalog["vectors"] if isinstance(v, dict) and v.get("id") == vector_id]
    if len(candidates) != 1:
        fail("selected_case does not resolve to exactly one catalog vector")
    return selected, candidates[0]


def request_body(vector: dict[str, Any]) -> bytes:
    request = vector.get("request")
    if not isinstance(request, dict):
        fail("vector request is not an object")
    if request.get("client_abort"):
        fail("client-abort vectors require a dedicated transport primitive and are not promoted by this driver")
    if vector.get("id") == "p2_body_limit":
        # ForwardAuth accepts at most the coordinator limit plus one byte.
        # The catalog's larger source vector remains available for host-only
        # rejection checks, while this composite case must reach the service
        # to prove its same-transaction, bounded P2-limit cleanup path.
        return b"x" * P2_LIMIT_PROBE_BYTES
    if isinstance(request.get("body"), str):
        return request["body"].encode("utf-8")
    prefix = request.get("body_prefix")
    if isinstance(prefix, str):
        target = request.get("headers", {}).get("Content-Length", len(prefix))
        if not isinstance(target, int) or target < len(prefix) or target > 64 * 1024:
            fail("body length is outside the bounded request budget")
        return prefix.encode("utf-8") + b"x" * (target - len(prefix))
    return b""


def read_events(runtime: Any, leaf: str) -> list[dict[str, Any]]:
    try:
        content = runtime.read_text(leaf, "observer event log", maximum_bytes=MAX_EVENT_LOG)
    except FileNotFoundError:
        return []
    events: list[dict[str, Any]] = []
    for number, line in enumerate(content.splitlines(keepends=True), 1):
        if len(line.encode("utf-8")) > MAX_EVENT_LINE or not line.strip():
            fail(f"observer event line {number} is not bounded metadata")
        event = json.loads(line)
        if not isinstance(event, dict) or set(event) - ALLOWED_EVENT_KEYS:
            fail(f"observer event line {number} contains unsupported or payload fields")
        if any(key.lower() in FORBIDDEN_OUTPUT_KEYS for key in event):
            fail(f"observer event line {number} contains a forbidden payload field")
        events.append(event)
    return events


def wait_for_terminal(runtime: Any, leaf: str, timeout: float = 8.0) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        events = read_events(runtime, leaf)
        if events and events[-1].get("phase") == "terminal":
            return events
        time.sleep(0.05)
    fail("observer did not close this transaction within the bounded timeout")


def _origin_target(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        fail("vector request path is not a bounded origin-form target")
    if not value.startswith("/") or value.startswith("//") or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        fail("vector request path must be a bounded origin-form target")
    return value


def _read_response_headers(sock: socket.socket) -> tuple[bytearray, int]:
    maximum = 64 * 1024
    data = bytearray()
    while b"\r\n\r\n" not in data and len(data) <= maximum:
        chunk = sock.recv(min(4096, maximum + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    separator = data.find(b"\r\n\r\n")
    if separator < 0:
        fail("upstream response headers are incomplete")
    return data, separator


def _parse_content_length(value: bytes, current: int | None) -> int:
    if current is not None or not value.strip().isdigit():
        fail("upstream response content length is invalid")
    length = int(value.strip())
    if length > 32 * 1024:
        fail("upstream response body exceeds the bounded response size")
    return length


def _parse_location(value: bytes) -> bytes:
    normalized = value.strip(b" \t")
    if (
        not normalized
        or len(normalized) > 2048
        or any(octet < 0x20 or octet == 0x7F for octet in normalized)
    ):
        fail("upstream response Location is invalid")
    return normalized


def _parse_response_headers(header_block: list[bytes]) -> tuple[int, int | None, tuple[bytes, ...]]:
    match = re.fullmatch(rb"HTTP/1\.1 (\d{3})(?: [^\r\n]*)?", header_block[0])
    if not match:
        fail("upstream response status line is invalid")
    status = int(match.group(1))
    if not 100 <= status <= 599:
        fail("upstream response status is invalid")
    content_length: int | None = None
    locations: list[bytes] = []
    for header in header_block[1:]:
        name, header_separator, value = header.partition(b":")
        if not header_separator or not re.fullmatch(rb"[A-Za-z0-9!#$%&'*+.^_`|~-]+", name):
            fail("upstream response header is invalid")
        normalized_name = name.lower()
        if normalized_name == b"content-length":
            content_length = _parse_content_length(value, content_length)
        elif normalized_name == b"location":
            locations.append(_parse_location(value))
    return status, content_length, tuple(locations)


def _read_response_body(
    sock: socket.socket, body: bytearray, content_length: int | None
) -> None:
    if content_length is None:
        if len(body) > 32 * 1024:
            fail("upstream response body exceeds the bounded response size")
        return
    while len(body) < content_length:
        chunk = sock.recv(min(4096, content_length - len(body)))
        if not chunk:
            fail("upstream response body is incomplete")
        body.extend(chunk)
    if len(body) > content_length:
        del body[content_length:]


def _read_http_response(sock: socket.socket, expected_location: bytes | None = None) -> int:
    data, separator = _read_response_headers(sock)
    header_block = bytes(data[:separator]).split(b"\r\n")
    status, content_length, locations = _parse_response_headers(header_block)
    if expected_location is not None and locations != (expected_location,):
        fail("upstream response does not contain exactly one expected Location")
    body = bytearray(data[separator + 4 :])
    _read_response_body(sock, body, content_length)
    return status


def _build_request_wire(
    port: int, vector: dict[str, Any], add_client_lease: bool
) -> bytes:
    request = vector.get("request")
    if not isinstance(request, dict):
        fail("vector request metadata is malformed")
    target = _origin_target(request.get("path"))
    method = request.get("method", "GET")
    headers = request.get("headers", {})
    if not isinstance(method, str) or not isinstance(headers, dict):
        fail("vector request metadata is malformed")
    body = request_body(vector)
    normalized_headers = {
        str(key): str(value)
        for key, value in headers.items()
        if str(key).lower() not in {"content-length", "host", "connection", "transfer-encoding", "x-msconnector-composite-lease"}
    }
    if body or any(str(key).lower() == "content-length" for key in headers):
        normalized_headers["Content-Length"] = str(len(body))
    if add_client_lease:
        # This arbitrary client value must be removed before the real upstream.
        # It is never persisted or included in an observation receipt.
        normalized_headers["X-Msconnector-Composite-Lease"] = "client-supplied-invalid"
    if method not in {"GET", "POST"} or any(ord(c) < 0x21 or ord(c) > 0x7E for c in method):
        fail("vector request method is unsupported")
    request_lines = [f"{method} {target} HTTP/1.1", f"Host: 127.0.0.1:{port}"]
    for key, value in normalized_headers.items():
        if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", key) or any(ord(c) < 0x20 or ord(c) > 0x7E for c in key + value):
            fail("vector request header is invalid")
        request_lines.append(f"{key}: {value}")
    wire = ("\r\n".join(request_lines) + "\r\n\r\n").encode("ascii") + body
    return wire


def _expected_redirect_location(case: str, vector: dict[str, Any]) -> bytes | None:
    if case != "p3_redirect":
        return None
    expected = vector.get("expected")
    if not isinstance(expected, dict):
        fail("P3 redirect vector expected metadata is invalid")
    target = expected.get("redirect_target")
    if (
        not isinstance(target, str)
        or not 1 <= len(target) <= 2048
        or target != target.strip()
        or not target.startswith("/")
        or target.startswith("//")
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in target)
    ):
        fail("P3 redirect vector target is invalid")
    try:
        return target.encode("ascii")
    except UnicodeEncodeError as exc:
        raise RuntimeError("P3 redirect vector target must be ASCII") from exc


def http_request(
    port: int, vector: dict[str, Any], add_client_lease: bool, timeout: float = 5.0,
    expected_location: bytes | None = None,
) -> tuple[int | None, bool]:
    if not isinstance(port, int) or not 1 <= port <= 65535:
        fail("port is outside the valid range")
    wire = _build_request_wire(port, vector, add_client_lease)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as conn:
            conn.settimeout(timeout)
            conn.sendall(wire)
            return _read_http_response(conn, expected_location), True
    except (OSError, ValueError, RuntimeError):
        return None, False


def expected_status(case: str) -> set[int] | None:
    return {
        "p1_allow": set(range(200, 300)), "p1_deny": {403},
        "p2_allow": set(range(200, 300)), "p2_deny": {403},
        "p2_oversize": {413}, "p3_deny": {403}, "p3_redirect": {302},
        "p4_safe": {200}, "p4_strict": None,
        "metadata_omitted": {503}, "p2_to_p3_timeout": {503},
    }[case]


def write_json(runtime: Any, leaf: str, value: dict[str, Any], label: str) -> None:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    runtime.create_text(leaf, encoded, label)


def read_upstream_observation(runtime: Any, leaf: str, case: str) -> dict[str, Any]:
    value = json.loads(runtime.read_text(leaf, "upstream observation", maximum_bytes=MAX_UPSTREAM_OBSERVATION))
    if not isinstance(value, dict) or set(value) != {"schema", "requests_seen", "lease_header_observed"}:
        fail("upstream observation schema is invalid")
    if value.get("schema") != "traefik-composite-upstream-observation/v1":
        fail("upstream observation schema version is invalid")
    if not isinstance(value.get("requests_seen"), int) or value["requests_seen"] < 0:
        fail("upstream observation request count is invalid")
    if not isinstance(value.get("lease_header_observed"), bool):
        fail("upstream observation lease flag is invalid")
    expected_upstream = case not in {"p1_deny", "p2_deny", "p2_oversize", "metadata_omitted"}
    if expected_upstream and value["requests_seen"] < 1:
        fail("expected case did not reach the real upstream")
    if value["lease_header_observed"]:
        fail("internal lease header reached the real upstream")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--event-log", required=True, type=Path)
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--upstream-observation", required=True, type=Path)
    parser.add_argument("--connector", required=True, choices=("traefik",))
    args = parser.parse_args(argv)
    try:
        runtime_root = args.runtime_root
        input_leaf = artifact_leaf(args.input, runtime_root, "case input")
        event_leaf = artifact_leaf(args.event_log, runtime_root, "event log")
        manifest_leaf = artifact_leaf(args.manifest, runtime_root, "manifest")
        observation_leaf = artifact_leaf(args.upstream_observation, runtime_root, "upstream observation")
        runtime = open_private_runtime_root(runtime_root)
        with runtime:
            catalog = load_catalog(runtime, input_leaf)
            case, vector = select_case(catalog, runtime_root)
            expected_location = _expected_redirect_location(case, vector)
            request_timeout = 10.0 if case == "p2_to_p3_timeout" else 5.0
            status, response_completed = http_request(
                args.port,
                vector,
                case == "p1_allow",
                request_timeout,
                expected_location,
            )
            allowed = expected_status(case)
            if allowed is not None and status not in allowed:
                fail(f"{case} returned an unexpected client status")
            events = wait_for_terminal(runtime, event_leaf)
            upstream_observation = read_upstream_observation(runtime, observation_leaf, case)
            ids = {event.get("decision_id") for event in events}
            if len(ids) != 1 or not isinstance(next(iter(ids)), str) or not DECISION_ID.fullmatch(next(iter(ids))):
                fail("observer did not provide exactly one server-generated decision_id")
            decision_id = next(iter(ids))
            phases = [event.get("phase") for event in events if event.get("phase") in {"P1", "P2", "P3", "P4"}]
            if tuple(phases) != CASES[case]:
                fail("observer phases do not match the selected isolated case")
            client = {
                "lease_observed": False, "visible_status": status,
                "redirect_location_verified": bool(expected_location is not None and response_completed),
                # The client socket is the bounded source of truth for the
                # committed P4 Safe status. Do not infer it from the
                # intermediate P4 deny event or a case/path name.
                "p4_outcome": "none",
                "p4_visible_status": status if case == "p4_safe" and response_completed else None,
                "p4_response_committed": bool(response_completed and case in {"p1_allow", "p2_allow", "p4_safe"}),
            }
            upstream = {
                "lease_observed": upstream_observation["lease_header_observed"],
                "request_terminal": case in {"p1_deny", "p2_deny", "p2_oversize"},
                "response_observed": upstream_observation["requests_seen"] > 0,
            }
            stem = args.manifest.stem
            client_leaf = f"{stem}.client.json"
            upstream_leaf = f"{stem}.upstream.json"
            write_json(runtime, client_leaf, client, "client receipt")
            write_json(runtime, upstream_leaf, upstream, "upstream receipt")
            manifest = {
                "schema": SCHEMA, "connector": args.connector, "case": case,
                "case_artifact": {"id": f"traefik-{case}", "event_log": event_leaf},
                "expected_phases": list(CASES[case]),
                "client_observation": client_leaf,
                "upstream_observation": upstream_leaf,
                "cleanup": {"count": 1, "status": "completed"},
            }
            write_json(runtime, manifest_leaf, manifest, "case manifest")
        print(json.dumps({"case": case, "decision_id": decision_id, "status": status}, sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"traefik_composite_case_driver: FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
