"""Original-ID patched lighttpd fixtures using the existing I12 native capture.

This producer never assigns lifecycle qualification. Specs declare expectations before execution;
the Root-owned original Oracle/35-observation qualifier reviews the physical
client, backend, native, host and cleanup artifacts independently.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import load_source

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import re
import signal
import stat
import socket
import struct
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Load the maintained Parent filesystem boundary from this checkout.
import sys as _i12_sys

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths


ROUTE = "lighttpd-patched-native"
RESPONSE = b"i12-qualified-response-marker-end"
REQUEST = b"i12-qualified-request-marker-end"
NEIGHBOR_RESPONSE = b"healthy"
EXTERNAL_ROOT = Path(os.environ.get("I12_TEST_ROOT", "/__i12_external_root_requires_I12_TEST_ROOT__")).absolute()
PROC_ROOT = Path("/proc")

TEXT_PLAIN = 'text/plain'
MODULE_SOURCE = 'connectors/lighttpd/module/mod_msconnector.c'
PATCHED_PATH_PREFIX = '/i12/patched/'
BACKEND_LOG = 'backend.jsonl'
BACKEND_TRANSPORT_LOG = 'backend-transport.jsonl'
BACKEND_READY = 'backend-ready.json'
DISPOSABLE_MARKER = '.i12-disposable-source-copy.json'
FIXTURE_SPEC = 'fixture-spec.json'
RULES_CONFIG = 'rules.conf'
AUDIT_LOG = 'audit.log'
NATIVE_LOG = 'native.jsonl'
HOST_LOG = 'host.jsonl'
FAULT_LOG = 'fault.jsonl'
EVENT_LOG = 'events.jsonl'
SNAPSHOT = 'snapshot.json'
CAPTURE_RECEIPT = 'capture_case.json'


def validate_storage(path, writing):
    if writing and path.is_relative_to(EXTERNAL_ROOT):
        for directory in (EXTERNAL_ROOT.parent, EXTERNAL_ROOT):
            storage = directory.lstat()
            if (not stat.S_ISDIR(storage.st_mode) or storage.st_uid != os.geteuid()
                    or storage.st_mode & 0o022):
                raise ValueError("Evidence storage must be caller-owned without shared write access")


def evidence_path(path, *, writing=False):
    path = Path(path).absolute()
    resolved = path.resolve(strict=False)
    validate_storage(path, writing)
    writable = (EXTERNAL_ROOT, Path("/task"))
    readable = (*writable, Path("/mnt/fixtures"), Path("/mnt/artifacts"), Path("/usr"), PROC_ROOT)
    if writing and resolved != path:
        raise ValueError("Evidence output must not traverse symlinks or dot components")
    if not any(resolved.is_relative_to(root) for root in (writable if writing else readable)):
        raise ValueError("Evidence path is outside the declared fixture/source/image roots")
    if writing and path.exists():
        details = path.stat()
        if not path.is_file() or details.st_nlink != 1 or details.st_uid != os.geteuid():
            raise ValueError("Evidence output is not a caller-owned single-link regular file")
    return path


def read_json(path):
    return json.loads(evidence_path(path).read_text())


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    return digest(evidence_path(path).read_bytes())


def write(path, value):
    path = evidence_path(path, writing=True)
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        details = os.fstat(fd)
        if not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid() or details.st_nlink != 1:
            raise ValueError("Evidence output must be a caller-owned single-link regular file")
        os.fchmod(fd, 0o600)
        os.ftruncate(fd, 0)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(payload)
    finally:
        os.close(fd)


def append(path, value):
    path = evidence_path(path, writing=True)
    encoded = (json.dumps(value, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        stat = os.fstat(fd)
        if stat.st_uid != os.geteuid() or stat.st_nlink != 1 or stat.st_mode & 0o077:
            raise ValueError("unsafe physical observation file")
        if os.write(fd, encoded) != len(encoded):
            raise OSError("incomplete physical observation write")
    finally:
        os.close(fd)


def request_fixture(spec):
    case = spec["case"]
    if case == "NEED-request-empty":
        spec["request_hex"] = ""
        spec["request_chunks"] = []
        spec["expectations"]["native_request_append_min"] = 0
    if case in ("NEED-request-streaming", "NEED-native-request-response-hooks", "NEED-body-feed"):
        spec["request_chunks"] = [3, len(REQUEST) - 3]
        spec["expectations"]["native_request_append_min"] = 2
    if case == "NEED-request-content-type-missing":
        spec["request_content_type"] = None
    if case == "NEED-request-charset-present":
        spec["request_content_type"] = "text/plain; charset=utf-8"
    if case == "NEED-request-csv":
        spec.update(request_content_type="text/csv", request_hex=b"column,value\r\nkey,benign\r\n".hex())
        spec["request_chunks"] = [len(bytes.fromhex(spec["request_hex"]))]
    if case == "NEED-request-mime-scope-out":
        spec["request_content_type"] = "application/octet-stream"


def response_fixture(spec):
    case = spec["case"]
    if case == "NEED-response-file":
        spec["response_input"] = "file"
    if case == "NEED-response-empty":
        spec["response_hex"] = ""
        spec["response_chunks"] = []
        spec["expectations"]["response_entity_sha256"] = digest(b"")
    if case in ("NEED-response-streaming", "NEED-native-request-response-hooks", "NEED-body-feed"):
        spec["response_chunks"] = [5, len(RESPONSE) - 5]
    if case == "NEED-response-content-type-missing":
        spec["response_content_type"] = None
    if case == "NEED-response-charset-present":
        spec["response_content_type"] = "text/plain; charset=utf-8"
    if case == "NEED-response-mime-scope-out":
        spec["response_content_type"] = "application/octet-stream"
    if case == "NEED-response-csv":
        spec["response_content_type"] = "text/csv"


def limit_fixtures(spec):
    case = spec["case"]
    if case in ("NEED-request-reject", "NEED-request-process-partial"):
        spec["request_limit"] = 16
        spec["request_limit_action"] = "Reject" if case.endswith("reject") else "ProcessPartial"
        if case.endswith("reject"):
            spec["oracle_proposal"].update(native_result="body_limit", visible_status=403)
            spec["expectations"].update(backend_main_count=0, response_eos=None,
                native_response_body_process=0, response_entity_sha256=None, common_terminal_events=None)
    if case in ("NEED-response-reject", "NEED-response-process-partial"):
        spec["response_limit"] = 16
        spec["response_limit_action"] = "Reject" if case.endswith("reject") else "ProcessPartial"
        spec["response_chunks"] = [5, len(RESPONSE) - 5]
        if case.endswith("reject"):
            spec["oracle_proposal"].update(native_result="postcommit_body_limit_safe_log_only", phase=4)
            spec["expectations"]["common_terminal_events"] = None


def abnormal_fixture(spec):
    case = spec["case"]
    if case in ("NEED-missing-eos", "NEED-incomplete-framing"):
        spec["backend_short_length"] = True
        spec["oracle_proposal"].update(native_result="upstream_disconnect", visible_status=200, phase=4)
        spec["expectations"].update(client_exit=1, response_eos=0, native_response_body_process=0, common_terminal_events=None)
    if case == "NEED-invalid-metadata":
        spec["max_header_count"] = 8
        spec["request_extra_headers"] = [[f"X-I12-Extra-{index}", "value"] for index in range(8)]
        spec["oracle_proposal"].update(native_result="mapping_failure_before_transaction", visible_status=None, phase=None)
        spec["expectations"].update(backend_main_count=0, client_exit=1, native_request_append_min=None,
            native_request_body_process=None, native_response_body_process=None, native_logging=None, native_cleanup=None,
            response_eos=None, common_terminal_events=None, response_entity_sha256=None)


def intervention_fixture(spec):
    case = spec["case"]
    if case in ("NEED-supported-postcommit-action", "NEED-abort-reset-observation"):
        spec["disruptive_phase"] = 4
        spec["response_chunks"] = [5, len(RESPONSE) - 5]
        spec["oracle_proposal"].update(native_result="late_intervention_log_only", rule_id=941234, phase=4)
        spec["expectations"]["common_terminal_events"] = None
    if case == "NEED-abort-reset-observation":
        spec["phase4_mode"] = "strict"
        spec["oracle_proposal"].update(native_result="configuration_rejected_unsupported_strict", visible_status=None)
    if case == "NEED-p3-redirect":
        spec["disruptive_phase"] = 3
        spec["redirect"] = True
        spec["oracle_proposal"].update(native_result="redirect_normalized_to_deny", visible_status=403, rule_id=941233, phase=3)
        spec["expectations"].update(response_entity_sha256=None, native_response_body_process=0, response_eos=None, common_terminal_events=None)


def former_limit_fixture(spec):
    case = spec["case"]
    if case not in ("NEED-request-above-former-connector-limit", "NEED-response-above-former-connector-limit"):
        return
    direction = "request" if case.startswith("NEED-request") else "response"
    marker = REQUEST if direction == "request" else RESPONSE
    body = b"x" * (1048576 + 2048) + marker
    spec[direction + "_hex"] = body.hex()
    spec[direction + "_chunks"] = [524288, len(body) - 524288]
    spec[direction + "_limit"] = 2097152
    spec["former_cap_bytes"] = 1048576
    spec["former_cap_source"] = "connectors/lighttpd/tests/test_stock_sidecar_contract.py::test_request_marker_after_former_cap_reaches_native_p2_without_upstream"
    if direction == "request":
        spec["expectations"]["native_request_append_min"] = 2
    else:
        spec["expectations"]["response_entity_sha256"] = digest(body)


def definitions():
    """Pre-execution declarations; names never substitute for original contracts."""
    specifications = []
    for case in ("NEED-request-single-chunk", "NEED-request-streaming", "NEED-request-content-type-present",
                 "NEED-request-empty", "NEED-request-file", "NEED-request-content-type-missing",
                 "NEED-request-charset-present", "NEED-request-charset-missing", "NEED-request-mime-scope-in",
                 "NEED-request-csv", "NEED-request-eos-once", "NEED-request-marker-at-payload-end",
                 "NEED-request-mime-scope-out", "NEED-request-above-former-connector-limit",
                 "NEED-response-above-former-connector-limit",
                 "NEED-response-empty", "NEED-response-single-chunk", "NEED-response-file",
                 "NEED-response-streaming", "NEED-response-content-type-present",
                 "NEED-response-content-type-missing", "NEED-response-charset-present",
                 "NEED-response-charset-missing", "NEED-response-mime-scope-in",
                 "NEED-response-mime-scope-out", "NEED-response-csv", "NEED-response-marker-at-payload-end",
                 "NEED-request-reject", "NEED-request-process-partial", "NEED-response-reject",
                 "NEED-response-process-partial", "NEED-missing-eos", "NEED-incomplete-framing",
                 "NEED-invalid-metadata", "NEED-native-request-response-hooks", "NEED-body-feed",
                 "NEED-client-response-bytes", "NEED-client-exit-signal", "NEED-neighbor-connection-stream",
                 "NEED-current-patch-binary-provenance", "NEED-supported-postcommit-action",
                 "NEED-abort-reset-observation", "NEED-p3-redirect"):
        spec = {"original_id": f"I12::{ROUTE}::{case}", "case": case,
            "request_hex": REQUEST.hex(), "response_hex": RESPONSE.hex(),
            "request_content_type": TEXT_PLAIN, "response_content_type": TEXT_PLAIN,
            "request_chunks": [len(REQUEST)], "response_chunks": [len(RESPONSE)],
            "phase4_mode": "safe", "request_limit": 1048576, "response_limit": 1048576,
            "request_limit_action": "Reject", "response_limit_action": "Reject",
            "backend_short_length": False, "max_header_count": 64,
            "request_extra_headers": [], "disruptive_phase": None,
            "oracle_proposal": {"native_result": "allow", "visible_status": 200,
                "rule_id": None, "phase": 2, "event_fields": [],
                "unresolved_expected_value_reason": None,
                "physical_evidence_not_projection": True},
            "expectations": {"backend_main_count": 1, "client_exit": 0,
                "response_entity_sha256": digest(RESPONSE), "native_request_body_process": 1,
                "native_response_body_process": 1, "native_logging": 1, "native_cleanup": 1,
                "native_request_append_min": 1, "response_eos": 1,
                "common_terminal_events": 0},
            "oracle_basis": [
                {"path": MODULE_SOURCE,
                 "symbols": ["mod_msconnector_finish_request_body", "mod_msconnector_handle_response_body", "mod_msconnector_handle_request_reset"]},
                {"path": "common/src/modsecurity_engine.c", "contract": "SDK-owned body processing and intervention"},
                {"path": "fixture:rules.conf", "contract": "Explicit pass/log P2/P4 rules; no matching disruptive rule in benign fixtures"},
                {"path": "fixture:backend specification", "contract": "Declared response literal and Content-Length, independent of client observations"}],
            "qualification_policy": "Root review and existing original oracle reconciliation required; producer does not qualify."}
        request_fixture(spec)
        response_fixture(spec)
        limit_fixtures(spec)
        abnormal_fixture(spec)
        intervention_fixture(spec)
        former_limit_fixture(spec)
        specifications.append(spec)
    return specifications


def canonical_spec(base, original, contract, baseline_rules):
    """Bind an original selected row to its actual canonical source contract.

    The caller parses the immutable YAML outside the isolated host fixture.
    Runtime subprocesses only need the fully materialized JSON declaration.
    """
    spec = copy.deepcopy(base)
    selected = original["selected_requirement"]
    case = selected["case_id"]
    spec.update(case=case, original_id=original["run_scoped_case_id"])
    spec["original_selected_requirement"] = selected
    spec["canonical_contract"] = contract
    spec["oracle_proposal"] = copy.deepcopy(selected["expected_oracle"])
    request = contract.get("request", {})
    response = contract.get("response", {})
    spec.update(method=request.get("method", "GET"),
        path=request.get("path", PATCHED_PATH_PREFIX + case),
        request_hex=request.get("body", "").encode().hex(),
        response_hex=response.get("body", RESPONSE.decode()).encode().hex())
    request_headers = request.get("headers", {})
    if isinstance(request_headers, dict):
        headers = list(request_headers.items())
    else:
        headers = [(h["name"], h["value"]) for h in request_headers]
    spec["request_content_type"] = None
    spec["request_extra_headers"] = []
    for name, value in headers:
        if name.lower() == "content-type":
            spec["request_content_type"] = value
        else:
            spec["request_extra_headers"].append([name, str(value)])
    spec["response_extra_headers"] = list(response.get("headers", {}).items())
    spec["request_chunks"] = [len(bytes.fromhex(spec["request_hex"]))] if spec["request_hex"] else []
    spec["response_chunks"] = [len(bytes.fromhex(spec["response_hex"]))] if spec["response_hex"] else []
    spec["rules_extra"] = baseline_rules + "\n" + contract.get("rules", "")
    spec["expectations"]["native_request_append_min"] = int(bool(spec["request_hex"]))
    spec["expectations"]["response_entity_sha256"] = digest(bytes.fromhex(spec["response_hex"]))
    spec["expectations"]["common_terminal_events"] = None
    phase = spec["oracle_proposal"]["phase"]
    status = spec["oracle_proposal"]["visible_status"]
    if status in (403, 429):
        spec["expectations"].update(response_entity_sha256=None,
            native_response_body_process=0, response_eos=None)
        if phase < 3:
            spec["expectations"]["backend_main_count"] = 0
        if phase == 1:
            spec["expectations"].update(native_request_body_process=0, native_request_append_min=0)
    return spec


def decode_chunked_entity(encoded):
    chunks = []
    remaining = encoded
    while True:
        length_line, remaining = remaining.split(b"\r\n", 1)
        length = int(length_line.split(b";", 1)[0], 16)
        if length == 0:
            complete = remaining == b"\r\n"
            break
        if len(remaining) < length + 2 or remaining[length:length + 2] != b"\r\n":
            raise ValueError("truncated response chunk")
        chunks.append(remaining[:length]); remaining = remaining[length + 2:]
    entity = b"".join(chunks)
    return entity, complete


def response_decode(received):
    header, encoded = received.split(b"\r\n\r\n", 1)
    headers = header.decode("iso-8859-1").split("\r\n")
    status = int(headers[0].split()[1])
    fields = [line.split(":", 1) for line in headers[1:]]
    lengths = [v.strip() for n, v in fields if n.lower() == "content-length"]
    transfer = [v.strip().lower() for n, v in fields if n.lower() == "transfer-encoding"]
    if lengths and transfer:
        raise ValueError("ambiguous Content-Length and Transfer-Encoding")
    entity = encoded
    framing = "close_delimited"
    complete = True
    if lengths:
        framing = "content_length"
        if len(lengths) != 1 or not lengths[0].isdecimal():
            raise ValueError("ambiguous Content-Length")
        complete = int(lengths[0]) == len(entity)
    elif transfer:
        if transfer != ["chunked"]:
            raise ValueError("unsupported transfer coding")
        framing = "chunked"
        entity, complete = decode_chunked_entity(encoded)
    return {"status": status, "headers": headers, "entity_bytes": len(entity),
        "entity_sha256": digest(entity), "framing": {"kind": framing, "content_lengths": lengths,
        "transfer_encoding": transfer, "encoded_entity_bytes": len(encoded), "decoded_entity_bytes": len(entity),
        "complete": complete}}, header + b"\r\n\r\n", entity


def client_headers(spec, token, selected_request, body, chunked):
    types = spec["request_content_type"] if selected_request else TEXT_PLAIN
    headers = [("Host", "i12.patched.test"), ("Connection", "close"), ("X-I12-Token", token)]
    if types is not None:
        headers.append(("Content-Type", types))
    if selected_request:
        headers += [tuple(h) for h in spec.get("request_extra_headers", [])]
    if selected_request and spec.get("framing_headers"):
        headers.extend(spec["framing_headers"])
    else:
        headers.append(("Transfer-Encoding", "chunked") if chunked else ("Content-Length", str(len(body))))
    return headers


def partial_request_chunks(partial_control, chunked, chunks):
    if partial_control is not None:
        if partial_control not in ("reset", "await_host_idle_timeout") or not chunked:
            raise ValueError("partial control requires declared chunked wire")
        chunks = chunks[:1]
    return chunks


def client_request(spec, output, token):
    """Materialize the exact declared file input and HTTP wire fragments."""
    selected_request = token != "neighbor"
    body = bytes.fromhex(spec["request_hex"]) if selected_request else b"healthy-neighbor"
    path = spec.get("path", PATCHED_PATH_PREFIX + spec["case"]) if selected_request else "/i12/patched/neighbor"
    method = spec.get("method", "POST") if selected_request else "POST"
    body_file = output / (token + ".input-body")
    body_file.write_bytes(body); body_file.chmod(0o600)
    # Reopen the materialized body, so file cases exercise actual file input.
    body = body_file.read_bytes()
    chunk_sizes = spec["request_chunks"] if selected_request else [len(body)]
    chunked = len(chunk_sizes) > 1 or (selected_request and spec.get("request_wire_chunked", False))
    headers = client_headers(spec, token, selected_request, body, chunked)
    wire_head = (f"{method} {path} HTTP/1.1\r\n" + "".join(f"{n}: {v}\r\n" for n, v in headers) + "\r\n").encode()
    chunks = []
    offset = 0
    for size in chunk_sizes:
        part = body[offset:offset + size]; offset += size
        chunks.append(f"{len(part):x}\r\n".encode() + part + b"\r\n" if chunked else part)
    if offset != len(body):
        raise ValueError("request chunks do not cover materialized body")
    if chunked:
        chunks.append(b"0\r\n\r\n")
    partial_control = spec.get("client_partial_control") if selected_request else None
    chunks = partial_request_chunks(partial_control, chunked, chunks)
    return SimpleNamespace(body=body, path=path, body_file=body_file, chunk_sizes=chunk_sizes,
        chunked=chunked, partial_control=partial_control, wire_head=wire_head, chunks=chunks,
        selected_request=selected_request)


def client_receive_pause(spec, selected_request, row):
    receive_pause = spec.get("client_receive_pause_seconds", 0) if selected_request else 0
    if not receive_pause:
        return
    if not 0 < float(receive_pause) <= 2:
        raise ValueError("receive pause must be bounded to two seconds")
    row["actual_receive_pause_started_ns"] = time.monotonic_ns()
    time.sleep(float(receive_pause))
    row["actual_receive_pause_completed_ns"] = time.monotonic_ns()


def client_receive(connection, received, row):
    while True:
        started = time.monotonic_ns()
        data = connection.recv(65536)
        completed = time.monotonic_ns()
        if not data:
            row["tcp_eof_observed"] = True; row["eof_ns"] = completed
            return
        row["recv_chunks"].append({"started_ns": started, "completed_ns": completed,
            "bytes": len(data), "prior_bytes": len(received)})
        received.extend(data)
        if len(received) > 2 * 1048576:
            raise ValueError("bounded client response exceeds2MiB")


def client_exchange(connection, spec, prepared, received, row):
    connection.sendall(prepared.wire_head)
    for part in prepared.chunks:
        connection.sendall(part)
        row["send_chunks"].append({"completed_ns": time.monotonic_ns(), "bytes": len(part)})
        if prepared.chunked:
            time.sleep(0.04)
    client_receive_pause(spec, prepared.selected_request, row)
    if prepared.partial_control == "reset":
        time.sleep(0.2)
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        row.update(local_abort_requested=True, local_linger_zero_configured=True,
            peer_rst_observation_claimed=False, actual_request_body_complete=False)
        return True
    if prepared.partial_control is not None:
        row.update(actual_request_body_complete=False, partial_request_terminal_chunk_sent=False)
    client_receive(connection, received, row)
    return False


def local_port(value):
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError("fixture TCP port is outside 1..65535")
    return port


def client(spec_path, output, port, token):
    spec = read_json(spec_path)
    if re.fullmatch(r"[A-Za-z0-9_-]{1,96}", token) is None:
        raise ValueError("Client token must be a bounded path component")
    if token not in ("main", "neighbor"):
        spec = {**spec, **spec["sequence_requests"][token]}
    if token == "main" and spec.get("same_socket_requests"):
        helper = load_source(Path(__file__).with_name('diagnostic_transport.py'))
        return helper.capture(port, spec["same_socket_requests"], output / "main.receipt.json")
    prepared = client_request(spec, output, token)
    body, path, body_file = prepared.body, prepared.path, prepared.body_file
    chunks, wire_head = prepared.chunks, prepared.wire_head
    request = wire_head + b"".join(chunks)
    received = bytearray()
    row = {"pid": os.getpid(), "uid": os.geteuid(), "gid": os.getegid(), "token": token,
        "original_id": spec["original_id"], "path": path, "request_bytes": len(body),
        "request_sha256": digest(body), "request_file_sha256": sha(body_file),
        "started_ns": time.monotonic_ns(), "tcp_eof_observed": False,
        "tcp_reset_observed": False, "timeout_observed": False, "error": None, "recv_chunks": [], "send_chunks": []}
    if prepared.partial_control is not None:
        row.update(planned_request_body_bytes=len(body), actual_request_body_bytes_sent=prepared.chunk_sizes[0],
            request_payload_identity_scope="planned_materialized_input; actual transmitted prefix preserved in request.raw")
    exitcode = 1
    try:
        with socket.create_connection(("127.0.0.1", local_port(port)), timeout=10) as connection:
            if client_exchange(connection, spec, prepared, received, row):
                exitcode = 0
                return exitcode
        decoded, head, entity = response_decode(bytes(received))
        row.update(decoded)
        row["response_header_bytes"] = len(head)
        row["first_entity_recv_completed_ns"] = next((part["completed_ns"]
            for part in row["recv_chunks"] if part["prior_bytes"] + part["bytes"] > len(head)), None)
        (output / (token + ".headers")).write_bytes(head)
        (output / (token + ".body")).write_bytes(entity)
        exitcode = 0 if decoded["framing"]["complete"] else 1
        if exitcode:
            row["error"] = {"type": "IncompleteFraming", "message": "Declared Content-Length differs from received entity"}
    except (OSError, ValueError) as exc:
        row["tcp_reset_observed"] = isinstance(exc, ConnectionResetError)
        row["timeout_observed"] = isinstance(exc, TimeoutError)
        row["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        (output / (token + ".request.raw")).write_bytes(request)
        (output / (token + ".response.raw")).write_bytes(received)
        row.update(completed_ns=time.monotonic_ns(), proposed_process_exit=exitcode,
            response_wire_bytes=len(received), response_wire_sha256=digest(received))
        write(output / (token + ".receipt.json"), row)
    return exitcode


class FixtureBackendHandler(BaseHTTPRequestHandler):
    def delay_before_headers(self, main):
        spec = self.server.fixture_spec
        if main and spec.get("response_before_headers_delay_seconds"):
            delay = float(spec["response_before_headers_delay_seconds"])
            if not 0 < delay <= 2:
                raise ValueError("preheader delay must be bounded to two seconds")
            time.sleep(delay)

    def do_POST(self):
        spec, output = self.server.fixture_spec, self.server.fixture_output
        body, sizes, main = self.observe_fixture_request()
        self.delay_before_headers(main)
        self.send_response(200)
        content_type = spec["response_content_type"] if main else TEXT_PLAIN
        if content_type is not None:
            self.send_header("Content-Type", content_type)
        self.send_header("X-I12-Response", "present")
        for name, value in spec.get("response_extra_headers", []) if main else []:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body) + (5 if main and spec["backend_short_length"] else 0)))
        if main and spec.get("response_header_body_coalesced"):
            self._headers_buffer.append(b"\r\n")
            headers = b"".join(self._headers_buffer)
            self._headers_buffer.clear()
            self.connection.sendall(headers + body)
            append(output / BACKEND_TRANSPORT_LOG, {"pid": os.getpid(), "path": self.path,
                "kind": "response_write", "bytes": len(body), "offset": len(body),
                "header_bytes_in_same_sendall": len(headers), "monotonic_ns": time.monotonic_ns()})
            return
        self.end_headers()
        if main and spec.get("response_header_delay_seconds"):
            time.sleep(float(spec["response_header_delay_seconds"]))
        self.send_fixture_body(body, sizes, main)

    def observe_fixture_request(self):
        spec, output = self.server.fixture_spec, self.server.fixture_output
        response_file = self.server.fixture_response_file
        consumed = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        main = self.path == spec.get("path", PATCHED_PATH_PREFIX + spec["case"])
        if main and response_file is not None:
            body = response_file.read_bytes()
        else:
            body = bytes.fromhex(spec["response_hex"]) if main else NEIGHBOR_RESPONSE
        sizes = spec["response_chunks"] if main else [len(body)]
        event = {"pid": os.getpid(), "uid": os.geteuid(), "gid": os.getegid(),
            "path": self.path, "method": self.command, "headers": list(self.headers.items()),
            "body_bytes_consumed": len(consumed), "body_sha256": digest(consumed),
            "response_source_body_sha256": digest(body), "monotonic_ns": time.monotonic_ns()}
        if main and response_file is not None:
            event["actual_response_file_read"] = {"path": str(response_file), "read_bytes": len(body),
                "read_sha256": digest(body), "physical_file_sha256": sha(response_file),
                "mode": oct(response_file.stat().st_mode & 0o777), "uid": response_file.stat().st_uid}
        append(output / BACKEND_LOG, event)
        return body, sizes, main

    def send_fixture_body(self, body, sizes, main):
        spec, output = self.server.fixture_spec, self.server.fixture_output
        offset = 0
        try:
            for size in sizes:
                part = body[offset:offset + size]; offset += size
                self.wfile.write(part); self.wfile.flush()
                append(output / BACKEND_TRANSPORT_LOG, {"pid": os.getpid(), "path": self.path,
                    "kind": "response_write", "bytes": len(part), "offset": offset,
                    "monotonic_ns": time.monotonic_ns()})
                if len(sizes) > 1:
                    time.sleep(0.05)
            append(output / BACKEND_TRANSPORT_LOG, {"pid": os.getpid(), "path": self.path,
                "kind": "response_complete", "physical_bytes": offset,
                "declared_short_fixture": bool(main and spec["backend_short_length"]),
                "monotonic_ns": time.monotonic_ns()})
        except OSError as exc:
            append(output / BACKEND_TRANSPORT_LOG, {"pid": os.getpid(), "path": self.path,
                "kind": "write_error", "error_type": type(exc).__name__, "errno": exc.errno,
                "monotonic_ns": time.monotonic_ns()})
    def log_message(self, *_):
        # The independent JSONL transport records replace console access logs.
        pass
    do_GET = do_POST
    do_PUT = do_POST


def backend(spec_path, output):
    spec = read_json(spec_path)
    response_file = None
    if spec.get("response_input") == "file":
        response_file = evidence_path(output / "backend-response.input", writing=True)
        response_file.write_bytes(bytes.fromhex(spec["response_hex"]))
        response_file.chmod(0o600)
    with ThreadingHTTPServer(("127.0.0.1", 0), FixtureBackendHandler) as server:
        server.fixture_spec = spec
        server.fixture_output = output
        server.fixture_response_file = response_file
        write(output / BACKEND_READY, {"pid": os.getpid(), "port": server.server_port,
            "uid": os.geteuid(), "gid": os.getegid(), "monotonic_ns": time.monotonic_ns()})
        server.serve_forever()


def starttime(pid):
    return (PROC_ROOT / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()[19]


def disposable_collector(source):
    source = Path(source).absolute()
    if source.resolve() != source or not source.is_relative_to(EXTERNAL_ROOT):
        raise ValueError("MIME overlay needs a physical authorized external source copy")
    marker = json.loads((source / DISPOSABLE_MARKER).read_text())
    if marker.get("disposable") is not True or marker.get("path") != str(source):
        raise ValueError("MIME overlay requires a matching disposable-copy marker")
    collector = source / "ci/runtime/lifecycle/native-lifecycle-observer.c"
    for path in (collector, *collector.parents):
        if path.is_symlink():
            raise ValueError("MIME overlay refuses symlink source components")
        if path == source:
            break
    if collector.stat().st_nlink != 1 or (source / ".git").exists():
        raise ValueError("MIME overlay refuses linked inputs or a checkout")
    return source, collector


def extend_mime_capture(source, accessor):
    """Extend the exact existing lighttpd collector in a disposable source copy."""
    source, collector = disposable_collector(source)
    before = sha(collector)
    if before != "270245fedf253e4ef502fc1aedcac5406ee516b85c90002cb7deaff69fb91736":
        raise ValueError("MIME extension requires the exact existing lighttpd collector variant")
    text = collector.read_text()
    replacements = [
        ("    const void *joined_native;", "    const void *joined_native;\n    void *native_engine;"),
        ("    int finalize_known;", "    char mime_selection[2048];\n    int finalize_known;"),
        ("        if (extracted == 1) entry->id_origin", "        entry->native_engine = engine;\n        if (extracted == 1) entry->id_origin"),
        ('\\\"native_mime_selection\\\":null', '\\\"native_mime_selection\\\":%s'),
        ("input_size, input_kind, pending, live, allocation,", "input_size, input_kind, pending, live,\n        observed->mime_selection[0] == '\\0' ? \"null\" : observed->mime_selection, allocation,"),
        ("NATIVE_WRAPPER(process_response_body, 4)", '''extern int msconnector_lifecycle_sdk_mime_selection(void *, const void *, char *, size_t);
static void observed_mime_snapshot(struct observed_subject *observed, Transaction *transaction) {
    const int saved_errno = errno;
    void *engine = NULL;
    (void)pthread_mutex_lock(&lock);
    struct mapping *mapping = lookup(transaction, 1);
    if (mapping != NULL) engine = mapping->native_engine;
    (void)pthread_mutex_unlock(&lock);
    if (msconnector_lifecycle_sdk_mime_selection(engine, transaction,
            observed->mime_selection, sizeof(observed->mime_selection)) != 1) invalid();
    errno = saved_errno;
}
extern int __real_msc_process_response_body(Transaction *);
int __wrap_msc_process_response_body(Transaction *transaction) {
    struct observed_subject observed = subject(transaction, 1, 4);
    observed_mime_snapshot(&observed, transaction);
    uint64_t call = enter_subject("native_process_response_body", &observed, NULL);
    int result = __real_msc_process_response_body(transaction);
    returned_subject("native_process_response_body", call, &observed, result, 0, NULL);
    return result;
}'''),
        ("    int result = __real_msc_process_response_headers(transaction, status, protocol);\n",
         "    int result = __real_msc_process_response_headers(transaction, status, protocol);\n    observed_mime_snapshot(&observed, transaction);\n"),
    ]
    for original, replacement in replacements:
        if text.count(original) != 1:
            raise ValueError("Exact MIME overlay anchor absent or ambiguous: " + original)
        text = text.replace(original, replacement)
    destination = source / "ci/runtime/lifecycle/native-lifecycle-sdk-mime.cpp"
    if destination.exists():
        raise ValueError("MIME accessor destination already exists")
    collector.write_text(text)
    destination = evidence_path(destination, writing=True)
    destination.write_bytes(evidence_path(accessor).read_bytes())
    constructor = extend_constructor_capture(collector)
    return {"collector_before_sha256": before, "collector_after_sha256": sha(collector),
        "accessor_source_sha256": sha(destination), "existing_trace_field_extended": "native_mime_selection",
        "actual_boundary": "Actual SDK response-header return and response-body entry; metadata snapshots do not assert phase4 processing",
        "production_sources_changed": False, "opaque_offsets_used": False,
        "constructor_output_observation": constructor}


def extend_constructor_capture(collector):
    """Sample constructor output slot after the actual return, including failure."""
    collector = evidence_path(collector, writing=True)
    source = collector.parents[3]
    marker = read_json(source / DISPOSABLE_MARKER)
    if marker.get("disposable") is not True or marker.get("path") != str(source) or (source / ".git").exists():
        raise ValueError("Constructor observation requires a marked disposable source copy")
    text = collector.read_text()
    replacements = [
        ("    int finalize_known;", "    int output_slot_known;\n    int output_argument_present;\n    int actual_output_handle_present;\n    int finalize_known;"),
        ('\\\"runtime_finalize_snapshot\\\":%s}\\n',
         '\\\"runtime_finalize_snapshot\\\":%s,\\\"output_argument_present\\\":%s,\\\"actual_output_handle_present\\\":%s}\\n'),
        ("kind, wall_ns, wall_sample_end_ns, framing, finalize);",
         'kind, wall_ns, wall_sample_end_ns, framing, finalize,\n        observed->output_slot_known ? (observed->output_argument_present ? "true" : "false") : "null",\n        observed->output_slot_known ? (observed->actual_output_handle_present ? "true" : "false") : "null");'),
        ("    returned(label, call, transaction, 2, 1, result, 0); \\",
         "    struct observed_subject observed = subject(transaction, 2, 1); \\\n    observed.output_slot_known = 1; \\\n    observed.output_argument_present = out != NULL; \\\n    observed.actual_output_handle_present = out != NULL && *out != NULL; \\\n    returned_subject(label, call, &observed, result, 0, NULL); \\")
    ]
    for original, replacement in replacements:
        if text.count(original) != 1:
            raise ValueError("Constructor output observation anchor missing or ambiguous")
        text = text.replace(original, replacement, 1)
    collector.write_text(text)
    return {"output_slot_read_after_real_return": True,
        "output_handle_dereferenced": False, "failure_result_replaced": False,
        "fields": ["output_argument_present", "actual_output_handle_present"]}


def rebase_host_observation(source, current_module):
    """Reapply the existing additive host observer onto the current product.

    An old profile contains a complete historical module. Never use that file
    as current product input: the independently hashed current module is the
    base, and removing these four additions must reproduce it byte for byte.
    """
    source = Path(source).absolute()
    marker = read_json(source / DISPOSABLE_MARKER)
    if source.resolve() != source or marker.get("disposable") is not True or marker.get("path") != str(source):
        raise ValueError("Host observation needs a physical marked disposable source copy")
    destination = evidence_path(source / MODULE_SOURCE, writing=True)
    current = evidence_path(current_module).read_text()
    replacements = [
        ('#include "first.h"', '#include "lighttpd-host-observer.h"\n#include "first.h"'),
        ('    if (r->reqbody_length == 0) {', '    if (r->reqbody_length == 0) {\n        lighttpd_observe_empty_request_boundary(ctx->transaction, (int64_t)r->reqbody_length);'),
        ('    if (length > 0 && !lighttpd_modsecurity_visit_body_range(', '    lighttpd_observe_body("patched_request_body_hook", ctx->transaction,\n        (int64_t)r->reqbody_length, (int64_t)stream_offset, (size_t)length, eos);\n    if (length > 0 && !lighttpd_modsecurity_visit_body_range('),
        ('    msconnector_error_init(&runtime_error);\n    if (length > 0U && msconnector_runtime_transaction_append_response_body_chunk(',
         '    msconnector_error_init(&runtime_error);\n    lighttpd_observe_body("patched_response_body_hook", ctx->transaction,\n        -1, (int64_t)stream_offset, length, eos);\n    if (length > 0U && msconnector_runtime_transaction_append_response_body_chunk('),
    ]
    observed = current
    for original, addition in replacements:
        if observed.count(original) != 1 or addition in observed:
            raise ValueError("Current lighttpd host observation seam absent or already modified")
        observed = observed.replace(original, addition, 1)
    restored = observed
    for original, addition in reversed(replacements):
        restored = restored.replace(addition, original, 1)
    if restored != current:
        raise ValueError("Observation delta does not preserve current product exactly")
    destination.write_text(observed)
    return {"current_product_module_sha256": digest(current.encode()),
        "observed_module_sha256": sha(destination),
        "stripped_observation_product_sha256": digest(restored.encode()),
        "current_product_byte_identity_after_stripping_observation": True,
        "historical_full_module_used_as_product": False, "additive_observation_seams": 4,
        "request_hook_sample": "actual argument boundary before body visit/append, including rejected invalid-pointer cases"}


def extend_fault_capture(source, sink_header, native_header):
    """Inject declared boundary errors after separately recorded actual calls."""
    source = Path(source).absolute()
    marker = read_json(source / DISPOSABLE_MARKER)
    if source.resolve() != source or marker.get("disposable") is not True or marker.get("path") != str(source):
        raise ValueError("Fault overlay needs a physical marked disposable copy")
    runtime = evidence_path(source / "common/runtime/msconnector_runtime.c", writing=True)
    before = sha(runtime)
    text = runtime.read_text()
    body_signature = ("int msconnector_runtime_transaction_append_request_body_chunk(\n"
        "    msconnector_runtime_transaction *transaction,\n    const unsigned char *data,\n"
        "    size_t size,\n    msconnector_error *error) {\n")
    replacements = [
        ("msc_process_request_headers(native->transaction) != 1",
         'i12_diagnostic_boundary_result("request_headers", msc_process_request_headers(native->transaction)) != 1'),
        ("msc_process_logging(native->transaction) != 1",
         'i12_diagnostic_boundary_result("logging", msc_process_logging(native->transaction)) != 1'),
        ("    if (native->transaction == NULL) {\n        free(native);",
         '    if (i12_pointer_null("constructor_null", native->transaction, 1U)) {\n        msc_transaction_cleanup(native->transaction);\n        native->transaction = NULL;\n    }\n    if (native->transaction == NULL) {\n        free(native);'),
        ("msconnector_open_private_event_file(path, &fd)", "i12_sink_open(path, &fd)"),
        ("fputs(json, runtime->event_file)", "i12_sink_puts(json, runtime->event_file)"),
        ("fflush(runtime->event_file)", "i12_sink_flush(runtime->event_file)"),
        ("fclose(runtime->event_file)", "i12_sink_close(runtime->event_file)"),
        (body_signature, body_signature + '    if (i12_pointer_null("body_null", data, size)) data = NULL;\n'),
        ("    return transaction_begin_internal(runtime, request, host_request_id, out,\n        decision, error, 1);",
         '    msconnector_request injected_request;\n    if (request != NULL && i12_pointer_null("headers_null", request->headers, request->header_count)) {\n        injected_request = *request;\n        injected_request.headers = NULL;\n        request = &injected_request;\n    }\n    return transaction_begin_internal(runtime, request, host_request_id, out,\n        decision, error, 1);'),
    ]
    for original, replaced in replacements:
        if text.count(original) != 1:
            raise ValueError("Explicit Runtime boundary fault anchor missing or ambiguous: " + original)
        text = text.replace(original, replaced, 1)
    text = ('#ifndef _GNU_SOURCE\n#define _GNU_SOURCE\n#endif\n'
        '#include "patched_faults.h"\n#include "diagnostic_faults.h"\n' + text)
    runtime.write_text(text)
    for original, name in ((sink_header, "patched_faults.h"), (native_header, "diagnostic_faults.h")):
        destination = evidence_path(source / name, writing=True)
        if destination.exists():
            raise ValueError("Fault header already exists")
        destination.write_bytes(evidence_path(original).read_bytes())
    return {"runtime_product_before_sha256": before, "runtime_fault_overlay_sha256": sha(runtime),
        "sink_header_sha256": sha(source / "patched_faults.h"),
        "native_fault_header_sha256": sha(source / "diagnostic_faults.h"),
        "real_sdk_observer_return_modified": False, "kernel_sink_failure_claimed": False,
        "injection_scope": "Explicit once-per-host selected test boundary; actual SDK/I/O and injected return logged separately"}


def find_child(launcher, executable):
    expected = Path(executable).resolve()
    for proc in PROC_ROOT.iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            parent = int((proc / "stat").read_text().rsplit(")", 1)[1].split()[1])
            if parent == launcher and (proc / "exe").resolve() == expected:
                return int(proc.name), starttime(int(proc.name))
        except (OSError, ValueError):
            continue
    raise RuntimeError("actual native child not found")


def listening(port):
    return any(line.split()[3] == "0A" and line.split()[1].endswith(f":{port:04X}")
        for line in (PROC_ROOT / "net/tcp").read_text().splitlines()[1:])


class CaptureActors:
    def __init__(self, **values):
        self.__dict__.update(values)

    def launch(self, name, command):
        stdout = (self.root / (name + ".stdout")).open("xb")
        stderr = (self.root / (name + ".stderr")).open("xb"); self.streams.extend((stdout, stderr))
        argv = ["rtk", "proxy", *map(str, command)]
        process = subprocess.Popen(argv, env=self.env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
        self.actors[name] = {"process": process, "argv": argv, "launcher_starttime": starttime(process.pid),
            "executable": str(command[0]), "native_pid": None, "native_starttime": None}
        return process
    def wait(self, name, predicate):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            row = self.actors[name]
            if row["process"].poll() is not None:
                raise RuntimeError(name + " exited before readiness")
            if predicate():
                row["native_pid"], row["native_starttime"] = find_child(row["process"].pid, row["executable"])
                return
            time.sleep(0.03)
        raise TimeoutError(name + " readiness")
    def snapshot(self, label):
        folder = self.root / "snapshots" / label; folder.mkdir(parents=True, mode=0o700)
        row = {"monotonic_ns": time.monotonic_ns(), "actors": {}, "physical_files": {}}
        for name, actor in self.actors.items():
            pid = actor["native_pid"]; proc = PROC_ROOT / str(pid)
            if starttime(pid) != actor["native_starttime"]:
                raise RuntimeError("native process starttime changed")
            maps = (proc / "maps").read_bytes(); status = (proc / "status").read_bytes()
            fds = {p.name: os.readlink(p) for p in (proc / "fd").iterdir()}
            (folder / (name + ".maps")).write_bytes(maps)
            (folder / (name + ".status")).write_bytes(status)
            write(folder / (name + ".fds.json"), fds)
            row["actors"][name] = {"pid": pid, "starttime": actor["native_starttime"],
                "launcher_pid": actor["process"].pid, "launcher_starttime": actor["launcher_starttime"],
                "argv": actor["argv"], "exe": os.readlink(proc / "exe"), "exe_sha256": sha(proc / "exe"),
                "maps_sha256": digest(maps), "status_sha256": digest(status), "fds": fds}
        for name in (EVENT_LOG, NATIVE_LOG, HOST_LOG, BACKEND_LOG):
            p = self.root / name
            row["physical_files"][name] = None if not p.exists() else {"sha256": sha(p), "bytes": p.stat().st_size,
                "uid": p.stat().st_uid, "mode": oct(p.stat().st_mode & 0o777)}
        write(folder / SNAPSHOT, row); self.snapshots.append(str(folder / SNAPSHOT))
    def run_client(self, token, port):
        argv = ["rtk", "proxy", sys.executable, "-B", str(Path(__file__).resolve()), "client",
            "--spec", str(self.spec_path), "--output", str(self.client_root), "--port", str(port), "--token", token]
        result = subprocess.run(argv, env=self.env, capture_output=True, timeout=30)
        (self.client_root / (token + ".stdout")).write_bytes(result.stdout)
        (self.client_root / (token + ".stderr")).write_bytes(result.stderr)
        row = {"argv": argv, "actual_returncode": result.returncode,
            "actual_signal": -result.returncode if result.returncode < 0 else None,
            "receipt": str(self.client_root / (token + ".receipt.json"))}
        write(self.client_root / (token + ".waited.json"), row); self.receipt["clients"][token] = row


def cleanup_actor(name, actor, cleanups):
    process = actor["process"]
    if process.poll() is None:
        if starttime(process.pid) != actor["launcher_starttime"]:
            raise RuntimeError("refuse signaling replaced launcher")
        if actor["native_pid"] is not None:
            if starttime(actor["native_pid"]) != actor["native_starttime"]:
                raise RuntimeError("refuse signaling replaced native actor")
            os.kill(actor["native_pid"], signal.SIGTERM)
        else:
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=5)
    try:
        native_gone = starttime(actor["native_pid"]) != actor["native_starttime"]
    except (FileNotFoundError, TypeError):
        native_gone = True
    cleanups.append({"actor": name, "launcher_pid": process.pid,
        "actual_returncode": process.returncode, "launcher_reaped": process.poll() is not None,
        "native_pid": actor["native_pid"], "native_starttime": actor["native_starttime"],
        "same_starttime_pid_gone": native_gone})


def cleanup_actors(actors, streams, cleanups):
    for name, actor in reversed(list(actors.items())):
        cleanup_actor(name, actor, cleanups)
    for stream in streams:
        stream.close()


def capture_configuration(spec, root):
    rules = root / RULES_CONFIG
    rule_lines = ["SecRuleEngine On", "SecRequestBodyAccess On", "SecResponseBodyAccess On",
        "SecResponseBodyMimeType text/plain text/csv", f"SecRequestBodyLimit {spec['request_limit']}",
        f"SecRequestBodyNoFilesLimit {spec['request_limit']}", f"SecRequestBodyLimitAction {spec['request_limit_action']}",
        f"SecResponseBodyLimit {spec['response_limit']}", f"SecResponseBodyLimitAction {spec['response_limit_action']}",
        "SecAuditEngine On", "SecAuditLogType Serial", "SecAuditLogParts ABHZ",
        f'SecAuditLog "{root}/audit.log"', f'SecDebugLog "{root}/debug.log"', "SecDebugLogLevel 9",
        'SecRule REQUEST_METHOD "@streq POST" "id:941231,phase:2,pass,log,msg:\'I12 qualified native P2\'"',
        'SecRule RESPONSE_BODY "@contains qualified-response" "id:941232,phase:4,pass,log,msg:\'I12 qualified native P4\'"']
    if spec.get("disruptive_phase") == 4:
        rule_lines.append('SecRule RESPONSE_BODY "@contains response-marker" "id:941234,phase:4,deny,status:406,log,msg:\'I12 Safe postcommit\'"')
    if spec.get("redirect"):
        rule_lines.append('SecRule REQUEST_URI "@contains NEED-p3-redirect" "id:941233,phase:3,redirect:https://fixture.invalid/target,log,msg:\'I12 redirect normalization\'"')
    extra_rules = spec.get("rules_extra", "")
    extra_rules = extra_rules.replace("@@AUDIT_LOG@@", str(root / AUDIT_LOG))
    extra_rules = extra_rules.replace("@@AUDIT_LOG_DIR@@", str(root))
    rule_lines.append(extra_rules)
    audit_format = spec.get("audit_log_format")
    if audit_format is not None:
        if audit_format != "JSON":
            raise ValueError("unsupported test audit format")
        rule_lines.append("SecAuditLogFormat JSON")
    rules.write_text("\n".join(rule_lines) + "\n"); rules.chmod(0o600)
    runtime = root / "runtime.conf"
    runtime.write_text("\n".join(["enabled=on", f"rules_file={rules}", "request_body_mode=streaming",
        "response_body_mode=streaming", f"phase4_mode={spec['phase4_mode']}",
        f"max_header_count={spec['max_header_count']}", "default_block_status=403",
        f"default_error_status={spec.get('default_error_status', 502)}",
        f"event_path={spec.get('event_path_override', str(root / EVENT_LOG))}", ""]))
    if spec.get("max_event_json_bytes") is not None:
        with runtime.open("a") as stream:
            stream.write(f"max_event_json_bytes={int(spec['max_event_json_bytes'])}\n")
    if spec.get("late_intervention_timeout_ms") is not None:
        with runtime.open("a") as stream:
            stream.write(f"late_intervention_timeout={int(spec['late_intervention_timeout_ms'])}\n")
    runtime.chmod(0o600)
    return runtime


def capture_case(spec, output, host, modules, run_id):
    host = evidence_path(host)
    modules = evidence_path(modules)
    if not host.is_file() or not modules.is_dir():
        raise ValueError("fixture host file and module directory required")
    case = spec["case"]
    if re.fullmatch(r"[A-Za-z0-9_-]{1,96}", case) is None:
        raise ValueError("invalid case label")
    root = output / case
    root.mkdir(mode=0o700)
    client_root = root / "client"; client_root.mkdir(mode=0o700)
    spec_path = root / FIXTURE_SPEC; write(spec_path, spec)
    # Physical empty files distinguish measured empty sinks from missing files.
    for name in (BACKEND_LOG, BACKEND_TRANSPORT_LOG):
        (root / name).touch(mode=0o600)
    runtime = capture_configuration(spec, root)
    env = {**os.environ, "MSCONNECTOR_LIGHTTPD_NATIVE_OBSERVER": str(root / NATIVE_LOG),
        "MSCONNECTOR_LIGHTTPD_HOST_OBSERVER": str(root / HOST_LOG),
        "MSCONNECTOR_LIFECYCLE_RUN": run_id, "MSCONNECTOR_LIFECYCLE_PROFILE": ROUTE,
        "MSCONNECTOR_LIFECYCLE_CASE": case}
    env.update(MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_FAULT=spec.get("native_fault", "off"),
        MSCONNECTOR_LIGHTTPD_SINK_FAULT=spec.get("sink_fault", "off"),
        MSCONNECTOR_LIGHTTPD_POINTER_FAULT=spec.get("pointer_fault", "off"),
        MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_FAULT_LOG=str(root / FAULT_LOG))
    actors = {}; streams = []; cleanups = []; snapshots = []
    receipt = {"original_id": spec["original_id"], "case": case, "run_id": run_id,
        "uid": os.geteuid(), "gid": os.getegid(), "fixture_spec_sha256": sha(spec_path),
        "producer_source_sha256": sha(Path(__file__)), "clients": {},
        "full_lifecycle_qualified": False, "oracle_evaluated": False}
    context = CaptureActors(root=root, env=env, actors=actors, streams=streams,
        snapshots=snapshots, client_root=client_root, spec_path=spec_path, receipt=receipt)
    launch, wait, snapshot, run_client = context.launch, context.wait, context.snapshot, context.run_client
    host_port = None
    try:
        launch("backend", [sys.executable, "-B", str(Path(__file__).resolve()), "backend", "--spec", str(spec_path), "--output", str(root)])
        wait("backend", lambda: (root / BACKEND_READY).exists())
        backend_ready = json.loads((root / BACKEND_READY).read_text())
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0)); host_port = reservation.getsockname()[1]
        hostconf = root / "lighttpd.conf"
        hostconf.write_text("\n".join(['server.compat-module-load = "disable"',
            'server.modules = ( "mod_proxy", "mod_msconnector" )', 'server.stream-response-body = 1',
            'msconnector.enabled = "enable"', f'msconnector.config-file = "{runtime}"',
            'msconnector.request-body-gate = "pre-upstream"', f'server.document-root = "{root}"',
            'server.bind = "127.0.0.1"', f"server.port = {host_port}",
            f'server.errorlog = "{root}/host-error.log"', f'server.pid-file = "{root}/host.pid"',
            f'proxy.server = ( "" => ( ( "host" => "127.0.0.1", "port" => {backend_ready["port"]} ) ) )', ""]))
        if spec.get("host_read_idle_seconds") is not None:
            with hostconf.open("a") as stream:
                stream.write(f"server.max-read-idle = {int(spec['host_read_idle_seconds'])}\n")
                stream.write('debug.log-timeouts = "enable"\n')
        if spec.get("observe_network_writev"):
            env["MSCONNECTOR_LIGHTTPD_NETWORK_HOST_PORT"] = str(host_port)
        if spec.get("network_shrink_on_pending"):
            env["MSCONNECTOR_LIGHTTPD_NETWORK_SHRINK_ON_PENDING"] = "1"
        hostconf.chmod(0o600)
        argv = ["rtk", "proxy", str(host), "-tt", "-m", str(modules), "-f", str(hostconf)]
        config_env = {**env, "MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_FAULT": "off",
            "MSCONNECTOR_LIGHTTPD_SINK_FAULT": "off", "MSCONNECTOR_LIGHTTPD_POINTER_FAULT": "off"}
        checked = subprocess.run(argv, env=config_env, capture_output=True, timeout=20)
        (root / "configtest.stdout").write_bytes(checked.stdout); (root / "configtest.stderr").write_bytes(checked.stderr)
        receipt["configtest"] = {"argv": argv, "returncode": checked.returncode,
            "declared_host_faults_disabled_in_separate_config_process": True}
        if checked.returncode:
            receipt["reached_stage"] = "configuration_rejected"
            return receipt
        launch("host", [str(host), "-D", "-m", str(modules), "-f", str(hostconf)])
        wait("host", lambda: listening(host_port))
        snapshot("before-main")
        receipt["main_started_ns"] = time.monotonic_ns(); run_client("main", host_port)
        receipt["main_completed_ns"] = time.monotonic_ns()
        time.sleep(0.05); snapshot("after-main")
        for token in spec.get("sequence_requests", {}):
            run_client(token, host_port)
        run_client("neighbor", host_port)
        time.sleep(0.05); snapshot("after-neighbor")
        receipt["reached_stage"] = "main_and_neighbor_http_executed"
    except Exception as exc:
        receipt["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        cleanup_actors(actors, streams, cleanups)
        receipt.update(cleanup=cleanups, snapshots=snapshots,
            host_listener_gone=host_port is None or not listening(host_port),
            backend_jsonl=str(root / BACKEND_LOG), native_jsonl=str(root / NATIVE_LOG), host_jsonl=str(root / HOST_LOG))
        receipt["physical_files"] = {str(p.relative_to(root)): {"sha256": sha(p), "bytes": p.stat().st_size,
            "uid": p.stat().st_uid, "mode": oct(p.stat().st_mode & 0o777)} for p in root.rglob("*") if p.is_file()}
        write(root / CAPTURE_RECEIPT, receipt)
    return receipt


def observe_product_host_identity(context):
    context.observation('product_host_identity', {'native_actors': context.snapshots[0]['actors'], 'actual_identity': {'uid': context.receipt['uid'], 'gid': context.receipt['gid']}, 'sdk_sha256': sha(Path('/usr/lib/x86_64-linux-gnu/libmodsecurity.so.3.0.14'))}, context.ref(context.root / 'snapshots/before-main/host.maps', 'loaded_image'), context.ref(context.inputs / 'artifacts/lighttpd', 'loaded_image'), context.ref(context.inputs / 'artifacts/modules/mod_msconnector.so', 'loaded_image'), context.ref(Path('/usr/lib/x86_64-linux-gnu/libmodsecurity.so.3.0.14'), 'loaded_image'), context.physical['isolation'])
    context.observation('source_config_binding', {'actual_parent_sha': context.identity['parent_sha'], 'product_inputs_equal_bound_build': context.source['current_product_input_equality'], 'reused_exact_compiler_inputs': context.source['compiler_inputs_unchanged_reused_module_explicit'], 'fixture_spec_sha256': sha(context.root / 'fixture-spec.json')}, context.physical['source'], context.ref(context.root / 'rules.conf', 'effective_configuration'), context.ref(context.root / 'runtime.conf', 'effective_configuration'), context.ref(context.root / 'lighttpd.conf', 'effective_configuration'))
    context.observation('capability', {'actual_main_hook_rows': context.hooks, 'strict_abort_not_claimed': True}, context.physical['host'], context.physical['contract'])
    context.observation('client_exit', context.receipt['clients']['main']['actual_returncode'], context.physical['waited'], context.physical['client'])
    context.observation('client_signal', {'actual_signal': context.receipt['clients']['main']['actual_signal'], 'actual_returncode': context.receipt['clients']['main']['actual_returncode']}, context.physical['waited'])

def observe_client_headers(context):
    context.observation('client_headers', context.main_client.get('headers'), context.physical['client'])
    context.observation('client_bytes', {'entity_bytes': context.main_client.get('entity_bytes'), 'wire_bytes': context.main_client['response_wire_bytes']}, context.physical['client'])
    context.observation('client_sha256', {'entity_sha256': context.main_client.get('entity_sha256'), 'wire_sha256': context.main_client['response_wire_sha256']}, context.physical['client'])
    context.observation('backend_request_count', {'main': len(context.main_backend), 'separate_neighbor': len(context.neighbor_backend), 'total': len(context.backend_rows)}, context.physical['backend'])
    context.observation('backend_payload_identity', {'actual_main_rows': context.main_backend, 'client_request_sha256': context.main_client['request_sha256'], 'client_response_sha256': context.main_client.get('entity_sha256')}, context.physical['backend'], context.physical['client'])

def observe_client_backend_correlation(context):
    context.observation('client_backend_correlation', {'main_path': context.main_path, 'backend_main_rows': context.main_backend, 'client_pid': context.main_client['pid'], 'independent_backend_pids': sorted({r['pid'] for r in context.main_backend})}, context.physical['backend'], context.physical['client'])
    context.observation('native_api_returns', [r for r in context.main if r['edge'] == 'return'], context.physical['native'])

def observe_native_transaction_id(context):
    context.observation('native_transaction_id', context.native_ids if context.native_ids else None, context.physical['native'])
    context.observation('common_transaction_id', context.common_ids if context.common_ids else None, context.physical['native'])
    context.observation('observed_handle_association', {'main_runtime_allocation_scope_call': context.scope, 'verified_rows': [r for r in context.main if r.get('allocation_join_verified')]}, context.physical['native'])
    context.observation('native_phases', {'actual_main_debug': context.debug_lines, 'actual_phase_api_rows': [r for r in context.main if r['function'].startswith('native_process_')]}, context.physical['native'], context.physical['debug'])
    context.observation('native_body_chunks', [r for r in context.main if r['function'] in ('native_append_request_body', 'native_append_response_body')], context.physical['native'])


def observe_failed_constructor(context):
    returned = [row for row in context.main if row["function"] in ("runtime_begin", "runtime_begin_request_stream")
        and row["edge"] == "return" and row["call"] == context.scope]
    if len(returned) != 1:
        return False
    row = returned[0]
    if row.get("result") != 0 or row.get("output_argument_present") is not True or row.get("actual_output_handle_present") is not False:
        return False
    cleanup = [item for item in context.main if item["function"] in ("native_cleanup", "common_cleanup")
        and item["edge"] == "return" and item["monotonic_ns"] < row["monotonic_ns"]]
    context.observation("observed_handle_association", {
        "association_kind": "failed_constructor_observed_absence",
        "actual_returned_handle": None, "output_argument_present": True,
        "actual_output_handle_present": False, "constructor_call": context.scope,
        "actual_constructor_return": 0, "nested_actual_native_ids": context.native_ids,
        "cleanup_before_return": cleanup, "scope_complete": True,
        "successful_join_claimed": False}, context.physical["native"], context.physical["source"])
    constructors = [item for item in context.main if item["function"] in ("native_new", "native_new_with_id")
        and item["edge"] == "enter"]
    if not constructors and not context.native_ids:
        context.observation("native_transaction_id", {"measured_absence": True,
            "actual_native_transaction_id": None, "native_constructor_calls": 0,
            "actual_allocation_scope": context.scope, "scope_complete": True},
            context.physical["native"], context.physical["source"])
    if context.counts.get("common_init", 0) == 0 and not context.common_ids:
        context.observation("common_transaction_id", {"measured_absence": True,
            "actual_common_transaction_id": None, "common_initialization_calls": 0,
            "actual_allocation_scope": context.scope, "scope_complete": True},
            context.physical["native"], context.physical["source"])
    return True


def observe_parser_rejection(context):
    cases = {"invalid_content_length", "conflicting_content_length", "duplicate_transfer_encoding", "content_length_overflow"}
    if context.spec["case"] not in cases or context.main_client.get("status") != 400 or context.scope is not None:
        return False
    window = [row for row in context.native if row["monotonic_ns"] >= context.receipt["main_started_ns"]
        and row["monotonic_ns"] <= context.receipt["main_completed_ns"]]
    constructors = [row for row in window if row["function"].startswith("native_new") and row["edge"] == "enter"]
    runtime = [row for row in window if row["function"] in ("runtime_begin", "runtime_begin_request_stream")]
    if constructors or runtime or any(row.get("invalid") for row in context.native):
        return False
    proof = {"measured_absence": True, "native_constructor_calls": 0, "runtime_constructor_calls": 0,
        "actual_native_transaction_id": None, "scope_kind": "host_parser_before_runtime_constructor",
        "scope_complete": True, "actual_main_window_api_rows": window,
        "actual_http_parser_response": context.main_client["status"], "successful_join_claimed": False}
    for name in ("native_transaction_id", "common_transaction_id", "observed_handle_association"):
        context.observation(name, proof, context.physical["native"], context.physical["client"], context.physical["source"])
    return True

def observe_native_intervention_or_first_cause(context):
    context.observation('native_intervention_or_first_cause', {'actual_interventions': [r for r in context.main if r['function'] == 'native_intervention'], 'inferred_technical_first_cause': None}, context.physical['native'])
    context.observation('host_eos', context.hooks, context.physical['host'])
    context.observation('native_eos', {'actual_host_arguments': context.hooks, 'actual_runtime_finish_rows': [r for r in context.main if r['function'] in ('runtime_finish_request_body', 'runtime_finish_response_body')], 'scope': 'Native SDK body-process APIs have no EOS parameter; actual host EOS and runtime finish handoff retained separately.'}, context.physical['native'], context.physical['host'])
    context.observation('commit_order', {'actual_committed_state_rows': [r for r in context.main if r['function'] == 'common_set_response_committed'], 'actual_host_callbacks': context.hooks, 'actual_client_recv_chunks': context.main_client['recv_chunks'], 'native_eos_not_inferred_from_client_eof': True}, context.physical['host'], context.physical['client'])

def observe_finish_calls(context):
    context.observation('finish_calls', context.finish, context.physical['native'])
    context.observation('finish_transitions', [r for r in context.finish if r['function'] == 'common_finish'], context.physical['native'])
    context.observation('native_free_calls', [r for r in context.main if r['function'] in ('runtime_destroy', 'native_cleanup', 'common_cleanup')], context.physical['native'])

def observe_cleanup_receipts(context):
    context.observation('cleanup_receipts', {'actual_actor_cleanup': context.receipt['cleanup'], 'actual_final_counters': context.finals, 'actual_main_common_cleanup': [r for r in context.main if r['function'] == 'common_cleanup']}, context.physical['cleanup'], context.physical['isolation'])
    context.observation('descriptor_cleanup', {'actual_snapshot_fds': [{name: actor['fds'] for name, actor in s['actors'].items()} for s in context.snapshots], 'actual_native_process_cleanup': context.receipt['cleanup']}, context.physical['cleanup'])
    context.observation('process_listener_cleanup', {'actual_native_process_cleanup': context.receipt['cleanup'], 'host_listener_gone': context.receipt['host_listener_gone']}, context.physical['cleanup'], context.physical['isolation'])
    context.observation('neighbor_health', {'separate_neighbor_client': context.neighbor_client, 'separate_neighbor_backend': context.neighbor_backend, 'main_measurements_not_replaced_by_neighbor': True}, context.physical['neighbor'], context.physical['backend'])
    context.observation('transport_framing', context.main_client.get('framing'), context.physical['client'])

def observe_transport_reset_scope(context):
    context.observation('transport_reset_scope', {k: context.main_client.get(k) for k in ('tcp_eof_observed', 'tcp_reset_observed', 'timeout_observed', 'error')}, context.physical['client'])
    context.observation('host_action', {'client_status': context.main_client.get('status'), 'actual_host_hook_rows': context.hooks, 'actual_events': context.events, 'no_inferred_transport_abort': True}, context.physical['host'], context.physical['client'])
    context.observation('physical_event_order', context.events, context.physical['events'])
    context.observation('terminal_event_count', {'actual_main_record_count': len(context.events), 'whole_sink_bytes': (context.root / EVENT_LOG).stat().st_size, 'actual_sink_snapshots': [s['physical_files'][EVENT_LOG] for s in context.snapshots]}, context.physical['events'])


def base_assertions(context):
    expected = context.spec["oracle_proposal"]
    demands = context.spec["expectations"]
    expected_hash = demands["response_entity_sha256"]
    return {
        "unique_main_allocation": context.scope is not None,
        "client_exit": context.receipt["clients"]["main"]["actual_returncode"] == demands["client_exit"],
        "visible_status": context.main_client.get("status") == expected["visible_status"],
        "backend_count": len(context.main_backend) == demands["backend_main_count"],
        "request_payload": all(row["body_sha256"] == context.main_client["request_sha256"] for row in context.main_backend),
        "response_payload": expected_hash is None or context.main_client.get("entity_sha256") == expected_hash,
        "native_request_finish": context.counts.get("native_process_request_body", 0) == demands["native_request_body_process"],
        "native_response_finish": context.counts.get("native_process_response_body", 0) == demands["native_response_body_process"],
        "native_logging": context.counts.get("native_process_logging", 0) == demands["native_logging"],
        "native_cleanup": context.counts.get("native_cleanup", 0) == demands["native_cleanup"],
        "native_body_chunks": demands["native_request_append_min"] is not None
            and context.counts.get("native_append_request_body", 0) >= demands["native_request_append_min"],
        "native_mime_snapshot": bool(context.native_mime) or context.no_response_phase,
        "native_invalid": not any(row.get("invalid") for row in context.native),
        "neighbor": context.neighbor_client.get("status") == 200 and len(context.neighbor_backend) == 1,
        "process_cleanup": all(row["same_starttime_pid_gone"] and row["launcher_reaped"] for row in context.receipt["cleanup"]),
        "host_listener_cleanup": context.receipt["host_listener_gone"],
        "applicable_observations_measured": all(item.get("value") is not None
            for item in context.packet["observations"].values() if item.get("applicable", True)),
    }


def eos_assertions(context, assertions):
    expected_eos = context.spec['expectations']['response_eos']
    if expected_eos is not None:
        assertions['actual_response_eos_count'] = sum((r['actual_eos_argument'] == 1 for r in context.hooks if r['kind'] == 'patched_response_body_hook')) == expected_eos
    expected_events = context.spec['expectations']['common_terminal_events']
    if expected_events is not None:
        assertions['actual_terminal_event_count'] = len(context.events) == expected_events
    if not context.spec['request_hex']:
        assertions['empty_request_no_native_append'] = context.counts.get('native_append_request_body', 0) == 0
    if not context.spec['response_hex']:
        assertions['empty_response_no_native_append'] = context.counts.get('native_append_response_body', 0) == 0
def response_entity_assertions(context, assertions):
    """A completed native response must receive all predeclared entity bytes."""
    demands = context.spec["expectations"]
    if demands["response_eos"] != 1 or demands["native_response_body_process"] != 1:
        return
    size = len(bytes.fromhex(context.spec["response_hex"]))
    hooks = [row for row in context.hooks if row["kind"] == "patched_response_body_hook"]
    appends = [row for row in context.main
        if row["function"] == "native_append_response_body" and row["edge"] == "enter"]
    assertions["complete_response_native_byte_total"] = sum(row["input_size"] for row in appends) == size
    offset = 0
    contiguous = True
    for row in hooks:
        contiguous = contiguous and row["stream_offset"] == offset
        offset += row["input_size"]
    assertions["complete_response_host_contiguous_bytes"] = contiguous and offset == size


def rule_assertions(context, assertions):
    expected = context.spec["oracle_proposal"]
    declared_rule = expected.get('rule_id')
    if declared_rule is not None:
        assertions['declared_rule_physically_observed'] = any((str(event.get('rule_id')) == str(declared_rule) for event in [*context.events, *context.sequence_events])) or any((f'[id "{declared_rule}"]' in line and any((f'[unique_id "{native_id}"]' in line for native_id in context.native_ids)) for line in (context.root / 'audit.log').read_text().splitlines()))
    contract = context.spec.get("canonical_contract", {})
    audit_only = (context.spec["case"] in ("log_only", "transaction_id_present", "transaction_id_generated_or_fallback")
        and "event_jsonl" not in contract.get("required_capabilities", [])
        and contract.get("expect", {}).get("audit_log", {}).get("required") is True)
    if audit_only:
        assertions["canonical_audit_rule_and_main_id"] = any(
            f'[id "{declared_rule}"]' in line for line in context.audit_lines)
        assertions["canonical_audit_native_phase1"] = context.counts.get("native_process_request_headers", 0) == 1
        if context.spec["case"] == "transaction_id_present":
            assertions["supplied_id_retained_in_native_audit_metadata"] = any(
                "no-crs-tx-0001" in line and f'[id "{declared_rule}"]' in line for line in context.audit_lines)
    else:
        assertions['declared_event_fields'] = all(any(field in event for event in context.events)
            for field in expected.get('event_fields', []))


def first_byte_assertions(context, assertions):
    if context.spec.get('expect_first_body_byte_before_upstream_finish'):
        final_offset = len(bytes.fromhex(context.spec["response_hex"]))
        upstream_finish = [r['monotonic_ns'] for r in context.records('backend-transport.jsonl')
            if r.get('path') == context.main_path and r.get('kind') == 'response_write'
            and r.get("offset") == final_offset]
        first_entity = context.main_client.get('first_entity_recv_completed_ns')
        assertions['actual_body_first_byte_before_upstream_finish'] = first_entity is not None and len(upstream_finish) == 1 and (first_entity < upstream_finish[0])


def evaluate_proposal(context):
    assertions = base_assertions(context)
    eos_assertions(context, assertions)
    response_entity_assertions(context, assertions)
    rule_assertions(context, assertions)
    first_byte_assertions(context, assertions)
    expected = context.spec["oracle_proposal"]
    expected_hash = context.helper.ORACLES.canonical_digest(expected)
    return expected, expected_hash, assertions, "PASS" if all(assertions.values()) else "FAIL"


def observe_sequence(context):
    transactions = []
    for client_row in context.sequence_clients:
        starts = [row for row in context.native if row["function"] == "runtime_begin_request_stream"
            and row["edge"] == "enter" and client_row["started_ns"] <= row["monotonic_ns"] <= client_row["completed_ns"]]
        scope = starts[0]["call"] if len(starts) == 1 else None
        trace = [row for row in context.native if scope is not None and row.get("allocation_scope_call") == scope]
        ids = sorted({row["transaction_id"] for row in trace if row.get("transaction_id_origin") == "sdk_public_m_id" and row.get("transaction_id")})
        counts = {name: sum(row["function"] == name and row["edge"] == "enter" for row in trace)
            for name in ("native_process_logging", "native_cleanup", "common_cleanup")}
        transactions.append({"actual_client": client_row, "actual_allocation_scope": scope,
            "actual_native_ids": ids, "actual_finish_free_counts": counts})
    ids = [item for tx in transactions for item in tx["actual_native_ids"]]
    return {"primary_transaction": "first real request; remaining requests retain distinct actual scopes and native IDs",
        "transactions": transactions, "actual_sequence_physical_events": context.sequence_events,
        "raw_client_receipt": context.physical["client"],
        "raw_native_trace": context.physical["native"], "assertions": {
            "actual_sequence_statuses": [row["status"] for row in context.sequence_clients] == [200, 403, 200],
            "actual_sequence_distinct_native_ids": len(ids) == len(transactions) == len(set(ids)),
            "actual_sequence_finish_free_once": all(all(count == 1 for count in tx["actual_finish_free_counts"].values()) for tx in transactions),
            "actual_sequence_unique_scopes": all(tx["actual_allocation_scope"] is not None for tx in transactions),
            "actual_sequence_same_socket": all(row["connection_identity"] == context.sequence_clients[0]["connection_identity"] for row in context.sequence_clients),
            "actual_sequence_complete_messages": all(row["actual_message_complete"] for row in context.sequence_clients)}}


def amend_source_counts(spec, root, source_count_review):
    count_review = None
    original_counts = copy.deepcopy(spec["expectations"])
    if source_count_review is not None:
        review_path = evidence_path(source_count_review)
        count_review = read_json(review_path)
        allowed = {"native_request_body_process", "native_response_body_process", "native_logging", "native_cleanup", "native_request_append_min"}
        if count_review.get("basis") != "source_control_flow" or count_review.get("case") != spec["case"]:
            raise ValueError("Count review must name exact source-control-flow case")
        if count_review.get("original_fixture_spec_sha256") != sha(root / FIXTURE_SPEC):
            raise ValueError("Count review does not bind original immutable fixture")
        counts = count_review["expected_counts"]
        if not counts or not set(counts).issubset(allowed) or any(type(value) is not int or value not in (0, 1) for value in counts.values()):
            raise ValueError("Count review may only amend bounded native call counts")
        for item in count_review["sources"]:
            if sha(evidence_path(item["path"])) != item["sha256"]:
                raise ValueError("Count review source hash mismatch")
        spec["expectations"].update(counts)
    return count_review, original_counts


def proposal_records(root, spec, decode_failures, name):
    p = root / name
    if not p.exists():
        return []
    rows = []
    for index, line in enumerate(p.read_bytes().splitlines(), 1):
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as error:
            if name != EVENT_LOG or spec.get("sink_fault") != "short_write":
                raise
            decode_failures.setdefault(name, []).append({"physical_line": index,
                "line_bytes": len(line), "line_sha256": digest(line),
                "error": error.msg, "error_column": error.colno})
    return rows


def proposal_clients(root, receipt):
    main_client = json.loads((root / "client/main.receipt.json").read_text())
    neighbor_client = json.loads((root / "client/neighbor.receipt.json").read_text())
    sequence_clients = main_client.get("all_requests", [])
    primary_started = receipt["main_started_ns"]
    primary_completed = receipt["main_completed_ns"]
    if sequence_clients:
        primary = sequence_clients[0]
        main_client = {**primary, "recv_chunks": primary["actual_socket_recv_chunks"],
            "response_wire_bytes": (root / "client/main.receipt.wire").stat().st_size,
            "response_wire_sha256": sha(root / "client/main.receipt.wire"),
            "wire_measurement_scope": "entire actual three-response sequence; primary entity fields are first response"}
        main_client["framing"] = {"kind": primary["framing"], "complete": primary["actual_message_complete"]}
        primary_started, primary_completed = primary["started_ns"], primary["completed_ns"]
    return main_client, neighbor_client, sequence_clients, primary_started, primary_completed


def proposal_scope(native, host, primary_started, primary_completed):
    begins = [r for r in native if r["function"] == "runtime_begin_request_stream" and r["edge"] == "enter"
        and primary_started <= r["monotonic_ns"] <= primary_completed]
    scope = begins[0]["call"] if len(begins) == 1 else None
    main = [r for r in native if scope is not None and r.get("allocation_scope_call") == scope]
    hooks = [r for r in host if scope is not None and r.get("runtime_allocation_scope_call") == scope]
    counts = {}
    for row in main:
        if row["edge"] == "enter":
            counts[row["function"]] = counts.get(row["function"], 0) + 1
    return scope, main, hooks, counts


def proposal_physical(root, attempt, inputs, ref):
    physical = {
        "native": ref(root / NATIVE_LOG, "native_api"), "host": ref(root / HOST_LOG, "host_callback"),
        "client": ref(root / "client/main.receipt.json", "client_process"),
        "waited": ref(root / "client/main.waited.json", "client_process"),
        "neighbor": ref(root / "client/neighbor.receipt.json", "client_process"),
        "backend": ref(root / BACKEND_LOG, "backend_process"),
        "backend_transport": ref(root / BACKEND_TRANSPORT_LOG, "backend_process"),
        "events": ref(root / EVENT_LOG, "physical_event_sink"),
        "debug": ref(root / "debug.log", "native_debug"),
        "cleanup": ref(root / CAPTURE_RECEIPT, "cleanup_observer"),
        "isolation": ref(attempt / "controller-result.json", "isolation_receipt"),
        "source": ref(inputs / "source-build-binding.json", "source_manifest"),
        "contract": ref(root / FIXTURE_SPEC, "source_contract"),
    }
    if (root / FAULT_LOG).exists():
        physical["fault"] = ref(root / FAULT_LOG, "test_boundary_injection")
    return physical


def observe_fault_boundary(context):
    if "fault" not in context.physical:
        return
    context.observation("native_intervention_or_first_cause", {
        "actual_native_interventions": [row for row in context.main if row["function"] == "native_intervention"],
        "actual_common_error_events_in_sink_order": [row for row in context.events if row.get("status") == "error"],
        "actual_declared_boundary_fault_rows": context.records(FAULT_LOG),
        "actual_host_error_log": (context.root / "host-error.log").read_text(),
        "injected_boundary_distinct_from_real_sdk_or_io": True},
        context.physical["native"], context.physical["events"], context.physical["fault"])


def observe_mime_boundary(context, failed_constructor_observed, parser_rejection_observed):
    native_mime = [r for r in context.main if r.get("native_mime_selection") is not None]
    context.observation("mime_gate", {"native_mime_observations": native_mime,
        "actual_main_debug": context.debug_lines,
        "native_p4_marker_matches": [line for line in context.debug_lines if "I12 qualified native P4" in line],
        "actual_client_headers": context.main_client.get("headers"),
        "actual_main_backend_headers": [r["headers"] for r in context.main_backend],
        "native_mime_scalar_unavailable": not native_mime} if native_mime else None,
        context.physical["native"], context.physical["debug"], context.physical["events"])
    no_response_phase = (context.spec["oracle_proposal"]["visible_status"] in (403, 429, 500, 502)
        and context.spec["oracle_proposal"]["phase"] in (1, 2, 3)
        and context.spec["expectations"]["native_response_body_process"] == 0
        and context.counts.get("native_process_response_body", 0) == 0)
    no_response_phase = no_response_phase or failed_constructor_observed or parser_rejection_observed
    if no_response_phase:
        build_source = Path(context.source["fresh_build_receipt"]).parent / "source"
        context.packet["observed_response_metadata_before_early_terminal"] = copy.deepcopy(context.packet["observations"]["mime_gate"])
        context.packet["observations"]["mime_gate"].update(value=None, applicable=False,
            reason="Declared early intervention or parser/preallocation rejection terminates before native response-body processing; actual main native/host rows establish that this MIME boundary was not reached.",
            capability_proof=[context.ref(context.root / FIXTURE_SPEC, "source_contract"),
                context.ref(build_source / MODULE_SOURCE, "source_contract"),
                context.ref(build_source / "common/runtime/msconnector_runtime.c", "source_contract")])
    return native_mime, no_response_phase


def preserve_original_status(context, expected, original_expected):
    intentional_status = (bool(context.spec.get("canonical_contract")) and original_expected.get("phase") == 4
        and original_expected.get("visible_status") is None and not original_expected.get("unresolved_expected_value_reason")
        and {**expected, "visible_status": None} == original_expected)
    if intentional_status:
        context.packet["stronger_predeclared_fixture_assertion"] = {
            "fixture_expected_status": expected["visible_status"], "actual_status": context.main_client.get("status"),
            "original_oracle_visible_status": None, "original_oracle_not_replaced": True,
            "fixture_source": context.ref(context.root / FIXTURE_SPEC, "source_contract")}
        expected = copy.deepcopy(original_expected)
    return expected, intentional_status


def proposal_events(records, main, main_path, sequence_clients):
    main_ids = {r.get("canonical_transaction_id") for r in main if r.get("canonical_transaction_id")}
    events = [r for r in records(EVENT_LOG)
        if r.get("uri") == main_path or r.get("transaction_id") in main_ids]
    sequence_paths = {item["path"] for item in sequence_clients}
    sequence_events = [row for row in records(EVENT_LOG) if row.get("uri") in sequence_paths]
    return events, sequence_events


def proposal_related_rows(root, backend_rows, main_path, neighbor_client):
    debug = (root / "debug.log").read_text()
    debug_lines = [line for line in debug.splitlines() if "] [" + main_path + "]" in line]
    main_backend = [r for r in backend_rows if r["path"] == main_path]
    neighbor_backend = [r for r in backend_rows if r["path"] == neighbor_client["path"]]
    snapshots = [json.loads((root / "snapshots" / label / SNAPSHOT).read_text())
        for label in ("before-main", "after-main", "after-neighbor")]
    return debug_lines, main_backend, neighbor_backend, snapshots


def proposal_native_events(root, main):
    native_ids = sorted({r["transaction_id"] for r in main if r.get("transaction_id_origin") == "sdk_public_m_id" and r.get("transaction_id")})
    common_ids = sorted({r["canonical_transaction_id"] for r in main if r.get("canonical_transaction_id")})
    audit_lines = [line for line in (root / AUDIT_LOG).read_text().splitlines()
        if any(f'[unique_id "{native_id}"]' in line for native_id in native_ids)]
    return native_ids, common_ids, audit_lines


def observe_proposal_completion(context):
    context.finish = [r for r in context.main if r["function"] in ("runtime_finish", "common_finish", "native_process_logging")]
    observe_finish_calls(context)
    context.finals = [r for r in context.native if r["function"] == "observer" and r["edge"] == "final"]
    observe_cleanup_receipts(context)
    observe_transport_reset_scope(context)
    for name, item in context.packet["observations"].items():
        if item.get("value") is None and item.get("applicable"):
            item["reason"] = "Physical producer did not establish a value for " + name + "; no neighbor substitution."


def propose(case_root, attempt, inputs, output, source_count_review=None, qualifier_path=None):
    """Translate physical producers into worker proposals for the existing qualifier."""
    helper_source = evidence_path(qualifier_path or Path(__file__).with_name("qualification.py"))
    helper = load_source(helper_source)
    ref = helper.reference
    root = Path(case_root); attempt = Path(attempt); inputs = Path(inputs)
    receipt = json.loads((root / CAPTURE_RECEIPT).read_text())
    spec = json.loads((root / FIXTURE_SPEC).read_text())
    source = json.loads((inputs / "source-build-binding.json").read_text())
    count_review, original_counts = amend_source_counts(spec, root, source_count_review)
    identity = {"run_id": receipt["run_id"], "parent_sha": source["actual_checkout_head"],
        "framework_sha": "99a7985c1be92a2297b1b59208f64df6768f2cbf",
        "mrts_sha": "8a6bb546c4c81d8ffc7be801dceac60c6925685f",
        "framework_scope": "gitlink_identity_only_not_executed", "mrts_scope": "gitlink_identity_only_not_executed",
        "effective_config_sha256": sha(root / "lighttpd.conf"), "rules_sha256": sha(root / RULES_CONFIG)}
    packet = helper.packet_template(spec["original_id"], identity)
    packet["execution_observed"] = receipt.get("reached_stage") == "main_and_neighbor_http_executed"
    decode_failures = {}
    def records(name):
        return proposal_records(root, spec, decode_failures, name)
    native = records(NATIVE_LOG); host = records(HOST_LOG); backend_rows = records(BACKEND_LOG)
    main_client, neighbor_client, sequence_clients, primary_started, primary_completed = proposal_clients(root, receipt)
    scope, main, hooks, counts = proposal_scope(native, host, primary_started, primary_completed)
    main_path = main_client["path"]
    events, sequence_events = proposal_events(records, main, main_path, sequence_clients)
    debug_lines, main_backend, neighbor_backend, snapshots = proposal_related_rows(root, backend_rows, main_path, neighbor_client)
    physical = proposal_physical(root, attempt, inputs, ref)
    def observation(name, value, *proofs):
        packet["observations"][name] = {"applicable": True, "value": value, "evidence": list(proofs)}
    observe_product_host_identity(SimpleNamespace(**locals()))
    observe_client_headers(SimpleNamespace(**locals()))
    observe_client_backend_correlation(SimpleNamespace(**locals()))
    native_ids, common_ids, audit_lines = proposal_native_events(root, main)
    observation("native_events", {"actual_common_jsonl_rows": events,
        "actual_scoped_native_audit_lines": audit_lines, "physical_decode_errors": decode_failures},
        physical["events"], ref(root / AUDIT_LOG, "physical_event_sink"))
    observe_native_transaction_id(SimpleNamespace(**locals()))
    failed_constructor_observed = observe_failed_constructor(SimpleNamespace(**locals()))
    parser_rejection_observed = observe_parser_rejection(SimpleNamespace(**locals()))
    observe_native_intervention_or_first_cause(SimpleNamespace(**locals()))
    observe_fault_boundary(SimpleNamespace(**locals()))
    if spec.get("pointer_fault") == "body_null" and not hooks:
        packet["observations"]["host_eos"].update(value=None,
            reason="Inherited request-hook observer runs after successful body append; injected NULL-data guard returned before that sample. Actual host EOS argument is unmeasured, not assumed absent.")
    native_mime, no_response_phase = observe_mime_boundary(SimpleNamespace(**locals()),
        failed_constructor_observed, parser_rejection_observed)
    observe_proposal_completion(SimpleNamespace(**locals()))
    expected, expected_hash, assertions, outcome = evaluate_proposal(SimpleNamespace(**locals()))
    if sequence_clients:
        sequence = observe_sequence(SimpleNamespace(**locals()))
        assertions.update(sequence["assertions"])
        packet["actual_sequence_observations"] = sequence
        packet["observations"]["observed_handle_association"]["value"]["actual_sequence"] = sequence
        outcome = "PASS" if all(assertions.values()) else "FAIL"
    return finalize_proposal(SimpleNamespace(**locals()))


def finalize_proposal(context):
    """Retain the original oracle and write separate, unqualified worker artifacts."""
    helper, helper_source, ref = context.helper, context.helper_source, context.ref
    spec, root, packet = context.spec, context.root, context.packet
    expected, expected_hash = context.expected, context.expected_hash
    assertions, outcome, output = context.assertions, context.outcome, context.output
    count_review, original_counts = context.count_review, context.original_counts
    source_count_review = context.source_count_review
    decode_failures, identity = context.decode_failures, context.identity
    scope, counts, physical = context.scope, context.counts, context.physical
    main_client = context.main_client
    original_expected = helper.original_row(spec["original_id"])["selected_requirement"]["expected_oracle"]
    expected, intentional_status = preserve_original_status(SimpleNamespace(**locals()), expected, original_expected)
    if intentional_status:
        expected_hash = helper.ORACLES.canonical_digest(expected)
    expected_response_hash = spec["expectations"]["response_entity_sha256"]
    packet.update(oracle_evaluated=True, oracle_sha256=expected_hash, outcome=outcome,
        full_lifecycle_qualified=False, physical_main_scope=scope, observed_assertions=assertions,
        packet_producer_source_sha256=sha(Path(__file__)),
        packet_producer_source=ref(Path(__file__), "source_contract"),
        packet_qualifier_source=ref(helper_source, "source_contract"))
    packet["physical_decode_errors"] = decode_failures
    if count_review is not None:
        packet["source_count_review"] = {"original_sealed_expectations": original_counts,
            "effective_expectations": spec["expectations"], "review": ref(Path(source_count_review), "source_contract"),
            "original_expected_oracle_unchanged": True, "root_review_required": True}
    packet["assertion_nonapplicability"] = {"response_payload": "Early native intervention uses a host-generated body, whose raw bytes/hash remain captured."} if expected_response_hash is None else {}
    output = Path(output); output.mkdir(parents=True, mode=0o700)
    retest = {"run_scoped_case_id": spec["original_id"], "leg_id": ROUTE, **identity,
        "execution_observed": packet["execution_observed"], "oracle_sha256": expected_hash,
        "oracle_evaluated": True, "outcome": outcome,
        "actual_observations": {"assertions": assertions, "main_scope": scope, "actual_counts": counts},
        "measurement_evidence": list(physical.values())}
    write(output / "retest.json", retest)
    independent = EXTERNAL_ROOT / "runs/e2e/20261014T182400Z-pr410-oracle-lifecycle/source-proof/sdk-3.0.14-transaction.cc"
    record = {"run_scoped_case_id": spec["original_id"], "leg_id": ROUTE,
        "reviewed_by": "worker", "category": "SOURCE_CONFIRMED_EXPECTATION",
        "interpretation": "Fixture expectation was declared before execution. SDK3.0.14 native body processing, configured limit actions, explicit rules and host Safe policy provide the proposed basis; observations are a separate retest.",
        "scope": "Exact original selected requirement, sealed fixture spec and one independently observed main transaction.",
        "independent_sources": [ref(independent, kind="native_engine_contract", revision="ModSecurity3.0.14",
            symbols=["processRequestBody", "processResponseBody", "intervention"],
            url="https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3.0.14/src/transaction.cc")],
        "implementation_sources": [ref(root / FIXTURE_SPEC, role="source_contract"),
            ref(root / RULES_CONFIG, role="source_contract"), physical["source"]],
        "resolved_expectation": expected, "retest": ref(output / "retest.json")}
    if intentional_status:
        record["proposed_intentional_null_fields"] = {"visible_status": {
            "interpretation": "The unchanged original P4 contract deliberately leaves visible_status unspecified. Native body-rule processing and intervention are separate from actual host output commitment. The stronger predeclared fixture200 assertion and physical status/commit evidence remain separately retained; they do not replace null with200 in the original oracle.",
            "proof": copy.deepcopy(record["independent_sources"])}}
    if count_review is not None:
        record["implementation_sources"].append(ref(Path(source_count_review), role="source_contract"))
        record["interpretation"] += " Abnormal call-count corrections are independently source-reviewed in the bound control-flow record; the sealed original spec and original expected oracle are preserved."
    if expected == original_expected:
        record.pop("resolved_expectation", None)
    elif not original_expected.get("unresolved_expected_value_reason"):
        record.pop("resolved_expectation", None)
        record["category"] = "UNRESOLVED_ORACLE"
        record["proposed_correction"] = {"expected_oracle": expected,
            "original_expected_oracle": original_expected, "reviewed_by": "worker",
            "explicit_root_approval_required": True}
        record["proposed_retest"] = record.pop("retest")
        record["interpretation"] += " The existing original oracle differs; a separate Root-approved source-backed correction is required. This producer does not approve replacement."
    write(output / "packet-proposal.json", packet)
    write(output / "oracle-record-proposal.json", record)
    return {"case": spec["case"], "outcome": outcome, "assertions": assertions,
        "packet": ref(output / "packet-proposal.json"), "oracle": ref(output / "oracle-record-proposal.json")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("definitions", "run", "client", "backend", "propose", "extend-mime"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--spec", type=Path)
    parser.add_argument("--host", type=Path)
    parser.add_argument("--modules", type=Path)
    parser.add_argument("--port", type=int)
    parser.add_argument("--token")
    parser.add_argument("--run-id", default="i12-lighttpd-412-patched-20261015")
    parser.add_argument("--cases", nargs="*")
    parser.add_argument("--case-root", type=Path)
    parser.add_argument("--attempt", type=Path)
    parser.add_argument("--inputs", type=Path)
    parser.add_argument("--source-copy", type=Path)
    parser.add_argument("--accessor", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if args.mode == "definitions":
        write(args.output, definitions()); return 0
    if args.mode == "extend-mime":
        write(args.output, extend_mime_capture(args.source_copy, args.accessor)); return 0
    if args.mode == "propose":
        print(json.dumps(propose(args.case_root, args.attempt, args.inputs, args.output)))
        return 0
    if args.mode == "client":
        return client(args.spec, args.output, args.port, args.token)
    if args.mode == "backend":
        backend(args.spec, args.output); return 0
    args.output = i12_paths.new_directory(args.output)
    selected = json.loads(args.spec.read_text()) if args.spec else definitions()
    if args.cases:
        selected = [s for s in selected if s["case"] in args.cases]
    write(args.output / "run-specifications.json", selected)
    rows = [capture_case(s, args.output, args.host, args.modules, args.run_id) for s in selected]
    write(args.output / "captures.json", rows)
    print(json.dumps({"original_ids_executed": len(rows), "qualified_by_producer": False}))
    return 0 if all("error" not in row for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
