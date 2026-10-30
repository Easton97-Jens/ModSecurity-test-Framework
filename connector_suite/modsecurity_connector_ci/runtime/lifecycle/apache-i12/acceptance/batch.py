#!/usr/bin/env python3
"""Execute Apache inputs in the existing private controller, without verdicts.

The original direct-runner owns process launch/readiness/shutdown. Existing
native/host observers and process snapshots remain the physical producers.
Unimplemented fault operations are explicitly distinguished from the principal
normal-path transaction that can still be observed safely.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
import base64
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import threading
import time


MAX_WIRE = 16 * 1024 * 1024
MIN_PRIVATE_PORT = 1024
MAX_PORT = 65535
ARTIFACT_MOUNT = Path("/mnt/artifacts")
FIXTURE_MOUNT = Path("/mnt/fixtures")
AUDIT_FILE = "audit.log"
EVENTS_FILE = "events.jsonl"
NATIVE_API_FILE = "native-api.jsonl"
RECEIPT_FILE = "receipt.json"
RULES_FILE = "rules.conf"
SEQUENCE_RECEIPT_FILE = "sequence-receipt.json"
SPEC_FILE = "spec.json"
TERMINATION_FILE = "termination.json"
PARENT = Path(__file__).resolve().parent.parent


paths = load_tool('ci/runtime/lifecycle/apache-i12/paths.py')
capture_process = load_tool('ci/runtime/lifecycle/apache-i12/process_capture.py').capture_process
keepalive = load_tool('ci/runtime/lifecycle/apache-i12/acceptance/keepalive.py')
cancellation = load_tool('ci/runtime/lifecycle/apache-i12/acceptance/cancellation.py')




def load_module(name, path):
    module = load_source(path)
    return module


def digest(path):
    """Hash only canonical files in sealed inputs or the private task root."""
    supplied = Path(path)
    if not supplied.is_absolute() or ".." in supplied.parts:
        raise ValueError("digest input must be a canonical absolute path")
    resolved = supplied.resolve(strict=True)
    if supplied != resolved or not resolved.is_file():
        raise ValueError("digest input must be a regular nonsymlink file")
    roots = []
    for candidate in (ARTIFACT_MOUNT, FIXTURE_MOUNT,
                      Path("/mnt/framework/tests/rules")):
        if candidate.is_dir() and candidate.resolve(strict=True) == candidate:
            roots.append(candidate)
    roots.append(paths.storage_root())
    if not any(resolved.is_relative_to(root) for root in roots):
        raise ValueError("digest input escapes admitted Apache evidence roots")
    return hashlib.sha256(resolved.read_bytes()).hexdigest()


def admitted_mount_path(value, root, file=True):
    """Canonicalize one CLI path below an exact sealed read-only mount."""
    root = Path(root)
    supplied = Path(value)
    if (not supplied.is_absolute() or ".." in supplied.parts or not root.is_absolute()
            or root.resolve(strict=True) != root or not root.is_dir()):
        raise ValueError("invalid sealed Apache input mount")
    resolved = supplied.resolve(strict=True)
    if supplied != resolved or not resolved.is_relative_to(root):
        raise ValueError("CLI input escapes its sealed Apache mount or follows a symlink")
    if file and not resolved.is_file():
        raise ValueError("expected a regular sealed Apache input")
    if not file and not resolved.is_dir():
        raise ValueError("expected a sealed Apache input directory")
    return resolved


def body_bytes(value):
    data = base64.b64decode(value["data"], validate=True)
    if len(data) != value["bytes"] or hashlib.sha256(data).hexdigest() != value["sha256"]:
        raise ValueError("fixture byte identity mismatch")
    return data


def save(path, value):
    with paths.new_text(Path(path)) as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def replace_tokens(text, root):
    return (text.replace("@@CASE_ROOT@@", str(root))
            .replace("@@BASELINE_RULES@@", "/mnt/framework/tests/rules/no-crs-baseline.conf")
            .replace("@@AUDIT_LOG@@", str(root / AUDIT_FILE))
            .replace("@@AUDIT_LOG_DIR@@", str(root / "audit-storage"))
            .replace("@@INVALID_SCOPE@@", "/mnt/framework/tests/fixtures/no-crs-baseline/invalid-content-type-scope.txt")
            .replace("@@WILDCARD_SCOPE@@", "/mnt/framework/tests/fixtures/no-crs-baseline/wildcard-content-type-scope.txt"))


def native_rules(plan, root):
    lines = ["SecRuleEngine On", "SecRequestBodyAccess On", "SecResponseBodyAccess On",
             "SecResponseBodyMimeType text/plain text/html application/json"]
    if plan["execution_kind"] == "host_http" and plan.get("baseline_rules_required"):
        baseline = Path("/mnt/framework/tests/rules/no-crs-baseline.conf")
        if digest(baseline) != plan["baseline_rules"]["sha256"]:
            raise ValueError("canonical rule source differs from prepared plan")
        lines.append('Include "' + str(baseline) + '"')
    lines.append(replace_tokens(plan.get("rules", ""), root))
    if plan.get("case_id") == "NEED-request-file":
        lines += ["SecTmpSaveUploadedFiles On", "SecUploadKeepFiles Off",
                  'SecUploadDir "' + str(root / "uploads") + '"']
    lines += ["SecAuditEngine On", "SecAuditLogType Serial", "SecAuditLogParts ABHZ",
              'SecAuditLog "' + str(root / AUDIT_FILE) + '"',
              'SecAuditLogStorageDir "' + str(root / "audit-storage") + '"',
              'SecDebugLog "' + str(root / "native-debug.log") + '"', "SecDebugLogLevel 5"]
    return "\n".join(lines) + "\n"


def selected_rules_file(plan, root):
    missing = plan["execution_kind"] == "configtest" and plan.get("case_id") == "missing_rules_file"
    if missing and plan["config"].get("setup"):
        raise ValueError("missing-rules fixture cannot have setup operations")
    return root / ("absent.rules" if missing else RULES_FILE)


def selected_rules_observation(plan, root):
    """Observe the actually selected pathname; absent inputs have no digest."""
    selected = selected_rules_file(plan, root)
    observed = {"path": str(selected), "operation": "lstat", "pid": os.getpid(),
                "monotonic_ns": time.monotonic_ns(), "result": None, "errno": None,
                "exists": None, "sha256": None}
    try:
        metadata = selected.lstat()
        observed.update(result=0, errno=0, exists=True, device=metadata.st_dev, inode=metadata.st_ino)
    except OSError as error:
        observed.update(result=-1, errno=error.errno, exists=False if error.errno == errno.ENOENT else None)
        if error.errno != errno.ENOENT:
            raise
    if selected.name == "absent.rules":
        if observed["exists"] is not False:
            raise ValueError("selected missing-rules fixture must genuinely be absent")
    elif observed["exists"]:
        observed["sha256"] = digest(selected)
    save(root / "selected-rules-path.json", observed)
    return observed


def static_file_path(plan, root):
    fixture = plan.get("backend", {}).get("file")
    if fixture is None:
        return None
    if fixture.get("serving") != "apache_static_file":
        raise ValueError("unsupported response file serving operation")
    path = plan["request"]["path"]
    if (not path.startswith("/") or any(c in path for c in '\r\n ?#%"\\')
            or any(part in ("", ".", "..") for part in path[1:].split("/"))):
        raise ValueError("unsafe static response path")
    return root / "static" / path[1:]


def materialize_response_file(plan, root):
    path = static_file_path(plan, root)
    if path is None:
        return None
    content = body_bytes(plan["backend"]["file"]["content"])
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("xb") as output:
        os.chmod(path, 0o600)
        output.write(content)
    return {"operation": "materialized_apache_DocumentRoot_file", "path": str(path),
            "bytes": len(content), "sha256": digest(path),
            "actual_static_handler_observed": None, "actual_APR_FILE_bucket_observed": None}


def config_text(plan, root, module, port, backend_port, principal_sink=None):
    lines = [f'ServerRoot "{root}"', f'DefaultRuntimeDir "{root}"',
             f'PidFile "{root}/httpd.pid"', f'Listen 127.0.0.1:{port}',
             "ServerName 127.0.0.1", f'ErrorLog "{root}/error.log"', "LogLevel info",
             f'CustomLog "{root}/access.log" "%r %>s %b %{{X-I12-ID}}i"']
    for name in ("mpm_event", "authz_core", "proxy", "proxy_http", "log_config"):
        path = Path("/usr/lib/apache2/modules") / ("mod_" + name + ".so")
        if path.is_file():
            lines.append(f"LoadModule {name}_module {path}")
    if static_file_path(plan, root) is not None:
        lines += [f'ProxyPass "{plan["request"]["path"]}" "!"',
                  f'DocumentRoot "{root}/static"',
                  f'<Directory "{root}/static">', "Require all granted", "ForceType text/plain", "</Directory>"]
    lines += [f'LoadModule security3_module "{module}"', "ProxyRequests Off",
              f'ProxyPass "/" "http://127.0.0.1:{backend_port}/" connectiontimeout=2 timeout=10',
              f'ProxyPassReverse "/" "http://127.0.0.1:{backend_port}/"',
              '<Location "/">', "Require all granted", "</Location>", "modsecurity on",
              f'modsecurity_phase4_log "{root / EVENTS_FILE}"',
              "modsecurity_phase4_mode " + plan.get("apache", {}).get("phase4_mode", "safe"),
              f'modsecurity_rules_file "{selected_rules_file(plan, root)}"']
    expression = plan.get("apache", {}).get("transaction_id_expression", "%{req:X-I12-ID}")
    if expression is not None:
        if expression != "%{req:X-I12-ID}":
            raise ValueError("unsupported transaction ID expression")
        lines.append('modsecurity_transaction_id_expr "' + expression + '"')
    directives = plan.get("apache", {}).get("config_directives", [])
    if plan["execution_kind"] == "configtest":
        directives = plan["config"]["directives"]
        if plan.get("case_id") == "missing_rules_file":
            if directives != ["modsecurity_rules_file @@CASE_ROOT@@/absent.rules"]:
                raise ValueError("missing-rules fixture must select the reviewed absent path")
            directives = []  # The sole selected rules directive above names the absent file.
    lines += [replace_tokens(line, root) for line in directives]
    if plan.get("case_id") in keepalive.CASES:
        lines += ["KeepAlive On", "MaxKeepAliveRequests 16", "KeepAliveTimeout 5"]
    if principal_sink is not None:
        # P1 runs at post_read_request, before directory/Location walking.
        # Name-vhost selection already happened when the Host was read. Keep
        # the principal's original Host as default; controls explicitly select
        # a separate context with the same rules and a genuinely healthy sink.
        lines += [f"<VirtualHost 127.0.0.1:{port}>", "ServerName 127.0.0.1",
                  f'modsecurity_phase4_log "{principal_sink}"', "</VirtualHost>",
                  f"<VirtualHost 127.0.0.1:{port}>", "ServerName control.localhost",
                  f'modsecurity_phase4_log "{root / EVENTS_FILE}"', "</VirtualHost>"]
    return "\n".join(lines) + "\n"


def private_loopback_port(value):
    if isinstance(value, bool):
        port = None
    elif isinstance(value, str) and value.isascii() and value.isdecimal():
        port = int(value, 10)
    elif isinstance(value, int):
        port = value
    else:
        port = None
    if port is None or not MIN_PRIVATE_PORT <= port <= MAX_PORT:
        raise ValueError("private loopback port is outside the admitted range")
    return port


def request_head(request, port):
    method = request["method"]
    if method not in ("GET", "POST"):
        raise ValueError("unsupported bounded method/body")
    path = request["path"]
    if not path.startswith("/") or any(c in path for c in "\r\n "):
        raise ValueError("unsafe raw request target")
    headers = request["headers"]
    head = f"{method} {path} HTTP/1.1\r\n".encode("ascii")
    if not any(name.lower() == "host" for name, _ in headers):
        head += f"Host: 127.0.0.1:{port}\r\n".encode("ascii")
    for name, value in headers:
        if any(c in name + value for c in "\r\n"):
            raise ValueError("header contains wire delimiter")
        head += (name + ": " + value + "\r\n").encode("ascii")
    return head


def framed_request_body(request, body):
    framing = request.get("framing", "content_length")
    if framing == "chunked":
        chunks = [body_bytes(item) for item in request.get("chunks", [])] or [body]
        if b"".join(chunks) != body:
            raise ValueError("request chunk content mismatch")
        encoded = [("%x\r\n" % len(part)).encode() + part + b"\r\n" for part in chunks if part]
        encoded.append(b"0\r\n\r\n")
        return b"Transfer-Encoding: chunked\r\n", encoded
    encoded = [body] if body else []
    if framing == "raw_no_normalization" or not body and request["method"] != "POST":
        return b"", encoded
    length = request.get("declared_content_length", len(body))
    return f"Content-Length: {length}\r\n".encode("ascii"), encoded


def wire_request(request, port):
    port = private_loopback_port(port)
    body = body_bytes(request["body"])
    if len(body) > MAX_WIRE:
        raise ValueError("unsupported bounded method/body")
    head = request_head(request, port)
    framing_header, encoded = framed_request_body(request, body)
    head += framing_header
    head += b"Connection: close\r\n\r\n"
    return head, encoded


def response_header(received):
    header, encoded = received.split(b"\r\n\r\n", 1)
    lines = header.decode("iso-8859-1").split("\r\n")
    status_line = lines[0].split()
    if len(status_line) < 2 or status_line[0] not in ("HTTP/1.0", "HTTP/1.1"):
        raise ValueError("invalid response status line")
    status = int(status_line[1])
    fields = [line.split(":", 1) for line in lines[1:]]
    lengths = [v.strip() for k, v in fields if k.lower() == "content-length"]
    transfers = [v.strip().lower() for k, v in fields if k.lower() == "transfer-encoding"]
    if lengths and transfers:
        raise ValueError("ambiguous response framing")
    return header, encoded, lines, status, lengths, transfers


def decode_chunked_response(encoded):
    rest = encoded
    parts = []
    while True:
        line, rest = rest.split(b"\r\n", 1)
        size_text = line.split(b";", 1)[0]
        if not size_text or any(c not in b"0123456789abcdefABCDEF" for c in size_text):
            raise ValueError("invalid response chunk size")
        length = int(size_text, 16)
        if not length:
            if rest != b"\r\n":
                raise ValueError("unexpected response trailers/suffix")
            return b"".join(parts)
        if len(rest) < length + 2 or rest[length:length + 2] != b"\r\n":
            raise ValueError("truncated response chunk")
        parts.append(rest[:length])
        rest = rest[length + 2:]


def decode_response_entity(encoded, lengths, transfers):
    if lengths:
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal() or int(lengths[0]) != len(encoded):
            raise ValueError("truncated or ambiguous Content-Length")
        return encoded, "content_length"
    if transfers:
        if transfers != ["chunked"]:
            raise ValueError("unsupported response transfer encoding")
        return decode_chunked_response(encoded), "chunked"
    return encoded, "close_delimited"


def response_framing(received):
    header, encoded, lines, status, lengths, transfers = response_header(received)
    decoded, kind = decode_response_entity(encoded, lengths, transfers)
    return {"status": status, "headers": lines, "framing": {"kind": kind,
            "content_lengths": lengths, "transfer_encoding": transfers,
            "encoded_entity_bytes": len(encoded), "decoded_entity_bytes": len(decoded)}}, decoded, header + b"\r\n\r\n"


def entity_prefix_received(received):
    """Chunk framing bytes alone cannot release a client-body barrier."""
    if b"\r\n\r\n" not in received:
        return False
    header, encoded = bytes(received).split(b"\r\n\r\n", 1)
    if not encoded:
        return False
    fields = [line.split(b":", 1) for line in header.split(b"\r\n")[1:] if b":" in line]
    transfer = [value.strip().lower() for name, value in fields if name.lower() == b"transfer-encoding"]
    if transfer:
        if transfer != [b"chunked"] or b"\r\n" not in encoded:
            return False
        size_text, data = encoded.split(b"\r\n", 1)
        size_text = size_text.split(b";", 1)[0]
        if not size_text or any(c not in b"0123456789abcdefABCDEF" for c in size_text):
            return False
        return int(size_text, 16) > 0 and bool(data)
    return True


def request_append_barrier(request, context):
    barrier = request.get("barrier")
    if barrier is None:
        return None
    if (not isinstance(barrier, dict) or type(barrier.get("after_chunk")) is not int
            or barrier["after_chunk"] != 1 or request.get("framing") != "chunked"
            or barrier.get("release_condition") != "native_append_first_chunk_observed"
            or type(barrier.get("timeout_seconds")) not in (int, float)
            or not 0 < barrier["timeout_seconds"] <= 20
            or len(request.get("chunks", [])) < 2
            or not body_bytes(request["chunks"][0])):
        raise ValueError("invalid first request body chunk barrier")
    if context is None:
        raise cancellation.GateError("request chunk barrier requires native identity context")
    cancellation.validate_identity(context["identity"])
    identifiers = [value for name, value in request["headers"] if name.lower() == "x-i12-id"]
    if identifiers != [context["identity"]["transaction_id"]] or "host_pid" not in context["identity"]:
        raise cancellation.GateError("request chunk barrier requires one exact principal and host PID")
    return barrier


def send_client_request(connection, request, head, chunks, root, receipt, context=None):
    barrier = request_append_barrier(request, context)
    connection.sendall(head)
    receipt["request_headers_sent_ns"] = time.monotonic_ns()
    for index, chunk in enumerate(chunks):
        connection.sendall(chunk)
        receipt["request_send_operations"].append({"index": index, "bytes": len(chunk),
            "sha256": hashlib.sha256(chunk).hexdigest(), "completed_ns": time.monotonic_ns()})
        if barrier is not None and index == 0:
            gate = {"release_condition": barrier["release_condition"], "after_chunk": 1,
                    "started_ns": time.monotonic_ns(), "released": False, "native_append": None}
            receipt["request_chunk_barrier"] = gate
            gate["native_append"] = cancellation.wait_for_append(context["native_log"],
                context["identity"], receipt["started_ns"], barrier["timeout_seconds"])
            gate.update(released=True, completed_ns=time.monotonic_ns())
        if request.get("chunks"):
            time.sleep(0.15)
    receipt["request_send_completed_ns"] = time.monotonic_ns()
    raw = head + b"".join(chunks)
    (root / "request.raw").write_bytes(raw)
    receipt.update(request_wire_bytes=len(raw), request_wire_sha256=hashlib.sha256(raw).hexdigest())


def after_client_send(connection, request, receipt, context):
    action = request.get("peer_action", "normal")
    if action in cancellation.ACTIONS:
        if context is None:
            raise RuntimeError("native-gated cancellation context is required")
        cancellation.publish_send_ready(context["ready_path"], receipt)
        cancellation.pause_for_parent()
    elif action == "shutdown_write_before_body_complete":
        connection.shutdown(socket.SHUT_WR)
        receipt["shutdown_write_ns"] = time.monotonic_ns()
    elif action == "SO_LINGER_zero_RST_after_first_native_append":
        if context is None:
            raise RuntimeError("native-gated reset context is required")
        receipt["reset_request"] = cancellation.wait_then_reset(connection,
            context["native_log"], context["identity"], receipt["started_ns"])
        return True
    return False


def receive_client_response(connection, backend_root, receipt, received):
    while True:
        before = time.monotonic_ns()
        chunk = connection.recv(65536)
        after = time.monotonic_ns()
        if not chunk:
            receipt.update(tcp_eof_observed=True, eof_ns=after)
            return
        received.extend(chunk)
        receipt["recv_chunks"].append({"started_ns": before, "completed_ns": after, "bytes": len(chunk)})
        if entity_prefix_received(received) and "first_encoded_entity_recv_ns" not in receipt:
            receipt["first_encoded_entity_recv_ns"] = after
            (backend_root / "client-first-body-received.release").touch(mode=0o600)
        if len(received) > MAX_WIRE:
            raise ValueError("response exceeded bounded capture")


def client_error(receipt, error):
    receipt["error"] = {"type": type(error).__name__, "message": str(error)}
    if isinstance(error, ConnectionResetError):
        receipt["tcp_reset_observed"] = True
    if isinstance(error, TimeoutError):
        receipt["timeout_observed"] = True


def client_main(spec_path, root, port, backend_root, cancellation_context=None):
    request = json.loads(spec_path.read_text())
    receipt = {"pid": os.getpid(), "started_ns": time.monotonic_ns(), "method": request["method"],
               "path": request["path"], "tcp_eof_observed": False, "tcp_reset_observed": False,
               "timeout_observed": False, "status": None, "entity_bytes": None,
               "entity_sha256": None, "framing": None, "error": None, "recv_chunks": [],
               "request_send_operations": []}
    received, raw = bytearray(), b""
    exit_code = 1
    try:
        head, chunks = wire_request(request, port)
        raw = head + b"".join(chunks)
        with socket.create_connection(("127.0.0.1", private_loopback_port(port)), timeout=10) as connection:
            connection.settimeout(10)
            send_client_request(connection, request, head, chunks, root, receipt, cancellation_context)
            if after_client_send(connection, request, receipt, cancellation_context):
                exit_code = 0
                return exit_code
            receive_client_response(connection, backend_root, receipt, received)
        fields, decoded, headers = response_framing(bytes(received))
        receipt.update(fields, entity_bytes=len(decoded), entity_sha256=hashlib.sha256(decoded).hexdigest())
        (root / "response.headers").write_bytes(headers)
        (root / "response.body").write_bytes(decoded)
        exit_code = 0
    except (OSError, ValueError, RuntimeError) as error:
        client_error(receipt, error)
    finally:
        if request.get("barrier") is not None:
            sent = len(receipt["request_send_operations"])
            raw = head + b"".join(chunks[:sent]) if "request_headers_sent_ns" in receipt else b""
            receipt.update(request_wire_bytes=len(raw), request_wire_sha256=hashlib.sha256(raw).hexdigest(),
                           request_wire_capture_scope="completed_sendall_operations_only")
        (root / "request.raw").write_bytes(raw)
        (root / "response.raw").write_bytes(received)
        receipt.update(completed_ns=time.monotonic_ns(), proposed_process_exit=exit_code)
        save(root / RECEIPT_FILE, receipt)
    return exit_code


SUPPORTED_SEAMS = frozenset(("raw_wire_preserve_invalid_framing", "causal_response_barrier",
                            "causal_native_request_append_barrier",
                            "shutdown_write_before_body_complete", "SO_LINGER_zero_RST_after_first_native_append",
                            *cancellation.ACTIONS))


def missing_operations(plan):
    missing = [item for item in plan.get("driver_seams", []) if item not in SUPPORTED_SEAMS]
    if plan.get("fault"):
        missing.append("fault_operation_not_activated:" + plan["fault"]["operation"])
    return missing


SINK_MODES = frozenset(("badpath", "devfull", "unwritable", "closed-descriptor", "physical-enospc"))


def prepare_sink(plan, root, helper):
    """Configure genuine physical faults without altering any native rule."""
    selected = plan.get("fault") or {}
    mode = selected.get("kind")
    if selected.get("boundary") != "physical_event_sink" or mode not in SINK_MODES:
        return None
    if not helper.is_file():
        return {"configured": False, "reason": "reviewed APR sink observer shared library not mounted",
                "requested_mode": mode, "actual_fault_observed": None}
    target = root / "principal-events.jsonl"
    if mode == "badpath":
        target = root / "absent-parent/events.jsonl"
    elif mode == "devfull":
        target = Path("/dev/full")
    elif mode == "unwritable":
        directory = root / "unwritable-sink-parent"
        directory.mkdir(mode=0o500)
        target = directory / EVENTS_FILE
    else:
        target.touch(mode=0o600)
    marker = root / "sink-fault.marker"
    marker.write_text("I12_APACHE_SINK_FAULT_V1\n")
    marker.chmod(0o600)
    preload = ":".join(item for item in (os.environ.get("LD_PRELOAD"), str(helper)) if item)
    environment = {"LD_PRELOAD": preload, "I12_SINK_ROOT": str(root), "I12_SINK_PATH": str(target),
                   "I12_SINK_MARKER": str(marker),
                   "I12_SINK_FAULT": mode if mode in ("closed-descriptor", "physical-enospc") else "observe"}
    return {"configured": True, "requested_mode": mode, "principal_sink": str(target),
            "healthy_control_sink": str(root / EVENTS_FILE), "helper_sha256": digest(helper),
            "marker_sha256": digest(marker), "environment": environment,
            "native_rule_order_unchanged": True, "actual_fault_observed": None,
            "apr_calls": None, "pre_apr_rejection": None}


def read_apr_calls(path):
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(errors="replace").splitlines():
        if "I12_APACHE_APR " in line:
            try:
                rows.append(json.loads(line.split("I12_APACHE_APR ", 1)[1]))
            except json.JSONDecodeError:
                continue
    return rows


def configure_io_environment(root, environment, helper):
    result = {"configured": False, "path": str(helper), "sha256": None}
    if helper.is_file():
        marker = root / "host-io.enable"
        with marker.open("x", encoding="ascii") as output:
            os.chmod(marker, 0o600)
            output.write("I12_APACHE_HOST_IO_V1\n")
        environment["I12_APACHE_IO_ROOT"] = str(root)
        environment["LD_PRELOAD"] = ":".join(item for item in (environment.get("LD_PRELOAD"), str(helper)) if item)
        result.update(configured=True, sha256=digest(helper), marker_sha256=digest(marker))
    return result


FAULT_MODES = {
    "body_size_nonzero_with_null_data": "null-body",
    "header_count_nonzero_with_null_headers": "null-headers",
    "early_mapping_failure_cleanup": "mapping-failure",
    "finish_failure_propagation": "finish-failure",
    "NEED-invalid-native-return": "invalid-native-return",
    "E2E-APACHE-TECHNICAL-PRECOMMIT": "technical-precommit",
    "E2E-APACHE-TECHNICAL-POSTCOMMIT": "technical-postcommit",
    "engine_timeout_before_commit": "timeout-decision-precommit",
    "engine_timeout_after_commit": "timeout-decision-postcommit",
    "NEED-timeout": "timeout-decision-precommit",
}
LINK_ARTIFACTS = ("host_bucket_object", "multipart_object", "fault_boundary_object", "fault_boundary_header")


def artifact_identity(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path or not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError("host helper artifact must be a regular one-link nonsymlink file")
    return {"path": str(path), "sha256": digest(path), "actual_linked_object_observed": None}


def helper_marker(root, name, content):
    marker = root / name
    with marker.open("x", encoding="ascii") as output:
        os.chmod(marker, 0o600)
        output.write(content)
    return {"path": str(marker), "sha256": digest(marker)}


def configure_host_helpers(plan, root, environment, artifacts):
    """Configure private admission, retaining the separate unknown runtime layer."""
    identities = {name: artifact_identity(path) for name, path in (artifacts or {}).items()}
    result = {"link_artifacts": identities, "actual_link_wiring_observed": None,
              "host_bucket": {"configured": False, "actual_observation": None},
              "multipart": {"configured": False, "actual_collection_observed": None,
                            "actual_cleanup_observed": None},
              "fault_boundary": {"configured": False, "actual_activation_observed": None,
                                 "actual_sdk_result": None, "actual_host_result": None}}
    if plan["execution_kind"] != "host_http":
        return result
    if "host_bucket_object" in identities:
        marker = helper_marker(root, "host-bucket.enable", "I12_APACHE_HOST_BUCKET_V1\n")
        environment.update(I12_APACHE_BUCKET_ROOT=str(root),
            I12_APACHE_BUCKET_RUN=environment["MSCONNECTOR_LIFECYCLE_RUN"], I12_APACHE_BUCKET_CASE=plan["case_id"])
        result["host_bucket"].update(configured=True, root=str(root), marker=marker)
    if plan.get("case_id") == "NEED-request-file" and "multipart_object" in identities:
        upload = root / "uploads"
        marker = helper_marker(upload, "multipart.enable", "I12_APACHE_MULTIPART_V1\n")
        environment["I12_APACHE_MULTIPART_ROOT"] = str(upload)
        result["multipart"].update(configured=True, root=str(upload), marker=marker,
            filename_collection_and_physical_file_are_distinct=True)
    mode = FAULT_MODES.get(plan.get("case_id"))
    if mode and all(name in identities for name in ("fault_boundary_object", "fault_boundary_header")):
        principal = plan["unique_main_request"]["token"]
        identifiers = [value for name, value in plan["request"]["headers"] if name.lower() == "x-i12-id"]
        allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."
        if identifiers != [principal] or not principal or len(principal) > 192 or any(c not in allowed for c in principal):
            raise ValueError("fault boundary needs exactly one bounded principal identity")
        marker = helper_marker(root, "fault-boundary.enable", "I12_APACHE_FAULT_BOUNDARY_V1\n")
        environment.update(I12_APACHE_FAULT_ROOT=str(root), I12_APACHE_FAULT_ID=principal, I12_APACHE_FAULT_MODE=mode)
        result["fault_boundary"].update(configured=True, root=str(root), marker=marker,
            mode=mode, principal_id=principal, elapsed_budget_enforcement_claimed=False,
            controlled_effective_return_is_actual_sdk_return=False)
    elif plan.get("fault"):
        result["fault_boundary"]["reason"] = "no reviewed callback mode or required linked artifacts for this case"
    return result


def case_environment(plan, root):
    environment = dict(os.environ, MSCONNECTOR_APACHE_NATIVE_OBSERVER=str(root / NATIVE_API_FILE),
                MSCONNECTOR_APACHE_HOST_OBSERVER=str(root / "host-eos.jsonl"),
                MSCONNECTOR_APACHE_BACKEND_CAPTURE=str(root / "connector-backend.jsonl"),
                MSCONNECTOR_LIFECYCLE_RUN=os.environ.get("MSCONNECTOR_LIFECYCLE_RUN", "apache-i12-batch"),
                MSCONNECTOR_LIFECYCLE_PROFILE="apache-native",
                MSCONNECTOR_LIFECYCLE_CASE=plan["case_id"])
    for name in tuple(environment):
        if name.startswith(("I12_APACHE_BUCKET_", "I12_APACHE_MULTIPART_", "I12_APACHE_FAULT_")):
            del environment[name]
    return environment


def client_request(plan, variants, label, sink):
    request = json.loads(json.dumps(variants.get(label, plan["request"])))
    if label in variants:
        request["headers"] = [[name, value + "-" + label if name.lower() == "x-i12-id" else value]
                              for name, value in request["headers"]]
    elif label != "main":
        if label == "precontrol":
            control = {"method": "GET", "path": "/i12-observer-control-before"}
        else:
            control = next(item for item in plan["controls"] if item["label"] == label)
        request.update(method=control["method"], path=control["path"], body={"encoding": "base64",
            "data": "", "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()},
            chunks=[], framing="content_length", peer_action="normal", barrier=None)
        request["headers"] = [["X-I12-ID", plan["unique_main_request"]["token"] + "-" + label]]
        if plan.get("baseline_rules_required"):
            # Exercise the unchanged baseline's benign pass/log rule so the
            # actual sink is independently witnessed around a rejected main.
            request["headers"].append(["X-Modsec-Smoke", "log-only"])
        if sink and sink["configured"]:
            request["headers"].append(["Host", "control.localhost"])
    return request


def client_command(plan, root, target, port, request, label, sequence, env, observation):
    if sequence:
        argv = [sys.executable, str(Path(__file__).with_name("keepalive.py")), "--spec", str(root / SPEC_FILE),
                "--output", str(target), "--port", str(port), "--backend-root", str(root / "backend")]
    else:
        argv = [sys.executable, str(Path(__file__)), "--client-spec", str(target / "request.json"),
                "--output", str(target), "--port", str(port), "--backend-root", str(root / "backend")]
        if label == "main" and (request.get("barrier") is not None or
                request.get("peer_action", "normal") in (*cancellation.ACTIONS,
                "SO_LINGER_zero_RST_after_first_native_append")):
            argv += ["--native-log", str(root / NATIVE_API_FILE), "--gate-run", env["MSCONNECTOR_LIFECYCLE_RUN"],
                     "--gate-case", plan["case_id"], "--gate-host-pid", str(observation["host_identity"]["pid"])]
    return argv


def read_sequence_observation(target, observation):
    client_observation = json.loads((target / SEQUENCE_RECEIPT_FILE).read_text())
    observation["clients"][-1]["receipt"] = str(target / SEQUENCE_RECEIPT_FILE)
    steps = client_observation["steps"]
    observation["actual_principal_execution"] = bool(steps and steps[0].get("request_send_completed_ns") is not None)
    if not client_observation["executed_requested_sequence"]:
        observation["missing_operations"].append("actual_requested_keepalive_sequence_incomplete")
    observation["actual_sequence_requests_sent"] = client_observation["actual_requests_sent_count"]
    observation["actual_concurrent_neighbor_process"] = client_observation.get("concurrent_neighbor")


def read_termination_observation(target, observation):
    termination = json.loads((target / TERMINATION_FILE).read_text())
    observation["clients"][-1].update(actual_client_termination=termination["actual_termination"],
        receipt=str(target / TERMINATION_FILE), wrapper_exit_is_not_wire_client_exit=True)
    ready_path = target / "send-ready.json"
    ready = json.loads(ready_path.read_text()) if ready_path.is_file() else None
    observation["actual_principal_execution"] = bool(ready and ready["progress"].get("request_send_completed_ns") is not None)
    if not termination["requested_action_performed"] or termination["wrapper_exit"] != 0:
        observation["missing_operations"].append("actual_native_gated_client_cancellation_unproven")


def read_client_observation(target, label, sequence, request, observation):
    if sequence and (target / SEQUENCE_RECEIPT_FILE).is_file():
        read_sequence_observation(target, observation)
    elif label == "main" and (target / TERMINATION_FILE).is_file():
        read_termination_observation(target, observation)
    elif label == "main" and (target / RECEIPT_FILE).is_file():
        client_observation = json.loads((target / RECEIPT_FILE).read_text())
        observation["actual_principal_execution"] = client_observation.get("request_send_completed_ns") is not None
        if request.get("barrier") is not None and not client_observation.get("request_chunk_barrier", {}).get("released"):
            observation["missing_operations"].append("actual_native_request_chunk_barrier_unproven")
        if request.get("peer_action") == "SO_LINGER_zero_RST_after_first_native_append" and not client_observation.get("reset_request"):
            observation["missing_operations"].append("actual_native_gated_client_reset_unproven")


def run_clients(plan, root, port, sink, env, observation, direct):
    variants = {item["label"]: item["request"] for item in plan.get("principal_request_variants", [])}
    labels = ("precontrol", "main", *variants, "followup", "neighbor")
    if plan["case_id"] in keepalive.CASES:
        labels = ("precontrol", "main", "followup") if plan["case_id"] == "NEED-neighbor-connection-stream" else ("precontrol", "main", "neighbor")
    for label in labels:
        target = root / label
        target.mkdir(mode=0o700)
        request = client_request(plan, variants, label, sink)
        save(target / "request.json", request)
        sequence = label == "main" and plan["case_id"] in keepalive.CASES
        argv = client_command(plan, root, target, port, request, label, sequence, env, observation)
        receipt = direct.waited(argv, root, target / "process", timeout=25)
        observation["clients"].append({"role": label, "actual_waited_exit": receipt["waited_exit"],
            "request_id": next(value for name, value in request["headers"] if name.lower() == "x-i12-id"),
            "receipt": str(target / RECEIPT_FILE), "command": receipt})
        read_client_observation(target, label, sequence, request, observation)


def collect_final_observation(root, event, sink, host, port, backend, backend_port, observation, direct):
    for process, listen_port, label in ((host, port, "host"), (backend, backend_port, "backend")):
        if process is not None:
            try:
                observation[label + "_cleanup"] = direct.stop(process, listen_port, root / (label + "-cleanup.json"))
            except (OSError, RuntimeError) as error:
                observation[label + "_cleanup_error"] = {"type": type(error).__name__, "message": str(error)}
                observation["stop_batch_after_cleanup_failure"] = True
    observation["physical_files"] = [{"path": str(path), "bytes": path.stat().st_size, "sha256": digest(path)}
        for path in (event, root / NATIVE_API_FILE, root / "host-eos.jsonl", root / AUDIT_FILE,
                     root / "native-debug.log", root / "error.log", root / "backend/requests.jsonl",
                     root / "principal-events.jsonl", root / "host-io.jsonl", root / "fault-boundary.jsonl",
                     root / "uploads/multipart.jsonl", root / "selected-rules-path.json") if path.is_file()]
    collect_sink_observation(root, sink, observation)


def collect_sink_observation(root, sink, observation):
    if not sink or not sink["configured"]:
        return
    sink["apr_calls"] = read_apr_calls(root / "error.log")
    mode = sink["requested_mode"]
    if mode in ("closed-descriptor", "physical-enospc"):
        expected_result = 9 if mode == "closed-descriptor" else 28
        sink["actual_fault_observed"] = any(row.get("stage") == "apr_file_write_full" and
            row.get("action") == mode and row.get("result") == expected_result and
            row.get("operation_result", -1) >= 0 for row in sink["apr_calls"])
        observation["fault_not_activated"] = not sink["actual_fault_observed"]
        if not sink["actual_fault_observed"]:
            observation["executed_case_contract"] = False
    else:
        # Missing APR rows cannot establish an APR open error. Root
        # must join actual Common/POSIX failure, native audit and host.
        observation["executed_case_contract"] = False
        observation["missing_operations"].append("independent_Common_POSIX_first_cause_and_native120016_join")


def sample_processes(host, owned, stop, snapshots, sample_errors, direct):
    while not stop.is_set():
        for pid in direct.descendant_pids(host.pid):
            try:
                if os.readlink(Path("/proc") / str(pid) / "exe") == str(owned):
                    snapshots.append(capture_process(pid))
            except (FileNotFoundError, ProcessLookupError):
                pass
            except (OSError, RuntimeError) as error:
                sample_errors.append({"type": type(error).__name__, "message": str(error)})
        stop.wait(0.1)


def prepare_config_fixtures(plan, root):
    if plan["execution_kind"] == "configtest":
        for instruction in plan["config"].get("setup", []):
            if instruction.startswith("mkdir_mode_0755:"):
                Path(replace_tokens(instruction.partition(":")[2], root)).mkdir(mode=0o755)
            else:
                raise ValueError("unsupported config fixture setup")


def observed_configtest(direct, owned, config, root, env):
    """Keep the RTK/helper transport separate from the actual parser child."""
    executable_sha256 = digest(owned)
    helper = Path(__file__).with_name("configtest_runner.py")
    helper_sha256 = digest(helper)
    prefix = root / "configtest-wrapper"
    wrapper = direct.waited([sys.executable, str(helper), "--owned", str(owned),
                             "--config", str(config), "--root", str(root)], root, prefix, env)
    for stream in ("stdout", "stderr"):
        content = Path(str(prefix) + "." + stream).read_bytes()
        wrapper[stream + "_bytes"] = len(content)
        wrapper[stream + "_sha256"] = hashlib.sha256(content).hexdigest()
    wrapper["helper_sha256"] = helper_sha256
    save(root / "configtest-wrapper-process.json", wrapper)
    receipt_file = root / "configtest-process.json"
    receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
    raw_returncode = receipt["raw_returncode"]
    if (isinstance(raw_returncode, bool) or not isinstance(raw_returncode, int)
            or receipt["waited_exit"] != raw_returncode
            or receipt["waited_signal"] != (-raw_returncode if raw_returncode < 0 else None)
            or receipt["argv"] != [str(owned), "-t", "-f", str(config)]
            or receipt["cwd"] != str(root)
            or receipt["pid"] != receipt["parser_pid"]
            or receipt["supervisor_parent_pid"] != wrapper["wrapper_pid"]):
        raise ValueError("physical parser process identity or raw wait binding failed")
    if (wrapper["waited_exit"] != 0 or receipt["timeout"] is not False or receipt["stream_decoding_errors"]
            or receipt["input_identity_unchanged"] is not True
            or receipt["executable_sha256"] != executable_sha256
            or digest(owned) != executable_sha256 or receipt["helper_sha256"] != helper_sha256
            or digest(helper) != helper_sha256 or receipt["config_sha256"] != digest(config)):
        raise ValueError("physical parser helper transport or input identity failed")
    for stream in ("stdout", "stderr"):
        content = (root / ("configtest." + stream)).read_bytes()
        if (hashlib.sha256(content).hexdigest() != receipt[stream + "_sha256"]
                or len(content) != receipt[stream + "_bytes"]
                or content.decode("utf-8", errors="strict") != receipt[stream]):
            raise ValueError("physical parser stream identity changed")
    cleanup = json.loads((root / "configtest-cleanup.json").read_text(encoding="utf-8"))
    if (digest(root / "configtest-cleanup.json") != receipt["cleanup_sha256"]
            or cleanup != receipt["cleanup"] or cleanup["pid"] != receipt["parser_pid"]):
        raise ValueError("physical parser cleanup identity changed")
    if digest(root / "configtest.command.json") != digest(receipt_file):
        raise ValueError("physical parser command receipt identity changed")
    receipt.update(parser_receipt_sha256=digest(receipt_file), wrapper_process=wrapper,
                   wrapper_receipt_sha256=digest(root / "configtest-wrapper-process.json"))
    return receipt


def execute(plan, ordinal, base, module, direct, owned, sink_helper, io_helper, helper_artifacts=None):
    root = base / ("%03d-" % ordinal + plan["case_id"])
    root.mkdir(mode=0o700)
    for name in ("audit-storage", "uploads", "backend"):
        (root / name).mkdir(mode=0o700)
    event = root / EVENTS_FILE
    event.touch(mode=0o600)
    save(root / "original-spec.json", plan)
    plan = keepalive.prepare_plan(plan)
    save(root / SPEC_FILE, plan)
    (root / RULES_FILE).write_text(native_rules(plan, root))
    (root / RULES_FILE).chmod(0o600)
    selected_rules = selected_rules_observation(plan, root)
    port, backend_port = direct.free_port(), direct.free_port()
    sink = prepare_sink(plan, root, sink_helper)
    config = root / "httpd.conf"
    config.write_text(config_text(plan, root, module, port, backend_port,
                                  sink["principal_sink"] if sink and sink["configured"] else None))
    config.chmod(0o600)
    env = case_environment(plan, root)
    if sink and sink["configured"]:
        env.update(sink["environment"])
    io_observer = configure_io_environment(root, env, io_helper)
    host_helpers = configure_host_helpers(plan, root, env, helper_artifacts)
    response_file = materialize_response_file(plan, root)
    observation = {"case_id": plan["case_id"], "original_id": plan["original_id"],
                   "execution_kind": plan["execution_kind"], "actual_principal_execution": False,
                   "executed_case_contract": False, "fault_not_activated": bool(plan.get("fault")),
                   "missing_operations": missing_operations(plan), "clients": [], "host_identity": None,
                   "physical_native_audit_rule_ids": None, "full_lifecycle_qualification": None,
                   "outcome": None, "effective_config_sha256": digest(config), "rules_sha256": selected_rules["sha256"]}
    observation["sink_fault"] = sink
    observation["host_io_observer"] = io_observer
    observation["response_file_source"] = response_file
    observation["selected_rules_path"] = selected_rules
    observation["host_helpers"] = host_helpers
    if host_helpers["fault_boundary"]["configured"]:
        observation["fault_not_activated"] = None
    if sink and sink["configured"]:
        # The exact operations are configured, but their physical outcome stays
        # unknown until the APR/host receipts are independently evaluated.
        observation["missing_operations"] = [item for item in observation["missing_operations"]
            if item != "physical_sink_" + sink["requested_mode"] and not item.startswith("fault_operation_not_activated:")
            and item not in ("preserve120001_separate_control_and_prove_actual120016_before_sink_failure",
                             "preserve120001_and120016_separate_first_sink_failure_from_native_deny")]
        observation["fault_not_activated"] = None
    backend = host = thread = None
    stop = threading.Event()
    snapshots, sample_errors = [], []

    try:
        prepare_config_fixtures(plan, root)
        configtest = observed_configtest(direct, owned, config, root, env)
        observation["configtest"] = configtest
        observation["configtest_cleanup"] = configtest["cleanup"]
        if plan["execution_kind"] == "configtest":
            observation["actual_config_execution"] = True
            observation["executed_case_contract"] = True
            return observation
        if configtest["waited_exit"] != 0:
            raise RuntimeError("actual configuration rejected before host request")
        backend, observation["backend_launch"] = direct.launch([sys.executable,
            str(Path(__file__).with_name("backend.py")), "--spec", str(root / SPEC_FILE),
            "--root", str(root / "backend"), "--port", str(backend_port)], root, root / "backend/process")
        observation["backend_identity"] = direct.ready(backend, backend_port, os.path.realpath(sys.executable))
        host, observation["host_launch"] = direct.launch([str(owned), "-X", "-f", str(config)], root, root / "host", env)
        thread = threading.Thread(target=sample_processes,
            args=(host, owned, stop, snapshots, sample_errors, direct), daemon=True)
        thread.start()
        observation["host_identity"] = direct.ready(host, port, str(owned))
        run_clients(plan, root, port, sink, env, observation, direct)
        observation["executed_case_contract"] = observation["actual_principal_execution"] and not observation["missing_operations"]
    except (OSError, RuntimeError, ValueError) as error:
        observation["execution_error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        stop.set()
        if thread is not None:
            thread.join(timeout=5)
        observation.update(native_process_snapshots=snapshots, native_process_sampler_errors=sample_errors,
                           sampler_thread_stopped=thread is None or not thread.is_alive())
        collect_final_observation(root, event, sink, host, port, backend, backend_port, observation, direct)
        save(root / "observation.json", observation)
    return observation


def private_admission(direct, module, helper_dir, helper_artifacts=None, runtime_helpers=None,
                      execution_helpers=None):
    admission = json.loads(Path("/opt/controller/admission.json").read_text())
    binding_file = helper_dir / "batch-binding.json"
    if not binding_file.is_file():
        raise ValueError("Root-reviewed batch-binding.json is required")
    binding = json.loads(binding_file.read_text())
    required_inputs = (str(module), "/usr/sbin/apache2", "/usr/lib/x86_64-linux-gnu/libmodsecurity.so.3.0.14",
                       *(str(path) for path in (helper_artifacts or {}).values()),
                       *(str(path) for path in (runtime_helpers or {}).values()),
                       *(str(path) for path in (execution_helpers or {}).values()))
    for required in required_inputs:
        if required not in binding.get("input_sha256", {}):
            raise ValueError("reviewed binding omits actual host/module/SDK")
    binding["outside_namespaces"] = admission["outside_namespaces"]
    identity = direct.admission(binding)
    return {"physical_identity": identity, "checked_binding": binding,
            "binding_source": str(binding_file)}


def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--module", type=Path)
    parser.add_argument("--helper-dir", type=Path)
    parser.add_argument("--sink-helper", type=Path, default=Path("/mnt/artifacts/apr-sink-fault.so"))
    parser.add_argument("--io-helper", type=Path, default=Path("/mnt/artifacts/apache-host-io.so"))
    for name in LINK_ARTIFACTS:
        parser.add_argument("--" + name.replace("_", "-"), type=Path)
    parser.add_argument("--only", default="")
    parser.add_argument("--client-spec", type=Path)
    parser.add_argument("--port", type=private_loopback_port)
    parser.add_argument("--backend-root", type=Path)
    parser.add_argument("--native-log", type=Path)
    parser.add_argument("--gate-run")
    parser.add_argument("--gate-case")
    parser.add_argument("--gate-host-pid", type=int)
    return parser


def run_client_mode(args, parser):
    request = json.loads(args.client_spec.read_text())
    action = request.get("peer_action", "normal")
    context = None
    if request.get("barrier") is not None or action in (*cancellation.ACTIONS, "SO_LINGER_zero_RST_after_first_native_append"):
        if args.native_log is None or not args.gate_run or not args.gate_case:
            parser.error("native-gated request requires physical native log and exact run/case identity")
        identity = {"run": args.gate_run, "case": args.gate_case,
                    "transaction_id": next(v for k, v in request["headers"] if k.lower() == "x-i12-id")}
        if args.gate_host_pid is not None:
            identity["host_pid"] = args.gate_host_pid
        context = {"native_log": args.native_log, "identity": identity, "ready_path": args.output / "send-ready.json"}
    if action in cancellation.ACTIONS:
        result = cancellation.supervise_client(
            lambda: client_main(args.client_spec, args.output, args.port, args.backend_root, context),
            args.native_log, identity, context["ready_path"], args.output / TERMINATION_FILE, action)
        return result["wrapper_exit"]
    return client_main(args.client_spec, args.output, args.port, args.backend_root, context)


def admit_batch_arguments(args, parser):
    if args.plan is None or args.module is None or args.helper_dir is None:
        parser.error("batch execution needs --plan --module --helper-dir")
    if any(getattr(args, name) is None for name in LINK_ARTIFACTS):
        parser.error("batch execution needs explicit --host-bucket-object --multipart-object --fault-boundary-object --fault-boundary-header")
    args.plan = admitted_mount_path(args.plan, FIXTURE_MOUNT)
    args.module = admitted_mount_path(args.module, ARTIFACT_MOUNT)
    args.helper_dir = admitted_mount_path(args.helper_dir, FIXTURE_MOUNT, file=False)
    args.sink_helper = admitted_mount_path(args.sink_helper, ARTIFACT_MOUNT)
    args.io_helper = admitted_mount_path(args.io_helper, ARTIFACT_MOUNT)
    for name in LINK_ARTIFACTS:
        setattr(args, name, admitted_mount_path(getattr(args, name), ARTIFACT_MOUNT))


def prelaunch_error(plan, ordinal, base, error):
    """Retain a case-bound input failure without inventing process execution."""
    result = {"case_id": plan["case_id"], "original_id": plan["original_id"],
        "actual_principal_execution": False, "executed_case_contract": False,
        "outcome": None, "full_lifecycle_qualification": None,
        "execution_error": {"type": type(error).__name__, "message": str(error)}}
    error_name = "%03d-" % ordinal + plan["case_id"] + "-prelaunch-error.json"
    save(base / error_name, result)
    return result


def main():
    parser = argument_parser()
    args = parser.parse_args()
    if args.client_spec:
        return run_client_mode(args, parser)
    admit_batch_arguments(args, parser)
    helper_artifacts = {name: getattr(args, name) for name in LINK_ARTIFACTS}
    helper_identities = {name: artifact_identity(path) for name, path in helper_artifacts.items()}
    runtime_helpers = {"sink_helper": args.sink_helper, "io_helper": args.io_helper}
    runtime_helper_identities = {name: artifact_identity(path) for name, path in runtime_helpers.items()}
    execution_helpers = {"configtest_runner": admitted_mount_path(
        Path(__file__).with_name("configtest_runner.py"), FIXTURE_MOUNT)}
    execution_helper_identities = {name: artifact_identity(path) for name, path in execution_helpers.items()}
    direct = load_module("apache_original_direct", args.helper_dir / "direct-runner.py")
    admission = private_admission(direct, args.module, args.helper_dir, helper_artifacts, runtime_helpers,
                                  execution_helpers)
    base = paths.private_directory(args.output)
    save(base / "admission.json", admission)
    payload = json.loads(args.plan.read_text())
    selected = set(args.only.split(",")) if args.only else {r["case_id"] for r in payload["rows"]}
    if selected - {r["case_id"] for r in payload["rows"]}:
        raise ValueError("unknown Apache original case selection")
    owned = base / "native-bin/apache2"
    owned.parent.mkdir(mode=0o700)
    shutil.copyfile("/usr/sbin/apache2", owned)
    owned.chmod(0o500)
    save(base / "binary-identity.json", {"owned_host": str(owned), "owned_host_sha256": digest(owned),
        "module": str(args.module), "module_sha256": digest(args.module),
        "host_helper_link_artifacts": helper_identities,
        "runtime_preload_artifacts": runtime_helper_identities,
        "execution_helper_artifacts": execution_helper_identities,
        "plan_sha256": digest(args.plan), "direct_helper_sha256": digest(args.helper_dir / "direct-runner.py")})
    results = []
    for ordinal, plan in enumerate(payload["rows"]):
        if plan["case_id"] not in selected:
            continue
        try:
            result = execute(plan, ordinal, base, args.module, direct, owned, args.sink_helper, args.io_helper, helper_artifacts)
        except (OSError, RuntimeError, ValueError) as error:
            # Input/materialization failures before process launch still get
            # their own original-ID receipt; never invent a principal request.
            result = prelaunch_error(plan, ordinal, base, error)
        results.append(result)
        print(json.dumps({"case_id": plan["case_id"], "actual_principal_execution": result["actual_principal_execution"],
                          "executed_case_contract": result["executed_case_contract"],
                          "execution_error": result.get("execution_error"), "outcome": None}), flush=True)
        if result.get("stop_batch_after_cleanup_failure"):
            break
    save(base / "batch-results.json", {"cases": results, "selected_ids": sorted(selected),
        "unattempted_ids": sorted(selected - {r["case_id"] for r in results}),
        "full_lifecycle_qualification": None})
    return 1 if any(r.get("execution_error") or r.get("stop_batch_after_cleanup_failure") for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
