#!/usr/bin/env python3
"""Prepare and measure native HTX sequences using the existing direct capture.

No host is started by preparation. HTTP measurements and native associations
remain separate; neither this driver nor the joiner awards lifecycle PASS.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import ssl
import sys
import time

CASE_NAMES = ("multiple_sequential_requests", "keep_alive_requests_if_supported")
PREFIX = "I12::haproxy-native-htx::"
ALLOW_BODY = b"ordinary-native-response\n"
DENY_BODY = b"I12 sequence denied\n"
LIMIT = 1024 * 1024
LEDGER_SUFFIX = "-ledger.json"
LIFECYCLE_ASSIGNMENT = "MSCONNECTOR_LIFECYCLE_CASE="


def sha(data):
    return hashlib.sha256(data).hexdigest()


def expected_sequence():
    return [{"index": index, "path": "/no-crs/deny" if smoke == "block" else "/no-crs/allow", "smoke": smoke,
             "status": status, "body_bytes": len(body), "body_sha256": sha(body)}
            for index, (smoke, status, body) in enumerate((
                ("allow", 200, ALLOW_BODY), ("block", 403, DENY_BODY),
                ("allow", 200, ALLOW_BODY)))]


def read_response(connection, pending=b""):
    """Read one bounded CL-framed response, retaining surplus for the next one."""
    data = pending
    reads = []
    while b"\r\n\r\n" not in data:
        data = receive(connection, data, reads)
    head, entity = data.split(b"\r\n\r\n", 1)
    lines = head.decode("iso-8859-1").split("\r\n")
    status_line = lines[0].split()
    if len(status_line) < 2 or status_line[0] != "HTTP/1.1":
        raise ValueError("expected HTTP/1.1 status line")
    headers = [line.split(":", 1) for line in lines[1:]]
    lengths = [value.strip() for key, value in headers if key.lower() == "content-length"]
    if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal():
        raise ValueError("one decimal Content-Length required")
    if any(key.lower() == "transfer-encoding" for key, _ in headers):
        raise ValueError("Transfer-Encoding conflicts with bounded CL fixture")
    length = int(lengths[0])
    if length > LIMIT:
        raise ValueError("response exceeds fixture bound")
    while len(entity) < length:
        entity = receive(connection, entity, reads)
    body, surplus = entity[:length], entity[length:]
    wire = head + b"\r\n\r\n" + body
    return {"status": int(status_line[1]), "headers": headers,
            "declared_content_length": length, "body_complete": True,
            "response_bytes": len(body), "response_sha256": sha(body),
            "wire_bytes": len(wire), "wire_sha256": sha(wire),
            "ssl_reads": reads, "wire": wire}, surplus


def receive(connection, previous, reads):
    before = time.time_ns()
    chunk = connection.recv(16384)
    reads.append({"before_wall_ns": before, "after_wall_ns": time.time_ns(),
                  "actual_bytes": len(chunk), "sha256": sha(chunk) if chunk else None})
    if not chunk:
        raise EOFError("actual TLS recv returned zero before complete HTTP framing")
    if len(previous) + len(chunk) > LIMIT + 65536:
        raise ValueError("bounded response buffer exceeded")
    return previous + chunk


def connect(context):
    return context.wrap_socket(socket.create_connection(("127.0.0.1", 18490), timeout=10),
                               server_hostname="127.0.0.1", suppress_ragged_eofs=False)


def socket_identity(connection, serial):
    return {"connection_serial": serial, "fd": connection.fileno(),
            "local": connection.getsockname(), "peer": connection.getpeername(),
            "tls_version": connection.version()}


def drive_item(name, root, item, connection, pending, same_socket, result):
    started = time.time_ns()
    identity = socket_identity(connection, result["connections_opened"])
    request = (f'GET {item["path"]} HTTP/1.1\r\nHost: 127.0.0.1\r\n'
               f'X-Modsec-Smoke: {item["smoke"]}\r\nContent-Length: 0\r\n'
               f'Connection: {"keep-alive" if same_socket else "close"}\r\n\r\n').encode()
    connection.sendall(request)
    observed, pending = read_response(connection, pending)
    wire = observed.pop("wire")
    (root / f'{name}-wire-{item["index"]}.bin').write_bytes(wire)
    observed.update(index=item["index"], path=item["path"],
                    started_wall_ns=started, completed_wall_ns=time.time_ns(),
                    socket=identity, request_wire_sha256=sha(request),
                    expected=item)
    # Explicit field mapping: expected payload identity is not a measurement.
    observed["matches_expected"] = (observed["status"] == item["status"] and
        observed["response_bytes"] == item["body_bytes"] and
        observed["response_sha256"] == item["body_sha256"])
    result["requests"].append(observed)
    return connection, pending


def release_independent_connection(connection, same_socket):
    if not same_socket:
        connection.close()
        return None
    return connection


def reject_independent_surplus(pending, same_socket):
    if not same_socket and pending:
        raise ValueError("unexpected bytes after independently closed response")


def drive(name, root=Path("/task"), contract=None):
    if contract is None:
        contract = json.loads(Path("/mnt/fixtures/case-contract.json").read_text())
    same_socket = contract["same_tls_socket_required"] and name == "main"
    context = ssl.create_default_context(cafile=str(root / "tls.crt"))
    expected = contract["sequence"] if name == "main" else [
        {"index": 0, "path": "/i12-neighbor", "smoke": "allow", "status": 200,
         "body_bytes": 8, "body_sha256": sha(b"healthy\n")}]
    result = {"name": name, "started_wall_ns": time.time_ns(), "requests": [],
              "connections_opened": 0, "full_lifecycle_pass": None,
              "same_tls_socket_required": same_socket, "error": None,
              "native_EOS_not_derived_from_HTTP": True}
    connection = None
    pending = b""
    try:
        for item in expected:
            if connection is None:
                connection = connect(context)
                result["connections_opened"] += 1
            connection, pending = drive_item(name, root, item, connection, pending, same_socket, result)
            connection = release_independent_connection(connection, same_socket)
            reject_independent_surplus(pending, same_socket)
        if pending:
            raise ValueError("unexpected bytes beyond final HTTP response")
    except (OSError, EOFError, ValueError) as error:
        result["error"] = {"type": type(error).__name__, "message": str(error),
                           "wall_ns": time.time_ns(), "no_reconnect_attempted": same_socket}
    finally:
        if connection is not None:
            connection.close()
        result["completed_wall_ns"] = time.time_ns()
        result["http_sequence_matches"] = (result["error"] is None and
            len(result["requests"]) == len(expected) and
            all(row["matches_expected"] for row in result["requests"]))
        (root / (name + "-client.json")).write_text(json.dumps(result, indent=2) + "\n")
    return 0 if result["http_sequence_matches"] else 1


def request_allocation(request, allocations, seen):
    candidates = [row for row in allocations
                  if request["started_wall_ns"] <= row["wall_ns"] <= request["completed_wall_ns"]]
    if len(candidates) > 1:
        raise ValueError("ambiguous native allocation within actual client interval")
    allocation = candidates[0] if candidates else None
    scope = allocation["allocation_scope_call"] if allocation else None
    if scope is not None and scope in seen:
        raise ValueError("native allocation reused across sequence requests")
    if scope is not None:
        seen.add(scope)
    return allocation


def join_native(client, native):
    """Bind only actual unambiguous allocations; retain absent/extra calls."""
    allocations = [row for row in native if row.get("function") == "host_allocation"
                   and row.get("edge") == "return" and row.get("result") == 1]
    joined = []
    seen = set()
    for request in client["requests"]:
        allocation = request_allocation(request, allocations, seen)
        scope = allocation["allocation_scope_call"] if allocation else None
        rows = [row for row in native if row.get("allocation_scope_call") == scope] if allocation else []
        joined.append({"index": request["index"], "observed_client": request,
                       "actual_allocation": allocation, "actual_native_rows": rows,
                       "actual_return_counts": {function: sum(row.get("function") == function and
                            row.get("edge") == "return" for row in rows)
                            for function in ("common_finish", "common_cleanup", "native_process_logging", "native_cleanup")},
                       "missing_allocation_reason": None if allocation else "No actual allocation in measured request interval"})
    return {"requests": joined, "full_lifecycle_pass": None,
            "HTTP_success_is_not_native_lifecycle_proof": True}


def bind_launch_identity(launch, base_contract, name):
    from connector_suite.adapters.haproxy.harness.i12_native_cases import replace_once

    if base_contract.get("original_id") != PREFIX + "allow" or name not in CASE_NAMES:
        raise ValueError("sequence base must bind the original native allow case")
    anchors = [LIFECYCLE_ASSIGNMENT + repr(label)
               for label in ("NEED-allow", PREFIX + "allow")]
    if launch.count(LIFECYCLE_ASSIGNMENT) != 1 or sum(launch.count(anchor) for anchor in anchors) != 1:
        raise ValueError("ambiguous or missing allow observer identity")
    anchor = next(anchor for anchor in anchors if anchor in launch)
    launch = replace_once(launch, anchor, LIFECYCLE_ASSIGNMENT + repr(PREFIX + name))
    return replace_once(launch, "'selected_id':" + repr(PREFIX + "allow"),
                        "'selected_id':" + repr(PREFIX + name))


def prepare(base, plans_path, output):
    from connector_suite.adapters.haproxy.harness.i12_native_cases import replace_once

    plans = json.loads(plans_path.read_text())["plans"]
    ledger = json.loads(base.with_name(base.name + LEDGER_SUFFIX).read_text())
    sources = {}
    for filename, expected in ledger["files"].items():
        path = base / filename
        if path.is_symlink() or sha(path.read_bytes()) != expected:
            raise ValueError("sealed base capture differs: " + filename)
        sources[filename] = path.read_bytes()
    records = []
    for name in CASE_NAMES:
        plan = next(row for row in plans if row["run_scoped_case_id"] == PREFIX + name)
        case = output / name
        case.mkdir()
        launch = sources["launch.py"].decode()
        launch = replace_once(launch, "    default_backend htx_upstream", "    errorfile 403 /mnt/fixtures/deny.http\n    default_backend htx_upstream")
        launch = bind_launch_identity(launch, json.loads(sources["case-contract.json"]), name)
        launch = launch.replace("20261015-htx-allow", "20261018-htx-" + name)
        backend = sources["backend.py"].decode()
        backend = replace_once(backend, "BaseHTTPRequestHandler,HTTPServer", "BaseHTTPRequestHandler,ThreadingHTTPServer")
        backend = replace_once(backend, "server=HTTPServer(", "server=ThreadingHTTPServer(")
        backend = replace_once(backend, "self.send_header('Connection','close');", "")
        backend = replace_once(backend, "self.close_connection=True", "self.close_connection=False")
        contract = {"schema": "i12-haproxy-native-sequence-v1", "original_id": PREFIX + name,
                    "original_requirement_binding": plan,
                    "same_tls_socket_required": name == CASE_NAMES[1],
                    "sequence": expected_sequence(), "full_lifecycle_pass": None,
                    "host_runs": 0, "independent_native_join_required": True,
                    "base_capture_ledger_sha256": sha(base.with_name(base.name + LEDGER_SUFFIX).read_bytes())}
        denied = (f"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {len(DENY_BODY)}\r\n\r\n").encode() + DENY_BODY
        files = {"launch.py": launch.encode(), "backend.py": backend.encode(),
                 "client.py": Path(__file__).read_bytes(),
                 "openssl.cnf": sources["openssl.cnf"], "deny.http": denied,
                 "case-contract.json": (json.dumps(contract, indent=2) + "\n").encode()}
        for filename, data in files.items():
            if filename.endswith(".py"):
                compile(data, filename, "exec")
            (case / filename).write_bytes(data)
            (case / filename).chmod(0o444)
        case.chmod(0o555)
        record = {"files": {key: sha(value) for key, value in files.items()}, "symlinks": {}}
        receipt = case.with_name(name + LEDGER_SUFFIX)
        receipt.write_text(json.dumps(record, indent=2) + "\n")
        receipt.chmod(0o444)
        records.append({"id": PREFIX + name, "fixture": str(case), "ledger": str(receipt),
                        "ledger_sha256": sha(receipt.read_bytes()), "host_runs": 0})
    return records


def main():
    if len(sys.argv) == 2 and sys.argv[1] in ("main", "neighbor"):
        return drive(sys.argv[1])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--plans", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    from connector_suite.adapters.haproxy.harness.i12_native_cases import fresh_output

    output = fresh_output(args.output)
    records = prepare(args.base, args.plans, output)
    index = output / "fixture-index.json"
    index.write_text(json.dumps(records, indent=2) + "\n")
    index.chmod(0o444)
    output.chmod(0o555)
    print(json.dumps({"fixtures": records, "host_runs": 0}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
