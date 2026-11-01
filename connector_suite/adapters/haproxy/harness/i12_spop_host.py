#!/usr/bin/env python3
"""Request-only HAProxy I12 capture, executed inside an admitted private host.

Inputs: /mnt/artifacts/{haproxy,haproxy-spop}, this script and i12_spop_wire.py
under /mnt/fixtures. All mutable output stays under /task. The independent TCP
observer preserves every SPOP byte and decodes complete frames. An explicitly
selected companion can complete held native transactions; these independent
request-profile runs never qualify the companion profile.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

from connector_suite.adapters.haproxy.harness.i12_spop_wire import decode_frame, MAX_FRAME
import connector_suite.adapters.haproxy.harness.i12_spop_cases as cases

ROOT = Path("/task")
CLIENT_FILE = 'client.jsonl'
COMMANDS_FILE = 'commands.jsonl'
SPOE_CONFIG_FILE = 'spoe.cfg'
FRAMES_FILE = 'frames.jsonl'
BACKEND_FILE = 'backend.jsonl'
HOST_BINARY = '/mnt/artifacts/haproxy'
LOCK = threading.Lock()


def record(name, value):
    with LOCK, (ROOT / name).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True) + "\n")


def case_identity(selected):
    if selected.get("schema") == cases.SCHEMA:
        original = cases.validate_original(selected)
        return {"diagnostic_id": original, "original_id": original,
                "original_obligation_eligible": True}
    # These supplemental probes do not carry a reviewed original Oracle
    # contract. In particular, an incoming legacy case_id must never invent
    # original membership or transfer a diagnostic run to a corrected ID.
    return {"diagnostic_id": "DIAG::haproxy-spop-request::" + selected["case"],
            "original_id": None, "original_obligation_eligible": False}


def snapshot(process, name):
    proc = Path("/proc") / str(process.pid)
    maps = proc.joinpath("maps").read_text()
    (ROOT / (name + ".maps")).write_text(maps)
    files = set()
    for line in maps.splitlines():
        fields = line.split(None, 5)
        if len(fields) == 6 and fields[5].startswith("/") and "libmodsecurity" in fields[5]:
            files.add(fields[5])
    identities = []
    for name_on_disk in sorted(files):
        file = Path(name_on_disk)
        identities.append({"path": name_on_disk, "sha256": hashlib.sha256(file.read_bytes()).hexdigest()})
    record("process-identity.jsonl", {"name": name, "pid": process.pid,
           "wall_ns": time.time_ns(), "native_libraries": identities,
           "exe": os.readlink(proc / "exe"),
           "fds": {file.name: os.readlink(file) for file in proc.joinpath("fd").iterdir()}})


def read_rows(name):
    path = ROOT / name
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def evaluate(selected):
    """Compare independent observations; a successful launcher is insufficient."""
    case = selected["case"]
    allowed = case in ("empty-allow", "post-allow", "h2-content-length-mapping")
    policy_deny = case in ("p1-deny", "p2-deny")
    technical_loss = case == "technical-agent-loss"
    ack_status = 503
    if allowed:
        ack_status = 200
    elif policy_deny:
        ack_status = 403
    elif case == "corrupt-notify":
        ack_status = 400
    elif technical_loss:
        ack_status = None
    expected = {"ack_status": ack_status,
                "ack_blocked": None if technical_loss else not allowed,
                "backend_requests": 1 if allowed else 0,
                "client_status": 200 if allowed else 503,
                "fully_inspected_http2": False}
    frames = read_rows(FRAMES_FILE)
    acks = [{action["name"]: action["value"] for action in frame["decoded"].get("actions", [])}
            for frame in frames if frame["decoded"].get("kind") == 103]
    clients = [json.loads(line) for line in (ROOT / CLIENT_FILE).read_text().splitlines()]
    observed = {"ack_status": acks[-1].get("status") if acks else None,
                "ack_blocked": acks[-1].get("blocked") if acks else None,
                "backend_requests": len(read_rows(BACKEND_FILE)),
                "client_status": None if clients[-1]["http2"] else int(clients[-1]["status_line"].split()[1]),
                "fully_inspected_http2": False}
    mismatches = [key for key in ("ack_status", "ack_blocked", "backend_requests") if observed[key] != expected[key]]
    if not clients[-1]["http2"] and observed["client_status"] != expected["client_status"]:
        mismatches.append("client_status")
    record("expectations.jsonl", {"case": case, **case_identity(selected),
           "expected": expected, "observed": observed, "mismatches": mismatches,
           "observation_result": "failed" if mismatches else "passed",
           "full_lifecycle_pass": None, "companion_profile_qualified": False,
           "limitation": "HTTP2 status HPACK is retained raw; no HTTP2 inspection qualification"})


class Observer:
    def __init__(self, corrupt_notify=False):
        self.corrupt_notify = corrupt_notify
        self.stop = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 18542))
        self.listener.listen(16)
        self.listener.settimeout(.1)
        self.peers = []
        self.workers = []
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def forward_frames(self, pending, destination, connection, direction, stamp):
        while len(pending) >= 4:
            size = struct.unpack("!I", pending[:4])[0]
            if size > MAX_FRAME:
                raise ValueError("observer frame budget exceeded")
            if len(pending) < 4 + size:
                break
            raw = bytes(pending[:4 + size])
            del pending[:4 + size]
            try:
                decoded = decode_frame(raw)
            except ValueError as error:
                decoded = {"decode_error": str(error)}
            record(FRAMES_FILE, {"connection": connection,
                   "direction": direction, "wall_ns": stamp,
                   "sha256": hashlib.sha256(raw).hexdigest(),
                   "hex": raw.hex(), "decoded": decoded})
            if decoded.get("kind") == 3:
                record("samples.jsonl", {"connection": connection,
                       "stream": decoded["stream"], "frame": decoded["frame"],
                       "wire_sha256": hashlib.sha256(raw).hexdigest(),
                       "measurement": cases.inspect_notify_frame(raw)})
            if self.corrupt_notify and direction == "host-agent":
                forwarded = raw
                if decoded.get("kind") == 3:
                    # Remove a byte from the final version argument,
                    # while giving the agent a complete TCP/SPOP
                    # envelope. The production notify parser must
                    # reject the damaged typed value before native
                    # transaction allocation.
                    forwarded = cases.corrupt_notify_frame(raw)
                record("forwarded-frames.jsonl", {"connection": connection,
                       "direction": direction, "wall_ns": time.time_ns(),
                       "hex": forwarded.hex(),
                       "sha256": hashlib.sha256(forwarded).hexdigest(),
                       "deliberately_corrupted": forwarded != raw})
                destination.sendall(forwarded)

    def copy(self, source, destination, connection, direction):
        pending = bytearray()
        try:
            while not self.stop.is_set():
                try:
                    data = source.recv(65536)
                except socket.timeout:
                    continue
                if not data:
                    break
                stamp = time.time_ns()
                record("wire-chunks.jsonl", {"connection": connection,
                       "direction": direction, "wall_ns": stamp, "hex": data.hex()})
                pending.extend(data)
                self.forward_frames(pending, destination, connection, direction, stamp)
                if not (self.corrupt_notify and direction == "host-agent"):
                    destination.sendall(data)
        except (OSError, ValueError) as error:
            record("observer-errors.jsonl", {"connection": connection,
                   "direction": direction, "error": str(error)})
        finally:
            if pending:
                record("wire-partials.jsonl", {"connection": connection,
                       "direction": direction, "hex": pending.hex()})
            try:
                destination.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def accept(self):
        while not self.stop.is_set():
            try:
                source, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                destination = socket.create_connection(("127.0.0.1", 18543), timeout=2)
            except OSError as error:
                record("observer-errors.jsonl", {"direction": "connect-agent", "error": str(error)})
                source.close()
                continue
            connection = len(self.peers) // 2
            self.peers.extend((source, destination))
            for peer in (source, destination):
                peer.settimeout(.2)
            for first, second, direction in ((source, destination, "host-agent"),
                                              (destination, source, "agent-host")):
                worker = threading.Thread(target=self.copy,
                                          args=(first, second, connection, direction), daemon=True)
                worker.start()
                self.workers.append(worker)

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(2)
        if self.thread.is_alive():
            raise RuntimeError("SPOP accept worker did not stop")
        for peer in self.peers:
            peer.close()
        for worker in self.workers:
            worker.join(2)
        record("observer-cleanup.jsonl", {"listener_joined": not self.thread.is_alive(),
               "workers_joined": all(not worker.is_alive() for worker in self.workers)})
        if any(worker.is_alive() for worker in self.workers):
            raise RuntimeError("SPOP relay worker did not stop")


def backend(stop):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 18541))
        listener.listen(16)
        listener.settimeout(.1)
        (source_path('backend.ready', root=ROOT)).touch()
        while not stop.is_set():
            try:
                peer, _ = listener.accept()
            except socket.timeout:
                continue
            with peer:
                peer.settimeout(3)
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    chunk = peer.recv(65536)
                    if not chunk:
                        break
                    request.extend(chunk)
                if b"\r\n\r\n" not in request:
                    continue
                head, body = request.split(b"\r\n\r\n", 1)
                length = next((int(line.split(b":", 1)[1].strip())
                               for line in head.split(b"\r\n")[1:]
                               if line.lower().startswith(b"content-length:")), 0)
                while len(body) < length:
                    chunk = peer.recv(65536)
                    if not chunk:
                        break
                    body += chunk
                record(BACKEND_FILE, {"wall_ns": time.time_ns(),
                       "header_hex": head.hex(), "body_hex": body.hex(),
                       "neighbor": head.split(b"\r\n", 1)[0].split(b" ")[1] == b"/i12-neighbor"})
                peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nBACKEND")


def h2_stream_ended(response):
    pos = 0
    ended = False
    while len(response) - pos >= 9:
        size = int.from_bytes(response[pos:pos + 3], "big")
        if len(response) - pos < 9 + size:
            break
        kind, flags = response[pos + 3:pos + 5]
        stream = int.from_bytes(response[pos + 5:pos + 9], "big") & 0x7fffffff
        ended = ended or (stream == 1 and kind in (0, 1) and bool(flags & 1))
        pos += 9 + size
    return ended


def prepare_request(case):
    # Mutate only the test representation emitted by the real HAProxy host.
    body_length = "body_len=req.body_size" if case != "missing-body-length" else ""
    if case == "mismatched-body-length":
        body_length = "body_len=int(99)"
    version = "http_version=req.ver" if case != "missing-version" else ""
    body = b"alpha=clean" if case in ("post-allow", "p2-deny") else b""
    if case == "p2-deny":
        body = b"alpha=I12_BLOCK_BODY"
    path = "/" + case
    headers = "Host: localhost\r\nConnection: close\r\n"
    if case == "p1-deny":
        headers += "X-I12-Block: yes\r\n"
    if body:
        headers += f"Content-Length: {len(body)}\r\nContent-Type: application/x-www-form-urlencoded\r\n"
    if case == "chunked-unsupported":
        headers += "Transfer-Encoding: chunked\r\n"
        body = b"4\r\ntest\r\n0\r\n\r\n"
    request = f"{'POST' if body else 'GET'} {path} HTTP/1.1\r\n{headers}\r\n".encode() + body
    h2 = case in ("h2-unframed-mapping", "h2-content-length-mapping")
    if h2:
        # Minimal real HTTP/2 prior-knowledge request. HPACK static indexes:
        # method GET=2, scheme http=6, path /=4, authority=1, content-length=28.
        block = b"\x82\x86\x84\x01\x09localhost"
        if case == "h2-content-length-mapping":
            block += b"\x0f\x0d\x010"
        request = (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00" +
                   len(block).to_bytes(3, "big") + b"\x01\x05\x00\x00\x00\x01" + block)
    return body_length, version, request, h2


def capture_response(case, request, h2):
    with socket.create_connection(("127.0.0.1", 18540), timeout=5) as client:
        client.settimeout(5)
        started = time.time_ns()
        client.sendall(request)
        response = bytearray()
        terminal = "eof"
        try:
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                response.extend(chunk)
                if h2:
                    # Stop only after the complete response stream's
                    # END_STREAM frame, preserving every transport byte.
                    ended = h2_stream_ended(response)
                    if ended:
                        terminal = "h2-end-stream"
                        break
        except OSError as error:
            terminal = type(error).__name__
        (source_path('response.raw', root=ROOT)).write_bytes(response)
        record(CLIENT_FILE, {"case": case, "started_ns": started,
               "finished_ns": time.time_ns(), "terminal": terminal,
               "response_hex": response.hex(), "http2": h2,
               "status_line": None if h2 else bytes(response).split(b"\r\n", 1)[0].decode("ascii", "replace")})


def cleanup_host(children, observer, stop, worker, with_companion):
    for name, process, argv in reversed(children):
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
        try:
            code = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            code = process.wait(timeout=5)
        record(COMMANDS_FILE, {"argv": argv, "launcher_rtk_proxied": True, "cwd": os.getcwd(),
               "exit": code, "reaped": True, "pid": process.pid})
    if observer is not None:
        observer.close()
    stop.set()
    worker.join(4)
    record("cleanup.jsonl", {"backend_joined": not worker.is_alive(),
           "response_companion_configured": with_companion, "full_lifecycle_pass": None})


def verify_host_configuration():
    for name, argv in (("identity", [HOST_BINARY, "-vv"]),
                       ("config", [HOST_BINARY, "-c", "-f", "/task/haproxy.cfg"])):
        with (ROOT / (name + ".stdout")).open("wb") as out, (ROOT / (name + ".stderr")).open("wb") as err:
            result = subprocess.run(["rtk", "proxy", *argv], stdout=out, stderr=err, timeout=10)
        record(COMMANDS_FILE, {"argv": ["rtk", "proxy", *argv], "cwd": os.getcwd(), "exit": result.returncode})
        if result.returncode:
            raise RuntimeError(name + " failed")


def original_rules(selected):
    profile = cases.validate_runtime(selected)
    # Preserve the canonical rules; override only runtime paths and the
    # explicitly source-bound native request body policy and physical native
    # observers. Audit parts deliberately omit request and response bodies.
    removed = ("SecAuditLog ", "SecAuditEngine ", "SecAuditLogType ",
               "SecAuditLogParts ", "SecDebugLog ", "SecDebugLogLevel ", "SecRequestBodyLimit ",
               "SecRequestBodyNoFilesLimit ", "SecRequestBodyLimitAction ")
    source = "\n".join(line for line in selected["rules_source"].splitlines()
                       if not line.strip().startswith(removed))
    return (source + "\n" + profile["rules_extra"] +
            f'\nSecRequestBodyLimit {profile["native_request_limit"]}\n'
            f'SecRequestBodyNoFilesLimit {profile["native_request_limit"]}\n'
            f'SecRequestBodyLimitAction {profile["native_request_limit_action"]}\n'
            'SecAuditEngine On\nSecAuditLogType Serial\nSecAuditLogParts ABFHZ\n'
            'SecAuditLog /task/native-audit.log\nSecDebugLog /task/native-debug.log\nSecDebugLogLevel 9\n')


def original_configuration(selected, config, spoe, agent):
    profile = cases.validate_runtime(selected)
    # Both faults are local to the original request. The clean neighbor uses
    # real req.body_size and real req.body in the same process pair.
    assignments = ('    http-request set-var(txn.i12_body) req.body\n'
                   '    http-request set-var(txn.i12_length) req.body_size\n')
    for field, fetch, normal in (("body", profile["body_fetch"], "req.body"),
                                ("length", profile["body_size_fetch"], "req.body_size")):
        if fetch != normal:
            assignments += (f'    http-request set-var(txn.i12_{field}) {fetch}'
                            ' unless { path -m str /i12-neighbor }\n')
    anchor = '    http-request send-spoe-group modsecurity request-check'
    config = config.replace(anchor, assignments + anchor)
    config = config.replace('    http-request deny deny_status 503 if',
                            '    http-request deny deny_status 403 if { var(txn.modsec.status) -m int 403 }\n'
                            '    http-request deny deny_status 429 if { var(txn.modsec.status) -m int 429 }\n'
                            '    http-request redirect location %[var(txn.modsec.redirect_url)] code 302 if { var(txn.modsec.status) -m int 302 }\n'
                            '    http-request deny deny_status 503 if')
    spoe = spoe.replace('body=req.body body_len=req.body_size',
                        'body=var(txn.i12_body) body_len=var(txn.i12_length)')
    if profile["companion_export_only"]:
        # Original traffic exports a held transaction without claiming it.
        # A second frontend in the same host lets the clean neighbor complete
        # its own real response companion lifecycle independently.
        start = config.index('frontend request_only\n')
        end = config.index('backend be_app\n')
        front = config[start:end]
        filter_line = next(line for line in front.splitlines(True) if 'filter modsecurity-htx ' in line)
        config = config[:start] + front.replace(filter_line, '') + front.replace(
            'frontend request_only', 'frontend clean_neighbor').replace('18540', '18544') + config[end:]
        agent = agent.replace('response-body-timeout=10000',
                              f'response-body-timeout={profile["companion_ttl_ms"]}')
    return config, spoe, agent


def response_measurement(raw):
    header, separator, body = raw.partition(b"\r\n\r\n")
    result = {"headers_complete": bool(separator), "status": None,
              "body_bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest(),
              "content_length": None, "complete_length_framing": False}
    if not separator:
        return result
    try:
        result["status"] = int(header.split(b"\r\n", 1)[0].split()[1])
        lengths = [line.split(b":", 1)[1].strip() for line in header.split(b"\r\n")[1:]
                   if line.lower().startswith(b"content-length:")]
        if len(lengths) == 1 and lengths[0].isdigit():
            result["content_length"] = int(lengths[0])
            result["complete_length_framing"] = len(body) == result["content_length"]
    except (ValueError, IndexError):
        result["parse_error"] = True
    return result


def original_client_endpoint(client, method):
    try:
        endpoint = getattr(client, method)()
    except OSError as error:
        return None, type(error).__name__
    if isinstance(endpoint, tuple) and len(endpoint) in (2, 4) and isinstance(endpoint[0], str) and type(endpoint[1]) is int:
        return list(endpoint), None
    return None, "non-IP-socket-endpoint"


def stamp_original_client(report, prefix):
    report[prefix + "_wall_ns"] = time.time_ns()
    report[prefix + "_monotonic_ns"] = time.monotonic_ns()


def send_original_request(client, request, body_start, chunks):
    if not chunks:
        client.sendall(request)
        return
    client.sendall(request[:body_start])
    position = body_start
    for size in chunks:
        client.sendall(request[position:position + size])
        position += size
        time.sleep(.025)
    client.sendall(request[position:])


def read_original_response(client, profile, response):
    while len(response) <= 2 * 1024 * 1024:
        chunk = client.recv(65536)
        if not chunk:
            return "tcp-eof"
        response.extend(chunk)
        if profile.get("connection_reuse") and response_measurement(response)["complete_length_framing"]:
            return "complete-content-length"
    raise ValueError("bounded client response exceeded")


def capture_original_request(client, profile, index, neighbor, connection):
    request = cases.profile_wire(profile)
    if profile.get("connection_reuse"):
        request = request.replace(b"Connection: close", b"Connection: keep-alive")
    (ROOT / f'request-{index}.raw').write_bytes(request)
    body_start = request.find(b"\r\n\r\n") + 4
    chunks = profile.get("request_chunk_sizes", [])
    response = bytearray()
    terminal = None
    report = {"schema": "i12-spop-client-capture-v2", "pid": os.getpid(),
              "error_type": None, "error_errno": None, "error_stage": None,
              "request_send_completed_wall_ns": None, "request_send_completed_monotonic_ns": None,
              "request_send_missing_reason": None}
    for field, method in (("connection_local", "getsockname"), ("connection_peer", "getpeername")):
        report[field], report[field + "_missing_reason"] = original_client_endpoint(client, method)
    stamp_original_client(report, "started")
    stage = "request_send"
    try:
        stamp_original_client(report, "request_send_started")
        send_original_request(client, request, body_start, chunks)
        stamp_original_client(report, "request_send_completed")
        stage = "request_shutdown"
        if profile.get("raw_template") == "incomplete-body":
            client.shutdown(socket.SHUT_WR)
        stage = "response_read"
        try:
            terminal = read_original_response(client, profile, response)
        except OSError as error:
            terminal = type(error).__name__
            report.update(error_type=type(error).__name__, error_errno=error.errno, error_stage=stage)
    except (OSError, ValueError) as error:
        terminal = type(error).__name__
        report.update(error_type=type(error).__name__, error_errno=getattr(error, "errno", None), error_stage=stage)
        if report["request_send_completed_wall_ns"] is None:
            report["request_send_missing_reason"] = type(error).__name__
        raise
    finally:
        stamp_original_client(report, "completed")
        raw = bytes(response)
        (ROOT / f'response-{index}.raw').write_bytes(raw)
        record(CLIENT_FILE, {**report, "case": profile["case"], "index": index, "neighbor": neighbor,
               "connection": connection, "socket_fd": client.fileno(), "terminal": terminal,
               "request_sha256": hashlib.sha256(request).hexdigest(), "response_sha256": hashlib.sha256(raw).hexdigest(),
               "http2": False, "measurement": response_measurement(raw)})


def original_client(selected):
    profile = cases.validate_runtime(selected)
    connection = 0
    shared = None
    try:
        for index, request in enumerate(cases.source_requests(profile)):
            reuse = profile.get("connection_reuse", False)
            request = dict(request, connection_reuse=reuse)
            if shared is None:
                shared = socket.create_connection(("127.0.0.1", 18540), timeout=5)
                shared.settimeout(5)
                connection += 1
            capture_original_request(shared, request, index, False, connection)
            if not reuse:
                shared.close()
                shared = None
    finally:
        if shared is not None:
            shared.close()
    time.sleep(profile["settle_seconds"])
    port = 18544 if profile["companion_export_only"] else 18540
    with socket.create_connection(("127.0.0.1", port), timeout=5) as neighbor:
        neighbor.settimeout(5)
        capture_original_request(neighbor, cases.neighbor_profile(), "neighbor", True, connection + 1)


def wait_original_client(argv, timeout=40):
    process = None
    reaped = False
    timed_out = False
    try:
        with (source_path('client.stdout', root=ROOT)).open("wb") as out, (source_path('client.stderr', root=ROOT)).open("wb") as err:
            process = subprocess.Popen(argv, stdout=out, stderr=err)
            try:
                code = process.wait(timeout=timeout)
                reaped = True
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                process.wait()
                reaped = True
                raise
            except BaseException:
                process.kill()
                process.wait()
                reaped = True
                raise
        return code
    finally:
        code = process.returncode if process is not None else None
        record(COMMANDS_FILE, {"argv": argv, "exit": code, "reaped": reaped,
               "pid": process.pid if process is not None else None,
               "pid_missing_reason": None if process is not None else "client-launch-failed",
               "parent_pid": os.getpid(), "timed_out": timed_out,
               "signal": -code if code is not None and code < 0 else None,
               "role": "independent-client", "launcher_rtk_proxied": True})


def run_original_client():
    argv = [sys.executable, str(Path(__file__).resolve()), "--original-client"]
    if wait_original_client(argv, timeout=40):
        raise RuntimeError("independent original client failed")


def evaluate_original(selected):
    clients = read_rows(CLIENT_FILE)
    main = [row for row in clients if not row["neighbor"]]
    neighbors = [row for row in clients if row["neighbor"]]
    frames = read_rows(FRAMES_FILE)
    actions, neighbor_actions = correlated_actions(frames)
    backend_rows = read_rows(BACKEND_FILE)
    expected = selected["effective_oracle"]
    expected_rows = expected.get("requests", [expected])
    mismatches = ack_integrity_violations(frames, expected_rows)
    mismatches.extend(sample_claim_violations(frames, expected_rows))
    mismatches.extend(original_request_violations(main, expected_rows, actions))
    count = sum(not row["neighbor"] for row in backend_rows)
    if expected.get("backend_requests") is not None and count != expected["backend_requests"]:
        mismatches.append("main-backend-count")
    neighbor_ok = healthy_neighbor_matches(neighbors, backend_rows, selected["neighbor_expected"])
    mismatches.extend(neighbor_violations(neighbor_ok, neighbor_actions))
    mismatches.extend(original_scope_violations(selected, expected_rows, actions, main))
    record("expectations.jsonl", {**case_identity(selected), "expected": expected,
           "main_clients": main, "main_backend_requests": count, "healthy_neighbor": neighbor_ok,
           "ack_actions": actions, "mismatches": mismatches,
           "observation_result": observation_result(mismatches, expected),
           "full_lifecycle_pass": None, "native_physical_evidence_requires_independent_review": True,
           "companion_profile_qualified": False})


def original_request_violations(main, expected_rows, actions):
    mismatches = []
    if len(main) != len(expected_rows):
        mismatches.append("main-client-count")
    for index, (client, oracle) in enumerate(zip(main, expected_rows)):
        mismatches.extend(original_request_mismatches(index, client, oracle, actions))
    return mismatches


def original_request_mismatches(index, client, oracle, actions):
    mismatches = []
    status = oracle.get("client_status")
    if status is not None and client["measurement"]["status"] != status:
        mismatches.append(f'client-status-{index}')
    if status == 200 and (client["measurement"]["body_sha256"] != hashlib.sha256(b"BACKEND").hexdigest()
                          or not client["measurement"]["complete_length_framing"]):
        mismatches.append(f'client-body-framing-{index}')
    ack = oracle.get("ack_status")
    if ack is not None and (len(actions) <= index or actions[index].get("status") != ack):
        mismatches.append(f'ack-status-{index}')
    blocked = oracle.get("ack_blocked")
    if blocked is not None and (len(actions) <= index or actions[index].get("blocked") != blocked):
        mismatches.append(f'ack-blocked-{index}')
    return mismatches


def healthy_neighbor_matches(neighbors, backend_rows, expected):
    return (len(neighbors) == 1 and neighbors[0]["measurement"]["status"] == 200
            and neighbors[0]["measurement"]["complete_length_framing"]
            and neighbors[0]["measurement"]["body_sha256"] == expected["body_sha256"]
            and sum(row["neighbor"] for row in backend_rows) == 1)


def neighbor_violations(neighbor_ok, neighbor_actions):
    mismatches = []
    if not neighbor_ok:
        mismatches.append("healthy-neighbor")
    if len(neighbor_actions) != 1 or neighbor_actions[0].get("status") != 200 or neighbor_actions[0].get("blocked") is not False:
        mismatches.append("healthy-neighbor-ack")
    return mismatches


def original_scope_violations(selected, expected_rows, actions, main):
    mismatches = []
    if all(row.get("ack_status") is None for row in expected_rows) and not selected["effective_oracle"].get("unresolved_expected_fields") and actions:
        mismatches.append("unexpected-main-ack")
    if selected["runtime"].get("connection_reuse") and len({row["connection"] for row in main}) != 1:
        mismatches.append("connection-reuse")
    return mismatches


def observation_result(mismatches, expected):
    if mismatches:
        return "failed"
    if expected.get("unresolved_expected_fields"):
        return "unproved"
    return "passed"


def correlated_actions(frames):
    roles = {}
    main, neighbors = [], []
    for row in frames:
        frame = row["decoded"]
        key = (row["connection"], frame.get("stream"), frame.get("frame"))
        if frame.get("kind") == 3:
            arguments = [argument for message in frame.get("messages", []) for argument in message["arguments"]]
            path = next((argument["value"] for argument in arguments if argument["name"] == "path"), None)
            roles[key] = path == "/i12-neighbor"
        elif frame.get("kind") == 103:
            action = {item["name"]: item["value"] for item in frame["actions"]}
            action["wire_binding"] = {"connection": key[0], "stream": key[1], "frame": key[2],
                                      "notify_observed": key in roles}
            (neighbors if roles.get(key) else main).append(action)
    return main, neighbors


def ack_action_violations(actions):
    names = [item["name"] for item in actions]
    errors = []
    if len(names) != len(set(names)):
        errors.append("duplicate-ack-action")
    values = {item["name"]: item for item in actions}
    status = values.get("status", {})
    blocked = values.get("blocked", {})
    if status.get("tag") not in (2, 3, 4, 5) or type(status.get("value")) is not int:
        errors.append("ack-status-type")
    if blocked.get("tag") not in (1, 17) or type(blocked.get("value")) is not bool:
        errors.append("ack-blocked-type")
    if any(item.get("scope") != 2 for item in actions):
        errors.append("ack-action-scope")
    return errors


def ack_integrity_violations(frames, expected_rows):
    notified, acknowledged = set(), set()
    errors = []
    for row in frames:
        frame = row["decoded"]
        kind = frame.get("kind")
        key = (row["connection"], frame.get("stream"), frame.get("frame"))
        if kind == 3:
            if not valid_notify_envelope(frame) or row.get("direction") != "host-agent":
                errors.append("notify-envelope-or-direction")
            if key in notified:
                errors.append("duplicate-notify-identity")
            notified.add(key)
        elif kind == 103:
            errors.extend(ack_frame_violations(row, notified, acknowledged))
            acknowledged.add(key)
    main, _neighbor = correlated_actions(frames)
    if not any("ack_status" in row.get("unresolved_expected_fields", []) for row in expected_rows):
        count = sum(row.get("ack_status") is not None for row in expected_rows)
        if len(main) != count:
            errors.append("main-ack-count")
    return errors


def valid_notify_envelope(frame):
    messages = frame.get("messages", [])
    return (frame.get("flags") == 1 and bool(frame.get("stream")) and bool(frame.get("frame"))
            and len(messages) == 1 and messages[0].get("name") == "check-request")


def sample_claim_violations(frames, expected_rows):
    samples = []
    for row in frames:
        frame = row["decoded"]
        if frame.get("kind") != 3:
            continue
        messages = frame.get("messages", [])
        arguments = [item for message in messages for item in message["arguments"]]
        if any(item["name"] == "path" and item["value"] == "/i12-neighbor" for item in arguments):
            continue
        samples.append(cases.inspect_sample(arguments))
    expected_claims = [row for row in expected_rows if row.get("sample_inspection_claim") is True]
    if not expected_claims:
        return []
    if len(samples) != len(expected_rows):
        return ["main-sample-count"]
    return [f'finite-sample-claim-{index}' for index, (sample, oracle) in enumerate(zip(samples, expected_rows))
            if oracle.get("sample_inspection_claim") is True and not sample["finite_sample_complete"]]


def ack_frame_violations(row, notified, acknowledged):
    frame = row["decoded"]
    key = (row["connection"], frame.get("stream"), frame.get("frame"))
    errors = ack_action_violations(frame["actions"])
    if key not in notified:
        errors.append("orphan-ack")
    if key in acknowledged:
        errors.append("duplicate-ack-identity")
    if frame.get("flags") != 1 or not frame.get("stream") or not frame.get("frame"):
        errors.append("ack-envelope")
    if row.get("direction") != "agent-host":
        errors.append("ack-direction")
    return errors


def prepare_host_inputs(selected):
    case = selected["case"]
    original = selected.get("schema") == cases.SCHEMA
    profile = cases.validate_runtime(selected) if original else None
    with_companion = profile["with_companion"] if original else selected.get("with_companion", False)
    body_length, version, request, h2 = prepare_request(case)
    if original:
        request = cases.profile_wire(cases.source_requests(profile)[0])
    (source_path('request.raw', root=ROOT)).write_bytes(request)
    (source_path('rules.conf', root=ROOT)).write_text('''SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 1024
SecRequestBodyNoFilesLimit 1024
SecRequestBodyLimitAction Reject
SecAuditEngine On
SecAuditLog /task/native-audit.log
SecAuditLogType Serial
SecAuditLogParts ABFHZ
SecDebugLog /task/native-debug.log
SecDebugLogLevel 9
SecRule REQUEST_HEADERS:X-I12-Block "@streq yes" "id:1999501,phase:1,deny,status:403,log"
SecRule ARGS:alpha "@streq I12_BLOCK_BODY" "id:1999502,phase:2,deny,status:403,log"
''')
    (ROOT / SPOE_CONFIG_FILE).write_text(f'''[modsecurity]
spoe-agent modsecurity-agent
    groups request-check
    option var-prefix modsec
    register-var-names blocked action status redirect_url rule_id phase error response_handle
    max-frame-size 65532
    option continue-on-error
    timeout hello 1s
    timeout idle 3s
    timeout processing 2s
    use-backend be_spoa
spoe-group request-check
    messages check-request
spoe-message check-request
    args request_id=unique-id client_ip=src client_port=src_port server_ip=dst server_port=dst_port method=method path=path uri=url host=req.hdr(host) headers_bin=req.hdrs_bin headers=req.hdrs body=req.body {body_length} {version}
''')
    agent_config = '''listen=127.0.0.1:18543
log-file=/task/agent.log
decision-log=/task/decision.jsonl
rules-file=/task/rules.conf
mode=block
fail-mode=closed
runtime-mode=production
response-phases=false
spoe-timeout=2000
max-transactions=64
'''
    if with_companion:
        agent_config = agent_config.replace("response-phases=false", f'''response-phases=true
response-companion=native-htx
response-companion-socket=/task/companion.sock
response-companion-uid={os.geteuid()}
response-companion-gid={os.getegid()}
response-body-timeout=10000''')
    (source_path('agent.conf', root=ROOT)).write_text(agent_config)
    config = '''global
    nbthread 1
    log stdout format raw local0
    tune.bufsize 65536
defaults
    mode http
    timeout connect 2s
    timeout client 5s
    timeout server 5s
frontend request_only
    bind 127.0.0.1:18540
    unique-id-format %[uuid()]
    option http-buffer-request
    filter spoe engine modsecurity config /task/spoe.cfg
    http-request set-var(txn.modsec.blocked) bool(true)
    http-request send-spoe-group modsecurity request-check
    http-request deny deny_status 503 if { var(txn.modsec.blocked) -m bool }
    default_backend be_app
backend be_app
    server app 127.0.0.1:18541
backend be_spoa
    mode spop
    timeout connect 1s
    timeout server 3s
    server agent 127.0.0.1:18542
'''
    if h2:
        config = config.replace("bind 127.0.0.1:18540", "bind 127.0.0.1:18540 proto h2")
    if with_companion:
        anchor = "    http-request set-var(txn.modsec.blocked) bool(true)"
        config = config.replace(anchor, f"    filter modsecurity-htx response-companion-socket /task/companion.sock response-companion-timeout-ms 2000 response-companion-uid {os.geteuid()} response-companion-gid {os.getegid()} phase4-mode safe\n" + anchor)
    if original:
        config, spoe, agent_config = original_configuration(selected, config, (ROOT / SPOE_CONFIG_FILE).read_text(), agent_config)
        (ROOT / SPOE_CONFIG_FILE).write_text(spoe)
        (source_path('agent.conf', root=ROOT)).write_text(agent_config)
        (source_path('rules.conf', root=ROOT)).write_text(original_rules(selected))
    (source_path('haproxy.cfg', root=ROOT)).write_text(config)
    return case, original, with_companion, request, h2


def start_native_hosts(selected, children):
    for name, argv in (("agent", ["/mnt/artifacts/haproxy-spop", "--config", "/task/agent.conf"]),
                       ("host", [HOST_BINARY, "-db", "-f", "/task/haproxy.cfg"])):
        fd = os.open(ROOT / (name + "-native-api.jsonl"), os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_APPEND, 0o600)
        env = dict(os.environ, MSCONNECTOR_LIFECYCLE_FD=str(fd),
                   MSCONNECTOR_LIFECYCLE_RUN=selected["run"],
                   MSCONNECTOR_LIFECYCLE_PROFILE="haproxy-spop-request",
                   MSCONNECTOR_LIFECYCLE_CASE=case_identity(selected)["diagnostic_id"])
        with (ROOT / (name + ".stdout")).open("wb") as out, (ROOT / (name + ".stderr")).open("wb") as err:
            # The admitted Python launcher is itself executed through
            # RTK. Retain the actual native PID here for /proc identity,
            # terminal wait status and inherited observer-fd ownership.
            process = subprocess.Popen(argv, stdout=out, stderr=err, env=env, pass_fds=(fd,))
        os.close(fd)
        children.append((name, process, argv))
        time.sleep(.4)
        if process.poll() is not None:
            raise RuntimeError(name + " startup failed")
        snapshot(process, name + "-before")


def main():
    selected = json.loads(Path("/mnt/fixtures/selected.json").read_text())
    case, original, with_companion, request, h2 = prepare_host_inputs(selected)
    children = []
    stop = threading.Event()
    worker = threading.Thread(target=backend, args=(stop,), daemon=True)
    observer = None
    try:
        worker.start()
        deadline = time.monotonic() + 5
        while not (source_path('backend.ready', root=ROOT)).exists():
            if time.monotonic() > deadline:
                raise TimeoutError("backend startup")
            time.sleep(.01)
        observer = Observer(corrupt_notify=case == "corrupt-notify")
        verify_host_configuration()
        start_native_hosts(selected, children)
        if case == "technical-agent-loss":
            # This is an independent transport failure, not an invented
            # native Engine result. The host's configured default stays deny.
            _, agent, _ = children[0]
            agent.send_signal(signal.SIGTERM)
            code = agent.wait(timeout=5)
            record("faults.jsonl", {"kind": "agent-stop-before-request", "exit": code})
        if original:
            run_original_client()
        else:
            capture_response(case, request, h2)
        time.sleep(.2)
        for name, process, _ in children:
            if process.poll() is None:
                snapshot(process, name + "-after")
    finally:
        cleanup_host(children, observer, stop, worker, with_companion)
    if original:
        evaluate_original(selected)
    else:
        evaluate(selected)


if __name__ == "__main__":
    if sys.argv[1:] == ["--original-client"]:
        original_client(json.loads(Path("/mnt/fixtures/selected.json").read_text()))
    elif not sys.argv[1:]:
        main()
    else:
        raise ValueError("unsupported private driver command")
