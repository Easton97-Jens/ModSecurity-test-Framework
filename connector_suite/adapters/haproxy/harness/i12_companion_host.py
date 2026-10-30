#!/usr/bin/env python3
"""Independent, loopback-only I12 companion host capture; never assigns PASS IDs.

Supply freshly source-bound observed binaries. The output records physical bytes,
backend observations, each native FD, process maps, argv/exits, and file hashes.
HTTP success alone intentionally cannot qualify a lifecycle.
"""
from __future__ import annotations
import argparse
import errno
from functools import partial
from concurrent.futures import ThreadPoolExecutor
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import struct
import connector_suite.adapters.haproxy.harness.i12_companion_cases as cases
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time

ROOT = Path("/var") / "tmp" / "codex" / "ModSecurity-conector"
TASK_ROOT = Path("/task")
FIXTURE_FILE = "fixture.json"
MRC_SOCKET = "mrc.sock"
TLS_CERT = "tls.crt"
TLS_KEY = "tls.key"
HOST_CONFIG = "haproxy.cfg"
BODY = b"companion-physical-response-body\n"
BACKEND_LISTEN_BACKLOG = 32


class CaptureBackendServer(ThreadingHTTPServer):
    request_queue_size = BACKEND_LISTEN_BACKLOG

def sha(path: Path) -> str:
    path = admitted_input(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def physical_path(path: Path, allowed_root: Path) -> Path:
    """Reject traversal and every symlink component before opening a CLI path."""
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute physical path required")
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError("symlink path component is not admitted")
    boundary_stat = allowed_root.stat()
    if boundary_stat.st_uid not in (0, os.geteuid()) or boundary_stat.st_mode & 0o022:
        raise ValueError("admitted boundary must have a trusted owner and private writes")
    resolved = path.resolve()
    resolved.relative_to(allowed_root.resolve())
    return resolved


def admitted_input(path: Path) -> Path:
    # The private controller mounts immutable artifacts and fixtures here.
    for boundary in (ROOT, Path("/mnt/artifacts"), Path("/mnt/fixtures"), TASK_ROOT):
        try:
            resolved = physical_path(path, boundary)
        except (ValueError, FileNotFoundError):
            continue
        if not resolved.is_file():
            raise ValueError("regular admitted input required")
        return resolved
    raise ValueError("input is outside admitted capture storage")

def fresh_root(path: Path, allowed_root: Path = ROOT) -> Path:
    # A caller may narrow the external boundary, never widen it.
    if allowed_root != TASK_ROOT:
        physical_path(allowed_root, ROOT)
    resolved = physical_path(path, allowed_root)
    resolved.mkdir(mode=0o700, parents=False, exist_ok=False)
    return resolved

def start_capture_thread(target, args, registry):
    """Publish only started threads so concurrent cleanup never joins a new one."""
    thread = threading.Thread(target=target, args=args, daemon=True)
    thread.start()
    registry.append(thread)
    return thread


def stop_capture_threads(workers, sockets, relays):
    """Freeze relay ownership only after every bounded accept worker has stopped."""
    for worker in workers:
        if worker.ident is not None:
            worker.join(timeout=4)
    if any(worker.is_alive() for worker in workers):
        raise RuntimeError("capture accept worker did not stop; relay ownership is not frozen")
    for sock in sockets:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
    stopped_relays = tuple(relays)
    for thread in stopped_relays:
        thread.join(timeout=1)
    if any(thread.is_alive() for thread in stopped_relays):
        raise RuntimeError("capture relay did not stop")
    return {"accept_workers_stopped": len(workers), "relays_stopped": len(stopped_relays)}


def stamp_window(report, prefix):
    report[prefix + "_wall_ns"] = time.time_ns()
    report[prefix + "_monotonic_ns"] = time.monotonic_ns()


def socket_endpoint(sock, method):
    try:
        endpoint = getattr(sock, method)()
    except OSError:
        return None
    if isinstance(endpoint, tuple) and len(endpoint) in (2, 4) and isinstance(endpoint[0], str) and type(endpoint[1]) is int:
        return list(endpoint)
    return None


def client_initial_report(index, cancel, neighbor):
    report = {"schema": "i12-companion-client-capture-v2", "kind": "client", "index": index,
              "pid": os.getpid(), "neighbor": neighbor, "cancel_requested": cancel,
              "error": None, "error_type": None, "error_errno": None, "error_stage": None,
              "kernel_tcp_reset": None, "kernel_error": None, "kernel_tcp_eof": None,
              "unwrap_error": None, "connection_local": None, "connection_peer": None,
              "request_send_started_wall_ns": None, "request_send_started_monotonic_ns": None,
              "request_send_completed_wall_ns": None, "request_send_completed_monotonic_ns": None,
              "transport_stage": "prepared"}
    stamp_window(report, "started")
    return report


def capture_client(root: Path, front: int, index: int, cancel: bool, neighbor: bool = False) -> None:
    boundary = TASK_ROOT if root.is_relative_to(TASK_ROOT) else ROOT
    root = physical_path(root, boundary)
    if not root.is_dir():
        raise ValueError("existing private client output directory required")
    report = client_initial_report(index, cancel, neighbor)
    path = "/neighbor" if neighbor else f"/i12/{index}"
    body = b"neighbor" if neighbor else b"abcdefgh"
    request = (f"POST {path} HTTP/1.1\r\nHost: companion.invalid\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    response = bytearray()
    try:
        fixture_path = root / FIXTURE_FILE
        fixture = json.loads(fixture_path.read_text()) if fixture_path.exists() else {}
        capture_client_transport(root, front, fixture, request, response, report)
    except (OSError, ValueError) as exc:
        report.update(error=type(exc).__name__ + ": " + str(exc), error_type=type(exc).__name__,
                      error_errno=getattr(exc, "errno", None), error_stage=report["transport_stage"])
        raise
    finally:
        stamp_window(report, "completed")
        report.update(length=len(response), time_ns=report["completed_wall_ns"], tls_eof=client_tls_terminal(report, cancel))
        (root / f"client-{index}.request").write_bytes(request)
        (root / f"client-{index}.response").write_bytes(response)
        (root / f"client-{index}.json").write_text(json.dumps(report) + "\n")


def client_tls_terminal(report, cancel):
    if report["error"]:
        return "exception"
    if cancel:
        return "client_cancel"
    return "close_notify"


def capture_client_transport(root, front, fixture, request, response, report):
    context = ssl.create_default_context(cafile=str(root / TLS_CERT))
    report["transport_stage"] = "connect"
    with socket.create_connection(("127.0.0.1", front), timeout=5) as connection:
        report.update(connection_local=socket_endpoint(connection, "getsockname"),
                      connection_peer=socket_endpoint(connection, "getpeername"))
        report["transport_stage"] = "tls_handshake"
        with context.wrap_socket(connection, server_hostname="localhost", suppress_ragged_eofs=False) as sock:
            report["transport_stage"] = "request_send"
            stamp_window(report, "request_send_started")
            sock.sendall(request)
            stamp_window(report, "request_send_completed")
            report["transport_stage"] = "response_read"
            capture_client_entity(sock, root, fixture, response, report)


def capture_client_entity(sock, root, fixture, response, report):
    index, cancel = report["index"], report["cancel_requested"]
    if cancel:
        response.extend(sock.recv(4096))
    else:
        report.update(capture_client_response(sock, root, index, response))
        if report["error"]:
            report["error_stage"] = "response_read"
    if cancel and fixture.get("transport") == "cancel":
        report["transport_stage"] = "client_cancel"
        raw = socket.socket(fileno=sock.detach())
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        raw.close()
    if not report["error"] and not cancel:
        report["transport_stage"] = "tls_unwrap"
        capture_client_unwrap(sock, report)


def capture_client_unwrap(sock, report):
    try:
        raw_socket = sock.unwrap()
        raw_socket.settimeout(5)
        report["kernel_tcp_eof"] = raw_socket.recv(1) == b""
        raw_socket.close()
    except OSError as exc:
        report.update(unwrap_error=type(exc).__name__ + ": " + str(exc),
                      kernel_tcp_reset=exc.errno == errno.ECONNRESET, kernel_error=repr(exc))


def capture_client_response(sock, root, index, response):
    result = {"error": None, "error_type": None, "error_errno": None,
              "kernel_tcp_reset": None, "kernel_tcp_eof": None, "kernel_error": None}
    try:
        while chunk := sock.recv(4096):
            response.extend(chunk)
            capture_first_body(root, index, response)
    except OSError as exc:
        result.update(error=type(exc).__name__ + ": " + str(exc), error_type=type(exc).__name__, error_errno=exc.errno)
        terminal = capture_kernel_terminal(sock)
        result.update(terminal)
        result["kernel_tcp_reset"] = exc.errno == errno.ECONNRESET or terminal["kernel_tcp_reset"]
    return result


def capture_kernel_terminal(tls_socket):
    result = {"kernel_tcp_eof": None, "kernel_tcp_reset": False, "kernel_error": None}
    try:
        raw = socket.socket(fileno=tls_socket.detach())
    except (OSError, ValueError) as exc:
        result["kernel_error"] = repr(exc)
        return result
    with raw:
        raw.settimeout(1)
        try:
            result["kernel_tcp_eof"] = raw.recv(1) == b""
        except OSError as exc:
            result["kernel_tcp_reset"] = exc.errno == errno.ECONNRESET
            result["kernel_error"] = repr(exc)
    return result


def capture_first_body(root, index, response):
    boundary = response.find(b"\r\n\r\n")
    signal_path = root / f"client-{index}.first-body.json"
    if boundary >= 0 and len(response) > boundary + 4 and not signal_path.exists():
        signal_path.write_text(json.dumps({"wall_ns": time.time_ns(), "monotonic_ns": time.monotonic_ns(), "received_bytes": len(response), "body_bytes": len(response) - boundary - 4}) + "\n")


def relay_bytes(proxy_stop, source, target, path):
    record = {"start_ns": time.monotonic_ns(), "received_bytes": 0, "forwarded_bytes": 0, "error": None, "end": None, "forwarded_counter_semantics": "completed sendall calls; bytes from a failed partial send are unknown"}
    with path.open("wb") as raw:
        try:
            relay_stream(proxy_stop, source, target, raw, record, path)
        except (OSError, ValueError) as exc:
            record.update(error=repr(exc), end="exception")
        try:
            target.shutdown(socket.SHUT_WR)
        except OSError as exc:
            record["shutdown_error"] = repr(exc)
    record["end_ns"] = time.monotonic_ns()
    path.with_suffix(".relay.json").write_text(json.dumps(record) + "\n")


def relay_stream(proxy_stop, source, target, raw, record, path):
    fixture_path = path.parent / FIXTURE_FILE
    fixture = json.loads(fixture_path.read_text()) if fixture_path.exists() else {}
    frame_mode = relay_frame_mode(fixture, path)
    pending = bytearray()
    with path.with_suffix(".forwarded.bin").open("wb") as forwarded:
        while not proxy_stop.is_set():
            chunk = source.recv(65536)
            if not chunk:
                record.update(end="peer_eof", trailing_frame_bytes=len(pending))
                return
            raw.write(chunk)
            raw.flush()
            record["received_bytes"] += len(chunk)
            outgoing = relay_outgoing(chunk, pending, frame_mode)
            for data in outgoing:
                observe_claim_replay(path, data, frame_mode, record)
                target.sendall(data)
                forwarded.write(data)
                forwarded.flush()
                record["forwarded_bytes"] += len(data)
        record["end"] = "capture_stop"


def relay_frame_mode(fixture, path):
    if (path.parent / "neighbor-stage").exists():
        return None
    mode = fixture.get("mrc_fault")
    if path.name.endswith("-host.bin"):
        return mode
    if mode == "claim-replay" and path.name.endswith("-owner.bin"):
        return "claim-owner"
    return None


def observe_claim_replay(path, frame, mode, record):
    prefix = path.name.rsplit("-", 1)[0]
    claim_path = path.parent / (prefix + "-claim.frame")
    if mode == "claim-replay" and frame[5] == 1:
        claim_path.write_bytes(frame)
    if mode == "claim-owner" and not record.get("claim_replay_done") and frame[5] == 128:
        record["claim_replay_done"] = True
        if len(frame) >= 24 and frame[12] == 1 and frame[13] == 0:
            probe_claim_once(path.parent, claim_path, prefix)


def probe_claim_once(root, claim_path, prefix):
    original = claim_path.read_bytes()
    response = bytearray()
    started = time.monotonic_ns()
    with connect_mrc(root) as peer:
        peer.settimeout(2)
        peer.sendall(original)
        frames = receive_mrc_result(peer, response)
    (root / (prefix + "-claim-replay.host.bin")).write_bytes(original)
    (root / (prefix + "-claim-replay.owner.bin")).write_bytes(response)
    report = {"kind": "adversarial-claim-during-held-host-transaction", "start_ns": started,
              "end_ns": time.monotonic_ns(), "source": "haproxy_spop_response_companion_backend.c:claim",
              "expected_result_code": 1, "actual_result_code": frames[0][13],
              "expected_error_code": 19, "actual_error_code": struct.unpack("!H", frames[0][18:20])[0],
              "expected_first_cause": "MSCONNECTOR_ERROR_CORRELATION_MISMATCH", "qualification": None}
    (root / (prefix + "-claim-replay.json")).write_text(json.dumps(report) + "\n")


def receive_mrc_result(peer, response):
    pending = bytearray()
    while True:
        chunk = peer.recv(65536)
        if not chunk:
            raise ValueError("claim replay peer closed before RESULT")
        response.extend(chunk)
        pending.extend(chunk)
        frames = cases.complete_mrc_frames(pending)
        if frames:
            if frames[0][5] != 128 or len(frames[0]) < 24 or frames[0][12] != 1:
                raise ValueError("claim replay returned invalid RESULT")
            return frames


def relay_outgoing(chunk, pending, frame_mode):
    if frame_mode is None:
        return (chunk,)
    pending.extend(chunk)
    return tuple(cases.mutate_outcome(frame, frame_mode) for frame in cases.complete_mrc_frames(pending))


def capture_record(observations, lock, value):
    with lock:
        observations.append(value)


def capture_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def connect_mrc(root):
    upstream = socket.socket(socket.AF_UNIX)
    upstream.connect(str(root / MRC_SOCKET))
    return upstream


def capture_accept_loop(listener, connect_upstream, prefix, directions, proxy_stop, proxy_sockets, root, proxy_threads):
    connection = 0
    while not proxy_stop.is_set():
        try:
            downstream, _ = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        upstream = connect_upstream()
        upstream.settimeout(None)  # connect deadline must not become a relay read deadline
        proxy_sockets.extend((downstream, upstream))
        connection += 1
        for source, target, direction in ((downstream, upstream, directions[0]), (upstream, downstream, directions[1])):
            start_capture_thread(relay_bytes, (proxy_stop, source, target, root / f"{prefix}-{connection}-{direction}.bin"), proxy_threads)


def backend_response_body(fixture, neighbor):
    if fixture:
        return cases.body_for(fixture, neighbor)
    return cases.NEIGHBOR if neighbor else BODY


def backend_handler(args, record):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_POST(self):
            request = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            record({"kind": "backend_request", "path": self.path, "body_hex": request.hex(), "headers": list(self.headers.items()), "time_ns": time.time_ns()})
            fixture = getattr(args, "fixture_data", {})
            neighbor = self.path == "/neighbor"
            body = backend_response_body(fixture, neighbor)
            if args.case == "expired" and not neighbor:
                time.sleep(.4)
            self.send_response(200)
            content_type = "text/plain" if neighbor else fixture.get("content_type", "text/plain")
            if content_type:
                self.send_header("Content-Type", content_type)
            self.send_header("X-Companion", "deny" if args.case.startswith("p3-") and not neighbor else "allow")
            self.send_header("X-Combined-Decision", "p3-deny" if args.case.startswith("p3-") and not neighbor else "allow")
            self.send_header("X-Modsec-Upstream", response_p3_header(args.case, neighbor))
            self.send_header("Content-Length", str(len(body) + (1 if fixture.get("transport") == "incomplete" and not neighbor else 0)))
            self.end_headers()
            if not neighbor and (args.case == "cancel" or fixture.get("transport") == "cancel"):
                self.wfile.flush()
                time.sleep(.4)
            write_backend_body(self, args, body, record, fixture, neighbor)
        def log_message(self, *_args):
            return
    return Handler


def response_p3_header(case, neighbor):
    if neighbor or not case.startswith("p3-"):
        return "allow"
    return "redirect" if case == "p3-redirect" else "block"


def write_backend_body(handler, args, body, record, fixture, neighbor):
    size = fixture.get("chunk_size", len(body) or 1)
    try:
        for offset in range(0, len(body), size):
            chunk = body[offset:offset + size]
            handler.wfile.write(chunk)
            handler.wfile.flush()
            record({"kind": "backend_chunk", "path": handler.path, "offset": offset, "bytes": len(chunk), "monotonic_ns": time.monotonic_ns()})
            if offset == 0 and fixture.get("pause_after_first") and not neighbor:
                wait_for_first_body(args.root, handler.path, record)
        record({"kind": "backend_body_finished", "path": handler.path, "bytes": len(body), "monotonic_ns": time.monotonic_ns()})
    except (BrokenPipeError, ConnectionResetError) as exc:
        record({"kind": "backend_disconnect", "path": handler.path, "error": repr(exc), "monotonic_ns": time.monotonic_ns()})
    handler.close_connection = True


def wait_for_first_body(root, path, record):
    index = int(path.rsplit("/", 1)[-1])
    signal_path = root / f"client-{index}.first-body.json"
    record({"kind": "backend_paused_before_eos", "path": path, "monotonic_ns": time.monotonic_ns()})
    deadline = time.monotonic() + 2
    while not signal_path.exists() and time.monotonic() < deadline:
        time.sleep(.01)
    record({"kind": "backend_resumed", "path": path, "client_first_body_observed": signal_path.exists(), "monotonic_ns": time.monotonic_ns()})


def capture_run(root, commands, argv, label):
    actual = ["rtk", "proxy", *map(str, argv)]
    result = subprocess.run(actual, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    (root / (label + ".stdout")).write_bytes(result.stdout)
    (root / (label + ".stderr")).write_bytes(result.stderr)
    commands.append({"label": label, "argv": actual, "exit": result.returncode})
    if result.returncode:
        raise RuntimeError(label + " failed")


def capture_start(root, args, children, commands, argv, label):
    fd = os.open(root / (label + "-native.jsonl"), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    env = dict(os.environ, MSCONNECTOR_LIFECYCLE_FD=str(fd), MSCONNECTOR_LIFECYCLE_RUN=root.name, MSCONNECTOR_LIFECYCLE_PROFILE="haproxy-spop-htx-response-companion", MSCONNECTOR_LIFECYCLE_CASE=args.case_id or args.case)
    argv = list(map(str, argv))
    # Direct subprocess ownership matches the preserved private launcher: no shell.
    with (root / (label + ".stdout")).open("wb") as out, (root / (label + ".stderr")).open("wb") as err:
        process = subprocess.Popen(argv, env=env, pass_fds=(fd,), stdout=out, stderr=err)
    os.close(fd)
    children.append((label, process))
    commands.append({"label": label, "argv": argv, "pid": process.pid})
    return process


def capture_wait_for(value, proc):
    deadline = time.monotonic() + 8
    while not value():
        if proc.poll() is not None or time.monotonic() > deadline:
            raise RuntimeError("service readiness failed")
        time.sleep(.02)


def capture_snapshot(root, children, stage):
    for label, process in children:
        proc = Path("/proc") / str(process.pid)
        (root / f"{label}-{stage}.maps").write_text((proc / "maps").read_text())
        (root / f"{label}-{stage}.status").write_text((proc / "status").read_text())
        fds = {}
        for path in (proc / "fd").iterdir():
            try:
                fds[path.name] = os.readlink(path)
            except FileNotFoundError:
                fds[path.name] = "closed_during_snapshot"
        (root / f"{label}-{stage}.fds.json").write_text(json.dumps({"pid": process.pid, "stage": stage, "wall_ns": time.time_ns(), "monotonic_ns": time.monotonic_ns(), "fds": fds}, indent=2) + "\n")


def reap_interrupted_client(process, receipt):
    process.kill()
    try:
        return process.communicate()
    finally:
        process.wait()
        receipt.update(exit=process.returncode, signal=-process.returncode if process.returncode < 0 else None, reaped=True)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def capture_client_process(root, index, argv):
    receipt = {"schema": "i12-companion-client-process-v1", "label": f"client-{index}",
               "argv": argv, "pid": None, "exit": None, "signal": None, "reaped": False,
               "timed_out": False, "launch_error": None, "communication_error": None}
    stamp_window(receipt, "started")
    stdout, stderr = b"", b""
    try:
        try:
            process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as exc:
            receipt["launch_error"] = repr(exc)
            raise
        receipt["pid"] = process.pid
        try:
            stdout, stderr = process.communicate(timeout=12)
        except BaseException as exc:
            # Match subprocess.run's ownership even for KeyboardInterrupt and
            # SystemExit; the caller receives the original exception only after
            # the actual child is terminated, drained and reaped.
            receipt["timed_out"] = isinstance(exc, subprocess.TimeoutExpired)
            if not receipt["timed_out"]:
                receipt["communication_error"] = repr(exc)
            stdout, stderr = reap_interrupted_client(process, receipt)
            raise
        finally:
            receipt.update(exit=process.returncode, signal=-process.returncode if process.returncode < 0 else None, reaped=True)
    finally:
        stamp_window(receipt, "completed")
        (root / f"client-{index}.stdout").write_bytes(stdout)
        (root / f"client-{index}.stderr").write_bytes(stderr)
        (root / f"client-{index}.process.json").write_text(json.dumps(receipt) + "\n")
    return receipt


def run_capture_client(root, front, args, commands, lock, record, index, neighbor=False):
    if neighbor:
        (root / "neighbor-stage").touch(exist_ok=False)
    if args.fixture_data:
        (root / f"client-{index}.expected.json").write_text(json.dumps(cases.source_expectation(args.fixture_data, neighbor), indent=2) + "\n")
    argv = [sys.executable, str(Path(__file__).resolve()), "--client-capture", str(root), str(front), str(index), "neighbor" if neighbor else args.case]
    process_receipt = capture_client_process(root, index, argv)
    with lock:
        commands.append(process_receipt)
    if process_receipt["exit"]:
        record({"kind": "client_process_failure", "index": index, "exit": process_receipt["exit"], "signal": process_receipt["signal"]})
        raise RuntimeError(f"client-{index} failed: {process_receipt['exit']}")
    observation = json.loads((root / f"client-{index}.json").read_text())
    if args.fixture_data:
        expected = cases.source_expectation(args.fixture_data, neighbor)
        observed = cases.response_measurements((root / f"client-{index}.response").read_bytes())
        observation.update(expected=expected, observed=observed, independent_comparison=cases.compare_response(expected, observed, cases.body_for(args.fixture_data, neighbor), observation))
    record(observation)


def cleanup_capture(children, worker, backend, proxy_stop, proxy, mrc_proxy, root, mrc_worker, proxy_worker, proxy_sockets, proxy_threads, commands, record):
    status = 0
    for name, proc in reversed(children):
        if proc.poll() is None:
            proc.send_signal(signal.SIGUSR1 if name == "host" else signal.SIGTERM)
        try:
            code = proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            code = proc.wait(timeout=3)
        commands.append({"label": name + "-wait", "exit": code, "reaped": True})
    if worker.is_alive():
        backend.shutdown()
        worker.join(timeout=3)
    backend.server_close()
    proxy_stop.set()
    proxy.close()
    mrc_proxy.close()
    (root / "mrc-tap.sock").unlink(missing_ok=True)
    try:
        record({"kind": "capture_cleanup", **stop_capture_threads((mrc_worker, proxy_worker), proxy_sockets, proxy_threads)})
    except Exception as exc:
        status = 1
        record({"kind": "capture_cleanup_error", "error": repr(exc)})
    return status


def request_spoe_directive(case):
    suffix = " if { path -m str /neighbor }" if case == "missing" else ""
    return "    http-request send-spoe-group modsecurity request-check" + suffix + "\n"


def load_fixture(path, selected_id):
    if path is None:
        return {}
    path = admitted_input(path)
    return cases.validate_fixture(json.loads(path.read_text()), selected_id)


def selected_client_cancel(root, mode):
    return mode != "neighbor" and (mode == "cancel" or client_is_cancel(root))


def client_is_cancel(root):
    boundary = TASK_ROOT if root.is_relative_to(TASK_ROOT) else ROOT
    root = physical_path(root, boundary)
    path = root / FIXTURE_FILE
    return path.exists() and json.loads(path.read_text()).get("transport") == "cancel"


def fixture_rules(fixture):
    rule_id = fixture.get("rule_id")
    scenario = fixture["scenario"]
    rule = ""
    if rule_id is not None and scenario == "p3-redirect":
        rule = f'SecRule RESPONSE_HEADERS:X-Modsec-Upstream "@streq redirect" "id:{rule_id},phase:3,redirect:https://no-crs.invalid/phase3-redirect,status:302,log"\n'
    elif rule_id is not None and scenario == "p3-deny":
        rule = f'SecRule RESPONSE_HEADERS:X-Modsec-Upstream "@streq block" "id:{rule_id},phase:3,deny,status:{fixture.get("p3_status", 403)},log"\n'
    elif rule_id is not None:
        rule = f'SecRule RESPONSE_BODY "@contains {fixture['marker']}" "id:{rule_id},phase:4,deny,status:403,log"\n'
    limit = fixture.get("native_limit", 4 * 1024 * 1024)
    mime = " ".join(cases.fixture_mime_types(fixture))
    return f"SecRequestBodyLimit {fixture.get('native_request_limit', 1024)}\nSecRequestBodyNoFilesLimit {fixture.get('native_request_limit', 1024)}\nSecRequestBodyLimitAction Reject\nSecResponseBodyMimeType {mime}\nSecResponseBodyLimit {limit}\nSecResponseBodyLimitAction {fixture.get('limit_action', 'Reject')}\n" + rule


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--neighbor", action="store_true")
    parser.add_argument("--case-id", default=None)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--host", required=True, type=Path)
    parser.add_argument("--agent", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--openssl-config", type=Path, required=True)
    parser.add_argument("--allowed-root", type=Path, default=ROOT)
    parser.add_argument("--case", choices=("p3-deny", "safe", "strict", "missing", "expired", "parallel", "cancel"), required=True)
    args = parser.parse_args()
    args.host = admitted_input(args.host)
    args.agent = admitted_input(args.agent)
    args.openssl_config = admitted_input(args.openssl_config)
    args.fixture_data = load_fixture(args.fixture, args.case_id)
    root = fresh_root(args.root, args.allowed_root)
    if args.fixture_data:
        (root / FIXTURE_FILE).write_text(json.dumps(args.fixture_data, indent=2) + "\n")
        args.case = args.fixture_data["scenario"]
    args.root = root
    if len(str(root / MRC_SOCKET)) >= 100:
        raise ValueError("MRC1 socket path must be shorter than 100 bytes")
    commands = []
    children = []
    observations = []
    lock = threading.Lock()
    record = partial(capture_record, observations, lock)
    port = capture_port
    front, spop = port(), port()
    proxy = socket.socket()
    proxy.bind(("127.0.0.1", 0))
    proxy.listen(16)
    proxy.settimeout(.1)
    proxy_stop = threading.Event()
    proxy_threads = []
    proxy_sockets = []
    proxy_loop = partial(capture_accept_loop, proxy, partial(socket.create_connection, ("127.0.0.1", spop), timeout=3), "spop", ("notify", "ack"), proxy_stop, proxy_sockets, root, proxy_threads)
    proxy_worker = threading.Thread(target=proxy_loop, daemon=True)
    # Independent private MRC1 byte tap; peer UID/GID checks remain effective.
    mrc_proxy = socket.socket(socket.AF_UNIX)
    mrc_proxy.bind(str(root / "mrc-tap.sock"))
    mrc_proxy.listen(32)
    mrc_proxy.settimeout(.1)
    mrc_loop = partial(capture_accept_loop, mrc_proxy, partial(connect_mrc, root), "mrc1", ("host", "owner"), proxy_stop, proxy_sockets, root, proxy_threads)
    mrc_worker = threading.Thread(target=mrc_loop, daemon=True)

    handler_class = backend_handler(args, record)
    backend = CaptureBackendServer(("127.0.0.1", 0), handler_class)
    worker = threading.Thread(target=backend.serve_forever, daemon=True)
    run = partial(capture_run, root, commands)
    start = partial(capture_start, root, args, children, commands)
    wait_for = capture_wait_for
    snapshot = partial(capture_snapshot, root, children)
    client = partial(run_capture_client, root, front, args, commands, lock, record)
    status = 0
    try:
        run([args.host, "-vv"], "host-identity")
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1", "-config", args.openssl_config, "-extensions", "v3_ca", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-keyout", root / TLS_KEY, "-out", root / TLS_CERT], "tls")
        (root / TLS_KEY).chmod(0o600)
        (root / "tls.pem").write_bytes((root / TLS_KEY).read_bytes() + (root / TLS_CERT).read_bytes())
        (root / "tls.pem").chmod(0o600)
        rules = "SecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess On\nSecAuditEngine On\nSecAuditLogType Serial\nSecAuditLogParts ABFHZ\n" + f"SecAuditLog {root}/native-audit.log\nSecDebugLog {root}/native-debug.log\nSecDebugLogLevel 9\n"
        if args.fixture_data:
            rules += fixture_rules(args.fixture_data)
        elif args.case == "p3-deny":
            rules += "SecResponseBodyMimeType text/plain\n"
            rules += 'SecRule RESPONSE_HEADERS:X-Companion "@streq deny" "id:1999503,phase:3,deny,status:403,log,msg:companion-P3"\n'
        else:
            rules += "SecResponseBodyMimeType text/plain\n"
            rules += 'SecRule RESPONSE_BODY "@contains companion-physical" "id:1999504,phase:4,deny,status:403,log,msg:companion-P4"\n'
        (root / "rules.conf").write_text(rules)
        ttl = 100 if args.case == "expired" else 5000
        (root / "agent.conf").write_text(f"listen=127.0.0.1:{spop}\nlog-file={root}/spoa.log\ndecision-log={root}/decision.jsonl\naudit-log={root}/audit.jsonl\nrules-file={root}/rules.conf\nmode=block\nfail-mode=closed\nruntime-mode=production\nresponse-companion=native-htx\nresponse-phases=true\nresponse-companion-socket={root}/mrc.sock\nresponse-companion-uid={os.geteuid()}\nresponse-companion-gid={os.getegid()}\nresponse-body-timeout={ttl}\nspoe-timeout=2000\nmax-transactions=64\n")
        (root / "spoe.cfg").write_text("[modsecurity]\nspoe-agent modsecurity-agent\n    groups request-check\n    option var-prefix modsec\n    register-var-names blocked action status redirect_url rule_id phase error response_handle\n    max-frame-size 65532\n    option continue-on-error\n    timeout hello 1s\n    timeout idle 3s\n    timeout processing 2s\n    use-backend be_spoa\nspoe-group request-check\n    messages check-request\nspoe-message check-request\n    args request_id=unique-id client_ip=src client_port=src_port server_ip=dst server_port=dst_port method=method path=path uri=url host=req.hdr(host) headers_bin=req.hdrs_bin headers=req.hdrs body=req.body body_len=req.body_size http_version=req.ver\n")
        send = request_spoe_directive(args.case)
        mode = args.fixture_data.get("mode", "strict" if args.case == "strict" else "safe")
        (root / HOST_CONFIG).write_text(f"global\n    nbthread 1\n    log stdout format raw local0\n    tune.bufsize 65536\ndefaults\n    mode http\n    timeout connect 2s\n    timeout client 5s\n    timeout server 5s\nfrontend combined\n    bind 127.0.0.1:{front} ssl crt {root}/tls.pem\n    unique-id-format %[uuid()]\n    option http-buffer-request\n    filter spoe engine modsecurity config {root}/spoe.cfg\n    filter modsecurity-htx response-companion-socket {root}/mrc-tap.sock response-companion-timeout-ms 2000 response-companion-uid {os.geteuid()} response-companion-gid {os.getegid()} phase4-mode {mode}\n{send}    http-request deny status 403 if {{ var(txn.modsec.blocked) -m bool }}\n    default_backend be_app\nbackend be_app\n    server app 127.0.0.1:{backend.server_port}\nbackend be_spoa\n    mode spop\n    timeout connect 1s\n    timeout server 3s\n    server agent 127.0.0.1:{proxy.getsockname()[1]}\n")
        run([args.host, "-c", "-f", root / HOST_CONFIG], "config")
        worker.start()
        proxy_worker.start()
        agent = start([args.agent, "--config", root / "agent.conf"], "agent")
        wait_for(lambda: (root / MRC_SOCKET).is_socket(), agent)
        mrc_worker.start()
        host = start([args.host, "-db", "-f", root / HOST_CONFIG], "host")
        time.sleep(.3)
        if host.poll() is not None:
            raise RuntimeError("host exited at startup")
        # Capture the actual mapped engine and host independently of caller claims.
        for name, proc in children:
            (root / (name + ".maps")).write_text(Path(f"/proc/{proc.pid}/maps").read_text())
        snapshot("before-main")
        count = args.fixture_data.get("count", 16 if args.case == "parallel" else 1)
        workers = min(count, 8) if args.fixture_data.get("parallel", args.case == "parallel") else 1
        with ThreadPoolExecutor(max_workers=workers) as executor:
            list(executor.map(client, range(count)))
        time.sleep(.2)
        snapshot("after-main")
        if args.neighbor:
            client(100, neighbor=True)
            time.sleep(.2)
            snapshot("after-neighbor")
        time.sleep(.3)
    except Exception as exc:
        status = 1
        record({"kind": "runner_error", "error": repr(exc)})
    finally:
        cleanup_status = cleanup_capture(children, worker, backend, proxy_stop, proxy, mrc_proxy, root, mrc_worker, proxy_worker, proxy_sockets, proxy_threads, commands, record)
        status = max(status, cleanup_status)
        (root / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")
        receipt = {"format": "i12-companion-private-host-v1", "case": args.case, "case_id": args.case_id, "commands": commands, "runner_exit": status, "host_sha256": sha(args.host), "agent_sha256": sha(args.agent), "runner_sha256": sha(Path(__file__)), "fixture_module_sha256": sha(Path(cases.__file__)), "full_lifecycle_pass": None, "limitation": "Physical capture only; independent oracle/lifecycle review required. Private TLS keys omitted from hash inventory.", "files": {str(p.relative_to(root)): sha(p) for p in sorted(root.rglob("*")) if p.is_file() and p.suffix not in (".key", ".pem")}}
        (root / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return status

if __name__ == "__main__":
    if len(sys.argv) == 6 and sys.argv[1] == "--client-capture":
        capture_client(Path(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), selected_client_cancel(Path(sys.argv[2]), sys.argv[5]), sys.argv[5] == "neighbor")
    else:
        raise SystemExit(main())
