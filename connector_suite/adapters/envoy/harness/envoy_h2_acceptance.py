#!/usr/bin/env python3
"""Opt-in real Envoy/ext_proc HTTP/2 acceptance preparation.

The small independent wire client sends literal HPACK request headers and never
decodes or stores response bodies. Native Envoy access logs establish status and
connection identity; Common and service completion logs establish rule/lifecycle
identity. No HTTP/1 client or protocol fallback is used.
"""
from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time


CASES = ("allow", "phase1", "phase2", "phase3", "phase4_safe", "client_cancel", "upstream_reset")
STRICT_CASE = "phase4_strict"
MAX_LOG = 16 * 1024 * 1024

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from tests.runners.native_h2_probe import WireClient, frame, hpack_string, request_headers


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_text(path: Path) -> str:
    require(path.is_absolute(), "absolute evidence path required")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:-1]:
            require(component not in ("", ".", ".."), "unsafe evidence component")
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        try:
            metadata = os.fstat(descriptor)
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid() and metadata.st_nlink == 1,
                    "evidence must be an owned regular single-link file")
            require(metadata.st_size <= MAX_LOG, "oversize evidence")
            content = bytearray()
            while len(content) <= MAX_LOG:
                chunk = os.read(descriptor, min(65536, MAX_LOG + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
            require(len(content) <= MAX_LOG, "evidence grew beyond bound")
            return content.decode("utf-8")
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def unique_object(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def load_json(value: str):
    def reject_constant(_value):
        raise ValueError("non-finite JSON number")
    return json.loads(value, object_pairs_hook=unique_object, parse_constant=reject_constant)


def read_records(path: Path) -> list[dict]:
    text = read_text(path)
    require(not text or text.endswith("\n"), "incomplete native JSONL writer record")
    records = [load_json(line) for line in text.splitlines() if line]
    require(all(isinstance(record, dict) for record in records), "non-object JSONL evidence")
    return records


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    path.chmod(0o600)


class Fixture(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, output: Path):
        super().__init__(address, Handler)
        self.output = output
        self.lock = threading.Lock()
        self.handlers = set()
        self.peer_release = threading.Event()
        self.target_release = threading.Event()
        self.peer_started = threading.Event()
        self.target_paused = threading.Event()

    def process_request_thread(self, request, client_address):
        current = threading.current_thread()
        with self.lock:
            self.handlers.add(current)
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.lock:
                self.handlers.discard(current)

    def record(self, event: str, transaction: str, **values) -> None:
        with self.lock, self.output.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"event": event, "transaction_id": transaction,
                                     "monotonic_ns": time.monotonic_ns(), **values}) + "\n")


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args) -> None:
        pass

    def do_GET(self) -> None:
        fixture = self.server
        transaction = self.headers.get("x-acceptance-id", "")
        count = int(self.headers.get("content-length", "0"))
        require(0 <= count <= 1024, "invalid fixture request size")
        self.rfile.read(count)
        fixture.record("upstream_request", transaction, request_body_bytes=count)
        role = self.path.rsplit("/", 1)[-1]
        case = self.path.split("/")[1]
        marker = b"no-crs-response-body-marker" if case in ("phase4_safe", STRICT_CASE) and role == "target" else b"end\n"
        held = role == "peer" or (role == "target" and case in ("phase4_safe", STRICT_CASE, "client_cancel", "upstream_reset"))
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("transfer-encoding", "chunked")
        if case == "phase3" and role == "target":
            self.send_header("x-modsec-upstream", "block")
        self.end_headers()
        try:
            self.wfile.write(b"6\r\nfirst\n\r\n")
            self.wfile.flush()
            if held:
                event = fixture.peer_release if role == "peer" else fixture.target_release
                (fixture.peer_started if role == "peer" else fixture.target_paused).set()
                fixture.record("upstream_paused", transaction, eos_sent=False)
                require(event.wait(10), "fixture release deadline exceeded")
            if role == "target" and case == "upstream_reset":
                fixture.record("upstream_abort", transaction, eos_sent=False)
                self.connection.shutdown(socket.SHUT_RDWR)
                self.close_connection = True
                return
            self.wfile.write(f"{len(marker):X}\r\n".encode() + marker + b"\r\n0\r\n\r\n")
            self.wfile.flush()
            fixture.record("upstream_eos", transaction, eos_sent=True)
        except (BrokenPipeError, ConnectionResetError):
            fixture.record("upstream_disconnected", transaction)

    do_POST = do_GET


def validate_case(case: str, wire: dict, access: list[dict], completion: list[dict], common: list[dict]) -> dict:
    require(case in (*CASES, STRICT_CASE), "unknown opt-in case")
    require(wire.get("alpn") == "h2" and wire.get("tls_verified") is True
            and wire.get("tls_version") == "TLSv1.3", "independent TLS/H2 proof missing")
    ids = {role: f"envoy-h2-{case}-{role}" for role in ("peer", "target", "followup")}
    requests = wire.get("requests", [])
    require(len(requests) == 3 and {row.get("stream_id") for row in requests} == {1, 3, 5}, "missing/duplicate actual wire requests")
    for role, stream in (("peer", 1), ("target", 3), ("followup", 5)):
        request = next(row for row in requests if row["stream_id"] == stream)
        size = 26 if role == "target" and case == "phase2" else 0
        require(request.get("transaction_id") == ids[role] and request.get("path") == f"/{case}/{role}"
                and request.get("body_bytes") == size and request.get("method") == ("POST" if size else "GET"),
                "wire request entity/identity mismatch")
    bodies = wire.get("body_bytes", {})
    require(bodies.get("1") == bodies.get("5") == 10, "peer/followup response incomplete")
    expected_body = 33 if case in ("phase4_safe", STRICT_CASE) else (6 if case in ("client_cancel", "upstream_reset") else (10 if case == "allow" else 0))
    require(bodies.get("3", 0) == expected_body, "target response body accounting mismatch")
    selected = {}
    for role, transaction in ids.items():
        native = [record for record in access if record.get("transaction_id") == transaction]
        done = [record for record in completion if record.get("transaction_id") == transaction]
        require(len(native) == 1 and len(done) == 1, f"{case}/{role}: native/completion uniqueness failed")
        require(native[0].get("protocol") == "HTTP/2", f"{case}/{role}: native protocol is not HTTP/2")
        require(done[0].get("rule_evaluation") == "libmodsecurity", "non-native evaluator")
        expected_close = "response_end_of_stream"
        if role == "target":
            expected_close = ("request_immediate_response" if case in ("phase1", "phase2", "phase3") else
                              "late_immediate_response" if case == STRICT_CASE else
                              "grpc_context_canceled_unattributed" if case in ("client_cancel", "upstream_reset") else expected_close)
        require(done[0].get("close_reason") == expected_close, "unexpected native completion lifecycle")
        selected[role] = {"native": native[0], "completion": done[0]}
    require(len({str(value["native"]["connection_id"]) for value in selected.values()}) == 1, "physical connection changed")
    require(len({str(value["native"]["stream_id"]) for value in selected.values()}) == 3, "native stream identity reused")
    for role in ("peer", "followup"):
        require(str(selected[role]["native"]["status"]) == "200", f"{role} did not survive")
    for role, stream in (("peer", 1), ("target", 3), ("followup", 5)):
        require(wire.get("status", {}).get(str(stream)) == int(selected[role]["native"]["status"]),
                f"{case}/{role}: independent wire/native HTTP status mismatch")
    expected = 403 if case in ("phase1", "phase2", "phase3") else 200
    require(str(selected["target"]["native"]["status"]) == str(expected), "wrong target status")
    rules = {"phase1": 1100001, "phase2": 1100101, "phase3": 1100201, "phase4_safe": 1100301, STRICT_CASE: 1100301}
    if case in rules:
        phase = {"phase1": "request_headers", "phase2": "request_body", "phase3": "response_headers"}.get(case, "response_body")
        decisions = [record for record in common if record.get("transaction_id") == ids["target"]
                     and record.get("event") == "engine_decision"]
        require(len(decisions) == 1 and str(decisions[0].get("rule_id")) == str(rules[case])
                and decisions[0].get("phase") == phase and decisions[0].get("http_status") == 403
                and decisions[0].get("requested_action") == "deny", f"{case}: native decision correlation missing/duplicated")
    terminal = wire["terminal"]
    barriers = [record for record in wire.get("frames", []) if record.get("type") == "native_completion_observed"]
    require(len(barriers) == 1 and barriers[0].get("transaction_id") == ids["target"]
            and barriers[0].get("peer_held") is True, "target cleanup was not observed with TLS/peer still active")
    for stream in (1, 5):
        require(terminal.get(str(stream), {}).get("type") in (0, 1)
                and terminal[str(stream)].get("flags", 0) & 1, "unrelated stream incomplete/reset")
    if case != "client_cancel":
        require("3" in terminal, "missing wire target terminal")
    if case not in (STRICT_CASE, "upstream_reset", "client_cancel"):
        require(terminal["3"].get("type") in (0, 1) and terminal["3"].get("flags", 0) & 1,
                "normal target did not finish with END_STREAM")
    if case in ("phase4_safe", STRICT_CASE, "client_cancel", "upstream_reset"):
        first = [row for row in wire.get("frames", []) if row.get("type") == "first_byte_before_eos"]
        require(len(first) == 1 and first[0].get("peer_held") is True and first[0].get("target_eos_held") is True,
                "first-byte/EOS barrier missing")
        data = [row for row in wire.get("frames", []) if row.get("type") == 0 and row.get("stream_id") == 3 and row.get("size", 0) > 0]
        require(data and 0 < data[0].get("monotonic_ns", 0) <= first[0].get("monotonic_ns", 0)
                < barriers[0].get("monotonic_ns", 0), "first DATA/native cleanup chronology missing")

    if case == "client_cancel":
        cancellations = [row for row in wire.get("frames", []) if row.get("type") == "client_rst_stream"]
        require(len(cancellations) == 1 and cancellations[0].get("stream_id") == 3 and cancellations[0].get("reset_code") == 8,
                "actual client cancellation missing")
        require(barriers[0].get("target_eos_held") is True, "upstream EOS released before cancellation cleanup")
        require(selected["target"]["completion"].get("close_reason") == "grpc_context_canceled_unattributed",
                "native completion did not follow cancellation")
    if case == "upstream_reset":
        require(terminal["3"]["type"] == 3 and terminal["3"].get("reset_code") == 2, "missing server RST_STREAM")
    if case == "phase4_safe":
        require(selected["target"]["completion"]["late_action"] == "log_only", "Safe did not log late P4")
        require(selected["target"]["completion"]["close_reason"] == "response_end_of_stream", "Safe did not finish at EOS")
    if case == "phase2":
        require(selected["target"]["completion"]["request_body_bytes"] == len(b"no-crs-request-body-marker"),
                "P2 did not evaluate the actual bounded request entity")
    if case == STRICT_CASE:
        require(terminal["3"]["type"] == 3 and terminal["3"].get("reset_code") == 2, "Strict did not produce server RST_STREAM")
        require(selected["target"]["completion"]["late_action"] == "strict_immediate_response_sent", "Strict native action not sent")
        require(selected["target"]["native"]["details"] == "msconnector-ext-proc-late-decision", "Strict native action correlation missing")
    return {"case_id": f"envoy_h2_{case}", "status": "PASS", "transactions": selected}


def exercise(port: int, ca: Path, root: Path, fixture: Fixture, case: str) -> None:
    for event in (fixture.peer_release, fixture.target_release, fixture.peer_started, fixture.target_paused):
        event.clear()
    client = WireClient(port, ca, root / f"wire-{case}.json")
    try:
        client.request(1, f"/{case}/peer", f"envoy-h2-{case}-peer")
        client.wait(lambda: client.bytes.get(1, 0) > 0 and fixture.peer_started.is_set())
        client.request(3, f"/{case}/target", f"envoy-h2-{case}-target",
                       b"no-crs-request-body-marker" if case == "phase2" else b"", case == "phase1")
        if case in ("phase4_safe", STRICT_CASE, "client_cancel", "upstream_reset"):
            client.wait(lambda: client.bytes.get(3, 0) > 0 and fixture.target_paused.is_set())
            require(3 not in client.terminal and 1 not in client.terminal, "first byte/EOS barrier failed")
            client.records.append({"type": "first_byte_before_eos", "peer_held": True, "target_eos_held": True,
                                   "monotonic_ns": time.monotonic_ns()})
            if case == "client_cancel":
                client.socket.sendall(frame(3, 0, 3, struct.pack("!I", 8)))
                client.records.append({"type": "client_rst_stream", "stream_id": 3, "reset_code": 8,
                                       "monotonic_ns": time.monotonic_ns()})
            else:
                fixture.target_release.set()
        if case != "client_cancel":
            client.wait(lambda: 3 in client.terminal)
        require(1 not in client.terminal, "held peer ended before target terminal")
        deadline = time.monotonic() + 3
        while True:
            require(time.monotonic() < deadline, "target native cleanup did not finish while peer remained active")
            try:
                records = read_records(root / "completion.jsonl")
            except (FileNotFoundError, json.JSONDecodeError):
                records = []
            target = [record for record in records if record.get("transaction_id") == f"envoy-h2-{case}-target"]
            require(len(target) <= 1, "duplicate target cleanup")
            if target:
                break
            client.poll()
        require(1 not in client.terminal and not fixture.peer_release.is_set(), "peer released before target cleanup")
        client.records.append({"type": "native_completion_observed", "transaction_id": f"envoy-h2-{case}-target",
                               "peer_held": True, "target_eos_held": not fixture.target_release.is_set(), "monotonic_ns": time.monotonic_ns()})
        fixture.target_release.set()
        fixture.peer_release.set()
        client.wait(lambda: 1 in client.terminal)
        client.request(5, f"/{case}/followup", f"envoy-h2-{case}-followup")
        client.wait(lambda: 5 in client.terminal)
    finally:
        fixture.target_release.set()
        fixture.peer_release.set()
        client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector-root", type=Path, required=True)
    parser.add_argument("--framework-root", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--envoy", type=Path, required=True)
    parser.add_argument("--service", type=Path, required=True)
    parser.add_argument("--connector-revision", required=True)
    parser.add_argument("--framework-revision", required=True)
    parser.add_argument("--late-action-policy", choices=("safe", "strict"), default="safe")
    parser.add_argument("--case", choices=(*CASES, STRICT_CASE))
    args = parser.parse_args()
    cases = (args.case,) if args.case else ((STRICT_CASE,) if args.late_action_policy == "strict" else CASES)
    require(all((case == STRICT_CASE) == (args.late_action_policy == "strict") for case in cases),
            "case and explicit late-action policy disagree")
    root = args.runtime_root.resolve()
    require(not root.exists(), "runtime root must be fresh")
    require(root.is_relative_to(Path("/var/tmp/codex")), "external task runtime required")
    root.mkdir(mode=0o700, parents=True)
    processes = []
    ports = []
    fixture = None
    thread = None
    report = {"profile": "envoy-ext-proc-h2", "results": [], "status": "FAIL", "cleanup": "NOT_RUN"}
    try:
        env = os.environ.copy()
        for checkout, revision in ((args.connector_root, args.connector_revision), (args.framework_root, args.framework_revision)):
            require(len(revision) == 40 and all(c in "0123456789abcdef" for c in revision), "exact source revision required")
            require(subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip() == revision,
                    "source HEAD differs from selected revision")
        env.update(TEST_ROOT=str(args.framework_root), CONNECTOR_ROOT=str(args.connector_root),
                   CONNECTOR_REVISION=args.connector_revision, FRAMEWORK_REVISION=args.framework_revision,
                   PYTHONPATH=f"{args.framework_root}:{args.framework_root / 'connector_suite'}")
        report["source_revisions"] = {"parent": args.connector_revision, "framework": args.framework_revision}
        preflight = [sys.executable, "-P", "-m", "modsecurity_connector_ci.runtime.common.hostruntime_preflight",
                     "--execution-context-only", "--connector", "envoy", "--profile", "envoy-ext-proc-h2",
                     "--runtime-root", str(root), "--output-dir", str(root / "preflight")]
        subprocess.run(preflight, env=env, check=True, stdout=(root / "preflight.log").open("wb"), stderr=subprocess.STDOUT)
        version = subprocess.check_output([str(args.envoy), "--version"], text=True)
        pin = (args.connector_root / "connectors/envoy/config/envoy-ext-proc-versions.env").read_text()
        release = next(line.split("=", 1)[1] for line in pin.splitlines() if line.startswith("ENVOY_RELEASE="))
        require(f"/{release}/" in version, "Envoy version mismatch")
        cert, key = root / "tls.crt", root / "tls.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
                        "-keyout", str(key), "-out", str(cert)], check=True,
                       stdout=subprocess.DEVNULL, stderr=(root / "certificate.log").open("wb"))
        key.chmod(0o600)
        fixture = Fixture(("127.0.0.1", 0), root / "upstream.jsonl")
        ports.append(fixture.server_port)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        fixture.socket = context.wrap_socket(fixture.socket, server_side=True)
        thread = threading.Thread(target=fixture.serve_forever, daemon=True)
        thread.start()
        def port():
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                return listener.getsockname()[1]
        listen, service_port, admin = port(), port(), port()
        ports.extend((listen, service_port, admin))
        config = root / "envoy.yaml"
        env.update(OUTPUT_CONFIG=str(config), BUILD_ROOT=str(root / "build"), LISTEN_PORT=str(listen),
                   UPSTREAM_PORT=str(fixture.server_port), EXT_PROC_PORT=str(service_port), ADMIN_PORT=str(admin),
                   TLS_CERTIFICATE=str(cert), TLS_PRIVATE_KEY=str(key), EXT_PROC_DOWNSTREAM_PROTOCOL="h2")
        subprocess.run(["sh", str(args.connector_root / "connectors/envoy/config/prepare_envoy_ext_proc_config.sh")],
                       env=env, check=True, stdout=subprocess.DEVNULL)
        content = config.read_text()
        access_log = root / "access.jsonl"
        insert = '''          access_log:
          - name: envoy.access_loggers.file
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
              path: ACCESS_PATH
              log_format:
                json_format:
                  transaction_id: "%REQ(X-ACCEPTANCE-ID)%"
                  protocol: "%PROTOCOL%"
                  connection_id: "%CONNECTION_ID%"
                  stream_id: "%STREAM_ID%"
                  status: "%RESPONSE_CODE%"
                  flags: "%RESPONSE_FLAGS%"
                  details: "%RESPONSE_CODE_DETAILS%"
'''.replace("ACCESS_PATH", json.dumps(str(access_log)))
        require(content.count("          stat_prefix:") == 1, "unexpected native HCM template")
        config.write_text(content.replace("          stat_prefix:", insert + "          stat_prefix:"))
        runtime = root / "common.conf"
        env.update(OUTPUT_CONFIG=str(runtime), RULES_FILE=str(args.framework_root / "tests/rules/no-crs-baseline.conf"),
                   EVENT_PATH=str(root / "common.jsonl"), ENVOY_EXT_PROC_PHASE4_MODE=args.late_action_policy)
        subprocess.run(["sh", str(args.connector_root / "connectors/envoy/config/prepare_envoy_ext_proc_runtime_config.sh")],
                       env=env, check=True, stdout=subprocess.DEVNULL)
        service_config = json.loads((args.connector_root / "connectors/envoy/config/envoy-ext-proc-service.json").read_text())
        service_config.update(listen_address=f"127.0.0.1:{service_port}", transaction_id_header="x-acceptance-id", late_action_policy=args.late_action_policy)
        write_json(root / "service.json", service_config)
        subprocess.run([str(args.envoy), "--mode", "validate", "-c", str(config), "--disable-hot-restart"],
                       check=True, stdout=(root / "validate.log").open("wb"), stderr=subprocess.STDOUT)
        def start(name, command, child_env):
            log = (root / f"{name}.log").open("wb")
            process = subprocess.Popen(command, env=child_env, stdout=log, stderr=subprocess.STDOUT)
            log.close()
            processes.append((name, process))
        service_env = env | {"EXT_PROC_BIN": str(args.service), "EXT_PROC_CONFIG": str(root / "service.json"),
                             "EXT_PROC_RUNTIME_CONFIG": str(runtime), "EVENT_LOG_PATH": str(root / "completion.jsonl"),
                             "LISTEN_ADDRESS": "127.0.0.1", "LISTEN_PORT": str(service_port)}
        start("service", ["sh", str(args.connector_root / "connectors/envoy/scripts/serve_envoy_ext_proc.sh")], service_env)
        start("envoy", [str(args.envoy), "-c", str(config), "--disable-hot-restart", "--concurrency", "2", "--log-level", "error"], env)
        for _ in range(50):
            require(all(process.poll() is None for _, process in processes), "host process exited")
            try:
                with socket.create_connection(("127.0.0.1", listen), 0.1):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise ValueError("host readiness listener missing")
        for case in cases:
            exercise(listen, cert, root, fixture, case)
        # A fixed sleep is not a native writer-flush barrier. Reap our actual
        # host children first; Envoy flushes its file access logger on shutdown.
        for _, process in reversed(processes):
            require(process.poll() is None, "host process exited during traffic")
            process.terminate()
            process.wait(timeout=7)
            require(process.returncode == 0, "host writer/shutdown failed")
        access, completions, common = read_records(access_log), read_records(root / "completion.jsonl"), read_records(root / "common.jsonl")
        expected_ids = {f"envoy-h2-{case}-{role}" for case in cases for role in ("peer", "target", "followup")}
        require(len(access) == len(completions) == len(expected_ids), "native result count mismatch")
        require({record.get("transaction_id") for record in access} == expected_ids, "foreign or missing native transaction")
        require({record.get("transaction_id") for record in completions} == expected_ids, "foreign or missing completion")
        require(all(record.get("transaction_id") in expected_ids for record in common), "foreign Common transaction")
        for case in cases:
            report["results"].append(validate_case(case, load_json(read_text(root / f"wire-{case}.json")), access, completions, common))
        report["status"] = "PASS"
        report["late_action_policy"] = args.late_action_policy
        report["artifact_hashes"] = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                                     for path in (args.envoy, args.service, config, runtime)}
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
    finally:
        if fixture is not None:
            fixture.peer_release.set()
            fixture.target_release.set()
        for _, process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=7)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        if fixture is not None:
            fixture.shutdown()
            fixture.server_close()
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                with fixture.lock:
                    handlers = list(fixture.handlers)
                if not handlers:
                    break
                for handler in handlers:
                    handler.join(timeout=min(0.1, max(0, deadline - time.monotonic())))
        if thread is not None:
            thread.join(timeout=3)
        for name in ("tls.key", "tls.crt"):
            (root / name).unlink(missing_ok=True)
        port_status = {}
        for number in ports:
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    listener.bind(("127.0.0.1", number))
                    port_status[str(number)] = "released"
                except OSError:
                    port_status[str(number)] = "in_use"
        report["cleanup_evidence"] = {"process_returncodes": {name: process.returncode for name, process in processes},
            "ports": port_status, "active_upstream_handlers": len(fixture.handlers) if fixture else 0,
            "private_tls_removed": not (root / "tls.key").exists() and not (root / "tls.crt").exists()}
        report["cleanup"] = "PASS" if all(p.poll() is not None for _, p in processes) and (thread is None or not thread.is_alive()) and not (fixture and fixture.handlers) and all(value == "released" for value in port_status.values()) else "FAIL"
        if report["cleanup"] != "PASS":
            report["status"] = "FAIL"
        write_json(root / "report.json", report)
    print(json.dumps({"status": report["status"], "report": str(root / "report.json"), "cases": len(report["results"])}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
