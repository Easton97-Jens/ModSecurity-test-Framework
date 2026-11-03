#!/usr/bin/env python3
"""Execute closed native H2/H3 cases; force and independently observe transport."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading

from modsecurity_test_framework.connector_context import load_source
from tests.runners import nginx_protocol as CONTRACT

HERE = Path(__file__).resolve().parent
HOST = load_source(HERE / "run-nginx-valid-rules.py")


def write(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write("\n")
    path.chmod(0o600)


class QuicObserver:
    """Capture metadata only from actual packets on this loopback listener."""
    def __init__(self, protocol, port):
        self.protocol, self.port = protocol, port
        self.rows, self.error = [], None
        self.stop = threading.Event()

    def __enter__(self):
        if self.protocol == "h3":
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
            self.socket.bind(("lo", 0))
            self.socket.settimeout(0.1)
            self.thread = threading.Thread(target=self.capture, daemon=False)
            self.thread.start()
        return self

    def capture(self):
        try:
            while not self.stop.is_set():
                try:
                    frame = self.socket.recv(65536)
                except socket.timeout:
                    continue
                row = CONTRACT.quic_datagram(frame, self.port)
                if row is not None and len(self.rows) < 128:
                    self.rows.append(row)
        except OSError as exc:
            self.error = type(exc).__name__

    def __exit__(self, *args):
        if self.protocol == "h3":
            self.stop.set()
            self.thread.join(timeout=2)
            self.socket.close()
            if self.thread.is_alive():
                raise RuntimeError("owned QUIC observer did not stop")


class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"no-crs-response-body-marker" if self.path.endswith("phase4") else b"protocol allow"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Modsec-Upstream", "block" if self.path.endswith("phase3") else "allow")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.rfile.read(min(int(self.headers.get("Content-Length", "0")), 1024))
        self.do_GET()

    def log_message(self, *args):
        pass


def configuration(output, port, upstream, protocol, run_id, case_id):
    quic = f"listen 127.0.0.1:{port} quic reuseport; http3 on;" if protocol == "h3" else ""
    return (
        f'load_module "{output}/nginx-module.so";\n'
        'user nobody nogroup; worker_processes 1; daemon off;\n'
        'env MSCONNECTOR_NGINX_EVENT_RUN_ID; env MSCONNECTOR_NGINX_EVENT_TRANSPORT_CASE_ID;\n'
        f'pid "{output}/nginx.pid"; error_log "{output}/nginx-error.log";\n'
        'events {}\nhttp {\n'
        'log_format protocol escape=json \'{"uri":"$request_uri","transaction_id":"'
        f'{run_id}-$connection-$connection_requests","status":$status,'
        '"protocol":"$server_protocol","alpn":"$ssl_alpn_protocol"}\';\n'
        f'access_log "{output}/access.jsonl" protocol;\n'
        f'modsecurity on; modsecurity_rules_file "{output}/rules.conf";\n'
        f'modsecurity_transaction_id "{run_id}-$connection-$connection_requests";\n'
        'modsecurity_phase4_mode safe;\n'
        f'modsecurity_phase4_log "{output}/native-events.jsonl";\n'
        f'server {{ listen 127.0.0.1:{port} ssl; http2 on; {quic}\n'
        f'ssl_certificate "{output}/tls.crt"; ssl_certificate_key "{output}/tls.key";\n'
        'ssl_protocols TLSv1.3;\n'
        f'add_header Alt-Svc \'h3=":{port}"; ma=60\' always;\n'
        f'location / {{ proxy_pass http://127.0.0.1:{upstream}; '
        'proxy_http_version 1.1; proxy_buffering off; } } }\n'
    )


def request(args, output, environment, protocol, path, *, allow=False):
    prefix = "allow" if allow else "contract"
    headers = output / (prefix + ".headers")
    trace = output / (prefix + ".trace")
    command = [args.curl, "--noproxy", "*", "--http2-prior-knowledge" if protocol == "h2" else "--http3-only",
               "--cacert", str(output / "tls.crt"), "--verbose", "--max-time", "10",
               "--output", os.devnull, "--dump-header", str(headers), "--write-out", "%{json}"]
    if not allow and CONTRACT.CASES[args.case_id][1] == 1:
        command += ["--header", "X-Modsec-Smoke: block"]
    if not allow and CONTRACT.CASES[args.case_id][1] == 2:
        command += ["--header", "Content-Type: text/plain", "--data-binary", "no-crs-request-body-marker"]
    command += [f"https://127.0.0.1:{args.port}{path}"]
    with trace.open("xb") as stderr:
        result = subprocess.run(command, env=environment, stdout=subprocess.PIPE, stderr=stderr,
                                timeout=12, check=False)
    metrics = json.loads(result.stdout) if result.stdout else {}
    # Persist only fields used by the closed reader. Raw curl traces and header
    # files are private transient data and are removed after bounded parsing.
    trace_text = HOST.bounded_capture(trace).decode(errors="replace")
    trace_facts = "\n".join(line for line in trace_text.splitlines()
                            if "server accepted" in line or "OPENED stream" in line or ":method:" in line)
    observed = {"exit_code": result.returncode, "http_code": metrics.get("http_code"),
                "http_version": metrics.get("http_version"),
                "trace": trace_facts,
                "alt_svc_h3": b"alt-svc: h3=" in HOST.bounded_capture(headers).lower() if headers.exists() else False}
    CONTRACT.client_facts(observed, protocol)
    trace.unlink()
    headers.unlink(missing_ok=True)
    return observed


def preflight(args, output):
    command = [sys.executable, "-P", "-m", "modsecurity_connector_ci.runtime.common.hostruntime_preflight",
               "--execution-context-only", "--connector", "nginx", "--profile", "nginx-native-protocol",
               "--runtime-root", str(output), "--output-dir", str(output / "preflight"),
               "--worker-user", "nobody", "--worker-group", "nogroup", "--require-root-master", "--require-chown"]
    return subprocess.run(command, check=False, timeout=20).returncode


@contextmanager
def tls_material(output):
    """Remove task-owned TLS keys even when certificate creation fails."""
    try:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
                        "-keyout", str(output / "tls.key"), "-out", str(output / "tls.crt")],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20, check=True)
        yield
    finally:
        (output / "tls.key").unlink(missing_ok=True)
        (output / "tls.crt").unlink(missing_ok=True)


def run(args):
    binary, module, output = HOST.BASE.validate_inputs(args)
    protocol, phase, status, rule = CONTRACT.CASES[args.case_id]
    os.umask(0o077)
    output.mkdir(mode=0o700)
    # Fresh same-process-launcher preflight before any identity-dependent host.
    if preflight(args, output) != 0:
        return 77
    client = load_source(Path(args.framework_root) / "ci/checks/protocol/protocol_client.py")
    inspection = client.inspect_curl(args.curl)
    support = client.preflight_curl(protocol, inspection)
    if support.status != "READY":
        write(output / "blocked.json", {"status": "BLOCKED", "reason": support.reason})
        return 77
    artifact_hashes = {
        "binary_sha256": HOST.BASE.snapshot_artifact(binary, output / "nginx-binary", executable=True),
        "module_sha256": HOST.BASE.snapshot_artifact(module, output / "nginx-module.so", executable=False),
    }
    rules = Path(args.framework_root) / "tests/rules/no-crs-baseline.conf"
    (output / "rules.conf").write_bytes(rules.read_bytes())
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        args.port = reservation.getsockname()[1]
    # Validate library authority before acquiring sockets or a non-daemon
    # upstream thread, so a rejected directory cannot escape owned cleanup.
    environment = HOST.BASE.configtest_environment(args.library_dir)
    backend = ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    thread = threading.Thread(target=backend.serve_forever, daemon=False)
    thread.start()
    environment.update(MSCONNECTOR_NGINX_EVENT_RUN_ID=args.run_id,
                       MSCONNECTOR_NGINX_EVENT_TRANSPORT_CASE_ID=args.case_id)
    process, roles, handles, error, blocked = None, {}, {}, None, False
    path = "/no-crs/protocol/alt-svc" if rule is None else f"/no-crs/protocol/phase{phase}"
    observed, quic_rows = {}, []
    certificate = tls_material(output)
    try:
        certificate.__enter__()
        config = output / "nginx.conf"
        config.write_text(configuration(output, args.port, backend.server_port, protocol, args.run_id, args.case_id))
        (output / "access.jsonl").touch(mode=0o600)
        argv = [str(output / "nginx-binary"), "-p", str(output) + "/", "-c", str(config)]
        code, stdout, stderr, failure = HOST.BASE.invoke([*argv, "-t"], environment)
        (output / "configtest.stdout").write_bytes(stdout)
        (output / "configtest.stderr").write_bytes(stderr)
        CONTRACT.require(code == 0 and not failure, "native protocol configuration rejected")
        with (output / "startup.stdout").open("xb") as out, (output / "startup.stderr").open("xb") as err:
            process = subprocess.Popen(argv, env=environment, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
            roles = HOST.observe_roles(process, args.run_id, args.port, output, handles)
            with QuicObserver(protocol, args.port) as observer:
                allowed = request(args, output, environment, protocol, "/no-crs/protocol/allow", allow=True)
                CONTRACT.require(allowed["http_code"] == 200, "modern-protocol allow request failed")
                observed = request(args, output, environment, protocol, path)
            quic_rows = observer.rows
            CONTRACT.require(observer.error is None, "QUIC observer failed")
    except PermissionError as exc:
        error, blocked = "blocked_environment: " + str(exc), True
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        error = str(exc)
    finally:
        cleanup = HOST.stop_owned_master(process, roles, args.port, args.run_id, handles)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            try:
                udp.bind(("127.0.0.1", args.port))
                cleanup["udp_listener_open"] = False
            except OSError:
                cleanup["udp_listener_open"] = True
                cleanup["verified"] = False
        backend.shutdown()
        backend.server_close()
        thread.join(timeout=3)
        certificate.__exit__(None, None, None)
    for leaf in ("native-events.jsonl", "access.jsonl"):
        if not (output / leaf).exists():
            (output / leaf).touch(mode=0o600)
    write(output / "client.json", observed)
    write(output / "quic.json", {"datagrams": quic_rows})
    write(output / "roles.json", roles)
    write(output / "cleanup.json", cleanup)
    write(output / "observation.json", {"case_id": args.case_id, "run_id": args.run_id,
          "request_path": path, "actual_status": observed.get("http_code"), "driver_error": error})
    receipt = {"case_id": args.case_id, "run_id": args.run_id, "integration_mode": CONTRACT.MODE,
               **{key: getattr(args, key) for key in ("parent_sha", "framework_sha", "mrts_sha")},
               **artifact_hashes, "driver_sha256": CONTRACT.digest(Path(__file__).read_bytes()),
               "contract_sha256": CONTRACT.digest(Path(CONTRACT.__file__).read_bytes()),
               "rules_sha256": CONTRACT.digest(rules.read_bytes()),
               "sha256": {leaf: CONTRACT.digest(CONTRACT.read_leaf(output, leaf)) for leaf in CONTRACT.LEAVES}}
    write(output / "receipt.json", receipt)
    if blocked:
        write(output / "source-result.json", {"case_id": args.case_id, "run_id": args.run_id,
              "connector": "nginx", "integration_mode": CONTRACT.MODE, "status": "BLOCKED", "reason": error})
        return 77
    try:
        CONTRACT.require(error is None, error or "protocol host failed")
        proof = CONTRACT.validate_bundle(output, case_id=args.case_id, run_id=args.run_id)
        row = {"case_id": args.case_id, "run_id": args.run_id, "connector": "nginx",
               "integration_mode": CONTRACT.MODE, "status": "PASS", "live_executed": True,
               "actual_status": proof["actual_status"], "transaction_ids": proof["transaction_ids"],
               "protocol_bundle": str(output), "protocol_receipt_sha256": CONTRACT.digest((output / "receipt.json").read_bytes())}
        write(output / "source-result.json", row)
        return 0
    except ValueError as exc:
        write(output / "source-result.json", {"case_id": args.case_id, "run_id": args.run_id,
              "connector": "nginx", "integration_mode": CONTRACT.MODE, "status": "FAIL", "reason": str(exc)})
        print("native protocol case failed: " + str(exc), file=sys.stderr)
        return 1


def main():
    parser = HOST.BASE.argument_parser()
    parser.description = __doc__
    for action in parser._actions:
        if action.dest == "case_id":
            action.choices = sorted(CONTRACT.CASES)
    parser.add_argument("--framework-root", required=True)
    parser.add_argument("--curl", default="curl")
    try:
        return run(parser.parse_args())
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print("native protocol input failure: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
