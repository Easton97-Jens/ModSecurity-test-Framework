#!/usr/bin/env python3
"""Run closed malformed H1 wire inputs against an owned native NGINX host.

The emitted receipt is observation only. Canonical acceptance additionally
requires strict retained-byte, identity, artifact and host-operation validation.
No synthetic Engine event is emitted for a host-core parser rejection.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import load_source

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import threading
import time

import importlib.util


def load_helper(_name, path):
    module = load_source(path)
    return module


HERE = Path(__file__).resolve().parent
HOST = load_helper("raw_h1_owned_host", HERE / "run-nginx-valid-rules.py")
BASE = HOST.BASE
NGINX_CONFIG = "nginx.conf"


def config_template(output: Path, port: int, upstream: int) -> str:
    return (
        f'load_module "{output}/nginx-module.so";\n'
        'user nobody nogroup;\nworker_processes 1;\ndaemon off;\n'
        f'pid "{output}/nginx.pid";\nerror_log "{output}/nginx-error.log" info;\n'
        'events {}\nhttp {\n'
        '  log_format raw_case escape=json \'{"method":"$request_method","uri":"$request_uri",'
        '"status":$status,"connection":"$connection","connection_requests":$connection_requests}\';\n'
        f'  access_log "{output}/access.jsonl" raw_case;\n'
        '  modsecurity on;\n'
        f'  modsecurity_rules_file "{output}/no-crs-baseline.conf";\n'
        f'  modsecurity_phase4_log "{output}/native-events.jsonl";\n'
        '  server {\n'
        f'    listen 127.0.0.1:{port};\n'
        f'    location / {{ proxy_pass http://127.0.0.1:{upstream}; }}\n'
        '  }\n}\n'
    )


def exchange(port: int, request: bytes) -> bytes:
    if not isinstance(request, bytes) or not 0 < len(request) <= 4096:
        raise ValueError("raw request must be bounded owned bytes")
    deadline = time.monotonic() + 5
    response = bytearray()
    with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
        client.sendall(request)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("raw response deadline exceeded")
            client.settimeout(remaining)
            chunk = client.recv(8192)
            if not chunk:
                return bytes(response)
            response.extend(chunk)
            if len(response) > BASE.CAPTURE_LIMIT:
                raise ValueError("raw response capture bound exceeded")


def access_for_path(raw: bytes, path: str) -> dict:
    if len(raw) > BASE.CAPTURE_LIMIT:
        raise ValueError("access log exceeds its bound")
    entries = [json.loads(line) for line in raw.splitlines() if line.strip()]
    matches = [row for row in entries if isinstance(row, dict) and row.get("uri") == path]
    if len(matches) != 1:
        raise ValueError("exactly one native access entry must bind the wire request")
    return matches[0]


class ControlUpstream(BaseHTTPRequestHandler):
    """Owned bounded positive control; no request payload or headers retained."""
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        if self.headers.get("Content-Length") != "1" or self.rfile.read(1) != b"x":
            self.send_error(400)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, format, *args):
        return


def reserve_port() -> int:
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def run(args) -> bool:
    binary, module, output = BASE.validate_inputs(args)
    if os.geteuid() != 0:
        raise ValueError("native host requires a root master and nobody worker")
    framework = BASE.absolute_path(args.framework_root)
    contract = load_helper("closed_nginx_raw_h1", framework / "tests/runners/nginx_raw_h1.py")
    wire = contract.request_bytes(args.case_id, args.run_id)
    control_run = args.run_id[:119] + "-control"
    control_wire = contract.request_bytes(args.case_id, control_run, control=True)
    environment = BASE.configtest_environment(args.library_dir)
    output.mkdir(mode=0o700)
    artifacts = {}
    artifacts["nginx-binary"] = BASE.snapshot_artifact(binary, output / "nginx-binary", executable=True)
    artifacts["nginx-module.so"] = BASE.snapshot_artifact(module, output / "nginx-module.so", executable=False)
    artifacts["no-crs-baseline.conf"] = BASE.snapshot_artifact(
        framework / "tests/rules/no-crs-baseline.conf", output / "no-crs-baseline.conf", executable=False)
    process, failure = None, None
    handles, requests = {}, {}
    roles = {"run_id": args.run_id, "master_pid": 0, "worker_pid": 0, "master_uid": -1, "worker_uid": -1}
    upstream = HTTPServer(("127.0.0.1", 0), ControlUpstream)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    port = reserve_port()
    configuration = config_template(output, port, upstream.server_port).encode()
    (output / NGINX_CONFIG).write_bytes(configuration)
    args_t = [str(output / "nginx-binary"), "-e", "stderr", "-t", "-c", str(output / NGINX_CONFIG), "-p", str(output) + "/"]
    config_exit, stdout, stderr, config_failure = BASE.invoke(args_t, environment)
    (output / "stdout.log").write_bytes(stdout)
    (output / "stderr.log").write_bytes(stderr)
    thread.start()
    try:
        if config_exit != 0 or config_failure:
            raise ValueError("actual native configuration did not load")
        with (output / "startup.stdout").open("xb") as out, (output / "startup.stderr").open("xb") as err:
            process = subprocess.Popen([str(output / "nginx-binary"), "-e", "stderr", "-c", str(output / NGINX_CONFIG),
                                        "-p", str(output) + "/"], env=environment, stdin=subprocess.DEVNULL,
                                       stdout=out, stderr=err)
            roles = HOST.observe_roles(process, args.run_id, port, output, handles)
            for label, request in (("fault", wire), ("control", control_wire)):
                (output / (label + "-request.bin")).write_bytes(request)
                response = exchange(port, request)
                (output / (label + "-response.bin")).write_bytes(response)
                requests[label] = {"client_exit_code": 0, "http_status": contract.response_status(response)}
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                access = HOST.bounded_capture(output / "access.jsonl")
                if len(access.splitlines()) >= 2:
                    break
                time.sleep(0.02)
            fault_access = access_for_path(access, contract.request_path(args.case_id, args.run_id))
            control_access = access_for_path(access, contract.request_path(args.case_id, control_run))
            errors = contract.validate_host_rejection(args.case_id, args.run_id,
                HOST.bounded_capture(output / "fault-response.bin"), fault_access,
                HOST.bounded_capture(output / "nginx-error.log"))
            if errors or requests["control"]["http_status"] != 200 or control_access.get("status") != 200:
                raise ValueError("native wire/host/control mismatch: " + "; ".join(errors))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        failure = str(exc)
    finally:
        cleanup = HOST.stop_owned_master(process, roles, port, args.run_id, handles)
        upstream.shutdown()
        upstream.server_close()
        thread.join(2)
    valid = failure is None and cleanup["verified"] and not thread.is_alive()
    for name, data in (("roles.json", roles), ("cleanup.json", cleanup)):
        HOST.write_json(output / name, data)
    for name in (NGINX_CONFIG, "stdout.log", "stderr.log", "startup.stdout", "startup.stderr", "access.jsonl",
                 "nginx-error.log", "native-events.jsonl", "fault-request.bin", "fault-response.bin",
                 "control-request.bin", "control-response.bin", "roles.json", "cleanup.json"):
        if (output / name).exists():
            artifacts[name] = BASE.digest(HOST.bounded_capture(output / name))
    receipt = {"schema_version": 1, "case_id": args.case_id, "connector": "nginx", "run_id": args.run_id,
               "operation": "native_h1_parser_rejection", "integration_mode": "native-nginx-http-module",
               "parent_sha": args.parent_sha, "framework_sha": args.framework_sha, "mrts_sha": args.mrts_sha,
               "raw_sha256": artifacts, "configtest_exit_code": config_exit, "requests": requests,
               "host_observation_valid": valid, "failure": failure, "canonical_status": "NOT_EXECUTED"}
    HOST.write_json(output / "source-result.json", receipt)
    return valid


def main() -> int:
    parser = BASE.argument_parser()
    for action in parser._actions:
        if action.dest == "case_id":
            action.choices = ("invalid_content_length", "conflicting_content_length", "duplicate_transfer_encoding", "content_length_overflow")
    parser.add_argument("--framework-root", required=True)
    args = parser.parse_args()
    try:
        return 0 if run(args) else 1
    except (OSError, ValueError) as exc:
        print("raw H1 host invocation failed: " + str(exc), file=HOST.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
