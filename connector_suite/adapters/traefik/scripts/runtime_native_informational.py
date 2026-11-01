#!/usr/bin/env python3
"""Bounded SEC-TRAEFIK-NATIVE-001 probe through the real local-plugin host.

This adapter reuses the native host's source staging, private UDS validation,
Common/libmodsecurity build, startup and cleanup contracts. It never promotes
capabilities. Evidence contains metadata only, never protected response bytes.
"""
from __future__ import annotations

import hashlib
import http.client
import http.server
import os
from pathlib import Path
import re
import shutil
import sys
import threading
import time

from modsecurity_test_framework.connector_context import ConnectorContext, framework_revision, load_tool

native = load_tool("connectors/traefik/scripts/runtime_native_smoke.py")
PROTECTED = b"SEC-TRAEFIK-NATIVE-001-protected-upstream-body\n"
ALLOW_BODY = b"informational-followup-ok\n"
P3_RULE = "1199000"
DENY_RULE = "1199001"
MAX_BODY = 65536


class InformationalResponse(native.CompletionHTTPResponse):
    """Observe each actual 1xx before letting HTTPResponse parse the final head."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.informational = []

    def _read_status(self):
        while True:
            version, status, reason = super()._read_status()
            if status < 100 or status >= 200 or status == 101:
                return version, status, reason
            if len(self.informational) >= 8:
                raise RuntimeError("too many informational responses")
            headers = http.client.parse_headers(self.fp)
            if headers.get("X-Modsec-Upstream") is not None:
                raise RuntimeError("deny marker leaked into an informational head")
            self.informational.append(status)


def handler():
    class Upstream(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            if self.headers.get("X-Native-Informational") == "103":
                self.send_response_only(103)
                self.send_header("Link", "</style.css>; rel=preload")
                self.end_headers()
                self.wfile.flush()
            deny = self.headers.get("X-Native-Response-Rule") == "block"
            body = PROTECTED if deny else ALLOW_BODY
            self.send_response(201)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            if deny:
                self.send_header("X-Modsec-Upstream", "block")
            self.end_headers()
            try:
                self.wfile.write(body)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_args):
            # Suppress request logging so the fixture emits no private request data.
            pass

    return Upstream


def validate_probe_response(response, body, transaction_id, informational, deny):
    if len(body) > MAX_BODY:
        raise RuntimeError("response exceeded bounded probe limit")
    expected = 403 if deny else 201
    if response.status != expected:
        raise RuntimeError(f"{transaction_id}: expected final {expected}, observed {response.status}")
    if response.informational != ([103] if informational else []):
        raise RuntimeError(f"{transaction_id}: expected informational head was not observed")
    if deny and body not in (b"", b"request rejected\n"):
        raise RuntimeError("P3 denial body differs from the middleware denial body")
    if deny and (PROTECTED in body or b"protected-upstream-body" in body):
        raise RuntimeError("P3 denial exposed protected upstream bytes")
    if not deny and body != ALLOW_BODY:
        raise RuntimeError("legitimate upstream response did not complete")


def require_probe_completion(connection, response, completion_socket):
    if completion_socket is not None:
        try:
            native.require_response_socket_eof(completion_socket)
        finally:
            completion_socket.close()
    elif response.will_close or connection.sock is None:
        raise RuntimeError("probe connection was not reusable")


def probe(connection, transaction_id, informational, deny, close=False):
    headers = {"X-Request-Id": transaction_id}
    if informational:
        headers["X-Native-Informational"] = "103"
    if deny:
        headers["X-Native-Response-Rule"] = "block"
    if close:
        headers["Connection"] = "close"
    connection.request("GET", "/native-informational", headers=headers)
    completion_socket = connection.sock.dup() if close else None
    response = connection.getresponse()
    body = response.read(MAX_BODY + 1)
    validate_probe_response(response, body, transaction_id, informational, deny)
    require_probe_completion(connection, response, completion_socket)
    return {"transaction_id": transaction_id, "status": response.status,
            "informational_statuses": response.informational, "response_bytes": len(body),
            "protected_body_absent": deny, "connection_reused": True,
            "physical_eof_observed": close}


def validate_correlated_evidence(artifacts, observations):
    log = (artifacts.logs_dir / native.ENGINE_STDERR_LOG_FILENAME).read_text(errors="replace")
    outcomes = native.read_host_outcomes(artifacts.event_path)
    for observation in observations:
        tid = observation["transaction_id"]
        lines = [line for line in log.splitlines() if f'[unique_id "{tid}"]' in line]
        p3 = [line for line in lines if f'[id "{P3_RULE}"]' in line]
        if len(p3) != 1:
            raise RuntimeError(f"{tid}: final P3 rule observed {len(p3)} times")
        observation["final_p3_count"] = len(p3)
        observation["p3_count_rule_id"] = P3_RULE
        if observation["status"] == 403:
            denies = [event for event in outcomes if event.get("transaction_id") == tid
                      and event.get("phase") == "response_headers"
                      and event.get("actual_action") == "deny"
                      and str(event.get("rule_id")) == DENY_RULE
                      and event.get("visible_http_status") == 403]
            if len(denies) != 1:
                raise RuntimeError(f"{tid}: missing unique correlated final P3 deny event")
            observation["deny_rule_id"] = DENY_RULE
    for name in (native.TRAEFIK_STDOUT_LOG_FILENAME, "traefik.stderr.log"):
        text = (artifacts.logs_dir / name).read_text(errors="replace")
        if re.search(r"(?i)panic|recoverer|recovered from", text):
            raise RuntimeError("unexpected recovery/panic in real Traefik host")


def wait_for_native_route(setup):
    deadline = time.monotonic() + 15
    while True:
        ready = http.client.HTTPConnection("127.0.0.1", setup.traefik_port, timeout=2)
        try:
            ready.response_class = native.CompletionHTTPResponse
            ready.request("GET", "/native-informational", headers={"X-Request-Id": "sec-traefik-native-001-readiness", "Connection": "close"})
            completion_socket = ready.sock.dup()
            response = ready.getresponse()
            body = response.read(MAX_BODY + 1)
            try:
                native.require_response_socket_eof(completion_socket)
            finally:
                completion_socket.close()
            if response.status == 201 and body == ALLOW_BODY:
                break
            if response.status != 404 or time.monotonic() >= deadline:
                raise RuntimeError(f"native route readiness returned {response.status}")
        finally:
            ready.close()
        time.sleep(0.1)


def probe_keepalive_sequence(setup, observations):
    connection = http.client.HTTPConnection("127.0.0.1", setup.traefik_port, timeout=10)
    connection.response_class = InformationalResponse
    try:
        original_socket = None
        for name, informational, deny in (("103-deny", True, True),
                ("control-deny", False, True), ("103-allow", True, False),
                ("legitimate-followup", False, False)):
            tid = "sec-traefik-native-001-" + name
            if original_socket is not None and connection.sock is not original_socket:
                raise RuntimeError("legitimate followup did not reuse the TCP connection")
            final = name == "legitimate-followup"
            observations.append(probe(connection, tid, informational, deny, close=final))
            if original_socket is None:
                original_socket = connection.sock
    finally:
        connection.close()


def run():
    context = ConnectorContext.from_environment()
    os.environ.setdefault("MSCONNECTOR_RULES_FILE", str(Path(__file__).with_name("native-informational-rules.conf")))
    inputs = native.collect_native_runtime_inputs()
    artifacts = native.stage_native_runtime(inputs)
    processes = native.NativeProcesses()
    setup = None
    socket_entries_before = set(inputs.engine_socket_parent.path.iterdir())
    observations = []
    error = None
    cleaned = False
    evidence_config = inputs.runtime_root / "evidence-config"
    evidence_config.mkdir(mode=0o700)
    config_digests = {}
    try:
        setup = native.start_native_runtime_setup(inputs, artifacts)
        # Replace only the loopback test fixture; retain the host/UDS contracts.
        setup.upstream.shutdown()
        setup.upstream.server_close()
        upstream = http.server.ThreadingHTTPServer(("127.0.0.1", setup.upstream_port), handler())
        object.__setattr__(setup, "upstream", upstream)
        thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        thread.start()
        with native.running_traefik_host(inputs, artifacts, setup, processes,
                engine_description="SEC native Common/libmodsecurity engine",
                host_description="SEC pinned Traefik local-plugin host"):
            wait_for_native_route(setup)
            probe_keepalive_sequence(setup, observations)
        if processes.traefik.poll() is not None or processes.engine.poll() is not None:
            raise RuntimeError("host or engine exited unexpectedly")
        native.stop_native_processes(processes)
        validate_correlated_evidence(artifacts, observations)
    except Exception as exc:
        error = str(exc)
    finally:
        stopped = all(native.stop_native_processes(processes))
        if setup is not None:
            setup.upstream.shutdown()
            setup.upstream.server_close()
            socket_cleaned = native.remove_private_engine_socket_dir(setup.engine_socket_dir, inputs.engine_socket_parent)
        else:
            socket_cleaned = set(inputs.engine_socket_parent.path.iterdir()) == socket_entries_before
        for source in (artifacts.static_config, artifacts.dynamic_config, artifacts.engine_config, inputs.rules_file):
            if source.is_file():
                destination = evidence_config / source.name
                shutil.copyfile(source, destination)
                destination.chmod(0o600)
                config_digests[destination.name] = hashlib.sha256(destination.read_bytes()).hexdigest()
        workspace_cleaned = native.cleanup_staged_runtime_workspaces(inputs, artifacts)
        cleaned = stopped and socket_cleaned and workspace_cleaned
    payload = {"finding": "SEC-TRAEFIK-NATIVE-001", "status": "FAIL" if error or not cleaned else "PASS",
               "connector_revision": context.revision,
               "framework_revision": framework_revision(),
               "host_version": native.traefik_version(inputs.binary),
               "host_binary_sha256": hashlib.sha256(inputs.binary.read_bytes()).hexdigest(),
               "fixture_sha256": hashlib.sha256(inputs.rules_file.read_bytes()).hexdigest(),
               "adapter_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               "evidence_config_sha256": config_digests,
               "correlation_events": "logs/events.jsonl",
               "correlation_engine_log": "logs/engine.stderr.log",
               "product_source_sha256": hashlib.sha256((context.connector / "connectors/traefik/native_middleware/middleware.go").read_bytes()).hexdigest(),
               "observations": observations, "processes_stopped": stopped,
               "socket_cleanup": socket_cleaned, "workspace_cleanup": workspace_cleaned,
               "capability_promotion": "not_permitted"}
    if error:
        payload["error"] = error
    native.write_json(artifacts.result_path, payload)
    print(f"{payload['status']}: SEC-TRAEFIK-NATIVE-001 real Traefik host")
    if error:
        print(error, file=sys.stderr)
    return 0 if payload["status"] == "PASS" else 1


def main():
    try:
        return run()
    except native.MissingDependency as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 77


if __name__ == "__main__":
    raise SystemExit(main())
