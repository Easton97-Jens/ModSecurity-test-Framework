#!/usr/bin/env python3
"""Explicit, on-demand NGINX protocol preparation; never default-suite promotion."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import threading
import time

from modsecurity_test_framework.connector_context import load_source
from tests.runners import protocol_acceptance_contract as CONTRACT
from tests.runners.protocol_acceptance_client import build_client

HERE = Path(__file__).resolve().parent
MODERN = load_source(HERE / "run-nginx-protocol-cases.py")
HOST = MODERN.HOST
CLIENT_EVENTS = "client.jsonl"
ACCESS_EVENTS = "access.jsonl"


class Upstream(ThreadingHTTPServer):
    """A response cannot reach EOS until the coordinator observes client bytes."""

    daemon_threads = False
    block_on_close = True

    def __init__(self, scenario, paths):
        self.scenario, self.paths = scenario, paths
        self.release = threading.Event()
        self.peer_release = threading.Event()
        self.lock = threading.Lock()
        self.proof = {"paths": {}, "peer_held_until_target_observed": False,
                      "driver_error": None}
        super().__init__(("127.0.0.1", 0), Handler)

    def observe(self, row):
        if row.get("name") != "target":
            return
        if (self.scenario in {"strict", "upstream-reset"} and
                row.get("event") == "debug_observation" and row.get("debug_failure")):
            with self.lock:
                peer = self.proof["paths"].get(self.paths["peer"])
                self.proof["peer_held_until_reset_observed"] = bool(
                    peer and not peer["response_finished"] and not self.peer_release.is_set())
                self.proof["reset_observation"] = {
                    "peer_response_finished": peer["response_finished"] if peer else None,
                    "client_event_monotonic_ns": row["monotonic_ns"]}
            self.peer_release.set()
        trigger = row.get("event") == "first_data" or (
            row.get("event") == "completed" and row.get("status") == 403)
        if not trigger:
            return
        with self.lock:
            target = self.proof["paths"].get(self.paths["target"])
            if row["event"] == "first_data" and target is not None and "first_byte_observation" not in target:
                snapshot = {"observed_bytes": row.get("bytes"), "upstream_paused": not self.release.is_set(),
                            "eos_sent": target["eos_sent"], "response_finished": target["response_finished"],
                            "client_event_monotonic": row["monotonic_ns"] / 1e9,
                            "observation_monotonic": time.monotonic()}
                target["first_byte_observation"] = snapshot
                target["first_byte_observed_before_eos"] = (
                    snapshot["upstream_paused"] and not snapshot["eos_sent"] and
                    not snapshot["response_finished"] and snapshot["observed_bytes"] > 0)
            self.proof["peer_held_until_target_observed"] = True
        # Cancellation must happen with the upstream still paused. A first-data
        # callback alone is not proof of cancellation or peer isolation.
        if self.scenario != "client-cancel":
            self.release.set()
            if self.scenario not in {"strict", "upstream-reset"}:
                self.peer_release.set()

    def get_request(self):
        connection, address = super().get_request()
        # Bound header/keepalive reads so server_close cannot wait forever for
        # an owned HTTP handler after the client and NGINX have stopped.
        connection.settimeout(2)
        return connection, address


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        state = self.server
        if self.path not in state.paths.values():
            self.send_error(404)
            return
        name = next(name for name, path in state.paths.items() if path == self.path)
        row = {"arrivals": 1, "eos_sent": False, "response_finished": False,
               "first_byte_observed_before_eos": False, "write_error": None}
        with state.lock:
            if self.path in state.proof["paths"]:
                state.proof["driver_error"] = "duplicate upstream request"
            state.proof["paths"][self.path] = row
        try:
            self.write_response(name, row)
        except (BrokenPipeError, ConnectionResetError) as exc:
            if name == "target" and state.scenario in {"client-cancel", "strict", "phase3"}:
                row["expected_disconnect"] = type(exc).__name__
            else:
                row["write_error"] = type(exc).__name__
        except OSError as exc:
            row["write_error"] = str(exc)
        finally:
            row["response_finished"] = True

    def write_response(self, name, row):
        state = self.server
        first = b"acceptance-prefix-"
        tail = (b"no-crs-response-body-marker" if name == "target" and
                state.scenario in {"safe", "strict"} else b"complete")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(first) + len(tail)))
        blocked = name == "target" and state.scenario == "phase3"
        self.send_header("X-Modsec-Upstream", "block" if blocked else "allow")
        self.end_headers()
        # Peer remains active until independently observed target data/reset.
        if name == "peer" and not state.peer_release.wait(10):
            raise TimeoutError("peer barrier was not released by target observation")
        self.wfile.write(first)
        self.wfile.flush()
        row["first_chunk_written_monotonic"] = time.monotonic()
        if not self.release_target(name, row):
            return
        self.wfile.write(tail)
        self.wfile.flush()
        row["eos_sent"] = True
        row["eos_monotonic"] = time.monotonic()

    def release_target(self, name, row):
        state = self.server
        if name != "target" or state.scenario == "phase3":
            return True
        if not state.release.wait(10):
            raise TimeoutError("upstream barrier was not released by client observation")
        row["released_monotonic"] = time.monotonic()
        if state.scenario != "upstream-reset":
            return True
        row["upstream_aborted"] = True
        self.connection.shutdown(socket.SHUT_RDWR)
        self.close_connection = True
        return False

    def log_message(self, *_args):
        # Request evidence is retained in the structured upstream proof instead
        # of BaseHTTPRequestHandler's unstructured stderr access log.
        pass


def configuration(output, port, upstream, protocol, run_id, scenario):
    config = MODERN.configuration(output, port, upstream, "h3" if protocol == "h3" else "h2", run_id)
    config = config.replace('"alpn":"$ssl_alpn_protocol"',
                            '"alpn":"$ssl_alpn_protocol","connection_id":"$connection",'
                            '"transport_endpoint":"$remote_addr:$remote_port"')
    if protocol == "h2c":
        config = config.replace(f"listen 127.0.0.1:{port} ssl;", f"listen 127.0.0.1:{port};")
    if scenario == "strict":
        config = config.replace("modsecurity_phase4_mode safe;", "modsecurity_phase4_mode strict;")
    return config


def consume_client_records(buffer, rows, backend):
    """Apply each complete callback record before reading the next chunk."""
    while b"\n" in buffer:
        line, buffer = buffer.split(b"\n", 1)
        row = json.loads(line)
        rows.append(row)
        backend.observe(row)
        if row.get("event") == "cancelled" and row.get("name") == "target":
            backend.release.set()
            backend.peer_release.set()
    return buffer


def collect_client_events(process, retained, backend):
    rows = []
    deadline = time.monotonic() + 20
    buffer = b""
    total = 0
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            if time.monotonic() > deadline:
                raise TimeoutError("protocol client deadline")
            for key, _mask in selector.select(0.2):
                chunk = os.read(key.fileobj.fileno(), 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total += len(chunk)
                if total > 262144:
                    raise ValueError("protocol client output limit")
                retained.write(chunk)
                retained.flush()
                buffer = consume_client_records(buffer + chunk, rows, backend)
        if buffer:
            raise ValueError("incomplete client JSONL record")
    return rows


def execute_client(command, output, backend):
    """Observe flushed callback events; bound stdout, stderr, duration and exit."""
    with (output / CLIENT_EVENTS).open("xb") as retained, (output / "client.stderr").open("xb") as err:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=err, stdin=subprocess.DEVNULL)
        try:
            rows = collect_client_events(process, retained, backend)
            code = process.wait(timeout=2)
            if code != 0:
                raise ValueError(f"client process failed: {code}")
            if not rows:
                raise ValueError("client produced zero observations")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            process.stdout.close()
    return rows


def validate_source_selection(args):
    framework = Path(__file__).resolve().parents[4]
    if Path(args.framework_root).resolve() != framework:
        raise ValueError("Framework source selection must match the executing driver")
    for root, expected in ((framework, args.framework_sha), (HOST.BASE.PARENT_ROOT, args.parent_sha)):
        actual = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
        if actual != expected:
            raise ValueError("selected source revision does not match checkout HEAD")
    mrts = subprocess.check_output(["git", "-C", str(framework), "rev-parse", "HEAD:tools/MRTS"], text=True).strip()
    if mrts != args.mrts_sha:
        raise ValueError("MRTS revision does not match the Framework gitlink")
    return framework


def stop_runtime(process, roles, handles, port, args, backend, backend_thread):
    backend.release.set()
    backend.peer_release.set()
    cleanup = HOST.stop_owned_master(process, roles, port, args.run_id, handles)
    backend.shutdown()
    backend.server_close()
    backend_thread.join(timeout=3)
    cleanup.update(upstream_stopped=not backend_thread.is_alive(), client_stopped=True)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        try:
            udp.bind(("127.0.0.1", port))
            cleanup["udp_listener_open"] = False
        except OSError:
            cleanup["udp_listener_open"] = True
    cleanup["verified"] = cleanup["verified"] and cleanup["upstream_stopped"] and not cleanup["udp_listener_open"]
    return cleanup


def run(args):
    framework = validate_source_selection(args)
    binary, module, output = HOST.BASE.validate_inputs(args)
    spec = CONTRACT.CASES[args.case_id]
    protocol, scenario = spec["protocol"], spec["scenario"]
    os.umask(0o077)
    output.mkdir(mode=0o700)
    if MODERN.preflight(output) != 0:
        MODERN.write(output / "source-result.json", {"status": "BLOCKED", "case_id": args.case_id,
                     "run_id": args.run_id, "reason": "execution-context preflight failed"})
        return 77
    client = build_client(Path(args.curl_prefix), Path(args.client_build_root))
    artifact = {"nginx_binary": HOST.BASE.snapshot_artifact(binary, output / "nginx-binary", executable=True),
                "module": HOST.BASE.snapshot_artifact(module, output / "nginx-module.so", executable=False),
                "client_binary": HOST.BASE.snapshot_artifact(client, output / "protocol-client", executable=True)}
    rules = (framework / "tests/rules/protocol-acceptance.conf").read_text()
    if scenario in {"multiplex", "h2c"}:
        rules += '\nSecRule REQUEST_URI "@endsWith /target" "id:1100001,phase:1,deny,status:403,log,t:none,msg:\'protocol acceptance P1\'"\n'
    (output / "rules.conf").write_text(rules)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    paths = {name: f"/acceptance/{args.run_id}/{name}" for name in ("target", "peer", "followup")}
    backend = Upstream(scenario, paths)
    backend_thread = threading.Thread(target=backend.serve_forever, daemon=False)
    environment = HOST.BASE.configtest_environment(args.library_dir)
    environment.update(MSCONNECTOR_NGINX_EVENT_RUN_ID=args.run_id,
                       MSCONNECTOR_NGINX_EVENT_TRANSPORT_CASE_ID=args.case_id)
    process, roles, handles, error, packets = None, {}, {}, None, []
    backend_thread.start()
    try:
        with MODERN.tls_material(output):
            config = output / "nginx.conf"
            config.write_text(configuration(output, port, backend.server_port, protocol, args.run_id, scenario))
            (output / ACCESS_EVENTS).touch(mode=0o600)
            argv = [str(output / "nginx-binary"), "-p", str(output) + "/", "-c", str(config)]
            code, out, err, failure = HOST.BASE.invoke([*argv, "-t"], environment)
            (output / "configtest.stdout").write_bytes(out)
            (output / "configtest.stderr").write_bytes(err)
            if code or failure:
                raise ValueError("native protocol acceptance configuration rejected")
            with (output / "startup.stdout").open("xb") as stdout, (output / "startup.stderr").open("xb") as stderr:
                process = subprocess.Popen(argv, env=environment, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
                roles = HOST.observe_roles(process, args.run_id, port, output, handles)
                client_scenario = "server-reset" if scenario in {"strict", "upstream-reset"} else scenario
                command = [str(output / "protocol-client"), "--protocol", protocol,
                           "--base-url", f"{'http' if protocol == 'h2c' else 'https'}://127.0.0.1:{port}",
                           "--ca", str(output / "tls.crt"), "--scenario", client_scenario]
                for name, path in paths.items():
                    command += ["--" + ("target" if name == "target" else name) + "-path", path]
                with MODERN.QuicObserver(protocol, port) as observer:
                    execute_client(command, output, backend)
                packets = observer.rows
                if observer.error:
                    raise ValueError("QUIC metadata observer failed")
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        error = str(exc)
    finally:
        cleanup = stop_runtime(process, roles, handles, port, args, backend, backend_thread)
    backend.proof["driver_error"] = error or backend.proof["driver_error"]
    retain_bundle(output, backend, roles, cleanup, packets, args, artifact)
    return validate_result(output, args)


def retain_bundle(output, backend, roles, cleanup, packets, args, artifact):
    framework = Path(args.framework_root).resolve()
    spec = CONTRACT.CASES[args.case_id]
    for leaf in ("native-events.jsonl", ACCESS_EVENTS, CLIENT_EVENTS):
        if not (output / leaf).exists():
            (output / leaf).touch(mode=0o600)
    for leaf, value in (("upstream.json", backend.proof), ("roles.json", roles),
                        ("cleanup.json", cleanup), ("quic.json", {"datagrams": packets})):
        MODERN.write(output / leaf, value)
    leaves = (CLIENT_EVENTS, "upstream.json", ACCESS_EVENTS, "native-events.jsonl", "roles.json", "cleanup.json", "quic.json",
              "nginx.conf", "rules.conf")
    source_paths = ("tests/runners/protocol_acceptance_contract.py", "tests/runners/protocol_acceptance_client.c",
                    "tests/runners/protocol_acceptance_client.py", "tests/rules/protocol-acceptance.conf",
                    "connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-protocol-acceptance.py")
    receipt = {"schema_version": 1, "case_id": args.case_id, "run_id": args.run_id,
               "protocol": spec["protocol"], "scenario": spec["scenario"], "profile": "native-nginx-http-module",
               **{key: getattr(args, key) for key in ("parent_sha", "framework_sha", "mrts_sha")},
               "artifact_sha256": artifact,
               "source_sha256": {path: MODERN.CONTRACT.digest((framework / path).read_bytes()) for path in source_paths},
               "sha256": {leaf: MODERN.CONTRACT.digest(HOST.bounded_capture(output / leaf)) for leaf in leaves}}
    MODERN.write(output / "receipt.json", receipt)


def validate_result(output, args):
    try:
        proof = CONTRACT.validate_bundle(output, case_id=args.case_id, run_id=args.run_id,
                                         identities={key: getattr(args, key) for key in
                                                     ("parent_sha", "framework_sha", "mrts_sha")})
        result = {"status": "PASS", "case_id": args.case_id, "run_id": args.run_id,
                  "evidence_kind": "focused_host_preparation", "proof": proof}
        code = 0
    except (OSError, ValueError) as exc:
        result = {"status": "FAIL", "case_id": args.case_id, "run_id": args.run_id, "reason": str(exc)}
        code = 1
    MODERN.write(output / "source-result.json", result)
    print(json.dumps(result), flush=True)
    return code


def main():
    parser = HOST.BASE.argument_parser()
    parser.description = __doc__
    for action in parser._actions:
        if action.dest == "case_id":
            action.choices = sorted(CONTRACT.CASES)
    parser.add_argument("--framework-root", required=True)
    parser.add_argument("--curl-prefix", required=True)
    parser.add_argument("--client-build-root", required=True)
    try:
        return run(parser.parse_args())
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print("protocol acceptance input failure: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
