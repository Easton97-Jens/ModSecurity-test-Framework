#!/usr/bin/env python3
"""Real NGINX I12 observations in the sealed controller; no PASS synthesis."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import load_source

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import threading
import time

from modsecurity_connector_ci.runtime.lifecycle.i12.nginx.scenarios import cases, serializable


CASE_ID_PREFIX = "I12::nginx-native::"
EVENT_RUN_ID = "MSCONNECTOR_NGINX_EVENT_RUN_ID"
EVENT_CASE_ID = "MSCONNECTOR_NGINX_EVENT_TRANSPORT_CASE_ID"


def event_provenance(run_id, selected_id):
    """Bind trusted controller identities; HTTP headers never supply these."""
    values = {EVENT_RUN_ID: run_id, EVENT_CASE_ID: selected_id}
    for key, value in values.items():
        if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value) is None:
            raise ValueError("invalid trusted event provenance token: " + key)
    return values


def storage_root():
    """Require the configured private project anchor, with no temp fallback."""
    value = os.environ.get("CODEX_TEMP_ROOT", "")
    match = re.fullmatch(r"/[A-Za-z0-9_./-]+", value)
    if match is None:
        raise ValueError("canonical CODEX_TEMP_ROOT required")
    root = Path(match.group(0))
    if (str(root) != value or root != root.resolve() or root == Path("/") or
            ".." in root.parts):
        raise ValueError("canonical CODEX_TEMP_ROOT required")
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022):
        raise ValueError("private root-owned CODEX_TEMP_ROOT required")
    return root


def client_environment(parser_environment):
    """Pass only the validated storage anchor alongside the filtered host env."""
    return {**parser_environment, "CODEX_TEMP_ROOT": str(storage_root())}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(_name, path):
    module = load_source(path)
    return module


class Backend(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def bounded_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 <= length <= 4 * 1024 * 1024:
            raise ValueError("bounded backend entity required")
        return self.rfile.read(length)

    def response_details(self, body):
        selected = self.path.endswith("/selected")
        row = self.server.fixture
        response = row["response"] if selected else b"NGXI12_RSP neighbor healthy\n"
        item = {"path": self.path, "body_bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest(),
                "response_bytes": len(response), "response_sha256": hashlib.sha256(response).hexdigest(),
                "request_transaction": self.headers.get("X-I12-Transaction"),
                "received_monotonic_ns": time.monotonic_ns(), "writes": []}
        return selected, row, response, item

    def send_backend_headers(self, selected, row, response):
        self.send_response(200)
        content_type = row["response_type"] if selected else "text/plain"
        if content_type:
            self.send_header("Content-Type", content_type)
        if selected and row.get("response_header"):
            self.send_header("X-Modsec-Upstream", row["response_header"])
        chunked = selected and row["chunked"]
        self.send_header("Transfer-Encoding" if chunked else "Content-Length", "chunked" if chunked else str(len(response)))
        self.send_header("Connection", "close")
        self.end_headers()

    def write_backend_response(self, response, parts, chunked, item):
        for index in range(parts):
            data = response[index * len(response) // parts:(index + 1) * len(response) // parts]
            if chunked and data:
                self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
            elif not chunked:
                self.wfile.write(data)
            self.wfile.flush()
            item["writes"].append({"bytes": len(data), "returned_monotonic_ns": time.monotonic_ns()})
            if parts > 1:
                time.sleep(0.08)
        if chunked:
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()

    def do_POST(self):
        body = self.bounded_body()
        selected, row, response, item = self.response_details(body)
        self.send_backend_headers(selected, row, response)
        chunked = selected and row["chunked"]
        parts = row["response_parts"] if selected else 1
        try:
            self.write_backend_response(response, parts, chunked, item)
            item["write_completed"] = True
        except OSError as exc:
            item["write_completed"] = False
            item["write_error"] = type(exc).__name__
        finally:
            item["finished_monotonic_ns"] = time.monotonic_ns()
            self.server.observations.append(item)

    do_GET = do_POST

    def log_message(self, *args):
        # Structured backend observations already retain the request evidence;
        # the base class's unstructured stderr log is deliberately unused.
        return


def configuration(raw, output, port, backend_port, row, worker, environment):
    provenance = event_provenance(environment.get(EVENT_RUN_ID), environment.get(EVENT_CASE_ID))
    text = raw.config_template(output, port, backend_port)
    inherited = [*provenance, *(key for key in environment
                              if key.startswith("MSCONNECTOR_") and key not in provenance)]
    text = text.replace("events {}", "\n".join("env " + key + ";" for key in inherited) + "\nevents {}")
    text = text.replace("modsecurity on;", "modsecurity on; modsecurity_phase4_mode " + row["mode"] + ";")
    text = text.replace("location / { proxy_pass", "location / { proxy_http_version 1.1; proxy_buffering off; proxy_pass")
    # Keep NGINX's own client-body ceiling above the bounded 2 MiB native
    # cases.  Otherwise its default 1 MiB parser limit would mask the former
    # connector-limit regression before the request reached ModSecurity.
    directives = (f'client_body_temp_path "{worker}/client"; proxy_temp_path "{worker}/proxy";\n'
                  + "client_max_body_size 4m;\n"
                  + ("client_body_in_file_only clean; client_body_buffer_size 1k;\n" if row["request_file"] else "")
                  + row["nginx_directives"])
    if row["fault"] or row.get("budget_phase") or row.get("invalid_return"):
        directives += "modsecurity_transaction_id $http_x_i12_transaction;\n"
    if row.get("budget_phase"):
        directives += "modsecurity_engine_call_budget_ms 10;\n"
    text = text.replace("http {", "http {\n" + directives)
    if row["response_file"]:
        text = text.replace("location / {", f'location = /ngxi12/selected {{ alias "{worker}/payload.txt"; default_type text/plain; sendfile on; }}\n    location / {{')
    return text


def rules(output, row, framework):
    baseline = (framework / "tests/rules/no-crs-baseline.conf").read_text()
    return (baseline + f'\nSecRequestBodyLimit {row["request_limit"]}\nSecRequestBodyNoFilesLimit {row["request_limit"]}\n'
            + f'SecRequestBodyLimitAction {row["request_action"]}\nSecResponseBodyLimit {row["response_limit"]}\n'
            + f'SecResponseBodyLimitAction {row["response_action"]}\nSecDebugLog "{output}/native-sdk-debug.log"\nSecDebugLogLevel 9\n'
            + 'SecRule REQUEST_BODY "@contains NGXI12_REQ" "id:941002,phase:2,pass,log,msg:\'NGXI12_REQUEST_BODY_PRIMARY\'"\n'
            + 'SecRule RESPONSE_BODY "@contains NGXI12_RSP" "id:941004,phase:4,pass,log,msg:\'NGXI12_RESPONSE_BODY_PRIMARY\'"\n'
            + row["extra_rules"])


def worker_directory(row):
    """Create the protected tree writable only by the real Nobody worker."""
    scratch_parent = storage_root().with_name("ModSecurity-nginx-i12")
    metadata = scratch_parent.lstat()
    if (scratch_parent.resolve() != scratch_parent or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0 or metadata.st_mode & 0o022):
        raise ValueError("root-owned non-writable worker scratch parent required")
    for ancestor in scratch_parent.parents:
        info = ancestor.lstat()
        sticky_root = (stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                       and info.st_mode & stat.S_ISVTX)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o022 and not sticky_root):
            raise ValueError("protected root-owned worker scratch ancestry required")
    worker = Path(tempfile.mkdtemp(prefix="nginx-i12-", dir=scratch_parent))
    worker.chmod(0o711)
    for leaf in ("client", "proxy"):
        path = worker / leaf
        path.mkdir(mode=0o700)
        os.chown(path, 65534, 65534)
    if row["response_file"]:
        (worker / "payload.txt").write_bytes(row["response"])
        (worker / "payload.txt").chmod(0o444)
    return worker


def observer_descriptors(output, environment):
    descriptors = []
    for leaf, key in (("physical-lifecycle.jsonl", "MSCONNECTOR_LIFECYCLE_FD"),
                      ("physical-host.jsonl", "MSCONNECTOR_NGX_HOST_FD")):
        descriptor = os.open(output / leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND, 0o600)
        os.fchmod(descriptor, 0o600)
        descriptors.append(descriptor)
        environment[key] = str(descriptor)
    return descriptors


def fault_descriptors(context):
    """Bind only the explicitly selected native fault fixture to this run."""
    row = context.row
    if row["fault"]:
        descriptor = os.open(context.output / "input-fault.jsonl",
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND, 0o600)
        context.descriptors.append(descriptor)
        context.environment.update(
            LD_PRELOAD=str(context.args.input_fault_library), MSCONNECTOR_OWNED_INPUT_FD=str(descriptor),
            MSCONNECTOR_OWNED_INPUT_FAULT=row["fault"], MSCONNECTOR_OWNED_INPUT_TXID="a" * 32)
    if row.get("budget_phase"):
        descriptor = os.open(context.output / "budget-fault.jsonl",
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND, 0o600)
        context.descriptors.append(descriptor)
        context.environment.update(
            LD_PRELOAD=str(context.args.budget_fault_library), MSCONNECTOR_OWNED_BUDGET_FD=str(descriptor),
            MSCONNECTOR_OWNED_BUDGET_PHASE=str(row["budget_phase"]), MSCONNECTOR_OWNED_BUDGET_TXID="a" * 32)
    if row.get("invalid_return"):
        descriptor = os.open(context.output / "invalid-return.jsonl",
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND, 0o600)
        context.descriptors.append(descriptor)
        context.environment.update(
            LD_PRELOAD=str(context.args.invalid_return_library), MSCONNECTOR_I12_INVALID_FD=str(descriptor),
            MSCONNECTOR_I12_INVALID_TXID="a" * 32)


def prepare_case(args, row, raw, maps):
    """Validate immutable inputs and allocate this case's owned resources."""
    run_id = args.run_prefix + "-" + hashlib.sha256(row["case_id"].encode()).hexdigest()[:16]
    # The host validator and native observer impose a narrower contract than
    # the optional product event fields. Satisfy every consumer before allocation.
    if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", run_id) is None:
        raise ValueError("invalid host/native observer run identity")
    provenance = event_provenance(run_id, CASE_ID_PREFIX + row["case_id"])
    output = args.output_root / row["case_id"]
    args.output_root.mkdir(exist_ok=True, mode=0o700)
    local_args = argparse.Namespace(**vars(args))
    local_args.output_root = str(output)
    # The preserved observer accepts run labels up to64 bytes. The complete
    # original ID remains independently present in its128-byte case field.
    local_args.run_id = run_id
    local_args.nginx_binary, local_args.module = str(args.nginx_binary), str(args.module)
    binary, module, output = raw.BASE.validate_inputs(local_args)
    if os.geteuid() != 0:
        raise ValueError("actual root master required")
    output.mkdir(mode=0o700)
    environment = {**raw.BASE.configtest_environment(str(args.library_dir)), **provenance}
    raw.BASE.snapshot_artifact(binary, output / "nginx-binary", executable=True)
    raw.BASE.snapshot_artifact(module, output / "nginx-module.so", executable=False)
    backend = HTTPServer(("127.0.0.1", 0), Backend)
    backend.fixture, backend.observations = row, []
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    port = raw.reserve_port()
    worker = worker_directory(row)
    descriptors = observer_descriptors(output, environment)
    roles = {"run_id": local_args.run_id, "master_pid": 0, "worker_pid": 0, "master_uid": -1, "worker_uid": -1}
    environment.update(MSCONNECTOR_LIFECYCLE_RUN=local_args.run_id, MSCONNECTOR_LIFECYCLE_PROFILE="nginx-native",
                       MSCONNECTOR_LIFECYCLE_CASE=CASE_ID_PREFIX + row["case_id"])
    context = argparse.Namespace(args=args, row=row, raw=raw, maps=maps, output=output,
                                 local_args=local_args, environment=environment, backend=backend,
                                 thread=thread, port=port, worker=worker, descriptors=descriptors,
                                 handles={}, clients=[], errors=[], process=None, capture=None,
                                 roles=roles, cleanup={}, configcode=None, master_result=None)
    fault_descriptors(context)
    capture = maps.Capture(local_args, output, environment, {}, raw.HOST)
    context.capture = capture
    descriptors.extend(capture.descriptors())
    return context


def apply_malformed_headers(headers, malformed):
    if malformed == "invalid_content_length":
        return [(key, "abc" if key == "Content-Length" else value) for key, value in headers]
    if malformed == "conflicting_content_length":
        return [*headers, ("Content-Length", "1")]
    if malformed == "duplicate_transfer_encoding":
        return [*headers, ("Transfer-Encoding", "chunked"), ("Transfer-Encoding", "chunked")]
    if malformed == "content_length_overflow":
        return [(key, "9223372036854775808" if key == "Content-Length" else value)
                for key, value in headers]
    return headers


def request_wire(row, label):
    selected = label == "selected"
    body = row["request"] if selected else b"marker=NGXI12_REQ&neighbor=1"
    path = "/no-crs/input-fault/" + row["fault"] if row["fault"] and label != "followup" else "/ngxi12/" + label
    method = "GET" if selected and row["response_file"] else "POST"
    if method == "GET" and not row.get("get_entity"):
        body = b""
    headers = [("Host", "localhost"), ("Content-Length", str(len(body))), ("Connection", "close")]
    content_type = row["request_type"] if selected else "application/x-www-form-urlencoded"
    if content_type:
        headers.append(("Content-Type", content_type))
    if selected:
        headers.extend(row["extra_headers"])
    if row["fault"] or row.get("budget_phase") or row.get("invalid_return"):
        headers.append(("X-I12-Transaction", ("a" if selected else "b") * 32))
    headers = apply_malformed_headers(headers, row.get("malformed") if selected else None)
    head = method + " " + path + " HTTP/1.1\r\n"
    return (head + "".join(key + ": " + value + "\r\n" for key, value in headers) + "\r\n").encode() + body


def invoke_client(context, label, parser_env):
    selected = label == "selected"
    request = context.output / (label + "-request.bin")
    request.write_bytes(request_wire(context.row, label))
    pieces = context.row["writes"] if selected else 1
    clientargv = [sys.executable, str(Path(__file__).with_name("wire_client.py")),
                  "--port", str(context.port), "--request", str(request),
                  "--output", str(context.output / label), "--pieces", str(pieces)]
    started = time.monotonic_ns()
    with subprocess.Popen(clientargv, env=client_environment(parser_env),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as client:
        try:
            client_stdout, client_stderr = client.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            client.kill()
            client_stdout, client_stderr = client.communicate()
            context.errors.append(label + " actual client timed out and was reaped")
    waited = time.monotonic_ns()
    (context.output / (label + "-client.stdout")).write_bytes(client_stdout)
    (context.output / (label + "-client.stderr")).write_bytes(client_stderr)
    item = {"label": label, "argv": clientargv, "exit_code": client.returncode,
            "pid": client.pid, "direct_child_wait": True,
            "signal": -client.returncode if client.returncode < 0 else None,
            "started_monotonic_ns": started, "waited_monotonic_ns": waited}
    observation = context.output / label / "client-observation.json"
    if observation.exists():
        item["observation"] = json.loads(observation.read_text())
    context.clients.append(item)


def exercise_case(context):
    output = context.output
    row = context.row
    (output / "no-crs-baseline.conf").write_text(rules(output, row, context.args.framework_root))
    (output / "fixture.json").write_text(json.dumps(serializable(row), indent=2) + "\n")
    (output / "nginx.conf").write_text(configuration(
        context.raw, output, context.port, context.backend.server_port, row,
        context.worker, context.environment))
    argv = [str(output / "nginx-binary"), "-e", "stderr", "-t", "-c",
            str(output / "nginx.conf"), "-p", str(output) + "/"]
    parser_env = {key: value for key, value in context.environment.items()
                  if key != "LD_PRELOAD" and not key.startswith("MSCONNECTOR_")}
    context.configcode, stdout, stderr, failure = context.raw.BASE.invoke(argv, parser_env)
    (output / "configtest.stdout").write_bytes(stdout)
    (output / "configtest.stderr").write_bytes(stderr)
    if context.configcode != 0 or failure:
        raise ValueError("actual native configuration did not load")
    with (output / "startup.stdout").open("xb") as stdout, (output / "startup.stderr").open("xb") as stderr:
        argv.remove("-t")
        context.process = subprocess.Popen(
            argv, env=context.environment, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
            pass_fds=tuple(context.descriptors))
        context.roles = context.raw.HOST.observe_roles(
            context.process, context.local_args.run_id, context.port, output, context.handles)
        context.capture.capture(context.roles)
        labels = ["selected", "followup"]
        if row["fault"] or row.get("invalid_return"):
            labels.append("wrong-transaction")
        for label in labels:
            invoke_client(context, label, parser_env)


def finalize_case(context):
    context.cleanup = context.raw.HOST.stop_owned_master(
        context.process, context.roles, context.port, context.local_args.run_id, context.handles)
    context.master_result = context.process.returncode if context.process is not None else None
    for descriptor in context.descriptors:
        if descriptor != context.capture.descriptor:
            os.fsync(descriptor)
            os.close(descriptor)
    context.capture.close()
    context.backend.shutdown()
    context.backend.server_close()
    context.thread.join(2)


def case_result(context):
    if not context.cleanup.get("verified") or context.thread.is_alive():
        context.errors.append("owned cleanup incomplete")
    (context.output / "backend.json").write_text(json.dumps(context.backend.observations, indent=2) + "\n")
    master_signal = None
    if context.master_result is not None and context.master_result < 0:
        master_signal = -context.master_result
    receipt = {"selected_id": CASE_ID_PREFIX + context.row["case_id"],
               "run_id": context.local_args.run_id, "parent_sha": context.args.parent_sha,
               "framework_sha": context.args.framework_sha, "mrts_sha": context.args.mrts_sha,
               "roles": context.roles, "configtest_exit": context.configcode, "cleanup": context.cleanup,
               "master_wait_result": context.master_result, "master_signal": master_signal,
               "clients": context.clients, "backend": context.backend.observations,
               "errors": context.errors, "full_lifecycle_qualified": False,
               "scope": "Physical observations only; independent Root reconciliation required",
               "raw_artifacts_sha256": {
                   str(path.relative_to(context.output)): digest(path)
                   for path in context.output.rglob("*") if path.is_file() and not path.is_symlink()}}
    (context.output / "full-observation-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    clients = [{key: item.get(key) for key in ("label", "exit_code", "signal")}
               for item in context.clients]
    return {"case_id": context.row["case_id"], "output": str(context.output),
            "errors": context.errors, "clients": clients}


def run_one(args, row, raw, maps):
    context = prepare_case(args, row, raw, maps)
    context.thread.start()
    try:
        exercise_case(context)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        context.errors.append(type(exc).__name__ + ": " + str(exc))
    finally:
        finalize_case(context)
    return case_result(context)


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for name in ("source", "nginx-binary", "module", "output-root", "library-dir", "framework-root", "worker-self-map-library", "input-fault-library", "budget-fault-library", "invalid-return-library"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("parent-sha", "framework-sha", "mrts-sha"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--run-prefix", required=True)
    parser.add_argument("--case", action="append", default=[])
    args = parser.parse_args()
    args.worker_self_map_library = str(args.worker_self_map_library)
    args.nginx_binary, args.module = args.nginx_binary.resolve(), args.module.resolve()
    raw = load("i12_real_nginx_raw", args.source / "ci/runtime/lifecycle/run-nginx-raw-h1.py")
    maps = load("i12_actual_worker_maps", args.source / "ci/runtime/lifecycle/nginx-worker-self-maps.py")
    selected = [row for row in cases() if not args.case or row["case_id"] in args.case]
    if args.case and len(selected) != len(set(args.case)):
        raise ValueError("unknown selected fixture")
    results = []
    for row in selected:
        result = run_one(args, row, raw, maps)
        results.append(result)
        print(json.dumps(result), flush=True)
    (args.output_root / "suite-observations.json").write_text(json.dumps(results, indent=2) + "\n")
    return 1 if any(row["errors"] for row in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
