#!/usr/bin/env python3
"""Execute the closed valid-rules config/startup/native-request contract."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import load_source

from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import subprocess
import sys
import time


def load_helper(name: str, path: Path):
    module = load_source(path)
    return module


HERE = Path(__file__).resolve().parent
BASE = load_helper("nginx_configtest_driver", HERE / "run-nginx-configtest.py")
from modsecurity_connector_ci.lib.runtime_path_utils import open_private_runtime_root

PROJECTION = load_helper("nginx_projection", HERE.parent / "common/prepare-nginx-docroot-projection.py")
BASELINE_RULES_NAME = "no-crs-baseline.conf"
PROC_ROOT = Path("/proc")
NATIVE_EVENTS_NAME = "phase1-events.jsonl"
STARTUP_STDOUT_NAME = "startup.stdout"
STARTUP_STDERR_NAME = "startup.stderr"
VALID_RULES_CONTRACT = {"operation": "startup", "directive": "modsecurity_rules_file",
            "value": BASELINE_RULES_NAME, "expected_exit_code": 0,
            "expected_outcome": "config_accepted", "error_class": "none",
            "diagnostic_fragments": ["syntax is ok", "test is successful"]}
CONTRACT = VALID_RULES_CONTRACT


def projection_name(run_id: str) -> str:
    return run_id[:90] + "-valid-rules-" + hashlib.sha256(run_id.encode()).hexdigest()[:16]


def config_template(origin: Path, port: int, projection_root: str) -> str:
    return (
        f'load_module "{origin}/nginx-module.so";\n'
        'user nobody nogroup;\nworker_processes 1;\ndaemon off;\n'
        f'pid "{origin}/nginx.pid";\nerror_log "{origin}/nginx-error.log";\n'
        'events {}\nhttp {\n  access_log off;\n  modsecurity on;\n'
        f'  modsecurity_rules_file "{origin}/{BASELINE_RULES_NAME}";\n'
        f'  modsecurity_phase4_log "{origin}/{NATIVE_EVENTS_NAME}";\n'
        '  server {\n'
        f'    listen 127.0.0.1:{port};\n    root "{projection_root}";\n'
        '    location / { try_files $uri /index.html; }\n  }\n}\n'
    )


def valid_roles(roles: dict) -> bool:
    return (type(roles.get("master_uid")) is int and roles["master_uid"] == 0
            and type(roles.get("worker_uid")) is int and roles["worker_uid"] == 65534
            and all(type(roles.get(key)) is int and roles[key] > 0
                    for key in ("master_pid", "worker_pid"))
            and roles["master_pid"] != roles["worker_pid"])


def match_native_event(events: list, run_id: str) -> str:
    matched = set()
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("native event is not an object")
        if event.get("run_id", run_id) != run_id:
            raise ValueError("foreign native run identity")
        if (event.get("connector") == "nginx"
                and event.get("integration_mode") == "native-nginx-http-module"
                and type(event.get("phase")) in (int, str)
                and event.get("phase") in (1, "1", "request_headers")
                and str(event.get("rule_id")) == "1100001"
                and event.get("event") == "engine_decision"
                and event.get("message_id") == "MSCONN_EVENT_ENGINE_DECISION"
                and event.get("status") == "blocked"
                and type(event.get("http_status")) is int and event["http_status"] == 403
                and event.get("requested_action") == "deny"
                and event.get("actual_action") == ""
                and type(event.get("visible_http_status")) is int and event["visible_http_status"] == 0
                and event.get("transport_result") == "not_observable"
                and event.get("method") == "GET" and event.get("uri") == "/no-crs/deny"):
            transaction = event.get("transaction_id")
            if isinstance(transaction, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", transaction):
                matched.add(transaction)
    if len(matched) != 1:
        raise ValueError("native phase-1 rule/request transaction is missing or ambiguous")
    return matched.pop()


def process_info(pid: int) -> tuple[int, int, str, str] | None:
    try:
        proc = PROC_ROOT / str(pid)
        status = (proc / "status").read_text()
        values = {line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                  for line in status.splitlines() if ":" in line}
        fields = (proc / "stat").read_text().rsplit(")", 1)[1].split()
        return int(values["Uid"].split()[1]), int(values["PPid"]), fields[0], fields[19]
    except (OSError, ValueError, KeyError, IndexError):
        return None


def listener_open(port: int) -> bool:
    with socket.socket() as connection:
        connection.settimeout(0.1)
        return connection.connect_ex(("127.0.0.1", port)) == 0


def bind_owned_children(process: subprocess.Popen, handles: dict[int, int]) -> None:
    try:
        children = (PROC_ROOT / str(process.pid) / "task" / str(process.pid) / "children").read_text().split()
    except OSError:
        return
    for child in children:
        pid = int(child)
        if pid in handles:
            continue
        before = process_info(pid)
        if before is None or before[1] != process.pid:
            continue
        try:
            handle = os.pidfd_open(pid)
        except OSError:
            continue
        after = process_info(pid)
        if after is None or after[1] != process.pid or after[3] != before[3]:
            os.close(handle)
        else:
            handles[pid] = handle


def pidfd_running(handle: int) -> bool:
    return not select.select([handle], [], [], 0)[0]


def verify_startup_captures(output: Path) -> None:
    for name in (STARTUP_STDOUT_NAME, STARTUP_STDERR_NAME, "nginx-error.log"):
        path = output / name
        if path.exists() and path.stat().st_size > BASE.CAPTURE_LIMIT:
            raise ValueError("startup capture limit exceeded")


def observed_owned_roles(process, master, children, worker_handles, port, run_id):
    for child in children:
        worker = process_info(int(child))
        if master and worker and worker[1] == process.pid and worker[2] != "Z":
            roles = {"run_id": run_id, "master_pid": process.pid, "worker_pid": int(child),
                     "master_uid": master[0], "worker_uid": worker[0]}
            if valid_roles(roles) and int(child) in worker_handles and listener_open(port):
                return roles
    return None


def observe_roles(process: subprocess.Popen, run_id: str, port: int, output: Path,
                  worker_handles: dict[int, int] | None = None) -> dict:
    if worker_handles is None:
        raise ValueError("startup requires an owned-child cleanup handle registry")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        bind_owned_children(process, worker_handles)
        if process.poll() is not None:
            raise ValueError("NGINX exited before native request")
        verify_startup_captures(output)
        master = process_info(process.pid)
        try:
            children = (PROC_ROOT / str(process.pid) / "task" / str(process.pid) / "children").read_text().split()
        except OSError:
            children = []
        roles = observed_owned_roles(process, master, children, worker_handles, port, run_id)
        if roles is not None:
            return roles
        time.sleep(0.05)
    raise ValueError("root master/nobody worker/listener observation timed out")


def request_owned_master_shutdown(process, worker_handles) -> bool:
    forced = False
    if process is not None and process.poll() is None:
        bind_owned_children(process, worker_handles)
        process.send_signal(signal.SIGQUIT)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            forced = True
            process.kill()
            process.wait(timeout=5)
    return forced


def retire_bound_children(worker_handles) -> tuple[bool, bool]:
    forced = False
    bound_running = False
    for handle in worker_handles.values():
        if pidfd_running(handle):
            forced = True
            try:
                signal.pidfd_send_signal(handle, signal.SIGKILL)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 2
            while pidfd_running(handle) and time.monotonic() < deadline:
                time.sleep(0.02)
            bound_running = bound_running or pidfd_running(handle)
    return forced, bound_running


def stop_owned_master(process: subprocess.Popen | None, roles: dict, port: int, run_id: str,
                      worker_handles: dict[int, int] | None = None) -> dict:
    worker_handles = {} if worker_handles is None else worker_handles
    try:
        forced = request_owned_master_shutdown(process, worker_handles)
        # Even a normally exited master can leave a child. Retire only handles
        # bound while that exact process was observed as this master's child.
        children_forced, bound_running = retire_bound_children(worker_handles)
        forced = forced or children_forced
    finally:
        for handle in worker_handles.values():
            os.close(handle)
    master = process_info(roles.get("master_pid", 0))
    worker = process_info(roles.get("worker_pid", 0))
    master_running = master is not None and master[2] != "Z"
    worker_running = bound_running or (worker is not None and worker[2] != "Z")
    opened = listener_open(port)
    return {"run_id": run_id, "master_pid": roles.get("master_pid", 0),
            "worker_pid": roles.get("worker_pid", 0), "master_running": master_running,
            "worker_running": worker_running, "listener_open": opened,
            "verified": valid_roles(roles) and not (forced or master_running or worker_running or opened)}


def write_json(path: Path, value: dict) -> bytes:
    """Create only a closed JSON leaf under the existing private output root."""
    path = BASE.absolute_path(str(path))
    if path.name not in {"request-result.json", "roles.json", "cleanup.json",
                         "source-result.json", "source-result.jsonl"}:
        raise ValueError("JSON artifact name is outside the closed startup contract")
    root = path.parent
    if BASE.AUTHORIZED_STORAGE_ROOT not in root.parents:
        raise ValueError("JSON output must be under authorized external task storage")
    if any(BASE.is_checkout(ancestor) for ancestor in (root, *root.parents)
           if BASE.AUTHORIZED_STORAGE_ROOT in ancestor.parents):
        raise ValueError("JSON output must be outside the checkout")
    text = json.dumps(value, sort_keys=True) + "\n"
    with open_private_runtime_root(root) as private_root:
        private_root.create_text(path.name, text, "startup JSON artifact")
    return text.encode()


def bounded_capture(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        import stat
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > BASE.CAPTURE_LIMIT:
            raise ValueError("capture must be a bounded regular file")
        raw = stream.read(BASE.CAPTURE_LIMIT + 1)
        if len(raw) > BASE.CAPTURE_LIMIT:
            raise ValueError("capture grew beyond its limit")
        return raw


def execute_native_probe(environment: dict, output: Path, run_id: str, port: int) -> tuple[dict, str]:
    """Return only a real HTTP deny bound to its strict native event."""
    curl = subprocess.run(["/usr/bin/curl", "--noproxy", "*", "--http1.1", "--silent", "--show-error",
                           "--max-time", "5", "--output", os.devnull, "--write-out", "%{http_code}",
                           "-H", "X-Modsec-Smoke: block", f"http://127.0.0.1:{port}/no-crs/deny"],
                          env=environment, capture_output=True, timeout=6, check=False)
    if curl.returncode != 0 or curl.stdout != b"403":
        raise ValueError("actual H1 deny probe did not return HTTP 403")
    events_path = output / NATIVE_EVENTS_NAME
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if events_path.exists() and events_path.stat().st_size:
            break
        time.sleep(0.05)
    raw_events = bounded_capture(events_path)
    transaction = match_native_event([json.loads(line) for line in raw_events.splitlines() if line.strip()], run_id)
    request = {"case_id": "valid_rules_file", "run_id": run_id, "operation": "request",
               "method": "GET", "path": "/no-crs/deny", "header_name": "X-Modsec-Smoke",
               "header_value": "block", "client_exit_code": curl.returncode,
               "observed_http_status": int(curl.stdout), "transaction_id": transaction}
    return request, transaction


def retain_startup_completion(process, output, receipt):
    if process is None:
        return
    code = process.returncode
    receipt.update(returncode=code, exit_code=code if code >= 0 else None,
                   signal=-code if code < 0 else None)
    try:
        stdout = bounded_capture(output / STARTUP_STDOUT_NAME)
        stderr = bounded_capture(output / STARTUP_STDERR_NAME)
        BASE.completed_invocation_receipt(receipt, code, stdout, stderr, None)
    except (OSError, ValueError) as exc:
        receipt["capture_failure"] = str(exc)


def run(args) -> bool:
    binary, module, output = BASE.validate_inputs(args)
    if os.geteuid() != 0:
        raise ValueError("valid-rules startup requires root master with nobody worker")
    rules = BASE.absolute_path(args.rules_file)
    framework_root = BASE.absolute_path(args.framework_root)
    expected_rules = framework_root / "tests/rules" / BASELINE_RULES_NAME
    if rules != expected_rules:
        raise ValueError("rules must be the exact Framework baseline at this checkout")
    parent = BASE.absolute_path(args.projection_parent)
    environment = BASE.configtest_environment(args.library_dir)
    output.mkdir(mode=0o700)
    (output / "logs").mkdir(mode=0o700)
    binary_sha = BASE.snapshot_artifact(binary, output / "nginx-binary", executable=True)
    module_sha = BASE.snapshot_artifact(module, output / "nginx-module.so", executable=False)
    rules_sha = BASE.snapshot_artifact(rules, output / BASELINE_RULES_NAME, executable=False)
    if (output / BASELINE_RULES_NAME).stat().st_size > 65536:
        raise ValueError("rules file capture limit exceeded")
    source = output / "docroot"
    source.mkdir(mode=0o700)
    for name in PROJECTION.PROJECTED_FILENAMES:
        (source / name).write_bytes(b"valid-rules-owned-static\n")
    projection = PROJECTION.prepare_projection(
        source_docroot=source, private_root=output, projection_parent=parent,
        projection_root=parent / projection_name(args.run_id), worker_gid=65534,
        avoid_roots=[output, BASE.PARENT_ROOT, framework_root])
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    configuration = config_template(output, port, str(projection)).encode()
    config = output / "nginx.conf"
    config.write_bytes(configuration)
    argv = [str(output / "nginx-binary"), "-e", "stderr", "-t", "-c", str(config), "-p", str(output) + "/"]
    parser_invocation = BASE.empty_invocation_receipt()
    exit_code, stdout, stderr, failure = BASE.invoke(argv, environment,
                                                    invocation_receipt=parser_invocation)
    (output / "stdout.log").write_bytes(stdout)
    (output / "stderr.log").write_bytes(stderr)
    fragments = [fragment for fragment in CONTRACT["diagnostic_fragments"] if fragment in stderr.decode(errors="replace")]
    process = None
    startup_invocation = BASE.empty_invocation_receipt()
    startup_invocation["readiness_observed"] = None
    worker_handles = {}
    roles = {"run_id": args.run_id, "master_pid": 0, "worker_pid": 0, "master_uid": -1, "worker_uid": -1}
    request = {}
    transaction = None
    try:
        if exit_code != 0 or failure or fragments != CONTRACT["diagnostic_fragments"]:
            raise ValueError("configuration acceptance was not proven")
        with (output / STARTUP_STDOUT_NAME).open("wb") as out, (output / STARTUP_STDERR_NAME).open("wb") as err:
            startup_cwd = os.getcwd()
            process = subprocess.Popen([str(output / "nginx-binary"), "-e", "stderr", "-c", str(config),
                                        "-p", str(output) + "/"], env=environment,
                                       stdin=subprocess.DEVNULL, stdout=out, stderr=err)
            startup_invocation.update(BASE.started_invocation_receipt(process, startup_cwd))
            roles = observe_roles(process, args.run_id, port, output, worker_handles)
            startup_invocation["readiness_observed"] = True
            request, transaction = execute_native_probe(environment, output, args.run_id, port)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        failure = str(exc)
    finally:
        cleanup = stop_owned_master(process, roles, port, args.run_id, worker_handles)
    retain_startup_completion(process, output, startup_invocation)
    passed = failure is None and transaction is not None and cleanup["verified"] and valid_roles(roles)
    raw_request = write_json(output / "request-result.json", request)
    raw_roles = write_json(output / "roles.json", roles)
    raw_cleanup = write_json(output / "cleanup.json", cleanup)
    events = bounded_capture(output / NATIVE_EVENTS_NAME) if (output / NATIVE_EVENTS_NAME).exists() else b""
    receipt = dict(CONTRACT, schema_version=1, case_id="valid_rules_file", connector="nginx",
                   run_id=args.run_id, integration_mode="native-nginx-http-module",
                   parent_sha=args.parent_sha, framework_sha=args.framework_sha, mrts_sha=args.mrts_sha,
                   binary_sha256=binary_sha, module_sha256=module_sha, config_path_identity="sha256:" + BASE.digest(configuration),
                   observed_exit_code=exit_code, observed_outcome="config_accepted" if exit_code == 0 else "unexpected_outcome",
                   stdout_sha256=BASE.digest(stdout), stderr_sha256=BASE.digest(stderr),
                   native_parser_invocation=parser_invocation,
                   native_startup_invocation=startup_invocation,
                   process_started=process is not None, listener_created=valid_roles(roles),
                   timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                   listen_port=port, docroot_projection_parent=str(parent), docroot_projection_root=str(projection),
                   cleanup_verified=cleanup["verified"],
                   rules_sha256=rules_sha, events_sha256=BASE.digest(events), request_sha256=BASE.digest(raw_request),
                   roles_sha256=BASE.digest(raw_roles), cleanup_sha256=BASE.digest(raw_cleanup),
                   request_probe={"run_id": args.run_id, "transaction_id": transaction,
                                  "observed_http_status": request.get("observed_http_status"),
                                  "client_exit_code": request.get("client_exit_code"), "phase": 1, "rule_id": 1100001})
    receipt["diagnostic_fragments"] = fragments
    if not passed:
        receipt["error_class"] = "unexpected_startup_outcome"
    row = {"case_id": "valid_rules_file", "status": "PASS" if passed else "FAIL", "live_executed": True,
           "actual_status": exit_code, "observed_result": receipt["observed_outcome"], "run_id": args.run_id,
           "integration_mode": receipt["integration_mode"], "observed_rule_ids": [1100001] if transaction else [],
           "transaction_ids": [transaction] if transaction else [], "artifacts": {"configtest_dir": str(output)},
           "configtest_receipt": receipt}
    write_json(output / "source-result.json", {"cases": [row]})
    write_json(output / "source-result.jsonl", row)
    if failure:
        print("valid-rules failure: " + failure, file=sys.stderr)
    return passed


def main(argv=None) -> int:
    parser = BASE.argument_parser()
    for action in parser._actions:
        if action.dest == "case_id":
            action.choices = ("valid_rules_file",)
    parser.add_argument("--rules-file", required=True)
    parser.add_argument("--projection-parent", required=True)
    parser.add_argument("--framework-root", default=str(BASE.PARENT_ROOT / "modules/ModSecurity-test-Framework"))
    args = parser.parse_args(argv)
    try:
        return 0 if run(args) else 1
    except (OSError, ValueError) as exc:
        print("valid-rules input failure: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
