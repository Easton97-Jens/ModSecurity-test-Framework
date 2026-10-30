#!/usr/bin/env python3
"""Run an exact own-worker fault through the genuine Common mapper guard."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import load_source

import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys

import importlib.util


def load(name, path):
    module = load_source(path)
    return module


HERE = Path(__file__).resolve().parent
STARTUP = load("input_fault_startup", HERE / "run-nginx-valid-rules.py")
SELF_MAPS = load("input_fault_self_maps", HERE / "nginx-worker-self-maps.py")
BASE = STARTUP.BASE
from modsecurity_connector_ci.lib.runtime_path_utils import open_private_runtime_root

CASES = ("body_size_nonzero_with_null_data", "header_count_nonzero_with_null_headers")
NATIVE_FAULT_LEDGER = "native-input-fault.jsonl"
NGINX_ERROR_LOG = "nginx-error.log"


def mismatch_transaction(transaction):
    return transaction[:-1] + ("1" if transaction[-1] == "0" else "0")


def fault_config(output, port, projection, transaction):
    text = STARTUP.config_template(output, port, projection)
    access = ('  log_format input_fault escape=json \'{"uri":"$request_uri","status":$status,'
              '"transaction_id":"' + transaction + '"}\';\n'
              f'  access_log "{output}/native-access.jsonl" input_fault;\n'
              f'  modsecurity_transaction_id "{transaction}";')
    return text.replace("  access_log off;", access)


def read_rows(output, leaf):
    path = output / leaf
    if not path.exists():
        return []
    return [json.loads(line) for line in STARTUP.bounded_capture(path).splitlines() if line.strip()]


def select_mapper_error_events(rows, transaction):
    """Project only the actual own-request P1 guard event; never alter raw rows.

    The sink also retains post-native-return cleanup events. Its complete bytes
    are still hashed below; strict helper validation rejects zero/multiple or
    malformed selected connector errors rather than choosing a convenient row.
    Common rejected this mapped view before canonical request metadata was
    recorded, so the source event must retain exact empty method/URI values.
    Access, fault-ledger, configuration and cleanup evidence bind the request.
    """
    identity = {"event": "phase1_error", "message_id": "MSCONN_EVENT_CONNECTOR_ERROR",
                "connector": "nginx", "integration_mode": "native-nginx-http-module",
                "phase": "request_headers", "transaction_id": transaction,
                "status": "error", "reason": "connector_error", "http_status": 500,
                "method": "", "uri": ""}
    return [row for row in rows if isinstance(row, dict)
            and all(type(row.get(key)) is type(value) and row.get(key) == value
                    for key, value in identity.items())]


def private_json(output, leaf, value):
    if leaf not in {"input-fault-observation.json", "input-fault-source.json", "input-fault-source.jsonl"}:
        raise ValueError("unknown input-fault artifact")
    raw = json.dumps(value, sort_keys=True) + "\n"
    with open_private_runtime_root(output) as root:
        root.create_text(leaf, raw, "Common input-fault observation")
    return raw.encode()


def prepare(args):
    binary, module, output = BASE.validate_inputs(args)
    if os.geteuid() != 0 or args.case_id not in CASES:
        raise ValueError("closed fault operation requires isolated root master/nobody worker")
    framework = BASE.absolute_path(args.framework_root)
    validator = load("input_fault_contract", framework / "tests/runners/nginx_common_input_faults.py")
    parent = BASE.absolute_path(args.projection_parent)
    output.mkdir(mode=0o700)
    (output / "logs").mkdir(mode=0o700)
    snapshots = ((binary, "nginx-binary", True), (module, "nginx-module.so", False),
                 (framework / "tests/rules/no-crs-baseline.conf", "no-crs-baseline.conf", False),
                 (BASE.absolute_path(args.fault_library), "native-input-fault.so", False))
    hashes = {leaf: BASE.snapshot_artifact(origin, output / leaf, executable=executable)
              for origin, leaf, executable in snapshots}
    source = output / "docroot"
    source.mkdir(mode=0o700)
    for name in STARTUP.PROJECTION.PROJECTED_FILENAMES:
        (source / name).write_bytes(b"owned-common-input-fault\n")
    transaction = hashlib.sha256((args.run_id + ":" + args.case_id).encode()).hexdigest()[:32]
    projection = STARTUP.PROJECTION.prepare_projection(source_docroot=source, private_root=output,
        projection_parent=parent, projection_root=parent / ("common-input-" + transaction),
        worker_gid=65534, avoid_roots=[output, BASE.PARENT_ROOT, framework])
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    configuration = fault_config(output, port, str(projection), transaction).encode()
    (output / "nginx.conf").write_bytes(configuration)
    return output, validator, hashes, transaction, port, configuration, projection


def native_environment(args, output, transaction):
    environment = BASE.configtest_environment(args.library_dir)
    descriptor = None
    try:
        with open_private_runtime_root(output) as root:
            descriptor = os.open(NATIVE_FAULT_LEDGER, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY,
                                 0o600, dir_fd=root.descriptor)
        os.fchmod(descriptor, 0o600)
        details = os.fstat(descriptor)
        if (descriptor < 3 or not stat.S_ISREG(details.st_mode) or details.st_uid != 0
                or stat.S_IMODE(details.st_mode) != 0o600 or details.st_nlink != 1 or details.st_size != 0):
            raise ValueError("fresh owned private input ledger descriptor required")
        environment.update(LD_PRELOAD=str(output / "native-input-fault.so"),
            MSCONNECTOR_OWNED_INPUT_FAULT=args.case_id,
            MSCONNECTOR_OWNED_INPUT_TXID=mismatch_transaction(transaction) if args.fault_negative_control else transaction,
            MSCONNECTOR_OWNED_INPUT_FD=str(descriptor))
        return environment, descriptor
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise


def request(port, path, environment, output):
    if (type(port) is not int or not 1 <= port <= 65535
            or not isinstance(path, str) or re.fullmatch(
                r"/no-crs/input-fault/(?:body_size_nonzero_with_null_data|header_count_nonzero_with_null_headers)", path) is None):
        raise ValueError("closed input-fault request path and port required")
    client_environment = dict(environment)
    # The fixture is loaded only into the owned native master/worker, never curl.
    client_environment.pop("LD_PRELOAD", None)
    for name in tuple(client_environment):
        if name.startswith(("MSCONNECTOR_OWNED_INPUT_", "MSCONNECTOR_OWNED_SELF_MAP_")):
            client_environment.pop(name)
    result = subprocess.run(["/usr/bin/curl", "--noproxy", "*", "--http1.1", "--silent", "--show-error",
        "--max-time", "5", "--output", os.devnull, "--write-out", "%{http_code}",
        "--data-binary", "owned", "--", f"http://127.0.0.1:{port}{path}"],
        env=client_environment, capture_output=True, timeout=6, check=False)
    (output / "client.stdout").write_bytes(result.stdout)
    (output / "client.stderr").write_bytes(result.stderr)
    status = int(result.stdout) if result.stdout.isdigit() else None
    return result.returncode, status


def run(args):
    output, validator, hashes, transaction, port, configuration, projection = prepare(args)
    environment, ledger_descriptor = native_environment(args, output, transaction)
    try:
        worker_maps = SELF_MAPS.Capture(args, output, environment, hashes, STARTUP)
    except BaseException:
        os.close(ledger_descriptor)
        raise
    argv = [str(output / "nginx-binary"), "-e", "stderr", "-c", str(output / "nginx.conf"), "-p", str(output) + "/"]
    code, failure = None, None
    process, handles = None, {}
    roles = {"master_pid": 0, "worker_pid": 0, "master_uid": -1, "worker_uid": -1}
    client_exit, status = None, None
    path = "/no-crs/input-fault/" + args.case_id
    try:
        # No pass_fds: configuration testing cannot arm the inherited-FD fixture.
        code, stdout, stderr, failure = BASE.invoke(argv + ["-t"], environment)
        (output / "configtest.stdout").write_bytes(stdout)
        (output / "configtest.stderr").write_bytes(stderr)
        if code != 0 or failure:
            raise ValueError("actual config acceptance is required")
        with (output / "startup.stdout").open("xb") as out, (output / "startup.stderr").open("xb") as err:
            process = subprocess.Popen(argv, env=environment, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                       pass_fds=worker_maps.descriptors(ledger_descriptor))
            roles = STARTUP.observe_roles(process, args.run_id, port, output, handles)
            worker_maps.capture(roles)
            client_exit, status = request(port, path, environment, output)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        failure = str(exc)
    finally:
        try:
            cleanup = STARTUP.stop_owned_master(process, roles, port, args.run_id, handles)
        finally:
            try:
                worker_maps.close()
            finally:
                try:
                    os.fsync(ledger_descriptor)
                finally:
                    os.close(ledger_descriptor)
    access, faults = read_rows(output, "native-access.jsonl"), read_rows(output, NATIVE_FAULT_LEDGER)
    diagnostic = "modsecurity common request mapper validation failed: " + validator.CONTRACTS[args.case_id]["diagnostic"]
    raw_error = STARTUP.bounded_capture(output / NGINX_ERROR_LOG) if (output / NGINX_ERROR_LOG).exists() else b""
    observed = {"schema_version": 1, "case_id": args.case_id, "run_id": args.run_id, "operation": "common_mapper_input_fault",
        "protocol": "http1", "client_exit_code": client_exit, "observed_http_status": status, "path": path, "transaction_id": transaction,
        "roles": roles, "cleanup": cleanup, "native_access": access[0] if len(access) == 1 else {},
        "native_fault": faults[0] if len(faults) == 1 else {},
        "native_events": select_mapper_error_events(read_rows(output, "phase1-events.jsonl"), transaction),
        "native_diagnostic": diagnostic if diagnostic.encode() in raw_error else None}
    errors = validator.observation_errors(observed, args.case_id, args.run_id)
    if failure:
        errors.append(failure)
    raw = private_json(output, "input-fault-observation.json", observed)
    receipt = {"schema_version": 1, "case_id": args.case_id, "run_id": args.run_id, "operation": "common_mapper_input_fault",
        "parent_sha": args.parent_sha, "framework_sha": args.framework_sha, "mrts_sha": args.mrts_sha, "artifacts_sha256": hashes,
        "observed_sha256": BASE.digest(raw), "config_sha256": BASE.digest(configuration), "configtest_exit_code": code,
        "projection_root": str(projection), "projection_parent": args.projection_parent}
    receipt["raw_artifacts_sha256"] = {
        leaf: BASE.digest(STARTUP.bounded_capture(output / leaf))
        for leaf in ("native-access.jsonl", NATIVE_FAULT_LEDGER, "phase1-events.jsonl",
                     "worker-maps.log", SELF_MAPS.LEDGER, NGINX_ERROR_LOG, "configtest.stdout", "configtest.stderr",
                     "client.stdout", "client.stderr", "startup.stdout", "startup.stderr")
        if (output / leaf).exists()
    }
    row = {"case_id": args.case_id, "run_id": args.run_id, "operation": "common_mapper_input_fault",
        "live_executed": process is not None, "input_fault_observation_valid": not errors, "errors": errors,
        "input_fault_receipt": receipt, "artifacts": {"input_fault_dir": str(output)}}
    private_json(output, "input-fault-source.json", {"cases": [row]})
    private_json(output, "input-fault-source.jsonl", row)
    for error in errors:
        print(error, file=sys.stderr)
    return not errors


def main():
    parser = BASE.argument_parser()
    for action in parser._actions:
        if action.dest == "case_id":
            action.choices = CASES
    parser.add_argument("--framework-root", required=True)
    parser.add_argument("--projection-parent", required=True)
    parser.add_argument("--fault-library", required=True)
    parser.add_argument("--worker-self-map-library", default=os.environ.get("NGX_NATIVE_WORKER_SELF_MAP_LIBRARY"))
    parser.add_argument("--fault-negative-control", action="store_true")
    args = parser.parse_args()
    try:
        return 0 if run(args) else 1
    except (OSError, ValueError) as exc:
        parser.exit(2, "input-fault boundary rejected: " + str(exc) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
