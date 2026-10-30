#!/usr/bin/env python3
"""Run closed real NGINX sequences, preserving native access/Engine evidence."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import load_source

import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from typing import NamedTuple

from modsecurity_connector_ci.runtime.lifecycle.nginx_sequence_client import capture_http11_wire, run_sequence
from modsecurity_connector_ci.runtime.lifecycle.nginx_sequence_upstream import FramingUpstream, SynchronizedUpstream, TRANSPORT_BODY

import importlib.util


def load(name, path):
    module = load_source(path)
    return module


HERE = Path(__file__).resolve().parent
STARTUP = load("nginx_sequence_startup", HERE / "run-nginx-valid-rules.py")
SELF_MAPS = load("nginx_sequence_self_maps", HERE / "nginx-worker-self-maps.py")
BASE = STARTUP.BASE
from modsecurity_connector_ci.lib.runtime_path_utils import open_private_runtime_root

SEQUENCES = {
    # Explicit producer schedules grouped only across adjacent equal inputs.
    # Keep invocation order and never obtain expectations from the validator.
    case_id: statuses
    for statuses, case_ids in (
        ((200,), ("single_request_cleanup",)),
        ((200, 403, 200), ("multiple_sequential_requests", "keep_alive_requests_if_supported")),
        ((200,), ("clean_shutdown",)),
        ((200, 200), ("keepalive_allow_allow",)),
        ((200, 403, 200), ("keepalive_allow_deny_allow",)),
        ((500,), ("early_mapping_failure_cleanup", "transaction_begin_failure_cleanup")),
        ((200,), ("phase4_strict_http1_client_abort",)),
        ((200, 200), ("phase4_strict_host_survives", "phase4_strict_followup_request_succeeds",
                      "keepalive_after_strict_new_connection", "keepalive_safe_followup")),
        ((200,), ("response_short_write_resume", "response_write_would_block_resume")),
        ((200, 200), ("transport_keep_alive",)),
        ((200, 403, 200), ("transport_sequential_requests",)),
        ((200,), ("finish_failure_propagation",)),
        ((504,), ("engine_timeout_before_commit",)),
        ((200,), ("engine_timeout_after_commit", "transport_http11_content_length", "transport_http11_chunked")),
    )
    for case_id in case_ids
}
KEEPALIVE = {"keep_alive_requests_if_supported", "keepalive_allow_allow", "keepalive_allow_deny_allow", "keepalive_safe_followup"}
KEEPALIVE.update({"transport_keep_alive", "transport_sequential_requests"})
STRICT = {"phase4_strict_http1_client_abort", "phase4_strict_host_survives",
          "phase4_strict_followup_request_succeeds", "keepalive_after_strict_new_connection"}
WRITE = {"response_short_write_resume", "response_write_would_block_resume"}
LATE = STRICT | {"keepalive_safe_followup"} | WRITE
DEADLINE = {"engine_timeout_before_commit", "engine_timeout_after_commit"}
FRAMING = {"transport_http11_content_length", "transport_http11_chunked"}
UPSTREAM_CASES = LATE | {"engine_timeout_after_commit", "transport_http11_chunked"}
RULES_LEAF = "no-crs-baseline.conf"
ACCESS_LEAF = "native-access.jsonl"
EVENTS_LEAF = "phase1-events.jsonl"
CONFIG_LEAF = "nginx.conf"
BINARY_LEAF = "nginx-binary"
MODULE_LEAF = "nginx-module.so"
BEGIN_LEDGER = "native-begin-observations.jsonl"
WRITE_LEDGER = "native-write-observations.jsonl"
FINISH_LEDGER = "native-finish-observations.jsonl"
BUDGET_LEDGER = "native-budget-observations.jsonl"
STATIC_LOCATION = 'location / { try_files $uri /index.html; }'
PROBE_LOCATION = 'location / { try_files /index.html =404; }'


class PreparedInvocation(NamedTuple):
    """Actual listener, child launch inputs, and completed config-test result."""
    port: int
    argv: list[str]
    environment: dict[str, str]
    fault_descriptor: int | None
    config_exit_code: int
    config_failure: str | None


class ExecutionOutcome(NamedTuple):
    """Observed execution and wire facts, without receipt or PASS projection."""
    observed: dict[str, object]
    wire: dict[str, object] | None
    post_roles: dict[str, int] | None
    upstream_observation: dict[str, object] | None
    failure: str | None
    live_executed: bool


class ReceiptContext(NamedTuple):
    """Snapshots, original config bytes, projection provenance and config exit."""
    hashes: dict[str, str]
    config: bytes
    projection_parent: Path
    projection_root: Path
    config_exit_code: int


def sequence_config(output, port, projection, case_id, fault_transaction=None, upstream_port=None, engine_budget_ms=10):
    # A sequence URI is a probe identity, not a docroot path.  Serve the fixed
    # projected body without an internal redirect so one request creates one
    # native transaction context and therefore one cleanup observation.
    text = STARTUP.config_template(output, port, str(projection)).replace(
        STATIC_LOCATION, PROBE_LOCATION)
    log = ('  log_format sequence escape=json \'{"uri":"$request_uri","status":$status,'
           '"connection":"$connection","connection_requests":$connection_requests,"remote_port":$remote_port,'
           '"transaction_id":"$request_id"}\';\n'
           f'  access_log "{output}/native-access.jsonl" sequence;\n'
           '  modsecurity_transaction_id "$request_id";')
    if case_id == "early_mapping_failure_cleanup":
        log = log.replace('modsecurity_transaction_id "$request_id";',
                          'modsecurity_transaction_id "$http_x_modsec_test_transaction";')
    if case_id == "transaction_begin_failure_cleanup":
        log = log.replace("$request_id", fault_transaction)
    if case_id in DEADLINE | FRAMING | {"finish_failure_propagation"}:
        log = log.replace("$request_id", "$sequence_transaction_id")
        log = ('  map $request_uri $sequence_transaction_id { default $request_id; '
               f'"/no-crs/sequence/{fault_transaction[:24]}/0" "{fault_transaction}"; }}\n' + log)
    if case_id in DEADLINE:
        if type(engine_budget_ms) is not int or engine_budget_ms not in (0, 10, 100):
            raise ValueError("budget probe permits only disabled, exceeded and under-budget controls")
        log += f"\n  modsecurity_engine_call_budget_ms {engine_budget_ms};"
    if case_id in FRAMING:
        log += "\n  types { }\n  default_type text/plain;"
        if case_id not in UPSTREAM_CASES:
            log += "\n  modsecurity_phase4_mode safe;"
    if case_id in UPSTREAM_CASES:
        mode = "strict" if case_id in STRICT else "safe"
        log += f"\n  modsecurity_phase4_mode {mode};"
        text = text.replace(PROBE_LOCATION,
                            'location / { proxy_buffering off; proxy_http_version 1.1; '
                            f'proxy_pass http://127.0.0.1:{upstream_port}; }}')
    return text.replace("  access_log off;", log).encode()


def private_json(output, leaf, value):
    if leaf not in {"sequence-observation.json", "sequence-source.json", "sequence-source.jsonl"}:
        raise ValueError("unrecognized sequence artifact")
    raw = json.dumps(value, sort_keys=True) + "\n"
    with open_private_runtime_root(output) as root:
        root.create_text(leaf, raw, "NGINX sequence observation")
    return raw.encode()


def begin_ledger_environment(output, environment, transaction, negative_control):
    """Preopen a private Root-owned descriptor; the fixture validates it again."""
    descriptor = os.open(output / BEGIN_LEDGER,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    mismatch = transaction[:-1] + ("0" if transaction[-1] != "0" else "1")
    environment.update(MSCONNECTOR_OWNED_BEGIN_FAULT="one-native-allocation-failure",
                       MSCONNECTOR_OWNED_BEGIN_TXID=mismatch if negative_control else transaction,
                       MSCONNECTOR_OWNED_BEGIN_FD=str(descriptor))
    return descriptor


def native_source_observations(output, case_id):
    """Retain every original source event, including errors and cleanup."""
    event_path = output / EVENTS_LEAF
    result = {"native_events": [json.loads(line) for line in STARTUP.bounded_capture(event_path).splitlines()
                                if line.strip()] if event_path.exists() else []}
    if case_id == "transaction_begin_failure_cleanup":
        result["native_begin"] = [json.loads(line) for line in STARTUP.bounded_capture(
            output / BEGIN_LEDGER).splitlines() if line.strip()]
    return result


def read_access(output, count):
    path = output / ACCESS_LEAF
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if path.exists():
            rows = [json.loads(line) for line in STARTUP.bounded_capture(path).splitlines() if line.strip()]
            if len(rows) >= count:
                return rows
        time.sleep(0.02)
    raise ValueError("native access records did not reach the required request count")


def configure_timeout_rules(output):
    """Bind the receipt to the effective technical probe rules, after removal."""
    path = output / RULES_LEAF
    with path.open("ab") as configured:
        configured.write(b"\n# Technical soft-budget probe has no rule-deny premise.\nSecRuleRemoveById 1100301\n")
    return BASE.digest(STARTUP.bounded_capture(path))


def validate_sequence_controls(args):
    if args.fault_negative_control and args.case_id not in WRITE | DEADLINE | {"transaction_begin_failure_cleanup", "finish_failure_propagation"}:
        raise ValueError("fault negative control requires its exact native fixture case")
    engine_budget_ms = getattr(args, "engine_call_budget_ms", 10)
    if engine_budget_ms != 10 and args.case_id not in DEADLINE:
        raise ValueError("engine budget controls require their exact timeout fixture case")
    if os.geteuid() != 0:
        raise ValueError("sequence operation requires isolated Root master and nobody worker")
    return engine_budget_ms


def prepare_sequence_assets(binary, module, output, framework, case_id):
    rules = framework / "tests/rules" / RULES_LEAF
    output.mkdir(mode=0o700)
    (output / "logs").mkdir(mode=0o700)
    hashes = {
        "binary_sha256": BASE.snapshot_artifact(binary, output / BINARY_LEAF, executable=True),
        "module_sha256": BASE.snapshot_artifact(module, output / MODULE_LEAF, executable=False),
        "rules_sha256": BASE.snapshot_artifact(rules, output / RULES_LEAF, executable=False),
    }
    if case_id in DEADLINE:
        hashes["rules_sha256"] = configure_timeout_rules(output)
    source = output / "docroot"
    source.mkdir(mode=0o700)
    for name in STARTUP.PROJECTION.PROJECTED_FILENAMES:
        (source / name).write_bytes(TRANSPORT_BODY if case_id in FRAMING else b"bounded-owned-sequence\n")
    return hashes, source


def prepare_sequence_projection(args, source, output, parent, framework):
    identity = hashlib.sha256((args.run_id + ":" + args.case_id).encode()).hexdigest()
    token = identity[:24]
    projection = STARTUP.PROJECTION.prepare_projection(
        source_docroot=source, private_root=output, projection_parent=parent,
        projection_root=parent / ("sequence-" + token), worker_gid=65534,
        avoid_roots=[output, BASE.PARENT_ROOT, framework])
    return identity, token, projection


def sequence_upstream(case_id, token):
    if case_id == "transport_http11_chunked":
        return FramingUpstream(f"/no-crs/sequence/{token}/0")
    if case_id in UPSTREAM_CASES:
        return SynchronizedUpstream(backpressure=case_id == "response_write_would_block_resume")
    return None


def snapshot_fault(args, output, hashes, leaf, missing_message):
    if args.fault_library is None:
        raise ValueError(missing_message)
    hashes["fault_library_sha256"] = BASE.snapshot_artifact(
        BASE.absolute_path(args.fault_library), output / leaf, executable=False)
    return str(output / leaf)


def prepare_write_fault(args, output, token, port, environment, hashes):
    preload = snapshot_fault(args, output, hashes, "native-write-fault.so",
        "write-resume operation requires its bounded native fixture library")
    descriptor = os.open(output / WRITE_LEDGER, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
    environment["LD_PRELOAD"] = preload
    environment["MSCONNECTOR_OWNED_WRITE_FAULT"] = "short_write" if args.case_id == "response_short_write_resume" else "write_would_block"
    if args.fault_negative_control:
        environment["MSCONNECTOR_OWNED_WRITE_FAULT"] = "disabled"
    environment["MSCONNECTOR_OWNED_WRITE_URI"] = f"/no-crs/sequence/{token}/0"
    environment["MSCONNECTOR_OWNED_WRITE_PORT"] = str(port)
    environment["MSCONNECTOR_OWNED_WRITE_FD"] = str(descriptor)
    return descriptor


def prepare_transaction_fault(args, output, identity, environment, hashes):
    finishing = args.case_id == "finish_failure_propagation"
    leaf = "native-finish-fault.so" if finishing else "native-budget-fault.so"
    message = ("post-response finish failure requires its exact owned native fixture" if finishing else
               "deadline case requires its scoped post-return delay fixture")
    preload = snapshot_fault(args, output, hashes, leaf, message)
    descriptor = os.open(output / (FINISH_LEDGER if finishing else BUDGET_LEDGER),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    transaction = identity[:32]
    mismatch = transaction[:-1] + ("0" if transaction[-1] != "0" else "1")
    environment["LD_PRELOAD"] = preload
    prefix = "MSCONNECTOR_OWNED_FINISH" if finishing else "MSCONNECTOR_OWNED_BUDGET"
    environment[prefix + "_TXID"] = mismatch if args.fault_negative_control else transaction
    environment[prefix + "_FD"] = str(descriptor)
    if not finishing:
        environment[prefix + "_PHASE"] = "1" if args.case_id == "engine_timeout_before_commit" else "4"
    return descriptor


def prepare_sequence_fault(args, output, identity, token, port, environment, hashes):
    if args.case_id == "transaction_begin_failure_cleanup":
        environment["LD_PRELOAD"] = snapshot_fault(args, output, hashes, "native-transaction-fault.so",
            "native begin-failure operation requires its bounded fixture library")
        transaction = identity[:32]
        return begin_ledger_environment(output, environment, transaction, args.fault_negative_control)
    if args.case_id in WRITE:
        return prepare_write_fault(args, output, token, port, environment, hashes)
    if args.case_id == "finish_failure_propagation" or args.case_id in DEADLINE:
        return prepare_transaction_fault(args, output, identity, environment, hashes)
    if args.fault_library is not None:
        raise ValueError("fault fixture is only authorized for its exact native boundary case")
    return None


def capture_sequence_wire(args, output, port, token):
    """Publish captured facts before parsing can reject the actual response."""
    if args.case_id not in FRAMING:
        return None, None
    request_wire, response_wire = capture_http11_wire(port, f"/no-crs/sequence/{token}/0")
    for leaf, raw in (("request-wire.bin", request_wire), ("response-wire.bin", response_wire)):
        with (output / leaf).open("xb") as capture:
            capture.write(raw)
    wire = {"request_hex": request_wire.hex(), "response_hex": response_wire.hex(), "eof_seen": True}
    return wire, response_wire


def capture_sequence_requests(args, port, token, upstream, validator, response_wire):
    statuses = SEQUENCES[args.case_id]
    paths = [f"/no-crs/sequence/{token}/{index}" for index in range(len(statuses))]
    if args.case_id not in FRAMING:
        observations = run_sequence(port, paths, statuses, keepalive=args.case_id in KEEPALIVE,
            headers_seen=upstream.headers_seen if upstream is not None else None,
            expect_first_abort=args.case_id in STRICT | {"engine_timeout_after_commit"},
            backpressure=args.case_id == "response_write_would_block_resume")
        return observations
    parsed = validator.WIRE.parse_http11_response(response_wire)
    parsed.pop("body")
    return [dict(parsed, path=paths[0], transport_result="completed", client_error=None)]


def execute_sequence(args, output, token, upstream, validator,
                     invocation: PreparedInvocation, worker_maps=None) -> ExecutionOutcome:
    port, argv, environment, write_fd, exit_code, failure = invocation
    if worker_maps is None:
        worker_maps = prepare_worker_maps(args, output, environment, {}, write_fd)
    roles = {"master_pid": 0, "worker_pid": 0, "master_uid": -1, "worker_uid": -1}
    process, handles = None, {}
    observations, access = [], []
    wire_observation = None
    post_roles = None
    upstream_observation = None
    client_exit = None
    try:
        if failure or exit_code != 0:
            raise ValueError("native config acceptance is required before sequence")
        if upstream is not None:
            upstream.start()
        with (output / "startup.stdout").open("xb") as out, (output / "startup.stderr").open("xb") as err:
            process = subprocess.Popen(argv, env=environment, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                       pass_fds=worker_maps.descriptors(write_fd))
            roles = STARTUP.observe_roles(process, args.run_id, port, output, handles)
            worker_maps.capture(roles)
            wire_observation, response_wire = capture_sequence_wire(args, output, port, token)
            observations = capture_sequence_requests(args, port, token, upstream, validator, response_wire)
            client_exit = 0
            access = read_access(output, len(SEQUENCES[args.case_id]))
            post_roles = STARTUP.observe_roles(process, args.run_id, port, output, handles)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        failure = str(exc)
        client_exit = 1
    finally:
        try:
            cleanup = STARTUP.stop_owned_master(process, roles, port, args.run_id, handles)
            if upstream is not None:
                upstream_observation = upstream.observation()
                upstream.stop()
        finally:
            try:
                worker_maps.close()
            finally:
                if write_fd is not None:
                    try:
                        os.fsync(write_fd)
                    finally:
                        os.close(write_fd)
    observed = {"schema_version": 1, "operation": "request_sequence", "protocol": "http1",
                "case_id": args.case_id, "run_id": args.run_id, "client_exit_code": client_exit,
                "requests": observations, "native_access": access, "roles": roles, "cleanup": cleanup}
    return ExecutionOutcome(observed, wire_observation, post_roles, upstream_observation,
                            failure, process is not None)


def add_sequence_observations(args, output, outcome: ExecutionOutcome, upstream, engine_budget_ms):
    observed = outcome.observed
    wire_observation, post_roles = outcome.wire, outcome.post_roles
    upstream_observation = outcome.upstream_observation
    if args.case_id in FRAMING:
        observed["wire"] = wire_observation
        observed["post_sequence_roles"] = post_roles
        if upstream is not None:
            observed["upstream_wire"] = upstream_observation
            for field, leaf in (("request_hex", "upstream-request-wire.bin"),
                                ("response_hex", "upstream-response-wire.bin")):
                with (output / leaf).open("xb") as capture:
                    capture.write(bytes.fromhex(upstream_observation[field]))
    if args.case_id in UPSTREAM_CASES - FRAMING:
        observed["upstream_barrier"] = upstream_observation
        observed["post_sequence_roles"] = post_roles
    observed.update(native_source_observations(output, args.case_id))
    add_native_fault_observations(args, output, observed, engine_budget_ms)


def ledger_rows(output, leaf):
    return [json.loads(line) for line in STARTUP.bounded_capture(output / leaf).splitlines() if line.strip()]


def add_native_fault_observations(args, output, observed, engine_budget_ms):
    if args.case_id in WRITE:
        observed["native_writes"] = ledger_rows(output, WRITE_LEDGER)
    if args.case_id == "finish_failure_propagation":
        observed["native_finish"] = ledger_rows(output, FINISH_LEDGER)
    if args.case_id in DEADLINE:
        observed["budget_ms"] = engine_budget_ms
        budget_rows = ledger_rows(output, BUDGET_LEDGER)
        cleanup_operation = "msconnector_transaction_contract_cleanup"
        observed["native_budget"] = [row for row in budget_rows if row.get("native_operation") != cleanup_operation]
        observed["native_cleanup"] = [row for row in budget_rows if row.get("native_operation") == cleanup_operation]
    fault_contracts = {
        "early_mapping_failure_cleanup": ("early_mapping_failure", "ModSecurity: invalid canonical transaction identifier"),
        "transaction_begin_failure_cleanup": ("transaction_begin_failure", "ModSecurity: failed to create transaction"),
        "finish_failure_propagation": ("finish_failure", "ModSecurity: native logging phase processing failed"),
    }
    if args.case_id in fault_contracts:
        requested, diagnostic = fault_contracts[args.case_id]
        native_error = STARTUP.bounded_capture(output / "nginx-error.log")
        triggered = diagnostic.encode() in native_error
        observed["fault"] = {"requested": requested, "triggered": triggered,
                             "native_diagnostic": diagnostic if triggered else None}


def sequence_receipt(args, output, context: ReceiptContext, observed_raw, client_exit):
    receipt = dict(context.hashes, schema_version=1, case_id=args.case_id, run_id=args.run_id,
                   operation="request_sequence", parent_sha=args.parent_sha,
                   framework_sha=args.framework_sha, mrts_sha=args.mrts_sha,
                   observed_exit_code=context.config_exit_code, client_exit_code=client_exit,
                   observed_sha256=BASE.digest(observed_raw), config_sha256=BASE.digest(context.config),
                   native_access_sha256=BASE.digest(STARTUP.bounded_capture(output / ACCESS_LEAF))
                       if (output / ACCESS_LEAF).exists() else None,
                   projection_parent=str(context.projection_parent), projection_root=str(context.projection_root))
    for key, leaf in {"events_sha256": EVENTS_LEAF, "worker_maps_sha256": "worker-maps.log",
                      "worker_self_maps_sha256": SELF_MAPS.LEDGER,
                      "native_writes_sha256": WRITE_LEDGER,
                      "native_finish_sha256": FINISH_LEDGER,
                      "native_begin_sha256": BEGIN_LEDGER,
                      "native_budget_sha256": BUDGET_LEDGER,
                      "request_wire_sha256": "request-wire.bin", "response_wire_sha256": "response-wire.bin",
                      "upstream_request_wire_sha256": "upstream-request-wire.bin",
                      "upstream_response_wire_sha256": "upstream-response-wire.bin"}.items():
        path = output / leaf
        if path.exists():
            receipt[key] = BASE.digest(STARTUP.bounded_capture(path))
    return receipt


def publish_sequence_source(args, output, live_executed, receipt, errors):
    # Host-only evidence is not Canonical PASS for transport event contracts.
    row = {"case_id": args.case_id, "run_id": args.run_id, "live_executed": live_executed,
           "operation": "request_sequence", "sequence_observation_valid": not errors,
           "errors": errors, "sequence_receipt": receipt, "artifacts": {"sequence_dir": str(output)}}
    private_json(output, "sequence-source.json", {"cases": [row]})
    private_json(output, "sequence-source.jsonl", row)
    for error in errors:
        print(error, file=sys.stderr)
    return not errors


def prepare_worker_maps(args, output, environment, hashes, fault_descriptor):
    try:
        return SELF_MAPS.Capture(args, output, environment, hashes, STARTUP)
    except BaseException:
        if fault_descriptor is not None:
            os.close(fault_descriptor)
        raise


def configtest_invocation(output, port, argv, environment, fault_descriptor, worker_maps):
    try:
        exit_code, stdout, stderr, failure = BASE.invoke(argv + ["-t"], environment)
        (output / "configtest.stdout").write_bytes(stdout)
        (output / "configtest.stderr").write_bytes(stderr)
        return PreparedInvocation(port, argv, environment, fault_descriptor, exit_code, failure)
    except BaseException as original_error:
        try:
            try:
                worker_maps.close()
            finally:
                if fault_descriptor is not None:
                    os.close(fault_descriptor)
        except OSError as cleanup_error:
            raise original_error from cleanup_error
        raise


def run(args):
    binary, module, output = BASE.validate_inputs(args)
    engine_budget_ms = validate_sequence_controls(args)
    framework = BASE.absolute_path(args.framework_root)
    validator = load("nginx_sequence_contract", framework / "tests/runners/nginx_lifecycle_sequence.py")
    parent = BASE.absolute_path(args.projection_parent)
    hashes, source = prepare_sequence_assets(binary, module, output, framework, args.case_id)
    identity, token, projection = prepare_sequence_projection(args, source, output, parent, framework)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    upstream = sequence_upstream(args.case_id, token)
    config = sequence_config(output, port, projection, args.case_id, identity[:32],
                             upstream.port if upstream is not None else None, engine_budget_ms)
    (output / CONFIG_LEAF).write_bytes(config)
    environment = BASE.configtest_environment(args.library_dir)
    write_fd = prepare_sequence_fault(args, output, identity, token, port, environment, hashes)
    worker_maps = prepare_worker_maps(args, output, environment, hashes, write_fd)
    argv = [str(output / BINARY_LEAF), "-e", "stderr", "-c", str(output / CONFIG_LEAF), "-p", str(output) + "/"]
    invocation = configtest_invocation(output, port, argv, environment, write_fd, worker_maps)
    exit_code = invocation.config_exit_code
    outcome = execute_sequence(args, output, token, upstream, validator, invocation, worker_maps)
    add_sequence_observations(args, output, outcome, upstream, engine_budget_ms)
    errors = validator.observation_errors(outcome.observed, args.case_id, args.run_id)
    if outcome.failure:
        errors.append(outcome.failure)
    observed_raw = private_json(output, "sequence-observation.json", outcome.observed)
    context = ReceiptContext(hashes, config, parent, projection, exit_code)
    receipt = sequence_receipt(args, output, context, observed_raw, outcome.observed["client_exit_code"])
    return publish_sequence_source(args, output, outcome.live_executed, receipt, errors)


def main():
    parser = BASE.argument_parser()
    for action in parser._actions:
        if action.dest == "case_id":
            action.choices = tuple(SEQUENCES)
    parser.add_argument("--framework-root", required=True)
    parser.add_argument("--projection-parent", required=True)
    parser.add_argument("--fault-library")
    parser.add_argument("--worker-self-map-library", default=os.environ.get("NGX_NATIVE_WORKER_SELF_MAP_LIBRARY"))
    parser.add_argument("--engine-call-budget-ms", type=int, choices=(0, 10, 100), default=10,
                        help="Timeout probes: 10ms positive; 0ms disabled or 100ms under-budget controls must fail timeout validation")
    parser.add_argument("--fault-negative-control", action="store_true",
                        help="Deliberately mismatch the owned fault transaction; must not satisfy the fault case")
    args = parser.parse_args()
    try:
        return 0 if run(args) else 1
    except (OSError, ValueError) as exc:
        parser.exit(2, "sequence boundary rejected: " + str(exc) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
