#!/usr/bin/env python3
"""Retain real bounded Phase-4 host observations, without synthetic events."""
from modsecurity_test_framework.connector_context import load_source
import hashlib
from functools import partial
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent


import importlib.util


def load(name, path):
    module = load_source(path)
    return module


HOST = load("phase4_owned_host", HERE / "run-nginx-valid-rules.py")
from modsecurity_connector_ci.runtime.common.nginx_phase4_upstream import BoundedPhase4Upstream
CLIENT_STDOUT = "client.stdout"


def _validated_receipt_metadata(receipt_metadata, observations):
    """Return closed adapter metadata after validating its source authority."""
    metadata = {} if receipt_metadata is None else receipt_metadata
    allowed = {"variant", "request_headers", "backend_contract_sha256", "backend_omission_contract_sha256"}
    if not isinstance(metadata, dict) or set(metadata) - allowed or set(metadata) & set(observations):
        raise ValueError("adapter receipt metadata is unknown or collides with runtime authority")
    for name, value in metadata.items():
        if name == "variant":
            if not isinstance(value, str) or value not in {"at255", "over256", "long-query"}:
                raise ValueError("adapter receipt variant must be a closed boundary identity")
        elif name == "request_headers":
            request_header_arguments({name: value})
        elif not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ValueError("adapter receipt source digest must be SHA256")
    return metadata


def write_source_result(output, observations, *, receipt_metadata=None, extra_capture_leaves=()):
    """Assemble closed adapter fields before the one exclusive receipt write."""
    metadata = _validated_receipt_metadata(receipt_metadata, observations)
    if (not isinstance(extra_capture_leaves, tuple) or len(extra_capture_leaves) > 1
            or any(leaf != "response-header-fixture.json" for leaf in extra_capture_leaves)):
        raise ValueError("adapter extra capture must be the closed MIME fixture leaf")
    captures = dict(observations["raw_sha256"])
    for leaf in extra_capture_leaves:
        path = output / leaf
        if leaf in captures or path.is_symlink() or not path.is_file():
            raise ValueError("adapter extra capture must be a fresh regular non-symlink leaf")
        captures[leaf] = HOST.BASE.digest(HOST.bounded_capture(path))
    receipt = dict(observations, raw_sha256=captures)
    receipt.update(metadata)
    HOST.write_json(output / "source-result.json", receipt)


def native_observations(raw, path):
    """Select only actual native response-body records matching this request."""
    events = [json.loads(line) for line in raw.splitlines() if line.strip()]
    if any(not isinstance(event, dict) for event in events):
        raise ValueError("native JSONL records must be objects")
    return [event for event in events if event.get("connector") == "nginx"
            and event.get("integration_mode") == "native-nginx-http-module"
            and event.get("phase") == "response_body"
            and event.get("method") == "GET" and event.get("uri") == path]


def configuration(output, port, upstream_port, projection, path, mode, run_id, *,
                  flush_response_headers=False):
    if mode not in {"off", "safe"}:
        raise ValueError("closed Phase-4 driver allows only existing off and safe contracts")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", run_id):
        raise ValueError("native transaction prefix must be bounded and configuration-safe")
    header_flush = "postpone_output 0; " if flush_response_headers else ""
    return (f'load_module "{output}/nginx-module.so";\n'
            'user nobody nogroup;\nworker_processes 1;\ndaemon off;\n'
            f'pid "{output}/nginx.pid";\nerror_log "{output}/nginx-error.log";\n'
            'events {}\nhttp { access_log off; modsecurity on;\n'
            f'modsecurity_transaction_id "{run_id}-$connection-$connection_requests";\n'
            f'modsecurity_rules_file "{output}/rules.conf";\n'
            f'modsecurity_phase4_mode {mode};\n'
            f'modsecurity_phase4_log "{output}/phase4-events.jsonl";\n'
            f'server {{ listen 127.0.0.1:{port}; root "{projection}";\n'
            f'location = {path} {{ proxy_pass http://127.0.0.1:{upstream_port}; '
            f'proxy_http_version 1.1; proxy_buffering off; {header_flush}}} }} }}\n')


def request_header_arguments(spec):
    """Return bounded literal header arguments for trusted closed adapters."""
    headers = spec.get("request_headers", {})
    if not isinstance(headers, dict) or len(headers) > 8:
        raise ValueError("closed request headers must be a mapping of at most eight fields")
    arguments = []
    total = 0
    for name, value in headers.items():
        if (not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}", name)
                or not isinstance(value, str) or len(value) > 256
                or any(ord(character) < 32 or ord(character) > 126 for character in value)):
            raise ValueError("closed request header has an invalid name/value or control byte")
        total += len(name) + len(value) + 2
        if total > 2048:
            raise ValueError("closed request headers exceed bounded total length")
        arguments.extend(("--header", name + ": " + value))
    return arguments


def actual_request(args, spec, output, environment, server):
    header_arguments = request_header_arguments(spec)
    body = output / "response.bin"
    # Retain an empty capture even when immediate rejection forwards no bytes.
    # Curl may otherwise omit its output file; a fresh exclusive leaf preserves
    # the distinction between observed zero bytes and an absent artifact.
    body.open("xb").close()
    with (output / CLIENT_STDOUT).open("wb") as out, (output / "client.stderr").open("wb") as err:
        client = subprocess.Popen(["/usr/bin/curl", "--noproxy", "*", "--http1.1", "--no-buffer", "--silent",
                                   "--show-error", "--max-time", "6", "--output", str(body),
                                   "--dump-header", str(output / "response.headers"),
                                   "--write-out", "%{http_code}",
                                   *header_arguments,
                                   f"http://127.0.0.1:{args.port}{spec['request_path']}"],
                                  env=environment, stdout=out, stderr=err)
        first_before_eos = False
        if spec["pause_between_chunks"]:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and client.poll() is None:
                if server.paused.is_set() and body.exists() and body.stat().st_size > 0:
                    first_before_eos = not server.eos_sent.is_set()
                    break
                time.sleep(0.02)
        server.release.set()
        try:
            exit_code = client.wait(timeout=7)
        except subprocess.TimeoutExpired:
            client.kill()
            exit_code = client.wait(timeout=2)
        server.finished.wait(6)
    raw_status = HOST.bounded_capture(output / CLIENT_STDOUT)
    return {"client_exit_code": exit_code,
            "observed_http_status": int(raw_status) if raw_status.isdigit() else None,
            "response_bytes_received": body.stat().st_size if body.exists() else 0,
            "first_body_byte_before_upstream_eos": first_before_eos,
            "upstream": server.observations()}


def run(args):
    framework = HOST.BASE.absolute_path(args.framework_root)
    input_path = framework / "tests/runners/nginx_phase4_contracts.py"
    contracts = load("phase4_closed_inputs", input_path)
    if args.case_id == "phase4_body_reject":
        # Flush the already committed headers before an immediate body Reject
        # aborts the connection; leave all other cases' scheduling unchanged.
        return run_operation(args, contracts.operation(args.case_id), input_path=input_path,
                             configuration_factory=partial(configuration, flush_response_headers=True))
    return run_operation(args, contracts.operation(args.case_id), input_path=input_path)


def run_operation(args, spec, *, input_path,
                  upstream_factory=BoundedPhase4Upstream,
                  upstream_kwargs=None, configuration_factory=configuration,
                  observation_factory=native_observations,
                  upstream_path=HERE.parent / "common/nginx_phase4_upstream.py",
                  receipt_metadata=None, extra_capture_leaves=()):
    """Run a prevalidated closed operation using actual source-bound adapters.

    Callers own specification validation and trusted source/helper selection.
    Factories only select the bounded actual upstream and native configuration;
    artifact, role and cleanup authority remains in this shared runtime.
    """
    binary, module, output = HOST.BASE.validate_inputs(args)
    if os.geteuid() != 0:
        raise ValueError("native host observation requires isolated root master/nobody worker")
    framework = HOST.BASE.absolute_path(args.framework_root)
    input_path = HOST.BASE.absolute_path(os.fspath(input_path))
    upstream_path = HOST.BASE.absolute_path(os.fspath(upstream_path))
    output.mkdir(mode=0o700)
    binary_sha = HOST.BASE.snapshot_artifact(binary, output / "nginx-binary", executable=True)
    module_sha = HOST.BASE.snapshot_artifact(module, output / "nginx-module.so", executable=False)
    (output / "rules.conf").write_text(spec["rules"])
    source = output / "docroot"
    source.mkdir(mode=0o700)
    for name in HOST.PROJECTION.PROJECTED_FILENAMES:
        (source / name).write_bytes(b"phase4-owned-static\n")
    parent = HOST.BASE.absolute_path(args.projection_parent)
    projection_name = "phase4-" + hashlib.sha256((args.run_id + ":" + args.case_id).encode()).hexdigest()[:24]
    projection = HOST.PROJECTION.prepare_projection(source_docroot=source, private_root=output,
        projection_parent=parent, projection_root=parent / projection_name, worker_gid=65534,
        avoid_roots=[output, HOST.BASE.PARENT_ROOT, framework])
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        args.port = reservation.getsockname()[1]
    environment = HOST.BASE.configtest_environment(args.library_dir)
    process = None
    handles = {}
    roles = {}
    observations = {}
    failure = None
    try:
        with upstream_factory(tuple(chunk.encode() for chunk in spec["response_chunks"]),
                              pause=spec["pause_between_chunks"], **(upstream_kwargs or {})) as server:
            config = output / "nginx.conf"
            config.write_text(configuration_factory(output, args.port, server.port, projection, spec["request_path"], spec["nginx_phase4_mode"], args.run_id))
            code, stdout, stderr, failure = HOST.BASE.invoke(
                [str(output / "nginx-binary"), "-e", "stderr", "-t", "-c", str(config), "-p", str(output) + "/"], environment)
            (output / "configtest.stdout").write_bytes(stdout)
            (output / "configtest.stderr").write_bytes(stderr)
            observations["configtest_exit_code"] = code
            if code != 0 or failure:
                raise ValueError("actual configtest failed")
            with (output / "startup.stdout").open("wb") as out, (output / "startup.stderr").open("wb") as err:
                process = subprocess.Popen([str(output / "nginx-binary"), "-e", "stderr", "-c", str(config),
                    "-p", str(output) + "/"], env=environment, stdout=out, stderr=err)
                roles = HOST.observe_roles(process, args.run_id, args.port, output, handles)
                observations.update(actual_request(args, spec, output, environment, server))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        failure = str(exc)
    finally:
        cleanup = HOST.stop_owned_master(process, roles, args.port, args.run_id, handles)
    events_path = output / "phase4-events.jsonl"
    raw = HOST.bounded_capture(events_path) if events_path.exists() else b""
    observations["native_events"] = observation_factory(raw, spec["request_path"])
    leaves = ("rules.conf", "nginx.conf", "configtest.stdout", "configtest.stderr",
              "startup.stdout", "startup.stderr", CLIENT_STDOUT, "client.stderr",
              "response.bin", "response.headers", "phase4-events.jsonl", "nginx-error.log")
    captures = {name: HOST.BASE.digest(HOST.bounded_capture(output / name))
                for name in leaves if (output / name).exists()}
    observations.update({"case_id": args.case_id, "run_id": args.run_id,
        "operation": spec["operation"], "source_record_id": spec["source_record_id"],
        "parent_sha": args.parent_sha,
        "framework_sha": args.framework_sha, "mrts_sha": args.mrts_sha,
        "binary_sha256": binary_sha, "module_sha256": module_sha,
        "raw_sha256": captures, "request_method": "GET", "request_path": spec["request_path"],
        "effective_phase4_mode": spec["nginx_phase4_mode"],
        "driver_sha256": HOST.BASE.digest(Path(__file__).read_bytes()),
        "closed_inputs_sha256": HOST.BASE.digest(input_path.read_bytes()),
        "upstream_driver_sha256": HOST.BASE.digest(upstream_path.read_bytes()),
        "docroot_projection_parent": str(parent), "docroot_projection_root": str(projection),
        "roles": roles, "cleanup": cleanup, "driver_error": failure,
        "canonical_status": "NOT_EXECUTED", "contract_validation_pending": True})
    write_source_result(output, observations, receipt_metadata=receipt_metadata,
                        extra_capture_leaves=extra_capture_leaves)
    return failure is None and cleanup["verified"]


def main():
    parser = HOST.BASE.argument_parser()
    parser.description = __doc__
    for action in parser._actions:
        if action.dest == "case_id":
            action.choices = None
    parser.add_argument("--projection-parent", required=True)
    parser.add_argument("--framework-root", required=True)
    try:
        return 0 if run(parser.parse_args()) else 1
    except (OSError, ValueError) as exc:
        print("phase4 input failure: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
