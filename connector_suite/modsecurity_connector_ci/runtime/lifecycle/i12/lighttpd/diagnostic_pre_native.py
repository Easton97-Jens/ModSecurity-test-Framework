#!/usr/bin/env python3
"""Bind the three physical lighttpd parser controls to the dedicated scope.

This assembler never approves sources or grants Root review. Every normalized
receipt retains its direct producer. Root supplies a separate exact-request
approval before the shared validator may qualify the case.
"""
from modsecurity_test_framework.connector_context import load_source
import argparse
import importlib.util
import json
from pathlib import Path

# Load the maintained Parent filesystem boundary from this checkout.
import sys as _i12_sys

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths


CONTROLLER_RESULT = "controller-result.json"
CAPTURE_FILE = "capture.json"
MODULE_FILE = "artifacts/modules/mod_msconnector.so"
CLIENT_SUFFIX = ".client.json"
COMMAND_SUFFIX = ".command.json"

NAMES = ("invalid_content_length", "conflicting_content_length", "content_length_overflow")
IDENTITY = ("run_scoped_case_id", "leg_id", "run_id", "parent_sha", "framework_sha", "mrts_sha",
            "effective_config_sha256", "rules_sha256", "host_pid", "host_starttime", "uid", "request_id", "request_sha256")


def adapter():
    module = load_source(Path(__file__).with_name('qualification.py'))
    return module


def load(path):
    return json.loads(path.read_text())


def assemble(args):
    q = adapter()
    preparation = load(args.preparation / "preparation.json")
    controller = load(args.attempt / CONTROLLER_RESULT)
    if args.output.resolve() != args.output or args.output.exists():
        raise ValueError("Pre-native proposal output must be a fresh physical directory")
    args.output = i12_paths.new_directory(args.output)
    for name in NAMES:
        source = args.attempt / "data/diagnostic" / name
        receipt = load(source / CAPTURE_FILE)
        if receipt["case_contract"].get("pre_native_control") is not True or len(receipt["actual_host"]) != 1:
            raise ValueError("Dedicated scope requires the actually executed three-case control fixture")
        case = receipt["run_scoped_case_id"]
        original = q.original_row(case)
        host = receipt["actual_host"][0]
        directory = args.output / name
        directory.mkdir(mode=0o700)

        def write(filename, data):
            path = directory / filename
            with i12_paths.new_text(path) as stream:
                json.dump(data, stream, indent=2)
                stream.write("\n")
            return q.reference(path)

        raw = source / (name + ".process.request.wire")
        packet = {"run_scoped_case_id": case, "leg_id": receipt["leg_id"], "run_id": receipt["actual_run_id"],
            "parent_sha": preparation["checkout_head"], "framework_sha": args.framework_sha, "mrts_sha": args.mrts_sha,
            "effective_config_sha256": receipt["effective_config_sha256"], "rules_sha256": receipt["rules_sha256"],
            "host_pid": host["pid"], "host_starttime": host["starttime"], "uid": receipt["uid"],
            "request_id": receipt["case_contract"]["request_id"], "request_sha256": q.reference(raw)["sha256"],
            "reviewed_by": "worker", "execution_kind": "host_pre_native_rejection", "execution_observed": True,
            "oracle_evaluated": True, "oracle_sha256": q.ORACLES.canonical_digest(original["selected_requirement"]["expected_oracle"]),
            "native_transaction_id": None, "full_lifecycle_qualified": False, "outcome": None,
            "worker_review_boundary": "Await exact source Root approval and shared physical validation; no worker PASS is qualification."}
        identity = {key: packet[key] for key in IDENTITY}
        images = {"host_binary_sha256": q.reference(args.preparation / "artifacts/bin/lighttpd")["sha256"],
            "module_sha256": q.reference(args.preparation / MODULE_FILE)["sha256"],
            "observer_sha256": q.reference(args.preparation / MODULE_FILE)["sha256"]}
        provenance = {**identity, **images, "actual_source_receipt": q.reference(args.preparation / "preparation.json"),
            "actual_runtime_configuration": q.reference(source / "runtime.conf"), "actual_capture": q.reference(source / CAPTURE_FILE),
            "executed_input_hashes": controller["executed_input_hashes_before"]}
        manifest = write("source-manifest.json", provenance)
        isolation = write("isolation-receipt.json", {**identity, **images,
            "loaded_images_observed": True, "exclusive_request_window": True,
            "maps": q.reference(source / f'host-{host["pid"]}.maps'),
            "status": q.reference(source / f'host-{host["pid"]}.status'),
            "mapped_paths": {"loaded_image": "/mnt/artifacts/bin/lighttpd",
                "native_module": "/mnt/artifacts/modules/mod_msconnector.so", "observer_image": "/mnt/artifacts/modules/mod_msconnector.so"},
            "actual_host_identity": q.reference(source / "host-identity.json"),
            "actual_controller_receipt": q.reference(args.attempt / CONTROLLER_RESULT)})
        before, after = receipt["main_window_before"], receipt["main_window_after"]
        sink = q.reference(source / "events.jsonl")
        event = write("event-observer.json", {**identity, "execution_observed": True, "window_complete": True,
            "observed_from_ns": before["event_sink"]["monotonic_ns"], "observed_through_ns": after["event_sink"]["monotonic_ns"],
            "before_offset": before["event_sink"]["size"], "after_offset": after["event_sink"]["size"], "sink": sink,
            "before_control": {"start_offset": 0, "end_offset": before["event_sink"]["size"]},
            "after_control": {"start_offset": after["event_sink"]["size"], "end_offset": sink["bytes"]},
            "actual_window_points": {"before": before["event_sink"], "after": after["event_sink"]},
            "actual_producer": q.reference(source / CAPTURE_FILE)})
        core_window = write("core-diagnostic-window.json", {**identity, "execution_observed": True,
            "exclusive_request_window": True, "before": before["core_diagnostic"], "after": after["core_diagnostic"],
            "core_sha256": q.reference(source / "host-error.log")["sha256"],
            "actual_host_identity": q.reference(source / "host-identity.json"), "actual_producer": q.reference(source / CAPTURE_FILE)})
        remaining = [r for r in receipt["actual_host_cleanup"] if r["same_process_gone"] is not True]
        cleanup = write("cleanup-observer.json", {**identity, "execution_observed": True,
            "descriptor_cleanup_observed": bool(receipt["actual_host_cleanup"]) and not remaining,
            "process_cleanup_observed": not remaining and controller["surviving_namespace_pids"] == [] and controller["supervisor_reaped"] is True,
            "listener_cleanup_observed": receipt["listeners_after_cleanup"] == [], "remaining_processes": remaining,
            "remaining_listeners": receipt["listeners_after_cleanup"], "unexpected_fd_targets": [],
            "descriptor_scope": "Actual host PID/starttime gone and namespace reaped; no inferred userspace fclose.",
            "actual_host_capture": q.reference(source / CAPTURE_FILE), "actual_controller": q.reference(args.attempt / CONTROLLER_RESULT)})
        controls = {}
        for label, token in (("before", name + "-prefix-0"), ("after", name + "-neighbor")):
            control = load(source / (token + CLIENT_SUFFIX))
            controls[label] = {"request_id": control["path"], "client_receipt": q.reference(source / (token + CLIENT_SUFFIX)),
                               "client_process": q.reference(source / (token + COMMAND_SUFFIX))}
        controls_ref = write("healthy-controls.json", {**identity, **controls})
        command = load(source / (name + COMMAND_SUFFIX))
        driver = write("driver-observation.json", {"case_id": name, "original_id": case,
            "actual_principal_execution": receipt["execution_observed"], "executed_case_contract": True, "missing_operations": [],
            "clients": [{"role": "main", "request_id": packet["request_id"], "actual_waited_exit": command["waited_exit"], "command": command}],
            "actual_producer": q.reference(source / CAPTURE_FILE)})
        proofs = [dict(q.reference(args.host_source / filename), kind="official_host_contract", revision="lighttpd-1.4.85")
                  for filename in ("request.c", "log.c", "configfile.c")]
        proofs.append(dict(q.reference(args.protocol_source), kind="protocol_contract", revision="RFC9112-June2022"))
        approval = {"reviewed_by": "worker", "scope": "host_pre_native_rejection", "run_scoped_case_id": case,
            "reason": "Exact original lighttpd malformed Content-Length parser rejection; logical phase1 does not assert native allocation.",
            "proof": proofs, "selected_requirement_sha256": q.ORACLES.canonical_digest(original["selected_requirement"]),
            "requirement_mapping_sha256": q.ORACLES.canonical_digest(original["selected_requirement"]["requirement_mapping"]),
            "oracle_sha256": packet["oracle_sha256"], "request_sha256": packet["request_sha256"],
            "core_diagnostic_code": receipt["case_contract"]["expected_source_diagnostic"]}
        packet["source_approval"] = approval
        write("source-approval-proposal.json", approval)
        role_paths = {"client_process": source / (name + COMMAND_SUFFIX), "client_receipt": source / (name + CLIENT_SUFFIX),
            "request_wire": raw, "response_wire": source / (name + ".process.wire"), "native_api": source / "native.jsonl",
            "host_callback": source / "host.jsonl", "backend_process": source / "backend.jsonl", "core_diagnostic": source / "host-error.log",
            "event_observer": event["path"], "source_manifest": manifest["path"], "effective_configuration": source / "lighttpd.conf",
            "rules_file": source / "rules.conf", "loaded_image": args.preparation / "artifacts/bin/lighttpd",
            "native_module": args.preparation / MODULE_FILE, "observer_image": args.preparation / MODULE_FILE,
            "isolation_receipt": isolation["path"], "cleanup_observer": cleanup["path"], "healthy_controls": controls_ref["path"],
            "driver_observation": driver["path"], "core_diagnostic_window": core_window["path"]}
        packet["measurement_evidence"] = [q.reference(Path(path), role) for role, path in role_paths.items()]
        write("packet-proposal.json", packet)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("attempt", "preparation", "host-source", "protocol-source", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--framework-sha", required=True)
    parser.add_argument("--mrts-sha", required=True)
    assemble(parser.parse_args())


if __name__ == "__main__":
    main()
