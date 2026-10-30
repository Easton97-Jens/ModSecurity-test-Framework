#!/usr/bin/env python3
"""Extract independently reviewable native HTX observations; never award PASS."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
from modsecurity_test_framework.connector_context import connector_root, test_root

# Load the maintained Parent filesystem boundary from this checkout.
import sys as _i12_sys

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths


EXECUTION_FILE = 'execution.json'
CASE_CONTRACT_FILE = 'case-contract.json'


HOST_CONFIG = 'haproxy.cfg'


RULES_FILE = 'rules.conf'


def read_bytes(path):
    """Admit metadata independently of its referenced filename, then pin the read."""
    path = Path(path)
    archive = os.environ.get('CODEX_CLEANUP_ARCHIVE_ROOT')
    if archive and (not Path(archive).is_absolute() or '..' in Path(archive).parts):
        raise ValueError('CODEX_CLEANUP_ARCHIVE_ROOT requires an absolute storage root')
    roots = (connector_root(), test_root(),
             *((Path(archive),) if archive else ()),
             *i12_paths._configured_roots())
    if (not path.is_absolute() or '..' in path.parts
            or any(part in {'.git', '.codex', '.aws', '.ssh', '.gnupg'} for part in path.parts)
            or not any(path != root and path.is_relative_to(root) for root in roots)):
        raise ValueError('sealed input outside approved evidence/source roots')
    try:
        return i12_paths._read_admitted(path, i12_paths.MAXIMUM_BYTES, require_owned_input=True)
    except OSError as error:
        raise ValueError('sealed input must be a physical absolute regular file') from error


def read_text(path):
    return read_bytes(path).decode('utf-8')


def sha(path):
    return hashlib.sha256(read_bytes(path)).hexdigest()


def reference(path, role):
    data = read_bytes(path)
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "role": role}


def load(path):
    return json.loads(read_bytes(path))


def require_hash(path, expected):
    if sha(Path(path)) != expected:
        raise ValueError("sealed input hash differs: " + str(path))


class Bindings:
    """Resolve namespace files only through controller-sealed source ledgers."""
    def __init__(self, spec):
        self.rows = []
        for item in spec["bindings"]:
            ledger_path = Path(item["ledger"])
            require_hash(ledger_path, item["ledger_sha256"])
            source, target = Path(item["source"]), Path(item["target"])
            if not source.is_absolute() or not target.is_absolute() or ".." in target.parts:
                raise ValueError("invalid namespace binding")
            ledger = load(ledger_path)
            if not isinstance(ledger.get("files"), dict):
                raise ValueError("sealed binding ledger has no file inventory")
            self.rows.append((source, target, ledger["files"], ledger_path))

    def resolve(self, namespace):
        path = Path(namespace)
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("invalid namespace path")
        matches = []
        for source, target, files, ledger in self.rows:
            if path.is_relative_to(target):
                relative = str(path.relative_to(target))
                if relative not in files:
                    raise ValueError("namespace image absent from sealed ledger")
                actual = source / relative
                require_hash(actual, files[relative])
                matches.append((actual, ledger))
        if len(matches) != 1:
            raise ValueError("namespace path has missing or ambiguous sealed binding")
        return matches[0]


def verified_source_binary(binary, source_receipt, provenance=None):
    receipt = load(source_receipt)
    binaries = receipt.get("binaries")
    if binaries is None:
        return {"receipt_format": "legacy", "source_receipt_sha256": sha(source_receipt)}
    if not isinstance(binaries, dict) or "direct" not in binaries:
        raise ValueError("current source receipt has no Direct binary")
    direct = binaries["direct"]
    expected = direct.get("sha256")
    source = Path(direct.get("path", ""))
    if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise ValueError("current build completion seal has an invalid Direct hash")
    try:
        require_hash(source, expected)
        require_hash(binary, expected)
    except ValueError as error:
        raise ValueError("executed Direct binary differs from current build completion seal") from error
    if provenance is not None:
        if provenance.get("build_completion_seal") != str(source_receipt):
            raise ValueError("source provenance names a different build completion seal")
        require_hash(source_receipt, provenance.get("build_completion_seal_sha256"))
        if provenance.get("product_and_capture_revision") != receipt.get("required_head"):
            raise ValueError("source provenance differs from build completion revision")
    return {"receipt_format": "current-completion-seal", "source_receipt_sha256": sha(source_receipt),
            "required_head": receipt.get("required_head"), "direct_binary_sha256": expected,
            "host_runs_before_capture": receipt.get("host_runs"), "runtime_qualified_before_capture": receipt.get("runtime_qualified")}


CONTROLLER_RESULT = 'controller-result.json'
FIXTURE_LAUNCH = '/mnt/fixtures/launch.py'


def verify_provenance_inventory(provenance, source_receipt, expected_paths):
    if set(load(source_receipt).get("binaries", {})) != {"direct", "agent", "companion"}:
        raise ValueError("build completion seal has an unexpected binary inventory")
    images = provenance.get("images")
    roles = [image.get("role") for image in images] if isinstance(images, list) else []
    expected_roles = {"direct", "agent", "companion", "native_engine"}
    if len(roles) != 4 or set(roles) != expected_roles or len(set(roles)) != len(roles):
        raise ValueError("current source provenance has an unexpected image inventory")
    by_role = {image["role"]: image for image in images}
    receipt = load(source_receipt)
    for role, actual in expected_paths.items():
        image = by_role[role]
        if Path(image.get("sealed_copy", "")) != actual:
            raise ValueError("source provenance sealed image differs from executed spec")
        require_hash(actual, image.get("sha256"))
        require_hash(Path(image.get("source", "")), image.get("sha256"))
        if role != "native_engine" and receipt["binaries"][role].get("sha256") != image.get("sha256"):
            raise ValueError("source provenance binary differs from build completion seal")
    return by_role


def verified_attempt_inputs(attempt, spec_path, fixture, binary, source_receipt):
    controller_path = attempt / CONTROLLER_RESULT
    controller = load(controller_path)
    require_hash(spec_path, controller["spec_sha256"])
    for key in ("executed_input_hashes_before", "executed_input_hashes_after"):
        if controller[key].get(str(spec_path)) != controller["spec_sha256"]:
            raise ValueError("controller does not bind explicit source spec")
    admission_path = attempt / "admission.original.json"
    require_hash(admission_path, controller["admission_sha256"])
    admission, spec = load(admission_path), load(spec_path)
    if admission["argv"] != spec["argv"]:
        raise ValueError("admitted argv differs from explicit source spec")
    if spec["argv"] != ["/usr/local/bin/python3", "-B", FIXTURE_LAUNCH]:
        raise ValueError("native host spec does not execute the sealed fixture entrypoint")

    bindings = Bindings(spec)
    direct, artifact_ledger = bindings.resolve("/mnt/artifacts/haproxy-direct")
    sdk, sdk_ledger = bindings.resolve("/mnt/artifacts/libmodsecurity.so.3")
    provenance_path, provenance_ledger = bindings.resolve("/mnt/artifacts/source-provenance.json")
    contract_path, fixture_ledger = bindings.resolve("/mnt/fixtures/case-contract.json")
    launch_path, launch_ledger = bindings.resolve(FIXTURE_LAUNCH)
    if direct != binary:
        raise ValueError("explicit Direct binary differs from executed sealed spec")
    if contract_path != fixture / CASE_CONTRACT_FILE:
        raise ValueError("explicit fixture differs from executed sealed spec")
    if launch_path != fixture / "launch.py" or launch_ledger != fixture_ledger:
        raise ValueError("executed fixture entrypoint differs from explicit sealed fixture")
    if len({artifact_ledger, sdk_ledger, provenance_ledger}) != 1:
        raise ValueError("artifact images do not share one sealed ledger")

    provenance = load(provenance_path)
    if provenance.get("schema") != "haproxy-i12-host-input-provenance-v1":
        raise ValueError("current host observation requires current source provenance")
    source_binding = verified_source_binary(binary, source_receipt, provenance)
    expected_paths = {
        "direct": direct,
        "agent": bindings.resolve("/mnt/artifacts/haproxy-spop")[0],
        "companion": bindings.resolve("/mnt/artifacts/haproxy")[0],
        "native_engine": sdk,
    }
    by_role = verify_provenance_inventory(provenance, source_receipt, expected_paths)
    return {
        "spec_sha256": controller["spec_sha256"],
        "admission_sha256": controller["admission_sha256"],
        "source_binary_binding": source_binding,
        "direct_binary": str(direct),
        "native_engine": str(sdk),
        "native_engine_sha256": by_role["native_engine"]["sha256"],
        "provenance": str(provenance_path),
        "provenance_sha256": sha(provenance_path),
        "artifact_ledger": str(artifact_ledger),
        "artifact_ledger_sha256": sha(artifact_ledger),
        "fixture_ledger": str(fixture_ledger),
        "fixture_ledger_sha256": sha(fixture_ledger),
    }


def resolve_sdk_image(namespace_path, attempt_binding):
    if namespace_path != "/mnt/artifacts/libmodsecurity.so.3":
        raise ValueError("unexpected loaded native engine namespace path")
    physical = Path(attempt_binding["native_engine"])
    require_hash(physical, attempt_binding["native_engine_sha256"])
    return {"namespace_path": namespace_path, "physical_path": str(physical), "sha256": sha(physical)}


def match_wire_segments(writes, wire):
    """Compare every positive host write with its contiguous actual client bytes."""
    cursor = 0
    segments = []
    for row in writes:
        count = row["actual_result"]
        if count > 0:
            segment = wire[cursor:cursor + count]
            actual = hashlib.sha256(segment).hexdigest()
            segments.append({"offset": cursor, "actual_host_write": row, "client_wire_segment_sha256": actual, "digest_matches": len(segment) == count and actual == row["positive_output_sha256"]})
            cursor += count
    return segments, cursor == len(wire)


def phase_transitions(native):
    transitions = []
    for enter in native:
        if enter["edge"] != "enter" or enter["function"] not in ("common_complete_phase", "common_finish", "common_cleanup"):
            continue
        returned = next((row for row in native if row["call"] == enter["call"] and row["edge"] == "return"), None)
        transitions.append({"function": enter["function"], "before": enter["contract_state"], "after": returned["contract_state"] if returned else None})
    return transitions


def select_main_allocation(allocated, client, contract):
    if "original_requirement_binding" not in contract:
        if len(allocated) != 2:
            raise ValueError("expected independent main and health-neighbor allocations")
        return allocated[0]
    candidates = [row for row in allocated if client["started_wall_ns"] <= row["wall_ns"] <= client["completed_wall_ns"]]
    if len(candidates) > 1:
        raise ValueError("main allocation association is ambiguous")
    return candidates[0] if candidates else None


def common_sink_rows(path, native_id, common_id):
    rows = [json.loads(line) for line in read_text(path).splitlines()]
    identities = {identity for identity in (native_id, common_id) if identity is not None}
    return {"all_physical_rows": rows,
            "exact_main_transaction_rows": [row for row in rows if row.get("transaction_id") in identities],
            "association": {"native_transaction_id": native_id, "common_transaction_id": common_id},
            "native_audit_is_not_common_sink": True}


def attach_supplemental_observations(observations, data, native_id, common_id, refs, backend, source_receipt):
    barrier = data / "client-first-body.json"
    if barrier.is_file():
        observations["commit_order"]["value"]["upstream_first_byte_barrier"] = {
            "actual_client": load(barrier),
            "actual_backend": [row for row in backend if row.get("kind", "").startswith("upstream_")],
            "backend_write_is_not_native_EOS": True,
        }
        observations["commit_order"]["evidence"].extend((reference(barrier, "client_process"), refs["backend"]))
    sink = data / "common-events.jsonl"
    if sink.is_file():
        physical = common_sink_rows(sink, native_id, common_id)
        sink_ref = reference(sink, "physical_event_sink")
        observations["native_events"]["value"]["physical_common_sink"] = physical
        observations["native_events"]["evidence"].append(sink_ref)
        observations["physical_event_order"]["value"]["physical_common_sink"] = physical
        observations["physical_event_order"]["evidence"].append(sink_ref)
        observations["terminal_event_count"]["value"]["physical_common_sink"] = physical
        observations["terminal_event_count"]["value"]["Common_Allow_reason"] = "Physical Common rows retained; Allow and terminal classification requires the independently reviewed product event contract."
        observations["terminal_event_count"]["evidence"].append(sink_ref)
    build_binding = source_receipt.parent.parent / "build-source-binding.json"
    if build_binding.is_file():
        observations["source_config_binding"]["evidence"].append(reference(build_binding, "source_manifest"))
        observations["source_config_binding"]["value"]["current_product_source_binding"] = load(build_binding)


def observe(attempt, fixture, binary, source_receipt, spec_path):
    data = attempt / "data"
    execution = load(data / EXECUTION_FILE)
    controller = load(attempt / CONTROLLER_RESULT)
    attempt_binding = verified_attempt_inputs(attempt, spec_path, fixture, binary, source_receipt)
    contract = load(fixture / CASE_CONTRACT_FILE)
    client = load(data / "main-client.json")
    neighbor = load(data / "neighbor-client.json")
    raw = [json.loads(line) for line in read_text(data / "native-api.jsonl").splitlines()]
    allocated = [row for row in raw if row["function"] == "host_allocation" and row["edge"] == "return" and row["result"] == 1]
    main_allocated = select_main_allocation(allocated, client, contract)
    scope = main_allocated["allocation_scope_call"] if main_allocated else None
    native = [row for row in raw if row["allocation_scope_call"] == scope] if scope is not None else []

    def calls(function, edge="return"):
        return [row for row in native if row["function"] == function and row["edge"] == edge]

    callbacks = [json.loads(line.split(" ", 1)[1]) for line in read_text(data / "haproxy.stderr").splitlines() if line.startswith("HAPROXY_")]
    eos = [row for row in callbacks if row.get("scope_call") == scope and row.get("kind", "").startswith("htx_")]
    writes = [row for row in callbacks if row.get("function") == "SSL_write" and client["started_wall_ns"] <= row["before_wall_ns"] <= client["completed_wall_ns"]]
    wire = read_bytes(data / "main-wire.bin")
    segments, wire_count_matches = match_wire_segments(writes, wire)
    backend = [json.loads(line) for line in read_text(data / "backend.jsonl").splitlines()]
    backend_requests = [row for row in backend if "method" in row]
    request_path = contract.get("request_path", "/i12-main")
    request_method = contract.get("request_method", "POST")
    main_backend = [row for row in backend_requests if row["path"] == request_path]
    native_new = calls("native_new_with_id")
    common_init = calls("common_init")
    native_id = native_new[0]["transaction_id"] if native_new else None
    common_id = common_init[0]["canonical_transaction_id"] if common_init else None
    audit = read_text(data / "native-audit.log")
    native_lines = [line for line in audit.splitlines() if f'[unique_id "{native_id}"]' in line]
    blocks = re.findall(r'^---([A-Za-z0-9]+)---A--\n([^\n]+)\n(.*?)^---\1---Z--', audit, re.M | re.S)
    request_line = f"{request_method} {request_path} HTTP/1.1"
    main_blocks = [block for block in blocks if native_id and (" " + native_id + " ") in block[1] and request_line in block[2]]
    rule_ids = {1999401, 1999404, 1999471, 1999472, 1999473}
    bound_rule = contract.get("original_requirement_binding", {}).get("original_oracle", {}).get("rule_id")
    if bound_rule is not None:
        rule_ids.add(bound_rule)
    counts = {str(rule): sum(f'[id "{rule}"]' in line for line in native_lines) for rule in sorted(rule_ids)}
    transitions = phase_transitions(native)
    command = next(row for row in execution["commands"] if row["label"] == "main-client")
    before = load(data / "before-main.fds.json")
    after = load(data / "after-main.fds.json")
    after_neighbor = load(data / "after-neighbor.fds.json")
    maps = read_text(data / "before-main.maps")
    loaded_sdk = sorted({line.split()[-1] for line in maps.splitlines() if "libmodsecurity.so" in line})
    sdk_images = [resolve_sdk_image(path, attempt_binding) for path in loaded_sdk]
    refs = {
        "api": reference(data / "native-api.jsonl", "native_api"),
        "host": reference(data / "haproxy.stderr", "host_callback"),
        "client": reference(data / "main-client.json", "client_process"),
        "client_commands": reference(data / EXECUTION_FILE, "client_process"),
        "neighbor": reference(data / "neighbor-client.json", "client_process"),
        "backend": reference(data / "backend.jsonl", "backend_process"),
        "audit": reference(data / "native-audit.log", "physical_event_sink"),
        "debug": reference(data / "native-debug.log", "native_debug"),
        "config": reference(data / HOST_CONFIG, "effective_configuration"),
        "rules": reference(data / RULES_FILE, "effective_configuration"),
        "contract": reference(fixture / CASE_CONTRACT_FILE, "source_contract"),
        "controller": reference(attempt / CONTROLLER_RESULT, "isolation_receipt"),
        "execution": reference(data / EXECUTION_FILE, "cleanup_observer"),
        "source": reference(source_receipt, "source_manifest"),
        "spec": reference(spec_path, "source_manifest"),
        "provenance": reference(Path(attempt_binding["provenance"]), "source_manifest"),
        "artifact_ledger": reference(Path(attempt_binding["artifact_ledger"]), "source_manifest"),
        "fixture_ledger": reference(Path(attempt_binding["fixture_ledger"]), "source_manifest"),
        "maps": reference(data / "before-main.maps", "loaded_image"),
        "identity": reference(data / "identity.stdout", "loaded_image"),
    }

    def known(value, *proof):
        return {"applicable": True, "value": value, "evidence": [refs[key] for key in proof]}

    observations = {
        "product_host_identity": known({"host_binary_sha256": sha(binary), "actual_loaded_SDK_images": sdk_images, "loaded_maps": maps, "identity": read_text(data / "identity.stdout")}, "maps", "identity", "controller"),
        "source_config_binding": known({"source_receipt_sha256": sha(source_receipt), "attempt_input_binding": attempt_binding, "effective_rules_sha256": sha(data / RULES_FILE), "effective_config_sha256": sha(data / HOST_CONFIG)}, "source", "spec", "provenance", "artifact_ledger", "fixture_ledger", "config", "rules"),
        "capability": known(contract, "contract", "host"),
        "client_exit": known(command["exit"], "client_commands"),
        "client_signal": known({"actual_signal": command["signal"], "actual_normal_exit": command["exit"] >= 0}, "client_commands"),
        "client_headers": known(client["headers"], "client"),
        "client_bytes": known(client["response_bytes"], "client"),
        "client_sha256": known(client["response_sha256"], "client"),
        "backend_request_count": known({"main": len(main_backend), "neighbor": sum(row["path"] == "/i12-neighbor" for row in backend_requests)}, "backend"),
        "backend_payload_identity": known(backend_requests, "backend", "client"),
        "client_backend_correlation": known({"main_backend": main_backend, "actual_client": client, "independent_backend_process": True}, "client", "backend"),
        "native_events": known({"native_id": native_id, "actual_lines": native_lines, "actual_rule_counts": counts}, "audit"),
        "native_api_returns": known(native, "api"),
        "native_transaction_id": known(native_id, "api"),
        "common_transaction_id": known(common_id, "api"),
        "observed_handle_association": known(main_allocated, "api"),
        "native_phases": known({phase: calls(phase) for phase in ("native_process_request_headers", "native_process_request_body", "native_process_response_headers", "native_process_response_body", "native_process_logging")}, "api", "debug"),
        "native_body_chunks": known({"request": calls("native_append_request_body"), "response": calls("native_append_response_body"), "native_append_has_no_EOS_argument": True}, "api"),
        "native_intervention_or_first_cause": known(calls("native_intervention"), "api"),
        "host_eos": known(eos, "host"),
        "native_eos": known({"request": calls("native_process_request_body"), "response": calls("native_process_response_body"), "not_inferred_from_client_close": True}, "api", "host"),
        "commit_order": known({"common_commit_calls": calls("common_set_response_committed"), "actual_SSL_writes": writes, "actual_client_first_receive": client["first_receive_wall_ns"], "client_wire_segments": segments, "host_positive_bytes_equal_client_wire": wire_count_matches}, "host", "client"),
        "mime_gate": known({"native_response_body_calls": calls("native_process_response_body"), "native_response_append_calls": calls("native_append_response_body"), "actual_native_mime_selection_rows": [row for row in native if row.get("native_mime_selection") is not None], "physical_P4_probe_count": counts["1999472"], "do_not_infer_MIME_from_HTTP_header_alone": True}, "debug", "audit"),
        "finish_calls": known({"native_logging": calls("native_process_logging"), "common_finish": calls("common_finish")}, "api"),
        "finish_transitions": known(transitions, "api"),
        "native_free_calls": known(calls("native_cleanup"), "api"),
        "cleanup_receipts": known({"native_final": raw[-1], "waits": execution["commands"], "survivors": controller["surviving_namespace_pids"]}, "execution", "controller"),
        "descriptor_cleanup": known({"before": before, "after_main": after, "after_neighbor": after_neighbor, "fd_targets_equal": before["fds"] == after["fds"] == after_neighbor["fds"]}, "execution"),
        "process_listener_cleanup": known({"surviving_namespace_pids": controller["surviving_namespace_pids"], "outside_mount_leaks": controller["outside_mount_leaks"], "supervisor_reaped": controller["supervisor_reaped"]}, "execution", "controller"),
        "neighbor_health": known(neighbor, "neighbor", "backend"),
        "transport_framing": known({key: client.get(key) for key in ("tls_version", "ssl_verifies_task_ca", "headers", "declared_content_length", "response_bytes", "body_complete", "termination", "ssl_reads", "actual_TLS_unwrap", "actual_raw_TCP_end")}, "client"),
        "transport_reset_scope": known({"actual_main": client.get("actual_raw_TCP_end"), "actual_neighbor": neighbor.get("actual_raw_TCP_end"), "no_synthesized_EOS": True}, "client", "host"),
        "host_action": known({"actual_client_status": client["status"], "actual_SSL_write_segments": segments, "all_segment_digests_match": bool(segments) and all(row["digest_matches"] for row in segments), "host_positive_bytes_equal_client_wire": wire_count_matches}, "client", "host"),
        "physical_event_order": known({"native_serial_A_Z_boundaries": [row[0] for row in main_blocks], "rule_counts": counts}, "audit"),
        "terminal_event_count": known({"native_main_serial_A_Z_records": len(main_blocks), "Common_Allow_physical_sink": None, "Common_Allow_reason": "No separately configured physical Common Allow sink; native audit and Common state remain separate."}, "audit"),
    }
    attach_supplemental_observations(observations, data, native_id, common_id, refs, backend, source_receipt)
    return {"run_scoped_case_id": contract.get("original_id") or contract["diagnostic_id"], "leg_id": "haproxy-native-htx", "run_id": raw[0]["run"], "execution_kind": "host_http", "execution_observed": True, "reviewed_by": "pending_root", "isolation_attempt_nonce": attempt.name.removeprefix("attempt-"), "effective_config_sha256": sha(data / HOST_CONFIG), "rules_sha256": sha(data / RULES_FILE), "source_bound_fixture_contract": contract, "oracle_evaluated": None, "outcome": None, "full_lifecycle_qualified": None, "observations": observations, "raw_artifacts": [{"path": str(path), "sha256": sha(path), "bytes": path.stat().st_size} for path in sorted(data.iterdir()) if path.is_file() and path.name not in ("tls.key", "tls.pem")]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("attempt", "fixture", "binary", "source-receipt", "spec", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    result = observe(args.attempt, args.fixture, args.binary, args.source_receipt, args.spec)
    i12_paths.create_text(args.output, json.dumps(result, indent=2) + "\n")
    print(json.dumps({"id": result["run_scoped_case_id"], "fields": len(result["observations"]), "full_lifecycle_qualified": None}))


if __name__ == "__main__":
    main()
