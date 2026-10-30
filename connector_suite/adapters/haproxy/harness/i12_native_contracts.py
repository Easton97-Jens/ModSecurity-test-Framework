#!/usr/bin/env python3
"""Bind frozen native I12 originals before execution using the existing capture.

This is preparation, not a second runner or a qualifier. Unavailable host fault,
deadline, native-file and physical-sink contracts remain explicit gaps. Every
generated fixture still requires a fresh source-bound host and Root review.
"""
import argparse
import copy
import hashlib
import json
import os
import stat
from pathlib import Path

import yaml

import connector_suite.adapters.haproxy.harness.i12_native_cases as fixtures
from connector_suite.adapters.haproxy.harness.i12_oracle_fixture import source_hash_map

SOURCE_ROOT = Path("/var") / "tmp" / "codex" / "ModSecurity-conector"
LEG = "haproxy-native-htx"
ORIGINAL_IDS_SHA256 = "bb34ce6c26063b1c13df6087b0a3cc5034f227216720aeaca2f195fba38b33d1"
ORIGINAL_CONTRACTS_SHA256 = "f4ca4e4b97cf3cf5dd267684afdfa39a8fd5b9e8b88b71bf6470cb184ce7ea3b"
SDK_TRANSACTION_SHA256 = "328ffa3b4517f0242450293a916aba4f512b4defc3bd1fcc7465e0778adc725c"
P4_MARKER = b"no-crs-response-body-marker"
CANONICAL_RULE_PREFIX = "# Native core probe compatibility:"
SPECIAL_CASES = {
    "body_size_nonzero_with_null_data": "actual_caller_null_body_fault_required",
    "header_count_nonzero_with_null_headers": "actual_caller_null_headers_fault_required",
    "early_mapping_failure_cleanup": "actual_caller_mapping_fault_required",
    "transaction_begin_failure_cleanup": "actual_native_allocation_fault_required",
    "finish_failure_propagation": "actual_common_finish_fault_required",
    "engine_timeout_before_commit": "synchronous_native_engine_deadline_contract_required",
    "engine_timeout_after_commit": "synchronous_native_engine_deadline_contract_required",
    "response_short_write_resume": "actual_host_short_write_capture_delta_required",
    "response_write_would_block_resume": "actual_host_EAGAIN_capture_delta_required",
    "keep_alive_requests_if_supported": "multi_request_same_TLS_connection_driver_required",
    "multiple_sequential_requests": "allow_deny_allow_main_sequence_driver_required",
    "phase4_deny_after_commit_log_only_minimal": "source_bound_minimal_mode_vs_supported_safe_mode_contract_required",
    "event_metadata_truncation": "physical_common_event_metadata_limit_fixture_required",
    "event_json_limit": "physical_common_event_json_size_boundary_required",
}
NAMED_GAPS = {
    "request-file": "original_native_file_API_vs_file_sourced_HTTP_contract_unresolved",
    "response-file": "native_response_file_API_not_present_in_loaded_SDK_contract",
    "request-above-former-connector-limit": "historical_former_request_threshold_source_required",
    "response-above-former-connector-limit": "historical_former_response_threshold_source_required",
    "invalid-native-return": "actual_host_native_return_fault_required",
    "invalid-metadata": "actual_host_metadata_fault_required",
    "missing-eos": "actual_host_incomplete_EOS_driver_required",
    "timeout": "source_bound_timeout_kind_and_driver_required",
    "cancel": "actual_client_cancel_and_host_native_cause_driver_required",
    "incomplete-framing": "actual_client_partial_request_and_terminal_observer_required",
    "abort-reset-observation": "actual_reset_and_healthy_neighbor_driver_required",
}


def digest(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(data).hexdigest()


def source_descriptor(path):
    """Pin each directory without ever reopening an untrusted full path."""
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("physical absolute source path required")
    relative = path.relative_to(SOURCE_ROOT)
    if not relative.parts:
        raise ValueError("source file beneath storage required")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open("/", directory_flags)
    try:
        for component in SOURCE_ROOT.parts[1:]:
            child = os.open(component, directory_flags, dir_fd=parent)
            os.close(parent)
            parent = child
        status = os.fstat(parent)
        if status.st_uid != os.getuid() or status.st_mode & 0o022:
            raise ValueError("source storage anchor must be privately owned")
        for component in relative.parts[:-1]:
            child = os.open(component, directory_flags, dir_fd=parent)
            os.close(parent)
            parent = child
        return os.open(relative.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)


def read_source(path):
    descriptor = source_descriptor(path)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("regular admitted source file required")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            return source.read()
    finally:
        os.close(descriptor)


def reference(path, role):
    data = read_source(path)
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "role": role}


def native_rows(inventory):
    ids = "\n".join(row["run_scoped_case_id"] for row in inventory["rows"]) + "\n"
    selected = [row["original_selected_requirement"] for row in inventory["rows"]]
    if hashlib.sha256(ids.encode()).hexdigest() != ORIGINAL_IDS_SHA256 or digest(selected) != ORIGINAL_CONTRACTS_SHA256:
        raise ValueError("frozen original inventory identity differs")
    rows = [row for row in inventory["rows"] if row["leg_id"] == LEG]
    if len(rows) != 112 or len({row["run_scoped_case_id"] for row in rows}) != 112:
        raise ValueError("exact 112 native original IDs required")
    for row in rows:
        if digest(row["original_selected_requirement"]) != row["original_selected_requirement_sha256"]:
            raise ValueError("original selected requirement hash differs")
        if row["run_scoped_case_id"] != "I12::" + LEG + "::" + row["original_selected_requirement"]["case_id"]:
            raise ValueError("original ID and requirement case differ")
    return rows


def resolve_request(name, catalog, seen=()):
    if name in seen:
        raise ValueError("catalog request reuse cycle")
    request = copy.deepcopy(catalog[name]["request"])
    if "reuses" in request:
        base = resolve_request(request.pop("reuses"), catalog, (*seen, name))
        base.update(request)
        return base
    sequence = request.get("sequence")
    if isinstance(sequence, list) and sequence and sequence[0] in catalog:
        base = resolve_request(sequence[0], catalog, (*seen, name))
        base.update(request)
        return base
    return request


def supplemental_rules(document):
    # The original YAML owns extra header-chain rules absent from the base set.
    lines = document.get("rules", "").splitlines(keepends=True)
    start = next((index for index, line in enumerate(lines) if line.startswith("SecRule ")), len(lines))
    return "".join(lines[start:])


def fixture_document(request, catalog_case, catalog_dir):
    relative = request.get("fixture") or catalog_case.get("runner_case")
    if not relative:
        return {}, None
    path = catalog_dir / relative
    if not path.is_file():
        return {}, None
    reference(path, "original_declarative_fixture")
    return yaml.safe_load(read_source(path)), path


def wire_request(request, body):
    malformed = {
        "invalid_content_length": b"Content-Length: invalid\r\n",
        "conflicting_content_length": b"Content-Length: 1\r\nContent-Length: 2\r\n",
        "duplicate_transfer_encoding": b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
        "content_length_overflow": b"Content-Length: 18446744073709551616\r\n",
    }
    template = request.get("raw_template")
    if template:
        tail = b"0\r\n\r\n" if template == "duplicate_transfer_encoding" else b""
        return b"POST /i12-main HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n" + malformed[template] + b"\r\n" + tail
    method = request.get("method", "GET")
    path = request.get("path", "/i12-main")
    headers = request.get("headers", [])
    if isinstance(headers, dict):
        headers = [{"name": key, "value": value} for key, value in headers.items()]
    fields = [("Host", "127.0.0.1"), ("Connection", "close"), ("Content-Length", str(len(body)))]
    fields.extend((header["name"], str(header["value"])) for header in headers)
    head = method + " " + path + " HTTP/1.1\r\n"
    head += "".join(name + ": " + value + "\r\n" for name, value in fields)
    return (head + "\r\n").encode("iso-8859-1") + body


def apply_source_chunks(case, lifecycle, body, response):
    if lifecycle.get("synchronization", {}).get("upstream_waits_for_test_barrier"):
        case["first_byte_barrier"] = True
        case["first_chunk_size"] = response.index(P4_MARKER)
    if lifecycle.get("response_committed_before_marker"):
        prefix_size = response.index(P4_MARKER)
        case["response_streaming"] = True
        case["response_chunk_sizes"] = [prefix_size, len(response) - prefix_size]
    for side, payload in (("request", body), ("response", response)):
        chunks = lifecycle.get(side + "_chunks")
        if not chunks:
            continue
        if "".join(chunks).encode() != payload:
            raise ValueError("declarative " + side + " chunks differ from source body")
        case[side + "_streaming"] = True
        case[side + "_chunk_sizes"] = [len(chunk.encode()) for chunk in chunks]


def canonical_case(name, catalog, catalog_dir, rules):
    request = resolve_request(name, catalog)
    document, document_path = fixture_document(request, catalog[name], catalog_dir)
    merged = copy.deepcopy(document.get("request", {}))
    merged.update(request)
    body = merged.get("body", merged.get("body_fixture", "")).encode()
    response_document = document.get("response", {})
    response = merged.get("response_body_fixture", response_document.get("body", "ordinary-native-response\n")).encode()
    response_headers = [{"name": key, "value": value} for key, value in response_document.get("headers", {}).items()]
    if merged.get("response_fixture") == "X-Modsec-Upstream: block":
        response_headers.append({"name": "X-Modsec-Upstream", "value": "block"})
    case = {"request": body, "response": response, "request_wire": wire_request(merged, body),
            "request_method": merged.get("method", "GET"), "request_path": merged.get("path", "/i12-main"),
            "rules_extra": rules + supplemental_rules(document), "response_headers": response_headers}
    status = catalog[name].get("expected_status")
    case["expected_status"] = 200 if status in (None, 0) else status
    location = document.get("full_lifecycle", {}).get("redirect_location")
    if location is not None:
        case["expected_location"] = location
        case["response_inspected"] = False
    apply_source_chunks(case, document.get("full_lifecycle", {}), body, response)
    if merged.get("raw_template"):
        case["request_method"] = "POST"
    return case, document_path


def named_case(name):
    available = fixtures.cases()
    if name in available:
        return copy.deepcopy(available[name])
    aliases = {"request-single-chunk": "response-single-chunk", "request-content-type-present": "request-charset-missing",
               "request-mime-scope-in": "request-charset-missing", "request-mime-scope-out": "request-charset-missing",
               "request-eos-once": "request-charset-missing", "client-response-bytes": "response-single-chunk",
               "client-exit-signal": "response-single-chunk", "neighbor-connection-stream": "response-single-chunk"}
    if name in aliases:
        case = copy.deepcopy(available[aliases[name]])
        if name == "request-mime-scope-out":
            case["request_type"] = "application/octet-stream"
        return case
    return None


def required_gap(name):
    if name in SPECIAL_CASES:
        return SPECIAL_CASES[name]
    if name.startswith("NEED-physical-event-sink-"):
        return "product_physical_common_sink_and_actual_stdio_fault_required"
    if name.startswith("NEED-"):
        return NAMED_GAPS.get(name.removeprefix("NEED-"))
    if name.startswith("HIST-"):
        return "product_physical_common_sink_and_cleanup_reproduction_required"
    return None


def bind_row(row, catalog, catalog_dir, rules, sources):
    selected = row["original_selected_requirement"]
    name = selected["case_id"]
    plan = {"run_scoped_case_id": row["run_scoped_case_id"], "leg_id": LEG,
            "original_selected_requirement": selected,
            "original_selected_requirement_sha256": row["original_selected_requirement_sha256"],
            "original_oracle": row["original_oracle"], "oracle_sources": sources,
            "source_fixture": None, "missing_observations": row["required_measurement_contract"],
            "measurements": dict.fromkeys(row["required_measurement_contract"]),
            "execution": None, "qualifier_result": None, "current_lifecycle_pass": False,
            "product_rebuild_required": True, "physical_common_event_sink_required": True,
            "qualification_dependencies": ["fresh_integrated_source_and_build_binding", "physical_common_event_sink", "actual_host_measurements", "independent_root_oracle_and_qualifier_review"],
            "contract_gaps": [], "status": "PLANNED_NOT_EXECUTED"}
    if selected["execution_kind"] == "actual_configtest":
        plan["status"] = "CONFIGURATION_ROOT_OWNED"
        return plan, None
    gap = required_gap(name)
    if gap:
        plan["contract_gaps"].append(gap)
        return plan, None
    if name == "NEED-p3-redirect":
        case, document = canonical_case("phase3_redirect_before_commit", catalog, catalog_dir, rules)
        if document:
            plan["oracle_sources"] = [*sources, reference(document, "original_declarative_fixture")]
    else:
        case = named_case(name.removeprefix("NEED-")) if name.startswith("NEED-") else None
    if case is None and name in catalog:
        case, document = canonical_case(name, catalog, catalog_dir, rules)
        if document:
            plan["oracle_sources"] = [*sources, reference(document, "original_declarative_fixture")]
    if case is None:
        plan["contract_gaps"].append("exact_executable_fixture_contract_required")
        return plan, None
    case["original_id"] = row["run_scoped_case_id"]
    case["original_requirement_binding"] = {"selected_requirement_sha256": row["original_selected_requirement_sha256"],
                                             "original_oracle": row["original_oracle"], "sources": plan["oracle_sources"]}
    plan["preexecution_fixture_expectation"] = {
        "declared_client_status": case.get("expected_status", 200),
        "declared_redirect_location": case.get("expected_location"),
        "request_bytes": len(case["request"]), "request_sha256": fixtures.digest(case["request"]),
        "response_bytes": len(case["response"]), "response_sha256": fixtures.digest(case["response"]),
        "native_rule_id_from_original": row["original_oracle"]["rule_id"],
        "native_phase_from_original": row["original_oracle"]["phase"],
        "original_unresolved_values_preserved": row["original_oracle"]["unresolved_expected_value_reason"] is not None,
        "independent_root_oracle_reconciliation_required": True,
    }
    return plan, case


def prepare(inventory_path, catalog_path, rules_path, sdk_source, capture, output):
    inventory_ref = reference(inventory_path, "frozen_original_inventory")
    sources = [reference(catalog_path, "original_contract_catalog"), reference(rules_path, "independent_rules_source"),
               reference(sdk_source, "independent_libModSecurity_3.0.14_source")]
    if sources[-1]["sha256"] != SDK_TRANSACTION_SHA256:
        raise ValueError("exact libModSecurity3.0.14 transaction source required")
    rows = native_rows(json.loads(read_source(inventory_path)))
    original_catalog_hashes = {source_hash_map(row["original_source_hashes"])["framework:tests/cases/no-crs-baseline/catalog.json"]
                               for row in rows if row.get("original_source_hashes")}
    if original_catalog_hashes != {sources[0]["sha256"]}:
        raise ValueError("pinned original Framework catalog hash differs")
    catalog = {case["case_id"]: case for case in json.loads(read_source(catalog_path))["cases"]}
    rules_text = read_source(rules_path).decode()
    rules = rules_text[rules_text.index(CANONICAL_RULE_PREFIX):]
    output = fixtures.fresh_output(output)
    plans = []
    for row in rows:
        plan, case = bind_row(row, catalog, catalog_path.parent, rules, sources)
        if case:
            name = row["original_selected_requirement"]["case_id"]
            plan["source_fixture"] = fixtures.materialize(capture, output / name, name, case)
            plan["status"] = "FIXTURE_PREPARED_NOT_EXECUTED"
        plans.append(plan)
    result = {"schema": "i12-haproxy-native-original-plans-v1", "inventory": inventory_ref,
              "preparer_sources": [reference(Path(__file__).resolve(), "case_preparer"), reference(Path(fixtures.__file__).resolve(), "fixture_preparer"),
                                   reference(Path(__file__).resolve().with_name("i12_native_observe.py"), "observation_extractor")],
              "original_ids": len(plans), "transaction_ids": 111, "configuration_ids": 1,
              "prepared_fixtures": sum(plan["source_fixture"] is not None for plan in plans),
              "host_runs": 0, "full_lifecycle_pass": 0, "plans": plans}
    (output / "original-case-plans.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("inventory", "catalog", "rules", "sdk-source", "capture", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    result = prepare(args.inventory, args.catalog, args.rules, args.sdk_source, args.capture, args.output)
    print(json.dumps({key: result[key] for key in ("original_ids", "prepared_fixtures", "host_runs", "full_lifecycle_pass")}))


if __name__ == "__main__":
    main()
