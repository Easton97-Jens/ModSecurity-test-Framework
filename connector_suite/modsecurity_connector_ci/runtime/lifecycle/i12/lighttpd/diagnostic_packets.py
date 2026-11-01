#!/usr/bin/env python3
"""Assemble worker proposals from physical stock-native diagnostic observations.

This is not a qualifier. Root must review exact sources and measurements before
the existing shared oracle and lifecycle validators can issue a verdict.
"""
from modsecurity_test_framework.connector_context import load_source
import argparse
from collections import Counter
import importlib.util
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace

# Load the maintained Parent filesystem boundary from this checkout.
import sys as _i12_sys

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths


FAULT_LOG = "fault.jsonl"
FINISH_LOG = "finish.jsonl"
AUDIT_LIMIT = 8 * 1024 * 1024
AUDIT_MARKER = re.compile(r"(?m)^---([A-Za-z0-9]+)---([A-Z])--\r?$")
AUDIT_RULE_ID = re.compile(r'\[id\s+"((?a:\d+))"\]')


def qualification_module():
    module = load_source(Path(__file__).with_name('qualification.py'))
    return module


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()] if path.is_file() else []


def physical_events(path):
    parsed, errors = [], []
    if path.is_file():
        for index, line in enumerate(path.read_text().splitlines(), 1):
            try:
                parsed.append(json.loads(line))
            except json.JSONDecodeError as error:
                errors.append({"physical_line": index, "parse_error": str(error),
                               "retained_raw_line_sha256": hashlib.sha256(line.encode()).hexdigest()})
    return parsed, errors


def _main_native_scope(native, receipt):
    starts = [r for r in native if r["function"] == "runtime_begin" and r["edge"] == "enter"]
    client = receipt["main"]
    main_starts = [r for r in starts if client["started_ns"] <= r["monotonic_ns"] <= client["completed_ns"]]
    if len(main_starts) > 1:
        raise ValueError("Actual main client interval contains ambiguous transaction allocations")
    scope = main_starts[0]["call"] if main_starts else None
    main = ([r for r in native if r.get("allocation_scope_call") == scope] if scope is not None else
            [r for r in native if client["started_ns"] <= r["monotonic_ns"] <= client["completed_ns"]])
    native_new = [r for r in main if r["function"] == "native_new_with_id" and r["edge"] == "return"]
    transaction_id = native_new[0]["transaction_id"] if len(native_new) == 1 else None
    return starts, client, scope, main, native_new, transaction_id


def _main_host_rows(case_dir, client, native_new, scope, transaction_id):
    host = [r for r in rows(case_dir / "host.jsonl") if
            (scope is None and client["started_ns"] <= r["monotonic_ns"] <= client["completed_ns"]) or
            r["runtime_allocation_scope_call"] == scope or
            (r["runtime_allocation_scope_call"] == 0 and transaction_id is not None
             and r["host_transaction_id"] == transaction_id and r["pid"] == native_new[0]["pid"])]
    return host


def _scoped_audit_rule_ids(audit_text, transaction_id):
    """Return exact rule tokens from the audit record for one transaction."""
    if transaction_id is None:
        return set()
    markers = list(AUDIT_MARKER.finditer(audit_text))
    current = None
    result = set()
    for index, marker in enumerate(markers):
        boundary, section = marker.groups()
        end = markers[index + 1].start() if index + 1 < len(markers) else len(audit_text)
        content = audit_text[marker.end():end]
        if section == "A":
            current = {"boundary": boundary, "sections": {"A": content}}
            continue
        if current is None or current["boundary"] != boundary:
            continue
        current["sections"][section] = content
        if section == "Z":
            if transaction_id in current["sections"].get("A", "").split():
                result.update(AUDIT_RULE_ID.findall(current["sections"].get("H", "")))
            current = None
    return result


def _matching_oracle_events(case_dir, events, expected, transaction_id):
    expected_rule = expected.get("rule_id")
    actual_rules = {str(r.get("rule_id")) for r in events}
    audit_path = case_dir / "audit.log"
    if audit_path.is_file() and audit_path.stat().st_size > AUDIT_LIMIT:
        raise ValueError("Diagnostic audit log exceeds its explicit 8 MiB budget")
    audit_text = audit_path.read_text() if audit_path.is_file() else ""
    audit_rules = _scoped_audit_rule_ids(audit_text, transaction_id)
    rule_observed = (expected_rule is None or str(expected_rule) in actual_rules
                     or str(expected_rule) in audit_rules)
    required_fields = expected.get("event_fields", [])
    qualifying_events = [r for r in events if expected_rule is None or str(r.get("rule_id")) == str(expected_rule)]
    event_fields_present = not required_fields or any(all(field in r for field in required_fields) for r in qualifying_events)
    return expected_rule, audit_text, rule_observed, event_fields_present


def _base_checks(context):
    expected_phase_function = {1: "native_process_request_headers", 3: "native_process_response_headers", 5: "native_process_logging"}
    checks = {
        "client_waited_exit_matches_declared_oracle": context.client["waited_exit"] == context.expected.get("client_exit", 0),
        "original_status_matches": context.client.get("status") == context.expected["visible_status"],
        "original_rule_observed": context.rule_observed,
        "original_event_fields_present_in_matching_physical_event": context.event_fields_present,
        "main_native_allocation_once": len(context.native_new) == 1,
        "main_native_logging_once": context.counts["native_process_logging"] == 1,
        "expected_native_phase_observed": context.counts[expected_phase_function[context.expected["phase"]]] == 1,
        "main_native_cleanup_once": context.counts["native_cleanup"] == 1,
        "main_runtime_finish_matches_allocation_path": context.counts["runtime_finish"] == (0 if context.begin_failed else 1),
        "main_common_cleanup_once": context.counts["common_cleanup"] == 1,
        "native_observer_valid": not any(r.get("invalid") for r in context.native),
        "healthy_neighbor": context.receipt["neighbor"].get("status") == 200 and context.receipt["neighbor"]["waited_exit"] == 0,
        "actual_host_gone": bool(context.receipt["actual_host_cleanup"]) and all(r["same_process_gone"] for r in context.receipt["actual_host_cleanup"]),
        "listeners_gone": not context.receipt["listeners_after_cleanup"],
    }
    return checks


def _check_preallocation(context):
    if context.preallocation:
        # A live observer records the healthy neighbor's constructor and final
        # state. No return from a constructor that was never called is invented.
        final = [r for r in context.native if r["function"] == "observer" and r["edge"] == "final"]
        context.checks.pop("main_native_allocation_once")
        context.checks.pop("expected_native_phase_observed")
        for key in ("main_native_logging_once", "main_native_cleanup_once",
                    "main_runtime_finish_matches_allocation_path", "main_common_cleanup_once"):
            context.checks.pop(key)
        context.checks["original_contract_permits_preallocation_rejection"] = context.preallocation_contract
        context.checks["main_constructor_and_native_phases_not_called"] = not context.native_new and not any(
            r["function"].startswith("native_process_") for r in context.main)
        context.checks["main_unallocated_finish_and_free_counts_zero"] = all(context.counts[name] == 0 for name in
            ("runtime_finish", "native_process_logging", "native_cleanup", "common_cleanup"))
        context.checks["observer_live_neighbor_and_final_receipts"] = bool(final) and any(
            r["function"] == "native_new_with_id" and r["edge"] == "return" for r in context.native)


def _check_header_normalization(context):
    if context.correction:
        audit = context.audit_text.split("---Z--", 1)[0]
        context.checks["documented_host_normalization_matches"] = (
            "X-No-Crs-Duplicate: one, two" in audit if context.case["case_id"] == "duplicate_header_names"
            else "X-No-Crs-Empty:" not in audit)


def _check_declared_shutdown(context):
    if context.case.get("declared_shutdown"):
        stopped = context.receipt["actors_cleanup"]["host"]
        context.checks["declared_host_shutdown_exits_zero"] = stopped["waited_exit"] == 0
        context.checks["host_shutdown_not_forced"] = stopped.get("forced_kill") is False
        context.checks["actual_host_shutdown_target_verified"] = bool(stopped.get("actual_host_pids_signalled_after_starttime_verification"))


def _check_unsupported_body_modes(context):
    if context.case.get("prove_unsupported_body_modes"):
        declared_body = bytes.fromhex(context.case["request"]["body_hex"])
        probes = context.receipt.get("unsupported_body_configuration_probes", [])
        context.checks["actual_streaming_configuration_rejections"] = len(probes) == 2 and all(
            row["waited_exit"] == 255 and row["waited_signal"] is None for row in probes)
        context.checks["physical_stock_body_configuration_rejection_reason"] = all(
            "stock lighttpd module requires request_body_mode=none and response_body_mode=none" in
            (context.case_dir / (row["mode"] + "-streaming.stderr")).read_text() for row in probes)
        context.checks["body_pass_through_reaches_backend_once"] = len(context.backend) == 1 and context.backend[0]["body_bytes_consumed"] == len(declared_body)
        context.checks["backend_request_entity_matches_declaration"] = len(context.backend) == 1 and context.backend[0]["body_sha256"] == hashlib.sha256(declared_body).hexdigest()
        context.checks["no_native_body_appends"] = not any("append" in row["function"] for row in context.main)
        context.checks["actual_empty_native_request_finalization_once"] = context.counts["native_process_request_body"] == 1
        context.packet["diagnostic_body_capability_control"] = {"native_body_streaming_capability": False,
            "actual_configuration_probes": probes,
            "probe_producer": context.q.reference(context.case_dir / "unsupported-body-configuration-probes.json", "parser_process")}


def _sequence_native_transaction(context, process):
    allocated = [r for r in context.starts if process["started_ns"] <= r["monotonic_ns"] <= process["completed_ns"]]
    if len(allocated) != 1:
        return None
    scope = allocated[0]["call"]
    entered = [r for r in context.native if r.get("allocation_scope_call") == scope and r["edge"] == "enter"]
    complete = all(sum(r["function"] == name for r in entered) == 1
                   for name in ("native_process_logging", "native_cleanup", "common_cleanup"))
    transaction_ids = [r["transaction_id"] for r in context.native if r.get("allocation_scope_call") == scope
                       and r["function"] == "native_new_with_id" and r["edge"] == "return"]
    return scope, complete, transaction_ids


def _check_request_sequence(context):
    if context.case.get("sequence_prefix") or context.case.get("sequence_from_wire"):
        sequence_clients = [*context.receipt["sequence_prefix"], context.client]
        sequence_scopes, sequence_ids = [], []
        sequence_complete = True
        for process in sequence_clients:
            transaction = _sequence_native_transaction(context, process)
            if transaction is None:
                sequence_complete = False
                continue
            scope, complete, transaction_ids = transaction
            sequence_scopes.append(scope)
            sequence_complete &= complete
            sequence_ids.extend(transaction_ids)
        context.checks["exact_declared_sequence_statuses"] = [r.get("status") for r in sequence_clients] == context.case["expected_sequence_statuses"]
        context.checks["sequence_clients_waited_successfully"] = all(r["waited_exit"] == 0 for r in sequence_clients)
        context.checks["sequence_native_logging_and_cleanup_once_each"] = sequence_complete
        context.checks["sequence_transaction_ids_distinct"] = len(sequence_ids) == len(sequence_clients) == len(set(sequence_ids))
        if context.expected_rule is not None:
            sequence_events = [r for r in context.all_events if r.get("transaction_id") in sequence_ids]
            context.checks["original_rule_observed"] = any(str(r.get("rule_id")) == str(context.expected_rule) for r in sequence_events)
        context.packet["actual_sequence_observations"] = {"clients": sequence_clients, "allocation_scopes": sequence_scopes,
                                                   "native_transaction_ids": sequence_ids}


def _check_declared_response(context):
    if context.resolution and context.resolution.get("kind") not in ("boundary_fault", "body_capability", "transport_control", "redirect_control", "caller_fault", "sink_fault"):
        declared = bytes.fromhex(context.resolution["declared_backend_response_hex"])
        context.checks["declared_response_bytes_match"] = context.client.get("entity_bytes") == len(declared)
        context.checks["declared_response_sha256_matches"] = context.client.get("entity_sha256") == hashlib.sha256(declared).hexdigest()
        context.checks["independent_backend_reached_once"] = len(context.backend) == 1
        context.checks["neighbor_native_scope_is_distinct"] = len(context.starts) == 2 and context.starts[1]["call"] != context.scope


def _check_boundary_fault(context):
    if context.resolution and context.resolution.get("kind") == "boundary_fault":
        fault = rows(context.case_dir / FAULT_LOG)
        declaration = context.case["predeclared_fault_contract"]
        context.checks["separately_recorded_fault_once"] = len(fault) == 1
        context.checks["real_sdk_result_separate"] = bool(fault) and fault[0]["real_sdk_return"] == 1
        context.checks["injected_boundary_matches_declaration"] = bool(fault) and fault[0]["injected_runtime_boundary_return"] == declaration["expected_boundary_return"]
        context.checks["expected_backend_count"] = len(context.backend) == declaration["expected_backend_count"]
        context.checks["physical_technical_first_cause"] = bool(context.events) and context.events[0].get("reason") == context.resolution["expected_first_cause"]
        if declaration["fault"].startswith("request_headers"):
            context.checks["main_runtime_finish_matches_allocation_path"] = context.counts["runtime_finish"] == 0
        else:
            context.checks["postcommit_flag_matches_actual_delivery"] = bool(context.events) and context.events[0].get("response_committed") is True
        if context.case.get("require_first_byte_before_fault"):
            context.checks["first_receive_precedes_explicit_logging_boundary_fault"] = bool(fault) and (
                0 < context.client.get("first_response_recv_completed_ns", 0) < fault[0]["monotonic_ns"])


def _check_short_response(context):
    if context.case.get("backend_short_length"):
        context.checks["actual_framing_incomplete"] = context.client.get("actual_message_complete") is False
        context.checks["declared_partial_entity_bytes_retained"] = context.client.get("entity_bytes") == 26


def _check_redirect_normalization(context):
    if context.case.get("prove_redirect_normalization"):
        interventions = [row for row in context.main if row["function"] == "native_intervention" and row["edge"] == "return"]
        context.checks["actual_native_redirect_302"] = any(row.get("intervention_status") == 302 for row in interventions)
        names = [header.partition(":")[0] if isinstance(header, str) else header[0] for header in context.client.get("headers", [])]
        context.checks["no_fabricated_location_delivery"] = not any(name.lower() == "location" for name in names)


def _check_denied_entity_delivery(context):
    if context.case.get("require_backend_entity_not_delivered_after_deny"):
        context.checks["denied_backend_entity_not_replayed_to_client"] = len(context.backend) == 1 and context.client.get("entity_sha256") is not None and context.client["entity_sha256"] != context.backend[0]["response_source_body_sha256"]


def _check_denied_location(context):
    if context.case.get("require_no_location_after_deny"):
        headers = [header.partition(":")[0] if isinstance(header, str) else header[0] for header in context.client.get("headers", [])]
        context.checks["denial_has_no_stale_backend_location"] = not any(name.lower() == "location" for name in headers)


def _check_sink_write_failure(context):
    context.checks["actual_runtime_io_first_cause"] = "msconnector transaction begin failed: io" in (context.case_dir / "host-error.log").read_text()
    context.checks["failed_begin_not_finished_again"] = context.begin_failed and context.counts["runtime_finish"] == 0
    if context.actual_finish:
        context.checks.pop("main_native_logging_once")
        context.checks["sdk_logging_not_reentered_after_sticky_sink_failure"] = context.counts["native_process_logging"] == 0
        context.checks["actual_internal_finish_once_replays_original_io_error"] = len(context.finish_entries) == len(context.finish_returns) == 1 and context.finish_returns[0]["actual_return"] == 0 and context.finish_returns[0]["actual_error"] == 14


def _check_sink_fault(context):
    if context.case.get("sink_fault"):
        faults = rows(context.case_dir / FAULT_LOG)
        context.checks["declared_physical_stdio_boundary_observed_once"] = len(faults) == 1 and faults[0].get("operation") == context.case["sink_fault"]
        context.checks["stdio_boundary_not_claimed_as_kernel_failure"] = bool(faults) and faults[0].get("kernel_failure_claimed") is False
        if context.case["sink_fault"] in ("write", "short_write", "flush"):
            _check_sink_write_failure(context)
        if context.case["sink_fault"] == "short_write":
            context.checks["actual_partial_stdio_write_retained"] = bool(faults) and 0 < faults[0]["actual_stdio_bytes_accepted"] < faults[0]["requested_bytes"] and bool(context.event_parse_errors)
        if context.case["sink_fault"] == "close":
            context.checks["actual_close_before_explicit_error_injection"] = bool(faults) and faults[0]["actual_io_result"] == 0 and faults[0]["injected_runtime_boundary_result"] == -1
            context.checks["graceful_host_exit_observed"] = context.receipt["actors_cleanup"]["host"]["waited_exit"] == 0


def _check_pointer_fault(context):
    if context.case.get("pointer_fault"):
        faults = rows(context.case_dir / FAULT_LOG)
        context.checks["explicit_caller_pointer_substitution_once"] = len(faults) == 1 and faults[0].get("boundary") == context.case["pointer_fault"] and faults[0].get("native_sdk_failure_claimed") is False


def _check_event_budget(context):
    if "max_event_json_bytes" in context.case.get("runtime_settings", {}):
        budget = rows(context.case_dir / "budget.jsonl")
        context.checks["physical_event_serializer_budget_rejection"] = len(budget) == 1 and budget[0]["actual_result"] == 0 and budget[0]["actual_capacity"] == int(context.case["runtime_settings"]["max_event_json_bytes"]) + 2 and budget[0]["actual_truncated"] == 1 and budget[0]["return_modified"] is False
        if context.begin_failed and context.actual_finish:
            context.checks.pop("main_native_logging_once")
            context.checks["sdk_logging_not_reentered_after_sticky_event_budget_failure"] = context.counts["native_process_logging"] == 0
            context.checks["actual_internal_finish_once_replays_original_budget_error"] = len(context.finish_entries) == len(context.finish_returns) == 1 and context.finish_returns[0]["actual_return"] == 0 and context.finish_returns[0]["actual_error"] == 9


def _executed_spec_proofs(isolation, q):
    executed_specs = [Path(path) for path in isolation["executed_input_hashes_before"]
                      if Path(path).name.startswith("admission-")]
    spec_proofs = []
    for spec_path in executed_specs:
        spec_proofs.append(q.reference(spec_path, "source_manifest"))
        spec_proofs.extend(q.reference(binding["ledger"], "source_manifest")
                           for binding in json.loads(spec_path.read_text())["bindings"])
    return spec_proofs


def _observe_identity_and_configuration(context):
    identities = context.receipt["actual_host"]
    mapped = [context.q.reference(context.case_dir / f'host-{record["pid"]}.maps', "loaded_image") for record in identities]
    context.observed("product_host_identity", {"actual_host": identities,
        "host_image": context.q.reference(context.preparation / "artifacts/bin/lighttpd"),
        "module_image": context.q.reference(context.preparation / "artifacts/modules/mod_msconnector.so"),
        "preparation": json.loads((context.preparation / "preparation.json").read_text())}, *mapped, context.isolation_ref)
    context.observed("source_config_binding", {"identity": context.identity, "case_contract": context.case,
        "rules_sha256": context.receipt["rules_sha256"], "runtime_config": context.q.reference(context.case_dir / "runtime.conf"),
        "exact_executed_input_hashes": context.isolation["executed_input_hashes_before"]},
        context.q.reference(context.preparation / "preparation.json", "source_manifest"),
        context.q.reference(context.case_dir / "lighttpd.conf", "effective_configuration"),
        context.q.reference(context.case_dir / "runtime.conf", "effective_configuration"),
        context.q.reference(context.case_dir / "rules.conf", "effective_configuration"), *context.spec_proofs)
    context.observed("capability", {"route": context.receipt["leg_id"], "request_body_mode": "none", "response_body_mode": "none",
        "actual_stock_callbacks": context.host, "native_streaming_body_hooks": False}, context.source_ref, context.host_ref)


def _observe_client_and_backend(context):
    empty_peer = context.client.get("tcp_eof_observed") and context.client.get("actual_socket_recv_chunks") == []
    for field, value in [("client_exit", context.client["waited_exit"]), ("client_signal", context.client["waited_signal"] or 0),
                         ("client_headers", context.client.get("headers", {}) if empty_peer else context.client.get("headers")),
                         ("client_bytes", 0 if empty_peer else context.client.get("entity_bytes")),
                         ("client_sha256", hashlib.sha256(b"").hexdigest() if empty_peer else context.client.get("entity_sha256"))]:
        context.observed(field, value, context.client_ref)
    context.observed("backend_request_count", len(context.backend), context.backend_ref)
    context.observed("backend_payload_identity", {"main_rows": context.backend, "client_entity_sha256": context.client.get("entity_sha256"),
        "client_request_sha256": context.client["request_sha256"], "backend_exclusion_measured": not context.backend}, context.backend_ref, context.client_ref)
    context.observed("client_backend_correlation", {"actual_client_path": context.client["path"], "main_backend_paths": [r["path"] for r in context.backend],
        "main_allocation_scope": context.scope, "host_transaction_id": context.transaction_id}, context.backend_ref, context.client_ref)
    return empty_peer


def _observe_native_calls(context):
    context.observed("native_events", context.events, context.event_ref)
    context.observed("native_api_returns", [r for r in context.main if r["edge"] == "return"], context.native_ref)
    context.observed("native_transaction_id", context.transaction_id if not context.preallocation else {
        "constructor_called": False, "constructor_return_observed": False,
        "actual_returned_handle": None, "join_verified": False,
        "main_interval_ns": [context.client["started_ns"], context.client["completed_ns"]],
        "observed_constructor_calls": 0, "reason": "Host/mapping rejection precedes native allocation"}, context.native_ref)
    commons = sorted({r["canonical_transaction_id"] for r in context.main if r.get("canonical_transaction_id")})
    context.observed("common_transaction_id", commons, context.native_ref)
    context.observed("observed_handle_association", {"scope": context.scope,
        "rows": [r for r in context.main if r.get("allocation_join_verified")],
        "sequence": context.packet.get("actual_sequence_observations")}, context.native_ref)
    phase_rows = [r for r in context.main if r["function"].startswith("native_process_")]
    context.observed("native_phases", phase_rows, context.native_ref, context.q.reference(context.case_dir / "debug.log", "native_debug"))
    context.observed("native_body_chunks", {"append_rows": [r for r in context.main if "append" in r["function"]],
        "request_native_finalization_calls": sum(r["function"] == "native_process_request_body" and r["edge"] == "enter" for r in context.main),
        "body_modes": "none; no host body ingestion"}, context.native_ref)


def _observe_first_cause(context):
    first_cause_proofs = [context.native_ref]
    if context.actual_finish:
        first_cause_proofs.append(context.q.reference(context.case_dir / FINISH_LOG, "native_api"))
    fault_rows = rows(context.case_dir / FAULT_LOG)
    if fault_rows:
        context.packet["test_boundary_fault_evidence"] = [context.q.reference(context.case_dir / FAULT_LOG, "runtime_boundary_fault")]
    context.observed("native_intervention_or_first_cause", {"interventions": [r for r in context.main if r["function"] == "native_intervention" and r["edge"] == "return"],
        "technical_fault_rows": [r for r in context.main if r.get("result") is not None and r["result"] < 0],
        "physical_first_cause_events": context.events, "physical_event_source": context.event_ref,
        "actual_runtime_finish_including_internal_calls": context.actual_finish,
        "injected_runtime_boundary_rows_separate_from_native_sdk_returns": fault_rows}, *first_cause_proofs)


def _observe_eos_finish_and_cleanup_calls(context):
    context.inapplicable("host_eos", "Stock-native body modes are none and stock ABI has no entity-body EOS callback; actual request-reset snapshots remain separate.")
    context.inapplicable("native_eos", "No entity body is ingested in stock-native mode; native empty request processing is measured separately and is not relabelled body EOS.")
    context.observed("commit_order", {"actual_host_snapshots": context.host, "client_first_recv_ns": context.client.get("first_response_recv_completed_ns"),
        "client_headers_complete_ns": context.client.get("headers_complete_recv_ns")}, context.host_ref, context.client_ref)
    context.inapplicable("mime_gate", "Stock-native modes none supply no native body MIME selection; response header mapping is independently observed.")
    finish_proofs = [context.native_ref]
    if (context.case_dir / FINISH_LOG).is_file():
        finish_proofs.append(context.q.reference(context.case_dir / FINISH_LOG, "native_api"))
    context.observed("finish_calls", {"runtime_finish": len(context.finish_entries) if context.actual_finish else context.counts["runtime_finish"],
        "runtime_finish_external_wrapped_calls": context.counts["runtime_finish"],
        "runtime_finish_actual_api_rows": context.actual_finish,
        "runtime_finish_count_scope": "actual API including internal calls" if context.actual_finish else "GNU external call wrappers; internal calls are not observed by this producer",
        "native_logging": context.counts["native_process_logging"], "common_finish_attempts": context.counts["common_finish"]}, *finish_proofs)
    context.observed("finish_transitions", [r for r in context.main if r["function"] == "common_finish"], context.native_ref)
    context.observed("native_free_calls", {"runtime_destroy": context.counts["runtime_destroy"], "native_cleanup": context.counts["native_cleanup"],
        "common_cleanup": context.counts["common_cleanup"]}, context.native_ref)


def _observe_process_cleanup_and_neighbor(context):
    context.observed("cleanup_receipts", {"actual_host_cleanup": context.receipt["actual_host_cleanup"], "actors": context.receipt["actors_cleanup"],
        "observer_final": [r for r in context.native if r["function"] == "observer" and r["edge"] == "final"]}, context.cleanup_ref, context.isolation_ref)
    context.observed("descriptor_cleanup", {"before": context.receipt["actual_host"], "after_main": context.receipt["after_main_host"],
        "actual_host_cleanup": context.receipt["actual_host_cleanup"]}, context.cleanup_ref)
    context.observed("process_listener_cleanup", {"processes": context.receipt["actual_host_cleanup"],
        "listeners_after_cleanup": context.receipt["listeners_after_cleanup"]}, context.cleanup_ref, context.isolation_ref)
    context.observed("neighbor_health", {"client": context.receipt["neighbor"],
        "backend_rows": [r for r in context.all_backend if r["path"] == "/diagnostic/healthy-neighbor"]}, context.neighbor_ref, context.backend_ref)


def _observe_transport_and_events(context):
    context.observed("transport_framing", {"peer_eof_without_response": True} if context.empty_peer else context.client.get("framing"), context.client_ref)
    context.observed("transport_reset_scope", {"peer_eof": context.client["tcp_eof_observed"], "reset": context.client["tcp_reset_observed"],
        "timeout": context.client["timeout_observed"], "host_snapshots": context.host}, context.client_ref, context.host_ref)
    context.observed("host_action", {"actual_host_snapshots": context.host, "client_status": context.client.get("status")}, context.host_ref, context.client_ref)
    context.observed("physical_event_order", context.events, context.event_ref)
    context.packet["physical_event_parse_errors"] = context.event_parse_errors
    if context.case.get("sink_fault") or context.case.get("pointer_fault"):
        context.packet["explicit_caller_or_stdio_fault_evidence"] = [context.q.reference(context.case_dir / FAULT_LOG, "runtime_boundary_fault"),
            context.q.reference(context.case_dir / "host-error.log", "host_callback")]
    context.observed("terminal_event_count", sum(r.get("actual_action") == "deny" for r in context.events), context.event_ref)


def _oracle_proposal(case, case_id, correction, q, receipt, resolution, source):
    independent = [{**q.reference(item["path"]), "kind": "native_engine_contract", "revision": item["revision"]} for item in case["independent_sources"]]
    oracle = {"run_scoped_case_id": case_id, "leg_id": receipt["leg_id"], "reviewed_by": "worker",
        "category": "SOURCE_CONFIRMED_EXPECTATION", "scope": "Exact stock-native original P1/P3 diagnostic contract",
        "interpretation": "Original declarative catalog/YAML and canonical rule actions define the expected status/rule independently of measurements.",
        "independent_sources": independent, "implementation_sources": [q.reference(source)]}
    if correction:
        oracle["category"] = "ORACLE_DEFECT_CONFIRMED"
        oracle["approved_correction"] = correction
        oracle["interpretation"] = correction["reason"]
        oracle["independent_sources"] += correction["proof"]
    if resolution:
        oracle["resolved_expectation"] = resolution["expected_oracle"]
        oracle["interpretation"] = resolution["reason"]
        for proof in resolution["proof"]:
            destination = "implementation_sources" if proof.get("kind") == "predeclared_fixture" else "independent_sources"
            oracle[destination].append(proof)
    return oracle


def assemble(case_dir, attempt, preparation, identity, correction=None, resolution=None):
    """Collect worker checks and physical observations without qualifying them.

    The contexts retain the same receipt and packet objects across the ordered
    checks and observations; helpers only append the original measurements.
    """
    q = qualification_module()
    receipt = json.loads((case_dir / "capture.json").read_text())
    case = receipt["case_contract"]
    case_id = receipt["run_scoped_case_id"]
    identity = {**identity, "run_id": receipt.get("actual_run_id", identity["run_id"])}
    original = q.original_row(case_id)
    native = rows(case_dir / "native.jsonl")
    starts, client, scope, main, native_new, transaction_id = _main_native_scope(native, receipt)
    host = _main_host_rows(case_dir, client, native_new, scope, transaction_id)
    all_events, event_parse_errors = physical_events(case_dir / "events.jsonl")
    events = [r for r in all_events if r.get("transaction_id") == transaction_id]
    backend = [json.loads(line) for line in receipt["backend_main_rows"]]
    all_backend = rows(case_dir / "backend.jsonl")
    selected_oracle = resolution or correction or original["selected_requirement"]
    expected = selected_oracle["expected_oracle"]
    packet = q.packet_template(case_id, {**identity, "effective_config_sha256": receipt["effective_config_sha256"]})
    packet["rules_sha256"] = receipt["rules_sha256"]
    packet["execution_observed"] = receipt["execution_observed"]
    packet["oracle_evaluated"] = True
    packet["oracle_sha256"] = q.ORACLES.canonical_digest(expected)
    expected_rule, audit_text, rule_observed, event_fields_present = _matching_oracle_events(
        case_dir, events, expected, transaction_id)
    counts = Counter(r["function"] for r in main if r["edge"] == "enter")
    actual_finish = [r for r in rows(case_dir / FINISH_LOG) if r.get("transaction_id") == transaction_id
                     and transaction_id is not None]
    finish_entries = [r for r in actual_finish if r["edge"] == "enter"]
    finish_returns = [r for r in actual_finish if r["edge"] == "return"]
    begin_returns = [r for r in main if r["function"] == "runtime_begin" and r["edge"] == "return"]
    begin_failed = len(begin_returns) == 1 and begin_returns[0]["result"] == 0
    preallocation = not native_new
    preallocation_contract = expected.get("native_result") in (
        "mapping_error", "rejected_by_host_before_connector_or_connector_rejection",
        "reject_or_rejected_by_host_before_connector")
    if preallocation and not preallocation_contract:
        raise ValueError("No native constructor observed and original oracle does not permit preallocation rejection")
    check_context = SimpleNamespace(
        actual_finish=actual_finish,
        all_events=all_events,
        audit_text=audit_text,
        backend=backend,
        begin_failed=begin_failed,
        case=case,
        case_dir=case_dir,
        client=client,
        correction=correction,
        counts=counts,
        event_fields_present=event_fields_present,
        event_parse_errors=event_parse_errors,
        events=events,
        expected=expected,
        expected_rule=expected_rule,
        finish_entries=finish_entries,
        finish_returns=finish_returns,
        main=main,
        native=native,
        native_new=native_new,
        packet=packet,
        preallocation=preallocation,
        preallocation_contract=preallocation_contract,
        q=q,
        receipt=receipt,
        resolution=resolution,
        rule_observed=rule_observed,
        scope=scope,
        starts=starts,
    )
    checks = _base_checks(check_context)
    check_context.checks = checks
    _check_preallocation(check_context)
    _check_header_normalization(check_context)
    _check_declared_shutdown(check_context)
    _check_unsupported_body_modes(check_context)
    _check_request_sequence(check_context)
    _check_declared_response(check_context)
    _check_boundary_fault(check_context)
    _check_short_response(check_context)
    _check_redirect_normalization(check_context)
    _check_denied_entity_delivery(check_context)
    _check_denied_location(check_context)
    _check_sink_fault(check_context)
    _check_pointer_fault(check_context)
    _check_event_budget(check_context)
    packet["independent_evaluation_checks"] = checks
    packet["outcome"] = "PASS" if all(checks.values()) else "FAIL"
    source = preparation / "source/connectors/lighttpd/module/mod_msconnector.c"
    source_ref = q.reference(source, "source_contract")
    host_ref = q.reference(case_dir / "host.jsonl", "host_callback")
    native_ref = q.reference(case_dir / "native.jsonl", "native_api")
    client_ref = q.reference(case_dir / f'{case["case_id"]}.process.json', "client_process")
    neighbor_ref = q.reference(case_dir / f'{case["case_id"]}-neighbor.process.json', "client_process")
    backend_ref = q.reference(case_dir / "backend.jsonl", "backend_process")
    event_ref = q.reference(case_dir / "events.jsonl", "physical_event_sink")
    cleanup_ref = q.reference(case_dir / "capture.json", "cleanup_observer")
    isolation_ref = q.reference(attempt / "controller-result.json", "isolation_receipt")
    isolation = json.loads((attempt / "controller-result.json").read_text())
    spec_proofs = _executed_spec_proofs(isolation, q)

    def observed(field, value, *proofs):
        packet["observations"][field] = {"value": value, "evidence": list(proofs)}

    def inapplicable(field, reason):
        packet["observations"][field] = {"value": None, "applicable": False,
            "reason": reason, "capability_proof": [source_ref]}

    observe_context = SimpleNamespace(
        actual_finish=actual_finish,
        all_backend=all_backend,
        backend=backend,
        backend_ref=backend_ref,
        case=case,
        case_dir=case_dir,
        cleanup_ref=cleanup_ref,
        client=client,
        client_ref=client_ref,
        counts=counts,
        event_parse_errors=event_parse_errors,
        event_ref=event_ref,
        events=events,
        finish_entries=finish_entries,
        host=host,
        host_ref=host_ref,
        identity=identity,
        inapplicable=inapplicable,
        isolation=isolation,
        isolation_ref=isolation_ref,
        main=main,
        native=native,
        native_ref=native_ref,
        neighbor_ref=neighbor_ref,
        observed=observed,
        packet=packet,
        preallocation=preallocation,
        preparation=preparation,
        q=q,
        receipt=receipt,
        scope=scope,
        source_ref=source_ref,
        spec_proofs=spec_proofs,
        transaction_id=transaction_id,
    )
    _observe_identity_and_configuration(observe_context)
    observe_context.empty_peer = _observe_client_and_backend(observe_context)
    _observe_native_calls(observe_context)
    _observe_first_cause(observe_context)
    _observe_eos_finish_and_cleanup_calls(observe_context)
    _observe_process_cleanup_and_neighbor(observe_context)
    _observe_transport_and_events(observe_context)
    oracle = _oracle_proposal(case, case_id, correction, q, receipt, resolution, source)
    return packet, oracle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("attempt", "preparation", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--parent-sha", required=True)
    parser.add_argument("--framework-sha", required=True)
    parser.add_argument("--mrts-sha", required=True)
    parser.add_argument("--corrections", type=Path)
    parser.add_argument("--resolutions", type=Path)
    args = parser.parse_args()
    args.output = i12_paths.new_directory(args.output)
    identity = {"run_id": "i12-lighttpd-412-diagnostic::" + args.attempt.name, "parent_sha": args.parent_sha,
                "framework_sha": args.framework_sha, "mrts_sha": args.mrts_sha}
    corrections = json.loads(args.corrections.read_text()) if args.corrections else {}
    corrections = corrections.get("corrections", corrections)
    resolutions = json.loads(args.resolutions.read_text()) if args.resolutions else {}
    for path in sorted((args.attempt / "data/diagnostic").glob("*/capture.json")):
        packet, oracle = assemble(path.parent, args.attempt, args.preparation, identity,
            corrections.get(path.parent.name), resolutions.get(path.parent.name))
        for suffix, value in (("packet-proposal", packet), ("oracle-proposal", oracle)):
            with (args.output / f'{path.parent.name}-{suffix}.json').open("x") as output:
                json.dump(value, output, indent=2)
                output.write("\n")


if __name__ == "__main__":
    main()
