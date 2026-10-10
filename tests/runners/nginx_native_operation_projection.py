"""Project verified native observations without canonical status or invented keys.

This seam does not authenticate a caller's proof. Source/run authority, retained
bytes and final acceptance remain the strict reader/coordinator's boundaries.
"""
from copy import deepcopy
import json
from pathlib import Path
import re
from types import MappingProxyType

from ci.checks.catalog.no_crs_baseline import json_schema_errors
from tests.runners import nginx_native_operation_bundle as bundle
from tests.runners import nginx_http11_framing as framing

ROOT = Path(__file__).resolve().parents[2]
_SCHEMA = bundle.json_object((ROOT / "tests/schemas/no-crs-baseline/case-catalog.schema.json").read_bytes())
_ITEM = _SCHEMA["properties"]["cases"]["items"]


def freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(freeze(item) for item in value)
    return value


def descriptor_registry():
    branches = _ITEM["allOf"][1]["then"]["anyOf"]
    descriptors = {}
    for branch in branches:
        properties = branch["properties"]
        case_id = properties["case_id"]["const"]
        descriptor = properties["native_invocations"]["const"]["nginx"]
        bundle.require(case_id not in descriptors and descriptor["contract_case_id"] == case_id
                       and descriptor["operation"] == bundle.route(case_id)[0], "invalid controlled native descriptor")
        descriptors[case_id] = freeze(descriptor)
    bundle.require(set(descriptors) == bundle.CASE_IDS, "controlled CaseSchema must declare exactly42 native cases")
    return MappingProxyType(descriptors)


NATIVE_DESCRIPTORS = descriptor_registry()
_TECHNICAL = MappingProxyType({
    "body_size_nonzero_with_null_data": ("protocol_error", "MSCONN_EVENT_PROTOCOL_ERROR", "request_headers"),
    "header_count_nonzero_with_null_headers": ("protocol_error", "MSCONN_EVENT_PROTOCOL_ERROR", "request_headers"),
    "early_mapping_failure_cleanup": ("protocol_error", "MSCONN_EVENT_PROTOCOL_ERROR", "request_headers"),
    "transaction_begin_failure_cleanup": ("connector_error", "MSCONN_EVENT_CONNECTOR_ERROR", "request_headers"),
    "finish_failure_propagation": ("invalid_engine_response", "MSCONN_EVENT_INVALID_ENGINE_RESPONSE", "logging"),
    "engine_timeout_before_commit": ("engine_timeout", "MSCONN_EVENT_ENGINE_TIMEOUT", "request_headers"),
    "engine_timeout_after_commit": ("engine_timeout", "MSCONN_EVENT_ENGINE_TIMEOUT", "response_body"),
})
_P4_MESSAGES = MappingProxyType({"phase4_append": "MSCONN_PHASE4_APPEND", "phase4_completion": "MSCONN_PHASE4_COMPLETE",
                              "phase4_intervention": "MSCONN_EVENT_PHASE4_LATE_INTERVENTION", "body_limit": "MSCONN_EVENT_BODY_LIMIT"})
_RECEIPT_FIELDS = frozenset({"observed_http_status", "response_bytes_received", "client_exit_code", "configtest_exit_code",
                           "observed_exit_code", "effective_phase4_mode", "first_body_byte_before_upstream_eos", "upstream",
                           "roles", "cleanup", "uri_buffer_bytes", "writer_buffer_bytes", "variant"})


def validate_identity(case, proof):
    bundle.require(isinstance(case, dict) and isinstance(proof, dict), "case and verified layer proof required")
    case_id = case.get("case_id")
    operation = bundle.route(case_id)[0]
    errors = json_schema_errors(case, _ITEM, root_schema=_SCHEMA, location="native case")
    bundle.require(not errors, "; ".join(errors))
    # JSON equality additionally distinguishes true from integer1 in const maps.
    actual = case["native_invocations"]["nginx"]
    expected = _ITEM["allOf"][1]["then"]["anyOf"]
    descriptor = next(branch["properties"]["native_invocations"]["const"]["nginx"]
                      for branch in expected if branch["properties"]["case_id"]["const"] == case_id)
    bundle.require(json.dumps(actual, sort_keys=True) == json.dumps(descriptor, sort_keys=True), "exact declared native descriptor required")
    bundle.exact(proof, {"layer_verified": True, "errors": [], "case_id": case_id, "operation": operation}, "verified operation proof")
    run_id = proof.get("run_id")
    bundle.require(isinstance(run_id, str) and bundle.RUN_ID.fullmatch(run_id), "bounded verified run required")
    bundle.require(type(proof.get("actual_status")) is int and 100 <= proof["actual_status"] <= 599, "actual visible HTTP status required")
    receipt = proof.get("receipt")
    bundle.exact(receipt, {"case_id": case_id, "operation": operation, "run_id": run_id}, "actual main receipt identity")
    names = {"at", "over"} if case_id == "event_json_limit" else {"main"}
    invocations, raw = proof.get("invocation_receipts"), proof.get("raw_artifacts")
    bundle.require(isinstance(invocations, dict) and set(invocations) == names
                   and isinstance(raw, dict) and set(raw) == names, "closed verified invocation proof required")
    for name, receipt in invocations.items():
        child_run = receipt.get("run_id")
        variant = {"at": "at255", "over": "over256", "main": "long-query"}[name] if case_id in bundle.EVENT_CASES else None
        expected_run = run_id + "-" + variant if variant else run_id
        bundle.require(child_run == expected_run and receipt.get("case_id") == case_id and receipt.get("operation") == operation, "actual invocation identity mismatch")
    return case_id, operation, run_id


def selected_events(case_id, events, transactions):
    if case_id in bundle.RAW_CASES:
        bundle.require(not events and not transactions, "preconnector rejection cannot have admitted native events/TX")
        return []
    if case_id in _TECHNICAL:
        name, message, phase = _TECHNICAL[case_id]
        selected = [event for event in events if event["event"] == name]
        bundle.require(len(selected) == 1, "one actual technical native event required")
        bundle.exact(selected[0], {"phase": phase, "message_id": message, "rule_id": "", "status": "error"}, "actual technical phase/Rule")
        if case_id.startswith("engine_timeout_"):
            timing = [event for event in events if event["event"] == "engine_call_budget_exceeded"]
            bundle.require(len(timing) == 1, "actual budget timing/native error pair required")
            bundle.exact(timing[0], {"phase": phase, "message_id": "MSCONN_ENGINE_CALL_BUDGET", "rule_id": "",
                                   "transaction_id": selected[0]["transaction_id"]}, "actual budget timing identity")
            selected.extend(timing)
        return selected
    if case_id in bundle.EVENT_CASES:
        selected = [event for event in events if event["event"] == "rule_match"]
        bundle.require(len(selected) == len(transactions) and selected, "actual event-boundary native matches required")
        for event in selected:
            bundle.exact(event, {"phase": "request_headers", "message_id": "MSCONN_EVENT_RULE_MATCHED", "rule_id": "1100402"}, "actual event-boundary Rule/phase")
        return selected
    if case_id in bundle.PHASE4_CASES | bundle.MIME_CASES:
        selected = [event for event in events if event["event"] in _P4_MESSAGES]
        bundle.require(selected, "actual Phase4 observations required")
        for event in selected:
            rule = "1100301" if event["event"] == "phase4_intervention" else ""
            bundle.exact(event, {"phase": "response_body", "message_id": _P4_MESSAGES[event["event"]], "rule_id": rule}, "actual Phase4 Rule/phase")
        return selected
    # Cleanup is deliberately excluded: LOGGING allow proves cleanup outcome,
    # never a request-header allow. Absence of request events remains visible.
    return [event for event in events if event["event"] != "transaction_cleanup"]


def native_facts(proof, case_id):
    events, transactions = proof.get("events"), proof.get("transaction_ids")
    bundle.require(isinstance(events, list) and isinstance(transactions, list)
                   and all(isinstance(tx, str) and tx and bundle.RUN_ID.fullmatch(tx) for tx in transactions)
                   and len(set(transactions)) == len(transactions), "actual native event/TX lists required")
    raw = b"\n".join(json.dumps(event, allow_nan=False).encode() for event in events)
    bundle.actual_events({"events": raw}, "events")
    phases = {"request_headers", "request_body", "response_headers", "response_body", "logging"}
    cleaned = set()
    for event in events:
        bundle.require(event.get("phase") in phases, "actual serialized native phase required")
        allowed = {""} if case_id == "early_mapping_failure_cleanup" else set(transactions)
        bundle.require(event["transaction_id"] in allowed, "native event differs from verified operation TX")
        bundle.require(event["transaction_id"] not in cleaned, "native events cannot follow actual transaction cleanup")
        if event["event"] == "transaction_cleanup":
            bundle.exact(event, {"phase": "logging", "message_id": "MSCONN_TRANSACTION_CLEANUP", "rule_id": ""}, "actual cleanup phase/Rule")
            cleaned.add(event["transaction_id"])
        if event.get("status") == "blocked" and event.get("phase") == "request_headers":
            # The real intervention callback runs before the host sends the
            # response. Native denial is not an invented already-sent action.
            bundle.exact(event, {"event": "engine_decision", "message_id": "MSCONN_EVENT_ENGINE_DECISION",
                                 "rule_id": "1100001", "action": "deny", "requested_action": "deny",
                                 "actual_action": "", "http_status": 403, "visible_http_status": 0,
                                 "transport_result": "not_observable"}, "actual request deny Rule/action/status")
        if case_id in bundle.INPUT_CASES:
            bundle.require(event["event"] in {"protocol_error", "transaction_cleanup"}, "pointer terminal proof contains foreign native operation")
    return selected_events(case_id, events, transactions)


def reason_measurements(events):
    measured = []
    for event in events:
        reason = event.get("reason")
        if not isinstance(reason, str) or not re.fullmatch(r"[a-z_]+=-?[0-9]+(?:;[a-z_]+=-?[0-9]+)*", reason):
            continue
        pairs = [part.split("=", 1) for part in reason.split(";")]
        if len({key for key, _ in pairs}) == len(pairs):
            measured.append({"transaction_id": event["transaction_id"], "event": event["event"],
                             "reason_fields": {key: int(value) for key, value in pairs}})
    return measured


def mapping_facts(proof):
    invocations = {}
    for name, receipt in proof.get("invocation_receipts", {}).items():
        raw = proof.get("raw_artifacts", {}).get(name, {})
        bundle.require(isinstance(raw, dict) and all(isinstance(value, bytes) for value in raw.values()), "actual retained invocation bytes required")
        invocations[name] = {"receipt_fields": {key: deepcopy(value) for key, value in receipt.items() if key in _RECEIPT_FIELDS},
                             "artifact_measurements": {leaf: {"bytes": len(data), "sha256": bundle.digest(data)} for leaf, data in raw.items()}}
        invocations[name]["native_jsonl_measurements"] = {
            leaf: [{"line_bytes": len(line), "sha256": bundle.digest(line)} for line in data.splitlines() if line.strip()]
            for leaf, data in raw.items() if leaf in {"phase1-events.jsonl", "phase4-events.jsonl", "native-events.jsonl"}}
        if proof["case_id"] in {"transport_http11_content_length", "transport_http11_chunked"}:
            wire = framing.parse_http11_response(raw["response-wire.bin"])
            invocations[name]["downstream_wire_measurements"] = {key: value for key, value in wire.items() if key != "body"}
    facts = {"invocations": invocations, "native_reason_measurements": reason_measurements(proof["events"])}
    observation = proof.get("observation")
    if isinstance(observation, dict):
        facts["observation_fields"] = {key: deepcopy(observation[key]) for key in ("protocol", "roles", "cleanup", "native_access", "fault", "native_begin", "native_finish", "native_budget", "native_cleanup") if key in observation}
        if "requests" in observation:
            facts["actual_request_measurements"] = [{key: deepcopy(value) for key, value in row.items() if key != "path"} for row in observation["requests"]]
    if "actual_statuses" in proof:
        facts["actual_statuses"] = deepcopy(proof["actual_statuses"])
    return facts


def visible_status(proof, case_id, selected):
    if case_id in bundle.RAW_CASES | bundle.INPUT_CASES:
        bundle.require(proof["actual_status"] == 400, "actual wire rejection status required")
    if case_id in {"clean_shutdown", "finish_failure_propagation", "engine_timeout_after_commit"}:
        bundle.require(proof["actual_status"] == 200, "actual already-visible response status required")
    if case_id == "engine_timeout_before_commit":
        bundle.require(proof["actual_status"] == 504, "actual precommit timeout wire status required")
    for receipt in proof.get("invocation_receipts", {}).values():
        if "observed_http_status" in receipt:
            bundle.require(receipt["observed_http_status"] == proof["actual_status"], "actual receipt/wire status contradiction")
    if case_id == "finish_failure_propagation":
        bundle.exact(selected[0], {"http_status": 0, "original_http_status": 200, "visible_http_status": 200}, "actual finish native/wire status")
    if case_id.startswith("engine_timeout_"):
        bundle.exact(selected[0], {"http_status": 504}, "actual native timeout status")


def project_native_operation(case, proof):
    """Return copied facts and immutable descriptor/overrides, never PASS.

    observed_event_fields is the union of genuine selected native keys only.
    mappingEvidenceFacts contains transparently derived/receipt facts separately.
    A caller merging connector expectations must copy these read-only mappings.
    """
    try:
        case_id, operation, run_id = validate_identity(case, proof)
        selected = native_facts(proof, case_id)
        visible_status(proof, case_id, selected)
        descriptor = NATIVE_DESCRIPTORS[case_id]
        return {"case_id": case_id, "run_id": run_id, "operation": operation,
                "native_descriptor": descriptor, "native_expected_overrides": descriptor.get("expected_overrides", MappingProxyType({})),
                "actual_status": proof["actual_status"], "transaction_ids": deepcopy(proof["transaction_ids"]),
                "native_events": deepcopy(proof["events"]), "selected_native_events": deepcopy(selected),
                "cleanup_native_events": deepcopy([event for event in proof["events"] if event["event"] == "transaction_cleanup"]),
                "observed_event_fields": sorted({key for event in selected for key in event}),
                "mappingEvidenceFacts": mapping_facts(proof)}
    except (TypeError, KeyError, AttributeError, StopIteration, OverflowError) as exc:
        raise ValueError("invalid native projection: " + str(exc)) from exc
