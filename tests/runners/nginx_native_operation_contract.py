"""Closed native facts for canonical consumers, never status or acceptance.

Call only with the strict bundle reader's authenticated result. This pure seam
does not establish artifact authority: callers must revalidate the original
bundle with explicit source/run authority, including during offline finalize.
Host facts are separate mappings, never additions to Common's native events.
"""
from copy import deepcopy
import re
from types import MappingProxyType

from tests.runners import nginx_native_operation_bundle as bundle
from tests.runners import nginx_native_operation_projection as projection
from tests.runners import nginx_http11_framing as framing
from tests.runners import nginx_lifecycle_sequence as sequence
from tests.runners import nginx_phase4_contracts as phase4


CASE_RESULTS = MappingProxyType({
    **{key: "rejected_by_host_before_connector_or_connector_rejection" for key in bundle.RAW_CASES},
    **{key: "mapping_error" for key in bundle.INPUT_CASES},
    "event_metadata_truncation": "event_metadata_truncated", "event_json_limit": "event_bounded_or_truncated",
    "single_request_cleanup": "clean_shutdown", "clean_shutdown": "clean_shutdown",
    "multiple_sequential_requests": "sequence_complete", "keep_alive_requests_if_supported": "sequence_complete_or_host_unsupported",
    **{key: "failure_propagated_and_cleaned" for key in ("early_mapping_failure_cleanup", "transaction_begin_failure_cleanup", "finish_failure_propagation")},
    "phase4_marker_split_across_chunks": "marker_split_across_chunks", "phase4_end_of_stream_evaluation": "end_of_stream_evaluation",
    "phase4_deny_after_commit_log_only_minimal": "late_intervention_log_only_safe",
    "phase4_in_scope_content_type": "content_type_in_scope", "phase4_content_type_with_charset": "content_type_in_scope_with_charset",
    "phase4_out_of_scope_content_type": "content_type_out_of_scope", "phase4_missing_content_type": "content_type_missing",
    **{key: key for key in ("transport_http11_content_length", "transport_http11_chunked", "transport_keep_alive", "transport_sequential_requests",
                          "keepalive_allow_allow", "keepalive_allow_deny_allow", "keepalive_safe_followup", "engine_timeout_before_commit",
                          "engine_timeout_after_commit", "response_short_write_resume", "response_write_would_block_resume")},
    **{key: "connection_aborted_strict" for key in ("phase4_strict_http1_client_abort", "phase4_strict_host_survives",
                                                  "phase4_strict_followup_request_succeeds", "keepalive_after_strict_new_connection")},
    **{"phase4_body_" + suffix: "response_body_" + suffix for suffix in ("at_limit", "over_limit", "process_partial", "reject")},
    "full_lifecycle_event_metadata_bounded": "event_bounded_or_truncated",
})
bundle.require(set(CASE_RESULTS) == bundle.CASE_IDS, "closed42 native semantic contracts required")
PHASES = MappingProxyType({1: "request_headers", 2: "request_body", 3: "response_headers", 4: "response_body", 5: "logging"})
HOST_FIELDS = frozenset({"run_id", "transport_case_id", "connection_id", "connection_reused", "transport_protocol",
                         "transfer_encoding", "timeout_stage", "write_result", "cleanup_reason"})
DERIVED_FIELDS = frozenset({"marker_split_across_chunks", "end_of_stream_evaluation", "body_started", "content_type_scope",
                            "body_limit_outcome", "truncated", "eos_seen", "transport_result"})
EVENT_LEAVES = frozenset({"phase1-events.jsonl", "phase4-events.jsonl", "native-events.jsonl"})


def event_origin(proof, event, event_index, field):
    """Locate the actual unchanged event in an original retained JSONL line."""
    for name, raw in proof["raw_artifacts"].items():
        for leaf in sorted(EVENT_LEAVES & set(raw)):
            for line_index, line in enumerate(raw[leaf].splitlines()):
                if line.strip() and bundle.json_object(line) == event:
                    return {"kind": "native_event", "invocation": name, "artifact": leaf,
                            "artifact_sha256": bundle.digest(raw[leaf]), "line_sha256": bundle.digest(line),
                            "line_index": line_index, "event_index": event_index,
                            "source_pointer": f"/events/{event_index}/{field}", "transaction_id": event["transaction_id"]}
    raise ValueError("native fact absent from original retained JSONL: " + field)


def observation_origin(proof, pointer):
    raw = proof["raw_artifacts"]["main"]
    leaf = "sequence-observation.json"
    bundle.require(leaf in raw and bundle.json_object(raw[leaf]) == proof.get("observation"),
                   "host fact differs from original retained observation")
    return {"kind": "host_observation", "invocation": "main", "artifact": leaf,
            "artifact_sha256": bundle.digest(raw[leaf]), "source_pointer": "/observation/" + pointer}


def receipt_origin(proof, name, field):
    leaf = "sequence-source.json" if proof["case_id"] in bundle.SEQUENCE_CASES else "input-fault-source.json" if proof["case_id"] in bundle.INPUT_CASES else "source-result.json"
    candidates = [key for key in proof.get("files", {}) if key == leaf or key.endswith("/" + leaf)]
    if proof["case_id"] in bundle.EVENT_CASES:
        variant = {"at": "at255", "over": "over256", "main": "long-query"}[name]
        candidates = [key for key in candidates if key == variant + "/" + leaf]
    bundle.require(len(candidates) == 1, "original receipt seal required for mapped receipt fact")
    seal = proof["files"][candidates[0]].get("sha256")
    bundle.require(isinstance(seal, str) and bundle.SHA256.fullmatch(seal), "actual receipt digest required")
    return {"kind": "operation_receipt", "invocation": name, "artifact": candidates[0],
            "artifact_sha256": seal, "source_pointer": f"/invocation_receipts/{name}/{field}"}


def native_values(proof, selected, field):
    rows = [(index, event) for index, event in enumerate(proof["events"]) if event in selected and field in event]
    bundle.require(rows, "unproved native event field: " + field)
    return [deepcopy(event[field]) for _, event in rows], [event_origin(proof, event, index, field) for index, event in rows]


def actual_reason_values(proof, selected, key):
    rows = []
    for index, event in enumerate(proof["events"]):
        if event not in selected:
            continue
        measured = projection.reason_measurements([event])
        if measured and key in measured[0]["reason_fields"]:
            rows.append((index, event, measured[0]["reason_fields"][key]))
    bundle.require(rows, "missing actual native reason measurement: " + key)
    return rows


def mapped_field(field, case_id, proof, selected):
    observation = proof.get("observation", {})
    requests = observation.get("requests", [])
    # These identities are authenticated receipt/host facts, not Common keys.
    if field in {"run_id", "transport_case_id"}:
        key = "run_id" if field == "run_id" else "case_id"
        value = proof["receipt"][key]
        return [value], [receipt_origin(proof, "main", key)]
    if field in {"connection_id", "connection_reused"}:
        accesses = observation.get("native_access", [])
        bundle.require(len(accesses) == len(requests) and accesses, "actual access connection counters required")
        connections = [row["connection"] for row in accesses]
        counters = [row["connection_requests"] for row in accesses]
        bundle.require(all(isinstance(conn, str) and conn.isdecimal() for conn in connections)
                       and all(type(count) is int and count > 0 for count in counters), "invalid actual connection measurements")
        value = connections if field == "connection_id" else [len(connections) > 1 and len(set(connections)) == 1 and counters == list(range(1, len(counters) + 1))]
        return value, [observation_origin(proof, "native_access/" + str(index)) for index in range(len(accesses))]
    if field == "transport_protocol":
        bundle.require(observation.get("protocol") == "http1", "only actual H1 transport is supported")
        return ["http1"], [observation_origin(proof, "protocol")]
    if field == "transfer_encoding":
        raw = proof["raw_artifacts"]["main"].get("response-wire.bin")
        bundle.require(type(raw) is bytes, "original downstream H1 wire required")
        wire = framing.parse_http11_response(raw)
        return [wire["framing"]], [{"kind": "downstream_wire", "invocation": "main", "artifact": "response-wire.bin",
                                   "artifact_sha256": bundle.digest(raw), "source_pointer": "/parsed/framing"}]
    if field == "cleanup_reason":
        cleanup = [row for row in proof["events"] if row.get("event") == "transaction_cleanup"]
        return native_values(proof, cleanup, field)
    if field == "timeout_stage":
        bundle.require(case_id in {"engine_timeout_before_commit", "engine_timeout_after_commit"}, "foreign timeout mapping")
        event = next((row for row in selected if row.get("event") == "engine_timeout"), None)
        stage = "before_commit" if event and event["phase"] == "request_headers" else "after_commit" if event and event["phase"] == "response_body" else None
        bundle.require(stage is not None, "actual timeout Source phase required")
        index = proof["events"].index(event)
        return [stage], [event_origin(proof, event, index, "phase")]
    if field == "write_result":
        writes = observation.get("native_writes")
        bundle.require(case_id in {"response_short_write_resume", "response_write_would_block_resume"}
                       and isinstance(writes, list) and writes, "actual native write ledger required")
        bundle.require(not sequence.write_observation_errors(observation, case_id), "actual write fault/resume identity mismatch")
        keys = {"pid", "peer_port", "requested_bytes", "returned_bytes", "errno", "fault_triggered"}
        bundle.require(all(isinstance(row, dict) and set(row) == keys for row in writes), "closed payload-free native write rows required")
        triggered = [row for row in writes if row["fault_triggered"] is True]
        bundle.require(len(triggered) == 1, "one actual write fault required")
        short = 0 < triggered[0]["returned_bytes"] < triggered[0]["requested_bytes"] and triggered[0]["errno"] == 0
        blocked = triggered[0]["returned_bytes"] == -1 and triggered[0]["errno"] == 11
        bundle.require(short if case_id == "response_short_write_resume" else blocked, "actual write fault mismatch")
        return ["short_write_resumed" if short else "would_block_resumed"], [observation_origin(proof, "native_writes")]
    if field == "content_type_scope":
        values, origins = native_values(proof, selected, "content_type")
        retained = actual_reason_values(proof, selected, "engine_retained_bytes")
        content = set(values)
        bundle.require(len(content) == 1, "actual MIME type contradiction")
        value = "missing" if content == {""} else "in_scope" if next(iter(content)).split(";", 1)[0] == "text/plain" and any(row[2] > 0 for row in retained) else "out_of_scope"
        origins += [event_origin(proof, row, index, "reason") for index, row, _ in retained]
        return [value], origins
    if field in {"end_of_stream_evaluation", "body_started", "marker_split_across_chunks"}:
        completes = [row for row in selected if row.get("event") == "phase4_completion" and row.get("eos_seen") is True]
        interventions = [row for row in selected if row.get("event") == "phase4_intervention" and row.get("rule_id") == "1100301" and row.get("eos_seen") is True]
        appends = actual_reason_values(proof, selected, "append_size")
        bundle.require(completes and interventions and appends and sum(row[2] for row in appends) > 0, "actual append/EOS/Rule evidence required")
        origins = [event_origin(proof, row, index, "reason") for index, row, _ in appends]
        origins += [event_origin(proof, row, proof["events"].index(row), "eos_seen") for row in completes + interventions]
        if field == "marker_split_across_chunks":
            receipt = proof["invocation_receipts"]["main"]
            bundle.require(len(appends) >= 2 and receipt.get("first_body_byte_before_upstream_eos") is True,
                           "actual split streaming boundary missing")
            raw = proof["raw_artifacts"]["main"].get("response.bin")
            bundle.require(type(raw) is bytes, "actual split marker body capture required")
            marker_start = raw.find(phase4.MARKER.encode())
            boundaries = []
            supplied = 0
            for _, _, size in appends[:-1]:
                supplied += size
                boundaries.append(supplied)
            bundle.require(marker_start >= 0 and any(marker_start < boundary < marker_start + len(phase4.MARKER) for boundary in boundaries),
                           "actual marker does not cross an observed native append boundary")
            origins.append({"kind": "response_capture_boundary", "invocation": "main", "artifact": "response.bin",
                            "artifact_sha256": bundle.digest(raw), "source_pointer": "/parsed/marker_append_boundary"})
            origins.append(receipt_origin(proof, "main", "first_body_byte_before_upstream_eos"))
        return [True], origins
    if field == "body_limit_outcome":
        if case_id == "phase4_body_reject":
            return native_values(proof, selected, field)
        retained = actual_reason_values(proof, selected, "engine_retained_bytes")
        seen, origins = native_values(proof, selected, "body_bytes_seen")
        inspected, more = native_values(proof, selected, "body_bytes_inspected")
        bundle.require(seen == inspected and max(seen) > 0, "actual Common supplied bytes contradiction")
        bundle.require(case_id in {"phase4_body_at_limit", "phase4_body_over_limit", "phase4_body_process_partial"}, "foreign body limit mapping")
        rules = proof["raw_artifacts"]["main"].get("rules.conf")
        bundle.require(type(rules) is bytes, "actual response limit rules required")
        limits = re.findall(rb"(?m)^SecResponseBodyLimit ([1-9][0-9]*)$", rules)
        actions = re.findall(rb"(?m)^SecResponseBodyLimitAction ([A-Za-z]+)$", rules)
        bundle.require(len(limits) == 1 and actions == [b"ProcessPartial"], "actual closed response limit/action required")
        limit = int(limits[0])
        bundle.require(max(row[2] for row in retained) == min(max(seen), limit), "actual retained length differs from configured limit")
        if case_id == "phase4_body_at_limit":
            bundle.require(max(seen) == limit, "actual at-limit boundary missing")
            outcome = "at_limit"
        else:
            bundle.require(max(seen) > limit, "actual over-limit boundary missing")
            # Same native ProcessPartial API evidence, different explicit
            # catalog questions: over-limit boundary versus partial retention.
            outcome = "over_limit" if case_id == "phase4_body_over_limit" else "process_partial"
        origins.append({"kind": "engine_configuration", "invocation": "main", "artifact": "rules.conf",
                        "artifact_sha256": bundle.digest(rules), "source_pointer": "/SecResponseBodyLimit"})
        return [outcome], origins + more + [event_origin(proof, row, index, "reason") for index, row, _ in retained]
    if field == "truncated" and case_id in bundle.PHASE4_CASES:
        return native_values(proof, selected, "body_truncated")
    if field in {"eos_seen", "transport_result"} and case_id in {"keepalive_allow_allow", "keepalive_allow_deny_allow"}:
        # Request-header native EOS/transport fields describe the pre-send
        # callback, not subsequent complete client framing. Keep them intact
        # in native_events; expose client completion as a separate host fact.
        bundle.require(requests and all(row.get("transport_result") == "completed" for row in requests), "actual keepalive client completion absent")
        value = [True] if field == "eos_seen" else [row["transport_result"] for row in requests]
        return value, [observation_origin(proof, "requests/" + str(index) + "/transport_result") for index in range(len(requests))]
    if field == "eos_seen" and not any(field in row for row in selected):
        bundle.require(requests and all(row.get("transport_result") == "completed" for row in requests), "actual client EOS completion absent")
        return [True], [observation_origin(proof, "requests/" + str(index) + "/transport_result") for index in range(len(requests))]
    if field == "transport_result" and case_id in bundle.MIME_CASES and not any(field in row for row in selected):
        receipt = proof["invocation_receipts"]["main"]
        bundle.require(receipt.get("client_exit_code") == 0, "actual completed MIME client required")
        return ["completed"], [receipt_origin(proof, "main", "client_exit_code")]
    if field == "transport_result" and case_id in {"transport_http11_content_length", "transport_http11_chunked"}:
        bundle.require(requests and all(row.get("transport_result") == "completed" for row in requests), "actual downstream completion absent")
        return ["completed"], [observation_origin(proof, "requests/0/transport_result")]
    bundle.require(field not in HOST_FIELDS and field not in DERIVED_FIELDS - {"truncated", "eos_seen", "transport_result"}, "unproved closed operation field: " + field)
    return native_values(proof, selected, field)


def derive_native_operation_contract(case, strict_reader_proof):
    """Return transparent actual facts, mappings and semantics; raise on gaps.

All42 routes are closed. Missing producer facts remain errors; recognizing a
route is not acceptance. Expected fields are checked, never copied into native
observed_event_fields. Native and downstream status retain different meanings.
"""
    try:
        proof = strict_reader_proof
        result = projection.project_native_operation(case, proof)
        case_id = result["case_id"]
        overrides = result["native_expected_overrides"]
        expected = {**case, **dict(overrides)}
        bundle.require(expected.get("expected_result") == CASE_RESULTS[case_id], "closed native result contract mismatch")
        status = expected.get("expected_status")
        bundle.require(status is None or type(status) is int and status == result["actual_status"], "explicit native/wire status expectation mismatch")
        phase = expected["phase"]
        selected = result["selected_native_events"]
        for event in selected:
            if event.get("event") == "request_headers_complete":
                bundle.exact(event, {"phase": "request_headers", "message_id": "MSCONN_PHASE1_COMPLETE", "rule_id": "",
                                     "status": "ok", "action": "allow", "requested_action": "allow", "actual_action": "",
                                     "http_status": 0, "visible_http_status": 0, "transport_result": "not_observable",
                                     "reason": "native_return=1;common_completed=1"}, "actual native P1 completion")
        phase_scope = "native_event"
        if case_id in bundle.RAW_CASES:
            phase_scope = "host_preconnector"
        elif phase == 5:
            phase_scope = "lifecycle_cleanup"
            if case_id == "early_mapping_failure_cleanup":
                bundle.require(proof.get("observation", {}).get("cleanup", {}).get("verified") is True,
                               "actual preadmission host cleanup required")
            else:
                bundle.require(result["cleanup_native_events"], "actual LOGGING cleanup required")
        else:
            bundle.require(any(row["phase"] == PHASES[phase] for row in selected), "actual required native phase missing")
        selected = [row for row in selected if phase == 5 or row["phase"] == PHASES[phase]]
        rule_ids = sorted({row["rule_id"] for row in result["selected_native_events"] if row["rule_id"]})
        rule = expected.get("expected_rule_id")
        bundle.require(rule is None or str(rule) in rule_ids, "actual required native Rule callback missing")
        # Every selected event must have an original byte origin even if this
        # case has no expected_event_fields. Cleanup stays a separate category.
        event_origins = [event_origin(proof, row, index, "event") for index, row in enumerate(proof["events"]) if row in result["selected_native_events"]]
        fields = expected.get("expected_event_fields") or []
        bundle.require(isinstance(fields, list) and len(set(fields)) == len(fields), "unique expected native fields required")
        mapped, origins = {}, {}
        for field in fields:
            bundle.require(isinstance(field, str), "expected field must be a string")
            mapped[field], origins[field] = mapped_field(field, case_id, proof, selected)
        if case_id in bundle.EVENT_CASES:
            bundle.require(any(value is True for value in mapped.get("truncated", [])), "actual bounded/truncated event required")
        if "expected_native_status" in overrides:
            bundle.require(any(row.get("http_status") == overrides["expected_native_status"] for row in selected), "actual native cause status mismatch")
        if "expected_engine_error_class" in overrides:
            bundle.require(any(row.get("event") == overrides["expected_engine_error_class"] for row in selected), "actual native error class mismatch")
        result.update(observed_rule_ids=rule_ids, mapped_evidence_fields=mapped, mapped_evidence_origins=origins,
                      native_event_origins=event_origins,
                      native_cause=[{key: deepcopy(row[key]) for key in ("event", "phase", "transaction_id", "rule_id", "http_status", "visible_http_status", "actual_action", "transport_result") if key in row} for row in result["selected_native_events"]],
                      semanticValues={"phase": phase, "phase_scope": phase_scope, "expected_result": CASE_RESULTS[case_id],
                                      "wire_status": result["actual_status"], "rule_ids": rule_ids})
        result["semantic_evidence_origins"] = {
            "expected_result": {"kind": "closed_verified_operation", "case_id": case_id, "operation": result["operation"],
                                "source_pointer": "/case_id", "retained_file_sha256": {path: seal["sha256"] for path, seal in proof.get("files", {}).items()}},
            "phase": {"kind": phase_scope, "event_origins": event_origins if phase_scope == "native_event" else
                      [event_origin(proof, row, proof["events"].index(row), "phase") for row in result["cleanup_native_events"]]},
            "rule_ids": [event_origin(proof, row, proof["events"].index(row), "rule_id") for row in result["selected_native_events"] if row["rule_id"]],
        }
        return result
    except (KeyError, TypeError, AttributeError, StopIteration, OverflowError) as exc:
        raise ValueError("invalid native fact contract: " + str(exc)) from exc
