"""Validate observed NGINX H1 sequences; never manufacture native events.

This helper validates host access-log receipts, not transport-hardening event
requirements. Canonical callers must additionally validate those requirements.
"""
from __future__ import annotations

import re
import hashlib
import importlib.util
from pathlib import Path

_wire_spec = importlib.util.spec_from_file_location("nginx_http11_wire", Path(__file__).with_name("nginx_http11_framing.py"))
WIRE = importlib.util.module_from_spec(_wire_spec)
_wire_spec.loader.exec_module(WIRE)


SEQUENCES = {
    "single_request_cleanup": (200,),
    "multiple_sequential_requests": (200, 403, 200),
    "keep_alive_requests_if_supported": (200, 403, 200),
    "clean_shutdown": (200,),
    "keepalive_allow_allow": (200, 200),
    "keepalive_allow_deny_allow": (200, 403, 200),
    "early_mapping_failure_cleanup": (500,),
    "transaction_begin_failure_cleanup": (500,),
    "phase4_strict_http1_client_abort": (200,),
    "phase4_strict_host_survives": (200, 200),
    "phase4_strict_followup_request_succeeds": (200, 200),
    "keepalive_after_strict_new_connection": (200, 200),
    "keepalive_safe_followup": (200, 200),
    "response_short_write_resume": (200,),
    "response_write_would_block_resume": (200,),
    "transport_keep_alive": (200, 200),
    "transport_sequential_requests": (200, 403, 200),
    "finish_failure_propagation": (200,),
    "engine_timeout_before_commit": (504,),
    "engine_timeout_after_commit": (200,),
    "transport_http11_content_length": (200,),
    "transport_http11_chunked": (200,),
}
KEEPALIVE_CASES = {
    "keep_alive_requests_if_supported", "keepalive_allow_allow", "keepalive_allow_deny_allow",
    "keepalive_safe_followup",
    "transport_keep_alive",
    "transport_sequential_requests",
}
STRICT_CASES = {"phase4_strict_http1_client_abort", "phase4_strict_host_survives",
                "phase4_strict_followup_request_succeeds", "keepalive_after_strict_new_connection"}
WRITE_CASES = {"response_short_write_resume", "response_write_would_block_resume"}
LATE_CASES = STRICT_CASES | {"keepalive_safe_followup"} | WRITE_CASES
TIMEOUT_CASES = {"engine_timeout_before_commit", "engine_timeout_after_commit"}
FRAMING_CASES = {"transport_http11_content_length", "transport_http11_chunked"}


def positive_integer(value):
    return type(value) is int and value > 0


def native_budget_errors(value, phase):
    """Actual scoped delegate/delay ledger; this alone is not a timeout event."""
    rows = value.get("native_budget")
    if type(phase) is not int or phase not in (1, 4) or not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        return ["exactly one bounded delegated native phase observation is required"]
    row = rows[0]
    access = value.get("native_access")
    roles = value.get("roles")
    if not isinstance(access, list) or len(access) != 1 or not isinstance(access[0], dict) or not isinstance(roles, dict):
        return ["native budget observation requires matching process and request identities"]
    operation = "msc_process_request_headers" if phase == 1 else "msc_process_response_body"
    wanted = {"native_phase": phase, "native_operation": operation, "observed_return": 1,
              "worker_pid": roles.get("worker_pid"), "transaction_id": access[0].get("transaction_id"),
              "requested_delay_ns": 25000000}
    errors = ["native delegated budget identity/outcome mismatch" for key, expected in wanted.items()
              if type(row.get(key)) is not type(expected) or row.get(key) != expected]
    measurements = (row.get("start_ns"), row.get("end_ns"), row.get("elapsed_ns"), value.get("budget_ms"))
    if not all(positive_integer(item) and item <= 2**64 - 1 for item in measurements):
        return errors + ["actual monotonic timing and positive configured budget are required"]
    start, end, elapsed, budget_ms = measurements
    if end - start != elapsed or not 25000000 <= elapsed <= 3000000000 or elapsed <= budget_ms * 1000000:
        errors.append("actual delegated native elapsed time must exceed the configured soft budget")
    return errors


def observation_errors(value, case_id, run_id):
    """Return every required-boundary error for a closed sequence operation."""
    if not isinstance(value, dict):
        return ["sequence observation must be an object"]
    expected = SEQUENCES.get(case_id)
    if expected is None:
        return ["case is not a supported observed sequence operation"]
    errors = []
    identity = {"schema_version": 1, "case_id": case_id, "run_id": run_id,
                "protocol": "http1", "operation": "request_sequence", "client_exit_code": 0}
    for field, wanted in identity.items():
        if type(value.get(field)) is not type(wanted) or value.get(field) != wanted:
            errors.append("sequence identity mismatch: " + field)
    requests = value.get("requests")
    access = value.get("native_access")
    if not isinstance(requests, list) or not isinstance(access, list):
        return errors + ["client and native access observations are required"]
    if len(requests) != len(expected) or len(access) != len(expected):
        return errors + ["sequence request/native observation count differs from the contract"]
    transactions = set()
    connections = []
    counters = []
    paths = set()
    for index, status in enumerate(expected):
        request, native = requests[index], access[index]
        if not isinstance(request, dict) or not isinstance(native, dict):
            errors.append("sequence entries must be objects")
            continue
        path = request.get("path")
        if not isinstance(path, str) or not re.fullmatch(r"/no-crs/sequence/[A-Za-z0-9_-]{1,96}/?[0-9]*", path):
            errors.append("sequence request path is invalid")
        elif path in paths:
            errors.append("sequence paths must identify each independent request")
        paths.add(path if isinstance(path, str) else "")
        if native.get("uri") != path:
            errors.append("native access request identity mismatch")
        if type(request.get("observed_status")) is not int or request.get("observed_status") != status:
            errors.append("client sequence status mismatch")
        if type(native.get("status")) is not int or native.get("status") != status:
            errors.append("native sequence status mismatch")
        received = request.get("bytes_received")
        body_limit = 262144 if case_id == "response_write_would_block_resume" else 65536
        if type(received) is not int or not 0 <= received <= body_limit:
            errors.append("bounded complete client response observation is required")
        transaction = native.get("transaction_id")
        if not isinstance(transaction, str) or not re.fullmatch(r"[0-9a-f]{32}", transaction):
            errors.append("native transaction identity is invalid")
        elif transaction in transactions:
            errors.append("transactions must remain distinct across sequence requests")
        transactions.add(transaction if isinstance(transaction, str) else "")
        connection = native.get("connection")
        if not isinstance(connection, str) or not re.fullmatch(r"[0-9]{1,20}", connection):
            errors.append("native connection identity is invalid")
        connections.append(connection if isinstance(connection, str) else None)
        counter = native.get("connection_requests")
        if not positive_integer(counter):
            errors.append("native connection request counter is invalid")
        counters.append(counter)
    if case_id in KEEPALIVE_CASES and (len(set(connections)) != 1 or counters != list(range(1, len(expected) + 1))):
        errors.append("keep-alive requires one native connection with increasing request counters")
    if case_id in STRICT_CASES and len(expected) == 2 and (len(set(connections)) != 2 or counters != [1, 1]):
        errors.append("strict abort follow-up requires a different native connection")
    roles = value.get("roles", {})
    if not isinstance(roles, dict) or not (
            type(roles.get("master_uid")) is int and roles["master_uid"] == 0
            and type(roles.get("worker_uid")) is int and roles["worker_uid"] == 65534
            and positive_integer(roles.get("master_pid")) and positive_integer(roles.get("worker_pid"))
            and roles["master_pid"] != roles["worker_pid"]):
        errors.append("root master and distinct nobody worker observations are required")
    cleanup = value.get("cleanup", {})
    if not isinstance(cleanup, dict) or any(cleanup.get(field) is not wanted for field, wanted in {
            "verified": True, "master_running": False, "worker_running": False, "listener_open": False}.items()):
        errors.append("bounded process and listener cleanup must be observed")
    fault_contracts = {
        "early_mapping_failure_cleanup": ("early_mapping_failure", "ModSecurity: invalid canonical transaction identifier"),
        "transaction_begin_failure_cleanup": ("transaction_begin_failure", "ModSecurity: failed to create transaction"),
        "finish_failure_propagation": ("finish_failure", "ModSecurity: native logging phase processing failed"),
    }
    if case_id in fault_contracts:
        requested, diagnostic = fault_contracts[case_id]
        fault = value.get("fault", {})
        if not isinstance(fault, dict) or not (
                fault.get("requested") == requested
                and fault.get("triggered") is True
                and fault.get("native_diagnostic") == diagnostic):
            errors.append("exact native fault rejection observation is required")
    if case_id in LATE_CASES:
        errors.extend(late_observation_errors(value, case_id))
    if case_id in WRITE_CASES:
        errors.extend(write_observation_errors(value, case_id))
    if case_id == "finish_failure_propagation":
        errors.extend(finish_observation_errors(value))
    if case_id in TIMEOUT_CASES:
        errors.extend(timeout_observation_errors(value, case_id))
    if case_id in FRAMING_CASES:
        errors.extend(framing_observation_errors(value, case_id))
    return errors


def framing_wire_errors(value, case_id):
    wire = value.get("wire")
    if not isinstance(wire, dict) or wire.get("eof_seen") is not True:
        return ["actual bounded downstream socket capture through EOF is required"]
    path = value["requests"][0].get("path")
    if not isinstance(path, str) or re.fullmatch(r"/no-crs/sequence/[A-Za-z0-9_/-]{1,128}", path) is None:
        return ["actual safe ASCII request path is required for wire binding"]
    expected_request = f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode("ascii")
    try:
        request = WIRE.capture_bytes(wire.get("request_hex"), 8192)
        response = WIRE.capture_bytes(wire.get("response_hex"), 32768)
        parsed = WIRE.parse_http11_response(response)
    except ValueError as exc:
        return [str(exc)]
    errors = []
    expected_framing = "chunked" if case_id == "transport_http11_chunked" else "content_length"
    if request != expected_request or parsed["body"] != WIRE.BODY or parsed["framing"] != expected_framing:
        errors.append("actual downstream request/framing/decoded fixture body differs from contract")
    for key, expected in parsed.items():
        if key != "body" and (type(value["requests"][0].get(key)) is not type(expected)
                              or value["requests"][0].get(key) != expected):
            errors.append("client metadata must match independently parsed raw wire: " + key)
    first = value["requests"][0]
    if first.get("transport_result") != "completed" or first.get("client_error") is not None:
        errors.append("actual complete downstream response is required")
    if case_id == "transport_http11_chunked":
        errors.extend(framing_upstream_errors(value, path))
    return errors


def framing_upstream_errors(value, path):
    origin = value.get("upstream_wire")
    if not isinstance(origin, dict) or type(origin.get("request_count")) is not int or origin["request_count"] != 1 or (
            origin.get("write_complete") is not True or origin.get("upstream_write_failed") is not False):
        return ["actual separate upstream request/write receipt is required"]
    try:
        request = WIRE.capture_bytes(origin.get("request_hex"), 8192)
        response = WIRE.parse_http11_response(WIRE.capture_bytes(origin.get("response_hex"), 32768))
    except ValueError as exc:
        return [str(exc)]
    if not request.startswith(f"GET {path} HTTP/1.1\r\n".encode("ascii")) or not request.endswith(b"\r\n\r\n"):
        return ["actual upstream HTTP/1.1 request must bind the same URI"]
    if response["body"] != WIRE.BODY or response["framing"] != "chunked":
        return ["actual chunked upstream write must contain the exact fixture body"]
    return []


def framing_observation_errors(value, case_id):
    request, native = value["requests"][0], value["native_access"][0]
    if not isinstance(request, dict) or not isinstance(native, dict):
        return ["framing requires actual request and native access records"]
    errors = framing_wire_errors(value, case_id)
    events = value.get("native_events")
    if not isinstance(events, list):
        return errors + ["actual native P4 and cleanup events are required"]
    completion = [event for event in events if isinstance(event, dict) and event.get("event") == "phase4_completion"]
    cleanup = [event for event in events if isinstance(event, dict) and event.get("event") == "transaction_cleanup"]
    if len(completion) != 1 or len(cleanup) != 1:
        return errors + ["exactly one native P4 completion and cleanup event are required"]
    wanted = {"connector": "nginx", "integration_mode": "native-nginx-http-module", "rule_id": "",
              "transaction_id": native.get("transaction_id"), "uri": request.get("path"),
              "status": "ok", "actual_action": "allow"}
    for record in (completion[0], cleanup[0]):
        if any(type(record.get(key)) is not type(expected) or record.get(key) != expected for key, expected in wanted.items()):
            errors.append("native framing lifecycle identity/outcome mismatch")
    errors.extend(framing_completion_errors(completion[0]))
    if cleanup[0].get("phase") != "logging" or cleanup[0].get("message_id") != "MSCONN_TRANSACTION_CLEANUP" or (
            cleanup[0].get("reason") != "common_return=0;common_complete=1;native_cleanup_completed=1;error_class=none"
            or cleanup[0].get("cleanup_reason") != "normal"):
        errors.append("actual delegated successful Common/native cleanup is required")
    if events.index(completion[0]) >= events.index(cleanup[0]):
        errors.append("native cleanup must follow actual P4 completion")
    return errors


def framing_completion_errors(event):
    wanted = {"event": "phase4_completion", "message_id": "MSCONN_PHASE4_COMPLETE", "phase": "response_body",
              "eos_seen": True, "body_bytes_seen": len(WIRE.BODY), "body_bytes_inspected": len(WIRE.BODY),
              "content_type": "text/plain"}
    errors = ["actual native P4 completion facts mismatch" for key, expected in wanted.items()
              if type(event.get(key)) is not type(expected) or event.get(key) != expected]
    reason = event.get("reason")
    match = re.fullmatch(r"engine_retained_bytes=22;append_calls=([1-9][0-9]?)", reason) if isinstance(reason, str) else None
    if match is None or int(match.group(1)) > 32:
        errors.append("actual native retained body and bounded append calls are required")
    return errors


def timeout_observation_errors(value, case_id):
    """Bind a real soft-budget overrun to the native classification and wire."""
    after_commit = case_id == "engine_timeout_after_commit"
    phase = 4 if after_commit else 1
    errors = native_budget_errors(value, phase)
    if errors:
        return errors
    request, native = value["requests"][0], value["native_access"][0]
    if not isinstance(request, dict) or not isinstance(native, dict):
        return ["timeout requires actual client and native request observations"]
    events = value.get("native_events")
    if not isinstance(events, list):
        return ["actual native engine timeout event is required"]
    matches = [event for event in events if isinstance(event, dict) and event.get("event") == "engine_timeout"]
    timing = [event for event in events if isinstance(event, dict) and event.get("event") == "engine_call_budget_exceeded"]
    if len(matches) != 1 or len(timing) != 1:
        return ["exactly one native timeout and one native timing event are required"]
    event, measurement = matches[0], timing[0]
    errors.extend(timeout_event_identity_errors(request, native, after_commit, event, measurement))
    errors.extend(timeout_timing_errors(value, measurement))
    errors.extend(timeout_wire_errors(value, after_commit))
    errors.extend(timeout_cleanup_errors(value, native))
    return errors


def timeout_event_identity_errors(request, native, after_commit, event, measurement):
    errors = []
    stage = "response_body" if after_commit else "request_headers"
    wanted = {"connector": "nginx", "integration_mode": "native-nginx-http-module",
              "transaction_id": native.get("transaction_id"), "uri": request.get("path"),
              "phase": stage, "timeout_stage": stage, "rule_id": "",
              "status": "error", "requested_action": "error",
              "response_committed": after_commit, "eos_seen": after_commit,
              "headers_sent": after_commit, "original_http_status": 200 if after_commit else 0,
              "visible_http_status": 200 if after_commit else 0,
              "actual_action": "abort_connection" if after_commit else "",
              "transport_result": "connection_aborted" if after_commit else "not_observable",
              "connection_aborted": after_commit,
              "http_status": 504}
    for record in (event, measurement):
        for key, expected in wanted.items():
            if type(record.get(key)) is not type(expected) or record.get(key) != expected:
                errors.append("native timeout classification/identity mismatch: " + key)
    if event.get("message_id") != "MSCONN_EVENT_ENGINE_TIMEOUT" or event.get("reason") != "engine_timeout":
        errors.append("canonical technical timeout classification is required")
    if measurement.get("message_id") != "MSCONN_ENGINE_CALL_BUDGET":
        errors.append("native measured timing event classification is required")
    return errors


def timeout_timing_errors(value, measurement):
    reason = measurement.get("reason")
    match = re.fullmatch(r"budget_ms=([1-9][0-9]{0,15});elapsed_ns=([1-9][0-9]{0,19});native_return=1;common_completed=0", reason) if isinstance(reason, str) else None
    if match is None:
        return ["exact payload-free native timeout reason is required"]
    budget_ms, elapsed_ns = map(int, match.groups())
    delegated_elapsed = value["native_budget"][0]["elapsed_ns"]
    if budget_ms != value["budget_ms"] or not delegated_elapsed <= elapsed_ns <= 3000000000 or elapsed_ns <= budget_ms * 1000000:
        return ["native timeout must measure the real delegated overrun"]
    return []


def timeout_wire_errors(value, after_commit):
    errors = []
    request = value["requests"][0]
    declared, received = request.get("declared_length"), request.get("bytes_received")
    chunked = request.get("framing") == "chunked" and declared is None
    if after_commit:
        if request.get("transport_result") != "connection_aborted" or request.get("client_error") != "incomplete_read":
            errors.append("committed timeout must abort actual client framing")
        if not (positive_integer(received) and (chunked or type(declared) is int and received < declared <= 65536)):
            errors.append("committed timeout requires received partial response framing")
        barrier = value.get("upstream_barrier")
        if not isinstance(barrier, dict) or any(barrier.get(key) is not expected for key, expected in {
                "prefix_sent": True, "client_headers_seen": True, "marker_sent": True,
                "barrier_timeout": False, "upstream_write_failed": False}.items()):
            errors.append("committed timeout requires the real post-header upstream barrier")
        post, roles = value.get("post_sequence_roles"), value.get("roles")
        if not isinstance(post, dict) or any(post.get(key) != roles.get(key) for key in (
                "master_pid", "worker_pid", "master_uid", "worker_uid")):
            errors.append("same native worker and master must survive the timeout")
    else:
        if request.get("transport_result") != "completed" or request.get("client_error") is not None or not (
                positive_integer(received) and (chunked or type(declared) is int and declared == received)):
            errors.append("precommit timeout requires the actual complete HTTP504 response")
    return errors


def timeout_cleanup_errors(value, native):
    cleanup = value.get("native_cleanup")
    wanted_cleanup = {"native_operation": "msconnector_transaction_contract_cleanup", "observed_return": 0,
                      "worker_pid": value["roles"].get("worker_pid"), "transaction_id": native.get("transaction_id"),
                      "cleanup_complete": 1, "error_class_code": 4, "error_class_name": "engine_timeout",
                      "timed_phase_completed": 0,
                      "timeout_error_preserved": 1}
    if not isinstance(cleanup, list) or len(cleanup) != 1 or not isinstance(cleanup[0], dict):
        return ["exactly one delegated native timeout cleanup observation is required"]
    if any(type(cleanup[0].get(key)) is not type(expected) or cleanup[0].get(key) != expected
             for key, expected in wanted_cleanup.items()):
        return ["native timeout cleanup outcome/classification/identity mismatch"]
    return []


def finish_observation_errors(value):
    rows = value.get("native_finish")
    wanted = (("msc_process_logging", -1), ("msconnector_transaction_contract_cleanup", 0),
              ("cleanup_complete", 1), ("native_logging_error_preserved", 1))
    if not isinstance(rows, list) or len(rows) != len(wanted):
        return ["actual native logging rejection and delegated successful cleanup are required"]
    roles = value.get("roles", {})
    access = value["native_access"][0]
    request = value["requests"][0]
    if not isinstance(roles, dict) or not isinstance(access, dict) or not isinstance(request, dict):
        return ["finish observations need valid native request and process identities"]
    errors = []
    for row, (operation, result) in zip(rows, wanted):
        if not isinstance(row, dict) or not (
                row.get("native_operation") == operation and type(row.get("observed_return")) is int
                and row["observed_return"] == result and row.get("worker_pid") == roles.get("worker_pid")
                and row.get("transaction_id") == access.get("transaction_id")):
            errors.append("native finish/cleanup outcome or identity mismatch")
    fixture = b"bounded-owned-sequence\n"
    if request.get("body_sha256") != hashlib.sha256(fixture).hexdigest() or request.get("bytes_received") != len(fixture):
        errors.append("post-response finish failure must preserve the original visible body")
    return errors


def write_observation_errors(value, case_id):
    rows = value.get("native_writes")
    if not isinstance(rows, list) or not 2 <= len(rows) <= 16:
        return ["native injected write and genuine resumed write observations are required"]
    roles = value.get("roles", {})
    access = value.get("native_access", [])
    if not isinstance(roles, dict) or not access or not isinstance(access[0], dict):
        return ["native writes require valid process/request observations"]
    triggered = []
    errors = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or not (
                type(row.get("pid")) is int and row["pid"] == roles.get("worker_pid")
                and type(row.get("peer_port")) is int and row["peer_port"] == access[0].get("remote_port")
                and positive_integer(row.get("requested_bytes"))
                and type(row.get("returned_bytes")) is int and type(row.get("errno")) is int
                and type(row.get("fault_triggered")) is bool):
            errors.append("write observation must bind the own native worker and client connection")
            continue
        if row["fault_triggered"]:
            triggered.append(index)
            short = 0 < row["returned_bytes"] < row["requested_bytes"] and row["errno"] == 0
            blocked = row["returned_bytes"] == -1 and row["errno"] == 11
            if not (short if case_id == "response_short_write_resume" else blocked):
                errors.append("actual native write result does not match the requested fault")
    if len(triggered) != 1:
        errors.append("exactly one requested native write fault must actually occur")
    elif not any(isinstance(row, dict) and row.get("fault_triggered") is False
                 and type(row.get("returned_bytes")) is int and row["returned_bytes"] > 0
                 and row.get("errno") == 0 for row in rows[triggered[0] + 1:]):
        errors.append("a positive actual native write must resume after the fault")
    return errors


def late_observation_errors(value, case_id):
    errors = []
    barrier = value.get("upstream_barrier", {})
    if not isinstance(barrier, dict) or any(barrier.get(key) is not wanted for key, wanted in {
            "prefix_sent": True, "client_headers_seen": True, "marker_sent": True,
            "barrier_timeout": False, "upstream_write_failed": False}.items()):
        errors.append("real post-header upstream marker barrier is required")
    first = value["requests"][0]
    native = value["native_access"][0]
    roles = value.get("roles")
    if not isinstance(first, dict) or not isinstance(native, dict) or not isinstance(roles, dict):
        return errors + ["late sequence request, native access and roles must be objects"]
    strict = case_id in STRICT_CASES
    transport = "connection_aborted" if strict else "completed"
    if first.get("transport_result") != transport:
        errors.append("client transport outcome differs from the late-intervention contract")
    declared, received = first.get("declared_length"), first.get("bytes_received")
    chunked = first.get("framing") == "chunked" and declared is None
    framed = (type(declared) is int and type(received) is int and
              (0 < received < declared <= 65536 if strict else 0 < received == declared <= 65536))
    limit = 262144 if case_id == "response_write_would_block_resume" else 65536
    if not (framed or chunked and type(received) is int and 0 < received <= limit):
        errors.append("exact partial/complete Content-Length framing must be observed")
    if strict and chunked and first.get("client_error") != "incomplete_read":
        errors.append("strict chunked framing must fail its actual terminal chunk parse")
    wanted_action = "abort_connection" if strict else "log_only"
    events = value.get("native_events")
    matched = []
    if isinstance(events, list):
        for event in events:
            if isinstance(event, dict) and event.get("event") == "phase4_intervention":
                matched.append(event)
    if len(matched) != 1:
        return errors + ["exactly one native phase4 intervention must bind the first request"]
    event = matched[0]
    if not (event.get("transaction_id") == native.get("transaction_id")
            and event.get("uri") == first.get("path") and event.get("connector") == "nginx"
            and event.get("integration_mode") == "native-nginx-http-module"
            and event.get("phase") in (4, "4", "response_body")
            and str(event.get("rule_id")) == "1100301" and event.get("requested_action") == "deny"
            and event.get("actual_action") == wanted_action
            and event.get("response_committed") in (True, 1) and event.get("eos_seen") in (True, 1)):
        errors.append("native phase4 identity, rule and late action must match the actual request")
    if case_id in WRITE_CASES and not (
            type(event.get("body_bytes_seen")) is int and event["body_bytes_seen"] == first.get("bytes_received")
            and type(event.get("body_bytes_inspected")) is int and event["body_bytes_inspected"] == first.get("bytes_received")):
        errors.append("write resume must preserve exact native single-pass body accounting")
    post = value.get("post_sequence_roles")
    if not isinstance(post, dict) or any(post.get(key) != roles.get(key) for key in (
            "master_pid", "worker_pid", "master_uid", "worker_uid")):
        errors.append("same live root master and nobody worker must survive the sequence")
    return errors
