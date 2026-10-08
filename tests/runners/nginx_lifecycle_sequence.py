"""Validate observed NGINX H1 sequences; never manufacture native events.

This helper validates host access-log receipts, not transport-hardening event
requirements. Canonical callers must additionally validate those requirements.
"""
from __future__ import annotations

import re


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
}
KEEPALIVE_CASES = {
    "keep_alive_requests_if_supported", "keepalive_allow_allow", "keepalive_allow_deny_allow",
    "keepalive_safe_followup",
    "transport_keep_alive",
}
STRICT_CASES = {"phase4_strict_http1_client_abort", "phase4_strict_host_survives",
                "phase4_strict_followup_request_succeeds", "keepalive_after_strict_new_connection"}
WRITE_CASES = {"response_short_write_resume", "response_write_would_block_resume"}
LATE_CASES = STRICT_CASES | {"keepalive_safe_followup"} | WRITE_CASES


def positive_integer(value):
    return type(value) is int and value > 0


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
