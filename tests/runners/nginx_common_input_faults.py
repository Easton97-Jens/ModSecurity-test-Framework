"""Validate actual own-worker Common mapper faults without generating events."""
from __future__ import annotations

import re

CONTRACTS = {
    "body_size_nonzero_with_null_data": {"phase": 1, "expected_status": 400, "expected_result": "mapping_error",
                                        "diagnostic": "missing body data"},
    "header_count_nonzero_with_null_headers": {"phase": 1, "expected_status": 400, "expected_result": "mapping_error",
                                              "diagnostic": "missing headers"},
}


def exact_fields(value, expected):
    return isinstance(value, dict) and all(
        type(value.get(key)) is type(wanted) and value.get(key) == wanted for key, wanted in expected.items())


def role_errors(roles, cleanup, run_id):
    if not exact_fields(roles, {"master_uid": 0, "worker_uid": 65534, "run_id": run_id}):
        return ["root master and nobody worker are required"]
    pids = [roles.get(name) for name in ("master_pid", "worker_pid")]
    if not all(type(pid) is int and pid > 0 for pid in pids) or pids[0] == pids[1]:
        return ["distinct observed owned process identities are required"]
    if not exact_fields(cleanup, {"verified": True, "master_running": False, "worker_running": False,
                                 "listener_open": False, "run_id": run_id,
                                 "master_pid": pids[0], "worker_pid": pids[1]}):
        return ["actual bounded cleanup is required"]
    return []


def native_fault_errors(value, case_id, transaction, roles):
    fault = value.get("native_fault")
    fields = {"case_id": case_id, "transaction_id": transaction, "uid": 65534,
              "pid": roles.get("worker_pid"), "ppid": roles.get("master_pid"),
              "validator_return": 0, "diagnostic_match": True}
    if case_id == "body_size_nonzero_with_null_data":
        fields.update({"body_size": 1, "body_data_null": True})
    else:
        fields.update({"header_count": 1, "headers_null": True})
    if not exact_fields(fault, fields):
        return ["actual fault must reach the exact own-worker Common guard"]
    diagnostic = "modsecurity common request mapper validation failed: " + CONTRACTS[case_id]["diagnostic"]
    return [] if value.get("native_diagnostic") == diagnostic else ["exact native mapper diagnostic is required"]


def native_event_errors(events, transaction):
    if not isinstance(events, list) or len(events) != 1:
        return ["exactly one real native protocol error is required"]
    event = events[0]
    required = {"event": "protocol_error", "message_id": "MSCONN_EVENT_PROTOCOL_ERROR", "connector": "nginx",
                "integration_mode": "native-nginx-http-module", "transaction_id": transaction,
                "status": "error", "reason": "protocol_error", "rule_id": ""}
    if (not exact_fields(event, required) or type(event.get("phase")) not in (int, str)
            or event.get("phase") not in (1, "1", "request_headers")):
        return ["native error classification must bind the actual transaction without a rule"]
    return []


def observation_errors(value, case_id, run_id):
    """Check parsed native observations; the caller must verify retained raw bytes.

    This helper does not authenticate receipts or infer product build identity.
    Those remain the central artifact reader's responsibility.
    """
    if case_id not in CONTRACTS or not isinstance(value, dict):
        return ["unsupported Common input fault operation"]
    identity = {"schema_version": 1, "case_id": case_id, "run_id": run_id,
                "operation": "common_mapper_input_fault", "protocol": "http1",
                "client_exit_code": 0, "observed_http_status": 400,
                "path": "/no-crs/input-fault/" + case_id}
    errors = [] if exact_fields(value, identity) else ["actual native fault invocation identity mismatch"]
    transaction = value.get("transaction_id")
    if not isinstance(transaction, str) or not re.fullmatch(r"[0-9a-f]{32}", transaction):
        errors.append("actual native transaction identity is required")
    roles = value.get("roles")
    errors.extend(role_errors(roles, value.get("cleanup"), run_id))
    if not isinstance(roles, dict):
        return errors
    access = {"uri": identity["path"], "status": 400, "transaction_id": transaction}
    if not exact_fields(value.get("native_access"), access):
        errors.append("actual access must bind the request and native transaction")
    errors.extend(native_fault_errors(value, case_id, transaction, roles))
    errors.extend(native_event_errors(value.get("native_events"), transaction))
    return errors
