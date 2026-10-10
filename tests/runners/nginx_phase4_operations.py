"""Validate observed Phase-4 bytes; never generate events or canonical PASS.

The enclosing canonical validator must additionally bind run/revisions/artifacts,
host roles, lifecycle cleanup and producer identity. This pure helper checks the
closed operation against the retained native JSONL, curl headers/body and inputs.
Append/complete/limit records are source-bound native producer contracts, not
fields populated from driver expectations.
"""
import hashlib
import json
import re

import nginx_phase4_contracts as contracts

MAX_RAW_BYTES = 1024 * 1024
MAX_EVENT_BYTES = 8192
NATIVE_MODE = "native-nginx-http-module"
APPEND_REASON = re.compile(r"native_return=([01]);append_size=(0|[1-9][0-9]*);append_index=([1-9][0-9]*);engine_retained_bytes=(0|[1-9][0-9]*)")
COMPLETE_REASON = re.compile(r"engine_retained_bytes=(0|[1-9][0-9]*);append_calls=(0|[1-9][0-9]*)")
RAW_LEAVES = frozenset({"phase4-events.jsonl", "response.bin", "response.headers",
                        "client.stdout", "client.stderr", "rules.conf", "nginx.conf", "nginx-error.log"})
REJECT_LOG = b"Response body limit is marked to reject the request"


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _equal_fields(value, expected, label):
    for field, wanted in expected.items():
        observed = value.get(field)
        _require(type(observed) is type(wanted) and observed == wanted,
                 f"{label}: {field} does not match observed contract")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate native JSON key")
        result[key] = value
    return result


def _native_events(receipt, raw, path):
    records = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        _require(len(line) + 1 <= MAX_EVENT_BYTES, "native event exceeds bounded JSONL size")
        event = json.loads(line, object_pairs_hook=_unique_object,
                           parse_constant=lambda value: (_ for _ in ()).throw(ValueError("invalid JSON number")))
        _require(isinstance(event, dict), "native JSONL must contain objects")
        if (event.get("connector") == "nginx" and event.get("integration_mode") == NATIVE_MODE
                and event.get("phase") == "response_body" and event.get("method") == "GET"
                and event.get("uri") == path):
            records.append(event)
    _require(records and records == receipt.get("native_events"), "native event projection differs from retained bytes")
    txids = {event.get("transaction_id") for event in records}
    _require(len(txids) == 1, "native events must bind one actual transaction")
    txid = next(iter(txids))
    _require(isinstance(txid, str) and re.fullmatch(re.escape(receipt["run_id"]) + r"-[1-9][0-9]*-[1-9][0-9]*", txid),
             "native transaction does not bind run/connection/request")
    return records


def _raw_inputs(receipt, artifacts, spec):
    _require(isinstance(artifacts, dict), "raw artifacts must be a mapping")
    hashes = receipt.get("raw_sha256")
    _require(isinstance(hashes, dict), "raw capture hashes absent")
    for leaf in RAW_LEAVES:
        data = artifacts.get(leaf)
        _require(type(data) is bytes and len(data) <= MAX_RAW_BYTES, f"missing or oversized raw {leaf}")
        _require(hashes.get(leaf) == hashlib.sha256(data).hexdigest(), f"raw {leaf} digest mismatch")
    _require(artifacts["rules.conf"] == spec["rules"].encode(), "rules differ from closed operation")
    config = artifacts["nginx.conf"]
    _require(re.findall(rb"\bmodsecurity_phase4_mode\s+([^;\s]+)\s*;", config) == [b"safe"],
             "actual configuration must use exactly existing safe mode")


def _wire(receipt, artifacts, status, expected_body, aborted=False):
    _equal_fields(receipt, {"client_exit_code": 18 if aborted else 0, "observed_http_status": status,
                           "response_bytes_received": len(artifacts["response.bin"])}, "wire receipt")
    _require(artifacts["client.stdout"] == str(status).encode(), "raw client status mismatch")
    if aborted:
        _require(re.fullmatch(rb"curl: \(18\) (?:transfer closed with outstanding read data remaining|end of response with [1-9][0-9]* bytes missing)\n?", artifacts["client.stderr"]),
                 "committed immediate Reject requires actual incomplete-framing curl18")
        _require(artifacts["response.bin"] == b"", "rejected append was forwarded to client")
    else:
        _require(artifacts["client.stderr"] == b"", "client reports incomplete or failed response")
    headers = artifacts["response.headers"]
    _require(headers.endswith(b"\r\n\r\n"), "response headers incomplete")
    lines = headers[:-4].split(b"\r\n")
    _require(re.fullmatch(rb"HTTP/1\.[01] " + str(status).encode() + rb" [^\r\n]+", lines[0]), "raw response status mismatch")
    fields = {}
    for line in lines[1:]:
        key, separator, value = line.partition(b":")
        _require(separator and key.lower() not in fields, "invalid or duplicate response header")
        fields[key.lower()] = value.strip()
    length = fields.get(b"content-length")
    encoding = fields.get(b"transfer-encoding")
    _require(not (length is not None and encoding is not None), "ambiguous response framing")
    if length is not None:
        _require(re.fullmatch(rb"0|[1-9][0-9]*", length), "invalid response length")
        _require(int(length) > 0 if aborted else int(length) == len(artifacts["response.bin"]), "response length framing mismatch")
    else:
        _require(encoding == b"chunked", "response must retain explicit framing")
    if expected_body is not None:
        _require(artifacts["response.bin"] == expected_body, "received body differs from exact split/limit fixture")
        _require(fields.get(b"content-type") == b"text/plain", "actual MIME header mismatch")


def _appends(events, sizes, retained, partial=False):
    appends = [event for event in events if event.get("event") == "phase4_append"]
    _require(len(appends) == len(sizes), "actual append count does not match exact fixture boundaries")
    supplied = 0
    for index, (event, size) in enumerate(zip(appends, sizes), 1):
        supplied += size
        match = APPEND_REASON.fullmatch(event.get("reason", ""))
        _require(match is not None, "native append metadata malformed")
        values = tuple(map(int, match.groups()))
        _require(values == (int(not partial), size, index, min(supplied, retained)), "native append API/count/size/retained mismatch")
        _equal_fields(event, {"message_id": "MSCONN_PHASE4_APPEND", "rule_id": "",
                              "actual_action": "allow", "body_bytes_seen": supplied,
                              "body_bytes_inspected": supplied, "eos_seen": False}, "native append")
    return appends


def _complete(events, sizes, retained):
    completions = [event for event in events if event.get("event") == "phase4_completion"]
    _require(len(completions) == 1, "one native process1/Common-completed EOS event required")
    event = completions[0]
    match = COMPLETE_REASON.fullmatch(event.get("reason", ""))
    _require(match is not None and tuple(map(int, match.groups())) == (retained, len(sizes)),
             "Engine retained bytes/native append count mismatch")
    _equal_fields(event, {"message_id": "MSCONN_PHASE4_COMPLETE", "eos_seen": True,
                          "body_bytes_seen": sum(sizes), "body_bytes_inspected": sum(sizes),
                          "body_truncated": retained < sum(sizes),
                          "content_type": "text/plain", "connection_aborted": False}, "native completion")
    _require(events.index(event) > max(events.index(item) for item in events if item.get("event") == "phase4_append"),
             "native completion precedes actual appends")


def _safe_rule(events):
    matches = [event for event in events if event.get("event") == "phase4_intervention"]
    _require(len(matches) == 1, "one actual phase4 marker intervention required")
    _require(events.index(matches[0]) > max(events.index(item) for item in events if item.get("event") == "phase4_append"),
             "EOS marker evaluation precedes native appends")
    _equal_fields(matches[0], {"message_id": "MSCONN_EVENT_PHASE4_LATE_INTERVENTION",
                              "rule_id": "1100301", "http_status": 403, "visible_http_status": 200,
                              "requested_action": "deny", "actual_action": "log_only",
                              "transport_result": "log_only", "late_intervention": True,
                              "late_intervention_mode": "safe", "response_committed": True,
                              "connection_aborted": False, "eos_seen": True}, "safe marker intervention")


def _reject(events, artifacts):
    limits = [event for event in events if event.get("event") == "body_limit"]
    _require(len(limits) == 1, "one actual immediate Engine limit intervention required")
    event = limits[0]
    _require(events.index(event) > max(events.index(item) for item in events if item.get("event") == "phase4_append"),
             "Engine rejection precedes native append observation")
    committed = event.get("response_committed")
    _require(type(committed) is bool, "Reject response commit observation absent")
    _equal_fields(event, {"message_id": "MSCONN_EVENT_BODY_LIMIT", "reason": "response_body_limit_exceeded",
                             "body_limit_outcome": "reject",
                             "http_status": 403, "visible_http_status": 200 if committed else 0, "rule_id": "",
                             "status": "blocked", "action": "abort_connection" if committed else "deny",
                             "requested_action": "deny",
                             "actual_action": "abort_connection" if committed else "deny",
                             "transport_result": "connection_aborted" if committed else "not_observable",
                             "headers_sent": committed, "connection_aborted": committed,
                             "body_bytes_seen": 65, "body_bytes_inspected": 65,
                             "body_truncated": True, "eos_seen": False}, "immediate Reject")
    _require(REJECT_LOG in artifacts["nginx-error.log"], "exact native Engine Reject diagnostic absent")
    _require(not any(event.get("event") in {"phase4_completion", "phase4_intervention"} for event in events),
             "immediate append Reject must not become late/EOS rule evaluation")
    return committed


def validate_phase4_operation(record_id, receipt, raw_artifacts):
    """Return errors; empty means this operation layer passed, never global PASS."""
    try:
        spec = contracts.operation(record_id)
        _require(isinstance(receipt, dict), "operation receipt must be an object")
        _equal_fields(receipt, {"case_id": record_id, "source_record_id": spec["source_record_id"],
                               "operation": "native_phase4_request", "request_method": "GET",
                               "request_path": spec["request_path"], "effective_phase4_mode": "safe",
                               "configtest_exit_code": 0}, "closed receipt")
        _require(receipt.get("driver_error") is None, "driver failed")
        _require(isinstance(receipt.get("run_id"), str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", receipt["run_id"]), "invalid run identity")
        _raw_inputs(receipt, raw_artifacts, spec)
        events = _native_events(receipt, raw_artifacts["phase4-events.jsonl"], spec["request_path"])
        sizes = [len(chunk.encode()) for chunk in spec["response_chunks"]]
        body = "".join(spec["response_chunks"]).encode()
        reject = record_id == "phase4_body_reject"
        allowed_events = {"phase4_append", "body_limit"} if reject else {"phase4_append", "phase4_completion", "phase4_intervention"}
        _require(all(event.get("event") in allowed_events for event in events), "unexpected native error/operation event")
        retained = 0 if reject else min(len(body), spec.get("engine_limit_bytes", len(body)))
        _appends(events, sizes, retained, partial=not reject and retained < len(body))
        if reject:
            committed = _reject(events, raw_artifacts)
            _wire(receipt, raw_artifacts, 200 if committed else 403, None, aborted=committed)
        else:
            _wire(receipt, raw_artifacts, 200, body)
            _complete(events, sizes, retained)
            _safe_rule(events)
            _equal_fields(receipt.get("upstream", {}), {"chunk_sizes_sent": sizes, "eos_sent": True, "error_class": "none"}, "actual upstream")
            if spec["pause_between_chunks"]:
                _equal_fields(receipt, {"first_body_byte_before_upstream_eos": True}, "streaming split")
        if record_id == "full_lifecycle_event_metadata_bounded":
            _require(contracts.MARKER.encode() not in raw_artifacts["phase4-events.jsonl"], "native metadata contains response payload")
        return []
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError) as exc:
        return [str(exc)]
