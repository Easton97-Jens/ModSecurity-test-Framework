"""Check four closed MIME operations against retained native and wire bytes.

The caller owns revision/artifact/process authentication and lifecycle cleanup.
Native append/completion shapes match nginx_phase4_operations; these checks do
not manufacture canonical events or treat fixture declarations as observations.
"""
import hashlib
import json
import re

BODY = b"no-crs-response-body-marker"
CONTENT_TYPES = {
    "phase4_in_scope_content_type": "text/plain",
    "phase4_content_type_with_charset": "text/plain; charset=utf-8",
    "phase4_out_of_scope_content_type": "image/png",
    "phase4_missing_content_type": "",
}
RAW_LEAVES = frozenset({"phase4-events.jsonl", "response.bin", "response.headers",
                        "client.stdout", "client.stderr", "rules.conf", "nginx.conf",
                        "response-header-fixture.json"})
MAX_RAW_BYTES = 1024 * 1024
APPEND_REASON = re.compile(r"native_return=([01]);append_size=([1-9][0-9]*);append_index=([1-9][0-9]*);engine_retained_bytes=(0|[1-9][0-9]*)")
COMPLETE_REASON = re.compile(r"engine_retained_bytes=(0|[1-9][0-9]*);append_calls=([1-9][0-9]*)")


def operation(case_id):
    """Return closed input only; none of these fields proves native execution."""
    if not isinstance(case_id, str) or case_id not in CONTENT_TYPES:
        raise ValueError("unsupported MIME operation")
    content_type = CONTENT_TYPES[case_id]
    fixture = {"headers": [["Content-Type", content_type]], "status": 200} if content_type else {
        "headers": [], "omit_headers": ["Content-Type"], "status": 200}
    return {"record_id": case_id, "source_record_id": case_id,
            "operation": "native_phase4_request", "nginx_phase4_mode": "safe",
            "request_path": "/no-crs/content-type/" + case_id,
            "response_content_type": content_type, "response_chunks": [BODY.decode()],
            "pause_between_chunks": False, "backend_fixture": fixture,
            "rules": ('SecRuleEngine On\nSecResponseBodyAccess On\n'
                      'SecResponseBodyMimeType text/plain application/json\n'
                      'SecRule RESPONSE_BODY "@contains ' + BODY.decode() + '" '
                      '"id:1100301,phase:4,deny,status:403,log,t:none,'
                      "msg:'no-crs phase-4 intervention probe'\"\n")}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def equal_fields(value, expected):
    require(isinstance(value, dict), "native observation must be an object")
    for field, wanted in expected.items():
        require(type(value.get(field)) is type(wanted) and value.get(field) == wanted,
                "MIME observation mismatch: " + field)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate raw JSON key")
        result[key] = value
    return result


def json_object(raw):
    value = json.loads(raw, object_pairs_hook=unique_object,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON number")))
    require(isinstance(value, dict), "raw JSON object required")
    return value


def wire_fields(raw):
    require(raw.endswith(b"\r\n\r\n"), "complete response headers required")
    lines = raw[:-4].split(b"\r\n")
    require(re.fullmatch(rb"HTTP/1\.[01] 200 [^\r\n]+", lines[0]), "actual HTTP200 required")
    fields = {}
    for line in lines[1:]:
        key, separator, value = line.partition(b":")
        require(separator and re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key)
                and key.lower() not in fields, "invalid or duplicate wire header")
        fields[key.lower()] = value.strip(b" \t")
    length, encoding = fields.get(b"content-length"), fields.get(b"transfer-encoding")
    require(not (length is not None and encoding is not None), "ambiguous wire framing")
    require(length == str(len(BODY)).encode() if length is not None else encoding == b"chunked",
            "explicit complete body framing required")
    return fields


def check_receipt_and_hashes(case_id, receipt, raw):
    require(case_id in CONTENT_TYPES and isinstance(raw, dict), "unsupported MIME operation")
    equal_fields(receipt, {"case_id": case_id, "source_record_id": case_id,
                          "operation": "native_phase4_request", "request_method": "GET",
                          "request_path": "/no-crs/content-type/" + case_id,
                          "effective_phase4_mode": "safe", "configtest_exit_code": 0,
                          "client_exit_code": 0, "observed_http_status": 200,
                          "response_bytes_received": len(BODY)})
    require(receipt.get("driver_error") is None, "MIME driver failed")
    require(isinstance(receipt.get("run_id"), str)
            and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", receipt["run_id"]), "invalid MIME run identity")
    hashes = receipt.get("raw_sha256")
    require(isinstance(hashes, dict), "raw capture hashes required")
    for leaf in RAW_LEAVES:
        data = raw.get(leaf)
        require(type(data) is bytes and len(data) <= MAX_RAW_BYTES, "missing or oversized raw " + leaf)
        require(hashes.get(leaf) == hashlib.sha256(data).hexdigest(), "raw digest mismatch: " + leaf)


def check_wire_and_fixture(raw, content_type):
    require(raw["client.stdout"] == b"200" and raw["client.stderr"] == b""
            and raw["response.bin"] == BODY, "actual complete client response required")
    fields = wire_fields(raw["response.headers"])
    require(fields.get(b"content-type") == content_type.encode() if content_type
            else b"content-type" not in fields, "actual wire Content-Type mismatch")
    fixture = {"headers": [["Content-Type", content_type]], "status": 200} if content_type else {
        "headers": [], "omit_headers": ["Content-Type"], "status": 200}
    actual = json_object(raw["response-header-fixture.json"])
    equal_fields(actual, fixture)
    require(set(actual) == set(fixture), "closed backend fixture mismatch")


def check_config_and_rules(raw, content_type):
    config = raw["nginx.conf"]
    require(re.findall(rb"\bmodsecurity_phase4_mode\s+([^;\s]+)\s*;", config) == [b"safe"],
            "existing safe mode required")
    require(re.findall(rb'\bdefault_type\s+"([^"]*)"\s*;', config) == [content_type.encode()]
            and re.search(rb"\btypes\s*\{\s*\}", config), "closed MIME default/type fixture required")
    rules = raw["rules.conf"]
    require(b"SecResponseBodyMimeTypesClear" not in rules and b"modsecurity_phase4_content_types_file" not in config,
            "obsolete scope/reset fixture rejected")
    require(re.search(rb"(?m)^SecResponseBodyAccess\s+On\s*$", rules)
            and re.search(rb"(?m)^SecRuleEngine\s+On\s*$", rules)
            and re.search(rb"(?m)^SecResponseBodyMimeType\s+text/plain\s+application/json\s*$", rules)
            and b'id:1100301,phase:4,deny,status:403' in rules and BODY in rules,
            "real Engine MIME and marker rules required")


def observed_events(receipt, raw):
    events = []
    for line in raw.splitlines():
        if line.strip():
            require(len(line) + 1 <= 8192, "oversized native event")
            event = json_object(line)
            if (event.get("connector") == "nginx"
                    and event.get("integration_mode") == "native-nginx-http-module"
                    and event.get("phase") == "response_body" and event.get("method") == "GET"
                    and event.get("uri") == receipt["request_path"]):
                events.append(event)
    require(events and events == receipt.get("native_events"), "native event projection mismatch")
    transaction = events[0].get("transaction_id")
    require(isinstance(transaction, str) and re.fullmatch(re.escape(receipt["run_id"])
            + r"-[1-9][0-9]*-[1-9][0-9]*", transaction), "native run/connection/request binding required")
    return events, transaction


def check_append(event, state, inspected):
    require(not state["completed"] and state["interventions"] == 0, "append after native EOS/intervention")
    match = APPEND_REASON.fullmatch(event.get("reason", ""))
    require(match is not None, "actual native append metadata required")
    native_return, size, index, retained = map(int, match.groups())
    state["seen"] += size
    state["append_count"] += 1
    require(native_return == 1 and index == state["append_count"] and state["seen"] <= len(BODY)
            and retained == (state["seen"] if inspected else 0), "native append/retained mismatch")
    equal_fields(event, {"message_id": "MSCONN_PHASE4_APPEND", "rule_id": "",
                        "actual_action": "allow", "body_bytes_seen": state["seen"],
                        "body_bytes_inspected": state["seen"], "eos_seen": False})


def check_completion(event, state, inspected):
    require(not state["completed"] and state["append_count"] > 0 and state["seen"] == len(BODY),
            "exact completed native P4 required")
    match = COMPLETE_REASON.fullmatch(event.get("reason", ""))
    require(match is not None and tuple(map(int, match.groups())) == (
        len(BODY) if inspected else 0, state["append_count"]), "actual Engine retention/completion count mismatch")
    equal_fields(event, {"message_id": "MSCONN_PHASE4_COMPLETE", "rule_id": "",
                        "body_bytes_seen": state["seen"], "body_bytes_inspected": state["seen"], "eos_seen": True})
    state["completed"] = True


def check_intervention(event, state, inspected):
    require(inspected and state["seen"] == len(BODY) and state["interventions"] == 0, "unexpected MIME intervention")
    equal_fields(event, {"message_id": "MSCONN_EVENT_PHASE4_LATE_INTERVENTION",
                        "rule_id": "1100301", "requested_action": "deny", "actual_action": "log_only",
                        "http_status": 403, "original_http_status": 200, "visible_http_status": 200,
                        "reason": "response_committed_safe", "transport_result": "log_only",
                        "late_intervention_mode": "safe", "late_intervention": True,
                        "response_committed": True, "eos_seen": True,
                        "body_bytes_seen": state["seen"], "body_bytes_inspected": state["seen"]})
    state["interventions"] += 1


def check_events(receipt, raw, content_type):
    events, transaction = observed_events(receipt, raw)
    inspected = content_type in ("text/plain", "text/plain; charset=utf-8")
    state = {"seen": 0, "append_count": 0, "completed": False, "interventions": 0}
    validators = {"phase4_append": check_append, "phase4_completion": check_completion,
                  "phase4_intervention": check_intervention}
    for event in events:
        equal_fields(event, {"connector": "nginx", "integration_mode": "native-nginx-http-module",
                            "phase": "response_body", "method": "GET", "uri": receipt["request_path"],
                            "transaction_id": transaction, "content_type": content_type,
                            "connection_aborted": False})
        validator = validators.get(event.get("event"))
        require(validator is not None, "unexpected native MIME event")
        validator(event, state, inspected)
    require(state["completed"] and state["interventions"] == int(inspected),
            "native completion and exact MIME rule outcome required")


def validate_mime_operation(case_id, receipt, raw_artifacts):
    """Return observation-layer errors; empty never means overall runtime PASS."""
    try:
        check_receipt_and_hashes(case_id, receipt, raw_artifacts)
        content_type = CONTENT_TYPES[case_id]
        check_wire_and_fixture(raw_artifacts, content_type)
        check_config_and_rules(raw_artifacts, content_type)
        check_events(receipt, raw_artifacts["phase4-events.jsonl"], content_type)
        return []
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError) as exc:
        return [str(exc)]
