"""Closed fixed NGX URI/writer boundary operations and raw native checks."""
import hashlib
import json
import re

from nginx_mime_operations import wire_fields
from nginx_common_input_faults import role_errors

IDS = frozenset({"event_metadata_truncation", "event_json_limit"})
URI_BUFFER_BYTES = 256
WRITER_BUFFER_BYTES = 4096
RAW_LEAVES = frozenset({"phase4-events.jsonl", "response.bin", "response.headers",
                        "client.stdout", "client.stderr", "rules.conf", "nginx.conf"})
BODY = b"no-crs-response-body-marker"
RULES = ('SecRuleEngine On\nSecResponseBodyAccess On\nSecResponseBodyMimeType text/plain\n'
         'SecRule REQUEST_HEADERS:X-Modsec-Smoke "@streq log-only" '
         '"id:1100402,phase:1,pass,log,t:none,msg:\'no-crs log-only\'"\n')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def equal_fields(value, expected):
    require(isinstance(value, dict), "event boundary object required")
    for field, wanted in expected.items():
        require(type(value.get(field)) is type(wanted) and value.get(field) == wanted,
                "event boundary field mismatch: " + field)


def operation(case_id, variant):
    require(isinstance(case_id, str) and case_id in IDS, "unknown event boundary operation")
    variants = ("long-query",) if case_id == "event_metadata_truncation" else ("at255", "over256")
    require(variant in variants, "unknown fixed-source boundary variant")
    prefix = "/no-crs/events/" + variant + "/"
    size = {"long-query": 512, "at255": 255, "over256": 256}[variant]
    path = prefix + "x" * (size - len(prefix))
    if variant == "long-query":
        path += "?probe=non-sensitive"
    return {"record_id": case_id, "source_record_id": case_id,
            "operation": "native_event_boundary_request", "variant": variant,
            "nginx_phase4_mode": "safe", "request_path": path,
            "request_headers": {"X-Modsec-Smoke": "log-only"},
            "response_chunks": [BODY.decode()], "response_content_type": "text/plain",
            "pause_between_chunks": False, "rules": RULES}


def projected_uri(uri):
    """Expected closed ASCII projection, mirroring the source contract only."""
    require(isinstance(uri, str) and uri.isascii(), "closed nonsensitive ASCII URI required")
    path, query, _ = uri.partition("?")
    suffix = "?<redacted>" if query and uri.split("?", 1)[1] else ""
    text = path + suffix
    truncated = len(text.encode()) >= URI_BUFFER_BYTES
    maximum = URI_BUFFER_BYTES - 1 - len(suffix)
    text = path[:maximum] + suffix
    while len(json.dumps(text, ensure_ascii=False).encode()) - 2 >= URI_BUFFER_BYTES:
        path = text[:-len(suffix)] if suffix else text
        require(path, "URI projection exhausted")
        text = path[:-1] + suffix
        truncated = True
    return text, truncated, bool(suffix)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate native JSON key")
        result[key] = value
    return result


def json_object(raw):
    value = json.loads(raw, object_pairs_hook=unique_object,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON number")))
    require(isinstance(value, dict), "raw event object required")
    return value


def check_raw(receipt, raw, spec):
    require(isinstance(raw, dict) and isinstance(receipt.get("raw_sha256"), dict), "raw event artifacts required")
    for leaf in RAW_LEAVES:
        data = raw.get(leaf)
        require(type(data) is bytes and len(data) <= 1024 * 1024, "missing/oversized event raw artifact")
        require(receipt["raw_sha256"].get(leaf) == hashlib.sha256(data).hexdigest(), "event raw hash mismatch")
    require(raw["client.stdout"] == b"200" and raw["client.stderr"] == b"" and raw["response.bin"] == BODY,
            "actual successful complete event response required")
    require(wire_fields(raw["response.headers"]).get(b"content-type") == b"text/plain",
            "actual event response framing/type required")
    require(raw["rules.conf"] == spec["rules"].encode(), "real fixed phase1 marker rules required")
    config = raw["nginx.conf"]
    require(b"modsecurity_event_json_limit" not in config, "invented configurable writer limit rejected")
    require(re.findall(rb"\bmodsecurity\s+([^;\s]+)\s*;", config) == [b"on"]
            and re.findall(rb"\bmodsecurity_phase4_mode\s+([^;\s]+)\s*;", config) == [b"safe"],
            "actual enabled safe event producer required")
    wanted = (receipt["run_id"] + "-$connection-$connection_requests").encode()
    require(re.findall(rb'\bmodsecurity_transaction_id\s+"([^"]+)"\s*;', config) == [wanted],
            "actual source-bound transaction prefix required")
    require(re.search(rb'\bmodsecurity_phase4_log\s+"[^"\r\n]+/phase4-events.jsonl"\s*;', config),
            "actual native event sink required")


def check_callback(receipt, raw, spec):
    uri, truncated, redacted = projected_uri(spec["request_path"])
    events = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        require(len(line) + 1 < WRITER_BUFFER_BYTES, "actual NGX event writer line exceeds4096 buffer")
        event = json_object(line)
        if event.get("event") == "request_rule_match" and event.get("transaction_id", "").startswith(receipt["run_id"] + "-"):
            events.append(event)
            require(BODY not in line and b"probe=" not in line and b"non-sensitive" not in line,
                    "event contains raw body/query payload")
    require(len(events) == 1 and events == receipt.get("native_events"), "exact native rule callback projection required")
    event = events[0]
    equal_fields(event, {"event": "request_rule_match", "message_id": "MSCONN_EVENT_RULE_MATCHED",
                        "connector": "nginx", "integration_mode": "native-nginx-http-module",
                        "phase": "request_headers", "status": "ok", "action": "pass",
                        "requested_action": "pass", "actual_action": "pass", "rule_id": "1100402",
                        "reason": "non_disruptive_rule_match", "method": "GET", "uri": uri,
                        "truncated": truncated, "redacted": redacted})
    require(re.fullmatch(re.escape(receipt["run_id"]) + r"-[1-9][0-9]*-[1-9][0-9]*", event["transaction_id"]),
            "native callback does not bind run/connection/request")
    require(not set(event).intersection({"request_body", "response_body", "raw_body", "data", "payload", "headers"}),
            "native event contains forbidden payload field")


def validate_event_boundary_child(case_id, variant, receipt, raw_artifacts):
    """Check one actual retained child; enclosing reader authenticates identity."""
    try:
        spec = operation(case_id, variant)
        equal_fields(receipt, {"case_id": case_id, "source_record_id": case_id,
                              "operation": "native_event_boundary_request", "variant": variant,
                              "request_method": "GET", "request_path": spec["request_path"],
                              "request_headers": spec["request_headers"], "effective_phase4_mode": "safe",
                              "configtest_exit_code": 0, "client_exit_code": 0,
                              "observed_http_status": 200, "response_bytes_received": len(BODY)})
        require(isinstance(receipt.get("run_id"), str)
                and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", receipt["run_id"]), "invalid child run identity")
        require(receipt.get("driver_error") is None, "event boundary driver failed")
        require(not role_errors(receipt.get("roles"), receipt.get("cleanup"), receipt["run_id"]),
                "actual event own-worker/run cleanup identity required")
        check_raw(receipt, raw_artifacts, spec)
        check_callback(receipt, raw_artifacts["phase4-events.jsonl"], spec)
        return []
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError) as exc:
        return [str(exc)]


def validate_event_boundary_operation(case_id, receipt, retained_children):
    """Check sealed at/over child receipts; caller supplies safe raw reads."""
    try:
        variants = ("long-query",) if case_id == "event_metadata_truncation" else ("at255", "over256")
        require(case_id in IDS, "unknown event operation")
        equal_fields(receipt, {"schema_version": 1, "case_id": case_id,
                              "operation": "native_event_boundary_request",
                              "uri_buffer_bytes": URI_BUFFER_BYTES, "writer_buffer_bytes": WRITER_BUFFER_BYTES})
        run_id = receipt.get("run_id")
        require(isinstance(run_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,96}", run_id), "invalid enclosing run identity")
        require(all(isinstance(receipt.get(field), str) and re.fullmatch(r"[0-9a-f]{40}", receipt[field])
                    for field in ("parent_sha", "framework_sha", "mrts_sha")), "coherent source identities required")
        require(isinstance(retained_children, dict) and set(retained_children) == set(variants), "missing/foreign event children")
        require(isinstance(receipt.get("children"), list) and len(receipt["children"]) == len(variants), "sealed children required")
        for descriptor, variant in zip(receipt["children"], variants):
            child = retained_children[variant]
            child_raw = child["receipt_bytes"]
            require(type(child_raw) is bytes and len(child_raw) <= 1024 * 1024, "bounded retained child receipt required")
            child_receipt = json_object(child_raw)
            equal_fields(descriptor, {"variant": variant, "directory": variant,
                                      "run_id": run_id + "-" + variant,
                                      "receipt_sha256": hashlib.sha256(child_raw).hexdigest()})
            equal_fields(child_receipt, {"run_id": descriptor["run_id"],
                                        **{field: receipt[field] for field in ("parent_sha", "framework_sha", "mrts_sha")}})
            errors = validate_event_boundary_child(case_id, variant, child_receipt, child["raw_artifacts"])
            require(not errors, "; ".join(errors))
        return []
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError) as exc:
        return [str(exc)]
