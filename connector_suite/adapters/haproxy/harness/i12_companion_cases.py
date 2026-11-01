"""Source-defined companion fixtures; observations never define expected values."""
from __future__ import annotations

import hashlib
import json
import struct

PLAIN_MIME = "text/plain"
CSV_MIME = "text/csv"
LEG = "haproxy-spop-htx-response-companion"
BODY = b"companion-physical-response-body\n"
NEIGHBOR = b"neighbor-ok\n"
PREFIX = "I12::" + LEG + "::"
MRC_PROTOCOL_VERSION = 2
ORIGINAL_IDS_SHA256 = "bb34ce6c26063b1c13df6087b0a3cc5034f227216720aeaca2f195fba38b33d1"
ORIGINAL_CONTRACTS_SHA256 = "f4ca4e4b97cf3cf5dd267684afdfa39a8fd5b9e8b88b71bf6470cb184ce7ea3b"


def body_for(fixture, neighbor=False):
    if neighbor:
        return NEIGHBOR
    kind = fixture.get("body", "single")
    marker = fixture.get("marker", "companion-physical").encode()
    single = marker + b"-response-body\n" if marker == b"companion-physical" else marker
    bodies = {"empty": b"", "single": single, "csv": b"id,value\n1,companion-physical\n",
              "large": b"x" * (1024 * 1024) + single, "at-limit": b"0123456789abcdef",
              "over-limit": b"0123456789abcdef ", "marker-end": b"x" * 65536 + marker}
    if kind not in bodies:
        raise ValueError("unknown source body fixture")
    return bodies[kind]


def fixture_mime_types(fixture):
    name = fixture["case_id"].rsplit("::", 1)[-1]
    return (PLAIN_MIME, CSV_MIME) if name.startswith(("NEED-", "HIST-")) else (PLAIN_MIME, "text/html", "application/json")


def native_rejects(fixture, body, neighbor):
    limit = fixture.get("native_limit")
    return not neighbor and limit is not None and len(body) > limit and fixture.get("limit_action") == "Reject"


def strict_aborts(fixture, body, neighbor):
    if neighbor or fixture.get("mode") != "strict":
        return False
    in_scope = str(fixture.get("content_type", "")).split(";", 1)[0] in fixture_mime_types(fixture)
    return in_scope and fixture.get("marker", "companion-physical").encode() in body


def native_prediction(fixture, body, neighbor):
    scenario = "safe" if neighbor else fixture.get("scenario", "safe")
    if scenario == "missing":
        return {"allocation": False, "decision": "correlation_missing", "rule_id": None, "eos": 0, "free": 0}
    if scenario == "expired":
        return {"allocation": True, "decision": "correlation_rejected_after_ttl", "rule_id": None, "eos": 0, "free": 1}
    if scenario in ("p3-deny", "p3-redirect"):
        return {"allocation": True, "decision": scenario, "rule_id": fixture["rule_id"], "eos": 0, "free": 1}
    if native_rejects(fixture, body, neighbor):
        return {"allocation": True, "decision": "native_body_limit_reject", "rule_id": None, "eos": 0, "free": 1}
    limit = fixture.get("native_limit", len(body))
    inspected = body[:limit]
    content_type = PLAIN_MIME if neighbor else fixture.get("content_type", "")
    in_scope = str(content_type).split(";", 1)[0] in fixture_mime_types(fixture)
    match = in_scope and fixture.get("marker", "companion-physical").encode() in inspected
    complete = neighbor or fixture.get("transport") == "complete"
    decision = "incomplete"
    if complete:
        decision = "deny" if match else "allow"
    return {"allocation": True, "decision": decision,
            "rule_id": fixture.get("rule_id") if match and complete else None,
            "eos": int(complete) if fixture.get("transport") != "cancel" else None, "free": 1}


def source_expectation(fixture, neighbor=False):
    body = body_for(fixture, neighbor)
    scenario = "safe" if neighbor else fixture.get("scenario", "safe")
    rejected = native_rejects(fixture, body, neighbor)
    strict = strict_aborts(fixture, body, neighbor) or rejected
    terminal = scenario in ("p3-deny", "p3-redirect", "missing", "expired")
    transport = "complete" if neighbor else fixture.get("transport", "complete")
    complete = not strict and not terminal and transport == "complete"
    status = 200
    if not neighbor:
        status = None if strict else fixture.get("status", 200)
    return {"source": "i12_companion_cases.py:body_for/source_expectation",
            "status": status,
            "source_body_bytes": len(body), "source_body_sha256": hashlib.sha256(body).hexdigest(),
            "body_bytes": len(body) if complete else None,
            "body_sha256": hashlib.sha256(body).hexdigest() if complete else None,
            "complete_body_required": complete, "complete_body_forbidden": strict and not fixture.get("pause_after_first"),
            "transport_abort_required": strict, "already_delivered_bytes_may_survive": strict,
            "backend_requests": 1, "native_allocation_expected": scenario != "missing",
            "native_eos_required": not terminal and not rejected and transport == "complete",
            "native_prediction": native_prediction(fixture, body, neighbor),
            "qualification": None}


PROFILE_OVERRIDES = (
    (("NEED-response-empty",), {"body": "empty"}),
    (("NEED-response-file", "NEED-response-above-former-connector-limit"), {"body": "large"}),
    (("NEED-response-csv",), {"body": "csv", "content_type": CSV_MIME}),
    (("NEED-response-marker-at-payload-end",), {"body": "marker-end"}),
    (("deny_response_header_marker_403", "phase3_response_header_rule", "phase3_deny_before_commit", "phase3_original_and_visible_status", "NEED-response-commit-order"), {"scenario": "p3-deny", "rule_id": 1100201, "status": 403}),
    (("phase3_redirect_before_commit",), {"scenario": "p3-redirect", "rule_id": 1100202, "status": 302}),
    (("NEED-allow", "single_request_cleanup", "multiple_sequential_requests", "keep_alive_requests_if_supported"), {"body": "empty", "rule_id": None}),
    (("phase4_marker_split_across_chunks", "NEED-response-streaming", "phase4_no_full_response_buffering", "phase4_first_byte_before_response_end"), {"chunk_size": 8, "pause_after_first": True}),
    (("phase4_content_type_with_charset",), {"content_type": "text/plain; charset=utf-8"}),
    (("phase4_out_of_scope_content_type",), {"content_type": "application/octet-stream"}),
    (("phase4_missing_content_type",), {"content_type": None}),
    (("phase4_body_at_limit",), {"body": "at-limit", "native_limit": 16, "limit_action": "Reject"}),
    (("phase4_body_over_limit", "phase4_body_reject"), {"body": "over-limit", "native_limit": 16, "limit_action": "Reject"}),
    (("phase4_body_process_partial",), {"body": "over-limit", "native_limit": 16, "limit_action": "ProcessPartial"}),
    (("NEED-correlation-claim-once",), {"mrc_fault": "claim-replay"}),
    (("NEED-missing-correlation",), {"scenario": "missing", "status": 503}),
    (("NEED-expired-correlation",), {"scenario": "expired", "status": 503}),
    (("NEED-cancel",), {"transport": "cancel"}),
    (("NEED-missing-eos", "NEED-incomplete-framing"), {"transport": "incomplete"}),
    (("NEED-neighbor-connection-stream", "HIST-SPOP-HTX-CORRELATION-CLEANUP"), {"scenario": "parallel", "count": 16, "parallel": True}),
    (("multiple_sequential_requests",), {"count": 4}),
)
FAULT_SEAMS = {
    "multiple_sequential_requests": "allow-deny-allow-driver",
    "phase4_deny_after_commit_log_only_minimal": "minimal-vs-safe-contract",
    "NEED-response-file": "native-response-file-contract",
    "NEED-response-above-former-connector-limit": "historical-former-limit-source",
    "early_mapping_failure_cleanup": "mapping", "transaction_begin_failure_cleanup": "native-begin",
    "finish_failure_propagation": "native-finish", "NEED-invalid-native-return": "native-return",
    "NEED-size-overflow": "size-overflow", "NEED-invalid-metadata": "metadata",
    "NEED-invalid-header": "header",
    "engine_timeout_before_commit": "native-timeout-precommit", "engine_timeout_after_commit": "native-timeout-postcommit",
    "NEED-timeout": "native-timeout", "response_short_write_resume": "short-write",
    "response_write_would_block_resume": "would-block", "keep_alive_requests_if_supported": "keepalive",
}


def fixture_profile(case_id):
    name = case_id.removeprefix(PREFIX)
    profile = {"case_id": case_id, "body": "single", "mode": "safe", "scenario": "safe",
               "content_type": PLAIN_MIME, "chunk_size": 65536, "pause_after_first": False,
               "transport": "complete", "count": 1, "parallel": False, "mrc_fault": None,
               "required_fault_seam": FAULT_SEAMS.get(name), "rule_id": 1100301, "status": 200,
               "native_limit": 4 * 1024 * 1024, "limit_action": "Reject", "native_request_limit": 1024,
               "marker": "companion-physical" if name.startswith(("NEED-", "HIST-")) else "no-crs-response-body-marker"}
    for names, overrides in PROFILE_OVERRIDES:
        if name in names:
            profile.update(overrides)
    if name.startswith("NEED-physical-event-sink-"):
        profile["required_fault_seam"] = name.removeprefix("NEED-physical-event-sink-")
    return profile


def companion_rows(inventory):
    ids = "\n".join(row["run_scoped_case_id"] for row in inventory["rows"]) + "\n"
    contracts = [row["original_selected_requirement"] for row in inventory["rows"]]
    encoded = json.dumps(contracts, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    if hashlib.sha256(ids.encode()).hexdigest() != ORIGINAL_IDS_SHA256 or hashlib.sha256(encoded).hexdigest() != ORIGINAL_CONTRACTS_SHA256:
        raise ValueError("frozen original inventory identity mismatch")
    rows = [row for row in inventory["rows"] if row["leg_id"] == LEG]
    if len(rows) != 72 or len({row["run_scoped_case_id"] for row in rows}) != 72:
        raise ValueError("exact 72 original companion IDs required")
    return rows


def bind_inventory(inventory):
    definitions = []
    for row in companion_rows(inventory):
        if row["execution_kind"] == "actual_configtest":
            continue
        case_id = row["run_scoped_case_id"]
        definition = fixture_profile(case_id)
        definition.update(schema="i12-companion-source-fixture-v2",
                          original_contract=row["original_selected_requirement"],
                          original_contract_sha256=row["original_selected_requirement_sha256"],
                          required_measurement_contract=row["required_measurement_contract"],
                          original_oracle=row["original_oracle"],
                          source_fixture_references=row["existing_fixture_references"])
        definition["expected"] = source_expectation(definition)
        definitions.append(definition)
    return definitions


def validate_fixture(fixture, selected_id):
    if fixture.get("schema") != "i12-companion-source-fixture-v2" or fixture.get("case_id") != selected_id:
        raise ValueError("exact companion fixture case binding required")
    contract = fixture.get("original_contract", {})
    if contract.get("run_scoped_case_id") != selected_id or not selected_id.startswith(PREFIX):
        raise ValueError("original companion contract required")
    digest = hashlib.sha256(json.dumps(contract, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if digest != fixture.get("original_contract_sha256"):
        raise ValueError("original selected contract hash mismatch")
    if fixture.get("required_fault_seam"):
        raise ValueError("required fault seam is not implemented: " + fixture["required_fault_seam"])
    validate_controls(fixture)
    expected = source_expectation(fixture)
    if fixture.get("expected") != expected:
        raise ValueError("fixture oracle differs from source prediction")
    return fixture


def mrc_frame(opcode, payload=b""):
    return b"MRC1" + bytes((MRC_PROTOCOL_VERSION, opcode, 0, 0)) + struct.pack("!I", len(payload)) + payload


def mutate_outcome(frame, mode):
    if frame[5] != 8 or mode in (None, "claim-replay", "claim-owner"):
        return frame
    if mode == "missing":
        return mrc_frame(7)
    if mode == "wrong":
        return frame[:12] + bytes((frame[12], frame[13], 0, 200))
    if mode == "stale":
        return frame[:12] + bytes((frame[12], frame[13], 1, 147))
    raise ValueError("unknown MRC1 fault mode")


def complete_mrc_frames(pending):
    frames = []
    while len(pending) >= 12:
        if pending[:4] != b"MRC1" or pending[4] != MRC_PROTOCOL_VERSION:
            raise ValueError("unexpected MRC1 header at physical tap")
        size = struct.unpack("!I", pending[8:12])[0]
        if size > 1024 * 1024:
            raise ValueError("unbounded MRC1 frame")
        if len(pending) < 12 + size:
            break
        frames.append(bytes(pending[:12 + size]))
        del pending[:12 + size]
    return frames


def response_measurements(response):
    boundary = response.find(b"\r\n\r\n")
    if boundary < 0:
        return {"status": None, "body_bytes": 0, "body_sha256": None, "body_hex": "", "headers_complete": False,
                "framing_kind": "incomplete_headers", "declared_body_bytes": None, "complete_length_framing": None}
    headers, body = response[:boundary], response[boundary + 4:]
    fields = headers.split(b"\r\n", 1)[0].split(b" ")
    status = int(fields[1]) if len(fields) > 1 and fields[1].isdigit() else None
    result = {"status": status, "body_bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest(),
              "headers_complete": True, "body_hex": body.hex(), "response_bytes": len(response),
              "response_sha256": hashlib.sha256(response).hexdigest()}
    result.update(response_framing(headers, body))
    return result


def response_framing(headers, body):
    fields = [line.split(b":", 1) for line in headers.split(b"\r\n")[1:] if b":" in line]
    lengths = [value.strip() for name, value in fields if name.lower() == b"content-length"]
    transfer = [value.strip().lower() for name, value in fields if name.lower() == b"transfer-encoding"]
    declared = None
    if not transfer and len(lengths) == 1 and len(lengths[0]) <= 20 and lengths[0].isdigit():
        value = int(lengths[0])
        declared = value if value <= (1 << 64) - 1 else None
    kind = "content_length" if declared is not None else "chunked_or_unknown"
    return {"framing_kind": kind, "declared_body_bytes": declared,
            "complete_length_framing": len(body) == declared if declared is not None else None,
            "body_length_underflow": len(body) < declared if declared is not None else None}


def compare_response(expected, observed, source_body=None, transport=None):
    checks = {"status_matches": expected["status"] is None or observed["status"] == expected["status"]}
    if expected["complete_body_required"]:
        checks["body_matches"] = all(expected[key] == observed[key] for key in ("body_bytes", "body_sha256"))
        checks["headers_complete"] = observed.get("headers_complete") is True
        checks["declared_framing_matches"] = observed.get("framing_kind") == "content_length" and observed.get("declared_body_bytes") == expected["body_bytes"]
        checks["length_framing_complete"] = observed.get("complete_length_framing") is True
    if expected["complete_body_forbidden"]:
        checks["complete_body_absent"] = observed["body_sha256"] != expected["source_body_sha256"]
    if expected.get("transport_abort_required"):
        checks["transport_abort_observed"] = transport_abort_observed(transport)
    if expected.get("transport_abort_required") and source_body is not None:
        checks["body_is_source_prefix"] = source_body.startswith(bytes.fromhex(observed.get("body_hex", "")))
    return checks


def outcome_negative_fixture(base, mode):
    if mode not in ("missing", "wrong", "stale"):
        raise ValueError("unknown outcome negative control")
    result = dict(base, scenario="p3-deny", rule_id=1100201, status=503, mrc_fault=mode,
                  p3_status=451 if mode == "stale" else 403,
                  additional_negative_control="outcome-" + mode, required_fault_seam=None)
    result["expected"] = source_expectation(result)
    return result


def validate_controls(fixture):
    choices = {"scenario": ("safe", "p3-deny", "p3-redirect", "missing", "expired", "parallel"),
               "mode": ("safe", "strict"), "limit_action": ("Reject", "ProcessPartial"), "transport": ("complete", "cancel", "incomplete"),
               "mrc_fault": (None, "missing", "wrong", "stale", "claim-replay"),
               "content_type": (None, PLAIN_MIME, "text/plain; charset=utf-8", CSV_MIME, "application/octet-stream")}
    for name, allowed in choices.items():
        if fixture.get(name) not in allowed:
            raise ValueError("unsupported fixture control: " + name)
    for name, maximum in (("count", 16), ("chunk_size", 65536), ("native_limit", 4 * 1024 * 1024), ("native_request_limit", 65536)):
        value = fixture.get(name)
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError("unbounded fixture control: " + name)
    if fixture.get("marker") not in ("companion-physical", "no-crs-response-body-marker"):
        raise ValueError("unsupported source rule marker")
    if fixture.get("rule_id") not in (None, 1100201, 1100202, 1100301):
        raise ValueError("original source rule identity required")
    if fixture.get("p3_status", 403) not in (403, 451):
        raise ValueError("unsupported P3 status fixture")


def transport_abort_observed(transport):
    if not transport:
        return False
    if transport.get("kernel_tcp_reset") is True:
        return True
    return (transport.get("error_type") == "SSLEOFError" and
            transport.get("tls_eof") == "exception" and transport.get("kernel_tcp_eof") is True)
