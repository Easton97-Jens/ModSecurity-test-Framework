#!/usr/bin/env python3
"""Materialize Apache inputs for every immutable I12 ID; never issue verdicts.

Rules and original oracles remain separate from candidate expectations. This
module plans real operations. A driver must reject unsupported seams instead of
claiming their operation or manufacturing an observation.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path

# Load the maintained Parent filesystem boundary from this checkout.
import sys as _i12_sys

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths


APACHE_IDS_SHA256 = "4c660ea9f259f43f13b5b3c7e1e09815a65d537dd5dcddfce446ee0183468c73"
APACHE_CONTRACTS_SHA256 = "2a470a552e424d149b601b11040694e79ff8f03d9421838c37dae51d823e2c33"
TEXT_PLAIN = "text/plain"
PREFIX_BYTES = b"prefix "

CONFIG_CASES = {
    "valid_rules_file": (["modsecurity_rules_file @@BASELINE_RULES@@"], 0),
    "missing_rules_file": (["modsecurity_rules_file @@CASE_ROOT@@/absent.rules"], 1),
    "invalid_rule_syntax": (["modsecurity_rules 'SecRule REQUEST_URI'"], 1),
    "unknown_config_key": (["modsecurity_unknown_config_key on"], 1),
    "invalid_boolean": (["modsecurity maybe"], 1),
    "invalid_status": (["modsecurity_rules 'SecRule REQUEST_URI \"@unconditionalMatch\" \"id:1100901,phase:1,deny,status:not-a-number\"'"], 1),
    "invalid_size": (["modsecurity_phase4_body_limit 1048576"], 1),
    "unsafe_event_path": (["modsecurity_phase4_log @@CASE_ROOT@@/unsafe-event-directory"], 1),
    "phase4_invalid_scope_file": (["modsecurity_phase4_content_types_file @@INVALID_SCOPE@@"], 1),
    "phase4_wildcard_scope_rejected": (["modsecurity_phase4_content_types_file @@WILDCARD_SCOPE@@"], 1),
}

REQUEST_MARKER = b"no-crs-request-body-marker"
RESPONSE_MARKER = b"no-crs-response-body-marker"
HISTORICAL_RULES = "\n".join([
    'SecRule REQUEST_URI "@beginsWith /" "id:120001,phase:1,pass,log,msg:I12-native-allow"',
    'SecRule REQUEST_URI "@streq /p1" "id:120011,phase:1,deny,status:403,log"',
    'SecRule REQUEST_URI "@streq /sink-disruptive" "id:120016,phase:1,deny,status:403,log,msg:I12-sink-mandatory-control"',
    'SecRule REQUEST_BODY "@contains P2BLOCK" "id:120012,phase:2,deny,status:403,log"',
    'SecRule REQUEST_URI "@streq /p3" "id:120013,phase:3,deny,status:403,log"',
    'SecRule REQUEST_URI "@streq /redirect" "id:120014,phase:3,redirect:http://127.0.0.1/redirect-target,log"',
    'SecRule RESPONSE_BODY "@contains LATEBLOCK" "id:120015,phase:4,deny,status:403,log"',
]) + "\n"


def source_reference(path, kind):
    path = Path(path).resolve()
    content = path.read_bytes()
    return {"path": str(path), "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content), "kind": kind}


def byte_input(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return {"encoding": "base64", "data": base64.b64encode(value).decode("ascii"),
            "bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}


def input_bytes(value):
    content = base64.b64decode(value["data"], validate=True)
    if len(content) != value["bytes"] or hashlib.sha256(content).hexdigest() != value["sha256"]:
        raise ValueError("body identity mismatch")
    return content


def ordered_headers(value):
    if isinstance(value, dict):
        return [[str(k), str(v)] for k, v in value.items()]
    result = []
    for item in value or []:
        result.append([str(item["name"]), str(item["value"])])
    return result


def set_header(headers, name, value):
    headers[:] = [item for item in headers if item[0].lower() != name.lower()]
    if value is not None:
        headers.append([name, value])


def config_case(case_id):
    """Only the ten selected parser contracts may enter this path."""
    if case_id not in CONFIG_CASES:
        raise ValueError("unknown Apache configuration case: " + case_id)
    directives, expected = CONFIG_CASES[case_id]
    return {"directives": list(directives), "expected_exit_code": expected,
            "operation": "apache_configtest", "request": None,
            "setup": ["mkdir_mode_0755:@@CASE_ROOT@@/unsafe-event-directory"]
            if case_id == "unsafe_event_path" else [],
            "required_observation_predicates": ["current_source_build_loaded_identity",
                "effective_config_and_rules_hashed", "waited_configtest_exit",
                "diagnostic_matches_original_error_class", "no_host_started"]}


def resolve_request(case_id, catalog, visited=()):
    if case_id in visited:
        raise ValueError("cyclic canonical request alias")
    entry = catalog.get(case_id, {})
    request = copy.deepcopy(entry.get("request", {}))
    reused = request.pop("reuses", None)
    if reused:
        result = resolve_request(reused, catalog, visited + (case_id,))
        result.update(request)
        return result
    return request


def fixture_for(entry, framework, yaml_loader):
    request = entry.get("request", {})
    name = entry.get("runner_case") or request.get("fixture")
    if not name:
        return None, None
    root = (framework / "tests/cases/no-crs-baseline").resolve()
    path = (root / name).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError("canonical fixture outside selected fixture root or missing")
    return yaml_loader(path.read_text()), source_reference(path, "original_fixture")


def fixture_entry(case_id, catalog, visited=()):
    if case_id in visited:
        raise ValueError("cyclic canonical fixture alias")
    entry = catalog.get(case_id, {})
    if entry.get("runner_case") or entry.get("request", {}).get("fixture"):
        return entry
    reused = entry.get("request", {}).get("reuses")
    return fixture_entry(reused, catalog, visited + (case_id,)) if reused else entry


def fault(kind, boundary, operation):
    return {"kind": kind, "boundary": boundary, "operation": operation,
            "activation": "exact_main_request_id_once", "expected_return": None,
            "must_observe_real_operation": True}


def base_host(case_id, ordinal):
    token = "apache-i12-%03d-%s" % (ordinal, case_id.replace("_", "-"))
    return {"request": {"method": "GET", "path": "/i12/" + case_id,
                "headers": [["X-I12-ID", token]], "body": byte_input(b""),
                "chunks": [], "framing": "content_length", "peer_action": "normal"},
            "backend": {"status": 200, "headers": [["Content-Type", TEXT_PLAIN]],
                "body": byte_input(b"Apache I12 healthy body\n"), "chunks": [],
                "framing": "content_length", "principal_only": True,
                "barrier": None, "peer_fault": None, "file": None},
            "controls": [{"label": "followup", "method": "GET", "path": "/followup",
                          "expected_status": 200, "backend_headers": [["Content-Type", TEXT_PLAIN]],
                          "backend_body": byte_input(b"OK\n")},
                         {"label": "neighbor", "method": "GET", "path": "/neighbor",
                          "connection": "independent", "expected_status": 200,
                          "backend_headers": [["Content-Type", TEXT_PLAIN]],
                          "backend_body": byte_input(b"OK\n")}],
            "apache": {"phase4_mode": "safe", "config_directives": [],
                       "transaction_id_expression": "%{req:X-I12-ID}"},
            "rules": "", "fault": None, "driver_seams": [],
            "candidate_expectation": {"visible_status": None, "native_status": None,
                "native_rule_id": None, "native_phase": None, "backend_requests": None},
            "execution_observed": None, "outcome": None,
            "unique_main_request": {"token": token, "required": True,
                "counting_key": "observed_process_connection_and_native_transaction_allocation"}}


def apply_canonical_request(plan, fixture, request):
    combined = copy.deepcopy(fixture.get("request", {}) if fixture else {})
    combined.update({k: v for k, v in request.items() if k in ("method", "path", "headers", "body")})
    for key in ("method", "path"):
        if key in combined:
            plan["request"][key] = combined[key]
    if "headers" in combined:
        plan["request"]["headers"] += ordered_headers(combined["headers"])
    if "body" in combined:
        plan["request"]["body"] = byte_input(str(combined["body"]))
    elif "body_fixture" in request:
        plan["request"]["body"] = byte_input(request["body_fixture"])


def apply_canonical_fixture(plan, fixture):
    if not fixture:
        return
    plan["rules"] = fixture.get("rules", "")
    response = fixture.get("response", {})
    if "body" in response:
        plan["backend"]["body"] = byte_input(str(response["body"]))
    if "content_type" in response:
        set_header(plan["backend"]["headers"], "Content-Type", response["content_type"])
    plan["backend"]["headers"] += ordered_headers(response.get("headers", {}))


def apply_canonical(plan, entry, fixture, request):
    apply_canonical_request(plan, fixture, request)
    apply_canonical_fixture(plan, fixture)
    if "response_body_fixture" in request:
        plan["backend"]["body"] = byte_input(request["response_body_fixture"])
    if "response_fixture" in request:
        name, _, value = request["response_fixture"].partition(":")
        set_header(plan["backend"]["headers"], name, value.strip())
    variant = request.get("content_type_variant")
    if variant:
        types = {"in_scope": TEXT_PLAIN, "charset": "text/plain; charset=utf-8",
                 "out_of_scope": "image/png", "missing": None}
        if variant not in types:
            raise ValueError("unknown content-type variant")
        set_header(plan["backend"]["headers"], "Content-Type", types[variant])
    if request.get("transport_variant") == "http11_chunked":
        plan["backend"]["framing"] = "chunked"
    expectation = plan["candidate_expectation"]
    expectation.update(visible_status=entry.get("expected_status"),
                       native_rule_id=entry.get("expected_rule_id"), native_phase=entry.get("phase"))


def historical_chunks(uri):
    if "empty" in uri:
        return []
    if "late" in uri or "postcommit" in uri:
        return [b"FIRST-I12\n", b"LATEBLOCK-I12\n", b"LAST-I12\n"]
    if "multi" in uri:
        return [b"FIRST-I12\n", b"MIDDLE-I12\n", b"LAST-I12\n"]
    return [b"ALLOW-I12\n"]


def historical_mime(uri):
    if "missing-content-type" in uri:
        return None
    if "scopeout" in uri:
        return "application/octet-stream"
    if "with-charset" in uri:
        return "text/plain; charset=utf-8"
    return TEXT_PLAIN


def configure_historical_fault(plan, original):
    mode = original.get("fault")
    if not mode:
        return
    native = mode in ("precommit", "postcommit")
    boundary = "native_api" if native else "physical_event_sink"
    seam = "native_" + mode if native else "physical_sink_" + mode
    plan["fault"] = fault(mode, boundary, "original_direct_runner_" + mode)
    plan["driver_seams"].append(seam)
    if not native:
        return
    sdk_boundary = "msc_process_request_headers" if mode == "precommit" else "msc_append_response_body"
    plan["controlled_fault_contract"] = controlled_fault_contract(
        sdk_boundary, 0 if mode == "precommit" else -1,
        "explicit_call_or_skip_with_separate_original_result")
    plan["controlled_fault_contract"].update(
        historical_fault_call_ordinal=1 if mode == "precommit" else 2,
        historical_sdk_called_on_fault=False,
        require_actual_commit_before_fault=mode == "postcommit")


def historical_case(plan, original):
    """Preserve the old direct runner's URI, rule IDs and byte generation."""
    plan["request"]["path"] = original["uri"]
    plan["apache"]["phase4_mode"] = original["mode"]
    plan["rules"] = ("SecRequestBodyLimit %d\nSecRequestBodyNoFilesLimit %d\n"
                     "SecRequestBodyLimitAction %s\nSecResponseBodyLimit %d\n"
                     "SecResponseBodyLimitAction %s\n" %
                     (original["request_limit"], original["request_limit"], original["request_action"],
                      original["response_limit"], original["response_action"])) + HISTORICAL_RULES
    if original["name"] == "p2-deny":
        plan["request"].update(method="POST", body=byte_input(b"P2BLOCK-I12"))
        set_header(plan["request"]["headers"], "Content-Type", TEXT_PLAIN)
    chunks = historical_chunks(original["uri"])
    plan["backend"].update(body=byte_input(b"".join(chunks)), chunks=[byte_input(x) for x in chunks],
                           framing="chunked", chunk_delay_seconds=0.15)
    set_header(plan["backend"]["headers"], "Content-Type", historical_mime(original["uri"]))
    plan["candidate_expectation"].update(visible_status=original["expected"].get("http_status"),
                                       backend_requests=original["expected"].get("backend_requests"))
    configure_historical_fault(plan, original)


def _configure_phase3(plan, case_id):
    backend = plan['backend']
    expected = plan['candidate_expectation']
    if not case_id.startswith('phase3_') and case_id != 'deny_response_header_marker_403':
        return
    redirect = 'redirect' in case_id
    set_header(backend['headers'], 'X-Modsec-Upstream', 'redirect' if redirect else 'block')
    backend['principal_only'] = True
    plan['variant_reason'] = 'Backend marker applies only to principal URI; unchanged native rule; healthy controls omit marker'
    expected.update(visible_status=302 if redirect else 403, backend_requests=1, native_rule_id=1100202 if redirect else 1100201, native_phase=3)

def _configure_phase4_marker(plan, case_id):
    backend = plan['backend']
    expected = plan['candidate_expectation']
    low = case_id.lower()
    if not low.startswith('phase4'):
        return
    if any(x in low for x in ('limit', 'partial', 'reject', 'scope', 'content_type')):
        return
    payload = input_bytes(backend['body'])
    if RESPONSE_MARKER not in payload:
        payload = PREFIX_BYTES + RESPONSE_MARKER
        backend['body'] = byte_input(payload)
    marker_at = payload.index(RESPONSE_MARKER)
    split = marker_at if marker_at > 0 else min(8, len(payload))
    backend['chunks'] = [byte_input(payload[:split]), byte_input(payload[split:])]
    backend['framing'] = 'chunked'
    expected.update(native_rule_id=1100301, native_phase=4)

def _configure_late_mode(plan, case_id):
    low = case_id.lower()
    if any(x in low for x in ('strict', 'after_commit_abort')):
        plan['apache']['phase4_mode'] = 'strict'
    elif low.endswith('_minimal'):
        plan['variant_conflicts'] = ['Apache exposes off/safe/strict, no separate minimal mode; Safe is not silently substituted for minimal']
        plan['driver_seams'].append('independent_minimal_to_apache_mode_reconciliation')

def _configure_body_limit(plan, case_id, contract, fixture):
    request = plan['request']
    backend = plan['backend']
    expected = plan['candidate_expectation']
    if case_id not in ('phase2_at_limit', 'phase2_over_limit', 'phase2_truncated', 'full_lifecycle_event_metadata_bounded', 'phase4_body_at_limit', 'phase4_body_over_limit', 'phase4_body_process_partial', 'phase4_body_reject'):
        return
    phase = 2 if case_id.startswith('phase2') else 4
    limit = (fixture or {}).get('full_lifecycle', {}).get('limit_bytes', 16)
    size = limit if case_id.endswith('at_limit') else limit + 1
    partial = case_id.endswith(('truncated', 'process_partial'))
    action = 'ProcessPartial' if partial else 'Reject'
    prefix = 'Request' if phase == 2 else 'Response'
    plan['rules'] += '\nSec%sBodyLimit %d\nSec%sBodyLimitAction %s\n' % (prefix, limit, prefix, action)
    if phase == 2:
        plan['rules'] += 'SecRequestBodyNoFilesLimit %d\n' % limit
        request.update(method='POST', body=byte_input(b'a' * size))
        set_header(request['headers'], 'Content-Type', TEXT_PLAIN)
    else:
        backend.update(body=byte_input(b'a' * size), chunks=[], framing='content_length')
        set_header(backend['headers'], 'Content-Type', TEXT_PLAIN)
    plan['limit_variant'] = {'phase': phase, 'limit_bytes': limit, 'wire_bytes': size, 'native_action': action, 'native_buffer_bytes': limit if partial else None, 'native_limit_intervention_status': 403 if size > limit and (not partial) else None, 'native_limit_rule_id': None, 'actual_transport_truncation': False, 'original_marker_rule_expected': contract['expected_oracle'].get('rule_id')}
    plan['variant_conflicts'] = ['Original physical limit metadata and marker-rule expectation require independent reconciliation; native limit decision has no intrinsic rule ID']
    expected.update(native_status=403 if size > limit and (not partial) else 200, native_rule_id=None, native_phase=phase)

def _configure_request_data(plan, case_id):
    request = plan['request']
    if not case_id.startswith('NEED-request-'):
        return
    request.update(method='POST', body=byte_input(b'Apache-I12-request-payload'))
    set_header(request['headers'], 'Content-Type', TEXT_PLAIN)
    if case_id.endswith('empty'):
        request['body'] = byte_input(b'')
    if case_id.endswith('content-type-missing'):
        set_header(request['headers'], 'Content-Type', None)
    if case_id.endswith('charset-present'):
        set_header(request['headers'], 'Content-Type', 'text/plain; charset=utf-8')
    if case_id.endswith('csv'):
        request['body'] = byte_input(b'column_a,column_b\nvalue_a,value_b\n')
        set_header(request['headers'], 'Content-Type', 'text/csv')
    if case_id.endswith('file'):
        payload = b'--i12boundary\r\nContent-Disposition: form-data; name=upload; filename=i12.txt\r\nContent-Type: text/plain\r\n\r\nApache-I12-file-payload\r\n--i12boundary--\r\n'
        request['body'] = byte_input(payload)
        set_header(request['headers'], 'Content-Type', 'multipart/form-data; boundary=i12boundary')
        plan['driver_seams'].append('native_multipart_file_collection_and_upload_tmp_cleanup')
        plan['rules'] += '\nSecUploadDir @@CASE_ROOT@@/uploads\nSecUploadKeepFiles Off\n'
        plan['file_input_provenance'] = {
            'operation': 'multipart_upload_over_HTTP',
            'local_payload_file_is_native_file_bucket': False,
            'native_upload_collection_observed': None,
            'native_upload_tmp_cleanup_observed': None,
            'actual_APR_FILE_bucket_observed': None}
    if 'mime-scope' in case_id:
        set_header(request['headers'], 'Content-Type', TEXT_PLAIN if case_id.endswith('in') else 'image/png')
        plan['variant_conflicts'] = ['SDK has no request MIME allowlist equivalent to response SecResponseBodyMimeType; raw-body ingestion candidate requires explicit original-obligation reconciliation']
    if case_id.endswith('marker-at-payload-end'):
        request['body'] = byte_input(b'a' * 65536 + REQUEST_MARKER)

def _configure_response_data(plan, case_id):
    backend = plan['backend']
    if not case_id.startswith('NEED-response-'):
        return
    backend['body'] = byte_input(b'Apache-I12-response-payload')
    if case_id.endswith('csv'):
        backend['body'] = byte_input(b'column_a,column_b\nvalue_a,value_b\n')
        set_header(backend['headers'], 'Content-Type', 'text/csv')
        plan['rules'] += '\nSecResponseBodyMimeType text/csv\n'
    if case_id.endswith('file'):
        backend['file'] = {'path': '@@CASE_ROOT@@/static' + plan['request']['path'], 'content': backend['body'], 'serving': 'apache_static_file', 'require_actual_file_bucket': True}
        plan['driver_seams'].append('actual_APR_FILE_bucket_capture')
        plan['file_input_provenance'] = {
            'operation': 'planned_apache_static_file_response',
            'local_payload_file_is_native_file_bucket': False,
            'static_route_executed': None,
            'actual_APR_FILE_bucket_observed': None}
    if case_id.endswith('marker-at-payload-end'):
        backend['body'] = byte_input(b'a' * 65536 + RESPONSE_MARKER)

def _configure_former_limit(plan, case_id):
    request = plan['request']
    backend = plan['backend']
    if 'above-former-connector-limit' not in case_id:
        return
    target = request if 'request' in case_id else backend
    size = 10 * 1024 * 1024 + 1
    marker = REQUEST_MARKER if 'request' in case_id else RESPONSE_MARKER
    target['body'] = byte_input(b'a' * (size - len(marker)) + marker)
    plan['rules'] += '\nSecRequestBodyLimit 16777216\nSecRequestBodyNoFilesLimit 16777216\nSecResponseBodyLimit 16777216\n'
    plan['former_limit_proof'] = {'former_limit_bytes': 10485760, 'candidate_bytes': size, 'marker_at_payload_end': byte_input(marker), 'native_limit_bytes': 16777216, 'source_history_receipt': None, 'source_reviewed_by': None, 'qualification_requires_numeric_original_source': True}

def _configure_streaming(plan, case_id):
    request = plan['request']
    backend = plan['backend']
    low = case_id.lower()
    streaming = any(x in low for x in ('streaming', 'split_across_chunks', 'first_byte', 'no_full_response_buffering'))
    if not streaming:
        return
    request_stream = 'request' in low or low.startswith('phase2')
    response = not request_stream
    target = backend if response else request
    chunks = [b'no-crs-response-', b'body-marker'] if response else [b'no-crs-request-', b'body-marker']
    target.update(body=byte_input(b''.join(chunks)), chunks=[byte_input(x) for x in chunks], framing='chunked')
    if not response:
        request['method'] = 'POST'
        set_header(request['headers'], 'Content-Type', TEXT_PLAIN)
    target['barrier'] = {'after_chunk': 1, 'release_condition': 'client_received_first_chunk' if response else 'native_append_first_chunk_observed', 'timeout_seconds': 5}
    plan['driver_seams'].append('causal_response_barrier' if response else 'causal_native_request_append_barrier')

def _configure_nonzero_body(plan, case_id):
    request = plan['request']
    if case_id != 'body_size_nonzero_with_null_data':
        return
    request.update(method='POST', body=byte_input(b'actual-nonzero-bucket'))
    set_header(request['headers'], 'Content-Type', TEXT_PLAIN)

def _configure_nonzero_headers(plan, case_id):
    request = plan['request']
    if case_id != 'header_count_nonzero_with_null_headers':
        return
    set_header(request['headers'], 'X-I12-Input-Fault', 'nonempty')

def _configure_keepalive_response(plan, case_id):
    backend = plan['backend']
    low = case_id.lower()
    if case_id not in ('keepalive_safe_followup', 'keepalive_after_strict_new_connection'):
        return
    backend.update(body=byte_input(PREFIX_BYTES + RESPONSE_MARKER),
                   chunks=[byte_input(PREFIX_BYTES), byte_input(RESPONSE_MARKER)], framing='chunked')
    plan['apache']['phase4_mode'] = 'strict' if 'strict' in low else 'safe'

def _configure_shutdown(plan, case_id):
    expected = plan['candidate_expectation']
    if case_id != 'clean_shutdown':
        return
    expected['visible_status'] = 200
    plan['process_operation'] = {'after_controls': 'SIGTERM_owned_host_and_wait', 'expected_host_exit': 0}
    plan['variant_conflicts'] = ['Original status0 describes shutdown command, not HTTP status; keep original contract, qualify process exit separately']

def _configure_malformed_request(plan, case_id):
    request = plan['request']
    malformed = {'invalid_content_length': [['Content-Length', 'invalid']], 'conflicting_content_length': [['Content-Length', '1'], ['Content-Length', '2']], 'duplicate_transfer_encoding': [['Transfer-Encoding', 'chunked'], ['Transfer-Encoding', 'chunked']], 'content_length_overflow': [['Content-Length', '18446744073709551616']]}
    if case_id not in malformed:
        return
    request['headers'] += malformed[case_id]
    request['framing'] = 'raw_no_normalization'
    plan['driver_seams'].append('raw_wire_preserve_invalid_framing')

def _configure_native_fault(plan, case_id):
    boundary_faults = {'body_size_nonzero_with_null_data': ('apache_input_filter_process_bucket', 'substitute_NULL_data_keep_nonzero_actual_bucket_length'), 'header_count_nonzero_with_null_headers': ('apache_request_mapper', 'substitute_NULL_header_table_keep_nonzero_count'), 'early_mapping_failure_cleanup': ('msc_add_request_header', 'controlled_header_mapping_failure_after_real_call_keep_original_result'), 'transaction_begin_failure_cleanup': ('msc_new_transaction_with_id', 'controlled_null_transaction_constructor_result_not_allocator_OOM'), 'finish_failure_propagation': ('msc_process_logging', 'controlled_native_logging_failure_after_real_call'), 'NEED-invalid-native-return': ('msc_process_request_headers', 'controlled_invalid_return_after_real_call_keep_original_return_record'), 'NEED-invalid-metadata': ('msc_apache_contract_begin', 'invalid_phase_enum_at_principal_boundary'), 'response_short_write_resume': ('ap_pass_brigade', 'real_short_write_then_resume_same_brigade'), 'response_write_would_block_resume': ('ap_pass_brigade', 'real_nonblocking_pipe_saturation_APR_EAGAIN_then_drain_resume')}
    if case_id not in boundary_faults:
        return
    boundary, operation = boundary_faults[case_id]
    plan['fault'] = fault('native_boundary', boundary, operation)
    plan['driver_seams'].append(operation)
    if case_id in ('early_mapping_failure_cleanup', 'transaction_begin_failure_cleanup', 'finish_failure_propagation'):
        constructor = case_id == 'transaction_begin_failure_cleanup'
        plan['controlled_fault_contract'] = controlled_fault_contract(
            boundary, None if constructor else 0, 'not_called_when_injected' if constructor else 'call_original_first')


def controlled_fault_contract(boundary, effective_result, call_policy):
    return {'boundary': boundary, 'operation_kind': 'explicit_controlled_fault_at_real_host_boundary',
        'controlled_effective_result': effective_result, 'sdk_call_policy': call_policy,
        'controlled_result_is_actual_sdk_return': False,
        'require_actual_original_result_when_sdk_called': True,
        'require_explicit_sdk_not_called_witness_when_skipped': True,
        'require_real_host_failure_and_cleanup': True,
        'genuine_allocator_OOM_required': False, 'elapsed_timeout_budget_required': False,
        'activation_observed': None, 'actual_sdk_result': None, 'actual_host_result': None,
        'source_basis': 'Original catalog86-88 names fault_injection and failure_propagated_and_cleaned, not allocator OOM; historical direct fault.c10-19 returns controlled0/-1, not elapsed timeout'}


def _configure_timeout(plan, case_id):
    low = case_id.lower()
    if 'timeout' not in low:
        return
    plan['fault'] = fault('timeout', 'msc_process_response_body' if 'after_commit' in low else 'msc_process_request_headers', 'real_monotonic_delay_exceed_authoritative_budget')
    plan['fault']['delay_ms'] = 100
    plan['driver_seams'].append('apache_authoritative_budget_capture_not_fake_return')

def _configure_physical_sink(plan, case_id):
    request = plan['request']
    if not case_id.startswith('NEED-physical-event-sink-'):
        return
    operation = case_id.removeprefix('NEED-physical-event-sink-')
    request['path'] = '/sink-disruptive'
    plan['rules'] += HISTORICAL_RULES
    apr_operation = 'write' if operation == 'short-write' else operation
    plan['fault'] = fault('physical_sink', 'apr_file_' + apr_operation, 'real_' + operation + '_failure_at_principal_sink')
    plan['fault']['native_rule_attribution'] = 'independently_observe120016_without_delaying_or_reordering_first_sink_failure'
    plan['driver_seams'].append('physical_sink_' + operation + '_with_independent_first_failure_and_native120016_join')

def _configure_abnormal_transport(plan, case_id):
    request = plan['request']
    if case_id not in ('NEED-missing-eos', 'NEED-incomplete-framing', 'NEED-cancel', 'NEED-client-exit-signal', 'NEED-abort-reset-observation'):
        return
    request.update(method='POST', body=byte_input(b'incomplete'), framing='content_length_overdeclared', declared_content_length=128, peer_action='shutdown_write_before_body_complete')
    if case_id.endswith('cancel'):
        request['peer_action'] = 'cancel_client_process_after_first_native_append'
    elif case_id.endswith('client-exit-signal'):
        request['peer_action'] = 'SIGTERM_client_process_after_first_native_append'
    elif case_id.endswith('abort-reset-observation'):
        request['peer_action'] = 'SO_LINGER_zero_RST_after_first_native_append'
    plan['driver_seams'].append(request['peer_action'])

def _configure_sequence(plan, case_id):
    low = case_id.lower()
    sequence = any(x in low for x in ('keepalive', 'keep_alive', 'sequential', 'neighbor-connection'))
    if not sequence:
        return
    plan['sequence'] = {'connection': 'same_http11_keepalive', 'requests': ['main', 'followup'], 'independent_neighbor': True}
    if 'allow_deny_allow' in low:
        plan['sequence']['requests'] = ['main', 'p1_deny', 'followup']
    if 'strict' in low:
        plan['sequence']['connection'] = 'new_after_strict_abort'
    plan['driver_seams'].append('raw_connection_sequence_transaction_join')

def _configure_event_boundary(plan, case_id):
    request = plan['request']
    expected = plan['candidate_expectation']
    if case_id not in ('event_metadata_truncation', 'event_json_limit'):
        return
    set_header(request['headers'], 'X-Modsec-Smoke', 'log-only')
    prefix = '/no-crs/events/'
    size = 4096 if case_id == 'event_metadata_truncation' else 255
    suffix = '?probe=non-sensitive' if case_id == 'event_metadata_truncation' else ''
    request['path'] = prefix + 'x' * (size - len(prefix) - len(suffix)) + suffix
    plan['event_boundary_variant'] = {'raw_target_bytes': size, 'uri_buffer_bytes': 256, 'writer_buffer_bytes': 4096, 'writer_buffer_configurable': False, 'source_basis': 'common/include/msconnector/event.h33 URI buffer256; Apache msc_filters.c667 writer4096; original1100402 message remains constant', 'previous_fixture_error': 'Previous8192-byte header could fail Apache Core8190 field limit before native evaluation; original plan retained'}
    expected.update(visible_status=200, native_rule_id=1100402, native_phase=1, backend_requests=1)
    if case_id == 'event_json_limit':
        other = copy.deepcopy(request)
        other['path'] = prefix + 'x' * (256 - len(prefix))
        plan['principal_request_variants'] = [{'label': 'over256', 'request': other}]
        plan['event_boundary_variant']['unproven_requirement'] = '255/256 URI inputs exercise field boundary, not total4096-byte serializer boundary. Apache has no configurable JSON writer limit; actual total-buffer at/over proof still required'
        plan['driver_seams'].append('actual_total_JSON_serializer_4096byte_boundary_proof')

def _configure_supplemental_rule(plan, case_id):
    request = plan['request']
    expected = plan['candidate_expectation']
    if not case_id.startswith('NEED-') or plan['fault']:
        return
    plan['rules'] += '\nSecRule REQUEST_URI "@streq ' + request['path'] + '" "id:91041950,phase:1,pass,log,t:none,msg:apache-i12-input-binding"\n'
    request_deny = 'streaming' in case_id and 'request' in case_id or case_id.endswith('request-marker-at-payload-end') or case_id == 'NEED-request-above-former-connector-limit'
    expected.update(visible_status=403 if request_deny else 200, native_rule_id=91041950, native_phase=1, backend_requests=1)
    if expected['visible_status'] == 403:
        expected.update(native_rule_id=1100101, native_phase=2, backend_requests=0)
    if case_id.endswith('response-marker-at-payload-end') or case_id in ('NEED-response-streaming', 'NEED-response-above-former-connector-limit'):
        expected.update(native_rule_id=1100301, native_phase=4)
    if 'mime-scope' in case_id:
        expected.update(visible_status=None, native_rule_id=None, native_phase=None, backend_requests=None)
    if plan['backend'].get('file'):
        expected['backend_requests'] = 0

def _configure_historical_sink(plan, case_id):
    selected = plan['fault']
    if not case_id.startswith('E2E-APACHE-') or not selected:
        return
    if selected['boundary'] != 'physical_event_sink':
        return
    plan['fault']['activation'] = 'exact_main_request_id_once_without_delaying_first_sink_failure'
    plan['historical_planning_assumption'] = {
        'superseded_claim': 'Persistent invalid sink prevents120016; require rule-order/control variant or deferred physical fault activation',
        'disposition': 'Source contradicted: nonmandatory120001 logging latches sink failure without preventing subsequent native120016. Retain historical evidence; do not reorder rules or defer first fault.'}
    plan.setdefault('variant_conflicts', []).append('First physical sink failure may occur at120001 pass/log before native120016 deny; independently retain both first failure and actual120016 attribution, with unchanged native rule order')
    plan['driver_seams'].append('preserve120001_and120016_separate_first_sink_failure_from_native_deny')


def _configure_generated_id(plan, case_id):
    if case_id != 'transaction_id_generated_or_fallback':
        return
    plan['apache']['transaction_id_expression'] = None
    plan['transaction_id_variant'] = {
        'configured_literal_id': None,
        'configured_expression': None,
        'client_header_role': 'independent_backend_join_only',
        'source_basis': 'mod_security3.c apache_resolve_transaction_id leaves NULL without directives; apache_store_transaction_id creates host fallback; apache_create_tx calls msc_new_transaction',
        'native_generated_id_observed': None,
        'host_fallback_id_observed': None,
        'requires_distinct_native_and_host_allocation_identity_join': True}


def special_inputs(plan, case_id, contract, fixture):
    """Apply Apache fixture variants without changing the original oracle."""
    _configure_phase3(plan, case_id)
    _configure_phase4_marker(plan, case_id)
    _configure_late_mode(plan, case_id)
    _configure_body_limit(plan, case_id, contract, fixture)
    _configure_request_data(plan, case_id)
    _configure_response_data(plan, case_id)
    _configure_former_limit(plan, case_id)
    _configure_streaming(plan, case_id)
    _configure_nonzero_body(plan, case_id)
    _configure_nonzero_headers(plan, case_id)
    _configure_keepalive_response(plan, case_id)
    _configure_shutdown(plan, case_id)
    _configure_malformed_request(plan, case_id)
    _configure_native_fault(plan, case_id)
    _configure_timeout(plan, case_id)
    _configure_physical_sink(plan, case_id)
    _configure_abnormal_transport(plan, case_id)
    _configure_sequence(plan, case_id)
    _configure_event_boundary(plan, case_id)
    _configure_supplemental_rule(plan, case_id)
    _configure_historical_sink(plan, case_id)
    _configure_generated_id(plan, case_id)


def _build_case(original, ordinal, context):
    framework = context['framework']
    catalog = context['catalog']
    history = context['history']
    baseline = context['baseline']
    sources = context['sources']
    yaml_loader = context['yaml_loader']
    former_limit_proof = context['former_limit_proof']
    contract = copy.deepcopy(original['selected_requirement'])
    case_id = contract['case_id']
    plan = {'original_id': original['run_scoped_case_id'], 'case_id': case_id, 'original_contract': contract, 'original_oracle': copy.deepcopy(contract['expected_oracle']), 'execution_kind': 'configtest' if contract['execution_kind'] == 'actual_configtest' else 'host_http', 'original54member': original.get('original_54_oracle_member', False), 'oracle_source_refs': copy.deepcopy(sources), 'reconciliation_required': True, 'oracle_reviewed_by': None, 'full_lifecycle_qualified': False, 'candidate_oracle_basis': {'sdk_revision': 'libModSecurity3.0.14 source reference; actual loaded SDK must independently match', 'request_ingest': 'transaction.cc928-970 appends raw bytes;575-587 selects multipart/urlencoded;P2 at processRequestBody', 'response_ingest': 'transaction.cc1026-1039 strips charset;1129-1145/1180-1188 MIME;1195-1217 native limits', 'host_policy': 'Apache msc_filters.c physical EOS/append/late-action branches; actual commit still needs host and client measurements', 'rule_decision': 'exact canonical rules or preserved historical rules; configured rule alone is not actual match evidence', 'approval': None}}
    if plan['execution_kind'] == 'configtest':
        plan['config'] = config_case(case_id)
        plan['candidate_expectation'] = {'configtest_exit': plan['config']['expected_exit_code']}
        plan['required_observation_predicates'] = plan['config']['required_observation_predicates']
    else:
        plan.update(base_host(case_id, ordinal))
        entry = catalog.get(case_id, {})
        request = resolve_request(case_id, catalog)
        fixture, reference = fixture_for(fixture_entry(case_id, catalog), framework, yaml_loader)
        if reference:
            plan['oracle_source_refs'].append(reference)
            plan['original_fixture'] = copy.deepcopy(fixture)
        apply_canonical(plan, entry, fixture, request)
        if case_id in history:
            plan['historical_fixture'] = copy.deepcopy(history[case_id])
            historical_case(plan, history[case_id])
        special_inputs(plan, case_id, contract, fixture)
        if 'former_limit_proof' in plan and former_limit_proof is not None:
            plan['former_limit_proof']['source_history_receipt'] = source_reference(former_limit_proof, 'independent_original_limit_history')
            plan['oracle_source_refs'].append(copy.deepcopy(plan['former_limit_proof']['source_history_receipt']))
        plan['baseline_rules'] = source_reference(baseline, 'canonical_rules')
        plan['baseline_rules_required'] = case_id not in history and (not case_id.startswith('NEED-physical-event-sink-'))
        plan['required_observation_predicates'] = ['unique_actual_main_transaction_and_run_identity', 'loaded_current_build_module_and_sdk', 'wire_client_exit_signal_status_headers_body_sha256_framing', 'independent_backend_count_and_payload', 'native_actual_phases_returns_header_body_appends', 'native_audit_rule_and_first_cause', 'physical_jsonl_original_required_fields', 'actual_commit_and_eos_order', 'applicable_finish_free_and_descriptor_cleanup', 'healthy_controls_expected_by_own_config', 'waited_host_process_and_listener_cleanup']
        plan['required_original_event_fields'] = copy.deepcopy(contract['expected_oracle'].get('event_fields', []))
    return plan


def build_plan(ledger, framework, historical, sdk_source, yaml_loader, former_limit_proof=None):
    framework = Path(framework).resolve()
    catalog_path = framework / "tests/cases/no-crs-baseline/catalog.json"
    catalog_payload = json.loads(catalog_path.read_text())
    catalog = {r["case_id"]: r for r in catalog_payload["cases"]}
    original_rows = ledger["rows"]
    if len(original_rows) != 155 or len({r["run_scoped_case_id"] for r in original_rows}) != 155:
        raise ValueError("expected all155 unique original Apache IDs")
    if any(r["leg_id"] != "apache-native" or not r["required_leg"] for r in original_rows):
        raise ValueError("only required Apache original contracts are permitted")
    identity_bytes = ("\n".join(r["run_scoped_case_id"] for r in original_rows) + "\n").encode()
    contract_bytes = json.dumps([r["selected_requirement"] for r in original_rows],
                               sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    if hashlib.sha256(identity_bytes).hexdigest() != APACHE_IDS_SHA256:
        raise ValueError("immutable Apache original ID order changed")
    if hashlib.sha256(contract_bytes).hexdigest() != APACHE_CONTRACTS_SHA256:
        raise ValueError("immutable Apache original contracts changed")
    baseline = framework / catalog_payload["ruleset"]["path"]
    sources = [source_reference(catalog_path, "canonical_catalog"), source_reference(baseline, "canonical_rules"),
               source_reference(sdk_source, "native_sdk_source")]
    repository = connector_root()
    for relative in ("connectors/apache/src/msc_config.c", "connectors/apache/src/msc_filters.c",
                     "connectors/apache/src/mod_security3.c", "common/runtime/msconnector_runtime.c",
                     "common/include/msconnector/event.h"):
        sources.append(source_reference(repository / relative, "actual_product_source"))
    history = {r["case_id"]: r for r in historical}
    rows = []
    context = {"framework": framework, "catalog": catalog, "history": history, "baseline": baseline, "sources": sources, "yaml_loader": yaml_loader, "former_limit_proof": former_limit_proof}
    rows = [_build_case(original, ordinal, context) for ordinal, original in enumerate(original_rows)]
    return {"schema_version": 1, "scope": "apache-native", "analysis_inputs_only": True,
            "no_runtime_or_oracle_promotion": True, "original_id_count": 155,
            "config_cases": sum(r["execution_kind"] == "configtest" for r in rows),
            "host_cases": sum(r["execution_kind"] == "host_http" for r in rows), "rows": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("ledger", "framework-root", "historical-cases", "sdk-source", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--former-limit-proof", type=Path)
    args = parser.parse_args()
    import yaml
    result = build_plan(json.loads(args.ledger.read_text()), args.framework_root,
                        json.loads(args.historical_cases.read_text()), args.sdk_source, yaml.safe_load,
                        args.former_limit_proof)
    result["input_sources"] = [source_reference(args.ledger, "original_ledger"),
                               source_reference(args.historical_cases, "original_historical_cases")]
    with i12_paths.new_text(args.output) as output:
        json.dump(result, output, indent=2)
        output.write("\n")


if __name__ == "__main__":
    main()
