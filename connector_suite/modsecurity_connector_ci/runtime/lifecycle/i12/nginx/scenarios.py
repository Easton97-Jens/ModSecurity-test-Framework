"""NGINX-only effective fixtures; original catalog expectations stay separate."""
from __future__ import annotations


MARKER_PREFIX = b"marker="


def cases():
    rows = []

    def add(identity, **changes):
        row = {"case_id": identity, "request": b"marker=NGXI12_REQ&shape=single",
               "response": b"NGXI12_RSP physical native response\n",
               "request_type": "application/x-www-form-urlencoded",
               "response_type": "text/plain; charset=utf-8", "mode": "safe",
               "request_limit": 1048576, "response_limit": 1048576,
               "request_action": "Reject", "response_action": "Reject", "writes": 1,
               "response_parts": 1, "chunked": False, "request_file": False,
               "response_file": False, "extra_headers": [], "extra_rules": "",
               "nginx_directives": "", "fault": None, "expected_status": 200,
               "expected_client_exit": 0, "expected_rule": None, "scope": "allow"}
        row.update(changes)
        rows.append(row)

    for name in ("NEED-request-single-chunk", "NEED-request-content-type-present", "NEED-request-charset-missing",
                 "NEED-request-mime-scope-in", "NEED-request-eos-once", "NEED-response-single-chunk",
                 "NEED-root-master-nobody-worker", "NEED-native-memory-body", "NEED-client-exit-signal",
                 "NEED-neighbor-connection-stream", "single_request_cleanup", "allow", "phase1_allow",
                 "allow_without_marker", "transport_http11_content_length"):
        add(name)
    add("NEED-request-empty", request=b"")
    add("NEED-response-empty", response=b"")
    add("NEED-request-content-type-missing", request_type=None)
    add("NEED-request-charset-present", request_type="application/x-www-form-urlencoded; charset=utf-8")
    add("NEED-request-mime-scope-out", request_type="image/png")
    add("NEED-request-csv", request=b"column,value\nNGXI12_REQ,1\n", request_type="text/csv")
    add("NEED-response-csv", response=b"column,value\nNGXI12_RSP,1\n", response_type="text/csv",
        extra_rules="SecResponseBodyMimeType text/csv\n")
    add("NEED-response-charset-missing", response_type="text/plain")
    for name in ("NEED-request-file", "NEED-native-file-body"):
        add(name, request=MARKER_PREFIX + b"x" * 65536 + b"NGXI12_REQ", request_file=True)
    add("NEED-request-multiple-chunks", request=MARKER_PREFIX + b"x" * 65536 + b"NGXI12_REQ", request_file=True, writes=4)
    add("NEED-request-streaming", request=MARKER_PREFIX + b"x" * 65536 + b"NGXI12_REQ", request_file=True, writes=8)
    add("NEED-response-file", response_file=True, get_entity=True, request=b"x")
    add("NEED-response-streaming", response=b"NGXI12_" + b"RSP streamed response\n", response_parts=4, chunked=True)
    add("transport_http11_chunked", response_parts=3, chunked=True)
    add("NEED-request-marker-at-payload-end", request=MARKER_PREFIX + b"x" * 32768 + b"NGXI12_REQ")
    add("NEED-response-marker-at-payload-end", response=b"x" * 32768 + b"NGXI12_RSP")
    add("NEED-request-above-former-connector-limit", request=MARKER_PREFIX + b"x" * 1048576 + b"NGXI12_REQ",
        request_limit=2097152, response_limit=2097152, request_file=True)
    add("NEED-response-above-former-connector-limit", response=b"x" * 1048576 + b"NGXI12_RSP",
        request_limit=2097152, response_limit=2097152)
    add("NEED-request-reject", request=MARKER_PREFIX + b"x" * 1024, request_limit=64, expected_status=403, scope="request_reject")
    add("NEED-request-process-partial", request=b"marker=NGXI12_REQ&" + b"x" * 1024, request_limit=64,
        request_action="ProcessPartial", scope="request_partial")
    add("phase4_body_reject", response=b"NGXI12_RSP" + b"x" * 128, response_limit=64,
        expected_client_exit=2, scope="response_reject")
    add("phase4_body_process_partial", response=b"no-crs-response-body-marker" + b"x" * 128,
        response_limit=64, response_action="ProcessPartial", scope="response_partial", expected_rule="1100301")
    for name in ("deny", "deny_header_marker_403", "phase1_deny_403", "event_contains_connector",
                 "event_contains_transaction_id", "event_contains_rule_id", "event_contains_phase", "event_contains_status"):
        add(name, extra_headers=[("X-Modsec-Smoke", "block")], expected_status=403, scope="p1_deny", expected_rule="1100001")
    for name in ("deny_with_alternative_status", "phase1_alternative_status"):
        add(name, extra_headers=[("X-Modsec-Smoke", "alternative-status")], expected_status=429, scope="p1_deny", expected_rule="1100002")
    for name in ("log_only",):
        add(name, extra_headers=[("X-Modsec-Smoke", "log-only")], expected_rule="1100402")
    for name in ("redirect_if_supported", "phase1_redirect"):
        add(name, extra_headers=[("X-Modsec-Smoke", "redirect")], expected_status=302, scope="p1_deny", expected_rule="1100401")
    for name in ("deny_request_body_marker_403", "phase2_request_body_rule", "phase2_no_payload_event", "event_has_no_request_body_payload"):
        add(name, request=b"marker=no-crs-request-body-marker", expected_status=403, scope="p2_deny", expected_rule="1100101")
    for name in ("deny_response_header_marker_403", "phase3_response_header_rule", "phase3_deny_before_commit", "phase3_original_and_visible_status"):
        add(name, response_header="block", expected_status=403, scope="p3_deny", expected_rule="1100201")
    add("phase3_redirect_before_commit", response_header="redirect", expected_status=302, scope="p3_deny", expected_rule="1100202")
    for name in ("phase4_rule_observed", "phase4_deny_after_commit_log_only", "phase4_event_contains_original_status",
                 "phase4_event_contains_late_intervention_action", "phase4_deny_after_commit_log_only_safe", "phase4_status_metadata",
                 "phase4_action_metadata", "phase4_no_payload_event", "event_has_no_response_body_payload",
                 "phase4_in_scope_content_type", "phase4_content_type_with_charset", "phase4_end_of_stream_evaluation"):
        add(name, response=b"no-crs-response-body-marker", expected_rule="1100301", scope="p4_safe")
    for name in ("phase4_deny_after_commit_abort", "phase4_deny_after_commit_abort_strict", "phase4_strict_http1_client_abort",
                 "phase4_strict_host_survives", "phase4_strict_followup_request_succeeds", "NEED-incomplete-framing",
                 "NEED-abort-reset-observation"):
        add(name, response=b"no-crs-response-body-marker", mode="strict", expected_client_exit=2,
            expected_rule="1100301", scope="p4_strict", chunked=True, response_parts=4)
    add("phase4_marker_split_across_chunks", response=b"no-crs-response-body-marker", response_parts=4,
        expected_rule="1100301", scope="p4_safe")
    add("phase4_missing_content_type", response_type=None, scope="mime_out")
    add("phase4_out_of_scope_content_type", response_type="image/png", scope="mime_out")
    for name in ("body_size_nonzero_with_null_data", "header_count_nonzero_with_null_headers"):
        add(name, fault=name, expected_status=500, scope="mapper_p1")
    for name in ("invalid_content_length", "conflicting_content_length", "duplicate_transfer_encoding", "content_length_overflow"):
        add(name, malformed=name, expected_status=400, scope="host_parser")
    add("NEED-timeout", budget_phase=1, expected_status=504, scope="budget_precommit")
    add("engine_timeout_before_commit", budget_phase=1, expected_status=504, scope="budget_precommit")
    add("engine_timeout_after_commit", budget_phase=4, expected_client_exit=2, scope="budget_postcommit", chunked=True, response_parts=4)
    add("NEED-invalid-native-return", invalid_return=True, expected_status=500, scope="invalid_p2_return")
    add("control-empty-get", response_file=True, request=b"", scope="empty_get_regression")
    assert len({row["case_id"] for row in rows}) == len(rows)
    return rows


def serializable(row):
    return {key: value.decode("ascii") if isinstance(value, bytes) else value for key, value in row.items()}
