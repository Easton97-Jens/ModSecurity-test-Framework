"""Closed bounded triggers for native NGINX Phase-4 Required operations.

These specifications describe input only. They never constitute host, Engine,
event, chunk-boundary, inspection-length, or successful-operation observations.
Every consumer must retain and validate those independent native artifacts.
"""
from copy import deepcopy

MARKER = "no-crs-response-body-marker"
RECORD_IDS = frozenset({
    "phase4_marker_split_across_chunks", "phase4_end_of_stream_evaluation",
    "phase4_deny_after_commit_log_only_minimal", "phase4_body_at_limit",
    "phase4_body_over_limit", "phase4_body_process_partial", "phase4_body_reject",
    "full_lifecycle_event_metadata_bounded",
})
SPLIT_ID = "phase4_marker_split_across_chunks"
LEGACY_SAFE_ID = "phase4_deny_after_commit_log_only_minimal"
OVER_LIMIT_ID = "phase4_body_over_limit"
SOURCES = {
    "phase4_end_of_stream_evaluation": SPLIT_ID,
    "full_lifecycle_event_metadata_bounded": OVER_LIMIT_ID,
}
LIMIT_VARIANTS = {
    "phase4_body_at_limit": (64, "ProcessPartial", "at_limit"),
    OVER_LIMIT_ID: (65, "ProcessPartial", "over_limit"),
    "phase4_body_process_partial": (65, "ProcessPartial", "process_partial"),
    "phase4_body_reject": (65, "Reject", "reject"),
}


def operation(record_id: str) -> dict:
    """Return a fresh closed specification; reject unknown or removed modes."""
    if not isinstance(record_id, str) or record_id not in RECORD_IDS:
        raise ValueError("unknown closed Phase-4 record identity")
    source = SOURCES.get(record_id, record_id)
    rules = (
        "SecRuleEngine On\nSecResponseBodyAccess On\n"
        "SecResponseBodyMimeType text/plain\n"
        f'SecRule RESPONSE_BODY "@contains {MARKER}" '
        '"id:1100301,phase:4,deny,status:403,log,msg:\'no-crs phase-4 intervention probe\'"\n'
    )
    result = {
        "record_id": record_id, "source_record_id": source,
        "operation": "native_phase4_request", "nginx_phase4_mode": "safe",
        "request_path": "/no-crs/full-lifecycle/" + source.replace("_", "-"),
        "response_content_type": "text/plain", "configured_rule_id": 1100301,
        "rules": rules,
    }
    if source in {SPLIT_ID, LEGACY_SAFE_ID}:
        result["response_chunks"] = ["no-crs-response-", "body-marker"]
        result["pause_between_chunks"] = True
    else:
        size, action, outcome = LIMIT_VARIANTS[source]
        result["response_chunks"] = [MARKER + "x" * (size - len(MARKER))]
        result["pause_between_chunks"] = False
        result["engine_limit_bytes"] = 64
        result["engine_limit_action"] = action
        result["expected_limit_outcome"] = outcome
        result["rules"] += f"SecResponseBodyLimit 64\nSecResponseBodyLimitAction {action}\n"
    return deepcopy(result)
