#!/usr/bin/env python3
"""Write bounded selected-case observations for patched lighttpd.

Every PASS remains bound to a raw Common event emitted by the real patched
host.  The helper never invents a rule, transaction ID, phase, body counter,
or first-byte result.  It also verifies the two HTTP/1.1 entity transfer
fixtures before publishing the P4 safe result used by the canonical runner.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Iterable

from adapters.lighttpd.harness.patched_event_validation import load_events, nonnegative, phase_is_four
from adapters.lighttpd.harness.namespace_fixture_directory import open_namespace_fixture_directory
from adapters.lighttpd.harness.safe_runtime_output import read_runtime_input_text, safe_input_path, verified_runtime_output_root, write_text_atomic


REPO_ROOT = connector_root()
CI_LIB = source_path('ci/lib', root=REPO_ROOT)


from modsecurity_connector_ci.lib.verified_run_id import VerifiedRunIdError, validate_verified_run_id  # noqa: E402


CASE_RULES = {
    "deny_header_marker_403": (1100001, 403),
    "deny_with_alternative_status": (1100002, 429),
    "deny_request_body_marker_403": (1100101, 403),
    "deny_response_header_marker_403": (1100201, 403),
    "phase3_deny_before_commit": (1100201, 403),
    "phase3_original_and_visible_status": (1100201, 403),
}
P4_SAFE_CASE_IDS = (
    "phase4_rule_observed",
    "phase4_end_of_stream_evaluation",
    "phase4_deny_after_commit_log_only",
    "phase4_deny_after_commit_log_only_safe",
    "phase4_event_contains_original_status",
    "phase4_event_contains_late_intervention_action",
)
P4_BARRIER_CASE_IDS = (
    "phase4_first_byte_before_response_end",
    "phase4_no_full_response_buffering",
)
P4_SEMANTIC_FIELDS = (
    "http_status",
    "original_http_status",
    "visible_http_status",
    "requested_action",
    "actual_action",
    "late_intervention",
    "late_intervention_mode",
    "headers_sent",
    "body_started",
    "response_committed",
    "connection_aborted",
    "transport_result",
    "body_bytes_seen",
    "body_bytes_inspected",
    "eos_seen",
    "end_of_stream_evaluation",
)
NON_OBJECT_ERROR = "{path}:{line_number} is not an object"
ENTITY_FIXTURE_RESULT_LABEL = "entity fixture result"


def has_transaction_id(event: dict[str, Any]) -> bool:
    return isinstance(event.get("transaction_id"), str) and bool(event["transaction_id"])


def host_confirmed_event(
    events: Iterable[dict[str, Any]], rule_id: int, visible_status: int
) -> dict[str, Any] | None:
    matches = [
        event
        for event in events
        if event.get("connector") == "lighttpd"
        and event.get("integration_mode") == "patched-native-lighttpd"
        and str(event.get("rule_id") or "") == str(rule_id)
        and event.get("visible_http_status") == visible_status
        and event.get("transport_result") == "http_status"
        and has_transaction_id(event)
    ]
    return matches[-1] if matches else None


def safe_phase4_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        event
        for event in events
        if event.get("connector") == "lighttpd"
        and event.get("integration_mode") == "patched-native-lighttpd"
        and str(event.get("rule_id") or "") == "1100301"
        and phase_is_four(event.get("phase"))
        and event.get("http_status") == 403
        and event.get("original_http_status") == 200
        and event.get("visible_http_status") == 200
        and event.get("requested_action") == "deny"
        and event.get("actual_action") == "log_only"
        and event.get("late_intervention") is True
        and event.get("late_intervention_mode") == "safe"
        and event.get("headers_sent") is True
        and event.get("body_started") is True
        and event.get("response_committed") is True
        and event.get("connection_aborted") is False
        and event.get("transport_result") == "log_only"
        and has_transaction_id(event)
    ]


def one_safe_phase4_event(events: Iterable[dict[str, Any]], label: str) -> dict[str, Any]:
    matches = safe_phase4_events(events)
    if len(matches) != 1:
        raise ValueError(f"{label} requires exactly one safe patched-lighttpd P4 host action")
    event = matches[0]
    seen = nonnegative(event.get("body_bytes_seen"), f"{label}.body_bytes_seen")
    inspected = nonnegative(
        event.get("body_bytes_inspected"), f"{label}.body_bytes_inspected"
    )
    if inspected > seen:
        raise ValueError(f"{label} body_bytes_inspected cannot exceed body_bytes_seen")
    return event


def event_fields(event: dict[str, Any]) -> dict[str, Any]:
    return {field: event.get(field) for field in P4_SEMANTIC_FIELDS}


def write_eos_projection(
    root: Path, path: Path, event: dict[str, Any], *, run_id: str
) -> dict[str, Any]:
    """Publish the one safe host action with its causal EOS facts.

    The raw Common event is emitted by ``finish_response_body``.  On the
    patched Lighttpd path that function is reached only from the entity hook
    with ``eos=1`` from a real HTTP/1.1 framing-end callback.  The projection
    retains that unique observed host action and adds bounded lifecycle facts
    only; it never creates another host action or a body/audit value.  It
    intentionally omits Common's integrity-chain fields rather than
    pretending that the derived record has a new Common event hash.
    """
    if "run_id" in event and event["run_id"] != run_id:
        raise ValueError(
            "raw Common event run_id conflicts with the selected Lighttpd run identity"
        )
    projection = dict(event)
    for field in ("sequence", "previous_event_hash", "event_hash"):
        projection.pop(field, None)
    projection["run_id"] = run_id
    projection["eos_seen"] = True
    projection["end_of_stream_evaluation"] = True
    write_text_atomic(
        root,
        path,
        json.dumps(projection, sort_keys=True) + "\n",
        "phase-4 EOS projection output",
    )
    return projection


def result_row(
    case_id: str,
    actual_status: int,
    event: dict[str, Any] | None,
    event_path: Path,
) -> dict[str, Any]:
    rule_id, expected_status = CASE_RULES[case_id]
    matched = event is not None and actual_status == expected_status
    row: dict[str, Any] = {
        "case_id": case_id,
        "status": "PASS" if matched else "FAIL",
        "actual_status": actual_status,
        "live_executed": True,
        "observed_rule_ids": [rule_id] if event is not None else [],
        "transaction_ids": [event["transaction_id"]] if event is not None else [],
        "decision_log_path": str(event_path),
        "observed_transport_result": "http_status",
        "reason": (
            "real patched-lighttpd host status and host-confirmed Common event agree"
            if matched
            else "real patched-lighttpd status lacks a matching host-confirmed Common event"
        ),
    }
    if case_id.startswith("phase3_") and event is not None:
        row.update(event_fields(event))
    return row


def phase4_result_row(
    case_id: str,
    event: dict[str, Any],
    event_path: Path,
    *,
    first_byte_evidence: Path,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "case_id": case_id,
        "status": "PASS",
        "actual_status": 200,
        "live_executed": True,
        "observed_rule_ids": [1100301],
        "transaction_ids": [event["transaction_id"]],
        "decision_log_path": str(event_path),
        "observed_transport_result": "log_only",
        "reason": "real patched-lighttpd HTTP/1.1 entity EOS safe host action and barrier evidence",
        **event_fields(event),
    }
    # Every selected P4 row reads the same causal barrier record.  The
    # collector then derives one identical canonical EOS event rather than a
    # bare-safe copy plus a second barrier-enriched copy for the same tx.
    row["first_byte_evidence_path"] = str(first_byte_evidence)
    return row


def requested_cases(value: str) -> set[str]:
    return {item for item in value.split() if item}


def load_fixture_result(
    root: Path,
    path: Path | None = None,
    *,
    fixture_directory_name: str | None = None,
    fixture_directory_identity: str | None = None,
    fixture_runtime_root: Path | None = None,
) -> tuple[int, int]:
    """Load one actual fixture result through one selected safe transport."""

    if path is not None:
        raw = read_runtime_input_text(root, path, ENTITY_FIXTURE_RESULT_LABEL)
    else:
        if (
            fixture_directory_name is None
            or fixture_directory_identity is None
            or fixture_runtime_root is None
        ):
            raise ValueError("descriptor fixture result needs directory name and identity")
        with open_namespace_fixture_directory(
            fixture_runtime_root,
            name=fixture_directory_name,
            identity=fixture_directory_identity,
        ) as directory:
            raw = directory.read_text(
                "result.json", ENTITY_FIXTURE_RESULT_LABEL, maximum_bytes=64 * 1024
            )
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("entity fixture result must be an object")
    if value.get("evidence_type") != "lighttpd_http1_entity_fixture_result":
        raise ValueError("entity fixture result has an unexpected type")
    if value.get("body_payload_persisted") is not False:
        raise ValueError("entity fixture result must be payload-free")
    if value.get("content_length_requests") != 1 or value.get("chunked_requests") != 1:
        raise ValueError("both HTTP/1.1 entity fixtures must execute exactly once")
    return (
        nonnegative(value.get("content_length_entity_bytes"), "content_length_entity_bytes"),
        nonnegative(value.get("chunked_entity_bytes"), "chunked_entity_bytes"),
    )


def validate_entity_boundary(
    path: Path, *, expected_bytes: int, label: str
) -> dict[str, Any]:
    event = one_safe_phase4_event(
        load_events(path, non_object_error=NON_OBJECT_ERROR), label
    )
    seen = nonnegative(event.get("body_bytes_seen"), f"{label}.body_bytes_seen")
    inspected = nonnegative(
        event.get("body_bytes_inspected"), f"{label}.body_bytes_inspected"
    )
    if seen != expected_bytes or inspected != expected_bytes:
        raise ValueError(
            f"{label} entity bytes do not match the real HTTP/1.1 fixture "
            f"(seen={seen}, inspected={inspected}, expected={expected_bytes})"
        )
    return event


def write_summary(
    root: Path,
    path: Path,
    safe_event: dict[str, Any],
    content_length_bytes: int,
    chunked_bytes: int,
) -> None:
    payload = {
        "schema_version": 1,
        "phase4_rule_id": 1100301,
        "phase4_safe_status": 200,
        "p4_safe_log_only_status": 200,
        "phase4_requested_action": safe_event["requested_action"],
        "phase4_actual_action": safe_event["actual_action"],
        "phase4_late_intervention": safe_event["late_intervention"],
        "phase4_late_intervention_mode": safe_event["late_intervention_mode"],
        "phase4_headers_sent": safe_event["headers_sent"],
        "phase4_body_started": safe_event["body_started"],
        "phase4_response_committed": safe_event["response_committed"],
        "phase4_connection_aborted": safe_event["connection_aborted"],
        "phase4_transport_result": safe_event["transport_result"],
        "phase4_entity_eos_finalized_once": True,
        "phase4_host_action_events": 1,
        "phase4_end_of_stream_evaluation_status": 200,
        "phase4_first_byte_before_response_end_status": 200,
        "phase4_no_full_response_buffering_status": 200,
        "http1_content_length_entity_bytes": content_length_bytes,
        "http1_chunked_entity_bytes": chunked_bytes,
        "body_payload_persisted": False,
    }
    write_text_atomic(
        root,
        path,
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        "phase-4 summary output",
    )


def _resolve_fixture_result_mode(
    args: argparse.Namespace, output_root: Path
) -> tuple[Path | None, str | None, str | None, Path | None]:
    fixture_path_mode = args.entity_fixture_result is not None
    descriptor_values = (
        args.entity_fixture_directory_name,
        args.entity_fixture_directory_identity,
        args.entity_fixture_runtime_output_root,
    )
    fixture_descriptor_mode = all(value is not None for value in descriptor_values)
    if fixture_path_mode == fixture_descriptor_mode:
        raise ValueError("select exactly one pathname or descriptor entity-fixture-result mode")
    fixture_result_path = (
        safe_input_path(output_root, args.entity_fixture_result, ENTITY_FIXTURE_RESULT_LABEL)
        if fixture_path_mode
        else None
    )
    return (
        fixture_result_path,
        args.entity_fixture_directory_name,
        args.entity_fixture_directory_identity,
        args.entity_fixture_runtime_output_root,
    )


def _prepare_inputs(
    args: argparse.Namespace, output_root: Path, run_id: str
) -> tuple[list[dict[str, Any]], set[str], int, int, dict[str, Any], Path, Path]:
    events_path = safe_input_path(output_root, args.events, "events input")
    phase4_safe_events_path = safe_input_path(
        output_root, args.phase4_safe_events, "phase-4 safe events input"
    )
    first_byte_evidence_path = safe_input_path(
        output_root, args.phase4_first_byte_evidence, "phase-4 first-byte evidence input"
    )
    content_length_events_path = safe_input_path(
        output_root, args.content_length_events, "Content-Length events input"
    )
    chunked_events_path = safe_input_path(
        output_root, args.chunked_events, "chunked events input"
    )
    fixture_path, directory_name, directory_identity, fixture_root = _resolve_fixture_result_mode(
        args, output_root
    )
    events = load_events(events_path, non_object_error=NON_OBJECT_ERROR)
    content_length_bytes, chunked_bytes = load_fixture_result(
        output_root,
        fixture_path,
        fixture_directory_name=directory_name,
        fixture_directory_identity=directory_identity,
        fixture_runtime_root=fixture_root,
    )
    validate_entity_boundary(
        content_length_events_path,
        expected_bytes=content_length_bytes,
        label="Content-Length entity boundary",
    )
    validate_entity_boundary(
        chunked_events_path,
        expected_bytes=chunked_bytes,
        label="chunked entity boundary",
    )
    raw_safe_event = one_safe_phase4_event(
        load_events(phase4_safe_events_path, non_object_error=NON_OBJECT_ERROR),
        "synchronized first-byte barrier",
    )
    safe_event = one_safe_phase4_event(
        [
            write_eos_projection(
                output_root,
                args.phase4_projected_events_output,
                raw_safe_event,
                run_id=run_id,
            )
        ],
        "synchronized first-byte barrier EOS projection",
    )
    if args.phase4_safe_status != 200:
        raise ValueError("safe Phase-4 HTTP/1.1 client status must remain 200")
    return (
        events,
        requested_cases(args.selected_case_ids),
        content_length_bytes,
        chunked_bytes,
        safe_event,
        events_path,
        first_byte_evidence_path,
    )


def _selected_rows(
    args: argparse.Namespace,
    events: list[dict[str, Any]],
    selected: set[str],
    safe_event: dict[str, Any],
    events_path: Path,
    first_byte_evidence_path: Path,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if "allow_without_marker" in selected:
        rows.append(
            {
                "case_id": "allow_without_marker",
                "status": "PASS" if args.allow_status == 200 else "FAIL",
                "actual_status": args.allow_status,
                "live_executed": True,
                "observed_transport_result": "http_status",
                "reason": "real patched-lighttpd allow request",
            }
        )
    statuses = {
        "deny_header_marker_403": args.deny_status,
        "deny_with_alternative_status": args.alternative_status,
        "deny_request_body_marker_403": args.request_body_status,
        "deny_response_header_marker_403": args.response_header_status,
        "phase3_deny_before_commit": args.response_header_status,
        "phase3_original_and_visible_status": args.response_header_status,
    }
    for case_id, actual_status in statuses.items():
        if case_id in selected:
            rule_id, expected_status = CASE_RULES[case_id]
            rows.append(
                result_row(
                    case_id,
                    actual_status,
                    host_confirmed_event(events, rule_id, expected_status),
                    events_path,
                )
            )
    for case_id in P4_SAFE_CASE_IDS + P4_BARRIER_CASE_IDS:
        if case_id in selected:
            rows.append(
                phase4_result_row(
                    case_id,
                    safe_event,
                    args.phase4_projected_events_output,
                    first_byte_evidence=first_byte_evidence_path,
                )
            )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--selected-case-ids", default="")
    parser.add_argument("--allow-status", required=True, type=int)
    parser.add_argument("--deny-status", required=True, type=int)
    parser.add_argument("--alternative-status", required=True, type=int)
    parser.add_argument("--request-body-status", required=True, type=int)
    parser.add_argument("--response-header-status", required=True, type=int)
    parser.add_argument("--phase4-safe-events", required=True, type=Path)
    parser.add_argument("--phase4-projected-events-output", required=True, type=Path)
    parser.add_argument("--phase4-safe-status", required=True, type=int)
    parser.add_argument("--phase4-first-byte-evidence", required=True, type=Path)
    parser.add_argument("--content-length-events", required=True, type=Path)
    parser.add_argument("--chunked-events", required=True, type=Path)
    parser.add_argument("--entity-fixture-result", type=Path)
    parser.add_argument("--entity-fixture-directory-name")
    parser.add_argument("--entity-fixture-directory-identity")
    parser.add_argument("--entity-fixture-runtime-output-root", type=Path)
    parser.add_argument("--phase4-summary-output", required=True, type=Path)
    parser.add_argument("--runtime-output-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        run_id = validate_verified_run_id(args.run_id)
    except VerifiedRunIdError as error:
        parser.error(str(error))
    output_root = verified_runtime_output_root(args.runtime_output_root)

    events, selected, content_length_bytes, chunked_bytes, safe_event, events_path, first_byte_evidence_path = _prepare_inputs(
        args, output_root, run_id
    )
    rows = _selected_rows(
        args, events, selected, safe_event, events_path, first_byte_evidence_path
    )

    write_text_atomic(
        output_root,
        args.output,
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        "lifecycle result output",
    )
    write_summary(
        output_root,
        args.phase4_summary_output,
        safe_event,
        content_length_bytes,
        chunked_bytes,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
