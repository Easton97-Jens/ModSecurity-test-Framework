#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path

# CI helpers are shared from ci/lib even when this file is executed directly.
import sys

from typing import Any

from modsecurity_connector_ci.lib.case_metadata_utils import parse_case_document
from modsecurity_connector_ci.lib.focused_analysis_utils import read_json, read_text, utc_now, write_json
from modsecurity_connector_ci.lib.focused_analysis_utils import upsert_marked_section
from modsecurity_connector_ci.lib.generated_report_utils import GENERATED_ROOT, build_metadata, generated_json_text, generated_markdown_text, report_path, report_path_from_root, report_relpath
from modsecurity_connector_ci.lib.report_path_safety import add_report_roots, add_safe_roots, resolve_output_dir, safe_existing_file, write_text_file

try:
    import yaml
except Exception:  # pragma: no cover - report generation still works from evidence metadata.
    yaml = None


REPORT_DIR = GENERATED_ROOT
PHASE4_CATEGORIES = (
    "phase4_no_hard_abort_required",
    "phase4_hard_abort_evidence",
    "phase4_connection_aborted",
    "phase4_log_only_no_abort",
    "phase4_truncated_not_accepted",
    "phase4_missing_abort_evidence",
    "phase4_connector_gap",
    "phase4_native_semantics",
)
ABSOLUTE_RUNTIME_PATH_RE = re.compile(r"(?<![\w.-])/(?:tmp|root|src)[^\s\"']*")


def normalize_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value in (None, ""):
        return []
    return [str(value)]


def first_value(*values: Any) -> str:
    for value in values:
        text = str(value or "")
        if text and text not in {"-", "none", "None", "null"}:
            return text
    return "-"


def sanitize_report_text(value: Any) -> str:
    return ABSOLUTE_RUNTIME_PATH_RE.sub("<evidence-path>", str(value or ""))


def is_phase4_candidate(entry: dict[str, Any]) -> bool:
    work = set(normalize_list(entry.get("work_direction")))
    capabilities = set(normalize_list(entry.get("capabilities")))
    classification = str(entry.get("classification") or "")
    return (
        str(entry.get("phase") or "") == "4"
        or "response_body_non_promoted" in work
        or classification == "response-body-non-promoted"
        or "phase4" in capabilities
    )


def first_rule_metadata(text: str) -> dict[str, str]:
    rule_match = re.search(r"SecRule\s+([^\s\"]+)\s+\"[^\"]+\"\s+(?:\\\s*)?\"([^\"]+)\"", text, re.MULTILINE)
    action_text = rule_match.group(2) if rule_match else ""
    id_match = re.search(r"\bid:(\d+)", action_text)
    phase_match = re.search(r"\bphase:(\d+)", action_text)
    return {
        "rule_id": id_match.group(1) if id_match else "-",
        "phase": phase_match.group(1) if phase_match else "-",
        "variable": rule_match.group(1) if rule_match else "-",
        "action_text": action_text,
        "rule_excerpt": re.sub(r"\s+", " ", rule_match.group(0)).strip() if rule_match else "-",
    }


def initial_phase4_metadata(entry: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_id": entry.get("case_id", "-"),
        "method": "-",
        "path": "-",
        "query": "-",
        "rule_id": str(evidence.get("rule_id") or "-"),
        "phase": str(evidence.get("phase") or entry.get("phase") or "-"),
        "variable": "-",
        "target": "-",
        "expected_action": str(evidence.get("expected_intervention") or "-"),
        "expected_response_body": "",
        "phase4_mode": "-",
        "content_type_scope": "-",
        "rule_excerpt": "-",
    }


def phase4_metadata_variable(source_metadata: dict[str, Any]) -> str:
    variables = source_metadata.get("variables")
    if isinstance(variables, list):
        return ", ".join(str(item) for item in variables)
    return str(variables or "-")


def phase4_metadata_expected_action(
    entry: dict[str, Any], expect: dict[str, Any], existing_action: Any
) -> str:
    expected_action = str(expect.get("intervention") or existing_action or "-")
    if expected_action not in ("", "-"):
        return expected_action
    return "deny" if entry.get("expected_status") in (401, 403, 302) else "pass"


def phase4_metadata_phase(
    entry: dict[str, Any], evidence: dict[str, Any], rule: dict[str, str], source_metadata: dict[str, Any]
) -> str:
    explicit_phase = evidence.get("phase")
    if explicit_phase:
        return str(explicit_phase)
    if rule["phase"] != "-":
        return rule["phase"]
    return str(source_metadata.get("phase") or entry.get("phase") or "-")


def phase4_metadata_updates(
    entry: dict[str, Any],
    evidence: dict[str, Any],
    metadata: dict[str, Any],
    parsed: dict[str, Any],
    request: dict[str, Any],
    expect: dict[str, Any],
    source_metadata: dict[str, Any],
    request_path: str,
    query: str,
    raw: str,
    rule: dict[str, str],
) -> dict[str, Any]:
    metadata_variable = phase4_metadata_variable(source_metadata)
    rule_variable = rule["variable"] if rule["variable"] != "-" else metadata_variable
    expected_response = (expect.get("response") or {}).get("body") or expect.get("response_body") or ""
    return {
        "method": str(request.get("method") or "-"),
        "path": request_path,
        "query": query,
        "rule_id": first_value(
            evidence.get("rule_id"), rule["rule_id"], expect.get("rule_id"), source_metadata.get("mrts_rule_id")
        ),
        "phase": phase4_metadata_phase(entry, evidence, rule, source_metadata),
        "variable": rule_variable,
        "target": rule_variable,
        "expected_action": phase4_metadata_expected_action(entry, expect, metadata["expected_action"]),
        "expected_response_body": str(expected_response),
        "phase4_mode": phase4_mode(parsed, raw),
        "content_type_scope": content_type_scope(parsed),
        "rule_excerpt": rule["rule_excerpt"],
    }


def case_metadata(entry: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    path = safe_existing_file(evidence.get("path"))
    metadata = initial_phase4_metadata(entry, evidence)
    raw = read_text(path) if path is not None and path.is_file() else ""
    parsed, request, expect, source_metadata, request_path, query = parse_case_document(raw, yaml)
    rules = str(parsed.get("rules") or raw)
    rule = first_rule_metadata(rules)
    metadata.update(
        phase4_metadata_updates(
            entry,
            evidence,
            metadata,
            parsed,
            request,
            expect,
            source_metadata,
            request_path,
            query,
            raw,
            rule,
        )
    )
    return metadata


def phase4_mode(parsed: dict[str, Any], raw: str) -> str:
    candidates = []
    for value in (parsed.get("config"), parsed.get("nginx"), parsed.get("apache")):
        if isinstance(value, str):
            candidates.append(value)
        elif isinstance(value, dict):
            candidates.extend(str(item) for item in value.values())
    candidates.append(raw)
    for text in candidates:
        match = re.search(r"modsecurity_phase4_mode\s+([A-Za-z0-9_-]+)", text)
        if match:
            return match.group(1)
    return "-"


def content_type_scope(parsed: dict[str, Any]) -> str:
    expect = parsed.get("expect") if isinstance(parsed.get("expect"), dict) else {}
    headers = (parsed.get("response") or {}).get("headers") if isinstance(parsed.get("response"), dict) else {}
    if isinstance(headers, dict) and headers.get("content-type"):
        return str(headers["content-type"])
    if expect.get("content_type"):
        return str(expect["content_type"])
    return "-"


def json_lines(path_value: Any) -> list[dict[str, Any]]:
    path = safe_existing_file(path_value)
    if path is None or not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in read_text(path).splitlines():
        try:
            loaded = json.loads(line)
        except Exception:
            continue
        if isinstance(loaded, dict):
            rows.append(loaded)
    return rows


def phase4_log_events(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    events = [row for row in json_lines(evidence.get("connector_phase4_log_path")) if row.get("event") == "phase4_intervention"]
    metadata = evidence.get("phase4_log_metadata")
    if isinstance(metadata, dict) and metadata and not events:
        events.append(metadata)
    return events


def decision_events(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in json_lines(evidence.get("decision_log_path") or evidence.get("decision_log")) if str(row.get("phase")) == "4"]


def sensitive_log_leak(meta: dict[str, Any], phase4_events: list[dict[str, Any]], decisions: list[dict[str, Any]]) -> bool:
    sensitive = meta.get("expected_response_body", "").strip()
    if not sensitive:
        return False
    haystack = "\n".join(json.dumps(row, sort_keys=True) for row in phase4_events + decisions)
    return sensitive in haystack


def actual_action(phase4_events: list[dict[str, Any]], decisions: list[dict[str, Any]], evidence: dict[str, Any]) -> str:
    for row in phase4_events:
        if row.get("actual_action"):
            return str(row["actual_action"])
    for row in decisions:
        if row.get("decision"):
            return str(row["decision"])
    intervention = evidence.get("intervention")
    if isinstance(intervention, dict) and intervention.get("disruptive"):
        return "deny_status"
    if evidence.get("intervention") is True:
        return "deny_status"
    return "-"


def log_evidence(phase4_events: list[dict[str, Any]], decisions: list[dict[str, Any]], evidence: dict[str, Any]) -> bool:
    if phase4_events or decisions:
        return True
    audit_path = safe_existing_file(evidence.get("audit_log_path"))
    return audit_path is not None and audit_path.is_file() and "phase 4" in read_text(audit_path).lower()


def response_delivered(entry: dict[str, Any], evidence: dict[str, Any], hard_abort: bool, action: str) -> str:
    transport = str(evidence.get("observed_transport_result") or "")
    if hard_abort or transport == "connection_aborted":
        return "aborted"
    if evidence.get("response_body_truncated") is True:
        return "partial"
    if action == "deny_status" and entry.get("actual_status") in (401, 403, 302):
        return "denied_before_commit" if evidence.get("response_committed") is False else "denied_after_commit_unknown"
    if entry.get("actual_status") == 200 or transport == "http_status":
        return "full"
    return "unknown"


def phase4_classification(
    *,
    hard_abort: bool,
    logs: bool,
    entry_classification: str,
    log_only: bool,
    response_body_truncated: bool,
    expected_action: str,
    known_gap: bool,
    runtime_status: str,
) -> tuple[str, list[str]]:
    if hard_abort and logs:
        return "phase4_hard_abort_evidence", ["phase4_connection_aborted"]
    if "native" in entry_classification:
        return "phase4_native_semantics", []
    if log_only:
        return "phase4_log_only_no_abort", []
    if response_body_truncated:
        return "phase4_truncated_not_accepted", []
    if expected_action == "deny" and known_gap:
        return "phase4_connector_gap", []
    if expected_action == "deny" or (not logs and runtime_status == "FAIL"):
        return "phase4_missing_abort_evidence", []
    return "phase4_no_hard_abort_required", []


def classify_case(
    entry: dict[str, Any],
    meta: dict[str, Any],
    evidence: dict[str, Any],
    phase4_events: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
) -> tuple[str, list[str], bool, bool, str, str]:
    connector = str(entry.get("connector") or "")
    reason = str(entry.get("reason") or evidence.get("reason") or "")
    mode = str(meta.get("phase4_mode") or evidence.get("mode") or "")
    action = actual_action(phase4_events, decisions, evidence)
    transport = str(evidence.get("observed_transport_result") or "")
    strict_abort = evidence.get("strict_abort") is True or any(row.get("strict_abort") is True for row in phase4_events)
    hard_abort = (
        strict_abort
        or transport == "connection_aborted"
        or any(row.get("actual_action") == "connection_abort" for row in phase4_events)
    )
    logs = log_evidence(phase4_events, decisions, evidence)
    expected_action = str(meta.get("expected_action") or "")
    log_only = action == "log_only" or mode == "safe" or reason == "mode_safe"
    known_gap = (
        "connector-gap" in str(entry.get("classification") or "")
        or any("connector-gap" in item for item in normalize_list(evidence.get("known_limitations")))
        or "connector_gap" in str(entry.get("case_id") or "")
        or connector == "haproxy"
    )

    category, evidence_categories = phase4_classification(
        hard_abort=hard_abort,
        logs=logs,
        entry_classification=str(entry.get("classification") or ""),
        log_only=log_only,
        response_body_truncated=evidence.get("response_body_truncated") is True,
        expected_action=expected_action,
        known_gap=known_gap,
        runtime_status=str(entry.get("runtime_status") or ""),
    )

    return category, evidence_categories, hard_abort, logs, action, response_delivered(entry, evidence, hard_abort, action)


def case_row(entry: dict[str, Any]) -> dict[str, Any]:
    evidence = read_json(entry.get("evidence"))
    meta = case_metadata(entry, evidence)
    phase4_events = phase4_log_events(evidence)
    decisions = decision_events(evidence)
    classification, evidence_categories, abort_evidence, logs, action, delivered = classify_case(entry, meta, evidence, phase4_events, decisions)
    return {
        "connector": entry.get("connector", "-"),
        "case_id": entry.get("case_id", "-"),
        "rule_id": meta.get("rule_id", "-"),
        "phase": meta.get("phase", "-"),
        "variable": meta.get("variable", "-"),
        "target": meta.get("target", "-"),
        "method": meta.get("method", "-"),
        "path": meta.get("path", "-"),
        "query": meta.get("query", "-"),
        "variant": f"{entry.get('test_variant', '-')}/{entry.get('mrts_variant', '-')}",
        "expected_action": meta.get("expected_action", "-"),
        "expected_status": entry.get("expected_status", "-"),
        "actual_status": entry.get("actual_status", "-"),
        "runtime_status": entry.get("runtime_status", "-"),
        "current_classification": entry.get("classification", "-"),
        "new_hard_abort_classification": classification,
        "evidence_categories": evidence_categories,
        "response_delivered": delivered,
        "abort_evidence": abort_evidence,
        "log_evidence": logs,
        "phase4_actual_action": action,
        "observed_transport_result": evidence.get("observed_transport_result", "-"),
        "phase4_mode": meta.get("phase4_mode", "-"),
        "content_type_scope": meta.get("content_type_scope", "-"),
        "response_body_seen": evidence.get("response_body_seen", "-"),
        "response_body_truncated": evidence.get("response_body_truncated", "-"),
        "response_committed": evidence.get("response_committed", "-"),
        "sensitive_log_leak": sensitive_log_leak(meta, phase4_events, decisions),
        "source_kind": entry.get("source_kind", "-"),
        "mrts_corpus": entry.get("mrts_corpus", "-"),
        "reason": sanitize_report_text(entry.get("reason", evidence.get("reason", "-"))),
    }


def category_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(row["new_hard_abort_classification"] for row in rows)
    for row in rows:
        counts.update(row.get("evidence_categories", []))
    return {category: counts.get(category, 0) for category in PHASE4_CATEGORIES if counts.get(category, 0)}


def connector_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for connector in ("apache", "nginx", "haproxy"):
        items = [row for row in rows if row.get("connector") == connector]
        counts = category_counts(items)
        hard_abort_rows = [row for row in items if row.get("abort_evidence") and row.get("log_evidence")]
        if connector == "nginx" and hard_abort_rows:
            status = "partial_supported_with_strict_evidence"
            finding = "Strict mode has runtime evidence for Phase 4 connection abort, but MRTS-enabled strict/log evidence still fails in the current matrix."
            next_step = "Keep default safe/log-only behavior separate; stabilize strict evidence when MRTS/CRS preambles are enabled."
        elif connector == "apache":
            status = "implementation_path_present_no_runtime_hard_abort_evidence"
            finding = "Apache emits Phase 4 intervention logs and deny-status evidence before commit; current matrix does not prove a connection abort."
            next_step = "Add or run a strict after-commit Apache evidence case before setting phase4-hard-abort as supported."
        else:
            status = "connector_gap_no_hard_abort_evidence"
            finding = "HAProxy response-body decisions are logged, but current SPOA evidence shows HTTP status decisions rather than transport aborts."
            next_step = "Do not promote to PASS on hard-abort semantics unless HAProxy can produce real close/abort evidence."
        summary[connector] = {
            "rows": len(items),
            "runtime_status": dict(Counter(str(row.get("runtime_status")) for row in items)),
            "classification_counts": counts,
            "hard_abort_evidence_rows": len(hard_abort_rows),
            "log_evidence_rows": sum(1 for row in items if row.get("log_evidence")),
            "full_delivery_without_abort_rows": sum(1 for row in items if row.get("response_delivered") == "full" and not row.get("abort_evidence")),
            "sensitive_log_leak_rows": sum(1 for row in items if row.get("sensitive_log_leak")),
            "capability_status": status,
            "finding": finding,
            "recommended_next_step": next_step,
        }
    return summary


def native_relation(report_dir: Path) -> dict[str, Any]:
    relation: dict[str, Any] = {
        "separate_from_connector_full_matrix": True,
        "classification": "phase4_native_semantics",
    }
    for name in ("apache", "nginx"):
        report = read_json(report_path_from_root(report_dir, f"mrts_native_{name}", "json"))
        relation[name] = {
            "status": report.get("status", "-"),
            "counts": report.get("counts", {}),
            "known_limitations": report.get("known_limitations", []),
            "first_failing_cases": report.get("first_failing_cases", []),
        }
    return relation


def build_report(connector_root: Path) -> dict[str, Any]:
    report_dir = connector_root / REPORT_DIR
    work_queue = read_json(report_path(connector_root, "connector_work_queue", "json"))
    entries = [entry for entry in work_queue.get("entries", []) if isinstance(entry, dict) and is_phase4_candidate(entry)]
    rows = [case_row(entry) for entry in entries]
    rows.sort(key=lambda item: (str(item["connector"]), str(item["case_id"]), str(item["variant"])))
    hard_abort_rows = [row for row in rows if row.get("abort_evidence") and row.get("log_evidence")]
    return {
        "generated_at": utc_now(),
        "report_kind": "phase4-hard-abort-capability",
        "capability": {
            "name": "phase4_hard_abort",
            "flag": "MSCONNECTOR_CAPABILITY_PHASE4_HARD_ABORT",
            "string": "phase4-hard-abort",
            "pass_criteria": [
                "Phase 4/RESPONSE_BODY rule matches sensitive outbound response data.",
                "Connector logs the Phase 4 intervention.",
                "Response is not fully delivered.",
                "Transport evidence shows connection close, hard abort, or equivalent connection-level abort.",
            ],
            "not_sufficient": [
                "HTTP 200 with full body delivery.",
                "Control/pass rows that do not require a hard abort.",
                "log_only without abort.",
                "body truncation without transport abort evidence.",
                "expected 403 alone without Phase 4 intervention evidence.",
            ],
        },
        "source_reports": {
            "connector_work_queue": report_relpath("connector_work_queue", "json"),
            "full_runtime_matrix": report_relpath("full_runtime_matrix", "json"),
            "remaining_failure_analysis": report_relpath("remaining_failure_analysis", "json"),
            "mrts_native_apache": report_relpath("mrts_native_apache", "json"),
            "mrts_native_nginx": report_relpath("mrts_native_nginx", "json"),
        },
        "source_code_findings": {
            "nginx": [
                "connectors/nginx/src/ngx_http_modsecurity_module.c exposes modsecurity_phase4_mode and modsecurity_phase4_log.",
                "connectors/nginx/src/ngx_http_modsecurity_body_filter.c reports actual_action=connection_abort in strict mode after headers are sent.",
            ],
            "apache": [
                "connectors/apache/src/msc_filters.c emits phase4_intervention logs and can return APR_ECONNABORTED when response data was already committed.",
                "Current harness evidence is primarily mode=safe deny_status before commit, not a runtime proof of hard abort.",
            ],
            "haproxy": [
                "Current HAProxy/SPOA evidence includes Phase 4 response-body decisions and 403 status decisions.",
                "No current matrix row shows transport-level connection_abort evidence for HAProxy Phase 4 response-body matches.",
            ],
        },
        "summary": {
            "rows": len(rows),
            "runtime_status": dict(Counter(str(row.get("runtime_status")) for row in rows)),
            "category_counts": category_counts(rows),
            "hard_abort_evidence_rows": len(hard_abort_rows),
            "connection_aborted_rows": sum(1 for row in rows if "phase4_connection_aborted" in row.get("evidence_categories", [])),
            "no_hard_abort_required_rows": sum(1 for row in rows if row.get("new_hard_abort_classification") == "phase4_no_hard_abort_required"),
            "log_evidence_rows": sum(1 for row in rows if row.get("log_evidence")),
            "log_only_not_hard_abort_rows": sum(1 for row in rows if row.get("new_hard_abort_classification") == "phase4_log_only_no_abort"),
            "truncated_not_hard_abort_rows": sum(1 for row in rows if row.get("new_hard_abort_classification") == "phase4_truncated_not_accepted"),
            "status_200_without_abort_rows": sum(1 for row in rows if row.get("actual_status") == 200 and not row.get("abort_evidence")),
            "full_delivery_without_abort_rows": sum(1 for row in rows if row.get("response_delivered") == "full" and not row.get("abort_evidence")),
            "sensitive_log_leak_rows": sum(1 for row in rows if row.get("sensitive_log_leak")),
        },
        "connector_summary": connector_summary(rows),
        "native_mrts_relation": native_relation(report_dir),
        "cases": rows,
        "next_fix_plan": [
            {
                "priority": "P1",
                "connector": "nginx",
                "cluster": "strict Phase 4 evidence with MRTS/CRS variants",
                "reason": "NGINX has strict hard-abort proof in no-MRTS rows, but the same strict/log-only connector-specific cases fail when MRTS is enabled.",
                "allowed_change": "harness/routing/evidence stabilization only; keep default safe behavior separate from strict test-only behavior.",
            },
            {
                "priority": "P2",
                "connector": "apache",
                "cluster": "strict after-commit hard-abort proof",
                "reason": "Apache source has a hard-abort path, but current evidence demonstrates deny_status before commit rather than connection abort.",
                "allowed_change": "add or run a targeted strict evidence case before setting phase4-hard-abort support.",
            },
            {
                "priority": "P3",
                "connector": "haproxy",
                "cluster": "response-body hard abort connector gap",
                "reason": "HAProxy evidence shows Phase 4 decisions, not connection-level aborts.",
                "allowed_change": "classify as connector gap unless a real HAProxy close/abort mechanism is implemented and evidenced.",
            },
        ],
    }


def md_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(item).replace("|", "\\|") for item in row) + " |")
    return lines


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Phase 4 Hard Abort Capability",
        "",
        f"Generated at: `{report['generated_at']}`",
        "",
        "## Capability Contract",
        "- Capability: `phase4_hard_abort` / `phase4-hard-abort`.",
        "- PASS evidence needs Phase 4 intervention logging plus response non-delivery through connection close, hard abort, or equivalent transport abort.",
        "- HTTP status may remain 200 or become a transport error; status alone is not enough.",
        "- This report does not change Expected status values or runtime PASS/FAIL values.",
        "",
        "## Summary",
    ]
    summary = report["summary"]
    lines.extend(
        md_table(
            [
                "Rows",
                "Runtime status",
                "Hard abort evidence",
                "Connection aborted",
                "No hard abort required",
                "Log-only not hard abort",
                "Truncated not hard abort",
                "Status 200 without abort",
                "Sensitive log leaks",
            ],
            [
                [
                    summary["rows"],
                    summary["runtime_status"],
                    summary["hard_abort_evidence_rows"],
                    summary["connection_aborted_rows"],
                    summary["no_hard_abort_required_rows"],
                    summary["log_only_not_hard_abort_rows"],
                    summary["truncated_not_hard_abort_rows"],
                    summary["status_200_without_abort_rows"],
                    summary["sensitive_log_leak_rows"],
                ]
            ],
        )
    )
    lines.extend(["", "## Category Rollup"])
    lines.extend(md_table(["Category", "Count"], [[key, value] for key, value in summary["category_counts"].items()]))
    lines.extend(["", "## Connector Capability"])
    lines.extend(
        md_table(
            ["Connector", "Status", "Rows", "Hard abort rows", "Finding", "Next step"],
            [
                [
                    connector,
                    data["capability_status"],
                    data["rows"],
                    data["hard_abort_evidence_rows"],
                    data["finding"],
                    data["recommended_next_step"],
                ]
                for connector, data in report["connector_summary"].items()
            ],
        )
    )
    lines.extend(["", "## Native MRTS Relation"])
    native_rows = []
    for connector in ("apache", "nginx"):
        data = report["native_mrts_relation"].get(connector, {})
        first = (data.get("first_failing_cases") or [{}])[0]
        native_rows.append(
            [
                connector,
                data.get("status", "-"),
                data.get("counts", {}),
                first.get("case_id", "-"),
                first.get("classification", "-"),
                first.get("secondary_classification", "-"),
            ]
        )
    lines.extend(md_table(["Native target", "Status", "Counts", "Case", "Classification", "Secondary"], native_rows))
    lines.extend(["", "## Source Findings"])
    for connector, findings in report["source_code_findings"].items():
        lines.append(f"- `{connector}`: " + " ".join(findings))
    lines.extend(["", "## Next Fix Plan"])
    lines.extend(
        md_table(
            ["Priority", "Connector", "Cluster", "Reason", "Allowed change"],
            [[item["priority"], item["connector"], item["cluster"], item["reason"], item["allowed_change"]] for item in report["next_fix_plan"]],
        )
    )
    lines.extend(["", "## Case Matrix"])
    lines.extend(
        md_table(
            [
                "Connector",
                "Variant",
                "Case",
                "Rule",
                "Phase",
                "Target",
                "Expected action",
                "Expected",
                "Actual",
                "Runtime",
                "Delivered",
                "Abort evidence",
                "Log evidence",
                "Current classification",
                "New hard-abort classification",
            ],
            [
                [
                    row["connector"],
                    row["variant"],
                    row["case_id"],
                    row["rule_id"],
                    row["phase"],
                    row["target"],
                    row["expected_action"],
                    row["expected_status"],
                    row["actual_status"],
                    row["runtime_status"],
                    row["response_delivered"],
                    row["abort_evidence"],
                    row["log_evidence"],
                    row["current_classification"],
                    row["new_hard_abort_classification"],
                ]
                for row in report["cases"]
            ],
        )
    )
    return "\n".join(lines) + "\n"


def update_phase_work_queue(report_dir: Path, report: dict[str, Any]) -> None:
    json_path = report_path_from_root(report_dir, "phase_work_queue", "json")
    data = read_json(json_path)
    if data:
        data["phase4_hard_abort_capability"] = {
            "report": report_relpath("phase4_hard_abort_capability", "md"),
            "json": report_relpath("phase4_hard_abort_capability", "json"),
            "summary": report["summary"],
            "connector_summary": report["connector_summary"],
        }
        guardrails = data.get("guardrails")
        if isinstance(guardrails, dict):
            guardrails["phase4_hard_abort_requires_transport_evidence"] = True
        write_json(json_path, data)

    md_path = report_path_from_root(report_dir, "phase_work_queue", "md")
    text = read_text(md_path)
    if text:
        section = "\n".join(
            [
                "## Phase 4 Hard Abort Capability",
                f"- Report: `{report_relpath('phase4_hard_abort_capability', 'md')}`",
                f"- Hard-abort evidence rows: **{report['summary']['hard_abort_evidence_rows']}**",
                f"- Full-delivery-without-abort rows: **{report['summary']['full_delivery_without_abort_rows']}**",
                "- Phase 4 PASS promotion now requires intervention log evidence plus transport abort evidence, not HTTP status alone.",
            ]
        )
        start = "<!-- phase4-hard-abort:start -->"
        end = "<!-- phase4-hard-abort:end -->"
        marked = f"{start}\n{section}\n{end}"
        if start in text and end in text:
            prefix = text.split(start, 1)[0].rstrip()
            suffix = text.split(end, 1)[1].lstrip()
            text = f"{prefix}\n\n{marked}\n\n{suffix}".rstrip() + "\n"
        else:
            text = text.rstrip() + "\n\n" + marked + "\n"
        write_text_file(md_path, text)


def update_full_run_evidence(report_dir: Path, report: dict[str, Any]) -> None:
    if os.environ.get("SUPPRESS_FULL_RUN_EVIDENCE_SIDE_EFFECTS") == "1":
        return
    json_path = report_path_from_root(report_dir, "full_run_evidence", "json")
    data = read_json(json_path)
    if data:
        data["phase4_hard_abort_capability"] = {
            "report": report_relpath("phase4_hard_abort_capability", "md"),
            "json": report_relpath("phase4_hard_abort_capability", "json"),
            "summary": report["summary"],
            "connector_summary": {
                connector: {
                    "capability_status": value["capability_status"],
                    "hard_abort_evidence_rows": value["hard_abort_evidence_rows"],
                    "full_delivery_without_abort_rows": value["full_delivery_without_abort_rows"],
                }
                for connector, value in report["connector_summary"].items()
            },
        }
        reports = data.get("reports")
        if isinstance(reports, list):
            for path in (
                report_relpath("phase4_hard_abort_capability", "json"),
                report_relpath("phase4_hard_abort_capability", "md"),
            ):
                if path not in reports:
                    reports.append(path)
            data["reports"] = reports
        write_json(json_path, data)

    md_path = report_path_from_root(report_dir, "full_run_evidence", "md")
    text = read_text(md_path)
    if text:
        section = "\n".join(
            [
                "## Phase 4 Hard Abort Capability",
                f"- Report: `{report_relpath('phase4_hard_abort_capability', 'md')}`",
                f"- Hard-abort evidence rows: **{report['summary']['hard_abort_evidence_rows']}**",
                f"- Full-delivery-without-abort rows: **{report['summary']['full_delivery_without_abort_rows']}**",
                "- The report keeps Expected status and runtime PASS/FAIL unchanged while adding hard-abort classifications.",
            ]
        )
        start = "<!-- phase4-hard-abort-capability:start -->"
        end = "<!-- phase4-hard-abort-capability:end -->"
        text = upsert_marked_section(
            text,
            start=start,
            end=end,
            section=section,
            insert_before="## Reports And Logs",
        )
        write_text_file(md_path, text)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector-root", default=".")
    parser.add_argument("--output-dir", default=None)
    args = parser.parse_args()

    connector_root = Path(args.connector_root).resolve()
    output_dir = resolve_output_dir(connector_root, args.output_dir, REPORT_DIR)
    add_safe_roots(connector_root, connector_root / REPORT_DIR)
    add_report_roots(connector_root / REPORT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)
    report = build_report(connector_root)
    metadata = build_metadata(
        generated_by="ci/evidence/reports/generate-phase4-hard-abort-capability.py",
        make_target="generate-phase4-hard-abort-capability",
        connector_root=connector_root,
        inputs=report["source_reports"].values(),
        generated_at=report["generated_at"],
    )
    json_path = report_path_from_root(output_dir, "phase4_hard_abort_capability", "json")
    md_path = report_path_from_root(output_dir, "phase4_hard_abort_capability", "md")
    write_text_file(json_path, generated_json_text(report, metadata))
    write_text_file(md_path, generated_markdown_text(render_markdown(report), metadata))
    update_phase_work_queue(output_dir, report)
    update_full_run_evidence(output_dir, report)
    print(md_path)
    print(json_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
