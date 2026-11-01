#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

# CI helpers are shared from ci/lib even when this file is executed directly.

from typing import Any

from modsecurity_connector_ci.lib.focused_analysis_utils import action_parts, action_value, as_list, find_framework_case_path, read_json, read_text, refresh_connector_queue_totals, regenerate_phase_work_queue, render_connector_work_queue_markdown, run_report_generator, sanitize_path, upsert_marked_section, utc_now, write_generated_report_pair, write_json
from modsecurity_connector_ci.lib.generated_report_utils import GENERATED_ROOT, report_path, report_path_from_root, report_relpath
from modsecurity_connector_ci.lib.report_path_safety import safe_existing_file, write_text_file

try:
    import yaml
except Exception:  # pragma: no cover - report generation has a regex fallback.
    yaml = None


REPORT_DIR = GENERATED_ROOT
CASE_ID = "v3_action_nolog_pass_no_audit"
CLASSIFICATION = "nolog-expected-no-audit"
EVIDENCE_CLASSIFICATION = "nolog_expected_no_audit"
WORK_DIRECTION = ["classification_only"]
TARGET_RULE_ID = "3326"


def first_secrule_parts(rules: str) -> tuple[str, str, str]:
    normalized = re.sub(r"\\\s*\n\s*", " ", rules)
    match = re.search(r"SecRule\s+([^\s]+)\s+\"([^\"]*)\"\s+\"([^\"]+)\"", normalized, re.DOTALL)
    if match:
        return match.group(1), match.group(2), match.group(3)
    return "-", "-", ""


def parsed_case_sections(raw: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    if yaml is None or not raw:
        return {}, {}, {}, raw
    try:
        parsed = yaml.safe_load(raw)
    except Exception:
        return {}, {}, {}, raw
    document = parsed if isinstance(parsed, dict) else {}
    request = document.get("request") if isinstance(document.get("request"), dict) else {}
    expect = document.get("expect") if isinstance(document.get("expect"), dict) else {}
    return document, request, expect, str(document.get("rules") or raw)


def request_path_and_query(request: dict[str, Any]) -> tuple[str, str]:
    path, separator, query = str(request.get("path") or "-").partition("?")
    return path or "/", query if separator and query else "-"


def parse_case_metadata(case_path: Path | None) -> dict[str, Any]:
    raw = read_text(case_path)
    parsed, request, expect, rules = parsed_case_sections(raw)
    variable, operator, action_text = first_secrule_parts(rules)
    actions = action_parts(action_text)
    path, query = request_path_and_query(request)
    return {
        "case_id": str(parsed.get("name") or CASE_ID),
        "category": str(parsed.get("category") or "-"),
        "case_path": str(case_path),
        "rule_id": action_value(actions, "id") if action_value(actions, "id") != "-" else TARGET_RULE_ID,
        "phase": action_value(actions, "phase"),
        "target": variable,
        "operator": operator,
        "actions": actions,
        "has_nolog": any(action == "nolog" for action in actions),
        "has_auditlog": any(action == "auditlog" for action in actions),
        "method": str(request.get("method") or "-"),
        "path": path,
        "query": query,
        "body": str(request.get("body") or ""),
        "content_type": str(request.get("content_type") or request.get("content-type") or "-"),
        "expected_status": expect.get("status"),
        "expected_rule_id": str(expect.get("rule_id") or "-"),
        "expects_audit_absent": bool((expect.get("audit_log") or {}).get("absent"))
        if isinstance(expect.get("audit_log"), dict)
        else False,
    }


def extract_rule_ids(text: str) -> list[str]:
    ids = set(re.findall(r"\[id \"?(\d+)\"?\]", text))
    ids.update(re.findall(r'"rule_id"\s*:\s*"?(\d+)"?', text))
    ids.update(re.findall(r"\brule_id=(\d+)\b", text))
    return sorted(ids)


def evidence_path(entry: dict[str, Any]) -> Path | None:
    path = str(entry.get("evidence") or entry.get("evidence_path") or "")
    return safe_existing_file(path)


def evidence_log_path(evidence: dict[str, Any], keys: tuple[str, ...]) -> Path | None:
    for key in keys:
        value = evidence.get(key)
        if value:
            return safe_existing_file(value)
    return None


def run_log_index(full_runtime_matrix: dict[str, Any]) -> dict[tuple[str, str, str], str]:
    index: dict[tuple[str, str, str], str] = {}
    for run in full_runtime_matrix.get("runs", []):
        if not isinstance(run, dict):
            continue
        key = (
            str(run.get("connector") or ""),
            str(run.get("test_variant") or ""),
            str(run.get("mrts_variant") or ""),
        )
        index[key] = str(run.get("log_path") or "")
    return index


def load_case_for_entry(entry: dict[str, Any], framework_root: Path) -> Path | None:
    evidence = read_json(evidence_path(entry) or Path())
    case_path = safe_existing_file(evidence.get("path"))
    if case_path is not None and case_path.is_file():
        return case_path
    return find_framework_case_path(framework_root, entry.get("case_id") or CASE_ID)


def nolog_log_evidence(evidence: dict[str, Any], target_rule_id: str) -> dict[str, Any]:
    audit_path = evidence_log_path(evidence, ("audit_log_path", "audit_log"))
    error_path = evidence_log_path(
        evidence,
        ("apache_error_log_path", "nginx_error_log_path", "error_log_path", "spoa_log_path", "haproxy_log_path"),
    )
    decision_path = evidence_log_path(evidence, ("decision_log_path", "decision_log"))
    audit_text, error_text, decision_text = read_text(audit_path), read_text(error_path), read_text(decision_path)
    audit_ids, error_ids, decision_ids = extract_rule_ids(audit_text), extract_rule_ids(error_text), extract_rule_ids(decision_text)
    target_present = any(target_rule_id in ids for ids in (audit_ids, error_ids, decision_ids))
    unrelated_audit_ids = [rule_id for rule_id in audit_ids if rule_id != target_rule_id]
    if not audit_text.strip():
        actual_evidence = "audit log absent or empty"
    elif target_present:
        actual_evidence = f"target rule {target_rule_id} appears in runtime logs"
    else:
        actual_evidence = "audit log contains unrelated rule(s): " + ", ".join(unrelated_audit_ids or audit_ids or ["unknown"])
    return {
        "audit_path": audit_path,
        "error_path": error_path,
        "decision_path": decision_path,
        "audit_text": audit_text,
        "error_text": error_text,
        "decision_text": decision_text,
        "audit_ids": audit_ids,
        "error_ids": error_ids,
        "decision_ids": decision_ids,
        "target_present": target_present,
        "unrelated_audit_ids": unrelated_audit_ids,
        "actual_evidence": actual_evidence,
    }


def nolog_reclassification(case_meta: dict[str, Any], target_present: bool, entry: dict[str, Any], target_rule_id: str) -> tuple[str, list[str], str]:
    no_audit_rule = case_meta.get("has_nolog") and not case_meta.get("has_auditlog") and not target_present
    if not no_audit_rule:
        return "requires_review", as_list(entry.get("work_direction")), "target rule appears in runtime logs or action metadata is ambiguous"
    return (
        EVIDENCE_CLASSIFICATION,
        WORK_DIRECTION,
        f"Rule {target_rule_id} has nolog/pass and is absent from audit, error, and decision logs; non-empty with-crs audit entries are unrelated CRS noise.",
    )


def observed_row(
    entry: dict[str, Any],
    case_meta: dict[str, Any],
    run_logs: dict[tuple[str, str, str], str],
    connector_root: Path,
    framework_root: Path,
) -> dict[str, Any]:
    result_path = evidence_path(entry)
    evidence = read_json(result_path or Path())
    target_rule_id = str(case_meta.get("rule_id") or TARGET_RULE_ID)
    log_evidence = nolog_log_evidence(evidence, target_rule_id)
    target_present = log_evidence["target_present"]
    with_crs_noise = bool(log_evidence["unrelated_audit_ids"] and str(entry.get("test_variant")) == "with-crs")
    expected_evidence = f"rule {target_rule_id} must not create an audit entry because the action list contains nolog"
    classification_after, work_direction_after, reason_after = nolog_reclassification(case_meta, target_present, entry, target_rule_id)
    key = (
        str(entry.get("connector") or ""),
        str(entry.get("test_variant") or ""),
        str(entry.get("mrts_variant") or ""),
    )
    return {
        "connector": entry.get("connector", "-"),
        "variant": f"{entry.get('test_variant', '-')}/{entry.get('mrts_variant', '-')}",
        "case_id": entry.get("case_id", "-"),
        "source_corpus": f"{entry.get('source_kind', '-')}/{entry.get('mrts_corpus', '-')}",
        "rule_id": target_rule_id,
        "phase": case_meta.get("phase", "-"),
        "action_list": case_meta.get("actions", []),
        "has_nolog": case_meta.get("has_nolog", False),
        "has_auditlog": case_meta.get("has_auditlog", False),
        "method": case_meta.get("method", "-"),
        "path": case_meta.get("path", "-"),
        "query": case_meta.get("query", "-"),
        "body": case_meta.get("body", ""),
        "content_type": case_meta.get("content_type", "-"),
        "expected_status": entry.get("expected_status"),
        "actual_status": entry.get("actual_status"),
        "runtime_status": entry.get("runtime_status"),
        "original_classification": entry.get("classification"),
        "original_work_direction": as_list(entry.get("work_direction")),
        "expected_evidence": expected_evidence,
        "actual_evidence": log_evidence["actual_evidence"],
        "audit_log_path": sanitize_path(log_evidence["audit_path"], connector_root, framework_root),
        "error_log_path": sanitize_path(log_evidence["error_path"], connector_root, framework_root),
        "decision_log_path": sanitize_path(log_evidence["decision_path"], connector_root, framework_root),
        "run_log_path": sanitize_path(run_logs.get(key), connector_root, framework_root),
        "audit_log_size": len(log_evidence["audit_text"]),
        "audit_rule_ids": log_evidence["audit_ids"],
        "error_log_rule_ids": log_evidence["error_ids"],
        "decision_log_rule_ids": log_evidence["decision_ids"],
        "target_rule_in_runtime_logs": target_present,
        "with_crs_unrelated_audit_noise": with_crs_noise,
        "backend_reached": bool(evidence.get("live_executed") or evidence.get("modsecurity_processed")),
        "modsecurity_processed": bool(evidence.get("modsecurity_processed", evidence.get("live_executed"))),
        "classification_after_analysis": classification_after,
        "work_direction_after_analysis": work_direction_after,
        "reason_after_analysis": reason_after,
    }


def should_reclassify(row: dict[str, Any], entry: dict[str, Any]) -> bool:
    return (
        entry.get("runtime_status") == "FAIL"
        and "audit_log_evidence" in as_list(entry.get("work_direction"))
        and row["classification_after_analysis"] == EVIDENCE_CLASSIFICATION
        and entry.get("expected_status") == entry.get("actual_status")
    )


def render_analysis_markdown(analysis: dict[str, Any]) -> str:
    summary = analysis["summary"]
    case_meta = analysis["case_metadata"]
    lines = [
        "# Nolog Audit Evidence Analysis",
        "",
        "Generated file - do not edit manually.",
        "",
        "## Scope",
        f"- Case: `{CASE_ID}`",
        f"- Extracted runtime rows: **{summary['rows_extracted']}**",
        f"- Metadata-only reclassified rows: **{summary['rows_reclassified']}**",
        f"- Connectors: {', '.join(summary['connectors']) or '-'}",
        f"- Variants: {', '.join(summary['variants']) or '-'}",
        "",
        "## Rule Semantics",
        f"- Rule ID: `{case_meta['rule_id']}`",
        f"- Phase: `{case_meta['phase']}`",
        f"- Target: `{case_meta['target']}`",
        f"- Actions: `{', '.join(case_meta['actions'])}`",
        f"- has_nolog / has_auditlog: **{case_meta['has_nolog']} / {case_meta['has_auditlog']}**",
        f"- Request: `{case_meta['method']} {case_meta['path']}?{case_meta['query']}`",
        f"- Body/content-type: `{case_meta['body'] or '<empty>'}` / `{case_meta['content_type']}`",
        "- Conclusion: explicit `nolog` means this rule is expected not to produce its own audit entry. "
        "A with-CRS audit record for a different CRS rule is not evidence that the nolog rule logged.",
        "",
        "## Before/After",
        f"- `audit_log_evidence` rows before: **{summary['audit_log_evidence_before']}**",
        f"- `audit_log_evidence` rows after: **{summary['audit_log_evidence_after']}**",
        f"- `classification_only` rows before: **{summary['classification_only_before']}**",
        f"- `classification_only` rows after: **{summary['classification_only_after']}**",
        "",
        "## Runtime Rows",
        "| Connector | Variant | Status | Expected | Actual | Audit IDs | Decision IDs | Target Rule Logged | Backend | Classification |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    def cell(value: Any) -> str:
        return str(value).replace("|", "\\|").replace("\n", " ")

    for row in analysis["rows"]:
        lines.append(
            "| "
            + " | ".join(
                [
                    cell(row["connector"]),
                    cell(row["variant"]),
                    cell(row["runtime_status"]),
                    cell(row["expected_status"]),
                    cell(row["actual_status"]),
                    cell(", ".join(row["audit_rule_ids"]) or "-"),
                    cell(", ".join(row["decision_log_rule_ids"]) or "-"),
                    cell(row["target_rule_in_runtime_logs"]),
                    cell(row["backend_reached"]),
                    cell(row["classification_after_analysis"]),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Evidence Fields",
            "| Connector | Variant | Method | Path | Query | Expected evidence | Actual evidence | Audit log | Error log | Run log |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]
    )
    for row in analysis["rows"]:
        lines.append(
            "| "
            + " | ".join(
                [
                    cell(row["connector"]),
                    cell(row["variant"]),
                    cell(row["method"]),
                    cell(row["path"]),
                    cell(row["query"] or "-"),
                    cell(row["expected_evidence"]),
                    cell(row["actual_evidence"]),
                    cell(row["audit_log_path"]),
                    cell(row["error_log_path"]),
                    cell(row["run_log_path"]),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def classify_connector_queue(
    report_dir: Path,
    rows: list[dict[str, Any]],
    framework_root: Path,
) -> dict[str, int]:
    path = report_path_from_root(report_dir, "connector_work_queue", "json")
    data = read_json(path)
    entries = data.get("entries", [])
    already_classified = sum(
        1
        for entry in entries
        if isinstance(entry, dict)
        and entry.get("case_id") == CASE_ID
        and entry.get("runtime_status") == "FAIL"
        and (
            entry.get("classification") == CLASSIFICATION
            or entry.get("evidence_classification") == EVIDENCE_CLASSIFICATION
        )
    )
    before_audit = sum(1 for entry in entries if "audit_log_evidence" in as_list(entry.get("work_direction"))) + already_classified
    before_classification = max(
        0,
        sum(1 for entry in entries if "classification_only" in as_list(entry.get("work_direction"))) - already_classified,
    )
    row_by_key = {
        (row["connector"], row["variant"]): row
        for row in rows
    }
    updated = 0
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("case_id") != CASE_ID:
            continue
        key = (entry.get("connector"), f"{entry.get('test_variant', '-')}/{entry.get('mrts_variant', '-')}")
        row = row_by_key.get(key)
        if not row or not should_reclassify(row, entry):
            continue
        entry["classification"] = CLASSIFICATION
        entry["work_direction"] = WORK_DIRECTION
        entry["priority"] = "P3"
        entry["evidence_classification"] = EVIDENCE_CLASSIFICATION
        entry["classification_detail"] = row["reason_after_analysis"]
        entry["reason"] = (
            f"classification-only: rule {row['rule_id']} has nolog/pass and is absent from "
            "runtime logs; with-crs audit contains unrelated CRS rule(s): "
            + (", ".join(row["audit_rule_ids"]) or "none")
        )
        updated += 1
    after_audit = sum(1 for entry in entries if "audit_log_evidence" in as_list(entry.get("work_direction")))
    after_classification = sum(1 for entry in entries if "classification_only" in as_list(entry.get("work_direction")))
    refresh_connector_queue_totals(data)
    write_json(path, data)
    render_connector_queue_markdown(report_dir, data, framework_root)
    return {
        "rows_reclassified": updated + already_classified,
        "audit_log_evidence_before": before_audit,
        "audit_log_evidence_after": after_audit,
        "classification_only_before": before_classification,
        "classification_only_after": after_classification,
    }


def render_connector_queue_markdown(report_dir: Path, data: dict[str, Any], framework_root: Path) -> None:
    render_connector_work_queue_markdown(report_dir, data, framework_root)


def render_phase_work_queue(
    report_dir: Path,
    framework_root: Path,
    connector_root: Path,
) -> None:
    def patched_phase_work_direction(
        entry: dict[str, Any],
        original_phase_work_direction: Any,
        module: Any,
    ) -> list[str]:
        if (
            entry.get("case_id") == CASE_ID
            and entry.get("classification") == CLASSIFICATION
            and "classification_only" in module.as_list(entry.get("work_direction"))
        ):
            return WORK_DIRECTION
        return original_phase_work_direction(entry)

    regenerate_phase_work_queue(
        report_dir,
        framework_root,
        connector_root,
        patched_phase_work_direction,
    )


def update_full_run_evidence(report_dir: Path) -> None:
    if os.environ.get("SUPPRESS_FULL_RUN_EVIDENCE_SIDE_EFFECTS") == "1":
        return
    json_path = report_path_from_root(report_dir, "full_run_evidence", "json")
    data = read_json(json_path)
    if data:
        data["nolog_audit_evidence_report"] = {
            "analysis": report_relpath("nolog_audit_evidence", "md"),
            "json": report_relpath("nolog_audit_evidence", "json"),
            "case_id": CASE_ID,
            "classification": EVIDENCE_CLASSIFICATION,
        }
        reports = data.get("reports")
        if isinstance(reports, list):
            for report in (
                report_relpath("nolog_audit_evidence", "json"),
                report_relpath("nolog_audit_evidence", "md"),
            ):
                if report not in reports:
                    reports.append(report)
            data["reports"] = reports
        write_json(json_path, data)
    md_path = report_path_from_root(report_dir, "full_run_evidence", "md")
    text = read_text(md_path)
    if not text:
        return
    lines = [
        "## Nolog Audit Evidence Analysis",
        f"- Nolog audit evidence: `{report_relpath('nolog_audit_evidence', 'md')}`",
        f"- Case `{CASE_ID}` is classified as `{EVIDENCE_CLASSIFICATION}` when rule {TARGET_RULE_ID} is absent from runtime logs.",
    ]
    section = "\n".join(lines)
    start = "<!-- nolog-audit-evidence:start -->"
    end = "<!-- nolog-audit-evidence:end -->"
    text = upsert_marked_section(
        text,
        start=start,
        end=end,
        section=section,
        insert_before="## Reports And Logs",
    )
    write_text_file(md_path, text)


def build_analysis(connector_root: Path, framework_root: Path) -> dict[str, Any]:
    report_dir = connector_root / REPORT_DIR
    connector_queue = read_json(report_path(connector_root, "connector_work_queue", "json"))
    full_runtime_matrix = read_json(report_path(connector_root, "full_runtime_matrix", "json"))
    entries = [
        entry for entry in connector_queue.get("entries", [])
        if isinstance(entry, dict) and entry.get("case_id") == CASE_ID
    ]
    if not entries:
        case_path = framework_root / "tests/cases/audit-log" / f"{CASE_ID}.yaml"
    else:
        case_path = load_case_for_entry(entries[0], framework_root)
    case_meta = parse_case_metadata(case_path)
    run_logs = run_log_index(full_runtime_matrix)
    rows = [
        observed_row(entry, case_meta, run_logs, connector_root, framework_root)
        for entry in entries
    ]
    before_counts = classify_connector_queue(report_dir, rows, framework_root)
    render_phase_work_queue(report_dir, framework_root, connector_root)
    update_full_run_evidence(report_dir)
    work_directions = Counter()
    for row in rows:
        for direction in row["work_direction_after_analysis"]:
            work_directions[direction] += 1
    return {
        "generated_at": utc_now(),
        "report_kind": "nolog-audit-evidence-analysis",
        "source_reports": {
            "connector_work_queue": report_relpath("connector_work_queue", "json"),
            "full_runtime_matrix": report_relpath("full_runtime_matrix", "json"),
            "phase_coverage": report_relpath("phase_coverage", "md"),
        },
        "case_metadata": {
            **case_meta,
            "case_path": sanitize_path(case_meta["case_path"], connector_root, framework_root),
        },
        "summary": {
            "rows_extracted": len(rows),
            "rows_reclassified": before_counts["rows_reclassified"],
            "connectors": sorted({str(row["connector"]) for row in rows}),
            "variants": sorted({str(row["variant"]) for row in rows}),
            "work_direction_after_analysis": dict(work_directions),
            **before_counts,
        },
        "rows": rows,
        "conclusion": {
            "missing_audit_log_for_rule_is_correct": True,
            "root_cause": "with-crs variants contain unrelated CRS audit entries while the nolog/pass rule is absent from audit, error, and decision logs",
            "runtime_status_changed": False,
            "expected_status_changed": False,
            "request_or_rule_changed": False,
        },
    }


def main() -> int:
    return run_report_generator(
        report_name="nolog_audit_evidence",
        generated_by="ci/evidence/reports/generate-nolog-audit-evidence-analysis.py",
        make_target="generate-nolog-audit-evidence-analysis",
        build_analysis=build_analysis,
        render_markdown=render_analysis_markdown,
    )


if __name__ == "__main__":
    raise SystemExit(main())
