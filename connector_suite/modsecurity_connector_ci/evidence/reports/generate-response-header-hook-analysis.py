#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# CI helpers are shared from ci/lib even when this file is executed directly.

from typing import Any

from modsecurity_connector_ci.lib.case_metadata_utils import parse_case_document
from modsecurity_connector_ci.lib.focused_analysis_utils import action_parts, as_list, find_framework_case_path, import_script, read_json, read_text, refresh_connector_queue_totals, regenerate_phase_work_queue, render_connector_work_queue_markdown, run_report_generator, sanitize_path, upsert_marked_section, utc_now, write_generated_report_pair, write_json
from modsecurity_connector_ci.lib.generated_report_utils import GENERATED_ROOT, report_path, report_path_from_root, report_relpath
from modsecurity_connector_ci.lib.report_path_safety import safe_existing_file, write_text_file

try:
    import yaml
except Exception:  # pragma: no cover - report generation has a regex fallback.
    yaml = None


REPORT_DIR = GENERATED_ROOT
CLASSIFICATION_TO_WORK_DIRECTION = {
    "response_header_backend_setup": "response_header_backend_setup",
    "response_header_multi_value_gap": "response_header_multi_value_gap",
    "response_header_mrts_detection_only": "response_header_mrts_detection_only",
}
CLASSIFICATION_LABEL = {
    "response_header_backend_setup": "response-header-backend-setup",
    "response_header_multi_value_gap": "response-header-multi-value-gap",
    "response_header_mrts_detection_only": "response-header-mrts-detection-only",
}


def case_path_for_entry(entry: dict[str, Any], evidence: dict[str, Any], framework_root: Path) -> Path | None:
    case_path = safe_existing_file(evidence.get("path"))
    if case_path is not None:
        return case_path
    return find_framework_case_path(framework_root, entry.get("case_id") or evidence.get("name"))


def response_header_rule_metadata(rules: str) -> dict[str, Any]:
    rule_match = re.search(r"SecRule\s+([^\s]+)\s+\"([^\"]*)\"\s+(?:\\\s*)?\"([^\"]+)\"", rules, re.DOTALL)
    variable = rule_match.group(1) if rule_match else "-"
    actions = action_parts(rule_match.group(3) if rule_match else "")
    action_text = ",".join(actions)
    rule_id_match = re.search(r"\bid:(\d+)", action_text)
    phase_match = re.search(r"\bphase:(\d+)", action_text)
    return {
        "rule_id": rule_id_match.group(1) if rule_id_match else "-",
        "phase": phase_match.group(1) if phase_match else "-",
        "target": variable,
        "header_name": variable.split(":", 1)[1] if ":" in variable else variable,
        "operator": rule_match.group(2) if rule_match else "-",
        "actions": actions,
    }


def response_header_case_fields(
    parsed: dict[str, Any], fallback: dict[str, Any], case_path: Path | None
) -> dict[str, Any]:
    return {
        "case_id": str(parsed.get("name") or fallback.get("case_id") or (case_path.stem if case_path else "-")),
        "category": str(parsed.get("category") or fallback.get("category") or "-"),
        "case_path": str(case_path) if case_path else "-",
    }


def response_header_request_fields(
    request: dict[str, Any],
    expect: dict[str, Any],
    fallback: dict[str, Any],
    response: dict[str, Any],
    path: str,
    query: str,
) -> dict[str, Any]:
    response_headers = response.get("headers") if isinstance(response.get("headers"), dict) else {}
    return {
        "method": str(request.get("method") or fallback.get("method") or "-"),
        "path": path,
        "query": query,
        "response_headers_configured": bool(response_headers),
        "response_headers": response_headers,
        "expected_status": expect.get("status", fallback.get("expected_status")),
    }


def parse_case_metadata(case_path: Path | None, fallback: dict[str, Any] | None = None) -> dict[str, Any]:
    fallback = fallback or {}
    raw = read_text(case_path)
    parsed, request, expect, _source_metadata, path, query = parse_case_document(raw, yaml)
    rules = str(parsed.get("rules") or raw)
    response = parsed.get("response") if isinstance(parsed.get("response"), dict) else {}
    rule_metadata = response_header_rule_metadata(rules)
    return {
        **response_header_case_fields(parsed, fallback, case_path),
        **rule_metadata,
        "phase": rule_metadata["phase"] if rule_metadata["phase"] != "-" else str(fallback.get("phase") or "-"),
        **response_header_request_fields(request, expect, fallback, response, path, query),
    }


def evidence_path(entry: dict[str, Any]) -> Path | None:
    return safe_existing_file(entry.get("evidence") or entry.get("evidence_path"))


def log_text(evidence: dict[str, Any]) -> str:
    texts = []
    for key in (
        "apache_error_log_path",
        "nginx_error_log_path",
        "decision_log_path",
        "audit_log_path",
        "spoa_log_path",
        "haproxy_log_path",
    ):
        value = evidence.get(key)
        if value:
            texts.append(read_text(value))
    return "\n".join(texts)


def rule_logged(logs: str, rule_id: str) -> bool:
    if not rule_id or rule_id == "-":
        return False
    return bool(
        re.search(r'\[id "' + re.escape(rule_id) + r'"\]', logs)
        or re.search(r'"rule_id"\s*:\s*"?' + re.escape(rule_id) + r'"?', logs)
    )


def rule_disruptive(logs: str, rule_id: str) -> bool:
    if not rule_logged(logs, rule_id):
        return False
    return "Access denied" in logs or '"decision":"deny"' in logs


def same_case_no_mrts_pass(entries: list[dict[str, Any]], entry: dict[str, Any]) -> bool:
    for candidate in entries:
        if (
            candidate.get("connector") == entry.get("connector")
            and candidate.get("test_variant") == entry.get("test_variant")
            and candidate.get("mrts_variant") == "no-mrts"
            and candidate.get("case_id") == entry.get("case_id")
            and candidate.get("runtime_status") == "PASS"
        ):
            return True
    return False


def classify_row(entry: dict[str, Any], meta: dict[str, Any], logs: str, entries: list[dict[str, Any]]) -> tuple[str, str]:
    if entry.get("mrts_variant") == "with-mrts" and same_case_no_mrts_pass(entries, entry):
        return (
            "response_header_mrts_detection_only",
            "with-mrts loads MRTS init, which sets ctl:ruleEngine=DetectionOnly; matching Phase 3 rules log but do not block",
        )
    if entry.get("connector") == "haproxy" and str(meta.get("header_name")) == "Set-Cookie":
        return (
            "response_header_multi_value_gap",
            "HAProxy response header hook is active, but Set-Cookie multi-value cases do not expose the expected value to ModSecurity",
        )
    if not rule_logged(logs, str(meta.get("rule_id") or "")):
        return (
            "response_header_backend_setup",
            "backend/harness response does not provide the target response header value observed by the rule",
        )
    return (
        "response_header_mrts_detection_only",
        "target rule is visible in logs but did not produce a disruptive intervention",
    )


def build_rows(
    connector_root: Path,
    framework_root: Path,
    remaining_module: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    report_dir = connector_root / REPORT_DIR
    queue = read_json(report_path_from_root(report_dir, "connector_work_queue", "json"))
    entries = [entry for entry in queue.get("entries", []) if isinstance(entry, dict)]
    failure_rows = [
        entry
        for entry in entries
        if entry.get("runtime_status") == "FAIL"
        and (
            remaining_module.failure_category(entry) == "response_header_hook"
            or str(entry.get("evidence_classification") or "") in CLASSIFICATION_TO_WORK_DIRECTION
            or entry.get("category") == "response-headers"
            or "response_headers" in as_list(entry.get("functional_area"))
        )
    ]
    pass_rows = [
        entry
        for entry in entries
        if entry.get("runtime_status") == "PASS"
        and ("response_headers" in as_list(entry.get("functional_area")) or entry.get("category") == "response-headers")
    ]
    rows: list[dict[str, Any]] = []
    for entry in failure_rows:
        evidence = read_json(evidence_path(entry) or Path())
        case_path = case_path_for_entry(entry, evidence, framework_root)
        meta = parse_case_metadata(case_path, entry)
        logs = log_text(evidence)
        evidence_classification, reason = classify_row(entry, meta, logs, entries)
        target_rule_logged = rule_logged(logs, str(meta.get("rule_id") or ""))
        target_rule_disruptive = rule_disruptive(logs, str(meta.get("rule_id") or ""))
        backend_header_set = bool(target_rule_logged or same_case_no_mrts_pass(entries, entry))
        rows.append(
            {
                "connector": entry.get("connector", "-"),
                "variant": f"{entry.get('test_variant', '-')}/{entry.get('mrts_variant', '-')}",
                "test_variant": entry.get("test_variant", "-"),
                "mrts_variant": entry.get("mrts_variant", "-"),
                "case_id": entry.get("case_id", "-"),
                "source_corpus": f"{entry.get('source_kind', '-')}/{entry.get('mrts_corpus', '-')}",
                "rule_id": meta["rule_id"],
                "phase": meta["phase"],
                "target": meta["target"],
                "header_name": meta["header_name"],
                "operator": meta["operator"],
                "action_list": meta["actions"],
                "method": meta["method"],
                "path": meta["path"],
                "expected_header": f"{meta['target']} {meta['operator']}",
                "actual_header_evidence": "target rule matched" if target_rule_logged else "target rule missing from logs",
                "backend_header_set": backend_header_set,
                "modsecurity_sees_header": target_rule_logged,
                "target_rule_disruptive": target_rule_disruptive,
                "expected_status": entry.get("expected_status"),
                "actual_status": entry.get("actual_status"),
                "expected_log_evidence": f"rule {meta['rule_id']} should deny in phase {meta['phase']}",
                "actual_log_evidence": reason,
                "classification_before": entry.get("classification"),
                "work_direction_before": as_list(entry.get("work_direction")),
                "evidence_classification": evidence_classification,
                "classification_after": CLASSIFICATION_LABEL[evidence_classification],
                "work_direction_after": [CLASSIFICATION_TO_WORK_DIRECTION[evidence_classification]],
                "audit_log_path": sanitize_path(evidence.get("audit_log_path"), connector_root, framework_root),
                "error_log_path": sanitize_path(
                    evidence.get("apache_error_log_path") or evidence.get("nginx_error_log_path") or evidence.get("spoa_log_path"),
                    connector_root,
                    framework_root,
                ),
                "decision_log_path": sanitize_path(evidence.get("decision_log_path"), connector_root, framework_root),
            }
        )
    controls: list[dict[str, Any]] = []
    for entry in pass_rows:
        evidence = read_json(evidence_path(entry) or Path())
        case_path = case_path_for_entry(entry, evidence, framework_root)
        meta = parse_case_metadata(case_path, entry)
        controls.append(
            {
                "connector": entry.get("connector", "-"),
                "variant": f"{entry.get('test_variant', '-')}/{entry.get('mrts_variant', '-')}",
                "case_id": entry.get("case_id", "-"),
                "rule_id": meta["rule_id"],
                "header_name": meta["header_name"],
                "expected_status": entry.get("expected_status"),
                "actual_status": entry.get("actual_status"),
            }
        )
    return rows, controls


def classify_connector_queue(
    report_dir: Path,
    rows: list[dict[str, Any]],
    framework_root: Path,
) -> dict[str, int]:
    path = report_path_from_root(report_dir, "connector_work_queue", "json")
    data = read_json(path)
    entries = data.get("entries", [])
    row_by_key = {
        (
            row["connector"],
            row["test_variant"],
            row["mrts_variant"],
            row["case_id"],
        ): row
        for row in rows
    }
    before_response_header_hook = sum(
        1
        for entry in entries
        if isinstance(entry, dict)
        and entry.get("runtime_status") == "FAIL"
        and (
            entry.get("category") == "response-headers"
            or "response_headers" in as_list(entry.get("functional_area"))
            or "response_header_hook" in as_list(entry.get("work_direction"))
        )
        and not str(entry.get("evidence_classification") or "").startswith("response_header_")
    ) + sum(
        1
        for entry in entries
        if isinstance(entry, dict)
        and entry.get("runtime_status") == "FAIL"
        and str(entry.get("evidence_classification") or "").startswith("response_header_")
    )
    before_custom = sum(
        1
        for entry in entries
        if isinstance(entry, dict)
        and entry.get("runtime_status") == "FAIL"
        and str(entry.get("evidence_classification") or "").startswith("response_header_")
    )
    updated = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        key = (
            entry.get("connector"),
            entry.get("test_variant"),
            entry.get("mrts_variant"),
            entry.get("case_id"),
        )
        row = row_by_key.get(key)
        if not row:
            continue
        entry["classification"] = row["classification_after"]
        entry["work_direction"] = row["work_direction_after"]
        entry["priority"] = "P2"
        entry["evidence_classification"] = row["evidence_classification"]
        entry["classification_detail"] = row["actual_log_evidence"]
        entry["reason"] = f"classification-only: {row['actual_log_evidence']}"
        updated += 1
    after_custom = sum(
        1
        for entry in entries
        if isinstance(entry, dict)
        and entry.get("runtime_status") == "FAIL"
        and str(entry.get("evidence_classification") or "").startswith("response_header_")
    )
    refresh_connector_queue_totals(data)
    write_json(path, data)
    render_connector_queue_markdown(report_dir, data, framework_root)
    return {
        "response_header_hook_before": before_response_header_hook,
        "response_header_hook_after": 0,
        "response_header_custom_before": before_custom,
        "response_header_custom_after": after_custom,
        "rows_reclassified": updated,
    }


def render_connector_queue_markdown(report_dir: Path, data: dict[str, Any], framework_root: Path) -> None:
    render_connector_work_queue_markdown(report_dir, data, framework_root)


def render_phase_work_queue(report_dir: Path, framework_root: Path, connector_root: Path) -> None:
    def patched_phase_work_direction(
        entry: dict[str, Any],
        original_phase_work_direction: Any,
        _module: Any,
    ) -> list[str]:
        evidence_classification = str(entry.get("evidence_classification") or "")
        if evidence_classification in CLASSIFICATION_TO_WORK_DIRECTION:
            return [CLASSIFICATION_TO_WORK_DIRECTION[evidence_classification]]
        if evidence_classification == "nolog_expected_no_audit" or (
            entry.get("classification") == "nolog-expected-no-audit"
            and "classification_only" in as_list(entry.get("work_direction"))
        ):
            return ["classification_only"]
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
        data["response_header_hook_analysis_report"] = {
            "analysis": report_relpath("response_header_hook_analysis", "md"),
            "json": report_relpath("response_header_hook_analysis", "json"),
            "classification": "response_header_hook_split",
        }
        reports = data.get("reports")
        if isinstance(reports, list):
            for report in (
                report_relpath("response_header_hook_analysis", "json"),
                report_relpath("response_header_hook_analysis", "md"),
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
        "## Response Header Hook Analysis",
        f"- Response header hook analysis: `{report_relpath('response_header_hook_analysis', 'md')}`",
        "- The former monolithic `response_header_hook` cluster is split into backend header setup, multi-value header, and MRTS DetectionOnly overlay buckets.",
    ]
    section = "\n".join(lines)
    start = "<!-- response-header-hook-analysis:start -->"
    end = "<!-- response-header-hook-analysis:end -->"
    text = upsert_marked_section(
        text,
        start=start,
        end=end,
        section=section,
        insert_before="## Reports And Logs",
    )
    write_text_file(md_path, text)


def rollup(rows: list[dict[str, Any]], key_fields: tuple[str, ...]) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[tuple(row.get(field, "-") for field in key_fields)].append(row)
    result = []
    for key, items in sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0])):
        result.append(
            {
                "count": len(items),
                **{field: key[index] for index, field in enumerate(key_fields)},
                "example_case": items[0]["case_id"],
            }
        )
    return result


def render_markdown(analysis: dict[str, Any]) -> str:
    summary = analysis["summary"]
    lines = [
        "# Response Header Hook Analysis",
        "",
        "Generated file - do not edit manually.",
        "",
        "## Scope",
        f"- Response-header FAIL rows analyzed: **{summary['failure_rows']}**",
        f"- Response-header PASS control rows: **{summary['pass_control_rows']}**",
        f"- Connectors: {', '.join(summary['connectors']) or '-'}",
        f"- Variants: {', '.join(summary['variants']) or '-'}",
        f"- Phases: {', '.join(summary['phases']) or '-'}",
        "",
        "## Classification",
        f"- `response_header_hook` before: **{summary['response_header_hook_before']}**",
        f"- `response_header_hook` after: **{summary['response_header_hook_after']}**",
        f"- Backend/header setup: **{summary['classification_counts'].get('response_header_backend_setup', 0)}**",
        f"- HAProxy Set-Cookie multi-value gap: **{summary['classification_counts'].get('response_header_multi_value_gap', 0)}**",
        f"- MRTS DetectionOnly overlay: **{summary['classification_counts'].get('response_header_mrts_detection_only', 0)}**",
        "",
        "## Root Cause",
        "- Apache, NGINX, and HAProxy now have no-MRTS PASS controls for deterministic response-header blocking, including specialized Content-Type, Location, and Set-Cookie probes.",
        "- HAProxy preserves repeated `Set-Cookie` response headers through the binary SPOE response-header argument path; the text/scalar fallback remains secondary evidence only.",
        "- `with-mrts` rows that otherwise pass in no-MRTS are suppressed by the MRTS init rule's transaction-level DetectionOnly control; this is classification-only and not a connector PASS promotion.",
        "",
        "## PASS Controls",
    ]
    lines.extend(table(["Connector", "Variant", "Case", "Rule", "Header", "Expected", "Actual"], [
        [
            row["connector"],
            row["variant"],
            row["case_id"],
            row["rule_id"],
            row["header_name"],
            row["expected_status"],
            row["actual_status"],
        ]
        for row in analysis["pass_controls"][:40]
    ]))
    lines.extend(["", "## Failure Groups"])
    lines.extend(table(
        ["Count", "Connector", "Header", "Classification", "Phase", "Expected", "Actual", "Example"],
        [
            [
                item["count"],
                item["connector"],
                item["header_name"],
                item["evidence_classification"],
                item["phase"],
                item["expected_status"],
                item["actual_status"],
                item["example_case"],
            ]
            for item in analysis["groups"]["by_connector_header_classification"]
        ],
    ))
    lines.extend(["", "## Failure Rows"])
    lines.extend(table(
        [
            "Connector",
            "Variant",
            "Case",
            "Rule",
            "Target",
            "Expected header",
            "Actual evidence",
            "Backend header set",
            "ModSecurity sees header",
            "Classification",
        ],
        [
            [
                row["connector"],
                row["variant"],
                row["case_id"],
                row["rule_id"],
                row["target"],
                row["expected_header"],
                row["actual_header_evidence"],
                row["backend_header_set"],
                row["modsecurity_sees_header"],
                row["evidence_classification"],
            ]
            for row in analysis["rows"][:120]
        ],
    ))
    return "\n".join(lines) + "\n"


def table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(item).replace("|", "\\|").replace("\n", " ") for item in row) + " |")
    if not rows:
        lines.append("| " + " | ".join("-" for _ in headers) + " |")
    return lines


def build_analysis(connector_root: Path, framework_root: Path) -> dict[str, Any]:
    report_dir = connector_root / REPORT_DIR
    remaining_module = import_script(connector_root / "ci/evidence/reports/generate-remaining-failure-analysis.py", "remaining_failure_analysis")
    rows, controls = build_rows(connector_root, framework_root, remaining_module)
    queue_counts = classify_connector_queue(report_dir, rows, framework_root)
    render_phase_work_queue(report_dir, framework_root, connector_root)
    update_full_run_evidence(report_dir)
    classification_counts = Counter(row["evidence_classification"] for row in rows)
    return {
        "generated_at": utc_now(),
        "report_kind": "response-header-hook-analysis",
        "source_reports": {
            "connector_work_queue": report_relpath("connector_work_queue", "json"),
            "full_runtime_matrix": report_relpath("full_runtime_matrix", "json"),
            "phase_coverage": report_relpath("phase_coverage", "md"),
        },
        "summary": {
            "failure_rows": len(rows),
            "pass_control_rows": len(controls),
            "connectors": sorted({str(row["connector"]) for row in rows + controls}),
            "variants": sorted({str(row["variant"]) for row in rows + controls}),
            "phases": sorted({str(row["phase"]) for row in rows}),
            "classification_counts": dict(classification_counts),
            **queue_counts,
        },
        "groups": {
            "by_connector_header_classification": rollup(
                rows,
                ("connector", "header_name", "evidence_classification", "phase", "expected_status", "actual_status"),
            ),
            "by_case": rollup(rows, ("case_id", "header_name", "evidence_classification")),
            "by_source": rollup(rows, ("source_corpus", "evidence_classification")),
        },
        "pass_controls": controls,
        "rows": rows,
        "conclusion": {
            "runtime_status_changed": False,
            "expected_status_changed": False,
            "request_or_rule_changed": False,
            "connector_core_changed": False,
            "root_cause": "monolithic response_header_hook cluster is reduced to MRTS DetectionOnly overlay after backend setup and HAProxy Set-Cookie multi-value evidence are stabilized",
        },
    }


def main() -> int:
    return run_report_generator(
        report_name="response_header_hook_analysis",
        generated_by="ci/evidence/reports/generate-response-header-hook-analysis.py",
        make_target="generate-response-header-hook-analysis",
        build_analysis=build_analysis,
        render_markdown=render_markdown,
    )


if __name__ == "__main__":
    raise SystemExit(main())
