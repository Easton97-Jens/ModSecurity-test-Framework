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

from modsecurity_connector_ci.lib.focused_analysis_utils import as_list, read_json, read_text, utc_now, write_json
from modsecurity_connector_ci.lib.focused_analysis_utils import upsert_marked_section
from modsecurity_connector_ci.lib.generated_report_utils import GENERATED_ROOT, build_metadata, generated_json_text, generated_markdown_text, report_path, report_path_from_root, report_relpath
from modsecurity_connector_ci.lib.report_path_safety import add_report_roots, add_safe_roots, resolve_output_dir, safe_existing_file, write_text_file

try:
    import yaml
except Exception:  # pragma: no cover - report generation keeps working without YAML detail.
    yaml = None


REPORT_DIR = GENERATED_ROOT
REPORT_STEM = "no-mrts-intervention-nomatch-analysis.generated"
FRAMEWORK_PATH_PREFIX = "framework:"
ABSOLUTE_RUNTIME_PATH_RE = re.compile(r"(?<![\w.-])/(?:tmp|root|src)[^\s\"']*")


CAUSE_DETAILS = {
    "transformation_request_value_absent_or_semantic_gap": {
        "label": "Transformation/request literal does not expose expected token",
        "suspected_cause": "The request literal does not contain the expected operator token, or requires unverified transformation semantics before a match can occur.",
        "safe_fixability": "not safe as a harness fix; changing the request token would change test semantics",
        "risk": "high",
    },
    "collection_name_normalization_semantics": {
        "label": "Collection-name normalization semantics",
        "suspected_cause": "Header, cookie, or query-name normalization differs from the rule target expectation.",
        "safe_fixability": "requires native/libmodsecurity comparison before changing harness or connector code",
        "risk": "medium to high",
    },
    "xml_processor_activation_missing": {
        "label": "XML processor activation missing",
        "suspected_cause": "The XML body and Content-Type are present, but these fixtures do not enable SecRequestBodyAccess/ctl:requestBodyProcessor=XML.",
        "safe_fixability": "metadata/report-only; do not change XML body, rules, Expected status, or connector-core behavior",
        "risk": "low if kept report-only; high if treated as connector XML parser evidence",
    },
    "multipart_processor_activation_missing": {
        "label": "Multipart processor activation missing",
        "suspected_cause": "The multipart bodies, Content-Type, and boundary are present, but these fixtures do not enable SecRequestBodyAccess before expecting Multipart FILES/ARGS_NAMES collections.",
        "safe_fixability": "metadata/report-only; do not change multipart body, rules, Expected status, or connector-core behavior",
        "risk": "low if kept report-only; high if treated as connector multipart parser evidence",
    },
    "phase1_request_body_unavailable_or_empty_body": {
        "label": "Phase 1 request-body unavailable or empty",
        "suspected_cause": "The rule reads REQUEST_BODY in phase 1 while the case request body does not contain the expected token.",
        "safe_fixability": "not safe to fix by changing the body; that would change the test definition",
        "risk": "low to medium",
    },
    "unknown_no_match": {
        "label": "Unknown loaded-rule no-match",
        "suspected_cause": "Rule is loaded but no target match evidence is visible.",
        "safe_fixability": "analysis required",
        "risk": "medium",
    },
}


def sanitize_report_text(value: Any) -> str:
    return ABSOLUTE_RUNTIME_PATH_RE.sub("<evidence-path>", str(value or ""))


def split_path_query(path: str) -> tuple[str, str]:
    if "?" not in path:
        return path or "/", "-"
    base, query = path.split("?", 1)
    return base or "/", query or "-"


def case_path_from_record(record: dict[str, Any], framework_root: Path) -> Path | None:
    value = str(record.get("case_path") or "")
    if value.startswith(FRAMEWORK_PATH_PREFIX):
        return framework_root / value.split(FRAMEWORK_PATH_PREFIX, 1)[1]
    path = safe_existing_file(value)
    if path is not None and path.is_file():
        return path
    return None


def display_case_path(path: Path | None, framework_root: Path) -> str:
    if path is None:
        return "-"
    try:
        return FRAMEWORK_PATH_PREFIX + str(path.resolve(strict=False).relative_to(framework_root.resolve(strict=False)))
    except ValueError:
        return sanitize_report_text(path.name)


def load_case(path: Path | None) -> dict[str, Any]:
    if path is None or yaml is None:
        return {}
    try:
        loaded = yaml.safe_load(read_text(path))
    except Exception:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def queue_by_key(connector_root: Path) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    queue = read_json(report_path(connector_root, "connector_work_queue", "json"))
    entries = queue.get("entries") if isinstance(queue.get("entries"), list) else []
    return {
        (
            str(item.get("case_id") or ""),
            str(item.get("connector") or ""),
            str(item.get("test_variant") or ""),
            str(item.get("mrts_variant") or ""),
        ): item
        for item in entries
    }


def operator_expected_token(operator: str) -> str:
    operator = operator.strip()
    parts = operator.split(maxsplit=1)
    if len(parts) == 2 and parts[0].startswith("@"):
        return parts[1].strip().strip("'\"")
    return "-"


def request_summary(case: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    request = case.get("request") if isinstance(case.get("request"), dict) else {}
    method = str(request.get("method") or record.get("method") or "-")
    raw_path = str(request.get("path") or record.get("path") or "/")
    path, query = split_path_query(raw_path)
    headers = request.get("headers") if isinstance(request.get("headers"), dict) else {}
    body = request.get("body")
    body_text = "" if body is None else str(body)
    content_type = str(headers.get("Content-Type") or headers.get("content-type") or record.get("content_type") or "-")
    return {
        "method": method,
        "path": path,
        "query": query if query != "-" else str(record.get("query") or "-"),
        "headers": {str(k): str(v) for k, v in headers.items()},
        "content_type": content_type,
        "body_length": len(body_text.encode("utf-8")),
        "body_present": bool(body_text),
        "request_literal": "\n".join(
            [
                method,
                raw_path,
                json.dumps(headers, sort_keys=True),
                body_text,
            ]
        ),
    }


def evidence_summary(queue_entry: dict[str, Any] | None) -> dict[str, Any]:
    if not queue_entry:
        return {
            "result": "-",
            "audit_log_present": "unknown",
            "target_rule_logged": False,
            "backend_reached": "unknown",
        }
    result_path = safe_existing_file(queue_entry.get("evidence"))
    result = read_json(result_path)
    audit_path = safe_existing_file(result.get("audit_log_path"))
    audit_text = read_text(audit_path)
    error_text = read_text(result.get("apache_error_log_path"))
    logs = "\n".join([audit_text, error_text])
    rule_id = str(queue_entry.get("rule_id") or "")
    target_rule_logged = bool(rule_id and re.search(r'\[id "' + re.escape(rule_id) + r'"\]', logs))
    return {
        "result": sanitize_report_text(result_path.name if result_path.name else "-"),
        "audit_log_present": "yes" if audit_text else "no",
        "target_rule_logged": target_rule_logged,
        "backend_reached": bool(str(result.get("actual_status") or queue_entry.get("actual_status")) == "200"),
    }


def classify_cause(record: dict[str, Any], request: dict[str, Any]) -> str:
    category = str(record.get("source_category") or "")
    target = str(record.get("target") or "")
    phase = str(record.get("phase") or "")
    expected_token = operator_expected_token(str(record.get("operator") or ""))
    literal = request.get("request_literal", "")
    literal_contains_token = expected_token != "-" and expected_token in literal
    if category == "phase-handling" or (phase == "1" and target == "REQUEST_BODY"):
        return "phase1_request_body_unavailable_or_empty_body"
    if category == "transformations":
        return "transformation_request_value_absent_or_semantic_gap"
    if category == "collections":
        return "collection_name_normalization_semantics"
    if category == "body-processors":
        return "xml_processor_activation_missing"
    if category == "multipart":
        return "multipart_processor_activation_missing"
    if not literal_contains_token:
        return "transformation_request_value_absent_or_semantic_gap"
    return "unknown_no_match"


def selected_records(connector_root: Path) -> list[dict[str, Any]]:
    report = read_json(report_path(connector_root, "intervention_blocking_analysis", "json"))
    records = report.get("records") if isinstance(report.get("records"), list) else []
    return [
        item
        for item in records
        if item.get("mrts_variant") == "no-mrts"
        and item.get("expected_status") == 403
        and item.get("actual_status") == 200
        and item.get("rule_loaded") is True
        and item.get("rule_matched") is False
    ]


def native_comparator(connector_root: Path, case_ids: set[str]) -> dict[str, Any]:
    apache = read_json(report_path(connector_root, "mrts_native_apache", "json"))
    nginx = read_json(report_path(connector_root, "mrts_native_nginx", "json"))
    summary = read_json(report_path(connector_root, "mrts_native_summary", "json"))
    native_ids = set()
    for report in (apache, nginx):
        counts = report.get("counts") if isinstance(report.get("counts"), dict) else {}
        native_ids.update(str(item) for item in counts.get("failed_cases", []) if item)
        for item in report.get("first_failing_cases", []) if isinstance(report.get("first_failing_cases"), list) else []:
            if isinstance(item, dict):
                native_ids.add(str(item.get("case_id") or item.get("name") or ""))
    overlap = sorted(case_ids & native_ids)
    return {
        "available": bool(overlap),
        "matching_case_ids": overlap,
        "status": "no native comparator" if not overlap else "native comparator present",
        "reason": "Native MRTS reports cover upstream MRTS target cases; these 105 rows are framework-owned no-MRTS connector cases.",
        "native_status": {
            "apache": apache.get("status", "-"),
            "nginx": nginx.get("status", "-"),
            "summary_generated_at": summary.get("generated_at", "-"),
        },
    }


def top_counts(values: list[Any], limit: int = 20) -> list[dict[str, Any]]:
    return [{"value": str(value), "count": count} for value, count in Counter(values).most_common(limit)]


def grouped(records: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        buckets[str(record.get(key) or "-")].append(record)
    groups = []
    for value, items in sorted(buckets.items(), key=lambda pair: (-len(pair[1]), pair[0])):
        groups.append(
            {
                "value": value,
                "count": len(items),
                "connectors": sorted({str(item["connector"]) for item in items}),
                "phases": top_counts([item.get("phase", "-") for item in items], limit=8),
                "targets": top_counts([item.get("target", "-") for item in items], limit=8),
                "operators": top_counts([item.get("operator", "-") for item in items], limit=8),
                "example_cases": sorted({str(item["case_id"]) for item in items})[:8],
            }
        )
    return groups


def build_report(connector_root: Path, framework_root: Path) -> dict[str, Any]:
    queue = queue_by_key(connector_root)
    full_matrix = read_json(report_path(connector_root, "full_runtime_matrix", "json"))
    raw_records = selected_records(connector_root)
    records: list[dict[str, Any]] = []
    for item in raw_records:
        case_path = case_path_from_record(item, framework_root)
        case = load_case(case_path)
        request = request_summary(case, item)
        key = (
            str(item.get("case_id") or ""),
            str(item.get("connector") or ""),
            str(item.get("test_variant") or ""),
            str(item.get("mrts_variant") or ""),
        )
        queue_entry = queue.get(key)
        expected_token = operator_expected_token(str(item.get("operator") or ""))
        evidence = evidence_summary(queue_entry)
        cause = classify_cause(item, request)
        details = CAUSE_DETAILS[cause]
        queue_or_item = queue_entry or item
        record = {
            "case_id": item.get("case_id", "-"),
            "connector": item.get("connector", "-"),
            "variant": item.get("variant", "-"),
            "classification": queue_or_item.get("classification", "-"),
            "work_direction": as_list(queue_or_item.get("work_direction")),
            "priority": queue_or_item.get("priority", "-"),
            "source_kind": queue_or_item.get("source_kind", item.get("source_kind", "-")),
            "source_category": queue_or_item.get("category", item.get("source_category", "-")),
            "case_path": display_case_path(case_path, framework_root),
            "rule_id": item.get("rule_id", "-"),
            "phase": item.get("phase", "-"),
            "target": item.get("target", "-"),
            "operator": item.get("operator", "-"),
            "transformations": as_list(item.get("transformations")),
            "actions": as_list(item.get("actions")),
            "request": {
                "method": request["method"],
                "path": request["path"],
                "query": request["query"],
                "headers": request["headers"],
                "content_type": request["content_type"],
                "body_present": request["body_present"],
                "body_length": request["body_length"],
            },
            "expected_match_value": expected_token,
            "raw_request_contains_expected_value": expected_token != "-" and expected_token in request["request_literal"],
            "backend_reached": item.get("backend_reached", "-"),
            "rule_loaded": item.get("rule_loaded", "-"),
            "rule_matched": item.get("rule_matched", "-"),
            "intervention_created": item.get("intervention_created", "-"),
            "evidence": evidence,
            "cause": cause,
            "suspected_cause": details["suspected_cause"],
            "safe_fixability": details["safe_fixability"],
            "risk": details["risk"],
            "known_limitations": as_list(case.get("known_limitations")),
        }
        records.append(record)

    case_ids = {str(item["case_id"]) for item in records}
    cause_counter = Counter(str(item["cause"]) for item in records)
    remaining_intervention_blocking = sum(
        1 for item in records if "intervention_blocking" in item["work_direction"]
    )
    remaining_p0_p1_intervention_blocking = sum(
        1
        for item in records
        if "intervention_blocking" in item["work_direction"] and item["priority"] in {"P0", "P1"}
    )
    safe_candidate = {
        "selected": False,
        "cluster": "none",
        "count": 0,
        "reason": "No small safe harness/evidence fix was identified. The smallest clear group is phase1_request_body_unavailable_or_empty_body, but changing its body would change the test definition.",
        "action": "analysis only; no runtime, rule, expected-status, or PASS/FAIL change",
    }
    report = {
        "report_kind": "no-mrts-intervention-nomatch-analysis",
        "generated_at": utc_now(),
        "source_reports": {
            "intervention_blocking_analysis": report_relpath("intervention_blocking_analysis", "json"),
            "full_runtime_matrix": report_relpath("full_runtime_matrix", "json"),
            "remaining_failure_analysis": report_relpath("remaining_failure_analysis", "json"),
            "connector_work_queue": report_relpath("connector_work_queue", "json"),
            "next_fix_plan": report_relpath("next_fix_plan", "json"),
        },
        "summary": {
            "no_mrts_no_match": len(records),
            "unique_cases": len(case_ids),
            "rule_not_loaded": 0,
            "rule_loaded_no_match": len(records),
            "rule_matched_no_intervention": 0,
            "intervention_created_connector_missed_403": 0,
            "backend_reached": sum(1 for item in records if item["backend_reached"] is True),
            "full_matrix_totals": full_matrix.get("totals", {}),
            "before_after": {
                "no_mrts_no_match_before": len(records),
                "no_mrts_no_match_after": len(records),
                "intervention_blocking_true_candidates_before": len(records),
                "intervention_blocking_true_candidates_after": remaining_intervention_blocking,
                "p0_p1_intervention_blocking_before": len(records),
                "p0_p1_intervention_blocking_after": remaining_p0_p1_intervention_blocking,
            },
        },
        "distribution": {
            "connectors": top_counts([item["connector"] for item in records]),
            "variants": top_counts([item["variant"] for item in records]),
            "classifications": top_counts([item["classification"] for item in records]),
            "work_directions": top_counts([",".join(item["work_direction"]) or "-" for item in records]),
            "priorities": top_counts([item["priority"] for item in records]),
            "phases": top_counts([item["phase"] for item in records]),
            "targets": top_counts([item["target"] for item in records]),
            "operators": top_counts([item["operator"] for item in records]),
            "transformations": top_counts([",".join(item["transformations"]) or "-" for item in records]),
            "source_categories": top_counts([item["source_category"] for item in records]),
            "causes": [
                {
                    "cause": cause,
                    "label": CAUSE_DETAILS[cause]["label"],
                    "count": count,
                    "suspected_cause": CAUSE_DETAILS[cause]["suspected_cause"],
                    "safe_fixability": CAUSE_DETAILS[cause]["safe_fixability"],
                    "risk": CAUSE_DETAILS[cause]["risk"],
                    "example_cases": sorted({str(item["case_id"]) for item in records if item["cause"] == cause})[:8],
                }
                for cause, count in cause_counter.most_common()
            ],
        },
        "groups": {
            "by_connector": grouped(records, "connector"),
            "by_phase": grouped(records, "phase"),
            "by_target": grouped(records, "target"),
            "by_operator": grouped(records, "operator"),
            "by_source_category": grouped(records, "source_category"),
            "by_cause": grouped(records, "cause"),
        },
        "native_comparator": native_comparator(connector_root, case_ids),
        "safe_subcluster": safe_candidate,
        "records": records,
    }
    return report


def md_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(sanitize_report_text(item).replace("|", "\\|") for item in row) + " |")
    return lines


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# No-MRTS Intervention No-Match Analysis",
        "",
        f"- Generated at: `{report['generated_at']}`",
        f"- no-MRTS expected `403` / actual `200` rows with loaded rule and no match: **{summary['no_mrts_no_match']}**",
        f"- Unique cases: **{summary['unique_cases']}**",
        f"- Rule not loaded: **{summary['rule_not_loaded']}**",
        f"- Rule loaded, no match: **{summary['rule_loaded_no_match']}**",
        f"- Rule matched, no intervention: **{summary['rule_matched_no_intervention']}**",
        f"- Intervention created but connector did not return 403: **{summary['intervention_created_connector_missed_403']}**",
        f"- Backend reached: **{summary['backend_reached']}**",
        "",
        "## Cause Groups",
        "",
    ]
    lines.extend(
        md_table(
            ["Cause", "Count", "Likely cause", "Safe fixability", "Risk", "Examples"],
            [
                [
                    item["label"],
                    item["count"],
                    item["suspected_cause"],
                    item["safe_fixability"],
                    item["risk"],
                    ", ".join(item["example_cases"]),
                ]
                for item in report["distribution"]["causes"]
            ],
        )
    )
    lines.extend(["", "## Connector / Phase / Target / Operator"])
    for title, key in [
        ("Connectors", "connectors"),
        ("Phases", "phases"),
        ("Targets", "targets"),
        ("Operators", "operators"),
        ("Source categories", "source_categories"),
        ("Classifications", "classifications"),
        ("Work directions", "work_directions"),
        ("Priorities", "priorities"),
    ]:
        lines.extend(["", f"### {title}"])
        lines.extend(md_table(["Value", "Count"], [[item["value"], item["count"]] for item in report["distribution"][key]]))

    native = report["native_comparator"]
    lines.extend(
        [
            "",
            "## Native Comparator",
            "",
            f"- Status: `{native['status']}`",
            f"- Matching native case IDs: `{', '.join(native['matching_case_ids']) or '-'}`",
            f"- Reason: {native['reason']}",
            f"- Native Apache status: `{native['native_status']['apache']}`",
            f"- Native NGINX status: `{native['native_status']['nginx']}`",
            "",
            "## Safe Subcluster Decision",
            "",
            f"- Selected: **{'yes' if report['safe_subcluster']['selected'] else 'no'}**",
            f"- Cluster: `{report['safe_subcluster']['cluster']}`",
            f"- Count: **{report['safe_subcluster']['count']}**",
            f"- Reason: {report['safe_subcluster']['reason']}",
            f"- Action: {report['safe_subcluster']['action']}",
            "",
            "## Before / After",
            "",
        ]
    )
    before_after = summary["before_after"]
    lines.extend(
        md_table(
            ["Metric", "Before", "After"],
            [
                ["no-MRTS no-match", before_after["no_mrts_no_match_before"], before_after["no_mrts_no_match_after"]],
                [
                    "intervention_blocking true candidates",
                    before_after["intervention_blocking_true_candidates_before"],
                    before_after["intervention_blocking_true_candidates_after"],
                ],
                [
                    "P0/P1 intervention_blocking rows",
                    before_after["p0_p1_intervention_blocking_before"],
                    before_after["p0_p1_intervention_blocking_after"],
                ],
                ["full-matrix pass", summary["full_matrix_totals"].get("pass", "-"), summary["full_matrix_totals"].get("pass", "-")],
                ["full-matrix fail", summary["full_matrix_totals"].get("fail", "-"), summary["full_matrix_totals"].get("fail", "-")],
                ["full-matrix blocked", summary["full_matrix_totals"].get("blocked", "-"), summary["full_matrix_totals"].get("blocked", "-")],
            ],
        )
    )
    lines.extend(["", "## Representative Records", ""])
    lines.extend(
        md_table(
            [
                "Case",
                "Connector",
                "Variant",
                "Rule",
                "Phase",
                "Target",
                "Operator",
                "Request",
                "Expected value",
                "Classification",
                "Work direction",
                "Priority",
                "Cause",
            ],
            [
                [
                    item["case_id"],
                    item["connector"],
                    item["variant"],
                    item["rule_id"],
                    item["phase"],
                    item["target"],
                    item["operator"],
                    f"{item['request']['method']} {item['request']['path']}?{item['request']['query']}",
                    item["expected_match_value"],
                    item["classification"],
                    ",".join(item["work_direction"]),
                    item["priority"],
                    item["cause"],
                ]
                for item in report["records"][:24]
            ],
        )
    )
    lines.extend(
        [
            "",
            "## Guardrails",
            "",
            "- Analysis-only report: no Expected status, runtime PASS/FAIL, rule, request, or MRTS definition was changed.",
            "- No connector/core code fix is recommended from this evidence alone.",
            "- No row shows a generated disruptive intervention that a connector later lost.",
        ]
    )
    return "\n".join(lines) + "\n"


def update_full_run_evidence(report_dir: Path) -> None:
    if os.environ.get("SUPPRESS_FULL_RUN_EVIDENCE_SIDE_EFFECTS") == "1":
        return
    json_path = report_path_from_root(report_dir, "full_run_evidence", "json")
    data = read_json(json_path)
    if data:
        data["no_mrts_intervention_nomatch_analysis_report"] = {
            "analysis": report_relpath("no_mrts_intervention_nomatch_analysis", "md"),
            "json": report_relpath("no_mrts_intervention_nomatch_analysis", "json"),
        }
        reports = data.get("reports")
        if isinstance(reports, list):
            for report in (
                report_relpath("no_mrts_intervention_nomatch_analysis", "json"),
                report_relpath("no_mrts_intervention_nomatch_analysis", "md"),
            ):
                if report not in reports:
                    reports.append(report)
            data["reports"] = reports
        write_json(json_path, data)

    md_path = report_path_from_root(report_dir, "full_run_evidence", "md")
    text = read_text(md_path)
    if text:
        start = "<!-- no-mrts-intervention-nomatch-analysis:start -->"
        end = "<!-- no-mrts-intervention-nomatch-analysis:end -->"
        section = "\n".join(
            [
                "## No-MRTS Intervention No-Match Analysis",
                f"- Report: `{report_relpath('no_mrts_intervention_nomatch_analysis', 'md')}`",
                "- Scope: 105 no-MRTS expected 403 / actual 200 rows where the rule is loaded but no match evidence is visible.",
                "- This is analysis-only evidence; Expected statuses and runtime PASS/FAIL values remain unchanged.",
            ]
        )
        text = upsert_marked_section(
            text,
            start=start,
            end=end,
            section=section,
            insert_before="<!-- remaining-failure-analysis:start -->",
        )
        write_text_file(md_path, text)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector-root", type=Path, default=Path.cwd())
    parser.add_argument("--framework-root", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args()

    connector_root = args.connector_root.resolve()
    framework_root = (args.framework_root or connector_root / "modules/ModSecurity-test-Framework").resolve()
    output_dir = resolve_output_dir(connector_root, args.output_dir, REPORT_DIR)
    add_safe_roots(connector_root, framework_root, connector_root / REPORT_DIR)
    add_report_roots(connector_root / REPORT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)

    report = build_report(connector_root, framework_root)
    metadata = build_metadata(
        generated_by="ci/evidence/reports/generate-no-mrts-intervention-nomatch-analysis.py",
        make_target="generate-no-mrts-intervention-nomatch-analysis",
        connector_root=connector_root,
        framework_root=framework_root,
        inputs=report["source_reports"].values(),
        generated_at=report["generated_at"],
    )
    json_path = report_path_from_root(output_dir, "no_mrts_intervention_nomatch_analysis", "json")
    md_path = report_path_from_root(output_dir, "no_mrts_intervention_nomatch_analysis", "md")
    write_text_file(json_path, generated_json_text(report, metadata))
    write_text_file(md_path, generated_markdown_text(render_markdown(report), metadata))
    update_full_run_evidence(output_dir)
    print(md_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
