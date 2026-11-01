#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

# CI helpers are shared from ci/lib even when this file is executed directly.
import sys

from typing import Any

from modsecurity_connector_ci.lib.case_metadata_utils import parse_case_document
from modsecurity_connector_ci.lib.generated_report_utils import GENERATED_ROOT, build_metadata, current_verified_run_id, generated_json_text, generated_markdown_text, report_path_from_root, report_relpath
from modsecurity_connector_ci.lib.focused_analysis_utils import read_json, read_text, upsert_marked_section, utc_now
from modsecurity_connector_ci.lib.report_path_safety import add_report_roots, add_safe_roots, resolve_output_dir, safe_existing_file, write_json_file, write_text_file

try:
    import yaml
except Exception:  # pragma: no cover - the report still works without YAML metadata.
    yaml = None


REPORT_DIR = GENERATED_ROOT
GENERATOR_PATH = "ci/evidence/reports/generate-remaining-failure-analysis.py"
LOW_TO_MEDIUM_RISK = "low to medium"
MEDIUM_TO_HIGH_RISK = "medium to high"
PRIMARY_CONNECTORS = "apache, nginx, haproxy"
NO_ROWS_MARKER = "- None."
RULE_ID_HEADER = "Rule ID"
VARIABLE_TARGET_HEADER = "Variable/target"
SOURCE_REPORT_INPUTS = (
    report_relpath("full_runtime_matrix", "json"),
    report_relpath("connector_work_queue", "json"),
    report_relpath("phase_work_queue", "json"),
    report_relpath("full_run_evidence", "json"),
    report_relpath("runtime_build_cache", "json"),
    report_relpath("mrts_native_summary", "json"),
    report_relpath("mrts_native_apache", "json"),
    report_relpath("mrts_native_nginx", "json"),
)
FAILURE_CATEGORIES = (
    "intervention_blocking",
    "collection_name_normalization_semantics",
    "phase4_no_hard_abort_required",
    "phase4_hard_abort_evidence",
    "phase4_connection_aborted",
    "phase4_log_only_no_abort",
    "phase4_truncated_not_accepted",
    "phase4_missing_abort_evidence",
    "phase4_connector_gap",
    "phase4_native_semantics",
    "native_modsecurity_semantics",
    "nolog_expected_no_audit",
    "audit_log_evidence",
    "request_body_processor",
    "xml_processor",
    "xml_processor_activation_missing",
    "multipart_processor_activation_missing",
    "multipart_files",
    "transformation_semantics",
    "rule_chain_semantics",
    "response_header_backend_setup",
    "response_header_multi_value_gap",
    "response_header_mrts_detection_only",
    "secaction_detection_only_overlay",
    "with_mrts_detection_only_non_disruptive",
    "response_header_hook",
    "request_routing",
    "harness_evidence_issue",
    "connector_gap",
    "classification_only",
    "unknown_requires_review",
)
NO_MRTS_NOMATCH_SEMANTIC_CLASSIFICATIONS = {
    "transformation_request_literal_no_match",
    "collection_name_normalization_semantics",
    "xml_body_processor_collection_semantics",
    "xml_processor_activation_missing",
    "multipart_processor_activation_missing",
    "phase1_request_body_unavailable",
}
PHASE4_HARD_ABORT_CATEGORIES = {
    "phase4_no_hard_abort_required",
    "phase4_hard_abort_evidence",
    "phase4_connection_aborted",
    "phase4_log_only_no_abort",
    "phase4_truncated_not_accepted",
    "phase4_missing_abort_evidence",
    "phase4_connector_gap",
    "phase4_native_semantics",
}
OLD_CLUSTER_CHECKS = (
    ("blocked_any", "Unexpected BLOCKED entries"),
    ("apache_expected_200_actual_404", "Apache expected 200 -> actual 404"),
    ("haproxy_expected_200_actual_501", "HAProxy expected 200 -> actual 501"),
    ("nginx_actual_500", "NGINX actual status 500"),
    ("classification_incomplete", "MRTS classification incomplete"),
)
BODY_PROCESSOR_CONNECTOR_GAP_CASES = {
    "phase1_vs_phase2_request_body_gap",
}
REPORT_ONLY_SINGLE_CONNECTOR_CATEGORIES = {
    "secaction_detection_only_overlay",
    "with_mrts_detection_only_non_disruptive",
    "response_header_mrts_detection_only",
    "phase4_missing_abort_evidence",
    "phase4_connector_gap",
    "phase4_log_only_no_abort",
    "phase4_truncated_not_accepted",
    "phase4_native_semantics",
    "nolog_expected_no_audit",
    "xml_processor_activation_missing",
    "multipart_processor_activation_missing",
    "collection_name_normalization_semantics",
}
NOT_NEXT_RECOMMENDATIONS = (
    {
        "cluster": "phase4_hard_abort_capability",
        "reason": "requires transport-abort proof plus Phase 4 intervention logs; do not solve with Expected/PASS changes",
    },
    {
        "cluster": "transformation_semantics",
        "reason": "large count but likely semantic; needs native/libmodsecurity comparison before fixes",
    },
    {
        "cluster": "nolog_expected_no_audit",
        "reason": "classification-only: explicit nolog means the matching rule should not emit audit evidence",
    },
    {
        "cluster": "response_header_mrts_detection_only",
        "reason": "classification-only: with-MRTS DetectionOnly overlay suppresses disruptive Phase 3 action",
    },
    {
        "cluster": "with_mrts_detection_only_non_disruptive",
        "reason": "classification-only: with-MRTS DetectionOnly overlay suppresses disruptive request-side action",
    },
    {
        "cluster": "secaction_detection_only_overlay",
        "reason": "classification-only: with-MRTS DetectionOnly overlay suppresses disruptive SecAction intervention",
    },
    {
        "cluster": "xml_processor_activation_missing",
        "reason": "classification-only: XML body and Content-Type exist, but these fixtures do not enable ctl:requestBodyProcessor=XML",
    },
    {
        "cluster": "multipart_processor_activation_missing",
        "reason": "classification-only: multipart body, Content-Type, and boundary exist, but these fixtures do not enable request body access before expecting FILES/ARGS_NAMES collections",
    },
    {
        "cluster": "collection_name_normalization_semantics",
        "reason": "metadata-only: loaded rules have no match evidence; needs native/libmodsecurity comparison before runtime fixes",
    },
)


def normalize_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value is None:
        return []
    return [str(value)]


def first_value(*values: Any) -> str:
    for value in values:
        text = str(value or "")
        if text and text not in {"-", "none", "None", "null"}:
            return text
    return "-"


def status_pair(entry: dict[str, Any]) -> str:
    return f"{entry.get('expected_status', '-')}\u2192{entry.get('actual_status', '-')}"


def phase_value(entry: dict[str, Any]) -> str:
    value = entry.get("phase")
    return str(value) if value not in (None, "") else "unknown"


def is_phase4_entry(entry: dict[str, Any]) -> bool:
    work_direction = set(normalize_list(entry.get("work_direction")))
    classification = str(entry.get("classification") or "")
    return (
        "response_body_non_promoted" in work_direction
        or classification == "response-body-non-promoted"
        or phase_value(entry) == "4"
    )


def phase4_detail_context(entry: dict[str, Any]) -> dict[str, Any]:
    evidence = read_json(entry.get("evidence"))
    phase4_log = read_text(evidence.get("connector_phase4_log_path"))
    decision_log = read_text(evidence.get("decision_log_path") or evidence.get("decision_log"))
    return {
        "evidence": evidence,
        "connector": str(entry.get("connector") or ""),
        "case_id": str(entry.get("case_id") or ""),
        "reason": str(entry.get("reason") or evidence.get("reason") or ""),
        "classification": str(entry.get("classification") or ""),
        "known_limitations": " ".join(normalize_list(evidence.get("known_limitations"))).lower(),
        "expected_action": phase4_expected_action(entry, evidence),
        "hard_abort": phase4_has_hard_abort(evidence, phase4_log),
        "has_log_evidence": bool(phase4_log.strip() or decision_log.strip()),
        "phase4_log": phase4_log,
    }


def phase4_precedence_category(context: dict[str, Any]) -> str | None:
    if context["hard_abort"] and context["has_log_evidence"]:
        return "phase4_hard_abort_evidence"
    if "native" in context["classification"]:
        return "phase4_native_semantics"
    if phase4_is_log_only(context["reason"], context["case_id"], context["phase4_log"]):
        return "phase4_log_only_no_abort"
    if context["evidence"].get("response_body_truncated") is True:
        return "phase4_truncated_not_accepted"
    return None


def phase4_action_category(entry: dict[str, Any], context: dict[str, Any]) -> str:
    if context["expected_action"] != "deny":
        if not context["has_log_evidence"] and entry.get("runtime_status") == "FAIL":
            return "phase4_missing_abort_evidence"
        return "phase4_no_hard_abort_required"
    if phase4_is_connector_gap(
        context["connector"], context["classification"], context["known_limitations"], context["case_id"]
    ):
        return "phase4_connector_gap"
    return "phase4_missing_abort_evidence"


def phase4_detail_category(entry: dict[str, Any]) -> str:
    context = phase4_detail_context(entry)
    precedence = phase4_precedence_category(context)
    if precedence is not None:
        return precedence
    return phase4_action_category(entry, context)


def phase4_expected_action(entry: dict[str, Any], evidence: dict[str, Any]) -> str:
    expected = str(evidence.get("expected_intervention") or "")
    if expected:
        return expected
    return "deny" if entry.get("expected_status") in (401, 403, 302) else "pass"


def phase4_has_hard_abort(evidence: dict[str, Any], phase4_log: str) -> bool:
    compact_log = phase4_log.replace(" ", "")
    return (
        evidence.get("strict_abort") is True
        or '"strict_abort":true' in compact_log
        or evidence.get("observed_transport_result") == "connection_aborted"
        or '"actual_action":"connection_abort"' in compact_log
    )


def phase4_is_log_only(reason: str, case_id: str, phase4_log: str) -> bool:
    return (
        '"actual_action":"log_only"' in phase4_log.replace(" ", "")
        or reason in {"mode_minimal", "mode_safe", "content_type_not_in_scope"}
        or any(token in case_id for token in ("minimal_log_only", "safe_log_only", "content_type_out_of_scope"))
    )


def phase4_is_connector_gap(
    connector: str, classification: str, known_limitations: str, case_id: str
) -> bool:
    return (
        connector == "haproxy"
        or "connector-gap" in classification
        or "connector-gap" in known_limitations
        or "connector_gap" in case_id
    )


def failure_category(entry: dict[str, Any]) -> str:
    work_direction = set(normalize_list(entry.get("work_direction")))
    functional_area = set(normalize_list(entry.get("functional_area")))
    failure_pattern = set(normalize_list(entry.get("failure_pattern")))
    category = str(entry.get("category") or "")
    case_id = str(entry.get("case_id") or "")
    classification = str(entry.get("classification") or "")
    evidence_classification = str(entry.get("evidence_classification") or "")
    direct = direct_failure_classification(classification)
    if direct:
        return direct
    if is_phase4_entry(entry):
        return phase4_detail_category(entry)
    if is_nolog_classification(
        classification, evidence_classification, case_id, work_direction, functional_area
    ):
        return "nolog_expected_no_audit"
    return categorized_failure(
        work_direction, functional_area, failure_pattern, category, case_id,
        evidence_classification,
    )


def direct_failure_classification(classification: str) -> str:
    return {
        "with_mrts_detection_only_non_disruptive": "with_mrts_detection_only_non_disruptive",
        "secaction_detection_only_overlay": "secaction_detection_only_overlay",
        "xml_processor_activation_missing": "xml_processor_activation_missing",
        "multipart_processor_activation_missing": "multipart_processor_activation_missing",
        "collection_name_normalization_semantics": "collection_name_normalization_semantics",
    }.get(classification, "")


def is_nolog_classification(
    classification: str, evidence_classification: str, case_id: str,
    work_direction: set[str], functional_area: set[str],
) -> bool:
    return (
        classification == "nolog-expected-no-audit"
        or evidence_classification == "nolog_expected_no_audit"
        or (
            case_id == "v3_action_nolog_pass_no_audit"
            and "classification_only" in work_direction
            and "audit_log" in functional_area
        )
    )


def categorized_failure(
    work_direction: set[str], functional_area: set[str], failure_pattern: set[str],
    category: str, case_id: str, evidence_classification: str,
) -> str:
    transformed = transformation_failure_category(functional_area, category)
    if transformed:
        return transformed
    return (
        evidence_failure_category(work_direction, failure_pattern, evidence_classification)
        or feature_failure_category(functional_area, category, case_id)
        or work_direction_failure_category(work_direction)
        or "unknown_requires_review"
    )


def evidence_failure_category(
    work_direction: set[str], failure_pattern: set[str], evidence_classification: str
) -> str:
    if "audit_log_evidence" in work_direction:
        return "audit_log_evidence"
    if "harness_incompatibility" in work_direction or "expected_200_got_0" in failure_pattern:
        return "harness_evidence_issue"
    if evidence_classification in {
        "response_header_backend_setup",
        "response_header_multi_value_gap",
        "response_header_mrts_detection_only",
    }:
        return evidence_classification
    return ""


def transformation_failure_category(functional_area: set[str], category: str) -> str:
    if category == "transformations" or "transformations" in functional_area:
        return "transformation_semantics"
    return ""


def feature_failure_category(functional_area: set[str], category: str, case_id: str) -> str:
    if category == "response-headers" or "response_headers" in functional_area:
        return "response_header_hook"
    if category == "multipart" or "multipart_files" in functional_area:
        return "multipart_files"
    if category == "xml" or "request_body_xml" in functional_area:
        return "xml_processor"
    if case_id in BODY_PROCESSOR_CONNECTOR_GAP_CASES:
        return "connector_gap"
    if category in {"body-processors", "request-body"} or any(
        item.startswith("request_body") for item in functional_area
    ):
        return "request_body_processor"
    if category == "security/rule-chain" or "chain" in case_id:
        return "rule_chain_semantics"
    return ""


def work_direction_failure_category(work_direction: set[str]) -> str:
    for marker, category in (
        ("request_routing", "request_routing"),
        ("connector_gap", "connector_gap"),
        ("classification_only", "classification_only"),
        ("intervention_blocking", "intervention_blocking"),
    ):
        if marker in work_direction:
            return category
    return ""


def safe_read_evidence(entry: dict[str, Any]) -> dict[str, Any]:
    path = safe_existing_file(entry.get("evidence"))
    if path is None:
        return {}
    return read_json(path)


def first_rule_metadata(text: str) -> dict[str, str]:
    rule_match = re.search(r"SecRule\s+([^\s\"]+)\s+\"[^\"]+\"\s+(?:\\\s*)?\"([^\"]+)\"", text, re.MULTILINE)
    action_text = rule_match.group(2) if rule_match else ""
    id_match = re.search(r"\bid:(\d+)", action_text)
    phase_match = re.search(r"\bphase:(\d+)", action_text)
    return {
        "rule_id": id_match.group(1) if id_match else "-",
        "phase": phase_match.group(1) if phase_match else "-",
        "variable": rule_match.group(1) if rule_match else "-",
        "rule_excerpt": re.sub(r"\s+", " ", rule_match.group(0)).strip() if rule_match else "-",
    }


def yaml_case_metadata(entry: dict[str, Any]) -> dict[str, Any]:
    evidence = safe_read_evidence(entry)
    case_path = safe_existing_file(evidence.get("path"))
    metadata: dict[str, Any] = {
        "case_id": entry.get("case_id", "-"),
        "rule_id": "-",
        "phase": phase_value(entry),
        "variable": "-",
        "target": "-",
        "method": "-",
        "path": "-",
        "query": "-",
        "runtime_verified": str(evidence.get("runtime_verified", "false")).lower(),
        "pending_or_non_promoted": entry.get("classification") == "response-body-non-promoted" or phase_value(entry) == "4",
        "rule_excerpt": "-",
    }
    if case_path is None:
        return metadata

    raw = read_text(case_path)
    parsed, request, expect, source_metadata, request_path, query = parse_case_document(
        raw, yaml, parse_empty=True
    )
    rules = str(parsed.get("rules") or raw)
    rule = first_rule_metadata(rules)
    variables = source_metadata.get("variables")
    metadata_variable = ", ".join(str(item) for item in variables) if isinstance(variables, list) else str(variables or "-")
    metadata.update(
        {
            "rule_id": rule["rule_id"],
            "phase": rule["phase"] if rule["phase"] != "-" else metadata["phase"],
            "variable": rule["variable"],
            "target": rule["variable"],
            "method": str(request.get("method") or "-"),
            "path": request_path,
            "query": query,
            "rule_excerpt": rule["rule_excerpt"],
            "runtime_verified": str(parsed.get("runtime_verified", metadata["runtime_verified"])).lower(),
        }
    )
    metadata["rule_id"] = first_value(metadata["rule_id"], expect.get("rule_id"), source_metadata.get("mrts_rule_id"))
    metadata["phase"] = str(source_metadata.get("phase") or metadata["phase"])
    if metadata["variable"] == "-":
        metadata["variable"] = metadata_variable
        metadata["target"] = metadata_variable
    return metadata


def example_entry(entries: list[dict[str, Any]]) -> dict[str, Any]:
    entry = entries[0]
    meta = yaml_case_metadata(entry)
    return {
        "connector": entry.get("connector", "-"),
        "variant": f"{entry.get('test_variant', '-')}/{entry.get('mrts_variant', '-')}",
        "case_id": entry.get("case_id", "-"),
        "rule_id": meta.get("rule_id", "-"),
        "phase": meta.get("phase", phase_value(entry)),
        "variable": meta.get("variable", "-"),
        "expected_status": entry.get("expected_status", "-"),
        "actual_status": entry.get("actual_status", "-"),
        "failure_pattern": normalize_list(entry.get("failure_pattern")) or ["-"],
        "work_direction": normalize_list(entry.get("work_direction")) or ["-"],
        "classification": entry.get("classification", "-"),
        "runtime_verified": meta.get("runtime_verified", "false"),
        "pending_or_non_promoted": meta.get("pending_or_non_promoted", False),
        "method": meta.get("method", "-"),
        "path": meta.get("path", "-"),
        "query": meta.get("query", "-"),
    }


def cluster_key(entry: dict[str, Any], *, include_connector: bool = False) -> tuple[Any, ...]:
    base = (
        failure_category(entry),
        entry.get("classification", "-"),
        entry.get("category", "-"),
        phase_value(entry),
        status_pair(entry),
        tuple(normalize_list(entry.get("work_direction"))),
        entry.get("source_kind", "-"),
        entry.get("mrts_corpus", "-"),
    )
    if include_connector:
        return (entry.get("connector", "-"),) + base
    return base


def make_cluster(counter_entries: list[dict[str, Any]], key: tuple[Any, ...], count: int, *, include_connector: bool = False) -> dict[str, Any]:
    entries = [entry for entry in counter_entries if cluster_key(entry, include_connector=include_connector) == key]
    connectors = sorted({str(entry.get("connector", "-")) for entry in entries})
    variants = sorted({f"{entry.get('test_variant', '-')}/{entry.get('mrts_variant', '-')}" for entry in entries})
    example = example_entry(entries)
    offset = 1 if include_connector else 0
    return {
        "cluster_name": " / ".join(
            str(part)
            for part in (
                (key[0],) if include_connector else ()
            )
            + (
                key[offset],
                key[offset + 2],
                f"phase:{key[offset + 3]}",
                key[offset + 4],
            )
        ),
        "count": count,
        "connectors": connectors,
        "variants": variants,
        "category": key[offset],
        "classification": key[offset + 1],
        "source_category": key[offset + 2],
        "phase": key[offset + 3],
        "status_pair": key[offset + 4],
        "work_direction": list(key[offset + 5]),
        "source_kind": key[offset + 6],
        "corpus": key[offset + 7],
        "examples": [example],
    }


def top_clusters(entries: list[dict[str, Any]], *, include_connector: bool = False, limit: int = 10) -> list[dict[str, Any]]:
    counts = Counter(cluster_key(entry, include_connector=include_connector) for entry in entries)
    return [
        make_cluster(entries, key, count, include_connector=include_connector)
        for key, count in counts.most_common(limit)
    ]


def case_groups(entries: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        groups[str(entry.get("case_id", "-"))].append(entry)
    return groups


def case_group_summary(case_id: str, entries: list[dict[str, Any]]) -> dict[str, Any]:
    connectors = sorted({str(entry.get("connector", "-")) for entry in entries})
    variants = sorted({f"{entry.get('test_variant', '-')}/{entry.get('mrts_variant', '-')}" for entry in entries})
    statuses = Counter(status_pair(entry) for entry in entries)
    categories = Counter(failure_category(entry) for entry in entries)
    return {
        "case_id": case_id,
        "count": len(entries),
        "connectors": connectors,
        "variants": variants,
        "category": categories.most_common(1)[0][0] if categories else "-",
        "status_pairs": dict(statuses.most_common()),
        "example": example_entry(entries),
    }


def top_case_groups(entries: list[dict[str, Any]], *, cross_connector: bool | None, limit: int = 10) -> list[dict[str, Any]]:
    summaries = []
    for case_id, grouped in case_groups(entries).items():
        connectors = {entry.get("connector") for entry in grouped}
        if cross_connector is True and len(connectors) <= 1:
            continue
        if cross_connector is False and len(connectors) != 1:
            continue
        summaries.append(case_group_summary(case_id, grouped))
    summaries.sort(key=lambda item: (-item["count"], item["case_id"]))
    return summaries[:limit]


def runtime_fixable_single_connector_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    eligible = []
    for entry in entries:
        category = failure_category(entry)
        if category in REPORT_ONLY_SINGLE_CONNECTOR_CATEGORIES:
            continue
        if category in PHASE4_HARD_ABORT_CATEGORIES:
            continue
        if "classification_only" in set(normalize_list(entry.get("work_direction"))):
            continue
        eligible.append(entry)
    grouped = case_groups(eligible)
    allowed_cases = {
        case_id
        for case_id, grouped_entries in grouped.items()
        if len({entry.get("connector") for entry in grouped_entries}) == 1
    }
    return [entry for entry in eligible if entry.get("case_id") in allowed_cases]


def old_cluster_regressions(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    checks = {
        "blocked_any": [entry for entry in entries if entry.get("runtime_status") == "BLOCKED"],
        "apache_expected_200_actual_404": [
            entry for entry in entries if entry.get("connector") == "apache" and entry.get("expected_status") == 200 and entry.get("actual_status") == 404
        ],
        "haproxy_expected_200_actual_501": [
            entry for entry in entries if entry.get("connector") == "haproxy" and entry.get("expected_status") == 200 and entry.get("actual_status") == 501
        ],
        "nginx_actual_500": [entry for entry in entries if entry.get("connector") == "nginx" and entry.get("actual_status") == 500],
        "classification_incomplete": [entry for entry in entries if "classification incomplete" in json.dumps(entry).lower()],
    }
    return {
        name: {
            "label": label,
            "count": len(rows),
            "status": "REGRESSION" if rows else "clear",
            "cases": sorted({str(row.get("case_id", "-")) for row in rows})[:25],
        }
        for name, label in OLD_CLUSTER_CHECKS
        for rows in [checks[name]]
    }


def category_rollup(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {category: [] for category in FAILURE_CATEGORIES}
    for entry in entries:
        grouped[failure_category(entry)].append(entry)
    rows = []
    for category, items in grouped.items():
        connectors = sorted({str(entry.get("connector", "-")) for entry in items})
        rows.append(
            {
                "category": category,
                "count": len(items),
                "connectors": connectors,
                "typical_examples": [example_entry(grouped_entries) for grouped_entries in list(case_groups(items).values())[:3]],
                "fixable": fixability(category),
                "risk": risk(category),
                "recommended_next_step": recommended_step(category),
            }
        )
    rows.sort(key=lambda item: (-item["count"], item["category"]))
    return rows


def fixability(category: str) -> str:
    return {
        "intervention_blocking": "partly fixable; first split true connector gaps from future/native semantic cases",
        "collection_name_normalization_semantics": "metadata-only semantic split; needs native/libmodsecurity comparison before any fix",
        "phase4_no_hard_abort_required": "classification-only; control/pass row does not require a hard abort and does not prove capability support",
        "phase4_hard_abort_evidence": "evidence-backed; preserve strict hard-abort proof while stabilizing variants",
        "phase4_connection_aborted": "evidence-backed transport outcome",
        "phase4_log_only_no_abort": "report-only unless the case is meant to exercise strict hard abort",
        "phase4_truncated_not_accepted": "not sufficient for PASS promotion without transport-abort proof",
        "phase4_missing_abort_evidence": "fixable only through real strict abort/log evidence, not status-only changes",
        "phase4_connector_gap": "connector capability gap unless a real abort mechanism is implemented and evidenced",
        "phase4_native_semantics": "native semantics evidence only; keep separate from connector Full-Matrix PASS/FAIL",
        "nolog_expected_no_audit": "classification-only; nolog/pass rule is absent from audit evidence and CRS noise is unrelated",
        "audit_log_evidence": "fixable if audit-log assertion path is wrong; otherwise report/classification-only",
        "request_body_processor": "possibly fixable after processor-specific triage",
        "xml_processor": "possibly fixable, but high risk without XML processor parity checks",
        "xml_processor_activation_missing": "classification-only; XML body exists but the fixture does not enable the XML request body processor",
        "multipart_processor_activation_missing": "classification-only; multipart body and boundary exist but the fixture does not enable request body access before expecting FILES/ARGS_NAMES collections",
        "multipart_files": "possibly fixable; likely connector/body parser evidence work",
        "transformation_semantics": "not a harness quick win; needs semantic comparison against libmodsecurity expectations",
        "rule_chain_semantics": "small but semantic; requires focused rule-chain evidence",
        "response_header_backend_setup": "likely harness/backend fix; add deterministic target response headers before judging connector parity",
        "response_header_multi_value_gap": "connector/hook gap; HAProxy Set-Cookie multi-value exposure needs focused evidence or implementation work",
        "response_header_mrts_detection_only": "classification-only; with-MRTS DetectionOnly overlay suppresses disruptive action",
        "secaction_detection_only_overlay": "classification-only; with-MRTS DetectionOnly overlay makes disruptive SecAction rules non-blocking",
        "with_mrts_detection_only_non_disruptive": "classification-only; with-MRTS DetectionOnly overlay makes disruptive request-side rules non-blocking",
        "response_header_hook": "possible connector/hook work; start with response-header capture evidence",
        "harness_evidence_issue": "likely quick win if evidence files/log matching are missing",
    }.get(category, "unknown; review required")


def risk(category: str) -> str:
    return {
        "harness_evidence_issue": LOW_TO_MEDIUM_RISK,
        "audit_log_evidence": LOW_TO_MEDIUM_RISK,
        "response_header_backend_setup": LOW_TO_MEDIUM_RISK,
        "response_header_multi_value_gap": "medium",
        "response_header_mrts_detection_only": "low; report-only if kept separate from PASS promotion",
        "secaction_detection_only_overlay": "low; report-only and not a connector blocking bug",
        "with_mrts_detection_only_non_disruptive": "low; report-only and not a connector blocking bug",
        "response_header_hook": "medium",
        "request_body_processor": "medium",
        "multipart_files": "medium",
        "xml_processor": MEDIUM_TO_HIGH_RISK,
        "xml_processor_activation_missing": "low if kept report-only; high if treated as connector runtime evidence",
        "multipart_processor_activation_missing": "low if kept report-only; high if treated as connector multipart runtime evidence",
        "intervention_blocking": MEDIUM_TO_HIGH_RISK,
        "collection_name_normalization_semantics": MEDIUM_TO_HIGH_RISK,
        "transformation_semantics": "high",
        "phase4_no_hard_abort_required": "low",
        "phase4_hard_abort_evidence": "medium; keep strict/test-only semantics scoped",
        "phase4_connection_aborted": "medium; transport-level evidence is connector-specific",
        "phase4_log_only_no_abort": "low if reported honestly, high if promoted as hard abort",
        "phase4_truncated_not_accepted": "high if treated as hard abort",
        "phase4_missing_abort_evidence": "high if promoted without transport proof",
        "phase4_connector_gap": "high if faked; low if reported as gap",
        "phase4_native_semantics": "low if kept separate",
        "nolog_expected_no_audit": "low; no runtime or expected-status change",
        "rule_chain_semantics": "medium",
    }.get(category, "unknown")


def recommended_step(category: str) -> str:
    return {
        "harness_evidence_issue": "inspect `tfn_chain_lowercase_trim_pass_through` evidence generation; verify whether actual_status 0 means missing result or real transport failure",
        "audit_log_evidence": "inspect `v3_action_nolog_pass_no_audit` audit expectation and report classification",
        "response_header_backend_setup": "add deterministic response headers to the Apache/NGINX harness/backend probes, then rerun targeted Phase 3 response-header cases",
        "response_header_multi_value_gap": "triage HAProxy Set-Cookie multi-value exposure through SPOE response-header evidence",
        "response_header_mrts_detection_only": "keep with-MRTS DetectionOnly rows classification-only; do not promote to PASS without disruptive runtime evidence",
        "secaction_detection_only_overlay": "keep with-MRTS SecAction DetectionOnly rows classification-only; no connector fix while no-MRTS/native controls block",
        "with_mrts_detection_only_non_disruptive": "keep with-MRTS request-side DetectionOnly rows report-only; continue intervention analysis on no-MRTS no-match cases",
        "collection_name_normalization_semantics": "compare collection-name normalization semantics against native/libmodsecurity before treating as a runtime fix",
        "response_header_hook": "triage response-header phase 3 capture on Apache/NGINX first, then HAProxy",
        "request_body_processor": "split JSON, URL-encoded, and XML body processor cases before code changes",
        "multipart_files": "compare multipart variable population across connectors with one representative request",
        "xml_processor": "verify XML processor enablement and malformed XML semantics",
        "xml_processor_activation_missing": "keep XML processor activation-missing rows report-only; do not change rules or Expected statuses",
        "multipart_processor_activation_missing": "keep Multipart processor activation-missing rows report-only; do not change bodies, rules, or Expected statuses",
        "intervention_blocking": "sample high-count expected 403 -> actual 200 cases and decide semantic gap vs stale promoted expectation",
        "transformation_semantics": "compare transformation-chain cases against native/libmodsecurity evidence before attempting fixes",
        "phase4_no_hard_abort_required": "keep as context/control evidence; do not promote as hard-abort support",
        "phase4_hard_abort_evidence": "preserve NGINX strict hard-abort proof and stabilize MRTS-enabled variants",
        "phase4_connection_aborted": "preserve transport-abort evidence and do not replace it with status-only assertions",
        "phase4_log_only_no_abort": "keep minimal/safe/content-type rows as log-only, not hard-abort PASS evidence",
        "phase4_truncated_not_accepted": "collect transport-abort proof or keep as non-promoted",
        "phase4_missing_abort_evidence": "add real Phase 4 intervention log plus connection-abort evidence before promotion",
        "phase4_connector_gap": "document connector gap unless implementation can prove a real hard abort",
        "phase4_native_semantics": "keep native MRTS result separate from connector Full-Matrix work",
        "nolog_expected_no_audit": "keep as classification-only evidence; do not add artificial audit logs",
        "rule_chain_semantics": "single-case rule-chain triage with logs",
    }.get(category, "manual review")


def priority_plan(entries: list[dict[str, Any]], categories: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    regressions = old_cluster_regressions(entries)
    single_connector_runtime_fixable = runtime_fixable_single_connector_entries(entries)
    plan: dict[str, list[dict[str, Any]]] = {"P0": [], "P1": [], "P2": [], "P3": [], "P4": []}
    for name, data in regressions.items():
        if data["count"]:
            plan["P0"].append(
                {
                    "cluster_name": name,
                    "count": data["count"],
                    "connector": "mixed",
                    "why": "previously resolved cluster reappeared",
                    "likely_change": "stop and triage regression before new work",
                    "risk": "high",
                    "tests": ["regenerate full matrix", "targeted smoke for affected connector"],
                }
            )
    plan["P1"].extend(
        [
            {
                "cluster_name": "harness_evidence_issue / tfn_chain_lowercase_trim_pass_through",
                "count": sum(1 for entry in entries if failure_category(entry) == "harness_evidence_issue"),
                "connector": PRIMARY_CONNECTORS,
                "why": "small, clear evidence-missing/actual_status 0 cluster; safest quick-win candidate",
                "likely_change": "inspect result creation/log matching for the transformation pass-through case; report-only or harness evidence fix if confirmed",
                "risk": LOW_TO_MEDIUM_RISK,
                "tests": ["targeted smoke for the case on all connectors", "make lint quick-check", "make full-matrix-parallel if harness behavior changes"],
            },
            {
                "cluster_name": "audit_log_evidence / v3_action_nolog_pass_no_audit",
                "count": sum(1 for entry in entries if failure_category(entry) == "audit_log_evidence"),
                "connector": PRIMARY_CONNECTORS,
                "why": "HTTP behavior passes; remaining failure is evidence/assertion semantics",
                "likely_change": "verify whether audit-log expectation is correct for nolog and classify/report accordingly",
                "risk": LOW_TO_MEDIUM_RISK,
                "tests": ["targeted smoke for v3_action_nolog_pass_no_audit", "make lint quick-check"],
            },
        ]
    )
    plan["P2"].extend(
        [
            {
                "cluster_name": "response_header_backend_setup",
                "count": next((item["count"] for item in categories if item["category"] == "response_header_backend_setup"), 0),
                "connector": "apache, nginx",
                "why": "specialized Phase 3 response-header probes need deterministic backend headers before connector behavior can be judged",
                "likely_change": "add or route deterministic Content-Type, Location, and Set-Cookie response headers in the harness/backend path",
                "risk": LOW_TO_MEDIUM_RISK,
                "tests": ["targeted response-header cases", "make smoke-apache", "make smoke-nginx"],
            },
            {
                "cluster_name": "response_header_multi_value_gap",
                "count": next((item["count"] for item in categories if item["category"] == "response_header_multi_value_gap"), 0),
                "connector": "haproxy",
                "why": "HAProxy proves response-header visibility for single-value controls but still misses Set-Cookie multi-value matches",
                "likely_change": "trace SPOE response-header argument population for repeated Set-Cookie values",
                "risk": "medium",
                "tests": ["targeted HAProxy Set-Cookie response-header cases", "make smoke-haproxy"],
            },
            {
                "cluster_name": "multipart_files",
                "count": next((item["count"] for item in categories if item["category"] == "multipart_files"), 0),
                "connector": PRIMARY_CONNECTORS,
                "why": "remaining active body-processor work is now multipart-only after URL-encoded and XML metadata splits",
                "likely_change": "compare multipart variable population across connectors with one representative request",
                "risk": "medium",
                "tests": ["targeted multipart cases", "connector smoke for touched connector", "full matrix if parser behavior changes"],
            },
        ]
    )
    plan["P3"].extend(
        [
            {
                "cluster_name": "phase4_hard_abort_capability",
                "count": sum(next((item["count"] for item in categories if item["category"] == category), 0) for category in PHASE4_HARD_ABORT_CATEGORIES),
                "connector": PRIMARY_CONNECTORS,
                "why": "Phase 4/RESPONSE_BODY now requires hard-abort evidence, not status-only denial",
                "likely_change": "stabilize NGINX strict evidence; classify Apache/HAProxy gaps until real transport abort evidence exists",
                "risk": "high if promoted prematurely or faked",
                "tests": ["phase4 hard-abort report regeneration", "targeted strict Phase 4 connector evidence", "native report regeneration"],
            },
            {
                "cluster_name": "transformation_semantics",
                "count": next((item["count"] for item in categories if item["category"] == "transformation_semantics"), 0),
                "connector": PRIMARY_CONNECTORS,
                "why": "largest semantic cluster; likely needs native/libmodsecurity comparison before any fix",
                "likely_change": "deeper semantic evidence, not harness routing",
                "risk": "high",
                "tests": ["targeted transformation cases", "native comparison where available"],
            },
        ]
    )
    plan["P4"].append(
        {
            "cluster_name": "rule_chain_semantics and small single-connector leftovers",
            "count": next((item["count"] for item in categories if item["category"] == "rule_chain_semantics"), 0) + len(top_case_groups(single_connector_runtime_fixable, cross_connector=False, limit=100)),
            "connector": "mostly nginx for connector-only leftovers",
            "why": "small connector-only leftovers after report-only and not-next groups are excluded",
            "likely_change": "focused per-case triage only when runtime-fixable evidence remains",
            "risk": LOW_TO_MEDIUM_RISK,
            "tests": ["targeted single-case smokes"],
        }
    )
    return {
        priority: [item for item in items if int(item.get("count") or 0) > 0]
        for priority, items in plan.items()
    }


def first_priority_item(plan: dict[str, list[dict[str, Any]]], *, excluded_clusters: set[str] | None = None) -> dict[str, Any] | None:
    excluded_clusters = excluded_clusters or set()
    for priority in ("P0", "P1", "P2", "P3", "P4"):
        items = plan.get(priority, [])
        for item in items:
            if str(item.get("cluster_name") or "") not in excluded_clusters:
                return item
    return None


def load_reports(root: Path) -> dict[str, dict[str, Any]]:
    return {
        "full_runtime_matrix": read_json(report_path_from_root(root, "full_runtime_matrix", "json")),
        "connector_work_queue": read_json(report_path_from_root(root, "connector_work_queue", "json")),
        "phase_work_queue": read_json(report_path_from_root(root, "phase_work_queue", "json")),
        "full_run_evidence": read_json(report_path_from_root(root, "full_run_evidence", "json")),
        "runtime_build_cache": read_json(report_path_from_root(root, "runtime_build_cache", "json")),
        "nginx_mrts_http500_cluster_analysis": read_json(report_path_from_root(root, "nginx_mrts_http500_cluster_analysis", "json")),
        "mrts_native_summary": read_json(report_path_from_root(root, "mrts_native_summary", "json")),
        "mrts_native_apache": read_json(report_path_from_root(root, "mrts_native_apache", "json")),
        "mrts_native_nginx": read_json(report_path_from_root(root, "mrts_native_nginx", "json")),
    }


def build_analysis(connector_root: Path) -> dict[str, Any]:
    report_dir = connector_root / REPORT_DIR
    reports = load_reports(report_dir)
    entries = reports["connector_work_queue"].get("entries", [])
    entries = [entry for entry in entries if isinstance(entry, dict)]
    failures = [entry for entry in entries if entry.get("runtime_status") == "FAIL"]
    categories = category_rollup(failures)
    by_connector = {connector: [entry for entry in failures if entry.get("connector") == connector] for connector in ("apache", "nginx", "haproxy")}
    mrt_failures = [entry for entry in failures if entry.get("mrts_corpus") not in (None, "", "none")]
    non_mrts_failures = [entry for entry in failures if entry.get("mrts_corpus") in (None, "", "none")]
    phase4 = [entry for entry in failures if failure_category(entry) in PHASE4_HARD_ABORT_CATEGORIES]
    intervention = [entry for entry in failures if entry.get("expected_status") == 403 and entry.get("actual_status") == 200]
    connector_only = top_case_groups(failures, cross_connector=False, limit=10)
    cross_connector = top_case_groups(failures, cross_connector=True, limit=10)
    analysis = {
        "generated_at": utc_now(),
        "report_kind": "remaining-full-matrix-failure-analysis",
        "source_reports": {
            name: reports[name].get("generated_at", "-")
            for name in reports
        },
        "summary": {
            "attempted": reports["full_runtime_matrix"].get("totals", {}).get("attempted", 0),
            "pass": reports["full_runtime_matrix"].get("totals", {}).get("pass", 0),
            "fail": reports["full_runtime_matrix"].get("totals", {}).get("fail", 0),
            "blocked": reports["full_runtime_matrix"].get("totals", {}).get("blocked", 0),
            "not_executable": reports["full_runtime_matrix"].get("totals", {}).get("not_executable", 0),
            "pending": reports["full_runtime_matrix"].get("totals", {}).get("pending", 0),
            "unique_failure_cases": len(case_groups(failures)),
            "mrt_imported_failures": len(mrt_failures),
            "non_mrts_framework_failures": len(non_mrts_failures),
        },
        "native_evidence": {
            "separate_from_connector_full_matrix": True,
            "apache": {
                "status": reports["mrts_native_apache"].get("status"),
                "counts": reports["mrts_native_apache"].get("counts", {}),
                "known_fail": reports["mrts_native_apache"].get("first_failing_cases", [{}])[0] if reports["mrts_native_apache"].get("first_failing_cases") else {},
            },
            "nginx": {
                "status": reports["mrts_native_nginx"].get("status"),
                "counts": reports["mrts_native_nginx"].get("counts", {}),
                "known_fail": reports["mrts_native_nginx"].get("first_failing_cases", [{}])[0] if reports["mrts_native_nginx"].get("first_failing_cases") else {},
            },
        },
        "regression_checks": old_cluster_regressions(entries),
        "top_clusters": {
            "overall": top_clusters(failures, limit=10),
            "apache": top_clusters(by_connector["apache"], include_connector=True, limit=10),
            "nginx": top_clusters(by_connector["nginx"], include_connector=True, limit=10),
            "haproxy": top_clusters(by_connector["haproxy"], include_connector=True, limit=10),
            "cross_connector_failures": cross_connector,
            "connector_only_failures": connector_only,
            "mrts_imported_failures": top_clusters(mrt_failures, limit=10),
            "non_mrts_framework_failures": top_clusters(non_mrts_failures, limit=10),
            "phase4_response_body_failures": top_clusters(phase4, limit=10),
            "intervention_blocking_failures": top_clusters(intervention, limit=10),
        },
        "category_rollup": categories,
    }
    analysis["priority_plan"] = priority_plan(failures, categories)
    nginx_http500 = reports.get("nginx_mrts_http500_cluster_analysis", {})
    http500_count = int((nginx_http500.get("summary") or {}).get("http500_failures") or 0)
    if http500_count > 0 and nginx_http500.get("primary_blocker") == "nginx_with_crs_with_mrts_http500_cluster":
        analysis["priority_plan"].setdefault("P0", [])
        analysis["priority_plan"]["P0"].insert(
            0,
            {
                "cluster_name": "nginx_with_crs_with_mrts_http500_cluster",
                "count": http500_count,
                "connector": "nginx",
                "why": "largest verified Full-Matrix blocker; all HTTP-500 rows share the /index.html redirect-cycle/docroot-permission signature",
                "likely_change": "move NGINX Full-Matrix harness roots out from under /root or block inaccessible worker docroots before runtime classification",
                "risk": "medium",
                "tests": ["targeted NGINX with-crs/with-mrts case", "make verified-full-matrix-job CONNECTOR=nginx CRS=with-crs MRTS=with-mrts"],
            },
        )
    not_next = [dict(item) for item in NOT_NEXT_RECOMMENDATIONS]
    recommended = first_priority_item(
        analysis["priority_plan"],
        excluded_clusters={str(item["cluster"]) for item in not_next},
    )
    analysis["recommendation"] = {
        "recommended_next_fix_cluster": recommended.get("cluster_name") if recommended else "none",
        "reason": recommended.get("why") if recommended else "No remaining runtime-fixable connector Full-Matrix cluster is recommended after report-only and not-next filters.",
        "not_next": not_next,
    }
    return analysis


def md_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(item).replace("|", "\\|") for item in row) + " |")
    return lines


def cluster_rows(clusters: list[dict[str, Any]]) -> list[list[Any]]:
    rows = []
    for cluster in clusters:
        example = cluster.get("examples", [{}])[0]
        rows.append(
            [
                cluster.get("count", 0),
                cluster.get("cluster_name", "-"),
                ", ".join(cluster.get("connectors", [])) or "-",
                ", ".join(cluster.get("variants", [])) or "-",
                cluster.get("classification", "-"),
                ", ".join(cluster.get("work_direction", [])) or "-",
                example.get("case_id", "-"),
                example.get("rule_id", "-"),
                example.get("variable", "-"),
            ]
        )
    return rows


def case_rows(cases: list[dict[str, Any]]) -> list[list[Any]]:
    return [
        [
            item.get("count", 0),
            item.get("case_id", "-"),
            ", ".join(item.get("connectors", [])) or "-",
            ", ".join(item.get("variants", [])) or "-",
            item.get("category", "-"),
            item.get("status_pairs", {}),
            item.get("example", {}).get("rule_id", "-"),
            item.get("example", {}).get("variable", "-"),
        ]
        for item in cases
    ]


def render_analysis_markdown(analysis: dict[str, Any]) -> str:
    summary = analysis["summary"]
    lines = [
        "# Remaining Full-Matrix Failure Analysis",
        "",
        f"Generated at: `{analysis['generated_at']}`",
        "",
        "## Scope",
        "- Connector Full-Matrix evidence is separate from Native MRTS infrastructure evidence.",
        "- Native Apache/NGINX evidence is reported in the `mrts-native-*` reports and does not replace connector PASS/FAIL values.",
        "- Native `100003-1` remains classified as `native_modsecurity_semantics / phase4_native_limitation`.",
        "- This report is analysis-only; runtime PASS/FAIL and expected statuses are not changed by classification metadata.",
        "",
        "## Summary",
        f"- Attempted/pass/fail/blocked/not executable: **{summary['attempted']} / {summary['pass']} / {summary['fail']} / {summary['blocked']} / {summary['not_executable']}**",
        f"- Pending metadata rows observed: **{summary['pending']}**",
        f"- Unique remaining failure cases: **{summary['unique_failure_cases']}**",
        f"- MRTS imported connector failures: **{summary['mrt_imported_failures']}**",
        f"- Non-MRTS framework failures: **{summary['non_mrts_framework_failures']}**",
        "",
        "## Regression Checks",
    ]
    lines.extend(
        md_table(
            ["Check", "Status", "Count", "Cases"],
            [
                [item["label"], item["status"], item["count"], ", ".join(item["cases"]) or "-"]
                for item in analysis["regression_checks"].values()
            ],
        )
    )
    lines.extend(["", "## Category Rollup"])
    lines.extend(
        md_table(
            ["Category", "Count", "Connectors", "Fixable", "Risk", "Next step"],
            [
                [
                    item["category"],
                    item["count"],
                    ", ".join(item["connectors"]) or "-",
                    item["fixable"],
                    item["risk"],
                    item["recommended_next_step"],
                ]
                for item in analysis["category_rollup"]
                if item["count"]
            ],
        )
    )
    section_titles = [
        ("overall", "Top 10 Overall Failure Clusters"),
        ("apache", "Top 10 Apache Clusters"),
        ("nginx", "Top 10 NGINX Clusters"),
        ("haproxy", "Top 10 HAProxy Clusters"),
        ("mrts_imported_failures", "Top MRTS Imported Failures"),
        ("non_mrts_framework_failures", "Top Non-MRTS Framework Failures"),
        ("phase4_response_body_failures", "Top Phase4 / Response-Body Failures"),
        ("intervention_blocking_failures", "Top Intervention / Blocking Failures"),
    ]
    for key, title in section_titles:
        lines.extend(["", f"## {title}"])
        clusters = analysis["top_clusters"][key]
        if not clusters:
            lines.append(NO_ROWS_MARKER)
        else:
            lines.extend(md_table(["Count", "Cluster", "Connectors", "Variants", "Classification", "Work direction", "Example", RULE_ID_HEADER, VARIABLE_TARGET_HEADER], cluster_rows(clusters)))
    lines.extend(["", "## Top Cross-Connector Failures"])
    lines.extend(md_table(["Count", "Case", "Connectors", "Variants", "Category", "Status pairs", RULE_ID_HEADER, VARIABLE_TARGET_HEADER], case_rows(analysis["top_clusters"]["cross_connector_failures"])))
    lines.extend(["", "## Top Connector-Only Failures"])
    connector_only = analysis["top_clusters"]["connector_only_failures"]
    if connector_only:
        lines.extend(md_table(["Count", "Case", "Connectors", "Variants", "Category", "Status pairs", RULE_ID_HEADER, VARIABLE_TARGET_HEADER], case_rows(connector_only)))
    else:
        lines.append(NO_ROWS_MARKER)
    lines.extend(["", "## Recommendation"])
    rec = analysis["recommendation"]
    lines.append(f"- Empfohlener nächster Fix-Cluster: `{rec['recommended_next_fix_cluster']}`")
    lines.append(f"- Begründung: {rec['reason']}")
    for item in rec["not_next"]:
        lines.append(f"- Nicht als nächstes bearbeiten: `{item['cluster']}`, weil {item['reason']}.")
    return "\n".join(lines) + "\n"


def render_plan_markdown(plan: dict[str, Any], generated_at: str, recommendation: dict[str, Any] | None = None) -> str:
    lines = [
        "# Next Fix Plan",
        "",
        f"Generated at: `{generated_at}`",
        "",
        "Native MRTS Apache/NGINX remains separate infrastructure evidence; this plan targets connector Full-Matrix leftovers only.",
    ]
    if recommendation:
        lines.extend(
            [
                "",
                "## Recommendation",
                f"- Empfohlener nächster Fix-Cluster: `{recommendation['recommended_next_fix_cluster']}`",
                f"- Begründung: {recommendation['reason']}",
            ]
        )
        for item in recommendation.get("not_next", []):
            lines.append(f"- Nicht als nächstes bearbeiten: `{item['cluster']}`, weil {item['reason']}.")
    for priority in ("P0", "P1", "P2", "P3", "P4"):
        lines.extend(["", f"## {priority}"])
        items = plan.get(priority, [])
        if not items:
            lines.append(NO_ROWS_MARKER)
            continue
        lines.extend(
            md_table(
                ["Cluster", "Count", "Connector", "Why", "Likely change", "Risk", "Tests"],
                [
                    [
                        item["cluster_name"],
                        item["count"],
                        item["connector"],
                        item["why"],
                        item["likely_change"],
                        item["risk"],
                        ", ".join(item["tests"]),
                    ]
                    for item in items
                ],
            )
        )
    return "\n".join(lines) + "\n"


def update_full_run_evidence(report_dir: Path, connector_root: Path) -> None:
    json_path = report_path_from_root(report_dir, "full_run_evidence", "json")
    generated_at = utc_now()
    data = read_json(json_path) or {
        "report_kind": "full-run-evidence",
        "reports": [],
        "notes": ["Evidence rollup created by remaining-failure-analysis because no categorized rollup existed yet."],
    }
    for stale_key in (
        "status",
        "reason",
        "empty_reason",
        "report_key",
        "report_name",
        "rows",
        "command",
        "generator",
        "make_target",
    ):
        data.pop(stale_key, None)
    data["status"] = "generated"
    data["report_kind"] = "full-run-evidence"
    data["generated_at"] = generated_at
    data["verified_run_id"] = current_verified_run_id(connector_root)
    data["remaining_failure_analysis_reports"] = {
        "analysis": report_relpath("remaining_failure_analysis", "md"),
        "next_fix_plan": report_relpath("next_fix_plan", "md"),
        "phase4_hard_abort_capability": report_relpath("phase4_hard_abort_capability", "md"),
        "nolog_audit_evidence": report_relpath("nolog_audit_evidence", "md"),
        "response_header_hook_analysis": report_relpath("response_header_hook_analysis", "md"),
    }
    reports = data.get("reports")
    if not isinstance(reports, list):
        reports = []
    for report in (
        report_relpath("remaining_failure_analysis", "json"),
        report_relpath("remaining_failure_analysis", "md"),
        report_relpath("next_fix_plan", "json"),
        report_relpath("next_fix_plan", "md"),
        report_relpath("phase4_hard_abort_capability", "json"),
        report_relpath("phase4_hard_abort_capability", "md"),
        report_relpath("nolog_audit_evidence", "json"),
        report_relpath("nolog_audit_evidence", "md"),
        report_relpath("response_header_hook_analysis", "json"),
        report_relpath("response_header_hook_analysis", "md"),
    ):
        if report not in reports:
            reports.append(report)
    data["reports"] = reports
    metadata = build_metadata(
        generated_by=GENERATOR_PATH,
        make_target="generate-remaining-failure-analysis",
        connector_root=connector_root,
        inputs=SOURCE_REPORT_INPUTS[:3],
        generated_at=generated_at,
    )
    write_text_file(json_path, generated_json_text(data, metadata))

    md_path = report_path_from_root(report_dir, "full_run_evidence", "md")
    text = read_text(md_path)
    if not text:
        text = "# Full Run Evidence\n\nGenerated file - do not edit manually.\n"
    if text:
        lines = [
            "## Remaining Failure Analysis",
            f"- Remaining failure analysis: `{report_relpath('remaining_failure_analysis', 'md')}`",
            f"- Next fix plan: `{report_relpath('next_fix_plan', 'md')}`",
            f"- Phase 4 hard-abort capability: `{report_relpath('phase4_hard_abort_capability', 'md')}`",
            f"- Nolog audit evidence: `{report_relpath('nolog_audit_evidence', 'md')}`",
            f"- Response header hook analysis: `{report_relpath('response_header_hook_analysis', 'md')}`",
            "- These reports analyze connector Full-Matrix leftovers and keep Native MRTS evidence separate.",
        ]
        section = "\n".join(lines)
        start = "<!-- remaining-failure-analysis:start -->"
        end = "<!-- remaining-failure-analysis:end -->"
        text = upsert_marked_section(
            text,
            start=start,
            end=end,
            section=section,
            insert_before="## Reports And Logs",
        )
        write_text_file(md_path, generated_markdown_text(text, metadata))


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
    analysis = build_analysis(connector_root)
    plan = {
        "generated_at": analysis["generated_at"],
        "report_kind": "next-fix-plan",
        "priority_plan": analysis["priority_plan"],
        "recommendation": analysis["recommendation"],
    }
    analysis_metadata = build_metadata(
        generated_by=GENERATOR_PATH,
        make_target="generate-remaining-failure-analysis",
        connector_root=connector_root,
        inputs=SOURCE_REPORT_INPUTS,
        generated_at=analysis["generated_at"],
    )
    plan_metadata = build_metadata(
        generated_by=GENERATOR_PATH,
        make_target="generate-remaining-failure-analysis",
        connector_root=connector_root,
        inputs=[report_relpath("remaining_failure_analysis", "json")],
        generated_at=plan["generated_at"],
    )
    analysis_json = report_path_from_root(output_dir, "remaining_failure_analysis", "json")
    analysis_md = report_path_from_root(output_dir, "remaining_failure_analysis", "md")
    plan_json = report_path_from_root(output_dir, "next_fix_plan", "json")
    plan_md = report_path_from_root(output_dir, "next_fix_plan", "md")
    write_text_file(analysis_json, generated_json_text(analysis, analysis_metadata))
    write_text_file(analysis_md, generated_markdown_text(render_analysis_markdown(analysis), analysis_metadata))
    write_text_file(plan_json, generated_json_text(plan, plan_metadata))
    write_text_file(plan_md, generated_markdown_text(render_plan_markdown(plan["priority_plan"], plan["generated_at"], plan["recommendation"]), plan_metadata))
    update_full_run_evidence(output_dir, connector_root)
    print(analysis_md)
    print(plan_md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
