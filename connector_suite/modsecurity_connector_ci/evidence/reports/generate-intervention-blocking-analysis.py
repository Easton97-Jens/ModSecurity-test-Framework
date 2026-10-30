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

from modsecurity_connector_ci.lib.focused_analysis_utils import action_parts, action_value, as_list, log_paths, read_json, read_text, utc_now, write_json
from modsecurity_connector_ci.lib.generated_report_utils import GENERATED_ROOT, build_metadata, generated_json_text, generated_markdown_text, report_path, report_path_from_root, report_relpath
from modsecurity_connector_ci.lib.report_path_safety import add_report_roots, add_safe_roots, resolve_output_dir, safe_existing_file, write_text_file

try:
    import yaml
except Exception:  # pragma: no cover - report generation still has a regex fallback.
    yaml = None


REPORT_DIR = GENERATED_ROOT
ABSOLUTE_RUNTIME_PATH_RE = re.compile(r"(?<![\w.-])/(?:tmp|root|src)[^\s\"']*")
STRICT_LOAD_ERROR_RE = re.compile(
    r"Rules error|Error parsing|Failed to load|Invalid input|AH00526|modsecurity_rules_file.*failed|Could not open",
    re.IGNORECASE,
)
WITH_MRTS_DETECTION_ONLY_CLASSIFICATION = "with_mrts_detection_only_non_disruptive"
SMOKE_RULES_RELATIVE_PATH = "conf/modsecurity-smoke.conf"
NO_MRTS_NOMATCH_SEMANTIC_CLASSIFICATIONS = {
    "transformation_request_literal_no_match",
    "collection_name_normalization_semantics",
    "xml_body_processor_collection_semantics",
    "multipart_collection_semantics",
    "phase1_request_body_unavailable",
}


GROUPS = {
    "A": "Rule not loaded",
    "B": "Rule loaded, no match",
    "C": "Rule matched, no intervention created",
    "D": "Intervention created, connector did not set 403",
    "E": "Intervention created, runner/evidence missed it",
    "F": "Expected block, but effective runtime is non-disruptive",
    "G": "CRS changed behavior",
    "H": "Connector-specific blocking gap",
}


def sanitize_report_text(value: Any) -> str:
    return ABSOLUTE_RUNTIME_PATH_RE.sub("<evidence-path>", str(value or ""))


def display_case_path(value: Any, framework_root: Path) -> str:
    if not value:
        return "-"
    path = safe_existing_file(value)
    if path is None:
        return sanitize_report_text(str(value).replace("\\", "/").rstrip("/").split("/")[-1] or "-")
    try:
        return "framework:" + str(path.resolve(strict=False).relative_to(framework_root.resolve(strict=False)))
    except ValueError:
        return sanitize_report_text(path.name)


def first_value(*values: Any) -> str:
    for value in values:
        text = str(value or "")
        if text and text not in {"-", "None", "none", "null"}:
            return text
    return "-"


def parse_rule_candidates(rules: str) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    pattern = re.compile(
        r"\b(SecRule|SecAction)\b\s+"
        r"(?:(?P<target>[^\s\"]+)\s+\"(?P<operator>[^\"]*)\"\s+)?"
        r"(?:\\\s*)?\"(?P<actions>[^\"]+)\"",
        re.DOTALL,
    )
    for match in pattern.finditer(rules):
        action_text = re.sub(r"\s+", " ", match.group("actions")).strip()
        actions = action_parts(action_text)
        rule_id = action_value(actions, "id")
        phase = action_value(actions, "phase")
        transformations = []
        for action in actions:
            if action.lower().startswith("t:"):
                transformations.append(action.split(":", 1)[1])
        candidates.append(
            {
                "kind": match.group(1),
                "rule_id": str(rule_id),
                "phase": phase,
                "target": match.group("target") or "-",
                "operator": match.group("operator") or "-",
                "actions": actions,
                "transformations": transformations,
                "rule_excerpt": sanitize_report_text(re.sub(r"\s+", " ", match.group(0)).strip()),
            }
        )
    return candidates


def load_intervention_case(path: Path | None) -> tuple[str, dict[str, Any]]:
    raw = read_text(path) if path is not None and path.is_file() else ""
    if not raw or yaml is None:
        return raw, {}
    try:
        loaded = yaml.safe_load(raw)
    except Exception:
        return raw, {}
    return raw, loaded if isinstance(loaded, dict) else {}


def fallback_intervention_rule(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "rule_id": "-",
        "phase": str(entry.get("phase") or "-"),
        "target": "-",
        "operator": "-",
        "actions": [],
        "transformations": [],
        "rule_excerpt": "-",
    }


def selected_intervention_rule(
    rule_candidates: list[dict[str, Any]], expected_rule_id: str, entry: dict[str, Any]
) -> dict[str, Any]:
    if expected_rule_id:
        selected = next((item for item in rule_candidates if item["rule_id"] == expected_rule_id), None)
        if selected is not None:
            return selected
    return next(
        (item for item in reversed(rule_candidates) if item["rule_id"] != "-"),
        fallback_intervention_rule(entry),
    )


def request_path_and_query(request: dict[str, Any]) -> tuple[str, str]:
    request_path = str(request.get("path") or "-")
    if "?" not in request_path:
        return request_path, "-"
    path, query = request_path.split("?", 1)
    return path or "/", query


def limitation_classification(known_limitations: list[str]) -> str:
    for item in known_limitations:
        match = re.search(r"Classification:\s*([^.\s]+)", item)
        if match:
            return match.group(1)
    return "-"


def case_metadata(entry: dict[str, Any], evidence: dict[str, Any], framework_root: Path) -> dict[str, Any]:
    case_path = safe_existing_file(evidence.get("path"))
    raw, parsed = load_intervention_case(case_path)
    request = parsed.get("request") if isinstance(parsed.get("request"), dict) else {}
    expect = parsed.get("expect") if isinstance(parsed.get("expect"), dict) else {}
    rules = str(parsed.get("rules") or raw)
    rules = sanitize_report_text(rules)
    rule_candidates = parse_rule_candidates(rules)
    expected_rule_id = str(expect.get("rule_id") or "")
    selected_rule = selected_intervention_rule(rule_candidates, expected_rule_id, entry)
    path, query = request_path_and_query(request)
    headers = request.get("headers") if isinstance(request.get("headers"), dict) else {}
    body = str(request.get("body") or "")
    known_limitations = as_list(parsed.get("known_limitations"))
    return {
        "case_path": display_case_path(case_path, framework_root),
        "method": str(request.get("method") or "-"),
        "path": path,
        "query": query,
        "body_present": bool(body),
        "content_type": first_value(headers.get("Content-Type"), headers.get("content-type")),
        "expected_intervention": str(expect.get("intervention") or evidence.get("expected_intervention") or "-"),
        "expected_rule_id": first_value(expected_rule_id, selected_rule.get("rule_id")),
        "rule_id": str(selected_rule.get("rule_id") or "-"),
        "phase": str(selected_rule.get("phase") or entry.get("phase") or "-"),
        "target": str(selected_rule.get("target") or "-"),
        "operator": str(selected_rule.get("operator") or "-"),
        "actions": selected_rule.get("actions") or [],
        "transformations": selected_rule.get("transformations") or [],
        "rule_excerpt": selected_rule.get("rule_excerpt") or "-",
        "rules": rules,
        "rule_ids": [item["rule_id"] for item in rule_candidates if item["rule_id"] != "-"],
        "known_limitations": known_limitations,
        "source_classification": limitation_classification(known_limitations),
    }


def evidence_path(entry: dict[str, Any]) -> Path | None:
    return safe_existing_file(entry.get("evidence") or entry.get("evidence_path"))


def generated_config_path(entry: dict[str, Any], evidence_file: Path | None) -> Path | None:
    if evidence_file is None:
        return None
    case_id = str(entry.get("case_id") or evidence_file.parent.name)
    connector = str(entry.get("connector") or "")
    log_dir = evidence_file.parent
    try:
        if connector == "nginx":
            run_root = log_dir.parent.parent
            return run_root / "runtime" / case_id / SMOKE_RULES_RELATIVE_PATH
        if connector == "apache":
            connector_run_root = log_dir.parent.parent.parent
            return connector_run_root / "apache-runtime" / case_id / SMOKE_RULES_RELATIVE_PATH
        if connector == "haproxy":
            connector_run_root = log_dir.parent.parent.parent
            return connector_run_root / "haproxy-runtime-cases" / case_id / SMOKE_RULES_RELATIVE_PATH
    except IndexError:
        return None
    return None


def rule_logged(logs: str, rule_id: str) -> bool:
    if not rule_id or rule_id == "-":
        return False
    patterns = [
        r'\[id "' + re.escape(rule_id) + r'"\]',
        r'"rule_id"\s*:\s*"?' + re.escape(rule_id) + r'"?',
        r"\brule_id=" + re.escape(rule_id) + r"\b",
        r"\bid:" + re.escape(rule_id) + r"\b",
    ]
    return any(re.search(pattern, logs) for pattern in patterns)


def observed_disruptive_intervention(logs: str, rule_id: str) -> bool:
    if not rule_logged(logs, rule_id):
        return False
    return bool(
        re.search(r"Access denied", logs, re.IGNORECASE)
        or re.search(r'"decision"\s*:\s*"deny"', logs)
        or re.search(r'"disruptive"\s*:\s*true', logs)
        or re.search(r'"intervention_status"\s*:\s*403', logs)
    )


def backend_reached(entry: dict[str, Any], evidence: dict[str, Any]) -> bool:
    if entry.get("actual_status") == 200:
        return True
    body_path = evidence.get("response_body_path")
    return "TEST-OK-IF-YOU-SEE-THIS" in read_text(body_path) if body_path else False


def decision_summary(logs: str) -> dict[str, Any]:
    decisions: list[dict[str, Any]] = []
    for line in logs.splitlines():
        if not line.startswith("{"):
            continue
        try:
            loaded = json.loads(line)
        except Exception:
            continue
        if isinstance(loaded, dict) and ("decision" in loaded or "disruptive" in loaded):
            decisions.append(loaded)
    if not decisions:
        return {"decision_entries": 0}
    disruptive = sum(1 for row in decisions if row.get("disruptive") is True or row.get("decision") == "deny")
    rule_ids = sorted({str(row.get("rule_id")) for row in decisions if str(row.get("rule_id") or "0") != "0"})
    return {
        "decision_entries": len(decisions),
        "disruptive_decisions": disruptive,
        "decision_rule_ids": rule_ids,
        "last_decision": str(decisions[-1].get("decision") or "-"),
        "last_intervention_status": decisions[-1].get("intervention_status"),
    }


def classify_record(record: dict[str, Any]) -> tuple[str, str, str, str]:
    if not record["rule_in_loadfile"] or record["strict_load_errors"]:
        return (
            "A",
            "Rule-load evidence is missing or startup logs show a strict rule-load error.",
            "fixable if generated loadfile path is wrong",
            "low to medium",
        )
    if record["classification"] == WITH_MRTS_DETECTION_ONLY_CLASSIFICATION or record["mrts_variant"] == "with-mrts":
        return (
            "F",
            "with-MRTS loads MRTS INIT, which sets ctl:ruleEngine=DetectionOnly; disruptive actions are intentionally non-blocking in this overlay.",
            "classification/report-only unless the MRTS overlay policy changes",
            "low for report-only, high if expectations are changed",
        )
    if not record["rule_matched"]:
        return (
            "B",
            "The rule is present and no strict load error is visible, but no target rule hit appears in logs or HAProxy decisions.",
            "not a safe intervention fix; requires semantic/native comparison",
            "medium to high",
        )
    if not record["intervention_created"]:
        return (
            "C",
            "The target rule matched, but no disruptive intervention evidence was produced.",
            "needs targeted ModSecurity/connector semantics analysis before code changes",
            "high",
        )
    if not record["connector_set_403"]:
        return (
            "D",
            "A disruptive intervention is visible, but the connector still returned 200.",
            "potentially fixable in connector intervention forwarding",
            "medium",
        )
    return (
        "E",
        "A disruptive status is visible in evidence but the runner recorded a different status.",
        "potentially fixable in evidence/status capture",
        "medium",
    )


def build_records(connector_root: Path, framework_root: Path) -> list[dict[str, Any]]:
    queue = read_json(report_path(connector_root, "connector_work_queue", "json"))
    entries = [entry for entry in queue.get("entries", []) if isinstance(entry, dict)]
    selected = [
        entry
        for entry in entries
        if (
            "intervention_blocking" in as_list(entry.get("work_direction"))
            or entry.get("classification") == WITH_MRTS_DETECTION_ONLY_CLASSIFICATION
            or entry.get("classification") in NO_MRTS_NOMATCH_SEMANTIC_CLASSIFICATIONS
        )
        and entry.get("expected_status") == 403
        and entry.get("actual_status") == 200
    ]
    records: list[dict[str, Any]] = []
    for entry in selected:
        e_path = evidence_path(entry)
        evidence = read_json(e_path) if e_path is not None else {}
        meta = case_metadata(entry, evidence, framework_root)
        config_path = generated_config_path(entry, e_path)
        generated_config = read_text(config_path)
        logs = "\n".join(read_text(path) for path in log_paths(evidence))
        rule_id = str(meta["rule_id"])
        rule_in_loadfile = bool(rule_id != "-" and rule_id in generated_config)
        strict_load_errors = bool(STRICT_LOAD_ERROR_RE.search(logs))
        rule_matched = rule_logged(logs, rule_id)
        intervention_created = observed_disruptive_intervention(logs, rule_id)
        connector_set_403 = intervention_created and str(entry.get("actual_status")) == "403"
        decisions = decision_summary(logs)
        record = {
            "case_id": entry.get("case_id"),
            "connector": entry.get("connector"),
            "variant": f"{entry.get('test_variant')}/{entry.get('mrts_variant')}",
            "test_variant": entry.get("test_variant"),
            "mrts_variant": entry.get("mrts_variant"),
            "source_kind": entry.get("source_kind"),
            "source_category": entry.get("category"),
            "classification": entry.get("classification"),
            "priority": entry.get("priority", "-"),
            "work_direction": as_list(entry.get("work_direction")),
            "failure_pattern": as_list(entry.get("failure_pattern")),
            "expected_status": entry.get("expected_status"),
            "actual_status": entry.get("actual_status"),
            "method": meta["method"],
            "path": meta["path"],
            "query": meta["query"],
            "body_present": meta["body_present"],
            "content_type": meta["content_type"],
            "rule_id": rule_id,
            "phase": meta["phase"],
            "target": meta["target"],
            "operator": meta["operator"],
            "transformations": meta["transformations"],
            "actions": meta["actions"],
            "expected_intervention": meta["expected_intervention"],
            "case_path": meta["case_path"],
            "known_limitations": meta["known_limitations"],
            "source_classification": meta["source_classification"],
            "rule_in_loadfile": rule_in_loadfile,
            "strict_load_errors": strict_load_errors,
            "rule_loaded": rule_in_loadfile and not strict_load_errors,
            "rule_matched": rule_matched,
            "intervention_created": intervention_created,
            "connector_set_403": connector_set_403,
            "backend_reached": backend_reached(entry, evidence),
            "decision_entries": decisions.get("decision_entries", 0),
            "decision_rule_ids": decisions.get("decision_rule_ids", []),
            "disruptive_decisions": decisions.get("disruptive_decisions", 0),
            "last_decision": decisions.get("last_decision", "-"),
            "last_intervention_status": decisions.get("last_intervention_status"),
        }
        group, cause, fixability, risk = classify_record(record)
        record.update(
            {
                "group": group,
                "group_label": GROUPS[group],
                "suspected_cause": cause,
                "fixability": fixability,
                "risk": risk,
            }
        )
        records.append(record)
    return records


def grouped_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    groups: dict[str, Any] = {}
    records_by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        records_by_group[str(record["group"])].append(record)
    for group_id, label in GROUPS.items():
        items = records_by_group.get(group_id, [])
        connectors = sorted({str(item["connector"]) for item in items})
        variants = sorted({str(item["variant"]) for item in items})
        examples = [
            {
                "case_id": item["case_id"],
                "connector": item["connector"],
                "variant": item["variant"],
                "rule_id": item["rule_id"],
                "phase": item["phase"],
                "target": item["target"],
                "operator": item["operator"],
                "method": item["method"],
                "path": item["path"],
                "query": item["query"],
                "rule_loaded": item["rule_loaded"],
                "rule_matched": item["rule_matched"],
                "intervention_created": item["intervention_created"],
                "backend_reached": item["backend_reached"],
            }
            for item in items[:8]
        ]
        groups[group_id] = {
            "label": label,
            "count": len(items),
            "connectors": connectors,
            "variants": variants,
            "example_cases": examples,
            "suspected_cause": items[0]["suspected_cause"] if items else "-",
            "fixability": items[0]["fixability"] if items else "-",
            "risk": items[0]["risk"] if items else "-",
        }
    return groups


def safe_subcluster(records: list[dict[str, Any]]) -> dict[str, Any]:
    d_candidates = [item for item in records if item["group"] in {"D", "E"}]
    h_candidates = [item for item in records if item["group"] == "H"]
    if d_candidates:
        return {
            "selected": True,
            "name": "observed intervention status forwarding",
            "count": len(d_candidates),
            "reason": "disruptive intervention evidence exists while actual status stayed 200",
            "recommended_action": "target connector/evidence status forwarding",
        }
    if h_candidates:
        return {
            "selected": True,
            "name": "connector-specific blocking gap",
            "count": len(h_candidates),
            "reason": "a connector-specific blocking gap is isolated",
            "recommended_action": "investigate only that connector",
        }
    return {
        "selected": False,
        "name": "none",
        "count": 0,
        "reason": "no row shows a real disruptive intervention that is later lost by connector or runner",
        "recommended_action": "do not edit connector/core code yet; decide whether to classify with-MRTS DetectionOnly overlay separately and run native/semantic comparison for no-MRTS no-match cases",
    }


def top_counts(records: list[dict[str, Any]], key: str, limit: int = 20) -> list[dict[str, Any]]:
    counter = Counter(str(item.get(key) or "-") for item in records)
    return [{"value": value, "count": count} for value, count in counter.most_common(limit)]


def next_recommendation(connector_root: Path) -> dict[str, Any]:
    plan = read_json(report_path(connector_root, "next_fix_plan", "json"))
    recommendation = plan.get("recommendation") if isinstance(plan.get("recommendation"), dict) else {}
    return {
        "recommended_next_fix_cluster": recommendation.get("recommended_next_fix_cluster", "-"),
        "reason": recommendation.get("reason", "-"),
        "generated_at": plan.get("generated_at", "-"),
    }


def build_report(connector_root: Path, framework_root: Path) -> dict[str, Any]:
    records = build_records(connector_root, framework_root)
    group_summary = grouped_summary(records)
    detection_only_records = [item for item in records if item["classification"] == WITH_MRTS_DETECTION_ONLY_CLASSIFICATION]
    no_mrts_semantic_records = [
        item for item in records if item["classification"] in NO_MRTS_NOMATCH_SEMANTIC_CLASSIFICATIONS
    ]
    true_candidates = [
        item
        for item in records
        if "intervention_blocking" in item["work_direction"]
        and item["classification"] != WITH_MRTS_DETECTION_ONLY_CLASSIFICATION
        and item["classification"] not in NO_MRTS_NOMATCH_SEMANTIC_CLASSIFICATIONS
    ]
    summary = {
        "expected_403_actual_200_total": len(records),
        "intervention_blocking_true_candidates": len(true_candidates),
        "detection_only_overlay_non_disruptive": len(detection_only_records),
        "no_mrts_semantic_no_match": len(no_mrts_semantic_records),
        "remaining_p0_p1_intervention_blocking": sum(
            1 for item in true_candidates if item.get("priority") in {"P0", "P1"}
        ),
        "rule_in_loadfile": sum(1 for item in records if item["rule_in_loadfile"]),
        "strict_rule_load_errors": sum(1 for item in records if item["strict_load_errors"]),
        "rule_loaded": sum(1 for item in records if item["rule_loaded"]),
        "rule_matched": sum(1 for item in records if item["rule_matched"]),
        "intervention_created": sum(1 for item in records if item["intervention_created"]),
        "connector_lost_intervention": sum(1 for item in records if item["intervention_created"] and not item["connector_set_403"]),
        "connector_set_403": sum(1 for item in records if item["connector_set_403"]),
        "backend_reached": sum(1 for item in records if item["backend_reached"]),
        "with_mrts_detection_only_overlay": sum(1 for item in records if item["mrts_variant"] == "with-mrts"),
        "no_mrts_no_match": sum(1 for item in records if item["mrts_variant"] == "no-mrts" and not item["rule_matched"]),
        "logged_match_suppressed_by_mrts_overlay": sum(
            1 for item in records if item["mrts_variant"] == "with-mrts" and item["rule_matched"]
        ),
    }
    return {
        "report_kind": "intervention-blocking-analysis",
        "generated_at": utc_now(),
        "source_reports": {
            "connector_work_queue": report_relpath("connector_work_queue", "json"),
            "full_runtime_matrix": report_relpath("full_runtime_matrix", "json"),
            "remaining_failure_analysis": report_relpath("remaining_failure_analysis", "json"),
            "phase_work_queue": report_relpath("phase_work_queue", "json"),
            "next_fix_plan": report_relpath("next_fix_plan", "json"),
        },
        "summary": summary,
        "distribution": {
            "connectors": top_counts(records, "connector"),
            "variants": top_counts(records, "variant"),
            "detection_only_connectors": top_counts(detection_only_records, "connector"),
            "detection_only_variants": top_counts(detection_only_records, "variant"),
            "no_mrts_semantic_connectors": top_counts(no_mrts_semantic_records, "connector"),
            "no_mrts_semantic_variants": top_counts(no_mrts_semantic_records, "variant"),
            "no_mrts_semantic_classifications": top_counts(no_mrts_semantic_records, "classification"),
            "source_categories": top_counts(records, "source_category"),
            "phases": top_counts(records, "phase"),
            "targets": top_counts(records, "target"),
        },
        "groups": group_summary,
        "safe_subcluster": safe_subcluster(records),
        "next_fix_plan": next_recommendation(connector_root),
        "records": records,
    }


def md_bool(value: Any) -> str:
    return "yes" if bool(value) else "no"


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Intervention Blocking Analysis",
        "",
        f"- Generated at: `{report['generated_at']}`",
        f"- Expected `403` / actual `200` rows under review: **{summary['expected_403_actual_200_total']}**.",
        f"- Intervention-blocking true candidates: **{summary['intervention_blocking_true_candidates']}** runtime-fixable rows.",
        f"- Remaining P0/P1 intervention-blocking rows: **{summary['remaining_p0_p1_intervention_blocking']}**.",
        f"- DetectionOnly overlay non-disruptive rows: **{summary['detection_only_overlay_non_disruptive']}** report-only rows.",
        f"- no-MRTS semantic no-match rows: **{summary['no_mrts_semantic_no_match']}** metadata-only rows.",
        f"- Rule in generated loadfile: **{summary['rule_in_loadfile']}**",
        f"- Strict rule-load errors: **{summary['strict_rule_load_errors']}**",
        f"- Rule matched: **{summary['rule_matched']}**",
        f"- Disruptive intervention evidence: **{summary['intervention_created']}**",
        f"- Connector lost intervention evidence: **{summary['connector_lost_intervention']}**",
        f"- Connector returned 403 from that evidence: **{summary['connector_set_403']}**",
        f"- Backend/client 200 reached: **{summary['backend_reached']}**",
        "",
        "## Key Split",
        "",
        f"- with-MRTS DetectionOnly overlay rows: **{summary['with_mrts_detection_only_overlay']}**",
        f"- with-MRTS rows with logged target-rule match suppressed by that overlay: **{summary['logged_match_suppressed_by_mrts_overlay']}**",
        f"- no-MRTS rows with loaded rule but no match evidence: **{summary['no_mrts_no_match']}**",
        "",
        "## A-H Groups",
        "",
        "| group | label | count | connectors | variants | suspected cause | fixability | risk |",
        "| --- | --- | ---: | --- | --- | --- | --- | --- |",
    ]
    for group_id in GROUPS:
        group = report["groups"][group_id]
        lines.append(
            "| {group_id} | {label} | {count} | {connectors} | {variants} | {cause} | {fixability} | {risk} |".format(
                group_id=group_id,
                label=group["label"],
                count=group["count"],
                connectors=", ".join(group["connectors"]) or "-",
                variants=", ".join(group["variants"]) or "-",
                cause=sanitize_report_text(group["suspected_cause"]),
                fixability=sanitize_report_text(group["fixability"]),
                risk=sanitize_report_text(group["risk"]),
            )
        )
    lines.extend(["", "## Representative Evidence", ""])
    for group_id in GROUPS:
        group = report["groups"][group_id]
        if not group["count"]:
            continue
        lines.extend([
            f"### {group_id}. {group['label']}",
            "",
            "| case | connector | variant | rule | phase | target | operator | request | loaded | matched | intervention | backend |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ])
        for item in group["example_cases"]:
            request = item["path"] if item["query"] in {"", "-"} else f"{item['path']}?{item['query']}"
            lines.append(
                "| {case} | {connector} | {variant} | {rule} | {phase} | `{target}` | `{operator}` | `{request}` | {loaded} | {matched} | {intervention} | {backend} |".format(
                    case=item["case_id"],
                    connector=item["connector"],
                    variant=item["variant"],
                    rule=item["rule_id"],
                    phase=item["phase"],
                    target=sanitize_report_text(item["target"]),
                    operator=sanitize_report_text(item["operator"]),
                    request=sanitize_report_text(request),
                    loaded=md_bool(item["rule_loaded"]),
                    matched=md_bool(item["rule_matched"]),
                    intervention=md_bool(item["intervention_created"]),
                    backend=md_bool(item["backend_reached"]),
                )
            )
        lines.append("")
    selected = report["safe_subcluster"]
    lines.extend(
        [
            "## Safe Subcluster",
            "",
            f"- Selected: **{md_bool(selected['selected'])}**",
            f"- Name: `{selected['name']}`",
            f"- Count: **{selected['count']}**",
            f"- Reason: {sanitize_report_text(selected['reason'])}",
            f"- Recommended action: {sanitize_report_text(selected['recommended_action'])}",
            "",
            "## Current Next Fix Plan",
            "",
            f"- Recommended next cluster: `{report['next_fix_plan']['recommended_next_fix_cluster']}`",
            f"- Reason: {sanitize_report_text(report['next_fix_plan']['reason'])}",
            "",
            "## Guardrail Notes",
            "",
            "- This report does not change Expected statuses, testcase rules, MRTS definitions, or PASS/FAIL values.",
            "- No row currently proves a disruptive intervention that was later lost by connector or runner.",
            "- The with-MRTS group is classification/report-only unless the MRTS overlay policy is intentionally changed.",
            "- Treat the no-MRTS group as semantic/native-comparison work, not as an intervention-forwarding fix.",
            "",
        ]
    )
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector-root", type=Path, default=Path.cwd())
    parser.add_argument("--framework-root", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    connector_root = args.connector_root.resolve()
    framework_root = (args.framework_root or connector_root / "modules/ModSecurity-test-Framework").resolve()
    output_dir = resolve_output_dir(connector_root, args.output_dir, REPORT_DIR)
    add_safe_roots(connector_root, framework_root, connector_root / REPORT_DIR)
    add_report_roots(connector_root / REPORT_DIR)
    report = build_report(connector_root, framework_root)
    metadata = build_metadata(
        generated_by="ci/evidence/reports/generate-intervention-blocking-analysis.py",
        make_target="generate-intervention-blocking-analysis",
        connector_root=connector_root,
        framework_root=framework_root,
        inputs=report["source_reports"].values(),
        generated_at=report["generated_at"],
    )
    write_text_file(report_path_from_root(output_dir, "intervention_blocking_analysis", "json"), generated_json_text(report, metadata))
    write_text_file(report_path_from_root(output_dir, "intervention_blocking_analysis", "md"), generated_markdown_text(render_markdown(report), metadata))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
