#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# CI helpers are shared from ci/lib even when this file is executed directly.

from typing import Any

from modsecurity_connector_ci.lib.focused_analysis_utils import action_parts, action_value, as_list, import_script, log_paths, read_json, read_text, utc_now, write_json
from modsecurity_connector_ci.lib.generated_report_utils import GENERATED_ROOT, build_metadata, generated_json_text, generated_markdown_text, report_path, report_path_from_root, report_relpath
from modsecurity_connector_ci.lib.report_path_safety import add_report_roots, add_safe_roots, resolve_output_dir, safe_existing_file, write_text_file

try:
    import yaml
except Exception:  # pragma: no cover - report generation has a conservative fallback.
    yaml = None


REPORT_DIR = GENERATED_ROOT
TARGET_CATEGORIES = {"request_body_processor", "multipart_files", "xml_processor"}
SELECTED_CONNECTOR_GAP_CASE = "phase1_vs_phase2_request_body_gap"
URLENCODED_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"
URLENCODED_FORM_CLASSIFICATION = "with_mrts_detection_only_non_disruptive"
XML_ACTIVATION_MISSING_CLASSIFICATION = "xml_processor_activation_missing"
MULTIPART_ACTIVATION_MISSING_CLASSIFICATION = "multipart_processor_activation_missing"
MULTIPART_FORM_DATA_CONTENT_TYPE = "multipart/form-data"
GENERATED_SMOKE_CONFIG_RELATIVE_PATH = "conf/modsecurity-smoke.conf"
ABSOLUTE_RUNTIME_PATH_RE = re.compile(r"(?<![\w.-])/(?:tmp|root|src)[^\s\"']*")
DISTRIBUTION_TABLE_HEADER = "| field | distribution |"
DISTRIBUTION_TABLE_SEPARATOR = "| --- | --- |"


def sanitize_report_text(value: Any) -> str:
    return ABSOLUTE_RUNTIME_PATH_RE.sub("<evidence-path>", str(value or ""))


def normalized_content_type(value: Any) -> str:
    return str(value or "").split(";", 1)[0].strip().lower()


def display_case_path(path_value: Any, framework_root: Path) -> str:
    path = safe_existing_file(path_value)
    if path is None:
        return sanitize_report_text(str(path_value or "").replace("\\", "/").rstrip("/").split("/")[-1] or "-")
    try:
        return "framework:" + str(path.resolve(strict=False).relative_to(framework_root.resolve(strict=False)))
    except ValueError:
        return sanitize_report_text(path.name or "-")


def generated_config_path(entry: dict[str, Any], evidence_path: Path) -> Path | None:
    case_id = str(entry.get("case_id") or evidence_path.parent.name)
    connector = str(entry.get("connector") or "")
    if connector == "nginx":
        return evidence_path.parent.parent.parent / "runtime" / case_id / GENERATED_SMOKE_CONFIG_RELATIVE_PATH
    if connector == "apache":
        return evidence_path.parent.parent.parent.parent / "apache-runtime" / case_id / GENERATED_SMOKE_CONFIG_RELATIVE_PATH
    if connector == "haproxy":
        return evidence_path.parent.parent.parent.parent / "haproxy-runtime-cases" / case_id / GENERATED_SMOKE_CONFIG_RELATIVE_PATH
    return None


def parse_rules(rules: str) -> list[dict[str, Any]]:
    parsed: list[dict[str, Any]] = []
    rule_re = re.compile(
        r"\b(SecRule|SecAction)\b\s+"
        r"(?:(?P<target>[^\s\"]+)\s+\"(?P<operator>[^\"]*)\"\s+)?"
        r"(?:\\\s*)?\"(?P<actions>[^\"]+)\"",
        re.DOTALL,
    )
    for match in rule_re.finditer(rules):
        actions = action_parts(re.sub(r"\s+", " ", match.group("actions")).strip())
        rule_id = action_value(actions, "id")
        phase = action_value(actions, "phase")
        parsed.append(
            {
                "rule_id": rule_id,
                "phase": phase,
                "target": match.group("target") or "-",
                "operator": match.group("operator") or "-",
                "actions": actions,
                "transformations": [action.split(":", 1)[1] for action in actions if action.lower().startswith("t:")],
            }
        )
    return parsed


def select_rule(rules: list[dict[str, Any]], expected_rule_id: Any) -> dict[str, Any]:
    expected = str(expected_rule_id or "")
    if expected:
        for rule in rules:
            if rule["rule_id"] == expected:
                return rule
    for rule in reversed(rules):
        if rule["rule_id"] != "-":
            return rule
    return {"rule_id": "-", "phase": "-", "target": "-", "operator": "-", "actions": [], "transformations": []}


def body_kind(request: dict[str, Any], content_type: str) -> str:
    body = str(request.get("body") or "")
    if isinstance(request.get("multipart"), dict):
        return "multipart"
    if not body:
        return "empty"
    lowered = content_type.lower()
    if MULTIPART_FORM_DATA_CONTENT_TYPE in lowered:
        return "multipart"
    if "json" in lowered:
        return "json"
    if "xml" in lowered:
        return "xml"
    if "x-www-form-urlencoded" in lowered:
        return "form"
    return "raw"


def rule_logged(logs: str, rule_id: str) -> bool:
    if not rule_id or rule_id == "-":
        return False
    return bool(
        re.search(r'\[id "' + re.escape(rule_id) + r'"\]', logs)
        or re.search(r'"rule_id"\s*:\s*"?' + re.escape(rule_id) + r'"?', logs)
    )


def request_body_seen(logs: str) -> str:
    seen = False
    any_decision = False
    for line in logs.splitlines():
        if not line.startswith("{"):
            continue
        try:
            loaded = json.loads(line)
        except Exception:
            continue
        if isinstance(loaded, dict) and "request_body_seen" in loaded:
            any_decision = True
            seen = seen or loaded.get("request_body_seen") is True
    if seen:
        return "yes"
    return "no" if any_decision else "unknown"


def generated_body_length(config_path: Path | None, request: dict[str, Any]) -> int:
    if config_path:
        request_body = safe_existing_file(config_path.parent / "request-body.bin")
        if request_body is not None:
            return len(read_text(request_body).encode())
    if isinstance(request.get("multipart"), dict):
        return -1
    return len(str(request.get("body") or "").encode())


def request_body_bytes(config_path: Path | None, request: dict[str, Any]) -> bytes:
    if config_path:
        request_body = safe_existing_file(config_path.parent / "request-body.bin")
        if request_body is not None:
            try:
                return request_body.read_bytes()
            except OSError:
                pass
    if isinstance(request.get("multipart"), dict):
        return b""
    return str(request.get("body") or "").encode()


def body_preview(body: bytes) -> str:
    text = body.decode("utf-8", errors="replace").replace("\n", "\\n")
    return text[:80]


def multipart_boundary(content_type: str) -> str:
    match = re.search(r'boundary="?([^";]+)"?', content_type, re.IGNORECASE)
    return match.group(1).strip() if match else "-"


def multipart_part_metadata(text: str, boundary: str) -> tuple[int, list[str], list[str]]:
    fields: list[str] = []
    filenames: list[str] = []
    parts = 0
    for raw_part in text.split("--" + boundary):
        part = raw_part.strip("\n").removesuffix("--").strip("\n")
        headers, _, _payload = part.partition("\n\n")
        disposition = next((line for line in headers.splitlines() if line.lower().startswith("content-disposition:")), "")
        if not part or not disposition:
            continue
        parts += 1
        name_match = re.search(r'name="([^"]*)"', disposition)
        filename_match = re.search(r'filename="([^"]*)"', disposition)
        if name_match:
            fields.append(name_match.group(1))
        if filename_match:
            filenames.append(filename_match.group(1))
    return parts, fields, filenames


def multipart_details(content_type: str, body: bytes) -> dict[str, Any]:
    boundary = multipart_boundary(content_type)
    details: dict[str, Any] = {
        "boundary": boundary,
        "boundary_status": "missing",
        "part_count": 0,
        "field_names": [],
        "filenames": [],
    }
    if boundary == "-" or not body:
        return details
    marker = ("--" + boundary).encode()
    closing = ("--" + boundary + "--").encode()
    details["boundary_status"] = "valid" if marker in body and closing in body else "mismatch"
    text = body.decode("utf-8", errors="replace").replace("\r\n", "\n")
    parts, fields, filenames = multipart_part_metadata(text, boundary)
    details["part_count"] = parts
    details["field_names"] = fields
    details["filenames"] = filenames
    return details


def loaded_case_data(case_path: Path | None) -> tuple[str, dict[str, Any]]:
    raw = read_text(case_path) if case_path is not None and case_path.is_file() else ""
    if not raw or yaml is None:
        return raw, {}
    try:
        parsed = yaml.safe_load(raw)
    except Exception:
        return raw, {}
    return raw, parsed if isinstance(parsed, dict) else {}


def request_metadata(loaded: dict[str, Any]) -> tuple[dict[str, Any], str, str, str, dict[str, Any]]:
    request = loaded.get("request") if isinstance(loaded.get("request"), dict) else {}
    headers = request.get("headers") if isinstance(request.get("headers"), dict) else {}
    content_type = str(headers.get("Content-Type") or headers.get("content-type") or "-")
    request_path = str(request.get("path") or "-")
    path, separator, query = request_path.partition("?")
    return request, content_type, path or "/", query if separator and query else "-", loaded.get("expect") if isinstance(loaded.get("expect"), dict) else {}


def request_body_access_state(config: str) -> str:
    if "SecRequestBodyAccess On" in config:
        return "yes"
    if "SecRequestBodyAccess Off" in config:
        return "no"
    return "unknown"


def body_payload_fields(config_path: Path | None, request: dict[str, Any], content_type: str) -> dict[str, Any]:
    kind = body_kind(request, content_type)
    body = request_body_bytes(config_path, request)
    multipart = multipart_details(content_type, body) if kind == "multipart" else {}
    return {
        "body_kind": kind,
        "body_length": len(body) if body else generated_body_length(config_path, request),
        "body_sha256": hashlib.sha256(body).hexdigest() if body else "-",
        "body_preview": body_preview(body) if body else "-",
        "multipart_boundary": multipart.get("boundary", "-"),
        "multipart_boundary_status": multipart.get("boundary_status", "not_applicable"),
        "multipart_part_count": multipart.get("part_count", 0),
        "multipart_field_names": multipart.get("field_names", []),
        "multipart_filenames": multipart.get("filenames", []),
    }


def body_rule_fields(rule: dict[str, Any], entry: dict[str, Any], config: str) -> dict[str, Any]:
    rule_id = str(rule["rule_id"])
    return {
        "rule_id": rule_id,
        "phase": str(rule["phase"] if rule["phase"] != "-" else entry.get("phase") or "-"),
        "target": str(rule["target"] or "-"),
        "operator": str(rule["operator"] or "-"),
        "transformations": rule["transformations"],
        "actions": rule["actions"],
        "rule_in_loadfile": bool(rule_id != "-" and rule_id in config),
    }


def body_observation_fields(
    entry: dict[str, Any],
    loaded: dict[str, Any],
    request_body_access: str,
    config: str,
    content_type: str,
    request: dict[str, Any],
    logs: str,
    rule_id: str,
) -> dict[str, Any]:
    matched = rule_logged(logs, rule_id)
    return {
        "request_body_access": request_body_access,
        "xml_processor": "yes" if "ctl:requestBodyProcessor=XML" in config else "unknown",
        "multipart_parser": "yes" if request_body_access == "yes" and body_kind(request, content_type) == "multipart" else "unknown",
        "request_body_seen": request_body_seen(logs),
        "rule_matched": matched,
        "collection_evidence": "yes" if matched else "no",
        "parse_error": bool(re.search(r"parse|parser|multipart|xml|json", logs, re.IGNORECASE))
        and "Warning. Matched" not in logs,
        "backend_reached": entry.get("actual_status") == 200,
        "known_limitations": as_list(loaded.get("known_limitations")),
    }


def case_metadata(entry: dict[str, Any], evidence: dict[str, Any], framework_root: Path) -> dict[str, Any]:
    case_path = safe_existing_file(evidence.get("path"))
    raw, loaded = loaded_case_data(case_path)
    request, content_type, path, query, expect = request_metadata(loaded)
    rules = parse_rules(str(loaded.get("rules") or raw))
    rule = select_rule(rules, expect.get("rule_id"))
    evidence_path = safe_existing_file(entry.get("evidence"))
    config_path = generated_config_path(entry, evidence_path) if evidence_path is not None else None
    config = read_text(config_path)
    logs = "\n".join(read_text(path_item) for path_item in log_paths(evidence))
    request_body_access = request_body_access_state(config)
    return {
        "case_path": display_case_path(case_path, framework_root),
        "method": str(request.get("method") or "-"),
        "path": path,
        "query": query,
        "content_type": content_type,
        **body_payload_fields(config_path, request, content_type),
        **body_rule_fields(rule, entry, config),
        **body_observation_fields(
            entry,
            loaded,
            request_body_access,
            config,
            content_type,
            request,
            logs,
            str(rule["rule_id"]),
        ),
    }


def build_records(
    connector_root: Path, framework_root: Path
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    remaining = import_script(connector_root / "ci/evidence/reports/generate-remaining-failure-analysis.py", "remaining_failure_analysis")
    queue = read_json(report_path(connector_root, "connector_work_queue", "json"))
    entries = [entry for entry in queue.get("entries", []) if isinstance(entry, dict) and entry.get("runtime_status") == "FAIL"]
    target_records: list[dict[str, Any]] = []
    selected_gap_records: list[dict[str, Any]] = []
    urlencoded_form_records: list[dict[str, Any]] = []
    xml_activation_missing_records: list[dict[str, Any]] = []
    multipart_activation_missing_records: list[dict[str, Any]] = []
    for entry in entries:
        category = remaining.failure_category(entry)
        is_selected_gap = entry.get("case_id") == SELECTED_CONNECTOR_GAP_CASE
        is_candidate_urlencoded = entry.get("classification") == URLENCODED_FORM_CLASSIFICATION
        is_candidate_xml_activation = entry.get("classification") == XML_ACTIVATION_MISSING_CLASSIFICATION
        is_candidate_multipart_activation = entry.get("classification") == MULTIPART_ACTIVATION_MISSING_CLASSIFICATION
        if (
            category not in TARGET_CATEGORIES
            and not is_selected_gap
            and not is_candidate_urlencoded
            and not is_candidate_xml_activation
            and not is_candidate_multipart_activation
        ):
            continue
        evidence = read_json(entry.get("evidence"))
        meta = case_metadata(entry, evidence, framework_root)
        record = {
            "case_id": entry.get("case_id"),
            "connector": entry.get("connector"),
            "variant": f"{entry.get('test_variant')}/{entry.get('mrts_variant')}",
            "test_variant": entry.get("test_variant"),
            "mrts_variant": entry.get("mrts_variant"),
            "failure_category": category,
            "queue_category": entry.get("category"),
            "classification": entry.get("classification"),
            "priority": entry.get("priority"),
            "functional_area": as_list(entry.get("functional_area")),
            "source_kind": entry.get("source_kind"),
            "source_corpus": entry.get("mrts_corpus"),
            "expected_status": entry.get("expected_status"),
            "actual_status": entry.get("actual_status"),
            "failure_pattern": as_list(entry.get("failure_pattern")),
            "work_direction": as_list(entry.get("work_direction")),
            **meta,
        }
        if is_urlencoded_form_detection_only(record):
            urlencoded_form_records.append(record)
        if is_xml_activation_missing(record):
            xml_activation_missing_records.append(record)
        if is_multipart_activation_missing(record):
            multipart_activation_missing_records.append(record)
        if is_selected_gap:
            selected_gap_records.append(record)
        elif category in TARGET_CATEGORIES:
            target_records.append(record)
    return (
        target_records,
        selected_gap_records,
        urlencoded_form_records,
        xml_activation_missing_records,
        multipart_activation_missing_records,
    )


def is_urlencoded_form_detection_only(record: dict[str, Any]) -> bool:
    return (
        record.get("classification") == URLENCODED_FORM_CLASSIFICATION
        and record.get("mrts_variant") == "with-mrts"
        and record.get("body_kind") == "form"
        and normalized_content_type(record.get("content_type")) == URLENCODED_FORM_CONTENT_TYPE
    )


def is_xml_activation_missing(record: dict[str, Any]) -> bool:
    return (
        record.get("classification") == XML_ACTIVATION_MISSING_CLASSIFICATION
        and record.get("body_kind") == "xml"
        and record.get("target") == "XML"
        and normalized_content_type(record.get("content_type")) in {"application/xml", "text/xml"}
    )


def is_multipart_activation_missing(record: dict[str, Any]) -> bool:
    return (
        record.get("classification") == MULTIPART_ACTIVATION_MISSING_CLASSIFICATION
        and record.get("body_kind") == "multipart"
        and normalized_content_type(record.get("content_type")) == MULTIPART_FORM_DATA_CONTENT_TYPE
        and record.get("multipart_boundary_status") == "valid"
    )


def count_records(records: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    counter = Counter(str(record.get(key) or "-") for record in records)
    return [{"value": value, "count": count} for value, count in counter.most_common()]


def grouped_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[
            (
                str(record["connector"]),
                str(record["body_kind"]),
                str(record["content_type"]),
                str(record["phase"]),
                str(record["target"]),
                f"{record['expected_status']}->{record['actual_status']}",
                str(record["failure_category"]),
                str(record["source_kind"]),
            )
        ].append(record)
    rows: list[dict[str, Any]] = []
    for key, items in grouped.items():
        example = items[0]
        rows.append(
            {
                "count": len(items),
                "connector": key[0],
                "body_kind": key[1],
                "content_type": key[2],
                "phase": key[3],
                "target": key[4],
                "status_pair": key[5],
                "failure_category": key[6],
                "source_kind": key[7],
                "variants": sorted({str(item["variant"]) for item in items}),
                "example_cases": sorted({str(item["case_id"]) for item in items})[:6],
                "request_body_access": sorted({str(item["request_body_access"]) for item in items}),
                "rule_matched_count": sum(1 for item in items if item["rule_matched"]),
                "collection_evidence_count": sum(1 for item in items if item["collection_evidence"] == "yes"),
                "body_seen": sorted({str(item["request_body_seen"]) for item in items}),
                "suspected_cause": suspected_cause(example),
                "risk": risk_for(example),
                "fixability": fixability_for(example),
            }
        )
    return sorted(rows, key=lambda item: (-item["count"], item["failure_category"], item["connector"], item["target"]))


def counter_dict(records: list[dict[str, Any]], key: str) -> dict[str, int]:
    return dict(Counter(str(record.get(key) or "-") for record in records).most_common())


def summarize_urlencoded_form(records: list[dict[str, Any]]) -> dict[str, Any]:
    body_sent = sum(1 for record in records if int(record.get("body_length") or 0) > 0)
    content_type_correct = sum(
        1 for record in records if normalized_content_type(record.get("content_type")) == URLENCODED_FORM_CONTENT_TYPE
    )
    return {
        "count": len(records),
        "active_request_body_processor_before_report_sync": len(records),
        "active_request_body_processor_after_report_sync": 0,
        "classification": URLENCODED_FORM_CLASSIFICATION,
        "work_direction": "classification_only",
        "priority": "report_only",
        "connectors": counter_dict(records, "connector"),
        "variants": counter_dict(records, "variant"),
        "case_ids": counter_dict(records, "case_id"),
        "rule_ids": counter_dict(records, "rule_id"),
        "targets": counter_dict(records, "target"),
        "operators": counter_dict(records, "operator"),
        "methods": counter_dict(records, "method"),
        "content_types": counter_dict(records, "content_type"),
        "body_kinds": counter_dict(records, "body_kind"),
        "body_lengths": counter_dict(records, "body_length"),
        "request_body_seen": counter_dict(records, "request_body_seen"),
        "body_sent_count": body_sent,
        "content_type_correct_count": content_type_correct,
        "request_body_access_on_count": sum(1 for record in records if record["request_body_access"] == "yes"),
        "rule_loaded_count": sum(1 for record in records if record["rule_in_loadfile"]),
        "rule_matched_count": sum(1 for record in records if record["rule_matched"]),
        "collection_evidence_count": sum(1 for record in records if record["collection_evidence"] == "yes"),
        "backend_reached_count": sum(1 for record in records if record["backend_reached"]),
        "root_cause": "The URL-encoded bodies and Content-Type are present; these rows are with-MRTS DetectionOnly overlay cases, so disruptive actions remain non-blocking and belong to report-only classification.",
        "fix": "metadata/report-only; no request body, Content-Type, rule, Expected status, or PASS/FAIL value changed",
        "risk": "low when kept out of active request_body_processor work; high if promoted to PASS without disruptive runtime evidence",
        "examples": records[:9],
    }


def summarize_xml_activation_missing(records: list[dict[str, Any]]) -> dict[str, Any]:
    body_sent = sum(1 for record in records if int(record.get("body_length") or 0) > 0)
    content_type_correct = sum(
        1 for record in records if normalized_content_type(record.get("content_type")) in {"application/xml", "text/xml"}
    )
    return {
        "count": len(records),
        "active_xml_processor_before_report_sync": len(records),
        "active_xml_processor_after_report_sync": 0,
        "classification": XML_ACTIVATION_MISSING_CLASSIFICATION,
        "work_direction": "classification_only",
        "priority": "report_only",
        "connectors": counter_dict(records, "connector"),
        "variants": counter_dict(records, "variant"),
        "case_ids": counter_dict(records, "case_id"),
        "rule_ids": counter_dict(records, "rule_id"),
        "targets": counter_dict(records, "target"),
        "operators": counter_dict(records, "operator"),
        "content_types": counter_dict(records, "content_type"),
        "body_lengths": counter_dict(records, "body_length"),
        "body_hashes": counter_dict(records, "body_sha256"),
        "request_body_seen": counter_dict(records, "request_body_seen"),
        "body_sent_count": body_sent,
        "content_type_correct_count": content_type_correct,
        "request_body_access_on_count": sum(1 for record in records if record["request_body_access"] == "yes"),
        "xml_processor_active_count": sum(1 for record in records if record["xml_processor"] == "yes"),
        "rule_loaded_count": sum(1 for record in records if record["rule_in_loadfile"]),
        "rule_matched_count": sum(1 for record in records if record["rule_matched"]),
        "xml_collection_evidence_count": sum(1 for record in records if record["collection_evidence"] == "yes"),
        "backend_reached_count": sum(1 for record in records if record["backend_reached"]),
        "root_cause": "The XML bodies and Content-Type are present, but these fixtures do not enable SecRequestBodyAccess/ctl:requestBodyProcessor=XML, so XML collection population is not expected evidence.",
        "fix": "metadata/report-only; no XML body, rule, Expected status, connector-core behavior, or PASS/FAIL value changed",
        "risk": "low when kept report-only; high if treated as a connector XML parser failure without processor activation",
        "examples": records[:9],
    }


def summarize_multipart_activation_missing(records: list[dict[str, Any]]) -> dict[str, Any]:
    body_sent = sum(1 for record in records if int(record.get("body_length") or 0) > 0)
    content_type_correct = sum(
        1 for record in records if normalized_content_type(record.get("content_type")) == MULTIPART_FORM_DATA_CONTENT_TYPE
    )
    boundary_valid = sum(1 for record in records if record.get("multipart_boundary_status") == "valid")
    return {
        "count": len(records),
        "active_multipart_files_before_report_sync": len(records),
        "active_multipart_files_after_report_sync": 0,
        "classification": MULTIPART_ACTIVATION_MISSING_CLASSIFICATION,
        "work_direction": "classification_only",
        "priority": "report_only",
        "connectors": counter_dict(records, "connector"),
        "variants": counter_dict(records, "variant"),
        "case_ids": counter_dict(records, "case_id"),
        "rule_ids": counter_dict(records, "rule_id"),
        "targets": counter_dict(records, "target"),
        "operators": counter_dict(records, "operator"),
        "content_types": counter_dict(records, "content_type"),
        "boundaries": counter_dict(records, "multipart_boundary"),
        "boundary_status": counter_dict(records, "multipart_boundary_status"),
        "part_counts": counter_dict(records, "multipart_part_count"),
        "field_names": dict(Counter(name for record in records for name in record.get("multipart_field_names", [])).most_common()),
        "filenames": dict(Counter(name for record in records for name in record.get("multipart_filenames", [])).most_common()),
        "body_lengths": counter_dict(records, "body_length"),
        "body_hashes": counter_dict(records, "body_sha256"),
        "request_body_seen": counter_dict(records, "request_body_seen"),
        "body_sent_count": body_sent,
        "content_type_correct_count": content_type_correct,
        "boundary_valid_count": boundary_valid,
        "request_body_access_on_count": sum(1 for record in records if record["request_body_access"] == "yes"),
        "multipart_parser_active_count": sum(1 for record in records if record["multipart_parser"] == "yes"),
        "rule_loaded_count": sum(1 for record in records if record["rule_in_loadfile"]),
        "rule_matched_count": sum(1 for record in records if record["rule_matched"]),
        "files_collection_evidence_count": sum(
            1
            for record in records
            if str(record.get("target") or "").startswith("FILES") and record["collection_evidence"] == "yes"
        ),
        "args_collection_evidence_count": sum(
            1
            for record in records
            if str(record.get("target") or "").startswith("ARGS") and record["collection_evidence"] == "yes"
        ),
        "collection_evidence_count": sum(1 for record in records if record["collection_evidence"] == "yes"),
        "backend_reached_count": sum(1 for record in records if record["backend_reached"]),
        "root_cause": "The multipart bodies, Content-Type, boundaries, field names, and filenames are present, but these fixtures do not enable SecRequestBodyAccess before expecting FILES/ARGS_NAMES collection evidence.",
        "fix": "metadata/report-only; no multipart body, Content-Type, boundary, rule, Expected status, connector-core behavior, or PASS/FAIL value changed",
        "risk": "low when kept report-only; high if treated as a connector multipart parser failure without request body activation",
        "examples": records[:9],
    }


def suspected_cause(example: dict[str, Any]) -> str:
    if example["failure_category"] == "request_body_processor" and example["body_kind"] == "json":
        return "JSON/raw REQUEST_BODY rows need processor-specific semantics review; with-MRTS rows may be non-blocking due DetectionOnly overlay."
    if example["failure_category"] == "request_body_processor" and example["body_kind"] == "form":
        return "URL-encoded body variables are present in selected rows, but with-MRTS overlay suppresses disruption."
    if example["failure_category"] == "xml_processor":
        return "XML target population is absent for future/gap rows or non-disruptive under with-MRTS DetectionOnly; XML processor parity needs targeted review."
    if example["failure_category"] == "multipart_files":
        return "Multipart FILES/FILES_NAMES population differs by case; some rows match but with-MRTS prevents blocking, others lack collection evidence."
    if example["case_id"] == SELECTED_CONNECTOR_GAP_CASE:
        return "The YAML request body is empty while a phase:1 REQUEST_BODY rule expects bodyhit; existing metadata marks it as connector-gap."
    return "manual review"


def risk_for(example: dict[str, Any]) -> str:
    if example["case_id"] == SELECTED_CONNECTOR_GAP_CASE:
        return "low for classification-only"
    if example["failure_category"] == "xml_processor":
        return "medium to high"
    return "medium"


def fixability_for(example: dict[str, Any]) -> str:
    if example["case_id"] == SELECTED_CONNECTOR_GAP_CASE:
        return "metadata-only; do not change request body, rule, or expected status"
    if example["mrts_variant"] == "with-mrts" and example["rule_matched"]:
        return "classification/report-only unless MRTS DetectionOnly policy changes"
    return "requires targeted native/connector comparison before code changes"


def build_report(connector_root: Path, framework_root: Path) -> dict[str, Any]:
    (
        records,
        selected_gap_records,
        urlencoded_form_records,
        xml_activation_missing_records,
        multipart_activation_missing_records,
    ) = build_records(connector_root, framework_root)
    category_counts = Counter(record["failure_category"] for record in records)
    selected_count = len(selected_gap_records)
    urlencoded_form_summary = summarize_urlencoded_form(urlencoded_form_records)
    xml_activation_summary = summarize_xml_activation_missing(xml_activation_missing_records)
    multipart_activation_summary = summarize_multipart_activation_missing(multipart_activation_missing_records)
    summary = {
        "before_metadata_fix": {
            "request_body_processor": category_counts.get("request_body_processor", 0) + selected_count,
            "multipart_files": category_counts.get("multipart_files", 0) + multipart_activation_summary["count"],
            "xml_processor": category_counts.get("xml_processor", 0) + xml_activation_summary["count"],
            "combined": len(records) + selected_count + xml_activation_summary["count"] + multipart_activation_summary["count"],
        },
        "after_metadata_fix": {
            "request_body_processor": category_counts.get("request_body_processor", 0),
            "multipart_files": category_counts.get("multipart_files", 0),
            "xml_processor": category_counts.get("xml_processor", 0),
            "combined": len(records),
        },
        "selected_subcluster_count": selected_count,
        "urlencoded_form_subcluster_count": urlencoded_form_summary["count"],
        "urlencoded_form_active_after_report_sync": urlencoded_form_summary["active_request_body_processor_after_report_sync"],
        "xml_activation_missing_subcluster_count": xml_activation_summary["count"],
        "xml_processor_active_after_report_sync": xml_activation_summary["active_xml_processor_after_report_sync"],
        "multipart_activation_missing_subcluster_count": multipart_activation_summary["count"],
        "multipart_files_active_after_report_sync": multipart_activation_summary["active_multipart_files_after_report_sync"],
        "rule_loaded": sum(1 for record in records + selected_gap_records if record["rule_in_loadfile"]),
        "rule_matched": sum(1 for record in records + selected_gap_records if record["rule_matched"]),
        "backend_reached": sum(1 for record in records + selected_gap_records if record["backend_reached"]),
        "request_body_access_on": sum(1 for record in records + selected_gap_records if record["request_body_access"] == "yes"),
        "collection_evidence": sum(1 for record in records + selected_gap_records if record["collection_evidence"] == "yes"),
    }
    plan = read_json(report_path(connector_root, "next_fix_plan", "json"))
    recommendation = plan.get("recommendation") if isinstance(plan.get("recommendation"), dict) else {}
    return {
        "report_kind": "body-processor-analysis",
        "generated_at": utc_now(),
        "source_reports": {
            "connector_work_queue": report_relpath("connector_work_queue", "json"),
            "remaining_failure_analysis": report_relpath("remaining_failure_analysis", "json"),
            "phase_work_queue": report_relpath("phase_work_queue", "json"),
            "next_fix_plan": report_relpath("next_fix_plan", "json"),
        },
        "summary": summary,
        "distribution": {
            "connectors": count_records(records, "connector"),
            "variants": count_records(records, "variant"),
            "body_kinds": count_records(records, "body_kind"),
            "content_types": count_records(records, "content_type"),
            "targets": count_records(records, "target"),
            "failure_categories": count_records(records, "failure_category"),
        },
        "selected_subcluster": {
            "case_id": SELECTED_CONNECTOR_GAP_CASE,
            "count": selected_count,
            "action": "metadata-only classification: request_body_processor -> connector_gap",
            "why_safe": "the case has an empty request body and existing source metadata says connector-gap; no request, rule, expected status, or PASS/FAIL value changed",
            "root_cause": "phase:1 REQUEST_BODY cannot match the expected bodyhit because the YAML request body is empty",
            "body_arrived": "empty by fixture",
            "processor_active": "not relevant for the selected metadata-only classification",
            "collections_created": "no target rule match evidence",
            "examples": selected_gap_records[:9],
        },
        "urlencoded_form_subcluster": urlencoded_form_summary,
        "xml_activation_missing_subcluster": xml_activation_summary,
        "multipart_activation_missing_subcluster": multipart_activation_summary,
        "groups": grouped_records(records),
        "records": records,
        "next_fix_plan": {
            "recommended_next_fix_cluster": recommendation.get("recommended_next_fix_cluster", "-"),
            "reason": recommendation.get("reason", "-"),
        },
    }


def md_bool(value: Any) -> str:
    return "yes" if bool(value) else "no"


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    before = summary["before_metadata_fix"]
    after = summary["after_metadata_fix"]
    urlencoded = report["urlencoded_form_subcluster"]
    xml_activation = report["xml_activation_missing_subcluster"]
    multipart_activation = report["multipart_activation_missing_subcluster"]
    lines = [
        "# Body Processor Failure Analysis",
        "",
        f"- Generated at: `{report['generated_at']}`",
        f"- Before selected metadata fix: request_body_processor **{before['request_body_processor']}**, multipart_files **{before['multipart_files']}**, xml_processor **{before['xml_processor']}**, combined **{before['combined']}**.",
        f"- After selected metadata fix: request_body_processor **{after['request_body_processor']}**, multipart_files **{after['multipart_files']}**, xml_processor **{after['xml_processor']}**, combined **{after['combined']}**.",
        f"- Selected subcluster rows: **{summary['selected_subcluster_count']}**",
        f"- URL-encoded form rows moved out of active body-processor work: **{summary['urlencoded_form_subcluster_count']}** -> **{summary['urlencoded_form_active_after_report_sync']}**.",
        f"- XML processor activation-missing rows moved out of active xml_processor work: **{summary['xml_activation_missing_subcluster_count']}** -> **{summary['xml_processor_active_after_report_sync']}**.",
        f"- Multipart processor activation-missing rows moved out of active multipart_files work: **{summary['multipart_activation_missing_subcluster_count']}** -> **{summary['multipart_files_active_after_report_sync']}**.",
        f"- Rule loaded evidence rows: **{summary['rule_loaded']}**",
        f"- Target rule matched rows: **{summary['rule_matched']}**",
        f"- Backend reached rows: **{summary['backend_reached']}**",
        f"- Request body access explicitly on: **{summary['request_body_access_on']}**",
        f"- Collection/target evidence rows: **{summary['collection_evidence']}**",
        "",
        "## Selected Subcluster",
        "",
        f"- Case: `{report['selected_subcluster']['case_id']}`",
        f"- Count: **{report['selected_subcluster']['count']}**",
        f"- Action: {report['selected_subcluster']['action']}",
        f"- Why safe: {report['selected_subcluster']['why_safe']}",
        f"- Root cause: {report['selected_subcluster']['root_cause']}",
        f"- Body arrived: {report['selected_subcluster']['body_arrived']}",
        f"- Processor active: {report['selected_subcluster']['processor_active']}",
        f"- Collections created: {report['selected_subcluster']['collections_created']}",
        "",
        "## URL-encoded Form Subcluster",
        "",
        f"- Count: **{urlencoded['count']}**",
        f"- Active request_body_processor rows before report sync: **{urlencoded['active_request_body_processor_before_report_sync']}**",
        f"- Active request_body_processor rows after report sync: **{urlencoded['active_request_body_processor_after_report_sync']}**",
        f"- Classification: `{urlencoded['classification']}`",
        f"- Work direction: `{urlencoded['work_direction']}`",
        f"- Priority: `{urlencoded['priority']}`",
        f"- Body sent rows: **{urlencoded['body_sent_count']}**",
        f"- Correct Content-Type rows: **{urlencoded['content_type_correct_count']}**",
        f"- SecRequestBodyAccess On rows: **{urlencoded['request_body_access_on_count']}**",
        f"- Rule loaded rows: **{urlencoded['rule_loaded_count']}**",
        f"- Rule matched rows: **{urlencoded['rule_matched_count']}**",
        f"- Collection/target evidence rows: **{urlencoded['collection_evidence_count']}**",
        f"- Backend reached rows: **{urlencoded['backend_reached_count']}**",
        f"- Root cause: {urlencoded['root_cause']}",
        f"- Fix: {urlencoded['fix']}",
        f"- Risk: {urlencoded['risk']}",
        "",
        DISTRIBUTION_TABLE_HEADER,
        DISTRIBUTION_TABLE_SEPARATOR,
    ]
    for key in ("connectors", "variants", "case_ids", "rule_ids", "targets", "operators", "body_lengths", "request_body_seen"):
        values = ", ".join(f"`{sanitize_report_text(name)}`: {count}" for name, count in urlencoded[key].items()) or "-"
        lines.append(f"| {key} | {values} |")
    lines.extend(
        [
            "",
            "## XML Processor Activation-Missing Subcluster",
            "",
            f"- Count: **{xml_activation['count']}**",
            f"- Active xml_processor rows before report sync: **{xml_activation['active_xml_processor_before_report_sync']}**",
            f"- Active xml_processor rows after report sync: **{xml_activation['active_xml_processor_after_report_sync']}**",
            f"- Classification: `{xml_activation['classification']}`",
            f"- Work direction: `{xml_activation['work_direction']}`",
            f"- Priority: `{xml_activation['priority']}`",
            f"- Body sent rows: **{xml_activation['body_sent_count']}**",
            f"- Correct XML Content-Type rows: **{xml_activation['content_type_correct_count']}**",
            f"- SecRequestBodyAccess On rows: **{xml_activation['request_body_access_on_count']}**",
            f"- XML processor active rows: **{xml_activation['xml_processor_active_count']}**",
            f"- Rule loaded rows: **{xml_activation['rule_loaded_count']}**",
            f"- Rule matched rows: **{xml_activation['rule_matched_count']}**",
            f"- XML collection evidence rows: **{xml_activation['xml_collection_evidence_count']}**",
            f"- Backend reached rows: **{xml_activation['backend_reached_count']}**",
            f"- Root cause: {xml_activation['root_cause']}",
            f"- Fix: {xml_activation['fix']}",
            f"- Risk: {xml_activation['risk']}",
            "",
            DISTRIBUTION_TABLE_HEADER,
            DISTRIBUTION_TABLE_SEPARATOR,
        ]
    )
    for key in ("connectors", "variants", "case_ids", "rule_ids", "targets", "operators", "content_types", "body_lengths", "body_hashes", "request_body_seen"):
        values = ", ".join(f"`{sanitize_report_text(name)}`: {count}" for name, count in xml_activation[key].items()) or "-"
        lines.append(f"| {key} | {values} |")
    lines.append("")
    lines.extend(
        [
            "## Multipart Processor Activation-Missing Subcluster",
            "",
            f"- Count: **{multipart_activation['count']}**",
            f"- Active multipart_files rows before report sync: **{multipart_activation['active_multipart_files_before_report_sync']}**",
            f"- Active multipart_files rows after report sync: **{multipart_activation['active_multipart_files_after_report_sync']}**",
            f"- Classification: `{multipart_activation['classification']}`",
            f"- Work direction: `{multipart_activation['work_direction']}`",
            f"- Priority: `{multipart_activation['priority']}`",
            f"- Body sent rows: **{multipart_activation['body_sent_count']}**",
            f"- Correct Multipart Content-Type rows: **{multipart_activation['content_type_correct_count']}**",
            f"- Boundary valid rows: **{multipart_activation['boundary_valid_count']}**",
            f"- SecRequestBodyAccess On rows: **{multipart_activation['request_body_access_on_count']}**",
            f"- Multipart parser active rows: **{multipart_activation['multipart_parser_active_count']}**",
            f"- Rule loaded rows: **{multipart_activation['rule_loaded_count']}**",
            f"- Rule matched rows: **{multipart_activation['rule_matched_count']}**",
            f"- FILES/FILES_NAMES evidence rows: **{multipart_activation['files_collection_evidence_count']}**",
            f"- ARGS/ARGS_NAMES evidence rows: **{multipart_activation['args_collection_evidence_count']}**",
            f"- Collection/target evidence rows: **{multipart_activation['collection_evidence_count']}**",
            f"- Backend reached rows: **{multipart_activation['backend_reached_count']}**",
            f"- Root cause: {multipart_activation['root_cause']}",
            f"- Fix: {multipart_activation['fix']}",
            f"- Risk: {multipart_activation['risk']}",
            "",
            DISTRIBUTION_TABLE_HEADER,
            DISTRIBUTION_TABLE_SEPARATOR,
        ]
    )
    for key in (
        "connectors",
        "variants",
        "case_ids",
        "rule_ids",
        "targets",
        "operators",
        "content_types",
        "boundaries",
        "boundary_status",
        "part_counts",
        "field_names",
        "filenames",
        "body_lengths",
        "body_hashes",
        "request_body_seen",
    ):
        values = ", ".join(
            f"`{sanitize_report_text(name)}`: {count}" for name, count in multipart_activation[key].items()
        ) or "-"
        lines.append(f"| {key} | {values} |")
    lines.append("")
    lines.extend(
        [
            "## Active Body Processor Distributions",
            "",
        ]
    )
    for title, key in (
        ("Connectors", "connectors"),
        ("Variants", "variants"),
        ("Body Kinds", "body_kinds"),
        ("Content Types", "content_types"),
        ("Targets", "targets"),
        ("Failure Categories", "failure_categories"),
    ):
        lines.extend([
            f"### {title}",
            "",
            "| value | count |",
            "| --- | ---: |",
        ])
        items = report["distribution"][key]
        if not items:
            lines.append("_No rows available. Reason: no active body-processor rows remain after report-only classification._")
        for item in items:
            lines.append(f"| `{sanitize_report_text(item['value'])}` | {item['count']} |")
        lines.append("")
    lines.extend(
        [
            "## Grouped Rows",
            "",
            "| count | connector | body kind | content-type | phase | target | status | category | variants | matched | cause | fixability |",
            "| ---: | --- | --- | --- | --- | --- | --- | --- | --- | ---: | --- | --- |",
        ]
    )
    if not report["groups"]:
        lines.append("_No rows available. Reason: no active body-processor grouped rows remain after report-only classification._")
    for group in report["groups"]:
        lines.append(
            "| {count} | {connector} | {body_kind} | `{content_type}` | {phase} | `{target}` | {status_pair} | {category} | {variants} | {matched} | {cause} | {fixability} |".format(
                count=group["count"],
                connector=group["connector"],
                body_kind=group["body_kind"],
                content_type=sanitize_report_text(group["content_type"]),
                phase=group["phase"],
                target=sanitize_report_text(group["target"]),
                status_pair=group["status_pair"],
                category=group["failure_category"],
                variants=", ".join(group["variants"]),
                matched=group["rule_matched_count"],
                cause=sanitize_report_text(group["suspected_cause"]),
                fixability=sanitize_report_text(group["fixability"]),
            )
        )
    lines.extend(
        [
            "",
            "## Current Next Fix Plan",
            "",
            f"- Recommended next cluster: `{report['next_fix_plan']['recommended_next_fix_cluster']}`",
            f"- Reason: {sanitize_report_text(report['next_fix_plan']['reason'])}",
            "",
            "## Guardrail Notes",
            "",
            "- No Expected statuses, testcase rules, request bodies, MRTS definitions, or PASS/FAIL values are changed by this analysis.",
            "- The selected subcluster is metadata-only and remains a runtime FAIL; it is no longer counted as body-processor work.",
            "- URL-encoded/form rows are report-only with-MRTS DetectionOnly overlay evidence; no harness or connector-core change is made for them.",
            "- XML rows in the activation-missing subcluster are report-only because their fixtures do not enable the XML request body processor.",
            "- Multipart rows in the activation-missing subcluster are report-only because their fixtures do not enable request body access before expecting FILES/ARGS_NAMES collection evidence.",
            "- Remaining active body-processor rows are zero after the URL-encoded, XML, and Multipart metadata splits.",
            "",
        ]
    )
    return "\n".join(lines)


def replace_marked_section(text: str, start: str, end: str, section: str) -> str:
    block = f"{start}\n{section}\n{end}"
    if start in text and end in text:
        pattern = re.compile(re.escape(start) + r".*?" + re.escape(end), re.DOTALL)
        return pattern.sub(block, text)
    return text.rstrip() + "\n\n" + block + "\n"


def update_full_run_evidence(report_dir: Path, report: dict[str, Any]) -> None:
    if os.environ.get("SUPPRESS_FULL_RUN_EVIDENCE_SIDE_EFFECTS") == "1":
        return
    json_path = report_path_from_root(report_dir, "full_run_evidence", "json")
    data = read_json(json_path)
    if data:
        data["body_processor_analysis_report"] = {
            "analysis": report_relpath("body_processor_analysis", "md"),
            "json": report_relpath("body_processor_analysis", "json"),
            "urlencoded_form_subcluster_count": report["summary"]["urlencoded_form_subcluster_count"],
            "urlencoded_active_after_report_sync": report["summary"]["urlencoded_form_active_after_report_sync"],
            "xml_activation_missing_subcluster_count": report["summary"]["xml_activation_missing_subcluster_count"],
            "xml_active_after_report_sync": report["summary"]["xml_processor_active_after_report_sync"],
            "multipart_activation_missing_subcluster_count": report["summary"]["multipart_activation_missing_subcluster_count"],
            "multipart_active_after_report_sync": report["summary"]["multipart_files_active_after_report_sync"],
        }
        reports = data.get("reports")
        if isinstance(reports, list):
            for item in (
                report_relpath("body_processor_analysis", "json"),
                report_relpath("body_processor_analysis", "md"),
            ):
                if item not in reports:
                    reports.append(item)
            data["reports"] = reports
        write_json(json_path, data)

    md_path = report_path_from_root(report_dir, "full_run_evidence", "md")
    text = read_text(md_path)
    if text:
        section = "\n".join(
            [
                "## Body Processor Analysis",
                f"- Body processor analysis: `{report_relpath('body_processor_analysis', 'md')}`",
                f"- URL-encoded/form rows: **{report['summary']['urlencoded_form_subcluster_count']}** -> **{report['summary']['urlencoded_form_active_after_report_sync']}** active request_body_processor rows after report sync.",
                f"- XML processor activation-missing rows: **{report['summary']['xml_activation_missing_subcluster_count']}** -> **{report['summary']['xml_processor_active_after_report_sync']}** active xml_processor rows after report sync.",
                f"- Multipart processor activation-missing rows: **{report['summary']['multipart_activation_missing_subcluster_count']}** -> **{report['summary']['multipart_files_active_after_report_sync']}** active multipart_files rows after report sync.",
                "- The URL-encoded rows have body and Content-Type evidence and are kept as report-only with-MRTS DetectionOnly overlay cases.",
                "- The XML rows have body and XML Content-Type evidence, but their fixtures do not enable the XML request body processor.",
                "- The Multipart rows have body, Content-Type, and boundary evidence, but their fixtures do not enable request body access before expecting FILES/ARGS_NAMES collection evidence.",
            ]
        )
        updated = replace_marked_section(
            text,
            "<!-- body-processor-analysis:start -->",
            "<!-- body-processor-analysis:end -->",
            section,
        )
        write_text_file(md_path, updated)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector-root", type=Path, default=Path.cwd())
    parser.add_argument("--framework-root", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=None)
    return parser.parse_args()


def body_processor_roots(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    connector_root = args.connector_root.resolve()
    framework_root = (args.framework_root or connector_root / "modules/ModSecurity-test-Framework").resolve()
    output_dir = resolve_output_dir(connector_root, args.output_dir, REPORT_DIR)
    add_safe_roots(connector_root, framework_root, connector_root / REPORT_DIR)
    add_report_roots(connector_root / REPORT_DIR)
    return connector_root, framework_root, output_dir


def main() -> int:
    args = parse_args()
    connector_root, framework_root, output_dir = body_processor_roots(args)
    report = build_report(connector_root, framework_root)
    metadata = build_metadata(
        generated_by="ci/evidence/reports/generate-body-processor-analysis.py",
        make_target="generate-body-processor-analysis",
        connector_root=connector_root,
        framework_root=framework_root,
        inputs=report["source_reports"].values(),
        generated_at=report["generated_at"],
    )
    write_text_file(report_path_from_root(output_dir, "body_processor_analysis", "json"), generated_json_text(report, metadata))
    write_text_file(report_path_from_root(output_dir, "body_processor_analysis", "md"), generated_markdown_text(render_markdown(report), metadata))
    update_full_run_evidence(output_dir, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
