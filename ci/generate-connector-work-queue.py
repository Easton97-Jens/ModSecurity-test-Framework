#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


CONNECTORS = ("apache", "nginx", "haproxy")
TEST_VARIANTS = ("no-crs", "with-crs")
MRTS_VARIANTS = ("no-mrts", "with-mrts")
WITH_MRTS_DETECTION_ONLY_CLASSIFICATION = "with_mrts_detection_only_non_disruptive"
WITH_MRTS_DETECTION_ONLY_WORK_DIRECTION = "classification_only"
WITH_MRTS_DETECTION_ONLY_PRIORITY = "report_only"
NO_MRTS_NOMATCH_SEMANTIC_GROUPS = {
    "transformation_request_literal_no_match": {
        "case_ids": {
            "sqli_like_keyword_spacing_probe",
            "sqli_like_quote_encoding_runtime_difference",
            "unicode_double_encoded_uri_runtime_difference",
            "unicode_whitespace_normalization_gap",
            "xss_like_encoded_angles_normalization_probe",
            "xss_like_mixed_case_script_token_gap",
        },
        "work_direction": "transformation_semantics",
        "priority": "P3",
    },
    "collection_name_normalization_semantics": {
        "case_ids": {
            "duplicate_args_encoded_separator_edge",
            "duplicate_header_case_normalization_gap",
            "edge_semicolon_query_args_names",
            "v3_request_cookies_names_case_runtime_difference",
            "v3_request_headers_names_lowercase_runtime_difference",
        },
        "work_direction": "collection_semantics",
        "priority": "P3",
    },
    "xml_processor_activation_missing": {
        "case_ids": {
            "parser_xml_partial_body_future_target",
            "xml_deep_nesting_future_target",
            "xml_namespace_edge_connector_gap",
            "xml_request_body_malformed_connector_gap",
        },
        "work_direction": "classification_only",
        "priority": "report_only",
    },
    "multipart_processor_activation_missing": {
        "case_ids": {
            "files_names_mixed_case_filename_gap",
            "multipart_duplicate_field_names_gap",
        },
        "work_direction": "classification_only",
        "priority": "report_only",
    },
    "phase1_request_body_unavailable": {
        "case_ids": {
            "phase1_vs_phase2_request_body_gap",
        },
        "work_direction": "request_body_processor",
        "priority": "P3",
    },
}
NO_MRTS_NOMATCH_BY_CASE = {
    case_id: {
        "classification": classification,
        "work_direction": data["work_direction"],
        "priority": data["priority"],
    }
    for classification, data in NO_MRTS_NOMATCH_SEMANTIC_GROUPS.items()
    for case_id in data["case_ids"]
}
RULE_TARGET_RE = re.compile(r"^\s*SecRule\s+([^\s]+)\s+")
PHASE_RE = re.compile(r"phase:(\d)")
DEFAULT_RUN_ROOT = Path(os.environ.get("VERIFIED_RUN_ROOT", str(Path(os.environ.get("RUNNER_TEMP") or os.environ.get("TMPDIR") or "/var/tmp") / "ModSecurity-conector-verified")))
DEFAULT_BUILD_ROOT = Path(os.environ.get("BUILD_ROOT", str(DEFAULT_RUN_ROOT / "build"))).resolve()
MRTS_BUILD_ROOT = Path(os.environ.get("MRTS_BUILD_ROOT", str(DEFAULT_BUILD_ROOT / "mrts"))).resolve()
MRTS_ROOT = Path(os.environ.get("MRTS_ROOT", "")).resolve() if os.environ.get("MRTS_ROOT") else None
MRTS_UPSTREAM_CASE_ROOT = MRTS_BUILD_ROOT / "upstream-config-tests/framework-cases"
MRTS_FEATURE_DEMO_CASE_ROOT = MRTS_BUILD_ROOT / "feature-demo/framework-cases"


@dataclass
class CaseMeta:
    case_id: str
    path: str
    source_kind: str
    category: str = "unknown"
    mrts_corpus: str = "none"
    phase: str = "unknown"
    variables: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    classification: str = "active"
    connector_observations: dict[str, Any] = field(default_factory=dict)


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def read_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return raw if isinstance(raw, dict) else {}


def norm(value: Any) -> str:
    return str(value or "").strip()


def token(value: Any) -> str:
    return norm(value).lower().replace("_", "-")


def rel_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve(strict=False).relative_to(root.resolve(strict=False)))
    except ValueError:
        return str(path)


def path_under(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return False
    return True


def listify(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [str(key) for key, enabled in value.items() if enabled]
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if value:
        return [str(value)]
    return []


def metadata_variables(data: dict[str, Any], rules: str) -> list[str]:
    variables: set[str] = set()
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    raw_variables = metadata.get("variables")
    if isinstance(raw_variables, list):
        variables.update(str(item) for item in raw_variables if str(item).strip())
    for line in rules.splitlines():
        match = RULE_TARGET_RE.search(line)
        if match:
            variables.add(match.group(1))
    return sorted(variables)


def metadata_phase(data: dict[str, Any], capabilities: list[str], rules: str) -> str:
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    raw = metadata.get("phase")
    if isinstance(raw, int):
        return str(raw)
    if isinstance(raw, str) and raw.strip().isdigit():
        return raw.strip()
    for cap in capabilities:
        match = re.fullmatch(r"phase[-_]?([1-4])", token(cap))
        if match:
            return match.group(1)
    match = PHASE_RE.search(rules)
    if match:
        return match.group(1)
    return "unknown"


def source_kind_for(path: Path, framework_root: Path, metadata: dict[str, Any]) -> tuple[str, str]:
    mrts_corpus = norm(metadata.get("mrts_corpus")) or "none"
    if mrts_corpus and mrts_corpus != "none":
        if mrts_corpus == "feature-demo":
            return "feature-demo-report-only", mrts_corpus
        return "mrts-imported", mrts_corpus
    if path_under(path, MRTS_UPSTREAM_CASE_ROOT):
        return "mrts-imported", "upstream-config-tests"
    if path_under(path, MRTS_FEATURE_DEMO_CASE_ROOT):
        return "feature-demo-report-only", "feature-demo"
    if MRTS_ROOT and (
        path_under(path, MRTS_ROOT / "generated")
        or path_under(path, MRTS_ROOT / "feature_demo/generated")
    ):
        return "golden-only", "upstream-generated"
    return "framework-owned", "none"


def load_cases(framework_root: Path) -> tuple[dict[str, CaseMeta], dict[str, CaseMeta], Counter[str]]:
    by_id: dict[str, CaseMeta] = {}
    by_path: dict[str, CaseMeta] = {}
    counts: Counter[str] = Counter()
    roots = [
        framework_root / "tests/cases",
        MRTS_UPSTREAM_CASE_ROOT,
        MRTS_FEATURE_DEMO_CASE_ROOT,
    ]
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.yaml")):
            data = read_yaml(path)
            metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
            rules = str(data.get("rules") or "")
            capabilities = listify(data.get("capabilities"))
            source_kind, mrts_corpus = source_kind_for(path, framework_root, metadata)
            case_id = norm(data.get("name")) or path.stem
            classification = norm(metadata.get("classification"))
            if not classification:
                classification = "unclassified" if source_kind in {"mrts-imported", "feature-demo-report-only"} else "active"
            meta = CaseMeta(
                case_id=case_id,
                path=rel_path(path, framework_root),
                source_kind=source_kind,
                category=norm(data.get("category")) or "unknown",
                mrts_corpus=mrts_corpus,
                phase=metadata_phase(data, capabilities, rules),
                variables=metadata_variables(data, rules),
                capabilities=capabilities,
                classification=classification,
                connector_observations=metadata.get("connector_observations", {}) if isinstance(metadata.get("connector_observations"), dict) else {},
            )
            counts[source_kind] += 1
            if source_kind != "golden-only":
                by_id[case_id] = meta
                by_path[str(path.resolve(strict=False))] = meta
                by_path[meta.path] = meta
    return by_id, by_path, counts


def load_full_matrix(connector_root: Path, explicit: Path | None) -> dict[str, Any]:
    path = explicit or connector_root / "reports/testing/generated/canonical/full-runtime-matrix.generated.json"
    if not path.is_file():
        return {"runs": [], "missing_full_matrix": str(path)}
    data = read_json(path)
    return data if isinstance(data, dict) else {"runs": []}


def runtime_status(case: dict[str, Any]) -> str:
    value = token(case.get("status") or case.get("result"))
    if value == "pass":
        return "PASS"
    if value == "fail":
        return "FAIL"
    if value == "blocked":
        return "BLOCKED"
    if value in {"not-executable", "not-executed"}:
        return "NOT_EXECUTABLE"
    return "UNKNOWN"


def status_int(case: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = case.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
    return None


def lookup_meta(case_id: str, case: dict[str, Any], by_id: dict[str, CaseMeta], by_path: dict[str, CaseMeta]) -> CaseMeta:
    path = norm(case.get("path") or case.get("test_case"))
    if path in by_path:
        return by_path[path]
    if case_id in by_id:
        return by_id[case_id]
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    path_obj = Path(path) if path else Path("/__missing_case__")
    source_kind, mrts_corpus = source_kind_for(path_obj, Path("/__missing_framework_root__"), metadata)
    if source_kind == "framework-owned" and "/upstream-config-tests/framework-cases/" in path:
        source_kind, mrts_corpus = "mrts-imported", "upstream-config-tests"
    elif source_kind == "framework-owned" and "/feature-demo/framework-cases/" in path:
        source_kind, mrts_corpus = "feature-demo-report-only", "feature-demo"
    capabilities = listify(case.get("capabilities"))
    return CaseMeta(
        case_id=case_id,
        path=path,
        source_kind=source_kind if source_kind != "framework-owned" and path else "framework-owned",
        category=norm(case.get("category")) or "unknown",
        mrts_corpus=mrts_corpus,
        phase=metadata_phase({"metadata": metadata}, capabilities, ""),
        variables=listify(metadata.get("variables")),
        capabilities=capabilities,
        classification=norm(metadata.get("classification")) or ("unclassified" if mrts_corpus != "none" else "active"),
        connector_observations=metadata.get("connector_observations", {}) if isinstance(metadata.get("connector_observations"), dict) else {},
    )


def functional_areas(meta: CaseMeta, case: dict[str, Any]) -> list[str]:
    values = {token(item) for item in [meta.category, *meta.variables, *meta.capabilities, meta.case_id]}
    areas: set[str] = set()
    variable_map = {
        "args": "args",
        "args-names": "args_names",
        "request-headers": "request_headers",
        "request-headers-names": "request_headers_names",
        "request-cookies": "request_cookies",
        "request-cookies-names": "request_cookies_names",
        "request-uri": "request_uri",
        "request-body": "request_body_urlencoded",
        "xml": "request_body_xml",
        "files": "multipart_files",
        "files-names": "multipart_files",
        "response-headers": "response_headers",
        "response-body": "response_body",
    }
    for value, area in variable_map.items():
        if value in values:
            areas.add(area)
    text = " ".join(values)
    substring_variable_map = {
        "args-names": "args_names",
        "args": "args",
        "request-cookies-names": "request_cookies_names",
        "request-cookies": "request_cookies",
        "request-headers-names": "request_headers_names",
        "request-headers": "request_headers",
        "request-uri": "request_uri",
        "request-body": "request_body_urlencoded",
        "response-headers": "response_headers",
        "response-body": "response_body",
    }
    for value, area in substring_variable_map.items():
        if value in text:
            areas.add(area)
    if "json" in text:
        areas.add("request_body_json")
    if "multipart" in text or "filename" in text:
        areas.add("multipart_files")
    if "audit" in text:
        areas.add("audit_log")
    if "operator" in text or "operators" in text:
        areas.add("operators")
    if "transformation" in text or "transformations" in text:
        areas.add("transformations")
    if "chain" in text:
        areas.add("rule_chain")
    if "secaction" in text:
        areas.add("secaction")
    if "intervention" in text or "actions" in text or case.get("expected_intervention") in {"deny", "block", "redirect"}:
        areas.add("action_intervention")
    return sorted(areas) or ["unknown"]


def failure_patterns(status: str, expected: int | None, actual: int | None) -> list[str]:
    if status == "NOT_EXECUTABLE":
        return ["not_executable"]
    if status == "BLOCKED":
        return ["no_runtime_evidence"]
    if status != "FAIL":
        return []
    if expected in {401, 403, 302} and actual == 200:
        return ["expected_block_got_200"]
    if expected == 403 and actual == 404:
        return ["expected_block_got_404"]
    if expected == 403 and actual == 405:
        return ["expected_block_got_405"]
    if expected == 403 and actual == 501:
        return ["expected_block_got_501"]
    if expected == 200 and actual == 200:
        return ["expected_pass_but_evidence_missing"]
    if actual is None:
        return ["no_runtime_evidence"]
    return [f"expected_{expected}_got_{actual}"]


def response_body_or_phase4(meta: CaseMeta, areas: list[str]) -> bool:
    return meta.phase == "4" or "response_body" in areas


def is_with_mrts_detection_only_non_disruptive(
    mrts_variant: str,
    status: str,
    expected: int | None,
    actual: int | None,
    work_direction: str,
) -> bool:
    return (
        mrts_variant == "with-mrts"
        and work_direction == "intervention_blocking"
        and status == "FAIL"
        and expected in {401, 403, 302}
        and actual == 200
    )


def no_mrts_nomatch_semantic_classification(
    case_id: str,
    mrts_variant: str,
    status: str,
    expected: int | None,
    actual: int | None,
    work_direction: str,
) -> dict[str, str] | None:
    if (
        mrts_variant != "no-mrts"
        or work_direction != "intervention_blocking"
        or status != "FAIL"
        or expected != 403
        or actual != 200
    ):
        return None
    return NO_MRTS_NOMATCH_BY_CASE.get(case_id)


def choose_work_direction(connector: str, patterns: list[str], areas: list[str], phase4_response: bool) -> str:
    pattern_set = set(patterns)
    area_set = set(areas)
    if phase4_response:
        return "response_body_non_promoted"
    if "expected_200_got_0" in pattern_set:
        return "harness_incompatibility"
    if "expected_200_got_404" in pattern_set or "expected_200_got_405" in pattern_set:
        return "request_routing"
    if "expected_200_got_501" in pattern_set:
        if "request_body_xml" in area_set:
            return "xml_processor"
        if "multipart_files" in area_set:
            return "multipart_files"
        if "request_body_json" in area_set or "request_body_urlencoded" in area_set:
            return "request_body_processor"
        return "connector_gap" if connector == "haproxy" else "harness_incompatibility"
    if "expected_block_got_200" in pattern_set:
        return "intervention_blocking"
    if "expected_block_got_404" in pattern_set or "expected_block_got_405" in pattern_set:
        return "request_routing"
    if "expected_block_got_501" in pattern_set:
        if "request_body_xml" in area_set:
            return "xml_processor"
        if "multipart_files" in area_set:
            return "multipart_files"
        if "request_body_json" in area_set or "request_body_urlencoded" in area_set:
            return "request_body_processor"
        return "connector_gap" if connector == "haproxy" else "harness_incompatibility"
    if "expected_pass_but_evidence_missing" in pattern_set:
        return "audit_log_evidence" if "audit_log" in area_set else "harness_incompatibility"
    if "not_executable" in pattern_set or "no_runtime_evidence" in pattern_set:
        return "harness_incompatibility"
    if "operators" in area_set:
        return "operator_semantics"
    if "transformations" in area_set:
        return "transformation_semantics"
    if "response_headers" in area_set:
        return "response_header_hook"
    if "multipart_files" in area_set:
        return "multipart_files"
    if "request_body_json" in area_set:
        return "json_processor"
    if "request_body_xml" in area_set:
        return "xml_processor"
    return "runtime_difference"


def overlay_classification(meta: CaseMeta, connector: str) -> str:
    raw = meta.connector_observations.get(connector)
    if isinstance(raw, dict):
        value = norm(raw.get("classification"))
        if value:
            return value
    return ""


def choose_classification(connector: str, status: str, patterns: list[str], meta: CaseMeta, phase4_response: bool) -> str:
    overlay = overlay_classification(meta, connector)
    if overlay:
        return overlay
    if phase4_response:
        return "response-body-non-promoted"
    if status == "PASS":
        return "pass"
    if status == "NOT_EXECUTABLE":
        return "pending"
    if "expected_block_got_404" in patterns or "expected_block_got_405" in patterns:
        return "harness-incompatibility"
    if "expected_block_got_501" in patterns:
        return "connector-gap" if connector == "haproxy" else "harness-incompatibility"
    if "no_runtime_evidence" in patterns:
        return "harness-incompatibility"
    if meta.classification and token(meta.classification) not in {"active", "unclassified"}:
        return meta.classification
    return "runtime-difference" if status == "FAIL" else "pending"


def initial_priority(status: str, patterns: list[str], areas: list[str], phase4_response: bool) -> str:
    if status == "PASS":
        return "P3" if phase4_response else "P3"
    if phase4_response or status == "NOT_EXECUTABLE":
        return "P3"
    if {"request_body_json", "request_body_xml", "multipart_files", "response_headers"}.intersection(areas):
        return "P2"
    if patterns:
        return "P1"
    return "P3"


def run_summary_path(run: dict[str, Any]) -> Path:
    return Path(norm(run.get("runtime_summary_path") or run.get("summary_path")))


def read_cases_from_summary(summary_path: Path, connector: str) -> dict[str, dict[str, Any]]:
    raw = read_json(summary_path)
    data = raw.get(connector, raw) if isinstance(raw, dict) else {}
    cases = data.get("cases") if isinstance(data, dict) else {}
    return cases if isinstance(cases, dict) else {}


def run_blocked_entry(run: dict[str, Any], summary_path: Path, reason: str | None = None) -> dict[str, Any]:
    connector = norm(run.get("connector"))
    test_variant = norm(run.get("test_variant"))
    mrts_variant = norm(run.get("mrts_variant"))
    log_path = norm(run.get("log_path"))
    return {
        "case_id": f"__run_{connector}_{test_variant}_{mrts_variant}",
        "connector": connector,
        "test_variant": test_variant,
        "mrts_variant": mrts_variant,
        "source_kind": "runtime-job",
        "mrts_corpus": "none",
        "category": "runtime-job",
        "functional_area": ["harness"],
        "phase": "unknown",
        "expected_status": None,
        "actual_status": None,
        "runtime_status": "BLOCKED",
        "failure_pattern": ["no_runtime_evidence"],
        "connector_pattern": ["single_connector_blocked"],
        "classification": "harness-incompatibility",
        "work_direction": ["harness_incompatibility"],
        "priority": "P1",
        "reason": reason or f"summary JSON missing or unreadable: {summary_path}",
        "evidence": log_path,
    }


def collect_entries(full_matrix: dict[str, Any], by_id: dict[str, CaseMeta], by_path: dict[str, CaseMeta]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for run in full_matrix.get("runs", []):
        if not isinstance(run, dict):
            continue
        connector = norm(run.get("connector"))
        if connector not in CONNECTORS:
            continue
        summary_path = run_summary_path(run)
        if not summary_path.is_file():
            entries.append(run_blocked_entry(run, summary_path))
            continue
        try:
            cases = read_cases_from_summary(summary_path, connector)
        except Exception:
            entries.append(run_blocked_entry(run, summary_path))
            continue
        if not cases and (norm(run.get("outcome")).upper() == "BLOCKED" or int(run.get("blocked") or 0) > 0):
            entries.append(run_blocked_entry(run, summary_path, f"runtime summary contains no cases and reports BLOCKED: {summary_path}"))
            continue
        for case_id, case in cases.items():
            if not isinstance(case, dict):
                continue
            meta = lookup_meta(str(case_id), case, by_id, by_path)
            status = runtime_status(case)
            expected = status_int(case, "expected_status", "expected")
            actual = status_int(case, "actual_status", "observed_status", "observed")
            areas = functional_areas(meta, case)
            patterns = failure_patterns(status, expected, actual)
            phase4_response = response_body_or_phase4(meta, areas)
            mrts_variant = norm(run.get("mrts_variant"))
            work_direction = choose_work_direction(connector, patterns, areas, phase4_response)
            classification = choose_classification(connector, status, patterns, meta, phase4_response)
            priority = initial_priority(status, patterns, areas, phase4_response)
            detection_only_overlay = is_with_mrts_detection_only_non_disruptive(
                mrts_variant,
                status,
                expected,
                actual,
                work_direction,
            )
            if detection_only_overlay:
                work_direction = WITH_MRTS_DETECTION_ONLY_WORK_DIRECTION
                classification = WITH_MRTS_DETECTION_ONLY_CLASSIFICATION
                priority = WITH_MRTS_DETECTION_ONLY_PRIORITY
            semantic_nomatch = no_mrts_nomatch_semantic_classification(
                str(case_id),
                mrts_variant,
                status,
                expected,
                actual,
                work_direction,
            )
            if semantic_nomatch:
                work_direction = semantic_nomatch["work_direction"]
                classification = semantic_nomatch["classification"]
                priority = semantic_nomatch["priority"]
            entries.append(
                {
                    "case_id": str(case_id),
                    "connector": connector,
                    "test_variant": norm(run.get("test_variant")),
                    "mrts_variant": mrts_variant,
                    "source_kind": meta.source_kind,
                    "mrts_corpus": meta.mrts_corpus,
                    "category": meta.category,
                    "functional_area": areas,
                    "phase": meta.phase,
                    "expected_status": expected,
                    "actual_status": actual,
                    "runtime_status": status,
                    "failure_pattern": patterns,
                    "connector_pattern": [],
                    "classification": classification,
                    "work_direction": [work_direction],
                    "priority": priority,
                    "reason": norm(case.get("reason")),
                    "evidence": norm(case.get("evidence_path") or case.get("evidence") or summary_path),
                    "summary_path": str(summary_path),
                }
            )
    apply_connector_patterns(entries)
    apply_priority_rules(entries)
    return entries


def connector_pattern_name(connectors: set[str]) -> str:
    if connectors == set(CONNECTORS):
        return "all_connectors_fail"
    if connectors == {"apache"}:
        return "apache_only_fail"
    if connectors == {"nginx"}:
        return "nginx_only_fail"
    if connectors == {"haproxy"}:
        return "haproxy_only_fail"
    if connectors == {"apache", "nginx"}:
        return "apache_nginx_fail"
    if connectors == {"apache", "haproxy"}:
        return "apache_haproxy_fail"
    if connectors == {"nginx", "haproxy"}:
        return "nginx_haproxy_fail"
    return "mixed_connector_status"


def apply_connector_patterns(entries: list[dict[str, Any]]) -> None:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        grouped[(entry["case_id"], entry["test_variant"], entry["mrts_variant"])].append(entry)
    for rows in grouped.values():
        failing = {row["connector"] for row in rows if row["runtime_status"] == "FAIL"}
        if not failing:
            continue
        pattern = connector_pattern_name(failing)
        actuals = {row["actual_status"] for row in rows if row.get("actual_status") is not None}
        for row in rows:
            if row["connector"] in failing:
                row["connector_pattern"] = [pattern]
                if len(actuals) > 1:
                    row["connector_pattern"].append("different_actual_statuses")


def apply_priority_rules(entries: list[dict[str, Any]]) -> None:
    high_volume: set[tuple[str, str]] = set()
    counts: Counter[tuple[str, str]] = Counter()
    for entry in entries:
        for pattern in entry["failure_pattern"]:
            if entry["runtime_status"] == "FAIL":
                counts[(entry["connector"], pattern)] += 1
    for key, count in counts.items():
        if count >= 10:
            high_volume.add(key)
    for entry in entries:
        if entry.get("classification") == WITH_MRTS_DETECTION_ONLY_CLASSIFICATION:
            entry["priority"] = WITH_MRTS_DETECTION_ONLY_PRIORITY
            continue
        semantic = NO_MRTS_NOMATCH_SEMANTIC_GROUPS.get(str(entry.get("classification") or ""))
        if semantic:
            entry["priority"] = semantic["priority"]
            continue
        patterns = set(entry["failure_pattern"])
        connectors = set(entry["connector_pattern"])
        areas = set(entry["functional_area"])
        phase4_response = entry.get("phase") == "4" or "response_body" in areas
        if phase4_response:
            entry["priority"] = "P3"
            continue
        if (
            "all_connectors_fail" in connectors
            and "expected_block_got_200" in patterns
            and ("action_intervention" in areas or "secaction" in areas)
        ):
            entry["priority"] = "P0"
        elif any((entry["connector"], pattern) in high_volume for pattern in patterns) and entry["runtime_status"] == "FAIL":
            if entry["priority"] != "P0":
                entry["priority"] = "P1"


def count_by(entries: list[dict[str, Any]], key: str, *, connector: str | None = None) -> Counter[str]:
    counts: Counter[str] = Counter()
    for entry in entries:
        if connector and entry["connector"] != connector:
            continue
        value = entry.get(key)
        if isinstance(value, list):
            for item in value:
                counts[str(item)] += 1
        else:
            counts[str(value)] += 1
    return counts


def fmt_counts(counter: Counter[str], limit: int = 5) -> str:
    return ", ".join(f"{name}({count})" for name, count in counter.most_common(limit)) or "-"


def markdown_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |"]
    lines.append("|" + "|".join("---" for _ in headers) + "|")
    if not rows:
        lines.append("| " + " | ".join("-" for _ in headers) + " |")
        return lines
    for row in rows:
        lines.append("| " + " | ".join(str(item).replace("\n", " ") if item is not None else "-" for item in row) + " |")
    return lines


def render_markdown(entries: list[dict[str, Any]], source_counts: Counter[str], runtime_source_counts: Counter[str], generated_at: str) -> str:
    failures = [entry for entry in entries if entry["runtime_status"] == "FAIL"]
    non_pass = [entry for entry in entries if entry["runtime_status"] != "PASS"]
    priority_counts = count_by(non_pass, "priority")
    lines: list[str] = [
        "# Connector Work Queue",
        "",
        "Generated file - do not edit manually.",
        "",
        "## Executive Summary",
        f"- Generated at: `{generated_at}`",
        f"- Total runtime cases analyzed: **{len(entries)}**",
        f"- Total failures: **{len(failures)}**",
        f"- P0/P1/P2/P3: **{priority_counts['P0']}** / **{priority_counts['P1']}** / **{priority_counts['P2']}** / **{priority_counts['P3']}**",
        f"- Source inventory split: framework-owned({source_counts['framework-owned']}), MRTS imported({source_counts['mrts-imported']}), feature-demo report-only({source_counts['feature-demo-report-only']}), golden-only({source_counts['golden-only']})",
        f"- Runtime source split: framework-owned({runtime_source_counts['framework-owned']}), MRTS imported({runtime_source_counts['mrts-imported']}), feature-demo report-only({runtime_source_counts['feature-demo-report-only']}), golden-only({runtime_source_counts['golden-only']}), runtime-job({runtime_source_counts['runtime-job']})",
        "",
        "## Per Connector Summary",
    ]
    for connector in CONNECTORS:
        connector_entries = [entry for entry in entries if entry["connector"] == connector and entry["runtime_status"] != "PASS"]
        lines.extend(
            [
                f"### {connector}",
                f"- Top failure patterns: {fmt_counts(count_by(connector_entries, 'failure_pattern'))}",
                f"- Top functional areas: {fmt_counts(count_by(connector_entries, 'functional_area'))}",
                f"- Top work directions: {fmt_counts(count_by(connector_entries, 'work_direction'))}",
                f"- Recommended next work: {fmt_counts(count_by(connector_entries, 'work_direction'), 1)}",
                "",
            ]
        )

    lines.append("## Cross-Connector Comparison")
    for name in [
        "all_connectors_fail",
        "apache_only_fail",
        "nginx_only_fail",
        "haproxy_only_fail",
        "different_actual_statuses",
    ]:
        cases = sorted({entry["case_id"] for entry in failures if name in entry["connector_pattern"]})
        lines.append(f"- {name}: **{len(cases)}**" + (f" - {', '.join(cases[:10])}" if cases else ""))

    lines.extend(["", "## Work Direction Summary"])
    rows = []
    directions = sorted(count_by(non_pass, "work_direction"))
    for direction in directions:
        rows.append([direction, *(count_by(non_pass, "work_direction", connector=connector)[direction] for connector in CONNECTORS), count_by(non_pass, "work_direction")[direction]])
    lines.extend(markdown_table(["work_direction", "apache", "nginx", "haproxy", "total"], rows))

    lines.extend(["", "## Failure Pattern Summary"])
    rows = []
    patterns = sorted(count_by(non_pass, "failure_pattern"))
    for pattern in patterns:
        rows.append([pattern, *(count_by(non_pass, "failure_pattern", connector=connector)[pattern] for connector in CONNECTORS), count_by(non_pass, "failure_pattern")[pattern]])
    lines.extend(markdown_table(["failure_pattern", "apache", "nginx", "haproxy", "total"], rows))

    lines.extend(["", "## Prioritized Work Queue"])
    queue = sorted(
        non_pass,
        key=lambda item: ({"P0": 0, "P1": 1, "P2": 2, "P3": 3}.get(item["priority"], 4), item["connector"], item["case_id"]),
    )
    rows = [
        [
            item["priority"],
            item["connector"],
            item["test_variant"],
            item["mrts_variant"],
            item["case_id"],
            ", ".join(item["functional_area"]),
            ", ".join(item["failure_pattern"]) or "-",
            item["classification"],
            ", ".join(item["work_direction"]),
            item["reason"] or "-",
            item["evidence"] or item.get("summary_path", "-"),
        ]
        for item in queue[:200]
    ]
    lines.extend(markdown_table(["priority", "connector", "test_variant", "mrts_variant", "case", "functional_area", "failure_pattern", "classification", "work_direction", "reason", "evidence"], rows))

    lines.extend(["", "## MRTS-only Section"])
    mrts_entries = [entry for entry in entries if entry["mrts_corpus"] == "upstream-config-tests"]
    rows = []
    for connector in CONNECTORS:
        connector_rows = [entry for entry in mrts_entries if entry["connector"] == connector]
        status_counts = count_by(connector_rows, "runtime_status")
        rows.append([connector, len(connector_rows), status_counts["PASS"], status_counts["FAIL"], status_counts["BLOCKED"], fmt_counts(count_by([entry for entry in connector_rows if entry["runtime_status"] != "PASS"], "work_direction"))])
    lines.extend(markdown_table(["connector", "attempted", "pass", "fail", "blocked", "top work directions"], rows))
    lines.append("- Feature-demo: visible as report-only unless `MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO=1` is set.")
    lines.append("- Golden references: drift/reference only, never runtime input.")

    lines.extend(
        [
            "",
            "## Guardrails",
            "- Runtime PASS/FAIL/BLOCKED comes from connector summary JSON only.",
            "- Classification does not alter expected or actual status.",
            "- `no-mrts` variants must not contain MRTS runtime cases.",
            "- `with-mrts` variants include only selected MRTS runtime cases.",
            "- MRTS golden outputs under the submodule are drift/reference only.",
            "- Generated MRTS artifacts remain ignored and uncommitted.",
        ]
    )
    return "\n".join(lines) + "\n"



def require_under(root: Path, candidate: Path, label: str) -> Path:
    root = root.resolve()
    candidate = candidate.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise SystemExit(f"{label} must stay under {root}: {candidate}") from exc
    return candidate

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--framework-root", default=Path(__file__).resolve().parents[1])
    parser.add_argument("--connector-root", default=Path.cwd())
    parser.add_argument("--output-root", default=None)
    parser.add_argument("--full-runtime-matrix", default=None)
    args = parser.parse_args()

    framework_root = Path(args.framework_root).resolve()
    connector_root = Path(args.connector_root).resolve()
    framework_ci = framework_root / "ci"
    if str(framework_ci) not in sys.path:
        sys.path.insert(0, str(framework_ci))
    from generated_report_utils import build_metadata, generated_json_text, generated_markdown_text, report_path_from_root

    output_root = Path(args.output_root).resolve() if args.output_root else connector_root
    output_dir = require_under(output_root, output_root / "reports/testing/generated", "generated report directory")
    full_matrix_path = Path(args.full_runtime_matrix).resolve() if args.full_runtime_matrix else None

    by_id, by_path, source_counts = load_cases(framework_root)
    full_matrix = load_full_matrix(connector_root, full_matrix_path)
    entries = collect_entries(full_matrix, by_id, by_path)
    runtime_source_counts = count_by(entries, "source_kind")

    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    payload = {
        "generated_at": generated_at,
        "framework_root": str(framework_root),
        "connector_root": str(connector_root),
        "source_counts": dict(source_counts),
        "runtime_source_counts": dict(runtime_source_counts),
        "totals": {
            "entries": len(entries),
            "failures": sum(1 for entry in entries if entry["runtime_status"] == "FAIL"),
            "priority": dict(count_by([entry for entry in entries if entry["runtime_status"] != "PASS"], "priority")),
        },
        "entries": entries,
        "guardrails": {
            "feature_demo_runtime_cases": sum(1 for entry in entries if entry["source_kind"] == "feature-demo-report-only"),
            "golden_runtime_cases": sum(1 for entry in entries if entry["source_kind"] == "golden-only"),
            "no_mrts_mrts_runtime_cases": sum(1 for entry in entries if entry["mrts_variant"] == "no-mrts" and entry["mrts_corpus"] != "none"),
        },
    }
    metadata = build_metadata(
        generated_by="framework:ci/generate-connector-work-queue.py",
        make_target="generate-work-queue",
        connector_root=connector_root,
        framework_root=framework_root,
        inputs=[full_matrix_path or connector_root / "reports/testing/generated/canonical/full-runtime-matrix.generated.json"],
        generated_at=generated_at,
    )
    json_path = report_path_from_root(output_dir, "connector_work_queue", "json")
    md_path = report_path_from_root(output_dir, "connector_work_queue", "md")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(generated_json_text(payload, metadata), encoding="utf-8")
    md_path.write_text(generated_markdown_text(render_markdown(entries, source_counts, runtime_source_counts, generated_at), metadata), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
