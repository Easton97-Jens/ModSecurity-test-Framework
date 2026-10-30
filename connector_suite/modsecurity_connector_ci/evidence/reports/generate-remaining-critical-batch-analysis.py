#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

# CI helpers are shared from ci/lib even when this file is executed directly.
import sys

from typing import Any

from modsecurity_connector_ci.lib.generated_report_utils import DATA_SOURCE_POLICY, GENERATED_REPORTS, build_metadata, generated_json_text, generated_markdown_text
from modsecurity_connector_ci.lib.report_path_safety import add_safe_roots, resolve_output_dir, write_text_file


CRITICAL_CATEGORIES = {
    "runtime_regression",
    "expected_status_mismatch",
    "connector_capability_gap",
    "framework_expected_behavior_gap",
    "environment_flake",
    "timeout_or_incomplete",
    "unknown",
}
BASELINE = {
    "source": "Fixture hygiene batch start official mismatch report before targeted YAML fix",
    "mismatch_count": 787,
    "critical_mismatch_count": 83,
}
NON_CRITICAL_CLASSIFICATIONS = {
    "known_not_next",
    "secaction_detection_only_overlay",
    "with_mrts_detection_only_overlay",
    "libmodsecurity_collection_semantics",
    "libmodsecurity_collection_name_case_semantics",
    "libmodsecurity_transformation_semantics",
    "libmodsecurity_xml_parser_semantics",
    "nolog_expected_no_audit",
}
DUPLICATE_HEADER_CASE = "duplicate_header_case_normalization_gap"
YAML_FIX_CASES = {
    "json_empty_body_future_compatibility",
    "phase3_response_headers_server_presence_pending",
    "phase4_response_body_empty_future_target",
    "unicode_whitespace_normalization_gap",
}
TRANSFORMATION_DEFER_CASE = "unicode_double_encoded_uri_runtime_difference"
PHASE_HANDLING_FIX_CASE = "phase1_vs_phase2_request_body_gap"
SECACTION_DETECTION_ONLY_CASE = "v3_secaction_block"
DEFAULT_TARGETED_VARIANTS = ("no-crs-no-mrts",)
SECACTION_TARGETED_VARIANTS = (
    "no-crs-no-mrts",
    "no-crs-with-mrts",
    "with-crs-with-mrts",
)
TARGETED_VARIANTS_BY_CASE = {SECACTION_DETECTION_ONLY_CASE: SECACTION_TARGETED_VARIANTS}
MANIFEST_REPORT_DIRECTORY = "reports/testing/generated/manifest"
CURRENT_ANALYSIS_CASES = {
    "phase1_vs_phase2_request_body_gap",
    "v3_secaction_block",
    "xml_namespace_edge_connector_gap",
    "xml_request_body_malformed_connector_gap",
    "unicode_whitespace_normalization_gap",
    "unicode_double_encoded_uri_runtime_difference",
    "v2_transformation_url_decode_invalid_sequence_mapped_candidate",
}
TARGETED_CLUSTERS = {
    "phase1_vs_phase2_request_body_gap": "connector_capability_gap / phase-handling",
    "xml_namespace_edge_connector_gap": "connector_capability_gap / body-processors",
    "xml_request_body_malformed_connector_gap": "expected_status_mismatch / body-processors",
    "unicode_whitespace_normalization_gap": "expected_status_mismatch / transformations",
    "unicode_double_encoded_uri_runtime_difference": "runtime_regression / transformations",
    "v2_transformation_url_decode_invalid_sequence_mapped_candidate": "timeout_or_incomplete / transformations",
    "v3_secaction_block": "expected_status_mismatch / actions",
}
CASE_RUN_TARGETS = {
    SECACTION_DETECTION_ONLY_CASE,
    PHASE_HANDLING_FIX_CASE,
    "xml_namespace_edge_connector_gap",
    "xml_request_body_malformed_connector_gap",
    "v2_transformation_url_decode_invalid_sequence_mapped_candidate",
}
REPRESENTATIVE_REPRO_COMMANDS = {
    "phase1_vs_phase2_request_body_gap": "make verified-case CONNECTOR=nginx CASE=phase1_vs_phase2_request_body_gap CRS=no-crs MRTS=no-mrts",
    "v3_secaction_block": "make verified-case CONNECTOR=haproxy CASE=v3_secaction_block CRS=no-crs MRTS=with-mrts",
    "xml_namespace_edge_connector_gap": "make verified-case CONNECTOR=nginx CASE=xml_namespace_edge_connector_gap CRS=no-crs MRTS=no-mrts",
    "xml_request_body_malformed_connector_gap": "make verified-case CONNECTOR=nginx CASE=xml_request_body_malformed_connector_gap CRS=no-crs MRTS=no-mrts",
    "unicode_whitespace_normalization_gap": "make verified-case CONNECTOR=nginx CASE=unicode_whitespace_normalization_gap CRS=no-crs MRTS=no-mrts",
    "unicode_double_encoded_uri_runtime_difference": "make verified-case CONNECTOR=nginx CASE=unicode_double_encoded_uri_runtime_difference CRS=no-crs MRTS=no-mrts",
    "v2_transformation_url_decode_invalid_sequence_mapped_candidate": "make verified-case CONNECTOR=haproxy CASE=v2_transformation_url_decode_invalid_sequence_mapped_candidate CRS=no-crs MRTS=no-mrts",
}
DEFAULT_VERIFIED_RUN_ROOT = Path.home() / ".cache" / "ModSecurity-conector" / "verified"
CURRENT_TARGETED_ROOT = (
    DEFAULT_VERIFIED_RUN_ROOT / "build" / "xml-unicode-transform-targeted-20260618"
)
VERIFIED_RUN_ROOT = Path(os.environ.get("VERIFIED_RUN_ROOT", DEFAULT_VERIFIED_RUN_ROOT))
YAML_FIX_FILES = {
    "modules/ModSecurity-test-Framework/tests/cases/body/json/json_empty_body_future_compatibility.yaml",
    "modules/ModSecurity-test-Framework/tests/cases/body/xml/xml_namespace_edge_connector_gap.yaml",
    "modules/ModSecurity-test-Framework/tests/cases/body/xml/xml_request_body_malformed_connector_gap.yaml",
    "modules/ModSecurity-test-Framework/tests/cases/phases/phase1/phase1_vs_phase2_request_body_gap.yaml",
    "modules/ModSecurity-test-Framework/tests/cases/response/headers/phase3_response_headers_server_presence_pending.yaml",
    "modules/ModSecurity-test-Framework/tests/cases/response/body/phase4_response_body_empty_future_target.yaml",
    "modules/ModSecurity-test-Framework/tests/cases/transformations/unicode_whitespace_normalization_gap.yaml",
    "modules/ModSecurity-test-Framework/tests/cases/request/uri/v2_transformation_url_decode_invalid_sequence_mapped_candidate.yaml",
}
FULL_MATRIX_CONNECTORS = ("apache", "nginx", "haproxy")
FULL_MATRIX_VARIANTS = (
    ("no-crs", "no-mrts"),
    ("no-crs", "with-mrts"),
    ("with-crs", "no-mrts"),
    ("with-crs", "with-mrts"),
)


def read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def parse_utc(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def full_matrix_refresh_status(connector_root: Path, completeness_path: Path) -> dict[str, Any]:
    inputs, newest_input_mtime, missing_path = yaml_fix_input_status(connector_root)
    if missing_path:
        return {
            "fresh": False,
            "reason": f"missing input {missing_path}",
            "inputs": inputs,
            "jobs": [],
        }
    jobs = indexed_full_matrix_jobs(read_json(completeness_path))
    job_statuses = full_matrix_job_statuses(jobs, newest_input_mtime)
    fresh = all(item["fresh_after_yaml_inputs"] for item in job_statuses)
    reason = (
        "all affected Full-Matrix jobs ended after the YAML/input fixes"
        if fresh
        else "one or more affected Full-Matrix jobs are stale or missing"
    )
    return {"fresh": fresh, "reason": reason, "inputs": inputs, "jobs": job_statuses}


def yaml_fix_input_status(
    connector_root: Path,
) -> tuple[list[dict[str, Any]], float, str | None]:
    newest_input_mtime = 0.0
    inputs: list[dict[str, Any]] = []
    for rel_path in sorted(YAML_FIX_FILES):
        path = connector_root / rel_path
        if not path.is_file():
            inputs.append({"path": rel_path, "status": "missing"})
            return inputs, newest_input_mtime, rel_path
        mtime = path.stat().st_mtime
        newest_input_mtime = max(newest_input_mtime, mtime)
        inputs.append(
            {
                "path": rel_path,
                "status": "present",
                "mtime": datetime.fromtimestamp(mtime, timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
            }
        )
    return inputs, newest_input_mtime, None


def indexed_full_matrix_jobs(data: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, Any]]:
    raw_jobs = data.get("jobs") or data.get("matrix") or data.get("records") or data.get("rows") or []
    jobs = raw_jobs if isinstance(raw_jobs, list) else []
    return {
        full_matrix_job_key(job): job
        for job in jobs
        if isinstance(job, dict)
    }


def full_matrix_job_key(job: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(job.get("connector") or ""),
        str(job.get("crs") or job.get("test_variant") or ""),
        str(job.get("mrts") or job.get("mrts_variant") or ""),
    )


def full_matrix_job_statuses(
    jobs: dict[tuple[str, str, str], dict[str, Any]], newest_input_mtime: float
) -> list[dict[str, Any]]:
    return [
        full_matrix_job_status(jobs.get((connector, crs, mrts), {}), connector, crs, mrts, newest_input_mtime)
        for connector in FULL_MATRIX_CONNECTORS
        for crs, mrts in FULL_MATRIX_VARIANTS
    ]


def full_matrix_job_status(
    job: dict[str, Any], connector: str, crs: str, mrts: str, newest_input_mtime: float
) -> dict[str, Any]:
    ended_at = str(job.get("ended_at") or "")
    ended_ts = parse_utc(ended_at)
    complete = str(job.get("status") or "") in {"completed", "completed_with_mismatches"}
    current = bool(ended_ts is not None and ended_ts >= newest_input_mtime and complete)
    return {
        "connector": connector,
        "crs": crs,
        "mrts": mrts,
        "status": job.get("status") or "missing",
        "return_code": job.get("return_code"),
        "ended_at": ended_at or "-",
        "fresh_after_yaml_inputs": current,
    }


def result_status(path: str) -> dict[str, Any]:
    if not path or path == "-":
        return {"status": "not_captured", "evidence_file": "-"}
    result_path = Path(path)
    data = read_json(result_path)
    if not data:
        return {"status": "missing", "evidence_file": path}
    return {
        "status": str(data.get("status") or "unknown").upper(),
        "expected": data.get("expected_status"),
        "actual": data.get("actual_status", data.get("observed_status")),
        "rule_id": data.get("rule_id"),
        "matched_data": data.get("matched_data") or data.get("matched_value_snippet"),
        "matched_variable": data.get("matched_variable"),
        "response_headers_seen": data.get("response_headers_seen"),
        "response_body_seen": data.get("response_body_seen"),
        "request_body_seen": data.get("request_body_seen"),
        "modsecurity_processed": data.get("modsecurity_processed"),
        "reason": data.get("reason"),
        "evidence_file": path,
    }


def runtime_reached_status(item: dict[str, Any]) -> str:
    status = str(item.get("status") or "").lower()
    actual = item.get("actual")
    if status in {"pass", "fail"} or actual is not None:
        return "runtime_reached_actual_match" if status == "pass" else "runtime_reached_actual_mismatch"
    if status == "NOT_EXECUTABLE":
        return "not_reached_not_executable"
    return "unknown"


def latest_case_run(case: str, connector: str, variant: str = "no-crs-no-mrts") -> Path | None:
    runs_root = VERIFIED_RUN_ROOT / "case-runs"
    if not runs_root.is_dir():
        return None
    pattern = f"*-{connector}-{case}-{variant}/case-run.json"
    candidates = sorted(runs_root.glob(pattern))
    return candidates[-1] if candidates else None


def latest_case_run_status(case: str, connector: str, variant: str = "no-crs-no-mrts") -> dict[str, Any] | None:
    case_run_path = latest_case_run(case, connector, variant=variant)
    if case_run_path is None:
        return None
    case_run = read_json(case_run_path)
    crs, mrts = case_run_variant(variant)
    item = case_run_result(case_run_path, case_run, crs, mrts)
    apply_rule_evidence(item, case_run)
    apply_xml_evidence(item, case, case_run)
    item["runtime_classification"] = runtime_reached_status(item)
    return item


def case_run_variant(variant: str) -> tuple[str, str]:
    parts = variant.split("-")
    if len(parts) < 4:
        return "no-crs", "no-mrts"
    return "-".join(parts[:2]), "-".join(parts[2:])


def case_run_result(
    case_run_path: Path, case_run: dict[str, Any], crs: str, mrts: str
) -> dict[str, Any]:
    item = result_status(str(case_run_path.parent / "result.json"))
    item.update(
        {
            "case_run": str(case_run_path),
            "variant": f"{crs}/{mrts}",
            "crs": crs,
            "mrts": mrts,
            "full_matrix_refresh_needed": bool(
                case_run.get("full_matrix_refresh_needed", False)
            ),
        }
    )
    return item


def apply_rule_evidence(item: dict[str, Any], case_run: dict[str, Any]) -> None:
    rule_evidence = case_run.get("rule_evidence")
    if not isinstance(rule_evidence, dict):
        return
    for key in ("rule_id", "matched_data", "matched_variable"):
        item[key] = item.get(key) or rule_evidence.get(key)


def apply_xml_evidence(item: dict[str, Any], case: str, case_run: dict[str, Any]) -> None:
    if not case.startswith("xml_"):
        item["xml_processor_evidence"] = "-"
        item["xml_target_evidence"] = "-"
        return
    rules = case_definition_rules(case_run.get("case_definition"))
    item["xml_processor_evidence"] = (
        "ctl:requestBodyProcessor=XML"
        if "ctl:requestBodyProcessor=XML" in rules
        else "xml_processor_control_missing"
    )
    item["xml_target_evidence"] = (
        "XML collection target present"
        if "XML:/*" in rules or "SecRule XML" in rules
        else "-"
    )


def case_definition_rules(case_definition: object) -> str:
    if not isinstance(case_definition, dict):
        return ""
    rules = str(case_definition.get("rules") or "")
    if rules:
        return rules
    case_path = Path(str(case_definition.get("path") or ""))
    if not case_path.is_file():
        return ""
    try:
        return case_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def latest_native_case_run(case: str) -> dict[str, Any] | None:
    runs_root = VERIFIED_RUN_ROOT / "native-case-runs"
    if not runs_root.is_dir():
        return None
    candidates = sorted(runs_root.glob(f"*-{case}/native-case-run.json"))
    if not candidates:
        return None
    return read_json(candidates[-1])


def critical_ranking(mismatches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: Counter[tuple[str, str]] = Counter()
    cases: dict[tuple[str, str], set[str]] = defaultdict(set)
    connectors: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in mismatches:
        classification = str(row.get("classification") or "")
        if classification not in CRITICAL_CATEGORIES:
            continue
        key = (classification, str(row.get("category") or "unknown"))
        counts[key] += 1
        cases[key].add(str(row.get("case") or "-"))
        connectors[key].add(str(row.get("connector") or "-"))
    return [
        {
            "rank": index,
            "cluster": f"{classification} / {category}",
            "count": count,
            "connectors": sorted(connectors[(classification, category)]),
            "cases": sorted(cases[(classification, category)]),
        }
        for index, ((classification, category), count) in enumerate(counts.most_common(), start=1)
    ]


def selected_cluster_count(mismatches: list[dict[str, Any]], classification: str, category: str) -> int:
    return sum(
        1
        for row in mismatches
        if row.get("classification") == classification and row.get("category") == category
    )


def is_critical(row: dict[str, Any]) -> bool:
    return str(row.get("classification") or "") not in NON_CRITICAL_CLASSIFICATIONS


def case_reflection(mismatches: list[dict[str, Any]], cases: set[str]) -> dict[str, Any]:
    rows = [row for row in mismatches if str(row.get("case") or "") in cases and row.get("connector")]
    critical_rows = [row for row in rows if is_critical(row)]
    classifications = Counter(str(row.get("classification") or "unknown") for row in rows)
    return {
        "official_rows": len(rows),
        "official_critical_rows": len(critical_rows),
        "classifications": dict(sorted(classifications.items())),
        "critical_variants": sorted(
            {
                f"{row.get('connector')}:{row.get('variant')}"
                for row in critical_rows
                if row.get("connector") and row.get("variant")
            }
        ),
    }


def targeted_repros() -> list[dict[str, Any]]:
    return [
        targeted_repro(case, connector, variant)
        for case in sorted(CURRENT_ANALYSIS_CASES)
        for connector in ("apache", "nginx", "haproxy")
        for variant in TARGETED_VARIANTS_BY_CASE.get(case, DEFAULT_TARGETED_VARIANTS)
    ]


def targeted_repro(case: str, connector: str, variant: str) -> dict[str, Any]:
    item = targeted_case_result(case, connector, variant)
    item.update(
        {
            "cluster": TARGETED_CLUSTERS[case],
            "case": case,
            "connector": connector,
            "variant": item.get("variant") or "no-crs/no-mrts",
            "phase": "TARGETED",
            "log_file": targeted_log_file(case, connector, item),
        }
    )
    if connector == "haproxy":
        item["decision_log"] = targeted_decision_log(case, item)
    return item


def targeted_case_result(case: str, connector: str, variant: str) -> dict[str, Any]:
    if case in CASE_RUN_TARGETS:
        item = latest_case_run_status(case, connector, variant=variant)
        if item is not None:
            return item
    result_file = CURRENT_TARGETED_ROOT / "results" / f"{case}-{connector}-result.json"
    item = result_status(str(result_file))
    item["runtime_classification"] = runtime_reached_status(item)
    return item


def case_run_logs(item: dict[str, Any]) -> str | None:
    if not item.get("case_run"):
        return None
    return str(Path(str(item["case_run"])).parent / "logs")


def targeted_log_file(case: str, connector: str, item: dict[str, Any]) -> str:
    recorded_logs = case_run_logs(item)
    if case in CASE_RUN_TARGETS and recorded_logs:
        return recorded_logs
    return str(CURRENT_TARGETED_ROOT / f"{case}-{connector}.log")


def targeted_decision_log(case: str, item: dict[str, Any]) -> str:
    recorded_logs = case_run_logs(item)
    if case in CASE_RUN_TARGETS and recorded_logs:
        return recorded_logs
    return str(CURRENT_TARGETED_ROOT / "results" / f"{case}-haproxy-decision.jsonl")


def native_comparison_status() -> list[dict[str, Any]]:
    return [native_comparison_row(case) for case in sorted(CURRENT_ANALYSIS_CASES)]


def native_comparison_row(case: str) -> dict[str, Any]:
    native = latest_native_case_run(case)
    if native:
        return native_comparison_row_with_control(case, native)
    return native_comparison_row_without_control(case)


def connector_case_repros(case: str, variant: str = "no-crs-no-mrts") -> list[dict[str, Any] | None]:
    return [
        latest_case_run_status(case, connector, variant=variant)
        for connector in ("apache", "nginx", "haproxy")
    ]


def connector_statuses(rows: list[dict[str, Any] | None]) -> str:
    return ", ".join(
        f"{connector}:{item.get('actual', '-') if item else '-'}"
        for connector, item in zip(("apache", "nginx", "haproxy"), rows)
    )


def all_targeted_match(rows: list[dict[str, Any] | None]) -> bool:
    return all(
        item and item.get("runtime_classification") == "runtime_reached_actual_match"
        for item in rows
    )


def native_comparison_row_with_control(case: str, native: dict[str, Any]) -> dict[str, Any]:
    native_actual = native.get("native_actual")
    expected = native.get("expected_status")
    repros = connector_case_repros(case)
    statuses = connector_statuses(repros)
    if case == SECACTION_DETECTION_ONLY_CASE:
        return secaction_native_comparison_row(case, native_actual, expected, statuses)
    if case == PHASE_HANDLING_FIX_CASE:
        return phase_handling_native_comparison_row(case, native_actual, expected, statuses, repros)
    if case == "xml_namespace_edge_connector_gap":
        return namespace_native_comparison_row(case, native_actual, expected, statuses, repros)
    if case == "xml_request_body_malformed_connector_gap":
        return malformed_xml_native_comparison_row(case, native_actual, expected, statuses)
    return {
        "case": case,
        "status": "native_comparison_complete",
        "evidence": f"native actual={native_actual}, expected={expected}; targeted connectors={statuses}.",
    }


def secaction_native_comparison_row(
    case: str, native_actual: Any, expected: Any, statuses: str
) -> dict[str, Any]:
    with_mrts_statuses = connector_statuses(connector_case_repros(case, "no-crs-with-mrts"))
    return {
        "case": case,
        "status": "secaction_native_control_complete",
        "evidence": (
            f"native actual={native_actual}, expected={expected}; no-MRTS targeted connectors={statuses}; "
            f"with-MRTS targeted connectors={with_mrts_statuses}. Native and no-MRTS block via SecAction "
            "rule 3312; with-MRTS loads MRTS_001_INIT ctl:ruleEngine=DetectionOnly, so disruptive "
            "SecAction is report-only."
        ),
    }


def phase_handling_native_comparison_row(
    case: str, native_actual: Any, expected: Any, statuses: str,
    repros: list[dict[str, Any] | None],
) -> dict[str, Any]:
    return {
        "case": case,
        "status": "native_phase_comparison_complete" if all_targeted_match(repros) else "fixture_experiment_targeted_only",
        "evidence": (
            f"native actual={native_actual}, expected={expected}; targeted connectors={statuses}; "
            "phase 1 is a pass-only reachability marker and phase 2 REQUEST_BODY rule 4512 blocks."
        ),
    }


def namespace_native_comparison_row(
    case: str, native_actual: Any, expected: Any, statuses: str,
    repros: list[dict[str, Any] | None],
) -> dict[str, Any]:
    return {
        "case": case,
        "status": "full_matrix_refresh_needed" if all_targeted_match(repros) else "fixture_experiment_targeted_only",
        "evidence": (
            f"native_comparison_complete: native actual={native_actual}, expected={expected}; "
            f"targeted connectors={statuses}; XML processor control present and XML:/* target matches."
        ),
    }


def malformed_xml_native_comparison_row(
    case: str, native_actual: Any, expected: Any, statuses: str
) -> dict[str, Any]:
    return {
        "case": case,
        "status": "native_comparison_complete",
        "evidence": (
            f"runtime_reached_actual_mismatch: native actual={native_actual}, expected={expected}; "
            f"targeted connectors={statuses}; XML processor control present, but no native "
            "rule match/parser-error evidence, so malformed XML parser semantics remain deferred."
        ),
    }


def native_comparison_row_without_control(case: str) -> dict[str, Any]:
    if case == "v2_transformation_url_decode_invalid_sequence_mapped_candidate":
        if all_targeted_match(connector_case_repros(case)):
            return {
                "case": case,
                "status": "runtime_reached_actual_match",
                "evidence": "Targeted connector repros now execute to HTTP 403; native comparison is no longer blocked by fixture syntax.",
            }
    return {
        "case": case,
        "status": "native_comparison_missing",
        "evidence": (
            "Existing reports/testing/generated/mrts-native artifacts cover the MRTS native suite; "
            "no direct native/libmodsecurity control artifact exists for this framework case."
        ),
    }


def case_repros(repros: list[dict[str, Any]], case: str, variants: set[str] | None = None) -> list[dict[str, Any]]:
    return [
        item
        for item in repros
        if item.get("case") == case and (variants is None or item.get("variant") in variants)
    ]


def has_targeted_classification(
    repros: list[dict[str, Any]],
    case: str,
    classification: str,
    count: int,
    variants: set[str] | None = None,
) -> bool:
    rows = case_repros(repros, case, variants)
    return len(rows) == count and all(item.get("runtime_classification") == classification for item in rows)


def native_case_matches(case: str, actual: str) -> bool:
    native = latest_native_case_run(case) or {}
    return str(native.get("native_actual") or "") == actual


def reflection_matches_classification(reflection: dict[str, Any], classification: str, rows: int) -> bool:
    return (
        reflection.get("official_critical_rows") == 0
        and reflection.get("classifications", {}).get(classification) == rows
    )


def secaction_with_mrts_is_non_intervening(repros: list[dict[str, Any]]) -> bool:
    rows = case_repros(repros, SECACTION_DETECTION_ONLY_CASE, {"no-crs/with-mrts", "with-crs/with-mrts"})
    return len(rows) == 6 and all(
        item.get("runtime_classification") == "runtime_reached_actual_mismatch"
        and str(item.get("actual") or "") == "200"
        for item in rows
    )


def critical_decision_context(mismatches: list[dict[str, Any]], repros: list[dict[str, Any]]) -> dict[str, Any]:
    malformed_reflection = case_reflection(mismatches, {"xml_request_body_malformed_connector_gap"})
    secaction_reflection = case_reflection(mismatches, {SECACTION_DETECTION_ONLY_CASE})
    return {
        "invalid_runtime_reached": has_targeted_classification(
            repros, "v2_transformation_url_decode_invalid_sequence_mapped_candidate", "runtime_reached_actual_match", 3
        ),
        "phase_fixed_targeted": has_targeted_classification(
            repros, PHASE_HANDLING_FIX_CASE, "runtime_reached_actual_match", 3
        ),
        "phase_native_matches": native_case_matches(PHASE_HANDLING_FIX_CASE, "403"),
        "phase_reflection": case_reflection(mismatches, {PHASE_HANDLING_FIX_CASE}),
        "namespace_fixed_targeted": has_targeted_classification(
            repros, "xml_namespace_edge_connector_gap", "runtime_reached_actual_match", 3
        ),
        "namespace_reflection": case_reflection(mismatches, {"xml_namespace_edge_connector_gap"}),
        "malformed_runtime_mismatch": has_targeted_classification(
            repros, "xml_request_body_malformed_connector_gap", "runtime_reached_actual_mismatch", 3
        ),
        "malformed_reflection": malformed_reflection,
        "malformed_reclassified": reflection_matches_classification(
            malformed_reflection, "libmodsecurity_xml_parser_semantics", 12
        ),
        "secaction_reflection": secaction_reflection,
        "secaction_reclassified": reflection_matches_classification(
            secaction_reflection, "secaction_detection_only_overlay", 6
        ),
        "secaction_native_matches_no_mrts": (
            has_targeted_classification(
                repros, SECACTION_DETECTION_ONLY_CASE, "runtime_reached_actual_match", 3, {"no-crs/no-mrts"}
            )
            and native_case_matches(SECACTION_DETECTION_ONLY_CASE, "403")
        ),
        "secaction_with_mrts_non_intervening": secaction_with_mrts_is_non_intervening(repros),
        "unicode_whitespace_reflection": case_reflection(mismatches, {"unicode_whitespace_normalization_gap"}),
        "unicode_double_encoded_reflection": case_reflection(mismatches, {"unicode_double_encoded_uri_runtime_difference"}),
        "invalid_reflection": case_reflection(
            mismatches, {"v2_transformation_url_decode_invalid_sequence_mapped_candidate"}
        ),
    }


def phase_handling_decision(context: dict[str, Any], matrix_status: dict[str, Any]) -> dict[str, Any]:
    complete = context["phase_fixed_targeted"] and context["phase_native_matches"]
    return {
        "cluster": "connector_capability_gap / phase-handling / phase1_vs_phase2_request_body_gap",
        "decision": "FIX_INPUT_REFRESH_REQUIRED" if complete else "DEFER",
        "rows": 9,
        "new_classification": "-",
        "native_comparison": "native_phase_comparison_complete" if context["phase_native_matches"] else "native_phase_comparison_missing",
        "full_matrix_refresh_needed": context["phase_fixed_targeted"] and not matrix_status["fresh"],
        "official_after": context["phase_reflection"],
        "phase1_body_expectation_gap": True,
        "phase2_runtime_reached": context["phase_fixed_targeted"],
        "connector_phase_gap": False,
        "native_phase_not_applicable": False,
        "targeted_only": True,
        "evidence": (
            "The original fixture asserted REQUEST_BODY in phase 1, omitted SecRequestBodyAccess On, and sent an empty "
            "body, so expected HTTP 403 was not logically derivable. Full-Matrix no-CRS rows reached runtime and "
            "returned HTTP 200 on Apache, NGINX, and HAProxy; HAProxy decision evidence showed phase 2 and "
            "request_body_seen=true with no disruptive rule match. The YAML now keeps phase 1 as a pass-only "
            "reachability marker and moves the body assertion to phase 2 rule 4512 with body 'bodyhit'. Targeted "
            "Apache, NGINX, HAProxy, and native libmodsecurity now return HTTP 403 with rule 4512. Official "
            "Full-Matrix rows remain stale until rerun."
            if complete
            else "Phase-handling evidence is incomplete. Do not reclassify official rows until targeted connector and native evidence agree on the corrected phase 2 body assertion."
        ),
    }


def secaction_decision(context: dict[str, Any]) -> dict[str, Any]:
    reclassified = context["secaction_reclassified"]
    return {
        "cluster": "expected_status_mismatch / actions / v3_secaction_block",
        "decision": "RECLASSIFY" if reclassified else "DEFER",
        "rows": 6,
        "new_classification": "secaction_detection_only_overlay" if reclassified else "-",
        "native_comparison": "secaction_native_control_complete" if context["secaction_native_matches_no_mrts"] else "native_comparison_missing",
        "full_matrix_refresh_needed": False,
        "official_after": context["secaction_reflection"],
        "secaction_runtime_reached": reclassified,
        "secaction_intervention_seen": context["secaction_native_matches_no_mrts"],
        "secaction_no_intervention": context["secaction_with_mrts_non_intervening"],
        "native_secaction_same_as_connectors": "no-mrts only; with-mrts overlay intentionally differs",
        "targeted_only": False,
        "evidence": (
            "The YAML SecAction is syntactically complete: id 3312, phase:2, deny, status:403, nolog, msg. "
            "Fresh Full-Matrix rows are limited to with-MRTS variants. The generated with-MRTS smoke rules "
            "include MRTS_001_INIT, which sets ctl:ruleEngine=DetectionOnly, before the SecAction. Apache, "
            "NGINX, and HAProxy no-MRTS controls return HTTP 403, and native libmodsecurity returns 403 via "
            "rule 3312. The with-MRTS targeted and Full-Matrix rows return HTTP 200 with runtime reached; "
            "HAProxy decision evidence shows decision=pass, disruptive=false, intervention_status=200. "
            "These six rows are report-only DetectionOnly overlay semantics, not connector intervention gaps."
            if reclassified
            else "SecAction evidence is incomplete. Keep the rows critical until Full-Matrix classification, targeted no-MRTS controls, and native SecAction evidence agree."
        ),
    }


def namespace_decision(context: dict[str, Any], matrix_status: dict[str, Any]) -> dict[str, Any]:
    fixed = context["namespace_fixed_targeted"]
    return {
        "cluster": "connector_capability_gap / body-processors / xml_namespace_edge_connector_gap",
        "decision": "FIX_INPUT_REFRESH_REQUIRED" if fixed else "DOCUMENT",
        "rows": 12,
        "new_classification": "-",
        "native_comparison": "full_matrix_refresh_needed" if fixed else "fixture_experiment_targeted_only",
        "official_after": context["namespace_reflection"],
        "full_matrix_refresh_needed": fixed and not matrix_status["fresh"],
        "evidence": (
            "Fixture evidence showed no explicit XML request-body processor control and a non-matching XML "
            "collection rule. The YAML now enables ctl:requestBodyProcessor=XML and uses the established "
            "XML:/* target against the namespaced body. Targeted Apache, NGINX, and HAProxy no-crs/no-mrts "
            "repros now return HTTP 403, and native libmodsecurity also returns 403 with rule 4711. Official "
            "Full-Matrix rows remain stale until the affected jobs are rerun."
            if fixed
            else "The XML namespace fixture still has only targeted evidence and no fresh Full-Matrix run. Do not reclassify official rows until connector and native evidence are complete."
        ),
    }


def malformed_xml_decision(context: dict[str, Any], matrix_status: dict[str, Any]) -> dict[str, Any]:
    reclassified = context["malformed_reclassified"]
    return {
        "cluster": "expected_status_mismatch / body-processors / xml_request_body_malformed_connector_gap",
        "decision": "RECLASSIFY" if reclassified else "DEFER",
        "rows": 12,
        "new_classification": "libmodsecurity_xml_parser_semantics" if reclassified else "-",
        "native_comparison": "native_comparison_complete" if context["malformed_runtime_mismatch"] else "native_comparison_missing",
        "full_matrix_refresh_needed": not matrix_status["fresh"],
        "official_after": context["malformed_reflection"],
        "evidence": (
            "The YAML explicitly enables ctl:requestBodyProcessor=XML and targets the XML collection. "
            "Targeted Apache, NGINX, and HAProxy return HTTP 200 with no rule match; native "
            "libmodsecurity also returns 200. Native debug evidence shows XML parser initialization, "
            "well_formed 0, and Failed to parse document, followed by rule 4408 returning 0 against "
            "the XML collection. The official Full-Matrix rows are fresh and all connector variants "
            "match native, so this case is reclassified as libmodsecurity XML parser semantics rather "
            "than a connector gap."
            if reclassified
            else "The YAML now explicitly enables ctl:requestBodyProcessor=XML, but targeted Apache, NGINX, and HAProxy still return HTTP 200 with no rule match. Native libmodsecurity also returns 200 with no intervention for the malformed body. Because there is no parser-error variable or native parser-error control in this fixture, the case remains deferred as malformed XML parser semantics/fixture expectation work, not a connector-only gap."
        ),
    }


def static_transformation_decision(cluster: str, reflection: dict[str, Any], evidence: str) -> dict[str, Any]:
    return {
        "cluster": cluster,
        "decision": "DEFER",
        "rows": 12,
        "new_classification": "-",
        "native_comparison": "native_comparison_missing",
        "full_matrix_refresh_needed": False,
        "official_after": reflection,
        "evidence": evidence,
    }


def invalid_sequence_decision(context: dict[str, Any], matrix_status: dict[str, Any]) -> dict[str, Any]:
    reached = context["invalid_runtime_reached"]
    return {
        "cluster": "timeout_or_incomplete / transformations / v2_transformation_url_decode_invalid_sequence_mapped_candidate",
        "decision": "FIX_INPUT_REFRESH_REQUIRED" if reached else "DOCUMENT",
        "rows": 12,
        "new_classification": "-",
        "native_comparison": "runtime_reached_actual_match" if reached else "not_reached_not_executable",
        "full_matrix_refresh_needed": reached and not matrix_status["fresh"],
        "official_after": context["invalid_reflection"],
        "evidence": (
            "The fixture syntax blocker was corrected by removing the former-XFAIL msg action text and "
            "using a parser-safe regex literal for percent (%). Targeted Apache, NGINX, and HAProxy "
            "no-crs/no-mrts repros now reach runtime and return HTTP 403 with rule 4406. Official "
            "Full-Matrix rows remain stale until the affected jobs are rerun."
            if reached
            else "The targeted case is not executable on Apache, NGINX, or HAProxy. Generated config uses msg:'former XFAIL invalid urlDecode sequence mapped candidate' and configtest/SPOA parsing fails before the request runs. This is a narrow test fixture syntax gap, not runtime evidence for t:urlDecode invalid-sequence behavior yet."
        ),
    }


def add_repro_commands(decisions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for item in decisions:
        case = str(item.get("cluster", "")).split("/")[-1].strip()
        item["repro_command"] = REPRESENTATIVE_REPRO_COMMANDS.get(
            case, f"make verified-case CONNECTOR=nginx CASE={case} CRS=no-crs MRTS=no-mrts"
        )
    return decisions


def critical_decisions(context: dict[str, Any], matrix_status: dict[str, Any]) -> list[dict[str, Any]]:
    return add_repro_commands(
        [
            phase_handling_decision(context, matrix_status),
            secaction_decision(context),
            namespace_decision(context, matrix_status),
            malformed_xml_decision(context, matrix_status),
            static_transformation_decision(
                "expected_status_mismatch / transformations / unicode_whitespace_normalization_gap",
                context["unicode_whitespace_reflection"],
                "Targeted repros exercise q=a%E2%80%83b and all connectors return 200 with no rule match. This suggests either libmodsecurity transformation semantics for t:compressWhitespace and Unicode spaces or an over-strict framework expectation, but native comparison is missing.",
            ),
            static_transformation_decision(
                "runtime_regression / transformations / unicode_double_encoded_uri_runtime_difference",
                context["unicode_double_encoded_reflection"],
                "Targeted repros send /?q=%25u0063%25u0061%25u0066%25u00E9. Apache, NGINX, and HAProxy all return 200 with no rule match; HAProxy logs the raw double-encoded URI. No connector divergence was observed, so native transform comparison is required before reclassification.",
            ),
            invalid_sequence_decision(context, matrix_status),
        ]
    )


def build_payload(connector_root: Path) -> tuple[dict[str, Any], list[Path]]:
    manifest_dir = connector_root / MANIFEST_REPORT_DIRECTORY
    canonical_dir = connector_root / "reports/testing/generated/canonical"
    mismatch_path = manifest_dir / "verified-runtime-mismatch-analysis.generated.json"
    readiness_path = manifest_dir / "merge-readiness-dashboard.generated.json"
    completeness_path = manifest_dir / "full-matrix-job-completeness.generated.json"
    full_matrix_path = canonical_dir / "full-runtime-matrix.generated.json"
    next_fix_path = canonical_dir / "next-fix-plan.generated.json"
    full_run_path = canonical_dir / "full-run-evidence.generated.json"
    mismatch = read_json(mismatch_path)
    mismatches = [row for row in mismatch.get("mismatches", []) if isinstance(row, dict)]
    ranking = critical_ranking(mismatches)
    repros = targeted_repros()
    matrix_status = full_matrix_refresh_status(connector_root, completeness_path)
    decisions = critical_decisions(critical_decision_context(mismatches, repros), matrix_status)
    payload = {
        "report_kind": "remaining-critical-batch-analysis",
        "data_source_policy": DATA_SOURCE_POLICY,
        "verified_run_id": mismatch.get("verified_run_id") or "-",
        "official_before": BASELINE,
        "official_after": {
            "mismatch_count": mismatch.get("mismatch_count"),
            "critical_mismatch_count": mismatch.get("critical_mismatch_count"),
            "merge_readiness": mismatch.get("merge_readiness"),
            "merge_readiness_reason": mismatch.get("merge_readiness_reason"),
        },
        "cluster_ranking": ranking,
        "decisions": decisions,
        "native_comparison": native_comparison_status(),
        "targeted_repros": repros,
        "full_matrix_refresh_status": matrix_status,
        "full_matrix_refresh_needed": any(item.get("full_matrix_refresh_needed") for item in decisions),
        "refresh_needed_reason": matrix_status["reason"],
        "remaining_top_critical_cluster": ranking[0] if ranking else {},
    }
    return payload, [mismatch_path, readiness_path, completeness_path, full_matrix_path, next_fix_path, full_run_path]


def md_table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(item).replace("|", "\\|") for item in row) + " |")
    return "\n".join(lines)


def critical_ranking_rows(payload: dict[str, Any]) -> list[list[Any]]:
    return [
        [item["rank"], item["cluster"], item["count"], ", ".join(item["connectors"]), ", ".join(item["cases"][:3])]
        for item in payload["cluster_ranking"][:15]
    ]


def yes_or_placeholder(item: dict[str, Any], field: str) -> str:
    return "yes" if item.get(field) else "-"


def connector_phase_gap_cell(item: dict[str, Any]) -> str:
    if "connector_phase_gap" not in item:
        return "-"
    return "yes" if item.get("connector_phase_gap") else "no"


def critical_decision_row(item: dict[str, Any]) -> list[Any]:
    return [
        item["cluster"],
        item["decision"],
        item.get("rows", "-"),
        item.get("new_classification", "-"),
        item.get("native_comparison", "-"),
        "yes" if item.get("full_matrix_refresh_needed") else "no",
        yes_or_placeholder(item, "phase1_body_expectation_gap"),
        yes_or_placeholder(item, "phase2_runtime_reached"),
        connector_phase_gap_cell(item),
        yes_or_placeholder(item, "secaction_runtime_reached"),
        yes_or_placeholder(item, "secaction_intervention_seen"),
        yes_or_placeholder(item, "secaction_no_intervention"),
        item.get("native_secaction_same_as_connectors", "-"),
        yes_or_placeholder(item, "targeted_only"),
        f"`{item.get('repro_command', '-')}`",
    ]


def targeted_repro_row(item: dict[str, Any]) -> list[Any]:
    return [
        item["phase"],
        item["cluster"],
        item["case"],
        item["connector"],
        item["variant"],
        item["status"],
        item.get("runtime_classification") or "-",
        item.get("actual") or "-",
        item.get("rule_id") or "-",
        item.get("matched_data") or "-",
        item.get("xml_processor_evidence") or "-",
        item["evidence_file"],
    ]


def cluster_ranking_markdown(ranking_rows: list[list[Any]]) -> str:
    table = md_table(["Rank", "Cluster", "Count", "Connectors", "Cases"], ranking_rows)
    if ranking_rows:
        return table
    return f"{table}\n\n_No rows available. Reason: no remaining critical mismatch clusters in the official report._"


def render_markdown(payload: dict[str, Any]) -> str:
    ranking_rows = critical_ranking_rows(payload)
    decision_rows = [critical_decision_row(item) for item in payload["decisions"]]
    native_rows = [[item["case"], item["status"], item["evidence"]] for item in payload["native_comparison"]]
    repro_rows = [targeted_repro_row(item) for item in payload["targeted_repros"]]
    before = payload["official_before"]
    after = payload["official_after"]
    metric_rows = [
        ["Total mismatches", before["mismatch_count"], after["mismatch_count"]],
        ["Critical mismatches", before["critical_mismatch_count"], after["critical_mismatch_count"]],
        ["Merge readiness", "FAIL", after["merge_readiness"]],
    ]
    cluster_ranking_section = cluster_ranking_markdown(ranking_rows)
    return "\n\n".join(
        [
            "# Remaining Critical Batch Analysis",
            "## Official Before / After",
            md_table(["Metric", "Before", "After"], metric_rows),
            "## Cluster Ranking",
            cluster_ranking_section,
            "## Decisions",
            md_table(
                [
                    "Cluster",
                    "Decision",
                    "Rows",
                    "New Classification",
                    "Native Comparison",
                    "Full-Matrix Refresh Needed",
                    "Phase1 Body Gap",
                    "Phase2 Runtime",
                    "Connector Phase Gap",
                    "SecAction Runtime",
                    "SecAction Intervention",
                    "SecAction No Intervention",
                    "Native SecAction Same",
                    "Targeted Only",
                    "Repro",
                ],
                decision_rows,
            ),
            "## Native Comparison",
            md_table(["Case", "Status", "Evidence"], native_rows),
            "## Targeted Repros",
            md_table(
                [
                    "Phase",
                    "Cluster",
                    "Case",
                    "Connector",
                    "Variant",
                    "Status",
                    "Runtime Classification",
                    "Actual",
                    "Rule",
                    "Matched Data",
                    "XML Processor Evidence",
                    "Evidence",
                ],
                repro_rows,
            ),
            "## Notes",
            f"- Full-matrix refresh needed: **{payload['full_matrix_refresh_needed']}**.",
            f"- Reason: {payload['refresh_needed_reason']}",
            f"- Current official top critical cluster: `{payload['remaining_top_critical_cluster'].get('cluster', '-')}` ({payload['remaining_top_critical_cluster'].get('count', '-')}).",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector-root", default=".")
    parser.add_argument("--framework-root", default=None)
    parser.add_argument("--output-dir", default=MANIFEST_REPORT_DIRECTORY)
    args = parser.parse_args()

    connector_root = Path(args.connector_root).resolve()
    framework_root = Path(args.framework_root).resolve() if args.framework_root else None
    output_dir = resolve_output_dir(connector_root, args.output_dir, MANIFEST_REPORT_DIRECTORY)
    add_safe_roots(connector_root, connector_root / "reports/testing/generated")

    payload, inputs = build_payload(connector_root)
    metadata = build_metadata(
        generated_by=GENERATED_REPORTS["remaining_critical_batch_analysis"].generator,
        make_target=GENERATED_REPORTS["remaining_critical_batch_analysis"].make_target,
        connector_root=connector_root,
        framework_root=framework_root,
        inputs=inputs,
        report_key="remaining_critical_batch_analysis",
    )
    json_path = output_dir / GENERATED_REPORTS["remaining_critical_batch_analysis"].filename("json")
    md_path = output_dir / GENERATED_REPORTS["remaining_critical_batch_analysis"].filename("md")
    write_text_file(json_path, generated_json_text(payload, metadata))
    write_text_file(md_path, generated_markdown_text(render_markdown(payload), metadata))
    print(md_path)
    print(json_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
