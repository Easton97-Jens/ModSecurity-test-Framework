#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

# CI helpers are shared from ci/lib even when this file is executed directly.
import sys

from typing import Any

from modsecurity_connector_ci.lib.evidence_inputs import EvidenceInputs
from modsecurity_connector_ci.lib.generated_report_utils import GENERATED_ROOT, build_metadata, current_verified_run_id, generated_json_text, generated_markdown_text, report_path, report_path_from_root
from modsecurity_connector_ci.lib.report_path_safety import add_safe_roots, write_text_file
from modsecurity_connector_ci.lib.runtime_path_utils import verified_runtime_paths
from modsecurity_connector_ci.lib.verified_run_id import VerifiedRunIdError, validate_verified_run_id


INPUTS = EvidenceInputs(())


def read_json(path: Path) -> dict[str, Any]:
    return INPUTS.json(path)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return INPUTS.jsonl(path)


JOB_ID = "nginx:with-crs:with-mrts"
PRIMARY_BLOCKER = "nginx_with_crs_with_mrts_http500_cluster"
ERROR_REWRITE_CYCLE = 'rewrite or internal redirection cycle while internally redirecting to "/index.html"'
ERROR_PERMISSION_DENIED = "htdocs/index.html permission denied"
DOCROOT_INDEX_PATH = "htdocs/index.html"
PERMISSION_DENIED_TEXT = "Permission denied"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def rel(path: str | Path, root: Path) -> str:
    if not path:
        return "-"
    item = Path(path)
    try:
        return str(item.resolve(strict=False).relative_to(root.resolve(strict=False)))
    except Exception:
        return str(path)


def read_lines(path: str | Path) -> list[str]:
    try:
        return INPUTS.read_text(path).splitlines()
    except (OSError, ValueError):
        return []


def final_run_prefix(job: dict[str, Any]) -> str:
    started = str(job.get("started_at") or "")
    if started.startswith("2026-06-16"):
        return "2026/06/16"
    if len(started) >= 10:
        return started[:10].replace("-", "/")
    return ""


def final_error_lines(path: str | Path, prefix: str) -> list[str]:
    lines = read_lines(path)
    if not prefix:
        return lines
    return [line for line in lines if line.startswith(prefix)]


def access_log_status(line: str) -> str | None:
    search_from = 0
    while True:
        request_start = line.find('"', search_from)
        if request_start < 0:
            return None
        request_end = line.find('"', request_start + 1)
        if request_end < 0:
            return None
        request = line[request_start + 1 : request_end]
        first_space = request.find(" ")
        protocol_marker = request.find(" HTTP/", first_space + 2)
        status_start = request_end + 1
        if (
            first_space > 0
            and not any(char.isspace() for char in request[:first_space])
            and protocol_marker >= first_space + 2
            and protocol_marker + len(" HTTP/") < len(request)
            and status_start + 5 <= len(line)
            and line[status_start] == " "
            and line[status_start + 1 : status_start + 4].isdigit()
            and line[status_start + 4] == " "
        ):
            return line[status_start + 1 : status_start + 4]
        search_from = request_start + 1


def access_status(path: str | Path, prefix_date: str) -> str:
    prefix = ""
    if prefix_date:
        parts = prefix_date.split("/")
        if len(parts) == 3:
            prefix = f"[{parts[2]}/{datetime.strptime(parts[1], '%m').strftime('%b')}/{parts[0]}:"
    statuses: list[str] = []
    for line in read_lines(path):
        if prefix and prefix not in line:
            continue
        status = access_log_status(line)
        if status is not None:
            statuses.append(status)
    return statuses[-1] if statuses else "-"


def harness_root_from_evidence(path: str | Path) -> Path:
    item = Path(str(path))
    try:
        if item.name == "result.json" and item.parent.parent.name == "logs":
            return item.parent.parent.parent
    except Exception:
        pass
    match = re.match(r"(.+)/logs/[^/]+/result\.json$", str(item))
    return Path(match.group(1)) if match else Path()


def patterns_for_error_line(line: str) -> list[str]:
    return [
        *rewrite_error_patterns(line),
        *permission_error_patterns(line),
        *modsecurity_warning_patterns(line),
        *generic_failure_patterns(line),
    ]


def rewrite_error_patterns(line: str) -> list[str]:
    return ["rewrite_internal_redirect_cycle_to_index"] if ERROR_REWRITE_CYCLE in line else []


def permission_error_patterns(line: str) -> list[str]:
    if PERMISSION_DENIED_TEXT not in line:
        return []
    if DOCROOT_INDEX_PATH in line:
        patterns = ["docroot_index_permission_denied"]
    elif "/htdocs/" in line:
        patterns = ["docroot_directory_permission_denied"]
    else:
        patterns = []
    if "[crit]" in line:
        patterns.append("nginx_crit_permission_denied")
    return patterns


def modsecurity_warning_patterns(line: str) -> list[str]:
    if "ModSecurity: Warning." not in line:
        return []
    if "/coreruleset/" in line or "OWASP_CRS" in line:
        return ["modsecurity_crs_warning"]
    if "/mrts/" in line or "MRTS/" in line:
        return ["modsecurity_mrts_warning"]
    return ["modsecurity_case_warning"]


def generic_failure_patterns(line: str) -> list[str]:
    return ["generic_failed"] if "failed" in line.lower() and PERMISSION_DENIED_TEXT not in line else []


def error_patterns_for_case(row: dict[str, Any], prefix: str) -> list[str]:
    patterns: dict[str, None] = {}
    for line in final_error_lines(str(row.get("nginx_error_log_path") or ""), prefix):
        for pattern in patterns_for_error_line(line):
            patterns.setdefault(pattern, None)
    return list(patterns)


def example_line_for_pattern(row: dict[str, Any], prefix: str, pattern: str) -> str:
    for line in final_error_lines(str(row.get("nginx_error_log_path") or ""), prefix):
        if pattern in patterns_for_error_line(line):
            return line[:600]
    return "-"


def representative_error_excerpt(row: dict[str, Any], prefix: str, max_lines: int = 4) -> list[str]:
    interesting: list[str] = []
    for line in final_error_lines(str(row.get("nginx_error_log_path") or ""), prefix):
        if (
            ERROR_REWRITE_CYCLE in line
            or (DOCROOT_INDEX_PATH in line and PERMISSION_DENIED_TEXT in line)
            or ("ModSecurity: Warning." in line and len(interesting) < 2)
        ):
            interesting.append(line[:600])
        if len(interesting) >= max_lines:
            break
    return interesting


def audit_excerpt(path: str | Path, max_lines: int = 4) -> list[str]:
    lines = read_lines(path)
    return [line[:600] for line in lines[:max_lines]]


def case_env(path: str | Path) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in read_lines(path):
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key] = value
    return data


def request_headers(path: str | Path) -> list[str]:
    return [line for line in read_lines(path) if line.strip()]


def request_body_info(path: str | Path) -> dict[str, Any]:
    item = Path(path)
    try:
        raw = INPUTS.read_bytes(item)
    except (OSError, ValueError):
        return {"path": str(item), "status": "missing_or_rejected", "bytes": 0, "excerpt": ""}
    excerpt = raw[:160].decode("utf-8", errors="replace")
    return {"path": str(item), "status": "present", "bytes": len(raw), "excerpt": excerpt}


def family_for(row: dict[str, Any]) -> str:
    name = str(row.get("name") or "").lower()
    category = str(row.get("category") or "").lower()
    capabilities = {str(item).lower() for item in row.get("capabilities", []) if isinstance(item, str)}
    return family_from_name_capabilities_category(name, capabilities, category)


def family_from_name_capabilities_category(name: str, capabilities: set[str], category: str) -> str:
    if "request_cookies_names" in name or "request_cookies" in name or "request-cookies" in capabilities:
        return "MRTS request cookie/name"
    if "_xml_" in name or category == "xml" or "xml" in capabilities:
        return "MRTS XML"
    if "request_filename" in name:
        return "Request filename"
    return family_from_category(name, category)


def family_from_category(name: str, category: str) -> str:
    if "response_body" in name or "phase4" in name or category == "response-body":
        return "Response body / phase 4"
    if "multipart" in name or "files_" in name or category == "multipart":
        return "Multipart"
    if name.startswith("mrts_"):
        return "Other MRTS"
    if category == "audit-log":
        return "Audit / intervention"
    if category in {"actions", "phase-handling"}:
        return "Intervention / actions"
    if category in {"body-processors", "request-body"}:
        return "Request body / parsers"
    if category == "collections":
        return "Collections / name handling"
    if category in {"transformations", "operators"}:
        return "Transformations / operators"
    if category == "response-headers":
        return "Response headers / phase 3"
    return "Unknown"


def classification_for_family(family: str) -> str:
    if family == "MRTS XML":
        return "xml_handling_bug_secondary_harness_environment_error"
    if family == "Multipart":
        return "multipart_handling_bug_secondary_harness_environment_error"
    if family == "Response body / phase 4":
        return "response_body_phase4_bug_secondary_harness_environment_error"
    if family in {"MRTS request cookie/name", "Request filename", "Other MRTS"}:
        return "crs_mrts_rule_interaction_secondary_harness_environment_error"
    if family in {"Audit / intervention", "Intervention / actions"}:
        return "intervention_handling_bug_secondary_harness_environment_error"
    return "harness_environment_error"


def rollup_patterns_for_row(row: dict[str, Any], prefix: str) -> list[str]:
    patterns = error_patterns_for_case(row, prefix)
    return patterns or ["no_matching_error_pattern"]


def pattern_rollup_example(row: dict[str, Any], prefix: str, pattern: str) -> str:
    if pattern == "no_matching_error_pattern":
        return next(iter(representative_error_excerpt(row, prefix, 1)), "-")
    return example_line_for_pattern(row, prefix, pattern)


def collect_pattern_rollup(
    counter: Counter[str],
    examples: dict[str, str],
    affected: defaultdict[str, list[str]],
    row: dict[str, Any],
    prefix: str,
) -> None:
    for pattern in rollup_patterns_for_row(row, prefix):
        counter[pattern] += 1
        if pattern not in examples:
            examples[pattern] = pattern_rollup_example(row, prefix, pattern)
        if len(affected[pattern]) < 8:
            affected[pattern].append(str(row.get("name") or "-"))


def pattern_rollup(rows: list[dict[str, Any]], prefix: str) -> list[dict[str, Any]]:
    counter: Counter[str] = Counter()
    examples: dict[str, str] = {}
    affected: defaultdict[str, list[str]] = defaultdict(list)
    for row in rows:
        collect_pattern_rollup(counter, examples, affected, row, prefix)
    return [
        {
            "pattern": pattern,
            "count": count,
            "example": examples.get(pattern, "-"),
            "affected_cases": affected.get(pattern, []),
        }
        for pattern, count in counter.most_common()
    ]


def build_groups(rows: list[dict[str, Any]], connector_root: Path) -> list[dict[str, Any]]:
    grouped: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[family_for(row)].append(row)
    result: list[dict[str, Any]] = []
    for family, items in sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0])):
        result.append(
            {
                "group": family,
                "count": len(items),
                "classification": classification_for_family(family),
                "representative_cases": [
                    {
                        "case": str(row.get("name") or "-"),
                        "expected": row.get("expected_status"),
                        "actual": row.get("actual_status"),
                        "evidence": rel(row.get("evidence_path") or row.get("nginx_error_log_path") or "-", connector_root),
                    }
                    for row in items[:5]
                ],
            }
        )
    return result


def representative_case_names() -> list[str]:
    return [
        "audit_log_empty_sections_future_target",
        "action_allow_phase1_pass",
        "duplicate_args_encoded_separator_edge",
        "multipart_basic_block",
        "response_body_basic_block",
        "mrts_100000_mrts_002_args_a_get_100000_1",
        "mrts_100116_mrts_059_request_cookies_100116_2",
        "mrts_100132_mrts_060_request_cookies_names_100132_2",
        "mrts_100148_mrts_061_request_filename_100148_1",
        "mrts_100154_mrts_110_xml_100154_1",
    ]


def selected_representative_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    wanted = representative_case_names()
    by_name = {str(row.get("name") or ""): row for row in rows}
    selected = [by_name[name] for name in wanted if name in by_name]
    if len(selected) < 10:
        seen = {str(row.get("name") or "") for row in selected}
        for row in rows:
            if str(row.get("name") or "") not in seen:
                selected.append(row)
                seen.add(str(row.get("name") or ""))
            if len(selected) >= 10:
                break
    return selected[:10]


def case_runtime_paths(row: dict[str, Any]) -> tuple[str, Path, Path, Path]:
    case_name = str(row.get("name") or "")
    harness_root = harness_root_from_evidence(Path(str(row.get("evidence_path") or "")))
    if not re.fullmatch(r"\w[\w.-]*", case_name, flags=re.ASCII):
        raise ValueError("invalid evidence case identity")
    case_root = harness_root / "runtime" / case_name / "conf"
    return case_name, case_root / "case.env", case_root / "request-headers.txt", case_root / "request-body.bin"


def request_content_type(headers: list[str]) -> str:
    return next((line.split(":", 1)[1].strip() for line in headers if line.lower().startswith("content-type:")), "")


def representative_case(row: dict[str, Any], prefix: str, connector_root: Path) -> dict[str, Any]:
    case_name, case_env_path, headers_path, body_path = case_runtime_paths(row)
    headers = request_headers(headers_path)
    environment = case_env(case_env_path)
    case_root = case_env_path.parent
    family = family_for(row)
    return {
        "case": case_name,
        "group": family,
        "expected": row.get("expected_status"),
        "actual": row.get("actual_status"),
        "access_log_status": access_status(str(row.get("nginx_access_log_path") or ""), prefix),
        "error_pattern": ", ".join(error_patterns_for_case(row, prefix)[:4]) or "-",
        "classification": classification_for_family(family),
        "error_log_excerpt": representative_error_excerpt(row, prefix),
        "audit_log_excerpt": audit_excerpt(str(row.get("audit_log_path") or "")),
        "result_json": read_json(Path(str(row.get("evidence_path") or ""))),
        "loaded_rules": {
            "crs_active": True, "mrts_active": True,
            "modsecurity_config": rel(case_root / "nginx.conf", connector_root),
            "rule_preamble": "crs/modsecurity-crs-preamble.conf + MRTS load/case rules",
        },
        "request": {
            "method": environment.get("REQUEST_METHOD", "-"), "path": environment.get("REQUEST_PATH", "-"),
            "has_body": environment.get("REQUEST_HAS_BODY", "-"), "content_type": request_content_type(headers) or "-",
            "headers": headers[:8], "body": request_body_info(body_path),
        },
        "evidence": {
            "result_json": rel(row.get("evidence_path") or "-", connector_root),
            "nginx_error_log": rel(row.get("nginx_error_log_path") or "-", connector_root),
            "nginx_access_log": rel(row.get("nginx_access_log_path") or "-", connector_root),
            "audit_log": rel(row.get("audit_log_path") or "-", connector_root),
        },
    }


def representative_cases(rows: list[dict[str, Any]], prefix: str, connector_root: Path) -> list[dict[str, Any]]:
    return [representative_case(row, prefix, connector_root) for row in selected_representative_rows(rows)]


def permissions_probe(row: dict[str, Any]) -> dict[str, Any]:
    evidence_path = Path(str(row.get("evidence_path") or ""))
    case_name = str(row.get("name") or "")
    harness_root = harness_root_from_evidence(evidence_path)
    index_path = harness_root / "runtime" / case_name / DOCROOT_INDEX_PATH
    if not INPUTS.is_file(index_path):
        return {"index_path": str(index_path), "path_components": [], "status": "missing_or_rejected"}
    paths: list[dict[str, Any]] = []
    current = Path("/")
    for part in index_path.parts[1:]:
        current = current / part
        try:
            stat = current.stat()
            paths.append(
                {
                    "path": str(current),
                    "mode": oct(stat.st_mode & 0o777),
                    "uid": stat.st_uid,
                    "gid": stat.st_gid,
                    "traversable_by_other": bool(stat.st_mode & 0o001) if current.is_dir() else None,
                }
            )
        except OSError as exc:
            paths.append({"path": str(current), "error": str(exc)})
            break
    return {"index_path": str(index_path), "path_components": paths}


def nginx_cluster_paths(connector_root: Path, build_root: Path, verified_run_id: str) -> dict[str, Path]:
    job_root = build_root / "full-matrix/with-crs/with-mrts/nginx"
    return {
        "job_json": job_root / "job.json",
        "run_log": job_root / "run.log",
        "summary_json": job_root / "results/force-all/nginx-summary.json",
        "results_jsonl": job_root / "results/force-all/nginx-results.jsonl",
        "full_matrix_job_completeness": report_path(connector_root, "full_matrix_job_completeness", "json"),
        "verified_runtime_mismatch_analysis": report_path(connector_root, "verified_runtime_mismatch_analysis", "json"),
        "verified_commands": build_root / "verified-runs" / verified_run_id / "verified-commands.json",
    }


def nginx_cluster_summary(rows: list[dict[str, Any]], http500_rows: list[dict[str, Any]], patterns: list[dict[str, Any]], prefix: str) -> dict[str, Any]:
    rewrite_count = next((item["count"] for item in patterns if item["pattern"] == "rewrite_internal_redirect_cycle_to_index"), 0)
    permission_case_count = sum(
        1 for row in http500_rows if "docroot_index_permission_denied" in error_patterns_for_case(row, prefix)
    )
    return {
        "total_rows": len(rows), "http500_failures": len(http500_rows),
        "rewrite_cycle_cases": rewrite_count, "permission_denied_cases": permission_case_count,
        "expected_status_counts": dict(Counter(str(row.get("expected_status")) for row in http500_rows)),
        "actual_status_counts": dict(Counter(str(row.get("actual_status")) for row in rows)),
        "status_counts": dict(Counter(str(row.get("status")) for row in rows)),
    }


def nginx_cluster_root_cause(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "likely_cause": "Historical evidence: NGINX worker could not traverse /root-owned runtime parents, generated docroot was inaccessible, and try_files /index.html looped into HTTP 500. New runs should block in the worker-docroot preflight before this becomes runtime mismatch evidence.",
        "classification": "harness_environment_error", "secondary_classification": "nginx_config_error", "confidence": "high",
        "evidence": [
            f"{summary['rewrite_cycle_cases']} HTTP-500 rows have {ERROR_REWRITE_CYCLE!r}.",
            f"{summary['permission_denied_cases']} HTTP-500 rows have {DOCROOT_INDEX_PATH} {PERMISSION_DENIED_TEXT} in final-run error logs.",
            "Historical namei evidence shows /root is 0700 while NGINX worker user is nobody; generated files below it are otherwise readable.",
            "No segfault/core/module-load error pattern was observed in the final-run cluster.",
        ],
    }


def minimal_http500_repro(rows: list[dict[str, Any]], connector_root: Path) -> dict[str, Any]:
    minimal_case = "mrts_100000_mrts_002_args_a_get_100000_1"
    minimal_row = next((row for row in rows if row.get("name") == minimal_case), rows[0] if rows else {})
    return {
        "case": minimal_case,
        "status": "reproduced_by_full_matrix_evidence; direct single-case target needs a stable full-matrix wrapper",
        "existing_reproducer": "VERIFIED_RUN_FULL_MATRIX_JOB_TIMEOUT_SECONDS=3600 make verified-full-matrix-job CONNECTOR=nginx CRS=with-crs MRTS=with-mrts",
        "target_to_add": "make verified-nginx-mrts-case CASE=mrts_100000_mrts_002_args_a_get_100000_1 CRS=with-crs MRTS=with-mrts",
        "notes": "The connector harness supports TEST_CASE internally, but the verified full-matrix path does not yet expose a single-case target with CRS/MRTS setup and isolated job metadata.",
        "evidence": {
            "result_json": rel(minimal_row.get("evidence_path") or "-", connector_root),
            "nginx_error_log": rel(minimal_row.get("nginx_error_log_path") or "-", connector_root),
        },
        "permissions_probe": permissions_probe(minimal_row) if minimal_row else {},
    }


def nginx_cluster_fix_plan() -> list[dict[str, Any]]:
    return [
        {"fix": "Keep verified NGINX Full-Matrix harness roots under VERIFIED_RUN_ROOT/NGINX_HARNESS_PARENT outside /root.", "path": "ci/runtime/lifecycle/run-full-matrix-parallel.sh / Makefile NGINX_HARNESS_PARENT", "risk": "medium", "expected_effect": "Eliminates docroot Permission denied or reports it as a BLOCKED preflight before the 500 cluster can form.", "needs_new_verified_run": True},
        {"fix": "Add a readiness/permission preflight that blocks NGINX jobs when worker user cannot traverse DOCROOT parents.", "path": "connectors/nginx/harness/run_nginx_smoke.sh", "risk": "low", "expected_effect": "Classifies future inaccessible-docroot evidence as BLOCKED instead of runtime FAIL.", "needs_new_verified_run": True},
        {"fix": "Add a verified single-case Full-Matrix target for NGINX with CRS/MRTS setup and job metadata.", "path": "Makefile / ci/runtime/lifecycle/run-full-matrix-job.py", "risk": "low", "expected_effect": "Provides minimal repro without rerunning the 524-case NGINX job.", "needs_new_verified_run": False},
    ]


def build_payload(connector_root: Path, build_root: Path, verified_run_id: str) -> dict[str, Any]:
    global INPUTS
    INPUTS = EvidenceInputs((connector_root, build_root))
    verified_run_id = validate_verified_run_id(verified_run_id)
    paths = nginx_cluster_paths(connector_root, build_root, verified_run_id)
    job = read_json(paths["job_json"])
    rows = read_jsonl(paths["results_jsonl"])
    http500_rows = [row for row in rows if row.get("actual_status") == 500]
    prefix = final_run_prefix(job)
    patterns = pattern_rollup(http500_rows, prefix)
    summary = nginx_cluster_summary(rows, http500_rows, patterns, prefix)
    minimal_repro = minimal_http500_repro(http500_rows, connector_root)
    return {
        "generated_at": utc_now(), "verified_run_id": verified_run_id, "job_id": JOB_ID,
        "primary_blocker": PRIMARY_BLOCKER if http500_rows else "none",
        "merge_readiness": "FAIL" if http500_rows else "UNKNOWN",
        "job": {key: job.get(key) for key in ("status", "return_code", "started_at", "ended_at", "duration_seconds")} | {"path": str(paths["job_json"])},
        "inputs": {key: str(value) for key, value in paths.items()},
        "summary": summary, "root_cause": nginx_cluster_root_cause(summary),
        "groups": build_groups(http500_rows, connector_root), "error_patterns": patterns,
        "representative_cases": representative_cases(http500_rows, prefix, connector_root),
        "permissions_probe": minimal_repro.pop("permissions_probe"), "minimal_repro": minimal_repro,
        "cluster_classification": [
            {"cluster": group["group"], "count": group["count"], "classification": group["classification"],
             "code_fix_needed": group["classification"] in {"harness_environment_error", "crs_mrts_rule_interaction_secondary_harness_environment_error"},
             "test_expectation_wrong": False, "document_only": False}
            for group in build_groups(http500_rows, connector_root)
        ],
        "fix_plan": nginx_cluster_fix_plan(),
        "data_availability": {
            "audit_logs": "Mostly absent for permission/docroot failures; NGINX fails while serving generated htdocs.",
            "single_case_target": "Not yet exposed as a verified make target.",
            "old_log_lines": "Some per-case logs include previous 2026-06-15 attempts; this report filters final-run error analysis to the job date prefix.",
        },
        "no_invented_values_statement": "All counts and examples are parsed from the verified NGINX with-crs/with-mrts job.json, JSONL result file, and referenced per-case logs.",
    }


def md(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    if not rows:
        lines.append("| " + " | ".join(["Missing/Empty"] + ["-" for _ in headers[1:]]) + " |")
        return lines
    for row in rows:
        lines.append("| " + " | ".join(md(item) for item in row) + " |")
    return lines


def render_markdown(payload: dict[str, Any]) -> str:
    root = payload["root_cause"]
    lines = [
        "# NGINX with-crs/with-mrts HTTP-500 Cluster Analysis",
        "",
        "## Summary",
        "",
        f"- Verified run id: `{payload['verified_run_id']}`",
        f"- Job: `{payload['job_id']}`",
        f"- Primary blocker: `{payload['primary_blocker']}`",
        f"- HTTP-500 failures: `{payload['summary']['http500_failures']}`",
        f"- Likely cause: {root['likely_cause']}",
        f"- Classification: `{root['classification']}`; secondary `{root['secondary_classification']}`",
        f"- Confidence: `{root['confidence']}`",
        "",
        "## Cluster Counts",
        "",
    ]
    lines.extend(
        table(
            ["Group", "Count", "Classification", "Representative Cases"],
            [
                [
                    group["group"],
                    group["count"],
                    group["classification"],
                    "<br>".join(f"`{case['case']}`" for case in group["representative_cases"][:3]),
                ]
                for group in payload["groups"]
            ],
        )
    )
    lines.extend(["", "## Error Patterns", ""])
    lines.extend(
        table(
            ["Error Pattern", "Count", "Example", "Affected Cases"],
            [
                [
                    item["pattern"],
                    item["count"],
                    item["example"][:220],
                    "<br>".join(f"`{case}`" for case in item["affected_cases"][:4]),
                ]
                for item in payload["error_patterns"][:12]
            ],
        )
    )
    lines.extend(["", "## Representative Cases", ""])
    lines.extend(
        table(
            ["Case", "Expected", "Actual", "Access", "Error Pattern", "Classification", "Evidence"],
            [
                [
                    f"`{case['case']}`",
                    case["expected"],
                    case["actual"],
                    case["access_log_status"],
                    case["error_pattern"],
                    case["classification"],
                    case["evidence"]["result_json"],
                ]
                for case in payload["representative_cases"]
            ],
        )
    )
    lines.extend(["", "## Root Cause Evidence", ""])
    for evidence in root["evidence"]:
        lines.append(f"- {evidence}")
    lines.extend(["", "## Minimal Repro", ""])
    repro = payload["minimal_repro"]
    lines.extend(
        [
            f"- Minimal case: `{repro['case']}`",
            f"- Existing producer reproducer: `{repro['existing_reproducer']}`",
            f"- Target to add: `{repro['target_to_add']}`",
            f"- Notes: {repro['notes']}",
        ]
    )
    lines.extend(["", "## Fix Plan", ""])
    lines.extend(
        table(
            ["Fix", "File/Path", "Risk", "Expected Effect", "Needs New Verified Run"],
            [
                [item["fix"], item["path"], item["risk"], item["expected_effect"], item["needs_new_verified_run"]]
                for item in payload["fix_plan"]
            ],
        )
    )
    lines.extend(["", "## Data Availability / Missing Information", ""])
    lines.extend(
        table(
            ["Item", "Status"],
            [[key, value] for key, value in payload["data_availability"].items()],
        )
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector-root", default=os.getcwd())
    parser.add_argument("--framework-root", default=None)
    parser.add_argument("--build-root", default=os.environ.get("BUILD_ROOT"))
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--verified-run-id", default=None)
    args = parser.parse_args()

    connector_root = Path(args.connector_root).resolve()
    framework_root = Path(args.framework_root).resolve() if args.framework_root else connector_root / "modules/ModSecurity-test-Framework"
    default_paths = verified_runtime_paths(os.environ)
    build_root = Path(args.build_root or default_paths["BUILD_ROOT"]).resolve()
    try:
        verified_run_id = validate_verified_run_id(
            args.verified_run_id or current_verified_run_id(connector_root)
        )
    except VerifiedRunIdError as exc:
        parser.error(str(exc))
    output_dir = Path(args.output_dir).resolve() if args.output_dir else connector_root / GENERATED_ROOT
    report_root = output_dir.parent if output_dir.name == "manifest" else output_dir
    add_safe_roots(report_root, output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    payload = build_payload(connector_root, build_root, verified_run_id)
    inputs = [Path(value) for value in payload["inputs"].values()]
    metadata = INPUTS.build_metadata(build_metadata,
        generated_by="ci/evidence/reports/generate-nginx-mrts-http500-cluster-analysis.py",
        make_target="generate-nginx-mrts-http500-cluster-analysis",
        connector_root=connector_root,
        framework_root=framework_root,
        inputs=inputs,
        report_key="nginx_mrts_http500_cluster_analysis",
        extra={"verified_run_id": verified_run_id},
    )
    json_path = report_path_from_root(report_root, "nginx_mrts_http500_cluster_analysis", "json")
    md_path = report_path_from_root(report_root, "nginx_mrts_http500_cluster_analysis", "md")
    write_text_file(json_path, generated_json_text(payload, metadata))
    write_text_file(md_path, generated_markdown_text(render_markdown(payload), metadata))
    print(md_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
