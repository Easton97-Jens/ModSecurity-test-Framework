#!/usr/bin/env python3
"""Update the tracked local runtime validation snapshot from smoke summaries."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml


FRAMEWORK_ROOT = Path(__file__).resolve().parents[2]
CONNECTOR_ROOT = Path.cwd()
OUTPUT_ROOT = CONNECTOR_ROOT
FRAMEWORK_REPORT_DIR = "docs/testing"
CONNECTOR_REPORT_DIR = "reports/testing"
REPORT_ROOT = OUTPUT_ROOT / FRAMEWORK_REPORT_DIR
SNAPSHOT_FILENAME = "runtime-validation-snapshot.json"
SNAPSHOT = REPORT_ROOT / SNAPSHOT_FILENAME
SNAPSHOT_LAYOUT: "SnapshotLayout | None" = None
for path in (FRAMEWORK_ROOT / "tests" / "runners", FRAMEWORK_ROOT / "ci" / "lib"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from runner_core import case_group, load_case  # noqa: E402
from generated_report_utils import write_generated_report_file  # noqa: E402
from response_body_status import (  # noqa: E402
    RESPONSE_BODY_RUNTIME_NOTE,
    is_response_body_related,
    matrix_status_for_result,
    response_body_non_promotion_fields,
)
from report_output_paths import (  # noqa: E402
    report_root_for as shared_report_root_for,
    resolve_allowed_output_root as shared_resolve_allowed_output_root,
    resolve_root,
    resolve_under_root,
)

RUNTIME_CONNECTORS = ("apache", "nginx", "haproxy")


def default_build_root() -> Path:
    """Return the explicitly configured private build root, never shared TMP."""
    configured_run_root = os.environ.get("VERIFIED_RUN_ROOT", "")
    configured_build_root = os.environ.get("BUILD_ROOT", "")
    if not configured_build_root and not configured_run_root:
        raise ValueError("BUILD_ROOT or VERIFIED_RUN_ROOT is required; shared temporary directories are forbidden")
    run_root = resolve_root(configured_run_root, label="verified run root") if configured_run_root else None
    build_root = resolve_root(configured_build_root, label="build root") if configured_build_root else run_root / "build"
    if run_root is not None:
        return resolve_under_root(run_root, build_root, label="build root")
    return build_root


@dataclass(frozen=True)
class SnapshotLayout:
    output_root: Path
    report_root: Path
    snapshot: Path

    def write(self, snapshot_data: dict) -> None:
        safe_snapshot_path = build_safe_snapshot_path(self.output_root)
        if self.snapshot != safe_snapshot_path:
            raise ValueError(f"snapshot path must be the configured report snapshot: {self.snapshot}")
        safe_snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        write_generated_report_file(
            safe_snapshot_path.parent,
            SNAPSHOT_FILENAME,
            json.dumps(snapshot_data, indent=2, sort_keys=False) + "\n",
        )


def resolve_allowed_output_root(output_root: str | Path | None) -> Path:
    return shared_resolve_allowed_output_root(
        output_root,
        framework_root=FRAMEWORK_ROOT,
        connector_root=CONNECTOR_ROOT,
    )


def report_root_for(output_root: Path) -> Path:
    return shared_report_root_for(
        output_root,
        framework_root=FRAMEWORK_ROOT,
        connector_root=CONNECTOR_ROOT,
        framework_report_dir=FRAMEWORK_REPORT_DIR,
        connector_report_dir=CONNECTOR_REPORT_DIR,
    )


def build_safe_snapshot_path(output_root: Path) -> Path:
    report_root = report_root_for(output_root)
    return resolve_under_root(report_root, report_root / SNAPSHOT_FILENAME, label="runtime snapshot path")


def build_safe_snapshot_layout(output_root: Path) -> SnapshotLayout:
    report_root = report_root_for(output_root)
    return SnapshotLayout(
        output_root=output_root,
        report_root=report_root,
        snapshot=resolve_under_root(report_root, report_root / SNAPSHOT_FILENAME, label="runtime snapshot path"),
    )


def active_snapshot_layout() -> SnapshotLayout:
    if SNAPSHOT_LAYOUT is None:
        raise RuntimeError("snapshot layout has not been configured")
    return SNAPSHOT_LAYOUT


def configure_paths(framework_root: str | Path, connector_root: str | Path, output_root: str | Path | None) -> None:
    global FRAMEWORK_ROOT, CONNECTOR_ROOT, OUTPUT_ROOT, REPORT_ROOT, SNAPSHOT, SNAPSHOT_LAYOUT
    FRAMEWORK_ROOT = resolve_root(framework_root, label="framework root")
    CONNECTOR_ROOT = resolve_root(connector_root, label="connector root")
    OUTPUT_ROOT = resolve_allowed_output_root(output_root)
    SNAPSHOT_LAYOUT = build_safe_snapshot_layout(OUTPUT_ROOT)
    REPORT_ROOT = SNAPSHOT_LAYOUT.report_root
    SNAPSHOT = SNAPSHOT_LAYOUT.snapshot


def git_value(*args: str) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=CONNECTOR_ROOT, text=True).strip()
    except Exception:
        return "unknown"


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def first_text_summary_line(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line:
                return line
    except Exception:
        return ""
    return ""


def normalize_case(path: str) -> str:
    try:
        resolved = Path(path).resolve()
        for root in (CONNECTOR_ROOT, FRAMEWORK_ROOT):
            try:
                return str(resolved.relative_to(root))
            except ValueError:
                continue
        return str(resolved)
    except Exception:
        return path


def resolve_case_path(relative: str) -> Path:
    candidate_paths = [CONNECTOR_ROOT / relative, FRAMEWORK_ROOT / relative]
    return next((candidate for candidate in candidate_paths if candidate.exists()), candidate_paths[0])


def load_case_metadata(case_path: Path) -> dict:
    try:
        return load_case(case_path)
    except Exception:
        try:
            raw = yaml.safe_load(case_path.read_text(encoding="utf-8"))
            return raw if isinstance(raw, dict) else {}
        except Exception:
            return {}


def classify_case(relative: str, status: str, case: dict) -> str:
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    declared = str(metadata.get("classification") or "").strip().lower().replace("-", "_")
    if declared and declared != "active":
        return declared
    text = " ".join(
        [
            relative,
            status,
            str(case.get("category", "") or ""),
            str(case.get("notes", "") or ""),
            str(case.get("source", "") or ""),
        ]
    ).lower()
    if "connector_gap" in text or "connector-gap" in text:
        return "connector_gap"
    if "runtime_difference" in text or "runtime-difference" in text or "runtime_diff" in text:
        return "runtime_difference"
    if "future" in text or "experimental" in text:
        return "future"
    if "pending" in text:
        return "pending"
    return "active"


def case_metadata(path: str) -> dict[str, object]:
    relative = normalize_case(path)
    case_path = resolve_case_path(relative)
    case = load_case_metadata(case_path)
    status = str(case.get("status", "active") or "active").strip().lower()
    group = case_group(case_path, case)
    classification = classify_case(relative, status, case)
    return {
        "yaml_status": status,
        "case_group": group,
        "classification": classification,
        "former_xfail": case.get("former_xfail") is True,
        "response_body_related": is_response_body_related(case, relative),
    }


def case_is_former_xfail(path: str) -> bool:
    return bool(case_metadata(path).get("former_xfail"))


NON_PROMOTABLE_CLASSIFICATIONS = {"pending", "future", "connector_gap", "runtime_difference", "non-promoted", "non_promoted"}


def matrix_status(result_status: str, classification: str, response_body_related: bool = False, *, strict_abort: bool = False) -> str:
    if strict_abort and str(result_status).strip().lower() == "pass":
        return "NOT_EXECUTABLE"
    if str(classification).strip().lower() in NON_PROMOTABLE_CLASSIFICATIONS and str(result_status).strip().lower() == "pass":
        return "NOT_EXECUTABLE"
    if response_body_related and str(result_status).strip().lower() == "pass":
        return "NOT_EXECUTABLE"
    return matrix_status_for_result(
        result_status,
        response_body_related=response_body_related,
    )


def response_body_pass_is_pass_through(expected: object, actual: object, transport: object) -> bool:
    if str(transport or "http_status").strip().lower() in {"connection_aborted", "aborted"}:
        return False
    try:
        return int(str(expected)) == 200 and int(str(actual)) == 200
    except (TypeError, ValueError):
        return False


CASE_ROW_OBSERVATION_FIELDS = (
    "phase",
    "response_headers_seen",
    "response_body_seen",
    "response_body_truncated",
    "response_committed",
    "intervention",
    "strict_abort",
    "observed_status",
    "observed_transport_result",
    "connector_phase4_log_path",
    "nginx_access_log_path",
    "nginx_error_log_path",
    "apache_access_log_path",
    "apache_error_log_path",
    "response_body_path",
    "body_bytes_seen",
    "body_bytes_inspected",
)


def case_evidence(summary_path: Path, name: object, status: str, expected: object, actual: object) -> str:
    evidence = f"{summary_path}; case={name}; status={status}"
    if expected is not None or actual is not None:
        evidence += f"; expected={expected}; actual={actual}"
    return evidence


def case_matrix_status(item: dict, metadata: dict[str, object], status: str, expected: object, actual: object) -> str:
    response_body_related = bool(metadata["response_body_related"])
    computed = matrix_status(
        status,
        str(metadata["classification"]),
        response_body_related,
        strict_abort=item.get("strict_abort") is True,
    )
    if status.strip().lower() == "pass" and (
        item.get("response_body_non_verified") is True or item.get("promotion_allowed") is False
    ):
        return "NOT_EXECUTABLE"
    return computed


def case_reason(item: dict, status: str) -> object:
    reason = item.get("reason", "")
    if not reason and status.strip().lower() == "not_executable":
        return "structurally not executable for this connector/runtime mode; see evidence_path and decision_log_path"
    return reason


def base_case_row(
    name: object,
    item: dict,
    metadata: dict[str, object],
    status: str,
    expected: object,
    actual: object,
    evidence: str,
) -> dict:
    return {
        "case": str(name),
        "path": normalize_case(str(item.get("path", ""))),
        "status": status,
        "matrix_status": case_matrix_status(item, metadata, status, expected, actual),
        "runtime_attempted": True,
        "live_executed": item.get("live_executed") is True,
        "operation_status": item.get("operation_status", "unknown"),
        "expected_status": expected,
        "actual_status": actual,
        "variant": item.get("variant", "-"),
        "scope": item.get("scope", "unknown"),
        "group": item.get("group", "unknown"),
        "yaml_status": metadata["yaml_status"],
        "runtime_classification": metadata["classification"],
        "capabilities": item.get("capabilities", []),
        "requires_crs": item.get("requires_crs") is True,
        "crs_verified": item.get("crs_verified") is True,
        "reason": case_reason(item, status),
        "promotion": item.get("promotion", ""),
        "source_evidence": item.get("evidence", ""),
        "response_body_non_verified": item.get("response_body_non_verified") is True,
        "evidence": evidence,
        "expected": item.get("expected", expected),
        "observed": item.get("observed", actual),
        "evidence_path": item.get("evidence_path", ""),
        "decision_log_path": item.get("decision_log_path", item.get("decision_log", "")),
    }


def add_case_observation_fields(row: dict, item: dict) -> None:
    for key in CASE_ROW_OBSERVATION_FIELDS:
        if key in item:
            row[key] = item.get(key)
    if item.get("audit_log_path"):
        row["audit_log_path"] = item.get("audit_log_path")


def apply_case_non_promotion(row: dict, metadata: dict[str, object], status: str) -> None:
    response_body_related = bool(metadata["response_body_related"])
    row.update(response_body_non_promotion_fields(response_body_related, str(metadata["classification"])))
    if response_body_related:
        row["response_body_related"] = True
        if status.strip().lower() == "pass":
            row["reason"] = RESPONSE_BODY_RUNTIME_NOTE
    if row.get("strict_abort") is True and status.strip().lower() == "pass":
        row["promotion_allowed"] = False
        row["runtime_verified"] = False
        row["reason"] = row.get("reason") or "strict abort evidence is non-promotable"


def case_row(name: object, item: dict, summary_path: Path) -> dict:
    status = str(item.get("status", "unknown"))
    metadata = case_metadata(str(item.get("path", "")))
    expected = item.get("expected_status")
    actual = item.get("actual_status")
    row = base_case_row(
        name,
        item,
        metadata,
        status,
        expected,
        actual,
        case_evidence(summary_path, name, status, expected, actual),
    )
    add_case_observation_fields(row, item)
    apply_case_non_promotion(row, metadata, status)
    return row


def case_rows(summary: dict, connector: str, summary_path: Path) -> list[dict]:
    connector_summary = summary.get(connector)
    cases = connector_summary.get("cases", {}) if isinstance(connector_summary, dict) else {}
    if not isinstance(cases, dict):
        return []
    return [case_row(name, item, summary_path) for name, item in sorted(cases.items()) if isinstance(item, dict)]


def connector_summary_for(summary_data: dict, connector: str) -> dict:
    summary = summary_data.get(connector, {})
    return summary if isinstance(summary, dict) else {}


def connector_counts(connector_summary: dict) -> dict:
    counts = connector_summary.get("summary", {})
    return counts if isinstance(counts, dict) else {}


def current_run_data(
    summary_data: dict,
    connector_summary: dict,
    rows: list[dict],
    exit_code: str,
    require_current_run: bool,
) -> tuple[dict, dict, list[dict]]:
    if require_current_run and exit_code in {"not_run", ""}:
        return {}, {}, []
    return summary_data, connector_summary, rows


def effective_exit_code_for(
    exit_code: str,
    connector_summary: dict,
    rows: list[dict],
    require_current_run: bool,
) -> str:
    effective_exit_code = str(exit_code)
    metadata_exit_status = connector_summary.get("exit_status")
    if effective_exit_code in {"not_run", ""} and metadata_exit_status is not None and rows and not require_current_run:
        return str(metadata_exit_status)
    return effective_exit_code


def connector_status(effective_exit_code: str, counts: dict) -> str:
    if effective_exit_code in {"not_run", ""}:
        return "NOT_RUN"
    try:
        status = "PASS" if int(effective_exit_code) == 0 else "FAIL"
    except ValueError:
        status = "UNKNOWN"
    return "BLOCKED" if counts.get("blocked", 0) and status == "PASS" else status


def connector_build_status(connector_summary: dict) -> str:
    build_status = connector_summary.get("build")
    return str(build_status).strip() if build_status is not None else ""


def unavailable_case_evidence(
    connector: str,
    rows: list[dict],
    status: str,
    build_status: str,
    effective_exit_code: str,
    evidence_note: str,
    summary_path: Path,
    text_summary_path: Path,
) -> tuple[str, dict[str, object]]:
    if rows or status not in {"FAIL", "BLOCKED", "UNKNOWN"}:
        return "", {}
    parts = [f"{connector.upper()} did not complete per-case runtime execution"]
    if build_status:
        parts.append(f"build={build_status}")
    if effective_exit_code not in {"", "not_run"}:
        parts.append(f"exit_code={effective_exit_code}")
    if evidence_note:
        parts.append(evidence_note)
    reason = "; ".join(parts)
    return reason, {
        "reason": reason,
        "summary_path": str(summary_path),
        "text_summary_path": str(text_summary_path),
        "evidence_note": evidence_note,
    }


def failed_case_rows(rows: list[dict], summary_path: Path) -> list[dict]:
    return [
        {
            "case": row["case"],
            "expected": row.get("expected_status"),
            "actual": row.get("actual_status"),
            "assessment": "runtime summary reported non-pass",
            "evidence": row.get("evidence", str(summary_path)),
        }
        for row in rows
        if row.get("status") == "fail" or row.get("matrix_status") == "FAIL"
    ]


def connector_smoke(
    connector: str,
    command: str,
    exit_code: str,
    summary_path: Path,
    text_summary_path: Path,
    *,
    runtime_mode: str = "default",
    require_current_run: bool = False,
) -> dict:
    summary_data = load_json(summary_path)
    connector_summary = connector_summary_for(summary_data, connector)
    counts = connector_counts(connector_summary)
    rows = case_rows(summary_data, connector, summary_path)
    summary_data, connector_summary, rows = current_run_data(
        summary_data,
        connector_summary,
        rows,
        exit_code,
        require_current_run,
    )
    runtime_mode = str(connector_summary.get("runtime_mode") or runtime_mode)
    effective_exit_code = effective_exit_code_for(
        exit_code,
        connector_summary,
        rows,
        require_current_run,
    )
    status = connector_status(effective_exit_code, counts)
    build_status = connector_build_status(connector_summary)
    evidence_note = first_text_summary_line(text_summary_path)
    unavailable_reason, blocker = unavailable_case_evidence(
        connector,
        rows,
        status,
        build_status,
        effective_exit_code,
        evidence_note,
        summary_path,
        text_summary_path,
    )
    return {
        "command": connector_summary.get("command", command),
        "connector": connector,
        "runtime_mode": runtime_mode,
        "status": status,
        "exit_code": int(effective_exit_code) if effective_exit_code.isdigit() else effective_exit_code,
        "summary_path": str(summary_path),
        "text_summary_path": str(text_summary_path),
        "build_status": build_status or "unknown",
        "per_case_results": "available" if rows else "unavailable",
        "per_case_unavailable_reason": unavailable_reason,
        "per_case_unavailable_evidence": evidence_note,
        "blocker": blocker,
        "counts": {
            "pass": counts.get("pass", 0),
            "fail": counts.get("fail", 0),
            "blocked": counts.get("blocked", 0),
            "not_executable": counts.get("not_executable", 0),
            "skipped": counts.get("skipped", 0),
        },
        "attempted": connector_summary.get("attempted", len(rows)),
        "total_cases": connector_summary.get("total_cases", len(rows)),
        "evidence_root": connector_summary.get("evidence_root", str(summary_path.parent)),
        "jsonl_path": connector_summary.get("jsonl_path", str(summary_path.with_name(f"{connector}-results.jsonl"))),
        "per_case_result_root": connector_summary.get("per_case_result_root", ""),
        "failed_due_to_live_mismatches": bool(connector_summary.get("failed_due_to_live_mismatches", False)),
        "verified_variables": connector_summary.get("verified_variables", []),
        "variant": summary_data.get("variant", connector_summary.get("variant", "")),
        "runtime_status": summary_data.get("runtime_status", ""),
        "matrix_counts": summary_data.get("counts", connector_summary.get("matrix_counts", {})) if isinstance(connector_summary, dict) else {},
        "verified_cases": summary_data.get("verified_cases", []),
        "crs_verified": summary_data.get("crs_verified", False) is True,
        "crs_verified_scope": summary_data.get("crs_verified_scope", []),
        "response_body_verified": summary_data.get("response_body_verified", False) is True,
        "full_matrix_verified": bool(summary_data.get("full_matrix_verified") or summary_data.get("matrix_full")),
        "mapped_only": summary_data.get("mapped_only", connector_summary.get("mapped_only", [])),
        "failed_cases": failed_case_rows(rows, summary_path),
        "cases": rows,
        "details": "Per-case results are copied from the local smoke summary JSON; they are runtime evidence only.",
    }


def current_test_variant() -> str:
    return str(os.environ.get("MODSECURITY_TEST_VARIANT") or "no-crs").strip() or "no-crs"


def current_mrts_variant() -> str:
    return str(os.environ.get("MODSECURITY_MRTS_VARIANT") or "no-mrts").strip() or "no-mrts"


def variant_summary_path(results_dir: Path, connector: str, fallback: Path) -> Path:
    """Return the direct summary created by the runtime-matrix invocation.

    Variant directories belong to separately invoked MRTS/CRS targets and can
    retain evidence from an earlier run.  A default runtime-matrix snapshot
    must never select one merely because it happens to exist.
    """
    del results_dir, connector
    return fallback


def summary_text_path(summary_path: Path) -> Path:
    return summary_path.with_name(summary_path.name.replace("-summary.json", "-summary.txt"))


def haproxy_default_matrix_smoke(
    command: str,
    exit_code: str,
    results_dir: Path,
) -> dict:
    summary_path = variant_summary_path(results_dir, "haproxy", results_dir / "haproxy-summary.json")
    text_summary_path = summary_text_path(summary_path)
    if exit_code in {"not_run", ""}:
        return not_available_force_all_row("haproxy", summary_path, command)

    row = connector_smoke("haproxy", command, exit_code, summary_path, text_summary_path)
    cases = [
        item
        for item in row.get("cases", [])
        if isinstance(item, dict)
        and item.get("live_executed") is True
        and not case_is_former_xfail(str(item.get("path", "")))
        and item.get("runtime_classification") == "active"
        and item.get("response_body_non_verified") is not True
        and item.get("strict_abort") is not True
    ]
    counts = {"pass": 0, "fail": 0, "blocked": 0, "not_executable": 0, "skipped": 0}
    for item in cases:
        status = str(item.get("status", "skipped")).strip().lower()
        if status in counts:
            counts[status] += 1
    failed_cases = [
        {
            "case": item.get("case"),
            "expected": item.get("expected_status"),
            "actual": item.get("actual_status"),
            "assessment": "runtime summary reported non-pass",
            "evidence": item.get("evidence", str(summary_path)),
        }
        for item in cases
        if item.get("status") == "fail" or item.get("matrix_status") == "FAIL"
    ]

    row.update(
        {
            "command": command,
            "status": "PASS" if cases and counts["fail"] == 0 and counts["blocked"] == 0 else row.get("status", "UNKNOWN"),
            "exit_code": 0 if cases and counts["fail"] == 0 and counts["blocked"] == 0 else row.get("exit_code", exit_code),
            "counts": counts,
            "attempted": len(cases),
            "total_cases": len(cases),
            "failed_due_to_live_mismatches": bool(failed_cases),
            "failed_cases": failed_cases,
            "cases": cases,
            "details": "Default HAProxy evidence is the supported non-former-XFAIL subset of live HAProxy matrix evidence; force-all rows remain separate runtime evidence.",
        }
    )
    return row


def runtime_smoke_by_connector(snapshot: dict) -> dict[str, dict]:
    rows = snapshot.get("runtime_smokes", [])
    if not isinstance(rows, list):
        return {}
    by_connector: dict[str, dict] = {}
    for row in rows:
        if isinstance(row, dict) and row.get("connector"):
            by_connector[str(row.get("connector"))] = row
    return by_connector


def force_all_runtime_smoke_by_connector(snapshot: dict) -> dict[str, dict]:
    rows = snapshot.get("force_all_runtime_smokes", [])
    if not isinstance(rows, list):
        return {}
    by_connector: dict[str, dict] = {}
    for row in rows:
        if isinstance(row, dict) and row.get("connector"):
            by_connector[str(row.get("connector"))] = row
    return by_connector


def not_available_force_all_row(connector: str, summary_path: Path, command: str) -> dict:
    return {
        "command": command,
        "connector": connector,
        "runtime_mode": "force-all",
        "status": "NOT_AVAILABLE",
        "exit_code": "not_run",
        "summary_path": str(summary_path),
        "text_summary_path": str(summary_path.with_suffix(".txt")),
        "build_status": "not_available",
        "per_case_results": "not_available",
        "per_case_unavailable_reason": f"No {connector.upper()} force-all summary is available.",
        "per_case_unavailable_evidence": "",
        "blocker": {},
        "counts": {
            "pass": "unknown",
            "fail": "unknown",
            "blocked": "unknown",
            "not_executable": "unknown",
            "skipped": "unknown",
        },
        "attempted": 0,
        "total_cases": 0,
        "evidence_root": str(summary_path.parent),
        "jsonl_path": str(summary_path.with_name(f"{connector}-results.jsonl")),
        "per_case_result_root": "",
        "failed_due_to_live_mismatches": False,
        "failed_cases": [],
        "cases": [],
        "details": "No force-all runtime evidence was found for this connector.",
    }


def connector_smoke_or_existing(
    existing_by_connector: dict[str, dict],
    connector: str,
    command: str,
    exit_code: str,
    summary_path: Path,
    text_summary_path: Path,
    *,
    runtime_mode: str = "default",
) -> dict:
    if exit_code in {"not_run", ""} and connector in existing_by_connector:
        return existing_by_connector[connector]
    return connector_smoke(connector, command, exit_code, summary_path, text_summary_path, runtime_mode=runtime_mode)


def not_run_all_row(existing_by_connector: dict[str, dict]) -> dict:
    if "all" in existing_by_connector:
        row = dict(existing_by_connector["all"])
        counts = row.get("counts")
        if isinstance(counts, dict):
            counts = dict(counts)
            counts.pop("xfail", None)
            row["counts"] = counts
        return row
    return {
        "command": "REFRESH=1 make smoke-all",
        "connector": "all",
        "runtime_mode": "default",
        "status": "NOT_RUN",
        "exit_code": "not_run",
        "summary_path": "not available",
        "text_summary_path": "not available",
        "build_status": "not_run",
        "per_case_results": "not_run",
        "per_case_unavailable_reason": "Full smoke-all was not run by runtime-matrix.",
        "per_case_unavailable_evidence": "",
        "blocker": {},
        "counts": {
            "pass": "unknown",
            "fail": "unknown",
            "blocked": "unknown",
            "not_executable": "unknown",
            "skipped": "unknown",
        },
        "failed_cases": [],
        "cases": [],
        "details": "Not run by runtime-matrix; no full-smoke PASS numbers claimed.",
    }


def validated_snapshot_path() -> Path:
    snapshot_path = SNAPSHOT.resolve()
    if snapshot_path.name != SNAPSHOT_FILENAME:
        raise ValueError(f"unexpected snapshot file name: {snapshot_path}")
    expected_snapshot_path = build_safe_snapshot_path(OUTPUT_ROOT)
    if snapshot_path != expected_snapshot_path:
        raise ValueError(f"snapshot path must be the configured report snapshot: {snapshot_path}")
    return snapshot_path


def write_snapshot(snapshot: dict) -> None:
    if validated_snapshot_path() != active_snapshot_layout().snapshot:
        raise ValueError("snapshot path validation mismatch")
    active_snapshot_layout().write(snapshot)


def load_existing_snapshot() -> dict:
    data = load_json(SNAPSHOT)
    return data if data else {}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", default=str(default_build_root()))
    parser.add_argument("--framework-root", default=str(FRAMEWORK_ROOT))
    parser.add_argument("--connector-root", default=str(Path.cwd()))
    parser.add_argument("--output-root")
    parser.add_argument("--apache-exit-code", default="not_run")
    parser.add_argument("--nginx-exit-code", default="not_run")
    parser.add_argument("--haproxy-exit-code", default="not_run")
    parser.add_argument("--apache-command", default="REFRESH=1 make smoke-apache")
    parser.add_argument("--nginx-command", default="REFRESH=1 make smoke-nginx")
    parser.add_argument("--haproxy-command", default="make smoke-haproxy")
    parser.add_argument("--force-all", action="store_true")
    args = parser.parse_args()
    configure_paths(args.framework_root, args.connector_root, args.output_root)

    build_root = Path(args.build_root)
    results_dir = build_root / "results"
    existing = load_existing_snapshot()
    existing_by_connector = runtime_smoke_by_connector(existing)
    existing_force_by_connector = force_all_runtime_smoke_by_connector(existing)
    now = datetime.now(ZoneInfo("Europe/Berlin"))
    default_apache_exit_code = "not_run" if args.force_all else str(args.apache_exit_code)
    default_nginx_exit_code = "not_run" if args.force_all else str(args.nginx_exit_code)
    default_haproxy_exit_code = "not_run" if args.force_all else str(args.haproxy_exit_code)
    force_all_dir = results_dir / "force-all"
    default_apache_summary = variant_summary_path(results_dir, "apache", results_dir / "apache-summary.json")
    default_nginx_summary = variant_summary_path(results_dir, "nginx", results_dir / "nginx-summary.json")

    def force_all_smoke_row(connector: str, command: str, exit_code: str) -> dict:
        summary_path = force_all_dir / f"{connector}-summary.json"
        text_summary_path = force_all_dir / f"{connector}-summary.txt"
        if not args.force_all:
            return not_available_force_all_row(connector, summary_path, command)
        if summary_path.exists():
            return connector_smoke(
                connector,
                command,
                exit_code,
                summary_path,
                text_summary_path,
                runtime_mode="force-all",
                require_current_run=True,
            )
        if connector in existing_force_by_connector:
            return existing_force_by_connector[connector]
        return not_available_force_all_row(connector, summary_path, command)

    snapshot = {
        "snapshot_date": now.date().isoformat(),
        "captured_at": now.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "branch": git_value("branch", "--show-current"),
        "commit": git_value("rev-parse", "--short", "HEAD"),
        "build_root": str(build_root),
        "force_all_cases": args.force_all,
        "notes": [
            "Runtime matrix snapshot generated from local Apache, NGINX, and HAProxy summary JSON files when present.",
            "Per-case PASS/FAIL/BLOCKED/NOT_EXECUTABLE values are runtime evidence for this local run only.",
            "Former XFAIL YAML cases are normal runtime cases; live results decide PASS/FAIL/BLOCKED/NOT_EXECUTABLE.",
            "RESPONSE_BODY remains non-verified/non-promoted, including pass-through response-body probes.",
            "Runtime-passing RESPONSE_BODY cases are marked non-promotable pass-through evidence.",
            "Mapped-only import inventory entries remain visible but are not executed runtime cases.",
            "make smoke-all is not implied by separate Apache/NGINX runtime matrix runs.",
        ],
        "framework_checks": existing.get("framework_checks", []),
        "readiness_checks": existing.get("readiness_checks", []),
        "runtime_smokes": [
            connector_smoke_or_existing(
                existing_by_connector,
                "apache",
                args.apache_command,
                default_apache_exit_code,
                default_apache_summary,
                summary_text_path(default_apache_summary),
            ),
            connector_smoke_or_existing(
                existing_by_connector,
                "nginx",
                args.nginx_command,
                default_nginx_exit_code,
                default_nginx_summary,
                summary_text_path(default_nginx_summary),
            ),
            haproxy_default_matrix_smoke(
                args.haproxy_command,
                default_haproxy_exit_code,
                results_dir,
            ),
            not_run_all_row(existing_by_connector),
        ],
        "force_all_runtime_smokes": [
            force_all_smoke_row(
                "apache",
                f"FORCE_ALL_CASES=1 {args.apache_command}",
                str(args.apache_exit_code) if args.force_all else "not_run",
            ),
            force_all_smoke_row(
                "nginx",
                f"FORCE_ALL_CASES=1 {args.nginx_command}",
                str(args.nginx_exit_code) if args.force_all else "not_run",
            ),
            force_all_smoke_row(
                "haproxy",
                args.haproxy_command if args.force_all else "FORCE_ALL_CASES=1 make smoke-haproxy",
                str(args.haproxy_exit_code) if args.force_all else "not_run",
            ),
        ],
        "runtime_verified_status": [
            "Runtime matrix records current local Apache, NGINX, and HAProxy per-case smoke evidence when available.",
            "PASS in this snapshot means the case was executed by that connector's smoke harness and matched the case expectation in the summary JSON.",
            "Pending, connector-gap, runtime-difference, future, and mapped-only inventory are not promoted by this snapshot.",
            "FORCE_ALL_CASES=1 attempts all materializable YAML cases where they are applicable to the connector.",
            "HAProxy PASS is scoped to live HAProxy evidence only; current HAProxy coverage is partial request-side YAML execution.",
            "RESPONSE_BODY remains non-verified/non-promoted.",
            "Runtime passed, but this does not verify RESPONSE_BODY support.",
            "make smoke-all was not run by runtime-matrix; full-smoke PASS counts remain unknown.",
        ],
        "open_issues": [
            "Mapped-only import inventory entries are not executable YAML runtime cases.",
            "Pending/future/connector-gap/runtime-difference topics require live evidence before any support claim.",
            "RESPONSE_BODY remains experimental/non-verified.",
        ],
    }
    write_snapshot(snapshot)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
