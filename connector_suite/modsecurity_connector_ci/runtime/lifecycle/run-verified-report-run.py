#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# CI helpers are shared from ci/lib even when this file is executed directly.

from typing import Any

from modsecurity_connector_ci.lib.best_effort_evidence_readers import read_json_object as read_json, read_jsonl_objects as read_jsonl
from modsecurity_connector_ci.lib.generated_report_utils import DATA_SOURCE_POLICY, GENERATED_REPORTS, build_metadata, current_verified_run_id, generated_json_text, generated_markdown_text, git_sha, report_path, report_relpath, sha256_file, utc_now
from modsecurity_connector_ci.lib.runtime_path_utils import WORKER_BLOCKED_REASON, canonical_project_roots, ensure_safe_runtime_directory, ensure_safe_writable_runtime_paths, is_under_root_home, open_runtime_artifact_parent, read_runtime_artifact_text, require_regular_runtime_artifact, runtime_artifact_path, runtime_path_rows, verified_runtime_paths, write_runtime_artifact_text_atomic
from modsecurity_connector_ci.lib.verified_run_id import VerifiedRunIdError, validate_verified_run_id
from modsecurity_connector_ci.lib.verified_full_matrix_receipt import AggregateReceiptError, aggregate_receipt_path, full_matrix_aggregate_receipt_record, seal_full_matrix_aggregate_receipt_record, validate_full_matrix_aggregate_receipt


SELF_GENERATED_VERIFIED_MANIFESTS = {
    "verified-run-manifest.generated.json",
    "verified-run-manifest.generated.md",
}
FULL_MATRIX_JOB_PREFIX = "full-matrix-job:"
UTC_OFFSET = "+00:00"
FIELD_VALUE_TABLE_HEADER = "| Field | Value |"
FIELD_VALUE_TABLE_DIVIDER = "|---|---|"
FOUR_COLUMN_TABLE_DIVIDER = "|---|---|---|---|"
ARGPARSE_ERROR_TERMINATION_ASSERTION = "argparse.error must terminate execution"
CURRENT_RUN_MARKER_LABEL = "current-run marker"


def git_output(args: list[str], cwd: Path) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
        )
    except Exception as exc:
        return f"unknown: {exc}"
    return result.stdout.strip() or "unknown"


def git_dirty_status(root: Path) -> str:
    status = git_output(["status", "--short"], root)
    if status.startswith("unknown:"):
        return "unknown"
    return "dirty" if status else "clean"


def git_branch(root: Path) -> str:
    return git_output(["rev-parse", "--abbrev-ref", "HEAD"], root)


def command_status(return_code: int, *, optional: bool = False, classification: str = "") -> str:
    if return_code == 0:
        return "PASS"
    if classification == "blocked_timeout":
        return "BLOCKED_TIMEOUT"
    if classification in {"blocked_network", "blocked_network_optional", "producer_readiness_blocked", "nginx_worker_docroot_blocked"}:
        return "BLOCKED_OPTIONAL" if optional else "BLOCKED"
    if classification == "interrupted":
        return "INTERRUPTED"
    if optional:
        return "BLOCKED_OPTIONAL" if return_code == 77 else "FAILED_OPTIONAL"
    if return_code == 77:
        return "BLOCKED"
    return "FAIL"


def write_commands_file(root: Path, path: Path, payload: dict[str, Any]) -> None:
    write_runtime_artifact_text_atomic(
        root,
        path,
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        "verified commands file",
    )


def canonical_roots(connector_root: str, framework_root: str | None) -> tuple[Path, Path]:
    """Do not allow CLI arguments to redirect runtime commands to other trees."""

    canonical_connector, canonical_framework = canonical_project_roots()
    requested_connector = Path(connector_root).resolve(strict=True)
    requested_framework = (
        Path(framework_root).resolve(strict=True)
        if framework_root
        else canonical_framework
    )
    if requested_connector != canonical_connector:
        raise ValueError(f"connector root must be this checkout: {requested_connector}")
    if requested_framework != canonical_framework:
        raise ValueError(f"framework root must be the pinned checkout: {requested_framework}")
    return canonical_connector, canonical_framework


def count_jsonl_rows(path: Path, root: Path) -> int:
    try:
        lines = read_runtime_artifact_text(root, path, "matrix results", errors="replace").splitlines()
    except (OSError, ValueError):
        return 0
    return sum(1 for line in lines if line.strip())


def private_job_json(root: Path, path: Path, label: str) -> dict[str, Any]:
    target = runtime_artifact_path(root, path, label)
    if not target.is_file():
        return {}
    try:
        data = json.loads(read_runtime_artifact_text(root, target, label))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def full_matrix_job_tokens(logical_target: str) -> tuple[str, str, str] | None:
    prefix = FULL_MATRIX_JOB_PREFIX
    if not logical_target.startswith(prefix):
        return None
    parts = logical_target.removeprefix(prefix).split(":")
    if len(parts) != 3:
        return None
    connector, crs, mrts = parts
    if connector not in {"apache", "nginx", "haproxy"} or crs not in {"no-crs", "with-crs"} or mrts not in {"no-mrts", "with-mrts"}:
        return None
    return connector, crs, mrts


def full_matrix_job_artifacts(env: dict[str, str], logical_target: str) -> dict[str, Any]:
    tokens = full_matrix_job_tokens(logical_target)
    if tokens is None:
        return {"complete": False}
    connector, crs, mrts = tokens
    matrix_root = Path(env.get("MATRIX_ROOT", ""))
    root = matrix_root / crs / mrts / connector
    job_path = root / "job.json"
    job = private_job_json(root, job_path, "matrix job")
    summary_path = Path(str(job.get("summary_path") or ""))
    if not summary_path.is_absolute():
        summary_path = root / "results" / "force-all" / f"{connector}-summary.json"
    results_jsonl = root / "results" / "force-all" / f"{connector}-results.jsonl"
    summary = private_job_json(root, summary_path, "matrix summary")
    connector_summary = summary.get(connector) if isinstance(summary.get(connector), dict) else {}
    cases = connector_summary.get("cases") if isinstance(connector_summary.get("cases"), dict) else {}
    result_rows = count_jsonl_rows(results_jsonl, root)
    status = str(job.get("status") or "")
    complete = (
        bool(job.get("ended_at"))
        and "return_code" in job
        and status in {"completed", "completed_with_mismatches"}
        and summary_path.is_file()
        and (bool(cases) or result_rows > 0)
    )
    return {
        "complete": complete,
        "job": job,
        "job_path": str(job_path),
        "summary_path": str(summary_path),
        "results_jsonl": str(results_jsonl),
        "result_rows": result_rows,
        "summary_cases": len(cases),
    }


def command_log_path(logs_dir: Path, index: int, command: list[str]) -> Path:
    slug = "".join(ch if ch.isalnum() else "-" for ch in "-".join(command)).strip("-")[:96] or "command"
    return logs_dir / f"{index:02d}-{slug}.log"


def send_process_group_signal(process: subprocess.Popen[str], signal_value: signal.Signals) -> None:
    try:
        os.killpg(process.pid, signal_value)
    except ProcessLookupError:
        pass


def terminate_timed_out_process(process: subprocess.Popen[str]) -> int:
    send_process_group_signal(process, signal.SIGTERM)
    try:
        return process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        send_process_group_signal(process, signal.SIGKILL)
        return process.wait()


def wait_for_full_matrix_finalization(
    process: subprocess.Popen[str],
    *,
    env: dict[str, str],
    logical_target: str,
    finalize_grace_seconds: int,
    log_handle: Any,
) -> int | None:
    if not logical_target.startswith(FULL_MATRIX_JOB_PREFIX) or finalize_grace_seconds <= 0:
        return None
    log_handle.write(
        f"verified-report-run: waiting {finalize_grace_seconds} seconds for full-matrix job finalization\n"
    )
    try:
        return process.wait(timeout=finalize_grace_seconds)
    except subprocess.TimeoutExpired:
        artifacts = full_matrix_job_artifacts(env, logical_target)
        if artifacts.get("complete"):
            log_handle.write(
                "verified-report-run: full-matrix job artifacts completed during timeout finalization\n"
            )
        return None


def timeout_return_code(
    process: subprocess.Popen[str],
    *,
    env: dict[str, str],
    logical_target: str,
    finalize_grace_seconds: int,
    log_handle: Any,
) -> tuple[int, bool]:
    finalization_return_code = wait_for_full_matrix_finalization(
        process,
        env=env,
        logical_target=logical_target,
        finalize_grace_seconds=finalize_grace_seconds,
        log_handle=log_handle,
    )
    if finalization_return_code is not None:
        return finalization_return_code, True
    artifacts = full_matrix_job_artifacts(env, logical_target)
    if artifacts.get("complete"):
        return int(artifacts.get("job", {}).get("return_code", 2)), False
    return terminate_timed_out_process(process), False


def wait_for_command_process(
    process: subprocess.Popen[str],
    *,
    env: dict[str, str],
    logical_target: str,
    timeout_seconds: int | None,
    finalize_grace_seconds: int,
    log_handle: Any,
) -> tuple[int, str]:
    try:
        return process.wait(timeout=timeout_seconds), ""
    except subprocess.TimeoutExpired:
        log_handle.write(
            f"\nverified-report-run: timeout after {timeout_seconds} seconds; terminating process group\n"
        )
        return_code, completed_during_finalization = timeout_return_code(
            process,
            env=env,
            logical_target=logical_target,
            finalize_grace_seconds=finalize_grace_seconds,
            log_handle=log_handle,
        )
        return return_code, "" if completed_during_finalization else "blocked_timeout"


def execute_command_process(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    log_path: Path,
    logical_target: str,
    timeout_seconds: int | None,
    finalize_grace_seconds: int,
) -> tuple[int, str]:
    with log_path.open("w", encoding="utf-8") as log_handle:
        process = subprocess.Popen(
            command,
            cwd=str(cwd),
            env=env,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        try:
            return wait_for_command_process(
                process,
                env=env,
                logical_target=logical_target,
                timeout_seconds=timeout_seconds,
                finalize_grace_seconds=finalize_grace_seconds,
                log_handle=log_handle,
            )
        except KeyboardInterrupt:
            log_handle.write("\nverified-report-run: interrupted; terminating process group\n")
            send_process_group_signal(process, signal.SIGTERM)
            return process.wait(), "interrupted"


def interrupted_signal_name(return_code: int) -> str:
    if return_code >= 0:
        return ""
    try:
        return signal.Signals(-return_code).name
    except ValueError:
        return f"SIG{-return_code}"


def classify_command_log(
    return_code: int,
    classification: str,
    log_text: str,
    *,
    optional: bool,
) -> str:
    if return_code == 0 or classification:
        return classification
    if "HTTP Error 504" in log_text or "Gateway Timeout" in log_text:
        return "blocked_network_optional" if optional else "blocked_network"
    if WORKER_BLOCKED_REASON in log_text:
        return "nginx_worker_docroot_blocked"
    return classification


def run_command(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    logs_dir: Path,
    index: int,
    phase: str,
    required: bool,
    optional: bool,
    timeout_seconds: int | None,
    finalize_grace_seconds: int,
    affected_reports: list[str],
    logical_target: str,
) -> dict[str, Any]:
    started_at = utc_now()
    started = time.monotonic()
    log_path = command_log_path(logs_dir, index, command)
    print("verified-report-run: RUN " + " ".join(command), flush=True)
    return_code, classification = execute_command_process(
        command,
        cwd=cwd,
        env=env,
        log_path=log_path,
        logical_target=logical_target,
        timeout_seconds=timeout_seconds,
        finalize_grace_seconds=finalize_grace_seconds,
    )
    finished_at = utc_now()
    signal_name = interrupted_signal_name(return_code)
    if signal_name:
        classification = classification or "interrupted"
    log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.is_file() else ""
    classification = classify_command_log(return_code, classification, log_text, optional=optional)
    log_hash = sha256_file(log_path)
    status = command_status(return_code, optional=optional, classification=classification)
    print(f"verified-report-run: {status} rc={return_code} log={log_path}", flush=True)
    return {
        "phase": phase,
        "command": command,
        "logical_target": logical_target,
        "required": required,
        "optional": optional,
        "affected_reports": affected_reports,
        "status": status,
        "return_code": return_code,
        "classification": classification or ("success" if return_code == 0 else "command_failed"),
        "signal": signal_name,
        "timeout_seconds": timeout_seconds,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": round(time.monotonic() - started, 3),
        "log_path": str(log_path),
        "log_hash": log_hash,
        "notes": "executed in verified-report-run",
    }


def skipped_command_record(
    command: list[str],
    *,
    logs_dir: Path,
    index: int,
    phase: str,
    required: bool,
    optional: bool,
    affected_reports: list[str],
    reason: str,
    logical_target: str,
) -> dict[str, Any]:
    started_at = utc_now()
    slug = "".join(ch if ch.isalnum() else "-" for ch in "-".join(command)).strip("-")[:96] or "command"
    log_path = logs_dir / f"{index:02d}-{slug}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(f"verified-report-run: skipped because {reason}\n", encoding="utf-8")
    return {
        "phase": phase,
        "command": command,
        "logical_target": logical_target,
        "required": required,
        "optional": optional,
        "affected_reports": affected_reports,
        "status": command_status(77, optional=optional, classification="producer_readiness_blocked"),
        "return_code": 77,
        "classification": "producer_readiness_blocked",
        "signal": "",
        "timeout_seconds": 0,
        "started_at": started_at,
        "finished_at": started_at,
        "duration_seconds": 0.0,
        "log_path": str(log_path),
        "log_hash": sha256_file(log_path),
        "notes": f"not executed: {reason}",
    }


def file_record(path: Path, root: Path) -> dict[str, Any]:
    shown = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
    if not path.is_file():
        return {"path": shown, "status": "missing", "sha256": "missing"}
    return {"path": shown, "status": "present", "sha256": sha256_file(path), "bytes": path.stat().st_size}


def aggregate_receipt_manifest_record(
    *,
    commands: list[dict[str, Any]],
    build_root: Path,
    verified_run_id: str,
) -> dict[str, Any]:
    """Use sealed descriptor metadata instead of reopening a mutable receipt path."""

    for command in reversed(commands):
        candidate = command.get("aggregate_receipt")
        if not isinstance(candidate, dict) or candidate.get("status") not in {"sealed", "already_sealed"}:
            continue
        path = candidate.get("path")
        digest = candidate.get("sha256")
        byte_count = candidate.get("bytes")
        if isinstance(path, str) and isinstance(digest, str) and isinstance(byte_count, int):
            return {
                "path": path,
                "status": "present",
                "sha256": digest,
                "bytes": byte_count,
            }
    try:
        receipt = full_matrix_aggregate_receipt_record(
            build_root=build_root,
            verified_run_id=verified_run_id,
            missing_ok=True,
        )
    except AggregateReceiptError:
        return {"path": "invalid", "status": "missing", "sha256": "missing"}
    if receipt is None:
        try:
            path = str(aggregate_receipt_path(build_root, verified_run_id))
        except AggregateReceiptError:
            path = "invalid"
        return {"path": path, "status": "missing", "sha256": "missing"}
    return {
        "path": receipt["path"],
        "status": "present",
        "sha256": receipt["sha256"],
        "bytes": receipt["bytes"],
    }


def generated_output_records(connector_root: Path) -> list[dict[str, Any]]:
    generated_root = connector_root / "reports/testing/generated"
    if not generated_root.is_dir():
        return []
    return [
        file_record(path, connector_root)
        for path in sorted(generated_root.rglob("*.generated.*"))
        if path.is_file() and path.name not in SELF_GENERATED_VERIFIED_MANIFESTS
    ]


def manifest_report_records(connector_root: Path) -> list[dict[str, Any]]:
    manifest = read_json(report_path(connector_root, "report_refresh_manifest", "json"))
    reports = manifest.get("reports")
    return reports if isinstance(reports, list) else []


def collect_declared_inputs(connector_root: Path) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for report in manifest_report_records(connector_root):
        for item in report.get("inputs", []):
            if not isinstance(item, dict):
                continue
            path = str(item.get("path", "unknown"))
            rows[path] = {
                "path": path,
                "status": item.get("status", "unknown"),
                "sha256": item.get("sha256") or item.get("source_hash") or "unknown",
                "verified_run_id": item.get("verified_run_id", "unknown"),
                "notes": item.get("notes", ""),
            }
    return [rows[key] for key in sorted(rows)]


def collect_report_statuses(connector_root: Path, status_prefix: str | None = None, status_values: set[str] | None = None) -> list[dict[str, Any]]:
    rows = []
    for report in manifest_report_records(connector_root):
        status = str(report.get("status", "unknown"))
        if status_prefix is not None and not status.startswith(status_prefix):
            continue
        if status_values is not None and status not in status_values:
            continue
        rows.append(
            {
                "report_name": report.get("report_name", "unknown"),
                "status": status,
                "reason": report.get("blocked_reason") or report.get("freshness_status") or report.get("input_status") or "unknown",
                "outputs": report.get("output_files", []),
                "inputs": report.get("input_files", []),
            }
        )
    return rows


def runtime_paths(env: dict[str, str], build_root: Path, verified_run_id: str) -> dict[str, str]:
    verified_run_id = validate_verified_run_id(verified_run_id)
    paths = verified_runtime_paths(env, build_root_override=build_root)
    verified_build_root = Path(paths["BUILD_ROOT"])
    verified_runs_root = verified_build_root / "verified-runs"
    paths["VERIFIED_RUNS_ROOT"] = str(verified_runs_root)
    paths["VERIFIED_RUN_INSTANCE_ROOT"] = str(verified_runs_root / verified_run_id)
    paths["VERIFIED_RUN_INSTANCE_LOG_ROOT"] = str(
        verified_runs_root / verified_run_id / "logs"
    )
    return paths


def prepare_runtime_roots(paths: dict[str, str]) -> None:
    ensure_safe_writable_runtime_paths(paths)
    for key in (
        "VERIFIED_RUNS_ROOT",
        "VERIFIED_RUN_INSTANCE_ROOT",
        "VERIFIED_RUN_INSTANCE_LOG_ROOT",
    ):
        ensure_safe_runtime_directory(paths[key])


def runtime_path_report_rows(paths: dict[str, str], connector_root: Path, framework_root: Path) -> list[dict[str, Any]]:
    return runtime_path_rows(paths, connector_root=connector_root, framework_root=framework_root)


def harness_parent_preflight_rows(harness_parent: Path) -> list[dict[str, Any]]:
    root_status = "FAIL" if is_under_root_home(harness_parent) else "PASS"
    rows = [
        {
            "check": "Path under /root",
            "status": root_status,
            "path": str(harness_parent),
            "notes": "NGINX_HARNESS_PARENT must be outside /root" if root_status == "FAIL" else "outside /root",
        }
    ]
    if harness_parent.exists():
        traverse_status = "PASS" if os.access(harness_parent, os.X_OK) else "FAIL"
        rows.append(
            {
                "check": "Harness parent traversable",
                "status": traverse_status,
                "path": str(harness_parent),
                "notes": "current process can traverse; per-case worker checks are recorded in nginx-worker-preflight.jsonl",
            }
        )
    else:
        rows.append(
            {
                "check": "Harness parent traversable",
                "status": "UNKNOWN",
                "path": str(harness_parent),
                "notes": "harness parent has not been created yet",
            }
        )
    return rows


def worker_preflight_candidates(harness_parent: Path, build_root: Path) -> list[Path]:
    candidates: list[Path] = []
    for root in (harness_parent, build_root):
        if root.exists():
            candidates.extend(root.rglob("nginx-worker-preflight.jsonl"))
    return sorted(
        candidates,
        key=lambda item: item.stat().st_mtime if item.exists() else 0,
        reverse=True,
    )


def worker_preflight_evidence_rows(candidates: list[Path], maximum_rows: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in candidates:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        for record in read_jsonl(path):
            if not isinstance(record, dict):
                continue
            rows.append(
                {
                    "check": record.get("check", "unknown"),
                    "status": record.get("status", "UNKNOWN"),
                    "path": record.get("path", str(path)),
                    "notes": record.get("notes", "-"),
                    "source_file": str(path),
                    "source_hash": sha256_file(path),
                }
            )
            if len(rows) >= maximum_rows:
                return rows
    return rows


def worker_preflight_rows(paths: dict[str, str], build_root: Path) -> list[dict[str, Any]]:
    harness_parent = Path(paths["NGINX_HARNESS_PARENT"])
    rows = harness_parent_preflight_rows(harness_parent)
    evidence_rows = worker_preflight_evidence_rows(
        worker_preflight_candidates(harness_parent, build_root),
        60 - len(rows),
    )
    rows.extend(evidence_rows)
    return rows


def full_matrix_completeness_summary(connector_root: Path) -> dict[str, Any]:
    data = read_json(report_path(connector_root, "full_matrix_job_completeness", "json"))
    jobs = data.get("jobs") if isinstance(data.get("jobs"), list) else []
    slowest = data.get("slowest_jobs") if isinstance(data.get("slowest_jobs"), list) else []
    return {
        "status": data.get("overall_status", "unknown"),
        "complete_jobs": data.get("complete_jobs", 0),
        "total_jobs": data.get("total_jobs", 0),
        "missing_jobs": data.get("missing_job_ids", []),
        "timeout_jobs": [
            job.get("job_id", "unknown")
            for job in jobs
            if str(job.get("status", "")).startswith("timeout") or "timeout" in str(job.get("reason", "")).lower()
        ],
        "slowest_jobs": [
            {
                "job_id": job.get("job_id", "unknown"),
                "duration_seconds": job.get("duration_seconds", "unknown"),
                "status": job.get("status", "unknown"),
            }
            for job in slowest[:5]
            if isinstance(job, dict)
        ],
        "source": str(report_path(connector_root, "full_matrix_job_completeness", "json")),
    }


def runtime_mismatch_summary(connector_root: Path) -> dict[str, Any]:
    data = read_json(report_path(connector_root, "verified_runtime_mismatch_analysis", "json"))
    by_connector = data.get("by_connector") if isinstance(data.get("by_connector"), dict) else {}
    top_connector = "unknown"
    top_count = -1
    for name, value in by_connector.items():
        count = value.get("total", value.get("count", 0)) if isinstance(value, dict) else value
        try:
            numeric = int(count)
        except Exception:
            numeric = 0
        if numeric > top_count:
            top_connector = str(name)
            top_count = numeric
    full_matrix = data.get("full_matrix") if isinstance(data.get("full_matrix"), dict) else {}
    blocker = full_matrix.get("classification") or full_matrix.get("status") or data.get("merge_readiness_reason") or "unknown"
    return {
        "total_mismatches": data.get("mismatch_count", "unknown"),
        "critical_mismatches": data.get("critical_mismatch_count", "unknown"),
        "top_connector": top_connector,
        "primary_blocker": blocker,
        "merge_readiness": data.get("merge_readiness", "unknown"),
        "source": str(report_path(connector_root, "verified_runtime_mismatch_analysis", "json")),
    }


def manifest_input_status(payload: dict[str, Any], metadata_status: str) -> str:
    if payload.get("missing_inputs") or payload.get("blocked_reports") or payload.get("failed_reports"):
        return "blocked"
    for item in payload.get("skipped_reports", []):
        status = str(item.get("status", ""))
        if status == "skipped_stale_input":
            return "stale"
        if status.startswith("skipped"):
            return "blocked"
    if payload.get("stale_inputs"):
        return "stale"
    if metadata_status != "complete":
        return metadata_status
    completeness = payload.get("full_matrix_job_completeness", {})
    if completeness.get("status") == "unknown":
        return "unknown"
    mismatch = payload.get("runtime_mismatch_summary", {})
    if mismatch.get("total_mismatches", "unknown") == "unknown":
        return "unknown"
    return "complete"


def parse_timeout(value: str | None) -> int | None:
    if value is None or value.strip() == "":
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed > 0 else None


def timeout_from_env(env: dict[str, str], name: str, default: int, *, aliases: tuple[str, ...] = ()) -> int:
    for key in (name, *aliases):
        parsed = parse_timeout(env.get(key))
        if parsed is not None:
            return parsed
    return default


def parse_time(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", UTC_OFFSET)).timestamp()
    except ValueError:
        return None


def fresh_full_matrix_rows(
    rows: list[dict[str, Any]],
    verified_run_id: str,
    started_ts: float | None,
    *,
    include_existing_run_rows: bool,
) -> list[dict[str, Any]]:
    fresh_rows: list[dict[str, Any]] = []
    for row in rows:
        if verified_run_id and row.get("verified_run_id") != verified_run_id:
            continue
        row_started = parse_time(str(row.get("started_at") or ""))
        if (
            not include_existing_run_rows
            and started_ts is not None
            and row_started is not None
            and row_started + 1 < started_ts
        ):
            continue
        fresh_rows.append(row)
    return fresh_rows


def full_matrix_runtime_state(
    record: dict[str, Any],
    env: dict[str, str],
    profile: str,
    *,
    include_existing_run_rows: bool = False,
) -> dict[str, Any]:
    manifest = Path(env.get("FULL_MATRIX_MANIFEST", ""))
    rows = read_jsonl(manifest)
    started_ts = parse_time(str(record.get("started_at") or ""))
    verified_run_id = str(env.get("VERIFIED_RUN_ID") or "")
    fresh_rows = fresh_full_matrix_rows(
        rows,
        verified_run_id,
        started_ts,
        include_existing_run_rows=include_existing_run_rows,
    )
    expected = 0 if profile == "smoke" else 12
    complete = expected > 0 and len(fresh_rows) >= expected
    return_codes = [row.get("return_code") for row in fresh_rows]
    mismatched = any(code not in {0, None} for code in return_codes)
    if complete and mismatched:
        runtime_status = "runtime_completed_with_mismatches"
    elif complete:
        runtime_status = "runtime_completed"
    elif record.get("classification") == "blocked_timeout":
        runtime_status = "runtime_timeout"
    elif record.get("return_code") == 0:
        runtime_status = "runtime_completed"
    else:
        runtime_status = "runtime_failed"
    return {
        "runtime_status": runtime_status,
        "runtime_complete": complete,
        "runtime_expected_jobs": expected,
        "runtime_completed_jobs": len(fresh_rows),
        "runtime_manifest_path": str(manifest),
        "runtime_job_return_codes": return_codes,
    }


def native_runtime_state(record: dict[str, Any], env: dict[str, str]) -> dict[str, Any]:
    native_root = Path(env.get("MRTS_NATIVE_ROOT", ""))
    targets = ("apache2_ubuntu", "nginx-pr24")
    jobs = []
    for target in targets:
        job_path = native_root / target / "job.json"
        if job_path.is_file():
            data = read_json(job_path)
            jobs.append({"target": target, "return_code": data.get("return_code"), "job_path": str(job_path)})
    complete = len(jobs) == len(targets)
    mismatched = any(job.get("return_code") not in {0, None} for job in jobs)
    if complete and mismatched:
        runtime_status = "runtime_completed_with_mismatches"
    elif complete:
        runtime_status = "runtime_completed"
    elif record.get("classification") == "blocked_timeout":
        runtime_status = "runtime_timeout"
    elif record.get("return_code") == 0:
        runtime_status = "runtime_completed"
    else:
        runtime_status = "runtime_failed"
    return {
        "runtime_status": runtime_status,
        "runtime_complete": complete,
        "runtime_expected_jobs": len(targets),
        "runtime_completed_jobs": len(jobs),
        "runtime_jobs": jobs,
    }


def simple_runtime_state(record: dict[str, Any]) -> dict[str, Any]:
    if record.get("classification") == "blocked_timeout":
        runtime_status = "runtime_timeout"
    elif record.get("return_code") == 0:
        runtime_status = "runtime_completed"
    elif record.get("return_code") in {1, 2}:
        runtime_status = "runtime_completed_with_mismatches"
    else:
        runtime_status = "runtime_failed"
    return {"runtime_status": runtime_status, "runtime_complete": runtime_status != "runtime_timeout"}


def float_record_value(record: dict[str, Any], name: str) -> float:
    try:
        return float(record.get(name) or 0)
    except (TypeError, ValueError):
        return 0


def timed_out_after_completed_artifacts(record: dict[str, Any]) -> bool:
    if record.get("classification") in {"blocked_timeout", "timeout_after_completion"}:
        return True
    if record.get("wrapper_status") == "timeout_after_completion":
        return True
    return (
        bool(record.get("signal"))
        and float_record_value(record, "timeout_seconds") > 0
        and float_record_value(record, "duration_seconds") >= float_record_value(record, "timeout_seconds")
    )


def completed_full_matrix_job_state(record: dict[str, Any], artifacts: dict[str, Any]) -> dict[str, Any]:
    job = artifacts.get("job", {}) if isinstance(artifacts.get("job"), dict) else {}
    status = str(job.get("status") or "completed")
    return_code = job.get("return_code", record.get("return_code"))
    wrapper_status = "timeout_after_completion" if timed_out_after_completed_artifacts(record) else "completed"
    return {
        "wrapper_status": wrapper_status,
        "runtime_status": status,
        "runtime_complete": True,
        "overall_job_status": status,
        "return_code": return_code,
        "job_artifact_path": artifacts.get("job_path"),
        "summary_path": artifacts.get("summary_path"),
        "results_jsonl": artifacts.get("results_jsonl"),
        "result_rows": artifacts.get("result_rows"),
        "summary_cases": artifacts.get("summary_cases"),
        "classification": "timeout_after_completion" if wrapper_status == "timeout_after_completion" else "completed",
        "status": "FAIL" if return_code not in {0, None} else "PASS",
        "notes": "wrapper timed out after completed job artifacts were written"
        if wrapper_status == "timeout_after_completion"
        else "job artifacts completed; job.json is source of truth",
    }


def incomplete_full_matrix_job_state(record: dict[str, Any]) -> dict[str, Any]:
    if record.get("classification") == "blocked_timeout" or record.get("return_code") == 77:
        runtime_status = "runtime_timeout"
    elif record.get("return_code") == 0:
        runtime_status = "completed"
    elif record.get("return_code") in {1, 2}:
        runtime_status = "completed_with_mismatches"
    else:
        runtime_status = "runtime_failed"
    return {
        "wrapper_status": "timeout" if runtime_status == "runtime_timeout" else "completed",
        "runtime_status": runtime_status,
        "runtime_complete": runtime_status != "runtime_timeout",
        "overall_job_status": runtime_status,
    }


def full_matrix_job_state(record: dict[str, Any], env: dict[str, str]) -> dict[str, Any]:
    artifacts = full_matrix_job_artifacts(env, str(record.get("logical_target") or ""))
    if artifacts.get("complete"):
        return completed_full_matrix_job_state(record, artifacts)
    return incomplete_full_matrix_job_state(record)


def refresh_state(record: dict[str, Any], env: dict[str, str]) -> dict[str, Any]:
    if record.get("classification") == "blocked_timeout":
        status = "refresh_timeout"
    elif record.get("return_code") == 0:
        status = "refresh_completed"
    else:
        log_text = ""
        log_root = env.get("VERIFIED_RUN_LOG_ROOT")
        if log_root:
            try:
                log_text = read_runtime_artifact_text(
                    Path(log_root), Path(str(record.get("log_path") or "")),
                    "report refresh log", errors="replace",
                )
            except (OSError, ValueError):
                pass
        if (
            "SKIPPED_STALE_INPUT" in log_text
            or "required generated input is stale" in log_text
            or "required generated input is blocked" in log_text
        ):
            status = "consumer_stale"
        else:
            status = "refresh_failed"
    overall = "blocked_refresh_timeout" if status == "refresh_timeout" else status
    return {"refresh_status": status, "overall_status": overall}


def apply_full_matrix_command_state(
    record: dict[str, Any],
    env: dict[str, str],
    profile: str,
    *,
    include_existing_run_rows: bool,
    preserve_persisted_runtime_state: bool,
) -> None:
    if preserve_persisted_runtime_state:
        # A later resume appends rows for the same run. Re-evaluating an
        # earlier parent command against those rows would incorrectly turn
        # a recorded incomplete attempt into a second completed producer.
        record.setdefault("runtime_complete", False)
        record.setdefault("runtime_status", "runtime_state_unavailable")
    else:
        record.update(
            full_matrix_runtime_state(
                record,
                env,
                profile,
                include_existing_run_rows=include_existing_run_rows,
            )
        )
    record["overall_status"] = record["runtime_status"]


def apply_command_semantics(
    record: dict[str, Any],
    env: dict[str, str],
    profile: str,
    *,
    preserve_persisted_runtime_state: bool = False,
) -> dict[str, Any]:
    target = str(record.get("logical_target") or "")
    if target in {"full-matrix-parallel", "full-matrix-resume"}:
        apply_full_matrix_command_state(
            record,
            env,
            profile,
            include_existing_run_rows=target == "full-matrix-resume",
            preserve_persisted_runtime_state=preserve_persisted_runtime_state,
        )
    elif target == "runtime-matrix-all":
        record.update(simple_runtime_state(record))
        record["overall_status"] = record["runtime_status"]
    elif target == "mrts-native-full-run":
        record.update(native_runtime_state(record, env))
        record["overall_status"] = record["runtime_status"]
    elif target.startswith(FULL_MATRIX_JOB_PREFIX):
        record.update(full_matrix_job_state(record, env))
        record["overall_status"] = record.get("overall_job_status") or record["runtime_status"]
    elif target in {"refresh-all-reports", "generate-system-environment-proof"}:
        record.update(refresh_state(record, env))
    elif target == "check-generated-report-layout":
        if record.get("return_code") == 0:
            record["overall_status"] = "checks_completed"
        else:
            record["overall_status"] = "layout_failed"
    return record


def normalize_existing_command_records(
    records: list[dict[str, Any]],
    env: dict[str, str],
    profile: str,
) -> list[dict[str, Any]]:
    """Preserve immutable parent semantics while an append phase adds records.

    Existing records describe what their Parent invocation observed at the time.
    They are history, not fresh evidence to be recalculated from artifacts that
    may have been produced by a later resume invocation.
    """

    return [
        apply_command_semantics(
            dict(record),
            env,
            profile,
            preserve_persisted_runtime_state=True,
        )
        for record in records
        if isinstance(record, dict)
    ]


def full_matrix_receipt_revisions(connector_root: Path, framework_root: Path) -> dict[str, str]:
    mrts_root = framework_root / "tools/MRTS"
    return {
        "connector_sha": git_sha(connector_root),
        "framework_sha": git_sha(framework_root),
        "mrts_sha": git_sha(mrts_root),
    }


def qualifies_for_full_matrix_receipt(record: dict[str, Any], profile: str) -> bool:
    return (
        profile == "full"
        and record.get("required") is True
        and record.get("logical_target") in {"full-matrix-parallel", "full-matrix-resume"}
        and record.get("runtime_complete") is True
        and record.get("runtime_status") in {"runtime_completed", "runtime_completed_with_mismatches"}
    )


def has_completed_full_matrix_producer(records: list[dict[str, Any]]) -> bool:
    return any(
        record.get("required") is True
        and record.get("logical_target") in {"full-matrix-parallel", "full-matrix-resume"}
        and record.get("runtime_complete") is True
        and record.get("runtime_status") in {"runtime_completed", "runtime_completed_with_mismatches"}
        for record in records
    )


def seal_full_matrix_receipt_for_record(
    *,
    record: dict[str, Any],
    connector_root: Path,
    framework_root: Path,
    build_root: Path,
    verified_run_id: str,
    profile: str,
) -> bool:
    """Seal the full-matrix child outputs only from the Parent runner path."""

    revisions = full_matrix_receipt_revisions(connector_root, framework_root)
    try:
        receipt_record = full_matrix_aggregate_receipt_record(
            build_root=build_root,
            verified_run_id=verified_run_id,
            missing_ok=True,
        )
        if receipt_record is not None:
            _, errors = validate_full_matrix_aggregate_receipt(
                build_root=build_root,
                verified_run_id=verified_run_id,
                expected_profile=profile,
                expected_revisions=revisions,
            )
            if errors:
                record["aggregate_receipt"] = {
                    "status": "invalid_existing_receipt",
                    "path": receipt_record["path"],
                    "errors": errors,
                }
                return False
            record["aggregate_receipt"] = {
                "status": "already_sealed",
                **receipt_record,
            }
            return True
        sealed_record = seal_full_matrix_aggregate_receipt_record(
            build_root=build_root,
            verified_run_id=verified_run_id,
            profile=profile,
            parent_command=record,
            revisions=revisions,
        )
        record["aggregate_receipt"] = sealed_record
        return True
    except AggregateReceiptError as exc:
        record["aggregate_receipt"] = {
            "status": "seal_failed",
            "error": str(exc),
        }
        return False


def command_plan(
    *,
    runtime_matrix_timeout: int,
    full_matrix_runtime_timeout: int,
    report_refresh_timeout: int,
    native_mrts_timeout: int,
    profile: str,
) -> list[dict[str, Any]]:
    producers: list[dict[str, Any]] = [
        {
            "phase": "runtime-producers",
            "command": ["git", "submodule", "update", "--init", "--recursive"],
            "logical_target": "git-submodule-update",
            "required": True,
            "optional": False,
            "affected_reports": ["framework_submodule", "mrts_submodule"],
            "timeout_seconds": 300,
        },
        {
            "phase": "runtime-producers",
            "command": ["make", "prepare-runtime-components"],
            "logical_target": "prepare-runtime-components",
            "required": True,
            "optional": False,
            "affected_reports": ["runtime_component_cache", "runtime_build_cache"],
            "timeout_seconds": 1800,
        },
        {
            "phase": "runtime-producers",
            "command": ["make", "check-runtime-producer-readiness"],
            "logical_target": "check-runtime-producer-readiness",
            "required": True,
            "optional": False,
            "affected_reports": ["runtime_component_cache", "runtime_build_cache", "system_environment_proof"],
            "timeout_seconds": 300,
        },
        {
            "phase": "runtime-producers",
            "command": ["make", "runtime-matrix-all-runtime"],
            "logical_target": "runtime-matrix-all",
            "required": True,
            "optional": False,
            "affected_reports": [
                "apache_runtime_results",
                "nginx_runtime_results",
                "haproxy_runtime_results",
                "runtime_matrix",
                "phase_coverage",
            ],
            "timeout_seconds": runtime_matrix_timeout,
        },
    ]
    if profile == "full":
        producers.extend(
            [
                {
                    "phase": "runtime-producers",
                    "command": ["make", "full-matrix-parallel-runtime"],
                    "logical_target": "full-matrix-parallel",
                    "required": True,
                    "optional": False,
                    "affected_reports": [
                        "full_runtime_matrix",
                        "connector_work_queue",
                        "phase_work_queue",
                        "remaining_failure_analysis",
                        "next_fix_plan",
                        "final_consistency_audit",
                        "full_run_evidence",
                    ],
                    "timeout_seconds": full_matrix_runtime_timeout,
                },
                {
                    "phase": "runtime-producers",
                    "command": ["make", "mrts-native-full-run-runtime"],
                    "logical_target": "mrts-native-full-run",
                    "required": False,
                    "optional": True,
                    "affected_reports": [
                        "mrts_native_full",
                        "mrts_native_apache",
                        "mrts_native_nginx",
                        "mrts_native_summary",
                    ],
                    "timeout_seconds": native_mrts_timeout,
                },
            ]
        )
    producers.append(
        {
            "phase": "runtime-producers",
            "command": ["make", "generate-verified-runtime-mismatch-analysis"],
            "logical_target": "generate-verified-runtime-mismatch-analysis",
            "required": False,
            "optional": True,
            "affected_reports": ["verified_runtime_mismatch_analysis"],
            "timeout_seconds": report_refresh_timeout,
        }
    )
    consumers = [
        {
            "phase": "report-refresh",
            "command": ["make", "refresh-all-reports"],
            "logical_target": "refresh-all-reports",
            "required": True,
            "optional": False,
            "affected_reports": ["report_refresh_manifest", "merge_readiness_dashboard", "report_freshness"],
            "timeout_seconds": report_refresh_timeout,
        },
        {
            "phase": "report-refresh",
            "command": ["make", "generate-system-environment-proof"],
            "logical_target": "generate-system-environment-proof",
            "required": True,
            "optional": False,
            "affected_reports": ["system_environment_proof"],
            "timeout_seconds": report_refresh_timeout,
        },
        {
            "phase": "report-refresh",
            "command": ["make", "refresh-all-reports"],
            "logical_target": "refresh-all-reports",
            "required": True,
            "optional": False,
            "affected_reports": ["report_refresh_manifest", "merge_readiness_dashboard", "report_freshness"],
            "timeout_seconds": report_refresh_timeout,
        },
    ]
    checks = [
        {
            "phase": "checks",
            "command": ["make", "verified-report-evidence-gate"],
            "logical_target": "verified-report-evidence-gate",
            "required": True,
            "optional": False,
            "affected_reports": ["all_generated_reports"],
            "timeout_seconds": 300,
        },
        {
            "phase": "checks",
            "command": ["make", "lint"],
            "logical_target": "lint",
            "required": True,
            "optional": False,
            "affected_reports": ["python_sources", "generated_report_layout"],
            "timeout_seconds": 900,
        },
        {
            "phase": "checks",
            "command": ["make", "quick-check"],
            "logical_target": "quick-check",
            "required": True,
            "optional": False,
            "affected_reports": ["python_sources", "generated_report_layout"],
            "timeout_seconds": 900,
        },
    ]
    return producers + consumers + checks


def select_commands(plan: list[dict[str, Any]], phase: str) -> list[dict[str, Any]]:
    aliases = {
        "producers": "runtime-producers",
        "consumers": "report-refresh",
    }
    phase = aliases.get(phase, phase)
    if phase == "all":
        return plan
    return [item for item in plan if item["phase"] == phase]


def system_proof_summary(connector_root: Path) -> dict[str, Any]:
    proof = read_json(report_path(connector_root, "system_environment_proof", "json"))
    return {
        "tools": proof.get("tools", []) if isinstance(proof.get("tools"), list) else [],
        "system": proof.get("os", {}) if isinstance(proof.get("os"), dict) else {},
        "runtime_component_readiness": proof.get("runtime_component_readiness", [])
        if isinstance(proof.get("runtime_component_readiness"), list)
        else [],
        "runtime_producer_readiness_check": proof.get("runtime_producer_readiness_check", {})
        if isinstance(proof.get("runtime_producer_readiness_check"), dict)
        else {},
        "https_repo_url_policy": proof.get("https_repo_url_policy", {})
        if isinstance(proof.get("https_repo_url_policy"), dict)
        else {},
    }


def duration_seconds(start: str, end: str) -> float | str:
    try:
        start_dt = datetime.fromisoformat(start.replace("Z", UTC_OFFSET))
        end_dt = datetime.fromisoformat(end.replace("Z", UTC_OFFSET))
    except ValueError:
        return "unknown"
    return round((end_dt - start_dt).total_seconds(), 3)


def markdown_cell(value: Any) -> str:
    return str(value if value is not None else "-").replace("|", "/").replace("\n", " ")


def markdown_summary_lines(payload: dict[str, Any]) -> list[str]:
    return [
        "# Verified Run Manifest",
        "",
        "## Summary",
        "",
        FIELD_VALUE_TABLE_HEADER,
        FIELD_VALUE_TABLE_DIVIDER,
        f"| Verified run id | `{markdown_cell(payload.get('verified_run_id', 'unknown'))}` |",
        f"| Data source policy | `{markdown_cell(payload.get('data_source_policy', DATA_SOURCE_POLICY))}` |",
        f"| Profile | `{markdown_cell(payload.get('profile', 'full'))}` |",
        f"| Start time UTC | `{markdown_cell(payload.get('started_at_utc', 'unknown'))}` |",
        f"| End time UTC | `{markdown_cell(payload.get('finished_at_utc', 'unknown'))}` |",
        f"| Duration seconds | `{markdown_cell(payload.get('duration_seconds', 'unknown'))}` |",
        f"| Input status | `{markdown_cell(payload.get('input_status', 'unknown'))}` |",
        "",
    ]


def markdown_runtime_environment_lines(payload: dict[str, Any]) -> list[str]:
    return [
        "## Runtime Environment",
        "",
        FIELD_VALUE_TABLE_HEADER,
        FIELD_VALUE_TABLE_DIVIDER,
        f"| Connector SHA | `{markdown_cell(payload.get('connector_sha', 'unknown'))}` |",
        f"| Framework SHA | `{markdown_cell(payload.get('framework_sha', 'unknown'))}` |",
        f"| MRTS SHA | `{markdown_cell(payload.get('mrts_sha', 'unknown'))}` |",
        f"| Connector branch | `{markdown_cell(payload.get('branches', {}).get('connector', 'unknown'))}` |",
        f"| Framework branch | `{markdown_cell(payload.get('branches', {}).get('framework', 'unknown'))}` |",
        f"| Dirty status | `{markdown_cell(payload.get('dirty_status', {}).get('connector', 'unknown'))}` / `{markdown_cell(payload.get('dirty_status', {}).get('framework', 'unknown'))}` |",
        f"| Runtime matrix timeout seconds | `{markdown_cell(payload.get('timeout_budgets', {}).get('runtime_matrix', 'none'))}` |",
        f"| Full matrix runtime timeout seconds | `{markdown_cell(payload.get('timeout_budgets', {}).get('full_matrix_runtime', 'none'))}` |",
        f"| Report refresh timeout seconds | `{markdown_cell(payload.get('timeout_budgets', {}).get('report_refresh', 'none'))}` |",
        f"| Native MRTS timeout seconds | `{markdown_cell(payload.get('timeout_budgets', {}).get('native_mrts', 'none'))}` |",
        "",
    ]


def markdown_runtime_path_lines(payload: dict[str, Any]) -> list[str]:
    lines = [
        "## Runtime Paths",
        "",
        "| Variable | Value | Status | Notes |",
        FOUR_COLUMN_TABLE_DIVIDER,
    ]
    for item in payload.get("runtime_path_rows", []):
        lines.append(
            f"| `{markdown_cell(item.get('variable'))}` | `{markdown_cell(item.get('value'))}` | {markdown_cell(item.get('status'))} | {markdown_cell(item.get('notes'))} |"
        )
    if not payload.get("runtime_path_rows"):
        lines.append("| `-` | `-` | UNKNOWN | no runtime path rows recorded |")
    return lines


def markdown_worker_preflight_lines(payload: dict[str, Any]) -> list[str]:
    lines = [
        "",
        "## Worker Accessibility / Preflight",
        "",
        "| Check | Status | Path | Notes |",
        "|---|---|---|---|",
    ]
    for item in payload.get("worker_preflight", []):
        lines.append(
            f"| {markdown_cell(item.get('check'))} | {markdown_cell(item.get('status'))} | `{markdown_cell(item.get('path'))}` | {markdown_cell(item.get('notes'))} |"
        )
    if not payload.get("worker_preflight"):
        lines.append("| NGINX worker preflight | UNKNOWN | `-` | no preflight evidence recorded |")
    return lines

def runtime_producer_readiness(payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    producer_check = payload.get("runtime_producer_readiness_check", {})
    if not isinstance(producer_check, dict):
        return {}, {}
    nginx_readiness = producer_check.get("nginx_runtime_module_readiness", {})
    return producer_check, nginx_readiness if isinstance(nginx_readiness, dict) else {}


def markdown_producer_readiness_lines(producer_check: dict[str, Any]) -> list[str]:
    lines = [
        "",
        "## Runtime Producer Readiness",
        "",
        f"- Status: `{producer_check.get('status', 'unknown')}`",
        f"- Runtime env loaded: `{producer_check.get('runtime_env_loaded', False)}`",
        f"- Runtime env path: `{producer_check.get('runtime_env_path', '-')}`",
        "",
        "| Component | Required | Status | Path | Fix |",
        "|---|---|---|---|---|",
    ]
    components = producer_check.get("components", [])
    for item in components:
        if isinstance(item, dict):
            lines.append(
                f"| {markdown_cell(item.get('component', '-'))} | {markdown_cell(item.get('required', '-'))} | {markdown_cell(item.get('status', 'unknown'))} | "
                f"`{markdown_cell(item.get('path', '-'))}` | `{markdown_cell(item.get('fix', '-'))}` |"
            )
    if not components:
        lines.append("| - | - | unknown | `-` | `make check-runtime-producer-readiness` |")
    return lines


def markdown_nginx_module_readiness_lines(nginx_readiness: dict[str, Any]) -> list[str]:
    return [
        "",
        "## NGINX Runtime Module Readiness",
        "",
        FIELD_VALUE_TABLE_HEADER,
        FIELD_VALUE_TABLE_DIVIDER,
        f"| NGINX_BIN | `{markdown_cell(nginx_readiness.get('NGINX_BIN', ''))}` |",
        f"| NGINX_MODULE_DIR | `{markdown_cell(nginx_readiness.get('NGINX_MODULE_DIR', ''))}` |",
        f"| ModSecurity module path | `{markdown_cell(nginx_readiness.get('ModSecurity module path', ''))}` |",
        f"| Module exists | `{markdown_cell(str(nginx_readiness.get('Module exists', False)).lower())}` |",
        f"| How to prepare | `{markdown_cell(nginx_readiness.get('How to prepare', 'make prepare-runtime-components'))}` |",
    ]


def markdown_network_cache_lines(producer_check: dict[str, Any]) -> list[str]:
    lines = [
        "",
        "## Runtime Network / Cache Readiness",
        "",
        "| Source | Status | Path | Notes |",
        FOUR_COLUMN_TABLE_DIVIDER,
    ]
    network_cache = producer_check.get("network_cache", [])
    for item in network_cache:
        if isinstance(item, dict):
            lines.append(
                f"| {markdown_cell(item.get('source', '-'))} | {markdown_cell(item.get('status', 'unknown'))} | `{markdown_cell(item.get('path', '-'))}` | {markdown_cell(item.get('notes', '-'))} |"
            )
    if not network_cache:
        lines.append("| - | unknown | `-` | No runtime producer cache rows recorded. |")
    return lines

def markdown_command_table(
    payload: dict[str, Any],
    title: str,
    targets: set[str],
    *,
    include_full_matrix_jobs: bool = False,
) -> list[str]:
    lines = [
        "",
        title,
        "",
        "| Command | Status | RC | Duration | Runtime Status | Refresh Status | Log |",
        "|---|---:|---:|---:|---|---|---|",
    ]
    rows = [
        command
        for command in payload.get("commands", [])
        if str(command.get("logical_target", "")) in targets
        or (
            include_full_matrix_jobs
            and str(command.get("logical_target", "")).startswith(FULL_MATRIX_JOB_PREFIX)
        )
    ]
    for command in rows:
        command_text = " ".join(command.get("command", []))
        lines.append(
            f"| `{markdown_cell(command_text)}` | {markdown_cell(command.get('status', 'unknown'))} | {markdown_cell(command.get('return_code', '-'))} | "
            f"{markdown_cell(command.get('duration_seconds', '-'))} | {markdown_cell(command.get('runtime_status', '-'))} | "
            f"{markdown_cell(command.get('refresh_status', '-'))} | `{markdown_cell(command.get('log_path', '-'))}` |"
        )
    if not rows:
        lines.append("| `-` | not_run | - | - | - | - | `-` |")
    return lines


def markdown_command_lines(payload: dict[str, Any]) -> list[str]:
    producer_targets = {
        "git-submodule-update",
        "prepare-runtime-components",
        "check-runtime-producer-readiness",
        "runtime-matrix-all",
        "full-matrix-parallel",
        "mrts-native-full-run",
        "generate-verified-runtime-mismatch-analysis",
    }
    consumer_targets = {"refresh-all-reports", "generate-system-environment-proof"}
    check_targets = {"verified-report-evidence-gate", "lint", "quick-check"}
    lines = markdown_command_table(
        payload,
        "## Producer Commands",
        producer_targets,
        include_full_matrix_jobs=True,
    )
    lines.extend(markdown_command_table(payload, "## Consumer / Refresh Commands", consumer_targets))
    lines.extend(markdown_command_table(payload, "## Checks", check_targets))
    return lines


def markdown_full_matrix_completeness_lines(payload: dict[str, Any]) -> list[str]:
    completeness = payload.get("full_matrix_job_completeness", {})
    lines = ["", "## Full-Matrix Job Completeness", "", FIELD_VALUE_TABLE_HEADER, FIELD_VALUE_TABLE_DIVIDER]
    lines.extend([
        f"| Completeness | `{markdown_cell(completeness.get('complete_jobs', 0))}/{markdown_cell(completeness.get('total_jobs', 0))}` |",
        f"| Overall status | `{markdown_cell(completeness.get('status', 'unknown'))}` |",
        f"| Missing jobs | `{markdown_cell(', '.join(completeness.get('missing_jobs', [])) or '-')}` |",
        f"| Timeout jobs | `{markdown_cell(', '.join(completeness.get('timeout_jobs', [])) or '-')}` |",
    ])
    lines.extend(["", "| Slowest Job | Duration Seconds | Status |", "|---|---:|---|"])
    for job in completeness.get("slowest_jobs", []):
        lines.append(
            f"| `{markdown_cell(job.get('job_id'))}` | {markdown_cell(job.get('duration_seconds'))} | {markdown_cell(job.get('status'))} |"
        )
    if not completeness.get("slowest_jobs"):
        lines.append("| `-` | - | unknown |")
    return lines


def markdown_runtime_mismatch_lines(payload: dict[str, Any]) -> list[str]:
    mismatch = payload.get("runtime_mismatch_summary", {})
    return [
        "",
        "## Runtime Mismatch Summary",
        "",
        FIELD_VALUE_TABLE_HEADER,
        FIELD_VALUE_TABLE_DIVIDER,
        f"| Total mismatches | `{markdown_cell(mismatch.get('total_mismatches', 'unknown'))}` |",
        f"| Critical mismatches | `{markdown_cell(mismatch.get('critical_mismatches', 'unknown'))}` |",
        f"| Top connector | `{markdown_cell(mismatch.get('top_connector', 'unknown'))}` |",
        f"| Primary blocker | `{markdown_cell(mismatch.get('primary_blocker', 'unknown'))}` |",
        f"| Merge readiness | `{markdown_cell(mismatch.get('merge_readiness', 'unknown'))}` |",
    ]

def blocked_or_stale_input_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in ("missing_inputs", "skipped_reports", "blocked_reports", "failed_reports", "stale_inputs"):
        rows.extend(payload.get(key, []))
    return rows


def markdown_blocked_or_stale_input_lines(payload: dict[str, Any]) -> list[str]:
    lines = ["", "## Blocked / Stale Inputs", "", "| Item | Status | Reason | Affected Reports |", FOUR_COLUMN_TABLE_DIVIDER]
    rows = blocked_or_stale_input_rows(payload)
    for item in rows:
        affected = ", ".join(str(value) for value in item.get("outputs", [])) or "-"
        lines.append(
            f"| `{markdown_cell(item.get('report_name', item.get('path', 'unknown')))}` | {markdown_cell(item.get('status', 'unknown'))} | "
            f"{markdown_cell(item.get('reason', item.get('notes', 'unknown')))} | {markdown_cell(affected)} |"
        )
    if not rows:
        lines.append("| `-` | zero_result_verified | No missing, skipped, blocked, stale, or failed reports were recorded. | - |")
    return lines


def markdown_tool_version_lines(payload: dict[str, Any]) -> list[str]:
    lines = ["", "## Tool Versions", "", "| Tool | Status | Version / Output |", "|---|---|---|"]
    for tool in payload.get("tool_versions", []):
        version = str(tool.get("version") or tool.get("version_output") or "-").splitlines()[0]
        lines.append(
            f"| {markdown_cell(tool.get('tool', '-'))} | {markdown_cell(tool.get('status', 'unknown'))} | `{markdown_cell(version)}` |"
        )
    if not payload.get("tool_versions"):
        lines.append("| `-` | unknown | `system-environment-proof unavailable` |")
    return lines

def markdown_git_evidence_lines(payload: dict[str, Any]) -> list[str]:
    return [
        "",
        "## Git Evidence",
        "",
        "| Repository | SHA | Branch | Dirty Status |",
        FOUR_COLUMN_TABLE_DIVIDER,
        f"| connector | `{markdown_cell(payload.get('connector_sha', 'unknown'))}` | `{markdown_cell(payload.get('branches', {}).get('connector', 'unknown'))}` | `{markdown_cell(payload.get('dirty_status', {}).get('connector', 'unknown'))}` |",
        f"| framework | `{markdown_cell(payload.get('framework_sha', 'unknown'))}` | `{markdown_cell(payload.get('branches', {}).get('framework', 'unknown'))}` | `{markdown_cell(payload.get('dirty_status', {}).get('framework', 'unknown'))}` |",
        f"| MRTS | `{markdown_cell(payload.get('mrts_sha', 'unknown'))}` | `{markdown_cell(payload.get('branches', {}).get('mrts', 'unknown'))}` | `{markdown_cell(payload.get('dirty_status', {}).get('mrts', 'unknown'))}` |",
        "",
        "## Proof Summary",
        "",
        "| Claim | Status | Evidence |",
        "|---|---|---|",
        f"| Runtime paths outside /root by default | `{markdown_cell('PASS' if not is_under_root_home(Path(payload.get('runtime_paths', {}).get('VERIFIED_RUN_ROOT', '/root'))) else 'FAIL')}` | `VERIFIED_RUN_ROOT={markdown_cell(payload.get('runtime_paths', {}).get('VERIFIED_RUN_ROOT', 'unknown'))}` |",
        f"| NGINX docroot preflight evidence | `{markdown_cell('PASS' if payload.get('worker_preflight') else 'UNKNOWN')}` | `nginx-worker-preflight.jsonl` rows are included when NGINX smoke ran |",
        f"| Verified inputs only | `PASS` | `{DATA_SOURCE_POLICY}` |",
    ]


def render_markdown(payload: dict[str, Any]) -> str:
    producer_check, nginx_readiness = runtime_producer_readiness(payload)
    sections = (
        markdown_summary_lines(payload),
        markdown_runtime_environment_lines(payload),
        markdown_runtime_path_lines(payload),
        markdown_worker_preflight_lines(payload),
        markdown_producer_readiness_lines(producer_check),
        markdown_nginx_module_readiness_lines(nginx_readiness),
        markdown_network_cache_lines(producer_check),
        markdown_command_lines(payload),
        markdown_full_matrix_completeness_lines(payload),
        markdown_runtime_mismatch_lines(payload),
        markdown_blocked_or_stale_input_lines(payload),
        markdown_tool_version_lines(payload),
        markdown_git_evidence_lines(payload),
    )
    lines: list[str] = []
    for section in sections:
        lines.extend(section)
    return "\n".join(lines) + "\n"


def write_verified_manifest(
    *,
    connector_root: Path,
    framework_root: Path,
    build_root: Path,
    verified_run_id: str,
    started_at: str,
    finished_at: str,
    commands: list[dict[str, Any]],
    commands_file: Path,
    env: dict[str, str],
    profile: str,
    full_matrix_timeout: int | None,
    timeout_budgets: dict[str, int],
) -> None:
    mrts_root = framework_root / "tools/MRTS"
    aggregate_receipt = aggregate_receipt_manifest_record(
        commands=commands,
        build_root=build_root,
        verified_run_id=verified_run_id,
    )
    proof = system_proof_summary(connector_root)
    reports = manifest_report_records(connector_root)
    runtime_path_records = runtime_path_report_rows(runtime_paths(env, build_root, verified_run_id), connector_root, framework_root)
    input_files = collect_declared_inputs(connector_root)
    payload = {
        "verified_run_id": verified_run_id,
        "data_source_policy": DATA_SOURCE_POLICY,
        "profile": profile,
        "full_matrix_timeout_seconds": full_matrix_timeout,
        "timeout_budgets": timeout_budgets,
        "runtime_paths": runtime_paths(env, build_root, verified_run_id),
        "runtime_path_rows": runtime_path_records,
        "worker_preflight": worker_preflight_rows(runtime_paths(env, build_root, verified_run_id), build_root),
        "started_at_utc": started_at,
        "finished_at_utc": finished_at,
        "duration_seconds": duration_seconds(started_at, finished_at),
        "connector_sha": git_sha(connector_root),
        "framework_sha": git_sha(framework_root),
        "mrts_sha": git_sha(mrts_root),
        "branches": {
            "connector": git_branch(connector_root),
            "framework": git_branch(framework_root),
            "mrts": git_branch(mrts_root) if mrts_root.exists() else "missing",
        },
        "dirty_status": {
            "connector": git_dirty_status(connector_root),
            "framework": git_dirty_status(framework_root),
            "mrts": git_dirty_status(mrts_root) if mrts_root.exists() else "missing",
        },
        "commands": commands,
        "command_file": file_record(commands_file, connector_root),
        "full_matrix_aggregate_receipt": aggregate_receipt,
        "input_files": input_files,
        "output_files": generated_output_records(connector_root),
        "missing_inputs": [
            {"path": item.get("path"), "status": item.get("status"), "reason": item.get("notes", "input missing")}
            for item in input_files
            if item.get("status") in {"missing", "empty", "unknown", "stale"}
        ],
        "stale_inputs": [
            {"path": item.get("path"), "status": item.get("status"), "reason": item.get("notes", "input stale")}
            for item in input_files
            if item.get("status") == "stale"
        ],
        "skipped_reports": collect_report_statuses(connector_root, status_prefix="skipped"),
        "blocked_reports": collect_report_statuses(connector_root, status_prefix="blocked"),
        "failed_reports": collect_report_statuses(connector_root, status_values={"failed"}),
        "full_matrix_job_completeness": full_matrix_completeness_summary(connector_root),
        "runtime_mismatch_summary": runtime_mismatch_summary(connector_root),
        "tool_versions": proof["tools"],
        "system": proof["system"],
        "runtime_component_readiness": proof["runtime_component_readiness"],
        "runtime_producer_readiness_check": proof["runtime_producer_readiness_check"],
        "https_repo_url_policy": proof["https_repo_url_policy"],
        "report_refresh_manifest_reports": reports,
    }
    metadata = build_metadata(
        generated_by=GENERATED_REPORTS["verified_run_manifest"].generator,
        make_target=GENERATED_REPORTS["verified_run_manifest"].make_target,
        connector_root=connector_root,
        framework_root=framework_root,
        inputs=[
            commands_file,
            report_path(connector_root, "report_refresh_manifest", "json"),
            report_path(connector_root, "system_environment_proof", "json"),
            report_path(connector_root, "merge_readiness_dashboard", "json"),
        ],
        generated_at=finished_at,
        report_key="verified_run_manifest",
        extra={"mrts_sha": git_sha(mrts_root)},
    )
    metadata["input_status"] = manifest_input_status(payload, metadata.get("input_status", "unknown"))
    payload["input_status"] = metadata.get("input_status", "unknown")
    json_path = report_path(connector_root, "verified_run_manifest", "json")
    md_path = report_path(connector_root, "verified_run_manifest", "md")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(generated_json_text(payload, metadata), encoding="utf-8")
    md_path.write_text(generated_markdown_text(render_markdown(payload), metadata), encoding="utf-8")


class VerifiedRunContext:
    def __init__(
        self,
        *,
        connector_root: Path,
        framework_root: Path,
        build_root: Path,
        verified_run_id: str,
        started_at: str,
        run_root: Path,
        logs_dir: Path,
        commands_file: Path,
        env: dict[str, str],
        timeout_budgets: dict[str, int],
    ) -> None:
        self.connector_root = connector_root
        self.framework_root = framework_root
        self.build_root = build_root
        self.verified_run_id = verified_run_id
        self.started_at = started_at
        self.run_root = run_root
        self.logs_dir = logs_dir
        self.commands_file = commands_file
        self.env = env
        self.timeout_budgets = timeout_budgets


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector-root", default=".")
    parser.add_argument("--framework-root", default=None)
    parser.add_argument("--build-root", default=os.environ.get("BUILD_ROOT"))
    parser.add_argument(
        "--phase",
        choices=(
            "all",
            "runtime-producers",
            "report-refresh",
            "checks",
            "full-matrix-job",
            "full-matrix-resume",
            "producers",
            "consumers",
        ),
        default="all",
    )
    parser.add_argument("--connector", choices=("apache", "nginx", "haproxy"), default=None)
    parser.add_argument("--crs", choices=("no-crs", "with-crs"), default=None)
    parser.add_argument("--mrts", choices=("no-mrts", "with-mrts"), default=None)
    parser.add_argument("--mode", choices=("strict", "soft"), default="strict")
    parser.add_argument("--profile", choices=("full", "smoke"), default="full")
    parser.add_argument("--soft", action="store_true")
    parser.add_argument(
        "--manifest-only",
        action="store_true",
        help="rewrite verified-run manifest from existing verified command records without running commands",
    )
    return parser


def canonical_roots_from_arguments(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
) -> tuple[Path, Path]:
    try:
        return canonical_roots(args.connector_root, args.framework_root)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    raise AssertionError(ARGPARSE_ERROR_TERMINATION_ASSERTION)


def initial_verified_run_id(parser: argparse.ArgumentParser) -> str:
    initial_run_id = os.environ.get("VERIFIED_RUN_ID", "") or "pending"
    try:
        return validate_verified_run_id(initial_run_id)
    except VerifiedRunIdError as exc:
        parser.error(str(exc))
    raise AssertionError(ARGPARSE_ERROR_TERMINATION_ASSERTION)


def restore_current_verified_run_id(args: argparse.Namespace, current_run_file: Path) -> None:
    append_phases = {
        "report-refresh",
        "consumers",
        "checks",
        "full-matrix-job",
        "full-matrix-resume",
    }
    if os.environ.get("VERIFIED_RUN_ID") or args.phase not in append_phases:
        return
    # Validate directory ownership before accessing even the marker's metadata.
    # Keep a no-follow parent descriptor and nonblocking leaf open so a swapped
    # FIFO cannot block between path validation and the descriptor checks.
    try:
        target = runtime_artifact_path(
            current_run_file.parent, current_run_file, CURRENT_RUN_MARKER_LABEL
        )
        no_follow = getattr(os, "O_NOFOLLOW", None)
        nonblocking = getattr(os, "O_NONBLOCK", None)
        if no_follow is None or nonblocking is None:
            raise ValueError("safe marker reads require no-follow and nonblocking opens")
        parent_descriptor = open_runtime_artifact_parent(target)
        descriptor = -1
        try:
            descriptor = os.open(
                target.name, os.O_RDONLY | no_follow | nonblocking,
                dir_fd=parent_descriptor,
            )
            require_regular_runtime_artifact(descriptor, CURRENT_RUN_MARKER_LABEL)
            details = os.fstat(descriptor)
            if details.st_uid != os.geteuid() or details.st_mode & 0o022 or details.st_nlink != 1:
                raise ValueError("current-run marker has unsafe ownership, permissions or links")
            # A canonical ID is at most 128 characters; allow bounded legacy
            # whitespace without allocating the size of a substituted file.
            chunks = []
            size = 0
            while size <= 4096:
                chunk = os.read(descriptor, 4097 - size)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            if size > 4096:
                raise ValueError("current-run marker is oversized")
            previous_run_id = b"".join(chunks).decode("utf-8").strip()
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(parent_descriptor)
    except FileNotFoundError:
        return
    except (OSError, ValueError):
        raise ValueError("current-run marker is unavailable or unsafe") from None
    if previous_run_id:
        os.environ["VERIFIED_RUN_ID"] = validate_verified_run_id(previous_run_id)


def current_verified_run_id_or_error(
    parser: argparse.ArgumentParser,
    connector_root: Path,
) -> str:
    os.environ.setdefault("VERIFIED_RUN_ID", current_verified_run_id(connector_root))
    try:
        return validate_verified_run_id(os.environ["VERIFIED_RUN_ID"])
    except VerifiedRunIdError as exc:
        parser.error(str(exc))
    raise AssertionError(ARGPARSE_ERROR_TERMINATION_ASSERTION)


def verified_run_timeout_budgets(env: dict[str, str]) -> dict[str, int]:
    runtime_matrix_timeout = timeout_from_env(env, "VERIFIED_RUN_RUNTIME_MATRIX_TIMEOUT_SECONDS", 1800)
    full_matrix_runtime_timeout = timeout_from_env(
        env,
        "VERIFIED_RUN_FULL_MATRIX_RUNTIME_TIMEOUT_SECONDS",
        7200,
        aliases=("VERIFIED_RUN_FULL_MATRIX_TIMEOUT_SECONDS",),
    )
    return {
        "runtime_matrix": runtime_matrix_timeout,
        "full_matrix_runtime": full_matrix_runtime_timeout,
        "report_refresh": timeout_from_env(env, "VERIFIED_RUN_REPORT_REFRESH_TIMEOUT_SECONDS", 1800),
        "native_mrts": timeout_from_env(env, "VERIFIED_RUN_NATIVE_MRTS_TIMEOUT_SECONDS", 1800),
        "full_matrix_job": timeout_from_env(env, "VERIFIED_RUN_FULL_MATRIX_JOB_TIMEOUT_SECONDS", 3600),
        "full_matrix_total": timeout_from_env(env, "VERIFIED_RUN_FULL_MATRIX_TOTAL_TIMEOUT_SECONDS", 14400),
        "job_finalize_grace": timeout_from_env(env, "VERIFIED_RUN_JOB_FINALIZE_GRACE_SECONDS", 60),
    }


def configure_verified_run_environment(
    env: dict[str, str],
    *,
    connector_root: Path,
    framework_root: Path,
    build_root: Path,
    paths: dict[str, str],
    verified_run_id: str,
    started_at: str,
    logs_dir: Path,
    commands_file: Path,
    profile: str,
    timeout_budgets: dict[str, int],
) -> None:
    full_matrix_runtime_timeout = timeout_budgets["full_matrix_runtime"]
    env.update(
        {
            "CONNECTOR_ROOT": str(connector_root),
            "FRAMEWORK_ROOT": str(framework_root),
            "VERIFIED_RUN_ROOT": paths["VERIFIED_RUN_ROOT"],
            "VERIFIED_STATE_ROOT": paths["VERIFIED_STATE_ROOT"],
            "VERIFIED_BUILD_ROOT": paths["VERIFIED_BUILD_ROOT"],
            "VERIFIED_SOURCE_ROOT": paths["VERIFIED_SOURCE_ROOT"],
            "VERIFIED_TMP_ROOT": paths["VERIFIED_TMP_ROOT"],
            "VERIFIED_LOG_ROOT": paths["VERIFIED_LOG_ROOT"],
            "VERIFIED_COMPONENT_CACHE": paths["VERIFIED_COMPONENT_CACHE"],
            "BUILD_ROOT": str(build_root),
            "SOURCE_ROOT": paths["SOURCE_ROOT"],
            "TMP_ROOT": paths["TMP_ROOT"],
            "LOG_ROOT": paths["LOG_ROOT"],
            "CONNECTOR_COMPONENT_CACHE": paths["CONNECTOR_COMPONENT_CACHE"],
            "NGINX_HARNESS_PARENT": paths["NGINX_HARNESS_PARENT"],
            "MATRIX_ROOT": paths["MATRIX_ROOT"],
            "FULL_MATRIX_MANIFEST": str(Path(paths["MATRIX_ROOT"]) / "full-runtime-matrix-runs.jsonl"),
            "MRTS_BUILD_ROOT": paths["MRTS_BUILD_ROOT"],
            "MRTS_NATIVE_ROOT": paths["MRTS_NATIVE_ROOT"],
            "VERIFIED_RUN_ID": verified_run_id,
            "VERIFIED_RUN_STARTED_AT": started_at,
            "VERIFIED_RUN_LOG_ROOT": str(logs_dir),
            "VERIFIED_RUN_COMMANDS_FILE": str(commands_file),
            "VERIFIED_RUN_PROFILE": profile,
            "VERIFIED_RUN_RUNTIME_MATRIX_TIMEOUT_SECONDS": str(timeout_budgets["runtime_matrix"]),
            "VERIFIED_RUN_FULL_MATRIX_RUNTIME_TIMEOUT_SECONDS": str(full_matrix_runtime_timeout),
            "VERIFIED_RUN_FULL_MATRIX_TIMEOUT_SECONDS": str(full_matrix_runtime_timeout),
            "VERIFIED_RUN_REPORT_REFRESH_TIMEOUT_SECONDS": str(timeout_budgets["report_refresh"]),
            "VERIFIED_RUN_NATIVE_MRTS_TIMEOUT_SECONDS": str(timeout_budgets["native_mrts"]),
            "VERIFIED_RUN_FULL_MATRIX_JOB_TIMEOUT_SECONDS": str(timeout_budgets["full_matrix_job"]),
            "VERIFIED_RUN_FULL_MATRIX_TOTAL_TIMEOUT_SECONDS": str(timeout_budgets["full_matrix_total"]),
            "VERIFIED_RUN_JOB_FINALIZE_GRACE_SECONDS": str(timeout_budgets["job_finalize_grace"]),
            "PYTHONDONTWRITEBYTECODE": env.get("PYTHONDONTWRITEBYTECODE", "1"),
        }
    )


def prepare_verified_run_context(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
) -> VerifiedRunContext:
    connector_root, framework_root = canonical_roots_from_arguments(parser, args)
    initial_paths = verified_runtime_paths(os.environ)
    build_root = Path(os.path.abspath(args.build_root or initial_paths["BUILD_ROOT"]))
    pending_run_id = initial_verified_run_id(parser)
    initial_runtime_paths = runtime_paths(dict(os.environ), build_root, pending_run_id)
    current_run_file = Path(initial_runtime_paths["VERIFIED_RUNS_ROOT"]) / "current-run-id"
    restore_current_verified_run_id(args, current_run_file)
    verified_run_id = current_verified_run_id_or_error(parser, connector_root)
    os.environ["VERIFIED_RUN_ID"] = verified_run_id
    started_at = utc_now()
    paths = runtime_paths(dict(os.environ), build_root, verified_run_id)
    prepare_runtime_roots(paths)
    run_root = Path(paths["VERIFIED_RUN_INSTANCE_ROOT"])
    logs_dir = Path(paths["VERIFIED_RUN_INSTANCE_LOG_ROOT"])
    write_runtime_artifact_text_atomic(
        Path(paths["VERIFIED_RUNS_ROOT"]), current_run_file,
        verified_run_id + "\n", CURRENT_RUN_MARKER_LABEL,
    )
    commands_file = run_root / "verified-commands.json"
    env = dict(os.environ)
    timeout_budgets = verified_run_timeout_budgets(env)
    configure_verified_run_environment(
        env,
        connector_root=connector_root,
        framework_root=framework_root,
        build_root=build_root,
        paths=paths,
        verified_run_id=verified_run_id,
        started_at=started_at,
        logs_dir=logs_dir,
        commands_file=commands_file,
        profile=args.profile,
        timeout_budgets=timeout_budgets,
    )
    return VerifiedRunContext(
        connector_root=connector_root,
        framework_root=framework_root,
        build_root=build_root,
        verified_run_id=verified_run_id,
        started_at=started_at,
        run_root=run_root,
        logs_dir=logs_dir,
        commands_file=commands_file,
        env=env,
        timeout_budgets=timeout_budgets,
    )


def full_matrix_job_command_plan(
    args: argparse.Namespace,
    timeout_budgets: dict[str, int],
) -> list[dict[str, Any]]:
    return [
        {
            "phase": "full-matrix-job",
            "command": [
                "make",
                "full-matrix-single-job-runtime",
                f"CONNECTOR={args.connector}",
                f"CRS={args.crs}",
                f"MRTS={args.mrts}",
            ],
            "logical_target": f"{FULL_MATRIX_JOB_PREFIX}{args.connector}:{args.crs}:{args.mrts}",
            "required": True,
            "optional": False,
            "affected_reports": ["full_matrix_job_completeness", "verified_runtime_mismatch_analysis"],
            "timeout_seconds": timeout_budgets["full_matrix_job"],
        },
        {
            "phase": "full-matrix-job",
            "command": ["make", "generate-full-matrix-job-completeness"],
            "logical_target": "generate-full-matrix-job-completeness",
            "required": False,
            "optional": True,
            "affected_reports": ["full_matrix_job_completeness"],
            "timeout_seconds": timeout_budgets["report_refresh"],
        },
    ]


def full_matrix_resume_command_plan(timeout_budgets: dict[str, int]) -> list[dict[str, Any]]:
    return [
        {
            "phase": "full-matrix-resume",
            "command": ["make", "full-matrix-resume-runtime"],
            "logical_target": "full-matrix-resume",
            "required": True,
            "optional": False,
            "affected_reports": ["full_matrix_job_completeness", "verified_runtime_mismatch_analysis"],
            "timeout_seconds": timeout_budgets["full_matrix_total"],
        },
        {
            "phase": "full-matrix-resume",
            "command": ["make", "generate-full-matrix-job-completeness"],
            "logical_target": "generate-full-matrix-job-completeness",
            "required": False,
            "optional": True,
            "affected_reports": ["full_matrix_job_completeness"],
            "timeout_seconds": timeout_budgets["report_refresh"],
        },
        {
            "phase": "full-matrix-resume",
            "command": ["make", "generate-verified-runtime-mismatch-analysis"],
            "logical_target": "generate-verified-runtime-mismatch-analysis",
            "required": False,
            "optional": True,
            "affected_reports": ["verified_runtime_mismatch_analysis"],
            "timeout_seconds": timeout_budgets["report_refresh"],
        },
    ]


def selected_command_plan(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    timeout_budgets: dict[str, int],
) -> list[dict[str, Any]]:
    if args.phase == "full-matrix-job":
        if not args.connector or not args.crs or not args.mrts:
            parser.error("--phase full-matrix-job requires --connector, --crs, and --mrts")
        return full_matrix_job_command_plan(args, timeout_budgets)
    if args.phase == "full-matrix-resume":
        return full_matrix_resume_command_plan(timeout_budgets)
    return select_commands(
        command_plan(
            runtime_matrix_timeout=timeout_budgets["runtime_matrix"],
            full_matrix_runtime_timeout=timeout_budgets["full_matrix_runtime"],
            report_refresh_timeout=timeout_budgets["report_refresh"],
            native_mrts_timeout=timeout_budgets["native_mrts"],
            profile=args.profile,
        ),
        args.phase,
    )


def existing_command_state(
    context: VerifiedRunContext,
    args: argparse.Namespace,
) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    existing_payload = read_json(context.commands_file)
    existing_commands = (
        existing_payload.get("commands")
        if isinstance(existing_payload.get("commands"), list)
        else []
    )
    append_phases = {
        "report-refresh",
        "consumers",
        "checks",
        "full-matrix-job",
        "full-matrix-resume",
    }
    command_records = (
        normalize_existing_command_records(existing_commands, context.env, args.profile)
        if args.manifest_only or args.phase in append_phases
        else []
    )
    run_started_at = (
        str(existing_payload.get("started_at_utc") or context.started_at)
        if command_records
        else context.started_at
    )
    return existing_payload, command_records, run_started_at


def command_records_payload(
    args: argparse.Namespace,
    context: VerifiedRunContext,
    command_records: list[dict[str, Any]],
    run_started_at: str,
    *,
    timestamp_name: str | None = None,
    timestamp_value: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "verified_run_id": context.verified_run_id,
        "data_source_policy": DATA_SOURCE_POLICY,
        "profile": args.profile,
        "phase": args.phase,
        "started_at_utc": run_started_at,
        "commands": command_records,
    }
    if timestamp_name is not None and timestamp_value is not None:
        payload[timestamp_name] = timestamp_value
    return payload


def write_command_records(
    args: argparse.Namespace,
    context: VerifiedRunContext,
    command_records: list[dict[str, Any]],
    run_started_at: str,
    *,
    timestamp_name: str | None = None,
    timestamp_value: str | None = None,
) -> None:
    write_commands_file(
        context.run_root,
        context.commands_file,
        command_records_payload(
            args,
            context,
            command_records,
            run_started_at,
            timestamp_name=timestamp_name,
            timestamp_value=timestamp_value,
        ),
    )


def write_context_manifest(
    args: argparse.Namespace,
    context: VerifiedRunContext,
    command_records: list[dict[str, Any]],
    run_started_at: str,
    finished_at: str,
) -> None:
    write_verified_manifest(
        connector_root=context.connector_root,
        framework_root=context.framework_root,
        build_root=context.build_root,
        verified_run_id=context.verified_run_id,
        started_at=run_started_at,
        finished_at=finished_at,
        commands=command_records,
        commands_file=context.commands_file,
        env=context.env,
        profile=args.profile,
        full_matrix_timeout=context.timeout_budgets["full_matrix_runtime"],
        timeout_budgets=context.timeout_budgets,
    )


def rewrite_manifest_only(
    args: argparse.Namespace,
    context: VerifiedRunContext,
    existing_payload: dict[str, Any],
    command_records: list[dict[str, Any]],
    run_started_at: str,
) -> int:
    finished_at = str(existing_payload.get("finished_at_utc") or utc_now())
    write_context_manifest(args, context, command_records, run_started_at, finished_at)
    return 0


def write_initial_run_artifacts(
    args: argparse.Namespace,
    context: VerifiedRunContext,
    command_records: list[dict[str, Any]],
    run_started_at: str,
) -> None:
    write_command_records(args, context, command_records, run_started_at)
    write_context_manifest(
        args,
        context,
        command_records,
        run_started_at,
        context.started_at,
    )


def planned_command_target(item: dict[str, Any], command: list[str]) -> str:
    fallback_target = command[1] if len(command) == 2 and command[0] == "make" else ""
    return str(item.get("logical_target") or fallback_target)


def runtime_producer_readiness_blocked(command_records: list[dict[str, Any]]) -> bool:
    return any(
        record.get("logical_target") == "check-runtime-producer-readiness"
        and record.get("return_code") != 0
        for record in command_records
    )


def skipped_redundant_full_matrix_resume(
    command: list[str],
    *,
    context: VerifiedRunContext,
    index: int,
    item: dict[str, Any],
    target: str,
) -> dict[str, Any]:
    record = skipped_command_record(
        command,
        logs_dir=context.logs_dir,
        index=index,
        phase=str(item["phase"]),
        required=False,
        optional=True,
        affected_reports=list(item.get("affected_reports", [])),
        reason="a completed required full-matrix producer already exists for this verified run",
        logical_target=target,
    )
    record.update(
        {
            "runtime_complete": False,
            "runtime_status": "runtime_not_required",
            "overall_status": "runtime_not_required",
        }
    )
    print(
        f"verified-report-run: {record['status']} {target}: {record['notes']} log={record['log_path']}",
        flush=True,
    )
    return record


def skipped_not_ready_runtime_producer(
    command: list[str],
    *,
    context: VerifiedRunContext,
    index: int,
    item: dict[str, Any],
    target: str,
) -> dict[str, Any]:
    record = skipped_command_record(
        command,
        logs_dir=context.logs_dir,
        index=index,
        phase=str(item["phase"]),
        required=bool(item["required"]),
        optional=bool(item["optional"]),
        affected_reports=list(item.get("affected_reports", [])),
        reason="check-runtime-producer-readiness did not pass",
        logical_target=target,
    )
    print(
        f"verified-report-run: {record['status']} {target}: {record['notes']} log={record['log_path']}",
        flush=True,
    )
    return record


def planned_command_record(
    item: dict[str, Any],
    *,
    context: VerifiedRunContext,
    index: int,
    command_records: list[dict[str, Any]],
    profile: str,
) -> dict[str, Any]:
    command = list(item["command"])
    target = planned_command_target(item, command)
    redundant_resume = (
        target == "full-matrix-resume"
        and has_completed_full_matrix_producer(command_records)
    )
    if redundant_resume:
        return skipped_redundant_full_matrix_resume(
            command,
            context=context,
            index=index,
            item=item,
            target=target,
        )
    readiness_blocked = runtime_producer_readiness_blocked(command_records)
    if readiness_blocked and target in {"runtime-matrix-all", "full-matrix-parallel", "mrts-native-full-run"}:
        record = skipped_not_ready_runtime_producer(
            command,
            context=context,
            index=index,
            item=item,
            target=target,
        )
    else:
        record = run_command(
            command,
            cwd=context.connector_root,
            env=context.env,
            logs_dir=context.logs_dir,
            index=index,
            phase=str(item["phase"]),
            required=bool(item["required"]),
            optional=bool(item["optional"]),
            timeout_seconds=item.get("timeout_seconds"),
            finalize_grace_seconds=context.timeout_budgets["job_finalize_grace"],
            affected_reports=list(item.get("affected_reports", [])),
            logical_target=target,
        )
    return apply_command_semantics(record, context.env, profile)


def execute_command_plan(
    plan: list[dict[str, Any]],
    *,
    args: argparse.Namespace,
    context: VerifiedRunContext,
    command_records: list[dict[str, Any]],
    run_started_at: str,
) -> bool:
    aggregate_receipt_failed = False
    next_log_index = len(command_records) + 1
    for index, item in enumerate(plan, start=next_log_index):
        record = planned_command_record(
            item,
            context=context,
            index=index,
            command_records=command_records,
            profile=args.profile,
        )
        if (
            qualifies_for_full_matrix_receipt(record, args.profile)
            and not seal_full_matrix_receipt_for_record(
                record=record,
                connector_root=context.connector_root,
                framework_root=context.framework_root,
                build_root=context.build_root,
                verified_run_id=context.verified_run_id,
                profile=args.profile,
            )
        ):
            aggregate_receipt_failed = True
        command_records.append(record)
        last_updated = utc_now()
        write_command_records(
            args,
            context,
            command_records,
            run_started_at,
            timestamp_name="last_updated_at_utc",
            timestamp_value=last_updated,
        )
        write_context_manifest(args, context, command_records, run_started_at, last_updated)
    return aggregate_receipt_failed


def final_exit_status(
    args: argparse.Namespace,
    command_records: list[dict[str, Any]],
    aggregate_receipt_failed: bool,
) -> int:
    failed = [
        record
        for record in command_records
        if record["return_code"] != 0 and record.get("required") and not record.get("optional")
    ]
    soft_mode = args.soft or args.mode == "soft"
    if (failed or aggregate_receipt_failed) and not soft_mode:
        return 1
    return 0


def finish_verified_run(
    args: argparse.Namespace,
    context: VerifiedRunContext,
    command_records: list[dict[str, Any]],
    run_started_at: str,
    aggregate_receipt_failed: bool,
) -> int:
    finished_at = utc_now()
    write_command_records(
        args,
        context,
        command_records,
        run_started_at,
        timestamp_name="finished_at_utc",
        timestamp_value=finished_at,
    )
    write_context_manifest(args, context, command_records, run_started_at, finished_at)
    return final_exit_status(args, command_records, aggregate_receipt_failed)


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()
    context = prepare_verified_run_context(parser, args)
    plan = selected_command_plan(parser, args, context.timeout_budgets)
    existing_payload, command_records, run_started_at = existing_command_state(context, args)
    if args.manifest_only:
        return rewrite_manifest_only(
            args,
            context,
            existing_payload,
            command_records,
            run_started_at,
        )
    write_initial_run_artifacts(args, context, command_records, run_started_at)
    aggregate_receipt_failed = execute_command_plan(
        plan,
        args=args,
        context=context,
        command_records=command_records,
        run_started_at=run_started_at,
    )
    return finish_verified_run(
        args,
        context,
        command_records,
        run_started_at,
        aggregate_receipt_failed,
    )

if __name__ == "__main__":
    raise SystemExit(main())
