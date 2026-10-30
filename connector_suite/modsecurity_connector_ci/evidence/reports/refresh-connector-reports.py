#!/usr/bin/env python3
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

# CI helpers are shared from ci/lib even when this file is executed directly.

from typing import Any

from framework_revision_pins import verify_framework_revision_pins

from modsecurity_connector_ci.lib.generated_report_utils import DATA_SOURCE_POLICY, FILENAME_TO_KEY, GENERATED_REPORTS, GENERATED_ROOT, build_metadata, current_verified_run_id, generated_json_text, generated_at_from_report, generated_markdown_text, generated_report_outputs, input_record, input_status_summary, legacy_report_path, portable_path_reference, registry_record, report_path, report_path_from_root, report_relpath, resolve_input_reference, sanitize_generated_markdown_tree
from modsecurity_connector_ci.lib.report_path_safety import add_report_roots, add_safe_roots, safe_existing_file, safe_path, write_text_file

REPORT_DIR = GENERATED_ROOT
UTC_OFFSET = "+00:00"
GERMAN_MARKDOWN_SUFFIX = ".de.md"
VERIFIED_COMMANDS_FILENAME = "verified-commands.json"
FRAMEWORK_SUBMODULE_PATH = "modules/ModSecurity-test-Framework"
NATIVE_CASE_COMPARISON_GENERATOR = "ci/runtime/lifecycle/run-native-case-comparison.py"
RETIRED_REPORT_NAMES = frozenset(
    {
        "connector_roadmap",
        "report_dependency_graph",
        "report_data_lineage",
        "report_path_migration",
        "generator_runtime_summary",
    }
)
RETIRED_REPORT_MARKERS = tuple(name.replace("_", "-") + ".generated" for name in RETIRED_REPORT_NAMES)
RETIRED_REPORT_TOKENS = RETIRED_REPORT_MARKERS + tuple(RETIRED_REPORT_NAMES)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(UTC_OFFSET, "Z")


def iso_from_timestamp(value: float | None) -> str:
    if value is None:
        return "-"
    return datetime.fromtimestamp(value, timezone.utc).replace(microsecond=0).isoformat().replace(UTC_OFFSET, "Z")


def path_mtime(path: Path) -> float | None:
    try:
        return path.stat().st_mtime if path.exists() else None
    except OSError:
        return None


def git_output(args: list[str], cwd: Path) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except Exception as exc:
        return f"unknown: {exc}"
    return result.stdout.strip()


def git_dirty_status(root: Path) -> str:
    status = git_output(["status", "--short"], root)
    if status.startswith("unknown:"):
        return "unknown"
    return "dirty" if status else "clean"


def git_branch(root: Path) -> str:
    return git_output(["rev-parse", "--abbrev-ref", "HEAD"], root) or "unknown"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def combined_fingerprint(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    seen = False
    for path in sorted(paths, key=lambda item: str(item)):
        if not path.is_file():
            continue
        seen = True
        digest.update(str(path).encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest() if seen else "missing"


def git_sha(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except Exception:
        return "unknown"
    return result.stdout.strip() or "unknown"


def display_path(path: Path, connector_root: Path, framework_root: Path, build_root: Path) -> str:
    path = path.resolve(strict=False)
    roots = (
        (connector_root.resolve(strict=False), ""),
        (framework_root.resolve(strict=False), "framework:"),
        (build_root.resolve(strict=False), "BUILD_ROOT:"),
    )
    for root, prefix in roots:
        try:
            rel = path.relative_to(root)
        except ValueError:
            continue
        return prefix + str(rel)
    return portable_path_reference(path)


def run_command(cmd: list[str], cwd: Path, env: dict[str, str]) -> tuple[int, str, dict[str, Any]]:
    print("refresh-connector-reports: RUN " + " ".join(cmd))
    started = time.monotonic()
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if proc.stdout:
        print(proc.stdout.rstrip())
    output = proc.stdout or ""
    log_info: dict[str, Any] = {
        "output_sha256": hashlib.sha256(output.encode("utf-8", errors="replace")).hexdigest(),
        "log_path": None,
        "log_hash": None,
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    log_root = env.get("VERIFIED_RUN_LOG_ROOT")
    if log_root:
        logs_dir = safe_path(Path(log_root) / "generator-logs", must_exist=False)
        if logs_dir is not None:
            slug_source = cmd[-1] if cmd else "command"
            slug = "".join(ch if ch.isalnum() else "-" for ch in slug_source).strip("-") or "command"
            log_path = logs_dir / f"{int(time.time() * 1000)}-{slug[:80]}.log"
            write_text_file(log_path, output)
            log_info["log_path"] = str(log_path)
            log_info["log_hash"] = sha256_file(log_path)
    return proc.returncode, output, log_info


def read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def contains_retired_report_reference(value: object) -> bool:
    return any(token in str(value) for token in RETIRED_REPORT_TOKENS)


def prune_retired_record_fields(record: dict[str, Any]) -> bool:
    """Remove retired report paths from one retained governance record."""

    changed = False
    for field in (
        "inputs",
        "input_files",
        "output_files",
        "missing_inputs",
        "empty_inputs",
        "unknown_inputs",
        "missing_outputs",
    ):
        values = record.get(field)
        if not isinstance(values, list):
            continue
        retained = [
            value
            for value in values
            if not contains_retired_report_reference(
                value.get("path") if isinstance(value, dict) else value
            )
        ]
        if len(retained) != len(values):
            record[field] = retained
            changed = True
    return changed


def prune_retired_report_records(payload: dict[str, Any]) -> bool:
    """Drop records and metadata inputs for outputs no longer in the registry.

    This supports a controlled documentation-output reduction without running
    runtime-producing report generators merely to rewrite their catalog.
    """

    records_changed = _prune_retired_records(payload)
    metadata_changed = _prune_retired_metadata_inputs(payload.get("metadata"))
    return records_changed or metadata_changed


def _prune_retired_records(payload: dict[str, Any]) -> bool:
    records = payload.get("reports")
    if not isinstance(records, list):
        return False
    retained: list[object] = []
    changed = False
    for record in records:
        if isinstance(record, dict) and str(record.get("report_name") or "") in RETIRED_REPORT_NAMES:
            changed = True
            continue
        if isinstance(record, dict):
            changed = prune_retired_record_fields(record) or changed
        retained.append(record)
    if changed:
        payload["reports"] = retained
    return changed


def _prune_retired_metadata_inputs(metadata: object) -> bool:
    if not isinstance(metadata, dict):
        return False
    inputs = metadata.get("inputs")
    if not isinstance(inputs, list):
        return False
    retained = [
        item
        for item in inputs
        if not contains_retired_report_reference(
            item.get("path") if isinstance(item, dict) else item
        )
    ]
    if len(retained) == len(inputs):
        return False
    metadata["inputs"] = retained
    _prune_retired_metadata_statuses(metadata)
    return True


def _prune_retired_metadata_statuses(metadata: dict[str, Any]) -> None:
    for field in ("missing_inputs", "empty_inputs", "unknown_inputs"):
        values = metadata.get(field)
        if isinstance(values, list):
            metadata[field] = [
                value
                for value in values
                if not contains_retired_report_reference(value)
            ]


def prune_retired_markdown_rows(path: Path) -> bool:
    """Remove retired generated-output rows from a retained language companion."""

    safe_report_path = safe_existing_file(path)
    if safe_report_path is None:
        return False
    text = safe_report_path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines(keepends=True)
    retained = [line for line in lines if not contains_retired_report_reference(line)]
    if len(retained) == len(lines):
        return False
    write_text_file(safe_report_path, "".join(retained))
    return True


def prune_retired_freshness_report(connector_root: Path) -> bool:
    """Refresh the retained freshness view without invoking runtime producers."""

    add_safe_roots(connector_root, connector_root / REPORT_DIR)
    json_path = safe_existing_file(report_path(connector_root, "report_freshness", "json"))
    if json_path is None:
        return False
    payload = read_json(json_path)
    if not payload or not prune_retired_report_records(payload):
        return False
    metadata = payload.pop("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError(f"cannot preserve metadata while pruning {json_path}")
    write_text_file(json_path, generated_json_text(payload, metadata))
    md_path = report_path(connector_root, "report_freshness", "md")
    write_text_file(md_path, generated_markdown_text(render_freshness_md(payload), metadata))
    prune_retired_markdown_rows(german_markdown_companion(md_path) or md_path)
    return True


def read_verified_commands(env: dict[str, str]) -> list[dict[str, Any]]:
    path_value = env.get("VERIFIED_RUN_COMMANDS_FILE")
    if not path_value:
        return []
    path = Path(path_value)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    commands = data.get("commands") if isinstance(data, dict) else data
    return commands if isinstance(commands, list) else []


def verified_command_for_target(env: dict[str, str], target: str) -> dict[str, Any]:
    for command in read_verified_commands(env):
        raw = command.get("command")
        if command.get("logical_target") == target:
            return command
        if isinstance(raw, list) and raw == ["make", target]:
            return command
    return {}


def full_matrix_job_evidence_complete(env: dict[str, str]) -> bool:
    connector_root_value = env.get("CONNECTOR_ROOT") or "."
    connector_root = Path(connector_root_value).resolve()
    data = read_json(report_path(connector_root, "full_matrix_job_completeness", "json"))
    try:
        complete = int(data.get("complete_jobs") or 0)
        total = int(data.get("total_jobs") or 0)
    except (TypeError, ValueError):
        return False
    return total > 0 and complete >= total and str(data.get("evidence_scope") or "") == "full"


def full_matrix_producer_block(spec: ReportSpec, env: dict[str, str]) -> tuple[str, str]:
    if spec.name != "full_runtime_matrix":
        return "", ""
    if env.get("VERIFIED_RUN_PROFILE") == "smoke":
        return "blocked_smoke_only", "smoke verified run does not produce merge-ready full matrix evidence"
    if full_matrix_job_evidence_complete(env):
        return "", ""
    command = verified_command_for_target(env, "full-matrix-parallel")
    if not command:
        return "", ""
    if command.get("runtime_complete") is True or str(command.get("runtime_status") or "").startswith("runtime_completed"):
        return "", ""
    try:
        return_code = int(command.get("return_code", 1))
    except (TypeError, ValueError):
        return_code = 1
    if command.get("status") == "PASS" and return_code == 0:
        return "", ""
    classification = str(command.get("classification") or "command_failed")
    if classification == "blocked_timeout":
        return "blocked_timeout", "full-matrix-parallel timed out before producing complete verified evidence"
    if classification == "interrupted":
        return "interrupted", "full-matrix-parallel was interrupted before producing complete verified evidence"
    return "blocked", f"full-matrix-parallel did not complete successfully: {classification}"


@dataclass(frozen=True)
class ReportSpec:
    name: str
    owner: str
    generator: str
    make_target: str
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    command: tuple[str, ...]
    requires_runtime: bool = False
    requires_native_mrts: bool = False
    requires_full_matrix: bool = False
    optional: bool = False


CONNECTOR_COVERAGE_OUTPUTS = ("reports/testing/test-coverage-overview.md",) + generated_report_outputs(
    [
        "apache_runtime_results",
        "case_matrix",
        "connector_gap_summary",
        "coverage_summary",
        "haproxy_runtime_results",
        "nginx_runtime_results",
        "phase_coverage",
        "runtime_matrix",
        "xfail_summary",
    ]
)
FULL_RUNTIME_OUTPUTS = generated_report_outputs(["full_runtime_matrix"])
CONNECTOR_WORK_QUEUE_OUTPUTS = generated_report_outputs(["connector_work_queue"])
PHASE_WORK_QUEUE_OUTPUTS = generated_report_outputs(["phase_work_queue"])
NATIVE_OUTPUTS = generated_report_outputs(
    ["mrts_native_full", "mrts_native_apache", "mrts_native_nginx", "mrts_native_summary"]
)
FULL_RUN_EVIDENCE_OUTPUTS = generated_report_outputs(["full_run_evidence"])
RUNTIME_CACHE_OUTPUTS = generated_report_outputs(["runtime_component_cache", "runtime_build_cache", "runtime_cache_index"])
FULL_MATRIX_JOB_COMPLETENESS_OUTPUTS = generated_report_outputs(["full_matrix_job_completeness"])
VERIFIED_RUNTIME_MISMATCH_OUTPUTS = generated_report_outputs(["verified_runtime_mismatch_analysis"])
NGINX_MRTS_HTTP500_OUTPUTS = generated_report_outputs(["nginx_mrts_http500_cluster_analysis"])
NATIVE_SEMANTICS_OUTPUTS = generated_report_outputs(["native_semantics_comparison"])
NOLOG_OUTPUTS = generated_report_outputs(["nolog_audit_evidence"])
RESPONSE_HEADER_OUTPUTS = generated_report_outputs(["response_header_hook_analysis"])
PHASE4_OUTPUTS = generated_report_outputs(["phase4_hard_abort_capability"])
INTERVENTION_BLOCKING_OUTPUTS = generated_report_outputs(["intervention_blocking_analysis"])
NO_MRTS_NOMATCH_OUTPUTS = generated_report_outputs(["no_mrts_intervention_nomatch_analysis"])
BODY_PROCESSOR_OUTPUTS = generated_report_outputs(["body_processor_analysis"])
RULE_CHAIN_OUTPUTS = generated_report_outputs(["rule_chain_semantics_analysis"])
FINAL_CONSISTENCY_OUTPUTS = generated_report_outputs(["final_consistency_audit"])
REMAINING_OUTPUTS = generated_report_outputs(["remaining_failure_analysis", "next_fix_plan"])


def verified_commands_path(build_root: Path, connector_root: Path) -> Path:
    configured = os.environ.get("VERIFIED_RUN_COMMANDS_FILE")
    if configured:
        return Path(configured)
    return build_root / "verified-runs" / current_verified_run_id(connector_root) / VERIFIED_COMMANDS_FILENAME


def make_catalog(connector_root: Path, framework_root: Path, build_root: Path, native_root: Path, python: str) -> list[ReportSpec]:
    report_dir = connector_root / REPORT_DIR
    default_verified_run_root = Path.home() / ".cache" / "ModSecurity-conector" / "verified"
    verified_run_root = Path(os.environ.get("VERIFIED_RUN_ROOT", default_verified_run_root))
    component_cache_root = Path(
        os.environ.get("CONNECTOR_COMPONENT_CACHE")
        or os.environ.get("VERIFIED_COMPONENT_CACHE")
        or Path(os.environ.get("CACHE_ROOT", verified_run_root / "cache-v2")) / "shared"
    ).resolve()
    existing_full_matrix = read_json(report_path(connector_root, "full_runtime_matrix", "json"))
    if not existing_full_matrix:
        existing_full_matrix = read_json(legacy_report_path(connector_root, "full_runtime_matrix", "json"))
    explicit_manifest = False
    if os.environ.get("FULL_MATRIX_MANIFEST"):
        explicit_manifest = True
        full_matrix_manifest = Path(str(os.environ["FULL_MATRIX_MANIFEST"]))
    elif os.environ.get("MATRIX_ROOT"):
        full_matrix_manifest = Path(str(os.environ["MATRIX_ROOT"])) / "full-runtime-matrix-runs.jsonl"
    elif existing_full_matrix.get("manifest"):
        full_matrix_manifest = Path(str(existing_full_matrix["manifest"]))
    else:
        full_matrix_manifest = build_root / "full-matrix" / "full-runtime-matrix-runs.jsonl"
    full_matrix_build_root = Path(str(existing_full_matrix.get("build_root") or build_root))
    if explicit_manifest:
        full_matrix_build_root = full_matrix_manifest.parent
    if os.environ.get("MATRIX_ROOT"):
        full_matrix_build_root = Path(str(os.environ["MATRIX_ROOT"]))
    full_matrix_log_root = Path(str(existing_full_matrix.get("log_root") or os.environ.get("LOG_ROOT", str(build_root / "logs"))))
    if explicit_manifest:
        full_matrix_log_root = full_matrix_manifest.parent
    if os.environ.get("MATRIX_ROOT"):
        full_matrix_log_root = Path(str(os.environ["MATRIX_ROOT"]))
    return [
        ReportSpec(
            name="connector_coverage_reports",
            owner="connector",
            generator="framework:ci/reporting/generate-case-matrix.py",
            make_target="generate-test-matrix",
            inputs=(
                "config/testing/import-status.json",
                "reports/testing/runtime-validation-snapshot.json",
            ),
            outputs=CONNECTOR_COVERAGE_OUTPUTS,
            command=(
                "make",
                "-C",
                str(framework_root),
                "generate-test-matrix",
                f"PYTHON={python}",
                f"FRAMEWORK_ROOT={framework_root}",
                f"CONNECTOR_ROOT={connector_root}",
                f"OUTPUT_ROOT={connector_root}",
                "SKIP_ROOT_SUMMARY=1",
            ),
            requires_runtime=True,
        ),
        ReportSpec(
            name="full_runtime_matrix",
            owner="connector",
            generator="ci/evidence/reports/generate-full-runtime-matrix.py",
            make_target="generate-full-runtime-matrix",
            inputs=(str(full_matrix_manifest),),
            outputs=FULL_RUNTIME_OUTPUTS,
            command=(
                python,
                "ci/evidence/reports/generate-full-runtime-matrix.py",
                "--connector-root",
                str(connector_root),
                "--framework-root",
                str(framework_root),
                "--build-root",
                str(full_matrix_build_root),
                "--log-root",
                str(full_matrix_log_root),
                "--manifest",
                str(full_matrix_manifest),
                "--output-dir",
                str(report_dir),
            ),
            requires_runtime=True,
            requires_full_matrix=True,
        ),
        ReportSpec(
            name="full_matrix_job_completeness",
            owner="connector",
            generator="ci/evidence/reports/generate-full-matrix-job-completeness.py",
            make_target="generate-full-matrix-job-completeness",
            inputs=(
                str(verified_commands_path(build_root, connector_root)),
                str(full_matrix_manifest),
            ),
            outputs=FULL_MATRIX_JOB_COMPLETENESS_OUTPUTS,
            command=(
                python,
                "ci/evidence/reports/generate-full-matrix-job-completeness.py",
                "--connector-root",
                str(connector_root),
                "--framework-root",
                str(framework_root),
                "--build-root",
                str(build_root),
                "--output-dir",
                str(report_dir / "manifest"),
                "--verified-run-id",
                current_verified_run_id(connector_root),
                "--verified-commands-file",
                str(verified_commands_path(build_root, connector_root)),
                "--rewrite-manifest",
            ),
            requires_runtime=True,
            requires_full_matrix=True,
        ),
        ReportSpec(
            name="verified_runtime_mismatch_analysis",
            owner="connector",
            generator="ci/evidence/reports/generate-verified-runtime-mismatch-analysis.py",
            make_target="generate-verified-runtime-mismatch-analysis",
            inputs=(
                str(verified_commands_path(build_root, connector_root)),
                str(full_matrix_manifest),
            ),
            outputs=VERIFIED_RUNTIME_MISMATCH_OUTPUTS,
            command=(
                python,
                "ci/evidence/reports/generate-verified-runtime-mismatch-analysis.py",
                "--connector-root",
                str(connector_root),
                "--framework-root",
                str(framework_root),
                "--build-root",
                str(build_root),
                "--output-dir",
                str(report_dir / "manifest"),
                "--verified-run-id",
                current_verified_run_id(connector_root),
                "--verified-commands-file",
                str(verified_commands_path(build_root, connector_root)),
            ),
            requires_runtime=True,
        ),
        ReportSpec(
            name="nginx_mrts_http500_cluster_analysis",
            owner="connector",
            generator="ci/evidence/reports/generate-nginx-mrts-http500-cluster-analysis.py",
            make_target="generate-nginx-mrts-http500-cluster-analysis",
            inputs=(
                str(verified_commands_path(build_root, connector_root)),
                str(full_matrix_manifest),
                report_relpath("full_matrix_job_completeness", "json"),
                report_relpath("verified_runtime_mismatch_analysis", "json"),
            ),
            outputs=NGINX_MRTS_HTTP500_OUTPUTS,
            command=(
                python,
                "ci/evidence/reports/generate-nginx-mrts-http500-cluster-analysis.py",
                "--connector-root",
                str(connector_root),
                "--framework-root",
                str(framework_root),
                "--build-root",
                str(build_root),
                "--output-dir",
                str(report_dir / "manifest"),
                "--verified-run-id",
                current_verified_run_id(connector_root),
            ),
            requires_runtime=True,
            requires_full_matrix=True,
        ),
        ReportSpec(
            name="connector_work_queue",
            owner="connector",
            generator="framework:ci/reporting/generate-connector-work-queue.py",
            make_target="generate-work-queue",
            inputs=(report_relpath("full_runtime_matrix", "json"),),
            outputs=CONNECTOR_WORK_QUEUE_OUTPUTS,
            command=(
                python,
                str(framework_root / "ci/reporting/generate-connector-work-queue.py"),
                "--connector-root",
                str(connector_root),
                "--framework-root",
                str(framework_root),
                "--output-root",
                str(connector_root),
                "--full-runtime-matrix",
                str(report_path(connector_root, "full_runtime_matrix", "json")),
            ),
            requires_runtime=True,
            requires_full_matrix=True,
        ),
        ReportSpec(
            name="phase_work_queue",
            owner="connector",
            generator="framework:ci/reporting/generate-phase-work-queue.py",
            make_target="generate-phase-work-queue",
            inputs=(
                report_relpath("connector_work_queue", "json"),
                report_relpath("phase_coverage", "md"),
                report_relpath("full_runtime_matrix", "json"),
            ),
            outputs=PHASE_WORK_QUEUE_OUTPUTS,
            command=(
                python,
                str(framework_root / "ci/reporting/generate-phase-work-queue.py"),
                "--connector-root",
                str(connector_root),
                "--framework-root",
                str(framework_root),
                "--output-root",
                str(connector_root),
                "--connector-work-queue",
                str(report_path(connector_root, "connector_work_queue", "json")),
                "--phase-coverage",
                str(report_path(connector_root, "phase_coverage", "md")),
                "--full-runtime-matrix",
                str(report_path(connector_root, "full_runtime_matrix", "json")),
            ),
            requires_runtime=True,
            requires_full_matrix=True,
        ),
        ReportSpec(
            name="native_mrts_reports",
            owner="connector",
            generator="framework:ci/reporting/generate-mrts-native-report.py",
            make_target="mrts-native-full-run",
            inputs=(
                str(native_root / "apache2_ubuntu/job.json"),
                str(native_root / "nginx-pr24/job.json"),
            ),
            outputs=NATIVE_OUTPUTS,
            command=(
                python,
                str(framework_root / "ci/reporting/generate-mrts-native-report.py"),
                "--connector-root",
                str(connector_root),
                "--framework-root",
                str(framework_root),
                "--native-root",
                str(native_root),
                "--output-root",
                str(connector_root),
            ),
            requires_native_mrts=True,
            optional=True,
        ),
        ReportSpec(
            name="native_semantics_comparison",
            owner="connector",
            generator=NATIVE_CASE_COMPARISON_GENERATOR,
            make_target="generate-native-semantics-comparison",
            inputs=(
                NATIVE_CASE_COMPARISON_GENERATOR,
                "ci/tools/native_modsecurity_oracle.c",
                report_relpath("verified_runtime_mismatch_analysis", "json"),
            ),
            outputs=NATIVE_SEMANTICS_OUTPUTS,
            command=(
                python,
                NATIVE_CASE_COMPARISON_GENERATOR,
                "--connector-root",
                str(connector_root),
                "--framework-root",
                str(framework_root),
                "--build-root",
                str(build_root),
                "--verified-run-root",
                str(verified_run_root),
                "--output-dir",
                str(report_dir / "manifest"),
                "--report-only",
            ),
            requires_runtime=True,
            requires_full_matrix=True,
            optional=True,
        ),
        ReportSpec(
            name="nolog_audit_evidence",
            owner="connector",
            generator="ci/evidence/reports/generate-nolog-audit-evidence-analysis.py",
            make_target="generate-nolog-audit-evidence-analysis",
            inputs=(
                report_relpath("connector_work_queue", "json"),
                report_relpath("full_runtime_matrix", "json"),
                report_relpath("phase_coverage", "md"),
            ),
            outputs=NOLOG_OUTPUTS + PHASE_WORK_QUEUE_OUTPUTS,
            command=(
                python,
                "ci/evidence/reports/generate-nolog-audit-evidence-analysis.py",
                "--connector-root",
                str(connector_root),
                "--framework-root",
                str(framework_root),
                "--output-dir",
                str(report_dir),
            ),
            requires_runtime=True,
            requires_full_matrix=True,
        ),
        ReportSpec(
            name="response_header_hook_analysis",
            owner="connector",
            generator="ci/evidence/reports/generate-response-header-hook-analysis.py",
            make_target="generate-response-header-hook-analysis",
            inputs=(
                report_relpath("connector_work_queue", "json"),
                report_relpath("full_runtime_matrix", "json"),
                report_relpath("phase_coverage", "md"),
            ),
            outputs=RESPONSE_HEADER_OUTPUTS + PHASE_WORK_QUEUE_OUTPUTS,
            command=(
                python,
                "ci/evidence/reports/generate-response-header-hook-analysis.py",
                "--connector-root",
                str(connector_root),
                "--framework-root",
                str(framework_root),
                "--output-dir",
                str(report_dir),
            ),
            requires_runtime=True,
            requires_full_matrix=True,
        ),
        ReportSpec(
            name="phase4_hard_abort_capability",
            owner="connector",
            generator="ci/evidence/reports/generate-phase4-hard-abort-capability.py",
            make_target="generate-phase4-hard-abort-capability",
            inputs=(
                report_relpath("connector_work_queue", "json"),
                report_relpath("full_runtime_matrix", "json"),
                report_relpath("mrts_native_apache", "json"),
                report_relpath("mrts_native_nginx", "json"),
            ),
            outputs=PHASE4_OUTPUTS + PHASE_WORK_QUEUE_OUTPUTS,
            command=(
                python,
                "ci/evidence/reports/generate-phase4-hard-abort-capability.py",
                "--connector-root",
                str(connector_root),
                "--output-dir",
                str(report_dir),
            ),
            requires_runtime=True,
            requires_full_matrix=True,
        ),
        ReportSpec(
            name="remaining_failure_analysis",
            owner="connector",
            generator="ci/evidence/reports/generate-remaining-failure-analysis.py",
            make_target="generate-remaining-failure-analysis",
            inputs=(
                report_relpath("full_runtime_matrix", "json"),
                report_relpath("connector_work_queue", "json"),
                report_relpath("phase_work_queue", "json"),
                report_relpath("mrts_native_summary", "json"),
            ),
            outputs=REMAINING_OUTPUTS + FULL_RUN_EVIDENCE_OUTPUTS,
            command=(
                python,
                "ci/evidence/reports/generate-remaining-failure-analysis.py",
                "--connector-root",
                str(connector_root),
                "--output-dir",
                str(report_dir),
            ),
            requires_runtime=True,
            requires_full_matrix=True,
        ),
        ReportSpec(
            name="intervention_blocking_analysis",
            owner="connector",
            generator="ci/evidence/reports/generate-intervention-blocking-analysis.py",
            make_target="generate-intervention-blocking-analysis",
            inputs=(
                report_relpath("connector_work_queue", "json"),
                report_relpath("full_runtime_matrix", "json"),
                report_relpath("remaining_failure_analysis", "json"),
                report_relpath("phase_work_queue", "json"),
                report_relpath("next_fix_plan", "json"),
            ),
            outputs=INTERVENTION_BLOCKING_OUTPUTS,
            command=(
                python,
                "ci/evidence/reports/generate-intervention-blocking-analysis.py",
                "--connector-root",
                str(connector_root),
                "--framework-root",
                str(framework_root),
                "--output-dir",
                str(report_dir),
            ),
            requires_runtime=True,
            requires_full_matrix=True,
        ),
        ReportSpec(
            name="no_mrts_intervention_nomatch_analysis",
            owner="connector",
            generator="ci/evidence/reports/generate-no-mrts-intervention-nomatch-analysis.py",
            make_target="generate-no-mrts-intervention-nomatch-analysis",
            inputs=(
                report_relpath("intervention_blocking_analysis", "json"),
                report_relpath("full_runtime_matrix", "json"),
                report_relpath("remaining_failure_analysis", "json"),
                report_relpath("next_fix_plan", "json"),
            ),
            outputs=NO_MRTS_NOMATCH_OUTPUTS,
            command=(
                python,
                "ci/evidence/reports/generate-no-mrts-intervention-nomatch-analysis.py",
                "--connector-root",
                str(connector_root),
                "--framework-root",
                str(framework_root),
                "--output-dir",
                str(report_dir),
            ),
            requires_runtime=True,
            requires_full_matrix=True,
        ),
        ReportSpec(
            name="body_processor_analysis",
            owner="connector",
            generator="ci/evidence/reports/generate-body-processor-analysis.py",
            make_target="generate-body-processor-analysis",
            inputs=(
                report_relpath("connector_work_queue", "json"),
                report_relpath("remaining_failure_analysis", "json"),
                report_relpath("phase_work_queue", "json"),
                report_relpath("next_fix_plan", "json"),
            ),
            outputs=BODY_PROCESSOR_OUTPUTS,
            command=(
                python,
                "ci/evidence/reports/generate-body-processor-analysis.py",
                "--connector-root",
                str(connector_root),
                "--framework-root",
                str(framework_root),
                "--output-dir",
                str(report_dir),
            ),
            requires_runtime=True,
            requires_full_matrix=True,
        ),
        ReportSpec(
            name="rule_chain_semantics_analysis",
            owner="connector",
            generator="ci/evidence/reports/generate-rule-chain-semantics-analysis.py",
            make_target="generate-rule-chain-semantics-analysis",
            inputs=(
                report_relpath("connector_work_queue", "json"),
                report_relpath("remaining_failure_analysis", "json"),
                report_relpath("next_fix_plan", "json"),
                report_relpath("full_runtime_matrix", "json"),
            ),
            outputs=RULE_CHAIN_OUTPUTS,
            command=(
                python,
                "ci/evidence/reports/generate-rule-chain-semantics-analysis.py",
                "--connector-root",
                str(connector_root),
                "--framework-root",
                str(framework_root),
                "--output-dir",
                str(report_dir),
            ),
            requires_runtime=True,
            requires_full_matrix=True,
        ),
        ReportSpec(
            name="final_consistency_audit",
            owner="connector",
            generator="ci/evidence/reports/generate-final-consistency-audit.py",
            make_target="generate-final-consistency-audit",
            inputs=(
                report_relpath("full_runtime_matrix", "json"),
                report_relpath("connector_work_queue", "json"),
                report_relpath("phase_work_queue", "json"),
                report_relpath("remaining_failure_analysis", "json"),
                report_relpath("next_fix_plan", "json"),
                report_relpath("full_run_evidence", "json"),
                report_relpath("mrts_native_summary", "json"),
                report_relpath("phase4_hard_abort_capability", "json"),
                report_relpath("nolog_audit_evidence", "json"),
                report_relpath("response_header_hook_analysis", "json"),
                report_relpath("body_processor_analysis", "json"),
                report_relpath("intervention_blocking_analysis", "json"),
                report_relpath("no_mrts_intervention_nomatch_analysis", "json"),
                report_relpath("rule_chain_semantics_analysis", "json"),
            ),
            outputs=FINAL_CONSISTENCY_OUTPUTS,
            command=(
                python,
                "ci/evidence/reports/generate-final-consistency-audit.py",
                "--connector-root",
                str(connector_root),
                "--framework-root",
                str(framework_root),
                "--output-dir",
                str(report_dir),
            ),
            requires_runtime=True,
            requires_full_matrix=True,
        ),
        ReportSpec(
            name="runtime_cache_reports",
            owner="cache",
            generator="ci/evidence/reports/update-runtime-reports.py",
            make_target="prepare-runtime-components",
            inputs=(
                str(component_cache_root / "manifest.json"),
                str(component_cache_root / "runtime-build-cache.json"),
            ),
            outputs=RUNTIME_CACHE_OUTPUTS,
            command=(
                python,
                "ci/evidence/reports/update-runtime-reports.py",
                "--connector-root",
                str(connector_root),
                "--cache-root",
                str(component_cache_root),
            ),
            requires_runtime=True,
            optional=True,
        ),
    ]


def resolve_input(raw: str, connector_root: Path, framework_root: Path, build_root: Path) -> Path:
    return resolve_input_reference(raw, connector_root, framework_root, build_root)


def resolve_output(raw: str, connector_root: Path) -> Path:
    path = Path(raw)
    return path if path.is_absolute() else connector_root / path


SPEC_PRIMARY_OUTPUT_KEYS: dict[str, set[str]] = {
    "connector_coverage_reports": {
        "apache_runtime_results",
        "case_matrix",
        "connector_gap_summary",
        "coverage_summary",
        "haproxy_runtime_results",
        "nginx_runtime_results",
        "phase_coverage",
        "runtime_matrix",
        "xfail_summary",
    },
    "native_mrts_reports": {"mrts_native_full", "mrts_native_apache", "mrts_native_nginx", "mrts_native_summary"},
    "remaining_failure_analysis": {"remaining_failure_analysis", "next_fix_plan", "full_run_evidence"},
    "final_consistency_audit": {"final_consistency_audit"},
    "runtime_cache_reports": {"runtime_component_cache", "runtime_build_cache"},
}


def primary_output_paths(spec: ReportSpec, output_paths: list[Path]) -> list[Path]:
    allowed = SPEC_PRIMARY_OUTPUT_KEYS.get(spec.name)
    if allowed is None and spec.name in GENERATED_REPORTS:
        allowed = {spec.name}
    if allowed is None:
        return output_paths
    return [path for path in output_paths if FILENAME_TO_KEY.get(path.name) in allowed]


def placeholder_markdown(key: str, status: str, reason: str, spec: ReportSpec) -> str:
    title = GENERATED_REPORTS[key].purpose
    command = " ".join(spec.command)
    return "\n".join(
        [
            f"# {title}",
            "",
            f"Status: `{status}`",
            "",
            f"Reason: {reason}",
            "",
            "## Verified Command",
            "",
            "| Command | Status | Return Code | Notes |",
            "|---|---|---:|---|",
            f"| `{md(command)}` | {status} | - | {md(reason)} |",
            "",
            "## Rows",
            "",
            "_No rows available. Reason: producer command was not run or verified input is unavailable._",
        ]
    ) + "\n"


def is_placeholder_output(path: Path) -> bool:
    """Return whether a prior generated output contains no retained evidence."""

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if path.suffix == ".json":
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            return False
        if not isinstance(value, dict):
            return False
        status = str(value.get("status") or "")
        return status.startswith(("skipped", "blocked", "failed")) and value.get("rows") == []
    return bool(
        re.search(r"^Status: `(?:skipped|blocked|failed)[^`]*`$", text, flags=re.MULTILINE)
        and "_No rows available. Reason: producer command was not run or verified input is unavailable._" in text
    )


def retained_notice(status: str, reason: str, *, german: bool) -> str:
    if german:
        return (
            "<!-- retained-historical-generated-output -->\n"
            f"> Aktueller Refresh-Status: `{status}`. Dieser Report bewahrt einen früheren "
            f"evidenztragenden Snapshot, weil keine neuen verifizierten Eingaben vorliegen. Grund: {reason}.\n\n"
        )
    return (
        "<!-- retained-historical-generated-output -->\n"
        f"> Current refresh status: `{status}`. This report retains an earlier evidence-bearing "
        f"snapshot because no newer verified inputs are available. Reason: {reason}.\n\n"
    )


def mark_retained_markdown(path: Path, status: str, reason: str) -> None:
    """Mark a retained generated snapshot without changing its evidence rows."""

    safe_report_path = safe_existing_file(path)
    if safe_report_path is None:
        return
    text = safe_report_path.read_text(encoding="utf-8")
    notice = retained_notice(status, reason, german=path.name.endswith(GERMAN_MARKDOWN_SUFFIX))
    marker = "<!-- retained-historical-generated-output -->"
    if marker in text:
        text = re.sub(
            rf"{re.escape(marker)}\n>.*?\n\n",
            notice,
            text,
            count=1,
            flags=re.DOTALL,
        )
    else:
        heading = text.find("\n\n#")
        if heading >= 0:
            text = text[: heading + 2] + notice + text[heading + 2 :]
        else:
            text += "\n" + notice
    write_text_file(safe_report_path, text)


def german_markdown_companion(path: Path) -> Path | None:
    if not path.name.endswith(".generated.md"):
        return None
    return path.with_name(path.name.removesuffix(".md") + GERMAN_MARKDOWN_SUFFIX)


def retain_existing_output(
    path: Path,
    status: str,
    reason: str,
    connector_root: Path,
    *,
    preserve_existing: bool,
) -> bool:
    if not preserve_existing or not path.is_file() or is_placeholder_output(path):
        return False
    if path.suffix == ".md":
        mark_retained_markdown(path, status, reason)
        german = german_markdown_companion(path)
        if german and german.is_file():
            mark_retained_markdown(german, status, reason)
    print(f"refresh-connector-reports: retained historical output {path.relative_to(connector_root)}")
    return True


def placeholder_metadata(
    spec: ReportSpec,
    key: str,
    connector_root: Path,
    framework_root: Path,
    generated_at: str,
    status: str,
    reason: str,
) -> dict[str, Any]:
    report = GENERATED_REPORTS[key]
    return build_metadata(
        generated_by=report.generator,
        make_target=report.make_target,
        connector_root=connector_root,
        framework_root=framework_root,
        inputs=spec.inputs,
        generated_at=generated_at,
        report_key=key,
        extra={"run_status": status, "blocked_reason": reason},
    )


def placeholder_payload(
    spec: ReportSpec, key: str, status: str, reason: str, metadata: dict[str, Any]
) -> dict[str, Any]:
    return {
        "status": status,
        "reason": reason,
        "report_key": key,
        "report_name": key,
        "generator": spec.generator,
        "make_target": spec.make_target,
        "command": list(spec.command),
        "data_source_policy": DATA_SOURCE_POLICY,
        "verified_run_id": metadata["verified_run_id"],
        "rows": [],
        "empty_reason": "producer command was not run or verified input is unavailable",
    }


def write_placeholder_output(
    path: Path,
    key: str,
    status: str,
    reason: str,
    spec: ReportSpec,
    payload: dict[str, Any],
    metadata: dict[str, Any],
) -> None:
    if path.suffix == ".json":
        write_text_file(path, generated_json_text(payload, metadata))
    elif path.suffix == ".md":
        write_text_file(path, generated_markdown_text(placeholder_markdown(key, status, reason, spec), metadata))


def write_placeholder_outputs(
    spec: ReportSpec,
    status: str,
    reason: str,
    output_paths: list[Path],
    connector_root: Path,
    framework_root: Path,
    generated_at: str,
    *,
    preserve_existing: bool = False,
) -> None:
    for path in primary_output_paths(spec, output_paths):
        key = FILENAME_TO_KEY.get(path.name)
        if not key:
            continue
        if retain_existing_output(
            path,
            status,
            reason,
            connector_root,
            preserve_existing=preserve_existing,
        ):
            continue
        metadata = placeholder_metadata(spec, key, connector_root, framework_root, generated_at, status, reason)
        payload = placeholder_payload(spec, key, status, reason, metadata)
        write_placeholder_output(path, key, status, reason, spec, payload, metadata)


def run_spec(
    spec: ReportSpec,
    connector_root: Path,
    framework_root: Path,
    build_root: Path,
    env: dict[str, str],
) -> dict[str, Any]:
    started_at = utc_now()
    started = time.monotonic()
    input_paths = [resolve_input(raw, connector_root, framework_root, build_root) for raw in spec.inputs]
    output_paths = [resolve_output(raw, connector_root) for raw in spec.outputs]
    records = [input_record(raw, connector_root, framework_root, build_root) for raw in spec.inputs]
    inputs = report_input_state(spec, input_paths, records, env)
    skip_status, blocked_reason = report_skip_status(spec, env, inputs)
    if skip_status:
        return skipped_spec_record(
            spec, skip_status, blocked_reason, input_paths, output_paths, inputs,
            connector_root, framework_root, build_root, started_at, started,
        )
    return generated_spec_record(
        spec, input_paths, output_paths, inputs, connector_root, framework_root,
        build_root, env, started_at, started,
    )


def report_input_state(
    spec: ReportSpec,
    input_paths: list[Path],
    records: list[dict[str, Any]],
    env: dict[str, str],
) -> dict[str, list[Any]]:
    stale = [record["path"] for record in records if record.get("status") == "stale"]
    stale.extend(stale_runtime_raw_inputs(spec, input_paths, env))
    return {
        "missing": [path for path in input_paths if not path.exists()],
        "stale": stale,
        "blocked": [
            record["path"]
            for record in records
            if is_blocked_input_status(str(record.get("status", "")))
        ],
        "empty": [record["path"] for record in records if record.get("status") == "empty"],
        "unknown": [record["path"] for record in records if record.get("status") == "unknown"],
    }


def is_blocked_input_status(status: str) -> bool:
    return status in {"blocked", "failed", "interrupted"} or status.startswith(("blocked", "skipped"))


def report_skip_status(
    spec: ReportSpec, env: dict[str, str], inputs: dict[str, list[Any]]
) -> tuple[str, str]:
    producer_status, producer_reason = full_matrix_producer_block(spec, env)
    if producer_status:
        return producer_status, producer_reason
    if inputs["blocked"]:
        return "blocked", "required generated input is blocked"
    if inputs["missing"] or inputs["empty"]:
        return "skipped_missing_input", "required input missing or empty"
    if inputs["stale"]:
        return "skipped_stale_input", "required generated input is stale"
    if inputs["unknown"]:
        return "blocked", "required input status is unknown"
    return "", ""


def skipped_spec_record(
    spec: ReportSpec, status: str, reason: str, input_paths: list[Path],
    output_paths: list[Path], inputs: dict[str, list[Any]], connector_root: Path,
    framework_root: Path, build_root: Path, started_at: str, started: float,
) -> dict[str, Any]:
    finished_at = utc_now()
    print(f"refresh-connector-reports: {status.upper()} {spec.name}: {reason}")
    write_placeholder_outputs(
        spec, status, reason, output_paths, connector_root, framework_root,
        finished_at, preserve_existing=True,
    )
    record = report_record(
        spec, status, input_paths, output_paths, connector_root, framework_root,
        build_root, inputs["missing"],
    )
    record.update(
        {
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_seconds": round(time.monotonic() - started, 3),
            "return_code": 0,
            "command": list(spec.command),
            "blocked_reason": reason,
            "blocked_inputs": inputs["blocked"],
        }
    )
    return record


def generated_spec_record(
    spec: ReportSpec, input_paths: list[Path], output_paths: list[Path],
    inputs: dict[str, list[Any]], connector_root: Path, framework_root: Path,
    build_root: Path, env: dict[str, str], started_at: str, started: float,
) -> dict[str, Any]:
    command_env = command_environment(spec, env)
    rc, _output, log_info = run_command(list(spec.command), connector_root, command_env)
    finished_at = utc_now()
    missing_outputs = [path for path in output_paths if not path.is_file()]
    status = generator_status(rc, missing_outputs)
    if status in {"failed", "blocked"}:
        reason = generator_failure_reason(rc)
        write_placeholder_outputs(spec, status, reason, output_paths, connector_root, framework_root, finished_at)
        missing_outputs = [path for path in output_paths if not path.is_file()]
    record = report_record(
        spec, status, input_paths, output_paths, connector_root, framework_root,
        build_root, inputs["missing"],
    )
    record.update(
        {
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_seconds": round(time.monotonic() - started, 3),
            "return_code": rc,
            "command": list(spec.command),
            "log_path": log_info.get("log_path"),
            "log_hash": log_info.get("log_hash") or log_info.get("output_sha256"),
            "output_sha256": log_info.get("output_sha256"),
        }
    )
    if missing_outputs:
        record["missing_outputs"] = [
            display_path(path, connector_root, framework_root, build_root)
            for path in missing_outputs
        ]
    return record


def command_environment(spec: ReportSpec, env: dict[str, str]) -> dict[str, str]:
    command_env = dict(env)
    if spec.name != "remaining_failure_analysis":
        command_env["SUPPRESS_FULL_RUN_EVIDENCE_SIDE_EFFECTS"] = "1"
    return command_env


def generator_status(return_code: int, missing_outputs: list[Path]) -> str:
    if return_code == 77:
        return "blocked"
    return "failed" if return_code != 0 or missing_outputs else "generated"


def generator_failure_reason(return_code: int) -> str:
    return f"generator returned {return_code}" if return_code != 0 else "generator did not produce all expected outputs"


def stale_runtime_raw_inputs(spec: ReportSpec, input_paths: list[Path], env: dict[str, str]) -> list[str]:
    if spec.name not in {"full_runtime_matrix", "native_mrts_reports"}:
        return []
    started_at = env.get("VERIFIED_RUN_STARTED_AT", "")
    if not started_at:
        return []
    try:
        start_ts = datetime.fromisoformat(started_at.replace("Z", UTC_OFFSET)).timestamp()
    except ValueError:
        return []
    stale: list[str] = []
    for path in input_paths:
        if not path.exists():
            continue
        try:
            if path.stat().st_mtime < start_ts:
                stale.append(portable_path_reference(path))
        except OSError:
            stale.append(portable_path_reference(path))
    return stale


def report_record(
    spec: ReportSpec,
    status: str,
    input_paths: list[Path],
    output_paths: list[Path],
    connector_root: Path,
    framework_root: Path,
    build_root: Path,
    missing_inputs: list[Path],
) -> dict[str, Any]:
    records = [input_record(raw, connector_root, framework_root, build_root) for raw in spec.inputs]
    missing = [record["path"] for record in records if record["status"] == "missing"]
    empty = [record["path"] for record in records if record["status"] == "empty"]
    unknown = [record["path"] for record in records if record["status"] == "unknown"]
    stale = [record["path"] for record in records if record["status"] == "stale"]
    blocked = [
        record["path"]
        for record in records
        if str(record.get("status", "")) in {"blocked", "failed", "interrupted"}
        or str(record.get("status", "")).startswith("blocked")
        or str(record.get("status", "")).startswith("skipped")
    ]
    primary_key = spec.name if spec.name in GENERATED_REPORTS else ""
    category = GENERATED_REPORTS[primary_key].category if primary_key else "mixed"
    kind = GENERATED_REPORTS[primary_key].kind if primary_key else "mixed"
    registry = registry_record(primary_key) if primary_key else {}
    freshness = freshness_status(status, input_paths, output_paths)
    if stale:
        freshness["freshness_status"] = "stale"
    return {
        "report_name": spec.name,
        "verified_run_id": current_verified_run_id(connector_root),
        "data_source_policy": DATA_SOURCE_POLICY,
        "category": category,
        "kind": kind,
        "path": ", ".join(display_path(path, connector_root, framework_root, build_root) for path in output_paths),
        "owner": spec.owner,
        "severity": registry.get("severity", "informational"),
        "data_origin": registry.get("data_origin", "connector"),
        "data_kind": registry.get("data_kind", kind),
        "commit_policy": registry.get("commit_policy", "versioned-generated"),
        "generator": spec.generator,
        "make_target": spec.make_target,
        "status": status,
        "input_status": input_status_summary(records),
        "inputs": records,
        "input_files": [record["path"] for record in records],
        "output_files": [display_path(path, connector_root, framework_root, build_root) for path in output_paths],
        "generated_at": next((generated_at_from_report(path) for path in output_paths if path.is_file()), "-"),
        "missing_inputs": missing,
        "empty_inputs": empty,
        "unknown_inputs": unknown,
        "stale_inputs": stale,
        "blocked_inputs": blocked,
        "missing_outputs": [],
        "input_fingerprint": combined_fingerprint(input_paths),
        "output_fingerprint": combined_fingerprint(output_paths),
        **freshness,
        "requires_runtime": spec.requires_runtime,
        "requires_native_mrts": spec.requires_native_mrts,
        "requires_full_matrix": spec.requires_full_matrix,
        "optional": spec.optional,
    }


def freshness_status(status: str, input_paths: list[Path], output_paths: list[Path]) -> dict[str, Any]:
    input_mtimes = [mtime for mtime in (path_mtime(path) for path in input_paths) if mtime is not None]
    output_mtimes = [mtime for mtime in (path_mtime(path) for path in output_paths) if mtime is not None]
    missing_inputs = [str(path) for path in input_paths if not path.exists()]
    missing_outputs = [str(path) for path in output_paths if not path.exists()]
    newest_input = max(input_mtimes) if input_mtimes else None
    newest_output = max(output_mtimes) if output_mtimes else None
    input_newer = bool(newest_input and newest_output and newest_input > newest_output)
    if status == "failed":
        freshness = "failed"
    elif status.startswith("skipped"):
        freshness = "skipped"
    elif missing_outputs:
        freshness = "missing-output"
    elif missing_inputs:
        freshness = "missing-input"
    elif input_newer:
        freshness = "input-newer-than-output"
    elif output_mtimes:
        freshness = "fresh"
    else:
        freshness = "unknown"
    return {
        "freshness_status": freshness,
        "oldest_input_mtime": iso_from_timestamp(min(input_mtimes) if input_mtimes else None),
        "newest_input_mtime": iso_from_timestamp(newest_input),
        "oldest_output_mtime": iso_from_timestamp(min(output_mtimes) if output_mtimes else None),
        "newest_output_mtime": iso_from_timestamp(newest_output),
        "input_newer_than_output": input_newer,
    }


def render_manifest_md(manifest: dict[str, Any]) -> str:
    lines = [
        "# Report Refresh Manifest",
        "",
        f"> Verified run id: `{manifest.get('verified_run_id', 'unknown')}`",
        f"> Data source policy: `{manifest.get('data_source_policy', DATA_SOURCE_POLICY)}`",
        "",
        "## Summary",
        f"- Connector SHA: `{manifest['connector_sha']}`",
        f"- Framework SHA: `{manifest['framework_sha']}`",
        f"- Framework submodule SHA: `{manifest['framework_submodule_sha']}`",
        f"- MRTS SHA: `{manifest['mrts_sha']}`",
        "",
        "## Inputs",
    ]
    for name, value in manifest["inputs"].items():
        lines.append(f"- `{name}`: `{value}`")
    lines.extend(
        [
            "",
            "## Verified Commands",
            "",
            "| Command | Status | Return Code | Duration | Log Hash | Notes |",
            "|---|---|---:|---:|---|---|",
        ]
    )
    commands = manifest.get("verified_commands", [])
    if commands:
        for command in commands:
            raw_command = command.get("command", "-")
            command_text = " ".join(raw_command) if isinstance(raw_command, list) else str(raw_command)
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{md(command_text)}`",
                        str(command.get("status", "unknown")),
                        str(command.get("return_code", "-")),
                        str(command.get("duration_seconds", "-")),
                        f"`{command.get('log_hash', 'unknown')}`",
                        md(command.get("notes") or command.get("summary") or "-"),
                    ]
                )
                + " |"
            )
    else:
        lines.append("| `-` | not_run | - | - | `unknown` | No verified command file was supplied. |")
    lines.extend(
        [
            "",
            "## Submodules",
            "| Name | Path | SHA | Branch | Dirty | Status |",
            "|---|---|---|---|---|---|",
        ]
    )
    for item in manifest.get("submodules", []):
        lines.append(
            "| "
            + " | ".join(
                [
                    str(item.get("name", "-")),
                    f"`{item.get('path', '-')}`",
                    f"`{item.get('sha', '-')}`",
                    f"`{item.get('branch', '-')}`",
                    str(item.get("dirty", "-")),
                    str(item.get("status", "-")),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Reports",
            "| Category | Owner | Severity | Report | Generator | Target | Status | Return code | Duration | Freshness | Outputs | Input status | Missing inputs | Missing outputs | Generated at |",
            "|---|---|---|---|---|---|---|---:|---:|---|---|---|---|---|---|",
        ]
    )
    for report in manifest["reports"]:
        missing = ", ".join(report.get("missing_inputs", [])) or "-"
        missing_outputs = ", ".join(report.get("missing_outputs", [])) or "-"
        outputs = "<br>".join(f"`{item}`" for item in report.get("output_files", [])) or "-"
        lines.append(
            "| "
            + " | ".join(
                [
                    report.get("category", "mixed"),
                    report.get("owner", "unknown"),
                    report.get("severity", "unknown"),
                    report["report_name"],
                    report["generator"],
                    report["make_target"],
                    report["status"],
                    str(report.get("return_code", "-")),
                    str(report.get("duration_seconds", "-")),
                    report.get("freshness_status", "unknown"),
                    outputs,
                    report.get("input_status", "unknown"),
                    missing,
                    missing_outputs,
                    report.get("generated_at", "-"),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def manifest_inputs(report_dir: Path) -> dict[str, str]:
    native_json = [
        report_path_from_root(report_dir, "mrts_native_full", "json"),
        report_path_from_root(report_dir, "mrts_native_apache", "json"),
        report_path_from_root(report_dir, "mrts_native_nginx", "json"),
        report_path_from_root(report_dir, "mrts_native_summary", "json"),
    ]
    return {
        "full_runtime_matrix": combined_fingerprint([report_path_from_root(report_dir, "full_runtime_matrix", "json")]),
        "native_mrts": combined_fingerprint(native_json),
        "build_cache": combined_fingerprint([report_path_from_root(report_dir, "runtime_build_cache", "json")]),
        "component_cache": combined_fingerprint([report_path_from_root(report_dir, "runtime_component_cache", "json")]),
    }


def md(value: Any) -> str:
    return str(value if value is not None else "-").replace("|", "\\|")


def submodule_rows(connector_root: Path, framework_root: Path, mrts_root: Path, sibling: Path) -> list[dict[str, str]]:
    return [
        {
            "name": "parent",
            "path": ".",
            "sha": git_sha(connector_root),
            "branch": git_branch(connector_root),
            "dirty": git_dirty_status(connector_root),
            "status": "present",
        },
        {
            "name": "framework_submodule",
            "path": FRAMEWORK_SUBMODULE_PATH,
            "sha": git_sha(framework_root),
            "branch": git_branch(framework_root),
            "dirty": git_dirty_status(framework_root),
            "status": "present" if framework_root.exists() else "not_found",
        },
        {
            "name": "mrts_submodule",
            "path": f"{FRAMEWORK_SUBMODULE_PATH}/tools/MRTS",
            "sha": git_sha(mrts_root),
            "branch": git_branch(mrts_root) if mrts_root.exists() else "not_found",
            "dirty": git_dirty_status(mrts_root) if mrts_root.exists() else "not_found",
            "status": "present" if mrts_root.exists() else "not_found",
        },
        {
            "name": "framework_sibling_checkout",
            "path": str(sibling),
            "sha": git_sha(sibling) if sibling.exists() else "not_found",
            "branch": git_branch(sibling) if sibling.exists() else "not_found",
            "dirty": git_dirty_status(sibling) if sibling.exists() else "not_found",
            "status": "present" if sibling.exists() else "not_found",
        },
    ]


def apply_expected_submodule_shas(rows: list[dict[str, str]], expected: str) -> None:
    for row in rows:
        row["expected"] = "-"
    for line in expected.splitlines():
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        if parts[1] == FRAMEWORK_SUBMODULE_PATH:
            rows[1]["expected"] = parts[0].lstrip("+-")
        if len(parts) >= 2 and parts[1] == f"{FRAMEWORK_SUBMODULE_PATH}/tools/MRTS":
            rows[2]["expected"] = parts[0].lstrip("+-")


def mark_sibling_difference(rows: list[dict[str, str]], sibling: Path) -> None:
    if sibling.exists() and rows[1]["sha"] != rows[3]["sha"]:
        rows[3]["status"] = "differs"


def submodule_report(connector_root: Path, framework_root: Path) -> list[dict[str, str]]:
    sibling = framework_root
    mrts_root = framework_root / "tools/MRTS"
    rows = submodule_rows(connector_root, framework_root, mrts_root, sibling)
    expected = git_output(["submodule", "status", "--recursive"], connector_root)
    apply_expected_submodule_shas(rows, expected)
    mark_sibling_difference(rows, sibling)
    return rows


def render_freshness_md(payload: dict[str, Any]) -> str:
    lines = [
        "# Report Freshness",
        "",
        "| Report | Status | Generated At | Newest Input | Newest Output | Missing Inputs | Notes |",
        "|---|---|---|---|---|---|---|",
    ]
    for report in payload["reports"]:
        missing = ", ".join(report.get("missing_inputs", [])) or "-"
        notes = report.get("notes") or report.get("status", "-")
        lines.append(
            f"| `{report['report_name']}` | {report.get('freshness_status', 'unknown')} | "
            f"{report.get('generated_at', '-')} | {report.get('newest_input_mtime', '-')} | "
            f"{report.get('newest_output_mtime', '-')} | {md(missing)} | {md(notes)} |"
        )
    return "\n".join(lines) + "\n"


def build_governance_record(
    key: str,
    connector_root: Path,
    framework_root: Path,
    build_root: Path,
    generated_at: str,
    inputs: tuple[str, ...] = (),
) -> dict[str, Any]:
    report = GENERATED_REPORTS[key]
    outputs = [report_path(connector_root, key, ext) for ext in report.formats]
    input_paths = [resolve_input(raw, connector_root, framework_root, build_root) for raw in inputs]
    input_records = [input_record(raw, connector_root, framework_root, build_root) for raw in inputs]
    input_status = input_status_summary(input_records)
    input_fingerprint = combined_fingerprint(input_paths)
    if key == "report_refresh_manifest" and not inputs:
        input_status = "self_generated_no_direct_input"
        input_fingerprint = "self_generated_no_direct_input"
    record = {
        "report_name": key,
        "verified_run_id": current_verified_run_id(connector_root),
        "data_source_policy": DATA_SOURCE_POLICY,
        "category": report.category,
        "kind": report.kind,
        "path": ", ".join(display_path(path, connector_root, framework_root, build_root) for path in outputs),
        "owner": report.owner,
        "severity": report.severity,
        "data_origin": report.data_origin,
        "data_kind": report.data_kind,
        "commit_policy": report.commit_policy,
        "generator": report.generator,
        "make_target": report.make_target,
        "status": "generated" if all(path.is_file() for path in outputs) else "missing-output",
        "input_status": input_status,
        "inputs": input_records,
        "input_files": [record["path"] for record in input_records],
        "output_files": [display_path(path, connector_root, framework_root, build_root) for path in outputs],
        "generated_at": generated_at,
        "missing_inputs": [display_path(path, connector_root, framework_root, build_root) for path in input_paths if not path.exists()],
        "empty_inputs": [record["path"] for record in input_records if record.get("status") == "empty"],
        "unknown_inputs": [record["path"] for record in input_records if record.get("status") == "unknown"],
        "stale_inputs": [record["path"] for record in input_records if record.get("status") == "stale"],
        "missing_outputs": [display_path(path, connector_root, framework_root, build_root) for path in outputs if not path.exists()],
        "input_fingerprint": input_fingerprint,
        "output_fingerprint": combined_fingerprint(outputs),
        "started_at": generated_at,
        "finished_at": generated_at,
        "duration_seconds": 0.0,
        "return_code": 0,
        "command": ["internal", report.generator],
        "requires_runtime": report.requires_runtime,
        "requires_native_mrts": report.requires_native_mrts,
        "requires_full_matrix": report.requires_full_matrix,
        "optional": report.optional,
    }
    record.update(freshness_status(record["status"], input_paths, outputs))
    return record


def dashboard_sources(connector_root: Path) -> dict[str, dict[str, Any]]:
    return {
        key: read_json(report_path(connector_root, key, "json"))
        for key in (
            "full_runtime_matrix",
            "final_consistency_audit",
            "next_fix_plan",
            "system_environment_proof",
            "verified_runtime_mismatch_analysis",
            "full_matrix_job_completeness",
            "nginx_mrts_http500_cluster_analysis",
        )
    }


def dashboard_report_groups(
    reports: list[dict[str, Any]], freshness: dict[str, Any], submodules: list[dict[str, str]]
) -> dict[str, list[dict[str, Any]]]:
    is_skipped = lambda report: str(report.get("status", "")).startswith("skipped")
    stale_statuses = {"stale", "input-newer-than-output", "missing-output", "missing-input"}
    return {
        "failed": [report for report in reports if report.get("status") == "failed" and not report.get("optional")],
        "optional_failed": [report for report in reports if report.get("status") == "failed" and report.get("optional")],
        "skipped": [report for report in reports if is_skipped(report) and not report.get("optional")],
        "optional_skipped": [report for report in reports if is_skipped(report) and report.get("optional")],
        "optional_blocked": [report for report in reports if report.get("status") == "blocked" and report.get("optional")],
        "stale": [report for report in freshness.get("reports", []) if report.get("freshness_status") in stale_statuses],
        "dirty": [item for item in submodules if item.get("dirty") == "dirty" or item.get("status") == "differs"],
    }


def dashboard_critical_groups(reports: list[dict[str, Any]], verified_run_id: str) -> dict[str, list[dict[str, Any]] | list[str]]:
    stale_statuses = {"stale", "input-newer-than-output", "missing-output", "missing-input"}
    unacceptable_inputs = {"stale", "blocked", "missing", "partial", "unknown"}
    critical = [report for report in reports if report.get("severity") == "critical" and not report.get("optional")]
    return {
        "missing": [report for report in critical if report.get("status") != "generated"],
        "stale": [
            report
            for report in critical
            if report.get("freshness_status") in stale_statuses
            or report.get("input_status") in unacceptable_inputs
            or report.get("stale_inputs")
        ],
        "run_mismatches": [
            str(report.get("report_name") or "unknown")
            for report in critical
            if str(report.get("verified_run_id") or "") not in {"", verified_run_id}
        ],
        "producer_not_run": [
            report for report in critical if report.get("requires_full_matrix") and report.get("status") != "generated"
        ],
    }


def metadata_verified_run_ids(sources: dict[str, dict[str, Any]]) -> dict[str, Any]:
    required = (
        "full_runtime_matrix",
        "final_consistency_audit",
        "system_environment_proof",
        "verified_runtime_mismatch_analysis",
    )
    return {
        key: (sources[key].get("metadata") if isinstance(sources[key].get("metadata"), dict) else {}).get("verified_run_id")
        for key in required
    }


def refresh_timed_out(manifest: dict[str, Any]) -> bool:
    commands = manifest.get("verified_commands") if isinstance(manifest.get("verified_commands"), list) else []
    return any(
        command.get("refresh_status") == "refresh_timeout"
        or command.get("overall_status") == "blocked_refresh_timeout"
        or (
            command.get("logical_target") in {"refresh-all-reports", "generate-system-environment-proof"}
            and command.get("classification") == "blocked_timeout"
        )
        for command in commands
        if isinstance(command, dict)
    )


def dashboard_matrix_state(
    mismatch_analysis: dict[str, Any], job_completeness: dict[str, Any], refresh_timeout: bool
) -> dict[str, Any]:
    matrix = mismatch_analysis.get("full_matrix") if isinstance(mismatch_analysis.get("full_matrix"), dict) else {}
    missing_jobs = matrix.get("missing_jobs")
    if not isinstance(missing_jobs, list):
        missing_jobs = job_completeness.get("missing_job_ids")
    return {
        "complete": bool(matrix.get("complete")),
        "timeout": bool(matrix.get("timeout")),
        "completed_jobs": int(matrix.get("completed_jobs") or job_completeness.get("complete_jobs") or 0),
        "expected_jobs": int(matrix.get("expected_jobs") or job_completeness.get("total_jobs") or 0),
        "missing_jobs": missing_jobs if isinstance(missing_jobs, list) else [],
        "refresh_timeout": bool(matrix.get("refresh_timeout")) or refresh_timeout,
    }


def dashboard_primary_blocker(
    nginx_http500: dict[str, Any],
    matrix: dict[str, Any],
    critical_mismatch_count: int,
    next_plan: dict[str, Any],
    final_audit: dict[str, Any],
) -> str:
    primary_blocker = str(nginx_http500.get("primary_blocker") or "")
    if primary_blocker == "none":
        primary_blocker = ""
    if not primary_blocker and matrix["complete"] and critical_mismatch_count > 0:
        return str(
            next_plan.get("recommendation", {}).get("recommended_next_fix_cluster")
            or final_audit.get("recommended_next_fix_cluster", {}).get("value", "unknown")
        )
    return primary_blocker


def merge_readiness(
    groups: dict[str, list[dict[str, Any]]],
    critical: dict[str, list[dict[str, Any]] | list[str]],
    matrix: dict[str, Any],
    *,
    metadata_run_mismatches: list[str],
    final_audit: dict[str, Any],
    mismatch_analysis: dict[str, Any],
) -> tuple[str, str]:
    critical_mismatch_count = int(mismatch_analysis.get("critical_mismatch_count") or 0)
    evidence_scope = str(mismatch_analysis.get("evidence_scope") or "")
    smoke_only = evidence_scope == "smoke-only"
    full_matrix_incomplete = bool(mismatch_analysis) and (smoke_only or not matrix["complete"])
    core_ok = all(
        (
            not groups["failed"],
            not groups["skipped"],
            not groups["stale"],
            not groups["dirty"],
            not critical["missing"],
            not critical["stale"],
            not critical["run_mismatches"],
            not metadata_run_mismatches,
            critical_mismatch_count == 0,
            final_audit.get("release_readiness") in {"ready", "ready_with_known_reported_gaps"},
        )
    )
    warning_conditions = any(
        (
            groups["skipped"],
            groups["optional_failed"],
            groups["optional_skipped"],
            groups["optional_blocked"],
            groups["stale"],
            groups["dirty"],
            critical["missing"],
            critical["stale"],
            critical["run_mismatches"],
            metadata_run_mismatches,
        )
    )
    if full_matrix_incomplete:
        readiness = "UNKNOWN"
    elif groups["failed"] or (matrix["complete"] and critical_mismatch_count > 0):
        readiness = "FAIL"
    elif critical["producer_not_run"]:
        readiness = "UNKNOWN"
    elif warning_conditions:
        readiness = "WARN"
    elif core_ok:
        readiness = "PASS"
    else:
        readiness = "UNKNOWN"
    return readiness, merge_readiness_reason(
        readiness,
        groups,
        critical,
        matrix,
        critical_mismatch_count=critical_mismatch_count,
        smoke_only=smoke_only,
        full_matrix_incomplete=full_matrix_incomplete,
    )


def merge_readiness_reason(
    readiness: str,
    groups: dict[str, list[dict[str, Any]]],
    critical: dict[str, list[dict[str, Any]] | list[str]],
    matrix: dict[str, Any],
    *,
    critical_mismatch_count: int,
    smoke_only: bool,
    full_matrix_incomplete: bool,
) -> str:
    if smoke_only:
        return "Smoke-only evidence is not a full verified matrix run; merge readiness remains UNKNOWN."
    if full_matrix_incomplete:
        missing = ", ".join(str(item) for item in matrix["missing_jobs"]) or "unknown"
        return f"Full-Matrix evidence is incomplete; {matrix['completed_jobs']}/{matrix['expected_jobs']} jobs complete; missing jobs: {missing}."
    critical_reason = critical_mismatch_reason(groups, critical, matrix, critical_mismatch_count)
    if critical_reason:
        return critical_reason
    if readiness == "UNKNOWN":
        return "Critical producer evidence was not generated in this verified run."
    if groups["optional_failed"] or groups["optional_skipped"] or groups["optional_blocked"]:
        return "Optional producer evidence is unavailable; required critical inputs are tracked separately."
    if readiness == "WARN":
        return "Core canonical reports are generated; warning conditions are documented."
    if readiness == "PASS":
        return "Core canonical reports are generated and no warning conditions were found."
    return "Merge readiness could not be determined from available reports."


def critical_mismatch_reason(
    groups: dict[str, list[dict[str, Any]]],
    critical: dict[str, list[dict[str, Any]] | list[str]],
    matrix: dict[str, Any],
    critical_mismatch_count: int,
) -> str | None:
    if groups["failed"]:
        return "Failed generator records block merge readiness."
    if not matrix["complete"] or critical_mismatch_count == 0:
        return None
    if matrix["refresh_timeout"]:
        return "Full-Matrix runtime completed with critical mismatches; downstream report refresh timed out."
    if groups["stale"] or critical["stale"]:
        return "Full-Matrix runtime completed with critical mismatches; downstream reports remain blocked, stale, or unknown."
    return "Full-Matrix completed and critical runtime mismatches are present."


def merge_dashboard_payload(manifest: dict[str, Any], freshness: dict[str, Any], submodules: list[dict[str, str]], connector_root: Path) -> dict[str, Any]:
    sources = dashboard_sources(connector_root)
    reports = manifest.get("reports", [])
    groups = dashboard_report_groups(reports, freshness, submodules)
    verified_run_id = str(manifest.get("verified_run_id") or current_verified_run_id(connector_root))
    critical = dashboard_critical_groups(reports, verified_run_id)
    metadata_ids = metadata_verified_run_ids(sources)
    metadata_run_mismatches = [name for name, run_id in metadata_ids.items() if run_id != verified_run_id]
    mismatch_analysis = sources["verified_runtime_mismatch_analysis"]
    matrix = dashboard_matrix_state(
        mismatch_analysis,
        sources["full_matrix_job_completeness"],
        refresh_timed_out(manifest),
    )
    critical_mismatch_count = int(mismatch_analysis.get("critical_mismatch_count") or 0)
    primary_blocker = dashboard_primary_blocker(
        sources["nginx_mrts_http500_cluster_analysis"],
        matrix,
        critical_mismatch_count,
        sources["next_fix_plan"],
        sources["final_consistency_audit"],
    )
    readiness, reason = merge_readiness(
        groups,
        critical,
        matrix,
        metadata_run_mismatches=metadata_run_mismatches,
        final_audit=sources["final_consistency_audit"],
        mismatch_analysis=mismatch_analysis,
    )
    full_matrix = sources["full_runtime_matrix"]
    final_audit = sources["final_consistency_audit"]
    next_plan = sources["next_fix_plan"]
    mismatch_count = int(mismatch_analysis.get("mismatch_count") or 0)
    return {
        "status": readiness,
        "verified_run_id": verified_run_id,
        "data_source_policy": DATA_SOURCE_POLICY,
        "generated_at": manifest.get("generated_at"),
        "connector_sha": manifest.get("connector_sha"),
        "framework_sha": manifest.get("framework_sha"),
        "full_matrix_totals": full_matrix.get("totals", {}),
        "full_matrix_complete": matrix["complete"],
        "full_matrix_completed_jobs": matrix["completed_jobs"],
        "full_matrix_expected_jobs": matrix["expected_jobs"],
        "full_matrix_missing_jobs": matrix["missing_jobs"],
        "full_matrix_timeout": matrix["timeout"],
        "full_matrix_refresh_timeout": matrix["refresh_timeout"],
        "evidence_scope": str(mismatch_analysis.get("evidence_scope") or "unknown"),
        "runtime_mismatch_count": mismatch_count,
        "critical_runtime_mismatch_count": critical_mismatch_count,
        "runtime_mismatch_categories": mismatch_analysis.get("by_classification", {}) if isinstance(mismatch_analysis.get("by_classification"), dict) else {},
        "final_consistency_status": final_audit.get("release_readiness", "unknown"),
        "primary_blocker": primary_blocker or "unknown",
        "recommended_next_fix_cluster": next_plan.get("recommendation", {}).get("recommended_next_fix_cluster")
        or final_audit.get("recommended_next_fix_cluster", {}).get("value", "unknown"),
        "failed_reports": [report.get("report_name") for report in groups["failed"]],
        "skipped_reports": [report.get("report_name") for report in groups["skipped"]],
        "optional_failed_reports": [report.get("report_name") for report in groups["optional_failed"]],
        "optional_skipped_reports": [report.get("report_name") for report in groups["optional_skipped"]],
        "optional_blocked_reports": [report.get("report_name") for report in groups["optional_blocked"]],
        "stale_reports": [report.get("report_name") for report in groups["stale"]],
        "critical_missing_reports": [report.get("report_name") for report in critical["missing"]],
        "critical_stale_reports": [report.get("report_name") for report in critical["stale"]],
        "critical_run_mismatches": critical["run_mismatches"],
        "metadata_run_mismatches": metadata_run_mismatches,
        "metadata_verified_run_ids": metadata_ids,
        "critical_producer_not_run": [report.get("report_name") for report in critical["producer_not_run"]],
        "dirty_submodules": groups["dirty"],
        "submodules": submodules,
        "reason": reason,
    }


def dashboard_runtime_mismatch_status(payload: dict[str, Any]) -> str:
    if not payload.get("full_matrix_complete"):
        return "UNKNOWN"
    return "FAIL" if payload.get("critical_runtime_mismatch_count") else "PASS"


def full_matrix_dashboard_check(payload: dict[str, Any], totals: dict[str, Any]) -> tuple[str, str, str]:
    return (
        "Full Runtime Matrix",
        "PASS" if payload.get("full_matrix_complete") else "UNKNOWN",
        f"complete={payload.get('full_matrix_complete', False)} jobs={payload.get('full_matrix_completed_jobs', 0)}/{payload.get('full_matrix_expected_jobs', 0)} missing={payload.get('full_matrix_missing_jobs', [])} runtime_timeout={payload.get('full_matrix_timeout', False)} refresh_timeout={payload.get('full_matrix_refresh_timeout', False)} PASS={totals.get('pass', '-')} FAIL={totals.get('fail', '-')} BLOCKED={totals.get('blocked', '-')}",
    )


def runtime_mismatch_dashboard_check(payload: dict[str, Any]) -> tuple[str, str, str]:
    return (
        "Runtime Mismatch Analysis",
        dashboard_runtime_mismatch_status(payload),
        f"mismatches={payload.get('runtime_mismatch_count', 0)} critical={payload.get('critical_runtime_mismatch_count', 0)} categories={payload.get('runtime_mismatch_categories', {})}",
    )


def dashboard_report_availability_checks(payload: dict[str, Any]) -> list[tuple[str, str, str]]:
    optional_evidence = payload.get("optional_failed_reports") or payload.get("optional_skipped_reports") or payload.get("optional_blocked_reports")
    return [
        ("Final Consistency Audit", "PASS" if payload.get("final_consistency_status") else "UNKNOWN", payload.get("final_consistency_status", "unknown")),
        ("Missing Inputs / Skipped Reports", "WARN" if payload.get("skipped_reports") else "PASS", ", ".join(payload.get("skipped_reports", [])) or "none"),
        ("Optional Producer Evidence", "WARN" if optional_evidence else "PASS", ", ".join(payload.get("optional_failed_reports", []) + payload.get("optional_skipped_reports", []) + payload.get("optional_blocked_reports", [])) or "available/not required"),
        ("Stale Reports", "WARN" if payload.get("stale_reports") else "PASS", ", ".join(payload.get("stale_reports", [])) or "none"),
        ("Report Refresh", "WARN" if payload.get("full_matrix_refresh_timeout") else "PASS", "refresh timeout after runtime completed" if payload.get("full_matrix_refresh_timeout") else "completed/no timeout recorded"),
    ]


def dashboard_control_checks(payload: dict[str, Any]) -> list[tuple[str, str, str]]:
    run_mismatches = payload.get("critical_run_mismatches") or payload.get("metadata_run_mismatches")
    return [
        ("Critical Input Freshness", "WARN" if payload.get("critical_stale_reports") else "PASS", ", ".join(payload.get("critical_stale_reports", [])) or "fresh"),
        ("Verified Run Consistency", "WARN" if run_mismatches else "PASS", ", ".join(payload.get("critical_run_mismatches", []) + payload.get("metadata_run_mismatches", [])) or "consistent"),
        ("Failed Generators", "FAIL" if payload.get("failed_reports") else "PASS", ", ".join(payload.get("failed_reports", [])) or "none"),
        ("Submodule Status", "WARN" if payload.get("dirty_submodules") else "PASS", ", ".join(item.get("name", "-") for item in payload.get("dirty_submodules", [])) or "clean/no mismatch"),
    ]


def merge_dashboard_checks(payload: dict[str, Any], totals: dict[str, Any]) -> list[tuple[str, str, str]]:
    return [
        full_matrix_dashboard_check(payload, totals),
        runtime_mismatch_dashboard_check(payload),
        *dashboard_report_availability_checks(payload),
        *dashboard_control_checks(payload),
    ]


def dashboard_evidence_lines(payload: dict[str, Any], totals: dict[str, Any]) -> list[str]:
    return [
        f"- Verified run id: `{payload.get('verified_run_id', 'unknown')}`",
        f"- Connector SHA: `{payload.get('connector_sha', 'unknown')}`",
        f"- Framework SHA: `{payload.get('framework_sha', 'unknown')}`",
        f"- Primary blocker: `{payload.get('primary_blocker', 'unknown')}`",
        f"- Recommended next fix cluster: `{payload.get('recommended_next_fix_cluster', 'unknown')}`",
        f"- Evidence scope: `{payload.get('evidence_scope', 'unknown')}`",
        f"- Full-Matrix complete: `{payload.get('full_matrix_complete', False)}`",
        f"- Full-Matrix completeness: `{payload.get('full_matrix_completed_jobs', 0)}` / `{payload.get('full_matrix_expected_jobs', 0)}`",
        f"- Missing Full-Matrix jobs: `{', '.join(str(item) for item in payload.get('full_matrix_missing_jobs', [])) or '-'}`",
        f"- Full-Matrix refresh timeout: `{payload.get('full_matrix_refresh_timeout', False)}`",
        f"- Runtime mismatches / critical: `{payload.get('runtime_mismatch_count', 0)}` / `{payload.get('critical_runtime_mismatch_count', 0)}`",
        f"- Full-Matrix PASS/FAIL/BLOCKED/NOT_EXECUTABLE: `{totals.get('pass', '-')}` / `{totals.get('fail', '-')}` / `{totals.get('blocked', '-')}` / `{totals.get('not_executable', '-')}`",
    ]


def dashboard_submodule_rows(submodules: list[dict[str, Any]]) -> list[str]:
    return [
        f"| {item.get('name', '-')} | `{item.get('path', '-')}` | `{item.get('sha', '-')}` | `{item.get('branch', '-')}` | {item.get('dirty', '-')} | {item.get('status', '-')} |"
        for item in submodules
    ]


def render_merge_dashboard_md(payload: dict[str, Any]) -> str:
    totals = payload.get("full_matrix_totals", {})
    checks = merge_dashboard_checks(payload, totals)
    lines = [
        "# Merge Readiness Dashboard",
        "",
        f"Merge Readiness: `{payload.get('status', 'UNKNOWN')}`",
        "",
        "## Summary",
        "",
        "| Check | Status | Notes |",
        "|---|---|---|",
    ]
    for name, status, notes in checks:
        lines.append(f"| {name} | {status} | {md(notes)} |")
    lines.extend(
        [
            "",
            "## Decision",
            "",
            f"Merge readiness: `{payload.get('status', 'UNKNOWN')}`",
            "",
            f"Reason: {payload.get('reason', 'unknown')}",
            "",
            "## Evidence",
            "",
        ]
    )
    lines.extend(dashboard_evidence_lines(payload, totals))
    lines.extend(["", "## Submodules", "", "| Name | Path | SHA | Branch | Dirty | Status |", "|---|---|---|---|---|---|"])
    lines.extend(dashboard_submodule_rows(payload.get("submodules", [])))
    return "\n".join(lines) + "\n"


def report_record_for_output(manifest: dict[str, Any], output_path: str) -> dict[str, Any]:
    for report in manifest.get("reports", []):
        if output_path in report.get("output_files", []):
            return report
    return {}


def report_index_text(german: bool) -> dict[str, str]:
    if german:
        return {
            "title": "# Testberichte",
            "language": "**Sprache:** [English](README.md) | Deutsch",
            "intro": "Dieser Index wird mit `make refresh-connector-reports` aktualisiert. Generierte Berichte liegen unter",
            "notice": "`reports/testing/generated/<category>/`; generierte Berichtsdateien nicht manuell bearbeiten.",
            "phases": "## Phasen des verifizierten Laufs",
            "phase_intro": "Runtime-erzeugende Befehle und die Berichtserneuerung sind absichtlich getrennt. Runtime-Evidence bleibt gültig,",
            "phase_explanation": "wenn eine spätere Berichtserneuerung abläuft oder nachgelagerte fokussierte Berichte stale sind.",
            "long_runs": "Für lange Full-Matrix-Läufe:",
            "compatibility": "Kompatibilität: `VERIFIED_RUN_FULL_MATRIX_TIMEOUT_SECONDS` wird weiterhin als Alias für",
            "compatibility_target": "`VERIFIED_RUN_FULL_MATRIX_RUNTIME_TIMEOUT_SECONDS` akzeptiert.",
            "index": "## Index der generierten Berichte",
            "columns": "| Kategorie | Owner | Schweregrad | Berichtsdatei | Zweck | Generator | Make-Ziel | Eingaben | Ausgabepfad | Zuletzt generiert | Art |",
            "migration": "## Migrationshinweise",
            "flat_layout": "- Das bisherige flache `reports/testing/generated/*.generated.*`-Layout ist veraltet.",
            "category_paths": "- Generatorcode schreibt Kategoriepfade direkt; die Aktualisierung entfernt veraltete flach generierte Berichtsdateien.",
            "runtime_caches": "- Runtime-Caches und native MRTS-Nachweise werden durch ihre Generatorziele neu erzeugt, wenn lokale Eingaben verfügbar sind.",
        }
    return {
        "title": "# Testing Reports",
        "language": "**Language:** English | [Deutsch](README.de.md)",
        "intro": "This index is refreshed by `make refresh-connector-reports`. Generated reports live under",
        "notice": "`reports/testing/generated/<category>/`; do not edit generated report files manually.",
        "phases": "## Verified Run Phases",
        "phase_intro": "Runtime-producing commands and report refresh are intentionally separated. Runtime evidence remains valid",
        "phase_explanation": "when a later report refresh times out or downstream focused reports are stale.",
        "long_runs": "For long full-matrix runs:",
        "compatibility": "Compatibility: `VERIFIED_RUN_FULL_MATRIX_TIMEOUT_SECONDS` is still accepted as an alias for",
        "compatibility_target": "`VERIFIED_RUN_FULL_MATRIX_RUNTIME_TIMEOUT_SECONDS`.",
        "index": "## Generated Report Index",
        "columns": "| Category | Owner | Severity | Report file | Purpose | Generator | Make target | Inputs | Output path | Last generated | Kind |",
        "migration": "## Migration Notes",
        "flat_layout": "- The previous flat `reports/testing/generated/*.generated.*` layout is deprecated.",
        "category_paths": "- Generator code writes category paths directly; refresh removes stale flat generated report files.",
        "runtime_caches": "- Runtime caches and native MRTS evidence are regenerated by their generator targets when local inputs are available.",
    }


def report_index_header(text: dict[str, str]) -> list[str]:
    return [
        text["title"],
        "",
        text["language"],
        "",
        text["intro"],
        text["notice"],
        "",
        text["phases"],
        "",
        text["phase_intro"],
        text["phase_explanation"],
        "",
        "```sh",
        "make verified-runtime-producers",
        "make verified-report-refresh",
        "make verified-report-checks",
        "```",
        "",
        text["long_runs"],
        "",
        "```sh",
        "export VERIFIED_RUN_FULL_MATRIX_RUNTIME_TIMEOUT_SECONDS=7200",
        "export VERIFIED_RUN_REPORT_REFRESH_TIMEOUT_SECONDS=1800",
        "make verified-report-run",
        "```",
        "",
        text["compatibility"],
        text["compatibility_target"],
        "",
        text["index"],
        "",
        text["columns"],
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]


def report_index_link_path(
    output_path: str, *, german: bool, connector_root: Path | None
) -> str:
    if not german or not output_path.endswith(".md") or connector_root is None:
        return output_path
    companion = output_path.removesuffix(".md") + GERMAN_MARKDOWN_SUFFIX
    return companion if (connector_root / companion).is_file() else output_path


def report_index_row(
    key: str,
    report: Any,
    ext: str,
    manifest: dict[str, Any],
    *,
    german: bool,
    connector_root: Path | None,
) -> str:
    output_path = report_relpath(key, ext)
    record = report_record_for_output(manifest, output_path)
    inputs = "<br>".join(
        f"`{portable_path_reference(item)}`" for item in record.get("input_files", report.inputs)
    ) or "`-`"
    link_path = report_index_link_path(output_path, german=german, connector_root=connector_root)
    link = link_path.removeprefix("reports/testing/")
    return "| " + " | ".join(
        [
            report.category,
            report.owner,
            report.severity,
            f"[{Path(link_path).name}](./{link})",
            report.purpose.replace("|", "\\|"),
            report.generator,
            report.make_target,
            inputs,
            f"`{output_path}`",
            record.get("generated_at", "-") if record else "-",
            report.kind,
        ]
    ) + " |"


def report_index_rows(manifest: dict[str, Any], *, german: bool, connector_root: Path | None) -> list[str]:
    rows: list[str] = []
    for key, report in sorted(GENERATED_REPORTS.items(), key=lambda item: (item[1].category, item[1].stem)):
        rows.extend(
            report_index_row(
                key,
                report,
                ext,
                manifest,
                german=german,
                connector_root=connector_root,
            )
            for ext in report.formats
        )
    return rows


def report_index_migration_notes(text: dict[str, str]) -> list[str]:
    return [
        "",
        text["migration"],
        "",
        text["flat_layout"],
        text["category_paths"],
        text["runtime_caches"],
    ]


def render_report_index_md(
    manifest: dict[str, Any], *, german: bool = False, connector_root: Path | None = None
) -> str:
    """Render the bilingual index from manifest records without local paths."""
    text = report_index_text(german)
    lines = report_index_header(text)
    lines.extend(report_index_rows(manifest, german=german, connector_root=connector_root))
    lines.extend(report_index_migration_notes(text))
    return "\n".join(lines) + "\n"


def cleanup_legacy_flat_reports(connector_root: Path) -> list[str]:
    removed: list[str] = []
    report_dir = connector_root / REPORT_DIR
    for filename in sorted(FILENAME_TO_KEY):
        path = report_dir / filename
        if not path.is_file():
            continue
        path.unlink()
        removed.append(str(path.relative_to(connector_root)))
    return removed


def refresh_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector-root", default=".")
    parser.add_argument("--framework-root", default=None)
    parser.add_argument("--build-root", default=os.environ.get("BUILD_ROOT"))
    parser.add_argument("--native-root", default=os.environ.get("MRTS_NATIVE_ROOT"))
    parser.add_argument("--strict-inputs", action="store_true")
    parser.add_argument("--profile", choices=("full", "bounded-smoke"), default="full")
    parser.add_argument("--begin-bounded-smoke", action="store_true")
    parser.add_argument("--variant", choices=("no-crs", "with-crs"))
    parser.add_argument(
        "--render-index-only",
        action="store_true",
        help="Re-render the bilingual index and prune retired catalog records without running generators.",
    )
    return parser.parse_args()



def refresh_roots(args: argparse.Namespace) -> tuple[Path, Path, Path, Path, Path]:
    connector_root = Path(args.connector_root).resolve()
    framework_root = Path(args.framework_root).resolve() if args.framework_root else connector_root / FRAMEWORK_SUBMODULE_PATH
    from modsecurity_connector_ci.lib.runtime_path_utils import verified_runtime_paths

    default_paths = verified_runtime_paths(os.environ)
    build_root = Path(args.build_root or default_paths["BUILD_ROOT"])
    native_root = Path(args.native_root or build_root / "mrts-native")
    if args.profile == "bounded-smoke":
        build_root = build_root.absolute()
        native_root = native_root.absolute()
    else:
        build_root = build_root.resolve()
        native_root = native_root.resolve()
    report_dir = connector_root / REPORT_DIR
    add_safe_roots(connector_root, framework_root, build_root, native_root, report_dir)
    add_report_roots(report_dir)
    return connector_root, framework_root, build_root, native_root, report_dir


def render_index_only(connector_root: Path) -> int:
    manifest_path = report_path(connector_root, "report_refresh_manifest", "json")
    manifest = read_json(manifest_path)
    if not manifest.get("reports"):
        raise SystemExit(f"cannot render report index without manifest reports: {manifest_path}")
    if prune_retired_report_records(manifest):
        metadata = manifest.pop("metadata", {})
        if not isinstance(metadata, dict):
            raise SystemExit(f"cannot preserve metadata while pruning {manifest_path}")
        write_text_file(manifest_path, generated_json_text(manifest, metadata))
        manifest_md_path = report_path(connector_root, "report_refresh_manifest", "md")
        write_text_file(manifest_md_path, generated_markdown_text(render_manifest_md(manifest), metadata))
        prune_retired_markdown_rows(
            manifest_md_path.with_name(manifest_md_path.name.removesuffix(".md") + GERMAN_MARKDOWN_SUFFIX)
        )
    prune_retired_freshness_report(connector_root)
    index_root = connector_root / "reports/testing"
    write_text_file(index_root / "README.md", render_report_index_md(manifest, connector_root=connector_root))
    write_text_file(index_root / "README.de.md", render_report_index_md(manifest, german=True, connector_root=connector_root))
    print(f"refresh-connector-reports: rendered indexes from {manifest_path}")
    return 0


def refresh_environment(
    connector_root: Path, framework_root: Path, build_root: Path, native_root: Path
) -> tuple[str, dict[str, str]]:
    verified_run_id = current_verified_run_id(connector_root)
    os.environ.setdefault("VERIFIED_RUN_ID", verified_run_id)
    env = dict(os.environ)
    env.update(
        {
            "PYTHONDONTWRITEBYTECODE": env.get("PYTHONDONTWRITEBYTECODE", "1"),
            "FRAMEWORK_ROOT": str(framework_root),
            "CONNECTOR_ROOT": str(connector_root),
            "BUILD_ROOT": str(build_root),
            "MRTS_NATIVE_ROOT": str(native_root),
            "VERIFIED_RUN_ID": verified_run_id,
        }
    )
    return verified_run_id, env


def report_outputs(records: list[dict[str, Any]], exclude: set[str] | None = None) -> tuple[str, ...]:
    excluded = exclude or set()
    return tuple(
        output
        for record in records
        if str(record.get("report_name") or "") not in excluded
        for output in record.get("output_files", [])
    )


def governance_record_with_outputs(
    key: str,
    payload: dict[str, Any],
    markdown: str,
    *,
    connector_root: Path,
    framework_root: Path,
    build_root: Path,
    generated_at: str,
    inputs: tuple[str, ...] = (),
) -> dict[str, Any]:
    metadata = build_metadata(
        generated_by=GENERATED_REPORTS[key].generator,
        make_target=GENERATED_REPORTS[key].make_target,
        connector_root=connector_root,
        framework_root=framework_root,
        inputs=inputs,
        generated_at=generated_at,
        report_key=key,
    )
    report = GENERATED_REPORTS[key]
    if "json" in report.formats:
        write_text_file(report_path(connector_root, key, "json"), generated_json_text(payload, metadata))
    if "md" in report.formats:
        write_text_file(report_path(connector_root, key, "md"), generated_markdown_text(markdown, metadata))
    return build_governance_record(key, connector_root, framework_root, build_root, generated_at, inputs)


def dashboard_inputs() -> tuple[str, ...]:
    return (
        report_relpath("full_runtime_matrix", "json"),
        report_relpath("verified_runtime_mismatch_analysis", "json"),
        report_relpath("final_consistency_audit", "json"),
        report_relpath("next_fix_plan", "json"),
        report_relpath("full_run_evidence", "json"),
        report_relpath("report_freshness", "json"),
    )


def refresh_governance_reports(
    reports: list[dict[str, Any]],
    *,
    connector_root: Path,
    framework_root: Path,
    build_root: Path,
    report_dir: Path,
    verified_run_id: str,
    environment: dict[str, str],
) -> Path:
    submodule_root = connector_root / FRAMEWORK_SUBMODULE_PATH
    mrts_root = framework_root / "tools/MRTS"
    submodules = submodule_report(connector_root, framework_root)
    generated_at = utc_now()
    cyclic_governance_reports = {"merge_readiness_dashboard", "report_freshness", "report_refresh_manifest"}
    manifest_record = build_governance_record("report_refresh_manifest", connector_root, framework_root, build_root, generated_at)
    freshness_placeholder = build_governance_record("report_freshness", connector_root, framework_root, build_root, generated_at)
    dashboard_placeholder = build_governance_record("merge_readiness_dashboard", connector_root, framework_root, build_root, generated_at)
    all_records = reports + [freshness_placeholder, dashboard_placeholder, manifest_record]
    freshness = {"generated_at": generated_at, "reports": all_records}
    freshness_record = governance_record_with_outputs(
        "report_freshness", freshness, render_freshness_md(freshness),
        connector_root=connector_root, framework_root=framework_root, build_root=build_root,
        generated_at=generated_at, inputs=report_outputs(all_records, cyclic_governance_reports),
    )
    all_records = reports + [freshness_record, dashboard_placeholder, manifest_record]
    manifest = {
        "verified_run_id": verified_run_id, "data_source_policy": DATA_SOURCE_POLICY, "generated_at": generated_at,
        "connector_sha": git_sha(connector_root), "framework_sha": git_sha(framework_root),
        "framework_submodule_sha": git_sha(submodule_root), "mrts_sha": git_sha(mrts_root),
        "parent_branch": git_branch(connector_root), "parent_dirty": git_dirty_status(connector_root),
        "framework_branch": git_branch(framework_root), "framework_dirty": git_dirty_status(framework_root),
        "submodules": submodules, "verified_commands": read_verified_commands(environment),
        "inputs": manifest_inputs(report_dir), "reports": all_records,
    }
    dashboard = merge_dashboard_payload(manifest, freshness, submodules, connector_root)
    dashboard_record = governance_record_with_outputs(
        "merge_readiness_dashboard", dashboard, render_merge_dashboard_md(dashboard),
        connector_root=connector_root, framework_root=framework_root, build_root=build_root,
        generated_at=generated_at, inputs=dashboard_inputs(),
    )
    manifest["reports"] = reports + [freshness_record, dashboard_record, manifest_record]
    freshness = {"generated_at": generated_at, "reports": manifest["reports"]}
    freshness_record = governance_record_with_outputs(
        "report_freshness", freshness, render_freshness_md(freshness),
        connector_root=connector_root, framework_root=framework_root, build_root=build_root,
        generated_at=generated_at, inputs=report_outputs(manifest["reports"], cyclic_governance_reports),
    )
    manifest["reports"] = reports + [freshness_record, dashboard_record, manifest_record]
    dashboard = merge_dashboard_payload(manifest, freshness, submodules, connector_root)
    dashboard_record = governance_record_with_outputs(
        "merge_readiness_dashboard", dashboard, render_merge_dashboard_md(dashboard),
        connector_root=connector_root, framework_root=framework_root, build_root=build_root,
        generated_at=generated_at, inputs=dashboard_inputs(),
    )
    manifest["reports"] = reports + [freshness_record, dashboard_record, manifest_record]
    metadata = build_metadata(
        generated_by="ci/evidence/reports/refresh-connector-reports.py", make_target="refresh-connector-reports",
        connector_root=connector_root, framework_root=framework_root,
        inputs=report_outputs(manifest["reports"], {"report_refresh_manifest"}), generated_at=manifest["generated_at"],
        report_key="report_refresh_manifest",
        extra={"framework_submodule_sha": manifest["framework_submodule_sha"], "mrts_sha": manifest["mrts_sha"], "submodules": submodules},
    )
    json_path = report_path_from_root(report_dir, "report_refresh_manifest", "json")
    md_path = report_path_from_root(report_dir, "report_refresh_manifest", "md")
    write_text_file(json_path, generated_json_text(manifest, metadata))
    write_text_file(md_path, generated_markdown_text(render_manifest_md(manifest), metadata))
    index_root = connector_root / "reports/testing"
    write_text_file(index_root / "README.md", render_report_index_md(manifest, connector_root=connector_root))
    write_text_file(index_root / "README.de.md", render_report_index_md(manifest, german=True, connector_root=connector_root))
    removed_legacy = cleanup_legacy_flat_reports(connector_root)
    if removed_legacy:
        print("refresh-connector-reports: removed legacy flat reports: " + ", ".join(removed_legacy))
    sanitized_paths = sanitize_generated_markdown_tree(report_dir)
    if sanitized_paths:
        print("refresh-connector-reports: normalized portable Markdown paths: " + ", ".join(str(path.relative_to(connector_root)) for path in sanitized_paths))
    print(f"refresh-connector-reports: manifest={md_path}")
    return md_path


def refresh_exit_code(reports: list[dict[str, Any]], strict_inputs: bool) -> int:
    failed = [item for item in reports if item["status"] == "failed" and not item.get("optional")]
    skipped_required = [
        item for item in reports
        if (str(item["status"]).startswith("skipped") or str(item["status"]).startswith("blocked") or item["status"] == "interrupted")
        and not item.get("optional")
    ]
    return 2 if failed or (strict_inputs and skipped_required) else 0


BOUNDED_SMOKE_RECEIPT = "bounded-smoke-producer.json"
BOUNDED_SMOKE_REPORTS = frozenset({"connector_coverage_reports", "runtime_cache_reports"})


def bounded_smoke_identity(connector_root: Path, framework_root: Path, build_root: Path,
                           variant: str | None, env: dict[str, str]) -> dict[str, str]:
    if framework_root != connector_root / "modules/ModSecurity-test-Framework":
        raise ValueError("bounded smoke requires the fixed Parent Framework module path")
    pins = verify_framework_revision_pins(connector_root, git_sha(connector_root))
    identity = {"parent_sha": git_sha(connector_root), "framework_sha": str(pins["framework_sha"]),
                "run_id": env.get("VERIFIED_RUN_ID", ""), "variant": variant or "",
                "build_root": str(build_root)}
    if not all(re.fullmatch(r"[0-9a-f]{40}", identity[key]) for key in ("parent_sha", "framework_sha")):
        raise ValueError("bounded smoke requires exact Parent and Framework revisions")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,160}", identity["run_id"]) or identity["variant"] not in {"no-crs", "with-crs"}:
        raise ValueError("bounded smoke requires a run ID and explicit variant")
    return identity


def bounded_smoke_expected_cases(connector_root: Path, framework_root: Path,
                                 env: dict[str, str], variant: str) -> dict[str, list[str]]:
    # This is exactly the pinned native harness catalog API, with no inherited
    # TEST_CASE / SMOKE_CASES or canonical-baseline selection narrowing.
    program = """import json, sys
from modsecurity_test_framework.runners.runner_core import discover_case_files, load_case
result = {connector: sorted(str(load_case(path)['name']) for path in
    discover_case_files(sys.argv[1], connector, scope='all', smoke_cases='',
                        test_case='', framework_root=sys.argv[2]))
    for connector in ('apache', 'nginx')}
print(json.dumps(result))
"""
    selection_env = {**env, "MODSECURITY_TEST_VARIANT": variant, "FORCE_ALL_CASES": "", "NO_CRS_BASELINE": "",
                     "TEST_ROOT": str(framework_root), "CONNECTOR_ROOT": str(connector_root),
                     "PYTHONPATH": os.pathsep.join((str(framework_root), str(framework_root / "connector_suite"))),
                     "PYTHONSAFEPATH": "1", "PYTHONNOUSERSITE": "1"}
    process = subprocess.run([sys.executable, "-P", "-c", program, str(connector_root), str(framework_root)],
                             cwd=connector_root, env=selection_env, capture_output=True, text=True, check=False, timeout=30)
    if process.returncode != 0:
        raise ValueError("bounded smoke pinned native case discovery failed: " + process.stderr.strip())
    expected = json.loads(process.stdout)
    for connector in ("apache", "nginx"):
        names = expected.get(connector) if isinstance(expected, dict) else None
        if (not isinstance(names, list) or not names
                or any(not isinstance(name, str) or not name for name in names)
                or len(names) != len(set(names))):
            raise ValueError("bounded smoke pinned native case catalog is incomplete or ambiguous")
    return expected


def begin_bounded_smoke(connector_root: Path, framework_root: Path, build_root: Path,
                        variant: str | None, env: dict[str, str]) -> None:
    from modsecurity_connector_ci.lib.runtime_path_utils import open_private_runtime_root

    identity = bounded_smoke_identity(connector_root, framework_root, build_root, variant, env)
    expected = bounded_smoke_expected_cases(connector_root, framework_root, env, identity["variant"])
    with open_private_runtime_root(build_root) as root:
        # O_EXCL receipt creation and a new results directory prohibit reuse of
        # an earlier run, even when every retained result happened to pass.
        os.mkdir("results", mode=0o700, dir_fd=root.descriptor)
        root.create_text(BOUNDED_SMOKE_RECEIPT, json.dumps(
            {**identity, "started_at_ns": time.time_ns(), "expected_cases": expected}, sort_keys=True
        ) + "\n")


def bounded_smoke_input(build_root: Path, name: str, started_at_ns: int) -> str:
    from modsecurity_connector_ci.lib.runtime_path_utils import read_runtime_artifact_text

    path = build_root / "results" / name
    details = path.lstat()
    if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid()
            or details.st_nlink != 1 or stat.S_IMODE(details.st_mode) & 0o022
            or details.st_size > 16 * 1024 * 1024 or details.st_mtime_ns < started_at_ns):
        raise ValueError(f"bounded smoke input is unsafe, stale or oversized: {name}")
    return read_runtime_artifact_text(build_root, path, "bounded smoke input")


def bounded_smoke_receipt(connector_root: Path, framework_root: Path, build_root: Path,
                          variant: str | None, env: dict[str, str]) -> dict[str, Any]:
    from modsecurity_connector_ci.lib.runtime_path_utils import open_private_runtime_root

    identity = bounded_smoke_identity(connector_root, framework_root, build_root, variant, env)
    with open_private_runtime_root(build_root) as root:
        receipt = json.loads(root.read_text(BOUNDED_SMOKE_RECEIPT))
    if not isinstance(receipt, dict) or any(receipt.get(key) != value for key, value in identity.items()):
        raise ValueError("bounded smoke producer identity does not match the current run")
    started_at_ns = receipt.get("started_at_ns")
    if type(started_at_ns) is not int or not 0 < started_at_ns <= time.time_ns():
        raise ValueError("bounded smoke producer start time is invalid")
    expected = bounded_smoke_expected_cases(connector_root, framework_root, env, identity["variant"])
    if receipt.get("expected_cases") != expected:
        raise ValueError("bounded smoke producer native case selection changed")
    return receipt


def validate_bounded_smoke_summary(connector: str, text: str, expected: list[str], variant: str) -> None:
    payload = json.loads(text)
    summary = payload.get(connector) if isinstance(payload, dict) else None
    cases = summary.get("cases") if isinstance(summary, dict) else None
    counts = summary.get("summary") if isinstance(summary, dict) else None
    if not isinstance(cases, dict) or set(cases) != set(expected):
        raise ValueError(f"bounded smoke {connector} case IDs differ from the pinned native catalog")
    required_counts = {"pass": len(expected), "fail": 0, "blocked": 0, "not_executable": 0, "skipped": 0}
    if (not isinstance(counts, dict) or counts != required_counts
            or any(type(value) is not int for value in counts.values())):
        raise ValueError(f"bounded smoke {connector} has incomplete or unsuccessful case counts")
    if any(not isinstance(row, dict) or row.get("variant") != variant
           or row.get("executed_connector") != connector for row in cases.values()):
        raise ValueError(f"bounded smoke {connector} case variant or executed connector differs from the producer")
    if any(not isinstance(row, dict) or row.get("status") != "pass"
           or row.get("live_executed") is not True for row in cases.values()):
        raise ValueError(f"bounded smoke {connector} requires current successful live case results")


def validate_bounded_smoke_inputs(connector_root: Path, framework_root: Path, build_root: Path,
                                  variant: str | None, env: dict[str, str]) -> dict[str, Any]:
    receipt = bounded_smoke_receipt(connector_root, framework_root, build_root, variant, env)
    hashes: dict[str, str] = {}
    for connector in ("apache", "nginx"):
        rc_name = f"{connector}.rc"
        summary_name = f"{connector}-summary.json"
        rc = bounded_smoke_input(build_root, rc_name, receipt["started_at_ns"])
        summary_text = bounded_smoke_input(build_root, summary_name, receipt["started_at_ns"])
        if rc.strip() != "0":
            raise ValueError(f"bounded smoke {connector} producer did not succeed")
        validate_bounded_smoke_summary(connector, summary_text, receipt["expected_cases"][connector], receipt["variant"])
        for name, content in ((rc_name, rc), (summary_name, summary_text)):
            hashes[name] = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return {**receipt, "input_sha256": hashes}


def bounded_smoke_catalog(catalog: list[ReportSpec]) -> list[ReportSpec]:
    selected = [replace(spec, optional=False) for spec in catalog if spec.name in BOUNDED_SMOKE_REPORTS]
    if {spec.name for spec in selected} != BOUNDED_SMOKE_REPORTS or len(selected) != len(BOUNDED_SMOKE_REPORTS):
        raise ValueError("bounded smoke report catalog is incomplete")
    return selected


def bounded_smoke_report_status(reports: list[dict[str, Any]], run_id: str) -> int:
    return 0 if (len(reports) == len(BOUNDED_SMOKE_REPORTS)
                 and {report.get("report_name") for report in reports} == BOUNDED_SMOKE_REPORTS
                 and all(report.get("status") == "generated"
                         and report.get("freshness_status") == "fresh"
                         and report.get("verified_run_id") == run_id
                         for report in reports)) else 2


def bounded_smoke_snapshot_path(connector_root: Path) -> Path:
    return connector_root / "reports/testing/runtime-validation-snapshot.json"


def validate_bounded_smoke_snapshot(connector_root: Path, receipt: dict[str, Any], started_at_ns: int) -> None:
    path = bounded_smoke_snapshot_path(connector_root)
    details = path.lstat()
    if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid()
            or details.st_nlink != 1 or stat.S_IMODE(details.st_mode) & 0o022
            or details.st_size > 16 * 1024 * 1024 or details.st_mtime_ns < started_at_ns):
        raise ValueError("bounded smoke snapshot was not safely regenerated for this refresh")
    snapshot = json.loads(path.read_text(encoding="utf-8"))
    commit = snapshot.get("commit", "")
    if (snapshot.get("build_root") != receipt["build_root"]
            or not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{7,40}", commit)
            or not receipt["parent_sha"].startswith(commit)):
        raise ValueError("bounded smoke snapshot source/run identity differs from the producer")
    rows = snapshot.get("runtime_smokes", [])
    for connector in ("apache", "nginx"):
        expected_path = str(Path(receipt["build_root"]) / "results" / f"{connector}-summary.json")
        selected = [row for row in rows if isinstance(row, dict) and row.get("connector") == connector]
        if len(selected) != 1 or selected[0].get("summary_path") != expected_path:
            raise ValueError("bounded smoke snapshot does not reference the exact producer summaries")


def bounded_smoke_command_label(variant: str | None) -> str:
    if variant == "no-crs":
        return "make test-smoke-sequential-no-crs"
    if variant == "with-crs":
        return "make test-smoke-sequential-with-crs"
    raise ValueError("bounded smoke command requires an explicit supported variant")


def refresh_bounded_smoke(connector_root: Path, framework_root: Path, build_root: Path,
                          variant: str | None, env: dict[str, str], catalog: list[ReportSpec]) -> int:
    from modsecurity_connector_ci.lib.runtime_path_utils import open_private_runtime_root

    command_label = bounded_smoke_command_label(variant)
    receipt = validate_bounded_smoke_inputs(connector_root, framework_root, build_root, variant, env)
    command = [sys.executable, str(framework_root / "ci/reporting/update-runtime-snapshot.py"),
               "--framework-root", str(framework_root), "--connector-root", str(connector_root),
               "--output-root", str(connector_root), "--build-root", str(build_root),
               "--apache-exit-code", "0", "--nginx-exit-code", "0",
               "--apache-command", command_label,
               "--nginx-command", command_label]
    snapshot_started_at_ns = time.time_ns()
    snapshot_status, _output, _log = run_command(command, connector_root, env)
    if snapshot_status != 0:
        raise ValueError(f"bounded smoke snapshot generator returned {snapshot_status}")
    # Revalidate after snapshot generation rather than trusting retained input
    # or a producer result that changed while a report was being refreshed.
    if validate_bounded_smoke_inputs(connector_root, framework_root, build_root, variant, env) != receipt:
        raise ValueError("bounded smoke inputs changed during snapshot generation")
    validate_bounded_smoke_snapshot(connector_root, receipt, snapshot_started_at_ns)
    selected = bounded_smoke_catalog(catalog)
    report_start_ns = time.time_ns()
    reports = [run_spec(spec, connector_root, framework_root, build_root, env) for spec in selected]
    status = bounded_smoke_report_status(reports, receipt["run_id"])
    for spec in selected:
        for output in spec.outputs:
            path = resolve_output(output, connector_root)
            if not path.is_file() or path.is_symlink() or path.stat().st_mtime_ns < report_start_ns:
                status = 2
    if validate_bounded_smoke_inputs(connector_root, framework_root, build_root, variant, env) != receipt:
        raise ValueError("bounded smoke inputs changed during report generation")
    with open_private_runtime_root(build_root) as root:
        root.create_text("bounded-smoke-report-refresh.json", json.dumps(
            {"profile": "bounded-smoke", "status": "PASS" if status == 0 else "FAIL",
             "producer": receipt, "reports": reports}, indent=2, sort_keys=True
        ) + "\n")
    return status


def main() -> int:
    args = refresh_arguments()
    if args.profile == "bounded-smoke":
        fixed_root = connector_root()
        fixed_framework = fixed_root / FRAMEWORK_SUBMODULE_PATH
        provided_framework = Path(args.framework_root).absolute() if args.framework_root else fixed_framework
        if (Path(args.connector_root).absolute() != fixed_root or provided_framework != fixed_framework
                or args.render_index_only):
            print("bounded smoke report refresh: FAIL: requires the script Parent/Framework roots and a fresh producer", file=sys.stderr)
            return 2
        args.connector_root = str(fixed_root)
        args.framework_root = str(fixed_framework)
    connector_root, framework_root, build_root, native_root, report_dir = refresh_roots(args)
    if args.profile == "bounded-smoke":
        connector_root = connector_root()
        framework_root = connector_root / FRAMEWORK_SUBMODULE_PATH
    if args.render_index_only:
        return render_index_only(connector_root)
    verified_run_id, environment = refresh_environment(connector_root, framework_root, build_root, native_root)
    if args.profile == "bounded-smoke":
        try:
            if args.begin_bounded_smoke:
                begin_bounded_smoke(connector_root, framework_root, build_root, args.variant, environment)
                return 0
            catalog = make_catalog(connector_root, framework_root, build_root, native_root, sys.executable)
            return refresh_bounded_smoke(connector_root, framework_root, build_root, args.variant, environment, catalog)
        except (OSError, ValueError, TypeError, subprocess.TimeoutExpired) as error:
            print(f"bounded smoke report refresh: FAIL: {error}", file=sys.stderr)
            return 2
    if args.begin_bounded_smoke or args.variant:
        raise ValueError("bounded smoke arguments require the bounded-smoke profile")
    catalog = make_catalog(connector_root, framework_root, build_root, native_root, sys.executable)
    reports = [run_spec(spec, connector_root, framework_root, build_root, environment) for spec in catalog]
    refresh_governance_reports(
        reports, connector_root=connector_root, framework_root=framework_root, build_root=build_root,
        report_dir=report_dir, verified_run_id=verified_run_id, environment=environment,
    )
    return refresh_exit_code(reports, args.strict_inputs)


if __name__ == "__main__":
    raise SystemExit(main())
