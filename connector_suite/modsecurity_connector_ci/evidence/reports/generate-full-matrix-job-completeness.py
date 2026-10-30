#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

# CI helpers are shared from ci/lib even when this file is executed directly.
import sys

from typing import Any

from modsecurity_connector_ci.lib.best_effort_evidence_readers import read_json_object as read_json, read_jsonl_objects as read_jsonl
from modsecurity_connector_ci.lib.generated_report_utils import DATA_SOURCE_POLICY, GENERATED_REPORTS, build_metadata, generated_json_text, generated_markdown_text, git_sha, report_path, sha256_file, utc_now
from modsecurity_connector_ci.lib.runtime_path_utils import verified_runtime_paths
from modsecurity_connector_ci.lib.verified_run_id import validate_verified_run_id
from modsecurity_connector_ci.lib.verified_full_matrix_receipt import AggregateReceiptError, aggregate_receipt_path


CONNECTORS = ("apache", "nginx", "haproxy")
VARIANTS = (("no-crs", "no-mrts"), ("no-crs", "with-mrts"), ("with-crs", "no-mrts"), ("with-crs", "with-mrts"))


def file_record(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        return {"label": label, "path": str(path), "status": "missing", "sha256": "missing"}
    return {
        "label": label,
        "path": str(path),
        "status": "present",
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
        "mtime_utc": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }


def job_id(connector: str, crs: str, mrts: str) -> str:
    return f"{connector}:{crs}:{mrts}"


def summary_candidates(job_root: Path, connector: str) -> list[Path]:
    return [
        job_root / "results" / f"{connector}-summary.json",
        job_root / "results" / "force-all" / f"{connector}-summary.json",
    ]


def result_jsonl_path(job_root: Path, connector: str) -> Path:
    return job_root / "results" / "force-all" / f"{connector}-results.jsonl"


def summary_path(job_root: Path, connector: str) -> Path:
    # A job-local summary.path used to be an unchecked indirection.  The
    # report generator must only consume the fixed, job-root-confined summary
    # locations; the later report gate cannot make an earlier arbitrary read
    # safe.
    for candidate in summary_candidates(job_root, connector):
        if candidate.is_file():
            return candidate
    return summary_candidates(job_root, connector)[0]


def count_summary_cases(path: Path, connector: str) -> dict[str, Any]:
    data = read_json(path)
    root = data.get(connector) if isinstance(data.get(connector), dict) else {}
    cases = root.get("cases") if isinstance(root.get("cases"), dict) else {}
    statuses = Counter(str(case.get("status", "unknown")) for case in cases.values() if isinstance(case, dict))
    attempted = root.get("attempted")
    if not isinstance(attempted, int):
        attempted = len(cases)
    return {
        "cases": len(cases),
        "attempted": attempted,
        "pass": statuses.get("pass", 0),
        "fail": statuses.get("fail", 0),
        "blocked": statuses.get("blocked", 0),
        "not_executable": statuses.get("not_executable", 0),
        "status_counts": dict(sorted(statuses.items())),
        "source": "summary_json",
    }


def count_jsonl_cases(path: Path) -> dict[str, Any]:
    rows = read_jsonl(path)
    statuses = Counter(str(row.get("status", "unknown")) for row in rows)
    actual = Counter(str(row.get("actual_status", row.get("observed_status", "unknown"))) for row in rows)
    return {
        "cases": len(rows),
        "attempted": len(rows),
        "pass": statuses.get("pass", 0),
        "fail": statuses.get("fail", 0),
        "blocked": statuses.get("blocked", 0),
        "not_executable": statuses.get("not_executable", 0),
        "status_counts": dict(sorted(statuses.items())),
        "actual_status_counts": dict(sorted(actual.items())),
        "source": "results_jsonl",
    }


def read_manifest_rows(manifest_path: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for row in read_jsonl(manifest_path):
        connector = str(row.get("connector") or "")
        crs = str(row.get("test_variant") or row.get("crs") or "")
        mrts = str(row.get("mrts_variant") or row.get("mrts") or "")
        if connector and crs and mrts:
            rows[job_id(connector, crs, mrts)] = row
    return rows


def detect_job_status(job: dict[str, Any], log_path: Path, jsonl_path: Path) -> tuple[str, str]:
    if job:
        rc = job.get("return_code")
        if rc == 0:
            return "completed", "job.json exists with rc=0"
        return "completed_with_mismatches", f"job.json exists with rc={rc}"
    if log_path.is_file():
        log = log_path.read_text(encoding="utf-8", errors="replace")
        if "Terminated" in log or "timeout" in log.lower():
            return "timeout_or_incomplete", "run.log ends with termination/timeout evidence"
        if jsonl_path.is_file():
            return "incomplete", "partial results exist but job.json is missing"
        return "incomplete", "run.log exists but job.json is missing"
    return "not_started", "no job.json or run.log found"


def nginx_log_observations(lines: list[str]) -> dict[str, Any]:
    running_cases = [line.split("case=", 1)[1].split()[0] for line in lines if "nginx_smoke: running case=" in line]
    fail_cases = [line.split(None, 1)[1] if " " in line else line for line in lines if line.startswith("FAIL ")]
    observed_500 = sum("observed=500" in line or "observed 500" in line for line in lines)
    terminated = any("Terminated" in line or ("lock-release" in line and "Bad file descriptor" in line) for line in lines)
    return {
        "running_cases": running_cases,
        "fail_cases": fail_cases,
        "observed_500": observed_500,
        "terminated": terminated,
    }


def analyze_nginx_with_crs_mrts(matrix_root: Path) -> dict[str, Any]:
    job_root = matrix_root / "with-crs" / "with-mrts" / "nginx"
    log_path = job_root / "run.log"
    jsonl_path = result_jsonl_path(job_root, "nginx")
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines() if log_path.is_file() else []
    observations = nginx_log_observations(lines)
    partial = count_jsonl_cases(jsonl_path) if jsonl_path.is_file() else {}
    return {
        "job_id": job_id("nginx", "with-crs", "with-mrts"),
        "log_path": str(log_path),
        "results_jsonl": str(jsonl_path),
        "run_log_lines": len(lines),
        "running_case_lines": len(observations["running_cases"]),
        "fail_lines": len(observations["fail_cases"]),
        "observed_500_lines": observations["observed_500"],
        "terminated": observations["terminated"],
        "last_running_case": observations["running_cases"][-1] if observations["running_cases"] else "",
        "last_fail_case": observations["fail_cases"][-1] if observations["fail_cases"] else "",
        "partial_result_counts": partial,
        "findings": [
            "The previous run was killed while NGINX with-crs/with-mrts was still executing MRTS request-cookie-name cases.",
            "The partial NGINX job produced result JSONL but no summary JSON and no job.json, so it cannot count as complete evidence.",
            "Observed failures are dominated by HTTP 500 responses in the NGINX harness for this variant.",
            "Current connector smoke runners expose TEST_CASE/SMOKE_CASES filters but no stable shard index contract for Full-Matrix merge semantics.",
        ],
        "sharding_note": (
            "Add sharding at the case-list stage in connectors/*/harness/run_*_smoke.sh, after case_cli list-cases "
            "and before the force-all loop, then write shard metadata into job.json and merge shards in this report."
        ),
    }


def job_case_counts(summary: Path, jsonl: Path, connector: str) -> tuple[dict[str, Any], Path]:
    if summary.is_file():
        return count_summary_cases(summary, connector), summary
    if jsonl.is_file():
        return count_jsonl_cases(jsonl), jsonl
    return {}, jsonl


def collect_job(
    matrix_root: Path,
    manifest: dict[str, dict[str, Any]],
    *,
    connector: str,
    crs: str,
    mrts: str,
) -> dict[str, Any]:
    jid = job_id(connector, crs, mrts)
    job_root = matrix_root / crs / mrts / connector
    job_path = job_root / "job.json"
    log_path = job_root / "run.log"
    build_manifest = job_root / "build-manifest.json"
    summary = summary_path(job_root, connector)
    jsonl = result_jsonl_path(job_root, connector)
    preamble = job_root / "preambles" / f"{connector}-{crs}-{mrts}.load"
    job = read_json(job_path)
    status, reason = detect_job_status(job, log_path, jsonl)
    counts, result_path = job_case_counts(summary, jsonl, connector)
    manifest_row = manifest.get(jid, {})
    duration = job.get("duration_seconds", manifest_row.get("duration_seconds"))
    return {
        "job_id": jid,
        "connector": connector,
        "crs": crs,
        "mrts": mrts,
        "verified_run_id": job.get("verified_run_id", ""),
        "status": status,
        "reason": reason,
        "manifest_recorded": bool(manifest_row),
        "return_code": job.get("return_code", manifest_row.get("return_code")),
        "started_at": job.get("started_at", manifest_row.get("started_at", "")),
        "ended_at": job.get("ended_at", manifest_row.get("ended_at", "")),
        "duration_seconds": duration if isinstance(duration, int) else None,
        "cases": counts.get("cases", 0),
        "attempted": counts.get("attempted", 0),
        "pass": counts.get("pass", 0),
        "fail": counts.get("fail", 0),
        "blocked": counts.get("blocked", 0),
        "not_executable": counts.get("not_executable", 0),
        "status_counts": counts.get("status_counts", {}),
        "actual_status_counts": counts.get("actual_status_counts", {}),
        "job_path": str(job_path),
        "log_path": str(log_path),
        "summary_path": str(summary),
        "results_jsonl": str(jsonl),
        "result_path": str(result_path),
        "hashes": job.get("hashes") if isinstance(job.get("hashes"), dict) else {},
        "inputs": job.get("inputs") if isinstance(job.get("inputs"), dict) else {},
        "outputs": job.get("outputs") if isinstance(job.get("outputs"), dict) else {},
        "input_hashes": [
            file_record(job_path, "job_json"),
            file_record(log_path, "run_log"),
            file_record(summary, "summary_json"),
            file_record(jsonl, "results_jsonl"),
            file_record(build_manifest, "build_manifest"),
            file_record(preamble, "rule_preamble"),
        ],
    }


def collect_jobs(matrix_root: Path, manifest_path: Path) -> list[dict[str, Any]]:
    manifest = read_manifest_rows(manifest_path)
    return [
        collect_job(matrix_root, manifest, connector=connector, crs=crs, mrts=mrts)
        for crs, mrts in VARIANTS
        for connector in CONNECTORS
    ]


def rewritten_manifest_text(jobs: list[dict[str, Any]]) -> str:
    completed = [job for job in jobs if job["status"] in {"completed", "completed_with_mismatches"}]
    lines = []
    for job in completed:
        row = {
            "connector": job["connector"],
            "job_id": job["job_id"],
            "verified_run_id": job["verified_run_id"],
            "test_variant": job["crs"],
            "mrts_variant": job["mrts"],
            "return_code": job["return_code"],
            "status": job["status"],
            "started_at": job["started_at"],
            "ended_at": job["ended_at"],
            "duration_seconds": job["duration_seconds"],
            "results_dir": str(Path(job["job_path"]).parent / "results"),
            "summary_path": job["summary_path"],
            "log_path": job["log_path"],
            "hashes": job["hashes"],
            "inputs": job["inputs"],
            "outputs": job["outputs"],
        }
        lines.append(json.dumps(row, sort_keys=True))
    return "\n".join(lines) + ("\n" if lines else "")


def source_manifest_run_ids(path: Path, build_root: Path) -> set[str]:
    """Return the validated run identities that own the current raw source.

    The full-matrix raw manifest is shared source material.  A report caller
    must not select an arbitrary different run ID to evade the aggregate
    receipt that governs the source it is about to rewrite.
    """

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return set()
    except OSError as exc:
        raise ValueError(f"refusing to rewrite full-matrix manifest: cannot read existing source: {exc}") from exc
    run_ids: set[str] = set()
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"refusing to rewrite full-matrix manifest: source row {line_number} is not valid JSON"
            ) from exc
        if not isinstance(row, dict) or not isinstance(row.get("verified_run_id"), str):
            raise ValueError(
                f"refusing to rewrite full-matrix manifest: source row {line_number} has no verified_run_id"
            )
        run_id = row["verified_run_id"]
        try:
            aggregate_receipt_path(build_root, run_id)
        except AggregateReceiptError as exc:
            raise ValueError(
                f"refusing to rewrite full-matrix manifest: source row {line_number} has an invalid verified_run_id"
            ) from exc
        run_ids.add(run_id)
    return run_ids


def rewrite_manifest(
    path: Path,
    jobs: list[dict[str, Any]],
    *,
    sealed_receipt_path: Path | None = None,
) -> None:
    content = rewritten_manifest_text(jobs)
    if sealed_receipt_path is not None and (sealed_receipt_path.exists() or sealed_receipt_path.is_symlink()):
        if sealed_receipt_path.is_symlink() or not sealed_receipt_path.is_file():
            raise ValueError("refusing to rewrite full-matrix manifest: aggregate receipt is not a regular file")
        try:
            existing = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"refusing to rewrite sealed full-matrix manifest: {exc}") from exc
        if existing != content:
            raise ValueError(
                "refusing to rewrite sealed full-matrix manifest: proposed bytes do not match the sealed source"
            )
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def markdown_table(rows: list[list[Any]]) -> list[str]:
    return ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Full-Matrix Job Completeness",
        "",
        f"Verified run id: `{payload['verified_run_id']}`",
        "",
        "## Summary",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Complete jobs | `{payload['complete_jobs']}/{payload['total_jobs']}` |",
        f"| Manifest-recorded jobs | `{payload['manifest_recorded_jobs']}/{payload['total_jobs']}` |",
        f"| Overall status | `{payload['overall_status']}` |",
        f"| Evidence scope | `{payload['evidence_scope']}` |",
        f"| Missing jobs | `{', '.join(payload['missing_job_ids']) or '-'}` |",
        "",
        "## Jobs",
        "",
    ]
    lines.extend(
        markdown_table(
            [
                ["Job", "Connector", "CRS", "MRTS", "Status", "Duration", "Cases", "Failures", "Log"],
                ["---", "---", "---", "---", "---", "---:", "---:", "---:", "---"],
                *[
                    [
                        f"`{job['job_id']}`",
                        job["connector"],
                        job["crs"],
                        job["mrts"],
                        f"`{job['status']}`",
                        job["duration_seconds"] if job["duration_seconds"] is not None else "-",
                        job["cases"],
                        job["fail"],
                        f"`{job['log_path']}`",
                    ]
                    for job in payload["jobs"]
                ],
            ]
        )
    )
    lines.extend(["", "## Completed Jobs", ""])
    lines.extend(
        markdown_table(
            [
                ["Job", "Duration", "RC", "Failures"],
                ["---", "---:", "-:", "---:"],
                *[
                    [f"`{job['job_id']}`", job["duration_seconds"], job["return_code"], job["fail"]]
                    for job in payload["jobs"]
                    if job["status"] in {"completed", "completed_with_mismatches"}
                ],
            ]
        )
    )
    lines.extend(["", "## Missing / Timeout Jobs", ""])
    missing_rows = [
        [
            f"`{job['job_id']}`",
            job["reason"],
            f"`make verified-full-matrix-job CONNECTOR={job['connector']} CRS={job['crs']} MRTS={job['mrts']}`",
        ]
        for job in payload["jobs"]
        if job["status"] not in {"completed", "completed_with_mismatches"}
    ]
    if missing_rows:
        lines.extend(markdown_table([["Job", "Reason", "Next Command"], ["---", "---", "---"], *missing_rows]))
    else:
        lines.append("Missing/Empty: no missing or timed-out Full-Matrix jobs.")
    lines.extend(["", "## Slowest Jobs", ""])
    lines.extend(
        markdown_table(
            [
                ["Job", "Duration", "Notes"],
                ["---", "---:", "---"],
                *[
                    [f"`{job['job_id']}`", job["duration_seconds"], job["reason"]]
                    for job in payload["slowest_jobs"]
                ],
            ]
        )
    )
    lines.extend(["", "## NGINX with-crs/with-mrts Runtime Analysis", ""])
    nginx = payload["nginx_with_crs_with_mrts_analysis"]
    lines.extend(
        [
            f"- Last running case: `{nginx.get('last_running_case') or '-'}`",
            f"- Last failed case: `{nginx.get('last_fail_case') or '-'}`",
            f"- Run log lines: `{nginx.get('run_log_lines', 0)}`",
            f"- Running-case lines: `{nginx.get('running_case_lines', 0)}`",
            f"- FAIL lines: `{nginx.get('fail_lines', 0)}`",
            f"- Observed 500 lines: `{nginx.get('observed_500_lines', 0)}`",
            f"- Terminated evidence: `{str(nginx.get('terminated', False)).lower()}`",
            f"- Partial result rows: `{nginx.get('partial_result_counts', {}).get('cases', 0)}`",
            "",
        ]
    )
    for finding in nginx.get("findings", []):
        lines.append(f"- {finding}")
    lines.extend(["", "## Sharding Note", "", nginx.get("sharding_note", "")])
    lines.extend(["", "## Inputs", ""])
    lines.extend(
        markdown_table(
            [
                ["Input", "Status", "SHA256"],
                ["---", "---", "---"],
                *[[f"`{item['path']}`", item["status"], f"`{item['sha256']}`"] for item in payload["inputs"]],
            ]
        )
    )
    return "\n".join(lines) + "\n"


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector-root", default=".")
    parser.add_argument("--framework-root", default=None)
    parser.add_argument("--build-root", default=None)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--verified-run-id", default="")
    parser.add_argument("--verified-commands-file", default="")
    parser.add_argument("--rewrite-manifest", action="store_true")
    return parser


def resolve_generation_context(
    args: argparse.Namespace,
) -> tuple[Path, Path, Path, Path, Path, Path, str, Path]:
    connector_root = Path(args.connector_root).resolve()
    framework_root = Path(args.framework_root).resolve() if args.framework_root else connector_root / "modules/ModSecurity-test-Framework"
    default_paths = verified_runtime_paths()
    build_root = Path(args.build_root or default_paths["BUILD_ROOT"]).resolve()
    output_dir = Path(args.output_dir).resolve() if args.output_dir else connector_root / "reports/testing/generated/manifest"
    matrix_root = build_root / "full-matrix"
    manifest_path = matrix_root / "full-runtime-matrix-runs.jsonl"
    verified_run_id = args.verified_run_id
    if not verified_run_id:
        current = build_root / "verified-runs" / "current-run-id"
        verified_run_id = current.read_text(encoding="utf-8").strip() if current.is_file() else ""
    if not verified_run_id:
        verified_run_id = "unknown"
    verified_run_id = validate_verified_run_id(verified_run_id)
    verified_commands = build_root / "verified-runs" / verified_run_id / "verified-commands.json"
    if args.verified_commands_file:
        verified_commands = Path(args.verified_commands_file)
    return (
        connector_root,
        framework_root,
        build_root,
        output_dir,
        matrix_root,
        manifest_path,
        verified_run_id,
        verified_commands,
    )


def rewrite_manifest_when_requested(
    parser: argparse.ArgumentParser,
    *,
    rewrite_manifest_requested: bool,
    manifest_path: Path,
    jobs: list[dict[str, Any]],
    build_root: Path,
    verified_run_id: str,
    matrix_root: Path,
) -> list[dict[str, Any]]:
    if not rewrite_manifest_requested:
        return jobs
    try:
        source_run_ids = source_manifest_run_ids(manifest_path, build_root)
        if source_run_ids and source_run_ids != {verified_run_id}:
            raise ValueError(
                "refusing to rewrite full-matrix manifest: source verified_run_id does not match --verified-run-id"
            )
        sealed_receipt_path = aggregate_receipt_path(build_root, verified_run_id)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        rewrite_manifest(manifest_path, jobs, sealed_receipt_path=sealed_receipt_path)
    except ValueError as exc:
        parser.error(str(exc))
    return collect_jobs(matrix_root, manifest_path)


def build_report_payload(
    *,
    connector_root: Path,
    framework_root: Path,
    matrix_root: Path,
    manifest_path: Path,
    verified_run_id: str,
    verified_commands: Path,
    jobs: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    complete = sum(1 for job in jobs if job["status"] in {"completed", "completed_with_mismatches"})
    manifest_recorded = sum(1 for job in jobs if job["manifest_recorded"])
    missing = [job for job in jobs if job["status"] not in {"completed", "completed_with_mismatches"}]
    slowest = sorted(
        [job for job in jobs if isinstance(job.get("duration_seconds"), int)],
        key=lambda item: int(item["duration_seconds"]),
        reverse=True,
    )[:5]
    inputs = [
        file_record(manifest_path, "full_matrix_manifest"),
        file_record(verified_commands, "verified_commands"),
    ]
    for job in jobs:
        inputs.extend(item for item in job["input_hashes"] if item["status"] == "present")
    dedup_inputs = {item["path"]: item for item in inputs}
    payload = {
        "verified_run_id": verified_run_id,
        "generated_at_utc": utc_now(),
        "data_source_policy": DATA_SOURCE_POLICY,
        "connector_sha": git_sha(connector_root),
        "framework_sha": git_sha(framework_root),
        "matrix_root": str(matrix_root),
        "manifest_path": str(manifest_path),
        "total_jobs": len(jobs),
        "complete_jobs": complete,
        "manifest_recorded_jobs": manifest_recorded,
        "missing_jobs": missing,
        "missing_job_ids": [job["job_id"] for job in missing],
        "overall_status": "complete" if complete == len(jobs) else "incomplete",
        "evidence_scope": "full" if complete == len(jobs) else "partial",
        "jobs": jobs,
        "slowest_jobs": slowest,
        "nginx_with_crs_with_mrts_analysis": analyze_nginx_with_crs_mrts(matrix_root),
        "inputs": list(dedup_inputs.values()),
    }
    return payload, dedup_inputs


def write_generated_report(output_dir: Path, payload: dict[str, Any], metadata: dict[str, Any]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / GENERATED_REPORTS["full_matrix_job_completeness"].filename("json")
    md_path = output_dir / GENERATED_REPORTS["full_matrix_job_completeness"].filename("md")
    json_path.write_text(generated_json_text(payload, metadata), encoding="utf-8")
    md_path.write_text(generated_markdown_text(render_markdown(payload), metadata), encoding="utf-8")
    return md_path


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()
    (
        connector_root,
        framework_root,
        build_root,
        output_dir,
        matrix_root,
        manifest_path,
        verified_run_id,
        verified_commands,
    ) = resolve_generation_context(args)
    jobs = collect_jobs(matrix_root, manifest_path)
    jobs = rewrite_manifest_when_requested(
        parser,
        rewrite_manifest_requested=args.rewrite_manifest,
        manifest_path=manifest_path,
        jobs=jobs,
        build_root=build_root,
        verified_run_id=verified_run_id,
        matrix_root=matrix_root,
    )
    payload, dedup_inputs = build_report_payload(
        connector_root=connector_root,
        framework_root=framework_root,
        matrix_root=matrix_root,
        manifest_path=manifest_path,
        verified_run_id=verified_run_id,
        verified_commands=verified_commands,
        jobs=jobs,
    )
    metadata = build_metadata(
        generated_by=GENERATED_REPORTS["full_matrix_job_completeness"].generator,
        make_target=GENERATED_REPORTS["full_matrix_job_completeness"].make_target,
        connector_root=connector_root,
        framework_root=framework_root,
        report_key="full_matrix_job_completeness",
        inputs=[item["path"] for item in dedup_inputs.values()],
        extra={"verified_run_id": verified_run_id},
    )
    print(write_generated_report(output_dir, payload, metadata))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
