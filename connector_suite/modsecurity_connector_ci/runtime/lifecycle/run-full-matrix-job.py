#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from modsecurity_test_framework.connector_context import source_path as framework_source_path
from pathlib import Path

# CI helpers are shared from ci/lib even when this file is executed directly.


from modsecurity_connector_ci.lib.generated_report_utils import utc_now
from modsecurity_connector_ci.lib.runtime_path_utils import canonical_project_roots, ensure_safe_writable_runtime_paths, read_runtime_artifact_text, runtime_artifact_path, verified_runtime_paths, write_runtime_artifact_text_atomic
from modsecurity_connector_ci.lib.verified_run_id import VerifiedRunIdError, validate_verified_run_id


CONNECTORS = {"apache", "nginx", "haproxy"}
CRS_VARIANTS = {"no-crs", "with-crs"}
MRTS_VARIANTS = {"no-mrts", "with-mrts"}


def canonical_roots(connector_root: str, framework_root: str | None) -> tuple[Path, Path]:
    """Require child tooling to run from this checked-out Parent/Framework pair."""

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


def safe_token(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in value)


def read_json(root: Path, value: Path | str, label: str) -> dict:
    path = runtime_artifact_path(root, value, label)
    if not path.is_file():
        return {}
    try:
        data = json.loads(read_runtime_artifact_text(root, path, label))
    except (ValueError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def job_root(matrix_root: Path, connector: str, crs: str, mrts: str) -> Path:
    return matrix_root / crs / mrts / connector


def count_jsonl_rows(root: Path, path: Path) -> int:
    try:
        lines = read_runtime_artifact_text(
            root,
            path,
            "matrix results",
            errors="replace",
        ).splitlines()
    except (ValueError, OSError):
        return 0
    count = 0
    for line in lines:
        if line.strip():
            count += 1
    return count


def job_artifacts(root: Path, connector: str) -> dict:
    job_path = root / "job.json"
    data = read_json(root, job_path, "job record")
    summary_path = Path(str(data.get("summary_path") or ""))
    if not summary_path.is_absolute():
        summary_path = root / "results" / "force-all" / f"{connector}-summary.json"
    results_jsonl = root / "results" / "force-all" / f"{connector}-results.jsonl"
    summary = read_json(root, summary_path, "job summary")
    connector_summary = summary.get(connector) if isinstance(summary.get(connector), dict) else {}
    cases = connector_summary.get("cases") if isinstance(connector_summary.get("cases"), dict) else {}
    result_rows = count_jsonl_rows(root, results_jsonl)
    status = str(data.get("status") or "")
    complete = (
        bool(data.get("ended_at"))
        and "return_code" in data
        and status in {"completed", "completed_with_mismatches"}
        and summary_path.is_file()
        and (result_rows > 0 or bool(cases))
    )
    return {
        "complete": complete,
        "job": data,
        "summary_path": str(summary_path),
        "results_jsonl": str(results_jsonl),
        "result_rows": result_rows,
        "summary_cases": len(cases),
    }


def run_completeness(
    connector_root: Path,
    framework_root: Path,
    build_root: Path,
    verified_run_id: str,
    verified_commands_file: str,
) -> int:
    cmd = [
        sys.executable,
        str(framework_source_path("ci/evidence/reports/generate-full-matrix-job-completeness.py", root=connector_root)),
        "--connector-root",
        str(connector_root),
        "--framework-root",
        str(framework_root),
        "--build-root",
        str(build_root),
        "--verified-run-id",
        verified_run_id,
        "--rewrite-manifest",
    ]
    if verified_commands_file:
        cmd.extend(["--verified-commands-file", verified_commands_file])
    return subprocess.run(cmd, cwd=str(connector_root)).returncode


def write_timeout_record(root: Path, connector: str, crs: str, mrts: str, started_at: str, duration: float) -> None:
    root.mkdir(parents=True, exist_ok=True)
    payload = {
        "connector": connector,
        "job_id": f"{connector}:{crs}:{mrts}",
        "test_variant": crs,
        "mrts_variant": mrts,
        "status": "timeout",
        "return_code": -15,
        "started_at": started_at,
        "ended_at": utc_now(),
        "duration_seconds": round(duration, 3),
        "log_path": str(root / "run.log"),
        "results_dir": str(root / "results"),
    }
    write_runtime_artifact_text_atomic(
        root,
        root / "job-timeout.json",
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        "matrix timeout record",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector", required=True, choices=sorted(CONNECTORS))
    parser.add_argument("--crs", required=True, choices=sorted(CRS_VARIANTS))
    parser.add_argument("--mrts", required=True, choices=sorted(MRTS_VARIANTS))
    parser.add_argument("--connector-root", default=".")
    parser.add_argument("--framework-root", default=None)
    parser.add_argument("--build-root", default=os.environ.get("BUILD_ROOT"))
    parser.add_argument("--timeout-seconds", type=int, default=int(os.environ.get("VERIFIED_RUN_FULL_MATRIX_JOB_TIMEOUT_SECONDS", "3600")))
    parser.add_argument("--finalize-grace-seconds", type=int, default=int(os.environ.get("VERIFIED_RUN_JOB_FINALIZE_GRACE_SECONDS", "60")))
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def runtime_context(args: argparse.Namespace) -> tuple[Path, Path, Path, Path, str, str]:
    """Resolve canonical sources and private runtime roots for one matrix job."""

    connector_root, framework_root = canonical_roots(args.connector_root, args.framework_root)
    build_root_override = Path(os.path.abspath(args.build_root)) if args.build_root else None
    paths = verified_runtime_paths(
        os.environ,
        build_root_override=build_root_override,
    )
    ensure_safe_writable_runtime_paths(paths)
    build_root = Path(paths["BUILD_ROOT"])
    matrix_root = Path(paths["MATRIX_ROOT"])
    verified_run_id = os.environ.get("VERIFIED_RUN_ID", "")
    if not verified_run_id:
        current = build_root / "verified-runs/current-run-id"
        verified_run_id = current.read_text(encoding="utf-8").strip() if current.is_file() else utc_now().replace(":", "-")
    verified_run_id = validate_verified_run_id(verified_run_id)
    verified_commands_file = os.environ.get("VERIFIED_RUN_COMMANDS_FILE", "")
    return connector_root, framework_root, build_root, matrix_root, verified_run_id, verified_commands_file


def temporary_job_locations(
    matrix_root: Path, verified_run_id: str, connector: str, crs: str, mrts: str
) -> tuple[Path, Path]:
    """Create private per-job manifest and report directories below the matrix root."""

    stamp = utc_now().replace(":", "-")
    job_name = safe_token(f"{connector}-{crs}-{mrts}")
    manifest = matrix_root / "_job-manifests" / verified_run_id / f"{job_name}-{stamp}.jsonl"
    report_dir = matrix_root / "_job-reports" / verified_run_id / job_name
    manifest.parent.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    return manifest, report_dir


def job_environment(
    connector_root: Path,
    framework_root: Path,
    build_root: Path,
    matrix_root: Path,
    connector: str,
    crs: str,
    mrts: str,
    manifest: Path,
    report_dir: Path,
    verified_run_id: str,
) -> dict[str, str]:
    """Build the bounded child environment without accepting extra CLI paths."""

    env = dict(os.environ)
    env.update(
        {
            "CONNECTOR_ROOT": str(connector_root),
            "FRAMEWORK_ROOT": str(framework_root),
            "BUILD_ROOT": str(build_root),
            "MATRIX_ROOT": str(matrix_root),
            "FULL_MATRIX_VARIANTS": f"{crs}/{mrts}",
            "FULL_MATRIX_CONNECTORS": connector,
            "FULL_MATRIX_MANIFEST": str(manifest),
            "FULL_MATRIX_REPORT_DIR": str(report_dir),
            "FULL_MATRIX_TRUNCATE_MANIFEST": "1",
            "FULL_MATRIX_SKIP_REPORTS": "1",
            "VERIFIED_RUN_ID": verified_run_id,
        }
    )
    return env


def completed_artifact_return_code(root: Path, connector: str, fallback: int) -> int | None:
    """Return the host-recorded result only after the job artifact is complete."""

    artifacts = job_artifacts(root, connector)
    if not artifacts["complete"]:
        return None
    return int(artifacts["job"].get("return_code", fallback))


def record_completeness(
    connector_root: Path,
    framework_root: Path,
    build_root: Path,
    verified_run_id: str,
    verified_commands_file: str,
) -> int:
    """Run the sole completeness publisher after a bounded job outcome."""

    return run_completeness(
        connector_root, framework_root, build_root, verified_run_id, verified_commands_file
    )


def terminate_timed_out_process(process: subprocess.Popen[object]) -> None:
    """Terminate a timed-out process group and wait for its final child state."""

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        process.wait()


def timeout_result(
    process: subprocess.Popen[object],
    root: Path,
    args: argparse.Namespace,
    started_at: str,
    started: float,
    connector_root: Path,
    framework_root: Path,
    build_root: Path,
    verified_run_id: str,
    verified_commands_file: str,
) -> int:
    """Prefer complete host artifacts, otherwise safely end and record the timeout."""

    print(
        f"full-matrix-job: timeout after {args.timeout_seconds}s for {args.connector}:{args.crs}:{args.mrts}",
        flush=True,
    )
    artifact_rc = wait_for_finalize_grace(process, root, args)
    if artifact_rc is not None:
        record_completeness(connector_root, framework_root, build_root, verified_run_id, verified_commands_file)
        return artifact_rc
    artifact_rc = completed_artifact_return_code(root, args.connector, 2)
    if artifact_rc is not None:
        record_completeness(connector_root, framework_root, build_root, verified_run_id, verified_commands_file)
        return artifact_rc
    terminate_timed_out_process(process)
    artifact_rc = completed_artifact_return_code(root, args.connector, 2)
    if artifact_rc is not None:
        record_completeness(connector_root, framework_root, build_root, verified_run_id, verified_commands_file)
        return artifact_rc
    write_timeout_record(root, args.connector, args.crs, args.mrts, started_at, time.monotonic() - started)
    record_completeness(connector_root, framework_root, build_root, verified_run_id, verified_commands_file)
    return 77


def wait_for_finalize_grace(
    process: subprocess.Popen[object], root: Path, args: argparse.Namespace
) -> int | None:
    """Allow a bounded final artifact write after the wrapper timeout fires."""

    if args.finalize_grace_seconds <= 0:
        return None
    print(
        f"full-matrix-job: waiting {args.finalize_grace_seconds}s finalize grace for job artifacts",
        flush=True,
    )
    try:
        return_code = process.wait(timeout=args.finalize_grace_seconds)
    except subprocess.TimeoutExpired:
        return None
    return completed_artifact_return_code(root, args.connector, return_code)


def main() -> int:
    args = parse_args()
    try:
        connector_root, framework_root, build_root, matrix_root, verified_run_id, verified_commands_file = runtime_context(args)
    except (OSError, VerifiedRunIdError) as exc:
        print(f"full-matrix-job: {exc}", file=sys.stderr)
        return 2

    root = job_root(matrix_root, args.connector, args.crs, args.mrts)
    if not args.force and job_artifacts(root, args.connector)["complete"]:
        print(f"full-matrix-job: skip complete job {args.connector}:{args.crs}:{args.mrts}")
        return run_completeness(connector_root, framework_root, build_root, verified_run_id, verified_commands_file)

    temp_manifest, temp_report_dir = temporary_job_locations(
        matrix_root, verified_run_id, args.connector, args.crs, args.mrts
    )
    env = job_environment(
        connector_root, framework_root, build_root, matrix_root,
        args.connector, args.crs, args.mrts, temp_manifest, temp_report_dir, verified_run_id,
    )
    cmd = ["sh", str(framework_source_path("ci/runtime/lifecycle/run-full-matrix-parallel.sh", root=connector_root))]
    started_at = utc_now()
    started = time.monotonic()
    process = subprocess.Popen(cmd, cwd=str(connector_root), env=env, start_new_session=True)
    try:
        rc = process.wait(timeout=args.timeout_seconds)
    except subprocess.TimeoutExpired:
        return timeout_result(
            process, root, args, started_at, started, connector_root, framework_root,
            build_root, verified_run_id, verified_commands_file,
        )

    completeness_rc = run_completeness(connector_root, framework_root, build_root, verified_run_id, verified_commands_file)
    if completeness_rc != 0:
        return completeness_rc
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
