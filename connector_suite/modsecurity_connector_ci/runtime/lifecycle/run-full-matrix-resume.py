#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from modsecurity_test_framework.connector_context import source_path as framework_source_path
from pathlib import Path

# CI helpers are shared from ci/lib even when this file is executed directly.


from modsecurity_connector_ci.lib.runtime_path_utils import canonical_project_roots, ensure_safe_writable_runtime_paths, verified_runtime_paths
from modsecurity_connector_ci.lib.verified_run_id import VerifiedRunIdError, validate_verified_run_id


CONNECTORS = frozenset(("apache", "nginx", "haproxy"))
CRS_VARIANTS = frozenset(("no-crs", "with-crs"))
MRTS_VARIANTS = frozenset(("no-mrts", "with-mrts"))
MAX_JOB_TIMEOUT_SECONDS = 86_400


def canonical_roots(connector_root: str, framework_root: str | None) -> tuple[Path, Path]:
    """Bind child-process paths to this checkout, never CLI-selected code."""

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


def missing_job_identity(job: object) -> tuple[str, str, str, str]:
    """Return only allow-listed matrix tokens for a subprocess invocation."""

    if not isinstance(job, dict):
        raise ValueError("matrix completeness entry must be an object")
    connector = str(job.get("connector") or "")
    crs = str(job.get("crs") or "")
    mrts = str(job.get("mrts") or "")
    if connector not in CONNECTORS or crs not in CRS_VARIANTS or mrts not in MRTS_VARIANTS:
        raise ValueError(
            "matrix completeness entry contains an unsupported connector/CRS/MRTS variant"
        )
    return connector, crs, mrts, f"{connector}:{crs}:{mrts}"


def read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def run_completeness(connector_root: Path, framework_root: Path, build_root: Path, verified_run_id: str) -> int:
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
    commands_file = os.environ.get("VERIFIED_RUN_COMMANDS_FILE", "")
    if commands_file:
        cmd.extend(["--verified-commands-file", commands_file])
    return subprocess.run(cmd, cwd=str(connector_root)).returncode


def load_missing(connector_root: Path) -> list[dict]:
    path = connector_root / "reports/testing/generated/manifest/full-matrix-job-completeness.generated.json"
    data = read_json(path)
    jobs = data.get("jobs") if isinstance(data.get("jobs"), list) else []
    return [job for job in jobs if job.get("status") not in {"completed", "completed_with_mismatches"}]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector-root", default=".")
    parser.add_argument("--framework-root", default=None)
    parser.add_argument("--build-root", default=os.environ.get("BUILD_ROOT"))
    parser.add_argument("--job-timeout-seconds", type=int, default=int(os.environ.get("VERIFIED_RUN_FULL_MATRIX_JOB_TIMEOUT_SECONDS", "3600")))
    parser.add_argument("--total-timeout-seconds", type=int, default=int(os.environ.get("VERIFIED_RUN_FULL_MATRIX_TOTAL_TIMEOUT_SECONDS", "14400")))
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def runtime_context(args: argparse.Namespace) -> tuple[Path, Path, Path, str]:
    """Resolve canonical sources and the verified runtime identity once."""

    connector_root, framework_root = canonical_roots(args.connector_root, args.framework_root)
    build_root_override = Path(os.path.abspath(args.build_root)) if args.build_root else None
    paths = verified_runtime_paths(
        os.environ,
        build_root_override=build_root_override,
    )
    ensure_safe_writable_runtime_paths(paths)
    build_root = Path(paths["BUILD_ROOT"])
    current = build_root / "verified-runs/current-run-id"
    verified_run_id = os.environ.get("VERIFIED_RUN_ID") or (current.read_text(encoding="utf-8").strip() if current.is_file() else "")
    return connector_root, framework_root, build_root, validate_verified_run_id(verified_run_id)


def remaining_job_identifiers(missing: list[dict]) -> str:
    """Render untrusted report rows only as non-executable status text."""

    return ", ".join(str(job.get("job_id")) for job in missing)


def decimal_timeout_argument(value: int) -> str:
    """Validate and render the only numeric child-process argument."""

    if not 1 <= value <= MAX_JOB_TIMEOUT_SECONDS:
        raise ValueError(f"job timeout must be between 1 and {MAX_JOB_TIMEOUT_SECONDS} seconds")
    return f"{value:d}"


def run_missing_job(
    job: object,
    args: argparse.Namespace,
    connector_root: Path,
    framework_root: Path,
    build_root: Path,
    remaining_seconds: float,
) -> int:
    """Invoke one allow-listed missing job with a bounded remaining timeout."""

    connector, crs, mrts, job_id = missing_job_identity(job)
    timeout = min(args.job_timeout_seconds, max(1, int(remaining_seconds)))
    cmd = [
        sys.executable,
        str(framework_source_path("ci/runtime/lifecycle/run-full-matrix-job.py", root=connector_root)),
        "--connector", connector,
        "--crs", crs,
        "--mrts", mrts,
        "--connector-root", str(connector_root),
        "--framework-root", str(framework_root),
        "--build-root", str(build_root),
        "--timeout-seconds", decimal_timeout_argument(timeout),
    ]
    if args.force:
        cmd.append("--force")
    print(f"full-matrix-resume: run {job_id} timeout={timeout}s", flush=True)
    return subprocess.run(
        cmd,
        cwd=str(connector_root),
        env=dict(os.environ),
        shell=False,
    ).returncode


def main() -> int:
    args = parse_args()
    try:
        connector_root, framework_root, build_root, verified_run_id = runtime_context(args)
    except (OSError, VerifiedRunIdError) as exc:
        print(f"full-matrix-resume: {exc}", file=sys.stderr)
        return 2

    rc = run_completeness(connector_root, framework_root, build_root, verified_run_id)
    if rc != 0:
        return rc
    missing = load_missing(connector_root)
    if not missing:
        print("full-matrix-resume: all jobs complete")
        return 0

    started = time.monotonic()
    worst_rc = 0
    for job in missing:
        elapsed = time.monotonic() - started
        if elapsed >= args.total_timeout_seconds:
            print(f"full-matrix-resume: total timeout reached after {elapsed:.1f}s")
            return 77
        try:
            job_rc = run_missing_job(
                job, args, connector_root, framework_root, build_root,
                args.total_timeout_seconds - elapsed,
            )
        except ValueError as exc:
            print(f"full-matrix-resume: invalid completeness entry: {exc}")
            return 2
        if job_rc != 0:
            worst_rc = job_rc if worst_rc == 0 else worst_rc
    run_completeness(connector_root, framework_root, build_root, verified_run_id)
    remaining = load_missing(connector_root)
    if remaining:
        print("full-matrix-resume: incomplete jobs remain: " + remaining_job_identifiers(remaining))
        return worst_rc or 77
    return worst_rc


if __name__ == "__main__":
    raise SystemExit(main())
