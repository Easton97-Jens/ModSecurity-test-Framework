#!/usr/bin/env python3
"""Collect and sanitize host-runtime preflight evidence for one connector.

The connector workflows intentionally remain responsible for their trigger,
job, profile selection, and artifact upload.  This helper centralizes only the
otherwise identical preflight invocation and payload-safe evidence projection.
It never executes a shell, reads secrets, or writes outside ``RUNNER_TEMP``.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
from typing import Any




from modsecurity_connector_ci.lib.runtime_path_utils import read_runtime_artifact_text, runtime_artifact_path, verified_runtime_artifact_root, write_runtime_artifact_text_atomic


ALLOWED_STATUSES = frozenset({"PASS", "FAIL", "BLOCKED", "NOT_RUN", "NOT_APPLICABLE"})
SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", re.ASCII)
CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
PREFLIGHT_SCRIPT = Path(__file__).with_name("hostruntime-preflight.py")
PREFLIGHT_STATUS_OUTPUT_LABEL = "preflight status output"


@dataclass(frozen=True)
class ProfileSpec:
    """The repository-reviewed inputs for one locked runtime profile."""

    profile: str
    config: str
    fixture: str


def clean(value: object, limit: int = 160) -> str:
    """Bound arbitrary preflight fields before they enter published evidence."""

    return CONTROL_CHARACTERS.sub(" ", str(value))[:limit]


def safe_component(value: str, option: str) -> str:
    """Accept one simple filesystem component for a connector/profile/tool name."""

    if not SAFE_COMPONENT.fullmatch(value):
        raise ValueError(f"{option} must be one safe path component")
    return value


def safe_relative_path(value: str, option: str) -> str:
    """Reject absolute and traversing repository-relative preflight inputs."""

    path = PurePosixPath(value)
    if (
        not value
        or "\x00" in value
        or path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"{option} must be a safe repository-relative path")
    return value


def project_preflight_record(
    raw_value: object,
    *,
    connector: str,
    profile: str,
    exit_code: int,
) -> dict[str, object]:
    """Return the exact bounded record allowed into the uploaded artifact."""

    raw = raw_value if isinstance(raw_value, dict) else {}
    status = raw.get("status")
    reason_code = raw.get("reason_code", "")
    runtime_lock = raw.get("runtime_lock")
    checks = raw.get("checks")
    host = raw.get("host")
    checks = checks if isinstance(checks, list) else []
    host = host if isinstance(host, dict) else {}
    binary_reasons = sorted(
        {
            reason
            for item in checks
            if isinstance(item, dict)
            for reason in (item.get("reason_code", ""),)
            if isinstance(reason, str) and reason.startswith("binary_")
        }
    )

    if status not in ALLOWED_STATUSES:
        status = "BLOCKED"
        reason_code = "invalid_or_missing_preflight_status"
    elif exit_code != 0 and status == "PASS":
        status = "BLOCKED"
        reason_code = "preflight_exit_without_pass_evidence"
    elif not isinstance(runtime_lock, dict) or not raw.get("lock_profile"):
        status = "BLOCKED"
        reason_code = "runtime_lock_missing"
    elif binary_reasons:
        status = "BLOCKED"
        reason_code = binary_reasons[0]

    return {
        "schema_version": 1,
        "evidence_kind": "preflight",
        "connector": connector,
        "profile": clean(raw.get("profile", profile), 120),
        "lock_profile": clean(raw.get("lock_profile", profile), 120),
        "status": status,
        "runtime_status": "NOT_RUN",
        "reason_code": clean(reason_code, 100),
        "exit_code": exit_code,
        "expected_version": clean(raw.get("expected_version", ""), 80),
        "actual_version": clean(raw.get("actual_version", ""), 80),
        "host": {
            "os": clean(host.get("os", ""), 32),
            "arch": clean(host.get("arch", ""), 32),
        },
        "runtime_lock": {
            "name": clean(runtime_lock.get("name", ""), 80)
            if isinstance(runtime_lock, dict)
            else "",
            "asset_id": clean(runtime_lock.get("asset_id", ""), 120)
            if isinstance(runtime_lock, dict)
            else "",
        },
    }


def write_record(
    root: Path,
    path: Path,
    payload: dict[str, object],
    label: str,
) -> None:
    """Write one canonical JSON payload without retaining untrusted raw data."""

    write_runtime_artifact_text_atomic(
        root,
        path,
        json.dumps(payload, sort_keys=True) + "\n",
        label,
    )


def markdown_value(value: object, markdown_code: bool) -> str:
    """Preserve the existing NGINX summary formatting without changing payloads."""

    rendered = str(value)
    return f"`{rendered}`" if markdown_code else rendered


def run_preflight(command: list[str]) -> int:
    """Run the existing preflight wrapper without shell interpolation."""

    try:
        return subprocess.run(command, check=False).returncode
    except OSError:
        # Match the former shell's fail-closed collection behavior: a missing
        # interpreter still produces a BLOCKED sanitized record and artifact.
        return 127


def collect(
    *,
    connector: str,
    runtime_lock: str,
    runner_temp: Path,
    binary_name: str,
    profiles: Sequence[ProfileSpec],
    markdown_code: bool,
    command_runner: Callable[[list[str]], int] = run_preflight,
) -> Path:
    """Collect all profile records and the connector-level runtime placeholder."""

    evidence_dir = verified_runtime_artifact_root(
        runner_temp / "hostruntime-evidence" / connector
    )
    binary_path = shutil.which(binary_name) or str(
        evidence_dir / f"hostruntime-missing-{binary_name}"
    )
    records: list[dict[str, object]] = []

    for spec in profiles:
        status_path = runtime_artifact_path(
            evidence_dir,
            evidence_dir / "preflight" / spec.profile / "status.json",
            PREFLIGHT_STATUS_OUTPUT_LABEL,
        )
        exit_code = command_runner(
            [
                sys.executable,
                str(PREFLIGHT_SCRIPT),
                "--connector",
                connector,
                "--profile",
                spec.profile,
                "--runtime-root",
                str(evidence_dir),
                "--runtime-lock",
                runtime_lock,
                "--lock-profile",
                spec.profile,
                "--binary",
                binary_path,
                "--expected-os",
                "linux",
                "--expected-arch",
                "amd64",
                "--write-dir",
                str(runner_temp),
                "--disk-path",
                str(runner_temp),
                "--min-free-bytes",
                "104857600",
                "--config",
                spec.config,
                "--fixture",
                spec.fixture,
                "--tool",
                "python3",
                "--tool",
                "make",
                "--output",
                str(status_path),
            ]
        )
        try:
            raw_value: object = json.loads(
                read_runtime_artifact_text(
                    evidence_dir,
                    status_path,
                    PREFLIGHT_STATUS_OUTPUT_LABEL,
                )
            )
        except (OSError, ValueError):
            raw_value = {}
        record = project_preflight_record(
            raw_value,
            connector=connector,
            profile=spec.profile,
            exit_code=exit_code,
        )
        write_record(evidence_dir, status_path, record, PREFLIGHT_STATUS_OUTPUT_LABEL)
        write_runtime_artifact_text_atomic(
            evidence_dir,
            status_path.parent / "summary.md",
            f"# {connector} {record['lock_profile']} preflight\n\n"
            f"- status: {markdown_value(record['status'], markdown_code)}\n"
            f"- reason_code: {markdown_value(record['reason_code'], markdown_code)}\n"
            f"- runtime_status: {markdown_value('NOT_RUN', markdown_code)}\n",
            "preflight summary output",
        )
        records.append(record)

    preflight_status = (
        "PASS" if records and all(record["status"] == "PASS" for record in records) else "BLOCKED"
    )
    runtime_reason = (
        "runtime_execution_not_configured"
        if preflight_status == "PASS"
        else "preflight_blocked"
    )
    runtime_record = {
        "schema_version": 1,
        "evidence_kind": "runtime",
        "connector": connector,
        "status": "NOT_RUN",
        "runtime_status": "NOT_RUN",
        "reason_code": runtime_reason,
        "preflight_status": preflight_status,
        "profiles": [record["lock_profile"] for record in records],
    }
    write_record(
        evidence_dir,
        evidence_dir / "hostruntime-record.json",
        runtime_record,
        "host-runtime record",
    )
    write_runtime_artifact_text_atomic(
        evidence_dir,
        evidence_dir / "summary.md",
        f"# {connector} host-runtime evidence\n\n"
        f"- preflight_status: {markdown_value(preflight_status, markdown_code)}\n"
        f"- runtime_status: {markdown_value('NOT_RUN', markdown_code)}\n"
        f"- reason_code: {markdown_value(runtime_reason, markdown_code)}\n",
        "host-runtime summary",
    )
    return evidence_dir


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse a deliberately narrow connector-workflow invocation."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector", required=True)
    parser.add_argument("--runtime-lock", required=True)
    parser.add_argument("--runner-temp", required=True)
    parser.add_argument("--binary-name", required=True)
    parser.add_argument("--profile", action="append", default=[])
    parser.add_argument("--config", action="append", default=[])
    parser.add_argument("--fixture", action="append", default=[])
    parser.add_argument("--markdown-code", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Validate workflow constants, then collect the sanitized evidence artifact."""

    args = parse_args(argv)
    try:
        connector = safe_component(args.connector, "--connector")
        binary_name = safe_component(args.binary_name, "--binary-name")
        runtime_lock = safe_relative_path(args.runtime_lock, "--runtime-lock")
        if not args.profile or not (
            len(args.profile) == len(args.config) == len(args.fixture)
        ):
            raise ValueError("--profile, --config, and --fixture require matching non-empty counts")
        profiles = tuple(
            ProfileSpec(
                profile=safe_component(profile, "--profile"),
                config=safe_relative_path(config, "--config"),
                fixture=safe_relative_path(fixture, "--fixture"),
            )
            for profile, config, fixture in zip(args.profile, args.config, args.fixture)
        )
        runner_temp = Path(args.runner_temp)
        if not runner_temp.is_absolute() or "\x00" in args.runner_temp:
            raise ValueError("--runner-temp must be an absolute path")
    except ValueError as error:
        print(f"hostruntime evidence collector error: {error}", file=sys.stderr)
        return 2

    collect(
        connector=connector,
        runtime_lock=runtime_lock,
        runner_temp=runner_temp,
        binary_name=binary_name,
        profiles=profiles,
        markdown_code=args.markdown_code,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
