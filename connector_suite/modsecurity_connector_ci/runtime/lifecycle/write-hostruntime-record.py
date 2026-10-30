#!/usr/bin/env python3
"""Project a finalized lifecycle result into a bounded hostruntime record.

This writer is deliberately a projection, not a lifecycle runner.  It never
starts a process and it never treats the presence of a log as proof of a
successful host run.  PASS requires an explicit, boolean proof for every
required lifecycle dimension in the final result.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any




from modsecurity_connector_ci.lib.runtime_path_utils import open_runtime_artifact_parent, prepare_verified_runtime_artifact_root, read_runtime_artifact_text, require_regular_runtime_artifact, runtime_artifact_path, write_runtime_artifact_text_atomic


STATUS_VALUES = {"PASS", "FAIL", "BLOCKED", "NOT_RUN", "NOT_APPLICABLE"}
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
REQUIRED = ("process", "config", "readiness", "interaction", "result", "cleanup")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MANIFEST_FILENAME = "manifest.json"
HOSTRUNTIME_RECORD_ARTIFACT = "hostruntime record"
HOSTRUNTIME_SUMMARY_ARTIFACT = "hostruntime summary"
NON_PRODUCED_ARTIFACT_STATES = {"not_produced", "not_applicable"}
SELF_ARTIFACT_PATHS = {"result": "result.json", "manifest": MANIFEST_FILENAME}


def safe_token(value: object, name: str) -> str:
    if not isinstance(value, str) or not SAFE_TOKEN.fullmatch(value.strip()):
        raise ValueError(f"{name} must be a bounded ASCII token")
    return value.strip()


def optional_token(value: object) -> str | None:
    """Keep optional provenance fields bounded without failing finalization."""

    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized if SAFE_TOKEN.fullmatch(normalized) else None


def load_result(runtime_root: Path, path: Path) -> dict[str, Any]:
    target = runtime_artifact_path(runtime_root, path, "result", must_exist=True)
    value = json.loads(read_runtime_artifact_text(runtime_root, target, "result"))
    if not isinstance(value, dict):
        raise ValueError("result must be a JSON object")
    return value


def load_json_artifact(runtime_root: Path, path: Path, label: str) -> dict[str, Any]:
    target = runtime_artifact_path(runtime_root, path, label, must_exist=True)
    try:
        value = json.loads(read_runtime_artifact_text(runtime_root, target, label))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot parse {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def relative_run_artifact(
    runtime_root: Path, run_dir: Path, value: Path, label: str, *, must_exist: bool
) -> tuple[Path, str]:
    target = runtime_artifact_path(runtime_root, value, label, must_exist=must_exist)
    try:
        relative = target.relative_to(run_dir)
    except ValueError as exc:
        raise ValueError(f"{label} must be below the canonical run directory") from exc
    if relative == Path(".") or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError(f"{label} has an unsafe relative path")
    return target, relative.as_posix()


def relative_declared_artifact(
    runtime_root: Path, run_dir: Path, value: object, label: str, *, must_exist: bool = True
) -> tuple[Path, str]:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} path must be a non-empty relative string")
    relative = Path(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError(f"{label} path must be a safe relative path")
    return relative_run_artifact(
        runtime_root, run_dir, run_dir / relative, label, must_exist=must_exist
    )


def artifact_sha256(runtime_root: Path, path: Path, label: str) -> str:
    """Hash original artifact bytes through the existing safe read boundary."""
    target = runtime_artifact_path(runtime_root, path, label, must_exist=True)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ValueError("safe runtime artifact reads require O_NOFOLLOW")
    parent_descriptor = open_runtime_artifact_parent(target)
    descriptor = -1
    try:
        descriptor = os.open(target.name, os.O_RDONLY | no_follow, dir_fd=parent_descriptor)
        require_regular_runtime_artifact(descriptor, label)
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            digest = hashlib.sha256()
            while chunk := stream.read(1 << 20):
                digest.update(chunk)
            return digest.hexdigest()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def artifact_map(value: dict[str, Any], label: str) -> dict[str, Any]:
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError(f"{label} artifacts must be a JSON object")
    return artifacts


def artifact_name(name: object, label: str) -> str:
    if not isinstance(name, str) or not name:
        raise ValueError(f"{label} artifact names must be non-empty strings")
    return name


def reject_reserved_artifact_path(path: Path, label: str, reserved_paths: set[Path]) -> None:
    if path in reserved_paths:
        raise ValueError(f"{label} uses a reserved lifecycle path")


def optional_manifest_checksum(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ValueError(f"{label} checksum is invalid")
    return value


def required_manifest_checksum(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ValueError(f"{label} checksum is invalid")
    return value


def manifest_artifact_state(value: dict[str, Any], label: str) -> str:
    state = value.get("state")
    if not isinstance(state, str) or not state.strip():
        raise ValueError(f"{label} state is invalid")
    return state


def validate_result_artifact(
    runtime_root: Path,
    run_dir: Path,
    name: object,
    value: object,
    reserved_paths: set[Path],
) -> None:
    name = artifact_name(name, "result")
    label = f"result artifact {name}"
    if name in SELF_ARTIFACT_PATHS:
        if value != SELF_ARTIFACT_PATHS[name]:
            raise ValueError(f"{label} path is not canonical")
        return
    path, _ = relative_declared_artifact(runtime_root, run_dir, value, label)
    reject_reserved_artifact_path(path, label, reserved_paths)


def validate_result_artifacts(
    runtime_root: Path,
    run_dir: Path,
    artifacts: dict[str, Any],
    reserved_paths: set[Path],
) -> None:
    for name, value in artifacts.items():
        validate_result_artifact(runtime_root, run_dir, name, value, reserved_paths)


def validate_self_manifest_artifact(
    runtime_root: Path,
    run_dir: Path,
    name: str,
    value: dict[str, Any],
    state: str,
) -> None:
    label = f"manifest artifact {name}"
    if value.get("path") != SELF_ARTIFACT_PATHS[name]:
        raise ValueError(f"{label} path is not canonical")
    if state != "produced":
        raise ValueError(f"{label} state is not produced")
    checksum = optional_manifest_checksum(value.get("sha256"), label)
    if name != "result" or checksum is None:
        return
    result_path, _ = relative_declared_artifact(
        runtime_root,
        run_dir,
        SELF_ARTIFACT_PATHS["result"],
        "manifest result artifact",
    )
    if artifact_sha256(runtime_root, result_path, "manifest result artifact") != checksum:
        raise ValueError("manifest result artifact checksum does not match")


def validate_non_produced_manifest_artifact(
    runtime_root: Path,
    run_dir: Path,
    value: dict[str, Any],
    label: str,
    reserved_paths: set[Path],
) -> None:
    declared_path = value.get("path")
    if declared_path is not None:
        path, _ = relative_declared_artifact(
            runtime_root, run_dir, declared_path, label, must_exist=False
        )
        reject_reserved_artifact_path(path, label, reserved_paths)
        if path.exists():
            raise ValueError(f"{label} non-produced target exists")
    optional_manifest_checksum(value.get("sha256"), label)


def validate_produced_manifest_artifact(
    runtime_root: Path,
    run_dir: Path,
    value: dict[str, Any],
    label: str,
    reserved_paths: set[Path],
) -> None:
    path, _ = relative_declared_artifact(runtime_root, run_dir, value.get("path"), label)
    reject_reserved_artifact_path(path, label, reserved_paths)
    checksum = required_manifest_checksum(value.get("sha256"), label)
    if artifact_sha256(runtime_root, path, label) != checksum:
        raise ValueError(f"{label} checksum does not match")


def validate_manifest_artifact(
    runtime_root: Path,
    run_dir: Path,
    name: object,
    value: object,
    reserved_paths: set[Path],
) -> None:
    name = artifact_name(name, "manifest")
    label = f"manifest artifact {name}"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    state = manifest_artifact_state(value, label)
    if name in SELF_ARTIFACT_PATHS:
        validate_self_manifest_artifact(runtime_root, run_dir, name, value, state)
        return
    if state in NON_PRODUCED_ARTIFACT_STATES:
        validate_non_produced_manifest_artifact(
            runtime_root, run_dir, value, label, reserved_paths
        )
        return
    if state != "produced":
        raise ValueError(f"{label} state is unsupported")
    validate_produced_manifest_artifact(runtime_root, run_dir, value, label, reserved_paths)


def validate_manifest_artifacts(
    runtime_root: Path,
    run_dir: Path,
    artifacts: dict[str, Any],
    reserved_paths: set[Path],
) -> None:
    for name, value in artifacts.items():
        validate_manifest_artifact(runtime_root, run_dir, name, value, reserved_paths)


def validate_artifact_maps(
    runtime_root: Path,
    run_dir: Path,
    result: dict[str, Any],
    manifest: dict[str, Any],
    reserved_paths: set[Path],
) -> None:
    result_artifacts = artifact_map(result, "result")
    manifest_artifacts = artifact_map(manifest, "manifest")
    validate_result_artifacts(runtime_root, run_dir, result_artifacts, reserved_paths)
    validate_manifest_artifacts(runtime_root, run_dir, manifest_artifacts, reserved_paths)


def project_manifest(
    runtime_root: Path,
    result_path: Path,
    manifest_path: Path,
    output_path: Path,
    summary_path: Path | None,
) -> None:
    result_target = runtime_artifact_path(runtime_root, result_path, "result", must_exist=True)
    manifest_target = runtime_artifact_path(runtime_root, manifest_path, "manifest", must_exist=True)
    run_dir = result_target.parent
    if manifest_target != run_dir / MANIFEST_FILENAME:
        raise ValueError("manifest must be the canonical run manifest.json")
    relative_run_artifact(
        runtime_root, run_dir, output_path, HOSTRUNTIME_RECORD_ARTIFACT, must_exist=True
    )
    if summary_path is not None:
        relative_run_artifact(
            runtime_root, run_dir, summary_path, HOSTRUNTIME_SUMMARY_ARTIFACT, must_exist=True
        )
    if output_path in {result_target, manifest_target} or summary_path in {result_target, manifest_target}:
        raise ValueError("hostruntime outputs must not replace result or manifest")
    result = load_json_artifact(runtime_root, result_target, "result")
    manifest = load_json_artifact(runtime_root, manifest_target, "manifest")
    validate_artifact_maps(
        runtime_root,
        run_dir,
        result,
        manifest,
        {result_target, manifest_target},
    )
    record_relative = relative_run_artifact(
        runtime_root,
        run_dir,
        output_path,
        HOSTRUNTIME_RECORD_ARTIFACT,
        must_exist=True,
    )[1]
    result_artifacts = result["artifacts"]
    manifest_artifacts = manifest["artifacts"]
    result_artifacts["hostruntime_record"] = record_relative
    manifest_artifacts["hostruntime_record"] = {
        "path": record_relative,
        "state": "produced",
        "sha256": artifact_sha256(runtime_root, output_path, HOSTRUNTIME_RECORD_ARTIFACT),
    }
    if summary_path is not None:
        summary_relative = relative_run_artifact(
            runtime_root,
            run_dir,
            summary_path,
            HOSTRUNTIME_SUMMARY_ARTIFACT,
            must_exist=True,
        )[1]
        result_artifacts["hostruntime_summary"] = summary_relative
        manifest_artifacts["hostruntime_summary"] = {
            "path": summary_relative,
            "state": "produced",
            "sha256": artifact_sha256(
                runtime_root, summary_path, HOSTRUNTIME_SUMMARY_ARTIFACT
            ),
        }
    result_serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
    result_sha256 = hashlib.sha256(result_serialized.encode("utf-8")).hexdigest()
    manifest_artifacts["result"] = {
        "path": SELF_ARTIFACT_PATHS["result"],
        "state": "produced",
        "sha256": result_sha256,
    }
    manifest_serialized = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    write_runtime_artifact_text_atomic(runtime_root, result_target, result_serialized, "result")
    write_runtime_artifact_text_atomic(runtime_root, manifest_target, manifest_serialized, "manifest")


def preflight_manifest_projection(
    runtime_root: Path,
    result_path: Path,
    manifest_path: Path,
    output_path: Path,
    summary_path: Path | None,
) -> None:
    result_target = runtime_artifact_path(runtime_root, result_path, "result", must_exist=True)
    manifest_target = runtime_artifact_path(runtime_root, manifest_path, "manifest", must_exist=True)
    run_dir = result_target.parent
    if manifest_target != run_dir / MANIFEST_FILENAME:
        raise ValueError("manifest must be the canonical run manifest.json")
    result = load_json_artifact(runtime_root, result_target, "result")
    manifest = load_json_artifact(runtime_root, manifest_target, "manifest")
    validate_artifact_maps(
        runtime_root,
        run_dir,
        result,
        manifest,
        {result_target, manifest_target},
    )
    output_target, _ = relative_run_artifact(
        runtime_root,
        run_dir,
        output_path,
        HOSTRUNTIME_RECORD_ARTIFACT,
        must_exist=False,
    )
    if output_target.exists():
        raise ValueError("hostruntime record destination already exists")
    if summary_path is not None:
        summary_target, _ = relative_run_artifact(
            runtime_root,
            run_dir,
            summary_path,
            HOSTRUNTIME_SUMMARY_ARTIFACT,
            must_exist=False,
        )
        if summary_target.exists():
            raise ValueError("hostruntime summary destination already exists")
    if output_path in {result_target, manifest_target} or summary_path in {result_target, manifest_target}:
        raise ValueError("hostruntime outputs must not replace result or manifest")


def explicit_status(value: object) -> str | None:
    if value is True:
        return "PASS"
    if value is False:
        return "FAIL"
    if not isinstance(value, str):
        return None
    normalized = value.strip().upper().replace("-", "_")
    if normalized in {"PASS", "PASSED", "VERIFIED", "COMPLETE", "TRUE"}:
        return "PASS"
    if normalized in {"FAIL", "FAILED", "FALSE"}:
        return "FAIL"
    if normalized in {"BLOCKED", "NOT_RUN", "NOT_APPLICABLE"}:
        return normalized
    return None


ALIASES = {
    "process": ("host_process_verified", "process_verified", "process_status"),
    "config": ("config_loaded", "configuration_loaded", "config_status"),
    "readiness": ("readiness_verified", "readiness_status"),
    "interaction": ("interaction_verified", "real_interaction", "interaction_status"),
    "result": ("result_verified", "result_status", "evaluation_status"),
    "cleanup": ("cleanup_verified", "cleanup_status"),
}


def evidence_status(result: dict[str, Any]) -> tuple[dict[str, str], str | None]:
    evidence = result.get("hostruntime_evidence")
    if not isinstance(evidence, dict):
        evidence = result.get("evidence")
    if not isinstance(evidence, dict):
        return {}, "missing_evidence_object"
    statuses: dict[str, str] = {}
    for dimension in REQUIRED:
        value = next((evidence[name] for name in ALIASES[dimension] if name in evidence), None)
        status = explicit_status(value)
        if status is None:
            return statuses, f"missing_evidence:{dimension}"
        statuses[dimension] = status
        if status != "PASS":
            return statuses, f"{dimension}:{status}"
    return statuses, None


def project(args: argparse.Namespace) -> dict[str, Any]:
    result = load_result(args.runtime_root, Path(args.result))
    # The finalizer's result may contain established, payload-free metadata
    # such as ``request_body_verified`` or ``body_payload_absent_from_events``.
    # Project only the allowlisted fields below; never reject the whole source
    # object and never copy arbitrary source keys into this record.
    connector = safe_token(args.connector, "connector")
    profile = safe_token(args.profile, "profile")
    source_status = explicit_status(result.get("status"))
    statuses, reason = evidence_status(result)
    if source_status == "FAIL" and reason is not None and (
        reason.startswith("missing_") or reason.endswith(":BLOCKED") or reason.endswith(":NOT_RUN")
    ):
        # A source failure without a complete host proof is an evidence gap,
        # not a connector/product failure attributable to this projection.
        final_status = "BLOCKED"
        reason = f"incomplete_hostruntime_evidence:{reason}"
    elif source_status in {"FAIL", "NOT_RUN", "NOT_APPLICABLE"}:
        final_status = source_status
        reason = f"source_result:{source_status}"
    elif source_status != "PASS":
        final_status = "BLOCKED"
        reason = "source_result_status_missing_or_not_pass"
    elif reason is None:
        final_status = "PASS"
        reason = "all_required_hostruntime_evidence_verified"
    elif reason.split(":", 1)[-1] in STATUS_VALUES:
        final_status = "BLOCKED" if "BLOCKED" in reason or "NOT_" in reason else "FAIL"
    else:
        final_status = "BLOCKED"
    record: dict[str, Any] = {
        "schema_version": "hostruntime-record-v1",
        "connector": connector,
        "profile": profile,
        "status": final_status,
        "reason": reason,
        "evidence": {name: statuses.get(name, "NOT_RUN") for name in REQUIRED},
        "runtime_lock_id": optional_token(args.runtime_lock_id),
        "expected_version": optional_token(args.expected_version),
        "actual_version": optional_token(args.actual_version),
        "timestamp": args.timestamp or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary")
    parser.add_argument("--manifest")
    parser.add_argument("--runtime-root", required=True)
    parser.add_argument("--connector", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--runtime-lock-id")
    parser.add_argument("--expected-version")
    parser.add_argument("--actual-version")
    parser.add_argument("--timestamp")
    args = parser.parse_args(argv)
    try:
        runtime_root = prepare_verified_runtime_artifact_root(args.runtime_root)
        args.runtime_root = runtime_root
        if args.manifest:
            preflight_manifest_projection(
                runtime_root,
                Path(args.result),
                Path(args.manifest),
                Path(args.output),
                Path(args.summary) if args.summary else None,
            )
        record = project(args)
        serialized = json.dumps(record, indent=2, sort_keys=True) + "\n"
        write_runtime_artifact_text_atomic(
            runtime_root, Path(args.output), serialized, "output"
        )
        if args.summary:
            summary = (f"status={record['status']}\nconnector={record['connector']}\n"
                       f"profile={record['profile']}\nreason={record['reason']}\n")
            write_runtime_artifact_text_atomic(
                runtime_root, Path(args.summary), summary, "summary"
            )
        if args.manifest:
            project_manifest(
                runtime_root,
                Path(args.result),
                Path(args.manifest),
                Path(args.output),
                Path(args.summary) if args.summary else None,
            )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
