#!/usr/bin/env python3
"""Parent-produced, detached receipts for verified full-matrix runtime evidence.

The matrix child writes job-local files and a raw JSONL manifest.  Those files
are deliberately treated as untrusted inputs here.  The Parent lifecycle
runner calls :func:`seal_full_matrix_aggregate_receipt` only after it has
observed completion of the full runtime command.  Consumers derive the receipt
location rather than trusting a report-declared path.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping

from modsecurity_connector_ci.lib.verified_run_id import VERIFIED_RUN_ID_PATTERN, VerifiedRunIdError, validate_verified_run_id


FULL_MATRIX_CONNECTORS = ("apache", "nginx", "haproxy")
FULL_MATRIX_CRS_VARIANTS = ("no-crs", "with-crs")
FULL_MATRIX_MRTS_VARIANTS = ("no-mrts", "with-mrts")
RECEIPT_FILENAME = "full-matrix-aggregate-receipt.json"
JOB_RECEIPT_FILENAME = "job.json"
FULL_RUNTIME_MATRIX_MANIFEST_FILENAME = "full-runtime-matrix-runs.jsonl"
RECEIPT_TYPE = "verified-full-matrix-aggregate"
RECEIPT_SCHEMA_VERSION = 1
INTEGRATION_MODE = "full-matrix-parallel-runtime"
RUN_ID_PATTERN = VERIFIED_RUN_ID_PATTERN
GIT_SHA_PATTERN = re.compile(r"[0-9a-f]{40,64}\Z")
COMPLETE_RUNTIME_STATUSES = {"runtime_completed", "runtime_completed_with_mismatches"}
COMPLETE_JOB_STATUSES = {"completed", "completed_with_mismatches"}
MAX_STRUCTURED_RECEIPT_BYTES = 1024 * 1024
SEALED_RECEIPT_MODE = stat.S_IRUSR
INVALID_VERIFIED_RUN_ID_MESSAGE = "verified_run_id is invalid"


class AggregateReceiptError(ValueError):
    """A proposed aggregate receipt cannot safely be created or verified."""


class _MissingReceiptPath(AggregateReceiptError):
    """A receipt component is absent rather than unsafe."""


def _validated_verified_run_id(verified_run_id: str) -> str:
    try:
        return validate_verified_run_id(verified_run_id)
    except VerifiedRunIdError as exc:
        raise AggregateReceiptError(INVALID_VERIFIED_RUN_ID_MESSAGE) from exc


def expected_full_matrix_job_ids() -> tuple[str, ...]:
    return tuple(
        f"{connector}:{crs}:{mrts}"
        for connector in FULL_MATRIX_CONNECTORS
        for crs in FULL_MATRIX_CRS_VARIANTS
        for mrts in FULL_MATRIX_MRTS_VARIANTS
    )


def aggregate_receipt_path(build_root: Path, verified_run_id: str) -> Path:
    verified_run_id = _validated_verified_run_id(verified_run_id)
    return build_root.absolute() / "verified-runs" / verified_run_id / RECEIPT_FILENAME


def _required_directory_flags() -> tuple[int, int]:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory is None:
        raise AggregateReceiptError("descriptor-relative receipt access requires O_NOFOLLOW and O_DIRECTORY")
    return no_follow, directory


def _validated_component(component: str) -> str:
    if not component or component in {".", ".."} or "/" in component or (os.altsep and os.altsep in component):
        raise AggregateReceiptError(f"invalid receipt path component: {component!r}")
    return component


def _relative_components(path: Path, root: Path) -> tuple[str, ...]:
    try:
        relative = path.absolute().relative_to(root.absolute())
    except ValueError as exc:
        raise AggregateReceiptError(f"path escapes build root: {path}") from exc
    return tuple(_validated_component(part) for part in relative.parts)


@contextmanager
def _open_root_directory(root: Path) -> Iterator[int]:
    no_follow, directory = _required_directory_flags()
    try:
        descriptor = os.open(root.absolute(), os.O_RDONLY | directory | no_follow)
    except OSError as exc:
        raise AggregateReceiptError(f"build root is unavailable or unsafe: {root}: {exc}") from exc
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise AggregateReceiptError("build root is not a regular directory")
        yield descriptor
    finally:
        os.close(descriptor)


def _open_child_directory(parent_descriptor: int, component: str, *, create: bool, label: str) -> int:
    no_follow, directory = _required_directory_flags()
    name = _validated_component(component)
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_descriptor)
        except FileExistsError:
            pass
        except OSError as exc:
            raise AggregateReceiptError(f"cannot create {label}: {exc}") from exc
    try:
        descriptor = os.open(name, os.O_RDONLY | directory | no_follow, dir_fd=parent_descriptor)
    except FileNotFoundError as exc:
        raise _MissingReceiptPath(f"directory is unavailable: {label}") from exc
    except OSError as exc:
        raise AggregateReceiptError(f"directory is unavailable or unsafe: {label}: {exc}") from exc
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise AggregateReceiptError(f"path is not a directory: {label}")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


@contextmanager
def _open_absolute_directory(root: Path, *, label: str) -> Iterator[int]:
    """Open every component of an absolute directory without following links.

    ``os.open(path, O_NOFOLLOW)`` protects only the final component.  Evidence
    staging receives three independent roots, so walk each absolute path from
    ``/`` through descriptor-relative opens instead of accepting a symlinked
    ancestor selected by a caller.
    """

    if not root.is_absolute():
        raise AggregateReceiptError(f"directory root is not absolute: {label}")
    no_follow, directory = _required_directory_flags()
    try:
        descriptor = os.open(os.sep, os.O_RDONLY | directory | no_follow)
    except OSError as exc:
        raise AggregateReceiptError(f"filesystem root is unavailable or unsafe: {exc}") from exc
    try:
        for component in root.parts[1:]:
            child = _open_child_directory(descriptor, component, create=False, label=label)
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


@contextmanager
def _open_relative_directory(
    root_descriptor: int,
    components: tuple[str, ...],
    *,
    create: bool = False,
    label: str,
) -> Iterator[int]:
    descriptor = os.dup(root_descriptor)
    try:
        for component in components:
            child = _open_child_directory(descriptor, component, create=create, label=label)
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


def _read_stable_regular_file_at(
    parent_descriptor: int,
    name: str,
    *,
    label: str,
    collect_data: bool = True,
    maximum_bytes: int | None = None,
) -> tuple[bytes, str, int]:
    no_follow, _ = _required_directory_flags()
    try:
        descriptor = os.open(_validated_component(name), os.O_RDONLY | no_follow, dir_fd=parent_descriptor)
    except FileNotFoundError as exc:
        raise _MissingReceiptPath(f"file is unavailable: {label}") from exc
    except OSError as exc:
        raise AggregateReceiptError(f"file is unavailable or unsafe: {label}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise AggregateReceiptError(f"file is not regular: {label}")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        byte_count = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            byte_count += len(chunk)
            if maximum_bytes is not None and byte_count > maximum_bytes:
                raise AggregateReceiptError(f"file exceeds the {maximum_bytes}-byte receipt limit: {label}")
            if collect_data:
                chunks.append(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after:
            raise AggregateReceiptError(f"file changed while it was read: {label}")
    finally:
        os.close(descriptor)
    data = b"".join(chunks) if collect_data else b""
    if byte_count != before.st_size:
        raise AggregateReceiptError(f"file byte count changed while it was read: {label}")
    return data, digest.hexdigest(), byte_count


def _read_stable_regular_file_from_root(
    root_descriptor: int,
    root: Path,
    path: Path,
    *,
    collect_data: bool = True,
    maximum_bytes: int | None = None,
) -> tuple[bytes, str, int]:
    components = _relative_components(path, root)
    if not components:
        raise AggregateReceiptError(f"file path is the build root: {path}")
    with _open_relative_directory(root_descriptor, components[:-1], label=str(path)) as parent_descriptor:
        return _read_stable_regular_file_at(
            parent_descriptor,
            components[-1],
            label=str(path),
            collect_data=collect_data,
            maximum_bytes=maximum_bytes,
        )


def _read_stable_regular_file(
    path: Path,
    root: Path,
    *,
    root_descriptor: int | None = None,
    collect_data: bool = True,
    maximum_bytes: int | None = None,
) -> tuple[bytes, str, int]:
    if root_descriptor is not None:
        return _read_stable_regular_file_from_root(
            root_descriptor,
            root,
            path,
            collect_data=collect_data,
            maximum_bytes=maximum_bytes,
        )
    with _open_root_directory(root) as opened_root:
        return _read_stable_regular_file_from_root(
            opened_root,
            root,
            path,
            collect_data=collect_data,
            maximum_bytes=maximum_bytes,
        )


def _require_directory(path: Path, root: Path, *, root_descriptor: int | None = None) -> None:
    if root_descriptor is None:
        with _open_root_directory(root) as opened_root:
            _require_directory(path, root, root_descriptor=opened_root)
        return
    components = _relative_components(path, root)
    with _open_relative_directory(root_descriptor, components, label=str(path)):
        return


def _load_json(path: Path, root: Path, *, label: str, root_descriptor: int | None = None) -> dict[str, Any]:
    data, _, _ = _read_stable_regular_file(
        path,
        root,
        root_descriptor=root_descriptor,
        maximum_bytes=MAX_STRUCTURED_RECEIPT_BYTES,
    )
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AggregateReceiptError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AggregateReceiptError(f"{label} JSON root must be an object")
    return payload


def _load_jsonl(path: Path, root: Path, *, label: str, root_descriptor: int | None = None) -> list[dict[str, Any]]:
    data, _, _ = _read_stable_regular_file(
        path,
        root,
        root_descriptor=root_descriptor,
        maximum_bytes=MAX_STRUCTURED_RECEIPT_BYTES,
    )
    rows: list[dict[str, Any]] = []
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise AggregateReceiptError(f"{label} is not UTF-8 JSONL: {exc}") from exc
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AggregateReceiptError(f"{label}:{index} is invalid JSONL: {exc.msg}") from exc
        if not isinstance(row, dict):
            raise AggregateReceiptError(f"{label}:{index} JSONL record must be an object")
        rows.append(row)
    return rows


def _relative_file_record(path: Path, build_root: Path, *, root_descriptor: int | None = None) -> dict[str, Any]:
    _, digest, byte_count = _read_stable_regular_file(
        path,
        build_root,
        root_descriptor=root_descriptor,
        collect_data=False,
    )
    try:
        relative = path.absolute().relative_to(build_root.absolute())
    except ValueError as exc:
        raise AggregateReceiptError(f"artifact path escapes build root: {path}") from exc
    return {
        "canonical_relative_path": relative.as_posix(),
        "sha256": digest,
        "bytes": byte_count,
    }


def _expected_job_paths(build_root: Path, connector: str, crs: str, mrts: str) -> dict[str, Any]:
    job_root = build_root / "full-matrix" / crs / mrts / connector
    results_dir = job_root / "results"
    return {
        "job_root": job_root,
        "job_receipt": job_root / JOB_RECEIPT_FILENAME,
        "log": job_root / "run.log",
        "build_manifest": job_root / "build-manifest.json",
        "results_dir": results_dir,
        "results_jsonl": results_dir / "force-all" / f"{connector}-results.jsonl",
        "summary_candidates": (
            results_dir / f"{connector}-summary.json",
            results_dir / "force-all" / f"{connector}-summary.json",
        ),
    }


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AggregateReceiptError(f"{label} is missing or invalid")
    return value


def _require_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise AggregateReceiptError(f"{label} is missing or invalid")
    return value


def _require_duration(value: object, label: str) -> int | float:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
        raise AggregateReceiptError(f"{label} is missing or invalid")
    return value


def _expect_absolute_path(value: object, expected: Path, label: str) -> None:
    if not isinstance(value, str) or not value or not Path(value).is_absolute() or Path(value).absolute() != expected.absolute():
        raise AggregateReceiptError(f"{label} is not canonical")


def _validate_job_payload(
    job: Mapping[str, Any],
    *,
    connector: str,
    crs: str,
    mrts: str,
    verified_run_id: str,
    paths: Mapping[str, Any],
    build_root: Path,
    root_descriptor: int,
) -> tuple[Path, dict[str, Any]]:
    job_id = f"{connector}:{crs}:{mrts}"
    for key, expected in (
        ("connector", connector),
        ("job_id", job_id),
        ("verified_run_id", verified_run_id),
        ("test_variant", crs),
        ("mrts_variant", mrts),
    ):
        if job.get(key) != expected:
            raise AggregateReceiptError(f"{job_id}: {key} mismatch")
    if job.get("status") not in COMPLETE_JOB_STATUSES:
        raise AggregateReceiptError(f"{job_id}: status is not a completed runtime state")
    _require_int(job.get("return_code"), f"{job_id}: return_code")
    _require_text(job.get("started_at"), f"{job_id}: started_at")
    _require_text(job.get("ended_at"), f"{job_id}: ended_at")
    _require_duration(job.get("duration_seconds"), f"{job_id}: duration_seconds")
    _expect_absolute_path(job.get("results_dir"), paths["results_dir"], f"{job_id}: results_dir")
    _expect_absolute_path(job.get("log_path"), paths["log"], f"{job_id}: log_path")
    summary = Path(_require_text(job.get("summary_path"), f"{job_id}: summary_path"))
    if not summary.is_absolute() or all(summary.absolute() != candidate.absolute() for candidate in paths["summary_candidates"]):
        raise AggregateReceiptError(f"{job_id}: summary_path is not canonical")
    _require_directory(paths["results_dir"], build_root, root_descriptor=root_descriptor)
    hashes = job.get("hashes")
    inputs = job.get("inputs")
    outputs = job.get("outputs")
    if not isinstance(hashes, dict) or not isinstance(inputs, dict) or not isinstance(outputs, dict):
        raise AggregateReceiptError(f"{job_id}: job receipt artifact fields are invalid")
    _expect_absolute_path(inputs.get("build_manifest"), paths["build_manifest"], f"{job_id}: build_manifest")
    _expect_absolute_path(outputs.get("job_json"), paths["job_receipt"], f"{job_id}: job_json")
    _expect_absolute_path(outputs.get("log"), paths["log"], f"{job_id}: output log")
    _expect_absolute_path(outputs.get("summary"), summary, f"{job_id}: output summary")
    _expect_absolute_path(outputs.get("results_dir"), paths["results_dir"], f"{job_id}: output results_dir")
    _expect_absolute_path(outputs.get("results_jsonl"), paths["results_jsonl"], f"{job_id}: output results_jsonl")
    return summary, {"hashes": hashes, "inputs": inputs, "outputs": outputs}


def _normalize_parent_command(parent_command: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(parent_command, Mapping):
        raise AggregateReceiptError("parent command is missing or invalid")
    logical_target = _require_text(parent_command.get("logical_target"), "parent command logical_target")
    if logical_target not in {"full-matrix-parallel", "full-matrix-resume"}:
        raise AggregateReceiptError("parent command logical_target is not a full-matrix runtime target")
    if parent_command.get("required") is not True:
        raise AggregateReceiptError("parent command is not required")
    if parent_command.get("runtime_complete") is not True:
        raise AggregateReceiptError("parent command is not runtime complete")
    if parent_command.get("runtime_status") not in COMPLETE_RUNTIME_STATUSES:
        raise AggregateReceiptError("parent command runtime_status is not complete")
    return {
        "logical_target": logical_target,
        "phase": _require_text(parent_command.get("phase"), "parent command phase"),
        "required": True,
        "return_code": _require_int(parent_command.get("return_code"), "parent command return_code"),
        "classification": _require_text(parent_command.get("classification"), "parent command classification"),
        "runtime_complete": True,
        "runtime_status": str(parent_command["runtime_status"]),
        "started_at": _require_text(parent_command.get("started_at"), "parent command started_at"),
        "finished_at": _require_text(parent_command.get("finished_at"), "parent command finished_at"),
    }


def _normalize_revisions(revisions: Mapping[str, Any]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key in ("connector_sha", "framework_sha", "mrts_sha"):
        value = revisions.get(key) if isinstance(revisions, Mapping) else None
        if not isinstance(value, str) or not GIT_SHA_PATTERN.fullmatch(value):
            raise AggregateReceiptError(f"revision binding {key} is missing or invalid")
        normalized[key] = value
    return normalized


def _raw_rows_by_job(
    build_root: Path,
    verified_run_id: str,
    *,
    root_descriptor: int,
) -> tuple[Path, dict[str, dict[str, Any]]]:
    matrix_manifest = build_root / "full-matrix" / FULL_RUNTIME_MATRIX_MANIFEST_FILENAME
    rows = _load_jsonl(
        matrix_manifest,
        build_root,
        label="full runtime matrix manifest",
        root_descriptor=root_descriptor,
    )
    expected = set(expected_full_matrix_job_ids())
    by_job: dict[str, dict[str, Any]] = {}
    for row in rows:
        connector = str(row.get("connector") or "")
        crs = str(row.get("test_variant") or "")
        mrts = str(row.get("mrts_variant") or "")
        job_id = str(row.get("job_id") or "")
        if job_id != f"{connector}:{crs}:{mrts}" or job_id not in expected:
            raise AggregateReceiptError(f"full runtime matrix manifest has invalid job identity {job_id or '<missing>'}")
        if row.get("verified_run_id") != verified_run_id:
            raise AggregateReceiptError(f"full runtime matrix manifest {job_id} verified_run_id mismatch")
        if job_id in by_job:
            raise AggregateReceiptError(f"full runtime matrix manifest has duplicate job {job_id}")
        by_job[job_id] = row
    if len(rows) != len(expected) or set(by_job) != expected:
        raise AggregateReceiptError("full runtime matrix manifest is incomplete")
    return matrix_manifest, by_job


def _build_full_matrix_job_record(
    *,
    root: Path,
    root_descriptor: int,
    verified_run_id: str,
    connector: str,
    crs: str,
    mrts: str,
    raw_rows: Mapping[str, dict[str, Any]],
) -> dict[str, Any]:
    job_id = f"{connector}:{crs}:{mrts}"
    paths = _expected_job_paths(root, connector, crs, mrts)
    job_path = paths["job_receipt"]
    job = _load_json(
        job_path,
        root,
        label=f"{job_id} job receipt",
        root_descriptor=root_descriptor,
    )
    summary_path, declarations = _validate_job_payload(
        job,
        connector=connector,
        crs=crs,
        mrts=mrts,
        verified_run_id=verified_run_id,
        paths=paths,
        build_root=root,
        root_descriptor=root_descriptor,
    )
    artifacts = {
        "log": _relative_file_record(paths["log"], root, root_descriptor=root_descriptor),
        "build_manifest": _relative_file_record(paths["build_manifest"], root, root_descriptor=root_descriptor),
        "summary": _relative_file_record(summary_path, root, root_descriptor=root_descriptor),
        "results_jsonl": _relative_file_record(paths["results_jsonl"], root, root_descriptor=root_descriptor),
    }
    for label, entry in artifacts.items():
        declared_hash = declarations["hashes"].get(label)
        if declared_hash != entry["sha256"]:
            raise AggregateReceiptError(f"{job_id}: {label} hash mismatch")
    raw = raw_rows[job_id]
    for key in (
        "connector",
        "job_id",
        "verified_run_id",
        "test_variant",
        "mrts_variant",
        "return_code",
        "status",
        "started_at",
        "ended_at",
        "duration_seconds",
        "results_dir",
        "summary_path",
        "log_path",
        "hashes",
        "inputs",
        "outputs",
    ):
        if raw.get(key) != job.get(key):
            raise AggregateReceiptError(f"{job_id}: raw matrix {key} does not match job receipt")
    return {
        "job_id": job_id,
        "connector": connector,
        "test_variant": crs,
        "mrts_variant": mrts,
        "verified_run_id": verified_run_id,
        "return_code": job["return_code"],
        "status": job["status"],
        "started_at": job["started_at"],
        "ended_at": job["ended_at"],
        "duration_seconds": job["duration_seconds"],
        "job_receipt": _relative_file_record(job_path, root, root_descriptor=root_descriptor),
        "artifacts": artifacts,
    }


def _build_full_matrix_aggregate_receipt_from_root(
    *,
    root: Path,
    root_descriptor: int,
    verified_run_id: str,
    profile: str,
    parent_command: Mapping[str, Any],
    revisions: Mapping[str, Any],
) -> dict[str, Any]:
    _require_directory(root, root, root_descriptor=root_descriptor)
    parent = _normalize_parent_command(parent_command)
    revision_binding = _normalize_revisions(revisions)
    matrix_manifest, raw_rows = _raw_rows_by_job(root, verified_run_id, root_descriptor=root_descriptor)
    jobs: list[dict[str, Any]] = []
    for connector in FULL_MATRIX_CONNECTORS:
        for crs in FULL_MATRIX_CRS_VARIANTS:
            for mrts in FULL_MATRIX_MRTS_VARIANTS:
                jobs.append(
                    _build_full_matrix_job_record(
                        root=root,
                        root_descriptor=root_descriptor,
                        verified_run_id=verified_run_id,
                        connector=connector,
                        crs=crs,
                        mrts=mrts,
                        raw_rows=raw_rows,
                    )
                )
    return {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "receipt_type": RECEIPT_TYPE,
        "verified_run_id": verified_run_id,
        "profile": "full",
        "integration_mode": INTEGRATION_MODE,
        "producer": {
            "component": "ci/runtime/lifecycle/run-verified-report-run.py",
            "parent_command": parent,
        },
        "revision_binding": revision_binding,
        "raw_matrix_manifest": _relative_file_record(
            matrix_manifest, root, root_descriptor=root_descriptor
        ),
        "jobs": jobs,
    }


def build_full_matrix_aggregate_receipt(
    *,
    build_root: Path,
    verified_run_id: str,
    profile: str,
    parent_command: Mapping[str, Any],
    revisions: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a deterministic receipt from the current canonical runtime files.

    This function does not write.  It is shared by the Parent producer and the
    strict consumer so every field that is sealed is independently recomputed.
    """

    verified_run_id = _validated_verified_run_id(verified_run_id)
    if profile != "full":
        raise AggregateReceiptError("aggregate receipt requires profile full")
    root = build_root.absolute()
    with _open_root_directory(root) as root_descriptor:
        return _build_full_matrix_aggregate_receipt_from_root(
            root=root,
            root_descriptor=root_descriptor,
            verified_run_id=verified_run_id,
            profile=profile,
            parent_command=parent_command,
            revisions=revisions,
        )


def _receipt_record_from_root(
    *,
    root: Path,
    root_descriptor: int,
    verified_run_id: str,
    missing_ok: bool,
) -> dict[str, Any] | None:
    path = aggregate_receipt_path(root, verified_run_id)
    try:
        _, digest, byte_count = _read_stable_regular_file_from_root(
            root_descriptor,
            root,
            path,
            collect_data=False,
        )
    except _MissingReceiptPath:
        if missing_ok:
            return None
        raise
    return {
        "path": str(path),
        "sha256": digest,
        "bytes": byte_count,
    }


def full_matrix_aggregate_receipt_record(
    *,
    build_root: Path,
    verified_run_id: str,
    missing_ok: bool = False,
) -> dict[str, Any] | None:
    """Read an aggregate-receipt record through a pinned BUILD_ROOT descriptor."""

    verified_run_id = _validated_verified_run_id(verified_run_id)
    root = build_root.absolute()
    with _open_root_directory(root) as root_descriptor:
        return _receipt_record_from_root(
            root=root,
            root_descriptor=root_descriptor,
            verified_run_id=verified_run_id,
            missing_ok=missing_ok,
        )


def verified_command_receipt(
    *,
    build_root: Path,
    verified_run_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read the Parent command receipt and its record through BUILD_ROOT's descriptor."""

    verified_run_id = _validated_verified_run_id(verified_run_id)
    root = build_root.absolute()
    path = root / "verified-runs" / verified_run_id / "verified-commands.json"
    with _open_root_directory(root) as root_descriptor:
        data, digest, byte_count = _read_stable_regular_file_from_root(
            root_descriptor,
            root,
            path,
            maximum_bytes=MAX_STRUCTURED_RECEIPT_BYTES,
        )
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AggregateReceiptError(f"verified command receipt is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AggregateReceiptError("verified command receipt JSON root must be an object")
    return payload, {
        "path": str(path),
        "sha256": digest,
        "bytes": byte_count,
    }


def _assert_directory_binding(
    *,
    root_descriptor: int,
    components: tuple[str, ...],
    expected_descriptor: int,
    label: str,
) -> None:
    expected = os.fstat(expected_descriptor)
    with _open_relative_directory(root_descriptor, components, label=label) as current_descriptor:
        current = os.fstat(current_descriptor)
    if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
        raise AggregateReceiptError(f"receipt directory changed while publishing: {label}")


def _write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            raise AggregateReceiptError("cannot write aggregate receipt")
        offset += written


@dataclass(frozen=True)
class StagedEvidenceFile:
    """One payload-safe file staged read-only for non-owner identities."""

    relative_path: str
    sha256: str
    bytes: int


@dataclass(frozen=True)
class StagedEvidence:
    """Descriptor-pinned result of one full verified-runtime evidence staging."""

    stage_root: Path
    verified_run_id: str
    files: tuple[StagedEvidenceFile, ...]


@dataclass(frozen=True)
class _StagedEvidenceSource:
    source_root: str
    source_components: tuple[str, ...]
    stage_components: tuple[str, ...]


STAGED_EVIDENCE_DIRECTORY_MODE = stat.S_IRUSR | stat.S_IXUSR
STAGED_EVIDENCE_FILE_MODE = stat.S_IRUSR
STAGED_EVIDENCE_CREATE_DIRECTORY_MODE = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
STAGED_EVIDENCE_FILE_COUNT = 18


def _read_relative_stable_file(
    root_descriptor: int,
    components: tuple[str, ...],
    *,
    label: str,
    maximum_bytes: int = MAX_STRUCTURED_RECEIPT_BYTES,
) -> tuple[bytes, str, int]:
    if not components:
        raise AggregateReceiptError(f"file path is the root: {label}")
    for component in components:
        _validated_component(component)
    with _open_relative_directory(root_descriptor, components[:-1], label=label) as parent_descriptor:
        return _read_stable_regular_file_at(
            parent_descriptor,
            components[-1],
            label=label,
            maximum_bytes=maximum_bytes,
        )


def _current_verified_run_id_for_staging(build_descriptor: int) -> str:
    data, _, _ = _read_relative_stable_file(
        build_descriptor,
        ("verified-runs", "current-run-id"),
        label="verified runtime current-run marker",
        maximum_bytes=130,
    )
    if data.endswith(b"\n"):
        data = data[:-1]
    if data.endswith(b"\r"):
        data = data[:-1]
    try:
        return _validated_verified_run_id(data.decode("ascii"))
    except UnicodeDecodeError as exc:
        raise AggregateReceiptError("verified runtime current-run marker is not ASCII") from exc


def _staged_evidence_sources(verified_run_id: str) -> tuple[_StagedEvidenceSource, ...]:
    sources: list[_StagedEvidenceSource] = []
    for filename in (
        "verified-run-manifest.generated.json",
        "report-freshness.generated.json",
        "report-refresh-manifest.generated.json",
    ):
        sources.append(
            _StagedEvidenceSource(
                source_root="connector",
                source_components=("reports", "testing", "generated", "manifest", filename),
                stage_components=("manifests", filename),
            )
        )
    for filename in ("verified-commands.json", RECEIPT_FILENAME):
        sources.append(
            _StagedEvidenceSource(
                source_root="build",
                source_components=("verified-runs", verified_run_id, filename),
                stage_components=("verified-runs", verified_run_id, filename),
            )
        )
    sources.append(
        _StagedEvidenceSource(
            source_root="build",
            source_components=("full-matrix", FULL_RUNTIME_MATRIX_MANIFEST_FILENAME),
            stage_components=("full-matrix", FULL_RUNTIME_MATRIX_MANIFEST_FILENAME),
        )
    )
    for crs in FULL_MATRIX_CRS_VARIANTS:
        for mrts in FULL_MATRIX_MRTS_VARIANTS:
            for connector in FULL_MATRIX_CONNECTORS:
                sources.append(
                    _StagedEvidenceSource(
                        source_root="build",
                        source_components=("full-matrix", crs, mrts, connector, JOB_RECEIPT_FILENAME),
                        stage_components=("full-matrix", crs, mrts, connector, JOB_RECEIPT_FILENAME),
                    )
                )
    result = tuple(sources)
    if len(result) != STAGED_EVIDENCE_FILE_COUNT:
        raise AggregateReceiptError("staged evidence allowlist has an unexpected file count")
    return result


def _create_empty_stage_root(parent_descriptor: int, parent: Path, stage_name: str) -> int:
    name = _validated_component(stage_name)
    try:
        os.lstat(name, dir_fd=parent_descriptor)
    except FileNotFoundError:
        pass
    else:
        raise AggregateReceiptError(f"staged evidence root already exists: {parent / name}")
    try:
        os.mkdir(name, STAGED_EVIDENCE_CREATE_DIRECTORY_MODE, dir_fd=parent_descriptor)
    except OSError as exc:
        raise AggregateReceiptError(f"cannot create staged evidence root: {parent / name}: {exc}") from exc
    try:
        os.fsync(parent_descriptor)
    except OSError as exc:
        raise AggregateReceiptError(f"cannot persist staged evidence root: {parent / name}: {exc}") from exc
    no_follow, directory = _required_directory_flags()
    try:
        descriptor = os.open(name, os.O_RDONLY | directory | no_follow, dir_fd=parent_descriptor)
    except OSError as exc:
        raise AggregateReceiptError(f"staged evidence root is unavailable or unsafe: {parent / name}: {exc}") from exc
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise AggregateReceiptError(f"staged evidence root is not a directory: {parent / name}")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _write_staged_file(
    stage_descriptor: int,
    components: tuple[str, ...],
    content: bytes,
    *,
    label: str,
) -> None:
    if not components:
        raise AggregateReceiptError(f"staged evidence path is empty: {label}")
    no_follow, _ = _required_directory_flags()
    for component in components:
        _validated_component(component)
    with _open_relative_directory(
        stage_descriptor,
        components[:-1],
        create=True,
        label=label,
    ) as parent_descriptor:
        descriptor: int | None = None
        created = False
        try:
            try:
                descriptor = os.open(
                    components[-1],
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
                    STAGED_EVIDENCE_FILE_MODE,
                    dir_fd=parent_descriptor,
                )
            except OSError as exc:
                raise AggregateReceiptError(f"cannot create staged evidence file: {label}: {exc}") from exc
            created = True
            _write_all(descriptor, content)
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or details.st_size != len(content):
                raise AggregateReceiptError(f"staged evidence file changed while publishing: {label}")
            os.fsync(descriptor)
            os.fchmod(descriptor, STAGED_EVIDENCE_FILE_MODE)
            os.fsync(descriptor)
        except BaseException:
            if created:
                try:
                    os.unlink(components[-1], dir_fd=parent_descriptor)
                    os.fsync(parent_descriptor)
                except OSError:
                    pass
            raise
        finally:
            if descriptor is not None:
                os.close(descriptor)


def _remove_staged_directory_contents(directory_descriptor: int) -> None:
    no_follow, directory = _required_directory_flags()
    os.fchmod(directory_descriptor, STAGED_EVIDENCE_CREATE_DIRECTORY_MODE)
    for name in os.listdir(directory_descriptor):
        _validated_component(name)
        details = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if stat.S_ISDIR(details.st_mode):
            child = os.open(name, os.O_RDONLY | directory | no_follow, dir_fd=directory_descriptor)
            try:
                _remove_staged_directory_contents(child)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=directory_descriptor)
        else:
            os.unlink(name, dir_fd=directory_descriptor)
    os.fsync(directory_descriptor)


def _seal_staged_directories(stage_descriptor: int, sources: tuple[_StagedEvidenceSource, ...]) -> None:
    directories = {
        source.stage_components[:index]
        for source in sources
        for index in range(1, len(source.stage_components))
    }
    for components in sorted(directories, key=lambda value: (len(value), value), reverse=True):
        with _open_relative_directory(stage_descriptor, components, label="/".join(components)) as descriptor:
            os.fchmod(descriptor, STAGED_EVIDENCE_DIRECTORY_MODE)
            os.fsync(descriptor)
    os.fchmod(stage_descriptor, STAGED_EVIDENCE_DIRECTORY_MODE)
    os.fsync(stage_descriptor)


def _validated_staging_roots(
    *,
    connector_root: Path,
    build_root: Path,
    stage_root: Path,
) -> tuple[Path, Path, Path]:
    for root in (connector_root, build_root, stage_root):
        if not root.is_absolute() or any(part in {".", ".."} for part in root.parts):
            raise AggregateReceiptError("staged evidence roots must be non-root absolute paths without traversal")
    if stage_root == stage_root.parent:
        raise AggregateReceiptError("staged evidence roots must be non-root absolute paths without traversal")
    return connector_root.absolute(), build_root.absolute(), stage_root.absolute()


def _require_private_staging_parent(parent_descriptor: int, parent: Path) -> None:
    details = os.fstat(parent_descriptor)
    if not stat.S_ISDIR(details.st_mode):
        raise AggregateReceiptError(f"staged evidence parent is not a directory: {parent}")
    if details.st_uid != os.geteuid():
        raise AggregateReceiptError(f"staged evidence parent is not owned by the current user: {parent}")
    if details.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise AggregateReceiptError(f"staged evidence parent is writable by another user: {parent}")


def _staged_directory_components(sources: tuple[_StagedEvidenceSource, ...]) -> set[tuple[str, ...]]:
    return {
        source.stage_components[:index]
        for source in sources
        for index in range(1, len(source.stage_components))
    }


def _read_expected_staged_file(
    directory_descriptor: int,
    name: str,
    components: tuple[str, ...],
    details: os.stat_result,
    expected_files: set[tuple[str, ...]],
) -> StagedEvidenceFile:
    relative_path = "/".join(components)
    if not stat.S_ISREG(details.st_mode):
        raise AggregateReceiptError(f"staged evidence contains a non-regular path: {relative_path}")
    if components not in expected_files:
        raise AggregateReceiptError(f"staged evidence contains an unexpected file: {relative_path}")
    data, digest, byte_count = _read_stable_regular_file_at(
        directory_descriptor,
        name,
        label=f"staged evidence:{relative_path}",
        maximum_bytes=MAX_STRUCTURED_RECEIPT_BYTES,
    )
    if hashlib.sha256(data).hexdigest() != digest or len(data) != byte_count:
        raise AggregateReceiptError("staged evidence bytes do not match their recorded digest")
    return StagedEvidenceFile(relative_path, digest, byte_count)


def _open_expected_staged_directory(
    directory_descriptor: int,
    name: str,
    components: tuple[str, ...],
    expected_directories: set[tuple[str, ...]],
    *,
    no_follow: int,
    directory: int,
) -> int:
    if components not in expected_directories:
        raise AggregateReceiptError(f"staged evidence contains an unexpected directory: {'/'.join(components)}")
    return os.open(name, os.O_RDONLY | directory | no_follow, dir_fd=directory_descriptor)


def _collect_exact_staged_tree(
    directory_descriptor: int,
    prefix: tuple[str, ...],
    *,
    expected_files: set[tuple[str, ...]],
    expected_directories: set[tuple[str, ...]],
    observed: dict[tuple[str, ...], StagedEvidenceFile],
    no_follow: int,
    directory: int,
) -> None:
    for name in os.listdir(directory_descriptor):
        _validated_component(name)
        components = (*prefix, name)
        details = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if stat.S_ISDIR(details.st_mode):
            child = _open_expected_staged_directory(
                directory_descriptor,
                name,
                components,
                expected_directories,
                no_follow=no_follow,
                directory=directory,
            )
            try:
                _collect_exact_staged_tree(
                    child,
                    components,
                    expected_files=expected_files,
                    expected_directories=expected_directories,
                    observed=observed,
                    no_follow=no_follow,
                    directory=directory,
                )
            finally:
                os.close(child)
            continue
        observed[components] = _read_expected_staged_file(
            directory_descriptor,
            name,
            components,
            details,
            expected_files,
        )


def _read_exact_staged_tree(
    stage_descriptor: int,
    sources: tuple[_StagedEvidenceSource, ...],
) -> dict[tuple[str, ...], StagedEvidenceFile]:
    expected_files = {source.stage_components for source in sources}
    expected_directories = _staged_directory_components(sources)
    observed: dict[tuple[str, ...], StagedEvidenceFile] = {}
    no_follow, directory = _required_directory_flags()
    _collect_exact_staged_tree(
        stage_descriptor,
        (),
        expected_files=expected_files,
        expected_directories=expected_directories,
        observed=observed,
        no_follow=no_follow,
        directory=directory,
    )
    missing = expected_files.difference(observed)
    if missing:
        raise AggregateReceiptError(
            "staged evidence is missing required files: " + ", ".join("/".join(item) for item in sorted(missing))
        )
    if set(observed) != expected_files:
        raise AggregateReceiptError("staged evidence allowlist does not match the expected files")
    return observed


def _stage_root_still_bound(
    *,
    parent_descriptor: int,
    stage_name: str,
    stage_descriptor: int,
    stage: Path,
) -> bool:
    try:
        _assert_directory_binding(
            root_descriptor=parent_descriptor,
            components=(stage_name,),
            expected_descriptor=stage_descriptor,
            label=str(stage),
        )
    except AggregateReceiptError:
        return False
    return True


def _read_evidence_source(
    source: _StagedEvidenceSource,
    *,
    connector_descriptor: int,
    build_descriptor: int,
) -> tuple[bytes, str, int]:
    descriptor = connector_descriptor if source.source_root == "connector" else build_descriptor
    return _read_relative_stable_file(
        descriptor,
        source.source_components,
        label=f"{source.source_root}:{'/'.join(source.source_components)}",
    )


def _buffer_evidence_sources(
    sources: tuple[_StagedEvidenceSource, ...],
    *,
    connector_descriptor: int,
    build_descriptor: int,
) -> list[tuple[_StagedEvidenceSource, bytes, str, int]]:
    buffered_sources: list[tuple[_StagedEvidenceSource, bytes, str, int]] = []
    for source in sources:
        data, digest, byte_count = _read_evidence_source(
            source,
            connector_descriptor=connector_descriptor,
            build_descriptor=build_descriptor,
        )
        buffered_sources.append((source, data, digest, byte_count))
    return buffered_sources


def _require_staged_root_binding(
    *,
    parent_descriptor: int,
    stage_name: str,
    stage_descriptor: int,
    stage: Path,
    action: str,
) -> None:
    if not _stage_root_still_bound(
        parent_descriptor=parent_descriptor,
        stage_name=stage_name,
        stage_descriptor=stage_descriptor,
        stage=stage,
    ):
        raise AggregateReceiptError(f"staged evidence root changed while {action}: {stage}")


def _discard_staged_root(
    *,
    parent_descriptor: int,
    stage_name: str,
    stage_descriptor: int,
    stage: Path,
) -> None:
    try:
        _remove_staged_directory_contents(stage_descriptor)
    except OSError:
        pass
    try:
        if _stage_root_still_bound(
            parent_descriptor=parent_descriptor,
            stage_name=stage_name,
            stage_descriptor=stage_descriptor,
            stage=stage,
        ):
            os.rmdir(stage_name, dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
    except OSError:
        pass


@contextmanager
def _open_new_staged_root(
    *,
    parent_descriptor: int,
    stage_name: str,
    stage: Path,
) -> Iterator[int]:
    descriptor = _create_empty_stage_root(parent_descriptor, stage.parent, stage_name)
    try:
        yield descriptor
    except BaseException:
        _discard_staged_root(
            parent_descriptor=parent_descriptor,
            stage_name=stage_name,
            stage_descriptor=descriptor,
            stage=stage,
        )
        raise
    finally:
        os.close(descriptor)


def _publish_buffered_evidence(
    *,
    parent_descriptor: int,
    stage_name: str,
    stage: Path,
    sources: tuple[_StagedEvidenceSource, ...],
    buffered_sources: list[tuple[_StagedEvidenceSource, bytes, str, int]],
) -> tuple[StagedEvidenceFile, ...]:
    with _open_new_staged_root(
        parent_descriptor=parent_descriptor,
        stage_name=stage_name,
        stage=stage,
    ) as stage_descriptor:
        records: list[StagedEvidenceFile] = []
        for source, data, digest, byte_count in buffered_sources:
            if hashlib.sha256(data).hexdigest() != digest or len(data) != byte_count:
                raise AggregateReceiptError("stable source evidence bytes do not match their recorded digest")
            relative_path = "/".join(source.stage_components)
            _write_staged_file(stage_descriptor, source.stage_components, data, label=relative_path)
            records.append(StagedEvidenceFile(relative_path, digest, byte_count))
        _seal_staged_directories(stage_descriptor, sources)
        _require_staged_root_binding(
            parent_descriptor=parent_descriptor,
            stage_name=stage_name,
            stage_descriptor=stage_descriptor,
            stage=stage,
            action="publishing",
        )
        return tuple(records)


def _verify_staged_evidence_tree(
    *,
    parent_descriptor: int,
    stage_name: str,
    stage: Path,
    sources: tuple[_StagedEvidenceSource, ...],
    connector_descriptor: int,
    build_descriptor: int,
) -> tuple[StagedEvidenceFile, ...]:
    with _open_relative_directory(parent_descriptor, (stage_name,), label=str(stage)) as stage_descriptor:
        staged_records = _read_exact_staged_tree(stage_descriptor, sources)
        records: list[StagedEvidenceFile] = []
        for source in sources:
            _, digest, byte_count = _read_evidence_source(
                source,
                connector_descriptor=connector_descriptor,
                build_descriptor=build_descriptor,
            )
            staged = staged_records[source.stage_components]
            if staged.sha256 != digest or staged.bytes != byte_count:
                relative_path = "/".join(source.stage_components)
                raise AggregateReceiptError(f"staged evidence does not match current source: {relative_path}")
            records.append(staged)
        _require_staged_root_binding(
            parent_descriptor=parent_descriptor,
            stage_name=stage_name,
            stage_descriptor=stage_descriptor,
            stage=stage,
            action="verifying",
        )
    return tuple(records)


def stage_verified_full_matrix_evidence(
    *,
    connector_root: Path,
    build_root: Path,
    stage_root: Path,
) -> StagedEvidence:
    """Copy the exact structured evidence allowlist through no-follow descriptors.

    The caller must follow this snapshot with a final strict evidence gate and
    :func:`verify_staged_full_matrix_evidence` before upload.  This function
    pins every source-root component by descriptor, rejects symlinked
    ancestors/leaves, checks stable file identity while reading, and writes a
    private, exact allowlist tree rather than returning PR-controlled source
    pathnames to an uploader.
    """

    connector, build, stage = _validated_staging_roots(
        connector_root=connector_root,
        build_root=build_root,
        stage_root=stage_root,
    )
    stage_parent = stage.parent
    stage_name = _validated_component(stage.name)

    with _open_absolute_directory(connector, label="connector evidence root") as connector_descriptor, _open_absolute_directory(
        build, label="build evidence root"
    ) as build_descriptor:
        verified_run_id = _current_verified_run_id_for_staging(build_descriptor)
        sources = _staged_evidence_sources(verified_run_id)
        buffered_sources = _buffer_evidence_sources(
            sources,
            connector_descriptor=connector_descriptor,
            build_descriptor=build_descriptor,
        )

        with _open_absolute_directory(stage_parent, label="staged evidence parent") as stage_parent_descriptor:
            _require_private_staging_parent(stage_parent_descriptor, stage_parent)
            records = _publish_buffered_evidence(
                parent_descriptor=stage_parent_descriptor,
                stage_name=stage_name,
                stage=stage,
                sources=sources,
                buffered_sources=buffered_sources,
            )
    return StagedEvidence(stage, verified_run_id, records)


def verify_staged_full_matrix_evidence(
    *,
    connector_root: Path,
    build_root: Path,
    stage_root: Path,
) -> StagedEvidence:
    """Prove a staged snapshot still matches the final strict-gate inputs.

    The strict gate is intentionally rerun immediately before this function.
    It compares each no-follow, stable source read with the sealed stage tree,
    rejects additions and path swaps, and rebinds the stage child to its opened
    parent descriptor.  It is not a transactional snapshot against arbitrary
    surviving same-UID processes; that limitation is recorded by the caller's
    evidence policy.
    """

    connector, build, stage = _validated_staging_roots(
        connector_root=connector_root,
        build_root=build_root,
        stage_root=stage_root,
    )
    stage_parent = stage.parent
    stage_name = _validated_component(stage.name)
    with _open_absolute_directory(connector, label="connector evidence root") as connector_descriptor, _open_absolute_directory(
        build, label="build evidence root"
    ) as build_descriptor, _open_absolute_directory(stage_parent, label="staged evidence parent") as stage_parent_descriptor:
        _require_private_staging_parent(stage_parent_descriptor, stage_parent)
        verified_run_id = _current_verified_run_id_for_staging(build_descriptor)
        sources = _staged_evidence_sources(verified_run_id)
        records = _verify_staged_evidence_tree(
            parent_descriptor=stage_parent_descriptor,
            stage_name=stage_name,
            stage=stage,
            sources=sources,
            connector_descriptor=connector_descriptor,
            build_descriptor=build_descriptor,
        )
    return StagedEvidence(stage, verified_run_id, records)


def seal_full_matrix_aggregate_receipt_record(
    *,
    build_root: Path,
    verified_run_id: str,
    profile: str,
    parent_command: Mapping[str, Any],
    revisions: Mapping[str, Any],
) -> dict[str, Any]:
    """Create one immutable receipt and return metadata from its open descriptor."""

    verified_run_id = _validated_verified_run_id(verified_run_id)
    if profile != "full":
        raise AggregateReceiptError("aggregate receipt requires profile full")

    root = build_root.absolute()
    path = aggregate_receipt_path(root, verified_run_id)
    directory_components = ("verified-runs", verified_run_id)
    no_follow, _ = _required_directory_flags()
    with _open_root_directory(root) as root_descriptor:
        existing = _receipt_record_from_root(
            root=root,
            root_descriptor=root_descriptor,
            verified_run_id=verified_run_id,
            missing_ok=True,
        )
        if existing is not None:
            raise AggregateReceiptError(f"aggregate receipt already exists: {path}")
        payload = _build_full_matrix_aggregate_receipt_from_root(
            root=root,
            root_descriptor=root_descriptor,
            verified_run_id=verified_run_id,
            profile=profile,
            parent_command=parent_command,
            revisions=revisions,
        )
        content = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        digest = hashlib.sha256(content).hexdigest()
        with _open_relative_directory(
            root_descriptor,
            directory_components,
            create=True,
            label=str(path.parent),
        ) as receipt_directory:
            descriptor: int | None = None
            created = False
            try:
                try:
                    descriptor = os.open(
                        RECEIPT_FILENAME,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
                        0o600,
                        dir_fd=receipt_directory,
                    )
                except FileExistsError as exc:
                    raise AggregateReceiptError(f"aggregate receipt already exists: {path}") from exc
                except OSError as exc:
                    raise AggregateReceiptError(f"cannot create aggregate receipt: {exc}") from exc
                created = True
                _write_all(descriptor, content)
                if os.fstat(descriptor).st_size != len(content):
                    raise AggregateReceiptError("aggregate receipt byte count changed while publishing")
                os.fsync(descriptor)
                os.fchmod(descriptor, SEALED_RECEIPT_MODE)
                os.fsync(descriptor)
                _assert_directory_binding(
                    root_descriptor=root_descriptor,
                    components=directory_components,
                    expected_descriptor=receipt_directory,
                    label=str(path.parent),
                )
                os.fsync(receipt_directory)
            except BaseException:
                if created:
                    try:
                        os.unlink(RECEIPT_FILENAME, dir_fd=receipt_directory)
                        os.fsync(receipt_directory)
                    except OSError:
                        pass
                raise
            finally:
                if descriptor is not None:
                    os.close(descriptor)
    return {
        "status": "sealed",
        "path": str(path),
        "sha256": digest,
        "bytes": len(content),
    }


def seal_full_matrix_aggregate_receipt(
    *,
    build_root: Path,
    verified_run_id: str,
    profile: str,
    parent_command: Mapping[str, Any],
    revisions: Mapping[str, Any],
) -> Path:
    """Atomically create one receipt; an existing receipt is never rewritten."""

    record = seal_full_matrix_aggregate_receipt_record(
        build_root=build_root,
        verified_run_id=verified_run_id,
        profile=profile,
        parent_command=parent_command,
        revisions=revisions,
    )
    return Path(str(record["path"]))


def validate_full_matrix_aggregate_receipt(
    *,
    build_root: Path,
    verified_run_id: str,
    expected_profile: str,
    expected_revisions: Mapping[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """Return the canonical receipt plus errors after recomputing every field."""

    try:
        root = build_root.absolute()
        path = aggregate_receipt_path(root, verified_run_id)
        with _open_root_directory(root) as root_descriptor:
            receipt = _load_json(
                path,
                root,
                label="aggregate receipt",
                root_descriptor=root_descriptor,
            )
            expected_revisions_normalized = _normalize_revisions(expected_revisions)
            if receipt.get("revision_binding") != expected_revisions_normalized:
                return receipt, ["aggregate receipt revision binding does not match verified run manifest"]
            producer = receipt.get("producer")
            if not isinstance(producer, dict):
                return receipt, ["aggregate receipt producer is missing or invalid"]
            parent_command = producer.get("parent_command")
            candidate = _build_full_matrix_aggregate_receipt_from_root(
                root=root,
                root_descriptor=root_descriptor,
                verified_run_id=verified_run_id,
                profile=expected_profile,
                parent_command=parent_command if isinstance(parent_command, Mapping) else {},
                revisions=expected_revisions_normalized,
            )
        if receipt != candidate:
            return receipt, ["aggregate receipt does not match current canonical runtime artifacts"]
        return receipt, []
    except AggregateReceiptError as exc:
        return {}, [f"aggregate receipt validation failed: {exc}"]
