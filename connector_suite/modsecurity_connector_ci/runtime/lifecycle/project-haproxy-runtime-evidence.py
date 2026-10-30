#!/usr/bin/env python3
"""Project one HAProxy runtime receipt into a sealed upload-safe package.

The HAProxy runtime tree is same-UID writable and can contain raw request,
response, log, and configuration material. This helper consumes only one
strict source receipt, then creates and verifies a new canonical package as a
separate unprivileged evidence identity. It never copies runtime files or
requires a privileged Python invocation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping, Sequence


SOURCE_RECEIPT_FILENAME = "haproxy-runtime-receipt.json"
EVIDENCE_FILENAME = "haproxy-runtime-evidence.json"
MANIFEST_FILENAME = "manifest.json"
SOURCE_SCHEMA_VERSION = 1
EVIDENCE_SCHEMA_VERSION = 1
MAX_SOURCE_RECEIPT_BYTES = 16 * 1024
MAX_FILE_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 256 * 1024
MAX_DIGEST_REPORT_BYTES = 1024
STAGE_PARENT_PREFIX = "haproxy-runtime-evidence-parent."
STAGE_PARENT_NAME = re.compile(
    rf"^{re.escape(STAGE_PARENT_PREFIX)}[A-Za-z0-9]{{8}}$", re.ASCII
)
STAGE_DIRECTORY_NAME = "package"
SHA40 = re.compile(r"^[0-9a-f]{40}$", re.ASCII)
SHA256 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


class EvidenceProjectionError(ValueError):
    """The untrusted runtime input or staged package violated its fixed contract."""


class TrustedRuntimeValues:
    """Workflow-owned immutable revisions used to bind the receipt."""

    __slots__ = ("parent_sha", "framework_sha", "mrts_sha", "cell_run_id")

    def __init__(
        self,
        *,
        parent_sha: str,
        framework_sha: str,
        mrts_sha: str,
        cell_run_id: str,
    ) -> None:
        self.parent_sha = _require_sha(parent_sha)
        self.framework_sha = _require_sha(framework_sha)
        self.mrts_sha = _require_sha(mrts_sha)
        self.cell_run_id = _require_cell_run_id(cell_run_id)


SOURCE_RECEIPT_FIELDS = frozenset(
    {
        "case_id",
        "cell_run_id",
        "cell_run_id_kind",
        "cleanup_result",
        "connector",
        "connector_profile",
        "crs_mode",
        "engine_decision",
        "evidence_scope",
        "expected_status",
        "framework_sha",
        "host_action",
        "host_status",
        "integration_mode",
        "mrts_mode",
        "mrts_sha",
        "observed_phases",
        "parent_sha",
        "phase_counts",
        "processes_waited",
        "record_type",
        "requested_action",
        "rule_id",
        "runtime_result",
        "schema_version",
        "transport_result",
    }
)
EVIDENCE_FIELDS = frozenset(SOURCE_RECEIPT_FIELDS)
MANIFEST_FIELDS = frozenset({"files", "record_type", "schema_version"})
DIGEST_REPORT_FIELDS = frozenset({"files", "record_type", "schema_version"})


def _require_sha(value: str) -> str:
    if not isinstance(value, str) or SHA40.fullmatch(value) is None:
        raise EvidenceProjectionError("INVALID_TRUSTED_SHA")
    return value


def _require_cell_run_id(value: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,47}", value, re.ASCII)
        is None
    ):
        raise EvidenceProjectionError("INVALID_CELL_RUN_ID")
    return value


def _require_runtime_uid(runtime_uid: int) -> int:
    if isinstance(runtime_uid, bool) or not isinstance(runtime_uid, int) or runtime_uid <= 0:
        raise EvidenceProjectionError("INVALID_RUNTIME_UID")
    return runtime_uid


def _require_evidence_identity(
    *,
    runtime_uid: int,
    upload_gid: int,
    evidence_uid: int | None,
    evidence_gid: int | None,
) -> tuple[int, int]:
    """Resolve the sealed-stage owner without conflating it with its reader."""
    caller_uid, caller_gid = _require_unprivileged_identity()
    if evidence_uid is None and evidence_gid is None:
        return caller_uid, caller_gid
    if evidence_uid is None or evidence_gid is None:
        raise EvidenceProjectionError("INCOMPLETE_EVIDENCE_IDENTITY")
    if (
        isinstance(evidence_uid, bool)
        or not isinstance(evidence_uid, int)
        or evidence_uid <= 0
        or isinstance(evidence_gid, bool)
        or not isinstance(evidence_gid, int)
        or evidence_gid <= 0
    ):
        raise EvidenceProjectionError("INVALID_EVIDENCE_IDENTITY")
    if evidence_uid == runtime_uid or evidence_gid == upload_gid:
        raise EvidenceProjectionError("NONSEPARATE_EVIDENCE_IDENTITY")
    return evidence_uid, evidence_gid


def _require_unprivileged_identity() -> tuple[int, int]:
    """Reject a caller that could turn a checkout parser into a root sink."""
    uid = os.geteuid()
    gid = os.getegid()
    if uid == 0:
        raise EvidenceProjectionError("PRIVILEGED_PROJECTOR_FORBIDDEN")
    return uid, gid


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the one permitted JSON encoding for source and staged records."""
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (RecursionError, TypeError, ValueError) as error:
        raise EvidenceProjectionError("NON_CANONICAL_JSON_VALUE") from error
    data = (rendered + "\n").encode("utf-8")
    if b"\x00" in data:
        raise EvidenceProjectionError("NUL_IN_CANONICAL_JSON")
    return data


def _reject_json_constant(_: str) -> None:
    raise EvidenceProjectionError("NON_FINITE_JSON_VALUE")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceProjectionError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _parse_canonical_object(raw: bytes, *, maximum_bytes: int) -> dict[str, object]:
    if not raw or len(raw) > maximum_bytes or b"\x00" in raw or not raw.endswith(b"\n"):
        raise EvidenceProjectionError("UNSAFE_JSON_BYTES")
    try:
        text = raw.decode("utf-8")
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except EvidenceProjectionError:
        raise
    except (RecursionError, ValueError) as error:
        raise EvidenceProjectionError("INVALID_JSON") from error
    if not isinstance(parsed, dict):
        raise EvidenceProjectionError("JSON_OBJECT_REQUIRED")
    if canonical_json_bytes(parsed) != raw:
        raise EvidenceProjectionError("JSON_NOT_CANONICAL")
    return parsed


def _required_open_flags() -> tuple[int, int, int, int]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    if not isinstance(nofollow, int) or not isinstance(directory, int) or not isinstance(nonblock, int):
        raise EvidenceProjectionError("SAFE_OPEN_CAPABILITY_UNAVAILABLE")
    return nofollow, directory, nonblock, getattr(os, "O_CLOEXEC", 0)


def _validated_component(value: str) -> str:
    if not value or value in {".", ".."} or "/" in value or "\\" in value or "\x00" in value:
        raise EvidenceProjectionError("UNSAFE_PATH_COMPONENT")
    return value


def _open_absolute_directory(path: Path, *, label: str) -> int:
    text = os.fspath(path)
    if (
        not os.path.isabs(text)
        or text == os.sep
        or os.path.normpath(text) != text
        or "\x00" in text
    ):
        raise EvidenceProjectionError("UNSAFE_DIRECTORY_PATH")
    nofollow, directory, _nonblock, close_on_exec = _required_open_flags()
    descriptor = -1
    try:
        descriptor = os.open(os.sep, os.O_RDONLY | directory | close_on_exec)
        for component in Path(text).parts[1:]:
            _validated_component(component)
            next_descriptor = os.open(
                component,
                os.O_RDONLY | directory | nofollow | close_on_exec,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        details = os.fstat(descriptor)
        if not stat.S_ISDIR(details.st_mode):
            raise EvidenceProjectionError("DIRECTORY_REQUIRED")
        result = descriptor
        descriptor = -1
        return result
    except EvidenceProjectionError:
        raise
    except OSError as error:
        raise EvidenceProjectionError(f"UNSAFE_{label.upper()}_DIRECTORY") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _list_exactly(descriptor: int, expected: set[str], *, label: str) -> None:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        names = set(os.listdir(descriptor))
    except OSError as error:
        raise EvidenceProjectionError(f"UNREADABLE_{label.upper()}_DIRECTORY") from error
    if names != expected:
        raise EvidenceProjectionError(f"UNEXPECTED_{label.upper()}_CONTENTS")


def _same_identity(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev == after.st_dev
        and before.st_ino == after.st_ino
        and before.st_size == after.st_size
        and before.st_mode == after.st_mode
        and before.st_uid == after.st_uid
        and before.st_gid == after.st_gid
        and before.st_nlink == after.st_nlink
    )


def _read_regular_child(
    directory_descriptor: int,
    name: str,
    *,
    maximum_bytes: int,
    owner_uid: int,
    owner_gid: int | None = None,
    mode: int,
    label: str,
) -> bytes:
    _validated_component(name)
    nofollow, _directory, nonblock, close_on_exec = _required_open_flags()
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | nofollow | nonblock | close_on_exec,
            dir_fd=directory_descriptor,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != owner_uid
            or (owner_gid is not None and before.st_gid != owner_gid)
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_size <= 0
            or before.st_size > maximum_bytes
        ):
            raise EvidenceProjectionError(f"UNSAFE_{label.upper()}_FILE")
        pieces: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 8192))
            if not chunk:
                break
            pieces.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(pieces)
        after = os.fstat(descriptor)
        if len(raw) != before.st_size or not _same_identity(before, after):
            raise EvidenceProjectionError(f"RACED_{label.upper()}_FILE")
        return raw
    except EvidenceProjectionError:
        raise
    except OSError as error:
        raise EvidenceProjectionError(f"UNSAFE_{label.upper()}_FILE") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _validate_output_request(
    name: str,
    data: bytes,
    *,
    owner_uid: int | None,
    owner_gid: int | None,
    label: str,
) -> None:
    _validated_component(name)
    if not data or len(data) > MAX_FILE_BYTES or b"\x00" in data:
        raise EvidenceProjectionError(f"UNSAFE_{label.upper()}_OUTPUT")
    if (owner_uid is None) != (owner_gid is None):
        raise EvidenceProjectionError(f"UNSAFE_{label.upper()}_OWNER")


def _apply_output_owner(
    descriptor: int,
    *,
    owner_uid: int | None,
    owner_gid: int | None,
) -> None:
    if owner_uid is None or owner_gid is None:
        return
    current_owner = os.fstat(descriptor)
    if current_owner.st_uid != owner_uid or current_owner.st_gid != owner_gid:
        os.fchown(descriptor, owner_uid, owner_gid)


def _write_all(descriptor: int, data: bytes) -> None:
    written = 0
    while written < len(data):
        count = os.write(descriptor, data[written:])
        if count <= 0:
            raise OSError("short evidence write")
        written += count


def _verify_regular_output(
    descriptor: int,
    *,
    mode: int,
    owner_uid: int | None,
    owner_gid: int | None,
    label: str,
) -> None:
    details = os.fstat(descriptor)
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_nlink != 1
        or stat.S_IMODE(details.st_mode) != mode
        or (owner_uid is not None and details.st_uid != owner_uid)
        or (owner_gid is not None and details.st_gid != owner_gid)
    ):
        raise EvidenceProjectionError(f"UNSAFE_{label.upper()}_OUTPUT")


def _write_regular_child(
    directory_descriptor: int,
    name: str,
    data: bytes,
    *,
    mode: int,
    owner_uid: int | None = None,
    owner_gid: int | None = None,
    label: str,
) -> None:
    _validate_output_request(
        name,
        data,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        label=label,
    )
    nofollow, _directory, _nonblock, close_on_exec = _required_open_flags()
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | close_on_exec,
            mode,
            dir_fd=directory_descriptor,
        )
        _apply_output_owner(descriptor, owner_uid=owner_uid, owner_gid=owner_gid)
        _write_all(descriptor, data)
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        _verify_regular_output(
            descriptor,
            mode=mode,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            label=label,
        )
    except EvidenceProjectionError:
        raise
    except OSError as error:
        raise EvidenceProjectionError(f"UNSAFE_{label.upper()}_OUTPUT") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _source_receipt(trusted: TrustedRuntimeValues, observed_status: int) -> dict[str, object]:
    if isinstance(observed_status, bool) or observed_status != 403:
        raise EvidenceProjectionError("UNEXPECTED_HOST_STATUS")
    return {
        "case_id": "crs_sqli_anomaly_block",
        "cell_run_id": trusted.cell_run_id,
        "cell_run_id_kind": "workflow_cell",
        "cleanup_result": "complete",
        "connector": "haproxy",
        "connector_profile": "haproxy_spoe_spop_htx",
        "crs_mode": "with-crs",
        "engine_decision": "block",
        "evidence_scope": "single_case_request_phase2",
        "expected_status": 403,
        "framework_sha": trusted.framework_sha,
        "host_action": "enforced_reply",
        "host_status": observed_status,
        "integration_mode": "spoe_spop_request",
        "mrts_mode": "no-mrts",
        "mrts_sha": trusted.mrts_sha,
        "observed_phases": ["P2"],
        "parent_sha": trusted.parent_sha,
        "phase_counts": {"P1": 0, "P2": 1, "P3": 0, "P4": 0},
        "processes_waited": ["backend", "spoa", "haproxy"],
        "record_type": "haproxy_runtime_source_receipt",
        "requested_action": "deny",
        "rule_id": 942270,
        "runtime_result": "success",
        "schema_version": SOURCE_SCHEMA_VERSION,
        "transport_result": "http_status",
    }


def _evidence_document(trusted: TrustedRuntimeValues) -> dict[str, object]:
    document = _source_receipt(trusted, 403)
    document["record_type"] = "haproxy_runtime_evidence"
    document["schema_version"] = EVIDENCE_SCHEMA_VERSION
    return document


def _strictly_equal_mappings(
    actual: dict[object, object], expected: dict[object, object]
) -> bool:
    return set(actual) == set(expected) and all(
        _strictly_equal(actual[key], expected[key]) for key in expected
    )


def _strictly_equal_lists(actual: list[object], expected: list[object]) -> bool:
    return len(actual) == len(expected) and all(
        _strictly_equal(item, expected_item) for item, expected_item in zip(actual, expected)
    )


def _strictly_equal(actual: object, expected: object) -> bool:
    """Compare parsed JSON without Python's bool/int or int/float aliases."""
    if type(actual) is not type(expected):
        return False
    if isinstance(actual, dict) and isinstance(expected, dict):
        return _strictly_equal_mappings(actual, expected)
    if isinstance(actual, list) and isinstance(expected, list):
        return _strictly_equal_lists(actual, expected)
    return actual == expected


def _validate_source_receipt(value: dict[str, object], trusted: TrustedRuntimeValues) -> None:
    if set(value) != SOURCE_RECEIPT_FIELDS:
        raise EvidenceProjectionError("SOURCE_RECEIPT_SCHEMA_REJECTED")
    if not _strictly_equal(value, _source_receipt(trusted, 403)):
        raise EvidenceProjectionError("SOURCE_RECEIPT_VALUES_REJECTED")


def _manifest(evidence: bytes) -> dict[str, object]:
    return {
        "files": [
            {
                "name": EVIDENCE_FILENAME,
                "sha256": hashlib.sha256(evidence).hexdigest(),
                "size_bytes": len(evidence),
            }
        ],
        "record_type": "haproxy_runtime_evidence_manifest",
        "schema_version": EVIDENCE_SCHEMA_VERSION,
    }


def _digest_report(digests: Mapping[str, str]) -> dict[str, object]:
    expected_names = (EVIDENCE_FILENAME, MANIFEST_FILENAME)
    if set(digests) != set(expected_names):
        raise EvidenceProjectionError("DIGEST_REPORT_REJECTED")
    files: list[dict[str, str]] = []
    for name in expected_names:
        digest = digests[name]
        if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            raise EvidenceProjectionError("DIGEST_REPORT_REJECTED")
        files.append({"name": name, "sha256": digest})
    return {
        "files": files,
        "record_type": "haproxy_runtime_evidence_digests",
        "schema_version": EVIDENCE_SCHEMA_VERSION,
    }


def _digest_report_bytes(digests: Mapping[str, str]) -> bytes:
    report = _digest_report(digests)
    data = canonical_json_bytes(report)
    if not data or len(data) > MAX_DIGEST_REPORT_BYTES or b"\x00" in data:
        raise EvidenceProjectionError("DIGEST_REPORT_REJECTED")
    parsed = _parse_canonical_object(data, maximum_bytes=MAX_DIGEST_REPORT_BYTES)
    if set(parsed) != DIGEST_REPORT_FIELDS or not _strictly_equal(parsed, report):
        raise EvidenceProjectionError("DIGEST_REPORT_REJECTED")
    return data


def write_source_receipt(
    *,
    source_root: Path,
    trusted: TrustedRuntimeValues,
    observed_status: int,
) -> Path:
    """Write the strict, un-uploadable source receipt after harness cleanup."""
    _require_unprivileged_identity()
    data = canonical_json_bytes(_source_receipt(trusted, observed_status))
    if len(data) > MAX_SOURCE_RECEIPT_BYTES:
        raise EvidenceProjectionError("SOURCE_RECEIPT_TOO_LARGE")
    descriptor = _open_absolute_directory(source_root, label="source")
    try:
        details = os.fstat(descriptor)
        if (
            details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) != 0o700
            or not stat.S_ISDIR(details.st_mode)
        ):
            raise EvidenceProjectionError("UNSAFE_SOURCE_DIRECTORY")
        _list_exactly(descriptor, set(), label="source")
        _write_regular_child(
            descriptor,
            SOURCE_RECEIPT_FILENAME,
            data,
            mode=0o600,
            label="source_receipt",
        )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return source_root / SOURCE_RECEIPT_FILENAME


def _read_valid_source_receipt(
    *,
    source_root: Path,
    trusted: TrustedRuntimeValues,
    runtime_uid: int,
) -> dict[str, object]:
    descriptor = _open_absolute_directory(source_root, label="source")
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(details.st_mode)
            or details.st_uid != runtime_uid
            or stat.S_IMODE(details.st_mode) != 0o700
        ):
            raise EvidenceProjectionError("UNSAFE_SOURCE_DIRECTORY")
        _list_exactly(descriptor, {SOURCE_RECEIPT_FILENAME}, label="source")
        raw = _read_regular_child(
            descriptor,
            SOURCE_RECEIPT_FILENAME,
            maximum_bytes=MAX_SOURCE_RECEIPT_BYTES,
            owner_uid=runtime_uid,
            mode=0o600,
            label="source_receipt",
        )
        after_read = os.fstat(descriptor)
        if not _same_identity(details, after_read) or stat.S_IMODE(after_read.st_mode) != 0o700:
            raise EvidenceProjectionError("RACED_SOURCE_DIRECTORY")
        _list_exactly(descriptor, {SOURCE_RECEIPT_FILENAME}, label="source")
    finally:
        os.close(descriptor)
    parsed = _parse_canonical_object(raw, maximum_bytes=MAX_SOURCE_RECEIPT_BYTES)
    _validate_source_receipt(parsed, trusted)
    return parsed


def export_source_receipt(
    *,
    source_root: Path,
    trusted: TrustedRuntimeValues,
    runtime_uid: int,
) -> bytes:
    """Read one source receipt and return only its canonical allowlist document."""
    _require_runtime_uid(runtime_uid)
    _require_unprivileged_identity()
    source = _read_valid_source_receipt(
        source_root=source_root,
        trusted=trusted,
        runtime_uid=runtime_uid,
    )
    return canonical_json_bytes(source)


def _stage_parent_name(*, runner_temp: Path, stage_parent: Path, stage_root: Path) -> str:
    runner_text = os.fspath(runner_temp)
    parent_text = os.fspath(stage_parent)
    stage_text = os.fspath(stage_root)
    if (
        not os.path.isabs(runner_text)
        or not os.path.isabs(parent_text)
        or not os.path.isabs(stage_text)
        or os.path.normpath(runner_text) != runner_text
        or os.path.normpath(parent_text) != parent_text
        or os.path.normpath(stage_text) != stage_text
        or os.path.dirname(parent_text) != runner_text
        or os.path.dirname(stage_text) != parent_text
        or os.path.basename(stage_text) != STAGE_DIRECTORY_NAME
    ):
        raise EvidenceProjectionError("UNSAFE_STAGE_PATH")
    parent_name = os.path.basename(parent_text)
    if STAGE_PARENT_NAME.fullmatch(parent_name) is None:
        raise EvidenceProjectionError("UNSAFE_STAGE_PARENT")
    return parent_name


def _close_stage_descriptors(*descriptors: int) -> None:
    for descriptor in reversed(descriptors):
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _open_staging_directory(
    *,
    runner_temp: Path,
    stage_parent: Path,
    stage_root: Path,
    runtime_uid: int,
    stage_uid: int,
    stage_gid: int,
    expected_stage_mode: int,
) -> tuple[int, int, int]:
    parent_name = _stage_parent_name(
        runner_temp=runner_temp,
        stage_parent=stage_parent,
        stage_root=stage_root,
    )
    nofollow, directory, _nonblock, close_on_exec = _required_open_flags()
    runner_descriptor = -1
    parent_descriptor = -1
    stage_descriptor = -1
    try:
        runner_descriptor = _open_absolute_directory(runner_temp, label="runner_temp")
        parent_descriptor = os.open(
            parent_name,
            os.O_RDONLY | directory | nofollow | close_on_exec,
            dir_fd=runner_descriptor,
        )
        parent_details = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(parent_details.st_mode)
            or parent_details.st_uid != 0
            or parent_details.st_gid != 0
            or stat.S_IMODE(parent_details.st_mode) != 0o755
        ):
            raise EvidenceProjectionError("UNSAFE_STAGE_PARENT")
        stage_descriptor = os.open(
            STAGE_DIRECTORY_NAME,
            os.O_RDONLY | directory | nofollow | close_on_exec,
            dir_fd=parent_descriptor,
        )
        stage_details = os.fstat(stage_descriptor)
        if (
            not stat.S_ISDIR(stage_details.st_mode)
            or stage_details.st_uid != stage_uid
            or stage_details.st_gid != stage_gid
            or stage_uid == runtime_uid
            or stat.S_IMODE(stage_details.st_mode) != expected_stage_mode
        ):
            raise EvidenceProjectionError("UNSAFE_STAGE_DIRECTORY")
    except EvidenceProjectionError:
        _close_stage_descriptors(runner_descriptor, parent_descriptor, stage_descriptor)
        raise
    except OSError as error:
        _close_stage_descriptors(runner_descriptor, parent_descriptor, stage_descriptor)
        raise EvidenceProjectionError("UNSAFE_STAGE_DIRECTORY") from error
    return runner_descriptor, parent_descriptor, stage_descriptor


def _discard_staged_files(
    descriptor: int,
    *,
    stage_uid: int,
    stage_gid: int,
    file_gid: int,
) -> None:
    """Remove only partial allowlisted files owned by this evidence identity."""
    try:
        directory = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != stage_uid
            or directory.st_gid != stage_gid
            or stat.S_IMODE(directory.st_mode) not in {0o700, 0o550}
        ):
            raise EvidenceProjectionError("UNSAFE_STAGE_CLEANUP")
        if stat.S_IMODE(directory.st_mode) == 0o550:
            os.fchmod(descriptor, 0o700)
            directory = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(directory.st_mode)
                or directory.st_uid != stage_uid
                or directory.st_gid != stage_gid
                or stat.S_IMODE(directory.st_mode) != 0o700
            ):
                raise EvidenceProjectionError("UNSAFE_STAGE_CLEANUP")
        os.lseek(descriptor, 0, os.SEEK_SET)
        names = set(os.listdir(descriptor))
        allowed = {EVIDENCE_FILENAME, MANIFEST_FILENAME}
        if not names.issubset(allowed):
            raise EvidenceProjectionError("UNSAFE_STAGE_CLEANUP")
        for name in names:
            details = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_nlink != 1
                or details.st_uid != stage_uid
                or details.st_gid != file_gid
                or details.st_mode & 0o222
            ):
                raise EvidenceProjectionError("UNSAFE_STAGE_CLEANUP")
            os.unlink(name, dir_fd=descriptor)
        _list_exactly(descriptor, set(), label="stage")
        os.fsync(descriptor)
    except EvidenceProjectionError:
        raise
    except OSError as error:
        raise EvidenceProjectionError("STAGE_CLEANUP_FAILED") from error


def _seal_stage_directory(descriptor: int, *, stage_uid: int, stage_gid: int) -> None:
    try:
        os.fchmod(descriptor, 0o550)
        os.fsync(descriptor)
        details = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(details.st_mode)
            or details.st_uid != stage_uid
            or details.st_gid != stage_gid
            or stat.S_IMODE(details.st_mode) != 0o550
        ):
            raise EvidenceProjectionError("CANNOT_SEAL_STAGE_DIRECTORY")
    except EvidenceProjectionError:
        raise
    except OSError as error:
        raise EvidenceProjectionError("CANNOT_SEAL_STAGE_DIRECTORY") from error


def _parse_source_document(value: str, trusted: TrustedRuntimeValues) -> dict[str, object]:
    if not isinstance(value, str):
        raise EvidenceProjectionError("UNSAFE_SOURCE_DOCUMENT")
    try:
        raw = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise EvidenceProjectionError("UNSAFE_SOURCE_DOCUMENT") from error
    parsed = _parse_canonical_object(raw, maximum_bytes=MAX_SOURCE_RECEIPT_BYTES)
    _validate_source_receipt(parsed, trusted)
    return parsed


def _read_source_document_from_standard_input() -> str:
    raw = sys.stdin.buffer.read(MAX_SOURCE_RECEIPT_BYTES + 1)
    if len(raw) > MAX_SOURCE_RECEIPT_BYTES:
        raise EvidenceProjectionError("SOURCE_RECEIPT_TOO_LARGE")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceProjectionError("UNSAFE_SOURCE_DOCUMENT") from error


def project_document(
    *,
    source_document: str,
    runner_temp: Path,
    stage_parent: Path,
    stage_root: Path,
    trusted: TrustedRuntimeValues,
    runtime_uid: int,
    upload_gid: int,
) -> None:
    """Create two fixed files below the pre-created separate-owner stage."""
    runtime_uid = _require_runtime_uid(runtime_uid)
    stage_uid, evidence_gid = _require_unprivileged_identity()
    if isinstance(upload_gid, bool) or not isinstance(upload_gid, int) or upload_gid <= 0:
        raise EvidenceProjectionError("INVALID_UPLOAD_GID")
    _parse_source_document(source_document, trusted)
    evidence = canonical_json_bytes(_evidence_document(trusted))
    manifest = canonical_json_bytes(_manifest(evidence))
    if (
        len(evidence) > MAX_FILE_BYTES
        or len(manifest) > MAX_FILE_BYTES
        or len(evidence) + len(manifest) > MAX_TOTAL_BYTES
    ):
        raise EvidenceProjectionError("PACKAGE_SIZE_LIMIT")
    runner_descriptor = -1
    parent_descriptor = -1
    stage_descriptor = -1
    write_started = False
    try:
        runner_descriptor, parent_descriptor, stage_descriptor = _open_staging_directory(
            runner_temp=runner_temp,
            stage_parent=stage_parent,
            stage_root=stage_root,
            runtime_uid=runtime_uid,
            stage_uid=stage_uid,
            stage_gid=upload_gid,
            expected_stage_mode=0o700,
        )
        _list_exactly(stage_descriptor, set(), label="stage")
        write_started = True
        _write_regular_child(
            stage_descriptor,
            EVIDENCE_FILENAME,
            evidence,
            mode=0o444,
            owner_uid=stage_uid,
            owner_gid=evidence_gid,
            label="evidence",
        )
        _write_regular_child(
            stage_descriptor,
            MANIFEST_FILENAME,
            manifest,
            mode=0o444,
            owner_uid=stage_uid,
            owner_gid=evidence_gid,
            label="manifest",
        )
        _seal_stage_directory(stage_descriptor, stage_uid=stage_uid, stage_gid=upload_gid)
    except BaseException:
        if write_started and stage_descriptor >= 0:
            try:
                _discard_staged_files(
                    stage_descriptor,
                    stage_uid=stage_uid,
                    stage_gid=upload_gid,
                    file_gid=evidence_gid,
                )
            except EvidenceProjectionError as cleanup_error:
                raise EvidenceProjectionError("STAGE_CLEANUP_FAILED") from cleanup_error
        raise
    finally:
        _close_stage_descriptors(runner_descriptor, parent_descriptor, stage_descriptor)


def verify_staged_package(
    *,
    runner_temp: Path,
    stage_parent: Path,
    stage_root: Path,
    trusted: TrustedRuntimeValues,
    runtime_uid: int,
    upload_gid: int,
    evidence_uid: int | None = None,
    evidence_gid: int | None = None,
) -> dict[str, str]:
    """Reopen and validate exactly the two files passed to upload-artifact."""
    runtime_uid = _require_runtime_uid(runtime_uid)
    stage_uid, evidence_gid = _require_evidence_identity(
        runtime_uid=runtime_uid,
        upload_gid=upload_gid,
        evidence_uid=evidence_uid,
        evidence_gid=evidence_gid,
    )
    if isinstance(upload_gid, bool) or not isinstance(upload_gid, int) or upload_gid <= 0:
        raise EvidenceProjectionError("INVALID_UPLOAD_GID")
    runner_descriptor = -1
    parent_descriptor = -1
    stage_descriptor = -1
    try:
        runner_descriptor, parent_descriptor, stage_descriptor = _open_staging_directory(
            runner_temp=runner_temp,
            stage_parent=stage_parent,
            stage_root=stage_root,
            runtime_uid=runtime_uid,
            stage_uid=stage_uid,
            stage_gid=upload_gid,
            expected_stage_mode=0o550,
        )
        _list_exactly(stage_descriptor, {EVIDENCE_FILENAME, MANIFEST_FILENAME}, label="stage")
        evidence = _read_regular_child(
            stage_descriptor,
            EVIDENCE_FILENAME,
            maximum_bytes=MAX_FILE_BYTES,
            owner_uid=stage_uid,
            owner_gid=evidence_gid,
            mode=0o444,
            label="evidence",
        )
        manifest = _read_regular_child(
            stage_descriptor,
            MANIFEST_FILENAME,
            maximum_bytes=MAX_FILE_BYTES,
            owner_uid=stage_uid,
            owner_gid=evidence_gid,
            mode=0o444,
            label="manifest",
        )
    finally:
        _close_stage_descriptors(runner_descriptor, parent_descriptor, stage_descriptor)
    if len(evidence) + len(manifest) > MAX_TOTAL_BYTES:
        raise EvidenceProjectionError("PACKAGE_SIZE_LIMIT")
    evidence_document = _parse_canonical_object(evidence, maximum_bytes=MAX_FILE_BYTES)
    if set(evidence_document) != EVIDENCE_FIELDS or not _strictly_equal(
        evidence_document, _evidence_document(trusted)
    ):
        raise EvidenceProjectionError("EVIDENCE_SCHEMA_REJECTED")
    manifest_document = _parse_canonical_object(manifest, maximum_bytes=MAX_FILE_BYTES)
    if set(manifest_document) != MANIFEST_FIELDS or not _strictly_equal(
        manifest_document, _manifest(evidence)
    ):
        raise EvidenceProjectionError("MANIFEST_REJECTED")
    return {
        EVIDENCE_FILENAME: hashlib.sha256(evidence).hexdigest(),
        MANIFEST_FILENAME: hashlib.sha256(manifest).hexdigest(),
    }


def _trusted_from_arguments(arguments: argparse.Namespace) -> TrustedRuntimeValues:
    return TrustedRuntimeValues(
        parent_sha=arguments.expected_parent_sha,
        framework_sha=arguments.expected_framework_sha,
        mrts_sha=arguments.expected_mrts_sha,
        cell_run_id=arguments.expected_cell_run_id,
    )


def _add_trusted_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--expected-parent-sha", required=True)
    parser.add_argument("--expected-framework-sha", required=True)
    parser.add_argument("--expected-mrts-sha", required=True)
    parser.add_argument("--expected-cell-run-id", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    write = commands.add_parser("write-source-receipt")
    write.add_argument("--source-root", required=True)
    write.add_argument("--observed-status", required=True, type=int)
    _add_trusted_arguments(write)

    export = commands.add_parser("export-source-receipt")
    export.add_argument("--source-root", required=True)
    export.add_argument("--runtime-uid", required=True, type=int)
    _add_trusted_arguments(export)

    project = commands.add_parser("project-document")
    project.add_argument("--source-document-stdin", action="store_true")
    project.add_argument("--runner-temp", required=True)
    project.add_argument("--stage-parent", required=True)
    project.add_argument("--stage-root", required=True)
    project.add_argument("--runtime-uid", required=True, type=int)
    project.add_argument("--upload-gid", required=True, type=int)
    _add_trusted_arguments(project)

    verify = commands.add_parser("verify")
    verify.add_argument("--runner-temp", required=True)
    verify.add_argument("--stage-parent", required=True)
    verify.add_argument("--stage-root", required=True)
    verify.add_argument("--runtime-uid", required=True, type=int)
    verify.add_argument("--upload-gid", required=True, type=int)
    _add_trusted_arguments(verify)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        trusted = _trusted_from_arguments(args)
        if args.command == "write-source-receipt":
            write_source_receipt(
                source_root=Path(args.source_root),
                trusted=trusted,
                observed_status=args.observed_status,
            )
        elif args.command == "export-source-receipt":
            sys.stdout.buffer.write(
                export_source_receipt(
                    source_root=Path(args.source_root),
                    trusted=trusted,
                    runtime_uid=args.runtime_uid,
                )
            )
        elif args.command == "project-document":
            if not args.source_document_stdin:
                raise EvidenceProjectionError("UNSAFE_SOURCE_DOCUMENT")
            project_document(
                source_document=_read_source_document_from_standard_input(),
                runner_temp=Path(args.runner_temp),
                stage_parent=Path(args.stage_parent),
                stage_root=Path(args.stage_root),
                trusted=trusted,
                runtime_uid=args.runtime_uid,
                upload_gid=args.upload_gid,
            )
        else:
            sys.stdout.buffer.write(
                _digest_report_bytes(
                    verify_staged_package(
                        runner_temp=Path(args.runner_temp),
                        stage_parent=Path(args.stage_parent),
                        stage_root=Path(args.stage_root),
                        trusted=trusted,
                        runtime_uid=args.runtime_uid,
                        upload_gid=args.upload_gid,
                    )
                )
            )
    except EvidenceProjectionError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
