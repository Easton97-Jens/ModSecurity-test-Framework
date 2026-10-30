#!/usr/bin/env python3
"""Validate root-owned evidence from the protected exact-head NGINX run."""
from __future__ import annotations
import argparse
from dataclasses import dataclass
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Callable

SHA40 = re.compile(r"^(?a:[\da-f]{40})$")
SHA256 = re.compile(r"^(?a:[\da-f]{64})$")
TX = re.compile(r"^nginx-exact-head-(?a:\d+)-(?a:\d+)-(?a:\d+)$")
FILES = frozenset({"identity.json", "runtime.json", "on.jsonl", "off.jsonl", "exit.json"})
EVIDENCE_ROOT_NAME = "launcher-evidence"
RESULT_OUTPUT_NAME = "exact-head-result.json"
RESULT_TEMPORARY_PREFIX = f".{RESULT_OUTPUT_NAME}.tmp-"
DISPATCHER_MANIFEST_NAME = "dispatcher-manifest.json"
DISPATCHER_MANIFEST_LABEL = "dispatcher manifest"
TASK_INPUT_COMPONENTS = ("inputs", "dispatcher")
REPO = "Easton97-Jens/ModSecurity-conector"
NGINX_VERSION = "1.31.6"
NGINX_SOURCE_DIGEST = "974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1"
MAX_JSON = 64 * 1024
MAX_JSONL = 2 * 1024 * 1024

IDENTITY_FIELDS = frozenset({
    "schema_version", "runner_uid", "runner_gid", "expected_worker_uid",
    "expected_worker_gid", "on", "off",
})
CELL_FIELDS = frozenset({
    "master_pid", "worker_pid", "master_uid", "master_gid", "worker_uid",
    "worker_gid",
})
RUNTIME_FIELDS = frozenset({
    "schema_version", "tested_pr_head", "tested_pr_base",
    "trusted_dispatcher_base_sha",
    "candidate_run_id", "nginx_version", "nginx_source_digest",
    "connector_module_digest",
})
JSONL_FIELDS = frozenset({
    "callback_observed", "callback_observation_source", "http_status",
    "http_status_observation_source", "jsonl_observed",
    "jsonl_observation_source", "mode", "transaction_id", "waf_decision",
})
EXIT_FIELDS = frozenset({"schema_version", "on_exit", "off_exit"})

class CollectorError(ValueError):
    """Evidence failed the authenticity contract."""


@dataclass(frozen=True)
class EvidenceObservations:
    """Validated, root-published facts used for the sanitized terminal result."""

    cells: dict[str, dict[str, Any]]
    tested_pr_base: str
    connector_module_digest: str
    on: dict[str, Any]
    off: dict[str, Any]

def _dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise CollectorError("duplicate JSON key")
        out[key] = value
    return out

def _metadata_key(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _require_bounded_regular(
    metadata: os.stat_result, label: str, limit: int
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > limit
    ):
        raise CollectorError(f"{label} is not bounded")


def _require_root_evidence_file(
    metadata: os.stat_result, label: str, limit: int
) -> None:
    _require_bounded_regular(metadata, label, limit)
    if (
        metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise CollectorError(f"unsafe evidence file: {label}")


def _stable_read_descriptor(
    descriptor: int,
    label: str,
    limit: int,
    validator: Callable[[os.stat_result, str, int], None],
) -> bytes:
    try:
        before = os.fstat(descriptor)
        validator(before, label, limit)
        data = bytearray()
        while True:
            chunk = os.read(descriptor, min(65536, limit - len(data) + 1))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > limit:
                raise CollectorError(f"{label} exceeds limit")
        after = os.fstat(descriptor)
    except OSError as exc:
        raise CollectorError(f"{label} unavailable") from exc
    if _metadata_key(before) != _metadata_key(after):
        raise CollectorError(f"{label} changed")
    return bytes(data)


def _obj(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != fields:
        raise CollectorError(f"{label} schema mismatch")
    return value


def _version_one(value: Any) -> bool:
    """Require the JSON integer version, rather than Python's bool-equivalent 1."""
    return type(value) is int and value == 1


def _open_root_owned_evidence(task_descriptor: int) -> int:
    """Open the single root-owned evidence leaf below the admitted task FD."""
    descriptor = -1
    try:
        before = os.stat(
            EVIDENCE_ROOT_NAME,
            dir_fd=task_descriptor,
            follow_symlinks=False,
        )
        if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise CollectorError("unsafe evidence root")
        descriptor = os.open(
            EVIDENCE_ROOT_NAME,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=task_descriptor,
        )
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise CollectorError("evidence root changed while being opened")
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise CollectorError("unsafe evidence root")
        result = descriptor
        descriptor = -1
        return result
    except OSError as exc:
        raise CollectorError("evidence root unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _open_evidence_file(
    root_descriptor: int, name: str, label: str, limit: int
) -> int:
    """Open one fixed evidence leaf relative to its retained root descriptor."""
    if name not in FILES:
        raise CollectorError("evidence file is outside the fixed allowlist")
    descriptor = -1
    try:
        before = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode):
            raise CollectorError(f"unsafe evidence file: {label}")
        _require_root_evidence_file(before, label, limit)
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=root_descriptor,
        )
        opened = os.fstat(descriptor)
        if _metadata_key(opened) != _metadata_key(before):
            raise CollectorError(f"{label} changed while being opened")
        _require_root_evidence_file(opened, label, limit)
        result = descriptor
        descriptor = -1
        return result
    except FileNotFoundError as exc:
        raise CollectorError(f"missing evidence file: {name}") from exc
    except OSError as exc:
        raise CollectorError(f"{label} unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_root_evidence(
    root_descriptor: int, name: str, label: str, limit: int
) -> bytes:
    descriptor = _open_evidence_file(root_descriptor, name, label, limit)
    try:
        return _stable_read_descriptor(
            descriptor, label, limit, _require_root_evidence_file
        )
    finally:
        os.close(descriptor)


def _json_root_evidence(
    root_descriptor: int, name: str, label: str, limit: int = MAX_JSON
) -> Any:
    return _json_bytes(_read_root_evidence(root_descriptor, name, label, limit), label)

def _open_task_root(path: Path, runner_uid: int, runner_gid: int) -> int:
    if (
        not path.is_absolute()
        or any(part in {".", ".."} for part in path.parts)
        or path == Path("/")
        or runner_uid < 0
        or runner_gid < 0
    ):
        raise CollectorError("task root path is unsafe")
    descriptor = -1
    try:
        descriptor = os.open(
            path.root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        for part in path.parts[1:]:
            before = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
                raise CollectorError("task root contains an unsafe component")
            next_descriptor = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            opened = os.fstat(next_descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                os.close(next_descriptor)
                raise CollectorError("task root changed while being opened")
            os.close(descriptor)
            descriptor = next_descriptor
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != runner_uid
            or metadata.st_gid != runner_gid
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise CollectorError("task root ownership or mode is unsafe")
        result = descriptor
        descriptor = -1
        return result
    except OSError as exc:
        raise CollectorError("task root is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _sha(value: Any, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise CollectorError(f"{label} has invalid digest")
    return value

def _require_runner_input_file(
    metadata: os.stat_result, label: str, limit: int, runner_uid: int, runner_gid: int
) -> None:
    _require_bounded_regular(metadata, label, limit)
    if (
        metadata.st_uid != runner_uid
        or metadata.st_gid != runner_gid
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise CollectorError(f"unsafe task input file: {label}")


def _open_task_input_directory(parent: int, component: str) -> int:
    """Open one fixed input directory and verify the descriptor identity."""
    descriptor = -1
    try:
        before = os.stat(component, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise CollectorError("unsafe dispatcher input directory")
        descriptor = os.open(
            component,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise CollectorError("dispatcher input directory changed while opening")
        result = descriptor
        descriptor = -1
        return result
    except OSError as exc:
        raise CollectorError("dispatcher input directory unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _open_task_input_manifest(
    task_descriptor: int,
    manifest_path: Path,
    task_root: Path,
    runner_uid: int,
    runner_gid: int,
) -> int:
    """Open only the dispatcher manifest at the fixed task-root location."""
    expected = task_root / "inputs" / "dispatcher" / DISPATCHER_MANIFEST_NAME
    if manifest_path != expected:
        raise CollectorError(
            f"{DISPATCHER_MANIFEST_LABEL} is outside the fixed task-root input"
        )
    descriptors: list[int] = []
    result = -1
    current = task_descriptor
    try:
        for component in TASK_INPUT_COMPONENTS:
            child = _open_task_input_directory(current, component)
            descriptors.append(child)
            current = child
        before = os.stat(
            DISPATCHER_MANIFEST_NAME, dir_fd=current, follow_symlinks=False
        )
        _require_runner_input_file(
            before, DISPATCHER_MANIFEST_LABEL, MAX_JSON, runner_uid, runner_gid
        )
        result = os.open(
            DISPATCHER_MANIFEST_NAME,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=current,
        )
        opened = os.fstat(result)
        if _metadata_key(opened) != _metadata_key(before):
            os.close(result)
            result = -1
            raise CollectorError(
                f"{DISPATCHER_MANIFEST_LABEL} changed while being opened"
            )
        _require_runner_input_file(
            opened, DISPATCHER_MANIFEST_LABEL, MAX_JSON, runner_uid, runner_gid
        )
        admitted = result
        result = -1
        return admitted
    except FileNotFoundError as exc:
        raise CollectorError(
            f"{DISPATCHER_MANIFEST_LABEL} input is unavailable"
        ) from exc
    except OSError as exc:
        raise CollectorError(
            f"{DISPATCHER_MANIFEST_LABEL} input is unavailable"
        ) from exc
    finally:
        if result >= 0:
            os.close(result)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _manifest_from_task_root(
    task_descriptor: int,
    manifest_path: Path,
    task_root: Path,
    runner_uid: int,
    runner_gid: int,
) -> dict[str, Any]:
    descriptor = _open_task_input_manifest(
        task_descriptor, manifest_path, task_root, runner_uid, runner_gid
    )
    try:
        raw = _stable_read_descriptor(
            descriptor,
            DISPATCHER_MANIFEST_LABEL,
            MAX_JSON,
            lambda metadata, label, limit: _require_runner_input_file(
                metadata, label, limit, runner_uid, runner_gid
            ),
        )
    finally:
        os.close(descriptor)
    return _manifest_value(_json_bytes(raw, DISPATCHER_MANIFEST_LABEL))


def _manifest_value(value: Any) -> dict[str, Any]:
    fields = frozenset({
        "schema_version", "trusted_dispatcher_base_sha", "run_id", "pr_number",
        "tested_pr_head", "tested_pr_head_ref", "tested_pr_head_repository",
        "tested_pr_base", "tested_pr_base_ref", "tested_pr_base_repository",
        "draft", "state", "merged",
    })
    value = _obj(value, fields, DISPATCHER_MANIFEST_LABEL)
    if (not _version_one(value["schema_version"])
            or type(value["pr_number"]) is not int
            or value["pr_number"] <= 0):
        raise CollectorError("invalid dispatcher identity")
    for key in ("trusted_dispatcher_base_sha", "tested_pr_head", "tested_pr_base"):
        _sha(value[key], key, SHA40)
    if (value["tested_pr_base_ref"] != "master"
            or value["tested_pr_base_repository"] != REPO
            or value["tested_pr_head_repository"] != REPO
            or value["state"] != "open" or value["draft"] is not True
            or value["merged"] is not False):
        raise CollectorError("manifest is not an eligible draft PR")
    return value

def _identity_cell(value: Any, label: str) -> dict[str, Any]:
    cell = _obj(value, CELL_FIELDS, label)
    for key in ("master_pid", "worker_pid"):
        if type(cell[key]) is not int or cell[key] <= 0:
            raise CollectorError(f"{label} invalid PID")
    for key in ("master_uid", "master_gid", "worker_uid", "worker_gid"):
        if type(cell[key]) is not int or cell[key] < 0:
            raise CollectorError(f"{label} invalid UID/GID")
    if (cell["master_pid"] == cell["worker_pid"]
            or cell["master_uid"] == cell["worker_uid"]
            or cell["worker_uid"] == 0 or cell["worker_gid"] == 0):
        raise CollectorError(f"{label} lacks distinct identity")
    return cell

def _jsonl(root_descriptor: int, mode: str) -> dict[str, Any]:
    lines = _read_root_evidence(
        root_descriptor, f"{mode}.jsonl", f"{mode} JSONL", MAX_JSONL
    ).splitlines()
    if (len(lines) != 1 or not lines[0] or b"\x1b" in lines[0]
            or b"::" in lines[0]):
        raise CollectorError(f"{mode} JSONL must contain one safe event")
    value = _obj(_json_bytes(lines[0], f"{mode} JSONL"), JSONL_FIELDS, f"{mode} JSONL")
    if (value["mode"] != mode
            or value["callback_observed"] is not (mode == "on")
            or value["jsonl_observed"] is not True
            or value["callback_observation_source"] != "candidate_scratch_untrusted"
            or value["jsonl_observation_source"] != "candidate_scratch_untrusted"
            or value["http_status_observation_source"] != "root_pidfd_network_namespace"
            or value["http_status"] != 403 or value["waf_decision"] != "deny"
            or not isinstance(value["transaction_id"], str)
            or TX.fullmatch(value["transaction_id"]) is None):
        raise CollectorError(f"{mode} JSONL evidence is invalid")
    return value

def _json_bytes(raw: bytes, label: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_dupes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollectorError(f"{label} invalid JSON") from exc


def _validate_collection_paths(
    manifest_path: Path, evidence_root: Path, output_path: Path, task_root: Path
) -> None:
    if (
        not output_path.is_absolute()
        or any(part in {".", ".."} for part in output_path.parts)
        or output_path != task_root / RESULT_OUTPUT_NAME
    ):
        raise CollectorError("output path is outside the fixed task-root allowlist")
    if evidence_root != task_root / EVIDENCE_ROOT_NAME:
        raise CollectorError("evidence root is outside the fixed task-root allowlist")
    expected_manifest = task_root / "inputs" / "dispatcher" / DISPATCHER_MANIFEST_NAME
    if manifest_path != expected_manifest:
        raise CollectorError(
            f"{DISPATCHER_MANIFEST_LABEL} is outside the fixed task-root input"
        )


def _evidence_names(root_descriptor: int) -> None:
    try:
        names = set(os.listdir(root_descriptor))
    except OSError as exc:
        raise CollectorError("cannot enumerate evidence root") from exc
    if names != FILES:
        raise CollectorError("evidence root allowlist mismatch")


def _identity_evidence(
    root_descriptor: int, runner_uid: int, runner_gid: int
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    identity = _obj(
        _json_root_evidence(root_descriptor, "identity.json", "identity"),
        IDENTITY_FIELDS,
        "identity",
    )
    numeric_keys = (
        "runner_uid",
        "runner_gid",
        "expected_worker_uid",
        "expected_worker_gid",
    )
    if (
        not _version_one(identity["schema_version"])
        or any(type(identity[key]) is not int or identity[key] < 0 for key in numeric_keys)
        or identity["runner_uid"] != runner_uid
        or identity["runner_gid"] != runner_gid
    ):
        raise CollectorError("identity metadata invalid")
    cells = {
        mode: _identity_cell(identity[mode], f"{mode} identity")
        for mode in ("on", "off")
    }
    return identity, cells


def _validate_worker_cells(
    identity: dict[str, Any], cells: dict[str, dict[str, Any]]
) -> None:
    for cell in cells.values():
        if (
            cell["worker_uid"] != identity["expected_worker_uid"]
            or cell["worker_gid"] != identity["expected_worker_gid"]
            or cell["worker_uid"] == identity["runner_uid"]
            or cell["worker_gid"] == identity["runner_gid"]
            or cell["master_uid"] != identity["runner_uid"]
            or cell["master_gid"] != identity["runner_gid"]
        ):
            raise CollectorError("worker identity does not match root proof")


def _runtime_module_digest(
    root_descriptor: int, manifest: dict[str, Any]
) -> tuple[str, str]:
    runtime = _obj(
        _json_root_evidence(root_descriptor, "runtime.json", "runtime"),
        RUNTIME_FIELDS,
        "runtime",
    )
    if (
        not _version_one(runtime["schema_version"])
        or runtime["tested_pr_head"] != manifest["tested_pr_head"]
        or runtime["tested_pr_base"] != manifest["tested_pr_base"]
        or runtime["trusted_dispatcher_base_sha"]
        != manifest["trusted_dispatcher_base_sha"]
        or runtime["candidate_run_id"] != manifest["run_id"]
        or runtime["nginx_version"] != NGINX_VERSION
        or runtime["nginx_source_digest"] != NGINX_SOURCE_DIGEST
    ):
        raise CollectorError("runtime identity mismatch")
    return (
        _sha(runtime["connector_module_digest"], "connector_module_digest", SHA256),
        _sha(runtime["tested_pr_base"], "tested_pr_base", SHA40),
    )


def _validate_exit_evidence(root_descriptor: int) -> None:
    exit_value = _obj(
        _json_root_evidence(root_descriptor, "exit.json", "exit"),
        EXIT_FIELDS,
        "exit",
    )
    if (
        not _version_one(exit_value["schema_version"])
        or exit_value["on_exit"] != 0
        or exit_value["off_exit"] != 0
    ):
        raise CollectorError("cell exit status is not successful")


def _validated_evidence(
    task_descriptor: int, manifest: dict[str, Any], runner_uid: int, runner_gid: int
) -> EvidenceObservations:
    evidence_descriptor = _open_root_owned_evidence(task_descriptor)
    try:
        _evidence_names(evidence_descriptor)
        identity, cells = _identity_evidence(
            evidence_descriptor, runner_uid, runner_gid
        )
        _validate_worker_cells(identity, cells)
        module_digest, tested_pr_base = _runtime_module_digest(
            evidence_descriptor, manifest
        )
        on = _jsonl(evidence_descriptor, "on")
        off = _jsonl(evidence_descriptor, "off")
        if on["transaction_id"] == off["transaction_id"]:
            raise CollectorError("on/off cells reused transaction ID")
        _validate_exit_evidence(evidence_descriptor)
        return EvidenceObservations(cells, tested_pr_base, module_digest, on, off)
    finally:
        os.close(evidence_descriptor)


def _terminal_result(
    manifest: dict[str, Any], observations: EvidenceObservations
) -> dict[str, Any]:
    on = observations.on
    off = observations.off
    cell = observations.cells["on"]
    return {
        "schema_version": 1,
        "status": "validated_observations",
        "tested_pr_head": manifest["tested_pr_head"],
        "tested_pr_base": observations.tested_pr_base,
        "trusted_dispatcher_base_sha": manifest["trusted_dispatcher_base_sha"],
        "nginx_version": NGINX_VERSION,
        "nginx_source_digest": NGINX_SOURCE_DIGEST,
        "connector_module_digest": observations.connector_module_digest,
        "master_pid": cell["master_pid"],
        "worker_pid": cell["worker_pid"],
        "master_uid": cell["master_uid"],
        "master_gid": cell["master_gid"],
        "worker_uid": cell["worker_uid"],
        "worker_gid": cell["worker_gid"],
        "distinct_identity_verified": True,
        "on_callback_observed": on["callback_observed"],
        "off_callback_observed": off["callback_observed"],
        "on_jsonl_observed": on["jsonl_observed"],
        "off_jsonl_observed": off["jsonl_observed"],
        "on_waf_decision": on["waf_decision"],
        "off_waf_decision": off["waf_decision"],
        "decision_equivalent": on["waf_decision"] == off["waf_decision"],
        "trusted_http_status_observed": True,
        "candidate_sandbox_observations_untrusted": True,
        "final_exit_code": 0,
    }


def _assert_fresh_result_destination(task_descriptor: int) -> None:
    try:
        os.stat(RESULT_OUTPUT_NAME, dir_fd=task_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise CollectorError("cannot inspect fixed result destination") from exc
    raise CollectorError("fixed result destination is not fresh")


def _write_complete_descriptor(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise CollectorError("could not write complete result")
        offset += written


def _write_result_temporary(
    task_descriptor: int, data: bytes, runner_uid: int, runner_gid: int
) -> str:
    temporary_name = f"{RESULT_TEMPORARY_PREFIX}{os.getpid()}"
    descriptor = -1
    temporary_created = False
    completed = False
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=task_descriptor,
        )
        temporary_created = True
        _write_complete_descriptor(descriptor, data)
        os.fsync(descriptor)
        os.fchown(descriptor, runner_uid, runner_gid)
        os.fchmod(descriptor, 0o600)
        os.close(descriptor)
        descriptor = -1
        completed = True
        return temporary_name
    except OSError as exc:
        raise CollectorError("could not atomically write result") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_created and not completed:
            try:
                os.unlink(temporary_name, dir_fd=task_descriptor)
            except FileNotFoundError:
                pass


def _publish_terminal_result(
    task_descriptor: int, result: dict[str, Any], runner_uid: int, runner_gid: int
) -> None:
    _assert_fresh_result_destination(task_descriptor)
    data = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode()
    temporary_name = _write_result_temporary(
        task_descriptor, data, runner_uid, runner_gid
    )
    try:
        os.replace(
            temporary_name,
            RESULT_OUTPUT_NAME,
            src_dir_fd=task_descriptor,
            dst_dir_fd=task_descriptor,
        )
    except OSError as exc:
        try:
            os.unlink(temporary_name, dir_fd=task_descriptor)
        except OSError:
            pass
        raise CollectorError("could not atomically write result") from exc


def collect(
    manifest_path: Path,
    evidence_root: Path,
    output_path: Path,
    task_root: Path,
    runner_uid: int,
    runner_gid: int,
) -> dict[str, Any]:
    _validate_collection_paths(manifest_path, evidence_root, output_path, task_root)
    task_descriptor = _open_task_root(task_root, runner_uid, runner_gid)
    try:
        manifest = _manifest_from_task_root(
            task_descriptor, manifest_path, task_root, runner_uid, runner_gid
        )
        observations = _validated_evidence(
            task_descriptor, manifest, runner_uid, runner_gid
        )
        result = _terminal_result(manifest, observations)
        _publish_terminal_result(task_descriptor, result, runner_uid, runner_gid)
        return result
    finally:
        os.close(task_descriptor)

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--task-root", type=Path, required=True)
    parser.add_argument("--runner-uid", type=int, required=True)
    parser.add_argument("--runner-gid", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        collect(
            args.manifest,
            args.evidence_root,
            args.output,
            args.task_root,
            args.runner_uid,
            args.runner_gid,
        )
    except CollectorError:
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
