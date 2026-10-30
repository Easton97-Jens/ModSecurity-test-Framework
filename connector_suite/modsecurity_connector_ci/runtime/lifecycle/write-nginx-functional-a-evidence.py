#!/usr/bin/env python3
"""Publish the bounded candidate-owned NGINX Functional-A evidence record.

The root Functional-A gate has already validated the live NGINX On/Off,
JSONL, WAF, and lifecycle conditions before it invokes this helper.  This
writer re-reads the fixed source files, validates the facts again, and emits
one payload-safe record for exact-head readback.  It is deliberately not an
independent protected-host attestation; that boundary remains FND-GITHUB-0009.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


MAX_SOURCE_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024
EXPECTED_NGINX_VERSION = "1.31.6"
# nginx -V adds these build-information lines after the exact version line.
# Their content is hashed with the source, never copied into public evidence.
NGINX_BUILD_METADATA = re.compile(
    rb"(?:built by [\x20-\x7e]+|built with [\x20-\x7e]+"
    rb"|TLS SNI support enabled|configure arguments:[\x20-\x7e]*)"
)
EXPECTED_URI = "/no-crs/response-body?<redacted>"
QUERY_CANARY = b"nginx-functional-a-canary=must-redact"
PHASE4_RULE_ID = "1100301"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
IDENTITY_LABELS = (
    "nginx_binary_sha256",
    "nginx_module_sha256",
    "modsecurity_runtime_library_sha256",
    "rule_preamble_sha256",
    "phase4_case_sha256",
    "inheritance_case_sha256",
    "allow_case_sha256",
)
LIFECYCLE_MARKERS = {
    "usr1_retained_secure_fd": b"phase=phase4_usr1 result=retained_secure_fd",
    "unsafe_reload_preserved_old_cycle": b"phase=phase4_reload_unsafe result=failed_old_cycle_preserved",
    "secure_reload_activated_validated_fd": b"phase=phase4_reload_secure result=new_validated_fd",
    "graceful_shutdown": b"phase=shutdown mode=graceful_quit exit_status=0",
    "children_drained": b"phase=cleanup children=none result=passed",
    "reload_overlap_observed": b"phase=phase4_reload_overlap ",
    "descriptor_closed_after_master_exit": b"phase=phase4_fd_shutdown result=closed_after_master_exit",
}


class EvidenceError(ValueError):
    """The root-only evidence source or output boundary is invalid."""


def _identity(details: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        details.st_dev,
        details.st_ino,
        stat.S_IFMT(details.st_mode),
        details.st_size,
        details.st_nlink,
        details.st_uid,
        stat.S_IMODE(details.st_mode),
    )


def _absolute_path(value: Path, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or path == Path("/") or ".." in path.parts:
        raise EvidenceError(f"{label} must be an absolute non-root non-traversing path")
    return path


def _require_no_symlink_components(path: Path, label: str) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            details = current.lstat()
        except OSError as error:
            raise EvidenceError(f"{label} is unavailable") from error
        if stat.S_ISLNK(details.st_mode):
            raise EvidenceError(f"{label} contains a symbolic link")


def _require_directory(
    path: Path,
    label: str,
    *,
    uid: int | None = None,
    gid: int | None = None,
    mode: int | None = None,
) -> os.stat_result:
    _require_no_symlink_components(path, label)
    try:
        details = path.lstat()
    except OSError as error:
        raise EvidenceError(f"{label} is unavailable") from error
    if not stat.S_ISDIR(details.st_mode):
        raise EvidenceError(f"{label} is not a directory")
    if uid is not None and details.st_uid != uid:
        raise EvidenceError(f"{label} has an unexpected owner")
    if gid is not None and details.st_gid != gid:
        raise EvidenceError(f"{label} has an unexpected group")
    if mode is not None and stat.S_IMODE(details.st_mode) != mode:
        raise EvidenceError(f"{label} has an unexpected mode")
    return details


def _open_directory(
    path: Path, label: str, *, uid: int | None = None, gid: int | None = None, mode: int | None = None
) -> int:
    before = _require_directory(path, label, uid=uid, gid=gid, mode=mode)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory is None:
        raise EvidenceError("evidence publication requires no-follow directory support")
    descriptor = os.open(path, os.O_RDONLY | directory | no_follow)
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise EvidenceError(f"{label} changed between validation and open")
        if not stat.S_ISDIR(opened.st_mode):
            raise EvidenceError(f"{label} is not a directory")
        if uid is not None and opened.st_uid != uid:
            raise EvidenceError(f"{label} has an unexpected owner")
        if gid is not None and opened.st_gid != gid:
            raise EvidenceError(f"{label} has an unexpected group")
        if mode is not None and stat.S_IMODE(opened.st_mode) != mode:
            raise EvidenceError(f"{label} has an unexpected mode")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _read_regular(path: Path, label: str) -> bytes:
    _require_no_symlink_components(path, label)
    try:
        before = path.lstat()
    except OSError as error:
        raise EvidenceError(f"{label} is unavailable") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > MAX_SOURCE_BYTES
        or stat.S_IMODE(before.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise EvidenceError(f"{label} is not a bounded private regular file")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    if no_follow is None or nonblock is None:
        raise EvidenceError("evidence reading requires no-follow non-blocking support")
    descriptor = os.open(path, os.O_RDONLY | no_follow | nonblock)
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise EvidenceError(f"{label} changed between validation and open")
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise EvidenceError(f"{label} is not a regular file")
        chunks: list[bytes] = []
        remaining = MAX_SOURCE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if _identity(after) != _identity(opened):
            raise EvidenceError(f"{label} changed while reading")
    finally:
        os.close(descriptor)
    if len(data) > MAX_SOURCE_BYTES:
        raise EvidenceError(f"{label} exceeds its bound")
    return data


def _parse_identity(data: bytes) -> dict[str, str]:
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise EvidenceError("artifact identity is not ASCII") from error
    if len(lines) != len(IDENTITY_LABELS):
        raise EvidenceError("artifact identity has an unexpected number of entries")
    values: list[str] = []
    for line in lines:
        fields = line.split(maxsplit=1)
        if len(fields) != 2 or SHA256.fullmatch(fields[0]) is None:
            raise EvidenceError("artifact identity has an invalid digest")
        values.append(fields[0])
    return dict(zip(IDENTITY_LABELS, values, strict=True))


def _validate_phase4_record(record: Any, mode: str) -> bool:
    if not isinstance(record, dict):
        raise EvidenceError(f"{mode} JSONL record is not an object")
    if str(record.get("rule_id")) != PHASE4_RULE_ID:
        return False
    if record.get("redacted") is not True or record.get("truncated") is not False:
        raise EvidenceError(f"{mode} JSONL redaction/truncation facts are invalid")
    if record.get("uri") != EXPECTED_URI:
        raise EvidenceError(f"{mode} JSONL URI is not the expected redacted form")
    transaction_id = record.get("transaction_id")
    if not isinstance(transaction_id, str) or not transaction_id:
        raise EvidenceError(f"{mode} JSONL transaction correlation is absent")
    for key in ("sequence", "previous_event_hash", "event_hash"):
        value = record.get(key)
        if type(value) is not int or value < 0:
            raise EvidenceError(f"{mode} JSONL integrity field is invalid")
    return True


def _parse_phase4_line(line: str, mode: str) -> bool:
    try:
        record = json.loads(line)
    except json.JSONDecodeError as error:
        raise EvidenceError(f"{mode} JSONL is malformed") from error
    return _validate_phase4_record(record, mode)


def _parse_phase4_jsonl(data: bytes, mode: str) -> int:
    if QUERY_CANARY in data:
        raise EvidenceError(f"{mode} JSONL contains the query canary")
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise EvidenceError(f"{mode} JSONL is not UTF-8") from error
    records = sum(_parse_phase4_line(line, mode) for line in lines if line)
    if not records:
        raise EvidenceError(f"{mode} JSONL has no Phase-4 record")
    return records


def _mode_sources(functional_root: Path, mode: str) -> dict[str, Path]:
    phase4 = functional_root / mode / "phase4"
    return {
        "phase4_jsonl": phase4 / "logs" / "phase4.log",
        "phase4_before_usr1_jsonl": phase4 / "logs" / "phase4-before-usr1.log",
        "lifecycle": phase4 / "logs" / "nginx-lifecycle.txt",
        "nginx_version": phase4 / "logs" / "nginx-version.log",
        "allow_status": functional_root / mode / "allow" / "logs" / "observed-status.txt",
        "raw_waf_access": phase4 / "harness" / "server-logs" / "nginx_phase4_deny_after_commit_log_only" / "access.log",
        "callback_error": phase4 / "harness" / "server-logs" / "nginx_phase4_deny_after_commit_log_only" / "error.log",
    }


def _nginx_version_matches(data: bytes) -> bool:
    """Accept the exact version line plus only ordinary nginx -V metadata."""
    lines = data.splitlines()
    expected = b"nginx version: nginx/" + EXPECTED_NGINX_VERSION.encode("ascii")
    if not lines or lines[0] != expected:
        return False
    return all(NGINX_BUILD_METADATA.fullmatch(line) is not None for line in lines[1:])


def _collect_mode(functional_root: Path, mode: str, scope: str = "full") -> dict[str, Any]:
    paths = _mode_sources(functional_root, mode)
    if scope == "selected-phase4":
        for name in ("phase4_before_usr1_jsonl", "lifecycle", "allow_status"):
            paths.pop(name)
    sources = {name: _read_regular(path, f"{mode} {name}") for name, path in paths.items()}
    phase4_records = _parse_phase4_jsonl(sources["phase4_jsonl"], mode)
    if scope == "full":
        phase4_records += _parse_phase4_jsonl(sources["phase4_before_usr1_jsonl"], mode)
    if QUERY_CANARY not in sources["raw_waf_access"]:
        raise EvidenceError(f"{mode} raw WAF path did not observe the query canary")
    callback_observed = PHASE4_RULE_ID.encode("ascii") in sources["callback_error"]
    callback_expected = mode == "on"
    if callback_observed is not callback_expected:
        raise EvidenceError(f"{mode} callback behavior is invalid")
    if not _nginx_version_matches(sources["nginx_version"]):
        raise EvidenceError(f"{mode} did not use NGINX {EXPECTED_NGINX_VERSION}")
    lifecycle: dict[str, bool] = {}
    if scope == "full":
        if sources["allow_status"].strip() != b"200":
            raise EvidenceError(f"{mode} allow control did not retain status 200")
        lifecycle = {name: marker in sources["lifecycle"] for name, marker in LIFECYCLE_MARKERS.items()}
        if not all(lifecycle.values()):
            raise EvidenceError(f"{mode} lifecycle facts are incomplete")
    observed = {
        "callback_marker_expected": callback_expected,
        "callback_marker_observed": callback_observed,
        "phase4_jsonl_valid": True,
        "phase4_rule_record_count": phase4_records,
        "phase4_redacted": True,
        "phase4_truncated": False,
        "query_canary_absent_from_jsonl": True,
        "redacted_uri_shape_valid": True,
        "transaction_id_present": True,
        "integrity_fields_valid": True,
        "raw_waf_uri_observed": True,
        "source_sha256": {name: hashlib.sha256(value).hexdigest() for name, value in sources.items()},
    }
    if scope == "full":
        observed.update({"allow_control_status": 200, "lifecycle": lifecycle})
    return observed


def _resolve_exact_head(connector_root: Path) -> str:
    result = subprocess.run(
        ["/usr/bin/git", "-C", str(connector_root), "rev-parse", "--verify", "HEAD^{commit}"],
        check=False,
        capture_output=True,
        text=True,
    )
    value = result.stdout.strip()
    if result.returncode != 0 or COMMIT_SHA.fullmatch(value) is None:
        raise EvidenceError("could not resolve the exact connector head")
    return value


def collect_evidence(
    connector_root: Path,
    functional_root: Path,
    parent_sha: str,
    nginx_archive_sha256: str,
    scope: str = "full",
) -> dict[str, Any]:
    if scope not in {"full", "selected-phase4"}:
        raise EvidenceError("unknown Functional-A selection scope")
    if COMMIT_SHA.fullmatch(parent_sha) is None:
        raise EvidenceError("parent SHA is not an exact lowercase commit SHA")
    if SHA256.fullmatch(nginx_archive_sha256) is None:
        raise EvidenceError("NGINX archive SHA-256 is invalid")
    connector_root = _absolute_path(connector_root, "connector root")
    _require_directory(connector_root, "connector root")
    functional_root = _absolute_path(functional_root, "Functional-A root")
    _require_directory(
        functional_root,
        "Functional-A root",
        uid=0,
        mode=0o711,
    )
    if _resolve_exact_head(connector_root) != parent_sha:
        raise EvidenceError("Functional-A evidence head does not match the expected Parent head")
    identity = _read_regular(functional_root / "artifact-identity.start.sha256", "artifact identity")
    artifact_identity = _parse_identity(identity)
    for mode in ("on", "off"):
        for phase in ("before", "after"):
            observed = _read_regular(
                functional_root / mode / f"artifact-identity.{phase}.sha256",
                f"{mode} artifact identity {phase}",
            )
            if observed != identity:
                raise EvidenceError("Functional-A artifact identities are inconsistent")
    document = {
        "schema_version": 1,
        "record_type": "nginx_functional_a_exact_head_evidence" if scope == "full" else "nginx_selected_phase4_exact_head_evidence",
        "status": "PASS",
        "parent_sha": parent_sha,
        "nginx_version": EXPECTED_NGINX_VERSION,
        "nginx_archive_sha256": nginx_archive_sha256,
        "artifact_identity_sha256": hashlib.sha256(identity).hexdigest(),
        "artifact_identity": artifact_identity,
        "modes": {mode: _collect_mode(functional_root, mode, scope) for mode in ("on", "off")},
    }
    if scope == "selected-phase4":
        document["scope"] = scope
        document["active_case_ids"] = ["runtime.nginx.phase4-callback.on", "runtime.nginx.phase4-callback.off"]
    return document


def _open_evidence_root(root: Path, owner_uid: int, owner_gid: int) -> int:
    root = _absolute_path(root, "Functional-A evidence root")
    return _open_directory(
        root,
        "Functional-A evidence root",
        uid=owner_uid,
        gid=owner_gid,
        mode=0o700,
    )


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short evidence write")
        view = view[written:]


def publish_one_shot(root: Path, owner_uid: int, owner_gid: int, document: dict[str, Any]) -> None:
    data = (json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if len(data) > MAX_OUTPUT_BYTES:
        raise EvidenceError("Functional-A evidence exceeds its bound")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise EvidenceError("evidence publication requires no-follow support")
    directory = _open_evidence_root(root, owner_uid, owner_gid)
    temporary: str | None = None
    try:
        try:
            os.stat("result.json", dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise EvidenceError("Functional-A evidence result already exists")
        temporary = f".result.json.tmp.{secrets.token_hex(16)}"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
            0o600,
            dir_fd=directory,
        )
        try:
            os.fchown(descriptor, owner_uid, owner_gid)
            _write_all(descriptor, data)
            os.fsync(descriptor)
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_nlink != 1
                or details.st_uid != owner_uid
                or details.st_gid != owner_gid
                or stat.S_IMODE(details.st_mode) != 0o600
                or details.st_size != len(data)
            ):
                raise EvidenceError("temporary Functional-A evidence has an unexpected identity")
        finally:
            os.close(descriptor)
        os.link(
            temporary,
            "result.json",
            src_dir_fd=directory,
            dst_dir_fd=directory,
            follow_symlinks=False,
        )
        os.fsync(directory)
        os.unlink(temporary, dir_fd=directory)
        temporary = None
        os.fsync(directory)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
        os.close(directory)


def _parse_nonnegative(value: str, label: str) -> int:
    if not value.isdecimal():
        raise EvidenceError(f"{label} is not a nonnegative integer")
    return int(value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector-root", type=Path, required=True)
    parser.add_argument("--functional-root", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--owner-uid", required=True)
    parser.add_argument("--owner-gid", required=True)
    parser.add_argument("--parent-sha", required=True)
    parser.add_argument("--nginx-archive-sha256", required=True)
    parser.add_argument("--scope", choices=("full", "selected-phase4"), default="full")
    args = parser.parse_args()
    try:
        owner_uid = _parse_nonnegative(args.owner_uid, "evidence owner UID")
        owner_gid = _parse_nonnegative(args.owner_gid, "evidence owner GID")
        document = collect_evidence(
            args.connector_root,
            args.functional_root,
            args.parent_sha,
            args.nginx_archive_sha256,
            args.scope,
        )
        publish_one_shot(args.evidence_root, owner_uid, owner_gid, document)
    except (EvidenceError, OSError, subprocess.SubprocessError) as error:
        print(f"FAIL: bounded Functional-A evidence was not published: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
