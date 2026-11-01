#!/usr/bin/env python3
"""Validate generic CRS/no-MRTS evidence or publish a bounded failure receipt.

The receipt contains workflow metadata only.  It is deliberately not a
replacement for runtime evidence: a failed runtime remains a failed job.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import load_source

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path


GENERIC_CONNECTORS = frozenset(("envoy", "lighttpd", "traefik"))
FAILURE_RECEIPT_CONNECTORS = GENERIC_CONNECTORS | frozenset(("apache",))
OUTCOMES = frozenset(("success", "failure", "cancelled", "skipped"))
MAX_RECORD_BYTES = 65536
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$")
VERIFIED_ROOT_LABEL = "verified root"
FAILURE_RECEIPT_NAME = "failure-receipt.json"
_THIS = Path(__file__).resolve()
_CONTRACT_PATH = _THIS.parents[1] / "contracts" / "runtime_observation.py"
RUNTIME_OBSERVATION = load_source(_CONTRACT_PATH)

ADAPTER_IDS = {
    "envoy": "envoy-ext-proc-service",
    "lighttpd": "lighttpd-patched-native-module",
    "traefik": "traefik-native-middleware",
}
INTEGRATION_MODES = {
    "envoy": "ext_proc",
    "lighttpd": "patched-native-lighttpd",
    "traefik": "native-traefik-middleware",
}


def sha(value: str) -> bool:
    return len(value) == 40 and all(char in "0123456789abcdef" for char in value)


def identity(details: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        details.st_dev,
        details.st_ino,
        stat.S_IFMT(details.st_mode),
        details.st_size,
        details.st_nlink,
        details.st_uid,
        stat.S_IMODE(details.st_mode),
    )


def require_safe_directory(details: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ValueError(f"{label} is not a private current-user directory")


def require_safe_regular(details: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_nlink != 1
        or stat.S_IMODE(details.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
        or details.st_size > MAX_RECORD_BYTES
    ):
        raise ValueError(f"{label} is not a bounded private regular file")


def require_verified_root(path: Path) -> Path:
    root = Path(path)
    if not root.is_absolute() or root == Path("/") or ".." in root.parts:
        raise ValueError("verified root is not an absolute non-root path")
    descriptor = open_private_directory(root, VERIFIED_ROOT_LABEL)
    os.close(descriptor)
    return root


def open_directory_component(
    parent: int, component: str, label: str, *, require_private: bool = False
) -> int:
    if not component or component in (".", "..") or "/" in component:
        raise ValueError(f"{label} has an unsafe path component")
    before = os.stat(component, dir_fd=parent, follow_symlinks=False)
    if stat.S_ISLNK(before.st_mode):
        raise ValueError(f"{label} contains a symbolic link")
    if not stat.S_ISDIR(before.st_mode):
        raise ValueError(f"{label} contains a non-directory component")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory is None:
        raise ValueError("safe evidence access requires no-follow directory support")
    descriptor = os.open(component, os.O_RDONLY | directory | no_follow, dir_fd=parent)
    try:
        opened = os.fstat(descriptor)
        if identity(opened) != identity(before):
            raise ValueError(f"{label} changed between validation and open")
        if not stat.S_ISDIR(opened.st_mode):
            raise ValueError(f"{label} component is not a directory")
        if require_private:
            require_safe_directory(opened, label)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def open_private_directory(path: Path, label: str) -> int:
    """Open every absolute component without trusting a symlinked ancestor.

    ``O_NOFOLLOW`` applies only to the terminal component of one ``open``;
    the descriptor-relative walk keeps an untrusted CLI root from redirecting
    receipt or evidence access through an ancestor symbolic link.
    """
    root = Path(path)
    if not root.is_absolute() or root == Path("/") or ".." in root.parts:
        raise ValueError(f"{label} is not an absolute non-root non-traversing path")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory is None:
        raise ValueError("safe evidence access requires no-follow directory support")
    descriptor = os.open("/", os.O_RDONLY | directory | no_follow)
    try:
        for component in root.parts[1:]:
            child = open_directory_component(descriptor, component, label)
            os.close(descriptor)
            descriptor = child
        require_safe_directory(os.fstat(descriptor), label)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def read_evidence(root: Path, components: tuple[str, ...], label: str) -> bytes:
    if not components:
        raise ValueError("evidence path is empty")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    if no_follow is None or nonblock is None:
        raise ValueError("safe evidence access requires no-follow non-blocking support")
    directory_descriptor = open_private_directory(root, VERIFIED_ROOT_LABEL)
    try:
        for component in components[:-1]:
            next_descriptor = open_directory_component(
                directory_descriptor, component, label, require_private=True
            )
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        before = os.stat(
            components[-1], dir_fd=directory_descriptor, follow_symlinks=False
        )
        require_safe_regular(before, label)
        file_descriptor = os.open(
            components[-1], os.O_RDONLY | no_follow | nonblock, dir_fd=directory_descriptor
        )
    finally:
        os.close(directory_descriptor)
    try:
        opened = os.fstat(file_descriptor)
        if identity(opened) != identity(before):
            raise ValueError(f"{label} changed between validation and open")
        require_safe_regular(opened, label)
        chunks: list[bytes] = []
        remaining = MAX_RECORD_BYTES + 1
        while remaining:
            chunk = os.read(file_descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(file_descriptor)
        if identity(after) != identity(opened):
            raise ValueError(f"{label} changed while reading")
        require_safe_regular(after, label)
    finally:
        os.close(file_descriptor)
    if len(data) > MAX_RECORD_BYTES:
        raise ValueError(f"{label} exceeds its bound")
    return data


def reject_duplicate_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("runtime evidence JSON contains a duplicate key")
        value[key] = item
    return value


def reject_nonfinite_json(_: str) -> None:
    raise ValueError("runtime evidence JSON contains a non-finite value")


def load_canonical_json(data: bytes, label: str) -> dict[str, object]:
    if not data or b"\0" in data or not data.endswith(b"\n"):
        raise ValueError(f"{label} is not canonical JSON bytes")
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicate_json_pairs,
            parse_constant=reject_nonfinite_json,
        )
    except (RecursionError, ValueError) as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if type(value) is not dict:
        raise ValueError(f"{label} is not an object")
    try:
        canonical = (
            json.dumps(value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            + "\n"
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError) as exc:
        raise ValueError(f"{label} cannot be canonicalized") from exc
    if canonical != data:
        raise ValueError(f"{label} is not canonical JSON")
    return value


def load_pass_evidence(root: Path, connector: str, run_id: str, parent_sha: str) -> None:
    record_data = read_evidence(
        root,
        ("evidence", "runtime", connector, run_id, "runtime.json"),
        "runtime evidence",
    )
    event_data = read_evidence(
        root,
        ("evidence", "normalized", connector, run_id, "event.json"),
        "normalized event evidence",
    )
    observation_data = read_evidence(
        root,
        (
            "evidence",
            "normalized",
            connector,
            run_id,
            "runtime-observation.json",
        ),
        "normalized observation evidence",
    )
    record = load_canonical_json(record_data, "runtime evidence")
    event = load_canonical_json(event_data, "normalized event evidence")
    observation = load_canonical_json(observation_data, "normalized observation evidence")
    if (
        record.get("record_type") != "parent_runtime_attestation"
        or record.get("connector") != connector
        or record.get("run_id") != run_id
        or record.get("runtime_status") != "PASS"
    ):
        raise ValueError("runtime evidence binding or status is invalid")
    identity = observation.get("identity")
    if type(identity) is not dict:
        raise ValueError("runtime observation identity is invalid")
    expected_identity = {
        "connector": connector,
        "adapter_id": ADAPTER_IDS[connector],
        "integration_mode": INTEGRATION_MODES[connector],
        "profile": "with-crs-no-mrts",
        "crs": True,
        "mrts": False,
        "run_id": run_id,
        "parent_commit": parent_sha,
        "framework_commit": identity.get("framework_commit"),
        "mrts_commit": identity.get("mrts_commit"),
        "producer": f"parent-runtime-observation-adapter-{connector}",
        "producer_version": "1.0.0",
    }
    validation = RUNTIME_OBSERVATION.validate_runtime_observation(
        observation,
        expected_identity,
        {"name": "strict", "evidence_root": root / "evidence"},
    )
    if validation.status != "PASS" or validation["validation_status"] != "CONTRACT_VALIDATED":
        raise ValueError("runtime observation binding or common contract does not pass")
    if (
        event.get("profile") != "five-connectors-with-crs-no-mrts"
        or event.get("connector") != connector
        or event.get("adapter_id") != ADAPTER_IDS[connector]
        or event.get("integration_mode") != INTEGRATION_MODES[connector]
        or event.get("run_id") != run_id
        or event.get("connector_commit") != parent_sha
        or event.get("framework_commit") != identity.get("framework_commit")
        or event.get("status") != "PASS"
    ):
        raise ValueError("normalized evidence binding or status is invalid")
    canonical_observation = record.get("canonical_observation")
    expected_path = f"normalized/{connector}/{run_id}/runtime-observation.json"
    if (
        not isinstance(canonical_observation, dict)
        or canonical_observation.get("validation_status") != "CONTRACT_VALIDATED"
        or canonical_observation.get("evidence_path") != expected_path
        or canonical_observation.get("evidence_sha256")
        != hashlib.sha256(observation_data).hexdigest()
    ):
        raise ValueError("runtime observation binding is invalid")


def write_receipt(
    root: Path, connector: str, run_id: str, parent_sha: str, outcome: str, reason: str
) -> None:
    document = {
        "schema_version": 1,
        "record_type": "crs_no_mrts_runtime_failure_receipt",
        "connector": connector,
        "run_id": run_id,
        "connector_commit": parent_sha,
        "runtime_outcome": outcome,
        "evidence_status": "not_available",
        "reason": reason[:128],
    }
    data = (
        json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")
    if len(data) > 4096:
        raise ValueError("failure receipt exceeds its bound")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ValueError("safe receipt publication requires no-follow support")
    root_descriptor = open_private_directory(root, VERIFIED_ROOT_LABEL)
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow
        descriptor = os.open(FAILURE_RECEIPT_NAME, flags, 0o600, dir_fd=root_descriptor)
        try:
            remaining = memoryview(data)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("short failure-receipt write")
                remaining = remaining[written:]
            os.fsync(descriptor)
            require_safe_regular(os.fstat(descriptor), "failure receipt")
        finally:
            os.close(descriptor)
        os.fsync(root_descriptor)
    finally:
        os.close(root_descriptor)


def receipt_exists(root: Path) -> bool:
    descriptor = open_private_directory(root, VERIFIED_ROOT_LABEL)
    try:
        try:
            os.stat(FAILURE_RECEIPT_NAME, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--parent-sha", required=True)
    parser.add_argument("--verified-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--runtime-outcome", required=True)
    args = parser.parse_args()
    if (
        args.connector not in FAILURE_RECEIPT_CONNECTORS
        or not RUN_ID.fullmatch(args.run_id)
        or not sha(args.parent_sha)
    ):
        return 2
    if args.runtime_outcome not in OUTCOMES:
        return 2
    try:
        verified_root = require_verified_root(args.verified_root)
        receipt = Path(args.receipt)
        expected_receipt = verified_root / FAILURE_RECEIPT_NAME
        if (
            not receipt.is_absolute()
            or ".." in receipt.parts
            or receipt != expected_receipt
        ):
            raise ValueError("failure receipt escapes the verified runtime root")
    except (OSError, ValueError) as exc:
        print(f"FAIL: unsafe runtime evidence root: {exc}", file=os.sys.stderr)
        return 1
    if args.runtime_outcome != "success":
        try:
            write_receipt(
                verified_root,
                args.connector,
                args.run_id,
                args.parent_sha,
                args.runtime_outcome,
                "runtime did not complete successfully",
            )
        except (OSError, ValueError) as receipt_error:
            print(
                f"FAIL: unable to retain bounded runtime failure receipt: {receipt_error}",
                file=os.sys.stderr,
            )
            return 1
        return 0
    if args.connector not in GENERIC_CONNECTORS:
        return 2
    try:
        load_pass_evidence(verified_root, args.connector, args.run_id, args.parent_sha)
    except (OSError, ValueError) as exc:
        print(f"FAIL: runtime evidence validation failed: {exc}", file=os.sys.stderr)
        return 1
    if receipt_exists(verified_root):
        print("FAIL: unexpected failure receipt accompanies PASS evidence", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
