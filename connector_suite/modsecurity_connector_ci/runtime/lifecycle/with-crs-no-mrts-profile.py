#!/usr/bin/env python3
"""Produce one sealed Parent receipt for the closed With-CRS/no-MRTS profile.

This is deliberately separate from the closed ``no-crs`` profile.  It turns
one already completed, connector-specific runtime result into a small,
payload-free profile cell only after checking the native source boundary.  A
workflow-owned cell run ID is recorded as such; it is never represented as a
native connector-issued identifier for Apache or HAProxy.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


PROFILE = "with-crs-no-mrts"
PROFILE_RECORD = "with_crs_no_mrts_profile_cell_receipt"
FACTS_RECORD = "with_crs_no_mrts_functional_facts"
MANIFEST_RECORD = "with_crs_no_mrts_profile_cell_manifest"
SCHEMA_VERSION = 1
CASE_ID = "crs_sqli_anomaly_block"
RULE_ID = 942270
CONNECTORS = ("apache", "haproxy", "envoy", "lighttpd", "traefik")
GENERIC_CONNECTORS = frozenset(("envoy", "lighttpd", "traefik"))
INTEGRATION_MODES = {
    "apache": "native-httpd-module",
    "haproxy": "spoe_spop_request",
    "envoy": "ext_proc",
    "lighttpd": "patched-native-lighttpd",
    "traefik": "native-traefik-middleware",
}
ADAPTER_IDS = {
    "envoy": "envoy-ext-proc-service",
    "lighttpd": "lighttpd-patched-native-module",
    "traefik": "traefik-native-middleware",
}
SOURCE_KINDS = {
    "apache": "apache_case_summary",
    "haproxy": "haproxy_projected_evidence",
    "envoy": "generic_runtime_observation",
    "lighttpd": "generic_runtime_observation",
    "traefik": "generic_runtime_observation",
}
FUNCTIONAL_FACTS_NAME = "functional-facts.json"
PROFILE_RECEIPT_NAME = "profile-cell-receipt.json"
MANIFEST_NAME = "manifest.json"
APACHE_CLEANUP_RECEIPT_LABEL = "Apache cleanup receipt"
CRS_RULE_FILE = "rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"
OUTPUT_NAMES = (FUNCTIONAL_FACTS_NAME, PROFILE_RECEIPT_NAME, MANIFEST_NAME)
APACHE_RUNTIME_ROOT_LABEL = "Apache runtime root"
APACHE_SELECTED_RESULTS_NAME = "apache-results.jsonl"
APACHE_SELECTED_SUMMARY_NAME = "apache-summary.json"
APACHE_SELECTED_SUMMARY_TEXT_NAME = "apache-summary.txt"
APACHE_SELECTED_CONNECTOR_SUMMARY_NAME = "connector-summary.txt"
APACHE_SELECTED_CASE_RESULT_LABEL = "selected Apache case result"
APACHE_SELECTED_RESULTS_DIRECTORY_LABEL = "selected Apache results directory"
APACHE_SELECTED_RESULTS_DIRECTORY_MARKER_LABEL = "selected Apache results directory marker"
APACHE_SELECTED_LOG_DIRECTORY_LABEL = "selected Apache log directory"
APACHE_SELECTED_DIRECTORY_MARKER_RECORD = "apache_selected_results_directory_identity"
APACHE_SELECTED_DIRECTORY_MARKER_PREFIX = ".apache-selected-results-"
APACHE_SELECTED_OUTPUT_NAMES = (
    APACHE_SELECTED_RESULTS_NAME,
    APACHE_SELECTED_SUMMARY_NAME,
    APACHE_SELECTED_SUMMARY_TEXT_NAME,
    APACHE_SELECTED_CONNECTOR_SUMMARY_NAME,
)
APACHE_SUMMARY_RELATIVE_PATH = "build/verified-apache-case/with-crs/no-mrts/results/apache-summary.json"
APACHE_RESULTS_RELATIVE_PATH = "build/verified-apache-case/with-crs/no-mrts/results/apache-results.jsonl"
APACHE_AUDIT_RELATIVE_PATH = (
    "build/verified-apache-case/with-crs-no-mrts-apache/logs/apache-runtime/"
    "audit.log"
)
APACHE_CLEANUP_RECEIPT_NAME = "apache-profile-cleanup-receipt.json"
APACHE_CLEANUP_RECORD = "apache_with_crs_no_mrts_cleanup_receipt"
APACHE_AUDIT_REQUEST_LINE = (
    "GET /?id=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1"
)
# ModSecurity Native serial audit sections use ``---<transaction>---<part>--``.
# This is deliberately narrower than arbitrary text so a preamble cannot be
# mistaken for a transaction boundary.
APACHE_AUDIT_BOUNDARY = re.compile(r"^---([A-Za-z\d]+)---([A-Z])--$", re.ASCII)
APACHE_AUDIT_STATUS = re.compile(r"^HTTP/\d+(?:\.\d+)? 403(?:[ \t\r]|$)", re.ASCII)
APACHE_CRS_RULE_ID = re.compile(
    rb"(?:^|[,\s])['\"]?id['\"]?\s*:\s*942270(?:[,\s]|$)"
)
APACHE_SELECTED_CASE_EXPECTATIONS = (
    ("name", CASE_ID),
    ("executed_connector", "apache"),
    ("live_executed", True),
    ("status", "pass"),
    ("expected_status", 403),
    ("actual_status", 403),
    ("observed_status", 403),
    ("observed_transport_result", "http_status"),
    ("expected_intervention", "deny"),
    ("requires_crs", True),
    ("variant", "with-crs"),
)
SHA40 = re.compile(r"^[\da-f]{40}$", re.ASCII)
SHA256 = re.compile(r"^[\da-f]{64}$", re.ASCII)
TOKEN = re.compile(r"^[A-Za-z\d][A-Za-z\d._-]{0,127}$", re.ASCII)
DECIMAL = re.compile(r"^[1-9]\d{0,19}$", re.ASCII)
MAX_JSON_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024


class ProfileError(ValueError):
    """Raised when one profile source or profile artifact is not trustworthy."""


def fail(message: str) -> ProfileError:
    return ProfileError(message)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise fail("JSON contains a duplicate key")
        value[key] = item
    return value


def _reject_nonfinite_json(_: str) -> None:
    raise fail("JSON contains a non-finite value")


def canonical_json(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (RecursionError, TypeError, ValueError) as exc:
        raise fail("JSON value is not canonicalizable") from exc
    return (rendered + "\n").encode("utf-8")


def parse_json_object(raw: bytes, label: str, *, canonical: bool = False) -> dict[str, Any]:
    if not raw or len(raw) > MAX_JSON_BYTES or b"\x00" in raw:
        raise fail(f"{label} has unsafe bytes")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_json,
        )
    except ProfileError:
        raise
    except (RecursionError, ValueError) as exc:
        raise fail(f"{label} is not valid JSON") from exc
    if type(value) is not dict:
        raise fail(f"{label} must be a JSON object")
    if canonical and raw != canonical_json(value):
        raise fail(f"{label} is not canonical JSON")
    return value


def _exact_json_scalar(value: object, expected: object) -> bool:
    """Require an exact JSON scalar type, not Python value equivalence."""
    return type(value) is type(expected) and value == expected


def _safe_absolute(path: Path, label: str) -> Path:
    if not path.is_absolute() or path == Path("/") or ".." in path.parts:
        raise fail(f"{label} must be an absolute non-root path")
    return Path(os.path.abspath(os.fspath(path)))


def _directory_is_safe(details: os.stat_result, label: str) -> None:
    mode = stat.S_IMODE(details.st_mode)
    if not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode):
        raise fail(f"{label} is not a directory")
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        # /tmp is a deliberately sticky, root-owned shared parent.  Every
        # descendant and the leaf are still checked through descriptors.
        if not (
            details.st_uid == 0
            and bool(mode & stat.S_ISVTX)
            and mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise fail(f"{label} is group- or world-writable")
    if details.st_uid not in {0, os.geteuid()}:
        raise fail(f"{label} has an untrusted owner")


def _regular_is_safe(details: os.stat_result, label: str, maximum: int) -> None:
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_nlink != 1
        or details.st_size < 0
        or details.st_size > maximum
        or stat.S_IMODE(details.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
        or details.st_uid not in {0, os.geteuid()}
    ):
        raise fail(f"{label} is not a bounded private regular file")


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


def _open_verified_directory_components(
    descriptor: int,
    components: Sequence[str],
    label: str,
    missing_flags_message: str = "safe profile evidence access requires O_NOFOLLOW and O_DIRECTORY",
) -> int:
    """Open trusted directory components while preserving descriptor identity."""
    try:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if nofollow is None or directory is None:
            raise fail(missing_flags_message)
        for component in components:
            before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                raise fail(f"{label} contains a symbolic link")
            child = os.open(component, os.O_RDONLY | directory | nofollow, dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                if _identity(before) != _identity(opened):
                    raise fail(f"{label} changed while opening")
                _directory_is_safe(opened, label)
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_absolute_directory(path: Path, label: str) -> int:
    path = _safe_absolute(path, label)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise fail("safe profile evidence access requires O_NOFOLLOW and O_DIRECTORY")
    descriptor = os.open("/", os.O_RDONLY | directory | nofollow)
    try:
        _directory_is_safe(os.fstat(descriptor), "filesystem root")
    except BaseException:
        os.close(descriptor)
        raise
    return _open_verified_directory_components(descriptor, path.parts[1:], label)


def _runtime_relative_path(runtime_root: Path, path: Path, label: str) -> tuple[Path, Path, tuple[str, ...]]:
    runtime = _safe_absolute(runtime_root, APACHE_RUNTIME_ROOT_LABEL)
    target = _safe_absolute(path, label)
    try:
        relative = target.relative_to(runtime)
    except ValueError as exc:
        raise fail(f"{label} is outside the Apache runtime root") from exc
    if not relative.parts:
        raise fail(f"{label} must be a child of the Apache runtime root")
    return runtime, target, tuple(relative.parts)


def _open_runtime_child(directory_fd: int, components: Sequence[str], label: str) -> int:
    descriptor = os.dup(directory_fd)
    return _open_verified_directory_components(
        descriptor,
        components,
        label,
        "safe profile evidence publication requires O_NOFOLLOW and O_DIRECTORY",
    )


def _create_runtime_component(
    directory_fd: int, component: str, label: str, nofollow: int, directory: int
) -> int:
    """Create/open one private component below a held directory descriptor."""
    created = False
    try:
        before = os.stat(component, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        try:
            os.mkdir(component, 0o700, dir_fd=directory_fd)
            created = True
            os.fsync(directory_fd)
        except FileExistsError:
            pass
        before = os.stat(component, dir_fd=directory_fd, follow_symlinks=False)
    if stat.S_ISLNK(before.st_mode):
        raise fail(f"{label} contains a symbolic link")
    child = os.open(component, os.O_RDONLY | directory | nofollow, dir_fd=directory_fd)
    try:
        opened = os.fstat(child)
        if _identity(before) != _identity(opened):
            raise fail(f"{label} changed while opening")
        if created:
            os.fchmod(child, 0o700)
            opened = os.fstat(child)
        _directory_is_safe(opened, label)
    except BaseException:
        os.close(child)
        raise
    return child


def _create_runtime_child(directory_fd: int, components: Sequence[str], label: str) -> int:
    """Create/open one private child below a held runtime-root descriptor."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise fail("safe profile evidence publication requires O_NOFOLLOW and O_DIRECTORY")
    descriptor = os.dup(directory_fd)
    try:
        for component in components:
            child = _create_runtime_component(descriptor, component, label, nofollow, directory)
            os.close(descriptor)
            descriptor = child
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _safe_relative_parts(value: str | PurePosixPath, label: str) -> tuple[str, ...]:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise fail(f"{label} is not a safe relative path")
    if any("\\" in part or "\x00" in part for part in path.parts):
        raise fail(f"{label} is not a safe relative path")
    return tuple(path.parts)


def _open_safe_file(
    root: Path, parts: tuple[str, ...], label: str, maximum: int
) -> tuple[int, os.stat_result]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or nonblock is None or directory is None:
        raise fail("safe profile evidence access requires no-follow non-blocking support")
    descriptor = _open_absolute_directory(root, label)
    try:
        for component in parts[:-1]:
            before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                raise fail(f"{label} has an unsafe directory component")
            child = os.open(component, os.O_RDONLY | directory | nofollow, dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                if _identity(before) != _identity(opened):
                    raise fail(f"{label} changed while opening")
                _directory_is_safe(opened, label)
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        before = os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False)
        _regular_is_safe(before, label, maximum)
        file_descriptor = os.open(parts[-1], os.O_RDONLY | nofollow | nonblock, dir_fd=descriptor)
    finally:
        os.close(descriptor)
    return file_descriptor, before


def _read_safe_descriptor(
    file_descriptor: int, before: os.stat_result, label: str, maximum: int
) -> bytes:
    try:
        opened = os.fstat(file_descriptor)
        if _identity(before) != _identity(opened):
            raise fail(f"{label} changed between validation and open")
        _regular_is_safe(opened, label, maximum)
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(file_descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(file_descriptor)
        if _identity(opened) != _identity(after):
            raise fail(f"{label} changed while reading")
        _regular_is_safe(after, label, maximum)
    finally:
        os.close(file_descriptor)
    if len(data) > maximum:
        raise fail(f"{label} exceeds its size bound")
    return data


def read_safe(root: Path, relative: str | PurePosixPath, label: str, *, maximum: int = MAX_SOURCE_BYTES) -> bytes:
    parts = _safe_relative_parts(relative, label)
    file_descriptor, before = _open_safe_file(root, parts, label, maximum)
    return _read_safe_descriptor(file_descriptor, before, label, maximum)


def _read_safe_named_file(directory_fd: int, name: str, label: str, maximum: int) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    if nofollow is None or nonblock is None:
        raise fail("safe profile evidence access requires no-follow non-blocking support")
    before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    _regular_is_safe(before, label, maximum)
    descriptor = os.open(name, os.O_RDONLY | nofollow | nonblock, dir_fd=directory_fd)
    return _read_safe_descriptor(descriptor, before, label, maximum)


def _list_safe(root: Path, label: str) -> set[str]:
    descriptor = _open_absolute_directory(root, label)
    try:
        names = set(os.listdir(descriptor))
        for name in names:
            if name in {".", ".."} or "/" in name or "\x00" in name:
                raise fail(f"{label} has an unsafe entry")
            details = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(details.st_mode):
                raise fail(f"{label} contains a symbolic link")
        return names
    finally:
        os.close(descriptor)


def _load_case_cli(path: Path) -> Any:
    path = _safe_absolute(path, "Apache case-summary helper")
    if path.name != "case_cli.py":
        raise fail("Apache case-summary helper name is invalid")
    read_safe(path.parent, path.name, "Apache case-summary helper", maximum=MAX_SOURCE_BYTES)
    try:
        module = load_source(path)
    except ProfileError:
        raise
    except (ImportError, OSError, RuntimeError, SyntaxError, ValueError) as exc:
        raise fail("Apache case-summary helper could not be imported") from exc
    if not callable(getattr(module, "connector_summary", None)):
        raise fail("Apache case-summary helper lacks connector_summary")
    return module


def _parse_selected_apache_case(raw: bytes) -> tuple[bytes, dict[str, Any]]:
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise fail(f"{APACHE_SELECTED_CASE_RESULT_LABEL} must be one JSONL record")
    value = parse_json_object(raw, APACHE_SELECTED_CASE_RESULT_LABEL)
    expected = (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")
    if raw != expected:
        raise fail(f"{APACHE_SELECTED_CASE_RESULT_LABEL} is not canonical case JSONL")
    for name, wanted in APACHE_SELECTED_CASE_EXPECTATIONS:
        if not _exact_json_scalar(value.get(name), wanted):
            raise fail(f"{APACHE_SELECTED_CASE_RESULT_LABEL} {name} is not the selected CRS result")
    return raw, value


def _case_summary_text(entry: Mapping[str, Any]) -> bytes:
    status = str(entry.get("status", "fail")).upper()
    scope = str(entry.get("scope", "unknown"))
    name = str(entry.get("name", "unknown"))
    expected = entry.get("expected_status")
    actual = entry.get("actual_status")
    suffix = f"expected={expected}" if actual is None else f"expected={expected} actual={actual}"
    return f"{status} {scope} {name} {suffix}\n".encode("utf-8")


def _require_token(value: str, label: str, *, decimal: bool = False) -> str:
    if not isinstance(value, str) or (DECIMAL if decimal else TOKEN).fullmatch(value) is None:
        raise fail(f"{label} is invalid")
    return value


def _require_sha(value: str, label: str, *, length: int = 40) -> str:
    pattern = SHA40 if length == 40 else SHA256
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise fail(f"{label} is not a lowercase full hash")
    return value


def _require_positive_identity(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise fail(f"{label} is invalid")
    return value


def _require_exact(mapping: Mapping[str, Any], required: set[str], label: str) -> None:
    actual = set(mapping)
    if actual != required:
        missing = ", ".join(sorted(required - actual))
        extra = ", ".join(sorted(actual - required))
        raise fail(f"{label} has unexpected fields (missing={missing or '-'} extra={extra or '-'})")


def _apache_selected_marker(runtime_root: Path, results_dir: Path) -> tuple[Path, tuple[str, ...], str, str]:
    runtime, _target, components = _runtime_relative_path(
        runtime_root, results_dir, APACHE_SELECTED_RESULTS_DIRECTORY_LABEL
    )
    relative = "/".join(components)
    marker = (
        APACHE_SELECTED_DIRECTORY_MARKER_PREFIX
        + hashlib.sha256(relative.encode("utf-8")).hexdigest()
        + ".json"
    )
    return runtime, components, relative, marker


def _apache_selected_directory_identity(details: os.stat_result) -> dict[str, int]:
    return {
        "device": details.st_dev,
        "inode": details.st_ino,
        "file_type": stat.S_IFMT(details.st_mode),
        "uid": details.st_uid,
        "mode": stat.S_IMODE(details.st_mode),
    }


def _apache_selected_marker_payload(relative: str, details: os.stat_result) -> bytes:
    return canonical_json(
        {
            "schema_version": SCHEMA_VERSION,
            "record_type": APACHE_SELECTED_DIRECTORY_MARKER_RECORD,
            "relative_path": relative,
            "identity": _apache_selected_directory_identity(details),
        }
    )


def _verify_apache_selected_marker(
    directory_fd: int, marker_name: str, relative: str, details: os.stat_result
) -> None:
    raw = _read_safe_named_file(
        directory_fd, marker_name, APACHE_SELECTED_RESULTS_DIRECTORY_MARKER_LABEL, MAX_JSON_BYTES
    )
    marker = parse_json_object(raw, APACHE_SELECTED_RESULTS_DIRECTORY_MARKER_LABEL, canonical=True)
    _require_exact(
        marker,
        {"schema_version", "record_type", "relative_path", "identity"},
        APACHE_SELECTED_RESULTS_DIRECTORY_MARKER_LABEL,
    )
    if (
        not _exact_json_scalar(marker.get("schema_version"), SCHEMA_VERSION)
        or not _exact_json_scalar(marker.get("record_type"), APACHE_SELECTED_DIRECTORY_MARKER_RECORD)
        or not _exact_json_scalar(marker.get("relative_path"), relative)
        or type(marker.get("identity")) is not dict
    ):
        raise fail(f"{APACHE_SELECTED_RESULTS_DIRECTORY_MARKER_LABEL} is invalid")
    expected = _apache_selected_directory_identity(details)
    identity = marker["identity"]
    _require_exact(
        identity,
        set(expected),
        f"{APACHE_SELECTED_RESULTS_DIRECTORY_MARKER_LABEL} identity",
    )
    for name, value in expected.items():
        if not _exact_json_scalar(identity.get(name), value):
            raise fail(f"{APACHE_SELECTED_RESULTS_DIRECTORY_LABEL} changed after preparation")


def _load_runtime_observation_module() -> Any:
    path = source_path('ci/runtime') / "contracts" / "runtime_observation.py"
    module = load_source(path)
    return module


RUNTIME_OBSERVATION = _load_runtime_observation_module()


def _load_haproxy_projector_module() -> Any:
    path = Path(__file__).with_name("project-haproxy-runtime-evidence.py")
    module = load_source(path)
    return module


HAPROXY_PROJECTOR = _load_haproxy_projector_module()


def _verify_crs_source(args: argparse.Namespace) -> dict[str, str]:
    source = _safe_absolute(args.crs_source_root, "CRS source root")
    # Descriptor-safe rule bytes are the evidence binding.  Git is used only
    # to read the commit of that exact, freshly prepared source checkout.
    rule = read_safe(source, CRS_RULE_FILE, "CRS rule")
    rule_sha = hashlib.sha256(rule).hexdigest()
    if rule_sha != args.crs_rule_sha256:
        raise fail("CRS rule digest does not match the trusted pin")
    if APACHE_CRS_RULE_ID.search(rule) is None:
        raise fail("CRS rule source does not contain the expected rule identity")
    environment = {
        "PATH": os.defpath,
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    try:
        result = subprocess.run(
            ["git", "-C", str(source), "rev-parse", "--verify", "HEAD^{commit}"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            env=environment,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise fail("fresh CRS source commit is not readable") from exc
    commit = result.stdout.strip()
    if commit != args.crs_commit or SHA40.fullmatch(commit) is None:
        raise fail("fresh CRS source commit does not match the trusted pin")
    return {
        "commit": commit,
        "rule_file": CRS_RULE_FILE,
        "rule_sha256": rule_sha,
    }


def _no_mrts_exact(value: object, label: str) -> dict[str, bool]:
    required = {
        "mrts_runner_invoked",
        "mrts_inventory_loaded",
        "mrts_process_started",
        "mrts_listener_created",
        "mrts_artifact_used",
    }
    if type(value) is not dict:
        raise fail(f"{label} must be an object")
    _require_exact(value, required, label)
    if any(item is not False for item in value.values()):
        raise fail(f"{label} contradicts no-MRTS execution")
    return dict.fromkeys(sorted(required), False)


def _generic_facts(args: argparse.Namespace) -> tuple[dict[str, Any], list[dict[str, str]]]:
    connector = args.connector
    root = args.source_root
    base = PurePosixPath("evidence")
    observation_rel = base / "normalized" / connector / args.cell_run_id / "runtime-observation.json"
    event_rel = base / "normalized" / connector / args.cell_run_id / "event.json"
    runtime_rel = base / "runtime" / connector / args.cell_run_id / "runtime.json"
    observation_raw = read_safe(root, observation_rel, "canonical runtime observation")
    event_raw = read_safe(root, event_rel, "normalized event")
    runtime_raw = read_safe(root, runtime_rel, "runtime attestation")
    observation = parse_json_object(observation_raw, "canonical runtime observation", canonical=True)
    event = parse_json_object(event_raw, "normalized event", canonical=True)
    runtime = parse_json_object(runtime_raw, "runtime attestation", canonical=True)
    expected_identity = {
        "connector": connector,
        "adapter_id": ADAPTER_IDS[connector],
        "integration_mode": INTEGRATION_MODES[connector],
        "profile": PROFILE,
        "crs": True,
        "mrts": False,
        "run_id": args.cell_run_id,
        "parent_commit": args.parent_sha,
        "framework_commit": args.framework_sha,
        "mrts_commit": args.mrts_sha,
        "producer": f"parent-runtime-observation-adapter-{connector}",
        "producer_version": "1.0.0",
    }
    validation = RUNTIME_OBSERVATION.validate_runtime_observation(
        observation,
        expected_identity,
        {"name": "strict", "evidence_root": root / "evidence"},
    )
    if validation.status != "PASS" or validation["validation_status"] != "CONTRACT_VALIDATED":
        raise fail("generic runtime observation did not pass the common contract")
    expected_event = {
        # The generic normalizer emits the existing Framework-compatibility
        # event profile.  Its canonical observation, validated above, carries
        # the closed Parent ``with-crs-no-mrts`` identity.
        "profile": "five-connectors-with-crs-no-mrts",
        "connector": connector,
        "adapter_id": ADAPTER_IDS[connector],
        "integration_mode": INTEGRATION_MODES[connector],
        "fixture_id": CASE_ID,
        "run_id": args.cell_run_id,
        "framework_commit": args.framework_sha,
        "connector_commit": args.parent_sha,
        "crs_commit": args.crs_commit,
        "crs_rule_file": CRS_RULE_FILE,
        "crs_rule_file_sha256": args.crs_rule_sha256,
        "expected_rule_id": RULE_ID,
        "observed_rule_id": RULE_ID,
        "expected_status": 403,
        "observed_status": 403,
        "intervention": "deny",
        "status": "PASS",
    }
    for name, expected in expected_event.items():
        if event.get(name) != expected:
            raise fail(f"generic normalized event {name} does not match the profile identity")
    expected_observation_path = str(observation_rel.relative_to(base))
    canonical = runtime.get("canonical_observation")
    if (
        runtime.get("record_type") != "parent_runtime_attestation"
        or runtime.get("connector") != connector
        or runtime.get("run_id") != args.cell_run_id
        or runtime.get("runtime_status") != "PASS"
        or type(canonical) is not dict
        or canonical.get("validation_status") != "CONTRACT_VALIDATED"
        or canonical.get("evidence_path") != expected_observation_path
        or canonical.get("evidence_sha256") != hashlib.sha256(observation_raw).hexdigest()
    ):
        raise fail("generic runtime attestation is not bound to the canonical observation")
    observation_runtime = observation.get("runtime")
    if type(observation_runtime) is not dict:
        raise fail("generic observation has no runtime assertions")
    allow = observation_runtime.get("allow_case")
    block = observation_runtime.get("block_case")
    if (
        type(allow) is not dict
        or type(block) is not dict
        or allow.get("result") != "PASS"
        or allow.get("observed") != {"http_status": 200}
        or block.get("result") != "PASS"
        or block.get("observed", {}).get("http_status") != 403
        or block.get("observed", {}).get("action") != "deny"
        or block.get("observed", {}).get("rule_ids") != [RULE_ID]
    ):
        raise fail("generic observation lacks the required allow/block functional facts")
    cleanup = observation.get("cleanup")
    if type(cleanup) is not dict or cleanup.get("cleanup_status") != "PASS":
        raise fail("generic observation cleanup is not complete")
    no_mrts = _no_mrts_exact(observation.get("isolation"), "generic no-MRTS isolation")
    facts = {
        "schema_version": SCHEMA_VERSION,
        "record_type": FACTS_RECORD,
        "profile": PROFILE,
        "connector": connector,
        "case_id": CASE_ID,
        "source_kind": SOURCE_KINDS[connector],
        "integration_mode": INTEGRATION_MODES[connector],
        "functional_result": "PASS",
        "allow_control": {"status": "observed", "http_status": 200},
        "block": {"http_status": 403, "action": "deny", "rule_id": RULE_ID},
        "cleanup_status": "complete",
        "no_mrts": {"status": "runtime_observed", "flags": no_mrts},
    }
    source_files = [
        {"path": str(runtime_rel), "sha256": hashlib.sha256(runtime_raw).hexdigest()},
        {"path": str(event_rel), "sha256": hashlib.sha256(event_raw).hexdigest()},
        {"path": str(observation_rel), "sha256": hashlib.sha256(observation_raw).hexdigest()},
    ]
    return facts, source_files


def _apache_case(value: object) -> Mapping[str, Any]:
    if not isinstance(value, dict) or type(value) is not dict:
        raise fail("Apache summary has no Apache section")
    apache = value.get("apache")
    if not isinstance(apache, dict) or type(apache) is not dict:
        raise fail("Apache summary has no Apache section")
    cases = apache.get("cases")
    if type(cases) is not dict or type(cases.get(CASE_ID)) is not dict:
        raise fail("Apache summary lacks the selected case")
    return cases[CASE_ID]


def _apache_audit_parts(raw: bytes) -> dict[str, dict[str, list[str]]]:
    """Parse a bounded serial ModSecurity audit without retaining its payload."""
    if not raw or len(raw) > MAX_SOURCE_BYTES or b"\x00" in raw:
        raise fail("Apache audit has unsafe bytes")
    try:
        lines = raw.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as exc:
        raise fail("Apache audit is not UTF-8") from exc
    transactions: dict[str, dict[str, list[str]]] = {}
    current: tuple[str, str] | None = None
    for line in lines:
        boundary = APACHE_AUDIT_BOUNDARY.fullmatch(line.rstrip("\r"))
        if boundary is not None:
            transaction, part = boundary.groups()
            parts = transactions.setdefault(transaction, {})
            if part in parts:
                raise fail("Apache audit repeats a transaction part")
            parts[part] = []
            current = (transaction, part)
            continue
        if current is None:
            if line:
                raise fail("Apache audit has data outside a transaction")
            continue
        transactions[current[0]][current[1]].append(line.rstrip("\r"))
    if not transactions:
        raise fail("Apache audit has no transactions")
    return transactions


def _apache_audit_block_observation(raw: bytes) -> None:
    """Require one complete raw transaction for the exact CRS block request."""
    transactions = _apache_audit_parts(raw)
    matches: list[dict[str, list[str]]] = []
    for parts in transactions.values():
        request_lines = [line for line in parts.get("B", ()) if line]
        if request_lines and request_lines[0] == APACHE_AUDIT_REQUEST_LINE:
            matches.append(parts)
    if len(matches) != 1:
        raise fail("Apache audit does not contain exactly one canonical block transaction")
    parts = matches[0]
    if not {"A", "B", "F", "H", "Z"}.issubset(parts):
        raise fail("Apache audit canonical block transaction is incomplete")
    response_lines = [line for line in parts["F"] if line]
    if not response_lines or APACHE_AUDIT_STATUS.match(response_lines[0]) is None:
        raise fail("Apache audit canonical block transaction lacks HTTP 403")
    rule_records = [
        line
        for line in parts["H"]
        if '[id "942270"]' in line
        and "REQUEST-942-APPLICATION-ATTACK-SQLI.conf" in line
    ]
    if len(rule_records) != 1:
        raise fail("Apache audit lacks one transaction-bound CRS rule 942270 record")


def _verify_apache_audit_path(path: Path) -> None:
    audit_path = _safe_absolute(path, "Apache audit path")
    _apache_audit_block_observation(
        read_safe(audit_path.parent, audit_path.name, "Apache audit")
    )


def _apache_cleanup_receipt(
    value: object,
    cell_run_id: str,
    github_run_id: str,
    github_run_attempt: str,
) -> None:
    if type(value) is not dict:
        raise fail(f"{APACHE_CLEANUP_RECEIPT_LABEL} must be an object")
    required = {
        "schema_version",
        "record_type",
        "profile",
        "connector",
        "case_id",
        "cell_run_id",
        "github_run_id",
        "github_run_attempt",
        "listener_port",
        "tracked_host_processes_remaining",
        "tracked_helper_processes_remaining",
        "selected_listeners_remaining",
        "pid_files_remaining",
        "cleanup_status",
    }
    _require_exact(value, required, APACHE_CLEANUP_RECEIPT_LABEL)
    expected = {
        "schema_version": SCHEMA_VERSION,
        "record_type": APACHE_CLEANUP_RECORD,
        "profile": PROFILE,
        "connector": "apache",
        "case_id": CASE_ID,
        "cell_run_id": cell_run_id,
        "github_run_id": github_run_id,
        "github_run_attempt": github_run_attempt,
        "cleanup_status": "PASS",
    }
    for name, wanted in expected.items():
        if not _exact_json_scalar(value.get(name), wanted):
            raise fail(f"{APACHE_CLEANUP_RECEIPT_LABEL} {name} is invalid")
    port = value.get("listener_port")
    if type(port) is not int or not 1 <= port <= 65535:
        raise fail(f"{APACHE_CLEANUP_RECEIPT_LABEL} listener port is invalid")
    for name in (
        "tracked_host_processes_remaining",
        "tracked_helper_processes_remaining",
        "selected_listeners_remaining",
        "pid_files_remaining",
    ):
        remaining = value.get(name)
        if type(remaining) is not int or remaining != 0:
            raise fail(f"{APACHE_CLEANUP_RECEIPT_LABEL} {name} is not clean")


def _write_apache_cleanup_receipt(args: argparse.Namespace) -> None:
    _require_token(args.github_run_id, "GitHub run ID", decimal=True)
    _require_token(args.github_run_attempt, "GitHub run attempt", decimal=True)
    _require_token(args.cell_run_id, "Apache workflow cell run ID")
    expected_cell = f"crs-{args.github_run_id}-{args.github_run_attempt}-apache"
    if args.cell_run_id != expected_cell:
        raise fail("Apache cleanup receipt cell run identity is invalid")
    output = _safe_absolute(args.output, "Apache cleanup receipt output")
    if output.name != APACHE_CLEANUP_RECEIPT_NAME:
        raise fail("Apache cleanup receipt output name is invalid")
    if type(args.listener_port) is not int or not 1 <= args.listener_port <= 65535:
        raise fail("Apache cleanup receipt listener port is invalid")
    payload = canonical_json(
        {
            "schema_version": SCHEMA_VERSION,
            "record_type": APACHE_CLEANUP_RECORD,
            "profile": PROFILE,
            "connector": "apache",
            "case_id": CASE_ID,
            "cell_run_id": args.cell_run_id,
            "github_run_id": args.github_run_id,
            "github_run_attempt": args.github_run_attempt,
            "listener_port": args.listener_port,
            "tracked_host_processes_remaining": 0,
            "tracked_helper_processes_remaining": 0,
            "selected_listeners_remaining": 0,
            "pid_files_remaining": 0,
            "cleanup_status": "PASS",
        }
    )
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise fail("Apache cleanup receipt publication requires O_NOFOLLOW")
    parent_fd = _open_absolute_directory(output.parent, "Apache cleanup receipt parent")
    descriptor = -1
    try:
        descriptor = os.open(
            output.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent_fd,
        )
        os.fchmod(descriptor, 0o600)
        before = os.fstat(descriptor)
        _regular_is_safe(before, APACHE_CLEANUP_RECEIPT_LABEL, MAX_JSON_BYTES)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise fail(f"{APACHE_CLEANUP_RECEIPT_LABEL} write was short")
            offset += written
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if _identity(before)[:3] != _identity(after)[:3]:
            raise fail(f"{APACHE_CLEANUP_RECEIPT_LABEL} changed while writing")
        _regular_is_safe(after, APACHE_CLEANUP_RECEIPT_LABEL, MAX_JSON_BYTES)
        os.fsync(parent_fd)
    except FileExistsError as exc:
        raise fail("Apache cleanup receipt already exists") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def _apache_facts(args: argparse.Namespace) -> tuple[dict[str, Any], list[dict[str, str]]]:
    if _safe_absolute(args.source_root, "Apache source root") != _safe_absolute(
        args.verified_root, "Apache verified runtime root"
    ):
        raise fail("Apache source root must be the verified runtime root")
    summary_rel = APACHE_SUMMARY_RELATIVE_PATH
    results_rel = APACHE_RESULTS_RELATIVE_PATH
    audit_rel = APACHE_AUDIT_RELATIVE_PATH
    cleanup_rel = APACHE_CLEANUP_RECEIPT_NAME
    summary_raw = read_safe(args.source_root, summary_rel, "Apache summary")
    results_raw = read_safe(args.source_root, results_rel, "Apache results")
    audit_raw = read_safe(args.source_root, audit_rel, "Apache audit")
    cleanup_raw = read_safe(args.source_root, cleanup_rel, APACHE_CLEANUP_RECEIPT_LABEL)
    summary = parse_json_object(summary_raw, "Apache summary")
    cleanup = parse_json_object(cleanup_raw, APACHE_CLEANUP_RECEIPT_LABEL, canonical=True)
    _apache_audit_block_observation(audit_raw)
    _apache_cleanup_receipt(
        cleanup,
        args.cell_run_id,
        args.github_run_id,
        args.github_run_attempt,
    )
    case = _apache_case(summary)
    for name, wanted in APACHE_SELECTED_CASE_EXPECTATIONS:
        if not _exact_json_scalar(case.get(name), wanted):
            raise fail(f"Apache case {name} is not the selected CRS result")
    try:
        lines = [
            json.loads(line, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_nonfinite_json)
            for line in results_raw.decode("utf-8").splitlines()
            if line.strip()
        ]
    except ValueError as exc:
        raise fail("Apache results JSONL is invalid") from exc
    if len(lines) != 1 or type(lines[0]) is not dict:
        raise fail("Apache results must contain exactly one selected case")
    for name, wanted in APACHE_SELECTED_CASE_EXPECTATIONS:
        if not _exact_json_scalar(lines[0].get(name), wanted):
            raise fail(f"Apache JSONL {name} disagrees with the selected case")
    facts = {
        "schema_version": SCHEMA_VERSION,
        "record_type": FACTS_RECORD,
        "profile": PROFILE,
        "connector": "apache",
        "case_id": CASE_ID,
        "source_kind": SOURCE_KINDS["apache"],
        "integration_mode": INTEGRATION_MODES["apache"],
        "functional_result": "PASS",
        # The selected Apache fixture executes the CRS block only.  This is
        # not upgraded into a synthetic allow claim by the Parent wrapper.
        "allow_control": {"status": "not_observed"},
        # The raw serial audit binds the request, response, and exact CRS
        # rule in one transaction; it is not inferred from the configured
        # CRS source or the summary labels.
        "block": {"http_status": 403, "action": "deny", "rule_id": RULE_ID},
        # The parent-owned receipt is emitted only after tracked cleanup,
        # PID-file removal, and the selected-port probe complete.
        "cleanup_status": "complete",
        # Apache's selected source artifact records the `with-crs` case and
        # its outcome, but it does not emit generic runtime isolation counters
        # or a native MRTS mode.  The no-MRTS value is therefore explicitly a
        # workflow configuration binding, not a manufactured runtime fact.
        "no_mrts": {"status": "workflow_declared", "workflow_value": "no-mrts"},
    }
    return facts, [
        {"path": summary_rel, "sha256": hashlib.sha256(summary_raw).hexdigest()},
        {"path": results_rel, "sha256": hashlib.sha256(results_raw).hexdigest()},
        {"path": audit_rel, "sha256": hashlib.sha256(audit_raw).hexdigest()},
        {"path": cleanup_rel, "sha256": hashlib.sha256(cleanup_raw).hexdigest()},
    ]


def _haproxy_facts(args: argparse.Namespace) -> tuple[dict[str, Any], list[dict[str, str]]]:
    evidence_sha256 = _require_sha(
        args.haproxy_evidence_sha256, "HAProxy verified evidence digest", length=64
    )
    manifest_sha256 = _require_sha(
        args.haproxy_manifest_sha256, "HAProxy verified manifest digest", length=64
    )
    evidence_uid = _require_positive_identity(
        args.haproxy_evidence_uid, "HAProxy evidence UID"
    )
    evidence_gid = _require_positive_identity(
        args.haproxy_evidence_gid, "HAProxy evidence GID"
    )
    stage_root = _safe_absolute(args.source_root, "HAProxy sealed stage root")
    trusted = HAPROXY_PROJECTOR.TrustedRuntimeValues(
        parent_sha=args.parent_sha,
        framework_sha=args.framework_sha,
        mrts_sha=args.mrts_sha,
        cell_run_id=args.cell_run_id,
    )
    # The sealed package remains owned by the separate evidence identity.
    # Reuse its strict verifier rather than weakening generic file ownership
    # checks or relabeling this workflow-owned handoff as native evidence.
    try:
        verified = HAPROXY_PROJECTOR.verify_staged_package(
            # The projector's runner root is the parent of the per-run stage
            # parent.  Derive it from the already validated stage path rather
            # than naming a shared public temporary directory.  The projector
            # still reopens every component with O_NOFOLLOW and checks its
            # ownership/mode through descriptors.
            runner_temp=stage_root.parent.parent,
            stage_parent=stage_root.parent,
            stage_root=stage_root,
            trusted=trusted,
            runtime_uid=os.geteuid(),
            upload_gid=os.getegid(),
            evidence_uid=evidence_uid,
            evidence_gid=evidence_gid,
        )
    except (OSError, ValueError, HAPROXY_PROJECTOR.EvidenceProjectionError) as exc:
        raise fail("HAProxy sealed package did not pass its strict verifier") from exc
    if verified != {
        "haproxy-runtime-evidence.json": evidence_sha256,
        MANIFEST_NAME: manifest_sha256,
    }:
        raise fail("HAProxy verified source digests do not match the workflow handoff")
    facts = {
        "schema_version": SCHEMA_VERSION,
        "record_type": FACTS_RECORD,
        "profile": PROFILE,
        "connector": "haproxy",
        "case_id": CASE_ID,
        "source_kind": SOURCE_KINDS["haproxy"],
        "integration_mode": INTEGRATION_MODES["haproxy"],
        "functional_result": "PASS",
        # The sealed HAProxy source receipt is one block case.  Its missing
        # allow fact remains explicit instead of being manufactured here.
        "allow_control": {"status": "not_observed"},
        "block": {"http_status": 403, "action": "deny", "rule_id": RULE_ID},
        "cleanup_status": "complete",
        # The sealed HAProxy source receipt binds `mrts_mode=no-mrts`, but
        # does not contain generic runtime isolation counters.
        "no_mrts": {"status": "source_declared", "source_value": "no-mrts"},
    }
    return facts, [
        {"path": "haproxy-runtime-evidence.json", "sha256": evidence_sha256},
        {"path": MANIFEST_NAME, "sha256": manifest_sha256},
    ]


def _create_output_directory(verified_root: Path, output_dir: Path) -> tuple[Path, int]:
    verified = _safe_absolute(verified_root, "verified runtime root")
    output = _safe_absolute(output_dir, "profile output directory")
    if output.parent != verified or output.name != "profile-cell":
        raise fail("profile output directory must be the fresh profile-cell child")
    root_fd = _open_absolute_directory(verified, "verified runtime root")
    try:
        try:
            os.mkdir(output.name, 0o700, dir_fd=root_fd)
        except FileExistsError as exc:
            raise fail("profile output directory already exists") from exc
        child = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            details = os.fstat(child)
            if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o700:
                raise fail("profile output directory is not a new private directory")
            os.fsync(root_fd)
            return output, child
        except BaseException:
            os.close(child)
            raise
    finally:
        os.close(root_fd)


def _write_new_named_file(
    directory_fd: int, name: str, data: bytes, label: str, allowed_names: Sequence[str]
) -> None:
    if name not in allowed_names or not data or len(data) > MAX_JSON_BYTES:
        raise fail(f"{label} is invalid")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise fail("profile publication requires O_NOFOLLOW")
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(descriptor, 0o600)
        before = os.fstat(descriptor)
        _regular_is_safe(before, label, MAX_JSON_BYTES)
        remaining = memoryview(data)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short profile receipt write")
            remaining = remaining[written:]
        os.fsync(descriptor)
        if _identity(before)[:3] != _identity(os.fstat(descriptor))[:3]:
            raise fail(f"{label} identity changed while writing")
    finally:
        os.close(descriptor)


def _write_new_file(directory_fd: int, name: str, data: bytes, label: str) -> None:
    _write_new_named_file(directory_fd, name, data, label, OUTPUT_NAMES)


def prepare_apache_selected_results(args: argparse.Namespace) -> None:
    runtime, components, relative, marker_name = _apache_selected_marker(
        args.runtime_root, args.results_dir
    )
    root_fd = _open_absolute_directory(runtime, APACHE_RUNTIME_ROOT_LABEL)
    try:
        descriptor = _create_runtime_child(root_fd, components, APACHE_SELECTED_RESULTS_DIRECTORY_LABEL)
        try:
            marker = _apache_selected_marker_payload(relative, os.fstat(descriptor))
            _write_new_named_file(
                root_fd,
                marker_name,
                marker,
                APACHE_SELECTED_RESULTS_DIRECTORY_MARKER_LABEL,
                (marker_name,),
            )
            os.fsync(descriptor)
            os.fsync(root_fd)
        finally:
            os.close(descriptor)
    finally:
        os.close(root_fd)


def _apache_selected_summary(args: argparse.Namespace, entry: dict[str, Any]) -> bytes:
    case_cli = _load_case_cli(args.case_cli)
    results_dir = _safe_absolute(args.results_dir, APACHE_SELECTED_RESULTS_DIRECTORY_LABEL)
    summary_args = argparse.Namespace(
        connector="apache",
        input_jsonl=os.fspath(results_dir / APACHE_SELECTED_RESULTS_NAME),
        summary_json=os.fspath(results_dir / APACHE_SELECTED_SUMMARY_NAME),
        summary_text=os.fspath(results_dir / APACHE_SELECTED_SUMMARY_TEXT_NAME),
        import_status_file=os.fspath(args.import_status_file),
        connector_path="real-world",
        validation_mode="real-world-connector-path",
        environment=None,
        server="apache",
        server_binary=args.server_binary,
        module=args.module,
        libmodsecurity=args.libmodsecurity,
        origin_source=args.origin_source,
        origin_source_repo=args.origin_source_repo,
        origin_source_url=args.origin_source_url,
        origin_source_commit=args.origin_source_commit,
        origin_source_version=args.origin_source_version,
        origin_license=args.origin_license,
        origin_imported_path=args.origin_imported_path,
        runtime_mode="selected-case",
        command="RUN_ONE_CASE=1 make verified-apache-case",
        exit_status="0",
        run_id="",
        run_started_at="",
        per_case_result_root=os.fspath(args.log_dir),
    )
    try:
        summary = case_cli.connector_summary(summary_args, [entry])
        payload = {"apache": summary}
        return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    except (AttributeError, TypeError, ValueError) as exc:
        raise fail("Apache case-summary construction failed") from exc


def publish_apache_selected_results(args: argparse.Namespace) -> None:
    runtime, result_components, relative, marker_name = _apache_selected_marker(
        args.runtime_root, args.results_dir
    )
    _log_runtime, _log_target, log_components = _runtime_relative_path(
        args.runtime_root, args.log_dir, APACHE_SELECTED_LOG_DIRECTORY_LABEL
    )
    log_dir = _safe_absolute(args.log_dir, APACHE_SELECTED_LOG_DIRECTORY_LABEL)
    result_json = _safe_absolute(args.result_json, APACHE_SELECTED_CASE_RESULT_LABEL)
    if result_json.name != "result.json" or result_json.parent != log_dir:
        raise fail(
            f"{APACHE_SELECTED_CASE_RESULT_LABEL} must be inside the "
            f"{APACHE_SELECTED_LOG_DIRECTORY_LABEL}"
        )
    root_fd = _open_absolute_directory(runtime, APACHE_RUNTIME_ROOT_LABEL)
    try:
        log_fd = _open_runtime_child(root_fd, log_components, APACHE_SELECTED_LOG_DIRECTORY_LABEL)
        try:
            result_raw, entry = _parse_selected_apache_case(
                _read_safe_named_file(
                    log_fd,
                    "result.json",
                    APACHE_SELECTED_CASE_RESULT_LABEL,
                    MAX_JSON_BYTES,
                )
            )
        finally:
            os.close(log_fd)
        summary_raw = _apache_selected_summary(args, entry)
        summary_text = _case_summary_text(entry)
        outputs = (
            (APACHE_SELECTED_RESULTS_NAME, result_raw, "selected Apache case JSONL"),
            (APACHE_SELECTED_SUMMARY_NAME, summary_raw, "selected Apache summary"),
            (APACHE_SELECTED_SUMMARY_TEXT_NAME, summary_text, "selected Apache text summary"),
            (APACHE_SELECTED_CONNECTOR_SUMMARY_NAME, summary_text, "selected Apache connector summary"),
        )
        descriptor = _open_runtime_child(
            root_fd, result_components, APACHE_SELECTED_RESULTS_DIRECTORY_LABEL
        )
        try:
            _verify_apache_selected_marker(
                root_fd, marker_name, relative, os.fstat(descriptor)
            )
            for name, _data, label in outputs:
                try:
                    existing = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if stat.S_ISLNK(existing.st_mode):
                    raise fail(f"{label} path is a symbolic link")
                raise fail(f"{label} already exists")
            for name, data, label in outputs:
                _write_new_named_file(descriptor, name, data, label, APACHE_SELECTED_OUTPUT_NAMES)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        os.close(root_fd)


def _source_files_value(source_files: list[dict[str, str]]) -> list[dict[str, str]]:
    ordered = sorted(source_files, key=lambda item: item["path"])
    if len({item["path"] for item in ordered}) != len(ordered):
        raise fail("source artifact paths are duplicated")
    for item in ordered:
        _safe_relative_parts(item["path"], "source artifact path")
        _require_sha(item["sha256"], "source artifact digest", length=64)
    return ordered


def produce(args: argparse.Namespace) -> dict[str, Any]:
    if args.connector not in CONNECTORS:
        raise fail("connector is outside the closed with-CRS/no-MRTS profile")
    _require_token(args.profile_run_id, "profile run ID")
    _require_token(args.cell_run_id, "workflow cell run ID")
    _require_token(args.github_run_id, "GitHub run ID", decimal=True)
    _require_token(args.github_run_attempt, "GitHub run attempt", decimal=True)
    for name in ("parent_sha", "base_sha", "framework_sha", "mrts_sha", "crs_commit"):
        _require_sha(getattr(args, name), name)
    _require_sha(args.crs_rule_sha256, "CRS rule digest", length=64)
    if args.parent_sha == args.base_sha:
        raise fail("candidate head and base must be distinct")
    expected_cell = f"crs-{args.github_run_id}-{args.github_run_attempt}-{args.connector}"
    expected_profile = f"with-crs-no-mrts-{args.github_run_id}-{args.github_run_attempt}"
    if args.cell_run_id != expected_cell or args.profile_run_id != expected_profile:
        raise fail("workflow cell or profile run identity does not match the GitHub invocation")
    if args.connector in GENERIC_CONNECTORS:
        facts, source_files = _generic_facts(args)
    elif args.connector == "apache":
        facts, source_files = _apache_facts(args)
    else:
        facts, source_files = _haproxy_facts(args)
    if facts.get("cleanup_status") != "complete":
        raise fail("source facts do not prove complete cleanup")
    crs = _verify_crs_source(args)
    source_files = _source_files_value(source_files)
    facts["source_files_sha256"] = hashlib.sha256(canonical_json(source_files)).hexdigest()
    facts_data = canonical_json(facts)
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "record_type": PROFILE_RECORD,
        "profile": PROFILE,
        "connector": args.connector,
        "cell_identity": f"{args.connector}:with-crs:no-mrts",
        "case_id": CASE_ID,
        "executed_test": CASE_ID,
        "source_kind": SOURCE_KINDS[args.connector],
        "integration_mode": INTEGRATION_MODES[args.connector],
        "profile_run_id": args.profile_run_id,
        "cell_run_id": args.cell_run_id,
        "cell_run_id_kind": "workflow_cell",
        "github_run_id": args.github_run_id,
        "github_run_attempt": args.github_run_attempt,
        "artifact_name": f"with-crs-no-mrts-{args.connector}-{args.github_run_id}-{args.github_run_attempt}",
        "parent_sha": args.parent_sha,
        "base_sha": args.base_sha,
        "framework_sha": args.framework_sha,
        "mrts_sha": args.mrts_sha,
        "crs_commit": crs["commit"],
        "crs_rule_file": crs["rule_file"],
        "crs_rule_sha256": crs["rule_sha256"],
        "functional_facts_sha256": hashlib.sha256(facts_data).hexdigest(),
        "source_files": source_files,
        "technical_validation": "PASS",
        "functional_result": "PASS",
        "cleanup_status": facts["cleanup_status"],
        "no_mrts": facts["no_mrts"],
    }
    receipt_data = canonical_json(receipt)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "record_type": MANIFEST_RECORD,
        "files": [
            {"name": FUNCTIONAL_FACTS_NAME, "sha256": hashlib.sha256(facts_data).hexdigest(), "size_bytes": len(facts_data)},
            {"name": PROFILE_RECEIPT_NAME, "sha256": hashlib.sha256(receipt_data).hexdigest(), "size_bytes": len(receipt_data)},
        ],
    }
    manifest_data = canonical_json(manifest)
    _output, output_fd = _create_output_directory(args.verified_root, args.output_dir)
    try:
        _write_new_file(output_fd, FUNCTIONAL_FACTS_NAME, facts_data, "functional facts")
        _write_new_file(output_fd, PROFILE_RECEIPT_NAME, receipt_data, "profile cell receipt")
        _write_new_file(output_fd, MANIFEST_NAME, manifest_data, "profile cell manifest")
        os.fsync(output_fd)
    finally:
        os.close(output_fd)
    return receipt


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    produce_parser = actions.add_parser("produce")
    produce_parser.add_argument("--connector", required=True, choices=CONNECTORS)
    produce_parser.add_argument("--profile-run-id", required=True)
    produce_parser.add_argument("--cell-run-id", required=True)
    produce_parser.add_argument("--parent-sha", required=True)
    produce_parser.add_argument("--base-sha", required=True)
    produce_parser.add_argument("--github-run-id", required=True)
    produce_parser.add_argument("--github-run-attempt", required=True)
    produce_parser.add_argument("--framework-sha", required=True)
    produce_parser.add_argument("--mrts-sha", required=True)
    produce_parser.add_argument("--crs-commit", required=True)
    produce_parser.add_argument("--crs-rule-sha256", required=True)
    produce_parser.add_argument("--crs-source-root", type=Path, required=True)
    produce_parser.add_argument("--haproxy-evidence-sha256")
    produce_parser.add_argument("--haproxy-manifest-sha256")
    produce_parser.add_argument("--haproxy-evidence-uid", type=int)
    produce_parser.add_argument("--haproxy-evidence-gid", type=int)
    produce_parser.add_argument("--verified-root", type=Path, required=True)
    produce_parser.add_argument("--source-root", type=Path, required=True)
    produce_parser.add_argument("--output-dir", type=Path, required=True)

    verify_audit = actions.add_parser("verify-apache-audit")
    verify_audit.add_argument("--audit-log", type=Path, required=True)

    write_cleanup = actions.add_parser("write-apache-cleanup-receipt")
    write_cleanup.add_argument("--output", type=Path, required=True)
    write_cleanup.add_argument("--cell-run-id", required=True)
    write_cleanup.add_argument("--github-run-id", required=True)
    write_cleanup.add_argument("--github-run-attempt", required=True)
    write_cleanup.add_argument("--listener-port", type=int, required=True)

    prepare_selected = actions.add_parser("prepare-apache-selected-results")
    prepare_selected.add_argument("--runtime-root", type=Path, required=True)
    prepare_selected.add_argument("--results-dir", type=Path, required=True)

    publish_selected = actions.add_parser("publish-apache-selected-results")
    publish_selected.add_argument("--runtime-root", type=Path, required=True)
    publish_selected.add_argument("--results-dir", type=Path, required=True)
    publish_selected.add_argument("--result-json", type=Path, required=True)
    publish_selected.add_argument("--case-cli", type=Path, required=True)
    publish_selected.add_argument("--import-status-file", type=Path, required=True)
    publish_selected.add_argument("--log-dir", type=Path, required=True)
    publish_selected.add_argument("--server-binary", required=True)
    publish_selected.add_argument("--module", required=True)
    publish_selected.add_argument("--libmodsecurity", required=True)
    publish_selected.add_argument("--origin-source", required=True)
    publish_selected.add_argument("--origin-source-repo", required=True)
    publish_selected.add_argument("--origin-source-url", required=True)
    publish_selected.add_argument("--origin-source-commit", required=True)
    publish_selected.add_argument("--origin-source-version", required=True)
    publish_selected.add_argument("--origin-license", required=True)
    publish_selected.add_argument("--origin-imported-path", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.action == "produce":
            receipt = produce(args)
            output = {
                "status": "PASS",
                "connector": receipt["connector"],
                "profile_run_id": receipt["profile_run_id"],
            }
        elif args.action == "verify-apache-audit":
            _verify_apache_audit_path(args.audit_log)
            output = {"status": "PASS", "connector": "apache", "check": "audit"}
        elif args.action == "write-apache-cleanup-receipt":
            _write_apache_cleanup_receipt(args)
            output = {"status": "PASS", "connector": "apache", "check": "cleanup"}
        elif args.action == "prepare-apache-selected-results":
            prepare_apache_selected_results(args)
            output = {"status": "PASS", "connector": "apache", "check": "selected-results-directory"}
        else:
            publish_apache_selected_results(args)
            output = {"status": "PASS", "connector": "apache", "check": "selected-results"}
    except (OSError, ProfileError, subprocess.SubprocessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
