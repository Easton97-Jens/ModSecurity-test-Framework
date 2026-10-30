#!/usr/bin/env python3
"""Run local Envoy/Traefik/lighttpd runtime smokes without global dependencies."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import contextlib
from dataclasses import dataclass
import http.client
import http.server
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


# CI helpers are shared from ci/lib even when this runner is executed directly.
_CI_LIB = connector_root() / "ci" / "lib"


_SCRIPT_DIR = Path(__file__).resolve().parent


_CONNECTOR_ROOT = _SCRIPT_DIR.parents[1]

from modsecurity_connector_ci.lib.runtime_path_utils import is_safe_runtime_root, verified_runtime_paths
from common.scripts.write_smoke_result import main as write_smoke_result_main


BLOCK_VALUES = {"1", "true", "block", "yes", "on"}
REQUEST_BODY_BLOCK_MARKER = "modsec-request-body-block"
REQUEST_BODY_ALLOW_BODY = b"payload=modsec-request-body-allow"
REQUEST_BODY_BLOCK_BODY = b"payload=modsec-request-body-block"
REQUEST_BODY_CONTENT_TYPE = "application/x-www-form-urlencoded"
DEFAULT_TEXT_CONTENT_TYPE = "text/plain"
DEFAULT_BLOCKED_PATH = "/blocked"
DEFAULT_ALLOWED_PATH = "/allowed"
LOOPBACK_HOST = "127.0.0.1"
MAX_REQUEST_BODY_BYTES = 64 * 1024
MAX_CHUNK_LINE_BYTES = 128
MAX_TRAILER_BYTES = 8 * 1024
SERVER_SOCKET_TIMEOUT_SECONDS = 5.0
MAX_LOCAL_REQUEST_TARGET_BYTES = 4096
TARGETED_SMOKE_CASES = {"targeted", "request_body"}
CRS_SETUP_TEMPLATE_NAME = "crs-setup.conf.example"
GENERATED_CRS_SMOKE_RULE_LABEL = "generated CRS smoke rule"
RUNTIME_PATH_DEPENDENCY = "runtime path"
RUNTIME_OUTPUT_PATH_FIELDS = (
    ("evidence_root", "EVIDENCE_ROOT"),
    ("results_dir", "RESULTS_DIR"),
    ("tmp_root", "TMP_ROOT"),
    ("log_root", "LOG_ROOT"),
    ("log_dir", "LOG_DIR"),
    ("config_root", "CONFIG_ROOT"),
)
CRS_SMOKE_CASES = {
    "minimal": {
        "blocked_path": "/?id=1%20UNION%20SELECT%20password%20FROM%20users",
        "description": "existing CRS SQLi anomaly probe",
    },
    "secondary": {
        "blocked_path": "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "description": "secondary CRS XSS query probe",
    },
}


class SmokeBlocked(RuntimeError):
    def __init__(self, reason: str, missing_dependencies: list[str]) -> None:
        super().__init__(reason)
        self.reason = reason
        self.missing_dependencies = missing_dependencies


class RequestBodyError(ValueError):
    status_code = 400


class RequestBodyTooLarge(RequestBodyError):
    status_code = 413


def require_local_request_method(value: str) -> str:
    """Accept only the HTTP methods implemented by the loopback smoke handlers."""

    if value not in {"GET", "POST", "HEAD"}:
        raise RequestBodyError(f"unsupported local smoke request method: {value}")
    return value


def require_local_request_target(value: str) -> str:
    """Return a bounded origin-form target without an authority or fragment."""

    if not value or len(value) > MAX_LOCAL_REQUEST_TARGET_BYTES:
        raise RequestBodyError("invalid local smoke request target length")
    if "\\" in value or any(ord(character) < 0x20 for character in value):
        raise RequestBodyError("invalid local smoke request target characters")
    parsed = urllib.parse.urlsplit(value, allow_fragments=True)
    if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path.startswith("/"):
        raise RequestBodyError("local smoke requests require an origin-form target")
    return urllib.parse.urlunsplit(("", "", parsed.path, parsed.query, ""))


def configured_smoke_target(value: str) -> str:
    """Return a fixed protocol probe selected from the local smoke contract."""

    target = require_local_request_target(value)
    if target in {"/", DEFAULT_ALLOWED_PATH, DEFAULT_BLOCKED_PATH}:
        return target
    for details in CRS_SMOKE_CASES.values():
        blocked_path = str(details["blocked_path"])
        if target == blocked_path:
            return blocked_path
    raise RequestBodyError("unsupported local smoke request target")


def require_loopback_port(value: int, *, allow_ephemeral: bool = False) -> int:
    """Return one permitted local TCP port, retaining `0` only for bind tests."""

    if value == 0:
        if allow_ephemeral:
            return 0
        raise RequestBodyError("invalid loopback TCP port: 0")
    if not 1 <= value <= 65535:
        raise RequestBodyError(f"invalid loopback TCP port: {value}")
    return value


def selected_loopback_port(value: int) -> int:
    """Use the configured loopback port or allocate one through the local binder."""

    return free_port() if value == 0 else require_loopback_port(value)


def local_smoke_url(port: int, target: str) -> str:
    """Build a loopback-only URL from independently validated components."""

    safe_port = require_loopback_port(port)
    parsed = urllib.parse.urlsplit(require_local_request_target(target), allow_fragments=True)
    return urllib.parse.urlunsplit(
        ("http", f"{LOOPBACK_HOST}:{safe_port}", parsed.path, parsed.query, "")
    )


@dataclass(frozen=True)
class RuntimeOutputPaths:
    runtime_root: Path
    evidence_root: Path
    results_dir: Path
    tmp_root: Path
    log_root: Path
    log_dir: Path
    config_root: Path


@dataclass(frozen=True)
class SmokeResult:
    """One immutable runtime-smoke result passed to the evidence writer."""

    status: str
    exit_code: int
    runtime_verified: bool
    allowed: int | None
    blocked: int | None
    skipped_reason: str = ""
    missing: tuple[str, ...] = ()
    modsecurity_backend_verified: bool = False
    modsecurity_rule_loaded: bool = False
    intervention_status: int | None = None
    decision_log_path: str = ""
    audit_log_path: str = ""
    lighttpd_binary_verified: bool = False
    lighttpd_http_verified: bool = False
    sidecar_proxy_verified: bool = False
    lighttpd_log_path: str = ""
    upstream_log_path: str = ""
    request_transcript_path: str = ""
    request_body_smoke_verified: bool = False
    request_body_access_enabled: bool = False
    request_body_rule_loaded: bool = False
    crs_minimal_smoke_verified: bool = False
    crs_secondary_smoke_verified: bool = False
    crs_rule_id: str = ""
    crs_rule_message: str = ""


@dataclass(frozen=True)
class BackendEvidence:
    """Decision-backend facts shared by every result from one smoke run."""

    modsecurity_backend_verified: bool = False
    modsecurity_rule_loaded: bool = False
    intervention_status: int | None = None
    request_body_smoke_verified: bool = False
    request_body_access_enabled: bool = False
    request_body_rule_loaded: bool = False
    crs_minimal_smoke_verified: bool = False
    crs_secondary_smoke_verified: bool = False
    crs_rule_id: str = ""
    crs_rule_message: str = ""


def backend_evidence_with_crs_rules(
    evidence: BackendEvidence, crs_rule_id: str, crs_rule_message: str
) -> BackendEvidence:
    """Retain backend facts while replacing only audit-derived CRS rule details."""

    return BackendEvidence(
        evidence.modsecurity_backend_verified,
        evidence.modsecurity_rule_loaded,
        evidence.intervention_status,
        evidence.request_body_smoke_verified,
        evidence.request_body_access_enabled,
        evidence.request_body_rule_loaded,
        evidence.crs_minimal_smoke_verified,
        evidence.crs_secondary_smoke_verified,
        crs_rule_id,
        crs_rule_message,
    )


def backend_evidence_with_crs_verification(
    evidence: BackendEvidence, minimal_verified: bool, secondary_verified: bool
) -> BackendEvidence:
    """Retain backend facts while setting the two derived CRS verification flags."""

    return BackendEvidence(
        evidence.modsecurity_backend_verified,
        evidence.modsecurity_rule_loaded,
        evidence.intervention_status,
        evidence.request_body_smoke_verified,
        evidence.request_body_access_enabled,
        evidence.request_body_rule_loaded,
        minimal_verified,
        secondary_verified,
        evidence.crs_rule_id,
        evidence.crs_rule_message,
    )


@dataclass(frozen=True)
class EvaluatorRequest:
    """Validated values that may cross into the local evaluator process."""

    header_value: str
    path: str
    method: str
    body: bytes
    content_type: str


@dataclass(frozen=True)
class SmokeWriterValues:
    """Derived, non-sensitive writer arguments for one smoke result."""

    effective_rule_file: str
    effective_crs_runtime_dir: str
    effective_crs_source_dir: str
    crs_version: str
    modsecurity_ruleset: str
    modsecurity_smoke_case: str
    crs_smoke_case: str
    modsecurity_rule_id: str
    request_body_rule_file: str
    request_body_rule_id: str
    request_method: str
    blocked_body_marker: str


def collect_backend_evidence(decision_backend: object) -> BackendEvidence:
    """Collect one immutable snapshot before the evidence writer runs."""

    (
        request_body_smoke_verified,
        request_body_access_enabled,
        request_body_rule_loaded,
    ) = request_body_evidence(decision_backend)
    return BackendEvidence(
        modsecurity_backend_verified=bool(
            getattr(decision_backend, "modsecurity_backend_verified", False)
        ),
        modsecurity_rule_loaded=bool(getattr(decision_backend, "modsecurity_rule_loaded", False)),
        intervention_status=getattr(decision_backend, "intervention_status", None),
        request_body_smoke_verified=request_body_smoke_verified,
        request_body_access_enabled=request_body_access_enabled,
        request_body_rule_loaded=request_body_rule_loaded,
        crs_rule_id=str(getattr(decision_backend, "crs_rule_id", "")),
        crs_rule_message=str(getattr(decision_backend, "crs_rule_message", "")),
    )


def smoke_result(
    status: str,
    exit_code: int,
    runtime_verified: bool,
    allowed: int | None,
    blocked: int | None,
    evidence: BackendEvidence = BackendEvidence(),
    *,
    skipped_reason: str = "",
    missing: tuple[str, ...] = (),
    context: dict[str, object] | None = None,
) -> SmokeResult:
    """Combine shared backend facts and run-specific paths into one result."""

    return SmokeResult(
        status,
        exit_code,
        runtime_verified,
        allowed,
        blocked,
        skipped_reason=skipped_reason,
        missing=missing,
        modsecurity_backend_verified=evidence.modsecurity_backend_verified,
        modsecurity_rule_loaded=evidence.modsecurity_rule_loaded,
        intervention_status=evidence.intervention_status,
        request_body_smoke_verified=evidence.request_body_smoke_verified,
        request_body_access_enabled=evidence.request_body_access_enabled,
        request_body_rule_loaded=evidence.request_body_rule_loaded,
        crs_minimal_smoke_verified=evidence.crs_minimal_smoke_verified,
        crs_secondary_smoke_verified=evidence.crs_secondary_smoke_verified,
        crs_rule_id=evidence.crs_rule_id,
        crs_rule_message=evidence.crs_rule_message,
        **(context or {}),
    )


def require_verified_runtime_output_path(value: str, label: str, root: Path) -> Path:
    """Return one absolute CLI output path constrained to the verified run root."""

    configured = Path(value)
    if not configured.is_absolute():
        raise SmokeBlocked(f"{label} must be absolute: {configured}", [RUNTIME_PATH_DEPENDENCY])
    component = Path(configured.anchor)
    for name in configured.parts[1:]:
        component /= name
        try:
            metadata = component.lstat()
        except FileNotFoundError:
            break
        except OSError as exc:
            raise SmokeBlocked(
                f"{label} cannot inspect path component: {component}", [RUNTIME_PATH_DEPENDENCY]
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise SmokeBlocked(
                f"{label} must not contain a symlink: {component}", [RUNTIME_PATH_DEPENDENCY]
            )
    try:
        resolved = configured.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise SmokeBlocked(f"{label} cannot be resolved: {configured}", [RUNTIME_PATH_DEPENDENCY]) from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise SmokeBlocked(
            f"{label} is outside the verified runtime root: {resolved}", [RUNTIME_PATH_DEPENDENCY]
        ) from exc
    return resolved


def validate_runtime_output_paths(args: argparse.Namespace) -> RuntimeOutputPaths:
    """Validate every direct CLI output destination before this runner writes."""

    try:
        verified = verified_runtime_paths(os.environ)
    except ValueError as exc:
        raise SmokeBlocked(f"invalid verified runtime paths: {exc}", [RUNTIME_PATH_DEPENDENCY]) from exc
    runtime_root = Path(verified["VERIFIED_RUN_ROOT"]).resolve(strict=False)
    if not is_safe_runtime_root(runtime_root):
        raise SmokeBlocked(f"VERIFIED_RUN_ROOT is unsafe: {runtime_root}", [RUNTIME_PATH_DEPENDENCY])

    values: dict[str, Path] = {}
    for field, label in RUNTIME_OUTPUT_PATH_FIELDS:
        configured = namespace_value(args, field)
        if not configured:
            raise SmokeBlocked(f"missing required {label}", [RUNTIME_PATH_DEPENDENCY])
        values[field] = require_verified_runtime_output_path(configured, label, runtime_root)
        setattr(args, field, str(values[field]))
    return RuntimeOutputPaths(runtime_root=runtime_root, **values)


def require_runtime_binary(args: argparse.Namespace) -> Path:
    """Validate the fixed connector executable before it reaches a process call."""

    expected_names = {"envoy": "envoy", "traefik": "traefik", "lighttpd": "lighttpd"}
    candidate = Path(namespace_value(args, "resolved_runtime_binary"))
    if not candidate.is_absolute():
        raise SmokeBlocked("runtime binary must be an absolute path", [RUNTIME_PATH_DEPENDENCY])
    if candidate.name != expected_names[args.connector]:
        raise SmokeBlocked(
            f"runtime binary does not match connector {args.connector}: {candidate}",
            [RUNTIME_PATH_DEPENDENCY],
        )
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise SmokeBlocked(f"runtime binary is unavailable: {candidate}", [RUNTIME_PATH_DEPENDENCY]) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SmokeBlocked(
            f"runtime binary must be a regular non-symlink file: {candidate}",
            [RUNTIME_PATH_DEPENDENCY],
        )
    if not os.access(candidate, os.X_OK):
        raise SmokeBlocked(f"runtime binary is not executable: {candidate}", [RUNTIME_PATH_DEPENDENCY])
    return candidate


def namespace_value(args: argparse.Namespace, name: str, default: str = "") -> str:
    value = getattr(args, name, default)
    return "" if value is None else str(value)


def normalize_ruleset(value: str) -> str:
    normalized = (value or "targeted").strip().lower()
    if normalized in {"", "targeted", "modsecurity-targeted"}:
        return "targeted"
    if normalized in {"crs", "owasp-crs", "coreruleset"}:
        return "crs"
    raise SmokeBlocked(f"unsupported ModSecurity ruleset: {value}", ["modsecurity ruleset"])


def normalize_modsecurity_smoke_case(value: str) -> str:
    normalized = (value or "targeted").strip().lower().replace("-", "_")
    if normalized in TARGETED_SMOKE_CASES:
        return normalized
    raise SmokeBlocked(f"unsupported ModSecurity smoke case: {value}", ["modsecurity smoke case"])


def normalize_crs_smoke_case(value: str) -> str:
    normalized = (value or "minimal").strip().lower()
    if normalized in CRS_SMOKE_CASES:
        return normalized
    raise SmokeBlocked(f"unsupported CRS smoke case: {value}", ["crs smoke case"])


def crs_blocked_path(args: argparse.Namespace) -> str:
    return str(CRS_SMOKE_CASES[args.crs_smoke_case]["blocked_path"])


def is_crs_block_probe(path: str, smoke_case: str) -> bool:
    decoded = urllib.parse.unquote(path).lower()
    if smoke_case == "minimal":
        return "union" in decoded and "select" in decoded
    if smoke_case == "secondary":
        return "<script>" in decoded and "alert(" in decoded
    return False


def crs_probe_uri(headers: http.client.HTTPMessage, path: str) -> str:
    for header_name in ("x-forwarded-uri", "x-envoy-original-path", "x-original-uri"):
        value = headers.get(header_name)
        if value:
            return configured_smoke_target(value)
    return configured_smoke_target(path)


def crs_version_from_source(source_dir: Path, configured_ref: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(source_dir), "describe", "--tags", "--always", "--dirty"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if completed.returncode == 0 and completed.stdout.strip():
            return completed.stdout.strip()
    except OSError:
        pass
    changes = source_dir / "CHANGES.md"
    if changes.is_file():
        match = re.search(r"^## Version ([^ \n]+)", changes.read_text(encoding="utf-8", errors="replace"), re.M)
        if match:
            return match.group(1)
    return configured_ref


def bracket_value_text(text: str, key: str) -> str:
    match = re.search(rf'\[{re.escape(key)} "([^"]*)"\]', text)
    return match.group(1) if match else ""


def crs_detection_from_audit_log(audit_log_path: Path, fallback_rule_id: str, fallback_message: str) -> tuple[str, str]:
    if not audit_log_path.is_file():
        return fallback_rule_id, fallback_message
    try:
        text = audit_log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return fallback_rule_id, fallback_message
    observed: list[tuple[str, str]] = []
    for line in text.splitlines():
        if "ModSecurity:" not in line:
            continue
        rule_id = bracket_value_text(line, "id")
        message = bracket_value_text(line, "msg")
        if rule_id:
            observed.append((rule_id, message))
    for rule_id, message in observed:
        if not rule_id.startswith("949"):
            return rule_id, message
    if observed:
        return observed[-1]
    return fallback_rule_id, fallback_message


def request_body_smoke_enabled(args: argparse.Namespace) -> bool:
    return (
        args.decision_backend == "libmodsecurity"
        and args.modsecurity_ruleset == "targeted"
        and args.modsecurity_smoke_case == "request_body"
    )


def request_body_headers() -> dict[str, str]:
    return {"Content-Type": REQUEST_BODY_CONTENT_TYPE}


def request_body_evidence(
    decision_backend: SimpleDecisionBackend | ModSecurityDecisionBackend,
) -> tuple[bool, bool, bool]:
    return (
        bool(getattr(decision_backend, "request_body_smoke_verified", False)),
        bool(getattr(decision_backend, "request_body_access_enabled", False)),
        bool(getattr(decision_backend, "request_body_rule_loaded", False)),
    )


def crs_source_candidate_roots(args: argparse.Namespace) -> list[Path]:
    """Return only explicitly selected CRS source candidates.

    Shared temporary locations are intentionally not consulted here. A
    direct caller must supply CRS_SOURCE_DIR or a runtime lookup root that the
    caller already selected for its run.
    """

    roots: list[Path] = []

    def add(path: Path) -> None:
        if path.is_absolute() and str(path) not in {str(existing) for existing in roots}:
            roots.append(path)

    if args.crs_source_dir:
        add(Path(args.crs_source_dir))
    for root_text in args.runtime_lookup_root:
        if not root_text:
            continue
        root = Path(root_text)
        add(root / "src/coreruleset")
        add(root / "coreruleset")
        add(root / "sources/coreruleset")
        add(root / "cache-v2/shared/sources/coreruleset")
    return roots


def is_trusted_crs_owner(path_stat: os.stat_result) -> bool:
    """Return whether the runner or root controls a selected CRS path."""

    return path_stat.st_uid in {os.geteuid(), 0}


def crs_directory_entry_is_protected(
    parent_stat: os.stat_result, child_stat: os.stat_result
) -> bool:
    """Return whether an ancestor prevents a different user replacing its child."""

    if not stat.S_ISDIR(parent_stat.st_mode):
        return False
    parent_mode = stat.S_IMODE(parent_stat.st_mode)
    if parent_mode & (stat.S_IWGRP | stat.S_IWOTH) == 0:
        return True
    return (
        bool(parent_mode & stat.S_ISVTX)
        and is_trusted_crs_owner(parent_stat)
        and is_trusted_crs_owner(child_stat)
    )


def assert_crs_path_has_no_symlink_components(path: Path, label: str) -> Path:
    """Return an absolute existing path after rejecting every symlink component."""

    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            current_stat = current.lstat()
        except OSError as exc:
            raise SmokeBlocked(f"{label} is unavailable: {current}", ["crs"]) from exc
        if stat.S_ISLNK(current_stat.st_mode):
            raise SmokeBlocked(f"{label} must not contain a symlink: {current}", ["crs"])
    return absolute


def assert_crs_path_ancestors_are_safe(path: Path, label: str) -> None:
    """Reject a CRS path replaceable through a different user's writable ancestor."""

    child = path
    while child != child.parent:
        try:
            child_stat = child.lstat()
            parent_stat = child.parent.lstat()
        except OSError as exc:
            raise SmokeBlocked(f"{label} ancestor is unavailable: {child.parent}", ["crs"]) from exc
        if not crs_directory_entry_is_protected(parent_stat, child_stat):
            raise SmokeBlocked(
                f"{label} has an ancestor that permits cross-user replacement: {child.parent}",
                ["crs"],
            )
        child = child.parent


def require_trusted_crs_path(path: Path, label: str, *, directory: bool) -> Path:
    """Require one non-replaceable selected CRS directory or configuration file."""

    if not path.is_absolute():
        raise SmokeBlocked(f"{label} must be absolute: {path}", ["crs"])
    trusted_path = assert_crs_path_has_no_symlink_components(path, label)
    if trusted_path == Path(trusted_path.anchor):
        raise SmokeBlocked(f"{label} is too broad: {trusted_path}", ["crs"])
    try:
        path_stat = trusted_path.lstat()
    except OSError as exc:
        raise SmokeBlocked(f"{label} is unavailable: {trusted_path}", ["crs"]) from exc
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    expected_name = "directory" if directory else "regular file"
    if not expected_type(path_stat.st_mode):
        raise SmokeBlocked(f"{label} must be a {expected_name}: {trusted_path}", ["crs"])
    if not is_trusted_crs_owner(path_stat):
        raise SmokeBlocked(f"{label} must be owned by the runner or root: {trusted_path}", ["crs"])
    if stat.S_IMODE(path_stat.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
        raise SmokeBlocked(f"{label} must not be group or world writable: {trusted_path}", ["crs"])
    assert_crs_path_ancestors_are_safe(trusted_path, label)
    return trusted_path


def require_safe_crs_config_path(path: Path, label: str) -> Path:
    """Reject a filesystem path that would change a quoted ModSecurity directive."""

    value = str(path)
    if any(
        character in value
        for character in ('"', "\\", "\r", "\n", "\0", "*", "?", "[", "]", "{", "}")
    ):
        raise SmokeBlocked(
            f"{label} contains unsupported characters for a ModSecurity directive",
            ["crs"],
        )
    return path


def require_trusted_crs_output_parent(path: Path, label: str) -> Path:
    """Validate an existing directory that may safely receive a runner-owned child."""

    if not path.is_absolute():
        raise SmokeBlocked(f"{label} must be absolute: {path}", ["crs"])
    trusted_path = assert_crs_path_has_no_symlink_components(path, label)
    try:
        path_stat = trusted_path.lstat()
    except OSError as exc:
        raise SmokeBlocked(f"{label} is unavailable: {trusted_path}", ["crs"]) from exc
    if not stat.S_ISDIR(path_stat.st_mode):
        raise SmokeBlocked(f"{label} must be a directory: {trusted_path}", ["crs"])
    if not is_trusted_crs_owner(path_stat):
        raise SmokeBlocked(f"{label} must be owned by the runner or root: {trusted_path}", ["crs"])
    mode = stat.S_IMODE(path_stat.st_mode)
    if mode & (stat.S_IWGRP | stat.S_IWOTH) and not mode & stat.S_ISVTX:
        raise SmokeBlocked(f"{label} must not be group or world writable: {trusted_path}", ["crs"])
    assert_crs_path_ancestors_are_safe(trusted_path, label)
    return trusted_path


def ensure_trusted_crs_output_directory(path: Path, label: str) -> Path:
    """Safely create or validate a private generated-CRS output directory."""

    if not path.is_absolute():
        raise SmokeBlocked(f"{label} must be absolute: {path}", ["crs"])
    absolute = Path(os.path.abspath(path))
    if absolute == Path(absolute.anchor):
        raise SmokeBlocked(f"{label} is too broad: {absolute}", ["crs"])

    missing: list[Path] = []
    current = absolute
    while True:
        try:
            current_stat = current.lstat()
        except FileNotFoundError:
            missing.append(current)
            current = current.parent
            continue
        except OSError as exc:
            raise SmokeBlocked(f"{label} is unavailable: {current}", ["crs"]) from exc
        if stat.S_ISLNK(current_stat.st_mode):
            raise SmokeBlocked(f"{label} must not contain a symlink: {current}", ["crs"])
        break

    if missing:
        require_trusted_crs_output_parent(current, f"{label} parent")
    for missing_directory in reversed(missing):
        try:
            missing_directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise SmokeBlocked(
                f"could not create {label}: {missing_directory}", ["crs"]
            ) from exc
        require_trusted_crs_path(missing_directory, label, directory=True)
    return require_trusted_crs_path(absolute, label, directory=True)


def secure_crs_output_file(path: Path, label: str) -> int:
    """Open one generated CRS artifact without following a stale symlink."""

    parent = require_trusted_crs_path(path.parent, f"{label} parent", directory=True)
    target = parent / path.name
    if target.exists() or target.is_symlink():
        require_trusted_crs_path(target, label, directory=False)
        try:
            target.unlink()
        except OSError as exc:
            raise SmokeBlocked(f"could not replace {label}: {target}", ["crs"]) from exc
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if no_follow == 0:
        raise SmokeBlocked("secure CRS output creation requires O_NOFOLLOW", ["crs"])
    try:
        return os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
            stat.S_IRUSR | stat.S_IWUSR,
        )
    except OSError as exc:
        raise SmokeBlocked(f"could not create {label}: {target}", ["crs"]) from exc


def write_trusted_crs_output(path: Path, label: str, content: str) -> Path:
    """Write one generated text artifact and verify it before later use."""

    descriptor = secure_crs_output_file(path, label)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
    except OSError as exc:
        raise SmokeBlocked(f"could not write {label}: {path}", ["crs"]) from exc
    return require_trusted_crs_path(path, label, directory=False)


def copy_trusted_crs_output(source: Path, destination: Path, label: str) -> Path:
    """Copy a validated source file into a generated CRS artifact safely."""

    descriptor = secure_crs_output_file(destination, label)
    try:
        with (
            os.fdopen(descriptor, "wb") as output_handle,
            source.open("rb") as input_handle,
        ):
            shutil.copyfileobj(input_handle, output_handle)
    except OSError as exc:
        raise SmokeBlocked(f"could not write {label}: {destination}", ["crs"]) from exc
    return require_trusted_crs_path(destination, label, directory=False)


def validate_crs_source_dir(candidate: Path) -> Path:
    """Validate every CRS path that the generated smoke config can include."""

    source_dir = require_trusted_crs_path(candidate, "CRS source directory", directory=True)
    setup_template = require_trusted_crs_path(
        source_dir / CRS_SETUP_TEMPLATE_NAME, "CRS setup template", directory=False
    )
    require_safe_crs_config_path(setup_template, "CRS setup template")
    rules_dir = require_trusted_crs_path(
        source_dir / "rules", "CRS rules directory", directory=True
    )
    require_safe_crs_config_path(rules_dir, "CRS rules directory")
    try:
        rule_files = sorted(path for path in rules_dir.iterdir() if path.name.endswith(".conf"))
    except OSError as exc:
        raise SmokeBlocked(f"CRS rules directory is unavailable: {rules_dir}", ["crs"]) from exc
    if not rule_files:
        raise SmokeBlocked(f"missing CRS rule files: {rules_dir}/*.conf", ["crs"])
    for rule_file in rule_files:
        trusted_rule_file = require_trusted_crs_path(rule_file, "CRS rule file", directory=False)
        require_safe_crs_config_path(trusted_rule_file, "CRS rule file")

    plugins_dir = source_dir / "plugins"
    if plugins_dir.exists() or plugins_dir.is_symlink():
        plugins_dir = require_trusted_crs_path(plugins_dir, "CRS plugins directory", directory=True)
        require_safe_crs_config_path(plugins_dir, "CRS plugins directory")
        plugin_files: list[Path] = []
        for pattern in ("*-config.conf", "*-before.conf", "*-after.conf"):
            plugin_files.extend(plugins_dir.glob(pattern))
        for plugin_file in sorted(set(plugin_files)):
            trusted_plugin_file = require_trusted_crs_path(
                plugin_file, "CRS plugin file", directory=False
            )
            require_safe_crs_config_path(trusted_plugin_file, "CRS plugin file")
    return source_dir


def resolve_crs_source_dir(args: argparse.Namespace) -> Path:
    for candidate in crs_source_candidate_roots(args):
        if (
            candidate.is_dir()
            and (candidate / CRS_SETUP_TEMPLATE_NAME).is_file()
            and (candidate / "rules").is_dir()
        ):
            return validate_crs_source_dir(candidate)
    configured = args.crs_source_dir or "<unset>"
    raise SmokeBlocked(f"missing CRS_SOURCE_DIR: {configured}; run make fetch-crs", ["crs"])


def free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind((LOOPBACK_HOST, 0))
        return int(sock.getsockname()[1])


class QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        return


class UpstreamHandler(QuietHandler):
    def _answer(self) -> None:
        try:
            read_request_body(self)
        except RequestBodyError as exc:
            self.send_error(exc.status_code, "request body rejected")
            return
        body = b"msconnector upstream ok\n"
        self.send_response(200)
        self.send_header("content-type", DEFAULT_TEXT_CONTENT_TYPE)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _answer
    do_POST = _answer
    do_HEAD = _answer


class SimpleDecisionBackend:
    decision_backend = "simple"
    modsecurity_backend_verified = False
    modsecurity_rule_loaded = False
    intervention_status: int | None = None
    last_error: str | None = None
    blocked_decision: dict[str, object] | None = None

    def decide(
        self,
        headers: http.client.HTTPMessage,
        path: str,
        method: str = "GET",
        body: bytes = b"",
    ) -> dict[str, object]:
        del path, method, body
        values = (
            headers.get("x-msconnector-block", ""),
            headers.get("x-modsec-smoke", ""),
        )
        if any(value.lower() in BLOCK_VALUES for value in values):
            return {
                "body": b"blocked by local msconnector decision service\n",
                "status": 403,
            }
        return {
            "body": b"allowed by local msconnector decision service\n",
            "status": 200,
        }


class ModSecurityDecisionBackend:
    decision_backend = "libmodsecurity"

    def __init__(
        self,
        helper: Path,
        rule_file: Path,
        decision_log_path: Path,
        env: dict[str, str],
        ruleset: str,
        crs_smoke_case: str,
        modsecurity_smoke_case: str,
    ) -> None:
        self.helper = helper
        self.rule_file = rule_file
        self.decision_log_path = decision_log_path
        self.env = env
        self.ruleset = ruleset
        self.crs_smoke_case = crs_smoke_case
        self.modsecurity_smoke_case = modsecurity_smoke_case
        self.modsecurity_backend_verified = False
        self.modsecurity_rule_loaded = False
        self.request_body_smoke_verified = False
        self.request_body_access_enabled = False
        self.request_body_rule_loaded = False
        self.intervention_status: int | None = None
        self.last_error: str | None = None
        self.blocked_decision: dict[str, object] | None = None
        self.allowed_decision: dict[str, object] | None = None
        self.crs_rule_id = ""
        self.crs_rule_message = ""

    def _evaluate(self, request: EvaluatorRequest) -> dict[str, object]:
        if self.ruleset == "crs":
            self.rule_file = require_trusted_crs_path(
                self.rule_file, GENERATED_CRS_SMOKE_RULE_LABEL, directory=False
            )
            require_safe_crs_config_path(self.rule_file, GENERATED_CRS_SMOKE_RULE_LABEL)
        command = [
            str(self.helper),
            "--rule-file",
            str(self.rule_file),
            "--decision-log",
            str(self.decision_log_path),
            "--ruleset",
            self.ruleset,
            "--uri",
            request.path,
            "--smoke-case",
            self.modsecurity_smoke_case,
            "--method",
            request.method,
        ]
        if request.header_value:
            command.extend(["--header-value", request.header_value])
        if request.body:
            command.extend(["--body", request.body.decode("utf-8")])
            command.extend(["--content-type", request.content_type])
            command.extend(["--request-body-marker", REQUEST_BODY_BLOCK_MARKER])
        completed = subprocess.run(
            command,
            check=False,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip() or f"exit {completed.returncode}"
            raise RuntimeError(f"libmodsecurity targeted evaluator failed: {detail}")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"libmodsecurity targeted evaluator returned invalid JSON: {completed.stdout}") from exc
        if not payload.get("ok"):
            raise RuntimeError(str(payload.get("error") or "libmodsecurity targeted evaluator failed"))
        return payload

    def _evaluator_request(
        self,
        headers: http.client.HTTPMessage,
        path: str,
        method: str,
        body: bytes,
    ) -> EvaluatorRequest:
        safe_method = require_local_request_method(method)
        if self.ruleset == "crs":
            return EvaluatorRequest("", crs_probe_uri(headers, path), safe_method, b"", "")
        safe_path = configured_smoke_target(path)
        if self.modsecurity_smoke_case == "request_body":
            if body not in {REQUEST_BODY_ALLOW_BODY, REQUEST_BODY_BLOCK_BODY}:
                raise RequestBodyError("unsupported local request-body smoke payload")
            return EvaluatorRequest("", safe_path, safe_method, body, REQUEST_BODY_CONTENT_TYPE)
        header_value = headers.get("x-modsec-smoke", "").lower()
        if header_value not in {"", "block"}:
            raise RequestBodyError("unsupported local targeted-smoke header value")
        return EvaluatorRequest(header_value, safe_path, safe_method, b"", "")

    def _record_evaluation(self, payload: dict[str, object]) -> tuple[bool, int]:
        self.modsecurity_rule_loaded = bool(payload.get("modsecurity_rule_loaded"))
        self.request_body_access_enabled = bool(payload.get("request_body_access_enabled"))
        self.request_body_rule_loaded = bool(payload.get("request_body_rule_loaded"))
        disruptive = bool(payload.get("intervention_disruptive"))
        status = int(payload.get("intervention_status") or (403 if disruptive else 200))
        self.intervention_status = status
        return disruptive, status

    def _crs_response(
        self, payload: dict[str, object], request: EvaluatorRequest, disruptive: bool, status: int
    ) -> dict[str, object]:
        if is_crs_block_probe(request.path, self.crs_smoke_case):
            self.blocked_decision = payload
            self.crs_rule_id = str(payload.get("crs_rule_id") or payload.get("modsecurity_rule_id") or "")
            self.crs_rule_message = str(payload.get("crs_rule_message") or "")
            self.modsecurity_backend_verified = (
                self.modsecurity_rule_loaded
                and disruptive
                and status == 403
                and bool(self.crs_rule_id)
                and self.crs_rule_id != "1000001"
            )
        else:
            self.allowed_decision = payload
        body = b"blocked by libmodsecurity CRS smoke rule\n" if disruptive else b"allowed by libmodsecurity CRS smoke rule\n"
        return {"body": body, "status": status if disruptive else 200}

    def _request_body_response(
        self, payload: dict[str, object], request: EvaluatorRequest, disruptive: bool, status: int
    ) -> dict[str, object]:
        if REQUEST_BODY_BLOCK_MARKER.encode("utf-8") in request.body:
            self.blocked_decision = payload
            self.request_body_smoke_verified = (
                self.request_body_access_enabled
                and self.request_body_rule_loaded
                and disruptive
                and status == 403
                and payload.get("modsecurity_rule_id") == "1000002"
            )
            self.modsecurity_backend_verified = self.request_body_smoke_verified
        else:
            self.allowed_decision = payload
        body = b"blocked by libmodsecurity request body smoke rule\n" if disruptive else b"allowed by libmodsecurity request body smoke rule\n"
        return {"body": body, "status": status if disruptive else 200}

    def _targeted_response(
        self, payload: dict[str, object], request: EvaluatorRequest, disruptive: bool, status: int
    ) -> dict[str, object]:
        if request.header_value == "block":
            self.blocked_decision = payload
            self.modsecurity_backend_verified = (
                self.modsecurity_rule_loaded
                and disruptive
                and status == 403
                and payload.get("modsecurity_rule_id") == "1000001"
            )
        body = b"blocked by libmodsecurity targeted smoke rule\n" if disruptive else b"allowed by libmodsecurity targeted smoke rule\n"
        return {"body": body, "status": status if disruptive else 200}

    def decide(
        self,
        headers: http.client.HTTPMessage,
        path: str,
        method: str = "GET",
        body: bytes = b"",
    ) -> dict[str, object]:
        request = self._evaluator_request(headers, path, method, body)
        payload = self._evaluate(request)
        disruptive, status = self._record_evaluation(payload)
        if self.ruleset == "crs":
            return self._crs_response(payload, request, disruptive, status)
        if self.modsecurity_smoke_case == "request_body":
            return self._request_body_response(payload, request, disruptive, status)
        return self._targeted_response(payload, request, disruptive, status)


def read_request_bytes(handler: http.server.BaseHTTPRequestHandler, size: int) -> bytes:
    try:
        value = handler.rfile.read(size)
    except OSError as exc:
        raise RequestBodyError("timed out reading request body") from exc
    if len(value) != size:
        raise RequestBodyError("incomplete request body")
    return value


def read_request_line(handler: http.server.BaseHTTPRequestHandler) -> bytes:
    try:
        value = handler.rfile.readline(MAX_CHUNK_LINE_BYTES + 1)
    except OSError as exc:
        raise RequestBodyError("timed out reading request body") from exc
    if not value or len(value) > MAX_CHUNK_LINE_BYTES or not value.endswith(b"\n"):
        raise RequestBodyError("invalid chunk framing")
    return value


def parse_chunk_size(line: bytes) -> int:
    size_text = line.split(b";", 1)[0].strip()
    if re.fullmatch(rb"[0-9A-Fa-f]+", size_text) is None:
        raise RequestBodyError("invalid chunk size")
    return int(size_text, 16)


def ensure_chunk_fits_request_limit(size: int, body_size: int) -> None:
    if size > MAX_REQUEST_BODY_BYTES - body_size:
        raise RequestBodyTooLarge("request body exceeds local smoke limit")


def read_chunked_trailers(handler: http.server.BaseHTTPRequestHandler) -> None:
    trailer_bytes = 0
    while True:
        trailer = read_request_line(handler)
        trailer_bytes += len(trailer)
        if trailer_bytes > MAX_TRAILER_BYTES:
            raise RequestBodyError("request trailers exceed local smoke limit")
        if trailer in {b"\r\n", b"\n"}:
            return


def read_chunk_data(handler: http.server.BaseHTTPRequestHandler, size: int) -> bytes:
    chunk = read_request_bytes(handler, size)
    if read_request_bytes(handler, 2) != b"\r\n":
        raise RequestBodyError("invalid chunk terminator")
    return chunk


def read_chunked_request_body(handler: http.server.BaseHTTPRequestHandler) -> bytes:
    body = bytearray()
    while True:
        size = parse_chunk_size(read_request_line(handler))
        ensure_chunk_fits_request_limit(size, len(body))
        if size == 0:
            read_chunked_trailers(handler)
            return bytes(body)
        body.extend(read_chunk_data(handler, size))


def read_content_length_request_body(handler: http.server.BaseHTTPRequestHandler) -> bytes:
    raw_length = handler.headers.get("content-length")
    if raw_length is None:
        return b""
    value = raw_length.strip()
    if re.fullmatch(r"\d+", value, flags=re.ASCII) is None:
        raise RequestBodyError("invalid content length")
    length = int(value, 10)
    if length > MAX_REQUEST_BODY_BYTES:
        raise RequestBodyTooLarge("request body exceeds local smoke limit")
    return read_request_bytes(handler, length)


def read_request_body(handler: http.server.BaseHTTPRequestHandler) -> bytes:
    transfer_encodings = handler.headers.get_all("transfer-encoding", [])
    content_lengths = handler.headers.get_all("content-length", [])
    if len(transfer_encodings) > 1:
        raise RequestBodyError("duplicate transfer encoding")
    if len(content_lengths) > 1:
        raise RequestBodyError("duplicate content length")
    raw_transfer_encoding = transfer_encodings[0] if transfer_encodings else None
    raw_content_length = content_lengths[0] if content_lengths else None
    if raw_transfer_encoding is not None and raw_content_length is not None:
        raise RequestBodyError("conflicting request body framing")
    transfer_encoding = (raw_transfer_encoding or "").strip().lower()
    if transfer_encoding:
        if transfer_encoding != "chunked":
            raise RequestBodyError("unsupported transfer encoding")
        return read_chunked_request_body(handler)
    return read_content_length_request_body(handler)


def make_decision_handler(
    decision_backend: SimpleDecisionBackend | ModSecurityDecisionBackend,
    transcript_path: Path | None = None,
) -> type[QuietHandler]:
    class RuntimeDecisionHandler(QuietHandler):
        def _answer(self) -> None:
            request_target = ""
            request_method = ""
            try:
                request_target = configured_smoke_target(self.path)
                request_method = require_local_request_method(self.command)
                request_body = read_request_body(self)
                decision = decision_backend.decide(
                    self.headers, request_target, request_method, request_body
                )
                status = int(decision["status"])
                body = decision["body"]
            except RequestBodyError as exc:
                decision_backend.last_error = str(exc)
                status = exc.status_code
                body = b"local smoke request body rejected\n"
                request_body = b""
            except Exception as exc:  # noqa: BLE001 - auth backend errors become smoke evidence.
                decision_backend.last_error = str(exc)
                status = 500
                body = f"decision backend error: {exc}\n".encode("utf-8")
                request_body = b""
            if transcript_path is not None:
                append_jsonl(
                    transcript_path,
                    {
                        "blocked_body_marker_present": REQUEST_BODY_BLOCK_MARKER.encode("utf-8") in request_body,
                        "body_length": len(request_body),
                        "content_length": self.headers.get("content-length"),
                        "decision_backend": decision_backend.decision_backend,
                        "method": request_method,
                        "path": request_target,
                        "response_status": status,
                        "transfer_encoding": self.headers.get("transfer-encoding"),
                    },
                )
            self.send_response(status)
            self.send_header("content-type", DEFAULT_TEXT_CONTENT_TYPE)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = _answer
        do_POST = _answer
        do_HEAD = _answer

    return RuntimeDecisionHandler


def append_jsonl(path: Path, record: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True))
        handle.write("\n")


def make_sidecar_proxy_handler(
    decision_backend: SimpleDecisionBackend | ModSecurityDecisionBackend,
    upstream_port: int,
    transcript_path: Path,
) -> type[QuietHandler]:
    class LighttpdSidecarProxyHandler(QuietHandler):
        def _answer(self) -> None:
            decision_status = 500
            upstream_status: int | None = None
            forwarded = False
            request_body = b""
            request_target = ""
            request_method = ""
            try:
                request_target = configured_smoke_target(self.path)
                request_method = require_local_request_method(self.command)
                request_body = read_request_body(self)
                decision = decision_backend.decide(
                    self.headers, request_target, request_method, request_body
                )
                decision_status = int(decision["status"])
                if decision_status >= 400:
                    body = decision["body"]
                    status = decision_status
                else:
                    forwarded = True
                    url = local_smoke_url(upstream_port, request_target)
                    forward_headers = {
                        key: value
                        for key, value in self.headers.items()
                        if key.lower() not in {"connection", "host", "proxy-connection"}
                    }
                    data = request_body if request_method not in {"GET", "HEAD"} else None
                    request = urllib.request.Request(
                        url, data=data, headers=forward_headers, method=request_method
                    )
                    try:
                        with urllib.request.urlopen(request, timeout=2) as response:
                            body = response.read()
                            status = int(response.status)
                    except urllib.error.HTTPError as exc:
                        body = exc.read()
                        status = int(exc.code)
                    upstream_status = status
            except RequestBodyError as exc:
                decision_backend.last_error = str(exc)
                body = b"local smoke request body rejected\n"
                status = exc.status_code
            except Exception as exc:  # noqa: BLE001 - proxy errors become smoke evidence.
                decision_backend.last_error = str(exc)
                body = f"sidecar proxy error: {exc}\n".encode("utf-8")
                status = 500

            append_jsonl(
                transcript_path,
                {
                    "blocked_body_marker_present": REQUEST_BODY_BLOCK_MARKER.encode("utf-8") in request_body,
                    "body_length": len(request_body),
                    "content_length": self.headers.get("content-length"),
                    "decision_backend": decision_backend.decision_backend,
                    "decision_status": decision_status,
                    "forwarded_to_lighttpd": forwarded,
                    "method": request_method,
                    "path": request_target,
                    "response_status": status,
                    "transfer_encoding": self.headers.get("transfer-encoding"),
                    "upstream_status": upstream_status,
                },
            )
            self.send_response(status)
            self.send_header("content-type", DEFAULT_TEXT_CONTENT_TYPE)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = _answer
        do_POST = _answer
        do_HEAD = _answer

    return LighttpdSidecarProxyHandler


class LocalSmokeHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        request, client_address = super().get_request()
        request.settimeout(SERVER_SOCKET_TIMEOUT_SECONDS)
        return request, client_address


def start_http_server(handler: type[http.server.BaseHTTPRequestHandler], port: int) -> LocalSmokeHTTPServer:
    server = LocalSmokeHTTPServer((LOOPBACK_HOST, require_loopback_port(port, allow_ephemeral=True)), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def http_status(
    url: str,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    data: bytes | None = None,
) -> int:
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            response.read()
            return int(response.status)
    except urllib.error.HTTPError as exc:
        exc.read()
        return int(exc.code)


def wait_for_proxy(url: str, process: subprocess.Popen[object], deadline: float, expected_status: int = 200) -> None:
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited early with code {process.returncode}")
        try:
            status = http_status(url)
            if status == expected_status:
                return
            last_error = RuntimeError(f"proxy returned {status}, expected {expected_status}")
        except Exception as exc:  # noqa: BLE001 - startup probes may fail many ways.
            last_error = exc
        time.sleep(0.2)
    raise RuntimeError(f"proxy did not become ready: {last_error}")


def wait_for_http_url(
    url: str,
    deadline: float,
    expected_status: int = 200,
    process: subprocess.Popen[object] | None = None,
    label: str = "service",
) -> None:
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"{label} exited early with code {process.returncode}")
        try:
            status = http_status(url)
            if status == expected_status:
                return
            last_error = RuntimeError(f"{label} returned {status}, expected {expected_status}")
        except Exception as exc:  # noqa: BLE001 - startup probes may fail many ways.
            last_error = exc
        time.sleep(0.2)
    raise RuntimeError(f"{label} did not become ready: {last_error}")


def local_library_env(base_env: dict[str, str], lib_dir: Path, runtime_lookup_roots: list[str]) -> dict[str, str]:
    env = dict(base_env)
    paths = [str(lib_dir)]
    for candidate in (
        lib_dir.parent.parent.parent / "expat/lib",
        lib_dir.parent.parent.parent / "pcre2/lib",
        lib_dir.parent.parent.parent / "yajl/lib",
    ):
        if candidate.is_dir():
            paths.append(str(candidate))
    for root_text in runtime_lookup_roots:
        root = Path(root_text)
        for candidate in (
            root / "prefix/expat/lib",
            root / "cache-v2/shared/prefix/expat/lib",
            root / "expat/lib",
        ):
            if candidate.is_dir():
                paths.append(str(candidate))
    existing = env.get("LD_LIBRARY_PATH", "")
    if existing:
        paths.append(existing)
    env["LD_LIBRARY_PATH"] = os.pathsep.join(dict.fromkeys(paths))
    return env


def prepare_crs_smoke_config(args: argparse.Namespace, log_dir: Path) -> tuple[Path, Path, str]:
    source_dir = resolve_crs_source_dir(args)
    args.effective_crs_source_dir = str(source_dir)
    setup_template = source_dir / CRS_SETUP_TEMPLATE_NAME
    rules_dir = source_dir / "rules"
    if not setup_template.is_file():
        raise SmokeBlocked(f"missing CRS setup template: {setup_template}", ["crs"])
    if not rules_dir.is_dir():
        raise SmokeBlocked(f"missing CRS rules directory: {rules_dir}", ["crs"])
    rule_files = sorted(rules_dir.glob("*.conf"))
    if not rule_files:
        raise SmokeBlocked(f"missing CRS rule files: {rules_dir}/*.conf", ["crs"])

    smoke_label = "crs-smoke" if args.crs_smoke_case == "minimal" else "crs-secondary-smoke"
    evidence_root = require_safe_crs_config_path(Path(args.evidence_root), "CRS evidence root")
    evidence_root = ensure_trusted_crs_output_directory(evidence_root, "CRS evidence root")
    runtime_dir = ensure_trusted_crs_output_directory(
        evidence_root / smoke_label, "CRS smoke runtime directory"
    )
    crs_setup = copy_trusted_crs_output(
        setup_template, runtime_dir / "crs-setup.conf", "generated CRS setup file"
    )
    require_safe_crs_config_path(crs_setup, "generated CRS setup file")

    audit_log_name = "crs-audit.log" if args.crs_smoke_case == "minimal" else "crs-secondary-audit.log"
    log_dir = require_safe_crs_config_path(log_dir, "CRS audit-log directory")
    log_dir = ensure_trusted_crs_output_directory(log_dir, "CRS audit-log directory")
    audit_log_path = write_trusted_crs_output(
        log_dir / audit_log_name, "generated CRS audit log", ""
    )
    require_safe_crs_config_path(audit_log_path, "generated CRS audit log")
    args.effective_audit_log_path = str(audit_log_path)
    if args.crs_smoke_case == "minimal":
        rule_file_name = "modsecurity-crs-smoke.conf"
    else:
        rule_file_name = "modsecurity-crs-secondary-smoke.conf"
    rule_file = runtime_dir / rule_file_name
    lines = [
        f"# Generated by run_local_runtime_smoke.py for the {args.crs_smoke_case} CRS smoke.",
        "SecRuleEngine On",
        "SecRequestBodyAccess On",
        "SecResponseBodyAccess Off",
        "SecAuditEngine RelevantOnly",
        "SecAuditLogType Serial",
        f'SecAuditLog "{audit_log_path}"',
        f'Include "{crs_setup}"',
    ]
    plugins_dir = source_dir / "plugins"
    if plugins_dir.is_dir():
        lines.extend(
            [
                f'Include "{plugins_dir}/*-config.conf"',
                f'Include "{plugins_dir}/*-before.conf"',
            ]
        )
    lines.append(f'Include "{rules_dir}/*.conf"')
    if plugins_dir.is_dir():
        lines.append(f'Include "{plugins_dir}/*-after.conf"')
    rule_file = write_trusted_crs_output(
        rule_file,
        GENERATED_CRS_SMOKE_RULE_LABEL,
        "\n".join(lines) + "\n",
    )
    require_safe_crs_config_path(rule_file, GENERATED_CRS_SMOKE_RULE_LABEL)

    version = crs_version_from_source(source_dir, args.crs_git_ref)
    payload_name = "crs-smoke-payload.txt" if args.crs_smoke_case == "minimal" else "crs-secondary-smoke-payload.txt"
    write_trusted_crs_output(
        log_dir / payload_name,
        "CRS smoke payload evidence",
        "\n".join(
            [
                "allowed_path=/allowed",
                f"blocked_path={crs_blocked_path(args)}",
                f"crs_smoke_case={args.crs_smoke_case}",
                f"crs_smoke_description={CRS_SMOKE_CASES[args.crs_smoke_case]['description']}",
                f"crs_source_dir={source_dir}",
                f"crs_runtime_dir={runtime_dir}",
                f"crs_git_ref={args.crs_git_ref}",
                f"crs_version={version}",
                f"audit_log_path={audit_log_path}",
            ]
        )
        + "\n",
    )
    return rule_file, runtime_dir, version


def system_cxx_compiler() -> Path:
    """Locate the fixed C++17 compiler without accepting shell-style options."""

    candidate = shutil.which("c++") or shutil.which("g++")
    if not candidate:
        raise RuntimeError("missing C++ compiler for libmodsecurity smoke evaluator")
    try:
        compiler = Path(candidate).resolve(strict=True)
    except OSError as exc:
        raise RuntimeError(f"C++ compiler cannot be resolved: {candidate}") from exc
    try:
        metadata = compiler.lstat()
    except OSError as exc:
        raise RuntimeError(f"C++ compiler is unavailable: {compiler}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError(f"C++ compiler must be a regular file: {compiler}")
    if not os.access(compiler, os.X_OK):
        raise RuntimeError(f"C++ compiler is not executable: {compiler}")
    return compiler


@dataclass(frozen=True)
class ModSecurityEvaluatorInputs:
    """Trusted local inputs used to build the fixed smoke evaluator."""

    include_dir: Path
    lib_dir: Path
    lib_file: Path
    rule_file: Path


def require_trusted_evaluator_path(value: Path, label: str, *, directory: bool) -> Path:
    """Resolve one private, regular evaluator input before compiler use."""

    if not value.is_absolute():
        raise SmokeBlocked(f"{label} must be absolute: {value}", ["libmodsecurity"])
    try:
        parent = assert_crs_path_has_no_symlink_components(value.parent, f"{label} parent")
        resolved = value.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SmokeBlocked(f"{label} is unavailable: {value}", ["libmodsecurity"]) from exc
    try:
        resolved.relative_to(parent)
    except ValueError as exc:
        raise SmokeBlocked(
            f"{label} must remain below its selected parent: {value}", ["libmodsecurity"]
        ) from exc
    return require_trusted_crs_path(resolved, label, directory=directory)


def prepare_modsecurity_evaluator_inputs(args: argparse.Namespace) -> ModSecurityEvaluatorInputs:
    """Validate all CLI-controlled compiler and linker inputs before execution."""

    include_dir_text = namespace_value(args, "modsecurity_include_dir")
    lib_dir_text = namespace_value(args, "modsecurity_lib_dir")
    lib_file_text = namespace_value(args, "modsecurity_lib_file")
    rule_file_text = namespace_value(
        args, "effective_modsecurity_rule_file", args.modsecurity_rule_file
    )
    if not include_dir_text or not lib_dir_text or not lib_file_text or not rule_file_text:
        raise RuntimeError(
            "local libmodsecurity include dir, lib dir, lib file, and rule file are required"
        )
    if any(character in lib_dir_text for character in (",", "\r", "\n", "\0")):
        raise SmokeBlocked(
            "libmodsecurity library directory contains a linker separator", ["libmodsecurity"]
        )

    include_dir = require_trusted_evaluator_path(
        Path(include_dir_text), "libmodsecurity include directory", directory=True
    )
    lib_dir = require_trusted_evaluator_path(
        Path(lib_dir_text), "libmodsecurity library directory", directory=True
    )
    lib_file = require_trusted_evaluator_path(
        Path(lib_file_text), "libmodsecurity shared library", directory=False
    )
    rule_file = require_trusted_evaluator_path(
        Path(rule_file_text), "ModSecurity smoke rule", directory=False
    )
    try:
        lib_file.relative_to(lib_dir)
    except ValueError as exc:
        raise SmokeBlocked(
            "libmodsecurity shared library must be inside its selected library directory",
            ["libmodsecurity"],
        ) from exc
    for header in ("modsecurity.h", "rules_set.h", "transaction.h"):
        require_trusted_evaluator_path(
            include_dir / "modsecurity" / header, f"libmodsecurity {header}", directory=False
        )
    if args.modsecurity_ruleset == "crs":
        require_safe_crs_config_path(rule_file, GENERATED_CRS_SMOKE_RULE_LABEL)
    return ModSecurityEvaluatorInputs(include_dir, lib_dir, lib_file, rule_file)


def build_modsecurity_evaluator(
    args: argparse.Namespace, runtime_paths: RuntimeOutputPaths
) -> tuple[Path, dict[str, str]]:
    inputs = prepare_modsecurity_evaluator_inputs(args)

    cxx = system_cxx_compiler()
    source = source_path('common/scripts/modsecurity_targeted_eval.cc', root=_CONNECTOR_ROOT)
    if not source.is_file():
        raise RuntimeError(f"modsecurity evaluator source missing: {source}")

    build_dir = runtime_paths.tmp_root / f"{args.connector}-modsecurity-{args.modsecurity_ruleset}-smoke"
    build_dir.mkdir(parents=True, exist_ok=True)
    output = build_dir / "modsecurity_targeted_eval"
    command = [
        str(cxx),
        "-std=c++17",
        "-I",
        str(inputs.include_dir),
        str(source),
        str(inputs.lib_file),
        f"-Wl,-rpath,{inputs.lib_dir}",
        "-o",
        str(output),
    ]
    (runtime_paths.log_dir / "modsecurity-evaluator-build-command.txt").write_text(
        " ".join(command) + "\n", encoding="utf-8"
    )
    completed = subprocess.run(
        command,
        check=False,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    (runtime_paths.log_dir / "modsecurity-evaluator-build.stdout.log").write_text(
        completed.stdout, encoding="utf-8"
    )
    (runtime_paths.log_dir / "modsecurity-evaluator-build.stderr.log").write_text(
        completed.stderr, encoding="utf-8"
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or f"exit {completed.returncode}"
        raise RuntimeError(f"could not build libmodsecurity evaluator: {detail}")
    output.chmod(0o755)
    env = local_library_env(os.environ, inputs.lib_dir, args.runtime_lookup_root)
    return output, env


def envoy_config(listen_port: int, admin_port: int, upstream_port: int, auth_port: int) -> str:
    return f"""static_resources:
  listeners:
  - name: listener_0
    address:
      socket_address:
        address: 127.0.0.1
        port_value: {listen_port}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match:
                  prefix: "/"
                route:
                  cluster: upstream_service
          http_filters:
          - name: envoy.filters.http.ext_authz
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
              http_service:
                server_uri:
                  uri: http://127.0.0.1:{auth_port}
                  cluster: ext_authz
                  timeout: 0.5s
                path_prefix: /auth
                authorization_request:
                  allowed_headers:
                    patterns:
                    - exact: content-length
                    - exact: content-type
                    - exact: x-msconnector-block
                    - exact: x-modsec-smoke
              with_request_body:
                max_request_bytes: 4096
                allow_partial_message: false
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
  - name: upstream_service
    connect_timeout: 0.25s
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: upstream_service
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: {upstream_port}
  - name: ext_authz
    connect_timeout: 0.25s
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: ext_authz
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: {auth_port}
admin:
  access_log_path: /dev/null
  address:
    socket_address:
      address: 127.0.0.1
      port_value: {admin_port}
"""


def traefik_dynamic_config(upstream_port: int, auth_port: int) -> str:
    return f"""http:
  routers:
    msconnector:
      entryPoints:
      - web
      rule: PathPrefix(`/`)
      middlewares:
      - msconnector-auth
      service: upstream
  middlewares:
    msconnector-auth:
      forwardAuth:
        address: http://127.0.0.1:{auth_port}/auth
        trustForwardHeader: true
        authRequestHeaders:
        - Content-Length
        - Content-Type
        - X-Msconnector-Block
        - X-Modsec-Smoke
        forwardBody: true
        maxBodySize: 4096
        preserveRequestMethod: true
  services:
    upstream:
      loadBalancer:
        servers:
        - url: http://127.0.0.1:{upstream_port}
"""


def lighttpd_escape(value: Path | str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def lighttpd_config(
    document_root: Path,
    upload_root: Path,
    error_log_path: Path,
    pid_path: Path,
    upstream_port: int,
) -> str:
    return f"""server.document-root = "{lighttpd_escape(document_root)}"
server.bind = "127.0.0.1"
server.port = {upstream_port}
server.errorlog = "{lighttpd_escape(error_log_path)}"
server.pid-file = "{lighttpd_escape(pid_path)}"
server.upload-dirs = ( "{lighttpd_escape(upload_root)}" )
index-file.names = ( "index.txt" )
mimetype.assign = ( ".txt" => "text/plain" )
"""


def build_proxy_command(connector: str, binary: Path, work_dir: Path, listen_port: int, upstream_port: int, auth_port: int) -> list[str]:
    if connector == "envoy":
        admin_port = free_port()
        config_path = work_dir / "envoy.yaml"
        config_path.write_text(envoy_config(listen_port, admin_port, upstream_port, auth_port), encoding="utf-8")
        return [
            str(binary),
            "-c",
            str(config_path),
            "--base-id",
            str((listen_port + admin_port) % 100000),
            "--disable-hot-restart",
            "--log-level",
            "error",
        ]

    if connector == "traefik":
        dynamic_path = work_dir / "traefik-dynamic.yml"
        dynamic_path.write_text(traefik_dynamic_config(upstream_port, auth_port), encoding="utf-8")
        return [
            str(binary),
            "--entryPoints.web.address=127.0.0.1:%d" % listen_port,
            "--providers.file.filename=%s" % dynamic_path,
            "--providers.file.watch=false",
            "--api=false",
            "--log.level=ERROR",
            "--global.sendAnonymousUsage=false",
        ]

    raise ValueError(f"unsupported connector for local runtime smoke: {connector}")


def smoke_writer_values(args: argparse.Namespace, result: SmokeResult) -> SmokeWriterValues:
    """Derive writer values without mixing them into command construction."""

    effective_rule_file = namespace_value(args, "effective_modsecurity_rule_file", args.modsecurity_rule_file)
    effective_crs_runtime_dir = namespace_value(args, "effective_crs_runtime_dir", args.crs_runtime_dir)
    effective_crs_source_dir = namespace_value(args, "effective_crs_source_dir", args.crs_source_dir)
    crs_version = namespace_value(args, "effective_crs_version", "")
    modsecurity_enabled = args.decision_backend == "libmodsecurity"
    request_body_enabled = modsecurity_enabled and args.modsecurity_smoke_case == "request_body"
    if not modsecurity_enabled:
        return SmokeWriterValues(
            effective_rule_file,
            effective_crs_runtime_dir,
            effective_crs_source_dir,
            crs_version,
            "",
            "",
            args.crs_smoke_case if args.modsecurity_ruleset == "crs" else "",
            "",
            "",
            "",
            "",
            "",
        )

    if args.modsecurity_ruleset == "crs":
        modsecurity_rule_id = result.crs_rule_id
    elif request_body_enabled:
        modsecurity_rule_id = "1000002"
    else:
        modsecurity_rule_id = "1000001"
    return SmokeWriterValues(
        effective_rule_file,
        effective_crs_runtime_dir,
        effective_crs_source_dir,
        crs_version,
        args.modsecurity_ruleset,
        args.modsecurity_smoke_case,
        args.crs_smoke_case if args.modsecurity_ruleset == "crs" else "",
        modsecurity_rule_id,
        effective_rule_file if request_body_enabled else "",
        "1000002" if request_body_enabled else "",
        "POST" if request_body_enabled else "",
        REQUEST_BODY_BLOCK_MARKER if request_body_enabled else "",
    )


def writer_flag(value: bool) -> str:
    return "true" if value else "false"


def writer_status(value: int | None) -> str:
    return str(value) if value is not None else "not-run"


def writer_args(args: argparse.Namespace, result: SmokeResult) -> list[str]:
    values = smoke_writer_values(args, result)
    command = [
        "--connector",
        args.connector,
        "--integration-mode",
        args.integration_mode,
        "--status",
        result.status,
        "--exit-code",
        str(result.exit_code),
        "--runtime-verified",
        writer_flag(result.runtime_verified),
        "--response-body-verified",
        "false",
        "--allowed-request-status",
        writer_status(result.allowed),
        "--blocked-request-status",
        writer_status(result.blocked),
        "--decision-backend",
        args.decision_backend,
        "--modsecurity-ruleset",
        values.modsecurity_ruleset,
        "--modsecurity-smoke-case",
        values.modsecurity_smoke_case,
        "--crs-smoke-case",
        values.crs_smoke_case,
        "--modsecurity-backend-verified",
        writer_flag(result.modsecurity_backend_verified),
        "--modsecurity-rule-file",
        values.effective_rule_file,
        "--modsecurity-rule-id",
        values.modsecurity_rule_id,
        "--modsecurity-rule-loaded",
        writer_flag(result.modsecurity_rule_loaded),
        "--request-body-smoke-verified",
        writer_flag(result.request_body_smoke_verified),
        "--request-body-access-enabled",
        writer_flag(result.request_body_access_enabled),
        "--request-body-rule-file",
        values.request_body_rule_file,
        "--request-body-rule-id",
        values.request_body_rule_id,
        "--request-body-rule-loaded",
        writer_flag(result.request_body_rule_loaded),
        "--request-method",
        values.request_method,
        "--blocked-body-marker",
        values.blocked_body_marker,
        "--intervention-status",
        writer_status(result.intervention_status),
        "--audit-log-path",
        result.audit_log_path,
        "--decision-log-path",
        result.decision_log_path,
        "--lighttpd-binary-verified",
        writer_flag(result.lighttpd_binary_verified),
        "--lighttpd-http-verified",
        writer_flag(result.lighttpd_http_verified),
        "--sidecar-proxy-verified",
        writer_flag(result.sidecar_proxy_verified),
        "--lighttpd-log-path",
        result.lighttpd_log_path,
        "--upstream-log-path",
        result.upstream_log_path,
        "--request-transcript-path",
        result.request_transcript_path,
        "--modsecurity-include-dir",
        args.modsecurity_include_dir,
        "--modsecurity-lib-dir",
        args.modsecurity_lib_dir,
        "--modsecurity-lib-file",
        args.modsecurity_lib_file,
        "--modsecurity-pkg-config-path",
        args.modsecurity_pkg_config_path,
        "--modsecurity-prefix",
        args.modsecurity_prefix,
        "--modsecurity-manifest",
        args.modsecurity_manifest,
        "--evidence-root",
        args.evidence_root,
        "--results-dir",
        args.results_dir,
        "--connector-root",
        args.connector_root,
        "--source-root",
        args.source_root,
        "--build-root",
        args.build_root,
        "--tmp-root",
        args.tmp_root,
        "--log-root",
        args.log_root,
        "--log-dir",
        args.log_dir,
        "--harness-path",
        args.harness_path,
        "--skipped-reason",
        result.skipped_reason,
        "--resolved-runtime-binary",
        args.resolved_runtime_binary,
        "--runtime-binary-env-var",
        args.runtime_binary_env_var,
        "--runtime-binary-name",
        args.runtime_binary_name,
        "--architecture-decision",
        args.architecture_decision,
        "--crs-repo-url",
        args.crs_repo_url,
        "--crs-git-ref",
        args.crs_git_ref,
        "--crs-source-dir",
        values.effective_crs_source_dir,
        "--crs-runtime-dir",
        values.effective_crs_runtime_dir,
        "--crs-version",
        values.crs_version,
        "--crs-minimal-smoke-verified",
        writer_flag(result.crs_minimal_smoke_verified),
        "--crs-secondary-smoke-verified",
        writer_flag(result.crs_secondary_smoke_verified),
        "--crs-rule-id",
        result.crs_rule_id,
        "--crs-rule-message",
        result.crs_rule_message,
    ]
    for dependency in result.missing:
        command.extend(["--missing-dependency", dependency])
    for root in args.runtime_lookup_root:
        command.extend(["--runtime-lookup-root", root])
    return command


def write_result(args: argparse.Namespace, result: SmokeResult) -> None:
    exit_code = write_smoke_result_main(writer_args(args, result))
    if exit_code != 0:
        raise RuntimeError(f"runtime-smoke result writer failed with exit code {exit_code}")


@dataclass(frozen=True)
class LighttpdArtifacts:
    """Private files belonging to one lighttpd sidecar smoke execution."""

    work_dir: Path
    log_dir: Path
    document_root: Path
    upload_root: Path
    lighttpd_log_path: Path
    upstream_log_path: Path
    request_transcript_path: Path
    stdout_path: Path
    stderr_path: Path
    config_path: Path
    pid_path: Path
    version_path: Path
    command_path: Path


@dataclass(frozen=True)
class LighttpdProbe:
    """Observed status values from the loopback upstream and sidecar probes."""

    direct_status: int | None
    allowed_status: int | None
    blocked_status: int | None
    lighttpd_http_verified: bool


def runtime_artifact_path(
    runtime_paths: RuntimeOutputPaths, root: Path, name: str, label: str
) -> Path:
    """Return a fixed-name artifact path under an already verified runtime root."""

    return require_verified_runtime_output_path(
        str(root / name), label, runtime_paths.runtime_root
    )


def lighttpd_artifact_namespace(args: argparse.Namespace) -> str:
    """Return the validated scenario namespace used for lighttpd evidence."""

    if args.modsecurity_ruleset == "crs":
        return f"crs-{args.crs_smoke_case}"
    return args.modsecurity_smoke_case


def lighttpd_artifacts(
    args: argparse.Namespace, runtime_paths: RuntimeOutputPaths
) -> LighttpdArtifacts:
    namespace = lighttpd_artifact_namespace(args)
    work_dir = runtime_artifact_path(
        runtime_paths, runtime_paths.config_root, f"lighttpd-{namespace}", "CONFIG_ROOT"
    )
    log_dir = runtime_artifact_path(
        runtime_paths, runtime_paths.log_dir, f"lighttpd-{namespace}", "LOG_DIR"
    )
    return LighttpdArtifacts(
        work_dir=work_dir,
        log_dir=log_dir,
        document_root=runtime_artifact_path(runtime_paths, work_dir, "docroot", "CONFIG_ROOT"),
        upload_root=runtime_artifact_path(runtime_paths, work_dir, "upload", "CONFIG_ROOT"),
        lighttpd_log_path=runtime_artifact_path(runtime_paths, log_dir, "lighttpd-error.log", "LOG_DIR"),
        upstream_log_path=runtime_artifact_path(runtime_paths, log_dir, "lighttpd-upstream.log", "LOG_DIR"),
        request_transcript_path=runtime_artifact_path(runtime_paths, log_dir, "request-transcript.jsonl", "LOG_DIR"),
        stdout_path=runtime_artifact_path(runtime_paths, log_dir, "lighttpd.stdout.log", "LOG_DIR"),
        stderr_path=runtime_artifact_path(runtime_paths, log_dir, "lighttpd.stderr.log", "LOG_DIR"),
        config_path=runtime_artifact_path(runtime_paths, work_dir, "lighttpd.conf", "CONFIG_ROOT"),
        pid_path=runtime_artifact_path(runtime_paths, work_dir, "lighttpd.pid", "CONFIG_ROOT"),
        version_path=runtime_artifact_path(runtime_paths, log_dir, "lighttpd-version.txt", "LOG_DIR"),
        command_path=runtime_artifact_path(runtime_paths, work_dir, "lighttpd-command.txt", "CONFIG_ROOT"),
    )


def prepare_lighttpd_artifacts(
    artifacts: LighttpdArtifacts,
    binary: Path,
    upstream_port: int,
    listen_port: int,
    decision_log_path: Path | None,
) -> bool:
    """Create only private runner artifacts before the local process starts."""

    artifacts.work_dir.mkdir(parents=True, exist_ok=True)
    artifacts.log_dir.mkdir(parents=True, exist_ok=True)
    artifacts.document_root.mkdir(parents=True, exist_ok=True)
    artifacts.upload_root.mkdir(parents=True, exist_ok=True)
    (artifacts.document_root / "index.txt").write_text(
        "msconnector lighttpd upstream ok\n", encoding="utf-8"
    )
    (artifacts.document_root / "allowed").write_text(
        "msconnector lighttpd upstream allowed\n", encoding="utf-8"
    )
    for stale_path in (
        artifacts.lighttpd_log_path,
        artifacts.upstream_log_path,
        artifacts.request_transcript_path,
        decision_log_path,
    ):
        if stale_path is not None and stale_path.exists():
            stale_path.unlink()
    version_completed = subprocess.run(
        [str(binary), "-v"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    version_output = (version_completed.stdout + version_completed.stderr).strip()
    artifacts.version_path.write_text(version_output + "\n", encoding="utf-8")
    if version_completed.returncode != 0:
        raise RuntimeError(f"lighttpd -v failed with code {version_completed.returncode}: {version_output}")
    artifacts.config_path.write_text(
        lighttpd_config(
            artifacts.document_root,
            artifacts.upload_root,
            artifacts.lighttpd_log_path,
            artifacts.pid_path,
            upstream_port,
        ),
        encoding="utf-8",
    )
    command = [str(binary), "-D", "-f", str(artifacts.config_path)]
    artifacts.command_path.write_text(" ".join(command) + "\n", encoding="utf-8")
    artifacts.upstream_log_path.write_text(
        "\n".join(
            (
                f"lighttpd_binary={binary}",
                f"lighttpd_config={artifacts.config_path}",
                f"lighttpd_upstream_port={upstream_port}",
                f"sidecar_listen_port={listen_port}",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    return True


def lighttpd_probe_request(args: argparse.Namespace) -> tuple[int, str, dict[str, str], str, bytes | None]:
    if request_body_smoke_enabled(args):
        return 200, DEFAULT_BLOCKED_PATH, request_body_headers(), "POST", REQUEST_BODY_BLOCK_BODY
    if args.modsecurity_ruleset == "crs":
        return 200, crs_blocked_path(args), {}, "GET", None
    return 200, DEFAULT_BLOCKED_PATH, {"X-Modsec-Smoke": "block"}, "GET", None


def run_lighttpd_probes(
    args: argparse.Namespace,
    artifacts: LighttpdArtifacts,
    decision_backend: SimpleDecisionBackend | ModSecurityDecisionBackend,
    binary: Path,
    upstream_port: int,
    listen_port: int,
) -> tuple[subprocess.Popen[object], http.server.ThreadingHTTPServer, LighttpdProbe]:
    command = [str(binary), "-D", "-f", str(artifacts.config_path)]
    process: subprocess.Popen[object] | None = None
    sidecar_server: http.server.ThreadingHTTPServer | None = None
    try:
        with artifacts.stdout_path.open("wb") as stdout, artifacts.stderr_path.open("wb") as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
            direct_url = local_smoke_url(upstream_port, DEFAULT_ALLOWED_PATH)
            wait_for_http_url(direct_url, time.monotonic() + 12, process=process, label="lighttpd")
            direct_status = http_status(direct_url)
            sidecar_server = start_http_server(
                make_sidecar_proxy_handler(
                    decision_backend, upstream_port, artifacts.request_transcript_path
                ),
                listen_port,
            )
            sidecar_url = local_smoke_url(listen_port, DEFAULT_ALLOWED_PATH)
            wait_for_http_url(sidecar_url, time.monotonic() + 8, label="lighttpd sidecar proxy")
            allowed_status, blocked_path, blocked_headers, blocked_method, blocked_body = lighttpd_probe_request(args)
            if request_body_smoke_enabled(args):
                allowed_status = http_status(
                    sidecar_url,
                    request_body_headers(),
                    method="POST",
                    data=REQUEST_BODY_ALLOW_BODY,
                )
            else:
                allowed_status = http_status(sidecar_url)
            blocked_status = http_status(
                local_smoke_url(listen_port, blocked_path),
                blocked_headers,
                method=blocked_method,
                data=blocked_body,
            )
        if process is None or sidecar_server is None:
            raise RuntimeError("lighttpd process startup did not return a running sidecar")
        return process, sidecar_server, LighttpdProbe(
            direct_status,
            allowed_status,
            blocked_status,
            direct_status == 200,
        )
    except Exception:
        stop_server(sidecar_server)
        stop_process(process)
        raise


def lighttpd_result_context(
    artifacts: LighttpdArtifacts,
    decision_log_path: Path | None,
    binary_verified: bool,
    probe: LighttpdProbe | None,
    sidecar_proxy_verified: bool,
    args: argparse.Namespace,
) -> dict[str, object]:
    return {
        "decision_log_path": str(decision_log_path) if decision_log_path is not None else "",
        "audit_log_path": namespace_value(args, "effective_audit_log_path", ""),
        "lighttpd_binary_verified": binary_verified,
        "lighttpd_http_verified": probe.lighttpd_http_verified if probe is not None else False,
        "sidecar_proxy_verified": sidecar_proxy_verified,
        "lighttpd_log_path": str(artifacts.lighttpd_log_path),
        "upstream_log_path": str(artifacts.upstream_log_path),
        "request_transcript_path": str(artifacts.request_transcript_path),
    }


def lighttpd_evidence(args: argparse.Namespace, decision_backend: object, sidecar_verified: bool) -> BackendEvidence:
    evidence = collect_backend_evidence(decision_backend)
    if args.modsecurity_ruleset == "crs" and args.crs_smoke_case == "secondary":
        crs_rule_id, crs_rule_message = crs_detection_from_audit_log(
            Path(namespace_value(args, "effective_audit_log_path", "")),
            evidence.crs_rule_id,
            evidence.crs_rule_message,
        )
        evidence = backend_evidence_with_crs_rules(evidence, crs_rule_id, crs_rule_message)
    crs_verified = (
        args.modsecurity_ruleset == "crs"
        and sidecar_verified
        and evidence.modsecurity_backend_verified
        and bool(evidence.crs_rule_id)
    )
    return backend_evidence_with_crs_verification(
        evidence,
        crs_verified and args.crs_smoke_case == "minimal",
        crs_verified and args.crs_smoke_case == "secondary",
    )


def lighttpd_outcome(
    args: argparse.Namespace,
    decision_backend: SimpleDecisionBackend | ModSecurityDecisionBackend,
    artifacts: LighttpdArtifacts,
    decision_log_path: Path | None,
    binary_verified: bool,
    probe: LighttpdProbe,
    evidence: BackendEvidence,
) -> int:
    sidecar_verified = probe.lighttpd_http_verified and probe.allowed_status == 200 and probe.blocked_status == 403
    context = lighttpd_result_context(
        artifacts, decision_log_path, binary_verified, probe, sidecar_verified, args
    )
    with artifacts.upstream_log_path.open("a", encoding="utf-8") as handle:
        handle.write(f"direct_upstream_status={probe.direct_status}\n")
        handle.write(f"allowed_sidecar_status={probe.allowed_status}\n")
        handle.write(f"blocked_sidecar_status={probe.blocked_status}\n")
        handle.write(f"lighttpd_http_verified={str(probe.lighttpd_http_verified).lower()}\n")
        handle.write(f"sidecar_proxy_verified={str(sidecar_verified).lower()}\n")
    verified = sidecar_verified
    if args.decision_backend == "libmodsecurity":
        verified = verified and evidence.modsecurity_backend_verified
    if args.modsecurity_ruleset == "crs":
        verified = verified and bool(evidence.crs_rule_id)
    if verified:
        write_result(args, smoke_result("PASS", 0, True, probe.allowed_status, probe.blocked_status, evidence, context=context))
        return 0
    backend_error = getattr(decision_backend, "last_error", None)
    reason = "lighttpd sidecar_proxy smoke did not produce expected direct 200 and sidecar 200/403 statuses"
    missing: tuple[str, ...] = ()
    if args.decision_backend == "libmodsecurity" and not evidence.modsecurity_backend_verified:
        reason = "lighttpd libmodsecurity smoke did not verify a rule-backed 403 intervention"
        missing = ("libmodsecurity",) if backend_error else ()
    if backend_error:
        reason = f"{reason}: {backend_error}"
    write_result(
        args,
        smoke_result(
            "BLOCKED", 77, False, probe.allowed_status, probe.blocked_status, evidence,
            skipped_reason=reason, missing=missing, context=context,
        ),
    )
    return 77


def run_lighttpd_sidecar_smoke(
    args: argparse.Namespace,
    runtime_paths: RuntimeOutputPaths,
    binary: Path,
    decision_backend: SimpleDecisionBackend | ModSecurityDecisionBackend,
    decision_log_path: Path | None,
) -> int:
    upstream_port = selected_loopback_port(args.upstream_port)
    listen_port = selected_loopback_port(args.listen_port)
    artifacts = lighttpd_artifacts(args, runtime_paths)
    binary_verified = False
    probe: LighttpdProbe | None = None
    process: subprocess.Popen[object] | None = None
    sidecar_server: http.server.ThreadingHTTPServer | None = None
    try:
        binary_verified = prepare_lighttpd_artifacts(
            artifacts, binary, upstream_port, listen_port, decision_log_path
        )
        process, sidecar_server, probe = run_lighttpd_probes(
            args, artifacts, decision_backend, binary, upstream_port, listen_port
        )
        sidecar_verified = probe.lighttpd_http_verified and probe.allowed_status == 200 and probe.blocked_status == 403
        evidence = lighttpd_evidence(args, decision_backend, sidecar_verified)
        return lighttpd_outcome(
            args, decision_backend, artifacts, decision_log_path,
            binary_verified, probe, evidence
        )
    except Exception as exc:  # noqa: BLE001 - runtime startup failures become blocked evidence.
        evidence = collect_backend_evidence(decision_backend)
        context = lighttpd_result_context(artifacts, decision_log_path, binary_verified, probe, False, args)
        write_result(
            args,
            smoke_result(
                "BLOCKED", 77, False, probe.allowed_status if probe else None, probe.blocked_status if probe else None, evidence,
                skipped_reason=f"lighttpd sidecar_proxy smoke could not be completed: {exc}",
                missing=(args.runtime_binary_name,),
                context=context,
            ),
        )
        return 77
    finally:
        if sidecar_server is not None:
            sidecar_server.shutdown()
            sidecar_server.server_close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


@dataclass(frozen=True)
class ProxyArtifacts:
    """Private resources for one Envoy or Traefik loopback smoke."""

    work_dir: Path
    log_dir: Path
    stdout_path: Path
    stderr_path: Path
    request_transcript_path: Path


@dataclass(frozen=True)
class ProxyProbe:
    """The two HTTP results that prove the local proxy decision contract."""

    allowed_status: int | None
    blocked_status: int | None


def normalize_smoke_options(args: argparse.Namespace, runtime_paths: RuntimeOutputPaths) -> RuntimeOutputPaths:
    args.modsecurity_ruleset = normalize_ruleset(args.modsecurity_ruleset)
    args.modsecurity_smoke_case = normalize_modsecurity_smoke_case(args.modsecurity_smoke_case)
    args.crs_smoke_case = normalize_crs_smoke_case(args.crs_smoke_case)
    if args.modsecurity_ruleset != "crs":
        return runtime_paths
    args.modsecurity_smoke_case = "targeted"
    suffix = "crs-smoke" if args.crs_smoke_case == "minimal" else "crs-secondary-smoke"
    config_root = require_verified_runtime_output_path(
        str(runtime_paths.config_root / suffix), "CONFIG_ROOT", runtime_paths.runtime_root
    )
    args.config_root = str(config_root)
    return RuntimeOutputPaths(
        runtime_paths.runtime_root,
        runtime_paths.evidence_root,
        runtime_paths.results_dir,
        runtime_paths.tmp_root,
        runtime_paths.log_root,
        runtime_paths.log_dir,
        config_root,
    )


def smoke_decision_log_path(args: argparse.Namespace, log_dir: Path) -> Path | None:
    if args.decision_backend != "libmodsecurity":
        return None
    if args.modsecurity_ruleset == "crs":
        name = "crs-secondary-decision.log" if args.crs_smoke_case == "secondary" else "crs-decision.log"
    elif request_body_smoke_enabled(args):
        name = "request-body-decision.log"
    else:
        name = "modsecurity-decision.log"
    return log_dir / name


def set_modsecurity_smoke_inputs(args: argparse.Namespace, log_dir: Path) -> None:
    if args.modsecurity_ruleset != "crs":
        args.effective_modsecurity_rule_file = args.modsecurity_rule_file
        args.effective_crs_runtime_dir = args.crs_runtime_dir
        args.effective_crs_version = ""
        return
    rule_file, crs_runtime_dir, crs_version = prepare_crs_smoke_config(args, log_dir)
    args.effective_modsecurity_rule_file = str(rule_file)
    args.effective_crs_runtime_dir = str(crs_runtime_dir)
    args.effective_crs_version = crs_version


def prepare_decision_backend(
    args: argparse.Namespace,
    runtime_paths: RuntimeOutputPaths,
    decision_log_path: Path | None,
) -> SimpleDecisionBackend | ModSecurityDecisionBackend:
    if args.modsecurity_ruleset == "crs" and args.decision_backend != "libmodsecurity":
        raise SmokeBlocked("CRS smoke requires DECISION_BACKEND=libmodsecurity", ["libmodsecurity"])
    if args.decision_backend != "libmodsecurity":
        return SimpleDecisionBackend()
    set_modsecurity_smoke_inputs(args, runtime_paths.log_dir)
    if decision_log_path is not None and decision_log_path.exists() and args.connector != "lighttpd":
        decision_log_path.unlink()
    helper, helper_env = build_modsecurity_evaluator(args, runtime_paths)
    return ModSecurityDecisionBackend(
        helper,
        Path(args.effective_modsecurity_rule_file),
        decision_log_path if decision_log_path is not None else runtime_paths.log_dir / "modsecurity-decision.log",
        helper_env,
        args.modsecurity_ruleset,
        args.crs_smoke_case,
        args.modsecurity_smoke_case,
    )


def proxy_artifacts(args: argparse.Namespace, runtime_paths: RuntimeOutputPaths) -> ProxyArtifacts:
    return ProxyArtifacts(
        work_dir=runtime_paths.config_root,
        log_dir=runtime_paths.log_dir,
        stdout_path=runtime_paths.log_dir / f"{args.connector}.stdout.log",
        stderr_path=runtime_paths.log_dir / f"{args.connector}.stderr.log",
        request_transcript_path=runtime_paths.log_dir / "request-body-request-transcript.jsonl",
    )


def proxy_probe_request(args: argparse.Namespace) -> tuple[dict[str, str], str, str, bytes | None, bool]:
    if request_body_smoke_enabled(args):
        return request_body_headers(), DEFAULT_BLOCKED_PATH, "POST", REQUEST_BODY_BLOCK_BODY, True
    if args.decision_backend == "libmodsecurity" and args.modsecurity_ruleset == "crs":
        return {}, crs_blocked_path(args), "GET", None, False
    if args.decision_backend == "libmodsecurity":
        return {"X-Modsec-Smoke": "block"}, DEFAULT_BLOCKED_PATH, "GET", None, False
    return {"X-Msconnector-Block": "1"}, DEFAULT_BLOCKED_PATH, "GET", None, False


def run_proxy_probes(
    args: argparse.Namespace,
    artifacts: ProxyArtifacts,
    binary: Path,
    decision_backend: SimpleDecisionBackend | ModSecurityDecisionBackend,
    upstream_port: int,
    auth_port: int,
    listen_port: int,
) -> tuple[
    subprocess.Popen[object],
    http.server.ThreadingHTTPServer,
    http.server.ThreadingHTTPServer,
    ProxyProbe,
]:
    artifacts.work_dir.mkdir(parents=True, exist_ok=True)
    artifacts.log_dir.mkdir(parents=True, exist_ok=True)
    headers, blocked_path, blocked_method, blocked_body, request_body_enabled = proxy_probe_request(args)
    if request_body_enabled and artifacts.request_transcript_path.exists():
        artifacts.request_transcript_path.unlink()
    process: subprocess.Popen[object] | None = None
    upstream_server: http.server.ThreadingHTTPServer | None = None
    auth_server: http.server.ThreadingHTTPServer | None = None
    try:
        upstream_server = start_http_server(UpstreamHandler, upstream_port)
        auth_server = start_http_server(
            make_decision_handler(
                decision_backend, artifacts.request_transcript_path if request_body_enabled else None
            ),
            auth_port,
        )
        command = build_proxy_command(
            args.connector, binary, artifacts.work_dir, listen_port, upstream_port, auth_port
        )
        (artifacts.work_dir / "proxy-command.txt").write_text(
            " ".join(command) + "\n", encoding="utf-8"
        )
        with artifacts.stdout_path.open("wb") as stdout, artifacts.stderr_path.open("wb") as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
            allowed_url = local_smoke_url(listen_port, DEFAULT_ALLOWED_PATH)
            wait_for_proxy(allowed_url, process, time.monotonic() + 12)
            if request_body_enabled:
                allowed_status = http_status(
                    allowed_url, request_body_headers(), method="POST", data=REQUEST_BODY_ALLOW_BODY
                )
            else:
                allowed_status = http_status(allowed_url)
            blocked_status = http_status(
                local_smoke_url(listen_port, blocked_path),
                headers,
                method=blocked_method,
                data=blocked_body,
            )
        if process is None or upstream_server is None or auth_server is None:
            raise RuntimeError("proxy smoke startup did not return all local resources")
        return process, upstream_server, auth_server, ProxyProbe(allowed_status, blocked_status)
    except Exception:
        stop_process(process)
        stop_server(upstream_server)
        stop_server(auth_server)
        raise


def proxy_evidence(args: argparse.Namespace, decision_backend: object, probe: ProxyProbe) -> BackendEvidence:
    evidence = collect_backend_evidence(decision_backend)
    if args.modsecurity_ruleset == "crs" and args.crs_smoke_case == "secondary":
        crs_rule_id, crs_rule_message = crs_detection_from_audit_log(
            Path(namespace_value(args, "effective_audit_log_path", "")),
            evidence.crs_rule_id,
            evidence.crs_rule_message,
        )
        evidence = backend_evidence_with_crs_rules(evidence, crs_rule_id, crs_rule_message)
    crs_verified = (
        args.modsecurity_ruleset == "crs"
        and probe.allowed_status == 200
        and probe.blocked_status == 403
        and evidence.modsecurity_backend_verified
        and bool(evidence.crs_rule_id)
    )
    return backend_evidence_with_crs_verification(
        evidence,
        crs_verified and args.crs_smoke_case == "minimal",
        crs_verified and args.crs_smoke_case == "secondary",
    )


def proxy_result_context(
    args: argparse.Namespace, decision_log_path: Path | None, request_transcript_path: Path
) -> dict[str, object]:
    return {
        "decision_log_path": str(decision_log_path) if decision_log_path is not None else "",
        "audit_log_path": namespace_value(args, "effective_audit_log_path", ""),
        "request_transcript_path": (
            str(request_transcript_path) if request_body_smoke_enabled(args) else ""
        ),
    }


def proxy_outcome(
    args: argparse.Namespace,
    decision_backend: object,
    decision_log_path: Path | None,
    artifacts: ProxyArtifacts,
    probe: ProxyProbe,
    evidence: BackendEvidence,
) -> int:
    context = proxy_result_context(args, decision_log_path, artifacts.request_transcript_path)
    verified = probe.allowed_status == 200 and probe.blocked_status == 403
    if args.decision_backend == "libmodsecurity":
        verified = verified and evidence.modsecurity_backend_verified
    if args.modsecurity_ruleset == "crs":
        verified = verified and bool(evidence.crs_rule_id)
    if verified:
        write_result(args, smoke_result("PASS", 0, True, probe.allowed_status, probe.blocked_status, evidence, context=context))
        return 0
    backend_error = getattr(decision_backend, "last_error", None)
    reason = f"{args.connector} local runtime smoke did not produce expected 200/403 statuses"
    missing: tuple[str, ...] = ()
    if args.decision_backend == "libmodsecurity" and not evidence.modsecurity_backend_verified:
        reason = f"{args.connector} libmodsecurity smoke did not verify a rule-backed 403 intervention"
        missing = ("libmodsecurity",) if backend_error else ()
    if backend_error:
        reason = f"{reason}: {backend_error}"
    write_result(
        args,
        smoke_result(
            "BLOCKED", 77, False, probe.allowed_status, probe.blocked_status, evidence,
            skipped_reason=reason, missing=missing, context=context,
        ),
    )
    return 77


def stop_process(process: subprocess.Popen[object] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def stop_server(server: http.server.ThreadingHTTPServer | None) -> None:
    if server is not None:
        server.shutdown()
        server.server_close()


def run_proxy_smoke(
    args: argparse.Namespace,
    runtime_paths: RuntimeOutputPaths,
    binary: Path,
    decision_backend: SimpleDecisionBackend | ModSecurityDecisionBackend,
    decision_log_path: Path | None,
) -> int:
    artifacts = proxy_artifacts(args, runtime_paths)
    process: subprocess.Popen[object] | None = None
    upstream_server: http.server.ThreadingHTTPServer | None = None
    auth_server: http.server.ThreadingHTTPServer | None = None
    probe: ProxyProbe | None = None
    try:
        process, upstream_server, auth_server, probe = run_proxy_probes(
            args,
            artifacts,
            binary,
            decision_backend,
            selected_loopback_port(args.upstream_port),
            selected_loopback_port(args.authz_port),
            selected_loopback_port(args.listen_port),
        )
        return proxy_outcome(
            args,
            decision_backend,
            decision_log_path,
            artifacts,
            probe,
            proxy_evidence(args, decision_backend, probe),
        )
    except Exception as exc:  # noqa: BLE001 - runtime startup failures become blocked evidence.
        context = proxy_result_context(args, decision_log_path, artifacts.request_transcript_path)
        write_result(
            args,
            smoke_result(
                "BLOCKED",
                77,
                False,
                probe.allowed_status if probe else None,
                probe.blocked_status if probe else None,
                collect_backend_evidence(decision_backend),
                skipped_reason=f"{args.connector} local runtime smoke could not be completed: {exc}",
                missing=(args.runtime_binary_name,),
                context=context,
            ),
        )
        return 77
    finally:
        stop_process(process)
        stop_server(upstream_server)
        stop_server(auth_server)


def run_smoke(args: argparse.Namespace) -> int:
    try:
        runtime_output_paths = validate_runtime_output_paths(args)
    except SmokeBlocked as exc:
        print(f"BLOCKED runtime output path: {exc.reason}", file=sys.stderr)
        return 77
    try:
        runtime_output_paths = normalize_smoke_options(args, runtime_output_paths)
    except SmokeBlocked as exc:
        if exc.missing_dependencies == [RUNTIME_PATH_DEPENDENCY]:
            print(f"BLOCKED runtime output path: {exc.reason}", file=sys.stderr)
            return 77
        write_result(
            args,
            SmokeResult(
                "BLOCKED",
                77,
                False,
                None,
                None,
                skipped_reason=exc.reason,
                missing=tuple(exc.missing_dependencies),
            ),
        )
        return 77
    try:
        binary = require_runtime_binary(args)
    except SmokeBlocked as exc:
        write_result(
            args,
            SmokeResult(
                "BLOCKED",
                77,
                False,
                None,
                None,
                skipped_reason=exc.reason,
                missing=tuple(exc.missing_dependencies),
            ),
        )
        return 77
    decision_log_path = smoke_decision_log_path(args, runtime_output_paths.log_dir)
    try:
        decision_backend = prepare_decision_backend(args, runtime_output_paths, decision_log_path)
    except SmokeBlocked as exc:
        write_result(
            args,
            SmokeResult(
                "BLOCKED",
                77,
                False,
                None,
                None,
                skipped_reason=exc.reason,
                missing=tuple(exc.missing_dependencies),
                decision_log_path=str(decision_log_path) if decision_log_path is not None else "",
            ),
        )
        return 77
    except Exception as exc:  # noqa: BLE001 - dependency/build gaps become blocked evidence.
        missing_dependency = "crs" if args.modsecurity_ruleset == "crs" and "CRS" in str(exc) else "libmodsecurity"
        write_result(
            args,
            SmokeResult(
                "BLOCKED",
                77,
                False,
                None,
                None,
                skipped_reason=f"{args.connector} libmodsecurity decision backend could not be prepared: {exc}",
                missing=(missing_dependency,),
                decision_log_path=str(decision_log_path) if decision_log_path is not None else "",
            ),
        )
        return 77

    if args.connector == "lighttpd":
        return run_lighttpd_sidecar_smoke(
            args, runtime_output_paths, binary, decision_backend, decision_log_path
        )
    return run_proxy_smoke(
        args, runtime_output_paths, binary, decision_backend, decision_log_path
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector", required=True, choices=["envoy", "traefik", "lighttpd"])
    parser.add_argument("--integration-mode", required=True)
    parser.add_argument("--resolved-runtime-binary", required=True)
    parser.add_argument("--runtime-binary-env-var", required=True)
    parser.add_argument("--runtime-binary-name", required=True)
    parser.add_argument("--runtime-lookup-root", action="append", default=[])
    parser.add_argument("--evidence-root", required=True)
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--connector-root", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--build-root", required=True)
    parser.add_argument("--tmp-root", required=True)
    parser.add_argument("--log-root", required=True)
    parser.add_argument("--log-dir", required=True)
    parser.add_argument("--config-root", required=True)
    parser.add_argument("--listen-port", type=int, default=0)
    parser.add_argument("--upstream-port", type=int, default=0)
    parser.add_argument("--authz-port", type=int, default=0)
    parser.add_argument("--harness-path", required=True)
    parser.add_argument("--architecture-decision", default="")
    parser.add_argument("--decision-backend", choices=["simple", "libmodsecurity"], default="simple")
    parser.add_argument("--modsecurity-ruleset", default=os.environ.get("MODSECURITY_RULESET", "targeted"))
    parser.add_argument("--modsecurity-smoke-case", default=os.environ.get("MODSECURITY_SMOKE_CASE", "targeted"))
    parser.add_argument("--crs-smoke-case", default=os.environ.get("CRS_SMOKE_CASE", "minimal"))
    parser.add_argument("--modsecurity-rule-file", default="")
    parser.add_argument("--modsecurity-include-dir", default="")
    parser.add_argument("--modsecurity-lib-dir", default="")
    parser.add_argument("--modsecurity-lib-file", default="")
    parser.add_argument("--modsecurity-pkg-config-path", default="")
    parser.add_argument("--modsecurity-prefix", default="")
    parser.add_argument("--modsecurity-manifest", default="")
    parser.add_argument("--crs-repo-url", default=os.environ.get("CRS_REPO_URL", ""))
    parser.add_argument("--crs-git-ref", default=os.environ.get("CRS_GIT_REF", ""))
    parser.add_argument("--crs-source-dir", default=os.environ.get("CRS_SOURCE_DIR", ""))
    parser.add_argument("--crs-runtime-dir", default=os.environ.get("CRS_RUNTIME_DIR", ""))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return run_smoke(args)


if __name__ == "__main__":
    raise SystemExit(main())
