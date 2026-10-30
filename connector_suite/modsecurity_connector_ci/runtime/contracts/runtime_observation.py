#!/usr/bin/env python3
"""Strict, connector-neutral runtime-observation contract.

This module deliberately separates contract validation from connector host
execution.  A connector producer must provide structured, live evidence; a
successful command or workflow step is never converted into a runtime PASS by
this validator.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


SCHEMA_VERSION = 1
MAX_OBSERVATION_BYTES = 1024 * 1024
MAX_EVIDENCE_FILES = 32
MAX_TEXT_LENGTH = 1024
MAX_COUNTER = 1_000_000
MAX_EXPECTATION_DEPTH = 4
MAX_COMPOUND_CONDITIONS = 16
MAX_EXPECTATION_ITEMS = 128
MAX_METADATA_DEPTH = 32
MAX_METADATA_NODES = 4096

CONNECTORS = frozenset(("apache", "envoy", "haproxy", "lighttpd", "traefik", "nginx"))
PROFILES = frozenset(
    (
        "no-crs-no-mrts",
        "no-crs-with-mrts",
        "with-crs-no-mrts",
        "with-crs-with-mrts",
    )
)
EXPECTATION_KINDS = frozenset(
    (
        "http_status",
        "intervention",
        "action",
        "rule_match",
        "event",
        "request_headers",
        "response_headers",
        "request_body",
        "response_body",
        "transport",
        "lifecycle",
        "cleanup",
        "compound",
        "not_applicable",
    )
)
ASSERTION_RESULTS = frozenset(("PASS", "FAIL", "NOT_APPLICABLE", "NOT_EXECUTED"))
FRAMEWORK_CASE_RESULTS = frozenset(
    ("PASS", "FAIL", "CANCELLED", "UNSUPPORTED", "NOT_APPLICABLE", "NOT_EXECUTED")
)
RUNTIME_STATUSES = frozenset(("PASS", "PARTIAL", "VALIDATION_FAILED", "FAIL"))
VALIDATION_STATUSES = frozenset(("CONTRACT_VALIDATED", "VALIDATION_FAILED", "PARTIAL"))
FRAMEWORK_SELECTION_STATUSES = frozenset(("SELECTED", "NONE_SELECTED"))
FRAMEWORK_EXECUTION_STATUSES = frozenset(("RUN", "NOT_RUN"))
LIVE_EVIDENCE_KINDS = frozenset(
    (
        "structured_connector_evidence",
        "live_runtime_evidence",
        "protected_runtime_evidence",
    )
)
CANONICAL_EVIDENCE_KINDS = LIVE_EVIDENCE_KINDS | frozenset(("canonical_fixture",))
RAW_EVIDENCE_KINDS = frozenset(("raw_log", "raw_payload", "synthetic", "step_exit"))
CANONICAL_EVIDENCE_RECORD_KINDS = LIVE_EVIDENCE_KINDS | frozenset(
    ("canonical_fixture", "manifest")
)
CONTRACT_VALIDATED = "CONTRACT_VALIDATED"
VALIDATION_FAILED = "VALIDATION_FAILED"
PARTIAL = "PARTIAL"
NOT_APPLICABLE = "NOT_APPLICABLE"
RUNTIME_OBSERVATION_LABEL = "runtime observation"

PRODUCER_VERSION = "1.0.0"

TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", re.ASCII)
FRAMEWORK_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.:/-]{0,127}$", re.ASCII)
SHA256 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
COMMIT = re.compile(r"^[0-9a-f]{40}$", re.ASCII)
TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$", re.ASCII
)
WINDOWS_ABSOLUTE_PATH = re.compile(r"^[A-Za-z]:[\\/]", re.ASCII)

RUNTIME_REQUIRED_ASSERTIONS = (
    "config_test",
    "host_start",
    "reachability",
    "allow_case",
    "block_case",
)
RUNTIME_OPTIONAL_ASSERTIONS = frozenset(("bypass_case",))
ISOLATION_FIELDS = (
    "mrts_runner_invoked",
    "mrts_inventory_loaded",
    "mrts_process_started",
    "mrts_listener_created",
    "mrts_artifact_used",
)
CLEANUP_COUNTERS = (
    "host_processes_remaining",
    "helper_processes_remaining",
    "listeners_remaining",
    "sockets_remaining",
    "pid_files_remaining",
    "temporary_paths_remaining",
)
SEMANTIC_VALUE_FIELDS = frozenset(
    (
        "kind",
        "value",
        "http_status",
        "action",
        "intervention",
        "event",
        "transport",
        "rule_ids",
        "intervention_rule_ids",
        "predicates",
        "status",
        "started",
        "reachable",
    )
)

FRAMEWORK_ACTIONS = frozenset(
    ("deny", "pass", "none", "redirect", "block", "drop", "abort_connection", "log_only")
)
FRAMEWORK_BODY_STATES = frozenset(
    ("observed", "matched", "buffered", "streaming", "incremental", "absent", "redacted")
)
FRAMEWORK_TRANSPORT_STATES = frozenset(
    (
        "connection_aborted",
        "stream_reset",
        "http1",
        "http2",
        "http3",
        "keep_alive",
        "first_byte_before_response_end",
        "no_full_response_buffering",
    )
)
FRAMEWORK_CLEANUP_STATES = frozenset(("balanced", "completed", "reused", "isolated"))
FRAMEWORK_NOT_APPLICABLE_REASONS = frozenset(
    (
        "unsupported_by_host_model",
        "not_implemented",
        "connector_gap",
        "future_target",
        "runtime_difference",
    )
)
FRAMEWORK_LIFECYCLE_PREDICATES = frozenset(
    (
        "host_started",
        "request_completed",
        "response_committed",
        "connection_reused",
        "transaction_isolated",
        "client_aborted",
        "upstream_aborted",
        "cleanup_balanced",
    )
)


def _profile_requirement(crs: bool, mrts: bool) -> dict[str, Any]:
    return {
        "crs": crs,
        "mrts": mrts,
        "requires_mrts": mrts,
        "required_runtime_assertions": RUNTIME_REQUIRED_ASSERTIONS,
        "optional_runtime_assertions": RUNTIME_OPTIONAL_ASSERTIONS,
        "require_framework_live_execution": True,
        "isolation": dict.fromkeys(ISOLATION_FIELDS, mrts),
        "require_clean_cleanup": True,
    }


PROFILE_REQUIREMENTS: dict[str, dict[str, Any]] = {
    "no-crs-no-mrts": _profile_requirement(False, False),
    "no-crs-with-mrts": _profile_requirement(False, True),
    "with-crs-no-mrts": _profile_requirement(True, False),
    "with-crs-with-mrts": _profile_requirement(True, True),
}


class ObservationInputError(ValueError):
    """Raised when an observation file cannot be safely ingested."""


RuntimeObservationError = ObservationInputError


class ValidationResult(dict[str, Any]):
    """Mapping result with compatibility attributes for direct callers."""

    @property
    def status(self) -> str:
        return str(self["status"])

    @property
    def errors(self) -> list[str]:
        return list(self["errors"])

    @property
    def valid(self) -> bool:
        return self["status"] == "PASS"


@dataclass(frozen=True)
class AdapterInterface:
    """Finite connector adapter interface; it never provides a fallback producer."""

    connector: str
    adapter_id: str
    integration_mode: str
    live_producer_supported: bool
    producer: str | None = None
    fixture_producer: str | None = None
    protected_separate: bool = False


ADAPTER_INTERFACES = {
    ("apache", "apache-native-httpd-module", "native-httpd-module"): AdapterInterface(
        "apache",
        "apache-native-httpd-module",
        "native-httpd-module",
        False,
        fixture_producer="canonical-runtime-fixture-apache-native-httpd-module",
    ),
    ("envoy", "envoy-ext-proc-service", "ext_proc"): AdapterInterface(
        "envoy",
        "envoy-ext-proc-service",
        "ext_proc",
        True,
        producer="parent-runtime-observation-adapter-envoy",
    ),
    ("haproxy", "haproxy-spoe-spop-agent", "spoe-spop-agent"): AdapterInterface(
        "haproxy",
        "haproxy-spoe-spop-agent",
        "spoe-spop-agent",
        False,
        fixture_producer="canonical-runtime-fixture-haproxy-spoe-spop-agent",
    ),
    ("haproxy", "haproxy-native-htx-filter", "native-htx-filter"): AdapterInterface(
        "haproxy",
        "haproxy-native-htx-filter",
        "native-htx-filter",
        False,
        fixture_producer="canonical-runtime-fixture-haproxy-native-htx-filter",
    ),
    ("lighttpd", "lighttpd-patched-native-module", "patched-native-lighttpd"): AdapterInterface(
        "lighttpd",
        "lighttpd-patched-native-module",
        "patched-native-lighttpd",
        True,
        producer="parent-runtime-observation-adapter-lighttpd",
    ),
    ("traefik", "traefik-native-middleware", "native-traefik-middleware"): AdapterInterface(
        "traefik",
        "traefik-native-middleware",
        "native-traefik-middleware",
        True,
        producer="parent-runtime-observation-adapter-traefik",
    ),
    # Existing Parent full-lifecycle records identify the NGINX adapter and
    # integration mode as native-nginx-http-module.  Its protected producer
    # boundary is intentionally separate from that identity tuple.
    ("nginx", "native-nginx-http-module", "native-nginx-http-module"): AdapterInterface(
        "nginx",
        "native-nginx-http-module",
        "native-nginx-http-module",
        False,
        producer="protected-nginx-root-broker",
        protected_separate=True,
    ),
}

ADAPTER_CATALOG = frozenset(ADAPTER_INTERFACES)
CONNECTOR_INTEGRATION_MODES = {
    connector: integration_mode
    for connector, adapter_id, integration_mode in ADAPTER_CATALOG
    if sum(1 for item in ADAPTER_CATALOG if item[0] == connector) == 1
}
DEFAULT_ADAPTER_IDS = {
    connector: adapter_id
    for connector, adapter_id, integration_mode in ADAPTER_CATALOG
    if sum(1 for item in ADAPTER_CATALOG if item[0] == connector) == 1
}


def adapter_for(
    connector: str,
    adapter_id: str | None = None,
    integration_mode: str | None = None,
) -> AdapterInterface:
    """Return one closed adapter identity, never a connector-wide fallback."""
    candidates = [
        adapter
        for (candidate_connector, candidate_id, candidate_mode), adapter in ADAPTER_INTERFACES.items()
        if candidate_connector == connector
        and (adapter_id is None or candidate_id == adapter_id)
        and (integration_mode is None or candidate_mode == integration_mode)
    ]
    if len(candidates) == 1:
        return candidates[0]
    if not _is_approved_literal(connector, CONNECTORS):
        raise RuntimeObservationError("connector is unsupported")
    if adapter_id is None or integration_mode is None:
        raise RuntimeObservationError("adapter identity must include adapter_id and integration_mode")
    raise RuntimeObservationError("connector, adapter_id, and integration_mode are not an approved tuple")


def require_live_adapter(
    connector: str, adapter_id: str | None = None, integration_mode: str | None = None
) -> AdapterInterface:
    adapter = adapter_for(connector, adapter_id, integration_mode)
    if not adapter.live_producer_supported:
        raise RuntimeObservationError(f"{adapter.adapter_id} has no live runtime producer")
    return adapter


class _Issues:
    def __init__(self) -> None:
        self.hard: list[str] = []
        self.incomplete: list[str] = []

    @staticmethod
    def _message(message: str) -> str:
        clean = " ".join(str(message).split())
        return clean[:MAX_TEXT_LENGTH] or "validation error"

    def error(self, message: str) -> None:
        value = self._message(message)
        if value not in self.hard:
            self.hard.append(value)

    def partial(self, message: str) -> None:
        value = self._message(message)
        if value not in self.incomplete:
            self.incomplete.append(value)

    def all(self) -> list[str]:
        return [*self.hard, *self.incomplete]


def canonical_json(value: object) -> bytes:
    """Return deterministic JSON bytes without allowing non-finite values."""
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def evidence_manifest_digest(evidence: list[dict[str, Any]]) -> str:
    """Digest a canonical, path-free evidence inventory rather than raw logs."""
    normalized = [
        {
            "kind": item.get("kind"),
            "name": item.get("name"),
            "path": item.get("path"),
            "sha256": item.get("sha256"),
        }
        for item in evidence
    ]
    normalized.sort(key=lambda item: (str(item["name"]), str(item["path"])))
    return hashlib.sha256(canonical_json(normalized)).hexdigest()


def _is_boolean(value: object) -> bool:
    return type(value) is bool


def _is_approved_literal(value: object, approved: frozenset[str]) -> bool:
    """Return whether untrusted input is one of the closed string literals."""
    return isinstance(value, str) and value in approved


def _is_bounded_integer(value: object, *, lower: int = 0, upper: int = MAX_COUNTER) -> bool:
    if type(value) is not int:
        return False
    integer_value = int(value)
    return lower <= integer_value <= upper


def _safe_token(value: object) -> bool:
    return isinstance(value, str) and TOKEN.fullmatch(value) is not None


def _safe_framework_identifier(value: object) -> bool:
    return (
        isinstance(value, str)
        and FRAMEWORK_IDENTIFIER.fullmatch(value) is not None
        and ".." not in value
        and "//" not in value
    )


def _safe_reason(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) <= MAX_TEXT_LENGTH
        and "\x00" not in value
        and "\r" not in value
        and "\n" not in value
    )


def _is_absolute_path_text(value: str) -> bool:
    return value.startswith("/") or WINDOWS_ABSOLUTE_PATH.match(value) is not None


def _has_forbidden_metadata(value: object) -> bool:
    """Reject unsafe metadata without recursive traversal of hostile input."""
    pending: list[tuple[object, int]] = [(value, 0)]
    seen_containers: set[int] = set()
    visited = 0
    while pending:
        current, depth = pending.pop()
        visited += 1
        if depth > MAX_METADATA_DEPTH or visited > MAX_METADATA_NODES:
            return True
        if _metadata_container_is_forbidden(current, seen_containers, pending, depth):
            return True
        if _metadata_text_is_forbidden(current):
            return True
    return False


def _metadata_container_is_forbidden(
    current: object,
    seen_containers: set[int],
    pending: list[tuple[object, int]],
    depth: int,
) -> bool:
    if not isinstance(current, (Mapping, list)):
        return False
    container_id = id(current)
    if container_id in seen_containers:
        return True
    seen_containers.add(container_id)
    if isinstance(current, Mapping):
        return _queue_metadata_mapping(current, pending, depth)
    pending.extend((child, depth + 1) for child in current)
    return False


def _metadata_text_is_forbidden(current: object) -> bool:
    return isinstance(current, str) and _is_absolute_path_text(current)


def _queue_metadata_mapping(
    current: Mapping[object, object], pending: list[tuple[object, int]], depth: int
) -> bool:
    forbidden_keys = {
        "payload", "payloads", "raw_log", "raw_logs", "log_content", "log_contents",
        "request", "response", "request_body", "response_body", "headers", "authorization",
        "cookie", "secret", "secrets", "credential", "credentials", "password",
        "private_key", "api_key", "runner_path", "absolute_path",
    }
    for key, child in current.items():
        if not isinstance(key, str) or key.lower() in forbidden_keys:
            return True
        pending.append((child, depth + 1))
    return False


def _as_mapping(value: object, label: str, issues: _Issues) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        issues.error(f"{label} must be an object")
        return None
    return dict(value)


def _require_exact_keys(
    value: Mapping[str, Any],
    required: set[str],
    optional: set[str],
    label: str,
    issues: _Issues,
) -> None:
    missing = sorted(required - set(value))
    unexpected = sorted(set(value) - required - optional)
    if missing:
        issues.error(f"{label} is missing required fields: {', '.join(missing)}")
    if unexpected:
        issues.error(f"{label} contains unsupported fields: {', '.join(unexpected)}")


def _check_string_field(
    value: Mapping[str, Any],
    name: str,
    label: str,
    issues: _Issues,
    *,
    matcher: re.Pattern[str] | None = None,
) -> str | None:
    field = value.get(name)
    pattern = matcher or TOKEN
    if not isinstance(field, str) or pattern.fullmatch(field) is None:
        issues.error(f"{label}.{name} must be a bounded token")
        return None
    return field


def _normalise_policy(policy: str | Mapping[str, Any] | None) -> dict[str, Any]:
    if policy is None:
        policy = "strict"
    if isinstance(policy, str):
        name = policy
        supplied: Mapping[str, Any] = {}
    elif isinstance(policy, Mapping):
        name = str(policy.get("name", "strict"))
        supplied = policy
    else:
        raise TypeError("policy must be a string, mapping, or None")
    if name not in {"strict", "partial", "fixture"}:
        raise ValueError("policy name must be strict, partial, or fixture")
    return {
        "name": name,
        "allow_partial": name == "partial",
        "allow_fixture_evidence": name == "fixture",
        "evidence_root": supplied.get("evidence_root"),
    }


def _path_from_value(value: Path | str) -> Path:
    return Path(os.path.abspath(os.fspath(value)))


def _validate_directory_details(
    details: os.stat_result,
    path: Path,
    *,
    private: bool = False,
) -> None:
    if not stat.S_ISDIR(details.st_mode):
        raise ObservationInputError("evidence path contains a non-directory component")
    mode = stat.S_IMODE(details.st_mode)
    if private:
        if details.st_uid != os.geteuid() or mode != 0o700:
            raise ObservationInputError(
                "evidence root and descendants must be current-user 0700 directories"
            )
        return
    public_sticky = details.st_uid == 0 and bool(mode & stat.S_ISVTX) and bool(mode & 0o022)
    if mode & 0o022 and not public_sticky:
        raise ObservationInputError("evidence path has a group- or world-writable directory")
    if details.st_uid not in {0, os.geteuid()}:
        raise ObservationInputError("evidence path has an untrusted directory owner")
    if path == Path("/") and not public_sticky and details.st_uid != 0:
        raise ObservationInputError("filesystem root has an untrusted owner")


def _open_secure_directory(root: Path | str) -> tuple[int, Path]:
    path = _path_from_value(root)
    if path == Path("/"):
        raise ObservationInputError("evidence root must be narrower than filesystem root")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        raise ObservationInputError("safe evidence reads require O_NOFOLLOW and O_DIRECTORY")
    flags = os.O_RDONLY | directory_flag | no_follow
    descriptor = os.open("/", flags)
    current = Path("/")
    try:
        _validate_directory_details(os.fstat(descriptor), current)
        for component in path.parts[1:]:
            next_path = current / component
            try:
                before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError as exc:
                raise ObservationInputError("evidence root is unavailable") from exc
            _validate_directory_details(before, next_path, private=next_path == path)
            child = os.open(component, flags, dir_fd=descriptor)
            after = os.fstat(child)
            if (before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode)) != (
                after.st_dev,
                after.st_ino,
                stat.S_IFMT(after.st_mode),
            ):
                os.close(child)
                raise ObservationInputError("evidence directory changed during validation")
            _validate_directory_details(after, next_path, private=next_path == path)
            os.close(descriptor)
            descriptor = child
            current = next_path
        return descriptor, current
    except BaseException:
        os.close(descriptor)
        raise


def _validate_file_details(details: os.stat_result, label: str, maximum: int) -> None:
    if not stat.S_ISREG(details.st_mode):
        raise ObservationInputError(f"{label} must be a regular file")
    if details.st_nlink != 1:
        raise ObservationInputError(f"{label} must not be hard-linked")
    if details.st_uid != os.geteuid():
        raise ObservationInputError(f"{label} must be owned by the current user")
    if stat.S_IMODE(details.st_mode) != 0o600:
        raise ObservationInputError(f"{label} must have exact mode 0600")
    if details.st_size > maximum:
        raise ObservationInputError(f"{label} exceeds the bounded evidence size")


def _file_snapshot(details: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        details.st_dev,
        details.st_ino,
        stat.S_IFMT(details.st_mode),
        details.st_size,
        details.st_nlink,
        details.st_uid,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )


def _write_all(descriptor: int, data: bytes) -> None:
    """Write all bytes, explicitly handling short or zero-progress writes."""
    view = memoryview(data)
    while view:
        count = os.write(descriptor, view)
        if count <= 0 or count > len(view):
            raise ObservationInputError("canonical evidence write did not make progress")
        view = view[count:]


def read_bounded_evidence_file(
    path: Path | str,
    evidence_root: Path | str,
    *,
    label: str = "evidence file",
    maximum: int = MAX_OBSERVATION_BYTES,
) -> bytes:
    """Read one regular evidence file through descriptor-relative no-follow I/O."""
    root_descriptor, root = _open_secure_directory(evidence_root)
    target = _path_from_value(path)
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        os.close(root_descriptor)
        raise ObservationInputError("evidence file escapes its declared root") from exc
    if not relative.parts:
        os.close(root_descriptor)
        raise ObservationInputError("evidence root cannot itself be an evidence file")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    if no_follow is None or directory_flag is None or nonblock is None:
        os.close(root_descriptor)
        raise ObservationInputError("safe evidence reads require no-follow non-blocking support")
    directory_flags = os.O_RDONLY | directory_flag | no_follow
    descriptor = root_descriptor
    current = root
    file_descriptor = -1
    try:
        for component in relative.parts[:-1]:
            current = current / component
            before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            _validate_directory_details(before, current, private=True)
            child = os.open(component, directory_flags, dir_fd=descriptor)
            after = os.fstat(child)
            if (before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode)) != (
                after.st_dev,
                after.st_ino,
                stat.S_IFMT(after.st_mode),
            ):
                os.close(child)
                raise ObservationInputError("evidence directory changed during validation")
            _validate_directory_details(after, current, private=True)
            os.close(descriptor)
            descriptor = child
        filename = relative.parts[-1]
        before = os.stat(filename, dir_fd=descriptor, follow_symlinks=False)
        _validate_file_details(before, label, maximum)
        file_descriptor = os.open(
            filename,
            os.O_RDONLY | no_follow | nonblock,
            dir_fd=descriptor,
        )
        opened = os.fstat(file_descriptor)
        _validate_file_details(opened, label, maximum)
        if _file_snapshot(before) != _file_snapshot(opened):
            raise ObservationInputError("evidence file changed between validation and open")
        pieces: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(file_descriptor, min(65536, remaining))
            if not chunk:
                break
            pieces.append(chunk)
            remaining -= len(chunk)
        data = b"".join(pieces)
        final = os.fstat(file_descriptor)
        _validate_file_details(final, label, maximum)
        if _file_snapshot(opened) != _file_snapshot(final):
            raise ObservationInputError("evidence file changed while reading")
        if len(data) > maximum:
            raise ObservationInputError("evidence file grew beyond the bounded size")
        return data
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        os.close(descriptor)


def _reject_duplicate_json_key(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ObservationInputError("JSON object contains a duplicate key")
        result[key] = value
    return result


def _reject_nonfinite_json(value: str) -> None:
    raise ObservationInputError("JSON contains a non-finite value")


def load_runtime_observation_file(
    path: Path | str,
    evidence_root: Path | str,
) -> dict[str, Any]:
    """Safely load a canonical observation without following arbitrary paths."""
    data = read_bounded_evidence_file(path, evidence_root, label=RUNTIME_OBSERVATION_LABEL)
    try:
        value = json.loads(
            data.decode("utf-8", "strict"),
            object_pairs_hook=_reject_duplicate_json_key,
            parse_constant=_reject_nonfinite_json,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ObservationInputError) as exc:
        if isinstance(exc, ObservationInputError):
            raise
        raise ObservationInputError("runtime observation is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ObservationInputError("runtime observation JSON root must be an object")
    return value


def write_canonical_evidence_file(
    relative_path: str,
    data: bytes,
    evidence_root: Path | str,
) -> Path:
    """Create one fresh canonical evidence file through no-follow descriptors.

    The writer intentionally never overwrites an existing path.  The caller
    must reserve its private run directory first; this function pins that
    directory before creating the leaf, so an intermediate path replacement
    cannot redirect the write outside the declared evidence root.
    """
    if len(data) > MAX_OBSERVATION_BYTES:
        raise ObservationInputError("canonical evidence exceeds the bounded size")
    if not _safe_relative_evidence_path(relative_path):
        raise ObservationInputError("canonical evidence path must be a safe relative path")
    root_descriptor, root = _open_secure_directory(evidence_root)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        os.close(root_descriptor)
        raise ObservationInputError("safe evidence writes require O_NOFOLLOW and O_DIRECTORY")
    descriptor = root_descriptor
    current = root
    temporary_name: str | None = None
    file_descriptor = -1
    try:
        parts = PurePosixPath(relative_path).parts
        for component in parts[:-1]:
            current = current / component
            before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            _validate_directory_details(before, current, private=True)
            child = os.open(component, os.O_RDONLY | directory_flag | no_follow, dir_fd=descriptor)
            after = os.fstat(child)
            if (before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode)) != (
                after.st_dev,
                after.st_ino,
                stat.S_IFMT(after.st_mode),
            ):
                os.close(child)
                raise ObservationInputError("canonical evidence directory changed during validation")
            _validate_directory_details(after, current, private=True)
            os.close(descriptor)
            descriptor = child
        leaf = parts[-1]
        try:
            os.stat(leaf, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ObservationInputError("refusing to overwrite canonical evidence")
        temporary_name = f".{leaf}.{os.urandom(16).hex()}.tmp"
        file_descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
            0o600,
            dir_fd=descriptor,
        )
        _write_all(file_descriptor, data)
        os.fsync(file_descriptor)
        opened = os.fstat(file_descriptor)
        _validate_file_details(opened, "canonical evidence", MAX_OBSERVATION_BYTES)
        os.close(file_descriptor)
        file_descriptor = -1
        try:
            os.stat(leaf, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ObservationInputError("canonical evidence appeared during write")
        os.link(temporary_name, leaf, src_dir_fd=descriptor, dst_dir_fd=descriptor, follow_symlinks=False)
        os.unlink(temporary_name, dir_fd=descriptor)
        temporary_name = None
        os.fsync(descriptor)
        return root / PurePosixPath(relative_path)
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=descriptor)
            except FileNotFoundError:
                pass
        os.close(descriptor)


load_runtime_observation = load_runtime_observation_file


def _validate_scalar_value_fields(
    label: str, mapping: Mapping[str, Any], issues: _Issues
) -> None:
    for name, item in mapping.items():
        if name not in SEMANTIC_VALUE_FIELDS:
            issues.error(f"{label}.{name} is not a supported typed semantic field")
        elif name not in {"rule_ids", "intervention_rule_ids", "predicates"} and not (
            (item is None and name == "value")
            or _is_boolean(item)
            or _is_bounded_integer(item, lower=-MAX_COUNTER, upper=MAX_COUNTER)
            or (isinstance(item, str) and _safe_token(item))
        ):
            issues.error(f"{label}.{name} must be a bounded scalar semantic value")


def _validate_value_map_rules(label: str, mapping: Mapping[str, Any], issues: _Issues) -> None:
    http_status = mapping.get("http_status")
    if http_status is not None and not _is_bounded_integer(http_status, lower=100, upper=599):
        issues.error(f"{label}.http_status must be a bounded integer")
    for name in ("action", "intervention", "event", "transport"):
        if name in mapping and not _safe_token(mapping[name]):
            issues.error(f"{label}.{name} must be a bounded token")
    for field in ("rule_ids", "intervention_rule_ids"):
        rules = mapping.get(field)
        if field in mapping and (
            not isinstance(rules, list)
            or not rules
            or len(rules) > 64
            or any(not _is_bounded_integer(rule, lower=1, upper=2_147_483_647) for rule in rules)
            or len(set(rules)) != len(rules)
        ):
            issues.error(f"{label}.{field} must be a unique bounded integer list")


def _validate_predicates(label: str, predicates: object, issues: _Issues) -> None:
    if not isinstance(predicates, Mapping) or not predicates:
        issues.error(f"{label}.predicates must be a non-empty object")
        return
    for name, predicate in predicates.items():
        safe = (
            _safe_token(name)
            and (
                _is_boolean(predicate)
                or _is_bounded_integer(predicate, lower=-MAX_COUNTER, upper=MAX_COUNTER)
                or (isinstance(predicate, str) and _safe_token(predicate))
            )
        )
        if not safe:
            issues.error(f"{label}.predicates contains an unsafe value")
            break


def _validate_value_map(label: str, value: object, issues: _Issues) -> dict[str, Any] | None:
    mapping = _as_mapping(value, label, issues)
    if mapping is None:
        return None
    if not mapping:
        issues.error(f"{label} must not be empty")
        return mapping
    if _has_forbidden_metadata(mapping):
        issues.error(f"{label} contains raw-log, payload, or absolute-path metadata")
        return mapping
    _validate_scalar_value_fields(label, mapping, issues)
    _validate_value_map_rules(label, mapping, issues)
    if "predicates" in mapping:
        _validate_predicates(label, mapping["predicates"], issues)
    return mapping


def _expected_matches_observed(
    expected: Mapping[str, Any], observed: Mapping[str, Any], label: str, issues: _Issues
) -> None:
    for name, expected_value in expected.items():
        if name not in observed:
            issues.error(f"{label}.observed is missing expected field {name}")
        elif observed[name] != expected_value:
            issues.error(f"{label}.expected and observed disagree for {name}")


def _validate_identity(
    identity_value: object,
    expected_identity: Mapping[str, Any] | None,
    issues: _Issues,
) -> dict[str, Any] | None:
    identity = _as_mapping(identity_value, "identity", issues)
    if identity is None:
        return None
    _validate_identity_contract(identity, issues)
    _validate_identity_profile(identity, issues)
    _validate_identity_commits(identity, issues)
    _validate_expected_identity(identity, expected_identity, issues)
    return identity


def _validate_identity_contract(identity: Mapping[str, Any], issues: _Issues) -> None:
    required = {
        "connector",
        "adapter_id",
        "integration_mode",
        "profile",
        "crs",
        "mrts",
        "run_id",
        "parent_commit",
        "framework_commit",
        "mrts_commit",
        "producer",
        "producer_version",
    }
    _require_exact_keys(identity, required, set(), "identity", issues)
    connector = identity.get("connector")
    if not _is_approved_literal(connector, CONNECTORS):
        issues.error("identity.connector is not a supported connector")
        return
    for field in ("adapter_id", "integration_mode", "run_id", "producer", "producer_version"):
        _check_string_field(identity, field, "identity", issues)
    try:
        adapter_for(
            str(connector),
            identity.get("adapter_id") if isinstance(identity.get("adapter_id"), str) else None,
            identity.get("integration_mode") if isinstance(identity.get("integration_mode"), str) else None,
        )
    except RuntimeObservationError:
        issues.error("identity connector, adapter_id, and integration_mode are not an approved tuple")


def _validate_identity_profile(identity: Mapping[str, Any], issues: _Issues) -> None:
    profile = identity.get("profile")
    requirements = _profile_requirements_for_identity(profile, issues)
    for field in ("crs", "mrts"):
        if not _is_boolean(identity.get(field)):
            issues.error(f"identity.{field} must be a boolean")
    if requirements is not None:
        for field in ("crs", "mrts"):
            if identity.get(field) is not requirements[field]:
                issues.error(f"identity.{field} contradicts identity.profile")


def _validate_identity_commits(identity: Mapping[str, Any], issues: _Issues) -> None:
    for field in ("parent_commit", "framework_commit", "mrts_commit"):
        value = identity.get(field)
        if not isinstance(value, str) or COMMIT.fullmatch(value) is None:
            issues.error(f"identity.{field} must be a lowercase full commit")


def _validate_expected_identity(
    identity: Mapping[str, Any],
    expected_identity: Mapping[str, Any] | None,
    issues: _Issues,
) -> None:
    if expected_identity is None:
        return
    aliases = {
        "parent_sha": "parent_commit",
        "framework_sha": "framework_commit",
        "mrts_sha": "mrts_commit",
    }
    for supplied_name, supplied_value in expected_identity.items():
        name = aliases.get(supplied_name, supplied_name)
        if name not in identity:
            issues.error(f"expected identity contains unsupported field {supplied_name}")
        elif supplied_value is not None and identity.get(name) != supplied_value:
            issues.error(f"identity.{name} does not match expected identity")


def _profile_requirements_for_identity(
    profile: object, issues: _Issues
) -> Mapping[str, Any] | None:
    if not _is_approved_literal(profile, PROFILES):
        issues.error("identity.profile is not a supported profile")
        return None
    return PROFILE_REQUIREMENTS[str(profile)]


def _validate_assertion(
    value: object,
    label: str,
    issues: _Issues,
    *,
    matrix_required: bool,
    matrix_optional: bool,
    provenance_evidence_kind: object,
    allow_fixture_evidence: bool,
) -> None:
    assertion = _as_mapping(value, label, issues)
    if assertion is None:
        return
    required = {
        "required",
        "applicable",
        "executed",
        "live_executed",
        "expected",
        "observed",
        "result",
        "reason",
        "evidence_kind",
    }
    _require_exact_keys(assertion, required, {"case_id"}, label, issues)
    if "case_id" in assertion and not _safe_token(assertion.get("case_id")):
        issues.error(f"{label}.case_id must be a bounded token")
    for field in ("required", "applicable", "executed", "live_executed"):
        if not _is_boolean(assertion.get(field)):
            issues.error(f"{label}.{field} must be a boolean")
    result = assertion.get("result")
    if not _is_approved_literal(result, ASSERTION_RESULTS):
        issues.error(f"{label}.result uses an unsupported status")
    if not _safe_reason(assertion.get("reason")):
        issues.error(f"{label}.reason must be bounded sanitized text")
    evidence_kind = assertion.get("evidence_kind")
    if not _is_approved_literal(evidence_kind, CANONICAL_EVIDENCE_KINDS):
        issues.error(f"{label}.evidence_kind is not canonical")
    if _is_approved_literal(evidence_kind, RAW_EVIDENCE_KINDS):
        issues.error(f"{label}.evidence_kind cannot use raw or synthetic evidence")
    if _is_approved_literal(provenance_evidence_kind, CANONICAL_EVIDENCE_KINDS) and evidence_kind != provenance_evidence_kind:
        issues.error(f"{label}.evidence_kind does not match provenance.evidence_kind")
    expected = _validate_value_map(f"{label}.expected", assertion.get("expected"), issues)
    observed = _validate_value_map(f"{label}.observed", assertion.get("observed"), issues)
    if _validate_not_applicable_assertion(assertion, label, result, issues, matrix_optional):
        return
    _validate_applicable_assertion(
        assertion,
        label,
        result,
        evidence_kind,
        issues,
        matrix_required=matrix_required,
        allow_fixture_evidence=allow_fixture_evidence,
    )
    if expected is not None and observed is not None:
        _expected_matches_observed(expected, observed, label, issues)


def _validate_not_applicable_assertion(
    assertion: Mapping[str, Any],
    label: str,
    result: object,
    issues: _Issues,
    matrix_optional: bool,
) -> bool:
    if assertion.get("applicable") is not False:
        return False
    if not matrix_optional:
        issues.error(f"{label} is not centrally optional")
    if assertion.get("required") is not False:
        issues.error(f"{label} marked not applicable must not be required")
    if result != "NOT_APPLICABLE":
        issues.error(f"{label} marked not applicable must report NOT_APPLICABLE")
    if assertion.get("executed") is not False or assertion.get("live_executed") is not False:
        issues.error(f"{label} marked not applicable cannot claim execution")
    return True


def _validate_applicable_assertion(
    assertion: Mapping[str, Any],
    label: str,
    result: object,
    evidence_kind: object,
    issues: _Issues,
    *,
    matrix_required: bool,
    allow_fixture_evidence: bool,
) -> None:
    if matrix_required and assertion.get("required") is not True:
        issues.error(f"{label} is mandatory in the central profile matrix")
    if assertion.get("applicable") is not True:
        return
    if assertion.get("executed") is not True or assertion.get("live_executed") is not True:
        issues.partial(f"{label} lacks required live execution")
    if result != "PASS":
        issues.partial(f"{label} is not a PASS assertion")
    fixture_allowed = allow_fixture_evidence and evidence_kind == "canonical_fixture"
    if not _is_approved_literal(evidence_kind, LIVE_EVIDENCE_KINDS) and not fixture_allowed:
        issues.error(f"{label} must bind live execution to live evidence")


def _validate_runtime(
    value: object,
    issues: _Issues,
    *,
    allow_partial: bool,
    provenance_evidence_kind: object,
    allow_fixture_evidence: bool,
) -> dict[str, Any] | None:
    runtime = _as_mapping(value, "runtime", issues)
    if runtime is None:
        return None
    required = set(RUNTIME_REQUIRED_ASSERTIONS) | {"runtime_status"}
    missing = sorted(required - set(runtime))
    unexpected = sorted(set(runtime) - required - set(RUNTIME_OPTIONAL_ASSERTIONS))
    if missing:
        if allow_partial:
            issues.partial(f"runtime is missing required fields: {', '.join(missing)}")
        else:
            issues.error(f"runtime is missing required fields: {', '.join(missing)}")
    if unexpected:
        issues.error(f"runtime contains unsupported fields: {', '.join(unexpected)}")
    runtime_status = runtime.get("runtime_status")
    if not _is_approved_literal(runtime_status, RUNTIME_STATUSES):
        issues.error("runtime.runtime_status uses an unsupported status")
    _validate_runtime_assertions(
        runtime,
        issues,
        provenance_evidence_kind,
        allow_fixture_evidence,
    )
    _validate_runtime_status_alignment(runtime, runtime_status, issues)
    if runtime_status != "PASS":
        _validate_runtime_aggregate(runtime_status, issues)
    return runtime


def _validate_runtime_assertions(
    runtime: Mapping[str, Any],
    issues: _Issues,
    provenance_evidence_kind: object,
    allow_fixture_evidence: bool,
) -> None:
    case_ids: set[str] = set()
    for name in RUNTIME_REQUIRED_ASSERTIONS:
        if name in runtime:
            _validate_assertion(
                runtime.get(name),
                f"runtime.{name}",
                issues,
                matrix_required=True,
                matrix_optional=False,
                provenance_evidence_kind=provenance_evidence_kind,
                allow_fixture_evidence=allow_fixture_evidence,
            )
            _record_case_id(runtime.get(name), case_ids, issues)
    if "bypass_case" in runtime:
        _validate_assertion(
            runtime["bypass_case"],
            "runtime.bypass_case",
            issues,
            matrix_required=False,
            matrix_optional=True,
            provenance_evidence_kind=provenance_evidence_kind,
            allow_fixture_evidence=allow_fixture_evidence,
        )
        _record_case_id(runtime["bypass_case"], case_ids, issues)


def _record_case_id(candidate: object, case_ids: set[str], issues: _Issues) -> None:
    if not isinstance(candidate, Mapping) or not isinstance(candidate.get("case_id"), str):
        return
    case_id = candidate["case_id"]
    if case_id in case_ids:
        issues.error("runtime assertion case IDs are contradictory")
    case_ids.add(case_id)


def _validate_runtime_aggregate(runtime_status: object, issues: _Issues) -> None:
    if runtime_status == "PARTIAL" or runtime_status == "VALIDATION_FAILED":
        issues.partial("runtime aggregate is not PASS")
    elif runtime_status == "FAIL":
        issues.error("runtime aggregate reports FAIL")


def _validate_runtime_status_alignment(
    runtime: Mapping[str, Any], runtime_status: object, issues: _Issues
) -> None:
    """A run aggregate may summarize assertions but may never create their PASS facts."""
    if runtime_status != "PASS":
        return
    for name in RUNTIME_REQUIRED_ASSERTIONS:
        assertion = runtime.get(name)
        if not isinstance(assertion, Mapping):
            issues.error("runtime PASS is missing a required assertion")
            continue
        if (
            assertion.get("applicable") is not True
            or assertion.get("executed") is not True
            or assertion.get("live_executed") is not True
            or assertion.get("result") != "PASS"
        ):
            issues.error("runtime PASS contradicts an individual required assertion")


def normalize_framework_expectation(expectation: Mapping[str, Any]) -> dict[str, Any]:
    """Return the public Framework expectation form without exposing legacy ``rule_id``."""
    issues = _Issues()
    normalized = _normalise_framework_expectation(
        expectation, "framework.expectation", issues, allow_legacy=True
    )
    if normalized is None or issues.hard:
        raise RuntimeObservationError("invalid framework expectation")
    return normalized


def _normalise_framework_expectation(
    value: object,
    label: str,
    issues: _Issues,
    depth: int = 0,
    *,
    allow_legacy: bool = False,
) -> dict[str, Any] | None:
    if depth > MAX_EXPECTATION_DEPTH:
        issues.error(f"{label} exceeds the maximum compound depth")
        return None
    expectation = _as_mapping(value, label, issues)
    if expectation is None:
        return None
    if _has_forbidden_metadata(expectation):
        issues.error(f"{label} contains raw-log, payload, or absolute-path metadata")
        return None
    if expectation.get("kind") == "rule_id":
        if not allow_legacy:
            issues.error(f"{label} must normalize legacy rule_id before canonical validation")
            return None
        _require_exact_keys(expectation, {"kind", "value"}, set(), label, issues)
        rule_id = expectation.get("value")
        if not _is_bounded_integer(rule_id, lower=1, upper=9_999_999):
            issues.error(f"{label}.value is not a bounded legacy rule_id")
            return None
        return {"kind": "rule_match", "rule_ids": [int(rule_id)]}
    kind = expectation.get("kind")
    if not _is_approved_literal(kind, EXPECTATION_KINDS):
        issues.error(f"{label}.kind is unsupported")
        return None
    return _normalise_framework_expectation_kind(
        expectation, kind, label, issues, depth, allow_legacy
    )


def _normalise_framework_expectation_kind(
    expectation: Mapping[str, Any],
    kind: str,
    label: str,
    issues: _Issues,
    depth: int,
    allow_legacy: bool,
) -> dict[str, Any] | None:
    if kind in {
        "http_status",
        "rule_match",
        "request_headers",
        "response_headers",
        "lifecycle",
    }:
        return _normalise_framework_direct_expectation(expectation, kind, label, issues)
    if kind in {
        "intervention",
        "action",
        "event",
        "request_body",
        "response_body",
        "transport",
        "cleanup",
        "compound",
    }:
        return _normalise_framework_special_expectation(
            expectation, kind, label, issues, depth, allow_legacy
        )
    return _normalise_framework_not_applicable(expectation, label, issues)


def _normalise_framework_direct_expectation(expectation, kind, label, issues):
    if kind == "http_status":
        _require_exact_keys(expectation, {"kind", "http_status"}, set(), label, issues)
        status = _framework_http_status(expectation.get("http_status"), label, issues)
        return {"kind": kind, "http_status": status} if status is not None else None
    if kind == "rule_match":
        _require_exact_keys(expectation, {"kind", "rule_ids"}, set(), label, issues)
        rules = _framework_rule_ids(expectation.get("rule_ids"), label, issues)
        return {"kind": kind, "rule_ids": rules} if rules is not None else None
    if kind in {"request_headers", "response_headers"}:
        _require_exact_keys(expectation, {"kind", "names"}, set(), label, issues)
        names = _framework_identifier_list(expectation.get("names"), label, issues)
        return {"kind": kind, "names": names} if names is not None else None
    _require_exact_keys(expectation, {"kind", "predicates"}, set(), label, issues)
    predicates = _framework_lifecycle_predicates(expectation.get("predicates"), label, issues)
    return {"kind": kind, "predicates": predicates} if predicates is not None else None


def _normalise_framework_special_expectation(
    expectation, kind, label, issues, depth, allow_legacy
):
    if kind in {"intervention", "action"}:
        return _normalise_framework_action(expectation, kind, label, issues)
    if kind == "event":
        return _normalise_framework_event(expectation, label, issues)
    if kind in {"request_body", "response_body", "transport", "cleanup"}:
        return _normalise_framework_state(expectation, kind, label, issues)
    return _normalise_framework_compound(expectation, label, issues, depth, allow_legacy)


def _normalise_framework_action(expectation, kind, label, issues):
    allowed = {"kind", "action", "rule_ids"}
    if kind == "intervention":
        allowed.add("http_status")
    _require_exact_keys(expectation, {"kind", "action"}, allowed - {"kind", "action"}, label, issues)
    action = expectation.get("action")
    if not _is_approved_literal(action, FRAMEWORK_ACTIONS):
        issues.error(f"{label}.action is not a public Framework action")
    normalized = {"kind": kind, "action": action}
    if "http_status" in expectation:
        status = _framework_http_status(expectation.get("http_status"), label, issues)
        if status is not None:
            normalized["http_status"] = status
    if "rule_ids" in expectation:
        rules = _framework_rule_ids(expectation.get("rule_ids"), label, issues)
        if rules is not None:
            normalized["rule_ids"] = rules
    return normalized


def _normalise_framework_event(expectation, label, issues):
    _require_exact_keys(expectation, {"kind"}, {"fields", "event_type"}, label, issues)
    if "fields" not in expectation and "event_type" not in expectation:
        issues.error(f"{label} needs fields or event_type")
    normalized = {"kind": "event"}
    if "fields" in expectation:
        fields = _framework_identifier_list(expectation.get("fields"), label, issues)
        if fields is not None:
            normalized["fields"] = fields
    if "event_type" in expectation:
        event_type = expectation.get("event_type")
        if not _safe_framework_identifier(event_type):
            issues.error(f"{label}.event_type is not a Framework identifier")
        else:
            normalized["event_type"] = event_type
    return normalized


def _framework_expectation_states(kind):
    if kind in {"request_body", "response_body"}:
        return FRAMEWORK_BODY_STATES
    if kind == "transport":
        return FRAMEWORK_TRANSPORT_STATES
    return FRAMEWORK_CLEANUP_STATES


def _normalise_framework_state(expectation, kind, label, issues):
    _require_exact_keys(expectation, {"kind", "state"}, set(), label, issues)
    state = expectation.get("state")
    if not _is_approved_literal(state, _framework_expectation_states(kind)):
        issues.error(f"{label}.state is not valid for {kind}")
    return {"kind": kind, "state": state}


def _normalise_framework_compound(expectation, label, issues, depth, allow_legacy):
    _require_exact_keys(expectation, {"kind", "conditions"}, set(), label, issues)
    conditions_value = expectation.get("conditions")
    if not isinstance(conditions_value, list) or not 2 <= len(conditions_value) <= MAX_COMPOUND_CONDITIONS:
        issues.error(f"{label}.conditions must contain 2 to {MAX_COMPOUND_CONDITIONS} conditions")
        return None
    conditions = [
        _normalise_framework_expectation(condition, f"{label}.conditions[{index}]", issues, depth + 1, allow_legacy=allow_legacy)
        for index, condition in enumerate(conditions_value)
    ]
    normalized_conditions = [condition for condition in conditions if condition is not None]
    if len(normalized_conditions) != len(conditions):
        return None
    fingerprints = {canonical_json(condition) for condition in normalized_conditions}
    if len(fingerprints) != len(normalized_conditions):
        issues.error(f"{label}.conditions contains duplicate conditions")
    return {"kind": "compound", "conditions": normalized_conditions}


def _normalise_framework_not_applicable(expectation, label, issues):
    _require_exact_keys(expectation, {"kind", "reason"}, set(), label, issues)
    reason = expectation.get("reason")
    if not _is_approved_literal(reason, FRAMEWORK_NOT_APPLICABLE_REASONS):
        issues.error(f"{label}.reason is not a public not_applicable reason")
    return {"kind": "not_applicable", "reason": reason}


def _framework_http_status(value: object, label: str, issues: _Issues) -> int | None:
    if not _is_bounded_integer(value, lower=100, upper=599):
        issues.error(f"{label}.http_status must be a bounded integer")
        return None
    return int(value)


def _framework_rule_ids(value: object, label: str, issues: _Issues) -> list[int] | None:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > MAX_EXPECTATION_ITEMS
        or any(not _is_bounded_integer(item, lower=1, upper=9_999_999) for item in value)
        or len(set(value)) != len(value)
    ):
        issues.error(f"{label}.rule_ids must be a unique bounded integer list")
        return None
    return sorted(int(item) for item in value)


def _framework_identifier_list(value: object, label: str, issues: _Issues) -> list[str] | None:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > MAX_EXPECTATION_ITEMS
        or any(not _safe_framework_identifier(item) for item in value)
        or len(set(value)) != len(value)
    ):
        issues.error(f"{label} must be a unique non-empty Framework identifier list")
        return None
    return sorted(str(item) for item in value)


def _framework_lifecycle_predicates(
    value: object, label: str, issues: _Issues
) -> dict[str, bool] | None:
    if not isinstance(value, Mapping) or not value or len(value) > len(FRAMEWORK_LIFECYCLE_PREDICATES):
        issues.error(f"{label}.predicates must be a non-empty Framework predicate object")
        return None
    predicates: dict[str, bool] = {}
    for name, predicate in value.items():
        if name not in FRAMEWORK_LIFECYCLE_PREDICATES or not _is_boolean(predicate):
            issues.error(f"{label}.predicates contains an unsupported predicate")
            return None
        predicates[str(name)] = bool(predicate)
    return dict(sorted(predicates.items()))


def _normalise_framework_observation(
    value: object, label: str, issues: _Issues
) -> dict[str, Any] | None:
    observation = _as_mapping(value, label, issues)
    if observation is None:
        return None
    if not observation or _has_forbidden_metadata(observation):
        issues.error(f"{label} is empty or contains raw-log, payload, or absolute-path metadata")
        return None
    allowed = {
        "http_status",
        "action",
        "rule_ids",
        "event_fields",
        "event_type",
        "request_header_names",
        "response_header_names",
        "request_body_state",
        "response_body_state",
        "transport",
        "lifecycle",
        "cleanup",
        "applicability",
    }
    _require_exact_keys(observation, set(), allowed, label, issues)
    normalized: dict[str, Any] = {}
    _normalise_framework_observation_scalars(observation, label, issues, normalized)
    _normalise_framework_observation_lists(observation, label, issues, normalized)
    _normalise_framework_observation_states(observation, label, issues, normalized)
    return normalized


def _normalise_framework_observation_scalars(observation, label, issues, normalized):
    if "http_status" in observation:
        status = _framework_http_status(observation.get("http_status"), label, issues)
        if status is not None:
            normalized["http_status"] = status
    if "action" in observation:
        action = observation.get("action")
        if not _is_approved_literal(action, FRAMEWORK_ACTIONS):
            issues.error(f"{label}.action is not a public Framework action")
        else:
            normalized["action"] = action
    if "rule_ids" in observation:
        rules = _framework_rule_ids(observation.get("rule_ids"), label, issues)
        if rules is not None:
            normalized["rule_ids"] = rules
    if "event_type" in observation:
        event_type = observation.get("event_type")
        if not _safe_framework_identifier(event_type):
            issues.error(f"{label}.event_type is not a Framework identifier")
        else:
            normalized["event_type"] = event_type


def _normalise_framework_observation_lists(observation, label, issues, normalized):
    for field in ("event_fields", "request_header_names", "response_header_names"):
        if field in observation:
            names = _framework_identifier_list(observation.get(field), label, issues)
            if names is not None:
                normalized[field] = names


def _normalise_framework_observation_states(observation, label, issues, normalized):
    allowed_states = {
        "request_body_state": FRAMEWORK_BODY_STATES,
        "response_body_state": FRAMEWORK_BODY_STATES,
        "transport": FRAMEWORK_TRANSPORT_STATES,
        "cleanup": FRAMEWORK_CLEANUP_STATES,
        "applicability": FRAMEWORK_NOT_APPLICABLE_REASONS,
    }
    for field, allowed in allowed_states.items():
        if field in observation:
            state = observation.get(field)
            if not _is_approved_literal(state, allowed):
                issues.error(f"{label}.{field} is not a public Framework value")
            else:
                normalized[field] = state
    if "lifecycle" in observation:
        lifecycle = _framework_lifecycle_predicates(observation.get("lifecycle"), label, issues)
        if lifecycle is not None:
            normalized["lifecycle"] = lifecycle


def _framework_expectation_mismatches(
    expectation: Mapping[str, Any], observation: Mapping[str, Any]
) -> list[str]:
    kind = expectation["kind"]
    if kind == "compound":
        return _framework_compound_mismatches(expectation, observation)
    if kind == "http_status":
        return _framework_value_mismatch(observation, "http_status", expectation["http_status"], "http_status")
    if kind in {"intervention", "action"}:
        return _framework_action_mismatches(expectation, observation)
    if kind == "rule_match":
        return _framework_subset_mismatch(expectation, observation, "rule_ids")
    if kind == "event":
        return _framework_event_mismatches(expectation, observation)
    if kind in {"request_headers", "response_headers"}:
        field = "request_header_names" if kind == "request_headers" else "response_header_names"
        return _framework_subset_mismatch(expectation, observation, field, kind)
    if kind == "lifecycle":
        actual = observation.get("lifecycle", {})
        return [] if all(actual.get(name) == state for name, state in expectation["predicates"].items()) else ["lifecycle"]
    return _framework_scalar_mismatch(expectation, observation, kind)


def _framework_compound_mismatches(expectation, observation):
    return [
        mismatch
        for condition in expectation["conditions"]
        for mismatch in _framework_expectation_mismatches(condition, observation)
    ]


def _framework_value_mismatch(observation, field, expected, mismatch):
    return [] if observation.get(field) == expected else [mismatch]


def _framework_subset_mismatch(expectation, observation, field, mismatch=None):
    mismatch = mismatch or field
    return [] if set(expectation.get("names", expectation.get("rule_ids", []))).issubset(observation.get(field, [])) else [mismatch]


def _framework_action_mismatches(expectation, observation):
    mismatches = _framework_value_mismatch(observation, "action", expectation["action"], "action")
    if "http_status" in expectation:
        mismatches += _framework_value_mismatch(observation, "http_status", expectation["http_status"], "http_status")
    if "rule_ids" in expectation:
        mismatches += _framework_subset_mismatch(expectation, observation, "rule_ids")
    return mismatches


def _framework_event_mismatches(expectation, observation):
    mismatches = []
    if "fields" in expectation and not set(expectation["fields"]).issubset(observation.get("event_fields", [])):
        mismatches.append("event_fields")
    if "event_type" in expectation:
        mismatches += _framework_value_mismatch(observation, "event_type", expectation["event_type"], "event_type")
    return mismatches


def _framework_scalar_mismatch(expectation, observation, kind):
    fields = {
        "request_body": ("request_body_state", "request_body"),
        "response_body": ("response_body_state", "response_body"),
        "transport": ("transport", "transport"),
        "cleanup": ("cleanup", "cleanup"),
        "not_applicable": ("applicability", "not_applicable"),
    }
    field, mismatch = fields[kind]
    expected = expectation.get("state", expectation.get("reason"))
    return _framework_value_mismatch(observation, field, expected, mismatch)


def _validate_framework_case(case_value: object, label: str, issues: _Issues) -> dict[str, int]:
    case = _as_mapping(case_value, label, issues)
    if case is None:
        return {}
    required = {"framework_test_id", "scenario_category", "selected", "executed", "live_executed", "expectation", "observation", "result", "failure_count", "mismatch_count"}
    _require_exact_keys(case, required, set(), label, issues)
    _validate_framework_case_identity(case, label, issues)
    result = _validate_framework_case_status(case, label, issues)
    _validate_framework_case_counts(case, label, issues)
    expectation = _normalise_framework_expectation(case.get("expectation"), f"{label}.expectation", issues)
    observation = _normalise_framework_observation(case.get("observation"), f"{label}.observation", issues)
    _validate_framework_case_consistency(result, expectation, observation, label, issues)
    _validate_framework_case_execution(case, result, label, issues)
    return {
        "selected_count": 1 if case.get("selected") is True else 0,
        "executed_count": 1 if case.get("executed") is True else 0,
        "passed_count": 1 if result == "PASS" else 0,
        "failed_count": 1 if result == "FAIL" else 0,
        "cancelled_count": 1 if result == "CANCELLED" else 0,
        "unsupported_count": 1 if result == "UNSUPPORTED" else 0,
        "not_applicable_count": 1 if result == "NOT_APPLICABLE" else 0,
        "not_executed_count": 1 if result == "NOT_EXECUTED" else 0,
        "failure_count": int(case.get("failure_count", 0)) if _is_bounded_integer(case.get("failure_count")) else 0,
        "mismatch_count": int(case.get("mismatch_count", 0)) if _is_bounded_integer(case.get("mismatch_count")) else 0,
    }


def _validate_framework_case_identity(case, label, issues):
    if not _safe_framework_identifier(case.get("framework_test_id")):
        issues.error(f"{label}.framework_test_id is not a Framework identifier")
    category = case.get("scenario_category")
    if category is not None and not _safe_framework_identifier(category):
        issues.error(f"{label}.scenario_category must be Framework metadata or null")
    for field in ("selected", "executed", "live_executed"):
        if not _is_boolean(case.get(field)):
            issues.error(f"{label}.{field} must be a boolean")
    if case.get("selected") is not True:
        issues.error(f"{label}.selected must be true in the selected case list")


def _validate_framework_case_status(case, label, issues):
    result = case.get("result")
    if not _is_approved_literal(result, FRAMEWORK_CASE_RESULTS):
        issues.error(f"{label}.result uses an unsupported status")
    return result


def _validate_framework_case_counts(case, label, issues):
    for field in ("failure_count", "mismatch_count"):
        if not _is_bounded_integer(case.get(field)):
            issues.error(f"{label}.{field} must be a bounded integer")


def _validate_framework_case_consistency(result, expectation, observation, label, issues):
    if expectation is None or observation is None:
        return
    mismatches = _framework_expectation_mismatches(expectation, observation)
    if mismatches:
        issues.error(f"{label}.expectation and observation disagree: {', '.join(sorted(set(mismatches)))}")
    if expectation["kind"] == "not_applicable" and result != "NOT_APPLICABLE":
        issues.error(f"{label}.not_applicable expectation must report NOT_APPLICABLE")
    if expectation["kind"] != "not_applicable" and result == "NOT_APPLICABLE":
        issues.error(f"{label}.NOT_APPLICABLE result needs a not_applicable expectation")


def _validate_framework_case_execution(case, result, label, issues):
    if result in {"PASS", "FAIL", "CANCELLED"}:
        if case.get("executed") is not True:
            issues.error(f"{label}.result requires executed=true")
    elif _is_approved_literal(result, FRAMEWORK_CASE_RESULTS):
        if case.get("executed") is not False or case.get("live_executed") is not False:
            issues.error(f"{label}.non-executed result cannot claim live execution")
    if result == "PASS" and (case.get("failure_count") != 0 or case.get("mismatch_count") != 0):
        issues.error(f"{label}.PASS result cannot retain failures or mismatches")
    if result == "PASS" and case.get("live_executed") is not True:
        issues.error(f"{label}.PASS result requires live_executed=true")
    if result == "FAIL" and case.get("failure_count") == 0 and case.get("mismatch_count") == 0:
        issues.error(f"{label}.FAIL result needs a failure or mismatch count")


def _validate_framework(
    value: object,
    issues: _Issues,
) -> dict[str, Any] | None:
    framework = _as_mapping(value, "framework", issues)
    if framework is None:
        return None
    count_fields = _framework_count_fields()
    _validate_framework_header(framework, count_fields, issues)
    cases = framework.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_EXPECTATION_ITEMS:
        issues.error("framework.cases must be a bounded non-empty list")
        return framework
    actual = _validate_framework_cases(cases, count_fields, issues)
    _validate_framework_aggregate(framework, actual, issues)
    _validate_framework_disposition(framework, actual, issues)
    return framework


def _framework_count_fields():
    return {
        "selected_count", "executed_count", "passed_count", "failed_count", "cancelled_count",
        "unsupported_count", "not_applicable_count", "not_executed_count", "failure_count", "mismatch_count",
    }


def _validate_framework_header(framework, count_fields, issues):
    required = {"selection_status", "execution_status", "validation_status", "cases", *count_fields}
    _require_exact_keys(framework, required, set(), "framework", issues)
    if not _is_approved_literal(framework.get("selection_status"), FRAMEWORK_SELECTION_STATUSES):
        issues.error("framework.selection_status uses an unsupported status")
    if not _is_approved_literal(framework.get("execution_status"), FRAMEWORK_EXECUTION_STATUSES):
        issues.error("framework.execution_status uses an unsupported status")
    if not _is_approved_literal(framework.get("validation_status"), VALIDATION_STATUSES):
        issues.error("framework.validation_status uses an unsupported status")
    for field in count_fields:
        if not _is_bounded_integer(framework.get(field)):
            issues.error(f"framework.{field} must be a bounded integer")


def _validate_framework_cases(cases, count_fields, issues):
    framework_ids: set[str] = set()
    actual = dict.fromkeys(count_fields, 0)
    for index, case in enumerate(cases):
        if isinstance(case, Mapping) and isinstance(case.get("framework_test_id"), str):
            framework_test_id = case["framework_test_id"]
            if framework_test_id in framework_ids:
                issues.error("framework.cases contains duplicate framework_test_id values")
            framework_ids.add(framework_test_id)
        counts = _validate_framework_case(case, f"framework.cases[{index}]", issues)
        for field, count in counts.items():
            actual[field] = int(actual[field]) + count
    return actual


def _validate_framework_aggregate(framework, actual, issues):
    for field, count in actual.items():
        if framework.get(field) != count:
            issues.error(f"framework.{field} does not match framework.cases")
    if actual["selected_count"] != actual["executed_count"] + actual["unsupported_count"] + actual["not_applicable_count"] + actual["not_executed_count"]:
        issues.error("framework selected-count equation is violated")
    if actual["executed_count"] != actual["passed_count"] + actual["failed_count"] + actual["cancelled_count"]:
        issues.error("framework executed-count equation is violated")
    expected_selection_status = "SELECTED" if actual["selected_count"] else "NONE_SELECTED"
    expected_execution_status = "RUN" if actual["executed_count"] else "NOT_RUN"
    if framework.get("selection_status") != expected_selection_status:
        issues.error("framework.selection_status contradicts framework.cases")
    if framework.get("execution_status") != expected_execution_status:
        issues.error("framework.execution_status contradicts framework.cases")


def _validate_framework_disposition(
    framework: Mapping[str, Any], actual: Mapping[str, int], issues: _Issues
) -> None:
    if actual["selected_count"] == 0:
        issues.partial("framework has no selected case for a runtime PASS")
    if actual["selected_count"] != actual["executed_count"]:
        issues.partial("framework selected case was not executed")
    if actual["executed_count"] != actual["passed_count"]:
        issues.partial("framework executed case is not a PASS")
    if framework.get("validation_status") != "CONTRACT_VALIDATED":
        issues.partial("framework validation_status is not CONTRACT_VALIDATED")
    if actual["failure_count"] != 0 or actual["mismatch_count"] != 0:
        issues.partial("framework failure_count or mismatch_count is non-zero")


def _validate_isolation(value: object, requirements: Mapping[str, Any] | None, issues: _Issues) -> None:
    isolation = _as_mapping(value, "isolation", issues)
    if isolation is None:
        return
    _require_exact_keys(isolation, set(ISOLATION_FIELDS), set(), "isolation", issues)
    expected_values = requirements.get("isolation", {}) if requirements is not None else {}
    for field in ISOLATION_FIELDS:
        _validate_isolation_field(field, isolation.get(field), expected_values, issues)


def _validate_isolation_field(
    field: str,
    actual: object,
    expected_values: Mapping[str, Any],
    issues: _Issues,
) -> None:
    if not _is_boolean(actual):
        issues.error(f"isolation.{field} must be a boolean")
        return
    if field in expected_values and actual is not expected_values[field]:
        issues.error(f"isolation.{field} contradicts the central profile matrix")


def _validate_cleanup(value: object, issues: _Issues) -> dict[str, Any] | None:
    cleanup = _as_mapping(value, "cleanup", issues)
    if cleanup is None:
        return None
    required = set(CLEANUP_COUNTERS) | {"cleanup_status"}
    _require_exact_keys(cleanup, required, set(), "cleanup", issues)
    for field in CLEANUP_COUNTERS:
        if not _is_bounded_integer(cleanup.get(field)):
            issues.error(f"cleanup.{field} must be a bounded integer")
    if not _is_approved_literal(cleanup.get("cleanup_status"), frozenset(("PASS", "PARTIAL", "FAIL"))):
        issues.error("cleanup.cleanup_status uses an unsupported status")
    residual = any(
        _is_bounded_integer(cleanup.get(field)) and cleanup.get(field) != 0
        for field in CLEANUP_COUNTERS
    )
    if residual:
        issues.partial("cleanup residue prevents a runtime PASS")
    if cleanup.get("cleanup_status") != "PASS":
        issues.partial("cleanup status is not PASS")
    return cleanup


def _safe_relative_evidence_path(value: object) -> bool:
    if not isinstance(value, str) or not value or len(value) > 512:
        return False
    if _is_absolute_path_text(value) or "\\" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


def _validate_producer_binding(
    identity: Mapping[str, Any] | None,
    provenance: Mapping[str, Any],
    policy: Mapping[str, Any],
    issues: _Issues,
) -> None:
    """Bind a producer, connector, and evidence class before any PASS is possible."""
    if identity is None:
        return
    connector = identity.get("connector")
    producer = identity.get("producer")
    producer_version = identity.get("producer_version")
    evidence_kind = provenance.get("evidence_kind")
    if producer_version != PRODUCER_VERSION:
        issues.error("identity.producer_version is not an approved contract producer version")
    try:
        adapter = adapter_for(
            str(connector),
            identity.get("adapter_id") if isinstance(identity.get("adapter_id"), str) else None,
            identity.get("integration_mode") if isinstance(identity.get("integration_mode"), str) else None,
        )
    except RuntimeObservationError:
        return
    if adapter.protected_separate:
        _validate_nginx_producer(adapter, producer, evidence_kind, issues)
        return
    if evidence_kind == "canonical_fixture":
        _validate_fixture_producer(adapter, producer, policy, issues)
        return
    if not adapter.live_producer_supported:
        _validate_unsupported_live_producer(adapter, issues)
        return
    _validate_live_producer(adapter, producer, evidence_kind, issues)


def _validate_nginx_producer(
    adapter: AdapterInterface, producer: object, evidence_kind: object, issues: _Issues
) -> None:
    if producer != adapter.producer:
        issues.error("identity.producer is not approved for the protected NGINX boundary")
    if evidence_kind != "protected_runtime_evidence":
        issues.error("provenance.evidence_kind is not approved for the protected NGINX boundary")


def _validate_fixture_producer(
    adapter: AdapterInterface,
    producer: object,
    policy: Mapping[str, Any],
    issues: _Issues,
) -> None:
    if producer != adapter.fixture_producer:
        issues.error("fixture evidence is not bound to its adapter fixture producer")
    if not policy["allow_fixture_evidence"]:
        issues.error("fixture evidence is forbidden by the strict runtime policy")


def _validate_unsupported_live_producer(adapter: AdapterInterface, issues: _Issues) -> None:
    issues.error(f"{adapter.adapter_id} has no approved live runtime producer")


def _validate_live_producer(
    adapter: AdapterInterface,
    producer: object,
    evidence_kind: object,
    issues: _Issues,
) -> None:
    if producer != adapter.producer:
        issues.error("identity.producer is not approved for the connector")
    expected_kind = "structured_connector_evidence"
    if evidence_kind != expected_kind:
        issues.error("provenance.evidence_kind is not approved for the connector producer")


def _validate_evidence_records(
    evidence: object,
    evidence_kind: object,
    issues: _Issues,
) -> list[dict[str, Any]]:
    valid_records: list[dict[str, Any]] = []
    if not isinstance(evidence, list) or not evidence or len(evidence) > MAX_EVIDENCE_FILES:
        issues.error("provenance.evidence must be a bounded non-empty list")
        return valid_records
    names: set[str] = set()
    paths: set[str] = set()
    has_bound_evidence = False
    for index, item in enumerate(evidence):
        record, is_bound = _validate_evidence_record(
            index, item, evidence_kind, names, paths, issues
        )
        if record is None:
            continue
        has_bound_evidence = has_bound_evidence or is_bound
        valid_records.append(record)
    if not has_bound_evidence:
        issues.error("provenance.evidence needs connector-bound evidence, not only a manifest")
    return valid_records


def _validate_evidence_record(
    index: int,
    item: object,
    evidence_kind: object,
    names: set[str],
    paths: set[str],
    issues: _Issues,
) -> tuple[dict[str, Any] | None, bool]:
    label = f"provenance.evidence[{index}]"
    record = _as_mapping(item, label, issues)
    if record is None:
        return None, False
    _require_exact_keys(record, {"name", "path", "sha256", "kind"}, set(), label, issues)
    if not _safe_token(record.get("name")):
        issues.error(f"{label}.name must be a bounded token")
    if not _safe_relative_evidence_path(record.get("path")):
        issues.error(f"{label}.path must be a safe relative path")
    digest = record.get("sha256")
    if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
        issues.error(f"{label}.sha256 must be a SHA-256 digest")
    _validate_evidence_record_kind(record.get("kind"), evidence_kind, label, issues)
    _validate_evidence_record_uniqueness(record, names, paths, issues)
    return record, record.get("kind") == evidence_kind


def _validate_evidence_record_uniqueness(
    record: Mapping[str, Any],
    names: set[str],
    paths: set[str],
    issues: _Issues,
) -> None:
    name = record.get("name")
    path = record.get("path")
    if isinstance(name, str) and name in names:
        issues.error("provenance.evidence contains duplicate names")
    if isinstance(path, str) and path in paths:
        issues.error("provenance.evidence contains duplicate paths")
    if isinstance(name, str):
        names.add(name)
    if isinstance(path, str):
        paths.add(path)


def _validate_evidence_record_kind(
    record_kind: object, evidence_kind: object, label: str, issues: _Issues
) -> None:
    if not _is_approved_literal(record_kind, CANONICAL_EVIDENCE_RECORD_KINDS):
        issues.error(f"{label}.kind is not a canonical evidence kind")
    if record_kind == "canonical_fixture" and evidence_kind != "canonical_fixture":
        issues.error("fixture evidence record cannot support a live runtime claim")
    if _is_approved_literal(record_kind, LIVE_EVIDENCE_KINDS) and evidence_kind == "canonical_fixture":
        issues.error("live evidence record cannot be relabelled as a fixture")
    if record_kind != "manifest" and record_kind != evidence_kind:
        issues.error("provenance evidence record kind does not match the producer evidence kind")


def _validate_referenced_evidence(
    evidence_root: object,
    records: list[dict[str, Any]],
    issues: _Issues,
) -> None:
    if evidence_root is None or not records:
        return
    try:
        root = _path_from_value(evidence_root)
        for record in records:
            path = root / str(record["path"])
            data = read_bounded_evidence_file(path, root, label="referenced evidence")
            if hashlib.sha256(data).hexdigest() != record["sha256"]:
                issues.error("referenced evidence digest does not match")
    except (ObservationInputError, OSError):
        # Do not leak a host path from an OS exception into the canonical
        # validation result. Missing or unreadable bound evidence is a
        # validation failure, never an in-process exception or a PASS.
        issues.error("referenced evidence is unavailable or unsafe")


def _validate_provenance(
    value: object,
    identity: Mapping[str, Any] | None,
    policy: Mapping[str, Any],
    issues: _Issues,
) -> dict[str, Any] | None:
    provenance = _as_mapping(value, "provenance", issues)
    if provenance is None:
        return None
    _validate_provenance_header(provenance, issues)
    _validate_provenance_kind(provenance, issues)
    _validate_provenance_fields(provenance, identity, issues)
    evidence_kind = provenance.get("evidence_kind")
    _validate_producer_binding(identity, provenance, policy, issues)
    valid_records = _validate_evidence_records(provenance.get("evidence"), evidence_kind, issues)
    if valid_records and provenance.get("evidence_digest") != evidence_manifest_digest(valid_records):
        issues.error("provenance.evidence_digest does not bind the evidence inventory")
    if _has_forbidden_metadata(provenance):
        issues.error("provenance contains raw-log, payload, or absolute-path metadata")
    _validate_provenance_evidence_root(evidence_kind, valid_records, policy, issues)
    return provenance


def _validate_provenance_header(
    provenance: Mapping[str, Any], issues: _Issues
) -> None:
    required = {
        "evidence_kind",
        "fixture_id",
        "source_contract",
        "manifest_digest",
        "evidence_digest",
        "contract_schema_version",
        "producer_version",
        "evidence",
    }
    _require_exact_keys(
        provenance,
        required,
        {"validation_timestamp", "validation_basis"},
        "provenance",
        issues,
    )
    if "validation_timestamp" not in provenance and "validation_basis" not in provenance:
        issues.error("provenance needs a timestamp or deterministic validation basis")
    if "validation_timestamp" in provenance and (
        not isinstance(provenance["validation_timestamp"], str)
        or TIMESTAMP.fullmatch(provenance["validation_timestamp"]) is None
    ):
        issues.error("provenance.validation_timestamp is not an ISO-8601 UTC timestamp")
    if "validation_basis" in provenance and provenance["validation_basis"] != "evidence-digest-v1":
        issues.error("provenance.validation_basis is unsupported")


def _validate_provenance_kind(provenance: Mapping[str, Any], issues: _Issues) -> None:
    evidence_kind = provenance.get("evidence_kind")
    if not _is_approved_literal(evidence_kind, CANONICAL_EVIDENCE_KINDS):
        issues.error("provenance.evidence_kind is not canonical")
    if _is_approved_literal(evidence_kind, RAW_EVIDENCE_KINDS):
        issues.error("provenance.evidence_kind cannot name raw or synthetic evidence")


def _validate_provenance_fields(
    provenance: Mapping[str, Any],
    identity: Mapping[str, Any] | None,
    issues: _Issues,
) -> None:
    for field in ("fixture_id", "source_contract", "producer_version"):
        _check_string_field(provenance, field, "provenance", issues)
    for field in ("manifest_digest", "evidence_digest"):
        digest = provenance.get(field)
        if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            issues.error(f"provenance.{field} must be a SHA-256 digest")
    if provenance.get("contract_schema_version") != SCHEMA_VERSION:
        issues.error("provenance.contract_schema_version does not match schema_version")
    if identity is not None and provenance.get("producer_version") != identity.get("producer_version"):
        issues.error("provenance.producer_version does not match identity.producer_version")


def _validate_provenance_evidence_root(
    evidence_kind: object,
    valid_records: list[dict[str, Any]],
    policy: Mapping[str, Any],
    issues: _Issues,
) -> None:
    evidence_root = policy.get("evidence_root")
    if evidence_root is None and evidence_kind != "canonical_fixture":
        if policy["allow_partial"]:
            issues.partial("live runtime evidence requires a private evidence root")
        else:
            issues.error("live runtime evidence requires a private evidence root")
    elif evidence_root is not None and valid_records:
        _validate_referenced_evidence(evidence_root, valid_records, issues)


def _observation_digest(value: object) -> str | None:
    try:
        return hashlib.sha256(canonical_json(value)).hexdigest()
    except (RecursionError, TypeError, ValueError):
        return None


def validate_runtime_observation(
    observation: object,
    expected_identity: Mapping[str, Any] | None,
    policy: str | Mapping[str, Any] | None = "strict",
) -> ValidationResult:
    """Validate one canonical observation and return a bounded canonical result.

    The API deliberately reports validation failures as data so a workflow can
    retain a bounded, non-payload diagnostic record.  Callers must use
    ``status == 'PASS'`` as the only success condition.
    """
    issues = _Issues()
    normalized_policy = _normalise_policy(policy)
    identity: dict[str, Any] | None = None
    runtime: dict[str, Any] | None = None
    provenance: dict[str, Any] | None = None
    try:
        identity, runtime, provenance = _validate_document(
            observation, expected_identity, normalized_policy, issues
        )
    except (RecursionError, TypeError):
        issues.error("runtime observation contains an unsafe or excessively nested value")
    status, validation_status = _validation_status(issues, normalized_policy)
    result: ValidationResult = ValidationResult({
        "schema_version": SCHEMA_VERSION,
        "result_type": "runtime_observation_validation",
        "status": status,
        "validation_status": validation_status,
        "policy": normalized_policy["name"],
        "failure_count": len(issues.hard),
        "incomplete_count": len(issues.incomplete),
        "errors": issues.all(),
        "observation_digest": _observation_digest(observation),
        "identity": {
            name: identity.get(name)
            for name in (
                "connector",
                "adapter_id",
                "integration_mode",
                "profile",
                "run_id",
                "parent_commit",
                "framework_commit",
                "mrts_commit",
            )
        }
        if identity is not None
        else {},
    })
    _add_result_disposition(result, provenance, runtime, status)
    return result


def _validate_document(
    observation: object,
    expected_identity: Mapping[str, Any] | None,
    policy: Mapping[str, Any],
    issues: _Issues,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None]:
    document = _as_mapping(observation, RUNTIME_OBSERVATION_LABEL, issues)
    if document is None:
        return None, None, None
    _require_exact_keys(
        document,
        {"schema_version", "identity", "runtime", "framework", "isolation", "cleanup", "provenance"},
        set(),
        RUNTIME_OBSERVATION_LABEL,
        issues,
    )
    if document.get("schema_version") != SCHEMA_VERSION:
        issues.error("schema_version is unsupported")
    identity = _validate_identity(document.get("identity"), expected_identity, issues)
    profile = identity.get("profile") if identity is not None else None
    requirements = PROFILE_REQUIREMENTS.get(profile) if isinstance(profile, str) else None
    provenance_hint = document.get("provenance")
    provenance_evidence_kind = (
        provenance_hint.get("evidence_kind") if isinstance(provenance_hint, Mapping) else None
    )
    runtime = _validate_runtime(
        document.get("runtime"),
        issues,
        allow_partial=bool(policy["allow_partial"]),
        provenance_evidence_kind=provenance_evidence_kind,
        allow_fixture_evidence=bool(policy["allow_fixture_evidence"]),
    )
    _validate_framework(document.get("framework"), issues)
    _validate_isolation(document.get("isolation"), requirements, issues)
    _validate_cleanup(document.get("cleanup"), issues)
    provenance = _validate_provenance(document.get("provenance"), identity, policy, issues)
    return identity, runtime, provenance


def _validation_status(issues: _Issues, policy: Mapping[str, Any]) -> tuple[str, str]:
    if issues.hard:
        return "VALIDATION_FAILED", "VALIDATION_FAILED"
    if issues.incomplete:
        status = "PARTIAL" if policy["allow_partial"] else "VALIDATION_FAILED"
        return status, "PARTIAL" if status == "PARTIAL" else "VALIDATION_FAILED"
    return "PASS", "CONTRACT_VALIDATED"


def _add_result_disposition(
    result: ValidationResult,
    provenance: Mapping[str, Any] | None,
    runtime: Mapping[str, Any] | None,
    status: str,
) -> None:
    if provenance is not None and provenance.get("evidence_kind") == "canonical_fixture":
        result["evidence_disposition"] = "fixture_only"
    else:
        result["evidence_disposition"] = "runtime_evidence" if status == "PASS" else "not_validated"
    if runtime is not None:
        result["declared_runtime_status"] = runtime.get("runtime_status")
