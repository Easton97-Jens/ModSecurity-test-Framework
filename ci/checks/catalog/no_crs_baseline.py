#!/usr/bin/env python3
"""Capability-driven No-CRS case planning, evidence writing, and validation.

The CLI is deliberately host-neutral.  Connector-owned harnesses perform all
build/config/start/request work and pass their observed JSON/JSONL/log files to
``finalize``.  This module never treats a zero exit code, a compiled mapper, or
a missing artifact as runtime PASS evidence.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import subprocess
import sys
from typing import Any, Callable, Iterable, Mapping, Sequence, TypedDict


FRAMEWORK_ROOT = Path(__file__).resolve().parents[3]
CI_ROOT = FRAMEWORK_ROOT / "ci"
RUNNER_ROOT = FRAMEWORK_ROOT / "tests/runners"
CATALOG_ROOT = CI_ROOT / "checks" / "catalog"
PROTOCOL_ROOT = CI_ROOT / "checks" / "protocol"
for path in (CATALOG_ROOT, PROTOCOL_ROOT, RUNNER_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from msconnector_models import STATUS_MODEL, operation_status  # noqa: E402
from synchronized_upstream import first_byte_evidence_errors  # noqa: E402

CATALOG_PATH = FRAMEWORK_ROOT / "tests/cases/no-crs-baseline/catalog.json"
RULES_PATH = FRAMEWORK_ROOT / "tests/rules/no-crs-baseline.conf"
EVENT_SCHEMA_PATH = FRAMEWORK_ROOT / "tests/schemas/no-crs-baseline/event.schema.json"
MANIFEST_FILE_NAME = "manifest.json"
RESULT_FILE_NAME = "result.json"
CASE_RESULTS_FILE_NAME = "results.jsonl"
EVENTS_FILE_NAME = "events.jsonl"
RUN_INVENTORY_FILE_PATH = "inventory/run.json"
RULES_ARTIFACT_FILE_PATH = "config/no-crs-baseline.conf"
CAPABILITIES_INVENTORY_FILE_PATH = "inventory/capabilities.json"
PLAN_FILE_NAME = "plan.json"
NO_CRS_SCHEMA_DIRECTORY = "tests/schemas/no-crs-baseline"
RESULT_GLOB_PATTERN = "*/result.json"
REPORT_STATUS_NOT_IMPLEMENTED = "NOT IMPLEMENTED"
REPORT_STATUS_NOT_EXECUTED = "NOT EXECUTED"
REPORT_STATUS_IMPLEMENTED_NOT_ASSERTED = "IMPLEMENTED, NOT ASSERTED"
CONNECTORS = ("apache", "nginx", "haproxy", "envoy", "traefik", "lighttpd")
EVIDENCE_STAGES = (
    "source_contract",
    "compile",
    "link",
    "config_load",
    "start_smoke",
    "minimal_runtime_smoke",
    "no_crs_baseline",
    "crs_smoke",
    "extended_matrix",
)
EVIDENCE_STAGE_STATUSES = {
    "supported_and_verified",
    "supported_not_verified",
    "implemented_not_asserted",
    "unsupported_by_host_model",
    "not_implemented",
    "blocked_before_execution",
    "failed",
    "not_executed",
    "not_applicable",
}
CAPABILITIES = (
    "connection_metadata",
    "transport_metadata",
    "request_headers",
    "request_body_buffered",
    "request_body_streaming",
    "request_body_incremental_ingest",
    "response_headers",
    "response_body_buffered",
    "response_body_streaming",
    "response_body_incremental_ingest",
    "phase1",
    "phase2",
    "phase3",
    "phase4",
    "phase4_rule_evaluation",
    "phase4_end_of_stream_evaluation",
    "phase4_pre_commit_deny",
    "late_intervention",
    "late_intervention_log_only",
    "late_intervention_abort",
    "late_intervention_status_metadata",
    "content_type_scope",
    "header_limits",
    "request_body_limits",
    "response_body_limits",
    "no_full_response_buffering",
    "first_byte_before_response_end",
    "http1_content_length",
    "http1_chunked",
    "keep_alive",
    "parallel_requests",
    "http2",
    "http2_downstream",
    "http2_upstream",
    "http2_tls_alpn",
    "http2_cleartext_h2c",
    "http2_multiplexing",
    "http2_stream_reset",
    "http3_downstream",
    "http3_upstream",
    "http3_quic",
    "http3_alt_svc",
    "http3_multiplexing",
    "http3_stream_reset",
    "protocol_transaction_isolation",
    "protocol_first_byte_before_response_end",
    "protocol_no_full_response_buffering",
    "client_abort",
    "upstream_abort",
    "response_body_decompression",
    "deny",
    "redirect",
    "drop",
    "abort_connection",
    "log_only",
    "transaction_id",
    "event_jsonl",
    "config_inline_rules",
    "config_rules_file",
    "config_remote_rules",
)
CAPABILITY_STATES = (
    "verified",
    "implemented_not_asserted",
    "configured_not_exercised",
    "unsupported_by_host_model",
    "not_implemented",
    "not_applicable",
)
EXECUTABLE_CAPABILITY_STATES = {
    "verified",
    "implemented_not_asserted",
    "configured_not_exercised",
}
CASE_STATUSES = (
    "PASS",
    "FAIL",
    "BLOCKED",
    "UNSUPPORTED",
    "NOT_APPLICABLE",
    "NOT_EXECUTED",
)
SELECTION_STATUSES = ("SELECTED", "UNSUPPORTED", "NOT_APPLICABLE", "NOT_EXECUTED")
WRITABLE_EVIDENCE_STAGES = ("minimal_runtime_smoke", "no_crs_baseline")
DEFAULT_ARTIFACT_PROFILE = "generic"
FULL_LIFECYCLE_ARTIFACT_PROFILE = "full_lifecycle"
ARTIFACT_PROFILES = (
    DEFAULT_ARTIFACT_PROFILE,
    FULL_LIFECYCLE_ARTIFACT_PROFILE,
)
FULL_LIFECYCLE_REQUIRED_ARTIFACTS = (
    ("manifest", MANIFEST_FILE_NAME),
    ("result", RESULT_FILE_NAME),
    ("case_results", CASE_RESULTS_FILE_NAME),
    ("events", EVENTS_FILE_NAME),
    ("inventory", RUN_INVENTORY_FILE_PATH),
    ("stdout", "logs/stdout.log"),
    ("stderr", "logs/stderr.log"),
    ("host_log", "logs/host.log"),
    ("first_byte_evidence", "inventory/first-byte-evidence.json"),
)
FIRST_BYTE_EVIDENCE_RELATIVE_PATH = "inventory/first-byte-evidence.json"
# These are deliberately separate from ``FULL_LIFECYCLE_REQUIRED_ARTIFACTS``.
# A generic full-lifecycle run may legitimately have no transport-hardening
# case (and must not be made to invent one).  The transport-hardening checker
# requires its complete evidence subset as soon as a transport case is
# promoted; ``effective_config`` is retained as bounded provenance only.
TRANSPORT_HARDENING_ARTIFACT_PATHS = {
    "client_log": "logs/client.log",
    "upstream_log": "logs/upstream.log",
    "transport_log": "logs/transport.log",
    "cleanup_log": "logs/cleanup.log",
    "transport_observations": "inventory/transport-observations.json",
    "connection_lifecycle": "inventory/connection-lifecycle.json",
    "barrier_events": "inventory/barrier-events.jsonl",
    "effective_config": "effective-config/manifest.json",
}
ENGINE_LIFECYCLE_ARTIFACT_PATHS = {
    "engine_version": "engine-version.txt",
    "engine_library_sha256": "engine-library-sha256.txt",
    "ruleset_sha256": "ruleset-sha256.txt",
    "transaction_counts": "transaction-counts.json",
    "lifecycle_counters": "lifecycle-counters.json",
}
PROTOCOL_CLIENT_ARTIFACT_DIR = "inventory/protocol-client"
PROTOCOL_CLIENT_ARTIFACT_PATHS = {
    "client_version": f"{PROTOCOL_CLIENT_ARTIFACT_DIR}/client-version.txt",
    "client_features": f"{PROTOCOL_CLIENT_ARTIFACT_DIR}/client-features.txt",
    "client_command": f"{PROTOCOL_CLIENT_ARTIFACT_DIR}/client-command.txt",
    "client_protocol_observation": (
        f"{PROTOCOL_CLIENT_ARTIFACT_DIR}/client-protocol-observation.json"
    ),
    "client_followup_observation": (
        f"{PROTOCOL_CLIENT_ARTIFACT_DIR}/client-followup-observation.json"
    ),
}
PROTOCOL_CLIENT_REQUIRED_ARTIFACT_NAMES = tuple(
    name for name in PROTOCOL_CLIENT_ARTIFACT_PATHS
    if name != "client_followup_observation"
)
# curl can force and observe negotiation, but it does not expose a portable
# stream-control primitive.  These case outcomes therefore need a dedicated
# H2/H3 stream client before they can be promoted; a sidecar label alone is
# not a client-observed reset/cancel proof.
DEDICATED_STREAM_CONTROL_RESULTS = frozenset({
    "connection_aborted_strict",
    "protocol_client_stream_reset",
    "protocol_server_stream_reset",
    "protocol_upstream_reset",
    "protocol_transaction_isolation",
    "protocol_unrelated_stream_healthy",
    "protocol_parallel_cleanup_balanced",
})
# Finalization is a trust boundary in its own right.  Keep this explicit
# rather than relying on a later ``validate --check all`` invocation to catch
# a substituted or shared modern-protocol client bundle.
FINALIZE_VALIDATION_CHECKS = (
    "schema",
    "completeness",
    "capability",
    "claim-policy",
    "layout",
    "body-payload",
    "protocol-client",
    "status",
)
MINIMAL_RUNTIME_CASE_IDS = ("allow_without_marker", "deny_header_marker_403")
REPORT_STATUSES = (
    "PASS",
    "FAIL",
    "BLOCKED",
    "UNSUPPORTED",
    REPORT_STATUS_NOT_IMPLEMENTED,
    REPORT_STATUS_NOT_EXECUTED,
    REPORT_STATUS_IMPLEMENTED_NOT_ASSERTED,
)
CLAIMS_NOT_ALLOWED = (
    "production-ready",
    "production hardened",
    "runtime secure",
    "security verified",
    "CRS verified",
    "CRS complete",
    "full matrix verified",
    "response body verified across all connectors",
    "all connectors fully verified",
)
FORBIDDEN_EVENT_KEYS = {
    "access_token",
    "api_key",
    "authorization",
    "body",
    "body_content",
    "proxy_authorization",
    "cookie",
    "set_cookie",
    "password",
    "passwd",
    "secret",
    "request_body",
    "response_body",
    "raw_body",
    "body_payload",
    "body_snippet",
    "blocked_body_marker",
    "intervention_log",
    "matched_value",
    "rule_message",
    "request_body_marker",
    "request_content",
    "refresh_token",
    "response_body_marker",
    "response_content",
    "payload",
}
BODY_METADATA_KEYS = {
    "body_bytes",
    "body_bytes_seen",
    "body_bytes_inspected",
    "body_hash",
    "body_length",
    "body_size",
    "content_type",
    "request_body_size",
    "response_body_size",
    "truncated",
}
BODY_SENTINELS = (
    "no-crs-request-body-marker",
    "no-crs-response-body-marker",
)
PHASE4_EXPECTED_RESULTS = {
    "rule_observed",
    "deny_before_commit",
    "late_intervention_log_only",
    "connection_aborted",
    "event_contains_original_status",
    "event_contains_late_intervention_action",
    "legacy_phase4_deny_before_commit",
    "marker_split_across_chunks",
    "end_of_stream_evaluation",
    "late_intervention_log_only_minimal",
    "late_intervention_log_only_safe",
    "connection_aborted_strict",
    "content_type_in_scope",
    "content_type_in_scope_with_charset",
    "content_type_out_of_scope",
    "content_type_missing",
    "no_full_response_buffering",
    "first_byte_before_response_end",
    "response_body_at_limit",
    "response_body_over_limit",
    "response_body_process_partial",
    "response_body_reject",
}
PHASE4_CASE_IDS = (
    "phase4_rule_observed",
    "phase4_deny_before_commit",
    "phase4_deny_after_commit_log_only",
    "phase4_deny_after_commit_abort",
    "phase4_event_contains_original_status",
    "phase4_event_contains_late_intervention_action",
    "phase4_marker_split_across_chunks",
    "phase4_end_of_stream_evaluation",
    "phase4_deny_before_commit_if_supported",
    "phase4_deny_after_commit_log_only_minimal",
    "phase4_deny_after_commit_log_only_safe",
    "phase4_deny_after_commit_abort_strict",
    "phase4_status_metadata",
    "phase4_action_metadata",
    "phase4_no_payload_event",
    "phase4_in_scope_content_type",
    "phase4_content_type_with_charset",
    "phase4_out_of_scope_content_type",
    "phase4_missing_content_type",
    "phase4_no_full_response_buffering",
    "phase4_first_byte_before_response_end",
    "phase4_body_at_limit",
    "phase4_body_over_limit",
    "phase4_body_process_partial",
    "phase4_body_reject",
)
FULL_LIFECYCLE_REQUIRED_IDS = {
    "phase1_allow",
    "phase1_deny_403",
    "phase1_alternative_status",
    "phase1_redirect",
    "phase1_transaction_id",
    "phase2_request_body_rule",
    "phase2_marker_split_across_chunks",
    "phase2_at_limit",
    "phase2_over_limit",
    "phase2_truncated",
    "phase2_no_payload_event",
    "phase3_response_header_rule",
    "phase3_deny_before_commit",
    "phase3_redirect_before_commit",
    "phase3_original_and_visible_status",
    "phase4_marker_split_across_chunks",
    "phase4_end_of_stream_evaluation",
    "phase4_deny_before_commit_if_supported",
    "phase4_deny_after_commit_log_only_minimal",
    "phase4_deny_after_commit_log_only_safe",
    "phase4_deny_after_commit_abort_strict",
    "phase4_status_metadata",
    "phase4_action_metadata",
    "phase4_no_payload_event",
    "phase4_in_scope_content_type",
    "phase4_content_type_with_charset",
    "phase4_out_of_scope_content_type",
    "phase4_missing_content_type",
    "phase4_invalid_scope_file",
    "phase4_wildcard_scope_rejected",
    "phase4_no_full_response_buffering",
    "phase4_first_byte_before_response_end",
    "transport_http11_content_length",
    "transport_http11_chunked",
    "transport_keep_alive",
    "transport_sequential_requests",
    "transport_parallel_requests",
    "transport_http2_if_supported",
    "transport_client_abort",
    "transport_upstream_abort",
    "client_disconnect_before_request_body_eos",
    "client_disconnect_during_request_body",
    "client_disconnect_after_response_headers",
    "client_disconnect_after_first_response_chunk",
    "client_disconnect_before_response_eos",
    "client_cancelled_during_request_body",
    "upstream_reset_before_headers",
    "upstream_reset_after_headers",
    "upstream_reset_during_body",
    "upstream_close_without_eos",
    "upstream_content_length_short",
    "phase4_strict_http1_client_abort",
    "phase4_strict_http2_stream_reset",
    "phase4_strict_host_survives",
    "phase4_strict_followup_request_succeeds",
    "keepalive_allow_allow",
    "keepalive_allow_deny_allow",
    "keepalive_safe_followup",
    "keepalive_after_strict_new_connection",
    "parallel_transaction_ids_unique",
    "parallel_events_not_cross_bound",
    "parallel_mixed_actions",
    "parallel_cleanup_balanced",
    "engine_timeout_before_commit",
    "engine_timeout_after_commit",
    "upstream_timeout",
    "client_idle_timeout",
    "response_short_write_resume",
    "response_write_would_block_resume",
    "phase4_body_at_limit",
    "phase4_body_over_limit",
    "phase4_body_process_partial",
    "phase4_body_reject",
    "full_lifecycle_event_metadata_bounded",
}
PHASE4_SEMANTIC_FIELDS = (
    "http_status",
    "requested_action",
    "actual_action",
    "original_http_status",
    "visible_http_status",
    "late_intervention",
    "headers_sent",
    "response_started",
    "body_started",
    "body_truncated",
    "response_committed",
    "connection_aborted",
    "transport_result",
    "late_intervention_mode",
    "content_type_scope",
    "body_limit_outcome",
    "marker_split_across_chunks",
    "end_of_stream_evaluation",
    "no_full_response_buffering",
    "first_byte_before_response_end",
    "upstream_response_finished_at_first_byte",
    "client_first_byte_received",
    "first_chunk_size",
    "upstream_paused",
    "upstream_eos_sent_at_first_byte",
    # ``transport_protocol`` is the historical http1/http2 field.  New
    # protocol evidence must use the explicit provenance fields below so a
    # client fallback cannot be relabelled as a newer protocol.
    "transport_protocol",
    "requested_protocol",
    "downstream_protocol",
    "upstream_protocol",
    "negotiated_protocol",
    "transport",
    "alpn",
    "stream_id",
    "transport_case_id",
    "barrier_id",
    "connection_id",
    "transfer_encoding",
    "connection_reused",
    "quic_connection_id_present",
    "quic_version",
    "fallback_used",
    "stream_reset",
    "stream_reset_code",
    "client_aborted",
    "upstream_aborted",
    # Transport-hardening metadata is bounded and payload-free.  These are
    # optional observations, not capabilities and never promote a result by
    # themselves.
    "client_disconnected",
    "upstream_disconnected",
    "cancelled",
    "reset_by",
    "reset_code",
    "timeout_stage",
    "write_result",
    "eos_seen",
    "cleanup_reason",
)
REQUESTED_ACTIONS = {"deny", "redirect", "drop", "log_only", "abort_connection"}
ACTUAL_ACTIONS = {"deny", "redirect", "log_only", "abort_connection", "stream_reset"}
TRANSPORT_RESULTS = {
    # ``http_status`` and ``not_observable`` are retained only for backwards
    # compatibility with pre-hardening artifacts.  New writers should use
    # ``completed`` for a normal completed transport.
    "completed", "log_only", "connection_aborted", "stream_reset",
    "client_cancelled", "client_disconnected", "upstream_reset",
    "upstream_disconnected", "timeout", "short_write", "write_would_block",
    "engine_error", "host_error", "http_status", "not_observable",
}
RESET_BY_VALUES = {
    "client", "upstream", "engine", "host", "strict_intervention", "timeout",
}
TIMEOUT_STAGES = {
    "engine", "request_body", "response_body", "upstream", "client_idle",
    "before_commit", "after_commit",
}
WRITE_RESULTS = {
    "completed", "short_write", "write_would_block", "engine_error", "host_error",
}
CLEANUP_REASONS = {
    "normal", "cancelled", "client_disconnected", "upstream_disconnected",
    "stream_reset", "timeout", "engine_error", "host_error", "strict_abort",
}
LATE_INTERVENTION_MODES = {"minimal", "safe", "strict"}
CONTENT_TYPE_SCOPES = {"in_scope", "out_of_scope", "missing"}
BODY_LIMIT_OUTCOMES = {"at_limit", "over_limit", "process_partial", "reject"}
# Keep this historical vocabulary stable.  It is deliberately not extended
# to H3: new evidence uses negotiated_protocol + transport instead.
LEGACY_TRANSPORT_PROTOCOLS = {"http1", "http2"}
CANONICAL_PROTOCOLS = {"http1", "h2", "h2c", "h3"}
CANONICAL_TRANSPORTS = {"tcp", "tls_tcp", "quic_udp"}
MAX_STREAM_ID = 4_611_686_018_427_387_903
PROTOCOL_PROVENANCE_FIELDS = (
    "requested_protocol",
    "downstream_protocol",
    "upstream_protocol",
    "negotiated_protocol",
    "transport",
    "alpn",
    "stream_id",
    "transport_case_id",
    "connection_id",
    "connection_reused",
    "quic_connection_id_present",
    "quic_version",
    "fallback_used",
    "stream_reset",
    "stream_reset_code",
)
# A reused HTTP/1.1 connection predates protocol provenance and must not turn
# an otherwise legacy record into a protocol claim on its own.
PROTOCOL_CLAIM_FIELDS = tuple(
    field for field in PROTOCOL_PROVENANCE_FIELDS if field != "connection_reused"
)
TRANSPORT_CLAIM_FIELDS = frozenset({
    *PROTOCOL_CLAIM_FIELDS,
    "client_disconnected", "upstream_disconnected", "cancelled", "reset_by",
    "reset_code", "timeout_stage", "write_result", "eos_seen", "cleanup_reason",
    "barrier_id",
})
TRANSFER_ENCODINGS = {"content_length", "chunked", "none"}
COMMON_PHASE_TO_CANONICAL = {
    # URI parsing and request-header processing both constitute ModSecurity
    # phase 1 evidence.  Common deliberately exposes the finer host lifecycle
    # labels, which must not be confused with the framework's rule phases.
    "connection": 0,
    "uri": 1,
    "request_headers": 1,
    "request_body": 2,
    "response_headers": 3,
    "response_body": 4,
    "logging": 5,
}
CANONICAL_PHASES = frozenset(range(6))
STATUS_ALIASES = {
    "pass": "PASS",
    "passed": "PASS",
    "ok": "PASS",
    "fail": "FAIL",
    "failed": "FAIL",
    "error": "FAIL",
    "blocked": "BLOCKED",
    "not_executable": "UNSUPPORTED",
    "unsupported": "UNSUPPORTED",
    "not_applicable": "NOT_APPLICABLE",
    "skipped": "NOT_EXECUTED",
    "not_run": "NOT_EXECUTED",
    "not_executed": "NOT_EXECUTED",
}


class ContractError(ValueError):
    """Raised for a canonical contract violation."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def lexical_absolute(path: str | Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _directory_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def _require_safe_directory_component(part: str, absolute: Path) -> None:
    if part in {"", ".", ".."}:
        raise ContractError(f"unsafe directory component in {absolute}: {part!r}")


def _create_directory_component(
    parent_descriptor: int,
    part: str,
    absolute: Path,
    flags: int,
) -> int:
    try:
        os.mkdir(part, mode=0o700, dir_fd=parent_descriptor)
    except FileExistsError:
        pass
    try:
        return os.open(part, flags, dir_fd=parent_descriptor)
    except OSError as exc:
        raise ContractError(f"directory component is unsafe: {absolute}: {exc}") from exc


def _open_directory_component(
    parent_descriptor: int,
    part: str,
    absolute: Path,
    flags: int,
    create: bool,
) -> int:
    try:
        return os.open(part, flags, dir_fd=parent_descriptor)
    except FileNotFoundError:
        if not create:
            raise ContractError(f"directory is missing: {absolute}") from None
    except OSError as exc:
        raise ContractError(f"directory component is unsafe or a symlink: {absolute}: {exc}") from exc
    return _create_directory_component(parent_descriptor, part, absolute, flags)


def open_directory_chain(path: str | Path, *, create: bool = False) -> int:
    """Open an absolute directory one no-follow component at a time."""
    absolute = lexical_absolute(path)
    flags = _directory_flags()
    descriptor = os.open(absolute.anchor or "/", flags)
    try:
        parts = absolute.parts[1:] if absolute.is_absolute() else absolute.parts
        for part in parts:
            _require_safe_directory_component(part, absolute)
            next_descriptor = _open_directory_component(
                descriptor, part, absolute, flags, create,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def assert_no_symlink_components(path: str | Path, *, include_leaf: bool = True) -> None:
    absolute = lexical_absolute(path)
    components = absolute.parts[1:] if absolute.is_absolute() else absolute.parts
    current = Path(absolute.anchor or "/")
    limit = len(components) if include_leaf else max(0, len(components) - 1)
    for part in components[:limit]:
        current /= part
        if current.is_symlink():
            raise ContractError(f"symlink component is forbidden: {current}")
        if not current.exists():
            break


def walk_files_no_symlinks(root: Path) -> tuple[list[Path], list[Path]]:
    root = lexical_absolute(root)
    files: list[Path] = []
    symlinks: list[Path] = []
    if root.is_symlink():
        return files, [root]
    for directory, names, filenames in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        safe_names: list[str] = []
        for name in names:
            path = directory_path / name
            if path.is_symlink():
                symlinks.append(path)
            else:
                safe_names.append(name)
        names[:] = safe_names
        for name in filenames:
            path = directory_path / name
            if path.is_symlink():
                symlinks.append(path)
            else:
                files.append(path)
    return files, symlinks


def _reject_destination_symlink(parent_descriptor: int, name: str, destination: Path) -> None:
    try:
        metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode):
        raise ContractError(f"copy/write destination must not be a symlink: {destination}")


def atomic_write_text(path: str | Path, content: str) -> None:
    destination = lexical_absolute(path)
    parent_descriptor = open_directory_chain(destination.parent, create=True)
    temporary_name = f".{destination.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    temporary_descriptor: int | None = None
    try:
        _reject_destination_symlink(parent_descriptor, destination.name, destination)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        temporary_descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_descriptor)
        with os.fdopen(temporary_descriptor, "w", encoding="utf-8", newline="") as handle:
            temporary_descriptor = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(
            temporary_name,
            destination.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
    except OSError as exc:
        raise ContractError(f"secure write failed for {destination}: {exc}") from exc
    finally:
        if temporary_descriptor is not None:
            os.close(temporary_descriptor)
        try:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        os.close(parent_descriptor)


def secure_read_text(path: str | Path, *, errors: str = "strict") -> str:
    source = lexical_absolute(path)
    parent_descriptor = open_directory_chain(source.parent)
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(source.name, flags, dir_fd=parent_descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ContractError(f"source must be a regular file: {source}")
        with os.fdopen(descriptor, "r", encoding="utf-8", errors=errors) as handle:
            descriptor = None
            return handle.read()
    except OSError as exc:
        raise ContractError(f"secure read failed for {source}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)


def reject_duplicate_json_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    """Build an object while rejecting ambiguous duplicate JSON keys."""
    payload: dict[str, Any] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError(f"duplicate JSON object key: {key!r}")
        payload[key] = value
    return payload


def load_json(path: str | Path) -> Any:
    source = Path(path)
    try:
        return json.loads(secure_read_text(source), object_pairs_hook=reject_duplicate_json_keys)
    except (OSError, ValueError) as exc:
        raise ContractError(f"{source}: invalid JSON: {exc}") from exc


def write_json(path: str | Path, payload: object) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def write_jsonl(path: str | Path, records: Iterable[Mapping[str, Any]]) -> None:
    content = "".join(json.dumps(record, sort_keys=True) + "\n" for record in records)
    atomic_write_text(path, content)


def read_jsonl(path: str | Path, *, required: bool = True) -> list[dict[str, Any]]:
    source = Path(path)
    if not source.exists():
        if required:
            raise ContractError(f"{source}: JSONL file is missing")
        return []
    records: list[dict[str, Any]] = []
    try:
        content = secure_read_text(source)
    except UnicodeError as exc:
        raise ContractError(f"{source}: JSONL is not valid UTF-8: {exc}") from exc
    for line_number, line in enumerate(content.splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line, object_pairs_hook=reject_duplicate_json_keys)
        except ValueError as exc:
            raise ContractError(f"{source}:{line_number}: invalid JSON: {exc}") from exc
        if not isinstance(record, dict):
            raise ContractError(f"{source}:{line_number}: JSONL record must be an object")
        records.append(record)
    return records


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    source = lexical_absolute(path)
    parent_descriptor = open_directory_chain(source.parent)
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(source.name, flags, dir_fd=parent_descriptor)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ContractError(f"hash source must be a regular file: {source}")
        while True:
            chunk = os.read(descriptor, 131072)
            if not chunk:
                break
            digest.update(chunk)
    except OSError as exc:
        raise ContractError(f"secure hash failed for {source}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)
    return digest.hexdigest()


def git_value(root: Path, *arguments: str) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def git_worktree_clean(root: Path | None) -> bool:
    if root is None:
        return True
    status = git_value(root, "status", "--porcelain=v1", "--untracked-files=all")
    return status == ""


def compiler_version() -> str:
    compiler = os.environ.get("CC", "cc").split()[0]
    try:
        first_line = subprocess.run(
            [compiler, "--version"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        ).stdout.splitlines()[0]
        return first_line.strip() or "unknown"
    except (OSError, subprocess.CalledProcessError, IndexError):
        return "unknown"


def normalize_status(value: object) -> str:
    text = str(value or "").strip()
    if text in CASE_STATUSES:
        return text
    normalized = STATUS_ALIASES.get(text.lower().replace("-", "_"))
    if normalized is None:
        raise ContractError(f"unsupported case status: {value!r}")
    return normalized


def bool_value(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def optional_int(value: object) -> int | None:
    if value in (None, "", "null", "none", "not-run"):
        return None
    if isinstance(value, bool):
        raise ContractError(f"Boolean is not an integer status: {value!r}")
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ContractError(f"invalid integer: {value!r}") from exc


def canonical_case(raw: Mapping[str, Any], defaults: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(defaults)
    merged.update(raw)
    return merged


def catalog_cases(catalog: Mapping[str, Any]) -> list[dict[str, Any]]:
    defaults = catalog.get("defaults")
    cases = catalog.get("cases")
    if not isinstance(defaults, Mapping) or not isinstance(cases, list):
        raise ContractError("catalog requires defaults mapping and cases list")
    return [canonical_case(item, defaults) for item in cases if isinstance(item, Mapping)]


def normalize_artifact_profile(value: object) -> str:
    """Return a known profile while accepting profile-less legacy plan inputs."""
    profile = str(value or DEFAULT_ARTIFACT_PROFILE).strip()
    if profile not in ARTIFACT_PROFILES:
        raise ContractError(f"unsupported artifact profile: {profile!r}")
    return profile


def canonical_artifact_profile(payload: Mapping[str, Any], label: str) -> str:
    """Read an explicit profile from a canonical run artifact.

    A missing profile used to be interpreted as ``generic`` for backward
    compatibility.  That is safe only while accepting an external legacy plan
    before ``init`` stamps it.  Once an artifact is part of a canonical run,
    the profile is identity data and must never be inferred.
    """
    if "artifact_profile" not in payload:
        raise ContractError(f"{label}: missing artifact_profile")
    value = payload.get("artifact_profile")
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{label}: artifact_profile must be a non-empty string")
    return normalize_artifact_profile(value)


def normalize_host_profile(value: object, *, default: str = "default") -> str:
    """Return a stable host-profile label for newly initialized runs."""
    profile = str(value or "").strip()
    return profile or default


def canonical_host_profile(payload: Mapping[str, Any], label: str) -> str:
    """Read an explicit, non-empty host profile from a canonical artifact."""
    if "host_profile" not in payload:
        raise ContractError(f"{label}: missing host_profile")
    profile = payload.get("host_profile")
    if not isinstance(profile, str) or not profile.strip():
        raise ContractError(f"{label}: host_profile must be a non-empty string")
    return profile.strip()


def required_event_integration_mode(payload: Mapping[str, Any]) -> str | None:
    """Return the selected mode only for strict full-lifecycle evidence.

    Generic and compatibility artifacts retain optional event metadata. A
    selected full-lifecycle PASS, by contrast, must bind its raw event to the
    exact host integration recorded by its manifest/result.
    """

    if payload.get("artifact_profile") != FULL_LIFECYCLE_ARTIFACT_PROFILE:
        return None
    value = str(payload.get("integration_mode") or "").strip()
    return value or None


def validate_catalog(catalog: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if catalog.get("schema_version") != 1:
        errors.append("catalog.schema_version must be 1")
    if catalog.get("catalog") != "no-crs-baseline":
        errors.append("catalog.catalog must be no-crs-baseline")
    if catalog.get("full_lifecycle_artifact_profile") != FULL_LIFECYCLE_ARTIFACT_PROFILE:
        errors.append(
            "catalog.full_lifecycle_artifact_profile must be "
            f"{FULL_LIFECYCLE_ARTIFACT_PROFILE!r}"
        )
    try:
        cases = catalog_cases(catalog)
    except ContractError as exc:
        return [str(exc)]
    raw_cases = catalog.get("cases", [])
    if len(cases) != len(raw_cases):
        errors.append("every catalog case must be an object")
    required = (
        "case_id",
        "title",
        "phase",
        "required_capabilities",
        "request",
        "expected_result",
        "expected_status",
        "expected_rule_id",
        "expected_event_fields",
        "forbidden_event_fields",
        "connector_applicability",
        "unsupported_behavior",
        "evidence_requirement",
    )
    catalog_root = CATALOG_PATH.parent.resolve(strict=False)
    shared_fixture_root = (FRAMEWORK_ROOT / "tests/fixtures/no-crs-baseline").resolve(strict=False)

    def checked_fixture_path(
        raw_path: object,
        *,
        root: Path,
        label: str,
        case_id: str,
    ) -> None:
        if not isinstance(raw_path, str) or not raw_path.strip():
            errors.append(f"{case_id}: {label} must be a non-empty relative path")
            return
        candidate = (catalog_root / raw_path).resolve(strict=False)
        try:
            candidate.relative_to(root)
        except ValueError:
            errors.append(f"{case_id}: {label} must remain under {root}")
            return
        if not candidate.is_file():
            errors.append(f"{case_id}: {label} is missing: {candidate}")

    seen: set[str] = set()
    for case in cases:
        case_id = str(case.get("case_id") or "")
        prefix = case_id or "<missing-case-id>"
        if not case_id:
            errors.append("case requires case_id")
        elif case_id in seen:
            errors.append(f"duplicate case_id: {case_id}")
        seen.add(case_id)
        for field in required:
            if field not in case:
                errors.append(f"{prefix}: missing {field}")
        required_capabilities = case.get("required_capabilities")
        if not isinstance(required_capabilities, list) or not required_capabilities:
            errors.append(f"{prefix}: required_capabilities must be a non-empty list")
        else:
            unknown = sorted({str(item) for item in required_capabilities} - set(CAPABILITIES))
            if unknown:
                errors.append(f"{prefix}: unknown capabilities: {', '.join(unknown)}")
        if not isinstance(case.get("request"), Mapping):
            errors.append(f"{prefix}: request must be an object")
        if not isinstance(case.get("expected_event_fields"), list):
            errors.append(f"{prefix}: expected_event_fields must be a list")
        if not isinstance(case.get("forbidden_event_fields"), list):
            errors.append(f"{prefix}: forbidden_event_fields must be a list")
        if "transport_hardening" in case and not isinstance(case.get("transport_hardening"), bool):
            errors.append(f"{prefix}: transport_hardening must be Boolean")
        if case.get("transport_hardening") is True:
            if not str(case.get("group") or "").startswith("full-lifecycle-transport"):
                errors.append(f"{prefix}: transport_hardening cases must use the full-lifecycle transport namespace")
            required_transport_fields = {
                "run_id", "integration_mode", "transaction_id", "phase", "event", "message_id",
                "requested_action", "actual_action", "transport_result", "transport_case_id",
            }
            declared_transport_fields = {str(field) for field in case.get("expected_event_fields", [])}
            missing_transport_fields = sorted(required_transport_fields - declared_transport_fields)
            if missing_transport_fields:
                errors.append(
                    f"{prefix}: transport_hardening case is missing causal event fields: "
                    + ", ".join(missing_transport_fields)
                )
        if case.get("connector_applicability") != "capability_driven":
            errors.append(f"{prefix}: connector_applicability must be capability_driven")
        if case.get("unsupported_behavior") != "UNSUPPORTED":
            errors.append(f"{prefix}: unsupported_behavior must be UNSUPPORTED")
        evidence_requirement = case.get("evidence_requirement")
        if not isinstance(evidence_requirement, Mapping):
            errors.append(f"{prefix}: evidence_requirement must be an object")
        else:
            if evidence_requirement.get("requires_real_host") is not True:
                errors.append(f"{prefix}: evidence_requirement.requires_real_host must be true")
            if evidence_requirement.get("accepts_synthetic_pass") is not False:
                errors.append(f"{prefix}: evidence_requirement.accepts_synthetic_pass must be false")
        runner_case = case.get("runner_case")
        if runner_case:
            runner_path = CATALOG_PATH.parent / str(runner_case)
            if not runner_path.is_file():
                errors.append(f"{prefix}: runner_case is missing: {runner_path}")
        request = case.get("request")
        if isinstance(request, Mapping):
            if "fixture" in request:
                checked_fixture_path(
                    request.get("fixture"), root=catalog_root,
                    label="request.fixture", case_id=prefix,
                )
            if "fixture_file" in request:
                checked_fixture_path(
                    request.get("fixture_file"), root=shared_fixture_root,
                    label="request.fixture_file", case_id=prefix,
                )
    required_ids = {
        "allow_without_marker", "deny_header_marker_403", "deny_with_alternative_status",
        "transaction_id_present", "transaction_id_generated_or_fallback", "multiple_headers",
        "deny_request_body_marker_403", "deny_response_header_marker_403", "deny_response_body_marker_403",
        "phase4_rule_observed", "phase4_deny_before_commit",
        "phase4_deny_after_commit_log_only", "phase4_deny_after_commit_abort",
        "phase4_event_contains_original_status",
        "phase4_event_contains_late_intervention_action",
        "duplicate_header_names", "empty_header_value", "case_insensitive_header_name",
        "header_count_at_limit", "header_count_over_limit", "total_header_bytes_at_limit",
        "total_header_bytes_over_limit", "invalid_content_length", "conflicting_content_length",
        "duplicate_transfer_encoding", "content_length_overflow", "body_size_nonzero_with_null_data",
        "header_count_nonzero_with_null_headers", "event_contains_connector",
        "event_contains_transaction_id", "event_contains_rule_id", "event_contains_phase",
        "event_contains_status", "event_metadata_truncation", "event_has_no_request_body_payload",
        "event_has_no_response_body_payload", "event_json_limit", "valid_rules_file",
        "missing_rules_file", "invalid_rule_syntax", "unknown_config_key", "invalid_boolean",
        "invalid_status", "invalid_size", "unsafe_event_path", "single_request_cleanup",
        "multiple_sequential_requests", "keep_alive_requests_if_supported", "parallel_requests",
        "early_mapping_failure_cleanup", "transaction_begin_failure_cleanup",
        "finish_failure_propagation", "clean_shutdown", "allow", "deny", "log_only",
        "redirect_if_supported", "drop_if_supported", "abort_if_supported",
    }
    missing_ids = sorted((required_ids | FULL_LIFECYCLE_REQUIRED_IDS) - seen)
    if missing_ids:
        errors.append(f"catalog missing required cases: {', '.join(missing_ids)}")
    by_id = {str(case.get("case_id") or ""): case for case in cases}
    phase4_contracts = {
        "phase4_rule_observed": (
            "rule_observed",
            {"response_body_buffered", "phase4", "phase4_rule_evaluation", "event_jsonl"},
            {"event", "message_id", "rule_id", "phase"},
            None,
        ),
        "phase4_deny_before_commit": (
            "deny_before_commit",
            {
                "response_body_buffered", "phase4", "phase4_rule_evaluation",
                "phase4_pre_commit_deny", "deny", "late_intervention_status_metadata", "event_jsonl",
            },
            {
                "event", "message_id", "rule_id", "phase", "http_status", "requested_action", "actual_action",
                "original_http_status", "visible_http_status", "headers_sent", "connection_aborted",
            },
            403,
        ),
        "phase4_deny_after_commit_log_only": (
            "late_intervention_log_only",
            {
                "response_body_buffered", "phase4", "phase4_rule_evaluation", "late_intervention",
                "late_intervention_log_only", "late_intervention_status_metadata", "event_jsonl",
            },
            {
                "event", "message_id", "rule_id", "phase", "http_status", "requested_action", "actual_action",
                "original_http_status", "visible_http_status", "late_intervention", "headers_sent",
                "connection_aborted",
            },
            None,
        ),
        "phase4_deny_after_commit_abort": (
            "connection_aborted",
            {
                "response_body_buffered", "phase4", "phase4_rule_evaluation", "late_intervention",
                "late_intervention_abort", "late_intervention_status_metadata", "event_jsonl",
            },
            {
                "event", "message_id", "rule_id", "phase", "http_status", "requested_action", "actual_action",
                "original_http_status", "visible_http_status", "late_intervention", "headers_sent",
                "connection_aborted",
            },
            None,
        ),
        "phase4_event_contains_original_status": (
            "event_contains_original_status",
            {
                "response_body_buffered", "phase4", "phase4_rule_evaluation",
                "late_intervention_status_metadata", "event_jsonl",
            },
            {"event", "message_id", "rule_id", "phase", "http_status", "original_http_status", "visible_http_status"},
            None,
        ),
        "phase4_event_contains_late_intervention_action": (
            "event_contains_late_intervention_action",
            {
                "response_body_buffered", "phase4", "phase4_rule_evaluation",
                "late_intervention_status_metadata", "event_jsonl",
            },
            {"event", "message_id", "rule_id", "phase", "requested_action", "actual_action", "late_intervention"},
            None,
        ),
    }
    for case_id, (expected_result, required_capabilities, event_fields, expected_status) in phase4_contracts.items():
        case = by_id.get(case_id)
        if not case:
            continue
        if case.get("phase") != 4:
            errors.append(f"{case_id}: phase must be 4")
        if case.get("group") != "late-intervention":
            errors.append(f"{case_id}: group must be late-intervention")
        if case.get("expected_result") != expected_result:
            errors.append(f"{case_id}: expected_result must be {expected_result}")
        if optional_int(case.get("expected_rule_id")) != 1100301:
            errors.append(f"{case_id}: expected_rule_id must be 1100301")
        if optional_int(case.get("expected_status")) != expected_status:
            errors.append(f"{case_id}: expected_status is not canonical for its semantic outcome")
        declared_capabilities = {str(item) for item in case.get("required_capabilities", [])}
        missing_capabilities = sorted(required_capabilities - declared_capabilities)
        if missing_capabilities:
            errors.append(f"{case_id}: missing Phase-4 capabilities: {', '.join(missing_capabilities)}")
        declared_event_fields = {str(item) for item in case.get("expected_event_fields", [])}
        missing_event_fields = sorted(event_fields - declared_event_fields)
        if missing_event_fields:
            errors.append(f"{case_id}: missing Phase-4 event fields: {', '.join(missing_event_fields)}")
    for case_id in sorted(FULL_LIFECYCLE_REQUIRED_IDS):
        case = by_id.get(case_id)
        if not case:
            continue
        if not str(case.get("group") or "").startswith("full-lifecycle-"):
            errors.append(f"{case_id}: group must use the full-lifecycle namespace")
        requirement = case.get("evidence_requirement")
        if not isinstance(requirement, Mapping) or requirement.get("requires_real_host") is not True:
            errors.append(f"{case_id}: must retain the real-host evidence requirement")

    full_lifecycle_contracts = {
        "phase2_marker_split_across_chunks": (
            "request_marker_split_across_chunks", 2,
            {"request_body_incremental_ingest", "phase2", "event_jsonl"},
            {"marker_split_across_chunks", "body_bytes_seen", "body_bytes_inspected"},
        ),
        "phase3_deny_before_commit": (
            "phase3_deny_before_commit", 3,
            {"response_headers", "phase3", "deny", "transport_metadata", "event_jsonl"},
            {"requested_action", "actual_action", "headers_sent", "visible_http_status"},
        ),
        "phase3_redirect_before_commit": (
            "phase3_redirect_before_commit", 3,
            {"response_headers", "phase3", "redirect", "transport_metadata", "event_jsonl"},
            {"requested_action", "actual_action", "headers_sent", "visible_http_status"},
        ),
        "phase4_marker_split_across_chunks": (
            "marker_split_across_chunks", 4,
            {"response_body_incremental_ingest", "phase4", "phase4_end_of_stream_evaluation", "event_jsonl"},
            {"marker_split_across_chunks", "end_of_stream_evaluation"},
        ),
        "phase4_end_of_stream_evaluation": (
            "end_of_stream_evaluation", 4,
            {"response_body_incremental_ingest", "phase4", "phase4_end_of_stream_evaluation", "event_jsonl"},
            {"end_of_stream_evaluation", "body_started"},
        ),
        "phase4_deny_after_commit_log_only_minimal": (
            "late_intervention_log_only_minimal", 4,
            {"late_intervention", "late_intervention_log_only", "late_intervention_status_metadata", "event_jsonl"},
            {"late_intervention", "late_intervention_mode", "actual_action", "connection_aborted"},
        ),
        "phase4_deny_after_commit_log_only_safe": (
            "late_intervention_log_only_safe", 4,
            {"late_intervention", "late_intervention_log_only", "late_intervention_status_metadata", "event_jsonl"},
            {"late_intervention", "late_intervention_mode", "actual_action", "connection_aborted"},
        ),
        "phase4_deny_after_commit_abort_strict": (
            "connection_aborted_strict", 4,
            {"late_intervention", "late_intervention_abort", "late_intervention_status_metadata", "event_jsonl"},
            {"late_intervention", "late_intervention_mode", "actual_action", "connection_aborted"},
        ),
        "phase4_no_full_response_buffering": (
            "no_full_response_buffering", 4,
            {"response_body_incremental_ingest", "no_full_response_buffering", "first_byte_before_response_end", "event_jsonl"},
            {
                "no_full_response_buffering", "client_first_byte_received",
                "first_byte_before_response_end", "first_chunk_size", "upstream_paused",
                "upstream_eos_sent_at_first_byte", "upstream_response_finished_at_first_byte",
                "response_committed", "body_bytes_seen", "body_bytes_inspected",
            },
        ),
        "phase4_first_byte_before_response_end": (
            "first_byte_before_response_end", 4,
            {"response_body_incremental_ingest", "first_byte_before_response_end", "event_jsonl"},
            {
                "client_first_byte_received", "first_byte_before_response_end",
                "first_chunk_size", "upstream_paused", "upstream_eos_sent_at_first_byte",
                "upstream_response_finished_at_first_byte", "response_committed",
                "body_bytes_seen", "body_bytes_inspected",
            },
        ),
        "phase4_content_type_with_charset": (
            "content_type_in_scope_with_charset", 4,
            {"response_body_incremental_ingest", "phase4", "content_type_scope", "event_jsonl"},
            {"content_type", "content_type_scope"},
        ),
        "phase4_out_of_scope_content_type": (
            "content_type_out_of_scope", 4,
            {"response_body_incremental_ingest", "phase4", "content_type_scope", "event_jsonl"},
            {"content_type", "content_type_scope", "transport_result"},
        ),
        "phase4_missing_content_type": (
            "content_type_missing", 4,
            {"response_body_incremental_ingest", "phase4", "content_type_scope", "event_jsonl"},
            {"content_type_scope", "transport_result"},
        ),
    }
    for case_id, (expected_result, phase, required_capabilities, event_fields) in full_lifecycle_contracts.items():
        case = by_id.get(case_id)
        if not case:
            continue
        if case.get("expected_result") != expected_result:
            errors.append(f"{case_id}: expected_result must be {expected_result}")
        if case.get("phase") != phase:
            errors.append(f"{case_id}: phase must be {phase}")
        declared_capabilities = {str(item) for item in case.get("required_capabilities", [])}
        missing_capabilities = sorted(required_capabilities - declared_capabilities)
        if missing_capabilities:
            errors.append(f"{case_id}: missing full-lifecycle capabilities: {', '.join(missing_capabilities)}")
        declared_event_fields = {str(item) for item in case.get("expected_event_fields", [])}
        missing_event_fields = sorted(event_fields - declared_event_fields)
        if missing_event_fields:
            errors.append(f"{case_id}: missing full-lifecycle event fields: {', '.join(missing_event_fields)}")
    legacy = by_id.get("deny_response_body_marker_403")
    if legacy:
        if legacy.get("deprecated_alias_for") != "phase4_deny_before_commit":
            errors.append("deny_response_body_marker_403 must be a deprecated alias for phase4_deny_before_commit")
        if legacy.get("expected_result") != "legacy_phase4_deny_before_commit":
            errors.append("deny_response_body_marker_403 must retain strict pre-commit alias semantics")
        if optional_int(legacy.get("expected_status")) != 403:
            errors.append("deny_response_body_marker_403 must retain expected_status=403")
        if legacy.get("runner_case"):
            errors.append("deny_response_body_marker_403 is an alias and must not own a runner fixture")
    pre_commit = by_id.get("phase4_deny_before_commit")
    if pre_commit and pre_commit.get("runner_case") != "deny_response_body_marker_403.yaml":
        errors.append("phase4_deny_before_commit must own the legacy pre-commit runner fixture")
    if RULES_PATH.is_file():
        rules = RULES_PATH.read_text(encoding="utf-8")
        required_rule_contracts = (
            'REQUEST_HEADERS:X-Modsec-Smoke "@streq block"',
            "id:1100001,phase:1,deny,status:403",
            "id:1100002,phase:1,deny,status:429",
            "id:1100003,phase:1",
            "id:1100101,phase:2",
            "id:1100201,phase:3",
            "id:1100202,phase:3,redirect",
            "id:1100301,phase:4",
            "id:1100401,phase:1",
            "id:1100402,phase:1",
            "id:1100403,phase:1",
        )
        for contract in required_rule_contracts:
            if contract not in rules:
                errors.append(f"ruleset missing contract: {contract}")
        lowered = rules.lower()
        if "owasp-crs" in lowered or "coreruleset" in lowered or re.search(r"\binclude\b.*\bcrs\b", lowered):
            errors.append("canonical No-CRS ruleset must not include CRS")
        if any(token in lowered for token in ("%{request_body}", "%{response_body}", "%{http:authorization}")):
            errors.append("canonical ruleset must not log body or authorization payloads")
    else:
        errors.append(f"canonical ruleset missing: {RULES_PATH}")
    return errors


def load_catalog() -> dict[str, Any]:
    payload = load_json(CATALOG_PATH)
    if not isinstance(payload, dict):
        raise ContractError("catalog root must be an object")
    errors = validate_catalog(payload)
    if errors:
        raise ContractError("; ".join(errors))
    return payload


def capability_state(value: object) -> str:
    if isinstance(value, Mapping):
        value = value.get("state")
    return str(value or "")


def capability_manifest_header_errors(
    payload: Mapping[str, Any], connector: str | None,
) -> list[str]:
    errors: list[str] = []
    if payload.get("schema_version") != 1:
        errors.append("capability manifest schema_version must be 1")
    declared = str(payload.get("connector") or "")
    if declared not in CONNECTORS:
        errors.append(f"capability manifest connector is invalid: {declared!r}")
    if connector and declared != connector:
        errors.append(f"capability manifest connector mismatch: {declared!r} != {connector!r}")
    for field in ("host_name", "integration_mode"):
        if not str(payload.get(field) or "").strip():
            errors.append(f"capability manifest missing {field}")
    return errors


def capability_manifest_capability_errors(capabilities: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    capability_names = {str(key) for key in capabilities}
    missing = sorted(set(CAPABILITIES) - capability_names)
    if missing:
        errors.append(f"capability manifest missing capabilities: {', '.join(missing)}")
    unknown = sorted(capability_names - set(CAPABILITIES))
    if unknown:
        errors.append(f"capability manifest has unknown capabilities: {', '.join(unknown)}")
    for name in CAPABILITIES:
        state = capability_state(capabilities.get(name))
        if state not in CAPABILITY_STATES:
            errors.append(f"capability {name} has invalid state: {state!r}")
        value = capabilities.get(name)
        if isinstance(value, Mapping) and not str(value.get("reason") or "").strip():
            errors.append(f"capability {name} requires a non-empty reason")
    return errors


def capability_manifest_stage_errors(stages: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    stage_names = {str(key) for key in stages}
    missing_stages = sorted(set(EVIDENCE_STAGES) - stage_names)
    if missing_stages:
        errors.append(f"capability manifest missing evidence stages: {', '.join(missing_stages)}")
    for stage in EVIDENCE_STAGES:
        value = stages.get(stage)
        status = str(value.get("status") or "") if isinstance(value, Mapping) else str(value or "")
        if status not in EVIDENCE_STAGE_STATUSES:
            errors.append(f"evidence stage {stage} has invalid status: {status!r}")
        if isinstance(value, Mapping) and not str(value.get("reason") or "").strip():
            errors.append(f"evidence stage {stage} requires a non-empty reason")
    return errors


def validate_capability_manifest(payload: Mapping[str, Any], connector: str | None = None) -> list[str]:
    errors = capability_manifest_header_errors(payload, connector)
    capabilities = payload.get("capabilities")
    if not isinstance(capabilities, Mapping):
        errors.append("capability manifest capabilities must be an object")
        return errors
    errors.extend(capability_manifest_capability_errors(capabilities))
    stages = payload.get("evidence_stages")
    if not isinstance(stages, Mapping):
        errors.append("capability manifest evidence_stages must be an object")
    else:
        errors.extend(capability_manifest_stage_errors(stages))
    constraints = payload.get("host_model_constraints")
    if constraints is not None and not isinstance(constraints, list):
        errors.append("host_model_constraints must be a list")
    return errors


def load_capability_manifest(path: str | Path, connector: str | None = None) -> dict[str, Any]:
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise ContractError(f"{path}: capability manifest root must be an object")
    errors = validate_capability_manifest(payload, connector)
    if errors:
        raise ContractError("; ".join(errors))
    return payload


def validate_selection_profile(
    catalog: Mapping[str, Any], evidence_stage: str, artifact_profile: str,
) -> None:
    if artifact_profile != FULL_LIFECYCLE_ARTIFACT_PROFILE:
        return
    if evidence_stage != "no_crs_baseline":
        raise ContractError(
            "full_lifecycle artifact profile requires the no_crs_baseline evidence stage"
        )
    if catalog.get("full_lifecycle_artifact_profile") != artifact_profile:
        raise ContractError(
            "catalog does not declare the requested full_lifecycle artifact profile"
        )


def selected_catalog_cases(catalog: Mapping[str, Any], evidence_stage: str) -> list[dict[str, Any]]:
    cases = catalog_cases(catalog)
    if evidence_stage == "minimal_runtime_smoke":
        return [case for case in cases if case["case_id"] in MINIMAL_RUNTIME_CASE_IDS]
    return cases


def selection_status_for_states(states: Mapping[str, str]) -> str:
    if any(state == "unsupported_by_host_model" for state in states.values()):
        return "UNSUPPORTED"
    if any(state == "not_applicable" for state in states.values()):
        return "NOT_APPLICABLE"
    if any(state == "not_implemented" for state in states.values()):
        # A missing implementation is materially different from a host model
        # boundary. Keep the case visible without claiming it is executable.
        return "NOT_EXECUTED"
    return "SELECTED"


def selection_reason(
    states: Mapping[str, str], capabilities: Mapping[str, Any],
) -> str:
    reasons = []
    for name, state in states.items():
        value = capabilities[name]
        reason = str(value.get("reason") or "") if isinstance(value, Mapping) else ""
        reasons.append(f"{name}={state}" + (f" ({reason})" if reason else ""))
    return "; ".join(reasons)


def select_catalog_case(
    case: Mapping[str, Any], capabilities: Mapping[str, Any],
) -> dict[str, Any]:
    required = [str(item) for item in case["required_capabilities"]]
    states = {name: capability_state(capabilities[name]) for name in required}
    return {
        "case_id": case["case_id"],
        "group": case.get("group", ""),
        "phase": case["phase"],
        "required_capabilities": required,
        "required_capability_states": states,
        "selection_status": selection_status_for_states(states),
        "selection_reason": selection_reason(states, capabilities),
        "runner_case": case.get("runner_case"),
    }


def select_cases(
    connector: str,
    manifest: Mapping[str, Any],
    catalog: Mapping[str, Any],
    evidence_stage: str = "no_crs_baseline",
    artifact_profile: str = DEFAULT_ARTIFACT_PROFILE,
) -> dict[str, Any]:
    artifact_profile = normalize_artifact_profile(artifact_profile)
    validate_selection_profile(catalog, evidence_stage, artifact_profile)
    capabilities = manifest["capabilities"]
    cases = selected_catalog_cases(catalog, evidence_stage)
    selections = [select_catalog_case(case, capabilities) for case in cases]
    counts = Counter(item["selection_status"] for item in selections)
    return {
        "schema_version": 1,
        "connector": connector,
        "catalog": "no-crs-baseline",
        "ruleset": "no-crs-baseline",
        "evidence_stage": evidence_stage,
        "artifact_profile": artifact_profile,
        "capability_manifest": str(manifest.get("source_path") or ""),
        "generated_at": utc_now(),
        "counts": {name: counts.get(name, 0) for name in SELECTION_STATUSES},
        "cases": selections,
    }


def plan_semantics(plan: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": plan.get("schema_version"),
        "connector": plan.get("connector"),
        "catalog": plan.get("catalog"),
        "ruleset": plan.get("ruleset"),
        "evidence_stage": plan.get("evidence_stage"),
        "artifact_profile": str(
            plan.get("artifact_profile") or DEFAULT_ARTIFACT_PROFILE
        ),
        "counts": plan.get("counts"),
        "cases": plan.get("cases"),
    }


def validate_plan_against_capabilities(
    plan: Mapping[str, Any],
    connector: str,
    manifest: Mapping[str, Any],
    catalog: Mapping[str, Any],
    evidence_stage: str,
    artifact_profile: str = DEFAULT_ARTIFACT_PROFILE,
) -> None:
    expected = select_cases(
        connector, manifest, catalog, evidence_stage, artifact_profile
    )
    if plan_semantics(plan) != plan_semantics(expected):
        raise ContractError(
            "plan does not match a fresh capability-driven selection; regenerate it with the select command"
        )


def nearest_existing_directory(path: Path) -> Path:
    candidate = path
    while not candidate.exists():
        if candidate == candidate.parent:
            raise ContractError(f"no existing parent directory for run-dir: {path}")
        candidate = candidate.parent
    if not candidate.is_dir():
        raise ContractError(f"run-dir parent is not a directory: {candidate}")
    return candidate


def assert_private_run_parent(run_dir: Path) -> None:
    parent = nearest_existing_directory(run_dir.parent)
    metadata = parent.stat(follow_symlinks=False)
    if metadata.st_mode & stat.S_IWOTH:
        raise ContractError(f"run-dir parent must not be publicly writable: {parent}")


def safe_run_dir(run_dir: Path, connector_root: Path | None = None) -> None:
    if not run_dir.is_absolute():
        raise ContractError(f"run-dir must be absolute: {run_dir}")
    absolute = lexical_absolute(run_dir)
    assert_no_symlink_components(absolute)
    assert_private_run_parent(absolute)
    if str(absolute) in {"/", "/tmp", "/src"}:
        raise ContractError(f"unsafe run-dir: {absolute}")
    protected = [FRAMEWORK_ROOT.resolve(strict=False)]
    if connector_root is not None:
        protected.append(connector_root.resolve(strict=False))
    for checkout in protected:
        try:
            absolute.relative_to(checkout)
        except ValueError:
            continue
        raise ContractError(f"run-dir must not be inside a source checkout: {absolute}")


def artifact_entry(path: str, state: str, *, sha256: str | None = None, note: str = "") -> dict[str, Any]:
    entry: dict[str, Any] = {"path": path, "state": state}
    if sha256:
        entry["sha256"] = sha256
    if note:
        entry["note"] = note
    return entry


def initial_artifacts() -> dict[str, dict[str, Any]]:
    artifacts = {
        "manifest": artifact_entry(MANIFEST_FILE_NAME, "produced"),
        "result": artifact_entry(RESULT_FILE_NAME, "not_produced"),
        "case_results": artifact_entry(CASE_RESULTS_FILE_NAME, "not_produced"),
        "events": artifact_entry(EVENTS_FILE_NAME, "not_produced"),
        "stdout": artifact_entry("logs/stdout.log", "not_produced"),
        "stderr": artifact_entry("logs/stderr.log", "not_produced"),
        "host_log": artifact_entry("logs/host.log", "not_produced"),
        "first_byte_evidence": artifact_entry(FIRST_BYTE_EVIDENCE_RELATIVE_PATH, "not_produced"),
        "rule_load_log": artifact_entry("logs/rule-load.log", "not_produced"),
        "rules": artifact_entry(RULES_ARTIFACT_FILE_PATH, "produced"),
        "inventory": artifact_entry(RUN_INVENTORY_FILE_PATH, "produced"),
        "capability_manifest": artifact_entry(CAPABILITIES_INVENTORY_FILE_PATH, "produced"),
        "plan": artifact_entry(PLAN_FILE_NAME, "produced"),
    }
    # Inventory-only transport sidecars are initialized for every run so the
    # manifest has stable canonical paths.  They become mandatory only when a
    # transport-hardening case is promoted by the dedicated checker.
    artifacts.update({
        name: artifact_entry(path, "not_produced")
        for name, path in TRANSPORT_HARDENING_ARTIFACT_PATHS.items()
    })
    return artifacts


def require_fresh_run_dir(run_dir: Path, connector_root: Path | None) -> None:
    safe_run_dir(run_dir, connector_root)
    if os.path.lexists(run_dir):
        raise ContractError(f"init requires a fresh, nonexistent run-dir: {run_dir}")


def init_plan(
    args: argparse.Namespace,
    capabilities: Mapping[str, Any],
    catalog: Mapping[str, Any],
    artifact_profile: str,
    host_profile: str,
) -> dict[str, Any]:
    if args.plan:
        plan = load_json(args.plan)
        if not isinstance(plan, dict) or plan.get("connector") != args.connector:
            raise ContractError("plan is invalid or belongs to another connector")
        validate_plan_against_capabilities(
            plan, args.connector, capabilities, catalog, args.evidence_stage,
            artifact_profile,
        )
    else:
        plan = select_cases(
            args.connector, capabilities, catalog, args.evidence_stage,
            artifact_profile,
        )
    # A legacy external plan may predate artifact profiles. It is valid only
    # as an input to init; every persisted canonical artifact is explicit.
    plan["artifact_profile"] = artifact_profile
    plan["host_profile"] = host_profile
    return plan


def materialize_init_artifacts(
    run_dir: Path, capabilities_path: str, plan: Mapping[str, Any],
) -> None:
    for directory in (run_dir, run_dir / "logs", run_dir / "config", run_dir / "inventory"):
        descriptor = open_directory_chain(directory, create=True)
        os.close(descriptor)
    write_json(run_dir / PLAN_FILE_NAME, plan)
    copy_artifact(RULES_PATH, run_dir / RULES_ARTIFACT_FILE_PATH)
    copy_artifact(Path(capabilities_path), run_dir / CAPABILITIES_INVENTORY_FILE_PATH)


def init_run(args: argparse.Namespace) -> int:
    connector_root = Path(args.connector_root).resolve() if args.connector_root else None
    run_dir = Path(args.run_dir)
    artifact_profile = normalize_artifact_profile(args.artifact_profile)
    host_profile = normalize_host_profile(args.host_profile)
    require_fresh_run_dir(run_dir, connector_root)
    manifest_capabilities = load_capability_manifest(args.capabilities, args.connector)
    catalog = load_catalog()
    plan = init_plan(
        args, manifest_capabilities, catalog, artifact_profile, host_profile,
    )
    materialize_init_artifacts(run_dir, args.capabilities, plan)
    framework_commit = args.framework_commit or git_value(FRAMEWORK_ROOT, "rev-parse", "HEAD")
    connector_commit = args.connector_commit or (
        git_value(connector_root, "rev-parse", "HEAD") if connector_root else "unknown"
    )
    # Standalone framework/unit-test runs may intentionally have no connector
    # checkout.  Production evidence passes --connector-root and records both
    # repository states fail-closed.
    connector_worktree_clean = git_worktree_clean(connector_root)
    framework_worktree_clean = git_worktree_clean(FRAMEWORK_ROOT) if connector_root else True
    provenance_required = connector_root is not None
    executed_targets = list(args.executed_target or [
        f"{args.evidence_stage}-{args.connector}"
    ])
    inventory = {
        "schema_version": 1,
        "connector": args.connector,
        "run_id": args.run_id,
        "connector_commit": connector_commit,
        "framework_commit": framework_commit,
        "connector_worktree_clean": connector_worktree_clean,
        "framework_worktree_clean": framework_worktree_clean,
        "provenance_required": provenance_required,
        "connector_commit_at_finalize": connector_commit,
        "framework_commit_at_finalize": framework_commit,
        "host_name": manifest_capabilities["host_name"],
        "host_version": args.host_version or "not_available",
        "integration_mode": manifest_capabilities["integration_mode"],
        # A connector may expose both a compatibility path and a selected
        # full-lifecycle host path.  Keep that selection explicit in every
        # canonical artifact; it is never inferred from a target name.
        "host_profile": host_profile,
        "libmodsecurity_version": args.libmodsecurity_version or "not_available",
        "compiler_version": args.compiler_version or compiler_version(),
        "operating_system": platform.platform(),
        "architecture": platform.machine() or "unknown",
        "python_version": platform.python_version(),
        "evidence_stage": args.evidence_stage,
        "artifact_profile": artifact_profile,
        "ruleset": "no-crs-baseline",
        "rules_sha256": sha256_file(RULES_PATH),
        "catalog_sha256": sha256_file(CATALOG_PATH),
        "capability_manifest_sha256": sha256_file(run_dir / CAPABILITIES_INVENTORY_FILE_PATH),
        "executed_targets": executed_targets,
        "created_at": utc_now(),
    }
    write_json(run_dir / RUN_INVENTORY_FILE_PATH, inventory)
    artifacts = initial_artifacts()
    artifacts["rules"]["sha256"] = inventory["rules_sha256"]
    artifacts["inventory"]["sha256"] = sha256_file(run_dir / RUN_INVENTORY_FILE_PATH)
    artifacts["capability_manifest"]["sha256"] = inventory["capability_manifest_sha256"]
    artifacts["plan"]["sha256"] = sha256_file(run_dir / PLAN_FILE_NAME)
    manifest = {
        "schema_version": 1,
        "connector": args.connector,
        "run_id": args.run_id,
        "evidence_stage": args.evidence_stage,
        "artifact_profile": artifact_profile,
        "ruleset": "no-crs-baseline",
        "status": "NOT_EXECUTED",
        "started_at": utc_now(),
        "ended_at": None,
        "connector_commit": connector_commit,
        "framework_commit": framework_commit,
        "connector_worktree_clean": connector_worktree_clean,
        "framework_worktree_clean": framework_worktree_clean,
        "provenance_required": provenance_required,
        "connector_commit_at_finalize": connector_commit,
        "framework_commit_at_finalize": framework_commit,
        "host_name": manifest_capabilities["host_name"],
        "host_version": inventory["host_version"],
        "integration_mode": manifest_capabilities["integration_mode"],
        "host_profile": inventory["host_profile"],
        "libmodsecurity_version": args.libmodsecurity_version or inventory["libmodsecurity_version"],
        "compiler_version": inventory["compiler_version"],
        "operating_system": inventory["operating_system"],
        "architecture": inventory["architecture"],
        "rules": [RULES_ARTIFACT_FILE_PATH],
        "cases": [item["case_id"] for item in plan.get("cases", [])],
        "executed_targets": executed_targets,
        "capability_manifest": CAPABILITIES_INVENTORY_FILE_PATH,
        "artifacts": artifacts,
    }
    write_json(run_dir / MANIFEST_FILE_NAME, manifest)
    print(run_dir)
    return 0


def copy_artifact(source: Path, destination: Path) -> None:
    source = lexical_absolute(source)
    destination = lexical_absolute(destination)
    if source == destination:
        assert_no_symlink_components(source)
        if not source.is_file():
            raise ContractError(f"source artifact is missing: {source}")
        return
    source_parent = open_directory_chain(source.parent)
    destination_parent = open_directory_chain(destination.parent, create=True)
    source_descriptor: int | None = None
    temporary_descriptor: int | None = None
    temporary_name = f".{destination.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    try:
        _reject_destination_symlink(destination_parent, destination.name, destination)
        source_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        source_descriptor = os.open(source.name, source_flags, dir_fd=source_parent)
        if not stat.S_ISREG(os.fstat(source_descriptor).st_mode):
            raise ContractError(f"source artifact must be a regular file: {source}")
        destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        temporary_descriptor = os.open(temporary_name, destination_flags, 0o600, dir_fd=destination_parent)
        while True:
            chunk = os.read(source_descriptor, 131072)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(temporary_descriptor, view)
                view = view[written:]
        os.fsync(temporary_descriptor)
        os.close(temporary_descriptor)
        temporary_descriptor = None
        os.replace(
            temporary_name,
            destination.name,
            src_dir_fd=destination_parent,
            dst_dir_fd=destination_parent,
        )
    except OSError as exc:
        raise ContractError(f"secure artifact copy failed: {source} -> {destination}: {exc}") from exc
    finally:
        if source_descriptor is not None:
            os.close(source_descriptor)
        if temporary_descriptor is not None:
            os.close(temporary_descriptor)
        try:
            os.unlink(temporary_name, dir_fd=destination_parent)
        except FileNotFoundError:
            pass
        os.close(source_parent)
        os.close(destination_parent)


def source_records(payload: object) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [dict(item) for item in payload if isinstance(item, Mapping)]
    if not isinstance(payload, Mapping):
        return []
    records: list[dict[str, Any]] = []
    results = payload.get("results")
    if isinstance(results, list):
        records.extend(dict(item) for item in results if isinstance(item, Mapping))
    cases = payload.get("cases")
    if isinstance(cases, list):
        records.extend(dict(item) for item in cases if isinstance(item, Mapping))
    elif isinstance(cases, Mapping):
        for case_id, item in cases.items():
            if isinstance(item, Mapping):
                record = dict(item)
                record.setdefault("case_id", case_id)
                records.append(record)
    if any(key in payload for key in ("case_id", "case", "name")):
        records.append(dict(payload))
    return records


def event_field_names(value: object, prefix: str = "") -> set[str]:
    names: set[str] = set()
    if isinstance(value, Mapping):
        for key, nested in value.items():
            key_text = str(key)
            names.add(key_text)
            names.add(key_text.lower())
            nested_prefix = f"{prefix}.{key_text}" if prefix else key_text
            names.add(nested_prefix)
            names.update(event_field_names(nested, nested_prefix))
    elif isinstance(value, list):
        for item in value:
            names.update(event_field_names(item, prefix))
    return names


def recursive_values(value: object, names: set[str]) -> list[object]:
    values: list[object] = []
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if str(key).lower() in names:
                values.append(nested)
            values.extend(recursive_values(nested, names))
    elif isinstance(value, list):
        for item in value:
            values.extend(recursive_values(item, names))
    return values


def event_rule_ids(event: Mapping[str, Any]) -> list[int]:
    identifiers: list[int] = []
    for value in recursive_values(event, {"rule_id", "ruleid", "id"}):
        candidates = value if isinstance(value, list) else [value]
        for candidate in candidates:
            try:
                identifier = int(candidate)
            except (TypeError, ValueError):
                continue
            if 1100001 <= identifier <= 1100999 and identifier not in identifiers:
                identifiers.append(identifier)
    return identifiers


def event_transaction_ids(event: Mapping[str, Any]) -> list[str]:
    values = recursive_values(event, {"transaction_id", "transactionid", "tx_id", "txid"})
    return [str(value) for value in values if str(value).strip()]


def event_for_rule(events: Sequence[Mapping[str, Any]], rule_id: int | None) -> Mapping[str, Any] | None:
    if rule_id is None:
        return events[0] if events else None
    return next((event for event in events if rule_id in event_rule_ids(event)), None)


def supplied_transaction_ids(raw: Mapping[str, Any]) -> list[str]:
    transaction_ids: list[str] = []
    values = raw.get("transaction_ids")
    if isinstance(values, list):
        transaction_ids.extend(str(item) for item in values if str(item).strip())
    for key in ("transaction_id", "tx_id"):
        if str(raw.get(key) or "").strip():
            transaction_ids.append(str(raw[key]))
    return sorted(dict.fromkeys(transaction_ids))


def normalize_canonical_phase(value: object) -> int | None:
    """Map closed Common phase labels to the framework's rule-phase numbers.

    Common distinguishes URI parsing from request-header processing, whereas
    both are canonical ModSecurity phase 1 evidence.  Only the published
    Common labels and canonical integer values are accepted so that an
    arbitrary phase string cannot silently become usable evidence.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value in CANONICAL_PHASES else None
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if normalized in COMMON_PHASE_TO_CANONICAL:
        return COMMON_PHASE_TO_CANONICAL[normalized]
    if normalized in {str(phase) for phase in CANONICAL_PHASES}:
        return int(normalized)
    return None


def canonicalize_event_phase(
    event: Mapping[str, Any], *, location: str = "event",
) -> dict[str, Any]:
    """Copy an accepted event and store its phase in canonical numeric form."""
    normalized = dict(event)
    if "phase" not in normalized:
        return normalized
    phase = normalize_canonical_phase(normalized["phase"])
    if phase is None:
        raise ContractError(
            f"{location}.phase: unsupported Common/canonical phase {normalized['phase']!r}"
        )
    normalized["phase"] = phase
    return normalized


EVENT_PROTOCOL_NORMALIZATION_FIELDS = (
    "transport_protocol",
    "requested_protocol",
    "downstream_protocol",
    "upstream_protocol",
    "negotiated_protocol",
    "transport",
    "alpn",
    "stream_id",
    "transport_case_id",
    "barrier_id",
    "connection_id",
    "quic_connection_id_present",
    "quic_version",
    "fallback_used",
    "stream_reset",
    "stream_reset_code",
    "connection_reused",
    "client_disconnected",
    "upstream_disconnected",
    "cancelled",
    "reset_by",
    "reset_code",
    "timeout_stage",
    "write_result",
    "eos_seen",
    "cleanup_reason",
)


def canonicalize_event_protocol_provenance(
    event: Mapping[str, Any], *, location: str = "event",
) -> dict[str, Any]:
    """Normalize accepted protocol aliases before writing canonical JSONL.

    Flat Common events may serialize empty optional fields.  Empty values stay
    empty (and non-promoting), while non-empty aliases such as ``HTTP/3`` are
    rewritten to their closed canonical form.
    """
    normalized = dict(event)
    for field in EVENT_PROTOCOL_NORMALIZATION_FIELDS:
        if field not in normalized:
            continue
        value = normalized[field]
        if _empty_runtime_value(value):
            continue
        try:
            canonical = normalize_semantic_value(field, value)
        except ContractError as exc:
            raise ContractError(f"{location}.{field}: invalid transport provenance") from exc
        if canonical is None:
            raise ContractError(f"{location}.{field}: unsupported transport provenance value {value!r}")
        normalized[field] = canonical
    return normalized


def has_valid_first_byte_measurements(event: Mapping[str, Any]) -> bool:
    first_chunk_size = event.get("first_chunk_size")
    body_bytes_seen = event.get("body_bytes_seen")
    body_bytes_inspected = event.get("body_bytes_inspected")
    integer_values = (first_chunk_size, body_bytes_seen, body_bytes_inspected)
    if any(isinstance(value, bool) or not isinstance(value, int) for value in integer_values):
        return False
    if first_chunk_size < 1 or body_bytes_seen < 0 or body_bytes_inspected < 0:
        return False
    return body_bytes_inspected <= body_bytes_seen


def has_first_byte_barrier_flags(event: Mapping[str, Any]) -> bool:
    expected_flags = {
        "client_first_byte_received": True,
        "first_byte_before_response_end": True,
        "upstream_paused": True,
        "upstream_eos_sent_at_first_byte": False,
        "upstream_response_finished_at_first_byte": False,
        "response_committed": True,
    }
    return all(event.get(field) is expected for field, expected in expected_flags.items())


def phase4_first_byte_barrier_matches(
    event: Mapping[str, Any], *, require_no_full_response_buffering: bool,
) -> bool:
    """Return whether a Phase-4 event is the complete streaming barrier proof.

    A single host run can emit ordinary Phase-4 events before the synchronized
    streaming event. Rule ID alone is therefore insufficient to associate a
    first-byte case with its complete causal barrier.
    """
    if not has_valid_first_byte_measurements(event):
        return False
    if not has_first_byte_barrier_flags(event):
        return False
    return not require_no_full_response_buffering or event.get("no_full_response_buffering") is True


def phase4_end_of_stream_matches(event: Mapping[str, Any]) -> bool:
    return event.get("end_of_stream_evaluation") is True and event.get("eos_seen") is True


def phase4_action_outcome_matches(event: Mapping[str, Any], expected_result: str) -> bool:
    requested = str(event.get("requested_action") or "").strip().lower().replace("-", "_")
    actual = str(event.get("actual_action") or "").strip().lower().replace("-", "_")
    actual = {"connection_abort": "abort_connection"}.get(actual, actual)
    denied_before_commit = requested == "deny" and actual == "deny" and event.get("headers_sent") is False
    log_only = requested == "deny" and actual == "log_only" and event.get("late_intervention") is True
    connection_aborted = (
        requested == "deny"
        and actual in {"abort_connection", "stream_reset"}
        and (event.get("connection_aborted") is True or event.get("stream_reset") is True)
    )
    return {
        "deny_before_commit": denied_before_commit,
        "legacy_phase4_deny_before_commit": denied_before_commit,
        "late_intervention_log_only": log_only,
        "late_intervention_log_only_minimal": log_only and event.get("late_intervention_mode") == "minimal",
        "late_intervention_log_only_safe": log_only and event.get("late_intervention_mode") == "safe",
        "connection_aborted": connection_aborted,
        "connection_aborted_strict": connection_aborted and event.get("late_intervention_mode") == "strict",
        "event_contains_late_intervention_action": (
            requested == "deny" and actual in {"deny", "log_only", "abort_connection"}
        ),
    }.get(expected_result, False)


def phase4_event_matches_outcome(event: Mapping[str, Any], expected_result: str) -> bool:
    """Identify the right event when one run contains several Phase-4 paths."""
    if normalize_canonical_phase(event.get("phase")) != 4:
        return False
    if expected_result == "end_of_stream_evaluation":
        # A host can emit its Common rule decision before it publishes the
        # causal post-EOS outcome.  Do not let that earlier rule-only event
        # satisfy the dedicated EOS case merely because it shares phase/rule
        # metadata with a later verified barrier event.
        return phase4_end_of_stream_matches(event)
    if expected_result in {
        "rule_observed", "event_contains_original_status", "marker_split_across_chunks",
        "content_type_in_scope",
        "content_type_in_scope_with_charset", "content_type_out_of_scope",
        "content_type_missing", "response_body_at_limit",
        "response_body_over_limit", "response_body_process_partial", "response_body_reject",
    }:
        return True
    if expected_result == "no_full_response_buffering":
        return phase4_first_byte_barrier_matches(
            event, require_no_full_response_buffering=True,
        )
    if expected_result == "first_byte_before_response_end":
        return phase4_first_byte_barrier_matches(
            event, require_no_full_response_buffering=False,
        )
    return phase4_action_outcome_matches(event, expected_result)


def events_for_rule(
    events: Sequence[Mapping[str, Any]], rule_id: int | None,
) -> list[Mapping[str, Any]]:
    if rule_id is None:
        return list(events)
    return [event for event in events if rule_id in event_rule_ids(event)]


def events_for_transactions(
    candidates: Sequence[Mapping[str, Any]], transaction_ids: Sequence[str],
) -> list[Mapping[str, Any]]:
    supplied = {str(value) for value in transaction_ids if str(value).strip()}
    if not supplied:
        return list(candidates)
    return [
        event for event in candidates
        if supplied.intersection(event_transaction_ids(event))
    ]


def preferred_integration_mode_events(
    candidates: Sequence[Mapping[str, Any]], integration_mode: str | None,
) -> list[Mapping[str, Any]]:
    if not integration_mode:
        return list(candidates)
    # A raw event from a compatibility path must not satisfy a selected native
    # host profile simply because connector, rule, and transaction IDs overlap.
    # Retain unmatched candidates for the caller's specific mismatch diagnostic.
    matched_mode = [
        event for event in candidates if event.get("integration_mode") == integration_mode
    ]
    return matched_mode or list(candidates)


def phase4_outcome_event(
    candidates: Sequence[Mapping[str, Any]], case: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    if not is_phase4_semantic_case(case):
        return None
    expected_result = str(case.get("expected_result") or "")
    return next(
        (
            event for event in candidates
            if phase4_event_matches_outcome(event, expected_result)
        ),
        None,
    )


def confirmed_event_for_case(
    candidates: Sequence[Mapping[str, Any]], case: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    # A Common rule-decision event can precede the host action.  When the same
    # transaction later publishes a bounded, host-confirmed outcome, prefer
    # that outcome for a non-Phase-4 case.  Do not manufacture a match: the
    # visible status must agree with the catalog's expected status whenever it
    # has one, otherwise retain the original decision event for validation.
    expected_status = optional_int(case.get("expected_status"))
    confirmed = [
        event
        for event in candidates
        if str(event.get("transport_result") or "")
        in {"http_status", "log_only", "connection_aborted", "stream_reset"}
        and (
            expected_status is None
            or optional_int(event.get("visible_http_status")) == expected_status
        )
    ]
    if confirmed:
        return confirmed[-1]
    return None


def event_for_case(
    events: Sequence[Mapping[str, Any]],
    rule_id: int | None,
    case: Mapping[str, Any],
    transaction_ids: Sequence[str] = (),
    integration_mode: str | None = None,
) -> Mapping[str, Any] | None:
    candidates = events_for_transactions(events_for_rule(events, rule_id), transaction_ids)
    if not candidates:
        return None
    candidates = preferred_integration_mode_events(candidates, integration_mode)
    phase4_event = phase4_outcome_event(candidates, case)
    if phase4_event is not None:
        return phase4_event
    return confirmed_event_for_case(candidates, case) or candidates[0]


def canonical_core_event_contract(
    events: Sequence[Mapping[str, Any]],
    connector: str,
    integration_mode: str | None = None,
) -> tuple[bool, bool]:
    """Return metadata and payload-absence evidence for the rule-1100001 event."""
    payload_absent = bool(events) and not any(
        canonical_event_errors(
            event,
            connector=connector,
            integration_mode=integration_mode,
        )
        for event in events
    )
    if not payload_absent:
        # A malformed or unreviewed event is not usable to establish either
        # canonical metadata evidence or the payload-absence claim.
        return False, False
    candidates = [event for event in events if 1100001 in event_rule_ids(event)]
    if integration_mode:
        candidates = [
            event for event in candidates
            if event.get("integration_mode") == integration_mode
        ]
    event = candidates[-1] if candidates else None
    if event is None:
        return False, payload_absent
    fields = event_field_names(event)
    required_fields = {"connector", "transaction_id", "rule_id", "phase", "status"}
    connector_values = {
        str(value).strip() for value in recursive_values(event, {"connector"})
        if str(value).strip()
    }
    phase_values = [value for value in recursive_values(event, {"phase"}) if str(value).strip()]
    status_values = [value for value in recursive_values(event, {"status"}) if str(value).strip()]
    metadata_verified = bool(
        required_fields.issubset(fields)
        and connector in connector_values
        and event_transaction_ids(event)
        and 1100001 in event_rule_ids(event)
        and phase_values
        and status_values
    )
    return metadata_verified, payload_absent


def concrete_version(value: object) -> bool:
    normalized = re.sub(r"[\s-]+", "_", str(value or "").strip().lower())
    if not normalized:
        return False
    placeholders = {
        "unknown", "not_available", "not_provisioned", "not_provided", "unavailable",
        "none", "null", "n/a", "na",
    }
    return normalized not in placeholders and not any(
        marker in normalized
        for marker in ("not_available", "not_provisioned", "not_provided", "version_unavailable")
    )


_MISSING = object()
_RAW_SEMANTIC_FIELD_ALIASES = {
    "http_status": ("http_status", "waf_status", "intervention_status"),
    "requested_action": ("requested_action", "wanted_action"),
    "actual_action": ("actual_action",),
    "original_http_status": ("original_http_status", "upstream_status"),
    "visible_http_status": ("visible_http_status", "client_status"),
    "late_intervention": ("late_intervention", "intervention"),
    "headers_sent": ("headers_sent", "header_sent"),
    "response_started": ("response_started",),
    "body_started": ("body_started", "response_body_seen"),
    "body_truncated": ("body_truncated", "response_body_truncated"),
    "response_committed": ("response_committed",),
    "connection_aborted": ("connection_aborted", "strict_abort"),
    "transport_result": ("transport_result", "observed_transport_result"),
    "late_intervention_mode": ("late_intervention_mode", "phase4_mode"),
    "content_type_scope": ("content_type_scope", "scope_result"),
    "body_limit_outcome": ("body_limit_outcome", "limit_outcome"),
    "marker_split_across_chunks": ("marker_split_across_chunks",),
    "end_of_stream_evaluation": ("end_of_stream_evaluation",),
    "no_full_response_buffering": ("no_full_response_buffering",),
    "first_byte_before_response_end": ("first_byte_before_response_end",),
    "upstream_response_finished_at_first_byte": (
        "upstream_response_finished_at_first_byte",
        "upstream_response_complete_at_first_byte",
    ),
    "client_first_byte_received": ("client_first_byte_received",),
    "first_chunk_size": ("first_chunk_size",),
    "upstream_paused": ("upstream_paused",),
    "upstream_eos_sent_at_first_byte": ("upstream_eos_sent_at_first_byte",),
    "transport_protocol": ("transport_protocol", "protocol"),
    "requested_protocol": ("requested_protocol",),
    "downstream_protocol": ("downstream_protocol",),
    "upstream_protocol": ("upstream_protocol",),
    "negotiated_protocol": ("negotiated_protocol",),
    "transport": ("transport",),
    "alpn": ("alpn",),
    "stream_id": ("stream_id",),
    "transport_case_id": ("transport_case_id", "protocol_case_id"),
    "barrier_id": ("barrier_id",),
    "connection_id": ("connection_id",),
    "transfer_encoding": ("transfer_encoding",),
    "connection_reused": ("connection_reused", "keep_alive_reused"),
    "quic_connection_id_present": ("quic_connection_id_present",),
    "quic_version": ("quic_version",),
    "fallback_used": ("fallback_used",),
    "stream_reset": ("stream_reset", "stream_reset_observed"),
    "stream_reset_code": ("stream_reset_code",),
    "client_aborted": ("client_aborted",),
    "upstream_aborted": ("upstream_aborted",),
    "client_disconnected": ("client_disconnected", "client_disconnect"),
    "upstream_disconnected": ("upstream_disconnected", "upstream_disconnect"),
    "cancelled": ("cancelled", "client_cancelled"),
    "reset_by": ("reset_by",),
    "reset_code": ("reset_code",),
    "timeout_stage": ("timeout_stage",),
    "write_result": ("write_result",),
    "eos_seen": ("eos_seen", "eos_received"),
    "cleanup_reason": ("cleanup_reason",),
}


def optional_bool(value: object) -> bool | None:
    if value in (None, "", "null", "none", "not-run"):
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    raise ContractError(f"invalid Boolean: {value!r}")


def normalize_action(value: object, allowed: set[str]) -> str | None:
    if value in (None, "", "null", "none", "not-run"):
        return None
    action = str(value).strip().lower().replace("-", "_")
    # This is the one legacy spelling emitted by existing host adapters.  The
    # canonical event vocabulary is deliberately only ``abort_connection``.
    if action == "connection_abort":
        action = "abort_connection"
    return action if action in allowed else None


def normalize_transport_result(value: object) -> str | None:
    if value in (None, "", "null", "none", "not-run"):
        return None
    transport = str(value).strip().lower().replace("-", "_")
    if transport == "aborted":
        transport = "connection_aborted"
    return transport if transport in TRANSPORT_RESULTS else None


def normalize_transport_enum(
    value: object, *, allowed: set[str], field: str,
) -> str | None:
    """Normalize a closed, metadata-only transport vocabulary."""
    if _empty_runtime_value(value):
        return None
    normalized = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    if normalized not in allowed:
        return None
    return normalized


def _empty_runtime_value(value: object) -> bool:
    """Return whether an optional host value is intentionally absent."""
    return value in (None, "", "null", "none", "not-run")


def normalize_protocol(value: object) -> str | None:
    """Normalize a host spelling into the closed protocol vocabulary.

    The accepted aliases are input compatibility only.  Canonical artifacts
    always serialize one of http1, h2, h2c, or h3; ambiguous labels such as
    ``http3_fallback`` intentionally have no mapping.
    """
    if _empty_runtime_value(value):
        return None
    normalized = str(value).strip().lower().replace("_", "").replace(" ", "")
    aliases = {
        "http1": "http1",
        "http/1": "http1",
        "http/1.0": "http1",
        "http/1.1": "http1",
        "http10": "http1",
        "http11": "http1",
        "h1": "http1",
        "h2": "h2",
        "http2": "h2",
        "http/2": "h2",
        "http/2.0": "h2",
        "h2c": "h2c",
        "http2c": "h2c",
        "http/2c": "h2c",
        "h3": "h3",
        "http3": "h3",
        "http/3": "h3",
        "http/3.0": "h3",
    }
    return aliases.get(normalized)


def normalize_legacy_transport_protocol(value: object) -> str | None:
    """Normalize only the legacy http1/http2 result field.

    H2 is intentionally rendered as its historical ``http2`` value here;
    h3 has no legacy representation and must use negotiated_protocol.
    """
    protocol = normalize_protocol(value)
    return {"http1": "http1", "h2": "http2"}.get(protocol)


def normalize_transport(value: object) -> str | None:
    if _empty_runtime_value(value):
        return None
    normalized = str(value).strip().lower().replace("/", "_").replace("-", "_")
    aliases = {
        "tcp": "tcp",
        "tls_tcp": "tls_tcp",
        "tlstcp": "tls_tcp",
        "quic_udp": "quic_udp",
        "quicudp": "quic_udp",
    }
    return aliases.get(normalized)


def normalize_bounded_token(
    value: object, *, maximum: int, field: str, allow_slash: bool = False,
) -> str | None:
    if _empty_runtime_value(value):
        return None
    if not isinstance(value, str):
        raise ContractError(f"invalid {field}: expected a string")
    normalized = value.strip()
    pattern = r"[A-Za-z0-9:._/-]+" if allow_slash else r"[A-Za-z0-9:._-]+"
    if not normalized or len(normalized) > maximum or re.fullmatch(pattern, normalized) is None:
        raise ContractError(f"invalid {field}: expected a bounded token")
    return normalized


def normalize_stream_id(value: object) -> int | None:
    normalized = optional_int(value)
    if normalized is None:
        return None
    if normalized < 0 or normalized > MAX_STREAM_ID:
        raise ContractError(f"invalid stream_id: {value!r}")
    return normalized


def normalize_stream_reset_code(value: object) -> int | str | None:
    if _empty_runtime_value(value):
        return None
    if isinstance(value, bool):
        raise ContractError(f"invalid stream_reset_code: {value!r}")
    if isinstance(value, int):
        if value < 0 or value > MAX_STREAM_ID:
            raise ContractError(f"invalid stream_reset_code: {value!r}")
        return value
    return normalize_bounded_token(value, maximum=64, field="stream_reset_code")


def is_hashed_connection_id(value: object) -> bool:
    """Allow only a bounded non-reversible identifier for QUIC evidence."""
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{16,64}", value) is not None


def normalize_enum_semantic_value(value: object, allowed: set[str]) -> str | None:
    normalized = str(value or "").strip().lower().replace("-", "_")
    return normalized if normalized in allowed else None


def normalize_requested_action(value: object) -> str | None:
    return normalize_action(value, REQUESTED_ACTIONS)


def normalize_actual_action(value: object) -> str | None:
    return normalize_action(value, ACTUAL_ACTIONS)


def normalize_late_intervention_mode(value: object) -> str | None:
    return normalize_enum_semantic_value(value, LATE_INTERVENTION_MODES)


def normalize_content_type_scope(value: object) -> str | None:
    return normalize_enum_semantic_value(value, CONTENT_TYPE_SCOPES)


def normalize_body_limit_outcome(value: object) -> str | None:
    return normalize_enum_semantic_value(value, BODY_LIMIT_OUTCOMES)


def normalize_transfer_encoding(value: object) -> str | None:
    return normalize_enum_semantic_value(value, TRANSFER_ENCODINGS)


def normalize_alpn(value: object) -> str | None:
    return normalize_bounded_token(value, maximum=64, field="alpn", allow_slash=True)


def normalize_transport_case_id(value: object) -> str | None:
    return normalize_bounded_token(value, maximum=128, field="transport_case_id")


def normalize_barrier_id(value: object) -> str | None:
    return normalize_bounded_token(value, maximum=128, field="barrier_id")


def normalize_connection_id(value: object) -> str | None:
    return normalize_bounded_token(value, maximum=128, field="connection_id")


def normalize_quic_version(value: object) -> str | None:
    return normalize_bounded_token(value, maximum=64, field="quic_version")


def normalize_reset_by(value: object) -> str | None:
    return normalize_transport_enum(value, allowed=RESET_BY_VALUES, field="reset_by")


def normalize_timeout_stage(value: object) -> str | None:
    return normalize_transport_enum(value, allowed=TIMEOUT_STAGES, field="timeout_stage")


def normalize_write_result(value: object) -> str | None:
    return normalize_transport_enum(value, allowed=WRITE_RESULTS, field="write_result")


def normalize_cleanup_reason(value: object) -> str | None:
    return normalize_transport_enum(value, allowed=CLEANUP_REASONS, field="cleanup_reason")


SEMANTIC_VALUE_NORMALIZERS: dict[str, Callable[[object], object]] = {
    **dict.fromkeys(
        {"http_status", "original_http_status", "visible_http_status", "first_chunk_size"},
        optional_int,
    ),
    "stream_id": normalize_stream_id,
    **dict.fromkeys(
        {
            "late_intervention", "headers_sent", "response_started", "body_started", "body_truncated",
            "response_committed", "connection_aborted", "marker_split_across_chunks",
            "end_of_stream_evaluation", "no_full_response_buffering",
            "first_byte_before_response_end", "upstream_response_finished_at_first_byte",
            "client_first_byte_received", "upstream_paused", "upstream_eos_sent_at_first_byte",
            "connection_reused", "quic_connection_id_present", "fallback_used", "stream_reset",
            "client_aborted", "upstream_aborted", "client_disconnected", "upstream_disconnected",
            "cancelled", "eos_seen",
        },
        optional_bool,
    ),
    "requested_action": normalize_requested_action,
    "actual_action": normalize_actual_action,
    "transport_result": normalize_transport_result,
    "late_intervention_mode": normalize_late_intervention_mode,
    "content_type_scope": normalize_content_type_scope,
    "body_limit_outcome": normalize_body_limit_outcome,
    "transport_protocol": normalize_legacy_transport_protocol,
    **dict.fromkeys(
        {"requested_protocol", "downstream_protocol", "upstream_protocol", "negotiated_protocol"},
        normalize_protocol,
    ),
    "transport": normalize_transport,
    "alpn": normalize_alpn,
    "transport_case_id": normalize_transport_case_id,
    "barrier_id": normalize_barrier_id,
    "connection_id": normalize_connection_id,
    "quic_version": normalize_quic_version,
    "stream_reset_code": normalize_stream_reset_code,
    "reset_code": normalize_stream_reset_code,
    "reset_by": normalize_reset_by,
    "timeout_stage": normalize_timeout_stage,
    "write_result": normalize_write_result,
    "cleanup_reason": normalize_cleanup_reason,
    "transfer_encoding": normalize_transfer_encoding,
}


def normalize_semantic_value(field: str, value: object) -> object:
    normalizer = SEMANTIC_VALUE_NORMALIZERS.get(field)
    if normalizer is None:
        raise ContractError(f"unsupported semantic field: {field}")
    return normalizer(value)


def raw_semantic_value(raw: Mapping[str, Any], field: str) -> object:
    for name in _RAW_SEMANTIC_FIELD_ALIASES[field]:
        if name in raw:
            return raw[name]
    return _MISSING


def normalized_runtime_value(
    field: str, value: object, source: str,
) -> tuple[object, list[str]]:
    if value is _MISSING:
        return _MISSING, []
    try:
        return normalize_semantic_value(field, value), []
    except ContractError:
        return _MISSING, [f"{field}: invalid {source} runtime value"]


def invalid_transport_claim_error(
    field: str, source: str, raw_value: object, normalized: object,
) -> list[str]:
    if field not in TRANSPORT_CLAIM_FIELDS:
        return []
    if raw_value is _MISSING or _empty_runtime_value(raw_value) or normalized is not None:
        return []
    return [f"{field}: invalid {source} runtime value"]


def semantic_field_value(
    raw: Mapping[str, Any], matching_event: Mapping[str, Any] | None, field: str,
) -> tuple[object, list[str]]:
    raw_value = raw_semantic_value(raw, field)
    event_value = matching_event.get(field, _MISSING) if matching_event else _MISSING
    raw_normalized, errors = normalized_runtime_value(field, raw_value, "raw")
    event_normalized, event_errors = normalized_runtime_value(field, event_value, "event")
    errors.extend(event_errors)
    errors.extend(invalid_transport_claim_error(field, "raw", raw_value, raw_normalized))
    errors.extend(invalid_transport_claim_error(field, "event", event_value, event_normalized))
    if (
        raw_normalized is not _MISSING
        and event_normalized is not _MISSING
        and raw_normalized != event_normalized
    ):
        errors.append(f"{field}: raw and event runtime evidence disagree")
    if raw_normalized is not _MISSING:
        return raw_normalized, errors
    if event_normalized is not _MISSING:
        return event_normalized, errors
    return None, errors


def reject_raw_quic_connection_id(values: dict[str, object], errors: list[str]) -> None:
    effective_downstream = values.get("negotiated_protocol") or values.get("downstream_protocol")
    if effective_downstream != "h3" and values.get("transport") != "quic_udp":
        return
    connection_id = values.get("connection_id")
    if connection_id is not None and not is_hashed_connection_id(connection_id):
        # Do not let a failed/non-promoting source record persist a raw QUIC
        # CID in canonical case JSONL either.
        values["connection_id"] = None
        errors.append("connection_id: raw QUIC connection identifiers are forbidden")


def semantic_runtime_fields(
    raw: Mapping[str, Any], matching_event: Mapping[str, Any] | None,
) -> tuple[dict[str, object], list[str]]:
    """Project only known runtime evidence into a canonical case record.

    The function intentionally has no capability-manifest input.  A capability
    says that a path might exist; it is never evidence that a particular live
    request took that path.
    """
    values: dict[str, object] = {}
    errors: list[str] = []
    for field in PHASE4_SEMANTIC_FIELDS:
        value, field_errors = semantic_field_value(raw, matching_event, field)
        values[field] = value
        errors.extend(field_errors)
    reject_raw_quic_connection_id(values, errors)
    return values, errors


def is_phase4_semantic_case(case: Mapping[str, Any]) -> bool:
    return (
        str(case.get("phase") or "") == "4"
        and str(case.get("expected_result") or "") in PHASE4_EXPECTED_RESULTS
    )


def protocol_claimed(record: Mapping[str, Any]) -> bool:
    """Return whether a record asserts any new protocol provenance.

    The legacy ``transport_protocol`` field deliberately does not count: it
    is kept for old H1/H2 artifacts and cannot promote a modern protocol
    result on its own.
    """
    for field in PROTOCOL_CLAIM_FIELDS:
        value = record.get(field)
        # Common's flat serializer may emit false for an unset optional
        # boolean.  A false fallback/reset/QUIC-presence bit by itself is not
        # a protocol observation and must remain non-promoting.
        if isinstance(value, bool):
            if value:
                return True
            continue
        if value not in (None, ""):
            return True
    return False


def case_protocol_profile(case: Mapping[str, Any]) -> str | None:
    """Return the catalog's optional downstream protocol execution profile."""
    request = case.get("request")
    if not isinstance(request, Mapping) or "protocol_profile" not in request:
        return None
    profile = normalize_protocol(request.get("protocol_profile"))
    if profile not in CANONICAL_PROTOCOLS:
        raise ContractError(f"invalid case protocol_profile: {request.get('protocol_profile')!r}")
    return profile


def normalized_event_semantic_value(
    event: Mapping[str, Any], field: str,
) -> object:
    if field not in event:
        return _MISSING
    return normalize_semantic_value(field, event[field])


def require_protocol_event(
    record: Mapping[str, Any],
    event: Mapping[str, Any],
    errors: list[str],
    field: str,
    expected: object = _MISSING,
) -> None:
    try:
        value = normalized_event_semantic_value(event, field)
    except ContractError:
        errors.append(f"canonical event has invalid {field}")
        return
    if value is _MISSING or value is None:
        errors.append(f"canonical event is missing protocol provenance {field}")
        return
    if record.get(field) != value:
        errors.append(f"case result {field} does not match canonical event")
    if expected is not _MISSING and value != expected:
        errors.append(f"canonical event {field}={value!r}, expected {expected!r}")


def append_protocol_causal_errors(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    if event.get("connector") != record.get("connector"):
        errors.append("protocol event connector does not match case result")
    record_phase = normalize_canonical_phase(record.get("phase"))
    event_phase = normalize_canonical_phase(event.get("phase"))
    if record_phase is None or event_phase != record_phase:
        errors.append("protocol event phase does not match case result")
    transaction_ids = {
        str(value) for value in record.get("transaction_ids", []) if str(value).strip()
    }
    if not transaction_ids:
        errors.append("protocol PASS requires a transaction_id")
    elif not transaction_ids.intersection(event_transaction_ids(event)):
        errors.append("protocol event transaction_id does not match case result")
    expected_rule_id = optional_int(record.get("expected_rule_id"))
    observed_rule_ids = {
        int(value) for value in record.get("observed_rule_ids", [])
        if not isinstance(value, bool) and str(value).strip().lstrip("-").isdigit()
    }
    event_rule_values = set(event_rule_ids(event))
    if expected_rule_id is not None and expected_rule_id not in event_rule_values:
        errors.append("protocol event does not report the expected rule")
    elif expected_rule_id is None and observed_rule_ids and not observed_rule_ids.intersection(event_rule_values):
        errors.append("protocol event rule_id does not match case result")


def append_protocol_action_errors(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    for field, allowed in (
        ("requested_action", REQUESTED_ACTIONS),
        ("actual_action", ACTUAL_ACTIONS),
    ):
        event_action = normalize_action(event.get(field), allowed)
        if record.get(field) != event_action:
            errors.append(f"protocol event {field} does not match case result")


def append_protocol_identity_error(
    event: Mapping[str, Any], errors: list[str], field: str, value: object,
) -> None:
    if value is None:
        return
    if not isinstance(value, str) or not value.strip():
        errors.append(f"protocol PASS requires a non-empty {field}")
    elif event.get(field) != value:
        errors.append(f"protocol event {field} does not match case result")


def selected_protocol_identity(
    record: Mapping[str, Any], supplied_value: str | None, field: str,
) -> object:
    return supplied_value if supplied_value is not None else record.get(field)


def protocol_record_values(record: Mapping[str, Any]) -> dict[str, object]:
    return {
        "requested": record.get("requested_protocol"),
        "downstream": record.get("downstream_protocol"),
        "negotiated": record.get("negotiated_protocol"),
        "transport": record.get("transport"),
        "fallback_used": record.get("fallback_used"),
    }


def append_required_protocol_profile_errors(
    values: dict[str, object], required_protocol: str | None, errors: list[str],
) -> str | None:
    downstream_protocol = values["negotiated"] or values["downstream"]
    if required_protocol is None:
        return downstream_protocol if isinstance(downstream_protocol, str) else None
    for field in ("requested", "downstream", "negotiated"):
        if values[field] != required_protocol:
            errors.append(f"case protocol_profile does not match {field}_protocol")
    return required_protocol


def require_declared_protocol_evidence(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    for field in (
        "requested_protocol", "downstream_protocol", "upstream_protocol",
        "negotiated_protocol", "transport", "alpn", "stream_id",
        "transport_case_id", "connection_id", "quic_connection_id_present",
        "quic_version", "fallback_used", "stream_reset", "stream_reset_code",
    ):
        if record.get(field) is not None:
            require_protocol_event(record, event, errors, field)


def append_requested_protocol_errors(
    values: Mapping[str, object], errors: list[str],
) -> None:
    requested = values["requested"]
    negotiated = values["negotiated"]
    downstream = values["downstream"]
    if requested in {"h2", "h2c", "h3"}:
        if negotiated is None:
            errors.append("protocol PASS requires negotiated_protocol")
        elif requested != negotiated:
            errors.append("requested_protocol does not match negotiated_protocol")
        if values["fallback_used"] is not False:
            errors.append("protocol PASS requires fallback_used=false")
    if downstream is not None and negotiated is not None and downstream != negotiated:
        errors.append("downstream_protocol does not match negotiated_protocol")


def append_modern_protocol_errors(
    record: Mapping[str, Any],
    event: Mapping[str, Any],
    errors: list[str],
    downstream_protocol: str | None,
    values: Mapping[str, object],
) -> None:
    if downstream_protocol not in {"h2", "h2c", "h3"}:
        return
    for field in (
        "requested_protocol", "downstream_protocol", "negotiated_protocol",
        "transport", "fallback_used", "stream_id", "transport_case_id",
    ):
        require_protocol_event(record, event, errors, field)
    if values["requested"] != downstream_protocol:
        errors.append("protocol PASS requested_protocol does not match downstream protocol")
    if values["downstream"] != downstream_protocol:
        errors.append("protocol PASS downstream_protocol does not match negotiated_protocol")
    if values["fallback_used"] is not False:
        errors.append("protocol PASS requires fallback_used=false")
    stream_id = record.get("stream_id")
    if not isinstance(stream_id, int) or isinstance(stream_id, bool):
        errors.append("H2/H3 protocol PASS requires a stream_id")
    transport_case_id = record.get("transport_case_id")
    if not isinstance(transport_case_id, str) or not transport_case_id:
        errors.append("H2/H3 protocol PASS requires a transport_case_id")


def append_h3_protocol_errors(record: Mapping[str, Any], errors: list[str]) -> None:
    if str(record.get("alpn") or "").lower() != "h3":
        errors.append("h3 protocol PASS requires alpn=h3")
    if record.get("quic_connection_id_present") is not True:
        errors.append("h3 protocol PASS requires quic_connection_id_present=true")
    if not isinstance(record.get("quic_version"), str) or not record.get("quic_version"):
        errors.append("h3 protocol PASS requires quic_version")
    connection_id = record.get("connection_id")
    if connection_id is not None and not is_hashed_connection_id(connection_id):
        errors.append("h3 protocol evidence may not persist a raw connection_id")


def append_protocol_transport_errors(
    record: Mapping[str, Any],
    errors: list[str],
    downstream_protocol: str | None,
    transport: object,
) -> None:
    expected_transport = {
        "h2": "tls_tcp",
        "h2c": "tcp",
        "h3": "quic_udp",
    }.get(downstream_protocol)
    if expected_transport is not None and transport != expected_transport:
        errors.append(
            f"{downstream_protocol} protocol PASS requires transport={expected_transport}"
        )
    if downstream_protocol == "h2" and str(record.get("alpn") or "").lower() != "h2":
        errors.append("h2 protocol PASS requires alpn=h2")
    if downstream_protocol == "h2c" and record.get("alpn") not in (None, ""):
        errors.append("h2c protocol PASS must not claim TLS ALPN")
    if downstream_protocol == "h3":
        append_h3_protocol_errors(record, errors)


def append_strict_stream_reset_errors(
    record: Mapping[str, Any], errors: list[str], downstream_protocol: str | None,
) -> None:
    stream_reset = record.get("stream_reset")
    if stream_reset is True and downstream_protocol not in {"h2", "h2c", "h3"}:
        errors.append("stream_reset is valid only for an H2/H3 downstream protocol")
    if (
        str(record.get("expected_result") or "") != "connection_aborted_strict"
        or downstream_protocol not in {"h2", "h2c", "h3"}
    ):
        return
    expected_values = {
        "requested_action": "deny",
        "actual_action": "stream_reset",
        "transport_result": "stream_reset",
    }
    for field, expected in expected_values.items():
        if record.get(field) != expected:
            errors.append(f"H2/H3 strict PASS requires {field}={expected}")
    if stream_reset is not True:
        errors.append("H2/H3 strict PASS requires a client-observed stream_reset")
    if record.get("stream_reset_code") is None:
        errors.append("H2/H3 strict PASS requires stream_reset_code")
    if record.get("connection_aborted") is True:
        errors.append("H2/H3 strict stream reset must not claim connection_aborted")


def protocol_pass_errors(
    record: Mapping[str, Any],
    matching_event: Mapping[str, Any] | None,
    *,
    expected_run_id: str | None = None,
    expected_integration_mode: str | None = None,
    required_protocol: str | None = None,
) -> list[str]:
    """Validate non-promoting H2/H3 protocol provenance for one PASS.

    This is intentionally evidence-driven.  A capability declaration, a raw
    result field, or the historical ``transport_protocol`` field cannot
    establish negotiated H2/H3 traffic.  A protocol claim needs a matching
    canonical host event and the event must carry the negotiated path.
    """
    if required_protocol is not None and required_protocol not in CANONICAL_PROTOCOLS:
        return [f"unsupported required protocol profile: {required_protocol!r}"]
    if not protocol_claimed(record) and required_protocol is None:
        return []
    errors: list[str] = []
    if matching_event is None:
        return ["protocol provenance requires a matching canonical event"]
    append_protocol_causal_errors(record, matching_event, errors)
    append_protocol_action_errors(record, matching_event, errors)

    run_id = selected_protocol_identity(record, expected_run_id, "run_id")
    append_protocol_identity_error(matching_event, errors, "run_id", run_id)
    integration_mode = selected_protocol_identity(
        record, expected_integration_mode, "integration_mode",
    )
    append_protocol_identity_error(
        matching_event, errors, "integration_mode", integration_mode,
    )
    values = protocol_record_values(record)
    downstream_protocol = append_required_protocol_profile_errors(
        values, required_protocol, errors,
    )
    require_declared_protocol_evidence(record, matching_event, errors)
    append_requested_protocol_errors(values, errors)
    append_modern_protocol_errors(
        record, matching_event, errors, downstream_protocol, values,
    )
    append_protocol_transport_errors(
        record, errors, downstream_protocol, values["transport"],
    )
    append_strict_stream_reset_errors(record, errors, downstream_protocol)
    return errors


def phase_is_four(value: object) -> bool:
    return normalize_canonical_phase(value) == 4


def require_phase4_event_value(
    record: Mapping[str, Any],
    event: Mapping[str, Any],
    errors: list[str],
    field: str,
    expected: object = _MISSING,
) -> None:
    if field not in event:
        errors.append(f"canonical event is missing {field}")
        return
    try:
        event_value = normalize_semantic_value(field, event[field])
    except ContractError:
        errors.append(f"canonical event has invalid {field}")
        return
    if record.get(field) != event_value:
        errors.append(f"case result {field} does not match canonical event")
    if expected is not _MISSING and event_value != expected:
        errors.append(f"canonical event {field}={event_value!r}, expected {expected!r}")


def require_phase4_status_triplet(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    require_phase4_event_value(record, event, errors, "http_status", 403)
    require_phase4_event_value(record, event, errors, "original_http_status")
    require_phase4_event_value(record, event, errors, "visible_http_status")


def append_observable_client_status_errors(
    record: Mapping[str, Any], errors: list[str],
) -> None:
    transport = record.get("transport_result")
    if transport in {"connection_aborted", "not_observable"}:
        errors.append("HTTP outcome cannot use a non-observable transport result")
        return
    actual_status = record.get("actual_status")
    visible_status = record.get("visible_http_status")
    if actual_status is None:
        errors.append("HTTP outcome is missing an observed client status")
    elif actual_status != visible_status:
        errors.append("observed client status does not match visible_http_status")


def append_abort_client_status_errors(
    record: Mapping[str, Any], errors: list[str],
) -> None:
    transport = record.get("transport_result")
    if transport in {"connection_aborted", "not_observable"}:
        return
    actual_status = record.get("actual_status")
    visible_status = record.get("visible_http_status")
    if actual_status is None:
        if transport in {"http_status", "log_only"}:
            errors.append("observable abort transport is missing an observed client status")
        return
    if actual_status != visible_status:
        errors.append("observed abort status does not match visible_http_status")


def phase4_abort_action(record: Mapping[str, Any]) -> str:
    if record.get("negotiated_protocol") in {"h2", "h2c", "h3"}:
        return "stream_reset"
    return "abort_connection"


def phase4_uses_stream_reset(record: Mapping[str, Any]) -> bool:
    return record.get("negotiated_protocol") in {"h2", "h2c", "h3"}


def validate_phase4_pre_commit_deny(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    require_phase4_status_triplet(record, event, errors)
    require_phase4_event_value(record, event, errors, "requested_action", "deny")
    require_phase4_event_value(record, event, errors, "actual_action", "deny")
    require_phase4_event_value(record, event, errors, "visible_http_status", 403)
    require_phase4_event_value(record, event, errors, "headers_sent", False)
    require_phase4_event_value(record, event, errors, "connection_aborted", False)
    if event.get("late_intervention") is True:
        errors.append("pre-commit deny cannot be marked as a late intervention")
    if event.get("response_committed") is True:
        errors.append("pre-commit deny cannot have response_committed=true")
    append_observable_client_status_errors(record, errors)


def validate_phase4_late_log_only(
    record: Mapping[str, Any],
    event: Mapping[str, Any],
    errors: list[str],
    expected_mode: str | None,
    preservation_error: str,
) -> None:
    require_phase4_status_triplet(record, event, errors)
    require_phase4_event_value(record, event, errors, "requested_action", "deny")
    require_phase4_event_value(record, event, errors, "actual_action", "log_only")
    require_phase4_event_value(record, event, errors, "late_intervention", True)
    if expected_mode is not None:
        require_phase4_event_value(record, event, errors, "late_intervention_mode", expected_mode)
    require_phase4_event_value(record, event, errors, "headers_sent", True)
    require_phase4_event_value(record, event, errors, "connection_aborted", False)
    if record.get("visible_http_status") != record.get("original_http_status"):
        errors.append(preservation_error)
    append_observable_client_status_errors(record, errors)


def validate_phase4_late_log_only_default(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    validate_phase4_late_log_only(
        record,
        event,
        errors,
        None,
        "log-only late intervention must preserve the visible HTTP status",
    )


def validate_phase4_late_log_only_minimal(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    validate_phase4_late_log_only(
        record,
        event,
        errors,
        "minimal",
        "late log-only intervention must preserve the visible HTTP status",
    )


def validate_phase4_late_log_only_safe(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    validate_phase4_late_log_only(
        record,
        event,
        errors,
        "safe",
        "late log-only intervention must preserve the visible HTTP status",
    )


def validate_phase4_abort(
    record: Mapping[str, Any],
    event: Mapping[str, Any],
    errors: list[str],
    *,
    strict: bool,
) -> None:
    require_phase4_status_triplet(record, event, errors)
    require_phase4_event_value(record, event, errors, "requested_action", "deny")
    require_phase4_event_value(record, event, errors, "actual_action", phase4_abort_action(record))
    require_phase4_event_value(record, event, errors, "late_intervention", True)
    if strict:
        require_phase4_event_value(record, event, errors, "late_intervention_mode", "strict")
    require_phase4_event_value(record, event, errors, "headers_sent", True)
    if phase4_uses_stream_reset(record):
        require_phase4_event_value(record, event, errors, "stream_reset", True)
        if strict:
            require_phase4_event_value(record, event, errors, "stream_reset_code")
            require_phase4_event_value(record, event, errors, "connection_aborted", False)
            require_phase4_event_value(record, event, errors, "transport_result", "stream_reset")
    else:
        require_phase4_event_value(record, event, errors, "connection_aborted", True)
    if record.get("visible_http_status") != record.get("original_http_status"):
        errors.append(
            "strict post-commit abort must preserve the already visible HTTP status"
            if strict
            else "post-commit abort must preserve the already visible HTTP status"
        )
    append_abort_client_status_errors(record, errors)


def validate_phase4_connection_aborted(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    validate_phase4_abort(record, event, errors, strict=False)


def validate_phase4_connection_aborted_strict(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    validate_phase4_abort(record, event, errors, strict=True)


def validate_phase4_marker_split(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    require_phase4_event_value(record, event, errors, "marker_split_across_chunks", True)
    require_phase4_event_value(record, event, errors, "end_of_stream_evaluation", True)


def validate_phase4_end_of_stream(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    require_phase4_event_value(record, event, errors, "end_of_stream_evaluation", True)
    require_phase4_event_value(record, event, errors, "body_started", True)


def validate_phase4_content_type_in_scope(
    record: Mapping[str, Any],
    event: Mapping[str, Any],
    errors: list[str],
    *,
    charset_required: bool,
) -> None:
    require_phase4_event_value(record, event, errors, "content_type_scope", "in_scope")
    content_type = str(event.get("content_type") or "")
    if not content_type:
        errors.append("in-scope response evidence is missing content_type")
    if charset_required and "charset=" not in content_type.lower():
        errors.append("charset content-type case requires a charset parameter")


def validate_phase4_content_type_in_scope_default(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    validate_phase4_content_type_in_scope(record, event, errors, charset_required=False)


def validate_phase4_content_type_in_scope_charset(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    validate_phase4_content_type_in_scope(record, event, errors, charset_required=True)


def validate_phase4_content_type_out_of_scope(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    require_phase4_event_value(record, event, errors, "content_type_scope", "out_of_scope")
    if not str(event.get("content_type") or ""):
        errors.append("out-of-scope response evidence is missing content_type")
    append_observable_client_status_errors(record, errors)


def validate_phase4_content_type_missing(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    require_phase4_event_value(record, event, errors, "content_type_scope", "missing")
    if event.get("content_type") not in (None, ""):
        errors.append("missing-content-type evidence must not invent content_type")
    append_observable_client_status_errors(record, errors)


def append_phase4_first_byte_errors(
    record: Mapping[str, Any],
    event: Mapping[str, Any],
    errors: list[str],
    label: str,
) -> None:
    require_phase4_event_value(record, event, errors, "client_first_byte_received", True)
    require_phase4_event_value(record, event, errors, "first_byte_before_response_end", True)
    require_phase4_event_value(record, event, errors, "first_chunk_size")
    first_chunk_size = event.get("first_chunk_size")
    if not isinstance(first_chunk_size, int) or first_chunk_size < 1:
        errors.append(f"{label} evidence requires first_chunk_size > 0")
    require_phase4_event_value(record, event, errors, "upstream_paused", True)
    require_phase4_event_value(record, event, errors, "upstream_eos_sent_at_first_byte", False)
    require_phase4_event_value(record, event, errors, "upstream_response_finished_at_first_byte", False)
    require_phase4_event_value(record, event, errors, "response_committed", True)
    for field in ("body_bytes_seen", "body_bytes_inspected"):
        if not isinstance(event.get(field), int):
            errors.append(f"{label} evidence requires {field}")
    body_bytes_seen = event.get("body_bytes_seen")
    body_bytes_inspected = event.get("body_bytes_inspected")
    if (
        isinstance(body_bytes_seen, int)
        and isinstance(body_bytes_inspected, int)
        and body_bytes_inspected > body_bytes_seen
    ):
        errors.append(f"{label} evidence has inspected bytes above seen bytes")


def validate_phase4_no_full_response_buffering(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    require_phase4_event_value(record, event, errors, "no_full_response_buffering", True)
    append_phase4_first_byte_errors(record, event, errors, "no-full-buffer")


def validate_phase4_first_byte_before_response_end(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    append_phase4_first_byte_errors(record, event, errors, "first-byte")


def validate_phase4_body_limit(
    record: Mapping[str, Any],
    event: Mapping[str, Any],
    errors: list[str],
    outcome: str,
) -> None:
    require_phase4_event_value(record, event, errors, "body_limit_outcome", outcome)
    for field in ("body_bytes_seen", "body_bytes_inspected", "truncated"):
        if field not in event:
            errors.append(f"canonical event is missing {field}")
    if outcome == "process_partial" and event.get("truncated") is not True:
        errors.append("ProcessPartial evidence must set truncated=true")
    if outcome == "reject" and event.get("truncated") is not False:
        errors.append("Reject evidence must set truncated=false")


def validate_phase4_body_limit_at_limit(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    validate_phase4_body_limit(record, event, errors, "at_limit")


def validate_phase4_body_limit_over_limit(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    validate_phase4_body_limit(record, event, errors, "over_limit")


def validate_phase4_body_limit_process_partial(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    validate_phase4_body_limit(record, event, errors, "process_partial")


def validate_phase4_body_limit_reject(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    validate_phase4_body_limit(record, event, errors, "reject")


def validate_phase4_event_contains_original_status(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    require_phase4_status_triplet(record, event, errors)
    visible_status = record.get("visible_http_status")
    if event.get("late_intervention") is True and visible_status != record.get("original_http_status"):
        errors.append("late-intervention status metadata must preserve the visible status")
    if event.get("headers_sent") is False and visible_status != record.get("http_status"):
        errors.append("uncommitted response metadata must expose the WAF status")


def validate_phase4_event_contains_late_intervention_action(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    require_phase4_event_value(record, event, errors, "requested_action", "deny")
    require_phase4_event_value(record, event, errors, "actual_action")
    require_phase4_event_value(record, event, errors, "late_intervention")
    actual_action = record.get("actual_action")
    late_intervention = record.get("late_intervention")
    if actual_action not in {"deny", "log_only", "abort_connection", "stream_reset"}:
        errors.append("phase-4 deny must resolve to deny, log_only, abort_connection, or stream_reset")
    if actual_action == "deny" and late_intervention is not False:
        errors.append("deny action must not be marked as a late intervention")
    if actual_action in {"log_only", "abort_connection", "stream_reset"} and late_intervention is not True:
        errors.append("post-commit action must be marked as a late intervention")
    if actual_action == "abort_connection" and event.get("connection_aborted") is False:
        errors.append("abort action conflicts with connection_aborted=false")
    if actual_action == "stream_reset" and event.get("stream_reset") is False:
        errors.append("stream-reset action conflicts with stream_reset=false")
    if actual_action in {"deny", "log_only"} and event.get("connection_aborted") is True:
        errors.append("non-abort action conflicts with connection_aborted=true")


PHASE4_PASS_VALIDATORS: dict[str, Callable[[Mapping[str, Any], Mapping[str, Any], list[str]], None]] = {
    "deny_before_commit": validate_phase4_pre_commit_deny,
    "legacy_phase4_deny_before_commit": validate_phase4_pre_commit_deny,
    "late_intervention_log_only": validate_phase4_late_log_only_default,
    "late_intervention_log_only_minimal": validate_phase4_late_log_only_minimal,
    "late_intervention_log_only_safe": validate_phase4_late_log_only_safe,
    "connection_aborted": validate_phase4_connection_aborted,
    "connection_aborted_strict": validate_phase4_connection_aborted_strict,
    "marker_split_across_chunks": validate_phase4_marker_split,
    "end_of_stream_evaluation": validate_phase4_end_of_stream,
    "content_type_in_scope": validate_phase4_content_type_in_scope_default,
    "content_type_in_scope_with_charset": validate_phase4_content_type_in_scope_charset,
    "content_type_out_of_scope": validate_phase4_content_type_out_of_scope,
    "content_type_missing": validate_phase4_content_type_missing,
    "no_full_response_buffering": validate_phase4_no_full_response_buffering,
    "first_byte_before_response_end": validate_phase4_first_byte_before_response_end,
    "response_body_at_limit": validate_phase4_body_limit_at_limit,
    "response_body_over_limit": validate_phase4_body_limit_over_limit,
    "response_body_process_partial": validate_phase4_body_limit_process_partial,
    "response_body_reject": validate_phase4_body_limit_reject,
    "event_contains_original_status": validate_phase4_event_contains_original_status,
    "event_contains_late_intervention_action": validate_phase4_event_contains_late_intervention_action,
}


def phase4_pass_errors(
    record: Mapping[str, Any], matching_event: Mapping[str, Any] | None,
    runtime_evidence_errors: Sequence[str] = (),
    required_protocol: str | None = None,
) -> list[str]:
    """Return semantic evidence failures for a canonical Phase-4 PASS.

    These checks deliberately use the matched canonical event as the source of
    truth for intervention metadata.  It prevents a host result from turning a
    visible 200 into a synthetic 403 PASS, and it makes post-finalize record
    tampering detectable by the validators that call this function again.
    """
    errors = list(runtime_evidence_errors)
    expected_result = str(record.get("expected_result") or "")
    if expected_result not in PHASE4_EXPECTED_RESULTS:
        return errors
    expected_rule_id = optional_int(record.get("expected_rule_id"))
    if record.get("live_executed") is not True:
        errors.append("live_executed must be true")
    if expected_rule_id is not None and expected_rule_id not in record.get("observed_rule_ids", []):
        errors.append("expected phase-4 rule was not observed")
    if matching_event is None:
        errors.append("canonical phase-4 event is missing")
        return errors
    errors.extend(protocol_pass_errors(
        record, matching_event, required_protocol=required_protocol,
    ))
    errors.extend(canonical_event_errors(
        matching_event,
        connector=str(record.get("connector") or "") or None,
    ))
    if not phase_is_four(matching_event.get("phase")):
        errors.append("canonical event does not report phase 4")
    if expected_rule_id is not None and expected_rule_id not in event_rule_ids(matching_event):
        errors.append("canonical event does not report the expected rule")
    validator = PHASE4_PASS_VALIDATORS.get(expected_result)
    if validator is not None:
        validator(record, matching_event, errors)
    return errors


def require_full_lifecycle_event_value(
    record: Mapping[str, Any],
    event: Mapping[str, Any],
    errors: list[str],
    field: str,
    expected: object = _MISSING,
) -> None:
    if field not in event:
        errors.append(f"canonical event is missing {field}")
        return
    value = event[field]
    if field in PHASE4_SEMANTIC_FIELDS:
        try:
            value = normalize_semantic_value(field, value)
        except ContractError:
            errors.append(f"canonical event has invalid {field}")
            return
        if record.get(field) != value:
            errors.append(f"case result {field} does not match canonical event")
    if expected is not _MISSING and value != expected:
        errors.append(f"canonical event {field}={value!r}, expected {expected!r}")


def require_full_lifecycle_limit(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str], expected: str,
) -> None:
    require_full_lifecycle_event_value(record, event, errors, "body_limit_outcome", expected)
    for field in ("body_bytes_seen", "body_bytes_inspected", "truncated"):
        require_full_lifecycle_event_value(record, event, errors, field)


def validate_full_lifecycle_request_marker_split(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    require_full_lifecycle_event_value(record, event, errors, "marker_split_across_chunks", True)
    for field in ("body_bytes_seen", "body_bytes_inspected"):
        require_full_lifecycle_event_value(record, event, errors, field)


def validate_full_lifecycle_request_body_at_limit(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    require_full_lifecycle_limit(record, event, errors, "at_limit")


def validate_full_lifecycle_request_body_over_limit(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    require_full_lifecycle_limit(record, event, errors, "over_limit")


def validate_full_lifecycle_request_body_process_partial(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    require_full_lifecycle_limit(record, event, errors, "process_partial")
    require_full_lifecycle_event_value(record, event, errors, "truncated", True)


def validate_full_lifecycle_phase3_pre_commit(
    record: Mapping[str, Any],
    event: Mapping[str, Any],
    errors: list[str],
    action: str,
    visible_status: int,
    late_intervention_error: str,
) -> None:
    require_full_lifecycle_event_value(record, event, errors, "requested_action", action)
    require_full_lifecycle_event_value(record, event, errors, "actual_action", action)
    require_full_lifecycle_event_value(record, event, errors, "headers_sent", False)
    require_full_lifecycle_event_value(record, event, errors, "visible_http_status", visible_status)
    if event.get("late_intervention") is True:
        errors.append(late_intervention_error)


def validate_full_lifecycle_phase3_deny(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    validate_full_lifecycle_phase3_pre_commit(
        record, event, errors, "deny", 403,
        "phase-3 pre-commit deny cannot be a late intervention",
    )


def validate_full_lifecycle_phase3_redirect(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    validate_full_lifecycle_phase3_pre_commit(
        record, event, errors, "redirect", 302,
        "phase-3 pre-commit redirect cannot be a late intervention",
    )


def validate_full_lifecycle_response_status_metadata(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    for field in ("http_status", "original_http_status", "visible_http_status", "headers_sent"):
        require_full_lifecycle_event_value(record, event, errors, field)
    if (
        event.get("headers_sent") is False
        and event.get("visible_http_status") != event.get("http_status")
    ):
        errors.append("uncommitted response metadata must expose the WAF status")


def validate_full_lifecycle_http11_transport(
    record: Mapping[str, Any],
    event: Mapping[str, Any],
    errors: list[str],
    transfer_encoding: str,
) -> None:
    require_full_lifecycle_event_value(record, event, errors, "transport_protocol", "http1")
    require_full_lifecycle_event_value(record, event, errors, "transfer_encoding", transfer_encoding)
    require_full_lifecycle_event_value(record, event, errors, "transport_result", "http_status")


def validate_full_lifecycle_http11_content_length(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    validate_full_lifecycle_http11_transport(record, event, errors, "content_length")


def validate_full_lifecycle_http11_chunked(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    validate_full_lifecycle_http11_transport(record, event, errors, "chunked")


def validate_full_lifecycle_connection_reuse(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    require_full_lifecycle_event_value(record, event, errors, "connection_reused", True)
    require_full_lifecycle_event_value(record, event, errors, "transport_protocol")


def validate_full_lifecycle_parallel_transport(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    require_full_lifecycle_event_value(record, event, errors, "transport_protocol")
    if len(record.get("transaction_ids", [])) < 2:
        errors.append("parallel transport evidence requires at least two transaction IDs")


def validate_full_lifecycle_http2_transport(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    require_full_lifecycle_event_value(record, event, errors, "transport_protocol", "http2")
    require_full_lifecycle_event_value(record, event, errors, "transport_result", "http_status")


def validate_full_lifecycle_client_abort(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    require_full_lifecycle_event_value(record, event, errors, "client_aborted", True)
    require_full_lifecycle_event_value(record, event, errors, "transport_result")


def validate_full_lifecycle_upstream_abort(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    require_full_lifecycle_event_value(record, event, errors, "upstream_aborted", True)
    require_full_lifecycle_event_value(record, event, errors, "transport_result")


def validate_full_lifecycle_bounded_or_truncated(
    record: Mapping[str, Any], event: Mapping[str, Any], errors: list[str],
) -> None:
    for field in ("truncated", "body_bytes_seen", "body_bytes_inspected"):
        require_full_lifecycle_event_value(record, event, errors, field)


FULL_LIFECYCLE_PASS_VALIDATORS: dict[str, Callable[[Mapping[str, Any], Mapping[str, Any], list[str]], None]] = {
    "request_marker_split_across_chunks": validate_full_lifecycle_request_marker_split,
    "request_body_at_limit": validate_full_lifecycle_request_body_at_limit,
    "request_body_over_limit": validate_full_lifecycle_request_body_over_limit,
    "request_body_process_partial": validate_full_lifecycle_request_body_process_partial,
    "phase3_deny_before_commit": validate_full_lifecycle_phase3_deny,
    "phase3_redirect_before_commit": validate_full_lifecycle_phase3_redirect,
    "response_status_metadata": validate_full_lifecycle_response_status_metadata,
    "transport_http11_content_length": validate_full_lifecycle_http11_content_length,
    "transport_http11_chunked": validate_full_lifecycle_http11_chunked,
    "transport_keep_alive": validate_full_lifecycle_connection_reuse,
    "transport_sequential_requests": validate_full_lifecycle_connection_reuse,
    "transport_parallel_requests": validate_full_lifecycle_parallel_transport,
    "transport_http2": validate_full_lifecycle_http2_transport,
    "transport_client_abort": validate_full_lifecycle_client_abort,
    "transport_upstream_abort": validate_full_lifecycle_upstream_abort,
    "event_bounded_or_truncated": validate_full_lifecycle_bounded_or_truncated,
}


def full_lifecycle_pass_errors(
    record: Mapping[str, Any], matching_event: Mapping[str, Any] | None,
) -> list[str]:
    """Validate the non-Phase-4 portions of the full-lifecycle catalog.

    These checks intentionally require a canonical event for each specialized
    PASS.  A host result with only an HTTP status cannot establish chunk
    boundaries, limit policy, transport mode, or a commit boundary.
    """
    validator = FULL_LIFECYCLE_PASS_VALIDATORS.get(str(record.get("expected_result") or ""))
    if validator is None:
        return []
    errors: list[str] = []
    if matching_event is None:
        return ["canonical full-lifecycle event is missing"]
    errors.extend(canonical_event_errors(
        matching_event, connector=str(record.get("connector") or "") or None,
    ))
    validator(record, matching_event, errors)
    return errors


def optional_case_provenance(value: object, *, maximum: int, field: str) -> str | None:
    if _empty_runtime_value(value):
        return None
    if not isinstance(value, str):
        raise ContractError(f"invalid {field}: expected a string")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise ContractError(f"invalid {field}: expected a bounded non-empty string")
    return normalized


def case_identifier(raw: Mapping[str, Any]) -> str:
    return str(raw.get("case_id") or raw.get("case") or raw.get("name") or "").strip()


def normalized_case_provenance(
    raw: Mapping[str, Any],
) -> tuple[str | None, str | None, list[str]]:
    values: dict[str, str | None] = {}
    errors: list[str] = []
    for field, maximum in (("run_id", 256), ("integration_mode", 64)):
        try:
            values[field] = optional_case_provenance(raw.get(field), maximum=maximum, field=field)
        except ContractError:
            values[field] = None
            errors.append(f"{field}: invalid raw runtime value")
    return values["run_id"], values["integration_mode"], errors


def normalized_observed_rule_ids(raw: Mapping[str, Any]) -> list[int]:
    candidates: list[object] = []
    if isinstance(raw.get("observed_rule_ids"), list):
        candidates.extend(raw["observed_rule_ids"])
    for key in ("observed_rule_id", "rule_id", "modsecurity_rule_id"):
        if raw.get(key) not in (None, ""):
            candidates.append(raw[key])
    rule_ids: list[int] = []
    for candidate in candidates:
        try:
            rule_id = int(candidate)
        except (TypeError, ValueError):
            continue
        if rule_id not in rule_ids:
            rule_ids.append(rule_id)
    return rule_ids


def normalized_actual_status_value(
    raw: Mapping[str, Any],
    case: Mapping[str, Any],
    semantic_values: Mapping[str, object],
) -> object:
    for field in ("actual_status", "observed_status", "visible_http_status", "client_status"):
        if field in raw:
            return raw[field]
    if is_phase4_semantic_case(case):
        return _MISSING
    visible_status = semantic_values["visible_http_status"]
    if visible_status is not None:
        return visible_status
    if "intervention_status" in raw:
        return raw["intervention_status"]
    return _MISSING


def bind_case_event_evidence(
    matching_event: Mapping[str, Any] | None,
    observed_rule_ids: Sequence[int],
    transaction_ids: Sequence[str],
) -> tuple[list[str], list[int], list[str]]:
    observed_event_fields = sorted(event_field_names(matching_event)) if matching_event else []
    bound_rule_ids = list(observed_rule_ids)
    bound_transaction_ids = list(transaction_ids)
    if matching_event:
        for rule_id in event_rule_ids(matching_event):
            if rule_id not in bound_rule_ids:
                bound_rule_ids.append(rule_id)
        bound_transaction_ids.extend(event_transaction_ids(matching_event))
    return (
        observed_event_fields,
        sorted(bound_rule_ids),
        sorted(dict.fromkeys(bound_transaction_ids)),
    )


def case_event_metadata_verified(
    raw: Mapping[str, Any],
    matching_event: Mapping[str, Any] | None,
    event_errors: Sequence[str],
    expected_fields: Sequence[str],
    observed_event_fields: Sequence[str],
) -> bool:
    if expected_fields:
        return bool(
            matching_event
            and not event_errors
            and all(field in observed_event_fields for field in expected_fields)
        )
    return bool(matching_event and not event_errors and raw.get("event_metadata_verified"))


def normalized_case_operation_status(status: str) -> str:
    return operation_status({
        "PASS": "pass", "FAIL": "fail", "BLOCKED": "blocked",
        "UNSUPPORTED": "not_executable", "NOT_APPLICABLE": "skipped",
        "NOT_EXECUTED": "skipped",
    }[status])


class NormalizedCaseRecordDetails(TypedDict):
    run_id: str | None
    integration_mode: str | None
    observed_result: object
    expected_status: int | None
    actual_status: int | None
    expected_rule_id: int | None
    observed_rule_ids: Sequence[int]
    transaction_ids: Sequence[str]
    expected_fields: Sequence[str]
    observed_event_fields: Sequence[str]
    event_metadata_verified: bool
    semantic_values: Mapping[str, object]


def build_normalized_case_record(
    raw: Mapping[str, Any],
    case: Mapping[str, Any],
    connector: str,
    case_id: str,
    status: str,
    details: NormalizedCaseRecordDetails,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "connector": connector,
        "run_id": details["run_id"],
        "integration_mode": details["integration_mode"],
        "case_id": case_id,
        "group": case.get("group", ""),
        "phase": case.get("phase"),
        "required_capabilities": list(case.get("required_capabilities", [])),
        "status": status,
        "operation_status": normalized_case_operation_status(status),
        "live_executed": raw.get("live_executed") is True,
        "expected_result": case.get("expected_result"),
        "observed_result": details["observed_result"],
        "expected_status": details["expected_status"],
        "actual_status": details["actual_status"],
        "expected_rule_id": details["expected_rule_id"],
        "observed_rule_ids": list(details["observed_rule_ids"]),
        "transaction_ids": list(details["transaction_ids"]),
        "expected_event_fields": list(details["expected_fields"]),
        "observed_event_fields": list(details["observed_event_fields"]),
        "event_metadata_verified": details["event_metadata_verified"],
        **details["semantic_values"],
        "reason": str(raw.get("reason") or raw.get("skipped_reason") or ""),
        "exit_code": optional_int(raw.get("exit_code")),
        "artifacts": raw.get("artifacts") if isinstance(raw.get("artifacts"), Mapping) else {},
    }


def non_phase4_case_pass_errors(
    record: Mapping[str, Any],
    matching_event: Mapping[str, Any] | None,
    expected_status: int | None,
    actual_status: int | None,
    expected_rule_id: int | None,
    observed_rule_ids: Sequence[int],
    expected_fields: Sequence[str],
    observed_event_fields: Sequence[str],
    event_errors: Sequence[str],
    required_protocol: str | None,
) -> list[str]:
    errors: list[str] = []
    if expected_status is not None and actual_status != expected_status:
        errors.append("actual status does not match expected status")
    if expected_rule_id is not None and expected_rule_id not in observed_rule_ids:
        errors.append("expected rule was not observed")
    if expected_fields and not set(expected_fields).issubset(observed_event_fields):
        errors.append("canonical event is missing expected fields")
    if matching_event and event_errors:
        errors.extend(event_errors)
    errors.extend(protocol_pass_errors(
        record, matching_event, required_protocol=required_protocol,
    ))
    return errors


def case_required_protocol_errors(case: Mapping[str, Any]) -> tuple[str | None, list[str]]:
    try:
        return case_protocol_profile(case), []
    except ContractError as exc:
        return None, [str(exc)]


def normalized_case_pass_errors(
    record: Mapping[str, Any],
    case: Mapping[str, Any],
    matching_event: Mapping[str, Any] | None,
    provenance_errors: Sequence[str],
    runtime_evidence_errors: Sequence[str],
    expected_status: int | None,
    actual_status: int | None,
    expected_rule_id: int | None,
    observed_rule_ids: Sequence[int],
    expected_fields: Sequence[str],
    observed_event_fields: Sequence[str],
    event_errors: Sequence[str],
) -> list[str]:
    required_protocol, protocol_errors = case_required_protocol_errors(case)
    errors = [*provenance_errors, *protocol_errors]
    if is_phase4_semantic_case(case):
        errors.extend(phase4_pass_errors(
            record, matching_event, runtime_evidence_errors, required_protocol,
        ))
    else:
        errors.extend(non_phase4_case_pass_errors(
            record,
            matching_event,
            expected_status,
            actual_status,
            expected_rule_id,
            observed_rule_ids,
            expected_fields,
            observed_event_fields,
            event_errors,
            required_protocol,
        ))
    errors.extend(full_lifecycle_pass_errors(record, matching_event))
    return errors


def mark_case_record_invalid(record: dict[str, Any], validation_errors: Sequence[str]) -> None:
    if not validation_errors:
        return
    record["status"] = "FAIL"
    record["operation_status"] = operation_status("fail")
    detail = "; ".join(dict.fromkeys(validation_errors))
    record["reason"] = "; ".join(
        part for part in (str(record["reason"]), f"runtime evidence invalid: {detail}") if part
    )


def normalize_case_record(
    raw: Mapping[str, Any],
    connector: str,
    case_by_id: Mapping[str, Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    integration_mode: str | None = None,
) -> dict[str, Any] | None:
    case_id = case_identifier(raw)
    if not case_id or case_id not in case_by_id:
        return None
    case = case_by_id[case_id]
    status = normalize_status(raw.get("status"))
    observed_result = raw.get("observed_result") or raw.get("outcome")
    if str(observed_result or "") == "rejected_by_host_before_connector":
        status = "NOT_APPLICABLE"
    raw_run_id, raw_integration_mode, provenance_errors = normalized_case_provenance(raw)
    observed_rule_ids = normalized_observed_rule_ids(raw)
    expected_rule_id = optional_int(case.get("expected_rule_id"))
    transaction_ids = supplied_transaction_ids(raw)
    matching_event = event_for_case(
        events, expected_rule_id, case, transaction_ids, integration_mode,
    )
    semantic_values, runtime_evidence_errors = semantic_runtime_fields(raw, matching_event)
    actual_status_value = normalized_actual_status_value(raw, case, semantic_values)
    actual_status = optional_int(actual_status_value) if actual_status_value is not _MISSING else None
    observed_event_fields, observed_rule_ids, transaction_ids = bind_case_event_evidence(
        matching_event, observed_rule_ids, transaction_ids,
    )
    expected_fields = [str(item) for item in case.get("expected_event_fields", [])]
    expected_status = optional_int(case.get("expected_status"))
    event_errors = (
        canonical_event_errors(
            matching_event,
            connector=connector,
            integration_mode=integration_mode,
        ) if matching_event else []
    )
    event_metadata_verified = case_event_metadata_verified(
        raw, matching_event, event_errors, expected_fields, observed_event_fields,
    )
    details: NormalizedCaseRecordDetails = {
        "run_id": raw_run_id,
        "integration_mode": raw_integration_mode,
        "observed_result": observed_result,
        "expected_status": expected_status,
        "actual_status": actual_status,
        "expected_rule_id": expected_rule_id,
        "observed_rule_ids": observed_rule_ids,
        "transaction_ids": transaction_ids,
        "expected_fields": expected_fields,
        "observed_event_fields": observed_event_fields,
        "event_metadata_verified": event_metadata_verified,
        "semantic_values": semantic_values,
    }
    record = build_normalized_case_record(
        raw,
        case,
        connector,
        case_id,
        status,
        details,
    )
    if status == "PASS":
        validation_errors = normalized_case_pass_errors(
            record,
            case,
            matching_event,
            provenance_errors,
            runtime_evidence_errors,
            expected_status,
            actual_status,
            expected_rule_id,
            observed_rule_ids,
            expected_fields,
            observed_event_fields,
            event_errors,
        )
        mark_case_record_invalid(record, validation_errors)
    return record


def derive_core_records(
    source: Mapping[str, Any],
    connector: str,
    case_by_id: Mapping[str, Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    integration_mode: str | None = None,
) -> list[dict[str, Any]]:
    if source.get("requests_sent") is not True and source.get("runtime_verified") is not True:
        return []
    records: list[dict[str, Any]] = []
    append_derived_allow_record(records, source, connector, case_by_id, events, integration_mode)
    append_derived_blocked_record(records, source, connector, case_by_id, events, integration_mode)
    return records


def append_normalized_record(
    records: list[dict[str, Any]],
    raw: Mapping[str, Any],
    connector: str,
    case_by_id: Mapping[str, Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    integration_mode: str | None,
) -> None:
    record = normalize_case_record(raw, connector, case_by_id, events, integration_mode)
    if record:
        records.append(record)


def append_derived_allow_record(
    records: list[dict[str, Any]],
    source: Mapping[str, Any],
    connector: str,
    case_by_id: Mapping[str, Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    integration_mode: str | None,
) -> None:
    allowed_status = optional_int(source.get("allowed_request_status"))
    if allowed_status is None:
        return
    append_normalized_record(
        records,
        {
            "case_id": "allow_without_marker",
            "status": "PASS" if allowed_status == 200 else "FAIL",
            "actual_status": allowed_status,
            "live_executed": True,
            "reason": "normalized from explicit source allowed_request_status",
        },
        connector,
        case_by_id,
        events,
        integration_mode,
    )


def source_observed_rule_ids(source: Mapping[str, Any]) -> list[int]:
    rule_ids: list[int] = []
    for key in ("observed_rule_ids", "modsecurity_rule_id", "rule_id"):
        value = source.get(key)
        candidates = value if isinstance(value, list) else [value]
        for candidate in candidates:
            try:
                rule_ids.append(int(candidate))
            except (TypeError, ValueError):
                continue
    return rule_ids


def append_derived_blocked_record(
    records: list[dict[str, Any]],
    source: Mapping[str, Any],
    connector: str,
    case_by_id: Mapping[str, Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    integration_mode: str | None,
) -> None:
    blocked_status = optional_int(source.get("blocked_request_status"))
    if blocked_status is None:
        return
    source_rule_ids = source_observed_rule_ids(source)
    denied = blocked_status == 403 and 1100001 in source_rule_ids
    append_normalized_record(
        records,
        {
            "case_id": "deny_header_marker_403",
            "status": "PASS" if denied else "FAIL",
            "actual_status": blocked_status,
            "observed_rule_ids": source_rule_ids,
            "live_executed": True,
            "reason": "normalized from explicit source blocked_request_status and rule ID",
        },
        connector,
        case_by_id,
        events,
        integration_mode,
    )


def forbidden_payload_errors(value: object, location: str = "event") -> list[str]:
    if isinstance(value, Mapping):
        return forbidden_mapping_payload_errors(value, location)
    if isinstance(value, list):
        return forbidden_list_payload_errors(value, location)
    if isinstance(value, str):
        return forbidden_string_payload_errors(value, location)
    return []


def forbidden_mapping_payload_errors(value: Mapping[object, object], location: str) -> list[str]:
    errors: list[str] = []
    for key, nested in value.items():
        normalized = str(key).strip().lower().replace("-", "_")
        child = f"{location}.{key}"
        if normalized in FORBIDDEN_EVENT_KEYS and normalized not in BODY_METADATA_KEYS:
            errors.append(f"{child}: forbidden payload/secret field")
        errors.extend(forbidden_payload_errors(nested, child))
    return errors


def forbidden_list_payload_errors(value: Sequence[object], location: str) -> list[str]:
    errors: list[str] = []
    for index, item in enumerate(value):
        errors.extend(forbidden_payload_errors(item, f"{location}[{index}]"))
    return errors


def forbidden_string_payload_errors(value: str, location: str) -> list[str]:
    lowered = value.lower()
    return [
        f"{location}: body payload sentinel is present"
        for sentinel in BODY_SENTINELS
        if sentinel in lowered
    ]


def append_derived_event_records(
    records: list[dict[str, Any]],
    plan: Mapping[str, Any],
    case_by_id: Mapping[str, Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    integration_mode: str | None = None,
) -> None:
    by_id = {record["case_id"]: record for record in records}
    selections = selected_plan_cases(plan)
    base = by_id.get("deny_header_marker_403")
    event = event_for_rule(events, 1100001)
    if not base or base.get("status") != "PASS" or not event:
        return
    append_event_field_derivations(
        records, by_id, selections, plan, case_by_id, events, event, integration_mode,
    )
    append_body_payload_derivation(
        records, by_id, selections, plan, case_by_id, events, event, integration_mode,
    )


def selected_plan_cases(plan: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {
        str(item.get("case_id") or ""): item
        for item in plan.get("cases", [])
        if isinstance(item, Mapping)
    }


def selected_plan_case(
    selections: Mapping[str, Mapping[str, Any]], case_id: str,
) -> bool:
    return selections.get(case_id, {}).get("selection_status") == "SELECTED"


def append_event_field_derivations(
    records: list[dict[str, Any]],
    by_id: dict[str, dict[str, Any]],
    selections: Mapping[str, Mapping[str, Any]],
    plan: Mapping[str, Any],
    case_by_id: Mapping[str, Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    event: Mapping[str, Any],
    integration_mode: str | None,
) -> None:
    fields = event_field_names(event)
    for case_id in (
        "event_contains_connector", "event_contains_transaction_id", "event_contains_rule_id",
        "event_contains_phase", "event_contains_status",
    ):
        if case_id in by_id or not selected_plan_case(selections, case_id):
            continue
        case = case_by_id[case_id]
        expected = [str(item) for item in case["expected_event_fields"]]
        append_derived_event_field_record(
            records,
            by_id,
            case_id,
            all(item in fields for item in expected),
            str(plan["connector"]),
            case_by_id,
            events,
            integration_mode,
        )


def append_derived_event_field_record(
    records: list[dict[str, Any]],
    by_id: dict[str, dict[str, Any]],
    case_id: str,
    passed: bool,
    connector: str,
    case_by_id: Mapping[str, Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    integration_mode: str | None,
) -> None:
    record = normalize_case_record(
        {
            "case_id": case_id,
            "status": "PASS" if passed else "FAIL",
            "actual_status": 403,
            "observed_rule_ids": [1100001],
            "live_executed": True,
            "reason": "derived from the observed rule-1100001 event",
        },
        connector,
        case_by_id,
        events,
        integration_mode,
    )
    if record:
        records.append(record)
        by_id[case_id] = record


def append_body_payload_derivation(
    records: list[dict[str, Any]],
    by_id: Mapping[str, Mapping[str, Any]],
    selections: Mapping[str, Mapping[str, Any]],
    plan: Mapping[str, Any],
    case_by_id: Mapping[str, Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    event: Mapping[str, Any],
    integration_mode: str | None,
) -> None:
    if canonical_event_errors(event, integration_mode=integration_mode):
        return
    case_id = "event_has_no_request_body_payload"
    if not selected_plan_case(selections, case_id):
        return
    body_base = by_id.get("deny_request_body_marker_403")
    body_event = event_for_rule(events, 1100101)
    if not body_base or body_base.get("status") != "PASS" or not body_event:
        return
    record = normalize_case_record(
        {
            "case_id": case_id,
            "status": "PASS",
            "actual_status": 403,
            "observed_rule_ids": [1100101],
            "live_executed": True,
            "reason": "observed phase-2 event contains no forbidden body payload",
        },
        str(plan["connector"]),
        case_by_id,
        events,
        integration_mode,
    )
    if record:
        records.append(record)


def append_derived_phase4_records(
    records: list[dict[str, Any]],
    plan: Mapping[str, Any],
    case_by_id: Mapping[str, Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    integration_mode: str | None = None,
) -> None:
    """Reuse a valid Phase-4 outcome event for its narrower evidence claims.

    Each real pre-commit or validated log-only late-intervention outcome
    observes rule 1100301.  Its status/action fields may prove the narrower
    facts for that exact transaction.  The inverse is never true: this helper
    deliberately never derives one disruptive outcome from another.  The
    strict-mode-specific case remains excluded: its client-visible abort
    contract must not be backfilled from a narrower fact derivation.
    """
    by_id = {str(record.get("case_id") or ""): record for record in records}
    selections = selected_plan_cases(plan)
    for base_case_id in (
        "phase4_deny_before_commit",
        "phase4_deny_after_commit_log_only",
        "phase4_deny_after_commit_log_only_minimal",
        "phase4_deny_after_commit_log_only_safe",
        "phase4_deny_after_commit_abort",
    ):
        append_phase4_derivations_for_base(
            records,
            by_id,
            selections,
            plan,
            case_by_id,
            events,
            base_case_id,
            integration_mode,
        )


def append_phase4_derivations_for_base(
    records: list[dict[str, Any]],
    by_id: dict[str, dict[str, Any]],
    selections: Mapping[str, Mapping[str, Any]],
    plan: Mapping[str, Any],
    case_by_id: Mapping[str, Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    base_case_id: str,
    integration_mode: str | None,
) -> None:
    base = by_id.get(base_case_id)
    if not base or base.get("status") != "PASS":
        return
    for case_id in (
        "phase4_rule_observed",
        "phase4_event_contains_original_status",
        "phase4_event_contains_late_intervention_action",
    ):
        if case_id in by_id or not selected_plan_case(selections, case_id):
            continue
        append_phase4_derived_record(
            records,
            by_id,
            base,
            base_case_id,
            case_id,
            str(plan.get("connector") or base.get("connector") or ""),
            case_by_id,
            events,
            integration_mode,
        )


def append_phase4_derived_record(
    records: list[dict[str, Any]],
    by_id: dict[str, dict[str, Any]],
    base: Mapping[str, Any],
    base_case_id: str,
    case_id: str,
    connector: str,
    case_by_id: Mapping[str, Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    integration_mode: str | None,
) -> None:
    derived_raw = dict(base)
    derived_raw.update({
        "case_id": case_id,
        "status": "PASS",
        "reason": f"derived from the validated {base_case_id} runtime event",
    })
    record = normalize_case_record(
        derived_raw, connector, case_by_id, events, integration_mode,
    )
    if record is not None and record.get("status") == "PASS":
        records.append(record)
        by_id[case_id] = record


def selection_record(
    selection: Mapping[str, Any],
    case: Mapping[str, Any],
    connector: str,
    status: str,
    reason: str,
    exit_code: int | None,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "connector": connector,
        "run_id": None,
        "integration_mode": None,
        "case_id": selection["case_id"],
        "group": case.get("group", ""),
        "phase": case.get("phase"),
        "required_capabilities": list(case.get("required_capabilities", [])),
        "status": status,
        "operation_status": operation_status("blocked" if status == "BLOCKED" else "skipped"),
        "live_executed": False,
        "expected_result": case.get("expected_result"),
        "observed_result": None,
        "expected_status": optional_int(case.get("expected_status")),
        "actual_status": None,
        "expected_rule_id": optional_int(case.get("expected_rule_id")),
        "observed_rule_ids": [],
        "transaction_ids": [],
        "expected_event_fields": list(case.get("expected_event_fields", [])),
        "observed_event_fields": [],
        "event_metadata_verified": False,
        **dict.fromkeys(PHASE4_SEMANTIC_FIELDS),
        "reason": reason,
        "exit_code": exit_code,
        "artifacts": {},
    }


def derive_deprecated_alias_targets(
    records: list[dict[str, Any]],
    plan: Mapping[str, Any],
    case_by_id: Mapping[str, Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    integration_mode: str | None = None,
) -> None:
    """Allow a fully evidenced legacy execution to populate its new target.

    Old host runners may still report ``deny_response_body_marker_403`` during
    the migration.  It can seed the replacement case only after it satisfies
    the strict pre-commit evidence contract; a bare 403 can never do so.
    """
    selections = {
        str(item.get("case_id") or ""): item
        for item in plan.get("cases", [])
        if isinstance(item, Mapping)
    }
    existing = {str(record.get("case_id") or "") for record in records}
    derived: list[dict[str, Any]] = []
    for record in records:
        case = case_by_id.get(str(record.get("case_id") or ""))
        target_id = str(case.get("deprecated_alias_for") or "") if case else ""
        if (
            not target_id
            or target_id in existing
            or record.get("status") != "PASS"
            or selections.get(target_id, {}).get("selection_status") != "SELECTED"
        ):
            continue
        target_raw = dict(record)
        target_raw["case_id"] = target_id
        target_raw["reason"] = (
            f"normalized from deprecated alias {record.get('case_id')} with strict pre-commit evidence"
        )
        target = normalize_case_record(
            target_raw,
            str(record.get("connector") or plan.get("connector") or ""),
            case_by_id,
            events,
            integration_mode,
        )
        if target is not None:
            derived.append(target)
            existing.add(target_id)
    records.extend(derived)


def resolve_deprecated_aliases(
    records: list[dict[str, Any]],
    case_by_id: Mapping[str, Mapping[str, Any]],
    selected_case_ids: set[str] | None = None,
) -> None:
    """Make deprecated aliases a view of the canonical replacement outcome."""
    positions = {str(record.get("case_id") or ""): index for index, record in enumerate(records)}
    for alias_id, case in case_by_id.items():
        resolve_deprecated_alias(
            records, positions, alias_id, case, selected_case_ids,
        )


def resolve_deprecated_alias(
    records: list[dict[str, Any]],
    positions: dict[str, int],
    alias_id: str,
    case: Mapping[str, Any],
    selected_case_ids: set[str] | None,
) -> None:
    if selected_case_ids is not None and alias_id not in selected_case_ids:
        return
    target_id = str(case.get("deprecated_alias_for") or "")
    if not target_id:
        return
    target = deprecated_alias_record(records, positions, target_id)
    alias_index = positions.get(alias_id)
    alias = records[alias_index] if alias_index is not None else None
    if target is not None and target.get("status") == "PASS":
        replacement = deprecated_alias_replacement(target, alias_id, case, target_id)
        replace_deprecated_alias_record(records, positions, alias_id, alias_index, replacement)
        return
    fail_deprecated_alias(alias, target_id)


def deprecated_alias_record(
    records: Sequence[dict[str, Any]], positions: Mapping[str, int], case_id: str,
) -> dict[str, Any] | None:
    index = positions.get(case_id)
    return records[index] if index is not None else None


def deprecated_alias_replacement(
    target: Mapping[str, Any],
    alias_id: str,
    case: Mapping[str, Any],
    target_id: str,
) -> dict[str, Any]:
    replacement = dict(target)
    replacement.update({
        "case_id": alias_id,
        "group": case.get("group", ""),
        "phase": case.get("phase"),
        "required_capabilities": list(case.get("required_capabilities", [])),
        "expected_result": case.get("expected_result"),
        "expected_status": optional_int(case.get("expected_status")),
        "expected_rule_id": optional_int(case.get("expected_rule_id")),
        "expected_event_fields": list(case.get("expected_event_fields", [])),
        "reason": f"deprecated alias for {target_id}; canonical replacement passed",
    })
    return replacement


def replace_deprecated_alias_record(
    records: list[dict[str, Any]],
    positions: dict[str, int],
    alias_id: str,
    alias_index: int | None,
    replacement: dict[str, Any],
) -> None:
    if alias_index is None:
        positions[alias_id] = len(records)
        records.append(replacement)
        return
    records[alias_index] = replacement


def fail_deprecated_alias(alias: dict[str, Any] | None, target_id: str) -> None:
    if alias is None or alias.get("status") != "PASS":
        return
    alias["status"] = "FAIL"
    alias["operation_status"] = operation_status("fail")
    alias["reason"] = (
        f"deprecated alias requires {target_id}=PASS; canonical replacement did not pass"
    )


def load_source_json(path: Path) -> object:
    try:
        return load_json(path)
    except ContractError:
        records = read_jsonl(path)
        return records


def validate_source_payload(source: Mapping[str, Any], manifest: Mapping[str, Any], label: str) -> None:
    connector = str(source.get("connector") or "")
    if connector and connector != manifest.get("connector"):
        raise ContractError(f"{label}: connector mismatch: {connector!r}")
    for field in ("connector_commit", "framework_commit"):
        observed = str(source.get(field) or "")
        expected = str(manifest.get(field) or "")
        if observed and expected not in {"", "unknown"} and observed != expected:
            raise ContractError(f"{label}: {field} mismatch: {observed!r} != {expected!r}")
    ruleset = str(source.get("ruleset") or source.get("modsecurity_ruleset") or "").lower()
    variant = str(source.get("test_variant") or "").lower()
    if ruleset == "crs" or variant == "with-crs" or source.get("crs_verified") is True:
        raise ContractError(f"{label}: CRS evidence cannot be normalized into a No-CRS run")
    payload_errors = forbidden_payload_errors(source, label)
    if payload_errors:
        raise ContractError("; ".join(payload_errors))


def copy_named_log(run_dir: Path, label: str, source_text: str, manifest: dict[str, Any]) -> None:
    if not source_text:
        return
    source = Path(source_text)
    canonical_names = {
        "stdout": "stdout.log",
        "stderr": "stderr.log",
        "host_log": "host.log",
        "rule_load_log": "rule-load.log",
    }
    safe_name = canonical_names.get(label, re.sub(r"[^A-Za-z0-9_.-]", "-", label))
    if label not in canonical_names and not safe_name.endswith(".log"):
        safe_name += ".log"
    destination = run_dir / "logs" / safe_name
    copy_artifact(source, destination)
    manifest["artifacts"][label] = artifact_entry(
        str(destination.relative_to(run_dir)), "produced", sha256=sha256_file(destination)
    )


def copy_first_byte_evidence(
    run_dir: Path,
    source_text: str,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Copy a bounded first-byte barrier record into the canonical inventory.

    A connector harness may create the source record with the reusable
    synchronized upstream helper.  This function deliberately accepts a
    synthetic record for diagnostic retention, but the promotion gate below
    prevents it from proving either first-byte or no-buffer capabilities.
    """
    source = Path(source_text)
    payload = load_json(source)
    errors = first_byte_evidence_errors(payload)
    if errors:
        raise ContractError("; ".join(errors))
    if not isinstance(payload, dict):
        raise ContractError("first-byte evidence must be a JSON object")
    copy_artifact(source, run_dir / FIRST_BYTE_EVIDENCE_RELATIVE_PATH)
    destination = run_dir / FIRST_BYTE_EVIDENCE_RELATIVE_PATH
    manifest["artifacts"]["first_byte_evidence"] = artifact_entry(
        FIRST_BYTE_EVIDENCE_RELATIVE_PATH,
        "produced",
        sha256=sha256_file(destination),
    )
    return payload


def _supplemental_sidecar_errors(
    name: str,
    payload: object,
    *,
    connector: str,
    run_id: str | None,
    integration_mode: str | None,
) -> list[str]:
    """Validate one payload-free supplemental full-lifecycle sidecar."""
    schema_names = {
        "transport_observations": "transport-observations.schema.json",
        "connection_lifecycle": "connection-lifecycle.schema.json",
        "effective_config": "effective-config.schema.json",
    }
    schema_name = schema_names.get(name)
    if schema_name is None:
        return []
    schema = load_json(FRAMEWORK_ROOT / NO_CRS_SCHEMA_DIRECTORY / schema_name)
    if not isinstance(schema, Mapping):
        return [f"{name}: checked-in schema is invalid"]
    errors = json_schema_errors(payload, schema, root_schema=schema, location=name)
    errors.extend(forbidden_payload_errors(payload, name))
    if not isinstance(payload, Mapping):
        return errors
    errors.extend(supplemental_sidecar_identity_errors(
        name, payload, connector, run_id, integration_mode,
    ))
    errors.extend(effective_config_sidecar_errors(name, payload))
    errors.extend(protocol_sidecar_connection_id_errors(name, payload))
    return errors


def supplemental_sidecar_identity_errors(
    name: str,
    payload: Mapping[str, Any],
    connector: str,
    run_id: str | None,
    integration_mode: str | None,
) -> list[str]:
    errors: list[str] = []
    if payload.get("connector") != connector:
        errors.append(f"{name}: connector does not match canonical run")
    if run_id is not None and payload.get("run_id") != run_id:
        errors.append(f"{name}: run_id does not match canonical run")
    if integration_mode is not None and payload.get("integration_mode") != integration_mode:
        errors.append(f"{name}: integration_mode does not match canonical run")
    return errors


def effective_config_sidecar_errors(name: str, payload: Mapping[str, Any]) -> list[str]:
    if name != "effective_config":
        return []
    files = payload.get("files")
    if not isinstance(files, list):
        return []
    errors: list[str] = []
    seen: set[str] = set()
    for index, entry in enumerate(files):
        if not isinstance(entry, Mapping):
            continue
        raw_path = str(entry.get("path") or "")
        path = Path(raw_path)
        if path.is_absolute() or ".." in path.parts or raw_path in {"", "."}:
            errors.append(f"effective_config.files[{index}].path is unsafe")
            continue
        if raw_path in seen:
            errors.append(f"effective_config.files has duplicate path {raw_path!r}")
        seen.add(raw_path)
    return errors


def protocol_sidecar_connection_id_errors(
    name: str, payload: Mapping[str, Any],
) -> list[str]:
    records_key = {
        "transport_observations": "observations",
        "connection_lifecycle": "records",
    }.get(name)
    if records_key is None:
        return []
    records = payload.get(records_key)
    if not isinstance(records, list):
        return []
    errors: list[str] = []
    for index, record in enumerate(records):
        if not isinstance(record, Mapping) or record.get("protocol") != "h3":
            continue
        connection_id = record.get("connection_id")
        if connection_id is not None and not is_hashed_connection_id(connection_id):
            errors.append(
                f"{name}.{records_key}[{index}].connection_id: "
                "raw H3 connection identifiers are forbidden"
            )
    return errors


def _copy_barrier_events_artifact(
    run_dir: Path,
    source_text: str,
    connector: str,
    manifest: dict[str, Any],
    *,
    run_id: str | None,
    integration_mode: str | None,
) -> None:
    """Normalize a bounded barrier-event JSONL sidecar before retaining it."""
    source = Path(source_text)
    raw_records = read_jsonl(source)
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    for index, raw in enumerate(raw_records):
        location = f"barrier_events[{index}]"
        try:
            event = canonicalize_event_phase(raw, location=location)
            event = canonicalize_event_protocol_provenance(event, location=location)
        except ContractError as exc:
            errors.append(str(exc))
            continue
        errors.extend(canonical_event_errors(event, location, connector, integration_mode))
        if run_id is not None and event.get("run_id") != run_id:
            errors.append(f"{location}.run_id does not match canonical run")
        if integration_mode is not None and event.get("integration_mode") != integration_mode:
            errors.append(f"{location}.integration_mode does not match canonical run")
        records.append(event)
    if errors:
        raise ContractError("; ".join(errors))
    destination = run_dir / TRANSPORT_HARDENING_ARTIFACT_PATHS["barrier_events"]
    write_jsonl(destination, records)
    manifest["artifacts"]["barrier_events"] = artifact_entry(
        str(destination.relative_to(run_dir)), "produced", sha256=sha256_file(destination)
    )


def copy_engine_lifecycle_artifacts(
    run_dir: Path,
    source_artifacts: Sequence[str],
    connector: str,
    artifact_profile: str,
    manifest: dict[str, Any],
    *,
    run_id: str | None = None,
    integration_mode: str | None = None,
) -> None:
    """Copy allowlisted engine and transport-hardening artifacts into a run.

    These files are inventory only.  They cannot affect case selection or
    capability promotion, which continues to require transaction-bound event
    evidence plus the dedicated transport-hardening validator.  Keeping this
    allowlist in the Framework prevents arbitrary raw connector files from
    entering canonical evidence.
    """
    if not source_artifacts:
        return
    if artifact_profile != FULL_LIFECYCLE_ARTIFACT_PROFILE:
        raise ContractError("engine lifecycle artifacts require the full_lifecycle profile")
    seen: set[str] = set()
    for item in source_artifacts:
        name, source_text = parse_engine_lifecycle_artifact(item, seen)
        copy_engine_lifecycle_artifact(
            run_dir,
            name,
            source_text,
            connector,
            manifest,
            run_id=run_id,
            integration_mode=integration_mode,
        )


def parse_engine_lifecycle_artifact(item: str, seen: set[str]) -> tuple[str, str]:
    if "=" not in item:
        raise ContractError("--source-artifact must be NAME=PATH")
    name, source_text = item.split("=", 1)
    allowed_names = {
        *ENGINE_LIFECYCLE_ARTIFACT_PATHS,
        *TRANSPORT_HARDENING_ARTIFACT_PATHS,
    }
    if name not in allowed_names:
        raise ContractError(f"unsupported engine lifecycle artifact: {name!r}")
    if name in seen:
        raise ContractError(f"duplicate engine lifecycle artifact: {name}")
    seen.add(name)
    return name, source_text


def copy_engine_lifecycle_artifact(
    run_dir: Path,
    name: str,
    source_text: str,
    connector: str,
    manifest: dict[str, Any],
    *,
    run_id: str | None,
    integration_mode: str | None,
) -> None:
    if name == "barrier_events":
        _copy_barrier_events_artifact(
            run_dir,
            source_text,
            connector,
            manifest,
            run_id=run_id,
            integration_mode=integration_mode,
        )
        return
    source = engine_lifecycle_source(name, source_text)
    if name in {"client_log", "upstream_log", "transport_log", "cleanup_log"}:
        copy_engine_lifecycle_artifact_file(run_dir, name, source, manifest)
        return
    if name in {"engine_version", "engine_library_sha256", "ruleset_sha256"}:
        validate_engine_lifecycle_text_artifact(name, source)
    else:
        payload = load_json(source)
        validate_engine_lifecycle_json_artifact(
            name, payload, connector, run_id, integration_mode,
        )
        if copy_engine_lifecycle_json_sidecar(run_dir, name, payload, manifest):
            return
    copy_engine_lifecycle_artifact_file(run_dir, name, source, manifest)


def engine_lifecycle_source(name: str, source_text: str) -> Path:
    source = Path(source_text)
    if name != "effective_config" or not source.is_dir():
        return source
    if source.is_symlink():
        raise ContractError("effective_config source directory must not be a symlink")
    return source / MANIFEST_FILE_NAME


def copy_engine_lifecycle_artifact_file(
    run_dir: Path, name: str, source: Path, manifest: dict[str, Any],
) -> None:
    destination_path = (
        TRANSPORT_HARDENING_ARTIFACT_PATHS.get(name)
        or ENGINE_LIFECYCLE_ARTIFACT_PATHS[name]
    )
    destination = run_dir / destination_path
    copy_artifact(source, destination)
    manifest["artifacts"][name] = artifact_entry(
        str(destination.relative_to(run_dir)), "produced", sha256=sha256_file(destination)
    )


def validate_engine_lifecycle_text_artifact(name: str, source: Path) -> None:
    try:
        text = source.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ContractError(f"cannot read engine lifecycle artifact {name}: {exc}") from exc
    if not text:
        raise ContractError(f"engine lifecycle artifact {name} is empty")
    if name != "engine_version" and re.fullmatch(r"[0-9a-f]{64}", text) is None:
        raise ContractError(f"engine lifecycle artifact {name} must contain a SHA-256 digest")


def validate_engine_lifecycle_json_artifact(
    name: str,
    payload: object,
    connector: str,
    run_id: str | None,
    integration_mode: str | None,
) -> None:
    if not isinstance(payload, Mapping):
        raise ContractError(f"engine lifecycle artifact {name} must be an object")
    supplemental_errors = _supplemental_sidecar_errors(
        name,
        payload,
        connector=connector,
        run_id=run_id,
        integration_mode=integration_mode,
    )
    if supplemental_errors:
        raise ContractError("; ".join(supplemental_errors))
    if name in {"transport_observations", "connection_lifecycle", "effective_config"}:
        return
    if payload.get("schema_version") != 1 or payload.get("connector") != connector:
        raise ContractError(f"engine lifecycle artifact {name} has invalid identity")
    if name == "transaction_counts":
        validate_transaction_count_artifact(name, payload)
        return
    validate_lifecycle_count_artifact(name, payload)


def copy_engine_lifecycle_json_sidecar(
    run_dir: Path, name: str, payload: object, manifest: dict[str, Any],
) -> bool:
    if name not in {"transport_observations", "connection_lifecycle", "effective_config"}:
        return False
    destination = run_dir / TRANSPORT_HARDENING_ARTIFACT_PATHS[name]
    # JSON is reserialized after strict parsing, so duplicate keys and
    # non-canonical formatting cannot survive into canonical inventory.
    write_json(destination, payload)
    manifest["artifacts"][name] = artifact_entry(
        str(destination.relative_to(run_dir)), "produced", sha256=sha256_file(destination),
    )
    return True


def validate_transaction_count_artifact(name: str, payload: Mapping[str, Any]) -> None:
    observed = payload.get("transactions_observed")
    identifiers = payload.get("transaction_ids")
    if not isinstance(observed, int) or observed < 0 or not isinstance(identifiers, list):
        raise ContractError(f"engine lifecycle artifact {name} has invalid transaction accounting")
    if (
        observed != len(identifiers)
        or not all(isinstance(value, str) and value for value in identifiers)
        or len(set(identifiers)) != len(identifiers)
    ):
        raise ContractError(f"engine lifecycle artifact {name} has inconsistent transaction accounting")


def validate_lifecycle_count_artifact(name: str, payload: Mapping[str, Any]) -> None:
    counter_names = (
        "transactions_started", "transactions_finished", "transactions_destroyed",
        "request_body_finishes", "response_body_finishes", "interventions_seen",
        "intentional_aborts", "unexpected_engine_errors",
    )
    if any(not isinstance(payload.get(field), int) or payload[field] < 0 for field in counter_names):
        raise ContractError(f"engine lifecycle artifact {name} has invalid counters")
    optional_counter_names = (
        "client_disconnects", "upstream_disconnects", "stream_resets", "timeouts",
        "short_writes", "write_would_block", "cleanup_normal", "cleanup_cancel",
        "cleanup_abort",
    )
    if any(
        field in payload and (not isinstance(payload[field], int) or payload[field] < 0)
        for field in optional_counter_names
    ):
        raise ContractError(f"engine lifecycle artifact {name} has invalid transport counters")
    if "transport_counters_bound" in payload and not isinstance(payload["transport_counters_bound"], bool):
        raise ContractError(f"engine lifecycle artifact {name} has invalid transport_counters_bound")
    if not (
        payload["transactions_started"] >= payload["transactions_finished"]
        >= payload["transactions_destroyed"]
    ):
        raise ContractError(f"engine lifecycle artifact {name} has inconsistent transaction lifecycle")


def copy_protocol_client_artifacts(
    run_dir: Path,
    source_text: str,
    artifact_profile: str,
    manifest: dict[str, Any],
) -> Path:
    """Copy the managed payload-free client bundle into a canonical run.

    A protocol case may not cite an arbitrary external artifact directory.  A
    full-lifecycle finalizer copies the narrow allowlist into its own
    inventory, declares checksums in the manifest, and later binds that bundle
    to the canonical case/event identity.  The optional follow-up observation
    is retained only when the strict client produced it.
    """

    if artifact_profile != FULL_LIFECYCLE_ARTIFACT_PROFILE:
        raise ContractError("protocol client artifacts require the full_lifecycle profile")
    source = Path(source_text)
    if source.is_symlink() or not source.is_dir():
        raise ContractError("protocol client artifact directory is missing or unsafe")
    destination_root = run_dir / PROTOCOL_CLIENT_ARTIFACT_DIR
    for name in PROTOCOL_CLIENT_REQUIRED_ARTIFACT_NAMES:
        source_name = Path(PROTOCOL_CLIENT_ARTIFACT_PATHS[name]).name
        input_path = source / source_name
        if input_path.is_symlink() or not input_path.is_file():
            raise ContractError(f"protocol client artifact is missing or unsafe: {source_name}")
        destination = run_dir / PROTOCOL_CLIENT_ARTIFACT_PATHS[name]
        copy_artifact(input_path, destination)
        manifest["artifacts"][name] = artifact_entry(
            str(destination.relative_to(run_dir)), "produced", sha256=sha256_file(destination)
        )
    followup_source = source / Path(PROTOCOL_CLIENT_ARTIFACT_PATHS["client_followup_observation"]).name
    if followup_source.exists():
        if followup_source.is_symlink() or not followup_source.is_file():
            raise ContractError("protocol client follow-up artifact is unsafe")
        followup_destination = run_dir / PROTOCOL_CLIENT_ARTIFACT_PATHS["client_followup_observation"]
        copy_artifact(followup_source, followup_destination)
        manifest["artifacts"]["client_followup_observation"] = artifact_entry(
            str(followup_destination.relative_to(run_dir)), "produced",
            sha256=sha256_file(followup_destination),
        )
    return destination_root


def protocol_client_artifact_errors(
    artifact_dir: Path,
    record: Mapping[str, Any],
    protocol: str,
) -> list[str]:
    """Delegate the client half of a protocol PASS to its narrow validator."""

    try:
        from check_protocol_evidence import validate_protocol_artifacts
    except ImportError as exc:  # pragma: no cover - source checkout defect
        return [f"protocol client evidence checker is unavailable: {exc}"]
    strict = str(record.get("expected_result") or "") == "connection_aborted_strict"
    visible_status = record.get("visible_http_status")
    expected_client_status = (
        visible_status
        if isinstance(visible_status, int) and not isinstance(visible_status, bool)
        else None
    )
    stream_id = record.get("stream_id")
    expected_stream_id = (
        stream_id if isinstance(stream_id, int) and not isinstance(stream_id, bool) else None
    )
    upstream_protocol = record.get("upstream_protocol")
    expected_upstream_protocol = (
        str(upstream_protocol) if isinstance(upstream_protocol, str) and upstream_protocol else None
    )
    transport_case_id = record.get("transport_case_id")
    expected_transport_case_id = (
        str(transport_case_id)
        if isinstance(transport_case_id, str) and transport_case_id else None
    )
    return validate_protocol_artifacts(
        artifact_dir,
        protocol=protocol,
        strict=strict,
        connector=str(record.get("connector") or "") or None,
        integration_mode=str(record.get("integration_mode") or "") or None,
        run_id=str(record.get("run_id") or "") or None,
        transaction_id=(
            str(record.get("transaction_ids", [""])[0])
            if isinstance(record.get("transaction_ids"), list)
            and record.get("transaction_ids") else None
        ),
        rule_id=(
            str(record.get("expected_rule_id"))
            if record.get("expected_rule_id") is not None else None
        ),
        phase=str(record.get("phase") or "") or None,
        expected_client_status=expected_client_status,
        expected_stream_id=expected_stream_id,
        expected_upstream_protocol=expected_upstream_protocol,
        expected_transport_case_id=expected_transport_case_id,
    )


def record_protocol_profile(
    record: Mapping[str, Any], case: Mapping[str, Any] | None,
) -> str | None:
    """Return the modern downstream profile asserted by one case record.

    A catalog profile is authoritative, but validation must also catch a
    legacy/generic case that tries to assert modern provenance directly in
    its result.  The historical ``transport_protocol`` field is deliberately
    excluded because it cannot promote H2/H3 evidence by itself.
    """

    if case is not None:
        profile = case_protocol_profile(case)
        if profile in {"h2", "h2c", "h3"}:
            return profile
    for field in (
        "negotiated_protocol", "downstream_protocol", "requested_protocol",
    ):
        value = record.get(field)
        if value in {"h2", "h2c", "h3"}:
            return str(value)
    return None


def prevent_synthetic_first_byte_promotion(
    records: Sequence[dict[str, Any]],
    evidence: Mapping[str, Any] | None,
) -> None:
    """Downgrade only the claims a synthetic barrier run cannot establish."""
    if evidence is None or evidence.get("evidence_origin") == "real_host":
        return
    protected_case_ids = {
        "phase4_first_byte_before_response_end",
        "phase4_no_full_response_buffering",
    }
    for record in records:
        if record.get("case_id") not in protected_case_ids or record.get("status") != "PASS":
            continue
        record["status"] = "FAIL"
        record["operation_status"] = operation_status("fail")
        record["reason"] = (
            "synthetic first-byte evidence is retained for diagnostics but cannot "
            "promote a canonical host capability"
        )


def require_full_lifecycle_artifact_inputs(args: argparse.Namespace) -> None:
    """Require host-produced evidence inputs for the opt-in full-lifecycle profile.

    Result and case-result records are normalized by this command, but events
    and the three logs must originate with the host run.  Empty input files are
    allowed for failed or inconclusive runs; silently omitted files are not.
    """
    required_arguments = (
        ("--source-events", args.source_events),
        ("--stdout-log", args.stdout_log),
        ("--stderr-log", args.stderr_log),
        ("--host-log", args.host_log),
        ("--first-byte-evidence", args.first_byte_evidence),
    )
    missing = [name for name, value in required_arguments if not str(value or "").strip()]
    if missing:
        raise ContractError(
            "full_lifecycle artifact profile requires host-produced "
            + ", ".join(missing)
        )


def aggregate_status(
    records: Sequence[Mapping[str, Any]],
    stage_rc: int,
    *,
    source_failure: bool = False,
) -> tuple[str, bool]:
    started = any(record.get("live_executed") is True for record in records)
    statuses = Counter(str(record.get("status")) for record in records)
    if stage_rc == 77:
        return ("FAIL", False) if started else ("BLOCKED", True)
    if stage_rc != 0 or source_failure or statuses["FAIL"]:
        return "FAIL", False
    if statuses["BLOCKED"]:
        return "BLOCKED", not started
    if statuses["NOT_EXECUTED"]:
        return "NOT_EXECUTED", False
    if statuses["PASS"]:
        return "PASS", False
    if statuses["UNSUPPORTED"]:
        return "UNSUPPORTED", False
    return "NOT_APPLICABLE", False


def canonical_pass_gate_failures(
    evidence_stage: str,
    pass_ids: set[str],
    event_metadata_verified: bool,
    body_payload_absent_from_events: bool,
    host_version: object,
    libmodsecurity_version: object,
) -> list[str]:
    failures: list[str] = []
    if evidence_stage == "minimal_runtime_smoke" and not (
        {"allow_without_marker", "deny_header_marker_403"}.issubset(pass_ids)
        and event_metadata_verified
        and body_payload_absent_from_events
    ):
        failures.append(
            "minimal runtime PASS requires the canonical rule-1100001 metadata event and payload absence"
        )
    if not concrete_version(host_version):
        failures.append("PASS requires a concrete host version")
    if not concrete_version(libmodsecurity_version):
        failures.append("PASS requires a concrete libModSecurity version")
    return failures


def provenance_pass_gate_failures(payload: Mapping[str, Any]) -> list[str]:
    """Return fail-closed PASS gates for the end-of-run repository state."""
    if payload.get("provenance_required") is not True:
        return []
    failures: list[str] = []
    connector_commit = str(payload.get("connector_commit") or "unknown")
    framework_commit = str(payload.get("framework_commit") or "unknown")
    connector_commit_at_finalize = str(
        payload.get("connector_commit_at_finalize") or "unknown"
    )
    framework_commit_at_finalize = str(
        payload.get("framework_commit_at_finalize") or "unknown"
    )
    if connector_commit_at_finalize == "unknown":
        failures.append("PASS requires a resolvable connector commit at finalize")
    elif connector_commit_at_finalize != connector_commit:
        failures.append("PASS requires an unchanged connector commit through finalize")
    if framework_commit_at_finalize == "unknown":
        failures.append("PASS requires a resolvable framework commit at finalize")
    elif framework_commit_at_finalize != framework_commit:
        failures.append("PASS requires an unchanged framework commit through finalize")
    return failures


def aggregate_case_status(records: Sequence[Mapping[str, Any]]) -> str:
    statuses = Counter(str(record.get("status")) for record in records)
    if statuses["FAIL"]:
        return "FAIL"
    if statuses["BLOCKED"]:
        return "BLOCKED"
    if statuses["NOT_EXECUTED"]:
        return "NOT_EXECUTED"
    if statuses["PASS"]:
        return "PASS"
    if statuses["UNSUPPORTED"]:
        return "UNSUPPORTED"
    return "NOT_APPLICABLE"


def phase4_case_result_projection(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return the payload-free Phase-4 portion of a canonical case result."""
    fields = (
        "case_id",
        "status",
        "live_executed",
        "run_id",
        "integration_mode",
        "expected_result",
        "expected_rule_id",
        "observed_rule_ids",
        "transaction_ids",
        *PHASE4_SEMANTIC_FIELDS,
    )
    return {field: record.get(field) for field in fields}


def bind_case_protocol_provenance(
    records: Sequence[dict[str, Any]],
    manifest: Mapping[str, Any],
    case_by_id: Mapping[str, Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    event_integration_mode: str | None,
) -> None:
    """Bind case records to their canonical run and recheck protocol PASSes.

    Case results are stored inside one run directory, but protocol promotion
    additionally requires an explicit event-level run/integration identity.
    This final binding prevents a source result from borrowing an H2/H3 event
    from another run or host mode.
    """
    run_id = str(manifest.get("run_id") or "")
    integration_mode = str(manifest.get("integration_mode") or "")
    for record in records:
        context_errors = case_protocol_context_errors(record, run_id, integration_mode)
        record["run_id"] = run_id
        record["integration_mode"] = integration_mode
        if record.get("status") != "PASS":
            continue
        case = case_by_id.get(str(record.get("case_id") or ""))
        matching_event = matching_protocol_event(
            record, case, events, event_integration_mode,
        )
        context_errors.extend(case_protocol_pass_errors(
            record, matching_event, case, run_id, integration_mode,
        ))
        mark_protocol_provenance_invalid(record, context_errors)


def case_protocol_context_errors(
    record: Mapping[str, Any], run_id: str, integration_mode: str,
) -> list[str]:
    errors: list[str] = []
    if record.get("run_id") is not None and record.get("run_id") != run_id:
        errors.append("source case run_id does not match canonical run")
    if record.get("integration_mode") is not None and record.get("integration_mode") != integration_mode:
        errors.append("source case integration_mode does not match canonical run")
    return errors


def matching_protocol_event(
    record: Mapping[str, Any],
    case: Mapping[str, Any] | None,
    events: Sequence[Mapping[str, Any]],
    event_integration_mode: str | None,
) -> Mapping[str, Any] | None:
    if case is None:
        return None
    transaction_ids = [str(value) for value in record.get("transaction_ids", [])]
    return event_for_case(
        events,
        optional_int(record.get("expected_rule_id")),
        case,
        transaction_ids,
        event_integration_mode,
    )


def case_protocol_pass_errors(
    record: Mapping[str, Any],
    matching_event: Mapping[str, Any] | None,
    case: Mapping[str, Any] | None,
    run_id: str,
    integration_mode: str,
) -> list[str]:
    required_protocol = case_protocol_profile(case) if case is not None else None
    return protocol_pass_errors(
        record,
        matching_event,
        expected_run_id=run_id,
        expected_integration_mode=integration_mode,
        required_protocol=required_protocol,
    )


def mark_protocol_provenance_invalid(record: dict[str, Any], errors: Sequence[str]) -> None:
    if not errors:
        return
    record["status"] = "FAIL"
    record["operation_status"] = operation_status("fail")
    detail = "; ".join(dict.fromkeys(errors))
    record["reason"] = "; ".join(
        part for part in (str(record.get("reason") or ""), f"protocol provenance invalid: {detail}")
        if part
    )


class FinalizeContext:
    def __init__(
        self,
        connector_root: Path | None,
        run_dir: Path,
        manifest_path: Path,
        manifest: dict[str, Any],
        plan: dict[str, Any],
        artifact_profile: str,
        host_profile: str,
        provenance_required: bool,
        connector: str,
        evidence_stage: str,
        event_integration_mode: str | None,
        capabilities: Mapping[str, Any],
        case_by_id: dict[str, Mapping[str, Any]],
    ) -> None:
        self.connector_root = connector_root
        self.run_dir = run_dir
        self.manifest_path = manifest_path
        self.manifest = manifest
        self.plan = plan
        self.artifact_profile = artifact_profile
        self.host_profile = host_profile
        self.provenance_required = provenance_required
        self.connector = connector
        self.evidence_stage = evidence_stage
        self.event_integration_mode = event_integration_mode
        self.capabilities = capabilities
        self.case_by_id = case_by_id


class FinalizeSummaryValues(TypedDict):
    status: str
    blocked_before_execution: bool
    source_statuses: list[str]
    source_failure: bool
    counts: Counter[str]
    observed_rule_ids: list[int]
    transaction_ids: list[str]
    pass_ids: set[str]
    verified_capabilities: list[str]
    unsupported_capabilities: list[str]
    not_exercised_capabilities: list[str]
    requests_sent: bool
    started: bool
    event_metadata_verified: bool
    body_payload_absent_from_events: bool
    host_version: object
    libmodsecurity_version: object
    minimal_runtime_verified: bool
    pass_gate_failures: list[str]
    allowed_record: Mapping[str, Any]
    blocked_record: Mapping[str, Any]
    evidence_stages: dict[str, Any]


class FinalizeSummary:
    def __init__(self, values: FinalizeSummaryValues) -> None:
        self.status = values["status"]
        self.blocked_before_execution = values["blocked_before_execution"]
        self.source_statuses = values["source_statuses"]
        self.source_failure = values["source_failure"]
        self.counts = values["counts"]
        self.observed_rule_ids = values["observed_rule_ids"]
        self.transaction_ids = values["transaction_ids"]
        self.pass_ids = values["pass_ids"]
        self.verified_capabilities = values["verified_capabilities"]
        self.unsupported_capabilities = values["unsupported_capabilities"]
        self.not_exercised_capabilities = values["not_exercised_capabilities"]
        self.requests_sent = values["requests_sent"]
        self.started = values["started"]
        self.event_metadata_verified = values["event_metadata_verified"]
        self.body_payload_absent_from_events = values["body_payload_absent_from_events"]
        self.host_version = values["host_version"]
        self.libmodsecurity_version = values["libmodsecurity_version"]
        self.minimal_runtime_verified = values["minimal_runtime_verified"]
        self.pass_gate_failures = values["pass_gate_failures"]
        self.allowed_record = values["allowed_record"]
        self.blocked_record = values["blocked_record"]
        self.evidence_stages = values["evidence_stages"]


def load_initialized_finalize_documents(run_dir: Path) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    manifest_path = run_dir / MANIFEST_FILE_NAME
    plan_path = run_dir / PLAN_FILE_NAME
    if not manifest_path.is_file() or not plan_path.is_file():
        raise ContractError("finalize requires an initialized run-dir with manifest.json and plan.json")
    manifest = load_json(manifest_path)
    plan = load_json(plan_path)
    if not isinstance(manifest, dict) or not isinstance(plan, dict):
        raise ContractError("manifest and plan must be JSON objects")
    return manifest_path, manifest, plan


def validate_finalize_profiles(
    run_dir: Path, manifest: Mapping[str, Any], plan: Mapping[str, Any],
) -> tuple[str, str]:
    artifact_profile = canonical_artifact_profile(manifest, MANIFEST_FILE_NAME)
    host_profile = canonical_host_profile(manifest, MANIFEST_FILE_NAME)
    if canonical_artifact_profile(plan, PLAN_FILE_NAME) != artifact_profile:
        raise ContractError("manifest and plan artifact profiles differ")
    if canonical_host_profile(plan, PLAN_FILE_NAME) != host_profile:
        raise ContractError("manifest and plan host profiles differ")
    inventory = load_json(run_dir / RUN_INVENTORY_FILE_PATH)
    if not isinstance(inventory, Mapping):
        raise ContractError("inventory/run.json must contain an object")
    if canonical_artifact_profile(inventory, RUN_INVENTORY_FILE_PATH) != artifact_profile:
        raise ContractError("manifest and inventory artifact profiles differ")
    if canonical_host_profile(inventory, RUN_INVENTORY_FILE_PATH) != host_profile:
        raise ContractError("manifest and inventory host profiles differ")
    return artifact_profile, host_profile


def finalize_provenance_required(manifest: Mapping[str, Any]) -> bool:
    return bool(
        manifest.get("provenance_required") is True
        or manifest.get("connector_commit") not in {None, "", "unknown"}
    )


def load_finalize_context(args: argparse.Namespace) -> FinalizeContext:
    connector_root = Path(args.connector_root).resolve() if args.connector_root else None
    run_dir = Path(args.run_dir)
    safe_run_dir(run_dir, connector_root)
    manifest_path, manifest, plan = load_initialized_finalize_documents(run_dir)
    artifact_profile, host_profile = validate_finalize_profiles(run_dir, manifest, plan)
    if artifact_profile == FULL_LIFECYCLE_ARTIFACT_PROFILE:
        require_full_lifecycle_artifact_inputs(args)
    provenance_required = finalize_provenance_required(manifest)
    if provenance_required and connector_root is None:
        raise ContractError("finalize requires --connector-root for repository provenance")
    connector = str(manifest.get("connector") or "")
    evidence_stage = str(manifest.get("evidence_stage") or "")
    if evidence_stage not in WRITABLE_EVIDENCE_STAGES:
        raise ContractError(f"unsupported writable evidence stage: {evidence_stage!r}")
    capabilities = load_capability_manifest(run_dir / CAPABILITIES_INVENTORY_FILE_PATH, connector)
    supplied_capabilities = load_capability_manifest(args.capabilities, connector)
    if capabilities != supplied_capabilities:
        raise ContractError("capability manifest changed between init and finalize")
    catalog = load_catalog()
    case_by_id = {case["case_id"]: case for case in catalog_cases(catalog)}
    return FinalizeContext(
        connector_root,
        run_dir,
        manifest_path,
        manifest,
        plan,
        artifact_profile,
        host_profile,
        provenance_required,
        connector,
        evidence_stage,
        required_event_integration_mode(manifest),
        capabilities,
        case_by_id,
    )


def canonical_finalize_event(
    source_event: Mapping[str, Any], index: int, connector: str,
) -> dict[str, Any]:
    location = f"events[{index}]"
    event = canonicalize_event_phase(source_event, location=location)
    event = canonicalize_event_protocol_provenance(event, location=location)
    errors = canonical_event_errors(event, location, connector)
    if errors:
        raise ContractError("; ".join(errors))
    return event


def copy_finalize_events(context: FinalizeContext, args: argparse.Namespace) -> list[dict[str, Any]]:
    if not args.source_events:
        return []
    events = [
        canonical_finalize_event(source_event, index, context.connector)
        for index, source_event in enumerate(read_jsonl(args.source_events))
    ]
    # Serialize reviewed parsed records rather than copying raw JSONL text, so
    # duplicate keys and parser ambiguities cannot enter canonical evidence.
    destination = context.run_dir / EVENTS_FILE_NAME
    write_jsonl(destination, events)
    context.manifest["artifacts"]["events"] = artifact_entry(
        EVENTS_FILE_NAME, "produced", sha256=sha256_file(destination),
    )
    return events


def copy_finalize_supporting_artifacts(
    context: FinalizeContext, args: argparse.Namespace,
) -> tuple[dict[str, Any] | None, Path | None]:
    first_byte_evidence = copy_optional_first_byte_evidence(context, args)
    copy_engine_lifecycle_artifacts(
        context.run_dir,
        args.source_artifact,
        context.connector,
        context.artifact_profile,
        context.manifest,
        run_id=str(context.manifest.get("run_id") or "") or None,
        integration_mode=str(context.manifest.get("integration_mode") or "") or None,
    )
    return first_byte_evidence, copy_optional_protocol_client_artifacts(context, args)


def copy_optional_first_byte_evidence(
    context: FinalizeContext, args: argparse.Namespace,
) -> dict[str, Any] | None:
    if not args.first_byte_evidence:
        return None
    return copy_first_byte_evidence(
        context.run_dir, args.first_byte_evidence, context.manifest,
    )


def copy_optional_protocol_client_artifacts(
    context: FinalizeContext, args: argparse.Namespace,
) -> Path | None:
    source_text = str(getattr(args, "protocol_client_artifact_dir", "") or "").strip()
    if not source_text:
        return None
    return copy_protocol_client_artifacts(
        context.run_dir,
        source_text,
        context.artifact_profile,
        context.manifest,
    )


def validate_source_records(
    records: Sequence[Mapping[str, Any]], manifest: Mapping[str, Any], source: Path,
) -> None:
    for index, record in enumerate(records):
        validate_source_payload(record, manifest, f"{source}[{index}]")


def retain_finalize_source_artifact(
    context: FinalizeContext,
    source: Path,
    artifact_key: str,
    filename: str,
) -> None:
    destination = context.run_dir / "inventory" / filename
    copy_artifact(source, destination)
    context.manifest["artifacts"][artifact_key] = artifact_entry(
        str(destination.relative_to(context.run_dir)), "produced", sha256=sha256_file(destination),
    )


def collect_finalize_result_sources(
    context: FinalizeContext,
    source_texts: Sequence[str],
    raw_records: list[dict[str, Any]],
    source_payloads: list[Mapping[str, Any]],
    source_index: int,
) -> int:
    for source_text in source_texts:
        source = Path(source_text)
        payload = load_source_json(source)
        if isinstance(payload, Mapping):
            validate_source_payload(payload, context.manifest, str(source))
            source_payloads.append(payload)
        payload_records = source_records(payload)
        validate_source_records(payload_records, context.manifest, source)
        raw_records.extend(payload_records)
        retain_finalize_source_artifact(
            context,
            source,
            f"source_result_{source_index}",
            f"source-result-{source_index}.json",
        )
        source_index += 1
    return source_index


def collect_finalize_jsonl_sources(
    context: FinalizeContext,
    source_texts: Sequence[str],
    raw_records: list[dict[str, Any]],
    source_index: int,
) -> int:
    for source_text in source_texts:
        source = Path(source_text)
        payload_records = read_jsonl(source)
        validate_source_records(payload_records, context.manifest, source)
        raw_records.extend(payload_records)
        retain_finalize_source_artifact(
            context,
            source,
            f"source_results_{source_index}",
            f"source-results-{source_index}.jsonl",
        )
        source_index += 1
    return source_index


def summary_connector_payload(
    payload: object, connector: str,
) -> Mapping[str, Any] | None:
    if not isinstance(payload, Mapping):
        return None
    connector_payload = payload.get(connector)
    if isinstance(connector_payload, Mapping):
        return connector_payload
    return payload


def collect_finalize_summary_sources(
    context: FinalizeContext,
    source_texts: Sequence[str],
    raw_records: list[dict[str, Any]],
    source_payloads: list[Mapping[str, Any]],
    source_index: int,
) -> int:
    for source_text in source_texts:
        source = Path(source_text)
        selected_payload = summary_connector_payload(load_json(source), context.connector)
        if selected_payload is not None:
            validate_source_payload(selected_payload, context.manifest, str(source))
            source_payloads.append(selected_payload)
            payload_records = source_records(selected_payload)
            validate_source_records(payload_records, context.manifest, source)
            raw_records.extend(payload_records)
        retain_finalize_source_artifact(
            context,
            source,
            f"source_summary_{source_index}",
            f"source-summary-{source_index}.json",
        )
        source_index += 1
    return source_index


def collect_finalize_sources(
    context: FinalizeContext, args: argparse.Namespace,
) -> tuple[list[dict[str, Any]], list[Mapping[str, Any]]]:
    raw_records: list[dict[str, Any]] = []
    source_payloads: list[Mapping[str, Any]] = []
    source_index = collect_finalize_result_sources(
        context, args.source_result or [], raw_records, source_payloads, 0,
    )
    source_index = collect_finalize_jsonl_sources(
        context, args.source_results_jsonl or [], raw_records, source_index,
    )
    collect_finalize_summary_sources(
        context, args.source_summary or [], raw_records, source_payloads, source_index,
    )
    return raw_records, source_payloads


def normalize_finalize_records(
    context: FinalizeContext,
    raw_records: Sequence[Mapping[str, Any]],
    source_payloads: Sequence[Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    first_byte_evidence: Mapping[str, Any] | None,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    records = normalized_finalize_case_records(context, raw_records, events)
    for payload in source_payloads:
        records.extend(derive_core_records(
            payload,
            context.connector,
            context.case_by_id,
            events,
            context.event_integration_mode,
        ))
    append_derived_event_records(
        records, context.plan, context.case_by_id, events, context.event_integration_mode,
    )
    derive_deprecated_alias_targets(
        records, context.plan, context.case_by_id, events, context.event_integration_mode,
    )
    append_derived_phase4_records(
        records, context.plan, context.case_by_id, events, context.event_integration_mode,
    )
    prevent_synthetic_first_byte_promotion(records, first_byte_evidence)
    return records, deduplicated_case_records(records)


def normalized_finalize_case_records(
    context: FinalizeContext,
    raw_records: Sequence[Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for raw in raw_records:
        record = normalize_case_record(
            raw,
            context.connector,
            context.case_by_id,
            events,
            context.event_integration_mode,
        )
        if record:
            records.append(record)
    return records


def deduplicated_case_records(records: Sequence[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {record["case_id"]: record for record in records}


def selection_status_reason(
    selection: Mapping[str, Any], stage_rc: int, any_live: bool, stage_reason: str,
) -> tuple[str, str]:
    selection_status = str(selection.get("selection_status") or "")
    selection_reason = str(selection.get("selection_reason") or "")
    declared_statuses = {
        "UNSUPPORTED": ("UNSUPPORTED", "unsupported by capability manifest"),
        "NOT_APPLICABLE": ("NOT_APPLICABLE", "not applicable to host model"),
        "NOT_EXECUTED": ("NOT_EXECUTED", "capability is not implemented"),
    }
    if selection_status in declared_statuses:
        status, default_reason = declared_statuses[selection_status]
        return status, selection_reason or default_reason
    if stage_rc == 77 and not any_live:
        return "BLOCKED", stage_reason or "blocked before execution"
    return "NOT_EXECUTED", stage_reason or "selected case produced no runtime evidence"


def append_missing_selected_records(
    context: FinalizeContext,
    records: list[dict[str, Any]],
    deduplicated: dict[str, dict[str, Any]],
    stage_rc: int,
    stage_reason: str,
) -> None:
    any_live = any(record.get("live_executed") is True for record in records)
    for selection in context.plan.get("cases", []):
        if not isinstance(selection, Mapping):
            continue
        case_id = str(selection.get("case_id") or "")
        if case_id in deduplicated or case_id not in context.case_by_id:
            continue
        status, reason = selection_status_reason(selection, stage_rc, any_live, stage_reason)
        record = selection_record(
            selection, context.case_by_id[case_id], context.connector, status, reason, stage_rc,
        )
        records.append(record)
        deduplicated[case_id] = record


def selected_finalize_case_ids(plan: Mapping[str, Any]) -> set[str]:
    return {
        str(item.get("case_id") or "")
        for item in plan.get("cases", [])
        if isinstance(item, Mapping)
    }


def complete_finalize_records(
    context: FinalizeContext,
    records: list[dict[str, Any]],
    deduplicated: dict[str, dict[str, Any]],
    events: Sequence[Mapping[str, Any]],
    stage_rc: int,
    stage_reason: str,
) -> None:
    append_missing_selected_records(context, records, deduplicated, stage_rc, stage_reason)
    resolve_deprecated_aliases(records, context.case_by_id, selected_finalize_case_ids(context.plan))
    bind_case_protocol_provenance(
        records,
        context.manifest,
        context.case_by_id,
        events,
        context.event_integration_mode,
    )


def validate_protocol_client_records(
    records: Sequence[dict[str, Any]],
    case_by_id: Mapping[str, Mapping[str, Any]],
    artifact_dir: Path | None,
) -> None:
    for record in records:
        validate_protocol_client_record(record, case_by_id, artifact_dir)


def validate_protocol_client_record(
    record: dict[str, Any],
    case_by_id: Mapping[str, Mapping[str, Any]],
    artifact_dir: Path | None,
) -> None:
    if record.get("status") != "PASS":
        return
    case = case_by_id.get(str(record.get("case_id") or ""))
    try:
        protocol = record_protocol_profile(record, case)
    except ContractError as exc:
        protocol = None
        errors = [str(exc)]
    else:
        errors = []
    if protocol not in {"h2", "h2c", "h3"}:
        return
    errors.extend(protocol_client_record_errors(record, protocol, artifact_dir))
    mark_protocol_client_evidence_invalid(record, errors)


def protocol_client_record_errors(
    record: dict[str, Any], protocol: str, artifact_dir: Path | None,
) -> list[str]:
    if str(record.get("expected_result") or "") in DEDICATED_STREAM_CONTROL_RESULTS:
        return [
            "protocol reset/cancel or multiplexing PASS requires a dedicated "
            "stream-control client; the managed curl probe is negotiation-only"
        ]
    if artifact_dir is None:
        return ["protocol PASS requires a managed client artifact bundle"]
    artifacts = record.get("artifacts")
    if not isinstance(artifacts, Mapping):
        artifacts = {}
    record["artifacts"] = {
        **dict(artifacts),
        "protocol_client_dir": PROTOCOL_CLIENT_ARTIFACT_DIR,
    }
    return protocol_client_artifact_errors(artifact_dir, record, protocol)


def mark_protocol_client_evidence_invalid(record: dict[str, Any], errors: Sequence[str]) -> None:
    if not errors:
        return
    record["status"] = "FAIL"
    record["operation_status"] = operation_status("fail")
    detail = "; ".join(dict.fromkeys(errors))
    record["reason"] = "; ".join(
        part for part in (
            str(record.get("reason") or ""),
            f"protocol client evidence invalid: {detail}",
        ) if part
    )


def write_finalize_case_results(
    context: FinalizeContext, records: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    deduplicated = deduplicated_case_records(records)
    order = {
        item["case_id"]: index
        for index, item in enumerate(context.plan.get("cases", []))
        if isinstance(item, Mapping)
    }
    records.sort(key=lambda item: order.get(item["case_id"], len(order)))
    for record in records:
        if record["status"] == "PASS" and record.get("live_executed") is not True:
            raise ContractError(f"{record['case_id']}: PASS requires live_executed=true")
    destination = context.run_dir / CASE_RESULTS_FILE_NAME
    write_jsonl(destination, records)
    context.manifest["artifacts"]["case_results"] = artifact_entry(
        CASE_RESULTS_FILE_NAME, "produced", sha256=sha256_file(destination),
    )
    return deduplicated


def copy_finalize_logs(context: FinalizeContext, args: argparse.Namespace) -> None:
    for key, source_text in (
        ("stdout", args.stdout_log), ("stderr", args.stderr_log),
        ("host_log", args.host_log), ("rule_load_log", args.rule_load_log),
    ):
        copy_named_log(context.run_dir, key, source_text, context.manifest)
    for item in args.source_log or []:
        copy_finalize_source_log(context, item)


def copy_finalize_source_log(context: FinalizeContext, item: str) -> None:
    if "=" not in item:
        raise ContractError("--source-log must be NAME=PATH")
    name, source_text = item.split("=", 1)
    copy_named_log(context.run_dir, name, source_text, context.manifest)


def capture_finalize_provenance(context: FinalizeContext) -> None:
    if context.provenance_required:
        assert context.connector_root is not None
        connector_commit = git_value(context.connector_root, "rev-parse", "HEAD")
        framework_commit = git_value(FRAMEWORK_ROOT, "rev-parse", "HEAD")
        connector_clean = git_worktree_clean(context.connector_root)
        framework_clean = git_worktree_clean(FRAMEWORK_ROOT)
        context.manifest["connector_worktree_clean"] = bool(
            context.manifest.get("connector_worktree_clean") is True and connector_clean
        )
        context.manifest["framework_worktree_clean"] = bool(
            context.manifest.get("framework_worktree_clean") is True and framework_clean
        )
    else:
        connector_commit = str(context.manifest.get("connector_commit") or "unknown")
        framework_commit = str(context.manifest.get("framework_commit") or "unknown")
    context.manifest["provenance_required"] = context.provenance_required
    context.manifest["connector_commit_at_finalize"] = connector_commit
    context.manifest["framework_commit_at_finalize"] = framework_commit


def finalize_capability_sets(
    records: Sequence[Mapping[str, Any]], capabilities: Mapping[str, Any],
) -> tuple[list[str], list[str], list[str]]:
    verified = sorted({
        capability for record in records if record["status"] == "PASS"
        for capability in record["required_capabilities"]
    })
    declared = capabilities.get("capabilities", {})
    unsupported = sorted({
        name for name in CAPABILITIES
        if capability_state(declared.get(name)) in {
            "unsupported_by_host_model", "not_applicable"
        }
    } - set(verified))
    not_exercised = sorted(set(CAPABILITIES) - set(verified) - set(unsupported))
    return verified, unsupported, not_exercised


def finalize_pass_gate(
    context: FinalizeContext,
    status: str,
    blocked_before_execution: bool,
    pass_ids: set[str],
    event_metadata_verified: bool,
    body_payload_absent_from_events: bool,
    host_version: object,
    libmodsecurity_version: object,
    first_byte_evidence: Mapping[str, Any] | None,
) -> tuple[str, bool, list[str]]:
    if status != "PASS":
        return status, blocked_before_execution, []
    failures = canonical_pass_gate_failures(
        context.evidence_stage,
        pass_ids,
        event_metadata_verified,
        body_payload_absent_from_events,
        host_version,
        libmodsecurity_version,
    )
    if context.manifest.get("connector_worktree_clean") is not True:
        failures.append("PASS requires a clean connector worktree")
    if context.manifest.get("framework_worktree_clean") is not True:
        failures.append("PASS requires a clean framework worktree")
    failures.extend(provenance_pass_gate_failures(context.manifest))
    if (
        context.artifact_profile == FULL_LIFECYCLE_ARTIFACT_PROFILE
        and first_byte_evidence is not None
        and first_byte_evidence.get("evidence_origin") != "real_host"
    ):
        failures.append(
            "PASS requires real-host first-byte evidence; synthetic harness output is non-promoting"
        )
    if failures:
        return "FAIL", False, failures
    return status, blocked_before_execution, failures


def finalized_evidence_stages(
    context: FinalizeContext, summary_status: str, minimal_runtime_verified: bool,
) -> dict[str, Any]:
    evidence_stages = json.loads(json.dumps(context.capabilities.get("evidence_stages", {})))
    if isinstance(evidence_stages.get("minimal_runtime_smoke"), Mapping) and minimal_runtime_verified:
        evidence_stages["minimal_runtime_smoke"] = {
            "status": "supported_and_verified",
            "reason": "Current canonical run observed allow, rule-1100001 deny, and required metadata event fields.",
            "evidence": [RESULT_FILE_NAME, CASE_RESULTS_FILE_NAME, EVENTS_FILE_NAME],
        }
    stage_status = {
        "PASS": "supported_and_verified",
        "FAIL": "failed",
        "BLOCKED": "blocked_before_execution",
        "UNSUPPORTED": "unsupported_by_host_model",
        "NOT_APPLICABLE": "unsupported_by_host_model",
        "NOT_EXECUTED": "supported_not_verified",
    }[summary_status]
    evidence_stages[context.evidence_stage] = {
        "status": stage_status,
        "reason": f"Current canonical result status is {summary_status}; unsupported and unexecuted cases are not PASS.",
        "evidence": [RESULT_FILE_NAME, CASE_RESULTS_FILE_NAME],
    }
    return evidence_stages


def build_finalize_summary(
    context: FinalizeContext,
    args: argparse.Namespace,
    records: Sequence[Mapping[str, Any]],
    deduplicated: Mapping[str, Mapping[str, Any]],
    source_payloads: Sequence[Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    first_byte_evidence: Mapping[str, Any] | None,
) -> FinalizeSummary:
    stage_rc = int(args.stage_rc)
    source_statuses = [str(payload.get("status") or "").upper() for payload in source_payloads]
    source_failure = "FAIL" in source_statuses
    status, blocked_before_execution = aggregate_status(
        records, stage_rc, source_failure=source_failure,
    )
    counts = Counter(record["status"] for record in records)
    observed_rule_ids = sorted({
        rule_id for record in records for rule_id in record["observed_rule_ids"]
    })
    transaction_ids = sorted({
        transaction_id for record in records for transaction_id in record["transaction_ids"]
    })
    pass_ids = {record["case_id"] for record in records if record["status"] == "PASS"}
    verified, unsupported, not_exercised = finalize_capability_sets(records, context.capabilities)
    requests_sent = any(record.get("live_executed") is True for record in records)
    source_started = any(payload.get("started") is True for payload in source_payloads)
    event_metadata_verified, body_payload_absent = canonical_core_event_contract(
        events, context.connector, context.event_integration_mode,
    )
    host_version = args.host_version or context.manifest["host_version"]
    libmodsecurity_version = args.libmodsecurity_version or context.manifest["libmodsecurity_version"]
    minimal_runtime_verified = bool(
        {"allow_without_marker", "deny_header_marker_403"}.issubset(pass_ids)
        and event_metadata_verified
        and body_payload_absent
        and concrete_version(host_version)
        and concrete_version(libmodsecurity_version)
    )
    status, blocked_before_execution, pass_gate_failures = finalize_pass_gate(
        context,
        status,
        blocked_before_execution,
        pass_ids,
        event_metadata_verified,
        body_payload_absent,
        host_version,
        libmodsecurity_version,
        first_byte_evidence,
    )
    values: FinalizeSummaryValues = {
        "status": status,
        "blocked_before_execution": blocked_before_execution,
        "source_statuses": source_statuses,
        "source_failure": source_failure,
        "counts": counts,
        "observed_rule_ids": observed_rule_ids,
        "transaction_ids": transaction_ids,
        "pass_ids": pass_ids,
        "verified_capabilities": verified,
        "unsupported_capabilities": unsupported,
        "not_exercised_capabilities": not_exercised,
        "requests_sent": requests_sent,
        "started": source_started or requests_sent,
        "event_metadata_verified": event_metadata_verified,
        "body_payload_absent_from_events": body_payload_absent,
        "host_version": host_version,
        "libmodsecurity_version": libmodsecurity_version,
        "minimal_runtime_verified": minimal_runtime_verified,
        "pass_gate_failures": pass_gate_failures,
        "allowed_record": deduplicated.get("allow_without_marker", {}),
        "blocked_record": deduplicated.get("deny_header_marker_403", {}),
        "evidence_stages": finalized_evidence_stages(
            context, status, minimal_runtime_verified,
        ),
    }
    return FinalizeSummary(values)


def write_finalize_inventory(
    context: FinalizeContext, args: argparse.Namespace, summary: FinalizeSummary,
) -> None:
    inventory_path = context.run_dir / RUN_INVENTORY_FILE_PATH
    inventory = load_json(inventory_path)
    if not isinstance(inventory, dict):
        raise ContractError("inventory/run.json must contain an object")
    inventory["host_version"] = summary.host_version
    inventory["libmodsecurity_version"] = summary.libmodsecurity_version
    for field in (
        "provenance_required", "connector_commit_at_finalize", "framework_commit_at_finalize",
        "connector_worktree_clean", "framework_worktree_clean",
    ):
        inventory[field] = context.manifest[field]
    inventory["finalized_at"] = args.ended_at or utc_now()
    write_json(inventory_path, inventory)
    context.manifest["artifacts"]["inventory"]["sha256"] = sha256_file(inventory_path)


def finalize_group_statuses(records: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    groups = sorted({
        str(record.get("group") or "") for record in records if record.get("group")
    })
    return {
        group: aggregate_case_status([
            record for record in records if record.get("group") == group
        ])
        for group in groups
    }


def finalized_artifact_paths(manifest: Mapping[str, Any]) -> dict[str, str]:
    return {
        name: entry["path"]
        for name, entry in manifest["artifacts"].items()
        if entry["state"] == "produced"
    }


def build_finalize_result(
    context: FinalizeContext,
    args: argparse.Namespace,
    summary: FinalizeSummary,
    records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    declared_capabilities = context.capabilities.get("capabilities", {})
    return {
        "schema_version": 1,
        "status_model": STATUS_MODEL,
        "connector": context.connector,
        "connector_commit": context.manifest["connector_commit"],
        "framework_commit": context.manifest["framework_commit"],
        "connector_worktree_clean": context.manifest.get("connector_worktree_clean", False),
        "framework_worktree_clean": context.manifest.get("framework_worktree_clean", False),
        "provenance_required": context.manifest.get("provenance_required", False),
        "connector_commit_at_finalize": context.manifest.get("connector_commit_at_finalize", "unknown"),
        "framework_commit_at_finalize": context.manifest.get("framework_commit_at_finalize", "unknown"),
        "run_id": context.manifest["run_id"],
        "host_name": context.manifest["host_name"],
        "host_version": summary.host_version,
        "integration_mode": context.manifest["integration_mode"],
        "host_profile": context.host_profile,
        "executed_targets": list(context.manifest.get("executed_targets", [])),
        "libmodsecurity_version": summary.libmodsecurity_version,
        "evidence_stage": context.evidence_stage,
        "artifact_profile": context.artifact_profile,
        "ruleset": "no-crs-baseline",
        "status": summary.status,
        "exit_code": int(args.stage_rc),
        "source_statuses": summary.source_statuses,
        "source_failure": summary.source_failure,
        "blocked_before_execution": summary.blocked_before_execution,
        "started": summary.started,
        "requests_sent": summary.requests_sent,
        "allowed_request_status": summary.allowed_record.get("actual_status"),
        "blocked_request_status": summary.blocked_record.get("actual_status"),
        "observed_rule_ids": summary.observed_rule_ids,
        "transaction_ids": summary.transaction_ids,
        "request_headers_verified": {"allow_without_marker", "deny_header_marker_403"}.issubset(summary.pass_ids),
        "request_body_verified": "deny_request_body_marker_403" in summary.pass_ids,
        "response_headers_verified": "deny_response_header_marker_403" in summary.pass_ids,
        "response_body_verified": "phase4_rule_observed" in summary.pass_ids,
        "late_intervention_verified": bool(
            {
                "phase4_deny_after_commit_log_only",
                "phase4_deny_after_commit_abort",
            }.intersection(summary.pass_ids)
            and "late_intervention" in summary.verified_capabilities
        ),
        "phase4_case_results": [
            phase4_case_result_projection(record)
            for record in records
            if record.get("case_id") in PHASE4_CASE_IDS
        ],
        "event_metadata_verified": summary.event_metadata_verified,
        "body_payload_absent_from_events": summary.body_payload_absent_from_events,
        "pass_gate_failures": summary.pass_gate_failures,
        "cases_total": len(records),
        "cases_passed": summary.counts["PASS"],
        "cases_failed": summary.counts["FAIL"],
        "cases_blocked": summary.counts["BLOCKED"],
        "cases_unsupported": summary.counts["UNSUPPORTED"],
        "cases_not_applicable": summary.counts["NOT_APPLICABLE"],
        "cases_not_executed": summary.counts["NOT_EXECUTED"],
        "status_counts": {name: summary.counts[name] for name in CASE_STATUSES},
        "group_statuses": finalize_group_statuses(records),
        "capabilities_verified": summary.verified_capabilities,
        "capabilities_unsupported": summary.unsupported_capabilities,
        "capabilities_not_exercised": summary.not_exercised_capabilities,
        "capability_states": {
            name: capability_state(declared_capabilities.get(name)) for name in CAPABILITIES
        },
        "evidence_stages": summary.evidence_stages,
        "artifacts": finalized_artifact_paths(context.manifest),
        "claims_not_allowed": list(CLAIMS_NOT_ALLOWED),
        "production_ready": False,
        "security_verified": False,
        "crs_verified": False,
        "crs_complete": False,
        "full_matrix_ready": False,
        "started_at": args.started_at or context.manifest["started_at"],
        "ended_at": args.ended_at or utc_now(),
    }


def write_finalize_result(
    context: FinalizeContext, result: dict[str, Any],
) -> Path:
    context.manifest["host_version"] = result["host_version"]
    context.manifest["libmodsecurity_version"] = result["libmodsecurity_version"]
    context.manifest["started_at"] = result["started_at"]
    context.manifest["status"] = result["status"]
    context.manifest["ended_at"] = result["ended_at"]
    context.manifest["artifacts"]["result"] = artifact_entry(RESULT_FILE_NAME, "produced")
    result["artifacts"]["result"] = RESULT_FILE_NAME
    result_path = context.run_dir / RESULT_FILE_NAME
    write_json(result_path, result)
    context.manifest["artifacts"]["result"]["sha256"] = sha256_file(result_path)
    write_json(context.manifest_path, context.manifest)
    return result_path


def finalize_run(args: argparse.Namespace) -> int:
    context = load_finalize_context(args)
    events = copy_finalize_events(context, args)
    first_byte_evidence, protocol_client_artifact_dir = copy_finalize_supporting_artifacts(
        context, args,
    )
    raw_records, source_payloads = collect_finalize_sources(context, args)
    records, deduplicated = normalize_finalize_records(
        context, raw_records, source_payloads, events, first_byte_evidence,
    )
    stage_rc = int(args.stage_rc)
    complete_finalize_records(
        context, records, deduplicated, events, stage_rc, args.stage_reason,
    )
    validate_protocol_client_records(
        records, context.case_by_id, protocol_client_artifact_dir,
    )
    deduplicated = write_finalize_case_results(context, records)
    copy_finalize_logs(context, args)
    capture_finalize_provenance(context)
    summary = build_finalize_summary(
        context,
        args,
        records,
        deduplicated,
        source_payloads,
        events,
        first_byte_evidence,
    )
    write_finalize_inventory(context, args, summary)
    result_path = write_finalize_result(
        context, build_finalize_result(context, args, summary, records),
    )
    errors = validate_run(
        context.run_dir, context.connector, context.capabilities, checks=FINALIZE_VALIDATION_CHECKS,
    )
    if errors:
        for error in errors:
            print(f"no-crs-finalize: {error}", file=sys.stderr)
        return 1
    print(result_path)
    return 1 if summary.status == "FAIL" else 0


def required_keys(payload: Mapping[str, Any], keys: Sequence[str], label: str) -> list[str]:
    return [f"{label}: missing {key}" for key in keys if key not in payload]


def _json_type_matches(value: object, expected: str) -> bool:
    return {
        "object": isinstance(value, Mapping),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, True)


def resolved_json_schema_reference(
    schema: Mapping[str, Any], root: Mapping[str, Any], location: str,
) -> tuple[Mapping[str, Any] | None, list[str]]:
    reference = schema.get("$ref")
    if not isinstance(reference, str):
        return schema, []
    if not reference.startswith("#/"):
        return None, [f"{location}: unsupported external schema reference {reference}"]
    target: object = root
    for component in reference[2:].split("/"):
        if not isinstance(target, Mapping) or component not in target:
            return None, [f"{location}: unresolved schema reference {reference}"]
        target = target[component]
    if not isinstance(target, Mapping):
        return None, [f"{location}: schema reference is not an object: {reference}"]
    return target, []


def json_schema_type_errors(value: object, schema: Mapping[str, Any], location: str) -> list[str]:
    expected_type = schema.get("type")
    expected_types = [expected_type] if isinstance(expected_type, str) else expected_type
    if isinstance(expected_types, list) and not any(
        _json_type_matches(value, str(item)) for item in expected_types
    ):
        return [f"{location}: expected type {expected_types}, got {type(value).__name__}"]
    return []


def json_schema_common_value_errors(
    value: object, schema: Mapping[str, Any], location: str,
) -> list[str]:
    errors: list[str] = []
    if "const" in schema and value != schema["const"]:
        errors.append(f"{location}: expected constant {schema['const']!r}, got {value!r}")
    if isinstance(schema.get("enum"), list) and value not in schema["enum"]:
        errors.append(f"{location}: value {value!r} is outside enum {schema['enum']!r}")
    return errors


def json_schema_string_errors(value: str, schema: Mapping[str, Any], location: str) -> list[str]:
    errors: list[str] = []
    if isinstance(schema.get("minLength"), int) and len(value) < schema["minLength"]:
        errors.append(f"{location}: string is shorter than minLength")
    if isinstance(schema.get("maxLength"), int) and len(value) > schema["maxLength"]:
        errors.append(f"{location}: string is longer than maxLength")
    if isinstance(schema.get("pattern"), str) and re.fullmatch(schema["pattern"], value) is None:
        errors.append(f"{location}: string does not match {schema['pattern']!r}")
    return errors


def json_schema_number_errors(
    value: int | float, schema: Mapping[str, Any], location: str,
) -> list[str]:
    errors: list[str] = []
    if isinstance(schema.get("minimum"), (int, float)) and value < schema["minimum"]:
        errors.append(f"{location}: value is below minimum")
    if isinstance(schema.get("maximum"), (int, float)) and value > schema["maximum"]:
        errors.append(f"{location}: value is above maximum")
    return errors


def json_schema_array_errors(
    value: list[object], schema: Mapping[str, Any], root: Mapping[str, Any], location: str,
) -> list[str]:
    errors: list[str] = []
    if isinstance(schema.get("minItems"), int) and len(value) < schema["minItems"]:
        errors.append(f"{location}: array is shorter than minItems")
    if schema.get("uniqueItems") is True:
        serialized = [json.dumps(item, sort_keys=True) for item in value]
        if len(serialized) != len(set(serialized)):
            errors.append(f"{location}: array items are not unique")
    item_schema = schema.get("items")
    if isinstance(item_schema, Mapping):
        for index, item in enumerate(value):
            errors.extend(json_schema_errors(
                item, item_schema, root_schema=root, location=f"{location}[{index}]",
            ))
    return errors


def json_schema_object_property_errors(
    value: Mapping[object, object],
    property_map: Mapping[object, object],
    pattern_map: Mapping[object, object],
    root: Mapping[str, Any],
    location: str,
) -> tuple[set[str], list[str]]:
    matched: set[str] = set()
    errors: list[str] = []
    for key, nested in value.items():
        key_text = str(key)
        property_schema = property_map.get(key_text)
        if isinstance(property_schema, Mapping):
            matched.add(key_text)
            errors.extend(json_schema_errors(
                nested, property_schema, root_schema=root, location=f"{location}.{key_text}",
            ))
        for pattern, nested_schema in pattern_map.items():
            if re.fullmatch(str(pattern), key_text) and isinstance(nested_schema, Mapping):
                matched.add(key_text)
                errors.extend(json_schema_errors(
                    nested, nested_schema, root_schema=root, location=f"{location}.{key_text}",
                ))
    return matched, errors


def json_schema_additional_property_errors(
    value: Mapping[object, object],
    matched: set[str],
    additional: object,
    root: Mapping[str, Any],
    location: str,
) -> list[str]:
    errors: list[str] = []
    for key, nested in value.items():
        key_text = str(key)
        if key_text in matched:
            continue
        if additional is False:
            errors.append(f"{location}: unexpected property {key_text}")
        elif isinstance(additional, Mapping):
            errors.extend(json_schema_errors(
                nested, additional, root_schema=root, location=f"{location}.{key_text}",
            ))
    return errors


def json_schema_object_errors(
    value: Mapping[object, object], schema: Mapping[str, Any], root: Mapping[str, Any], location: str,
) -> list[str]:
    errors: list[str] = []
    required = schema.get("required", [])
    if isinstance(required, list):
        for key in required:
            if key not in value:
                errors.append(f"{location}: missing required property {key}")
    properties = schema.get("properties", {})
    property_map = properties if isinstance(properties, Mapping) else {}
    pattern_properties = schema.get("patternProperties", {})
    pattern_map = pattern_properties if isinstance(pattern_properties, Mapping) else {}
    matched, property_errors = json_schema_object_property_errors(
        value, property_map, pattern_map, root, location,
    )
    errors.extend(property_errors)
    errors.extend(json_schema_additional_property_errors(
        value, matched, schema.get("additionalProperties", True), root, location,
    ))
    return errors


def json_schema_errors(
    value: object,
    schema: Mapping[str, Any],
    *,
    root_schema: Mapping[str, Any] | None = None,
    location: str = "$",
) -> list[str]:
    """Validate the JSON-Schema subset used by the checked-in contracts."""
    root = root_schema or schema
    resolved_schema, reference_errors = resolved_json_schema_reference(schema, root, location)
    if reference_errors:
        return reference_errors
    if resolved_schema is not schema:
        assert resolved_schema is not None
        return json_schema_errors(value, resolved_schema, root_schema=root, location=location)
    type_errors = json_schema_type_errors(value, schema, location)
    if type_errors:
        return type_errors
    errors = json_schema_common_value_errors(value, schema, location)
    if isinstance(value, str):
        errors.extend(json_schema_string_errors(value, schema, location))
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        errors.extend(json_schema_number_errors(value, schema, location))
    if isinstance(value, list):
        errors.extend(json_schema_array_errors(value, schema, root, location))
    if isinstance(value, Mapping):
        errors.extend(json_schema_object_errors(value, schema, root, location))
    return errors


def canonical_event_errors(
    event: object,
    location: str = "event",
    connector: str | None = None,
    integration_mode: str | None = None,
) -> list[str]:
    """Validate the deliberately small metadata-only canonical event contract.

    Host event logs are connector-local inputs.  They must be normalized by a
    host adapter before reaching this writer, so a canonical event never
    accepts arbitrary fields or nested values merely because they do not match
    a known sensitive-field blacklist.
    """
    schema = load_json(EVENT_SCHEMA_PATH)
    if not isinstance(schema, Mapping):
        return [f"{location}: checked-in event schema must contain an object"]
    errors = json_schema_errors(event, schema, root_schema=schema, location=location)
    errors.extend(forbidden_payload_errors(event, location))
    if not isinstance(event, Mapping):
        return errors
    errors.extend(canonical_event_protocol_errors(event, location))
    errors.extend(canonical_event_phase_errors(event, location))
    errors.extend(canonical_event_phase4_identity_errors(event, location))
    errors.extend(canonical_event_context_errors(
        event, location, connector, integration_mode,
    ))
    return errors


def normalized_event_protocol_values(
    event: Mapping[str, Any], location: str,
) -> tuple[dict[str, object], list[str]]:
    errors: list[str] = []
    protocol_values: dict[str, object] = {}
    for field in EVENT_PROTOCOL_NORMALIZATION_FIELDS:
        if field not in event:
            continue
        try:
            protocol_values[field] = normalize_semantic_value(field, event[field])
        except ContractError:
            errors.append(f"{location}.{field}: invalid transport provenance")
            continue
        if (
            field in TRANSPORT_CLAIM_FIELDS
            and not _empty_runtime_value(event[field])
            and protocol_values[field] is None
        ):
            errors.append(f"{location}.{field}: unsupported transport provenance")
    return protocol_values, errors


def canonical_event_transport_errors(
    protocol_values: Mapping[str, object], location: str,
) -> list[str]:
    errors: list[str] = []
    effective_downstream = (
        protocol_values.get("negotiated_protocol")
        or protocol_values.get("downstream_protocol")
    )
    transport = protocol_values.get("transport")
    if effective_downstream == "h3" or transport == "quic_udp":
        connection_id = protocol_values.get("connection_id")
        if connection_id is not None and not is_hashed_connection_id(connection_id):
            errors.append(f"{location}.connection_id: raw QUIC connection identifiers are forbidden")
    if (
        protocol_values.get("stream_reset") is True
        and effective_downstream not in {"h2", "h2c", "h3"}
    ):
        errors.append(f"{location}.stream_reset: requires h2, h2c, or h3 downstream protocol")
    return errors


def canonical_event_protocol_errors(event: Mapping[str, Any], location: str) -> list[str]:
    protocol_values, errors = normalized_event_protocol_values(event, location)
    errors.extend(canonical_event_transport_errors(protocol_values, location))
    return errors


def canonical_event_phase_errors(event: Mapping[str, Any], location: str) -> list[str]:
    if "phase" in event and normalize_canonical_phase(event.get("phase")) is None:
        return [f"{location}.phase: unsupported Common/canonical phase"]
    return []


def canonical_event_phase4_identity_errors(
    event: Mapping[str, Any], location: str,
) -> list[str]:
    if not phase_is_four(event.get("phase")):
        return []
    return [
        f"{location}.{field}: phase-4 events require a non-empty string"
        for field in ("event", "message_id")
        if not isinstance(event.get(field), str) or not event[field].strip()
    ]


def canonical_event_context_errors(
    event: Mapping[str, Any],
    location: str,
    connector: str | None,
    integration_mode: str | None,
) -> list[str]:
    errors: list[str] = []
    if connector and event.get("connector") != connector:
        errors.append(
            f"{location}.connector: {event.get('connector')!r} does not match {connector!r}"
        )
    if integration_mode and event.get("integration_mode") != integration_mode:
        errors.append(
            f"{location}.integration_mode: {event.get('integration_mode')!r} does not match selected {integration_mode!r}"
        )
    return errors


def canonical_case_protocol_errors(record: Mapping[str, Any], location: str) -> list[str]:
    """Reject privacy-invalid protocol data in canonical case results."""
    errors: list[str] = []
    try:
        negotiated = normalize_semantic_value("negotiated_protocol", record.get("negotiated_protocol"))
        downstream = normalize_semantic_value("downstream_protocol", record.get("downstream_protocol"))
        transport = normalize_semantic_value("transport", record.get("transport"))
    except ContractError:
        return [f"{location}: invalid protocol provenance"]
    if negotiated == "h3" or downstream == "h3" or transport == "quic_udp":
        connection_id = record.get("connection_id")
        if connection_id is not None and not is_hashed_connection_id(connection_id):
            errors.append(f"{location}.connection_id: raw QUIC connection identifiers are forbidden")
    return errors


def result_evidence_stage_errors(value: object, location: str = "result.json.evidence_stages") -> list[str]:
    """Validate the complete shared evidence-stage vocabulary in a result."""
    if not isinstance(value, Mapping):
        return [f"{location}: must be an object"]
    errors = result_evidence_stage_set_errors(value, location)
    for stage in EVIDENCE_STAGES:
        errors.extend(result_evidence_stage_entry_errors(value.get(stage), stage, location))
    return errors


def result_evidence_stage_set_errors(value: Mapping[str, Any], location: str) -> list[str]:
    errors: list[str] = []
    keys = {str(key) for key in value}
    missing = sorted(set(EVIDENCE_STAGES) - keys)
    unknown = sorted(keys - set(EVIDENCE_STAGES))
    if missing:
        errors.append(f"{location}: missing stages: {', '.join(missing)}")
    if unknown:
        errors.append(f"{location}: unknown stages: {', '.join(unknown)}")
    return errors


def result_evidence_stage_entry_errors(
    entry: object, stage: str, location: str,
) -> list[str]:
    if not isinstance(entry, Mapping):
        return [f"{location}.{stage}: must be an object"]
    errors: list[str] = []
    status = str(entry.get("status") or "")
    if status not in EVIDENCE_STAGE_STATUSES:
        errors.append(f"{location}.{stage}: invalid status {status!r}")
    if not str(entry.get("reason") or "").strip():
        errors.append(f"{location}.{stage}: missing non-empty reason")
    evidence = entry.get("evidence")
    if evidence is not None and (
        not isinstance(evidence, list)
        or any(not isinstance(item, str) or not item for item in evidence)
    ):
        errors.append(f"{location}.{stage}: evidence must be a list of non-empty strings")
    return errors


def load_schema_documents(run_dir: Path) -> dict[str, Mapping[str, Any]] | None:
    documents = {
        RESULT_FILE_NAME: load_json(run_dir / RESULT_FILE_NAME),
        MANIFEST_FILE_NAME: load_json(run_dir / MANIFEST_FILE_NAME),
        RUN_INVENTORY_FILE_PATH: load_json(run_dir / RUN_INVENTORY_FILE_PATH),
    }
    if not all(isinstance(document, Mapping) for document in documents.values()):
        return None
    return documents


def load_no_crs_schemas() -> dict[str, Mapping[str, Any]] | None:
    schema_root = FRAMEWORK_ROOT / NO_CRS_SCHEMA_DIRECTORY
    schemas = {
        RESULT_FILE_NAME: load_json(schema_root / "result.schema.json"),
        MANIFEST_FILE_NAME: load_json(schema_root / "manifest.schema.json"),
        RUN_INVENTORY_FILE_PATH: load_json(schema_root / "inventory.schema.json"),
        CASE_RESULTS_FILE_NAME: load_json(schema_root / "case-result.schema.json"),
        EVENTS_FILE_NAME: load_json(schema_root / "event.schema.json"),
    }
    if not all(isinstance(schema, Mapping) for schema in schemas.values()):
        return None
    return schemas


def schema_document_validation_errors(
    documents: Mapping[str, Mapping[str, Any]], schemas: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    errors: list[str] = []
    for name in (RESULT_FILE_NAME, MANIFEST_FILE_NAME, RUN_INVENTORY_FILE_PATH):
        errors.extend(
            f"{name} schema: {error}"
            for error in json_schema_errors(documents[name], schemas[name])
        )
    return errors


def schema_required_key_errors(documents: Mapping[str, Mapping[str, Any]]) -> list[str]:
    result = documents[RESULT_FILE_NAME]
    manifest = documents[MANIFEST_FILE_NAME]
    inventory = documents[RUN_INVENTORY_FILE_PATH]
    errors = required_keys(result, (
        "schema_version", "status_model", "connector", "connector_commit", "framework_commit", "host_name",
        "host_version", "integration_mode", "artifact_profile", "host_profile", "executed_targets", "libmodsecurity_version", "run_id",
        "connector_worktree_clean", "framework_worktree_clean", "provenance_required",
        "connector_commit_at_finalize", "framework_commit_at_finalize",
        "evidence_stage", "ruleset", "status", "exit_code", "blocked_before_execution", "started",
        "requests_sent", "source_statuses", "source_failure", "allowed_request_status", "blocked_request_status", "observed_rule_ids",
        "transaction_ids", "request_headers_verified", "request_body_verified",
        "response_headers_verified", "response_body_verified", "late_intervention_verified",
        "phase4_case_results",
        "event_metadata_verified", "body_payload_absent_from_events", "pass_gate_failures",
        "cases_total", "cases_passed", "cases_failed", "cases_blocked", "cases_unsupported",
        "cases_not_applicable", "cases_not_executed", "status_counts", "group_statuses",
        "capabilities_verified", "capabilities_unsupported",
        "capabilities_not_exercised", "capability_states", "artifacts", "claims_not_allowed",
        "evidence_stages", "production_ready", "security_verified", "crs_verified", "crs_complete",
        "full_matrix_ready", "started_at", "ended_at",
    ), RESULT_FILE_NAME)
    errors.extend(required_keys(manifest, (
        "schema_version", "connector", "run_id", "evidence_stage", "ruleset", "status",
        "started_at", "ended_at", "connector_commit", "framework_commit", "host_name",
        "host_version", "integration_mode", "artifact_profile", "host_profile", "libmodsecurity_version", "compiler_version",
        "operating_system", "architecture", "rules", "cases", "executed_targets", "artifacts",
        "capability_manifest", "connector_worktree_clean", "framework_worktree_clean",
        "provenance_required", "connector_commit_at_finalize", "framework_commit_at_finalize",
    ), MANIFEST_FILE_NAME))
    errors.extend(required_keys(inventory, (
        "schema_version", "connector", "run_id", "evidence_stage", "ruleset",
        "connector_commit", "framework_commit", "host_name", "host_version",
        "integration_mode", "artifact_profile", "host_profile", "libmodsecurity_version", "compiler_version",
        "operating_system", "architecture", "python_version", "rules_sha256",
        "catalog_sha256", "capability_manifest_sha256", "executed_targets", "created_at",
        "connector_worktree_clean", "framework_worktree_clean", "provenance_required",
        "connector_commit_at_finalize", "framework_commit_at_finalize",
    ), RUN_INVENTORY_FILE_PATH))
    return errors


def schema_result_consistency_errors(
    documents: Mapping[str, Mapping[str, Any]], connector: str,
) -> list[str]:
    result = documents[RESULT_FILE_NAME]
    manifest = documents[MANIFEST_FILE_NAME]
    inventory = documents[RUN_INVENTORY_FILE_PATH]
    errors: list[str] = []
    if result.get("schema_version") != 1 or manifest.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if result.get("status_model") != STATUS_MODEL:
        errors.append(f"status_model must be {STATUS_MODEL}")
    if result.get("connector") != connector or manifest.get("connector") != connector:
        errors.append("connector mismatch")
    if result.get("status") not in CASE_STATUSES or manifest.get("status") not in CASE_STATUSES:
        errors.append("status is outside the canonical status vocabulary")
    if result.get("evidence_stage") not in WRITABLE_EVIDENCE_STAGES:
        errors.append("result evidence_stage is not writable by the canonical runner")
    errors.extend(result_evidence_stage_errors(result.get("evidence_stages")))
    if not (
        result.get("evidence_stage")
        == manifest.get("evidence_stage")
        == inventory.get("evidence_stage")
    ):
        errors.append("manifest/result/inventory evidence_stage mismatch")
    if not (
        result.get("integration_mode")
        == manifest.get("integration_mode")
        == inventory.get("integration_mode")
    ):
        errors.append("manifest/result/inventory integration_mode mismatch")
    if any(payload.get("ruleset") != "no-crs-baseline" for payload in documents.values()):
        errors.append("ruleset must be no-crs-baseline")
    if not isinstance(result.get("observed_rule_ids"), list) or not isinstance(result.get("transaction_ids"), list):
        errors.append("observed_rule_ids and transaction_ids must be lists")
    errors.extend(result_boolean_field_errors(result))
    return errors


def result_boolean_field_errors(result: Mapping[str, Any]) -> list[str]:
    fields = (
        "started", "requests_sent", "request_headers_verified", "request_body_verified",
        "response_headers_verified", "response_body_verified", "late_intervention_verified",
        "event_metadata_verified", "body_payload_absent_from_events", "source_failure",
    )
    return [
        f"result.json: {field} must be Boolean"
        for field in fields
        if not isinstance(result.get(field), bool)
    ]


def case_result_schema_errors(
    records: Sequence[Mapping[str, Any]],
    schema: Mapping[str, Any],
    connector: str,
) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for index, record in enumerate(records):
        label = f"{CASE_RESULTS_FILE_NAME}[{index}]"
        errors.extend(
            f"{label} schema: {error}" for error in json_schema_errors(record, schema)
        )
        errors.extend(required_keys(record, (
            "schema_version", "connector", "run_id", "integration_mode", "case_id", "group", "phase", "status",
            "operation_status", "live_executed", "required_capabilities", "expected_result",
            "observed_result", "expected_status", "expected_rule_id",
            "actual_status", "observed_rule_ids", "transaction_ids", "expected_event_fields",
            "observed_event_fields", "event_metadata_verified", *PHASE4_SEMANTIC_FIELDS,
            "reason", "exit_code", "artifacts",
        ), label))
        errors.extend(case_result_identity_errors(record, label, connector, seen))
    return errors


def case_result_identity_errors(
    record: Mapping[str, Any], label: str, connector: str, seen: set[str],
) -> list[str]:
    errors = canonical_case_protocol_errors(record, label)
    if record.get("status") not in CASE_STATUSES:
        errors.append(f"{label}: invalid status")
    if record.get("connector") != connector:
        errors.append(f"{label}: connector mismatch")
    case_id = str(record.get("case_id") or "")
    if case_id in seen:
        errors.append(f"{label}: duplicate case_id {case_id}")
    seen.add(case_id)
    return errors


def event_schema_validation_errors(
    run_dir: Path, connector: str, integration_mode: str | None,
) -> list[str]:
    errors: list[str] = []
    for index, event in enumerate(read_jsonl(run_dir / EVENTS_FILE_NAME, required=False)):
        errors.extend(canonical_event_errors(
            event, f"{EVENTS_FILE_NAME}[{index}]", connector, integration_mode,
        ))
    return errors


def schema_errors(run_dir: Path, connector: str, capabilities: Mapping[str, Any]) -> list[str]:
    documents = load_schema_documents(run_dir)
    if documents is None:
        return ["result.json, manifest.json, and inventory/run.json must contain objects"]
    schemas = load_no_crs_schemas()
    if schemas is None:
        return ["checked-in JSON schemas must contain objects"]
    errors = schema_document_validation_errors(documents, schemas)
    errors.extend(schema_required_key_errors(documents))
    errors.extend(schema_result_consistency_errors(documents, connector))
    records = read_jsonl(run_dir / CASE_RESULTS_FILE_NAME)
    errors.extend(case_result_schema_errors(records, schemas[CASE_RESULTS_FILE_NAME], connector))
    errors.extend(event_schema_validation_errors(
        run_dir,
        connector,
        required_event_integration_mode(documents[MANIFEST_FILE_NAME]),
    ))
    errors.extend(validate_capability_manifest(capabilities, connector))
    return errors


def completeness_errors(run_dir: Path) -> list[str]:
    result = load_json(run_dir / RESULT_FILE_NAME)
    records = read_jsonl(run_dir / CASE_RESULTS_FILE_NAME)
    errors: list[str] = []
    if not isinstance(result, Mapping):
        return ["result.json must be an object"]
    connector = str(result.get("connector") or "")
    integration_mode = required_event_integration_mode(result)
    events = read_jsonl(run_dir / EVENTS_FILE_NAME, required=False)
    event_metadata_verified, body_payload_absent = canonical_core_event_contract(
        events, connector, integration_mode
    )
    if result.get("event_metadata_verified") is not event_metadata_verified:
        errors.append("event_metadata_verified is inconsistent with the canonical rule-1100001 event")
    errors.extend(result_pass_completeness_errors(
        result, records, event_metadata_verified, body_payload_absent,
    ))
    for record in records:
        errors.extend(pass_case_completeness_errors(
            record, events, connector, integration_mode,
        ))
    return errors


def result_pass_completeness_errors(
    result: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
    event_metadata_verified: bool,
    body_payload_absent: bool,
) -> list[str]:
    if result.get("status") != "PASS":
        return []
    errors: list[str] = []
    if result.get("started") is not True or result.get("requests_sent") is not True:
        errors.append("PASS requires started=true and requests_sent=true")
    if not concrete_version(result.get("host_version")):
        errors.append("PASS requires a concrete host_version")
    if not concrete_version(result.get("libmodsecurity_version")):
        errors.append("PASS requires a concrete libmodsecurity_version")
    if result.get("cases_passed", 0) < 1:
        errors.append("PASS requires at least one passed case")
    if any(result.get(key, 0) for key in ("cases_failed", "cases_blocked", "cases_not_executed")):
        errors.append("PASS cannot contain failed, blocked, or not-executed cases")
    if result.get("evidence_stage") == "minimal_runtime_smoke":
        errors.extend(minimal_runtime_completeness_errors(
            records, event_metadata_verified, body_payload_absent,
        ))
    return errors


def minimal_runtime_completeness_errors(
    records: Sequence[Mapping[str, Any]],
    event_metadata_verified: bool,
    body_payload_absent: bool,
) -> list[str]:
    errors: list[str] = []
    pass_ids = {
        str(record.get("case_id")) for record in records if record.get("status") == "PASS"
    }
    if not {"allow_without_marker", "deny_header_marker_403"}.issubset(pass_ids):
        errors.append("minimal runtime PASS requires both canonical core request cases")
    if not event_metadata_verified:
        errors.append("minimal runtime PASS requires all canonical event metadata fields")
    if not body_payload_absent:
        errors.append("minimal runtime PASS requires evidence of body-payload absence")
    return errors


def matching_case_event_for_validation(
    record: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    integration_mode: str | None,
) -> Mapping[str, Any] | None:
    return event_for_case(
        events,
        optional_int(record.get("expected_rule_id")),
        record,
        [str(value) for value in record.get("transaction_ids", [])],
        integration_mode,
    )


def pass_case_completeness_errors(
    record: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    connector: str,
    integration_mode: str | None,
) -> list[str]:
    if record.get("status") != "PASS":
        return []
    case_id = record.get("case_id")
    errors: list[str] = []
    if record.get("live_executed") is not True:
        errors.append(f"{case_id}: PASS requires live_executed=true")
    expected_status = record.get("expected_status")
    if (
        not is_phase4_semantic_case(record)
        and expected_status is not None
        and record.get("actual_status") != expected_status
    ):
        errors.append(f"{case_id}: PASS status mismatch")
    expected_rule = record.get("expected_rule_id")
    if expected_rule is not None and expected_rule not in record.get("observed_rule_ids", []):
        errors.append(f"{case_id}: PASS missing expected rule ID {expected_rule}")
    expected_fields = set(record.get("expected_event_fields", []))
    observed_fields = set(record.get("observed_event_fields", []))
    if expected_fields and not expected_fields.issubset(observed_fields):
        errors.append(f"{case_id}: PASS missing expected event fields")
    matching_event = matching_case_event_for_validation(record, events, integration_mode)
    if is_phase4_semantic_case(record):
        errors.extend(f"{case_id}: {error}" for error in phase4_pass_errors(record, matching_event))
    errors.extend(f"{case_id}: {error}" for error in canonical_event_errors(
        matching_event, connector=connector, integration_mode=integration_mode,
    ))
    errors.extend(f"{case_id}: {error}" for error in full_lifecycle_pass_errors(record, matching_event))
    return errors


def capability_errors(run_dir: Path, capabilities: Mapping[str, Any]) -> list[str]:
    result = load_json(run_dir / RESULT_FILE_NAME)
    records = read_jsonl(run_dir / CASE_RESULTS_FILE_NAME)
    declared = capabilities.get("capabilities", {})
    if not isinstance(result, Mapping) or not isinstance(declared, Mapping):
        return ["invalid result or capability manifest"]
    errors = capability_inventory_errors(run_dir, capabilities)
    errors.extend(pass_case_capability_errors(records, declared))
    errors.extend(verified_capability_boundary_errors(result, declared))
    errors.extend(capability_partition_errors(result))
    expected_states = {name: capability_state(declared.get(name)) for name in CAPABILITIES}
    if result.get("capability_states") != expected_states:
        errors.append("result capability_states differ from the canonical manifest")
    return errors


def capability_inventory_errors(run_dir: Path, capabilities: Mapping[str, Any]) -> list[str]:
    canonical_capabilities = load_json(run_dir / CAPABILITIES_INVENTORY_FILE_PATH)
    if not isinstance(canonical_capabilities, Mapping):
        return ["inventory/capabilities.json must contain an object"]
    if canonical_capabilities != capabilities:
        return ["current capability manifest differs from the run inventory copy"]
    return []


def pass_case_capability_errors(
    records: Sequence[Mapping[str, Any]], declared: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    for record in records:
        if record.get("status") != "PASS":
            continue
        for capability in record.get("required_capabilities", []):
            state = capability_state(declared.get(capability))
            if state not in EXECUTABLE_CAPABILITY_STATES:
                errors.append(f"{record.get('case_id')}: PASS conflicts with {capability}={state}")
    return errors


def verified_capability_boundary_errors(
    result: Mapping[str, Any], declared: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    boundary_fields = {
        "request_body_verified": (
            "request_body_buffered", "request_body_streaming", "request_body_incremental_ingest",
        ),
        "response_headers_verified": ("response_headers",),
        "response_body_verified": (
            "response_body_buffered", "response_body_streaming", "response_body_incremental_ingest",
        ),
        "late_intervention_verified": ("late_intervention",),
    }
    for field, names in boundary_fields.items():
        if result.get(field) is not True:
            continue
        states = {capability_state(declared.get(name)) for name in names}
        if not states.intersection(EXECUTABLE_CAPABILITY_STATES):
            errors.append(f"{field}=true conflicts with host-model capability states")
    return errors


def capability_partition_errors(result: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    verified = {str(item) for item in result.get("capabilities_verified", [])}
    unsupported = {str(item) for item in result.get("capabilities_unsupported", [])}
    not_exercised = {str(item) for item in result.get("capabilities_not_exercised", [])}
    if verified.intersection(unsupported):
        errors.append("capabilities_verified and capabilities_unsupported must be disjoint")
    if verified.intersection(not_exercised):
        errors.append("capabilities_verified and capabilities_not_exercised must be disjoint")
    if unsupported.intersection(not_exercised):
        errors.append("capabilities_unsupported and capabilities_not_exercised must be disjoint")
    if verified.union(unsupported, not_exercised) != set(CAPABILITIES):
        errors.append("capability result partitions must cover the canonical capability set exactly")
    return errors


def claim_policy_errors(run_dir: Path) -> list[str]:
    result = load_json(run_dir / RESULT_FILE_NAME)
    errors: list[str] = []
    if not isinstance(result, Mapping):
        return ["result.json must be an object"]
    for field in ("production_ready", "security_verified", "crs_verified", "crs_complete", "full_matrix_ready"):
        if result.get(field) is not False:
            errors.append(f"No-CRS result must set {field}=false")
    claims = result.get("claims_not_allowed")
    if not isinstance(claims, list) or not set(CLAIMS_NOT_ALLOWED).issubset({str(item) for item in claims}):
        errors.append("claims_not_allowed is incomplete")
    serialized = json.dumps(result).lower()
    if '"ruleset": "crs"' in serialized or '"crs_verified": true' in serialized:
        errors.append("No-CRS result contains a CRS claim")
    if result.get("status") == "PASS":
        artifact_text = json.dumps(result.get("artifacts", {})).lower()
        if "self-test" in artifact_text or "starter" in artifact_text:
            errors.append("self-test/starter artifact cannot support a host-runtime PASS")
    return errors


def base_layout_errors(run_dir: Path, symlinks: Sequence[Path]) -> list[str]:
    errors = [
        f"symlink is forbidden in canonical run: {symlink.relative_to(lexical_absolute(run_dir))}"
        for symlink in symlinks
    ]
    for directory in ("logs", "config", "inventory"):
        if not (run_dir / directory).is_dir():
            errors.append(f"artifact directory missing: {directory}/")
    for filename in (MANIFEST_FILE_NAME, RESULT_FILE_NAME, CASE_RESULTS_FILE_NAME, PLAN_FILE_NAME):
        if not (run_dir / filename).is_file():
            errors.append(f"required artifact missing: {filename}")
    return errors


def layout_artifact_profile(
    payload: Mapping[str, Any], label: str, errors: list[str],
) -> str:
    try:
        return canonical_artifact_profile(payload, label)
    except ContractError as exc:
        prefix = "" if label == MANIFEST_FILE_NAME else "plan: "
        errors.append(f"{prefix}{exc}")
        return DEFAULT_ARTIFACT_PROFILE


def manifest_artifact_entry_errors(
    run_dir: Path, name: str, entry: object,
) -> list[str]:
    if not isinstance(entry, Mapping):
        return [f"manifest artifact {name} must be an object"]
    errors: list[str] = []
    state = entry.get("state")
    if state not in {"produced", "not_produced", "not_applicable"}:
        return [f"manifest artifact {name} has invalid state"]
    relative_path = Path(str(entry.get("path") or ""))
    if relative_path.is_absolute() or ".." in relative_path.parts or relative_path in {Path(""), Path(".")}:
        return [f"manifest artifact {name} has unsafe path: {relative_path}"]
    path = run_dir / relative_path
    if path.is_symlink():
        return [f"manifest artifact {name} is a symlink: {relative_path}"]
    if state == "produced" and not path.is_file():
        errors.append(f"manifest produced artifact is missing: {name} -> {path}")
    if state != "produced" and path.exists():
        errors.append(f"manifest says {state} but artifact exists: {name} -> {path}")
    if state == "produced" and entry.get("sha256") and sha256_file(path) != entry["sha256"]:
        errors.append(f"artifact checksum mismatch: {name}")
    return errors


def manifest_artifact_layout_errors(
    run_dir: Path, artifacts: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    for name, entry in artifacts.items():
        errors.extend(manifest_artifact_entry_errors(run_dir, str(name), entry))
    return errors


def full_lifecycle_layout_errors(
    run_dir: Path,
    artifacts: Mapping[str, Any],
    artifact_profile: str,
    plan_artifact_profile: str,
) -> list[str]:
    if FULL_LIFECYCLE_ARTIFACT_PROFILE not in {artifact_profile, plan_artifact_profile}:
        return []
    errors: list[str] = []
    for name, expected_path in FULL_LIFECYCLE_REQUIRED_ARTIFACTS:
        entry = artifacts.get(name)
        if not isinstance(entry, Mapping):
            errors.append(f"full_lifecycle artifact is missing from manifest: {name}")
            continue
        if entry.get("path") != expected_path:
            errors.append(f"full_lifecycle artifact {name} must use {expected_path}")
        if entry.get("state") != "produced":
            errors.append(f"full_lifecycle artifact {name} must be produced")
            continue
        if not (run_dir / expected_path).is_file():
            errors.append(f"full_lifecycle artifact is missing: {expected_path}")
    return errors


def unmanifested_layout_errors(
    run_dir: Path,
    actual_file_paths: Sequence[Path],
    artifacts: Mapping[str, Any],
) -> list[str]:
    declared_paths = {
        str(Path(str(entry.get("path"))))
        for entry in artifacts.values()
        if isinstance(entry, Mapping) and entry.get("state") == "produced"
    }
    actual_paths = {
        str(path.relative_to(lexical_absolute(run_dir))) for path in actual_file_paths
    }
    return [
        f"unmanifested artifact in canonical run: {path}"
        for path in sorted(actual_paths - declared_paths)
    ]


def layout_errors(run_dir: Path) -> list[str]:
    actual_file_paths, symlinks = walk_files_no_symlinks(run_dir)
    errors = base_layout_errors(run_dir, symlinks)
    manifest = load_json(run_dir / MANIFEST_FILE_NAME)
    if not isinstance(manifest, Mapping) or not isinstance(manifest.get("artifacts"), Mapping):
        return errors + ["manifest artifacts must be an object"]
    plan = load_json(run_dir / PLAN_FILE_NAME)
    if not isinstance(plan, Mapping):
        return errors + ["plan.json must contain an object"]
    artifact_profile = layout_artifact_profile(manifest, MANIFEST_FILE_NAME, errors)
    plan_artifact_profile = layout_artifact_profile(plan, PLAN_FILE_NAME, errors)
    if plan_artifact_profile != artifact_profile:
        errors.append("plan and manifest artifact profiles differ")
    artifacts = manifest["artifacts"]
    errors.extend(manifest_artifact_layout_errors(run_dir, artifacts))
    errors.extend(full_lifecycle_layout_errors(
        run_dir, artifacts, artifact_profile, plan_artifact_profile,
    ))
    errors.extend(unmanifested_layout_errors(run_dir, actual_file_paths, artifacts))
    return errors


def body_payload_errors(run_dir: Path) -> list[str]:
    actual_files, symlinks = walk_files_no_symlinks(run_dir)
    errors = [
        f"symlink is forbidden in canonical run: {symlink.relative_to(lexical_absolute(run_dir))}"
        for symlink in symlinks
    ]
    events, json_errors = body_payload_json_artifact_errors(run_dir, actual_files)
    errors.extend(json_errors)
    errors.extend(body_payload_log_errors(run_dir, actual_files))
    errors.extend(body_payload_result_consistency_errors(run_dir, events))
    return errors


def body_payload_json_artifact_errors(
    run_dir: Path, actual_files: Sequence[Path],
) -> tuple[list[dict[str, Any]], list[str]]:
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    json_artifacts = {
        path for path in actual_files
        if path.suffix in {".json", ".jsonl"} and "config" not in path.relative_to(lexical_absolute(run_dir)).parts
    }
    for path in sorted(json_artifacts):
        if not path.is_file():
            continue
        artifact_events, artifact_errors = body_payload_artifact_errors(path)
        if artifact_events is not None:
            events = artifact_events
        errors.extend(artifact_errors)
    return events, errors


def body_payload_artifact_errors(
    path: Path,
) -> tuple[list[dict[str, Any]] | None, list[str]]:
    if path.suffix != ".jsonl":
        return None, forbidden_payload_errors(load_json(path), path.name)
    records = read_jsonl(path)
    if path.name != EVENTS_FILE_NAME:
        return None, [
            error
            for index, record in enumerate(records)
            for error in forbidden_payload_errors(record, f"{path.name}[{index}]")
        ]
    return records, [
        error
        for index, record in enumerate(records)
        for error in canonical_event_errors(record, f"{path.name}[{index}]")
    ]


def body_payload_log_errors(run_dir: Path, actual_files: Sequence[Path]) -> list[str]:
    errors: list[str] = []
    for path in [
        item for item in actual_files
        if item.parent == lexical_absolute(run_dir) / "logs" and item.suffix == ".log"
    ]:
        text = secure_read_text(path, errors="replace").lower()
        for sentinel in BODY_SENTINELS:
            if sentinel in text:
                errors.append(f"{path}: body payload sentinel is present")
        if re.search(r"(?im)^(authorization|cookie|set-cookie)\s*:", text):
            errors.append(f"{path}: sensitive HTTP header is present")
    return errors


def body_payload_result_consistency_errors(
    run_dir: Path, events: Sequence[Mapping[str, Any]],
) -> list[str]:
    errors: list[str] = []
    result = load_json(run_dir / RESULT_FILE_NAME)
    if isinstance(result, Mapping):
        expected_absence = bool(events) and not any(canonical_event_errors(event) for event in events)
        if result.get("body_payload_absent_from_events") is not expected_absence:
            errors.append("body_payload_absent_from_events is inconsistent with events.jsonl")
    return errors


def status_profile_errors(documents: Mapping[str, Mapping[str, Any]]) -> list[str]:
    errors: list[str] = []
    artifact_profiles = status_document_profiles(documents, canonical_artifact_profile, errors)
    if artifact_profiles and len(set(artifact_profiles.values())) != 1:
        errors.append("plan, result, manifest, and inventory artifact profiles differ")
    host_profiles = status_document_profiles(documents, canonical_host_profile, errors)
    if host_profiles and len(set(host_profiles.values())) != 1:
        errors.append("plan, result, manifest, and inventory host profiles differ")
    return errors


def status_document_profiles(
    documents: Mapping[str, Mapping[str, Any]],
    normalizer: Callable[[Mapping[str, Any], str], str],
    errors: list[str],
) -> dict[str, str]:
    profiles: dict[str, str] = {}
    for label, payload in documents.items():
        try:
            profiles[label] = normalizer(payload, f"{label}.json")
        except ContractError as exc:
            errors.append(f"{label}: {exc}")
    return profiles


def status_count_errors(result: Mapping[str, Any], records: Sequence[Mapping[str, Any]]) -> list[str]:
    counts = Counter(record.get("status") for record in records)
    expected_fields = {
        "cases_total": len(records), "cases_passed": counts["PASS"],
        "cases_failed": counts["FAIL"], "cases_blocked": counts["BLOCKED"],
        "cases_unsupported": counts["UNSUPPORTED"],
        "cases_not_applicable": counts["NOT_APPLICABLE"],
        "cases_not_executed": counts["NOT_EXECUTED"],
    }
    errors = [
        f"{field}={result.get(field)!r}, expected {expected}"
        for field, expected in expected_fields.items()
        if result.get(field) != expected
    ]
    expected_status_counts = {name: counts[name] for name in CASE_STATUSES}
    if result.get("status_counts") != expected_status_counts:
        errors.append(
            f"status_counts={result.get('status_counts')!r}, expected {expected_status_counts!r}"
        )
    return errors


def status_record_facts(
    records: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, object], set[str]]:
    records_by_id = {
        str(record.get("case_id") or ""): record
        for record in records
        if record.get("case_id")
    }
    pass_ids = {
        str(record.get("case_id"))
        for record in records
        if record.get("status") == "PASS"
    }
    verified_capabilities = sorted({
        str(capability)
        for record in records
        if record.get("status") == "PASS"
        for capability in record.get("required_capabilities", [])
    })
    return {
        "allowed_request_status": records_by_id.get("allow_without_marker", {}).get("actual_status"),
        "blocked_request_status": records_by_id.get("deny_header_marker_403", {}).get("actual_status"),
        "observed_rule_ids": sorted({
            rule_id for record in records for rule_id in record.get("observed_rule_ids", [])
        }),
        "transaction_ids": sorted({
            transaction_id
            for record in records
            for transaction_id in record.get("transaction_ids", [])
        }),
        "requests_sent": any(record.get("live_executed") is True for record in records),
        "request_headers_verified": {
            "allow_without_marker", "deny_header_marker_403",
        }.issubset(pass_ids),
        "request_body_verified": "deny_request_body_marker_403" in pass_ids,
        "response_headers_verified": "deny_response_header_marker_403" in pass_ids,
        "response_body_verified": "phase4_rule_observed" in pass_ids,
        "late_intervention_verified": bool(
            {
                "phase4_deny_after_commit_log_only",
                "phase4_deny_after_commit_abort",
            }.intersection(pass_ids)
            and "late_intervention" in verified_capabilities
        ),
        "phase4_case_results": [
            phase4_case_result_projection(record)
            for record in records
            if record.get("case_id") in PHASE4_CASE_IDS
        ],
        "capabilities_verified": verified_capabilities,
    }, pass_ids


def status_record_consistency_errors(
    result: Mapping[str, Any], records: Sequence[Mapping[str, Any]],
) -> tuple[list[str], set[str]]:
    expected_fields, pass_ids = status_record_facts(records)
    return [
        f"{field} is inconsistent with canonical case records"
        for field, expected in expected_fields.items()
        if result.get(field) != expected
    ], pass_ids


def status_group_errors(result: Mapping[str, Any], records: Sequence[Mapping[str, Any]]) -> list[str]:
    expected_group_statuses = finalize_group_statuses(records)
    if result.get("group_statuses") != expected_group_statuses:
        return ["group_statuses is inconsistent with canonical case records"]
    return []


def status_source_failure_errors(result: Mapping[str, Any]) -> list[str]:
    expected_source_failure = "FAIL" in {
        str(status).upper() for status in result.get("source_statuses", [])
    }
    if result.get("source_failure") is not expected_source_failure:
        return ["source_failure is inconsistent with source_statuses"]
    return []


def status_event_and_gate_errors(
    run_dir: Path,
    result: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
    pass_ids: set[str],
) -> list[str]:
    expected_status, expected_blocked = aggregate_status(
        records,
        int(result.get("exit_code") or 0),
        source_failure=result.get("source_failure") is True,
    )
    events = read_jsonl(run_dir / EVENTS_FILE_NAME, required=False)
    event_metadata_verified, body_payload_absent = canonical_core_event_contract(
        events,
        str(result.get("connector") or ""),
        required_event_integration_mode(result),
    )
    errors: list[str] = []
    if result.get("event_metadata_verified") is not event_metadata_verified:
        errors.append("event_metadata_verified is inconsistent with the canonical rule-1100001 event")
    if result.get("body_payload_absent_from_events") is not body_payload_absent:
        errors.append("body_payload_absent_from_events is inconsistent with canonical events")
    expected_status, gate_errors = status_pass_gate(
        result, expected_status, pass_ids, event_metadata_verified, body_payload_absent,
    )
    if result.get("status") != expected_status:
        errors.append(f"aggregate status mismatch: {result.get('status')!r} != {expected_status!r}")
    if result.get("pass_gate_failures") != gate_errors:
        errors.append("pass_gate_failures is inconsistent with canonical PASS gates")
    if result.get("blocked_before_execution") is not expected_blocked:
        errors.append("blocked_before_execution is inconsistent with case evidence and exit code")
    return errors


def status_pass_gate(
    result: Mapping[str, Any],
    expected_status: str,
    pass_ids: set[str],
    event_metadata_verified: bool,
    body_payload_absent: bool,
) -> tuple[str, list[str]]:
    if expected_status != "PASS":
        return expected_status, []
    errors = canonical_pass_gate_failures(
        str(result.get("evidence_stage") or ""),
        pass_ids,
        event_metadata_verified,
        body_payload_absent,
        result.get("host_version"),
        result.get("libmodsecurity_version"),
    )
    if result.get("connector_worktree_clean") is not True:
        errors.append("PASS requires a clean connector worktree")
    if result.get("framework_worktree_clean") is not True:
        errors.append("PASS requires a clean framework worktree")
    errors.extend(provenance_pass_gate_failures(result))
    return ("FAIL" if errors else expected_status), errors


def status_document_identity_errors(
    result: Mapping[str, Any],
    manifest: Mapping[str, Any],
    inventory: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    for field in (
        "connector", "run_id", "connector_commit", "framework_commit", "host_name",
        "host_version", "integration_mode", "artifact_profile", "host_profile", "executed_targets", "libmodsecurity_version", "evidence_stage", "ruleset",
        "connector_worktree_clean", "framework_worktree_clean", "provenance_required",
        "connector_commit_at_finalize", "framework_commit_at_finalize",
    ):
        if result.get(field) != manifest.get(field):
            errors.append(f"manifest/result {field} mismatch")
        if result.get(field) != inventory.get(field):
            errors.append(f"result/inventory {field} mismatch")
    for field in ("compiler_version", "operating_system", "architecture"):
        if manifest.get(field) != inventory.get(field):
            errors.append(f"manifest/inventory {field} mismatch")
    return errors


def status_exit_state_errors(result: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    exit_code = result.get("exit_code")
    if exit_code == 77 and not (
        result.get("status") == "BLOCKED" and result.get("blocked_before_execution") is True
        and result.get("started") is False and result.get("requests_sent") is False
    ):
        errors.append("exit 77 is allowed only for BLOCKED before execution")
    if result.get("status") == "BLOCKED" and result.get("blocked_before_execution") is not True:
        errors.append("BLOCKED result must be explicitly blocked_before_execution")
    return errors


def status_errors(run_dir: Path) -> list[str]:
    result = load_json(run_dir / RESULT_FILE_NAME)
    manifest = load_json(run_dir / MANIFEST_FILE_NAME)
    inventory = load_json(run_dir / RUN_INVENTORY_FILE_PATH)
    plan = load_json(run_dir / PLAN_FILE_NAME)
    records = read_jsonl(run_dir / CASE_RESULTS_FILE_NAME)
    if not all(isinstance(payload, Mapping) for payload in (result, manifest, inventory, plan)):
        return ["result, manifest, inventory, and plan must be objects"]
    documents = {
        "result": result,
        "manifest": manifest,
        "inventory": inventory,
        "plan": plan,
    }
    errors = status_profile_errors(documents)
    errors.extend(status_count_errors(result, records))
    record_errors, pass_ids = status_record_consistency_errors(result, records)
    errors.extend(record_errors)
    errors.extend(status_group_errors(result, records))
    errors.extend(status_source_failure_errors(result))
    if result.get("status") != manifest.get("status"):
        errors.append("manifest/result status mismatch")
    errors.extend(status_event_and_gate_errors(run_dir, result, records, pass_ids))
    errors.extend(status_document_identity_errors(result, manifest, inventory))
    errors.extend(status_exit_state_errors(result))
    return errors


def modern_protocol_pass_records(
    records: Sequence[Mapping[str, Any]], case_by_id: Mapping[str, Mapping[str, Any]],
) -> tuple[list[str], list[tuple[Mapping[str, Any], str]]]:
    errors: list[str] = []
    modern_records: list[tuple[Mapping[str, Any], str]] = []
    for record in records:
        if record.get("status") != "PASS":
            continue
        case = case_by_id.get(str(record.get("case_id") or ""))
        try:
            protocol = record_protocol_profile(record, case)
        except ContractError as exc:
            errors.append(f"{record.get('case_id')}: {exc}")
            continue
        if protocol in {"h2", "h2c", "h3"}:
            modern_records.append((record, protocol))
    return errors, modern_records


def multiple_modern_protocol_errors(
    modern_records: Sequence[tuple[Mapping[str, Any], str]],
) -> list[str]:
    if len(modern_records) <= 1:
        return []
    case_ids = ", ".join(str(record.get("case_id") or "") for record, _ in modern_records)
    return [
        "managed protocol client represents one request; modern protocol PASSes "
        f"must be finalized in separate canonical runs: {case_ids}"
    ]


def protocol_client_manifest_artifacts(
    run_dir: Path,
) -> tuple[Mapping[str, Any] | None, str | None]:
    manifest = load_json(run_dir / MANIFEST_FILE_NAME)
    if not isinstance(manifest, Mapping):
        return None, "manifest.json must be an object"
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping):
        return None, "manifest.json artifacts must be an object"
    return artifacts, None


def protocol_client_manifest_errors(run_dir: Path, artifacts: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    for name in PROTOCOL_CLIENT_REQUIRED_ARTIFACT_NAMES:
        expected_path = PROTOCOL_CLIENT_ARTIFACT_PATHS[name]
        entry = artifacts.get(name)
        path = run_dir / expected_path
        if not isinstance(entry, Mapping):
            errors.append(f"protocol client artifact is missing from manifest: {name}")
            continue
        if entry.get("path") != expected_path or entry.get("state") != "produced":
            errors.append(f"protocol client artifact has invalid manifest entry: {name}")
            continue
        if not path.is_file() or path.is_symlink():
            errors.append(f"protocol client artifact is missing or unsafe: {name}")
            continue
        if entry.get("sha256") != sha256_file(path):
            errors.append(f"protocol client artifact checksum mismatch: {name}")
    return errors


def protocol_client_case_errors(
    artifact_dir: Path, modern_records: Sequence[tuple[Mapping[str, Any], str]],
) -> list[str]:
    errors: list[str] = []
    for record, protocol in modern_records:
        case_id = str(record.get("case_id") or "")
        if str(record.get("expected_result") or "") in DEDICATED_STREAM_CONTROL_RESULTS:
            errors.append(
                f"{case_id}: reset/cancel or multiplexing PASS requires a dedicated "
                "stream-control client"
            )
            continue
        record_artifacts = record.get("artifacts")
        if not isinstance(record_artifacts, Mapping) or (
            record_artifacts.get("protocol_client_dir") != PROTOCOL_CLIENT_ARTIFACT_DIR
        ):
            errors.append(f"{case_id}: protocol client bundle is not declared by the case result")
        errors.extend(
            f"{case_id}: {error}"
            for error in protocol_client_artifact_errors(artifact_dir, record, protocol)
        )
    return errors


def protocol_client_errors(run_dir: Path) -> list[str]:
    """Re-evaluate run-local client evidence for every modern protocol PASS."""
    records = read_jsonl(run_dir / CASE_RESULTS_FILE_NAME)
    catalog = load_catalog()
    case_by_id = {case["case_id"]: case for case in catalog_cases(catalog)}
    errors, modern_records = modern_protocol_pass_records(records, case_by_id)
    if not modern_records:
        return errors
    errors.extend(multiple_modern_protocol_errors(modern_records))
    artifacts, manifest_error = protocol_client_manifest_artifacts(run_dir)
    if manifest_error:
        return [*errors, manifest_error]
    if artifacts is None:
        return errors
    errors.extend(protocol_client_manifest_errors(run_dir, artifacts))
    errors.extend(protocol_client_case_errors(run_dir / PROTOCOL_CLIENT_ARTIFACT_DIR, modern_records))
    return errors


VALID_CHECKS = {
    "schema": schema_errors,
    "completeness": completeness_errors,
    "capability": capability_errors,
    "claim-policy": claim_policy_errors,
    "layout": layout_errors,
    "body-payload": body_payload_errors,
    "protocol-client": protocol_client_errors,
    "status": status_errors,
}


def validate_run(
    run_dir: Path,
    connector: str,
    capabilities: Mapping[str, Any],
    checks: Sequence[str],
) -> list[str]:
    errors: list[str] = []
    for check in checks:
        function = VALID_CHECKS[check]
        if check in {"schema", "capability"}:
            check_errors = function(run_dir, connector, capabilities) if check == "schema" else function(run_dir, capabilities)
        else:
            check_errors = function(run_dir)
        errors.extend(f"{check}: {error}" for error in check_errors)
    return errors


def validation_capabilities_path(
    connector_root: Path,
    connector: str,
    run_dir: Path,
    explicit_capabilities: str | None,
) -> Path:
    """Return the capability contract that was effective for a validation.

    A full-lifecycle connector route is deliberately allowed to materialize a
    more conservative, profile-specific capability manifest before it writes
    canonical evidence.  Its inventory copy is therefore the exact contract
    used to select and finalize the run; comparing it to the generic connector
    manifest would reject valid non-promoted native-host evidence.  Provenance
    checks still bind the run to the current connector commit when validation
    is invoked with ``--check all``.
    """
    if explicit_capabilities:
        return Path(explicit_capabilities)
    manifest = load_json(run_dir / MANIFEST_FILE_NAME)
    if (
        isinstance(manifest, Mapping)
        and manifest.get("artifact_profile") == FULL_LIFECYCLE_ARTIFACT_PROFILE
    ):
        return run_dir / CAPABILITIES_INVENTORY_FILE_PATH
    return connector_root / f"connectors/{connector}/capabilities.json"


def validation_run_dir_for_connector(
    evidence_root: Path,
    connector: str,
    run_id: str | None,
    fallback_to_connector_root: bool,
) -> list[tuple[str, Path]]:
    candidate = evidence_root / connector / run_id if run_id else evidence_root / connector
    if run_id and (candidate / RESULT_FILE_NAME).is_file():
        return [(connector, candidate)]
    search_root = evidence_root / connector if fallback_to_connector_root else candidate
    matches = sorted(search_root.glob(RESULT_GLOB_PATTERN)) if search_root.is_dir() else []
    if len(matches) == 1:
        return [(connector, matches[0].parent)]
    if len(matches) > 1:
        raise ContractError(f"multiple results for {connector}; pass --run-id")
    return []


def validation_run_dirs(
    evidence_root: Path, connector: str | None, run_id: str | None,
) -> list[tuple[str, Path]]:
    if (evidence_root / RESULT_FILE_NAME).is_file():
        result = load_json(evidence_root / RESULT_FILE_NAME)
        connector = connector or (str(result.get("connector") or "") if isinstance(result, Mapping) else "")
        return [(connector, evidence_root)]
    if connector:
        return validation_run_dir_for_connector(
            evidence_root, connector, run_id, fallback_to_connector_root=False,
        )
    return [
        run_dir
        for connector_name in CONNECTORS
        for run_dir in validation_run_dir_for_connector(
            evidence_root, connector_name, run_id, fallback_to_connector_root=True,
        )
    ]


def missing_validation_connector_errors(
    run_dirs: Sequence[tuple[str, Path]], connector: str | None,
) -> list[str]:
    expected_connectors = {connector} if connector else set(CONNECTORS)
    found_connectors = {connector for connector, _ in run_dirs}
    return [
        f"{missing_connector}: canonical result.json missing"
        for missing_connector in sorted(expected_connectors - found_connectors)
    ]


def validation_provenance_errors(
    connector: str,
    run_dir: Path,
    connector_root: Path,
    current_connector_commit: str,
    current_framework_commit: str,
) -> list[str]:
    result = load_json(run_dir / RESULT_FILE_NAME)
    if not isinstance(result, Mapping):
        return [f"{connector}: provenance: result.json must be an object"]
    errors: list[str] = []
    if current_connector_commit == "unknown":
        errors.append(f"{connector}: provenance: current connector commit cannot be resolved")
    elif result.get("connector_commit") != current_connector_commit:
        errors.append(
            f"{connector}: provenance: evidence connector_commit {result.get('connector_commit')!r} "
            f"does not match current {current_connector_commit!r}"
        )
    if current_framework_commit == "unknown":
        errors.append(f"{connector}: provenance: current framework commit cannot be resolved")
    elif result.get("framework_commit") != current_framework_commit:
        errors.append(
            f"{connector}: provenance: evidence framework_commit {result.get('framework_commit')!r} "
            f"does not match current {current_framework_commit!r}"
        )
    if not git_worktree_clean(connector_root):
        errors.append(f"{connector}: provenance: current connector worktree is dirty")
    if not git_worktree_clean(FRAMEWORK_ROOT):
        errors.append(f"{connector}: provenance: current framework worktree is dirty")
    return errors


def validation_run_errors(
    connector: str,
    run_dir: Path,
    connector_root: Path,
    explicit_capabilities: str | None,
    checks: Sequence[str],
    check_current_provenance: bool,
    current_connector_commit: str,
    current_framework_commit: str,
) -> list[str]:
    capabilities_path = validation_capabilities_path(
        connector_root, connector, run_dir, explicit_capabilities,
    )
    capabilities = load_capability_manifest(capabilities_path, connector)
    errors = [
        f"{connector}: {error}"
        for error in validate_run(run_dir, connector, capabilities, checks)
    ]
    if check_current_provenance:
        errors.extend(validation_provenance_errors(
            connector, run_dir, connector_root,
            current_connector_commit, current_framework_commit,
        ))
    return errors


def validate_command(args: argparse.Namespace) -> int:
    checks = tuple(VALID_CHECKS) if args.check == "all" else (args.check,)
    evidence_root = Path(args.evidence_root)
    run_dirs = validation_run_dirs(evidence_root, args.connector, args.run_id)
    errors = missing_validation_connector_errors(run_dirs, args.connector)
    connector_root = Path(args.connector_root or ".")
    current_connector_commit = git_value(connector_root, "rev-parse", "HEAD")
    current_framework_commit = git_value(FRAMEWORK_ROOT, "rev-parse", "HEAD")
    check_current_provenance = args.check in {"all", "completeness", "status"}
    for connector, run_dir in run_dirs:
        errors.extend(validation_run_errors(
            connector, run_dir, connector_root, args.capabilities, checks,
            check_current_provenance, current_connector_commit, current_framework_commit,
        ))
    if errors:
        for error in errors:
            print(f"no-crs-evidence: {error}", file=sys.stderr)
        return 1
    print(f"no-crs-evidence: {args.check}: PASS ({len(run_dirs)} run(s) under {evidence_root})")
    return 0


def stage_report_status(value: object) -> str:
    if isinstance(value, Mapping):
        value = value.get("status") or value.get("state")
    normalized = str(value or "").strip().lower().replace("-", "_")
    if normalized in {"pass", "verified", "supported_and_verified", "ok"}:
        return "PASS"
    if normalized in {"fail", "failed", "error"}:
        return "FAIL"
    if normalized in {"blocked", "blocked_before_execution"}:
        return "BLOCKED"
    if normalized in {"unsupported", "unsupported_by_host_model", "not_applicable"}:
        return "UNSUPPORTED"
    if normalized == "not_implemented":
        return REPORT_STATUS_NOT_IMPLEMENTED
    if normalized in {"implemented_not_asserted", "supported_not_verified"}:
        return REPORT_STATUS_IMPLEMENTED_NOT_ASSERTED
    return REPORT_STATUS_NOT_EXECUTED


def result_cell(result: Mapping[str, Any] | None, field: str) -> str:
    if result is None:
        return REPORT_STATUS_NOT_EXECUTED
    if field == "no_crs_baseline" and result.get("evidence_stage") == "no_crs_baseline":
        return report_status(str(result.get("status") or "NOT_EXECUTED"))
    stages = result.get("evidence_stages", {})
    if isinstance(stages, Mapping) and field in stages:
        return stage_report_status(stages[field])
    return REPORT_STATUS_NOT_EXECUTED


def combined_stage_cell(result: Mapping[str, Any] | None, *fields: str) -> str:
    values = [result_cell(result, field) for field in fields]
    priority = (
        "FAIL", "BLOCKED", REPORT_STATUS_NOT_EXECUTED, "UNSUPPORTED", REPORT_STATUS_NOT_IMPLEMENTED,
        REPORT_STATUS_IMPLEMENTED_NOT_ASSERTED, "PASS",
    )
    return next((status for status in priority if status in values), REPORT_STATUS_NOT_EXECUTED)


def capability_cell(result: Mapping[str, Any] | None, capability: str) -> str:
    if result is None:
        return REPORT_STATUS_NOT_EXECUTED
    if capability in result.get("capabilities_verified", []):
        return "PASS"
    states = result.get("capability_states", {})
    state = str(states.get(capability) or "") if isinstance(states, Mapping) else ""
    if state == "not_implemented":
        return REPORT_STATUS_NOT_IMPLEMENTED
    if state in {"unsupported_by_host_model", "not_applicable"}:
        return "UNSUPPORTED"
    if state == "implemented_not_asserted":
        return REPORT_STATUS_IMPLEMENTED_NOT_ASSERTED
    return REPORT_STATUS_NOT_EXECUTED


def report_status(status: str) -> str:
    if status == "NOT_EXECUTED":
        return REPORT_STATUS_NOT_EXECUTED
    if status == "NOT_APPLICABLE":
        return "UNSUPPORTED"
    return status if status in REPORT_STATUSES else REPORT_STATUS_NOT_EXECUTED


def aggregate_report_status(statuses: Sequence[str]) -> str:
    for status in (
        "FAIL", "BLOCKED", REPORT_STATUS_NOT_EXECUTED, "UNSUPPORTED",
        REPORT_STATUS_NOT_IMPLEMENTED, REPORT_STATUS_IMPLEMENTED_NOT_ASSERTED,
    ):
        if status in statuses:
            return status
    return "PASS" if statuses and all(status == "PASS" for status in statuses) else REPORT_STATUS_NOT_EXECUTED


def group_cell(result: Mapping[str, Any] | None, group: str) -> str:
    if result is None or not isinstance(result.get("group_statuses"), Mapping):
        return REPORT_STATUS_NOT_EXECUTED
    return report_status(str(result["group_statuses"].get(group) or "NOT_EXECUTED"))


def find_result(evidence_root: Path, connector: str, run_id: str) -> Mapping[str, Any] | None:
    if run_id:
        path = evidence_root / connector / run_id / RESULT_FILE_NAME
        if not path.is_file():
            return None
        payload = load_json(path)
        if not isinstance(payload, Mapping):
            raise ContractError(f"{path}: result.json must contain an object")
        return payload
    paths = sorted((evidence_root / connector).glob(RESULT_GLOB_PATTERN))
    if not paths:
        return None
    if len(paths) > 1:
        raise ContractError(f"multiple results for {connector}; pass --run-id")
    payload = load_json(paths[0])
    if not isinstance(payload, Mapping):
        raise ContractError(f"{paths[0]}: result.json must contain an object")
    return payload


def result_only_summary_errors(result: Mapping[str, Any], connector: str) -> list[str]:
    """Reject malformed or claim-bearing inputs before result-only aggregation.

    The aggregate intentionally consumes only the canonical result files, not
    host artifacts.  It still validates the result contract so a partial or
    forged object cannot become a rendered PASS simply because it contains a
    status field.
    """
    schema = load_json(FRAMEWORK_ROOT / NO_CRS_SCHEMA_DIRECTORY / "result.schema.json")
    if not isinstance(schema, Mapping):
        return ["checked-in result schema must contain an object"]
    errors = json_schema_errors(result, schema, root_schema=schema, location=RESULT_FILE_NAME)
    try:
        canonical_artifact_profile(result, RESULT_FILE_NAME)
    except ContractError as exc:
        errors.append(str(exc))
    try:
        canonical_host_profile(result, RESULT_FILE_NAME)
    except ContractError as exc:
        errors.append(str(exc))
    if result.get("connector") != connector:
        errors.append(f"result.json connector {result.get('connector')!r} does not match {connector!r}")
    for field in (
        "production_ready", "security_verified", "crs_verified", "crs_complete", "full_matrix_ready",
    ):
        if result.get(field) is not False:
            errors.append(f"result.json must set {field}=false")
    claims = result.get("claims_not_allowed")
    if not isinstance(claims, list) or not set(CLAIMS_NOT_ALLOWED).issubset({str(item) for item in claims}):
        errors.append("result.json claims_not_allowed is incomplete")
    return errors


def render_summary(results: Mapping[str, Mapping[str, Any] | None], *, german: bool = False) -> str:
    title = "Alle Connectoren: No-CRS-Baseline" if german else "All connectors: No-CRS baseline"
    note = (
        "Fehlende Ergebnisse werden als NOT EXECUTED ausgewiesen; UNSUPPORTED wird nie als PASS gezählt."
        if german else
        "Missing results are reported as NOT EXECUTED; UNSUPPORTED is never counted as PASS."
    )
    overall_status = aggregate_report_status([
        report_status(str(result.get("status") or "NOT_EXECUTED")) if result else REPORT_STATUS_NOT_EXECUTED
        for result in results.values()
    ])
    language = (
        "**Sprache:** [English](all-connectors-no-crs-baseline.md) | Deutsch"
        if german else
        "**Language:** English | [Deutsch](all-connectors-no-crs-baseline.de.md)"
    )
    status_marker = (
        f"Kanonischer Gesamtstatus: `{overall_status}`"
        if german else
        f"Overall canonical status: `{overall_status}`"
    )
    lines = [f"# {title}", "", language, "", status_marker, "", note, "", "| Connector | Build | Config | Start | Minimal runtime | No-CRS baseline | P1 | P2 | P3 | P4 | Events | Lifecycle | Status |", "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for connector in CONNECTORS:
        result = results.get(connector)
        status = report_status(str(result.get("status") or "NOT_EXECUTED")) if result else REPORT_STATUS_NOT_EXECUTED
        lines.append(
            "| " + " | ".join((
                connector,
                combined_stage_cell(result, "compile", "link"),
                result_cell(result, "config_load"),
                result_cell(result, "start_smoke"),
                result_cell(result, "minimal_runtime_smoke"),
                result_cell(result, "no_crs_baseline"),
                capability_cell(result, "phase1"),
                capability_cell(result, "phase2"),
                capability_cell(result, "phase3"),
                capability_cell(result, "phase4"),
                group_cell(result, "events"),
                group_cell(result, "lifecycle"),
                status,
            )) + " |"
        )
    lines.extend(["", "This report is result-derived and makes no CRS, production, security, full-matrix, or universal response-body claim." if not german else "Dieser Bericht wird aus Ergebnissen abgeleitet und behauptet keine CRS-, Produktions-, Sicherheits-, Full-Matrix- oder allgemeine Response-Body-Verifikation.", ""])
    return "\n".join(lines)


def render_connector_report(connector: str, result: Mapping[str, Any] | None, *, german: bool = False) -> str:
    title = f"{connector}: No-CRS-Baseline"
    if result is None:
        status = REPORT_STATUS_NOT_EXECUTED
        counts = dict.fromkeys(CASE_STATUSES, 0)
        gaps = "Kein kanonisches result.json vorhanden." if german else "No canonical result.json is available."
    else:
        status = report_status(str(result.get("status") or "NOT_EXECUTED"))
        counts = result.get("status_counts", {}) if isinstance(result.get("status_counts"), Mapping) else {}
        gaps = ", ".join(str(item) for item in result.get("capabilities_not_exercised", [])) or "-"
    labels = {
        "Status": "Status", "Cases": "Fälle" if german else "Cases",
        "Remaining gaps": "Verbleibende Lücken" if german else "Remaining gaps",
    }
    language = (
        f"**Sprache:** [English]({connector}-no-crs-baseline.md) | Deutsch"
        if german else
        f"**Language:** English | [Deutsch]({connector}-no-crs-baseline.de.md)"
    )
    status_marker = f"Kanonischer Gesamtstatus: `{status}`" if german else f"Overall canonical status: `{status}`"
    dimension = "Dimension"
    lines = [
        f"# {title}", "", language, "", status_marker, "",
        f"- {labels['Cases']}: " + ", ".join(f"{name}={counts.get(name, 0)}" for name in CASE_STATUSES),
        f"- {labels['Remaining gaps']}: {gaps}", "",
        f"| {dimension} | Status |", "|---|---|",
        f"| Phase 1 | {capability_cell(result, 'phase1')} |",
        f"| Phase 2 | {capability_cell(result, 'phase2')} |",
        f"| Phase 3 | {capability_cell(result, 'phase3')} |",
        f"| Phase 4 | {capability_cell(result, 'phase4')} |",
        f"| Events | {group_cell(result, 'events')} |",
        "",
        "UNSUPPORTED and NOT EXECUTED are not PASS evidence." if not german else "UNSUPPORTED und NOT EXECUTED sind keine PASS-Evidence.",
        "",
    ]
    return "\n".join(lines)


def summarize_command(args: argparse.Namespace) -> int:
    evidence_root = Path(args.evidence_root)
    results = {connector: find_result(evidence_root, connector, args.run_id or "") for connector in CONNECTORS}
    errors = [
        f"{connector}: {error}"
        for connector, result in results.items() if result is not None
        for error in result_only_summary_errors(result, connector)
    ]
    if errors:
        raise ContractError("refusing to summarize invalid canonical result(s): " + "; ".join(errors))
    rendered_statuses = [
        report_status(str(result.get("status") or "NOT_EXECUTED")) if result else REPORT_STATUS_NOT_EXECUTED
        for result in results.values()
    ]
    payload = {
        "schema_version": 1,
        "run_id": args.run_id or None,
        "generated_at": utc_now(),
        "connectors": {
            connector: (result if result is not None else {
                "connector": connector, "status": "NOT_EXECUTED", "reason": "result.json missing"
            })
            for connector, result in results.items()
        },
        "status_counts": dict(Counter(
            str(result.get("status") or "NOT_EXECUTED") if result else "NOT_EXECUTED"
            for result in results.values()
        )),
        "overall_status": aggregate_report_status(rendered_statuses),
        "claims_not_allowed": list(CLAIMS_NOT_ALLOWED),
    }
    write_json(args.output_json, payload)
    atomic_write_text(args.output_md, render_summary(results))
    atomic_write_text(args.output_md_de, render_summary(results, german=True))
    if args.reports_dir:
        reports_dir = Path(args.reports_dir)
        atomic_write_text(reports_dir / "all-connectors-no-crs-baseline.md", render_summary(results))
        atomic_write_text(reports_dir / "all-connectors-no-crs-baseline.de.md", render_summary(results, german=True))
        for connector, result in results.items():
            atomic_write_text(reports_dir / f"{connector}-no-crs-baseline.md", render_connector_report(connector, result))
            atomic_write_text(reports_dir / f"{connector}-no-crs-baseline.de.md", render_connector_report(connector, result, german=True))
    print(args.output_json)
    return 0


def catalog_check_command(_args: argparse.Namespace) -> int:
    catalog = load_json(CATALOG_PATH)
    if not isinstance(catalog, Mapping):
        print("catalog root must be an object", file=sys.stderr)
        return 1
    errors = validate_catalog(catalog)
    catalog_schema = load_json(FRAMEWORK_ROOT / NO_CRS_SCHEMA_DIRECTORY / "case-catalog.schema.json")
    if isinstance(catalog_schema, Mapping):
        errors.extend(f"catalog schema: {error}" for error in json_schema_errors(catalog, catalog_schema))
    else:
        errors.append("case catalog schema must contain an object")
    for schema_path in sorted((FRAMEWORK_ROOT / NO_CRS_SCHEMA_DIRECTORY).glob("*.json")):
        try:
            schema = load_json(schema_path)
        except ContractError as exc:
            errors.append(str(exc))
            continue
        if not isinstance(schema, Mapping) or not str(schema.get("$schema") or "").startswith("https://json-schema.org/"):
            errors.append(f"{schema_path}: invalid JSON Schema declaration")
    if errors:
        for error in errors:
            print(f"no-crs-catalog: {error}", file=sys.stderr)
        return 1
    print(f"no-crs-catalog: PASS ({len(catalog_cases(catalog))} cases)")
    return 0


def select_command(args: argparse.Namespace) -> int:
    manifest = load_capability_manifest(args.capabilities, args.connector)
    manifest["source_path"] = str(Path(args.capabilities).resolve())
    plan = select_cases(
        args.connector, manifest, load_catalog(), args.evidence_stage,
        args.artifact_profile,
    )
    write_json(args.output, plan)
    print(args.output)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    catalog_parser = subparsers.add_parser("catalog-check", help="validate the canonical catalog and rules")
    catalog_parser.set_defaults(func=catalog_check_command)

    select_parser = subparsers.add_parser("select", help="select cases through canonical capability states")
    select_parser.add_argument("--connector", required=True, choices=CONNECTORS)
    select_parser.add_argument("--capabilities", required=True)
    select_parser.add_argument("--evidence-stage", choices=WRITABLE_EVIDENCE_STAGES, default="no_crs_baseline")
    select_parser.add_argument(
        "--artifact-profile", choices=ARTIFACT_PROFILES,
        default=DEFAULT_ARTIFACT_PROFILE,
        help="generic legacy artifacts or the strict full_lifecycle evidence set",
    )
    select_parser.add_argument("--output", required=True)
    select_parser.set_defaults(func=select_command)

    init_parser = subparsers.add_parser("init", help="initialize a canonical run without PASS evidence")
    init_parser.add_argument("--connector", required=True, choices=CONNECTORS)
    init_parser.add_argument("--capabilities", required=True)
    init_parser.add_argument("--evidence-stage", choices=WRITABLE_EVIDENCE_STAGES, default="no_crs_baseline")
    init_parser.add_argument(
        "--artifact-profile", choices=ARTIFACT_PROFILES,
        default=DEFAULT_ARTIFACT_PROFILE,
        help="must match the capability-selection plan artifact profile",
    )
    init_parser.add_argument("--plan")
    init_parser.add_argument("--run-dir", required=True)
    init_parser.add_argument("--run-id", required=True)
    init_parser.add_argument("--connector-root")
    init_parser.add_argument("--connector-commit")
    init_parser.add_argument("--framework-commit")
    init_parser.add_argument("--host-version", default="")
    init_parser.add_argument("--libmodsecurity-version", default="")
    init_parser.add_argument("--compiler-version", default="")
    init_parser.add_argument(
        "--host-profile",
        default="",
        help="explicit selected host profile; defaults to the compatibility/default profile",
    )
    init_parser.add_argument("--executed-target", action="append", default=[])
    init_parser.set_defaults(func=init_run)

    finalize_parser = subparsers.add_parser("finalize", help="normalize actual host evidence into canonical artifacts")
    finalize_parser.add_argument("--run-dir", required=True)
    finalize_parser.add_argument("--connector-root")
    finalize_parser.add_argument("--capabilities", required=True)
    finalize_parser.add_argument("--source-result", action="append", default=[])
    finalize_parser.add_argument("--source-results-jsonl", action="append", default=[])
    finalize_parser.add_argument("--source-summary", action="append", default=[])
    finalize_parser.add_argument("--source-events")
    finalize_parser.add_argument(
        "--source-artifact",
        action="append",
        default=[],
        help=(
            "allowlisted full-lifecycle artifact as NAME=PATH "
            "(engine_version, engine_library_sha256, ruleset_sha256, "
            "transaction_counts, lifecycle_counters, client_log, upstream_log, "
            "transport_log, cleanup_log, transport_observations, "
            "connection_lifecycle, barrier_events, effective_config)"
        ),
    )
    finalize_parser.add_argument(
        "--first-byte-evidence",
        default="",
        help="payload-free JSON emitted by the synchronized streaming barrier",
    )
    finalize_parser.add_argument(
        "--protocol-client-artifact-dir",
        default="",
        help=(
            "directory containing managed payload-free client artifacts; "
            "required for any promoted H2/H2C/H3 case"
        ),
    )
    finalize_parser.add_argument("--stdout-log", default="")
    finalize_parser.add_argument("--stderr-log", default="")
    finalize_parser.add_argument("--host-log", default="")
    finalize_parser.add_argument("--rule-load-log", default="")
    finalize_parser.add_argument("--source-log", action="append", default=[])
    finalize_parser.add_argument("--stage-rc", required=True, type=int)
    finalize_parser.add_argument("--stage-reason", default="")
    finalize_parser.add_argument("--host-version", default="")
    finalize_parser.add_argument("--libmodsecurity-version", default="")
    finalize_parser.add_argument("--started-at", default="")
    finalize_parser.add_argument("--ended-at", default="")
    finalize_parser.set_defaults(func=finalize_run)

    validate_parser = subparsers.add_parser("validate", help="validate canonical evidence")
    validate_parser.add_argument(
        "--evidence-root", required=True,
        help="exact connector/run-id directory or aggregate evidence root",
    )
    validate_parser.add_argument("--connector", choices=CONNECTORS)
    validate_parser.add_argument("--run-id", default=os.environ.get("NO_CRS_RUN_ID", ""))
    validate_parser.add_argument("--capabilities")
    validate_parser.add_argument("--connector-root")
    validate_parser.add_argument("--check", required=True, choices=("all", *VALID_CHECKS))
    validate_parser.set_defaults(func=validate_command)

    summary_parser = subparsers.add_parser("summarize", help="generate a result-only six-connector summary")
    summary_parser.add_argument("--evidence-root", required=True)
    summary_parser.add_argument("--run-id", default="")
    summary_parser.add_argument("--output-json", required=True)
    summary_parser.add_argument("--output-md", required=True)
    summary_parser.add_argument("--output-md-de", required=True)
    summary_parser.add_argument("--reports-dir")
    summary_parser.set_defaults(func=summarize_command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        return int(args.func(args))
    except ContractError as exc:
        print(f"no-crs-baseline: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
