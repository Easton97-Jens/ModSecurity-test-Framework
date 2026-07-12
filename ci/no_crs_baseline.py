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
from typing import Any, Iterable, Mapping, Sequence


FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
CI_ROOT = FRAMEWORK_ROOT / "ci"
RUNNER_ROOT = FRAMEWORK_ROOT / "tests/runners"
if str(CI_ROOT) not in sys.path:
    sys.path.insert(0, str(CI_ROOT))
if str(RUNNER_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNNER_ROOT))

from msconnector_models import STATUS_MODEL, operation_status  # noqa: E402
from synchronized_upstream import first_byte_evidence_errors  # noqa: E402

CATALOG_PATH = FRAMEWORK_ROOT / "tests/cases/no-crs-baseline/catalog.json"
RULES_PATH = FRAMEWORK_ROOT / "tests/rules/no-crs-baseline.conf"
EVENT_SCHEMA_PATH = FRAMEWORK_ROOT / "tests/schemas/no-crs-baseline/event.schema.json"
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
    ("manifest", "manifest.json"),
    ("result", "result.json"),
    ("case_results", "results.jsonl"),
    ("events", "events.jsonl"),
    ("inventory", "inventory/run.json"),
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
    "NOT IMPLEMENTED",
    "NOT EXECUTED",
    "IMPLEMENTED, NOT ASSERTED",
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


def open_directory_chain(path: str | Path, *, create: bool = False) -> int:
    """Open an absolute directory one no-follow component at a time."""
    absolute = lexical_absolute(path)
    flags = _directory_flags()
    descriptor = os.open(absolute.anchor or "/", flags)
    try:
        parts = absolute.parts[1:] if absolute.is_absolute() else absolute.parts
        for part in parts:
            if part in {"", ".", ".."}:
                raise ContractError(f"unsafe directory component in {absolute}: {part!r}")
            try:
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise ContractError(f"directory is missing: {absolute}") from None
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                try:
                    next_descriptor = os.open(part, flags, dir_fd=descriptor)
                except OSError as exc:
                    raise ContractError(f"directory component is unsafe: {absolute}: {exc}") from exc
            except OSError as exc:
                raise ContractError(f"directory component is unsafe or a symlink: {absolute}: {exc}") from exc
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
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
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
        except (ValueError, json.JSONDecodeError) as exc:
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


def validate_capability_manifest(payload: Mapping[str, Any], connector: str | None = None) -> list[str]:
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
    capabilities = payload.get("capabilities")
    if not isinstance(capabilities, Mapping):
        errors.append("capability manifest capabilities must be an object")
        return errors
    missing = sorted(set(CAPABILITIES) - set(str(key) for key in capabilities))
    if missing:
        errors.append(f"capability manifest missing capabilities: {', '.join(missing)}")
    unknown = sorted(set(str(key) for key in capabilities) - set(CAPABILITIES))
    if unknown:
        errors.append(f"capability manifest has unknown capabilities: {', '.join(unknown)}")
    for name in CAPABILITIES:
        state = capability_state(capabilities.get(name))
        if state not in CAPABILITY_STATES:
            errors.append(f"capability {name} has invalid state: {state!r}")
        value = capabilities.get(name)
        if isinstance(value, Mapping) and not str(value.get("reason") or "").strip():
            errors.append(f"capability {name} requires a non-empty reason")
    stages = payload.get("evidence_stages")
    if not isinstance(stages, Mapping):
        errors.append("capability manifest evidence_stages must be an object")
    else:
        missing_stages = sorted(set(EVIDENCE_STAGES) - set(str(key) for key in stages))
        if missing_stages:
            errors.append(f"capability manifest missing evidence stages: {', '.join(missing_stages)}")
        for stage in EVIDENCE_STAGES:
            value = stages.get(stage)
            status = str(value.get("status") or "") if isinstance(value, Mapping) else str(value or "")
            if status not in EVIDENCE_STAGE_STATUSES:
                errors.append(f"evidence stage {stage} has invalid status: {status!r}")
            if isinstance(value, Mapping) and not str(value.get("reason") or "").strip():
                errors.append(f"evidence stage {stage} requires a non-empty reason")
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


def select_cases(
    connector: str,
    manifest: Mapping[str, Any],
    catalog: Mapping[str, Any],
    evidence_stage: str = "no_crs_baseline",
    artifact_profile: str = DEFAULT_ARTIFACT_PROFILE,
) -> dict[str, Any]:
    artifact_profile = normalize_artifact_profile(artifact_profile)
    if artifact_profile == FULL_LIFECYCLE_ARTIFACT_PROFILE:
        if evidence_stage != "no_crs_baseline":
            raise ContractError(
                "full_lifecycle artifact profile requires the no_crs_baseline evidence stage"
            )
        if catalog.get("full_lifecycle_artifact_profile") != artifact_profile:
            raise ContractError(
                "catalog does not declare the requested full_lifecycle artifact profile"
            )
    capabilities = manifest["capabilities"]
    selections: list[dict[str, Any]] = []
    cases = catalog_cases(catalog)
    if evidence_stage == "minimal_runtime_smoke":
        cases = [case for case in cases if case["case_id"] in MINIMAL_RUNTIME_CASE_IDS]
    for case in cases:
        required = [str(item) for item in case["required_capabilities"]]
        states = {name: capability_state(capabilities[name]) for name in required}
        if any(state == "unsupported_by_host_model" for state in states.values()):
            selection = "UNSUPPORTED"
        elif any(state == "not_applicable" for state in states.values()):
            selection = "NOT_APPLICABLE"
        elif any(state == "not_implemented" for state in states.values()):
            # A missing implementation is materially different from a host
            # model boundary.  Keep the case visible, but do not pretend it
            # was executable or classify it as host-model unsupported.
            selection = "NOT_EXECUTED"
        else:
            selection = "SELECTED"
        reasons = []
        for name, state in states.items():
            value = capabilities[name]
            reason = str(value.get("reason") or "") if isinstance(value, Mapping) else ""
            reasons.append(f"{name}={state}" + (f" ({reason})" if reason else ""))
        selections.append(
            {
                "case_id": case["case_id"],
                "group": case.get("group", ""),
                "phase": case["phase"],
                "required_capabilities": required,
                "required_capability_states": states,
                "selection_status": selection,
                "selection_reason": "; ".join(reasons),
                "runner_case": case.get("runner_case"),
            }
        )
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


def safe_run_dir(run_dir: Path, connector_root: Path | None = None) -> None:
    if not run_dir.is_absolute():
        raise ContractError(f"run-dir must be absolute: {run_dir}")
    absolute = lexical_absolute(run_dir)
    assert_no_symlink_components(absolute)
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
        "manifest": artifact_entry("manifest.json", "produced"),
        "result": artifact_entry("result.json", "not_produced"),
        "case_results": artifact_entry("results.jsonl", "not_produced"),
        "events": artifact_entry("events.jsonl", "not_produced"),
        "stdout": artifact_entry("logs/stdout.log", "not_produced"),
        "stderr": artifact_entry("logs/stderr.log", "not_produced"),
        "host_log": artifact_entry("logs/host.log", "not_produced"),
        "first_byte_evidence": artifact_entry(FIRST_BYTE_EVIDENCE_RELATIVE_PATH, "not_produced"),
        "rule_load_log": artifact_entry("logs/rule-load.log", "not_produced"),
        "rules": artifact_entry("config/no-crs-baseline.conf", "produced"),
        "inventory": artifact_entry("inventory/run.json", "produced"),
        "capability_manifest": artifact_entry("inventory/capabilities.json", "produced"),
        "plan": artifact_entry("plan.json", "produced"),
    }
    # Inventory-only transport sidecars are initialized for every run so the
    # manifest has stable canonical paths.  They become mandatory only when a
    # transport-hardening case is promoted by the dedicated checker.
    artifacts.update({
        name: artifact_entry(path, "not_produced")
        for name, path in TRANSPORT_HARDENING_ARTIFACT_PATHS.items()
    })
    return artifacts


def init_run(args: argparse.Namespace) -> int:
    connector_root = Path(args.connector_root).resolve() if args.connector_root else None
    run_dir = Path(args.run_dir)
    artifact_profile = normalize_artifact_profile(args.artifact_profile)
    host_profile = normalize_host_profile(args.host_profile)
    safe_run_dir(run_dir, connector_root)
    if run_dir.exists() or run_dir.is_symlink():
        raise ContractError(f"init requires a fresh, nonexistent run-dir: {run_dir}")
    manifest_capabilities = load_capability_manifest(args.capabilities, args.connector)
    catalog = load_catalog()
    if args.plan:
        plan = load_json(args.plan)
        if not isinstance(plan, dict) or plan.get("connector") != args.connector:
            raise ContractError("plan is invalid or belongs to another connector")
        validate_plan_against_capabilities(
            plan, args.connector, manifest_capabilities, catalog, args.evidence_stage,
            artifact_profile,
        )
    else:
        plan = select_cases(
            args.connector, manifest_capabilities, catalog, args.evidence_stage,
            artifact_profile,
        )
    # A legacy external plan may predate artifact profiles.  It is valid only
    # as an input to init; every persisted canonical run artifact carries the
    # explicit selected profile and host profile from this point onward.
    plan["artifact_profile"] = artifact_profile
    plan["host_profile"] = host_profile
    for directory in (run_dir, run_dir / "logs", run_dir / "config", run_dir / "inventory"):
        descriptor = open_directory_chain(directory, create=True)
        os.close(descriptor)
    write_json(run_dir / "plan.json", plan)
    copy_artifact(RULES_PATH, run_dir / "config/no-crs-baseline.conf")
    copy_artifact(Path(args.capabilities), run_dir / "inventory/capabilities.json")
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
        "capability_manifest_sha256": sha256_file(run_dir / "inventory/capabilities.json"),
        "executed_targets": executed_targets,
        "created_at": utc_now(),
    }
    write_json(run_dir / "inventory/run.json", inventory)
    artifacts = initial_artifacts()
    artifacts["rules"]["sha256"] = inventory["rules_sha256"]
    artifacts["inventory"]["sha256"] = sha256_file(run_dir / "inventory/run.json")
    artifacts["capability_manifest"]["sha256"] = inventory["capability_manifest_sha256"]
    artifacts["plan"]["sha256"] = sha256_file(run_dir / "plan.json")
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
        "rules": ["config/no-crs-baseline.conf"],
        "cases": [item["case_id"] for item in plan.get("cases", [])],
        "executed_targets": executed_targets,
        "capability_manifest": "inventory/capabilities.json",
        "artifacts": artifacts,
    }
    write_json(run_dir / "manifest.json", manifest)
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


def phase4_first_byte_barrier_matches(
    event: Mapping[str, Any], *, require_no_full_response_buffering: bool,
) -> bool:
    """Return whether a Phase-4 event is the complete streaming barrier proof.

    A single host run can emit ordinary Phase-4 events before the synchronized
    streaming event.  Rule ID alone is therefore not enough to associate a
    first-byte case with its evidence: choose only the event that carries the
    complete causal barrier, then let the normal Phase-4 checks validate it.
    """
    first_chunk_size = event.get("first_chunk_size")
    body_bytes_seen = event.get("body_bytes_seen")
    body_bytes_inspected = event.get("body_bytes_inspected")
    integer_values = (first_chunk_size, body_bytes_seen, body_bytes_inspected)
    if any(isinstance(value, bool) or not isinstance(value, int) for value in integer_values):
        return False
    if first_chunk_size < 1 or body_bytes_seen < 0 or body_bytes_inspected < 0:
        return False
    if body_bytes_inspected > body_bytes_seen:
        return False
    if (
        event.get("client_first_byte_received") is not True
        or event.get("first_byte_before_response_end") is not True
        or event.get("upstream_paused") is not True
        or event.get("upstream_eos_sent_at_first_byte") is not False
        or event.get("upstream_response_finished_at_first_byte") is not False
        or event.get("response_committed") is not True
    ):
        return False
    return (
        event.get("no_full_response_buffering") is True
        if require_no_full_response_buffering
        else True
    )


def phase4_event_matches_outcome(event: Mapping[str, Any], expected_result: str) -> bool:
    """Identify the right event when one run contains several Phase-4 paths."""
    if normalize_canonical_phase(event.get("phase")) != 4:
        return False
    if expected_result in {
        "rule_observed", "event_contains_original_status", "marker_split_across_chunks",
        "end_of_stream_evaluation", "content_type_in_scope",
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
    requested = str(event.get("requested_action") or "").strip().lower().replace("-", "_")
    actual = str(event.get("actual_action") or "").strip().lower().replace("-", "_")
    if actual == "connection_abort":
        actual = "abort_connection"
    if expected_result in {"deny_before_commit", "legacy_phase4_deny_before_commit"}:
        return requested == "deny" and actual == "deny" and event.get("headers_sent") is False
    if expected_result == "late_intervention_log_only":
        return (
            requested == "deny"
            and actual == "log_only"
            and event.get("late_intervention") is True
        )
    if expected_result == "late_intervention_log_only_minimal":
        return (
            requested == "deny"
            and actual == "log_only"
            and event.get("late_intervention") is True
            and event.get("late_intervention_mode") == "minimal"
        )
    if expected_result == "late_intervention_log_only_safe":
        return (
            requested == "deny"
            and actual == "log_only"
            and event.get("late_intervention") is True
            and event.get("late_intervention_mode") == "safe"
        )
    if expected_result == "connection_aborted":
        return (
            requested == "deny"
            and actual in {"abort_connection", "stream_reset"}
            and (
                event.get("connection_aborted") is True
                or event.get("stream_reset") is True
            )
        )
    if expected_result == "connection_aborted_strict":
        return (
            requested == "deny"
            and actual in {"abort_connection", "stream_reset"}
            and (
                event.get("connection_aborted") is True
                or event.get("stream_reset") is True
            )
            and event.get("late_intervention_mode") == "strict"
        )
    if expected_result == "event_contains_late_intervention_action":
        return requested == "deny" and actual in {"deny", "log_only", "abort_connection"}
    return False


def event_for_case(
    events: Sequence[Mapping[str, Any]],
    rule_id: int | None,
    case: Mapping[str, Any],
    transaction_ids: Sequence[str] = (),
    integration_mode: str | None = None,
) -> Mapping[str, Any] | None:
    if rule_id is None:
        candidates = list(events)
    else:
        candidates = [event for event in events if rule_id in event_rule_ids(event)]
    supplied = {str(value) for value in transaction_ids if str(value).strip()}
    if supplied:
        candidates = [
            event for event in candidates
            if supplied.intersection(event_transaction_ids(event))
        ]
        if not candidates:
            return None
    if not candidates:
        return None
    if integration_mode:
        # A raw event from a compatibility path must not satisfy a selected
        # native host profile merely because connector, rule, and transaction
        # identifiers happen to overlap. Prefer the exact selected mode. Keep
        # an unmatched candidate only so the caller can produce the specific
        # mismatch diagnostic instead of silently dropping causal evidence.
        matched_mode = [
            event
            for event in candidates
            if event.get("integration_mode") == integration_mode
        ]
        if matched_mode:
            candidates = matched_mode
    if is_phase4_semantic_case(case):
        expected_result = str(case.get("expected_result") or "")
        for event in candidates:
            if phase4_event_matches_outcome(event, expected_result):
                return event
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
    return candidates[0]


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


def normalize_semantic_value(field: str, value: object) -> object:
    if field in {"http_status", "original_http_status", "visible_http_status", "first_chunk_size"}:
        return optional_int(value)
    if field == "stream_id":
        return normalize_stream_id(value)
    if field in {
        "late_intervention", "headers_sent", "response_started", "body_started", "body_truncated",
        "response_committed",
        "connection_aborted", "marker_split_across_chunks",
        "end_of_stream_evaluation", "no_full_response_buffering",
        "first_byte_before_response_end", "upstream_response_finished_at_first_byte",
        "client_first_byte_received", "upstream_paused", "upstream_eos_sent_at_first_byte",
        "connection_reused", "quic_connection_id_present", "fallback_used", "stream_reset",
        "client_aborted", "upstream_aborted",
        "client_disconnected", "upstream_disconnected", "cancelled", "eos_seen",
    }:
        return optional_bool(value)
    if field == "requested_action":
        return normalize_action(value, REQUESTED_ACTIONS)
    if field == "actual_action":
        return normalize_action(value, ACTUAL_ACTIONS)
    if field == "transport_result":
        return normalize_transport_result(value)
    if field == "late_intervention_mode":
        normalized = str(value or "").strip().lower()
        return normalized if normalized in LATE_INTERVENTION_MODES else None
    if field == "content_type_scope":
        normalized = str(value or "").strip().lower().replace("-", "_")
        return normalized if normalized in CONTENT_TYPE_SCOPES else None
    if field == "body_limit_outcome":
        normalized = str(value or "").strip().lower().replace("-", "_")
        return normalized if normalized in BODY_LIMIT_OUTCOMES else None
    if field == "transport_protocol":
        return normalize_legacy_transport_protocol(value)
    if field in {"requested_protocol", "downstream_protocol", "upstream_protocol", "negotiated_protocol"}:
        return normalize_protocol(value)
    if field == "transport":
        return normalize_transport(value)
    if field == "alpn":
        return normalize_bounded_token(value, maximum=64, field="alpn", allow_slash=True)
    if field == "transport_case_id":
        return normalize_bounded_token(value, maximum=128, field="transport_case_id")
    if field == "barrier_id":
        return normalize_bounded_token(value, maximum=128, field="barrier_id")
    if field == "connection_id":
        return normalize_bounded_token(value, maximum=128, field="connection_id")
    if field == "quic_version":
        return normalize_bounded_token(value, maximum=64, field="quic_version")
    if field == "stream_reset_code":
        return normalize_stream_reset_code(value)
    if field == "reset_code":
        return normalize_stream_reset_code(value)
    if field == "reset_by":
        return normalize_transport_enum(value, allowed=RESET_BY_VALUES, field=field)
    if field == "timeout_stage":
        return normalize_transport_enum(value, allowed=TIMEOUT_STAGES, field=field)
    if field == "write_result":
        return normalize_transport_enum(value, allowed=WRITE_RESULTS, field=field)
    if field == "cleanup_reason":
        return normalize_transport_enum(value, allowed=CLEANUP_REASONS, field=field)
    if field == "transfer_encoding":
        normalized = str(value or "").strip().lower().replace("-", "_")
        return normalized if normalized in TRANSFER_ENCODINGS else None
    raise ContractError(f"unsupported semantic field: {field}")


def raw_semantic_value(raw: Mapping[str, Any], field: str) -> object:
    for name in _RAW_SEMANTIC_FIELD_ALIASES[field]:
        if name in raw:
            return raw[name]
    return _MISSING


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
        raw_value = raw_semantic_value(raw, field)
        event_value = matching_event.get(field, _MISSING) if matching_event else _MISSING
        raw_normalized: object = _MISSING
        event_normalized: object = _MISSING
        if raw_value is not _MISSING:
            try:
                raw_normalized = normalize_semantic_value(field, raw_value)
            except ContractError:
                errors.append(f"{field}: invalid raw runtime value")
        if event_value is not _MISSING:
            try:
                event_normalized = normalize_semantic_value(field, event_value)
            except ContractError:
                errors.append(f"{field}: invalid event runtime value")
        # New protocol and transport fields must never quietly turn an
        # unknown spelling into an absent value.  That would let an invalid
        # reset/cancel/fallback claim evade the evidence gates below.  Older
        # unrelated semantic fields retain their historical permissive
        # behavior.
        if field in TRANSPORT_CLAIM_FIELDS:
            if raw_value is not _MISSING and not _empty_runtime_value(raw_value) and raw_normalized is None:
                errors.append(f"{field}: invalid raw runtime value")
            if event_value is not _MISSING and not _empty_runtime_value(event_value) and event_normalized is None:
                errors.append(f"{field}: invalid event runtime value")
        if (
            raw_normalized is not _MISSING
            and event_normalized is not _MISSING
            and raw_normalized != event_normalized
        ):
            errors.append(f"{field}: raw and event runtime evidence disagree")
        if raw_normalized is not _MISSING:
            values[field] = raw_normalized
        elif event_normalized is not _MISSING:
            values[field] = event_normalized
        else:
            values[field] = None
    effective_downstream = values.get("negotiated_protocol") or values.get("downstream_protocol")
    if effective_downstream == "h3" or values.get("transport") == "quic_udp":
        connection_id = values.get("connection_id")
        if connection_id is not None and not is_hashed_connection_id(connection_id):
            # Do not let a failed/non-promoting source record persist a raw
            # QUIC CID in canonical case JSONL either.
            values["connection_id"] = None
            errors.append("connection_id: raw QUIC connection identifiers are forbidden")
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

    def event_value(field: str) -> object:
        try:
            return normalized_event_semantic_value(matching_event, field)
        except ContractError:
            errors.append(f"canonical event has invalid {field}")
            return _MISSING

    def require_event(field: str, expected: object = _MISSING) -> object:
        value = event_value(field)
        if value is _MISSING or value is None:
            errors.append(f"canonical event is missing protocol provenance {field}")
            return None
        if record.get(field) != value:
            errors.append(f"case result {field} does not match canonical event")
        if expected is not _MISSING and value != expected:
            errors.append(f"canonical event {field}={value!r}, expected {expected!r}")
        return value

    # Bind the event to the same causal operation, not merely to a host that
    # happened to negotiate the desired protocol elsewhere in the run.
    if matching_event.get("connector") != record.get("connector"):
        errors.append("protocol event connector does not match case result")
    record_phase = normalize_canonical_phase(record.get("phase"))
    event_phase = normalize_canonical_phase(matching_event.get("phase"))
    if record_phase is None or event_phase != record_phase:
        errors.append("protocol event phase does not match case result")
    transaction_ids = {
        str(value) for value in record.get("transaction_ids", []) if str(value).strip()
    }
    if not transaction_ids:
        errors.append("protocol PASS requires a transaction_id")
    elif not transaction_ids.intersection(event_transaction_ids(matching_event)):
        errors.append("protocol event transaction_id does not match case result")
    expected_rule_id = optional_int(record.get("expected_rule_id"))
    observed_rule_ids = {
        int(value) for value in record.get("observed_rule_ids", [])
        if not isinstance(value, bool) and str(value).strip().lstrip("-").isdigit()
    }
    event_rule_values = set(event_rule_ids(matching_event))
    if expected_rule_id is not None and expected_rule_id not in event_rule_values:
        errors.append("protocol event does not report the expected rule")
    elif expected_rule_id is None and observed_rule_ids and not observed_rule_ids.intersection(event_rule_values):
        errors.append("protocol event rule_id does not match case result")

    for field, allowed in (
        ("requested_action", REQUESTED_ACTIONS),
        ("actual_action", ACTUAL_ACTIONS),
    ):
        try:
            event_action = normalize_action(matching_event.get(field), allowed)
        except ContractError:
            event_action = None
        if record.get(field) != event_action:
            errors.append(f"protocol event {field} does not match case result")

    run_id = expected_run_id if expected_run_id is not None else record.get("run_id")
    if run_id is not None:
        if not isinstance(run_id, str) or not run_id.strip():
            errors.append("protocol PASS requires a non-empty run_id")
        elif matching_event.get("run_id") != run_id:
            errors.append("protocol event run_id does not match case result")
    integration_mode = (
        expected_integration_mode
        if expected_integration_mode is not None
        else record.get("integration_mode")
    )
    if integration_mode is not None:
        if not isinstance(integration_mode, str) or not integration_mode.strip():
            errors.append("protocol PASS requires a non-empty integration_mode")
        elif matching_event.get("integration_mode") != integration_mode:
            errors.append("protocol event integration_mode does not match case result")

    requested = record.get("requested_protocol")
    downstream = record.get("downstream_protocol")
    negotiated = record.get("negotiated_protocol")
    transport = record.get("transport")
    fallback_used = record.get("fallback_used")
    downstream_protocol = negotiated or downstream

    if required_protocol is not None:
        if requested != required_protocol:
            errors.append("case protocol_profile does not match requested_protocol")
        if downstream != required_protocol:
            errors.append("case protocol_profile does not match downstream_protocol")
        if negotiated != required_protocol:
            errors.append("case protocol_profile does not match negotiated_protocol")
        downstream_protocol = required_protocol

    if requested is not None:
        require_event("requested_protocol")
    if downstream is not None:
        require_event("downstream_protocol")
    if record.get("upstream_protocol") is not None:
        require_event("upstream_protocol")
    if negotiated is not None:
        require_event("negotiated_protocol")
    if transport is not None:
        require_event("transport")
    if record.get("alpn") is not None:
        require_event("alpn")
    if record.get("stream_id") is not None:
        require_event("stream_id")
    if record.get("transport_case_id") is not None:
        require_event("transport_case_id")
    if record.get("connection_id") is not None:
        require_event("connection_id")
    if record.get("quic_connection_id_present") is not None:
        require_event("quic_connection_id_present")
    if record.get("quic_version") is not None:
        require_event("quic_version")
    if fallback_used is not None:
        require_event("fallback_used")
    if record.get("stream_reset") is not None:
        require_event("stream_reset")
    if record.get("stream_reset_code") is not None:
        require_event("stream_reset_code")

    if requested in {"h2", "h2c", "h3"}:
        if negotiated is None:
            errors.append("protocol PASS requires negotiated_protocol")
        elif requested != negotiated:
            errors.append("requested_protocol does not match negotiated_protocol")
        if fallback_used is not False:
            errors.append("protocol PASS requires fallback_used=false")
    if downstream is not None and negotiated is not None and downstream != negotiated:
        errors.append("downstream_protocol does not match negotiated_protocol")

    if downstream_protocol in {"h2", "h2c", "h3"}:
        for field in (
            "requested_protocol", "downstream_protocol", "negotiated_protocol",
            "transport", "fallback_used", "stream_id", "transport_case_id",
        ):
            require_event(field)
        if requested != downstream_protocol:
            errors.append("protocol PASS requested_protocol does not match downstream protocol")
        if downstream != downstream_protocol:
            errors.append("protocol PASS downstream_protocol does not match negotiated_protocol")
        if fallback_used is not False:
            errors.append("protocol PASS requires fallback_used=false")
        if not isinstance(record.get("stream_id"), int) or isinstance(record.get("stream_id"), bool):
            errors.append("H2/H3 protocol PASS requires a stream_id")
        if not isinstance(record.get("transport_case_id"), str) or not record.get("transport_case_id"):
            errors.append("H2/H3 protocol PASS requires a transport_case_id")

    expected_transport = {
        "h2": "tls_tcp",
        "h2c": "tcp",
        "h3": "quic_udp",
    }.get(downstream_protocol)
    if expected_transport is not None and transport != expected_transport:
        errors.append(
            f"{downstream_protocol} protocol PASS requires transport={expected_transport}"
        )
    if downstream_protocol == "h2":
        if str(record.get("alpn") or "").lower() != "h2":
            errors.append("h2 protocol PASS requires alpn=h2")
    if downstream_protocol == "h2c" and record.get("alpn") not in (None, ""):
        errors.append("h2c protocol PASS must not claim TLS ALPN")
    if downstream_protocol == "h3":
        if str(record.get("alpn") or "").lower() != "h3":
            errors.append("h3 protocol PASS requires alpn=h3")
        if record.get("quic_connection_id_present") is not True:
            errors.append("h3 protocol PASS requires quic_connection_id_present=true")
        if not isinstance(record.get("quic_version"), str) or not record.get("quic_version"):
            errors.append("h3 protocol PASS requires quic_version")
        connection_id = record.get("connection_id")
        if connection_id is not None and not is_hashed_connection_id(connection_id):
            errors.append("h3 protocol evidence may not persist a raw connection_id")

    stream_reset = record.get("stream_reset")
    if stream_reset is True and downstream_protocol not in {"h2", "h2c", "h3"}:
        errors.append("stream_reset is valid only for an H2/H3 downstream protocol")
    if (
        str(record.get("expected_result") or "") == "connection_aborted_strict"
        and downstream_protocol in {"h2", "h2c", "h3"}
    ):
        if record.get("requested_action") != "deny":
            errors.append("H2/H3 strict PASS requires requested_action=deny")
        if record.get("actual_action") != "stream_reset":
            errors.append("H2/H3 strict PASS requires actual_action=stream_reset")
        if stream_reset is not True:
            errors.append("H2/H3 strict PASS requires a client-observed stream_reset")
        if record.get("stream_reset_code") is None:
            errors.append("H2/H3 strict PASS requires stream_reset_code")
        if record.get("transport_result") != "stream_reset":
            errors.append("H2/H3 strict PASS requires transport_result=stream_reset")
        if record.get("connection_aborted") is True:
            errors.append("H2/H3 strict stream reset must not claim connection_aborted")
    return errors


def phase_is_four(value: object) -> bool:
    return normalize_canonical_phase(value) == 4


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
    def require_event_value(field: str, expected: object = _MISSING) -> None:
        if field not in matching_event:
            errors.append(f"canonical event is missing {field}")
            return
        try:
            event_value = normalize_semantic_value(field, matching_event[field])
        except ContractError:
            errors.append(f"canonical event has invalid {field}")
            return
        if record.get(field) != event_value:
            errors.append(f"case result {field} does not match canonical event")
        if expected is not _MISSING and event_value != expected:
            errors.append(f"canonical event {field}={event_value!r}, expected {expected!r}")

    def require_status_triplet() -> None:
        require_event_value("http_status", 403)
        require_event_value("original_http_status")
        require_event_value("visible_http_status")

    def require_observable_client_status() -> None:
        """Bind a host-observed HTTP status to the event's visible status."""
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

    def validate_abort_client_status() -> None:
        """Compare abort status only when an HTTP status was observable."""
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

    if expected_result == "rule_observed":
        return errors

    if expected_result in {"deny_before_commit", "legacy_phase4_deny_before_commit"}:
        require_status_triplet()
        require_event_value("requested_action", "deny")
        require_event_value("actual_action", "deny")
        require_event_value("visible_http_status", 403)
        require_event_value("headers_sent", False)
        require_event_value("connection_aborted", False)
        if matching_event.get("late_intervention") is True:
            errors.append("pre-commit deny cannot be marked as a late intervention")
        if matching_event.get("response_committed") is True:
            errors.append("pre-commit deny cannot have response_committed=true")
        require_observable_client_status()
        return errors

    if expected_result == "late_intervention_log_only":
        require_status_triplet()
        require_event_value("requested_action", "deny")
        require_event_value("actual_action", "log_only")
        require_event_value("late_intervention", True)
        require_event_value("headers_sent", True)
        require_event_value("connection_aborted", False)
        if record.get("visible_http_status") != record.get("original_http_status"):
            errors.append("log-only late intervention must preserve the visible HTTP status")
        require_observable_client_status()
        return errors

    if expected_result == "connection_aborted":
        require_status_triplet()
        require_event_value("requested_action", "deny")
        require_event_value(
            "actual_action",
            "stream_reset" if record.get("negotiated_protocol") in {"h2", "h2c", "h3"}
            else "abort_connection",
        )
        require_event_value("late_intervention", True)
        require_event_value("headers_sent", True)
        if record.get("negotiated_protocol") in {"h2", "h2c", "h3"}:
            require_event_value("stream_reset", True)
        else:
            require_event_value("connection_aborted", True)
        if record.get("visible_http_status") != record.get("original_http_status"):
            errors.append("post-commit abort must preserve the already visible HTTP status")
        validate_abort_client_status()
        return errors

    if expected_result in {
        "late_intervention_log_only_minimal", "late_intervention_log_only_safe",
    }:
        expected_mode = "minimal" if expected_result.endswith("_minimal") else "safe"
        require_status_triplet()
        require_event_value("requested_action", "deny")
        require_event_value("actual_action", "log_only")
        require_event_value("late_intervention", True)
        require_event_value("late_intervention_mode", expected_mode)
        require_event_value("headers_sent", True)
        require_event_value("connection_aborted", False)
        if record.get("visible_http_status") != record.get("original_http_status"):
            errors.append("late log-only intervention must preserve the visible HTTP status")
        require_observable_client_status()
        return errors

    if expected_result == "connection_aborted_strict":
        require_status_triplet()
        require_event_value("requested_action", "deny")
        require_event_value(
            "actual_action",
            "stream_reset" if record.get("negotiated_protocol") in {"h2", "h2c", "h3"}
            else "abort_connection",
        )
        require_event_value("late_intervention", True)
        require_event_value("late_intervention_mode", "strict")
        require_event_value("headers_sent", True)
        if record.get("negotiated_protocol") in {"h2", "h2c", "h3"}:
            require_event_value("stream_reset", True)
            require_event_value("stream_reset_code")
            require_event_value("connection_aborted", False)
            require_event_value("transport_result", "stream_reset")
        else:
            require_event_value("connection_aborted", True)
        if record.get("visible_http_status") != record.get("original_http_status"):
            errors.append("strict post-commit abort must preserve the already visible HTTP status")
        validate_abort_client_status()
        return errors

    if expected_result == "marker_split_across_chunks":
        require_event_value("marker_split_across_chunks", True)
        require_event_value("end_of_stream_evaluation", True)
        return errors

    if expected_result == "end_of_stream_evaluation":
        require_event_value("end_of_stream_evaluation", True)
        require_event_value("body_started", True)
        return errors

    if expected_result in {"content_type_in_scope", "content_type_in_scope_with_charset"}:
        require_event_value("content_type_scope", "in_scope")
        content_type = str(matching_event.get("content_type") or "")
        if not content_type:
            errors.append("in-scope response evidence is missing content_type")
        if expected_result == "content_type_in_scope_with_charset" and "charset=" not in content_type.lower():
            errors.append("charset content-type case requires a charset parameter")
        return errors

    if expected_result == "content_type_out_of_scope":
        require_event_value("content_type_scope", "out_of_scope")
        if not str(matching_event.get("content_type") or ""):
            errors.append("out-of-scope response evidence is missing content_type")
        require_observable_client_status()
        return errors

    if expected_result == "content_type_missing":
        require_event_value("content_type_scope", "missing")
        if matching_event.get("content_type") not in (None, ""):
            errors.append("missing-content-type evidence must not invent content_type")
        require_observable_client_status()
        return errors

    if expected_result == "no_full_response_buffering":
        require_event_value("no_full_response_buffering", True)
        require_event_value("client_first_byte_received", True)
        require_event_value("first_byte_before_response_end", True)
        require_event_value("first_chunk_size")
        if not isinstance(matching_event.get("first_chunk_size"), int) or matching_event["first_chunk_size"] < 1:
            errors.append("no-full-buffer evidence requires first_chunk_size > 0")
        require_event_value("upstream_paused", True)
        require_event_value("upstream_eos_sent_at_first_byte", False)
        require_event_value("upstream_response_finished_at_first_byte", False)
        require_event_value("response_committed", True)
        for field in ("body_bytes_seen", "body_bytes_inspected"):
            if not isinstance(matching_event.get(field), int):
                errors.append(f"no-full-buffer evidence requires {field}")
        if (
            isinstance(matching_event.get("body_bytes_seen"), int)
            and isinstance(matching_event.get("body_bytes_inspected"), int)
            and matching_event["body_bytes_inspected"] > matching_event["body_bytes_seen"]
        ):
            errors.append("no-full-buffer evidence has inspected bytes above seen bytes")
        return errors

    if expected_result == "first_byte_before_response_end":
        require_event_value("client_first_byte_received", True)
        require_event_value("first_byte_before_response_end", True)
        require_event_value("first_chunk_size")
        if not isinstance(matching_event.get("first_chunk_size"), int) or matching_event["first_chunk_size"] < 1:
            errors.append("first-byte evidence requires first_chunk_size > 0")
        require_event_value("upstream_paused", True)
        require_event_value("upstream_eos_sent_at_first_byte", False)
        require_event_value("upstream_response_finished_at_first_byte", False)
        require_event_value("response_committed", True)
        for field in ("body_bytes_seen", "body_bytes_inspected"):
            if not isinstance(matching_event.get(field), int):
                errors.append(f"first-byte evidence requires {field}")
        if (
            isinstance(matching_event.get("body_bytes_seen"), int)
            and isinstance(matching_event.get("body_bytes_inspected"), int)
            and matching_event["body_bytes_inspected"] > matching_event["body_bytes_seen"]
        ):
            errors.append("first-byte evidence has inspected bytes above seen bytes")
        return errors

    limit_outcomes = {
        "response_body_at_limit": "at_limit",
        "response_body_over_limit": "over_limit",
        "response_body_process_partial": "process_partial",
        "response_body_reject": "reject",
    }
    if expected_result in limit_outcomes:
        require_event_value("body_limit_outcome", limit_outcomes[expected_result])
        for field in ("body_bytes_seen", "body_bytes_inspected", "truncated"):
            if field not in matching_event:
                errors.append(f"canonical event is missing {field}")
        if expected_result == "response_body_process_partial" and matching_event.get("truncated") is not True:
            errors.append("ProcessPartial evidence must set truncated=true")
        if expected_result == "response_body_reject" and matching_event.get("truncated") is not False:
            errors.append("Reject evidence must set truncated=false")
        return errors

    if expected_result == "event_contains_original_status":
        require_status_triplet()
        if matching_event.get("late_intervention") is True and (
            record.get("visible_http_status") != record.get("original_http_status")
        ):
            errors.append("late-intervention status metadata must preserve the visible status")
        if matching_event.get("headers_sent") is False and (
            record.get("visible_http_status") != record.get("http_status")
        ):
            errors.append("uncommitted response metadata must expose the WAF status")
        return errors

    if expected_result == "event_contains_late_intervention_action":
        require_event_value("requested_action", "deny")
        require_event_value("actual_action")
        require_event_value("late_intervention")
        actual_action = record.get("actual_action")
        late_intervention = record.get("late_intervention")
        if actual_action not in {"deny", "log_only", "abort_connection", "stream_reset"}:
            errors.append("phase-4 deny must resolve to deny, log_only, abort_connection, or stream_reset")
        if actual_action == "deny" and late_intervention is not False:
            errors.append("deny action must not be marked as a late intervention")
        if actual_action in {"log_only", "abort_connection", "stream_reset"} and late_intervention is not True:
            errors.append("post-commit action must be marked as a late intervention")
        if actual_action == "abort_connection" and matching_event.get("connection_aborted") is False:
            errors.append("abort action conflicts with connection_aborted=false")
        if actual_action == "stream_reset" and matching_event.get("stream_reset") is False:
            errors.append("stream-reset action conflicts with stream_reset=false")
        if actual_action in {"deny", "log_only"} and matching_event.get("connection_aborted") is True:
            errors.append("non-abort action conflicts with connection_aborted=true")
    return errors


def full_lifecycle_pass_errors(
    record: Mapping[str, Any], matching_event: Mapping[str, Any] | None,
) -> list[str]:
    """Validate the non-Phase-4 portions of the full-lifecycle catalog.

    These checks intentionally require a canonical event for each specialized
    PASS.  A host result with only an HTTP status cannot establish chunk
    boundaries, limit policy, transport mode, or a commit boundary.
    """
    expected_result = str(record.get("expected_result") or "")
    outcomes = {
        "request_marker_split_across_chunks",
        "request_body_at_limit",
        "request_body_over_limit",
        "request_body_process_partial",
        "phase3_deny_before_commit",
        "phase3_redirect_before_commit",
        "response_status_metadata",
        "transport_http11_content_length",
        "transport_http11_chunked",
        "transport_keep_alive",
        "transport_sequential_requests",
        "transport_parallel_requests",
        "transport_http2",
        "transport_client_abort",
        "transport_upstream_abort",
        "event_bounded_or_truncated",
    }
    if expected_result not in outcomes:
        return []
    errors: list[str] = []
    if matching_event is None:
        return ["canonical full-lifecycle event is missing"]
    errors.extend(canonical_event_errors(
        matching_event, connector=str(record.get("connector") or "") or None,
    ))

    def require(field: str, expected: object = _MISSING) -> None:
        if field not in matching_event:
            errors.append(f"canonical event is missing {field}")
            return
        value = matching_event[field]
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

    def require_limit(expected: str) -> None:
        require("body_limit_outcome", expected)
        for field in ("body_bytes_seen", "body_bytes_inspected", "truncated"):
            require(field)

    if expected_result == "request_marker_split_across_chunks":
        require("marker_split_across_chunks", True)
        for field in ("body_bytes_seen", "body_bytes_inspected"):
            require(field)
        return errors
    if expected_result == "request_body_at_limit":
        require_limit("at_limit")
        return errors
    if expected_result == "request_body_over_limit":
        require_limit("over_limit")
        return errors
    if expected_result == "request_body_process_partial":
        require_limit("process_partial")
        require("truncated", True)
        return errors
    if expected_result == "phase3_deny_before_commit":
        require("requested_action", "deny")
        require("actual_action", "deny")
        require("headers_sent", False)
        require("visible_http_status", 403)
        if matching_event.get("late_intervention") is True:
            errors.append("phase-3 pre-commit deny cannot be a late intervention")
        return errors
    if expected_result == "phase3_redirect_before_commit":
        require("requested_action", "redirect")
        require("actual_action", "redirect")
        require("headers_sent", False)
        require("visible_http_status", 302)
        if matching_event.get("late_intervention") is True:
            errors.append("phase-3 pre-commit redirect cannot be a late intervention")
        return errors
    if expected_result == "response_status_metadata":
        for field in ("http_status", "original_http_status", "visible_http_status", "headers_sent"):
            require(field)
        if matching_event.get("headers_sent") is False and (
            matching_event.get("visible_http_status") != matching_event.get("http_status")
        ):
            errors.append("uncommitted response metadata must expose the WAF status")
        return errors
    if expected_result == "transport_http11_content_length":
        require("transport_protocol", "http1")
        require("transfer_encoding", "content_length")
        require("transport_result", "http_status")
        return errors
    if expected_result == "transport_http11_chunked":
        require("transport_protocol", "http1")
        require("transfer_encoding", "chunked")
        require("transport_result", "http_status")
        return errors
    if expected_result in {"transport_keep_alive", "transport_sequential_requests"}:
        require("connection_reused", True)
        require("transport_protocol")
        return errors
    if expected_result == "transport_parallel_requests":
        require("transport_protocol")
        if len(record.get("transaction_ids", [])) < 2:
            errors.append("parallel transport evidence requires at least two transaction IDs")
        return errors
    if expected_result == "transport_http2":
        require("transport_protocol", "http2")
        require("transport_result", "http_status")
        return errors
    if expected_result == "transport_client_abort":
        require("client_aborted", True)
        require("transport_result")
        return errors
    if expected_result == "transport_upstream_abort":
        require("upstream_aborted", True)
        require("transport_result")
        return errors
    if expected_result == "event_bounded_or_truncated":
        for field in ("truncated", "body_bytes_seen", "body_bytes_inspected"):
            require(field)
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


def normalize_case_record(
    raw: Mapping[str, Any],
    connector: str,
    case_by_id: Mapping[str, Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    integration_mode: str | None = None,
) -> dict[str, Any] | None:
    case_id = str(raw.get("case_id") or raw.get("case") or raw.get("name") or "").strip()
    if not case_id or case_id not in case_by_id:
        return None
    case = case_by_id[case_id]
    status = normalize_status(raw.get("status"))
    live_executed = raw.get("live_executed") is True
    provenance_errors: list[str] = []
    try:
        raw_run_id = optional_case_provenance(raw.get("run_id"), maximum=256, field="run_id")
    except ContractError:
        raw_run_id = None
        provenance_errors.append("run_id: invalid raw runtime value")
    try:
        raw_integration_mode = optional_case_provenance(
            raw.get("integration_mode"), maximum=64, field="integration_mode",
        )
    except ContractError:
        raw_integration_mode = None
        provenance_errors.append("integration_mode: invalid raw runtime value")
    observed_result = raw.get("observed_result") or raw.get("outcome")
    if str(observed_result or "") == "rejected_by_host_before_connector":
        status = "NOT_APPLICABLE"
    observed_rule_ids: list[int] = []
    candidates: list[object] = []
    if isinstance(raw.get("observed_rule_ids"), list):
        candidates.extend(raw["observed_rule_ids"])
    for key in ("observed_rule_id", "rule_id", "modsecurity_rule_id"):
        if raw.get(key) not in (None, ""):
            candidates.append(raw[key])
    for candidate in candidates:
        try:
            rule_id = int(candidate)
        except (TypeError, ValueError):
            continue
        if rule_id not in observed_rule_ids:
            observed_rule_ids.append(rule_id)
    expected_rule_id = optional_int(case.get("expected_rule_id"))
    transaction_ids = supplied_transaction_ids(raw)
    matching_event = event_for_case(
        events, expected_rule_id, case, transaction_ids, integration_mode,
    )
    semantic_values, runtime_evidence_errors = semantic_runtime_fields(raw, matching_event)
    actual_status_value: object = _MISSING
    for field in ("actual_status", "observed_status", "visible_http_status", "client_status"):
        if field in raw:
            actual_status_value = raw[field]
            break
    if not is_phase4_semantic_case(case):
        if actual_status_value is _MISSING and semantic_values["visible_http_status"] is not None:
            actual_status_value = semantic_values["visible_http_status"]
        # Keep the historical intervention_status fallback only for legacy
        # non-Phase-4 records.  It is a requested WAF status, not proof of the
        # client-visible status in a late intervention.
        if actual_status_value is _MISSING and "intervention_status" in raw:
            actual_status_value = raw["intervention_status"]
    actual_status = optional_int(actual_status_value) if actual_status_value is not _MISSING else None
    observed_event_fields = sorted(event_field_names(matching_event)) if matching_event else []
    if matching_event:
        for rule_id in event_rule_ids(matching_event):
            if rule_id not in observed_rule_ids:
                observed_rule_ids.append(rule_id)
    if matching_event:
        transaction_ids.extend(event_transaction_ids(matching_event))
    transaction_ids = sorted(dict.fromkeys(transaction_ids))
    expected_fields = [str(item) for item in case.get("expected_event_fields", [])]
    expected_status = optional_int(case.get("expected_status"))
    event_errors = (
        canonical_event_errors(
            matching_event,
            connector=connector,
            integration_mode=integration_mode,
        ) if matching_event else []
    )
    event_metadata_verified = bool(
        matching_event
        and not event_errors
        and all(field in observed_event_fields for field in expected_fields)
    ) if expected_fields else bool(matching_event and not event_errors and raw.get("event_metadata_verified"))
    record = {
        "schema_version": 1,
        "connector": connector,
        "run_id": raw_run_id,
        "integration_mode": raw_integration_mode,
        "case_id": case_id,
        "group": case.get("group", ""),
        "phase": case.get("phase"),
        "required_capabilities": list(case.get("required_capabilities", [])),
        "status": status,
        "operation_status": operation_status({
            "PASS": "pass", "FAIL": "fail", "BLOCKED": "blocked",
            "UNSUPPORTED": "not_executable", "NOT_APPLICABLE": "skipped",
            "NOT_EXECUTED": "skipped",
        }[status]),
        "live_executed": live_executed,
        "expected_result": case.get("expected_result"),
        "observed_result": observed_result,
        "expected_status": expected_status,
        "actual_status": actual_status,
        "expected_rule_id": expected_rule_id,
        "observed_rule_ids": sorted(observed_rule_ids),
        "transaction_ids": transaction_ids,
        "expected_event_fields": expected_fields,
        "observed_event_fields": observed_event_fields,
        "event_metadata_verified": event_metadata_verified,
        **semantic_values,
        "reason": str(raw.get("reason") or raw.get("skipped_reason") or ""),
        "exit_code": optional_int(raw.get("exit_code")),
        "artifacts": raw.get("artifacts") if isinstance(raw.get("artifacts"), Mapping) else {},
    }
    if status == "PASS":
        validation_errors: list[str] = list(provenance_errors)
        try:
            required_protocol = case_protocol_profile(case)
        except ContractError as exc:
            required_protocol = None
            validation_errors.append(str(exc))
        if is_phase4_semantic_case(case):
            validation_errors.extend(phase4_pass_errors(
                record, matching_event, runtime_evidence_errors, required_protocol,
            ))
        else:
            if expected_status is not None and actual_status != expected_status:
                validation_errors.append("actual status does not match expected status")
            if expected_rule_id is not None and expected_rule_id not in observed_rule_ids:
                validation_errors.append("expected rule was not observed")
            if expected_fields and not set(expected_fields).issubset(observed_event_fields):
                validation_errors.append("canonical event is missing expected fields")
            if matching_event and event_errors:
                validation_errors.extend(event_errors)
            validation_errors.extend(protocol_pass_errors(
                record, matching_event, required_protocol=required_protocol,
            ))
        validation_errors.extend(full_lifecycle_pass_errors(record, matching_event))
        if validation_errors:
            record["status"] = "FAIL"
            record["operation_status"] = operation_status("fail")
            detail = "; ".join(dict.fromkeys(validation_errors))
            record["reason"] = "; ".join(
                part for part in (str(record["reason"]), f"runtime evidence invalid: {detail}") if part
            )
    return record


def derive_core_records(
    source: Mapping[str, Any],
    connector: str,
    case_by_id: Mapping[str, Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    integration_mode: str | None = None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    explicitly_executed = source.get("requests_sent") is True or source.get("runtime_verified") is True
    if not explicitly_executed:
        return records
    allowed_status = optional_int(source.get("allowed_request_status"))
    if allowed_status is not None:
        record = normalize_case_record(
            {
                "case_id": "allow_without_marker",
                "status": "PASS" if allowed_status == 200 else "FAIL",
                "actual_status": allowed_status,
                "live_executed": True,
                "reason": "normalized from explicit source allowed_request_status",
            }, connector, case_by_id, events, integration_mode,
        )
        if record:
            records.append(record)
    blocked_status = optional_int(source.get("blocked_request_status"))
    source_rule_ids: list[int] = []
    for key in ("observed_rule_ids", "modsecurity_rule_id", "rule_id"):
        value = source.get(key)
        values = value if isinstance(value, list) else [value]
        for candidate in values:
            try:
                source_rule_ids.append(int(candidate))
            except (TypeError, ValueError):
                continue
    if blocked_status is not None:
        denied = blocked_status == 403 and 1100001 in source_rule_ids
        record = normalize_case_record(
            {
                "case_id": "deny_header_marker_403",
                "status": "PASS" if denied else "FAIL",
                "actual_status": blocked_status,
                "observed_rule_ids": source_rule_ids,
                "live_executed": True,
                "reason": "normalized from explicit source blocked_request_status and rule ID",
            }, connector, case_by_id, events, integration_mode,
        )
        if record:
            records.append(record)
    return records


def forbidden_payload_errors(value: object, location: str = "event") -> list[str]:
    errors: list[str] = []
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            child = f"{location}.{key}"
            if normalized in FORBIDDEN_EVENT_KEYS and normalized not in BODY_METADATA_KEYS:
                errors.append(f"{child}: forbidden payload/secret field")
            errors.extend(forbidden_payload_errors(nested, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            errors.extend(forbidden_payload_errors(item, f"{location}[{index}]"))
    elif isinstance(value, str):
        lowered = value.lower()
        for sentinel in BODY_SENTINELS:
            if sentinel in lowered:
                errors.append(f"{location}: body payload sentinel is present")
    return errors


def append_derived_event_records(
    records: list[dict[str, Any]],
    plan: Mapping[str, Any],
    case_by_id: Mapping[str, Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    integration_mode: str | None = None,
) -> None:
    by_id = {record["case_id"]: record for record in records}
    selections = {item["case_id"]: item for item in plan.get("cases", []) if isinstance(item, Mapping)}
    base = by_id.get("deny_header_marker_403")
    event = event_for_rule(events, 1100001)
    if not base or base.get("status") != "PASS" or not event:
        return
    fields = event_field_names(event)
    payload_clean = not canonical_event_errors(event, integration_mode=integration_mode)
    for case_id in (
        "event_contains_connector", "event_contains_transaction_id", "event_contains_rule_id",
        "event_contains_phase", "event_contains_status",
    ):
        if case_id in by_id or selections.get(case_id, {}).get("selection_status") != "SELECTED":
            continue
        case = case_by_id[case_id]
        expected = [str(item) for item in case["expected_event_fields"]]
        passed = all(item in fields for item in expected)
        record = normalize_case_record(
            {
                "case_id": case_id,
                "status": "PASS" if passed else "FAIL",
                "actual_status": 403,
                "observed_rule_ids": [1100001],
                "live_executed": True,
                "reason": "derived from the observed rule-1100001 event",
            }, str(plan["connector"]), case_by_id, events, integration_mode,
        )
        if record:
            records.append(record)
            by_id[case_id] = record
    if payload_clean and selections.get("event_has_no_request_body_payload", {}).get("selection_status") == "SELECTED":
        body_base = by_id.get("deny_request_body_marker_403")
        body_event = event_for_rule(events, 1100101)
        if body_base and body_base.get("status") == "PASS" and body_event:
            record = normalize_case_record(
                {"case_id": "event_has_no_request_body_payload", "status": "PASS", "actual_status": 403,
                 "observed_rule_ids": [1100101], "live_executed": True,
                 "reason": "observed phase-2 event contains no forbidden body payload"},
                str(plan["connector"]), case_by_id, events, integration_mode,
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
    selections = {
        str(item.get("case_id") or ""): item
        for item in plan.get("cases", [])
        if isinstance(item, Mapping)
    }
    for base_case_id in (
        "phase4_deny_before_commit",
        "phase4_deny_after_commit_log_only",
        "phase4_deny_after_commit_log_only_minimal",
        "phase4_deny_after_commit_log_only_safe",
        "phase4_deny_after_commit_abort",
    ):
        base = by_id.get(base_case_id)
        if not base or base.get("status") != "PASS":
            continue
        for case_id in (
            "phase4_rule_observed",
            "phase4_event_contains_original_status",
            "phase4_event_contains_late_intervention_action",
        ):
            if case_id in by_id or selections.get(case_id, {}).get("selection_status") != "SELECTED":
                continue
            derived_raw = dict(base)
            derived_raw.update({
                "case_id": case_id,
                "status": "PASS",
                "reason": f"derived from the validated {base_case_id} runtime event",
            })
            record = normalize_case_record(
                derived_raw,
                str(plan.get("connector") or base.get("connector") or ""),
                case_by_id,
                events,
                integration_mode,
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
        **{field: None for field in PHASE4_SEMANTIC_FIELDS},
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
        if selected_case_ids is not None and alias_id not in selected_case_ids:
            continue
        target_id = str(case.get("deprecated_alias_for") or "")
        if not target_id:
            continue
        target = records[positions[target_id]] if target_id in positions else None
        alias_index = positions.get(alias_id)
        alias = records[alias_index] if alias_index is not None else None
        if target is not None and target.get("status") == "PASS":
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
            if alias_index is None:
                positions[alias_id] = len(records)
                records.append(replacement)
            else:
                records[alias_index] = replacement
            continue
        if alias is not None and alias.get("status") == "PASS":
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
    schema = load_json(FRAMEWORK_ROOT / "tests/schemas/no-crs-baseline" / schema_name)
    if not isinstance(schema, Mapping):
        return [f"{name}: checked-in schema is invalid"]
    errors = json_schema_errors(payload, schema, root_schema=schema, location=name)
    errors.extend(forbidden_payload_errors(payload, name))
    if not isinstance(payload, Mapping):
        return errors
    if payload.get("connector") != connector:
        errors.append(f"{name}: connector does not match canonical run")
    if run_id is not None and payload.get("run_id") != run_id:
        errors.append(f"{name}: run_id does not match canonical run")
    if integration_mode is not None and payload.get("integration_mode") != integration_mode:
        errors.append(f"{name}: integration_mode does not match canonical run")
    if name == "effective_config":
        files = payload.get("files")
        if isinstance(files, list):
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
    if name in {"transport_observations", "connection_lifecycle"}:
        records_key = "observations" if name == "transport_observations" else "records"
        records = payload.get(records_key)
        if isinstance(records, list):
            for index, record in enumerate(records):
                if not isinstance(record, Mapping):
                    continue
                if record.get("protocol") == "h3":
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
        if "=" not in item:
            raise ContractError("--source-artifact must be NAME=PATH")
        name, source_text = item.split("=", 1)
        if name not in {
            *ENGINE_LIFECYCLE_ARTIFACT_PATHS,
            *TRANSPORT_HARDENING_ARTIFACT_PATHS,
        }:
            raise ContractError(f"unsupported engine lifecycle artifact: {name!r}")
        if name in seen:
            raise ContractError(f"duplicate engine lifecycle artifact: {name}")
        seen.add(name)
        source = Path(source_text)
        if name == "barrier_events":
            _copy_barrier_events_artifact(
                run_dir,
                source_text,
                connector,
                manifest,
                run_id=run_id,
                integration_mode=integration_mode,
            )
            continue
        if name == "effective_config" and source.is_dir():
            if source.is_symlink():
                raise ContractError("effective_config source directory must not be a symlink")
            source = source / "manifest.json"
        if name in {"client_log", "upstream_log", "transport_log", "cleanup_log"}:
            destination = run_dir / TRANSPORT_HARDENING_ARTIFACT_PATHS[name]
            copy_artifact(source, destination)
            manifest["artifacts"][name] = artifact_entry(
                str(destination.relative_to(run_dir)), "produced", sha256=sha256_file(destination)
            )
            continue
        if name in {"engine_version", "engine_library_sha256", "ruleset_sha256"}:
            try:
                text = source.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise ContractError(f"cannot read engine lifecycle artifact {name}: {exc}") from exc
            if not text:
                raise ContractError(f"engine lifecycle artifact {name} is empty")
            if name != "engine_version" and re.fullmatch(r"[0-9a-f]{64}", text) is None:
                raise ContractError(f"engine lifecycle artifact {name} must contain a SHA-256 digest")
        else:
            payload = load_json(source)
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
                destination = run_dir / TRANSPORT_HARDENING_ARTIFACT_PATHS[name]
                # JSON is reserialized after strict parsing, so duplicate
                # keys and non-canonical formatting cannot survive into
                # canonical inventory.
                write_json(destination, payload)
                manifest["artifacts"][name] = artifact_entry(
                    str(destination.relative_to(run_dir)), "produced",
                    sha256=sha256_file(destination),
                )
                continue
            if payload.get("schema_version") != 1 or payload.get("connector") != connector:
                raise ContractError(f"engine lifecycle artifact {name} has invalid identity")
            if name == "transaction_counts":
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
            else:
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
                    field in payload
                    and (not isinstance(payload[field], int) or payload[field] < 0)
                    for field in optional_counter_names
                ):
                    raise ContractError(f"engine lifecycle artifact {name} has invalid transport counters")
                if (
                    "transport_counters_bound" in payload
                    and not isinstance(payload["transport_counters_bound"], bool)
                ):
                    raise ContractError(
                        f"engine lifecycle artifact {name} has invalid transport_counters_bound"
                    )
                if not (
                    payload["transactions_started"] >= payload["transactions_finished"]
                    >= payload["transactions_destroyed"]
                ):
                    raise ContractError(f"engine lifecycle artifact {name} has inconsistent transaction lifecycle")
        destination_path = (
            TRANSPORT_HARDENING_ARTIFACT_PATHS.get(name)
            or ENGINE_LIFECYCLE_ARTIFACT_PATHS[name]
        )
        destination = run_dir / destination_path
        copy_artifact(source, destination)
        manifest["artifacts"][name] = artifact_entry(
            str(destination.relative_to(run_dir)), "produced", sha256=sha256_file(destination)
        )


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
        supplied_run_id = record.get("run_id")
        supplied_mode = record.get("integration_mode")
        context_errors: list[str] = []
        if supplied_run_id is not None and supplied_run_id != run_id:
            context_errors.append("source case run_id does not match canonical run")
        if supplied_mode is not None and supplied_mode != integration_mode:
            context_errors.append("source case integration_mode does not match canonical run")
        record["run_id"] = run_id
        record["integration_mode"] = integration_mode
        if record.get("status") != "PASS":
            continue
        case = case_by_id.get(str(record.get("case_id") or ""))
        matching_event = (
            event_for_case(
                events,
                optional_int(record.get("expected_rule_id")),
                case,
                [str(value) for value in record.get("transaction_ids", [])],
                event_integration_mode,
            )
            if case is not None
            else None
        )
        context_errors.extend(protocol_pass_errors(
            record,
            matching_event,
            expected_run_id=run_id,
            expected_integration_mode=integration_mode,
            required_protocol=case_protocol_profile(case) if case is not None else None,
        ))
        if context_errors:
            record["status"] = "FAIL"
            record["operation_status"] = operation_status("fail")
            detail = "; ".join(dict.fromkeys(context_errors))
            record["reason"] = "; ".join(
                part for part in (str(record.get("reason") or ""), f"protocol provenance invalid: {detail}")
                if part
            )


def finalize_run(args: argparse.Namespace) -> int:
    connector_root = Path(args.connector_root).resolve() if args.connector_root else None
    run_dir = Path(args.run_dir)
    safe_run_dir(run_dir, connector_root)
    manifest_path = run_dir / "manifest.json"
    plan_path = run_dir / "plan.json"
    if not manifest_path.is_file() or not plan_path.is_file():
        raise ContractError("finalize requires an initialized run-dir with manifest.json and plan.json")
    manifest = load_json(manifest_path)
    plan = load_json(plan_path)
    if not isinstance(manifest, dict) or not isinstance(plan, dict):
        raise ContractError("manifest and plan must be JSON objects")
    artifact_profile = canonical_artifact_profile(manifest, "manifest.json")
    host_profile = canonical_host_profile(manifest, "manifest.json")
    plan_artifact_profile = canonical_artifact_profile(plan, "plan.json")
    if plan_artifact_profile != artifact_profile:
        raise ContractError("manifest and plan artifact profiles differ")
    if canonical_host_profile(plan, "plan.json") != host_profile:
        raise ContractError("manifest and plan host profiles differ")
    initial_inventory = load_json(run_dir / "inventory/run.json")
    if not isinstance(initial_inventory, Mapping):
        raise ContractError("inventory/run.json must contain an object")
    if canonical_artifact_profile(initial_inventory, "inventory/run.json") != artifact_profile:
        raise ContractError("manifest and inventory artifact profiles differ")
    if canonical_host_profile(initial_inventory, "inventory/run.json") != host_profile:
        raise ContractError("manifest and inventory host profiles differ")
    if artifact_profile == FULL_LIFECYCLE_ARTIFACT_PROFILE:
        require_full_lifecycle_artifact_inputs(args)
    first_byte_evidence: dict[str, Any] | None = None
    provenance_required = bool(
        manifest.get("provenance_required") is True
        or manifest.get("connector_commit") not in {None, "", "unknown"}
    )
    if provenance_required and connector_root is None:
        raise ContractError("finalize requires --connector-root for repository provenance")
    connector = str(manifest.get("connector") or "")
    evidence_stage = str(manifest.get("evidence_stage") or "")
    selected_event_integration_mode = required_event_integration_mode(manifest)
    if evidence_stage not in WRITABLE_EVIDENCE_STAGES:
        raise ContractError(f"unsupported writable evidence stage: {evidence_stage!r}")
    capabilities = load_capability_manifest(run_dir / "inventory/capabilities.json", connector)
    supplied_capabilities = load_capability_manifest(args.capabilities, connector)
    if capabilities != supplied_capabilities:
        raise ContractError("capability manifest changed between init and finalize")
    catalog = load_catalog()
    case_by_id = {case["case_id"]: case for case in catalog_cases(catalog)}

    events: list[dict[str, Any]] = []
    if args.source_events:
        source_events = read_jsonl(args.source_events)
        for index, source_event in enumerate(source_events):
            event = canonicalize_event_phase(
                source_event, location=f"events[{index}]",
            )
            event = canonicalize_event_protocol_provenance(
                event, location=f"events[{index}]",
            )
            errors = canonical_event_errors(event, f"events[{index}]", connector)
            if errors:
                raise ContractError("; ".join(errors))
            events.append(event)
        # Serialize the reviewed parsed records rather than copying raw JSONL
        # text, so duplicate keys, Common lifecycle labels, and other parser
        # ambiguities cannot enter the canonical artifact after validation.
        write_jsonl(run_dir / "events.jsonl", events)
        manifest["artifacts"]["events"] = artifact_entry(
            "events.jsonl", "produced", sha256=sha256_file(run_dir / "events.jsonl")
        )

    if args.first_byte_evidence:
        first_byte_evidence = copy_first_byte_evidence(
            run_dir, args.first_byte_evidence, manifest
        )
    copy_engine_lifecycle_artifacts(
        run_dir,
        args.source_artifact,
        connector,
        artifact_profile,
        manifest,
        run_id=str(manifest.get("run_id") or "") or None,
        integration_mode=str(manifest.get("integration_mode") or "") or None,
    )
    protocol_client_artifact_dir: Path | None = None
    if str(getattr(args, "protocol_client_artifact_dir", "") or "").strip():
        protocol_client_artifact_dir = copy_protocol_client_artifacts(
            run_dir,
            str(args.protocol_client_artifact_dir),
            artifact_profile,
            manifest,
        )

    raw_records: list[dict[str, Any]] = []
    source_payloads: list[Mapping[str, Any]] = []
    source_index = 0
    for source_text in args.source_result or []:
        source = Path(source_text)
        payload = load_source_json(source)
        if isinstance(payload, Mapping):
            validate_source_payload(payload, manifest, str(source))
            source_payloads.append(payload)
        payload_records = source_records(payload)
        for index, record in enumerate(payload_records):
            validate_source_payload(record, manifest, f"{source}[{index}]")
        raw_records.extend(payload_records)
        destination = run_dir / "inventory" / f"source-result-{source_index}.json"
        copy_artifact(source, destination)
        manifest["artifacts"][f"source_result_{source_index}"] = artifact_entry(
            str(destination.relative_to(run_dir)), "produced", sha256=sha256_file(destination)
        )
        source_index += 1
    for source_text in args.source_results_jsonl or []:
        source = Path(source_text)
        payload_records = read_jsonl(source)
        for index, record in enumerate(payload_records):
            validate_source_payload(record, manifest, f"{source}[{index}]")
        raw_records.extend(payload_records)
        destination = run_dir / "inventory" / f"source-results-{source_index}.jsonl"
        copy_artifact(source, destination)
        manifest["artifacts"][f"source_results_{source_index}"] = artifact_entry(
            str(destination.relative_to(run_dir)), "produced", sha256=sha256_file(destination)
        )
        source_index += 1
    for source_text in args.source_summary or []:
        source = Path(source_text)
        payload = load_json(source)
        if isinstance(payload, Mapping):
            connector_payload = payload.get(connector)
            if isinstance(connector_payload, Mapping):
                validate_source_payload(connector_payload, manifest, str(source))
                source_payloads.append(connector_payload)
                payload_records = source_records(connector_payload)
            else:
                validate_source_payload(payload, manifest, str(source))
                source_payloads.append(payload)
                payload_records = source_records(payload)
            for index, record in enumerate(payload_records):
                validate_source_payload(record, manifest, f"{source}[{index}]")
            raw_records.extend(payload_records)
        destination = run_dir / "inventory" / f"source-summary-{source_index}.json"
        copy_artifact(source, destination)
        manifest["artifacts"][f"source_summary_{source_index}"] = artifact_entry(
            str(destination.relative_to(run_dir)), "produced", sha256=sha256_file(destination)
        )
        source_index += 1

    records: list[dict[str, Any]] = []
    for raw in raw_records:
        record = normalize_case_record(
            raw,
            connector,
            case_by_id,
            events,
            selected_event_integration_mode,
        )
        if record:
            records.append(record)
    for payload in source_payloads:
        records.extend(
            derive_core_records(
                payload,
                connector,
                case_by_id,
                events,
                selected_event_integration_mode,
            )
        )
    append_derived_event_records(
        records, plan, case_by_id, events, selected_event_integration_mode,
    )
    derive_deprecated_alias_targets(
        records, plan, case_by_id, events, selected_event_integration_mode,
    )
    append_derived_phase4_records(
        records, plan, case_by_id, events, selected_event_integration_mode,
    )
    prevent_synthetic_first_byte_promotion(records, first_byte_evidence)
    deduplicated: dict[str, dict[str, Any]] = {}
    for record in records:
        deduplicated[record["case_id"]] = record
    records = list(deduplicated.values())

    stage_rc = int(args.stage_rc)
    any_live = any(record.get("live_executed") is True for record in records)
    for selection in plan.get("cases", []):
        if not isinstance(selection, Mapping):
            continue
        case_id = str(selection.get("case_id") or "")
        if case_id in deduplicated or case_id not in case_by_id:
            continue
        selected = str(selection.get("selection_status") or "")
        if selected == "UNSUPPORTED":
            status = "UNSUPPORTED"
            reason = str(selection.get("selection_reason") or "unsupported by capability manifest")
        elif selected == "NOT_APPLICABLE":
            status = "NOT_APPLICABLE"
            reason = str(selection.get("selection_reason") or "not applicable to host model")
        elif selected == "NOT_EXECUTED":
            status = "NOT_EXECUTED"
            reason = str(selection.get("selection_reason") or "capability is not implemented")
        elif stage_rc == 77 and not any_live:
            status = "BLOCKED"
            reason = args.stage_reason or "blocked before execution"
        else:
            status = "NOT_EXECUTED"
            reason = args.stage_reason or "selected case produced no runtime evidence"
        record = selection_record(selection, case_by_id[case_id], connector, status, reason, stage_rc)
        records.append(record)
        deduplicated[case_id] = record
    selected_case_ids = {
        str(item.get("case_id") or "")
        for item in plan.get("cases", [])
        if isinstance(item, Mapping)
    }
    resolve_deprecated_aliases(records, case_by_id, selected_case_ids)
    bind_case_protocol_provenance(
        records,
        manifest,
        case_by_id,
        events,
        selected_event_integration_mode,
    )
    for record in records:
        if record.get("status") != "PASS":
            continue
        case = case_by_id.get(str(record.get("case_id") or ""))
        try:
            protocol = record_protocol_profile(record, case)
        except ContractError as exc:
            protocol = None
            errors = [str(exc)]
        else:
            errors = []
        if protocol not in {"h2", "h2c", "h3"}:
            continue
        if str(record.get("expected_result") or "") in DEDICATED_STREAM_CONTROL_RESULTS:
            errors.append(
                "protocol reset/cancel or multiplexing PASS requires a dedicated "
                "stream-control client; the managed curl probe is negotiation-only"
            )
        elif protocol_client_artifact_dir is None:
            errors.append("protocol PASS requires a managed client artifact bundle")
        else:
            artifacts = record.get("artifacts")
            if not isinstance(artifacts, Mapping):
                artifacts = {}
            record["artifacts"] = {
                **dict(artifacts),
                "protocol_client_dir": PROTOCOL_CLIENT_ARTIFACT_DIR,
            }
            errors.extend(protocol_client_artifact_errors(
                protocol_client_artifact_dir, record, protocol,
            ))
        if errors:
            record["status"] = "FAIL"
            record["operation_status"] = operation_status("fail")
            detail = "; ".join(dict.fromkeys(errors))
            record["reason"] = "; ".join(
                part for part in (
                    str(record.get("reason") or ""),
                    f"protocol client evidence invalid: {detail}",
                ) if part
            )
    deduplicated = {record["case_id"]: record for record in records}
    order = {item["case_id"]: index for index, item in enumerate(plan.get("cases", [])) if isinstance(item, Mapping)}
    records.sort(key=lambda item: order.get(item["case_id"], len(order)))

    for record in records:
        if record["status"] == "PASS" and record.get("live_executed") is not True:
            raise ContractError(f"{record['case_id']}: PASS requires live_executed=true")
    write_jsonl(run_dir / "results.jsonl", records)
    manifest["artifacts"]["case_results"] = artifact_entry(
        "results.jsonl", "produced", sha256=sha256_file(run_dir / "results.jsonl")
    )
    for key, source_text in (
        ("stdout", args.stdout_log), ("stderr", args.stderr_log),
        ("host_log", args.host_log), ("rule_load_log", args.rule_load_log),
    ):
        copy_named_log(run_dir, key, source_text, manifest)
    for item in args.source_log or []:
        if "=" not in item:
            raise ContractError("--source-log must be NAME=PATH")
        name, source_text = item.split("=", 1)
        copy_named_log(run_dir, name, source_text, manifest)

    # Recheck provenance after the connector-owned runtime work and artifact
    # collection.  A clean init snapshot is insufficient: either checkout may
    # have changed while the run was in progress.
    if provenance_required:
        assert connector_root is not None
        connector_commit_at_finalize = git_value(connector_root, "rev-parse", "HEAD")
        framework_commit_at_finalize = git_value(FRAMEWORK_ROOT, "rev-parse", "HEAD")
        connector_clean_at_finalize = git_worktree_clean(connector_root)
        framework_clean_at_finalize = git_worktree_clean(FRAMEWORK_ROOT)
        manifest["connector_worktree_clean"] = bool(
            manifest.get("connector_worktree_clean") is True and connector_clean_at_finalize
        )
        manifest["framework_worktree_clean"] = bool(
            manifest.get("framework_worktree_clean") is True and framework_clean_at_finalize
        )
    else:
        connector_commit_at_finalize = str(manifest.get("connector_commit") or "unknown")
        framework_commit_at_finalize = str(manifest.get("framework_commit") or "unknown")
    manifest["provenance_required"] = provenance_required
    manifest["connector_commit_at_finalize"] = connector_commit_at_finalize
    manifest["framework_commit_at_finalize"] = framework_commit_at_finalize

    source_statuses = [str(payload.get("status") or "").upper() for payload in source_payloads]
    source_failure = "FAIL" in source_statuses
    status, blocked_before_execution = aggregate_status(records, stage_rc, source_failure=source_failure)
    counts = Counter(record["status"] for record in records)
    observed_rule_ids = sorted({rule_id for record in records for rule_id in record["observed_rule_ids"]})
    transaction_ids = sorted({tx for record in records for tx in record["transaction_ids"]})
    pass_ids = {record["case_id"] for record in records if record["status"] == "PASS"}
    verified_capabilities = sorted({
        capability for record in records if record["status"] == "PASS"
        for capability in record["required_capabilities"]
    })
    declared_capabilities = capabilities.get("capabilities", {})
    unsupported_capabilities = sorted({
        name for name in CAPABILITIES
        if capability_state(declared_capabilities.get(name)) in {
            "unsupported_by_host_model", "not_applicable"
        }
    } - set(verified_capabilities))
    not_exercised_capabilities = sorted(set(CAPABILITIES) - set(verified_capabilities) - set(unsupported_capabilities))
    allowed_record = deduplicated.get("allow_without_marker", {})
    blocked_record = deduplicated.get("deny_header_marker_403", {})
    requests_sent = any(record.get("live_executed") is True for record in records)
    source_started = any(payload.get("started") is True for payload in source_payloads)
    started = source_started or requests_sent
    event_metadata_verified, body_payload_absent_from_events = canonical_core_event_contract(
        events, connector, selected_event_integration_mode
    )
    host_version = args.host_version or manifest["host_version"]
    libmodsecurity_version = args.libmodsecurity_version or manifest["libmodsecurity_version"]
    minimal_runtime_verified = bool(
        {"allow_without_marker", "deny_header_marker_403"}.issubset(pass_ids)
        and event_metadata_verified
        and body_payload_absent_from_events
        and concrete_version(host_version)
        and concrete_version(libmodsecurity_version)
    )
    pass_gate_failures: list[str] = []
    if status == "PASS":
        pass_gate_failures = canonical_pass_gate_failures(
            evidence_stage, pass_ids, event_metadata_verified,
            body_payload_absent_from_events, host_version, libmodsecurity_version,
        )
        if manifest.get("connector_worktree_clean") is not True:
            pass_gate_failures.append("PASS requires a clean connector worktree")
        if manifest.get("framework_worktree_clean") is not True:
            pass_gate_failures.append("PASS requires a clean framework worktree")
        pass_gate_failures.extend(provenance_pass_gate_failures(manifest))
        if (
            artifact_profile == FULL_LIFECYCLE_ARTIFACT_PROFILE
            and first_byte_evidence is not None
            and first_byte_evidence.get("evidence_origin") != "real_host"
        ):
            pass_gate_failures.append(
                "PASS requires real-host first-byte evidence; synthetic harness output is non-promoting"
            )
        if pass_gate_failures:
            status = "FAIL"
            blocked_before_execution = False
    inventory_path = run_dir / "inventory/run.json"
    inventory = load_json(inventory_path)
    if not isinstance(inventory, dict):
        raise ContractError("inventory/run.json must contain an object")
    inventory["host_version"] = host_version
    inventory["libmodsecurity_version"] = libmodsecurity_version
    for field in (
        "provenance_required", "connector_commit_at_finalize", "framework_commit_at_finalize",
        "connector_worktree_clean", "framework_worktree_clean",
    ):
        inventory[field] = manifest[field]
    inventory["finalized_at"] = args.ended_at or utc_now()
    write_json(inventory_path, inventory)
    manifest["artifacts"]["inventory"]["sha256"] = sha256_file(inventory_path)
    evidence_stages = json.loads(json.dumps(capabilities.get("evidence_stages", {})))
    if isinstance(evidence_stages.get("minimal_runtime_smoke"), Mapping) and minimal_runtime_verified:
        evidence_stages["minimal_runtime_smoke"] = {
            "status": "supported_and_verified",
            "reason": "Current canonical run observed allow, rule-1100001 deny, and required metadata event fields.",
            "evidence": ["result.json", "results.jsonl", "events.jsonl"],
        }
    current_stage_status = {
        "PASS": "supported_and_verified",
        "FAIL": "failed",
        "BLOCKED": "blocked_before_execution",
        "UNSUPPORTED": "unsupported_by_host_model",
        "NOT_APPLICABLE": "unsupported_by_host_model",
        "NOT_EXECUTED": "supported_not_verified",
    }[status]
    evidence_stages[evidence_stage] = {
        "status": current_stage_status,
        "reason": f"Current canonical result status is {status}; unsupported and unexecuted cases are not PASS.",
        "evidence": ["result.json", "results.jsonl"],
    }
    result = {
        "schema_version": 1,
        "status_model": STATUS_MODEL,
        "connector": connector,
        "connector_commit": manifest["connector_commit"],
        "framework_commit": manifest["framework_commit"],
        "connector_worktree_clean": manifest.get("connector_worktree_clean", False),
        "framework_worktree_clean": manifest.get("framework_worktree_clean", False),
        "provenance_required": manifest.get("provenance_required", False),
        "connector_commit_at_finalize": manifest.get("connector_commit_at_finalize", "unknown"),
        "framework_commit_at_finalize": manifest.get("framework_commit_at_finalize", "unknown"),
        "run_id": manifest["run_id"],
        "host_name": manifest["host_name"],
        "host_version": host_version,
        "integration_mode": manifest["integration_mode"],
        "host_profile": host_profile,
        "executed_targets": list(manifest.get("executed_targets", [])),
        "libmodsecurity_version": libmodsecurity_version,
        "evidence_stage": evidence_stage,
        "artifact_profile": artifact_profile,
        "ruleset": "no-crs-baseline",
        "status": status,
        "exit_code": stage_rc,
        "source_statuses": source_statuses,
        "source_failure": source_failure,
        "blocked_before_execution": blocked_before_execution,
        "started": started,
        "requests_sent": requests_sent,
        "allowed_request_status": allowed_record.get("actual_status"),
        "blocked_request_status": blocked_record.get("actual_status"),
        "observed_rule_ids": observed_rule_ids,
        "transaction_ids": transaction_ids,
        "request_headers_verified": {"allow_without_marker", "deny_header_marker_403"}.issubset(pass_ids),
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
        "event_metadata_verified": event_metadata_verified,
        "body_payload_absent_from_events": body_payload_absent_from_events,
        "pass_gate_failures": pass_gate_failures,
        "cases_total": len(records),
        "cases_passed": counts["PASS"],
        "cases_failed": counts["FAIL"],
        "cases_blocked": counts["BLOCKED"],
        "cases_unsupported": counts["UNSUPPORTED"],
        "cases_not_applicable": counts["NOT_APPLICABLE"],
        "cases_not_executed": counts["NOT_EXECUTED"],
        "status_counts": {name: counts[name] for name in CASE_STATUSES},
        "group_statuses": {
            group: aggregate_case_status([record for record in records if record.get("group") == group])
            for group in sorted({str(record.get("group") or "") for record in records if record.get("group")})
        },
        "capabilities_verified": verified_capabilities,
        "capabilities_unsupported": unsupported_capabilities,
        "capabilities_not_exercised": not_exercised_capabilities,
        "capability_states": {
            name: capability_state(declared_capabilities.get(name)) for name in CAPABILITIES
        },
        "evidence_stages": evidence_stages,
        "artifacts": {name: entry["path"] for name, entry in manifest["artifacts"].items() if entry["state"] == "produced"},
        "claims_not_allowed": list(CLAIMS_NOT_ALLOWED),
        "production_ready": False,
        "security_verified": False,
        "crs_verified": False,
        "crs_complete": False,
        "full_matrix_ready": False,
        "started_at": args.started_at or manifest["started_at"],
        "ended_at": args.ended_at or utc_now(),
    }
    manifest["host_version"] = result["host_version"]
    manifest["libmodsecurity_version"] = result["libmodsecurity_version"]
    manifest["started_at"] = result["started_at"]
    manifest["status"] = status
    manifest["ended_at"] = result["ended_at"]
    manifest["artifacts"]["result"] = artifact_entry("result.json", "produced")
    result["artifacts"]["result"] = "result.json"
    write_json(run_dir / "result.json", result)
    manifest["artifacts"]["result"]["sha256"] = sha256_file(run_dir / "result.json")
    write_json(manifest_path, manifest)
    errors = validate_run(
        run_dir, connector, capabilities, checks=FINALIZE_VALIDATION_CHECKS,
    )
    if errors:
        for error in errors:
            print(f"no-crs-finalize: {error}", file=sys.stderr)
        return 1
    print(run_dir / "result.json")
    return 1 if status == "FAIL" else 0


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


def json_schema_errors(
    value: object,
    schema: Mapping[str, Any],
    *,
    root_schema: Mapping[str, Any] | None = None,
    location: str = "$",
) -> list[str]:
    """Validate the JSON-Schema subset used by the checked-in contracts."""
    root = root_schema or schema
    reference = schema.get("$ref")
    if isinstance(reference, str):
        if not reference.startswith("#/"):
            return [f"{location}: unsupported external schema reference {reference}"]
        target: object = root
        for component in reference[2:].split("/"):
            if not isinstance(target, Mapping) or component not in target:
                return [f"{location}: unresolved schema reference {reference}"]
            target = target[component]
        if not isinstance(target, Mapping):
            return [f"{location}: schema reference is not an object: {reference}"]
        return json_schema_errors(value, target, root_schema=root, location=location)
    errors: list[str] = []
    expected_type = schema.get("type")
    expected_types = [expected_type] if isinstance(expected_type, str) else expected_type
    if isinstance(expected_types, list) and not any(_json_type_matches(value, str(item)) for item in expected_types):
        return [f"{location}: expected type {expected_types}, got {type(value).__name__}"]
    if "const" in schema and value != schema["const"]:
        errors.append(f"{location}: expected constant {schema['const']!r}, got {value!r}")
    if isinstance(schema.get("enum"), list) and value not in schema["enum"]:
        errors.append(f"{location}: value {value!r} is outside enum {schema['enum']!r}")
    if isinstance(value, str):
        if isinstance(schema.get("minLength"), int) and len(value) < schema["minLength"]:
            errors.append(f"{location}: string is shorter than minLength")
        if isinstance(schema.get("maxLength"), int) and len(value) > schema["maxLength"]:
            errors.append(f"{location}: string is longer than maxLength")
        if isinstance(schema.get("pattern"), str) and re.fullmatch(schema["pattern"], value) is None:
            errors.append(f"{location}: string does not match {schema['pattern']!r}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(schema.get("minimum"), (int, float)) and value < schema["minimum"]:
            errors.append(f"{location}: value is below minimum")
        if isinstance(schema.get("maximum"), (int, float)) and value > schema["maximum"]:
            errors.append(f"{location}: value is above maximum")
    if isinstance(value, list):
        if isinstance(schema.get("minItems"), int) and len(value) < schema["minItems"]:
            errors.append(f"{location}: array is shorter than minItems")
        if schema.get("uniqueItems") is True:
            serialized = [json.dumps(item, sort_keys=True) for item in value]
            if len(serialized) != len(set(serialized)):
                errors.append(f"{location}: array items are not unique")
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                errors.extend(json_schema_errors(item, item_schema, root_schema=root, location=f"{location}[{index}]"))
    if isinstance(value, Mapping):
        required = schema.get("required", [])
        if isinstance(required, list):
            for key in required:
                if key not in value:
                    errors.append(f"{location}: missing required property {key}")
        properties = schema.get("properties", {})
        property_map = properties if isinstance(properties, Mapping) else {}
        pattern_properties = schema.get("patternProperties", {})
        pattern_map = pattern_properties if isinstance(pattern_properties, Mapping) else {}
        matched: set[str] = set()
        for key, nested in value.items():
            key_text = str(key)
            if key_text in property_map and isinstance(property_map[key_text], Mapping):
                matched.add(key_text)
                errors.extend(json_schema_errors(nested, property_map[key_text], root_schema=root, location=f"{location}.{key_text}"))
            for pattern, nested_schema in pattern_map.items():
                if re.fullmatch(str(pattern), key_text) and isinstance(nested_schema, Mapping):
                    matched.add(key_text)
                    errors.extend(json_schema_errors(nested, nested_schema, root_schema=root, location=f"{location}.{key_text}"))
        additional = schema.get("additionalProperties", True)
        for key, nested in value.items():
            key_text = str(key)
            if key_text in matched:
                continue
            if additional is False:
                errors.append(f"{location}: unexpected property {key_text}")
            elif isinstance(additional, Mapping):
                errors.extend(json_schema_errors(nested, additional, root_schema=root, location=f"{location}.{key_text}"))
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
    if isinstance(event, Mapping):
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
        negotiated = protocol_values.get("negotiated_protocol")
        downstream = protocol_values.get("downstream_protocol")
        transport = protocol_values.get("transport")
        stream_reset = protocol_values.get("stream_reset")
        effective_downstream = negotiated or downstream
        if effective_downstream == "h3" or transport == "quic_udp":
            connection_id = protocol_values.get("connection_id")
            if connection_id is not None and not is_hashed_connection_id(connection_id):
                errors.append(
                    f"{location}.connection_id: raw QUIC connection identifiers are forbidden"
                )
        if stream_reset is True and effective_downstream not in {"h2", "h2c", "h3"}:
            errors.append(f"{location}.stream_reset: requires h2, h2c, or h3 downstream protocol")
    if isinstance(event, Mapping) and "phase" in event:
        if normalize_canonical_phase(event.get("phase")) is None:
            errors.append(f"{location}.phase: unsupported Common/canonical phase")
    # Core request events predate these correlation fields, so the schema
    # keeps them optional.  Every Phase-4 record must nevertheless identify
    # its producer event and message before it becomes canonical evidence.
    if isinstance(event, Mapping) and phase_is_four(event.get("phase")):
        for field in ("event", "message_id"):
            value = event.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{location}.{field}: phase-4 events require a non-empty string")
    if connector and isinstance(event, Mapping) and event.get("connector") != connector:
        errors.append(
            f"{location}.connector: {event.get('connector')!r} does not match {connector!r}"
        )
    if integration_mode and isinstance(event, Mapping) and event.get("integration_mode") != integration_mode:
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
    errors: list[str] = []
    if not isinstance(value, Mapping):
        return [f"{location}: must be an object"]
    keys = {str(key) for key in value}
    missing = sorted(set(EVIDENCE_STAGES) - keys)
    unknown = sorted(keys - set(EVIDENCE_STAGES))
    if missing:
        errors.append(f"{location}: missing stages: {', '.join(missing)}")
    if unknown:
        errors.append(f"{location}: unknown stages: {', '.join(unknown)}")
    for stage in EVIDENCE_STAGES:
        entry = value.get(stage)
        if not isinstance(entry, Mapping):
            errors.append(f"{location}.{stage}: must be an object")
            continue
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


def schema_errors(run_dir: Path, connector: str, capabilities: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    result = load_json(run_dir / "result.json")
    manifest = load_json(run_dir / "manifest.json")
    inventory = load_json(run_dir / "inventory/run.json")
    if not all(isinstance(item, Mapping) for item in (result, manifest, inventory)):
        return ["result.json, manifest.json, and inventory/run.json must contain objects"]
    schema_root = FRAMEWORK_ROOT / "tests/schemas/no-crs-baseline"
    result_schema = load_json(schema_root / "result.schema.json")
    manifest_schema = load_json(schema_root / "manifest.schema.json")
    inventory_schema = load_json(schema_root / "inventory.schema.json")
    case_result_schema = load_json(schema_root / "case-result.schema.json")
    event_schema = load_json(schema_root / "event.schema.json")
    if not all(isinstance(item, Mapping) for item in (
        result_schema, manifest_schema, inventory_schema, case_result_schema, event_schema,
    )):
        return ["checked-in JSON schemas must contain objects"]
    errors.extend(f"result.json schema: {error}" for error in json_schema_errors(result, result_schema))
    errors.extend(f"manifest.json schema: {error}" for error in json_schema_errors(manifest, manifest_schema))
    errors.extend(
        f"inventory/run.json schema: {error}"
        for error in json_schema_errors(inventory, inventory_schema)
    )
    errors.extend(required_keys(result, (
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
    ), "result.json"))
    errors.extend(required_keys(manifest, (
        "schema_version", "connector", "run_id", "evidence_stage", "ruleset", "status",
        "started_at", "ended_at", "connector_commit", "framework_commit", "host_name",
        "host_version", "integration_mode", "artifact_profile", "host_profile", "libmodsecurity_version", "compiler_version",
        "operating_system", "architecture", "rules", "cases", "executed_targets", "artifacts",
        "capability_manifest", "connector_worktree_clean", "framework_worktree_clean",
        "provenance_required", "connector_commit_at_finalize", "framework_commit_at_finalize",
    ), "manifest.json"))
    errors.extend(required_keys(inventory, (
        "schema_version", "connector", "run_id", "evidence_stage", "ruleset",
        "connector_commit", "framework_commit", "host_name", "host_version",
        "integration_mode", "artifact_profile", "host_profile", "libmodsecurity_version", "compiler_version",
        "operating_system", "architecture", "python_version", "rules_sha256",
        "catalog_sha256", "capability_manifest_sha256", "executed_targets", "created_at",
        "connector_worktree_clean", "framework_worktree_clean", "provenance_required",
        "connector_commit_at_finalize", "framework_commit_at_finalize",
    ), "inventory/run.json"))
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
    if any(
        payload.get("ruleset") != "no-crs-baseline"
        for payload in (result, manifest, inventory)
    ):
        errors.append("ruleset must be no-crs-baseline")
    if not isinstance(result.get("observed_rule_ids"), list) or not isinstance(result.get("transaction_ids"), list):
        errors.append("observed_rule_ids and transaction_ids must be lists")
    for field in (
        "started", "requests_sent", "request_headers_verified", "request_body_verified",
        "response_headers_verified", "response_body_verified", "late_intervention_verified",
        "event_metadata_verified", "body_payload_absent_from_events", "source_failure",
    ):
        if not isinstance(result.get(field), bool):
            errors.append(f"result.json: {field} must be Boolean")
    records = read_jsonl(run_dir / "results.jsonl")
    seen: set[str] = set()
    for index, record in enumerate(records):
        label = f"results.jsonl[{index}]"
        errors.extend(f"{label} schema: {error}" for error in json_schema_errors(record, case_result_schema))
        errors.extend(required_keys(record, (
            "schema_version", "connector", "run_id", "integration_mode", "case_id", "group", "phase", "status",
            "operation_status", "live_executed", "required_capabilities", "expected_result",
            "observed_result", "expected_status", "expected_rule_id",
            "actual_status", "observed_rule_ids", "transaction_ids", "expected_event_fields",
            "observed_event_fields", "event_metadata_verified", *PHASE4_SEMANTIC_FIELDS,
            "reason", "exit_code", "artifacts",
        ), label))
        if isinstance(record, Mapping):
            errors.extend(canonical_case_protocol_errors(record, label))
        if record.get("status") not in CASE_STATUSES:
            errors.append(f"{label}: invalid status")
        if record.get("connector") != connector:
            errors.append(f"{label}: connector mismatch")
        case_id = str(record.get("case_id") or "")
        if case_id in seen:
            errors.append(f"{label}: duplicate case_id {case_id}")
        seen.add(case_id)
    event_integration_mode = required_event_integration_mode(manifest)
    for index, event in enumerate(read_jsonl(run_dir / "events.jsonl", required=False)):
        errors.extend(
            canonical_event_errors(
                event,
                f"events.jsonl[{index}]",
                connector,
                event_integration_mode,
            )
        )
    errors.extend(validate_capability_manifest(capabilities, connector))
    return errors


def completeness_errors(run_dir: Path) -> list[str]:
    result = load_json(run_dir / "result.json")
    records = read_jsonl(run_dir / "results.jsonl")
    errors: list[str] = []
    if not isinstance(result, Mapping):
        return ["result.json must be an object"]
    connector = str(result.get("connector") or "")
    integration_mode = required_event_integration_mode(result)
    events = read_jsonl(run_dir / "events.jsonl", required=False)
    event_metadata_verified, body_payload_absent = canonical_core_event_contract(
        events, connector, integration_mode
    )
    if result.get("event_metadata_verified") is not event_metadata_verified:
        errors.append("event_metadata_verified is inconsistent with the canonical rule-1100001 event")
    if result.get("status") == "PASS":
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
            pass_ids = {
                str(record.get("case_id")) for record in records if record.get("status") == "PASS"
            }
            if not {"allow_without_marker", "deny_header_marker_403"}.issubset(pass_ids):
                errors.append("minimal runtime PASS requires both canonical core request cases")
            if not event_metadata_verified:
                errors.append("minimal runtime PASS requires all canonical event metadata fields")
            if not body_payload_absent:
                errors.append("minimal runtime PASS requires evidence of body-payload absence")
    for record in records:
        if record.get("status") != "PASS":
            continue
        case_id = record.get("case_id")
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
        if is_phase4_semantic_case(record):
            matching_event = event_for_case(
                events,
                optional_int(record.get("expected_rule_id")),
                record,
                [str(value) for value in record.get("transaction_ids", [])],
                integration_mode,
            )
            for error in phase4_pass_errors(record, matching_event):
                errors.append(f"{case_id}: {error}")
        matching_event = event_for_case(
            events,
            optional_int(record.get("expected_rule_id")),
            record,
            [str(value) for value in record.get("transaction_ids", [])],
            integration_mode,
        )
        for error in canonical_event_errors(
            matching_event,
            connector=connector,
            integration_mode=integration_mode,
        ):
            errors.append(f"{case_id}: {error}")
        for error in full_lifecycle_pass_errors(record, matching_event):
            errors.append(f"{case_id}: {error}")
    return errors


def capability_errors(run_dir: Path, capabilities: Mapping[str, Any]) -> list[str]:
    result = load_json(run_dir / "result.json")
    records = read_jsonl(run_dir / "results.jsonl")
    errors: list[str] = []
    declared = capabilities.get("capabilities", {})
    if not isinstance(result, Mapping) or not isinstance(declared, Mapping):
        return ["invalid result or capability manifest"]
    canonical_capabilities = load_json(run_dir / "inventory/capabilities.json")
    if not isinstance(canonical_capabilities, Mapping):
        errors.append("inventory/capabilities.json must contain an object")
    elif canonical_capabilities != capabilities:
        errors.append("current capability manifest differs from the run inventory copy")
    for record in records:
        if record.get("status") != "PASS":
            continue
        for capability in record.get("required_capabilities", []):
            state = capability_state(declared.get(capability))
            if state not in EXECUTABLE_CAPABILITY_STATES:
                errors.append(f"{record.get('case_id')}: PASS conflicts with {capability}={state}")
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
    verified = set(str(item) for item in result.get("capabilities_verified", []))
    unsupported = set(str(item) for item in result.get("capabilities_unsupported", []))
    not_exercised = set(str(item) for item in result.get("capabilities_not_exercised", []))
    if verified.intersection(unsupported):
        errors.append("capabilities_verified and capabilities_unsupported must be disjoint")
    if verified.intersection(not_exercised):
        errors.append("capabilities_verified and capabilities_not_exercised must be disjoint")
    if unsupported.intersection(not_exercised):
        errors.append("capabilities_unsupported and capabilities_not_exercised must be disjoint")
    if verified.union(unsupported, not_exercised) != set(CAPABILITIES):
        errors.append("capability result partitions must cover the canonical capability set exactly")
    expected_states = {name: capability_state(declared.get(name)) for name in CAPABILITIES}
    if result.get("capability_states") != expected_states:
        errors.append("result capability_states differ from the canonical manifest")
    return errors


def claim_policy_errors(run_dir: Path) -> list[str]:
    result = load_json(run_dir / "result.json")
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


def layout_errors(run_dir: Path) -> list[str]:
    errors: list[str] = []
    actual_file_paths, symlinks = walk_files_no_symlinks(run_dir)
    for symlink in symlinks:
        errors.append(f"symlink is forbidden in canonical run: {symlink.relative_to(lexical_absolute(run_dir))}")
    for directory in ("logs", "config", "inventory"):
        if not (run_dir / directory).is_dir():
            errors.append(f"artifact directory missing: {directory}/")
    for filename in ("manifest.json", "result.json", "results.jsonl", "plan.json"):
        if not (run_dir / filename).is_file():
            errors.append(f"required artifact missing: {filename}")
    manifest = load_json(run_dir / "manifest.json")
    if not isinstance(manifest, Mapping) or not isinstance(manifest.get("artifacts"), Mapping):
        return errors + ["manifest artifacts must be an object"]
    plan = load_json(run_dir / "plan.json")
    if not isinstance(plan, Mapping):
        return errors + ["plan.json must contain an object"]
    try:
        artifact_profile = canonical_artifact_profile(manifest, "manifest.json")
    except ContractError as exc:
        errors.append(str(exc))
        artifact_profile = DEFAULT_ARTIFACT_PROFILE
    try:
        plan_artifact_profile = canonical_artifact_profile(plan, "plan.json")
    except ContractError as exc:
        errors.append(f"plan: {exc}")
        plan_artifact_profile = DEFAULT_ARTIFACT_PROFILE
    if plan_artifact_profile != artifact_profile:
        errors.append("plan and manifest artifact profiles differ")
    for name, entry in manifest["artifacts"].items():
        if not isinstance(entry, Mapping):
            errors.append(f"manifest artifact {name} must be an object")
            continue
        state = entry.get("state")
        if state not in {"produced", "not_produced", "not_applicable"}:
            errors.append(f"manifest artifact {name} has invalid state")
            continue
        relative_path = Path(str(entry.get("path") or ""))
        if relative_path.is_absolute() or ".." in relative_path.parts or relative_path in {Path(""), Path(".")}:
            errors.append(f"manifest artifact {name} has unsafe path: {relative_path}")
            continue
        path = run_dir / relative_path
        if path.is_symlink():
            errors.append(f"manifest artifact {name} is a symlink: {relative_path}")
            continue
        if state == "produced" and not path.is_file():
            errors.append(f"manifest produced artifact is missing: {name} -> {path}")
        if state != "produced" and path.exists():
            errors.append(f"manifest says {state} but artifact exists: {name} -> {path}")
        if state == "produced" and entry.get("sha256") and sha256_file(path) != entry["sha256"]:
            errors.append(f"artifact checksum mismatch: {name}")
    if FULL_LIFECYCLE_ARTIFACT_PROFILE in {
        artifact_profile,
        plan_artifact_profile,
    }:
        for name, expected_path in FULL_LIFECYCLE_REQUIRED_ARTIFACTS:
            entry = manifest["artifacts"].get(name)
            if not isinstance(entry, Mapping):
                errors.append(f"full_lifecycle artifact is missing from manifest: {name}")
                continue
            if entry.get("path") != expected_path:
                errors.append(
                    f"full_lifecycle artifact {name} must use {expected_path}"
                )
            if entry.get("state") != "produced":
                errors.append(
                    f"full_lifecycle artifact {name} must be produced"
                )
                continue
            if not (run_dir / expected_path).is_file():
                errors.append(
                    f"full_lifecycle artifact is missing: {expected_path}"
                )
    declared_paths = {
        str(Path(str(entry.get("path"))))
        for entry in manifest["artifacts"].values()
        if isinstance(entry, Mapping) and entry.get("state") == "produced"
    }
    actual_paths = {str(path.relative_to(lexical_absolute(run_dir))) for path in actual_file_paths}
    for undeclared in sorted(actual_paths - declared_paths):
        errors.append(f"unmanifested artifact in canonical run: {undeclared}")
    return errors


def body_payload_errors(run_dir: Path) -> list[str]:
    errors: list[str] = []
    events: list[dict[str, Any]] = []
    actual_files, symlinks = walk_files_no_symlinks(run_dir)
    for symlink in symlinks:
        errors.append(f"symlink is forbidden in canonical run: {symlink.relative_to(lexical_absolute(run_dir))}")
    json_artifacts = {
        path for path in actual_files
        if path.suffix in {".json", ".jsonl"} and "config" not in path.relative_to(lexical_absolute(run_dir)).parts
    }
    for path in sorted(json_artifacts):
        if not path.is_file():
            continue
        if path.suffix == ".jsonl":
            records = read_jsonl(path)
            if path.name == "events.jsonl":
                events = records
            for index, record in enumerate(records):
                if path.name == "events.jsonl":
                    errors.extend(canonical_event_errors(record, f"{path.name}[{index}]"))
                else:
                    errors.extend(forbidden_payload_errors(record, f"{path.name}[{index}]"))
        else:
            payload = load_json(path)
            errors.extend(forbidden_payload_errors(payload, path.name))
    for path in [item for item in actual_files if item.parent == lexical_absolute(run_dir) / "logs" and item.suffix == ".log"]:
        text = secure_read_text(path, errors="replace").lower()
        for sentinel in BODY_SENTINELS:
            if sentinel in text:
                errors.append(f"{path}: body payload sentinel is present")
        if re.search(r"(?im)^(authorization|cookie|set-cookie)\s*:", text):
            errors.append(f"{path}: sensitive HTTP header is present")
    result = load_json(run_dir / "result.json")
    if isinstance(result, Mapping):
        expected_absence = bool(events) and not any(canonical_event_errors(event) for event in events)
        if result.get("body_payload_absent_from_events") is not expected_absence:
            errors.append("body_payload_absent_from_events is inconsistent with events.jsonl")
    return errors


def status_errors(run_dir: Path) -> list[str]:
    result = load_json(run_dir / "result.json")
    manifest = load_json(run_dir / "manifest.json")
    inventory = load_json(run_dir / "inventory/run.json")
    plan = load_json(run_dir / "plan.json")
    records = read_jsonl(run_dir / "results.jsonl")
    errors: list[str] = []
    if not all(isinstance(payload, Mapping) for payload in (result, manifest, inventory, plan)):
        return ["result, manifest, inventory, and plan must be objects"]
    profiles: dict[str, str] = {}
    for label, payload in (
        ("result", result), ("manifest", manifest), ("inventory", inventory), ("plan", plan),
    ):
        try:
            profiles[label] = canonical_artifact_profile(payload, f"{label}.json")
        except ContractError as exc:
            errors.append(f"{label}: {exc}")
    if profiles and len(set(profiles.values())) != 1:
        errors.append("plan, result, manifest, and inventory artifact profiles differ")
    host_profiles: dict[str, str] = {}
    for label, payload in (
        ("result", result), ("manifest", manifest), ("inventory", inventory), ("plan", plan),
    ):
        try:
            host_profiles[label] = canonical_host_profile(payload, f"{label}.json")
        except ContractError as exc:
            errors.append(f"{label}: {exc}")
    if host_profiles and len(set(host_profiles.values())) != 1:
        errors.append("plan, result, manifest, and inventory host profiles differ")
    counts = Counter(record.get("status") for record in records)
    expected_status_counts = {name: counts[name] for name in CASE_STATUSES}
    expected_fields = {
        "cases_total": len(records), "cases_passed": counts["PASS"],
        "cases_failed": counts["FAIL"], "cases_blocked": counts["BLOCKED"],
        "cases_unsupported": counts["UNSUPPORTED"],
        "cases_not_applicable": counts["NOT_APPLICABLE"],
        "cases_not_executed": counts["NOT_EXECUTED"],
    }
    for field, expected in expected_fields.items():
        if result.get(field) != expected:
            errors.append(f"{field}={result.get(field)!r}, expected {expected}")
    if result.get("status_counts") != expected_status_counts:
        errors.append(
            f"status_counts={result.get('status_counts')!r}, expected {expected_status_counts!r}"
        )

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
    expected_record_fields: dict[str, object] = {
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
    }
    for field, expected in expected_record_fields.items():
        if result.get(field) != expected:
            errors.append(f"{field} is inconsistent with canonical case records")

    expected_group_statuses = {
        group: aggregate_case_status([
            record for record in records if record.get("group") == group
        ])
        for group in sorted({
            str(record.get("group") or "") for record in records if record.get("group")
        })
    }
    if result.get("group_statuses") != expected_group_statuses:
        errors.append("group_statuses is inconsistent with canonical case records")
    expected_source_failure = "FAIL" in {
        str(status).upper() for status in result.get("source_statuses", [])
    }
    if result.get("source_failure") is not expected_source_failure:
        errors.append("source_failure is inconsistent with source_statuses")
    if result.get("status") != manifest.get("status"):
        errors.append("manifest/result status mismatch")
    expected_status, expected_blocked_before_execution = aggregate_status(
        records,
        int(result.get("exit_code") or 0),
        source_failure=result.get("source_failure") is True,
    )
    events = read_jsonl(run_dir / "events.jsonl", required=False)
    event_metadata_verified, body_payload_absent = canonical_core_event_contract(
        events,
        str(result.get("connector") or ""),
        required_event_integration_mode(result),
    )
    if result.get("event_metadata_verified") is not event_metadata_verified:
        errors.append("event_metadata_verified is inconsistent with the canonical rule-1100001 event")
    if result.get("body_payload_absent_from_events") is not body_payload_absent:
        errors.append("body_payload_absent_from_events is inconsistent with canonical events")
    expected_gate_failures: list[str] = []
    if expected_status == "PASS":
        expected_gate_failures = canonical_pass_gate_failures(
            str(result.get("evidence_stage") or ""),
            pass_ids,
            event_metadata_verified,
            body_payload_absent,
            result.get("host_version"),
            result.get("libmodsecurity_version"),
        )
        if result.get("connector_worktree_clean") is not True:
            expected_gate_failures.append("PASS requires a clean connector worktree")
        if result.get("framework_worktree_clean") is not True:
            expected_gate_failures.append("PASS requires a clean framework worktree")
        expected_gate_failures.extend(provenance_pass_gate_failures(result))
        if expected_gate_failures:
            expected_status = "FAIL"
    if result.get("status") != expected_status:
        errors.append(f"aggregate status mismatch: {result.get('status')!r} != {expected_status!r}")
    if result.get("pass_gate_failures") != expected_gate_failures:
        errors.append("pass_gate_failures is inconsistent with canonical PASS gates")
    if result.get("blocked_before_execution") is not expected_blocked_before_execution:
        errors.append("blocked_before_execution is inconsistent with case evidence and exit code")
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
    exit_code = result.get("exit_code")
    if exit_code == 77 and not (
        result.get("status") == "BLOCKED" and result.get("blocked_before_execution") is True
        and result.get("started") is False and result.get("requests_sent") is False
    ):
        errors.append("exit 77 is allowed only for BLOCKED before execution")
    if result.get("status") == "BLOCKED" and result.get("blocked_before_execution") is not True:
        errors.append("BLOCKED result must be explicitly blocked_before_execution")
    return errors


def protocol_client_errors(run_dir: Path) -> list[str]:
    """Re-evaluate run-local client evidence for every modern protocol PASS.

    Finalization is not the only trust boundary: a later validation must
    detect a deleted, substituted, or hand-edited bundle in
    ``inventory/protocol-client``.  A managed curl invocation describes one
    request only, so separate promoted protocol cases must use separate
    canonical runs until a dedicated multiplexing client contract exists.
    """

    errors: list[str] = []
    records = read_jsonl(run_dir / "results.jsonl")
    catalog = load_catalog()
    case_by_id = {case["case_id"]: case for case in catalog_cases(catalog)}
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

    if not modern_records:
        return errors
    if len(modern_records) > 1:
        case_ids = ", ".join(str(record.get("case_id") or "") for record, _ in modern_records)
        errors.append(
            "managed protocol client represents one request; modern protocol PASSes "
            f"must be finalized in separate canonical runs: {case_ids}"
        )

    manifest = load_json(run_dir / "manifest.json")
    if not isinstance(manifest, Mapping):
        return [*errors, "manifest.json must be an object"]
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping):
        return [*errors, "manifest.json artifacts must be an object"]
    artifact_dir = run_dir / PROTOCOL_CLIENT_ARTIFACT_DIR
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
        for error in protocol_client_artifact_errors(artifact_dir, record, protocol):
            errors.append(f"{case_id}: {error}")
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
    manifest = load_json(run_dir / "manifest.json")
    if (
        isinstance(manifest, Mapping)
        and manifest.get("artifact_profile") == FULL_LIFECYCLE_ARTIFACT_PROFILE
    ):
        return run_dir / "inventory/capabilities.json"
    return connector_root / f"connectors/{connector}/capabilities.json"


def validate_command(args: argparse.Namespace) -> int:
    checks = tuple(VALID_CHECKS) if args.check == "all" else (args.check,)
    evidence_root = Path(args.evidence_root)
    run_dirs: list[tuple[str, Path]] = []
    if (evidence_root / "result.json").is_file():
        result = load_json(evidence_root / "result.json")
        connector = args.connector or (str(result.get("connector") or "") if isinstance(result, Mapping) else "")
        run_dirs.append((connector, evidence_root))
    else:
        if args.connector:
            candidate = evidence_root / args.connector / args.run_id if args.run_id else evidence_root / args.connector
            if args.run_id and (candidate / "result.json").is_file():
                run_dirs.append((args.connector, candidate))
            else:
                matches = sorted(candidate.glob("*/result.json")) if candidate.is_dir() else []
                if len(matches) == 1:
                    run_dirs.append((args.connector, matches[0].parent))
                elif len(matches) > 1:
                    raise ContractError(f"multiple results for {args.connector}; pass --run-id")
        else:
            for connector in CONNECTORS:
                candidate = evidence_root / connector / args.run_id / "result.json" if args.run_id else None
                if candidate is not None and candidate.is_file():
                    run_dirs.append((connector, candidate.parent))
                    continue
                matches = sorted((evidence_root / connector).glob("*/result.json"))
                if len(matches) == 1:
                    run_dirs.append((connector, matches[0].parent))
                elif len(matches) > 1:
                    raise ContractError(f"multiple results for {connector}; pass --run-id")
    errors: list[str] = []
    expected_connectors = {args.connector} if args.connector else set(CONNECTORS)
    found_connectors = {connector for connector, _ in run_dirs}
    for connector in sorted(expected_connectors - found_connectors):
        errors.append(f"{connector}: canonical result.json missing")
    connector_root = Path(args.connector_root or ".")
    current_connector_commit = git_value(connector_root, "rev-parse", "HEAD")
    current_framework_commit = git_value(FRAMEWORK_ROOT, "rev-parse", "HEAD")
    check_current_provenance = args.check in {"all", "completeness", "status"}
    for connector, run_dir in run_dirs:
        capabilities_path = validation_capabilities_path(
            connector_root,
            connector,
            run_dir,
            args.capabilities,
        )
        capabilities = load_capability_manifest(capabilities_path, connector)
        errors.extend(f"{connector}: {error}" for error in validate_run(run_dir, connector, capabilities, checks))
        if check_current_provenance:
            result = load_json(run_dir / "result.json")
            if not isinstance(result, Mapping):
                errors.append(f"{connector}: provenance: result.json must be an object")
                continue
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
        return "NOT IMPLEMENTED"
    if normalized in {"implemented_not_asserted", "supported_not_verified"}:
        return "IMPLEMENTED, NOT ASSERTED"
    return "NOT EXECUTED"


def result_cell(result: Mapping[str, Any] | None, field: str) -> str:
    if result is None:
        return "NOT EXECUTED"
    if field == "no_crs_baseline" and result.get("evidence_stage") == "no_crs_baseline":
        return report_status(str(result.get("status") or "NOT_EXECUTED"))
    stages = result.get("evidence_stages", {})
    if isinstance(stages, Mapping) and field in stages:
        return stage_report_status(stages[field])
    return "NOT EXECUTED"


def combined_stage_cell(result: Mapping[str, Any] | None, *fields: str) -> str:
    values = [result_cell(result, field) for field in fields]
    priority = (
        "FAIL", "BLOCKED", "NOT EXECUTED", "UNSUPPORTED", "NOT IMPLEMENTED",
        "IMPLEMENTED, NOT ASSERTED", "PASS",
    )
    return next((status for status in priority if status in values), "NOT EXECUTED")


def capability_cell(result: Mapping[str, Any] | None, capability: str) -> str:
    if result is None:
        return "NOT EXECUTED"
    if capability in result.get("capabilities_verified", []):
        return "PASS"
    states = result.get("capability_states", {})
    state = str(states.get(capability) or "") if isinstance(states, Mapping) else ""
    if state == "not_implemented":
        return "NOT IMPLEMENTED"
    if state in {"unsupported_by_host_model", "not_applicable"}:
        return "UNSUPPORTED"
    if state == "implemented_not_asserted":
        return "IMPLEMENTED, NOT ASSERTED"
    return "NOT EXECUTED"


def report_status(status: str) -> str:
    if status == "NOT_EXECUTED":
        return "NOT EXECUTED"
    if status == "NOT_APPLICABLE":
        return "UNSUPPORTED"
    return status if status in REPORT_STATUSES else "NOT EXECUTED"


def aggregate_report_status(statuses: Sequence[str]) -> str:
    for status in ("FAIL", "BLOCKED", "NOT EXECUTED", "UNSUPPORTED", "NOT IMPLEMENTED", "IMPLEMENTED, NOT ASSERTED"):
        if status in statuses:
            return status
    return "PASS" if statuses and all(status == "PASS" for status in statuses) else "NOT EXECUTED"


def group_cell(result: Mapping[str, Any] | None, group: str) -> str:
    if result is None or not isinstance(result.get("group_statuses"), Mapping):
        return "NOT EXECUTED"
    return report_status(str(result["group_statuses"].get(group) or "NOT_EXECUTED"))


def find_result(evidence_root: Path, connector: str, run_id: str) -> Mapping[str, Any] | None:
    if run_id:
        path = evidence_root / connector / run_id / "result.json"
        if not path.is_file():
            return None
        payload = load_json(path)
        if not isinstance(payload, Mapping):
            raise ContractError(f"{path}: result.json must contain an object")
        return payload
    paths = sorted((evidence_root / connector).glob("*/result.json"))
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
    schema = load_json(FRAMEWORK_ROOT / "tests/schemas/no-crs-baseline/result.schema.json")
    if not isinstance(schema, Mapping):
        return ["checked-in result schema must contain an object"]
    errors = json_schema_errors(result, schema, root_schema=schema, location="result.json")
    try:
        canonical_artifact_profile(result, "result.json")
    except ContractError as exc:
        errors.append(str(exc))
    try:
        canonical_host_profile(result, "result.json")
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
        report_status(str(result.get("status") or "NOT_EXECUTED")) if result else "NOT EXECUTED"
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
        status = report_status(str(result.get("status") or "NOT_EXECUTED")) if result else "NOT EXECUTED"
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
        status = "NOT EXECUTED"
        counts = {name: 0 for name in CASE_STATUSES}
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
        report_status(str(result.get("status") or "NOT_EXECUTED")) if result else "NOT EXECUTED"
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
    catalog_schema = load_json(FRAMEWORK_ROOT / "tests/schemas/no-crs-baseline/case-catalog.schema.json")
    if isinstance(catalog_schema, Mapping):
        errors.extend(f"catalog schema: {error}" for error in json_schema_errors(catalog, catalog_schema))
    else:
        errors.append("case catalog schema must contain an object")
    for schema_path in sorted((FRAMEWORK_ROOT / "tests/schemas/no-crs-baseline").glob("*.json")):
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
