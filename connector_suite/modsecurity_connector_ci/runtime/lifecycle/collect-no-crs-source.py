#!/usr/bin/env python3
"""Normalize real host-runner observations for the canonical evidence writer.

This is a host-harness adapter, not the canonical result writer.  It reads
only explicit status, rule, transaction, and event metadata and never copies
request or response payloads into its output.
"""

from __future__ import annotations

import argparse
import importlib.util
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import sys
from typing import Any

from modsecurity_test_framework.result_identity import RESULT_BINDING_FIELDS, validate_result_binding, validate_request_observation


from modsecurity_connector_ci.lib.runtime_path_utils import open_runtime_artifact_parent, prepare_verified_runtime_artifact_root, runtime_artifact_path, write_runtime_artifact_text_atomic
from modsecurity_connector_ci.lib.first_byte_binding import event_digest, verify_binding

from modsecurity_connector_ci.runtime.lifecycle import nginx_native_collection as _NATIVE_COLLECTION


CORE_CASES = {"allow_without_marker": 200, "deny_header_marker_403": 403}
CONFIGTEST_RECEIPT_FIELDS = {
    "schema_version", "case_id", "connector", "operation", "run_id", "integration_mode",
    "parent_sha", "framework_sha", "mrts_sha", "binary_sha256", "module_sha256",
    "config_path_identity", "directive", "value", "expected_outcome", "expected_exit_code",
    "observed_exit_code", "observed_outcome", "error_class", "diagnostic_fragments",
    "stdout_sha256", "stderr_sha256", "process_started", "listener_created", "timestamp",
}
VALID_RULES_RECEIPT_FIELDS = {
    "request_probe", "cleanup_verified", "listen_port", "docroot_projection_parent",
    "docroot_projection_root", "rules_sha256", "events_sha256", "request_sha256",
    "roles_sha256", "cleanup_sha256",
}
VALID_RULES_RAW_FILES = (
    "no-crs-baseline.conf", "phase1-events.jsonl", "request-result.json", "roles.json", "cleanup.json",
)


def _configtest_source_identity_fields(row: dict[str, Any]) -> dict[str, Any]:
    """Retain the producer's bounded identity values without filling them."""
    fields = {}
    for field in ("run_id", "integration_mode", "observed_result"):
        value = row.get(field)
        if value is not None and (not isinstance(value, str) or len(value) > 256):
            raise ValueError("configuration source identity is not bounded")
        fields[field] = value
    return fields


def _configtest_source_artifacts(
    artifacts: Any, allowed_source_root: Path | None, case_id: str | None = None,
) -> dict[str, str]:
    """Validate the closed bundle against its explicit source authority."""
    if not isinstance(artifacts, dict) or set(artifacts) != {"configtest_dir"}:
        raise ValueError("configuration source contains undeclared artifact references")
    reference = artifacts["configtest_dir"]
    if (allowed_source_root is None or not isinstance(reference, str)
            or not reference or len(reference) > 4096):
        raise ValueError("configuration artifact reference requires bounded path and source authority")
    bundle = contained_source_event_path(Path(reference), allowed_source_root)
    if not bundle.is_dir():
        raise ValueError("configuration artifact bundle must be an existing directory")
    for name in ("nginx-binary", "nginx-module.so", "nginx.conf", "stdout.log", "stderr.log"):
        runtime_artifact_path(allowed_source_root, bundle / name,
                              "configuration artifact", must_exist=True)
    if case_id == "valid_rules_file":
        for name in VALID_RULES_RAW_FILES:
            runtime_artifact_path(allowed_source_root, bundle / name,
                                  "startup/probe artifact", must_exist=True)
    removed_api_fixtures = {
        "phase4_invalid_scope_file": "invalid-content-type-scope.txt",
        "phase4_wildcard_scope_rejected": "wildcard-content-type-scope.txt",
    }
    if case_id in removed_api_fixtures:
        runtime_artifact_path(allowed_source_root, bundle / removed_api_fixtures[case_id],
                              "removed-API fixture", must_exist=True)
    return {"configtest_dir": str(bundle)}


def _startup_probe_source_fields(row: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    """Preserve only the exact bounded producer-native transaction and rule."""
    if row.get("case_id") != "valid_rules_file" or receipt.get("operation") != "startup":
        return {}
    probe = receipt.get("request_probe")
    transactions = row.get("transaction_ids")
    if (not isinstance(probe, dict) or not isinstance(transactions, list)
            or len(transactions) != 1 or not isinstance(transactions[0], str)
            or not transactions[0] or len(transactions[0]) > 256
            or transactions[0] != probe.get("transaction_id")):
        raise ValueError("startup source requires its exact bounded native-probe transaction")
    rules = row.get("observed_rule_ids")
    if (not isinstance(rules, list) or len(rules) != 1
            or type(rules[0]) is not int or rules[0] != 1100001):
        raise ValueError("startup source requires its exact integer native-probe rule")
    return {"transaction_ids": transactions, "observed_rule_ids": rules}


def configtest_source_fields(
    row: dict[str, Any], expected_phase: int | None,
    allowed_source_root: Path | None = None,
) -> dict[str, Any]:
    """Retain only bounded producer metadata; Framework validates the contract.

    This adapter never invents a receipt/event, fills missing keys, changes a
    failing source status, or maps configtest evidence onto an HTTP case.
    """
    if "configtest_receipt" not in row:
        return {}
    receipt = row["configtest_receipt"]
    if expected_phase != 0 or not isinstance(receipt, dict):
        raise ValueError("configuration receipt is not a phase-0 source object")
    allowed_fields = CONFIGTEST_RECEIPT_FIELDS
    if row.get("case_id") in {"missing_rules_file", "unsafe_event_path"}:
        allowed_fields = allowed_fields | {"fixture_leaf", "fixture_state"}
    if row.get("case_id") in {"phase4_invalid_scope_file", "phase4_wildcard_scope_rejected"}:
        allowed_fields = allowed_fields | {"fixture_leaf", "fixture_state", "fixture_sha256"}
    if row.get("case_id") == "valid_rules_file":
        allowed_fields = allowed_fields | VALID_RULES_RECEIPT_FIELDS
    if set(receipt) - allowed_fields or len(json.dumps(receipt)) > 8192:
        raise ValueError("configuration receipt contains unbounded or undeclared fields")
    fields = {"configtest_receipt": receipt}
    fields.update(_configtest_source_identity_fields(row))
    # The retained phase-1 event is validated by the Framework bundle contract;
    # this projection never creates a phase-0 event.
    fields.update(_startup_probe_source_fields(row, receipt))
    if "artifacts" in row:
        fields["artifacts"] = _configtest_source_artifacts(row["artifacts"], allowed_source_root, row.get("case_id"))
    return fields


def verify_closed_five_connector_profile(profile_name: str, connector: str) -> None:
    """Reject a profile-selected collector invocation outside its fixed rows.

    The profile module is loaded from a fixed sibling path rather than from a
    caller-controlled import location.  This keeps collection aligned with
    the workflow matrix and runner dispatch without extending Framework's
    canonical result schema.
    """
    profile_path = Path(__file__).with_name("five-connector-no-crs-profile.py")
    spec = importlib.util.spec_from_file_location("five_connector_no_crs_profile", profile_path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load the closed five-connector profile")
    profile = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(profile)
    if profile_name != profile.PROFILE:
        raise ValueError(f"unsupported closed five-connector profile: {profile_name!r}")
    profile.profile_row(connector)

# These names are intentionally limited to the explicit summaries written by
# the selected native host runners.  They are *not* generic status aliases:
# each mapped record still has to bind to a raw Common/host event at
# finalization, including its canonical rule ID, transaction metadata, and
# selected integration mode.  This lets a real native host result enter the
# existing catalog without treating a build-only ``not_permitted`` marker as
# evidence.
NATIVE_HOST_SUMMARY_CASES = (
    ("allowed_request_status", "allow_without_marker", None),
    ("p1_allow_status", "allow_without_marker", None),
    ("blocked_request_status", "deny_header_marker_403", 1100001),
    ("phase1_deny_status", "deny_header_marker_403", 1100001),
    ("p1_deny_status", "deny_header_marker_403", 1100001),
    ("p1_alternative_status", "deny_with_alternative_status", 1100002),
    ("phase1_alternative_status_client_status", "deny_with_alternative_status", 1100002),
    ("phase2_deny_status", "deny_request_body_marker_403", 1100101),
    ("p2_deny_status", "deny_request_body_marker_403", 1100101),
    ("phase3_deny_status", "deny_response_header_marker_403", 1100201),
    ("phase3_deny_client_status", "deny_response_header_marker_403", 1100201),
    ("p3_precommit_deny_status", "deny_response_header_marker_403", 1100201),
    ("phase3_redirect_status", "phase3_redirect_before_commit", 1100202),
    ("phase4_rule_observed_status", "phase4_rule_observed", 1100301),
    ("phase4_safe_status", "phase4_deny_after_commit_log_only_safe", 1100301),
    ("p4_safe_log_only_status", "phase4_deny_after_commit_log_only_safe", 1100301),
    ("phase4_end_of_stream_evaluation_status", "phase4_end_of_stream_evaluation", 1100301),
    ("phase4_first_byte_before_response_end_status", "phase4_first_byte_before_response_end", 1100301),
    ("phase4_no_full_response_buffering_status", "phase4_no_full_response_buffering", 1100301),
)

# Apache and NGINX execute their native P3 and post-commit P4 fixtures under
# the full-lifecycle catalog names below.  The compact gate consumes the
# existing, connector-neutral core IDs instead.  These are evidence aliases,
# not status aliases: an alias is emitted only after the same raw host event
# has the complete semantics required by the target case, and finalization
# still binds it to the selected integration mode and transaction ID.
NATIVE_RUNNER_CORE_CASE_ALIASES = {
    "apache": {
        "phase3_deny_before_commit": "deny_response_header_marker_403",
        "phase4_deny_after_commit_log_only": "phase4_deny_after_commit_log_only_safe",
    },
    "nginx": {
        "phase3_deny_before_commit": "deny_response_header_marker_403",
        "phase4_deny_after_commit_log_only": "phase4_deny_after_commit_log_only_safe",
    },
}

NATIVE_RULE_ENGINE_EVALUATIONS = {
    "libmodsecurity",
    "libmodsecurity_host_runtime",
    "common_libmodsecurity",
    "host_runtime_observed_not_promoted",
}
FORBIDDEN_EVENT_KEYS = {
    "authorization",
    "body_payload",
    "body_snippet",
    "cookie",
    "cookies",
    "password",
    "matched_value",
    "matched_value_snippet",
    "request_body",
    "response_body",
    "intervention_log",
    "rule_message",
    "secret",
}
APPROVED_RAW_EVENT_KEYS = {
    "action",
    "actual_action",
    "anomaly_score",
    "audit_log_path",
    "body_started",
    "body_bytes_seen",
    "body_bytes_inspected",
    "client_first_byte_received",
    "first_byte_before_response_end",
    "first_chunk_size",
    "upstream_paused",
    "upstream_eos_sent_at_first_byte",
    "upstream_response_finished_at_first_byte",
    "upstream_response_complete_at_first_byte",
    "no_full_response_buffering",
    "response_body_size",
    "body_truncated",
    "client_ip",
    "connection_aborted",
    "connection_id",
    "connection_reused",
    "connector",
    "content_type",
    "decision",
    "disruptive",
    "event",
    "event_hash",
    "event_truncated",
    "eos_seen",
    "end_of_stream_evaluation",
    "evaluation_mode",
    "expected_status",
    "headers_sent",
    "header_sent",
    "http_default_message",
    "http_reason_phrase",
    "http_status",
    "haproxy_log_path",
    "intervention_status",
    "integration_mode",
    "intervention",
    "late_intervention_mode",
    "late_intervention",
    "level",
    "live_executed",
    "message",
    "message_id",
    "method",
    "mode",
    "modsecurity_processed",
    "modsecurity_rule_id",
    "observed_status",
    "observed_client_status",
    "original_http_status",
    "phase",
    "payload_recorded",
    "previous_event_hash",
    "reason",
    "redacted",
    "reason_code",
    "redirect_present",
    "request_id",
    "request_body_seen",
    "request_headers_seen",
    "requested_action",
    "wanted_action",
    "upstream_status",
    "client_status",
    "response_body_seen",
    "response_committed",
    "strict_abort",
    "response_headers_seen",
    "response_started",
    "result",
    "rule_id",
    "sequence",
    "status",
    "spoa_log_path",
    "timestamp",
    "transaction_id",
    "truncated",
    "tx_id",
    "uri",
    "variant",
    "visible_http_status",
    "waf_status",
    "transport_result",
    "observed_transport_result",
    "protocol",
    "requested_protocol",
    "downstream_protocol",
    "upstream_protocol",
    "negotiated_protocol",
    "transport",
    "alpn",
    "stream_id",
    "quic_connection_id_present",
    "quic_version",
    "fallback_used",
    "stream_reset",
    "stream_reset_code",
    "transport_case_id",
    "case_id",
    "barrier_id",
    "client_result",
    "host_survived",
    "followup_request_result",
    "client_disconnected",
    "upstream_disconnected",
    "cancelled",
    "reset_by",
    "reset_code",
    "timeout_stage",
    "write_result",
    "cleanup_reason",
    "transaction_started",
    "transaction_finished",
    "transaction_destroyed",
    "request_body_finished",
    "response_body_finished",
    "intentional_abort",
    "client_disconnect",
    "upstream_disconnect",
    "timeout",
    "short_writes",
    "write_would_block",
    "runtime_mode",
    "rule_evaluation",
    "case",
    "host_action",
    "run_id",
}
BODY_SENTINELS = (
    "no-crs-request-body-marker",
    "no-crs-response-body-marker",
)
MAX_METADATA_LENGTH = {
    "connector": 64,
    "integration_mode": 64,
    "transaction_id": 256,
    "case_id": 128,
    "transport_case_id": 128,
    "barrier_id": 128,
    "connection_id": 128,
    "stream_reset_code": 64,
    "reset_code": 64,
    "reset_by": 64,
    "timeout_stage": 64,
    "write_result": 64,
    "cleanup_reason": 64,
    "status": 64,
    "content_type": 256,
}
REQUESTED_ACTIONS = {"deny", "redirect", "drop", "log_only", "abort_connection"}
ACTUAL_ACTIONS = {"deny", "redirect", "log_only", "abort_connection", "stream_reset"}
TRANSPORT_RESULTS = {
    "completed", "http_status", "log_only", "connection_aborted", "stream_reset",
    "client_cancelled", "client_disconnected", "upstream_reset", "upstream_disconnected",
    "timeout", "short_write", "write_would_block", "engine_error", "host_error",
    "not_observable",
}
CANONICAL_PROTOCOLS = {"http1", "h2", "h2c", "h3"}
CANONICAL_TRANSPORTS = {"tcp", "tls_tcp", "quic_udp"}
TRANSPORT_TOKEN_FIELDS = {
    "case_id", "transport_case_id", "barrier_id", "connection_id", "reset_by",
    "reset_code", "stream_reset_code", "timeout_stage", "write_result", "cleanup_reason",
    "client_result", "followup_request_result", "run_id",
}
INTEGER_METADATA_FIELDS = {
    "rule_id", "http_status", "original_http_status", "visible_http_status",
}
NONNEGATIVE_INTEGER_METADATA_FIELDS = {
    "first_chunk_size", "body_bytes_seen", "body_bytes_inspected", "stream_id",
    "short_writes", "write_would_block",
}
BOOLEAN_METADATA_FIELDS = {
    "truncated", "late_intervention", "headers_sent", "body_started",
    "connection_aborted", "connection_reused", "quic_connection_id_present",
    "fallback_used", "stream_reset", "client_disconnected", "upstream_disconnected",
    "cancelled", "eos_seen", "end_of_stream_evaluation", "host_survived",
    "transaction_started", "transaction_finished", "transaction_destroyed",
    "request_body_finished", "response_body_finished", "intentional_abort",
    "client_disconnect", "upstream_disconnect", "timeout", "response_committed",
    "client_first_byte_received", "first_byte_before_response_end", "upstream_paused",
    "upstream_eos_sent_at_first_byte", "upstream_response_finished_at_first_byte",
    "no_full_response_buffering",
}
PHASE_ALIASES = {
    "connection": 0,
    "request_headers": 1,
    "request_body": 2,
    "response_headers": 3,
    "response_body": 4,
    "phase1": 1,
    "phase2": 2,
    "phase3": 3,
    "phase4": 4,
}
FIRST_BYTE_REQUIRED_FIELDS = (
    "client_first_byte_received",
    "first_byte_before_response_end",
    "first_chunk_size",
    "upstream_paused",
    "upstream_eos_sent_at_first_byte",
    "upstream_response_finished_at_first_byte",
    "response_committed",
    "body_bytes_seen",
    "body_bytes_inspected",
    "no_full_response_buffering",
    "connector_owned_full_response_buffer",
)
FIRST_BYTE_REQUIRED_BOOLS = {
    "client_first_byte_received": True,
    "first_byte_before_response_end": True,
    "upstream_paused": True,
    "upstream_eos_sent_at_first_byte": False,
    "upstream_response_finished_at_first_byte": False,
    "response_committed": True,
    "no_full_response_buffering": True,
    "connector_owned_full_response_buffer": False,
}
FIRST_BYTE_COUNTER_FIELDS = (
    "first_chunk_size",
    "body_bytes_seen",
    "body_bytes_inspected",
)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON source is not an object: {path}")
    return value


def canonical_framework_root(value: Path) -> Path:
    """Validate the exact read-only Framework root selected for one invocation."""

    if not value.is_absolute():
        raise ValueError(f"Framework source root must be absolute: {value}")
    if ".." in value.parts:
        raise ValueError(f"Framework source root contains an unsafe path component: {value}")
    lexical = Path(os.path.abspath(os.fspath(value)))
    try:
        resolved = lexical.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"Framework source root is unavailable: {lexical}") from exc
    if lexical != resolved:
        raise ValueError(f"Framework source root must not contain symbolic links: {lexical}")
    if not resolved.is_dir():
        raise ValueError(f"Framework source root must be an existing directory: {resolved}")
    return resolved


def canonical_catalog_path(value: Path, framework_root: Path) -> Path:
    """Accept a regular non-symlink catalog under the selected Framework root."""

    framework = canonical_framework_root(framework_root)
    if not value.is_absolute():
        raise ValueError(f"catalog must be absolute: {value}")
    if ".." in value.parts:
        raise ValueError(f"catalog contains an unsafe path component: {value}")
    lexical = Path(os.path.abspath(os.fspath(value)))
    try:
        candidate = lexical.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"catalog is unavailable: {lexical}") from exc
    if lexical != candidate:
        raise ValueError(f"catalog must not contain symbolic links: {lexical}")
    try:
        candidate.relative_to(framework)
    except ValueError as exc:
        raise ValueError(f"catalog must remain under the Framework source root: {candidate}") from exc
    if not candidate.is_file():
        raise ValueError(f"catalog must be a regular source file: {candidate}")
    return candidate


def runtime_artifact_paths(
    root: Path,
    values: list[Path],
    label: str,
    *,
    must_exist: bool,
) -> list[Path]:
    """Validate every CLI-supplied artifact under one private run root."""

    return [
        runtime_artifact_path(root, value, label, must_exist=must_exist)
        for value in values
    ]


def paired_runtime_log_root(source_root: Path, log_root: Path) -> Path:
    """Bind diagnostic logs to the same invocation, connector, and run."""

    source_identity = (
        source_root.parent.parent.parent,
        source_root.parent.name,
        source_root.name,
    )
    log_identity = (
        log_root.parent.parent.parent,
        log_root.parent.name,
        log_root.name,
    )
    if source_root == log_root or source_identity != log_identity:
        raise ValueError(
            "allowed log root must differ from and match the allowed source "
            "root's invocation, connector, and run identity"
        )
    return log_root


def catalog_runner_case_path(catalog_root: Path, runner_case: object) -> Path:
    """Resolve one catalog-owned runner case without accepting path aliases."""
    if not isinstance(runner_case, str) or not runner_case:
        raise ValueError("catalog runner_case must be a non-empty string")
    if "\\" in runner_case:
        raise ValueError(f"catalog runner_case must use POSIX separators: {runner_case!r}")
    parts = runner_case.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"catalog runner_case contains an unsafe path component: {runner_case!r}")
    candidate = (catalog_root / runner_case).resolve(strict=True)
    try:
        candidate.relative_to(catalog_root)
    except ValueError as exc:
        raise ValueError(f"catalog runner_case escapes its catalog root: {runner_case!r}") from exc
    if not candidate.is_file():
        raise ValueError(f"catalog runner_case is not a regular file: {runner_case!r}")
    return candidate


def catalog_contract(
    path: Path,
) -> tuple[
    dict[str, tuple[int | None, str | None, int | None]],
    dict[Path, str],
]:
    catalog = load_json(path)
    cases = catalog.get("cases")
    if not isinstance(cases, list):
        raise ValueError(f"catalog cases are missing: {path}")
    catalog_root = path.resolve(strict=True).parent
    expectations: dict[str, tuple[int | None, str | None, int | None]] = {}
    runner_case_index: dict[Path, str] = {}
    for case in cases:
        if not isinstance(case, dict) or not case.get("case_id"):
            continue
        case_id = str(case["case_id"])
        expected_status = scalar_int(case.get("expected_status"))
        expected_rule_id = case.get("expected_rule_id")
        expectations[case_id] = (
            expected_status,
            str(expected_rule_id) if expected_rule_id not in (None, "") else None,
            scalar_int(case.get("phase")),
        )
        runner_case = case.get("runner_case")
        if runner_case in (None, ""):
            continue
        runner_path = catalog_runner_case_path(catalog_root, runner_case)
        existing = runner_case_index.get(runner_path)
        if existing is not None:
            raise ValueError(
                f"catalog runner_case is not unique: {runner_case!r} maps to "
                f"both {existing!r} and {case_id!r}"
            )
        runner_case_index[runner_path] = case_id
    return expectations, runner_case_index


def catalog_expectations(path: Path) -> dict[str, tuple[int | None, str | None, int | None]]:
    return catalog_contract(path)[0]


def catalog_case_id_from_row(
    row: dict[str, Any], runner_case_index: dict[Path, str] | None
) -> str | None:
    """Match a host result to one catalog runner_case by exact resolved path."""
    if not runner_case_index:
        return None
    raw_path = row.get("path")
    if not isinstance(raw_path, str) or not raw_path:
        return None
    try:
        candidate = Path(raw_path).resolve(strict=True)
    except OSError:
        return None
    return runner_case_index.get(candidate)


def observed_case_id(
    row: dict[str, Any],
    expectations: dict[str, tuple[Any, ...]],
    runner_case_index: dict[Path, str] | None,
) -> str:
    explicit = str(row.get("case_id") or "")
    from_runner_case = catalog_case_id_from_row(row, runner_case_index)
    if explicit and from_runner_case and explicit != from_runner_case:
        raise ValueError(
            f"source result case_id {explicit!r} conflicts with catalog runner_case "
            f"mapping {from_runner_case!r}"
        )
    if explicit in expectations:
        return explicit
    if from_runner_case is not None:
        return from_runner_case
    return str(row.get("name") or row.get("case") or "")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.is_file():
        return records
    for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if isinstance(value, dict) and 'native_operation_receipt' in value:
            if len(line.encode('utf-8')) > _NATIVE_COLLECTION.SOURCE.MAX_BYTES:
                raise ValueError('native source row exceeds collection bound')
            value = _NATIVE_COLLECTION.SOURCE.decode(line)
        if not isinstance(value, dict):
            raise ValueError(f"JSONL record is not an object: {path}:{number}")
        records.append(value)
    return records


def scalar_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def scalar_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"true", "1"}:
            return True
        if normalized in {"false", "0"}:
            return False
    return None


def record_transaction_ids(record: dict[str, Any]) -> set[str]:
    """Return only explicitly supplied, nonempty transaction identifiers."""
    if record.get("evidence_identity") == "request_bound":
        validate_request_observation(record)
        return set()
    identifiers: set[str] = set()
    values = record.get("transaction_ids")
    if isinstance(values, list):
        identifiers.update(str(value) for value in values if str(value).strip())
    for key in ("transaction_id", "tx_id"):
        value = record.get(key)
        if value not in (None, "") and str(value).strip():
            identifiers.add(str(value))
    if not identifiers:
        value = record.get("request_id")
        if isinstance(value, str) and value:
            identifiers.add(value)
    return identifiers


def parse_key_value_text(path: Path) -> dict[str, Any]:
    values: dict[str, Any] = {}
    if not path.is_file():
        return values
    text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            if re.fullmatch(r"[A-Za-z]\w*", key.strip(), flags=re.ASCII):
                values[key.strip()] = value.strip()
    match = re.search(r"\bPASS\b.*\bbaseline=(\d+)\b.*\bblocked=(\d+)\b", text)
    if match:
        values.setdefault("status", "PASS")
        values.setdefault("allowed_request_status", int(match.group(1)))
        values.setdefault("blocked_request_status", int(match.group(2)))
    return values


def nested_forbidden_key(value: Any) -> str | None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized in FORBIDDEN_EVENT_KEYS:
                return str(key)
            found = nested_forbidden_key(child)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = nested_forbidden_key(child)
            if found:
                return found
    return None


def nested_unapproved_event_key(value: Any) -> str | None:
    """Reject raw event schemas that could hide payload under a new field.

    The canonical event is an allow-listed projection, so silently dropping an
    unknown raw field would make the payload-absence claim impossible to
    establish.  Raw producers must extend this reviewed list deliberately.
    """
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized not in APPROVED_RAW_EVENT_KEYS:
                return str(key)
            found = nested_unapproved_event_key(child)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = nested_unapproved_event_key(child)
            if found:
                return found
    return None


def nested_values(value: Any) -> list[Any]:
    """Flatten structured metadata while preserving every scalar value."""

    if isinstance(value, dict):
        return [item for child in value.values() for item in nested_values(child)]
    if isinstance(value, list):
        return [item for child in value for item in nested_values(child)]
    return [value]


def nested_forbidden_value(value: Any) -> str | None:
    for candidate in nested_values(value):
        if isinstance(candidate, str):
            lowered = candidate.casefold()
            for sentinel in BODY_SENTINELS:
                if sentinel in lowered:
                    return sentinel
    return None


def nonnegative_metadata_integer(value: Any) -> int | None:
    numeric = scalar_int(value)
    return numeric if numeric is not None and numeric >= 0 else None


def phase_metadata_value(value: Any) -> int | str | None:
    numeric = scalar_int(value)
    if numeric is not None:
        return numeric
    if not isinstance(value, str):
        return None
    normalized = value.strip().casefold().replace("-", "_")
    if normalized in PHASE_ALIASES:
        return PHASE_ALIASES[normalized]
    return value if re.fullmatch(r"[A-Za-z0-9_-]{1,32}", value) else None


def normalized_metadata_enum(value: Any, allowed: set[str], *, aliases: Mapping[str, str] | None = None) -> str | None:
    normalized = str(value).strip().casefold().replace("-", "_")
    if aliases is not None:
        normalized = aliases.get(normalized, normalized)
    return normalized if normalized in allowed else None


def metadata_token(value: Any, target: str) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > MAX_METADATA_LENGTH.get(target, 128):
        return None
    return text if re.fullmatch(r"[A-Za-z0-9:._-]+", text) else None


_UNHANDLED_METADATA_VALUE = object()


def requested_action_metadata_value(value: Any) -> str | None:
    return normalized_metadata_enum(
        value, REQUESTED_ACTIONS, aliases={"connection_abort": "abort_connection"}
    )


def actual_action_metadata_value(value: Any) -> str | None:
    return normalized_metadata_enum(
        value, ACTUAL_ACTIONS, aliases={"connection_abort": "abort_connection"}
    )


def transport_result_metadata_value(value: Any) -> str | None:
    return normalized_metadata_enum(
        value,
        TRANSPORT_RESULTS,
        aliases={"connection_abort": "connection_aborted"},
    )


def protocol_metadata_value(value: Any) -> str | None:
    return normalized_metadata_enum(
        value, CANONICAL_PROTOCOLS, aliases={"http2": "h2"}
    )


def transport_metadata_value(value: Any) -> str | None:
    return normalized_metadata_enum(value, CANONICAL_TRANSPORTS)


def late_intervention_mode_metadata_value(value: Any) -> str | None:
    return normalized_metadata_enum(value, {"off", "safe", "strict"})


_KNOWN_METADATA_NORMALIZERS = (
    (INTEGER_METADATA_FIELDS, scalar_int),
    (NONNEGATIVE_INTEGER_METADATA_FIELDS, nonnegative_metadata_integer),
    ({"phase"}, phase_metadata_value),
    (BOOLEAN_METADATA_FIELDS, scalar_bool),
    ({"requested_action"}, requested_action_metadata_value),
    ({"actual_action"}, actual_action_metadata_value),
    ({"transport_result"}, transport_result_metadata_value),
    (
        {
            "protocol",
            "requested_protocol",
            "downstream_protocol",
            "upstream_protocol",
            "negotiated_protocol",
        },
        protocol_metadata_value,
    ),
    ({"transport"}, transport_metadata_value),
    ({"late_intervention_mode"}, late_intervention_mode_metadata_value),
)


def known_metadata_value(target: str, value: Any) -> Any:
    for fields, normalizer in _KNOWN_METADATA_NORMALIZERS:
        if target in fields:
            return normalizer(value)
    if target in TRANSPORT_TOKEN_FIELDS:
        return metadata_token(value, target)
    return _UNHANDLED_METADATA_VALUE


def sanitized_metadata_text(target: str, value: Any) -> str | None:
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        return None
    text = "".join(character for character in str(value) if character >= " " and character != "\x7f")
    return text[: MAX_METADATA_LENGTH.get(target, 256)] or None


def safe_metadata_value(target: str, value: Any) -> Any | None:
    normalized = known_metadata_value(target, value)
    if normalized is not _UNHANDLED_METADATA_VALUE:
        return normalized
    return sanitized_metadata_text(target, value)


def sanitized_event(record: dict[str, Any]) -> dict[str, Any]:
    """Keep only the metadata allow-list accepted by canonical evidence."""
    output: dict[str, Any] = {}
    aliases = {
        "connector": ("connector",),
        "integration_mode": ("integration_mode",),
        "event": ("event",),
        "message_id": ("message_id",),
        "transaction_id": ("transaction_id", "request_id", "tx_id"),
        "rule_id": ("rule_id", "modsecurity_rule_id"),
        "phase": ("phase",),
        "status": ("status", "decision", "result"),
        "http_status": ("http_status", "waf_status", "intervention_status"),
        "original_http_status": ("original_http_status", "upstream_status"),
        "visible_http_status": ("visible_http_status", "client_status"),
        "requested_action": ("requested_action", "wanted_action"),
        "actual_action": ("actual_action",),
        "late_intervention": ("late_intervention", "intervention"),
        "late_intervention_mode": ("late_intervention_mode",),
        "headers_sent": ("headers_sent", "header_sent"),
        "body_started": ("body_started", "response_body_seen"),
        "connection_aborted": ("connection_aborted", "strict_abort"),
        "response_committed": ("response_committed",),
        "transport_result": ("transport_result", "observed_transport_result"),
        "transport_case_id": ("transport_case_id",),
        "barrier_id": ("barrier_id",),
        "requested_protocol": ("requested_protocol",),
        "downstream_protocol": ("downstream_protocol",),
        "upstream_protocol": ("upstream_protocol",),
        "negotiated_protocol": ("negotiated_protocol",),
        "transport": ("transport",),
        "alpn": ("alpn",),
        "stream_id": ("stream_id",),
        "connection_id": ("connection_id",),
        "connection_reused": ("connection_reused",),
        "quic_connection_id_present": ("quic_connection_id_present",),
        "quic_version": ("quic_version",),
        "fallback_used": ("fallback_used",),
        "stream_reset": ("stream_reset",),
        "stream_reset_code": ("stream_reset_code",),
        "reset_by": ("reset_by",),
        "reset_code": ("reset_code",),
        "client_disconnected": ("client_disconnected",),
        "upstream_disconnected": ("upstream_disconnected",),
        "cancelled": ("cancelled",),
        "timeout_stage": ("timeout_stage",),
        "write_result": ("write_result",),
        "cleanup_reason": ("cleanup_reason",),
        "eos_seen": ("eos_seen",),
        "end_of_stream_evaluation": ("end_of_stream_evaluation",),
        "client_result": ("client_result",),
        "host_survived": ("host_survived",),
        "followup_request_result": ("followup_request_result",),
        "transaction_started": ("transaction_started",),
        "transaction_finished": ("transaction_finished",),
        "transaction_destroyed": ("transaction_destroyed",),
        "request_body_finished": ("request_body_finished",),
        "response_body_finished": ("response_body_finished",),
        "intentional_abort": ("intentional_abort",),
        "client_disconnect": ("client_disconnect",),
        "upstream_disconnect": ("upstream_disconnect",),
        "timeout": ("timeout",),
        "short_writes": ("short_writes",),
        "write_would_block": ("write_would_block",),
        "run_id": ("run_id",),
        "body_bytes_seen": ("body_bytes_seen",),
        "body_bytes_inspected": ("body_bytes_inspected",),
        "client_first_byte_received": ("client_first_byte_received",),
        "first_chunk_size": ("first_chunk_size",),
        "upstream_paused": ("upstream_paused",),
        "upstream_eos_sent_at_first_byte": ("upstream_eos_sent_at_first_byte",),
        "first_byte_before_response_end": ("first_byte_before_response_end",),
        "upstream_response_finished_at_first_byte": (
            "upstream_response_finished_at_first_byte",
            "upstream_response_complete_at_first_byte",
        ),
        "no_full_response_buffering": ("no_full_response_buffering",),
        "truncated": ("truncated", "event_truncated"),
        "content_type": ("content_type",),
    }
    for target, names in aliases.items():
        for name in names:
            value = record.get(name)
            if value not in (None, ""):
                safe_value = safe_metadata_value(target, value)
                if safe_value is not None:
                    output[target] = safe_value
                    break
    return output


def contained_source_event_path(path: Path, allowed_root: Path) -> Path:
    """Return an absolute source-event path only when it is run-local.

    Native harness summaries contain paths to audit and decision logs.  Those
    paths are evidence inputs, so accepting a path from another run would let
    stale metadata satisfy the current run.  Reject symlinks as well as lexical
    and resolved escapes before reading or removing the file.
    """

    if not path.is_absolute():
        raise ValueError(f"source event path must be absolute: {path}")
    root = Path(os.path.abspath(allowed_root))
    candidate = Path(os.path.abspath(path))
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"source event path is outside the allowed run root: {candidate}"
        ) from exc

    current = Path(candidate.anchor)
    for component in candidate.parts[1:]:
        current /= component
        if current.is_symlink():
            raise ValueError(f"source event path contains a symlink: {current}")
        if not current.exists():
            break

    resolved_root = root.resolve(strict=True)
    resolved_candidate = candidate.resolve(strict=False)
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(
            f"resolved source event path is outside the allowed run root: {candidate}"
        ) from exc
    return candidate


def scrub_source_event_paths(
    paths: list[Path],
    allowed_root: Path,
    log_path: Path | None = None,
    log_root: Path | None = None,
) -> list[Path]:
    removed: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        candidate = contained_source_event_path(path, allowed_root)
        if candidate in seen:
            continue
        seen.add(candidate)
        if unlink_contained_source_event(candidate, allowed_root):
            removed.append(candidate)
    if log_path is not None:
        lines = [f"removed_after_allowlist_normalization={path}" for path in removed]
        write_runtime_artifact_text_atomic(
            log_root or allowed_root,
            log_path,
            "\n".join(lines or ["not_produced"]) + "\n",
            "source event scrub log",
        )
    return removed


def unlink_contained_source_event(candidate: Path, allowed_root: Path) -> bool:
    """Remove one regular run-local source event through no-follow descriptors."""

    target = runtime_artifact_path(
        allowed_root,
        candidate,
        "source event",
        must_exist=True,
    )
    parent_descriptor = open_runtime_artifact_parent(target)
    try:
        try:
            target_stat = os.stat(
                target.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return False
        if not stat.S_ISREG(target_stat.st_mode):
            return False
        os.unlink(target.name, dir_fd=parent_descriptor)
        return True
    finally:
        os.close(parent_descriptor)


def audit_event(path: Path, connector: str, http_status: int | None,
                transaction_ids: set[str] | None = None) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    # Native audit message lines bind the rule and unique ID together. Never
    # combine the last rule in a file with another line's transaction or phase.
    candidates = []
    for line in text.splitlines():
        rules = re.findall(r'\[id "(\d+)"\]', line)
        transactions = re.findall(r'\[unique_id "([^"\r\n]{1,256})"\]', line)
        if len(rules) != 1 or len(transactions) != 1:
            continue
        if transaction_ids is not None and transactions[0] not in transaction_ids:
            continue
        phase_match = re.search(r"\(phase\s+(\d+)\)", line, re.IGNORECASE)
        candidates.append((rules[0], transactions[0], int(phase_match.group(1)) if phase_match else 1))
    if not candidates or len({value[1] for value in candidates}) != 1:
        return None
    rule, transaction, phase = candidates[-1]
    event: dict[str, Any] = {
        "connector": connector,
        "rule_id": int(rule),
        "phase": phase,
        "status": "blocked" if http_status and http_status >= 400 else "allowed",
    }
    event["transaction_id"] = transaction
    if http_status is not None:
        event["http_status"] = http_status
    return event


def runtime_event_records(
    path_value: Any,
    allowed_source_root: Path | None,
    consumed_event_paths: list[Path] | None,
) -> list[dict[str, Any]]:
    """Read an explicitly referenced runtime event stream without widening scope."""
    text = str(path_value or "")
    if not text:
        return []
    path = Path(text)
    if allowed_source_root is not None:
        path = contained_source_event_path(path, allowed_source_root)
    if not path.is_file():
        return []
    if consumed_event_paths is not None:
        consumed_event_paths.append(path)
    return load_jsonl(path)


def first_byte_evidence_record(
    path_value: Any,
    allowed_source_root: Path | None,
) -> dict[str, Any] | None:
    """Read a real-host barrier record without treating it as an event stream.

    The evidence is merged only into an actual Phase-4 event emitted by the
    selected host.  This prevents a direct/synthetic helper invocation from
    manufacturing a Phase-4 rule observation.
    """
    text = str(path_value or "")
    if not text:
        return None
    path = Path(text)
    if allowed_source_root is not None:
        path = contained_source_event_path(path, allowed_source_root)
    if not path.is_file():
        return None
    try:
        value = load_json(path)
    except (OSError, ValueError):
        return None
    if not first_byte_evidence_identity_is_valid(value):
        return None
    if not first_byte_evidence_contract_is_valid(value):
        return None
    if not normalize_first_byte_counters(value):
        return None
    return value


def first_byte_evidence_identity_is_valid(value: dict[str, Any]) -> bool:
    """Require a promotable real-host barrier record before reading its fields."""

    return (
        value.get("evidence_type") == "synchronized_first_byte"
        and value.get("evidence_origin") == "real_host"
        and value.get("promotion_eligible") is True
        and value.get("outcome") == "PASS"
        and value.get("body_payload_persisted") is False
    )


def first_byte_evidence_contract_is_valid(value: dict[str, Any]) -> bool:
    """Check required barrier fields and their exact causal Boolean states."""

    return all(name in value for name in FIRST_BYTE_REQUIRED_FIELDS) and all(
        value.get(name) is expected
        for name, expected in FIRST_BYTE_REQUIRED_BOOLS.items()
    )


def normalize_first_byte_counters(value: dict[str, Any]) -> bool:
    """Normalize nonnegative counters and retain their order invariant."""

    counters = {
        name: scalar_int(value.get(name))
        for name in FIRST_BYTE_COUNTER_FIELDS
    }
    if any(number is None or number < 0 for number in counters.values()):
        return False
    value.update(counters)
    return (
        value["first_chunk_size"] >= 1
        and value["body_bytes_inspected"] <= value["body_bytes_seen"]
    )


def merge_first_byte_evidence(
    records: list[dict[str, Any]], evidence: dict[str, Any] | None,
    binding: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Attach bounded causal metadata only to observed Phase-4 host events."""
    if evidence is None:
        return records
    if binding is not None:
        matches = [record for record in records
                   if record.get("transaction_id") == binding.get("transaction_id")
                   and event_digest(record) == binding.get("event_sha256")]
        if len(matches) != 1:
            raise ValueError("first-byte append identity is missing or ambiguous")
    fields = (
        "client_first_byte_received",
        "first_byte_before_response_end",
        "first_chunk_size",
        "upstream_paused",
        "upstream_eos_sent_at_first_byte",
        "upstream_response_finished_at_first_byte",
        "response_committed",
        "body_bytes_seen",
        "body_bytes_inspected",
        "no_full_response_buffering",
    )
    merged: list[dict[str, Any]] = []
    for record in records:
        candidate = dict(record)
        phase = safe_metadata_value("phase", candidate.get("phase"))
        matches_binding = binding is None or (
            record.get("transaction_id") == binding.get("transaction_id")
            and event_digest(record) == binding.get("event_sha256")
        )
        if phase == 4 and matches_binding:
            merge_first_byte_fields(candidate, evidence, fields)
        merged.append(candidate)
    return merged


def merge_first_byte_fields(
    candidate: dict[str, Any], evidence: dict[str, Any], fields: tuple[str, ...]
) -> None:
    """Merge authoritative barrier fields without hiding host-counter conflicts."""

    for field in fields:
        if first_byte_counter_conflicts(candidate, evidence, field):
            candidate["first_byte_evidence_counter_mismatch"] = True
            continue
        candidate[field] = evidence[field]


def first_byte_counter_conflicts(
    candidate: dict[str, Any], evidence: dict[str, Any], field: str
) -> bool:
    """Return whether a producer counter disagrees with barrier evidence."""

    if field not in {"body_bytes_seen", "body_bytes_inspected"} or field not in candidate:
        return False
    existing = scalar_int(candidate.get(field))
    return existing is not None and existing != evidence[field]


def observed_technical_failure(record: dict[str, Any]) -> bool:
    """Identify an explicit runtime fault without inventing outcome fields."""
    return record.get("status") == "error" or record.get("transport_result") in {
        "engine_error", "host_error", "timeout", "short_write", "upstream_reset",
    }


def canonical_semantics(
    records: list[dict[str, Any]],
    expected_rule_id: str | None = None,
    expected_phase: int | None = None,
) -> dict[str, Any]:
    """Project only producer-observed Phase-4 metadata.

    This intentionally does not fill defaults.  A missing runtime value must
    remain missing so the framework can fail a claimed semantic case instead
    of manufacturing evidence from its catalog or capability manifest.
    """
    fields = {
        "http_status",
        "original_http_status",
        "visible_http_status",
        "requested_action",
        "actual_action",
        "late_intervention",
        "late_intervention_mode",
        "headers_sent",
        "body_started",
        "connection_aborted",
        "response_committed",
        "transport_result",
        "body_bytes_seen",
        "body_bytes_inspected",
        "client_first_byte_received",
        "first_chunk_size",
        "upstream_paused",
        "upstream_eos_sent_at_first_byte",
        "first_byte_before_response_end",
        "upstream_response_finished_at_first_byte",
        "no_full_response_buffering",
    }
    normalized_records = [sanitized_event(record) for record in records]
    identities = set().union(*(record_transaction_ids(record) for record in records))
    if len(identities) > 1:
        return {}
    output: dict[str, Any] = {}
    for normalized in normalized_records:
        for field in fields:
            if field in normalized:
                output[field] = normalized[field]
    # Completion/cleanup events describe lifecycle state, not the earlier
    # decision or the Host action. Preserve a single evidenced intervention;
    # never assemble that decision from unrelated rule/phase observations.
    decision_fields = fields - {
        "body_bytes_seen", "body_bytes_inspected", "client_first_byte_received",
        "first_chunk_size", "upstream_paused", "upstream_eos_sent_at_first_byte",
        "first_byte_before_response_end", "upstream_response_finished_at_first_byte",
        "no_full_response_buffering",
    }
    if not restore_intervention_decision(
            output, normalized_records, decision_fields, expected_rule_id, expected_phase):
        return {}
    # A genuine subsequent technical fault remains authoritative. This is not
    # a general last-event rule; retain the first evidenced technical failure.
    for record in normalized_records:
        if observed_technical_failure(record):
            output.update({key: value for key, value in record.items() if key in fields})
            break
    snapshots = [record for record in normalized_records
                 if record.get("client_first_byte_received") is True]
    if len(snapshots) == 1:
        snapshot_fields = fields - decision_fields
        output.update({key: value for key, value in snapshots[0].items() if key in snapshot_fields})
    return output


def restore_intervention_decision(
    output: dict[str, Any], records: list[dict[str, Any]], decision_fields: set[str],
    expected_rule_id: str | None, expected_phase: int | None,
) -> bool:
    """Restore one matching decision, rejecting contradictory observations."""
    interventions = [
        record for record in records
        if record.get("event") in {"phase3_intervention", "phase4_intervention"}
        and (expected_rule_id is None or str(record.get("rule_id")) == expected_rule_id)
        and (expected_phase is None or record.get("phase") == expected_phase)
    ]
    if any(record.get("event") in {"phase3_intervention", "phase4_intervention"}
           for record in records):
        for key in decision_fields:
            output.pop(key, None)
    if interventions:
        decisions = [{key: value for key, value in record.items() if key in decision_fields}
                     for record in interventions]
        if any(decision != decisions[0] for decision in decisions[1:]):
            return False
        output.update(decisions[0])
    return True


def native_runner_core_case_alias(
    connector: str,
    case_id: str,
    records: list[dict[str, Any]],
) -> str | None:
    """Return a compact core alias only for an evidenced native runner case.

    The Apache/NGINX harnesses deliberately keep their full-lifecycle fixture
    names.  Reusing an outcome under a core catalog ID is safe only when a
    single raw host event already proves the stricter target contract.  This
    keeps the collector from turning a fixture name or a bare HTTP status into
    lifecycle evidence.
    """
    target = NATIVE_RUNNER_CORE_CASE_ALIASES.get(connector, {}).get(case_id)
    if target is None:
        return None
    if case_id == "phase3_deny_before_commit":
        required = {
            "phase": 3,
            "rule_id": 1100201,
            "requested_action": "deny",
            "actual_action": "deny",
            "headers_sent": False,
            "visible_http_status": 403,
            "late_intervention": False,
            "transport_result": "http_status",
        }
    elif case_id == "phase4_deny_after_commit_log_only":
        required = {
            "phase": 4,
            "rule_id": 1100301,
            "requested_action": "deny",
            "actual_action": "log_only",
            "late_intervention": True,
            "late_intervention_mode": "safe",
            "headers_sent": True,
            "body_started": True,
            "response_committed": True,
            "connection_aborted": False,
            "http_status": 403,
            "original_http_status": 200,
            "visible_http_status": 200,
            "transport_result": "log_only",
        }
    else:
        return None
    # Native Apache/NGINX writers publish Common's closed phase names and
    # decimal rule IDs as JSON strings.  Normalize each producer record here
    # as well as in the caller, so this narrow alias cannot depend on its
    # invocation path or weaken a semantic requirement through type coercion.
    for record in records:
        normalized = sanitized_event(record)
        if all(normalized.get(field) == value for field, value in required.items()):
            return target
    return None


def event_evidence(
    paths: list[Path], expected_rule_id: str, derived_records: list[dict[str, Any]]
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    invalid: list[str] = []
    forbidden: list[str] = []
    seen_records: set[str] = set()
    for index, record in enumerate(derived_records):
        add_validated_event_record(
            records, seen_records, forbidden, record, f"derived-event:{index + 1}"
        )
    for path in paths:
        try:
            for index, record in enumerate(load_jsonl(path)):
                add_validated_event_record(
                    records, seen_records, forbidden, record, f"{path}:{index + 1}"
                )
        except (OSError, ValueError) as exc:
            invalid.append(f"{path}: {exc}")
    return event_evidence_payload(records, expected_rule_id, invalid, forbidden)


def event_record_violation(record: dict[str, Any], label: str) -> str | None:
    """Return a stable label for forbidden or unreviewed raw event content."""

    forbidden_key = nested_forbidden_key(record)
    if forbidden_key:
        return f"{label}:{forbidden_key}"
    unapproved_key = nested_unapproved_event_key(record)
    if unapproved_key:
        return f"{label}:unapproved-field:{unapproved_key}"
    if nested_forbidden_value(record):
        return f"{label}:payload-sentinel"
    return None


def add_validated_event_record(
    records: list[dict[str, Any]],
    seen_records: set[str],
    forbidden: list[str],
    record: dict[str, Any],
    label: str,
) -> None:
    """Append one unique reviewed event or retain its rejection evidence."""

    violation = event_record_violation(record, label)
    if violation:
        forbidden.append(violation)
        return
    normalized = sanitized_event(record)
    serialized = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    if serialized not in seen_records:
        seen_records.add(serialized)
        records.append(normalized)


def event_evidence_summary(records: list[dict[str, Any]]) -> tuple[set[str], set[str], bool, bool, bool]:
    """Summarize required identity fields from canonical event projections."""

    observed_rule_ids = {
        str(record["rule_id"])
        for record in records
        if record.get("rule_id") not in (None, "")
    }
    transaction_ids = {
        str(record["transaction_id"])
        for record in records
        if record.get("transaction_id") not in (None, "")
    }
    return (
        observed_rule_ids,
        transaction_ids,
        any(bool(record.get("connector")) for record in records),
        any(record.get("phase") not in (None, "") for record in records),
        any(record.get("status") not in (None, "") for record in records),
    )


def event_evidence_payload(
    raw_records: list[dict[str, Any]],
    expected_rule_id: str,
    invalid: list[str],
    forbidden: list[str],
) -> dict[str, Any]:
    """Build the canonical event-evidence contract after source validation."""

    records = [record for record in raw_records if record]
    rule_ids, transaction_ids, connector_seen, phase_seen, status_seen = event_evidence_summary(records)
    metadata_verified = bool(
        records
        and connector_seen
        and transaction_ids
        and expected_rule_id in rule_ids
        and phase_seen
        and status_seen
        and not invalid
        and not forbidden
    )
    return {
        "body_payload_absent_from_events": bool(records) and not forbidden and not invalid,
        "event_metadata_verified": metadata_verified,
        "event_records": len(records),
        "event_validation_errors": invalid,
        "forbidden_event_keys": sorted(set(forbidden)),
        "observed_rule_ids": sorted(rule_ids),
        "transaction_ids": sorted(transaction_ids),
        "records": records,
    }


def row_log_path(
    row: dict[str, Any],
    names: tuple[str, ...],
    allowed_source_root: Path | None,
    consumed_event_paths: list[Path] | None,
) -> Path | None:
    """Read one declared run-local log location and account for its consumption."""

    text = next((str(row.get(name) or "") for name in names if row.get(name)), "")
    if not text:
        return None
    path = Path(text)
    if allowed_source_root is not None:
        path = contained_source_event_path(path, allowed_source_root)
    if path.is_file() and consumed_event_paths is not None:
        consumed_event_paths.append(path)
    return path


def _validate_row_runtime_record_identities(row, records):
    for record in records:
        for field in ("run_id", "case_id", "request_id", "source_revision"):
            if row.get(field) and field in record and record[field] != row[field]:
                raise ValueError(f"source/event identity mismatch: {field}")


def row_runtime_records(
    row: dict[str, Any],
    decision_path: Path | None,
    allowed_source_root: Path | None,
    consumed_event_paths: list[Path] | None,
    connector: str | None = None,
) -> list[dict[str, Any]]:
    """Collect raw producer events, preserving transaction and barrier binding."""

    if row.get("evidence_identity") == "request_bound":
        validate_request_observation(row)
        return []
    records = load_jsonl(decision_path) if decision_path and decision_path.is_file() else []
    for name in ("connector_phase4_log_path", "phase4_log_path"):
        records.extend(runtime_event_records(row.get(name), allowed_source_root, consumed_event_paths))
    transaction_ids = record_transaction_ids(row)
    # No source identity means no permission to borrow a shared log's events.
    # Client observations remain visible, but cannot manufacture a transaction.
    records = [record for record in records
               if transaction_ids and transaction_ids.intersection(record_transaction_ids(record))]
    _validate_row_runtime_record_identities(row, records)
    evidence = first_byte_evidence_record(row.get("first_byte_evidence_path"), allowed_source_root)
    binding = None
    if connector == "nginx" and row.get("first_byte_evidence_path"):
        if evidence is None:
            raise ValueError("NGINX first-byte snapshot does not satisfy the real-host contract")
        if allowed_source_root is None:
            raise ValueError("NGINX first-byte binding requires an authorized source root")
        binding_path = contained_source_event_path(Path(str(row.get("first_byte_binding_path") or "")), allowed_source_root)
        binding = load_json(binding_path)
        log_path = contained_source_event_path(Path(str(row["connector_phase4_log_path"])), allowed_source_root)
        evidence_path = contained_source_event_path(Path(str(row["first_byte_evidence_path"])), allowed_source_root)
        if binding_path != Path(str(evidence_path) + ".binding.json"):
            raise ValueError("first-byte binding belongs to another snapshot invocation")
        verify_binding(binding, log_path, evidence_path, allowed_source_root)
    return merge_first_byte_evidence(records, evidence, binding)


def row_rule_ids(row: dict[str, Any], runtime_records: list[dict[str, Any]]) -> set[str]:
    """Gather rule IDs from declared row metadata and validated raw records."""

    raw_rule_ids = row.get("observed_rule_ids")
    identifiers = set(map(str, raw_rule_ids)) if isinstance(raw_rule_ids, list) else set()
    identifiers.update(
        str(row[name])
        for name in ("rule_id", "modsecurity_rule_id")
        if row.get(name) not in (None, "")
    )
    identifiers.update(
        str(event["rule_id"])
        for event in (sanitized_event(record) for record in runtime_records)
        if event.get("rule_id") not in (None, "")
    )
    return identifiers


def expected_case_values(expectation: tuple[Any, ...]) -> tuple[int | None, str | None, int | None]:
    """Normalize a catalog expectation without filling missing evidence."""

    expected_status = scalar_int(expectation[0]) if expectation else None
    expected_rule_id = (
        str(expectation[1])
        if len(expectation) > 1 and expectation[1] not in (None, "")
        else None
    )
    expected_phase = scalar_int(expectation[2]) if len(expectation) > 2 else None
    return expected_status, expected_rule_id, expected_phase


def case_status_value(status: str) -> str | None:
    """Preserve non-execution states instead of recasting them as failures."""

    if status in {"NOT_EXECUTABLE", "SKIPPED"}:
        return "NOT_EXECUTED"
    return status if status in {"BLOCKED", "UNSUPPORTED", "NOT_APPLICABLE", "NOT_EXECUTED"} else None


def case_passes(
    status: str,
    live: bool,
    actual: int | None,
    expected_status: int | None,
    expected_rule_id: str | None,
    expected_phase: int | None,
    case_id: str,
    observed_rule_ids: set[str],
    records: list[dict[str, Any]],
) -> bool:
    """Evaluate one case only against its observed status, rule, and phase evidence."""

    phase4_case = expected_phase == 4 or case_id.startswith("phase4_")
    structured_runtime_case = expected_phase in {3, 4}
    status_matches = phase4_case or expected_status is None or actual == expected_status
    rule_matches = expected_rule_id is None or expected_rule_id in observed_rule_ids
    phase_matches = not structured_runtime_case or any(
        record.get("phase") == expected_phase for record in records
    )
    normal_outcome_case = case_id in {
        "phase3_deny_before_commit", "phase3_redirect_before_commit",
        "phase4_deny_after_commit_log_only", "phase4_deny_after_commit_abort",
        "phase4_deny_after_commit_log_only_safe", "phase4_rule_observed",
        "phase4_no_full_response_buffering", "phase4_first_byte_before_response_end",
    }
    return (
        status == "PASS" and live and status_matches and rule_matches and phase_matches
        and not (normal_outcome_case and any(observed_technical_failure(record) for record in records))
    )


def default_case_expectations(expected_rule_id: str) -> dict[str, tuple[int, str | None]]:
    return {
        case_id: (status, expected_rule_id if case_id == "deny_header_marker_403" else None)
        for case_id, status in CORE_CASES.items()
    }


def source_case_rows(paths: list[Path]) -> list[dict[str, Any]]:
    return [row for path in paths for row in load_jsonl(path)]


def audit_fallback_events(
    case_id: str,
    expected_phase: int | None,
    canonical_records: list[dict[str, Any]],
    audit_path: Path | None,
    connector: str,
    actual: int | None,
    transaction_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Use an audit event only where it cannot compete with a native event.

    An audit log can corroborate older request-path cases only when the host
    supplied no structured event at all. Once a native writer has published a
    raw event, an audit-derived duplicate would lose the selected integration
    mode and let weaker evidence compete with causal host evidence. Phase-4
    cases always require their structured producer event for the same reason.
    """

    phase4_case = expected_phase == 4 or case_id.startswith("phase4_")
    if phase4_case or canonical_records or audit_path is None or not transaction_ids:
        return []
    event = audit_event(audit_path, connector, actual, transaction_ids)
    return [event] if event else []


def event_metadata_is_verified(
    canonical_records: list[dict[str, Any]],
    transaction_ids: set[str],
    expected_rule_id: str | None,
    observed_rule_ids: set[str],
    expected_phase: int | None,
) -> bool:
    structured_runtime_case = expected_phase in {3, 4}
    phase_matches = any(
        record.get("phase") == expected_phase for record in canonical_records
    )
    return bool(
        canonical_records
        and transaction_ids
        and expected_rule_id is not None
        and expected_rule_id in observed_rule_ids
        and (not structured_runtime_case or phase_matches)
    )


def case_observation_payload(
    row: dict[str, Any],
    case_id: str,
    actual: int | None,
    expected_status: int | None,
    expected_rule_id: str | None,
    expected_phase: int | None,
    status: str,
    live: bool,
    observed_rule_ids: set[str],
    canonical_records: list[dict[str, Any]],
    runtime_records: list[dict[str, Any]],
    allowed_source_root: Path | None = None,
) -> dict[str, Any]:
    if row.get("evidence_identity") == "request_bound":
        identity = validate_request_observation(row)
        if case_id != identity["case_id"] or actual != row["actual_status"] or not live:
            raise ValueError("client request observation cannot change its case or observed response")
        return {**identity, "actual_status": actual, "visible_http_status": actual,
                "expected_status": expected_status, "live_executed": True,
                "source_status": status, "status": "PASS" if status == "PASS" else "FAIL",
                "observed_rule_ids": [], "transaction_id": None, "transaction_ids": [],
                "observed_event_fields": [], "event_metadata_verified": False,
                "evidence_identity": "request_bound", "runtime_verified": False,
                "promotion_allowed": False, "request_observation": dict(row["request_observation"])}
    transaction_ids = {
        str(record["transaction_id"])
        for record in canonical_records
        if record.get("transaction_id") not in (None, "")
    }
    observed_event_fields = sorted({field for record in canonical_records for field in record})
    event_metadata_verified = event_metadata_is_verified(
        canonical_records,
        transaction_ids,
        expected_rule_id,
        observed_rule_ids,
        expected_phase,
    )
    identity = {field: row.get(field) for field in RESULT_BINDING_FIELDS}
    identity["case_id"] = case_id
    try:
        bound = validate_result_binding(identity)
        identity_verified = all(field in row for field in RESULT_BINDING_FIELDS)
    except ValueError:
        bound = {field: value for field, value in identity.items()
                 if isinstance(value, str) and value}
        identity_verified = False
    return {
        "case_id": case_id,
        "actual_status": actual,
        "expected_status": expected_status,
        "live_executed": live,
        "observed_rule_ids": sorted(observed_rule_ids),
        "transaction_ids": sorted(transaction_ids),
        "observed_event_fields": observed_event_fields,
        "event_metadata_verified": event_metadata_verified,
        "source_status": status,
        "status": case_status_value(status)
        or (
            "PASS"
            if case_passes(
                status,
                live,
                actual,
                expected_status,
                expected_rule_id,
                expected_phase,
                case_id,
                observed_rule_ids,
                canonical_records,
            )
            else "FAIL"
        ),
        **canonical_semantics([row, *runtime_records], expected_rule_id, expected_phase),
        **configtest_source_fields(row, expected_phase, allowed_source_root),
        **bound,
        "evidence_identity": "bound" if identity_verified else "unbound",
        "promotion_allowed": identity_verified and row.get("promotion_allowed") is not False,
    }


def case_alias_observations(
    connector: str,
    case_id: str,
    canonical_records: list[dict[str, Any]],
    expectations: dict[str, tuple[Any, ...]],
    observation: dict[str, Any],
) -> list[dict[str, Any]]:
    alias_case_id = native_runner_core_case_alias(
        connector, case_id, canonical_records
    )
    if (
        alias_case_id is None
        or alias_case_id not in expectations
        or observation["status"] != "PASS"
    ):
        return []
    alias = dict(observation)
    alias["case_id"] = alias_case_id
    alias["reason"] = (
        f"reused native {connector} event from {case_id} for compact core evidence"
    )
    return [alias]


def case_row_observations(
    row: dict[str, Any],
    connector: str,
    expectations: dict[str, tuple[Any, ...]],
    allowed_source_root: Path | None,
    consumed_event_paths: list[Path] | None,
    runner_case_index: dict[Path, str] | None,
    allowed_native_operation_root: Path | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if row.get("evidence_identity") == "request_bound":
        validate_request_observation(row)
    if 'native_operation_receipt' in row:
        return [_NATIVE_COLLECTION.collect_native_row(
            row, connector, expectations, allowed_native_operation_root)], []
    case_id = observed_case_id(row, expectations, runner_case_index)
    if case_id not in expectations:
        return [], []
    decision_path = row_log_path(
        row, ("decision_log_path", "decision_log"), allowed_source_root, consumed_event_paths
    )
    audit_path = row_log_path(
        row, ("audit_log_path",), allowed_source_root, consumed_event_paths
    )
    expected_status, expected_rule_id, expected_phase = expected_case_values(
        expectations[case_id]
    )
    actual = scalar_int(row.get("actual_status", row.get("observed_status")))
    status = str(row.get("status") or row.get("result") or "").upper()
    live = row.get("live_executed", True) is not False
    runtime_records = row_runtime_records(
        row, decision_path, allowed_source_root, consumed_event_paths, connector
    )
    observed_rule_ids = row_rule_ids(row, runtime_records)
    canonical_records = [sanitized_event(record) for record in runtime_records]
    fallback_events = audit_fallback_events(
        case_id,
        expected_phase,
        canonical_records,
        audit_path,
        connector,
        actual,
        record_transaction_ids(row),
    )
    observed_rule_ids.update(str(event["rule_id"]) for event in fallback_events)
    observation = case_observation_payload(
        row,
        case_id,
        actual,
        expected_status,
        expected_rule_id,
        expected_phase,
        status,
        live,
        observed_rule_ids,
        canonical_records,
        runtime_records,
        allowed_source_root,
    )
    aliases = case_alias_observations(
        connector, case_id, canonical_records, expectations, observation
    )
    return [observation, *aliases], [*runtime_records, *fallback_events]


def case_observations(
    paths: list[Path],
    connector: str,
    expected_rule_id: str,
    expectations: dict[str, tuple[Any, ...]] | None = None,
    allowed_source_root: Path | None = None,
    consumed_event_paths: list[Path] | None = None,
    runner_case_index: dict[Path, str] | None = None,
    allowed_native_operation_root: Path | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    expectations = expectations or default_case_expectations(expected_rule_id)
    observations: list[dict[str, Any]] = []
    derived_events: list[dict[str, Any]] = []
    native_case_ids: set[str] = set()
    seen_case_ids: set[str] = set()
    for row in source_case_rows(paths):
        row_case_id = observed_case_id(row, expectations, runner_case_index)
        if row_case_id in native_case_ids:
            raise ValueError('duplicate native source case identity')
        if 'native_operation_receipt' in row:
            native_case_id = row.get('case_id')
            if not isinstance(native_case_id, str) or native_case_id in seen_case_ids:
                raise ValueError('duplicate or invalid native source case identity')
            native_case_ids.add(native_case_id)
        seen_case_ids.add(row_case_id)
        row_observations, row_events = case_row_observations(
            row,
            connector,
            expectations,
            allowed_source_root,
            consumed_event_paths,
            runner_case_index,
            allowed_native_operation_root,
        )
        observations.extend(row_observations)
        derived_events.extend(row_events)
    return observations, derived_events


def only_nonexecuted_cases(cases: list[dict[str, Any]]) -> bool:
    """Return whether a host reported cases but none as a runtime failure.

    Connector harnesses use their historical ``NOT_EXECUTABLE`` spelling for
    an intentionally unimplemented protocol dispatch. Canonical evidence
    normalizes it to ``NOT_EXECUTED``: it is not a host crash or a failed
    request assertion, and therefore must not turn an otherwise clean
    full-lifecycle run into a synthetic source failure.
    """

    return bool(cases) and all(
        case.get("status") in {"NOT_EXECUTED", "UNSUPPORTED", "NOT_APPLICABLE"}
        for case in cases
    )


def source_objects(paths: list[Path]) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    for path in paths:
        if not path.is_file():
            continue
        if path.suffix == ".json":
            objects.append(load_json(path))
        else:
            objects.append(parse_key_value_text(path))
    return objects


def first_status(objects: list[dict[str, Any]], key: str) -> int | None:
    for value in objects:
        observed = scalar_int(value.get(key))
        if observed is not None:
            return observed
    return None


def native_rule_engine_observed(objects: list[dict[str, Any]]) -> bool:
    """Return whether a native summary declares a real rule-engine path.

    This is only a routing guard for explicit native summary fields.  It does
    not promote anything on its own: the caller still validates the raw event
    stream, and the Framework subsequently binds every PASS to the selected
    integration mode and matching transaction evidence.
    """

    for value in objects:
        if str(value.get("status") or "").strip().upper() not in {"PASS", "FAIL"}:
            continue
        if scalar_bool(value.get("common_runtime_bridge")) is True:
            return True
        evaluation = str(value.get("rule_evaluation") or "").strip().casefold()
        if evaluation in NATIVE_RULE_ENGINE_EVALUATIONS:
            return True
    return False


def native_host_summary_cases(objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Project explicit native-host statuses into their catalog cases.

    A native runner has to name the field above and report a real
    rule-engine host run. Failed runs retain their actually observed traffic.
    The projection deliberately contains no event
    fields or integration mode: those must come from the actual raw producer,
    so this helper cannot manufacture causal evidence from a summary.
    """

    if not native_rule_engine_observed(objects):
        return []
    records: list[dict[str, Any]] = []
    seen_case_ids: set[str] = set()
    for value in objects:
        status = str(value.get("status") or "").strip().upper()
        if status not in {"PASS", "FAIL"}:
            continue
        for field, case_id, rule_id in NATIVE_HOST_SUMMARY_CASES:
            actual_status = scalar_int(value.get(field))
            if actual_status is None or case_id in seen_case_ids:
                continue
            record: dict[str, Any] = {
                "case_id": case_id,
                "status": status,
                "actual_status": actual_status,
                "live_executed": True,
                "reason": f"normalized from native host summary {field}",
                "promotion_allowed": False,
            }
            if rule_id is not None:
                record["observed_rule_ids"] = [rule_id]
            records.append(record)
            seen_case_ids.add(case_id)
    return records


def _append_native_probe_observations(path, summary, rows):
    for row in load_jsonl(path):
        if row.get("evidence_type") != "envoy_http_client_probe":
            continue
        for field in ("run_id", "source_revision"):
            if not summary.get(field) or row.get(field) != summary[field]:
                raise ValueError(f"native probe/summary identity mismatch: {field}")
        rows.append(row)


def native_probe_observations(objects: list[dict[str, Any]], source_root: Path) -> list[dict[str, Any]]:
    """Load durable per-request observations independently of final run status."""
    rows: list[dict[str, Any]] = []
    seen: set[Path] = set()
    for summary in objects:
        reference = summary.get("probe_observations_path")
        if not reference:
            continue
        path = contained_source_event_path(Path(str(reference)), source_root)
        if path in seen:
            continue
        seen.add(path)
        _append_native_probe_observations(path, summary, rows)
    return rows


def native_probe_rows(objects: list[dict[str, Any]], source_root: Path) -> list[dict[str, Any]]:
    """Select catalog rows while retaining auxiliary traffic in the source view."""
    return [row for row in native_probe_observations(objects, source_root) if row.get("case_id")]


def nonpromoted_host_success(objects: list[dict[str, Any]]) -> bool:
    """Return whether a real host ran without an allowed capability promotion.

    Native profile runners may prove host selection and transport while their
    Engine deliberately has no canonical rule-evaluation bridge.  Such a run
    must be recorded as ``NOT_EXECUTED`` rather than reclassified as a source
    failure merely because it cannot produce the compatibility 200/403 pair.
    The explicit marker prevents ordinary incomplete smokes from using this
    path.
    """

    if native_rule_engine_observed(objects):
        return False
    for value in objects:
        if (
            str(value.get("status") or "").strip().upper() == "PASS"
            and str(value.get("capability_promotion") or "").strip()
            == "not_permitted"
        ):
            return True
    return False


def collector_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connector", required=True)
    parser.add_argument("--stage-rc", required=True, type=int)
    parser.add_argument("--expected-rule-id", default="1100001")
    parser.add_argument("--framework-root", required=True, type=Path)
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--source-result", action="append", type=Path, default=[])
    parser.add_argument("--source-results-jsonl", action="append", type=Path, default=[])
    parser.add_argument("--source-events", action="append", type=Path, default=[])
    parser.add_argument("--allowed-source-root", type=Path)
    parser.add_argument("--allowed-native-operation-root", type=Path)
    parser.add_argument("--allowed-log-root", type=Path)
    parser.add_argument("--scrub-source-events", action="store_true")
    parser.add_argument("--source-event-scrub-log", type=Path)
    parser.add_argument("--five-connector-profile")
    parser.add_argument("--events-output", type=Path)
    parser.add_argument("--stdout", type=Path)
    parser.add_argument("--stderr", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def prepare_diagnostic_log_root(
    parser: argparse.ArgumentParser, args: argparse.Namespace, source_root: Path
) -> Path | None:
    has_lifecycle_logs = (
        args.stdout is not None
        or args.stderr is not None
        or args.source_event_scrub_log is not None
    )
    if has_lifecycle_logs and args.allowed_log_root is None:
        parser.error("--allowed-log-root is required to confine runtime logs")
    if args.allowed_log_root is None:
        return None
    log_root = prepare_verified_runtime_artifact_root(args.allowed_log_root)
    if has_lifecycle_logs:
        return paired_runtime_log_root(source_root, log_root)
    return log_root


def normalize_diagnostic_artifact(
    log_root: Path | None, artifact: Path | None, label: str
) -> Path | None:
    if artifact is None:
        return None
    if log_root is None:
        raise ValueError(f"{label} requires an allowed log root")
    return runtime_artifact_path(log_root, artifact, label)


def prepare_collector_arguments(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> Path:
    if args.five_connector_profile:
        try:
            verify_closed_five_connector_profile(args.five_connector_profile, args.connector)
        except ValueError as exc:
            parser.error(str(exc))
    if args.allowed_source_root is None:
        parser.error("--allowed-source-root is required to confine runtime artifacts")
    if args.allowed_log_root is None:
        parser.error("--allowed-log-root is required to confine lifecycle logs")
    try:
        source_root = prepare_verified_runtime_artifact_root(args.allowed_source_root)
        if getattr(args, 'allowed_native_operation_root', None) is not None:
            args.allowed_native_operation_root = _NATIVE_COLLECTION.authority_directory(
                args.allowed_native_operation_root)
        log_root = prepare_diagnostic_log_root(parser, args, source_root)
        if log_root is None:
            raise ValueError("allowed log root is required to confine lifecycle logs")
        args.allowed_log_root = log_root
        args.framework_root = canonical_framework_root(args.framework_root)
        args.catalog = canonical_catalog_path(args.catalog, args.framework_root)
        args.source_result = runtime_artifact_paths(
            source_root, args.source_result, "source result", must_exist=True
        )
        args.source_results_jsonl = runtime_artifact_paths(
            source_root, args.source_results_jsonl, "source results", must_exist=True
        )
        args.source_events = runtime_artifact_paths(
            source_root, args.source_events, "source events", must_exist=True
        )
        args.stdout = normalize_diagnostic_artifact(log_root, args.stdout, "stdout")
        args.stderr = normalize_diagnostic_artifact(log_root, args.stderr, "stderr")
        args.output = runtime_artifact_path(source_root, args.output, "output")
        if args.events_output is not None:
            args.events_output = runtime_artifact_path(
                source_root, args.events_output, "events output"
            )
        if args.source_event_scrub_log is not None:
            args.source_event_scrub_log = runtime_artifact_path(
                log_root, args.source_event_scrub_log, "source event scrub log"
            )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return source_root


def source_objects_from_arguments(args: argparse.Namespace) -> list[dict[str, Any]]:
    objects = source_objects(args.source_result)
    if args.stdout:
        objects.append(parse_key_value_text(args.stdout))
    return objects


def collector_cases_and_events(
    args: argparse.Namespace, source_root: Path, objects: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, Any], list[Path], list[Path]]:
    consumed_event_paths: list[Path] = []
    source_events = [
        contained_source_event_path(path, source_root)
        for path in args.source_events
    ]
    expectations, runner_case_index = catalog_contract(args.catalog)
    cases, derived_events = case_observations(
        args.source_results_jsonl,
        args.connector,
        args.expected_rule_id,
        expectations,
        source_root,
        consumed_event_paths,
        runner_case_index,
        getattr(args, 'allowed_native_operation_root', None),
    )
    for row in native_probe_rows(objects, source_root):
        observed, events = case_row_observations(
            row, args.connector, expectations, source_root, consumed_event_paths,
            runner_case_index, getattr(args, 'allowed_native_operation_root', None),
        )
        cases.extend(observed)
        derived_events.extend(events)
    observed_case_ids = {
        str(case.get("case_id") or "") for case in cases if isinstance(case, dict)
    }
    cases.extend(
        record
        for record in native_host_summary_cases(objects)
        if record["case_id"] not in observed_case_ids
    )
    native_root = getattr(args, 'allowed_native_operation_root', None)
    if native_root is not None:
        native_root = _NATIVE_COLLECTION.authority_directory(native_root)
        if any(path == native_root or native_root in path.parents
               for path in [*source_events, *consumed_event_paths]):
            raise ValueError('native bundle raw events cannot enter generic collection or scrubbing')
    return (
        unique_case_observations(cases),
        event_evidence(source_events, args.expected_rule_id, derived_events),
        source_events,
        consumed_event_paths,
    )


def _validate_client_observation_context(cases, has_client):
    if has_client:
        for case in cases:
            if case.get("evidence_identity") == "request_bound":
                validate_request_observation(case)
        contexts = {(case["run_id"], case["source_revision"]) for case in cases
                    if case.get("run_id") and case.get("source_revision")}
        if len(contexts) > 1:
            raise ValueError("client request observations mix runs or source revisions")


def _bind_client_request_observation_owner(case, has_client, request_owners):
    if has_client and all(case.get(field) for field in ("run_id", "request_id", "source_revision")):
        request = (case["run_id"], case["request_id"])
        owner = (case["case_id"], case["source_revision"], tuple(case.get("transaction_ids", [])),
                 case.get("evidence_identity") == "request_bound")
        previous_owner = request_owners.get(request)
        if (previous_owner is not None and previous_owner != owner
                and (previous_owner[3] or owner[3])):
            raise ValueError("conflicting client request ownership across cases")
        request_owners[request] = owner


def _select_unique_case_observation(
    case,
    has_client,
    request_owners,
    seen,
    selected,
    attempts,
    severity,
):
    if case.get("evidence_identity") == "request_bound":
        validate_request_observation(case)
    _bind_client_request_observation_owner(case, has_client, request_owners)
    case_id = str(case["case_id"])
    identity = (case_id, case.get("run_id"), case.get("source_revision"),
                case.get("request_id"), tuple(case.get("transaction_ids", [])))
    outcome = json.dumps({field: case.get(field) for field in (
        "status", "actual_status", "observed_rule_ids", "actual_action")}, sort_keys=True)
    if identity in seen and seen[identity] != outcome:
        raise ValueError("conflicting observations of one case/request identity")
    seen[identity] = outcome
    previous = selected.get(case_id)
    if previous is not None:
        for field in ("run_id", "source_revision"):
            if previous.get(field) != case.get(field):
                raise ValueError(f"mixed case source identities: {field}")
    attempts.setdefault(case_id, []).append(case)
    if previous is None or severity.get(str(case.get("status")), 5) > severity.get(str(previous.get("status")), 5):
        selected[case_id] = case


def unique_case_observations(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Count retries once without replacing a failed observed attempt by PASS."""
    selected: dict[str, dict[str, Any]] = {}
    attempts: dict[str, list[dict[str, Any]]] = {}
    seen: dict[tuple[Any, ...], str] = {}
    request_owners: dict[tuple[Any, ...], tuple[Any, ...]] = {}
    has_client = any(case.get("evidence_identity") == "request_bound" for case in cases)
    _validate_client_observation_context(cases, has_client)
    severity = {"PASS": 0, "NOT_APPLICABLE": 1, "UNSUPPORTED": 2, "NOT_EXECUTED": 3,
                "BLOCKED": 4, "FAIL": 5}
    for case in cases:
        _select_unique_case_observation(
            case, has_client, request_owners, seen, selected, attempts, severity,
        )
    for case_id, values in attempts.items():
        if len(values) > 1:
            selected[case_id] = {**selected[case_id], "attempt_count": len(values), "attempts": values}
    return list(selected.values())


def first_available_status(objects: list[dict[str, Any]], names: tuple[str, ...]) -> int | None:
    for name in names:
        value = first_status(objects, name)
        if value is not None:
            return value
    return None


def core_response_statuses(
    objects: list[dict[str, Any]], cases: list[dict[str, Any]]
) -> tuple[int | None, int | None]:
    allowed = first_available_status(
        objects,
        ("allowed_request_status", "baseline_status", "p1_allow_status"),
    )
    blocked = first_available_status(
        objects,
        ("blocked_request_status", "block_status", "phase1_deny_status", "p1_deny_status"),
    )
    for case in cases:
        if case["case_id"] == "allow_without_marker":
            allowed = scalar_int(case["actual_status"])
        elif case["case_id"] == "deny_header_marker_403":
            blocked = scalar_int(case["actual_status"])
    return allowed, blocked


def reported_core_response_statuses(
    nonpromoted_host: bool,
    allowed: int | None,
    blocked: int | None,
    cases: list[dict[str, Any]],
) -> tuple[int | None, int | None]:
    """Avoid deriving a second Framework core record from an explicit case."""

    if nonpromoted_host:
        return None, None
    reported_case_ids = {case.get("case_id") for case in cases}
    return (
        None if "allow_without_marker" in reported_case_ids else allowed,
        None if "deny_header_marker_403" in reported_case_ids else blocked,
    )


def collector_observed_rule_ids(
    objects: list[dict[str, Any]], events: dict[str, Any]
) -> list[str]:
    object_rule_ids = {
        str(value)
        for obj in objects
        for value in (
            obj.get("modsecurity_rule_id"),
            obj.get("rule_id"),
        )
        if value not in (None, "")
    }
    return sorted(object_rule_ids | set(events["observed_rule_ids"]))


def collector_status(
    stage_rc: int,
    explicit_runtime: bool,
    nonpromoted_host: bool,
    cases: list[dict[str, Any]],
    core_status_ok: bool,
    expected_rule_id: str,
    observed_rule_ids: list[str],
    events: dict[str, Any],
) -> str:
    if stage_rc == 77:
        return "FAIL" if explicit_runtime else "BLOCKED"
    if stage_rc != 0:
        return "FAIL"
    if nonpromoted_host or only_nonexecuted_cases(cases):
        return "NOT_EXECUTED"
    if (
        core_status_ok
        and expected_rule_id in observed_rule_ids
        and events["event_metadata_verified"]
        and events["body_payload_absent_from_events"]
    ):
        return "PASS"
    return "FAIL"


def request_runtime_observed(
    allowed: int | None, blocked: int | None,
    cases: list[dict[str, Any]], nonpromoted_host: bool,
) -> bool:
    return allowed is not None or blocked is not None or nonpromoted_host or any(
        "configtest_receipt" not in case or (
            case.get("case_id") == "valid_rules_file"
            and case.get("live_executed") is True
            and isinstance(case.get("configtest_receipt"), dict)
            and case["configtest_receipt"].get("case_id") == "valid_rules_file"
            and case["configtest_receipt"].get("operation") == "startup"
            and case["configtest_receipt"].get("process_started") is True
            and case["configtest_receipt"].get("listener_created") is True
            and isinstance(case["configtest_receipt"].get("request_probe"), dict)
            and case["configtest_receipt"]["request_probe"].get("client_exit_code") == 0
            and case["configtest_receipt"]["request_probe"].get("observed_http_status") == 403
        ) for case in cases
    )


def collector_payload(
    args: argparse.Namespace,
    status: str,
    explicit_runtime: bool,
    nonpromoted_host: bool,
    allowed: int | None,
    blocked: int | None,
    observed_rule_ids: list[str],
    core_status_ok: bool,
    cases: list[dict[str, Any]],
    events: dict[str, Any],
) -> dict[str, Any]:
    # A non-promoted native transport may return a 200 from its pass-through
    # host probe. That response is host-selection metadata, not a canonical
    # Phase-1 allow result, so do not let the Framework derive a case PASS
    # from it later.
    reported_allowed, reported_blocked = reported_core_response_statuses(
        nonpromoted_host, allowed, blocked, cases
    )
    return {
        "schema_version": 1,
        "connector": args.connector,
        "run_id": os.environ.get("NO_CRS_RUN_ID") or os.environ.get("SMOKE_RUN_ID") or os.environ.get("VERIFIED_RUN_ID", ""),
        "connector_commit": os.environ.get("CONNECTOR_REVISION", ""),
        "status": status,
        "stage_exit_code": args.stage_rc,
        "started": explicit_runtime,
        "requests_sent": explicit_runtime,
        "allowed_request_status": reported_allowed,
        "blocked_request_status": reported_blocked,
        "observed_rule_ids": observed_rule_ids,
        "transaction_ids": events["transaction_ids"],
        "request_headers_verified": core_status_ok,
        "request_body_verified": False,
        "response_headers_verified": False,
        "response_body_verified": False,
        "late_intervention_verified": False,
        "event_metadata_verified": events["event_metadata_verified"],
        "body_payload_absent_from_events": events["body_payload_absent_from_events"],
        "cases": cases,
        "event_records": events["event_records"],
        "event_validation_errors": events["event_validation_errors"],
        "forbidden_event_keys": events["forbidden_event_keys"],
    }


def write_collector_artifacts(
    args: argparse.Namespace,
    payload: dict[str, Any],
    events: dict[str, Any],
    source_events: list[Path],
    consumed_event_paths: list[Path],
    source_root: Path,
) -> None:
    write_runtime_artifact_text_atomic(
        source_root,
        args.output,
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        "collector output",
    )
    if args.events_output:
        write_runtime_artifact_text_atomic(
            source_root,
            args.events_output,
            "".join(json.dumps(record, sort_keys=True) + "\n" for record in events["records"]),
            "collector events output",
        )
    if args.scrub_source_events:
        scrub_source_event_paths(
            [*source_events, *consumed_event_paths],
            source_root,
            args.source_event_scrub_log,
            args.allowed_log_root,
        )


def main() -> int:
    parser = collector_argument_parser()
    args = parser.parse_args()
    source_root = prepare_collector_arguments(parser, args)

    objects = source_objects_from_arguments(args)
    request_observations = native_probe_observations(objects, source_root)
    cases, events, source_events, consumed_event_paths = collector_cases_and_events(
        args, source_root, objects
    )
    allowed, blocked = core_response_statuses(objects, cases)
    observed_rule_ids = collector_observed_rule_ids(objects, events)
    nonpromoted_host = nonpromoted_host_success(objects)
    explicit_runtime = request_runtime_observed(allowed, blocked, cases, nonpromoted_host) or any(
        row.get("live_executed") is True for row in request_observations)
    core_status_ok = allowed == 200 and blocked == 403
    status = collector_status(
        args.stage_rc,
        explicit_runtime,
        nonpromoted_host,
        cases,
        core_status_ok,
        args.expected_rule_id,
        observed_rule_ids,
        events,
    )
    payload = collector_payload(
        args,
        status,
        explicit_runtime,
        nonpromoted_host,
        allowed,
        blocked,
        observed_rule_ids,
        core_status_ok,
        cases,
        events,
    )
    payload["executed_request_observations"] = request_observations
    payload["executed_request_observations_sha256"] = hashlib.sha256(
        json.dumps(request_observations, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    payload["executed_request_count"] = sum(row.get("live_executed") is True for row in request_observations)
    write_collector_artifacts(
        args,
        payload,
        events,
        source_events,
        consumed_event_paths,
        source_root,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
