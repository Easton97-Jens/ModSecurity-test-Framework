#!/usr/bin/env python3
"""Validate and render canonical connector capability declarations.

Connector-local JSON files remain immutable source-contract declarations.  A
generated catalog can optionally overlay one explicitly selected, fully
validated canonical No-CRS run for every connector.  The overlay is a report
view only: it never writes back to a connector manifest and it promotes a
capability only when the canonical result's checked ``capabilities_verified``
list says that a live case verified it.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from types import MappingProxyType

# CI helpers are shared from ci/lib even when this file is executed directly.

from typing import Any

from modsecurity_connector_ci.lib.generated_report_utils import build_metadata, generated_json_text, generated_markdown_text, report_filename


ROOT = connector_root()
CONNECTORS = ("apache", "nginx", "haproxy", "envoy", "traefik", "lighttpd")
REQUEST_METADATA_CAPABILITIES = (
    "connection_metadata",
    "transport_metadata",
    "request_headers",
    "request_body_buffered",
    "request_body_streaming",
    "request_body_incremental_ingest",
)
RESPONSE_METADATA_CAPABILITIES = (
    "response_headers",
    "response_body_buffered",
    "response_body_streaming",
    "response_body_incremental_ingest",
)
PHASE_CAPABILITIES = (
    "phase1",
    "phase2",
    "phase3",
    "phase4",
    "phase4_rule_evaluation",
    "phase4_end_of_stream_evaluation",
)
INTERVENTION_CAPABILITIES = (
    "phase4_pre_commit_deny",
    "late_intervention",
    "late_intervention_log_only",
    "late_intervention_abort",
    "late_intervention_status_metadata",
)
REQUEST_PROTOCOL_CAPABILITIES = (
    "content_type_scope",
    "header_limits",
    "request_body_limits",
    "response_body_limits",
    "no_full_response_buffering",
    "first_byte_before_response_end",
)
HTTP1_CAPABILITIES = (
    "http1_content_length",
    "http1_chunked",
    "keep_alive",
    "parallel_requests",
)
HTTP2_CAPABILITIES = (
    "http2",
    "http2_downstream",
    "http2_upstream",
    "http2_tls_alpn",
    "http2_cleartext_h2c",
    "http2_multiplexing",
    "http2_stream_reset",
)
HTTP3_CAPABILITIES = (
    "http3_downstream",
    "http3_upstream",
    "http3_quic",
    "http3_alt_svc",
    "http3_multiplexing",
    "http3_stream_reset",
)
TRANSACTION_ISOLATION_CAPABILITIES = (
    "protocol_transaction_isolation",
    "protocol_first_byte_before_response_end",
    "protocol_no_full_response_buffering",
)
TRANSPORT_CAPABILITIES = (
    "client_abort",
    "upstream_abort",
    "response_body_decompression",
)
ACTION_CAPABILITIES = (
    "deny",
    "redirect",
    "drop",
    "abort_connection",
    "log_only",
)
OBSERVABILITY_CAPABILITIES = (
    "transaction_id",
    "event_jsonl",
)
RULE_CONFIGURATION_CAPABILITIES = (
    "config_inline_rules",
    "config_rules_file",
    "config_remote_rules",
)
CAPABILITY_NAMES = (
    *REQUEST_METADATA_CAPABILITIES,
    *RESPONSE_METADATA_CAPABILITIES,
    *PHASE_CAPABILITIES,
    *INTERVENTION_CAPABILITIES,
    *REQUEST_PROTOCOL_CAPABILITIES,
    *HTTP1_CAPABILITIES,
    *HTTP2_CAPABILITIES,
    *HTTP3_CAPABILITIES,
    *TRANSACTION_ISOLATION_CAPABILITIES,
    *TRANSPORT_CAPABILITIES,
    *ACTION_CAPABILITIES,
    *OBSERVABILITY_CAPABILITIES,
    *RULE_CONFIGURATION_CAPABILITIES,
)
CAPABILITY_STATES = {
    "verified",
    "implemented_not_asserted",
    "configured_not_exercised",
    "unsupported_by_host_model",
    "not_implemented",
    "not_applicable",
}
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
PHASE_DEPENDENCIES = {
    "phase1": "request_headers",
    "phase2": "request_body_buffered",
    "phase3": "response_headers",
    "phase4": "response_body_buffered",
}
VERIFIED_DEPENDENCIES = {
    "phase4_rule_evaluation": "phase4",
    "phase4_end_of_stream_evaluation": "phase4_rule_evaluation",
    "first_byte_before_response_end": "no_full_response_buffering",
    "phase4_pre_commit_deny": "phase4_rule_evaluation",
    "late_intervention_log_only": "late_intervention",
    "late_intervention_abort": "late_intervention",
}
TRAEFIK_FORWARDAUTH_REFERENCE = (
    "https://doc.traefik.io/traefik/v3.7/reference/"
    "routing-configuration/http/middlewares/forwardauth/"
)
STAGE_STATES = {
    "supported_and_verified",
    "supported_not_verified",
    "implemented_not_asserted",
    "unsupported_by_host_model",
    "not_implemented",
    "blocked_before_execution",
    "failed",
}
FLAG_TO_CAPABILITY = {
    "MSCONNECTOR_CAPABILITY_CONNECTION_METADATA": "connection_metadata",
    "MSCONNECTOR_CAPABILITY_REQUEST_HEADERS": "request_headers",
    "MSCONNECTOR_CAPABILITY_REQUEST_BODY_BUFFERED": "request_body_buffered",
    "MSCONNECTOR_CAPABILITY_REQUEST_BODY_STREAMING": "request_body_streaming",
    "MSCONNECTOR_CAPABILITY_RESPONSE_HEADERS": "response_headers",
    "MSCONNECTOR_CAPABILITY_RESPONSE_BODY_BUFFERED": "response_body_buffered",
    "MSCONNECTOR_CAPABILITY_RESPONSE_BODY_STREAMING": "response_body_streaming",
    "MSCONNECTOR_CAPABILITY_CUSTOM_TRANSACTION_ID": "transaction_id",
    "MSCONNECTOR_CAPABILITY_PHASE4_RULE_EVALUATION": "phase4_rule_evaluation",
    "MSCONNECTOR_CAPABILITY_PHASE4_PRE_COMMIT_DENY": "phase4_pre_commit_deny",
    "MSCONNECTOR_CAPABILITY_LATE_INTERVENTION_LOG_ONLY": "late_intervention_log_only",
    "MSCONNECTOR_CAPABILITY_LATE_INTERVENTION_ABORT": "late_intervention_abort",
    "MSCONNECTOR_CAPABILITY_LATE_INTERVENTION_STATUS_METADATA": "late_intervention_status_metadata",
}
NEGATIVE_CAPABILITY_STATES = {
    "unsupported_by_host_model",
    "not_implemented",
    "not_applicable",
}
RESULT_STATUSES = {
    "PASS",
    "FAIL",
    "BLOCKED",
    "UNSUPPORTED",
    "NOT_APPLICABLE",
    "NOT_EXECUTED",
}
NO_CRS_STAGE_STATES = {
    "PASS": "supported_and_verified",
    "FAIL": "failed",
    "BLOCKED": "blocked_before_execution",
    "UNSUPPORTED": "unsupported_by_host_model",
    "NOT_APPLICABLE": "unsupported_by_host_model",
    "NOT_EXECUTED": "supported_not_verified",
}
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
FRAMEWORK_NO_CRS_TOOL = source_path('modules/ModSecurity-test-Framework/ci/checks/catalog/no_crs_baseline.py', root=ROOT)

_PRE_UPSTREAM_RESPONSE_REQUIRED_STATES = MappingProxyType(
    dict.fromkeys(
        (
            "response_headers",
            "response_body_buffered",
            "response_body_streaming",
            "phase3",
            "phase4",
            "phase4_rule_evaluation",
            "phase4_pre_commit_deny",
            "late_intervention",
            "late_intervention_log_only",
            "late_intervention_abort",
            "late_intervention_status_metadata",
        ),
        "unsupported_by_host_model",
    )
)
_HOST_MODEL_REQUIRED_STATES = MappingProxyType(
    {
        "envoy": MappingProxyType(
            {
                "request_body_buffered": "configured_not_exercised",
                "phase2": "configured_not_exercised",
                **_PRE_UPSTREAM_RESPONSE_REQUIRED_STATES,
            }
        ),
        "traefik": MappingProxyType(
            {
                "request_body_buffered": "configured_not_exercised",
                "request_body_streaming": "unsupported_by_host_model",
                "phase2": "configured_not_exercised",
                **_PRE_UPSTREAM_RESPONSE_REQUIRED_STATES,
            }
        ),
        "lighttpd": MappingProxyType(
            {
                "request_body_buffered": "not_implemented",
                "request_body_streaming": "not_implemented",
                "response_body_buffered": "not_implemented",
                "response_body_streaming": "not_implemented",
                "phase2": "not_implemented",
                "phase4": "not_implemented",
                "phase4_rule_evaluation": "not_implemented",
                "phase4_pre_commit_deny": "not_implemented",
                "late_intervention": "not_implemented",
                "late_intervention_log_only": "not_implemented",
                "late_intervention_abort": "not_implemented",
                "late_intervention_status_metadata": "not_implemented",
            }
        ),
    }
)


class DuplicateKeyError(ValueError):
    """Raised when a JSON object contains a duplicate key."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
    )
    if not isinstance(value, dict):
        raise ValueError("top-level JSON value must be an object")
    return value


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _relative_source_path(value: object, label: str, errors: list[str]) -> Path | None:
    if not _nonempty(value):
        errors.append(f"{label}: path must be a non-empty string")
        return None
    path = Path(str(value))
    if path.is_absolute() or ".." in path.parts:
        errors.append(f"{label}: path must be repository-relative without '..': {value}")
        return None
    resolved = (ROOT / path).resolve(strict=False)
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        errors.append(f"{label}: path escapes the repository: {value}")
        return None
    return path


def _validate_evidence_list(
    value: object, label: str, errors: list[str], *, require_nonempty: bool
) -> None:
    if not isinstance(value, list) or (require_nonempty and not value):
        errors.append(f"{label}: evidence must be a non-empty list")
        return
    for index, item in enumerate(value):
        _validate_evidence_item(item, f"{label}[{index}]", errors)


def _validate_evidence_path(value: object, label: str, errors: list[str]) -> None:
    path = _relative_source_path(value, label, errors)
    if path is not None and not (ROOT / path).is_file():
        errors.append(f"{label}: evidence file does not exist: {value}")


def _validate_evidence_item(item: object, label: str, errors: list[str]) -> None:
    if isinstance(item, str):
        _validate_evidence_path(item, label, errors)
        return
    if not isinstance(item, dict):
        errors.append(f"{label}: evidence entry must be a path or object")
        return
    evidence_path = item.get("path")
    if evidence_path is not None:
        _validate_evidence_path(evidence_path, f"{label}.path", errors)
    elif not _nonempty(item.get("artifact")):
        errors.append(f"{label}: evidence object requires path or artifact")


def _validate_capabilities(
    connector: str, data: dict[str, Any], errors: list[str]
) -> None:
    capabilities = data.get("capabilities")
    if not isinstance(capabilities, dict):
        errors.append(f"{connector}: capabilities must be an object")
        return
    actual = set(capabilities)
    expected = set(CAPABILITY_NAMES)
    for name in sorted(expected - actual):
        errors.append(f"{connector}: missing capability {name}")
    for name in sorted(actual - expected):
        errors.append(f"{connector}: unknown capability {name}")
    for name in CAPABILITY_NAMES:
        entry = capabilities.get(name)
        label = f"{connector}.capabilities.{name}"
        if not isinstance(entry, dict):
            if name in capabilities:
                errors.append(f"{label}: entry must be an object")
            continue
        state = entry.get("state")
        if state not in CAPABILITY_STATES:
            errors.append(f"{label}: invalid state {state!r}")
        if not _nonempty(entry.get("reason")):
            errors.append(f"{label}: reason must be non-empty")
        if state == "verified":
            _validate_evidence_list(
                entry.get("evidence"), f"{label}.evidence", errors, require_nonempty=True
            )


def _validate_stages(connector: str, data: dict[str, Any], errors: list[str]) -> None:
    stages = data.get("evidence_stages")
    if not isinstance(stages, dict):
        errors.append(f"{connector}: evidence_stages must be an object")
        return
    actual = set(stages)
    expected = set(EVIDENCE_STAGES)
    for name in sorted(expected - actual):
        errors.append(f"{connector}: missing evidence stage {name}")
    for name in sorted(actual - expected):
        errors.append(f"{connector}: unknown evidence stage {name}")
    for name in EVIDENCE_STAGES:
        entry = stages.get(name)
        label = f"{connector}.evidence_stages.{name}"
        if not isinstance(entry, dict):
            if name in stages:
                errors.append(f"{label}: entry must be an object")
            continue
        status = entry.get("status")
        if status not in STAGE_STATES:
            errors.append(f"{label}: invalid status {status!r}")
        if not _nonempty(entry.get("reason")):
            errors.append(f"{label}: reason must be non-empty")
        if status == "supported_and_verified":
            _validate_evidence_list(
                entry.get("evidence"), f"{label}.evidence", errors, require_nonempty=True
            )


def _source_contract_file(path: Path) -> Path:
    if ROOT != connector_root():
        return ROOT / path
    selected = source_path(path, root=ROOT)
    framework = test_root()
    authority = framework if selected.is_relative_to(framework) else ROOT
    if not selected.resolve(strict=False).is_relative_to(authority.resolve()):
        raise ValueError(f"source-contract path escapes its selected owner: {path}")
    return selected


def _validate_paths(connector: str, data: dict[str, Any], errors: list[str]) -> None:
    expected_metadata = f"connectors/{connector}/metadata.c"
    metadata_value = data.get("metadata_source")
    if metadata_value != expected_metadata:
        errors.append(
            f"{connector}: metadata_source must be {expected_metadata!r}, got {metadata_value!r}"
        )
    source_contract = data.get("source_contract")
    if not isinstance(source_contract, list) or not source_contract:
        errors.append(f"{connector}: source_contract must be a non-empty path list")
        return
    if len(source_contract) != len(set(map(str, source_contract))):
        errors.append(f"{connector}: source_contract contains duplicate paths")
    if expected_metadata not in source_contract:
        errors.append(f"{connector}: source_contract must include metadata_source")
    for index, value in enumerate(source_contract):
        path = _relative_source_path(value, f"{connector}.source_contract[{index}]", errors)
        if path is None:
            continue
        try:
            selected = _source_contract_file(path)
        except ValueError as exc:
            errors.append(f"{connector}: {exc}")
            continue
        if not selected.is_file():
            errors.append(f"{connector}: source-contract file does not exist: {value}")


def _validate_metadata_drift(
    connector: str, data: dict[str, Any], errors: list[str]
) -> None:
    metadata_path = ROOT / f"connectors/{connector}/metadata.c"
    if not metadata_path.is_file():
        return
    text = metadata_path.read_text(encoding="utf-8", errors="replace")
    lowered = text.casefold()
    for label, value in (
        ("connector", data.get("connector")),
        ("host_name", data.get("host_name")),
    ):
        if _nonempty(value) and str(value).casefold() not in lowered:
            errors.append(
                f"{connector}: {label} value {value!r} is absent from metadata.c"
            )
    capabilities = data.get("capabilities")
    if not isinstance(capabilities, dict):
        return
    for flag, capability in FLAG_TO_CAPABILITY.items():
        if flag not in text:
            continue
        entry = capabilities.get(capability)
        state = entry.get("state") if isinstance(entry, dict) else None
        if state in NEGATIVE_CAPABILITY_STATES:
            errors.append(
                f"{connector}: metadata.c declares {flag} but {capability} is {state}"
            )


def _all_json_strings(value: object) -> set[str]:
    if isinstance(value, dict):
        result = set(value)
        for item in value.values():
            result.update(_all_json_strings(item))
        return result
    if isinstance(value, list):
        result: set[str] = set()
        for item in value:
            result.update(_all_json_strings(item))
        return result
    return {value} if isinstance(value, str) else set()


def _validate_source_map(connector: str, errors: list[str]) -> None:
    source_map_path = ROOT / f"connectors/{connector}/SOURCE_MAP.json"
    if not source_map_path.is_file():
        errors.append(f"{connector}: SOURCE_MAP.json is missing")
        return
    try:
        source_map = _read_json(source_map_path)
    except (OSError, ValueError) as exc:
        errors.append(f"{connector}: cannot parse SOURCE_MAP.json: {exc}")
        return
    if source_map.get("connector") != connector:
        errors.append(f"{connector}: SOURCE_MAP.json connector field does not match")
    manifest_path = f"connectors/{connector}/capabilities.json"
    if manifest_path not in _all_json_strings(source_map):
        errors.append(f"{connector}: SOURCE_MAP.json does not account for {manifest_path}")


def _validate_external_references(
    connector: str, data: dict[str, Any], errors: list[str]
) -> None:
    references = data.get("external_references", [])
    if not isinstance(references, list):
        errors.append(f"{connector}: external_references must be a list")
        return
    for index, reference in enumerate(references):
        label = f"{connector}.external_references[{index}]"
        if not isinstance(reference, dict):
            errors.append(f"{label}: reference must be an object")
            continue
        if not _nonempty(reference.get("title")) or not _nonempty(
            reference.get("supports")
        ):
            errors.append(f"{label}: title and supports must be non-empty")
        url = reference.get("url")
        if not _nonempty(url) or not str(url).startswith("https://"):
            errors.append(f"{label}: url must be an https URL")


def _state(data: dict[str, Any], capability: str) -> str | None:
    capabilities = data.get("capabilities")
    entry = capabilities.get(capability) if isinstance(capabilities, dict) else None
    return entry.get("state") if isinstance(entry, dict) else None


def _validate_relationships(
    connector: str, data: dict[str, Any], errors: list[str]
) -> None:
    _validate_verified_dependencies(connector, data, errors, PHASE_DEPENDENCIES)
    _validate_verified_dependencies(connector, data, errors, VERIFIED_DEPENDENCIES)
    _validate_host_model_requirements(connector, data, errors)
    _validate_connector_specific_relationships(connector, data, errors)


def _validate_verified_dependencies(
    connector: str,
    data: dict[str, Any],
    errors: list[str],
    dependencies: dict[str, str],
) -> None:
    for capability, prerequisite in dependencies.items():
        if _state(data, capability) == "verified" and _state(data, prerequisite) != "verified":
            errors.append(
                f"{connector}: {capability}=verified requires {prerequisite}=verified"
            )

def _validate_host_model_requirements(
    connector: str, data: dict[str, Any], errors: list[str]
) -> None:
    for capability, expected in _HOST_MODEL_REQUIRED_STATES.get(connector, {}).items():
        actual = _state(data, capability)
        if actual != expected:
            errors.append(
                f"{connector}: host-model invariant requires {capability}={expected}, got {actual}"
            )
def _validate_connector_specific_relationships(
    connector: str, data: dict[str, Any], errors: list[str]
) -> None:
    if connector == "lighttpd":
        _validate_lighttpd_phase3_evidence(data, errors)
    if connector == "traefik":
        _validate_traefik_forwardauth_reference(data, errors)


def _validate_lighttpd_phase3_evidence(data: dict[str, Any], errors: list[str]) -> None:
    for capability in ("response_headers", "phase3"):
        if _state(data, capability) == "verified":
            errors.append(
                f"lighttpd: {capability} must not be verified without Phase-3 runtime evidence"
            )


def _validate_traefik_forwardauth_reference(
    data: dict[str, Any], errors: list[str]
) -> None:
    urls = {
        str(item.get("url"))
        for item in data.get("external_references", [])
        if isinstance(item, dict)
    }
    if TRAEFIK_FORWARDAUTH_REFERENCE not in urls:
        errors.append("traefik: missing versioned official ForwardAuth reference")


def validate_manifest(connector: str, data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if data.get("schema_version") != 1:
        errors.append(f"{connector}: schema_version must be integer 1")
    if data.get("connector") != connector:
        errors.append(
            f"{connector}: connector field must equal directory name, got {data.get('connector')!r}"
        )
    if not _nonempty(data.get("host_name")):
        errors.append(f"{connector}: host_name must be non-empty")
    if not _nonempty(data.get("integration_mode")):
        errors.append(f"{connector}: integration_mode must be non-empty")
    constraints = data.get("host_model_constraints")
    if not isinstance(constraints, list) or not constraints or not all(
        _nonempty(item) for item in constraints
    ):
        errors.append(
            f"{connector}: host_model_constraints must be a non-empty string list"
        )
    _validate_paths(connector, data, errors)
    _validate_capabilities(connector, data, errors)
    _validate_stages(connector, data, errors)
    _validate_metadata_drift(connector, data, errors)
    _validate_source_map(connector, errors)
    _validate_external_references(connector, data, errors)
    _validate_relationships(connector, data, errors)
    return errors


def load_manifests() -> tuple[dict[str, dict[str, Any]], list[str]]:
    manifests: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for connector in CONNECTORS:
        path = ROOT / f"connectors/{connector}/capabilities.json"
        if not path.is_file():
            errors.append(f"{connector}: missing manifest {path.relative_to(ROOT)}")
            continue
        try:
            data = _read_json(path)
        except (OSError, ValueError) as exc:
            errors.append(f"{connector}: cannot parse {path.relative_to(ROOT)}: {exc}")
            continue
        manifests[connector] = data
        errors.extend(validate_manifest(connector, data))
    return manifests, errors


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_run_id(run_id: str) -> str | None:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        return (
            "run id must start with an alphanumeric character, contain only "
            "[A-Za-z0-9._-], and be at most 128 characters"
        )
    return None


def _validator_output(process: subprocess.CompletedProcess[str]) -> str:
    output = "\n".join(
        item.strip()
        for item in (process.stdout, process.stderr)
        if isinstance(item, str) and item.strip()
    )
    if len(output) > 4000:
        return output[:4000] + "\n... validator output truncated"
    return output or f"validator exited {process.returncode} without diagnostic output"


def _validate_evidence_run(
    connector: str,
    run_dir: Path,
    manifest_path: Path,
) -> list[str]:
    """Validate the complete canonical run before trusting its result.json.

    Calling the Framework validator rather than treating a standalone JSON
    object as evidence protects the report from stale commits, mismatched
    manifest inventories, fabricated capability lists, and incomplete artifact
    trees.  ``--connector-root`` deliberately makes this a current-checkout
    validation, not a historical-result renderer.
    """
    if not FRAMEWORK_NO_CRS_TOOL.is_file():
        return [
            f"{connector}: canonical evidence validator is missing: "
            f"{FRAMEWORK_NO_CRS_TOOL.relative_to(ROOT)}"
        ]
    command = [
        sys.executable,
        str(FRAMEWORK_NO_CRS_TOOL),
        "validate",
        "--evidence-root",
        str(run_dir),
        "--connector",
        connector,
        "--run-id",
        run_dir.name,
        "--connector-root",
        str(ROOT),
        "--capabilities",
        str(manifest_path),
        "--check",
        "all",
    ]
    try:
        process = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [f"{connector}: could not validate canonical evidence: {exc}"]
    if process.returncode != 0:
        return [
            f"{connector}: canonical evidence validation failed for "
            f"{run_dir}: {_validator_output(process)}"
        ]
    return []


def _validated_result_shape_errors(
    connector: str,
    run_id: str,
    result: dict[str, Any],
    manifest: dict[str, Any],
) -> list[str]:
    """Apply report-specific fail-closed checks after Framework validation."""
    errors = _result_identity_errors(connector, run_id, result)
    errors.extend(_result_count_errors(connector, result))
    expected_states = _manifest_capability_states(manifest)
    if result.get("capability_states") != expected_states:
        errors.append(
            f"{connector}: result.json capability_states do not match the current source manifest"
        )
    errors.extend(_verified_capability_errors(connector, result, expected_states))
    return errors


def _result_identity_errors(
    connector: str, run_id: str, result: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    required_values = {
        "connector": connector,
        "run_id": run_id,
        "evidence_stage": "no_crs_baseline",
        "ruleset": "no-crs-baseline",
    }
    for field, expected in required_values.items():
        if result.get(field) != expected:
            errors.append(
                f"{connector}: result.json {field} must be {expected!r}, got "
                f"{result.get(field)!r}"
            )
    if result.get("status") not in RESULT_STATUSES:
        errors.append(f"{connector}: result.json has invalid status {result.get('status')!r}")
    if not isinstance(result.get("source_failure"), bool):
        errors.append(f"{connector}: result.json source_failure must be Boolean")
    return errors


def _result_count_errors(connector: str, result: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for field in ("cases_failed", "cases_blocked"):
        value = result.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            errors.append(f"{connector}: result.json {field} must be a non-negative integer")
    return errors


def _manifest_capability_states(manifest: dict[str, Any]) -> dict[str, Any]:
    declared = manifest.get("capabilities")
    return {
        name: entry.get("state")
        for name, entry in declared.items()
        if isinstance(entry, dict)
    } if isinstance(declared, dict) else {}


def _verified_capability_errors(
    connector: str, result: dict[str, Any], expected_states: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    verified = result.get("capabilities_verified")
    if not isinstance(verified, list) or not all(isinstance(item, str) for item in verified):
        errors.append(f"{connector}: result.json capabilities_verified must be a string list")
        return errors
    if len(verified) != len(set(verified)):
        errors.append(f"{connector}: result.json capabilities_verified contains duplicates")
    for capability in verified:
        if capability not in CAPABILITY_NAMES:
            errors.append(
                f"{connector}: result.json verifies unknown capability {capability!r}"
            )
            continue
        source_state = expected_states.get(capability)
        if source_state in NEGATIVE_CAPABILITY_STATES:
            errors.append(
                f"{connector}: result.json verifies {capability} although the source "
                f"manifest declares {source_state}"
            )
    return errors


def _load_connector_runtime_result(
    connector: str,
    manifests: dict[str, dict[str, Any]],
    evidence_root: Path,
    run_id: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    connector_dir = evidence_root / connector
    run_dir = connector_dir / run_id
    result_path = run_dir / "result.json"
    if connector_dir.is_symlink() or run_dir.is_symlink():
        return None, [f"{connector}: canonical evidence directories must not be symlinks"]
    if not run_dir.is_dir():
        return None, [f"{connector}: canonical evidence run directory is missing: {connector}/{run_id}"]
    if not result_path.is_file():
        return None, [f"{connector}: canonical result.json is missing: {connector}/{run_id}/result.json"]
    if result_path.is_symlink():
        return None, [f"{connector}: canonical result.json must not be a symlink"]
    try:
        result = _read_json(result_path)
    except (OSError, ValueError) as exc:
        return None, [f"{connector}: cannot parse canonical result.json: {exc}"]
    errors = _validated_result_shape_errors(connector, run_id, result, manifests[connector])
    if errors:
        return None, errors
    errors = _validate_evidence_run(
        connector,
        run_dir,
        ROOT / f"connectors/{connector}/capabilities.json",
    )
    if errors:
        return None, errors
    return {
        "result": result,
        "path": f"{connector}/{run_id}/result.json",
        "sha256": _sha256_file(result_path),
    }, []


def load_validated_runtime_results(
    manifests: dict[str, dict[str, Any]],
    evidence_root: Path,
    run_id: str,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Load exactly six validated canonical No-CRS result files.

    Evidence merge is intentionally all-or-nothing.  A report which silently
    promotes only the available connectors would make absent or invalid
    evidence look like a static assertion, which is precisely what this view
    is intended to avoid.
    """
    errors: list[str] = []
    validated: dict[str, dict[str, Any]] = {}
    run_id_error = _validate_run_id(run_id)
    if run_id_error:
        return {}, [f"canonical evidence: {run_id_error}"]
    if not evidence_root.is_dir():
        return {}, [f"canonical evidence root is not a directory: {evidence_root}"]
    if evidence_root.is_symlink():
        return {}, [f"canonical evidence root must not be a symlink: {evidence_root}"]

    for connector in CONNECTORS:
        result, result_errors = _load_connector_runtime_result(
            connector, manifests, evidence_root, run_id
        )
        errors.extend(result_errors)
        if result is not None:
            validated[connector] = result
    return validated, errors


def _result_allows_capability_promotion(result: dict[str, Any]) -> bool:
    """Whether individual PASS cases are trustworthy promotion evidence."""
    # A NOT_EXECUTED baseline can still contain valid core-case evidence while
    # unrelated selected cases have no host runner.  Failed, blocked, or
    # source-failed runs must never promote a partial observation.
    return (
        result.get("status") in {"PASS", "NOT_EXECUTED"}
        and result.get("source_failure") is False
        and result.get("cases_failed") == 0
        and result.get("cases_blocked") == 0
    )


def merge_runtime_results(
    manifests: dict[str, dict[str, Any]],
    results: dict[str, dict[str, Any]],
    run_id: str,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Return a report-only capability view overlaid with validated evidence."""
    merged = copy.deepcopy(manifests)
    evidence_connectors: dict[str, dict[str, Any]] = {}
    for connector in CONNECTORS:
        record = results[connector]
        result = record["result"]
        if not isinstance(result, dict):
            raise ValueError(f"{connector}: validated result record is not an object")
        result_path = str(record["path"])
        result_sha256 = str(record["sha256"])
        result_status = str(result["status"])
        reported_verified = sorted(set(result["capabilities_verified"]))
        promotion_eligible = _result_allows_capability_promotion(result)
        verified = reported_verified if promotion_eligible else []
        provenance = {
            "run_id": run_id,
            "result": result_path,
            "result_sha256": result_sha256,
            "result_status": result_status,
        }

        capabilities = merged[connector]["capabilities"]
        for capability in verified:
            entry = capabilities[capability]
            source_state = entry["state"]
            if source_state in NEGATIVE_CAPABILITY_STATES:
                # This should be unreachable after the Framework validation and
                # _validated_result_shape_errors, but retain the guard at the
                # trust boundary in case this helper is reused directly.
                raise ValueError(
                    f"{connector}: refusing to promote {capability} from "
                    f"source state {source_state}"
                )
            entry["state"] = "verified"
            entry["declared_state"] = source_state
            entry["evidence_state"] = "verified_in_current_run"
            entry["reason"] = (
                f"Validated canonical No-CRS result {run_id!r} verified this "
                f"capability through live case evidence; the source declaration "
                f"remains {source_state!r}."
            )
            entry["runtime_evidence"] = dict(provenance)

        stage = merged[connector]["evidence_stages"]["no_crs_baseline"]
        source_status = stage["status"]
        stage["status"] = NO_CRS_STAGE_STATES[result_status]
        stage["declared_status"] = source_status
        stage["reason"] = (
            f"Validated canonical No-CRS result {run_id!r} reported "
            f"{result_status}; this current stage view does not infer a PASS "
            "from unsupported or unexecuted cases."
        )
        stage["runtime_evidence"] = dict(provenance)

        evidence_connectors[connector] = {
            **provenance,
            "promotion_eligible": promotion_eligible,
            "reported_capabilities_verified": reported_verified,
            "capabilities_verified": verified,
            "no_crs_baseline_state": stage["status"],
        }
    return merged, {
        "run_id": run_id,
        "evidence_stage": "no_crs_baseline",
        "validation": "framework-validate-all-current-provenance",
        "connectors": evidence_connectors,
    }


def _normalized_manifest(data: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {
        "connector": data["connector"],
        "host_name": data["host_name"],
        "integration_mode": data["integration_mode"],
        "metadata_source": data["metadata_source"],
        "source_contract": list(data["source_contract"]),
        "host_model_constraints": list(data["host_model_constraints"]),
    }
    if data.get("external_references"):
        normalized["external_references"] = data["external_references"]
    normalized["capabilities"] = {
        name: data["capabilities"][name] for name in CAPABILITY_NAMES
    }
    normalized["evidence_stages"] = {
        name: data["evidence_stages"][name] for name in EVIDENCE_STAGES
    }
    return normalized


def aggregate_payload(
    manifests: dict[str, dict[str, Any]],
    *,
    runtime_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "kind": "connector-capability-catalog",
        "runtime_promotion": runtime_evidence is not None,
        "generated_from": [f"connectors/{name}/capabilities.json" for name in CONNECTORS],
        "capability_names": list(CAPABILITY_NAMES),
        "evidence_stage_names": list(EVIDENCE_STAGES),
        "connectors": {
            name: _normalized_manifest(manifests[name]) for name in CONNECTORS
        },
    }
    if runtime_evidence is not None:
        payload["runtime_evidence"] = runtime_evidence
    return payload


def _markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _markdown_labels(german: bool, runtime_evidence: dict[str, Any] | None) -> dict[str, str]:
    if german:
        return {
            "title": "# Kanonische Connector-Capabilities",
            "intro": (
                "Diese Datei wird deterministisch aus den sechs connector-lokalen Manifesten "
                "erzeugt. Sie beschreibt Host-Grenzen und Implementierungszustände; sie "
                "befördert keine Capability ohne kanonische Lauf-Evidence zu `verified`."
                if runtime_evidence is None
                else "Diese Datei verbindet unveränderte connector-lokale Source-Contracts mit "
                "vollständig validierter kanonischer No-CRS-Evidence. Nur die in den "
                "Resultaten belegten Capabilities werden in dieser Report-Ansicht zu "
                "`verified` befördert."
            ),
            "capability_heading": "## Capability-Matrix",
            "stage_heading": "## Evidence-Stufen",
            "detail_heading": "## Connector-Details",
            "capability_label": "Capability",
            "stage_label": "Stufe",
            "state_label": "Zustand",
            "reason_label": (
                "Kanonischer Grund (aus dem Manifest)"
                if runtime_evidence is None
                else "Kanonischer Grund"
            ),
            "constraints_label": "Host-Modell-Grenzen",
            "sources_label": "Source-Contract",
        }
    return {
        "title": "# Canonical connector capabilities",
        "intro": (
            "This file is rendered deterministically from the six connector-local "
            "manifests. It describes host boundaries and implementation states; it "
            "does not promote any capability to `verified` without canonical run evidence."
            if runtime_evidence is None
            else "This file merges unchanged connector-local source contracts with fully "
            "validated canonical No-CRS evidence. Only capabilities evidenced by the "
            "canonical results are promoted to `verified` in this report view."
        ),
        "capability_heading": "## Capability matrix",
        "stage_heading": "## Evidence stages",
        "detail_heading": "## Connector details",
        "capability_label": "Capability",
        "stage_label": "Stage",
        "state_label": "State",
        "reason_label": (
            "Canonical reason (from manifest)"
            if runtime_evidence is None
            else "Canonical reason"
        ),
        "constraints_label": "Host-model constraints",
        "sources_label": "Source contract",
    }


def _markdown_header(title: str, intro: str, german: bool) -> list[str]:
    if german:
        return [
            "> Generierte Datei – nicht manuell bearbeiten.",
            "",
            title,
            "",
            "**Sprache:** [English](connector-capabilities.generated.md) | Deutsch",
            "",
            "> Hinweis: Diese deutsche Datei ist eine übersetzte Begleitdatei zur "
            "generierten englischen Quelle. Maschinenlesbare Werte, Statusnamen, "
            "Pfade und Tabellen bleiben absichtlich unverändert.",
            "",
            intro,
            "",
        ]
    return [
        "> Generated file - do not edit manually.",
        "",
        title,
        "",
        "**Language:** English | [Deutsch](connector-capabilities.generated.de.md)",
        "",
        intro,
        "",
    ]


def _append_runtime_evidence_table(
    lines: list[str],
    runtime_evidence: dict[str, Any],
    display_names: dict[str, str],
    german: bool,
) -> None:
    heading = "## Aktuelle kanonische No-CRS-Evidence" if german else "## Current canonical No-CRS evidence"
    labels = (
        ("Connector", "Ergebnis", "Status", "Verifizierte Capabilities")
        if german
        else ("Connector", "Result", "Status", "Verified capabilities")
    )
    evidence_connectors = runtime_evidence.get("connectors", {})
    lines.extend([heading, "", "| " + " | ".join(labels) + " |", "|---|---|---|---|"])
    for connector in CONNECTORS:
        evidence = evidence_connectors.get(connector, {}) if isinstance(evidence_connectors, dict) else {}
        verified = evidence.get("capabilities_verified", []) if isinstance(evidence, dict) else []
        displayed = ", ".join(f"`{_markdown_cell(item)}`" for item in verified) or "-"
        result = _markdown_cell(evidence.get("result", "-")) if isinstance(evidence, dict) else "-"
        status = _markdown_cell(evidence.get("result_status", "-")) if isinstance(evidence, dict) else "-"
        lines.append(
            "| "
            + " | ".join([display_names[connector], f"`{result}`", f"`{status}`", displayed])
            + " |"
        )


def render_markdown(
    manifests: dict[str, dict[str, Any]],
    *,
    german: bool,
    runtime_evidence: dict[str, Any] | None = None,
) -> str:
    labels = _markdown_labels(german, runtime_evidence)
    display_names = {
        "apache": "Apache",
        "nginx": "NGINX",
        "haproxy": "HAProxy",
        "envoy": "Envoy",
        "traefik": "Traefik",
        "lighttpd": "lighttpd",
    }
    lines = _markdown_header(labels["title"], labels["intro"], german)
    if runtime_evidence is not None:
        _append_runtime_evidence_table(lines, runtime_evidence, display_names, german)
        lines.extend(["", labels["capability_heading"], ""])
    else:
        lines.extend([labels["capability_heading"], ""])
    connector_headers = [display_names[name] for name in CONNECTORS]
    lines.append(
        "| " + " | ".join([labels["capability_label"], *connector_headers]) + " |"
    )
    lines.append("|" + "---|" * (len(CONNECTORS) + 1))
    for capability in CAPABILITY_NAMES:
        values = [
            manifests[name]["capabilities"][capability]["state"]
            for name in CONNECTORS
        ]
        lines.append(
            "| "
            + " | ".join([f"`{capability}`", *[f"`{value}`" for value in values]])
            + " |"
        )

    lines.extend(["", labels["stage_heading"], ""])
    lines.append("| " + " | ".join([labels["stage_label"], *connector_headers]) + " |")
    lines.append("|" + "---|" * (len(CONNECTORS) + 1))
    for stage in EVIDENCE_STAGES:
        values = [
            manifests[name]["evidence_stages"][stage]["status"]
            for name in CONNECTORS
        ]
        lines.append(
            "| "
            + " | ".join([f"`{stage}`", *[f"`{value}`" for value in values]])
            + " |"
        )

    lines.extend(["", labels["detail_heading"], ""])
    for connector in CONNECTORS:
        manifest = manifests[connector]
        lines.extend(
            [
                f"### {display_names[connector]}",
                "",
                f"- Host: `{_markdown_cell(manifest['host_name'])}`",
                f"- Integration: `{_markdown_cell(manifest['integration_mode'])}`",
                f"- Metadata: `{_markdown_cell(manifest['metadata_source'])}`",
                f"- {labels['sources_label']}: "
                + ", ".join(
                    f"`{_markdown_cell(path)}`" for path in manifest["source_contract"]
                ),
                "",
                f"{labels['constraints_label']}:",
                "",
            ]
        )
        lines.extend(
            f"- {_markdown_cell(constraint)}"
            for constraint in manifest["host_model_constraints"]
        )
        lines.extend(
            [
                "",
                f"| {labels['capability_label']} | {labels['state_label']} | {labels['reason_label']} |",
                "|---|---|---|",
            ]
        )
        for capability in CAPABILITY_NAMES:
            entry = manifest["capabilities"][capability]
            lines.append(
                f"| `{capability}` | `{entry['state']}` | "
                f"{_markdown_cell(entry['reason'])} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def generate(
    manifests: dict[str, dict[str, Any]],
    output_dir: Path,
    *,
    runtime_evidence: dict[str, Any] | None = None,
) -> list[Path]:
    payload = aggregate_payload(manifests, runtime_evidence=runtime_evidence)
    json_name = report_filename("connector_capabilities", "json")
    markdown_name = report_filename("connector_capabilities", "md")
    outputs = [
        output_dir / json_name,
        output_dir / markdown_name,
        output_dir / (markdown_name.removesuffix(".md") + ".de.md"),
    ]
    inputs = [f"connectors/{name}/capabilities.json" for name in CONNECTORS]
    metadata = build_metadata(
        generated_by="ci/evidence/collectors/connector_capabilities.py",
        make_target=(
            "capabilities-all-connectors-evidence"
            if runtime_evidence is not None
            else "capabilities-all-connectors"
        ),
        connector_root=ROOT,
        inputs=inputs,
        report_key="connector_capabilities",
        extra=(
            {
                "runtime_promotion": True,
                "canonical_evidence_run_id": runtime_evidence["run_id"],
                "canonical_evidence_stage": runtime_evidence["evidence_stage"],
            }
            if runtime_evidence is not None
            else None
        ),
    )
    # An evidence-backed view has one explicit, already validated run.  Do not
    # let an unrelated VERIFIED_RUN_ID inherited from another report workflow
    # make the generated header disagree with the selected evidence paths.
    if runtime_evidence is not None:
        metadata["verified_run_id"] = runtime_evidence["run_id"]
    _atomic_write(outputs[0], generated_json_text(payload, metadata))
    english_metadata = dict(metadata, output_name=outputs[1].name)
    german_metadata = dict(metadata, output_name=outputs[2].name)
    _atomic_write(
        outputs[1],
        generated_markdown_text(
            render_markdown(
                manifests,
                german=False,
                runtime_evidence=runtime_evidence,
            ),
            english_metadata,
        ),
    )
    _atomic_write(
        outputs[2],
        generated_markdown_text(
            render_markdown(
                manifests,
                german=True,
                runtime_evidence=runtime_evidence,
            ),
            german_metadata,
        ),
    )
    return outputs


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("check", help="validate all six connector manifests")
    generate_parser = subparsers.add_parser(
        "generate", help="validate manifests and render deterministic aggregate files"
    )
    generate_parser.add_argument(
        "--output-dir",
        type=Path,
        default=source_path('reports/testing/generated/canonical', root=ROOT),
    )
    generate_parser.add_argument(
        "--evidence-root",
        type=Path,
        help=(
            "aggregate canonical evidence root containing "
            "<connector>/<run-id>/result.json for all six connectors"
        ),
    )
    generate_parser.add_argument(
        "--run-id",
        help=(
            "explicit canonical No-CRS run id to merge; required with "
            "--evidence-root and never inferred from latest-run-id"
        ),
    )
    return parser


def _generate_report(
    args: argparse.Namespace, manifests: dict[str, dict[str, Any]]
) -> int:
    if (args.evidence_root is None) != (args.run_id is None):
        print(
            "connector_capabilities: --evidence-root and --run-id must be supplied together",
            file=sys.stderr,
        )
        return 2
    report_manifests = manifests
    runtime_evidence: dict[str, Any] | None = None
    if args.evidence_root is not None and args.run_id is not None:
        results, evidence_errors = load_validated_runtime_results(
            manifests,
            args.evidence_root.expanduser(),
            args.run_id,
        )
        if evidence_errors:
            for error in evidence_errors:
                print(f"connector_capabilities: {error}", file=sys.stderr)
            return 1
        try:
            report_manifests, runtime_evidence = merge_runtime_results(
                manifests,
                results,
                args.run_id,
            )
        except ValueError as exc:
            print(f"connector_capabilities: {exc}", file=sys.stderr)
            return 1
    output_dir = args.output_dir.resolve(strict=False)
    for output in generate(report_manifests, output_dir, runtime_evidence=runtime_evidence):
        print(f"connector_capabilities: wrote {output}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    manifests, errors = load_manifests()
    if errors:
        for error in errors:
            print(f"connector_capabilities: {error}", file=sys.stderr)
        return 1
    if args.command == "check":
        print(
            "connector_capabilities: ok "
            f"connectors={len(CONNECTORS)} capabilities={len(CAPABILITY_NAMES)}"
        )
        return 0
    if args.command == "generate":
        return _generate_report(args, manifests)
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
