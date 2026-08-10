#!/usr/bin/env python3
"""Fail-closed five-connector With-CRS/No-MRTS evidence contract.

This Framework tool validates supplied host-evidence records.  It does not
start a connector host, cryptographically authenticate a host producer, or
make a host-runtime PASS claim.  A later Parent composition run supplies the
five host-owned adapters and their immutable raw evidence under the private
evidence root.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import sys
from typing import Any, Mapping

import yaml

from no_crs_baseline import (
    ContractError,
    assert_no_symlink_components,
    git_value,
    git_worktree_clean,
    load_json,
    open_directory_chain,
    reject_duplicate_json_keys,
    secure_read_text,
)


PROFILE = "five-connectors-with-crs-no-mrts"
SCHEMA_VERSION = 1
CONNECTORS = ("apache", "haproxy", "envoy", "traefik", "lighttpd")
CRS_REPOSITORY = "https://github.com/coreruleset/coreruleset.git"
CRS_RELEASE_TAG = "v4.28.0"
CRS_COMMIT = "55b09f5acfd16413e7b31041100711ceb7adc89c"
CRS_RULE_FILE = "rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"
CRS_RULE_FILE_SHA256 = (
    "db756f71e8270280c5ae74d09c11250fad8c118f6a905c6a6794d5643d27cd00"
)
EXPECTED_RULE_ID = 942270
FIXTURE_ID = "crs_sqli_anomaly_block"
ALLOW_PATH = "/?id=42"
BLOCK_PATH = "/?id=1%20UNION%20SELECT%20password%20FROM%20users"
CORRELATION_HEADER = "X-Framework-Run-ID"
NORMALIZED_EVIDENCE_LABEL = "normalized evidence"
CANONICAL_BLOCK_REQUEST_LABEL = "canonical_block.request"
HOST_CONFIGURATION_LABEL = "event.host_configuration"
ALLOW_CASE_LABEL = "event.allow_case"
BLOCK_EVIDENCE_LABEL = "event.block_evidence"
CLEANUP_LABEL = "event.cleanup"
RESULT_FILE_NAME = "result.json"
FRAMEWORK_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_PATH = FRAMEWORK_ROOT / "tests/cases/security/crs/crs_sqli_anomaly_block.yaml"
SCHEMA_DIRECTORY = FRAMEWORK_ROOT / "tests/schemas/five-connectors-with-crs-no-mrts"
EVENT_SCHEMA_PATH = SCHEMA_DIRECTORY / "normalized-event.schema.json"
MANIFEST_SCHEMA_PATH = SCHEMA_DIRECTORY / "manifest.schema.json"
RECEIPT_SCHEMA_PATH = SCHEMA_DIRECTORY / "receipt.schema.json"
RESULT_SCHEMA_PATH = SCHEMA_DIRECTORY / "result.schema.json"
CONTRACT_VALIDATED = "CONTRACT_VALIDATED"

# These identifiers are the closed host-contract names.  They are not dynamic
# plugin paths and do not cause Python or shell dispatch from evidence input.
ADAPTERS: dict[str, dict[str, Any]] = {
    "apache": {
        "adapter_id": "apache-native-httpd-module",
        "integration_mode": "native-httpd-module",
        "framework_entrypoint": "ci/runtime/run-apache-smoke.sh",
        "framework_entrypoint_role": "compatibility-only",
        "host_contract_owner": "parent",
        "evidence_types": ("audit",),
    },
    "haproxy": {
        "adapter_id": "haproxy-native-htx-filter",
        "integration_mode": "native-htx-filter",
        "framework_entrypoint": "ci/runtime/run-haproxy-smoke.sh",
        "framework_entrypoint_role": "compatibility-only",
        "host_contract_owner": "parent",
        "evidence_types": ("event",),
    },
    "envoy": {
        "adapter_id": "envoy-ext-proc-service",
        "integration_mode": "ext_proc",
        "framework_entrypoint": "ci/runtime/run-envoy-smoke.sh",
        "framework_entrypoint_role": "compatibility-only",
        "host_contract_owner": "parent",
        "evidence_types": ("event",),
    },
    "traefik": {
        "adapter_id": "traefik-native-middleware",
        "integration_mode": "native-traefik-middleware",
        "framework_entrypoint": "ci/runtime/run-traefik-smoke.sh",
        "framework_entrypoint_role": "compatibility-only",
        "host_contract_owner": "parent",
        "evidence_types": ("event",),
    },
    "lighttpd": {
        "adapter_id": "lighttpd-patched-native-module",
        "integration_mode": "patched-native-lighttpd",
        "framework_entrypoint": "ci/runtime/run-lighttpd-smoke.sh",
        "framework_entrypoint_role": "compatibility-only",
        "host_contract_owner": "parent",
        "evidence_types": ("audit", "event"),
    },
}
EXPECTED_FRAMEWORK_ENTRYPOINTS = {
    "apache": "ci/runtime/run-apache-smoke.sh",
    "haproxy": "ci/runtime/run-haproxy-smoke.sh",
    "envoy": "ci/runtime/run-envoy-smoke.sh",
    "traefik": "ci/runtime/run-traefik-smoke.sh",
    "lighttpd": "ci/runtime/run-lighttpd-smoke.sh",
}

RULE_FINGERPRINTS = (
    "@rx (?i)union.*?select.*?from",
    "id:942270",
    "Looking for basic sql injection. Common attack string for mysql, oracle and others",
    "ver:'OWASP_CRS/4.28.0'",
)
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
FRAMEWORK_ENTRYPOINT = re.compile(
    r"ci/runtime/run-(?:apache|haproxy|envoy|traefik|lighttpd)-smoke\.sh\Z"
)
RAW_RECORD_KEY = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_CRS_RULE_FILE_BYTES = 2 * 1024 * 1024
NO_MRTS_FIELDS = {
    "runner_invoked",
    "case_inventory_loaded",
    "process_started",
    "socket_or_listener_created",
    "artifact_used",
}
CLEANUP_FIELDS = {
    "status",
    "host_processes_remaining",
    "helper_processes_remaining",
    "listeners_remaining",
    "sockets_remaining",
    "pid_files_remaining",
    "runtime_fixtures_remaining",
    "temporary_paths_remaining",
    "evidence_path",
    "evidence_sha256",
}
HOST_CONFIGURATION_FIELDS = {
    "config_test_status",
    "host_start_status",
    "evidence_path",
    "evidence_sha256",
}
ALLOW_FIELDS = {
    "fixture_id",
    "run_id",
    "request_id",
    "transaction_id",
    "expected_status",
    "observed_status",
    "observed_rule_id",
    "evidence_path",
    "evidence_sha256",
}
BLOCK_EVIDENCE_FIELDS = {"evidence_path", "evidence_sha256"}
EVENT_FIELDS = {
    "schema_version",
    "profile",
    "connector",
    "adapter_id",
    "integration_mode",
    "fixture_id",
    "run_id",
    "framework_commit",
    "connector_commit",
    "request_id",
    "transaction_id",
    "evidence_type",
    "evidence_origin",
    "crs_repository",
    "crs_release_tag",
    "crs_commit",
    "crs_rule_file",
    "crs_rule_file_sha256",
    "crs_source_kind",
    "crs_git_ref",
    "expected_rule_id",
    "observed_rule_id",
    "expected_status",
    "observed_status",
    "intervention",
    "allow_case",
    "host_configuration",
    "block_evidence",
    "no_mrts",
    "cleanup",
    "status",
    "failure_count",
    "mismatch_count",
}
MANIFEST_FIELDS = {
    "schema_version",
    "profile",
    "connector",
    "adapter_id",
    "integration_mode",
    "framework_entrypoint",
    "framework_entrypoint_role",
    "host_contract_owner",
    "fixture_id",
    "framework_commit",
    "connector_commit",
    "validation_status",
    "host_runtime_status",
    "crs_repository",
    "crs_release_tag",
    "crs_commit",
    "crs_rule_file",
    "crs_rule_file_sha256",
    "run_id",
    "expected_rule_id",
    "observed_rule_id",
    "expected_status",
    "observed_status",
    "request_id",
    "transaction_id",
    "evidence_type",
    "artifacts",
    "no_mrts",
    "cleanup",
}
RECEIPT_FIELDS = {
    "schema_version",
    "profile",
    "connector",
    "framework_commit",
    "connector_commit",
    "validation_status",
    "host_runtime_status",
    "crs_commit",
    "fixture_id",
    "expected_rule_id",
    "observed_rule_id",
    "run_id",
    "request_id",
    "transaction_id",
    "evidence_hashes",
    "no_mrts_status",
    "cleanup_status",
    "manifest_sha256",
}
RESULT_FIELDS = {
    "schema_version",
    "profile",
    "connector",
    "run_id",
    "status",
    "validation_status",
    "host_runtime_status",
    "expected_rule_id",
    "observed_rule_id",
    "expected_status",
    "observed_status",
    "failure_count",
    "mismatch_count",
    "no_mrts_status",
    "cleanup_status",
    "manifest_sha256",
    "receipt_sha256",
}
AGGREGATE_FIELDS = {
    "schema_version",
    "profile",
    "run_id",
    "status",
    "host_runtime_status",
    "connectors",
    "results",
}


def _contract_error(message: str) -> ContractError:
    return ContractError(f"{PROFILE}: {message}")


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _contract_error(f"{label} must be an object")
    return value


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise _contract_error(f"{label} must be a list")
    return value


def _text(value: object, label: str, *, pattern: re.Pattern[str] = TOKEN) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise _contract_error(f"{label} is invalid")
    return value


def _sha256(value: object, label: str) -> str:
    return _text(value, label, pattern=SHA256)


def _commit(value: object, label: str) -> str:
    return _text(value, label, pattern=COMMIT)


def _integer(value: object, label: str, *, expected: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _contract_error(f"{label} must be an integer")
    if expected is not None and value != expected:
        raise _contract_error(f"{label} must equal {expected}")
    return value


def _zero(value: object, label: str) -> None:
    _integer(value, label, expected=0)


def _exact(value: object, expected: object, label: str) -> None:
    if value != expected:
        raise _contract_error(f"{label} must equal {expected!r}")


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise _contract_error(
            f"{label} keys must be exactly {sorted(expected)!r}, got {sorted(actual)!r}"
        )


def _closed_connectors(value: object, label: str) -> tuple[str, ...]:
    members = tuple(_list(value, label))
    if members != CONNECTORS:
        raise _contract_error(f"{label} must be exactly {list(CONNECTORS)!r}")
    return CONNECTORS


def _private_directory(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise _contract_error(f"{label} must be absolute: {path}")
    assert_no_symlink_components(path)
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise _contract_error(f"cannot inspect {label}: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise _contract_error(f"{label} must be a directory: {path}")
    if metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise _contract_error(f"{label} must not be group/world accessible: {path}")
    try:
        path.relative_to(FRAMEWORK_ROOT)
    except ValueError:
        return path
    raise _contract_error(f"{label} must not be inside the Framework checkout: {path}")


def _source_directory(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise _contract_error(f"{label} must be absolute: {path}")
    assert_no_symlink_components(path)
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise _contract_error(f"cannot inspect {label}: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise _contract_error(f"{label} must be a directory: {path}")
    return path


def _source_directory_identity(
    path: Path, label: str
) -> tuple[int, int, int, int, int]:
    """Return a no-follow directory identity for a source snapshot check."""
    _source_directory(path, label)
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise _contract_error(f"cannot inspect {label} identity: {exc}") from exc
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def verifier_framework_commit() -> str:
    """Return the exact clean checkout commit of this verifier, never caller input."""
    commit = git_value(FRAMEWORK_ROOT, "rev-parse", "HEAD")
    _commit(commit, "Framework verifier commit")
    if not git_worktree_clean(FRAMEWORK_ROOT):
        raise _contract_error("Framework verifier checkout must be clean")
    return commit


def _schema_reference(
    schema: Mapping[str, Any], root: Mapping[str, Any], label: str
) -> Mapping[str, Any]:
    reference = schema.get("$ref")
    if not isinstance(reference, str) or not reference.startswith("#/"):
        raise _contract_error(f"{label} has an unsupported schema reference")
    resolved: object = root
    for component in reference.removeprefix("#/").split("/"):
        if not isinstance(resolved, Mapping):
            raise _contract_error(f"{label} has an invalid schema reference")
        resolved = resolved.get(component.replace("~1", "/").replace("~0", "~"))
    return _mapping(resolved, f"{label} schema reference")


def _matches_schema_type(value: object, type_name: str) -> bool:
    return {
        "object": isinstance(value, Mapping),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(type_name, False)


def _validate_json_schema_instance(
    value: object,
    schema: Mapping[str, Any],
    label: str,
    root: Mapping[str, Any],
) -> None:
    """Validate the deliberately small checked-in JSON-Schema subset we use.

    Keeping this validator local avoids an undeclared runtime dependency while
    making the versioned schema an active control instead of documentation.
    The schema is trusted repository input and supports only closed structural
    keywords used by this contract.
    """
    if "$ref" in schema:
        if set(schema) != {"$ref"}:
            raise _contract_error(
                f"{label} schema reference cannot have sibling keywords"
            )
        _validate_json_schema_instance(
            value, _schema_reference(schema, root, label), label, root
        )
        return
    _validate_json_schema_value_constraints(value, schema, label)
    if isinstance(value, Mapping):
        _validate_json_schema_mapping(value, schema, label, root)
    if isinstance(value, list) and "items" in schema:
        item_schema = _mapping(schema["items"], f"{label} item schema")
        for index, item in enumerate(value):
            _validate_json_schema_instance(item, item_schema, f"{label}[{index}]", root)


def _validate_json_schema_value_constraints(
    value: object, schema: Mapping[str, Any], label: str
) -> None:
    if "const" in schema and value != schema["const"]:
        raise _contract_error(f"{label} does not match its schema constant")
    enumeration = schema.get("enum")
    if enumeration is not None:
        if not isinstance(enumeration, list) or value not in enumeration:
            raise _contract_error(f"{label} is not one of its schema values")
    schema_type = schema.get("type")
    if schema_type is not None:
        allowed_types = [schema_type] if isinstance(schema_type, str) else schema_type
        if (
            not isinstance(allowed_types, list)
            or not allowed_types
            or not all(isinstance(item, str) for item in allowed_types)
            or not any(_matches_schema_type(value, item) for item in allowed_types)
        ):
            raise _contract_error(f"{label} does not match its schema type")
    if isinstance(value, str) and "pattern" in schema:
        pattern = schema["pattern"]
        if not isinstance(pattern, str):
            raise _contract_error(f"{label} schema pattern is invalid")
        try:
            valid = re.search(pattern, value) is not None
        except re.error as exc:
            raise _contract_error(f"{label} schema pattern is invalid: {exc}") from exc
        if not valid:
            raise _contract_error(f"{label} does not match its schema pattern")


def _validate_json_schema_mapping(
    value: Mapping[str, Any],
    schema: Mapping[str, Any],
    label: str,
    root: Mapping[str, Any],
) -> None:
    required = schema.get("required", [])
    if not isinstance(required, list) or not all(
        isinstance(item, str) for item in required
    ):
        raise _contract_error(f"{label} schema required fields are invalid")
    if len(set(required)) != len(required):
        raise _contract_error(f"{label} schema repeats required fields")
    missing = [item for item in required if item not in value]
    if missing:
        raise _contract_error(f"{label} is missing schema-required fields: {missing!r}")
    properties = _mapping(schema.get("properties", {}), f"{label} schema properties")
    if schema.get("additionalProperties") is False:
        extra = set(value).difference(properties)
        if extra:
            raise _contract_error(
                f"{label} has schema-forbidden fields: {sorted(extra)!r}"
            )
    for name, property_schema in properties.items():
        if name in value:
            _validate_json_schema_instance(
                value[name],
                _mapping(property_schema, f"{label}.{name} schema"),
                f"{label}.{name}",
                root,
            )


def _load_event_schema() -> Mapping[str, Any]:
    schema = _mapping(load_json(EVENT_SCHEMA_PATH), "normalized event schema")
    _exact(schema.get("type"), "object", "normalized event schema.type")
    _exact(
        schema.get("additionalProperties"),
        False,
        "normalized event schema.additionalProperties",
    )
    required = schema.get("required")
    if (
        not isinstance(required, list)
        or set(required) != EVENT_FIELDS
        or len(required) != len(EVENT_FIELDS)
    ):
        raise _contract_error(
            "normalized event schema required fields drift from the validator"
        )
    properties = _mapping(
        schema.get("properties"), "normalized event schema.properties"
    )
    if set(properties) != EVENT_FIELDS:
        raise _contract_error(
            "normalized event schema properties drift from the validator"
        )
    connector_schema = _mapping(
        properties.get("connector"), "normalized event schema.connector"
    )
    _exact(
        connector_schema.get("enum"),
        list(CONNECTORS),
        "normalized event schema.connector.enum",
    )
    definitions = _mapping(schema.get("$defs"), "normalized event schema definitions")
    for name in (
        "token",
        "commit",
        "sha256",
        "evidence_reference",
        "allow_case",
        "host_configuration",
        "block_evidence",
        "no_mrts",
        "cleanup",
    ):
        _mapping(definitions.get(name), f"normalized event schema definition {name}")
    return schema


def _validate_event_schema(event: Mapping[str, Any]) -> None:
    schema = _load_event_schema()
    _validate_json_schema_instance(event, schema, NORMALIZED_EVIDENCE_LABEL, schema)


def _load_output_schema(
    path: Path,
    label: str,
    fields: set[str],
    *,
    connector_scoped: bool,
) -> Mapping[str, Any]:
    schema = _mapping(load_json(path), label)
    _exact(schema.get("type"), "object", f"{label}.type")
    _exact(schema.get("additionalProperties"), False, f"{label}.additionalProperties")
    required = schema.get("required")
    if (
        not isinstance(required, list)
        or set(required) != fields
        or len(required) != len(fields)
    ):
        raise _contract_error(f"{label} required fields drift from the validator")
    properties = _mapping(schema.get("properties"), f"{label}.properties")
    _exact_keys(properties, fields, f"{label}.properties")
    _exact(
        _mapping(properties.get("schema_version"), f"{label}.schema_version").get(
            "const"
        ),
        SCHEMA_VERSION,
        f"{label}.schema_version.const",
    )
    _exact(
        _mapping(properties.get("profile"), f"{label}.profile").get("const"),
        PROFILE,
        f"{label}.profile.const",
    )
    if connector_scoped:
        connector_schema = _mapping(properties.get("connector"), f"{label}.connector")
        _exact(
            connector_schema.get("enum"), list(CONNECTORS), f"{label}.connector.enum"
        )
    return schema


def _validate_output_schema(
    payload: Mapping[str, Any],
    path: Path,
    label: str,
    fields: set[str],
    *,
    connector_scoped: bool,
) -> None:
    schema = _load_output_schema(path, label, fields, connector_scoped=connector_scoped)
    _validate_json_schema_instance(payload, schema, label, schema)


def _validate_adapter(connector: str) -> None:
    adapter = _mapping(ADAPTERS[connector], f"adapter {connector}")
    _exact_keys(
        adapter,
        {
            "adapter_id",
            "integration_mode",
            "framework_entrypoint",
            "framework_entrypoint_role",
            "host_contract_owner",
            "evidence_types",
        },
        f"adapter {connector}",
    )
    _text(adapter.get("adapter_id"), f"adapter {connector}.adapter_id")
    _text(adapter.get("integration_mode"), f"adapter {connector}.integration_mode")
    _exact(
        adapter.get("framework_entrypoint_role"),
        "compatibility-only",
        f"adapter {connector}.framework_entrypoint_role",
    )
    _exact(
        adapter.get("host_contract_owner"),
        "parent",
        f"adapter {connector}.host_contract_owner",
    )
    entrypoint = adapter.get("framework_entrypoint")
    if (
        not isinstance(entrypoint, str)
        or FRAMEWORK_ENTRYPOINT.fullmatch(entrypoint) is None
    ):
        raise _contract_error(f"adapter {connector}.framework_entrypoint is invalid")
    _exact(
        entrypoint,
        EXPECTED_FRAMEWORK_ENTRYPOINTS[connector],
        f"adapter {connector}.framework_entrypoint",
    )
    entrypoint_path = PurePosixPath(entrypoint)
    if entrypoint_path.is_absolute() or any(
        part in {"", ".", ".."} for part in entrypoint_path.parts
    ):
        raise _contract_error(f"adapter {connector}.framework_entrypoint is unsafe")
    source = FRAMEWORK_ROOT.joinpath(*entrypoint_path.parts)
    assert_no_symlink_components(source)
    try:
        metadata = source.stat(follow_symlinks=False)
    except OSError as exc:
        raise _contract_error(
            f"adapter {connector}.framework_entrypoint is missing: {exc}"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise _contract_error(
            f"adapter {connector}.framework_entrypoint must be a regular file"
        )
    evidence_types = adapter.get("evidence_types")
    if not isinstance(evidence_types, tuple) or not evidence_types:
        raise _contract_error(f"adapter {connector}.evidence_types is invalid")
    for evidence_type in evidence_types:
        _text(evidence_type, f"adapter {connector}.evidence_type")


def validate_profile() -> None:
    """Validate the checked-in, closed adapter inventory before any evidence use."""
    if tuple(ADAPTERS) != CONNECTORS:
        raise _contract_error(
            "adapter inventory is not the exact ordered five-connector set"
        )
    for connector in CONNECTORS:
        _validate_adapter(connector)
    _load_event_schema()
    _load_output_schema(
        MANIFEST_SCHEMA_PATH,
        "manifest schema",
        MANIFEST_FIELDS,
        connector_scoped=True,
    )
    _load_output_schema(
        RECEIPT_SCHEMA_PATH,
        "receipt schema",
        RECEIPT_FIELDS,
        connector_scoped=True,
    )
    _load_output_schema(
        RESULT_SCHEMA_PATH,
        "result schema",
        RESULT_FIELDS,
        connector_scoped=True,
    )


def _relative_path(value: object, root: Path, label: str) -> Path:
    if not isinstance(value, str):
        raise _contract_error(f"{label} must be a relative path")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise _contract_error(f"{label} is unsafe: {value!r}")
    candidate = root.joinpath(*relative.parts)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise _contract_error(f"{label} escapes the evidence root") from exc
    assert_no_symlink_components(candidate)
    try:
        metadata = candidate.stat(follow_symlinks=False)
    except OSError as exc:
        raise _contract_error(f"cannot inspect {label}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise _contract_error(f"{label} must reference a regular file")
    return candidate


def _read_bounded_regular_text(
    path: Path, label: str, *, max_bytes: int = MAX_EVIDENCE_BYTES
) -> tuple[str, str]:
    """Read and hash exactly one no-follow regular-file snapshot.

    Evidence and output artifacts may be writable by a concurrent process with
    the same UID.  Hashing a pathname and parsing a later pathname read would
    allow a rename between the two operations.  Keep one file descriptor open
    while collecting the bounded bytes, then derive both the decoded content
    and digest from that exact byte sequence.
    """
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise _contract_error(f"{label} has an unsafe input path: {path}")
    try:
        parent_descriptor = open_directory_chain(path.parent)
    except (ContractError, OSError) as exc:
        raise _contract_error(f"cannot open {label} parent directory: {exc}") from exc
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise _contract_error(f"{label} must reference a regular file")
        if not 0 < before.st_size <= max_bytes:
            raise _contract_error(f"{label} must be non-empty and bounded")
        remaining = max_bytes + 1
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, min(131072, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
            if remaining <= 0:
                raise _contract_error(f"{label} must be non-empty and bounded")
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise _contract_error(f"{label} changed while it was being read")
        if not 0 < len(data) <= max_bytes:
            raise _contract_error(f"{label} must be non-empty and bounded")
        try:
            content = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _contract_error(f"{label} is not valid UTF-8: {exc}") from exc
        return content, hashlib.sha256(data).hexdigest()
    except OSError as exc:
        raise _contract_error(f"cannot read {label}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)


def _read_json_snapshot(path: Path, label: str) -> tuple[Mapping[str, Any], str]:
    content, digest = _read_bounded_regular_text(path, label)
    try:
        payload = json.loads(content, object_pairs_hook=reject_duplicate_json_keys)
    except ValueError as exc:
        raise _contract_error(f"{label} is not valid JSON: {exc}") from exc
    return _mapping(payload, label), digest


def _read_yaml(path: Path) -> Mapping[str, Any]:
    try:
        loaded = yaml.safe_load(secure_read_text(path))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise _contract_error(f"cannot load canonical fixture {path}: {exc}") from exc
    return _mapping(loaded, "canonical fixture")


def load_fixture(path: Path = FIXTURE_PATH) -> Mapping[str, Any]:
    """Load and structurally validate the one checked-in canonical fixture."""
    validate_profile()
    fixture = _read_yaml(path)
    validate_fixture(fixture)
    return fixture


def _validate_request(value: object, label: str, *, path: str) -> Mapping[str, Any]:
    request = _mapping(value, label)
    _exact(request.get("method"), "GET", f"{label}.method")
    _exact(request.get("path"), path, f"{label}.path")
    _exact(request.get("body"), "", f"{label}.body")
    headers = _mapping(request.get("headers"), f"{label}.headers")
    _exact(headers, {"X-Framework-Run-ID": "{run_id}"}, f"{label}.headers")
    return request


def validate_fixture(fixture: Mapping[str, Any]) -> None:
    """Validate immutable fixture semantics independently of a host runtime."""
    _exact(fixture.get("fixture_id"), FIXTURE_ID, "fixture_id")
    _exact(fixture.get("requires_crs"), True, "requires_crs")
    if re.search(r"\bid\s*:\s*\d+", str(fixture.get("rules", "")), re.IGNORECASE):
        raise _contract_error("fixture must not define an artificial local rule ID")
    _exact(str(fixture.get("rules", "")).strip(), "SecRuleEngine On", "fixture rules")

    top_level_request = _mapping(fixture.get("request"), "request")
    _exact(top_level_request.get("method"), "GET", "request.method")
    _exact(
        top_level_request.get("path"),
        "/?id=1%20UNION%20SELECT%20password%20FROM%20users",
        "request.path",
    )
    expect = _mapping(fixture.get("expect"), "expect")
    _integer(expect.get("status"), "expect.status", expected=403)
    _exact(expect.get("intervention"), "deny", "expect.intervention")

    origins = _list(fixture.get("origin"), "origin")
    if not origins:
        raise _contract_error("origin must contain the official CRS source")
    origin = _mapping(origins[0], "origin[0]")
    _exact(origin.get("repo"), "coreruleset/coreruleset", "origin[0].repo")
    _exact(origin.get("path"), CRS_RULE_FILE, "origin[0].path")

    contract = _mapping(fixture.get("with_crs_no_mrts"), "with_crs_no_mrts")
    _exact(contract.get("schema_version"), 1, "with_crs_no_mrts.schema_version")
    _exact(contract.get("profile"), PROFILE, "with_crs_no_mrts.profile")
    _closed_connectors(contract.get("connectors"), "with_crs_no_mrts.connectors")
    allow = _mapping(contract.get("canonical_allow"), "canonical_allow")
    _validate_request(allow.get("request"), "canonical_allow.request", path="/?id=42")
    _integer(
        allow.get("expected_status"), "canonical_allow.expected_status", expected=200
    )

    block = _mapping(contract.get("canonical_block"), "canonical_block")
    _validate_request(
        block.get("request"),
        CANONICAL_BLOCK_REQUEST_LABEL,
        path=BLOCK_PATH,
    )
    _integer(
        block.get("expected_status"), "canonical_block.expected_status", expected=403
    )
    _exact(
        block.get("expected_intervention"),
        "deny",
        "canonical_block.expected_intervention",
    )
    _integer(
        block.get("expected_rule_id"),
        "canonical_block.expected_rule_id",
        expected=EXPECTED_RULE_ID,
    )
    _exact(block.get("crs_mode"), "enabled", "canonical_block.crs_mode")
    _exact(
        top_level_request.get("method"),
        _mapping(block.get("request"), CANONICAL_BLOCK_REQUEST_LABEL).get("method"),
        "canonical_block.request.method mirrors request",
    )
    _exact(
        top_level_request.get("path"),
        _mapping(block.get("request"), CANONICAL_BLOCK_REQUEST_LABEL).get("path"),
        "canonical_block.request.path mirrors request",
    )
    _integer(
        block.get("expected_status"),
        "canonical_block.expected_status",
        expected=expect["status"],
    )
    _exact(
        block.get("expected_intervention"),
        expect["intervention"],
        "canonical_block.expected_intervention mirrors expect",
    )

    provenance = _mapping(contract.get("provenance"), "provenance")
    _exact(provenance.get("repository"), CRS_REPOSITORY, "provenance.repository")
    _exact(provenance.get("release_tag"), CRS_RELEASE_TAG, "provenance.release_tag")
    _exact(provenance.get("commit"), CRS_COMMIT, "provenance.commit")
    _exact(provenance.get("rule_file"), CRS_RULE_FILE, "provenance.rule_file")
    _exact(
        provenance.get("rule_file_sha256"),
        CRS_RULE_FILE_SHA256,
        "provenance.rule_file_sha256",
    )
    expected_rule_id = _integer(
        provenance.get("expected_rule_id"), "provenance.expected_rule_id"
    )
    _integer(expected_rule_id, "provenance.expected_rule_id", expected=EXPECTED_RULE_ID)
    _exact(
        provenance.get("git_ref_mode"),
        "release-tag-peeled-to-commit",
        "provenance.git_ref_mode",
    )

    evidence = _mapping(contract.get("evidence"), "evidence")
    _exact(
        evidence.get("correlation_header"),
        "X-Framework-Run-ID",
        "evidence.correlation_header",
    )
    _exact(evidence.get("request_id"), "required", "evidence.request_id")
    _exact(evidence.get("transaction_id"), "required", "evidence.transaction_id")
    _exact(evidence.get("raw_evidence"), "hash-addressed", "evidence.raw_evidence")
    _exact(evidence.get("normalization"), "non-mutating", "evidence.normalization")
    _exact(evidence.get("no_mrts"), "required", "evidence.no_mrts")
    _exact(evidence.get("cleanup"), "required", "evidence.cleanup")


def _verify_fresh_crs_checkout(crs_source: Path) -> tuple[int, int, int, int, int]:
    """Verify Git provenance and detect a source-directory replacement."""
    identity = _source_directory_identity(crs_source, "fresh CRS source")
    if git_value(crs_source, "rev-parse", "--is-inside-work-tree") != "true":
        raise _contract_error("fresh CRS source must be a Git checkout")
    if git_value(crs_source, "rev-parse", "HEAD") != CRS_COMMIT:
        raise _contract_error(
            "fresh CRS source is not checked out at the approved commit"
        )
    if git_value(crs_source, "config", "--get", "remote.origin.url") != CRS_REPOSITORY:
        raise _contract_error("fresh CRS source does not have the approved origin")
    if (
        git_value(crs_source, "rev-parse", f"refs/tags/{CRS_RELEASE_TAG}^{{}}")
        != CRS_COMMIT
    ):
        raise _contract_error(
            "approved CRS release tag does not peel to the approved commit"
        )
    if not git_worktree_clean(crs_source):
        raise _contract_error("fresh CRS source is not clean")
    if git_value(crs_source, "submodule", "status", "--recursive") != "":
        raise _contract_error(
            "fresh CRS source must not contain initialized submodules"
        )
    if git_value(crs_source, "show", "HEAD:.gitmodules") not in {"", "unknown"}:
        raise _contract_error(
            "fresh CRS source must not contain a populated .gitmodules file"
        )
    if _source_directory_identity(crs_source, "fresh CRS source") != identity:
        raise _contract_error(
            "fresh CRS source changed while provenance was being checked"
        )
    return identity


def verify_fixture_source(fixture: Mapping[str, Any], source_root: Path) -> Path:
    """Verify the target rule in the fresh source root prepared by fetch-crs."""
    validate_fixture(fixture)
    rule_file = CRS_RULE_FILE
    expected_sha256 = CRS_RULE_FILE_SHA256
    expected_rule_id = EXPECTED_RULE_ID
    source_root = _source_directory(source_root, "source_root")
    source_root_identity = _source_directory_identity(source_root, "source_root")
    if tuple(sorted(entry.name for entry in source_root.iterdir())) != ("coreruleset",):
        raise _contract_error(
            "fresh CRS source root must contain only the canonical coreruleset checkout"
        )
    crs_source = source_root / "coreruleset"
    crs_source_identity = _verify_fresh_crs_checkout(crs_source)
    rule_path = crs_source.joinpath(*Path(rule_file).parts)
    assert_no_symlink_components(rule_path)
    source, actual_sha256 = _read_bounded_regular_text(
        rule_path,
        "pinned CRS rule file",
        max_bytes=MAX_CRS_RULE_FILE_BYTES,
    )
    if actual_sha256 != expected_sha256:
        raise _contract_error(
            "pinned CRS rule file digest does not match the canonical fixture"
        )
    rule_id_fingerprint = f"id:{expected_rule_id}"
    fingerprints = tuple(
        rule_id_fingerprint if fingerprint == f"id:{EXPECTED_RULE_ID}" else fingerprint
        for fingerprint in RULE_FINGERPRINTS
    )
    missing = [fingerprint for fingerprint in fingerprints if fingerprint not in source]
    if missing:
        raise _contract_error(
            "pinned CRS source lacks the canonical Rule ID fingerprint"
        )
    if _source_directory_identity(source_root, "source_root") != source_root_identity:
        raise _contract_error(
            "fresh CRS source root changed while the rule was being checked"
        )
    if _verify_fresh_crs_checkout(crs_source) != crs_source_identity:
        raise _contract_error(
            "fresh CRS source changed while the rule was being checked"
        )
    return rule_path


def _raw_evidence_relative_path(connector: str, run_id: str, name: str) -> Path:
    return Path("raw") / connector / run_id / name


def host_configuration_relative_path(connector: str, run_id: str) -> Path:
    return _raw_evidence_relative_path(connector, run_id, "host-configuration.log")


def allow_evidence_relative_path(connector: str, run_id: str) -> Path:
    return _raw_evidence_relative_path(connector, run_id, "allow-request.log")


def block_evidence_relative_path(connector: str, run_id: str) -> Path:
    return _raw_evidence_relative_path(connector, run_id, "block-audit.log")


def cleanup_evidence_relative_path(connector: str, run_id: str) -> Path:
    return _raw_evidence_relative_path(connector, run_id, "cleanup.log")


def normalized_event_relative_path(connector: str, run_id: str) -> Path:
    return Path("normalized") / connector / run_id / "event.json"


def result_directory(evidence_root: Path, connector: str, run_id: str) -> Path:
    return evidence_root / "results" / connector / run_id


def _require_event_identity(
    event: Mapping[str, Any], connector: str, run_id: str, framework_commit: str
) -> None:
    adapter = ADAPTERS[connector]
    _exact(event.get("schema_version"), SCHEMA_VERSION, "event.schema_version")
    _exact(event.get("profile"), PROFILE, "event.profile")
    _exact(event.get("connector"), connector, "event.connector")
    _exact(event.get("adapter_id"), adapter["adapter_id"], "event.adapter_id")
    _exact(
        event.get("integration_mode"),
        adapter["integration_mode"],
        "event.integration_mode",
    )
    _exact(event.get("fixture_id"), FIXTURE_ID, "event.fixture_id")
    _exact(event.get("run_id"), run_id, "event.run_id")
    _exact(event.get("framework_commit"), framework_commit, "event.framework_commit")
    _commit(event.get("connector_commit"), "event.connector_commit")
    _text(event.get("request_id"), "event.request_id")
    _text(event.get("transaction_id"), "event.transaction_id")
    evidence_type = _text(event.get("evidence_type"), "event.evidence_type")
    if evidence_type not in adapter["evidence_types"]:
        raise _contract_error(f"event.evidence_type is not valid for {connector}")
    _exact(event.get("evidence_origin"), "connector-host", "event.evidence_origin")


def _require_crs_identity(event: Mapping[str, Any]) -> None:
    _exact(event.get("crs_repository"), CRS_REPOSITORY, "event.crs_repository")
    _exact(event.get("crs_release_tag"), CRS_RELEASE_TAG, "event.crs_release_tag")
    _exact(event.get("crs_commit"), CRS_COMMIT, "event.crs_commit")
    _exact(event.get("crs_rule_file"), CRS_RULE_FILE, "event.crs_rule_file")
    _exact(
        event.get("crs_rule_file_sha256"),
        CRS_RULE_FILE_SHA256,
        "event.crs_rule_file_sha256",
    )
    _exact(event.get("crs_source_kind"), "fresh", "event.crs_source_kind")
    _exact(event.get("crs_git_ref"), CRS_RELEASE_TAG, "event.crs_git_ref")
    _integer(
        event.get("expected_rule_id"),
        "event.expected_rule_id",
        expected=EXPECTED_RULE_ID,
    )
    _integer(
        event.get("observed_rule_id"),
        "event.observed_rule_id",
        expected=EXPECTED_RULE_ID,
    )
    _integer(event.get("expected_status"), "event.expected_status", expected=403)
    _integer(event.get("observed_status"), "event.observed_status", expected=403)
    _exact(event.get("intervention"), "deny", "event.intervention")


def _bounded_evidence_file(
    evidence_root: Path,
    value: object,
    label: str,
    expected_relative: Path,
    expected_keys: set[str],
) -> tuple[Path, str, str]:
    artifact = _mapping(value, label)
    _exact_keys(artifact, expected_keys, label)
    relative = _relative_path(
        artifact.get("evidence_path"), evidence_root, f"{label}.evidence_path"
    )
    if relative.relative_to(evidence_root) != expected_relative:
        raise _contract_error(
            f"{label}.evidence_path is not the canonical run-bound path"
        )
    content, digest = _read_bounded_regular_text(relative, label)
    _exact(
        _sha256(artifact.get("evidence_sha256"), f"{label}.evidence_sha256"),
        digest,
        f"{label}.evidence_sha256",
    )
    return relative, content, digest


def _record_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _require_evidence_record(
    content: str, label: str, expected: Mapping[str, object]
) -> None:
    """Parse one bounded, non-normalized adapter record with exact field binding."""
    fields: dict[str, str] = {}
    for line_number, line in enumerate(content.splitlines(), 1):
        name, separator, value = line.partition("=")
        if not separator or not RAW_RECORD_KEY.fullmatch(name) or not value:
            raise _contract_error(
                f"{label} has an invalid raw record line {line_number}"
            )
        if name in fields:
            raise _contract_error(f"{label} repeats raw record field {name!r}")
        fields[name] = value
    expected_fields = {name: _record_value(value) for name, value in expected.items()}
    _exact_keys(fields, set(expected_fields), f"{label} raw record")
    for name, value in expected_fields.items():
        _exact(fields.get(name), value, f"{label} raw record {name}")


def _require_host_configuration(
    evidence_root: Path,
    event: Mapping[str, Any],
    connector: str,
    run_id: str,
) -> tuple[Path, str]:
    configuration = _mapping(event.get("host_configuration"), HOST_CONFIGURATION_LABEL)
    _exact_keys(configuration, HOST_CONFIGURATION_FIELDS, HOST_CONFIGURATION_LABEL)
    _exact(
        configuration.get("config_test_status"),
        "passed",
        "event.host_configuration.config_test_status",
    )
    _exact(
        configuration.get("host_start_status"),
        "passed",
        "event.host_configuration.host_start_status",
    )
    path, content, digest = _bounded_evidence_file(
        evidence_root,
        configuration,
        HOST_CONFIGURATION_LABEL,
        host_configuration_relative_path(connector, run_id),
        HOST_CONFIGURATION_FIELDS,
    )
    _require_evidence_record(
        content,
        HOST_CONFIGURATION_LABEL,
        {
            "schema_version": SCHEMA_VERSION,
            "record_type": "host_configuration",
            "profile": PROFILE,
            "connector": connector,
            "integration_mode": ADAPTERS[connector]["integration_mode"],
            "run_id": run_id,
            "config_test_status": "passed",
            "host_start_status": "passed",
        },
    )
    return path, digest


def _require_allow_control(
    evidence_root: Path,
    event: Mapping[str, Any],
    connector: str,
    run_id: str,
) -> tuple[Path, str]:
    allow = _mapping(event.get("allow_case"), ALLOW_CASE_LABEL)
    _exact_keys(allow, ALLOW_FIELDS, ALLOW_CASE_LABEL)
    _exact(
        allow.get("fixture_id"), f"{FIXTURE_ID}:allow", "event.allow_case.fixture_id"
    )
    _exact(allow.get("run_id"), run_id, "event.allow_case.run_id")
    _text(allow.get("request_id"), "event.allow_case.request_id")
    _text(allow.get("transaction_id"), "event.allow_case.transaction_id")
    _integer(
        allow.get("expected_status"), "event.allow_case.expected_status", expected=200
    )
    _integer(
        allow.get("observed_status"), "event.allow_case.observed_status", expected=200
    )
    if allow.get("observed_rule_id") is not None:
        raise _contract_error("event.allow_case.observed_rule_id must be null")
    path, content, digest = _bounded_evidence_file(
        evidence_root,
        allow,
        ALLOW_CASE_LABEL,
        allow_evidence_relative_path(connector, run_id),
        ALLOW_FIELDS,
    )
    _require_evidence_record(
        content,
        ALLOW_CASE_LABEL,
        {
            "schema_version": SCHEMA_VERSION,
            "record_type": "allow_request",
            "profile": PROFILE,
            "connector": connector,
            "integration_mode": ADAPTERS[connector]["integration_mode"],
            "fixture_id": f"{FIXTURE_ID}:allow",
            "run_id": run_id,
            "request_id": allow["request_id"],
            "transaction_id": allow["transaction_id"],
            "method": "GET",
            "path": ALLOW_PATH,
            "correlation_header": CORRELATION_HEADER,
            "correlation_value": run_id,
            "payload_length": 0,
            "status": 200,
        },
    )
    return path, digest


def _require_block_evidence(
    evidence_root: Path,
    event: Mapping[str, Any],
    connector: str,
    run_id: str,
) -> tuple[Path, str]:
    block = _mapping(event.get("block_evidence"), BLOCK_EVIDENCE_LABEL)
    _exact_keys(block, BLOCK_EVIDENCE_FIELDS, BLOCK_EVIDENCE_LABEL)
    path, content, digest = _bounded_evidence_file(
        evidence_root,
        block,
        BLOCK_EVIDENCE_LABEL,
        block_evidence_relative_path(connector, run_id),
        BLOCK_EVIDENCE_FIELDS,
    )
    _require_evidence_record(
        content,
        BLOCK_EVIDENCE_LABEL,
        {
            "schema_version": SCHEMA_VERSION,
            "record_type": "block_audit",
            "profile": PROFILE,
            "connector": connector,
            "integration_mode": ADAPTERS[connector]["integration_mode"],
            "fixture_id": FIXTURE_ID,
            "run_id": run_id,
            "request_id": event["request_id"],
            "transaction_id": event["transaction_id"],
            "method": "GET",
            "path": BLOCK_PATH,
            "correlation_header": CORRELATION_HEADER,
            "correlation_value": run_id,
            "payload_length": 0,
            "expected_rule_id": EXPECTED_RULE_ID,
            "observed_rule_id": EXPECTED_RULE_ID,
            "expected_status": 403,
            "observed_status": 403,
            "intervention": "deny",
            "evidence_type": event["evidence_type"],
        },
    )
    return path, digest


def _require_no_mrts(event: Mapping[str, Any]) -> None:
    no_mrts = _mapping(event.get("no_mrts"), "event.no_mrts")
    _exact_keys(no_mrts, NO_MRTS_FIELDS, "event.no_mrts")
    for field in NO_MRTS_FIELDS:
        _exact(no_mrts.get(field), False, f"event.no_mrts.{field}")


def _require_cleanup(
    evidence_root: Path,
    event: Mapping[str, Any],
    connector: str,
    run_id: str,
) -> tuple[Path, str]:
    cleanup = _mapping(event.get("cleanup"), CLEANUP_LABEL)
    _exact_keys(cleanup, CLEANUP_FIELDS, CLEANUP_LABEL)
    _exact(cleanup.get("status"), "passed", "event.cleanup.status")
    for field in (
        "host_processes_remaining",
        "helper_processes_remaining",
        "listeners_remaining",
        "sockets_remaining",
        "pid_files_remaining",
        "runtime_fixtures_remaining",
        "temporary_paths_remaining",
    ):
        _zero(cleanup.get(field), f"event.cleanup.{field}")
    path, content, digest = _bounded_evidence_file(
        evidence_root,
        cleanup,
        CLEANUP_LABEL,
        cleanup_evidence_relative_path(connector, run_id),
        CLEANUP_FIELDS,
    )
    _require_evidence_record(
        content,
        CLEANUP_LABEL,
        {
            "schema_version": SCHEMA_VERSION,
            "record_type": "cleanup",
            "profile": PROFILE,
            "connector": connector,
            "run_id": run_id,
            "status": "passed",
            "host_processes_remaining": 0,
            "helper_processes_remaining": 0,
            "listeners_remaining": 0,
            "sockets_remaining": 0,
            "pid_files_remaining": 0,
            "runtime_fixtures_remaining": 0,
            "temporary_paths_remaining": 0,
            "mrts_runner_invoked": False,
            "mrts_case_inventory_loaded": False,
            "mrts_process_started": False,
            "mrts_socket_or_listener_created": False,
            "mrts_artifact_used": False,
        },
    )
    return path, digest


def _read_event(
    evidence_root: Path, connector: str, run_id: str
) -> tuple[Mapping[str, Any], Path, str]:
    normalized_relative = normalized_event_relative_path(connector, run_id)
    normalized_path = _relative_path(
        normalized_relative.as_posix(), evidence_root, "normalized evidence"
    )
    event, normalized_sha256 = _read_json_snapshot(
        normalized_path, "normalized evidence"
    )
    _exact_keys(event, EVENT_FIELDS, "normalized evidence")
    _validate_event_schema(event)
    return event, normalized_path, normalized_sha256


def _reserve_output_directory(path: Path, label: str) -> None:
    """Create a private output directory exactly once without following links.

    The evidence root is intentionally private, but concurrent jobs can still
    share its UID.  Reserve the final run directory with ``mkdir`` rather than
    checking and later replacing it, so a foreign same-run output is never
    overwritten.
    """
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise _contract_error(f"{label} has an unsafe output path: {path}")
    assert_no_symlink_components(path.parent)
    parent_descriptor = open_directory_chain(path.parent, create=True)
    child_descriptor: int | None = None
    try:
        try:
            os.mkdir(path.name, mode=0o700, dir_fd=parent_descriptor)
        except FileExistsError as exc:
            raise _contract_error(
                f"{label} already exists and will not be overwritten: {path}"
            ) from exc
        flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        child_descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
        metadata = os.fstat(child_descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise _contract_error(f"{label} must be a directory: {path}")
        if metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise _contract_error(f"{label} must remain private: {path}")
        os.fsync(parent_descriptor)
    except OSError as exc:
        raise _contract_error(f"could not reserve {label}: {path}: {exc}") from exc
    finally:
        if child_descriptor is not None:
            os.close(child_descriptor)
        os.close(parent_descriptor)


def _json_write(
    path: Path,
    payload: Mapping[str, Any],
    expected_fields: set[str],
    label: str,
    *,
    schema_path: Path | None = None,
    connector_scoped: bool = False,
) -> str:
    """Publish one JSON artifact with create-only hard-link semantics.

    ``os.replace`` would permit a same-UID race to replace a result after a
    preliminary existence check.  A temporary regular file followed by a
    hard-link to the final name is atomic and fails when the name already
    exists.  All paths are closed internal paths beneath a reserved run
    directory; untrusted evidence never supplies an output filename.
    """
    _exact_keys(payload, expected_fields, label)
    if schema_path is not None:
        _validate_output_schema(
            payload,
            schema_path,
            f"{label} schema",
            expected_fields,
            connector_scoped=connector_scoped,
        )
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise _contract_error(f"{label} has an unsafe output path: {path}")
    content = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    encoded = content.encode("utf-8")
    parent_descriptor = open_directory_chain(path.parent)
    temporary_name = f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(16)}"
    temporary_descriptor: int | None = None
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        temporary_descriptor = os.open(
            temporary_name, flags, 0o600, dir_fd=parent_descriptor
        )
        with os.fdopen(temporary_descriptor, "wb") as handle:
            temporary_descriptor = None
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(
                temporary_name,
                path.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise _contract_error(
                f"{label} already exists and will not be overwritten: {path}"
            ) from exc
        os.fsync(parent_descriptor)
        return hashlib.sha256(encoded).hexdigest()
    except OSError as exc:
        raise _contract_error(
            f"secure create-only write failed for {path}: {exc}"
        ) from exc
    finally:
        if temporary_descriptor is not None:
            os.close(temporary_descriptor)
        try:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        os.close(parent_descriptor)


def _validate_host_evidence(
    evidence_root: Path,
    connector: str,
    run_id: str,
    framework_commit: str,
    fixture: Mapping[str, Any],
    source_root: Path,
) -> tuple[Mapping[str, Any], Mapping[str, Mapping[str, str]]]:
    """Validate bounded host input without assigning it a host-runtime PASS."""
    validate_profile()
    if connector not in ADAPTERS:
        raise _contract_error(f"connector is not in the closed profile: {connector}")
    _text(run_id, "run_id")
    _commit(framework_commit, "framework_commit")
    _private_directory(evidence_root, "evidence_root")
    verify_fixture_source(fixture, source_root)
    event, normalized_path, normalized_sha256 = _read_event(
        evidence_root,
        connector,
        run_id,
    )
    _exact(event.get("status"), "PASS", "event.status")
    _zero(event.get("failure_count"), "event.failure_count")
    _zero(event.get("mismatch_count"), "event.mismatch_count")
    _require_event_identity(event, connector, run_id, framework_commit)
    _require_crs_identity(event)
    host_configuration_path, host_configuration_sha256 = _require_host_configuration(
        evidence_root,
        event,
        connector,
        run_id,
    )
    allow_path, allow_sha256 = _require_allow_control(
        evidence_root, event, connector, run_id
    )
    block_path, block_sha256 = _require_block_evidence(
        evidence_root, event, connector, run_id
    )
    _require_no_mrts(event)
    cleanup_path, cleanup_sha256 = _require_cleanup(
        evidence_root, event, connector, run_id
    )
    artifacts = {
        "host_configuration": {
            "path": host_configuration_path.relative_to(evidence_root).as_posix(),
            "sha256": host_configuration_sha256,
        },
        "allow_request": {
            "path": allow_path.relative_to(evidence_root).as_posix(),
            "sha256": allow_sha256,
        },
        "block_audit": {
            "path": block_path.relative_to(evidence_root).as_posix(),
            "sha256": block_sha256,
        },
        "cleanup": {
            "path": cleanup_path.relative_to(evidence_root).as_posix(),
            "sha256": cleanup_sha256,
        },
        "normalized_event": {
            "path": normalized_path.relative_to(evidence_root).as_posix(),
            "sha256": normalized_sha256,
        },
    }
    return event, artifacts


def validate_connector_run(
    evidence_root: Path,
    connector: str,
    run_id: str,
    fixture: Mapping[str, Any],
    source_root: Path,
) -> Mapping[str, Any]:
    """Validate one host input and write non-promoting contract artifacts.

    The result proves only that the fixed Framework contract structurally
    validates the supplied bounded evidence.  It intentionally never becomes
    a connector-host runtime PASS; that assertion belongs to the later trusted
    Parent composition boundary.
    """
    framework_commit = verifier_framework_commit()
    event, artifacts = _validate_host_evidence(
        evidence_root,
        connector,
        run_id,
        framework_commit,
        fixture,
        source_root,
    )

    output = result_directory(evidence_root, connector, run_id)
    _reserve_output_directory(output, f"result directory for {connector}")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "connector": connector,
        "adapter_id": ADAPTERS[connector]["adapter_id"],
        "integration_mode": ADAPTERS[connector]["integration_mode"],
        "framework_entrypoint": ADAPTERS[connector]["framework_entrypoint"],
        "framework_entrypoint_role": ADAPTERS[connector]["framework_entrypoint_role"],
        "host_contract_owner": ADAPTERS[connector]["host_contract_owner"],
        "fixture_id": FIXTURE_ID,
        "framework_commit": framework_commit,
        "connector_commit": event["connector_commit"],
        "validation_status": CONTRACT_VALIDATED,
        "host_runtime_status": "UNATTESTED",
        "crs_repository": CRS_REPOSITORY,
        "crs_release_tag": CRS_RELEASE_TAG,
        "crs_commit": CRS_COMMIT,
        "crs_rule_file": CRS_RULE_FILE,
        "crs_rule_file_sha256": CRS_RULE_FILE_SHA256,
        "run_id": run_id,
        "expected_rule_id": EXPECTED_RULE_ID,
        "observed_rule_id": EXPECTED_RULE_ID,
        "expected_status": 403,
        "observed_status": 403,
        "request_id": event["request_id"],
        "transaction_id": event["transaction_id"],
        "evidence_type": event["evidence_type"],
        "artifacts": artifacts,
        "no_mrts": event["no_mrts"],
        "cleanup": event["cleanup"],
    }
    manifest_path = output / "manifest.json"
    manifest_sha256 = _json_write(
        manifest_path,
        manifest,
        MANIFEST_FIELDS,
        f"{connector} manifest",
        schema_path=MANIFEST_SCHEMA_PATH,
        connector_scoped=True,
    )
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "connector": connector,
        "framework_commit": framework_commit,
        "connector_commit": event["connector_commit"],
        "validation_status": CONTRACT_VALIDATED,
        "host_runtime_status": "UNATTESTED",
        "crs_commit": CRS_COMMIT,
        "fixture_id": FIXTURE_ID,
        "expected_rule_id": EXPECTED_RULE_ID,
        "observed_rule_id": EXPECTED_RULE_ID,
        "run_id": run_id,
        "request_id": event["request_id"],
        "transaction_id": event["transaction_id"],
        "evidence_hashes": {
            name: artifact["sha256"] for name, artifact in artifacts.items()
        },
        "no_mrts_status": "passed",
        "cleanup_status": "passed",
        "manifest_sha256": manifest_sha256,
    }
    receipt_path = output / "receipt.json"
    receipt_sha256 = _json_write(
        receipt_path,
        receipt,
        RECEIPT_FIELDS,
        f"{connector} receipt",
        schema_path=RECEIPT_SCHEMA_PATH,
        connector_scoped=True,
    )
    result = {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "connector": connector,
        "run_id": run_id,
        "status": CONTRACT_VALIDATED,
        "validation_status": CONTRACT_VALIDATED,
        "host_runtime_status": "UNATTESTED",
        "expected_rule_id": EXPECTED_RULE_ID,
        "observed_rule_id": EXPECTED_RULE_ID,
        "expected_status": 403,
        "observed_status": 403,
        "failure_count": 0,
        "mismatch_count": 0,
        "no_mrts_status": "passed",
        "cleanup_status": "passed",
        "manifest_sha256": manifest_sha256,
        "receipt_sha256": receipt_sha256,
    }
    result_path = output / RESULT_FILE_NAME
    _json_write(
        result_path,
        result,
        RESULT_FIELDS,
        f"{connector} result",
        schema_path=RESULT_SCHEMA_PATH,
        connector_scoped=True,
    )
    return result


def _bundle(
    root: Path,
    connector: str,
    run_id: str,
    event: Mapping[str, Any],
    expected_artifacts: Mapping[str, Mapping[str, str]],
    framework_commit: str,
) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any], Mapping[str, str]]:
    output = result_directory(root, connector, run_id)
    _source_directory(output, f"result directory for {connector}")
    result, result_sha256 = _read_json_snapshot(
        output / RESULT_FILE_NAME, f"{connector} result"
    )
    manifest, manifest_sha256 = _read_json_snapshot(
        output / "manifest.json", f"{connector} manifest"
    )
    receipt, receipt_sha256 = _read_json_snapshot(
        output / "receipt.json", f"{connector} receipt"
    )
    _exact_keys(result, RESULT_FIELDS, f"{connector} result")
    _exact_keys(manifest, MANIFEST_FIELDS, f"{connector} manifest")
    _exact_keys(receipt, RECEIPT_FIELDS, f"{connector} receipt")
    _validate_output_schema(
        manifest,
        MANIFEST_SCHEMA_PATH,
        f"{connector} manifest schema",
        MANIFEST_FIELDS,
        connector_scoped=True,
    )
    _validate_output_schema(
        receipt,
        RECEIPT_SCHEMA_PATH,
        f"{connector} receipt schema",
        RECEIPT_FIELDS,
        connector_scoped=True,
    )
    _validate_output_schema(
        result,
        RESULT_SCHEMA_PATH,
        f"{connector} result schema",
        RESULT_FIELDS,
        connector_scoped=True,
    )
    _exact(result.get("status"), CONTRACT_VALIDATED, f"{connector} result.status")
    _exact(
        result.get("host_runtime_status"),
        "UNATTESTED",
        f"{connector} result.host_runtime_status",
    )
    _exact(result.get("profile"), PROFILE, f"{connector} result.profile")
    _exact(result.get("connector"), connector, f"{connector} result.connector")
    _exact(result.get("run_id"), run_id, f"{connector} result.run_id")
    _zero(result.get("failure_count"), f"{connector} result.failure_count")
    _zero(result.get("mismatch_count"), f"{connector} result.mismatch_count")
    _exact(result.get("no_mrts_status"), "passed", f"{connector} result.no_mrts_status")
    _exact(result.get("cleanup_status"), "passed", f"{connector} result.cleanup_status")
    _integer(
        result.get("expected_rule_id"),
        f"{connector} result.expected_rule_id",
        expected=EXPECTED_RULE_ID,
    )
    _integer(
        result.get("observed_rule_id"),
        f"{connector} result.observed_rule_id",
        expected=EXPECTED_RULE_ID,
    )
    _integer(
        result.get("expected_status"),
        f"{connector} result.expected_status",
        expected=403,
    )
    _integer(
        result.get("observed_status"),
        f"{connector} result.observed_status",
        expected=403,
    )
    _exact(
        result.get("validation_status"),
        CONTRACT_VALIDATED,
        f"{connector} result.validation_status",
    )
    _exact(receipt.get("profile"), PROFILE, f"{connector} receipt.profile")
    _exact(receipt.get("connector"), connector, f"{connector} receipt.connector")
    _exact(receipt.get("run_id"), run_id, f"{connector} receipt.run_id")
    _integer(
        receipt.get("expected_rule_id"),
        f"{connector} receipt.expected_rule_id",
        expected=EXPECTED_RULE_ID,
    )
    _integer(
        receipt.get("observed_rule_id"),
        f"{connector} receipt.observed_rule_id",
        expected=EXPECTED_RULE_ID,
    )
    _exact(
        receipt.get("no_mrts_status"), "passed", f"{connector} receipt.no_mrts_status"
    )
    _exact(
        receipt.get("cleanup_status"), "passed", f"{connector} receipt.cleanup_status"
    )
    _exact(
        receipt.get("validation_status"),
        CONTRACT_VALIDATED,
        f"{connector} receipt.validation_status",
    )
    _exact(
        receipt.get("host_runtime_status"),
        "UNATTESTED",
        f"{connector} receipt.host_runtime_status",
    )
    _exact(
        receipt.get("manifest_sha256"),
        manifest_sha256,
        f"{connector} receipt.manifest_sha256",
    )
    _exact(
        result.get("manifest_sha256"),
        manifest_sha256,
        f"{connector} result.manifest_sha256",
    )
    _exact(
        result.get("receipt_sha256"),
        receipt_sha256,
        f"{connector} result.receipt_sha256",
    )
    _exact(manifest.get("profile"), PROFILE, f"{connector} manifest.profile")
    _exact(manifest.get("connector"), connector, f"{connector} manifest.connector")
    _exact(manifest.get("run_id"), run_id, f"{connector} manifest.run_id")
    _exact(
        manifest.get("framework_entrypoint"),
        ADAPTERS[connector]["framework_entrypoint"],
        f"{connector} manifest.framework_entrypoint",
    )
    _exact(
        manifest.get("framework_entrypoint_role"),
        "compatibility-only",
        f"{connector} manifest.framework_entrypoint_role",
    )
    _exact(
        manifest.get("host_contract_owner"),
        "parent",
        f"{connector} manifest.host_contract_owner",
    )
    _exact(
        manifest.get("validation_status"),
        CONTRACT_VALIDATED,
        f"{connector} manifest.validation_status",
    )
    _exact(
        manifest.get("host_runtime_status"),
        "UNATTESTED",
        f"{connector} manifest.host_runtime_status",
    )
    _exact(
        manifest.get("framework_commit"),
        framework_commit,
        f"{connector} manifest.framework_commit",
    )
    _exact(
        receipt.get("framework_commit"),
        framework_commit,
        f"{connector} receipt.framework_commit",
    )
    _exact(
        manifest.get("connector_commit"),
        event.get("connector_commit"),
        f"{connector} manifest.connector_commit",
    )
    _exact(
        receipt.get("connector_commit"),
        event.get("connector_commit"),
        f"{connector} receipt.connector_commit",
    )
    _exact(
        manifest.get("request_id"),
        event.get("request_id"),
        f"{connector} manifest.request_id",
    )
    _exact(
        receipt.get("request_id"),
        event.get("request_id"),
        f"{connector} receipt.request_id",
    )
    _exact(
        manifest.get("transaction_id"),
        event.get("transaction_id"),
        f"{connector} manifest.transaction_id",
    )
    _exact(
        receipt.get("transaction_id"),
        event.get("transaction_id"),
        f"{connector} receipt.transaction_id",
    )
    artifacts = _mapping(manifest.get("artifacts"), f"{connector} manifest.artifacts")
    _exact_keys(artifacts, set(expected_artifacts), f"{connector} manifest.artifacts")
    hashes = _mapping(
        receipt.get("evidence_hashes"), f"{connector} receipt.evidence_hashes"
    )
    _exact_keys(hashes, set(expected_artifacts), f"{connector} receipt.evidence_hashes")
    for name, expected in expected_artifacts.items():
        artifact = _mapping(
            artifacts.get(name), f"{connector} manifest artifact {name}"
        )
        _exact_keys(
            artifact, {"path", "sha256"}, f"{connector} manifest artifact {name}"
        )
        _exact(
            artifact.get("path"),
            expected["path"],
            f"{connector} manifest artifact {name}.path",
        )
        _exact(
            artifact.get("sha256"),
            expected["sha256"],
            f"{connector} manifest artifact {name}.sha256",
        )
        _exact(
            hashes.get(name),
            expected["sha256"],
            f"{connector} receipt artifact {name} hash",
        )
    return (
        result,
        manifest,
        receipt,
        {
            "result_sha256": result_sha256,
            "manifest_sha256": manifest_sha256,
            "receipt_sha256": receipt_sha256,
        },
    )


def aggregate(
    evidence_root: Path, run_id: str, fixture: Mapping[str, Any], source_root: Path
) -> Mapping[str, Any]:
    """Require and revalidate exactly five same-run non-promoting contract bundles."""
    _text(run_id, "run_id")
    _private_directory(evidence_root, "evidence_root")
    framework_commit = verifier_framework_commit()
    results_root = evidence_root / "results"
    _source_directory(results_root, "results root")
    assert_no_symlink_components(results_root)
    entries = tuple(sorted(path.name for path in results_root.iterdir()))
    if entries != tuple(sorted(CONNECTORS)):
        raise _contract_error(f"results root must contain exactly {list(CONNECTORS)!r}")
    bundles: dict[str, Mapping[str, Any]] = {}
    for connector in CONNECTORS:
        connector_root = results_root / connector
        _source_directory(connector_root, f"result root for {connector}")
        runs = tuple(sorted(path.name for path in connector_root.iterdir()))
        if runs != (run_id,):
            raise _contract_error(
                f"{connector} must contain exactly the requested run ID"
            )
        event, artifacts = _validate_host_evidence(
            evidence_root,
            connector,
            run_id,
            framework_commit,
            fixture,
            source_root,
        )
        result, manifest, receipt, output_hashes = _bundle(
            evidence_root,
            connector,
            run_id,
            event,
            artifacts,
            framework_commit,
        )
        bundles[connector] = {
            **output_hashes,
            "framework_commit": receipt["framework_commit"],
            "connector_commit": receipt["connector_commit"],
            "crs_commit": receipt["crs_commit"],
            "request_id": receipt["request_id"],
            "transaction_id": receipt["transaction_id"],
            "evidence_hashes": receipt["evidence_hashes"],
            "manifest": manifest,
            "result": result,
        }
    aggregate_directory = evidence_root / "aggregate" / run_id
    _reserve_output_directory(aggregate_directory, "aggregate result directory")
    aggregate_path = aggregate_directory / "result.json"
    payload = {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "run_id": run_id,
        "status": CONTRACT_VALIDATED,
        "host_runtime_status": "UNATTESTED",
        "connectors": list(CONNECTORS),
        "results": bundles,
    }
    _json_write(aggregate_path, payload, AGGREGATE_FIELDS, "aggregate result")
    return payload


def profile_payload() -> Mapping[str, Any]:
    validate_profile()
    return {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "connectors": list(CONNECTORS),
        "adapters": ADAPTERS,
        "fixture_id": FIXTURE_ID,
        "crs": {
            "repository": CRS_REPOSITORY,
            "release_tag": CRS_RELEASE_TAG,
            "commit": CRS_COMMIT,
            "rule_file": CRS_RULE_FILE,
            "rule_file_sha256": CRS_RULE_FILE_SHA256,
            "expected_rule_id": EXPECTED_RULE_ID,
        },
        "mrts": "disabled",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "profile", help="emit the fixed connector and adapter inventory"
    )

    fixture = commands.add_parser(
        "verify-fixture", help="verify the canonical fixture against a fresh CRS source"
    )
    fixture.add_argument("--source-root", type=Path, required=True)

    validate = commands.add_parser(
        "validate", help="validate one connector's host-produced evidence"
    )
    validate.add_argument("--evidence-root", type=Path, required=True)
    validate.add_argument("--source-root", type=Path, required=True)
    validate.add_argument("--connector", choices=CONNECTORS, required=True)
    validate.add_argument("--run-id", required=True)

    aggregate_parser = commands.add_parser(
        "aggregate", help="aggregate exactly five validated connector results"
    )
    aggregate_parser.add_argument("--evidence-root", type=Path, required=True)
    aggregate_parser.add_argument("--source-root", type=Path, required=True)
    aggregate_parser.add_argument("--run-id", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "profile":
            print(json.dumps(profile_payload(), indent=2, sort_keys=True))
            return 0
        fixture = load_fixture()
        if args.command == "verify-fixture":
            rule = verify_fixture_source(fixture, args.source_root)
            print(
                json.dumps(
                    {
                        "fixture_id": FIXTURE_ID,
                        "rule_file": str(rule),
                        "rule_id": EXPECTED_RULE_ID,
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "validate":
            result = validate_connector_run(
                args.evidence_root,
                args.connector,
                args.run_id,
                fixture,
                args.source_root,
            )
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.command == "aggregate":
            result = aggregate(
                args.evidence_root, args.run_id, fixture, args.source_root
            )
            print(json.dumps(result, sort_keys=True))
            return 0
    except ContractError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
