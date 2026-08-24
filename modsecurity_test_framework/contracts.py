"""Stable public contracts for Framework test inventory and validation.

The module intentionally loads only a checked-in package resource at runtime.
It never imports a caller-selected module, discovers case files from the
current working directory, or exposes request/response payloads in its JSON
results or diagnostics.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
import copy
import errno
import importlib.resources
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any


SCHEMA_VERSION = 1
CONTRACT_ERROR_EXIT_CODE = 2
MAX_EXTERNAL_JSON_BYTES = 256 * 1024
MAX_PACKAGE_CATALOG_BYTES = 4 * 1024 * 1024
MAX_CATALOG_TESTS = 512
MAX_LIST_ITEMS = 128
MAX_STRING_LENGTH = 256
MAX_EXPECTATION_DEPTH = 4
IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_.:/-]{0,127}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

EXPECTATION_KINDS = frozenset(
    {
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
    }
)
ACTION_VALUES = frozenset(
    {"deny", "pass", "none", "redirect", "block", "drop", "abort_connection", "log_only"}
)
BODY_STATES = frozenset({"observed", "matched", "buffered", "streaming", "incremental", "absent", "redacted"})
TRANSPORT_STATES = frozenset(
    {
        "connection_aborted",
        "stream_reset",
        "http1",
        "http2",
        "http3",
        "keep_alive",
        "first_byte_before_response_end",
        "no_full_response_buffering",
    }
)
CLEANUP_STATES = frozenset({"balanced", "completed", "reused", "isolated"})
NOT_APPLICABLE_REASONS = frozenset(
    {
        "unsupported_by_host_model",
        "not_implemented",
        "connector_gap",
        "future_target",
        "runtime_difference",
    }
)
LIFECYCLE_PREDICATES = frozenset(
    {
        "host_started",
        "request_completed",
        "response_committed",
        "connection_reused",
        "transaction_isolated",
        "client_aborted",
        "upstream_aborted",
        "cleanup_balanced",
    }
)
CAPABILITY_STATES = frozenset(
    {
        "verified",
        "implemented_not_asserted",
        "configured_not_exercised",
        "unsupported_by_host_model",
        "not_implemented",
        "not_applicable",
    }
)
SELECTABLE_CAPABILITY_STATES = frozenset(
    {"verified", "implemented_not_asserted", "configured_not_exercised"}
)
SENSITIVE_RESULT_FIELDS = frozenset(
    {
        "authorization",
        "cookie",
        "password",
        "secret",
        "payload",
        "request_body",
        "response_body",
        "request_headers",
        "response_headers",
    }
)


class ContractError(ValueError):
    """Fail-closed public contract error with a stable, non-sensitive code."""

    def __init__(self, code: str = "contract_error") -> None:
        super().__init__(code)
        self.code = code


def _fail(code: str = "contract_error") -> None:
    raise ContractError(code)


def _is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _identifier(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not IDENTIFIER_RE.fullmatch(value)
        or ".." in value
        or "//" in value
    ):
        _fail("invalid_identifier")
    return value


def _text(value: Any, limit: int = MAX_STRING_LENGTH) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        _fail("invalid_text")
    return value


def _optional_identifier(value: Any) -> str | None:
    if value is None:
        return None
    return _identifier(value)


def _http_status(value: Any) -> int:
    if not _is_integer(value) or not 100 <= value <= 599:
        _fail("invalid_http_status")
    return value


def _rule_ids(value: Any) -> list[int]:
    if not isinstance(value, list) or not value or len(value) > MAX_LIST_ITEMS:
        _fail("invalid_rule_ids")
    result: list[int] = []
    for item in value:
        if not _is_integer(item) or not 1 <= item <= 9_999_999:
            _fail("invalid_rule_ids")
        result.append(item)
    if len(set(result)) != len(result):
        _fail("invalid_rule_ids")
    return sorted(result)


def _identifier_list(value: Any, code: str, *, minimum: int = 0) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= MAX_LIST_ITEMS:
        _fail(code)
    result = [_identifier(item) for item in value]
    if len(set(result)) != len(result):
        _fail(code)
    return sorted(result)


def _exact_fields(
    value: Mapping[str, Any],
    required: set[str],
    allowed: set[str],
) -> None:
    keys = set(value)
    if any(not isinstance(key, str) for key in keys) or not required.issubset(keys) or not keys.issubset(allowed):
        _fail("invalid_expectation_fields")


def _expectation_http_status(value: Mapping[str, Any], kind: str) -> dict[str, Any]:
    _exact_fields(value, {"kind", "http_status"}, {"kind", "http_status"})
    return {"kind": kind, "http_status": _http_status(value["http_status"])}


def _expectation_action(value: Mapping[str, Any], kind: str) -> dict[str, Any]:
    allowed = {"kind", "action", "http_status", "rule_ids"} if kind == "intervention" else {"kind", "action", "rule_ids"}
    _exact_fields(value, {"kind", "action"}, allowed)
    action = value["action"]
    if not isinstance(action, str) or action not in ACTION_VALUES:
        _fail("invalid_action")
    result: dict[str, Any] = {"kind": kind, "action": action}
    if "http_status" in value:
        result["http_status"] = _http_status(value["http_status"])
    if "rule_ids" in value:
        result["rule_ids"] = _rule_ids(value["rule_ids"])
    return result


def _expectation_rule_match(value: Mapping[str, Any], kind: str) -> dict[str, Any]:
    _exact_fields(value, {"kind", "rule_ids"}, {"kind", "rule_ids"})
    return {"kind": kind, "rule_ids": _rule_ids(value["rule_ids"])}


def _expectation_event(value: Mapping[str, Any], kind: str) -> dict[str, Any]:
    _exact_fields(value, {"kind"}, {"kind", "fields", "event_type"})
    if "fields" not in value and "event_type" not in value:
        _fail("invalid_event")
    result: dict[str, Any] = {"kind": kind}
    if "fields" in value:
        result["fields"] = _identifier_list(value["fields"], "invalid_event", minimum=1)
    if "event_type" in value:
        result["event_type"] = _identifier(value["event_type"])
    return result


def _expectation_headers(value: Mapping[str, Any], kind: str) -> dict[str, Any]:
    _exact_fields(value, {"kind", "names"}, {"kind", "names"})
    return {"kind": kind, "names": _identifier_list(value["names"], "invalid_header_names", minimum=1)}


def _expectation_state(value: Mapping[str, Any], kind: str) -> dict[str, Any]:
    _exact_fields(value, {"kind", "state"}, {"kind", "state"})
    state = value["state"]
    if kind in {"request_body", "response_body"}:
        allowed, code = BODY_STATES, "invalid_body_state"
    elif kind == "transport":
        allowed, code = TRANSPORT_STATES, "invalid_transport"
    else:
        allowed, code = CLEANUP_STATES, "invalid_cleanup"
    if not isinstance(state, str) or state not in allowed:
        _fail(code)
    return {"kind": kind, "state": state}


def _expectation_lifecycle(value: Mapping[str, Any], kind: str) -> dict[str, Any]:
    _exact_fields(value, {"kind", "predicates"}, {"kind", "predicates"})
    predicates = value["predicates"]
    if not isinstance(predicates, Mapping) or not predicates or len(predicates) > len(LIFECYCLE_PREDICATES):
        _fail("invalid_lifecycle")
    result: dict[str, bool] = {}
    for key, predicate in predicates.items():
        if key not in LIFECYCLE_PREDICATES or not isinstance(predicate, bool):
            _fail("invalid_lifecycle")
        result[key] = predicate
    return {"kind": kind, "predicates": dict(sorted(result.items()))}


def _expectation_compound(value: Mapping[str, Any], kind: str, depth: int) -> dict[str, Any]:
    _exact_fields(value, {"kind", "conditions"}, {"kind", "conditions"})
    conditions = value["conditions"]
    if not isinstance(conditions, list) or not 2 <= len(conditions) <= 16:
        _fail("invalid_compound")
    normalised = [_normalise_expectation(condition, depth + 1) for condition in conditions]
    fingerprints = {json.dumps(item, sort_keys=True, separators=(",", ":")) for item in normalised}
    if len(fingerprints) != len(normalised):
        _fail("invalid_compound")
    return {"kind": kind, "conditions": normalised}


def _expectation_not_applicable(value: Mapping[str, Any], kind: str) -> dict[str, Any]:
    _exact_fields(value, {"kind", "reason"}, {"kind", "reason"})
    reason = value["reason"]
    if not isinstance(reason, str) or reason not in NOT_APPLICABLE_REASONS:
        _fail("invalid_not_applicable")
    return {"kind": kind, "reason": reason}


def _normalise_expectation(value: Any, depth: int = 0) -> dict[str, Any]:
    if depth > MAX_EXPECTATION_DEPTH or not isinstance(value, Mapping):
        _fail("invalid_expectation")
    kind = value.get("kind")
    if not isinstance(kind, str) or kind not in EXPECTATION_KINDS:
        _fail("unknown_expectation_kind")
    handler = _EXPECTATION_HANDLERS[kind]
    if kind == "compound":
        return handler(value, kind, depth)
    return handler(value, kind)


_EXPECTATION_HANDLERS = {
    "http_status": _expectation_http_status,
    "intervention": _expectation_action,
    "action": _expectation_action,
    "rule_match": _expectation_rule_match,
    "event": _expectation_event,
    "request_headers": _expectation_headers,
    "response_headers": _expectation_headers,
    "request_body": _expectation_state,
    "response_body": _expectation_state,
    "transport": _expectation_state,
    "lifecycle": _expectation_lifecycle,
    "cleanup": _expectation_state,
    "compound": _expectation_compound,
    "not_applicable": _expectation_not_applicable,
}


def normalize_expectation(expectation: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return one canonical, closed tagged expectation union."""

    return _normalise_expectation(expectation)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_json_key")
        result[key] = value
    return result


def _parse_json_bytes(payload: bytes, maximum: int) -> Any:
    if not 0 < len(payload) <= maximum:
        _fail("invalid_input_size")
    try:
        text = payload.decode("utf-8")
        return json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
    except ContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("invalid_json")


def _relative_external_parts(path_value: str | Path) -> tuple[str, ...]:
    try:
        raw_path = os.fspath(path_value)
    except TypeError:
        _fail("invalid_input_path")
    if not isinstance(raw_path, str) or os.path.isabs(raw_path) or "\\" in raw_path or "\x00" in raw_path:
        _fail("invalid_input_path")
    parts = tuple(raw_path.split("/"))
    if not parts or any(part in {"", ".", ".."} for part in parts):
        _fail("invalid_input_path")
    return parts


def _read_relative_external_json(path_value: str | Path) -> Any:
    parts = _relative_external_parts(path_value)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    non_block = getattr(os, "O_NONBLOCK", 0)
    if not no_follow or not directory or not non_block:
        _fail("unavailable_no_follow")
    parent_descriptor: int | None = None
    try:
        parent_descriptor = os.open(".", os.O_RDONLY | directory | no_follow)
        for part in parts[:-1]:
            next_descriptor = os.open(
                part,
                os.O_RDONLY | directory | no_follow,
                dir_fd=parent_descriptor,
            )
            os.close(parent_descriptor)
            parent_descriptor = next_descriptor
        descriptor = os.open(parts[-1], os.O_RDONLY | no_follow | non_block, dir_fd=parent_descriptor)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            _fail("unsafe_input_path")
        _fail("invalid_input_path")
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_EXTERNAL_JSON_BYTES:
            _fail("invalid_input_size")
        chunks: list[bytes] = []
        remaining = MAX_EXTERNAL_JSON_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if before.st_dev != after.st_dev or before.st_ino != after.st_ino or len(payload) > MAX_EXTERNAL_JSON_BYTES:
            _fail("unsafe_input_path")
    finally:
        os.close(descriptor)
    return _parse_json_bytes(payload, MAX_EXTERNAL_JSON_BYTES)


def _load_raw_catalog() -> Mapping[str, Any]:
    try:
        resource = importlib.resources.files("modsecurity_test_framework").joinpath(
            "data/framework-contract-catalog.json"
        )
        payload = resource.read_bytes()
    except (ModuleNotFoundError, OSError):
        _fail("catalog_unavailable")
    data = _parse_json_bytes(payload, MAX_PACKAGE_CATALOG_BYTES)
    if not isinstance(data, Mapping):
        _fail("invalid_catalog")
    return data


def _relative_resource_path(value: Any) -> str:
    path = _text(value, 512)
    if path.startswith("/") or "\\" in path or any(part in {"", ".", ".."} for part in path.split("/")):
        _fail("invalid_catalog")
    return path


_RECORD_FIELDS = {
    "framework_test_id",
    "display_name",
    "scenario_category",
    "phase",
    "area",
    "profile",
    "required_capabilities",
    "expectation",
    "applicability",
    "catalogs",
    "sources",
}


def _normalise_record_applicability(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "portable",
        "requires_crs",
        "connector",
        "declared_status",
    }:
        _fail("invalid_catalog")
    portable = value["portable"]
    requires_crs = value["requires_crs"]
    if portable is not None and not isinstance(portable, bool):
        _fail("invalid_catalog")
    if requires_crs is not None and not isinstance(requires_crs, bool):
        _fail("invalid_catalog")
    return {
        "portable": portable,
        "requires_crs": requires_crs,
        "connector": _optional_identifier(value["connector"]),
        "declared_status": _optional_identifier(value["declared_status"]),
    }


def _normalise_record_sources(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value or len(value) > 16:
        _fail("invalid_catalog")
    result: list[dict[str, str]] = []
    for source in value:
        if not isinstance(source, Mapping) or set(source) != {"kind", "path"}:
            _fail("invalid_catalog")
        result.append({"kind": _identifier(source["kind"]), "path": _relative_resource_path(source["path"])})
    return result


def _normalise_record(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("invalid_catalog")
    if set(value) != _RECORD_FIELDS:
        _fail("invalid_catalog")
    phase = value["phase"]
    if phase is not None and (not _is_integer(phase) or not 0 <= phase <= 9):
        _fail("invalid_catalog")
    return {
        "framework_test_id": _identifier(value["framework_test_id"]),
        "display_name": _text(value["display_name"]),
        "scenario_category": _optional_identifier(value["scenario_category"]),
        "phase": phase,
        "area": _optional_identifier(value["area"]),
        "profile": _identifier(value["profile"]),
        "required_capabilities": _identifier_list(value["required_capabilities"], "invalid_catalog"),
        "expectation": normalize_expectation(value["expectation"]),
        "applicability": _normalise_record_applicability(value["applicability"]),
        "catalogs": _identifier_list(value["catalogs"], "invalid_catalog", minimum=1),
        "sources": _normalise_record_sources(value["sources"]),
    }


def _normalise_profile(value: Any, expected_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "profile",
        "fixture_id",
        "connectors",
        "required_capabilities",
        "expectation",
        "provenance",
    }:
        _fail("invalid_catalog")
    if _identifier(value["profile"]) != expected_name:
        _fail("invalid_catalog")
    provenance = value["provenance"]
    if not isinstance(provenance, Mapping) or set(provenance) != {
        "release_tag",
        "commit",
        "expected_rule_id",
    }:
        _fail("invalid_catalog")
    commit = provenance["commit"]
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        _fail("invalid_catalog")
    rule_id = provenance["expected_rule_id"]
    if not _is_integer(rule_id) or not 1 <= rule_id <= 9_999_999:
        _fail("invalid_catalog")
    return {
        "profile": expected_name,
        "fixture_id": _identifier(value["fixture_id"]),
        "connectors": _identifier_list(value["connectors"], "invalid_catalog", minimum=1),
        "required_capabilities": _identifier_list(value["required_capabilities"], "invalid_catalog"),
        "expectation": normalize_expectation(value["expectation"]),
        "provenance": {
            "release_tag": _identifier(provenance["release_tag"]),
            "commit": commit,
            "expected_rule_id": rule_id,
        },
    }


def _normalise_catalog(value: Mapping[str, Any]) -> dict[str, Any]:
    if set(value) != {"schema_version", "source_commit", "profiles", "tests"}:
        _fail("invalid_catalog")
    if value["schema_version"] != SCHEMA_VERSION:
        _fail("unsupported_schema_version")
    source_commit = value["source_commit"]
    if source_commit != "unavailable" and (not isinstance(source_commit, str) or not COMMIT_RE.fullmatch(source_commit)):
        _fail("invalid_catalog")
    raw_tests = value["tests"]
    if not isinstance(raw_tests, list) or not raw_tests or len(raw_tests) > MAX_CATALOG_TESTS:
        _fail("invalid_catalog")
    tests = [_normalise_record(record) for record in raw_tests]
    test_ids = [record["framework_test_id"] for record in tests]
    if len(set(test_ids)) != len(test_ids):
        _fail("duplicate_test_id")
    profiles = value["profiles"]
    if not isinstance(profiles, Mapping) or not profiles or len(profiles) > 16:
        _fail("invalid_catalog")
    normalised_profiles = {
        _identifier(profile_name): _normalise_profile(profile_value, _identifier(profile_name))
        for profile_name, profile_value in profiles.items()
    }
    if len(normalised_profiles) != len(profiles):
        _fail("duplicate_profile")
    return {
        "schema_version": SCHEMA_VERSION,
        "source_commit": source_commit,
        "profiles": normalised_profiles,
        "tests": tests,
    }


def _framework_commit(catalog: Mapping[str, Any]) -> str:
    root = Path(__file__).resolve().parent.parent
    if (root / ".git").exists():
        try:
            completed = subprocess.run(
                ("git", "-C", str(root), "rev-parse", "HEAD"),
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2,
                env={"PATH": os.defpath, "LC_ALL": "C", "GIT_OPTIONAL_LOCKS": "0"},
            )
        except (OSError, subprocess.TimeoutExpired):
            completed = None
        if completed is not None:
            candidate = completed.stdout.strip()
            if completed.returncode == 0 and COMMIT_RE.fullmatch(candidate):
                return candidate
    source_commit = catalog["source_commit"]
    return source_commit if source_commit != "unavailable" else "unavailable"


def _catalog_for(catalog_data: Mapping[str, Any] | None) -> dict[str, Any]:
    raw = _load_raw_catalog() if catalog_data is None else catalog_data
    if not isinstance(raw, Mapping):
        _fail("invalid_catalog")
    return _normalise_catalog(raw)


def _public_record(record: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(dict(record))
    expectation = result["expectation"]
    result["expectation_type"] = expectation["kind"]
    return result


def load_test_catalog(
    *,
    catalog: str = "all",
    profile: str | None = None,
    catalog_data: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return package-owned test metadata without loading caller paths."""

    if not isinstance(catalog, str) or catalog not in {"all", "no-crs-baseline", "framework-yaml"}:
        _fail("unknown_catalog")
    if profile is not None:
        _identifier(profile)
    data = _catalog_for(catalog_data)
    records = [
        record
        for record in data["tests"]
        if (catalog == "all" or catalog in record["catalogs"])
        and (profile is None or record["profile"] == profile)
    ]
    records.sort(key=lambda record: record["framework_test_id"])
    return {
        "schema_version": SCHEMA_VERSION,
        "framework_commit": _framework_commit(data),
        "catalog": catalog,
        "profile": profile or "all",
        "test_ids": [record["framework_test_id"] for record in records],
        "tests": [_public_record(record) for record in records],
    }


def describe_test(
    framework_test_id: str,
    *,
    catalog_data: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return canonical metadata for one real Framework test identifier."""

    test_id = _identifier(framework_test_id)
    data = _catalog_for(catalog_data)
    for record in data["tests"]:
        if record["framework_test_id"] == test_id:
            return {
                "schema_version": SCHEMA_VERSION,
                "framework_commit": _framework_commit(data),
                "framework_test_id": test_id,
                "profile": record["profile"],
                "expectation_type": record["expectation"]["kind"],
                "test": _public_record(record),
            }
    _fail("unknown_test_id")


def load_profile_contract(
    profile: str = "five-connectors-with-crs-no-mrts",
    *,
    catalog_data: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Load a closed, package-owned profile contract by its fixed name."""

    profile_name = _identifier(profile)
    data = _catalog_for(catalog_data)
    contract = data["profiles"].get(profile_name)
    if contract is None:
        _fail("unknown_profile")
    result = copy.deepcopy(contract)
    result.update(
        {
            "schema_version": SCHEMA_VERSION,
            "framework_commit": _framework_commit(data),
            "expectation_type": contract["expectation"]["kind"],
        }
    )
    return result


def _normalise_capability_manifest(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not {"schema_version", "connector", "capabilities"}.issubset(value):
        _fail("invalid_capability_manifest")
    if value["schema_version"] != SCHEMA_VERSION:
        _fail("unsupported_schema_version")
    capabilities = value["capabilities"]
    if not isinstance(capabilities, Mapping) or not capabilities or len(capabilities) > MAX_LIST_ITEMS:
        _fail("invalid_capability_manifest")
    normalised_capabilities: dict[str, str] = {}
    for name, declaration in capabilities.items():
        capability_name = _identifier(name)
        if not isinstance(declaration, Mapping) or "state" not in declaration:
            _fail("invalid_capability_manifest")
        state = declaration["state"]
        if not isinstance(state, str) or state not in CAPABILITY_STATES:
            _fail("invalid_capability_manifest")
        normalised_capabilities[capability_name] = state
    return {
        "schema_version": SCHEMA_VERSION,
        "connector": _identifier(value["connector"]),
        "capabilities": dict(sorted(normalised_capabilities.items())),
    }


def load_capability_manifest(source: Mapping[str, Any] | str | Path) -> dict[str, Any]:
    """Load a bounded, no-follow JSON capability manifest or mapping.

    A file source is intentionally relative to the explicit caller process;
    absolute paths, traversal, symlinks, special files, duplicate keys, and
    oversized documents are rejected before the manifest is parsed.
    """

    raw = source if isinstance(source, Mapping) else _read_relative_external_json(source)
    return _normalise_capability_manifest(raw)


def select_tests(
    capability_manifest: Mapping[str, Any] | str | Path,
    *,
    catalog: str = "no-crs-baseline",
    profile: str | None = None,
    catalog_data: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Select tests using the existing capability-state semantics."""

    manifest = load_capability_manifest(capability_manifest)
    inventory = load_test_catalog(catalog=catalog, profile=profile, catalog_data=catalog_data)
    selected_tests: list[dict[str, Any]] = []
    counts = {"selected": 0, "unsupported": 0, "not_applicable": 0, "not_executed": 0}
    for record in inventory["tests"]:
        states = {
            capability: manifest["capabilities"].get(capability, "not_applicable")
            for capability in record["required_capabilities"]
        }
        if any(state == "unsupported_by_host_model" for state in states.values()):
            selection_status = "unsupported"
        elif any(state == "not_applicable" for state in states.values()):
            selection_status = "not_applicable"
        elif any(state == "not_implemented" for state in states.values()):
            selection_status = "not_executed"
        elif all(state in SELECTABLE_CAPABILITY_STATES for state in states.values()):
            selection_status = "selected"
        else:
            selection_status = "not_executed"
        counts[selection_status] += 1
        selected_record = _public_record(record)
        selected_record["selection"] = {
            "status": selection_status,
            "required_capability_states": dict(sorted(states.items())),
        }
        selected_tests.append(selected_record)
    selected_ids = [
        record["framework_test_id"]
        for record in selected_tests
        if record["selection"]["status"] == "selected"
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "framework_commit": inventory["framework_commit"],
        "catalog": inventory["catalog"],
        "profile": inventory["profile"],
        "connector": manifest["connector"],
        "selected_test_ids": selected_ids,
        "counts": counts,
        "tests": selected_tests,
    }


_RESULT_FIELDS = {
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


def _normalise_result_scalar_fields(value: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if "http_status" in value:
        result["http_status"] = _http_status(value["http_status"])
    if "action" in value:
        if not isinstance(value["action"], str) or value["action"] not in ACTION_VALUES:
            _fail("invalid_result")
        result["action"] = value["action"]
    if "rule_ids" in value:
        result["rule_ids"] = _rule_ids(value["rule_ids"])
    if "event_fields" in value:
        result["event_fields"] = _identifier_list(value["event_fields"], "invalid_result", minimum=1)
    if "event_type" in value:
        result["event_type"] = _identifier(value["event_type"])
    return result


def _normalise_result_headers(value: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in ("request_header_names", "response_header_names"):
        if name in value:
            result[name] = _identifier_list(value[name], "invalid_result", minimum=1)
    return result


def _normalise_result_states(value: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in ("request_body_state", "response_body_state"):
        if name in value:
            state = value[name]
            if not isinstance(state, str) or state not in BODY_STATES:
                _fail("invalid_result")
            result[name] = state
    if "transport" in value:
        transport = value["transport"]
        if not isinstance(transport, str) or transport not in TRANSPORT_STATES:
            _fail("invalid_result")
        result["transport"] = transport
    if "cleanup" in value:
        cleanup = value["cleanup"]
        if not isinstance(cleanup, str) or cleanup not in CLEANUP_STATES:
            _fail("invalid_result")
        result["cleanup"] = cleanup
    if "applicability" in value:
        applicability = value["applicability"]
        if not isinstance(applicability, str) or applicability not in NOT_APPLICABLE_REASONS:
            _fail("invalid_result")
        result["applicability"] = applicability
    return result


def _normalise_result_lifecycle(value: Mapping[str, Any]) -> dict[str, Any]:
    if "lifecycle" not in value:
        return {}
    lifecycle = value["lifecycle"]
    if not isinstance(lifecycle, Mapping) or not lifecycle:
        _fail("invalid_result")
    result: dict[str, bool] = {}
    for key, predicate in lifecycle.items():
        if key not in LIFECYCLE_PREDICATES or not isinstance(predicate, bool):
            _fail("invalid_result")
        result[key] = predicate
    return {"lifecycle": dict(sorted(result.items()))}


def _normalise_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not value:
        _fail("invalid_result")
    keys = set(value)
    if any(key in SENSITIVE_RESULT_FIELDS for key in keys):
        _fail("sensitive_result_field")
    if any(not isinstance(key, str) for key in keys) or not keys.issubset(_RESULT_FIELDS):
        _fail("invalid_result")
    result = _normalise_result_scalar_fields(value)
    result.update(_normalise_result_headers(value))
    result.update(_normalise_result_states(value))
    result.update(_normalise_result_lifecycle(value))
    return result


def _match_compound(expectation: Mapping[str, Any], result: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []
    for condition in expectation["conditions"]:
        failures.extend(_match_expectation(condition, result))
    return failures


def _match_http_status(expectation: Mapping[str, Any], result: Mapping[str, Any]) -> list[str]:
    return [] if result.get("http_status") == expectation["http_status"] else ["http_status_mismatch"]


def _match_action(expectation: Mapping[str, Any], result: Mapping[str, Any]) -> list[str]:
    failures = [] if result.get("action") == expectation["action"] else ["action_mismatch"]
    if "http_status" in expectation and result.get("http_status") != expectation["http_status"]:
        failures.append("http_status_mismatch")
    if "rule_ids" in expectation and not set(expectation["rule_ids"]).issubset(result.get("rule_ids", [])):
        failures.append("rule_id_mismatch")
    return failures


def _match_rule_ids(expectation: Mapping[str, Any], result: Mapping[str, Any]) -> list[str]:
    return [] if set(expectation["rule_ids"]).issubset(result.get("rule_ids", [])) else ["rule_id_mismatch"]


def _match_event(expectation: Mapping[str, Any], result: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []
    if "fields" in expectation and not set(expectation["fields"]).issubset(result.get("event_fields", [])):
        failures.append("event_fields_mismatch")
    if "event_type" in expectation and result.get("event_type") != expectation["event_type"]:
        failures.append("event_type_mismatch")
    return failures


def _match_membership(expectation: Mapping[str, Any], result: Mapping[str, Any], field: str, code: str) -> list[str]:
    return [] if set(expectation["names"]).issubset(result.get(field, [])) else [code]


def _match_value(expectation: Mapping[str, Any], result: Mapping[str, Any], field: str, code: str) -> list[str]:
    return [] if result.get(field) == expectation["state"] else [code]


def _match_lifecycle(expectation: Mapping[str, Any], result: Mapping[str, Any]) -> list[str]:
    observed = result.get("lifecycle", {})
    return [] if all(observed.get(key) == value for key, value in expectation["predicates"].items()) else ["lifecycle_mismatch"]


def _match_applicability(expectation: Mapping[str, Any], result: Mapping[str, Any]) -> list[str]:
    return [] if result.get("applicability") == expectation["reason"] else ["applicability_mismatch"]


def _match_expectation(expectation: Mapping[str, Any], result: Mapping[str, Any]) -> list[str]:
    kind = expectation["kind"]
    return _MATCH_HANDLERS[kind](expectation, result)


_MATCH_HANDLERS = {
    "compound": _match_compound,
    "http_status": _match_http_status,
    "intervention": _match_action,
    "action": _match_action,
    "rule_match": _match_rule_ids,
    "event": _match_event,
    "request_headers": lambda expectation, result: _match_membership(
        expectation, result, "request_header_names", "request_headers_mismatch"
    ),
    "response_headers": lambda expectation, result: _match_membership(
        expectation, result, "response_header_names", "response_headers_mismatch"
    ),
    "request_body": lambda expectation, result: _match_value(
        expectation, result, "request_body_state", "request_body_mismatch"
    ),
    "response_body": lambda expectation, result: _match_value(
        expectation, result, "response_body_state", "response_body_mismatch"
    ),
    "transport": lambda expectation, result: _match_value(expectation, result, "transport", "transport_mismatch"),
    "lifecycle": _match_lifecycle,
    "cleanup": lambda expectation, result: _match_value(expectation, result, "cleanup", "cleanup_mismatch"),
    "not_applicable": _match_applicability,
}


def validate_test_result(
    framework_test_id: str,
    result: Mapping[str, Any],
    *,
    catalog_data: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate a bounded, payload-free result mapping for one Framework test."""

    description = describe_test(framework_test_id, catalog_data=catalog_data)
    observed = _normalise_result(result)
    failures = sorted(set(_match_expectation(description["test"]["expectation"], observed)))
    return {
        "schema_version": SCHEMA_VERSION,
        "framework_commit": description["framework_commit"],
        "framework_test_id": description["framework_test_id"],
        "profile": description["profile"],
        "expectation_type": description["expectation_type"],
        "valid": not failures,
        "failure_codes": failures,
    }


class _JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise ContractError("invalid_arguments")


def _parser() -> _JsonArgumentParser:
    parser = _JsonArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--help", action="store_true")
    subparsers = parser.add_subparsers(dest="command")
    inventory = subparsers.add_parser("inventory", add_help=False, allow_abbrev=False)
    inventory.add_argument("--catalog", default="all")
    inventory.add_argument("--profile")
    select = subparsers.add_parser("select", add_help=False, allow_abbrev=False)
    select.add_argument("--capabilities", required=True)
    select.add_argument("--catalog", default="no-crs-baseline")
    select.add_argument("--profile")
    validate = subparsers.add_parser("validate", add_help=False, allow_abbrev=False)
    validate.add_argument("--test-id", required=True)
    validate.add_argument("--result", required=True)
    describe = subparsers.add_parser("describe", add_help=False, allow_abbrev=False)
    describe.add_argument("--test-id", required=True)
    return parser


def _emit(payload: Mapping[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")


def _help_payload() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "commands": ["inventory", "select", "validate", "describe"],
        "contract_error_exit_code": CONTRACT_ERROR_EXIT_CODE,
    }


def main(argv: list[str] | None = None) -> int:
    """Run the JSON-only public module CLI."""

    try:
        args = _parser().parse_args(argv)
        if args.help:
            _emit(_help_payload())
            return 0
        if args.command == "inventory":
            payload = load_test_catalog(catalog=args.catalog, profile=args.profile)
        elif args.command == "select":
            payload = select_tests(args.capabilities, catalog=args.catalog, profile=args.profile)
        elif args.command == "validate":
            raw_result = _read_relative_external_json(args.result)
            if not isinstance(raw_result, Mapping):
                _fail("invalid_result")
            payload = validate_test_result(args.test_id, raw_result)
        elif args.command == "describe":
            payload = describe_test(args.test_id)
        else:
            _fail("invalid_arguments")
    except ContractError as exc:
        _emit({"schema_version": SCHEMA_VERSION, "error": {"code": exc.code}})
        return CONTRACT_ERROR_EXIT_CODE
    except (BrokenPipeError, KeyboardInterrupt):
        return 1
    except Exception:
        _emit({"schema_version": SCHEMA_VERSION, "error": {"code": "internal_error"}})
        return 1
    _emit(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
