#!/usr/bin/env python3
"""Data-only preparation and evidence checks for the protected broker caller.

This helper is deliberately unprivileged.  In particular, a caller-provided
Parent SHA is checked only as a GitHub commit identity; it is never checked
out, imported, sourced, built, or executed.  Privileged NGINX work remains in
the separately pinned reusable broker workflow.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any
from urllib.request import Request, urlopen


PROTECTED_BROKER_SHA = "8ae707d72f1a8acb25d239e55e28a73cbc7522b1"
PROTECTED_FRAMEWORK_SHA = "99a7985c1be92a2297b1b59208f64df6768f2cbf"
PROJECT_GIT_COMMIT_API = (
    "https://api.github.com/repos/Easton97-Jens/ModSecurity-conector/git/commits/"
)
API_USER_AGENT = "ModSecurity-conector-protected-nginx-broker-caller"
TARGET_PARENT_SHA_LABEL = "target Parent SHA"
RUNNER_TEMP_ENVIRONMENT = "RUNNER_TEMP"
FIXED_RUN_PAIR_ERROR = "broker run IDs do not form the fixed caller pair"

SCHEMA_VERSION = 2
NO_CRS_VARIANT = "no-crs"
WITH_CRS_VARIANT = "with-crs"
NO_CRS_PROFILE = "no-crs"
OWASP_CRS_PROFILE = "owasp-crs"
PROFILE_BY_VARIANT = {
    NO_CRS_VARIANT: NO_CRS_PROFILE,
    WITH_CRS_VARIANT: OWASP_CRS_PROFILE,
}
CALLER_MANIFEST_FILENAME = "caller-manifest.json"
CALLER_RUN_ID_PREFIX = "protected-nginx-root-"
NO_CRS_RUN_ID_SUFFIX = "-no-crs"
WITH_CRS_RUN_ID_SUFFIX = "-with-crs"
CALLER_MANIFEST_ROOT_PREFIX = "protected-nginx-root-caller-"
CALLER_EVIDENCE_ROOT_PREFIX = "protected-nginx-root-evidence-"
CALLER_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "run_id",
        "matrix_variant",
        "parent_head_sha",
        "framework_sha",
        "protected_broker_sha",
        "policy_profile",
    }
)
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
TRANSACTION_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")

IDENTITY_FILENAME = "identity.json"
RUNTIME_FILENAME = "runtime.json"
POLICY_FILENAME = "policy.json"
ACCESS_LOG_FILENAME = "nginx-access.log"
ERROR_LOG_FILENAME = "nginx-error.log"
AUDIT_LOG_FILENAME = "nginx-audit.log"
CLEANUP_FILENAME = "cleanup.json"
NO_CRS_EVIDENCE_FILES = frozenset(
    {
        IDENTITY_FILENAME,
        RUNTIME_FILENAME,
        POLICY_FILENAME,
        ACCESS_LOG_FILENAME,
        ERROR_LOG_FILENAME,
        CLEANUP_FILENAME,
    }
)
WITH_CRS_EVIDENCE_FILES = frozenset((*NO_CRS_EVIDENCE_FILES, AUDIT_LOG_FILENAME))
MAX_JSON_BYTES = 64 * 1024
MAX_LOG_BYTES = 8 * 1024 * 1024

CRS_REPOSITORY = "https://github.com/coreruleset/coreruleset.git"
CRS_RELEASE_TAG = "v4.30.0"
CRS_COMMIT = "e03a4f6dabc7a30ebd8c52c97d28a154f590a48f"
NGINX_PINNED_VERSION = "1.31.4"
CRS_RULE_ID = "949110"
CRS_ALLOW_PATH = "/"
CRS_BLOCK_PATH = "/?id=1%20UNION%20SELECT%20password%20FROM%20users"
NO_CRS_SCOPE = "protected no-crs control profile; no CRS tuple is present"
WITH_CRS_SCOPE = (
    "protected OWASP CRS profile with broker-generated configuration and audit evidence"
)
CLEANUP_STATE = "stopped; mandatory descriptor-relative cleanup pending"


class CallerContractError(RuntimeError):
    """Raised when caller-controlled data or returned evidence violates its contract."""


def fail(message: str) -> None:
    raise CallerContractError(message)


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        fail(f"{label} must be a string")
    return value


def require_exact_fields(payload: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        fail(f"{label} must be a JSON object")
    observed = frozenset(payload)
    if observed != expected:
        missing = sorted(expected - observed)
        unknown = sorted(observed - expected)
        fail(f"{label} has unexpected fields; missing={missing!r} unknown={unknown!r}")
    return payload


def require_sha40(value: Any, label: str) -> str:
    candidate = require_string(value, label)
    if SHA40_RE.fullmatch(candidate) is None:
        fail(f"{label} must be exactly 40 lowercase hexadecimal characters")
    return candidate


def require_sha256(value: Any, label: str) -> str:
    candidate = require_string(value, label)
    if SHA256_RE.fullmatch(candidate) is None:
        fail(f"{label} must be exactly 64 lowercase hexadecimal characters")
    return candidate


def require_run_id(value: Any, label: str) -> str:
    candidate = require_string(value, label)
    if RUN_ID_RE.fullmatch(candidate) is None:
        fail(f"{label} is not a safe broker run identifier")
    return candidate


def require_fixed_run_pair(no_crs_run_id: str, with_crs_run_id: str) -> str:
    no_crs_value = require_run_id(no_crs_run_id, "no-CRS run ID")
    with_crs_value = require_run_id(with_crs_run_id, "OWASP CRS run ID")
    if not no_crs_value.startswith(CALLER_RUN_ID_PREFIX) or not no_crs_value.endswith(
        NO_CRS_RUN_ID_SUFFIX
    ):
        fail(FIXED_RUN_PAIR_ERROR)
    run_token = no_crs_value[len(CALLER_RUN_ID_PREFIX) : -len(NO_CRS_RUN_ID_SUFFIX)]
    if not run_token:
        fail(FIXED_RUN_PAIR_ERROR)
    if with_crs_value != f"{CALLER_RUN_ID_PREFIX}{run_token}{WITH_CRS_RUN_ID_SUFFIX}":
        fail(FIXED_RUN_PAIR_ERROR)
    return run_token


def trusted_runner_temp() -> Path:
    raw_path = os.environ.get(RUNNER_TEMP_ENVIRONMENT)
    if not raw_path:
        fail("RUNNER_TEMP is required for caller artifact paths")
    directory = Path(raw_path)
    if not directory.is_absolute():
        fail("RUNNER_TEMP must be an absolute directory")
    require_directory(directory, "trusted runner temporary directory")
    try:
        resolved = directory.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        fail(f"could not resolve RUNNER_TEMP: {exc}")
    if resolved != directory:
        fail("RUNNER_TEMP must be a canonical non-symlink directory")
    return directory


def validated_direct_child_path(parent: Path, child_name: str, label: str) -> Path:
    """Return one canonical direct non-symlink child before filesystem use."""
    if Path(child_name).name != child_name or child_name in {".", ".."}:
        fail(f"{label} name must select one direct child")
    require_directory(parent, f"{label} parent")
    try:
        resolved_parent = parent.resolve(strict=True)
        constructed_path = resolved_parent / child_name
        resolved_path = constructed_path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        fail(f"could not resolve {label} path: {exc}")
    try:
        resolved_path.relative_to(resolved_parent)
    except ValueError:
        fail(f"{label} escapes its trusted parent")
    if resolved_path != constructed_path or resolved_path.parent != resolved_parent:
        fail(f"{label} must be a direct non-symlink child of its trusted parent")
    return resolved_path


def caller_artifact_root(root_prefix: str, no_crs_run_id: str, with_crs_run_id: str) -> Path:
    run_token = require_fixed_run_pair(no_crs_run_id, with_crs_run_id)
    return validated_direct_child_path(
        trusted_runner_temp(),
        f"{root_prefix}{run_token}",
        "caller artifact root",
    )


def require_positive_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        fail(f"{label} must be an integer greater than or equal to {minimum}")
    return value


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON object contains the duplicate key {key!r}")
        result[key] = value
    return result


def parse_json_bytes(raw: bytes, label: str) -> Any:
    try:
        decoded = raw.decode("utf-8")
        return json.loads(decoded, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"{label} is not valid UTF-8 JSON: {exc}")


def require_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        fail(f"{label} is unavailable: {exc}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail(f"{label} must be a non-symlink directory")


def require_private_directory(path: Path, label: str) -> None:
    require_directory(path, label)
    metadata = path.lstat()
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail(f"{label} must have mode 0700")


def create_private_directory(path: Path, label: str) -> None:
    path = validated_direct_child_path(path.parent, path.name, label)
    if path.exists() or path.is_symlink():
        fail(f"{label} already exists")
    try:
        path.mkdir(mode=0o700)
    except OSError as exc:
        fail(f"could not create {label}: {exc}")
    require_private_directory(path, label)


def write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        offset += os.write(descriptor, raw[offset:])


def write_private_json(path: Path, payload: dict[str, Any], label: str) -> None:
    path = validated_direct_child_path(path.parent, path.name, label)
    if path.exists() or path.is_symlink():
        fail(f"{label} destination already exists")
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
    except OSError as exc:
        fail(f"could not create {label}: {exc}")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            fail(f"{label} has an unsafe file mode")
        write_all(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def read_regular_file(path: Path, label: str, maximum_size: int) -> bytes:
    path = validated_direct_child_path(path.parent, path.name, label)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        fail(f"could not open {label}: {exc}")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            fail(f"{label} must be a regular file")
        if metadata.st_size < 0 or metadata.st_size > maximum_size:
            fail(f"{label} has an invalid size")
        raw = bytearray()
        while True:
            chunk = os.read(descriptor, min(8192, maximum_size + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > maximum_size:
                fail(f"{label} exceeds the size limit")
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            fail(f"{label} changed while being read")
        return bytes(raw)
    finally:
        os.close(descriptor)


def read_json_file(path: Path, label: str) -> dict[str, Any]:
    payload = parse_json_bytes(read_regular_file(path, label, MAX_JSON_BYTES), label)
    if not isinstance(payload, dict):
        fail(f"{label} must contain a JSON object")
    return payload


def verify_target_commit(target_sha: str) -> None:
    """Verify target existence by the fixed, unauthenticated read-only API endpoint."""

    require_sha40(target_sha, TARGET_PARENT_SHA_LABEL)
    request_url = f"{PROJECT_GIT_COMMIT_API}{target_sha}"
    request = Request(
        request_url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": API_USER_AGENT,
        },
    )
    try:
        with urlopen(request, timeout=15) as response:  # nosec B310: fixed HTTPS origin
            if response.geturl() != request_url:
                fail("target Parent SHA API response was redirected")
            if response.status != 200:
                fail("target Parent SHA API response did not confirm a commit")
            raw = response.read(MAX_JSON_BYTES + 1)
    except OSError as exc:
        fail(f"could not verify target Parent SHA through the read-only GitHub API: {exc}")
    if len(raw) > MAX_JSON_BYTES:
        fail("target Parent SHA API response exceeds the size limit")
    payload = parse_json_bytes(raw, "target Parent SHA API response")
    if not isinstance(payload, dict) or payload.get("sha") != target_sha:
        fail("target Parent SHA API response does not bind the requested commit")


def manifest_payload(target_sha: str, run_id: str, variant: str) -> dict[str, Any]:
    profile = PROFILE_BY_VARIANT.get(variant)
    if profile is None:
        fail("caller manifest uses an unknown fixed profile variant")
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "matrix_variant": variant,
        "parent_head_sha": target_sha,
        "framework_sha": PROTECTED_FRAMEWORK_SHA,
        "protected_broker_sha": PROTECTED_BROKER_SHA,
        "policy_profile": profile,
    }


def validate_manifest(payload: Any, target_sha: str, run_id: str, variant: str) -> None:
    value = require_exact_fields(payload, CALLER_MANIFEST_FIELDS, "caller manifest")
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        fail("caller manifest must use schema version 2")
    if require_run_id(value["run_id"], "caller manifest run_id") != run_id:
        fail("caller manifest run_id is not bound to the fixed caller run")
    if value["matrix_variant"] != variant:
        fail("caller manifest matrix variant is not bound to the fixed caller profile")
    if require_sha40(value["parent_head_sha"], "caller manifest parent_head_sha") != target_sha:
        fail("caller manifest parent_head_sha is not bound to the declared target")
    if require_sha40(value["framework_sha"], "caller manifest framework_sha") != PROTECTED_FRAMEWORK_SHA:
        fail("caller manifest framework SHA is not the immutable broker gitlink")
    if (
        require_sha40(value["protected_broker_sha"], "caller manifest protected_broker_sha")
        != PROTECTED_BROKER_SHA
    ):
        fail("caller manifest protected broker SHA is not immutable")
    if value["policy_profile"] != PROFILE_BY_VARIANT[variant]:
        fail("caller manifest profile and fixed variant do not match")


def create_manifests(target_sha: str, no_crs_run_id: str, with_crs_run_id: str) -> None:
    require_sha40(target_sha, TARGET_PARENT_SHA_LABEL)
    output_root = caller_artifact_root(
        CALLER_MANIFEST_ROOT_PREFIX,
        no_crs_run_id,
        with_crs_run_id,
    )
    verify_target_commit(target_sha)
    create_private_directory(output_root, "caller manifest root")
    for variant, run_id in (
        (NO_CRS_VARIANT, no_crs_run_id),
        (WITH_CRS_VARIANT, with_crs_run_id),
    ):
        profile_directory = output_root / variant
        create_private_directory(profile_directory, f"{variant} caller manifest directory")
        manifest_path = profile_directory / CALLER_MANIFEST_FILENAME
        payload = manifest_payload(target_sha, run_id, variant)
        validate_manifest(payload, target_sha, run_id, variant)
        write_private_json(manifest_path, payload, f"{variant} caller manifest")
        parsed = read_json_file(manifest_path, f"{variant} caller manifest")
        validate_manifest(parsed, target_sha, run_id, variant)
        if {entry.name for entry in profile_directory.iterdir()} != {CALLER_MANIFEST_FILENAME}:
            fail(f"{variant} caller manifest directory contains an unexpected entry")


def require_bound_identity(
    payload: Any,
    *,
    target_sha: str,
    run_id: str,
    variant: str,
    profile: str,
    label: str,
) -> dict[str, Any]:
    value = require_exact_fields(
        payload,
        frozenset(
            {
                "schema_version",
                "run_id",
                "matrix_variant",
                "parent_head_sha",
                "framework_sha",
                "protected_broker_sha",
                "nginx_binary_sha256",
                "nginx_module_sha256",
                "modsecurity_library_sha256",
                "nginx_version",
                "master_pid",
                "master_uid",
                "worker_pid",
                "worker_uid",
                "worker_gid",
                "policy_profile",
                *(("crs_bundle_digest", "crs_commit") if profile == OWASP_CRS_PROFILE else ()),
            }
        ),
        label,
    )
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        fail(f"{label} has an unsupported schema version")
    bindings = {
        "run_id": run_id,
        "matrix_variant": variant,
        "parent_head_sha": target_sha,
        "framework_sha": PROTECTED_FRAMEWORK_SHA,
        "protected_broker_sha": PROTECTED_BROKER_SHA,
        "policy_profile": profile,
        "nginx_version": NGINX_PINNED_VERSION,
    }
    for field, expected in bindings.items():
        if value.get(field) != expected:
            fail(f"{label} field {field!r} is not bound to the protected caller")
    for field in (
        "nginx_binary_sha256",
        "nginx_module_sha256",
        "modsecurity_library_sha256",
    ):
        require_sha256(value[field], f"{label} {field}")
    master_pid = require_positive_int(value["master_pid"], f"{label} master PID", minimum=2)
    worker_pid = require_positive_int(value["worker_pid"], f"{label} worker PID", minimum=2)
    if master_pid == worker_pid:
        fail(f"{label} must record separate master and worker processes")
    if require_positive_int(value["master_uid"], f"{label} master UID") != 0:
        fail(f"{label} master is not root")
    if require_positive_int(value["worker_uid"], f"{label} worker UID") == 0:
        fail(f"{label} worker must not be root")
    require_positive_int(value["worker_gid"], f"{label} worker GID")
    if profile == OWASP_CRS_PROFILE:
        require_sha256(value["crs_bundle_digest"], f"{label} CRS bundle digest")
        if value["crs_commit"] != CRS_COMMIT:
            fail(f"{label} CRS commit is not the protected broker value")
    return value


def validate_runtime_crs_evidence(crs_value: Any, identity: dict[str, Any]) -> None:
    crs = require_exact_fields(
        crs_value,
        frozenset(
            {
                "crs_repository",
                "crs_release_tag",
                "crs_commit",
                "crs_bundle_manifest_sha256",
                "crs_bundle_digest",
                "crs_file_count",
                "expected_crs_evidence",
            }
        ),
        "runtime evidence CRS tuple",
    )
    if crs["crs_repository"] != CRS_REPOSITORY or crs["crs_release_tag"] != CRS_RELEASE_TAG:
        fail("runtime evidence CRS source tuple is not the protected broker tuple")
    if crs["crs_commit"] != CRS_COMMIT:
        fail("runtime evidence CRS commit is not the protected broker value")
    require_sha256(crs["crs_bundle_manifest_sha256"], "runtime evidence CRS manifest digest")
    if require_sha256(crs["crs_bundle_digest"], "runtime evidence CRS bundle digest") != identity[
        "crs_bundle_digest"
    ]:
        fail("runtime evidence CRS bundle digest does not match identity evidence")
    require_positive_int(crs["crs_file_count"], "runtime evidence CRS file count", minimum=1)
    expected_observation = {
        "rule_id": CRS_RULE_ID,
        "request_path": CRS_BLOCK_PATH,
        "allow_path": CRS_ALLOW_PATH,
    }
    if crs["expected_crs_evidence"] != expected_observation:
        fail("runtime evidence CRS expected observation is not the protected broker value")


def validate_runtime_evidence(
    payload: Any,
    identity: dict[str, Any],
    *,
    target_sha: str,
    run_id: str,
    variant: str,
    profile: str,
) -> dict[str, Any]:
    expected_fields = {
        "schema_version",
        "run_id",
        "matrix_variant",
        "parent_head_sha",
        "framework_sha",
        "protected_broker_sha",
        "artifact_digest",
        "nginx_binary_sha256",
        "nginx_module_sha256",
        "modsecurity_library_sha256",
        "nginx_version",
        "root_broker_status",
        "cleanup_state",
        "policy_profile",
        "scope",
    }
    if profile == OWASP_CRS_PROFILE:
        expected_fields.add("crs")
    value = require_exact_fields(payload, frozenset(expected_fields), "runtime evidence")
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        fail("runtime evidence has an unsupported schema version")
    bindings = {
        "run_id": run_id,
        "matrix_variant": variant,
        "parent_head_sha": target_sha,
        "framework_sha": PROTECTED_FRAMEWORK_SHA,
        "protected_broker_sha": PROTECTED_BROKER_SHA,
        "policy_profile": profile,
        "nginx_version": NGINX_PINNED_VERSION,
        "root_broker_status": "PASS",
        "cleanup_state": CLEANUP_STATE,
        "scope": WITH_CRS_SCOPE if profile == OWASP_CRS_PROFILE else NO_CRS_SCOPE,
    }
    for field, expected in bindings.items():
        if value.get(field) != expected:
            fail(f"runtime evidence field {field!r} is not bound to the protected caller")
    require_sha256(value["artifact_digest"], "runtime evidence artifact digest")
    for field in (
        "nginx_binary_sha256",
        "nginx_module_sha256",
        "modsecurity_library_sha256",
    ):
        require_sha256(value[field], f"runtime evidence {field}")
        if value[field] != identity[field]:
            fail(f"runtime evidence {field} does not match identity evidence")
    if profile == OWASP_CRS_PROFILE:
        validate_runtime_crs_evidence(value["crs"], identity)
    return value


def validate_owasp_crs_policy_identity(
    value: dict[str, Any],
    identity: dict[str, Any],
    runtime: dict[str, Any],
) -> str:
    block = require_exact_fields(
        value["block"],
        frozenset({"path", "status"}),
        "OWASP CRS policy block",
    )
    if block != {"path": CRS_BLOCK_PATH, "status": 403}:
        fail("OWASP CRS policy evidence does not prove the fixed CRS block")
    transaction_id = require_string(value["transaction_id"], "policy transaction ID")
    if TRANSACTION_ID_RE.fullmatch(transaction_id) is None:
        fail("policy transaction ID is unsafe")
    if value["crs_rule_id"] != CRS_RULE_ID or value["crs_commit"] != CRS_COMMIT:
        fail("OWASP CRS policy evidence has an unexpected CRS identity")
    if require_sha256(value["crs_bundle_digest"], "policy CRS bundle digest") != identity[
        "crs_bundle_digest"
    ]:
        fail("policy CRS bundle digest does not match identity evidence")
    if value["crs_bundle_digest"] != runtime["crs"]["crs_bundle_digest"]:
        fail("policy CRS bundle digest does not match runtime evidence")
    return transaction_id


def validate_owasp_crs_audit_record(
    value: dict[str, Any],
    audit_raw: bytes | None,
    run_id: str,
    transaction_id: str,
) -> None:
    if audit_raw is None or not audit_raw:
        fail("OWASP CRS evidence requires a non-empty audit record")
    if require_sha256(value["audit_log_sha256"], "policy audit digest") != hashlib.sha256(audit_raw).hexdigest():
        fail("policy audit digest does not match the downloaded audit record")
    try:
        audit_text = audit_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"OWASP CRS audit record is not UTF-8: {exc}")
    if run_id not in audit_text or CRS_BLOCK_PATH not in audit_text:
        fail("OWASP CRS audit record is not bound to the protected run and request")
    if CRS_RULE_ID not in audit_text or not re.search(r"\b403\b", audit_text):
        fail("OWASP CRS audit record lacks the required rule or block status")
    if f"--{transaction_id}-A--" not in audit_text or f"--{transaction_id}-Z--" not in audit_text:
        fail("OWASP CRS audit record does not bind the policy transaction")


def validate_policy_evidence(
    payload: Any,
    identity: dict[str, Any],
    runtime: dict[str, Any],
    audit_raw: bytes | None,
    *,
    run_id: str,
    variant: str,
    profile: str,
) -> None:
    expected_fields = {
        "schema_version",
        "run_id",
        "matrix_variant",
        "policy_profile",
        "allow",
        "block",
    }
    if profile == OWASP_CRS_PROFILE:
        expected_fields.update(
            {
                "transaction_id",
                "audit_log_sha256",
                "crs_rule_id",
                "crs_bundle_digest",
                "crs_commit",
            }
        )
    value = require_exact_fields(payload, frozenset(expected_fields), "policy evidence")
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        fail("policy evidence has an unsupported schema version")
    if (
        value["run_id"] != run_id
        or value["matrix_variant"] != variant
        or value["policy_profile"] != profile
    ):
        fail("policy evidence is not bound to the protected caller run and profile")
    allow = require_exact_fields(value["allow"], frozenset({"path", "status"}), "policy allow")
    if allow != {"path": CRS_ALLOW_PATH, "status": 200}:
        fail("policy evidence does not prove the fixed allow request")
    if profile == NO_CRS_PROFILE:
        block = require_exact_fields(
            value["block"],
            frozenset({"path", "status", "rule_id"}),
            "no-CRS policy block",
        )
        if block != {"path": "/blocked", "status": 403, "rule_id": "941001"}:
            fail("no-CRS policy evidence does not prove the fixed control block")
        if audit_raw is not None:
            fail("no-CRS evidence must not include an audit record")
        return
    transaction_id = validate_owasp_crs_policy_identity(value, identity, runtime)
    validate_owasp_crs_audit_record(value, audit_raw, run_id, transaction_id)


def validate_cleanup_evidence(
    payload: Any, *, run_id: str, variant: str
) -> None:
    value = require_exact_fields(
        payload,
        frozenset({"broker_sha", "cleanup_status", "matrix_variant", "run_id"}),
        "cleanup evidence",
    )
    if (
        value["broker_sha"] != PROTECTED_BROKER_SHA
        or value["cleanup_status"] != "PASS"
        or value["matrix_variant"] != variant
        or value["run_id"] != run_id
    ):
        fail("cleanup evidence is not a PASS bound to the protected caller run")


def validate_evidence_directory(
    directory: Path,
    *,
    target_sha: str,
    run_id: str,
    variant: str,
) -> None:
    profile = PROFILE_BY_VARIANT[variant]
    require_directory(directory, f"{variant} evidence directory")
    expected_files = WITH_CRS_EVIDENCE_FILES if profile == OWASP_CRS_PROFILE else NO_CRS_EVIDENCE_FILES
    observed_files = {entry.name for entry in directory.iterdir()}
    if observed_files != expected_files:
        fail(
            f"{variant} evidence file set is not exact; "
            f"missing={sorted(expected_files - observed_files)!r} "
            f"unknown={sorted(observed_files - expected_files)!r}"
        )
    identity = require_bound_identity(
        read_json_file(directory / IDENTITY_FILENAME, "identity evidence"),
        target_sha=target_sha,
        run_id=run_id,
        variant=variant,
        profile=profile,
        label="identity evidence",
    )
    runtime = validate_runtime_evidence(
        read_json_file(directory / RUNTIME_FILENAME, "runtime evidence"),
        identity,
        target_sha=target_sha,
        run_id=run_id,
        variant=variant,
        profile=profile,
    )
    audit_raw = (
        read_regular_file(directory / AUDIT_LOG_FILENAME, "OWASP CRS audit evidence", MAX_LOG_BYTES)
        if profile == OWASP_CRS_PROFILE
        else None
    )
    read_regular_file(directory / ACCESS_LOG_FILENAME, "NGINX access log", MAX_LOG_BYTES)
    read_regular_file(directory / ERROR_LOG_FILENAME, "NGINX error log", MAX_LOG_BYTES)
    validate_policy_evidence(
        read_json_file(directory / POLICY_FILENAME, "policy evidence"),
        identity,
        runtime,
        audit_raw,
        run_id=run_id,
        variant=variant,
        profile=profile,
    )
    validate_cleanup_evidence(
        read_json_file(directory / CLEANUP_FILENAME, "cleanup evidence"),
        run_id=run_id,
        variant=variant,
    )


def verify_evidence(target_sha: str, no_crs_run_id: str, with_crs_run_id: str) -> None:
    require_sha40(target_sha, TARGET_PARENT_SHA_LABEL)
    evidence_root = caller_artifact_root(
        CALLER_EVIDENCE_ROOT_PREFIX,
        no_crs_run_id,
        with_crs_run_id,
    )
    require_directory(evidence_root, "caller evidence root")
    validate_evidence_directory(
        evidence_root / NO_CRS_VARIANT,
        target_sha=target_sha,
        run_id=no_crs_run_id,
        variant=NO_CRS_VARIANT,
    )
    validate_evidence_directory(
        evidence_root / WITH_CRS_VARIANT,
        target_sha=target_sha,
        run_id=with_crs_run_id,
        variant=WITH_CRS_VARIANT,
    )


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(
        description="Prepare and validate data-only protected NGINX broker caller artifacts."
    )
    subcommands = argument_parser.add_subparsers(dest="command", required=True)
    create = subcommands.add_parser("create-manifests")
    create.add_argument("--target-sha", required=True)
    create.add_argument("--no-crs-run-id", required=True)
    create.add_argument("--with-crs-run-id", required=True)
    verify = subcommands.add_parser("verify-evidence")
    verify.add_argument("--target-sha", required=True)
    verify.add_argument("--no-crs-run-id", required=True)
    verify.add_argument("--with-crs-run-id", required=True)
    return argument_parser


def main(arguments: list[str] | None = None) -> int:
    parsed = parser().parse_args(arguments)
    try:
        if parsed.command == "create-manifests":
            create_manifests(
                parsed.target_sha,
                parsed.no_crs_run_id,
                parsed.with_crs_run_id,
            )
            print("prepared two validated declarative caller manifests")
        else:
            verify_evidence(
                parsed.target_sha,
                parsed.no_crs_run_id,
                parsed.with_crs_run_id,
            )
            print("validated no-CRS and OWASP CRS broker evidence")
    except CallerContractError as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 77
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
