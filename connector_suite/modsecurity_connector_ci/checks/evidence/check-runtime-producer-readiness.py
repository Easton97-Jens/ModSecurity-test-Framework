#!/usr/bin/env python3
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# CI helpers are shared from ci/lib even when this file is executed directly.

from typing import Any

from modsecurity_connector_ci.lib.runtime_path_utils import is_read_only_source_path, is_safe_runtime_root, is_system_write_path, is_under, verified_runtime_paths


RUNTIME_COMPONENT_PREPARATION_FIX = "run make prepare-runtime-components"
NGINX_READY_STATUSES = frozenset({"present", "built", "reused"})
NGINX_RUNTIME_CONTRACT_FIELDS = (
    "component",
    "source_repository",
    "source_mode",
    "release_tag",
    "source_ref",
    "release_asset_name",
    "expected_archive_sha256",
    "actual_archive_sha256",
    "source_version_readback",
    "source_directory",
    "binary_path",
    "binary_sha256",
    "binary_version_readback",
    "configure_arguments",
    "build_id",
    "framework_commit",
    "parent_commit",
    "generated_at",
)
NGINX_PINNED_TUPLE_FIELDS = (
    "source_repository",
    "source_mode",
    "release_tag",
    "source_ref",
    "release_asset_name",
    "expected_archive_sha256",
    "actual_archive_sha256",
    "source_version_readback",
    "binary_version_readback",
)
CANONICAL_NGINX_SOURCE_REPOSITORY = "https://github.com/nginx/nginx"
CANONICAL_NGINX_SOURCE_MODE = "github-release"
CANONICAL_NGINX_RELEASE_TAG = "release-1.31.6"
CANONICAL_NGINX_SOURCE_REF = "release-1.31.6"
CANONICAL_NGINX_RELEASE_ASSET_NAME = "nginx-1.31.6.tar.gz"
CANONICAL_NGINX_ARCHIVE_SHA256 = "974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1"
CANONICAL_NGINX_VERSION_READBACK = "nginx/1.31.6"
CANONICAL_NGINX_CONTRACT_VALUES = {
    "source_repository": CANONICAL_NGINX_SOURCE_REPOSITORY,
    "source_mode": CANONICAL_NGINX_SOURCE_MODE,
    "release_tag": CANONICAL_NGINX_RELEASE_TAG,
    "source_ref": CANONICAL_NGINX_SOURCE_REF,
    "release_asset_name": CANONICAL_NGINX_RELEASE_ASSET_NAME,
    "expected_archive_sha256": CANONICAL_NGINX_ARCHIVE_SHA256,
    "actual_archive_sha256": CANONICAL_NGINX_ARCHIVE_SHA256,
    "source_version_readback": CANONICAL_NGINX_VERSION_READBACK,
    "binary_version_readback": CANONICAL_NGINX_VERSION_READBACK,
}
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT_ID_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
UTC_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
MARKDOWN_THREE_COLUMN_SEPARATOR = "|---|---|---|"


def default_state_home() -> Path:
    return Path(verified_runtime_paths(os.environ)["VERIFIED_STATE_ROOT"])


def read_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def contract_display(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value or "")


def contract_markdown_value(value: Any) -> str:
    return contract_display(value).replace("`", "\\`").replace("|", "/").replace("\n", " ")


def contract_value_present(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple)):
        return bool(value)
    return value is not None and value != ""


def nginx_record_from_manifest(manifest: dict[str, Any]) -> tuple[dict[str, Any], str]:
    direct = manifest.get("nginx")
    if isinstance(direct, dict):
        return direct, "nginx"
    components = manifest.get("components")
    nested = components.get("nginx") if isinstance(components, dict) else None
    if isinstance(nested, dict):
        return nested, "components.nginx"
    return {}, "missing"


def nginx_runtime_contract_from_manifest(cache_root: Path) -> dict[str, Any]:
    manifest_path = cache_root / "manifest.json"
    manifest = read_json(manifest_path)
    record, record_path = nginx_record_from_manifest(manifest)
    nested = record.get("runtime_contract")
    if isinstance(nested, dict):
        contract = nested
        contract_path = f"{record_path}.runtime_contract"
    elif record:
        # The producer's stable snake_case fields are also accepted directly
        # on its nginx record for backward-compatible report consumption.  The
        # validator still rejects any missing field rather than filling it from
        # defaults, PATH, or the current environment.
        contract = {field: record.get(field, "") for field in NGINX_RUNTIME_CONTRACT_FIELDS}
        contract_path = record_path
    else:
        contract = {}
        contract_path = "missing"
    return {
        "manifest_path": str(manifest_path),
        "manifest_loaded": bool(manifest),
        "record_path": contract_path,
        "record_status": contract_display(record.get("status")),
        "record": record,
        "contract": contract,
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def field_status(value: Any) -> str:
    return "PASS" if contract_value_present(value) else "BLOCKED"


def nginx_evidence_path_problem(path: Path, roots: dict[str, Path]) -> str:
    if is_system_write_path(path):
        return "system path is forbidden for NGINX runtime evidence"
    mrts_native_root = roots.get("mrts_native_root")
    if mrts_native_root is not None and (path == mrts_native_root or is_within(path, mrts_native_root)):
        return "MRTS_NATIVE_ROOT is forbidden for NGINX runtime evidence"
    allowed = any(
        name != "mrts_native_root" and (path == root or is_within(path, root))
        for name, root in roots.items()
    )
    return "" if allowed else "path is outside approved non-MRTS runtime/source roots"


def canonical_utc_timestamp(value: str) -> bool:
    if not UTC_TIMESTAMP_PATTERN.fullmatch(value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def nginx_runtime_contract_fields(contract: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    fields = {field: contract.get(field, "") for field in NGINX_RUNTIME_CONTRACT_FIELDS}
    return fields, {field: field_status(fields[field]) for field in NGINX_RUNTIME_CONTRACT_FIELDS}


def nginx_runtime_record_issues(record: dict[str, Any]) -> list[str]:
    if not record:
        return ["NGINX runtime record is missing from the component manifest"]
    if record.get("status") not in NGINX_READY_STATUSES:
        status = contract_display(record.get("status")) or "missing"
        return [f"NGINX runtime record is not ready (status={status})"]
    return []


def validate_nginx_runtime_contract_values(
    fields: dict[str, Any],
    field_states: dict[str, str],
    issues: list[str],
) -> None:
    missing = [field for field in NGINX_RUNTIME_CONTRACT_FIELDS if not contract_value_present(fields[field])]
    if missing:
        issues.append("missing required NGINX runtime contract fields: " + ", ".join(missing))
    if fields["component"] != "nginx":
        field_states["component"] = "BLOCKED"
        issues.append("component must be nginx")
    for field, expected in CANONICAL_NGINX_CONTRACT_VALUES.items():
        if contract_display(fields[field]) != expected:
            field_states[field] = "BLOCKED"
            issues.append(f"{field} must equal the canonical reviewed NGINX value {expected}")


def validate_nginx_runtime_contract_identity(
    fields: dict[str, Any],
    field_states: dict[str, str],
    issues: list[str],
) -> None:
    for field in ("framework_commit", "parent_commit"):
        if not GIT_OBJECT_ID_PATTERN.fullmatch(contract_display(fields[field])):
            field_states[field] = "BLOCKED"
            issues.append(f"{field} must be a full lowercase Git object ID")
    if not canonical_utc_timestamp(contract_display(fields["generated_at"])):
        field_states["generated_at"] = "BLOCKED"
        issues.append("generated_at must be a canonical UTC timestamp")


def validate_nginx_runtime_source_directory(
    fields: dict[str, Any],
    field_states: dict[str, str],
    roots: dict[str, Path],
    issues: list[str],
) -> None:
    source_directory_text = contract_display(fields["source_directory"])
    if not source_directory_text:
        return
    source_directory_candidate = Path(source_directory_text)
    source_directory = source_directory_candidate.resolve(strict=False)
    source_problem = nginx_evidence_path_problem(source_directory, roots)
    if source_directory_candidate.is_symlink() or source_problem or not source_directory.is_dir():
        field_states["source_directory"] = "BLOCKED"
        issues.append(
            "source_directory must be a non-symlink directory below an approved non-MRTS runtime/source root"
            + (f" ({source_problem})" if source_problem else "")
        )


def validate_nginx_runtime_binary(
    fields: dict[str, Any],
    field_states: dict[str, str],
    roots: dict[str, Path],
    issues: list[str],
) -> None:
    binary_path_text = contract_display(fields["binary_path"])
    if not binary_path_text:
        field_states["binary_sha256"] = "BLOCKED"
        return
    binary_path_candidate = Path(binary_path_text)
    binary_path = binary_path_candidate.resolve(strict=False)
    binary_problem = nginx_evidence_path_problem(binary_path, roots)
    if binary_path_candidate.is_symlink() or binary_problem:
        field_states["binary_path"] = "BLOCKED"
        field_states["binary_sha256"] = "BLOCKED"
        issues.append(
            "binary_path must be a non-symlink executable below an approved non-MRTS runtime/cache root"
            + (f" ({binary_problem})" if binary_problem else "")
        )
        return
    if not executable(binary_path):
        field_states["binary_path"] = "BLOCKED"
        field_states["binary_sha256"] = "BLOCKED"
        issues.append("binary_path is missing or is not executable")
        return
    actual_binary_sha = sha256_file(binary_path)
    expected_binary_sha = contract_display(fields["binary_sha256"]).lower()
    if not SHA256_PATTERN.fullmatch(expected_binary_sha):
        field_states["binary_sha256"] = "BLOCKED"
        issues.append("binary_sha256 must be a 64-character SHA-256 value")
    elif actual_binary_sha != expected_binary_sha:
        field_states["binary_sha256"] = "BLOCKED"
        issues.append("binary_sha256 does not match the managed binary")


def validate_nginx_runtime_contract(
    contract_input: dict[str, Any],
    roots: dict[str, Path],
) -> dict[str, Any]:
    contract = contract_input.get("contract") if isinstance(contract_input.get("contract"), dict) else {}
    record = contract_input.get("record") if isinstance(contract_input.get("record"), dict) else {}
    fields, field_states = nginx_runtime_contract_fields(contract)
    issues = nginx_runtime_record_issues(record)
    validate_nginx_runtime_contract_values(fields, field_states, issues)
    validate_nginx_runtime_contract_identity(fields, field_states, issues)
    validate_nginx_runtime_source_directory(fields, field_states, roots, issues)
    validate_nginx_runtime_binary(fields, field_states, roots, issues)
    status = "PASS" if not issues and all(state == "PASS" for state in field_states.values()) else "BLOCKED"
    return {
        "status": status,
        "manifest_path": contract_input.get("manifest_path", ""),
        "manifest_loaded": bool(contract_input.get("manifest_loaded")),
        "record_path": contract_input.get("record_path", "missing"),
        "record_status": contract_input.get("record_status", ""),
        "fields": fields,
        "field_status": field_states,
        "issues": issues,
    }


def nginx_runtime_module_candidate_problem(
    module_candidate: Path,
    module_path: Path,
    roots: dict[str, Path],
) -> str:
    module_problem = nginx_evidence_path_problem(module_path, roots)
    if module_candidate.is_symlink() or module_problem or not module_path.is_file():
        return (
            "reported NGINX module must be a non-symlink regular file below an approved non-MRTS runtime/cache root"
            + (f" ({module_problem})" if module_problem else "")
        )
    return ""


def validate_nginx_runtime_module_binding(
    contract_input: dict[str, Any],
    module_candidate: Path,
    roots: dict[str, Path],
) -> dict[str, Any]:
    """Bind the reported dynamic module to the managed producer record.

    The required runtime contract identifies the source and host binary.  The
    component record separately owns the module output path.  Comparing them
    prevents a later runtime-environment override from pairing a managed binary
    with a module from MRTS or a system location.
    """

    record = contract_input.get("record") if isinstance(contract_input.get("record"), dict) else {}
    expected_text = contract_display(record.get("module_file"))
    issues: list[str] = []
    module_path = module_candidate.resolve(strict=False)
    candidate_problem = nginx_runtime_module_candidate_problem(module_candidate, module_path, roots)
    if not expected_text:
        issues.append("NGINX component record is missing its managed module_file")
    if candidate_problem:
        issues.append(candidate_problem)
    elif expected_text != str(module_path):
        issues.append("reported NGINX module does not match the managed component record")

    return {
        "status": "PASS" if not issues else "BLOCKED",
        "expected_module_path": expected_text,
        "reported_module_path": str(module_path),
        "issues": issues,
    }


def is_within(path: Path, root: Path) -> bool:
    return is_under(path, root)


def parse_export_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped.startswith("export ") or "=" not in stripped:
            continue
        try:
            parts = shlex.split(stripped.removeprefix("export "), posix=True)
        except ValueError:
            continue
        for part in parts:
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            if key:
                values[key] = value
    return values


def load_common_sh(connector_root: Path, framework_root: Path, env: dict[str, str]) -> dict[str, Any]:
    common_sh = framework_root / "ci/lib/common.sh"
    if not common_sh.is_file():
        return {"status": "blocked", "return_code": 77, "path": str(common_sh), "error": "missing common.sh", "env": {}}
    proc = subprocess.run(
        ["bash", "-lc", 'set -a; . "$FRAMEWORK_ROOT/ci/lib/common.sh"; env -0'],
        cwd=str(connector_root),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        timeout=60,
    )
    loaded: dict[str, str] = {}
    if proc.returncode == 0:
        for chunk in proc.stdout.split(b"\0"):
            if not chunk or b"=" not in chunk:
                continue
            key, value = chunk.split(b"=", 1)
            loaded[key.decode("utf-8", errors="replace")] = value.decode("utf-8", errors="replace")
    return {
        "status": "present" if proc.returncode == 0 else "blocked",
        "return_code": proc.returncode,
        "path": str(common_sh),
        "error": proc.stderr.decode("utf-8", errors="replace").strip(),
        "env": loaded,
    }


def executable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def executable_or_path(value: str) -> Path | None:
    if not value:
        return None
    if "/" in value:
        return Path(value)
    resolved = shutil.which(value)
    return Path(resolved) if resolved else None


def file_status(path: Path | None, *, executable_required: bool = False) -> str:
    if path is None:
        return "missing"
    if executable_required:
        return "present" if executable(path) else "missing"
    return "present" if path.is_file() else "missing"


def first_nonempty(*values: str | None) -> str:
    for value in values:
        if value:
            return value
    return ""


def status_for_required(items: list[dict[str, Any]]) -> str:
    return "PASS" if all(item["status"] == "present" for item in items) else "BLOCKED"


def status_for_optional(items: list[dict[str, Any]]) -> str:
    return "PASS" if all(item["status"] == "present" for item in items) else "WARN"


def component(
    name: str,
    status: str,
    path: Path | None,
    fix: str,
    *,
    required: bool = True,
    details: str = "",
) -> dict[str, Any]:
    return {
        "component": name,
        "required": required,
        "status": status,
        "path": str(path) if path is not None else "",
        "fix": fix,
        "details": details,
    }


def check_safe_path(path: Path, label: str, roots: dict[str, Path], connector_root: Path, framework_root: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=False)
    status = "PASS"
    notes: list[str] = []
    del connector_root, framework_root
    read_only_source = label == "SOURCE_ROOT" and is_read_only_source_path(resolved)
    if not resolved.is_absolute():
        status = "BLOCKED"
        notes.append("path is not absolute")
    if is_system_write_path(resolved) and not read_only_source:
        status = "BLOCKED"
        notes.append("system write path is forbidden")
    allowed = any(
        is_safe_runtime_root(root) and (is_within(resolved, root) or resolved == root)
        for root in roots.values()
    )
    if not read_only_source and not allowed:
        status = "BLOCKED"
        notes.append("path is outside allowed runtime/cache roots")
    if read_only_source:
        notes.append("read-only source path")
    return {"label": label, "path": str(resolved), "status": status, "notes": "; ".join(notes) or "ok"}


def nginx_tuple_cache_row(cache_root: Path, nginx_contract: dict[str, Any] | None) -> dict[str, Any]:
    contract = nginx_contract or {}
    fields = contract.get("fields") if isinstance(contract.get("fields"), dict) else {}
    tuple_status = "present" if contract.get("status") == "PASS" else "missing"
    tuple_values = ", ".join(
        f"{field}={contract_markdown_value(fields.get(field)) or '-'}"
        for field in NGINX_PINNED_TUPLE_FIELDS
    )
    tuple_notes = (
        "pinned release-asset/full tuple validated"
        if tuple_status == "present"
        else "pinned release-asset/full tuple is missing or invalid; "
        + "; ".join(contract.get("issues", []))
    )
    manifest_path = Path(str(contract.get("manifest_path") or cache_root / "manifest.json"))
    return {
        "source": "nginx pinned release-asset tuple",
        "status": tuple_status,
        "path": str(manifest_path),
        "notes": f"{tuple_notes}; {tuple_values}",
    }


def local_cache_status(path: Path) -> str:
    if path.is_dir():
        return "present" if any(path.iterdir()) else "missing"
    return "present" if path.is_file() and path.stat().st_size > 0 else "missing"


def local_cache_row(name: str, path: Path) -> dict[str, Any]:
    status = local_cache_status(path)
    return {
        "source": name,
        "status": status,
        "path": str(path),
        "notes": "local cache available" if status == "present" else "network may be required unless this cache is prefilled",
    }


def network_cache_status(
    cache_root: Path,
    nginx_contract: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    return [
        nginx_tuple_cache_row(cache_root, nginx_contract),
        local_cache_row("nginx archive cache", cache_root / "archives/nginx"),
        local_cache_row("go-ftw git cache", cache_root / "git/go-ftw"),
        local_cache_row("albedo git cache", cache_root / "git/albedo"),
    ]


def readiness_environment(
    connector_root: Path,
    framework_root: Path,
    build_root: Path,
) -> tuple[Path, dict[str, Any], dict[str, str], Path, dict[str, Path]]:
    defaults = verified_runtime_paths(os.environ, build_root_override=build_root)
    state_home = Path(defaults["VERIFIED_STATE_ROOT"])
    cache_root = Path(defaults["CONNECTOR_COMPONENT_CACHE"])
    base_env = dict(os.environ)
    base_env.update(
        {
            "CONNECTOR_ROOT": str(connector_root),
            "FRAMEWORK_ROOT": str(framework_root),
            "BUILD_ROOT": str(build_root),
            "VERIFIED_RUN_ROOT": defaults["VERIFIED_RUN_ROOT"],
            "VERIFIED_STATE_ROOT": defaults["VERIFIED_STATE_ROOT"],
            "VERIFIED_BUILD_ROOT": defaults["VERIFIED_BUILD_ROOT"],
            "VERIFIED_SOURCE_ROOT": defaults["VERIFIED_SOURCE_ROOT"],
            "VERIFIED_TMP_ROOT": defaults["VERIFIED_TMP_ROOT"],
            "VERIFIED_LOG_ROOT": defaults["VERIFIED_LOG_ROOT"],
            "VERIFIED_COMPONENT_CACHE": defaults["VERIFIED_COMPONENT_CACHE"],
            "SOURCE_ROOT": base_env.get("SOURCE_ROOT", defaults["SOURCE_ROOT"]),
            "TMP_ROOT": base_env.get("TMP_ROOT", defaults["TMP_ROOT"]),
            "LOG_ROOT": base_env.get("LOG_ROOT", defaults["LOG_ROOT"]),
            "CONNECTOR_COMPONENT_CACHE": str(cache_root),
            "NGINX_HARNESS_PARENT": base_env.get("NGINX_HARNESS_PARENT", defaults["NGINX_HARNESS_PARENT"]),
            "MRTS_NATIVE_ROOT": base_env.get("MRTS_NATIVE_ROOT", defaults["MRTS_NATIVE_ROOT"]),
        }
    )
    common = load_common_sh(connector_root, framework_root, base_env)
    effective_env = dict(base_env)
    effective_env.update(common.get("env", {}))
    runtime_env_path = cache_root / "runtime-env.sh"
    effective_env.update(parse_export_file(runtime_env_path))
    roots = {
        "verified_run_root": Path(defaults["VERIFIED_RUN_ROOT"]),
        "state_home": state_home,
        "build_root": Path(defaults["BUILD_ROOT"]),
        # These paths have already passed verified_runtime_paths() validation.
        # Do not replace them with a later runtime-env SOURCE_ROOT override.
        "verified_source_root": Path(defaults["VERIFIED_SOURCE_ROOT"]),
        "source_root": Path(defaults["SOURCE_ROOT"]),
        "cache_root": cache_root,
        "tmp_root": Path(defaults["TMP_ROOT"]),
        "log_root": Path(defaults["LOG_ROOT"]),
        "mrts_native_root": Path(defaults["MRTS_NATIVE_ROOT"]),
    }
    return cache_root, common, effective_env, runtime_env_path, roots


def nginx_readiness_values(
    effective_env: dict[str, str],
    build_root: Path,
    nginx_contract_input: dict[str, Any],
    roots: dict[str, Path],
) -> tuple[dict[str, Any], Path | None, Path, dict[str, Any]]:
    nginx_contract = validate_nginx_runtime_contract(nginx_contract_input, roots)
    nginx_prefix = Path(effective_env.get("NGINX_PREFIX", str(build_root / "nginx-runtime/nginx"))).resolve()
    nginx_binary_path = contract_display(nginx_contract["fields"].get("binary_path"))
    nginx_bin = Path(nginx_binary_path).resolve() if nginx_binary_path else None
    nginx_module_dir_value = first_nonempty(effective_env.get("MRTS_NATIVE_NGINX_MODULE_DIR"), str(nginx_prefix / "modules"))
    nginx_module_candidate = Path(
        first_nonempty(
            effective_env.get("NGINX_MODULE"),
            effective_env.get("MRTS_NATIVE_NGINX_MODULE_FILE"),
            str(Path(nginx_module_dir_value) / "ngx_http_modsecurity_module.so"),
        )
    )
    nginx_module_file = nginx_module_candidate.resolve(strict=False)
    nginx_module_binding = validate_nginx_runtime_module_binding(
        nginx_contract_input,
        nginx_module_candidate,
        roots,
    )
    return nginx_contract, nginx_bin, nginx_module_file, nginx_module_binding


def runtime_component_paths(effective_env: dict[str, str]) -> dict[str, Path | None]:
    modsecurity_lib_dir = Path(
        first_nonempty(
            effective_env.get("NGINX_MRTS_MODSECURITY_LIB_DIR"),
            effective_env.get("MRTS_NATIVE_NGINX_MODSECURITY_LIB_DIR"),
            effective_env.get("MODSECURITY_LIB_DIR"),
        )
    )
    return {
        "modsecurity_lib": (modsecurity_lib_dir / "libmodsecurity.so").resolve()
        if str(modsecurity_lib_dir)
        else None,
        "apache_httpd": executable_or_path(effective_env.get("APACHE_HTTPD", "")),
        "apache_module": Path(effective_env["APACHE_MODULE"]).resolve()
        if effective_env.get("APACHE_MODULE")
        else None,
        "apxs": executable_or_path(effective_env.get("APXS_BIN") or effective_env.get("APXS", "")),
        "haproxy": executable_or_path(effective_env.get("HAPROXY_BIN", "")),
        "spoa": executable_or_path(effective_env.get("SPOA_RUNTIME_BIN", "")),
        "haproxy_binding": Path(effective_env["MODSECURITY_BINDING_DIR"]) / "paths.env"
        if effective_env.get("MODSECURITY_BINDING_DIR")
        else None,
        "go_ftw": executable_or_path(effective_env.get("GO_FTW_BIN", "go-ftw")),
        "albedo": executable_or_path(effective_env.get("ALBEDO_BIN", "albedo")),
    }


def readiness_component_items(
    common: dict[str, Any],
    nginx_contract: dict[str, Any],
    nginx_bin: Path | None,
    nginx_module_file: Path,
    nginx_module_binding: dict[str, Any],
    component_paths: dict[str, Path | None],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    required_items = [
        component("common.sh", "present" if common["status"] == "present" else "missing", Path(common["path"]), "ensure FRAMEWORK_ROOT points at modules/ModSecurity-test-Framework"),
        component(
            "NGINX runtime contract",
            "present" if nginx_contract["status"] == "PASS" else "missing",
            Path(nginx_contract["manifest_path"]),
            RUNTIME_COMPONENT_PREPARATION_FIX,
            details="; ".join(nginx_contract["issues"]) or "full pinned release-asset tuple and binary identity validated",
        ),
        component("NGINX binary", file_status(nginx_bin, executable_required=True), nginx_bin, RUNTIME_COMPONENT_PREPARATION_FIX),
        component(
            "NGINX ModSecurity module",
            "present"
            if file_status(nginx_module_file) == "present" and nginx_module_binding["status"] == "PASS"
            else "missing",
            nginx_module_file,
            RUNTIME_COMPONENT_PREPARATION_FIX,
            details="; ".join(nginx_module_binding["issues"])
            or "module path matches the managed NGINX component record",
        ),
        component("NGINX libmodsecurity", file_status(component_paths["modsecurity_lib"]), component_paths["modsecurity_lib"], RUNTIME_COMPONENT_PREPARATION_FIX),
        component("Apache/httpd", file_status(component_paths["apache_httpd"], executable_required=True), component_paths["apache_httpd"], RUNTIME_COMPONENT_PREPARATION_FIX),
        component("Apache/APXS", file_status(component_paths["apxs"], executable_required=True), component_paths["apxs"], RUNTIME_COMPONENT_PREPARATION_FIX),
        component("Apache ModSecurity module", file_status(component_paths["apache_module"]), component_paths["apache_module"], RUNTIME_COMPONENT_PREPARATION_FIX),
        component("HAProxy binary", file_status(component_paths["haproxy"], executable_required=True), component_paths["haproxy"], RUNTIME_COMPONENT_PREPARATION_FIX),
        component("HAProxy SPOA runtime", file_status(component_paths["spoa"], executable_required=True), component_paths["spoa"], RUNTIME_COMPONENT_PREPARATION_FIX),
        component("HAProxy binding metadata", file_status(component_paths["haproxy_binding"]), component_paths["haproxy_binding"], RUNTIME_COMPONENT_PREPARATION_FIX),
    ]
    optional_items = [
        component("go-ftw", file_status(component_paths["go_ftw"], executable_required=True), component_paths["go_ftw"], "optional native MRTS: install or cache go-ftw", required=False),
        component("albedo", file_status(component_paths["albedo"], executable_required=True), component_paths["albedo"], "optional native MRTS: install or cache albedo", required=False),
    ]
    return required_items, optional_items


def readiness_path_checks(
    effective_env: dict[str, str],
    roots: dict[str, Path],
    connector_root: Path,
    framework_root: Path,
) -> list[dict[str, Any]]:
    path_keys = (
        "BUILD_ROOT",
        "SOURCE_ROOT",
        "TMP_ROOT",
        "LOG_ROOT",
        "CONNECTOR_COMPONENT_CACHE",
        "NGINX_HARNESS_PARENT",
        "MRTS_NATIVE_ROOT",
    )
    return [
        check_safe_path(Path(effective_env[key]).resolve(), key, roots, connector_root, framework_root)
        for key in path_keys
        if effective_env.get(key)
    ]


def readiness_status(
    required_items: list[dict[str, Any]],
    optional_items: list[dict[str, Any]],
    path_checks: list[dict[str, Any]],
) -> str:
    status = "PASS" if status_for_required(required_items) == "PASS" and all(
        item["status"] == "PASS" for item in path_checks
    ) else "BLOCKED"
    if status == "PASS" and status_for_optional(optional_items) == "WARN":
        return "WARN"
    return status


def build_payload(connector_root: Path, framework_root: Path, build_root: Path) -> dict[str, Any]:
    cache_root, common, effective_env, runtime_env_path, roots = readiness_environment(
        connector_root,
        framework_root,
        build_root,
    )
    nginx_contract_input = nginx_runtime_contract_from_manifest(cache_root)
    nginx_contract, nginx_bin, nginx_module_file, nginx_module_binding = nginx_readiness_values(
        effective_env,
        build_root,
        nginx_contract_input,
        roots,
    )
    nginx_module_dir = nginx_module_file.parent
    component_paths = runtime_component_paths(effective_env)
    required_items, optional_items = readiness_component_items(
        common,
        nginx_contract,
        nginx_bin,
        nginx_module_file,
        nginx_module_binding,
        component_paths,
    )
    path_checks = readiness_path_checks(effective_env, roots, connector_root, framework_root)
    status = readiness_status(required_items, optional_items, path_checks)
    return {
        "status": status,
        "runtime_env_path": str(runtime_env_path),
        "runtime_env_loaded": runtime_env_path.is_file(),
        "common_sh": {key: value for key, value in common.items() if key != "env"},
        "paths": path_checks,
        "components": required_items + optional_items,
        "nginx_runtime_module_readiness": {
            "NGINX_BIN": str(nginx_bin) if nginx_bin is not None else "",
            "NGINX_MODULE_DIR": str(nginx_module_dir),
            "ModSecurity module path": str(nginx_module_file),
            "Module exists": nginx_module_file.is_file(),
            "Module binding": nginx_module_binding,
            "How to prepare": "make prepare-runtime-components",
        },
        "nginx_runtime_contract": nginx_contract,
        "network_cache": network_cache_status(cache_root, nginx_contract),
    }


def render_text(payload: dict[str, Any]) -> str:
    lines = [f"check-runtime-producer-readiness: {payload['status']}"]
    lines.extend(
        [
            "",
            "| Component | Required | Status | Path | Fix |",
            "|---|---|---|---|---|",
        ]
    )
    for item in payload["components"]:
        lines.append(
            f"| {item['component']} | {item['required']} | {item['status']} | `{item['path'] or '-'}` | `{item['fix']}` |"
        )
    nginx_contract = payload.get("nginx_runtime_contract", {})
    contract_fields = nginx_contract.get("fields", {}) if isinstance(nginx_contract, dict) else {}
    field_statuses = nginx_contract.get("field_status", {}) if isinstance(nginx_contract, dict) else {}
    lines.extend(
        [
            "",
            "## NGINX Runtime Contract",
            "",
            f"- Status: {nginx_contract.get('status', 'BLOCKED') if isinstance(nginx_contract, dict) else 'BLOCKED'}",
            f"- Manifest: `{nginx_contract.get('manifest_path', '-') if isinstance(nginx_contract, dict) else '-'}`",
            f"- Record: `{nginx_contract.get('record_path', 'missing') if isinstance(nginx_contract, dict) else 'missing'}`",
            "",
            "| Field | Status | Value |",
            MARKDOWN_THREE_COLUMN_SEPARATOR,
        ]
    )
    for field in NGINX_RUNTIME_CONTRACT_FIELDS:
        value = contract_markdown_value(contract_fields.get(field)) or "-"
        lines.append(f"| {field} | {field_statuses.get(field, 'BLOCKED')} | `{value}` |")
    issues = nginx_contract.get("issues", []) if isinstance(nginx_contract, dict) else []
    if issues:
        lines.append("- Issues: " + "; ".join(contract_markdown_value(issue) for issue in issues))
    lines.extend(["", "| Path | Status | Notes |", MARKDOWN_THREE_COLUMN_SEPARATOR])
    for item in payload["paths"]:
        lines.append(f"| `{item['label']}={item['path']}` | {item['status']} | {item['notes']} |")
    lines.extend(["", "| Source | Status | Notes |", MARKDOWN_THREE_COLUMN_SEPARATOR])
    for item in payload["network_cache"]:
        lines.append(f"| {item['source']} | {item['status']} | `{item['path']}`: {item['notes']} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector-root", default=".")
    parser.add_argument("--framework-root", default=None)
    parser.add_argument("--build-root", default=os.environ.get("BUILD_ROOT"))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    connector_root = Path(args.connector_root).resolve()
    framework_root = Path(args.framework_root).resolve() if args.framework_root else connector_root / "modules/ModSecurity-test-Framework"
    default_paths = verified_runtime_paths(os.environ)
    build_root = Path(args.build_root or default_paths["BUILD_ROOT"]).resolve()
    payload = build_payload(connector_root, framework_root, build_root)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        sys.stdout.write(render_text(payload))
    if payload["status"] == "BLOCKED":
        return 77
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
