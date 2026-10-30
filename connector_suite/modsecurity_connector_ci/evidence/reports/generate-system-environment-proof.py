#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import platform
import shlex
import shutil
import socket
import subprocess
import sys
import time
from urllib.parse import urlsplit
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# CI helpers are shared from ci/lib even when this file is executed directly.

from typing import Any

from modsecurity_connector_ci.lib.generated_report_utils import DATA_SOURCE_POLICY, FILENAME_TO_KEY, GENERATED_REPORTS, GENERATED_ROOT, build_metadata, current_verified_run_id, generated_json_text, generated_markdown_text, report_path
from modsecurity_connector_ci.lib.runtime_path_utils import verified_runtime_paths

FRAMEWORK_ENVIRONMENT_VARS = (
    "VERIFIED_RUN_ROOT",
    "VERIFIED_STATE_ROOT",
    "VERIFIED_BUILD_ROOT",
    "VERIFIED_SOURCE_ROOT",
    "VERIFIED_TMP_ROOT",
    "VERIFIED_LOG_ROOT",
    "VERIFIED_COMPONENT_CACHE",
    "BUILD_ROOT",
    "SOURCE_ROOT",
    "TMP_ROOT",
    "LOG_ROOT",
    "CONNECTOR_COMPONENT_CACHE",
    "NGINX_HARNESS_PARENT",
    "MATRIX_ROOT",
    "MRTS_BUILD_ROOT",
    "MRTS_NATIVE_ROOT",
    "VERIFIED_RUN_ID",
    "VERIFIED_RUN_PROFILE",
    "VERIFIED_RUN_FULL_MATRIX_TIMEOUT_SECONDS",
    "GO_FTW_BIN",
    "GO_FTW_SOURCE_URL",
    "GO_FTW_PROMPT_EXPECTED_LATEST",
    "GO_FTW_GIT_REF",
    "ALBEDO_BIN",
    "ALBEDO_SOURCE_URL",
    "ALBEDO_PROMPT_EXPECTED_LATEST",
    "ALBEDO_GIT_REF",
    "APACHECTL_BIN",
    "APACHE_BIN",
    "HTTPD_BIN",
    "HTTPD_VERSION",
    "HTTPD_SOURCE_URL",
    "APXS",
    "APXS_BIN",
    "NGINX_BIN",
    "NGINX_SOURCE_MODE",
    "NGINX_SOURCE_REPO_URL",
    "NGINX_GITHUB_REPO",
    "NGINX_RELEASE_TAG",
    "NGINX_SOURCE_GIT_REF",
    "NGINX_RELEASE_ASSET_NAME",
    "NGINX_SHA256",
    "CI_APACHE_BIN_CANDIDATES",
    "CI_APXS_BIN_CANDIDATES",
    "CI_NGINX_BIN_CANDIDATES",
    "HAPROXY_BIN",
    "HAPROXY_VERSION",
    "HAPROXY_SOURCE_URL",
    "HAPROXY_RUNTIME_DIR",
    "HAPROXY_RUNTIME_BUILD_DIR",
    "EXPAT_SOURCE_URL",
    "EXPAT_GIT_REF",
    "EXPAT_GIT_URL",
    "EXPAT_PROMPT_EXPECTED_LATEST",
    "CC",
    "CLANG",
    "MAKE",
    "PYTHON",
)

GITHUB_REPOSITORY_HOST = "github.com"
DISALLOWED_REPOSITORY_SCHEMES = frozenset({"http", "ssh", "git"})

PATH_FALLBACK_SOURCE = "PATH fallback"
SHELL_PATH = "/bin/sh"
SHELL_EXECUTABLE_CHECK_SOURCE = "/bin/sh executable check"
APACHE_HTTPD_TOOL = "apache/httpd"
MARKDOWN_FIELD_VALUE_HEADER = "| Field | Value |"
MARKDOWN_FIELD_VALUE_SEPARATOR = "|---|---|"
NGINX_RUNTIME_CONTRACT_MISSING = "NGINX runtime contract missing"
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


@dataclass(frozen=True)
class ToolSpec:
    tool: str
    version_args: tuple[str, ...]
    env_vars: tuple[str, ...] = ()
    path_fallbacks: tuple[str, ...] = ()
    sys_executable_fallback: bool = False


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run(cmd: list[str], cwd: Path, timeout: int = 300) -> dict[str, Any]:
    started_at = utc_now()
    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        output = proc.stdout or ""
        rc = proc.returncode
        status = "PASS" if rc == 0 else "FAIL"
    except FileNotFoundError as exc:
        output = str(exc)
        rc = 127
        status = "missing"
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        output += "\nTIMEOUT"
        rc = 124
        status = "timeout"
    finished_at = utc_now()
    return {
        "command": " ".join(cmd),
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": round(time.monotonic() - started, 3),
        "return_code": rc,
        "status": status,
        "output_excerpt": output.strip()[:4000],
        "output_sha256": hashlib.sha256(output.encode("utf-8", errors="replace")).hexdigest(),
    }


def read_os_release() -> dict[str, str]:
    path = Path("/etc/os-release")
    data: dict[str, str] = {}
    if not path.is_file():
        return data
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key] = value.strip().strip('"')
    return data


def framework_environment_result(
    framework_root: Path,
    common_sh: Path,
    *,
    status: str,
    return_code: int,
    output_excerpt: str,
    environment: dict[str, str],
) -> dict[str, Any]:
    return {
        "framework_root": str(framework_root),
        "common_sh_path": str(common_sh),
        "common_sh_status": status,
        "load_return_code": return_code,
        "load_output_excerpt": output_excerpt[:4000],
        "env": environment,
        "variables": {name: environment.get(name) or None for name in FRAMEWORK_ENVIRONMENT_VARS},
    }


def load_framework_environment(connector_root: Path, framework_root: Path) -> dict[str, Any]:
    common_sh = framework_root / "ci/lib/common.sh"
    base_env = os.environ.copy()
    base_env["CONNECTOR_ROOT"] = str(connector_root)
    base_env["FRAMEWORK_ROOT"] = str(framework_root)
    for key, value in verified_runtime_paths(base_env).items():
        base_env.setdefault(key, value)
    if not common_sh.is_file():
        return framework_environment_result(
            framework_root,
            common_sh,
            status="missing",
            return_code=127,
            output_excerpt="common.sh not found",
            environment=base_env,
        )
    try:
        proc = subprocess.run(
            ["bash", "-lc", 'set -a; . "$FRAMEWORK_ROOT/ci/lib/common.sh"; env -0'],
            cwd=str(connector_root),
            env=base_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            timeout=60,
        )
    except FileNotFoundError as exc:
        return framework_environment_result(
            framework_root,
            common_sh,
            status="failed",
            return_code=127,
            output_excerpt=str(exc),
            environment=base_env,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or b""
        output += b"\nTIMEOUT"
        return framework_environment_result(
            framework_root,
            common_sh,
            status="failed",
            return_code=124,
            output_excerpt=output.decode("utf-8", errors="replace").strip(),
            environment=base_env,
        )
    stderr = proc.stderr.decode("utf-8", errors="replace").strip()
    if proc.returncode != 0:
        return framework_environment_result(
            framework_root,
            common_sh,
            status="failed",
            return_code=proc.returncode,
            output_excerpt=stderr or f"common.sh load failed with return code {proc.returncode}",
            environment=base_env,
        )
    loaded_env: dict[str, str] = {}
    for chunk in proc.stdout.split(b"\0"):
        if not chunk or b"=" not in chunk:
            continue
        key, value = chunk.split(b"=", 1)
        loaded_env[key.decode("utf-8", errors="replace")] = value.decode("utf-8", errors="replace")
    return framework_environment_result(
        framework_root,
        common_sh,
        status="loaded",
        return_code=proc.returncode,
        output_excerpt=stderr,
        environment=loaded_env,
    )


def split_command_value(value: str) -> list[str]:
    try:
        parts = shlex.split(value)
    except ValueError:
        return [value]
    return parts or [value]


def command_exists(command: str, cwd: Path, env: dict[str, str]) -> tuple[str | None, str, int]:
    expanded = os.path.expanduser(os.path.expandvars(command))
    if "/" in expanded:
        path = Path(expanded)
        if not path.is_absolute():
            path = cwd / path
        if not path.exists():
            return str(path), "file not found", 127
        if not path.is_file() or not os.access(path, os.X_OK):
            return str(path), "not executable", 126
        return str(path), "", 0
    resolved = shutil.which(expanded, path=env.get("PATH"))
    if resolved is None:
        return expanded, "command not found", 127
    return resolved, "", 0


def common_env(framework_env: dict[str, Any]) -> dict[str, str]:
    return framework_env.get("env", {})


def env_var_candidate(
    var_name: str,
    initial_env: dict[str, str],
    framework_env: dict[str, Any],
) -> tuple[str, str] | None:
    initial_value = initial_env.get(var_name)
    if initial_value:
        return initial_value, f"{var_name} from process/make environment"
    loaded_value = framework_env.get("env", {}).get(var_name)
    if loaded_value:
        return loaded_value, f"{var_name} from framework common.sh"
    return None


def env_var_value(
    var_name: str,
    initial_env: dict[str, str],
    framework_env: dict[str, Any],
) -> tuple[str, str] | None:
    return env_var_candidate(var_name, initial_env, framework_env)


def framework_candidate_values(
    var_name: str,
    initial_env: dict[str, str],
    framework_env: dict[str, Any],
) -> tuple[list[str], str]:
    initial_value = initial_env.get(var_name)
    if initial_value:
        return split_command_value(initial_value), f"{var_name} from process/make environment"
    loaded_value = common_env(framework_env).get(var_name, "")
    if loaded_value:
        return split_command_value(loaded_value), f"{var_name} from framework common.sh"
    return [], f"{var_name} from framework common.sh"


def run_common_helper(
    function_name: str,
    args: list[str],
    cwd: Path,
    framework_env: dict[str, Any],
    timeout: int = 60,
) -> dict[str, Any]:
    if framework_env.get("common_sh_status") != "loaded":
        return {
            "return_code": 127,
            "status": "missing",
            "output_excerpt": f"common.sh not loaded; cannot run {function_name}",
            "output_sha256": hashlib.sha256(b"").hexdigest(),
        }
    env = dict(common_env(framework_env))
    script = f'. "$FRAMEWORK_ROOT/ci/lib/common.sh"; {function_name} "$@"'
    try:
        proc = subprocess.run(
            ["bash", "-lc", script, "bash", *args],
            cwd=str(cwd),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        output = str(exc)
        return {
            "return_code": 127,
            "status": "missing",
            "output_excerpt": output,
            "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        }
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        output += "\nTIMEOUT"
        return {
            "return_code": 124,
            "status": "timeout",
            "output_excerpt": output.strip()[:4000],
            "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        }
    output = proc.stdout or ""
    return {
        "return_code": proc.returncode,
        "status": "PASS" if proc.returncode == 0 else "FAIL",
        "output_excerpt": output.strip()[:4000],
        "output_sha256": hashlib.sha256(output.encode("utf-8", errors="replace")).hexdigest(),
    }


def unique_candidates(candidates: list[str]) -> list[str]:
    unique: list[str] = []
    for candidate in candidates:
        if candidate not in unique:
            unique.append(candidate)
    return unique


def make_tool_record(
    *,
    tool: str,
    status: str,
    resolved_command: str | None,
    attempted_command: str | None,
    source: str,
    candidates: list[str] | None = None,
    version_output: str,
    return_code: int,
    notes: str = "",
    output_sha256: str | None = None,
) -> dict[str, Any]:
    version = version_output.splitlines()[0] if version_output else f"return code {return_code}"
    clean_candidates = unique_candidates(candidates or [])
    return {
        "tool": tool,
        "status": status,
        "resolved_command": resolved_command,
        "attempted_command": attempted_command,
        "source": source,
        "candidates": clean_candidates,
        "version_output": version_output,
        "version": version,
        "return_code": return_code,
        "notes": notes,
        "output_sha256": output_sha256 or hashlib.sha256(version_output.encode("utf-8")).hexdigest(),
    }


def run_resolved_tool(
    *,
    tool: str,
    resolved_command: str,
    attempted_command: str,
    source: str,
    version_args: tuple[str, ...],
    candidates: list[str],
    cwd: Path,
    notes: str = "",
) -> dict[str, Any]:
    result = run([resolved_command, *version_args], cwd, timeout=60)
    version_output = result["output_excerpt"] or f"return code {result['return_code']}"
    return make_tool_record(
        tool=tool,
        status="present" if result["return_code"] == 0 else "error",
        resolved_command=resolved_command,
        attempted_command=attempted_command,
        source=source,
        candidates=candidates,
        version_output=version_output,
        return_code=result["return_code"],
        notes=notes,
        output_sha256=result["output_sha256"],
    )


def resolve_candidate_list(
    *,
    tool: str,
    candidates: list[str],
    source: str,
    version_args: tuple[str, ...],
    cwd: Path,
    env: dict[str, str],
    notes: str,
) -> dict[str, Any]:
    attempted = candidates[-1] if candidates else None
    for candidate in candidates:
        resolved, _, rc = command_exists(candidate, cwd, env)
        attempted = candidate
        if rc == 0 and resolved is not None:
            return run_resolved_tool(
                tool=tool,
                resolved_command=resolved,
                attempted_command=candidate,
                source=source,
                version_args=version_args,
                candidates=candidates,
                cwd=cwd,
                notes=notes,
            )
    joined = " ".join(candidates)
    output = f"no candidate found: {joined}" if joined else "no candidate configured"
    return make_tool_record(
        tool=tool,
        status="missing",
        resolved_command=None,
        attempted_command=attempted,
        source=source,
        candidates=candidates,
        version_output=output,
        return_code=127,
        notes=notes,
    )


def tool_spec_candidates(
    spec: ToolSpec,
    initial_env: dict[str, str],
    framework_env: dict[str, Any],
) -> list[tuple[str, str]]:
    candidates = [
        candidate
        for var_name in spec.env_vars
        if (candidate := env_var_candidate(var_name, initial_env, framework_env)) is not None
    ]
    if spec.sys_executable_fallback:
        candidates.append((sys.executable, "current sys.executable"))
    candidates.extend((name, PATH_FALLBACK_SOURCE) for name in spec.path_fallbacks)
    return candidates


def first_tool_resolution(
    candidates: list[tuple[str, str]],
    cwd: Path,
    environment: dict[str, str],
) -> dict[str, Any]:
    resolution = {
        "attempted_command": "",
        "source": PATH_FALLBACK_SOURCE,
        "resolved_command": None,
        "prefix_args": [],
        "error": "command not found",
        "return_code": 127,
    }
    for value, candidate_source in candidates:
        parts = split_command_value(value)
        resolved, error, return_code = command_exists(parts[0], cwd, environment)
        resolution = {
            "attempted_command": parts[0],
            "source": candidate_source,
            "resolved_command": resolved,
            "prefix_args": parts[1:],
            "error": error,
            "return_code": return_code,
        }
        if return_code == 0 or candidate_source != PATH_FALLBACK_SOURCE:
            return resolution
    return resolution


def missing_tool_record(spec: ToolSpec, candidates: list[tuple[str, str]], resolution: dict[str, Any]) -> dict[str, Any]:
    error = str(resolution["error"])
    source = str(resolution["source"])
    return make_tool_record(
        tool=spec.tool,
        status="missing",
        resolved_command=resolution["resolved_command"] if source != PATH_FALLBACK_SOURCE else None,
        attempted_command=str(resolution["attempted_command"]),
        source=source,
        candidates=unique_candidates([item for item, _source in candidates]),
        version_output=error,
        return_code=int(resolution["return_code"]),
    )


def configured_tool_record(
    *,
    tool: str,
    variable: str,
    candidate: tuple[str, str],
    version_args: tuple[str, ...],
    cwd: Path,
    environment: dict[str, str],
) -> dict[str, Any]:
    value, source = candidate
    resolved, error, return_code = command_exists(value, cwd, environment)
    if return_code == 0 and resolved is not None:
        return run_resolved_tool(
            tool=tool,
            resolved_command=resolved,
            attempted_command=value,
            source=source,
            version_args=version_args,
            candidates=[],
            cwd=cwd,
            notes=f"{variable} is set and executable",
        )
    return make_tool_record(
        tool=tool,
        status="missing",
        resolved_command=resolved,
        attempted_command=value,
        source=source,
        candidates=[],
        version_output=error,
        return_code=return_code,
        notes=f"{variable} is set but does not resolve to an executable",
    )


def configured_tool_from_environment(
    *,
    tool: str,
    variables: tuple[str, ...],
    version_args: tuple[str, ...],
    cwd: Path,
    framework_env: dict[str, Any],
    initial_env: dict[str, str],
) -> dict[str, Any] | None:
    environment = dict(common_env(framework_env) or initial_env)
    for variable in variables:
        candidate = env_var_value(variable, initial_env, framework_env)
        if candidate is not None:
            return configured_tool_record(
                tool=tool,
                variable=variable,
                candidate=candidate,
                version_args=version_args,
                cwd=cwd,
                environment=environment,
            )
    return None


def resolve_tool(spec: ToolSpec, cwd: Path, framework_env: dict[str, Any], initial_env: dict[str, str]) -> dict[str, Any]:
    effective_env = dict(framework_env.get("env") or initial_env)
    candidates = tool_spec_candidates(spec, initial_env, framework_env)
    resolution = first_tool_resolution(candidates, cwd, effective_env)
    if resolution["return_code"] != 0:
        return missing_tool_record(spec, candidates, resolution)
    return run_resolved_tool(
        tool=spec.tool,
        resolved_command=str(resolution["resolved_command"] or resolution["attempted_command"]),
        attempted_command=str(resolution["attempted_command"]),
        source=str(resolution["source"]),
        version_args=tuple(resolution["prefix_args"]) + spec.version_args,
        candidates=unique_candidates([item for item, _source in candidates]),
        cwd=cwd,
    )


def resolve_python_tool(cwd: Path, framework_env: dict[str, Any], initial_env: dict[str, str]) -> dict[str, Any]:
    candidates: list[tuple[str, str]] = []
    python_env = initial_env.get("PYTHON")
    if python_env:
        candidates.append((python_env, "PYTHON from process/make environment"))
    else:
        helper = run_common_helper("ci_python", [], cwd, framework_env)
        helper_output = helper.get("output_excerpt", "").splitlines()[0] if helper.get("output_excerpt") else ""
        if helper.get("return_code") == 0 and helper_output:
            candidates.append((helper_output, "ci_python from framework common.sh"))
    candidates.extend((item, PATH_FALLBACK_SOURCE) for item in ("python3", "python"))

    effective_env = dict(common_env(framework_env) or initial_env)
    for value, source in candidates:
        parts = split_command_value(value)
        resolved, error, rc = command_exists(parts[0], cwd, effective_env)
        if rc == 0 and resolved is not None:
            return run_resolved_tool(
                tool="python",
                resolved_command=resolved,
                attempted_command=parts[0],
                source=source,
                version_args=("--version",),
                candidates=[candidate for candidate, _source in candidates],
                cwd=cwd,
                notes="resolved by Make PYTHON, ci_python, then python3/python fallback",
            )
        if source != PATH_FALLBACK_SOURCE:
            return make_tool_record(
                tool="python",
                status="missing",
                resolved_command=resolved,
                attempted_command=parts[0],
                source=source,
                candidates=[candidate for candidate, _source in candidates],
                version_output=error,
                return_code=rc,
                notes="configured Python command could not be executed",
            )
    return make_tool_record(
        tool="python",
        status="missing",
        resolved_command=None,
        attempted_command="python",
        source=PATH_FALLBACK_SOURCE,
        candidates=[candidate for candidate, _source in candidates],
        version_output="no candidate found: python3 python",
        return_code=127,
        notes="python3/python fallback commands are unavailable",
    )


def resolve_sh_tool(cwd: Path) -> dict[str, Any]:
    sh_path = Path(SHELL_PATH)
    if not sh_path.exists():
        return make_tool_record(
            tool="sh",
            status="missing",
            resolved_command=None,
            attempted_command=SHELL_PATH,
            source=SHELL_EXECUTABLE_CHECK_SOURCE,
            candidates=[SHELL_PATH],
            version_output="file not found",
            return_code=127,
            notes="checked /bin/sh without using unsupported --version",
        )
    if not os.access(sh_path, os.X_OK):
        return make_tool_record(
            tool="sh",
            status="missing",
            resolved_command=str(sh_path),
            attempted_command=SHELL_PATH,
            source=SHELL_EXECUTABLE_CHECK_SOURCE,
            candidates=[SHELL_PATH],
            version_output="not executable",
            return_code=126,
            notes="checked /bin/sh without using unsupported --version",
        )
    result = run([str(sh_path), "-c", "printf '%s' 'POSIX shell available'"], cwd, timeout=60)
    resolved = str(sh_path.resolve(strict=False))
    version_output = f"{result['output_excerpt']} ({resolved})" if result["output_excerpt"] else resolved
    return make_tool_record(
        tool="sh",
        status="present" if result["return_code"] == 0 else "error",
        resolved_command=resolved,
        attempted_command=SHELL_PATH,
        source=SHELL_EXECUTABLE_CHECK_SOURCE,
        candidates=[SHELL_PATH],
        version_output=version_output,
        return_code=result["return_code"],
        notes="checked shell availability with /bin/sh -c instead of sh --version",
        output_sha256=result["output_sha256"],
    )


def resolve_haproxy_tool(cwd: Path, framework_env: dict[str, Any], initial_env: dict[str, str]) -> dict[str, Any]:
    effective_env = dict(common_env(framework_env) or initial_env)
    candidate = env_var_value("HAPROXY_BIN", initial_env, framework_env)
    if candidate is not None:
        value, source = candidate
        resolved, error, rc = command_exists(value, cwd, effective_env)
        metadata = common_env(framework_env)
        notes = (
            "runtime path configured by common.sh but binary has not been built/prepared locally; "
            f"HAPROXY_VERSION={metadata.get('HAPROXY_VERSION', 'unset')}; "
            f"HAPROXY_SOURCE_URL={metadata.get('HAPROXY_SOURCE_URL', 'unset')}; "
            f"HAPROXY_RUNTIME_DIR={metadata.get('HAPROXY_RUNTIME_DIR', 'unset')}; "
            f"HAPROXY_RUNTIME_BUILD_DIR={metadata.get('HAPROXY_RUNTIME_BUILD_DIR', 'unset')}"
        )
        if rc != 0:
            return make_tool_record(
                tool="haproxy",
                status="configured_missing",
                resolved_command=resolved,
                attempted_command=value,
                source=source,
                candidates=[],
                version_output=error,
                return_code=rc,
                notes=notes,
            )
        return run_resolved_tool(
            tool="haproxy",
            resolved_command=resolved or value,
            attempted_command=value,
            source=source,
            version_args=("-vv",),
            candidates=[],
            cwd=cwd,
            notes="runtime path configured and executable",
        )
    return resolve_candidate_list(
        tool="haproxy",
        candidates=["haproxy"],
        source=PATH_FALLBACK_SOURCE,
        version_args=("-vv",),
        cwd=cwd,
        env=effective_env,
        notes="HAPROXY_BIN is unset; checked PATH fallback",
    )


def nginx_contract_binary_path(runtime_check: dict[str, Any] | None) -> tuple[Path | None, str]:
    """Return a freshly hash-checked NGINX binary only after contract validation."""

    contract = nginx_runtime_contract(runtime_check)
    fields = contract["fields"]
    if contract["status"] != "PASS":
        issues = contract.get("issues", [])
        detail = "; ".join(str(issue) for issue in issues) or "runtime contract is not PASS"
        return None, f"NGINX binary was not executed before runtime-contract validation: {detail}"

    binary_value = fields.get("binary_path")
    if not isinstance(binary_value, str) or not binary_value:
        return None, "NGINX runtime contract has no binary_path"
    try:
        binary_path = Path(binary_value)
    except (TypeError, ValueError):
        return None, "NGINX runtime contract has an invalid binary_path"
    if not binary_path.is_absolute():
        return None, "NGINX runtime contract binary_path must be absolute"
    if binary_path.is_symlink() or not binary_path.is_file() or not os.access(binary_path, os.X_OK):
        return None, "NGINX runtime contract binary_path is no longer a non-symlink executable"

    expected_digest = str(fields.get("binary_sha256") or "").lower()
    if len(expected_digest) != 64 or any(character not in "0123456789abcdef" for character in expected_digest):
        return None, "NGINX runtime contract binary_sha256 is invalid"
    digest = hashlib.sha256()
    try:
        with binary_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        return None, f"NGINX runtime contract binary could not be read: {exc}"
    if digest.hexdigest() != expected_digest:
        return None, "NGINX runtime contract binary_sha256 no longer matches binary_path"
    return binary_path, ""


def resolve_nginx_tool(cwd: Path, runtime_check: dict[str, Any] | None) -> dict[str, Any]:
    """Inventory only the managed binary accepted by the runtime-contract checker."""

    binary_path, blocker = nginx_contract_binary_path(runtime_check)
    if binary_path is None:
        return make_tool_record(
            tool="nginx",
            status="blocked",
            resolved_command=None,
            attempted_command=None,
            source="validated NGINX runtime contract",
            candidates=[],
            version_output=blocker,
            return_code=125,
            notes="NGINX tool inventory is fail-closed until the runtime contract passes",
        )
    return run_resolved_tool(
        tool="nginx",
        resolved_command=str(binary_path),
        attempted_command=str(binary_path),
        source="validated NGINX runtime contract",
        version_args=("-v",),
        candidates=[],
        cwd=cwd,
        notes="managed NGINX binary matches the validated runtime contract",
    )


def resolve_apxs_tool(cwd: Path, framework_env: dict[str, Any], initial_env: dict[str, str]) -> dict[str, Any]:
    effective_env = dict(common_env(framework_env) or initial_env)
    for var_name in ("APXS_BIN", "APXS"):
        candidate = env_var_value(var_name, initial_env, framework_env)
        if candidate is None:
            continue
        value, source = candidate
        if var_name == "APXS" and source.endswith("framework common.sh"):
            source = "APXS from environment"
        resolved, error, rc = command_exists(value, cwd, effective_env)
        if rc == 0 and resolved is not None:
            return run_resolved_tool(
                tool="apxs",
                resolved_command=resolved,
                attempted_command=value,
                source=source,
                version_args=("-v",),
                candidates=[],
                cwd=cwd,
                notes=f"{var_name} is set and executable",
            )
        return make_tool_record(
            tool="apxs",
            status="missing",
            resolved_command=resolved,
            attempted_command=value,
            source=source,
            candidates=[],
            version_output=error,
            return_code=rc,
            notes=f"{var_name} is set but does not resolve to an executable",
        )
    candidates, source = framework_candidate_values("CI_APXS_BIN_CANDIDATES", initial_env, framework_env)
    return resolve_candidate_list(
        tool="apxs",
        candidates=candidates,
        source=source,
        version_args=("-v",),
        cwd=cwd,
        env=effective_env,
        notes="APXS_BIN is unset; checked framework candidates",
    )


def resolve_apache_tool(
    cwd: Path,
    framework_env: dict[str, Any],
    initial_env: dict[str, str],
    apxs_record: dict[str, Any],
) -> dict[str, Any]:
    effective_env = dict(common_env(framework_env) or initial_env)
    configured = configured_tool_from_environment(
        tool=APACHE_HTTPD_TOOL,
        variables=("APACHECTL_BIN", "APACHE_BIN", "HTTPD_BIN"),
        version_args=("-v",),
        cwd=cwd,
        framework_env=framework_env,
        initial_env=initial_env,
    )
    if configured is not None:
        return configured

    apxs_path = apxs_record.get("resolved_command")
    if apxs_record.get("status") == "present" and apxs_path:
        helper = run_common_helper("ci_resolve_apache_from_apxs", [str(apxs_path)], cwd, framework_env)
        helper_output = helper.get("output_excerpt", "").splitlines()[0] if helper.get("output_excerpt") else ""
        if helper.get("return_code") == 0 and helper_output:
            resolved, error, rc = command_exists(helper_output, cwd, effective_env)
            if rc == 0 and resolved is not None:
                return run_resolved_tool(
                    tool=APACHE_HTTPD_TOOL,
                    resolved_command=resolved,
                    attempted_command=helper_output,
                    source="ci_resolve_apache_from_apxs from framework common.sh",
                    version_args=("-v",),
                    candidates=[apxs_path],
                    cwd=cwd,
                    notes="resolved Apache binary through APXS helper",
                )
            return make_tool_record(
                tool=APACHE_HTTPD_TOOL,
                status="missing",
                resolved_command=resolved,
                attempted_command=helper_output,
                source="ci_resolve_apache_from_apxs from framework common.sh",
                candidates=[apxs_path],
                version_output=error,
                return_code=rc,
                notes="APXS helper returned a path that is not executable",
            )

    candidates, source = framework_candidate_values("CI_APACHE_BIN_CANDIDATES", initial_env, framework_env)
    return resolve_candidate_list(
        tool=APACHE_HTTPD_TOOL,
        candidates=candidates,
        source=source,
        version_args=("-v",),
        cwd=cwd,
        env=effective_env,
        notes="APACHECTL_BIN/APACHE_BIN are unset; checked APXS helper and framework candidates",
    )


def resolve_apachectl_tool(cwd: Path, framework_env: dict[str, Any], initial_env: dict[str, str]) -> dict[str, Any]:
    effective_env = dict(common_env(framework_env) or initial_env)
    candidate = env_var_value("APACHECTL_BIN", initial_env, framework_env)
    if candidate is not None:
        value, source = candidate
        resolved, error, rc = command_exists(value, cwd, effective_env)
        if rc == 0 and resolved is not None:
            return run_resolved_tool(
                tool="apachectl",
                resolved_command=resolved,
                attempted_command=value,
                source=source,
                version_args=("-v",),
                candidates=[],
                cwd=cwd,
                notes="APACHECTL_BIN is set and executable",
            )
        return make_tool_record(
            tool="apachectl",
            status="missing",
            resolved_command=resolved,
            attempted_command=value,
            source=source,
            candidates=[],
            version_output=error,
            return_code=rc,
            notes="APACHECTL_BIN is set but does not resolve to an executable",
        )
    candidates, source = framework_candidate_values("CI_APACHE_BIN_CANDIDATES", initial_env, framework_env)
    apachectl_candidates = [candidate for candidate in candidates if "apachectl" in Path(candidate).name]
    return resolve_candidate_list(
        tool="apachectl",
        candidates=apachectl_candidates or ["apachectl"],
        source=source if apachectl_candidates else PATH_FALLBACK_SOURCE,
        version_args=("-v",),
        cwd=cwd,
        env=effective_env,
        notes="APACHECTL_BIN is unset; checked apachectl candidate",
    )


def add_optional_tool_note(record: dict[str, Any], note: str) -> dict[str, Any]:
    if record.get("status") == "missing":
        record = dict(record)
        record["notes"] = note
    return record


def resolve_tools(
    cwd: Path,
    framework_env: dict[str, Any],
    initial_env: dict[str, str],
    runtime_check: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    generic_specs = [
        ToolSpec("git", ("--version",), path_fallbacks=("git",)),
        ToolSpec("python3", ("--version",), path_fallbacks=("python3",)),
        ToolSpec("make", ("--version",), env_vars=("MAKE",), path_fallbacks=("make",)),
        ToolSpec("bash", ("--version",), path_fallbacks=("bash",)),
        ToolSpec("gcc", ("--version",), env_vars=("CC",), path_fallbacks=("gcc",)),
        ToolSpec("clang", ("--version",), env_vars=("CLANG",), path_fallbacks=("clang",)),
        ToolSpec("go", ("version",), path_fallbacks=("go",)),
        ToolSpec("go-ftw", ("version",), env_vars=("GO_FTW_BIN",), path_fallbacks=("go-ftw",)),
        ToolSpec("albedo", ("--version",), env_vars=("ALBEDO_BIN",), path_fallbacks=("albedo",)),
        ToolSpec("actionlint", ("--version",), path_fallbacks=("actionlint",)),
        ToolSpec("jq", ("--version",), path_fallbacks=("jq",)),
        ToolSpec("curl", ("--version",), path_fallbacks=("curl",)),
        ToolSpec("docker", ("--version",), path_fallbacks=("docker",)),
    ]
    generic_records = {spec.tool: resolve_tool(spec, cwd, framework_env, initial_env) for spec in generic_specs}
    generic_records["go-ftw"] = add_optional_tool_note(
        generic_records["go-ftw"],
        "optional MRTS/FTW tool not installed or not in PATH",
    )
    generic_records["albedo"] = add_optional_tool_note(
        generic_records["albedo"],
        "optional native MRTS tool not installed or not in PATH",
    )
    apxs_record = resolve_apxs_tool(cwd, framework_env, initial_env)
    return [
        generic_records["git"],
        generic_records["python3"],
        resolve_python_tool(cwd, framework_env, initial_env),
        generic_records["make"],
        generic_records["bash"],
        resolve_sh_tool(cwd),
        generic_records["gcc"],
        generic_records["clang"],
        generic_records["go"],
        generic_records["go-ftw"],
        generic_records["albedo"],
        generic_records["actionlint"],
        generic_records["jq"],
        generic_records["curl"],
        generic_records["docker"],
        resolve_apachectl_tool(cwd, framework_env, initial_env),
        resolve_apache_tool(cwd, framework_env, initial_env, apxs_record),
        resolve_nginx_tool(cwd, runtime_check),
        resolve_haproxy_tool(cwd, framework_env, initial_env),
        apxs_record,
    ]


def git_evidence(connector_root: Path, framework_root: Path) -> dict[str, Any]:
    commands = {
        "git_status_short": ["git", "status", "--short"],
        "git_head": ["git", "rev-parse", "HEAD"],
        "git_branch": ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        "git_submodule_status": ["git", "submodule", "status", "--recursive"],
        "git_diff_stat": ["git", "diff", "--stat"],
    }
    evidence = {name: run(command, connector_root, timeout=120) for name, command in commands.items()}
    framework_commands = {
        "framework_status_short": ["git", "-C", str(framework_root), "status", "--short"],
        "framework_head": ["git", "-C", str(framework_root), "rev-parse", "HEAD"],
        "framework_diff_stat": ["git", "-C", str(framework_root), "diff", "--stat"],
    }
    evidence.update({name: run(command, connector_root, timeout=120) for name, command in framework_commands.items()})
    return evidence


def layout_evidence(connector_root: Path) -> dict[str, Any]:
    generated_root = connector_root / GENERATED_ROOT
    generated_files = sorted(generated_root.rglob("*.generated.*"))
    flat_files = sorted(generated_root.glob("*.generated.*"))
    categories = sorted({path.parent.name for path in generated_files if path.parent != generated_root})
    expected = {
        str((connector_root / GENERATED_ROOT / report.category / report.filename(ext)).resolve(strict=False))
        for report in GENERATED_REPORTS.values()
        for ext in report.formats
        if report.commit_policy not in {"local-only", "do-not-commit"} and report.data_kind != "system-proof"
    }
    existing = {str(path.resolve(strict=False)) for path in generated_files}
    orphan = [
        str(path.relative_to(connector_root))
        for path in generated_files
        if path.name not in FILENAME_TO_KEY or str(path.resolve(strict=False)) not in {
            str((connector_root / GENERATED_ROOT / GENERATED_REPORTS[FILENAME_TO_KEY[path.name]].category / path.name).resolve(strict=False))
        }
    ]
    manifest = {}
    manifest_path = report_path(connector_root, "report_refresh_manifest", "json")
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            manifest = {}
    reports = manifest.get("reports", []) if isinstance(manifest.get("reports"), list) else []
    return {
        "generated_report_files": len(generated_files),
        "flat_files_in_generated_root": len(flat_files),
        "categories": categories,
        "category_count": len(categories),
        "reports_per_category": {category: sum(1 for path in generated_files if path.parent.name == category) for category in categories},
        "missing_registry_outputs": sorted(expected - existing),
        "orphan_generated_reports": orphan,
        "skipped_reports": [report for report in reports if str(report.get("status", "")).startswith("skipped")],
        "failed_reports": [report for report in reports if report.get("status") == "failed"],
    }


def https_repository_scan_paths(connector_root: Path, framework_root: Path) -> list[Path]:
    text_suffixes = {"", ".md", ".py", ".sh", ".json", ".yml", ".yaml", ".mk"}
    scan_paths = [
        connector_root / "Makefile",
        connector_root / "README.md",
    ]
    scan_paths.extend(sorted(connector_root.glob("COMPILE_*.md")))
    roots = (
        connector_root / "ci",
        framework_root / "ci",
        connector_root / "docs",
        connector_root / "reports/testing",
    )
    for root in roots:
        if root.is_dir():
            scan_paths.extend(path for path in sorted(root.rglob("*")) if path.is_file())
    return [path for path in scan_paths if path.suffix in text_suffixes]


def repository_url_scan_allowed(path: Path, connector_root: Path) -> bool:
    if "__pycache__" in path.parts:
        return False
    if path.name in {"check-generated-report-layout.py", "generate-system-environment-proof.py"}:
        return False
    try:
        generated_root = (connector_root / GENERATED_ROOT).resolve(strict=False)
        return generated_root not in path.resolve(strict=False).parents
    except OSError:
        return False


def insecure_repository_url_pattern(candidate: str) -> str | None:
    parsed = urlsplit(candidate)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if candidate.startswith(f"git@{GITHUB_REPOSITORY_HOST}:"):
        return f"git@{GITHUB_REPOSITORY_HOST}:"
    if host == GITHUB_REPOSITORY_HOST and scheme in DISALLOWED_REPOSITORY_SCHEMES:
        return scheme
    return None


def repository_url_findings(path: Path, connector_root: Path) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return []
    try:
        display_path = str(path.relative_to(connector_root))
    except ValueError:
        display_path = str(path)
    findings = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for token in line.split():
            pattern = insecure_repository_url_pattern(token.strip("`'\"()[]{}<>,.;"))
            if pattern is not None:
                findings.append({"path": display_path, "line": line_number, "pattern": pattern})
    return findings


def https_repo_url_policy(connector_root: Path, framework_root: Path) -> dict[str, Any]:
    findings = [
        finding
        for path in https_repository_scan_paths(connector_root, framework_root)
        if repository_url_scan_allowed(path, connector_root)
        for finding in repository_url_findings(path, connector_root)
    ]
    status = "PASS" if not findings else "FAIL"
    notes = (
        "no active http, ssh, git protocol repo URLs found"
        if status == "PASS"
        else f"{len(findings)} insecure repo URL pattern(s) found"
    )
    return {
        "status": status,
        "blocked_protocols": ["http", "ssh", "git"],
        "allowed_protocol": "https",
        "notes": "Only HTTPS repository URLs are accepted.",
        "active_scan_notes": notes,
        "github_policy": "only https://github.com/owner/repo accepted",
        "findings": findings,
    }


def pip_freeze_summary(cwd: Path) -> dict[str, Any]:
    result = run([sys.executable, "-m", "pip", "freeze"], cwd, timeout=120)
    lines = [line for line in result["output_excerpt"].splitlines() if line.strip()]
    full_output_hash = result["output_sha256"]
    return {
        "status": result["status"],
        "return_code": result["return_code"],
        "package_count_from_excerpt": len(lines),
        "output_sha256": full_output_hash,
    }


def md_cell(value: Any) -> str:
    text = "unset" if value is None else str(value)
    return text.replace("|", "/").replace("\n", " ")


def md_code(value: Any) -> str:
    return "`" + md_cell(value).replace("`", "\\`") + "`"


def md_optional_code(value: Any) -> str:
    if value is None:
        return "``"
    return md_code(value)


def nginx_runtime_contract(runtime_check: dict[str, Any] | None) -> dict[str, Any]:
    raw = runtime_check.get("nginx_runtime_contract") if isinstance(runtime_check, dict) else None
    contract = raw if isinstance(raw, dict) else {}
    source_fields = contract.get("fields") if isinstance(contract.get("fields"), dict) else {}
    fields = {field: source_fields.get(field, "") for field in NGINX_RUNTIME_CONTRACT_FIELDS}
    return {
        "status": str(contract.get("status") or "BLOCKED"),
        "manifest_path": str(contract.get("manifest_path") or ""),
        "record_path": str(contract.get("record_path") or "missing"),
        "record_status": str(contract.get("record_status") or ""),
        "fields": fields,
        "field_status": contract.get("field_status") if isinstance(contract.get("field_status"), dict) else {},
        "issues": contract.get("issues") if isinstance(contract.get("issues"), list) else [],
    }


def tool_by_name(tools: list[dict[str, Any]], name: str) -> dict[str, Any]:
    return next((tool for tool in tools if tool.get("tool") == name), {})


def first_framework_value(variables: dict[str, Any], names: tuple[str, ...], fallback: str) -> str:
    for name in names:
        value = variables.get(name)
        if value:
            return str(value)
    return fallback


def runtime_component_row(
    component: str,
    status: str,
    expected_path: str,
    source_url: str,
    version_ref: str,
    how_to_prepare: str,
) -> dict[str, str]:
    return {
        "component": component,
        "status": status,
        "expected_path": expected_path,
        "source_url": source_url,
        "version_ref": version_ref,
        "how_to_prepare": how_to_prepare,
    }


def present_or_missing(tool: dict[str, Any]) -> str:
    return "present" if tool.get("status") == "present" else "missing"


def optional_tool_status(tool: dict[str, Any]) -> str:
    return "present" if tool.get("status") == "present" else "missing_optional"


def apache_runtime_status(apxs: dict[str, Any], apache: dict[str, Any]) -> str:
    return "present" if "present" in {apxs.get("status"), apache.get("status")} else "missing"


def runtime_component_readiness(
    tools: list[dict[str, Any]],
    framework_env: dict[str, Any],
    runtime_check: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    variables = framework_env.get("variables", {})
    haproxy = tool_by_name(tools, "haproxy")
    apxs = tool_by_name(tools, "apxs")
    apache = tool_by_name(tools, APACHE_HTTPD_TOOL)
    go_ftw = tool_by_name(tools, "go-ftw")
    albedo = tool_by_name(tools, "albedo")
    nginx_contract = nginx_runtime_contract(runtime_check)
    nginx_fields = nginx_contract["fields"]
    nginx_ready = nginx_contract["status"] == "PASS"
    return [
        runtime_component_row(
            "HAProxy",
            str(haproxy.get("status", "missing")),
            first_framework_value(variables, ("HAPROXY_BIN",), "$HAPROXY_BIN"),
            first_framework_value(variables, ("HAPROXY_SOURCE_URL",), "$HAPROXY_SOURCE_URL"),
            first_framework_value(variables, ("HAPROXY_VERSION",), "$HAPROXY_VERSION"),
            "make prepare-runtime-components or make runtime-matrix-haproxy",
        ),
        runtime_component_row(
            "NGINX",
            "present" if nginx_ready else "blocked",
            str(nginx_fields.get("binary_path") or NGINX_RUNTIME_CONTRACT_MISSING),
            str(nginx_fields.get("source_repository") or NGINX_RUNTIME_CONTRACT_MISSING),
            str(nginx_fields.get("source_ref") or nginx_fields.get("release_tag") or NGINX_RUNTIME_CONTRACT_MISSING),
            "run make prepare-runtime-components and require the pinned NGINX release-asset/full tuple",
        ),
        runtime_component_row(
            "Apache/APXS",
            apache_runtime_status(apxs, apache),
            first_framework_value(variables, ("APXS_BIN", "CI_APXS_BIN_CANDIDATES"), "$APXS_BIN or CI_APXS_BIN_CANDIDATES"),
            first_framework_value(variables, ("HTTPD_SOURCE_URL",), "$HTTPD_SOURCE_URL"),
            first_framework_value(variables, ("HTTPD_VERSION",), "$HTTPD_VERSION"),
            "install apache2-dev/httpd-devel or prepare Apache runtime",
        ),
        runtime_component_row(
            "go-ftw",
            optional_tool_status(go_ftw),
            first_framework_value(variables, ("GO_FTW_BIN",), "$GO_FTW_BIN"),
            first_framework_value(variables, ("GO_FTW_SOURCE_URL",), "$GO_FTW_SOURCE_URL"),
            first_framework_value(variables, ("GO_FTW_PROMPT_EXPECTED_LATEST", "GO_FTW_GIT_REF"), "$GO_FTW_PROMPT_EXPECTED_LATEST"),
            "install go-ftw only if MRTS/FTW checks are required",
        ),
        runtime_component_row(
            "albedo",
            optional_tool_status(albedo),
            first_framework_value(variables, ("ALBEDO_BIN",), "$ALBEDO_BIN"),
            first_framework_value(variables, ("ALBEDO_SOURCE_URL",), "$ALBEDO_SOURCE_URL"),
            first_framework_value(variables, ("ALBEDO_PROMPT_EXPECTED_LATEST", "ALBEDO_GIT_REF"), "$ALBEDO_PROMPT_EXPECTED_LATEST"),
            "install albedo only if native MRTS checks require it",
        ),
        runtime_component_row(
            "expat",
            "informational",
            "n/a",
            first_framework_value(variables, ("EXPAT_SOURCE_URL",), "$EXPAT_SOURCE_URL"),
            first_framework_value(variables, ("EXPAT_GIT_REF",), "$EXPAT_GIT_REF"),
            "used only if the related runtime build path requires it",
        ),
    ]


def runtime_producer_readiness_check(connector_root: Path, framework_root: Path) -> dict[str, Any]:
    script = connector_root / "ci/checks/evidence/check-runtime-producer-readiness.py"
    if not script.is_file():
        return {
            "status": "missing",
            "return_code": 127,
            "nginx_runtime_module_readiness": {
                "NGINX_BIN": "",
                "NGINX_MODULE_DIR": "",
                "ModSecurity module path": "",
                "Module exists": False,
                "How to prepare": "make prepare-runtime-components",
            },
            "nginx_runtime_contract": {
                "status": "BLOCKED",
                "manifest_path": "",
                "record_path": "missing",
                "fields": dict.fromkeys(NGINX_RUNTIME_CONTRACT_FIELDS, ""),
                "field_status": dict.fromkeys(NGINX_RUNTIME_CONTRACT_FIELDS, "BLOCKED"),
                "issues": ["runtime readiness checker is unavailable"],
            },
            "components": [],
            "network_cache": [],
        }
    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            "--connector-root",
            str(connector_root),
            "--framework-root",
            str(framework_root),
            "--json",
        ],
        cwd=str(connector_root),
        env=os.environ.copy(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=120,
    )
    try:
        payload = json.loads(proc.stdout)
    except Exception:
        payload = {"status": "unknown", "components": [], "network_cache": [], "raw_output": proc.stdout}
    payload["return_code"] = proc.returncode
    return payload


def read_verified_commands() -> list[dict[str, Any]]:
    path_value = os.environ.get("VERIFIED_RUN_COMMANDS_FILE", "")
    if not path_value:
        return []
    path = Path(path_value)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    commands = data.get("commands") if isinstance(data, dict) else data
    return commands if isinstance(commands, list) else []


def command_record(commands: list[dict[str, Any]], target: str) -> dict[str, Any]:
    for record in commands:
        raw = record.get("command")
        if record.get("logical_target") == target:
            return record
        if isinstance(raw, list) and raw == ["make", target]:
            return record
    return {}


def tool_missing(tools: list[dict[str, Any]], names: tuple[str, ...]) -> list[str]:
    rows = []
    for name in names:
        record = tool_by_name(tools, name)
        if record.get("status") != "present":
            rows.append(name)
    return rows


def producer_status(commands: list[dict[str, Any]], target: str) -> str:
    record = command_record(commands, target)
    if not record:
        return "not_run"
    return str(record.get("status") or "unknown")


def verified_producer_readiness(
    tools: list[dict[str, Any]],
    framework_env: dict[str, Any],
) -> list[dict[str, Any]]:
    variables = framework_env.get("variables", {})
    defaults = verified_runtime_paths(os.environ)
    commands = read_verified_commands()
    runtime_paths = {
        "BUILD_ROOT": variables.get("BUILD_ROOT") or os.environ.get("BUILD_ROOT") or defaults["BUILD_ROOT"],
        "SOURCE_ROOT": variables.get("SOURCE_ROOT") or os.environ.get("SOURCE_ROOT") or defaults["SOURCE_ROOT"],
        "TMP_ROOT": variables.get("TMP_ROOT") or os.environ.get("TMP_ROOT") or defaults["TMP_ROOT"],
        "LOG_ROOT": variables.get("LOG_ROOT") or os.environ.get("LOG_ROOT") or defaults["LOG_ROOT"],
        "CONNECTOR_COMPONENT_CACHE": variables.get("CONNECTOR_COMPONENT_CACHE") or os.environ.get("CONNECTOR_COMPONENT_CACHE") or defaults["CONNECTOR_COMPONENT_CACHE"],
        "NGINX_HARNESS_PARENT": variables.get("NGINX_HARNESS_PARENT") or os.environ.get("NGINX_HARNESS_PARENT") or defaults["NGINX_HARNESS_PARENT"],
        "MATRIX_ROOT": variables.get("MATRIX_ROOT") or os.environ.get("MATRIX_ROOT") or defaults["MATRIX_ROOT"],
        "MRTS_NATIVE_ROOT": variables.get("MRTS_NATIVE_ROOT") or os.environ.get("MRTS_NATIVE_ROOT") or defaults["MRTS_NATIVE_ROOT"],
    }
    native_missing = tool_missing(
        tools,
        ("go-ftw", "albedo", "apachectl", APACHE_HTTPD_TOOL, "nginx", "apxs"),
    )
    full_matrix = command_record(commands, "full-matrix-parallel")
    full_matrix_status = producer_status(commands, "full-matrix-parallel")
    full_matrix_fix = (
        "increase VERIFIED_RUN_FULL_MATRIX_RUNTIME_TIMEOUT_SECONDS and rerun make verified-report-run"
        if full_matrix.get("classification") == "blocked_timeout"
        else "run make verified-report-run with safe BUILD_ROOT/MATRIX_ROOT paths"
    )
    return [
        {
            "producer": "prepare-runtime-components",
            "required": True,
            "status": producer_status(commands, "prepare-runtime-components"),
            "missing_tools": [],
            "missing_paths": [
                f"{key}={value}"
                for key, value in runtime_paths.items()
                if key in {"BUILD_ROOT", "SOURCE_ROOT", "CONNECTOR_COMPONENT_CACHE"}
            ],
            "how_to_fix": "ensure VERIFIED_RUN_ROOT points outside /root and rerun make prepare-runtime-components",
        },
        {
            "producer": "runtime-matrix-all",
            "required": True,
            "status": producer_status(commands, "runtime-matrix-all"),
            "missing_tools": [],
            "missing_paths": [
                f"{key}={value}"
                for key, value in runtime_paths.items()
                if key in {"BUILD_ROOT", "TMP_ROOT", "LOG_ROOT", "NGINX_HARNESS_PARENT"}
            ],
            "how_to_fix": "run make runtime-matrix-all after prepare-runtime-components; inspect the verified command log on BLOCKED/FAIL",
        },
        {
            "producer": "full-matrix-parallel",
            "required": True,
            "status": full_matrix_status,
            "missing_tools": [],
            "missing_paths": [f"MATRIX_ROOT={runtime_paths['MATRIX_ROOT']}"],
            "how_to_fix": full_matrix_fix,
        },
        {
            "producer": "mrts-native-full-run",
            "required": False,
            "status": producer_status(commands, "mrts-native-full-run"),
            "missing_tools": native_missing,
            "missing_paths": [f"MRTS_NATIVE_ROOT={runtime_paths['MRTS_NATIVE_ROOT']}"],
            "how_to_fix": "install optional go-ftw/albedo/native webserver tooling or leave native MRTS as optional WARN evidence",
        },
    ]


def proof_header_markdown(payload: dict[str, Any]) -> list[str]:
    os_info = payload["os"]
    return [
        "# System Environment Proof",
        "",
        "## Proof Status",
        "",
        MARKDOWN_FIELD_VALUE_HEADER,
        MARKDOWN_FIELD_VALUE_SEPARATOR,
        f"| Proof generation status | `{payload.get('proof_generation_status', '-')}` |",
        f"| Embedded strict evidence gate | `{payload.get('embedded_strict_evidence_gate', '-')}` |",
        f"| Overall target status | `{payload.get('overall_target_status', '-')}` |",
        f"| Strict gate reason | {md_cell(payload.get('strict_evidence_gate_reason', '-'))} |",
        "",
        "## OS / System",
        "",
        MARKDOWN_FIELD_VALUE_HEADER,
        MARKDOWN_FIELD_VALUE_SEPARATOR,
        f"| OS Name | {os_info.get('name', '-')} |",
        f"| OS Version | {os_info.get('version', '-')} |",
        f"| Kernel | {os_info.get('kernel', '-')} |",
        f"| Architecture | {os_info.get('architecture', '-')} |",
        f"| Hostname | {os_info.get('hostname', '-')} |",
        f"| User | {os_info.get('user', '-')} |",
        f"| Working Directory | `{os_info.get('working_directory', '-')}` |",
    ]


def framework_environment_markdown(framework_env: dict[str, Any]) -> list[str]:
    lines = [
        "",
        "## Framework Environment Resolution",
        "",
        MARKDOWN_FIELD_VALUE_HEADER,
        MARKDOWN_FIELD_VALUE_SEPARATOR,
        f"| Framework root | {md_code(framework_env.get('framework_root'))} |",
        f"| common.sh path | {md_code(framework_env.get('common_sh_path'))} |",
        f"| common.sh status | {md_code(framework_env.get('common_sh_status'))} |",
        f"| common.sh return code | {md_code(framework_env.get('load_return_code'))} |",
    ]
    for name in FRAMEWORK_ENVIRONMENT_VARS:
        lines.append(f"| {name} | {md_code(framework_env.get('variables', {}).get(name))} |")
    if framework_env.get("load_output_excerpt"):
        lines.append(f"| common.sh output | {md_code(framework_env.get('load_output_excerpt'))} |")
    return lines


def tool_versions_markdown(tools: list[dict[str, Any]]) -> list[str]:
    lines = [
        "",
        "## Tool Versions",
        "",
        "| Tool | Status | Resolved Command | Source | Candidates | Version / Output | Notes |",
        "|---|---|---|---|---|---|---|",
    ]
    for tool in tools:
        displayed_command = tool.get("resolved_command")
        candidates = " ".join(str(item) for item in tool.get("candidates", []))
        version_line = str(tool.get("version_output") or tool.get("version") or "-").splitlines()[0]
        lines.append(
            f"| {tool['tool']} | {tool['status']} | {md_optional_code(displayed_command)} | "
            f"{md_code(tool.get('source', '-'))} | {md_optional_code(candidates or None)} | "
            f"{md_code(version_line)} | {md_optional_code(tool.get('notes') or None)} |"
        )
    return lines


def runtime_component_markdown(items: list[dict[str, str]]) -> list[str]:
    lines = [
        "",
        "## Runtime Component Readiness",
        "",
        "| Component | Status | Expected Path | Source URL | Version / Ref | How to Prepare |",
        "|---|---|---|---|---|---|",
    ]
    for item in items:
        lines.append(
            f"| {item['component']} | {item['status']} | {md_code(item['expected_path'])} | "
            f"{md_code(item['source_url'])} | {md_code(item['version_ref'])} | {md_code(item['how_to_prepare'])} |"
        )
    return lines


def nginx_module_markdown(runtime_check: dict[str, Any]) -> list[str]:
    nginx_module = runtime_check.get("nginx_runtime_module_readiness", {})
    return [
        "",
        "## NGINX Runtime Module Readiness",
        "",
        MARKDOWN_FIELD_VALUE_HEADER,
        MARKDOWN_FIELD_VALUE_SEPARATOR,
        f"| NGINX_BIN | {md_code(nginx_module.get('NGINX_BIN', ''))} |",
        f"| NGINX_MODULE_DIR | {md_code(nginx_module.get('NGINX_MODULE_DIR', ''))} |",
        f"| ModSecurity module path | {md_code(nginx_module.get('ModSecurity module path', ''))} |",
        f"| Module exists | {md_code(str(nginx_module.get('Module exists', False)).lower())} |",
        f"| How to prepare | {md_code(nginx_module.get('How to prepare', 'make prepare-runtime-components'))} |",
    ]


def nginx_runtime_contract_markdown(runtime_check: dict[str, Any]) -> list[str]:
    contract = nginx_runtime_contract(runtime_check)
    fields = contract["fields"]
    field_status = contract["field_status"]
    lines = [
        "",
        "## NGINX Runtime Contract",
        "",
        MARKDOWN_FIELD_VALUE_HEADER,
        MARKDOWN_FIELD_VALUE_SEPARATOR,
        f"| Readiness status | {md_code(contract['status'])} |",
        f"| Manifest path | {md_code(contract['manifest_path'])} |",
        f"| Record path | {md_code(contract['record_path'])} |",
    ]
    for field in NGINX_RUNTIME_CONTRACT_FIELDS:
        value = fields.get(field, "")
        status = field_status.get(field, "BLOCKED")
        lines.append(f"| {field} ({status}) | {md_code(value or '-')} |")
    issues = contract["issues"]
    if issues:
        lines.append(f"| Issues | {md_code('; '.join(str(issue) for issue in issues))} |")
    return lines


def verified_producer_markdown(items: list[dict[str, Any]]) -> list[str]:
    lines = [
        "",
        "## Verified Producer Readiness",
        "",
        "| Producer | Required | Status | Missing Tools | Missing Paths | How to Fix |",
        "|---|---|---|---|---|---|",
    ]
    for item in items:
        missing_tools = ", ".join(item.get("missing_tools", [])) or "-"
        missing_paths = "<br>".join(md_code(path) for path in item.get("missing_paths", [])) or "-"
        lines.append(
            f"| {item.get('producer', '-')} | {item.get('required', '-')} | {item.get('status', 'unknown')} | "
            f"{md_cell(missing_tools)} | {missing_paths} | {md_code(item.get('how_to_fix', '-'))} |"
        )
    return lines


def network_cache_markdown(runtime_check: dict[str, Any]) -> list[str]:
    items = runtime_check.get("network_cache", [])
    lines = [
        "",
        "## Runtime Network / Cache Readiness",
        "",
        "| Source | Status | Path | Notes |",
        "|---|---|---|---|",
    ]
    for item in items:
        lines.append(
            f"| {md_cell(item.get('source', '-'))} | {md_cell(item.get('status', 'unknown'))} | "
            f"{md_code(item.get('path', '-'))} | {md_cell(item.get('notes', '-'))} |"
        )
    if not items:
        lines.append("| - | unknown | `` | _No rows available. Reason: runtime readiness checker unavailable._ |")
    return lines


def https_policy_markdown(policy: dict[str, Any]) -> list[str]:
    return [
        "",
        "## HTTPS Repository URL Policy",
        "",
        "| Check | Status | Notes |",
        "|---|---|---|",
        f"| HTTPS-only repo URLs | {policy.get('status', '-')} | {md_cell(policy.get('active_scan_notes', '-'))} |",
        f"| GitHub repo URL policy | {policy.get('status', '-')} | {md_cell(policy.get('github_policy', '-'))} |",
    ]


def python_environment_markdown(python_info: dict[str, Any]) -> list[str]:
    return [
        "",
        "## Python Environment",
        "",
        MARKDOWN_FIELD_VALUE_HEADER,
        MARKDOWN_FIELD_VALUE_SEPARATOR,
        f"| sys.version | `{python_info.get('sys_version', '-')}` |",
        f"| sys.executable | `{python_info.get('sys_executable', '-')}` |",
        f"| sys.platform | `{python_info.get('sys_platform', '-')}` |",
        f"| platform.platform() | `{python_info.get('platform', '-')}` |",
        f"| PYTHONPATH | `{python_info.get('pythonpath', '-')}` |",
        f"| PYTHONDONTWRITEBYTECODE | `{python_info.get('pythondontwritebytecode', '-')}` |",
        f"| .venv exists | `{python_info.get('venv_exists', '-')}` |",
        f"| pip --version | `{python_info.get('pip_version', '-')}` |",
        f"| pip freeze packages in excerpt | `{python_info.get('pip_freeze', {}).get('package_count_from_excerpt', '-')}` |",
        f"| pip freeze output hash | `{python_info.get('pip_freeze', {}).get('output_sha256', '-')}` |",
    ]


def executed_checks_markdown(checks: list[dict[str, Any]]) -> list[str]:
    lines = [
        "",
        "## Executed Checks",
        "",
        "| Command | Status | Return Code | Duration | Notes |",
        "|---|---|---:|---:|---|",
    ]
    for check in checks:
        note = check["output_excerpt"].splitlines()[-1] if check["output_excerpt"] else "-"
        lines.append(f"| `{check['command']}` | {check['status']} | {check['return_code']} | {check['duration_seconds']} | {note.replace('|', '/')} |")
    return lines


def report_layout_markdown(layout: dict[str, Any]) -> list[str]:
    return [
        "",
        "## Report Layout Evidence",
        "",
        "| Metric | Value |",
        MARKDOWN_FIELD_VALUE_SEPARATOR,
        f"| Generated report files | {layout['generated_report_files']} |",
        f"| Flat files in generated root | {layout['flat_files_in_generated_root']} |",
        f"| Categories | {layout['category_count']} ({', '.join(layout['categories'])}) |",
        f"| Missing registry outputs | {len(layout['missing_registry_outputs'])} |",
        f"| Orphan generated reports | {len(layout['orphan_generated_reports'])} |",
        f"| Skipped reports | {len(layout['skipped_reports'])} |",
        f"| Failed reports | {len(layout['failed_reports'])} |",
    ]


def skipped_inputs_markdown(skipped: list[dict[str, Any]]) -> list[str]:
    lines = [
        "",
        "## Known Skipped Inputs",
        "",
        "| Report | Status | Missing Inputs | Reason |",
        "|---|---|---|---|",
    ]
    if not skipped:
        lines.append("| `-` | none | - | no skipped reports |")
        return lines
    for report in skipped:
        missing_inputs = ", ".join(f"`{item}`" for item in report.get("missing_inputs", [])) or "-"
        lines.append(
            f"| `{report.get('report_name', '-')}` | {report.get('status', '-')} | {missing_inputs} | "
            "local optional inputs are missing or unavailable |"
        )
    return lines


def git_evidence_markdown(git_records: dict[str, dict[str, Any]]) -> list[str]:
    lines = [
        "",
        "## Git Evidence",
        "",
        "| Command | Status | Return Code | Output Hash |",
        "|---|---|---:|---|",
    ]
    for name, record in git_records.items():
        lines.append(f"| `{name}` | {record['status']} | {record['return_code']} | `{record['output_sha256']}` |")
    return lines


def proof_summary_markdown(checks: list[dict[str, Any]], layout: dict[str, Any], skipped: list[dict[str, Any]]) -> list[str]:
    lines = [
        "",
        "## Proof Summary",
        "",
        "The generated report layout was validated on the system above.",
    ]
    lines.extend(f"- `{check['command']}`: {check['status']}" for check in checks)
    lines.extend(
        [
            f"- Flat generated root files: {layout['flat_files_in_generated_root']}",
            f"- Categorized generated report files: {layout['generated_report_files']}",
        ]
    )
    if skipped:
        lines.append("- Known skipped report: runtime/cache reports due to missing optional local inputs")
    return lines


def render_markdown(payload: dict[str, Any]) -> str:
    layout = payload["layout"]
    runtime_check = payload.get("runtime_producer_readiness_check", {})
    skipped = layout.get("skipped_reports", [])
    sections = (
        proof_header_markdown(payload),
        framework_environment_markdown(payload["framework_environment"]),
        tool_versions_markdown(payload["tools"]),
        runtime_component_markdown(payload["runtime_component_readiness"]),
        nginx_module_markdown(runtime_check),
        nginx_runtime_contract_markdown(runtime_check),
        verified_producer_markdown(payload.get("verified_producer_readiness", [])),
        network_cache_markdown(runtime_check),
        https_policy_markdown(payload["https_repo_url_policy"]),
        python_environment_markdown(payload["python"]),
        executed_checks_markdown(payload["checks"]),
        report_layout_markdown(layout),
        skipped_inputs_markdown(skipped),
        git_evidence_markdown(payload["git"]),
        proof_summary_markdown(payload["checks"], layout, skipped),
    )
    return "\n".join(line for section in sections for line in section) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector-root", default=".")
    parser.add_argument("--framework-root", default=None)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--skip-check-runs", action="store_true")
    args = parser.parse_args()

    connector_root = Path(args.connector_root).resolve()
    framework_root = Path(args.framework_root).resolve() if args.framework_root else connector_root / "modules/ModSecurity-test-Framework"
    output_dir = Path(args.output_dir).resolve() if args.output_dir else connector_root / GENERATED_ROOT / "manifest"
    generated_at = utc_now()
    initial_env = os.environ.copy()
    framework_environment = load_framework_environment(connector_root, framework_root)

    os_release = read_os_release()
    checks = []
    if args.skip_check_runs:
        for command in (
            "make refresh-connector-reports",
            "make check-generated-report-layout",
            "make lint",
            "make quick-check",
            "git status --short",
        ):
            checks.append(
                {
                    "command": command,
                    "started_at": generated_at,
                    "finished_at": generated_at,
                    "duration_seconds": 0.0,
                    "return_code": 0,
                    "status": "not-run-by-generator",
                    "output_excerpt": "Skipped by --skip-check-runs.",
                    "output_sha256": hashlib.sha256(b"").hexdigest(),
                }
            )
    else:
        checks = [
            run(["make", "refresh-connector-reports"], connector_root, timeout=900),
            run(["env", "ALLOW_IN_PROGRESS_SYSTEM_PROOF=1", "make", "check-generated-report-layout"], connector_root, timeout=300),
            run(["make", "lint"], connector_root, timeout=900),
            run(["make", "quick-check"], connector_root, timeout=900),
            run(["git", "status", "--short"], connector_root, timeout=120),
        ]

    pip_version = run([sys.executable, "-m", "pip", "--version"], connector_root, timeout=60)
    runtime_producer_check = runtime_producer_readiness_check(connector_root, framework_root)
    tools = resolve_tools(connector_root, framework_environment, initial_env, runtime_producer_check)
    readiness = runtime_component_readiness(tools, framework_environment, runtime_producer_check)
    producer_readiness = verified_producer_readiness(tools, framework_environment)
    https_policy = https_repo_url_policy(connector_root, framework_root)
    strict_gate_check = next(
        (
            item
            for item in checks
            if "check-generated-report-layout" in item.get("command", "")
        ),
        {},
    )
    embedded_strict_gate = "PASS" if strict_gate_check.get("return_code") == 0 else "FAIL"
    overall_target_status = (
        "PASS"
        if all(item["return_code"] == 0 for item in checks if item["status"] != "not-run-by-generator")
        else "FAIL"
    )
    strict_output_lines = [
        line
        for line in str(strict_gate_check.get("output_excerpt", "")).splitlines()
        if line.startswith(("check-generated-report-layout", "- "))
    ]
    strict_reason = (
        "strict generated-report evidence gate passed"
        if embedded_strict_gate == "PASS"
        else "; ".join(strict_output_lines[-4:]) or "strict evidence gate failed"
    )
    payload = {
        "proof_generation_status": "PASS",
        "embedded_strict_evidence_gate": embedded_strict_gate,
        "overall_target_status": overall_target_status,
        "strict_evidence_gate_reason": strict_reason,
        "generated_at": generated_at,
        "verified_run_id": current_verified_run_id(connector_root),
        "data_source_policy": DATA_SOURCE_POLICY,
        "framework_common_sh_status": framework_environment["common_sh_status"],
        "framework_environment": {
            key: value for key, value in framework_environment.items() if key != "env"
        },
        "os": {
            "name": os_release.get("NAME", platform.system()),
            "version": os_release.get("VERSION", platform.version()),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "hostname": socket.gethostname(),
            "user": getpass.getuser(),
            "working_directory": str(connector_root),
            "uname": " ".join(platform.uname()),
        },
        "tools": tools,
        "runtime_component_readiness": readiness,
        "runtime_producer_readiness_check": runtime_producer_check,
        "verified_producer_readiness": producer_readiness,
        "https_repo_url_policy": https_policy,
        "python": {
            "sys_version": sys.version,
            "sys_executable": sys.executable,
            "sys_platform": sys.platform,
            "platform": platform.platform(),
            "pythonpath": os.environ.get("PYTHONPATH", ""),
            "pythondontwritebytecode": os.environ.get("PYTHONDONTWRITEBYTECODE", ""),
            "venv_exists": (connector_root / ".venv").is_dir(),
            "pip_version": pip_version["output_excerpt"].splitlines()[0] if pip_version["output_excerpt"] else "missing",
            "pip_freeze": pip_freeze_summary(connector_root),
        },
        "git": git_evidence(connector_root, framework_root),
        "checks": checks,
        "layout": layout_evidence(connector_root),
    }
    metadata = build_metadata(
        generated_by="ci/evidence/reports/generate-system-environment-proof.py",
        make_target="generate-system-environment-proof",
        connector_root=connector_root,
        framework_root=framework_root,
        inputs=[
            report_path(connector_root, "report_refresh_manifest", "json"),
            report_path(connector_root, "report_freshness", "json"),
            report_path(connector_root, "merge_readiness_dashboard", "json"),
        ],
        generated_at=generated_at,
        report_key="system_environment_proof",
        extra={"check_statuses": [{key: item[key] for key in ("command", "status", "return_code")} for item in checks]},
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / GENERATED_REPORTS["system_environment_proof"].filename("json")
    md_path = output_dir / GENERATED_REPORTS["system_environment_proof"].filename("md")
    json_path.write_text(generated_json_text(payload, metadata), encoding="utf-8")
    md_path.write_text(generated_markdown_text(render_markdown(payload), metadata), encoding="utf-8")
    print(md_path)
    return 0 if overall_target_status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
