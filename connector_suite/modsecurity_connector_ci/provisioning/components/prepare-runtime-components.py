#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections.abc import Callable, Iterator
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

from modsecurity_test_framework.connector_context import connector_root as selected_connector_root, test_root, source_path as framework_source_path, validate_checkout

from typing import Any, NamedTuple
from urllib.parse import urlsplit

from modsecurity_connector_ci.lib.generated_report_utils import GENERATED_ROOT, build_metadata, generated_json_text, generated_markdown_text, report_path_from_root
from modsecurity_connector_ci.provisioning.components.nginx_exact_head_diagnostics import DiagnosticInputError, bounded_fixed_log_tail
from modsecurity_connector_ci.lib.runtime_path_utils import is_system_write_path


COMMON_SH_CONFIG_VARS = (
    "GO_FTW_SOURCE_URL",
    "GO_FTW_PROMPT_EXPECTED_LATEST",
    "GO_FTW_GIT_REF",
    "GO_FTW_BIN",
    "ALBEDO_SOURCE_URL",
    "ALBEDO_PROMPT_EXPECTED_LATEST",
    "ALBEDO_GIT_REF",
    "ALBEDO_BIN",
    "EXPAT_SOURCE_URL",
    "EXPAT_GIT_REF",
    "EXPAT_GIT_URL",
    "EXPAT_PROMPT_EXPECTED_LATEST",
    "NGINX_PROTOCOL_PROFILE",
    "NGINX_QUIC_TLS_LIBRARY",
    "NGINX_QUIC_TLS_VERSION",
    "NGINX_QUIC_TLS_SOURCE_URL",
    "NGINX_QUIC_TLS_SOURCE_SHA256",
)

GITHUB_REPO_URL_KEYS = (
    "CRS_REPO_URL",
    "MODSECURITY_REPO_URL",
    "MODSECURITY_V3_GIT_URL",
    "MODSECURITY_APACHE_REPO_URL",
    "MODSECURITY_APACHE_GIT_URL",
    "MODSECURITY_NGINX_REPO_URL",
    "MODSECURITY_NGINX_GIT_URL",
    "NGINX_SOURCE_REPO_URL",
    "NGINX_GITHUB_REPO",
    "GO_FTW_SOURCE_URL",
    "ALBEDO_SOURCE_URL",
    "EXPAT_SOURCE_URL",
    "EXPAT_GIT_URL",
)

NGINX_GITHUB_REPO_URL_KEYS = frozenset(
    {
        "MODSECURITY_NGINX_REPO_URL",
        "MODSECURITY_NGINX_GIT_URL",
        "NGINX_SOURCE_REPO_URL",
        "NGINX_GITHUB_REPO",
    }
)

HTTPS_URL_KEYS = (
    "HAPROXY_SOURCE_URL",
    "HAPROXY_SHA256_URL",
    "HTTPD_SOURCE_URL",
    "HTTPD_SHA256_URL",
    "APR_SOURCE_URL",
    "APR_SHA256_URL",
    "APR_UTIL_SOURCE_URL",
    "APR_UTIL_SHA256_URL",
    "PCRE2_SOURCE_URL",
    "PCRE2_SHA256_URL",
    "NGINX_QUIC_TLS_SOURCE_URL",
)

NGINX_HTTPS_URL_KEYS = frozenset({"NGINX_QUIC_TLS_SOURCE_URL"})
RUNTIME_COMPONENT_TARGETS = ("all", "shared", "apache", "nginx", "haproxy")
NGINX_RUNTIME_COMPONENT_TARGETS = frozenset({"all", "nginx"})


NGINX_PROTOCOL_PROFILES = ("h1", "h1-h2", "h1-h2-h3-quic")
NGINX_STAGED_MAKE_LOG_RELATIVE_PATH = Path("build/logs/nginx/nginx-make.log")
NGINX_STAGED_MAKE_LOG_PREFIX = "nginx staged make diagnostics:"
NGINX_STAGED_MAKE_LOG_LINE_PREFIX = f"{NGINX_STAGED_MAKE_LOG_PREFIX} log: "
DEFAULT_NGINX_QUIC_TLS_LIBRARY = "openssl"
DEFAULT_NGINX_QUIC_TLS_VERSION = "4.0.1"
DEFAULT_NGINX_QUIC_TLS_SOURCE_URL = "https://github.com/openssl/openssl/releases/download/openssl-4.0.1/openssl-4.0.1.tar.gz"
DEFAULT_NGINX_QUIC_TLS_SOURCE_SHA256 = "2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09"
PATH_POLICY_ENV = dict(os.environ)
FULL_GIT_COMMIT_ID = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")
SAFE_RUNTIME_BUILD_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
HAPROXY_BINDING_BUILD_TARGETS = ("build-modsecurity-binding", "build-spoa-runtime")
HAPROXY_BINDING_FAILURE_OUTPUT_NAMES = {
    "build-modsecurity-binding": "haproxy-modsecurity-binding-self-test",
    "build-spoa-runtime": "haproxy-modsecurity-spoa",
}
HAPROXY_FAILURE_DIAGNOSTIC_MAX_LINES = 8
HAPROXY_FAILURE_DIAGNOSTIC_SCAN_MAX_LINES = 512
HAPROXY_FAILURE_DIAGNOSTIC_MAX_LINE_CHARS = 4096
HAPROXY_FAILURE_FOOTER_MARKER = ": *** ["
HAPROXY_FAILURE_FOOTER_SUFFIX = "] Error "
HAPROXY_FAILURE_FOOTER_WHITESPACE = " \t\f\v"
HAPROXY_DIAGNOSTIC_RESOLVER_ERROR = "classification=resolver_error"
HAPROXY_DIAGNOSTIC_COMPILER_FATAL_ERROR = "classification=compiler_fatal_error"
HAPROXY_DIAGNOSTIC_COMPILER_ERROR = "classification=compiler_error"
HAPROXY_DIAGNOSTIC_LINKER_ERROR = "classification=linker_error"
HAPROXY_RESOLVER_SENTINEL_PREFIX = "BLOCKED: HAProxy libModSecurity resolver: sentinel="
HAPROXY_RESOLVER_SENTINEL_CAUSES = (
    "invalid_path_syntax",
    "output_path_not_absolute",
    "output_path_symlink",
    "path_contains_whitespace",
    "headers_not_found",
    "library_not_found",
    "headers_missing",
    "headers_modsecurity_h_and_rules_set_h_missing",
    "headers_modsecurity_h_and_transaction_h_missing",
    "headers_rules_set_h_and_transaction_h_missing",
    "headers_modsecurity_h_and_rules_set_h_and_transaction_h_missing",
    "header_modsecurity_h_missing",
    "header_rules_set_h_missing",
    "header_transaction_h_missing",
    "library_missing",
    "readlink_missing",
    "library_target_unresolved",
    "library_target_not_regular",
    "file_missing",
    "architecture_mismatch",
    "ldd_missing",
    "unresolved_runtime_dependencies",
)


def haproxy_resolver_cause_diagnostics(cause: str) -> tuple[str, ...]:
    """Return the closed, payload-free diagnostics for one resolver cause."""

    if cause not in HAPROXY_RESOLVER_SENTINEL_CAUSES:
        raise ValueError("unknown HAProxy resolver diagnostic cause")
    return (
        HAPROXY_DIAGNOSTIC_RESOLVER_ERROR,
        "build_step=modsecurity_resolver",
        f"resolver_cause={cause}",
    )


HAPROXY_RESOLVER_SENTINEL_DIAGNOSTICS = {
    f"{HAPROXY_RESOLVER_SENTINEL_PREFIX}{cause}": haproxy_resolver_cause_diagnostics(cause)
    for cause in HAPROXY_RESOLVER_SENTINEL_CAUSES
}
HAPROXY_RESOLVER_CAUSE_VALUES = frozenset(
    diagnostics[-1] for diagnostics in HAPROXY_RESOLVER_SENTINEL_DIAGNOSTICS.values()
)
HAPROXY_FAILURE_DIAGNOSTIC_RULES = (
    (
        re.compile(r"^BLOCKED: HAProxy libModSecurity resolver:", re.ASCII),
        (HAPROXY_DIAGNOSTIC_RESOLVER_ERROR, "build_step=modsecurity_resolver"),
    ),
    (
        re.compile(
            r"\bfatal error:\s*modsecurity/modsecurity\.h:\s*No such file or directory\b",
            re.IGNORECASE | re.ASCII,
        ),
        (HAPROXY_DIAGNOSTIC_COMPILER_FATAL_ERROR, "missing_header=modsecurity.h"),
    ),
    (
        re.compile(
            r"\bfatal error:\s*modsecurity/rules_set\.h:\s*No such file or directory\b",
            re.IGNORECASE | re.ASCII,
        ),
        (HAPROXY_DIAGNOSTIC_COMPILER_FATAL_ERROR, "missing_header=rules_set.h"),
    ),
    (
        re.compile(
            r"\bfatal error:\s*modsecurity/transaction\.h:\s*No such file or directory\b",
            re.IGNORECASE | re.ASCII,
        ),
        (HAPROXY_DIAGNOSTIC_COMPILER_FATAL_ERROR, "missing_header=transaction.h"),
    ),
    (
        re.compile(
            r"^FAIL: HAProxy ModSecurity binding source did not compile for diagnostic SPOP runtime$",
            re.ASCII,
        ),
        (HAPROXY_DIAGNOSTIC_COMPILER_ERROR, "build_step=spoa_binding_source_compile"),
    ),
    (
        re.compile(r"^FAIL: HAProxy ModSecurity SPOA runtime source did not compile$", re.ASCII),
        (HAPROXY_DIAGNOSTIC_COMPILER_ERROR, "build_step=spoa_runtime_source_compile"),
    ),
    (
        re.compile(r"^FAIL: HAProxy ModSecurity SPOA runtime did not link with libmodsecurity$", re.ASCII),
        (HAPROXY_DIAGNOSTIC_LINKER_ERROR, "build_step=spoa_runtime_link"),
    ),
    (
        re.compile(r"^FAIL: HAProxy ModSecurity binding source did not compile$", re.ASCII),
        (HAPROXY_DIAGNOSTIC_COMPILER_ERROR, "build_step=modsecurity_binding_source_compile"),
    ),
    (
        re.compile(r"^FAIL: HAProxy Common SDK source did not compile:", re.ASCII),
        (HAPROXY_DIAGNOSTIC_COMPILER_ERROR, "build_step=modsecurity_common_sdk_source_compile"),
    ),
    (
        re.compile(r"^FAIL: HAProxy ModSecurity binding self-test source did not compile$", re.ASCII),
        (HAPROXY_DIAGNOSTIC_COMPILER_ERROR, "build_step=modsecurity_binding_self_test_source_compile"),
    ),
    (
        re.compile(r"^FAIL: HAProxy ModSecurity binding self-test did not link$", re.ASCII),
        (HAPROXY_DIAGNOSTIC_LINKER_ERROR, "build_step=modsecurity_binding_self_test_link"),
    ),
    (
        re.compile(
            r"^FAIL: The HAProxy connector requires the public libModSecurity API available in version "
            r"3\.0\.14 or newer\. The detected headers and library do not provide the required baseline "
            r"API or do not match\.$",
            re.ASCII,
        ),
        ("classification=modsecurity_baseline_api_failure", "build_step=modsecurity_baseline_api_validation"),
    ),
)


# Bump this whenever the on-disk cache contract or the identity inputs change.
# A cache entry is only reusable when its manifest was produced by this schema.
CACHE_SCHEMA_VERSION = 2
CACHE_ROOT_MARKER = ".msconnector-runtime-cache-root.json"
CACHE_ENTRY_MARKER_DIRECTORY = ".msconnector-runtime-cache-entries"
CACHE_MANIFEST_STATUS_COMPLETE = "complete"
CACHE_MANIFEST_FILENAME = "manifest.json"
COMPONENT_MANIFEST_FILENAME = "component-manifest.json"
EXPAT_HEADER_FILENAME = "expat.h"
EXPAT_HEADER_RELATIVE_PATH = f"include/{EXPAT_HEADER_FILENAME}"
EXPAT_BUILDCONF_FILENAME = "buildconf.sh"
MISSING_COMMAND_TEXT = "not found"
MISSING_FILE_TEXT = "no such file"
MODSECURITY_LIBRARY_FILENAME = "libmodsecurity.so"
# The shared-object SONAME shipped by the approved ModSecurity v3 build.  The
# generic prefix keeps the libtool linker alias above, while the protected
# NGINX broker records only this regular, non-symlinked runtime artifact.
MODSECURITY_RUNTIME_LIBRARY_FILENAME = "libmodsecurity.so.3"
MODSECURITY_REQUIRED_PUBLIC_HEADERS = (
    "modsecurity.h",
    "rules_set.h",
    "transaction.h",
)
MODSECURITY_OUTPUT_LAYOUT_VERSION = 1
NGINX_MODULE_FILENAME = "ngx_http_modsecurity_module.so"
NATIVE_NGINX_OVERRIDE_ENV = "MRTS_NATIVE_NGINX_BIN/MRTS_NATIVE_NGINX_MODULE_DIR"
NGINX_REQUIRE_PINNED_PROVENANCE_ENV = "NGINX_REQUIRE_PINNED_PROVENANCE"
# Parent full-smoke NGINX provenance is an atomic reviewed tuple.  Keep these
# literals together: changing any individual field is a new upstream-source
# review, not a runtime override.
NGINX_PINNED_SOURCE_MODE = "github-release"
NGINX_PINNED_SOURCE_REPOSITORY = "https://github.com/nginx/nginx"
NGINX_PINNED_RELEASE_TAG = "release-1.31.6"
NGINX_PINNED_SOURCE_REF = "release-1.31.6"
NGINX_PINNED_RELEASE_ASSET_NAME = "nginx-1.31.6.tar.gz"
NGINX_PINNED_RELEASE_ASSET_SHA256 = "974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1"
NGINX_PINNED_VERSION_READBACK = "nginx/1.31.6"
DEFAULT_HAPROXY_VERSION = "3.2.25"
NGINX_PINNED_PROVENANCE_SCHEMA_VERSION = 1
APACHE_APXS_RELATIVE_PATH = "bin/apxs"
UNMANAGED_CACHE_ENTRY_MARKER_MISSING_PREFIX = "unmanaged_cache_entry_marker_missing: "
READY_COMPONENT_STATUSES = frozenset({"present", "built", "reused"})
CONNECTOR_BUILD_ID_LABEL = "Connector build ID"
USES_MODSECURITY_BUILD_ID_LABEL = "Uses ModSecurity build ID"
RUNTIME_ENV_SNAPSHOT_SCHEMA_VERSION = 1
PROTECTED_NGINX_BROKER_SNAPSHOT_CONTRACT = "protected-nginx-broker"
GENERIC_RUNTIME_ENV_SNAPSHOT_CONTRACT = "generic"
TRUSTED_NGINX_BROKER_PROVENANCE_FILENAME = "trusted-nginx-broker-provenance.json"
TRUSTED_NGINX_BROKER_PROVENANCE_SCHEMA_VERSION = 1
_TRUSTED_FRAMEWORK_GUARD_SHELL = Path("/bin/sh")
_TRUSTED_FRAMEWORK_GUARD_GIT = Path("/usr/bin/git")
_TRUSTED_FRAMEWORK_GUARD_PATH = "/usr/bin:/bin"
FRAMEWORK_APR_UTIL_ENV_KEYS = (
    "APR_UTIL_VERSION",
    "APR_UTIL_SOURCE_URL",
    "APR_UTIL_SHA256",
    "APR_UTIL_SHA256_URL",
)
# Framework common.sh captures the inherited environment before it assigns
# canonical pins.  Its own snapshot is internal validation state, not runtime
# configuration: passing it through another source operation would turn its
# embedded pin lines into apparent duplicate inherited variables.
FRAMEWORK_TRANSIENT_ENV_KEYS = (
    "CI_INHERITED_UPSTREAM_ENV",
    "CI_INHERITED_UPSTREAM_ENV_STATUS",
)
# A Framework provenance guard sources common.sh itself.  Carry only the
# resolved runtime-root tuple from the previously loaded Framework environment
# into that second source.  Passing common.sh's exported version/provenance
# values back into another common.sh source creates duplicate inherited
# environment entries on dash, which the Framework correctly rejects before
# any source acquisition.  Original caller values remain in os.environ so a
# genuine attempted pin override still reaches the fail-closed guard.
FRAMEWORK_GUARD_RUNTIME_ROOT_ENV_KEYS = (
    "CONNECTOR_ROOT",
    "VERIFIED_RUN_ROOT",
    "VERIFIED_STATE_ROOT",
    "VERIFIED_BUILD_ROOT",
    "VERIFIED_SOURCE_ROOT",
    "VERIFIED_TMP_ROOT",
    "VERIFIED_LOG_ROOT",
    "CACHE_ROOT",
    "VERIFIED_COMPONENT_CACHE",
    "CONNECTOR_COMPONENT_CACHE",
    "SOURCE_ROOT",
    "BUILD_ROOT",
    "TMP_ROOT",
    "LOG_ROOT",
    "MRTS_NATIVE_ROOT",
)
APR_UTIL_VERSION_RE = re.compile(r"\d+(?:\.\d+)+", re.ASCII)
APR_UTIL_SHA256_RE = re.compile(r"[0-9a-f]{64}")
SHELL_QUOTED_ENV_RE = re.compile(r"([A-Z_][A-Z0-9_]*)='([^']*)'")
GIT_STATUS_SHORT_ARGS = (
    "status",
    "--porcelain",
    "--untracked-files=all",
    "--ignored=matching",
)
GIT_SUBMODULE_STATUS_RECURSIVE_ARGS = ("submodule", "status", "--recursive")

# Apache httpd generates several installed helper/configuration files with the
# configured absolute prefix.  Connector cache entries are built below an
# atomic staging directory and then renamed, so those text files must be
# rebased before publication.  Keep this an explicit allowlist: native
# executables are deliberately never rewritten after they are linked.
APACHE_INSTALL_TEXT_PATHS = (
    "bin/apachectl",
    "bin/apachectl-mrts",
    "bin/apr-1-config",
    "bin/apu-1-config",
    APACHE_APXS_RELATIVE_PATH,
    "bin/envvars",
    "bin/envvars-std",
    "build/apr_rules.mk",
    "build/config.nice",
    "build/config_vars.mk",
    "build/config_vars.sh",
    "build/instdso.sh",
    "build/libtool",
    "include/ap_config_auto.h",
    "include/ap_config_layout.h",
    "lib/libapr-1.la",
    "lib/libaprutil-1.la",
    "lib/pkgconfig/apr-1.pc",
    "lib/pkgconfig/apr-util-1.pc",
)


def cache_root_marker_path(cache_root: Path) -> Path:
    return cache_root / CACHE_ROOT_MARKER


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def is_system_path(path: Path) -> bool:
    return is_system_write_path(path, PATH_POLICY_ENV)


def sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def run(cmd: list[str], cwd: Path | None = None, check: bool = False) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and proc.returncode != 0:
        raise RuntimeError((proc.stdout + proc.stderr).strip() or f"command failed: {' '.join(cmd)}")
    return proc


def run_env(
    cmd: list[str],
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = False,
    errors: str | None = None,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        errors=errors,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and proc.returncode != 0:
        raise RuntimeError((proc.stdout + proc.stderr).strip() or f"command failed: {' '.join(cmd)}")
    return proc


def _framework_guard_environment(
    base_env: dict[str, str],
    connector_root: Path,
    framework_root: Path,
) -> dict[str, str]:
    """Build the fixed, non-login environment for Framework guard commands."""
    env = dict(base_env)
    for key in (
        *FRAMEWORK_APR_UTIL_ENV_KEYS,
        *FRAMEWORK_TRANSIENT_ENV_KEYS,
        "ENV",
        "BASH_ENV",
        "SHELLOPTS",
    ):
        env.pop(key, None)
    env["PATH"] = _TRUSTED_FRAMEWORK_GUARD_PATH
    env["CONNECTOR_ROOT"] = str(connector_root)
    env["FRAMEWORK_ROOT"] = str(framework_root)
    return env


def _run_framework_guard(
    command: list[str],
    connector_root: Path,
    env: dict[str, str],
) -> tuple[bytes | None, str | None]:
    """Run one fixed-shell Framework guard and map failures to existing statuses."""
    try:
        proc = subprocess.run(
            command,
            cwd=str(connector_root),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            timeout=60,
        )
    except FileNotFoundError as exc:
        return None, f"failed:{exc}"
    except RuntimeError as exc:
        return None, f"failed:{exc}"
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or b""
        output = output.decode("utf-8", errors="replace").strip()
        return None, f"failed:timeout loading common.sh {output}"
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        return None, f"failed:{stderr or proc.returncode}"
    return proc.stdout, None


def _guarded_apr_util_tuple(output: bytes) -> tuple[dict[str, str] | None, str | None]:
    """Strictly parse and structurally validate the bridge's four assignments."""
    guarded_apr_util: dict[str, str] = {}
    try:
        lines = output.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError:
        return None, "failed:invalid_framework_apr_util_bridge_output"
    for line in lines:
        match = SHELL_QUOTED_ENV_RE.fullmatch(line)
        if match is None or match.group(1) not in FRAMEWORK_APR_UTIL_ENV_KEYS:
            return None, "failed:invalid_framework_apr_util_bridge_output"
        key, value = match.groups()
        if key in guarded_apr_util:
            return None, "failed:duplicate_framework_apr_util_bridge_output"
        guarded_apr_util[key] = value
    try:
        require_apr_util_pinned_provenance(guarded_apr_util)
    except RuntimeError as exc:
        return None, f"failed:{exc}"
    if set(guarded_apr_util) != set(FRAMEWORK_APR_UTIL_ENV_KEYS):
        return None, "failed:incomplete_framework_apr_util_bridge_output"
    return guarded_apr_util, None


def _incoming_apr_util_tuple(base_env: dict[str, str]) -> dict[str, str]:
    """Snapshot only explicitly inherited APR-util fields, including empty ones."""
    return {
        key: base_env[key]
        for key in FRAMEWORK_APR_UTIL_ENV_KEYS
        if key in base_env
    }


def _validate_inherited_apr_util_tuple(
    inherited: dict[str, str],
    canonical: dict[str, str],
) -> str | None:
    """Accept only absent or full byte-identical Framework provenance state."""
    if not inherited:
        return None
    empty_keys = [key for key, value in inherited.items() if not value]
    if empty_keys:
        return f"failed:inherited_parent_apr_util_empty:{','.join(empty_keys)}"
    if set(inherited) != set(FRAMEWORK_APR_UTIL_ENV_KEYS):
        return f"failed:inherited_parent_apr_util_partial:{','.join(sorted(inherited))}"
    if inherited != canonical:
        return "failed:inherited_parent_apr_util_mismatch"
    return None


def _null_delimited_environment(output: bytes) -> dict[str, str]:
    """Decode the Framework common.sh environment without shell evaluation."""
    loaded: dict[str, str] = {}
    for chunk in output.split(b"\0"):
        if not chunk or b"=" not in chunk:
            continue
        key, value = chunk.split(b"=", 1)
        loaded[key.decode("utf-8", errors="replace")] = value.decode("utf-8", errors="replace")
    return loaded


def load_framework_environment(connector_root: Path, framework_root: Path, base_env: dict[str, str]) -> tuple[dict[str, str], str]:
    common_sh = framework_root / "ci/lib/common.sh"
    if not common_sh.is_file():
        return dict(base_env), f"missing:{common_sh}"
    inherited_apr_util = _incoming_apr_util_tuple(base_env)
    try:
        trusted_shell = verified_host_guard_executable(
            _TRUSTED_FRAMEWORK_GUARD_SHELL,
            "framework_apr_util_guard_shell",
        )
        verified_host_guard_executable(
            _TRUSTED_FRAMEWORK_GUARD_GIT,
            "framework_apr_util_guard_git",
        )
    except RuntimeError as exc:
        return dict(base_env), f"failed:{exc}"
    env = _framework_guard_environment(base_env, connector_root, framework_root)
    bridge_output, bridge_error = _run_framework_guard(
        [
            str(trusted_shell),
            str(connector_root / "ci/tools/print-framework-apr-util-env.sh"),
            str(framework_root),
            str(connector_root),
        ],
        connector_root,
        env,
    )
    if bridge_error is not None or bridge_output is None:
        return dict(base_env), bridge_error or "failed:framework_apr_util_bridge_output_missing"
    guarded_apr_util, tuple_error = _guarded_apr_util_tuple(bridge_output)
    if tuple_error is not None or guarded_apr_util is None:
        return dict(base_env), tuple_error or "failed:framework_apr_util_bridge_output_missing"
    inherited_error = _validate_inherited_apr_util_tuple(inherited_apr_util, guarded_apr_util)
    if inherited_error is not None:
        return dict(base_env), inherited_error
    common_output, common_error = _run_framework_guard(
        [
            str(trusted_shell),
            "-eu",
            "-c",
            'set -a; . "$1"; ci_require_apr_util_pinned_provenance; ci_validate_https_runtime_url_config; env -0',
            "framework-common-environment",
            str(common_sh),
        ],
        connector_root,
        env,
    )
    if common_error is not None or common_output is None:
        return dict(base_env), common_error or "failed:framework_common_environment_missing"
    loaded = _null_delimited_environment(common_output)
    for key in FRAMEWORK_TRANSIENT_ENV_KEYS:
        loaded.pop(key, None)
    if any(loaded.get(key) != value for key, value in guarded_apr_util.items()):
        return dict(base_env), "failed:framework_apr_util_guarded_tuple_mismatch"
    loaded.update(guarded_apr_util)
    return loaded, "loaded"


def require_env_value(env: dict[str, str], key: str) -> str:
    value = env.get(key, "").strip()
    if not value:
        raise RuntimeError(f"missing required runtime component config: {key} from framework common.sh")
    return value


def require_full_immutable_git_commit(value: str, label: str) -> str:
    """Accept only a full Git object ID for a mandatory pinned source."""
    commit = value.strip()
    if not FULL_GIT_COMMIT_ID.fullmatch(commit):
        raise RuntimeError(
            f"{label} must be a full immutable Git commit ID "
            "(40 or 64 hexadecimal characters)"
        )
    return commit


def require_staging_path(staging_path: Path | None) -> Path:
    if staging_path is None:
        raise RuntimeError("staging cache entry is required")
    return staging_path


def require_https_url(url: str, label: str) -> str:
    raw = url.strip()
    if not raw.startswith("https://"):
        raise RuntimeError(f"{label} must use https:// only: {url}")
    return raw


def require_apr_util_pinned_provenance(env: dict[str, str]) -> dict[str, str]:
    """Fail closed unless the guarded Framework APR-util archive tuple is exact."""
    values = {key: require_env_value(env, key) for key in FRAMEWORK_APR_UTIL_ENV_KEYS}
    version = values["APR_UTIL_VERSION"]
    if not APR_UTIL_VERSION_RE.fullmatch(version):
        raise RuntimeError("APR_UTIL_VERSION must be a dotted numeric version")
    source_url = values["APR_UTIL_SOURCE_URL"]
    expected_source_url = f"https://downloads.apache.org/apr/apr-util-{version}.tar.bz2"
    if source_url != expected_source_url:
        raise RuntimeError("APR_UTIL_SOURCE_URL must be the exact Apache APR-util archive for APR_UTIL_VERSION")
    sha_url = values["APR_UTIL_SHA256_URL"]
    if sha_url != f"{source_url}.sha256":
        raise RuntimeError("APR_UTIL_SHA256_URL must derive from APR_UTIL_SOURCE_URL")
    expected_sha = values["APR_UTIL_SHA256"].lower()
    if not APR_UTIL_SHA256_RE.fullmatch(expected_sha):
        raise RuntimeError("APR_UTIL_SHA256 must contain exactly 64 hexadecimal characters")
    values["APR_UTIL_SHA256"] = expected_sha
    require_https_url(source_url, "APR_UTIL_SOURCE_URL")
    require_https_url(sha_url, "APR_UTIL_SHA256_URL")
    return values


def require_https_github_repo_url(url: str) -> str:
    repo = github_repo_path(url)
    return f"https://github.com/{repo}"


def require_runtime_component_target(target_connector: str) -> str:
    if target_connector not in RUNTIME_COMPONENT_TARGETS:
        raise RuntimeError(f"unsupported_runtime_component_target:{target_connector}")
    return target_connector


def validate_https_url_config(env: dict[str, str], target_connector: str = "all") -> None:
    target_connector = require_runtime_component_target(target_connector)
    for key in GITHUB_REPO_URL_KEYS:
        if (
            key in NGINX_GITHUB_REPO_URL_KEYS
            and target_connector not in NGINX_RUNTIME_COMPONENT_TARGETS
        ):
            continue
        value = env.get(key, "").strip()
        if value:
            require_https_github_repo_url(value)
    for key in HTTPS_URL_KEYS:
        if (
            key in NGINX_HTTPS_URL_KEYS
            and target_connector not in NGINX_RUNTIME_COMPONENT_TARGETS
        ):
            continue
        value = env.get(key, "").strip()
        if value:
            require_https_url(value, key)


def network_blocker_reason(exc: Exception, *, optional: bool = False) -> str:
    prefix = "blocked_network_optional" if optional else "blocked_network"
    return f"{prefix}:{exc}"


def retry_count() -> int:
    try:
        return max(1, int(os.environ.get("RUNTIME_COMPONENT_NETWORK_RETRIES", "3")))
    except ValueError:
        return 3


def retry_delay_seconds() -> float:
    try:
        return max(0.0, float(os.environ.get("RUNTIME_COMPONENT_NETWORK_RETRY_DELAY_SECONDS", "2")))
    except ValueError:
        return 2.0


def urlopen_bytes(url: str, *, timeout: int = 60) -> bytes:
    last_exc: Exception | None = None
    for attempt in range(1, retry_count() + 1):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                return response.read()
        except Exception as exc:
            last_exc = exc
            if attempt < retry_count():
                time.sleep(retry_delay_seconds())
    raise RuntimeError(last_exc or f"network request failed: {url}")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_manifest(path: Path) -> dict[str, Any]:
    file_count = 0
    total_size = 0
    digest = hashlib.sha256()
    if not path.exists():
        return {"exists": False, "file_count": 0, "total_size": 0, "sha256_manifest": ""}
    for item in sorted(path.rglob("*")):
        if not item.is_file():
            continue
        try:
            rel = item.relative_to(path).as_posix()
            size = item.stat().st_size
        except OSError:
            continue
        file_count += 1
        total_size += size
        digest.update(rel.encode("utf-8", "surrogateescape"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
    return {
        "exists": True,
        "file_count": file_count,
        "total_size": total_size,
        "sha256_manifest": digest.hexdigest(),
    }


def read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def atomic_write_text(path: Path, text: str) -> None:
    """Publish a small cache-control file without exposing partial JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=str(path.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def runtime_env_shell_text(values: dict[str, str]) -> str:
    """Render the deliberately small, sourceable runtime environment format."""
    return "\n".join(
        f"export {key}={sh_quote(value)}" for key, value in sorted(values.items())
    ) + "\n"


def snapshot_path_within_output_root(snapshot_path: Path, output_root: Path) -> Path:
    """Resolve and validate a caller-selected invocation-local snapshot path.

    A shared Cache-v2 runtime-env file remains a compatibility artifact, but
    it cannot be used as a later runner input: concurrent target preparation
    may legitimately republish it.  Snapshot files therefore belong to the
    invocation's report root, never to the shared cache.
    """
    if not snapshot_path.is_absolute():
        raise RuntimeError(f"runtime_env_snapshot_must_be_absolute:{snapshot_path}")
    resolved_root = output_root.resolve()
    resolved_snapshot = snapshot_path.resolve()
    try:
        resolved_snapshot.relative_to(resolved_root)
    except ValueError as exc:
        raise RuntimeError(
            "runtime_env_snapshot_outside_output_root:"
            f"snapshot={resolved_snapshot} output_root={resolved_root}"
        ) from exc
    if resolved_snapshot == resolved_root:
        raise RuntimeError("runtime_env_snapshot_must_be_a_file")
    return resolved_snapshot


def allocate_runtime_env_snapshot(output_root: Path) -> Path:
    """Reserve one unique local destination for a direct Python invocation."""
    output_root.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        prefix="runtime-env-snapshot.", suffix=".sh", dir=str(output_root)
    )
    os.close(descriptor)
    return Path(name)


def write_runtime_env_snapshot(
    runtime_env: dict[str, str],
    *,
    snapshot_path: Path,
    output_root: Path,
    target_connector: str,
    cache_root: Path,
) -> Path:
    """Atomically publish an invocation-local environment snapshot.

    The additional metadata intentionally lives only in this snapshot.  The
    shared ``runtime-env.sh`` keeps its long-standing export contract for
    reports and legacy consumers, while central runners can verify that the
    local file belongs to their selected target and Cache-v2 root.
    """
    destination = snapshot_path_within_output_root(snapshot_path, output_root)
    values = dict(runtime_env)
    values.update(
        {
            "RUNTIME_COMPONENT_ENV_SNAPSHOT": str(destination),
            "RUNTIME_COMPONENT_ENV_SNAPSHOT_CACHE": str(cache_root),
            "RUNTIME_COMPONENT_ENV_SNAPSHOT_SCHEMA": str(
                RUNTIME_ENV_SNAPSHOT_SCHEMA_VERSION
            ),
            "RUNTIME_COMPONENT_ENV_SNAPSHOT_TARGET": target_connector,
        }
    )
    atomic_write_text(destination, runtime_env_shell_text(values))
    return destination


def _private_atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    """Atomically replace one private provenance record, never a partial file."""
    if path.exists() or path.is_symlink():
        details = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(details.st_mode) or details.st_mode & 0o077:
            raise RuntimeError(f"protected_nginx_broker_unsafe_provenance_path:{path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=str(path.parent))
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(data, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def protected_nginx_broker_artifact(path: Path, expected: Path, *, executable_required: bool) -> dict[str, Any]:
    """Return immutable facts only for the canonical, non-symlinked artifact."""
    if path != expected or not path.is_absolute():
        raise RuntimeError(f"protected_nginx_broker_noncanonical_artifact:{path}")
    try:
        details = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"protected_nginx_broker_artifact_unavailable:{path}") from exc
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        raise RuntimeError(f"protected_nginx_broker_unsafe_artifact:{path}")
    if details.st_mode & 0o022:
        raise RuntimeError(f"protected_nginx_broker_writable_artifact:{path}")
    if executable_required and not os.access(path, os.X_OK):
        raise RuntimeError(f"protected_nginx_broker_artifact_not_executable:{path}")
    return {
        "path": str(path),
        "sha256": sha256_file(path),
        "device": details.st_dev,
        "uid": details.st_uid,
        "mode": stat.S_IMODE(details.st_mode),
        "size": details.st_size,
    }


def _protected_nginx_broker_plan_artifacts(
    nginx_plan: dict[str, Any],
) -> tuple[Path, Path, Path]:
    """Validate the completed plan and return its canonical artifacts."""
    completed_manifest = read_json(Path(str(nginx_plan.get("manifest", ""))))
    if completed_manifest.get("build_flags") != nginx_plan.get("build_flags"):
        raise RuntimeError("protected_nginx_broker_completed_manifest_mismatch")
    output_paths = nginx_plan.get("output_paths")
    if not isinstance(output_paths, dict):
        raise RuntimeError("protected_nginx_broker_plan_output_paths_missing")
    try:
        binary = Path(str(output_paths["binary"]))
        module = Path(str(output_paths["module"]))
    except KeyError as exc:
        raise RuntimeError("protected_nginx_broker_plan_artifact_missing") from exc
    if not binary.is_absolute() or not module.is_absolute():
        raise RuntimeError("protected_nginx_broker_plan_artifact_not_absolute")
    try:
        plan_root = Path(str(nginx_plan.get("root", ""))).resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("protected_nginx_broker_plan_root_missing") from exc
    expected_binary = plan_root / "nginx" / "sbin" / "nginx"
    expected_module = plan_root / "nginx" / "modules" / NGINX_MODULE_FILENAME
    if binary != expected_binary or module != expected_module:
        raise RuntimeError("protected_nginx_broker_plan_output_paths_not_canonical")
    return binary, module, plan_root


def _protected_nginx_broker_modsecurity_prefix(
    context: dict[str, Any],
    modsecurity: dict[str, Any],
) -> Path:
    """Return the validated Cache-v2 ModSecurity prefix."""
    try:
        modsecurity_prefix = Path(str(modsecurity.get("prefix", ""))).resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("protected_nginx_broker_modsecurity_prefix_missing") from exc
    expected_modsecurity_prefix = (
        context["cache_root"]
        / "prefix"
        / "modsecurity"
        / str(modsecurity.get("build_id", ""))
    ).resolve()
    if (
        not modsecurity.get("build_id")
        or modsecurity_prefix != expected_modsecurity_prefix
        or not modsecurity_ready(modsecurity_prefix)
    ):
        raise RuntimeError("protected_nginx_broker_modsecurity_prefix_unvalidated")
    return modsecurity_prefix


def _protected_nginx_broker_source_revisions(
    context: dict[str, Any],
) -> tuple[str, str]:
    """Return the immutable Parent and Framework source revisions."""
    parent_sha = git_revision(context["connector_root"])
    framework_sha = git_revision(context["framework_root"])
    if not FULL_GIT_COMMIT_ID.fullmatch(parent_sha) or not FULL_GIT_COMMIT_ID.fullmatch(
        framework_sha
    ):
        raise RuntimeError("protected_nginx_broker_source_revision_missing")
    return parent_sha, framework_sha


def _protected_nginx_broker_release_provenance(
    nginx_plan: dict[str, Any],
    nginx_release_tag: str,
) -> tuple[str, str]:
    """Return the validated NGINX release source and digest."""
    try:
        plan_build_flags = json.loads(str(nginx_plan.get("build_flags", "")))
    except json.JSONDecodeError as exc:
        raise RuntimeError("protected_nginx_broker_plan_release_provenance_missing") from exc
    if not isinstance(plan_build_flags, dict):
        raise RuntimeError("protected_nginx_broker_plan_release_provenance_missing")
    source_repository = str(plan_build_flags.get("NGINX_SOURCE_REPO_URL", ""))
    source_sha256 = str(plan_build_flags.get("NGINX_SHA256", "")).lower()
    if (
        plan_build_flags.get("NGINX_RELEASE_TAG", "") != nginx_release_tag
        or not source_repository
        or not re.fullmatch(r"[0-9a-f]{64}", source_sha256)
    ):
        raise RuntimeError("protected_nginx_broker_release_provenance_incomplete")
    return source_repository, source_sha256


def protected_nginx_broker_runtime_environment(
    context: dict[str, Any],
    components: dict[str, dict[str, Any]],
) -> tuple[dict[str, str], Path]:
    """Build the fixed broker tuple and publish its canonical provenance first."""
    if context["target_connector"] != "nginx":
        raise RuntimeError("protected_nginx_broker_requires_nginx_target")
    nginx = components["nginx"]
    modsecurity = components["modsecurity"]
    nginx_plan = components.get("nginx_plan", {})
    if nginx.get("status") not in READY_COMPONENT_STATUSES or modsecurity.get("status") not in READY_COMPONENT_STATUSES:
        raise RuntimeError("protected_nginx_broker_components_not_ready")
    if not isinstance(nginx_plan, dict) or not connector_manifest_ready(nginx_plan):
        raise RuntimeError("protected_nginx_broker_cache_completion_missing")
    binary, module, plan_root = _protected_nginx_broker_plan_artifacts(nginx_plan)
    expected_binary = plan_root / "nginx" / "sbin" / "nginx"
    expected_module = plan_root / "nginx" / "modules" / NGINX_MODULE_FILENAME
    modsecurity_prefix = _protected_nginx_broker_modsecurity_prefix(context, modsecurity)
    parent_sha, framework_sha = _protected_nginx_broker_source_revisions(context)
    nginx_version = NGINX_PINNED_VERSION_READBACK.removeprefix("nginx/")
    nginx_release_tag = NGINX_PINNED_RELEASE_TAG
    source_repository, source_sha256 = _protected_nginx_broker_release_provenance(
        nginx_plan, nginx_release_tag
    )
    provenance_path = context["output_root"] / TRUSTED_NGINX_BROKER_PROVENANCE_FILENAME
    provenance_path = snapshot_path_within_output_root(provenance_path, context["output_root"])
    binary_artifact = protected_nginx_broker_artifact(binary, expected_binary, executable_required=True)
    module_artifact = protected_nginx_broker_artifact(module, expected_module, executable_required=False)
    library = modsecurity_prefix / "lib" / MODSECURITY_RUNTIME_LIBRARY_FILENAME
    library_artifact = protected_nginx_broker_artifact(library, library, executable_required=False)
    provenance = {
        "schema_version": TRUSTED_NGINX_BROKER_PROVENANCE_SCHEMA_VERSION,
        "producer": {
            "parent_sha": parent_sha.lower(),
            "framework_sha": framework_sha.lower(),
        },
        "nginx": {
            "version": nginx_version,
            "release_tag": nginx_release_tag,
            "source_repository": source_repository,
            "source_sha256": source_sha256,
            "cache_schema_version": nginx_plan.get("cache_schema_version"),
            "cache_key": nginx_plan.get("cache_key"),
            "connector_build_id": nginx_plan.get("connector_build_id"),
            "root": str(plan_root),
            "binary": binary_artifact,
            "module": module_artifact,
        },
        "modsecurity": {
            "prefix": str(modsecurity_prefix),
            "library": library_artifact,
        },
    }
    provenance["producer"]["identity"] = stable_hash(provenance)
    _private_atomic_write_json(provenance_path, provenance)
    if read_json(provenance_path) != provenance:
        raise RuntimeError("protected_nginx_broker_provenance_validation_failed")
    return {
        "NGINX_BINARY": str(provenance["nginx"]["binary"]["path"]),
        "NGINX_MODULE": str(provenance["nginx"]["module"]["path"]),
        "MODSECURITY_SHARED_PREFIX": str(provenance["modsecurity"]["prefix"]),
    }, provenance_path


def nginx_runtime_environment(
    connector_root: Path,
    cache_root: Path,
    nginx: dict[str, Any],
) -> dict[str, str]:
    """Return the ready NGINX values for an invocation-local runtime snapshot.

    The Framework materializes the NGINX adapter below the managed build root,
    while the adapter config still compiles the Parent-owned Common sources.
    This value must be derived from the verified connector root rather than an
    inherited job environment so a direct runtime-matrix invocation receives
    the same explicit source boundary as cache preparation.
    """
    if nginx.get("status") not in {"present", "built", "reused"}:
        return {}
    if nginx.get("require_pinned_provenance") and not nginx.get("runtime_contract_valid"):
        return {}
    return {
        "MRTS_NATIVE_NGINX_BIN": str(nginx.get("nginx_bin", "")),
        "MRTS_NATIVE_NGINX_MODULE_DIR": str(nginx.get("module_dir", "")),
        "MRTS_NATIVE_NGINX_MODULE_FILE": str(nginx.get("module_file", "")),
        "MRTS_NATIVE_NGINX_MODSECURITY_LIB_DIR": str(nginx.get("modsecurity_lib_dir", "")),
        "MSCONNECTOR_COMMON_SRC": str(connector_root / "common" / "src"),
        "NGINX_BUILD_DIR": str(nginx.get("build_path", "")),
        "NGINX_BUILD_OWNER_ROOT": str(cache_root / "builds" / "connectors"),
        "NGINX_PREFIX": str(nginx.get("nginx_prefix", "")),
        "NGINX_CONNECTOR_BUILD_ID": str(nginx.get("connector_build_id", "")),
        "NGINX_PROTOCOL_PROFILE": str(nginx.get("protocol_profile", "h1")),
    }


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=str(path.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def write_json(path: Path, data: Any) -> None:
    atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")


def stable_hash(data: Any) -> str:
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def target_architecture(env: dict[str, str]) -> str:
    return (
        env.get("TARGET_ARCHITECTURE", "").strip()
        or env.get("TARGETARCH", "").strip()
        or env.get("ARCH", "").strip()
        or platform.machine().strip()
        or "unknown"
    )


def patchset_identity(roots: list[Path]) -> dict[str, Any]:
    """Hash patch names, deterministic application order, and full contents."""
    digest = hashlib.sha256()
    files: list[str] = []
    for root_index, root in enumerate(roots):
        digest.update(f"root:{root_index}:{root.name}".encode("utf-8", "surrogateescape"))
        digest.update(b"\0")
        if not root.is_dir():
            digest.update(b"missing\0")
            continue
        ordered = [item for item in sorted(root.rglob("*")) if item.is_file() and ".git" not in item.parts]
        for order, item in enumerate(ordered):
            relative = item.relative_to(root).as_posix()
            files.append(relative)
            digest.update(f"{order}:{relative}".encode("utf-8", "surrogateescape"))
            digest.update(b"\0")
            digest.update(hashlib.sha256(item.read_bytes()).digest())
            digest.update(b"\0")
    return {"sha256": digest.hexdigest(), "files": files}


def component_patchset_roots(connector_root: Path | None, component: str) -> list[Path]:
    if connector_root is None:
        return []
    roots = [
        connector_root / "connectors" / component / "patches",
        connector_root / "patches" / component,
        connector_root / "common" / "patches" / component,
    ]
    # The version-contract-selected HAProxy HTX overlay is copied into a disposable upstream
    # worktree during its optional source-linked build. Treat its source,
    # build script, and pinned Makefile overlay exactly like a patchset so a
    # change cannot reuse a binary built from older overlay inputs.
    if component == "haproxy":
        roots.append(connector_root / "connectors" / "haproxy" / "htx-overlay")
    return roots


def canonical_cache_identity(
    component: str,
    *,
    env: dict[str, str],
    upstream_url: str = "",
    upstream_version: str = "",
    upstream_commit: str = "",
    source_sha256: str = "",
    patchset_sha256: str = "",
    build_profile: str = "",
    configuration_flags: Any = None,
    toolchain: dict[str, Any] | None = None,
    extra_inputs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The complete, stable cache contract used for every reusable build entry."""
    toolchain_payload = toolchain if toolchain is not None else toolchain_identity(env)
    identity: dict[str, Any] = {
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "component": component,
        "upstream_url": upstream_url,
        "upstream_version": upstream_version,
        "upstream_commit": upstream_commit,
        "source_sha256": source_sha256,
        "patchset_sha256": patchset_sha256,
        "target_architecture": target_architecture(env),
        "compiler_id": str(toolchain_payload.get("cc", "")),
        "compiler_version": str(toolchain_payload.get("cc_version", "")),
        "toolchain": toolchain_payload,
        "build_profile": build_profile or env.get("RUNTIME_BUILD_PROFILE", "") or env.get("BUILD_PROFILE", ""),
        "configuration_flags": configuration_flags if configuration_flags is not None else {},
    }
    if extra_inputs:
        identity["extra_inputs"] = extra_inputs
    identity["cache_key"] = stable_hash(identity)
    return identity


def cache_manifest_complete(path: Path, identity: dict[str, Any]) -> bool:
    manifest = read_json(path)
    return (
        manifest.get("status") == CACHE_MANIFEST_STATUS_COMPLETE
        and manifest.get("cache_schema_version") == CACHE_SCHEMA_VERSION
        and manifest.get("cache_key") == identity.get("cache_key")
        and manifest.get("cache_identity") == identity
    )


def write_cache_manifest(path: Path, record: dict[str, Any]) -> None:
    """Persist an entry manifest; only successful artifacts receive complete status."""
    manifest = dict(record)
    record_status = str(record.get("status", "unknown"))
    if record_status in {"built", "reused", "present"}:
        manifest["build_status"] = record_status
        manifest["status"] = CACHE_MANIFEST_STATUS_COMPLETE
    else:
        manifest["status"] = record_status
    manifest.setdefault("cache_schema_version", CACHE_SCHEMA_VERSION)
    identity = manifest.get("cache_identity")
    if isinstance(identity, dict):
        manifest.setdefault("cache_key", identity.get("cache_key", ""))
    write_json(path, manifest)


def is_within(path: Path, owner: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(owner.resolve(strict=False))
        return True
    except ValueError:
        return False


def _resolved_absolute(path: Path, label: str) -> Path:
    raw = Path(path)
    if not raw.is_absolute():
        raise RuntimeError(f"unsafe_{label}_path_not_absolute: {path}")
    return raw.resolve(strict=False)


def paths_overlap(first: Path, second: Path) -> bool:
    first_resolved = first.resolve(strict=False)
    second_resolved = second.resolve(strict=False)
    return first_resolved == second_resolved or is_within(first_resolved, second_resolved) or is_within(second_resolved, first_resolved)


def default_protected_cache_paths() -> tuple[Path, ...]:
    return (selected_connector_root(), test_root())


def cache_root_marker_valid(cache_root: Path) -> bool:
    resolved_root = cache_root.resolve(strict=False)
    marker = read_json(cache_root_marker_path(resolved_root))
    return (
        marker.get("kind") == "msconnector-runtime-cache-root"
        and marker.get("schema_version") == CACHE_SCHEMA_VERSION
        and marker.get("cache_root") == str(resolved_root)
    )


def ensure_managed_cache_root(cache_root: Path, *, protected_paths: tuple[Path, ...] = ()) -> Path:
    """Declare an explicitly configured runtime cache root as repository-managed."""
    resolved_root = _resolved_absolute(cache_root, "cache_root")
    home = Path.home().resolve(strict=False)
    protected = (*default_protected_cache_paths(), *protected_paths)
    if (
        resolved_root == Path("/")
        or resolved_root == home
        or is_system_path(resolved_root)
        or any(paths_overlap(resolved_root, item) for item in protected)
    ):
        raise RuntimeError(f"unsafe_cache_root_forbidden: {resolved_root}")
    resolved_root.mkdir(parents=True, exist_ok=True)
    marker_path = cache_root_marker_path(resolved_root)
    existing_marker = read_json(marker_path) if marker_path.exists() else {}
    if marker_path.exists() and (
        existing_marker.get("kind") != "msconnector-runtime-cache-root"
        or existing_marker.get("cache_root") != str(resolved_root)
    ):
        raise RuntimeError(f"invalid_managed_cache_root_marker: {marker_path}")
    if not cache_root_marker_valid(resolved_root):
        write_json(
            marker_path,
            {
                "kind": "msconnector-runtime-cache-root",
                "schema_version": CACHE_SCHEMA_VERSION,
                "cache_root": str(resolved_root),
                "created_at": utc_now(),
                "previous_schema_version": existing_marker.get("schema_version", ""),
            },
        )
    return resolved_root


def validate_managed_cache_child(
    path: Path,
    cache_root: Path,
    *,
    protected_paths: tuple[Path, ...] = (),
) -> tuple[Path, Path]:
    resolved_path = _resolved_absolute(path, "remove")
    resolved_root = _resolved_absolute(cache_root, "cache_root")
    protected = (*default_protected_cache_paths(), *protected_paths)
    if (
        resolved_path == Path("/")
        or resolved_path == Path.home().resolve(strict=False)
        or resolved_path == resolved_root
        or is_system_path(resolved_path)
        or not is_within(resolved_path, resolved_root)
        or any(paths_overlap(resolved_path, item) for item in protected)
    ):
        raise RuntimeError(f"unsafe_remove_path_forbidden: {resolved_path}")
    if not cache_root_marker_valid(resolved_root):
        raise RuntimeError(f"unmanaged_cache_root_marker_missing: {resolved_root}")
    entry_registry = resolved_root / CACHE_ENTRY_MARKER_DIRECTORY
    if resolved_path == entry_registry or is_within(resolved_path, entry_registry):
        raise RuntimeError(f"unsafe_remove_cache_control_path: {resolved_path}")
    return resolved_path, resolved_root


def cache_entry_marker_path(entry: Path, cache_root: Path) -> Path:
    key = stable_hash({"entry_path": str(entry.resolve(strict=False))})
    return cache_root / CACHE_ENTRY_MARKER_DIRECTORY / f"{key}.json"


def cache_entry_marker_valid(entry: Path, cache_root: Path) -> bool:
    resolved_entry = entry.resolve(strict=False)
    resolved_root = cache_root.resolve(strict=False)
    marker = read_json(cache_entry_marker_path(resolved_entry, resolved_root))
    return (
        marker.get("kind") == "msconnector-runtime-cache-entry"
        and marker.get("schema_version") == CACHE_SCHEMA_VERSION
        and marker.get("cache_root") == str(resolved_root)
        and marker.get("entry_path") == str(resolved_entry)
        and isinstance(marker.get("component"), str)
        and bool(marker.get("component"))
        and isinstance(marker.get("cache_key"), str)
        and bool(marker.get("cache_key"))
    )


def cache_entry_complete(
    entry: Path,
    cache_root: Path,
    *,
    component: str,
    cache_key: str,
    cache_identity: dict[str, Any] | None = None,
) -> bool:
    """Check the registry-side completion manifest for a cache entry."""
    resolved_entry = entry.resolve(strict=False)
    resolved_root = cache_root.resolve(strict=False)
    marker = read_json(cache_entry_marker_path(resolved_entry, resolved_root))
    return (
        cache_entry_marker_valid(resolved_entry, resolved_root)
        and marker.get("component") == component
        and marker.get("cache_key") == cache_key
        and marker.get("status") == CACHE_MANIFEST_STATUS_COMPLETE
        and (cache_identity is None or marker.get("cache_identity") == cache_identity)
    )


def write_cache_entry_completion(
    entry: Path,
    cache_root: Path,
    *,
    component: str,
    cache_key: str,
    cache_identity: dict[str, Any],
) -> None:
    """Write a complete registry-side manifest without touching a Git tree."""
    resolved_entry, resolved_root = validate_managed_cache_child(entry, cache_root)
    marker_path = cache_entry_marker_path(resolved_entry, resolved_root)
    marker = read_json(marker_path)
    if (
        not cache_entry_marker_valid(resolved_entry, resolved_root)
        or marker.get("component") != component
        or marker.get("cache_key") != cache_key
    ):
        raise RuntimeError(f"managed_cache_entry_identity_mismatch: {resolved_entry}")
    identity_key = cache_identity.get("cache_key")
    identity_payload = dict(cache_identity)
    identity_payload.pop("cache_key", None)
    if identity_key != cache_key or stable_hash(identity_payload) != cache_key:
        raise RuntimeError(f"invalid_cache_entry_identity: {resolved_entry}")
    marker.update(
        status=CACHE_MANIFEST_STATUS_COMPLETE,
        cache_identity=cache_identity,
        completed_at=utc_now(),
    )
    write_json(marker_path, marker)


def migrate_legacy_cache_entry_for_removal(
    entry: Path,
    cache_root: Path,
    *,
    component: str,
) -> bool:
    """Upgrade one exact legacy entry marker solely so the entry can be removed.

    Schema upgrades must rebuild old entries, not silently reuse them.  A
    legacy marker therefore grants deletion only when it still binds the exact
    canonical cache root and target path and names the expected component.  It
    is deliberately not a generic path claim and its old cache key is never
    treated as a cache hit.
    """
    resolved_entry, resolved_root = validate_managed_cache_child(entry, cache_root)
    marker_path = cache_entry_marker_path(resolved_entry, resolved_root)
    marker = read_json(marker_path)
    schema_version = marker.get("schema_version")
    if (
        marker.get("kind") != "msconnector-runtime-cache-entry"
        or not isinstance(schema_version, int)
        or schema_version < 1
        or schema_version >= CACHE_SCHEMA_VERSION
        or marker.get("cache_root") != str(resolved_root)
        or marker.get("entry_path") != str(resolved_entry)
        or marker.get("component") != component
        or not isinstance(marker.get("cache_key"), str)
        or not marker.get("cache_key")
    ):
        return False
    write_json(
        marker_path,
        {
            "kind": "msconnector-runtime-cache-entry",
            "schema_version": CACHE_SCHEMA_VERSION,
            "cache_root": str(resolved_root),
            "entry_path": str(resolved_entry),
            "component": component,
            "cache_key": marker["cache_key"],
            "created_at": utc_now(),
            "migrated_from_schema_version": schema_version,
        },
    )
    return True


def cache_manifest_paths(entry: Path) -> tuple[Path, Path]:
    return (
        entry / CACHE_MANIFEST_FILENAME,
        entry / COMPONENT_MANIFEST_FILENAME,
    )


def cache_manifest_identity_is_complete(manifest: dict[str, Any]) -> bool:
    if manifest.get("status") != CACHE_MANIFEST_STATUS_COMPLETE:
        return False
    if manifest.get("cache_schema_version") != CACHE_SCHEMA_VERSION:
        return False
    identity = manifest.get("cache_identity")
    if not isinstance(identity, dict):
        return False
    if identity.get("cache_schema_version") != CACHE_SCHEMA_VERSION:
        return False
    cache_key = manifest.get("cache_key")
    if not isinstance(cache_key, str) or not cache_key:
        return False
    if identity.get("cache_key") != cache_key:
        return False
    identity_payload = dict(identity)
    identity_payload.pop("cache_key", None)
    return stable_hash(identity_payload) == cache_key


def cache_manifest_explicitly_binds_entry(
    manifest_path: Path,
    manifest: dict[str, Any],
    entry: Path,
) -> bool:
    for key in ("prefix", "build_root", "root", "build_path", "path", "source_path"):
        if manifest_path_value_matches_entry(manifest.get(key), entry):
            return True
    return manifest_path.parent == entry and entry.name == manifest.get("cache_key")


def validated_cache_manifest_for_entry(entry: Path) -> dict[str, Any] | None:
    """Return a complete, self-consistent local manifest for exactly ``entry``.

    A filename and a plausible path string are not enough to authorize removal:
    the manifest must carry a current schema cache identity whose deterministic
    key agrees with the manifest, and it must explicitly bind that identity to
    this directory.
    """
    resolved_entry = entry.resolve(strict=False)
    for manifest_path in cache_manifest_paths(resolved_entry):
        manifest = read_json(manifest_path)
        if cache_manifest_identity_is_complete(manifest) and cache_manifest_explicitly_binds_entry(
            manifest_path,
            manifest,
            resolved_entry,
        ):
            return manifest
    return None


def manifest_path_value_matches_entry(raw_path: Any, entry: Path) -> bool:
    """Compare a manifest string as data without making it a path authority.

    The manifest path is used only as a normalized equality proof for an
    already-resolved cache entry.  It must not become a new filesystem path
    for a write, deletion, or subprocess operation.
    """
    if not isinstance(raw_path, str) or not raw_path:
        return False
    try:
        return os.path.realpath(raw_path) == str(entry)
    except (OSError, ValueError):
        return False


def unmanaged_cache_entry_marker_missing(path: Path) -> str:
    return f"{UNMANAGED_CACHE_ENTRY_MARKER_MISSING_PREFIX}{path}"


def cache_manifest_owns_entry(entry: Path) -> bool:
    """Whether a validated local manifest uniquely assigns this cache entry."""
    return validated_cache_manifest_for_entry(entry) is not None


def managed_cache_entry_valid(entry: Path, cache_root: Path) -> bool:
    return cache_entry_marker_valid(entry, cache_root) or cache_manifest_owns_entry(entry)


def mark_managed_cache_entry(
    entry: Path,
    cache_root: Path,
    *,
    component: str,
    cache_key: str,
) -> None:
    resolved_entry, resolved_root = validate_managed_cache_child(entry, cache_root)
    marker_path = cache_entry_marker_path(resolved_entry, resolved_root)
    existing_marker = read_json(marker_path) if marker_path.exists() else {}
    entry_exists = resolved_entry.exists() or resolved_entry.is_symlink()
    manifest = validated_cache_manifest_for_entry(resolved_entry) if entry_exists else None
    if entry_exists and not cache_entry_marker_valid(resolved_entry, resolved_root):
        # A self-consistent local manifest can authorize *removal* of an old
        # cache entry, but it must never become a substitute for the registry
        # marker.  In particular, do not bless an interrupted or externally
        # copied tree merely because it contains a plausible manifest: callers
        # must remove that entry and build a newly marked staging entry.
        if manifest is not None:
            raise RuntimeError(f"managed_cache_entry_requires_rebuild: {resolved_entry}")
        raise RuntimeError(unmanaged_cache_entry_marker_missing(resolved_entry))
    if marker_path.exists() and not cache_entry_marker_valid(resolved_entry, resolved_root):
        raise RuntimeError(f"invalid_managed_cache_entry_marker: {marker_path}")
    if existing_marker and cache_entry_marker_valid(resolved_entry, resolved_root):
        if existing_marker.get("component") != component or existing_marker.get("cache_key") != cache_key:
            raise RuntimeError(f"managed_cache_entry_identity_mismatch: {resolved_entry}")
        return
    write_json(
        marker_path,
        {
            "kind": "msconnector-runtime-cache-entry",
            "schema_version": CACHE_SCHEMA_VERSION,
            "cache_root": str(resolved_root),
            "entry_path": str(resolved_entry),
            "component": component,
            "cache_key": cache_key,
            "created_at": utc_now(),
        },
    )


def remove_managed_cache_entry_marker(entry: Path, cache_root: Path) -> None:
    marker_path = cache_entry_marker_path(entry.resolve(strict=False), cache_root.resolve(strict=False))
    try:
        marker_path.unlink()
    except FileNotFoundError:
        pass


def temporary_cache_dir(
    final_path: Path,
    cache_root: Path,
    *,
    component: str = "staging",
    cache_key: str = "",
) -> Path:
    """Create a same-filesystem staging directory for atomic cache publication."""
    resolved_final, resolved_root = validate_managed_cache_child(final_path, cache_root)
    resolved_final.parent.mkdir(parents=True, exist_ok=True)
    for _ in range(32):
        staging = resolved_final.parent / f".{resolved_final.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
        # Register the randomly named, still-nonexistent path before creating
        # it.  This preserves per-entry ownership even for an interrupted
        # staging setup without retroactively claiming an existing directory.
        mark_managed_cache_entry(staging, resolved_root, component=component, cache_key=cache_key or resolved_final.name)
        try:
            staging.mkdir()
            return staging
        except FileExistsError:
            remove_managed_cache_entry_marker(staging, resolved_root)
    raise RuntimeError(f"cache_staging_directory_collision: {resolved_final.parent}")


def atomic_publish_dir(
    staging_path: Path,
    final_path: Path,
    cache_root: Path,
    *,
    require_complete: bool = False,
) -> None:
    """Publish a fully prepared cache entry without replacing a valid peer entry."""
    staging, resolved_root = validate_managed_cache_child(staging_path, cache_root)
    final, _ = validate_managed_cache_child(final_path, resolved_root)
    if not staging.is_dir():
        raise RuntimeError(f"cache_staging_directory_missing: {staging}")
    if not managed_cache_entry_valid(staging, resolved_root):
        raise RuntimeError(unmanaged_cache_entry_marker_missing(staging))
    if final.exists():
        raise RuntimeError(f"cache_publish_destination_exists: {final}")
    staging_marker = read_json(cache_entry_marker_path(staging, resolved_root))
    if require_complete and (
        staging_marker.get("status") != CACHE_MANIFEST_STATUS_COMPLETE
        and read_json(staging / CACHE_MANIFEST_FILENAME).get("status")
        != CACHE_MANIFEST_STATUS_COMPLETE
    ):
        raise RuntimeError(f"cache_staging_manifest_incomplete: {staging}")
    publish_lock = final.parent / f".{final.name}.publish.lock"
    try:
        publish_lock.mkdir()
    except FileExistsError as exc:
        if final.exists():
            raise RuntimeError(f"cache_publish_destination_exists: {final}") from exc
        raise RuntimeError(f"cache_publish_lock_busy: {publish_lock}") from exc
    try:
        # Do not let a non-cooperating writer overwrite a valid peer entry.
        if final.exists():
            raise RuntimeError(f"cache_publish_destination_exists: {final}")
        final_marker = dict(staging_marker)
        final_marker.update(
            schema_version=CACHE_SCHEMA_VERSION,
            cache_root=str(resolved_root),
            entry_path=str(final),
            published_at=utc_now(),
        )
        write_json(cache_entry_marker_path(final, resolved_root), final_marker)
        os.replace(staging, final)
        remove_managed_cache_entry_marker(staging, resolved_root)
    except Exception:
        remove_managed_cache_entry_marker(final, resolved_root)
        raise
    finally:
        try:
            publish_lock.rmdir()
        except OSError:
            pass


def safe_remove_dir(
    path: Path,
    owner: Path,
    *,
    protected_paths: tuple[Path, ...] = (),
) -> None:
    """Remove only a per-entry marked or manifest-owned cache entry."""
    managed_owner = ensure_managed_cache_root(owner)
    resolved_path, resolved_root = validate_managed_cache_child(path, managed_owner, protected_paths=protected_paths)
    if not resolved_path.exists():
        return
    if not managed_cache_entry_valid(resolved_path, resolved_root):
        raise RuntimeError(unmanaged_cache_entry_marker_missing(resolved_path))
    shutil.rmtree(resolved_path)
    remove_managed_cache_entry_marker(resolved_path, resolved_root)


def safe_remove_file(
    path: Path,
    owner: Path,
    *,
    protected_paths: tuple[Path, ...] = (),
) -> None:
    managed_owner = ensure_managed_cache_root(owner)
    resolved_path, resolved_root = validate_managed_cache_child(path, managed_owner, protected_paths=protected_paths)
    if not resolved_path.exists() and not resolved_path.is_symlink():
        return
    if not resolved_path.is_file() and not resolved_path.is_symlink():
        raise RuntimeError(f"unsafe_remove_file_not_regular: {resolved_path}")
    if not managed_cache_entry_valid(resolved_path, resolved_root):
        raise RuntimeError(unmanaged_cache_entry_marker_missing(resolved_path))
    resolved_path.unlink()
    remove_managed_cache_entry_marker(resolved_path, resolved_root)


def git_output(path: Path, *args: str) -> str:
    proc = run(["git", "-C", str(path), *args])
    return proc.stdout.strip()


def git_revision(path: Path) -> str:
    proc = run(["git", "-C", str(path), "rev-parse", "HEAD"])
    return proc.stdout.strip() if proc.returncode == 0 else ""


def resolved_remote_git_ref(url: str, expected_ref: str) -> str:
    """Resolve a requested Git ref without mutating a published checkout.

    Cache reuse for a moving branch must still notice that origin advanced.
    ``git ls-remote`` supplies that freshness check without cloning or
    fetching the immutable published source tree.
    """
    if FULL_GIT_COMMIT_ID.fullmatch(expected_ref):
        return expected_ref
    requested = expected_ref.removeprefix("origin/")
    if requested.startswith("refs/heads/"):
        candidates = (requested,)
    elif requested.startswith("refs/tags/"):
        candidates = (f"{requested}^{{}}", requested)
    elif requested.startswith("refs/"):
        candidates = (requested,)
    else:
        candidates = (
            f"refs/heads/{requested}",
            f"refs/tags/{requested}^{{}}",
            f"refs/tags/{requested}",
            requested,
        )
    proc = run(["git", "ls-remote", url, *candidates])
    if proc.returncode != 0:
        return ""
    resolved: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 2 and FULL_GIT_COMMIT_ID.fullmatch(fields[0]):
            resolved.setdefault(fields[1], fields[0])
    for candidate in candidates:
        if candidate in resolved:
            return resolved[candidate]
    return ""


def submodule_status_clean(status_text: str) -> tuple[bool, str]:
    for line in status_text.splitlines():
        if not line:
            continue
        if line.startswith("-"):
            return False, "submodule_missing"
        if line.startswith("+"):
            return False, "submodule_ref_mismatch"
    return True, ""


def should_skip_fsck(previous: dict[str, Any], record: dict[str, Any], strict: bool) -> bool:
    if strict:
        return False
    return (
        previous.get("url") == record.get("url")
        and previous.get("expected_ref") == record.get("expected_ref")
        and previous.get("actual_head") == record.get("actual_head")
        and previous.get("submodule_status") == record.get("submodule_status")
        and previous.get("git_fsck") == "PASS"
    )


def source_cache_identity(
    name: str,
    url: str,
    expected_ref: str,
    resolved_commit: str | None = None,
) -> dict[str, Any]:
    """Identity for a Git source, including the immutable resolved commit."""
    if resolved_commit is None:
        # Preserve deterministic identities for callers already pinning a
        # full commit, while leaving moving refs unresolved until Git has
        # fetched and checked out their current origin commit.
        resolved_commit = expected_ref if FULL_GIT_COMMIT_ID.fullmatch(expected_ref) else ""
    identity: dict[str, Any] = {
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "component": name,
        "source_kind": "git",
        "url": url,
        "expected_ref": expected_ref,
        "resolved_commit": resolved_commit,
    }
    identity["cache_key"] = stable_hash(identity)
    return identity


def archive_cache_identity(name: str, url: str, expected_sha: str, sha_url: str) -> dict[str, Any]:
    identity: dict[str, Any] = {
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "component": name,
        "source_kind": "archive",
        "url": url,
        "expected_sha256": expected_sha,
        "sha256_url": sha_url,
    }
    identity["cache_key"] = stable_hash(identity)
    return identity


def apr_util_archive_cache_identity(env: dict[str, str]) -> dict[str, Any]:
    values = require_apr_util_pinned_provenance(env)
    identity = archive_cache_identity(
        "apr-util",
        values["APR_UTIL_SOURCE_URL"],
        values["APR_UTIL_SHA256"],
        values["APR_UTIL_SHA256_URL"],
    )
    identity.update(
        apr_util_version=values["APR_UTIL_VERSION"],
        archive_name=f"apr-util-{values['APR_UTIL_VERSION']}.tar.bz2",
    )
    identity["cache_key"] = stable_hash({key: value for key, value in identity.items() if key != "cache_key"})
    return identity


def retag_staging_cache_entry(
    entry: Path,
    cache_root: Path,
    *,
    component: str,
    cache_key: str,
) -> None:
    """Bind a newly-created, incomplete staging entry to its final identity."""
    resolved_entry, resolved_root = validate_managed_cache_child(entry, cache_root)
    marker_path = cache_entry_marker_path(resolved_entry, resolved_root)
    marker = read_json(marker_path)
    if (
        not cache_entry_marker_valid(resolved_entry, resolved_root)
        or marker.get("component") != component
        or marker.get("status") == CACHE_MANIFEST_STATUS_COMPLETE
        or not resolved_entry.name.startswith(".")
        or ".tmp-" not in resolved_entry.name
    ):
        raise RuntimeError(f"invalid_staging_cache_entry: {resolved_entry}")
    marker["cache_key"] = cache_key
    write_json(marker_path, marker)


def git_checkout_is_reusable(
    checkout_path: Path,
    cache_root: Path,
    *,
    component: str,
    cache_identity: dict[str, Any],
    expected_url: str,
    actual_head: str,
) -> bool:
    """Read-only validation for a published source checkout cache hit."""
    cache_key = str(cache_identity["cache_key"])
    if not (
        checkout_path.is_dir()
        and (checkout_path / ".git").exists()
        and cache_entry_complete(
            checkout_path,
            cache_root,
            component=component,
            cache_key=cache_key,
            cache_identity=cache_identity,
        )
    ):
        return False
    remote = git_output(checkout_path, "config", "--get", "remote.origin.url")
    if remote != expected_url or git_revision(checkout_path) != actual_head:
        return False
    status = run(
        [
            "git",
            "-C",
            str(checkout_path),
            *GIT_STATUS_SHORT_ARGS,
        ]
    )
    return status.returncode == 0 and not status.stdout.strip()


def reusable_git_source_record(
    checkout_path: Path,
    cache_root: Path,
    *,
    name: str,
    expected_url: str,
    expected_ref: str,
    previous: dict[str, Any],
) -> dict[str, Any] | None:
    """Return current provenance for a clean, complete published checkout.

    Target-specific preparation calls share one Cache-v2 source root.  The
    first call has already resolved a moving ref in a fresh clone and stored
    its immutable commit in the root manifest.  A later target can safely
    reuse that exact completed checkout after local provenance/cleanliness
    checks; it must not create another clone merely to rediscover the same
    commit.  Missing, dirty, stale, or incomplete records deliberately fall
    through to the normal fresh-clone recovery path.
    """
    actual_head = previous.get("actual_head")
    if not (
        previous.get("status") in {"present", "built", "reused"}
        and previous.get("url") == expected_url
        and previous.get("expected_ref") == expected_ref
        and isinstance(actual_head, str)
        and actual_head
        and previous.get("git_fsck") == "PASS"
    ):
        return None
    remote_head = resolved_remote_git_ref(expected_url, expected_ref)
    if not remote_head or remote_head.lower() != actual_head.lower():
        return None
    identity = source_cache_identity(name, expected_url, expected_ref, actual_head)
    component = f"source:{name}"
    if not git_checkout_is_reusable(
        checkout_path,
        cache_root,
        component=component,
        cache_identity=identity,
        expected_url=expected_url,
        actual_head=actual_head,
    ):
        return None
    submodules = git_output(checkout_path, *GIT_SUBMODULE_STATUS_RECURSIVE_ARGS)
    clean, _ = submodule_status_clean(submodules)
    if not clean:
        return None
    return {
        "actual_head": actual_head,
        "status_short": "",
        "submodule_status": submodules,
        "submodule_count": len([line for line in submodules.splitlines() if line.strip()]),
        "submodule_status_clean": True,
        "git_fsck": "PASS",
        "tree": tree_manifest(checkout_path),
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "cache_identity": identity,
        "cache_key": identity["cache_key"],
    }


def git_component_record(name: str, url: str, expected_ref: str, checkout_path: Path) -> dict[str, Any]:
    return {
        "name": name,
        "url": url,
        "expected_ref": expected_ref,
        "path": str(checkout_path),
        "recursive_submodules": True,
        "submodule_count": 0,
        "submodule_status_clean": False,
        "git_fsck": "SKIPPED",
        "status": "unknown",
        "blocker_reason": "",
    }


def git_component_request_blocker(url: str, expected_ref: str) -> str:
    if not url or not expected_ref:
        return "missing_url_or_ref"
    try:
        github_repo_path(url)
    except RuntimeError as exc:
        return f"https_github_url_policy:{exc}"
    return ""


def git_component_checkout_location(
    path: Path,
    cache_root: Path | None,
) -> tuple[Path, Path | None, str]:
    checkout_path = Path(path)
    managed_root: Path | None = None
    if cache_root is not None:
        try:
            managed_root = ensure_managed_cache_root(cache_root)
            checkout_path, _ = validate_managed_cache_child(checkout_path, managed_root)
        except RuntimeError as exc:
            return checkout_path, None, str(exc)
    if is_system_path(checkout_path):
        return checkout_path, managed_root, "system_path_write_forbidden"
    return checkout_path, managed_root, ""


def prepare_git_component_with_lock(
    record: dict[str, Any],
    name: str,
    url: str,
    expected_ref: str,
    checkout_path: Path,
    previous_records: dict[str, dict[str, Any]],
    strict: bool,
    managed_root: Path,
    recovery_attempt: bool,
) -> dict[str, Any]:
    ref_lock_key = str(source_cache_identity(name, url, expected_ref)["cache_key"])
    try:
        with BuildLock(cache_entry_lock_path(managed_root, f"source-{name}", ref_lock_key)):
            return prepare_git_component(
                name,
                url,
                expected_ref,
                checkout_path,
                previous_records,
                strict,
                cache_root=managed_root,
                _recovery_attempt=recovery_attempt,
                _lock_held=True,
            )
    except TimeoutError as exc:
        record.update(status="blocked", blocker_reason="cache_lock_timeout", details=str(exc))
        return record


def reuse_git_component_record(
    record: dict[str, Any],
    checkout_path: Path,
    managed_root: Path,
    name: str,
    url: str,
    expected_ref: str,
    previous_records: dict[str, dict[str, Any]],
) -> bool:
    previous = previous_records.get(name, {})
    if not isinstance(previous, dict):
        return False
    reusable = reusable_git_source_record(
        checkout_path,
        managed_root,
        name=name,
        expected_url=url,
        expected_ref=expected_ref,
        previous=previous,
    )
    if reusable is None:
        return False
    record.update(
        reusable,
        path=str(checkout_path),
        manifest=str(cache_entry_marker_path(checkout_path, managed_root)),
        status="present",
    )
    return True


def git_working_path_for_preparation(
    record: dict[str, Any],
    checkout_path: Path,
    managed_root: Path | None,
    name: str,
    url: str,
    expected_ref: str,
    previous_records: dict[str, dict[str, Any]],
    ref_lock_key: str,
) -> tuple[Path | None, Path | None]:
    if managed_root is None:
        if checkout_path.exists():
            record.update(status="blocked", blocker_reason="unmanaged_source_checkout_requires_cache_root")
            return None, None
        checkout_path.parent.mkdir(parents=True, exist_ok=True)
        return checkout_path, None
    if reuse_git_component_record(
        record,
        checkout_path,
        managed_root,
        name,
        url,
        expected_ref,
        previous_records,
    ):
        return None, None
    staging_path = temporary_cache_dir(
        checkout_path,
        managed_root,
        component=f"source:{name}",
        cache_key=ref_lock_key,
    )
    return staging_path, staging_path


def clone_git_checkout(url: str, working_path: Path) -> str:
    run(["git", "clone", "--recursive", url, str(working_path)], check=True)
    remote_url = git_output(working_path, "config", "--get", "remote.origin.url")
    if remote_url and remote_url != url:
        return f"unexpected_origin:{remote_url}"
    return ""


def checkout_fresh_git_source(
    working_path: Path,
    expected_ref: str,
) -> tuple[str, str, str]:
    fetch = run(["git", "-C", str(working_path), "fetch", "--tags", "--prune", "origin"])
    if fetch.returncode != 0:
        return "", "git_fetch_failed", (fetch.stdout + fetch.stderr).strip()
    checkout_candidates = [expected_ref]
    if not expected_ref.startswith(("origin/", "refs/")) and not FULL_GIT_COMMIT_ID.fullmatch(expected_ref):
        # Prefer the freshly fetched remote tracking ref for branches; tags and
        # other refs still fall back to the requested spelling.
        checkout_candidates.insert(0, f"origin/{expected_ref}")
    checkout_ref = checkout_candidates[0]
    checkout = subprocess.CompletedProcess([], 1, "", "")
    for candidate in checkout_candidates:
        checkout_ref = candidate
        checkout = run(["git", "-C", str(working_path), "checkout", "--detach", candidate])
        if checkout.returncode == 0:
            break
    if checkout.returncode != 0:
        return "", "git_checkout_failed", (checkout.stdout + checkout.stderr).strip()
    return checkout_ref, "", ""


def initialize_git_submodules(working_path: Path) -> tuple[bool, str]:
    for command in (
        ["git", "-C", str(working_path), "submodule", "sync", "--recursive"],
        ["git", "-C", str(working_path), "submodule", "update", "--init", "--recursive"],
    ):
        proc = run(command)
        if proc.returncode != 0:
            return False, (proc.stdout + proc.stderr).strip()
    return True, ""


def record_fresh_git_checkout(
    record: dict[str, Any],
    working_path: Path,
    name: str,
    url: str,
    expected_ref: str,
) -> bool:
    actual_head = git_output(working_path, "rev-parse", "HEAD")
    if not actual_head:
        record.update(status="blocked", blocker_reason="git_resolved_commit_missing")
        return False
    source_identity = source_cache_identity(name, url, expected_ref, actual_head)
    status_short = git_output(working_path, *GIT_STATUS_SHORT_ARGS)
    submodules = git_output(working_path, *GIT_SUBMODULE_STATUS_RECURSIVE_ARGS)
    clean, reason = submodule_status_clean(submodules)
    record.update(
        actual_head=actual_head,
        status_short=status_short,
        submodule_status=submodules,
        submodule_count=len([line for line in submodules.splitlines() if line.strip()]),
        submodule_status_clean=clean,
        tree=tree_manifest(working_path),
        cache_schema_version=CACHE_SCHEMA_VERSION,
        cache_identity=source_identity,
        cache_key=source_identity["cache_key"],
    )
    if status_short:
        record.update(status="blocked", blocker_reason="dirty_source_checkout", details=status_short)
        return False
    if not clean:
        record.update(status="blocked", blocker_reason=reason)
        return False
    fsck = run(["git", "-C", str(working_path), "fsck", "--full"])
    record["git_fsck"] = "PASS" if fsck.returncode == 0 else "FAIL"
    if fsck.returncode != 0:
        record.update(
            status="corrupt",
            blocker_reason="git_fsck_failed",
            details=(fsck.stdout + fsck.stderr).strip(),
        )
        return False
    return True


def prepare_fresh_git_checkout(
    record: dict[str, Any],
    working_path: Path,
    name: str,
    url: str,
    expected_ref: str,
) -> bool:
    clone_blocker = clone_git_checkout(url, working_path)
    if clone_blocker:
        record.update(status="blocked", blocker_reason=clone_blocker)
        return False
    checkout_ref, checkout_blocker, details = checkout_fresh_git_source(working_path, expected_ref)
    if checkout_blocker:
        record.update(status="blocked", blocker_reason=checkout_blocker, details=details)
        return False
    record["checkout_ref"] = checkout_ref
    submodules_ready, submodule_details = initialize_git_submodules(working_path)
    if not submodules_ready:
        record.update(status="blocked", blocker_reason="submodule_update_failed", details=submodule_details)
        return False
    return record_fresh_git_checkout(record, working_path, name, url, expected_ref)


def git_checkout_removal_blocker(checkout_path: Path, managed_root: Path, component: str) -> str:
    if not checkout_path.exists():
        return ""
    marker = read_json(cache_entry_marker_path(checkout_path, managed_root))
    if cache_entry_marker_valid(checkout_path, managed_root):
        if marker.get("component") != component:
            return f"managed_cache_entry_identity_mismatch: {checkout_path}"
        return ""
    if cache_manifest_owns_entry(checkout_path):
        return ""
    if migrate_legacy_cache_entry_for_removal(checkout_path, managed_root, component=component):
        return ""
    return unmanaged_cache_entry_marker_missing(checkout_path)


def remove_existing_git_checkout_for_rebuild(
    record: dict[str, Any],
    checkout_path: Path,
    managed_root: Path,
    component: str,
) -> bool:
    blocker = git_checkout_removal_blocker(checkout_path, managed_root, component)
    if blocker:
        record.update(status="blocked", blocker_reason=blocker)
        return False
    if not checkout_path.exists():
        return True
    safe_remove_dir(checkout_path, managed_root)
    record.update(
        rebuild_required=True,
        invalidation_reason="resolved_source_commit_changed_or_incomplete",
        old_entry_removed=True,
        previous_path=str(checkout_path),
    )
    return True


def publish_fresh_git_checkout(
    record: dict[str, Any],
    checkout_path: Path,
    staging_path: Path,
    managed_root: Path,
    name: str,
    url: str,
) -> dict[str, Any]:
    component = f"source:{name}"
    source_identity = record["cache_identity"]
    source_cache_key = str(record["cache_key"])
    actual_head = str(record["actual_head"])
    if git_checkout_is_reusable(
        checkout_path,
        managed_root,
        component=component,
        cache_identity=source_identity,
        expected_url=url,
        actual_head=actual_head,
    ):
        record.update(
            path=str(checkout_path),
            manifest=str(cache_entry_marker_path(checkout_path, managed_root)),
            status="present",
            tree=tree_manifest(checkout_path),
        )
        return record
    if not remove_existing_git_checkout_for_rebuild(record, checkout_path, managed_root, component):
        return record
    staging_path = require_staging_path(staging_path)
    retag_staging_cache_entry(
        staging_path,
        managed_root,
        component=component,
        cache_key=source_cache_key,
    )
    write_cache_entry_completion(
        staging_path,
        managed_root,
        component=component,
        cache_key=source_cache_key,
        cache_identity=source_identity,
    )
    atomic_publish_dir(staging_path, checkout_path, managed_root, require_complete=True)
    record.update(
        path=str(checkout_path),
        manifest=str(cache_entry_marker_path(checkout_path, managed_root)),
        status="present",
        tree=tree_manifest(checkout_path),
    )
    return record


def prepare_git_component_unlocked(
    record: dict[str, Any],
    name: str,
    url: str,
    expected_ref: str,
    checkout_path: Path,
    previous_records: dict[str, dict[str, Any]],
    managed_root: Path | None,
) -> dict[str, Any]:
    ref_lock_key = str(source_cache_identity(name, url, expected_ref)["cache_key"])
    staging_path: Path | None = None
    try:
        working_path, staging_path = git_working_path_for_preparation(
            record,
            checkout_path,
            managed_root,
            name,
            url,
            expected_ref,
            previous_records,
            ref_lock_key,
        )
        if working_path is None:
            return record
        if not prepare_fresh_git_checkout(record, working_path, name, url, expected_ref):
            return record
        if managed_root is not None:
            return publish_fresh_git_checkout(
                record,
                checkout_path,
                require_staging_path(staging_path),
                managed_root,
                name,
                url,
            )
        record.update(path=str(checkout_path), status="present")
        return record
    except Exception as exc:
        record.update(status="blocked", blocker_reason=str(exc))
        return record
    finally:
        if staging_path is not None and staging_path.exists() and managed_root is not None:
            try:
                safe_remove_dir(staging_path, managed_root)
            except RuntimeError:
                pass


def prepare_git_component(
    name: str,
    url: str,
    expected_ref: str,
    path: Path,
    previous_records: dict[str, dict[str, Any]],
    strict: bool,
    cache_root: Path | None = None,
    _recovery_attempt: bool = False,
    _lock_held: bool = False,
) -> dict[str, Any]:
    checkout_path = Path(path)
    record = git_component_record(name, url, expected_ref, checkout_path)
    blocker = git_component_request_blocker(url, expected_ref)
    if blocker:
        record.update(status="blocked", blocker_reason=blocker)
        return record
    checkout_path, managed_root, blocker = git_component_checkout_location(checkout_path, cache_root)
    if blocker:
        record.update(status="blocked", blocker_reason=blocker)
        return record
    record["path"] = str(checkout_path)
    if managed_root is not None and not _lock_held:
        return prepare_git_component_with_lock(
            record,
            name,
            url,
            expected_ref,
            checkout_path,
            previous_records,
            strict,
            managed_root,
            _recovery_attempt,
        )
    return prepare_git_component_unlocked(
        record,
        name,
        url,
        expected_ref,
        checkout_path,
        previous_records,
        managed_root,
    )


def resolve_latest_github_release_tag(source_url: str, cache_path: Path | None = None) -> tuple[str, str, str]:
    repo = github_repo_path(source_url)
    api_url = f"https://api.github.com/repos/{repo}/releases/latest"
    source = "network"
    try:
        raw = urlopen_bytes(api_url, timeout=60)
        data = json.loads(raw.decode("utf-8"))
        if cache_path is not None:
            atomic_write_bytes(cache_path, raw)
    except Exception as exc:
        if cache_path is None or not cache_path.is_file():
            raise
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        source = f"cached_after_network_error:{exc}"
    tag = data.get("tag_name")
    html_url = data.get("html_url") or f"https://github.com/{repo}/releases/tag/{tag or ''}"
    if not isinstance(tag, str) or not tag:
        raise RuntimeError(f"latest release for {source_url} did not include tag_name")
    return tag, str(html_url), source


def prepare_release_git_component(
    name: str,
    source_url: str,
    expected_prompt_latest: str,
    path: Path,
    previous_records: dict[str, dict[str, Any]],
    strict: bool,
    optional: bool = False,
    cache_root: Path | None = None,
) -> dict[str, Any]:
    try:
        release_tag, release_url, release_lookup_status = resolve_latest_github_release_tag(
            source_url,
            path.parent / f"{name}-latest-release.json",
        )
    except Exception as exc:
        return {
            "name": name,
            "url": source_url,
            "source": source_url,
            "path": str(path),
            "expected_ref": "",
            "release_tag": "",
            "status": "blocked_optional" if optional else "blocked",
            "optional": optional,
            "blocker_reason": network_blocker_reason(exc, optional=optional),
        }
    record = prepare_git_component(
        name,
        source_url,
        release_tag,
        path,
        previous_records,
        strict,
        cache_root=cache_root,
    )
    if optional and record.get("status") in {"blocked", "corrupt"}:
        record["status"] = "blocked_optional"
        record["optional"] = True
        record["blocker_reason"] = f"optional_source_unavailable:{record.get('blocker_reason', 'unknown')}"
    record.update(
        source=source_url,
        release_tag=release_tag,
        release_url=release_url,
        release_lookup_status=release_lookup_status,
        optional=optional,
        expected_prompt_latest=expected_prompt_latest,
        release_tag_deviation=bool(expected_prompt_latest and release_tag != expected_prompt_latest),
        release_tag_deviation_note=(
            f"prompt_expected_latest={expected_prompt_latest}; current_latest={release_tag}"
            if expected_prompt_latest and release_tag != expected_prompt_latest
            else ""
        ),
    )
    return record


def prepare_immutable_git_component(
    name: str,
    source_url: str,
    expected_commit: str,
    path: Path,
    previous_records: dict[str, dict[str, Any]],
    strict: bool,
    cache_root: Path | None = None,
) -> dict[str, Any]:
    """Prepare a mandatory Git source pinned to one immutable commit.

    Unlike optional release-backed tools, this path intentionally never asks
    GitHub for a latest release.  The completed checkout record must prove the
    checked-out object is exactly the configured full commit ID before its
    source can be consumed by a dependent runtime component.
    """
    try:
        expected_commit = require_full_immutable_git_commit(expected_commit, f"{name} Git ref")
    except RuntimeError as exc:
        return {
            "name": name,
            "url": source_url,
            "source": source_url,
            "path": str(path),
            "expected_ref": expected_commit.strip(),
            "release_tag": "",
            "release_lookup_status": "not_applicable_immutable_commit",
            "immutable_commit_verified": False,
            "status": "blocked",
            "optional": False,
            "blocker_reason": str(exc),
        }

    record = prepare_git_component(
        name,
        source_url,
        expected_commit,
        path,
        previous_records,
        strict,
        cache_root=cache_root,
    )
    actual_head = record.get("actual_head")
    immutable_commit_verified = (
        isinstance(actual_head, str) and actual_head.lower() == expected_commit.lower()
    )
    record.update(
        source=source_url,
        expected_ref=expected_commit,
        release_tag=expected_commit,
        release_lookup_status="not_applicable_immutable_commit",
        immutable_commit_verified=immutable_commit_verified,
        optional=False,
        expected_prompt_latest="",
        release_tag_deviation=False,
        release_tag_deviation_note="",
    )
    if record.get("status") == "present" and not immutable_commit_verified:
        record.update(
            status="blocked",
            blocker_reason="immutable_git_checkout_record_mismatch",
        )
    return record


def prepare_expat_git_component(
    source_url: str,
    expected_ref: str,
    path: Path,
    previous_records: dict[str, dict[str, Any]],
    strict: bool,
    cache_root: Path | None = None,
) -> dict[str, Any]:
    """Prepare Expat from its configured immutable commit in every mode.

    ``strict`` still controls the cache/fsck policy of the shared Git
    preparer.  It must not change Expat provenance into a latest-release
    lookup.
    """
    return prepare_immutable_git_component(
        "expat",
        source_url,
        expected_ref,
        path,
        previous_records,
        strict,
        cache_root=cache_root,
    )


def archive_can_list(path: Path) -> bool:
    try:
        with tarfile.open(path) as archive:
            archive.getmembers()
        return True
    except Exception:
        return False


def download(url: str, dest: Path) -> None:
    require_https_url(url, "download URL")
    atomic_write_bytes(dest, urlopen_bytes(url, timeout=60))


class HttpdSourceNoRedirect(urllib.request.HTTPRedirectHandler):
    """A retired HTTPD release may move only through the explicit 404 policy."""

    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def httpd_archive_recovery_url(url: str, expected_sha: str) -> str:
    require_literal_sha256(expected_sha, "httpd")
    match = re.fullmatch(
        r"https://downloads\.apache\.org/httpd/(httpd-\d+\.\d+\.\d+\.tar\.bz2)",
        url,
        flags=re.ASCII,
    )
    if match is None:
        raise RuntimeError("httpd_source_recovery_requires_canonical_release_url")
    return f"https://archive.apache.org/dist/httpd/{match.group(1)}"


def download_httpd_source_archive(url: str, dest: Path, expected_sha: str) -> str:
    """Recover only an exact canonical HTTPD 404, retaining the reviewed digest."""
    archived_url = httpd_archive_recovery_url(url, expected_sha)
    opener = urllib.request.build_opener(HttpdSourceNoRedirect())

    def acquire(selected_url: str) -> bytes:
        try:
            with opener.open(selected_url, timeout=60) as response:
                if response.geturl() != selected_url:
                    raise RuntimeError("httpd_source_redirect_forbidden")
                return response.read()
        except urllib.error.HTTPError as error:
            error.close()
            raise

    download_url = url
    try:
        payload = acquire(url)
    except urllib.error.HTTPError as error:
        if error.code != 404 or error.geturl() != url:
            raise
        download_url = archived_url
        payload = acquire(download_url)
    atomic_write_bytes(dest, payload)
    return download_url


def expected_sha_from_url(url: str, archive_name: str, dest: Path) -> str:
    if not url:
        return ""
    download(url, dest)
    text = dest.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) == 1 or archive_name in fields[-1]:
            return fields[0]
    return ""


def require_literal_sha256(value: str, label: str) -> str:
    """Require a configured literal SHA-256 before handling a pinned archive."""

    digest = value.strip()
    if not digest:
        raise RuntimeError(f"missing required SHA256 digest for {label}")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        raise RuntimeError(
            f"invalid SHA256 digest for {label}: expected exactly 64 hexadecimal characters"
        )
    return digest.lower()


def nginx_pinned_provenance_required(env: dict[str, str]) -> bool:
    """Return whether a full-smoke run requires managed local NGINX artifacts.

    NGINX source provenance is always pinned below.  This separate, narrowly
    scoped flag controls whether inherited native binary/module overrides are
    allowed to provide runtime artifacts for a smoke run.
    """

    value = env.get(NGINX_REQUIRE_PINNED_PROVENANCE_ENV, "")
    if value in {"", "0"}:
        return False
    if value == "1":
        return True
    raise RuntimeError(
        f"invalid {NGINX_REQUIRE_PINNED_PROVENANCE_ENV}: expected unset, 0, or 1"
    )


def nginx_pinned_env_value(env: dict[str, str], key: str) -> str:
    """Read one strict NGINX tuple value without normalizing unsafe input."""

    raw = env.get(key, "")
    if not isinstance(raw, str) or not raw:
        raise RuntimeError(f"nginx_pinned_provenance_missing:{key}")
    if raw != raw.strip():
        raise RuntimeError(f"nginx_pinned_provenance_noncanonical_whitespace:{key}")
    return raw


def nginx_pinned_source_tuple(provenance: dict[str, str]) -> dict[str, str]:
    """Return the stable evidence/cache tuple without derived path values."""

    return {
        "mode": provenance["mode"],
        "repo": provenance["repository"],
        "tag": provenance["release_tag"],
        "ref": provenance["source_ref"],
        "asset": provenance["release_asset_name"],
        "sha256": provenance["sha256"],
    }


def nginx_pinned_provenance(env: dict[str, str]) -> dict[str, str]:
    """Validate the reviewed NGINX release-asset tuple before any I/O.

    This route intentionally has no latest-release lookup, tag archive fallback,
    or alternate repository path.  The values are compared before cache marker
    reads, download attempts, archive inspection, or archive publication.
    """

    mode = nginx_pinned_env_value(env, "NGINX_SOURCE_MODE")
    repository = nginx_pinned_env_value(env, "NGINX_SOURCE_REPO_URL")
    tag = nginx_pinned_env_value(env, "NGINX_RELEASE_TAG")
    source_ref = nginx_pinned_env_value(env, "NGINX_SOURCE_GIT_REF")
    asset_name = nginx_pinned_env_value(env, "NGINX_RELEASE_ASSET_NAME")
    supplied_sha256 = nginx_pinned_env_value(env, "NGINX_SHA256")
    github_repo = env.get("NGINX_GITHUB_REPO", "")

    if mode != NGINX_PINNED_SOURCE_MODE:
        raise RuntimeError("nginx_pinned_provenance_mode_mismatch")
    if repository != NGINX_PINNED_SOURCE_REPOSITORY:
        raise RuntimeError("nginx_pinned_provenance_repository_mismatch")
    if github_repo and github_repo != repository:
        raise RuntimeError("nginx_pinned_provenance_github_repository_mismatch")
    if tag.lower() == "latest" or source_ref.lower() == "latest":
        raise RuntimeError("nginx_pinned_provenance_latest_forbidden")
    if tag != source_ref:
        raise RuntimeError("nginx_pinned_provenance_tag_ref_mismatch")
    if tag != NGINX_PINNED_RELEASE_TAG or source_ref != NGINX_PINNED_SOURCE_REF:
        raise RuntimeError("nginx_pinned_provenance_ref_mismatch")
    if asset_name != NGINX_PINNED_RELEASE_ASSET_NAME:
        raise RuntimeError("nginx_pinned_provenance_asset_mismatch")
    expected_sha256 = require_literal_sha256(supplied_sha256, "NGINX_SHA256")
    if expected_sha256 != NGINX_PINNED_RELEASE_ASSET_SHA256:
        raise RuntimeError("nginx_pinned_provenance_sha256_mismatch")

    release_asset_url = (
        f"{NGINX_PINNED_SOURCE_REPOSITORY}/releases/download/"
        f"{NGINX_PINNED_RELEASE_TAG}/{NGINX_PINNED_RELEASE_ASSET_NAME}"
    )
    return {
        "mode": mode,
        "repository": repository,
        "release_tag": tag,
        "source_ref": source_ref,
        "release_asset_name": asset_name,
        "sha256": expected_sha256,
        "release_asset_url": release_asset_url,
    }


def nginx_pinned_archive_cache_identity(provenance: dict[str, str]) -> dict[str, Any]:
    """Bind NGINX archive reuse to all reviewed provenance tuple fields."""

    identity: dict[str, Any] = {
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "component": "archive:nginx",
        "source_kind": "nginx-pinned-release-asset",
        "url": provenance["release_asset_url"],
        "expected_sha256": provenance["sha256"],
        "sha256_url": "",
        "nginx_pinned_provenance_schema_version": NGINX_PINNED_PROVENANCE_SCHEMA_VERSION,
        "source_tuple": nginx_pinned_source_tuple(provenance),
    }
    identity["cache_key"] = stable_hash(identity)
    return identity


def nginx_archive_provenance_fields(provenance: dict[str, str]) -> dict[str, Any]:
    """Normalize reviewed source evidence for archive and component records."""

    source_tuple = nginx_pinned_source_tuple(provenance)
    return {
        "source": provenance["release_asset_url"],
        "source_tuple": source_tuple,
        "source_mode": provenance["mode"],
        "source_repository": provenance["repository"],
        "release_tag": provenance["release_tag"],
        "source_ref": provenance["source_ref"],
        "release_asset_name": provenance["release_asset_name"],
        "release_asset_url": provenance["release_asset_url"],
        "expected_sha256": provenance["sha256"],
        "resolved_tag": provenance["release_tag"],
        "release_lookup_status": "not_applicable_pinned_release_asset",
        "pinned_provenance": True,
        "provenance_validation": "passed",
    }


def archive_cache_component(name: str) -> str:
    return f"archive:{name}"


def archive_cache_entry_action(
    path: Path,
    cache_root: Path,
    component: str,
    cache_key: str,
    cache_identity: dict[str, Any],
) -> tuple[str, str]:
    if not path.exists():
        return "create", ""
    marker = read_json(cache_entry_marker_path(path, cache_root))
    if not cache_entry_marker_valid(path, cache_root):
        if migrate_legacy_cache_entry_for_removal(path, cache_root, component=component):
            return "replace", "cache_schema_changed"
        return "blocked", unmanaged_cache_entry_marker_missing(path)
    if marker.get("component") != component:
        return "blocked", f"managed_cache_entry_identity_mismatch: {path}"
    if marker.get("cache_key") != cache_key:
        return "replace", "archive_cache_identity_changed"
    if not cache_entry_complete(
        path,
        cache_root,
        component=component,
        cache_key=cache_key,
        cache_identity=cache_identity,
    ):
        return "replace", "incomplete_archive_cache_entry"
    return "keep", ""


def reconcile_archive_cache_entry(
    record: dict[str, Any],
    path: Path,
    cache_root: Path,
    component: str,
    cache_key: str,
    cache_identity: dict[str, Any],
) -> bool:
    action, reason = archive_cache_entry_action(
        path,
        cache_root,
        component,
        cache_key,
        cache_identity,
    )
    if action == "blocked":
        record.update(status="blocked", blocker_reason=reason)
        return False
    if action == "keep":
        return True
    if path.exists():
        safe_remove_file(path, cache_root)
    mark_managed_cache_entry(path, cache_root, component=component, cache_key=cache_key)
    if reason:
        record.update(
            rebuild_required=True,
            invalidation_reason=reason,
            old_entry_removed=True,
        )
    return True


def remove_archive_path(path: Path, cache_root: Path | None) -> None:
    if cache_root is None:
        path.unlink()
        return
    safe_remove_file(path, cache_root)


def archive_requires_download(
    path: Path,
    *,
    expected_sha: str = "",
    verify_digest_before_archive_list: bool = False,
) -> bool:
    if not path.is_file():
        return True
    if path.stat().st_size <= 0:
        return True
    if verify_digest_before_archive_list:
        if not expected_sha:
            raise RuntimeError("missing_expected_sha256_before_archive_list")
        if sha256_file(path) != expected_sha:
            return True
    return not archive_can_list(path)


def download_archive_if_needed(
    url: str,
    path: Path,
    cache_root: Path | None,
    component: str,
    cache_key: str,
    *,
    expected_sha: str = "",
    verify_digest_before_archive_list: bool = False,
    allow_httpd_source_recovery: bool = False,
) -> str | None:
    if not archive_requires_download(
        path,
        expected_sha=expected_sha,
        verify_digest_before_archive_list=verify_digest_before_archive_list,
    ):
        return
    if path.exists():
        remove_archive_path(path, cache_root)
    if cache_root is not None:
        mark_managed_cache_entry(path, cache_root, component=component, cache_key=cache_key)
    if allow_httpd_source_recovery:
        if component != archive_cache_component("httpd"):
            raise RuntimeError("httpd_source_recovery_component_invalid")
        return download_httpd_source_archive(url, path, expected_sha)
    download(url, path)
    return None


def corrupt_archive_record(
    record: dict[str, Any],
    path: Path,
    cache_root: Path | None,
    blocker_reason: str,
) -> dict[str, Any]:
    remove_archive_path(path, cache_root)
    record.update(status="corrupt", blocker_reason=blocker_reason)
    return record


def archive_expected_checksum(
    expected_sha: str,
    sha_url: str,
    archive_name: str,
    dest_dir: Path,
    name: str,
) -> str:
    if expected_sha or not sha_url:
        return expected_sha
    return expected_sha_from_url(sha_url, archive_name, dest_dir / f"{name}.sha256")


def archive_managed_root(dest_dir: Path, cache_root: Path | None) -> Path | None:
    if cache_root is None:
        return None
    managed_root = ensure_managed_cache_root(cache_root)
    validate_managed_cache_child(dest_dir, managed_root)
    return managed_root


def prepare_archive_with_lock(
    record: dict[str, Any],
    name: str,
    url: str,
    expected_sha: str,
    sha_url: str,
    dest_dir: Path,
    managed_root: Path,
    required_literal_sha256: bool,
    cache_key: str,
    *,
    cache_identity: dict[str, Any] | None = None,
    verify_digest_before_archive_list: bool = False,
    allow_httpd_source_recovery: bool = False,
) -> dict[str, Any]:
    try:
        with BuildLock(cache_entry_lock_path(managed_root, f"archive-{name}", cache_key)):
            return prepare_archive(
                name,
                url,
                expected_sha,
                sha_url,
                dest_dir,
                managed_root,
                required_literal_sha256=required_literal_sha256,
                _lock_held=True,
                cache_identity=cache_identity,
                verify_digest_before_archive_list=verify_digest_before_archive_list,
                allow_httpd_source_recovery=allow_httpd_source_recovery,
            )
    except TimeoutError as exc:
        record.update(status="blocked", blocker_reason="cache_lock_timeout", details=str(exc))
        return record


def prepare_archive_unlocked(
    record: dict[str, Any],
    name: str,
    url: str,
    expected_sha: str,
    sha_url: str,
    archive_name: str,
    path: Path,
    dest_dir: Path,
    managed_root: Path | None,
    archive_identity: dict[str, Any],
    *,
    verify_digest_before_archive_list: bool = False,
    allow_httpd_source_recovery: bool = False,
) -> dict[str, Any]:
    component = archive_cache_component(name)
    cache_key = str(archive_identity["cache_key"])
    dest_dir.mkdir(parents=True, exist_ok=True)
    if managed_root is not None and not reconcile_archive_cache_entry(
        record,
        path,
        managed_root,
        component,
        cache_key,
        archive_identity,
    ):
        return record
    acquired_url = download_archive_if_needed(
        url,
        path,
        managed_root,
        component,
        cache_key,
        expected_sha=expected_sha,
        verify_digest_before_archive_list=verify_digest_before_archive_list,
        allow_httpd_source_recovery=allow_httpd_source_recovery,
    )
    if acquired_url is not None:
        record["download_url"] = acquired_url
        if acquired_url != url:
            record["source_recovery"] = "official_httpd_archive_after_direct_404"
    size = path.stat().st_size
    if size <= 0:
        return corrupt_archive_record(record, path, managed_root, "empty_archive")
    local_sha = sha256_file(path)
    record.update(size=size, sha256=local_sha)
    if verify_digest_before_archive_list and not archive_checksum_matches(record, expected_sha, local_sha):
        return corrupt_archive_record(record, path, managed_root, "sha256_mismatch")
    if not archive_can_list(path):
        return corrupt_archive_record(record, path, managed_root, "archive_list_failed")
    record["archive_list"] = "PASS"
    expected = expected_sha if verify_digest_before_archive_list else archive_expected_checksum(
        expected_sha,
        sha_url,
        archive_name,
        dest_dir,
        name,
    )
    if expected and not archive_checksum_matches(record, expected, local_sha):
        return corrupt_archive_record(record, path, managed_root, "sha256_mismatch")
    if managed_root is not None:
        write_cache_entry_completion(
            path,
            managed_root,
            component=component,
            cache_key=cache_key,
            cache_identity=archive_identity,
        )
    record["status"] = "present"
    return record


def archive_checksum_matches(record: dict[str, Any], expected_sha: str, actual_sha: str) -> bool:
    record["expected_sha256"] = expected_sha
    record["checksum_status"] = "PASS" if expected_sha == actual_sha else "FAIL"
    return expected_sha == actual_sha


def validate_httpd_source_recovery_policy(
    name: str,
    url: str,
    expected_sha: str,
    *,
    required_literal_sha256: bool,
    verify_digest_before_archive_list: bool,
) -> None:
    if name != "httpd" or not required_literal_sha256 or not verify_digest_before_archive_list:
        raise RuntimeError("httpd_source_recovery_policy_invalid")
    httpd_archive_recovery_url(url, expected_sha)


def prepare_archive(
    name: str,
    url: str,
    expected_sha: str,
    sha_url: str,
    dest_dir: Path,
    cache_root: Path | None = None,
    *,
    required_literal_sha256: bool = False,
    _lock_held: bool = False,
    cache_identity: dict[str, Any] | None = None,
    verify_digest_before_archive_list: bool = False,
    allow_httpd_source_recovery: bool = False,
) -> dict[str, Any]:
    archive_name = url.rstrip("/").split("/")[-1] if url else ""
    path = dest_dir / archive_name if archive_name else dest_dir / name
    record: dict[str, Any] = {
        "name": name,
        "url": url,
        "path": str(path),
        "status": "unknown",
        "blocker_reason": "",
        "checksum_status": "checksum_unavailable",
    }
    if not url:
        record.update(status="blocked", blocker_reason="missing_url")
        return record
    if is_system_path(dest_dir):
        record.update(status="blocked", blocker_reason="system_path_write_forbidden")
        return record
    try:
        if allow_httpd_source_recovery:
            validate_httpd_source_recovery_policy(
                name,
                url,
                expected_sha,
                required_literal_sha256=required_literal_sha256,
                verify_digest_before_archive_list=verify_digest_before_archive_list,
            )
        if required_literal_sha256:
            # A reviewed literal digest is required.  A digest URL is retained
            # as metadata but must not turn an absent override into a
            # cacheable/downloadable archive.
            expected_sha = require_literal_sha256(expected_sha, name)
        if cache_identity is None:
            archive_identity = archive_cache_identity(name, url, expected_sha, sha_url)
        else:
            archive_identity = dict(cache_identity)
            cache_key_value = archive_identity.pop("cache_key", None)
            if (
                archive_identity.get("component")
                not in {name, archive_cache_component(name)}
                or not isinstance(cache_key_value, str)
                or not cache_key_value
                or stable_hash(archive_identity) != cache_key_value
            ):
                raise RuntimeError("invalid_archive_cache_identity")
            archive_identity["cache_key"] = cache_key_value
        archive_cache_key = str(archive_identity["cache_key"])
        managed_root = archive_managed_root(dest_dir, cache_root)
        if managed_root is not None and not _lock_held:
            return prepare_archive_with_lock(
                record,
                name,
                url,
                expected_sha,
                sha_url,
                dest_dir,
                managed_root,
                required_literal_sha256,
                archive_cache_key,
                cache_identity=archive_identity,
                verify_digest_before_archive_list=verify_digest_before_archive_list,
                allow_httpd_source_recovery=allow_httpd_source_recovery,
            )
        return prepare_archive_unlocked(
            record,
            name,
            url,
            expected_sha,
            sha_url,
            archive_name,
            path,
            dest_dir,
            managed_root,
            archive_identity,
            verify_digest_before_archive_list=verify_digest_before_archive_list,
            allow_httpd_source_recovery=allow_httpd_source_recovery,
        )
    except Exception as exc:
        record.update(status="blocked", blocker_reason=str(exc))
        return record


def github_repo_path(url: str) -> str:
    raw = url.strip()
    parsed = urlsplit(raw)
    if parsed.scheme != "https":
        raise RuntimeError(f"only HTTPS GitHub URLs are supported: {url}")
    if parsed.netloc != "github.com":
        raise RuntimeError(f"only github.com URLs are supported: {url}")
    if parsed.query or parsed.fragment:
        raise RuntimeError(f"not a plain GitHub owner/repo URL: {url}")
    repo = parsed.path.removeprefix("/").removesuffix(".git").strip("/")
    parts = repo.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise RuntimeError(f"not a plain GitHub owner/repo URL: {url}")
    return f"{parts[0]}/{parts[1]}"


def nginx_archive_source_settings(env: dict[str, str]) -> tuple[str, str]:
    provenance = nginx_pinned_provenance(env)
    return provenance["repository"], provenance["release_tag"]


def latest_nginx_release_tag(repo: str, latest_cache_path: Path | None) -> tuple[str, str]:
    # Preserve the helper name for callers that imported it while making the
    # former mutable NGINX lookup path categorically non-executable.
    del repo, latest_cache_path
    raise RuntimeError("nginx_pinned_provenance_latest_forbidden")


def resolve_nginx_archive(env: dict[str, str], latest_cache_path: Path | None = None) -> tuple[str, str, str]:
    # The optional legacy cache argument remains only for call compatibility;
    # the pinned route never reads or writes a mutable release-lookup cache.
    del latest_cache_path
    provenance = nginx_pinned_provenance(env)
    return (
        provenance["release_tag"],
        provenance["release_asset_url"],
        "not_applicable_pinned_release_asset",
    )


def nginx_protocol_build_inputs(env: dict[str, str]) -> dict[str, Any]:
    """Resolve the bounded NGINX protocol build contract.

    H2/H3 runtime traffic is intentionally *not* inferred here: these inputs
    only select host build capabilities and the immutable cache boundary.  H3
    requires a pinned TLS source because an ambient system library is neither
    reproducible nor a safe substitute for the requested QUIC build.
    """
    profile = env.get("NGINX_PROTOCOL_PROFILE", "").strip() or "h1"
    if profile not in NGINX_PROTOCOL_PROFILES:
        raise RuntimeError(
            "unsupported NGINX_PROTOCOL_PROFILE="
            f"{profile}; expected one of {', '.join(NGINX_PROTOCOL_PROFILES)}"
        )

    if profile == "h1":
        return {
            "profile": profile,
            "http_ssl_enabled": False,
            "http2_enabled": False,
            "http3_enabled": False,
            "quic_enabled": False,
            "configure_flags": [],
            "tls_library": "not_used",
            "tls_version": "",
            "tls_source_url": "",
            "tls_source_sha256": "",
        }
    if profile == "h1-h2":
        return {
            "profile": profile,
            "http_ssl_enabled": True,
            "http2_enabled": True,
            "http3_enabled": False,
            "quic_enabled": False,
            "configure_flags": ["--with-http_ssl_module", "--with-http_v2_module"],
            "tls_library": "system",
            "tls_version": "",
            "tls_source_url": "",
            "tls_source_sha256": "",
        }

    library = env.get("NGINX_QUIC_TLS_LIBRARY", "").strip() or DEFAULT_NGINX_QUIC_TLS_LIBRARY
    version = env.get("NGINX_QUIC_TLS_VERSION", "").strip() or DEFAULT_NGINX_QUIC_TLS_VERSION
    source_url = env.get("NGINX_QUIC_TLS_SOURCE_URL", "").strip() or DEFAULT_NGINX_QUIC_TLS_SOURCE_URL
    source_sha256 = (
        env.get("NGINX_QUIC_TLS_SOURCE_SHA256", "").strip() or DEFAULT_NGINX_QUIC_TLS_SOURCE_SHA256
    )
    if library != "openssl":
        raise RuntimeError(
            "H3 profile requires the pinned OpenSSL QUIC/TLS source; "
            f"unsupported NGINX_QUIC_TLS_LIBRARY={library}"
        )
    if not version:
        raise RuntimeError("H3 profile requires NGINX_QUIC_TLS_VERSION")
    require_https_url(source_url, "NGINX_QUIC_TLS_SOURCE_URL")
    if not re.fullmatch(r"[0-9A-Fa-f]{64}", source_sha256):
        raise RuntimeError("NGINX_QUIC_TLS_SOURCE_SHA256 must be a pinned SHA-256 value")
    return {
        "profile": profile,
        "http_ssl_enabled": True,
        "http2_enabled": True,
        "http3_enabled": True,
        "quic_enabled": True,
        "configure_flags": [
            "--with-http_ssl_module",
            "--with-http_v2_module",
            "--with-http_v3_module",
        ],
        "tls_library": library,
        "tls_version": version,
        "tls_source_url": source_url,
        "tls_source_sha256": source_sha256.lower(),
    }


def default_state_home() -> Path:
    from modsecurity_connector_ci.lib.runtime_path_utils import verified_runtime_paths

    return Path(verified_runtime_paths(os.environ)["VERIFIED_STATE_ROOT"])


def executable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def resolve_executable(configured: str) -> str | None:
    if not configured:
        return None
    if "/" in configured:
        path = Path(configured)
        return str(path) if executable(path) else None
    return shutil.which(configured)


def read_key_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def artifact_status(paths: dict[str, Path], executable_keys: set[str] | None = None) -> tuple[bool, list[str]]:
    executable_keys = executable_keys or set()
    missing = []
    for key, path in paths.items():
        if key in executable_keys:
            if not executable(path):
                missing.append(f"{key}:{path}")
        elif not path.is_file():
            missing.append(f"{key}:{path}")
    return not missing, missing


def build_env(base: dict[str, str], **overrides: str) -> dict[str, str]:
    result = dict(base)
    for key, value in overrides.items():
        if value is not None:
            result[key] = value
    return result


def command_text(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    proc = run_env(cmd, cwd=cwd, env=env)
    text = (proc.stdout + proc.stderr).strip()
    return text if proc.returncode == 0 else f"unavailable rc={proc.returncode}: {text}"


def compiler_identity(env: dict[str, str]) -> dict[str, str]:
    cc = resolve_compiler(env)
    cxx_configured = env.get("CXX", "").strip()
    cxx = cxx_configured.split()[0] if cxx_configured and shutil.which(cxx_configured.split()[0]) else (shutil.which("c++") or shutil.which("g++") or "")
    return {
        "cc": cc,
        "cc_version": command_text([cc, "--version"], env=env).splitlines()[0] if cc else "",
        "cxx": cxx,
        "cxx_version": command_text([cxx, "--version"], env=env).splitlines()[0] if cxx else "",
    }


def toolchain_identity(env: dict[str, str]) -> dict[str, Any]:
    """Capture compiler, linker, and build-tool versions that affect artifacts."""
    identity: dict[str, Any] = dict(compiler_identity(env))
    linker_configured = env.get("LD", "").strip().split()
    linker = linker_configured[0] if linker_configured and shutil.which(linker_configured[0]) else (shutil.which("ld") or "")
    identity["linker"] = linker
    identity["linker_version"] = command_text([linker, "--version"], env=env).splitlines()[0] if linker else ""
    build_tools: dict[str, str] = {}
    for tool in ("make", "cmake", "autoconf", "meson", "ninja"):
        resolved = shutil.which(tool)
        build_tools[tool] = command_text([resolved, "--version"], env=env).splitlines()[0] if resolved else ""
    identity["build_tools"] = build_tools
    return identity


def hash_file_contents(path: Path, digest: Any) -> None:
    try:
        rel = path.as_posix()
        data = path.read_bytes()
    except OSError:
        return
    digest.update(rel.encode("utf-8", "surrogateescape"))
    digest.update(b"\0")
    digest.update(hashlib.sha256(data).hexdigest().encode("ascii"))
    digest.update(b"\0")


def hash_missing_input_root(root: Path, digest: Any) -> None:
    digest.update(f"missing:{root}".encode("utf-8", "surrogateescape"))
    digest.update(b"\0")


def skip_input_hash_path(item: Path) -> bool:
    if ".git" in item.parts:
        return True
    if "__pycache__" in item.parts:
        return True
    if not item.is_file():
        return True
    return item.suffix in {".o", ".so", ".a", ".la", ".lo", ".log"}


def hash_directory_input_file(root: Path, item: Path, digest: Any) -> None:
    try:
        relative_path = item.relative_to(root)
    except ValueError:
        relative_path = item
    digest.update(
        f"{root.as_posix()}:{relative_path.as_posix()}".encode("utf-8", "surrogateescape")
    )
    digest.update(hashlib.sha256(item.read_bytes()).hexdigest().encode("ascii"))
    digest.update(b"\0")


def hash_directory_input_paths(root: Path, digest: Any) -> None:
    for item in sorted(root.rglob("*")):
        if skip_input_hash_path(item):
            continue
        hash_directory_input_file(root, item, digest)


def hash_input_paths(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for root in paths:
        if not root.exists():
            hash_missing_input_root(root, digest)
            continue
        if root.is_file():
            hash_file_contents(root, digest)
            continue
        hash_directory_input_paths(root, digest)
    return digest.hexdigest()


def read_text_if_file(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def run_build(script: Path, env: dict[str, str], cwd: Path, log_path: Path) -> subprocess.CompletedProcess[str]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["sh", str(script)],
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    log_path.write_text(proc.stdout, encoding="utf-8", errors="replace")
    return proc


def append_command_log(log_parts: list[str], label: str, proc: subprocess.CompletedProcess[str]) -> None:
    log_parts.extend(
        [
            f"[{label}]",
            f"returncode={proc.returncode}",
            "$ " + " ".join(sh_quote(str(part)) for part in proc.args) if isinstance(proc.args, list) else f"$ {proc.args}",
            "",
            proc.stdout,
            proc.stderr,
            "",
        ]
    )


def write_component_log(log_path: Path, log_parts: list[str]) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("\n".join(log_parts), encoding="utf-8", errors="replace")


def local_build_env(base: dict[str, str], cache_root: Path) -> dict[str, str]:
    result = dict(base)
    result["GOPATH"] = str(cache_root / "go")
    result["GOMODCACHE"] = str(cache_root / "go/pkg/mod")
    result["GOCACHE"] = str(cache_root / "go/cache")
    result["XDG_CACHE_HOME"] = str(cache_root / "go/xdg-cache")
    return result


def resolve_compiler(env: dict[str, str]) -> str:
    configured = env.get("CC", "").strip()
    if configured:
        return configured.split()[0] if shutil.which(configured.split()[0]) else ""
    return shutil.which("cc") or shutil.which("gcc") or ""


def first_missing_tool(tools: list[tuple[str, str]]) -> str:
    for tool, reason in tools:
        if not shutil.which(tool):
            return reason
    return ""


def expat_libs(lib_dir: Path) -> list[Path]:
    if not lib_dir.is_dir():
        return []
    return sorted(path for path in lib_dir.glob("libexpat.*") if path.is_file() or path.is_symlink())


def expat_artifacts_ready(prefix: Path) -> bool:
    return (prefix / EXPAT_HEADER_RELATIVE_PATH).is_file() and bool(expat_libs(prefix / "lib"))


def expat_source_dir(repo_path: Path) -> Path:
    for candidate in (repo_path / "expat", repo_path):
        if (
            (candidate / EXPAT_BUILDCONF_FILENAME).is_file()
            or (candidate / "configure").is_file()
            or (candidate / "configure.ac").is_file()
            or (candidate / "CMakeLists.txt").is_file()
        ):
            return candidate
    return repo_path


def make_command_is_missing(text: str) -> bool:
    """Match the original same-line, post-command ``make`` diagnostic."""
    for line in text.splitlines():
        for match in re.finditer(r"\bmake\b", line):
            suffix = line[match.end() :]
            if MISSING_COMMAND_TEXT in suffix or MISSING_FILE_TEXT in suffix:
                return True
    return False


def map_expat_build_failure(text: str) -> str:
    lowered = text.lower()
    if "cmake" in lowered and MISSING_COMMAND_TEXT in lowered:
        return "missing_cmake"
    if "autoconf" in lowered and (MISSING_COMMAND_TEXT in lowered or MISSING_FILE_TEXT in lowered):
        return "missing_autoconf"
    if "automake" in lowered or "aclocal" in lowered:
        return "missing_automake"
    if "libtoolize" in lowered or "glibtoolize" in lowered or "libtool" in lowered:
        return "missing_libtool"
    if make_command_is_missing(lowered):
        return "missing_make"
    if "c compiler" in lowered or "compiler" in lowered and MISSING_COMMAND_TEXT in lowered:
        return "missing_compiler"
    return "expat_build_failed"


def expat_override_entries_complete(
    prefix: Path,
    build_dir: Path,
    source_copy: Path,
    cache_root: Path,
    cache_identity: dict[str, Any],
) -> bool:
    """A managed override is reusable only when every published entry completed."""
    cache_key = str(cache_identity["cache_key"])
    return (
        expat_artifacts_ready(prefix)
        and cache_manifest_complete(prefix / COMPONENT_MANIFEST_FILENAME, cache_identity)
        and build_dir.is_dir()
        and source_copy.is_dir()
        and cache_entry_complete(
            prefix,
            cache_root,
            component="expat-prefix",
            cache_key=cache_key,
            cache_identity=cache_identity,
        )
        and cache_entry_complete(
            build_dir,
            cache_root,
            component="expat-build",
            cache_key=cache_key,
            cache_identity=cache_identity,
        )
        and cache_entry_complete(
            source_copy,
            cache_root,
            component="expat-source",
            cache_key=cache_key,
            cache_identity=cache_identity,
        )
    )


def expat_override_final_entries(
    prefix: Path,
    build_dir: Path,
    source_copy: Path,
) -> tuple[tuple[str, Path], ...]:
    return (
        ("expat-prefix", prefix),
        ("expat-build", build_dir),
        ("expat-source", source_copy),
    )


def resolved_expat_override_entries(
    prefix: Path,
    build_dir: Path,
    source_copy: Path,
    cache_root: Path,
) -> tuple[tuple[str, Path], ...]:
    final_entries = expat_override_final_entries(prefix, build_dir, source_copy)
    resolved_entries = tuple(
        (component, validate_managed_cache_child(path, cache_root)[0])
        for component, path in final_entries
    )
    for index, (_, first) in enumerate(resolved_entries):
        for _, second in resolved_entries[index + 1 :]:
            if paths_overlap(first, second):
                raise RuntimeError("expat_override_paths_overlap")
    return resolved_entries


def update_expat_override_record_paths(
    record: dict[str, Any],
    prefix: Path,
    build_dir: Path,
    source_copy: Path,
) -> None:
    record.update(
        prefix=str(prefix),
        expat_h=str(prefix / EXPAT_HEADER_RELATIVE_PATH),
        include=str(prefix / EXPAT_HEADER_RELATIVE_PATH),
        lib_dir=str(prefix / "lib"),
        library=str(prefix / "lib"),
        build_path=str(build_dir),
        build_source_copy=str(source_copy),
        manifest=str(prefix / COMPONENT_MANIFEST_FILENAME),
    )


def expat_override_present_record(
    record: dict[str, Any],
    prefix: Path,
    build_dir: Path,
    source_copy: Path,
) -> dict[str, Any]:
    previous = read_json(prefix / COMPONENT_MANIFEST_FILENAME)
    update_expat_override_record_paths(record, prefix, build_dir, source_copy)
    record.update(
        status="present",
        libraries=[str(path) for path in expat_libs(prefix / "lib")],
        build_system=previous.get("build_system", ""),
        tree=tree_manifest(prefix),
    )
    return record


def expat_override_entries_rebuildable(
    entries: tuple[tuple[str, Path], ...],
    cache_root: Path,
    record: dict[str, Any],
) -> str:
    for component, final_path in entries:
        if not final_path.exists():
            continue
        if not managed_cache_entry_valid(final_path, cache_root):
            if not migrate_legacy_cache_entry_for_removal(final_path, cache_root, component=component):
                return unmanaged_cache_entry_marker_missing(final_path)
        record.update(
            rebuild_required=True,
            invalidation_reason="missing_or_incomplete_expat_override_cache",
            old_entry_removed=True,
        )
    return ""


def create_expat_override_staging_entries(
    entries: tuple[tuple[str, Path], ...],
    cache_root: Path,
    cache_key: str,
) -> dict[str, Path | None]:
    return {
        component: temporary_cache_dir(
            final_path,
            cache_root,
            component=component,
            cache_key=cache_key,
        )
        for component, final_path in entries
    }


def staged_expat_override_environment(
    env: dict[str, str],
    staging_entries: dict[str, Path | None],
) -> dict[str, str]:
    staged_env = dict(env)
    staged_env.update(
        EXPAT_PREFIX=str(require_staging_path(staging_entries["expat-prefix"])),
        EXPAT_BUILD_DIR=str(require_staging_path(staging_entries["expat-build"])),
        EXPAT_SOURCE_COPY=str(require_staging_path(staging_entries["expat-source"])),
    )
    return staged_env


def complete_expat_override_staging_entries(
    staging_entries: dict[str, Path | None],
    cache_root: Path,
    cache_key: str,
    cache_identity: dict[str, Any],
) -> None:
    for component, staging_path in staging_entries.items():
        write_cache_entry_completion(
            require_staging_path(staging_path),
            cache_root,
            component=component,
            cache_key=cache_key,
            cache_identity=cache_identity,
        )


def replace_expat_override_entries(
    entries: tuple[tuple[str, Path], ...],
    staging_entries: dict[str, Path | None],
    cache_root: Path,
) -> None:
    for _, final_path in entries:
        if final_path.exists():
            safe_remove_dir(final_path, cache_root)
    for component, final_path in entries:
        staging_path = require_staging_path(staging_entries[component])
        atomic_publish_dir(staging_path, final_path, cache_root, require_complete=True)
        staging_entries[component] = None


def expat_override_failed_record(
    staged_record: dict[str, Any],
    prefix: Path,
    build_dir: Path,
    source_copy: Path,
) -> dict[str, Any]:
    failed_record = dict(staged_record)
    update_expat_override_record_paths(failed_record, prefix, build_dir, source_copy)
    return failed_record


def expat_override_published_record(
    staged_record: dict[str, Any],
    prefix: Path,
    build_dir: Path,
    source_copy: Path,
) -> dict[str, Any]:
    published_record = dict(staged_record)
    update_expat_override_record_paths(published_record, prefix, build_dir, source_copy)
    published_record.update(status="built", tree=tree_manifest(prefix))
    write_cache_manifest(prefix / COMPONENT_MANIFEST_FILENAME, published_record)
    return published_record


def cleanup_expat_staging_entries(staging_entries: dict[str, Path | None], cache_root: Path) -> None:
    for staging_path in staging_entries.values():
        if staging_path is None or not staging_path.exists():
            continue
        try:
            safe_remove_dir(staging_path, cache_root)
        except RuntimeError:
            pass


def prepare_expat_managed_overrides(
    env: dict[str, str],
    cache_root: Path,
    build_root: Path,
    git_record: dict[str, Any],
    record: dict[str, Any],
    *,
    prefix: Path,
    build_dir: Path,
    source_copy: Path,
    cache_identity: dict[str, Any],
) -> dict[str, Any]:
    """Publish explicit, managed Expat paths from isolated staging entries.

    Historical EXPAT_PREFIX/EXPAT_BUILD_DIR support wrote directly into the
    supplied directories.  Keep the override feature only for cache-managed
    paths, and publish each independently owned path from a completed staging
    entry.  This makes an interrupted override build non-reusable and keeps
    external/unowned directories out of the cache mutation path.
    """
    try:
        resolved_entries = resolved_expat_override_entries(prefix, build_dir, source_copy, cache_root)
    except RuntimeError as exc:
        record.update(status="blocked", blocker_reason=str(exc))
        return record

    cache_key = str(cache_identity["cache_key"])
    staging_entries: dict[str, Path | None] = {}
    try:
        with BuildLock(cache_entry_lock_path(cache_root, "expat", cache_key)):
            if expat_override_entries_complete(prefix, build_dir, source_copy, cache_root, cache_identity):
                return expat_override_present_record(record, prefix, build_dir, source_copy)
            blocker = expat_override_entries_rebuildable(resolved_entries, cache_root, record)
            if blocker:
                record.update(status="blocked", blocker_reason=blocker)
                return record
            staging_entries = create_expat_override_staging_entries(resolved_entries, cache_root, cache_key)
            staged_env = staged_expat_override_environment(env, staging_entries)
            staged_record = prepare_expat(staged_env, cache_root, build_root, git_record, _transactional=True)
            if staged_record.get("status") != "built":
                return expat_override_failed_record(staged_record, prefix, build_dir, source_copy)
            complete_expat_override_staging_entries(staging_entries, cache_root, cache_key, cache_identity)
            # Validate/build before removing an old final entry; a failed
            # staging build therefore leaves a known-good prior cache intact.
            replace_expat_override_entries(resolved_entries, staging_entries, cache_root)
            return expat_override_published_record(staged_record, prefix, build_dir, source_copy)
    except TimeoutError as exc:
        record.update(status="blocked", blocker_reason="cache_lock_timeout", details=str(exc))
        return record
    except RuntimeError as exc:
        record.update(status="blocked", blocker_reason=str(exc))
        return record
    finally:
        cleanup_expat_staging_entries(staging_entries, cache_root)


def prepare_expat(
    env: dict[str, str],
    cache_root: Path,
    build_root: Path,
    git_record: dict[str, Any],
    _transactional: bool = False,
) -> dict[str, Any]:
    try:
        cache_root = ensure_managed_cache_root(cache_root)
    except RuntimeError as exc:
        return {"name": "expat", "status": "blocked", "blocker_reason": str(exc)}
    prefix = Path(env.get("EXPAT_PREFIX", str(cache_root / "prefix/expat"))).resolve()
    build_dir = Path(env.get("EXPAT_BUILD_DIR", str(cache_root / "build/expat"))).resolve()
    build_source_copy = Path(env.get("EXPAT_SOURCE_COPY", str(cache_root / "build/expat-source"))).resolve()
    expat_h = prefix / EXPAT_HEADER_RELATIVE_PATH
    lib_dir = prefix / "lib"
    log_path = build_root / "logs/runtime-components/expat-build.log"
    marker_path = prefix / COMPONENT_MANIFEST_FILENAME
    source_path = Path(git_record.get("path", "")).resolve() if git_record.get("path") else Path()
    expat_source = git_record.get("source") or git_record.get("url") or env.get("EXPAT_SOURCE_URL", "")
    record: dict[str, Any] = {
        "name": "expat",
        "source": expat_source,
        "url": git_record.get("url") or git_record.get("source") or expat_source,
        "expected_ref": git_record.get("expected_ref", ""),
        "release_tag": git_record.get("release_tag", git_record.get("expected_ref", "")),
        "actual_head": git_record.get("actual_head", ""),
        "recursive_submodules": True,
        "recursive_submodule_status": git_record.get("submodule_status", ""),
        "submodule_status_clean": git_record.get("submodule_status_clean", False),
        "git_fsck": git_record.get("git_fsck", ""),
        "path": str(source_path) if str(source_path) != "." else "",
        "prefix": str(prefix),
        "expat_h": str(expat_h),
        "include": str(expat_h),
        "lib_dir": str(lib_dir),
        "library": str(lib_dir),
        "build_path": str(build_dir),
        "build_source_copy": str(build_source_copy),
        "build_log": str(log_path),
        "status": "unknown",
        "blocker_reason": "",
    }
    build_flags = {
        key: env.get(key, "")
        for key in ("CC", "CXX", "CPPFLAGS", "CFLAGS", "CXXFLAGS", "LDFLAGS", "LIBS")
    }
    toolchain = toolchain_identity(env)
    cache_identity = canonical_cache_identity(
        "expat",
        env=env,
        upstream_url=str(record["url"]),
        upstream_version=str(record["release_tag"]),
        upstream_commit=str(record["actual_head"]),
        source_sha256=str(record["actual_head"]),
        patchset_sha256=patchset_identity([])["sha256"],
        configuration_flags=build_flags,
        toolchain=toolchain,
    )
    build_inputs = {
        "actual_head": record["actual_head"],
        "compiler": toolchain,
        "build_flags": build_flags,
        "cache_identity": cache_identity,
    }
    record["cache_schema_version"] = CACHE_SCHEMA_VERSION
    record["cache_identity"] = cache_identity
    record["cache_key"] = cache_identity["cache_key"]
    record["build_id"] = cache_identity["cache_key"]
    record["build_inputs"] = build_inputs
    if git_record.get("status") != "present":
        record.update(status="blocked", blocker_reason=git_record.get("blocker_reason") or "expat_source_unavailable")
        return record
    if is_system_path(prefix) or is_system_path(build_dir) or is_system_path(build_source_copy):
        record.update(status="blocked", blocker_reason="system_path_write_forbidden")
        return record
    if not is_within(prefix, cache_root) or not is_within(build_dir, cache_root) or not is_within(build_source_copy, cache_root):
        record.update(status="blocked", blocker_reason="expat_paths_must_be_under_connector_component_cache")
        return record
    explicit_override = any(env.get(key) for key in ("EXPAT_PREFIX", "EXPAT_BUILD_DIR", "EXPAT_SOURCE_COPY"))
    if not _transactional and explicit_override:
        return prepare_expat_managed_overrides(
            env,
            cache_root,
            build_root,
            git_record,
            record,
            prefix=prefix,
            build_dir=build_dir,
            source_copy=build_source_copy,
            cache_identity=cache_identity,
        )
    if not _transactional:
        return prepare_default_expat_cache_entry(
            env,
            cache_root,
            build_root,
            git_record,
            record,
            cache_identity,
        )
    return prepare_expat_transactional_build(
        env,
        cache_root,
        build_root,
        source_path,
        record,
        cache_identity,
        prefix,
        build_dir,
        build_source_copy,
        marker_path,
    )


def expat_default_cache_paths(cache_root: Path, cache_key: str) -> dict[str, Path]:
    entry_root = (cache_root / "builds/expat" / cache_key).resolve()
    return {
        "entry_root": entry_root,
        "prefix": entry_root / "prefix",
        "build_dir": entry_root / "build",
        "source_copy": entry_root / "source",
        "manifest": entry_root / CACHE_MANIFEST_FILENAME,
    }


def update_expat_default_cache_record_paths(record: dict[str, Any], paths: dict[str, Path]) -> None:
    prefix = paths["prefix"]
    record.update(
        prefix=str(prefix),
        expat_h=str(prefix / EXPAT_HEADER_RELATIVE_PATH),
        include=str(prefix / EXPAT_HEADER_RELATIVE_PATH),
        lib_dir=str(prefix / "lib"),
        library=str(prefix / "lib"),
        build_path=str(paths["build_dir"]),
        build_source_copy=str(paths["source_copy"]),
        manifest=str(paths["manifest"]),
    )


def expat_default_cache_is_ready(
    paths: dict[str, Path],
    cache_root: Path,
    cache_identity: dict[str, Any],
) -> bool:
    return (
        expat_artifacts_ready(paths["prefix"])
        and cache_manifest_complete(paths["manifest"], cache_identity)
        and cache_entry_complete(
            paths["entry_root"],
            cache_root,
            component="expat",
            cache_key=str(cache_identity["cache_key"]),
            cache_identity=cache_identity,
        )
    )


def expat_default_cache_hit_record(
    record: dict[str, Any],
    paths: dict[str, Path],
) -> dict[str, Any]:
    previous = read_json(paths["manifest"])
    record.update(
        status="present",
        libraries=[str(path) for path in expat_libs(paths["prefix"] / "lib")],
        build_system=previous.get("build_system", ""),
        tree=tree_manifest(paths["prefix"]),
    )
    return record


def discard_incomplete_expat_default_cache_entry(
    record: dict[str, Any],
    entry_root: Path,
    cache_root: Path,
) -> bool:
    if not entry_root.exists():
        return True
    if not managed_cache_entry_valid(entry_root, cache_root):
        if not migrate_legacy_cache_entry_for_removal(entry_root, cache_root, component="expat"):
            record.update(status="blocked", blocker_reason=unmanaged_cache_entry_marker_missing(entry_root))
            return False
    safe_remove_dir(entry_root, cache_root)
    record.update(
        rebuild_required=True,
        invalidation_reason="missing_or_incomplete_expat_cache",
        old_entry_removed=True,
    )
    return True


def cleanup_expat_staging_root(staging_root: Path | None, cache_root: Path) -> None:
    if staging_root is None or not staging_root.exists():
        return
    try:
        safe_remove_dir(staging_root, cache_root)
    except RuntimeError:
        pass


def build_and_publish_default_expat_cache_entry(
    env: dict[str, str],
    cache_root: Path,
    build_root: Path,
    git_record: dict[str, Any],
    cache_identity: dict[str, Any],
    paths: dict[str, Path],
) -> dict[str, Any]:
    staging_root: Path | None = None
    try:
        staging_root = temporary_cache_dir(
            paths["entry_root"],
            cache_root,
            component="expat",
            cache_key=str(cache_identity["cache_key"]),
        )
        staged_env = dict(env)
        staged_env.update(
            EXPAT_PREFIX=str(staging_root / "prefix"),
            EXPAT_BUILD_DIR=str(staging_root / "build"),
            EXPAT_SOURCE_COPY=str(staging_root / "source"),
        )
        staged_record = prepare_expat(staged_env, cache_root, build_root, git_record, _transactional=True)
        if staged_record.get("status") != "built":
            return rebase_cache_record(staged_record, staging_root, paths["entry_root"])
        published_record = rebase_cache_record(staged_record, staging_root, paths["entry_root"])
        update_expat_default_cache_record_paths(published_record, paths)
        published_record["tree"] = tree_manifest(staging_root / "prefix")
        write_cache_manifest(staging_root / CACHE_MANIFEST_FILENAME, published_record)
        write_cache_entry_completion(
            staging_root,
            cache_root,
            component="expat",
            cache_key=str(cache_identity["cache_key"]),
            cache_identity=cache_identity,
        )
        for child in (staging_root / "build", staging_root / "source", staging_root / "prefix"):
            remove_managed_cache_entry_marker(child, cache_root)
        atomic_publish_dir(staging_root, paths["entry_root"], cache_root, require_complete=True)
        staging_root = None
        published_record["tree"] = tree_manifest(paths["prefix"])
        write_cache_manifest(paths["manifest"], published_record)
        return published_record
    finally:
        cleanup_expat_staging_root(staging_root, cache_root)


def prepare_default_expat_cache_entry(
    env: dict[str, str],
    cache_root: Path,
    build_root: Path,
    git_record: dict[str, Any],
    record: dict[str, Any],
    cache_identity: dict[str, Any],
) -> dict[str, Any]:
    paths = expat_default_cache_paths(cache_root, str(cache_identity["cache_key"]))
    update_expat_default_cache_record_paths(record, paths)
    try:
        with BuildLock(cache_entry_lock_path(cache_root, "expat", str(cache_identity["cache_key"]))):
            if expat_default_cache_is_ready(paths, cache_root, cache_identity):
                return expat_default_cache_hit_record(record, paths)
            if not discard_incomplete_expat_default_cache_entry(record, paths["entry_root"], cache_root):
                return record
            return build_and_publish_default_expat_cache_entry(
                env,
                cache_root,
                build_root,
                git_record,
                cache_identity,
                paths,
            )
    except TimeoutError as exc:
        record.update(status="blocked", blocker_reason="cache_lock_timeout", details=str(exc))
        return record


def expat_transactional_cache_is_ready(
    prefix: Path,
    marker_path: Path,
    cache_root: Path,
    cache_identity: dict[str, Any],
) -> bool:
    return (
        expat_artifacts_ready(prefix)
        and cache_manifest_complete(marker_path, cache_identity)
        and cache_entry_complete(
            prefix,
            cache_root,
            component="expat-prefix",
            cache_key=str(cache_identity["cache_key"]),
            cache_identity=cache_identity,
        )
    )


def expat_transactional_cache_hit_record(
    record: dict[str, Any],
    prefix: Path,
    lib_dir: Path,
    marker_path: Path,
) -> dict[str, Any]:
    previous = read_json(marker_path)
    record.update(
        status="present",
        libraries=[str(path) for path in expat_libs(lib_dir)],
        build_system=previous.get("build_system", ""),
        tree=tree_manifest(prefix),
    )
    return record


def expat_build_selection(env: dict[str, str], source_path: Path) -> dict[str, Any]:
    missing = first_missing_tool([("make", "missing_make")])
    compiler = resolve_compiler(env)
    if not compiler:
        missing = "missing_compiler"
    if missing:
        return {"blocker": missing}
    git_source_dir = expat_source_dir(source_path)
    has_autotools = any(
        (git_source_dir / filename).is_file()
        for filename in (EXPAT_BUILDCONF_FILENAME, "configure", "configure.ac")
    )
    if has_autotools:
        if not (git_source_dir / "configure").is_file():
            missing = first_missing_tool(
                [
                    ("autoconf", "missing_autoconf"),
                    ("automake", "missing_automake"),
                    ("aclocal", "missing_automake"),
                    ("libtoolize", "missing_libtool"),
                ]
            )
            if missing:
                return {"blocker": missing}
        return {"build_system": "autotools", "compiler": compiler, "source_dir": git_source_dir}
    if (git_source_dir / "CMakeLists.txt").is_file():
        if not shutil.which("cmake"):
            return {"blocker": "missing_cmake"}
        return {"build_system": "cmake", "compiler": compiler, "source_dir": git_source_dir}
    return {"blocker": "missing_expat_build_system"}


def expat_build_environment(
    env: dict[str, str],
    compiler: str,
    prefix: Path,
) -> dict[str, str]:
    build_env_vars = dict(os.environ)
    build_env_vars.update(env)
    build_env_vars["CC"] = env.get("CC", compiler)
    build_env_vars["PKG_CONFIG_PATH"] = (
        f"{prefix / 'lib/pkgconfig'}{os.pathsep}{env.get('PKG_CONFIG_PATH', '')}".rstrip(os.pathsep)
    )
    return build_env_vars


def expat_build_cache_paths(
    build_dir: Path,
    source_copy: Path,
    prefix: Path,
) -> tuple[tuple[str, Path], ...]:
    return (
        ("expat-build", build_dir),
        ("expat-source", source_copy),
        ("expat-prefix", prefix),
    )


def prepare_expat_transactional_cache_paths(
    cache_root: Path,
    cache_key: str,
    build_dir: Path,
    source_copy: Path,
    prefix: Path,
    git_source_dir: Path,
) -> str:
    cache_paths = expat_build_cache_paths(build_dir, source_copy, prefix)
    for label, cache_path in cache_paths:
        if cache_path.exists() and not managed_cache_entry_valid(cache_path, cache_root):
            if not migrate_legacy_cache_entry_for_removal(cache_path, cache_root, component=label):
                return unmanaged_cache_entry_marker_missing(cache_path)
    for _, cache_path in cache_paths:
        safe_remove_dir(cache_path, cache_root)
    for label, cache_path in cache_paths:
        mark_managed_cache_entry(cache_path, cache_root, component=label, cache_key=cache_key)
    shutil.copytree(
        git_source_dir,
        source_copy,
        ignore=shutil.ignore_patterns(".git", ".github", "autom4te.cache", "__pycache__"),
    )
    mark_managed_cache_entry(source_copy, cache_root, component="expat-source", cache_key=cache_key)
    build_dir.mkdir(parents=True, exist_ok=True)
    mark_managed_cache_entry(build_dir, cache_root, component="expat-build", cache_key=cache_key)
    prefix.mkdir(parents=True, exist_ok=True)
    mark_managed_cache_entry(prefix, cache_root, component="expat-prefix", cache_key=cache_key)
    return ""


def run_expat_build_step(
    label: str,
    command: list[str],
    *,
    cwd: Path | None,
    env: dict[str, str],
    log_parts: list[str],
    log_path: Path,
    record: dict[str, Any],
) -> bool:
    proc = run_env(command, cwd=cwd, env=env)
    append_command_log(log_parts, label, proc)
    if proc.returncode == 0:
        return True
    write_component_log(log_path, log_parts)
    record.update(
        status="failed",
        blocker_reason=map_expat_build_failure(proc.stdout + proc.stderr),
        build_exit_code=proc.returncode,
    )
    return False


def runtime_make_jobs(env: dict[str, str]) -> str:
    return env.get("MAKE_JOBS") or str(os.cpu_count() or 2)


def run_expat_autotools_build(
    source_dir: Path,
    build_dir: Path,
    prefix: Path,
    env: dict[str, str],
    log_parts: list[str],
    log_path: Path,
    record: dict[str, Any],
) -> bool:
    if (source_dir / EXPAT_BUILDCONF_FILENAME).is_file():
        if not run_expat_build_step(
            "expat-buildconf",
            ["sh", str(source_dir / EXPAT_BUILDCONF_FILENAME)],
            cwd=source_dir,
            env=env,
            log_parts=log_parts,
            log_path=log_path,
            record=record,
        ):
            return False
    elif not (source_dir / "configure").is_file() and not run_expat_build_step(
            "expat-autoreconf",
            ["autoreconf", "-fi"],
            cwd=source_dir,
            env=env,
            log_parts=log_parts,
            log_path=log_path,
            record=record,
        ):
        return False
    if not run_expat_build_step(
        "expat-configure",
        [str(source_dir / "configure"), f"--prefix={prefix}"],
        cwd=build_dir,
        env=env,
        log_parts=log_parts,
        log_path=log_path,
        record=record,
    ):
        return False
    for label, command in (
        ("expat-make", ["make", f"-j{runtime_make_jobs(env)}"]),
        ("expat-make-install", ["make", "install"]),
    ):
        if not run_expat_build_step(
            label,
            command,
            cwd=build_dir,
            env=env,
            log_parts=log_parts,
            log_path=log_path,
            record=record,
        ):
            return False
    return True


def run_expat_cmake_build(
    source_dir: Path,
    build_dir: Path,
    prefix: Path,
    env: dict[str, str],
    log_parts: list[str],
    log_path: Path,
    record: dict[str, Any],
) -> bool:
    if not run_expat_build_step(
        "expat-cmake-configure",
        [
            "cmake",
            "-S",
            str(source_dir),
            "-B",
            str(build_dir),
            f"-DCMAKE_INSTALL_PREFIX={prefix}",
            "-DEXPAT_BUILD_TESTS=OFF",
            "-DEXPAT_BUILD_EXAMPLES=OFF",
            "-DEXPAT_BUILD_TOOLS=OFF",
        ],
        cwd=None,
        env=env,
        log_parts=log_parts,
        log_path=log_path,
        record=record,
    ):
        return False
    for label, command in (
        ("expat-cmake-build", ["cmake", "--build", str(build_dir), "--parallel", runtime_make_jobs(env)]),
        ("expat-cmake-install", ["cmake", "--install", str(build_dir)]),
    ):
        if not run_expat_build_step(
            label,
            command,
            cwd=None,
            env=env,
            log_parts=log_parts,
            log_path=log_path,
            record=record,
        ):
            return False
    return True


def run_selected_expat_build(
    build_system: str,
    source_dir: Path,
    build_dir: Path,
    prefix: Path,
    env: dict[str, str],
    log_parts: list[str],
    log_path: Path,
    record: dict[str, Any],
) -> bool:
    if build_system == "autotools":
        return run_expat_autotools_build(source_dir, build_dir, prefix, env, log_parts, log_path, record)
    return run_expat_cmake_build(source_dir, build_dir, prefix, env, log_parts, log_path, record)


def prepare_expat_transactional_build(
    env: dict[str, str],
    cache_root: Path,
    build_root: Path,
    source_path: Path,
    record: dict[str, Any],
    cache_identity: dict[str, Any],
    prefix: Path,
    build_dir: Path,
    source_copy: Path,
    marker_path: Path,
) -> dict[str, Any]:
    lib_dir = prefix / "lib"
    if expat_transactional_cache_is_ready(prefix, marker_path, cache_root, cache_identity):
        return expat_transactional_cache_hit_record(record, prefix, lib_dir, marker_path)
    selection = expat_build_selection(env, source_path)
    blocker = str(selection.get("blocker", ""))
    if blocker:
        record.update(status="blocked", blocker_reason=blocker)
        return record
    log_path = build_root / "logs/runtime-components/expat-build.log"
    log_parts: list[str] = []
    try:
        source_dir = Path(selection["source_dir"])
        record["git_source_dir"] = str(source_dir)
        cache_error = prepare_expat_transactional_cache_paths(
            cache_root,
            str(record["cache_key"]),
            build_dir,
            source_copy,
            prefix,
            source_dir,
        )
        if cache_error:
            record.update(status="blocked", blocker_reason=cache_error)
            return record
        record["build_source_dir"] = str(source_copy)
        build_environment = expat_build_environment(env, str(selection["compiler"]), prefix)
        if not run_selected_expat_build(
            str(selection["build_system"]),
            source_copy,
            build_dir,
            prefix,
            build_environment,
            log_parts,
            log_path,
            record,
        ):
            return record
        write_component_log(log_path, log_parts)
    except Exception as exc:
        write_component_log(log_path, log_parts + [str(exc)])
        record.update(status="failed", blocker_reason=str(exc), build_exit_code=1)
        return record
    if not expat_artifacts_ready(prefix):
        record.update(status="failed", blocker_reason="expat_artifacts_missing", build_exit_code=0)
        return record
    record.update(
        status="built",
        build_system=str(selection["build_system"]),
        libraries=[str(path) for path in expat_libs(lib_dir)],
        tree=tree_manifest(prefix),
        generated_at=utc_now(),
    )
    write_cache_manifest(marker_path, record)
    write_cache_entry_completion(
        prefix,
        cache_root,
        component="expat-prefix",
        cache_key=str(cache_identity["cache_key"]),
        cache_identity=cache_identity,
    )
    return record


def shared_modsecurity_paths(cache_root: Path, build_id: str) -> dict[str, Path]:
    return {
        "build_root": cache_root / "builds/modsecurity" / build_id,
        "prefix": cache_root / "prefix/modsecurity" / build_id,
        "manifest": cache_root / "builds/modsecurity" / build_id / CACHE_MANIFEST_FILENAME,
        "lock": cache_root / "locks" / f"modsecurity-{build_id}.lock",
    }


def modsecurity_lib_file(prefix: Path) -> Path:
    return prefix / "lib" / MODSECURITY_LIBRARY_FILENAME


def modsecurity_public_headers_present(include_root: Path) -> bool:
    return all(
        (include_root / "modsecurity" / header_name).is_file()
        for header_name in MODSECURITY_REQUIRED_PUBLIC_HEADERS
    )


def modsecurity_ready(prefix: Path) -> bool:
    return (
        modsecurity_public_headers_present(prefix / "include")
        and modsecurity_lib_file(prefix).is_file()
    )


def modsecurity_build_manifest_binds_prefix(
    build_root: Path,
    prefix: Path,
    cache_identity: dict[str, Any],
) -> bool:
    """Whether a complete build manifest explicitly owns this stale prefix.

    This is deliberately a deletion-only proof.  It lets recovery discard a
    prefix whose registry marker was lost, while never turning the build
    manifest into a cache-hit or post-hoc ownership marker for that prefix.
    """
    manifest_path = build_root / CACHE_MANIFEST_FILENAME
    if not cache_manifest_complete(manifest_path, cache_identity):
        return False
    manifest = read_json(manifest_path)
    return (
        manifest_path_value_matches_entry(manifest.get("build_root"), build_root.resolve(strict=False))
        and manifest_path_value_matches_entry(manifest.get("prefix"), prefix.resolve(strict=False))
    )


def safe_remove_modsecurity_prefix_bound_by_build_manifest(
    prefix: Path,
    cache_root: Path,
    *,
    build_root: Path,
    cache_identity: dict[str, Any],
) -> None:
    """Remove only a prefix bound by a complete, current build manifest."""
    resolved_prefix, resolved_root = validate_managed_cache_child(prefix, cache_root)
    if not resolved_prefix.exists():
        return
    if cache_entry_marker_valid(resolved_prefix, resolved_root):
        safe_remove_dir(resolved_prefix, resolved_root)
        return
    if not modsecurity_build_manifest_binds_prefix(build_root, resolved_prefix, cache_identity):
        raise RuntimeError(unmanaged_cache_entry_marker_missing(resolved_prefix))
    shutil.rmtree(resolved_prefix)
    remove_managed_cache_entry_marker(resolved_prefix, resolved_root)


def modsecurity_expat_dependency(expat: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    expat_prefix = str(expat.get("prefix", ""))
    expat_lib_dir = str(expat.get("lib_dir", ""))
    expat_cache_identity = expat.get("cache_identity")
    if isinstance(expat_cache_identity, dict) and expat_cache_identity:
        return (
            expat_prefix,
            expat_lib_dir,
            {
                "cache_identity": expat_cache_identity,
                "cache_key": str(expat.get("cache_key", expat_cache_identity.get("cache_key", ""))),
                "prefix": expat_prefix,
            },
        )
    return (
        expat_prefix,
        expat_lib_dir,
        {
            "actual_head": expat.get("actual_head", ""),
            "prefix": expat_prefix,
            "tree": expat.get("tree", {}),
        },
    )


def modsecurity_build_flags(env: dict[str, str], expat_prefix: str, expat_lib_dir: str) -> dict[str, str]:
    include_flag = f"-I{Path(expat_prefix) / 'include'}" if expat_prefix else ""
    library_flag = f"-L{expat_lib_dir}" if expat_lib_dir else ""
    pkg_config_path = env.get("PKG_CONFIG_PATH", "")
    if expat_prefix:
        pkg_config_path = f"{expat_prefix}/lib/pkgconfig{os.pathsep}{pkg_config_path}".rstrip(os.pathsep)
    return {
        "configure_args": env.get("MODSECURITY_CONFIGURE_ARGS", ""),
        "CPPFLAGS": " ".join(part for part in (include_flag, env.get("CPPFLAGS", "")) if part).strip(),
        "CFLAGS": env.get("CFLAGS", ""),
        "CXXFLAGS": env.get("CXXFLAGS", ""),
        "LDFLAGS": " ".join(part for part in (library_flag, env.get("LDFLAGS", "")) if part).strip(),
        "LIBS": env.get("LIBS", ""),
        "PKG_CONFIG_PATH": pkg_config_path,
    }


def modsecurity_dependency_payload(
    env: dict[str, str],
    expat_dependency: dict[str, Any],
) -> dict[str, Any]:
    return {
        "expat": expat_dependency,
        "pkg_config_path": env.get("PKG_CONFIG_PATH", ""),
        "ld_library_path": env.get("LD_LIBRARY_PATH", ""),
    }


def modsecurity_cache_identity(
    env: dict[str, str],
    git_record: dict[str, Any],
    build_flags: dict[str, str],
    dependency_hash: str,
    patchset: dict[str, Any],
    toolchain: dict[str, Any],
) -> dict[str, Any]:
    return canonical_cache_identity(
        "modsecurity",
        env=env,
        upstream_url=str(git_record.get("url", git_record.get("source", ""))),
        upstream_version=str(git_record.get("expected_ref", "")),
        upstream_commit=str(git_record.get("actual_head", "")),
        source_sha256=str(git_record.get("actual_head", "")),
        patchset_sha256=str(patchset["sha256"]),
        configuration_flags=build_flags,
        toolchain=toolchain,
        extra_inputs={
            "dependency_hash": dependency_hash,
            "modsecurity_output_layout_version": MODSECURITY_OUTPUT_LAYOUT_VERSION,
            "recursive_submodule_status": git_record.get("submodule_status", ""),
        },
    )


def modsecurity_build_inputs(
    env: dict[str, str],
    git_record: dict[str, Any],
    expat: dict[str, Any],
    connector_root: Path | None = None,
) -> dict[str, Any]:
    expat_prefix, expat_lib_dir, expat_dependency = modsecurity_expat_dependency(expat)
    dependency_payload = modsecurity_dependency_payload(env, expat_dependency)
    build_flags = modsecurity_build_flags(env, expat_prefix, expat_lib_dir)
    dependency_hash = stable_hash(dependency_payload)
    toolchain = toolchain_identity(env)
    patchset = patchset_identity(component_patchset_roots(connector_root, "modsecurity"))
    cache_identity = modsecurity_cache_identity(
        env,
        git_record,
        build_flags,
        dependency_hash,
        patchset,
        toolchain,
    )
    inputs = {
        "source_url": git_record.get("url", git_record.get("source", "")),
        "source_ref": git_record.get("expected_ref", ""),
        "actual_source_sha": git_record.get("actual_head", ""),
        "recursive_submodule_status": git_record.get("submodule_status", ""),
        "build_flags": build_flags,
        "compiler": toolchain,
        "dependency_hash": dependency_hash,
        "dependency_prefixes": dependency_payload,
        "patchset": patchset,
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "cache_identity": cache_identity,
        "cache_key": cache_identity["cache_key"],
    }
    inputs["build_id"] = cache_identity["cache_key"]
    inputs["build_flags_text"] = json.dumps(build_flags, sort_keys=True)
    inputs["dependency_hash"] = dependency_hash
    return inputs


class BuildLock:
    def __init__(self, lock_path: Path, timeout: int = 900) -> None:
        self.lock_path = lock_path
        self.timeout = timeout
        self.handle: Any = None
        self.mkdir_lock = lock_path.with_suffix(lock_path.suffix + ".dir")

    def _acquire_file_lock(self) -> "BuildLock":
        import fcntl  # type: ignore

        self.handle = self.lock_path.open("w", encoding="utf-8")
        deadline = time.time() + self.timeout
        while True:
            try:
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.handle.write(f"pid={os.getpid()} acquired_at={utc_now()}\n")
                self.handle.flush()
                return self
            except BlockingIOError:
                if time.time() > deadline:
                    raise TimeoutError(f"lock_timeout: {self.lock_path}")
                time.sleep(1)

    def _acquire_directory_lock(self) -> "BuildLock":
        deadline = time.time() + self.timeout
        while True:
            try:
                self.mkdir_lock.mkdir()
                (self.mkdir_lock / "owner").write_text(
                    f"pid={os.getpid()} acquired_at={utc_now()}\n",
                    encoding="utf-8",
                )
                return self
            except FileExistsError:
                if time.time() > deadline:
                    raise TimeoutError(f"lock_timeout: {self.mkdir_lock}")
                time.sleep(1)

    def __enter__(self) -> "BuildLock":
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            return self._acquire_file_lock()
        except ImportError:
            return self._acquire_directory_lock()

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self.handle is not None:
            try:
                import fcntl  # type: ignore

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            finally:
                self.handle.close()
        if self.mkdir_lock.is_dir():
            # The fallback lock directory contains only the owner marker we
            # created; avoid a recursive removal primitive for lock cleanup.
            try:
                (self.mkdir_lock / "owner").unlink()
            except FileNotFoundError:
                pass
            try:
                self.mkdir_lock.rmdir()
            except OSError:
                pass


def cache_entry_lock_path(cache_root: Path, component: str, cache_key: str) -> Path:
    """Return a deterministic lock path for exactly one canonical entry."""
    safe_component = re.sub(r"[^A-Za-z0-9_.-]+", "-", component).strip("-") or "component"
    safe_key = stable_hash({"component": component, "cache_key": cache_key})[:24]
    return cache_root / "locks" / f"{safe_component}-{safe_key}.lock"


def _modsecurity_runtime_library_terminal_details(
    current: str, details: os.stat_result
) -> os.stat_result | None:
    """Return a verified Libtool terminal or reject an unexpected inode type."""
    if stat.S_ISREG(details.st_mode):
        if not current.startswith(f"{MODSECURITY_RUNTIME_LIBRARY_FILENAME}."):
            raise RuntimeError("modsecurity_library_terminal_name_invalid_after_build")
        if details.st_mode & 0o022:
            raise RuntimeError("modsecurity_library_terminal_writable_after_build")
        return details
    if not stat.S_ISLNK(details.st_mode):
        raise RuntimeError("modsecurity_library_terminal_nonregular_after_build")
    return None


def _modsecurity_runtime_library_alias_target(
    libs_descriptor: int, current: str, details: os.stat_result
) -> str:
    """Read one stable, direct-basename Libtool alias target."""
    try:
        target = os.readlink(current, dir_fd=libs_descriptor)
        link_after_read = os.stat(current, dir_fd=libs_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise RuntimeError("modsecurity_library_symlink_changed_after_build") from exc
    if (details.st_dev, details.st_ino) != (
        link_after_read.st_dev,
        link_after_read.st_ino,
    ):
        raise RuntimeError("modsecurity_library_symlink_changed_after_build")
    target_path = Path(target)
    if (
        not target
        or target_path.is_absolute()
        or target_path.name != target
        or target in {".", ".."}
    ):
        raise RuntimeError("modsecurity_library_symlink_outside_after_build")
    return target


def _contained_modsecurity_runtime_library(
    libs_descriptor: int, start_name: str
) -> tuple[str, os.stat_result]:
    """Resolve one Libtool alias relative to an already verified directory.

    The protected broker cannot publish a symlink, including one that merely
    happens to resolve to a regular file today.  Resolve the two expected
    aliases explicitly.  Libtool emits basename-only links in ``src/.libs``;
    rejecting every path component also prevents a symlinked intermediate
    directory from escaping that directory.
    """
    current = start_name
    seen: set[str] = set()
    while True:
        if current in seen:
            raise RuntimeError("modsecurity_library_symlink_cycle_after_build")
        seen.add(current)
        try:
            details = os.stat(current, dir_fd=libs_descriptor, follow_symlinks=False)
        except OSError as exc:
            raise RuntimeError("modsecurity_library_symlink_dangling_after_build") from exc
        terminal_details = _modsecurity_runtime_library_terminal_details(current, details)
        if terminal_details is not None:
            return current, terminal_details
        current = _modsecurity_runtime_library_alias_target(libs_descriptor, current, details)


def _verified_modsecurity_runtime_library(libs: Path) -> tuple[int, os.stat_result]:
    """Open the one regular inode backing both expected Libtool aliases."""
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_NOFOLLOW
    try:
        libs_descriptor = os.open(libs, directory_flags)
    except OSError as exc:
        raise RuntimeError("modsecurity_library_directory_unsafe_after_build") from exc
    terminal_descriptors: list[tuple[int, os.stat_result]] = []
    try:
        resolved = [
            _contained_modsecurity_runtime_library(libs_descriptor, name)
            for name in (MODSECURITY_LIBRARY_FILENAME, MODSECURITY_RUNTIME_LIBRARY_FILENAME)
        ]
        for terminal_name, expected_details in resolved:
            try:
                descriptor = os.open(terminal_name, file_flags, dir_fd=libs_descriptor)
            except OSError as exc:
                raise RuntimeError("modsecurity_library_terminal_changed_after_build") from exc
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or (details.st_dev, details.st_ino)
                != (expected_details.st_dev, expected_details.st_ino)
            ):
                os.close(descriptor)
                raise RuntimeError("modsecurity_library_terminal_changed_after_build")
            if details.st_mode & 0o022:
                os.close(descriptor)
                raise RuntimeError("modsecurity_library_terminal_writable_after_build")
            terminal_descriptors.append((descriptor, details))
        if len({(details.st_dev, details.st_ino) for _, details in terminal_descriptors}) != 1:
            raise RuntimeError("modsecurity_library_multiple_terminal_targets_after_build")
        verified_descriptor, verified_details = terminal_descriptors.pop()
        return verified_descriptor, verified_details
    finally:
        os.close(libs_descriptor)
        for descriptor, _ in terminal_descriptors:
            os.close(descriptor)


def _copy_verified_modsecurity_runtime_library(
    source_descriptor: int,
    source_details: os.stat_result,
    destination: Path,
) -> None:
    """Atomically copy the verified source inode without reopening its path."""
    temporary_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.tmp-", dir=str(destination.parent)
    )
    temporary = Path(temporary_name)
    try:
        os.lseek(source_descriptor, 0, os.SEEK_SET)
        with os.fdopen(os.dup(source_descriptor), "rb") as source_handle, os.fdopen(
            temporary_descriptor, "wb"
        ) as destination_handle:
            temporary_descriptor = -1
            shutil.copyfileobj(source_handle, destination_handle)
            destination_handle.flush()
            os.fsync(destination_handle.fileno())
            os.fchmod(destination_handle.fileno(), stat.S_IMODE(source_details.st_mode))
            os.utime(
                destination_handle.fileno(),
                ns=(source_details.st_atime_ns, source_details.st_mtime_ns),
            )
        details_after_copy = os.fstat(source_descriptor)
        if (
            details_after_copy.st_size,
            details_after_copy.st_mtime_ns,
        ) != (
            source_details.st_size,
            source_details.st_mtime_ns,
        ):
            raise RuntimeError("modsecurity_library_terminal_changed_during_copy")
        os.replace(temporary, destination)
        if not stat.S_ISREG(destination.lstat().st_mode):
            raise RuntimeError("modsecurity_library_runtime_nonregular_after_copy")
    except Exception:
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def copy_modsecurity_outputs(source_dir: Path, prefix: Path) -> None:
    headers = source_dir / "headers"
    libs = source_dir / "src/.libs"
    if not modsecurity_public_headers_present(headers):
        raise RuntimeError("modsecurity_headers_missing_after_build")
    terminal_descriptor, terminal_details = _verified_modsecurity_runtime_library(libs)
    include_dir = prefix / "include"
    lib_dir = prefix / "lib"
    include_dir.mkdir(parents=True, exist_ok=True)
    lib_dir.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copytree(headers, include_dir, dirs_exist_ok=True, symlinks=True)
        for item in libs.glob(f"{MODSECURITY_LIBRARY_FILENAME}*"):
            dest = lib_dir / item.name
            if dest.exists() or dest.is_symlink():
                dest.unlink()
            if item.is_symlink():
                os.symlink(os.readlink(item), dest)
            else:
                shutil.copy2(item, dest)
        # Preserve the ordinary libtool aliases for generic consumers, but
        # publish the protected regular file from the descriptor held since
        # alias verification, never by reopening the terminal pathname.
        runtime_library = lib_dir / MODSECURITY_RUNTIME_LIBRARY_FILENAME
        _copy_verified_modsecurity_runtime_library(
            terminal_descriptor, terminal_details, runtime_library
        )
    finally:
        os.close(terminal_descriptor)


_FRAMEWORK_MODSECURITY_V3_GUARD = (
    'set -eu\n'
    '. "$1"\n'
    'MODSECURITY_V3_SOURCE_DIR=$2\n'
    'export MODSECURITY_V3_SOURCE_DIR\n'
    'ci_require_approved_modsecurity_v3_checkout "$MODSECURITY_V3_SOURCE_DIR"\n'
)
_FRAMEWORK_MODSECURITY_V3_PROVENANCE_GUARD = (
    'set -eu\n'
    '. "$1"\n'
    'ci_require_approved_modsecurity_v3_provenance\n'
)
_FRAMEWORK_MODSECURITY_V3_PROVISIONING_BRIDGE = (
    'set -eu\n'
    '. "$1"\n'
    'ci_provision_approved_modsecurity_v3_checkout "$2"\n'
)


def verified_host_guard_executable(path: Path, label: str) -> Path:
    """Return a root-owned, non-writable host executable for guard execution."""
    try:
        resolved = path.resolve(strict=True)
        details = resolved.stat()
    except OSError as exc:
        raise RuntimeError(f"trusted_{label}_unavailable:{exc}") from exc
    if not stat.S_ISREG(details.st_mode) or not os.access(resolved, os.X_OK):
        raise RuntimeError(f"trusted_{label}_not_executable:{resolved}")
    if details.st_uid != 0 or details.st_mode & 0o022:
        raise RuntimeError(f"trusted_{label}_ownership_or_mode_invalid:{resolved}")
    return resolved


def run_framework_modsecurity_v3_guard(
    env: dict[str, str],
    framework_root: Path | None,
    guard_script: str,
    guard_label: str,
    source_path: Path | None = None,
) -> dict[str, Any]:
    """Run one Framework-owned V3 guard with positional path arguments."""
    if framework_root is None:
        return {
            "status": "blocked",
            "blocker_reason": "framework_root_missing_for_modsecurity_v3_provenance_guard",
        }
    resolved_framework_root = framework_root.resolve()
    common_sh = resolved_framework_root / "ci" / "lib" / "common.sh"
    if not common_sh.is_file():
        return {
            "status": "blocked",
            "blocker_reason": "framework_modsecurity_v3_provenance_guard_missing",
            "framework_common": str(common_sh),
        }
    guard_env = dict(os.environ)
    for key in FRAMEWORK_GUARD_RUNTIME_ROOT_ENV_KEYS:
        value = env.get(key)
        if value:
            guard_env[key] = value
    guard_env["FRAMEWORK_ROOT"] = str(resolved_framework_root)
    try:
        trusted_shell = verified_host_guard_executable(_TRUSTED_FRAMEWORK_GUARD_SHELL, "framework_guard_shell")
        verified_host_guard_executable(_TRUSTED_FRAMEWORK_GUARD_GIT, "framework_guard_git")
    except RuntimeError as exc:
        return {
            "status": "blocked",
            "blocker_reason": str(exc),
            "framework_common": str(common_sh),
        }
    # The Framework helper deliberately invokes `git` by name after clearing
    # Git-specific attacker controls.  Limit that lookup to the verified host
    # baseline and execute the shell itself by an immutable absolute path.
    guard_env["PATH"] = _TRUSTED_FRAMEWORK_GUARD_PATH
    guard_env.pop("ENV", None)
    guard_env.pop("BASH_ENV", None)
    command = [str(trusted_shell), "-c", guard_script, guard_label, str(common_sh)]
    if source_path is not None:
        guard_env["MODSECURITY_V3_SOURCE_DIR"] = str(source_path)
        command.append(str(source_path))
    proc = run_env(command, cwd=resolved_framework_root, env=guard_env)
    diagnostic = (proc.stdout + proc.stderr).strip()
    result: dict[str, Any] = {
        "status": "passed" if proc.returncode == 0 else "blocked",
        "framework_common": str(common_sh),
        "exit_code": proc.returncode,
    }
    if source_path is not None:
        result["source_path"] = str(source_path)
    if diagnostic:
        result["details"] = diagnostic
    if proc.returncode != 0:
        result["blocker_reason"] = "framework_modsecurity_v3_provenance_guard_rejected"
    return result


def verify_framework_approved_modsecurity_v3_provenance(
    env: dict[str, str],
    framework_root: Path | None,
) -> dict[str, Any]:
    """Fail closed before Parent asks Git to acquire the V3 source."""
    return run_framework_modsecurity_v3_guard(
        env,
        framework_root,
        _FRAMEWORK_MODSECURITY_V3_PROVENANCE_GUARD,
        "framework-modsecurity-v3-provenance-configuration-guard",
    )


def verify_framework_approved_modsecurity_v3_checkout(
    env: dict[str, str],
    framework_root: Path | None,
    source_path: Path,
) -> dict[str, Any]:
    """Ask the Framework to admit the exact V3 checkout before any build use.

    The Parent deliberately delegates the immutable origin/commit/topology
    policy to the Framework-owned guard.  The command string is constant and
    the two filesystem paths are passed as positional arguments, so neither
    a source checkout path nor caller-supplied environment data becomes shell
    syntax.
    """
    return run_framework_modsecurity_v3_guard(
        env,
        framework_root,
        _FRAMEWORK_MODSECURITY_V3_GUARD,
        "framework-modsecurity-v3-provenance-guard",
        source_path,
    )


def provision_framework_approved_modsecurity_v3_checkout(
    env: dict[str, str],
    framework_root: Path | None,
    source_path: Path,
) -> dict[str, Any]:
    """Provision a fresh V3 checkout through the Framework-owned bridge."""
    return run_framework_modsecurity_v3_guard(
        env,
        framework_root,
        _FRAMEWORK_MODSECURITY_V3_PROVISIONING_BRIDGE,
        "framework-modsecurity-v3-provisioning-bridge",
        source_path,
    )


def reserve_framework_approved_modsecurity_v3_staging_path(
    final_path: Path,
    cache_root: Path,
    *,
    component: str,
    cache_key: str,
) -> Path:
    """Reserve an absent cache child for the Framework's fresh-only V3 API.

    The Framework bridge rejects an existing destination.  Unlike
    ``temporary_cache_dir``, this helper intentionally writes only the managed
    cache marker; the bridge is the sole creator of the checkout directory.
    """
    resolved_final, resolved_root = validate_managed_cache_child(final_path, cache_root)
    resolved_final.parent.mkdir(parents=True, exist_ok=True)
    for _ in range(32):
        staging = resolved_final.parent / f".{resolved_final.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
        marker_path = cache_entry_marker_path(staging, resolved_root)
        if staging.exists() or staging.is_symlink() or marker_path.exists():
            continue
        mark_managed_cache_entry(staging, resolved_root, component=component, cache_key=cache_key)
        # Do not create this child: ci_provision_approved_modsecurity_v3_checkout
        # requires the destination to remain absent until it owns creation.
        if not staging.exists() and not staging.is_symlink():
            return staging
        remove_managed_cache_entry_marker(staging, resolved_root)
    raise RuntimeError(f"cache_staging_directory_collision: {resolved_final.parent}")


def trusted_framework_modsecurity_v3_git_output(checkout_path: Path, *args: str) -> str:
    """Read verified V3 metadata without inheriting caller-controlled Git state."""
    trusted_git = verified_host_guard_executable(_TRUSTED_FRAMEWORK_GUARD_GIT, "framework_guard_git")
    # Metadata is read only after the Framework's complete checkout guard has
    # admitted the path.  Keep the follow-up probes equally independent of
    # caller PATH, global/system Git config, hooks, fsmonitor, and loader state.
    metadata_env = {
        "PATH": _TRUSTED_FRAMEWORK_GUARD_PATH,
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_COUNT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    proc = run_env(
        [
            str(trusted_git),
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.useBuiltinFSMonitor=false",
            "-C",
            str(checkout_path),
            *args,
        ],
        env=metadata_env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"framework_approved_git_metadata_failed:{' '.join(args)}")
    return proc.stdout.strip()


def framework_approved_modsecurity_v3_checkout_metadata(
    url: str,
    expected_ref: str,
    checkout_path: Path,
) -> dict[str, Any]:
    """Record local metadata after the Framework has verified a V3 checkout."""
    actual_head = trusted_framework_modsecurity_v3_git_output(checkout_path, "rev-parse", "HEAD")
    if not actual_head:
        raise RuntimeError("git_resolved_commit_missing")
    status_short = trusted_framework_modsecurity_v3_git_output(
        checkout_path,
        *GIT_STATUS_SHORT_ARGS,
    )
    if status_short:
        raise RuntimeError("dirty_source_checkout")
    submodules = trusted_framework_modsecurity_v3_git_output(
        checkout_path,
        *GIT_SUBMODULE_STATUS_RECURSIVE_ARGS,
    )
    clean, reason = submodule_status_clean(submodules)
    if not clean:
        raise RuntimeError(reason)
    source_identity = source_cache_identity("modsecurity-v3", url, expected_ref, actual_head)
    return {
        "actual_head": actual_head,
        "status_short": status_short,
        "submodule_status": submodules,
        "submodule_count": len([line for line in submodules.splitlines() if line.strip()]),
        "submodule_status_clean": True,
        # The Framework verifier performs fsck for the approved root and its
        # static child graph; do not replace its fixed topology with a generic
        # Parent acquisition path merely to gather this field.
        "git_fsck": "PASS",
        "tree": tree_manifest(checkout_path),
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "cache_identity": source_identity,
        "cache_key": source_identity["cache_key"],
    }


def reusable_framework_approved_modsecurity_v3_cache_record(
    env: dict[str, str],
    framework_root: Path,
    checkout_path: Path,
    cache_root: Path,
    *,
    component: str,
    url: str,
    expected_ref: str,
) -> dict[str, Any] | None:
    """Return a reusable V3 record only after Framework revalidation.

    A completed local marker is intentionally insufficient on its own.  The
    Framework must first admit the exact checkout, then the Parent recomputes
    the identity-bound metadata and verifies the completion marker.
    """
    if not checkout_path.exists():
        return None
    verification = verify_framework_approved_modsecurity_v3_checkout(
        env,
        framework_root,
        checkout_path,
    )
    if verification.get("status") != "passed":
        return None
    try:
        metadata = framework_approved_modsecurity_v3_checkout_metadata(
            url,
            expected_ref,
            checkout_path,
        )
    except RuntimeError:
        return None
    if not cache_entry_complete(
        checkout_path,
        cache_root,
        component=component,
        cache_key=str(metadata["cache_key"]),
        cache_identity=metadata["cache_identity"],
    ):
        return None
    return {
        **metadata,
        "manifest": str(cache_entry_marker_path(checkout_path, cache_root)),
        "status": "present",
        "approved_acquisition": "framework_approved_v3_cache_reuse",
        "provenance_verification": verification,
    }


def verified_framework_approved_modsecurity_v3_staging_metadata(
    env: dict[str, str],
    framework_root: Path,
    staging_path: Path,
    *,
    url: str,
    expected_ref: str,
) -> dict[str, Any]:
    """Provision and verify a fresh V3 staging checkout through Framework.

    The returned metadata is not yet published.  The caller must bind it to a
    complete cache marker before an existing published entry is removed.
    """
    provisioning = provision_framework_approved_modsecurity_v3_checkout(
        env,
        framework_root,
        staging_path,
    )
    result: dict[str, Any] = {"provenance_provisioning": provisioning}
    if provisioning.get("status") != "passed":
        result.update(
            status="blocked",
            blocker_reason="modsecurity_v3_framework_provisioning_failed",
            details=provisioning.get("details") or provisioning.get("blocker_reason", ""),
        )
        return result
    if not staging_path.is_dir() or staging_path.is_symlink():
        result.update(
            status="blocked",
            blocker_reason="modsecurity_v3_framework_provisioning_destination_missing",
        )
        return result

    verification = verify_framework_approved_modsecurity_v3_checkout(
        env,
        framework_root,
        staging_path,
    )
    result["provenance_verification"] = verification
    if verification.get("status") != "passed":
        result.update(
            status="blocked",
            blocker_reason="modsecurity_v3_provenance_guard_failed",
            details=verification.get("details") or verification.get("blocker_reason", ""),
        )
        return result
    try:
        result.update(
            framework_approved_modsecurity_v3_checkout_metadata(
                url,
                expected_ref,
                staging_path,
            )
        )
    except RuntimeError as exc:
        result.update(status="blocked", blocker_reason=str(exc))
    return result


def remove_replaceable_framework_approved_modsecurity_v3_cache_entry(
    checkout_path: Path,
    cache_root: Path,
    *,
    component: str,
) -> dict[str, Any]:
    """Discard only a cache entry whose ownership permits replacement.

    This is intentionally called only after a new Framework-verified staging
    checkout has a complete, identity-bound cache marker.
    """
    if not checkout_path.exists():
        return {}
    marker = read_json(cache_entry_marker_path(checkout_path, cache_root))
    marker_is_valid = cache_entry_marker_valid(checkout_path, cache_root)
    if marker_is_valid:
        if marker.get("component") != component:
            raise RuntimeError(f"managed_cache_entry_identity_mismatch: {checkout_path}")
    elif not (
        cache_manifest_owns_entry(checkout_path)
        or migrate_legacy_cache_entry_for_removal(
            checkout_path,
            cache_root,
            component=component,
        )
    ):
        raise RuntimeError(unmanaged_cache_entry_marker_missing(checkout_path))
    safe_remove_dir(checkout_path, cache_root)
    return {
        "rebuild_required": True,
        "invalidation_reason": "approved_source_cache_replaced",
        "old_entry_removed": True,
        "previous_path": str(checkout_path),
    }


def discard_unpublished_framework_approved_modsecurity_v3_staging_entry(
    staging_path: Path | None,
    cache_root: Path,
) -> None:
    """Best-effort cleanup for an unpublished V3 staging cache child."""
    if staging_path is None:
        return
    try:
        if staging_path.is_dir() and not staging_path.is_symlink():
            safe_remove_dir(staging_path, cache_root)
        elif not staging_path.exists() and not staging_path.is_symlink():
            remove_managed_cache_entry_marker(staging_path, cache_root)
    except RuntimeError:
        # Cleanup cannot make an unverified staging path usable.  Preserve the
        # original fail-closed result and never hide it with a cleanup error.
        return


def prepare_framework_approved_modsecurity_v3_source(
    env: dict[str, str],
    framework_root: Path,
    path: Path,
    cache_root: Path,
) -> dict[str, Any]:
    """Acquire V3 only through the Framework's approved provisioning bridge."""
    url = env.get("MODSECURITY_V3_GIT_URL") or env.get("MODSECURITY_REPO_URL", "")
    expected_ref = env.get("MODSECURITY_V3_GIT_REF") or env.get("MODSECURITY_GIT_REF", "")
    record: dict[str, Any] = {
        "name": "modsecurity-v3",
        "url": url,
        "expected_ref": expected_ref,
        "path": str(path),
        "recursive_submodules": True,
        "submodule_count": 0,
        "submodule_status_clean": False,
        "git_fsck": "SKIPPED",
        "status": "unknown",
        "blocker_reason": "",
    }
    configuration = verify_framework_approved_modsecurity_v3_provenance(env, framework_root)
    record["provenance_configuration"] = configuration
    if configuration.get("status") != "passed":
        record.update(
            status="blocked",
            blocker_reason="modsecurity_v3_provenance_configuration_failed",
            details=configuration.get("details") or configuration.get("blocker_reason", ""),
        )
        return record

    try:
        managed_root = ensure_managed_cache_root(cache_root)
        checkout_path, _ = validate_managed_cache_child(Path(path), managed_root)
        record["path"] = str(checkout_path)
    except RuntimeError as exc:
        record.update(status="blocked", blocker_reason=str(exc))
        return record
    if is_system_path(checkout_path):
        record.update(status="blocked", blocker_reason="system_path_write_forbidden")
        return record

    component = "source:modsecurity-v3"
    ref_identity = source_cache_identity("modsecurity-v3", url, expected_ref)
    ref_lock_key = str(ref_identity["cache_key"])
    staging_path: Path | None = None
    try:
        with BuildLock(cache_entry_lock_path(managed_root, component, ref_lock_key)):
            # A published cache hit is admitted only by the fixed Framework
            # checkout verifier.  Its immutable provenance makes a generic
            # Parent ls-remote/fetch recovery path both unnecessary and unsafe.
            cached_record = reusable_framework_approved_modsecurity_v3_cache_record(
                env,
                framework_root,
                checkout_path,
                managed_root,
                component=component,
                url=url,
                expected_ref=expected_ref,
            )
            if cached_record is not None:
                record.update(cached_record)
                return record

            # The bridge must create the fresh child itself.  Reserve the
            # managed registry marker first, but leave the destination absent
            # until the Framework-owned helper has taken responsibility for it.
            staging_path = reserve_framework_approved_modsecurity_v3_staging_path(
                checkout_path,
                managed_root,
                component=component,
                cache_key=ref_lock_key,
            )
            staging_record = verified_framework_approved_modsecurity_v3_staging_metadata(
                env,
                framework_root,
                staging_path,
                url=url,
                expected_ref=expected_ref,
            )
            record.update(staging_record)
            if staging_record.get("status") == "blocked":
                return record

            # Seal the staged entry before touching an existing published
            # cache path.  A bridge, verification, or completion failure must
            # leave that final entry available to its current consumers.
            retag_staging_cache_entry(
                staging_path,
                managed_root,
                component=component,
                cache_key=str(staging_record["cache_key"]),
            )
            write_cache_entry_completion(
                staging_path,
                managed_root,
                component=component,
                cache_key=str(staging_record["cache_key"]),
                cache_identity=staging_record["cache_identity"],
            )

            # A failed bridge or verification leaves this published entry
            # untouched.  Only a fully verified staging checkout may replace a
            # managed stale entry, and never an unowned or mismatched one.
            record.update(
                remove_replaceable_framework_approved_modsecurity_v3_cache_entry(
                    checkout_path,
                    managed_root,
                    component=component,
                )
            )

            atomic_publish_dir(staging_path, checkout_path, managed_root, require_complete=True)
            staging_path = None
            record.update(
                path=str(checkout_path),
                manifest=str(cache_entry_marker_path(checkout_path, managed_root)),
                status="present",
                approved_acquisition="framework_approved_v3_bridge",
                tree=tree_manifest(checkout_path),
            )
            return record
    except TimeoutError as exc:
        record.update(status="blocked", blocker_reason="cache_lock_timeout", details=str(exc))
        return record
    except Exception as exc:
        record.update(status="blocked", blocker_reason=str(exc))
        return record
    finally:
        discard_unpublished_framework_approved_modsecurity_v3_staging_entry(staging_path, managed_root)


MODSECURITY_BUILD_FAILURE_BLOCKER = "modsecurity_build_failed"


def modsecurity_cache_path_blocker(paths: dict[str, Path], cache_root: Path) -> str:
    for label in ("build_root", "prefix", "lock"):
        path = paths[label]
        if is_system_path(path) or not is_within(path, cache_root):
            return f"{label}:{path}"
    return ""


def modsecurity_source_preflight(
    env: dict[str, str],
    git_record: dict[str, Any],
    framework_root: Path | None,
    source_path: Path,
) -> tuple[dict[str, Any] | None, str, str]:
    if git_record.get("status") != "present":
        return None, "", ""
    if not git_record.get("submodule_status_clean", False):
        return None, "modsecurity_submodule_missing", ""
    provenance = verify_framework_approved_modsecurity_v3_checkout(env, framework_root, source_path)
    if provenance.get("status") == "passed":
        return provenance, "", ""
    details = str(provenance.get("details") or provenance.get("blocker_reason", ""))
    return provenance, "modsecurity_v3_provenance_guard_failed", details


def prepare_modsecurity_build_root(
    record: dict[str, Any],
    paths: dict[str, Path],
    cache_root: Path,
    inputs: dict[str, Any],
) -> str:
    build_root = paths["build_root"]
    if build_root.exists() and not cache_entry_marker_valid(build_root, cache_root):
        if cache_manifest_owns_entry(build_root):
            safe_remove_dir(build_root, cache_root)
            record.update(
                rebuild_required=True,
                invalidation_reason="missing_modsecurity_cache_registry_marker",
                old_entry_removed=True,
            )
        elif migrate_legacy_cache_entry_for_removal(build_root, cache_root, component="modsecurity-build"):
            safe_remove_dir(build_root, cache_root)
            record.update(
                rebuild_required=True,
                invalidation_reason="cache_schema_changed",
                old_entry_removed=True,
            )
        else:
            return unmanaged_cache_entry_marker_missing(build_root)
    try:
        mark_managed_cache_entry(
            build_root,
            cache_root,
            component="modsecurity-build",
            cache_key=str(inputs["cache_key"]),
        )
    except RuntimeError as exc:
        return str(exc)
    return ""


def modsecurity_cache_is_ready(
    record: dict[str, Any],
    paths: dict[str, Path],
    cache_root: Path,
    inputs: dict[str, Any],
) -> bool:
    prefix = paths["prefix"]
    cache_identity = inputs["cache_identity"]
    if not (
        modsecurity_ready(prefix)
        and cache_manifest_complete(paths["manifest"], cache_identity)
        and cache_entry_complete(
            paths["build_root"],
            cache_root,
            component="modsecurity-build",
            cache_key=str(inputs["cache_key"]),
            cache_identity=cache_identity,
        )
        and cache_entry_complete(
            prefix,
            cache_root,
            component="modsecurity-prefix",
            cache_key=str(inputs["cache_key"]),
            cache_identity=cache_identity,
        )
    ):
        return False
    record.update(status="reused", tree=tree_manifest(prefix), generated_at=utc_now())
    write_cache_manifest(paths["manifest"], record)
    return True


def missing_modsecurity_build_dependency(env: dict[str, str]) -> str:
    missing = first_missing_tool([("make", "missing_make"), ("git", "missing_git")])
    if not resolve_compiler(env):
        return "missing_compiler"
    return missing


def discard_incomplete_modsecurity_cache_entries(
    record: dict[str, Any],
    paths: dict[str, Path],
    cache_root: Path,
    inputs: dict[str, Any],
) -> str:
    prefix = paths["prefix"]
    for label, cache_path, component in (
        ("modsecurity-build", paths["build_root"], "modsecurity-build"),
        ("modsecurity-prefix", prefix, "modsecurity-prefix"),
    ):
        if not cache_path.exists() or managed_cache_entry_valid(cache_path, cache_root):
            continue
        if label == "modsecurity-prefix" and modsecurity_build_manifest_binds_prefix(
            paths["build_root"],
            prefix,
            inputs["cache_identity"],
        ):
            # The build manifest grants deletion only.  It never admits the
            # markerless prefix as a reusable cache entry.
            safe_remove_modsecurity_prefix_bound_by_build_manifest(
                prefix,
                cache_root,
                build_root=paths["build_root"],
                cache_identity=inputs["cache_identity"],
            )
            record.update(
                rebuild_required=True,
                invalidation_reason="missing_modsecurity_prefix_registry_marker",
                old_entry_removed=True,
            )
            continue
        if not migrate_legacy_cache_entry_for_removal(cache_path, cache_root, component=component):
            return unmanaged_cache_entry_marker_missing(cache_path)
    safe_remove_dir(paths["build_root"], cache_root)
    safe_remove_dir(prefix, cache_root)
    return ""


def modsecurity_staging_paths(
    paths: dict[str, Path],
    cache_root: Path,
    cache_key: str,
) -> tuple[Path, Path]:
    return (
        temporary_cache_dir(
            paths["build_root"],
            cache_root,
            component="modsecurity-build",
            cache_key=cache_key,
        ),
        temporary_cache_dir(
            paths["prefix"],
            cache_root,
            component="modsecurity-prefix",
            cache_key=cache_key,
        ),
    )


def modsecurity_build_environment(
    env: dict[str, str],
    inputs: dict[str, Any],
    expat: dict[str, Any],
) -> dict[str, str]:
    build_env_vars = dict(os.environ)
    build_env_vars.update(env)
    flag_payload = json.loads(str(inputs["build_flags_text"]))
    for key in ("CPPFLAGS", "CFLAGS", "CXXFLAGS", "LDFLAGS", "LIBS", "PKG_CONFIG_PATH"):
        if flag_payload.get(key):
            build_env_vars[key] = str(flag_payload[key])
    expat_lib_dir = expat.get("lib_dir")
    if expat_lib_dir:
        build_env_vars["LD_LIBRARY_PATH"] = (
            f"{expat_lib_dir}{os.pathsep}{env.get('LD_LIBRARY_PATH', '')}".rstrip(os.pathsep)
        )
    return build_env_vars


def modsecurity_build_commands(env: dict[str, str], staging_prefix: Path) -> list[tuple[str, list[str]]]:
    configure_command = ["./configure", f"--prefix={staging_prefix}"]
    configure_command.extend(env.get("MODSECURITY_CONFIGURE_ARGS", "").split())
    return [
        ("modsecurity-build-sh", ["sh", "./build.sh"]),
        ("modsecurity-configure", configure_command),
        ("modsecurity-make", ["make", f"-j{runtime_make_jobs(env)}"]),
    ]


def record_modsecurity_build_failure(
    record: dict[str, Any],
    staging_build: Path,
    log_path: Path,
    return_code: int,
) -> None:
    record.update(
        status="failed",
        blocker_reason=MODSECURITY_BUILD_FAILURE_BLOCKER,
        build_exit_code=return_code,
        build_log=str(log_path),
    )
    write_cache_manifest(staging_build / CACHE_MANIFEST_FILENAME, record)


def build_modsecurity_staging_entry(
    env: dict[str, str],
    inputs: dict[str, Any],
    expat: dict[str, Any],
    source_path: Path,
    staging_build: Path,
    staging_prefix: Path,
    log_path: Path,
    record: dict[str, Any],
) -> bool:
    build_source = staging_build / "source"
    shutil.copytree(
        source_path,
        build_source,
        ignore=shutil.ignore_patterns(
            ".git", ".github", "__pycache__", "autom4te.cache", "*.o", "*.lo", "*.la", "*.log"
        ),
    )
    build_env_vars = modsecurity_build_environment(env, inputs, expat)
    log_parts: list[str] = []
    for label, command in modsecurity_build_commands(env, staging_prefix):
        proc = run_env(command, cwd=build_source, env=build_env_vars)
        append_command_log(log_parts, label, proc)
        if proc.returncode != 0:
            write_component_log(log_path, log_parts)
            record_modsecurity_build_failure(record, staging_build, log_path, proc.returncode)
            return False
    copy_modsecurity_outputs(build_source, staging_prefix)
    write_component_log(log_path, log_parts)
    if not modsecurity_ready(staging_prefix):
        record_modsecurity_build_failure(record, staging_build, log_path, 0)
        return False
    record.update(
        status="built",
        build_log=str(log_path),
        tree=tree_manifest(staging_prefix),
        generated_at=utc_now(),
    )
    write_cache_manifest(staging_build / CACHE_MANIFEST_FILENAME, record)
    return True


def publish_modsecurity_staging_entries(
    record: dict[str, Any],
    paths: dict[str, Path],
    cache_root: Path,
    inputs: dict[str, Any],
    staging_build: Path,
    staging_prefix: Path,
) -> None:
    cache_identity = inputs["cache_identity"]
    cache_key = str(inputs["cache_key"])
    write_cache_entry_completion(
        staging_build,
        cache_root,
        component="modsecurity-build",
        cache_key=cache_key,
        cache_identity=cache_identity,
    )
    write_cache_entry_completion(
        staging_prefix,
        cache_root,
        component="modsecurity-prefix",
        cache_key=cache_key,
        cache_identity=cache_identity,
    )
    atomic_publish_dir(staging_prefix, paths["prefix"], cache_root, require_complete=True)
    atomic_publish_dir(staging_build, paths["build_root"], cache_root, require_complete=True)
    record.update(tree=tree_manifest(paths["prefix"]), generated_at=utc_now())
    write_cache_manifest(paths["manifest"], record)


def cleanup_modsecurity_staging_entry(staging_path: Path | None, cache_root: Path) -> None:
    if staging_path is None or not staging_path.exists():
        return
    try:
        safe_remove_dir(staging_path, cache_root)
    except RuntimeError:
        pass


def build_shared_modsecurity_cache(
    env: dict[str, str],
    cache_root: Path,
    build_root: Path,
    expat: dict[str, Any],
    inputs: dict[str, Any],
    paths: dict[str, Path],
    source_path: Path,
    record: dict[str, Any],
) -> dict[str, Any]:
    log_path = build_root / "logs/runtime-components" / f"modsecurity-{str(inputs['build_id'])[:16]}-build.log"
    staging_build: Path | None = None
    staging_prefix: Path | None = None
    try:
        with BuildLock(paths["lock"]):
            if modsecurity_cache_is_ready(record, paths, cache_root, inputs):
                return record
            missing = missing_modsecurity_build_dependency(env)
            if missing:
                record.update(
                    status="blocked",
                    blocker_reason="missing_modsecurity_dependency",
                    missing_dependency=missing,
                )
                write_cache_manifest(paths["manifest"], record)
                return record
            cache_error = discard_incomplete_modsecurity_cache_entries(record, paths, cache_root, inputs)
            if cache_error:
                record.update(status="blocked", blocker_reason=cache_error)
                return record
            staging_build, staging_prefix = modsecurity_staging_paths(paths, cache_root, str(inputs["cache_key"]))
            if not build_modsecurity_staging_entry(
                env,
                inputs,
                expat,
                source_path,
                staging_build,
                staging_prefix,
                log_path,
                record,
            ):
                return record
            publish_modsecurity_staging_entries(
                record,
                paths,
                cache_root,
                inputs,
                staging_build,
                staging_prefix,
            )
            staging_build = None
            staging_prefix = None
            return record
    except TimeoutError as exc:
        record.update(status="blocked", blocker_reason="cache_lock_timeout", details=str(exc), build_log=str(log_path))
        write_cache_manifest(paths["manifest"], record)
        return record
    except Exception as exc:
        write_component_log(log_path, [str(exc)])
        record.update(
            status="failed",
            blocker_reason=MODSECURITY_BUILD_FAILURE_BLOCKER,
            details=str(exc),
            build_exit_code=1,
            build_log=str(log_path),
        )
        write_cache_manifest(paths["manifest"], record)
        return record
    finally:
        cleanup_modsecurity_staging_entry(staging_build, cache_root)
        cleanup_modsecurity_staging_entry(staging_prefix, cache_root)


def prepare_shared_modsecurity(
    env: dict[str, str],
    cache_root: Path,
    build_root: Path,
    git_record: dict[str, Any],
    expat: dict[str, Any],
    connector_root: Path | None = None,
    framework_root: Path | None = None,
) -> dict[str, Any]:
    try:
        cache_root = ensure_managed_cache_root(cache_root)
    except RuntimeError as exc:
        return {"component": "modsecurity", "status": "blocked", "blocker_reason": str(exc)}
    inputs = modsecurity_build_inputs(env, git_record, expat, connector_root)
    build_id = inputs["build_id"]
    paths = shared_modsecurity_paths(cache_root, build_id)
    prefix = paths["prefix"]
    manifest_path = paths["manifest"]
    source_path = Path(str(git_record.get("path", ""))).resolve() if git_record.get("path") else Path()
    record: dict[str, Any] = {
        "component": "modsecurity",
        "name": "modsecurity",
        "source_url": inputs["source_url"],
        "source_ref": inputs["source_ref"],
        "actual_sha": inputs["actual_source_sha"],
        "build_id": build_id,
        "prefix": str(prefix),
        "include_dir": str(prefix / "include"),
        "lib_dir": str(prefix / "lib"),
        "lib_file": str(modsecurity_lib_file(prefix)),
        "pkg_config_path": str(prefix / "lib/pkgconfig"),
        "submodules_recursive": True,
        "submodule_status": inputs["recursive_submodule_status"],
        "build_flags": inputs["build_flags_text"],
        "dependency_hash": inputs["dependency_hash"],
        "compiler": inputs["compiler"],
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "cache_identity": inputs["cache_identity"],
        "cache_key": inputs["cache_key"],
        "patchset_sha256": inputs["patchset"]["sha256"],
        "target_architecture": inputs["cache_identity"]["target_architecture"],
        "build_root": str(paths["build_root"]),
        "manifest": str(manifest_path),
        "lock": str(paths["lock"]),
        "status": "unknown",
        "blocker_reason": "",
    }
    blocked_path = modsecurity_cache_path_blocker(paths, cache_root)
    if blocked_path:
        record.update(
            status="blocked",
            blocker_reason="system_path_write_forbidden",
            blocked_path=blocked_path,
        )
        return record
    provenance, preflight_blocker, details = modsecurity_source_preflight(
        env,
        git_record,
        framework_root,
        source_path,
    )
    if provenance is not None:
        record["provenance_verification"] = provenance
    if preflight_blocker:
        record.update(status="blocked", blocker_reason=preflight_blocker, details=details)
        return record
    root_blocker = prepare_modsecurity_build_root(record, paths, cache_root, inputs)
    if root_blocker:
        record.update(status="blocked", blocker_reason=root_blocker)
        return record
    if git_record.get("status") != "present":
        record.update(
            status="blocked",
            blocker_reason=git_record.get("blocker_reason") or "modsecurity_source_unavailable",
        )
        write_cache_manifest(manifest_path, record)
        return record
    return build_shared_modsecurity_cache(
        env,
        cache_root,
        build_root,
        expat,
        inputs,
        paths,
        source_path,
        record,
    )


def connector_input_paths(connector_root: Path, framework_root: Path, connector: str) -> list[Path]:
    common_paths = [connector_root / "common/include", connector_root / "common/src"]
    framework_script = {
        "apache": framework_root / "ci/provisioning/prepare-apache-build.sh",
        "nginx": framework_root / "ci/provisioning/prepare-nginx-build.sh",
        "haproxy": framework_root / "ci/provisioning/prepare-haproxy-runtime.sh",
    }.get(connector)
    paths = [connector_root / "connectors" / connector, *common_paths]
    if framework_script:
        paths.append(framework_script)
    if connector == "nginx":
        # The NGINX module uses the canonical profile registry in addition to
        # its materialized adapter/Common sources.  Bind both files directly
        # into the source hash so a registry-only revision cannot reuse an old
        # connector artifact when connector_commit is intentionally ignored.
        paths.extend(
            [
                connector_root / "connectors/profile_registry.c",
                connector_root / "connectors/profile_registry.h",
            ]
        )
        # common.sh owns the protocol profile defaults and pinned TLS source
        # inputs, so changing it must invalidate an NGINX host build.
        paths.append(framework_root / "ci/lib/common.sh")
    return paths


def connector_build_flags(
    env: dict[str, str],
    connector: str,
    nginx_protocol_inputs: dict[str, Any],
) -> dict[str, str]:
    """Return every cache-relevant connector build flag."""
    flags = {
        key: env.get(key, "")
        for key in (
            "CPPFLAGS",
            "CFLAGS",
            "CXXFLAGS",
            "LDFLAGS",
            "LIBS",
            "HTTPD_VERSION",
            "HTTPD_SOURCE_URL",
            "HTTPD_SHA256",
            "APR_VERSION",
            "APR_SOURCE_URL",
            "APR_SHA256",
            "APR_UTIL_VERSION",
            "APR_UTIL_SOURCE_URL",
            "APR_UTIL_SHA256",
            "APR_UTIL_SHA256_URL",
            "PCRE2_VERSION",
            "PCRE2_SOURCE_URL",
            "PCRE2_SHA256",
            "NGINX_SOURCE_MODE",
            "NGINX_RELEASE_TAG",
            "NGINX_SOURCE_GIT_REF",
            "NGINX_SOURCE_REPO_URL",
            "NGINX_RELEASE_ASSET_NAME",
            "NGINX_SHA256",
            "HAPROXY_VERSION",
            "HAPROXY_SOURCE_URL",
            "HAPROXY_SHA256",
        )
    }
    if connector == "nginx":
        flags.update(
            {
                "NGINX_PROTOCOL_PROFILE": str(nginx_protocol_inputs["profile"]),
                "NGINX_PROTOCOL_CONFIGURE_FLAGS": " ".join(
                    str(flag) for flag in nginx_protocol_inputs["configure_flags"]
                ),
                "NGINX_QUIC_TLS_LIBRARY": str(nginx_protocol_inputs["tls_library"]),
                "NGINX_QUIC_TLS_VERSION": str(nginx_protocol_inputs["tls_version"]),
                "NGINX_QUIC_TLS_SOURCE_URL": str(nginx_protocol_inputs["tls_source_url"]),
                "NGINX_QUIC_TLS_SOURCE_SHA256": str(nginx_protocol_inputs["tls_source_sha256"]),
            }
        )
    return flags


def connector_archive_inputs(
    connector: str,
    archives: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    archive_names = {
        "apache": {"httpd", "apr", "apr-util", "pcre2"},
        "nginx": {"nginx", "nginx-quic-tls"},
        "haproxy": {"haproxy"},
    }[connector]
    return {
        str(item.get("name")): {
            key: item.get(key, "")
            for key in (
                "url",
                "path",
                "status",
                "blocker_reason",
                "sha256",
                "expected_sha256",
                "resolved_tag",
                "checksum_status",
                "archive_list",
                "source_tuple",
                "source_mode",
                "source_repository",
                "release_tag",
                "source_ref",
                "release_asset_name",
                "release_asset_url",
                "verified_archive_sha256",
                "archive_digest_verified",
                "source_readback",
                "pinned_provenance",
                "provenance_validation",
                "cache_identity",
                "cache_key",
            )
        }
        for item in archives
        if isinstance(item, dict) and item.get("name") in archive_names
    }


def connector_upstream_details(connector: str, env: dict[str, str]) -> tuple[str, str, str]:
    """Return the version, source URL, and pinned commit for one connector."""
    if connector == "apache":
        return env.get("HTTPD_VERSION", ""), env.get("HTTPD_SOURCE_URL", ""), ""
    if connector == "nginx":
        return (
            env.get("NGINX_RELEASE_TAG", "") or env.get("NGINX_SOURCE_GIT_REF", ""),
            env.get("NGINX_SOURCE_REPO_URL", ""),
            env.get("NGINX_SOURCE_GIT_REF", ""),
        )
    return env.get("HAPROXY_VERSION", ""), env.get("HAPROXY_SOURCE_URL", ""), ""


def connector_cache_extra_inputs(
    connector: str,
    connector_root: Path,
    framework_root: Path,
    env: dict[str, str],
    archive_inputs: dict[str, dict[str, Any]],
    archive_source_hash: str,
    source_hash: str,
    modsecurity: dict[str, Any],
    expat: dict[str, Any],
    nginx_protocol_inputs: dict[str, Any],
) -> dict[str, Any]:
    common_commit = ""
    nginx_commit = ""
    if connector == "nginx":
        common_commit = git_revision(connector_root / "common")
        nginx_commit = env.get("NGINX_SOURCE_GIT_REF", "")
    return {
        "archives": archive_inputs,
        "archive_source_hash": archive_source_hash,
        "connector_source_hash": source_hash,
        "modsecurity_build_id": modsecurity.get("build_id", ""),
        "expat_build_id": expat.get("build_id", ""),
        "common_commit": common_commit,
        "nginx_protocol_build": nginx_protocol_inputs,
        "nginx_commit": nginx_commit,
        "connector_commit": git_revision(connector_root),
        "framework_commit": git_revision(framework_root),
    }


def connector_output_layout(connector: str, root: Path) -> dict[str, Any]:
    """Describe the connector-specific cache layout without sharing build logic."""
    if connector == "apache":
        return {
            "build_root": str(root / "build"),
            "httpd_prefix": str(root / "httpd"),
            "output_paths": {
                "binary": str(root / "httpd/bin/httpd"),
                "module": str(root / "build/output/apache/mod_security3.so"),
                "config": str(root / "httpd/conf/httpd.conf"),
            },
        }
    if connector == "nginx":
        return {
            "build_root": str(root / "build"),
            "nginx_prefix": str(root / "nginx"),
            "output_paths": {
                "binary": str(root / "nginx/sbin/nginx"),
                "module": str(root / "nginx/modules" / NGINX_MODULE_FILENAME),
                "config": str(root / "nginx/conf/nginx.conf"),
            },
        }
    if connector == "haproxy":
        return {
            "build_root": str(root),
            # HAProxy's connector-cache entry owns identity/provenance and its
            # manifest, not mutable runtime artifacts.  The invocation-local
            # output paths are recorded after they are derived from BUILD_ROOT.
            "output_paths": {},
        }
    return {}


def connector_plan(
    connector_root: Path,
    framework_root: Path,
    cache_root: Path,
    env: dict[str, str],
    connector: str,
    modsecurity: dict[str, Any],
    expat: dict[str, Any],
    archives: list[dict[str, Any]],
) -> dict[str, Any]:
    source_paths = connector_input_paths(connector_root, framework_root, connector)
    source_hash = hash_input_paths(source_paths)
    patchset = patchset_identity(component_patchset_roots(connector_root, connector))
    nginx_protocol_inputs = nginx_protocol_build_inputs(env) if connector == "nginx" else {}
    build_flags = connector_build_flags(env, connector, nginx_protocol_inputs)
    archive_inputs = connector_archive_inputs(connector, archives)
    toolchain = toolchain_identity(env)
    archive_source_hash = stable_hash(archive_inputs)
    upstream_version, upstream_url, upstream_commit = connector_upstream_details(connector, env)
    cache_identity = canonical_cache_identity(
        connector,
        env=env,
        upstream_url=upstream_url,
        upstream_version=upstream_version,
        upstream_commit=upstream_commit,
        source_sha256=archive_source_hash,
        patchset_sha256=str(patchset["sha256"]),
        configuration_flags=build_flags,
        toolchain=toolchain,
        extra_inputs=connector_cache_extra_inputs(
            connector,
            connector_root,
            framework_root,
            env,
            archive_inputs,
            archive_source_hash,
            source_hash,
            modsecurity,
            expat,
            nginx_protocol_inputs,
        ),
    )
    payload = {
        "connector": connector,
        "source_hash": source_hash,
        "build_flags": build_flags,
        "compiler": toolchain,
        "archives": archive_inputs,
        "modsecurity_build_id": modsecurity.get("build_id", ""),
        "dependency_prefixes": {
            "modsecurity_prefix": modsecurity.get("prefix", ""),
            "expat_prefix": expat.get("prefix", ""),
            "expat_build_id": expat.get("build_id", ""),
        },
        "patchset": patchset,
        "nginx_protocol_build": nginx_protocol_inputs,
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "cache_identity": cache_identity,
    }
    build_id = cache_identity["cache_key"]
    root = cache_root / "builds/connectors" / connector / build_id
    plan = {
        "connector": connector,
        "connector_build_id": build_id,
        "modsecurity_build_id": modsecurity.get("build_id", ""),
        "source_hash": source_hash,
        "source_inputs": [str(path) for path in source_paths],
        "build_flags": json.dumps(build_flags, sort_keys=True),
        "compiler": payload["compiler"],
        "archive_inputs": archive_inputs,
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "cache_identity": cache_identity,
        "cache_key": cache_identity["cache_key"],
        "patchset_sha256": patchset["sha256"],
        "patchset_files": patchset["files"],
        "nginx_protocol_build": nginx_protocol_inputs,
        "target_architecture": cache_identity["target_architecture"],
        "cache_root": str(cache_root),
        "root": str(root),
        "manifest": str(root / CACHE_MANIFEST_FILENAME),
        "status": "unknown",
        "blocker_reason": "",
    }
    plan.update(connector_output_layout(connector, root))
    return reuse_connector_cache_entry_if_only_commit_changed(plan)


def connector_manifest_contract_ready(plan: dict[str, Any]) -> bool:
    """Validate the local connector manifest, without treating it as a hit."""
    manifest_path = Path(str(plan.get("manifest", "")))
    identity = plan.get("cache_identity")
    if not isinstance(identity, dict) or not cache_manifest_complete(manifest_path, identity):
        return False
    manifest = read_json(manifest_path)
    return (
        manifest.get("connector_build_id") == plan.get("connector_build_id")
        and manifest.get("modsecurity_build_id") == plan.get("modsecurity_build_id")
        and manifest.get("source_hash") == plan.get("source_hash")
    )


def connector_manifest_ready(plan: dict[str, Any]) -> bool:
    """A connector cache hit additionally requires registry completion."""
    if not connector_manifest_contract_ready(plan):
        return False
    cache_root_value = plan.get("cache_root")
    root_value = plan.get("root")
    cache_key = plan.get("cache_key", plan.get("connector_build_id", ""))
    identity = plan.get("cache_identity")
    if (
        not isinstance(cache_root_value, str)
        or not cache_root_value
        or not isinstance(root_value, str)
        or not root_value
        or not isinstance(cache_key, str)
        or not cache_key
        or not isinstance(identity, dict)
    ):
        return False
    try:
        return cache_entry_complete(
            Path(root_value),
            Path(cache_root_value),
            component=f"connector:{plan.get('connector', 'unknown')}",
            cache_key=cache_key,
            cache_identity=identity,
        )
    except OSError:
        return False


def write_connector_manifest(plan: dict[str, Any], record: dict[str, Any]) -> None:
    cache_root_value = plan.get("cache_root")
    root_value = plan.get("root")
    if isinstance(cache_root_value, str) and cache_root_value and isinstance(root_value, str) and root_value:
        cache_root = Path(cache_root_value)
        root = Path(root_value)
        try:
            # Claim a planned, absent root before `write_json` creates it.  If
            # it already exists, it must already be marker- or
            # complete-manifest-owned; never bless an arbitrary cache child.
            mark_managed_cache_entry(
                root,
                cache_root,
                component=f"connector:{plan.get('connector', 'unknown')}",
                cache_key=str(plan.get("cache_key", "")),
            )
        except RuntimeError:
            return
    manifest = dict(plan)
    manifest.pop("root", None)
    manifest.update(
        status=record.get("status", "blocked"),
        blocker_reason=record.get("blocker_reason", ""),
        invalidation_reason=record.get("invalidation_reason", ""),
        output_paths=record.get("output_paths", plan.get("output_paths", {})),
        generated_at=utc_now(),
    )
    write_cache_manifest(Path(str(plan["manifest"])), manifest)


def go_main_packages(source_path: Path, env: dict[str, str], log_parts: list[str]) -> tuple[list[str], subprocess.CompletedProcess[str]]:
    proc = run_env(
        ["go", "list", "-mod=readonly", "-f", "{{if eq .Name \"main\"}}{{.ImportPath}}{{end}}", "./..."],
        cwd=source_path,
        env=env,
    )
    append_command_log(log_parts, "go-list-main-packages", proc)
    packages = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return packages, proc


def go_tool_blocked_record(
    record: dict[str, Any],
    optional: bool,
    reason: str,
    **extra: Any,
) -> dict[str, Any]:
    record.update(
        status="blocked_optional" if optional else "blocked",
        blocker_reason=reason,
        **extra,
    )
    return record


def go_tool_record(
    dependency: str,
    env_var: str,
    build_root: Path,
    git_record: dict[str, Any],
) -> dict[str, Any]:
    log_path = build_root / f"logs/runtime-components/{dependency}-build.log"
    source_path = Path(git_record.get("path", "")).resolve() if git_record.get("path") else Path()
    return {
        "dependency": dependency,
        "name": dependency,
        "source": git_record.get("source", git_record.get("url", "")),
        "known_source": git_record.get("source", git_record.get("url", "")),
        "known_source_url": git_record.get("source", git_record.get("url", "")),
        "expected_ref": git_record.get("expected_ref", ""),
        "known_ref": git_record.get("expected_ref", ""),
        "release_tag": git_record.get("release_tag", git_record.get("expected_ref", "")),
        "release_url": git_record.get("release_url", ""),
        "expected_prompt_latest": git_record.get("expected_prompt_latest", ""),
        "release_tag_deviation": git_record.get("release_tag_deviation", False),
        "release_tag_deviation_note": git_record.get("release_tag_deviation_note", ""),
        "actual_head": git_record.get("actual_head", ""),
        "recursive_submodules": True,
        "recursive_submodule_status": git_record.get("submodule_status", ""),
        "submodule_status_clean": git_record.get("submodule_status_clean", False),
        "git_fsck": git_record.get("git_fsck", ""),
        "path": "",
        "binary": "",
        "source_path": str(source_path) if str(source_path) != "." else "",
        "searched_paths": [],
        "env_override": env_var,
        "can_build_locally": True,
        "build_log": str(log_path),
        "status": "unknown",
        "blocker_reason": "",
        "optional": False,
    }


def go_tool_cache_hit(
    binary_path: Path,
    manifest_path: Path,
    entry_root: Path,
    cache_root: Path,
    dependency: str,
    cache_identity: dict[str, Any],
) -> bool:
    return (
        executable(binary_path)
        and cache_manifest_complete(manifest_path, cache_identity)
        and cache_entry_complete(
            entry_root,
            cache_root,
            component=f"go:{dependency}",
            cache_key=str(cache_identity["cache_key"]),
            cache_identity=cache_identity,
        )
    )


def remove_stale_go_cache_entry(
    entry_root: Path,
    cache_root: Path,
    dependency: str,
    record: dict[str, Any],
) -> bool:
    if not entry_root.exists():
        return True
    if not managed_cache_entry_valid(entry_root, cache_root):
        if not migrate_legacy_cache_entry_for_removal(
            entry_root,
            cache_root,
            component=f"go:{dependency}",
        ):
            return False
        record.update(
            rebuild_required=True,
            invalidation_reason="cache_schema_changed",
            old_entry_removed=True,
        )
    safe_remove_dir(entry_root, cache_root)
    record.setdefault("rebuild_required", True)
    record.setdefault("invalidation_reason", "missing_or_incomplete_go_cache")
    record.setdefault("old_entry_removed", True)
    return True


def build_go_tool_in_staging(
    dependency: str,
    source_path: Path,
    cache_root: Path,
    entry_root: Path,
    staging_path: Path,
    cache_identity: dict[str, Any],
    record: dict[str, Any],
    optional: bool,
    log_path: Path,
) -> dict[str, Any]:
    staging_binary = staging_path / "bin" / dependency
    staging_manifest = staging_path / CACHE_MANIFEST_FILENAME
    build_env_vars = local_build_env(os.environ, cache_root)
    build_env_vars["PATH"] = os.environ.get("PATH", "")
    log_parts: list[str] = []
    version_proc = run_env(["go", "version"], env=build_env_vars)
    append_command_log(log_parts, "go-version", version_proc)
    packages, list_proc = go_main_packages(source_path, build_env_vars, log_parts)
    if list_proc.returncode != 0:
        write_component_log(log_path, log_parts)
        return go_tool_blocked_record(record, optional, "go_list_failed", build_exit_code=list_proc.returncode)
    if not packages:
        write_component_log(log_path, log_parts)
        return go_tool_blocked_record(record, optional, "go_main_package_not_found")
    if len(packages) > 1:
        write_component_log(log_path, log_parts)
        return go_tool_blocked_record(record, optional, "go_multiple_main_packages", main_packages=packages)
    build_package = packages[0]
    staging_binary.parent.mkdir(parents=True, exist_ok=True)
    proc = run_env(
        ["go", "build", "-trimpath", "-mod=readonly", "-o", str(staging_binary), build_package],
        cwd=source_path,
        env=build_env_vars,
    )
    append_command_log(log_parts, "go-build", proc)
    write_component_log(log_path, log_parts)
    if proc.returncode != 0:
        return go_tool_blocked_record(record, optional, "go_build_failed", build_exit_code=proc.returncode)
    if not executable(staging_binary):
        return go_tool_blocked_record(record, optional, "go_binary_missing_after_build")
    staged_record = dict(record)
    staged_record.update(
        status="built",
        build_package=build_package,
        go_version=version_proc.stdout.strip(),
        tree=tree_manifest(staging_path),
        generated_at=utc_now(),
    )
    write_cache_manifest(staging_manifest, staged_record)
    write_cache_entry_completion(
        staging_path,
        cache_root,
        component=f"go:{dependency}",
        cache_key=str(cache_identity["cache_key"]),
        cache_identity=cache_identity,
    )
    atomic_publish_dir(staging_path, entry_root, cache_root, require_complete=True)
    record.update(
        status="built",
        build_package=build_package,
        go_version=version_proc.stdout.strip(),
        tree=tree_manifest(entry_root),
        generated_at=utc_now(),
    )
    return record


def prepare_go_tool_cache_entry(
    dependency: str,
    cache_root: Path,
    entry_root: Path,
    binary_path: Path,
    manifest_path: Path,
    source_path: Path,
    cache_identity: dict[str, Any],
    record: dict[str, Any],
    optional: bool,
    log_path: Path,
) -> dict[str, Any]:
    previous = read_json(manifest_path)
    if go_tool_cache_hit(
        binary_path,
        manifest_path,
        entry_root,
        cache_root,
        dependency,
        cache_identity,
    ):
        record.update(
            status="present",
            build_package=previous.get("build_package", ""),
            go_version=previous.get("go_version", ""),
        )
        return record
    if not remove_stale_go_cache_entry(entry_root, cache_root, dependency, record):
        return go_tool_blocked_record(
            record,
            optional,
            unmanaged_cache_entry_marker_missing(entry_root),
        )
    staging_path: Path | None = None
    try:
        staging_path = temporary_cache_dir(
            entry_root,
            cache_root,
            component=f"go:{dependency}",
            cache_key=str(cache_identity["cache_key"]),
        )
        return build_go_tool_in_staging(
            dependency,
            source_path,
            cache_root,
            entry_root,
            staging_path,
            cache_identity,
            record,
            optional,
            log_path,
        )
    finally:
        if staging_path is not None and staging_path.exists():
            try:
                safe_remove_dir(staging_path, cache_root)
            except RuntimeError:
                pass


def prepare_go_tool(
    dependency: str,
    env_var: str,
    cache_root: Path,
    build_root: Path,
    git_record: dict[str, Any],
    optional: bool = False,
) -> dict[str, Any]:
    env = dict(os.environ)
    try:
        cache_root = ensure_managed_cache_root(cache_root)
    except RuntimeError as exc:
        return {
            "dependency": dependency,
            "name": dependency,
            "status": "blocked_optional" if optional else "blocked",
            "blocker_reason": str(exc),
            "optional": optional,
        }
    record = go_tool_record(dependency, env_var, build_root, git_record)
    record["optional"] = optional
    source_path = Path(str(record["source_path"])) if record["source_path"] else Path()
    log_path = Path(str(record["build_log"]))

    if git_record.get("status") != "present":
        return go_tool_blocked_record(
            record,
            optional,
            git_record.get("blocker_reason") or f"{dependency}_source_unavailable",
        )
    go_bin = shutil.which("go")
    if not go_bin:
        return go_tool_blocked_record(record, optional, "missing_go")
    go_toolchain = toolchain_identity(env)
    go_toolchain["go"] = command_text([go_bin, "version"], env=env)
    cache_identity = canonical_cache_identity(
        dependency,
        env=env,
        upstream_url=str(record["source"]),
        upstream_version=str(record["release_tag"]),
        upstream_commit=str(record["actual_head"]),
        source_sha256=str(record["actual_head"]),
        patchset_sha256=patchset_identity([])["sha256"],
        configuration_flags={"go_build_flags": "-trimpath -mod=readonly"},
        toolchain=go_toolchain,
    )
    record.update(
        cache_schema_version=CACHE_SCHEMA_VERSION,
        cache_identity=cache_identity,
        cache_key=cache_identity["cache_key"],
    )
    entry_root = (cache_root / "builds/go" / dependency / str(cache_identity["cache_key"])).resolve()
    binary_path = entry_root / "bin" / dependency
    manifest_path = entry_root / CACHE_MANIFEST_FILENAME
    if is_system_path(entry_root) or not is_within(entry_root, cache_root):
        return go_tool_blocked_record(record, optional, "system_path_write_forbidden")
    record.update(
        path=str(binary_path),
        binary=str(binary_path),
        searched_paths=[str(binary_path)],
        build_path=str(entry_root),
        manifest=str(manifest_path),
    )
    try:
        with BuildLock(cache_entry_lock_path(cache_root, f"go-{dependency}", str(cache_identity["cache_key"]))):
            return prepare_go_tool_cache_entry(
                dependency,
                cache_root,
                entry_root,
                binary_path,
                manifest_path,
                source_path,
                cache_identity,
                record,
                optional,
                log_path,
            )
    except TimeoutError as exc:
        return go_tool_blocked_record(record, optional, "cache_lock_timeout", details=str(exc))


def apache_log_reports_missing_expat_header(text: str) -> bool:
    """Match the compiler's single-line Expat-header diagnostic safely.

    This keeps the former diagnosis order (``error:``, then ``expat.h``, then
    the missing-file phrase) without applying an unbounded wildcard to a
    build log whose length is outside this function's control.
    """
    for line in text.lower().splitlines():
        error_index = line.find("error:")
        header_index = line.find(EXPAT_HEADER_FILENAME, error_index + 1)
        if error_index < 0 or header_index < 0:
            continue
        suffix = line[header_index + len(EXPAT_HEADER_FILENAME) :]
        if MISSING_FILE_TEXT in suffix or MISSING_COMMAND_TEXT in suffix:
            return True
    return False


def map_apache_blocker(text: str, missing: list[str]) -> str:
    lowered = text.lower()
    if "undefined reference to `crypt" in lowered or "undefined reference to 'crypt" in lowered:
        return "missing_crypt_library"
    # Build commands legitimately contain the managed Expat prefix.  Do not
    # turn an unrelated connector compilation error into a missing-header
    # diagnosis merely because that prefix appears in the command line.
    if apache_log_reports_missing_expat_header(text):
        return "missing_expat_headers"
    if "missing required command" in lowered or MISSING_COMMAND_TEXT in lowered:
        return "missing_apache_build_dependency"
    if any(item.startswith("modsecurity_lib:") for item in missing) or any(
        marker in lowered
        for marker in (
            "cannot find -lmodsecurity",
            "cannot find libmodsecurity",
            "libmodsecurity.so: cannot open shared object file",
        )
    ):
        return "missing_libmodsecurity_build"
    if re.search(r"(?m)^.+:\d+(?::\d+)?: (?:fatal )?error:", text) or "apxs:error:" in lowered:
        return "apache_connector_build_failed"
    return "missing_local_httpd_build"


def map_nginx_blocker(text: str, missing: list[str]) -> str:
    lowered = text.lower()
    if any(item.startswith("modsecurity_lib:") for item in missing) or "libmodsecurity" in lowered:
        return "missing_libmodsecurity_build"
    if "missing required command" in lowered or MISSING_COMMAND_TEXT in lowered:
        return "missing_nginx_build_dependency"
    if re.search(r"(?m)^.+:\d+(?::\d+)?: (?:fatal )?error:", text):
        return "nginx_connector_build_failed"
    if any(item.startswith("module_file:") for item in missing):
        return "missing_nginx_modsecurity_module"
    return "missing_local_nginx_build"


def apache_apxs_includedir_usable(httpd_prefix: Path) -> bool:
    """Return whether an installed Apache ``apxs`` resolves its include dir.

    Merely checking that the generated Perl script is executable is not
    enough: it can still point at the vanished atomic staging directory.  The
    query is deliberately narrow, side-effect free, and also verifies that
    the reported directory belongs to the published prefix.
    """
    prefix = httpd_prefix.resolve(strict=False)
    apxs_bin = prefix / APACHE_APXS_RELATIVE_PATH
    expected_include = prefix / "include"
    if not executable(apxs_bin) or not expected_include.is_dir():
        return False
    try:
        proc = subprocess.run(
            [str(apxs_bin), "-q", "INCLUDEDIR"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0 and proc.stdout.strip() == str(expected_include)


def apache_install_text_paths(httpd_prefix: Path) -> list[Path]:
    """Return the installed Apache text files allowed to carry its prefix."""
    paths = [httpd_prefix / relative for relative in APACHE_INSTALL_TEXT_PATHS]
    config_root = httpd_prefix / "conf"
    if config_root.is_dir() and not config_root.is_symlink():
        paths.extend(sorted(config_root.rglob("*.conf")))
    return paths


def apache_publication_paths(
    staged_plan: dict[str, Any],
    final_root: Path,
) -> tuple[Path, Path, Path]:
    """Validate the staging and final paths used by Apache publication."""
    root_value = staged_plan.get("root")
    prefix_value = staged_plan.get("httpd_prefix")
    if not isinstance(root_value, str) or not root_value:
        raise RuntimeError("apache_publication_paths_missing")
    if not isinstance(prefix_value, str) or not prefix_value:
        raise RuntimeError("apache_publication_paths_missing")
    return (
        Path(root_value).resolve(),
        Path(prefix_value).resolve(),
        final_root.resolve(strict=False),
    )


def validate_apache_staging_prefix(staging_root: Path, staging_prefix: Path) -> None:
    if not is_within(staging_prefix, staging_root):
        raise RuntimeError(f"apache_publication_prefix_outside_staging_root: {staging_prefix}")
    if not staging_prefix.is_dir() or staging_prefix.is_symlink():
        raise RuntimeError(f"apache_publication_prefix_missing: {staging_prefix}")


def rebase_apache_install_text_path(
    path: Path,
    staging_bytes: bytes,
    published_bytes: bytes,
) -> None:
    if not path.exists():
        return
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"apache_publication_text_path_invalid: {path}")
    content = path.read_bytes()
    if staging_bytes not in content:
        return
    if b"\0" in content:
        raise RuntimeError(f"apache_publication_text_path_contains_nul: {path}")
    mode = path.stat().st_mode & 0o777
    atomic_write_bytes(path, content.replace(staging_bytes, published_bytes))
    path.chmod(mode)


def validate_apache_published_text_paths(staging_prefix: Path, staging_bytes: bytes) -> None:
    for relative in (APACHE_APXS_RELATIVE_PATH, "build/config_vars.mk"):
        path = staging_prefix / relative
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"apache_publication_required_text_path_missing: {path}")
        if staging_bytes in path.read_bytes():
            raise RuntimeError(f"apache_publication_staging_reference_remaining: {path}")


def rebase_apache_install_text_paths_for_publish(
    staged_plan: dict[str, Any],
    final_root: Path,
) -> None:
    """Rebase known Apache install text files before atomically publishing.

    httpd's installed ``apxs`` and its configuration helpers contain absolute
    paths to the configured prefix.  Cache-v2 builds that prefix below a
    temporary sibling directory, then renames the complete tree.  Rewrite
    only the allowlisted text artifacts here; linked executables and modules
    are intentionally left byte-for-byte untouched.
    """
    staging_root, staging_prefix, published_root = apache_publication_paths(staged_plan, final_root)
    validate_apache_staging_prefix(staging_root, staging_prefix)

    staging_bytes = os.fsencode(str(staging_root))
    published_bytes = os.fsencode(str(published_root))
    for path in apache_install_text_paths(staging_prefix):
        rebase_apache_install_text_path(path, staging_bytes, published_bytes)

    # These are the two files required for `apxs -q INCLUDEDIR`; ensure a
    # staging reference can never reach the final cache entry unnoticed.
    validate_apache_published_text_paths(staging_prefix, staging_bytes)


def connector_cache_entry_complete(plan: dict[str, Any]) -> bool:
    """A connector entry is a hit only with its manifest and declared outputs."""
    if not connector_manifest_ready(plan):
        return False
    if not connector_output_paths_ready(plan):
        return False
    return connector_apache_artifacts_ready(plan)


def connector_output_paths_ready(plan: dict[str, Any]) -> bool:
    output_paths = plan.get("output_paths")
    if not isinstance(output_paths, dict):
        return False
    for name, raw_path in output_paths.items():
        if not isinstance(raw_path, str) or not raw_path:
            return False
        path = Path(raw_path)
        if name == "binary":
            if not executable(path):
                return False
        elif not path.is_file():
            return False
    return True


def connector_apache_artifacts_ready(plan: dict[str, Any]) -> bool:
    if plan.get("connector") != "apache":
        return True
    httpd_prefix = plan.get("httpd_prefix")
    return isinstance(httpd_prefix, str) and bool(httpd_prefix) and apache_apxs_includedir_usable(
        Path(httpd_prefix)
    )


def cache_identity_is_self_consistent(identity: Any) -> bool:
    """Return whether a cache identity still hashes to its declared key."""
    if not isinstance(identity, dict):
        return False
    cache_key = identity.get("cache_key")
    if not isinstance(cache_key, str) or not cache_key:
        return False
    if identity.get("cache_schema_version") != CACHE_SCHEMA_VERSION:
        return False
    payload = dict(identity)
    payload.pop("cache_key", None)
    return stable_hash(payload) == cache_key


def connector_cache_identity_equivalent_ignoring_connector_commit(
    candidate: Any,
    requested: Any,
) -> bool:
    """Compare all connector build inputs except a differing root revision.

    ``connector_commit`` is deliberately a broad provenance input.  A
    top-level runner-only change should not force a source download and host
    rebuild when every connector build input below remains byte-for-byte the
    same.  This compatibility comparison is intentionally narrow: both
    identities must validate their own keys, both commits must be present and
    different, and every other field stays part of the equality check.
    """
    if not cache_identity_is_self_consistent(candidate) or not cache_identity_is_self_consistent(requested):
        return False
    try:
        candidate_payload = json.loads(json.dumps(candidate, sort_keys=True))
        requested_payload = json.loads(json.dumps(requested, sort_keys=True))
    except (TypeError, ValueError):
        return False
    candidate_payload.pop("cache_key", None)
    requested_payload.pop("cache_key", None)
    candidate_inputs = candidate_payload.get("extra_inputs")
    requested_inputs = requested_payload.get("extra_inputs")
    if not isinstance(candidate_inputs, dict) or not isinstance(requested_inputs, dict):
        return False
    candidate_commit = candidate_inputs.pop("connector_commit", "")
    requested_commit = requested_inputs.pop("connector_commit", "")
    return (
        isinstance(candidate_commit, str)
        and bool(candidate_commit)
        and isinstance(requested_commit, str)
        and bool(requested_commit)
        and candidate_commit != requested_commit
        and candidate_payload == requested_payload
    )


def connector_cache_reuse_request(plan: dict[str, Any]) -> dict[str, Any] | None:
    connector = plan.get("connector")
    cache_root_value = plan.get("cache_root")
    requested_identity = plan.get("cache_identity")
    requested_key = plan.get("cache_key")
    if not isinstance(connector, str) or not connector:
        return None
    if not isinstance(cache_root_value, str) or not cache_root_value:
        return None
    if not isinstance(requested_key, str) or not requested_key:
        return None
    if not cache_identity_is_self_consistent(requested_identity):
        return None
    requested_inputs = requested_identity.get("extra_inputs")
    requested_commit = ""
    if isinstance(requested_inputs, dict):
        requested_commit = str(requested_inputs.get("connector_commit", ""))
    return {
        "connector": connector,
        "cache_root": Path(cache_root_value),
        "requested_identity": requested_identity,
        "requested_key": requested_key,
        "requested_commit": requested_commit,
    }


def connector_cache_reuse_candidates(
    cache_root: Path,
    connector: str,
) -> tuple[Path, list[Path]] | None:
    if not cache_root_marker_valid(cache_root):
        return None
    candidate_parent = cache_root / "builds" / "connectors" / connector
    try:
        candidates = sorted(candidate_parent.iterdir(), key=lambda path: path.name)
    except OSError:
        return None
    return candidate_parent, candidates


def managed_connector_cache_candidate(
    candidate_root: Path,
    candidate_parent: Path,
    cache_root: Path,
) -> Path | None:
    if candidate_root.is_symlink() or not candidate_root.is_dir():
        return None
    try:
        resolved_candidate, _ = validate_managed_cache_child(candidate_root, cache_root)
    except RuntimeError:
        return None
    if resolved_candidate.parent != candidate_parent.resolve(strict=False):
        return None
    return resolved_candidate


def connector_reusable_candidate_plan(
    plan: dict[str, Any],
    candidate_root: Path,
    connector: str,
    requested_identity: dict[str, Any],
    requested_key: str,
    requested_commit: str,
) -> dict[str, Any] | None:
    manifest = read_json(candidate_root / CACHE_MANIFEST_FILENAME)
    candidate_identity = manifest.get("cache_identity")
    candidate_key = manifest.get("cache_key")
    if manifest.get("connector") != connector:
        return None
    if not isinstance(candidate_key, str) or candidate_key != candidate_root.name:
        return None
    if not connector_cache_identity_equivalent_ignoring_connector_commit(
        candidate_identity,
        requested_identity,
    ):
        return None
    candidate_inputs = candidate_identity["extra_inputs"]
    candidate_plan = staged_connector_plan(plan, candidate_root)
    candidate_plan.update(
        connector_build_id=candidate_key,
        cache_identity=candidate_identity,
        cache_key=candidate_key,
        requested_cache_identity=requested_identity,
        requested_cache_key=requested_key,
        requested_connector_commit=requested_commit,
        reused_from_connector_commit=str(candidate_inputs["connector_commit"]),
        cache_reuse_reason="connector_commit_only",
    )
    return candidate_plan


def reuse_connector_cache_entry_if_only_commit_changed(plan: dict[str, Any]) -> dict[str, Any]:
    """Adopt one complete managed connector entry with matching scoped inputs.

    This is read-only cache discovery.  It never marks, repairs, removes, or
    trusts an entry solely because its directory exists.  The adopted plan
    uses the current canonical layout rebased to the candidate root instead
    of accepting output paths embedded in a cache manifest.
    """
    request = connector_cache_reuse_request(plan)
    if request is None:
        return plan
    candidates = connector_cache_reuse_candidates(request["cache_root"], request["connector"])
    if candidates is None:
        return plan
    candidate_parent, candidate_roots = candidates
    for candidate_root in candidate_roots:
        resolved_candidate = managed_connector_cache_candidate(
            candidate_root,
            candidate_parent,
            request["cache_root"],
        )
        if resolved_candidate is None:
            continue
        candidate_plan = connector_reusable_candidate_plan(
            plan,
            resolved_candidate,
            request["connector"],
            request["requested_identity"],
            request["requested_key"],
            request["requested_commit"],
        )
        if candidate_plan is not None and connector_cache_entry_complete(candidate_plan):
            return candidate_plan
    return plan


def rebase_cache_path(path: Path, source_root: Path, destination_root: Path) -> Path:
    resolved = path.resolve(strict=False)
    try:
        return destination_root / resolved.relative_to(source_root)
    except ValueError:
        return resolved


def staged_connector_plan(plan: dict[str, Any], staging_root: Path) -> dict[str, Any]:
    """Clone a connector plan with every entry-local path rebased to staging."""
    final_root = Path(str(plan["root"])).resolve()
    staged = dict(plan)
    staged["root"] = str(staging_root)
    for key in ("manifest", "build_root", "httpd_prefix", "nginx_prefix"):
        raw_path = plan.get(key)
        if isinstance(raw_path, str) and raw_path:
            staged[key] = str(rebase_cache_path(Path(raw_path), final_root, staging_root))
    output_paths = plan.get("output_paths")
    if isinstance(output_paths, dict):
        staged["output_paths"] = {
            name: str(rebase_cache_path(Path(raw_path), final_root, staging_root))
            if isinstance(raw_path, str) and raw_path
            else raw_path
            for name, raw_path in output_paths.items()
        }
    return staged


def rebase_cache_record(value: Any, source_root: Path, destination_root: Path) -> Any:
    if isinstance(value, dict):
        return {key: rebase_cache_record(item, source_root, destination_root) for key, item in value.items()}
    if isinstance(value, list):
        return [rebase_cache_record(item, source_root, destination_root) for item in value]
    if isinstance(value, str):
        try:
            path = Path(value)
            if path.is_absolute():
                # Records contain both entry-local artifact paths and stable
                # identity inputs such as /usr/bin/cc.  Only a path already
                # lexically under the staging tree is eligible for resolving
                # and rebasing.  External strings must remain byte-for-byte
                # unchanged: normalizing a compiler symlink after cache_key
                # calculation makes the published manifest disagree with its
                # registry marker and turns every later invocation into a
                # cache miss.
                source = source_root.resolve(strict=False)
                try:
                    path.relative_to(source)
                except ValueError:
                    # Do not even canonicalize a foreign spelling such as
                    # /usr/bin/cc; it is an identity value, not an artifact.
                    return value
                resolved = path.resolve(strict=False)
                relative = resolved.relative_to(source)
                return str(destination_root / relative)
        except (OSError, RuntimeError, ValueError):
            pass
    return value


def remove_incomplete_connector_cache_entry(
    final_root: Path,
    managed_root: Path,
    connector: str,
) -> bool:
    """Remove only an owned stale connector entry before making staging."""
    if not final_root.exists():
        return True
    migration_required = not managed_cache_entry_valid(final_root, managed_root)
    if migration_required and not migrate_legacy_cache_entry_for_removal(
        final_root,
        managed_root,
        component=f"connector:{connector}",
    ):
        return False
    safe_remove_dir(final_root, managed_root)
    return True


def rebase_apache_staging_for_publication(
    connector: str,
    staged_plan: dict[str, Any],
    final_root: Path,
    record: dict[str, Any],
    staging_root: Path,
) -> dict[str, Any] | None:
    if connector != "apache":
        return None
    try:
        rebase_apache_install_text_paths_for_publish(staged_plan, final_root)
    except RuntimeError as exc:
        failed_record = rebase_cache_record(record, staging_root, final_root)
        failed_record.update(
            status="failed",
            blocker_reason="apache_publication_relocation_failed",
            details=str(exc),
        )
        return failed_record
    return None


def apache_publish_validation_failure(
    connector: str,
    plan: dict[str, Any],
    final_root: Path,
    managed_root: Path,
    published_record: dict[str, Any],
) -> dict[str, Any] | None:
    if connector != "apache":
        return None
    if apache_apxs_includedir_usable(Path(str(plan.get("httpd_prefix", "")))):
        return None
    try:
        safe_remove_dir(final_root, managed_root)
    except RuntimeError as exc:
        published_record.update(
            status="failed",
            blocker_reason="apache_apxs_publish_validation_failed",
            details=str(exc),
        )
    else:
        published_record.update(
            status="failed",
            blocker_reason="apache_apxs_publish_validation_failed",
        )
    return published_record


def publish_connector_staging(
    connector: str,
    cache_key: str,
    plan: dict[str, Any],
    prepare: Any,
    staging_root: Path,
    final_root: Path,
    managed_root: Path,
) -> dict[str, Any]:
    staged_plan = staged_connector_plan(plan, staging_root)
    record = prepare(staged_plan, True)
    if record.get("status") != "built" or not connector_manifest_contract_ready(staged_plan):
        return rebase_cache_record(record, staging_root, final_root)
    apache_relocation_failure = rebase_apache_staging_for_publication(
        connector,
        staged_plan,
        final_root,
        record,
        staging_root,
    )
    if apache_relocation_failure is not None:
        return apache_relocation_failure
    write_cache_entry_completion(
        staging_root,
        managed_root,
        component=f"connector:{connector}",
        cache_key=cache_key,
        cache_identity=staged_plan["cache_identity"],
    )
    atomic_publish_dir(staging_root, final_root, managed_root, require_complete=True)
    published_record = rebase_cache_record(record, staging_root, final_root)
    apache_failure = apache_publish_validation_failure(
        connector,
        plan,
        final_root,
        managed_root,
        published_record,
    )
    if apache_failure is not None:
        return apache_failure
    write_connector_manifest(plan, published_record)
    return published_record


def prepare_connector_under_lock(
    connector: str,
    cache_key: str,
    plan: dict[str, Any],
    prepare: Any,
    final_root: Path,
    managed_root: Path,
) -> dict[str, Any]:
    if connector_cache_entry_complete(plan):
        return prepare(plan, True)
    if not remove_incomplete_connector_cache_entry(final_root, managed_root, connector):
        return prepare(plan, True)
    staging_root = temporary_cache_dir(
        final_root,
        managed_root,
        component=f"connector:{connector}",
        cache_key=cache_key,
    )
    try:
        return publish_connector_staging(
            connector,
            cache_key,
            plan,
            prepare,
            staging_root,
            final_root,
            managed_root,
        )
    finally:
        if staging_root.exists():
            try:
                safe_remove_dir(staging_root, managed_root)
            except RuntimeError:
                pass


def prepare_connector_transactionally(
    connector: str,
    cache_root: Path,
    plan: dict[str, Any],
    prepare: Any,
) -> dict[str, Any]:
    """Build a keyed connector tree in staging, then atomically publish it."""
    final_root = Path(str(plan["root"])).resolve()
    cache_key = str(plan.get("cache_key", plan.get("connector_build_id", "")))
    if not cache_key:
        return prepare(plan, True)
    try:
        _, managed_root = validate_managed_cache_child(final_root, cache_root)
    except RuntimeError:
        return prepare(plan, True)
    try:
        with BuildLock(cache_entry_lock_path(managed_root, f"connector-{connector}", cache_key)):
            return prepare_connector_under_lock(
                connector,
                cache_key,
                plan,
                prepare,
                final_root,
                managed_root,
            )
    except TimeoutError as exc:
        return {
            "connector": connector,
            "connector_build_id": plan.get("connector_build_id", ""),
            "status": "blocked",
            "blocker_reason": "cache_lock_timeout",
            "details": str(exc),
        }


def can_link_crypt(link_arg: str, env: dict[str, str] | None = None) -> bool:
    check_env = env or os.environ
    compiler = resolve_compiler(check_env)
    if not compiler:
        return False
    source = "extern char *crypt(const char *, const char *); int main(void) { return crypt(\"x\", \"xx\") == 0; }\n"
    proc = subprocess.run(
        [compiler, "-x", "c", "-", link_arg, "-o", os.devnull],
        input=source,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=check_env,
    )
    return proc.returncode == 0


def crypt_diagnostics(env: dict[str, str]) -> dict[str, Any]:
    header_path = Path("/usr/include/crypt.h")
    candidates = [
        Path("/usr/lib/x86_64-linux-gnu/libcrypt.so"),
        Path("/lib/x86_64-linux-gnu/libcrypt.so"),
        Path("/usr/lib64/libcrypt.so"),
        Path("/lib64/libcrypt.so"),
        Path("/usr/lib/x86_64-linux-gnu/libcrypt.so.1"),
        Path("/lib/x86_64-linux-gnu/libcrypt.so.1"),
        Path("/usr/lib64/libcrypt.so.1"),
        Path("/lib64/libcrypt.so.1"),
    ]
    found = [str(path) for path in candidates if path.exists()]
    configured = env.get("CRYPT_LIB", "").strip()
    link_arg = ""
    link_mode = ""
    if configured:
        link_arg = configured
        link_mode = "env:CRYPT_LIB"
    elif can_link_crypt("-lcrypt", env):
        link_arg = "-lcrypt"
        link_mode = "compiler:-lcrypt"
    elif found:
        link_arg = found[0]
        link_mode = "direct-path"
    return {
        "crypt_h_path": str(header_path),
        "crypt_h_status": "present" if header_path.is_file() else "missing",
        "libcrypt_paths": found,
        "libcrypt_status": "present" if found else "missing",
        "crypt_link_arg": link_arg,
        "crypt_link_mode": link_mode,
    }


def resolve_crypt_link_arg(env: dict[str, str]) -> str:
    configured = env.get("CRYPT_LIB", "").strip()
    if configured:
        return configured
    if can_link_crypt("-lcrypt", env):
        return "-lcrypt"
    for candidate in (
        Path("/usr/lib/x86_64-linux-gnu/libcrypt.so"),
        Path("/lib/x86_64-linux-gnu/libcrypt.so"),
        Path("/usr/lib64/libcrypt.so"),
        Path("/lib64/libcrypt.so"),
        Path("/usr/lib/x86_64-linux-gnu/libcrypt.so.1"),
        Path("/lib/x86_64-linux-gnu/libcrypt.so.1"),
        Path("/usr/lib64/libcrypt.so.1"),
        Path("/lib64/libcrypt.so.1"),
    ):
        if candidate.is_file():
            return str(candidate)
    return ""


def write_apachectl_wrapper(
    wrapper_path: Path,
    httpd_bin: Path,
    httpd_prefix: Path,
    modsecurity_lib_dir: Path,
    pcre2_lib_dir: Path,
    expat_lib_dir: Path | None = None,
) -> None:
    if is_system_path(wrapper_path):
        raise RuntimeError(f"system_path_write_forbidden: {wrapper_path}")
    wrapper_path.parent.mkdir(parents=True, exist_ok=True)
    content = f"""#!/bin/sh
set -eu

HTTPD_BIN={sh_quote(str(httpd_bin))}
HTTPD_PREFIX={sh_quote(str(httpd_prefix))}
MODSECURITY_LIB_DIR={sh_quote(str(modsecurity_lib_dir))}
PCRE2_LIB_DIR={sh_quote(str(pcre2_lib_dir))}
EXPAT_LIB_DIR={sh_quote(str(expat_lib_dir or ""))}

server_root=""
previous=""
for arg in "$@"; do
    if [ "$previous" = "-d" ]; then
        server_root=$arg
        previous=""
        continue
    fi
    if [ "$arg" = "-d" ]; then
        previous="-d"
    fi
done

if [ -n "$server_root" ]; then
    export APACHE_RUN_DIR="${{APACHE_RUN_DIR:-$server_root/run}}"
    export APACHE_LOCK_DIR="${{APACHE_LOCK_DIR:-$server_root/run}}"
    export APACHE_LOG_DIR="${{APACHE_LOG_DIR:-$server_root/log}}"
fi

if [ -z "${{APACHE_RUN_USER:-}}" ]; then
    if [ "$(id -u)" = "0" ]; then
        APACHE_RUN_USER=nobody
    else
        APACHE_RUN_USER=$(id -un)
    fi
    export APACHE_RUN_USER
fi
if [ -z "${{APACHE_RUN_GROUP:-}}" ]; then
    if [ "$(id -u)" = "0" ]; then
        APACHE_RUN_GROUP=$(getent group nogroup >/dev/null 2>&1 && printf '%s' nogroup || printf '%s' nobody)
    else
        APACHE_RUN_GROUP=$(id -gn)
    fi
    export APACHE_RUN_GROUP
fi

LD_LIBRARY_PATH="$MODSECURITY_LIB_DIR:$HTTPD_PREFIX/lib:$PCRE2_LIB_DIR${{EXPAT_LIB_DIR:+:$EXPAT_LIB_DIR}}${{LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}}"
export LD_LIBRARY_PATH
exec "$HTTPD_BIN" "$@"
"""
    wrapper_path.write_text(content, encoding="utf-8")
    wrapper_path.chmod(0o755)


def finish_planned_connector_record(plan: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    """Persist a record only when it belongs to a keyed connector plan."""
    if plan:
        write_connector_manifest(plan, record)
    return record


def requires_transactional_connector_prepare(plan: dict[str, Any] | None, transactional: bool) -> bool:
    """Return whether a keyed connector plan must be prepared via staging."""
    return bool(plan and plan.get("root") and not transactional)


def prepare_connector_with_optional_staging(
    connector: str,
    cache_root: Path,
    plan: dict[str, Any] | None,
    transactional: bool,
    prepare: Callable[[dict[str, Any] | None], dict[str, Any]],
) -> dict[str, Any]:
    """Prepare a connector directly or publish a keyed plan from staging."""
    if requires_transactional_connector_prepare(plan, transactional):
        return prepare_connector_transactionally(
            connector,
            cache_root,
            plan,
            lambda staged_plan, _inner: prepare(staged_plan),
        )
    return prepare(plan)


def apache_runtime_context(
    env: dict[str, str],
    plan: dict[str, Any],
    build_root: Path,
    modsecurity: dict[str, Any],
    expat: dict[str, Any],
) -> dict[str, Any]:
    apache_build_root = Path(
        env.get("APACHE_BUILD_ROOT", str(plan.get("build_root") or build_root / "apache-build"))
    ).resolve()
    httpd_prefix = Path(
        env.get("HTTPD_PREFIX", str(plan.get("httpd_prefix") or build_root / "apache-runtime/httpd"))
    ).resolve()
    httpd_bin = Path(
        env.get("APACHE_HTTPD") or env.get("APACHE") or str(httpd_prefix / "bin/httpd")
    ).resolve()
    apxs_bin = Path(
        env.get("APXS") or env.get("APXS_BIN") or str(httpd_prefix / APACHE_APXS_RELATIVE_PATH)
    ).resolve()
    apache_module = Path(
        env.get("APACHE_MODULE", str(apache_build_root / "output/apache/mod_security3.so"))
    ).resolve()
    modsecurity_lib_dir = Path(
        env.get(
            "APACHE_MRTS_MODSECURITY_LIB_DIR",
            str(modsecurity.get("lib_dir") or apache_build_root / "output/modsecurity/lib"),
        )
    ).resolve()
    pcre2_prefix = Path(env.get("PCRE2_PREFIX", str(apache_build_root / "output/pcre2"))).resolve()
    expat_prefix = Path(str(expat.get("prefix", ""))).resolve() if expat.get("prefix") else None
    expat_lib_dir = Path(str(expat.get("lib_dir", ""))).resolve() if expat.get("lib_dir") else None
    expat_cppflags = f"-I{expat_prefix / 'include'}" if expat_prefix else ""
    expat_ldflags = f"-L{expat_lib_dir}" if expat_lib_dir else ""
    expat_pkg_config_path = str(expat_prefix / "lib/pkgconfig") if expat_prefix else ""
    crypt = crypt_diagnostics(env)
    crypt_link_arg = str(crypt.get("crypt_link_arg", ""))
    apache_libs = " ".join(part for part in (env.get("LIBS", ""), crypt_link_arg) if part).strip()
    override_apachectl = env.get("APACHECTL_BIN", "")
    wrapper_path = httpd_prefix / "bin/apachectl-mrts"
    effective_apachectl = Path(override_apachectl).resolve() if override_apachectl else wrapper_path
    artifacts = {
        "httpd_bin": httpd_bin,
        "apxs_bin": apxs_bin,
        "module_file": apache_module,
        "modsecurity_lib": modsecurity_lib_dir / MODSECURITY_LIBRARY_FILENAME,
    }
    return {
        "apache_build_root": apache_build_root,
        "httpd_prefix": httpd_prefix,
        "httpd_bin": httpd_bin,
        "apxs_bin": apxs_bin,
        "apache_module": apache_module,
        "modsecurity_lib_dir": modsecurity_lib_dir,
        "pcre2_prefix": pcre2_prefix,
        "pcre2_lib_dir": pcre2_prefix / "lib",
        "expat_prefix": expat_prefix,
        "expat_lib_dir": expat_lib_dir,
        "expat_cppflags": expat_cppflags,
        "expat_ldflags": expat_ldflags,
        "expat_pkg_config_path": expat_pkg_config_path,
        "crypt": crypt,
        "crypt_link_arg": crypt_link_arg,
        "apache_libs": apache_libs,
        "override_apachectl": override_apachectl,
        "wrapper_path": wrapper_path,
        "effective_apachectl": effective_apachectl,
        "artifacts": artifacts,
    }


def apache_runtime_record(
    env: dict[str, str],
    plan: dict[str, Any],
    archives_root: Path,
    modsecurity: dict[str, Any],
    expat: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    artifacts = context["artifacts"]
    crypt = context["crypt"]
    return {
        "source": "connector-local-build",
        "connector": "apache",
        "connector_build_id": plan.get("connector_build_id", ""),
        "modsecurity_build_id": modsecurity.get("build_id", ""),
        "cache_schema_version": plan.get("cache_schema_version", ""),
        "cache_key": plan.get("cache_key", ""),
        "patchset_sha256": plan.get("patchset_sha256", ""),
        "target_architecture": plan.get("target_architecture", ""),
        "expected_ref": env.get("HTTPD_VERSION", ""),
        "cache_path": str(archives_root / "apache"),
        "build_path": str(context["apache_build_root"]),
        "httpd_prefix": str(context["httpd_prefix"]),
        "pcre2_prefix": str(context["pcre2_prefix"]),
        "httpd_bin": str(context["httpd_bin"]),
        "apxs_bin": str(context["apxs_bin"]),
        "module_file": str(context["apache_module"]),
        "modsecurity_lib_dir": str(context["modsecurity_lib_dir"]),
        "apachectl_bin": str(context["effective_apachectl"]),
        "expat_source": expat.get("source", ""),
        "expat_release_tag": expat.get("release_tag", expat.get("expected_ref", "")),
        "expat_actual_head": expat.get("actual_head", ""),
        "expat_prefix": str(context["expat_prefix"]) if context["expat_prefix"] else "",
        "expat_h": str(expat.get("expat_h", "")),
        "expat_lib_dir": str(context["expat_lib_dir"]) if context["expat_lib_dir"] else "",
        "cppflags": " ".join(
            part for part in (context["expat_cppflags"], env.get("CPPFLAGS", "")) if part
        ).strip(),
        "ldflags": " ".join(
            part for part in (context["expat_ldflags"], env.get("LDFLAGS", "")) if part
        ).strip(),
        "libs": context["apache_libs"],
        "crypt_lib": context["crypt_link_arg"],
        "crypt_h_status": crypt.get("crypt_h_status", ""),
        "crypt_h_path": crypt.get("crypt_h_path", ""),
        "libcrypt_status": crypt.get("libcrypt_status", ""),
        "libcrypt_paths": crypt.get("libcrypt_paths", []),
        "crypt_link_mode": crypt.get("crypt_link_mode", ""),
        "crypt_config_cache": context["crypt_link_arg"],
        "aprutil_libs": context["crypt_link_arg"],
        "pkg_config_path": (
            f"{context['expat_pkg_config_path']}{os.pathsep}{env.get('PKG_CONFIG_PATH', '')}".rstrip(
                os.pathsep
            )
            if context["expat_pkg_config_path"]
            else env.get("PKG_CONFIG_PATH", "")
        ),
        "status": "unknown",
        "blocker_reason": "",
        "searched_paths": [str(path) for path in artifacts.values()],
        "env_override": "APACHECTL_BIN",
        "output_paths": {
            "binary": str(context["httpd_bin"]),
            "module": str(context["apache_module"]),
            "config": str(context["httpd_prefix"] / "conf/httpd.conf"),
        },
    }


def apache_preflight_blocked(
    record: dict[str, Any],
    modsecurity: dict[str, Any],
    override_apachectl: str,
) -> bool:
    if modsecurity.get("status") not in READY_COMPONENT_STATUSES:
        record.update(
            status="blocked",
            blocker_reason=modsecurity.get("blocker_reason") or "modsecurity_build_failed",
        )
        return True
    if override_apachectl and not executable(Path(override_apachectl)):
        record.update(
            status="blocked",
            blocker_reason="missing_local_httpd_build",
            missing_file=override_apachectl,
        )
        return True
    return False


def reconcile_apache_cached_entry(
    plan: dict[str, Any],
    cache_root: Path,
    artifacts: dict[str, Path],
    ready: bool,
    missing: list[str],
    manifest_ready: bool,
    record: dict[str, Any],
) -> tuple[bool, list[str], str]:
    root_value = plan.get("root")
    if not root_value:
        return ready, missing, ""
    stale_root = Path(str(root_value))
    if not stale_root.exists() or (ready and manifest_ready):
        return ready, missing, ""
    try:
        safe_remove_dir(stale_root, cache_root)
    except RuntimeError as exc:
        return ready, missing, str(exc)
    record["invalidation_reason"] = (
        "missing_or_incomplete_connector_manifest" if not manifest_ready else "connector_artifact_missing"
    )
    ready, missing = artifact_status(artifacts, {"httpd_bin", "apxs_bin"})
    if ready:
        return ready, missing, "connector_manifest_missing_for_external_artifacts"
    return ready, missing, ""


def apache_cached_entry_reusable(
    plan: dict[str, Any],
    ready: bool,
    httpd_prefix: Path,
) -> bool:
    return bool(plan) and ready and connector_manifest_ready(plan) and apache_apxs_includedir_usable(httpd_prefix)


def claim_apache_cache_entry(plan: dict[str, Any], cache_root: Path) -> str:
    root_value = plan.get("root")
    if not root_value:
        return ""
    try:
        mark_managed_cache_entry(
            Path(str(root_value)),
            cache_root,
            component="connector:apache",
            cache_key=str(plan.get("cache_key", plan.get("connector_build_id", ""))),
        )
    except RuntimeError as exc:
        return str(exc)
    return ""


def apache_blocker_details(blocker: str, env: dict[str, str]) -> dict[str, Any]:
    if blocker == "missing_expat_headers":
        return {
            "missing_file": EXPAT_HEADER_FILENAME,
            "build_component": "apache_httpd_source_build",
            "env_variable_can_set": "CPPFLAGS/LDFLAGS",
            "dependency_searched_paths": [env.get("CPPFLAGS") or "<compiler default include paths>"],
        }
    if blocker == "missing_crypt_library":
        return {
            "missing_file": "libcrypt.so development link target or explicit -lcrypt linkage",
            "build_component": "apache_httpd_source_build",
            "env_variable_can_set": "LIBS/LDFLAGS",
            "dependency_searched_paths": [env.get("LIBS") or "<configure default libraries>"],
        }
    return {}


def apache_build_environment(
    env: dict[str, str],
    connector_root: Path,
    framework_root: Path,
    cache_root: Path,
    build_root: Path,
    sources_root: Path,
    archives_root: Path,
    modsecurity: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, str]:
    expat_lib_dir = context["expat_lib_dir"]
    expat_pkg_config_path = context["expat_pkg_config_path"]
    return build_env(
        env,
        FRAMEWORK_ROOT=str(framework_root),
        CONNECTOR_ROOT=str(connector_root),
        CONNECTOR_COMPONENT_CACHE=str(cache_root),
        SOURCE_ROOT=str(sources_root),
        MODSECURITY_SOURCE_DIR=str(sources_root / "ModSecurity_V3"),
        MODSECURITY_V3_SOURCE_DIR=str(sources_root / "ModSecurity_V3"),
        MODSECURITY_V3_ROOT=str(sources_root / "ModSecurity_V3"),
        BUILD_ROOT=str(build_root),
        TMP_ROOT=str(build_root / "tmp"),
        LOG_ROOT=str(build_root / "logs"),
        APACHE_BUILD_ROOT=str(context["apache_build_root"]),
        APACHE_BUILD_OWNER_ROOT=str(cache_root / "builds" / "connectors"),
        HTTPD_PREFIX=str(context["httpd_prefix"]),
        APACHE_DOWNLOAD_DIR=str(archives_root / "apache"),
        MODSECURITY_SHARED_PREFIX=str(modsecurity.get("prefix", "")),
        MODSECURITY_BUILD_ID=str(modsecurity.get("build_id", "")),
        CPPFLAGS=" ".join(part for part in (context["expat_cppflags"], env.get("CPPFLAGS", "")) if part).strip(),
        LDFLAGS=" ".join(part for part in (context["expat_ldflags"], env.get("LDFLAGS", "")) if part).strip(),
        LIBS=context["apache_libs"],
        CRYPT_LIBS=context["crypt_link_arg"] if context["crypt_link_arg"] else None,
        APRUTIL_LIBS=context["crypt_link_arg"] if context["crypt_link_arg"] else None,
        ac_cv_search_crypt=context["crypt_link_arg"] if context["crypt_link_arg"] else None,
        PKG_CONFIG_PATH=(
            f"{expat_pkg_config_path}{os.pathsep}{env.get('PKG_CONFIG_PATH', '')}".rstrip(os.pathsep)
            if expat_pkg_config_path
            else env.get("PKG_CONFIG_PATH", "")
        ),
        LD_LIBRARY_PATH=(
            f"{expat_lib_dir}{os.pathsep}{env.get('LD_LIBRARY_PATH', '')}".rstrip(os.pathsep)
            if expat_lib_dir
            else env.get("LD_LIBRARY_PATH", "")
        ),
        # The Framework-owned Apache provisioner extracts verified source
        # archives.  The task-owned runtime roots can be user namespaces or
        # id-mapped mounts, where restoring the archive's original owner
        # fails even though extraction is otherwise valid.  Archive ownership
        # is not build input, so consistently suppress its restoration.
        TAR_OPTIONS="--no-same-owner",
        BUILD_HTTPD_FROM_SOURCE="1",
        BUILD_PCRE2_FROM_SOURCE="1",
        AUTO_FETCH_SMOKE_SOURCES="0",
        REFRESH="1",
        SKIP_RUNTIME_COMPONENT_PREPARE="1",
    )


def build_apache_source(
    env: dict[str, str],
    connector_root: Path,
    framework_root: Path,
    cache_root: Path,
    build_root: Path,
    sources_root: Path,
    archives_root: Path,
    modsecurity: dict[str, Any],
    context: dict[str, Any],
    record: dict[str, Any],
) -> tuple[bool, list[str], bool]:
    log_path = build_root / "logs/runtime-components/apache-build.log"
    proc = run_build(
        framework_root / "ci/provisioning/prepare-apache-build.sh",
        apache_build_environment(
            env,
            connector_root,
            framework_root,
            cache_root,
            build_root,
            sources_root,
            archives_root,
            modsecurity,
            context,
        ),
        connector_root,
        log_path,
    )
    record["build_log"] = str(log_path)
    record["build_exit_code"] = proc.returncode
    artifacts_file = context["apache_build_root"] / "logs/apache/artifacts.txt"
    if artifacts_file.is_file():
        record["artifacts"] = read_key_values(artifacts_file)
    ready, missing = artifact_status(context["artifacts"], {"httpd_bin", "apxs_bin"})
    if proc.returncode == 0 and ready:
        return ready, missing, True
    apache_log_dir = build_root / "logs/apache"
    diagnostic_text = "\n".join(
        [
            proc.stdout,
            read_text_if_file(log_path),
            read_text_if_file(apache_log_dir / "check-expat.h.log"),
            read_text_if_file(apache_log_dir / "httpd-configure.log"),
            read_text_if_file(apache_log_dir / "httpd-make.log"),
            read_text_if_file(apache_log_dir / "apache-configure.log"),
            read_text_if_file(apache_log_dir / "apache-make.log"),
        ]
    )
    blocker = map_apache_blocker(diagnostic_text, missing)
    record.update(
        status="failed",
        blocker_reason=blocker,
        missing_files=missing,
        **apache_blocker_details(blocker, env),
    )
    return ready, missing, False


def write_apache_runtime_wrapper(context: dict[str, Any]) -> str:
    override_apachectl = context["override_apachectl"]
    try:
        if not override_apachectl:
            write_apachectl_wrapper(
                context["wrapper_path"],
                context["httpd_bin"],
                context["httpd_prefix"],
                context["modsecurity_lib_dir"],
                context["pcre2_lib_dir"],
                context["expat_lib_dir"],
            )
        elif not executable(Path(override_apachectl)):
            raise RuntimeError(f"APACHECTL_BIN is not executable: {override_apachectl}")
    except Exception as exc:
        return str(exc)
    return ""


def prepare_apache_httpd(
    env: dict[str, str],
    connector_root: Path,
    framework_root: Path,
    cache_root: Path,
    build_root: Path,
    sources_root: Path,
    archives_root: Path,
    expat: dict[str, Any] | None = None,
    modsecurity: dict[str, Any] | None = None,
    plan: dict[str, Any] | None = None,
    _transactional: bool = False,
) -> dict[str, Any]:
    """Prepare Apache while preserving atomic staging for keyed cache plans."""
    return prepare_connector_with_optional_staging(
        "apache",
        cache_root,
        plan,
        _transactional,
        lambda active_plan: _prepare_apache_httpd_for_plan(
            env,
            connector_root,
            framework_root,
            cache_root,
            build_root,
            sources_root,
            archives_root,
            expat,
            modsecurity,
            active_plan,
        ),
    )


def _prepare_apache_httpd_for_plan(
    env: dict[str, str],
    connector_root: Path,
    framework_root: Path,
    cache_root: Path,
    build_root: Path,
    sources_root: Path,
    archives_root: Path,
    expat: dict[str, Any] | None,
    modsecurity: dict[str, Any] | None,
    plan: dict[str, Any] | None,
) -> dict[str, Any]:
    modsecurity = modsecurity or {}
    plan = plan or {}
    expat = expat or {}
    context = apache_runtime_context(env, plan, build_root, modsecurity, expat)
    record = apache_runtime_record(env, plan, archives_root, modsecurity, expat, context)
    if apache_preflight_blocked(record, modsecurity, context["override_apachectl"]):
        return finish_planned_connector_record(plan, record)
    ready, missing = artifact_status(context["artifacts"], {"httpd_bin", "apxs_bin"})
    manifest_ready = connector_manifest_ready(plan) if plan else False
    ready, missing, cache_blocker = reconcile_apache_cached_entry(
        plan,
        cache_root,
        context["artifacts"],
        ready,
        missing,
        manifest_ready,
        record,
    )
    if cache_blocker:
        record.update(status="blocked", blocker_reason=cache_blocker)
        return finish_planned_connector_record(plan, record)
    if apache_cached_entry_reusable(plan, ready, context["httpd_prefix"]):
        record.update(
            status="reused",
            tree=tree_manifest(context["apache_build_root"]),
            apachectl_bin=str(context["effective_apachectl"]),
        )
        return finish_planned_connector_record(plan, record)
    claim_error = claim_apache_cache_entry(plan, cache_root)
    if claim_error:
        record.update(status="blocked", blocker_reason=claim_error)
        return finish_planned_connector_record(plan, record)
    if not ready:
        ready, missing, build_succeeded = build_apache_source(
            env,
            connector_root,
            framework_root,
            cache_root,
            build_root,
            sources_root,
            archives_root,
            modsecurity,
            context,
            record,
        )
        if not build_succeeded:
            return finish_planned_connector_record(plan, record)
    wrapper_error = write_apache_runtime_wrapper(context)
    if wrapper_error:
        record.update(
            status="blocked",
            blocker_reason="missing_local_httpd_build",
            details=wrapper_error,
        )
        return finish_planned_connector_record(plan, record)
    record.update(
        status="built" if plan else "present",
        invalidation_reason=record.get("invalidation_reason")
        or ("missing_or_stale_connector_build" if plan else ""),
        tree=tree_manifest(context["apache_build_root"]),
        apachectl_bin=str(context["effective_apachectl"]),
    )
    return finish_planned_connector_record(plan, record)


def nginx_protocol_context(
    env: dict[str, str],
    plan: dict[str, Any],
    archives_root: Path,
) -> tuple[dict[str, Any], str, str, str]:
    """Resolve the effective NGINX protocol profile and optional TLS archive."""
    protocol_inputs = plan.get("nginx_protocol_build")
    if not isinstance(protocol_inputs, dict) or not protocol_inputs:
        protocol_inputs = nginx_protocol_build_inputs(env)
    protocol_profile = str(protocol_inputs.get("profile", "h1"))
    if not bool(protocol_inputs.get("quic_enabled")):
        return protocol_inputs, protocol_profile, "", ""
    quic_source_url = str(protocol_inputs.get("tls_source_url", ""))
    quic_archive_name = Path(urlsplit(quic_source_url).path).name
    if not quic_archive_name:
        return protocol_inputs, protocol_profile, "", "invalid_nginx_quic_tls_archive_name"
    return protocol_inputs, protocol_profile, str((archives_root / "nginx" / quic_archive_name).resolve()), ""


def nginx_managed_local_artifacts_match_plan(
    plan: dict[str, Any],
    local_nginx_bin: Path,
    local_module: Path,
) -> bool:
    """Prove that local artifacts are the cache-plan-owned NGINX outputs."""

    root_value = plan.get("root")
    output_paths = plan.get("output_paths")
    if not isinstance(root_value, str) or not root_value or not isinstance(output_paths, dict):
        return False
    binary_value = output_paths.get("binary")
    module_value = output_paths.get("module")
    if not isinstance(binary_value, str) or not binary_value or not isinstance(module_value, str) or not module_value:
        return False
    root = Path(root_value).resolve(strict=False)
    expected_binary = Path(binary_value).resolve(strict=False)
    expected_module = Path(module_value).resolve(strict=False)
    return (
        local_nginx_bin == expected_binary
        and local_module == expected_module
        and is_within(local_nginx_bin, root)
        and is_within(local_module, root)
    )


def nginx_path_readback(path: Path, *, require_executable: bool = False) -> dict[str, Any]:
    """Capture bounded local artifact evidence without executing the artifact."""

    result: dict[str, Any] = {
        "path": str(path),
        "is_file": path.is_file(),
        "executable": executable(path) if require_executable else False,
        "size": 0,
        "sha256": "",
    }
    if not result["is_file"]:
        return result
    try:
        result["size"] = path.stat().st_size
        result["sha256"] = sha256_file(path)
    except OSError as exc:
        result["readback_error"] = str(exc)
    return result


def nginx_binary_readback(context: dict[str, Any]) -> dict[str, Any]:
    """Report managed/effective binary identities for downstream evidence."""

    return {
        "managed_local_binary": nginx_path_readback(context["local_nginx_bin"], require_executable=True),
        "managed_local_module": nginx_path_readback(context["local_module"]),
        "effective_binary": nginx_path_readback(context["effective_bin"], require_executable=True),
        "effective_module": nginx_path_readback(context["effective_module"]),
    }


def update_nginx_runtime_readback(record: dict[str, Any], context: dict[str, Any]) -> None:
    record.update(
        managed_local_binary_origin=context["managed_local_binary_origin"],
        effective_binary_origin=context["effective_binary_origin"],
        managed_local_artifacts_match_plan=context["managed_local_artifacts_match_plan"],
        binary_readback=nginx_binary_readback(context),
    )


def nginx_managed_plan_root(plan: dict[str, Any]) -> Path | None:
    root_value = plan.get("root")
    if not isinstance(root_value, str) or not root_value:
        return None
    root = Path(root_value)
    if root.is_symlink() or not root.is_dir():
        return None
    try:
        return root.resolve(strict=True)
    except OSError:
        return None


def nginx_managed_regular_file(path: Path, root: Path, *, require_executable: bool = False) -> bool:
    if path.is_symlink() or not path.is_file() or (require_executable and not executable(path)):
        return False
    try:
        resolved_path = path.resolve(strict=True)
    except OSError:
        return False
    return is_within(resolved_path, root)


def nginx_source_header_readback(header: Path, root: Path) -> tuple[str, str] | None:
    if header.parts[-3:] != ("src", "core", "nginx.h") or header.is_symlink():
        return None
    source_directory = header.parent.parent.parent
    if source_directory.is_symlink() or not source_directory.is_dir():
        return None
    try:
        resolved_source = source_directory.resolve(strict=True)
        resolved_header = header.resolve(strict=True)
        if not is_within(resolved_source, root) or not is_within(resolved_header, resolved_source):
            return None
        contents = header.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    match = re.search(r'^\s*#define\s+NGINX_VERSION\s+"([^"\\]+)"', contents, re.MULTILINE)
    if match is None:
        return None
    return str(resolved_source), f"nginx/{match.group(1)}"


def nginx_managed_source_readback(plan: dict[str, Any]) -> tuple[str, str]:
    """Read the version from an extracted, plan-owned NGINX source tree."""

    root = nginx_managed_plan_root(plan)
    if root is None:
        return "", ""
    fallback: tuple[str, str] = ("", "")
    try:
        headers = sorted(root.rglob("nginx.h"))
    except OSError:
        return fallback
    for header in headers:
        candidate = nginx_source_header_readback(header, root)
        if candidate is None:
            continue
        if candidate[1] == NGINX_PINNED_VERSION_READBACK:
            return candidate
        if not fallback[0]:
            fallback = candidate
    return fallback


def nginx_managed_binary_readback(
    plan: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    """Read version/configuration from the exact managed local executable."""

    root = nginx_managed_plan_root(plan)
    binary = context["local_nginx_bin"]
    result: dict[str, Any] = {
        "binary_path": "",
        "binary_sha256": "",
        "binary_version_readback": "",
        "configure_arguments": "",
    }
    if (
        root is None
        or not context["managed_local_artifacts_match_plan"]
        or not nginx_managed_regular_file(binary, root, require_executable=True)
    ):
        return result
    try:
        proc = subprocess.run(
            [str(binary), "-V"],
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["readback_error"] = str(exc)
        return result
    output = (proc.stdout + proc.stderr)[-65536:]
    version_match = re.search(r"\bnginx/(\d+(?:\.\d+){2})\b", output)
    configure_arguments = ""
    for line in output.splitlines():
        prefix = "configure arguments:"
        if prefix in line:
            configure_arguments = line.split(prefix, 1)[1].strip()
            break
    if proc.returncode != 0:
        result["readback_error"] = f"nginx_-V_exit_{proc.returncode}"
        return result
    result.update(
        binary_path=str(binary.resolve(strict=True)),
        binary_sha256=sha256_file(binary),
        binary_version_readback=(f"nginx/{version_match.group(1)}" if version_match else ""),
        configure_arguments=configure_arguments,
    )
    return result


def nginx_plan_commit(plan: dict[str, Any], key: str) -> str:
    identity = plan.get("cache_identity")
    if not isinstance(identity, dict):
        return ""
    extra_inputs = identity.get("extra_inputs")
    value = extra_inputs.get(key, "") if isinstance(extra_inputs, dict) else ""
    return value if isinstance(value, str) else ""


def nginx_artifact_value(artifacts: dict[str, str], *keys: str) -> str:
    for key in keys:
        value = artifacts.get(key, "")
        if value:
            return value.strip()
    return ""


def nginx_builder_archive_readback(record: dict[str, Any]) -> dict[str, Any]:
    """Read the builder's own archive verification result without defaults."""

    artifacts = record.get("artifacts")
    artifacts = artifacts if isinstance(artifacts, dict) else {}
    values = {
        str(key): str(value)
        for key, value in artifacts.items()
        if isinstance(key, str) and isinstance(value, str)
    }
    actual_sha256 = nginx_artifact_value(
        values,
        "nginx_archive_sha256_local",
        "NGINX_ARCHIVE_SHA256_LOCAL",
    ).lower()
    verified_marker = nginx_artifact_value(
        values,
        "nginx_archive_verified",
        "NGINX_ARCHIVE_VERIFIED",
        "nginx_archive_sha256_verified",
        "NGINX_ARCHIVE_SHA256_VERIFIED",
    ).lower()
    return {
        "actual_archive_sha256": actual_sha256,
        "archive_verified": verified_marker in {"1", "true", "yes", "pass", "verified"},
        "verification_marker": verified_marker,
    }


def nginx_runtime_contract(
    env: dict[str, str],
    plan: dict[str, Any],
    context: dict[str, Any],
    record: dict[str, Any],
) -> dict[str, Any]:
    """Build the exact source/binary evidence contract from managed artifacts."""

    provenance = nginx_pinned_provenance(env)
    source_directory, source_version_readback = nginx_managed_source_readback(plan)
    binary = nginx_managed_binary_readback(plan, context)
    builder_archive = nginx_builder_archive_readback(record)
    parent_archive_sha256 = str(record.get("verified_archive_sha256", "")).lower()
    actual_archive_sha256 = str(builder_archive["actual_archive_sha256"])
    return {
        "component": "nginx",
        "source_repository": provenance["repository"],
        "source_mode": provenance["mode"],
        "release_tag": provenance["release_tag"],
        "source_ref": provenance["source_ref"],
        "release_asset_name": provenance["release_asset_name"],
        "expected_archive_sha256": provenance["sha256"],
        "actual_archive_sha256": actual_archive_sha256,
        "source_version_readback": source_version_readback,
        "source_directory": source_directory,
        "binary_path": binary["binary_path"],
        "binary_sha256": binary["binary_sha256"],
        "binary_version_readback": binary["binary_version_readback"],
        "configure_arguments": binary["configure_arguments"],
        "build_id": str(plan.get("connector_build_id", "")),
        "framework_commit": nginx_plan_commit(plan, "framework_commit"),
        "parent_commit": nginx_plan_commit(plan, "connector_commit"),
        "generated_at": utc_now(),
        "parent_archive_sha256": parent_archive_sha256,
        "builder_archive_sha256": actual_archive_sha256,
        "builder_archive_verified": builder_archive["archive_verified"],
        "builder_archive_verification_marker": builder_archive["verification_marker"],
    }


def nginx_runtime_contract_required_fields() -> tuple[str, ...]:
    return (
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


def nginx_runtime_contract_expected_values() -> dict[str, str]:
    return {
        "component": "nginx",
        "source_repository": NGINX_PINNED_SOURCE_REPOSITORY,
        "source_mode": NGINX_PINNED_SOURCE_MODE,
        "release_tag": NGINX_PINNED_RELEASE_TAG,
        "source_ref": NGINX_PINNED_SOURCE_REF,
        "release_asset_name": NGINX_PINNED_RELEASE_ASSET_NAME,
        "expected_archive_sha256": NGINX_PINNED_RELEASE_ASSET_SHA256,
        "actual_archive_sha256": NGINX_PINNED_RELEASE_ASSET_SHA256,
        "source_version_readback": NGINX_PINNED_VERSION_READBACK,
        "binary_version_readback": NGINX_PINNED_VERSION_READBACK,
    }


def nginx_runtime_contract_value_blockers(contract: dict[str, Any]) -> list[str]:
    blockers = [field for field in nginx_runtime_contract_required_fields() if not contract.get(field)]
    blockers.extend(
        f"mismatch:{key}"
        for key, value in nginx_runtime_contract_expected_values().items()
        if contract.get(key) and contract.get(key) != value
    )
    return blockers


def nginx_runtime_contract_identity_blockers(contract: dict[str, Any]) -> list[str]:
    blockers = []
    for key in ("framework_commit", "parent_commit"):
        value = contract.get(key)
        if value and (not isinstance(value, str) or FULL_GIT_COMMIT_ID.fullmatch(value) is None):
            blockers.append(f"invalid:{key}")
    return blockers


def nginx_runtime_contract_archive_blockers(contract: dict[str, Any]) -> list[str]:
    blockers = []
    if not contract.get("builder_archive_verified"):
        blockers.append("builder_archive_not_verified")
    if contract.get("builder_archive_sha256") != contract.get("actual_archive_sha256"):
        blockers.append("builder_archive_sha256_mismatch")
    if contract.get("parent_archive_sha256") != contract.get("actual_archive_sha256"):
        blockers.append("parent_builder_archive_sha256_mismatch")
    return blockers


def nginx_runtime_contract_managed_path_blockers(contract: dict[str, Any], plan: dict[str, Any]) -> list[str]:
    root = nginx_managed_plan_root(plan)
    if root is None:
        return ["managed_plan_root"]
    blockers = []
    source_directory = contract.get("source_directory")
    if isinstance(source_directory, str) and source_directory:
        source = Path(source_directory)
        if source.is_symlink() or not source.is_dir() or not is_within(source.resolve(strict=False), root):
            blockers.append("source_directory_not_managed")
    binary_path = contract.get("binary_path")
    if not isinstance(binary_path, str) or not binary_path:
        return blockers
    binary = Path(binary_path)
    if not nginx_managed_regular_file(binary, root, require_executable=True):
        blockers.append("binary_path_not_managed")
        return blockers
    try:
        if sha256_file(binary) != contract.get("binary_sha256"):
            blockers.append("binary_sha256_readback_mismatch")
    except OSError:
        blockers.append("binary_sha256_readback_failed")
    return blockers


def nginx_runtime_contract_blockers(
    contract: dict[str, Any],
    plan: dict[str, Any],
    context: dict[str, Any],
) -> list[str]:
    """Return exact evidence gaps; an empty list proves a strict contract."""

    del context
    blockers = nginx_runtime_contract_value_blockers(contract)
    blockers.extend(nginx_runtime_contract_identity_blockers(contract))
    blockers.extend(nginx_runtime_contract_archive_blockers(contract))
    blockers.extend(nginx_runtime_contract_managed_path_blockers(contract, plan))
    return list(dict.fromkeys(blockers))


def update_nginx_runtime_contract(
    record: dict[str, Any],
    env: dict[str, str],
    plan: dict[str, Any],
    context: dict[str, Any],
) -> list[str]:
    try:
        contract = nginx_runtime_contract(env, plan, context, record)
    except Exception as exc:
        contract = {}
        blockers = [f"runtime_contract_readback_failed:{exc}"]
    else:
        blockers = nginx_runtime_contract_blockers(contract, plan, context)
    record["runtime_contract"] = contract
    record["runtime_contract_blockers"] = blockers
    record["runtime_contract_valid"] = not blockers
    if contract:
        source_readback = record.get("source_readback")
        source_readback = dict(source_readback) if isinstance(source_readback, dict) else {}
        source_readback.update(
            source_directory=contract.get("source_directory", ""),
            source_version_readback=contract.get("source_version_readback", ""),
        )
        record["source_readback"] = source_readback
    return blockers


def nginx_runtime_contract_preflight_blocked(
    record: dict[str, Any],
    env: dict[str, str],
    plan: dict[str, Any],
    context: dict[str, Any],
) -> bool:
    """Keep a ready NGINX record contingent on complete managed evidence."""

    blockers = update_nginx_runtime_contract(record, env, plan, context)
    if not blockers:
        return False
    record.update(
        status="blocked",
        blocker_reason="nginx_pinned_provenance_runtime_contract_not_ready",
        runtime_contract_blockers=blockers,
    )
    return True


def nginx_runtime_context(
    env: dict[str, str],
    plan: dict[str, Any],
    build_root: Path,
    modsecurity: dict[str, Any],
) -> dict[str, Any]:
    nginx_build_root = Path(
        env.get("NGINX_BUILD_DIR", str(plan.get("build_root") or build_root / "nginx-build"))
    ).resolve()
    nginx_prefix = Path(
        env.get("NGINX_PREFIX", str(plan.get("nginx_prefix") or build_root / "nginx-runtime/nginx"))
    ).resolve()
    local_nginx_bin = Path(env.get("NGINX_BINARY", str(nginx_prefix / "sbin/nginx"))).resolve()
    local_module = Path(
        env.get("NGINX_MODULE", str(nginx_prefix / "modules" / NGINX_MODULE_FILENAME))
    ).resolve()
    modsecurity_lib_dir = Path(
        env.get(
            "NGINX_MRTS_MODSECURITY_LIB_DIR",
            str(modsecurity.get("lib_dir") or nginx_build_root / "output/modsecurity/lib"),
        )
    ).resolve()
    override_bin = env.get("MRTS_NATIVE_NGINX_BIN", "")
    override_module_dir = env.get("MRTS_NATIVE_NGINX_MODULE_DIR", "")
    effective_bin = Path(override_bin).resolve() if override_bin else local_nginx_bin
    effective_module = (
        Path(override_module_dir).resolve() / NGINX_MODULE_FILENAME
        if override_module_dir
        else local_module
    )
    managed_local_artifacts_match_plan = nginx_managed_local_artifacts_match_plan(
        plan,
        local_nginx_bin,
        local_module,
    )
    managed_local_binary_origin = (
        "managed_connector_cache_plan"
        if managed_local_artifacts_match_plan
        else "unmanaged_local_path"
    )
    return {
        "nginx_build_root": nginx_build_root,
        "nginx_prefix": nginx_prefix,
        "local_nginx_bin": local_nginx_bin,
        "local_module": local_module,
        "modsecurity_lib_dir": modsecurity_lib_dir,
        "override_bin": override_bin,
        "override_module_dir": override_module_dir,
        "effective_bin": effective_bin,
        "effective_module": effective_module,
        "require_pinned_provenance": nginx_pinned_provenance_required(env),
        "managed_local_artifacts_match_plan": managed_local_artifacts_match_plan,
        "managed_local_binary_origin": managed_local_binary_origin,
        "effective_binary_origin": (
            "inherited_native_override"
            if override_bin or override_module_dir
            else managed_local_binary_origin
        ),
        "local_artifacts": {
            "nginx_bin": local_nginx_bin,
            "module_file": local_module,
            "modsecurity_lib": modsecurity_lib_dir / MODSECURITY_LIBRARY_FILENAME,
        },
        "effective_artifacts": {
            "nginx_bin": effective_bin,
            "module_file": effective_module,
        },
    }


def nginx_runtime_record(
    env: dict[str, str],
    plan: dict[str, Any],
    archives_root: Path,
    modsecurity: dict[str, Any],
    protocol_inputs: dict[str, Any],
    protocol_profile: str,
    context: dict[str, Any],
) -> dict[str, Any]:
    archive_inputs = plan.get("archive_inputs")
    nginx_archive = archive_inputs.get("nginx", {}) if isinstance(archive_inputs, dict) else {}
    if not isinstance(nginx_archive, dict):
        nginx_archive = {}
    source_tuple = nginx_archive.get("source_tuple", {})
    if not isinstance(source_tuple, dict):
        source_tuple = {}
    source_readback = nginx_archive.get("source_readback", {})
    if not isinstance(source_readback, dict):
        source_readback = {}
    record: dict[str, Any] = {
        "source": "connector-local-build",
        "connector": "nginx",
        "connector_build_id": plan.get("connector_build_id", ""),
        "modsecurity_build_id": modsecurity.get("build_id", ""),
        "cache_schema_version": plan.get("cache_schema_version", ""),
        "cache_key": plan.get("cache_key", ""),
        "patchset_sha256": plan.get("patchset_sha256", ""),
        "target_architecture": plan.get("target_architecture", ""),
        "expected_ref": env.get("NGINX_RELEASE_TAG") or env.get("NGINX_SOURCE_GIT_REF", ""),
        "protocol_profile": protocol_profile,
        "protocol_build_inputs": protocol_inputs,
        "cache_path": str(archives_root / "nginx"),
        "build_path": str(context["nginx_build_root"]),
        "nginx_prefix": str(context["nginx_prefix"]),
        "nginx_bin": str(context["effective_bin"]),
        "module_dir": str(context["effective_module"].parent),
        "module_file": str(context["effective_module"]),
        "local_nginx_bin": str(context["local_nginx_bin"]),
        "local_module_file": str(context["local_module"]),
        "modsecurity_lib_dir": str(context["modsecurity_lib_dir"]),
        "pinned_provenance": bool(nginx_archive.get("pinned_provenance", False)),
        "provenance_validation": nginx_archive.get("provenance_validation", ""),
        "source_tuple": source_tuple,
        "source_mode": nginx_archive.get("source_mode", ""),
        "source_repository": nginx_archive.get("source_repository", ""),
        "release_tag": nginx_archive.get("release_tag", ""),
        "source_ref": nginx_archive.get("source_ref", ""),
        "release_asset_name": nginx_archive.get("release_asset_name", ""),
        "release_asset_url": nginx_archive.get("release_asset_url", ""),
        "expected_sha256": nginx_archive.get("expected_sha256", ""),
        "verified_archive_sha256": nginx_archive.get("verified_archive_sha256", ""),
        "archive_digest_verified": bool(nginx_archive.get("archive_digest_verified", False)),
        "source_readback": source_readback,
        "archive_cache_identity": nginx_archive.get("cache_identity", {}),
        "archive_cache_key": nginx_archive.get("cache_key", ""),
        "require_pinned_provenance": context["require_pinned_provenance"],
        "status": "unknown",
        "blocker_reason": "",
        "searched_paths": [str(path) for path in context["local_artifacts"].values()],
        "env_override": NATIVE_NGINX_OVERRIDE_ENV,
        "output_paths": {
            "binary": str(context["effective_bin"]),
            "module": str(context["effective_module"]),
            "config": str(context["nginx_prefix"] / "conf/nginx.conf"),
        },
    }
    update_nginx_runtime_readback(record, context)
    return record


def nginx_preflight_blocked(
    record: dict[str, Any],
    modsecurity: dict[str, Any],
    context: dict[str, Any],
) -> bool:
    if modsecurity.get("status") not in READY_COMPONENT_STATUSES:
        record.update(
            status="blocked",
            blocker_reason=modsecurity.get("blocker_reason") or "modsecurity_build_failed",
        )
        return True
    if context["require_pinned_provenance"]:
        if context["override_bin"] or context["override_module_dir"]:
            record.update(
                status="blocked",
                blocker_reason="nginx_pinned_provenance_native_override_forbidden",
                inherited_native_override={
                    "nginx_bin": context["override_bin"],
                    "module_dir": context["override_module_dir"],
                },
            )
            return True
        if not context["managed_local_artifacts_match_plan"]:
            record.update(
                status="blocked",
                blocker_reason="nginx_pinned_provenance_managed_local_artifacts_required",
            )
            return True
    if context["override_bin"] and not executable(Path(context["override_bin"])):
        record.update(
            status="blocked",
            blocker_reason="missing_local_nginx_build",
            missing_file=context["override_bin"],
        )
        return True
    override_module_dir = context["override_module_dir"]
    if override_module_dir and not (Path(override_module_dir) / NGINX_MODULE_FILENAME).is_file():
        record.update(
            status="blocked",
            blocker_reason="missing_nginx_modsecurity_module",
            missing_file=str(Path(override_module_dir) / NGINX_MODULE_FILENAME),
        )
        return True
    return False


def nginx_pinned_archive_source_tuple() -> dict[str, str]:
    return {
        "mode": NGINX_PINNED_SOURCE_MODE,
        "repo": NGINX_PINNED_SOURCE_REPOSITORY,
        "tag": NGINX_PINNED_RELEASE_TAG,
        "ref": NGINX_PINNED_SOURCE_REF,
        "asset": NGINX_PINNED_RELEASE_ASSET_NAME,
        "sha256": NGINX_PINNED_RELEASE_ASSET_SHA256,
    }


def nginx_archive_metadata_blocker(archive: dict[str, Any]) -> str:
    if archive.get("status") != "present":
        return "archive_not_present"
    if archive.get("checksum_status") != "PASS":
        return "archive_checksum_not_pass"
    if not archive.get("archive_digest_verified"):
        return "archive_digest_not_verified"
    if archive.get("expected_sha256") != NGINX_PINNED_RELEASE_ASSET_SHA256:
        return "archive_expected_sha256_mismatch"
    if archive.get("verified_archive_sha256") != NGINX_PINNED_RELEASE_ASSET_SHA256:
        return "archive_verified_sha256_mismatch"
    if archive.get("source_tuple") != nginx_pinned_archive_source_tuple():
        return "archive_source_tuple_mismatch"
    return ""


def nginx_archive_path_blocker(archive_path: Path | None, archives_root: Path) -> str:
    archive_root = (archives_root / "nginx").resolve(strict=False)
    if (
        archive_path is None
        or archive_path.is_symlink()
        or not archive_path.is_file()
        or not is_within(archive_path.resolve(strict=False), archive_root)
    ):
        return "archive_path_not_managed"
    return ""


def nginx_archive_readback_blocker(archive_path: Path) -> str:
    try:
        if sha256_file(archive_path) != NGINX_PINNED_RELEASE_ASSET_SHA256:
            return "archive_digest_readback_mismatch"
        if not archive_can_list(archive_path):
            return "archive_list_readback_failed"
    except OSError:
        return "archive_readback_failed"
    return ""


def nginx_archive_preflight_blocked(
    record: dict[str, Any],
    plan: dict[str, Any],
    archives_root: Path,
) -> bool:
    """Refuse NGINX build/extraction unless the pinned archive is still sound."""

    archive_inputs = plan.get("archive_inputs")
    archive = archive_inputs.get("nginx", {}) if isinstance(archive_inputs, dict) else {}
    if not isinstance(archive, dict):
        archive = {}
    reason = nginx_archive_metadata_blocker(archive)
    path_value = archive.get("path")
    archive_path = Path(path_value) if isinstance(path_value, str) and path_value else None
    if not reason:
        reason = nginx_archive_path_blocker(archive_path, archives_root)
    if not reason and archive_path is not None:
        reason = nginx_archive_readback_blocker(archive_path)
    if not reason:
        return False
    record.update(
        status="blocked",
        blocker_reason="nginx_pinned_provenance_archive_not_ready",
        archive_blocker_reason=reason,
    )
    return True


def nginx_artifact_statuses(context: dict[str, Any]) -> tuple[bool, list[str], bool, list[str]]:
    local_ready, local_missing = artifact_status(context["local_artifacts"], {"nginx_bin"})
    effective_ready, effective_missing = artifact_status(context["effective_artifacts"], {"nginx_bin"})
    return local_ready, local_missing, effective_ready, effective_missing


def reconcile_nginx_cached_entry(
    plan: dict[str, Any],
    cache_root: Path,
    context: dict[str, Any],
    local_ready: bool,
    local_missing: list[str],
    effective_ready: bool,
    effective_missing: list[str],
    manifest_ready: bool,
    record: dict[str, Any],
) -> tuple[bool, list[str], bool, list[str], str]:
    root_value = plan.get("root")
    if not root_value:
        return local_ready, local_missing, effective_ready, effective_missing, ""
    stale_root = Path(str(root_value))
    if not stale_root.exists() or (local_ready and effective_ready and manifest_ready):
        return local_ready, local_missing, effective_ready, effective_missing, ""
    try:
        safe_remove_dir(stale_root, cache_root)
    except RuntimeError as exc:
        return local_ready, local_missing, effective_ready, effective_missing, str(exc)
    record["invalidation_reason"] = (
        "missing_or_incomplete_connector_manifest" if not manifest_ready else "connector_artifact_missing"
    )
    local_ready, local_missing, effective_ready, effective_missing = nginx_artifact_statuses(context)
    if local_ready and effective_ready:
        return (
            local_ready,
            local_missing,
            effective_ready,
            effective_missing,
            "connector_manifest_missing_for_external_artifacts",
        )
    return local_ready, local_missing, effective_ready, effective_missing, ""


def nginx_cached_entry_reusable(plan: dict[str, Any], local_ready: bool, effective_ready: bool) -> bool:
    return bool(plan) and local_ready and effective_ready and connector_manifest_ready(plan)


def nginx_source_build_required(local_ready: bool, effective_ready: bool) -> bool:
    """Build only when neither local nor configured NGINX artifacts are ready."""
    return not effective_ready and not local_ready


def claim_nginx_cache_entry(plan: dict[str, Any], cache_root: Path) -> str:
    root_value = plan.get("root")
    if not root_value:
        return ""
    try:
        mark_managed_cache_entry(
            Path(str(root_value)),
            cache_root,
            component="connector:nginx",
            cache_key=str(plan.get("cache_key", plan.get("connector_build_id", ""))),
        )
    except RuntimeError as exc:
        return str(exc)
    return ""


def copy_nginx_common_sources(connector_root: Path, plan: dict[str, Any]) -> Path:
    common_source_root = connector_root / "common/src"
    common_build_source_root = Path(str(plan["root"])) / "common-src"
    common_build_source_root.mkdir(parents=True, exist_ok=True)
    for common_source in sorted(common_source_root.glob("*.c")):
        shutil.copy2(common_source, common_build_source_root / common_source.name)
    # The NGINX addon compiles the staged Common translation units from this
    # directory.  request_helpers.c and response_helpers.c both include this
    # private sibling header, so stage it explicitly with the C sources rather
    # than relying on the original checkout being on the compiler include path.
    private_header = common_source_root / "header_validation_internal.h"
    shutil.copy2(private_header, common_build_source_root / private_header.name)
    return common_build_source_root


def _nginx_profile_registry_file_identity(details: os.stat_result) -> tuple[int, ...]:
    """Return the immutable attributes checked while a registry file is copied."""

    return (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_nlink,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )


def _open_nginx_profile_registry_directory(directory: Path, failure: str) -> int:
    """Open a directory without resolving a final symlink component."""

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError as exc:
        raise RuntimeError(failure) from exc
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise RuntimeError(failure)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _open_nginx_profile_registry_child_directory(
    parent_descriptor: int,
    name: str,
    *,
    create: bool,
    failure: str,
) -> int:
    """Open one stable, direct child directory through a held parent descriptor."""

    if create:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_descriptor)
        except FileExistsError:
            pass
        except OSError as exc:
            raise RuntimeError(failure) from exc
    try:
        before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            raise RuntimeError(failure)
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
    except OSError as exc:
        raise RuntimeError(failure) from exc
    try:
        after = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(after.st_mode)
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise RuntimeError(failure)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _open_nginx_profile_registry_source(
    connector_root: Path, filename: str
) -> tuple[int, os.stat_result]:
    """Open one canonical registry input after binding its inode to a descriptor."""

    connector_descriptor = _open_nginx_profile_registry_directory(
        connector_root, "nginx_profile_registry_source_directory_unsafe"
    )
    try:
        source_directory_descriptor = _open_nginx_profile_registry_child_directory(
            connector_descriptor,
            "connectors",
            create=False,
            failure="nginx_profile_registry_source_directory_unsafe",
        )
    finally:
        os.close(connector_descriptor)
    try:
        before = os.stat(
            filename,
            dir_fd=source_directory_descriptor,
            follow_symlinks=False,
        )
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError("nginx_profile_registry_source_unsafe")
        descriptor = os.open(
            filename,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=source_directory_descriptor,
        )
    except OSError as exc:
        raise RuntimeError("nginx_profile_registry_source_unsafe") from exc
    finally:
        os.close(source_directory_descriptor)
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
            or _nginx_profile_registry_file_identity(before)
            != _nginx_profile_registry_file_identity(details)
        ):
            raise RuntimeError("nginx_profile_registry_source_changed")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, details


def _open_nginx_profile_registry_destination_directory(plan_root: Path) -> int:
    """Create and hold the private cache destination without path re-resolution."""

    plan_descriptor = _open_nginx_profile_registry_directory(
        plan_root, "nginx_profile_registry_destination_directory_unsafe"
    )
    try:
        registry_descriptor = _open_nginx_profile_registry_child_directory(
            plan_descriptor,
            "profile-registry",
            create=True,
            failure="nginx_profile_registry_destination_directory_unsafe",
        )
    finally:
        os.close(plan_descriptor)
    try:
        return _open_nginx_profile_registry_child_directory(
            registry_descriptor,
            "connectors",
            create=True,
            failure="nginx_profile_registry_destination_directory_unsafe",
        )
    finally:
        os.close(registry_descriptor)


def _create_nginx_profile_registry_temporary_destination(
    destination_directory_descriptor: int,
    filename: str,
) -> tuple[str, int]:
    """Create one no-follow temporary output within a held destination directory."""

    creation_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    for _ in range(32):
        candidate = f".{filename}.{uuid.uuid4().hex}.tmp"
        try:
            descriptor = os.open(
                candidate,
                creation_flags,
                0o600,
                dir_fd=destination_directory_descriptor,
            )
        except FileExistsError:
            continue
        except OSError as exc:
            raise RuntimeError("nginx_profile_registry_destination_write_failed") from exc
        return candidate, descriptor
    raise RuntimeError("nginx_profile_registry_destination_temporary_name_exhausted")


def _read_nginx_profile_registry_source_chunk(source_descriptor: int, remaining: int) -> bytes:
    """Read a bounded source chunk while preserving the staging failure contract."""

    try:
        return os.read(source_descriptor, min(64 * 1024, remaining))
    except OSError as exc:
        raise RuntimeError("nginx_profile_registry_source_changed_during_copy") from exc


def _write_nginx_profile_registry_chunk(temporary_descriptor: int, chunk: bytes) -> None:
    """Write one source chunk completely or fail without publishing it."""

    offset = 0
    while offset < len(chunk):
        try:
            written = os.write(temporary_descriptor, chunk[offset:])
        except OSError as exc:
            raise RuntimeError("nginx_profile_registry_destination_write_failed") from exc
        if written <= 0:
            raise RuntimeError("nginx_profile_registry_destination_write_failed")
        offset += written


def _copy_nginx_profile_registry_contents(
    source_descriptor: int,
    source_size: int,
    temporary_descriptor: int,
) -> None:
    """Copy exactly the verified source length through held file descriptors."""

    remaining = source_size
    while remaining:
        chunk = _read_nginx_profile_registry_source_chunk(source_descriptor, remaining)
        if not chunk:
            raise RuntimeError("nginx_profile_registry_source_changed_during_copy")
        remaining -= len(chunk)
        _write_nginx_profile_registry_chunk(temporary_descriptor, chunk)


def _sync_nginx_profile_registry_temporary_file(
    source_descriptor: int,
    source_details: os.stat_result,
    temporary_descriptor: int,
) -> os.stat_result:
    """Sync and bind the temporary output to the previously verified source inode."""

    try:
        os.fsync(temporary_descriptor)
        os.fchmod(temporary_descriptor, stat.S_IMODE(source_details.st_mode))
    except OSError as exc:
        raise RuntimeError("nginx_profile_registry_destination_write_failed") from exc
    if _nginx_profile_registry_file_identity(os.fstat(source_descriptor)) != _nginx_profile_registry_file_identity(
        source_details
    ):
        raise RuntimeError("nginx_profile_registry_source_changed_during_copy")
    return os.fstat(temporary_descriptor)


def _close_nginx_profile_registry_temporary_descriptor(temporary_descriptor: int) -> None:
    """Close a temporary file before atomically publishing its stable inode."""

    try:
        os.close(temporary_descriptor)
    except OSError as exc:
        raise RuntimeError("nginx_profile_registry_destination_write_failed") from exc


def _publish_nginx_profile_registry_temporary_file(
    destination_directory_descriptor: int,
    temporary_name: str,
    filename: str,
    temporary_details: os.stat_result,
) -> None:
    """Atomically replace one destination child and verify the published inode."""

    try:
        os.replace(
            temporary_name,
            filename,
            src_dir_fd=destination_directory_descriptor,
            dst_dir_fd=destination_directory_descriptor,
        )
        destination_details = os.stat(
            filename,
            dir_fd=destination_directory_descriptor,
            follow_symlinks=False,
        )
        os.fsync(destination_directory_descriptor)
    except OSError as exc:
        raise RuntimeError("nginx_profile_registry_destination_write_failed") from exc
    if (
        not stat.S_ISREG(destination_details.st_mode)
        or (temporary_details.st_dev, temporary_details.st_ino)
        != (destination_details.st_dev, destination_details.st_ino)
    ):
        raise RuntimeError("nginx_profile_registry_destination_changed_after_copy")


def _cleanup_nginx_profile_registry_temporary_file(
    destination_directory_descriptor: int,
    temporary_name: str,
) -> None:
    """Best-effort descriptor-relative cleanup that cannot mask the primary error."""

    if not temporary_name:
        return
    try:
        os.unlink(temporary_name, dir_fd=destination_directory_descriptor)
    except OSError:
        pass


def _copy_nginx_profile_registry_source(
    source_descriptor: int,
    source_details: os.stat_result,
    destination_directory_descriptor: int,
    filename: str,
) -> None:
    """Copy one held source descriptor through an atomically replaced child path."""

    temporary_name = ""
    temporary_descriptor = -1
    try:
        temporary_name, temporary_descriptor = _create_nginx_profile_registry_temporary_destination(
            destination_directory_descriptor,
            filename,
        )
        _copy_nginx_profile_registry_contents(
            source_descriptor,
            source_details.st_size,
            temporary_descriptor,
        )
        temporary_details = _sync_nginx_profile_registry_temporary_file(
            source_descriptor,
            source_details,
            temporary_descriptor,
        )
        _close_nginx_profile_registry_temporary_descriptor(temporary_descriptor)
        temporary_descriptor = -1
        _publish_nginx_profile_registry_temporary_file(
            destination_directory_descriptor,
            temporary_name,
            filename,
            temporary_details,
        )
        temporary_name = ""
    except Exception:
        if temporary_descriptor >= 0:
            try:
                os.close(temporary_descriptor)
            except OSError:
                pass
        _cleanup_nginx_profile_registry_temporary_file(
            destination_directory_descriptor,
            temporary_name,
        )
        raise


def copy_nginx_profile_registry_sources(connector_root: Path, plan: dict[str, Any]) -> Path:
    """Stage canonical registry inputs without reopening untrusted path components."""

    plan_root = Path(str(plan["root"]))
    profile_registry_build_root = plan_root / "profile-registry"
    destination_directory_descriptor = _open_nginx_profile_registry_destination_directory(plan_root)
    try:
        for filename in ("profile_registry.c", "profile_registry.h"):
            source_descriptor, source_details = _open_nginx_profile_registry_source(
                connector_root, filename
            )
            try:
                _copy_nginx_profile_registry_source(
                    source_descriptor,
                    source_details,
                    destination_directory_descriptor,
                    filename,
                )
            finally:
                os.close(source_descriptor)
    finally:
        os.close(destination_directory_descriptor)
    return profile_registry_build_root


class NginxBuildEnvironmentInputs(NamedTuple):
    """Immutable call boundary for one NGINX connector build environment."""

    connector_root: Path
    framework_root: Path
    cache_root: Path
    build_root: Path
    sources_root: Path
    archives_root: Path
    modsecurity: dict[str, Any]
    protocol_inputs: dict[str, Any]
    protocol_profile: str
    quic_tls_archive: str
    common_build_source_root: Path
    profile_registry_build_root: Path
    context: dict[str, Any]


def nginx_build_environment(
    env: dict[str, str],
    inputs: NginxBuildEnvironmentInputs,
) -> dict[str, str]:
    # Framework common.sh owns the reviewed QUIC TLS pin tuple and validates
    # inherited values before any source preparation.  H1/H2 metadata uses
    # empty/not-used TLS fields, but those are output facts, not child-process
    # pin overrides.  Passing them through would correctly fail Framework's
    # guard as an attempted empty override.  H3 alone consumes the resolved
    # tuple as build input, so only it receives an explicit replacement.
    quic_tls_overrides: dict[str, str] = {}
    if inputs.protocol_profile == "h1-h2-h3-quic":
        quic_tls_overrides = {
            "NGINX_QUIC_TLS_LIBRARY": str(inputs.protocol_inputs.get("tls_library", "")),
            "NGINX_QUIC_TLS_VERSION": str(inputs.protocol_inputs.get("tls_version", "")),
            "NGINX_QUIC_TLS_SOURCE_URL": str(inputs.protocol_inputs.get("tls_source_url", "")),
            "NGINX_QUIC_TLS_SOURCE_SHA256": str(inputs.protocol_inputs.get("tls_source_sha256", "")),
        }
    return build_env(
        env,
        FRAMEWORK_ROOT=str(inputs.framework_root),
        CONNECTOR_ROOT=str(inputs.connector_root),
        CONNECTOR_COMPONENT_CACHE=str(inputs.cache_root),
        SOURCE_ROOT=str(inputs.sources_root),
        MODSECURITY_SOURCE_DIR=str(inputs.sources_root / "ModSecurity_V3"),
        MODSECURITY_V3_SOURCE_DIR=str(inputs.sources_root / "ModSecurity_V3"),
        MODSECURITY_V3_ROOT=str(inputs.sources_root / "ModSecurity_V3"),
        BUILD_ROOT=str(inputs.cache_root),
        TMP_ROOT=str(inputs.build_root / "tmp"),
        LOG_ROOT=str(inputs.build_root / "logs"),
        LOG_DIR=str(inputs.context["nginx_build_root"] / "logs/nginx"),
        NGINX_BUILD_DIR=str(inputs.context["nginx_build_root"]),
        NGINX_BUILD_OWNER_ROOT=str(inputs.cache_root / "builds" / "connectors"),
        NGINX_PREFIX=str(inputs.context["nginx_prefix"]),
        NGINX_BINARY=str(inputs.context["local_nginx_bin"]),
        NGINX_MODULE=str(inputs.context["local_module"]),
        NGINX_PROTOCOL_PROFILE=inputs.protocol_profile,
        **quic_tls_overrides,
        NGINX_QUIC_TLS_ARCHIVE=inputs.quic_tls_archive,
        NGINX_DOWNLOAD_DIR=str(inputs.archives_root / "nginx"),
        MSCONNECTOR_COMMON_SRC=str(inputs.common_build_source_root),
        MSCONNECTOR_PROFILE_REGISTRY_ROOT=str(inputs.profile_registry_build_root),
        MODSECURITY_SHARED_PREFIX=str(inputs.modsecurity.get("prefix", "")),
        MODSECURITY_BUILD_ID=str(inputs.modsecurity.get("build_id", "")),
        # The Framework-owned NGINX provisioner extracts the pinned source
        # archive. Archive ownership is not build input, and restoring
        # archive-recorded numeric owners can fail in user namespaces or on
        # id-mapped mounts. Replace, rather than inherit, TAR_OPTIONS so a
        # caller cannot re-enable owner restoration for this private route.
        TAR_OPTIONS="--no-same-owner",
        BUILD_NGINX_FROM_SOURCE="1",
        AUTO_FETCH_SMOKE_SOURCES="0",
        REFRESH="1",
        SKIP_RUNTIME_COMPONENT_PREPARE="1",
    )


def nginx_build_blocker_details(blocker: str) -> dict[str, str]:
    build_component = "nginx_modsecurity_module_build"
    if blocker == "missing_libmodsecurity_build":
        build_component = "libmodsecurity_build"
    elif blocker == "missing_local_nginx_build":
        build_component = "nginx_source_build"
    return {
        "build_component": build_component,
        "env_variable_can_set": NATIVE_NGINX_OVERRIDE_ENV,
    }


def nginx_refresh_build_artifacts(record: dict[str, Any], context: dict[str, Any]) -> None:
    artifacts_file = context["nginx_build_root"] / "logs/nginx/artifacts.txt"
    if artifacts_file.is_symlink() or not artifacts_file.is_file():
        return
    try:
        record["artifacts"] = read_key_values(artifacts_file)
    except OSError as exc:
        record["artifacts_readback_error"] = str(exc)


def nginx_staged_build_log_root(
    plan: dict[str, Any],
    cache_root: Path,
    context: dict[str, Any],
) -> Path | None:
    """Return only the current marked staging root that owns the make log."""

    root_value = plan.get("root")
    build_root_value = plan.get("build_root")
    cache_key = plan.get("cache_key", plan.get("connector_build_id", ""))
    context_build_root = context.get("nginx_build_root")
    if not all(isinstance(value, str) and value for value in (root_value, build_root_value, cache_key)):
        return None
    if not isinstance(context_build_root, Path):
        return None
    try:
        staging_root, managed_root = validate_managed_cache_child(Path(root_value), cache_root)
    except RuntimeError:
        return None
    marker = read_json(cache_entry_marker_path(staging_root, managed_root))
    if (
        marker.get("component") != "connector:nginx"
        or marker.get("cache_key") != cache_key
        or not cache_entry_marker_valid(staging_root, managed_root)
    ):
        return None
    expected_build_root = staging_root / "build"
    if (
        Path(build_root_value).resolve(strict=False) != expected_build_root
        or context_build_root.resolve(strict=False) != expected_build_root
    ):
        return None
    return staging_root


def append_nginx_staged_make_log_diagnostics(
    log_path: Path,
    plan: dict[str, Any],
    cache_root: Path,
    context: dict[str, Any],
) -> None:
    """Persist only a bounded sanitized inner make-log tail before cleanup."""

    try:
        staging_root = nginx_staged_build_log_root(plan, cache_root, context)
    except (OSError, RuntimeError, ValueError):
        # This is diagnostic-only after the primary build already failed.
        staging_root = None
    if staging_root is None:
        lines = [f"{NGINX_STAGED_MAKE_LOG_PREFIX} inner_make_log_unavailable=staging_identity"]
    else:
        try:
            rendered, truncated = bounded_fixed_log_tail(
                staging_root,
                NGINX_STAGED_MAKE_LOG_RELATIVE_PATH,
                "inner_make_log",
                output_prefix=NGINX_STAGED_MAKE_LOG_LINE_PREFIX,
            )
        except DiagnosticInputError as exc:
            lines = [f"{NGINX_STAGED_MAKE_LOG_PREFIX} inner_make_log_unavailable={exc.reason}"]
        except OSError:
            lines = [f"{NGINX_STAGED_MAKE_LOG_PREFIX} inner_make_log_unavailable=unavailable"]
        else:
            lines = [
                f"{NGINX_STAGED_MAKE_LOG_PREFIX} inner_make_log_tail_truncated={'true' if truncated else 'false'}",
                f"{NGINX_STAGED_MAKE_LOG_PREFIX} begin bounded nginx-make.log tail",
                *(NGINX_STAGED_MAKE_LOG_LINE_PREFIX + line for line in rendered),
                f"{NGINX_STAGED_MAKE_LOG_PREFIX} end bounded nginx-make.log tail",
            ]
    try:
        with log_path.open("a", encoding="utf-8", errors="replace") as log_file:
            log_file.write("\n" + "\n".join(lines) + "\n")
    except OSError:
        # This is diagnostic-only after the primary build already failed.
        return


def build_nginx_source(
    env: dict[str, str],
    connector_root: Path,
    framework_root: Path,
    cache_root: Path,
    build_root: Path,
    sources_root: Path,
    archives_root: Path,
    modsecurity: dict[str, Any],
    plan: dict[str, Any],
    protocol_inputs: dict[str, Any],
    quic_tls_archive: str,
    context: dict[str, Any],
    record: dict[str, Any],
) -> tuple[bool, list[str], bool]:
    common_build_source_root = copy_nginx_common_sources(connector_root, plan)
    profile_registry_build_root = copy_nginx_profile_registry_sources(connector_root, plan)
    log_path = build_root / "logs/runtime-components/nginx-build.log"
    proc = run_build(
        framework_root / "ci/provisioning/prepare-nginx-build.sh",
        nginx_build_environment(
            env,
            NginxBuildEnvironmentInputs(
                connector_root=connector_root,
                framework_root=framework_root,
                cache_root=cache_root,
                build_root=build_root,
                sources_root=sources_root,
                archives_root=archives_root,
                modsecurity=modsecurity,
                protocol_inputs=protocol_inputs,
                protocol_profile=str(protocol_inputs.get("profile", "h1")),
                quic_tls_archive=quic_tls_archive,
                common_build_source_root=common_build_source_root,
                profile_registry_build_root=profile_registry_build_root,
                context=context,
            ),
        ),
        connector_root,
        log_path,
    )
    if proc.returncode != 0:
        append_nginx_staged_make_log_diagnostics(log_path, plan, cache_root, context)
    record["build_log"] = str(log_path)
    record["build_exit_code"] = proc.returncode
    nginx_refresh_build_artifacts(record, context)
    local_ready, local_missing = artifact_status(context["local_artifacts"], {"nginx_bin"})
    if proc.returncode == 0 and local_ready:
        return local_ready, local_missing, True
    diagnostic_text = "\n".join(
        [
            proc.stdout,
            read_text_if_file(log_path),
            read_text_if_file(cache_root / "logs/nginx/nginx-configure.log"),
            read_text_if_file(cache_root / "logs/nginx/nginx-make.log"),
        ]
    )
    blocker = map_nginx_blocker(diagnostic_text, local_missing)
    record.update(
        status="failed",
        blocker_reason=blocker,
        missing_files=local_missing,
        **nginx_build_blocker_details(blocker),
    )
    return local_ready, local_missing, False


def update_nginx_effective_artifacts(context: dict[str, Any]) -> None:
    if not context["override_bin"]:
        context["effective_bin"] = context["local_nginx_bin"]
    if not context["override_module_dir"]:
        context["effective_module"] = context["local_module"]
    context["effective_artifacts"] = {
        "nginx_bin": context["effective_bin"],
        "module_file": context["effective_module"],
    }


def prepare_nginx_runtime(
    env: dict[str, str],
    connector_root: Path,
    framework_root: Path,
    cache_root: Path,
    build_root: Path,
    sources_root: Path,
    archives_root: Path,
    modsecurity: dict[str, Any] | None = None,
    plan: dict[str, Any] | None = None,
    _transactional: bool = False,
) -> dict[str, Any]:
    """Prepare NGINX while preserving atomic staging for keyed cache plans."""
    try:
        nginx_pinned_provenance(env)
        nginx_pinned_provenance_required(env)
    except RuntimeError as exc:
        return {
            "source": "connector-local-build",
            "connector": "nginx",
            "status": "blocked",
            "blocker_reason": str(exc),
        }
    return prepare_connector_with_optional_staging(
        "nginx",
        cache_root,
        plan,
        _transactional,
        lambda active_plan: _prepare_nginx_runtime_for_plan(
            env,
            connector_root,
            framework_root,
            cache_root,
            build_root,
            sources_root,
            archives_root,
            modsecurity,
            active_plan,
        ),
    )


def nginx_prepare_or_reuse_runtime(
    env: dict[str, str],
    connector_root: Path,
    framework_root: Path,
    cache_root: Path,
    build_root: Path,
    sources_root: Path,
    archives_root: Path,
    modsecurity: dict[str, Any],
    plan: dict[str, Any],
    protocol_inputs: dict[str, Any],
    quic_tls_archive: str,
    context: dict[str, Any],
    record: dict[str, Any],
) -> dict[str, Any]:
    local_ready, local_missing, effective_ready, effective_missing = nginx_artifact_statuses(context)
    manifest_ready = connector_manifest_ready(plan) if plan else False
    (
        local_ready,
        local_missing,
        effective_ready,
        effective_missing,
        cache_blocker,
    ) = reconcile_nginx_cached_entry(
        plan,
        cache_root,
        context,
        local_ready,
        local_missing,
        effective_ready,
        effective_missing,
        manifest_ready,
        record,
    )
    if cache_blocker:
        record.update(status="blocked", blocker_reason=cache_blocker)
        return finish_planned_connector_record(plan, record)
    if nginx_cached_entry_reusable(plan, local_ready, effective_ready):
        update_nginx_runtime_readback(record, context)
        nginx_refresh_build_artifacts(record, context)
        record.update(
            status="reused",
            nginx_bin=str(context["effective_bin"]),
            module_dir=str(context["effective_module"].parent),
            module_file=str(context["effective_module"]),
            tree=tree_manifest(context["nginx_build_root"]),
        )
        nginx_runtime_contract_preflight_blocked(record, env, plan, context)
        return finish_planned_connector_record(plan, record)
    claim_error = claim_nginx_cache_entry(plan, cache_root)
    if claim_error:
        record.update(status="blocked", blocker_reason=claim_error)
        return finish_planned_connector_record(plan, record)
    if nginx_source_build_required(local_ready, effective_ready):
        local_ready, local_missing, build_succeeded = build_nginx_source(
            env,
            connector_root,
            framework_root,
            cache_root,
            build_root,
            sources_root,
            archives_root,
            modsecurity,
            plan,
            protocol_inputs,
            quic_tls_archive,
            context,
            record,
        )
        if not build_succeeded:
            return finish_planned_connector_record(plan, record)
    update_nginx_effective_artifacts(context)
    update_nginx_runtime_readback(record, context)
    effective_ready, effective_missing = artifact_status(context["effective_artifacts"], {"nginx_bin"})
    if not effective_ready:
        blocker = map_nginx_blocker("", effective_missing)
        record.update(
            status="blocked",
            blocker_reason=blocker,
            missing_files=effective_missing,
            build_component="nginx_native_runtime_inventory",
            env_variable_can_set=NATIVE_NGINX_OVERRIDE_ENV,
        )
        return finish_planned_connector_record(plan, record)
    record.update(
        status="built" if plan else "present",
        invalidation_reason=record.get("invalidation_reason")
        or ("missing_or_stale_connector_build" if plan else ""),
        nginx_bin=str(context["effective_bin"]),
        module_dir=str(context["effective_module"].parent),
        module_file=str(context["effective_module"]),
        tree=tree_manifest(context["nginx_build_root"]),
    )
    nginx_refresh_build_artifacts(record, context)
    nginx_runtime_contract_preflight_blocked(record, env, plan, context)
    return finish_planned_connector_record(plan, record)


def _prepare_nginx_runtime_for_plan(
    env: dict[str, str],
    connector_root: Path,
    framework_root: Path,
    cache_root: Path,
    build_root: Path,
    sources_root: Path,
    archives_root: Path,
    modsecurity: dict[str, Any] | None,
    plan: dict[str, Any] | None,
) -> dict[str, Any]:
    modsecurity = modsecurity or {}
    plan = plan or {}
    try:
        nginx_pinned_provenance(env)
        nginx_pinned_provenance_required(env)
    except RuntimeError as exc:
        return finish_planned_connector_record(
            plan,
            {
                "source": "connector-local-build",
                "connector": "nginx",
                "status": "blocked",
                "blocker_reason": str(exc),
            },
        )
    protocol_inputs, protocol_profile, quic_tls_archive, protocol_blocker = nginx_protocol_context(
        env,
        plan,
        archives_root,
    )
    if protocol_blocker:
        record = {
            "source": "connector-local-build",
            "connector": "nginx",
            "status": "blocked",
            "blocker_reason": protocol_blocker,
            "protocol_profile": protocol_profile,
        }
        return finish_planned_connector_record(plan, record)
    context = nginx_runtime_context(env, plan, build_root, modsecurity)
    record = nginx_runtime_record(
        env,
        plan,
        archives_root,
        modsecurity,
        protocol_inputs,
        protocol_profile,
        context,
    )
    if nginx_archive_preflight_blocked(record, plan, archives_root):
        return finish_planned_connector_record(plan, record)
    if nginx_preflight_blocked(record, modsecurity, context):
        return finish_planned_connector_record(plan, record)
    return nginx_prepare_or_reuse_runtime(
        env,
        connector_root,
        framework_root,
        cache_root,
        build_root,
        sources_root,
        archives_root,
        modsecurity,
        plan,
        protocol_inputs,
        quic_tls_archive,
        context,
        record,
    )


def haproxy_runtime_build_key(plan: dict[str, Any]) -> str:
    """Return one validated cache identity for the mutable runtime namespace."""
    cache_key = plan.get("cache_key")
    connector_build_id = plan.get("connector_build_id")
    cache_identity = plan.get("cache_identity")
    identity_key = cache_identity.get("cache_key") if isinstance(cache_identity, dict) else None
    if not (
        plan.get("connector") == "haproxy"
        and isinstance(cache_key, str)
        and cache_key
        and connector_build_id == cache_key
        and identity_key == cache_key
    ):
        raise RuntimeError("haproxy_source_build_key_mismatch")
    if cache_key in {".", ".."} or not SAFE_RUNTIME_BUILD_KEY.fullmatch(cache_key):
        raise RuntimeError("unsafe_haproxy_runtime_build_key")
    identity_inputs = cache_identity.get("extra_inputs")
    source_hash = plan.get("source_hash")
    if not (
        cache_identity.get("component") == "haproxy"
        and cache_identity_is_self_consistent(cache_identity)
        and isinstance(identity_inputs, dict)
        and isinstance(source_hash, str)
        and source_hash
        and identity_inputs.get("connector_source_hash") == source_hash
    ):
        raise RuntimeError("haproxy_source_build_key_mismatch")
    return cache_key


def haproxy_runtime_context(plan: dict[str, Any], build_root: Path) -> dict[str, Any]:
    cache_key = haproxy_runtime_build_key(plan)
    invocation_build_root = build_root.resolve()
    cache_root = Path(str(plan.get("cache_root", ""))).resolve()
    root = (
        invocation_build_root / "runtime-components" / "haproxy" / cache_key
    ).resolve()
    if root == invocation_build_root or not is_within(root, invocation_build_root):
        raise RuntimeError("haproxy_runtime_path_outside_build_root")
    if paths_overlap(root, cache_root):
        raise RuntimeError("haproxy_runtime_output_overlaps_component_cache")
    haproxy_runtime_build_dir = root / "haproxy-runtime-build"
    haproxy_runtime_build_worktree = haproxy_runtime_build_dir / "worktree"
    haproxy_runtime_dir = root / "haproxy-runtime/haproxy"
    haproxy_bin = haproxy_runtime_dir / "sbin/haproxy"
    binding_dir = root / "haproxy-modsecurity-binding"
    spoa_dir = root / "haproxy-spoa-runtime"
    spoa_bin = spoa_dir / "haproxy-modsecurity-spoa"
    paths_env = binding_dir / "paths.env"
    framework_log_dir = root / "logs" / "haproxy-prepare"
    return {
        "root": root,
        "build_root": invocation_build_root,
        "cache_root": cache_root,
        "haproxy_runtime_build_dir": haproxy_runtime_build_dir,
        "haproxy_runtime_build_worktree": haproxy_runtime_build_worktree,
        "haproxy_runtime_dir": haproxy_runtime_dir,
        "haproxy_bin": haproxy_bin,
        "binding_dir": binding_dir,
        "spoa_dir": spoa_dir,
        "spoa_bin": spoa_bin,
        "paths_env": paths_env,
        "log_path": root / "logs/haproxy-build.log",
        "framework_log_dir": framework_log_dir,
        "framework_build_log": framework_log_dir / "haproxy-build.log",
    }


def haproxy_runtime_record(
    plan: dict[str, Any],
    modsecurity: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    return {
        "connector": "haproxy",
        "connector_build_id": plan.get("connector_build_id", ""),
        "modsecurity_build_id": modsecurity.get("build_id", ""),
        "cache_schema_version": plan.get("cache_schema_version", ""),
        "cache_key": plan.get("cache_key", ""),
        "patchset_sha256": plan.get("patchset_sha256", ""),
        "target_architecture": plan.get("target_architecture", ""),
        "source_hash": plan.get("source_hash", ""),
        "build_flags": plan.get("build_flags", ""),
        "build_path": str(context["root"]),
        "haproxy_runtime_build_dir": str(context["haproxy_runtime_build_dir"]),
        "haproxy_runtime_dir": str(context["haproxy_runtime_dir"]),
        "haproxy_bin": str(context["haproxy_bin"]),
        "spoa_runtime_bin": str(context["spoa_bin"]),
        "modsecurity_binding_dir": str(context["binding_dir"]),
        "paths_env": str(context["paths_env"]),
        "framework_prepare_log_dir": str(context["framework_log_dir"]),
        "framework_prepare_build_log": str(context["framework_build_log"]),
        "output_paths": {
            "binary": str(context["haproxy_bin"]),
            "module": str(context["spoa_bin"]),
            "config": str(context["paths_env"]),
        },
        "status": "unknown",
        "blocker_reason": "",
    }


def write_haproxy_record(plan: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    write_connector_manifest(plan, record)
    return record


def haproxy_preflight_blocked(
    record: dict[str, Any],
    modsecurity: dict[str, Any],
    cache_root: Path,
    context: dict[str, Any],
) -> bool:
    if modsecurity.get("status") not in READY_COMPONENT_STATUSES:
        record.update(
            status="blocked",
            blocker_reason=modsecurity.get("blocker_reason") or "modsecurity_build_failed",
        )
        return True
    for path in (
        context["root"],
        context["haproxy_runtime_build_dir"],
        context["haproxy_runtime_build_worktree"],
        context["haproxy_runtime_dir"],
        context["haproxy_bin"],
        context["binding_dir"],
        context["spoa_dir"],
        context["spoa_bin"],
        context["paths_env"],
        context["log_path"],
        context["framework_log_dir"],
        context["framework_build_log"],
    ):
        if (
            is_system_path(path)
            or path == context["build_root"]
            or not is_within(path, context["build_root"])
        ):
            record.update(
                status="blocked",
                blocker_reason="haproxy_runtime_path_outside_build_root",
                blocked_path=str(path),
            )
            return True
        if paths_overlap(path, cache_root):
            record.update(
                status="blocked",
                blocker_reason="haproxy_runtime_output_overlaps_component_cache",
                blocked_path=str(path),
            )
            return True
    return False


def reconcile_haproxy_cached_entry(
    plan: dict[str, Any],
    context: dict[str, Any],
    record: dict[str, Any],
) -> str:
    root = context["root"]
    if not root.exists() or haproxy_cached_entry_reusable(plan, context):
        return ""
    try:
        safe_remove_dir(root, context["build_root"])
    except RuntimeError as exc:
        return str(exc)
    record["invalidation_reason"] = "missing_or_incomplete_haproxy_runtime"
    return ""


def haproxy_cached_entry_reusable(plan: dict[str, Any], context: dict[str, Any]) -> bool:
    return (
        cache_root_marker_valid(Path(context["build_root"]))
        and cache_entry_marker_valid(Path(context["root"]), Path(context["build_root"]))
        and executable(context["haproxy_bin"])
        and executable(context["spoa_bin"])
        and context["paths_env"].is_file()
        and connector_manifest_ready(plan)
    )


def claim_haproxy_cache_entry(plan: dict[str, Any], cache_root: Path) -> str:
    try:
        mark_managed_cache_entry(
            Path(str(plan["root"])),
            cache_root,
            component="connector:haproxy",
            cache_key=str(plan.get("cache_key", plan.get("connector_build_id", ""))),
        )
    except RuntimeError as exc:
        return str(exc)
    return ""


def claim_haproxy_runtime_entry(plan: dict[str, Any], context: dict[str, Any]) -> str:
    """Pre-claim and create the invocation-local runtime tree fail closed.

    A later incomplete build may remove only a registered child of its
    invocation build root.  Registering the deterministic, verified path
    before a non-idempotent create preserves that cleanup authority across
    interruption and rejects a directory that appeared concurrently.
    """
    try:
        build_root = ensure_managed_cache_root(Path(context["build_root"]))
        root = Path(context["root"])
        marker_path = cache_entry_marker_path(root, build_root)
        mark_managed_cache_entry(
            root,
            build_root,
            component="runtime:haproxy",
            cache_key=haproxy_runtime_build_key(plan),
        )
        try:
            root.mkdir(parents=True)
        except FileExistsError:
            marker_path.unlink(missing_ok=True)
            return f"haproxy_runtime_root_already_exists: {root}"
        if (
            root.is_symlink()
            or not root.is_dir()
            or not cache_entry_marker_valid(root, build_root)
        ):
            marker_path.unlink(missing_ok=True)
            return f"haproxy_runtime_root_invalid_after_claim: {root}"
    except (OSError, RuntimeError) as exc:
        return str(exc)
    return ""


def haproxy_prepare_environment(
    env: dict[str, str],
    connector_root: Path,
    framework_root: Path,
    cache_root: Path,
    build_root: Path,
    sources_root: Path,
    archives_root: Path,
    context: dict[str, Any],
) -> dict[str, str]:
    return build_env(
        env,
        FRAMEWORK_ROOT=str(framework_root),
        CONNECTOR_ROOT=str(connector_root),
        CONNECTOR_COMPONENT_CACHE=str(cache_root),
        SOURCE_ROOT=str(sources_root),
        BUILD_ROOT=str(context["build_root"]),
        TMP_ROOT=str(context["root"] / "tmp"),
        LOG_ROOT=str(context["root"] / "logs"),
        LOG_DIR=str(context["framework_log_dir"]),
        HAPROXY_SOURCE_ROOT=str(sources_root / "haproxy"),
        HAPROXY_DOWNLOAD_DIR=str(archives_root / "haproxy"),
        HAPROXY_SOURCE_DIR=str(
            sources_root / "haproxy" / f"haproxy-{env.get('HAPROXY_VERSION', DEFAULT_HAPROXY_VERSION)}"
        ),
        HAPROXY_RUNTIME_BUILD_DIR=str(context["haproxy_runtime_build_dir"]),
        HAPROXY_RUNTIME_BUILD_WORKTREE=str(context["haproxy_runtime_build_worktree"]),
        HAPROXY_RUNTIME_DIR=str(context["haproxy_runtime_dir"]),
        HAPROXY_BIN=str(context["haproxy_bin"]),
        REFRESH="0",
        SKIP_RUNTIME_COMPONENT_PREPARE="1",
    )


def haproxy_prepare_reached_execution(prep: subprocess.CompletedProcess[str]) -> bool:
    return any(
        marker in prep.stdout
        for marker in (
            "haproxy_prepare: running haproxy-source-extract",
            "haproxy_prepare: running haproxy-source-copy",
            "haproxy_prepare: running haproxy-build",
            "haproxy_prepare: running haproxy-binary-stage",
        )
    )


def record_haproxy_prepare_failure(
    record: dict[str, Any],
    prep: subprocess.CompletedProcess[str],
) -> None:
    # Exit 77 is a pre-execution availability block only if no build phase
    # was reached.  Once the helper starts a build, retain the failed status.
    if prep.returncode == 77 and not haproxy_prepare_reached_execution(prep):
        record.update(status="blocked", blocker_reason="missing_haproxy_runtime_build")
        return
    record.update(
        status="failed",
        blocker_reason="haproxy_runtime_prepare_failed",
        build_exit_code=prep.returncode,
    )


def haproxy_binding_environment(
    prep_env: dict[str, str],
    connector_root: Path,
    modsecurity: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, str]:
    return build_env(
        prep_env,
        REPO_ROOT=str(connector_root),
        HAPROXY_SPOA_RUNTIME_DIR=str(context["spoa_dir"]),
        HAPROXY_MODSECURITY_BINDING_DIR=str(context["binding_dir"]),
        MODSECURITY_INCLUDE_DIR=str(modsecurity.get("include_dir", "")),
        MODSECURITY_LIB_DIR=str(modsecurity.get("lib_dir", "")),
        MODSECURITY_INCLUDE_CANDIDATES=str(modsecurity.get("include_dir", "")),
        MODSECURITY_LIB_CANDIDATES=str(modsecurity.get("lib_dir", "")),
    )


def run_haproxy_binding_build(
    connector_root: Path,
    make_env: dict[str, str],
    log_path: Path,
) -> subprocess.CompletedProcess[str]:
    proc = run_env(
        [
            "make",
            "-C",
            str(connector_root / "connectors/haproxy"),
            *HAPROXY_BINDING_BUILD_TARGETS,
        ],
        env=make_env,
        errors="replace",
    )
    with log_path.open("a", encoding="utf-8", errors="replace") as handle:
        handle.write("\n[haproxy-modsecurity-binding]\n")
        handle.write(proc.stdout)
        handle.write(proc.stderr)
    return proc


def haproxy_failure_diagnostics_for_line(raw_line: str) -> tuple[tuple[str, ...], ...]:
    """Return the fixed diagnostic values allowlisted for one tool-output line."""

    return tuple(
        diagnostics
        for pattern, diagnostics in HAPROXY_FAILURE_DIAGNOSTIC_RULES
        if pattern.search(raw_line)
    )


def append_haproxy_failure_diagnostics(
    selected: list[str], diagnostics: tuple[str, ...]
) -> bool:
    """Append unseen fixed diagnostics and report whether the bounded list overflowed."""

    for diagnostic in diagnostics:
        if diagnostic in selected:
            continue
        if len(selected) >= HAPROXY_FAILURE_DIAGNOSTIC_MAX_LINES:
            return True
        selected.append(diagnostic)
    return False


def haproxy_failure_output_lines(output: str) -> Iterator[str]:
    """Yield a per-stream bounded prefix of lines for fixed diagnostics only.

    An overlong untrusted line ends the scan for that stream rather than being
    copied, truncated, or searched beyond the configured bound.
    """

    position = 0
    for _ in range(HAPROXY_FAILURE_DIAGNOSTIC_SCAN_MAX_LINES):
        if position >= len(output):
            return
        scan_end = min(len(output), position + HAPROXY_FAILURE_DIAGNOSTIC_MAX_LINE_CHARS + 1)
        line_end = output.find("\n", position, scan_end)
        if line_end < 0:
            if scan_end == len(output):
                yield output[position:scan_end].removesuffix("\r")
            return
        yield output[position:line_end].removesuffix("\r")
        position = line_end + 1


def ascii_decimal(value: str) -> bool:
    """Return whether ``value`` consists of one or more ASCII decimal digits."""

    return bool(value) and all("0" <= character <= "9" for character in value)


def haproxy_make_footer_target_text(footer_target: str) -> str:
    """Remove the first GNU Make ``:line:`` location prefix, when present."""

    for index, character in enumerate(footer_target):
        if character != ":":
            continue
        line_start = index + 1
        line_end = line_start
        while line_end < len(footer_target) and "0" <= footer_target[line_end] <= "9":
            line_end += 1
        if line_end == line_start or line_end == len(footer_target):
            continue
        if footer_target[line_end] == ":":
            return footer_target[line_end + 1 :].lstrip(HAPROXY_FAILURE_FOOTER_WHITESPACE)
    return footer_target


def haproxy_make_footer_target(raw_line: str) -> str | None:
    """Parse one GNU Make footer in linear time without retaining raw output."""

    if not raw_line.startswith("make"):
        return None
    footer = raw_line[len("make") :]
    if footer.startswith("["):
        level_end = footer.find("]")
        if level_end <= 1 or not ascii_decimal(footer[1:level_end]):
            return None
        footer = footer[level_end + 1 :]
    if not footer.startswith(HAPROXY_FAILURE_FOOTER_MARKER):
        return None
    footer = footer[len(HAPROXY_FAILURE_FOOTER_MARKER) :]
    target_end = footer.find(HAPROXY_FAILURE_FOOTER_SUFFIX)
    if target_end <= 0:
        return None
    target = footer[:target_end]
    exit_code = footer[target_end + len(HAPROXY_FAILURE_FOOTER_SUFFIX) :]
    if "]" in target or not ascii_decimal(exit_code):
        return None
    return haproxy_make_footer_target_text(target)


def haproxy_failure_target_from_footers(
    proc: subprocess.CompletedProcess[str], expected_target_paths: dict[str, str] | None = None
) -> str | None:
    """Return the first logical target named by an exact GNU Make stderr footer."""

    # GNU Make writes its failure footer to stderr.  Ignore stdout entirely so
    # compiler output cannot forge a target label or influence footer order.
    expected_target_paths = expected_target_paths or {}
    for raw_line in haproxy_failure_output_lines(str(proc.stderr or "")):
        target = haproxy_make_footer_target(raw_line)
        if target is None:
            continue
        if target in HAPROXY_BINDING_BUILD_TARGETS:
            return target
        for logical_target in HAPROXY_BINDING_BUILD_TARGETS:
            if target == expected_target_paths.get(logical_target):
                return logical_target
    return None


def append_haproxy_failure_output_diagnostics(
    selected: list[str], output: str, is_stderr: bool
) -> bool:
    """Append fixed diagnostics for one bounded stream and report truncation."""

    for raw_line in haproxy_failure_output_lines(output):
        if is_stderr:
            resolver_diagnostics = HAPROXY_RESOLVER_SENTINEL_DIAGNOSTICS.get(raw_line)
            if resolver_diagnostics is not None and append_haproxy_failure_diagnostics(
                selected, resolver_diagnostics
            ):
                selected[-1] = "[classification list truncated]"
                return True
        for diagnostics in haproxy_failure_diagnostics_for_line(raw_line):
            if append_haproxy_failure_diagnostics(selected, diagnostics):
                selected[-1] = "[classification list truncated]"
                return True
    return False


def haproxy_failure_diagnostic_lines(
    proc: subprocess.CompletedProcess[str], expected_target_paths: dict[str, str] | None = None
) -> list[str]:
    """Return only repository-known diagnostic constants; raw tool output stays private."""

    selected: list[str] = []
    target_failure = haproxy_failure_target_from_footers(proc, expected_target_paths)
    if target_failure is not None:
        selected.append(f"target_failure={target_failure}")
    for is_stderr, output in ((True, str(proc.stderr or "")), (False, str(proc.stdout or ""))):
        if append_haproxy_failure_output_diagnostics(selected, output, is_stderr):
            return selected
    return selected


def haproxy_resolver_cause_annotation(diagnostics: list[str]) -> str | None:
    """Return one exact resolver cause suitable for a GitHub Actions annotation."""

    matches = [
        diagnostic for diagnostic in diagnostics if diagnostic in HAPROXY_RESOLVER_CAUSE_VALUES
    ]
    return matches[0] if len(matches) == 1 else None


def emit_haproxy_binding_failure_diagnostic(
    proc: subprocess.CompletedProcess[str],
    missing_artifacts: tuple[str, ...],
    expected_target_paths: dict[str, str] | None = None,
) -> None:
    """Expose a bounded summary while retaining raw compiler output privately."""

    print(
        "prepare-runtime-components: HAProxy binding build failed "
        f"target={' '.join(HAPROXY_BINDING_BUILD_TARGETS)} exit_code={proc.returncode} "
        "build_log=private_task_owned_haproxy-build.log",
        file=sys.stderr,
    )
    for artifact in missing_artifacts:
        print(
            f"prepare-runtime-components: HAProxy binding build missing_artifact={artifact}",
            file=sys.stderr,
        )
    diagnostics = haproxy_failure_diagnostic_lines(proc, expected_target_paths)
    if not diagnostics:
        diagnostics = ["[no allowlisted compiler or linker failure classification captured]"]
    for diagnostic in diagnostics:
        print(
            f"prepare-runtime-components: HAProxy binding diagnostic: {diagnostic}",
            file=sys.stderr,
        )
    resolver_cause = haproxy_resolver_cause_annotation(diagnostics)
    if resolver_cause is not None and os.environ.get("GITHUB_ACTIONS") == "true":
        print(
            f"::error title=HAProxy resolver diagnostic::{resolver_cause}",
            file=sys.stderr,
        )


def prepare_haproxy_runtime(
    env: dict[str, str],
    connector_root: Path,
    framework_root: Path,
    cache_root: Path,
    build_root: Path,
    sources_root: Path,
    archives_root: Path,
    modsecurity: dict[str, Any],
    plan: dict[str, Any],
    _transactional: bool = False,
) -> dict[str, Any]:
    try:
        haproxy_runtime_build_key(plan)
    except RuntimeError as exc:
        return {
            "connector": "haproxy",
            "connector_build_id": plan.get("connector_build_id", ""),
            "cache_key": plan.get("cache_key", ""),
            "modsecurity_build_id": modsecurity.get("build_id", ""),
            "status": "blocked",
            "blocker_reason": str(exc),
        }
    if plan.get("root") and not _transactional:
        return prepare_connector_transactionally(
            "haproxy",
            cache_root,
            plan,
            lambda staged_plan, _inner: prepare_haproxy_runtime(
                env,
                connector_root,
                framework_root,
                cache_root,
                build_root,
                sources_root,
                archives_root,
                modsecurity,
                staged_plan,
                _transactional=True,
            ),
        )
    context = haproxy_runtime_context(plan, build_root)
    record = haproxy_runtime_record(plan, modsecurity, context)
    if haproxy_preflight_blocked(record, modsecurity, cache_root, context):
        return write_haproxy_record(plan, record)
    cache_blocker = reconcile_haproxy_cached_entry(plan, context, record)
    if cache_blocker:
        record.update(status="blocked", blocker_reason=cache_blocker)
        return write_haproxy_record(plan, record)
    if haproxy_cached_entry_reusable(plan, context):
        record.update(status="reused", tree=tree_manifest(context["root"]))
        return write_haproxy_record(plan, record)
    claim_error = claim_haproxy_cache_entry(plan, cache_root)
    if claim_error:
        record.update(status="blocked", blocker_reason=claim_error)
        return write_haproxy_record(plan, record)
    runtime_claim_error = claim_haproxy_runtime_entry(plan, context)
    if runtime_claim_error:
        record.update(status="blocked", blocker_reason=runtime_claim_error)
        return write_haproxy_record(plan, record)
    prep_env = haproxy_prepare_environment(
        env,
        connector_root,
        framework_root,
        cache_root,
        build_root,
        sources_root,
        archives_root,
        context,
    )
    prep = run_build(
        framework_root / "ci/provisioning/prepare-haproxy-runtime.sh",
        prep_env,
        connector_root,
        context["log_path"],
    )
    record["build_log"] = str(context["log_path"])
    record["haproxy_prepare_exit_code"] = prep.returncode
    if prep.returncode != 0 or not executable(context["haproxy_bin"]):
        record_haproxy_prepare_failure(record, prep)
        return write_haproxy_record(plan, record)
    make_env = haproxy_binding_environment(prep_env, connector_root, modsecurity, context)
    proc = run_haproxy_binding_build(connector_root, make_env, context["log_path"])
    expected_target_paths = {
        "build-modsecurity-binding": str(
            context["binding_dir"]
            / HAPROXY_BINDING_FAILURE_OUTPUT_NAMES["build-modsecurity-binding"]
        ),
        "build-spoa-runtime": str(context["spoa_bin"]),
    }
    missing_artifacts = tuple(
        label
        for label, available in (
            ("spoa_runtime_binary", executable(context["spoa_bin"])),
            ("modsecurity_binding_paths", context["paths_env"].is_file()),
        )
        if not available
    )
    if proc.returncode != 0 or missing_artifacts:
        emit_haproxy_binding_failure_diagnostic(proc, missing_artifacts, expected_target_paths)
        record.update(
            status="failed",
            blocker_reason="haproxy_connector_build_failed",
            build_exit_code=proc.returncode,
        )
        return write_haproxy_record(plan, record)
    record.update(
        status="built",
        invalidation_reason=record.get("invalidation_reason") or "missing_or_stale_connector_build",
        tree=tree_manifest(context["root"]),
    )
    return write_haproxy_record(plan, record)


KNOWN_TOOL_SOURCE_SUFFIXES = frozenset({"", ".md", ".sh", ".py", ".txt", ".yaml", ".yml", ".mk", ".json"})
LOCAL_BUILD_READ_ONLY_EXECUTABLE = "local-build/read-only-executable"
REPORT_VALUE_FALLBACK = "-"


def known_tool_source_candidate(path: Path) -> bool:
    return ".git" not in path.parts and path.is_file() and path.suffix in KNOWN_TOOL_SOURCE_SUFFIXES


def known_tool_source_texts(roots: list[Path]):
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not known_tool_source_candidate(path):
                continue
            try:
                yield path, path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue


def known_tool_source(tool: str, roots: list[Path]) -> tuple[str, str, bool]:
    token = f"github.com/coreruleset/{tool}"
    build_markers = (f"go install {token}", f"git clone https://{token}", f"git clone https://{token}.git")
    source_url = ""
    known_ref = ""
    can_build = False
    for path, text in known_tool_source_texts(roots):
        token_present = token in text
        if token_present and not source_url:
            source_url = f"https://{token}"
        if any(marker in text for marker in build_markers):
            can_build = True
        if token_present and "ref=" in text and not known_ref:
            known_ref = "see " + str(path)
    return source_url, known_ref, can_build


def inventory_tool(
    dependency: str,
    env_var: str,
    default: str,
    env: dict[str, str],
    cache_root: Path,
    build_root: Path,
    native_root: Path,
    source_roots: list[Path],
) -> dict[str, Any]:
    configured = env.get(env_var, "")
    candidates = []
    if configured:
        candidates.append(configured)
    candidates.extend(
        [
            default,
            str(cache_root / f"bin/{dependency}"),
            str(cache_root / f"tools/{dependency}"),
            str(build_root / f"bin/{dependency}"),
            str(build_root / f"tools/{dependency}"),
            str(native_root / f"bin/{dependency}"),
        ]
    )
    searched = []
    resolved = ""
    for candidate in candidates:
        if not candidate or candidate in searched:
            continue
        searched.append(candidate)
        path = resolve_executable(candidate)
        if path and not resolved:
            resolved = path
    source_url, known_ref, can_build = known_tool_source(dependency, source_roots)
    status = "present" if resolved else "blocked"
    blocker = "" if resolved else f"missing_{dependency.replace('-', '_')}_source_ref"
    return {
        "dependency": dependency,
        "status": status,
        "path": resolved,
        "searched_paths": searched,
        "env_override": env_var,
        "known_source": source_url,
        "known_source_url": source_url,
        "known_ref": known_ref,
        "can_build_locally": can_build and bool(known_ref),
        "blocker_reason": blocker,
    }


def dependency_inventory_entry(
    name: str,
    env_var: str,
    path: Any,
    component: dict[str, Any],
    access: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "env_var": env_var,
        "path": path,
        "status": "present" if component.get("status") in READY_COMPONENT_STATUSES else "missing",
        "access": access,
    }


def dependency_inventory(
    apache_httpd: dict[str, Any],
    nginx: dict[str, Any],
    haproxy: dict[str, Any],
    go_ftw: dict[str, Any],
    albedo: dict[str, Any],
    expat: dict[str, Any],
    modsecurity: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        dependency_inventory_entry("go-ftw", "GO_FTW_BIN", go_ftw.get("path"), go_ftw, "read-only/executable"),
        dependency_inventory_entry("albedo", "ALBEDO_BIN", albedo.get("path"), albedo, "read-only/executable"),
        dependency_inventory_entry("expat", "EXPAT_PREFIX", expat.get("prefix"), expat, "local-prefix/read-only"),
        dependency_inventory_entry(
            "libmodsecurity",
            "MODSECURITY_LIB_DIR",
            modsecurity.get("lib_file"),
            modsecurity,
            "shared-local-prefix/read-only",
        ),
        dependency_inventory_entry(
            "apachectl",
            "APACHECTL_BIN",
            apache_httpd.get("apachectl_bin"),
            apache_httpd,
            "local-wrapper/read-only-executable",
        ),
        dependency_inventory_entry(
            "nginx",
            "MRTS_NATIVE_NGINX_BIN",
            nginx.get("nginx_bin"),
            nginx,
            LOCAL_BUILD_READ_ONLY_EXECUTABLE,
        ),
        dependency_inventory_entry(
            NGINX_MODULE_FILENAME,
            "MRTS_NATIVE_NGINX_MODULE_DIR",
            nginx.get("module_file"),
            nginx,
            "local-build/module-reference",
        ),
        dependency_inventory_entry(
            "haproxy",
            "HAPROXY_BIN",
            haproxy.get("haproxy_bin"),
            haproxy,
            LOCAL_BUILD_READ_ONLY_EXECUTABLE,
        ),
        dependency_inventory_entry(
            "haproxy-modsecurity-spoa",
            "SPOA_RUNTIME_BIN",
            haproxy.get("spoa_runtime_bin"),
            haproxy,
            LOCAL_BUILD_READ_ONLY_EXECUTABLE,
        ),
    ]


def runtime_build_cache_payload(modsecurity: dict[str, Any], connectors: list[dict[str, Any]]) -> dict[str, Any]:
    rebuilt = sum(1 for item in connectors if item.get("status") == "built")
    reused = sum(1 for item in connectors if item.get("status") == "reused")
    blocked = sum(1 for item in connectors if item.get("status") == "blocked")
    failed = sum(1 for item in connectors if item.get("status") == "failed")
    shared_id = modsecurity.get("build_id", "")
    mismatches = [
        item.get("connector", "")
        for item in connectors
        if item.get("status") in {"built", "reused", "present"}
        and item.get("modsecurity_build_id") != shared_id
    ]
    return {
        "generated_at": utc_now(),
        "shared_modsecurity_build": modsecurity,
        "connector_builds": connectors,
        "build_reuse_summary": {
            "rebuilt_count": rebuilt,
            "reused_count": reused,
            "blocked_count": blocked,
            "failed_count": failed,
            "saved_rebuilds_estimate": reused,
            "modsecurity_build_status": modsecurity.get("status", ""),
            "modsecurity_build_id_mismatches": mismatches,
            "status": "blocked" if mismatches else "ok",
            "blocker_reason": "modsecurity_build_id_mismatch" if mismatches else "",
        },
    }


def runtime_build_cache_markdown(payload: dict[str, Any]) -> str:
    modsecurity = payload.get("shared_modsecurity_build", {})
    summary = payload.get("build_reuse_summary", {})
    lines = [
        "# Runtime Build Cache",
        "",
        f"Generated at: `{payload.get('generated_at', '-')}`",
        "",
        "## Shared ModSecurity Build",
        f"- Status: `{modsecurity.get('status', '-')}`",
        f"- Blocker: `{modsecurity.get('blocker_reason') or '-'}`",
        f"- Source URL: `{modsecurity.get('source_url', '-')}`",
        f"- Source ref: `{modsecurity.get('source_ref', '-')}`",
        f"- Actual SHA: `{modsecurity.get('actual_sha', '-')}`",
        f"- Build ID: `{modsecurity.get('build_id', '-')}`",
        f"- Prefix: `{modsecurity.get('prefix', '-')}`",
        f"- Include dir: `{modsecurity.get('include_dir', '-')}`",
        f"- Lib dir: `{modsecurity.get('lib_dir', '-')}`",
        f"- libmodsecurity: `{modsecurity.get('lib_file', '-')}`",
        f"- pkg-config path: `{modsecurity.get('pkg_config_path', '-')}`",
        f"- Dependency hash: `{modsecurity.get('dependency_hash', '-')}`",
        f"- Submodules recursive: `{modsecurity.get('submodules_recursive', '-')}`",
        f"- Submodule status: `{modsecurity.get('submodule_status') or '-'}`",
        "",
        "## Connector Builds",
        "| Connector | Status | Connector build ID | ModSecurity build ID | Invalidation reason | Binary | Module | Config | Blocker |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for item in payload.get("connector_builds", []):
        outputs = item.get("output_paths", {})
        lines.append(
            "| {connector} | {status} | `{connector_id}` | `{modsec_id}` | {reason} | `{binary}` | `{module}` | `{config}` | {blocker} |".format(
                connector=item.get("connector", "-"),
                status=item.get("status", "-"),
                connector_id=item.get("connector_build_id", "-"),
                modsec_id=item.get("modsecurity_build_id", "-"),
                reason=item.get("invalidation_reason") or "-",
                binary=outputs.get("binary", "-"),
                module=outputs.get("module", "-"),
                config=outputs.get("config", "-"),
                blocker=item.get("blocker_reason") or "-",
            )
        )
    lines.extend(
        [
            "",
            "## Build Reuse Summary",
            f"- Rebuilt count: `{summary.get('rebuilt_count', '-')}`",
            f"- Reused count: `{summary.get('reused_count', '-')}`",
            f"- Blocked count: `{summary.get('blocked_count', '-')}`",
            f"- Saved rebuilds estimate: `{summary.get('saved_rebuilds_estimate', '-')}`",
            f"- Mismatch status: `{summary.get('status', '-')}`",
            f"- Mismatch blocker: `{summary.get('blocker_reason') or '-'}`",
        ]
    )
    return "\n".join(lines) + "\n"


def report_value(record: dict[str, Any], key: str, empty_as_fallback: bool = False) -> Any:
    value = record.get(key, REPORT_VALUE_FALLBACK)
    return value or REPORT_VALUE_FALLBACK if empty_as_fallback else value


def first_report_value(record: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = record.get(key)
        if value:
            return value
    return REPORT_VALUE_FALLBACK


def comma_separated_report_value(record: dict[str, Any], key: str) -> str:
    return ", ".join(record.get(key, [])) or REPORT_VALUE_FALLBACK


def markdown_record_lines(
    record: dict[str, Any],
    fields: tuple[tuple[str, str, bool], ...],
) -> list[str]:
    return [
        f"- {label}: `{report_value(record, key, empty_as_fallback)}`"
        for label, key, empty_as_fallback in fields
    ]


def markdown_section_lines(
    heading: str,
    record: dict[str, Any],
    fields: tuple[tuple[str, str, bool], ...],
) -> list[str]:
    return ["", heading, *markdown_record_lines(record, fields)]


def apache_markdown_lines(apache: dict[str, Any]) -> list[str]:
    lines = markdown_section_lines(
        "## Apache httpd",
        apache,
        (
            ("Status", "status", False),
            ("Blocker", "blocker_reason", True),
            (CONNECTOR_BUILD_ID_LABEL, "connector_build_id", True),
            (USES_MODSECURITY_BUILD_ID_LABEL, "modsecurity_build_id", True),
            ("Source", "source", False),
            ("Expected ref/version", "expected_ref", False),
            ("Cache path", "cache_path", False),
            ("Build path", "build_path", False),
            ("apachectl/APACHECTL_BIN", "apachectl_bin", False),
            ("Missing file", "missing_file", True),
            ("Build component", "build_component", True),
        ),
    )
    lines.append(
        f"- Env variable to set: `{first_report_value(apache, 'env_variable_can_set', 'env_override')}`"
    )
    lines.extend(
        markdown_record_lines(
            apache,
            (
                ("Expat source", "expat_source", True),
                ("Expat release tag", "expat_release_tag", True),
                ("CPPFLAGS", "cppflags", True),
                ("LDFLAGS", "ldflags", True),
                ("LIBS", "libs", True),
                ("PKG_CONFIG_PATH", "pkg_config_path", True),
                ("crypt.h status", "crypt_h_status", True),
                ("crypt.h path", "crypt_h_path", True),
                ("libcrypt status", "libcrypt_status", True),
            ),
        )
    )
    lines.append(f"- libcrypt paths: `{comma_separated_report_value(apache, 'libcrypt_paths')}`")
    lines.extend(markdown_record_lines(apache, (("crypt link mode", "crypt_link_mode", True),)))
    return lines


def nginx_markdown_lines(nginx: dict[str, Any]) -> list[str]:
    lines = markdown_section_lines(
        "## NGINX",
        nginx,
        (
            ("Status", "status", False),
            ("Blocker", "blocker_reason", True),
            (CONNECTOR_BUILD_ID_LABEL, "connector_build_id", True),
            (USES_MODSECURITY_BUILD_ID_LABEL, "modsecurity_build_id", True),
            ("Source", "source", False),
            ("Expected ref/version", "expected_ref", False),
            ("Cache path", "cache_path", False),
            ("Build path", "build_path", False),
            ("MRTS_NATIVE_NGINX_BIN", "nginx_bin", False),
            ("MRTS_NATIVE_NGINX_MODULE_DIR", "module_dir", False),
            ("Module file", "module_file", False),
            ("Missing file", "missing_file", True),
            ("Build component", "build_component", True),
        ),
    )
    lines.append(
        f"- Env variable to set: `{first_report_value(nginx, 'env_variable_can_set', 'env_override')}`"
    )
    return lines


def haproxy_markdown_lines(haproxy: dict[str, Any]) -> list[str]:
    return markdown_section_lines(
        "## HAProxy",
        haproxy,
        (
            ("Status", "status", False),
            ("Blocker", "blocker_reason", True),
            (CONNECTOR_BUILD_ID_LABEL, "connector_build_id", True),
            (USES_MODSECURITY_BUILD_ID_LABEL, "modsecurity_build_id", True),
            ("HAPROXY_BIN", "haproxy_bin", True),
            ("SPOA_RUNTIME_BIN", "spoa_runtime_bin", True),
            ("MODSECURITY_BINDING_DIR", "modsecurity_binding_dir", True),
        ),
    )


def expat_markdown_lines(expat: dict[str, Any]) -> list[str]:
    lines = markdown_section_lines(
        "## Expat",
        expat,
        (
            ("Status", "status", False),
            ("Blocker", "blocker_reason", True),
            ("Source", "source", False),
        ),
    )
    lines.append(f"- Release tag: `{first_report_value(expat, 'release_tag', 'expected_ref')}`")
    lines.extend(
        markdown_record_lines(
            expat,
            (
                ("Actual head", "actual_head", True),
                ("Prefix", "prefix", True),
                (EXPAT_HEADER_FILENAME, "expat_h", True),
                ("lib dir", "lib_dir", True),
                ("Recursive submodules", "recursive_submodule_status", True),
            ),
        )
    )
    return lines


def tool_markdown_row(item: dict[str, Any]) -> str:
    return "| {dep} | {status} | `{env}` | `{source}` | `{ref}` | `{head}` | `{binary}` | `{subs}` | {note} | {blocker} |".format(
        dep=item.get("dependency", REPORT_VALUE_FALLBACK),
        status=item.get("status", REPORT_VALUE_FALLBACK),
        env=item.get("env_override", REPORT_VALUE_FALLBACK),
        source=first_report_value(item, "known_source"),
        ref=first_report_value(item, "release_tag", "known_ref"),
        head=report_value(item, "actual_head", True),
        binary=first_report_value(item, "binary", "path"),
        subs=report_value(item, "recursive_submodule_status", True),
        note=report_value(item, "release_tag_deviation_note", True),
        blocker=report_value(item, "blocker_reason", True),
    )


def git_component_markdown_row(item: dict[str, Any]) -> str:
    return "| {name} | {status} | `{ref}` | `{head}` | {subs} | {fsck} | {blocker} |".format(
        name=item.get("name", REPORT_VALUE_FALLBACK),
        status=item.get("status", REPORT_VALUE_FALLBACK),
        ref=item.get("expected_ref", REPORT_VALUE_FALLBACK),
        head=item.get("actual_head", REPORT_VALUE_FALLBACK),
        subs=item.get("submodule_count", 0),
        fsck=item.get("git_fsck", REPORT_VALUE_FALLBACK),
        blocker=report_value(item, "blocker_reason", True),
    )


def archive_markdown_row(item: dict[str, Any]) -> str:
    return "| {name} | {status} | {checksum} | `{path}` | {blocker} |".format(
        name=item.get("name", REPORT_VALUE_FALLBACK),
        status=item.get("status", REPORT_VALUE_FALLBACK),
        checksum=item.get("checksum_status", REPORT_VALUE_FALLBACK),
        path=item.get("path", REPORT_VALUE_FALLBACK),
        blocker=report_value(item, "blocker_reason", True),
    )


def dependency_markdown_row(item: dict[str, Any]) -> str:
    return "| {name} | {status} | `{env}` | `{path}` | {access} |".format(
        name=item.get("name", REPORT_VALUE_FALLBACK),
        status=item.get("status", REPORT_VALUE_FALLBACK),
        env=item.get("env_var", REPORT_VALUE_FALLBACK),
        path=first_report_value(item, "path", "configured"),
        access=item.get("access", REPORT_VALUE_FALLBACK),
    )


def markdown_report(payload: dict[str, Any]) -> str:
    modsecurity = payload.get("modsecurity", {})
    lines = [
        "# Runtime Component Cache",
        "",
        f"Generated at: `{payload['generated_at']}`",
        f"Cache root: `{payload['cache_root']}`",
        f"Cache schema: `{payload.get('cache_schema_version', REPORT_VALUE_FALLBACK)}`",
        f"Cache manifest status: `{payload.get('status', REPORT_VALUE_FALLBACK)}`",
        "",
        "## Prepare Phases",
    ]
    lines.extend(f"- {phase}" for phase in payload.get("prepare_phases", []))
    lines.extend(
        markdown_section_lines(
            "## Shared ModSecurity",
            modsecurity,
            (
                ("Status", "status", False),
                ("Blocker", "blocker_reason", True),
                ("Source ref", "source_ref", True),
                ("Actual SHA", "actual_sha", True),
                ("Build ID", "build_id", True),
                ("Prefix", "prefix", True),
                ("Include dir", "include_dir", True),
                ("Lib dir", "lib_dir", True),
            ),
        )
    )
    lines.extend(apache_markdown_lines(payload.get("apache_httpd", {})))
    lines.extend(nginx_markdown_lines(payload.get("nginx", {})))
    lines.extend(haproxy_markdown_lines(payload.get("haproxy", {})))
    lines.extend(expat_markdown_lines(payload.get("expat", {})))
    lines.extend(
        [
            "",
            "## go-ftw / albedo",
            "| Dependency | Status | Env override | Source | Release tag | Head | Binary | Submodules | Release note | Blocker |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]
    )
    lines.extend(tool_markdown_row(item) for item in (payload.get("go_ftw", {}), payload.get("albedo", {})))
    lines.extend(
        [
            "",
            "## Git Components",
            "| Name | Status | Ref | Head | Submodules | fsck | Blocker |",
            "|---|---|---|---|---:|---|---|",
        ]
    )
    lines.extend(git_component_markdown_row(item) for item in payload["git_components"])
    lines.extend(["", "## Archives", "| Name | Status | Checksum | Path | Blocker |", "|---|---|---|---|---|"])
    lines.extend(archive_markdown_row(item) for item in payload["archives"])
    lines.extend(["", "## Local Dependencies", "| Name | Status | Env | Path | Access |", "|---|---|---|---|---|"])
    lines.extend(dependency_markdown_row(item) for item in payload["dependencies"])
    lines.extend(
        [
            "",
            "## Guardrails",
            "- System paths are not used for runtime component writes.",
            "- Runtime writes are constrained to cache/build/runtime roots.",
            "- Native Apache and NGINX use local prepared components when env overrides are absent.",
            "- go-ftw and albedo use release-tag resolution; Expat always uses its configured immutable commit.",
            "- `RUNTIME_COMPONENT_STRICT_VERIFY=1` requires a fresh-clone or prior-cache full git fsck PASS; Expat requires an immutable commit pin in every mode.",
        ]
    )
    return "\n".join(lines) + "\n"


def runtime_component_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector-root", required=True)
    parser.add_argument("--framework-root", required=True)
    parser.add_argument("--cache-root", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument(
        "--runtime-env-snapshot",
        default=os.environ.get("RUNTIME_COMPONENT_ENV_SNAPSHOT", ""),
        help=(
            "Invocation-local runtime environment export file.  When omitted, "
            "a unique file is allocated below --output-root."
        ),
    )
    parser.add_argument(
        "--runtime-env-snapshot-contract",
        choices=(GENERIC_RUNTIME_ENV_SNAPSHOT_CONTRACT, PROTECTED_NGINX_BROKER_SNAPSHOT_CONTRACT),
        default=os.environ.get(
            "RUNTIME_COMPONENT_SNAPSHOT_CONTRACT",
            GENERIC_RUNTIME_ENV_SNAPSHOT_CONTRACT,
        ),
        help="Select the generic compatibility snapshot or the fixed protected NGINX broker tuple.",
    )
    parser.add_argument("--build-root", default=None)
    parser.add_argument("--native-root", default=None)
    parser.add_argument(
        "--target-connector",
        choices=RUNTIME_COMPONENT_TARGETS,
        default=os.environ.get("RUNTIME_COMPONENT_TARGET", "all"),
        help="Prepare shared dependencies, one native connector, or all native connectors.",
    )
    return parser


def parse_runtime_component_args() -> argparse.Namespace:
    return runtime_component_argument_parser().parse_args()


def required_runtime_component_sources(
    env: dict[str, str], target_connector: str
) -> dict[str, Any]:
    target_connector = require_runtime_component_target(target_connector)
    validate_https_url_config(env, target_connector)
    # Validate the guarded Framework tuple before any managed cache root,
    # archive path, extraction, or download is reached.
    values = {"apr_util_provenance": require_apr_util_pinned_provenance(env)}
    values.update({
        "expat_source_url": require_env_value(env, "EXPAT_SOURCE_URL"),
        "expat_git_ref": require_full_immutable_git_commit(
            require_env_value(env, "EXPAT_GIT_REF"), "EXPAT_GIT_REF"
        ),
    })
    if target_connector == "all":
        # These optional tools are prepared only by the aggregate target; a
        # connector-scoped run must not be blocked by their unrelated source
        # configuration.
        values.update({
            "go_ftw_source_url": require_env_value(env, "GO_FTW_SOURCE_URL"),
            "go_ftw_expected_latest": require_env_value(env, "GO_FTW_PROMPT_EXPECTED_LATEST"),
            "albedo_source_url": require_env_value(env, "ALBEDO_SOURCE_URL"),
            "albedo_expected_latest": require_env_value(env, "ALBEDO_PROMPT_EXPECTED_LATEST"),
        })
    # NGINX no longer has a mutable fallback. Validate its complete reviewed
    # release tuple before the managed cache root is initialized, but only
    # when this invocation can prepare NGINX.
    if target_connector in NGINX_RUNTIME_COMPONENT_TARGETS:
        values["nginx_pinned_provenance"] = nginx_pinned_provenance(env)
        values["nginx_require_pinned_provenance"] = nginx_pinned_provenance_required(env)
        nginx_protocol_build_inputs(env)
    return values


def ensure_runtime_component_roots(
    cache_root: Path,
    connector_root: Path,
    framework_root: Path,
    build_root: Path,
    native_root: Path,
) -> Path | None:
    try:
        managed_cache_root = ensure_managed_cache_root(
            cache_root,
            protected_paths=(connector_root, framework_root),
        )
    except RuntimeError as exc:
        print(f"prepare-runtime-components: BLOCKED cache: {exc}")
        return None
    for label, path in (("BUILD_ROOT", build_root), ("MRTS_NATIVE_ROOT", native_root)):
        if is_system_path(path):
            print(f"prepare-runtime-components: BLOCKED {label}: system_path_write_forbidden path={path}")
            return None
    build_root.mkdir(parents=True, exist_ok=True)
    native_root.mkdir(parents=True, exist_ok=True)
    return managed_cache_root


def runtime_component_context(args: argparse.Namespace) -> tuple[dict[str, Any] | None, int]:
    global PATH_POLICY_ENV

    initial_env = dict(os.environ)
    connector_root = Path(args.connector_root).resolve()
    framework_root = Path(args.framework_root).resolve()
    env, common_status = load_framework_environment(connector_root, framework_root, initial_env)
    if common_status != "loaded":
        print(f"prepare-runtime-components: BLOCKED: framework common.sh could not be loaded ({common_status})")
        return None, 77
    cache_root = Path(args.cache_root).resolve()
    output_root = Path(args.output_root).resolve()
    requested_runtime_env_snapshot: Path | None = None
    if args.runtime_env_snapshot:
        try:
            requested_runtime_env_snapshot = snapshot_path_within_output_root(
                Path(args.runtime_env_snapshot), output_root
            )
        except RuntimeError as exc:
            print(f"prepare-runtime-components: BLOCKED runtime env snapshot: {exc}")
            return None, 77
    build_root = Path(args.build_root or env.get("BUILD_ROOT", str(default_state_home() / "ModSecurity-conector-build"))).resolve()
    native_root = Path(args.native_root or env.get("MRTS_NATIVE_ROOT", str(build_root / "mrts-native"))).resolve()
    env.update(
        {
            "REPO_ROOT": str(connector_root),
            "CONNECTOR_ROOT": str(connector_root),
            "FRAMEWORK_ROOT": str(framework_root),
            "CONNECTOR_COMPONENT_CACHE": str(cache_root),
            "BUILD_ROOT": str(build_root),
            "MRTS_NATIVE_ROOT": str(native_root),
        }
    )
    PATH_POLICY_ENV = dict(env)
    strict = env.get("RUNTIME_COMPONENT_STRICT_VERIFY") == "1"
    try:
        sources = required_runtime_component_sources(env, args.target_connector)
    except RuntimeError as exc:
        print(f"prepare-runtime-components: BLOCKED: {exc}")
        return None, 77
    cache_root = ensure_runtime_component_roots(
        cache_root,
        connector_root,
        framework_root,
        build_root,
        native_root,
    )
    if cache_root is None:
        return None, 77
    return {
        "env": env,
        "connector_root": connector_root,
        "framework_root": framework_root,
        "cache_root": cache_root,
        "output_root": output_root,
        "build_root": build_root,
        "native_root": native_root,
        "report_dir": output_root / GENERATED_ROOT,
        "requested_runtime_env_snapshot": requested_runtime_env_snapshot,
        "runtime_env_snapshot_contract": args.runtime_env_snapshot_contract,
        "strict": strict,
        "target_connector": args.target_connector,
        **sources,
    }, 0


def runtime_component_cache_paths(cache_root: Path) -> dict[str, Path]:
    sources_root = cache_root / "sources"
    return {
        "sources_root": sources_root,
        "archives_root": cache_root / "archives",
        "git_root": cache_root / "git",
        "modsec_path": sources_root / "ModSecurity_V3",
        "crs_path": sources_root / "coreruleset",
        "haproxy_source_root": sources_root / "haproxy",
    }


def previous_git_components(cache_root: Path) -> dict[str, dict[str, Any]]:
    previous_manifest = read_json(cache_root / CACHE_MANIFEST_FILENAME)
    return {
        str(item.get("name")): item
        for item in previous_manifest.get("git_components", [])
        if isinstance(item, dict) and item.get("name")
    }


def optional_external_connector_sources(
    env: dict[str, str],
    sources_root: Path,
    previous_git: dict[str, dict[str, Any]],
    strict: bool,
    cache_root: Path,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for name, url_key, ref_key in (
        ("modsecurity-apache", "MODSECURITY_APACHE_GIT_URL", "MODSECURITY_APACHE_GIT_REF"),
        ("modsecurity-nginx", "MODSECURITY_NGINX_GIT_URL", "MODSECURITY_NGINX_GIT_REF"),
    ):
        url = env.get(url_key, "")
        ref = env.get(ref_key, "")
        if not url or not ref:
            records.append(
                {
                    "name": name,
                    "url": url,
                    "expected_ref": ref,
                    "path": str(sources_root / name),
                    "status": "blocked",
                    "blocker_reason": "missing_url_or_ref",
                }
            )
            continue
        records.append(
            prepare_git_component(
                name,
                url,
                ref,
                sources_root / name,
                previous_git,
                strict,
                cache_root=cache_root,
            )
        )
    return records


def prepare_runtime_git_components(
    context: dict[str, Any],
    paths: dict[str, Path],
) -> list[dict[str, Any]]:
    env = context["env"]
    cache_root = context["cache_root"]
    previous_git = previous_git_components(cache_root)
    components = [
        prepare_framework_approved_modsecurity_v3_source(
            env,
            context["framework_root"],
            paths["modsec_path"],
            cache_root=cache_root,
        ),
        prepare_expat_git_component(
            env.get("EXPAT_GIT_URL") or context["expat_source_url"],
            context["expat_git_ref"],
            paths["git_root"] / "libexpat",
            previous_git,
            context["strict"],
            cache_root=cache_root,
        ),
    ]
    if context["target_connector"] == "all":
        components.extend(
            [
                prepare_git_component(
                    "coreruleset",
                    env.get("CRS_REPO_URL", ""),
                    env.get("CRS_GIT_REF", ""),
                    paths["crs_path"],
                    previous_git,
                    context["strict"],
                    cache_root=cache_root,
                ),
                prepare_release_git_component(
                    "go-ftw",
                    context["go_ftw_source_url"],
                    context["go_ftw_expected_latest"],
                    paths["git_root"] / "go-ftw",
                    previous_git,
                    context["strict"],
                    optional=True,
                    cache_root=cache_root,
                ),
                prepare_release_git_component(
                    "albedo",
                    context["albedo_source_url"],
                    context["albedo_expected_latest"],
                    paths["git_root"] / "albedo",
                    previous_git,
                    context["strict"],
                    optional=True,
                    cache_root=cache_root,
                ),
            ]
        )
    if env.get("ALLOW_EXTERNAL_CONNECTOR_REPOS") == "1":
        components.extend(
            optional_external_connector_sources(
                env,
                paths["sources_root"],
                previous_git,
                context["strict"],
                cache_root,
            )
        )
    return components


def apache_archive_records(env: dict[str, str], archives_root: Path, cache_root: Path) -> list[dict[str, Any]]:
    apache_root = archives_root / "apache"
    apr_util_identity = apr_util_archive_cache_identity(env)
    return [
        prepare_archive(
            "httpd", env.get("HTTPD_SOURCE_URL", ""), env.get("HTTPD_SHA256", ""),
            env.get("HTTPD_SHA256_URL", ""), apache_root, cache_root,
            required_literal_sha256=True,
            verify_digest_before_archive_list=True,
            allow_httpd_source_recovery=True,
        ),
        prepare_archive("apr", env.get("APR_SOURCE_URL", ""), env.get("APR_SHA256", ""), env.get("APR_SHA256_URL", ""), apache_root, cache_root),
        prepare_archive(
            "apr-util",
            env.get("APR_UTIL_SOURCE_URL", ""),
            env.get("APR_UTIL_SHA256", ""),
            env.get("APR_UTIL_SHA256_URL", ""),
            apache_root,
            cache_root,
            required_literal_sha256=True,
            cache_identity=apr_util_identity,
            verify_digest_before_archive_list=True,
        ),
        prepare_archive(
            "pcre2",
            env.get("PCRE2_SOURCE_URL", ""),
            env.get("PCRE2_SHA256", ""),
            env.get("PCRE2_SHA256_URL", ""),
            apache_root,
            cache_root,
            required_literal_sha256=True,
        ),
    ]


def nginx_archive_records(env: dict[str, str], archives_root: Path, cache_root: Path) -> list[dict[str, Any]]:
    try:
        # Validate the entire immutable tuple before touching the cache root,
        # a network client, an archive, or a release-lookup cache path.
        provenance = nginx_pinned_provenance(env)
        cache_identity = nginx_pinned_archive_cache_identity(provenance)
        nginx_root = archives_root / "nginx"
        nginx_record = prepare_archive(
            "nginx",
            provenance["release_asset_url"],
            provenance["sha256"],
            "",
            nginx_root,
            cache_root,
            required_literal_sha256=True,
            cache_identity=cache_identity,
            verify_digest_before_archive_list=True,
        )
        nginx_record.update(nginx_archive_provenance_fields(provenance))
        verified_archive_sha256 = str(nginx_record.get("sha256", ""))
        archive_digest_verified = (
            nginx_record.get("status") == "present"
            and nginx_record.get("checksum_status") == "PASS"
            and verified_archive_sha256 == provenance["sha256"]
        )
        nginx_record.update(
            verified_archive_sha256=verified_archive_sha256 if archive_digest_verified else "",
            archive_digest_verified=archive_digest_verified,
            source_readback={
                "release_asset_url": provenance["release_asset_url"],
                "archive_path": str(nginx_record.get("path", "")),
                "expected_sha256": provenance["sha256"],
                "verified_archive_sha256": verified_archive_sha256,
            },
            cache_identity=cache_identity,
            cache_key=cache_identity["cache_key"],
        )
        records = [nginx_record]
        nginx_protocol = nginx_protocol_build_inputs(env)
        if nginx_protocol["quic_enabled"]:
            records.append(
                prepare_archive(
                    "nginx-quic-tls",
                    str(nginx_protocol["tls_source_url"]),
                    str(nginx_protocol["tls_source_sha256"]),
                    "",
                    nginx_root,
                    cache_root,
                )
            )
        return records
    except Exception as exc:
        return [
            {
                "name": "nginx",
                "status": "blocked",
                "blocker_reason": str(exc),
                "checksum_status": "unknown",
                "pinned_provenance": True,
                "provenance_validation": "failed",
                "archive_digest_verified": False,
            }
        ]


def prepare_runtime_archives(context: dict[str, Any], paths: dict[str, Path]) -> list[dict[str, Any]]:
    env = context["env"]
    cache_root = context["cache_root"]
    target_connector = context["target_connector"]
    archives: list[dict[str, Any]] = []
    if target_connector in {"all", "apache"}:
        archives.extend(apache_archive_records(env, paths["archives_root"], cache_root))
    if target_connector in {"all", "haproxy"}:
        archives.append(
            prepare_archive(
                "haproxy",
                env.get("HAPROXY_SOURCE_URL", ""),
                env.get("HAPROXY_SHA256", ""),
                env.get("HAPROXY_SHA256_URL", ""),
                paths["archives_root"] / "haproxy",
                cache_root,
            )
        )
    if target_connector in NGINX_RUNTIME_COMPONENT_TARGETS:
        archives.extend(nginx_archive_records(env, paths["archives_root"], cache_root))
    return archives


def git_components_by_name(git_components: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("name")): item
        for item in git_components
        if isinstance(item, dict) and item.get("name")
    }


def not_selected_connector(name: str, modsecurity: dict[str, Any]) -> dict[str, Any]:
    return {
        "connector": name,
        "name": name,
        "status": "not_selected",
        "blocker_reason": "",
        "modsecurity_build_id": modsecurity.get("build_id", ""),
    }


def prepare_native_component_records(
    context: dict[str, Any],
    paths: dict[str, Path],
    git_components: list[dict[str, Any]],
    archives: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    env = context["env"]
    cache_root = context["cache_root"]
    build_root = context["build_root"]
    connector_root = context["connector_root"]
    framework_root = context["framework_root"]
    target_connector = context["target_connector"]
    git_by_name = git_components_by_name(git_components)
    expat = prepare_expat(env, cache_root, build_root, git_by_name.get("expat", {}))
    modsecurity = prepare_shared_modsecurity(
        env,
        cache_root,
        build_root,
        git_by_name.get("modsecurity-v3", {}),
        expat,
        connector_root=connector_root,
        framework_root=framework_root,
    )
    connector_plans = {
        name: connector_plan(connector_root, framework_root, cache_root, env, name, modsecurity, expat, archives)
        for name in ("apache", "haproxy")
    }
    nginx_plan: dict[str, Any] = {}
    if target_connector in NGINX_RUNTIME_COMPONENT_TARGETS:
        nginx_plan = connector_plan(
            connector_root,
            framework_root,
            cache_root,
            env,
            "nginx",
            modsecurity,
            expat,
            archives,
        )
    apache_httpd = not_selected_connector("apache", modsecurity)
    nginx = not_selected_connector("nginx", modsecurity)
    haproxy = not_selected_connector("haproxy", modsecurity)
    if target_connector in {"all", "apache"}:
        apache_httpd = prepare_apache_httpd(
            env,
            connector_root,
            framework_root,
            cache_root,
            build_root,
            paths["sources_root"],
            paths["archives_root"],
            expat,
            modsecurity,
            connector_plans["apache"],
        )
    if target_connector in {"all", "nginx"}:
        nginx = prepare_nginx_runtime(
            env,
            connector_root,
            framework_root,
            cache_root,
            build_root,
            paths["sources_root"],
            paths["archives_root"],
            modsecurity,
            nginx_plan,
        )
    if target_connector in {"all", "haproxy"}:
        haproxy = prepare_haproxy_runtime(
            env,
            connector_root,
            framework_root,
            cache_root,
            build_root,
            paths["sources_root"],
            paths["archives_root"],
            modsecurity,
            connector_plans["haproxy"],
        )
    if target_connector == "all":
        go_ftw = prepare_go_tool("go-ftw", "GO_FTW_BIN", cache_root, build_root, git_by_name.get("go-ftw", {}), optional=True)
        albedo = prepare_go_tool("albedo", "ALBEDO_BIN", cache_root, build_root, git_by_name.get("albedo", {}), optional=True)
    else:
        go_ftw = {"dependency": "go-ftw", "name": "go-ftw", "status": "not_selected", "blocker_reason": ""}
        albedo = {"dependency": "albedo", "name": "albedo", "status": "not_selected", "blocker_reason": ""}
    return {
        "expat": expat,
        "modsecurity": modsecurity,
        "apache_httpd": apache_httpd,
        "nginx": nginx,
        "nginx_plan": nginx_plan,
        "haproxy": haproxy,
        "go_ftw": go_ftw,
        "albedo": albedo,
    }


def add_modsecurity_runtime_environment(runtime_env: dict[str, str], modsecurity: dict[str, Any]) -> None:
    if modsecurity.get("status") not in READY_COMPONENT_STATUSES:
        return
    runtime_env.update(
        {
            "MODSECURITY_SOURCE_URL": str(modsecurity.get("source_url", "")),
            "MODSECURITY_SOURCE_REF": str(modsecurity.get("source_ref", "")),
            "MODSECURITY_SOURCE_SHA": str(modsecurity.get("actual_sha", "")),
            "MODSECURITY_BUILD_FLAGS": str(modsecurity.get("build_flags", "")),
            "MODSECURITY_DEPENDENCY_HASH": str(modsecurity.get("dependency_hash", "")),
            "MODSECURITY_BUILD_ID": str(modsecurity.get("build_id", "")),
            "MODSECURITY_PREFIX": str(modsecurity.get("prefix", "")),
            "MODSECURITY_SHARED_PREFIX": str(modsecurity.get("prefix", "")),
            "MODSECURITY_INCLUDE_DIR": str(modsecurity.get("include_dir", "")),
            "MODSECURITY_LIB_DIR": str(modsecurity.get("lib_dir", "")),
            "MODSECURITY_PKG_CONFIG_PATH": str(modsecurity.get("pkg_config_path", "")),
        }
    )


def add_expat_runtime_environment(
    runtime_env: dict[str, str],
    expat: dict[str, Any],
    env: dict[str, str],
) -> None:
    if expat.get("status") not in {"present", "built"}:
        return
    runtime_env.update(
        {
            "EXPAT_PREFIX": str(expat.get("prefix", "")),
            "CPPFLAGS": " ".join(part for part in (f"-I{Path(str(expat.get('prefix'))) / 'include'}", env.get("CPPFLAGS", "")) if part).strip(),
            "LDFLAGS": " ".join(part for part in (f"-L{expat.get('lib_dir')}", env.get("LDFLAGS", "")) if part).strip(),
            "LIBS": " ".join(part for part in (env.get("LIBS", ""), resolve_crypt_link_arg(env)) if part).strip(),
            "PKG_CONFIG_PATH": f"{expat.get('prefix')}/lib/pkgconfig{os.pathsep}{env.get('PKG_CONFIG_PATH', '')}".rstrip(os.pathsep),
            "LD_LIBRARY_PATH": f"{expat.get('lib_dir')}{os.pathsep}{env.get('LD_LIBRARY_PATH', '')}".rstrip(os.pathsep),
        }
    )


def add_apache_runtime_environment(
    runtime_env: dict[str, str],
    apache_httpd: dict[str, Any],
    cache_root: Path,
) -> None:
    if apache_httpd.get("status") not in READY_COMPONENT_STATUSES:
        return
    runtime_env.update(
        {
            "APACHECTL_BIN": str(apache_httpd.get("apachectl_bin", "")),
            "APACHE_BUILD_ROOT": str(apache_httpd.get("build_path", "")),
            "APACHE_BUILD_OWNER_ROOT": str(cache_root / "builds" / "connectors"),
            "APACHE_HTTPD": str(apache_httpd.get("httpd_bin", "")),
            "APXS": str(apache_httpd.get("apxs_bin", "")),
            "APXS_BIN": str(apache_httpd.get("apxs_bin", "")),
            "HTTPD_PREFIX": str(apache_httpd.get("httpd_prefix", "")),
            "PCRE2_PREFIX": str(apache_httpd.get("pcre2_prefix", "")),
            "APACHE_MODULE": str(apache_httpd.get("module_file", "")),
            "APACHE_MRTS_MODULE": str(apache_httpd.get("module_file", "")),
            "APACHE_MRTS_MODSECURITY_LIB_DIR": str(apache_httpd.get("modsecurity_lib_dir", "")),
            "APACHE_CONNECTOR_BUILD_ID": str(apache_httpd.get("connector_build_id", "")),
        }
    )


def add_haproxy_runtime_environment(runtime_env: dict[str, str], haproxy: dict[str, Any]) -> None:
    if haproxy.get("status") not in READY_COMPONENT_STATUSES:
        return
    runtime_env.update(
        {
            "HAPROXY_BIN": str(haproxy.get("haproxy_bin", "")),
            "HAPROXY_RUNTIME_BUILD_DIR": str(haproxy.get("haproxy_runtime_build_dir", "")),
            "HAPROXY_RUNTIME_DIR": str(haproxy.get("haproxy_runtime_dir", "")),
            "SPOA_RUNTIME_BIN": str(haproxy.get("spoa_runtime_bin", "")),
            "MODSECURITY_BINDING_DIR": str(haproxy.get("modsecurity_binding_dir", "")),
            "HAPROXY_CONNECTOR_BUILD_ID": str(haproxy.get("connector_build_id", "")),
        }
    )


def runtime_component_environment(
    context: dict[str, Any],
    paths: dict[str, Path],
    components: dict[str, dict[str, Any]],
) -> dict[str, str]:
    env = context["env"]
    cache_root = context["cache_root"]
    runtime_env = {
        "CONNECTOR_COMPONENT_CACHE": str(cache_root),
        "SOURCE_ROOT": str(paths["sources_root"]),
        "MODSECURITY_SOURCE_DIR": str(paths["modsec_path"]),
        "MODSECURITY_V3_SOURCE_DIR": str(paths["modsec_path"]),
        "MODSECURITY_V3_ROOT": str(paths["modsec_path"]),
        "CRS_SOURCE_DIR": str(paths["crs_path"]),
        "APACHE_DOWNLOAD_DIR": str(paths["archives_root"] / "apache"),
        "NGINX_DOWNLOAD_DIR": str(paths["archives_root"] / "nginx"),
        "HAPROXY_SOURCE_ROOT": str(paths["haproxy_source_root"]),
        "HAPROXY_DOWNLOAD_DIR": str(paths["archives_root"] / "haproxy"),
        "HAPROXY_SOURCE_DIR": str(
            paths["haproxy_source_root"] / f"haproxy-{env.get('HAPROXY_VERSION', DEFAULT_HAPROXY_VERSION)}"
        ),
    }
    add_modsecurity_runtime_environment(runtime_env, components["modsecurity"])
    add_expat_runtime_environment(runtime_env, components["expat"], env)
    add_apache_runtime_environment(runtime_env, components["apache_httpd"], cache_root)
    runtime_env.update(nginx_runtime_environment(context["connector_root"], cache_root, components["nginx"]))
    add_haproxy_runtime_environment(runtime_env, components["haproxy"])
    runtime_env["RUNTIME_BUILD_CACHE_MANIFEST"] = str(
        report_path_from_root(context["report_dir"], "runtime_build_cache", "json")
    )
    if components["go_ftw"].get("path"):
        runtime_env["GO_FTW_BIN"] = str(components["go_ftw"]["path"])
    if components["albedo"].get("path"):
        runtime_env["ALBEDO_BIN"] = str(components["albedo"]["path"])
    return runtime_env


def write_runtime_environment_exports(context: dict[str, Any], runtime_env: dict[str, str]) -> Path:
    cache_root = context["cache_root"]
    output_root = context["output_root"]
    # Keep the shared cache file as a backwards-compatible report input while
    # each invocation uses its own output-root-contained snapshot.
    atomic_write_text(cache_root / "runtime-env.sh", runtime_env_shell_text(runtime_env))
    requested_snapshot = context["requested_runtime_env_snapshot"]
    snapshot_reserved_here = requested_snapshot is None
    runtime_env_snapshot = requested_snapshot or allocate_runtime_env_snapshot(output_root)
    try:
        if context["runtime_env_snapshot_contract"] == PROTECTED_NGINX_BROKER_SNAPSHOT_CONTRACT:
            protected_env, _ = protected_nginx_broker_runtime_environment(context, context["components"])
            destination = snapshot_path_within_output_root(runtime_env_snapshot, output_root)
            atomic_write_text(destination, runtime_env_shell_text(protected_env))
            return destination
        return write_runtime_env_snapshot(
            runtime_env,
            snapshot_path=runtime_env_snapshot,
            output_root=output_root,
            target_connector=context["target_connector"],
            cache_root=cache_root,
        )
    except Exception:
        if snapshot_reserved_here:
            try:
                runtime_env_snapshot.unlink()
            except FileNotFoundError:
                pass
        raise


def runtime_component_cache_manifest_status(records: list[dict[str, Any]]) -> str:
    return (
        CACHE_MANIFEST_STATUS_COMPLETE
        if all(item.get("status") not in {"unknown", "blocked", "corrupt", "failed"} for item in records)
        else "incomplete"
    )


def runtime_component_payload(
    context: dict[str, Any],
    components: dict[str, dict[str, Any]],
    git_components: list[dict[str, Any]],
    archives: list[dict[str, Any]],
    prepare_phases: list[str],
    runtime_env: dict[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    apache_httpd = components["apache_httpd"]
    nginx = components["nginx"]
    haproxy = components["haproxy"]
    modsecurity = components["modsecurity"]
    go_ftw = components["go_ftw"]
    albedo = components["albedo"]
    expat = components["expat"]
    connector_builds = [apache_httpd, nginx, haproxy]
    build_cache = runtime_build_cache_payload(modsecurity, connector_builds)
    cache_records = [*git_components, *archives, modsecurity, apache_httpd, nginx, haproxy, go_ftw, albedo, expat]
    payload = {
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "status": runtime_component_cache_manifest_status(cache_records),
        "generated_at": utc_now(),
        "cache_root": str(context["cache_root"]),
        "connector_root": str(context["connector_root"]),
        "framework_root": str(context["framework_root"]),
        "build_root": str(context["build_root"]),
        "native_root": str(context["native_root"]),
        "strict_verify": context["strict"],
        "target_connector": context["target_connector"],
        "prepare_phases": prepare_phases,
        "framework_runtime_config": {key: context["env"].get(key, "") for key in COMMON_SH_CONFIG_VARS},
        "runtime_env": runtime_env,
        "git_components": git_components,
        "archives": archives,
        "modsecurity": modsecurity,
        "apache_httpd": apache_httpd,
        "nginx": nginx,
        "haproxy": haproxy,
        "go_ftw": go_ftw,
        "albedo": albedo,
        "expat": expat,
        "runtime_build_cache": build_cache,
        "dependencies": dependency_inventory(apache_httpd, nginx, haproxy, go_ftw, albedo, expat, modsecurity),
        "guardrails": {
            "system_paths_read_only": True,
            "no_new_external_sources": True,
            "fsck_cache_enabled": True,
            "native_system_apachectl_dependency": False,
            "native_system_nginx_dependency": False,
        },
    }
    return payload, build_cache


def configured_component_file_approvals(configured: dict[str, Any]) -> list[str]:
    """Approve explicit invocation leaves, never paths selected by a manifest."""
    overrides = [configured.get(key) for key in (
        "APACHE_HTTPD", "APACHE", "APXS", "APXS_BIN", "APACHE_MODULE",
        "NGINX_BINARY", "NGINX_MODULE", "MRTS_NATIVE_NGINX_BIN",
        "MRTS_NATIVE_NGINX_MODULE_FILE", "HAPROXY_BIN", "HAPROXY_SPOA_BIN",
        "MODSECURITY_LIB_FILE", "GO_FTW_BIN", "ALBEDO_BIN",
    )]
    for key, leaf in (
        ("MRTS_NATIVE_NGINX_MODULE_DIR", NGINX_MODULE_FILENAME),
        ("MODSECURITY_LIB_DIR", MODSECURITY_LIBRARY_FILENAME),
        ("APACHE_MRTS_MODSECURITY_LIB_DIR", MODSECURITY_LIBRARY_FILENAME),
        ("NGINX_MRTS_MODSECURITY_LIB_DIR", MODSECURITY_LIBRARY_FILENAME),
    ):
        if configured.get(key):
            overrides.append(str(Path(configured[key]) / leaf))
    approved = set()
    for value in overrides:
        if not value:
            continue
        try:
            candidate = Path(value).resolve(strict=True)
        except OSError:
            continue
        if candidate.is_file():
            approved.add(str(candidate))
    return sorted(approved)


def write_runtime_component_reports(
    context: dict[str, Any],
    payload: dict[str, Any],
    build_cache: dict[str, Any],
    git_components: list[dict[str, Any]],
) -> Path:
    cache_root = context["cache_root"]
    connector_root = context["connector_root"]
    framework_root = context["framework_root"]
    report_dir = context["report_dir"]
    write_json(cache_root / CACHE_MANIFEST_FILENAME, payload)
    write_json(cache_root / "git-components.json", {"generated_at": payload["generated_at"], "components": git_components})
    write_json(cache_root / "runtime-build-cache.json", build_cache)
    component_metadata = build_metadata(
        generated_by="ci/provisioning/components/prepare-runtime-components.py",
        make_target="prepare-runtime-components",
        connector_root=connector_root,
        framework_root=framework_root,
        inputs=[cache_root / CACHE_MANIFEST_FILENAME],
        generated_at=payload["generated_at"],
        report_key="runtime_component_cache",
    )
    build_metadata_payload = build_metadata(
        generated_by="ci/provisioning/components/prepare-runtime-components.py",
        make_target="prepare-runtime-components",
        connector_root=connector_root,
        framework_root=framework_root,
        inputs=[cache_root / "runtime-build-cache.json"],
        generated_at=str(build_cache.get("generated_at") or payload["generated_at"]),
        report_key="runtime_build_cache",
    )
    component_json = report_path_from_root(report_dir, "runtime_component_cache", "json")
    component_md = report_path_from_root(report_dir, "runtime_component_cache", "md")
    build_json = report_path_from_root(report_dir, "runtime_build_cache", "json")
    build_md = report_path_from_root(report_dir, "runtime_build_cache", "md")
    component_json.parent.mkdir(parents=True, exist_ok=True)
    write_json(component_json, json.loads(generated_json_text(payload, component_metadata)))
    write_json(build_json, json.loads(generated_json_text(build_cache, build_metadata_payload)))
    component_md.write_text(generated_markdown_text(markdown_report(payload), component_metadata), encoding="utf-8")
    build_md.write_text(generated_markdown_text(runtime_build_cache_markdown(build_cache), build_metadata_payload), encoding="utf-8")
    postprocess = framework_source_path("ci/evidence/reports/update-runtime-reports.py", root=connector_root)
    if postprocess.is_file():
        command = [sys.executable, "-P", str(postprocess), "--connector-root", str(connector_root),
                   "--output-root", str(context["output_root"]), "--cache-root", str(cache_root)]
        if context.get("build_root"):
            command.extend(("--build-root", str(context["build_root"])))
        # Approvals come only from invocation configuration, never the manifest.
        for candidate in configured_component_file_approvals(context.get("env", {})):
            command.extend(("--approved-component-file", candidate))
        run(command)
    return component_md


def blocked_input_records(
    git_components: list[dict[str, Any]],
    archives: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    non_nginx = [
        item
        for item in git_components + archives
        if item.get("status") in {"blocked", "corrupt"}
        and item.get("name") not in {"nginx", "nginx-quic-tls"}
    ]
    nginx = [
        item
        for item in archives
        if item.get("name") in {"nginx", "nginx-quic-tls"}
        and item.get("status") in {"blocked", "corrupt"}
    ]
    return non_nginx, nginx


def selected_native_component_records(
    target_connector: str,
    components: dict[str, dict[str, Any]],
) -> tuple[tuple[str, dict[str, Any]], ...]:
    native_components = (
        ("apache_httpd", components["apache_httpd"]),
        ("nginx", components["nginx"]),
        ("haproxy", components["haproxy"]),
    )
    if target_connector == "all":
        return native_components
    return tuple(item for item in native_components if item[1].get("connector") == target_connector)


def runtime_component_blockers(
    context: dict[str, Any],
    components: dict[str, dict[str, Any]],
    git_components: list[dict[str, Any]],
    archives: list[dict[str, Any]],
    build_cache: dict[str, Any],
) -> list[dict[str, Any]]:
    blocked, nginx_blocked = blocked_input_records(git_components, archives)
    if components["nginx"].get("status") not in READY_COMPONENT_STATUSES:
        blocked.extend(nginx_blocked)
    selected = selected_native_component_records(context["target_connector"], components)
    for component_name, component in (("modsecurity", components["modsecurity"]), *selected):
        if component.get("status") in {"blocked", "corrupt", "failed"}:
            blocked.append({"name": component_name, **component})
    if build_cache.get("build_reuse_summary", {}).get("status") == "blocked":
        blocked.append(
            {
                "name": "runtime_build_cache",
                "blocker_reason": build_cache.get("build_reuse_summary", {}).get("blocker_reason", "modsecurity_build_id_mismatch"),
            }
        )
    for component_name in ("expat", "go_ftw", "albedo"):
        component = components[component_name]
        if component.get("status") in {"blocked", "corrupt", "failed"}:
            blocked.append({"name": "go-ftw" if component_name == "go_ftw" else component_name, **component})
    return blocked


def runtime_component_exit_code(
    context: dict[str, Any],
    blocked: list[dict[str, Any]],
    component_md: Path,
    runtime_env_snapshot: Path,
) -> int:
    if blocked:
        for item in blocked:
            label = "FAILED" if item.get("status") == "failed" else "BLOCKED"
            print(f"prepare-runtime-components: {label} {item.get('name')}: {item.get('blocker_reason')}")
        if any("build_exit_code" in item for item in blocked):
            return 1
        return 77
    print(f"prepare-runtime-components: cache={context['cache_root']}")
    print(f"prepare-runtime-components: report={component_md}")
    print(f"prepare-runtime-components: runtime-env-snapshot={runtime_env_snapshot}")
    return 0


def main() -> int:
    args = parse_runtime_component_args()
    selected = validate_checkout()
    if Path(args.connector_root).resolve() != selected or Path(args.framework_root).resolve() != test_root():
        raise RuntimeError("component preparation roots differ from the explicit selected checkouts")
    if not os.environ.get("CONNECTOR_TEST_PROFILE"):
        raise RuntimeError("CONNECTOR_TEST_PROFILE is required explicitly")
    context, exit_code = runtime_component_context(args)
    if context is None:
        return exit_code
    paths = runtime_component_cache_paths(context["cache_root"])
    prepare_phases = [
        "1. validate safe paths",
        "2. prepare git/source/archive cache recursively",
        "3. prepare/build expat local prefix",
        "4. prepare/build shared ModSecurity v3 once per source/ref/build config",
        "5. prepare/reuse connector builds keyed by connector inputs and ModSecurity build ID",
        "6. prepare/build go-ftw from latest release tag",
        "7. prepare/build albedo from latest release tag",
        "8. write manifests/reports",
    ]

    git_components = prepare_runtime_git_components(context, paths)

    archives = prepare_runtime_archives(context, paths)

    components = prepare_native_component_records(context, paths, git_components, archives)
    context["components"] = components
    runtime_env = runtime_component_environment(context, paths, components)
    runtime_env_snapshot = write_runtime_environment_exports(context, runtime_env)
    payload, build_cache = runtime_component_payload(
        context,
        components,
        git_components,
        archives,
        prepare_phases,
        runtime_env,
    )
    component_md = write_runtime_component_reports(context, payload, build_cache, git_components)

    blocked = runtime_component_blockers(context, components, git_components, archives, build_cache)
    return runtime_component_exit_code(context, blocked, component_md, runtime_env_snapshot)


if __name__ == "__main__":
    raise SystemExit(main())
