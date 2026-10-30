#!/usr/bin/env python3
"""Launch the bounded GitHub-hosted NGINX functional-A root runtime.

This is deliberately not a broker or an adversarial attestation boundary.  It
only keeps the already-built, exact-head NGINX functional test from inheriting
the runner's ambient environment or re-running provisioning as root.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Mapping


_SAFE_PATH = "/usr/bin:/bin"
_SUDO = "/usr/bin/sudo"
_ENV = "/usr/bin/env"
_SHELL = "/bin/sh"
_PYTHON = "/usr/bin/python3"
_CURL = "/usr/bin/curl"
_WORKER_NAME_MAX = 64
_WORKER_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_")
_MODSECURITY_RUNTIME_LIBRARY = "libmodsecurity.so.3"
# Resolve the standard temporary root, then bind it back to the one fixed
# workflow-owned shared namespace.  A candidate-controlled TMPDIR cannot
# redirect the later privileged handoff: a value other than this exact path
# fails closed before any sudo invocation.
_EXPECTED_FUNCTIONAL_TMP_ROOT = Path(os.sep) / "tmp"
_FUNCTIONAL_JOB_ROOT_PREFIX = "ModSecurity-conector-nginx-functional-root."
_FUNCTIONAL_JOB_ROOT_SUFFIX_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
)
_VERIFIED_RUN_ROOT_NAME = "ModSecurity-conector-nginx-exact-head"
_FUNCTIONAL_PARENT_NAME = "ModSecurity-conector-nginx-functional-parent"
_FUNCTIONAL_ROOT_NAME = "nginx-hosted-functional-a"
_FUNCTIONAL_EVIDENCE_DIRECTORY_NAME = "nginx-functional-a-evidence"
_COMMIT_SHA_CHARS = frozenset("0123456789abcdef")


class FunctionalALaunchError(ValueError):
    """The unprivileged preparation did not provide a bounded root input."""


def _has_unsafe_character(value: str) -> bool:
    return not value or any(character in value for character in ("\x00", "\r", "\n"))


def _require_worker_name(env: Mapping[str, str], name: str) -> str:
    value = str(env.get(name, ""))
    if (
        _has_unsafe_character(value)
        or len(value) > _WORKER_NAME_MAX
        or value[0] == "-"
        or any(character not in _WORKER_NAME_CHARS for character in value)
    ):
        raise FunctionalALaunchError(f"{name} is not a bounded local account name")
    return value


def _require_commit_sha(env: Mapping[str, str], name: str) -> str:
    value = str(env.get(name, ""))
    if len(value) != 40 or any(character not in _COMMIT_SHA_CHARS for character in value):
        raise FunctionalALaunchError(f"{name} must be an exact lowercase commit SHA")
    return value


def _require_sha256(env: Mapping[str, str], name: str) -> str:
    value = str(env.get(name, ""))
    if len(value) != 64 or any(character not in _COMMIT_SHA_CHARS for character in value):
        raise FunctionalALaunchError(f"{name} must be an exact lowercase SHA-256")
    return value


def _absolute_path(value: str, name: str) -> Path:
    if _has_unsafe_character(value):
        raise FunctionalALaunchError(f"{name} is empty or contains a control character")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise FunctionalALaunchError(f"{name} must be an absolute non-traversing path")
    return path


def _require_no_symlink_components(path: Path, name: str) -> Path:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as error:
            raise FunctionalALaunchError(f"{name} is unavailable: {current}: {error}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise FunctionalALaunchError(f"{name} contains a symbolic link: {current}")
    return path


def _require_under(path: Path, root: Path, name: str) -> Path:
    try:
        path.relative_to(root)
    except ValueError as error:
        raise FunctionalALaunchError(f"{name} must remain below VERIFIED_RUN_ROOT") from error
    return path


def _require_directory(path: Path, name: str) -> Path:
    _require_no_symlink_components(path, name)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise FunctionalALaunchError(f"{name} is unavailable: {error}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise FunctionalALaunchError(f"{name} must be a directory")
    return path


def _require_regular_executable(path: Path, name: str) -> Path:
    _require_no_symlink_components(path, name)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise FunctionalALaunchError(f"{name} is unavailable: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
        raise FunctionalALaunchError(f"{name} must be an executable regular file")
    return path


def _require_regular_file(path: Path, name: str) -> Path:
    _require_no_symlink_components(path, name)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise FunctionalALaunchError(f"{name} is unavailable: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise FunctionalALaunchError(f"{name} must be a regular file")
    return path


def _require_trusted_functional_tmp_root() -> Path:
    """Require the fixed sticky parent that protects the fresh job-root name."""

    path = _absolute_path(tempfile.gettempdir(), "Functional-A temporary root")
    if path != _EXPECTED_FUNCTIONAL_TMP_ROOT:
        raise FunctionalALaunchError(
            "Functional-A temporary root must resolve to the fixed /tmp namespace"
        )
    path = _require_directory(path, "Functional-A temporary root")
    filesystem_root = _require_directory(Path(path.anchor), "Functional-A filesystem root")
    if not filesystem_root.lstat().st_mode & stat.S_IXOTH:
        raise FunctionalALaunchError(
            "Functional-A temporary root has a worker-non-traversable ancestor"
        )
    metadata = path.lstat()
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o1777:
        raise FunctionalALaunchError(
            "Functional-A temporary root must be root-owned sticky mode 01777"
        )
    return path


def _require_private_verified_run_root(verified_root: Path) -> Path:
    """Bind provisioning artifacts to the fresh job root, not a broad temp tree."""

    temporary_root = _require_trusted_functional_tmp_root()
    job_root = verified_root.parent
    suffix = job_root.name[len(_FUNCTIONAL_JOB_ROOT_PREFIX) :]
    if (
        job_root.parent != temporary_root
        or not job_root.name.startswith(_FUNCTIONAL_JOB_ROOT_PREFIX)
        or not suffix
        or any(character not in _FUNCTIONAL_JOB_ROOT_SUFFIX_CHARS for character in suffix)
    ):
        raise FunctionalALaunchError(
            "VERIFIED_RUN_ROOT must be below the designated fresh /tmp job root"
        )
    _require_directory(job_root, "Functional-A job root")
    job_metadata = job_root.lstat()
    if job_metadata.st_uid != 0:
        raise FunctionalALaunchError(
            "Functional-A job root must be owned by root"
        )
    if stat.S_IMODE(job_metadata.st_mode) != 0o711:
        raise FunctionalALaunchError(
            "Functional-A job root must be exactly non-enumerable mode 0711"
        )
    if verified_root.name != _VERIFIED_RUN_ROOT_NAME or verified_root.parent != job_root:
        raise FunctionalALaunchError(
            "VERIFIED_RUN_ROOT must be the designated private child of the Functional-A job root"
        )
    _require_directory(verified_root, "VERIFIED_RUN_ROOT")
    verified_metadata = verified_root.lstat()
    if verified_metadata.st_uid != os.geteuid():
        raise FunctionalALaunchError(
            "VERIFIED_RUN_ROOT must be owned by the workflow runner"
        )
    if stat.S_IMODE(verified_metadata.st_mode) != 0o700:
        raise FunctionalALaunchError("VERIFIED_RUN_ROOT must be exactly private mode 0700")
    return job_root


def _require_worker_traversable_functional_parent(
    path: Path, verified_root: Path
) -> Path:
    """Accept only the workflow-created sibling for worker-visible runtime paths."""

    job_root = _require_private_verified_run_root(verified_root)
    if path.name != _FUNCTIONAL_PARENT_NAME or path.parent != job_root:
        raise FunctionalALaunchError(
            "NGINX_FUNCTIONAL_A_PARENT_ROOT must be the designated sibling of VERIFIED_RUN_ROOT"
        )
    _require_directory(path, "NGINX_FUNCTIONAL_A_PARENT_ROOT")
    metadata = path.lstat()
    if metadata.st_uid != 0:
        raise FunctionalALaunchError(
            "NGINX_FUNCTIONAL_A_PARENT_ROOT must be owned by root"
        )
    if stat.S_IMODE(metadata.st_mode) != 0o711:
        raise FunctionalALaunchError(
            "NGINX_FUNCTIONAL_A_PARENT_ROOT must be exactly non-enumerable mode 0711"
        )
    # The private-root helper has already bound this direct child to the fixed
    # root-owned sticky /tmp parent.  Only the two newly-created descendants
    # remain to be checked here; both must carry other-execute access.
    for current in (job_root, path):
        if not current.lstat().st_mode & stat.S_IXOTH:
            raise FunctionalALaunchError(
                "NGINX_FUNCTIONAL_A_PARENT_ROOT has a worker-non-traversable ancestor"
            )
    return path


def _require_functional_evidence_directory(path: Path, verified_root: Path) -> Path:
    """Bind the only runner-readable Functional-A evidence staging directory."""

    expected = verified_root / _FUNCTIONAL_EVIDENCE_DIRECTORY_NAME
    if path != expected:
        raise FunctionalALaunchError(
            "NGINX_FUNCTIONAL_A_EVIDENCE_ROOT must be the designated verified-root child"
        )
    _require_directory(path, "NGINX_FUNCTIONAL_A_EVIDENCE_ROOT")
    metadata = path.lstat()
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise FunctionalALaunchError(
            "NGINX_FUNCTIONAL_A_EVIDENCE_ROOT must be runner-owned private mode 0700"
        )
    try:
        with os.scandir(path) as entries:
            if next(entries, None) is not None:
                raise FunctionalALaunchError(
                    "NGINX_FUNCTIONAL_A_EVIDENCE_ROOT must be fresh and empty"
                )
    except OSError as error:
        raise FunctionalALaunchError(
            f"NGINX_FUNCTIONAL_A_EVIDENCE_ROOT cannot be inspected: {error}"
        ) from error
    return path


def repository_root(env: Mapping[str, str] | None = None) -> Path:
    """Validate an explicitly selected product checkout without package imports."""
    env = os.environ if env is None else env
    root = _require_directory(_absolute_path(str(env.get("CONNECTOR_ROOT", "")), "CONNECTOR_ROOT"),
                              "CONNECTOR_ROOT")
    revision = _require_commit_sha(env, "CONNECTOR_REVISION")
    try:
        observed = subprocess.run(
            ["/usr/bin/git", "-c", "core.hooksPath=/nonexistent", "-c", "core.fsmonitor=false",
             "-C", str(root), "rev-parse", "--show-toplevel", "HEAD"],
            check=True, capture_output=True, text=True, timeout=15,
            env={"PATH": _SAFE_PATH, "HOME": "/nonexistent", "LC_ALL": "C",
                 "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise FunctionalALaunchError("explicit Connector checkout cannot be verified") from error
    if observed.stdout.splitlines() != [str(root), revision]:
        raise FunctionalALaunchError("explicit Connector checkout or revision does not match")
    return root


def build_root_command(env: Mapping[str, str]) -> list[str]:
    """Validate fixed inputs and return the one explicit root command vector."""

    connector_root = _require_directory(repository_root(env), "connector root")
    framework_root = _require_directory(
        _absolute_path(str(env.get("TEST_ROOT", "")), "TEST_ROOT"), "Framework root")
    if str(env.get("FRAMEWORK_ROOT", "")) != str(framework_root):
        raise FunctionalALaunchError("FRAMEWORK_ROOT must match explicit TEST_ROOT")
    rule_preamble = _require_regular_file(
        framework_root / "tests" / "rules" / "no-crs-baseline.conf", "no-CRS rule preamble"
    )
    exact_script = _require_regular_file(
        framework_root / "connector_suite/adapters/nginx/harness/run_exact_head_use_error_log.sh",
        "exact functional-A script",
    )

    verified_root = _require_directory(
        _absolute_path(str(env.get("VERIFIED_RUN_ROOT", "")), "VERIFIED_RUN_ROOT"),
        "VERIFIED_RUN_ROOT",
    )
    functional_parent = _require_worker_traversable_functional_parent(
        _absolute_path(
            str(env.get("NGINX_FUNCTIONAL_A_PARENT_ROOT", "")),
            "NGINX_FUNCTIONAL_A_PARENT_ROOT",
        ),
        verified_root,
    )
    functional_root = functional_parent / _FUNCTIONAL_ROOT_NAME
    evidence_root = _require_functional_evidence_directory(
        _absolute_path(
            str(env.get("NGINX_FUNCTIONAL_A_EVIDENCE_ROOT", "")),
            "NGINX_FUNCTIONAL_A_EVIDENCE_ROOT",
        ),
        verified_root,
    )
    expected_parent_sha = _require_commit_sha(env, "EXPECTED_PARENT_SHA")
    if _require_commit_sha(env, "CONNECTOR_REVISION") != expected_parent_sha:
        raise FunctionalALaunchError("CONNECTOR_REVISION must match EXPECTED_PARENT_SHA")
    nginx_archive_sha256 = _require_sha256(env, "NGINX_SHA256")

    nginx_prefix = _require_under(
        _absolute_path(str(env.get("NGINX_PREFIX", "")), "NGINX_PREFIX"),
        verified_root,
        "NGINX_PREFIX",
    )
    nginx_build = _require_under(
        _absolute_path(str(env.get("NGINX_BUILD_DIR", "")), "NGINX_BUILD_DIR"),
        verified_root,
        "NGINX_BUILD_DIR",
    )
    modsecurity_lib = _require_under(
        _absolute_path(str(env.get("MODSECURITY_LIB_DIR", "")), "MODSECURITY_LIB_DIR"),
        verified_root,
        "MODSECURITY_LIB_DIR",
    )
    _require_directory(nginx_prefix, "NGINX_PREFIX")
    _require_directory(nginx_build, "NGINX_BUILD_DIR")
    _require_directory(modsecurity_lib, "MODSECURITY_LIB_DIR")
    nginx_binary = _require_regular_executable(nginx_prefix / "sbin/nginx", "NGINX binary")
    nginx_module = _require_regular_file(
        nginx_prefix / "modules/ngx_http_modsecurity_module.so", "NGINX module"
    )
    modsecurity_runtime_library = _require_regular_file(
        modsecurity_lib / _MODSECURITY_RUNTIME_LIBRARY,
        "libmodsecurity runtime library",
    )

    worker_user = _require_worker_name(env, "NGINX_FUNCTIONAL_WORKER_USER")
    worker_group = _require_worker_name(env, "NGINX_FUNCTIONAL_WORKER_GROUP")
    protocol = str(env.get("NGINX_PROTOCOL_PROFILE", "h1"))
    if protocol != "h1":
        raise FunctionalALaunchError("functional-A exact gate requires the h1 profile")

    functional_scope = str(env.get("NGINX_FUNCTIONAL_SCOPE", "selected-phase4"))
    if functional_scope not in {"selected-phase4", "full"}:
        raise FunctionalALaunchError("unknown Functional-A selection scope")
    if functional_scope == "full" and env.get("ON_DEMAND_TESTS") != "1":
        raise FunctionalALaunchError("full Functional-A campaign requires explicit ON_DEMAND_TESTS=1")

    root_environment = {
        "PATH": _SAFE_PATH,
        "HOME": "/nonexistent",
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "CONNECTOR_ROOT": str(connector_root),
        "CONNECTOR_REVISION": expected_parent_sha,
        "FRAMEWORK_ROOT": str(framework_root),
        "TEST_ROOT": str(framework_root),
        "CONNECTOR_TEST_PROFILE": "h1",
        "NGINX_FUNCTIONAL_A_PARENT_ROOT": str(functional_parent),
        "VERIFIED_RUN_ROOT": str(functional_root),
        "NGINX_FUNCTIONAL_A_ROOT": str(functional_root),
        "NGINX_FUNCTIONAL_A_EVIDENCE_ROOT": str(evidence_root),
        "NGINX_FUNCTIONAL_A_EVIDENCE_OWNER_UID": str(os.geteuid()),
        "NGINX_FUNCTIONAL_A_EVIDENCE_OWNER_GID": str(os.getegid()),
        "EXPECTED_PARENT_SHA": expected_parent_sha,
        "NGINX_SHA256": nginx_archive_sha256,
        "NGINX_PREFIX": str(nginx_prefix),
        "NGINX_BUILD_DIR": str(nginx_build),
        "NGINX_BINARY": str(nginx_binary),
        "NGINX_MODULE": str(nginx_module),
        "MODSECURITY_LIB_DIR": str(modsecurity_lib),
        "NGINX_FUNCTIONAL_A_RUNTIME_LIBRARY": str(modsecurity_runtime_library),
        "MODSECURITY_RULE_PREAMBLE_FILE": str(rule_preamble),
        "MODSECURITY_TEST_VARIANT": "no-crs",
        "NO_CRS_BASELINE": "1",
        "NGINX_WORKER_USER": worker_user,
        "NGINX_WORKER_GROUP": worker_group,
        "NGINX_HOSTED_FUNCTIONAL_A": "1",
        "NGINX_FUNCTIONAL_SCOPE": functional_scope,
        "ON_DEMAND_TESTS": "1" if functional_scope == "full" else "0",
        "NGINX_LIFECYCLE_ENABLED": "1",
        "NGINX_PROTOCOL_PROFILE": "h1",
        "PYTHON": _PYTHON,
        "CURL": _CURL,
    }
    assignments = [f"{key}={value}" for key, value in root_environment.items()]
    return [_SUDO, "-n", _ENV, "-i", *assignments, _SHELL, str(exact_script)]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--print-command",
        action="store_true",
        help="validate inputs and print the root command without executing it",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        command = build_root_command(os.environ)
    except FunctionalALaunchError as error:
        print(f"nginx hosted functional A blocked: {error}", file=sys.stderr)
        return 77
    if args.print_command:
        print(json.dumps(command))
        return 0
    # ``sudo`` itself receives only PATH.  Its child immediately replaces the
    # environment with the explicit allowlist above; no runner LD/Python/shell
    # startup variable crosses this privilege boundary.
    os.execve(_SUDO, command, {"PATH": _SAFE_PATH})
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
