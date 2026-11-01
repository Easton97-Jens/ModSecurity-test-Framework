#!/usr/bin/env python3
"""Fail-closed runner preflight for the protected exact-head NGINX workflow.

This program is part of the protected Base.  It deliberately consumes no
candidate checkout and does not try to infer that a generic runner is safe.
Instead it validates the properties that can be observed locally before a
candidate build or a privileged cell starts: a fixed, scrubbed environment, a
private run directory, a checked-out Base revision, and the absence of common
host-control sockets.  Provisioning a disposable runner and a GitHub
Environment remains an external, reviewable prerequisite.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


SHA40_RE = re.compile(r"^(?a:[\da-f]{40})$")
ROLES = frozenset({"candidate-build", "privileged"})
_CANDIDATE_TASK_ROOT_NAME = "protected-exact-head-build"
_PRIVILEGED_TASK_ROOT_NAME = "protected-exact-head-runtime"
_ROLE_TASK_DIRECTORIES = {
    "candidate-build": (("dispatcher",),),
    "privileged": (("inputs", "dispatcher"), ("inputs", "candidate")),
}
REQUIRED_ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/nonexistent",
    "LANG": "C",
    "LC_ALL": "C",
}
OPTIONAL_ENV = frozenset({"RUNNER_TEMP", "GITHUB_WORKSPACE"})
HOST_CONTROL_PATHS = (
    Path("/var/run/docker.sock"),
    Path("/run/docker.sock"),
    Path("/run/containerd/containerd.sock"),
    Path("/var/run/podman/podman.sock"),
    Path("/run/podman/podman.sock"),
)
# This executable is provisioned outside the checkout by the protected runner
# owner.  It must snapshot and verify the exact Base Git blob before invoking
# any checkout-resident code as root; a runner-local copy is not trusted.
HOST_GATE_PATH = Path(
    "/usr/local/libexec/modsecurity-protected-exact-head/run-exact-base-launcher"
)


class PreflightError(RuntimeError):
    """The runner does not satisfy the protected-cell admission contract."""


def fail(message: str) -> None:
    raise PreflightError(message)


def require_sha40(value: str, label: str) -> str:
    if SHA40_RE.fullmatch(value) is None:
        fail(f"{label} must be a lowercase 40-character SHA")
    return value


def normalized_absolute(value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        fail(f"{label} must be an absolute normalized path")
    result = Path(os.path.normpath(os.fspath(path)))
    if result == Path("/"):
        fail(f"{label} must not be filesystem root")
    return result


def no_symlink_chain(path: Path, label: str, *, missing_leaf: bool = False) -> Path:
    path = normalized_absolute(os.fspath(path), label)
    current = Path(path.root)
    for index, part in enumerate(path.parts[1:]):
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if missing_leaf and index == len(path.parts) - 2:
                break
            fail(f"{label} component is missing")
        if stat.S_ISLNK(metadata.st_mode):
            fail(f"{label} contains a symbolic link")
    return path


def _task_root_name(role: str) -> str:
    if role == "candidate-build":
        return _CANDIDATE_TASK_ROOT_NAME
    if role == "privileged":
        return _PRIVILEGED_TASK_ROOT_NAME
    fail("runner role is unsupported")


def _runner_temp_path() -> Path:
    return no_symlink_chain(Path(os.environ["RUNNER_TEMP"]), "RUNNER_TEMP")


def _open_private_runner_temp() -> tuple[Path, int]:
    runner_temp = _runner_temp_path()
    descriptor = -1
    try:
        descriptor = os.open(
            runner_temp,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or metadata.st_mode & 0o022
        ):
            fail("RUNNER_TEMP is not a private runner-owned directory")
        result = descriptor
        descriptor = -1
        return runner_temp, result
    except OSError as exc:
        fail(f"cannot open RUNNER_TEMP: {exc}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _require_fresh_private_task_root(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        fail("task root is not private to the invoking runner identity")
    if os.listdir(descriptor):
        fail("task root must be fresh")


def _open_or_create_private_task_root(role: str) -> tuple[Path, int]:
    runner_temp, parent_descriptor = _open_private_runner_temp()
    name = _task_root_name(role)
    descriptor = -1
    try:
        try:
            before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            try:
                os.mkdir(name, mode=0o700, dir_fd=parent_descriptor)
            except OSError as exc:
                fail(f"cannot create private task root: {exc}")
            before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode):
            fail("task root is not a non-symlink directory")
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            fail("task root changed while being opened")
        _require_fresh_private_task_root(descriptor)
        result = descriptor
        descriptor = -1
        return runner_temp / name, result
    except OSError as exc:
        fail(f"cannot open private task root: {exc}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def _require_private_task_directory(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        fail("protected run directory has unsafe ownership or mode")


def _create_private_task_directory(
    task_descriptor: int, components: tuple[str, ...]
) -> None:
    descriptor = os.dup(task_descriptor)
    try:
        for index, name in enumerate(components):
            try:
                before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                os.mkdir(name, mode=0o700, dir_fd=descriptor)
                before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            else:
                if index == len(components) - 1:
                    fail("protected run directory is not fresh")
            if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
                fail("protected run directory is not a non-symlink directory")
            child = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            opened = os.fstat(child)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                os.close(child)
                fail("protected run directory changed while being opened")
            _require_private_task_directory(child)
            previous = descriptor
            descriptor = child
            os.close(previous)
    except OSError as exc:
        fail(f"cannot create protected run directory: {exc}")
    finally:
        os.close(descriptor)


def require_scrubbed_environment() -> None:
    allowed = set(REQUIRED_ENV) | set(OPTIONAL_ENV)
    unexpected = set(os.environ) - allowed
    if unexpected:
        fail("runner environment contains a non-allowlisted variable")
    for key, expected in REQUIRED_ENV.items():
        if os.environ.get(key) != expected:
            fail(f"runner environment does not provide fixed {key}")
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        fail("runner environment lacks RUNNER_TEMP")
    if not os.environ.get("GITHUB_WORKSPACE"):
        fail("runner environment lacks GITHUB_WORKSPACE")
    no_symlink_chain(Path(runner_temp), "RUNNER_TEMP")


def reject_host_control_sockets() -> None:
    for path in HOST_CONTROL_PATHS:
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            fail(f"cannot inspect host-control path: {exc}")
        # Treat any pre-existing entry at one of these fixed control locations
        # as unsafe.  A non-socket replacement is not a harmless exception.
        fail("runner exposes a host-control socket path")


def require_private_task_root(role: str = "candidate-build") -> Path:
    root, descriptor = _open_or_create_private_task_root(role)
    try:
        return root
    finally:
        os.close(descriptor)


def _base_repo_path() -> Path:
    value = os.environ.get("GITHUB_WORKSPACE")
    if not value:
        fail("trusted Base checkout is unavailable")
    return no_symlink_chain(Path(value), "trusted Base checkout")


def require_base_checkout(expected_sha: str) -> Path:
    root = _base_repo_path()
    descriptor = -1
    try:
        descriptor = os.open(
            root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o022:
            fail("trusted Base checkout is not a safe directory")
        git = Path("/usr/bin/git")
        try:
            git_stat = git.lstat()
        except OSError as exc:
            fail(f"fixed git is unavailable: {exc}")
        if not stat.S_ISREG(git_stat.st_mode) or git_stat.st_mode & 0o022:
            fail("fixed git executable is unsafe")
        try:
            completed = subprocess.run(
                [os.fspath(git), "rev-parse", "HEAD^{commit}"],
                check=False,
                cwd=f"/proc/self/fd/{descriptor}",
                pass_fds=(descriptor,),
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                env=dict(REQUIRED_ENV),
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            fail(f"cannot verify trusted Base checkout: {exc}")
    except OSError as exc:
        fail(f"cannot open trusted Base checkout: {exc}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    observed = completed.stdout.strip()
    if completed.returncode != 0 or observed != require_sha40(expected_sha, "trusted Base SHA"):
        fail("trusted Base checkout is not at the expected immutable revision")
    return root


def require_host_gate() -> Path:
    """Admit only the preinstalled, root-owned privilege bootstrap."""

    gate = no_symlink_chain(HOST_GATE_PATH, "protected host gate")
    try:
        metadata = gate.lstat()
    except OSError as exc:
        fail(f"protected host gate is unavailable: {exc}")
    if not stat.S_ISREG(metadata.st_mode):
        fail("protected host gate is not a regular file")
    if metadata.st_uid != 0 or metadata.st_gid != 0:
        fail("protected host gate is not root-owned")
    if stat.S_IMODE(metadata.st_mode) != 0o755:
        fail("protected host gate does not have mode 0755")
    return gate


def prepare(role: str, trusted_base_sha: str) -> Path:
    if role not in ROLES:
        fail("runner role is unsupported")
    trusted_base_sha = require_sha40(trusted_base_sha, "trusted Base SHA")
    require_scrubbed_environment()
    reject_host_control_sockets()
    require_base_checkout(trusted_base_sha)
    if role == "privileged":
        require_host_gate()
    root, descriptor = _open_or_create_private_task_root(role)
    try:
        # The fixed children are created through the retained task-root FD,
        # before candidate checkout or build code can execute.
        for components in _ROLE_TASK_DIRECTORIES[role]:
            _create_private_task_directory(descriptor, components)
        return root
    finally:
        os.close(descriptor)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=sorted(ROLES), required=True)
    parser.add_argument("--trusted-base-sha", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = parse_args(argv)
        prepare(arguments.role, arguments.trusted_base_sha)
    except PreflightError as exc:
        print(f"protected exact-head runner preflight: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
