#!/usr/bin/env python3
"""Run the update-submodules candidate in a private Linux mount/PID namespace.

This is intentionally a small trusted, root-only launcher.  Candidate code is
never evaluated until after the namespace has been built and the process has
dropped to the dedicated validator account.
"""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
import errno
import grp
import os
from pathlib import Path
import pwd
import stat
import sys
from typing import Callable, Sequence


CLONE_NEWNS = 0x00020000
CLONE_NEWPID = 0x20000000
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
MS_REMOUNT = 32
PR_SET_NO_NEW_PRIVS = 38
LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
LIBC.mount.restype = ctypes.c_int
LIBC.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
LIBC.umount2.restype = ctypes.c_int
LIBC.unshare.argtypes = [ctypes.c_int]
LIBC.unshare.restype = ctypes.c_int
LIBC.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
LIBC.prctl.restype = ctypes.c_int
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PROCFS_TARGET = Path("/proc")
JAIL_ROOT = Path("/")
JAIL_SOURCE = Path("/source")
JAIL_EXTERNAL = Path("/external")
JAIL_GUARD = Path("/guard")
JAIL_DEV = Path("/dev")
JAIL_RUNTIME_DIRECTORIES = (
    Path("/usr"),
    Path("/bin"),
    Path("/sbin"),
    Path("/lib"),
    Path("/lib64"),
)
JAIL_HOSTED_PYTHON_ROOT = Path("/opt/hostedtoolcache/Python")
JAIL_HOSTED_PYTHON_ARCHITECTURE = "x64"
JAIL_COMPILER_ROOT = Path("/usr")
JAIL_C_COMPILER = Path("/usr/bin/gcc")
JAIL_CXX_COMPILER = Path("/usr/bin/g++")
JAIL_RUNTIME_ETC_DIRECTORIES = (Path("/etc/ssl"),)
JAIL_RUNTIME_ETC_FILES = (
    Path("/etc/passwd"),
    Path("/etc/group"),
    Path("/etc/nsswitch.conf"),
    Path("/etc/resolv.conf"),
    Path("/etc/hosts"),
    Path("/etc/ld.so.cache"),
    Path("/etc/ca-certificates.conf"),
)
JAIL_FORBIDDEN_PATH_COMPONENTS = ("tmp", "var", "home", "root", "run", "sys")
CandidateEntry = Callable[[Path, Path, Path, Path, Path, int, int], None]
CandidateArguments = tuple[Path, Path, Path, Path, Path, int, int]


@dataclass(frozen=True)
class JailLayout:
    """Physical mount targets that form the candidate's chroot."""

    root: Path
    source: Path
    external: Path
    proc: Path
    mounts: tuple[Path, ...]


class NamespaceUnavailable(RuntimeError):
    """The host kernel/container does not permit the required isolation."""


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--framework-root", required=True)
    parser.add_argument("--write-root", required=True)
    parser.add_argument("--external-root", required=True)
    parser.add_argument("--validator-user", required=True)
    parser.add_argument("--validator-group", required=True)
    parser.add_argument("--python", required=True)
    parser.add_argument("--namespace-parent", required=True)
    return parser.parse_args(argv)


def _absolute_existing_directory(value: str, label: str) -> Path:
    if not value or not os.path.isabs(value) or os.path.normpath(value) != value:
        raise ValueError(f"{label} must be a canonical absolute path")
    path = Path(value)
    current = Path("/")
    for part in path.parts[1:]:
        current /= part
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"{label} must be an existing non-symlink directory")
    return path


def _strict_child(child: Path, parent: Path, label: str) -> None:
    try:
        child.relative_to(parent)
    except ValueError as exc:
        raise ValueError(f"{label} must be below source root") from exc
    if child == parent:
        raise ValueError(f"{label} must be a strict child of source root")


def _disjoint(first: Path, second: Path, first_label: str, second_label: str) -> None:
    for candidate, parent in ((first, second), (second, first)):
        try:
            candidate.relative_to(parent)
        except ValueError:
            continue
        raise ValueError(f"{first_label} and {second_label} must be disjoint")


def _identity(user: str, group: str) -> tuple[int, int]:
    try:
        account = pwd.getpwnam(user)
        group_entry = grp.getgrnam(group)
        primary_group = grp.getgrgid(account.pw_gid)
    except KeyError as error:
        raise ValueError("validator user and group must already exist") from error
    if (
        account.pw_uid == 0
        or account.pw_gid == 0
        or group_entry.gr_gid == 0
        or primary_group.gr_name == "root"
        or group_entry.gr_name == "root"
    ):
        raise ValueError("validator identity must be unprivileged")
    memberships = {entry.gr_name for entry in grp.getgrall() if user in entry.gr_mem}
    memberships.add(primary_group.gr_name)
    if group not in memberships or memberships & {"root", "sudo", "wheel", "admin"}:
        raise ValueError("validator identity is not a dedicated unprivileged account")
    return account.pw_uid, group_entry.gr_gid


def _mount(source: str | None, target: Path, flags: int, filesystem_type: str | None = None) -> None:
    result = LIBC.mount(
        ctypes.c_char_p(source.encode() if source is not None else None),
        ctypes.c_char_p(os.fsencode(target)),
        ctypes.c_char_p(filesystem_type.encode() if filesystem_type is not None else None),
        ctypes.c_ulong(flags), None,
    )
    if result != 0:
        error = ctypes.get_errno()
        if error in {errno.EPERM, errno.ENOSYS, errno.EINVAL}:
            raise NamespaceUnavailable(f"mount namespace operation unavailable: {os.strerror(error)}")
        raise OSError(error, os.strerror(error), target)


def _umount(target: Path) -> None:
    if LIBC.umount2(ctypes.c_char_p(os.fsencode(target)), 0) != 0:
        error = ctypes.get_errno()
        if error != errno.EINVAL:
            raise OSError(error, os.strerror(error), target)


def _mountinfo_for(path: Path) -> list[str]:
    target = str(path)
    return [
        line for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
        if len(line.split(" - ", 1)[0].split()) > 4 and line.split(" - ", 1)[0].split()[4] == target
    ]


def _decode_mountinfo_path(value: str) -> str:
    """Decode a mountinfo mountpoint and reject malformed octal escapes."""
    fragments = value.split("\\")
    decoded = [fragments[0]]
    for fragment in fragments[1:]:
        escaped = fragment[:3]
        if len(escaped) != 3 or any(digit not in "01234567" for digit in escaped):
            raise ValueError("mountinfo contains an invalid escaped mount path")
        decoded.extend((chr(int(escaped, 8)), fragment[3:]))
    return "".join(decoded)


def _reject_nested_source_mounts(source: Path) -> None:
    """Reject host submounts before a non-recursive source bind is created."""
    try:
        rows = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise RuntimeError("cannot read mountinfo for source topology validation") from error
    for row in rows:
        before_separator, separator, _after_separator = row.partition(" - ")
        fields = before_separator.split()
        if not separator or len(fields) < 5:
            raise RuntimeError("mountinfo contains an invalid mount record")
        mountpoint = Path(_decode_mountinfo_path(fields[4]))
        if not mountpoint.is_absolute() or os.path.normpath(os.fspath(mountpoint)) != os.fspath(
            mountpoint
        ):
            raise RuntimeError("mountinfo contains an invalid mountpoint")
        try:
            mountpoint.relative_to(source)
        except ValueError:
            continue
        if mountpoint != source:
            raise RuntimeError(f"source root contains an unexpected active mount: {mountpoint}")


def _validate_namespace_parent(namespace_parent: Path, validator_gid: int) -> None:
    """Accept only a root-created private child of a trusted sticky directory."""
    namespace_ancestor = namespace_parent.parent
    if namespace_parent == namespace_ancestor:
        raise ValueError("namespace parent must have a trusted sticky ancestor")
    ancestor_metadata = os.lstat(namespace_ancestor)
    if (
        not stat.S_ISDIR(ancestor_metadata.st_mode)
        or stat.S_ISLNK(ancestor_metadata.st_mode)
        or ancestor_metadata.st_uid != 0
        or not ancestor_metadata.st_mode & stat.S_ISVTX
    ):
        raise ValueError("namespace parent requires a root-owned sticky ancestor")
    metadata = os.lstat(namespace_parent)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode))
        != (0, validator_gid, 0o750)
    ):
        raise ValueError("namespace parent must be root:validator mode 0750")
    if any(os.scandir(namespace_parent)):
        raise ValueError("namespace parent must be empty before mount layout creation")


def _create_mount_layout(namespace_parent: Path, validator_gid: int) -> Path:
    """Create and verify fixed root:validator traversal placeholders."""
    mount_root = namespace_parent / "mount-root"
    for path in (mount_root, mount_root / "source", mount_root / "external"):
        os.mkdir(path, mode=0o700)
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0:
                raise RuntimeError(f"unsafe namespace mount placeholder: {path}")
            os.fchown(descriptor, 0, validator_gid)
            os.fchmod(descriptor, 0o750)
        finally:
            os.close(descriptor)
    for path in (mount_root, mount_root / "source", mount_root / "external"):
        metadata = os.lstat(path)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != validator_gid
            or stat.S_IMODE(metadata.st_mode) != 0o750
        ):
            raise RuntimeError(f"unsafe namespace mount placeholder: {path}")
    return mount_root


def _verify_mount(
    target: Path, *, readonly: bool, require_nodev: bool = True, require_noexec: bool = False
) -> None:
    rows = _mountinfo_for(target)
    if len(rows) != 1:
        raise RuntimeError(f"expected exactly one private bind mount for {target}")
    options = rows[0].split(" - ", 1)[0].split()[5].split(",")
    if (
        ("ro" in options) != readonly
        or "nosuid" not in options
        or (require_nodev and "nodev" not in options)
        or (require_noexec and "noexec" not in options)
    ):
        raise RuntimeError(f"unsafe mount flags for {target}: {','.join(options)}")


def _verify_procfs(target: Path) -> None:
    """Require one fresh, hardened procfs layer over the supplied jail target."""
    hardened_rows = []
    for row in _mountinfo_for(target):
        before_separator, separator, after_separator = row.partition(" - ")
        fields = before_separator.split()
        filesystem = after_separator.split()[0] if separator and after_separator else ""
        options = fields[5].split(",") if len(fields) > 5 else []
        if filesystem == "proc" and {"ro", "nosuid", "nodev", "noexec"}.issubset(options):
            hardened_rows.append(row)
    if len(hardened_rows) != 1:
        raise RuntimeError(f"expected exactly one hardened procfs mount at {target}")


def _jail_target(jail_root: Path, candidate_path: Path) -> Path:
    """Map one fixed absolute path inside the jail to its physical mount target."""
    if not candidate_path.is_absolute() or candidate_path == JAIL_ROOT:
        raise RuntimeError(f"invalid jail target: {candidate_path}")
    return jail_root / candidate_path.relative_to(JAIL_ROOT)


def _secure_directory(path: Path, mode: int) -> None:
    """Set and verify an existing directory with descriptor-only ownership changes."""
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError(f"unsafe jail directory: {path}")
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, mode)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != mode
        ):
            raise RuntimeError(f"unsafe jail directory: {path}")
    finally:
        os.close(descriptor)


def _create_jail_directory(path: Path, mode: int = 0o755) -> None:
    os.mkdir(path, mode=0o700)
    _secure_directory(path, mode)


def _create_jail_file(path: Path) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise RuntimeError(f"unsafe jail file: {path}")
    finally:
        os.close(descriptor)


def _create_jail_device(path: Path, major: int, minor: int, mode: int) -> None:
    os.mknod(path, stat.S_IFCHR | mode, os.makedev(major, minor))
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISCHR(metadata.st_mode):
            raise RuntimeError(f"unsafe jail device: {path}")
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def _trusted_runtime_source(path: Path, *, directory: bool) -> None:
    """Accept only a host runtime input that is not writable by non-root users."""
    metadata = os.stat(path)
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected(metadata.st_mode)
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise RuntimeError(f"unsafe host runtime path for jailed candidate: {path}")


def _bind_readonly(source: Path, target: Path, *, noexec: bool = False) -> None:
    _mount(str(source), target, MS_BIND)
    flags = MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV
    if noexec:
        flags |= MS_NOEXEC
    _mount(None, target, flags)
    _verify_mount(target, readonly=True, require_noexec=noexec)


def _runtime_path_is_exposed(path: Path) -> bool:
    return any(
        path == directory or directory in path.parents
        for directory in JAIL_RUNTIME_DIRECTORIES
    )


def _fixed_runtime_executable(path: Path, label: str) -> Path:
    """Resolve one fixed compiler only when the jailed runtime exposes it read-only."""
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise RuntimeError(f"unsafe {label} for jailed candidate: {path}") from error
    metadata = os.stat(resolved)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
        or not metadata.st_mode & stat.S_IXOTH
        or not _runtime_path_is_exposed(resolved)
        or not (resolved == JAIL_COMPILER_ROOT or JAIL_COMPILER_ROOT in resolved.parents)
    ):
        raise RuntimeError(f"unsafe {label} for jailed candidate: {path}")
    return resolved


def _validate_hosted_python_runtime(path: Path) -> None:
    """Accept exactly one real toolcache runtime before its private RO bind.

    GitHub-hosted images may make the setup-python toolcache runner-writable.
    That is not accepted as general host-runtime trust: this helper limits the
    candidate view to the resolved ``<version>/x64`` subtree, and
    ``_bind_readonly`` verifies its independent read-only mount before the
    candidate exists.
    """
    try:
        relative = path.relative_to(JAIL_HOSTED_PYTHON_ROOT)
    except ValueError as error:
        raise RuntimeError(
            f"unsafe hosted Python runtime for jailed candidate: {path}"
        ) from error
    if len(relative.parts) != 2 or relative.parts[1] != JAIL_HOSTED_PYTHON_ARCHITECTURE:
        raise RuntimeError(f"unsafe hosted Python runtime for jailed candidate: {path}")
    current = JAIL_ROOT
    for part in path.parts[1:]:
        current /= part
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError(f"unsafe hosted Python runtime for jailed candidate: {path}")


def _hosted_python_runtime_root(python: Path) -> Path | None:
    """Return one exact setup-python runtime tree, never a broad host /opt mount."""
    if _runtime_path_is_exposed(python):
        return None
    try:
        relative = python.relative_to(JAIL_HOSTED_PYTHON_ROOT)
    except ValueError as error:
        raise RuntimeError(f"python is outside the jailed runtime allowlist: {python}") from error
    if (
        len(relative.parts) != 4
        or relative.parts[1] != JAIL_HOSTED_PYTHON_ARCHITECTURE
        or relative.parts[2] != "bin"
    ):
        raise RuntimeError(f"python is outside a hosted setup-python runtime: {python}")
    runtime_root = JAIL_HOSTED_PYTHON_ROOT.joinpath(*relative.parts[:2])
    _validate_hosted_python_runtime(runtime_root)
    return runtime_root


def _build_jail_layout(mount_root: Path, source: Path, external: Path, python: Path) -> JailLayout:
    """Build a private, allowlisted filesystem tree before candidate code exists."""
    hosted_python_root = _hosted_python_runtime_root(python)
    _mount("tmpfs", mount_root, MS_NOSUID | MS_NODEV | MS_NOEXEC, "tmpfs")
    _secure_directory(mount_root, 0o755)
    source_view = _jail_target(mount_root, JAIL_SOURCE)
    external_view = _jail_target(mount_root, JAIL_EXTERNAL)
    proc_view = _jail_target(mount_root, PROCFS_TARGET)
    guard_view = _jail_target(mount_root, JAIL_GUARD)
    dev_view = _jail_target(mount_root, JAIL_DEV)
    for target in (source_view, external_view, proc_view, guard_view, dev_view):
        _create_jail_directory(target)
    _mount("tmpfs", dev_view, MS_NOSUID | MS_NOEXEC, "tmpfs")
    _secure_directory(dev_view, 0o755)
    _create_jail_device(dev_view / "null", 1, 3, 0o666)
    _create_jail_device(dev_view / "urandom", 1, 9, 0o444)
    _verify_mount(dev_view, readonly=False, require_nodev=False, require_noexec=True)
    for candidate_directory in JAIL_RUNTIME_DIRECTORIES:
        host_directory = candidate_directory
        _trusted_runtime_source(host_directory, directory=True)
        target = _jail_target(mount_root, candidate_directory)
        _create_jail_directory(target)
        _bind_readonly(host_directory, target)
    hosted_python_target: Path | None = None
    if hosted_python_root is not None:
        hosted_parts = hosted_python_root.relative_to(JAIL_ROOT).parts
        for depth in range(1, len(hosted_parts) + 1):
            _create_jail_directory(mount_root.joinpath(*hosted_parts[:depth]))
        hosted_python_target = _jail_target(mount_root, hosted_python_root)
        _bind_readonly(hosted_python_root, hosted_python_target)
    etc_root = _jail_target(mount_root, Path("/etc"))
    _create_jail_directory(etc_root)
    for candidate_directory in JAIL_RUNTIME_ETC_DIRECTORIES:
        _trusted_runtime_source(candidate_directory, directory=True)
        target = _jail_target(mount_root, candidate_directory)
        _create_jail_directory(target)
        _bind_readonly(candidate_directory, target, noexec=True)
    for candidate_file in JAIL_RUNTIME_ETC_FILES:
        _trusted_runtime_source(candidate_file, directory=False)
        target = _jail_target(mount_root, candidate_file)
        _create_jail_file(target)
        _bind_readonly(candidate_file, target, noexec=True)
    _mount(str(source), source_view, MS_BIND)
    _mount(None, source_view, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV)
    _verify_mount(source_view, readonly=True)
    _mount(str(external), external_view, MS_BIND)
    _mount(None, external_view, MS_BIND | MS_REMOUNT | MS_NOSUID | MS_NODEV)
    _verify_mount(external_view, readonly=False)
    _mount(None, mount_root, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC)
    _verify_mount(mount_root, readonly=True, require_noexec=True)
    runtime_mounts = [*(_jail_target(mount_root, path) for path in JAIL_RUNTIME_DIRECTORIES)]
    if hosted_python_target is not None:
        runtime_mounts.append(hosted_python_target)
    mounts = (
        mount_root,
        source_view,
        external_view,
        dev_view,
        *runtime_mounts,
        *(_jail_target(mount_root, path) for path in JAIL_RUNTIME_ETC_DIRECTORIES),
        *(_jail_target(mount_root, path) for path in JAIL_RUNTIME_ETC_FILES),
        proc_view,
    )
    return JailLayout(mount_root, source_view, external_view, proc_view, mounts)


def _teardown_jail_layout(layout: JailLayout) -> None:
    """Synchronously remove every exact private mount in reverse creation order."""
    for target in reversed(layout.mounts):
        _umount(target)


def _close_unapproved_descriptors(allowed: set[int]) -> None:
    """Remove inherited files, directories, sockets, and pipes before UID drop."""
    with os.scandir("/proc/self/fd") as entries:
        descriptors = [int(entry.name) for entry in entries if entry.name.isdecimal()]
    for descriptor in descriptors:
        if descriptor > 2 and descriptor not in allowed:
            try:
                os.close(descriptor)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise


def _replace_standard_input() -> None:
    """Give the candidate a closed anonymous input, never an inherited host fd."""
    read_end, write_end = os.pipe()
    try:
        os.close(write_end)
        os.dup2(read_end, 0, inheritable=True)
    finally:
        if read_end != 0:
            os.close(read_end)


def _enter_jail(jail_root: Path) -> None:
    # Anchor the current directory inside the private tree before chrooting so
    # no pre-jail cwd can provide a relative-path escape after the UID drop.
    os.chdir(jail_root)
    os.chroot(".")
    os.chdir(JAIL_ROOT)
    _verify_procfs(PROCFS_TARGET)
    for component in JAIL_FORBIDDEN_PATH_COMPONENTS:
        forbidden = JAIL_ROOT / component
        if forbidden.exists():
            raise RuntimeError(f"unexpected host path remains reachable in jail: {forbidden}")
    if sorted(path.name for path in JAIL_DEV.iterdir()) != ["null", "urandom"]:
        raise RuntimeError("jail exposes unexpected device entries")


def _unshare() -> None:
    if LIBC.unshare(ctypes.c_int(CLONE_NEWNS | CLONE_NEWPID)) != 0:
        error = ctypes.get_errno()
        if error in {errno.EPERM, errno.ENOSYS, errno.EINVAL}:
            raise NamespaceUnavailable(f"mount/PID namespace unavailable: {os.strerror(error)}")
        raise OSError(error, os.strerror(error))


def _set_no_new_privs() -> None:
    """Fail closed before candidate setup so setuid/file-cap binaries cannot elevate."""
    if LIBC.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, f"cannot set no_new_privs: {os.strerror(error)}")


def _candidate_environment(
    source: Path,
    framework_relative: Path,
    external: Path,
    guard: Path,
    python: Path,
    compiler: Path,
    cxx_compiler: Path,
) -> dict[str, str]:
    root = external
    return {
        "PATH": SAFE_PATH, "PYTHON": str(python), "CC": str(compiler), "CXX": str(cxx_compiler), "HOME": str(root / "home"),
        "TMPDIR": str(root / "tmp"), "TMP": str(root / "tmp"), "TEMP": str(root / "tmp"),
        "XDG_CACHE_HOME": str(root / "xdg-cache"), "XDG_CONFIG_HOME": str(root / "xdg-config"),
        "XDG_DATA_HOME": str(root / "xdg-data"), "XDG_STATE_HOME": str(root / "xdg-state"),
        "PIP_CACHE_DIR": str(root / "pip-cache"), "PYTHONPYCACHEPREFIX": str(root / "pycache"),
        "PYTHONUSERBASE": str(root / "python-user-base"), "PYTHONPATH": str(root / "python-packages"),
        "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1", "GIT_CONFIG_GLOBAL": str(root / "gitconfig"),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0", "GITHUB_ACTIONS": "true",
        "GITHUB_WORKSPACE": str(source),
        "FRAMEWORK_ROOT": str(source / framework_relative), "VALIDATOR_EXTERNAL_ROOT": str(root),
        "BUILD_ROOT": str(root / "build"),
        "APACHE_C_STANDARDS_OUT": str(root / "build/apache-c-standards"),
        "VALIDATION_WRITE_ROOT": str(guard), "VERIFIED_RUN_ROOT": str(root / "verified-run"),
        "VERIFIED_STATE_ROOT": str(root / "verified-run/state"), "VERIFIED_BUILD_ROOT": str(root / "verified-run/build"),
        "VERIFIED_SOURCE_ROOT": str(root / "verified-run/source"), "VERIFIED_TMP_ROOT": str(root / "verified-run/tmp"),
        "VERIFIED_LOG_ROOT": str(root / "verified-run/log"), "CACHE_ROOT": str(root / "cache"),
        "VERIFIED_COMPONENT_CACHE": str(root / "cache/shared"), "CONNECTOR_COMPONENT_CACHE": str(root / "cache/components"),
        "VERIFIED_EVIDENCE_ROOT": str(root / "evidence"), "EVIDENCE_ROOT": str(root / "evidence/no-crs"),
        "RUNTIME_EVIDENCE_ROOT": str(root / "evidence/runtime"), "RUNTIME_RUN_ROOT": str(root / "runtime"),
        "RUNTIME_LOG_ROOT": str(root / "runtime-log"), "SOURCE_ROOT": str(root / "source"),
        "TMP_ROOT": str(root / "tmp-root"), "LOG_ROOT": str(root / "log"), "MATRIX_ROOT": str(root / "matrix"),
    }


def _candidate_script() -> str:
    """Return the fixed, unprivileged candidate program; never accept source input."""
    return (
        'umask 077\n'
        'test "$(id -un)" = "modsecurity-validator"\n'
        'test "$PWD" = "$GITHUB_WORKSPACE"\n'
        'cap_eff=""; no_new_privs=""\n'
        'while IFS=$\'\\t \' read -r label value; do\n'
        '  case "$label" in CapEff:) cap_eff="$value" ;; NoNewPrivs:) no_new_privs="$value" ;; esac\n'
        'done < /proc/self/status\n'
        'test "$cap_eff" = 0000000000000000\n'
        'test "$no_new_privs" = 1\n'
        'for target in /tmp /var /home /root /run /sys /dev/shm; do test ! -e "$target"; done\n'
        'test -x "$CC"; test -x "$CXX"\n'
        'test -c /dev/null; test -c /dev/urandom; test ! -w /dev\n'
        'for device in /dev/*; do case "${device##*/}" in null|urandom) ;; *) echo "validator sees an unexpected device: $device" >&2; exit 1 ;; esac; done\n'
        'for descriptor in /proc/self/fd/*; do test -e "$descriptor" || continue; case "${descriptor##*/}" in 0|1|2) ;; *) echo "validator retained an inherited descriptor: $descriptor" >&2; exit 1 ;; esac; done\n'
        'test ! -w "$VALIDATION_WRITE_ROOT"; test ! -w "$GITHUB_WORKSPACE"; test ! -w "$GITHUB_WORKSPACE/.git"\n'
        'test ! -w "$GITHUB_WORKSPACE/.git/modules"; test ! -w "$FRAMEWORK_ROOT"; test ! -w "$FRAMEWORK_ROOT/.git"\n'
        'expect_blocked() { if "$@"; then echo "validator changed a protected path: $*" >&2; exit 1; fi; }\n'
        'for target in "$GITHUB_WORKSPACE/.readonly-validator-write-probe" "$FRAMEWORK_ROOT/.readonly-validator-write-probe" "$GITHUB_WORKSPACE/.git/index.lock" "$FRAMEWORK_ROOT/.git/index.lock" "$VALIDATION_WRITE_ROOT/.readonly-validator-guard-probe" "/dev/.readonly-validator-device-probe" "/dev/shm/.readonly-validator-device-probe"; do expect_blocked touch "$target"; done\n'
        'for target in "$GITHUB_WORKSPACE/Makefile" "$FRAMEWORK_ROOT/Makefile" "$GITHUB_WORKSPACE/.git" "$FRAMEWORK_ROOT/.git"; do expect_blocked chmod 600 "$target"; done\n'
        'expect_blocked mv "$GITHUB_WORKSPACE/Makefile" "$GITHUB_WORKSPACE/.readonly-validator-rename-probe"\n'
        'expect_blocked mv "$FRAMEWORK_ROOT/Makefile" "$FRAMEWORK_ROOT/.readonly-validator-rename-probe"\n'
        'expect_blocked mv "$GITHUB_WORKSPACE/.git" "$GITHUB_WORKSPACE/.readonly-validator-git-rename-probe"\n'
        'expect_blocked mv "$FRAMEWORK_ROOT/.git" "$FRAMEWORK_ROOT/.readonly-validator-git-rename-probe"\n'
        'for target in "$GITHUB_WORKSPACE/Makefile" "$FRAMEWORK_ROOT/Makefile"; do expect_blocked rm "$target"; done\n'
        'python_runtime_bin=$(dirname "$PYTHON")\n'
        'expect_blocked touch "$python_runtime_bin/.readonly-validator-runtime-write-probe"\n'
        'expect_blocked mkdir "$python_runtime_bin/.readonly-validator-runtime-directory-probe"\n'
        'expect_blocked chmod 600 "$PYTHON"\n'
        'expect_blocked mv "$PYTHON" "$python_runtime_bin/.readonly-validator-runtime-rename-probe"\n'
        'if sudo -n true >/dev/null 2>&1 || /usr/bin/sudo -n true >/dev/null 2>&1; then echo "validator obtained sudo" >&2; exit 1; fi\n'
        'if /usr/bin/mount -o remount,rw "$GITHUB_WORKSPACE" >/dev/null 2>&1; then echo "validator remounted source" >&2; exit 1; fi\n'
        'mkdir -p "$HOME" "$TMPDIR" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" '
        '"$XDG_STATE_HOME" "$PIP_CACHE_DIR" "$PYTHONPYCACHEPREFIX" "$PYTHONUSERBASE" '
        '"$PYTHONPATH" "$VERIFIED_RUN_ROOT" "$VERIFIED_STATE_ROOT" "$VERIFIED_BUILD_ROOT" '
        '"$VERIFIED_SOURCE_ROOT" "$VERIFIED_TMP_ROOT" "$VERIFIED_LOG_ROOT" "$CACHE_ROOT" '
        '"$VERIFIED_COMPONENT_CACHE" "$CONNECTOR_COMPONENT_CACHE" "$VERIFIED_EVIDENCE_ROOT" '
        '"$EVIDENCE_ROOT" "$RUNTIME_EVIDENCE_ROOT" "$RUNTIME_RUN_ROOT" "$RUNTIME_LOG_ROOT" '
        '"$SOURCE_ROOT" "$TMP_ROOT" "$LOG_ROOT" "$MATRIX_ROOT" "$BUILD_ROOT"\n'
        'git config --global --add safe.directory "$GITHUB_WORKSPACE"\n'
        'git config --global --add safe.directory "$FRAMEWORK_ROOT"\n'
        'touch "$VALIDATOR_EXTERNAL_ROOT/write-probe"; test -f "$VALIDATOR_EXTERNAL_ROOT/write-probe"\n'
        '"$PYTHON" -I -c "import yaml; assert not yaml.__with_libyaml__"\n'
        'exec make PYTHON="$PYTHON" quick-check'
    )


def _candidate_pid1(source: Path, framework_relative: Path, external: Path, guard: Path, python: Path, uid: int, gid: int) -> None:
    compiler = _fixed_runtime_executable(JAIL_C_COMPILER, "C compiler")
    cxx_compiler = _fixed_runtime_executable(JAIL_CXX_COMPILER, "C++ compiler")
    env = _candidate_environment(source, framework_relative, external, guard, python, compiler, cxx_compiler)
    os.setgroups([]); os.setgid(gid); os.setuid(uid); os.chdir(source)
    os.execve("/bin/bash", ["bash", "--noprofile", "--norc", "-ceu", _candidate_script()], env)


def _run_pid1_candidate(
    candidate_arguments: CandidateArguments,
    candidate_entry: CandidateEntry,
    proc_ready: tuple[int, int],
    layout: JailLayout,
) -> None:
    proc_ready_read, proc_ready_write = proc_ready
    os.close(proc_ready_read)
    try:
        _mount("proc", layout.proc, MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, "proc")
        _verify_procfs(layout.proc)
        _enter_jail(layout.root)
        _replace_standard_input()
        _close_unapproved_descriptors({0, 1, 2, proc_ready_write})
        os.write(proc_ready_write, b"1")
        os.close(proc_ready_write)
        _set_no_new_privs()
        candidate_entry(*candidate_arguments)
    except Exception as error:
        print(f"readonly namespace candidate setup failed: {error}", file=sys.stderr)
        try:
            os.close(proc_ready_write)
        except OSError:
            pass
        os._exit(127)


def _namespace_child(
    source: Path,
    framework: Path,
    external: Path,
    mount_root: Path,
    python: Path,
    uid: int,
    gid: int,
    candidate_entry: CandidateEntry = _candidate_pid1,
) -> int:
    _unshare()
    _mount(None, Path("/"), MS_REC | MS_PRIVATE)
    layout = _build_jail_layout(mount_root, source, external, python)
    framework_relative = framework.relative_to(source)
    proc_ready_read, proc_ready_write = os.pipe()
    child = os.fork()
    if child == 0:
        _run_pid1_candidate(
            (JAIL_SOURCE, framework_relative, JAIL_EXTERNAL, JAIL_GUARD, python, uid, gid),
            candidate_entry,
            (proc_ready_read, proc_ready_write),
            layout,
    )
    os.close(proc_ready_write)
    proc_ready = os.read(proc_ready_read, 1) == b"1"
    os.close(proc_ready_read)
    try:
        _pid, status = os.waitpid(child, 0)
    finally:
        _teardown_jail_layout(layout)
    if not proc_ready and os.waitstatus_to_exitcode(status) == 0:
        raise RuntimeError("namespace candidate exited before jailed procfs readiness")
    return os.waitstatus_to_exitcode(status)


def _validated_configuration(arguments: argparse.Namespace) -> tuple[Path, Path, Path, Path, Path, Path, int, int]:
    source = _absolute_existing_directory(arguments.source_root, "source root")
    framework = _absolute_existing_directory(arguments.framework_root, "framework root")
    write_root = _absolute_existing_directory(arguments.write_root, "write root")
    external = _absolute_existing_directory(arguments.external_root, "external root")
    _strict_child(framework, source, "framework root")
    _disjoint(source, write_root, "source root", "write root")
    _reject_nested_source_mounts(source)
    if external != write_root / "external":
        raise ValueError("external root must be exactly the write root external child")
    namespace_parent = _absolute_existing_directory(arguments.namespace_parent, "namespace parent")
    requested_python = Path(arguments.python)
    if not requested_python.is_absolute() or not requested_python.is_file() or not os.access(requested_python, os.X_OK):
        raise ValueError("python must be an executable absolute path")
    python = requested_python.resolve(strict=True)
    if not python.is_file() or not os.access(python, os.X_OK):
        raise ValueError("python must resolve to an executable regular file")
    uid, gid = _identity(arguments.validator_user, arguments.validator_group)
    _validate_namespace_parent(namespace_parent, gid)
    write_metadata = os.stat(write_root, follow_symlinks=False)
    external_metadata = os.stat(external, follow_symlinks=False)
    if write_metadata.st_uid != 0 or write_metadata.st_gid != 0 or stat.S_IMODE(write_metadata.st_mode) != 0o711:
        raise ValueError("write root must be root-owned mode 0711")
    if (external_metadata.st_uid, external_metadata.st_gid, stat.S_IMODE(external_metadata.st_mode)) != (uid, gid, 0o700):
        raise ValueError("external root must be validator-owned mode 0700")
    return source, framework, write_root, external, namespace_parent, python, uid, gid


def _cleanup_partial_mount_layout(mount_root: Path) -> None:
    """Remove exact empty placeholders only after confirming no host mount remains."""
    if _mountinfo_for(mount_root):
        return
    for path in (mount_root / "source", mount_root / "external", mount_root):
        if path.exists():
            os.rmdir(path)


def run(arguments: argparse.Namespace) -> int:
    if os.name != "posix" or sys.platform != "linux" or os.geteuid() != 0:
        raise NamespaceUnavailable("readonly namespace runner requires Linux root")
    source, framework, _write_root, external, namespace_parent, python, uid, gid = _validated_configuration(arguments)
    # The layout creator can fail after making one or two deterministic
    # placeholders.  Keep the exact expected child available to finally so
    # that no private namespace residue survives a setup failure.
    mount_root = namespace_parent / "mount-root"
    try:
        created_mount_root = _create_mount_layout(namespace_parent, gid)
        if created_mount_root != mount_root:
            raise RuntimeError("namespace layout returned an unexpected mount root")
        before = _mountinfo_for(mount_root)
        child = os.fork()
        if child == 0:
            try: os._exit(_namespace_child(source, framework, external, mount_root, python, uid, gid))
            except NamespaceUnavailable as error: print(str(error), file=sys.stderr); os._exit(125)
            except Exception as error: print(f"readonly namespace setup failed: {error}", file=sys.stderr); os._exit(126)
        _pid, status = os.waitpid(child, 0)
        code = os.waitstatus_to_exitcode(status)
        if _mountinfo_for(mount_root) != before:
            raise RuntimeError("namespace runner leaked a host mount")
        if code == 0:
            print("READONLY_SUBMODULE_VALIDATION_NAMESPACE_COMPLETE")
        return code
    finally:
        # The bind mounts live only in the child mount namespace.  Do not use a
        # recursive cleanup: these are exact, trusted empty placeholders. This
        # also handles a partial _create_mount_layout() failure before fork.
        _cleanup_partial_mount_layout(mount_root)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return run(parse_args(sys.argv[1:] if argv is None else argv))
    except (ValueError, OSError, RuntimeError) as error:
        print(f"readonly namespace validation blocked: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
