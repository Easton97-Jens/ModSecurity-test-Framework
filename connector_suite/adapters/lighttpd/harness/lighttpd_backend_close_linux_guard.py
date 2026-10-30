#!/usr/bin/env python3
"""Linux-only identity, pidfd, and listener guards for the close harness."""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
import errno
import json
import os
from pathlib import Path
import resource
import re
import signal
import stat
import sys
import time
from typing import TextIO


class GuardFailure(RuntimeError):
    """A process or listener cannot be safely attributed to this harness."""


class PidfdTargetExited(GuardFailure):
    """The pidfd target died or became a zombie before a pidfd was acquired."""


PIDFD_TARGET_EXIT_STATUS = 75


@dataclass(frozen=True)
class RegisteredSession:
    leader_pid: int
    leader_start_time: str
    session_id: int
    process_group: int


@dataclass
class OpenSessionMember:
    pid: int
    start_time: str
    session_id: int
    process_group: int
    pidfd: int


@dataclass(frozen=True)
class LeaderAnchor:
    is_live: bool
    is_registered_member: bool


MAX_PROC_SCAN_ENTRIES = 4096
MAX_SESSION_MEMBERS = 256
MAX_TASK_FD_ENTRIES = 4096
MAX_GUARD_ERRORS = 16
MAX_GUARD_ERROR_TEXT = 192
MAX_GUARD_ERROR_SUMMARY = 1024
MAX_RECORDED_MEMBER_IDS = 512
MAX_KILL_RESCANS = 64
MAX_SESSION_WAIT_RESCANS = 1024
MAX_SESSION_ABSENCE_RESCANS = 1024
MAX_ABORT_EVENT_RESCANS = 1024
MAX_RUNTIME_TREE_ENTRIES = 4096
MAX_RUNTIME_TREE_DEPTH = 32
MAX_JSON_FIELDS = 32
MAX_JSON_FIELD_BYTES = 4096
MAX_JSON_OUTPUT_BYTES = 65536
MAX_TCP_LISTENER_LINES = 4096
MAX_TCP_LISTENER_LINE_BYTES = 4096
_ERROR_OVERFLOW = "additional task-guard errors suppressed"
_PIDFD_UNAVAILABLE = "Linux pidfd capability is unavailable or unusable"
_SIGNAL_MEMBER_LIMIT = "bounded recorded task-member signal limit exceeded"
_INVENTORY_MEMBER_LIMIT = "bounded recorded task-member inventory limit exceeded"
MIN_BACKEND_READ_TIMEOUT_SECONDS = 1
MAX_BACKEND_READ_TIMEOUT_SECONDS = 30
TRUSTED_RUNTIME_ROOT_ENV = "MSCONNECTOR_TRUSTED_RUNTIME_ROOT"
SESSION_ENV_PREFIX = "MSCONNECTOR_LIGHTTPD_SESSION_"
SESSION_PROFILE_ENV = f"{SESSION_ENV_PREFIX}PROFILE"
SESSION_EXECUTABLE_ENV = f"{SESSION_ENV_PREFIX}EXECUTABLE"
SESSION_MODULE_DIR_ENV = f"{SESSION_ENV_PREFIX}MODULE_DIR"
SESSION_CONFIG_ENV = f"{SESSION_ENV_PREFIX}CONFIG"
SESSION_DURATION_ENV = f"{SESSION_ENV_PREFIX}DURATION"
SESSION_FRONTEND_PORT_ENV = f"{SESSION_ENV_PREFIX}FRONTEND_PORT"
SESSION_UPSTREAM_PORT_ENV = f"{SESSION_ENV_PREFIX}UPSTREAM_PORT"
SESSION_READY_ENV = f"{SESSION_ENV_PREFIX}READY"
SESSION_RELEASE_ENV = f"{SESSION_ENV_PREFIX}RELEASE"
SESSION_RUNTIME_ROOT_ENV = f"{SESSION_ENV_PREFIX}RUNTIME_ROOT"
SESSION_RECEIPT_ENV = f"{SESSION_ENV_PREFIX}RECEIPT"
SESSION_TIMEOUT_ENV = f"{SESSION_ENV_PREFIX}TIMEOUT"
SESSION_PARENT_PID_ENV = f"{SESSION_ENV_PREFIX}PARENT_PID"
MAX_SESSION_VALUE_BYTES = 8192


def _trusted_runtime_root() -> Path:
    """Return the mandatory, private runtime root established by the harness."""

    configured_root = os.environ.get(TRUSTED_RUNTIME_ROOT_ENV)
    if not configured_root:
        raise GuardFailure("trusted runtime root is required for artifact access")
    trusted_root = Path(configured_root)
    if not trusted_root.is_absolute() or ".." in trusted_root.parts or "." in trusted_root.parts:
        raise GuardFailure("trusted runtime root must be absolute and traversal-free")
    try:
        resolved_root = trusted_root.resolve(strict=True)
        root_info = os.lstat(resolved_root)
    except OSError as exc:
        raise GuardFailure("trusted runtime root cannot be inspected") from exc
    if trusted_root != resolved_root:
        raise GuardFailure("trusted runtime root must not contain symbolic links")
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or stat.S_ISLNK(root_info.st_mode)
        or root_info.st_mode & 0o077
        or root_info.st_uid != os.geteuid()
    ):
        raise GuardFailure("trusted runtime root must be a private runner-owned directory")
    return trusted_root


def _private_artifact_path(path: Path) -> Path:
    """Validate a task-owned artifact path before any filesystem operation.

    Callers establish the immediate parent as the trusted, private task root.
    Traversal and symlinks are rejected before descriptor-relative access.
    """

    if (
        not path.is_absolute()
        or path.name in ("", ".", "..")
        or ".." in path.parts
        or any(part in ("", ".") for part in path.parts[1:])
    ):
        raise GuardFailure("task artifact path must be absolute and have a filename")
    try:
        resolved_parent = path.parent.resolve(strict=True)
        resolved_path = path.resolve(strict=False)
        parent_info = os.lstat(resolved_parent)
        parent_mode = parent_info.st_mode
        target_mode = os.lstat(resolved_path)
    except FileNotFoundError:
        target_mode = None
        try:
            resolved_parent = path.parent.resolve(strict=True)
            parent_info = os.lstat(resolved_parent)
            parent_mode = parent_info.st_mode
        except OSError as exc:
            raise GuardFailure("task artifact parent cannot be inspected") from exc
    except OSError as exc:
        raise GuardFailure("task artifact path cannot be inspected") from exc
    if resolved_path != path:
        raise GuardFailure("task artifact path must remain inside its trusted real directory")
    trusted_root = _trusted_runtime_root()
    try:
        resolved_path.relative_to(trusted_root)
    except ValueError as exc:
        raise GuardFailure("artifact path is outside the trusted runtime root") from exc
    if (
        not stat.S_ISDIR(parent_mode)
        or stat.S_ISLNK(parent_mode)
        or parent_mode & 0o077
        or parent_info.st_uid != os.geteuid()
    ):
        raise GuardFailure("task artifact parent must be a private runner-owned directory")
    if target_mode is not None and stat.S_ISLNK(target_mode.st_mode):
        raise GuardFailure("task artifact must not be a symbolic link")
    return path


def _nofollow_open_flag() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(nofollow, int):
        raise GuardFailure("safe artifact opens are unavailable")
    return nofollow


def _directory_open_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", None)
    if not isinstance(directory, int):
        raise GuardFailure("safe directory traversal flags are unavailable")
    return os.O_RDONLY | directory | _nofollow_open_flag()


def _open_directory_chain(directory: Path, *, final_private: bool = True) -> int:
    """Open an absolute directory path without pathname-based ancestor races."""

    if not directory.is_absolute() or ".." in directory.parts or any(
        part in ("", ".") for part in directory.parts[1:]
    ):
        raise GuardFailure("task directory path must be absolute and traversal-free")
    flags = _directory_open_flags()
    current_fd = os.open("/", flags)
    try:
        components = directory.parts[1:]
        for index, component in enumerate(components):
            child_fd = os.open(component, flags, dir_fd=current_fd)
            try:
                metadata = os.fstat(child_fd)
                mode = metadata.st_mode
                is_final = index == len(components) - 1
                shared_anchor = (
                    not is_final
                    and metadata.st_uid == 0
                    and stat.S_ISDIR(mode)
                    and bool(mode & stat.S_ISVTX)
                    and bool(mode & 0o022)
                )
                if (
                    not stat.S_ISDIR(mode)
                    or metadata.st_uid not in (0, os.geteuid())
                    or (mode & 0o022 and not shared_anchor)
                    or final_private and is_final and (
                        metadata.st_uid != os.geteuid() or mode & 0o077
                    )
                ):
                    raise GuardFailure("task directory must be a private runner-owned directory")
            except Exception:
                os.close(child_fd)
                raise
            os.close(current_fd)
            current_fd = child_fd
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


def _open_trusted_root() -> int:
    trusted_root = _trusted_runtime_root()
    try:
        return _open_directory_chain(trusted_root, final_private=True)
    except FileNotFoundError as exc:
        raise GuardFailure("trusted runtime root cannot be opened safely") from exc


def _read_private_artifact(path: Path, maximum_bytes: int, description: str) -> bytes:
    """Read a bounded artifact through a validated, symlink-free directory fd."""

    if not 1 <= maximum_bytes <= 65536:
        raise GuardFailure("artifact inspection limit is invalid")
    safe_path = _private_artifact_path(path)
    nonblocking = getattr(os, "O_NONBLOCK", None)
    if nonblocking is None:
        raise GuardFailure("nonblocking artifact reads are unavailable")
    parent_fd = -1
    descriptor = -1
    try:
        parent_fd = _open_directory_chain(safe_path.parent, final_private=True)
        descriptor = os.open(
            safe_path.name,
            os.O_RDONLY
            | _nofollow_open_flag()
            | nonblocking,
            dir_fd=parent_fd,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
        ):
            raise GuardFailure(f"{description} is not a private regular task artifact")
        if metadata.st_size > maximum_bytes:
            raise GuardFailure(f"{description} exceeds its bounded inspection limit")
        with os.fdopen(descriptor, "rb") as input_file:
            descriptor = -1
            payload = input_file.read(maximum_bytes + 1)
            if len(payload) > maximum_bytes:
                raise GuardFailure(f"{description} exceeds its bounded inspection limit")
            return payload
    except FileNotFoundError:
        # assert_abort_event deliberately polls for an asynchronously-created
        # error log. Preserve this signal instead of converting it to a
        # generic guard failure.
        raise
    except OSError as exc:
        raise GuardFailure(f"cannot safely read {description}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)


def _proc_stat_path(pid: int) -> Path:
    if type(pid) is not int or not 1 <= pid <= 4_000_000_000:
        raise GuardFailure("process ID is outside the bounded Linux range")
    return Path("/proc") / str(pid) / "stat"


def _bounded_error_text(value: object) -> str:
    message = str(value)
    if len(message) > MAX_GUARD_ERROR_TEXT:
        return message[: MAX_GUARD_ERROR_TEXT - 3] + "..."
    return message


def _append_error(errors: list[str], value: object) -> None:
    """Retain bounded, deduplicated diagnostics without unbounded error text."""

    message = _bounded_error_text(value)
    if message in errors:
        return
    if len(errors) < MAX_GUARD_ERRORS:
        errors.append(message)
        return
    overflow_marker = _bounded_error_text(_ERROR_OVERFLOW)
    if errors and errors[-1] != overflow_marker:
        errors[-1] = overflow_marker


def _append_member_ids(
    destination: list[int],
    additions: list[int],
    errors: list[str],
    overflow_message: str,
) -> None:
    """Keep task-member receipts bounded while preserving fail-closed evidence."""

    for member_pid in additions:
        if member_pid in destination:
            continue
        if len(destination) >= MAX_RECORDED_MEMBER_IDS:
            _append_error(errors, overflow_message)
            return
        destination.append(member_pid)


def _error_summary(errors: list[str]) -> str:
    """Return a bounded error aggregate suitable for a fail-closed receipt."""

    summary = "; ".join(errors[:MAX_GUARD_ERRORS])
    if len(summary) > MAX_GUARD_ERROR_SUMMARY:
        return summary[: MAX_GUARD_ERROR_SUMMARY - 3] + "..."
    return summary


def _require_pidfd() -> None:
    if sys.platform != "linux" or not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise GuardFailure("Linux os.pidfd_open and signal.pidfd_send_signal are required")
    self_pid = os.getpid()
    try:
        pidfd = os.pidfd_open(self_pid, 0)
    except OSError as exc:
        raise GuardFailure(_PIDFD_UNAVAILABLE) from exc
    try:
        _pidfd_matches_pid(pidfd, self_pid)
        # Signal 0 verifies the pidfd-backed signal path without changing state.
        signal.pidfd_send_signal(pidfd, 0)
    except (GuardFailure, OSError, TypeError) as exc:
        try:
            os.close(pidfd)
        except OSError:
            pass
        raise GuardFailure(_PIDFD_UNAVAILABLE) from exc
    try:
        os.close(pidfd)
    except OSError as exc:
        raise GuardFailure(_PIDFD_UNAVAILABLE) from exc


def _write_new(path: Path, payload: bytes) -> None:
    path = _private_artifact_path(path)
    if not hasattr(os, "O_NOFOLLOW"):
        raise GuardFailure("safe artifact opens are unavailable")
    parent_fd = -1
    descriptor = -1
    try:
        parent_fd = _open_directory_chain(path.parent, final_private=True)
        descriptor = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(payload)
    except OSError as exc:
        raise GuardFailure("cannot safely create a no-overwrite task artifact") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)


def _lighttpd_string(path: str) -> str:
    if not path.startswith("/") or any(character in path for character in ("\x00", "\r", "\n")):
        raise GuardFailure("lighttpd config path is unsafe")
    return path.replace("\\", "\\\\").replace('"', '\\"')


def _runtime_config_path(path: str) -> str:
    if not path.startswith("/") or any(character in path for character in ("\x00", "\r", "\n", "=", "#", ";")):
        raise GuardFailure("runtime config path is unsafe")
    return path


def write_config(
    root: Path,
    rules_file: str,
    frontend_port: int,
    upstream_port: int,
    backend_read_timeout: int | None = None,
) -> None:
    trusted_root = _trusted_runtime_root()
    if root != trusted_root:
        raise GuardFailure("runtime config root must be the trusted runtime root")
    root = trusted_root
    if not 1024 <= frontend_port <= 65535 or not 1024 <= upstream_port <= 65535:
        raise GuardFailure("ports must be unprivileged")
    if backend_read_timeout is not None and (
        type(backend_read_timeout) is not int
        or not MIN_BACKEND_READ_TIMEOUT_SECONDS <= backend_read_timeout <= MAX_BACKEND_READ_TIMEOUT_SECONDS
    ):
        raise GuardFailure("backend read timeout must be an integer between 1 and 30 seconds")
    document_root = root / "document-root"
    upload_root = root / "upload"
    document_root.mkdir(mode=0o700)
    upload_root.mkdir(mode=0o700)
    runtime_config = root / "msconnector-runtime.conf"
    lighttpd_config = root / "lighttpd.conf"
    event_path = root / "events.jsonl"
    error_log = root / "lighttpd-error.log"
    pid_file = root / "lighttpd.pid"
    escaped = {name: _lighttpd_string(str(path)) for name, path in {
        "document_root": document_root,
        "upload_root": upload_root,
        "runtime_config": runtime_config,
        "event_path": event_path,
        "error_log": error_log,
        "pid_file": pid_file,
    }.items()}
    rules = _runtime_config_path(rules_file)
    runtime_event_path = _runtime_config_path(str(event_path))
    backend_read_timeout_setting = (
        f', "read-timeout" => {backend_read_timeout}' if backend_read_timeout is not None else ""
    )
    _write_new(
        runtime_config,
        (
            "enabled=on\n"
            f"rules_file={rules}\n"
            "transaction_id_header=x-modsec-transaction-id\n"
            "request_body_mode=none\n"
            "response_body_mode=streaming\n"
            "default_block_status=403\n"
            "default_error_status=500\n"
            "max_header_count=256\n"
            "max_header_name_size=256\n"
            "max_header_value_size=8192\n"
            "max_total_header_bytes=65536\n"
            "max_event_json_bytes=16384\n"
            f"event_path={runtime_event_path}\n"
        ).encode("utf-8"),
    )
    _write_new(
        lighttpd_config,
        (
            'server.compat-module-load = "disable"\n'
            'server.modules = ( "mod_proxy", "mod_msconnector" )\n'
            'server.stream-response-body = 1\n'
            f'server.document-root = "{escaped["document_root"]}"\n'
            'server.bind = "127.0.0.1"\n'
            f"server.port = {frontend_port}\n"
            f'server.errorlog = "{escaped["error_log"]}"\n'
            f'server.pid-file = "{escaped["pid_file"]}"\n'
            f'server.upload-dirs = ( "{escaped["upload_root"]}" )\n'
            'msconnector.enabled = "enable"\n'
            f'msconnector.config-file = "{escaped["runtime_config"]}"\n'
            'msconnector.expose-host-transaction-id = "enable"\n'
            "proxy.server = (\n"
            f'  "/p4/close/" => ( ( "host" => "127.0.0.1", "port" => {upstream_port}'
            f"{backend_read_timeout_setting} ) )\n"
            ")\n"
        ).encode("utf-8"),
    )


def _session_fields(pid: int) -> tuple[int, int]:
    try:
        stat_data = _proc_stat_path(pid).read_text(encoding="ascii")
        after_comm = stat_data.rsplit(")", 1)[1].split()
        return int(after_comm[2]), int(after_comm[3])
    except (OSError, IndexError, ValueError) as exc:
        raise GuardFailure(f"cannot parse /proc/{pid}/stat session fields") from exc


def _scan_session_entry(
    entry: Path,
    session_id: int,
    members: list[int],
    errors: list[str],
) -> None:
    if not entry.name.isdigit():
        return
    try:
        _pgrp, member_session = _session_fields(int(entry.name))
    except GuardFailure as exc:
        try:
            os.lstat(entry)
        except FileNotFoundError:
            # The process exited while the scan was in flight; it cannot be
            # signalled and does not make membership ambiguous.
            return
        except OSError as inspect_exc:
            _append_error(errors, f"cannot revalidate /proc/{entry.name}: {inspect_exc}")
            return
        _append_error(errors, exc)
        return
    if member_session != session_id:
        return
    if len(members) >= MAX_SESSION_MEMBERS:
        _append_error(errors, "bounded task-session member limit exceeded")
        return
    members.append(int(entry.name))


def _scan_session_members(session_id: int) -> tuple[list[int], list[str]]:
    """Return observable session members and every non-disappearance read failure.

    A `/proc` entry may disappear between directory enumeration and stat parsing.
    That one race is harmless.  Every other parse or inspection failure is retained
    so callers can fail closed after attempting containment of the members that
    were still provably in the registered task session.
    """

    members: list[int] = []
    errors: list[str] = []
    try:
        entries = Path("/proc").iterdir()
    except OSError:
        _append_error(errors, "cannot enumerate /proc for task session containment")
        return members, errors
    scanned_entries = 0
    try:
        for entry in entries:
            scanned_entries += 1
            if scanned_entries > MAX_PROC_SCAN_ENTRIES:
                _append_error(errors, "bounded /proc task-session scan limit exceeded")
                break
            _scan_session_entry(entry, session_id, members, errors)
    except OSError:
        _append_error(errors, "cannot continue /proc task-session enumeration")
    return sorted(members), errors


def _session_members(session_id: int, strict: bool = False) -> list[int]:
    members, errors = _scan_session_members(session_id)
    if strict and errors:
        raise GuardFailure("cannot fully inspect task session membership: " + _error_summary(errors))
    return members


def _process_state(pid: int) -> str | None:
    try:
        stat_data = _proc_stat_path(pid).read_text(encoding="ascii")
    except OSError as exc:
        # Enumeration and the state read are separate operations. ENOENT and
        # ESRCH are the expected process-exit races; all other read failures
        # remain fail-closed and are reported to the caller.
        if exc.errno in (errno.ENOENT, errno.ESRCH):
            return None
        raise GuardFailure(
            f"cannot read /proc/{pid}/stat process state (errno={exc.errno} {exc.strerror})"
        ) from exc
    try:
        return stat_data.rsplit(")", 1)[1].split()[0]
    except (IndexError, UnicodeError) as exc:
        raise GuardFailure(f"cannot parse /proc/{pid}/stat process state") from exc


def _active_member_ids(member_pids: list[int]) -> tuple[list[int], list[str]]:
    """Filter one membership snapshot to active PIDs without hiding errors."""

    active: list[int] = []
    errors: list[str] = []
    for member_pid in member_pids:
        try:
            state = _process_state(member_pid)
        except GuardFailure as exc:
            _append_error(errors, exc)
            # An uninspectable member must not be mistaken for a clean exit.
            active.append(member_pid)
            continue
        if state not in (None, "Z"):
            active.append(member_pid)
    return active, errors


def _active_session_members(session_id: int) -> tuple[list[int], list[str]]:
    members, errors = _scan_session_members(session_id)
    active, state_errors = _active_member_ids(members)
    _add_errors(errors, state_errors)
    return active, errors


def _append_unexpected_members(
    destination: list[int],
    additions: list[int],
    leader_pid: int,
    errors: list[str],
) -> None:
    """Record only active non-leader session members as cleanup surprises."""

    _append_member_ids(
        destination,
        [member_pid for member_pid in additions if member_pid != leader_pid],
        errors,
        _INVENTORY_MEMBER_LIMIT,
    )


def _task_fd_entries(pid: int) -> list[Path]:
    entries: list[Path] = []
    try:
        for entry in Path(f"/proc/{pid}/fd").iterdir():
            if len(entries) >= MAX_TASK_FD_ENTRIES:
                raise GuardFailure("bounded task process FD inspection limit exceeded")
            entries.append(entry)
    except OSError as exc:
        raise GuardFailure("cannot inspect process file descriptors") from exc
    return entries


def assert_singleton_session(pid: int, expected_start: str, expected_exe: str) -> dict[str, object]:
    pidfd = _pidfd_for_identity(pid, expected_start, expected_exe)
    try:
        process_group, session_id = _session_fields(pid)
        if process_group != pid or session_id != pid:
            raise GuardFailure("task host is not its own session and process-group leader")
        members = _session_members(session_id, strict=True)
        if members != [pid]:
            raise GuardFailure("task session contains unexpected processes")
        fd_count = len(_task_fd_entries(pid))
        _validate_identity(pid, expected_start, expected_exe)
        return {"session_id": session_id, "members": members, "fd_count": fd_count}
    finally:
        os.close(pidfd)


def assert_session_absent(session_id: int, wait_seconds: float = 0.0) -> None:
    if not 0.0 <= wait_seconds <= 30.0:
        raise GuardFailure("session-absence wait bound is invalid")
    deadline = time.monotonic() + wait_seconds
    for _rescan_number in range(MAX_SESSION_ABSENCE_RESCANS):
        members, errors = _active_session_members(session_id)
        if errors:
            raise GuardFailure("cannot fully inspect task session membership: " + _error_summary(errors))
        if not members:
            return
        if time.monotonic() >= deadline:
            raise GuardFailure("task session still contains processes")
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    raise GuardFailure("bounded task-session absence rescan limit exceeded")


def _scan_runtime_directory(
    parent_fd: int,
    depth: int,
    pending: list[tuple[int, int]],
    inspected: int,
) -> int:
    child_fds: list[int] = []
    entries = None
    try:
        entries = os.scandir(parent_fd)
        for entry in entries:
            inspected += 1
            if inspected > MAX_RUNTIME_TREE_ENTRIES:
                raise GuardFailure("task runtime tree exceeds its bounded entry limit")
            _scan_runtime_entry(parent_fd, depth, entry, pending, child_fds)
        entries.close()
        entries = None
    except Exception:
        _close_runtime_directory_resources(parent_fd, entries, child_fds, pending)
        raise
    os.close(parent_fd)
    return inspected


def _close_runtime_directory_resources(
    parent_fd: int,
    entries: os.ScandirIterator[str] | None,
    child_fds: list[int],
    pending: list[tuple[int, int]],
) -> None:
    """Close a failed directory scan without closing queued child descriptors."""

    if entries is not None:
        try:
            entries.close()
        except OSError:
            pass
    pending_fds = {item[0] for item in pending}
    for child_fd in child_fds:
        if child_fd not in pending_fds:
            os.close(child_fd)
    try:
        os.close(parent_fd)
    except OSError:
        pass


def _scan_runtime_entry(
    parent_fd: int,
    depth: int,
    entry: os.DirEntry[str],
    pending: list[tuple[int, int]],
    child_fds: list[int],
) -> None:
    """Inspect one runtime entry and enqueue private directories for scanning."""

    try:
        metadata = entry.stat(follow_symlinks=False)
    except OSError as exc:
        raise GuardFailure("cannot inspect task runtime tree entry") from exc
    if stat.S_ISSOCK(metadata.st_mode):
        raise GuardFailure("task runtime root retains a unix-domain socket")
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        return
    if depth >= MAX_RUNTIME_TREE_DEPTH:
        raise GuardFailure("task runtime tree exceeds its bounded depth limit")
    child_fd = _open_directory_chain_from_fd(parent_fd, entry.name)
    child_fds.append(child_fd)
    pending.append((child_fd, depth + 1))


def assert_no_unix_sockets(root: Path) -> None:
    trusted_root = _trusted_runtime_root()
    if root != trusted_root:
        raise GuardFailure("unix-socket root must be the trusted runtime root")
    root_fd = _open_trusted_root()
    pending: list[tuple[int, int]] = [(root_fd, 0)]
    inspected = 0
    try:
        while pending:
            parent_fd, depth = pending.pop()
            inspected = _scan_runtime_directory(parent_fd, depth, pending, inspected)
    finally:
        for descriptor, _depth in pending:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _open_directory_chain_from_fd(parent_fd: int, name: str) -> int:
    """Open a discovered child relative to its already-open parent."""

    if not name or name in (".", "..") or "/" in name or "\x00" in name:
        raise GuardFailure("runtime tree entry name is unsafe")
    flags = _directory_open_flags()
    child_fd = -1
    try:
        child_fd = os.open(name, flags, dir_fd=parent_fd)
        metadata = os.fstat(child_fd)
    except OSError as exc:
        if child_fd >= 0:
            os.close(child_fd)
        raise GuardFailure("cannot safely open runtime tree directory") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in (0, os.geteuid())
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        os.close(child_fd)
        raise GuardFailure("runtime tree directory is not private")
    return child_fd


def assert_private_artifact_contains(path: Path, marker: str, maximum_bytes: int) -> None:
    if not isinstance(marker, str) or not 1 <= len(marker) <= 256 or "\x00" in marker:
        raise GuardFailure("artifact marker is invalid")
    try:
        encoded_marker = marker.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise GuardFailure("artifact marker is not valid UTF-8") from exc
    payload = _read_private_artifact(path, maximum_bytes, "task artifact")
    if encoded_marker not in payload:
        raise GuardFailure("task artifact marker is missing")


def _receipt_abort_evidence(receipt_path: Path) -> tuple[str, int]:
    try:
        receipt = json.loads(
            _read_private_artifact(receipt_path, 65536, "raw receipt").decode("utf-8")
        )
        transaction_id = receipt["host_transaction_id"]
        status = receipt["frontend_status"]
        content_length = receipt["frontend_content_length"]
        body_bytes = receipt["frontend_body_bytes"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise GuardFailure("cannot read bounded host transaction ID from receipt") from exc
    if not isinstance(transaction_id, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", transaction_id):
        raise GuardFailure("host transaction ID is unsafe or outside the bounded format")
    if (
        type(status) is not int
        or type(content_length) is not int
        or type(body_bytes) is not int
        or status != 200
        or content_length != 64
        or body_bytes != 5
    ):
        raise GuardFailure("raw receipt does not contain the correlated 200/64/5 fixture")
    return transaction_id, body_bytes


def _abort_event_status(log_text: str, event_pattern: re.Pattern[str], expected_pattern: re.Pattern[str]) -> str | None:
    event_lines = [
        line
        for line in log_text.splitlines()
        if re.search(r"(?:^|\s)" + event_pattern.pattern + r"\s*$", line)
    ]
    if len(event_lines) == 1 and re.search(
        r"(?:^|\s)" + expected_pattern.pattern + r"\s*$", event_lines[0]
    ):
        return None
    if len(event_lines) > 1:
        return "multiple upstream_eof response-body-abort events were recorded for the host transaction"
    return "matching upstream_eof response-body-abort event is missing"


def assert_abort_event(receipt_path: Path, error_log: Path, max_bytes: int, wait_seconds: float = 0.0) -> None:
    if not 1 <= max_bytes <= 1024 * 1024:
        raise GuardFailure("error-log inspection bound is invalid")
    if not 0.0 <= wait_seconds <= 30.0:
        raise GuardFailure("abort-event wait bound is invalid")
    transaction_id, expected_offset = _receipt_abort_evidence(receipt_path)
    event_pattern = re.compile(
        r"msconnector event=upstream_eof response-body-abort host-transaction-id="
        + re.escape(transaction_id)
        + r" offset=[0-9]+"
    )
    expected_pattern = re.compile(
        r"msconnector event=upstream_eof response-body-abort host-transaction-id="
        + re.escape(transaction_id)
        + r" offset=" + str(expected_offset)
    )
    deadline = time.monotonic() + wait_seconds
    last_error = "matching upstream_eof response-body-abort event is missing"
    for _rescan_number in range(MAX_ABORT_EVENT_RESCANS):
        try:
            log_text = _read_private_artifact(error_log, max_bytes, "host error log").decode("utf-8")
            event_error = _abort_event_status(log_text, event_pattern, expected_pattern)
            if event_error is None:
                return
            last_error = event_error
        except FileNotFoundError:
            last_error = "task-owned host error log is missing"
        except OSError as exc:
            raise GuardFailure("cannot read task-owned host error log") from exc
        except UnicodeError as exc:
            raise GuardFailure("task-owned host error log is not valid UTF-8") from exc
        if time.monotonic() >= deadline:
            raise GuardFailure(last_error)
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    raise GuardFailure("bounded upstream_eof abort-event rescan limit exceeded")


def signal_singleton_session(pid: int, expected_start: str, expected_exe: str, signal_number: int) -> None:
    assert_singleton_session(pid, expected_start, expected_exe)
    signal_owned(pid, expected_start, expected_exe, signal_number)


def _register_session(path: Path) -> None:
    leader_pid = os.getpid()
    process_group, session_id = _session_fields(leader_pid)
    if process_group != leader_pid or session_id != leader_pid:
        raise GuardFailure("exec-session did not create a unique task SID/PGID")
    _write_new(
        path,
        (
            json.dumps(
                {
                    "leader_pid": leader_pid,
                    "leader_start_time": _start_time(leader_pid),
                    "process_group": process_group,
                    "session_id": session_id,
                },
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8"),
    )


def _registered_session(path: Path) -> RegisteredSession:
    try:
        value = json.loads(_read_private_artifact(path, 16384, "session registration").decode("utf-8"))
        record = RegisteredSession(
            leader_pid=value["leader_pid"],
            leader_start_time=value["leader_start_time"],
            process_group=value["process_group"],
            session_id=value["session_id"],
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise GuardFailure("cannot read registered task session") from exc
    if (
        type(record.leader_pid) is not int
        or type(record.process_group) is not int
        or type(record.session_id) is not int
        or not isinstance(record.leader_start_time, str)
        or not record.leader_start_time.isdecimal()
        or record.leader_pid <= 0
        or record.session_id != record.leader_pid
        or record.process_group != record.leader_pid
    ):
        raise GuardFailure("registered task SID/PGID is invalid")
    return record


def write_json(path: Path, fields: list[str]) -> None:
    if not isinstance(fields, list) or len(fields) > MAX_JSON_FIELDS:
        raise GuardFailure("JSON field count exceeds its bounded limit")
    value: dict[str, str] = {}
    for field in fields:
        if not isinstance(field, str) or "\x00" in field:
            raise GuardFailure("JSON field is invalid")
        try:
            field_bytes = field.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise GuardFailure("JSON field is not valid UTF-8") from exc
        if len(field_bytes) > MAX_JSON_FIELD_BYTES:
            raise GuardFailure("JSON field exceeds its bounded byte limit")
        key, separator, item = field.partition("=")
        if (
            not separator
            or not re.fullmatch(r"[A-Za-z]\w{0,63}", key, flags=re.ASCII)
            or key in value
        ):
            raise GuardFailure("JSON fields must be unique key=value pairs")
        value[key] = item
    payload = (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > MAX_JSON_OUTPUT_BYTES:
        raise GuardFailure("JSON output exceeds its bounded byte limit")
    _write_new(path, payload)


def _validated_executable(value: str) -> str:
    """Accept only an owner-controlled executable with stable path identity."""

    executable = Path(value)
    if not executable.is_absolute() or executable.name in ("", ".", ".."):
        raise GuardFailure("session executable must be an absolute path")
    try:
        resolved = executable.resolve(strict=True)
        metadata = os.lstat(executable)
    except OSError as exc:
        raise GuardFailure("session executable cannot be inspected") from exc
    if resolved != executable or stat.S_ISLNK(metadata.st_mode):
        raise GuardFailure("session executable path must not contain symbolic links")
    if not stat.S_ISREG(metadata.st_mode) or not os.access(executable, os.X_OK):
        raise GuardFailure("session executable must be an executable regular file")
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
        raise GuardFailure("session executable must be owned by the runner and not group/world writable")
    return str(executable)


def _runner_session_value(variable: str) -> str:
    """Read one bounded value from the harness-owned session profile."""

    value = os.environ.get(variable)
    if not value or "\x00" in value:
        raise GuardFailure(f"runner session configuration {variable} is required")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise GuardFailure("runner session configuration is not valid UTF-8") from exc
    if len(encoded) > MAX_SESSION_VALUE_BYTES:
        raise GuardFailure("runner session configuration exceeds its bounded byte limit")
    return value


def _validated_module_directory(value: str) -> str:
    directory = Path(value)
    if not directory.is_absolute() or ".." in directory.parts or "." in directory.parts:
        raise GuardFailure("lighttpd module directory is outside the trusted task boundary")
    try:
        resolved_directory = directory.resolve(strict=True)
        metadata = os.lstat(directory)
    except OSError as exc:
        raise GuardFailure("lighttpd module directory cannot be inspected") from exc
    if (
        resolved_directory != directory
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_mode & 0o022
        or metadata.st_uid != os.geteuid()
    ):
        raise GuardFailure("lighttpd module directory is not trusted")
    return str(directory)


def _session_profile_environment(profile: str, required: tuple[str, ...]) -> None:
    allowed = {SESSION_PROFILE_ENV, *required}
    unexpected = sorted(
        variable
        for variable in os.environ
        if variable.startswith(SESSION_ENV_PREFIX) and variable not in allowed
    )
    if unexpected:
        raise GuardFailure(f"session profile {profile} has unsupported runner configuration")


def _profile_executable(profile: str, expected_prefix: str) -> str:
    executable = _validated_executable(_runner_session_value(SESSION_EXECUTABLE_ENV))
    if not Path(executable).name.startswith(expected_prefix):
        raise GuardFailure(f"session profile {profile} has an unexpected executable")
    return executable


def _profile_private_artifact(variable: str) -> str:
    return str(_private_artifact_path(Path(_runner_session_value(variable))))


def _profile_port(variable: str) -> str:
    value = _runner_session_value(variable)
    if not value.isdigit() or not 1024 <= int(value) <= 65535:
        raise GuardFailure("python lifecycle port is outside the bounded range")
    return value


def _profile_timeout() -> str:
    value = _runner_session_value(SESSION_TIMEOUT_ENV)
    if not value.isdigit() or not 1 <= int(value) <= 30:
        raise GuardFailure("python lifecycle timeout is outside the bounded range")
    return value


def _runner_session_command() -> list[str]:
    """Construct the only argv forms a runner-owned session may execute.

    `exec-session` intentionally has no positional command vector. A caller
    must select one of these complete profiles and every profile value is
    checked before the process boundary is reached.
    """
    profile = _runner_session_value(SESSION_PROFILE_ENV)
    if profile == "lighttpd-config-check":
        _session_profile_environment(profile, (SESSION_EXECUTABLE_ENV, SESSION_MODULE_DIR_ENV, SESSION_CONFIG_ENV, SESSION_PARENT_PID_ENV))
        executable = _profile_executable(profile, "lighttpd")
        module_directory = _validated_module_directory(_runner_session_value(SESSION_MODULE_DIR_ENV))
        config = _profile_private_artifact(SESSION_CONFIG_ENV)
        return [executable, "-m", module_directory, "-tt", "-f", config]
    if profile == "lighttpd-server":
        _session_profile_environment(profile, (SESSION_EXECUTABLE_ENV, SESSION_MODULE_DIR_ENV, SESSION_CONFIG_ENV, SESSION_PARENT_PID_ENV))
        executable = _profile_executable(profile, "lighttpd")
        module_directory = _validated_module_directory(_runner_session_value(SESSION_MODULE_DIR_ENV))
        config = _profile_private_artifact(SESSION_CONFIG_ENV)
        return [executable, "-D", "-m", module_directory, "-f", config]
    if profile == "sleep-duration":
        _session_profile_environment(profile, (SESSION_EXECUTABLE_ENV, SESSION_DURATION_ENV, SESSION_PARENT_PID_ENV))
        executable = _profile_executable(profile, "sleep")
        duration = _runner_session_value(SESSION_DURATION_ENV)
        if not duration.isdigit() or int(duration) > 86400:
            raise GuardFailure("sleep session requires one bounded duration")
        return [executable, duration]
    if profile == "stock-lifecycle-hold":
        required = (
            SESSION_EXECUTABLE_ENV,
            SESSION_FRONTEND_PORT_ENV,
            SESSION_UPSTREAM_PORT_ENV,
            SESSION_READY_ENV,
            SESSION_RELEASE_ENV,
            SESSION_RUNTIME_ROOT_ENV,
            SESSION_RECEIPT_ENV,
            SESSION_TIMEOUT_ENV,
            SESSION_PARENT_PID_ENV,
        )
        _session_profile_environment(profile, required)
        executable = _profile_executable(profile, "python")
        runtime_root = _trusted_runtime_root()
        configured_root = Path(_runner_session_value(SESSION_RUNTIME_ROOT_ENV))
        if configured_root != runtime_root:
            raise GuardFailure("python lifecycle runtime root does not match the trusted root")
        expected_probe = Path(__file__).resolve().with_name("lighttpd_stock_lifecycle_probe.py")
        return [
            executable,
            str(expected_probe),
            "hold",
            "--frontend-port",
            _profile_port(SESSION_FRONTEND_PORT_ENV),
            "--upstream-port",
            _profile_port(SESSION_UPSTREAM_PORT_ENV),
            "--ready",
            _profile_private_artifact(SESSION_READY_ENV),
            "--release",
            _profile_private_artifact(SESSION_RELEASE_ENV),
            "--runtime-root",
            str(runtime_root),
            "--receipt",
            _profile_private_artifact(SESSION_RECEIPT_ENV),
            "--timeout",
            _profile_timeout(),
        ]
    raise GuardFailure("session profile is not approved")


def _session_parent_pid() -> int:
    # Older direct guard callers do not provide the optional binding; bind to
    # the observed parent immediately and still perform the post-prctl
    # recheck.  The lifecycle harness always supplies the explicit PID.
    value = os.environ.get(SESSION_PARENT_PID_ENV, str(os.getppid()))
    if not value.isdigit():
        raise GuardFailure("session parent PID is invalid")
    parent_pid = int(value)
    if not 1 <= parent_pid <= 4_194_304:
        raise GuardFailure("session parent PID is outside the bounded range")
    return parent_pid


def _bind_parent_death_signal(expected_parent_pid: int) -> None:
    if os.getppid() != expected_parent_pid:
        raise GuardFailure("session parent changed before parent-death binding")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
        prctl.restype = ctypes.c_int
        if prctl(1, signal.SIGTERM, 0, 0, 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
    except (AttributeError, OSError) as exc:
        raise GuardFailure("cannot bind parent-death signal") from exc
    if os.getppid() != expected_parent_pid:
        raise GuardFailure("session parent changed after parent-death binding")


def exec_session(file_limit_blocks: int, session_record: Path | None = None) -> None:
    if not 1 <= file_limit_blocks <= 2048:
        raise GuardFailure("session file limit is invalid")
    expected_parent_pid = _session_parent_pid()
    command = _runner_session_command()
    try:
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit_blocks * 512, file_limit_blocks * 512))
        _bind_parent_death_signal(expected_parent_pid)
        os.setsid()
        if session_record is not None:
            _register_session(session_record)
        os.execv(command[0], command)
    except OSError as exc:
        raise GuardFailure("cannot create task-owned session or exec host") from exc


def _start_time(pid: int) -> str:
    try:
        stat = _proc_stat_path(pid).read_text(encoding="ascii")
    except OSError as exc:
        raise GuardFailure(f"cannot read /proc/{pid}/stat") from exc
    try:
        after_comm = stat.rsplit(")", 1)[1].split()
        return after_comm[19]
    except (IndexError, ValueError) as exc:
        raise GuardFailure(f"cannot parse /proc/{pid}/stat start time") from exc


def _validate_identity(pid: int, expected_start: str, expected_exe: str) -> None:
    if _start_time(pid) != expected_start:
        raise GuardFailure("process start time changed")
    try:
        actual_exe = os.path.realpath(f"/proc/{pid}/exe")
    except OSError as exc:
        raise GuardFailure(f"cannot resolve /proc/{pid}/exe") from exc
    if actual_exe != os.path.realpath(expected_exe):
        raise GuardFailure("process executable changed")


def _pidfd_matches_pid(pidfd: int, pid: int) -> None:
    try:
        fdinfo = Path(f"/proc/self/fdinfo/{pidfd}").read_text(encoding="ascii")
    except OSError as exc:
        raise GuardFailure("cannot inspect pidfd identity") from exc
    if f"Pid:\t{pid}\n" not in fdinfo:
        raise GuardFailure("pidfd no longer refers to the expected live pid")


def _open_pidfd(pid: int) -> int:
    _require_pidfd()
    try:
        pidfd = os.pidfd_open(pid, 0)
    except OSError as exc:
        # Never fall back to a numeric signal.  A config-check can finish in
        # the small interval after its shell-side liveness check, but an open
        # failure for any target that remains live is ambiguous and must fail
        # closed.
        try:
            target_state = _process_state(pid)
        except GuardFailure as state_exc:
            raise GuardFailure("cannot classify pidfd target after open failure") from state_exc
        if target_state in (None, "Z"):
            raise PidfdTargetExited("pidfd target exited before it could be opened") from exc
        raise GuardFailure("cannot open pidfd for a live target") from exc
    try:
        _pidfd_matches_pid(pidfd, pid)
        return pidfd
    except BaseException:
        os.close(pidfd)
        raise


def _pidfd_for_identity(pid: int, expected_start: str, expected_exe: str) -> int:
    pidfd = _open_pidfd(pid)
    try:
        _validate_identity(pid, expected_start, expected_exe)
        return pidfd
    except BaseException:
        os.close(pidfd)
        raise


def signal_owned(pid: int, expected_start: str, expected_exe: str, signal_number: int) -> None:
    pidfd = _pidfd_for_identity(pid, expected_start, expected_exe)
    try:
        signal.pidfd_send_signal(pidfd, signal_number)
    except OSError as exc:
        raise GuardFailure("pidfd signal failed") from exc
    finally:
        os.close(pidfd)


def terminate_unregistered_session(pid: int, expected_start: str, expected_exe: str,
                                   timeout_seconds: float) -> None:
    """Terminate only the exec-session leader before registration is published.

    This is intentionally limited to a still-unique session leader.  The
    caller may use it only during the bounded window between fork and
    ``_register_session``; no numeric PID fallback or process-group signal is
    permitted when that identity cannot be proven.
    """
    if not 0.0 < timeout_seconds <= 30.0:
        raise GuardFailure("unregistered session timeout is outside the bounded range")
    pidfd = _pidfd_for_identity(pid, expected_start, expected_exe)
    try:
        process_group, session_id = _session_fields(pid)
        if process_group != pid or session_id != pid:
            raise GuardFailure("unregistered task is not a unique session leader")
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        except OSError as exc:
            if exc.errno != errno.ESRCH:
                raise GuardFailure("pidfd signal failed for unregistered task") from exc
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if _process_state(pid) in (None, "Z"):
                return
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        except OSError as exc:
            if exc.errno != errno.ESRCH:
                raise GuardFailure("pidfd kill failed for unregistered task") from exc
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if _process_state(pid) in (None, "Z"):
                return
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        raise GuardFailure("unregistered task remained after bounded pidfd termination")
    finally:
        os.close(pidfd)


def _member_snapshot(member_pid: int, session: RegisteredSession) -> tuple[str, int, int]:
    start_time = _start_time(member_pid)
    process_group, session_id = _session_fields(member_pid)
    if session_id != session.session_id or process_group <= 0:
        raise GuardFailure("session member SID/PGID does not match the registered task session")
    if member_pid == session.leader_pid:
        if start_time != session.leader_start_time:
            raise GuardFailure("registered task leader start time changed within the task session")
        if process_group != session.process_group:
            raise GuardFailure("registered task leader PGID changed within the task session")
    return start_time, process_group, session_id


def _open_verified_session_member(member_pid: int, session: RegisteredSession) -> OpenSessionMember:
    pidfd = _open_pidfd(member_pid)
    try:
        first = _member_snapshot(member_pid, session)
        second = _member_snapshot(member_pid, session)
        if first != second:
            raise GuardFailure("session member identity changed while opening its pidfd")
        return OpenSessionMember(
            pid=member_pid,
            start_time=second[0],
            process_group=second[1],
            session_id=second[2],
            pidfd=pidfd,
        )
    except BaseException:
        os.close(pidfd)
        raise


def _member_is_current(member: OpenSessionMember, session: RegisteredSession) -> bool:
    if _process_state(member.pid) in (None, "Z"):
        return False
    try:
        _pidfd_matches_pid(member.pidfd, member.pid)
        signal.pidfd_send_signal(member.pidfd, 0)
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return False
        raise GuardFailure("cannot probe a verified task-session pidfd") from exc
    snapshot = _member_snapshot(member.pid, session)
    if snapshot != (member.start_time, member.process_group, member.session_id):
        raise GuardFailure("session member identity changed before pidfd signal")
    return True


def _validate_registered_leader(session: RegisteredSession, expected_exe: str) -> LeaderAnchor:
    state = _process_state(session.leader_pid)
    if state in (None, "Z"):
        return LeaderAnchor(is_live=False, is_registered_member=False)
    pidfd = _pidfd_for_identity(session.leader_pid, session.leader_start_time, expected_exe)
    try:
        process_group, session_id = _session_fields(session.leader_pid)
        return LeaderAnchor(
            is_live=True,
            is_registered_member=(
                process_group == session.process_group and session_id == session.session_id
            ),
        )
    finally:
        os.close(pidfd)


def _signal_registered_leader_if_live(
    session: RegisteredSession,
    expected_exe: str,
    signal_number: int,
) -> tuple[list[int], list[str]]:
    """Contain an identity-verified leader that has left the recorded session.

    The normal member scan handles the common case.  This fallback is only for
    a still-live registered leader which was not in that scan (or changed its
    PGID): its pidfd and original start time/executable remain a stronger proof
    of task ownership than a later session-field mismatch.  The mismatch still
    makes the run fail closed after this repair attempt.
    """

    errors: list[str] = []
    try:
        leader_state = _process_state(session.leader_pid)
    except GuardFailure as exc:
        _append_error(errors, exc)
        return [], errors
    if leader_state in (None, "Z"):
        return [], []
    try:
        pidfd = _pidfd_for_identity(
            session.leader_pid,
            session.leader_start_time,
            expected_exe,
        )
    except GuardFailure as exc:
        _append_error(errors, exc)
        return [], errors
    try:
        process_group, session_id = _session_fields(session.leader_pid)
        if process_group != session.process_group or session_id != session.session_id:
            _append_error(errors, "registered task leader SID/PGID changed")
        signal.pidfd_send_signal(pidfd, signal_number)
        return [session.leader_pid], errors
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return [], errors
        _append_error(errors, "pidfd signal failed for the registered task leader")
        return [], errors
    except GuardFailure as exc:
        _append_error(errors, exc)
        return [], errors
    finally:
        os.close(pidfd)


def _add_errors(errors: list[str], additions: list[str]) -> None:
    for addition in additions:
        _append_error(errors, addition)


def _signal_one_session_member(
    member_pid: int,
    session: RegisteredSession,
    signal_number: int,
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    try:
        member_state = _process_state(member_pid)
    except GuardFailure as exc:
        _append_error(errors, exc)
        return False, errors
    if member_state in (None, "Z"):
        return False, errors
    try:
        member = _open_verified_session_member(member_pid, session)
    except GuardFailure as exc:
        try:
            member_state = _process_state(member_pid)
        except GuardFailure as state_exc:
            _append_error(errors, state_exc)
        else:
            if member_state not in (None, "Z"):
                _append_error(errors, exc)
        return False, errors
    try:
        if not _member_is_current(member, session):
            return False, errors
        signal.pidfd_send_signal(member.pidfd, signal_number)
        return True, errors
    except OSError as exc:
        if exc.errno != errno.ESRCH:
            _append_error(errors, "pidfd signal failed for a verified task-session member")
        return False, errors
    except GuardFailure as exc:
        _append_error(errors, exc)
        return False, errors
    finally:
        os.close(member.pidfd)


def _signal_current_session_members(
    session: RegisteredSession,
    signal_number: int,
    deadline: float,
    excluded_pids: frozenset[int] = frozenset(),
) -> tuple[list[int], list[str]]:
    """Signal every observable member one pidfd at a time before the deadline.

    Keeping only one pidfd open at a time gives every member a pidfd-bound
    signal path without turning an unexpected child population into an
    unbounded FD allocation.  Membership is read only after the pidfd is open
    and is checked again immediately before that pidfd is used.
    """

    member_pids, errors = _scan_session_members(session.session_id)
    signaled: list[int] = []
    for member_pid in member_pids:
        if member_pid in excluded_pids:
            continue
        if time.monotonic() >= deadline:
            _append_error(errors, "bounded task-session pidfd signal deadline expired")
            break
        member_signaled, member_errors = _signal_one_session_member(member_pid, session, signal_number)
        _add_errors(errors, member_errors)
        if member_signaled:
            if len(signaled) >= MAX_RECORDED_MEMBER_IDS:
                _append_error(errors, _SIGNAL_MEMBER_LIMIT)
                break
            signaled.append(member_pid)
    return signaled, errors


KILL_RESCAN_SECONDS = 0.05
TERM_EMPTY_CONFIRMATION_RESCANS = 6


def _wait_for_no_active_session_members(
    session_id: int,
    deadline: float,
    maximum_wait_seconds: float | None = None,
    excluded_pids: frozenset[int] = frozenset(),
    minimum_empty_rescans: int = 1,
) -> tuple[bool, list[str]]:
    if minimum_empty_rescans < 1:
        raise GuardFailure("session-empty confirmation bound is invalid")
    wait_deadline = deadline
    if maximum_wait_seconds is not None:
        wait_deadline = min(wait_deadline, time.monotonic() + maximum_wait_seconds)
    errors: list[str] = []
    empty_rescans = 0
    for _rescan_number in range(MAX_SESSION_WAIT_RESCANS):
        active_members, scan_errors = _active_session_members(session_id)
        _add_errors(errors, scan_errors)
        active_members = [member_pid for member_pid in active_members if member_pid not in excluded_pids]
        if not active_members:
            empty_rescans += 1
            if empty_rescans >= minimum_empty_rescans:
                return True, errors
        else:
            empty_rescans = 0
        if time.monotonic() >= wait_deadline:
            return False, errors
        time.sleep(min(0.05, max(0.0, wait_deadline - time.monotonic())))
    _append_error(errors, "bounded task-session wait rescan limit exceeded")
    return False, errors


def _kill_until_no_active_session_members(
    session: RegisteredSession,
    deadline: float,
    excluded_pids: frozenset[int] = frozenset(),
) -> tuple[list[int], bool, list[str]]:
    """Repeat bounded pidfd KILL snapshots so forked late members are contained."""

    signaled: list[int] = []
    errors: list[str] = []
    for _rescan_number in range(MAX_KILL_RESCANS):
        round_signaled, round_errors = _signal_current_session_members(
            session,
            signal.SIGKILL,
            deadline,
            excluded_pids,
        )
        _append_member_ids(
            signaled,
            round_signaled,
            errors,
            _SIGNAL_MEMBER_LIMIT,
        )
        _add_errors(errors, round_errors)
        stopped, wait_errors = _wait_for_no_active_session_members(
            session.session_id,
            deadline,
            KILL_RESCAN_SECONDS,
            excluded_pids,
        )
        _add_errors(errors, wait_errors)
        if stopped:
            return signaled, True, errors
        if time.monotonic() >= deadline:
            return signaled, False, errors
    _append_error(errors, "bounded task-session KILL rescan limit exceeded")
    return signaled, False, errors


def _prepare_leader_cleanup(
    session: RegisteredSession,
    expected_leader_exe: str,
    cleanup_errors: list[str],
) -> tuple[bool, frozenset[int], LeaderAnchor]:
    excluded_pids: frozenset[int] = frozenset()
    leader_signal_allowed = True
    try:
        leader_anchor = _validate_registered_leader(session, expected_leader_exe)
    except GuardFailure as exc:
        # A live leader whose start time or executable no longer matches might
        # be a reused numeric PID. Never signal that numeric PID. Continue with
        # independently pidfd-verified members of the recorded task session.
        leader_signal_allowed = False
        excluded_pids = frozenset((session.leader_pid,))
        try:
            leader_state = _process_state(session.leader_pid)
        except GuardFailure as state_exc:
            _append_error(cleanup_errors, "registered task leader state is not safely inspectable")
            _append_error(cleanup_errors, state_exc)
            leader_state = None
        if leader_state not in (None, "Z"):
            _append_error(
                cleanup_errors,
                "registered task leader identity is not pidfd-verifiable; "
                "containing other verified task-session members only",
            )
        else:
            _append_error(cleanup_errors, exc)
        leader_anchor = LeaderAnchor(is_live=False, is_registered_member=False)
    if leader_anchor.is_live and not leader_anchor.is_registered_member:
        _append_error(cleanup_errors, "registered task leader SID/PGID changed")
    return leader_signal_allowed, excluded_pids, leader_anchor


def terminate_registered_session(
    session_record: Path,
    expected_leader_exe: str,
    timeout_seconds: float,
) -> dict[str, object]:
    if not 0.1 <= timeout_seconds <= 30.0:
        raise GuardFailure("session cleanup timeout is outside the bounded range")
    session = _registered_session(session_record)
    initial_members, initial_errors = _scan_session_members(session.session_id)
    initial_active_members, initial_state_errors = _active_member_ids(initial_members)
    observed_members: list[int] = []
    unexpected_members: list[int] = []
    cleanup_errors: list[str] = []
    _append_member_ids(
        observed_members,
        initial_members,
        cleanup_errors,
        _INVENTORY_MEMBER_LIMIT,
    )
    _add_errors(cleanup_errors, initial_errors)
    _add_errors(cleanup_errors, initial_state_errors)
    _append_unexpected_members(
        unexpected_members,
        initial_active_members,
        session.leader_pid,
        cleanup_errors,
    )
    leader_signal_allowed, excluded_pids, _leader_anchor = _prepare_leader_cleanup(
        session,
        expected_leader_exe,
        cleanup_errors,
    )
    term_deadline = time.monotonic() + timeout_seconds
    term_signaled, term_errors = _signal_current_session_members(
        session,
        signal.SIGTERM,
        term_deadline,
        excluded_pids,
    )
    _add_errors(cleanup_errors, term_errors)
    _append_member_ids(
        observed_members,
        term_signaled,
        cleanup_errors,
        _INVENTORY_MEMBER_LIMIT,
    )
    _append_unexpected_members(
        unexpected_members,
        term_signaled,
        session.leader_pid,
        cleanup_errors,
    )
    if leader_signal_allowed and session.leader_pid not in term_signaled:
        leader_signaled, leader_signal_errors = _signal_registered_leader_if_live(
            session,
            expected_leader_exe,
            signal.SIGTERM,
        )
        _append_member_ids(
            term_signaled,
            leader_signaled,
            cleanup_errors,
            _SIGNAL_MEMBER_LIMIT,
        )
        _append_member_ids(
            observed_members,
            leader_signaled,
            cleanup_errors,
            _INVENTORY_MEMBER_LIMIT,
        )
        _append_unexpected_members(
            unexpected_members,
            leader_signaled,
            session.leader_pid,
            cleanup_errors,
        )
        _add_errors(cleanup_errors, leader_signal_errors)
    term_stopped, term_wait_errors = _wait_for_no_active_session_members(
        session.session_id,
        term_deadline,
        excluded_pids=excluded_pids,
        minimum_empty_rescans=TERM_EMPTY_CONFIRMATION_RESCANS,
    )
    _add_errors(cleanup_errors, term_wait_errors)
    kill_signaled: list[int] = []
    if not term_stopped:
        kill_deadline = time.monotonic() + timeout_seconds
        kill_signaled, kill_stopped, kill_errors = _kill_until_no_active_session_members(
            session,
            kill_deadline,
            excluded_pids,
        )
        _add_errors(cleanup_errors, kill_errors)
        _append_member_ids(
            observed_members,
            kill_signaled,
            cleanup_errors,
            _INVENTORY_MEMBER_LIMIT,
        )
        _append_unexpected_members(
            unexpected_members,
            kill_signaled,
            session.leader_pid,
            cleanup_errors,
        )
        if leader_signal_allowed and session.leader_pid not in kill_signaled:
            leader_signaled, leader_signal_errors = _signal_registered_leader_if_live(
                session,
                expected_leader_exe,
                signal.SIGKILL,
            )
            _append_member_ids(
                kill_signaled,
                leader_signaled,
                cleanup_errors,
            _SIGNAL_MEMBER_LIMIT,
            )
            _append_member_ids(
                observed_members,
                leader_signaled,
                cleanup_errors,
            _INVENTORY_MEMBER_LIMIT,
            )
            _append_unexpected_members(
                unexpected_members,
                leader_signaled,
                session.leader_pid,
                cleanup_errors,
            )
            _add_errors(cleanup_errors, leader_signal_errors)
    else:
        kill_stopped = True
    if not kill_stopped:
        raise GuardFailure("task session retains active members after bounded TERM/KILL containment")
    if cleanup_errors:
        raise GuardFailure(
            "task session membership could not be fully verified for cleanup: "
            + _error_summary(cleanup_errors)
        )
    return {
        "initial_members": initial_members,
        "kill_signaled": kill_signaled,
        "process_group": session.process_group,
        "session_id": session.session_id,
        "term_signaled": term_signaled,
        "unexpected_members": sorted(unexpected_members),
    }


def _listen_table_inodes(
    table_path: Path,
    expected_port: str,
    accepted_local_addresses: set[str] | None,
    table_name: str,
) -> set[str]:
    """Read one bounded kernel TCP table and return matching LISTEN inodes."""
    address_width = _tcp_table_address_width(table_path, table_name)
    inodes: set[str] = set()
    try:
        with table_path.open("r", encoding="ascii", errors="strict") as table:
            _validate_tcp_table_header(table, table_name)
            for _ in range(MAX_TCP_LISTENER_LINES):
                line = _read_bounded_tcp_line(table, table_name, "entry")
                if not line:
                    break
                inode = _tcp_listener_inode(
                    line,
                    address_width,
                    expected_port,
                    accepted_local_addresses,
                    table_name,
                )
                if inode is not None:
                    inodes.add(inode)
            else:
                if table.read(1):
                    raise GuardFailure(f"bounded {table_name} listener scan limit exceeded")
    except (OSError, UnicodeError) as exc:
        raise GuardFailure(f"cannot inspect {table_name}") from exc
    return inodes


def _tcp_table_address_width(table_path: Path, table_name: str) -> int:
    if table_path.name == "tcp":
        return 8
    if table_path.name == "tcp6":
        return 32
    raise GuardFailure(f"{table_name} has an unknown TCP table family")


def _read_bounded_tcp_line(table: TextIO, table_name: str, line_kind: str) -> str:
    line = table.readline(MAX_TCP_LISTENER_LINE_BYTES + 1)
    if len(line) > MAX_TCP_LISTENER_LINE_BYTES and not line.endswith("\n"):
        raise GuardFailure(f"{table_name} {line_kind} exceeds the bounded inspection limit")
    return line


def _validate_tcp_table_header(table: TextIO, table_name: str) -> None:
    header = _read_bounded_tcp_line(table, table_name, "header")
    fields = header.split()
    if (
        not header.endswith("\n")
        or len(fields) < 4
        or fields[:2] != ["sl", "local_address"]
        or fields[2] not in {"rem_address", "remote_address"}
        or fields[3] != "st"
        or "inode" not in fields
    ):
        raise GuardFailure(f"{table_name} contains an invalid or incomplete header")


def _is_tcp_endpoint(value: str, address_width: int) -> bool:
    address, separator, port = value.partition(":")
    return (
        bool(separator)
        and len(address) == address_width
        and len(port) == 4
        and all(character in "0123456789ABCDEFabcdef" for character in address + port)
    )


def _tcp_listener_inode(
    line: str,
    address_width: int,
    expected_port: str,
    accepted_local_addresses: set[str] | None,
    table_name: str,
) -> str | None:
    fields = line.split()
    if len(fields) <= 9:
        raise GuardFailure(f"{table_name} contains a malformed nonblank row")
    local_address, _, local_port = fields[1].partition(":")
    if not _is_tcp_endpoint(fields[1], address_width):
        raise GuardFailure(f"{table_name} contains an invalid local endpoint")
    if not _is_tcp_endpoint(fields[2], address_width):
        raise GuardFailure(f"{table_name} contains an invalid remote endpoint")
    state = fields[3]
    if len(state) != 2 or any(character not in "0123456789ABCDEFabcdef" for character in state):
        raise GuardFailure(f"{table_name} contains an invalid state field")
    inode = fields[9]
    if not inode or not inode.isdecimal():
        raise GuardFailure(f"{table_name} contains an invalid inode field")
    if (
        state == "0A"
        and local_port == expected_port
        and (accepted_local_addresses is None or local_address in accepted_local_addresses)
    ):
        return inode
    return None


def _listen_inodes_snapshot(host: str, port: int, include_ipv6: bool = False) -> set[str]:
    """Return LISTEN inodes without using a bind/TIME_WAIT probe."""
    if host != "127.0.0.1":
        raise GuardFailure("listener guard supports only 127.0.0.1")
    expected_port = f"{port:04X}"
    tcp_inodes = _listen_table_inodes(
        Path("/proc/net/tcp"),
        expected_port,
        {"0100007F", "00000000"},
        "/proc/net/tcp",
    )
    if len(tcp_inodes) > 1:
        raise GuardFailure("expected exactly one frontend LISTEN inode for the task port")
    if not include_ipv6:
        return tcp_inodes
    # /proc/net/tcp6 prints IPv6 addresses as 32 lower-case hex digits.  The
    # wildcard and loopback forms cover [::]:PORT and [::1]:PORT, including
    # both IPV6_V6ONLY settings.  A matching IPv6 listener is relevant even
    # when the task itself uses IPv4, so absence is fail-closed on both tables.
    tcp6_inodes = _listen_table_inodes(
        Path("/proc/net/tcp6"),
        expected_port,
        None,
        "/proc/net/tcp6",
    )
    return tcp_inodes | tcp6_inodes


def _listen_inodes(host: str, port: int, include_ipv6: bool = False) -> set[str]:
    inodes = _listen_inodes_snapshot(host, port, include_ipv6=include_ipv6)
    if not inodes:
        raise GuardFailure("expected frontend listener is absent")
    return inodes


def assert_listener_absent(host: str, port: int) -> None:
    """Fail closed if any listener remains after cleanup."""

    inodes = _listen_inodes_snapshot(host, port, include_ipv6=True)
    if inodes:
        raise GuardFailure("frontend listener remains after cleanup")


def _owned_listener_inodes(pid: int, inodes: set[str]) -> set[str]:
    """Return listener inodes still held by the exact task process."""

    owned_inodes: set[str] = set()
    for entry in _task_fd_entries(pid):
        try:
            target = os.readlink(entry)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise GuardFailure("cannot inspect process file descriptor") from exc
        for inode in inodes:
            if target == f"socket:[{inode}]":
                owned_inodes.add(inode)
    return owned_inodes


def assert_listener_owned(pid: int, expected_start: str, expected_exe: str, host: str, port: int) -> None:
    pidfd = _pidfd_for_identity(pid, expected_start, expected_exe)
    try:
        # An independently-held IPv6 listener on the same port is an
        # ambiguous active endpoint and must fail closed during attribution.
        before_inodes = _listen_inodes(host, port, include_ipv6=True)
        if _owned_listener_inodes(pid, before_inodes) != before_inodes:
            raise GuardFailure("a frontend listener inode is not exclusively owned by the task host")
        after_inodes = _listen_inodes(host, port, include_ipv6=True)
        if after_inodes != before_inodes:
            raise GuardFailure("frontend listener changed during task-FD attribution")
        if _owned_listener_inodes(pid, after_inodes) != after_inodes:
            raise GuardFailure("frontend listener inode is no longer held by the task host")
        _validate_identity(pid, expected_start, expected_exe)
    finally:
        os.close(pidfd)


def _run_basic_command(args: argparse.Namespace) -> bool:
    if args.command == "check-pidfd":
        _require_pidfd()
    elif args.command == "write-config":
        write_config(args.root, args.rules_file, args.frontend_port, args.upstream_port, args.backend_read_timeout)
    elif args.command == "write-json":
        write_json(args.output, args.field)
    elif args.command == "exec-session":
        exec_session(args.file_limit_blocks, args.session_record)
    else:
        return False
    return True


def _run_session_command(args: argparse.Namespace) -> bool:
    if args.command == "assert-session":
        inventory = assert_singleton_session(args.pid, args.start_time, args.exe)
        if args.output is not None:
            _write_new(args.output, (json.dumps(inventory, sort_keys=True) + "\n").encode("utf-8"))
    elif args.command == "assert-session-absent":
        assert_session_absent(args.session, args.wait_seconds)
    elif args.command == "cleanup-session":
        inventory = terminate_registered_session(args.session_record, args.leader_exe, args.timeout_seconds)
        if args.output is not None:
            _write_new(args.output, (json.dumps(inventory, sort_keys=True) + "\n").encode("utf-8"))
        if args.reject_unexpected_members and inventory["unexpected_members"]:
            raise GuardFailure("task session contained unexpected members during cleanup")
    elif args.command == "signal-session":
        signal_singleton_session(args.pid, args.start_time, args.exe, getattr(signal, f"SIG{args.signal}"))
    elif args.command == "terminate-unregistered":
        terminate_unregistered_session(args.pid, args.start_time, args.exe, args.timeout_seconds)
    else:
        return False
    return True


def _run_guard_command(args: argparse.Namespace) -> None:
    if args.command == "assert-no-uds":
        assert_no_unix_sockets(args.root)
    elif args.command == "assert-abort-event":
        assert_abort_event(args.receipt, args.error_log, args.max_bytes, args.wait_seconds)
    elif args.command == "assert-file-marker":
        assert_private_artifact_contains(args.path, args.marker, args.max_bytes)
    elif args.command == "signal":
        signal_owned(args.pid, args.start_time, args.exe, getattr(signal, f"SIG{args.signal}"))
    elif args.command == "assert-listener-absent":
        assert_listener_absent(args.host, args.port)
    else:
        assert_listener_owned(args.pid, args.start_time, args.exe, args.host, args.port)


def _run_command(args: argparse.Namespace) -> None:
    if _run_basic_command(args) or _run_session_command(args):
        return
    _run_guard_command(args)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    command = parser.add_subparsers(dest="command", required=True)
    command.add_parser("check-pidfd")
    config = command.add_parser("write-config")
    config.add_argument("--root", type=Path, required=True)
    config.add_argument("--rules-file", required=True)
    config.add_argument("--frontend-port", type=int, required=True)
    config.add_argument("--upstream-port", type=int, required=True)
    config.add_argument("--backend-read-timeout", type=int)
    writer = command.add_parser("write-json")
    writer.add_argument("--output", type=Path, required=True)
    writer.add_argument("--field", action="append", default=[])
    executor = command.add_parser("exec-session")
    executor.add_argument("--file-limit-blocks", type=int, required=True)
    executor.add_argument("--session-record", type=Path)
    session = command.add_parser("assert-session")
    session.add_argument("--pid", type=int, required=True)
    session.add_argument("--start-time", required=True)
    session.add_argument("--exe", required=True)
    session.add_argument("--output", type=Path)
    session_signal = command.add_parser("signal-session")
    session_signal.add_argument("--pid", type=int, required=True)
    session_signal.add_argument("--start-time", required=True)
    session_signal.add_argument("--exe", required=True)
    session_signal.add_argument("--signal", choices=("TERM", "KILL"), required=True)
    unregistered = command.add_parser("terminate-unregistered")
    unregistered.add_argument("--pid", type=int, required=True)
    unregistered.add_argument("--start-time", required=True)
    unregistered.add_argument("--exe", required=True)
    unregistered.add_argument("--timeout-seconds", type=float, required=True)
    absent = command.add_parser("assert-session-absent")
    absent.add_argument("--session", type=int, required=True)
    absent.add_argument("--wait-seconds", type=float, default=0.0)
    cleanup = command.add_parser("cleanup-session")
    cleanup.add_argument("--session-record", type=Path, required=True)
    cleanup.add_argument("--leader-exe", required=True)
    cleanup.add_argument("--timeout-seconds", type=float, required=True)
    cleanup.add_argument("--output", type=Path)
    cleanup.add_argument("--reject-unexpected-members", action="store_true")
    sockets = command.add_parser("assert-no-uds")
    sockets.add_argument("--root", type=Path, required=True)
    abort = command.add_parser("assert-abort-event")
    abort.add_argument("--receipt", type=Path, required=True)
    abort.add_argument("--error-log", type=Path, required=True)
    abort.add_argument("--max-bytes", type=int, required=True)
    abort.add_argument("--wait-seconds", type=float, default=0.0)
    marker = command.add_parser("assert-file-marker")
    marker.add_argument("--path", type=Path, required=True)
    marker.add_argument("--marker", required=True)
    marker.add_argument("--max-bytes", type=int, required=True)
    for name in ("signal", "assert-listener"):
        subparser = command.add_parser(name)
        subparser.add_argument("--pid", type=int, required=True)
        subparser.add_argument("--start-time", required=True)
        subparser.add_argument("--exe", required=True)
        if name == "signal":
            subparser.add_argument("--signal", choices=("TERM", "KILL"), required=True)
        else:
            subparser.add_argument("--host", required=True)
            subparser.add_argument("--port", type=int, required=True)
    listener_absent = command.add_parser("assert-listener-absent")
    listener_absent.add_argument("--host", required=True)
    listener_absent.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    try:
        _run_command(args)
    except PidfdTargetExited as exc:
        print(f"lighttpd_backend_close_linux_guard: EXITED {exc}", file=sys.stderr)
        return PIDFD_TARGET_EXIT_STATUS
    except GuardFailure as exc:
        print(f"lighttpd_backend_close_linux_guard: FAIL {exc}", file=sys.stderr)
        return 1
    print(f"lighttpd_backend_close_linux_guard: PASS {args.command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
