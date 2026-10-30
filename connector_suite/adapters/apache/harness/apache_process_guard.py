#!/usr/bin/env python3
"""Linux-only ownership guard for the Apache smoke host.

The guard deliberately uses a recorded /proc identity and listener inode.  A
numeric PID or a port is never sufficient to authorize a signal.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import select
import secrets
import signal
import socket
import stat
import struct
import subprocess
import time
from typing import Any, Callable


PROC = Path("/proc")
LISTEN = "0A"
MAX_PROC_ENTRIES = 4096
MAX_FD_ENTRIES = 4096
MAX_NET_ROWS = 4096
MAX_NET_BYTES = 4 * 1024 * 1024
MAX_NET_LINE = 4096
MAX_EVIDENCE_BYTES = 1024 * 1024
TERM_TIMEOUT = 2.0
KILL_TIMEOUT = 2.0
RECORD_FAILURE_CLEANED_EXIT = 74
TEMPORARY_ARTIFACT_ATTEMPTS = 16
RECORD_INSPECTION_ATTEMPTS = 8
RECORD_INSPECTION_RETRY_SECONDS = 0.01
SUPERVISOR_CONTROL_TIMEOUT = 0.25
SUPERVISOR_TERM_TIMEOUT = 2.0
SUPERVISOR_KILL_TIMEOUT = 2.0
SUPERVISOR_REAP_GRACE = 1.0
SUPERVISOR_ACK_TIMEOUT = SUPERVISOR_TERM_TIMEOUT + SUPERVISOR_KILL_TIMEOUT + SUPERVISOR_REAP_GRACE + 1.0
SUPERVISOR_CONTROL_BYTES = 32
SUPERVISOR_EXIT_CONFIRM_ATTEMPTS = 40
RUNNER_DIRECTORY_ENV = "MSCONNECTOR_APACHE_GUARD_DIRECTORY"
RUNNER_ARTIFACT_ROOT_ENV = "MSCONNECTOR_APACHE_GUARD_ARTIFACT_ROOT"
RUNNER_HTTPD_ENV = "MSCONNECTOR_APACHE_GUARD_HTTPD"
APACHE_EXECUTABLE_LABEL = "Apache executable"
APACHE_ARTIFACT_ROOT_LABEL = "Apache artifact root"


class GuardError(RuntimeError):
    pass


class RecordFailureCleaned(GuardError):
    """Evidence publication failed after verified runtime cleanup."""


def _set_parent_death_signal(sig: int = int(signal.SIGTERM)) -> None:
    """Ask Linux to terminate the supervisor when its runner disappears."""
    if os.name != "posix":
        return
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                          ctypes.c_ulong, ctypes.c_ulong]
        prctl.restype = ctypes.c_int
        if prctl(1, sig, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_PDEATHSIG) failed")
    except (AttributeError, OSError) as exc:
        raise GuardError(f"cannot arm Apache supervisor parent-death cleanup: {exc}") from exc


def _supervisor_paths(state: Path, pid_output: Path) -> None:
    for label, path in (("supervisor state", state), ("supervisor PID output", pid_output)):
        if not path.is_absolute() or "\x00" in os.fspath(path) or ".." in path.parts:
            raise GuardError(f"{label} path must be absolute and traversal-free")
    if state == pid_output:
        raise GuardError("supervisor state and PID output must differ")


def _supervisor_stop_child(pidfd: int, child: subprocess.Popen[bytes]) -> None:
    """Stop exactly the launch-bound child, then wait for its reap."""
    if child.poll() is None:
        _send_child_signal(pidfd, child, signal.SIGTERM)
        if not _child_exited_within(pidfd, child, SUPERVISOR_TERM_TIMEOUT):
            _send_child_signal(pidfd, child, signal.SIGKILL)
            if not _child_exited_within(pidfd, child, SUPERVISOR_KILL_TIMEOUT):
                raise GuardError(
                    "Apache supervisor child did not exit within bounded cleanup"
                )
    try:
        child.wait(timeout=SUPERVISOR_REAP_GRACE)
    except subprocess.TimeoutExpired as exc:
        raise GuardError("Apache supervisor child was not reaped within bounded cleanup") from exc


def _send_child_signal(
    pidfd: int, child: subprocess.Popen[bytes], sig: signal.Signals
) -> None:
    if pidfd >= 0:
        _pidfd_send_signal(pidfd, int(sig))
    elif sig == signal.SIGKILL:
        child.kill()
    else:
        child.send_signal(sig)


def _child_exited_within(
    pidfd: int, child: subprocess.Popen[bytes], timeout: float
) -> bool:
    if pidfd >= 0:
        return _poll_pidfd(pidfd, timeout)
    try:
        child.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return False
    return True


def _launch_input_flags() -> int:
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _validate_launch_fd(fd: int, *, executable: bool) -> None:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise GuardError("Apache launch input is not an owned regular file")
    if executable and not (info.st_mode & 0o111):
        raise GuardError("Apache executable inode is not executable")


def _validated_httpd_path(path: Path, trusted_path: Path) -> Path:
    """Bind a CLI executable selection to the runner-provisioned capability."""
    for label, candidate in ((APACHE_EXECUTABLE_LABEL, path), ("trusted Apache executable", trusted_path)):
        if not candidate.is_absolute() or "\x00" in os.fspath(candidate) or any(
            component in (".", "..") for component in candidate.parts
        ):
            raise GuardError(f"{label} path must be absolute and traversal-free")
    try:
        resolved = path.resolve(strict=True)
        trusted = trusted_path.resolve(strict=True)
    except OSError as exc:
        raise GuardError(f"cannot resolve trusted Apache executable: {exc}") from exc
    if resolved != path or trusted != trusted_path:
        raise GuardError("Apache executable path must not contain symlinks")
    if resolved != trusted:
        raise GuardError("Apache executable does not match the runner-provisioned capability")
    if resolved.name not in ("httpd", "apache2"):
        raise GuardError("Apache supervisor accepts only an httpd/apache2 executable")
    return resolved


def _pin_launch_fd(path: Path, *, executable: bool) -> int:
    """Open and validate an exact canonical launch inode."""
    fd = -1
    try:
        fd = os.open(path, _launch_input_flags())
        _validate_launch_fd(fd, executable=executable)
        return fd
    except (GuardError, OSError) as exc:
        if fd >= 0:
            os.close(fd)
        if isinstance(exc, GuardError):
            raise
        raise GuardError(f"cannot pin Apache launch input {path}: {exc}") from exc


def _pin_config_fd(path: Path, artifact_root: Path) -> int:
    """Open the fixed generated config beneath the private runtime root."""
    expected = artifact_root / "conf" / "httpd.conf"
    if path != expected:
        raise GuardError("Apache config must be the generated runtime config")
    fd = -1
    try:
        fd = _open_artifact(path, artifact_root, _launch_input_flags())
        _validate_launch_fd(fd, executable=False)
        return fd
    except (GuardError, OSError) as exc:
        if fd >= 0:
            os.close(fd)
        if isinstance(exc, GuardError):
            raise
        raise GuardError(f"cannot pin Apache config {path}: {exc}") from exc


def _write_pid_output(path: Path, pid: int, artifact_root: Path) -> os.stat_result:
    parent_fd, name = _open_artifact_parent(path, artifact_root)
    fd = -1
    created_identity: os.stat_result | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
        created_identity = os.fstat(fd)
        _write_all(fd, f"{pid}\n".encode("ascii"))
        os.fsync(fd)
        identity = os.fstat(fd)
        closing_fd = fd
        fd = -1
        os.close(closing_fd)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
            raise GuardError("Apache supervisor PID output inode changed during publication")
        return identity
    except (GuardError, OSError) as exc:
        if fd >= 0:
            os.close(fd)
        if created_identity is not None:
            try:
                current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == (created_identity.st_dev, created_identity.st_ino):
                    os.unlink(name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        raise GuardError(f"cannot publish Apache supervisor PID: {exc}") from exc
    finally:
        os.close(parent_fd)


def retire_supervisor_session(state: Path, pid_output: Path, artifact_root: Path) -> None:
    """Retire one proven-stale supervisor session, never an arbitrary path."""
    try:
        state_info = os.lstat(state)
    except OSError as exc:
        raise GuardError(f"cannot inspect Apache supervisor state: {exc}") from exc
    evidence = _load(state, artifact_root)
    if evidence.get("kind") != "apache-supervisor-session" or evidence.get("version") != 1:
        raise GuardError("invalid Apache supervisor stale-session state kind/version")
    _validate_stale_session_parent(evidence)
    _validate_stale_session_processes(evidence)
    pid_info = None
    try:
        pid_info = os.stat(pid_output, follow_symlinks=False)
    except FileNotFoundError:
        pass
    _remove_exact_artifact(state, artifact_root, state_info)
    if pid_info is not None:
        _remove_exact_artifact(pid_output, artifact_root, pid_info)


def _validate_stale_session_parent(evidence: dict[str, Any]) -> None:
    parent_pid = int(evidence["parent_pid"])
    parent_start = int(evidence["parent_pid_starttime"])
    caller_parent = os.getppid()
    try:
        caller_parent_identity = _stat(caller_parent)
    except (FileNotFoundError, GuardError) as exc:
        raise GuardError("current Apache runner lineage is unavailable") from exc
    direct_identity = _stat(os.getpid())
    caller_matches = (
        caller_parent == parent_pid
        and caller_parent_identity["starttime"] == parent_start
    )
    process_matches = (
        os.getpid() == parent_pid and direct_identity["starttime"] == parent_start
    )
    if not (caller_matches or process_matches):
        raise GuardError("current Apache runner lineage does not match recorded parent")


def _validate_stale_session_processes(evidence: dict[str, Any]) -> None:
    for field in ("supervisor_pid", "child_pid"):
        try:
            pid = int(evidence[field])
            start = int(evidence[f"{field}_starttime"])
            actual = _stat(pid)
        except FileNotFoundError:
            continue
        except (KeyError, TypeError, ValueError, GuardError) as exc:
            raise GuardError("invalid Apache supervisor stale-session identity") from exc
        if actual["starttime"] == start:
            raise GuardError("Apache supervisor session is active or ambiguous")


def _remove_exact_artifact(path: Path, artifact_root: Path, expected: os.stat_result) -> None:
    parent_fd, name = _open_artifact_parent(path, artifact_root)
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino):
            os.unlink(name, dir_fd=parent_fd)
    except FileNotFoundError:
        pass
    finally:
        os.close(parent_fd)


def _child_preexec(expected_parent: int, parent_mask: set[signal.Signals]) -> None:
    """Install child PDEATHSIG before exec and reject a dead supervisor."""
    signal.pthread_sigmask(signal.SIG_SETMASK, parent_mask)
    # SIGKILL is kernel-enforced and cannot be ignored: if pidfd acquisition
    # fails or the supervisor is killed, this exact child cannot orphan.
    _set_parent_death_signal(int(signal.SIGKILL))
    if os.getppid() != expected_parent:
        os._exit(77)


def supervise(httpd: Path, config: Path, state: Path, pid_output: Path) -> int:
    """Run only the validated Apache smoke command under a launch-bound guard."""
    _supervisor_paths(state, pid_output)
    artifact_root = _runner_configured_path(
        RUNNER_ARTIFACT_ROOT_ENV, APACHE_ARTIFACT_ROOT_LABEL
    )
    httpd = _validated_httpd_path(
        httpd, _runner_configured_path(RUNNER_HTTPD_ENV, APACHE_EXECUTABLE_LABEL)
    )
    expected_parent = os.getppid()
    supervisor_pid = os.getpid()
    stop_requested = False

    def request_stop(signum: int, _frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True

    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(signum, request_stop)
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, (signal.SIGTERM, signal.SIGHUP, signal.SIGINT))
    # During fork/exec the signal mask is intentionally blocked.  Use an
    # unignorable supervisor death action for that short window so a pending
    # runner death cannot leave a half-launched child behind.
    _set_parent_death_signal(int(signal.SIGKILL))
    if os.getppid() != expected_parent:
        raise GuardError("Apache supervisor runner disappeared before launch")
    child, pidfd = _launch_supervised_child(
        httpd, config, artifact_root, expected_parent, supervisor_pid, old_mask
    )
    try:
        return _run_supervisor_session(
            child, pidfd, expected_parent, supervisor_pid, state, pid_output, artifact_root,
            old_mask, lambda: stop_requested,
        )
    finally:
        os.close(pidfd)


def _launch_supervised_child(
    httpd: Path,
    config: Path,
    artifact_root: Path,
    expected_parent: int,
    supervisor_pid: int,
    old_mask: set[signal.Signals],
) -> tuple[subprocess.Popen[bytes], int]:
    httpd_fd = -1
    config_fd = -1
    try:
        httpd_fd = _pin_launch_fd(httpd, executable=True)
        config_fd = _pin_config_fd(config, artifact_root)
        child = subprocess.Popen(
            [f"/proc/self/fd/{httpd_fd}", "-X", "-f", f"/proc/self/fd/{config_fd}"],
            stdout=subprocess.DEVNULL,
            stderr=None,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
            pass_fds=(httpd_fd, config_fd),
            preexec_fn=lambda: _child_preexec(supervisor_pid, old_mask),
        )
    except OSError as exc:
        _close_launch_fds(httpd_fd, config_fd)
        raise GuardError(f"cannot launch Apache under supervisor: {exc}") from exc
    except GuardError:
        _close_launch_fds(httpd_fd, config_fd)
        raise
    try:
        _set_parent_death_signal()
        if os.getppid() != expected_parent:
            raise GuardError("Apache supervisor runner disappeared during launch")
        pidfd = os.pidfd_open(child.pid)
    except (GuardError, OSError) as exc:
        try:
            _supervisor_stop_child(locals().get("pidfd", -1), child)
        except (GuardError, OSError, subprocess.TimeoutExpired):
            pass
        raise GuardError(str(exc)) from exc
    finally:
        _close_launch_fds(httpd_fd, config_fd)
    return child, pidfd


def _close_launch_fds(httpd_fd: int, config_fd: int) -> None:
    if httpd_fd >= 0:
        os.close(httpd_fd)
    if config_fd >= 0:
        os.close(config_fd)


def _run_supervisor_session(
    child: subprocess.Popen[bytes],
    pidfd: int,
    expected_parent: int,
    supervisor_pid: int,
    state: Path,
    pid_output: Path,
    artifact_root: Path,
    old_mask: set[signal.Signals],
    stop_requested: Callable[[], bool],
) -> int:
    listener: socket.socket | None = None
    address = "\0msconnector-apache-" + secrets.token_hex(16)
    state_identity: os.stat_result | None = None
    try:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.settimeout(SUPERVISOR_CONTROL_TIMEOUT)
        listener.bind(address)
        listener.listen(1)
        parent_starttime = _stat(expected_parent)["starttime"]
        child_stat = _stat(child.pid)
        supervisor_stat = _stat(supervisor_pid)
        state_identity = _publish_supervisor_state(
            {"kind": "apache-supervisor-session", "version": 1,
             "address": address[1:], "parent_pid": expected_parent,
             "parent_pid_starttime": parent_starttime, "child_pid": child.pid,
             "child_pid_starttime": child_stat["starttime"], "supervisor_pid": supervisor_pid,
             "supervisor_pid_starttime": supervisor_stat["starttime"]}, state,
            artifact_root,
        )
        pid_identity = _write_pid_output(
            pid_output, child.pid, artifact_root,
        )
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        _supervisor_session_loop(
            listener, child, pidfd, expected_parent, parent_starttime, stop_requested
        )
        if child.poll() is None:
            _supervisor_stop_child(pidfd, child)
        # The runner observes Apache's actual PID for readiness and records;
        # supervisor status is reserved for supervisor/cleanup failures.  A
        # signal-terminated Apache is therefore a successfully reaped child,
        # not a cleanup error.
        return 0
    except (OSError, GuardError, subprocess.TimeoutExpired) as exc:
        try:
            _supervisor_stop_child(pidfd, child)
        except (GuardError, OSError, subprocess.TimeoutExpired):
            pass
        raise GuardError(f"Apache supervisor failed: {exc}") from exc
    finally:
        if listener is not None:
            listener.close()
        if state_identity is not None:
            try:
                _remove_exact_artifact(
                    state, artifact_root, state_identity,
                )
            except GuardError:
                pass
        if "pid_identity" in locals():
            try:
                _remove_exact_artifact(pid_output, artifact_root, pid_identity)
            except GuardError:
                pass


def _supervisor_session_loop(
    listener: socket.socket,
    child: subprocess.Popen[bytes],
    pidfd: int,
    expected_parent: int,
    parent_starttime: int,
    stop_requested: Callable[[], bool],
) -> None:
    while child.poll() is None:
        if stop_requested():
            _supervisor_stop_child(pidfd, child)
            return
        if _handle_supervisor_command(
            listener, child, pidfd, expected_parent, parent_starttime
        ):
            return


def _handle_supervisor_command(
    listener: socket.socket,
    child: subprocess.Popen[bytes],
    pidfd: int,
    expected_parent: int,
    parent_starttime: int,
) -> bool:
    try:
        peer, _ = listener.accept()
    except socket.timeout:
        return False
    with peer:
        credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        peer_pid, peer_uid, _ = struct.unpack("3i", credentials)
        if peer_uid != os.geteuid() or peer_pid <= 1:
            return False
        peer_identity = _stat(peer_pid)
        if (peer_identity["ppid"] != expected_parent or
                _stat(expected_parent)["starttime"] != parent_starttime):
            return False
        peer.settimeout(SUPERVISOR_CONTROL_TIMEOUT)
        command = peer.recv(SUPERVISOR_CONTROL_BYTES)
        if command.rstrip(b"\n") not in (b"stop", b"shutdown", b"cancel"):
            return False
        _supervisor_stop_child(pidfd, child)
        peer.sendall(b"ACK\n")
        return True


def stop_supervisor(state: Path, artifact_root: Path) -> None:
    evidence = _load(state, artifact_root)
    if evidence.get("kind") != "apache-supervisor-session" or evidence.get("version") != 1:
        raise GuardError("invalid Apache supervisor state kind/version")
    address = evidence.get("address")
    if not isinstance(address, str) or not address.startswith("msconnector-apache-"):
        raise GuardError("invalid Apache supervisor state address")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(SUPERVISOR_ACK_TIMEOUT)
    try:
        client.connect("\0" + address)
        client.sendall(b"stop\n")
        if client.recv(8) != b"ACK\n":
            raise GuardError("Apache supervisor did not acknowledge reaped child")
    except OSError as exc:
        raise GuardError(f"cannot stop Apache supervisor: {exc}") from exc
    finally:
        client.close()


def _runner_configured_path(variable: str, capability: str) -> Path:
    """Read a path capability selected by the Apache smoke runner.

    The guard deliberately has no generic CLI root flag. Its root values are
    trusted smoke-runner configuration, not an authentication mechanism for a
    same-identity local caller; the guard still validates every resulting path
    before runtime creation or guard-evidence access.
    """
    raw_path = os.environ.get(variable)
    if not raw_path or "\x00" in raw_path:
        raise GuardError(f"{capability} must be supplied by the Apache smoke runner")
    return Path(raw_path)


def _directory_open_flags() -> int:
    """Return the descriptor flags required for race-safe directory walking."""
    directory = getattr(os, "O_DIRECTORY", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if directory is None or nofollow is None:
        raise GuardError("Apache runtime directory hardening is unavailable on this platform")
    flags = os.O_RDONLY | directory | nofollow
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _runtime_ancestor_open_flags() -> int:
    """Traverse trusted execute-only ancestors without requiring list access."""
    path_flag = getattr(os, "O_PATH", None)
    if path_flag is None:
        raise GuardError("Apache runtime ancestor traversal requires O_PATH")
    return _directory_open_flags() | path_flag


def _safe_runtime_ancestor(metadata: os.stat_result, path: Path) -> None:
    """Accept only stable ancestors for a later pathname-based harness use.

    A descriptor-relative create prevents a symlink insertion during setup.
    Once the descriptor is closed, however, the shell uses the resulting path
    again. Writable shared ancestors are therefore allowed only when the
    sticky-bit rule protects the task-owned child from another user renaming
    it (the normal /tmp and /var/tmp case).
    """
    if not stat.S_ISDIR(metadata.st_mode):
        raise GuardError(f"Apache runtime path must contain directories only: {path}")
    if metadata.st_uid not in (0, os.geteuid()):
        raise GuardError(
            f"Apache runtime path has an untrusted ancestor owner: {path}"
        )
    if metadata.st_mode & 0o022 and not (
        metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX
    ):
        raise GuardError(
            f"Apache runtime path has an unsafe writable shared ancestor: {path}"
        )


def prepare_runtime_directory(path: Path, label: str, private_mode: bool) -> None:
    """Create and validate a harness directory without pathname races.

    Every component is opened relative to an already verified descriptor with
    ``O_DIRECTORY|O_NOFOLLOW``. Missing components are created with
    ``mkdirat`` semantics, then reopened through that same parent descriptor.
    This rejects a symlink inserted between existence checking and creation.
    """
    raw_path = os.fspath(path)
    if not os.path.isabs(raw_path) or "\x00" in raw_path:
        raise GuardError(f"{label} must be an absolute path")
    components = Path(raw_path).parts
    if len(components) < 2 or components[0] != os.sep or any(
        component in ("", ".", "..") for component in components[1:]
    ):
        raise GuardError(f"{label} must not contain empty, dot, or parent components")

    flags = _runtime_ancestor_open_flags()
    try:
        current_fd = os.open(os.sep, flags)
    except OSError as exc:
        raise GuardError(f"cannot open Apache runtime filesystem root: {exc}") from exc

    current_path = Path(os.sep)
    try:
        for index, component in enumerate(components[1:], start=1):
            is_leaf = index == len(components) - 1
            child_path = current_path / component
            child_flags = _directory_open_flags() if is_leaf else flags
            child_fd = _open_runtime_child(
                current_fd, component, child_path, child_flags, private_mode or not is_leaf
            )
            try:
                _validate_runtime_child(
                    child_fd, child_path, label, is_leaf, private_mode
                )
            except OSError as exc:
                os.close(child_fd)
                raise GuardError(
                    f"cannot validate Apache runtime directory {child_path}: {exc}"
                ) from exc
            except GuardError:
                os.close(child_fd)
                raise
            try:
                os.close(current_fd)
            except OSError as exc:
                os.close(child_fd)
                raise GuardError(
                    f"cannot close Apache runtime directory {current_path}: {exc}"
                ) from exc
            current_fd = child_fd
            current_path = child_path
    finally:
        os.close(current_fd)


def _open_runtime_child(
    parent_fd: int,
    component: str,
    child_path: Path,
    flags: int,
    private_mode: bool,
) -> int:
    try:
        return os.open(component, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        mode = 0o700 if private_mode else 0o755
        try:
            os.mkdir(component, mode, dir_fd=parent_fd)
        except FileExistsError:
            pass
        except OSError as exc:
            raise GuardError(
                f"cannot create Apache runtime directory {child_path}: {exc}"
            ) from exc
        try:
            return os.open(component, flags, dir_fd=parent_fd)
        except OSError as exc:
            raise GuardError(
                f"cannot reopen Apache runtime directory {child_path}: {exc}"
            ) from exc
    except OSError as exc:
        raise GuardError(
            f"cannot open Apache runtime directory {child_path}: {exc}"
        ) from exc


def _validate_runtime_child(
    child_fd: int, child_path: Path, label: str, is_leaf: bool, private_mode: bool
) -> None:
    metadata = os.fstat(child_fd)
    if not is_leaf:
        _safe_runtime_ancestor(metadata, child_path)
        return
    if not stat.S_ISDIR(metadata.st_mode):
        raise GuardError(f"{label} must be a directory: {child_path}")
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
        raise GuardError(
            f"{label} must be owned and not group/world writable: {child_path}"
        )
    if private_mode:
        os.fchmod(child_fd, 0o700)
        metadata = os.fstat(child_fd)
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise GuardError(f"{label} must have private mode 0700: {child_path}")


def _pidfd_available() -> bool:
    return callable(getattr(os, "pidfd_open", None)) and callable(
        getattr(signal, "pidfd_send_signal", None)
    )


def _pidfd_send_signal(fd: int, sig: int) -> None:
    signal.pidfd_send_signal(fd, sig)


def _pid_path(pid: int, name: str) -> Path:
    return PROC / str(pid) / name


def _stat(pid: int) -> dict[str, int]:
    raw = _pid_path(pid, "stat").read_text(encoding="ascii")
    close = raw.rfind(")")
    if close < 0:
        raise GuardError(f"malformed /proc/{pid}/stat")
    fields = raw[close + 2 :].split()
    # fields[0] is field 3 (state); parent/pgrp/session/starttime are fields
    # 4/5/6/22, hence indexes 1/2/3/19 in this suffix.
    try:
        return {
            "ppid": int(fields[1]),
            "pgrp": int(fields[2]),
            "session": int(fields[3]),
            "starttime": int(fields[19]),
        }
    except (IndexError, ValueError) as exc:
        raise GuardError(f"incomplete /proc/{pid}/stat") from exc


def _exe(pid: int) -> str:
    return os.path.realpath(os.readlink(_pid_path(pid, "exe")))


def _fd_inodes(pid: int) -> set[int]:
    result: set[int] = set()
    try:
        entries = os.scandir(_pid_path(pid, "fd"))
    except OSError as exc:
        raise GuardError(f"cannot inspect /proc/{pid}/fd: {exc}") from exc
    with entries:
        seen = 0
        for entry in entries:
            seen += 1
            if seen > MAX_FD_ENTRIES:
                raise GuardError("/proc fd scan exceeds bounded descriptor limit")
            try:
                target = os.readlink(entry.path)
            except OSError as exc:
                raise GuardError(f"cannot inspect {entry.path}: {exc}") from exc
            if target.startswith("socket:[") and target.endswith("]"):
                try:
                    result.add(int(target[8:-1]))
                except ValueError as exc:
                    raise GuardError(f"malformed socket descriptor {entry.path}") from exc
    return result


def _session_members(session: int, pgrp: int) -> list[int]:
    members: list[int] = []
    try:
        entries = os.scandir(PROC)
    except OSError as exc:
        raise GuardError(f"cannot scan {PROC}: {exc}") from exc
    with entries:
        seen = 0
        for entry in entries:
            seen += 1
            if seen > MAX_PROC_ENTRIES:
                raise GuardError("/proc scan exceeds bounded process-entry limit")
            if not entry.name.isdigit():
                continue
            candidate = int(entry.name)
            try:
                actual = _stat(candidate)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise GuardError(f"cannot inspect /proc/{candidate}/stat: {exc}") from exc
            if actual["session"] == session or actual["pgrp"] == pgrp:
                members.append(candidate)
    return members


def _listener_inodes(port: int) -> set[int]:
    if not 1 <= port <= 65535:
        raise GuardError("port is outside the TCP range")
    result: set[int] = set()
    for name in ("net/tcp", "net/tcp6"):
        result.update(_listener_inodes_from_file(name, f"{port:04X}"))
    return result


def _listener_inodes_from_file(name: str, wanted: str) -> set[int]:
    try:
        stream = (PROC / name).open(encoding="ascii")
    except OSError as exc:
        raise GuardError(f"cannot read {PROC / name}: {exc}") from exc
    with stream:
        try:
            next(stream)
            return _listener_inodes_from_rows(stream, name, wanted)
        except (UnicodeError, StopIteration) as exc:
            raise GuardError(f"cannot parse {name}") from exc


def _listener_inode_from_row(line: str, name: str, wanted: str) -> int | None:
    if not line.strip():
        return None
    fields = line.split()
    if len(fields) < 10:
        raise GuardError(f"malformed listener row in {name}")
    address = fields[1]
    if fields[3].upper() != LISTEN or ":" not in address:
        return None
    if address.rsplit(":", 1)[1].upper() != wanted:
        return None
    try:
        return int(fields[9])
    except ValueError as exc:
        raise GuardError(f"invalid listener inode in {name}") from exc


def _listener_inodes_from_rows(stream: Any, name: str, wanted: str) -> set[int]:
    result: set[int] = set()
    rows = 0
    total_bytes = 0
    for line in stream:
        rows += 1
        total_bytes += len(line)
        if rows > MAX_NET_ROWS or total_bytes > MAX_NET_BYTES:
            raise GuardError(f"{name} exceeds bounded listener scan")
        if len(line) > MAX_NET_LINE:
            raise GuardError(f"oversized listener row in {name}")
        inode = _listener_inode_from_row(line, name, wanted)
        if inode is not None:
            result.add(inode)
    return result


def _bounded_net_header(name: str) -> None:
    try:
        with (PROC / name).open(encoding="ascii") as stream:
            header = stream.readline(MAX_NET_LINE + 1)
    except (OSError, UnicodeError) as exc:
        raise GuardError(f"cannot read {PROC / name}: {exc}") from exc
    if not header or len(header) > MAX_NET_LINE or not header.lstrip().startswith("sl "):
        raise GuardError(f"invalid or oversized header in {name}")


def _validated_artifact_path(path: Path, artifact_root: Path) -> Path:
    """Return an absolute task artifact path with a trusted parent chain.

    Evidence is both security-sensitive input and a cleanup capability.  Do
    not follow links in any directory component, and require every existing
    directory in the chain to be owned by this process without group/world
    access.  The final file is protected separately with O_NOFOLLOW.
    """
    _validate_artifact_paths(path, artifact_root)
    root = _resolve_artifact_root(artifact_root)
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise GuardError("Apache artifact path is outside the trusted artifact root") from exc
    if not relative.parts or relative.name in ("", ".", ".."):
        raise GuardError("Apache artifact path is not a file below the trusted artifact root")
    _validate_private_artifact_root(root)
    current = root
    for component in relative.parts[:-1]:
        current = current / component
        _validate_private_artifact_directory(current)
    return path


def _validate_artifact_paths(path: Path, artifact_root: Path) -> None:
    if not path.is_absolute() or not artifact_root.is_absolute():
        raise GuardError("Apache artifact path must be absolute")
    if any(
        component in (".", "..")
        for component in (*path.parts, *artifact_root.parts)
    ):
        raise GuardError("Apache artifact path must not contain parent traversal")


def _resolve_artifact_root(artifact_root: Path) -> Path:
    try:
        root = artifact_root.resolve(strict=True)
    except OSError as exc:
        raise GuardError(
            f"cannot resolve trusted Apache artifact root {artifact_root}: {exc}"
        ) from exc
    if root != artifact_root:
        raise GuardError("trusted Apache artifact root must not contain symlinks")
    return root


def _validate_private_artifact_root(root: Path) -> None:
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise GuardError(f"cannot inspect trusted Apache artifact root {root}: {exc}") from exc
    if not root.is_dir() or root.is_symlink() or root_info.st_uid != os.getuid() or root_info.st_mode & 0o077:
        raise GuardError("trusted Apache artifact root is not a private directory")


def _validate_private_artifact_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise GuardError(f"cannot inspect Apache artifact directory {path}: {exc}") from exc
    if not path.is_dir() or path.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise GuardError(f"Apache artifact directory is not a private directory: {path}")


def _open_artifact_parent(path: Path, artifact_root: Path) -> tuple[int, str]:
    """Open an artifact's validated private parent and return its leaf name."""
    path = _validated_artifact_path(path, artifact_root)
    parent_flags = _directory_open_flags()
    try:
        parent_fd = os.open(artifact_root, parent_flags)
    except OSError as exc:
        raise GuardError(f"cannot open Apache artifact directory {path.parent}: {exc}") from exc
    try:
        relative = path.relative_to(artifact_root)
        for component in relative.parts[:-1]:
            next_fd = os.open(component, parent_flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        return parent_fd, relative.name
    except OSError as exc:
        os.close(parent_fd)
        raise GuardError(f"cannot open Apache artifact directory {path.parent}: {exc}") from exc


def _open_artifact(path: Path, artifact_root: Path, flags: int, mode: int = 0) -> int:
    """Open an already validated artifact relative to its private parent.

    Keeping the untrusted CLI value out of the final ``open`` call prevents
    path injection after the parent boundary has been checked.  ``O_NOFOLLOW``
    protects the artifact itself; the parent validation protects the directory
    namespace used by the guard.
    """
    parent_fd, name = _open_artifact_parent(path, artifact_root)
    try:
        return os.open(name, flags, mode, dir_fd=parent_fd)
    except OSError as exc:
        raise GuardError(f"cannot open Apache artifact {path}: {exc}") from exc
    finally:
        os.close(parent_fd)


def _load(path: Path, artifact_root: Path) -> dict[str, Any]:
    flags = os.O_RDONLY
    # O_NONBLOCK makes opening a FIFO or other special file non-blocking so
    # that the descriptor can be rejected after fstat().  It is harmless for
    # regular files and avoids trusting the path type before opening it.
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = _open_artifact(path, artifact_root, flags)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise GuardError("Apache guard evidence must be a regular file")
            if metadata.st_size > MAX_EVIDENCE_BYTES:
                raise GuardError("Apache guard evidence exceeds bounded size")
            payload = bytearray()
            while len(payload) <= MAX_EVIDENCE_BYTES:
                chunk = os.read(fd, min(65536, MAX_EVIDENCE_BYTES + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
            if len(payload) > MAX_EVIDENCE_BYTES:
                raise GuardError("Apache guard evidence exceeds bounded size")
        finally:
            os.close(fd)
        value = json.loads(bytes(payload).decode("utf-8"))
    except (GuardError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GuardError(f"cannot read guard evidence {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise GuardError("guard evidence is not an object")
    return value


def _identity(evidence: dict[str, Any]) -> tuple[int, str, dict[str, int]]:
    try:
        pid = int(evidence["pid"])
        expected_exe = os.path.realpath(str(evidence["executable"]))
        expected = {
            key: int(evidence[key])
            for key in ("starttime", "session", "pgrp")
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise GuardError("guard evidence lacks a complete process identity") from exc
    if pid <= 1 or not expected_exe.startswith("/"):
        raise GuardError("invalid recorded process identity")
    return pid, expected_exe, expected


def _open_verified_pidfd(evidence: dict[str, Any]) -> tuple[int, int, str, dict[str, int]]:
    if not _pidfd_available():
        raise GuardError("Linux pidfd support is unavailable")
    pid, expected_exe, expected = _identity(evidence)
    try:
        fd = os.pidfd_open(pid)
    except OSError as exc:
        raise GuardError(f"cannot open Apache pidfd: {exc}") from exc
    try:
        if _pidfd_bound_pid(fd) != pid:
            raise GuardError("pidfd is not bound to the recorded PID")
    except (GuardError, OSError, ValueError) as exc:
        try:
            os.close(fd)
        except OSError as close_exc:
            raise GuardError(
                f"cannot verify Apache pidfd binding and cannot close pidfd: {close_exc}"
            ) from exc
        if isinstance(exc, GuardError):
            raise
        raise GuardError(f"cannot verify Apache pidfd binding: {exc}") from exc
    return fd, pid, expected_exe, expected


def _pidfd_bound_pid(fd: int) -> int:
    fdinfo = Path(f"/proc/self/fdinfo/{fd}").read_text(encoding="ascii")
    for line in fdinfo.splitlines():
        if line.startswith("Pid:"):
            return int(line.split(":", 1)[1].strip())
    raise GuardError("pidfd fdinfo has no PID binding")


def verify_running(evidence: dict[str, Any]) -> None:
    pid, expected_exe, expected = _identity(evidence)
    try:
        actual = _stat(pid)
        actual_exe = _exe(pid)
        fds = _fd_inodes(pid)
    except OSError as exc:
        raise GuardError(f"process identity is unavailable: {exc}") from exc
    if any(actual.get(key) != value for key, value in expected.items()) or actual_exe != expected_exe:
        raise GuardError("Apache PID identity changed (possible PID reuse)")
    try:
        port = int(evidence["port"])
        recorded = {int(item) for item in evidence["listener_inodes"]}
    except (KeyError, TypeError, ValueError) as exc:
        raise GuardError("guard evidence lacks listener ownership") from exc
    current = _listener_inodes(port)
    if not recorded or not recorded.issubset(current) or not recorded.issubset(fds):
        raise GuardError("Apache listener ownership cannot be proven")


def verify_stopped(evidence: dict[str, Any], pidfile: str | None = None) -> None:
    pid, _, expected = _identity(evidence)
    if (_pid_path(pid, "stat")).exists():
        raise GuardError(f"Apache process still exists: {pid}")
    try:
        listeners = _listener_inodes(int(evidence["port"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise GuardError("guard evidence lacks a valid listener port") from exc
    if listeners:
        raise GuardError("a listener remains on the selected Apache port")
    members = _session_members(expected["session"], expected["pgrp"])
    if members:
        raise GuardError(f"Apache session/process-group members remain: {members}")
    if pidfile and Path(pidfile).exists():
        raise GuardError(f"Apache pidfile remains after cleanup: {pidfile}")


def _write_all(fd: int, payload: bytes) -> None:
    """Write a bounded evidence payload completely or fail closed."""
    view = memoryview(payload)
    offset = 0
    while offset < len(view):
        try:
            written = os.write(fd, view[offset:])
        except OSError as exc:
            raise GuardError(f"cannot write Apache guard evidence: {exc}") from exc
        if written <= 0:
            raise GuardError("cannot write Apache guard evidence: write made no progress")
        offset += written


def _record_failure_runtime_quiesced(
    evidence: dict[str, Any], leader_exit_confirmed: bool
) -> None:
    """Prove that a failed evidence publication retained no live runtime."""
    pid, _, expected = _identity(evidence)
    try:
        port = int(evidence["port"])
    except (KeyError, TypeError, ValueError) as exc:
        raise GuardError("record cleanup lacks a valid listener port") from exc
    if _listener_inodes(port):
        raise GuardError("Apache listener remains after failed evidence publication")
    members = _session_members(expected["session"], expected["pgrp"])
    if leader_exit_confirmed:
        members = [member for member in members if member != pid]
    elif _pid_path(pid, "stat").exists():
        raise GuardError("Apache process remains after failed evidence publication")
    if members:
        raise GuardError(
            f"Apache session/process-group members remain after failed evidence publication: {members}"
        )


def _terminate_after_record_failure(evidence: dict[str, Any]) -> None:
    """Use the in-memory verified identity when persistence itself fails."""
    leader_exit_confirmed = False
    termination_error: GuardError | None = None
    try:
        terminate_verified(evidence)
        leader_exit_confirmed = True
    except GuardError as exc:
        termination_error = exc
    try:
        _record_failure_runtime_quiesced(evidence, leader_exit_confirmed)
    except GuardError as exc:
        if termination_error is None:
            raise
        raise GuardError(
            f"cannot terminate Apache after failed evidence publication: "
            f"{termination_error}; {exc}"
        ) from exc


def _capture_record_payload(
    pid: int, expected_exe: str, port: int
) -> tuple[dict[str, Any], GuardError | OSError | None]:
    """Capture one stable ownership snapshot with bounded transient retries."""
    inspection_error: GuardError | OSError | None = None
    for attempt in range(RECORD_INSPECTION_ATTEMPTS):
        try:
            process_stat = _stat(pid)
            actual_exe = _exe(pid)
            fds = _fd_inodes(pid)
            listeners = _listener_inodes(port)
        except (GuardError, OSError) as exc:
            inspection_error = exc
        else:
            if actual_exe != expected_exe:
                raise GuardError("started process executable does not match Apache binary")
            owned = sorted(fds & listeners)
            if owned:
                return {
                    "pid": pid,
                    "executable": actual_exe,
                    "starttime": process_stat["starttime"],
                    "session": process_stat["session"],
                    "pgrp": process_stat["pgrp"],
                    "port": port,
                    "listener_inodes": owned,
                    "task_socket_inodes": sorted(fds),
                    "pidfd_supported": _pidfd_available(),
                }, inspection_error
            inspection_error = GuardError(
                "started Apache process does not own the selected listener"
            )
        if attempt + 1 < RECORD_INSPECTION_ATTEMPTS:
            time.sleep(RECORD_INSPECTION_RETRY_SECONDS)
    raise GuardError(
        f"cannot obtain stable Apache ownership evidence: {inspection_error}"
    ) from inspection_error


def _temporary_evidence_flags() -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _open_temporary_evidence(parent_fd: int, flags: int) -> tuple[int, str]:
    for _ in range(TEMPORARY_ARTIFACT_ATTEMPTS):
        candidate = f".apache-process-guard-{secrets.token_hex(16)}.tmp"
        try:
            return os.open(candidate, flags, 0o600, dir_fd=parent_fd), candidate
        except FileExistsError:
            continue
    raise GuardError("cannot create a unique temporary Apache evidence file")


def _rollback_record_artifacts(
    parent_fd: int,
    output_name: str,
    temporary_fd: int,
    temporary_name: str | None,
    published: bool,
) -> list[str]:
    cleanup_errors: list[str] = []
    if temporary_fd >= 0:
        try:
            os.close(temporary_fd)
        except OSError as exc:
            cleanup_errors.append(f"temporary evidence close failed: {exc}")
    if parent_fd < 0:
        cleanup_errors.append("Apache evidence parent could not be opened")
        return cleanup_errors
    if temporary_name is not None:
        cleanup_errors.extend(_unlink_if_present(
            temporary_name, parent_fd, "temporary evidence removal failed"
        ))
    if published:
        cleanup_errors.extend(_unlink_if_present(
            output_name, parent_fd, "published evidence rollback failed"
        ))
    absence_error = _check_absent(output_name, parent_fd)
    if absence_error is not None:
        cleanup_errors.append(absence_error)
    return cleanup_errors


def _unlink_if_present(name: str, parent_fd: int, error_prefix: str) -> list[str]:
    try:
        os.unlink(name, dir_fd=parent_fd)
    except FileNotFoundError:
        return []
    except OSError as exc:
        return [f"{error_prefix}: {exc}"]
    return []


def _check_absent(name: str, parent_fd: int) -> str | None:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"cannot verify evidence rollback: {exc}"
    return "Apache evidence path remains after rollback"


def _publish_record_payload(
    payload: dict[str, Any], output: Path, artifact_root: Path
) -> None:
    encoded = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
    flags = _temporary_evidence_flags()
    parent_fd = -1
    output_name = ""
    temporary_fd = -1
    temporary_name: str | None = None
    published = False
    try:
        parent_fd, output_name = _open_artifact_parent(output, artifact_root)
        temporary_fd, temporary_name = _open_temporary_evidence(parent_fd, flags)
        _write_all(temporary_fd, encoded)
        # This guard is Linux-only because its termination authority is pidfd.
        # Linux releases a descriptor before reporting any delayed close error;
        # relinquish the number first because retrying close could target a
        # descriptor that another thread or signal handler has already reused.
        closing_fd = temporary_fd
        temporary_fd = -1
        os.close(closing_fd)
        os.link(
            temporary_name,
            output_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
        published = True
        os.unlink(temporary_name, dir_fd=parent_fd)
        temporary_name = None
    except (GuardError, OSError) as exc:
        cleanup_errors = _rollback_record_artifacts(
            parent_fd,
            output_name,
            temporary_fd,
            temporary_name,
            published,
        )
        try:
            _terminate_after_record_failure(payload)
        except GuardError as cleanup_exc:
            cleanup_errors.append(str(cleanup_exc))
        if cleanup_errors:
            raise GuardError(
                f"cannot publish non-overwriting Apache evidence: {exc}; "
                f"cleanup incomplete: {'; '.join(cleanup_errors)}"
            ) from exc
        raise RecordFailureCleaned(
            f"cannot publish non-overwriting Apache evidence: {exc}; "
            "verified Apache cleanup completed"
        ) from exc
    finally:
        if parent_fd >= 0:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def _publish_supervisor_state(
    payload: dict[str, Any], output: Path, artifact_root: Path
) -> os.stat_result:
    """Publish launch state atomically without a pathname control socket."""
    encoded = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
    parent_fd = -1
    temporary_fd = -1
    temporary_name: str | None = None
    temporary_identity: os.stat_result | None = None
    owned_identity: os.stat_result | None = None
    try:
        parent_fd, output_name = _open_artifact_parent(output, artifact_root)
        temporary_fd, temporary_name = _open_temporary_evidence(parent_fd, _temporary_evidence_flags())
        _write_all(temporary_fd, encoded)
        temporary_identity = os.fstat(temporary_fd)
        owned_identity = temporary_identity
        closing_fd = temporary_fd
        temporary_fd = -1
        os.close(closing_fd)
        os.link(temporary_name, output_name, src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd, follow_symlinks=False)
        current = os.stat(output_name, dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (
                temporary_identity.st_dev, temporary_identity.st_ino):
            raise GuardError("Apache supervisor state inode changed during publication")
        os.unlink(temporary_name, dir_fd=parent_fd)
        temporary_name = None
        return owned_identity
    except (GuardError, OSError) as exc:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if parent_fd >= 0 and temporary_name is not None and temporary_identity is not None:
            _remove_owned_name(parent_fd, temporary_name, temporary_identity)
        if parent_fd >= 0 and owned_identity is not None:
            _remove_owned_name(parent_fd, output_name, owned_identity)
        raise GuardError(f"cannot publish Apache supervisor state: {exc}") from exc
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)


def _remove_owned_name(
    parent_fd: int, name: str, expected: os.stat_result
) -> None:
    """Remove a publication artifact only when its inode is still ours."""
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino):
            os.unlink(name, dir_fd=parent_fd)
    except OSError:
        pass


def record(pid: int, executable: str, port: int, output: Path, artifact_root: Path) -> None:
    payload, inspection_error = _capture_record_payload(
        pid, os.path.realpath(executable), port
    )
    if inspection_error is not None:
        try:
            _terminate_after_record_failure(payload)
        except GuardError as cleanup_exc:
            raise GuardError(
                f"Apache ownership inspection was unstable: {inspection_error}; "
                f"cleanup incomplete: {cleanup_exc}"
            ) from cleanup_exc
        raise RecordFailureCleaned(
            f"Apache ownership inspection was unstable: {inspection_error}; "
            "verified Apache cleanup completed"
        ) from inspection_error
    _publish_record_payload(payload, output, artifact_root)


def signal_verified(evidence: dict[str, Any], sig: int) -> str:
    fd, _, _, _ = _open_verified_pidfd(evidence)
    try:
        verify_running(evidence)
        _pidfd_send_signal(fd, sig)
    finally:
        os.close(fd)
    return "pidfd"


def _poll_pidfd(fd: int, timeout: float) -> bool:
    poller = select.poll()
    poller.register(fd, select.POLLIN | select.POLLHUP)
    return bool(poller.poll(int(timeout * 1000)))


def terminate_verified(evidence: dict[str, Any]) -> str:
    fd, _, _, _ = _open_verified_pidfd(evidence)
    try:
        verify_running(evidence)
        _pidfd_send_signal(fd, int(signal.SIGTERM))
        if not _poll_pidfd(fd, TERM_TIMEOUT):
            _pidfd_send_signal(fd, int(signal.SIGKILL))
            if not _poll_pidfd(fd, KILL_TIMEOUT):
                raise GuardError("verified Apache process did not exit within bounded cleanup")
    finally:
        os.close(fd)
    return "pidfd-term-kill"


def verify_pidfile(evidence: dict[str, Any], pid: int) -> None:
    recorded, _, _ = _identity(evidence)
    if recorded != pid:
        raise GuardError("Apache pidfile PID does not match recorded evidence")


def preflight() -> None:
    if not PROC.is_dir():
        raise GuardError("/proc is unavailable")
    if not _pidfd_available():
        raise GuardError("Linux pidfd support is unavailable")
    try:
        fd = os.pidfd_open(os.getpid())
    except OSError as exc:
        raise GuardError(f"cannot open self pidfd: {exc}") from exc
    try:
        if _pidfd_bound_pid(fd) != os.getpid():
            raise GuardError("self pidfd binding is incorrect")
        _pidfd_send_signal(fd, 0)
    except (OSError, ValueError) as exc:
        raise GuardError(f"self pidfd validation failed: {exc}") from exc
    finally:
        try:
            os.close(fd)
        except OSError as exc:
            raise GuardError(f"cannot close self pidfd: {exc}") from exc
    for name in ("net/tcp", "net/tcp6"):
        _bounded_net_header(name)


def _execute_command(args: argparse.Namespace) -> int:
    if args.command == "prepare-directory":
        prepare_runtime_directory(
            _runner_configured_path(RUNNER_DIRECTORY_ENV, "Apache runtime directory"),
            args.label,
            args.private,
        )
    elif args.command == "record":
        record(
            args.pid,
            args.executable,
            args.port,
            args.output,
            _runner_configured_path(RUNNER_ARTIFACT_ROOT_ENV, APACHE_ARTIFACT_ROOT_LABEL),
        )
    elif args.command == "supervise":
        artifact_root = _runner_configured_path(
            RUNNER_ARTIFACT_ROOT_ENV, APACHE_ARTIFACT_ROOT_LABEL
        )
        httpd = _runner_configured_path(RUNNER_HTTPD_ENV, APACHE_EXECUTABLE_LABEL)
        return supervise(
            httpd,
            artifact_root / "conf" / "httpd.conf",
            args.state,
            args.pid_output,
        )
    elif args.command == "stop-supervisor":
        stop_supervisor(
            args.state,
            _runner_configured_path(RUNNER_ARTIFACT_ROOT_ENV, APACHE_ARTIFACT_ROOT_LABEL),
        )
    elif args.command == "retire-supervisor-artifact":
        retire_supervisor_session(
            args.state, args.pid_output,
            _runner_configured_path(RUNNER_ARTIFACT_ROOT_ENV, APACHE_ARTIFACT_ROOT_LABEL),
        )
    elif args.command == "verify-running":
        verify_running(
            _load(
                args.evidence,
                _runner_configured_path(RUNNER_ARTIFACT_ROOT_ENV, APACHE_ARTIFACT_ROOT_LABEL),
            )
        )
    elif args.command == "signal":
        print(
            signal_verified(
                _load(
                    args.evidence,
                    _runner_configured_path(RUNNER_ARTIFACT_ROOT_ENV, APACHE_ARTIFACT_ROOT_LABEL),
                ),
                args.signal,
            )
        )
    elif args.command == "terminate":
        print(
            terminate_verified(
                _load(
                    args.evidence,
                    _runner_configured_path(RUNNER_ARTIFACT_ROOT_ENV, APACHE_ARTIFACT_ROOT_LABEL),
                )
            )
        )
    elif args.command == "verify-pid":
        verify_pidfile(
            _load(
                args.evidence,
                _runner_configured_path(RUNNER_ARTIFACT_ROOT_ENV, APACHE_ARTIFACT_ROOT_LABEL),
            ),
            args.pid,
        )
    elif args.command == "preflight":
        preflight()
    else:
        verify_stopped(
            _load(
                args.evidence,
                _runner_configured_path(RUNNER_ARTIFACT_ROOT_ENV, APACHE_ARTIFACT_ROOT_LABEL),
            ),
            args.pidfile,
        )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare-directory")
    prepare.add_argument("--label", required=True)
    prepare.add_argument("--private", action="store_true")
    rec = sub.add_parser("record")
    rec.add_argument("--pid", type=int, required=True)
    rec.add_argument("--executable", required=True)
    rec.add_argument("--port", type=int, required=True)
    rec.add_argument("--output", type=Path, required=True)
    supervisor = sub.add_parser("supervise")
    supervisor.add_argument("--state", type=Path, required=True)
    supervisor.add_argument("--pid-output", type=Path, required=True)
    stop = sub.add_parser("stop-supervisor")
    stop.add_argument("--state", type=Path, required=True)
    retire = sub.add_parser("retire-supervisor-artifact")
    retire.add_argument("--state", type=Path, required=True)
    retire.add_argument("--pid-output", type=Path, required=True)
    for name in ("verify-running", "signal", "terminate", "verify-stopped", "verify-pid", "preflight"):
        command = sub.add_parser(name)
        if name not in ("preflight",):
            command.add_argument("--evidence", type=Path, required=True)
        command.add_argument("--pidfile")
        if name in ("signal", "terminate"):
            command.add_argument("--signal", type=int, default=int(signal.SIGTERM))
        if name == "verify-pid":
            command.add_argument("--pid", type=int, required=True)
    args = parser.parse_args()
    try:
        return _execute_command(args)
    except RecordFailureCleaned as exc:
        print(f"apache_process_guard: blocked {exc}")
        return RECORD_FAILURE_CLEANED_EXIT
    except GuardError as exc:
        print(f"apache_process_guard: blocked {exc}")
        return 77
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
