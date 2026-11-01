"""Bounded Linux execution-context probes; no runtime support claims.

Only explicit profile requirements are tested. Identity-sensitive operations run
in a forked child after a verified credential transition. Directory-search
checks use that child's effective credentials against pinned directory inodes.
"""
from __future__ import annotations

import errno
import grp
import json
import os
import pwd
import select
import signal
import socket
import stat
import tempfile
import time
from pathlib import Path

from modsecurity_connector_ci.lib.runtime_path_utils import verified_runtime_artifact_root

MAX_ITEMS = 64
MAX_PROC_BYTES = 16384
MAX_REPORT_BYTES = 32768


def check(name, reason, passed=True):
    return {"name": name[:80], "status": "PASS" if passed else "BLOCKED",
            "reason_code": reason[:100], "remediation": "No action required." if passed
            else "Use an execution context satisfying the declared profile requirements."}


def _proc_text(name):
    with open("/proc/self/" + name, encoding="ascii") as stream:
        value = stream.read(MAX_PROC_BYTES + 1)
    if len(value) > MAX_PROC_BYTES:
        raise ValueError("execution_context_metadata_limit")
    return value


def snapshot():
    """Return bounded non-secret process metadata, independent of requirements."""
    status = {}
    for line in _proc_text("status").splitlines():
        key, _, value = line.partition(":")
        if key in {"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp"}:
            status[key] = value.strip()
    groups = os.getgroups()
    if len(groups) > MAX_ITEMS:
        raise ValueError("execution_context_group_limit")
    return {"uid": list(os.getresuid()), "gid": list(os.getresgid()), "groups": groups,
            "uid_map": _proc_text("uid_map").splitlines(),
            "gid_map": _proc_text("gid_map").splitlines(),
            "user_namespace": os.readlink("/proc/self/ns/user"), "security": status,
            "container": {"dockerenv": Path("/.dockerenv").exists(),
                          "containerenv": Path("/run/.containerenv").exists(),
                          "cgroup_markers": [name for name in ("docker", "kubepods", "containerd", "lxc")
                                             if name in _proc_text("cgroup")]}}


def mapped(identity, lines):
    try:
        return any(start <= identity < start + count
                   for start, _outside, count in (map(int, line.split()) for line in lines))
    except (TypeError, ValueError):
        return False


def resolve_worker(user, group):
    """Match initgroups semantics when an NSS username exists."""
    entry = None
    if user is None:
        if group is not None:
            raise ValueError("worker_user_required")
        return os.geteuid(), os.getegid(), sorted(os.getgroups()), False
    try:
        entry = pwd.getpwuid(int(user)) if str(user).isdigit() else pwd.getpwnam(user)
    except KeyError:
        if not str(user).isdigit():
            raise ValueError("worker_user_unresolved") from None
    uid = entry.pw_uid if entry else int(user)
    if group is None:
        if entry is None:
            raise ValueError("worker_group_required")
        gid = entry.pw_gid
    else:
        try:
            gid = int(group) if str(group).isdigit() else grp.getgrnam(group).gr_gid
        except KeyError:
            raise ValueError("worker_group_unresolved") from None
    groups = sorted(set(os.getgrouplist(entry.pw_name, gid))) if entry else [gid]
    if not 0 <= uid < 2**32 - 1 or not 0 <= gid < 2**32 - 1 or len(groups) > MAX_ITEMS:
        raise ValueError("worker_identity_invalid")
    transition = (list(os.getresuid()) != [uid] * 3 or list(os.getresgid()) != [gid] * 3
                  or sorted(os.getgroups()) != groups)
    return uid, gid, groups, transition


def _open_path(value, flags):
    """Pin every component, rejecting symlinks including intermediate links."""
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("worker_path_untrusted")
    descriptor = os.open("/", os.O_PATH | os.O_DIRECTORY)
    try:
        for index, part in enumerate(path.parts[1:]):
            last = index == len(path.parts) - 2
            new = os.open(part, (flags if last else os.O_PATH | os.O_DIRECTORY) | os.O_NOFOLLOW,
                          dir_fd=descriptor)
            os.close(descriptor)
            descriptor = new
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _path_probe(kind, value):
    descriptor = -1
    name = ".execution-probe-" + os.urandom(12).hex()
    created = False
    try:
        descriptor = _open_path(value, os.O_PATH | os.O_DIRECTORY if kind == "write"
                                else os.O_PATH if kind == "deny" else os.O_RDONLY | os.O_NONBLOCK)
        details = os.fstat(descriptor)
        if kind == "deny":
            if stat.S_ISDIR(details.st_mode):
                # This runs only after the child's credentials were verified.
                # Test traversal of the pinned inode, not directory listing.
                if not os.access(".", os.X_OK, dir_fd=descriptor, effective_ids=True):
                    raise PermissionError(errno.EACCES, "directory traversal denied")
            elif stat.S_ISREG(details.st_mode):
                readable = os.open(f"/proc/self/fd/{descriptor}", os.O_RDONLY | os.O_NONBLOCK)
                os.close(readable)
            else:
                raise ValueError("worker_path_type_untrusted")
        elif kind == "write":
            if not stat.S_ISDIR(details.st_mode):
                raise ValueError("worker_write_requires_directory")
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=descriptor)
            created = True
            try:
                os.write(fd, b"probe\n")
            finally:
                os.close(fd)
        elif stat.S_ISREG(details.st_mode):
            os.read(descriptor, 1)
        elif stat.S_ISDIR(details.st_mode):
            os.listdir(descriptor)
        else:
            raise ValueError("worker_path_type_untrusted")
    except PermissionError:
        return check("worker-" + kind + ":" + Path(value).name, "worker_denial_verified" if kind == "deny"
                     else "worker_" + kind + "_denied", kind == "deny")
    except (OSError, ValueError):
        return check("worker-" + kind + ":" + Path(value).name, "worker_path_unavailable_or_untrusted", False)
    finally:
        if created:
            os.unlink(name, dir_fd=descriptor)
        if descriptor >= 0:
            os.close(descriptor)
    return check("worker-" + kind + ":" + Path(value).name, "worker_deny_unenforced" if kind == "deny"
                 else "worker_" + kind + "_verified", kind != "deny")


def _socket_probe(path, root, timeout):
    descriptor = -1
    bound = False
    try:
        value = Path(path)
        if not value.is_absolute() or ".." in value.parts or not value.is_relative_to(root):
            return check("uds", "uds_path_untrusted", False)
        if len(os.fsencode(value)) >= 108:
            return check("uds", "uds_path_too_long", False)
        descriptor = _open_path(value.parent, os.O_PATH | os.O_DIRECTORY)
        details = os.fstat(descriptor)
        if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077:
            return check("uds", "uds_parent_not_private", False)
        # A pinned private directory and a fresh socket name prevent redirection.
        with socket.socket(socket.AF_UNIX) as server, socket.socket(socket.AF_UNIX) as client:
            server.settimeout(timeout)
            client.settimeout(timeout)
            pinned_path = f"/proc/self/fd/{descriptor}/{value.name}"
            server.bind(pinned_path)
            bound = True
            server.listen(1)
            current_parent = os.stat(value.parent, follow_symlinks=False)
            if (current_parent.st_dev, current_parent.st_ino) != (details.st_dev, details.st_ino):
                raise ValueError("uds parent changed")
            # Exercise the caller's actual pathname too, including path-based
            # security policy; procfd pinning protects only the server bind.
            client.connect(str(value))
            connection, _ = server.accept()
            with connection:
                connection.settimeout(timeout)
                client.sendall(b"x")
                if connection.recv(1) != b"x":
                    raise OSError("uds round trip failed")
        return check("uds", "uds_bind_connect_verified")
    except (OSError, ValueError):
        return check("uds", "uds_bind_connect_unavailable", False)
    finally:
        if bound:
            os.unlink(value.name, dir_fd=descriptor)
        if descriptor >= 0:
            os.close(descriptor)


def _child_probes(args, root, worker):
    uid, gid, groups, transition = worker
    if transition:
        os.setgroups(groups)
        os.setgid(gid)
        os.setuid(uid)
    identity = {"uid": list(os.getresuid()), "gid": list(os.getresgid()), "groups": sorted(os.getgroups())}
    expected_uid = [uid] * 3 if transition else list(os.getresuid())
    expected_gid = [gid] * 3 if transition else list(os.getresgid())
    if identity != {"uid": expected_uid, "gid": expected_gid, "groups": groups}:
        return {"checks": [check("worker-transition", "worker_identity_mismatch", False)]}
    checks = [check("worker-transition", "worker_identity_verified")]
    for kind in ("read", "write", "deny"):
        checks.extend(_path_probe(kind, path) for path in getattr(args, "worker_" + kind))
    if args.uds_path:
        checks.append(_socket_probe(args.uds_path, args.uds_root or root, args.timeout))
    for port in args.port:
        try:
            if not 1 <= port <= 65535:
                raise ValueError("invalid port")
            with socket.socket() as listener:
                listener.settimeout(args.timeout)
                listener.bind(("127.0.0.1", port))
            checks.append(check("port:" + str(port), "port_bind_verified"))
        except (OSError, ValueError):
            checks.append(check("port:" + str(port), "port_bind_unavailable", False))
    return {"identity": identity, "checks": checks}


def _fork_probe(args, root, worker):
    reader, writer = os.pipe()
    try:
        child = os.fork()
    except OSError:
        os.close(reader)
        os.close(writer)
        raise
    if child == 0:
        os.close(reader)
        try:
            result = _child_probes(args, root, worker)
        except (OSError, ValueError):
            result = {"checks": [check("worker-transition", "worker_transition_unavailable", False)]}
        payload = json.dumps(result).encode()
        if len(payload) <= MAX_REPORT_BYTES:
            view = memoryview(payload)
            while view:
                view = view[os.write(writer, view):]
        os.close(writer)
        os._exit(0)
    os.close(writer)
    deadline = time.monotonic() + args.timeout
    payload = bytearray()
    reaped = False
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([reader], [], [], max(0, deadline - time.monotonic()))
            if not ready:
                break
            chunk = os.read(reader, 4096)
            if not chunk:
                while time.monotonic() < deadline:
                    observed, status = os.waitpid(child, os.WNOHANG)
                    if observed:
                        reaped = True
                        if status == 0 and payload:
                            return json.loads(payload)
                        break
                    time.sleep(0.005)
                break
            payload.extend(chunk)
            if len(payload) > MAX_REPORT_BYTES:
                break
        return {"checks": [check("worker-probes", "worker_probe_timeout_or_invalid", False)]}
    finally:
        os.close(reader)
        if not reaped:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(child, 0)


def execution_context(args, runtime_root):
    checks = []
    try:
        root = verified_runtime_artifact_root(runtime_root)
        if getattr(args, "uds_root", None) is not None:
            args.uds_root = verified_runtime_artifact_root(args.uds_root)
        metadata = snapshot()
        worker = resolve_worker(args.worker_user, args.worker_group)
    except (OSError, ValueError) as exc:
        reason = str(exc) if isinstance(exc, ValueError) else "execution_context_unavailable"
        return {}, [check("execution-context", reason, False)]
    metadata["requested_worker"] = {"uid": worker[0], "gid": worker[1], "groups": worker[2]}
    requirements = sum(len(getattr(args, "worker_" + kind)) for kind in ("read", "write", "deny")) + len(args.port)
    if requirements > 48:
        return metadata, [check("execution-context", "execution_context_requirement_limit", False)]
    if args.require_root_master:
        checks.append(check("root-master", "root_master_verified" if os.geteuid() == 0
                            else "root_master_required", os.geteuid() == 0))
    maps_ok = mapped(worker[0], metadata["uid_map"]) and all(
        mapped(gid, metadata["gid_map"]) for gid in [worker[1], *worker[2]])
    checks.append(check("worker-mapping", "worker_identity_mapped" if maps_ok else "worker_identity_unmapped", maps_ok))
    caps = int(metadata["security"].get("CapEff", "0"), 16)
    if worker[3]:
        caps_ok = bool(caps & (1 << 6)) and bool(caps & (1 << 7))
        checks.append(check("worker-capabilities", "worker_transition_capabilities_present" if caps_ok
                            else "worker_transition_capabilities_missing", caps_ok))
    if args.require_chown:
        if not caps & 1:
            checks.append(check("chown-capability", "chown_capability_missing", False))
            return metadata, checks
        try:
            with tempfile.TemporaryDirectory(prefix=".ec-", dir=root) as probe:
                with tempfile.TemporaryFile(dir=probe) as stream:
                    os.fchown(stream.fileno(), worker[0], worker[1])
                    details = os.fstat(stream.fileno())
                    passed = (details.st_uid, details.st_gid) == worker[:2]
            checks.append(check("chown", "chown_verified" if passed else "chown_unavailable", passed))
        except OSError:
            checks.append(check("chown", "chown_unavailable", False))
    if any(item["status"] == "BLOCKED" for item in checks):
        return metadata, checks
    try:
        result = _fork_probe(args, root, worker)
    except (OSError, ValueError):
        return metadata, checks + [check("worker-probes", "worker_probe_unavailable", False)]
    metadata["observed_worker"] = result.get("identity", {})
    checks.extend(result["checks"])
    return metadata, checks
