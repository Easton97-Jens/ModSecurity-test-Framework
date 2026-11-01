#!/usr/bin/env python3
"""Exercise the pinned Traefik local-plugin UDS engine route without promotion.

The runner stages the repository-owned local plugin beneath Traefik's
``plugins-local`` workspace, starts the pinned binary with a File Provider,
and sends bounded body-bearing requests through a router that explicitly
selects the plugin. The plugin talks once per request to a persistent local
Common/libmodsecurity Unix-domain-socket service. The result retains actual
host status/event artifacts but never changes checked-in capability state.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import contextlib
import http.client
import http.server
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator


class MissingDependency(RuntimeError):
    """A required local host prerequisite is unavailable before execution."""


REPO_ROOT = connector_root()
PLUGIN_SOURCE = source_path('connectors/traefik/native_middleware', root=REPO_ROOT)
PLUGIN_ID = "modsecurityNative"
REQUEST_BODY = b"native-traefik-request-body"
P2_BODY = b"no-crs-request-body-marker"
P1_ALLOW_TRANSACTION_ID = "traefik-native-p1-allow"
NATIVE_REQUEST_PATH = "/native"
PLAIN_TEXT_CONTENT_TYPE = "text/plain"
CRS_ALLOW_PATH = "/?id=42"
CRS_BLOCK_PATH = "/?id=1%20UNION%20SELECT%20password%20FROM%20users"
CRS_BYPASS_PATH = "/?id=1%20union%20select%20password%20from%20users"
CRS_RUNTIME_HOST = "crs-runtime.test"
CRS_RUNTIME_RUN_ID_MAX_LENGTH = 48
CRS_RULE_ID = "942270"
CRS_INTERVENTION_RULE_ID = "949110"
ENGINE_BUILD_SCRIPT = source_path('connectors/traefik/build/build-engine-service.sh', root=REPO_ROOT)
STANDALONE_ENGINE_RULES = source_path('connectors/traefik/config/traefik-native-engine-rules.conf', root=REPO_ROOT)

CANONICAL_RULE_IDS = {
    "p1": "1100001",
    "p1_alternative": "1100002",
    "p2": "1100101",
    "p3": "1100201",
    "p4": "1100301",
}
STANDALONE_RULE_IDS = {
    "p1": "1000001",
    "p1_alternative": "1000005",
    "p2": "1000002",
    "p3": "1000003",
    "p4": "1000004",
}
ENGINE_SOCKET_DIRECTORY_PREFIX = "msconnector-traefik-uds-"
ENGINE_SOCKET_PARENT_ENV = "TRAEFIK_ENGINE_SOCKET_PARENT"
FIRST_BYTE_EVIDENCE_ROOT_ENV = "TRAEFIK_FIRST_BYTE_EVIDENCE_ROOT"
FIRST_BYTE_EVIDENCE_FILENAME = "first-byte-evidence.json"
ENGINE_SOCKET_FILENAME = "engine.sock"
ENGINE_SOCKET_PARENT_LABEL = "Traefik engine socket parent"
ENGINE_SOCKET_DIRECTORY_RANDOM_HEX_LENGTH = 16
ENGINE_STDERR_LOG_FILENAME = "engine.stderr.log"
TRAEFIK_STDOUT_LOG_FILENAME = "traefik.stdout.log"
# Linux sockaddr_un traditionally permits 107 pathname bytes plus NUL. Keep a
# margin so a pinned host with a shorter implementation cannot silently turn
# a long canonical run root into an engine-start failure.
ENGINE_SOCKET_PATH_MAX_BYTES = 100
TRANSPORT_OBSERVATION_MAX_BODY_BYTES = 64 << 10
SAFE_RUN_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


@dataclass(frozen=True)
class DirectoryIdentity:
    """No-follow identity captured when the runner allocates a directory."""

    device: int
    inode: int


@dataclass(frozen=True)
class EngineSocketParent:
    """Validated parent plus the identity that cleanup must preserve."""

    path: Path
    identity: DirectoryIdentity


@dataclass(frozen=True)
class EngineSocketDirectory:
    """Unique runner-created UDS child plus its allocation identity."""

    path: Path
    identity: DirectoryIdentity


def assert_no_symlink_components(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        if current.is_symlink():
            raise MissingDependency(f"runtime path contains a symlink: {current}")
        if not current.exists():
            break


def directory_entry_is_protected_from_cross_user_replacement(
    parent_stat: os.stat_result, child_stat: os.stat_result
) -> bool:
    """Return whether an ancestor prevents another UID replacing its child."""

    if not stat.S_ISDIR(parent_stat.st_mode):
        return False
    parent_mode = stat.S_IMODE(parent_stat.st_mode)
    if parent_mode & (stat.S_IWGRP | stat.S_IWOTH) == 0:
        return True
    return bool(parent_mode & stat.S_ISVTX) and child_stat.st_uid == os.geteuid()


def assert_private_engine_socket_parent_ancestors_are_safe(parent: Path, label: str) -> None:
    """Reject a parent replaceable through a cross-user writable ancestor."""

    child = parent
    while child != child.parent:
        child_stat = child.lstat()
        ancestor = child.parent
        try:
            ancestor_stat = ancestor.lstat()
        except OSError as exc:
            raise MissingDependency(f"{label} ancestor is unavailable: {ancestor}") from exc
        if not directory_entry_is_protected_from_cross_user_replacement(
            ancestor_stat, child_stat
        ):
            raise MissingDependency(
                f"{label} has an ancestor that permits cross-user replacement: {ancestor}"
            )
        child = ancestor


def assert_runtime_root(path: Path) -> Path:
    """Validate the selected native runtime output before creating it.

    This path becomes the parent of staged plugin sources, generated configs,
    logs and a locally compiled engine. It may therefore be created only below
    an existing, owner-controlled ancestor that cannot be replaced by another
    user. An existing selected root must keep those same protections.
    """

    resolved = Path(os.path.abspath(path))
    if not resolved.is_absolute():
        raise MissingDependency("native runtime root must be absolute")
    if resolved in {Path("/"), Path("/var")}:
        raise MissingDependency(f"native runtime root is too broad: {resolved}")
    try:
        resolved.relative_to(REPO_ROOT)
    except ValueError:
        pass
    else:
        raise MissingDependency(f"native runtime root must be outside checkout: {resolved}")
    assert_no_symlink_components(resolved)
    existing_ancestor = resolved
    while not existing_ancestor.exists():
        existing_ancestor = existing_ancestor.parent
    try:
        ancestor_stat = existing_ancestor.lstat()
    except OSError as exc:
        raise MissingDependency(
            f"native runtime root ancestor is unavailable: {existing_ancestor}"
        ) from exc
    if not stat.S_ISDIR(ancestor_stat.st_mode):
        raise MissingDependency(
            f"native runtime root ancestor must be a directory: {existing_ancestor}"
        )
    if ancestor_stat.st_uid != os.geteuid():
        raise MissingDependency(
            f"native runtime root ancestor must be owned by the current user: {existing_ancestor}"
        )
    if stat.S_IMODE(ancestor_stat.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
        raise MissingDependency(
            "native runtime root ancestor must not be group or world writable: "
            f"{existing_ancestor}"
        )
    assert_private_engine_socket_parent_ancestors_are_safe(
        existing_ancestor, "native runtime root"
    )
    return resolved


def assert_private_engine_socket_parent(path: Path, label: str) -> Path:
    """Validate an explicitly selected private parent for a UDS child."""

    if not path.is_absolute():
        raise MissingDependency(f"{label} must be an existing absolute directory")
    parent = Path(os.path.abspath(path))
    if parent == Path(parent.anchor):
        raise MissingDependency(f"{label} is too broad: {parent}")
    try:
        parent.relative_to(REPO_ROOT)
    except ValueError:
        pass
    else:
        raise MissingDependency(f"{label} must be outside checkout: {parent}")
    assert_no_symlink_components(parent)
    try:
        parent_stat = parent.stat()
    except OSError as exc:
        raise MissingDependency(f"{label} is unavailable: {parent}") from exc
    if not stat.S_ISDIR(parent_stat.st_mode):
        raise MissingDependency(f"{label} must be an existing directory: {parent}")
    if (
        parent_stat.st_uid != os.geteuid()
        or stat.S_IMODE(parent_stat.st_mode) != 0o700
    ):
        raise MissingDependency(f"{label} must be private and owned by the current user: {parent}")
    assert_private_engine_socket_parent_ancestors_are_safe(parent, label)
    if not os.access(parent, os.W_OK | os.X_OK):
        raise MissingDependency(f"{label} is not writable by the current user: {parent}")
    return parent


def assert_engine_socket_parent_text_is_safe(value: str, label: str) -> None:
    """Reject control characters before a selected path reaches YAML output."""

    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise MissingDependency(f"{label} must not contain control characters")


def resolve_engine_socket_parent() -> EngineSocketParent:
    """Resolve the required explicit private parent before host setup."""

    explicit = os.environ.get(ENGINE_SOCKET_PARENT_ENV, "")
    if not explicit:
        raise MissingDependency(
            f"set {ENGINE_SOCKET_PARENT_ENV} to an existing private "
            f"{ENGINE_SOCKET_PARENT_LABEL}"
        )
    assert_engine_socket_parent_text_is_safe(explicit, ENGINE_SOCKET_PARENT_ENV)
    parent = assert_private_engine_socket_parent(Path(explicit), ENGINE_SOCKET_PARENT_ENV)
    return EngineSocketParent(
        path=parent,
        identity=private_directory_identity(parent, ENGINE_SOCKET_PARENT_ENV),
    )


def resolve_first_byte_evidence_output(path: Path) -> Path:
    """Bind optional first-byte evidence to one explicit private parent."""

    if not path.is_absolute():
        raise MissingDependency("FULL_LIFECYCLE_EVIDENCE_OUTPUT must be an absolute path")
    root_text = os.environ.get(FIRST_BYTE_EVIDENCE_ROOT_ENV, "")
    if not root_text:
        raise MissingDependency(
            f"{FIRST_BYTE_EVIDENCE_ROOT_ENV} is required for first-byte evidence output"
        )
    assert_engine_socket_parent_text_is_safe(root_text, FIRST_BYTE_EVIDENCE_ROOT_ENV)
    root = assert_private_engine_socket_parent(Path(root_text), FIRST_BYTE_EVIDENCE_ROOT_ENV)
    output = Path(os.path.abspath(path))
    if output.parent != root or output.name != FIRST_BYTE_EVIDENCE_FILENAME:
        raise MissingDependency(
            "FULL_LIFECYCLE_EVIDENCE_OUTPUT must be the fixed first-byte artifact "
            f"below {FIRST_BYTE_EVIDENCE_ROOT_ENV}"
        )
    try:
        output.lstat()
    except FileNotFoundError:
        return output
    raise MissingDependency("FULL_LIFECYCLE_EVIDENCE_OUTPUT must not already exist")


def assert_engine_socket_path_length(parent: Path) -> None:
    candidate = (
        parent
        / f"{ENGINE_SOCKET_DIRECTORY_PREFIX}{'f' * ENGINE_SOCKET_DIRECTORY_RANDOM_HEX_LENGTH}"
        / ENGINE_SOCKET_FILENAME
    )
    if len(os.fsencode(str(candidate))) > ENGINE_SOCKET_PATH_MAX_BYTES:
        raise MissingDependency("private Traefik engine socket path is too long")


def private_directory_identity(path: Path, label: str) -> DirectoryIdentity:
    """Return the no-follow identity of a private directory boundary."""

    path_stat = path.lstat()
    if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISDIR(path_stat.st_mode):
        raise MissingDependency(f"{label} is not a safe directory: {path}")
    return DirectoryIdentity(int(path_stat.st_dev), int(path_stat.st_ino))


def create_private_engine_socket_dir(parent: EngineSocketParent) -> EngineSocketDirectory:
    """Create a short private UDS child below one validated selected parent.

    Canonical run roots include connector and timestamp components and can
    exceed the portable Unix-domain pathname limit. The socket itself is
    transient transport state, not evidence. The caller chooses only a safe
    parent; this runner creates and later removes only its unique private
    child. All durable events, configs, logs, and results remain under the
    connector's isolated runtime root.
    """
    assert_private_engine_socket_parent(parent.path, ENGINE_SOCKET_PARENT_LABEL)
    assert_engine_socket_path_length(parent.path)
    if private_directory_identity(parent.path, ENGINE_SOCKET_PARENT_LABEL) != parent.identity:
        raise MissingDependency(f"{ENGINE_SOCKET_PARENT_LABEL} changed before allocation")
    try:
        root = Path(tempfile.mkdtemp(prefix=ENGINE_SOCKET_DIRECTORY_PREFIX, dir=parent.path))
    except OSError as exc:
        raise MissingDependency(
            f"cannot create private Traefik engine socket directory below {parent.path}"
        ) from exc
    child: EngineSocketDirectory | None = None
    socket_path = root / ENGINE_SOCKET_FILENAME
    try:
        assert_no_symlink_components(root)
        if private_directory_identity(parent.path, ENGINE_SOCKET_PARENT_LABEL) != parent.identity:
            raise MissingDependency(f"{ENGINE_SOCKET_PARENT_LABEL} changed during allocation")
        root_stat = root.lstat()
        if (
            not stat.S_ISDIR(root_stat.st_mode)
            or root_stat.st_uid != os.geteuid()
            or stat.S_IMODE(root_stat.st_mode) != 0o700
        ):
            raise MissingDependency("private Traefik engine socket directory is unsafe")
        child = EngineSocketDirectory(
            path=root,
            identity=DirectoryIdentity(int(root_stat.st_dev), int(root_stat.st_ino)),
        )
        if len(os.fsencode(str(socket_path))) > ENGINE_SOCKET_PATH_MAX_BYTES:
            raise MissingDependency("private Traefik engine socket path is too long")
        return child
    except Exception:
        remove_private_engine_socket_dir(child, parent)
        raise


def remove_private_engine_socket_dir(
    directory: EngineSocketDirectory | None, parent: EngineSocketParent
) -> bool:
    """Remove only an unchanged, empty child created by this runner.

    The engine service owns its own socket lifecycle. Refusing to recursively
    delete a nonempty child keeps a raced-in or foreign socket intact and
    turns incomplete cleanup into a visible runtime failure.
    """

    if directory is None:
        return True
    expected_parent = Path(os.path.abspath(parent.path))
    try:
        if directory.path.parent != expected_parent or not directory.path.name.startswith(
            ENGINE_SOCKET_DIRECTORY_PREFIX
        ):
            return False
        if private_directory_identity(parent.path, ENGINE_SOCKET_PARENT_LABEL) != parent.identity:
            return False
        assert_no_symlink_components(directory.path)
        path_stat = directory.path.lstat()
        if (
            not stat.S_ISDIR(path_stat.st_mode)
            or path_stat.st_uid != os.geteuid()
            or stat.S_IMODE(path_stat.st_mode) != 0o700
            or DirectoryIdentity(int(path_stat.st_dev), int(path_stat.st_ino)) != directory.identity
        ):
            return False
        if any(directory.path.iterdir()):
            return False
        directory.path.rmdir()
        return True
    except FileNotFoundError:
        return True
    except (OSError, MissingDependency):
        return False


def require_local_executable(path: Path, label: str) -> Path:
    resolved = Path(os.path.abspath(path))
    if not resolved.is_absolute():
        raise MissingDependency(f"{label} must be an absolute local path")
    if str(resolved).startswith(("/usr/", "/bin/", "/sbin/", "/opt/")):
        raise MissingDependency(f"{label} must not use a global system path: {resolved}")
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise MissingDependency(f"{label} is not executable: {resolved}")
    return resolved


def require_modsecurity_environment() -> tuple[Path, Path]:
    include = Path(os.environ.get("MODSECURITY_INCLUDE_DIR", ""))
    library = Path(os.environ.get("MODSECURITY_LIB_DIR", ""))
    if not include.is_absolute() or not (include / "modsecurity/modsecurity.h").is_file():
        raise MissingDependency("MODSECURITY_INCLUDE_DIR does not contain libmodsecurity headers")
    if not library.is_absolute() or not (library / "libmodsecurity.so").is_file():
        raise MissingDependency("MODSECURITY_LIB_DIR does not contain libmodsecurity.so")
    return include, library


def select_engine_rules() -> tuple[Path, dict[str, str], str]:
    configured = os.environ.get("MSCONNECTOR_RULES_FILE", "").strip()
    if configured:
        rules = Path(configured)
        if not rules.is_absolute() or not rules.is_file():
            raise MissingDependency("MSCONNECTOR_RULES_FILE must name an existing absolute rules file")
        if os.environ.get("MSCONNECTOR_CRS_RUNTIME") == "1":
            return rules.resolve(), {"block": CRS_RULE_ID}, "framework-crs-v4.29.0"
        return rules.resolve(), CANONICAL_RULE_IDS, "framework-no-crs"
    if not STANDALONE_ENGINE_RULES.is_file():
        raise MissingDependency(f"standalone Traefik rule fixture is unavailable: {STANDALONE_ENGINE_RULES}")
    return STANDALONE_ENGINE_RULES.resolve(), STANDALONE_RULE_IDS, "standalone-targeted"


def require_engine_inputs(rules_file: Path) -> None:
    if not ENGINE_BUILD_SCRIPT.is_file() or not os.access(ENGINE_BUILD_SCRIPT, os.X_OK):
        raise MissingDependency(f"persistent Traefik engine build script is unavailable: {ENGINE_BUILD_SCRIPT}")
    if not rules_file.is_absolute() or not rules_file.is_file():
        raise MissingDependency(f"native Traefik rules file is unavailable: {rules_file}")


def free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def read_plugin_module(source: Path) -> str:
    go_mod = source / "go.mod"
    middleware = source / "middleware.go"
    uds_engine = source / "engine_uds.go"
    metadata = source / ".traefik.yml"
    if not go_mod.is_file() or not middleware.is_file() or not uds_engine.is_file() or not metadata.is_file():
        raise MissingDependency(f"native plugin source is incomplete: {source}")
    for candidate in source.rglob("*"):
        if candidate.is_symlink():
            raise MissingDependency(f"native plugin source must not contain symlinks: {candidate}")
    module_match = re.search(r"(?m)^module\s+([^\s]+)\s*$", go_mod.read_text(encoding="utf-8"))
    package_match = re.search(
        r"(?m)^package\s+([A-Za-z_]\w*)\s*$",
        middleware.read_text(encoding="utf-8"),
        flags=re.ASCII,
    )
    if module_match is None or package_match is None:
        raise MissingDependency("native plugin must declare a Go module and package")
    module_name = module_match.group(1)
    if module_name.rsplit("/", 1)[-1] != package_match.group(1):
        raise MissingDependency(
            "Traefik local-plugin package must match the final module-path component"
        )
    if f"import: {module_name}" not in metadata.read_text(encoding="utf-8"):
        raise MissingDependency("native plugin metadata import does not match go.mod")
    return module_name


def write_json(path: Path, payload: dict[str, Any]) -> None:
    """Atomically replace one JSON artifact without following path symlinks."""

    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise MissingDependency("runtime JSON output must be an absolute file path")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise MissingDependency("runtime JSON output requires O_NOFOLLOW support")
    assert_no_symlink_components(path.parent)
    contents = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | nofollow
    try:
        directory_descriptor = os.open(path.parent, directory_flags)
    except OSError as exc:
        raise MissingDependency(f"runtime JSON output directory is unsafe: {path.parent}") from exc
    temporary_name = f".{path.name}.{os.urandom(16).hex()}.tmp"
    temporary_descriptor: int | None = None
    try:
        try:
            existing_stat = os.stat(path.name, dir_fd=directory_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(existing_stat.st_mode) or not stat.S_ISREG(existing_stat.st_mode):
                raise MissingDependency(f"runtime JSON artifact path is unsafe: {path}")
        temporary_descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
            0o600,
            dir_fd=directory_descriptor,
        )
        try:
            if not stat.S_ISREG(os.fstat(temporary_descriptor).st_mode):
                raise MissingDependency(f"runtime JSON temporary path is not regular: {path}")
            with os.fdopen(temporary_descriptor, "wb", closefd=False) as stream:
                stream.write(contents)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(temporary_descriptor)
            temporary_descriptor = None
        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
        artifact_descriptor = os.open(path.name, os.O_RDONLY | nofollow, dir_fd=directory_descriptor)
        try:
            artifact_stat = os.fstat(artifact_descriptor)
            if not stat.S_ISREG(artifact_stat.st_mode) or stat.S_IMODE(artifact_stat.st_mode) != 0o600:
                raise MissingDependency(f"runtime JSON artifact is unsafe: {path}")
        finally:
            os.close(artifact_descriptor)
        os.fsync(directory_descriptor)
    except OSError as exc:
        raise MissingDependency(f"could not atomically write runtime JSON artifact: {path}") from exc
    finally:
        if temporary_descriptor is not None:
            os.close(temporary_descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_descriptor)
        except FileNotFoundError:
            pass
        finally:
            os.close(directory_descriptor)


def wait_for_port(port: int, process: subprocess.Popen[bytes], label: str) -> None:
    deadline = time.monotonic() + 15
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{label} exited early with code {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError as exc:
            last_error = exc
        time.sleep(0.1)
    raise RuntimeError(f"{label} did not listen on {port}: {last_error}")


def wait_for_socket(path: Path, process: subprocess.Popen[bytes], label: str) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{label} exited early with code {process.returncode}")
        if path.exists() and path.is_socket():
            return
        time.sleep(0.05)
    raise RuntimeError(f"{label} did not create its Unix socket")


def write_engine_config(path: Path, rules_file: Path, event_path: Path) -> None:
    if not rules_file.is_absolute() or not event_path.is_absolute():
        raise MissingDependency("engine rules and event paths must be absolute")
    for candidate in (rules_file, event_path):
        if ".." in candidate.parts or "\n" in str(candidate) or "\r" in str(candidate):
            raise MissingDependency("engine rules and event paths must be isolated normalized paths")
    path.write_text(
        "\n".join(
            (
                "enabled=on",
                f"rules_file={rules_file}",
                "transaction_id_header=x-request-id",
                "request_body_mode=streaming",
                "response_body_mode=streaming",
                "phase4_mode=safe",
                "default_block_status=403",
                "default_error_status=500",
                "use_error_log=off",
                f"event_path={event_path}",
                "max_header_count=100",
                "max_header_name_size=256",
                "max_header_value_size=8192",
                "max_total_header_bytes=65536",
                "max_event_json_bytes=16384",
                "",
            )
        ),
        encoding="utf-8",
    )


def build_engine_service(runtime_root: Path, logs_dir: Path, include_dir: Path, library_dir: Path) -> Path:
    build_dir = runtime_root / "engine-build"
    engine_bin = build_dir / "traefik-engine-service"
    environment = os.environ.copy()
    environment.update(
        {
            "MODSECURITY_INCLUDE_DIR": str(include_dir),
            "MODSECURITY_LIB_DIR": str(library_dir),
            "TRAEFIK_ENGINE_SERVICE_BUILD_DIR": str(build_dir),
            "TRAEFIK_ENGINE_SERVICE_BIN": str(engine_bin),
        }
    )
    with (logs_dir / "engine-build.stdout.log").open("wb") as stdout, (
        logs_dir / "engine-build.stderr.log"
    ).open("wb") as stderr:
        completed = subprocess.run(
            [str(ENGINE_BUILD_SCRIPT), "build"],
            cwd=REPO_ROOT,
            env=environment,
            stdout=stdout,
            stderr=stderr,
            check=False,
        )
    if completed.returncode != 0:
        raise RuntimeError("persistent Traefik engine build failed")
    return require_local_executable(engine_bin, "persistent Traefik engine service")


def stop_process(process: subprocess.Popen[bytes] | None) -> bool:
    if process is None or process.poll() is not None:
        return True
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    return process.poll() is not None


@dataclass
class UpstreamState:
    request_count: int = 0
    request_body_bytes: int = 0
    response_chunks: int = 0
    p1_allow_upstream_requests: int = 0
    p3_requests: int = 0
    p4_requests: int = 0
    barrier_first_chunk_size: int = 0
    barrier_response_bytes: int = 0
    barrier_eos_sent: bool = False
    barrier_reached: threading.Event = field(default_factory=threading.Event)
    barrier_release: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)


def upstream_handler(state: UpstreamState) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def handle(self) -> None:
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError):
                return

        def do_POST(self) -> None:  # noqa: N802 - HTTP server callback name
            expected = int(self.headers.get("Content-Length", "0"))
            seen = 0
            while seen < expected:
                chunk = self.rfile.read(min(4096, expected - seen))
                if not chunk:
                    break
                seen += len(chunk)
            p3_requested = self.headers.get("X-Native-Response-Rule") == "block"
            p4_requested = self.headers.get("X-Native-P4-Rule") == "block"
            barrier_requested = self.headers.get("X-Native-P4-Barrier") == "true"
            p1_allow_requested = self.headers.get("X-Request-Id") == P1_ALLOW_TRANSACTION_ID
            if barrier_requested and not p4_requested:
                self.send_error(http.HTTPStatus.BAD_REQUEST)
                return
            chunks = (
                b"native-traefik-first-chunk\n",
                b"no-crs-response-body-marker\n" if p4_requested else b"native-traefik-final-chunk\n",
            )
            with state.lock:
                state.request_count += 1
                state.request_body_bytes += seen
                state.response_chunks += len(chunks)
                state.p1_allow_upstream_requests += int(p1_allow_requested)
                state.p3_requests += int(p3_requested)
                state.p4_requests += int(p4_requested)
            self.send_response(200)
            self.send_header("Content-Type", PLAIN_TEXT_CONTENT_TYPE)
            if p3_requested:
                self.send_header("X-Modsec-Upstream", "block")
            self.send_header("Content-Length", str(sum(len(chunk) for chunk in chunks)))
            self.end_headers()
            try:
                self.wfile.write(chunks[0])
                self.wfile.flush()
                if barrier_requested:
                    with state.lock:
                        state.barrier_first_chunk_size = len(chunks[0])
                        state.barrier_response_bytes = sum(len(chunk) for chunk in chunks)
                        state.barrier_eos_sent = False
                    state.barrier_reached.set()
                    if not state.barrier_release.wait(timeout=20):
                        return
                self.wfile.write(chunks[1])
                self.wfile.flush()
                if barrier_requested:
                    with state.lock:
                        state.barrier_eos_sent = True
            except (BrokenPipeError, ConnectionResetError):
                return

        def do_GET(self) -> None:  # noqa: N802 - HTTP server callback name
            with state.lock:
                state.request_count += 1
                state.response_chunks += 1
            payload = b"traefik-crs-upstream-ok\n"
            self.send_response(200)
            self.send_header("Content-Type", PLAIN_TEXT_CONTENT_TYPE)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return

        def log_message(self, _format: str, *_args: object) -> None:
            # Request paths and body values are not useful evidence.
            return

    return Handler


def write_static_config(path: Path, dynamic_path: Path, port: int, module_name: str) -> None:
    path.write_text(
        "\n".join(
            (
                "entryPoints:",
                "  web:",
                f'    address: "127.0.0.1:{port}"',
                "providers:",
                "  file:",
                f'    filename: "{dynamic_path}"',
                "    watch: false",
                "experimental:",
                "  localPlugins:",
                f"    {PLUGIN_ID}:",
                f"      moduleName: {module_name}",
                "      settings:",
                "        envs: []",
                "global:",
                "  checkNewVersion: false",
                "  sendAnonymousUsage: false",
                "log:",
                "  level: INFO",
                "",
            )
        ),
        encoding="utf-8",
    )


def write_dynamic_config(path: Path, upstream_port: int, engine_socket: Path) -> None:
    path.write_text(
        "\n".join(
            (
                "http:",
                "  routers:",
                "    native:",
                "      entryPoints: [web]",
                '      rule: "PathPrefix(`/`)"',
                "      middlewares: [native]",
                "      service: upstream",
                "  middlewares:",
                "    native:",
                "      plugin:",
                f"        {PLUGIN_ID}:",
                "          maxHeaderCount: 128",
                "          maxHeaderBytes: 65536",
                "          maxRequestChunkBytes: 32768",
                "          maxResponseChunkBytes: 32768",
                "          transactionIDHeader: X-Request-Id",
                "          engineMode: uds",
                f"          engineSocketPath: {json.dumps(str(engine_socket))}",
                "  services:",
                "    upstream:",
                "      loadBalancer:",
                "        servers:",
                f"          - url: http://127.0.0.1:{upstream_port}",
                "",
            )
        ),
        encoding="utf-8",
    )


class CompletionHTTPResponse(http.client.HTTPResponse):
    """Avoid reading past the body before the separate physical EOF check."""

    def __init__(self, sock: socket.socket, *args: Any, **kwargs: Any) -> None:
        super().__init__(sock, *args, **kwargs)
        self.fp.close()
        self.fp = sock.makefile("rb", buffering=0)

    def _safe_read(self, amount: int) -> bytes:
        # Raw socket reads may be short. Preserve HTTP chunk framing without
        # buffering bytes that belong to the separate completion observation.
        chunks = []
        remaining = amount
        while remaining:
            chunk = self.fp.read(remaining)
            if not chunk:
                raise http.client.IncompleteRead(b"".join(chunks), remaining)
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)


def require_response_socket_eof(completion_socket: socket.socket) -> None:
    """Wait for a bounded actual peer close, without synthesizing native EOS."""

    try:
        extra = completion_socket.recv(1)
    except OSError as exc:
        raise RuntimeError("native response did not reach physical socket EOF") from exc
    if extra:
        raise RuntimeError("native response carried bytes beyond its declared body")


def read_response_body(response: http.client.HTTPResponse) -> tuple[int, int]:
    """Require a bounded, complete body through the actual sized-read path."""

    try:
        status, body_bytes, _ = read_complete_response(response)
    except (OSError, http.client.HTTPException) as exc:
        raise RuntimeError("native response body did not complete") from exc
    if response.length not in (None, 0):
        raise RuntimeError("native response ended before its declared body length")
    return status, body_bytes


def close_response_resources(
    response: http.client.HTTPResponse | None,
    connection: http.client.HTTPConnection,
    completion_socket: socket.socket | None,
) -> None:
    """Close every owned resource while retaining an active failure cause."""

    active_error = sys.exception()
    cleanup_errors: list[OSError] = []
    for resource in (response, connection, completion_socket):
        if resource is not None:
            try:
                resource.close()
            except OSError as exc:
                cleanup_errors.append(exc)
    if cleanup_errors:
        if active_error is None:
            raise cleanup_errors[0]
        active_error.add_note(
            "native response cleanup failures: "
            + ", ".join(type(error).__name__ for error in cleanup_errors)
        )


def request_through_traefik(
    port: int,
    body: bytes,
    request_id: str,
    expected_status: int,
    extra_headers: dict[str, str] | None = None,
    method: str = "POST",
    path: str = NATIVE_REQUEST_PATH,
) -> tuple[int, int]:
    deadline = time.monotonic() + 15
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        connection.response_class = CompletionHTTPResponse
        completion_socket: socket.socket | None = None
        response: http.client.HTTPResponse | None = None
        try:
            headers = {
                "Content-Type": PLAIN_TEXT_CONTENT_TYPE,
                "X-Request-Id": request_id,
            }
            if extra_headers:
                headers.update(extra_headers)
            headers["Connection"] = "close"
            connection.request(
                method,
                path,
                body=body,
                headers=headers,
            )
            if connection.sock is None:
                raise RuntimeError("native request has no connected completion socket")
            completion_socket = connection.sock.dup()
            response = connection.getresponse()
            status, body_bytes = read_response_body(response)
            require_response_socket_eof(completion_socket)
            if status == expected_status:
                return status, body_bytes
            last_error = RuntimeError(f"native router returned unexpected status {status}")
        except (OSError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            close_response_resources(response, connection, completion_socket)
        time.sleep(0.2)
    raise RuntimeError(f"native router did not complete expected status {expected_status}: {last_error}")


def read_complete_response(response: http.client.HTTPResponse) -> tuple[int, int, bool]:
    """Read one bounded test response without retaining a payload artifact.

    The native transport sidecar may record whether a client saw headers, a
    body byte, and a complete Content-Length response.  It must never persist
    the response itself, including the deliberate Phase-4 marker fixture.
    """
    status = int(response.status)
    declared_length = response.getheader("Content-Length")
    expected_length: int | None = None
    if declared_length is not None:
        try:
            expected_length = int(declared_length)
        except ValueError as exc:
            raise RuntimeError("native router returned an invalid Content-Length") from exc
        if expected_length < 0 or expected_length > TRANSPORT_OBSERVATION_MAX_BODY_BYTES:
            raise RuntimeError("native router returned an out-of-range Content-Length")
    body_bytes = 0
    first_byte_received = False
    while True:
        chunk = response.read(4096)
        if not chunk:
            break
        body_bytes += len(chunk)
        if body_bytes > TRANSPORT_OBSERVATION_MAX_BODY_BYTES:
            raise RuntimeError("native router exceeded the transport observation body limit")
        first_byte_received = True
    if expected_length is not None and body_bytes != expected_length:
        raise RuntimeError(
            f"native router returned incomplete body {body_bytes}, expected {expected_length}"
        )
    return status, body_bytes, first_byte_received


def read_response_after_first_byte(
    response: http.client.HTTPResponse, first_byte_count: int,
) -> tuple[int, int]:
    """Finish one response after a separately observed first entity byte.

    The caller keeps at most the single byte needed for the barrier assertion
    in memory.  This helper counts the rest without retaining payload data.
    """
    if first_byte_count < 1:
        raise RuntimeError("first-byte barrier did not deliver an entity byte")
    status = int(response.status)
    declared_length = response.getheader("Content-Length")
    expected_length: int | None = None
    if declared_length is not None:
        try:
            expected_length = int(declared_length)
        except ValueError as exc:
            raise RuntimeError("native router returned an invalid Content-Length") from exc
        if expected_length < first_byte_count or expected_length > TRANSPORT_OBSERVATION_MAX_BODY_BYTES:
            raise RuntimeError("native router returned an invalid bounded entity length")
    body_bytes = first_byte_count
    while True:
        chunk = response.read(4096)
        if not chunk:
            break
        body_bytes += len(chunk)
        if body_bytes > TRANSPORT_OBSERVATION_MAX_BODY_BYTES:
            raise RuntimeError("native router exceeded the transport observation body limit")
    if expected_length is not None and body_bytes != expected_length:
        raise RuntimeError(
            f"native router returned incomplete body {body_bytes}, expected {expected_length}"
        )
    return status, body_bytes


def synchronized_safe_followup_attempt(
    port: int,
    state: UpstreamState,
    body: bytes,
    safe_request_id: str,
    followup_request_id: str,
) -> dict[str, int | bool]:
    """Run one first-byte proof attempt on one HTTP/1.1 connection."""

    state.barrier_reached.clear()
    state.barrier_release.clear()
    with state.lock:
        state.barrier_first_chunk_size = 0
        state.barrier_response_bytes = 0
        state.barrier_eos_sent = False
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(
            "POST",
            NATIVE_REQUEST_PATH,
            body=body,
            headers={
                "Content-Type": PLAIN_TEXT_CONTENT_TYPE,
                "X-Request-Id": safe_request_id,
                "X-Native-P4-Rule": "block",
                "X-Native-P4-Barrier": "true",
            },
        )
        safe_response = connection.getresponse()
        if not state.barrier_reached.wait(timeout=5):
            raise RuntimeError("upstream did not reach the Phase-4 first-byte barrier")
        first_byte = safe_response.read(1)
        with state.lock:
            upstream_paused = state.barrier_reached.is_set() and not state.barrier_eos_sent
            first_chunk_size = state.barrier_first_chunk_size
            response_bytes = state.barrier_response_bytes
        if not first_byte or not upstream_paused or first_chunk_size < 1:
            raise RuntimeError("client did not receive a first body byte while upstream was paused")
        state.barrier_release.set()
        safe_status, safe_bytes = read_response_after_first_byte(safe_response, len(first_byte))
        first_socket = connection.sock
        if safe_status != http.HTTPStatus.OK or safe_bytes != response_bytes or first_socket is None:
            raise RuntimeError("native safe barrier response did not complete correctly")
        if safe_response.will_close:
            raise RuntimeError("native safe barrier response closed the HTTP/1.1 connection")
        connection.request(
            "POST",
            NATIVE_REQUEST_PATH,
            body=body,
            headers={
                "Content-Type": PLAIN_TEXT_CONTENT_TYPE,
                "X-Request-Id": followup_request_id,
            },
        )
        followup_response = connection.getresponse()
        followup_status, followup_bytes, followup_first_byte = read_complete_response(followup_response)
        if followup_status != http.HTTPStatus.OK or not followup_first_byte:
            raise RuntimeError("native first-byte follow-up did not complete")
        if first_socket is not connection.sock:
            raise RuntimeError("native first-byte follow-up opened a different TCP connection")
        return {
            "connection_reused": True,
            "first_chunk_size": first_chunk_size,
            "followup_first_byte_received": followup_first_byte,
            "followup_response_bytes": followup_bytes,
            "followup_status": followup_status,
            "safe_first_byte_received": True,
            "safe_response_bytes": safe_bytes,
            "safe_status": safe_status,
            "upstream_eos_sent_at_first_byte": False,
            "upstream_paused": True,
        }
    finally:
        connection.close()


def synchronized_safe_followup(
    port: int,
    state: UpstreamState,
    body: bytes,
    safe_request_id: str,
    followup_request_id: str,
) -> dict[str, int | bool]:
    """Prove a real Traefik byte crossed the host before upstream EOS."""

    deadline = time.monotonic() + 15
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return synchronized_safe_followup_attempt(
                port, state, body, safe_request_id, followup_request_id
            )
        except (OSError, http.client.HTTPException, RuntimeError) as exc:
            last_error = exc
            state.barrier_release.set()
        time.sleep(0.2)
    raise RuntimeError(f"native first-byte barrier probe did not complete: {last_error}")


def keepalive_safe_followup(
    port: int,
    body: bytes,
    safe_request_id: str,
    followup_request_id: str,
) -> dict[str, int | bool]:
    """Exercise a real HTTP/1.1 keep-alive after a late Safe decision.

    This is deliberately a narrow native-host observation.  A reused socket is
    required; silently reconnecting would only prove two unrelated requests
    and must not be reported as keep-alive evidence.
    """
    deadline = time.monotonic() + 15
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            connection.request(
                "POST",
                NATIVE_REQUEST_PATH,
                body=body,
                headers={
                    "Content-Type": PLAIN_TEXT_CONTENT_TYPE,
                    "X-Request-Id": safe_request_id,
                    "X-Native-P4-Rule": "block",
                },
            )
            safe_response = connection.getresponse()
            safe_status, safe_bytes, safe_first_byte = read_complete_response(safe_response)
            first_socket = connection.sock
            if safe_status != http.HTTPStatus.OK or not safe_first_byte or first_socket is None:
                raise RuntimeError("native safe request did not complete on a reusable HTTP/1.1 connection")
            if safe_response.will_close:
                raise RuntimeError("native safe response closed the HTTP/1.1 connection")

            connection.request(
                "POST",
                NATIVE_REQUEST_PATH,
                body=body,
                headers={
                    "Content-Type": PLAIN_TEXT_CONTENT_TYPE,
                    "X-Request-Id": followup_request_id,
                },
            )
            followup_response = connection.getresponse()
            followup_status, followup_bytes, followup_first_byte = read_complete_response(followup_response)
            second_socket = connection.sock
            if followup_status != http.HTTPStatus.OK or not followup_first_byte:
                raise RuntimeError("native keep-alive follow-up did not complete")
            if first_socket is not second_socket:
                raise RuntimeError("native keep-alive follow-up opened a different TCP connection")
            return {
                "connection_reused": True,
                "followup_first_byte_received": followup_first_byte,
                "followup_response_bytes": followup_bytes,
                "followup_status": followup_status,
                "safe_first_byte_received": safe_first_byte,
                "safe_response_bytes": safe_bytes,
                "safe_status": safe_status,
            }
        except (OSError, http.client.HTTPException, RuntimeError) as exc:
            last_error = exc
        finally:
            connection.close()
        time.sleep(0.2)
    raise RuntimeError(f"native keep-alive probe did not complete: {last_error}")


def traefik_version(binary: Path) -> str:
    completed = subprocess.run(
        [str(binary), "version"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if completed.returncode != 0:
        raise MissingDependency("could not determine pinned Traefik version")
    return next((line.strip() for line in completed.stdout.splitlines() if line.strip()), "unknown")


def read_host_outcomes(event_path: Path) -> list[dict[str, Any]]:
    if not event_path.is_file():
        raise RuntimeError("persistent engine did not produce run-local events.jsonl")
    outcomes: list[dict[str, Any]] = []
    for raw_line in event_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw_line:
            continue
        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise RuntimeError("persistent engine emitted malformed JSONL") from exc
        if not isinstance(event, dict):
            raise RuntimeError("persistent engine emitted a non-object JSONL event")
        if event.get("integration_mode") != "native-traefik-middleware":
            continue
        if event.get("transport_result") in {"http_status", "log_only"}:
            outcomes.append(event)
    return outcomes


def host_outcome(
    outcomes: list[dict[str, Any]], phase: str, actual_action: str, visible_status: int, rule_id: str
) -> dict[str, Any]:
    for event in outcomes:
        if (
            event.get("phase") == phase
            and event.get("actual_action") == actual_action
            and event.get("visible_http_status") == visible_status
            and str(event.get("rule_id")) == rule_id
        ):
            return event
    raise RuntimeError(
        f"missing host-confirmed outcome phase={phase} action={actual_action} status={visible_status} rule={rule_id}"
    )


def require_host_outcome(
    outcomes: list[dict[str, Any]], phase: str, actual_action: str, visible_status: int, rule_id: str
) -> None:
    host_outcome(outcomes, phase, actual_action, visible_status, rule_id)


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n")


def optional_canonical_run_id() -> str | None:
    """Return the run ID when this host probe is running canonically.

    Direct local host runs predate canonical evidence collection and do not
    necessarily have a run ID.  A supplied ID, however, is used as evidence
    metadata and must therefore obey the same bounded token policy as the
    full-lifecycle dispatcher.
    """
    environment_name = (
        "CRS_RUNTIME_RUN_ID"
        if os.environ.get("MSCONNECTOR_CRS_RUNTIME") == "1"
        else "NO_CRS_RUN_ID"
    )
    run_id = os.environ.get(environment_name, "").strip()
    if not run_id:
        return None
    if not SAFE_RUN_ID_PATTERN.fullmatch(run_id):
        raise RuntimeError(f"{environment_name} is not a bounded safe canonical run ID")
    return run_id


def append_allow_host_event(
    event_path: Path,
    observed_status: int,
    response_bytes: int,
    transaction_id: str,
    upstream_requests: int,
    run_id: str | None,
) -> None:
    """Append one causally checked, payload-free P1 allow outcome.

    The no-rule case is summary-derived, so this event deliberately follows
    the P4 barrier event.  That makes the final confirmed HTTP 200 belong to
    the actual P1 request instead of incorrectly borrowing the P4-safe
    response.  It is a host-forward observation, not a policy action: allow
    is intentionally absent from the closed action vocabularies.
    """
    if transaction_id != P1_ALLOW_TRANSACTION_ID:
        raise RuntimeError("Traefik P1 allow event has an unexpected transaction ID")
    if observed_status != http.HTTPStatus.OK or response_bytes < 1:
        raise RuntimeError("Traefik P1 allow client outcome must preserve HTTP 200 with a body")
    if upstream_requests != 1:
        raise RuntimeError("Traefik P1 allow transaction was not observed exactly once upstream")
    record: dict[str, Any] = {
        "connector": "traefik",
        "integration_mode": "native-traefik-middleware",
        "event": "native_traefik_host_forward",
        "message_id": "TRAEFIK_NATIVE_P1_ALLOW",
        "transaction_id": transaction_id,
        "phase": 1,
        "status": "allowed",
        "http_status": http.HTTPStatus.OK,
        "visible_http_status": http.HTTPStatus.OK,
        "headers_sent": True,
        "response_committed": True,
        "connection_aborted": False,
        "transport_result": "http_status",
    }
    if run_id is not None:
        record["run_id"] = run_id
    append_jsonl(event_path, record)


def write_first_byte_evidence(
    path: Path, observation: dict[str, int | bool], total_entity_bytes: int,
) -> None:
    if not path.is_absolute():
        raise RuntimeError("FULL_LIFECYCLE_EVIDENCE_OUTPUT must be an absolute path")
    first_chunk_size = int(observation["first_chunk_size"])
    if first_chunk_size < 1 or total_entity_bytes < first_chunk_size:
        raise RuntimeError("invalid bounded Traefik first-byte observation")
    write_json(
        path,
        {
            "schema_version": 1,
            "evidence_type": "synchronized_first_byte",
            "evidence_origin": "real_host",
            "promotion_eligible": True,
            "client_first_byte_received": observation["safe_first_byte_received"] is True,
            "first_byte_before_response_end": observation["upstream_paused"] is True,
            "first_chunk_size": first_chunk_size,
            "upstream_paused": observation["upstream_paused"] is True,
            "upstream_eos_sent_at_first_byte": observation["upstream_eos_sent_at_first_byte"] is True,
            "upstream_response_finished_at_first_byte": False,
            "response_committed": True,
            "body_bytes_seen": total_entity_bytes,
            "body_bytes_inspected": total_entity_bytes,
            "no_full_response_buffering": True,
            "connector_owned_full_response_buffer": False,
            "transport_protocol": "http1",
            "body_payload_persisted": False,
            "outcome": "PASS",
        },
    )


def append_first_byte_host_event(
    event_path: Path,
    phase4_event: dict[str, Any],
    observation: dict[str, int | bool],
    safe_request_id: str,
    rule_id: str,
    total_entity_bytes: int,
    run_id: str | None,
) -> None:
    transaction_id = str(phase4_event.get("transaction_id") or "")
    if transaction_id != safe_request_id:
        raise RuntimeError("Traefik Phase-4 event is not causally bound to the barrier transaction")
    first_chunk_size = int(observation["first_chunk_size"])
    if first_chunk_size < 1 or total_entity_bytes < first_chunk_size:
        raise RuntimeError("invalid Traefik Phase-4 barrier byte counters")
    host_event = dict(phase4_event)
    host_event.update(
        {
            "connector": "traefik",
            "integration_mode": "native-traefik-middleware",
            "event": "traefik_native_first_byte_barrier",
            "message_id": "TRAEFIK_NATIVE_P4_FIRST_BYTE",
            "transaction_id": transaction_id,
            "rule_id": int(rule_id),
            "phase": 4,
            "requested_action": "deny",
            "actual_action": "log_only",
            "late_intervention": True,
            "late_intervention_mode": "safe",
            "http_status": http.HTTPStatus.FORBIDDEN,
            "original_http_status": http.HTTPStatus.OK,
            "visible_http_status": http.HTTPStatus.OK,
            "headers_sent": True,
            "body_started": True,
            "response_committed": True,
            "connection_aborted": False,
            "transport_result": "log_only",
            "negotiated_protocol": "http1",
            "transport_case_id": "phase4-first-byte-traefik",
            "connection_id": "traefik-native-p4-safe",
            "barrier_id": "traefik-native-p4",
            "client_first_byte_received": observation["safe_first_byte_received"] is True,
            "first_byte_before_response_end": observation["upstream_paused"] is True,
            "first_chunk_size": first_chunk_size,
            "upstream_paused": observation["upstream_paused"] is True,
            "upstream_eos_sent_at_first_byte": observation["upstream_eos_sent_at_first_byte"] is True,
            "upstream_response_finished_at_first_byte": False,
            "no_full_response_buffering": True,
            "body_bytes_seen": total_entity_bytes,
            "body_bytes_inspected": total_entity_bytes,
            "eos_seen": True,
            "end_of_stream_evaluation": True,
            "cleanup_reason": "normal",
        }
    )
    if run_id is not None:
        host_event["run_id"] = run_id
    append_jsonl(event_path, host_event)


@dataclass(frozen=True)
class NativeRuntimeInputs:
    """Validated immutable inputs for one native Traefik host run."""

    runtime_root: Path
    engine_socket_parent: EngineSocketParent
    run_id: str | None
    first_byte_output: Path | None
    binary: Path
    include_dir: Path
    library_dir: Path
    rules_file: Path
    rule_ids: dict[str, str]
    rules_profile: str
    module_name: str


@dataclass(frozen=True)
class NativeRuntimeArtifacts:
    """Paths staged below the validated runtime root."""

    logs_dir: Path
    result_path: Path
    transport_observations_path: Path
    static_config: Path
    dynamic_config: Path
    engine_config: Path
    event_path: Path


@dataclass(frozen=True)
class NativeRuntimeSetup:
    """Private socket, loopback fixture, and generated runtime configuration."""

    engine_socket_dir: EngineSocketDirectory
    engine_socket: Path
    upstream: http.server.ThreadingHTTPServer
    upstream_port: int
    traefik_port: int
    state: UpstreamState


@dataclass
class NativeProcesses:
    """Owned child processes that must be stopped on every outcome."""

    traefik: subprocess.Popen[bytes] | None = None
    engine: subprocess.Popen[bytes] | None = None


@dataclass(frozen=True)
class NativeRequestResults:
    """Responses observed through the live Traefik host."""

    p1_allow_status: int
    p1_allow_bytes: int
    p1_deny_status: int
    p1_alternative_status: int
    p2_deny_status: int
    p3_deny_status: int
    p4_safe_status: int
    p4_safe_bytes: int
    keepalive_observation: dict[str, int | bool]


@dataclass(frozen=True)
class CrsRequestIDs:
    """Run-scoped request identifiers that remain within Common's 128-byte limit."""

    allow: str
    block: str
    bypass: str


def crs_request_ids(run_id: str) -> CrsRequestIDs:
    """Derive injective CRS transaction IDs from the validated canonical run ID."""

    if not SAFE_RUN_ID_PATTERN.fullmatch(run_id):
        raise MissingDependency("CRS_RUNTIME_RUN_ID is not a bounded safe canonical run ID")
    if len(run_id) > CRS_RUNTIME_RUN_ID_MAX_LENGTH:
        raise MissingDependency(
            "CRS_RUNTIME_RUN_ID exceeds the Traefik CRS transaction-ID safety limit"
        )
    prefix = f"traefik-native-crs-{run_id}"
    return CrsRequestIDs(
        allow=f"{prefix}-allow",
        block=f"{prefix}-block",
        bypass=f"{prefix}-bypass",
    )


@dataclass(frozen=True)
class CrsRequestResults:
    """Responses observed through the live Traefik CRS host path."""

    request_ids: CrsRequestIDs
    allow_status: int
    allow_bytes: int
    block_status: int
    bypass_status: int
    bypass_bytes: int


@dataclass(frozen=True)
class NativeLiveObservation:
    """State confirmed while the native host is still running."""

    plugin_loaded: bool
    upstream_requests: int
    request_body_bytes: int
    response_chunks: int
    p1_allow_upstream_requests: int


def collect_native_runtime_inputs() -> NativeRuntimeInputs:
    """Resolve all environment-derived inputs before making runtime changes."""

    runtime_root = assert_runtime_root(Path(os.environ.get("TRAEFIK_NATIVE_RUNTIME_ROOT", "")))
    first_byte_output_text = os.environ.get("FULL_LIFECYCLE_EVIDENCE_OUTPUT", "").strip()
    first_byte_output = Path(first_byte_output_text) if first_byte_output_text else None
    if first_byte_output is not None:
        first_byte_output = resolve_first_byte_evidence_output(first_byte_output)
    if os.environ.get("NO_CRS_ARTIFACT_PROFILE") == "full_lifecycle" and first_byte_output is None:
        raise MissingDependency("FULL_LIFECYCLE_EVIDENCE_OUTPUT is required for the native first-byte proof")
    engine_socket_parent = resolve_engine_socket_parent()
    binary = require_local_executable(Path(os.environ.get("TRAEFIK_BIN", "")), "Traefik binary")
    rules_file, rule_ids, rules_profile = select_engine_rules()
    require_engine_inputs(rules_file)
    include_dir, library_dir = require_modsecurity_environment()
    run_id = optional_canonical_run_id()
    if os.environ.get("MSCONNECTOR_CRS_RUNTIME") == "1" and run_id is None:
        raise MissingDependency("CRS_RUNTIME_RUN_ID is required for Traefik CRS request correlation")
    if os.environ.get("MSCONNECTOR_CRS_RUNTIME") == "1":
        assert run_id is not None
        crs_request_ids(run_id)
    return NativeRuntimeInputs(
        runtime_root=runtime_root,
        engine_socket_parent=engine_socket_parent,
        run_id=run_id,
        first_byte_output=first_byte_output,
        binary=binary,
        include_dir=include_dir,
        library_dir=library_dir,
        rules_file=rules_file,
        rule_ids=rule_ids,
        rules_profile=rules_profile,
        module_name=read_plugin_module(PLUGIN_SOURCE),
    )


def stage_native_runtime(inputs: NativeRuntimeInputs) -> NativeRuntimeArtifacts:
    """Stage one isolated local-plugin workspace below the trusted root."""

    if inputs.runtime_root.exists() and any(inputs.runtime_root.iterdir()):
        raise MissingDependency(f"native runtime root must be empty: {inputs.runtime_root}")
    staging_started = False
    try:
        inputs.runtime_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(inputs.runtime_root, 0o700)
        staging_started = True
        plugin_destination = inputs.runtime_root / "plugins-local/src" / Path(inputs.module_name)
        plugin_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(PLUGIN_SOURCE, plugin_destination)
        # copytree preserves sealed source modes. The fresh owned copy must
        # remain writable so fail-closed cleanup can remove its directories.
        plugin_workspace = inputs.runtime_root / "plugins-local"
        for candidate in (plugin_workspace, *plugin_workspace.rglob("*")):
            if candidate.is_symlink():
                raise MissingDependency(f"staged native plugin contains a symlink: {candidate}")
            os.chmod(candidate, 0o700 if candidate.is_dir() else 0o600)
        config_dir = inputs.runtime_root / "effective-config"
        logs_dir = inputs.runtime_root / "logs"
        config_dir.mkdir()
        logs_dir.mkdir()
        return NativeRuntimeArtifacts(
            logs_dir=logs_dir,
            result_path=inputs.runtime_root / "result.json",
            transport_observations_path=inputs.runtime_root / "transport-observations.diagnostic.json",
            static_config=config_dir / "traefik-native-static.yaml",
            dynamic_config=config_dir / "traefik-native-dynamic.yaml",
            engine_config=config_dir / "traefik-native-engine.conf",
            event_path=logs_dir / "events.jsonl",
        )
    except Exception as exc:
        if staging_started and not cleanup_staged_runtime_workspaces(inputs):
            raise RuntimeError("Traefik staged runtime cleanup was refused") from exc
        raise


def cleanup_staged_runtime_workspaces(
    inputs: NativeRuntimeInputs, artifacts: NativeRuntimeArtifacts | None = None
) -> bool:
    """Remove only the exact temporary workspaces after preserving raw evidence.

    The result and log files are evidence inputs for the Parent normalizer, so
    they deliberately remain below ``runtime_root``. The local plugin copy,
    generated configuration, and native engine build are instead ephemeral
    execution material. Refuse cleanup when a selected path no longer has its
    expected direct-child, non-symlink directory identity.
    """

    del artifacts  # Documents that evidence paths are intentionally retained.
    root = inputs.runtime_root
    try:
        root_stat = root.lstat()
        if (
            root.is_symlink()
            or not stat.S_ISDIR(root_stat.st_mode)
            or root_stat.st_uid != os.geteuid()
            or stat.S_IMODE(root_stat.st_mode) != 0o700
        ):
            return False
        assert_private_engine_socket_parent_ancestors_are_safe(root, "native runtime root")
        if not shutil.rmtree.avoids_symlink_attacks:
            return False
        for name in ("plugins-local", "effective-config", "engine-build"):
            workspace = root / name
            if workspace.parent != root:
                return False
            try:
                workspace_stat = workspace.lstat()
            except FileNotFoundError:
                continue
            if workspace.is_symlink() or not stat.S_ISDIR(workspace_stat.st_mode):
                return False
            shutil.rmtree(workspace)
            if workspace.exists() or workspace.is_symlink():
                return False
    except (OSError, RuntimeError):
        return False
    return True


def start_native_runtime_setup(
    inputs: NativeRuntimeInputs, artifacts: NativeRuntimeArtifacts
) -> NativeRuntimeSetup:
    """Start the loopback fixture after creating one private engine socket path."""

    engine_socket_dir: EngineSocketDirectory | None = None
    upstream: http.server.ThreadingHTTPServer | None = None
    try:
        engine_socket_dir = create_private_engine_socket_dir(inputs.engine_socket_parent)
        engine_socket = engine_socket_dir.path / ENGINE_SOCKET_FILENAME
        upstream_port = free_port()
        traefik_port = free_port()
        write_static_config(artifacts.static_config, artifacts.dynamic_config, traefik_port, inputs.module_name)
        write_dynamic_config(artifacts.dynamic_config, upstream_port, engine_socket)
        write_engine_config(artifacts.engine_config, inputs.rules_file, artifacts.event_path)
        state = UpstreamState()
        upstream = http.server.ThreadingHTTPServer(
            ("127.0.0.1", upstream_port), upstream_handler(state)
        )
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        return NativeRuntimeSetup(
            engine_socket_dir=engine_socket_dir,
            engine_socket=engine_socket,
            upstream=upstream,
            upstream_port=upstream_port,
            traefik_port=traefik_port,
            state=state,
        )
    except Exception as exc:
        if upstream is not None:
            upstream.shutdown()
            upstream.server_close()
        if not remove_private_engine_socket_dir(engine_socket_dir, inputs.engine_socket_parent):
            raise RuntimeError(
                "Traefik engine socket setup failed and safe cleanup was refused"
            ) from exc
        raise


@contextlib.contextmanager
def running_traefik_host(
    inputs: NativeRuntimeInputs,
    artifacts: NativeRuntimeArtifacts,
    setup: NativeRuntimeSetup,
    processes: NativeProcesses,
    *,
    engine_description: str,
    host_description: str,
) -> Iterator[None]:
    """Start the common engine/host pair while keeping its log descriptors open."""

    engine_binary = build_engine_service(
        inputs.runtime_root, artifacts.logs_dir, inputs.include_dir, inputs.library_dir
    )
    with (artifacts.logs_dir / "engine.stdout.log").open("wb") as engine_stdout, (
        artifacts.logs_dir / ENGINE_STDERR_LOG_FILENAME
    ).open("wb") as engine_stderr:
        processes.engine = subprocess.Popen(
            [
                str(engine_binary),
                "--serve",
                "--config",
                str(artifacts.engine_config),
                "--socket",
                str(setup.engine_socket),
            ],
            cwd=inputs.runtime_root,
            stdout=engine_stdout,
            stderr=engine_stderr,
        )
        wait_for_socket(setup.engine_socket, processes.engine, engine_description)
        with (artifacts.logs_dir / TRAEFIK_STDOUT_LOG_FILENAME).open("wb") as stdout, (
            artifacts.logs_dir / "traefik.stderr.log"
        ).open("wb") as stderr:
            processes.traefik = subprocess.Popen(
                [str(inputs.binary), f"--configFile={artifacts.static_config}"],
                cwd=inputs.runtime_root,
                stdout=stdout,
                stderr=stderr,
            )
            wait_for_port(setup.traefik_port, processes.traefik, host_description)
            yield


def run_native_requests(
    inputs: NativeRuntimeInputs,
    artifacts: NativeRuntimeArtifacts,
    setup: NativeRuntimeSetup,
    processes: NativeProcesses,
) -> NativeRequestResults:
    """Start both host processes and make the bounded lifecycle requests."""

    if os.environ.get("MSCONNECTOR_CRS_RUNTIME") == "1":
        raise RuntimeError("CRS mode must use run_crs_requests")

    with running_traefik_host(
        inputs,
        artifacts,
        setup,
        processes,
        engine_description="persistent Traefik engine service",
        host_description="Traefik native local-plugin host",
    ):
        p1_allow_status, p1_allow_bytes = request_through_traefik(
            setup.traefik_port, REQUEST_BODY, P1_ALLOW_TRANSACTION_ID, http.HTTPStatus.OK
        )
        p1_deny_status, _ = request_through_traefik(
            setup.traefik_port,
            REQUEST_BODY,
            "traefik-native-p1-deny",
            http.HTTPStatus.FORBIDDEN,
            {"X-Modsec-Smoke": "block"},
        )
        p1_alternative_status, _ = request_through_traefik(
            setup.traefik_port,
            REQUEST_BODY,
            "traefik-native-p1-alternative",
            http.HTTPStatus.TOO_MANY_REQUESTS,
            {"X-Modsec-Smoke": "alternative-status"},
        )
        p2_deny_status, _ = request_through_traefik(
            setup.traefik_port, P2_BODY, "traefik-native-p2-deny", http.HTTPStatus.FORBIDDEN
        )
        p3_deny_status, _ = request_through_traefik(
            setup.traefik_port,
            REQUEST_BODY,
            "traefik-native-p3-deny",
            http.HTTPStatus.FORBIDDEN,
            {"X-Native-Response-Rule": "block"},
        )
        keepalive_observation = synchronized_safe_followup(
            setup.traefik_port,
            setup.state,
            REQUEST_BODY,
            "traefik-native-p4-safe",
            "traefik-native-keepalive-followup",
        )
    if processes.traefik.poll() is not None:
        raise RuntimeError(
            f"Traefik exited after native requests with code {processes.traefik.returncode}"
        )
    if processes.engine.poll() is not None:
        raise RuntimeError("persistent Traefik engine exited before lifecycle completion")
    return NativeRequestResults(
        p1_allow_status=p1_allow_status,
        p1_allow_bytes=p1_allow_bytes,
        p1_deny_status=p1_deny_status,
        p1_alternative_status=p1_alternative_status,
        p2_deny_status=p2_deny_status,
        p3_deny_status=p3_deny_status,
        p4_safe_status=int(keepalive_observation["safe_status"]),
        p4_safe_bytes=int(keepalive_observation["safe_response_bytes"]),
        keepalive_observation=keepalive_observation,
    )


def run_crs_requests(
    inputs: NativeRuntimeInputs,
    artifacts: NativeRuntimeArtifacts,
    setup: NativeRuntimeSetup,
    processes: NativeProcesses,
) -> CrsRequestResults:
    """Run canonical CRS requests through Traefik and its private UDS engine."""

    if inputs.rules_profile != "framework-crs-v4.29.0":
        raise MissingDependency("CRS mode requires the pinned Framework CRS rules profile")
    if inputs.run_id is None:
        raise MissingDependency("CRS_RUNTIME_RUN_ID is required for Traefik CRS request correlation")
    request_ids = crs_request_ids(inputs.run_id)
    crs_headers = {
        "Host": CRS_RUNTIME_HOST,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Framework-Run-ID": inputs.run_id,
    }
    with running_traefik_host(
        inputs,
        artifacts,
        setup,
        processes,
        engine_description="persistent Traefik CRS engine service",
        host_description="Traefik CRS native host",
    ):
        allow_status, allow_bytes = request_through_traefik(
            setup.traefik_port,
            b"",
            request_ids.allow,
            http.HTTPStatus.OK,
            crs_headers,
            method="GET",
            path=CRS_ALLOW_PATH,
        )
        block_status, _ = request_through_traefik(
            setup.traefik_port,
            b"",
            request_ids.block,
            http.HTTPStatus.FORBIDDEN,
            crs_headers,
            method="GET",
            path=CRS_BLOCK_PATH,
        )
        bypass_status, bypass_bytes = request_through_traefik(
            setup.traefik_port,
            b"",
            request_ids.bypass,
            http.HTTPStatus.FORBIDDEN,
            crs_headers,
            method="GET",
            path=CRS_BYPASS_PATH,
        )
    if processes.traefik.poll() is not None:
        raise RuntimeError(f"Traefik exited after CRS requests with code {processes.traefik.returncode}")
    if processes.engine.poll() is not None:
        raise RuntimeError("persistent Traefik CRS engine exited before lifecycle completion")
    return CrsRequestResults(
        request_ids=request_ids,
        allow_status=allow_status,
        allow_bytes=allow_bytes,
        block_status=block_status,
        bypass_status=bypass_status,
        bypass_bytes=bypass_bytes,
    )


def finalize_crs_host_observations(
    artifacts: NativeRuntimeArtifacts,
    results: CrsRequestResults,
) -> tuple[dict[str, Any] | None, dict[str, Any], dict[str, Any]]:
    """Bind host decisions and CRS triggers to actual per-request evidence.

    libmodsecurity reports a disruptive anomaly-score decision as rule 949110,
    while the request's canonical SQLi trigger is 942270 in the raw audit/log
    stream.  Keep those observations separate; treating the intervention rule
    as the trigger would lose the contract's requested CRS provenance.
    """

    outcomes = read_host_outcomes(artifacts.event_path)
    matching_events = [
        event
        for event in outcomes
        if event.get("phase") in {"request_headers", "request_body"}
        and event.get("actual_action") == "deny"
        and event.get("visible_http_status") == http.HTTPStatus.FORBIDDEN
        and str(event.get("rule_id")) == CRS_INTERVENTION_RULE_ID
    ]
    block_event = next(
        (event for event in matching_events if event.get("transaction_id") == results.request_ids.block),
        None,
    )
    bypass_event = next(
        (event for event in matching_events if event.get("transaction_id") == results.request_ids.bypass),
        None,
    )
    if block_event is None:
        raise RuntimeError("Traefik CRS block event is not bound to its attack transaction")
    if bypass_event is None:
        raise RuntimeError("Traefik CRS bypass event is not bound to its transformed transaction")

    engine_log = artifacts.logs_dir / ENGINE_STDERR_LOG_FILENAME
    if not engine_log.is_file():
        raise RuntimeError("Traefik CRS engine stderr evidence is missing")
    raw_lines = engine_log.read_text(encoding="utf-8", errors="replace").splitlines()

    def require_trigger(transaction_id: str) -> None:
        marker = f'[unique_id "{transaction_id}"]'
        rule_marker = f'[id "{CRS_RULE_ID}"]'
        if not any(marker in line and rule_marker in line for line in raw_lines):
            raise RuntimeError(
                f"Traefik CRS trigger {CRS_RULE_ID} is not correlated to {transaction_id}"
            )

    require_trigger(results.request_ids.block)
    require_trigger(results.request_ids.bypass)
    allow_event = next(
        (
            event
            for event in outcomes
            if event.get("transaction_id") == results.request_ids.allow
            and event.get("visible_http_status") == http.HTTPStatus.OK
        ),
        None,
    )
    if results.allow_status != http.HTTPStatus.OK or results.allow_bytes < 1:
        raise RuntimeError("Traefik CRS allow request did not produce a real 200 host outcome")
    return allow_event, block_event, bypass_event


def write_crs_success(
    inputs: NativeRuntimeInputs,
    artifacts: NativeRuntimeArtifacts,
    results: CrsRequestResults,
    events: tuple[dict[str, Any] | None, dict[str, Any], dict[str, Any]],
    processes_stopped: bool,
) -> None:
    """Persist only observed CRS host outcomes for the parent normalizer."""

    allow_event, block_event, bypass_event = events
    allow_payload: dict[str, Any] = {
        "request_path": CRS_ALLOW_PATH,
        "request_id": results.request_ids.allow,
        "status": results.allow_status,
        "response_bytes": results.allow_bytes,
    }
    if allow_event is not None:
        allow_payload["observed_event"] = allow_event
    write_json(
        artifacts.result_path,
        {
            "capability_promotion": "canonical-finalization-required",
            "connector": "traefik",
            # This record is written only after the pinned host configuration
            # was accepted, the process became reachable, all CRS outcomes
            # were validated, and both owned processes stopped cleanly.
            "config_test_status": "PASS",
            "engine_mode": "uds",
            "host_start_status": "PASS",
            "integration_mode": "native-traefik-middleware",
            "plugin_loaded": "Plugins loaded." in (artifacts.logs_dir / TRAEFIK_STDOUT_LOG_FILENAME).read_text(
                encoding="utf-8", errors="replace"
            ),
            "processes_stopped": processes_stopped,
            "production_ready": False,
            "reachability_status": "PASS",
            "run_id": inputs.run_id,
            "rules_profile": inputs.rules_profile,
            "crs_rule_id": CRS_RULE_ID,
            "allow": allow_payload,
            "block": {
                "request_path": CRS_BLOCK_PATH,
                "request_id": block_event.get("transaction_id"),
                "status": results.block_status,
                "observed_action": block_event["actual_action"],
                "observed_rule_id": str(block_event.get("rule_id")),
                "trigger_rule_id": CRS_RULE_ID,
                "raw_trigger_log": f"logs/{ENGINE_STDERR_LOG_FILENAME}",
                "intervention_rule_id": str(block_event.get("rule_id")),
                "observed_event": block_event,
            },
            "bypass": {
                "class": "sql-keyword-case-variation",
                "request_path": CRS_BYPASS_PATH,
                "request_id": bypass_event.get("transaction_id"),
                "status": results.bypass_status,
                "response_bytes": results.bypass_bytes,
                "observed_action": bypass_event["actual_action"],
                "observed_rule_id": str(bypass_event.get("rule_id")),
                "trigger_rule_id": CRS_RULE_ID,
                "raw_trigger_log": f"logs/{ENGINE_STDERR_LOG_FILENAME}",
                "intervention_rule_id": str(bypass_event.get("rule_id")),
                "observed_event": bypass_event,
            },
            "status": "PASS",
            "cleanup_status": "PASS" if processes_stopped else "FAIL",
            "traefik_version": traefik_version(inputs.binary),
        },
    )


def observe_live_native_host(
    artifacts: NativeRuntimeArtifacts, setup: NativeRuntimeSetup, processes: NativeProcesses
) -> NativeLiveObservation:
    """Require the expected plugin, streaming fixture, and keep-alive state."""

    host_log = (artifacts.logs_dir / TRAEFIK_STDOUT_LOG_FILENAME).read_text(
        encoding="utf-8", errors="replace"
    )
    plugin_loaded = "Plugins loaded." in host_log and PLUGIN_ID in host_log
    if not plugin_loaded:
        raise RuntimeError("Traefik did not confirm local-plugin loading")
    with setup.state.lock:
        observation = NativeLiveObservation(
            plugin_loaded=plugin_loaded,
            upstream_requests=setup.state.request_count,
            request_body_bytes=setup.state.request_body_bytes,
            response_chunks=setup.state.response_chunks,
            p1_allow_upstream_requests=setup.state.p1_allow_upstream_requests,
        )
        p3_requests = setup.state.p3_requests
        p4_requests = setup.state.p4_requests
    if (
        observation.upstream_requests < 3
        or observation.request_body_bytes < len(REQUEST_BODY)
        or observation.response_chunks < 6
    ):
        raise RuntimeError("native plugin route did not reach the streaming upstream contract")
    if p3_requests < 1 or p4_requests < 1:
        raise RuntimeError("native host did not reach the P3/P4 upstream fixture branches")
    if processes.traefik is None or processes.traefik.poll() is not None:
        raise RuntimeError("Traefik did not survive the keep-alive follow-up")
    return observation


def stop_native_processes(processes: NativeProcesses) -> tuple[bool, bool]:
    """Stop both owned process handles and clear them from subsequent cleanup."""

    traefik_stopped = stop_process(processes.traefik)
    engine_stopped = stop_process(processes.engine)
    processes.traefik = None
    processes.engine = None
    return traefik_stopped, engine_stopped


def finalize_native_host_observations(
    inputs: NativeRuntimeInputs,
    artifacts: NativeRuntimeArtifacts,
    results: NativeRequestResults,
    live_observation: NativeLiveObservation,
) -> int:
    """Bind all lifecycle outcomes to the completed local host transactions."""

    outcomes = read_host_outcomes(artifacts.event_path)
    require_host_outcome(
        outcomes, "request_headers", "deny", http.HTTPStatus.FORBIDDEN, inputs.rule_ids["p1"]
    )
    p1_alternative_event = host_outcome(
        outcomes,
        "request_headers",
        "deny",
        http.HTTPStatus.TOO_MANY_REQUESTS,
        inputs.rule_ids["p1_alternative"],
    )
    if p1_alternative_event.get("transaction_id") != "traefik-native-p1-alternative":
        raise RuntimeError("Traefik P1 alternative outcome is not bound to its host transaction")
    require_host_outcome(
        outcomes, "request_body", "deny", http.HTTPStatus.FORBIDDEN, inputs.rule_ids["p2"]
    )
    require_host_outcome(
        outcomes, "response_headers", "deny", http.HTTPStatus.FORBIDDEN, inputs.rule_ids["p3"]
    )
    phase4_event = host_outcome(
        outcomes, "response_body", "log_only", http.HTTPStatus.OK, inputs.rule_ids["p4"]
    )
    if inputs.first_byte_output is not None:
        write_first_byte_evidence(
            inputs.first_byte_output, results.keepalive_observation, results.p4_safe_bytes
        )
    append_first_byte_host_event(
        artifacts.event_path,
        phase4_event,
        results.keepalive_observation,
        "traefik-native-p4-safe",
        inputs.rule_ids["p4"],
        results.p4_safe_bytes,
        inputs.run_id,
    )
    append_allow_host_event(
        artifacts.event_path,
        results.p1_allow_status,
        results.p1_allow_bytes,
        P1_ALLOW_TRANSACTION_ID,
        live_observation.p1_allow_upstream_requests,
        inputs.run_id,
    )
    write_json(
        artifacts.transport_observations_path,
        {
            "artifact_profile": "native-http1-barrier-observation",
            "capability_promotion": "canonical-finalization-required",
            "canonical_evidence": True,
            "connection_reused": bool(results.keepalive_observation["connection_reused"]),
            "connector": "traefik",
            "diagnostic_case": "phase4_safe_first_byte_barrier",
            "diagnostic_only": False,
            "eos_received": True,
            "first_byte_received": bool(results.keepalive_observation["safe_first_byte_received"]),
            "followup_request_result": "completed",
            "host_survived": True,
            "integration_mode": "native-traefik-middleware",
            "protocol": "http1",
            "response_committed": True,
            "schema_version": 1,
            "strict": {
                "client_visible_abort": False,
                "reason": "The public middleware path has no verified post-commit HTTP/1 abort implementation and no HTTP/2 stream-reset API.",
                "state": "NOT_EXECUTED",
            },
            "transport_result": "completed",
        },
    )
    return len(outcomes)


def write_native_success(
    inputs: NativeRuntimeInputs,
    artifacts: NativeRuntimeArtifacts,
    results: NativeRequestResults,
    live_observation: NativeLiveObservation,
    outcome_count: int,
    processes_stopped: bool,
) -> None:
    """Write the successful local-host result without promoting capability state."""

    write_json(
        artifacts.result_path,
        {
            "capability_promotion": "not_permitted",
            "common_runtime_bridge": True,
            "connector": "traefik",
            "engine_mode": "uds",
            "engine_service_started": True,
            "host_outcome_events": outcome_count,
            "integration_mode": "native-traefik-middleware",
            "p1_deny_rule_id": inputs.rule_ids["p1"],
            "p1_alternative_rule_id": inputs.rule_ids["p1_alternative"],
            "plugin_loaded": live_observation.plugin_loaded,
            "plugin_module": inputs.module_name,
            "p1_allow_response_bytes": results.p1_allow_bytes,
            "p1_allow_status": results.p1_allow_status,
            "p1_deny_status": results.p1_deny_status,
            "p1_alternative_status": results.p1_alternative_status,
            "allowed_request_status": results.p1_allow_status,
            "blocked_request_status": results.p1_deny_status,
            "phase1_alternative_status_client_status": results.p1_alternative_status,
            "p2_deny_status": results.p2_deny_status,
            "p2_deny_rule_id": inputs.rule_ids["p2"],
            "p3_precommit_deny_status": results.p3_deny_status,
            "p3_precommit_deny_rule_id": inputs.rule_ids["p3"],
            "p4_safe_log_only_response_bytes": results.p4_safe_bytes,
            "p4_safe_log_only_status": results.p4_safe_status,
            "p4_safe_log_only_rule_id": inputs.rule_ids["p4"],
            "phase4_rule_observed_status": results.p4_safe_status,
            "phase4_end_of_stream_evaluation_status": results.p4_safe_status,
            "phase4_first_byte_before_response_end_status": results.p4_safe_status,
            "phase4_no_full_response_buffering_status": results.p4_safe_status,
            "p4_strict": "NOT_EXECUTED",
            "keepalive_connection_reused": bool(results.keepalive_observation["connection_reused"]),
            "keepalive_followup_status": int(results.keepalive_observation["followup_status"]),
            "processes_stopped": processes_stopped,
            "production_ready": False,
            "request_body_bytes_observed": live_observation.request_body_bytes,
            "response_chunks_observed": live_observation.response_chunks,
            "rule_evaluation": "host_runtime_observed_not_promoted",
            "rules_profile": inputs.rules_profile,
            "status": "PASS",
            "traefik_version": traefik_version(inputs.binary),
            "transport_observations_diagnostic": artifacts.transport_observations_path.name,
            "upstream_requests": live_observation.upstream_requests,
        },
    )


def write_native_failure(result_path: Path, error_class: str, rule_evaluation: str, stopped: bool) -> None:
    """Write a non-promoting failure result for the isolated native host run."""

    payload: dict[str, Any] = {
        "common_runtime_bridge": True,
        "connector": "traefik",
        "engine_mode": "uds",
        "integration_mode": "native-traefik-middleware",
        "processes_stopped": stopped,
        "production_ready": False,
        "rule_evaluation": rule_evaluation,
        "status": "FAIL",
    }
    if error_class:
        payload["error_class"] = error_class
    write_json(result_path, payload)


def run() -> int:
    """Run the isolated native host lifecycle with safe cleanup on every path."""

    inputs = collect_native_runtime_inputs()
    artifacts = stage_native_runtime(inputs)
    processes = NativeProcesses()
    try:
        setup = start_native_runtime_setup(inputs, artifacts)
    except Exception as exc:
        if not cleanup_staged_runtime_workspaces(inputs):
            raise RuntimeError("Traefik staged runtime cleanup was refused") from exc
        raise
    outcome = 1
    try:
        if os.environ.get("MSCONNECTOR_CRS_RUNTIME") == "1":
            crs_results = run_crs_requests(inputs, artifacts, setup, processes)
            traefik_stopped, engine_stopped = stop_native_processes(processes)
            crs_events = finalize_crs_host_observations(artifacts, crs_results)
            write_crs_success(
                inputs,
                artifacts,
                crs_results,
                crs_events,
                traefik_stopped and engine_stopped,
            )
        else:
            results = run_native_requests(inputs, artifacts, setup, processes)
            live_observation = observe_live_native_host(artifacts, setup, processes)
            traefik_stopped, engine_stopped = stop_native_processes(processes)
            outcome_count = finalize_native_host_observations(
                inputs, artifacts, results, live_observation
            )
            write_native_success(
                inputs,
                artifacts,
                results,
                live_observation,
                outcome_count,
                traefik_stopped and engine_stopped,
            )
        outcome = 0
    except Exception as exc:
        traefik_stopped, engine_stopped = stop_native_processes(processes)
        write_native_failure(
            artifacts.result_path,
            type(exc).__name__,
            "host_runtime_failed",
            traefik_stopped and engine_stopped,
        )
        print(f"FAIL: Traefik native local-plugin host: {type(exc).__name__}", file=sys.stderr)
    finally:
        stop_native_processes(processes)
        setup.upstream.shutdown()
        setup.upstream.server_close()
        socket_cleanup_ok = remove_private_engine_socket_dir(
            setup.engine_socket_dir, inputs.engine_socket_parent
        )
        workspace_cleanup_ok = cleanup_staged_runtime_workspaces(inputs, artifacts)
        if not socket_cleanup_ok or not workspace_cleanup_ok:
            write_native_failure(
                artifacts.result_path,
                "",
                "host_runtime_cleanup_incomplete",
                False,
            )
            print("FAIL: Traefik native local-plugin cleanup was refused", file=sys.stderr)
            outcome = 1
    return outcome


def main() -> int:
    try:
        return run()
    except MissingDependency as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 77
    except Exception as exc:
        print(f"FAIL: Traefik native local-plugin host: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover - command entry point
    raise SystemExit(main())
