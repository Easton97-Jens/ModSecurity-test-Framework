#!/usr/bin/env python3
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
import secrets
import stat
from contextlib import suppress
from pathlib import Path
from typing import Any, Mapping


DEFAULT_RUN_BASENAME = "ModSecurity-conector-verified"
WORKER_BLOCKED_REASON = "BLOCKED: nginx worker cannot access harness docroot"
_PATH_SEPARATOR = os.sep
_FIXED_RUNTIME_TEMP_PARENT_TEXT = os.path.join(_PATH_SEPARATOR, "var", "tmp")
_FIXED_RUNTIME_TEMP_PARENT = Path(_FIXED_RUNTIME_TEMP_PARENT_TEXT)
SYSTEM_WRITE_PREFIXES = (
    "/usr",
    "/usr/local",
    "/opt",
    "/etc",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/run",
    "/root",
)
SYSTEM_WRITE_VAR_ALLOWLIST = (
    _FIXED_RUNTIME_TEMP_PARENT_TEXT,
)
READ_ONLY_SOURCE_MOUNT_ROOTS = (Path("/src"),)
BROAD_RUNTIME_ROOTS = (
    Path(_PATH_SEPARATOR),
    Path(os.path.join(_PATH_SEPARATOR, "tmp")),
    _FIXED_RUNTIME_TEMP_PARENT,
    Path(os.path.join(_PATH_SEPARATOR, "home")),
)
WRITABLE_RUNTIME_PATH_KEYS = (
    "VERIFIED_RUN_ROOT",
    "VERIFIED_STATE_ROOT",
    "VERIFIED_BUILD_ROOT",
    "VERIFIED_SOURCE_ROOT",
    "VERIFIED_TMP_ROOT",
    "VERIFIED_LOG_ROOT",
    "CACHE_ROOT",
    "VERIFIED_COMPONENT_CACHE",
    "NGINX_HARNESS_PARENT",
    "BUILD_ROOT",
    "SOURCE_ROOT",
    "TMP_ROOT",
    "LOG_ROOT",
    "CONNECTOR_COMPONENT_CACHE",
    "MATRIX_ROOT",
    "MRTS_BUILD_ROOT",
    "MRTS_NATIVE_ROOT",
)


def _absolute_path_without_resolution(path: Path | str) -> Path:
    """Normalize a path lexically without following a possible symlink."""
    return Path(os.path.abspath(os.fspath(path)))


def _contains_symbolic_link(path: Path | str) -> bool:
    """Return whether an existing component would redirect this path."""
    absolute = _absolute_path_without_resolution(path)
    try:
        return absolute.resolve(strict=False) != absolute
    except (OSError, RuntimeError):
        return True


def _runtime_path(path: Path | str, label: str) -> Path:
    absolute = _absolute_path_without_resolution(path)
    if _contains_symbolic_link(absolute):
        raise ValueError(f"{label} must not use symbolic links: {absolute}")
    return absolute


def _env_value(env: Mapping[str, str], name: str) -> str:
    return str(env.get(name) or "").strip()


def _environment_runtime_path(
    values: Mapping[str, str],
    label: str,
    default: Path | str,
) -> Path:
    configured = _env_value(values, label)
    return _runtime_path(configured if configured else default, label)


def _matches_path_prefix(path: Path, prefix: str) -> bool:
    text = str(path)
    return text == prefix or text.startswith(prefix + "/")


def _is_root_owned_sticky_shared_directory(details: os.stat_result) -> bool:
    """Return whether an opened public ancestor safely protects child names.

    Sticky, root-owned public directories protect a child created by this user
    from replacement by a different local user.  The caller still validates
    every descendant and the final write root through its own descriptor.
    """

    mode = stat.S_IMODE(details.st_mode)
    return (
        stat.S_ISDIR(details.st_mode)
        and details.st_uid == 0
        and bool(details.st_mode & stat.S_ISVTX)
        and bool(mode & 0o022)
    )


from modsecurity_test_framework.connector_context import (
    connector_root as selected_connector_root,
    test_root as selected_test_root,
)


_CANONICAL_SOURCE_ROOTS = ((selected_connector_root(), selected_test_root())
                           if os.environ.get("CONNECTOR_ROOT") else (selected_test_root(),))


def canonical_project_roots() -> tuple[Path, ...]:
    """Return source roots validated and frozen at adapter startup."""
    return _CANONICAL_SOURCE_ROOTS


def fixed_runtime_temp_parent() -> Path:
    """Return the fixed policy temp parent, never a writable run root.

    The environment cannot select this fallback. Callers must derive and
    validate a narrow child before using it for runtime artifacts.
    """
    return _FIXED_RUNTIME_TEMP_PARENT


def default_verified_run_root(env: Mapping[str, str] | None = None) -> Path:
    values = env or os.environ
    parent_value = _env_value(values, "RUNNER_TEMP") or _env_value(values, "TMPDIR")
    fallback_parent = fixed_runtime_temp_parent()
    parent = (
        _absolute_path_without_resolution(parent_value)
        if parent_value
        else fallback_parent
    )
    if not is_safe_runtime_parent(parent):
        parent = fallback_parent
    return parent / DEFAULT_RUN_BASENAME


def is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def is_under_root_home(path: Path) -> bool:
    return is_under(path, Path("/root"))


def is_read_only_source_path(path: Path) -> bool:
    resolved = path.resolve(strict=False)
    return any(
        resolved == root.resolve(strict=False) or is_under(resolved, root)
        for root in (*READ_ONLY_SOURCE_MOUNT_ROOTS, *canonical_project_roots())
    )


def is_configured_project_path(path: Path, env: Mapping[str, str] | None = None) -> bool:
    """Compatibility helper that deliberately ignores mutable project-root inputs.

    ``REPO_ROOT``, ``CONNECTOR_ROOT``, and ``FRAMEWORK_ROOT`` are location
    hints.  They are not write authorization.  Known source locations remain
    recognizable only for callers that need to preserve read-only source use.
    """
    del env
    return is_read_only_source_path(path)


def is_safe_runtime_parent(path: Path) -> bool:
    """Return whether an invocation parent is safe to derive a child run root."""
    if _contains_symbolic_link(path):
        return False
    resolved = _absolute_path_without_resolution(path)
    if (
        resolved == Path("/")
        or resolved.parent == Path("/")
        or is_read_only_source_path(resolved)
    ):
        return False
    text = str(resolved)
    if text == "/var" or text.startswith("/var/"):
        fixed_parent = fixed_runtime_temp_parent()
        return resolved == fixed_parent or is_under(resolved, fixed_parent)
    return not any(_matches_path_prefix(resolved, prefix) for prefix in SYSTEM_WRITE_PREFIXES)


def is_safe_runtime_root(path: Path) -> bool:
    """Return whether an exact invocation root is narrow enough for writes."""
    if _contains_symbolic_link(path):
        return False
    resolved = _absolute_path_without_resolution(path)
    return resolved not in BROAD_RUNTIME_ROOTS and is_safe_runtime_parent(resolved)


def is_system_write_path(path: Path, env: Mapping[str, str] | None = None) -> bool:
    del env
    resolved = path.resolve(strict=False)
    if is_read_only_source_path(resolved):
        return True
    text = str(resolved)
    if text == "/var":
        return True
    if text.startswith("/var/"):
        for prefix in SYSTEM_WRITE_VAR_ALLOWLIST:
            if text == prefix or text.startswith(prefix + "/"):
                return False
        return True
    return any(text == prefix or text.startswith(prefix + "/") for prefix in SYSTEM_WRITE_PREFIXES)


def allowed_runtime_roots(env: Mapping[str, str] | None = None) -> list[Path]:
    values = env or os.environ
    try:
        paths = verified_runtime_paths(values)
    except ValueError:
        paths = {}
    roots = [Path(paths["VERIFIED_RUN_ROOT"])] if paths else []
    roots.extend((*READ_ONLY_SOURCE_MOUNT_ROOTS, *canonical_project_roots()))
    normalized: list[Path] = []
    for root in roots:
        resolved = root.resolve(strict=False)
        if not (is_safe_runtime_root(resolved) or is_read_only_source_path(resolved)):
            continue
        if resolved not in normalized:
            normalized.append(resolved)
    return normalized


def is_allowed_runtime_path(path: Path, env: Mapping[str, str] | None = None) -> bool:
    resolved = path.resolve(strict=False)
    return any(resolved == root or is_under(resolved, root) for root in allowed_runtime_roots(env))


def verified_runtime_paths(
    env: Mapping[str, str] | None = None,
    *,
    build_root_override: Path | str | None = None,
) -> dict[str, str]:
    values = env or os.environ
    run_root = _environment_runtime_path(
        values, "VERIFIED_RUN_ROOT", default_verified_run_root(values)
    )
    if not is_safe_runtime_root(run_root):
        raise ValueError(f"VERIFIED_RUN_ROOT is unsafe for runtime writes: {run_root}")
    state_root = _environment_runtime_path(values, "VERIFIED_STATE_ROOT", run_root / "state")
    verified_build_root = _environment_runtime_path(
        values, "VERIFIED_BUILD_ROOT", run_root / "build"
    )
    verified_source_root = _environment_runtime_path(
        values, "VERIFIED_SOURCE_ROOT", run_root / "src"
    )
    verified_tmp_root = _environment_runtime_path(values, "VERIFIED_TMP_ROOT", run_root / "tmp")
    verified_log_root = _environment_runtime_path(values, "VERIFIED_LOG_ROOT", run_root / "logs")
    cache_root = _environment_runtime_path(values, "CACHE_ROOT", run_root / "cache-v2")
    verified_component_cache = _environment_runtime_path(
        values, "VERIFIED_COMPONENT_CACHE", cache_root / "shared"
    )

    build_root = (
        _runtime_path(build_root_override, "BUILD_ROOT")
        if build_root_override is not None
        else _environment_runtime_path(values, "BUILD_ROOT", verified_build_root)
    )
    source_root = _environment_runtime_path(values, "SOURCE_ROOT", verified_source_root)
    tmp_root = _environment_runtime_path(values, "TMP_ROOT", verified_tmp_root)
    log_root = _environment_runtime_path(values, "LOG_ROOT", verified_log_root)
    component_cache = _environment_runtime_path(
        values, "CONNECTOR_COMPONENT_CACHE", verified_component_cache
    )
    nginx_harness_parent = _environment_runtime_path(
        values, "NGINX_HARNESS_PARENT", run_root / "nginx-harness"
    )
    matrix_root = _environment_runtime_path(values, "MATRIX_ROOT", build_root / "full-matrix")
    mrts_build_root = _environment_runtime_path(values, "MRTS_BUILD_ROOT", build_root / "mrts")
    mrts_native_root = _environment_runtime_path(
        values, "MRTS_NATIVE_ROOT", build_root / "mrts-native"
    )

    for label, path in (
        ("VERIFIED_STATE_ROOT", state_root),
        ("VERIFIED_BUILD_ROOT", verified_build_root),
        ("VERIFIED_SOURCE_ROOT", verified_source_root),
        ("VERIFIED_TMP_ROOT", verified_tmp_root),
        ("VERIFIED_LOG_ROOT", verified_log_root),
        ("CACHE_ROOT", cache_root),
        ("VERIFIED_COMPONENT_CACHE", verified_component_cache),
        ("NGINX_HARNESS_PARENT", nginx_harness_parent),
        ("BUILD_ROOT", build_root),
        ("SOURCE_ROOT", source_root),
        ("TMP_ROOT", tmp_root),
        ("LOG_ROOT", log_root),
        ("CONNECTOR_COMPONENT_CACHE", component_cache),
        ("MATRIX_ROOT", matrix_root),
        ("MRTS_BUILD_ROOT", mrts_build_root),
        ("MRTS_NATIVE_ROOT", mrts_native_root),
    ):
        if label == "SOURCE_ROOT" and is_read_only_source_path(path):
            continue
        if not is_safe_runtime_root(path):
            raise ValueError(f"{label} is unsafe for runtime writes: {path}")

    return {
        "VERIFIED_RUN_ROOT": str(run_root),
        "VERIFIED_STATE_ROOT": str(state_root),
        "VERIFIED_BUILD_ROOT": str(verified_build_root),
        "VERIFIED_SOURCE_ROOT": str(verified_source_root),
        "VERIFIED_TMP_ROOT": str(verified_tmp_root),
        "VERIFIED_LOG_ROOT": str(verified_log_root),
        "CACHE_ROOT": str(cache_root),
        "VERIFIED_COMPONENT_CACHE": str(verified_component_cache),
        "NGINX_HARNESS_PARENT": str(nginx_harness_parent),
        "BUILD_ROOT": str(build_root),
        "SOURCE_ROOT": str(source_root),
        "TMP_ROOT": str(tmp_root),
        "LOG_ROOT": str(log_root),
        "CONNECTOR_COMPONENT_CACHE": str(component_cache),
        "MATRIX_ROOT": str(matrix_root),
        "MRTS_BUILD_ROOT": str(mrts_build_root),
        "MRTS_NATIVE_ROOT": str(mrts_native_root),
    }


def _open_runtime_root_descriptor() -> tuple[int, int]:
    """Open the filesystem root with the flags required for safe traversal."""
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    path_flag = getattr(os, "O_PATH", None)
    if no_follow is None or directory_flag is None or path_flag is None:
        raise ValueError(
            "safe runtime directories require O_PATH, O_NOFOLLOW and O_DIRECTORY support"
        )
    flags = path_flag | directory_flag | no_follow
    return os.open("/", flags), flags


def _runtime_leaf_flags(ancestor_flags: int) -> int:
    """Keep the actual writable leaf readable rather than a path-only handle."""
    return (ancestor_flags & ~os.O_PATH) | os.O_RDONLY


def _open_runtime_component(
    descriptor: int,
    component: str,
    directory_path: Path,
    flags: int,
) -> int:
    """Create then reopen one path component without following a symlink."""
    try:
        os.mkdir(component, 0o755, dir_fd=descriptor)
    except FileExistsError:
        pass
    try:
        return os.open(component, flags, dir_fd=descriptor)
    except OSError as exc:
        raise ValueError(
            f"runtime directory is unavailable or unsafe: {directory_path}: {exc}"
        ) from exc


def _validate_runtime_ancestor(
    descriptor: int,
    current_path: Path,
    shared_temp_root: Path | None,
) -> Path | None:
    """Validate one opened ancestor and track a trusted sticky shared root."""
    details = os.fstat(descriptor)
    if not stat.S_ISDIR(details.st_mode):
        raise ValueError(f"runtime directory is not a directory: {current_path}")
    trusted_shared_root = _is_root_owned_sticky_shared_directory(details)
    if not trusted_shared_root and stat.S_IMODE(details.st_mode) & 0o022:
        raise ValueError(
            "runtime directory has a group- or world-writable ancestor: "
            f"{current_path}"
        )
    if trusted_shared_root:
        return current_path
    if shared_temp_root is not None and details.st_uid not in {os.geteuid(), 0}:
        raise ValueError(
            "runtime directory has an untrusted owner below shared temporary root "
            f"{shared_temp_root}: {current_path}"
        )
    return shared_temp_root


def _validate_runtime_leaf(descriptor: int, directory_path: Path) -> None:
    """Require a private directory at the final writable runtime path."""
    details = os.fstat(descriptor)
    if not stat.S_ISDIR(details.st_mode):
        raise ValueError(f"runtime directory is not a directory: {directory_path}")
    if details.st_uid != os.geteuid():
        raise ValueError(
            f"runtime directory is not owned by the current user: {directory_path}"
        )
    if stat.S_IMODE(details.st_mode) & 0o022:
        raise ValueError(f"runtime directory is group- or world-writable: {directory_path}")


def ensure_safe_runtime_directory(path: Path | str) -> Path:
    """Create or open one runtime directory without following path symlinks.

    The returned leaf must be owned by the current user and not writable by
    group or other users.  Existing safe directories retain their mode so
    worker-readable directories stay compatible with the runtime harness.
    """

    directory_path = _runtime_path(path, "runtime directory")
    if not is_safe_runtime_root(directory_path):
        raise ValueError(f"runtime directory is unsafe for writes: {directory_path}")

    descriptor, directory_flags = _open_runtime_root_descriptor()
    current_path = Path("/")
    shared_temp_root: Path | None = None
    try:
        components = directory_path.parts[1:]
        for index, component in enumerate(components):
            flags = directory_flags
            if index == len(components) - 1:
                flags = _runtime_leaf_flags(directory_flags)
            child_descriptor = _open_runtime_component(
                descriptor, component, directory_path, flags
            )
            os.close(descriptor)
            descriptor = child_descriptor
            current_path /= component
            shared_temp_root = _validate_runtime_ancestor(
                descriptor, current_path, shared_temp_root
            )

        _validate_runtime_leaf(descriptor, directory_path)
    finally:
        os.close(descriptor)
    return directory_path


_PRIVATE_RUNTIME_DIRECTORY_MODE = 0o700
_PRIVATE_RUNTIME_FILE_MODE = 0o600
_PRIVATE_ARTIFACT_LABEL = "private artifact"
_PRIVATE_RUNTIME_ROOT_LABEL = "private runtime root"
_PRIVATE_RUNTIME_ARTIFACT_NOFOLLOW_ERROR = "private runtime artifacts require O_NOFOLLOW"
_MAX_PRIVATE_RUNTIME_LEAF_NAME = 128


def _private_runtime_leaf_name(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or len(value) > _MAX_PRIVATE_RUNTIME_LEAF_NAME
        or "/" in value
        or "\\" in value
        or "\x00" in value
    ):
        raise ValueError(f"{label} must be one bounded direct filename")
    return value


def _require_private_runtime_directory(details: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid():
        raise ValueError(f"{label} must be an owned directory")
    if stat.S_IMODE(details.st_mode) != _PRIVATE_RUNTIME_DIRECTORY_MODE:
        raise ValueError(f"{label} must have private mode 0700")


def _require_private_runtime_file(details: os.stat_result, label: str) -> None:
    if not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid():
        raise ValueError(f"{label} must be an owned regular file")
    if stat.S_IMODE(details.st_mode) != _PRIVATE_RUNTIME_FILE_MODE:
        raise ValueError(f"{label} must have private mode 0600")
    if details.st_nlink != 1:
        raise ValueError(f"{label} must not have additional hard links")


def _close_runtime_descriptor(descriptor: int) -> None:
    if descriptor < 0:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def _open_private_runtime_components(
    root: Path, descriptor: int, flags: int
) -> tuple[int, int]:
    current_path = Path("/")
    shared_temp_root: Path | None = None
    parent_descriptor = -1
    components = root.parts[1:]
    try:
        for index, component in enumerate(components):
            child_descriptor = -1
            try:
                try:
                    component_flags = flags
                    if index == len(components) - 1:
                        component_flags = _runtime_leaf_flags(flags)
                    child_descriptor = os.open(component, component_flags, dir_fd=descriptor)
                except OSError as exc:
                    raise ValueError(
                        f"private runtime root is unavailable or unsafe: {root}: {exc}"
                    ) from exc
                if index == len(components) - 1:
                    parent_descriptor = os.dup(descriptor)
                os.close(descriptor)
                descriptor = child_descriptor
                child_descriptor = -1
                current_path /= component
                shared_temp_root = _validate_runtime_ancestor(
                    descriptor, current_path, shared_temp_root
                )
            except BaseException:
                _close_runtime_descriptor(child_descriptor)
                raise
        return descriptor, parent_descriptor
    except BaseException:
        _close_runtime_descriptor(descriptor)
        _close_runtime_descriptor(parent_descriptor)
        raise


class PrivateRuntimeRoot:
    """Descriptor-backed access to an existing, exact private runtime root."""

    def __init__(
        self,
        descriptor: int,
        identity: tuple[int, int],
        parent_descriptor: int,
        name: str,
    ) -> None:
        self._descriptor = descriptor
        self._identity = identity
        self._parent_descriptor = parent_descriptor
        self._name = name
        self._closed = False
        self._assert_identity()

    @classmethod
    def open(cls, path: Path | str) -> "PrivateRuntimeRoot":
        root = Path(path)
        if not root.is_absolute():
            raise ValueError(f"private runtime root must be absolute: {root}")
        root = _absolute_path_without_resolution(root)
        if not root.exists() or root.is_symlink() or _contains_symbolic_link(root):
            raise ValueError(f"private runtime root must already exist without symlinks: {root}")
        if not is_safe_runtime_root(root):
            raise ValueError(f"private runtime root is unsafe for writes: {root}")
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        if not directory_flag or not no_follow:
            raise ValueError("private runtime roots require O_DIRECTORY and O_NOFOLLOW")
        descriptor, flags = _open_runtime_root_descriptor()
        parent_descriptor = -1
        leaf_name = root.name
        try:
            try:
                descriptor, parent_descriptor = _open_private_runtime_components(
                    root, descriptor, flags
                )
            except BaseException:
                descriptor = -1
                parent_descriptor = -1
                raise
            details = os.fstat(descriptor)
            _require_private_runtime_directory(details, _PRIVATE_RUNTIME_ROOT_LABEL)
            handle = cls(
                descriptor,
                (details.st_dev, details.st_ino),
                parent_descriptor,
                leaf_name,
            )
            descriptor = -1
            parent_descriptor = -1
            return handle
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            if parent_descriptor >= 0:
                os.close(parent_descriptor)
            raise

    @property
    def descriptor(self) -> int:
        self._assert_identity()
        return self._descriptor

    @property
    def identity(self) -> tuple[int, int]:
        return self._identity

    def _assert_identity(self) -> None:
        if self._closed:
            raise ValueError("private runtime root handle is closed")
        details = os.fstat(self._descriptor)
        if (details.st_dev, details.st_ino) != self._identity:
            raise ValueError("private runtime root descriptor identity changed")
        _require_private_runtime_directory(details, _PRIVATE_RUNTIME_ROOT_LABEL)
        try:
            current = os.stat(
                self._name, dir_fd=self._parent_descriptor, follow_symlinks=False
            )
        except FileNotFoundError as error:
            raise ValueError("private runtime root path was replaced") from error
        if (current.st_dev, current.st_ino) != self._identity:
            raise ValueError("private runtime root path was replaced")
        _require_private_runtime_directory(current, _PRIVATE_RUNTIME_ROOT_LABEL)

    def create_text(self, name: str, value: str, label: str = _PRIVATE_ARTIFACT_LABEL) -> None:
        name = _private_runtime_leaf_name(name, label)
        if not isinstance(value, str):
            raise ValueError(f"{label} must be text")
        self._assert_identity()
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        if not no_follow:
            raise ValueError(_PRIVATE_RUNTIME_ARTIFACT_NOFOLLOW_ERROR)
        descriptor = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
            _PRIVATE_RUNTIME_FILE_MODE, dir_fd=self._descriptor
        )
        try:
            os.fchmod(descriptor, _PRIVATE_RUNTIME_FILE_MODE)
            _require_private_runtime_file(os.fstat(descriptor), label)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = -1
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def read_text(self, name: str, label: str = _PRIVATE_ARTIFACT_LABEL, *, maximum_bytes: int = 1 << 20) -> str:
        name = _private_runtime_leaf_name(name, label)
        if not isinstance(maximum_bytes, int) or maximum_bytes < 0:
            raise ValueError(f"{label} maximum size is invalid")
        self._assert_identity()
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        if not no_follow:
            raise ValueError(_PRIVATE_RUNTIME_ARTIFACT_NOFOLLOW_ERROR)
        descriptor = os.open(name, os.O_RDONLY | no_follow, dir_fd=self._descriptor)
        try:
            details = os.fstat(descriptor)
            _require_private_runtime_file(details, label)
            if details.st_size > maximum_bytes:
                raise ValueError(f"{label} exceeds the bounded private artifact size")
            value = os.read(descriptor, maximum_bytes + 1)
            if len(value) > maximum_bytes:
                raise ValueError(f"{label} exceeds the bounded private artifact size")
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ValueError(f"{label} is not UTF-8 text") from error
        finally:
            os.close(descriptor)

    def replace_text(self, name: str, value: str, label: str = _PRIVATE_ARTIFACT_LABEL) -> None:
        name = _private_runtime_leaf_name(name, label)
        if not isinstance(value, str):
            raise ValueError(f"{label} must be text")
        self._assert_identity()
        original = os.stat(name, dir_fd=self._descriptor, follow_symlinks=False)
        _require_private_runtime_file(original, label)
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        if not no_follow:
            raise ValueError(_PRIVATE_RUNTIME_ARTIFACT_NOFOLLOW_ERROR)
        temporary = f".{name}.{secrets.token_hex(16)}.tmp"
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
            _PRIVATE_RUNTIME_FILE_MODE, dir_fd=self._descriptor
        )
        try:
            os.fchmod(descriptor, _PRIVATE_RUNTIME_FILE_MODE)
            _require_private_runtime_file(os.fstat(descriptor), label)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = -1
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
            current = os.stat(name, dir_fd=self._descriptor, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
                raise ValueError(f"{label} changed before replacement")
            _require_private_runtime_file(current, label)
            os.replace(temporary, name, src_dir_fd=self._descriptor, dst_dir_fd=self._descriptor)
            temporary = ""
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary:
                with suppress(FileNotFoundError):
                    os.unlink(temporary, dir_fd=self._descriptor)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                os.close(self._descriptor)
            finally:
                os.close(self._parent_descriptor)

    def __enter__(self) -> "PrivateRuntimeRoot":
        self._assert_identity()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def open_private_runtime_root(path: Path | str) -> PrivateRuntimeRoot:
    """Open an existing exact 0700 runtime root without materializing it."""
    return PrivateRuntimeRoot.open(path)


def verified_runtime_artifact_root(value: Path | str) -> Path:
    """Return a private root that may contain one invocation's artifacts."""
    root = Path(value)
    if not root.is_absolute():
        raise ValueError(f"runtime root must be absolute: {root}")
    normalized = _absolute_path_without_resolution(root)
    if not is_safe_runtime_root(normalized):
        raise ValueError(f"runtime root is unsafe for writes: {normalized}")
    return ensure_safe_runtime_directory(normalized)


def prepare_verified_runtime_artifact_root(
    override: Path | str | None = None,
    *,
    env: Mapping[str, str] | None = None,
    fallback: Path | str | None = None,
) -> Path:
    """Select and materialize a private verified-run artifact root.

    The explicit caller value has precedence over ``VERIFIED_RUN_ROOT`` and
    the supplied fallback. Normalize relative values lexically, never by
    resolving links, so the artifact-root validator can reject every existing
    symlink component before any lifecycle writer or child process uses it.
    """
    values = os.environ if env is None else env
    selected = (
        override
        or _env_value(values, "VERIFIED_RUN_ROOT")
        or fallback
        or default_verified_run_root(values)
    )
    return verified_runtime_artifact_root(_absolute_path_without_resolution(selected))


def runtime_artifact_path(
    root: Path,
    value: Path | str,
    label: str,
    *,
    must_exist: bool = False,
) -> Path:
    """Validate one regular artifact path below a verified private root."""
    candidate = Path(value)
    if not candidate.is_absolute():
        raise ValueError(f"{label} must be absolute: {candidate}")
    verified_root = ensure_safe_runtime_directory(root)
    normalized = _absolute_path_without_resolution(candidate)
    if normalized == verified_root or not is_under(normalized, verified_root):
        raise ValueError(f"{label} must be below the runtime root: {normalized}")
    if normalized.is_symlink():
        raise ValueError(f"{label} must not be a symbolic link: {normalized}")
    parent = ensure_safe_runtime_directory(normalized.parent)
    if not is_under(parent, verified_root):
        raise ValueError(f"{label} parent escaped the runtime root: {parent}")
    if must_exist and (not normalized.is_file() or normalized.is_symlink()):
        raise ValueError(f"{label} must be an existing regular file: {normalized}")
    return normalized


def runtime_or_source_artifact_path(
    root: Path,
    value: Path | str,
    label: str,
    *,
    must_exist: bool = False,
) -> Path:
    """Validate a read-only source file or a run-local runtime artifact.

    Runtime helpers sometimes hash a checked-in capability/rule file together
    with run-local evidence.  A CLI value may therefore identify only these
    two explicit trust domains: an existing regular file below a canonical
    read-only project root, or an artifact below the caller's private runtime
    root.  It cannot widen reads to an arbitrary host path.
    """

    candidate = Path(value)
    if (
        candidate.is_absolute()
        and candidate.is_file()
        and not candidate.is_symlink()
        and is_read_only_source_path(candidate)
    ):
        return candidate
    return runtime_artifact_path(root, candidate, label, must_exist=must_exist)


def open_runtime_artifact_parent(target: Path) -> int:
    """Open an artifact's already-validated parent without link traversal."""
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory is None:
        raise ValueError("safe runtime artifacts require O_NOFOLLOW and O_DIRECTORY")
    return os.open(target.parent, os.O_RDONLY | directory | no_follow)


def require_regular_runtime_artifact(descriptor: int, label: str) -> None:
    """Reject a descriptor that does not reference a regular file."""
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        raise ValueError(f"{label} must be a regular file")


def _existing_regular_runtime_artifact(
    parent_descriptor: int,
    target: Path,
    label: str,
) -> None:
    try:
        existing = os.stat(target.name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(existing.st_mode):
        raise ValueError(f"{label} must be a regular file")


def read_runtime_artifact_text(
    root: Path,
    value: Path | str,
    label: str,
    *,
    errors: str | None = None,
) -> str:
    """Read a regular artifact through no-follow descriptors only."""
    target = runtime_artifact_path(root, value, label, must_exist=True)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ValueError("safe runtime artifact reads require O_NOFOLLOW")
    parent_descriptor = open_runtime_artifact_parent(target)
    descriptor = -1
    try:
        descriptor = os.open(target.name, os.O_RDONLY | no_follow, dir_fd=parent_descriptor)
        require_regular_runtime_artifact(descriptor, label)
        with os.fdopen(descriptor, "r", encoding="utf-8", errors=errors) as stream:
            descriptor = -1
            return stream.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def append_runtime_artifact_text(
    root: Path,
    value: Path | str,
    text: str,
    label: str,
) -> Path:
    """Append text to a private regular artifact through no-follow descriptors."""
    target = runtime_artifact_path(root, value, label)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ValueError("safe runtime artifact writes require O_NOFOLLOW")
    parent_descriptor = open_runtime_artifact_parent(target)
    descriptor = -1
    try:
        _existing_regular_runtime_artifact(parent_descriptor, target, label)
        descriptor = os.open(
            target.name,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | no_follow,
            0o600,
            dir_fd=parent_descriptor,
        )
        require_regular_runtime_artifact(descriptor, label)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)
    return target


def write_runtime_artifact_text_atomic(
    root: Path,
    value: Path | str,
    text: str,
    label: str,
) -> Path:
    """Atomically replace a private regular artifact without following links."""
    target = runtime_artifact_path(root, value, label)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ValueError("safe runtime artifact writes require O_NOFOLLOW")
    parent_descriptor = open_runtime_artifact_parent(target)
    temporary_name: str | None = None
    temporary_created = False
    descriptor = -1
    try:
        _existing_regular_runtime_artifact(parent_descriptor, target, label)
        for _ in range(100):
            temporary_name = f".{target.name}.{secrets.token_hex(16)}.tmp"
            try:
                descriptor = os.open(
                    temporary_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
                    0o600,
                    dir_fd=parent_descriptor,
                )
            except FileExistsError:
                temporary_name = None
                continue
            temporary_created = True
            break
        else:
            raise ValueError(f"could not allocate a temporary {label}")
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        _existing_regular_runtime_artifact(parent_descriptor, target, label)
        os.replace(
            temporary_name,
            target.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        temporary_name = None
        temporary_created = False
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_created and temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        os.close(parent_descriptor)
    return target


def _open_temporary_runtime_artifact(
    destination_parent_descriptor: int,
    destination_target: Path,
    label: str,
    no_follow: int,
) -> tuple[int, str]:
    """Exclusively create a private no-follow temporary destination artifact."""
    for _ in range(100):
        temporary_name = f".{destination_target.name}.{secrets.token_hex(16)}.tmp"
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
                0o600,
                dir_fd=destination_parent_descriptor,
            )
        except FileExistsError:
            continue
        return descriptor, temporary_name
    raise ValueError(f"could not allocate a temporary {label} destination")


def _copy_runtime_artifact_bytes(
    source_descriptor: int,
    destination_descriptor: int,
    label: str,
) -> None:
    """Copy every source byte, retrying short writes and failing on no progress."""
    while True:
        chunk = os.read(source_descriptor, 1024 * 1024)
        if not chunk:
            return
        written = 0
        while written < len(chunk):
            count = os.write(destination_descriptor, chunk[written:])
            if count <= 0:
                raise OSError(f"unable to write {label} destination")
            written += count


def _unlink_temporary_runtime_artifact(
    destination_parent_descriptor: int,
    temporary_name: str,
) -> None:
    """Remove a task-created temporary artifact when it still exists."""
    try:
        os.unlink(temporary_name, dir_fd=destination_parent_descriptor)
    except FileNotFoundError:
        pass


def _copy_runtime_artifact_to_destination(
    source_descriptor: int,
    destination_parent_descriptor: int,
    destination_target: Path,
    label: str,
    no_follow: int,
) -> None:
    """Copy a pinned source descriptor into a private, atomically installed file."""
    temporary_name: str | None = None
    destination_descriptor = -1
    try:
        _existing_regular_runtime_artifact(
            destination_parent_descriptor, destination_target, f"{label} destination"
        )
        destination_descriptor, temporary_name = _open_temporary_runtime_artifact(
            destination_parent_descriptor,
            destination_target,
            label,
            no_follow,
        )

        require_regular_runtime_artifact(
            destination_descriptor, f"{label} destination"
        )
        _copy_runtime_artifact_bytes(source_descriptor, destination_descriptor, label)
        os.fchmod(destination_descriptor, 0o600)
        os.fsync(destination_descriptor)
        os.close(destination_descriptor)
        destination_descriptor = -1

        _existing_regular_runtime_artifact(
            destination_parent_descriptor, destination_target, f"{label} destination"
        )
        os.replace(
            temporary_name,
            destination_target.name,
            src_dir_fd=destination_parent_descriptor,
            dst_dir_fd=destination_parent_descriptor,
        )
        temporary_name = None
    finally:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
        if temporary_name is not None:
            _unlink_temporary_runtime_artifact(
                destination_parent_descriptor, temporary_name
            )


def _unlink_unchanged_runtime_artifact(
    source_parent_descriptor: int,
    source_target: Path,
    source_details: os.stat_result,
    label: str,
) -> None:
    """Remove the original name only when it still references the pinned source."""
    current_source = os.stat(
        source_target.name,
        dir_fd=source_parent_descriptor,
        follow_symlinks=False,
    )
    if (
        not stat.S_ISREG(current_source.st_mode)
        or current_source.st_dev != source_details.st_dev
        or current_source.st_ino != source_details.st_ino
    ):
        raise ValueError(f"{label} source changed while being moved")
    os.unlink(source_target.name, dir_fd=source_parent_descriptor)


def move_runtime_artifact_atomic(
    source_root: Path,
    source: Path | str,
    destination_root: Path,
    destination: Path | str,
    label: str,
) -> Path:
    """Move one private regular artifact between verified roots without link traversal.

    The destination is written through a fresh no-follow temporary file and
    atomically installed before the source is removed.  The source descriptor
    pins the bytes being copied; the final unlink additionally requires the
    original inode so a concurrent replacement cannot be removed by mistake.
    """

    source_target = runtime_artifact_path(
        source_root, source, f"{label} source", must_exist=True
    )
    destination_target = runtime_artifact_path(
        destination_root, destination, f"{label} destination"
    )
    if source_target == destination_target:
        raise ValueError(f"{label} source and destination must differ")

    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ValueError("safe runtime artifact moves require O_NOFOLLOW")

    source_parent_descriptor = open_runtime_artifact_parent(source_target)
    destination_parent_descriptor = open_runtime_artifact_parent(destination_target)
    source_descriptor = -1
    try:
        source_descriptor = os.open(
            source_target.name,
            os.O_RDONLY | no_follow,
            dir_fd=source_parent_descriptor,
        )
        require_regular_runtime_artifact(source_descriptor, f"{label} source")
        source_details = os.fstat(source_descriptor)

        _copy_runtime_artifact_to_destination(
            source_descriptor,
            destination_parent_descriptor,
            destination_target,
            label,
            no_follow,
        )
        _unlink_unchanged_runtime_artifact(
            source_parent_descriptor, source_target, source_details, label
        )
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
        os.close(destination_parent_descriptor)
        os.close(source_parent_descriptor)
    return destination_target


def ensure_safe_writable_runtime_paths(paths: Mapping[str, str]) -> None:
    """Materialize every write-capable verified runtime path without following links.

    ``verified_runtime_paths()`` keeps canonical source locations available for
    read-only inputs.  All other returned locations can become write sinks in
    a lifecycle child, so create and inspect them before exporting the values.
    """

    for key in WRITABLE_RUNTIME_PATH_KEYS:
        try:
            path = Path(paths[key])
        except KeyError as exc:
            raise ValueError(f"missing verified runtime path: {key}") from exc
        if key == "SOURCE_ROOT" and is_read_only_source_path(_runtime_path(path, key)):
            continue
        ensure_safe_runtime_directory(path)


def path_status(
    path: str | Path,
    *,
    label: str,
    connector_root: Path,
    framework_root: Path,
    allowed_roots: list[Path],
    worker_compatible: bool = False,
) -> dict[str, Any]:
    resolved = Path(path).resolve(strict=False)
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
    if worker_compatible and is_under_root_home(resolved) and not read_only_source:
        status = "BLOCKED"
        notes.append("path is under /root and is not worker-traversable")
    safe_allowed_roots = [
        root.resolve(strict=False)
        for root in allowed_roots
        if is_safe_runtime_root(root.resolve(strict=False))
    ]
    if not read_only_source and not any(resolved == root or is_under(resolved, root) for root in safe_allowed_roots):
        status = "BLOCKED"
        notes.append("path is outside verified runtime roots")
    if read_only_source:
        notes.append("read-only source path")
    return {"variable": label, "value": str(resolved), "status": status, "notes": "; ".join(notes) or "ok"}


def runtime_path_rows(
    paths: Mapping[str, str],
    *,
    connector_root: Path,
    framework_root: Path,
) -> list[dict[str, Any]]:
    allowed = [Path(value) for value in paths.values()]
    order = (
        "VERIFIED_RUN_ROOT",
        "VERIFIED_BUILD_ROOT",
        "VERIFIED_SOURCE_ROOT",
        "VERIFIED_TMP_ROOT",
        "VERIFIED_LOG_ROOT",
        "CACHE_ROOT",
        "VERIFIED_COMPONENT_CACHE",
        "NGINX_HARNESS_PARENT",
        "BUILD_ROOT",
        "SOURCE_ROOT",
        "TMP_ROOT",
        "LOG_ROOT",
        "CONNECTOR_COMPONENT_CACHE",
    )
    return [
        path_status(
            paths[name],
            label=name,
            connector_root=connector_root,
            framework_root=framework_root,
            allowed_roots=allowed,
            worker_compatible=name == "NGINX_HARNESS_PARENT",
        )
        for name in order
        if name in paths
    ]
