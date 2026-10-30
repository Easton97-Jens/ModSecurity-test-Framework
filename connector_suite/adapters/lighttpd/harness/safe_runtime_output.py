"""Create Lighttpd harness outputs only below a verified private runtime root."""

from __future__ import annotations

import os
from contextlib import ExitStack
from pathlib import Path
import secrets
import stat
import sys


from modsecurity_connector_ci.lib.runtime_path_utils import ensure_safe_runtime_directory, is_safe_runtime_root, is_under, read_runtime_artifact_text, runtime_artifact_path


_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_MAX_PRIVATE_LEAF_NAME_LENGTH = 128


def _directory_open_flags() -> int:
    """Return the no-follow flags required for a private directory handle."""

    directory = getattr(os, "O_DIRECTORY", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    if not directory or not no_follow:
        raise ValueError("private runtime directories require O_DIRECTORY and O_NOFOLLOW")
    return os.O_RDONLY | directory | no_follow


def _no_follow_flag() -> int:
    """Return the required kernel flag for private artifact opens."""

    value = getattr(os, "O_NOFOLLOW", 0)
    if not value:
        raise ValueError("private runtime artifacts require O_NOFOLLOW")
    return value


def _validate_private_leaf_name(value: str, label: str) -> str:
    """Accept one direct, bounded filename and never a path expression."""

    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or len(value) > _MAX_PRIVATE_LEAF_NAME_LENGTH
        or "/" in value
        or "\\" in value
        or "\x00" in value
    ):
        raise ValueError(f"{label} must be one bounded direct filename")
    return value


def _parse_directory_identity(value: str) -> tuple[int, int]:
    """Parse an exact ``st_dev:st_ino`` token supplied by a trusted caller."""

    if not isinstance(value, str):
        raise ValueError("private runtime directory identity must be text")
    parts = value.split(":")
    if len(parts) != 2 or any(not part.isdecimal() for part in parts):
        raise ValueError("private runtime directory identity must be dev:ino")
    identity = tuple(int(part) for part in parts)
    if identity[0] < 0 or identity[1] <= 0:
        raise ValueError("private runtime directory identity is invalid")
    return identity


def _require_private_directory(details: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid():
        raise ValueError(f"{label} must be an owned directory")
    if stat.S_IMODE(details.st_mode) != _PRIVATE_DIRECTORY_MODE:
        raise ValueError(f"{label} must have private mode 0700")


def _require_safe_runtime_root(details: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid():
        raise ValueError(f"{label} must be an owned directory")
    if stat.S_IMODE(details.st_mode) & 0o022:
        raise ValueError(f"{label} must not be group- or world-writable")


def _require_private_regular_file(details: os.stat_result, label: str) -> None:
    if not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid():
        raise ValueError(f"{label} must be an owned regular file")
    if stat.S_IMODE(details.st_mode) != _PRIVATE_FILE_MODE:
        raise ValueError(f"{label} must have private mode 0600")
    if details.st_nlink != 1:
        raise ValueError(f"{label} must not have additional hard links")


def _list_private_directory(descriptor: int) -> list[str]:
    """List through a fresh descriptor so one directory stream cannot go stale."""

    fresh_descriptor = os.open(".", _directory_open_flags(), dir_fd=descriptor)
    try:
        return os.listdir(fresh_descriptor)
    finally:
        os.close(fresh_descriptor)


def _reject_legacy_children(
    parent_descriptor: int, rejected_names: tuple[str, ...]
) -> None:
    for legacy_name in rejected_names:
        legacy_name = _validate_private_leaf_name(
            legacy_name, "rejected legacy runtime child"
        )
        try:
            os.stat(legacy_name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise ValueError(f"legacy runtime child already exists: {legacy_name}")


def _cleanup_created_child(
    parent_descriptor: int, name: str, identity: tuple[int, int]
) -> None:
    current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if (current.st_dev, current.st_ino) != identity:
        raise ValueError("new private runtime directory was replaced during setup")
    _require_private_directory(current, "new private runtime directory")
    os.rmdir(name, dir_fd=parent_descriptor)


def _create_private_child(
    parent_descriptor: int, prefix: str, flags: int
) -> tuple[str, tuple[int, int], int]:
    """Create and verify one child below a held private-root descriptor."""

    for _ in range(100):
        candidate = f"{prefix}{secrets.token_hex(16)}"
        try:
            os.mkdir(candidate, _PRIVATE_DIRECTORY_MODE, dir_fd=parent_descriptor)
        except FileExistsError:
            continue
        created = os.stat(candidate, dir_fd=parent_descriptor, follow_symlinks=False)
        identity = (created.st_dev, created.st_ino)
        with ExitStack() as cleanup:
            cleanup.callback(
                _cleanup_created_child, parent_descriptor, candidate, identity
            )
            child_descriptor = os.open(candidate, flags, dir_fd=parent_descriptor)
            cleanup.callback(os.close, child_descriptor)
            _require_private_directory(
                os.fstat(child_descriptor), "new private runtime directory"
            )
            os.fchmod(child_descriptor, _PRIVATE_DIRECTORY_MODE)
            cleanup.pop_all()
            return candidate, identity, child_descriptor
    raise ValueError("could not create a collision-free private runtime directory")


def verified_runtime_output_root(value: Path) -> Path:
    """Return one private runtime root, never a source or broad system path."""

    if not value.is_absolute():
        raise ValueError(f"runtime output root must be absolute: {value}")
    root = Path(os.path.abspath(value))
    if not is_safe_runtime_root(root):
        raise ValueError(f"runtime output root is unsafe for writes: {root}")
    return ensure_safe_runtime_directory(root)


def safe_output_path(root: Path, value: Path, label: str) -> Path:
    """Validate a regular output location strictly below the private root."""

    if not value.is_absolute():
        raise ValueError(f"{label} must be absolute: {value}")
    output = Path(os.path.abspath(value))
    if output == root or not is_under(output, root):
        raise ValueError(f"{label} must be below the runtime output root: {output}")
    if output.is_symlink():
        raise ValueError(f"{label} must not be a symbolic link: {output}")
    parent = ensure_safe_runtime_directory(output.parent)
    if not is_under(parent, root):
        raise ValueError(f"{label} parent escaped the runtime output root: {parent}")
    return output


def safe_input_path(root: Path, value: Path, label: str) -> Path:
    """Validate an existing regular runtime artifact before it is consumed."""

    return runtime_artifact_path(root, value, label, must_exist=True)


def read_runtime_input_text(root: Path, value: Path, label: str) -> str:
    """Read one validated runtime artifact without following symbolic links."""

    return read_runtime_artifact_text(root, value, label)


def write_text_atomic(root: Path, output: Path, content: str, label: str) -> Path:
    """Write one text artifact without following output or temporary-file links."""

    destination = safe_output_path(root, output, label)
    no_follow = _no_follow_flag()
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return destination


class BoundRuntimeDirectory:
    """One private direct runtime child held by a verified directory descriptor.

    The caller must retain the opaque ``identity`` token and use it whenever
    reopening the child.  Every artifact operation below uses ``dir_fd``;
    consequently a later pathname replacement cannot redirect a read, write,
    unlink, or cleanup operation into a replacement directory.
    """

    def __init__(
        self,
        *,
        directory_descriptor: int,
        identity: tuple[int, int],
        parent_descriptor: int | None = None,
        name: str | None = None,
    ) -> None:
        self._directory_descriptor = directory_descriptor
        self._identity = identity
        self._parent_descriptor = parent_descriptor
        self._name = name
        self._closed = False
        self._assert_directory_identity()

    @property
    def identity(self) -> str:
        return f"{self._identity[0]}:{self._identity[1]}"

    @property
    def name(self) -> str | None:
        return self._name

    @property
    def descriptor(self) -> int:
        self._assert_open()
        return self._directory_descriptor

    def _assert_open(self) -> None:
        if self._closed:
            raise ValueError("private runtime directory handle is closed")

    def _assert_directory_identity(self) -> os.stat_result:
        self._assert_open()
        details = os.fstat(self._directory_descriptor)
        if (details.st_dev, details.st_ino) != self._identity:
            raise ValueError("private runtime directory descriptor identity changed")
        _require_private_directory(details, "private runtime directory")
        return details

    @classmethod
    def create(
        cls,
        root: Path,
        *,
        prefix: str,
        rejected_legacy_names: tuple[str, ...] = (),
    ) -> "BoundRuntimeDirectory":
        """Create one opaque direct child atomically below ``root``.

        The resulting child is always mode 0700.  Known legacy names are
        rejected rather than adopted, so a caller-controlled old directory
        cannot become a cleanup or output target.
        """

        root = verified_runtime_output_root(root)
        prefix = _validate_private_leaf_name(prefix, "private runtime directory prefix")
        if not prefix.startswith(".") or not prefix.endswith("-"):
            raise ValueError("private runtime directory prefix must be an opaque dotted stem")
        flags = _directory_open_flags()
        parent_descriptor = os.open(root, flags)
        child_descriptor = -1
        name: str | None = None
        identity: tuple[int, int] | None = None
        try:
            _require_safe_runtime_root(os.fstat(parent_descriptor), "runtime output root")
            _reject_legacy_children(parent_descriptor, rejected_legacy_names)
            name, identity, child_descriptor = _create_private_child(
                parent_descriptor, prefix, flags
            )
            handle = cls(
                directory_descriptor=child_descriptor,
                identity=identity,
                parent_descriptor=parent_descriptor,
                name=name,
            )
            child_descriptor = -1
            parent_descriptor = -1
            return handle
        except BaseException as error:
            if child_descriptor >= 0:
                os.close(child_descriptor)
                child_descriptor = -1
            if name is not None and identity is not None:
                try:
                    _cleanup_created_child(parent_descriptor, name, identity)
                except (OSError, ValueError) as cleanup_error:
                    raise ValueError(
                        f"private runtime directory setup failed and exact cleanup failed: {cleanup_error}"
                    ) from error
            raise
        finally:
            if child_descriptor >= 0:
                os.close(child_descriptor)
            if parent_descriptor >= 0:
                os.close(parent_descriptor)

    @classmethod
    def open(
        cls, root: Path, *, name: str, identity: str
    ) -> "BoundRuntimeDirectory":
        """Open an existing direct child only when its kernel token matches."""

        root = verified_runtime_output_root(root)
        name = _validate_private_leaf_name(name, "private runtime directory name")
        expected_identity = _parse_directory_identity(identity)
        flags = _directory_open_flags()
        parent_descriptor = os.open(root, flags)
        child_descriptor = -1
        try:
            _require_safe_runtime_root(os.fstat(parent_descriptor), "runtime output root")
            child_descriptor = os.open(name, flags, dir_fd=parent_descriptor)
            details = os.fstat(child_descriptor)
            if (details.st_dev, details.st_ino) != expected_identity:
                raise ValueError("private runtime directory identity changed")
            _require_private_directory(details, "private runtime directory")
            handle = cls(
                directory_descriptor=child_descriptor,
                identity=expected_identity,
                parent_descriptor=parent_descriptor,
                name=name,
            )
            child_descriptor = -1
            parent_descriptor = -1
            return handle
        finally:
            if child_descriptor >= 0:
                os.close(child_descriptor)
            if parent_descriptor >= 0:
                os.close(parent_descriptor)

    def create_empty_file(self, name: str, label: str) -> int:
        """Create one fresh private regular artifact relative to the held fd."""

        name = _validate_private_leaf_name(name, label)
        self._assert_directory_identity()
        no_follow = _no_follow_flag()
        descriptor = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | no_follow,
            _PRIVATE_FILE_MODE,
            dir_fd=self._directory_descriptor,
        )
        try:
            os.fchmod(descriptor, _PRIVATE_FILE_MODE)
            _require_private_regular_file(os.fstat(descriptor), label)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def require_absent(self, name: str, label: str) -> None:
        """Reject an existing leaf before a producer reserves its output name."""

        name = _validate_private_leaf_name(name, label)
        self._assert_directory_identity()
        try:
            os.stat(name, dir_fd=self._directory_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise ValueError(f"{label} must be fresh")

    def write_bytes_atomic(self, name: str, value: bytes, label: str) -> None:
        """Install one fresh private file without following or overwriting names."""

        name = _validate_private_leaf_name(name, label)
        if not isinstance(value, bytes):
            raise ValueError(f"{label} must be bytes")
        self._assert_directory_identity()
        no_follow = _no_follow_flag()
        temporary_name: str | None = None
        descriptor = -1
        try:
            for _ in range(100):
                candidate = f".{name}.{secrets.token_hex(16)}.tmp"
                try:
                    descriptor = os.open(
                        candidate,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
                        _PRIVATE_FILE_MODE,
                        dir_fd=self._directory_descriptor,
                    )
                except FileExistsError:
                    continue
                temporary_name = candidate
                break
            if temporary_name is None:
                raise ValueError(f"{label} could not reserve a private temporary artifact")
            os.fchmod(descriptor, _PRIVATE_FILE_MODE)
            _require_private_regular_file(os.fstat(descriptor), label)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
            self._assert_directory_identity()
            try:
                os.link(
                    temporary_name,
                    name,
                    src_dir_fd=self._directory_descriptor,
                    dst_dir_fd=self._directory_descriptor,
                    follow_symlinks=False,
                )
            except FileExistsError as error:
                raise ValueError(f"{label} already exists") from error
            os.unlink(temporary_name, dir_fd=self._directory_descriptor)
            temporary_name = None
            self._assert_directory_identity()
            descriptor = os.open(
                name,
                os.O_RDONLY | no_follow,
                dir_fd=self._directory_descriptor,
            )
            _require_private_regular_file(os.fstat(descriptor), label)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name, dir_fd=self._directory_descriptor)
                except FileNotFoundError:
                    pass

    def write_text_atomic(self, name: str, value: str, label: str) -> None:
        if not isinstance(value, str):
            raise ValueError(f"{label} must be text")
        self.write_bytes_atomic(name, value.encode("utf-8"), label)

    def read_bytes(self, name: str, label: str, *, maximum_bytes: int) -> bytes:
        """Read one bounded private artifact through the held directory fd."""

        name = _validate_private_leaf_name(name, label)
        if not isinstance(maximum_bytes, int) or maximum_bytes < 0:
            raise ValueError(f"{label} maximum size is invalid")
        self._assert_directory_identity()
        no_follow = _no_follow_flag()
        descriptor = os.open(
            name, os.O_RDONLY | no_follow, dir_fd=self._directory_descriptor
        )
        try:
            details = os.fstat(descriptor)
            _require_private_regular_file(details, label)
            if details.st_size > maximum_bytes:
                raise ValueError(f"{label} exceeds the bounded private artifact size")
            chunks: list[bytes] = []
            remaining = maximum_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            value = b"".join(chunks)
            if len(value) > maximum_bytes:
                raise ValueError(f"{label} exceeds the bounded private artifact size")
            self._assert_directory_identity()
            return value
        finally:
            os.close(descriptor)

    def read_text(self, name: str, label: str, *, maximum_bytes: int) -> str:
        try:
            return self.read_bytes(name, label, maximum_bytes=maximum_bytes).decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(f"{label} is not UTF-8 text") from error

    def cleanup_allowed(self, allowed_names: tuple[str, ...]) -> None:
        """Remove exactly the known private leaf artifacts, never recursively."""

        if self._parent_descriptor is None or self._name is None:
            raise ValueError("private runtime directory cleanup needs its direct parent handle")
        allowed = {
            _validate_private_leaf_name(name, "allowed private runtime artifact")
            for name in allowed_names
        }
        if len(allowed) != len(allowed_names):
            raise ValueError("allowed private runtime artifact names are not unique")
        self._assert_directory_identity()
        entries = _list_private_directory(self._directory_descriptor)
        unexpected = sorted(set(entries) - allowed)
        if unexpected:
            raise ValueError(
                f"private runtime directory cleanup refuses unexpected entries: {unexpected}"
            )
        for name in sorted(entries):
            self._assert_directory_identity()
            details = os.stat(
                name, dir_fd=self._directory_descriptor, follow_symlinks=False
            )
            _require_private_regular_file(details, f"private runtime cleanup artifact {name}")
            self._assert_directory_identity()
            os.unlink(name, dir_fd=self._directory_descriptor)
        if _list_private_directory(self._directory_descriptor):
            raise ValueError("private runtime directory cleanup target remains non-empty")
        self._assert_directory_identity()
        current = os.stat(
            self._name, dir_fd=self._parent_descriptor, follow_symlinks=False
        )
        if (current.st_dev, current.st_ino) != self._identity:
            raise ValueError("private runtime directory changed before cleanup removal")
        _require_private_directory(current, "private runtime cleanup target")
        os.rmdir(self._name, dir_fd=self._parent_descriptor)
        try:
            os.stat(self._name, dir_fd=self._parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise ValueError("private runtime directory remains after cleanup removal")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            os.close(self._directory_descriptor)
        finally:
            if self._parent_descriptor is not None:
                os.close(self._parent_descriptor)
                self._parent_descriptor = None

    def __enter__(self) -> "BoundRuntimeDirectory":
        self._assert_open()
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def create_private_runtime_directory(
    root: Path, *, prefix: str, rejected_legacy_names: tuple[str, ...] = ()
) -> BoundRuntimeDirectory:
    """Create an opaque direct private child held by a directory descriptor."""

    return BoundRuntimeDirectory.create(
        root, prefix=prefix, rejected_legacy_names=rejected_legacy_names
    )


def open_private_runtime_directory(
    root: Path, *, name: str, identity: str
) -> BoundRuntimeDirectory:
    """Open a previously-created private child only with its exact token."""

    return BoundRuntimeDirectory.open(root, name=name, identity=identity)
