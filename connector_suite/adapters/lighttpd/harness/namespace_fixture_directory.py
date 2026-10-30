"""Descriptor-bound I/O for the private No-CRS fixture tmpfs.

This module intentionally does not share the generic runtime-directory cleanup
API.  The private fixture directory is released only when the Mount/PID
namespace ends; this module never invokes ``rmdir`` on its mutable name.
"""

from __future__ import annotations

import os
from pathlib import Path
import secrets
import stat


PRIVATE_TMPFS_MOUNT = Path(os.sep, "tmp")
FIXTURE_ROOT = PRIVATE_TMPFS_MOUNT / "msconnector-lighttpd-no-crs-fixture"
_FIXTURE_ROOT_LABEL = "namespace fixture root"
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
MAX_LEAF_NAME_LENGTH = 128
_CAPABILITY_FIELDS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")


def _status_field(name: str) -> str:
    """Read one status field without accepting a missing kernel assertion."""

    try:
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition(":")
            if separator and key == name:
                return value.strip()
    except OSError as error:
        raise ValueError("namespace fixture cannot inspect capability status") from error
    raise ValueError(f"namespace fixture capability status has no {name} field")


def _require_post_capability_drop() -> None:
    """Require the launcher to have completed all privileged setup already."""

    for field in _CAPABILITY_FIELDS:
        if _status_field(field) != "0000000000000000":
            raise ValueError(f"namespace fixture retained {field}")
    if _status_field("NoNewPrivs") != "1":
        raise ValueError("namespace fixture requires no_new_privs")


def _directory_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", 0)
    if not directory:
        raise ValueError("namespace fixture directory requires O_DIRECTORY and O_NOFOLLOW")
    return os.O_RDONLY | directory | _no_follow_flag()


def _no_follow_flag() -> int:
    """Require the kernel no-follow primitive for every fixture leaf open."""

    value = getattr(os, "O_NOFOLLOW", 0)
    if not value:
        raise ValueError("namespace fixture directory requires O_NOFOLLOW")
    return value


def _leaf(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or len(value) > MAX_LEAF_NAME_LENGTH
        or "/" in value
        or "\\" in value
        or "\x00" in value
    ):
        raise ValueError(f"{label} must be one bounded direct filename")
    return value


def _identity(value: str) -> tuple[int, int]:
    parts = value.split(":") if isinstance(value, str) else []
    if len(parts) != 2 or any(not part.isdecimal() for part in parts):
        raise ValueError("namespace fixture identity must be dev:ino")
    result = (int(parts[0]), int(parts[1]))
    if result[0] < 0 or result[1] <= 0:
        raise ValueError("namespace fixture identity is invalid")
    return result


def _require_private_directory(details: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != PRIVATE_DIRECTORY_MODE
    ):
        raise ValueError(f"{label} must be an owned mode-0700 directory")


def _require_private_file(details: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != PRIVATE_FILE_MODE
        or details.st_nlink != 1
    ):
        raise ValueError(f"{label} must be an owned mode-0600 regular file")


def _fixture_root(value: Path) -> int:
    """Return one verified, held descriptor for the fixed private root.

    The caller must use this descriptor directly for every subsequent child
    operation.  Returning the pathname after its identity check would create a
    second name-resolution window in which a same-UID process could replace
    the fixed root before ``create`` or ``open`` obtained its parent fd.
    """

    root = Path(os.path.abspath(value))
    if root != FIXTURE_ROOT:
        raise ValueError(f"{_FIXTURE_ROOT_LABEL} is not the fixed private mount")
    if os.environ.get("LIGHTTPD_NO_CRS_FIXTURE_NAMESPACE_ACTIVE") != "1":
        raise ValueError(f"{_FIXTURE_ROOT_LABEL} requires an active private namespace")
    _require_post_capability_drop()
    expected_identity = _identity(
        os.environ.get("LIGHTTPD_NO_CRS_FIXTURE_ROOT_IDENTITY", "")
    )
    descriptor = os.open(root, _directory_flags())
    try:
        details = os.fstat(descriptor)
        _require_private_directory(details, _FIXTURE_ROOT_LABEL)
        if (details.st_dev, details.st_ino) != expected_identity:
            raise ValueError(f"{_FIXTURE_ROOT_LABEL} identity changed")
        rows = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
        matched: list[tuple[list[str], list[str]]] = []
        for row in rows:
            before, separator, after = row.partition(" - ")
            fields = before.split()
            if separator and len(fields) >= 6 and fields[4] == str(PRIVATE_TMPFS_MOUNT):
                matched.append((fields, after.split()))
        if len(matched) != 1:
            raise ValueError(f"{_FIXTURE_ROOT_LABEL} has no unique private tmpfs mount")
        fields, after = matched[0]
        if (
            not after
            or after[0] != "tmpfs"
            or not {"nosuid", "nodev", "noexec"}.issubset(set(fields[5].split(",")))
            or any(field.startswith(("shared:", "master:")) for field in fields[6:])
        ):
            raise ValueError(f"{_FIXTURE_ROOT_LABEL} mount is unsafe")
        # The descriptor, rather than ``root``, is the capability used by
        # create/open below.  Keep it open across the entire fixture lifetime.
        return descriptor
    except OSError as error:
        os.close(descriptor)
        raise ValueError(f"{_FIXTURE_ROOT_LABEL} cannot inspect mountinfo") from error
    except BaseException:
        os.close(descriptor)
        raise


class NamespaceFixtureDirectory:
    """One direct fixture child held by root and child directory descriptors."""

    def __init__(self, *, parent: int, directory: int, name: str, identity: tuple[int, int]) -> None:
        self._parent = parent
        self._directory = directory
        self._name = name
        self._identity = identity
        self._closed = False
        self._assert_identity()

    @property
    def identity(self) -> str:
        return f"{self._identity[0]}:{self._identity[1]}"

    @property
    def name(self) -> str:
        return self._name

    def _assert_open(self) -> None:
        if self._closed:
            raise ValueError("namespace fixture directory handle is closed")

    def _assert_identity(self) -> None:
        self._assert_open()
        details = os.fstat(self._directory)
        if (details.st_dev, details.st_ino) != self._identity:
            raise ValueError("namespace fixture descriptor identity changed")
        _require_private_directory(details, "namespace fixture directory")

    @classmethod
    def create(cls, root: Path, *, prefix: str, rejected_names: tuple[str, ...]) -> "NamespaceFixtureDirectory":
        prefix = _leaf(prefix, "namespace fixture prefix")
        if not prefix.startswith(".") or not prefix.endswith("-"):
            raise ValueError("namespace fixture prefix must be an opaque dotted stem")
        parent = _fixture_root(root)
        directory = -1
        try:
            _require_private_directory(os.fstat(parent), _FIXTURE_ROOT_LABEL)
            for rejected in rejected_names:
                rejected = _leaf(rejected, "rejected legacy namespace fixture name")
                try:
                    os.stat(rejected, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise ValueError(f"legacy namespace fixture child already exists: {rejected}")
            for _ in range(100):
                name = f"{prefix}{secrets.token_hex(16)}"
                try:
                    os.mkdir(name, PRIVATE_DIRECTORY_MODE, dir_fd=parent)
                except FileExistsError:
                    continue
                directory = os.open(name, _directory_flags(), dir_fd=parent)
                details = os.fstat(directory)
                _require_private_directory(details, "new namespace fixture directory")
                os.fchmod(directory, PRIVATE_DIRECTORY_MODE)
                result = cls(
                    parent=parent,
                    directory=directory,
                    name=name,
                    identity=(details.st_dev, details.st_ino),
                )
                parent = -1
                directory = -1
                return result
            raise ValueError("could not create a collision-free namespace fixture directory")
        finally:
            # Setup failures deliberately leave only namespace-private data.
            # Namespace teardown, not pathname rmdir, releases the directory.
            if directory >= 0:
                os.close(directory)
            if parent >= 0:
                os.close(parent)

    @classmethod
    def open(cls, root: Path, *, name: str, identity: str) -> "NamespaceFixtureDirectory":
        name = _leaf(name, "namespace fixture directory name")
        expected = _identity(identity)
        parent = _fixture_root(root)
        directory = -1
        try:
            _require_private_directory(os.fstat(parent), _FIXTURE_ROOT_LABEL)
            directory = os.open(name, _directory_flags(), dir_fd=parent)
            details = os.fstat(directory)
            if (details.st_dev, details.st_ino) != expected:
                raise ValueError("namespace fixture directory identity changed")
            _require_private_directory(details, "namespace fixture directory")
            result = cls(parent=parent, directory=directory, name=name, identity=expected)
            parent = -1
            directory = -1
            return result
        finally:
            if directory >= 0:
                os.close(directory)
            if parent >= 0:
                os.close(parent)

    def create_empty_file(self, name: str, label: str) -> int:
        name = _leaf(name, label)
        self._assert_identity()
        descriptor = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | _no_follow_flag(),
            PRIVATE_FILE_MODE,
            dir_fd=self._directory,
        )
        try:
            os.fchmod(descriptor, PRIVATE_FILE_MODE)
            _require_private_file(os.fstat(descriptor), label)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def require_absent(self, name: str, label: str) -> None:
        """Reject an existing direct leaf through the held fixture descriptor.

        This reserves no pathname and deliberately performs no cleanup.  The
        subsequent producer must still use ``O_EXCL|O_NOFOLLOW`` so a
        same-namespace insertion between this check and the write fails
        closed rather than replacing attacker-controlled data.
        """

        name = _leaf(name, label)
        self._assert_identity()
        try:
            os.stat(name, dir_fd=self._directory, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise ValueError(f"{label} must be fresh")

    def write_bytes_fresh(self, name: str, value: bytes, label: str) -> None:
        """Write one new fixture artifact without a later cleanup unlink.

        Each normal caller writes a given leaf exactly once.  Creating that
        final name with ``O_EXCL|O_NOFOLLOW`` avoids a temporary-name cleanup
        path altogether.  If writing fails, the incomplete namespace-private
        artifact is intentionally retained for whole-namespace teardown.
        """

        name = _leaf(name, label)
        if not isinstance(value, bytes):
            raise ValueError(f"{label} must be bytes")
        self._assert_identity()
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _no_follow_flag(),
            PRIVATE_FILE_MODE,
            dir_fd=self._directory,
        )
        try:
            os.fchmod(descriptor, PRIVATE_FILE_MODE)
            _require_private_file(os.fstat(descriptor), label)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
            self._assert_identity()
            verify = os.open(name, os.O_RDONLY | _no_follow_flag(), dir_fd=self._directory)
            try:
                _require_private_file(os.fstat(verify), label)
            finally:
                os.close(verify)
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def write_text_fresh(self, name: str, value: str, label: str) -> None:
        """Publish one immutable text leaf without a temporary-path cleanup."""

        if not isinstance(value, str):
            raise ValueError(f"{label} must be text")
        self.write_bytes_fresh(name, value.encode("utf-8"), label)

    def read_bytes(self, name: str, label: str, *, maximum_bytes: int) -> bytes:
        name = _leaf(name, label)
        if not isinstance(maximum_bytes, int) or maximum_bytes < 0:
            raise ValueError(f"{label} maximum size is invalid")
        self._assert_identity()
        descriptor = os.open(name, os.O_RDONLY | _no_follow_flag(), dir_fd=self._directory)
        try:
            details = os.fstat(descriptor)
            _require_private_file(details, label)
            if details.st_size > maximum_bytes:
                raise ValueError(f"{label} exceeds its bounded size")
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
                raise ValueError(f"{label} exceeds its bounded size")
            self._assert_identity()
            return value
        finally:
            os.close(descriptor)

    def read_text(self, name: str, label: str, *, maximum_bytes: int) -> str:
        try:
            return self.read_bytes(name, label, maximum_bytes=maximum_bytes).decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(f"{label} is not UTF-8 text") from error

    def verify_allowed_leaves(self, names: tuple[str, ...]) -> None:
        """Verify the exact leaf inventory; namespace teardown releases it.

        No artifact is unlinked here.  Even a descriptor-relative unlink would
        resolve the leaf name again and could act on a same-UID replacement.
        The private mount is discarded as one kernel-owned lifecycle unit.
        """

        allowed = {_leaf(name, "namespace fixture cleanup artifact") for name in names}
        if len(allowed) != len(names):
            raise ValueError("namespace fixture cleanup artifacts are not unique")
        self._assert_identity()
        fresh = os.open(".", _directory_flags(), dir_fd=self._directory)
        try:
            entries = set(os.listdir(fresh))
        finally:
            os.close(fresh)
        unexpected = entries - allowed
        if unexpected:
            raise ValueError(f"namespace fixture cleanup refuses unexpected entries: {sorted(unexpected)}")
        for name in sorted(entries):
            self._assert_identity()
            descriptor = os.open(name, os.O_RDONLY | _no_follow_flag(), dir_fd=self._directory)
            try:
                _require_private_file(os.fstat(descriptor), f"namespace fixture artifact {name}")
            finally:
                os.close(descriptor)
        self._assert_identity()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            os.close(self._directory)
        finally:
            os.close(self._parent)

    def __enter__(self) -> "NamespaceFixtureDirectory":
        self._assert_open()
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def create_namespace_fixture_directory(
    root: Path, *, prefix: str, rejected_names: tuple[str, ...]
) -> NamespaceFixtureDirectory:
    return NamespaceFixtureDirectory.create(root, prefix=prefix, rejected_names=rejected_names)


def open_namespace_fixture_directory(
    root: Path, *, name: str, identity: str
) -> NamespaceFixtureDirectory:
    return NamespaceFixtureDirectory.open(root, name=name, identity=identity)
