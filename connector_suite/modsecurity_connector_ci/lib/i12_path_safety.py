"""Admit I12 evidence data and publish artifacts inside explicit storage roots."""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import secrets
import stat

from modsecurity_connector_ci.lib.runtime_path_utils import canonical_project_roots, is_safe_runtime_root


_SEALED_READ_ROOTS = tuple(map(Path, (
    "/task", "/mnt/fixtures", "/mnt/artifacts", "/mnt/framework", "/mnt/src",
)))
_SEALED_WRITE_ROOT = Path("/task")
_ROOT_VARIABLES = ("CODEX_TEMP_ROOT", "VERIFIED_RUN_ROOT", "I12_TEST_ROOT", "CODEX_PROJECT_STATE")
MAXIMUM_BYTES = 64 * 1024 * 1024


def _source_roots() -> tuple[Path, ...]:
    try:
        return canonical_project_roots()
    except RuntimeError:
        # Standalone sealed fixtures have no checkout and authorize no source tree.
        return ()


def leaf_name(value: str) -> str:
    """Validate one bounded receipt/matrix name before joining it to a root."""
    if (not isinstance(value, str) or not value or len(value) > 128
            or value in {".", ".."} or any(c in value for c in "/\\\x00")
            or any(ord(c) < 32 for c in value)):
        raise ValueError("evidence name must be one bounded filename")
    return value


def _canonical(value: Path | str, *, exists: bool) -> Path:
    text = os.fspath(value)
    if not text or "\x00" in text:
        raise ValueError("invalid evidence path")
    supplied = Path(text)
    if ".." in supplied.parts:
        raise ValueError("evidence paths cannot traverse parents")
    absolute = supplied.absolute()
    resolved = absolute.resolve(strict=exists)
    if absolute != resolved:
        raise ValueError("evidence paths cannot traverse symbolic links")
    return resolved


def _trusted_directory(path: Path) -> None:
    details = path.stat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid not in {0, os.geteuid()}:
        raise ValueError("evidence directory has an untrusted owner or type")
    if details.st_mode & 0o022:
        sticky = details.st_uid == 0 and details.st_mode & stat.S_ISVTX
        if not sticky:
            raise ValueError("evidence directory permits untrusted replacement")


def _configured_roots() -> tuple[Path, ...]:
    roots = []
    for variable in _ROOT_VARIABLES:
        value = os.environ.get(variable)
        if not value:
            continue
        root = _canonical(value, exists=True)
        try:
            safe = is_safe_runtime_root(root)
        except RuntimeError:
            safe = root.is_relative_to(_SEALED_WRITE_ROOT) and root != _SEALED_WRITE_ROOT
        if not Path(value).is_absolute() or not safe:
            raise ValueError(f"{variable} is not a narrow runtime root")
        for directory in (root, *root.parents):
            _trusted_directory(directory)
        roots.append(root)
    if _SEALED_WRITE_ROOT.is_dir():
        root = _canonical(_SEALED_WRITE_ROOT, exists=True)
        _trusted_directory(root)
        roots.append(root)
    return tuple(roots)


def _admitted(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path != root and path.is_relative_to(root) for root in roots)


def input_path(value: Path | str) -> Path:
    """Authorize a regular data file below source, sealed input, or runtime roots."""
    path = _canonical(value, exists=True)
    if any(part in {".git", ".codex", ".aws", ".ssh", ".gnupg"} for part in path.parts):
        raise ValueError("private configuration cannot be consumed as evidence")
    roots = (*_source_roots(), *_configured_roots(), *_SEALED_READ_ROOTS)
    if not _admitted(path, roots) or not path.is_file():
        raise ValueError("input is outside approved evidence/source roots")
    return path


def input_directory(value: Path | str) -> Path:
    path = _canonical(value, exists=True)
    if any(part in {".git", ".codex", ".aws", ".ssh", ".gnupg"} for part in path.parts):
        raise ValueError("private configuration cannot be consumed as evidence")
    roots = (*_source_roots(), *_configured_roots(), *_SEALED_READ_ROOTS)
    if not any(path.is_relative_to(root) for root in roots) or not path.is_dir():
        raise ValueError("input directory is outside approved evidence/source roots")
    return path


def _checkout_marker(directory: Path) -> bool:
    marker = directory / ".git"
    try:
        details = marker.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISDIR(details.st_mode):
        # Worktree files and redirected/ambiguous markers fail closed.
        return True
    try:
        head = (marker / "HEAD").lstat()
    except FileNotFoundError:
        # Managed workspaces can expose an empty read-only platform marker.
        return False
    return stat.S_ISREG(head.st_mode) or stat.S_ISLNK(head.st_mode)


def output_path(value: Path | str) -> Path:
    """Authorize a destination independently of its caller-selected parent."""
    path = _canonical(value, exists=False)
    if any(path.is_relative_to(root) for root in _source_roots()):
        raise ValueError("source checkouts are read-only evidence inputs")
    if any(_checkout_marker(directory) for directory in path.parents):
        raise ValueError("Git checkouts cannot be evidence output roots")
    if not _admitted(path, _configured_roots()):
        raise ValueError("output is outside approved runtime roots")
    leaf_name(path.name)
    for directory in path.parents:
        if directory.exists():
            _trusted_directory(directory)
    return path


@contextmanager
def _parent(path: Path):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for component in path.parent.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            details = os.fstat(descriptor)
            if details.st_uid not in {0, os.geteuid()}:
                raise ValueError("artifact parent owner changed")
            if details.st_mode & 0o022 and not (
                    details.st_uid == 0 and details.st_mode & stat.S_ISVTX):
                raise ValueError("artifact parent is writable by another user")
        yield descriptor
    finally:
        os.close(descriptor)


def _read_admitted(path: Path, maximum_bytes: int, *, require_owned_input: bool = False) -> bytes:
    with _parent(path) as parent:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=parent)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_bytes:
                raise ValueError("evidence input is not a bounded regular file")
            if require_owned_input and (
                    before.st_uid not in {0, os.geteuid()} or before.st_mode & 0o022):
                raise ValueError("evidence input requires a trusted owner and safe write permissions")
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                content = stream.read(maximum_bytes + 1)
                after = os.fstat(stream.fileno())
            if (len(content) > maximum_bytes or
                    (before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                    (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise ValueError("evidence input changed during bounded read")
            return content
        finally:
            if descriptor >= 0:
                os.close(descriptor)


def read_bytes(value: Path | str, *, maximum_bytes: int = MAXIMUM_BYTES) -> bytes:
    """Read bounded regular data through a descriptor-pinned, no-follow parent."""
    return _read_admitted(input_path(value), maximum_bytes)


def read_image_bytes(value: Path | str) -> bytes:
    """Hash evidence data or an installed public host/library image, never host configuration."""
    path = _canonical(value, exists=True)
    image_roots = tuple(map(Path, ("/usr/bin", "/usr/sbin", "/usr/lib", "/usr/local/lib")))
    if _admitted(path, image_roots):
        return _read_admitted(path, MAXIMUM_BYTES)
    return read_bytes(path)


def read_text(value: Path | str, *, maximum_bytes: int = MAXIMUM_BYTES) -> str:
    return read_bytes(value, maximum_bytes=maximum_bytes).decode("utf-8")


def create_bytes(value: Path | str, content: bytes) -> Path:
    """Create one private artifact once; never follow or overwrite an existing leaf."""
    path = output_path(value)
    with _parent(path) as parent:
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    return path


def create_text(value: Path | str, content: str) -> Path:
    return create_bytes(value, content.encode("utf-8"))


@contextmanager
def new_text(value: Path | str):
    """Expose a UTF-8 stream while retaining the admitted parent descriptor."""
    path = output_path(value)
    with _parent(path) as parent:
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            yield stream
            stream.flush()
            os.fsync(stream.fileno())


def replace_text(value: Path | str, content: str) -> Path:
    """Explicitly replace an admitted owned file atomically, preserving leaf identity checks."""
    path = output_path(value)
    with _parent(path) as parent:
        original = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(original.st_mode) or original.st_uid != os.geteuid()
                or original.st_nlink != 1):
            raise ValueError("replacement requires an owned single-link regular file")
        temporary = ".i12-" + secrets.token_hex(16)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content.encode("utf-8"))
                stream.flush()
                os.fsync(stream.fileno())
            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
                raise ValueError("replacement target changed")
            os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
            temporary = ""
        finally:
            if temporary:
                os.unlink(temporary, dir_fd=parent)
    return path


def new_directory(value: Path | str) -> Path:
    path = output_path(value)
    with _parent(path) as parent:
        os.mkdir(path.name, 0o700, dir_fd=parent)
    return path


def ensure_directory(value: Path | str) -> Path:
    """Create admitted output descendants without following any directory links."""
    path = output_path(value)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(component, 0o700, dir_fd=descriptor)
                child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            details = os.fstat(descriptor)
            if details.st_uid not in {0, os.geteuid()} or (
                    details.st_mode & 0o022 and not (
                        details.st_uid == 0 and details.st_mode & stat.S_ISVTX)):
                raise ValueError("output directory permits untrusted replacement")
    finally:
        os.close(descriptor)
    return path
