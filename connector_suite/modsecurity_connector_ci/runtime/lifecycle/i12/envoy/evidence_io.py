"""Read bounded evidence through approved, pinned directory descriptors."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import stat

REPOSITORY = connector_root()
ARCHIVES = os.environ.get('CODEX_CLEANUP_ARCHIVE_ROOT')
if ARCHIVES and (not Path(ARCHIVES).is_absolute() or '..' in Path(ARCHIVES).parts):
    raise ValueError('CODEX_CLEANUP_ARCHIVE_ROOT requires an absolute storage root')
MAX_BYTES = 128 * 1024 * 1024
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def approved_path(value, roots):
    """Reject outside paths before performing any filesystem operation."""
    text = os.fspath(value)
    if not isinstance(text, str) or not text or '\\' in text or '\x00' in text:
        raise ValueError('invalid evidence path')
    path = Path(text)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute evidence path without traversal required')
    if any(part in ('.git', '.aws', '.codex', '.agents') for part in path.parts):
        raise ValueError('private configuration is not evidence')
    for root in roots:
        root = Path(root)
        if root.is_absolute() and path != root and path.is_relative_to(root):
            return path, root
    raise ValueError('evidence path outside approved storage/source roots')


def trusted_metadata(metadata):
    if metadata.st_uid not in (0, os.geteuid()) or metadata.st_mode & 0o022:
        raise ValueError('evidence must be owned and not group/other writable')


def configured_storage(required=True):
    """Use the trusted project configuration export; never invent a temp root."""
    value = os.environ.get('CODEX_PROJECT_STATE')
    if not value:
        if required:
            raise ValueError('CODEX_PROJECT_STATE must name the configured evidence root')
        return None
    path = Path(value)
    if not path.is_absolute() or len(path.parts) < 3 or '..' in path.parts:
        raise ValueError('configured evidence root requires a physical absolute directory')
    directory = os.open('/', DIRECTORY_FLAGS)
    try:
        for component in path.parts[1:]:
            child = os.open(component, DIRECTORY_FLAGS, dir_fd=directory)
            os.close(directory)
            directory = child
        trusted_metadata(os.fstat(directory))
    finally:
        os.close(directory)
    return path


STORAGE = configured_storage(required=False)
DEFAULT_ROOTS = (REPOSITORY, test_root()) + ((Path(ARCHIVES),) if ARCHIVES else ()) + ((STORAGE,) if STORAGE is not None else ())


@contextmanager
def open_evidence(value, roots=DEFAULT_ROOTS, max_bytes=MAX_BYTES):
    """Walk with openat/O_NOFOLLOW; never resolve or open an unchecked path."""
    path, root = approved_path(value, roots)
    directory = os.open('/', DIRECTORY_FLAGS)
    stream = None
    try:
        for index, component in enumerate(path.parts[1:-1], 1):
            child = os.open(component, DIRECTORY_FLAGS, dir_fd=directory)
            os.close(directory)
            directory = child
            if index >= len(root.parts) - 1:
                trusted_metadata(os.fstat(directory))
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                             | os.O_NONBLOCK, dir_fd=directory)
        stream = os.fdopen(descriptor, 'rb')
        before = os.fstat(stream.fileno())
        trusted_metadata(before)
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            raise ValueError('evidence requires a bounded physical regular file')
        yield stream, before
        after = os.fstat(stream.fileno())
        if identity(before) != identity(after):
            raise ValueError('evidence changed while reading')
    finally:
        if stream is not None:
            stream.close()
        os.close(directory)


def identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def read_bytes(path, roots=DEFAULT_ROOTS, max_bytes=MAX_BYTES):
    with open_evidence(path, roots, max_bytes) as (stream, _):
        data = stream.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError('evidence exceeds read bound')
        return data


def read_json(path, roots=DEFAULT_ROOTS):
    return json.loads(read_bytes(path, roots))


def digest_stream(stream, max_bytes=MAX_BYTES):
    digest = hashlib.sha256()
    remaining = max_bytes
    while block := stream.read(min(1024 * 1024, remaining + 1)):
        remaining -= len(block)
        if remaining < 0:
            raise ValueError('evidence exceeds hash bound')
        digest.update(block)
    return digest.hexdigest()


def reference(path, roots=DEFAULT_ROOTS):
    with open_evidence(path, roots) as (stream, metadata):
        digest = digest_stream(stream)
    return {'path': str(path), 'sha256': digest, 'bytes': metadata.st_size}
