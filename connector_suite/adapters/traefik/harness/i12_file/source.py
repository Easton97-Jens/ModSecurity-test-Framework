"""Physical regular-file streaming receipts, never native SDK file API evidence."""

import hashlib
import os
from pathlib import PurePosixPath
import stat
import time

MAX_FILE = 512 * 1024
MAX_READ = 64 * 1024
MAX_READS = 4096


class SourceFailure(ValueError):
    """A failed physical-source contract with its incomplete receipt preserved."""

    def __init__(self, message, receipt):
        super().__init__(message)
        self.receipt = receipt


def snapshot(value):
    return {"dev": value.st_dev, "inode": value.st_ino, "uid": value.st_uid,
            "gid": value.st_gid, "mode": stat.S_IMODE(value.st_mode),
            "regular_file": stat.S_ISREG(value.st_mode), "size": value.st_size,
            "mtime_ns": value.st_mtime_ns, "ctime_ns": value.st_ctime_ns,
            "nlink": value.st_nlink}


def same_snapshot(left, right):
    """Compare two independently sampled identities field by field."""
    return all(left.get(field) == right.get(field) for field in (
        "dev", "inode", "uid", "gid", "mode", "regular_file", "size",
        "mtime_ns", "ctime_ns", "nlink"))


def validate_manifest(spec):
    """Only one literal file component under the already admitted private root."""
    if not isinstance(spec, dict):
        raise ValueError("file manifest object required")
    name = spec.get("relative_path")
    if (not isinstance(name, str) or not name or "\x00" in name or
            PurePosixPath(name).parts != (name,) or name in (".", "..")):
        raise ValueError("one private-root relative filename required")
    size, chunk = spec.get("size"), spec.get("read_size")
    if type(size) is not int or not 0 <= size <= MAX_FILE:
        raise ValueError("bounded literal file size required")
    if type(chunk) is not int or not 1 <= chunk <= MAX_READ:
        raise ValueError("bounded physical read size required")
    if (size + chunk - 1) // chunk > MAX_READS:
        raise ValueError("bounded physical read receipt count required")
    digest = spec.get("sha256")
    if (not isinstance(digest, str) or len(digest) != 64 or
            any(c not in "0123456789abcdef" for c in digest)):
        raise ValueError("literal SHA256 required")
    return name, size, chunk, digest


def _validate_file(root_fd, file_fd, receipt):
    before = snapshot(os.fstat(file_fd))
    receipt["pre_stat"] = before
    if (not before["regular_file"] or before["uid"] != os.getuid() or
            before["mode"] != 0o600 or before["nlink"] != 1 or before["size"] != receipt["expected_size"]):
        raise ValueError("owned mode0600 single-link regular file of exact size required")
    named = snapshot(os.stat(receipt["relative_path"], dir_fd=root_fd, follow_symlinks=False))
    if not same_snapshot(named, before):
        raise ValueError("source identity changed at open")


def _read_chunk(file_fd, requested, receipt):
    entry = {"offset": os.lseek(file_fd, 0, os.SEEK_CUR), "requested": requested,
             "started_ns": time.monotonic_ns()}
    receipt["reads"].append(entry)
    try:
        part = os.read(file_fd, requested)
    except OSError as error:
        entry.update(result=-1, errno=error.errno, completed_ns=time.monotonic_ns())
        raise
    entry.update(result=len(part), completed_ns=time.monotonic_ns(),
                 sha256=hashlib.sha256(part).hexdigest())
    return part, entry


def _read_contents(file_fd, root_fd, receipt, digest, consume):
    before = receipt["pre_stat"]
    while receipt["bytes"] < receipt["expected_size"]:
        requested = min(receipt["requested_read_size"], receipt["expected_size"] - receipt["bytes"])
        part, entry = _read_chunk(file_fd, requested, receipt)
        digest.update(part)
        offset_matches = entry["offset"] == receipt["bytes"]
        receipt["bytes"] += len(part)
        if not offset_matches or len(part) != requested:
            raise ValueError("physical source short read or unexpected offset")
        if snapshot(os.fstat(file_fd)) != before:
            raise ValueError("source mutated during physical read")
        consume(part, dict(entry))
        entry["consumer_returned_ns"] = time.monotonic_ns()
        named = os.stat(receipt["relative_path"], dir_fd=root_fd, follow_symlinks=False)
        if snapshot(os.fstat(file_fd)) != before or snapshot(named) != before:
            raise ValueError("source mutated or replaced during consumer callback")
    receipt["eof_read_started_ns"] = time.monotonic_ns()
    extra = os.read(file_fd, 1)
    receipt.update(eof_read_result=len(extra), eof_read_completed_ns=time.monotonic_ns(),
                   post_stat=snapshot(os.fstat(file_fd)))
    if extra or receipt["post_stat"] != before:
        raise ValueError("source grew or mutated before physical EOF")
    if digest.hexdigest() != receipt["expected_sha256"]:
        raise ValueError("physical source hash mismatch")


def _close_source(file_fd, root_fd, receipt):
    failure = None
    if file_fd is not None and "post_stat" not in receipt:
        try:
            receipt["post_stat"] = snapshot(os.fstat(file_fd))
        except OSError as error:
            receipt["post_stat_error"] = {"errno": error.errno}
            failure = error
    for fd, key in ((file_fd, "close"), (root_fd, "root_close")):
        if fd is None:
            continue
        close = {"started_ns": time.monotonic_ns()}
        try:
            os.close(fd)
            close["result"] = 0
        except OSError as error:
            close.update(result=-1, errno=error.errno)
            failure = failure or error
        close["completed_ns"] = time.monotonic_ns()
        receipt[key] = close
    return failure


def stream_file(private_root, spec, consume):
    """Call consume once per physical read; retain at most read_size bytes.

    consume must synchronously use/copy the chunk. Its successful return proves
    only that callback's completion, never remote delivery or engine inspection.
    SourceFailure.receipt is always available for fail-closed negative evidence.
    """
    receipt = {"schema": "traefik-physical-file-source-v1", "pid": os.getpid(),
               "uid": os.getuid(), "started_ns": time.monotonic_ns(), "reads": [],
               "native_file_api": False, "native_eos": None, "complete": False,
               "close": None, "root_close": None, "bytes": 0}
    root_fd = file_fd = None
    digest = hashlib.sha256()
    failure = None
    try:
        name, expected_size, read_size, expected_hash = validate_manifest(spec)
        receipt.update(relative_path=name, expected_size=expected_size,
                       expected_sha256=expected_hash, requested_read_size=read_size)
        root_fd = os.open(private_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        root_stat = os.fstat(root_fd)
        receipt["root_stat"] = snapshot(root_stat)
        if root_stat.st_uid != os.getuid() or stat.S_IMODE(root_stat.st_mode) != 0o700:
            raise ValueError("private root must be owned by reader and mode0700")
        # O_NONBLOCK also keeps a malicious FIFO replacement from blocking open.
        receipt["open_started_ns"] = time.monotonic_ns()
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd)
        receipt["open_result_fd"] = file_fd
        receipt["opened_ns"] = time.monotonic_ns()
        _validate_file(root_fd, file_fd, receipt)
        _read_contents(file_fd, root_fd, receipt, digest, consume)
    except Exception as error:
        failure = error
        receipt["error"] = {"type": type(error).__name__, "message": str(error)[:256]}
        if isinstance(error, OSError):
            receipt["error"]["errno"] = error.errno
    finally:
        close_failure = _close_source(file_fd, root_fd, receipt)
        failure = failure or close_failure
        receipt.update(sha256=digest.hexdigest(), completed_ns=time.monotonic_ns())
        receipt["complete"] = failure is None
    if failure is not None:
        raise SourceFailure(str(failure), receipt) from failure
    return receipt
