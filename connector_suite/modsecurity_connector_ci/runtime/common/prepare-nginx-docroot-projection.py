#!/usr/bin/env python3
"""Create a narrow worker-readable projection of an NGINX case docroot.

Framework case materialization remains in the private connector build root.
Only the two static files needed by NGINX's document root are copied into a
fresh, worker-traversable directory. This helper deliberately does not clean
up the projection: its trusted lifecycle/operator caller retains task-owned
cleanup responsibility for the explicitly supplied parent and fresh child.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import sys


PROJECTED_FILENAMES = ("index.html", "__modsec_smoke_ready")
PUBLIC_TRAVERSE_MODE = stat.S_IXOTH
PROJECTION_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def fail(message: str) -> None:
    raise ValueError(message)


def normalized_absolute(value: str | Path, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        fail(f"{label} must be absolute: {path}")
    # This is lexical normalization only.  It must not resolve symlinks before
    # the component-by-component no-follow checks below.
    normalized = Path(os.path.abspath(os.path.normpath(os.fspath(path))))
    if normalized == Path("/") and label != "projection parent base":
        fail(f"{label} must not be the filesystem root")
    return normalized


def require_no_symlink_directory(path: Path, label: str) -> None:
    """Reject a missing, special, or symlink component without following it."""

    current = Path("/")
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            fail(f"{label} component is missing: {current}")
        if stat.S_ISLNK(metadata.st_mode):
            fail(f"{label} contains a symbolic link: {current}")
        if not stat.S_ISDIR(metadata.st_mode):
            fail(f"{label} component is not a directory: {current}")


def is_descendant(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def overlaps(left: Path, right: Path) -> bool:
    return is_descendant(left, right) or is_descendant(right, left)


def ensure_private_parent(path: Path, label: str) -> None:
    require_no_symlink_directory(path, label)
    metadata = path.lstat()
    if metadata.st_uid != os.geteuid():
        fail(f"{label} is not owned by the effective uid: {path}")
    if metadata.st_mode & 0o022:
        fail(f"{label} is group- or other-writable: {path}")
    if metadata.st_mode & 0o044:
        fail(f"{label} is group- or other-readable: {path}")
    if not metadata.st_mode & PUBLIC_TRAVERSE_MODE:
        fail(f"{label} is not worker-traversable: {path}")
    for ancestor in (Path("/").joinpath(*path.parts[:index]) for index in range(2, len(path.parts) + 1)):
        ancestor_metadata = ancestor.lstat()
        if not ancestor_metadata.st_mode & PUBLIC_TRAVERSE_MODE:
            fail(f"projection parent has a non-traversable ancestor: {ancestor}")


def validate_source_docroot(source: Path, private_root: Path) -> None:
    require_no_symlink_directory(private_root, "private build root")
    require_no_symlink_directory(source, "source docroot")
    if not is_descendant(source, private_root):
        fail(f"source docroot must remain inside private build root: {source}")


def open_regular_source(path: Path) -> int:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        fail(f"cannot open projected source file {path}: {exc}")
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        fail(f"projected source is not a regular file: {path}")
    return descriptor


def validate_worker_gid(worker_gid: int) -> int:
    if worker_gid < 0:
        fail(f"worker gid must be non-negative: {worker_gid}")
    return worker_gid


def copy_regular_file(source: Path, destination: Path, worker_gid: int) -> None:
    source_fd = open_regular_source(source)
    try:
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
    except OSError as exc:
        os.close(source_fd)
        fail(f"cannot create projected file {destination}: {exc}")
    try:
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            written = 0
            while written < len(chunk):
                written += os.write(destination_fd, chunk[written:])
        os.fchown(destination_fd, os.geteuid(), worker_gid)
        os.fchmod(destination_fd, 0o640)
    finally:
        os.close(source_fd)
        os.close(destination_fd)


def finalize_projection_directory(
    projection: Path, expected: os.stat_result, worker_gid: int
) -> None:
    """Bind group ownership and traversal mode to the exact fresh directory."""

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        descriptor = os.open(projection, flags)
    except OSError as exc:
        fail(f"cannot open fresh projection directory {projection}: {exc}")
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode):
            fail(f"fresh projection is not a directory: {projection}")
        if opened.st_dev != expected.st_dev or opened.st_ino != expected.st_ino:
            fail(f"fresh projection changed while being opened: {projection}")
        os.fchown(descriptor, os.geteuid(), worker_gid)
        os.fchmod(descriptor, 0o710)
    finally:
        os.close(descriptor)


def prepare_projection(
    *,
    source_docroot: Path,
    private_root: Path,
    projection_parent: Path | None,
    projection_root: Path | None,
    worker_gid: int,
    avoid_roots: list[Path],
) -> Path:
    worker_gid = validate_worker_gid(worker_gid)
    validate_source_docroot(source_docroot, private_root)
    if projection_parent is None or projection_root is None:
        fail("projection requires an explicit safe parent and fresh root")
    parent = projection_parent
    if projection_root.parent != parent:
        fail("projection root must be a direct child of projection parent")
    if not PROJECTION_NAME_RE.fullmatch(projection_root.name):
        fail(f"projection root name is unsafe: {projection_root.name}")
    ensure_private_parent(parent, "projection parent")

    checked_avoid_roots = [normalized_absolute(root, "avoid root") for root in avoid_roots]
    for root in checked_avoid_roots:
        if overlaps(parent, root):
            fail(f"projection parent overlaps a private runtime root: {parent} <-> {root}")

    projection = projection_root
    try:
        os.mkdir(projection, 0o700)
    except FileExistsError:
        fail(f"projection root already exists: {projection}")
    except OSError as exc:
        fail(f"cannot create specified projection root {projection}: {exc}")
    projection_metadata = projection.lstat()
    if not stat.S_ISDIR(projection_metadata.st_mode) or stat.S_ISLNK(projection_metadata.st_mode):
        fail(f"fresh projection is not a directory: {projection}")

    for filename in PROJECTED_FILENAMES:
        copy_regular_file(source_docroot / filename, projection / filename, worker_gid)

    # The parent and this exact caller-supplied child are non-enumerable. Only
    # the verified NGINX worker group may traverse the child and read the two
    # fixed static files at known paths. Do not chmod/chown a caller-owned root.
    finalize_projection_directory(projection, projection_metadata, worker_gid)
    return projection


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-docroot", type=Path, required=True)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--worker-gid", type=int, required=True)
    parser.add_argument("--projection-parent", type=Path, required=True)
    parser.add_argument(
        "--projection-root",
        type=Path,
        required=True,
        help="exact fresh child supplied by the trusted lifecycle caller",
    )
    parser.add_argument("--avoid-root", type=Path, action="append", default=[])
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        source_docroot = normalized_absolute(args.source_docroot, "source docroot")
        private_root = normalized_absolute(args.private_root, "private build root")
        projection_parent = normalized_absolute(args.projection_parent, "projection parent")
        projection_root = normalized_absolute(args.projection_root, "projection root")
        projection = prepare_projection(
            source_docroot=source_docroot,
            private_root=private_root,
            projection_parent=projection_parent,
            projection_root=projection_root,
            worker_gid=args.worker_gid,
            avoid_roots=args.avoid_root,
        )
    except (OSError, ValueError) as exc:
        print(f"FAIL: NGINX docroot projection: {exc}", file=sys.stderr)
        return 1
    print(projection)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
