#!/usr/bin/env python3
"""Prepare, verify, and clean a read-only source boundary for CI validation.

The trusted root-side entry point accepts a fresh root-owned guard directory
below ``RUNNER_TEMP``. It validates the source topology without following
links, records the original complete source/Git inventory inside the root-only
guard, and creates the sole validator-owned ``external`` output root. The
actual source tree is never ownership- or mode-mutated: the namespace runner
provides its read-only mount boundary. After candidate execution this helper
compares the inventory and validates every candidate-created output object
fail-closed. Its cleanup mode removes only a fully verified private guard.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import sys
from typing import Iterator, Sequence


PRIVILEGED_GROUPS = frozenset({"admin", "sudo", "wheel"})
EXTERNAL_DIRNAME = "external"
INVENTORY_FILENAME = "source-inventory.json"
GITFILE_MAX_BYTES = 4096
SOURCE_ROOT_LABEL = "source root"
WRITE_ROOT_PREFIX = "modsecurity-readonly-validation."


@dataclass(frozen=True)
class ValidatorIdentity:
    """The exact unprivileged identity allowed to own candidate output."""

    user: str
    group: str
    uid: int
    gid: int


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="prepare, verify, or clean a private read-only validation guard"
    )
    parser.add_argument("--source-root")
    parser.add_argument("--framework-root")
    parser.add_argument("--write-root", required=True)
    parser.add_argument("--runner-temp", required=True)
    parser.add_argument("--validator-user")
    parser.add_argument("--validator-group")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="compare the post-run source inventory and validate external outputs",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="remove only the validated private write-root guard",
    )
    arguments = parser.parse_args(argv)
    if arguments.verify and arguments.cleanup:
        parser.error("--verify and --cleanup are mutually exclusive")
    required = ("source_root", "framework_root")
    if not arguments.cleanup:
        required += ("validator_user", "validator_group")
    for attribute in required:
        if not getattr(arguments, attribute):
            parser.error(f"--{attribute.replace('_', '-')} is required for this mode")
    return arguments


def _lexical_absolute_path(value: str, label: str) -> Path:
    """Accept one canonical-looking absolute path without resolving links."""
    if not value or not os.path.isabs(value):
        raise ValueError(f"{label} must be an absolute path")
    normalized = os.path.normpath(value)
    if normalized != value or ".." in Path(value).parts:
        raise ValueError(f"{label} must not contain traversal or redundant components: {value}")
    return Path(value)


def _existing_directory_without_symlinks(value: str, label: str) -> Path:
    """Validate every existing component without following a symbolic link."""
    path = _lexical_absolute_path(value, label)
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError as error:
            raise ValueError(f"{label} must be an existing directory: {path}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"{label} must not contain symbolic links: {path}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"{label} must be a directory: {path}")
    return path


def _is_below(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
    except ValueError:
        return False
    return candidate != parent


def _is_within(candidate: Path, parent: Path) -> bool:
    return candidate == parent or _is_below(candidate, parent)


def _same_inode(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _decode_mountinfo_path(value: str) -> str:
    """Decode a mountinfo path while rejecting malformed escapes."""
    decoded: list[str] = []
    index = 0
    while index < len(value):
        character = value[index]
        if character != "\\":
            decoded.append(character)
            index += 1
            continue
        escaped = value[index + 1 : index + 4]
        if len(escaped) != 3 or any(digit not in "01234567" for digit in escaped):
            raise ValueError("mountinfo contains an invalid escaped mount path")
        decoded.append(chr(int(escaped, 8)))
        index += 4
    return "".join(decoded)


def _mountinfo_mountpoints() -> Iterator[Path]:
    """Yield canonical-looking mountpoints from the current mount namespace."""
    try:
        rows = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ValueError("cannot read mountinfo for source topology validation") from error
    for row in rows:
        before_separator, separator, _after_separator = row.partition(" - ")
        fields = before_separator.split()
        if not separator or len(fields) < 5:
            raise ValueError("mountinfo contains an invalid mount record")
        mountpoint = Path(_decode_mountinfo_path(fields[4]))
        if not mountpoint.is_absolute() or os.path.normpath(os.fspath(mountpoint)) != os.fspath(
            mountpoint
        ):
            raise ValueError("mountinfo contains an invalid mountpoint")
        yield mountpoint


def _reject_mounts_within(root: Path, label: str, *, include_root: bool) -> None:
    """Fail closed when a host mount could invalidate a path boundary."""
    for mountpoint in _mountinfo_mountpoints():
        contained = _is_within(mountpoint, root) if include_root else _is_below(mountpoint, root)
        if contained:
            raise ValueError(f"{label} contains an unexpected active mount: {mountpoint}")


def _reject_nested_source_mounts(source: Path) -> None:
    """Reject non-recursive bind-mount bypasses before candidate execution."""
    _reject_mounts_within(source, SOURCE_ROOT_LABEL, include_root=False)


def _walk_tree(root: Path) -> Iterator[tuple[Path, str, os.stat_result]]:
    """Yield all tree entries in deterministic order without traversing links."""
    pending: list[tuple[Path, str]] = [(root, ".")]
    while pending:
        path, relative = pending.pop()
        metadata = os.lstat(path)
        yield path, relative, metadata
        if not stat.S_ISDIR(metadata.st_mode):
            continue
        with os.scandir(path) as entries:
            children = sorted(entries, key=lambda entry: entry.name, reverse=True)
        for entry in children:
            child_relative = entry.name if relative == "." else f"{relative}/{entry.name}"
            pending.append((Path(entry.path), child_relative))


def _read_small_regular_text(path: Path, expected: os.stat_result) -> str:
    """Read a bounded regular gitfile through a no-follow descriptor."""
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_inode(expected, opened):
            raise ValueError(f"git metadata changed while opening: {path}")
        data = os.read(descriptor, GITFILE_MAX_BYTES + 1)
        if len(data) > GITFILE_MAX_BYTES:
            raise ValueError(f"git metadata is unexpectedly large: {path}")
        if not _same_inode(opened, os.fstat(descriptor)):
            raise ValueError(f"git metadata changed while reading: {path}")
    finally:
        os.close(descriptor)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"git metadata is not UTF-8: {path}") from error


def _lexical_link_target(path: Path, target_text: str) -> Path:
    """Return a link target normalized without resolving any filesystem links."""
    return Path(
        os.path.normpath(
            target_text if os.path.isabs(target_text) else os.path.join(path.parent, target_text)
        )
    )


def _digest_regular_file(path: Path, expected: os.stat_result) -> str:
    """Hash one regular source file via a bounded, no-follow descriptor."""
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_inode(expected, opened):
            raise ValueError(f"source entry changed while opening: {path}")
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(descriptor)
        if not _same_inode(opened, after) or after.st_size != opened.st_size:
            raise ValueError(f"source entry changed while reading: {path}")
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _source_inventory(root: Path) -> list[dict[str, object]]:
    """Return the complete deterministic source/Git inventory without mutation."""
    entries: list[dict[str, object]] = []
    for path, relative, metadata in _walk_tree(root):
        mode = stat.S_IMODE(metadata.st_mode)
        record: dict[str, object] = {
            "path": relative,
            "size": metadata.st_size,
            "mode": mode,
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "nlink": metadata.st_nlink,
        }
        if stat.S_ISDIR(metadata.st_mode):
            record["type"] = "directory"
        elif stat.S_ISREG(metadata.st_mode):
            record["type"] = "regular"
            record["sha256"] = _digest_regular_file(path, metadata)
        elif stat.S_ISLNK(metadata.st_mode):
            record["type"] = "symlink"
            record["target"] = os.readlink(path)
        else:
            raise ValueError(f"source inventory rejects unsupported file type: {relative}")
        entries.append(record)
    return entries


def _inventory_payload(entries: list[dict[str, object]]) -> bytes:
    return (
        json.dumps({"version": 1, "entries": entries}, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _write_exact_regular_file(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
    finally:
        os.close(descriptor)


def _read_inventory(path: Path) -> tuple[list[dict[str, object]], str]:
    metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise ValueError("source inventory must be one root-owned mode-0600 regular file")
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_inode(metadata, opened):
            raise ValueError("source inventory changed while opening")
        blocks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            blocks.append(block)
        payload = b"".join(blocks)
        if not _same_inode(opened, os.fstat(descriptor)):
            raise ValueError("source inventory changed while reading")
    finally:
        os.close(descriptor)
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("source inventory is not valid JSON") from error
    if not isinstance(decoded, dict) or decoded.get("version") != 1 or not isinstance(
        decoded.get("entries"), list
    ):
        raise ValueError("source inventory has an unexpected schema")
    entries = decoded["entries"]
    if not all(isinstance(entry, dict) for entry in entries):
        raise ValueError("source inventory contains an invalid entry")
    return entries, hashlib.sha256(payload).hexdigest()


def resolve_validator_identity(user: str, group: str) -> ValidatorIdentity:
    """Require an existing dedicated identity with no privileged group."""
    try:
        account = pwd.getpwnam(user)
        group_entry = grp.getgrnam(group)
    except KeyError as error:
        raise ValueError("validator user and group must already exist") from error
    if account.pw_uid == 0 or group_entry.gr_gid == 0:
        raise ValueError("validator user and group must be unprivileged")
    groups = {entry.gr_name for entry in grp.getgrall() if user in entry.gr_mem}
    try:
        groups.add(grp.getgrgid(account.pw_gid).gr_name)
    except KeyError as error:
        raise ValueError("validator user primary group must exist") from error
    if group not in groups:
        raise ValueError("validator user must be a member of validator group")
    if groups & PRIVILEGED_GROUPS:
        raise ValueError("validator user must not belong to an administrative group")
    return ValidatorIdentity(user=user, group=group, uid=account.pw_uid, gid=group_entry.gr_gid)


def _validate_layout(
    *, source_root: str, framework_root: str, write_root: str, runner_temp: str, fresh: bool
) -> tuple[Path, Path, Path]:
    source = _existing_directory_without_symlinks(source_root, SOURCE_ROOT_LABEL)
    framework = _existing_directory_without_symlinks(framework_root, "framework root")
    write = _existing_directory_without_symlinks(write_root, "write root")
    temporary = _existing_directory_without_symlinks(runner_temp, "runner temp")
    if not _is_below(framework, source):
        raise ValueError("framework root must be a strict child of source root")
    if write.parent != temporary:
        raise ValueError("write root must be a direct private child of runner temp")
    if not write.name.startswith(WRITE_ROOT_PREFIX) or write.name == WRITE_ROOT_PREFIX:
        raise ValueError("write root must use the private validation prefix")
    if any(
        write == tree or _is_below(write, tree) or _is_below(tree, write)
        for tree in (source, framework)
    ):
        raise ValueError("write root must be disjoint from source and framework roots")
    write_metadata = os.lstat(write)
    if write_metadata.st_uid != 0 or stat.S_IMODE(write_metadata.st_mode) != 0o711:
        raise ValueError("write root must be root-owned with mode 0711")
    if fresh:
        with os.scandir(write) as entries:
            if next(entries, None) is not None:
                raise ValueError("write root must be newly created and empty")
    return source, framework, write


def validate_layout(
    *, source_root: str, framework_root: str, write_root: str, runner_temp: str
) -> tuple[Path, Path, Path]:
    """Validate a fresh setup layout without creating or changing anything."""
    return _validate_layout(
        source_root=source_root,
        framework_root=framework_root,
        write_root=write_root,
        runner_temp=runner_temp,
        fresh=True,
    )


def _validate_cleanup_layout(arguments: argparse.Namespace) -> tuple[Path, Path]:
    """Accept only one exact private guard root for descriptor-safe removal."""
    source = _existing_directory_without_symlinks(arguments.source_root, SOURCE_ROOT_LABEL)
    framework = _existing_directory_without_symlinks(arguments.framework_root, "framework root")
    write = _existing_directory_without_symlinks(arguments.write_root, "write root")
    temporary = _existing_directory_without_symlinks(arguments.runner_temp, "runner temp")
    if not _is_below(framework, source):
        raise ValueError("framework root must be a strict child of source root")
    if write.parent != temporary:
        raise ValueError("cleanup write root must be a direct child of runner temp")
    if not write.name.startswith(WRITE_ROOT_PREFIX) or write.name == WRITE_ROOT_PREFIX:
        raise ValueError("cleanup write root must use the private validation prefix")
    if any(
        _is_within(write, tree) or _is_within(tree, write)
        for tree in (source, framework, source / ".git")
    ):
        raise ValueError("cleanup write root must not overlap source, framework, or Git metadata")
    write_metadata = os.lstat(write)
    if (
        write_metadata.st_uid != 0
        or write_metadata.st_gid != 0
        or stat.S_IMODE(write_metadata.st_mode) != 0o711
    ):
        raise ValueError("cleanup write root must remain root-owned with mode 0711")
    _reject_mounts_within(write, "cleanup write root", include_root=True)
    return write, temporary


def _open_child_directory(parent_descriptor: int, name: str) -> int:
    return os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=parent_descriptor,
    )


def _open_existing_directory_path(path: Path) -> int:
    """Open every directory component by descriptor without link traversal."""
    descriptor = os.open(
        path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        for component in path.parts[1:]:
            child_descriptor = _open_child_directory(descriptor, component)
            os.close(descriptor)
            descriptor = child_descriptor
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _remove_tree_contents(directory_descriptor: int) -> None:
    """Unlink an already-validated private tree without following symlinks."""
    with os.scandir(directory_descriptor) as entries:
        names = sorted(entry.name for entry in entries)
    for name in names:
        metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            child_descriptor = _open_child_directory(directory_descriptor, name)
            try:
                opened = os.fstat(child_descriptor)
                if not _same_inode(metadata, opened):
                    raise ValueError("cleanup directory changed while opening")
                _remove_tree_contents(child_descriptor)
            finally:
                os.close(child_descriptor)
            os.rmdir(name, dir_fd=directory_descriptor)
            continue
        # unlink() never follows a final symlink and cannot traverse a child.
        os.unlink(name, dir_fd=directory_descriptor)


def cleanup_sandbox(arguments: argparse.Namespace) -> Path:
    """Remove only a checked direct child of runner temp without source access."""
    if os.geteuid() != 0:
        raise ValueError("readonly validation sandbox cleanup must run as root")
    write, temporary = _validate_cleanup_layout(arguments)
    temporary_descriptor = _open_existing_directory_path(temporary)
    write_descriptor = -1
    try:
        expected = os.stat(write.name, dir_fd=temporary_descriptor, follow_symlinks=False)
        write_descriptor = _open_child_directory(temporary_descriptor, write.name)
        opened = os.fstat(write_descriptor)
        if (
            not _same_inode(expected, opened)
            or not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != 0
            or opened.st_gid != 0
            or stat.S_IMODE(opened.st_mode) != 0o711
        ):
            raise ValueError("cleanup write root changed while opening")
        _remove_tree_contents(write_descriptor)
        os.close(write_descriptor)
        write_descriptor = -1
        # A mount installed after the initial check must fail rather than be
        # hidden by recursive deletion. The final rmdir is descriptor-relative.
        _reject_mounts_within(write, "cleanup write root", include_root=True)
        os.rmdir(write.name, dir_fd=temporary_descriptor)
    finally:
        if write_descriptor >= 0:
            os.close(write_descriptor)
        os.close(temporary_descriptor)
    return write


def _validate_parent_git_layout(source: Path) -> Path:
    """Require Parent Git control directories to be real, non-link directories."""
    source_git_root = source / ".git"
    source_git_metadata = os.lstat(source_git_root)
    if stat.S_ISLNK(source_git_metadata.st_mode) or not stat.S_ISDIR(source_git_metadata.st_mode):
        raise ValueError("Parent .git must be a non-symlink directory")
    modules = source_git_root / "modules"
    modules_metadata = os.lstat(modules)
    if stat.S_ISLNK(modules_metadata.st_mode) or not stat.S_ISDIR(modules_metadata.st_mode):
        raise ValueError("Parent .git/modules must be a non-symlink directory")
    return source_git_root


def _validate_source_symbolic_link(path: Path, relative: str, source: Path) -> None:
    """Require one source symlink's lexical target to remain within source."""
    target = _lexical_link_target(path, os.readlink(path))
    if not _is_within(target, source):
        raise ValueError(f"source symbolic link must remain inside source root: {relative}")


def _validate_gitfile(
    path: Path, relative: str, metadata: os.stat_result, source_git_root: Path
) -> None:
    """Validate one non-directory nested Git metadata entry."""
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"Git metadata must not be a symbolic link: {relative}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"Git metadata has an unsupported type: {relative}")
    content = _read_small_regular_text(path, metadata).strip()
    if not content.startswith("gitdir: "):
        raise ValueError(f"Git metadata has an invalid gitdir declaration: {relative}")
    target_text = content.removeprefix("gitdir: ")
    if not target_text or "\x00" in target_text:
        raise ValueError(f"Git metadata has an invalid gitdir target: {relative}")
    target = _lexical_link_target(path, target_text)
    if not _is_within(target, source_git_root):
        raise ValueError(f"Git metadata target must remain below Parent .git: {relative}")
    _existing_directory_without_symlinks(str(target), f"Git metadata target for {relative}")


def _validate_source_links_and_git_metadata(source: Path) -> None:
    """Reject links which could turn a source path into an external write path."""
    source_git_root = _validate_parent_git_layout(source)
    for path, relative, metadata in _walk_tree(source):
        if stat.S_ISLNK(metadata.st_mode):
            _validate_source_symbolic_link(path, relative, source)
        if path.name != ".git" or path == source_git_root:
            continue
        if stat.S_ISDIR(metadata.st_mode):
            continue
        _validate_gitfile(path, relative, metadata, source_git_root)


def _make_external_root(write_root: Path, identity: ValidatorIdentity) -> Path:
    """Create the only directory writable by the validator identity."""
    external = write_root / EXTERNAL_DIRNAME
    os.mkdir(external, 0o700)
    os.chown(external, identity.uid, identity.gid, follow_symlinks=False)
    os.chmod(external, 0o700)
    return external


def _prepared_control_paths(write_root: Path, identity: ValidatorIdentity) -> tuple[Path, Path]:
    """Validate the root-only inventory and validator-only external root."""
    with os.scandir(write_root) as entries:
        names = {entry.name for entry in entries}
    expected = {INVENTORY_FILENAME, EXTERNAL_DIRNAME}
    if names != expected:
        raise ValueError("write root contains an unexpected control or candidate output")
    inventory = write_root / INVENTORY_FILENAME
    external = write_root / EXTERNAL_DIRNAME
    inventory_metadata = os.lstat(inventory)
    if (
        not stat.S_ISREG(inventory_metadata.st_mode)
        or inventory_metadata.st_uid != 0
        or inventory_metadata.st_gid != 0
        or stat.S_IMODE(inventory_metadata.st_mode) != 0o600
        or inventory_metadata.st_nlink != 1
    ):
        raise ValueError("source inventory must remain root-owned mode-0600 regular data")
    external_metadata = os.lstat(external)
    if (
        stat.S_ISLNK(external_metadata.st_mode)
        or not stat.S_ISDIR(external_metadata.st_mode)
        or external_metadata.st_uid != identity.uid
        or external_metadata.st_gid != identity.gid
        or stat.S_IMODE(external_metadata.st_mode) != 0o700
    ):
        raise ValueError("external root must remain validator-owned mode-0700 directory")
    return inventory, external


def _source_regular_inodes(source: Path) -> set[tuple[int, int]]:
    """Collect regular-file identities that candidate output must not hardlink."""
    return {
        (metadata.st_dev, metadata.st_ino)
        for _path, _relative, metadata in _walk_tree(source)
        if stat.S_ISREG(metadata.st_mode)
    }


def _validate_external_symbolic_link(path: Path, relative: str, external: Path) -> None:
    """Require one candidate output link to remain lexical and private."""
    target = os.readlink(path)
    if not target or "\x00" in target or os.path.isabs(target):
        raise ValueError(f"external output link has an unsafe target: {relative}")
    if not _is_within(_lexical_link_target(path, target), external):
        raise ValueError(f"external output link escapes external root: {relative}")


def _validate_external_entry(
    *,
    path: Path,
    relative: str,
    metadata: os.stat_result,
    external: Path,
    identity: ValidatorIdentity,
    source_regular_inodes: set[tuple[int, int]],
) -> None:
    """Validate one candidate-created object against output safety invariants."""
    if metadata.st_uid != identity.uid or metadata.st_gid != identity.gid:
        raise ValueError(f"external output has a foreign owner: {relative}")
    if stat.S_ISLNK(metadata.st_mode):
        _validate_external_symbolic_link(path, relative, external)
        return
    if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
        raise ValueError(f"external output has an unsupported file type: {relative}")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o022 or mode & 0o7000:
        raise ValueError(f"external output has unsafe permissions: {relative}")
    if stat.S_ISREG(metadata.st_mode) and (metadata.st_dev, metadata.st_ino) in source_regular_inodes:
        raise ValueError(f"external output hardlinks a source file: {relative}")


def _validate_external_tree(external: Path, source: Path, identity: ValidatorIdentity) -> None:
    """Reject output types, ownership, and links that escape the private root."""
    source_regular_inodes = _source_regular_inodes(source)
    for path, relative, metadata in _walk_tree(external):
        _validate_external_entry(
            path=path,
            relative=relative,
            metadata=metadata,
            external=external,
            identity=identity,
            source_regular_inodes=source_regular_inodes,
        )


def prepare_sandbox(args: argparse.Namespace) -> tuple[Path, str]:
    """Inventory an unchanged source tree and create its private output root."""
    if os.geteuid() != 0:
        raise ValueError("readonly validation sandbox preparation must run as root")
    source, _framework, write = validate_layout(
        source_root=args.source_root,
        framework_root=args.framework_root,
        write_root=args.write_root,
        runner_temp=args.runner_temp,
    )
    _reject_nested_source_mounts(source)
    _validate_source_links_and_git_metadata(source)
    identity = resolve_validator_identity(args.validator_user, args.validator_group)
    payload = _inventory_payload(_source_inventory(source))
    _write_exact_regular_file(write / INVENTORY_FILENAME, payload)
    external = _make_external_root(write, identity)
    return external, hashlib.sha256(payload).hexdigest()


def verify_sandbox(args: argparse.Namespace) -> tuple[Path, str]:
    """Fail closed unless source inventory and candidate output are valid."""
    if os.geteuid() != 0:
        raise ValueError("readonly validation sandbox verification must run as root")
    source, _framework, write = _validate_layout(
        source_root=args.source_root,
        framework_root=args.framework_root,
        write_root=args.write_root,
        runner_temp=args.runner_temp,
        fresh=False,
    )
    _reject_nested_source_mounts(source)
    identity = resolve_validator_identity(args.validator_user, args.validator_group)
    inventory_path, external = _prepared_control_paths(write, identity)
    expected, inventory_sha256 = _read_inventory(inventory_path)
    current = _source_inventory(source)
    if current != expected:
        raise ValueError("source inventory changed after validator execution")
    _validate_external_tree(external, source, identity)
    return external, inventory_sha256


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if arguments.cleanup:
            write_root = cleanup_sandbox(arguments)
            print(f"READONLY_SUBMODULE_VALIDATION_SANDBOX_CLEANED write_root={write_root}")
            return 0
        if arguments.verify:
            external, inventory_sha256 = verify_sandbox(arguments)
            state = "VERIFIED"
        else:
            external, inventory_sha256 = prepare_sandbox(arguments)
            state = "READY"
    except (OSError, ValueError) as error:
        print(f"readonly validation sandbox: {error}", file=sys.stderr)
        return 2
    print(
        "READONLY_SUBMODULE_VALIDATION_SANDBOX_"
        f"{state} external={external} source_inventory_sha256={inventory_sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
