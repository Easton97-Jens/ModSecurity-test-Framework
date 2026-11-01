#!/usr/bin/env python3
"""Execute Go's actual tool unchanged; retain link output after FIPS finalization."""

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import uuid


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def open_directory(value, *, private=False):
    path = Path(value)
    if not path.is_absolute() or str(path) != value or ".." in path.parts:
        raise ValueError("Go capture directories must be canonical absolute paths")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            details = os.fstat(descriptor)
            if (details.st_uid not in {0, os.geteuid()}
                    or details.st_mode & 0o022 and not (details.st_uid == 0 and details.st_mode & stat.S_ISVTX)):
                raise ValueError("Go capture directories require trusted non-writable ancestry")
        details = os.fstat(descriptor)
        if private and (details.st_uid != os.geteuid() or details.st_mode & 0o077):
            raise ValueError("Go capture directories must be owned and private")
        return path, descriptor
    except BaseException:
        os.close(descriptor)
        raise


def link_output(command):
    if Path(command[0]).name != "link" or command[1:] in (["-V"], ["-V=full"]):
        return None
    arguments = command[1:]
    if not arguments or any(argument.startswith("@") for argument in arguments):
        raise ValueError("Go link output requires an explicit unambiguous native operand")
    if arguments[0] == "-o" and len(arguments) > 1:
        value, remaining = arguments[1], arguments[2:]
    elif arguments[0].startswith("-o="):
        value, remaining = arguments[0][3:], arguments[1:]
    else:
        raise ValueError("Go link output must be its first native option")
    if not value or any(argument in {"-o", "--o"} or argument.startswith(("-o=", "--o="))
                        for argument in remaining):
        raise ValueError("Go link output must have one nonempty native operand")
    path = Path(value)
    if not path.is_absolute() or str(path) != value or ".." in path.parts:
        raise ValueError("Go link output must be canonical and absolute")
    return path


def verify_output_file(details):
    if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid()
            or details.st_nlink != 1 or details.st_mode & 0o022):
        raise ValueError("Go link output must be an owned single-link regular file")


def output_parent(work, work_descriptor, output):
    relative = output.relative_to(work)
    if not relative.parts:
        raise ValueError("Go link output must be below its admitted work directory")
    descriptor = os.dup(work_descriptor)
    try:
        for part in relative.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            details = os.fstat(descriptor)
            if details.st_uid != os.geteuid() or details.st_mode & 0o022:
                raise ValueError("Go link output ancestors must remain task-owned and non-writable")
        try:
            verify_output_file(os.stat(relative.name, dir_fd=descriptor, follow_symlinks=False))
        except FileNotFoundError:
            pass
        return descriptor, relative.name
    except BaseException:
        os.close(descriptor)
        raise


def file_identity(details):
    return tuple(getattr(details, field) for field in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns"))


def copy_output(source, destination):
    before = os.fstat(source)
    verify_output_file(before)
    checksum = hashlib.sha256()
    length = 0
    with os.fdopen(destination, "wb", closefd=False) as retained:
        while chunk := os.read(source, 1024 * 1024):
            length += len(chunk)
            if length > before.st_size:
                raise ValueError("Go linker output changed during retention")
            checksum.update(chunk)
            retained.write(chunk)
        retained.flush()
        os.fsync(retained.fileno())
    if length != before.st_size or file_identity(before) != file_identity(os.fstat(source)):
        raise ValueError("Go linker output changed during retention")
    return checksum.hexdigest()


def retain_output(root, root_descriptor, parent_descriptor, name, command, output):
    identifier = uuid.uuid4().hex
    try:
        os.mkdir("go-postlink", mode=0o700, dir_fd=root_descriptor)
    except FileExistsError:
        pass
    directory = os.open("go-postlink", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=root_descriptor)
    try:
        details = os.fstat(directory)
        if details.st_uid != os.geteuid() or details.st_mode & 0o077:
            raise ValueError("Go retained output directory must be owned and private")
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_descriptor)
        try:
            destination = os.open(identifier, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                  0o600, dir_fd=directory)
            try:
                checksum = copy_output(source, destination)
            finally:
                os.close(destination)
        finally:
            os.close(source)
        record = {"schema": 1, "kind": "go-tool-link", "arguments": command,
                  "tool_sha256": digest(command[0]), "directory": str(Path.cwd().resolve()),
                  "output": str(output), "output_sha256": checksum,
                  "retained_output": str(root / "go-postlink" / identifier)}
        receipt = os.open(identifier + ".json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                          0o600, dir_fd=root_descriptor)
        try:
            with os.fdopen(receipt, "w", closefd=False) as stream:
                stream.write(json.dumps(record, sort_keys=True) + "\n")
        finally:
            os.close(receipt)
    finally:
        os.close(directory)


def run_admitted(command, root, root_descriptor, work, work_descriptor):
    output = link_output(command)
    parent_descriptor = None
    try:
        if output is not None:
            parent_descriptor, name = output_parent(work, work_descriptor, output)
        status = subprocess.run(command, check=False).returncode
        if status or output is None:
            return status
        retain_output(root, root_descriptor, parent_descriptor, name, command, output)
        return 0
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def main():
    if len(sys.argv) < 2:
        return 2
    root_descriptor = work_descriptor = None
    try:
        root, root_descriptor = open_directory(os.environ["SONAR_NATIVE_CAPTURE_ROOT"], private=True)
        work, work_descriptor = open_directory(os.environ["SONAR_NATIVE_GO_WORK_ROOT"], private=True)
        if work != root.parent / "go-work":
            raise ValueError("Go work root must be the admitted capture run's private go-work sibling")
        return run_admitted(sys.argv[1:], root, root_descriptor, work, work_descriptor)
    except (OSError, ValueError, KeyError) as error:
        print(f"Go linker retention failed: {error}", file=sys.stderr)
        return 1
    finally:
        if work_descriptor is not None:
            os.close(work_descriptor)
        if root_descriptor is not None:
            os.close(root_descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
