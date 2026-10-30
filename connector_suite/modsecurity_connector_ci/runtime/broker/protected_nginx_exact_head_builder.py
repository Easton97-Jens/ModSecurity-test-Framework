#!/usr/bin/env python3
"""Build and package one untrusted exact-head NGINX candidate without privilege.

This helper is deliberately a *producer*, not an admission decision.  It is
run only on the isolated unprivileged candidate-build runner.  The candidate
checkout and its Makefile are untrusted and may execute there, but this helper
uses a fixed, empty-derived environment and transfers only three fixed-name
regular files plus a data-only manifest to the protected launcher.  The root
launcher recomputes all identities and never trusts this manifest as proof of
the artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any


EXPECTED_NGINX_VERSION = "1.31.6"
EXPECTED_NGINX_SOURCE_SHA256 = "974ed5298a5e398e008704ed5db284e655fc270c596493dbccada452448fc9f1"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
SHA40_RE = re.compile(r"^(?a:[\da-f]{40})$")
SHA256_RE = re.compile(r"^(?a:[\da-f]{64})$")
SAFE_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SNAPSHOT_RE = re.compile(r"^export ([A-Z][A-Z0-9_]*)='([^'\r\n]*)'$")
ARTIFACTS = {
    "nginx": "nginx",
    "module": "ngx_http_modsecurity_module.so",
    "library": "libmodsecurity.so.3",
}
ARTIFACT_MODES = {
    ARTIFACTS["nginx"]: 0o500,
    ARTIFACTS["module"]: 0o400,
    ARTIFACTS["library"]: 0o400,
}
TASK_ROOT_LABEL = "task root"
CANDIDATE_ROOT_LABEL = "candidate root"
RUNTIME_SNAPSHOT_LABEL = "runtime snapshot"
BUILD_ROOT_LABEL = "candidate build root"
OUTPUT_ROOT_LABEL = "candidate artifact root"
LIBRARY_DIRECTORY_LABEL = "ModSecurity library directory"
PINNED_ARCHIVE_LABEL = "pinned NGINX source archive"


class BuilderError(RuntimeError):
    """Raised for a rejected build input or artifact boundary."""


def fail(message: str) -> None:
    raise BuilderError(message)


def require_sha40(value: str, label: str) -> str:
    if SHA40_RE.fullmatch(value) is None:
        fail(f"{label} must be a lowercase 40-character SHA")
    return value


def require_sha256(value: str, label: str) -> str:
    if SHA256_RE.fullmatch(value) is None:
        fail(f"{label} must be a lowercase SHA-256")
    return value


def require_run_id(value: str) -> str:
    if SAFE_RUN_ID_RE.fullmatch(value) is None:
        fail("run ID is unsafe")
    return value


def require_unprivileged_identity() -> tuple[int, int]:
    """Return the effective non-root build identity or fail before Makefile code."""
    try:
        user_ids = os.getresuid()
        group_ids = os.getresgid()
    except AttributeError:
        fail("candidate build platform cannot verify complete UID/GID identities")
    if any(identity == 0 for identity in (*user_ids, *group_ids)):
        fail("candidate build must not run with a root UID or GID")
    return user_ids[1], group_ids[1]


def absolute_normalized(path: Path, label: str) -> Path:
    if not path.is_absolute():
        fail(f"{label} must be absolute")
    normalized = Path(os.path.normpath(os.fspath(path)))
    if normalized == Path("/"):
        fail(f"{label} must not be filesystem root")
    return normalized


def _directory_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _regular_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_nlink,
    )


def _relative_components(path: Path, root: Path, label: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    root = absolute_normalized(root, f"{label} root")
    path = absolute_normalized(path, label)
    try:
        relative = path.relative_to(root)
    except ValueError:
        fail(f"{label} escapes its approved root")
    components = relative.parts
    if not allow_empty and not components:
        fail(f"{label} must not be its approved root")
    if any(component in {"", ".", ".."} for component in components):
        fail(f"{label} has an unsafe relative component")
    return components


def _require_private_directory_metadata(
    metadata: os.stat_result, label: str, *, owner: int | None = None
) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        fail(f"{label} must be a directory")
    if metadata.st_mode & 0o022:
        fail(f"{label} must not be group- or other-writable")
    if owner is not None and metadata.st_uid != owner:
        fail(f"{label} has an unexpected owner")


def _open_relative_directory(root_descriptor: int, components: tuple[str, ...], label: str) -> int:
    """Walk directory components below an admitted descriptor without links."""
    descriptor = os.dup(root_descriptor)
    try:
        for component in components:
            before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
                fail(f"{label} contains an unsafe directory component")
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            opened = os.fstat(child)
            if _directory_identity(opened) != _directory_identity(before):
                os.close(child)
                fail(f"{label} changed while opening")
            previous = descriptor
            descriptor = child
            os.close(previous)
        result = descriptor
        descriptor = -1
        return result
    except OSError as exc:
        fail(f"could not open {label}: {exc}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _open_private_directory(path: Path, label: str, *, owner: int | None = None) -> int:
    path = absolute_normalized(path, label)
    root_descriptor = -1
    descriptor = -1
    try:
        root_descriptor = os.open(
            path.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        descriptor = _open_relative_directory(root_descriptor, path.parts[1:], label)
    except OSError as exc:
        fail(f"could not open {label}: {exc}")
    finally:
        if root_descriptor >= 0:
            os.close(root_descriptor)
    try:
        _require_private_directory_metadata(os.fstat(descriptor), label, owner=owner)
        result = descriptor
        descriptor = -1
        return result
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _verify_relative_directory_identity(
    root_descriptor: int,
    components: tuple[str, ...],
    expected: tuple[int, int],
    label: str,
) -> None:
    descriptor = _open_relative_directory(root_descriptor, components, label)
    try:
        if _directory_identity(os.fstat(descriptor)) != expected:
            fail(f"{label} changed while packaging")
    finally:
        os.close(descriptor)


def _verify_absolute_directory_identity(
    path: Path, expected: tuple[int, int], label: str
) -> None:
    descriptor = _open_private_directory(path, label, owner=os.geteuid())
    try:
        if _directory_identity(os.fstat(descriptor)) != expected:
            fail(f"{label} changed while packaging")
    finally:
        os.close(descriptor)


def require_no_symlink_chain(path: Path, label: str, *, allow_missing_leaf: bool = False) -> Path:
    path = absolute_normalized(path, label)
    current = Path(path.root)
    parts = path.parts[1:]
    for index, part in enumerate(parts):
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if allow_missing_leaf and index == len(parts) - 1:
                break
            fail(f"{label} component is missing")
        if stat.S_ISLNK(metadata.st_mode):
            fail(f"{label} contains a symbolic link")
    return path


def contained(path: Path, root: Path, label: str, *, allow_missing_leaf: bool = False) -> Path:
    root = require_no_symlink_chain(root, f"{label} root")
    path = require_no_symlink_chain(path, label, allow_missing_leaf=allow_missing_leaf)
    try:
        path.relative_to(root)
    except ValueError:
        fail(f"{label} escapes its approved root")
    return path


def require_private_directory(path: Path, label: str, *, owner: int | None = None) -> None:
    descriptor = _open_private_directory(path, label, owner=owner)
    os.close(descriptor)


def _create_private_relative_directory(
    task_descriptor: int, components: tuple[str, ...], label: str
) -> int:
    if not components:
        fail(f"{label} must not be its approved root")
    parent_descriptor = _open_relative_directory(
        task_descriptor, components[:-1], f"{label} parent"
    )
    descriptor = -1
    try:
        name = components[-1]
        try:
            os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            fail(f"{label} must be fresh")
        try:
            os.mkdir(name, 0o700, dir_fd=parent_descriptor)
        except OSError as exc:
            fail(f"could not create {label}: {exc}")
        descriptor = _open_relative_directory(parent_descriptor, (name,), label)
        _require_private_directory_metadata(
            os.fstat(descriptor), label, owner=os.geteuid()
        )
        result = descriptor
        descriptor = -1
        return result
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def create_private_directory(
    path: Path, task_root: Path, label: str, *, task_descriptor: int | None = None
) -> None:
    own_descriptor = task_descriptor is None
    descriptor = task_descriptor
    if descriptor is None:
        descriptor = _open_private_directory(task_root, TASK_ROOT_LABEL, owner=os.geteuid())
    try:
        components = _relative_components(path, task_root, label)
        created = _create_private_relative_directory(descriptor, components, label)
        os.close(created)
    finally:
        if own_descriptor:
            os.close(descriptor)


def _require_regular_metadata(
    metadata: os.stat_result, label: str, *, owner: int | None, maximum: int
) -> None:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail(f"{label} must be a single-link regular file")
    if metadata.st_size < 1 or metadata.st_size > maximum:
        fail(f"{label} has an invalid size")
    if metadata.st_mode & 0o022:
        fail(f"{label} must not be group- or other-writable")
    if owner is not None and metadata.st_uid != owner:
        fail(f"{label} has an unexpected owner")


def _open_regular_at(
    root_descriptor: int,
    components: tuple[str, ...],
    label: str,
    *,
    owner: int | None = None,
    maximum: int = MAX_ARTIFACT_BYTES,
) -> tuple[int, os.stat_result]:
    if not components:
        fail(f"{label} must name a file")
    parent_descriptor = _open_relative_directory(
        root_descriptor, components[:-1], f"{label} parent"
    )
    descriptor = -1
    try:
        name = components[-1]
        before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode):
            fail(f"{label} contains a symbolic link")
        _require_regular_metadata(before, label, owner=owner, maximum=maximum)
        descriptor = os.open(
            name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_descriptor
        )
        opened = os.fstat(descriptor)
        if _regular_identity(opened) != _regular_identity(before):
            os.close(descriptor)
            descriptor = -1
            fail(f"{label} changed while opening")
        _require_regular_metadata(opened, label, owner=owner, maximum=maximum)
        result = descriptor
        descriptor = -1
        return result, opened
    except OSError as exc:
        fail(f"could not open {label}: {exc}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def open_regular_no_follow(path: Path, label: str, *, owner: int | None = None) -> tuple[int, os.stat_result]:
    path = absolute_normalized(path, label)
    root_descriptor = -1
    try:
        root_descriptor = os.open(
            path.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        return _open_regular_at(
            root_descriptor, path.parts[1:], label, owner=owner
        )
    except OSError as exc:
        fail(f"could not open {label}: {exc}")
    finally:
        if root_descriptor >= 0:
            os.close(root_descriptor)


def read_bounded_fd(descriptor: int, maximum: int, label: str) -> bytes:
    result = bytearray()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while len(result) <= maximum:
        chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - len(result)))
        if not chunk:
            break
        result.extend(chunk)
    if len(result) > maximum:
        fail(f"{label} exceeds its size limit")
    return bytes(result)


def sha256_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def strict_snapshot(
    path: Path, task_root: Path, *, task_descriptor: int | None = None
) -> dict[str, str]:
    if task_descriptor is None:
        path = contained(path, task_root, RUNTIME_SNAPSHOT_LABEL)
        descriptor, metadata = open_regular_no_follow(
            path, RUNTIME_SNAPSHOT_LABEL, owner=os.geteuid()
        )
    else:
        descriptor, metadata = _open_regular_at(
            task_descriptor,
            _relative_components(path, task_root, RUNTIME_SNAPSHOT_LABEL),
            RUNTIME_SNAPSHOT_LABEL,
            owner=os.geteuid(),
            maximum=MAX_MANIFEST_BYTES,
        )
    try:
        if metadata.st_size > MAX_MANIFEST_BYTES:
            fail(f"{RUNTIME_SNAPSHOT_LABEL} exceeds the size limit")
        raw = read_bounded_fd(descriptor, MAX_MANIFEST_BYTES, RUNTIME_SNAPSHOT_LABEL)
    finally:
        os.close(descriptor)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"{RUNTIME_SNAPSHOT_LABEL} is not UTF-8: {exc}")
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = SNAPSHOT_RE.fullmatch(line)
        if match is None:
            fail(f"{RUNTIME_SNAPSHOT_LABEL} is not a declarative export list")
        key, value = match.groups()
        if key in values:
            fail(f"{RUNTIME_SNAPSHOT_LABEL} has a duplicate key")
        values[key] = value
    required = {
        "MRTS_NATIVE_NGINX_BIN",
        "MRTS_NATIVE_NGINX_MODULE_FILE",
        "MRTS_NATIVE_NGINX_MODSECURITY_LIB_DIR",
        "NGINX_BUILD_DIR",
        "NGINX_PREFIX",
        "NGINX_DOWNLOAD_DIR",
    }
    if not required.issubset(values) or any(not values[key] for key in required):
        fail(f"{RUNTIME_SNAPSHOT_LABEL} lacks required NGINX artifact fields")
    if values.get("RUNTIME_COMPONENT_ENV_SNAPSHOT_TARGET") != "nginx":
        fail(f"{RUNTIME_SNAPSHOT_LABEL} target is not nginx")
    return values


def copy_fd(source: int, destination: int, expected_size: int, label: str) -> str:
    digest = hashlib.sha256()
    copied = 0
    os.lseek(source, 0, os.SEEK_SET)
    while True:
        chunk = os.read(source, 1024 * 1024)
        if not chunk:
            break
        copied += len(chunk)
        if copied > expected_size:
            fail(f"{label} grew while copying")
        digest.update(chunk)
        offset = 0
        while offset < len(chunk):
            offset += os.write(destination, chunk[offset:])
    if copied != expected_size:
        fail(f"{label} changed while copying")
    os.fsync(destination)
    return digest.hexdigest()


def package_file(
    source: Path,
    destination_name: str,
    build_root: Path,
    build_descriptor: int,
    output_descriptor: int,
    label: str,
) -> dict[str, Any]:
    if destination_name not in ARTIFACTS.values():
        fail(f"{label} destination is not allowlisted")
    destination_mode = ARTIFACT_MODES[destination_name]
    descriptor, metadata = _open_regular_at(
        build_descriptor,
        _relative_components(source, build_root, label),
        label,
        owner=os.geteuid(),
    )
    try:
        if (
            destination_name == ARTIFACTS["nginx"]
            and not metadata.st_mode & stat.S_IXUSR
        ):
            fail("candidate NGINX binary must be owner-executable")
        try:
            os.stat(destination_name, dir_fd=output_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            fail(f"{label} destination is not fresh")
        try:
            target = os.open(
                destination_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=output_descriptor,
            )
        except OSError as exc:
            fail(f"could not create {label} destination: {exc}")
        try:
            digest = copy_fd(descriptor, target, metadata.st_size, label)
            os.fchmod(target, destination_mode)
            final = os.fstat(target)
            if (not stat.S_ISREG(final.st_mode) or final.st_nlink != 1
                    or final.st_size != metadata.st_size
                    or stat.S_IMODE(final.st_mode) != destination_mode):
                fail(f"{label} destination changed while packaging")
        finally:
            os.close(target)
    finally:
        os.close(descriptor)
    return {"filename": destination_name, "sha256": digest, "size": metadata.st_size}


def write_private_json(payload: dict[str, Any], output_descriptor: int) -> None:
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(raw) > MAX_MANIFEST_BYTES:
        fail("artifact manifest exceeds the size limit")
    name = "artifact-manifest.json"
    temporary_name = f".{name}.tmp-{os.getpid()}"
    try:
        os.stat(name, dir_fd=output_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        fail("artifact manifest destination is not fresh")
    descriptor = -1
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=output_descriptor,
        )
    except OSError as exc:
        fail(f"could not create artifact manifest: {exc}")
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(
            temporary_name,
            name,
            src_dir_fd=output_descriptor,
            dst_dir_fd=output_descriptor,
        )
        descriptor = os.open(
            name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=output_descriptor
        )
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != 0o600):
                fail("artifact manifest has unsafe output metadata")
        finally:
            os.close(descriptor)
    except OSError as exc:
        fail(f"could not atomically publish artifact manifest: {exc}")
    finally:
        try:
            os.unlink(temporary_name, dir_fd=output_descriptor)
        except FileNotFoundError:
            pass


def package(arguments: argparse.Namespace, *, task_descriptor: int | None = None) -> Path:
    expected_head = require_sha40(arguments.expected_pr_head, "expected PR head")
    base_sha = require_sha40(arguments.trusted_dispatcher_base_sha, "trusted dispatcher base SHA")
    run_id = require_run_id(arguments.run_id)
    task_root = absolute_normalized(Path(arguments.task_root), TASK_ROOT_LABEL)
    build_root = absolute_normalized(Path(arguments.build_root), BUILD_ROOT_LABEL)
    output_root = absolute_normalized(Path(arguments.output_root), OUTPUT_ROOT_LABEL)
    own_task_descriptor = task_descriptor is None
    descriptor = task_descriptor
    if descriptor is None:
        descriptor = _open_private_directory(task_root, TASK_ROOT_LABEL, owner=os.geteuid())
    try:
        _require_private_directory_metadata(
            os.fstat(descriptor), TASK_ROOT_LABEL, owner=os.geteuid()
        )
        task_identity = _directory_identity(os.fstat(descriptor))
        output_components = _relative_components(
            output_root, task_root, OUTPUT_ROOT_LABEL
        )
        build_descriptor = _open_relative_directory(
            descriptor,
            _relative_components(build_root, task_root, BUILD_ROOT_LABEL),
            BUILD_ROOT_LABEL,
        )
        try:
            _require_private_directory_metadata(
                os.fstat(build_descriptor), BUILD_ROOT_LABEL, owner=os.geteuid()
            )
            output_descriptor = _create_private_relative_directory(
                descriptor, output_components, OUTPUT_ROOT_LABEL
            )
            try:
                _require_private_directory_metadata(
                    os.fstat(output_descriptor),
                    OUTPUT_ROOT_LABEL,
                    owner=os.geteuid(),
                )
                output_identity = _directory_identity(os.fstat(output_descriptor))
                values = strict_snapshot(
                    Path(arguments.runtime_snapshot), task_root, task_descriptor=descriptor
                )
                binary = Path(values["MRTS_NATIVE_NGINX_BIN"])
                module = Path(values["MRTS_NATIVE_NGINX_MODULE_FILE"])
                library_dir = Path(values["MRTS_NATIVE_NGINX_MODSECURITY_LIB_DIR"])
                library_descriptor = _open_relative_directory(
                    build_descriptor,
                    _relative_components(
                        library_dir, build_root, LIBRARY_DIRECTORY_LABEL
                    ),
                    LIBRARY_DIRECTORY_LABEL,
                )
                try:
                    _require_private_directory_metadata(
                        os.fstat(library_descriptor),
                        LIBRARY_DIRECTORY_LABEL,
                        owner=os.geteuid(),
                    )
                finally:
                    os.close(library_descriptor)
                # The native Cache-v2 producer retains reviewed release assets
                # in NGINX_DOWNLOAD_DIR, independently of the connector build.
                # The directory remains beneath the admitted build descriptor.
                archive = Path(values["NGINX_DOWNLOAD_DIR"]) / f"nginx-{EXPECTED_NGINX_VERSION}.tar.gz"
                archive_fd, _ = _open_regular_at(
                    build_descriptor,
                    _relative_components(
                        archive, build_root, PINNED_ARCHIVE_LABEL
                    ),
                    PINNED_ARCHIVE_LABEL,
                    owner=os.geteuid(),
                )
                try:
                    if sha256_fd(archive_fd) != EXPECTED_NGINX_SOURCE_SHA256:
                        fail(f"pinned NGINX source archive digest does not match {EXPECTED_NGINX_VERSION}")
                finally:
                    os.close(archive_fd)
                artifacts = {
                    "nginx": package_file(
                        binary,
                        ARTIFACTS["nginx"],
                        build_root,
                        build_descriptor,
                        output_descriptor,
                        "NGINX binary",
                    ),
                    "module": package_file(
                        module,
                        ARTIFACTS["module"],
                        build_root,
                        build_descriptor,
                        output_descriptor,
                        "NGINX module",
                    ),
                    "library": package_file(
                        library_dir / ARTIFACTS["library"],
                        ARTIFACTS["library"],
                        build_root,
                        build_descriptor,
                        output_descriptor,
                        "ModSecurity library",
                    ),
                }
                manifest = {
                    "schema_version": 1,
                    "run_id": run_id,
                    "tested_pr_head": expected_head,
                    "trusted_dispatcher_base_sha": base_sha,
                    "nginx_version": EXPECTED_NGINX_VERSION,
                    "nginx_source_digest": EXPECTED_NGINX_SOURCE_SHA256,
                    "artifacts": artifacts,
                    "producer": {
                        "kind": "unprivileged-exact-head-build",
                        "runner_uid": os.geteuid(),
                        "runner_gid": os.getegid(),
                    },
                }
                write_private_json(manifest, output_descriptor)
            finally:
                os.close(output_descriptor)
            _verify_relative_directory_identity(
                descriptor,
                output_components,
                output_identity,
                "candidate artifact root",
            )
            _verify_absolute_directory_identity(
                task_root, task_identity, TASK_ROOT_LABEL
            )
        finally:
            os.close(build_descriptor)
    finally:
        if own_task_descriptor:
            os.close(descriptor)
    manifest_path = output_root / "artifact-manifest.json"
    return manifest_path


def build_environment(arguments: argparse.Namespace) -> dict[str, str]:
    task_root = absolute_normalized(Path(arguments.task_root), TASK_ROOT_LABEL)
    candidate_root = absolute_normalized(Path(arguments.candidate_root), CANDIDATE_ROOT_LABEL)
    framework_root = candidate_root / "modules" / "ModSecurity-test-Framework"
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONNOUSERSITE": "1",
        "PIP_REQUIRE_VIRTUALENV": "true",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "BUILD_ROOT": str(task_root / "build"),
        "VERIFIED_RUN_ROOT": str(task_root / "verified"),
        "TMP_ROOT": str(task_root / "tmp"),
        "LOG_ROOT": str(task_root / "logs"),
        "SOURCE_ROOT": str(task_root / "source"),
        "CONNECTOR_COMPONENT_CACHE": str(task_root / "build" / "component-cache"),
        "RUNTIME_REPORT_OUTPUT_ROOT": str(task_root / "runtime-component-reports"),
        "FRAMEWORK_ROOT": str(framework_root),
        "RUNTIME_COMPONENT_TARGET": "nginx",
        "ALLOW_RUNTIME_BUILDS": "1",
        "ALLOW_RUNTIME_DOWNLOADS": "1",
        "NGINX_SOURCE_MODE": "github-release",
        "NGINX_SOURCE_REPO_URL": "https://github.com/nginx/nginx",
        "NGINX_RELEASE_TAG": f"release-{EXPECTED_NGINX_VERSION}",
        "NGINX_SOURCE_GIT_REF": f"release-{EXPECTED_NGINX_VERSION}",
        "NGINX_RELEASE_ASSET_NAME": f"nginx-{EXPECTED_NGINX_VERSION}.tar.gz",
        "NGINX_SHA256": EXPECTED_NGINX_SOURCE_SHA256,
        "NGINX_REQUIRE_PINNED_PROVENANCE": "1",
    }


def run_candidate_build(arguments: argparse.Namespace) -> Path:
    expected_head = require_sha40(arguments.expected_pr_head, "expected PR head")
    base_sha = require_sha40(arguments.trusted_dispatcher_base_sha, "trusted dispatcher base SHA")
    require_run_id(arguments.run_id)
    runner_uid, _ = require_unprivileged_identity()
    task_root = absolute_normalized(Path(arguments.task_root), TASK_ROOT_LABEL)
    candidate_root = require_no_symlink_chain(Path(arguments.candidate_root), CANDIDATE_ROOT_LABEL)
    candidate_descriptor = _open_private_directory(
        candidate_root, CANDIDATE_ROOT_LABEL, owner=runner_uid
    )
    task_descriptor = -1
    try:
        task_descriptor = _open_private_directory(
            task_root, TASK_ROOT_LABEL, owner=runner_uid
        )
        environment = build_environment(arguments)
        # The target is a fixed Makefile entry point.  It is candidate-controlled
        # code, but this process has no root, no inherited environment, no secret,
        # and no credential helper.  A failure (including 77) propagates unchanged.
        command = ["/usr/bin/make", "fetch-deps"]
        try:
            subprocess.run(
                command,
                check=True,
                # Keep the admitted directory open through process creation.  A
                # same-UID writer cannot swap the validated path between the
                # admission checks and the child chdir; the child receives only
                # this directory descriptor, not an attacker-controlled path.
                cwd=f"/proc/self/fd/{candidate_descriptor}",
                env=environment,
                stdin=subprocess.DEVNULL,
                shell=False,
                pass_fds=(candidate_descriptor,),
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            fail(f"unprivileged candidate build failed: {exc}")
        snapshots = sorted(
            (task_root / "runtime-component-reports").glob("runtime-env-snapshot.*.sh")
        )
        if len(snapshots) != 1:
            fail("candidate build did not produce exactly one runtime snapshot")
        package_arguments = argparse.Namespace(
            expected_pr_head=expected_head,
            trusted_dispatcher_base_sha=base_sha,
            run_id=arguments.run_id,
            task_root=str(task_root),
            build_root=str(task_root / "build"),
            runtime_snapshot=str(snapshots[0]),
            output_root=arguments.output_root,
        )
        return package(package_arguments, task_descriptor=task_descriptor)
    finally:
        if task_descriptor >= 0:
            os.close(task_descriptor)
        os.close(candidate_descriptor)


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("package", "build"):
        command = commands.add_parser(name)
        command.add_argument("--expected-pr-head", required=True)
        command.add_argument("--trusted-dispatcher-base-sha", required=True)
        command.add_argument("--run-id", required=True)
        command.add_argument("--task-root", required=True)
        command.add_argument("--output-root", required=True)
    package_command = commands.choices["package"]
    package_command.add_argument("--build-root", required=True)
    package_command.add_argument("--runtime-snapshot", required=True)
    build_command = commands.choices["build"]
    build_command.add_argument("--candidate-root", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        output = package(arguments) if arguments.command == "package" else run_candidate_build(arguments)
        print(f"packaged protected exact-head candidate: {output.name}")
    except BuilderError as exc:
        print(f"BLOCKED: protected exact-head candidate builder: {exc}", file=sys.stderr)
        return 77
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
