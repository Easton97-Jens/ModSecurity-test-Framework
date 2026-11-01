#!/usr/bin/env python3
"""Seal explicit current source identities and artifact bytes, not build proof."""
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


from modsecurity_connector_ci.lib.runtime_path_utils import fixed_runtime_temp_parent, open_private_runtime_root

EXTERNAL_ROOT = fixed_runtime_temp_parent() / "codex" / "ModSecurity-conector"
ARTIFACT_LIMIT = 64 * 1024 * 1024
FAULT_LIBRARIES = {
    "input": ("body_size_nonzero_with_null_data", "header_count_nonzero_with_null_headers"),
    "begin": ("transaction_begin_failure_cleanup",),
    "finish": ("finish_failure_propagation",),
    "write": ("response_short_write_resume", "response_write_would_block_resume"),
    "budget": ("engine_timeout_before_commit", "engine_timeout_after_commit"),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def absolute_path(value):
    path = Path(value)
    require(path.is_absolute() and str(path) == str(value) and path != Path("/")
            and ".." not in path.parts and len(str(path)) <= 4096
            and not any(ord(char) < 32 for char in str(path)), "canonical absolute path required")
    return path


def open_directory(path):
    """Pin existing directories without following any path component."""
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in absolute_path(path).parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            details = os.fstat(descriptor)
            sticky_shared = details.st_uid == 0 and details.st_mode & stat.S_ISVTX
            require(details.st_uid in {0, os.geteuid()} and (not details.st_mode & 0o022 or sticky_shared), "unsafe directory ancestor")
        details = os.fstat(descriptor)
        require(details.st_uid == os.geteuid() and not details.st_mode & 0o022, "owned non022 directory required")
        return descriptor
    except (OSError, ValueError) as error:
        os.close(descriptor)
        raise ValueError("unsafe explicit directory") from error


def identity(details):
    return (details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns,
            details.st_ctime_ns, details.st_uid, details.st_mode, details.st_nlink)


def hash_artifact(path, *, maximum_bytes=ARTIFACT_LIMIT):
    path = absolute_path(path)
    require(type(maximum_bytes) is int and maximum_bytes > 0, "positive artifact bound required")
    parent = open_directory(path.parent)
    descriptor = None
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid == os.geteuid() and not before.st_mode & 0o022
                and 0 < before.st_size <= maximum_bytes, "owned bounded single-link non022 artifact required")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum_bytes + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            require(size <= maximum_bytes, "artifact size exceeded")
            digest.update(chunk)
        require(size == before.st_size and identity(before) == identity(os.fstat(descriptor))
                and identity(before) == identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), "artifact changed during hash")
        return digest.hexdigest()
    except OSError as error:
        raise ValueError("unsafe artifact") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def git(root, *args):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", LC_ALL="C")
    result = subprocess.run(["rtk", "proxy", "git", "-c", "core.fsmonitor=false",
                             "-c", "core.untrackedCache=false", "-C", str(root), *args],
                            env=env, capture_output=True, timeout=30, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 1024 * 1024, "explicit source Git read failed")
    return result.stdout.decode("utf-8").strip()


def source_tuple(parent, framework, mrts):
    revisions = []
    for root in (parent, framework, mrts):
        require(git(root, "rev-parse", "--show-toplevel") == str(root), "source must be exact Git root")
        sha = git(root, "rev-parse", "--verify", "HEAD")
        require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None, "actual HEAD40 required")
        require(not git(root, "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"), "dirty source rejected")
        revisions.append(sha)
    for root, leaf, expected in ((parent, "modules/ModSecurity-test-Framework", revisions[1]),
                                 (framework, "tools/MRTS", revisions[2])):
        require(git(root, "ls-tree", "HEAD", "--", leaf) == f"160000 commit {expected}\t{leaf}", "current Gitlink mismatch")
    return tuple(revisions)


def produce_native_authority(*, parent_root, framework_root, mrts_root, run_id,
                             artifact_root, binary_path, module_path, fault_libraries, output_parent):
    require(isinstance(run_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", run_id) is not None, "bounded run ID required")
    require(isinstance(fault_libraries, dict) and set(fault_libraries) == set(FAULT_LIBRARIES), "all five closed fault libraries required")
    sources = tuple(absolute_path(root) for root in (parent_root, framework_root, mrts_root))
    artifact_root, output_parent = absolute_path(artifact_root), absolute_path(output_parent)
    require(artifact_root != EXTERNAL_ROOT and artifact_root.is_relative_to(EXTERNAL_ROOT)
            and output_parent.is_relative_to(artifact_root), "output must be under explicit external artifact root")
    for root in sources:
        require(not artifact_root.is_relative_to(root) and not root.is_relative_to(artifact_root), "artifact/source boundaries overlap")
    roots = (*sources, artifact_root, output_parent)
    identities = []
    for root in roots:
        descriptor = open_directory(root)
        try:
            details = os.fstat(descriptor)
            identities.append((details.st_dev, details.st_ino))
        finally:
            os.close(descriptor)
    require(len(set(identities[:3])) == 3, "distinct source roots required")
    revisions = source_tuple(*sources)
    paths = {"binary": absolute_path(binary_path), "module": absolute_path(module_path),
             **{key: absolute_path(value) for key, value in fault_libraries.items()}}
    digests = {key: hash_artifact(path) for key, path in paths.items()}
    require(source_tuple(*sources) == revisions, "source tuple changed during sealing")
    require(all(hash_artifact(path) == digests[key] for key, path in paths.items()), "artifact changed before seal")
    require(source_tuple(*sources) == revisions, "source tuple changed before seal")
    for root, expected in zip(roots, identities, strict=True):
        descriptor = open_directory(root)
        try:
            details = os.fstat(descriptor)
            require((details.st_dev, details.st_ino) == expected, "explicit root changed")
        finally:
            os.close(descriptor)
    document = {"schema_version": 1, "connector": "nginx", "run_id": run_id,
                    "artifact_root": str(artifact_root), "parent_root": str(sources[0]), "framework_root": str(sources[1]),
                    "parent_sha": revisions[0], "framework_sha": revisions[1], "mrts_sha": revisions[2],
                    "binary_sha256": digests["binary"], "module_sha256": digests["module"],
                    "fault_library_sha256": {case: digests[key] for key, cases in FAULT_LIBRARIES.items() for case in cases}}
    raw = (json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    require(len(raw) <= 16384, "authority document exceeds bound")
    with open_private_runtime_root(output_parent) as directory:
        descriptor = os.open("native-operation-authority.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=directory.descriptor)
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o400)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(directory.descriptor)
    return {"authority_path": output_parent / "native-operation-authority.json", "authority_sha256": hashlib.sha256(raw).hexdigest(), "document": document}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("parent-root", "framework-root", "mrts-root", "artifact-root", "binary-path", "module-path", "output-parent"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    for name in FAULT_LIBRARIES:
        parser.add_argument("--" + name + "-fault-library", required=True, type=Path)
    args = vars(parser.parse_args(argv))
    args["fault_libraries"] = {name: args.pop(name + "_fault_library") for name in FAULT_LIBRARIES}
    try:
        result = produce_native_authority(**args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(2, f"native authority rejected: {error}\n")
    print(json.dumps({"authority_path": str(result["authority_path"]), "authority_sha256": result["authority_sha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
