#!/usr/bin/env python3
"""Synchronize reviewed test metadata after canonical maintenance changes."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import stat
import subprocess
import sys

TOOL_ROOT = Path(__file__).resolve().parents[2]
INVENTORY = "connector_suite/config/testing/active-cases.json"
ARCHIVE = "connector_suite/reports/testing/test-selection-archive.generated.json"
COMMON = "ci/lib/common.sh"
COMMON_BINDING = "modules/ModSecurity-test-Framework/ci/lib/common.sh"
LIMIT = 4 * 1024 * 1024


def validate_root(value):
    root = Path(value)
    if (
        root.is_symlink()
        or root.absolute() != root.resolve()
        or root.resolve() != TOOL_ROOT
    ):
        raise ValueError("--root must identify this trusted tool checkout")
    return TOOL_ROOT


@contextmanager
def local_context(root):
    keys = (
        "TEST_ROOT",
        "FRAMEWORK_ROOT",
        "FRAMEWORK_REVISION",
        "CONNECTOR_ROOT",
        "CONNECTOR_REVISION",
        "CONNECTOR_TEST_PROFILE",
        "CONNECTOR_TEST_OUTPUT_ROOT",
        "PYTHONPATH",
    )
    keys += tuple(key for key in os.environ if key.startswith("GIT_"))
    previous = {key: os.environ.get(key) for key in keys}
    old_path = sys.path[:]
    try:
        for key in keys:
            os.environ.pop(key, None)
        os.environ.update(
            TEST_ROOT=str(root),
            FRAMEWORK_ROOT=str(root),
            PYTHONPATH=os.pathsep.join((str(root), str(root / "connector_suite"))),
        )
        sys.path[:0] = [str(root), str(root / "connector_suite")]
        yield
    finally:
        sys.path[:] = old_path
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def native_tool(root, name):
    path = root / "connector_suite/modsecurity_connector_ci/tools" / name
    spec = importlib.util.spec_from_file_location(
        "maintenance_" + name.replace("-", "_"), path
    )
    if spec is None or spec.loader is None:
        raise ValueError("cannot load native test metadata generator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def archive_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sync(root, *, write):
    with local_context(root):
        bindings = native_tool(root, "update-inventory-bindings.py")
        archive = native_tool(root, "update-test-archive.py")
        original, updated, changed = bindings.planned(root)
        if changed and not write:
            raise ValueError("inventory source bindings require regeneration")
        if changed:
            bindings.atomic_write(root, original, updated)
        # The archive reads the newly synchronized inventory, in this order.
        expected = archive_bytes(archive.archive())
        current = bindings.inventory._read_regular_source(root, ARCHIVE)
        if current != expected:
            if not write:
                raise ValueError("test selection archive requires regeneration")
            destination = root / ARCHIVE
            metadata = destination.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError(
                    "archive destination must be a regular single-link file"
                )
            destination.write_bytes(expected)
    print(
        "MAINTENANCE_TEST_VIEWS_VERIFIED"
        if not write
        else "MAINTENANCE_TEST_VIEWS_UPDATED"
    )


def git(root, *arguments):
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        timeout=30,
        env={
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GIT_")
        },
    )
    if len(result.stdout) > LIMIT:
        raise ValueError("Git metadata exceeds maintenance bound")
    return result.stdout


def revision(root, reference):
    result = (
        git(root, "rev-parse", "--verify", "--end-of-options", reference + "^{commit}")
        .decode()
        .strip()
    )
    if len(result) != 40 or any(char not in "0123456789abcdef" for char in result):
        raise ValueError("revision must resolve to an exact Git commit")
    return result


def blob(root, commit, path):
    row = git(root, "ls-tree", "-z", commit, "--", path)
    fields = row.rstrip(b"\0").split(b"\t")
    if len(fields) != 2 or fields[1].decode() != path:
        raise ValueError("required maintenance path is absent")
    mode, kind, identity = fields[0].decode().split()
    if kind != "blob" or mode not in {"100644", "100755"}:
        raise ValueError("maintenance paths must be regular Git blobs")
    size = int(git(root, "cat-file", "-s", identity))
    if size < 0 or size > LIMIT:
        raise ValueError("Git blob exceeds maintenance bound")
    data = git(root, "cat-file", "blob", identity)
    if len(data) != size:
        raise ValueError("Git blob size changed during inspection")
    return mode, data


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate maintenance metadata key")
        value[key] = item
    return value


def decode(data):
    return json.loads(data, object_pairs_hook=unique)


def verify_python_candidate(root, base, head):
    base, head = revision(root, base), revision(root, head)
    before, after = {}, {}
    for path in (COMMON, ".python-version", INVENTORY, ARCHIVE):
        old_mode, before[path] = blob(root, base, path)
        new_mode, after[path] = blob(root, head, path)
        if old_mode != new_mode:
            raise ValueError("maintenance candidate changes a file mode: " + path)
    assignments = re.findall(
        rb"(?m)^[ \t]*(?:export[ \t]+)?CI_CANONICAL_PYTHON_VERSION[ \t]*=.*$",
        after[COMMON],
    )
    pattern = rb'CI_CANONICAL_PYTHON_VERSION=(?:"(3\.15\.(?:0|[1-9]\d*))"|(3\.15\.(?:0|[1-9]\d*)))'
    assignment = (
        re.fullmatch(pattern, assignments[0], flags=re.ASCII)
        if len(assignments) == 1
        else None
    )
    if assignment is None:
        raise ValueError(
            "candidate requires one literal ASCII Python 3.15 patch assignment"
        )
    version = assignment.group(1) or assignment.group(2)
    if after[".python-version"] != version + b"\n":
        raise ValueError(
            "candidate Python selector must match its canonical assignment"
        )
    inventory = decode(before[INVENTORY])
    pool = inventory["source_bindings"]
    selected = [row for row in pool if row["path"] == COMMON_BINDING]
    if (
        len(selected) != 1
        or selected[0]["sha256"] != hashlib.sha256(before[COMMON]).hexdigest()
    ):
        raise ValueError("trusted base must contain the exact canonical source binding")
    selected[0]["sha256"] = hashlib.sha256(after[COMMON]).hexdigest()
    expected_inventory = (
        json.dumps(inventory, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode()
    if after[INVENTORY] != expected_inventory:
        raise ValueError(
            "candidate inventory must change only the canonical source digest"
        )
    archive = decode(before[ARCHIVE])
    if archive["inventory_sha256"] != hashlib.sha256(before[INVENTORY]).hexdigest():
        raise ValueError("trusted base archive must bind its inventory")
    archive["inventory_sha256"] = hashlib.sha256(expected_inventory).hexdigest()
    if after[ARCHIVE] != archive_bytes(archive):
        raise ValueError("candidate archive must change only its inventory digest")
    print("PYTHON_CANDIDATE_TEST_VIEWS_VERIFIED")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--root", required=True)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--write", action="store_true")
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--verify-python-candidate", action="store_true")
    args = parser.parse_args(argv)
    try:
        root = validate_root(args.root)
        if args.verify_python_candidate:
            verify_python_candidate(
                root, "origin/master", "origin/automation/update-framework-python-315"
            )
        else:
            sync(root, write=args.write)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
    ) as error:
        print("MAINTENANCE_TEST_VIEWS_REJECTED: " + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
