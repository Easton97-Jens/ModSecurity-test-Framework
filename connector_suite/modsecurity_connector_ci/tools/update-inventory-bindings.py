"""Review or refresh only existing Framework schema-4/5 source digest slots.

Run with explicit TEST_ROOT and the Framework package on PYTHONPATH. The default
is --check; --apply is an explicit local maintenance write, never activation.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import uuid

from modsecurity_test_framework.connector_context import test_root
from modsecurity_connector_ci.lib import active_test_inventory as inventory

INVENTORY = "connector_suite/config/testing/active-cases.json"
SOURCE_MAP = "connector_suite/source-map.json"
LIMIT = 2 * 1024 * 1024
PREFIX = "modules/ModSecurity-test-Framework/"


def decode(raw):
    if len(raw) > LIMIT:
        raise ValueError("inventory maintenance JSON exceeds 2 MiB")
    return json.loads(raw, object_pairs_hook=inventory._unique_object)


def planned(root: Path):
    original = inventory._read_regular_source(root, INVENTORY)
    value = decode(original)
    inventory._keys(value, {"schema_version", "executions", "offline_unit_exceptions",
                            "source_bindings", "connector_source_paths"}, "inventory")
    if type(value["schema_version"]) is not int or value["schema_version"] not in {4, 5}:
        raise ValueError("maintenance requires schema 4 or 5")
    pool = value["source_bindings"]
    if not isinstance(pool, list) or not pool:
        raise ValueError("source bindings must be a nonempty array")
    bindings = inventory._source_bindings(pool)
    products = value["connector_source_paths"]
    if not isinstance(products, list) or not products:
        raise ValueError("product snapshots must be an explicit nonempty list")
    for path in products:
        inventory._relative_path(path)
    if len(set(products)) != len(products) or set(products) & bindings.keys():
        raise ValueError("duplicate or conflicting source ownership")
    rows = value["executions"]
    exceptions = value["offline_unit_exceptions"]
    if not isinstance(rows, list) or not rows or not isinstance(exceptions, list):
        raise ValueError("invalid execution arrays")
    all_bindings = {**bindings, **{path: "0" * 64 for path in products}}
    used = set()
    expanded = copy.deepcopy(rows + exceptions)
    inventory._expand_indexed_sources(value, expanded)
    for row in expanded:
        refs = inventory._shared_source_references(row, all_bindings)
        used.update(refs)
        row["sources"] = [{"path": path, "sha256": all_bindings[path]} for path in row["sources"]]
        inventory._validate_execution(row)
    if used != set(all_bindings):
        raise ValueError("unused source bindings")
    inventory._validate_offline_exceptions(expanded[len(rows):])
    if sum(len(row["cases"]) for row in rows) > inventory.HARD_CASE_LIMIT:
        raise ValueError("default case limit exceeded")
    for values in ([row["id"] for row in expanded],
                   [json.dumps(row["selector"], sort_keys=True) for row in expanded],
                   [case["id"] for row in expanded for case in row["cases"]]):
        if len(values) != len(set(values)):
            raise ValueError("duplicate execution, selector or case")
    mapping = decode(inventory._read_regular_source(root, SOURCE_MAP))
    inventory._keys(mapping, {"schema_version", "paths", "connector_paths"}, "source map")
    if type(mapping["schema_version"]) is not int or mapping["schema_version"] != 1:
        raise ValueError("unsupported source map")
    if not isinstance(mapping["paths"], dict) or not isinstance(mapping["connector_paths"], dict):
        raise ValueError("invalid source map paths")
    for key, destination in mapping["paths"].items():
        inventory._relative_path(key)
        inventory._relative_path(destination)
    changes = []
    for source in pool:
        logical = source["path"]
        if logical in mapping["paths"]:
            relative = mapping["paths"][logical]
        elif logical.startswith(PREFIX):
            relative = logical[len(PREFIX):]
        else:
            raise ValueError("binding has no exact Framework mapping: " + logical)
        inventory._relative_path(relative)
        digest = hashlib.sha256(inventory._read_regular_source(root, relative)).hexdigest()
        if digest != source["sha256"]:
            changes.append(logical)
            source["sha256"] = digest
    updated = (json.dumps(value, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    if len(updated) > LIMIT:
        raise ValueError("updated inventory exceeds 2 MiB")
    return original, updated if changes else original, changes


def atomic_write(root: Path, original: bytes, updated: bytes):
    if len(original) > LIMIT or len(updated) > LIMIT:
        raise ValueError("inventory replacement exceeds 2 MiB")
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    name = INVENTORY.split("/")[-1]
    temporary = "." + name + "." + uuid.uuid4().hex
    created = False
    try:
        for part in INVENTORY.split("/")[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_nlink != 1):
            raise ValueError("destination must be an owned single-link regular file")
        if inventory._read_regular_source(root, INVENTORY) != original:
            raise ValueError("inventory changed during maintenance")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             stat.S_IMODE(before.st_mode), dir_fd=directory)
        created = True
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), stat.S_IMODE(before.st_mode))
            output.write(updated)
            output.flush()
            os.fsync(output.fileno())
        now = os.stat(name, dir_fd=directory, follow_symlinks=False)
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        if (any(getattr(now, key) != getattr(before, key) for key in fields)
                or inventory._read_regular_source(root, INVENTORY) != original):
            raise ValueError("inventory changed before replacement")
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        created = False
        os.fsync(directory)
    finally:
        if created:
            os.unlink(temporary, dir_fd=directory)
        os.close(directory)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        root = test_root()
        original, updated, changes = planned(root)
        for path in changes:
            print("SOURCE_DIGEST_DRIFT " + path)
        if changes and args.apply:
            atomic_write(root, original, updated)
        print("INVENTORY_BINDINGS_" + ("UPDATED" if changes and args.apply else
              "DRIFT" if changes else "VERIFIED"))
        return 1 if changes and not args.apply else 0
    except (OSError, ValueError) as error:
        print("INVENTORY_BINDINGS_REJECTED: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
