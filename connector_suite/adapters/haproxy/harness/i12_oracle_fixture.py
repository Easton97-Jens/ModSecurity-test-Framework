"""Lossless HAProxy-local source-hash representation contract.

The reviewed proposal fixture is maintained separately from the shared original
inventory generator. Paths are values in its source-hash entries; original
inventories retain their frozen mapping representation. Canonicalization makes
the two representations comparable without changing any Oracle decisions.
"""
import argparse
import copy
import hashlib
import json
import re
from pathlib import Path

# Load the maintained Parent filesystem boundary from this checkout.
import sys as _i12_sys

import modsecurity_connector_ci.lib.i12_path_safety as i12_paths


def _ordered_source_hash_entries(value):
    entries = []
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise ValueError("source-hash entry requires only path and sha256")
        entries.append((entry["path"], entry["sha256"]))
    return entries


def source_hash_map(value):
    """Read frozen mappings or ordered entries, rejecting ambiguous entries."""
    if isinstance(value, dict):
        entries = list(value.items())
    elif isinstance(value, list):
        entries = _ordered_source_hash_entries(value)
    else:
        raise ValueError("source hashes require a mapping or ordered entries")
    result = {}
    for path, checksum in entries:
        if not isinstance(path, str) or not path or path in result:
            raise ValueError("source-hash paths must be unique nonempty strings")
        if (not isinstance(checksum, str) or len(checksum) != 64
                or any(character not in "0123456789abcdef" for character in checksum)):
            raise ValueError("source hash must be a lowercase SHA256")
        result[path] = checksum
    return result


def canonical_fixture(document):
    result = copy.deepcopy(document)
    for row in result["records"]:
        row["original_source_hashes"] = source_hash_map(row["original_source_hashes"])
    return result


def semantic_sha256(document):
    canonical = canonical_fixture(document)
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def migrate_fixture(document):
    result = copy.deepcopy(document)
    for row in result["records"]:
        row["original_source_hashes"] = [
            {"path": path, "sha256": checksum}
            for path, checksum in source_hash_map(row["original_source_hashes"]).items()
        ]
    if canonical_fixture(result) != canonical_fixture(document):
        raise ValueError("source-hash representation changed fixture semantics")
    return result


def render_fixture(document):
    """Keep simple path/hash entries on one line for a reviewable ledger."""
    text = json.dumps(document, indent=2, ensure_ascii=False)
    pattern = r'(?m)^( *)\{\n\1 {2}"path": ("(?:[^"\\]|\\.)*"),\n\1 {2}"sha256": ("[a-f0-9]{64}")\n\1\}'
    return re.sub(pattern, r'\1{"path": \2, "sha256": \3}', text) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    document = json.loads(i12_paths.read_text(args.source))
    result = migrate_fixture(document)
    with i12_paths.new_text(args.output) as output:
        output.write(render_fixture(result))
    print(json.dumps({"records": len(result["records"]), "semantic_sha256": semantic_sha256(result)}))


if __name__ == "__main__":
    main()
