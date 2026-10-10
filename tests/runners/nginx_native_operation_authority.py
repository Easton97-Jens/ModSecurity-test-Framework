"""Load explicit native authority; never infer it from operation receipts.

Root selects the file and expected tuple, checks Git/build authority and retains
original bytes. This read-only seam checks the closed local manifest boundary.
"""
from collections.abc import Mapping
import os
from pathlib import Path
from types import MappingProxyType

from tests.runners import nginx_native_operation_bundle as bundle

AUTHORITY_LIMIT = 16384
EXPECTED_FIELDS = frozenset({"run_id", "parent_sha", "framework_sha", "mrts_sha"})
ROOT_FIELDS = frozenset({"artifact_root", "parent_root", "framework_root"})
FIELDS = EXPECTED_FIELDS | ROOT_FIELDS | {"schema_version", "connector", "binary_sha256", "module_sha256", "fault_library_sha256"}
FAULT_CASES = bundle.INPUT_CASES | set(bundle.FAULT_SOURCES)


def freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    return value


def validate_expected(expected):
    bundle.require(isinstance(expected, dict) and set(expected) == EXPECTED_FIELDS, "explicit exact four-field authority tuple required")
    bundle.require(isinstance(expected["run_id"], str) and bundle.RUN_ID.fullmatch(expected["run_id"]), "bounded authority run required")
    for field in EXPECTED_FIELDS - {"run_id"}:
        bundle.require(isinstance(expected[field], str) and bundle.SHA40.fullmatch(expected[field]), "exact authority revision required: " + field)


def absolute_path(value):
    bundle.require(isinstance(value, str) and 0 < len(value) <= 4096
                   and not any(ord(character) < 32 or ord(character) == 127 for character in value), "bounded explicit authority path required")
    path = Path(value)
    bundle.require(path.is_absolute() and not value.startswith("//") and path != Path("/") and ".." not in path.parts
                   and str(path) == value, "canonical explicit absolute authority path required")
    return path


def validate_document(document, expected):
    validate_expected(expected)
    bundle.require(isinstance(document, dict) and set(document) == FIELDS, "closed native authority fields required")
    bundle.exact(document, {"schema_version": 1, "connector": "nginx", **expected}, "native authority identity")
    for field in ("binary_sha256", "module_sha256"):
        bundle.require(isinstance(document[field], str) and bundle.SHA256.fullmatch(document[field]), "explicit compiled artifact digest required: " + field)
    faults = document["fault_library_sha256"]
    bundle.require(isinstance(faults, dict) and set(faults) <= FAULT_CASES
                   and all(isinstance(value, str) and bundle.SHA256.fullmatch(value) for value in faults.values()), "closed compiled fault digest map required")
    return {field: absolute_path(document[field]) for field in ROOT_FIELDS}


def directory_identity(path):
    descriptor = bundle.open_directory(path)
    try:
        metadata = os.fstat(descriptor)
        bundle.require(metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o022, "owned non-group/world-writable authority directory required")
        return metadata.st_dev, metadata.st_ino
    finally:
        os.close(descriptor)


def validate_roots(roots):
    identities = {field: directory_identity(path) for field, path in roots.items()}
    bundle.require(len(set(identities.values())) == 3, "distinct existing artifact and source roots required")
    artifact = roots["artifact_root"]
    for field in ("parent_root", "framework_root"):
        source = roots[field]
        bundle.require(artifact != source and artifact not in source.parents and source not in artifact.parents,
                       "authority artifacts must not overlap source checkouts")
    # Framework may legitimately be nested beneath Parent. Git ownership,
    # cleanliness and Gitlink checks belong to the explicit Parent coordinator.


def load_native_operation_authority(path, expected):
    """Return immutable authority and exact retained original bytes, or ValueError.

    Pass ``dict(result['sources'])`` to a reader requiring a concrete dict. Fault
    maps remain read-only; none of this context is derived from a receipt.
    """
    try:
        validate_expected(expected)
        original_path = absolute_path(str(path)) if isinstance(path, Path) else absolute_path(path)
        raw = bundle.read_bounded_file(original_path.parent, original_path.name, AUTHORITY_LIMIT)
        document = bundle.json_object(raw)
        roots = validate_document(document, expected)
        validate_roots(roots)
        sources = {field: document[field] for field in EXPECTED_FIELDS - {"run_id"}}
        sources.update({"parent_root": roots["parent_root"], "framework_root": roots["framework_root"],
                        "binary_sha256": document["binary_sha256"], "module_sha256": document["module_sha256"],
                        "fault_library_sha256": document["fault_library_sha256"]})
        return freeze({**document, **roots, "sources": sources, "authority_path": original_path,
                       "authority_sha256": bundle.digest(raw), "authority_bytes": raw})
    except (OSError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError) as exc:
        raise ValueError("invalid native operation authority: " + str(exc)) from exc


def serialized_mapping(loaded):
    """Return fresh plain schema1 metadata, NOT original retention bytes or writes.

    Retain authority_bytes unchanged under authority_sha256; serialization is
    merely a caller-facing mapping, not a replacement seal or new authority.
    """
    try:
        bundle.require(isinstance(loaded, Mapping), "loaded native authority required")
        raw = loaded["authority_bytes"]
        bundle.require(isinstance(raw, bytes) and len(raw) <= AUTHORITY_LIMIT
                       and bundle.digest(raw) == loaded["authority_sha256"], "original authority byte seal mismatch")
        document = bundle.json_object(raw)
        expected = {field: loaded[field] for field in EXPECTED_FIELDS}
        roots = validate_document(document, expected)
        for field, path in roots.items():
            bundle.require(loaded[field] == path, "loaded authority root differs from original bytes")
        for field in FIELDS - ROOT_FIELDS:
            bundle.require(loaded[field] == document[field], "loaded authority metadata differs from original bytes")
        return document
    except (TypeError, KeyError, AttributeError, UnicodeError, RecursionError) as exc:
        raise ValueError("invalid serialized native authority: " + str(exc)) from exc
