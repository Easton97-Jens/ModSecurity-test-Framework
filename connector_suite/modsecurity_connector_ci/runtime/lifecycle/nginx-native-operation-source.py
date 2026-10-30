"""Seal original owned native receipts as NOT_EXECUTED canonical input."""
from __future__ import annotations

from modsecurity_test_framework.connector_context import source_path, test_root

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


from modsecurity_connector_ci.lib.runtime_path_utils import fixed_runtime_temp_parent

STORAGE = fixed_runtime_temp_parent() / "codex" / "ModSecurity-conector"
MAX_BYTES = 4 * 1024 * 1024
MODE = "native-nginx-http-module"
SOURCE_RESULT = "source-result.json"
ALIASES = {"phase4_end_of_stream_evaluation": "phase4_marker_split_across_chunks",
           "full_lifecycle_event_metadata_bounded": "phase4_body_over_limit"}


def directory(path, *, external=True):
    """Open absolute authority without following any directory symlink."""
    path = Path(path)
    if (not path.is_absolute() or ".." in path.parts
            or (external and STORAGE not in path.parents)):
        raise ValueError("native authority must be an absolute external storage child")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ValueError("native authority must be owned and nonwritable by others")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_owned(root, relative, maximum=MAX_BYTES):
    if (not isinstance(relative, str) or not relative or relative.startswith("/")
            or any(part in ("", ".", "..") for part in relative.split("/"))):
        raise ValueError("receipt must use a closed relative leaf path")
    descriptor = directory(root)
    try:
        parts = relative.split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            metadata = os.fstat(descriptor)
            if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
                raise ValueError("receipt directory is not owned and safe")
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(leaf, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                    or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) & 0o077
                    or metadata.st_size > maximum):
                raise ValueError("receipt must be bounded, owner-only, regular, single-link")
            raw = stream.read(maximum + 1)
            if len(raw) > maximum:
                raise ValueError("receipt grew beyond the bound")
            return raw
    finally:
        os.close(descriptor)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate source JSON key")
        result[key] = value
    return result


def invalid_json_number(_value):
    raise ValueError("invalid JSON number")


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_object,
                      parse_constant=invalid_json_number)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def source_hashes(paths, parent_root, framework_root):
    """Caller supplies the Framework reader's closed source-path whitelist."""
    roots = {"parent": Path(parent_root), "framework": Path(framework_root)}
    hashes = {}
    for name in sorted(paths):
        namespace, separator, relative = name.partition(":")
        if (not separator or namespace not in roots or relative.startswith("/")
                or any(part in ("", ".", "..") for part in relative.split("/"))):
            raise ValueError("source must use a closed namespaced relative path")
        # Preserve admission of the original supplied namespace before remapping.
        os.close(directory(roots[namespace], external=False))
        selected_parent = os.environ.get("CONNECTOR_ROOT")
        if (namespace == "parent" and selected_parent
                and roots["parent"].resolve() == Path(selected_parent).resolve()
                and roots["framework"] != test_root()):
            raise ValueError("reviewed source requires the explicit selected Framework root")
        path = (source_path(relative, root=roots["parent"]) if namespace == "parent"
                else roots["framework"] / relative)
        if not any(path.is_relative_to(root) for root in roots.values()):
            raise ValueError("reviewed source must stay inside explicit Parent/Framework roots")
        authority = (roots["framework"] if path.is_relative_to(roots["framework"])
                     else roots["parent"])
        parts = path.relative_to(authority).parts
        descriptor = directory(authority, external=False)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                metadata = os.fstat(descriptor)
                if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
                    raise ValueError("source directory must be owned and nonwritable by others")
            leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
            with os.fdopen(leaf, "rb") as stream:
                metadata = os.fstat(stream.fileno())
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_BYTES
                        or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o022):
                    raise ValueError("source must be bounded owned nonwritable regular file")
                raw = stream.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    raise ValueError("source exceeds hash bound")
                hashes[name] = digest(raw)
        finally:
            os.close(descriptor)
    return hashes


def receipt_identity(raw, case_id, run_id, operation, identities):
    value = decode(raw)
    if not isinstance(value, dict):
        raise ValueError("original receipt must be a JSON object")
    if operation in {"request_sequence", "common_mapper_input_fault"}:
        rows = value.get("cases")
        if not isinstance(rows, list) or len(rows) != 1:
            raise ValueError("closed source must contain exactly one case")
        row = rows[0]
        if not isinstance(row, dict):
            raise ValueError("original source row must be an object")
        if any(row.get(key) != wanted for key, wanted in
               {"case_id": case_id, "run_id": run_id, "operation": operation}.items()):
            raise ValueError("original source row identity mismatch")
        value = row.get("sequence_receipt" if operation == "request_sequence" else "input_fault_receipt", {})
    if not isinstance(value, dict):
        raise ValueError("original native receipt must be an object")
    expected = dict(case_id=case_id, run_id=run_id, operation=operation,
                    **{key: identities[key] for key in ("parent_sha", "framework_sha", "mrts_sha")})
    if any(value.get(key) != wanted for key, wanted in expected.items()):
        raise ValueError("original receipt identity mismatch")
    return value


def validate_source_identity(case_id, run_id, identities, driver_exit_code, source_sha256):
    if (not re.fullmatch(r"[a-z][a-z0-9_]{0,127}", case_id)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,96}", run_id)
            or type(driver_exit_code) is not int):
        raise ValueError("invalid source identity or actual driver exit")
    if any(not re.fullmatch(r"[0-9a-f]{40}", identities.get(key, ""))
           for key in ("parent_sha", "framework_sha", "mrts_sha")):
        raise ValueError("source identities require exact Git SHAs")
    if (not isinstance(source_sha256, dict) or not source_sha256
            or any(not re.fullmatch(r"(?:parent|framework):[A-Za-z0-9_./-]+", name)
                   or any(part in ("", ".", "..") for part in name.partition(":")[2].split("/"))
                   or not re.fullmatch(r"[0-9a-f]{64}", value)
                   for name, value in source_sha256.items())):
        raise ValueError("actual namespaced source SHA seals required")


def event_source_paths(root, case_id, run_id, operation, identities, wrapper):
    parent_raw = read_owned(root, SOURCE_RESULT)
    parent = receipt_identity(parent_raw, case_id, run_id, operation, identities)
    variants = ("at255", "over256") if case_id == "event_json_limit" else ("long-query",)
    if case_id not in {"event_json_limit", "event_metadata_truncation"}:
        raise ValueError("unknown event boundary case")
    children = parent.get("children", [])
    if not isinstance(children, list) or any(not isinstance(child, dict) for child in children):
        raise ValueError("event parent children must be a bounded object list")
    if [child.get("variant") for child in children] != list(variants):
        raise ValueError("event parent does not seal exact variants")
    wrapper.update(parent_receipt_path=SOURCE_RESULT, parent_receipt_sha256=digest(parent_raw))
    names = {"at255": "at", "over256": "over", "long-query": "main"}
    paths = [(names[variant], variant + "/" + SOURCE_RESULT, run_id + "-" + variant) for variant in variants]
    return paths, children


def main_source_paths(operation, run_id):
    leaves = {"native_h1_parser_rejection": SOURCE_RESULT,
              "native_phase4_request": SOURCE_RESULT,
              "request_sequence": "sequence-source.json",
              "common_mapper_input_fault": "input-fault-source.json"}
    if operation not in leaves:
        raise ValueError("unknown closed native operation")
    return [("main", leaves[operation], run_id)]


def validate_event_child(child, path, child_run, sealed):
    if (child.get("directory") != path.split("/")[0] or child.get("run_id") != child_run
            or child.get("receipt_sha256") != sealed):
        raise ValueError("event child differs from original parent seal")


def build_source(case_id, run_id, operation, bundle_root, identities, driver_exit_code, *, source_sha256):
    validate_source_identity(case_id, run_id, identities, driver_exit_code, source_sha256)
    root = Path(bundle_root)
    wrapper = {"schema_version": 1, "case_id": case_id, "run_id": run_id, "operation": operation,
               "integration_mode": MODE, "bundle_root": str(root), "invocations": [], "source_sha256": source_sha256}
    if case_id in ALIASES:
        wrapper["source_record_id"] = ALIASES[case_id]
    if operation == "native_event_boundary_request":
        paths, children = event_source_paths(root, case_id, run_id, operation, identities, wrapper)
    else:
        paths = main_source_paths(operation, run_id)
    for index, (name, path, child_run) in enumerate(paths):
        raw = read_owned(root, path)
        receipt_identity(raw, case_id, child_run, operation, identities)
        sealed = digest(raw)
        if operation == "native_event_boundary_request":
            validate_event_child(children[index], path, child_run, sealed)
        wrapper["invocations"].append({"name": name, "receipt_path": path, "receipt_sha256": sealed})
    return dict(case_id=case_id, run_id=run_id, connector="nginx", operation=operation,
                integration_mode=MODE, status="NOT_EXECUTED", canonical_status="NOT_EXECUTED",
                **identities, driver_exit_code=driver_exit_code, native_operation_receipt=wrapper)
