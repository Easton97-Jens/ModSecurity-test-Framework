"""Framework-owned inventory maintenance and preserved legacy fixture proofs.

Product updaters never call this module. Canonical selection maintenance is a
separately reviewed Framework change; pure legacy schemas remain testable with
explicit isolated fixture roots. This is not a product hash-refresh endpoint.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from modsecurity_test_framework.connector_context import test_root, source_path, load_source
import tempfile

ROOT = test_root()
INVENTORY = "config/testing/active-cases.json"
ARCHIVE = "reports/testing/test-selection-archive.generated.json"
COMPANIONS = frozenset((INVENTORY, ARCHIVE))
PROJECT_LOCK = "ci/tooling/project-versions.lock.json"
LANGUAGE_PATHS = {
    "python": frozenset((".python-version", PROJECT_LOCK)),
    "go": frozenset((".go-version", PROJECT_LOCK,
                     "connectors/envoy/ext_proc/go.mod", "connectors/envoy/ext_proc/go.sum")),
}
MAX_BYTES = 16 * 1024 * 1024


class InventoryUpdateError(ValueError):
    """A maintenance change cannot derive the unchanged selection safely."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InventoryUpdateError("duplicate maintenance JSON key")
        result[key] = value
    return result


def _json(raw: bytes):
    if len(raw) > MAX_BYTES:
        raise InventoryUpdateError("maintenance companion exceeds its size limit")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_object)


def _source_records(rows):
    for row in rows:
        sources = row.get("sources") if isinstance(row, dict) else None
        if not isinstance(sources, list) or not sources:
            raise InventoryUpdateError("inventory source bindings must remain nonempty arrays")
        for source in sources:
            _validate_source_record(source)
            yield source


def _validate_source_record(source) -> None:
    if (not isinstance(source, dict) or set(source) != {"path", "sha256"}
            or not isinstance(source["path"], str)
            or not isinstance(source["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", source["sha256"]) is None):
        raise InventoryUpdateError("malformed maintenance source binding")
    _source_path(source["path"])


def _source_path(value) -> None:
    if (not isinstance(value, str) or not value or value.startswith("/") or "\\" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise InventoryUpdateError("maintenance source path must be canonical relative POSIX")


def _shared_reference_paths(row, paths):
    references = row.get("sources") if isinstance(row, dict) else None
    if not isinstance(references, list) or not references:
        raise InventoryUpdateError("inventory shared source references must be nonempty arrays")
    local = set()
    for relative in references:
        _source_path(relative)
        if relative not in paths or relative in local:
            raise InventoryUpdateError("shared maintenance references must be unique known paths")
        local.add(relative)
    return local


def _shared_records(value, rows):
    pool = value["source_bindings"]
    if not isinstance(pool, list) or not pool:
        raise InventoryUpdateError("shared source bindings must be a nonempty array")
    paths = set()
    for source in pool:
        _validate_source_record(source)
        if source["path"] in paths:
            raise InventoryUpdateError("duplicate shared maintenance source path")
        paths.add(source["path"])
    used = set()
    for row in rows:
        used.update(_shared_reference_paths(row, paths))
    if used != paths:
        raise InventoryUpdateError("unused shared maintenance source binding")
    return pool


def _records(value):
    version = value.get("schema_version") if isinstance(value, dict) else None
    schemas = {1: {"schema_version", "executions"},
               2: {"schema_version", "executions", "offline_unit_exceptions"},
               3: {"schema_version", "executions", "offline_unit_exceptions", "source_bindings"}}
    if type(version) is not int or version not in schemas:
        raise InventoryUpdateError("unsupported maintenance inventory schema")
    if set(value) != schemas[version]:
        raise InventoryUpdateError("maintenance requires the closed inventory schema")
    all_rows = []
    for key in ("executions", "offline_unit_exceptions"):
        rows = value.get(key, [])
        if not isinstance(rows, list):
            raise InventoryUpdateError("inventory executions must remain arrays")
        all_rows.extend(rows)
    if version == 3:
        yield from _shared_records(value, all_rows)
    else:
        yield from _source_records(all_rows)


def _encoded(value) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _same(first, second) -> bool:
    # Python considers True == 1. Inventory/control JSON must not do so.
    return json.dumps(first, sort_keys=True, ensure_ascii=False) == json.dumps(second, sort_keys=True, ensure_ascii=False)


def derive_companions(inventory: bytes, archive: bytes, before: dict[str, bytes],
                      after: dict[str, bytes], approved_paths: frozenset[str]) -> dict[str, bytes]:
    """Pure derivation: only supplied approved source SHA slots may change.

    Callers must obtain baseline bytes from prior complete admission or trusted
    Git base objects, and prove after-bytes with the existing updater algorithm.
    No candidate supplies inventory content, paths or selection fields.
    """
    if set(before) != set(after) or not set(before) <= approved_paths:
        raise InventoryUpdateError("maintenance source changes escape their fixed policy")
    if COMPANIONS.intersection(approved_paths):
        raise InventoryUpdateError("derived companions are not primary update inputs")
    old = _json(inventory)
    updated = copy.deepcopy(old)
    old_archive = _json(archive)
    if not isinstance(old_archive, dict) or old_archive.get("inventory_sha256") != digest(inventory):
        raise InventoryUpdateError("pre-update archive does not bind the admitted inventory")
    changes = {path for path in before if before[path] != after[path]}
    for source in _records(updated):
        path = source["path"]
        if path == ARCHIVE:
            raise InventoryUpdateError("digest-bearing archive cannot be an inventory source")
        if path in before and source["sha256"] != digest(before[path]):
            raise InventoryUpdateError("approved source does not match its pre-update inventory binding")
        if path in changes:
            source["sha256"] = digest(after[path])
    # Construction changes only existing SHA values. Preserve original bytes on
    # a no-op, including formatting, rather than creating maintenance churn.
    if updated == old:
        return {INVENTORY: inventory, ARCHIVE: archive}
    inventory_bytes = _encoded(updated)
    new_archive = copy.deepcopy(old_archive)
    new_archive["inventory_sha256"] = digest(inventory_bytes)
    return {INVENTORY: inventory_bytes, ARCHIVE: _encoded(new_archive)}


def verify_companions(inventory: bytes, archive: bytes, before: dict[str, bytes],
                       after: dict[str, bytes], approved_paths: frozenset[str],
                       proposed: dict[str, bytes]) -> None:
    """Pure exact-output proof for publisher and offline regression controls."""
    expected = derive_companions(inventory, archive, before, after, approved_paths)
    if set(proposed) != COMPANIONS or proposed != expected:
        raise InventoryUpdateError("maintenance companions differ from trusted-base derivation")


def read_regular(root: Path, relative: str) -> bytes:
    parts = relative.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts) or relative.startswith("/"):
        raise InventoryUpdateError("maintenance paths must be canonical relative paths")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        child = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(child, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > MAX_BYTES:
                raise InventoryUpdateError("maintenance input must be a bounded single-link regular file")
            return source.read(MAX_BYTES + 1)
    finally:
        os.close(descriptor)


def _admit(root: Path) -> None:
    # Ordinary package import; no candidate-selected module names or search-path edits.
    from .active_test_inventory import load_inventory
    load_inventory(root)


def capture_update(root: Path, approved_paths: frozenset[str]):
    """Capture complete admission before a constrained updater changes bytes.

    Legacy isolated algorithm fixtures have neither companion; they perform no
    inventory mutation. Actual publishers additionally require trusted-base
    companion verification, so absence is never publication authority.
    """
    selected_product = os.environ.get("CONNECTOR_ROOT")
    if selected_product and root.resolve() == Path(selected_product).resolve():
        raise InventoryUpdateError("product checkouts cannot own Framework inventory maintenance")
    if root.resolve() == ROOT:
        raise InventoryUpdateError("canonical schema-4 inventory changes require a separately reviewed Framework change")
    present = [(root / name).exists() or (root / name).is_symlink() for name in COMPANIONS]
    if not any(present):
        return None
    if not all(present):
        raise InventoryUpdateError("maintenance requires both canonical companions")
    _admit(root)
    inventory, archive = read_regular(root, INVENTORY), read_regular(root, ARCHIVE)
    # Verify the archive even if the primary update eventually proves a no-op.
    derive_companions(inventory, archive, {}, {}, approved_paths)
    return {"inventory": inventory, "archive": archive,
            "before": {name: read_regular(root, name) for name in approved_paths},
            "approved": approved_paths}


def _check_other_bindings(root: Path, inventory: bytes, replacements: dict[str, bytes]) -> None:
    for source in _records(_json(inventory)):
        path = source["path"]
        actual = replacements[path] if path in replacements else read_regular(root, path)
        if digest(actual) != source["sha256"]:
            raise InventoryUpdateError("unapproved or concurrent inventory source drift: " + path)


def planned_companions(root: Path, snapshot, proposed: dict[str, bytes]) -> dict[str, bytes]:
    if snapshot is None:
        return {}
    if not set(proposed) <= snapshot["approved"]:
        raise InventoryUpdateError("proposed update escapes captured approved source paths")
    if (read_regular(root, INVENTORY) != snapshot["inventory"]
            or read_regular(root, ARCHIVE) != snapshot["archive"]):
        raise InventoryUpdateError("maintenance companions changed during update")
    after = dict(snapshot["before"])
    after.update(proposed)
    # Primary changes may already have been written by Actions. All other
    # bound sources still require the captured digest before companion writes.
    _check_other_bindings(root, snapshot["inventory"], snapshot["before"])
    return derive_companions(snapshot["inventory"], snapshot["archive"], snapshot["before"], after,
                             snapshot["approved"])


def atomic_write(root: Path, relative: str, before: bytes, after: bytes) -> None:
    if read_regular(root, relative) != before:
        raise InventoryUpdateError("maintenance output changed before replacement")
    path = root / relative
    original = path.lstat()
    descriptor, temporary = tempfile.mkstemp(prefix=".maintenance-", dir=path.parent)
    try:
        os.fchmod(descriptor, stat.S_IMODE(original.st_mode))
        with os.fdopen(descriptor, "wb") as output:
            output.write(after)
            output.flush()
            os.fsync(output.fileno())
        if path.lstat() != original or read_regular(root, relative) != before:
            raise InventoryUpdateError("maintenance output identity changed before replacement")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def finish_update(root: Path, snapshot) -> list[str]:
    if snapshot is None:
        return []
    after = {name: read_regular(root, name) for name in snapshot["approved"]}
    outputs = planned_companions(root, snapshot, after)
    return _write_companions(root, {INVENTORY: snapshot["inventory"], ARCHIVE: snapshot["archive"]}, outputs)


def _write_companions(root: Path, before: dict[str, bytes], outputs: dict[str, bytes]) -> list[str]:
    written = []
    try:
        for name in (INVENTORY, ARCHIVE):
            original = before[name]
            if outputs[name] != original:
                atomic_write(root, name, original, outputs[name])
                written.append((name, original, outputs[name]))
        _admit(root)
    except Exception as error:
        for name, original, generated in reversed(written):
            try:
                if read_regular(root, name) == generated:
                    atomic_write(root, name, generated, original)
            except (OSError, ValueError) as rollback_error:
                error.add_note("maintenance rollback preserved a concurrent replacement: " + str(rollback_error))
        raise
    return [name for name, _, _ in written]



def apply_fixture_update(root: Path, replacements: dict[str, bytes]) -> list[str]:
    """Preserve legacy atomic test-source/inventory proofs in isolated fixtures.

    Canonical Framework and selected product roots are rejected by capture_update;
    no product publisher calls this API and it is not a hash-refresh CLI.
    """
    snapshot = capture_update(root, frozenset(replacements))
    if snapshot is None:
        raise InventoryUpdateError("legacy fixture transaction requires both companions")
    outputs = planned_companions(root, snapshot, replacements)
    archive = _json(outputs[ARCHIVE])
    for row in archive.get("sources", []):
        if not isinstance(row, dict) or row.get("source") not in replacements:
            continue
        name = row["source"]
        if row.get("source_sha256") != digest(snapshot["before"][name]):
            raise InventoryUpdateError("legacy archive source digest differs from its fixture input")
        row["source_sha256"] = digest(replacements[name])
    outputs[ARCHIVE] = _encoded(archive)
    before = dict(snapshot["before"], **{INVENTORY: snapshot["inventory"], ARCHIVE: snapshot["archive"]})
    outputs = dict(replacements, **outputs)
    written = []
    try:
        for name, after in outputs.items():
            if before[name] != after:
                atomic_write(root, name, before[name], after)
                written.append((name, before[name], after))
        _admit(root)
    except Exception as error:
        for name, original, generated in reversed(written):
            try:
                if read_regular(root, name) == generated:
                    atomic_write(root, name, generated, original)
            except (OSError, ValueError) as rollback_error:
                error.add_note("fixture rollback preserved a concurrent replacement: " + str(rollback_error))
        raise
    return [name for name, _, _ in written]

def _git(root: Path, *arguments: str) -> bytes:
    return subprocess.check_output(["git", "--no-replace-objects", "-C", str(root), *arguments], timeout=30)


def trusted_blob(root: Path, revision: str, relative: str) -> bytes:
    if (re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,199}", revision) is None or ".." in revision
            or relative.startswith("/") or any(part in {"", ".", ".."} for part in relative.split("/"))):
        raise InventoryUpdateError("unsafe maintenance Git object reference")
    row = _git(root, "ls-tree", "-z", revision, "--", relative).split(b"\0")
    if len(row) != 2 or not row[0].startswith(b"100644 blob ") or row[0].split(b"\t", 1)[-1].decode() != relative:
        raise InventoryUpdateError("maintenance baseline must contain a fixed regular source blob")
    return _git(root, "show", "--no-textconv", "--format=", "--end-of-options", revision + ":" + relative)


def index_blob(root: Path, relative: str) -> bytes:
    if relative not in COMPANIONS | LANGUAGE_PATHS["python"] | LANGUAGE_PATHS["go"]:
        raise InventoryUpdateError("index path escapes fixed maintenance policy")
    rows = _git(root, "ls-files", "--stage", "-z", "--", relative).split(b"\0")
    if len(rows) != 2 or not rows[0].startswith(b"100644 ") or b" 0\t" not in rows[0]:
        raise InventoryUpdateError("staged maintenance input must be one regular stage-zero blob")
    return _git(root, "show", "--no-textconv", ":" + relative)


def _go_triplet(value: object) -> tuple[int, int, int]:
    """Legacy fixture proof delegates to the fixed product-primary grammar."""
    module = load_source(source_path("ci/lib/maintenance_changes.py"))
    try:
        return module._go_triplet(value)
    except ValueError as error:
        raise InventoryUpdateError(str(error)) from error


def _go_component_policy(before: dict[str, bytes], after: dict[str, bytes]) -> None:
    module = load_source(source_path("ci/lib/maintenance_changes.py"))
    try:
        module._go_component_policy(before, after)
    except ValueError as error:
        raise InventoryUpdateError(str(error)) from error


def _language_policy(kind: str, before: dict[str, bytes], after: dict[str, bytes]) -> None:
    old, new = _json(before[PROJECT_LOCK]), _json(after[PROJECT_LOCK])
    field = kind + "_version"
    if set(old) != set(new) or any(not _same(old[key], new[key]) for key in old if key != field):
        raise InventoryUpdateError("maintenance changed another central version-lock field")
    for values, bodies in ((old, before), (new, after)):
        if bodies["." + kind + "-version"] != (str(values[field]) + "\n").encode():
            raise InventoryUpdateError("maintenance version view differs from its central lock")
    if kind == "python":
        pattern = r"3\.15\.(0|[1-9]\d*)"
        first, second = re.fullmatch(pattern, str(old[field]), re.ASCII), re.fullmatch(pattern, str(new[field]), re.ASCII)
        if not first or not second or int(second[1]) < int(first[1]):
            raise InventoryUpdateError("maintenance Python version is noncanonical or nonmonotonic")
    elif _go_triplet(new[field]) < _go_triplet(old[field]):
        raise InventoryUpdateError("maintenance Go version is nonmonotonic")
    if kind == "go":
        _go_component_policy(before, after)


def language_companions(root: Path, base: str, kind: str, head: str | None = None,
                        *, staged: bool = False) -> dict[str, bytes]:
    approved = LANGUAGE_PATHS[kind]
    before = {name: trusted_blob(root, base, name) for name in approved}
    after = {name: (trusted_blob(root, head, name) if head else
                    index_blob(root, name) if staged else read_regular(root, name)) for name in approved}
    _language_policy(kind, before, after)
    return derive_companions(trusted_blob(root, base, INVENTORY), trusted_blob(root, base, ARCHIVE),
                             before, after, approved)


def _finalize_companions(root: Path, base: str, kind: str, current: dict[str, bytes],
                         outputs: dict[str, bytes]) -> None:
    baseline = trusted_blob(root, base, INVENTORY)
    old, actual = _json(baseline), _json(current[INVENTORY])
    expected = _json(outputs[INVENTORY])
    # Only intermediate baseline/final source SHA values of approved
    # paths are acceptable; all selection/data fields remain exact.
    old_sources, actual_sources, new_sources = list(_records(old)), list(_records(actual)), list(_records(expected))
    if len(old_sources) != len(actual_sources):
        raise InventoryUpdateError("maintenance altered source binding membership")
    for previous, observed, generated in zip(old_sources, actual_sources, new_sources):
        if observed["path"] == previous["path"] and observed["path"] in LANGUAGE_PATHS[kind]:
            if observed["sha256"] not in {previous["sha256"], generated["sha256"]}:
                raise InventoryUpdateError("unexpected intermediate maintenance source digest")
            observed["sha256"] = previous["sha256"]
    if not _same(actual, old):
        raise InventoryUpdateError("maintenance changed immutable inventory fields")
    archive = _json(current[ARCHIVE])
    baseline_archive = _json(trusted_blob(root, base, ARCHIVE))
    if archive.get("inventory_sha256") != digest(current[INVENTORY]):
        raise InventoryUpdateError("intermediate archive digest is not exact")
    archive["inventory_sha256"] = baseline_archive["inventory_sha256"]
    if not _same(archive, baseline_archive):
        raise InventoryUpdateError("maintenance changed archive fields")
    _check_other_bindings(root, outputs[INVENTORY], {})
    _write_companions(root, current, outputs)


def _cli_root(value: str | Path) -> Path:
    """Confine CLI operations to this source tree; library roots stay explicit."""
    text = os.fspath(value)
    if text != str(ROOT) or Path(text).resolve(strict=True) != ROOT:
        raise InventoryUpdateError("maintenance CLI root must be exactly its canonical source repository")
    return ROOT


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("command", choices=("verify", "finalize"))
    parser.add_argument("--kind", required=True, choices=tuple(LANGUAGE_PATHS))
    parser.add_argument("--base", required=True)
    parser.add_argument("--head")
    parser.add_argument("--staged", action="store_true")
    parser.add_argument("--root", default=str(ROOT))
    args = parser.parse_args(argv)
    try:
        root = _cli_root(args.root)
        if args.head and args.staged:
            raise InventoryUpdateError("staged verification cannot select a branch head")
        if args.command == "finalize" and (args.head or args.staged):
            raise InventoryUpdateError("finalization cannot mutate a Git object")
        outputs = language_companions(root, args.base, args.kind, args.head, staged=args.staged)
        current = {name: (trusted_blob(root, args.head, name) if args.head else
                          index_blob(root, name) if args.staged else read_regular(root, name))
                   for name in COMPANIONS}
        if args.command == "finalize":
            _finalize_companions(root, args.base, args.kind, current, outputs)
        elif current != outputs:
            raise InventoryUpdateError("maintenance companions differ from trusted-base derivation")
        elif not args.head and not args.staged:
            _admit(root)
        print("MAINTENANCE_COMPANIONS_VERIFIED")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("MAINTENANCE_COMPANIONS_REJECTED: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
