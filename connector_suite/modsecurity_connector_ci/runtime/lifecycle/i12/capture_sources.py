#!/usr/bin/env python3
"""Materialize exact test capture sources in an explicitly disposable copy only."""
from modsecurity_test_framework.connector_context import connector_root, source_path
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat

HERE = Path(__file__).resolve().parent
REPOSITORY = connector_root()
MARKER = ".i12-disposable-source-copy.json"
SNAPSHOT = ".i12-source-export-manifest.json"
RECEIPT = "i12-source-application-receipt.json"
CAPTURE_DIRECTORY = ".i12-capture"
SOURCE_SUFFIXES = frozenset((".py", ".c", ".cc", ".cpp", ".h", ".hpp", ".go", ".sh"))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def relative(value):
    path = Path(value)
    if (not value or path.is_absolute() or any(part in ("", ".", "..", ".git") for part in value.split("/"))
            or "\\" in value):
        raise ValueError("Expected a bounded relative source path")
    return path


def plain(path):
    if path.resolve(strict=True) != path or not path.is_file():
        raise ValueError("Expected physical regular source file: " + str(path))
    info = path.stat()
    if info.st_nlink != 1:
        raise ValueError("Hard-linked source/evidence files are forbidden")
    if info.st_size > 2 * 1024 * 1024:
        raise ValueError("Only bounded text source is permitted")
    data = path.read_bytes()
    if len(data) > 2 * 1024 * 1024 or b"\0" in data:
        raise ValueError("Only bounded text source is permitted")
    data.decode("utf-8")
    return data


def _hunk_header(row):
    match = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\n", row)
    if match is None:
        raise ValueError("Invalid payload hunk")
    start, old_count = int(match[1]), int(match[2] or 1)
    new_start, new_count = int(match[3]), int(match[4] or 1)
    return (start - 1 if old_count else start), old_count, new_start, new_count


def _hunk_body(rows, index, source, cursor, output):
    old_seen, new_seen = 0, 0
    while index < len(rows) and not rows[index].startswith("@@ "):
        row = rows[index]
        if not row or row[0] not in " +-":
            raise ValueError("Invalid payload hunk line")
        if row[0] in " -":
            if cursor >= len(source) or source[cursor] != row[1:]:
                raise ValueError("Payload context/base bytes differ")
            cursor += 1
            old_seen += 1
        if row[0] in " +":
            output.append(row[1:])
            new_seen += 1
        index += 1
    return index, cursor, old_seen, new_seen


def exact_patch(original, patch):
    """Apply a single-file unified diff without fuzz, execution or path selection."""
    rows = patch.decode("utf-8").splitlines(keepends=True)
    if rows[:2] != ["--- a/payload\n", "+++ b/payload\n"]:
        raise ValueError("Only the exact payload delta format is permitted")
    source = original.decode("utf-8").splitlines(keepends=True)
    output, cursor, index = [], 0, 2
    while index < len(rows):
        start, old_count, new_start, new_count = _hunk_header(rows[index])
        if start < cursor or start > len(source):
            raise ValueError("Overlapping or out-of-range payload hunk")
        output.extend(source[cursor:start])
        if new_start != len(output) + (1 if new_count else 0):
            raise ValueError("Unexpected new payload offset")
        index, cursor, old_seen, new_seen = _hunk_body(rows, index + 1, source, start, output)
        if (old_seen, new_seen) != (old_count, new_count):
            raise ValueError("Payload hunk lengths differ")
    output.extend(source[cursor:])
    return "".join(output).encode()


class Registry:
    def __init__(self, root=HERE, repository=REPOSITORY):
        self.root, self.repository = root, repository
        self.manifest = json.loads(plain(root / "manifest.json"))
        self.cache = {}

    def _text_content(self, item, kind):
        path = relative(item["file"])
        if kind == "text":
            if path.suffix.lower() in SOURCE_SUFFIXES:
                raise ValueError("Archived source must use inert lossless text-line data")
            return plain(self.root / path)
        if path.suffix != ".json":
            raise ValueError("Lossless source-line storage requires a JSON data file")
        rows = json.loads(plain(self.root / path))
        if not isinstance(rows, list) or any(not isinstance(row, str) for row in rows):
            raise ValueError("Invalid lossless text-line object")
        return "".join(rows).encode("utf-8")

    def content(self, identity, trail=()):
        if identity in trail:
            raise ValueError("Cyclic source delta")
        if identity in self.cache:
            return self.cache[identity]
        item = self.manifest["objects"][identity]
        kind = item["kind"]
        if kind == "repository":
            logical = relative(item["path"])
            path = (source_path(logical, root=self.repository)
                    if self.repository == connector_root() else self.repository / logical)
            result = plain(path)
        elif kind in ("text", "text_lines"):
            result = self._text_content(item, kind)
        elif kind == "delta":
            patch = plain(self.root / relative(item["patch"]))
            if digest(patch) != item["patch_sha256"]:
                raise ValueError("Source delta hash mismatch")
            result = exact_patch(self.content(item["base"], (*trail, identity)), patch)
        else:
            raise ValueError("Unknown source object kind")
        if digest(result) != identity:
            raise ValueError("Source byte hash mismatch: " + identity)
        self.cache[identity] = result
        return result

    def verify(self):
        for identity in self.manifest["objects"]:
            self.content(identity)
        for profile in self.manifest["profiles"].values():
            if ("required_source_identity_format" in profile and profile["required_source_identity_format"] not in
                    ("i12-disposable-source-copy-v1", "i12-disposable-source-copy-v2")):
                raise ValueError("Unknown required source identity format")
            for mapping in (profile["source_targets"], profile["capture_files"]):
                for name, entry in mapping.items():
                    relative(name)
                    self.content(entry["sha256"])
        return {"objects": len(self.cache), "profiles": len(self.manifest["profiles"]),
                "source_only": True, "runtime_qualified": False}


def _unique_fields(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate identity/inventory field")
        result[name] = value
    return result


def _keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("Unexpected identity/inventory schema")


def _hex(value, length):
    if not isinstance(value, str) or re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is None:
        raise ValueError("Expected complete lowercase revision/hash")
    return value


def _export_file(name, entry):
    path = relative(name)
    if name in (MARKER, SNAPSHOT, RECEIPT) or CAPTURE_DIRECTORY in path.parts:
        raise ValueError("Export inventory contains capture metadata")
    _keys(entry, ("mode", "sha256"))
    if type(entry["mode"]) is not int or entry["mode"] not in (420, 493):
        raise ValueError("Expected exact Git regular-file mode")
    _hex(entry["sha256"], 64)
    return path


def _export_gitlink(name, revision, gitlinks, files, directories):
    path = relative(name)
    _hex(revision, 40)
    if (name in (MARKER, SNAPSHOT, RECEIPT) or CAPTURE_DIRECTORY in path.parts or
            any(str(parent) in gitlinks for parent in path.parents)):
        raise ValueError("Invalid or nested Gitlink metadata")
    if name in files or name in directories:
        raise ValueError("Gitlink contents or file collision in source inventory")
    return path


def _snapshot_entries(snapshot):
    files, gitlinks = snapshot["files"], snapshot["gitlinks"]
    if not isinstance(files, dict) or not files or not isinstance(gitlinks, dict):
        raise ValueError("Expected complete nonempty source-file inventory")
    directories = set()
    for name, entry in files.items():
        path = _export_file(name, entry)
        directories.update(str(parent) for parent in path.parents if str(parent) != ".")
    for name, revision in gitlinks.items():
        path = _export_gitlink(name, revision, gitlinks, files, directories)
        directories.add(name)
        directories.update(str(parent) for parent in path.parents if str(parent) != ".")
    if any(name in files for name in directories):
        raise ValueError("Inventory file/directory collision")
    return files, directories


def _file_hash(path, expected):
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("Source inventory requires physical unlinked regular files")
    if stat.S_IMODE(info.st_mode) != expected["mode"]:
        raise ValueError("Export source mode differs: " + str(path))
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
    after = path.stat(follow_symlinks=False)
    if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError("Source inventory changed during validation")
    if result.hexdigest() != expected["sha256"]:
        raise ValueError("Export source hash differs: " + str(path))


def _verify_snapshot_files(path, files, directories):
    seen = set()
    for child in path.rglob("*"):
        name = str(child.relative_to(path))
        info = child.stat(follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            if name not in directories:
                raise ValueError("Unexpected export directory: " + name)
        elif name in (MARKER, SNAPSHOT):
            plain(child)
        elif name in files:
            _file_hash(child, files[name])
            seen.add(name)
        else:
            raise ValueError("Unexpected export object: " + name)
    if seen != set(files):
        raise ValueError("Missing exported source files")


def _snapshot_identity(path, marker_bytes):
    marker = json.loads(marker_bytes, object_pairs_hook=_unique_fields)
    _keys(marker, ("format", "path", "disposable", "source_revision",
                   "snapshot_manifest", "snapshot_manifest_sha256"))
    if marker["path"] != str(path) or marker["disposable"] is not True or marker["snapshot_manifest"] != SNAPSHOT:
        raise ValueError("Explicit current disposable source identity differs")
    revision = _hex(marker["source_revision"], 40)
    identity = _hex(marker["snapshot_manifest_sha256"], 64)
    data = plain(path / SNAPSHOT)
    if digest(data) != identity:
        raise ValueError("Frozen export inventory hash differs")
    snapshot = json.loads(data, object_pairs_hook=_unique_fields)
    _keys(snapshot, ("format", "source_revision", "git_tree", "files", "gitlinks"))
    if snapshot["format"] != "i12-source-export-manifest-v1" or snapshot["source_revision"] != revision:
        raise ValueError("Export revision/schema differs from marker")
    tree = _hex(snapshot["git_tree"], 40)
    files, directories = _snapshot_entries(snapshot)
    _verify_snapshot_files(path, files, directories)
    return {"source_revision": revision, "source_git_tree": tree,
            "snapshot_manifest": SNAPSHOT, "snapshot_manifest_sha256": identity,
            "snapshot_file_count": len(files), "snapshot_gitlinks": snapshot["gitlinks"],
            "source_identity_format": marker["format"]}


def disposable(path, parent_sha, storage_root):
    if not path.is_absolute() or path.resolve(strict=True) != path or not path.is_dir():
        raise ValueError("Source copy must be a physical absolute directory")
    if storage_root not in path.parents:
        raise ValueError("Source copy must be below the declared external storage root")
    # The storage control plane may itself have Git metadata. Only its declared
    # external subtree is authorized; a checkout nested within it is forbidden.
    for ancestor in (path, *path.parents):
        if ancestor == storage_root:
            break
        if (ancestor / ".git").exists():
            raise ValueError("Git checkout/metadata is forbidden")
    for child in path.rglob("*"):
        if child.name == ".git" or child.is_symlink():
            raise ValueError("Git metadata or symlink inside source copy")
    marker_bytes = plain(path / MARKER)
    marker = json.loads(marker_bytes)
    if isinstance(marker, dict) and marker.get("format") == "i12-disposable-source-copy-v2":
        return _snapshot_identity(path, marker_bytes)
    if marker != {"format": "i12-disposable-source-copy-v1", "path": str(path),
                  "disposable": True, "parent_sha": parent_sha}:
        raise ValueError("Explicit disposable source-copy identity is missing or differs")
    return {"source_revision": parent_sha, "source_identity_format": marker["format"]}


def _source_writes(registry, profile, target, identity):
    writes = []
    applied_bases = {}
    for name, entry in profile["source_targets"].items():
        path = target / relative(name)
        expected = entry["before_sha256"]
        actual = digest(plain(path)) if path.exists() else None
        allowed = [expected]
        if "current_before_sha256" in entry:
            current = _hex(entry["current_before_sha256"], 64)
            if identity["source_identity_format"] == "i12-disposable-source-copy-v2":
                allowed.append(current)
        if actual not in allowed or (expected is not None and actual is None):
            raise ValueError("Source-copy base differs: " + name)
        applied_bases[name] = actual
        writes.append((path, registry.content(entry["sha256"]), entry.get("mode", 420)))
    return writes, applied_bases


def _capture_writes(registry, profile, target, profile_name):
    fixture_root = target / CAPTURE_DIRECTORY / profile_name
    if fixture_root.exists():
        raise ValueError("Capture destination already exists")
    return [(fixture_root / relative(name), registry.content(entry["sha256"]), entry.get("mode", 420))
            for name, entry in profile["capture_files"].items()]


def _validate_writes(writes, target):
    # Validate the entire plan before any write; parent components were checked above.
    for path, data, mode in writes:
        if not path.is_relative_to(target) or mode not in (420, 493):
            raise ValueError("Invalid source-copy write")
        for parent in path.parents:
            if parent == target:
                break
            if parent.exists() and not parent.is_dir():
                raise ValueError("Source-copy parent is not a directory")


def apply(registry, profile_name, target):
    profile = registry.manifest["profiles"][profile_name]
    identity = disposable(target, registry.manifest["delivery_product_baseline"], Path(registry.manifest["authorized_storage_root"]))
    required_format = profile.get("required_source_identity_format")
    if required_format is not None and identity["source_identity_format"] != required_format:
        raise ValueError("Selected profile requires its declared source identity format")
    receipt_path = target / RECEIPT
    if receipt_path.exists():
        raise ValueError("Source application receipt already exists")
    registry.verify()
    writes, applied_bases = _source_writes(registry, profile, target, identity)
    writes.extend(_capture_writes(registry, profile, target, profile_name))
    _validate_writes(writes, target)
    for path, data, mode in writes:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
    receipt = {**identity, "delivery_product_baseline": registry.manifest["delivery_product_baseline"],
               "profile": profile_name, "source_copy": str(target),
               "capture_manifest_sha256": digest(plain(registry.root / "manifest.json")),
               "actual_before_sha256": applied_bases,
               "exact_written_sha256": {str(p.relative_to(target)): digest(data) for p, data, _ in writes},
               "source_copy_only": True, "runtime_qualified": False}
    with receipt_path.open("x", encoding="utf-8") as output:
        output.write(json.dumps(receipt, indent=2) + "\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("verify", "apply"))
    parser.add_argument("--profile")
    parser.add_argument("--source-copy", type=Path)
    args = parser.parse_args()
    try:
        registry = Registry()
        if args.action == "verify":
            result = registry.verify()
        elif args.profile is None or args.source_copy is None:
            raise ValueError("apply needs --profile and --source-copy")
        else:
            result = apply(registry, args.profile, args.source_copy)
        print(json.dumps(result, sort_keys=True))
    except (ValueError, KeyError, OSError, TypeError) as exc:
        parser.exit(2, "Capture source rejected: " + str(exc) + "\n")


if __name__ == "__main__":
    main()
