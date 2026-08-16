#!/usr/bin/env python3
"""Synchronize the reviewed Python CI pins into their committed views.

The values in ``ci/lib/common.sh`` are the only manually maintained source.
This tool deliberately parses a tiny assignment grammar instead of sourcing a
shell file, so checking a checkout cannot execute repository code or discover
anything over the network.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


PIN_NAMES = (
    "CI_CANONICAL_PYTHON_VERSION",
    "CI_CANONICAL_PYYAML_VERSION",
    "CI_CANONICAL_PYYAML_SHA256",
)
ASSIGNMENT = re.compile(
    r"^\s*(?P<name>CI_CANONICAL_(?:PYTHON_VERSION|PYYAML_VERSION|PYYAML_SHA256))"
    r"\s*=\s*(?:\"(?P<double>[^\"\n]*)\"|'(?P<single>[^'\n]*)'|"
    r"(?P<bare>[^\s#]+))\s*(?:#.*)?$"
)
VERSION = re.compile(r"\A\d+\.\d+\.\d+\Z", flags=re.ASCII)
SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
PYTHON_VIEW = re.compile(r"\A(?P<value>\d+\.\d+\.\d+)\n\Z", flags=re.ASCII)
PYAML_VERSION_LINE = re.compile(
    r"\A(?P<prefix>\s*PyYAML==)(?P<value>[^\s\\]+)(?P<suffix>\s*\\\n)\Z"
)
PYAML_HASH_LINE = re.compile(
    r"\A(?P<prefix>\s*--hash=sha256:)(?P<value>[0-9A-Fa-f]+)(?P<suffix>\s*\n)\Z"
)


class PinError(ValueError):
    """A fail-closed input or provenance error."""


def lexical_path(path: Path) -> Path:
    """Normalize lexical path segments without resolving repository-controlled links."""
    return Path(os.path.abspath(path))


def reject_symlink_components(path: Path, label: str) -> None:
    """Reject links in an existing path before any content is read or written."""
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            details = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise PinError(f"{current}: cannot inspect {label}: {exc}") from exc
        if stat.S_ISLNK(details.st_mode):
            raise PinError(f"{current}: {label} may not contain symlink components")


def path_in_root(path: Path, root: Path, label: str) -> Path:
    """Validate lexical containment and reject symlinked path components."""
    candidate = lexical_path(path)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise PinError(f"{candidate}: {label} must remain below {root}") from exc
    reject_symlink_components(candidate, label)
    return candidate


def validate_root(root: Path) -> Path:
    root = lexical_path(root)
    reject_symlink_components(root, "repository root")
    try:
        details = root.lstat()
    except OSError as exc:
        raise PinError(f"{root}: repository root is unavailable: {exc}") from exc
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise PinError(f"{root}: repository root must be a real directory")
    return root


def regular_file(path: Path, label: str) -> None:
    try:
        details = path.lstat()
    except OSError as exc:
        raise PinError(f"{path}: {label} is missing: {exc}") from exc
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        raise PinError(f"{path}: {label} must be a regular non-symlink file")


def read_utf8(path: Path, label: str) -> str:
    regular_file(path, label)
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise PinError(f"{path}: {label} is not readable UTF-8: {exc}") from exc


def canonical_values(common: Path) -> dict[str, str]:
    text = read_utf8(common, "common pin source")
    values: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = ASSIGNMENT.fullmatch(line)
        if match is None:
            continue
        name = match.group("name")
        if name in values:
            raise PinError(f"{common}:{line_number}: duplicate {name}")
        value = next(
            value for value in (match.group("double"), match.group("single"), match.group("bare"))
            if value is not None
        )
        values[name] = value
    missing = [name for name in PIN_NAMES if name not in values]
    if missing:
        raise PinError(f"{common}: missing canonical pin(s): {', '.join(missing)}")
    if not VERSION.fullmatch(values[PIN_NAMES[0]]):
        raise PinError(f"{common}: CI_CANONICAL_PYTHON_VERSION is malformed")
    if not VERSION.fullmatch(values[PIN_NAMES[1]]):
        raise PinError(f"{common}: CI_CANONICAL_PYYAML_VERSION is malformed")
    if not SHA256.fullmatch(values[PIN_NAMES[2]]):
        raise PinError(f"{common}: CI_CANONICAL_PYYAML_SHA256 must be 64 lowercase hex characters")
    return values


def expected_views(root: Path, values: dict[str, str]) -> dict[Path, bytes]:
    python_label = ".python-version"
    requirements_label = "requirements-ci.lock"
    python_path = path_in_root(root / python_label, root, python_label)
    requirements_path = path_in_root(root / requirements_label, root, requirements_label)
    python_text = read_utf8(python_path, python_label)
    if PYTHON_VIEW.fullmatch(python_text) is None:
        raise PinError(f"{python_path}: expected exactly one newline-terminated stable version")
    requirements = read_utf8(requirements_path, requirements_label)
    lines = requirements.splitlines(keepends=True)
    version_indexes = [
        index for index, line in enumerate(lines) if PYAML_VERSION_LINE.fullmatch(line)
    ]
    hash_indexes = [index for index, line in enumerate(lines) if PYAML_HASH_LINE.fullmatch(line)]
    if len(version_indexes) != 1:
        raise PinError(f"{requirements_path}: expected exactly one PyYAML requirement line")
    if len(hash_indexes) != 1:
        raise PinError(f"{requirements_path}: expected exactly one PyYAML SHA-256 line")
    if hash_indexes[0] <= version_indexes[0]:
        raise PinError(f"{requirements_path}: PyYAML hash must follow its requirement")
    version_line = lines[version_indexes[0]]
    hash_line = lines[hash_indexes[0]]
    lines[version_indexes[0]] = (
        PYAML_VERSION_LINE.fullmatch(version_line).group("prefix")
        + values["CI_CANONICAL_PYYAML_VERSION"]
        + PYAML_VERSION_LINE.fullmatch(version_line).group("suffix")
    )
    lines[hash_indexes[0]] = (
        PYAML_HASH_LINE.fullmatch(hash_line).group("prefix")
        + values["CI_CANONICAL_PYYAML_SHA256"]
        + PYAML_HASH_LINE.fullmatch(hash_line).group("suffix")
    )
    return {
        python_path: (values["CI_CANONICAL_PYTHON_VERSION"] + "\n").encode(),
        requirements_path: "".join(lines).encode(),
    }


def atomic_write(path: Path, data: bytes) -> bool:
    regular_file(path, "generated view")
    current = path.read_bytes()
    if current == data:
        return False
    directory = path.parent
    directory_details = directory.lstat()
    if stat.S_ISLNK(directory_details.st_mode) or not stat.S_ISDIR(directory_details.st_mode):
        raise PinError(f"{directory}: target directory must be a real directory")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=directory)
    temporary_path = Path(temporary)
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        return True
    except OSError as exc:
        raise PinError(f"{path}: atomic update failed: {exc}") from exc
    finally:
        temporary_path.unlink(missing_ok=True)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="validate generated views without writing")
    mode.add_argument("--write", action="store_true", help="atomically update generated views")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--common", type=Path, default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        root = validate_root(args.root)
        common = path_in_root(args.common or root / "ci/lib/common.sh", root, "common pin source")
        values = canonical_values(common)
        views = expected_views(root, values)
        mismatches = [path for path, expected in views.items() if path.read_bytes() != expected]
        if args.check:
            if mismatches:
                for path in mismatches:
                    print(f"{path}: OUT-OF-SYNC", file=sys.stderr)
                return 1
            print("canonical Python pins: PASS")
            return 0
        changed = [path for path, data in views.items() if atomic_write(path, data)]
        print("canonical Python pins: UPDATED" if changed else "canonical Python pins: PASS")
        return 0
    except (OSError, PinError) as exc:
        print(f"canonical Python pins: ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
