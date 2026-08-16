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
    "CI_CANONICAL_PYYAML_ARTIFACT",
    "CI_CANONICAL_PYYAML_PLATFORM",
)
TOOL_ROOT = Path(__file__).resolve().parents[2]
GENERATED_VIEW_LABEL = "generated view"
ASSIGNMENT = re.compile(
    r"^\s*(?P<name>CI_CANONICAL_(?:PYTHON_VERSION|PYYAML_VERSION|PYYAML_SHA256|PYYAML_ARTIFACT|PYYAML_PLATFORM))"
    r"\s*=\s*(?:\"(?P<double>[^\"\n]*)\"|'(?P<single>[^'\n]*)'|"
    r"(?P<bare>[^\s#]+))\s*(?:#.*)?$"
)
VERSION = re.compile(r"\A\d+\.\d+\.\d+\Z", flags=re.ASCII)
SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
ARTIFACT = re.compile(r"\Apyyaml-\d+\.\d+\.\d+-[A-Za-z0-9_.-]+\.whl\Z")
PLATFORM = re.compile(r"\A[A-Za-z0-9_.-]+(?:\.[A-Za-z0-9_.-]+)*\Z")
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
    supplied = lexical_path(root)
    expected = lexical_path(TOOL_ROOT)
    if supplied != expected:
        raise PinError(
            f"{supplied}: --root must match this tool's repository root {expected}"
        )
    reject_symlink_components(expected, "repository root")
    try:
        details = expected.lstat()
    except OSError as exc:
        raise PinError(f"{expected}: repository root is unavailable: {exc}") from exc
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise PinError(f"{expected}: repository root must be a real directory")
    return expected


def regular_file(path: Path, label: str) -> None:
    try:
        details = path.lstat()
    except OSError as exc:
        raise PinError(f"{path}: {label} is missing: {exc}") from exc
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        raise PinError(f"{path}: {label} must be a regular non-symlink file")


def read_utf8(path: Path, root: Path, label: str) -> str:
    """Read one regular, non-symlink UTF-8 file confined to ``root``."""
    validated = path_in_root(path, root, label)
    regular_file(validated, label)
    try:
        return validated.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise PinError(f"{path}: {label} is not readable UTF-8: {exc}") from exc


def read_bytes(path: Path, root: Path, label: str) -> bytes:
    """Read one regular, non-symlink byte stream confined to ``root``."""
    validated = path_in_root(path, root, label)
    regular_file(validated, label)
    try:
        return validated.read_bytes()
    except OSError as exc:
        raise PinError(f"{path}: {label} is not readable: {exc}") from exc


def canonical_values(common: Path, root: Path) -> dict[str, str]:
    text = read_utf8(common, root, "common pin source")
    values: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = ASSIGNMENT.fullmatch(line)
        if match is None:
            continue
        name = match.group("name")
        if name in values:
            raise PinError(f"{common}:{line_number}: duplicate {name}")
        value = next(
            value
            for value in (
                match.group("double"),
                match.group("single"),
                match.group("bare"),
            )
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
        raise PinError(
            f"{common}: CI_CANONICAL_PYYAML_SHA256 must be 64 lowercase hex characters"
        )
    if not ARTIFACT.fullmatch(values[PIN_NAMES[3]]):
        raise PinError(f"{common}: CI_CANONICAL_PYYAML_ARTIFACT is malformed")
    if not PLATFORM.fullmatch(values[PIN_NAMES[4]]):
        raise PinError(f"{common}: CI_CANONICAL_PYYAML_PLATFORM is malformed")
    expected_platform = values[PIN_NAMES[3]].removesuffix(".whl").split("-", 4)[-1]
    if values[PIN_NAMES[4]] != expected_platform:
        raise PinError(f"{common}: PyYAML artifact/platform provenance does not match")
    return values


def expected_views(root: Path, values: dict[str, str]) -> dict[Path, bytes]:
    python_label = ".python-version"
    requirements_label = "requirements-ci.lock"
    python_path = path_in_root(root / python_label, root, python_label)
    requirements_path = path_in_root(
        root / requirements_label, root, requirements_label
    )
    python_text = read_utf8(python_path, root, python_label)
    if PYTHON_VIEW.fullmatch(python_text) is None:
        raise PinError(
            f"{python_path}: expected exactly one newline-terminated stable version"
        )
    requirements = read_utf8(requirements_path, root, requirements_label)
    lines = requirements.splitlines(keepends=True)
    lines = [
        line for line in lines
        if not line.startswith(("# PyYAML artifact:", "# PyYAML platform:"))
    ]
    provenance = (
        "# PyYAML artifact: " + values["CI_CANONICAL_PYYAML_ARTIFACT"] + "\n"
        "# PyYAML platform: " + values["CI_CANONICAL_PYYAML_PLATFORM"] + "\n"
    )
    if lines and lines[0].startswith("# generated view;"):
        lines[1:1] = provenance.splitlines(keepends=True)
    version_indexes = [
        index for index, line in enumerate(lines) if PYAML_VERSION_LINE.fullmatch(line)
    ]
    hash_indexes = [
        index for index, line in enumerate(lines) if PYAML_HASH_LINE.fullmatch(line)
    ]
    if len(version_indexes) != 1:
        raise PinError(
            f"{requirements_path}: expected exactly one PyYAML requirement line"
        )
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


def atomic_write(path: Path, root: Path, data: bytes) -> bool:
    validated = path_in_root(path, root, GENERATED_VIEW_LABEL)
    current = read_bytes(validated, root, GENERATED_VIEW_LABEL)
    if current == data:
        return False
    directory = validated.parent
    directory_details = directory.lstat()
    if stat.S_ISLNK(directory_details.st_mode) or not stat.S_ISDIR(
        directory_details.st_mode
    ):
        raise PinError(f"{directory}: target directory must be a real directory")
    fd, temporary = tempfile.mkstemp(prefix=f".{validated.name}.", dir=directory)
    temporary_path = Path(temporary)
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, validated)
        return True
    except OSError as exc:
        raise PinError(f"{validated}: atomic update failed: {exc}") from exc
    finally:
        temporary_path.unlink(missing_ok=True)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--check", action="store_true", help="validate generated views without writing"
    )
    mode.add_argument(
        "--write", action="store_true", help="atomically update generated views"
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=TOOL_ROOT,
        help="repository root; must match the checkout containing this tool",
    )
    parser.add_argument("--common", type=Path, default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        root = validate_root(args.root)
        common = path_in_root(
            args.common or root / "ci/lib/common.sh", root, "common pin source"
        )
        values = canonical_values(common, root)
        views = expected_views(root, values)
        mismatches = [
            path
            for path, expected in views.items()
            if read_bytes(path, root, GENERATED_VIEW_LABEL) != expected
        ]
        if args.check:
            if mismatches:
                for path in mismatches:
                    print(f"{path}: OUT-OF-SYNC", file=sys.stderr)
                return 1
            print("canonical Python pins: PASS")
            return 0
        changed = [
            path for path, data in views.items() if atomic_write(path, root, data)
        ]
        print(
            "canonical Python pins: UPDATED"
            if changed
            else "canonical Python pins: PASS"
        )
        return 0
    except (OSError, PinError) as exc:
        print(f"canonical Python pins: ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
