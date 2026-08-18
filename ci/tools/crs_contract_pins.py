"""Read the reviewed CRS identity from ``ci/lib/common.sh``.

This is deliberately a small, non-executing parser.  Contract tooling must
not source shell configuration or resolve values from the caller's
environment.  Only the four literal assignments below are accepted.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlsplit


class CrsPins(NamedTuple):
    repository: str
    release_tag: str
    commit: str
    rule_file_sha256: str


_ASSIGNMENT = re.compile(r"^([A-Z][A-Z0-9_]*)=(?:\"([^\"]*)\"|'([^']*)')\s*$")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_TAG = re.compile(r"v\d+\.\d+\.\d+\Z", flags=re.ASCII)


def _valid_repository_url(value: str) -> bool:
    parsed = urlsplit(value)
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
        and parsed.path.startswith("/")
        and parsed.path.endswith(".git")
        and len(parsed.path.split("/")) >= 3
    )


def require_regular_file_within_root(path: Path, root: Path) -> Path:
    """Reject symlinked or escaping files before they become trusted input."""

    root_path = Path(os.path.abspath(root))
    candidate = Path(os.path.abspath(path))
    try:
        relative = candidate.relative_to(root_path)
    except ValueError as error:
        raise ValueError(f"path escapes framework root: {candidate}") from error
    try:
        root_mode = root_path.lstat().st_mode
    except FileNotFoundError as error:
        raise ValueError(f"framework root does not exist: {root_path}") from error
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
        raise ValueError(f"framework root must be a non-symlink directory: {root_path}")

    current = root_path
    for index, part in enumerate(relative.parts):
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError as error:
            raise ValueError(
                f"required framework path does not exist: {current}"
            ) from error
        if stat.S_ISLNK(mode):
            raise ValueError(f"symlinked framework path is not allowed: {current}")
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(mode):
            raise ValueError(f"framework path parent is not a directory: {current}")
    if not stat.S_ISREG(current.lstat().st_mode):
        raise ValueError(f"framework path is not a regular file: {current}")

    resolved_root = root_path.resolve(strict=True)
    resolved_candidate = current.resolve(strict=True)
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as error:
        raise ValueError(f"path resolves outside framework root: {current}") from error
    # Return the path after the same-root check.  Callers must use this value
    # for filesystem access; the original CLI-derived path remains tainted.
    return resolved_candidate


_REQUIRED = frozenset(
    (
        "CRS_APPROVED_REPO_URL",
        "CRS_RELEASE_TAG",
        "CRS_APPROVED_COMMIT",
        "CRS_RULE_FILE_SHA256",
    )
)


def _parse_assignments(common_path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        common_path.read_text(encoding="utf-8").splitlines(), 1
    ):
        line = raw_line.strip()
        match = _ASSIGNMENT.fullmatch(line) if line and not line.startswith("#") else None
        if match is None or match.group(1) not in _REQUIRED:
            continue
        name = match.group(1)
        if name in values:
            raise ValueError(f"duplicate CRS assignment at {common_path}:{line_number}")
        value = match.group(2) or match.group(3)
        if not value:
            raise ValueError(f"empty CRS assignment at {common_path}:{line_number}")
        values[name] = value
    return values


def _validate_values(values: dict[str, str], common_path: Path) -> CrsPins:
    required = set(_REQUIRED)
    if set(values) != required:
        missing = ", ".join(sorted(required - set(values)))
        raise ValueError(f"missing CRS assignments in {common_path}: {missing}")
    if not _valid_repository_url(values["CRS_APPROVED_REPO_URL"]):
        raise ValueError("CRS repository must be an HTTPS Git repository URL")
    if not _TAG.fullmatch(values["CRS_RELEASE_TAG"]):
        raise ValueError("CRS release tag is not a semantic release tag")
    if not _COMMIT.fullmatch(values["CRS_APPROVED_COMMIT"]):
        raise ValueError("CRS approved commit is not a lowercase 40-character SHA")
    if not _SHA256.fullmatch(values["CRS_RULE_FILE_SHA256"]):
        raise ValueError("CRS rule file digest is not a lowercase 64-character SHA-256")
    return CrsPins(
        repository=values["CRS_APPROVED_REPO_URL"],
        release_tag=values["CRS_RELEASE_TAG"],
        commit=values["CRS_APPROVED_COMMIT"],
        rule_file_sha256=values["CRS_RULE_FILE_SHA256"],
    )


def load_crs_pins(common_path: Path, *, root: Path) -> CrsPins:
    """Return CRS pins from literal assignments in *common_path*.

    Comments and blank lines are ignored.  Duplicate assignments, shell
    expansions, and malformed values fail closed.
    """

    common_path = require_regular_file_within_root(common_path, root)
    return _validate_values(_parse_assignments(common_path), common_path)
