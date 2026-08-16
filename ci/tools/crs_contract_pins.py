"""Read the reviewed CRS identity from ``ci/lib/common.sh``.

This is deliberately a small, non-executing parser.  Contract tooling must
not source shell configuration or resolve values from the caller's
environment.  Only the three literal assignments below are accepted.
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


_ASSIGNMENT = re.compile(r"^([A-Z][A-Z0-9_]*)=(?:\"([^\"]*)\"|'([^']*)')\s*$")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+\Z")


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
            raise ValueError(f"required framework path does not exist: {current}") from error
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
    return current


def load_crs_pins(common_path: Path, *, root: Path) -> CrsPins:
    """Return CRS pins from literal assignments in *common_path*.

    Comments and blank lines are ignored.  Duplicate assignments, shell
    expansions, and malformed values fail closed.
    """

    common_path = require_regular_file_within_root(common_path, root)
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        common_path.read_text(encoding="utf-8").splitlines(), 1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _ASSIGNMENT.fullmatch(line)
        if not match:
            continue
        name = match.group(1)
        if name not in {"CRS_APPROVED_REPO_URL", "CRS_RELEASE_TAG", "CRS_APPROVED_COMMIT"}:
            continue
        if name in values:
            raise ValueError(f"duplicate CRS assignment at {common_path}:{line_number}")
        value = match.group(2) if match.group(2) is not None else match.group(3)
        if not value:
            raise ValueError(f"empty CRS assignment at {common_path}:{line_number}")
        values[name] = value
    required = {"CRS_APPROVED_REPO_URL", "CRS_RELEASE_TAG", "CRS_APPROVED_COMMIT"}
    if set(values) != required:
        missing = ", ".join(sorted(required - set(values)))
        raise ValueError(f"missing CRS assignments in {common_path}: {missing}")
    if not _valid_repository_url(values["CRS_APPROVED_REPO_URL"]):
        raise ValueError("CRS repository must be an HTTPS Git repository URL")
    if not _TAG.fullmatch(values["CRS_RELEASE_TAG"]):
        raise ValueError("CRS release tag is not a semantic release tag")
    if not _COMMIT.fullmatch(values["CRS_APPROVED_COMMIT"]):
        raise ValueError("CRS approved commit is not a lowercase 40-character SHA")
    return CrsPins(
        repository=values["CRS_APPROVED_REPO_URL"],
        release_tag=values["CRS_RELEASE_TAG"],
        commit=values["CRS_APPROVED_COMMIT"],
    )
