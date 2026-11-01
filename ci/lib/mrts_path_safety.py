"""Shared private external-root contract for MRTS packages and run evidence."""

from __future__ import annotations

import os
from pathlib import Path
import runpy
import stat
import tempfile

_runtime_safety = runpy.run_path(
    str(Path(__file__).with_name("runtime_path_safety.py"))
)
nearest_existing_directory = _runtime_safety["nearest_existing_directory"]
private_runtime_root = _runtime_safety["private_runtime_root"]


def _source_roots() -> list[Path]:
    roots = [Path(__file__).resolve().parents[2]]
    for name in ("FRAMEWORK_ROOT", "CONNECTOR_ROOT", "PROJECT_ROOT"):
        value = os.environ.get(name)
        if value and Path(value).is_absolute():
            roots.append(Path(value).resolve())
    return roots


def _check_dedicated_external_root(path: Path, label: str) -> None:
    # System namespaces are never runtime destinations. On /var, the external
    # task area must be below tmp, with an additional dedicated directory.
    parts = path.parts
    if len(parts) < 3 or parts[1] in {
        "bin",
        "sbin",
        "usr",
        "etc",
        "dev",
        "proc",
        "sys",
        "boot",
        "lib",
        "lib64",
        "root",
        "run",
    }:
        raise ValueError(f"{label} must be a dedicated external runtime root")
    if parts[1] == "var" and (len(parts) < 4 or parts[2] != "tmp"):
        raise ValueError(f"{label} must be a dedicated external runtime root")
    if path == Path(tempfile.gettempdir()).resolve():
        raise ValueError(f"{label} must not be the general temporary directory")
    for source in _source_roots():
        if path == source or path.is_relative_to(source) or source.is_relative_to(path):
            raise ValueError(f"{label} must be separate from source checkouts")


def _check_ownership(path: Path, label: str) -> None:
    existing = nearest_existing_directory(path)
    info = existing.lstat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
        raise ValueError(
            f"{label} requires an owned directory without group or public write access"
        )
    for parent in existing.parents:
        info = parent.lstat()
        if info.st_uid not in (0, os.geteuid()):
            raise ValueError(f"{label} has an untrusted directory owner")
        # A trusted sticky shared temp ancestor cannot rename another owner's
        # private child. A writable non-sticky ancestor can, and is rejected.
        if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise ValueError(f"{label} has a writable non-sticky directory ancestor")


def approved_runtime_root(value: str | Path, label: str) -> Path:
    """Validate an explicitly selected external root without creating it."""
    path = private_runtime_root(value, label)
    _check_dedicated_external_root(path, label)
    _check_ownership(path, label)
    anchors = [
        Path(value)
        for name in ("CODEX_TEMP_ROOT", "RUNNER_TEMP")
        if (value := os.environ.get(name))
    ]
    if anchors and not any(
        anchor.is_absolute()
        and path != anchor.resolve()
        and path.is_relative_to(anchor.resolve())
        for anchor in anchors
    ):
        raise ValueError(f"{label} is outside the configured external runtime roots")
    return path
