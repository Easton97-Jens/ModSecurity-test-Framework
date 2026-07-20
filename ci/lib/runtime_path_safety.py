#!/usr/bin/env python3
"""Validate private task-owned runtime-root paths without following symlinks."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def absolute_path_without_traversal(value: Path | str, label: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"{label} must be an absolute path without traversal: {value}")
    return candidate


def nearest_existing_directory(path: Path) -> Path:
    current = path
    while not current.exists() and current != current.parent:
        current = current.parent
    return current


def has_symlink_component(path: Path) -> bool:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.is_symlink():
            return True
        if not current.exists():
            return False
    return False


def private_runtime_root(value: Path | str, label: str) -> Path:
    candidate = absolute_path_without_traversal(value, label)
    if has_symlink_component(candidate):
        raise ValueError(f"{label} must not contain a symlink component: {candidate}")
    existing = nearest_existing_directory(candidate)
    mode = os.lstat(existing).st_mode
    if not stat.S_ISDIR(mode):
        raise ValueError(f"{label} must have an existing directory parent: {candidate}")
    if stat.S_IMODE(mode) & stat.S_IWOTH:
        raise ValueError(f"{label} must not use a publicly writable directory: {existing}")
    return candidate.resolve(strict=False)
