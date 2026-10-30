"""Safely read and write HAProxy HTX runtime artifacts below one private root."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import sys


_CI_LIB = connector_root() / "ci" / "lib"


from modsecurity_connector_ci.lib.runtime_path_utils import append_runtime_artifact_text, read_runtime_artifact_text, runtime_artifact_path, verified_runtime_artifact_root, write_runtime_artifact_text_atomic


def verified_runtime_root(value: str | Path) -> Path:
    """Return a private root that may contain this invocation's artifacts."""
    return verified_runtime_artifact_root(value)


def artifact_path(root: Path, value: str | Path, label: str, *, must_exist: bool) -> Path:
    """Validate an artifact path before any filesystem access.

    The root and every opened parent are checked by descriptor, and the final
    file is rejected when it is a symbolic link.  This keeps a CLI-provided
    path from crossing into a checkout, system directory, or sibling run.
    """

    return runtime_artifact_path(root, value, label, must_exist=must_exist)


def read_text(root: Path, value: str | Path, label: str, *, errors: str | None = None) -> str:
    """Read one verified regular artifact without following its final link."""

    return read_runtime_artifact_text(root, value, label, errors=errors)


def append_text(root: Path, value: str | Path, text: str, label: str) -> Path:
    """Append one private text artifact through a no-follow descriptor."""

    return append_runtime_artifact_text(root, value, text, label)


def write_text_atomic(root: Path, value: str | Path, text: str, label: str) -> Path:
    """Replace one private regular artifact atomically without following links."""

    return write_runtime_artifact_text_atomic(root, value, text, label)
