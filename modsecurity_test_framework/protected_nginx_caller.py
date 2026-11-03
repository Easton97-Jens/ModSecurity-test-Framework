"""Generate the fixed Parent inline projection without duplicating test logic."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess


SOURCE = ".github/workflows/connector-protected-nginx-root-broker-caller.yml"
TARGET = ".github/workflows/run-protected-nginx-root-broker.yml"
APPROVED_SOURCE_SHA256 = "11ee98f070a5a4c088e0c10466c0e867869f1769e5832bacf6bf2c5986a2cb3c"
MAX_BYTES = 256 * 1024


class CallerProjectionError(ValueError):
    """The selected source does not match the reviewed inline projection."""


def render(source: bytes, revision: str) -> bytes:
    """Only the trigger changes; every executable step stays Framework-owned."""
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise CallerProjectionError("Framework revision must be an exact lowercase SHA-40")
    if hashlib.sha256(source).hexdigest() != APPROVED_SOURCE_SHA256:
        raise CallerProjectionError("canonical caller source changed; review its protected contract")
    trigger = b"\non:\n  workflow_call:\n"
    if source.count(trigger) != 1:
        raise CallerProjectionError("canonical caller must have exactly one reusable trigger")
    header = (
        "# Generated from Framework; edit the canonical source and regenerate.\n"
        f"# framework-caller-source: {SOURCE}\n"
        f"# framework-caller-revision: {revision}\n"
        f"# framework-caller-source-sha256: {APPROVED_SOURCE_SHA256}\n"
    ).encode("ascii")
    return header + source.replace(trigger, b"\non:\n  workflow_dispatch:\n", 1)


def read_source(root: Path, revision: str) -> bytes:
    """Read the one canonical regular Git blob; never execute candidate code."""
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise CallerProjectionError("Framework revision must be an exact lowercase SHA-40")
    def git(*arguments: str) -> bytes:
        return subprocess.run(
            ["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null", "-C", str(root), *arguments],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        ).stdout
    entry = git("ls-tree", revision, "--", SOURCE)
    match = re.fullmatch(rb"100644 blob ([a-f0-9]{40})\t" + re.escape(SOURCE.encode()) + rb"\n", entry)
    if match is None:
        raise CallerProjectionError("canonical caller must be a regular Git blob")
    oid = match[1].decode("ascii")
    size = git("cat-file", "-s", oid).strip()
    if not size.isdigit() or int(size) > MAX_BYTES:
        raise CallerProjectionError("canonical caller exceeds its bounded size")
    raw = git("cat-file", "blob", oid)
    if len(raw) != int(size):
        raise CallerProjectionError("canonical caller changed while reading")
    return raw
