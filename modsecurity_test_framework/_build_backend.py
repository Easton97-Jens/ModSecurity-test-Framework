"""Dependency-free PEP 517 backend for the public contract package.

The Framework previously had no Python distribution.  Keeping this tiny build
backend in-tree lets a consumer install the public contracts from a checkout
without downloading a build backend or depending on the current directory.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile


NAME = "modsecurity-test-framework"
NORMALIZED_NAME = "modsecurity_test_framework"
VERSION = "1.0.0"
DIST_INFO = f"{NORMALIZED_NAME}-{VERSION}.dist-info"
WHEEL_NAME = f"{NORMALIZED_NAME}-{VERSION}-py3-none-any.whl"
SOURCE_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_FILES = (
    "modsecurity_test_framework/__init__.py",
    "modsecurity_test_framework/_build_backend.py",
    "modsecurity_test_framework/contracts.py",
    "modsecurity_test_framework/data/framework-contract-catalog.json",
)
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def _metadata() -> str:
    return "\n".join(
        (
            "Metadata-Version: 2.3",
            f"Name: {NAME}",
            f"Version: {VERSION}",
            "Summary: Public, package-safe contracts for the ModSecurity test framework",
            "Requires-Python: >=3.11",
            "",
        )
    )


def _wheel() -> str:
    return "\n".join(
        (
            "Wheel-Version: 1.0",
            "Generator: modsecurity-test-framework",
            "Root-Is-Purelib: true",
            "Tag: py3-none-any",
            "",
        )
    )


def _write_metadata(target: Path) -> None:
    dist_info = target / DIST_INFO
    dist_info.mkdir(parents=True, exist_ok=True)
    (dist_info / "METADATA").write_text(_metadata(), encoding="utf-8")
    (dist_info / "WHEEL").write_text(_wheel(), encoding="utf-8")


def prepare_metadata_for_build_wheel(
    metadata_directory: str,
    config_settings: object | None = None,
) -> str:
    del config_settings
    _write_metadata(Path(metadata_directory))
    return DIST_INFO


def _record_line(path: str, content: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=")
    return f"{path},sha256={digest.decode('ascii')},{len(content)}"


def _source_commit() -> str | None:
    """Read the checkout commit with a fixed, non-shell Git invocation."""

    try:
        completed = subprocess.run(
            ("git", "-C", str(SOURCE_ROOT), "rev-parse", "HEAD"),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2,
            env={"PATH": os.defpath, "LC_ALL": "C", "GIT_OPTIONAL_LOCKS": "0"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    candidate = completed.stdout.strip()
    return candidate if completed.returncode == 0 and COMMIT_RE.fullmatch(candidate) else None


def _package_content(relative_path: str, source_commit: str | None) -> bytes:
    content = (SOURCE_ROOT / relative_path).read_bytes()
    if relative_path != "modsecurity_test_framework/data/framework-contract-catalog.json" or source_commit is None:
        return content
    catalog = json.loads(content.decode("utf-8"))
    catalog["source_commit"] = source_commit
    return (json.dumps(catalog, indent=2, sort_keys=True) + "\n").encode("utf-8")


def build_wheel(
    wheel_directory: str,
    config_settings: object | None = None,
    metadata_directory: str | None = None,
) -> str:
    del config_settings, metadata_directory
    destination = Path(wheel_directory)
    destination.mkdir(parents=True, exist_ok=True)
    wheel_path = destination / WHEEL_NAME
    entries: dict[str, bytes] = {}
    source_commit = _source_commit()
    for relative_path in PACKAGE_FILES:
        entries[relative_path] = _package_content(relative_path, source_commit)
    entries[f"{DIST_INFO}/METADATA"] = _metadata().encode("utf-8")
    entries[f"{DIST_INFO}/WHEEL"] = _wheel().encode("utf-8")
    record_path = f"{DIST_INFO}/RECORD"
    record_lines = [_record_line(path, content) for path, content in sorted(entries.items())]
    record_lines.append(f"{record_path},,")
    entries[record_path] = ("\n".join(record_lines) + "\n").encode("utf-8")
    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, content in sorted(entries.items()):
            archive.writestr(path, content)
    return WHEEL_NAME
