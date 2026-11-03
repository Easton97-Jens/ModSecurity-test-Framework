#!/usr/bin/env python3
"""Check or materialize the fixed Parent caller from exact Framework Git data."""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "protected_nginx_caller", ROOT / "modsecurity_test_framework/protected_nginx_caller.py")
PROJECTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROJECTION)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--sync", action="store_true")
    parser.add_argument("--parent-root", type=Path, required=True)
    parser.add_argument("--framework-revision", required=True)
    args = parser.parse_args()
    try:
        parent = args.parent_root.absolute()
        target = parent / PROJECTION.TARGET
        if any(path.is_symlink() for path in (target, *target.parents)):
            raise PROJECTION.CallerProjectionError("Parent caller path contains a symlink")
        if not parent.is_dir() or not target.is_file() or target.stat().st_nlink != 1:
            raise PROJECTION.CallerProjectionError("existing Parent caller target is required")
        replacement = PROJECTION.render(PROJECTION.read_source(ROOT, args.framework_revision), args.framework_revision)
        original = target.read_bytes()
        mode = stat.S_IMODE(target.stat().st_mode)
        if original == replacement:
            print("protected caller projection: current")
            return 0
        if args.check:
            print("protected caller projection: stale", file=sys.stderr)
            return 1
        descriptor, temporary = tempfile.mkstemp(prefix=".protected-caller-", dir=target.parent)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(replacement)
                os.fchmod(handle.fileno(), mode)
                os.fsync(handle.fileno())
            if target.is_symlink() or target.read_bytes() != original:
                raise PROJECTION.CallerProjectionError("Parent caller changed concurrently")
            os.replace(temporary, target)
        finally:
            Path(temporary).unlink(missing_ok=True)
        print("protected caller projection: regenerated")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError):
        print("protected caller projection: BLOCKED (source/target contract)", file=sys.stderr)
        return 77


if __name__ == "__main__":
    raise SystemExit(main())
