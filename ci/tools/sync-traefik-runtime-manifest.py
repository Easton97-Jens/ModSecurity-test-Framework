#!/usr/bin/env python3
"""Compatibility wrapper for the generic runtime component synchronizer."""
from __future__ import annotations

import runpy
import sys
import importlib.util
from pathlib import Path

GENERIC = Path(__file__).with_name("sync-runtime-components.py")
_spec = importlib.util.spec_from_file_location("sync_runtime_components", GENERIC)
_module = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(_module)
load_canonical_tuple = _module.load_canonical_tuple
validate_canonical_tuple = _module.validate_canonical_tuple
VERSION_RE = _module.VERSION_RE
ManifestSyncError = _module.ManifestSyncError

if __name__ == "__main__":
    args = list(sys.argv[1:])
    if "--check" not in args and "--write" not in args:
        print("sync-traefik-runtime-manifest: ERROR: --check or --write is required", file=sys.stderr)
        raise SystemExit(2)
    sys.argv = [str(GENERIC), *args, "--component", "traefik"]
    runpy.run_path(str(GENERIC), run_name="__main__")
