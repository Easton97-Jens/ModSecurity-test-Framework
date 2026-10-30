#!/usr/bin/env python3
"""Create and verify lifecycle runtime paths before a shell entrypoint writes."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path




from modsecurity_connector_ci.lib.runtime_path_utils import ensure_safe_writable_runtime_paths, verified_runtime_paths


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-root", default=os.environ.get("BUILD_ROOT"))
    args = parser.parse_args()

    build_root_override = Path(os.path.abspath(args.build_root)) if args.build_root else None
    try:
        paths = verified_runtime_paths(
            os.environ,
            build_root_override=build_root_override,
        )
        ensure_safe_writable_runtime_paths(paths)
    except ValueError as exc:
        print(f"prepare-verified-runtime-paths: {exc}", file=sys.stderr)
        return 77
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
