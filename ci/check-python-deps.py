#!/usr/bin/env python3
"""Validate required Python modules for local CI helpers."""

from __future__ import annotations

import importlib
import sys

REQUIRED = {
    "yaml": "PyYAML>=6,<7",
}


def main() -> int:
    missing: list[tuple[str, str]] = []
    for module, requirement in REQUIRED.items():
        try:
            importlib.import_module(module)
        except ModuleNotFoundError:
            missing.append((module, requirement))
    if not missing:
        return 0

    print("blocked: missing required Python dependencies for CI helpers", file=sys.stderr)
    for module, requirement in missing:
        print(f" - module '{module}' not found (install requirement: {requirement})", file=sys.stderr)
    print("hint: python3 -m pip install -r requirements-dev.txt", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
