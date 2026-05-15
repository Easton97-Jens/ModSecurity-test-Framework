#!/usr/bin/env python3
"""Parse GitHub workflow YAML files."""

from __future__ import annotations

import pathlib

import yaml  # type: ignore[import-not-found]


def main() -> int:
    for path in pathlib.Path(".github/workflows").glob("*.yml"):
        yaml.safe_load(path.read_text(encoding="utf-8"))
        print("ok", path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
