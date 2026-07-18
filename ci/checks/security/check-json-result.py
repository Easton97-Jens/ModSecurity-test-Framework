#!/usr/bin/env python3
"""Validate a bounded, non-symlink JSON evidence file before it is retained."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat


class JsonEvidenceError(ValueError):
    """Raised when a scanner result is not safe, bounded JSON evidence."""


def read_json_object(path: Path, maximum_bytes: int) -> dict[str, object]:
    if maximum_bytes <= 0:
        raise JsonEvidenceError("maximum byte count must be positive")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise JsonEvidenceError(
            f"cannot open JSON evidence file {path}: {exc}"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise JsonEvidenceError("JSON evidence must be a regular file")
        if metadata.st_size > maximum_bytes:
            raise JsonEvidenceError(
                f"JSON evidence exceeds the {maximum_bytes}-byte retention limit"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            payload = source.read(maximum_bytes + 1)
    finally:
        os.close(descriptor)
    if len(payload) > maximum_bytes:
        raise JsonEvidenceError(
            f"JSON evidence exceeds the {maximum_bytes}-byte retention limit"
        )
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JsonEvidenceError(
            f"JSON evidence is not valid UTF-8 JSON: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise JsonEvidenceError("JSON evidence must contain an object")
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--max-bytes", required=True, type=int)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    read_json_object(args.input, args.max_bytes)
    print(f"JSON evidence passed: {args.input}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except JsonEvidenceError as exc:
        print(f"JSON evidence error: {exc}", file=os.sys.stderr)
        raise SystemExit(2) from exc
