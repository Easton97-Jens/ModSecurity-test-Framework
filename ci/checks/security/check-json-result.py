#!/usr/bin/env python3
"""Validate a bounded, non-symlink JSON evidence file before it is retained."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

from osv_report_schema import OsvReportError, validate_osv_report


class JsonEvidenceError(ValueError):
    """Raised when a scanner result is not safe, bounded JSON evidence."""


def trusted_evidence_roots() -> tuple[Path, ...]:
    """Return the runner-owned directories that may contain CI evidence."""
    runner_temp = os.environ.get("RUNNER_TEMP")
    roots = [Path(runner_temp)] if runner_temp else [Path(tempfile.gettempdir())]
    try:
        resolved_roots = tuple(root.resolve(strict=True) for root in roots)
    except OSError as exc:
        raise JsonEvidenceError(
            f"cannot resolve a trusted JSON evidence directory: {exc}"
        ) from exc
    if not all(root.is_dir() for root in resolved_roots):
        raise JsonEvidenceError("trusted JSON evidence directories must exist")
    return resolved_roots


def normalised_path(path: Path) -> Path:
    """Return an absolute path without untrusted parent traversal components."""
    if path.name in {"", ".", ".."}:
        raise JsonEvidenceError("JSON evidence path must name a file")
    try:
        absolute_path = path if path.is_absolute() else Path.cwd() / path
        return absolute_path.parent.resolve(strict=False) / absolute_path.name
    except OSError as exc:
        raise JsonEvidenceError(
            f"cannot normalise JSON evidence path {path}: {exc}"
        ) from exc


def is_within(path: Path, root: Path) -> bool:
    """Return whether ``path`` is contained by the trusted ``root``."""
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def validated_evidence_path(path: Path) -> Path:
    """Reject evidence outside runner-owned temporary directories before opening it."""
    candidate = normalised_path(path)
    try:
        resolved_candidate = candidate.resolve(strict=False)
    except OSError as exc:
        raise JsonEvidenceError(
            f"cannot resolve JSON evidence path {path}: {exc}"
        ) from exc
    if not any(
        is_within(resolved_candidate, root) for root in trusted_evidence_roots()
    ):
        raise JsonEvidenceError(
            "JSON evidence path must be inside a trusted temporary directory"
        )
    return candidate


def read_json_object(path: Path, maximum_bytes: int) -> dict[str, object]:
    if maximum_bytes <= 0:
        raise JsonEvidenceError("maximum byte count must be positive")
    evidence_path = validated_evidence_path(path)
    if not hasattr(os, "O_NOFOLLOW"):
        raise JsonEvidenceError("platform cannot safely open non-symlink JSON evidence")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    try:
        descriptor = os.open(evidence_path, flags)
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


def validate_osv_evidence(value: dict[str, object]) -> None:
    """Require the OSV result/package/group structure before retaining evidence."""
    try:
        validate_osv_report(value)
    except OsvReportError as exc:
        raise JsonEvidenceError(f"JSON evidence is not an OSV report: {exc}") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--max-bytes", required=True, type=int)
    parser.add_argument(
        "--osv-report",
        action="store_true",
        help="require the OSV result/package/group JSON structure",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    value = read_json_object(args.input, args.max_bytes)
    if args.osv_report:
        validate_osv_evidence(value)
        print(f"OSV JSON evidence passed: {args.input}")
    else:
        print(f"JSON evidence passed: {args.input}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except JsonEvidenceError as exc:
        print(f"JSON evidence error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
