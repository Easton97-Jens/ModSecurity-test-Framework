#!/usr/bin/env python3
"""Compare exact-revision OSV JSON reports and fail only on new groups."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any

from osv_report_schema import OsvReportError, report_groups


REVISION = re.compile(r"^[0-9a-f]{40}$")


OsvComparisonError = OsvReportError


def trusted_evidence_roots() -> tuple[Path, ...]:
    """Return the runner-owned directories that may contain OSV evidence."""
    runner_temp = os.environ.get("RUNNER_TEMP")
    roots = [Path(runner_temp)] if runner_temp else [Path(tempfile.gettempdir())]
    try:
        resolved_roots = tuple(root.resolve(strict=True) for root in roots)
    except OSError as exc:
        raise OsvComparisonError(
            f"cannot resolve a trusted OSV evidence directory: {exc}"
        ) from exc
    if not all(root.is_dir() for root in resolved_roots):
        raise OsvComparisonError("trusted OSV evidence directories must exist")
    return resolved_roots


def normalised_path(path: Path) -> Path:
    """Return an absolute path without untrusted parent traversal components."""
    if path.name in {"", ".", ".."}:
        raise OsvComparisonError("OSV evidence path must name a file")
    try:
        absolute_path = path if path.is_absolute() else Path.cwd() / path
        return absolute_path.parent.resolve(strict=False) / absolute_path.name
    except OSError as exc:
        raise OsvComparisonError(
            f"cannot normalise OSV evidence path {path}: {exc}"
        ) from exc


def is_within(path: Path, root: Path) -> bool:
    """Return whether ``path`` is contained by the trusted ``root``."""
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def validated_evidence_path(path: Path, description: str) -> Path:
    """Reject evidence outside runner-owned temporary directories before using it."""
    candidate = normalised_path(path)
    try:
        resolved_candidate = candidate.resolve(strict=False)
    except OSError as exc:
        raise OsvComparisonError(
            f"cannot resolve {description} path {path}: {exc}"
        ) from exc
    if not any(
        is_within(resolved_candidate, root) for root in trusted_evidence_roots()
    ):
        raise OsvComparisonError(
            f"{description} path must be inside a trusted temporary directory"
        )
    return candidate


def read_regular_json(path: Path) -> dict[str, Any]:
    """Read one regular non-symlink JSON document after path validation."""
    if not hasattr(os, "O_NOFOLLOW"):
        raise OsvComparisonError("platform cannot safely open non-symlink OSV evidence")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise OsvComparisonError(f"cannot read OSV JSON report {path}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OsvComparisonError(f"OSV JSON report {path} must be a regular file")
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as source:
            value = json.load(source)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OsvComparisonError(f"cannot read OSV JSON report {path}: {exc}") from exc
    finally:
        os.close(descriptor)
    if not isinstance(value, dict):
        raise OsvComparisonError(f"OSV JSON report {path} must be an object")
    return value


def read_report(path: Path) -> dict[str, Any]:
    return read_regular_json(validated_evidence_path(path, "OSV JSON report"))


def serialise_groups(
    groups: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "ecosystem": group["ecosystem"],
            "package": group["package"],
            "vulnerability_ids": group["vulnerability_ids"],
            "versions": sorted(group["versions"]),
        }
        for _identity, group in sorted(groups.items())
    ]


def validate_revision(revision: str, name: str) -> None:
    """Require the immutable revision format recorded in comparison evidence."""
    if not REVISION.fullmatch(revision):
        raise OsvComparisonError(
            f"{name} revision must be a lowercase 40-character SHA"
        )


def vulnerability_ids_by_package(
    groups: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]],
) -> dict[tuple[str, str], list[frozenset[str]]]:
    """Index base groups by package so aliases survive package version changes."""
    identifiers: dict[tuple[str, str], list[frozenset[str]]] = {}
    for group in groups.values():
        package_identity = (group["ecosystem"], group["package"])
        identifiers.setdefault(package_identity, []).append(
            frozenset(group["vulnerability_ids"])
        )
    return identifiers


def is_new_vulnerability_group(
    group: dict[str, Any],
    base_ids_by_package: dict[tuple[str, str], list[frozenset[str]]],
) -> bool:
    """Return whether no base group for this package shares a vulnerability id."""
    package_identity = (group["ecosystem"], group["package"])
    vulnerability_ids = frozenset(group["vulnerability_ids"])
    return not any(
        vulnerability_ids.intersection(base_ids)
        for base_ids in base_ids_by_package.get(package_identity, [])
    )


def new_vulnerability_groups(
    base_groups: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]],
    head_groups: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]],
) -> dict[tuple[str, str, tuple[str, ...]], dict[str, Any]]:
    """Return head groups whose vulnerability identities are absent from base."""
    base_ids_by_package = vulnerability_ids_by_package(base_groups)
    return {
        identity: group
        for identity, group in head_groups.items()
        if is_new_vulnerability_group(group, base_ids_by_package)
    }


def compare_reports(
    base_report: dict[str, Any],
    head_report: dict[str, Any],
    base_revision: str,
    head_revision: str,
) -> dict[str, Any]:
    validate_revision(base_revision, "base")
    validate_revision(head_revision, "head")
    base_groups = report_groups(base_report)
    head_groups = report_groups(head_report)
    new_groups = new_vulnerability_groups(base_groups, head_groups)
    return {
        "schema_version": 1,
        "base_revision": base_revision,
        "head_revision": head_revision,
        "status": "new_vulnerabilities" if new_groups else "no_new_vulnerabilities",
        "base_vulnerability_groups": serialise_groups(base_groups),
        "head_vulnerability_groups": serialise_groups(head_groups),
        "new_vulnerability_groups": serialise_groups(new_groups),
    }


def prepare_output_path(path: Path) -> Path:
    """Create and revalidate the trusted directory for one comparison report."""
    output_path = validated_evidence_path(path, "OSV comparison output")
    try:
        output_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise OsvComparisonError(
            f"cannot create OSV comparison output directory {output_path.parent}: {exc}"
        ) from exc
    return validated_evidence_path(output_path, "OSV comparison output")


def write_temporary_report(directory: Path, report: dict[str, Any]) -> Path:
    """Write a mode-0600 temporary report in an already validated directory."""
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".osv-comparison-",
            suffix=".tmp",
            dir=directory,
            text=True,
        )
    except OSError as exc:
        raise OsvComparisonError(
            f"cannot create temporary OSV comparison report in {directory}: {exc}"
        ) from exc
    temporary_path = validated_evidence_path(
        Path(temporary_name), "OSV comparison temporary output"
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
    except OSError as exc:
        raise OsvComparisonError(
            f"cannot write temporary OSV comparison report {temporary_path}: {exc}"
        ) from exc
    return temporary_path


def write_report(path: Path, report: dict[str, Any]) -> None:
    output_path = prepare_output_path(path)
    temporary_path = write_temporary_report(output_path.parent, report)
    try:
        os.replace(temporary_path, output_path)
    except OSError as exc:
        raise OsvComparisonError(
            f"cannot retain OSV comparison report {output_path}: {exc}"
        ) from exc
    finally:
        temporary_path.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, type=Path)
    parser.add_argument("--head", required=True, type=Path)
    parser.add_argument("--base-revision", required=True)
    parser.add_argument("--head-revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = compare_reports(
        read_report(args.base),
        read_report(args.head),
        args.base_revision,
        args.head_revision,
    )
    write_report(args.output, report)
    if report["new_vulnerability_groups"]:
        print(
            "OSV comparison found vulnerability groups absent from the base revision."
        )
        return 1
    print("OSV comparison found no vulnerability groups absent from the base revision.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except OsvComparisonError as exc:
        print(f"OSV comparison error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
