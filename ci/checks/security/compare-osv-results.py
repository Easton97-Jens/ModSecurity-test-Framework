#!/usr/bin/env python3
"""Compare exact-revision OSV JSON reports and fail only on new groups."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
from typing import Any


REVISION = re.compile(r"^[0-9a-f]{40}$")


class OsvComparisonError(ValueError):
    """Raised when an OSV JSON report cannot be compared safely."""


def read_report(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OsvComparisonError(f"cannot read OSV JSON report {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise OsvComparisonError(f"OSV JSON report {path} must be an object")
    return value


def required_string(value: Any, description: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OsvComparisonError(f"{description} must be a non-empty string")
    return value


def package_version(package: dict[str, Any]) -> str | None:
    for field in ("version", "commit"):
        value = package.get(field)
        if isinstance(value, str) and value.strip():
            return value
    return None


def grouped_vulnerability_ids(package_result: dict[str, Any]) -> list[list[str]]:
    vulnerabilities = package_result.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise OsvComparisonError("OSV package vulnerabilities must be a list")
    vulnerability_ids = {
        required_string(vulnerability.get("id"), "OSV vulnerability id")
        for vulnerability in vulnerabilities
        if isinstance(vulnerability, dict)
    }
    if len(vulnerability_ids) != len(vulnerabilities):
        raise OsvComparisonError("OSV vulnerability entries must be objects")
    if not vulnerability_ids:
        return []
    groups = package_result.get("groups")
    if not isinstance(groups, list) or not groups:
        raise OsvComparisonError(
            "OSV vulnerable package results must contain non-empty groups"
        )
    grouped_ids: list[list[str]] = []
    for group in groups:
        if not isinstance(group, dict):
            raise OsvComparisonError("OSV vulnerability groups must be objects")
        identifiers = group.get("ids")
        if (
            not isinstance(identifiers, list)
            or not identifiers
            or not all(
                isinstance(identifier, str) and identifier.strip()
                for identifier in identifiers
            )
        ):
            raise OsvComparisonError(
                "OSV vulnerability group ids must be a string list"
            )
        normalized_ids = sorted(set(identifiers))
        if not set(normalized_ids).issubset(vulnerability_ids):
            raise OsvComparisonError(
                "OSV vulnerability group ids must refer to listed vulnerabilities"
            )
        grouped_ids.append(normalized_ids)
    return grouped_ids


def report_groups(
    report: dict[str, Any],
) -> dict[tuple[str, str, tuple[str, ...]], dict[str, Any]]:
    results = report.get("results")
    if not isinstance(results, list):
        raise OsvComparisonError("OSV JSON report must contain a results list")
    groups: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]] = {}
    for result in results:
        if not isinstance(result, dict):
            raise OsvComparisonError("OSV result entries must be objects")
        packages = result.get("packages", [])
        if not isinstance(packages, list):
            raise OsvComparisonError("OSV result packages must be a list")
        for package_result in packages:
            if not isinstance(package_result, dict):
                raise OsvComparisonError("OSV package result entries must be objects")
            package = package_result.get("package")
            if not isinstance(package, dict):
                raise OsvComparisonError(
                    "OSV package result must contain a package object"
                )
            name = required_string(package.get("name"), "OSV package name")
            ecosystem = required_string(
                package.get("ecosystem"), "OSV package ecosystem"
            )
            for vulnerability_ids in grouped_vulnerability_ids(package_result):
                identity = (ecosystem, name, tuple(vulnerability_ids))
                group = groups.setdefault(
                    identity,
                    {
                        "ecosystem": ecosystem,
                        "package": name,
                        "vulnerability_ids": vulnerability_ids,
                        "versions": set(),
                    },
                )
                version = package_version(package)
                if version is not None:
                    group["versions"].add(version)
    return groups


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


def compare_reports(
    base_report: dict[str, Any],
    head_report: dict[str, Any],
    base_revision: str,
    head_revision: str,
) -> dict[str, Any]:
    if not REVISION.fullmatch(base_revision):
        raise OsvComparisonError("base revision must be a lowercase 40-character SHA")
    if not REVISION.fullmatch(head_revision):
        raise OsvComparisonError("head revision must be a lowercase 40-character SHA")
    base_groups = report_groups(base_report)
    head_groups = report_groups(head_report)
    new_groups = {
        identity: group
        for identity, group in head_groups.items()
        if identity not in base_groups
    }
    return {
        "schema_version": 1,
        "base_revision": base_revision,
        "head_revision": head_revision,
        "status": "new_vulnerabilities" if new_groups else "no_new_vulnerabilities",
        "base_vulnerability_groups": serialise_groups(base_groups),
        "head_vulnerability_groups": serialise_groups(head_groups),
        "new_vulnerability_groups": serialise_groups(new_groups),
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.tmp")
    try:
        with temporary_path.open("x", encoding="utf-8") as output:
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
        os.replace(temporary_path, path)
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
        print(f"OSV comparison error: {exc}", file=os.sys.stderr)
        raise SystemExit(2) from exc
