"""Validate the OSV JSON report shape used by Framework CI evidence."""

from __future__ import annotations

from typing import Any


class OsvReportError(ValueError):
    """Raised when an OSV JSON report cannot be interpreted safely."""


def required_string(value: Any, description: str) -> str:
    """Return a non-empty string or reject an untrusted report field."""
    if not isinstance(value, str) or not value.strip():
        raise OsvReportError(f"{description} must be a non-empty string")
    return value


def package_version(package: dict[str, Any]) -> str | None:
    """Return the best available package revision without requiring one."""
    for field in ("version", "commit"):
        value = package.get(field)
        if isinstance(value, str) and value.strip():
            return value
    return None


def grouped_vulnerability_ids(package_result: dict[str, Any]) -> list[list[str]]:
    """Validate and return the complete, disjoint alias groups for one package."""
    vulnerabilities = package_result.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise OsvReportError("OSV package vulnerabilities must be a list")
    if not all(isinstance(vulnerability, dict) for vulnerability in vulnerabilities):
        raise OsvReportError("OSV vulnerability entries must be objects")
    vulnerability_ids = {
        required_string(vulnerability.get("id"), "OSV vulnerability id")
        for vulnerability in vulnerabilities
    }
    if len(vulnerability_ids) != len(vulnerabilities):
        raise OsvReportError("OSV vulnerability ids must be unique")

    groups = package_result.get("groups", [])
    if not vulnerability_ids:
        if not isinstance(groups, list) or groups:
            raise OsvReportError(
                "OSV clean package results must not contain vulnerability groups"
            )
        return []
    if not isinstance(groups, list) or not groups:
        raise OsvReportError(
            "OSV vulnerable package results must contain non-empty groups"
        )

    covered_ids: set[str] = set()
    grouped_ids: list[list[str]] = []
    for group in groups:
        if not isinstance(group, dict):
            raise OsvReportError("OSV vulnerability groups must be objects")
        identifiers = group.get("ids")
        if (
            not isinstance(identifiers, list)
            or not identifiers
            or not all(
                isinstance(identifier, str) and identifier.strip()
                for identifier in identifiers
            )
        ):
            raise OsvReportError("OSV vulnerability group ids must be a string list")
        normalized_ids = sorted(set(identifiers))
        if len(normalized_ids) != len(identifiers):
            raise OsvReportError("OSV vulnerability group ids must be unique")
        group_ids = set(normalized_ids)
        if not group_ids.issubset(vulnerability_ids):
            raise OsvReportError(
                "OSV vulnerability group ids must refer to listed vulnerabilities"
            )
        overlap = covered_ids.intersection(group_ids)
        if overlap:
            raise OsvReportError(
                "OSV vulnerability groups must not overlap: "
                + ", ".join(sorted(overlap))
            )
        covered_ids.update(group_ids)
        grouped_ids.append(normalized_ids)
    if covered_ids != vulnerability_ids:
        missing = vulnerability_ids.difference(covered_ids)
        raise OsvReportError(
            "OSV vulnerability groups must cover every listed vulnerability id: "
            + ", ".join(sorted(missing))
        )
    return grouped_ids


def report_groups(
    report: dict[str, Any],
) -> dict[tuple[str, str, tuple[str, ...]], dict[str, Any]]:
    """Validate an OSV report and return deterministic vulnerability group records."""
    results = report.get("results")
    if not isinstance(results, list):
        raise OsvReportError("OSV JSON report must contain a results list")
    groups: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]] = {}
    for result in results:
        if not isinstance(result, dict):
            raise OsvReportError("OSV result entries must be objects")
        packages = result.get("packages", [])
        if not isinstance(packages, list):
            raise OsvReportError("OSV result packages must be a list")
        for package_result in packages:
            if not isinstance(package_result, dict):
                raise OsvReportError("OSV package result entries must be objects")
            package = package_result.get("package")
            if not isinstance(package, dict):
                raise OsvReportError("OSV package result must contain a package object")
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


def validate_osv_report(report: dict[str, Any]) -> None:
    """Reject any report that lacks the required OSV result/package/group shape."""
    report_groups(report)
