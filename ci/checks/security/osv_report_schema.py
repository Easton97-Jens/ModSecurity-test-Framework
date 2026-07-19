"""Validate the OSV JSON report shape used by Framework CI evidence."""

from __future__ import annotations

from typing import Any, Iterator


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


def _vulnerability_ids(package_result: dict[str, Any]) -> set[str]:
    """Return the unique vulnerability IDs declared for one package result."""
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
    return vulnerability_ids


def _required_group_entries(groups: Any, vulnerability_ids: set[str]) -> list[Any]:
    """Reject absent or unexpected groups before validating their members."""
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
    return groups


def _normalized_group_ids(
    group: Any, vulnerability_ids: set[str], covered_ids: set[str]
) -> list[str]:
    """Validate one disjoint group and return its deterministically ordered IDs."""
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
            "OSV vulnerability groups must not overlap: " + ", ".join(sorted(overlap))
        )
    return normalized_ids


def grouped_vulnerability_ids(package_result: dict[str, Any]) -> list[list[str]]:
    """Validate and return the complete, disjoint alias groups for one package."""
    vulnerability_ids = _vulnerability_ids(package_result)
    groups = _required_group_entries(
        package_result.get("groups", []), vulnerability_ids
    )

    if not vulnerability_ids:
        return []

    covered_ids: set[str] = set()
    grouped_ids: list[list[str]] = []
    for group in groups:
        normalized_ids = _normalized_group_ids(group, vulnerability_ids, covered_ids)
        covered_ids.update(normalized_ids)
        grouped_ids.append(normalized_ids)
    if covered_ids != vulnerability_ids:
        missing = vulnerability_ids.difference(covered_ids)
        raise OsvReportError(
            "OSV vulnerability groups must cover every listed vulnerability id: "
            + ", ".join(sorted(missing))
        )
    return grouped_ids


def _package_results(report: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield only package result mappings from a strictly shaped OSV report."""
    results = report.get("results")
    if not isinstance(results, list):
        raise OsvReportError("OSV JSON report must contain a results list")
    for result in results:
        if not isinstance(result, dict):
            raise OsvReportError("OSV result entries must be objects")
        packages = result.get("packages", [])
        if not isinstance(packages, list):
            raise OsvReportError("OSV result packages must be a list")
        for package_result in packages:
            if not isinstance(package_result, dict):
                raise OsvReportError("OSV package result entries must be objects")
            yield package_result


def _package_identity(
    package_result: dict[str, Any],
) -> tuple[str, str, dict[str, Any]]:
    """Return the required package identity fields for a package result."""
    package = package_result.get("package")
    if not isinstance(package, dict):
        raise OsvReportError("OSV package result must contain a package object")
    name = required_string(package.get("name"), "OSV package name")
    ecosystem = required_string(package.get("ecosystem"), "OSV package ecosystem")
    return ecosystem, name, package


def _record_group(
    groups: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]],
    ecosystem: str,
    name: str,
    vulnerability_ids: list[str],
    version: str | None,
) -> None:
    """Add one normalized group to the deterministic report aggregation."""
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
    if version is not None:
        group["versions"].add(version)


def report_groups(
    report: dict[str, Any],
) -> dict[tuple[str, str, tuple[str, ...]], dict[str, Any]]:
    """Validate an OSV report and return deterministic vulnerability group records."""
    groups: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]] = {}
    for package_result in _package_results(report):
        ecosystem, name, package = _package_identity(package_result)
        version = package_version(package)
        for vulnerability_ids in grouped_vulnerability_ids(package_result):
            _record_group(groups, ecosystem, name, vulnerability_ids, version)
    return groups


def validate_osv_report(report: dict[str, Any]) -> None:
    """Reject any report that lacks the required OSV result/package/group shape."""
    report_groups(report)
